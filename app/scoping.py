"""The view filter - one place that decides what exists for the current user.

Two independent dimensions narrow the platform:

  scope       a business scope taken from the asset inventory
              (Application, Crown Jewel, PCI, Infrastructure ...)
  assessment  VA, CIS, SAST, DAST or PT

Each dimension has two layers:

  the grant      what the account is allowed to reach at all. Set by an
                 administrator on Settings -> Users & Access. It is not a
                 view preference - it also governs writing and ingest.
  the selection  what the person picked in the header right now. A view
                 preference only; it never widens the grant and it never
                 affects writing.

The effective view is the intersection. Everything outside it is treated as
absent rather than hidden: it is not listed, counted, charted, searched,
opened by id, edited, or accepted from an upload. That is the whole point -
a user restricted to Application should never be able to tell that anything
else was ever loaded.

Assets the inventory has not explained (the Default Asset that unmapped IPs
wait on, and any host whose scope is blank) form their own bucket. It is
granted by default, because a brand new IP belongs to nobody until the
inventory says otherwise, and refusing it would silently drop rows.
"""
from sqlalchemy import String, and_, func, literal, or_, select

from . import models

SCOPE_COOKIE = "av_scope"
SOURCE_COOKIE = "av_source"
UNSCOPED_TOKEN = "__unscoped__"


# --------------------------------------------------------------------------
# scope strings
# --------------------------------------------------------------------------
def scope_tokens(raw) -> set:
    """Split an asset's scope cell into its individual scopes.

    One asset commonly carries several - "Crown Jewel, PCI, Application" is a
    single cell, three scopes. Membership is exact: a rule for "PCI" must not
    be satisfied by a scope called "Not PCI".
    """
    return {p.strip() for p in str(raw or "").split(",") if p.strip()}


def is_unscoped_value(raw) -> bool:
    tokens = scope_tokens(raw)
    if not tokens:
        return True
    return tokens == {models.NO_ASSET_SCOPE}


def _scope_key_expr():
    """SQL expression giving ',Crown Jewel,PCI,Application,' for an asset.

    Wrapping in commas turns a substring test into an exact membership test,
    so LIKE '%,PCI,%' cannot be satisfied by a scope named "Non PCI".
    """
    collapsed = func.replace(func.replace(
        func.coalesce(models.Asset.scope, ""), ", ", ","), " ,", ",",
        type_=String)
    return literal(",", String).concat(collapsed).concat(literal(",", String))


def asset_clause(scopes, include_unscoped):
    """Condition on Asset for a set of scopes.

    scopes is None for "every scope" (an administrator with no header
    selection). An empty list is a real answer - this account reaches no
    named scope at all - and produces a condition nothing satisfies unless
    the unscoped bucket is granted.
    """
    if scopes is None and include_unscoped:
        return None                      # no restriction whatsoever
    parts = []
    if scopes:
        key = _scope_key_expr()
        parts.append(or_(*[key.like(f"%,{s},%") for s in scopes]))
    elif scopes is None:
        parts.append(models.Asset.id.isnot(None))
    unscoped = or_(models.Asset.scope.is_(None),
                   models.Asset.scope == "",
                   models.Asset.scope == models.NO_ASSET_SCOPE)
    if include_unscoped:
        parts.append(unscoped)
        return or_(*parts)
    if not parts:
        return models.Asset.id.is_(None)     # reaches nothing
    return and_(or_(*parts), ~unscoped)


# --------------------------------------------------------------------------
# the view itself
# --------------------------------------------------------------------------
class ViewFilter:
    """What exists, for one request, for one user."""

    def __init__(self, user, scope_choice="", source_choice="", available_scopes=None):
        self.user = user
        self.available_scopes = list(available_scopes or [])

        granted = user.scope_grants()                    # None = every scope
        self.granted_scopes = granted
        self.granted_unscoped = user.reaches_unscoped()
        granted_sources = user.source_grants()           # None = both
        self.granted_sources = granted_sources

        # -- scope selection ------------------------------------------------
        allowed = self.available_scopes if granted is None else \
            [s for s in self.available_scopes if s in granted]
        self.scope_options = allowed
        choice = (scope_choice or "").strip()
        # A selection the account is not granted is not an error worth showing
        # - it is simply ignored, which lands the user back on "everything I
        # am allowed to see" rather than on an empty screen.
        self.scope = choice if choice in allowed else ""

        if self.scope:
            self.scopes = [self.scope]
            self.include_unscoped = False
        else:
            self.scopes = granted            # None = unrestricted
            self.include_unscoped = self.granted_unscoped

        # -- assessment selection -------------------------------------------
        source_allowed = list(models.SOURCES) if granted_sources is None else list(granted_sources)
        self.source_options = source_allowed
        src = (source_choice or "").strip().upper()
        self.source = src if src in source_allowed else ""
        self.sources = [self.source] if self.source else \
            (None if granted_sources is None else list(granted_sources))

    # -- introspection ------------------------------------------------------
    @property
    def scope_restricted(self) -> bool:
        return not (self.scopes is None and self.include_unscoped)

    @property
    def source_restricted(self) -> bool:
        return self.sources is not None

    @property
    def restricted(self) -> bool:
        return self.scope_restricted or self.source_restricted

    def to_dict(self) -> dict:
        return {
            "scope": self.scope,
            "source": self.source,
            "scope_options": self.scope_options,
            "source_options": self.source_options,
            "scope_locked": self.granted_scopes is not None,
            "source_locked": self.granted_sources is not None,
            "restricted": self.restricted,
        }

    # -- query narrowing ----------------------------------------------------
    def asset_condition(self):
        return asset_clause(self.scopes, self.include_unscoped)

    def assets(self, query):
        cond = self.asset_condition()
        return query.filter(cond) if cond is not None else query

    def findings(self, query):
        """Narrow a Finding query.

        The asset side goes through a subquery on purpose. Several callers
        already join Asset for their own reasons and an extra join would
        duplicate rows and inflate every count on the dashboard.
        """
        cond = self.asset_condition()
        if cond is not None:
            query = query.filter(models.Finding.asset_id.in_(
                select(models.Asset.id).where(cond)))
        if self.sources is not None:
            query = query.filter(models.Finding.source.in_(self.sources))
        return query

    def finding_conditions(self) -> list:
        """The same narrowing as a list of conditions, for aggregate queries."""
        out = []
        cond = self.asset_condition()
        if cond is not None:
            out.append(models.Finding.asset_id.in_(
                select(models.Asset.id).where(cond)))
        if self.sources is not None:
            out.append(models.Finding.source.in_(self.sources))
        return out

    def asset_conditions(self) -> list:
        cond = self.asset_condition()
        return [cond] if cond is not None else []

    def exception_conditions(self) -> list:
        """Narrow an ExceptionRecord query.

        A finding-level exception follows its finding. A control-level one has
        no finding of its own - it is a standing decision that lands on rows as
        they appear - so it is kept only while at least one finding inside the
        view is covered by it. Without that test a restricted account would be
        shown decisions about hosts it is not allowed to know exist.
        """
        conds = self.finding_conditions()
        if not conds:
            return []
        visible = select(models.Finding.id).where(*conds)
        control = select(models.Finding.plugin_name).where(*conds)
        return [or_(models.ExceptionRecord.finding_id.in_(visible),
                    and_(models.ExceptionRecord.finding_id.is_(None),
                         models.ExceptionRecord.control_key.in_(control)))]

    def audit_conditions(self) -> list:
        """Narrow the assessment file list.

        Only the assessment dimension applies: a file is a VA file or a CIS
        file, but it carries rows from every scope, so hiding it by scope
        would be arbitrary.
        """
        if self.sources is None:
            return []
        like = or_(*[models.AuditFile.source_type.ilike(f"{s}%") for s in self.sources]) \
            if self.sources else models.AuditFile.id.is_(None)
        return [like]

    # -- membership tests ---------------------------------------------------
    def covers_asset(self, asset) -> bool:
        if asset is None:
            return self.include_unscoped or self.scopes is None
        if is_unscoped_value(asset.scope):
            return self.include_unscoped
        if self.scopes is None:
            return True
        return bool(scope_tokens(asset.scope) & set(self.scopes))

    def covers_source(self, source) -> bool:
        if self.sources is None:
            return True
        return (source or "").upper() in {s.upper() for s in self.sources}

    def covers_finding(self, finding) -> bool:
        return self.covers_source(finding.source) and self.covers_asset(finding.asset)


class WriteReach:
    """What a user may create or change - the grant alone, never the header.

    Filtering the screen down to Application and then uploading a report must
    not throw away every other row: the header is a way of looking, not a way
    of working. Ingest and edits therefore consult this, which knows nothing
    about the current selection.
    """

    def __init__(self, user):
        self.user = user
        self.scopes = user.scope_grants()
        self.unscoped = user.reaches_unscoped()
        self.sources = user.source_grants()

    @property
    def unrestricted(self) -> bool:
        return self.scopes is None and self.sources is None and self.unscoped

    def covers_scope_value(self, raw) -> bool:
        if is_unscoped_value(raw):
            return self.unscoped
        if self.scopes is None:
            return True
        return bool(scope_tokens(raw) & set(self.scopes))

    def covers_asset(self, asset) -> bool:
        if asset is None:
            return self.unscoped
        return self.covers_scope_value(asset.scope)

    def covers_source(self, source) -> bool:
        if self.sources is None:
            return True
        return (source or "").upper() in {s.upper() for s in self.sources}

    def covers_finding(self, finding) -> bool:
        return self.covers_source(finding.source) and self.covers_asset(finding.asset)

    def condition(self):
        return asset_clause(self.scopes, self.unscoped)

    def finding_conditions(self) -> list:
        out = []
        cond = self.condition()
        if cond is not None:
            out.append(models.Finding.asset_id.in_(
                select(models.Asset.id).where(cond)))
        if self.sources is not None:
            out.append(models.Finding.source.in_(self.sources))
        return out

    def asset_conditions(self) -> list:
        cond = self.condition()
        return [cond] if cond is not None else []
