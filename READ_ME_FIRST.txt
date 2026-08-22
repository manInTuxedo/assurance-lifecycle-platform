ASSURANCE FINDING LIFECYCLE & SLA MANAGEMENT PLATFORM
=====================================================

Same project, same structure, same way of running it. What changed is inside:
the logic was reworked and the interface was tidied. CHANGELOG_REVIEW.md lists
every change with the reason and the numbers behind it.

The database ships loaded, so the platform is full the moment it opens.


RUN IT
    pip install -r requirements.txt
    uvicorn app.main:app --reload

    http://127.0.0.1:8000      admin / admin

Any account can change its own password from the key icon beside its name.


WHAT THE PLATFORM READS
  Five kinds of assessment, and it works out which is which from the CONTENT
  of the file - never from its name, never from a dropdown:

    VA     infrastructure vulnerability assessment   IP + plugin + port
    CIS    benchmark / hardening audit               IP + control
    SAST   static application security testing       application + title
                                                     + file + CWE
    DAST   dynamic application security testing      application + title
                                                     + URL + OWASP category
    PT     penetration test activity                 application + title + URL

  VA and CIS are told apart by the shape of the control name. SAST, DAST and
  PT are told apart by the prefix on their Finding ID. A workbook holding all
  three on separate sheets is split into three assessments.

  Severity is not part of any correlation key. A finding re-rated from High to
  Critical is the same finding: the severity is updated and the age is kept.


WHERE AN APPLICATION FINDING LANDS
  SAST reads source code, so it is about an application and not about a
  machine - it lands on the application's own row in the register.
  DAST and PT exercise a running service, so they land on the host behind the
  domain in the URL. That is what the Domain column on the inventory is for.

  An application, or a host name, the inventory has not heard of yet waits on
  the Default Asset and moves across on its own once the inventory catches up.


WHAT IS ALREADY LOADED
  1,232 assets      1,182 hosts and 50 applications, read on startup
  4,529 findings    from 25 assessments across three cycles
                      2,580 VA . 422 CIS . 834 SAST . 526 DAST . 167 PT
  1,063 closed      automatically, proven gone by a later assessment
    284 reappeared  closed, then detected again, original age kept
     61 exceptions  worked examples across all five assessment types,
                    one of them control-level and covering future occurrences
     22 SLA rules   the default firewall-style policy, with its own windows
                    for SAST, DAST and PT


THE DATA IS IN THE PACKAGE
  sample_reports/   the inventory and all 16 assessment reports

  To exercise the platform from nothing:

    1. Settings -> Maintenance -> Reset the platform
         Clear findings              keeps assets and policy
         Clear findings and assets   reloads the inventory afterwards
         Factory reset               also resets the SLA policy
       Administrator only, and each one asks you to type a word first.
       Accounts are never deleted.

    2. Findings -> Upload Report -> Choose files, or Choose a folder.
       Select all 25 at once if you like. Every kind can be mixed: the
       platform reads which is which from the content of the file, not from
       the name and not from a dropdown.
       AppSec_Portfolio_Review_2026-08-18.xlsx is the same third cycle in one
       workbook of three sheets - it is there to show the split, so loading it
       as well changes nothing.

    3. The asset inventory is uploaded from the Assets page only.

  GROUND_TRUTH_do_not_import.xlsx and APPSEC_GROUND_TRUTH_do_not_import.xlsx
  are the references used to check the platform, not inputs.


THINGS WORTH KNOWING BEFORE READING THE CODE
  * Absence is not evidence. A finding is closed only when an assessment that
    actually covered it failed to report it. For VA and CIS the unit of
    coverage is the host, and it must have been reached with working
    credentials - every host carries a coverage state, Assessed, Inconclusive
    or Not Assessed, taken from the "Nessus Scan Information" row. For SAST,
    DAST and PT the unit is the application: if a report tested an
    application, everything it does not mention for that application and that
    assessment type is gone; an application absent from the report proves
    nothing about it at all.
  * Last Observed is the authority, not the upload order. Loading cycle 3
    then 1 then 2 ends in exactly the same state as 1, 2, 3.
  * A finding keeps its original discovery date for ever, including after it
    reappears. The clock is never reset.
  * "SLA Exceeded" means an assessment saw it after the due date. A deadline
    that passed with no assessment since is "Past Due" - the platform does not
    claim a breach it has not seen.
  * Nothing from the report is thrown away. Every finding keeps the original
    sheet row exactly as it arrived - open a finding and click "Open the full
    record" to see every column, including the ones the data model has no field
    for. A CIS export has no Description column at all, so that field is empty
    on CIS findings by design, not by loss.
  * The database runs in WAL mode, so recent writes may sit in
    data/assurance.db-wal for a moment. The platform folds it back in when it
    stops - if you ever copy the database while it is running, take the -wal
    and -shm files with it.
  * Assets are never invented from a scan row. Unmapped IPs wait on the
    Default Asset until the inventory explains them, then move across on
    their own.


ACCESS
  One account ships: admin / admin, an administrator.
  More are created in Settings -> Users & Access, with two things per account:

    a level per page      No access / View only / View and edit
    a data reach          which business scopes and which assessments exist
                          for that account at all

  Both are enforced on the server, not just hidden in the interface. A scope
  that is not ticked is not filtered out of the screen - it is absent: not
  listed, not counted, not charted, not exported, and a report row about it is
  ignored on upload instead of being refused.


THE TWO FILTERS IN THE HEADER
  Scope and Assessment narrow the whole platform at once - every page, every
  chart, every total, the search and the exports. Settings is the exception;
  the policy and the user list are global.

  They are a way of LOOKING, not a way of working. An administrator filtered to
  one scope still uploads a full report in full. What a person may write is
  their data reach, never what they happen to be looking at.
