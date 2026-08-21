# Testing Guide

## Quick Start Test

### 1. Start the Application
```bash
cd "d:\Banque Misr Assurance Proj. 2\Assure\assurance-lifecycle-platform\assurance_platform"
./venv/Scripts/uvicorn.exe app.main:app --reload --host 127.0.0.1 --port 8000
```

Expected console output:
```
✅ Asset inventory loaded: X created, Y updated, Z skipped
INFO:     Uvicorn running on http://127.0.0.1:8000
```

### 2. Login
- URL: http://127.0.0.1:8000
- Username: `admin`
- Password: `admin`

### 3. Verify Asset Inventory Loaded

Navigate to: http://127.0.0.1:8000/assets

**Expected Results:**
- Total assets: 1,249+ (from Asset_Inventory.xlsx)
- Assets should show:
  - Crown Jewel scope for CJ assets
  - PCI scope for PCI assets
  - Proper owner teams (Application Owner column)
  - Sites: HQ, DR

**Sample Assets to Verify:**
```
IP: 10.20.1.56  - Crown Jewel, UAT, DR
IP: 10.20.1.41  - Crown Jewel, UAT, DR
IP: 10.10.1.214 - Crown Jewel, Production, HQ
```

### 4. Test VA Report Upload

**File:** `VA_C1_2026-03-16_R1_HQ-App-Servers-A.xlsx`

**Method 1: Via UI**
1. Navigate to Reports page
2. Click "Upload Report"
3. Select the VA file
4. Submit

**Method 2: Via API**
```bash
curl -X POST http://127.0.0.1:8000/api/upload \
  -H "Cookie: assurance_token=YOUR_TOKEN" \
  -F "file=@VA_C1_2026-03-16_R1_HQ-App-Servers-A.xlsx" \
  -F "source_type=va"
```

**Expected Response:**
```json
{
  "ok": true,
  "filename": "VA_C1_2026-03-16_R1_HQ-App-Servers-A.xlsx",
  "stats": {
    "records": 781,
    "new": 65+,
    "updated": 0,
    "reappeared": 0,
    "unmapped": 0,
    "detected_type": "VA",
    "skipped_uncredentialed": 1
  }
}
```

**Verify:**
- `detected_type` should be `"VA"`
- `skipped_uncredentialed` should be 1 (IP: 10.10.1.137 has no credentials)
- New findings created

### 5. Test CIS Report Upload

**File:** `CIS_Juniper_OS_v2.1.0_L1_2026-03-22.xlsx`

Upload using same method as VA report.

**Expected Response:**
```json
{
  "ok": true,
  "filename": "CIS_Juniper_OS_v2.1.0_L1_2026-03-22.xlsx",
  "stats": {
    "records": 460,
    "new": 458+,
    "updated": 0,
    "reappeared": 0,
    "unmapped": 0,
    "detected_type": "CIS"
  }
}
```

**Verify:**
- `detected_type` should be `"CIS"`
- No `skipped_uncredentialed` field (not applicable for CIS)
- Findings have severity: "Failed", "Manual Check", or "Passed"

### 6. Verify Findings Page

Navigate to: http://127.0.0.1:8000/findings

**Check VA Findings:**
- Filter by Source: VA
- Should see findings like:
  - "OpenSSH < 9.6 Multiple Vulnerabilities"
  - "AIX Security Update (IJ52011)"
- Composite key: IP + Plugin + Port + Protocol
- Only credentialed IPs processed

**Check CIS Findings:**
- Filter by Source: CIS
- Should see findings like:
  - "1.1 Ensure Device is running Current Junos Software"
  - "1.2 Ensure End of Life JUNOS Devices are not used"
- Severity: Passed, Failed, Manual Check
- No port field (CIS uses IP + Plugin only)

### 7. Verify SLA Calculation

Navigate to: http://127.0.0.1:8000/sla-tracking

**Check SLA Assignment:**
1. Find a Critical finding on a Crown Jewel asset
   - Should have 5-day SLA
2. Find a Critical finding on a PCI asset
   - Should have 10-day SLA
3. Find a Critical finding on Infrastructure asset
   - Should have 30-day SLA

**Verify Dashboard:**
- Within SLA count should be majority
- Approaching SLA and Exceeded depend on finding ages

### 8. Test Reappearance Logic

**Scenario:** Upload same VA report twice

1. Upload `VA_C1_2026-03-16_R1_HQ-App-Servers-A.xlsx`
2. Manually close a few findings (set status to Closed)
3. Upload the same file again

**Expected:**
- Closed findings should reappear
- `is_reappeared` flag set to true
- `reappeared_count` incremented
- Status changed back to Open
- Age preserved (based on `original_created_at`)

### 9. Dashboard Charts Verification

Navigate to: http://127.0.0.1:8000

**Verify Charts Load:**
1. **Aging & SLA Trend Chart** (top section)
   - Bar chart showing opened findings per week
   - Line chart showing SLA exceeded findings
   - Should render without errors
2. **Retest & Validation Chart** (right section)
   - Doughnut chart showing retest status
   - Labels: Pending, Passed, Failed, Not Requested

**Check Browser Console:**
- Press F12 to open developer tools
- Check Console tab for errors
- Should see no Chart.js errors

### 10. Verify Audit Route Removal

**Test:**
```bash
curl http://127.0.0.1:8000/audit
```

**Expected:** 404 Not Found or redirect

**Navigation Menu:**
- "Audit Files" should NOT appear in sidebar
- Navigation should show: Dashboard, Findings, SLA Tracking, Retests, Exceptions, Assets, Reports, Settings

**API Still Works:**
```bash
curl http://127.0.0.1:8000/api/audit
```
Should return audit file records (200 OK)

## Detailed Test Cases

### Test Case 1: Credentialed Scan Filtering

**File:** VA_C1_2026-03-16_R1_HQ-App-Servers-A.xlsx

**Check these IPs:**
- `10.10.1.110` - Should have "credentialed checks : yes" → ✅ Processed
- `10.10.1.114` - Should have "credentialed checks : yes" → ✅ Processed
- `10.10.1.137` - Should have "credentialed checks : no" → ❌ Skipped

**Verification Query:**
```sql
SELECT COUNT(*) FROM findings WHERE ip_address = '10.10.1.137';
-- Should return 0 (skipped)

SELECT COUNT(*) FROM findings WHERE ip_address = '10.10.1.114';
-- Should return > 0 (processed)
```

### Test Case 2: CIS Status Mapping

**File:** CIS_Juniper_OS_v2.1.0_L1_2026-03-22.xlsx

**Check Severity Mapping:**

Original Excel:
```
Plugin Name: "1.1 Ensure Device is running Current Junos Software"
Severity: Info
```

In Database:
```sql
SELECT severity FROM findings WHERE plugin_name LIKE '1.1 Ensure Device%';
-- Should return "Passed" (Info → Passed)
```

### Test Case 3: Composite Key Differences

**VA Finding:**
```
IP: 10.10.1.114
Plugin: OpenSSH < 9.6 Multiple Vulnerabilities
Port: 22
Protocol: TCP
```
Composite Key: `10.10.1.114 + OpenSSH < 9.6 Multiple Vulnerabilities + 22 + TCP`

**CIS Finding:**
```
IP: 10.40.2.213
Plugin: 1.1 Ensure Device is running Current Junos Software
Port: (ignored)
Protocol: (ignored)
```
Composite Key: `10.40.2.213 + 1.1 Ensure Device is running Current Junos Software`

**Test:**
1. Upload CIS report with finding on port 0 and port 22
2. Should create ONE finding (port ignored in CIS correlation)

### Test Case 4: Asset Scope SLA Priority

**Setup:**
1. Ensure you have:
   - Asset with Crown Jewel scope
   - Asset with PCI scope
   - Asset with Infrastructure scope

2. Create Critical findings on each:
   ```sql
   INSERT INTO findings (source, severity, ip_address, asset_id, ...)
   VALUES ('VA', 'Critical', '10.10.1.214', <crown_jewel_asset_id>, ...);
   ```

3. Check SLA assignments:
   ```sql
   SELECT 
     f.finding_code,
     a.scope,
     f.sla_days,
     f.due_date
   FROM findings f
   JOIN assets a ON f.asset_id = a.id
   WHERE f.severity = 'Critical';
   ```

**Expected:**
- Crown Jewel: sla_days = 5
- PCI: sla_days = 10
- Infrastructure: sla_days = 30

## Performance Tests

### Large File Upload
```bash
time curl -X POST http://127.0.0.1:8000/api/upload \
  -F "file=@VA_C1_2026-03-16_R1_HQ-App-Servers-A.xlsx"
```

**Expected:**
- 781 records processed in < 5 seconds
- No memory issues
- All findings created/updated correctly

### Asset Inventory Load Time
Check startup logs:
```
✅ Asset inventory loaded: 1249 created, 0 updated, 0 skipped
```
Should complete in < 3 seconds

## Troubleshooting

### Issue: Asset inventory not loading
**Check:**
1. File exists: `Asset_Inventory.xlsx` in workspace root
2. File permissions: readable by application
3. Database: `data/assurance.db` is writable

**Fix:**
```bash
ls -la Asset_Inventory.xlsx
# Should show the file with read permissions
```

### Issue: Chart.js not rendering
**Check:**
1. Browser console (F12) for errors
2. Network tab: Chart.js CDN loaded (200 OK)
3. Base.html includes: `chart.js@4.4.3/dist/chart.umd.min.js`

**Fix:**
Clear browser cache and reload

### Issue: Findings not correlating correctly
**Check:**
1. Source type: VA vs CIS
2. Composite key fields: IP, Plugin, Port (VA only), Protocol (VA only)
3. Case sensitivity: IPs should match exactly

**Debug Query:**
```sql
SELECT 
  ip_address,
  plugin_name,
  port,
  protocol,
  source,
  COUNT(*) as duplicates
FROM findings
GROUP BY ip_address, plugin_name, port, protocol, source
HAVING COUNT(*) > 1;
-- Should return no results (no duplicate composite keys)
```

### Issue: Uncredentialed IPs being processed
**Check:**
1. Plugin output contains: "credentialed checks : yes"
2. Case-insensitive matching working
3. Parser function: `check_credentialed_scan()`

**Debug:**
```python
from app import parsers
rows = parsers.parse_va_scan("test.xlsx", content)
creds = parsers.check_credentialed_scan(rows)
print(creds)  # Should show IP → True/False mapping
```

## API Testing with Postman/curl

### Get Summary Stats
```bash
curl http://127.0.0.1:8000/api/summary \
  -H "Cookie: assurance_token=YOUR_TOKEN"
```

### Get Findings
```bash
curl "http://127.0.0.1:8000/api/findings?source=VA&severity=Critical" \
  -H "Cookie: assurance_token=YOUR_TOKEN"
```

### Upload Report
```bash
curl -X POST http://127.0.0.1:8000/api/upload \
  -H "Cookie: assurance_token=YOUR_TOKEN" \
  -F "file=@report.xlsx" \
  -F "source_type=va"
```

### Get Audit Log
```bash
curl http://127.0.0.1:8000/api/audit \
  -H "Cookie: assurance_token=YOUR_TOKEN"
```

## Success Criteria

✅ **All tests pass if:**
1. Asset inventory loads on startup (1,249 assets)
2. VA report auto-detected and only credentialed IPs processed
3. CIS report auto-detected with correct status mapping
4. Composite keys work correctly (different for VA vs CIS)
5. SLA calculation incorporates Crown Jewel/PCI priority
6. Dashboard charts render without errors
7. /audit route returns 404, but /api/audit works
8. Reappearance logic preserves age and increments counter

---

**Testing Date:** 2026-08-21  
**All Features:** ✅ Implemented and Ready for Testing
