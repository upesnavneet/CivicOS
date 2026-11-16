"""Extract ward- and city-level tables from the two Praja Foundation reports into one long-format JSON.
Usage: python3 extract.py p26.txt p25.txt out.json
Every record keeps the source id (report + table + page). Each table is checked against its own Total row."""
import json, re, sys

WARDS = ["A","B","C","D","E","F/N","F/S","G/N","G/S","H/E","H/W","K/E","K/W","L","M/E","M/W","N","P/N","P/S","R/C","R/N","R/S","S","T"]
EXTRA = ["P/E"]  # appears only in the 2025 waste tables; no boundary or complaint data
MONTHS = ["January","February","March","April","May","June","July","August","September","October","November","December"]

def pages(path):
    out, cur = {}, None
    for line in open(path, encoding="utf-8"):
        m = re.match(r"@@PAGE (\d+)", line)
        if m: cur = int(m.group(1)); out[cur] = []
        elif cur: out[cur].append(line.rstrip("\n"))
    return out

def num(tok):
    t = tok.replace(",", "").replace("%", "").strip()
    if t in ("-", "", "–"): return None
    return float(t) if "." in t else int(t)

NUMTOK = re.compile(r"^-?[\d,]*\d(\.\d+)?%?$|^[-–]$")
def split_row(line):
    """-> (label, [numbers]) where numbers are the trailing numeric tokens."""
    toks = line.split()
    i = len(toks)
    while i > 0 and NUMTOK.match(toks[i-1]): i -= 1
    return " ".join(toks[:i]), [num(t) for t in toks[i:]]

def ward_of(label):
    """Ward code if the label (minus region words / footnote stars) is exactly one ward code."""
    for tok in reversed(label.replace("*", "").split()):
        if tok in WARDS or tok in EXTRA: return tok
    return None

records, sources, checks = [], {}, []
def src(sid, report, table, page, title):
    sources[sid] = {"report": report, "table": table, "page": page, "title": title}
def add(sid, zone, year, metric, value, unit, category=None, month=None):
    if value is None: return
    records.append({"zone": zone, "year": year, "month": month, "metric": metric, "category": category,
                    "value": value, "unit": unit, "source": sid})
def check(name, got, want, tol=0):
    ok = want is not None and abs(got - want) <= tol
    checks.append((name, got, want, ok))

def ward_rows(lines, n_nums, start_after=None):
    """Yield (ward, nums) for lines that are 'WARD n1 n2 ...' with exactly n_nums numbers; also the Total row."""
    rows, total, started = [], None, start_after is None
    for ln in lines:
        if not started:
            started = start_after in ln
            continue
        label, nums = split_row(ln)
        if label.strip().startswith(("Total", "Grand Total")) and len(nums) >= n_nums - 1 and total is None:
            total = nums
        w = ward_of(label)
        if w and len(nums) == n_nums and len(label.replace("*", "").split()) <= 3:
            rows.append((w, nums))
    return rows, total

R26 = "Praja Foundation, Report on the Status of Civic Services, Environmental and Climate Issues in Mumbai (2026)"
R25 = "Praja Foundation, Report on the Status of Civic Issues in Mumbai (2025)"
p26, p25 = pages(sys.argv[1]), pages(sys.argv[2])
YEARS = list(range(2016, 2026))
UNASSIGNED_2025 = {"p26-t43": 7641, "p26-t39": 1432, "p26-t41": 1229}

# ---- ward x year complaint counts: T43 (all), T39 (SWM), T41 (drainage) -------------------------
for sid, page, table, title, cat in [
    ("p26-t43", 100, "Table 43", "Ward-wise Total Complaints Registered in Civic Complaint System from 2016 to 2025", None),
    ("p26-t39", 96, "Table 39", "Ward-wise Solid Waste Management Complaints from 2016 to 2025", "Solid Waste Management (SWM)"),
    ("p26-t41", 98, "Table 41", "Ward-wise Drainage Complaints from 2016 to 2025", "Drainage"),
]:
    src(sid, R26, table, page, title)
    rows, total = ward_rows(p26[page], 12)
    assert len(rows) == 24, (sid, len(rows))
    for w, n in rows:
        for y, v in zip(YEARS, n[1:11]): add(sid, w, y, "complaints_registered", v, "complaints", cat)
        if sid == "p26-t43": add(sid, w, 2025, "population", n[0], "people")
    for i, y in enumerate(YEARS):
        got = sum(n[1+i] for _, n in rows)
        # the 2025 totals include complaints with no ward assigned (printed in each table's "Ward not Assigned" row)
        extra = UNASSIGNED_2025[sid] if y == 2025 else 0
        check(f"{sid} {y} ward sum", got + extra, total[1+i])
    add(sid, None, 2025, "complaints_unassigned_ward", UNASSIGNED_2025[sid], "complaints", cat)
    if sid == "p26-t43":
        check("p26-t43 population sum", sum(n[0] for _, n in rows), total[0])

# ---- ward: registered / closed / avg days for two years -----------------------------------------
def two_year(sid, report, pg, page, table, title, y1, y2, cat, has_unassigned=False):
    src(sid, report, table, page, title)
    rows, total = ward_rows(pg[page], 8)
    assert len(rows) == 24, (sid, len(rows))
    for w, n in rows:
        r1, r2, c1, _, c2, _, d1, d2 = n
        for y, r, c, d in ((y1, r1, c1, d1), (y2, r2, c2, d2)):
            add(sid, w, y, "complaints_registered_cmp", r, "complaints", cat)
            add(sid, w, y, "complaints_closed", c, "complaints", cat)
            add(sid, w, y, "avg_days_to_close", d, "days", cat)
    for idx, nm in ((0, f"{y1} registered"), (2, f"{y1} closed")):
        check(f"{sid} {nm}", sum(n[idx] for _, n in rows), total[idx])
    add(sid, None, y1, "avg_days_to_close", total[6], "days", cat)
    add(sid, None, y2, "avg_days_to_close", total[7], "days", cat)
    add(sid, None, y1, "complaints_closed", total[2], "complaints", cat)
    add(sid, None, y2, "complaints_closed", total[4], "complaints", cat)
    return rows, total

rows, total = two_year("p26-t3", R26, p26, 13, "Table 3", "Ward-wise Comparison of Total Complaints and Complaints Closed in 2023 and 2025", 2023, 2025, None)
check("p26-t3 2025 registered (+7,641 unassigned)", sum(n[1] for _, n in rows) + 7641, total[1])
check("p26-t3 2025 closed (+34 unassigned)", sum(n[4] for _, n in rows) + 34, total[4])
rows, total = two_year("p25-t45", R25, p25, 73, "Table 45", "Ward-wise Comparison of Total Complaints and Complaints Closed in 2023 and 2024", 2023, 2024, None)
check("p25-t45 2024 registered", sum(n[1] for _, n in rows), total[1]); check("p25-t45 2024 closed", sum(n[4] for _, n in rows), total[4])
rows, total = two_year("p26-t40", R26, p26, 97, "Table 40", "Ward-wise SWM Complaints Registered, Closed and Average Days for Closure in 2021 and 2025", 2021, 2025, "Solid Waste Management (SWM)")
check("p26-t40 2025 registered (+1,432 unassigned)", sum(n[1] for _, n in rows) + 1432, total[1])
rows, total = two_year("p26-t42", R26, p26, 99, "Table 42", "Ward-wise Drainage Complaints Registered, Closed and Average Days for Closure in 2021 and 2025", 2021, 2025, "Drainage")
check("p26-t42 2025 registered (+1,229 unassigned)", sum(n[1] for _, n in rows) + 1229, total[1])

# ---- city: issue x year (T1) and issue closure (T2) ---------------------------------------------
def issue_rows(lines, n_nums):
    out, total = [], None
    for i, ln in enumerate(lines):
        label, nums = split_row(ln)
        if len(nums) != n_nums: continue
        if not label:  # name wrapped around the number line
            label = (lines[i-1].strip() + " " + lines[i+1].strip()).strip()
        if label.startswith(("Grand Total", "Total")): total = nums
        elif re.match(r"^[A-Za-z]", label) and "Complaints" not in label: out.append((label, nums))
    return out, total

src("p26-t1", R26, "Table 1", 11, "Issue Wise Overall Complaints from 2016 to 2025")
rows, total = issue_rows(p26[11], 11)
if total is None:  # the Grand Total numbers sit on the next page
    for pgno in (11, 12):
        for i, ln in enumerate(p26[pgno]):
            if ln.strip().startswith("Grand Total"):
                _, t = split_row(ln if len(split_row(ln)[1]) == 11 else ln + " " + p26[pgno][i+1])
                if len(t) == 11 and total is None: total = t
assert len(rows) == 18, len(rows)
for label, n in rows:
    for y, v in zip(YEARS, n[:10]): add("p26-t1", None, y, "complaints_registered", v, "complaints", label)
if total:
    for i, y in enumerate(YEARS): check(f"p26-t1 {y} issue sum", sum(n[i] for _, n in rows), total[i])

src("p26-t2", R26, "Table 2", 12, "Issue-wise Comparison of Total Complaints and Complaints Closed in 2023 and 2025")
rows, total = issue_rows(p26[12], 8)
assert len(rows) == 18, len(rows)
for label, (r1, r2, c1, _, c2, _, d1, d2) in rows:
    for y, c, d in ((2023, c1, d1), (2025, c2, d2)):
        add("p26-t2", None, y, "complaints_closed", c, "complaints", label)
        add("p26-t2", None, y, "avg_days_to_close", d, "days", label)
check("p26-t2 2025 registered", sum(n[1] for _, n in rows), total[1]); check("p26-t2 2025 closed", sum(n[4] for _, n in rows), total[4])
# city totals per year (from table 43's Total row, already validated)
_, t43 = ward_rows(p26[100], 12)
for y, v in zip(YEARS, t43[1:11]): add("p26-t43", None, y, "complaints_registered", v, "complaints")

# ---- waste: T37 (avg tonnes/day by ward 2021-25) and T11 (2025 detail) ---------------------------
src("p26-t37", R26, "Table 37", 94, "Ward wise Waste Generation from Year 2021 to Year 2025")
rows, total = ward_rows(p26[94], 6)
assert len(rows) == 25, len(rows)
other = next(split_row(l)[1] for l in p26[94] if l.startswith("Other"))
for w, n in rows:
    for y, v in zip(range(2021, 2026), n[:5]): add("p26-t37", w, y, "waste_tonnes_per_day", v, "MT/day")
for i, y in enumerate(range(2021, 2026)):
    add("p26-t37", None, y, "waste_tonnes_per_day", total[i], "MT/day")
    add("p26-t37", None, y, "waste_tonnes_per_day_other_facilities", other[i], "MT/day")
    check(f"p26-t37 {y} ward+other sum", sum((n[i] or 0) for _, n in rows) + (other[i] or 0), total[i], tol=3)

src("p26-t11", R26, "Table 11", 25, "Ward wise Garbage Lifted from January 2025 to December 2025")
n11 = 0
for ln in p26[25]:
    label, nums = split_row(ln)
    w = ward_of(label)
    if w in WARDS and len(nums) == 6:
        pop, slum, mt, per_day, per_cap, share = nums
        add("p26-t11", w, 2011, "slum_population_pct", slum, "%")
        add("p26-t11", w, 2025, "waste_total", mt, "MT")
        add("p26-t11", w, 2025, "waste_per_capita", per_cap, "kg/person/day")
        n11 += 1
assert n11 == 24, n11

# ---- air quality: T29 (city monthly AQI) and T30 (ward days by level, 2025) ----------------------
src("p26-t29", R26, "Table 29", 46, "Average Month-wise AQI from January 2016 to December 2025")
nm = 0
for ln in p26[46]:
    label, nums = split_row(ln)
    if label in MONTHS and len(nums) == 10:
        for y, v in zip(YEARS, nums): add("p26-t29", None, y, "aqi_monthly_avg", v, "AQI", month=MONTHS.index(label) + 1)
        nm += 1
assert nm == 12, nm

src("p26-t30", R26, "Table 30", 47, "Ward and Region wise Average Number of Days with Air Quality Level for the Year 2025")
LEVELS = ["Good", "Satisfactory", "Moderate", "Poor", "Very Poor", "Severe", "No data"]
aq = 0
for ln in p26[47]:
    label, nums = split_row(ln)
    if len(nums) != 8 or "Average" in label: continue
    cands = [t for t in label.split() if t in WARDS]
    if len(cands) != 1: continue
    for lvl, v in zip(LEVELS, nums[:7]): add("p26-t30", cands[0], 2025, "air_quality_days", v, "days", lvl)
    check(f"p26-t30 {cands[0]} days (rounded averages)", sum(nums[:7]), nums[7], tol=2); aq += 1
assert aq == 17, aq   # the report covers 17 wards with monitoring stations

# ---- water (2025 report): T4 supply hours by ward, T7 unfit samples, T1/T2 city supply ----------
src("p25-t4", R25, "Table 4", 14, "Ward wise Number of zones with water supply duration (2024)")
rows, total = ward_rows(p25[14], 10)
assert len(rows) == 24, len(rows)
BANDS = ["<=2 hrs", ">2 to <=4 hrs", ">4 to <=8 hrs", ">8 to <=12 hrs", ">12 to <=18 hrs", ">18 to <24 hrs", "24 hrs", "Not available"]
for w, n in rows:
    add("p25-t4", w, 2024, "water_supply_zones", n[0], "zones")
    add("p25-t4", w, 2024, "water_supply_hours", n[1], "hours/day")
    for b, v in zip(BANDS, n[2:]): add("p25-t4", w, 2024, "water_zones_by_hours", v, "zones", b)
    check(f"p25-t4 {w} zones", sum(n[2:]), n[0])
check("p25-t4 zone sum", sum(n[0] for _, n in rows), total[0])
add("p25-t4", None, 2024, "water_supply_hours", total[1], "hours/day")

src("p25-t7", R25, "Table 7", 17, "Ward Wise Drinking Water Quality Testing Results from 2020 to 2024")
rows, total = ward_rows(p25[17], 5)
assert len(rows) == 24, len(rows)
for w, n in rows:
    for y, v in zip(range(2020, 2025), n): add("p25-t7", w, y, "water_unfit_samples_pct", v, "%")
for y, v in zip(range(2020, 2025), total): add("p25-t7", None, y, "water_unfit_samples_pct", v, "%")

src("p25-t1", R25, "Table 1", 12, "Water Sources, Demand, and Supply Deficit in Mumbai (2023-24), as per the Environmental Status Report")
def grab(prefix):
    for ln in p25[12]:
        if ln.startswith(prefix): return split_row(ln)[1]
vals = {"water_yield_mld": grab("Subtotal (A)")[0], "water_enroute_loss_mld": abs(grab("Enroute + Losses (B)")[0]),
        "water_supply_mld": grab("Total Supply to City")[0], "water_gap_mld": grab("Water Supply Gap")[0]}
for k, v in vals.items(): add("p25-t1", None, 2024, k, v, "MLD")
add("p25-t1", None, 2024, "water_demand_mld", 4664, "MLD")   # printed as "4,6642": 4,664 followed by footnote mark 2
check("p25-t1 yield - loss = supply", vals["water_yield_mld"] - vals["water_enroute_loss_mld"], vals["water_supply_mld"])
check("p25-t1 demand - supply = gap", 4664 - vals["water_supply_mld"], vals["water_gap_mld"])

json.dump({"wards": WARDS, "sources": sources, "records": records}, open(sys.argv[3], "w"), indent=1)
bad = [c for c in checks if not c[3]]
print(f"records={len(records)} sources={len(sources)} checks={len(checks)} failed={len(bad)}")
for c in bad: print("  FAIL", c[:3])
