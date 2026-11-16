"""Train CivicOS's two Mumbai models on the published ward figures (../praja_tables.json).

1. Ward groups: k-means on standardised ward indicators; k chosen by silhouette score.
2. Complaint forecasts for 2026: three simple methods compared by a rolling backtest
   (forecast each of 2022-2025 from the years before it). The method with the lowest
   error across a family of series is used for every series in that family. The 80%
   interval comes from that method's own backtest errors.

Usage: python3 train.py ../praja_tables.json results.json
Everything is deterministic (fixed seeds), so re-running gives the same output.
"""
import json, sys
from datetime import date
import numpy as np
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
from sklearn.preprocessing import StandardScaler

data = json.load(open(sys.argv[1]))
WARDS = data["wards"]
R = data["records"]

def val(zone, year, metric, category=None):
    for r in R:
        if r["zone"] == zone and r["year"] == year and r["metric"] == metric and r["category"] == category and r["month"] is None:
            return r["value"]
    return None

# ---------------------------------------------------------------------------
# 1. Ward groups
# ---------------------------------------------------------------------------
FEATURES = [  # (key, label, how to read it, higher is better?)
    ("complaints_per_10k", "Complaints per 10,000 residents (2025)", False),
    ("closed_pct", "Complaints closed, % (2025)", True),
    ("avg_days", "Average days to close (2025)", False),
    ("water_hours", "Water supply, hours per day (2024)", True),
    ("water_unfit_pct", "Drinking-water samples unfit, % (2024)", False),
    ("waste_per_capita", "Waste per person, kg per day (2025)", None),
    ("slum_pct", "Slum population, % (2011)", None),
]
rows = []
for w in WARDS:
    pop = val(w, 2025, "population")
    reg = val(w, 2025, "complaints_registered")
    closed = val(w, 2025, "complaints_closed")
    rows.append({
        "ward": w,
        "complaints_per_10k": round(10000 * reg / pop, 2),
        "closed_pct": round(100 * closed / reg, 2),
        "avg_days": val(w, 2025, "avg_days_to_close"),
        "water_hours": val(w, 2024, "water_supply_hours"),
        "water_unfit_pct": val(w, 2024, "water_unfit_samples_pct"),
        "waste_per_capita": val(w, 2025, "waste_per_capita"),
        "slum_pct": val(w, 2011, "slum_population_pct"),
    })
keys = [f[0] for f in FEATURES]
missing = [(r["ward"], k) for r in rows for k in keys if r[k] is None]
assert not missing, missing      # every ward has every feature, so no imputation is needed
X_raw = np.array([[r[k] for k in keys] for r in rows], dtype=float)
# Water supply hours is very skewed (T = 24 h, most wards 2-6 h); log keeps one ward from dominating.
X_t = X_raw.copy()
X_t[:, keys.index("water_hours")] = np.log(X_t[:, keys.index("water_hours")])
X = StandardScaler().fit_transform(X_t)

scores = {}
for k in range(2, 6):
    km = KMeans(n_clusters=k, n_init=50, random_state=42).fit(X)
    sizes = np.bincount(km.labels_)
    scores[k] = {"silhouette": round(float(silhouette_score(X, km.labels_)), 3), "smallest_group": int(sizes.min())}
# best silhouette among solutions where every group has at least 3 wards
eligible = {k: s for k, s in scores.items() if s["smallest_group"] >= 3}
k_best = max(eligible, key=lambda k: eligible[k]["silhouette"])
km = KMeans(n_clusters=k_best, n_init=50, random_state=42).fit(X)

# z-scores on the untransformed features, for describing groups in plain units
Z = StandardScaler().fit_transform(X_raw)
city_mean = X_raw.mean(axis=0)
groups = []
for g in range(k_best):
    idx = np.where(km.labels_ == g)[0]
    mean_raw = X_raw[idx].mean(axis=0)
    mean_z = Z[idx].mean(axis=0)
    groups.append({"cluster": g, "wards": [rows[i]["ward"] for i in idx],
                   "mean": {k: round(float(v), 2) for k, v in zip(keys, mean_raw)},
                   "z": {k: round(float(v), 2) for k, v in zip(keys, mean_z)}})

def describe(gr):
    """Label a group by its two most distinctive features (largest |z|), in plain words."""
    words = {
        "complaints_per_10k": ("many complaints", "few complaints"),
        "closed_pct": ("high closure", "low closure"),
        "avg_days": ("slow resolution", "fast resolution"),
        "water_hours": ("long water supply", "short water supply"),
        "water_unfit_pct": ("more unfit water", "cleaner water"),
        "waste_per_capita": ("high waste per person", "low waste per person"),
        "slum_pct": ("high slum share", "low slum share"),
    }
    top = sorted(keys, key=lambda k: -abs(gr["z"][k]))[:2]
    return ", ".join(words[k][0 if gr["z"][k] > 0 else 1] for k in top).capitalize()

for gr in groups: gr["label"] = describe(gr)
# number groups by size, largest first, so the ids are stable and readable
groups.sort(key=lambda g: (-len(g["wards"]), g["wards"][0]))
remap = {g["cluster"]: i + 1 for i, g in enumerate(groups)}
for g in groups: g["cluster"] = remap[g["cluster"]]
assignments = []
for i, r in enumerate(rows):
    g = remap[int(km.labels_[i])]
    assignments.append({"ward": r["ward"], "cluster": g,
                        "features": {k: r[k] for k in keys},
                        "z": {k: round(float(v), 2) for k, v in zip(keys, Z[i])}})

cluster_model = {
    "id": "ward-groups-2025",
    "name": "Ward groups",
    "kind": "clustering",
    "method": "k-means (scikit-learn), features standardised; water hours log-transformed",
    "description": "Groups wards that look alike across complaints, resolution, water and waste. Unsupervised: there are no right answers to train against, so it describes patterns rather than predicting anything.",
    "params": {"k": k_best, "features": [{"key": k, "label": l, "higher_is_better": h} for k, l, h in FEATURES],
               "n_init": 50, "random_state": 42, "groups": groups},
    "metrics": {"silhouette": scores[k_best]["silhouette"], "candidates": scores},
    "trained_on": "24 wards; Praja Foundation 2026 report Tables 3, 11, 43; 2025 report Tables 4, 7",
}

# ---------------------------------------------------------------------------
# 2. Complaint forecasts
# ---------------------------------------------------------------------------
YEARS = list(range(2016, 2026))
BACKTEST = [2022, 2023, 2024, 2025]

def series(zone, metric, category):
    ys = [val(zone, y, metric, category) for y in YEARS]
    return ys if all(v is not None for v in ys) else None

def f_naive(hist): return hist[-1]
def f_mean3(hist): return float(np.mean(hist[-3:]))
def f_trend(hist):
    x = np.arange(len(hist)); b, a = np.polyfit(x, hist, 1)
    return max(0.0, a + b * len(hist))
METHODS = {"naive": ("Last year's value", f_naive),
           "mean3": ("Average of the last three years", f_mean3),
           "trend": ("Straight-line trend over all earlier years", f_trend)}

families = {
    "ward_total": [(w, None) for w in WARDS],
    "ward_swm": [(w, "Solid Waste Management (SWM)") for w in WARDS],
    "ward_drainage": [(w, "Drainage") for w in WARDS],
    "city_issue": [(None, c) for c in sorted({r["category"] for r in R if r["metric"] == "complaints_registered" and r["zone"] is None and r["category"]})],
    "city_total": [(None, None)],
}
FAMILY_LABEL = {"ward_total": "All complaints, by ward", "ward_swm": "Solid waste complaints, by ward",
                "ward_drainage": "Drainage complaints, by ward", "city_issue": "City complaints, by issue",
                "city_total": "City complaints, all issues"}

forecasts, family_metrics = [], {}
for fam, keys_ in families.items():
    ser = {(z, c): series(z, "complaints_registered", c) for z, c in keys_}
    ser = {k: v for k, v in ser.items() if v}
    errs = {m: [] for m in METHODS}          # absolute % errors
    abs_errs = {m: [] for m in METHODS}
    for (z, c), ys in ser.items():
        for t in BACKTEST:
            i = YEARS.index(t); hist, actual = ys[:i], ys[i]
            for m, (_, fn) in METHODS.items():
                p = fn(hist)
                abs_errs[m].append(abs(p - actual))
                if actual > 0: errs[m].append(abs(p - actual) / actual)
    mape = {m: round(100 * float(np.mean(e)), 1) for m, e in errs.items()}
    mae = {m: round(float(np.mean(e)), 1) for m, e in abs_errs.items()}
    best = min(mape, key=mape.get)
    q80 = float(np.quantile(errs[best], 0.8))          # 80% of backtest forecasts were within this % of the actual
    family_metrics[fam] = {"label": FAMILY_LABEL[fam], "series": len(ser), "backtest_years": BACKTEST,
                           "chosen": best, "mape_pct": mape, "mae": mae, "interval_pct": round(100 * q80, 1),
                           "baseline": "naive",
                           "improvement_vs_naive_pct": round(100 * (mape["naive"] - mape[best]) / mape["naive"], 1) if mape["naive"] else None}
    for (z, c), ys in ser.items():
        p = METHODS[best][1](ys)
        forecasts.append({"zone": z, "category": c, "year": 2026, "value": round(p),
                          "lower": max(0, round(p * (1 - q80))), "upper": round(p * (1 + q80)), "method": best, "family": fam})

forecast_model = {
    "id": "complaints-forecast-2026",
    "name": "Complaint forecasts",
    "kind": "forecast",
    "method": "Per family of series, the best of three simple methods by rolling backtest; 80% interval from that method's backtest errors",
    "description": "Predicts how many complaints will be registered in 2026, with a range. Built on ten yearly figures per series, so the ranges are wide on purpose.",
    "params": {"methods": {m: l for m, (l, _) in METHODS.items()}, "backtest_years": BACKTEST, "families": family_metrics},
    "metrics": {fam: {"mape_pct": m["mape_pct"][m["chosen"]], "naive_mape_pct": m["mape_pct"]["naive"]} for fam, m in family_metrics.items()},
    "trained_on": "Complaints registered 2016-2025; Praja Foundation 2026 report Tables 1, 39, 41, 43",
}

json.dump({"trained_at": date.today().isoformat(), "models": [cluster_model, forecast_model],
           "clusters": assignments, "forecasts": forecasts}, open(sys.argv[2], "w"), indent=1)

print("k candidates:", scores, "-> k =", k_best)
for g in groups: print(f"  group {g['cluster']} ({len(g['wards'])}): {g['label']}: {' '.join(g['wards'])}")
for fam, m in family_metrics.items():
    print(f"  {fam:14} chosen={m['chosen']:6} MAPE {m['mape_pct']}  interval ±{m['interval_pct']}%  vs naive {m['improvement_vs_naive_pct']}%")
city = next(f for f in forecasts if f["family"] == "city_total")
print("  city 2026:", city)
