# Mumbai models

`train.py` trains two models on the published figures in `../praja_tables.json` and writes `results.json`;
`build_ml_sql.py` turns that into `supabase/migrations/0009_mumbai_models.sql`. Both are deterministic.

```bash
pip install scikit-learn numpy
python3 train.py ../praja_tables.json results.json
python3 build_ml_sql.py results.json ../../../supabase/migrations/0009_mumbai_models.sql
```

## Ward groups (clustering)

- **Features, per ward:** complaints per 10,000 residents, % closed, average days to close (all 2025),
  water supply hours and % unfit water samples (2024), waste kg per person per day (2025), slum share (2011).
  Every ward has every feature, so nothing is imputed. Air quality is left out because 7 wards have no station.
- **Method:** standardise, log-transform water hours (ward T has 24 h against a median under 4), k-means
  with 50 restarts. k from 2 to 5 chosen by silhouette score, requiring at least 3 wards per group.
- **Result:** k = 2, silhouette 0.35. Group 2 is A, B, C and H/W. Higher k scored 0.19 to 0.20 or left a
  one-ward group, so the data supports two groups and no more.

## Complaint forecasts (2026)

- **Series:** complaints registered per year, 2016 to 2025, for every ward (all issues, SWM, drainage), every
  city issue, and the city total: 91 series.
- **Methods compared:** last year's value, average of the last three years, straight-line trend.
- **Backtest:** forecast 2022, 2023, 2024 and 2025 from the years before each. The method with the lowest
  mean absolute percentage error across a family of series is used for every series in it.
- **Interval:** 80% of that method's backtest errors fell within ±x%; the range is forecast × (1 ± x).

| Family | Chosen | Error (MAPE) | Last-year baseline | 80% range |
| --- | --- | --- | --- | --- |
| All complaints, by ward | trend | 9.7% | 11.7% | ±14.2% |
| Solid waste, by ward | last year | 23.4% | 23.4% | ±43.6% |
| Drainage, by ward | last year | 22.2% | 22.2% | ±27.4% |
| City, by issue | 3-yr average | 16.5% | 16.8% | ±25.7% |
| City, all issues | trend | 5.8% | 10.6% | ±10.2% |

The city-total result rests on four test forecasts of one series, so treat its edge over the baseline as tentative.
