# Mumbai dataset: how it was built

Everything in `supabase/migrations/0008_mumbai_data.sql` is generated from two inputs:

| Input | Source | Licence / terms |
| --- | --- | --- |
| `wards_simplified.json` | DataMeet, Municipal Spatial Data, `Mumbai/BMC_Wards.geojson` | CC BY-SA 2.5 India |
| `praja_tables.json` | Tables read from two Praja Foundation reports (PDFs not included here) | Praja's reports; BMC data obtained under the RTI Act and from BMC's Environment Status Report |

Reports:

- Report on the Status of Civic Services, Environmental and Climate Issues in Mumbai (2026)
- Report on the Status of Civic Issues in Mumbai (2025)

## Rebuild

```bash
pip install pdfplumber shapely
python3 pdf_to_text.py praja2026.pdf p26.txt
python3 pdf_to_text.py praja2025.pdf p25.txt
python3 extract_praja_tables.py p26.txt p25.txt praja_tables.json     # prints "failed=0" when every check passes
python3 simplify_wards.py BMC_Wards.geojson wards_simplified.json
python3 build_sql.py praja_tables.json wards_simplified.json ../../supabase/migrations/0008_mumbai_data.sql
```

## Checks the extractor runs

106 checks, all passing: each ward table's column sums equal the table's own Total row, zone counts add up,
and the water balance is arithmetically consistent.

## Things to know about the published figures

- **Unassigned complaints (2025).** 7,641 complaints (1,432 SWM, 1,229 drainage) have no ward in the report.
  They are in the city totals and not in any ward.
- **Ward P/E.** The 2025 waste tables list a 25th ward, P/E. It has no boundary in the DataMeet file and no
  complaint rows, so it is left out of ward figures. Its tonnage is still inside the city total.
- **Waste "Other".** From 2023 the report lists about 2,000 t/day handled at transfer stations separately
  from wards. Ward figures before and after 2023 are therefore not directly comparable.
- **Air-quality days.** Published for 17 of 24 wards (those with a monitoring station). Rows are station
  averages rounded to whole days, so a ward can add up to 366 or 367 instead of 365.
- **One small disagreement inside the 2026 report.** Drainage complaints closed in 2025 is 15,067 in Table 2
  and 15,063 as the total of Table 42. The city figure uses Table 2.
- **Table 3's title** says "2023 and 2024" but its columns are 2023 and 2025; the values match the 2025 totals
  elsewhere in the report, so they are loaded as 2025. The 2024 ward closure figures come from the 2025 report.
- **Populations** are the 2025 ward figures printed in the report and are used for every year's per-10,000 rate.
