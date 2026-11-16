"""Simplify the DataMeet BMC ward boundaries (CC BY-SA 2.5 IN) for web use. Usage: simplify.py in.geojson out.json"""
import json, sys
from shapely.geometry import shape, mapping
from shapely.validation import make_valid
src = json.load(open(sys.argv[1]))
out = {}
for f in src["features"]:
    g = make_valid(shape(f["geometry"]))
    s = g.simplify(0.00025, preserve_topology=True)      # about 25 m
    if s.geom_type == "Polygon":
        s = shape({"type": "MultiPolygon", "coordinates": [mapping(s)["coordinates"]]})
    assert s.geom_type == "MultiPolygon" and s.is_valid, (f["properties"], s.geom_type)
    m = mapping(s)
    m = json.loads(json.dumps(m), parse_float=lambda x: round(float(x), 5))
    out[f["properties"]["name"]] = {"geometry": m, "area_km2_deg": g.area, "centroid": [round(s.centroid.x, 5), round(s.centroid.y, 5)]}
json.dump(out, open(sys.argv[2], "w"), separators=(",", ":"))
print(len(out), "wards", sum(len(json.dumps(v["geometry"])) for v in out.values()) // 1024, "KB")
