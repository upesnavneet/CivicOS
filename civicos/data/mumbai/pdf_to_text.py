import sys, pdfplumber
src, out = sys.argv[1], sys.argv[2]
with pdfplumber.open(src) as pdf, open(out, "w") as f:
    for i, p in enumerate(pdf.pages):
        f.write(f"\n@@PAGE {i+1}\n" + (p.extract_text() or "") + "\n")
