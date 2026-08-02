"""Build three test PDFs: clean, fake-redacted (black box over live text), unapplied-redact-annot."""
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import pikepdf

SECRET = "742 Evergreen Terrace"

def letter_pdf(path, include_secret=True, cover=False):
    c = canvas.Canvas(path, pagesize=letter)
    c.setFont("Helvetica", 12)
    c.drawString(72, 720, "Dear Sir or Madam,")
    if include_secret:
        c.drawString(72, 700, SECRET)
    c.drawString(72, 680, "Please find enclosed the requested documents.")
    c.drawString(72, 660, "Sincerely, A. Person")
    if cover:
        c.setFillColorRGB(0, 0, 0)
        c.rect(70, 694, 200, 16, fill=1, stroke=0)
    c.save()

letter_pdf("clean.pdf", include_secret=False)
letter_pdf("fake_redacted.pdf", include_secret=True, cover=True)

# Simulate ASD CMap-remnant case: remove the secret from the content stream
# but leave the font subset/ToUnicode untouched.
letter_pdf("orphan_font.pdf", include_secret=True, cover=False)
with pikepdf.open("orphan_font.pdf", allow_overwriting_input=True) as pdf:
    page = pdf.pages[0]
    data = page.Contents.read_bytes()
    data = data.replace(SECRET.encode(), b" " * len(SECRET))
    page.Contents = pdf.make_stream(data)
    pdf.save("orphan_font.pdf")

# Unapplied /Redact annotation
letter_pdf("unapplied.pdf", include_secret=True)
with pikepdf.open("unapplied.pdf", allow_overwriting_input=True) as pdf:
    page = pdf.pages[0]
    annot = pdf.make_indirect(pikepdf.Dictionary(
        Type=pikepdf.Name("/Annot"), Subtype=pikepdf.Name("/Redact"),
        Rect=[70, 694, 270, 710], Contents=pikepdf.String(SECRET)))
    page.Annots = pdf.make_indirect([annot])
    pdf.save("unapplied.pdf")
print("built")
