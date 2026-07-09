from io import BytesIO
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup
import fitz
from docx import Document
from PIL import Image


def extract_text(filename: str, content: bytes, content_type: str):
    name = filename.lower()
    notes=[]
    try:
        if name.endswith('.eml'):
            return extract_eml(content), ["Parsed EML MIME parts."]
        if name.endswith('.pdf'):
            doc = fitz.open(stream=content, filetype='pdf')
            text='\n'.join(page.get_text() for page in doc)
            return text, [f"Extracted text from {len(doc)} PDF pages using PyMuPDF."]
        if name.endswith('.docx'):
            d=Document(BytesIO(content))
            return '\n'.join(p.text for p in d.paragraphs), ["Extracted DOCX paragraphs."]
        if name.endswith(('.png','.jpg','.jpeg','.webp')):
            Image.open(BytesIO(content)).verify()
            return "[IMAGE FILE] OCR/QR requires optional tesseract/pyzbar installation. Image accepted for pipeline.", ["Image validated. OCR/QR extension point ready."]
        return content.decode('utf-8', errors='ignore'), ["Decoded as text."]
    except Exception as e:
        return content.decode('utf-8', errors='ignore'), [f"Fallback text decode after extractor error: {e}"]


def extract_eml(content: bytes):
    msg = BytesParser(policy=policy.default).parsebytes(content)
    chunks=[]
    for k,v in msg.items():
        chunks.append(f"{k}: {v}")
    chunks.append("\n--- BODY ---\n")
    if msg.is_multipart():
        for part in msg.walk():
            ctype=part.get_content_type()
            if ctype in ('text/plain','text/html'):
                payload = part.get_content()
                if ctype == 'text/html':
                    payload = BeautifulSoup(payload, 'html.parser').get_text('\n')
                chunks.append(str(payload))
    else:
        payload = msg.get_content()
        if msg.get_content_type() == 'text/html':
            payload=BeautifulSoup(payload,'html.parser').get_text('\n')
        chunks.append(str(payload))
    return '\n'.join(chunks)
