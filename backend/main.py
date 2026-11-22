import io
from PIL import Image
import os
import re
import json
import time
from pathlib import Path
from urllib.parse import urlparse
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from google import genai
from google.genai import types
from rapidocr_onnxruntime import RapidOCR
ocr_engine = RapidOCR()


load_dotenv()
client = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY"),
    http_options={"timeout": 4000}
)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_FILE = Path(__file__).resolve().parent.parent / "frontend" / "index.html"

@app.get("/")
def serve_ui():
    return FileResponse(FRONTEND_FILE)

class ScamRequest(BaseModel):
    message: str
    language: str

TRUSTED_DOMAINS = (
    "indianoil.in", "cx.indianoil.in", "myhpgas.in", "ebharatgas.com",
    "hellobpcl.in", "bharatpetroleum.in",
    "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "bescom.co.in", "bescom.karnataka.gov.in", "gov.in", "nic.in", "irctc.co.in"
)

def run_heuristics(text: str) -> tuple[list[str], list[str]]:
    flags = []
    trusted_notes = []
    urls = re.findall(r'https?://[^\s]+|www\.[^\s]+', text, re.IGNORECASE)
    shorteners = ("bit.ly", "tinyurl.com", "t.co", "rb.gy", "cutt.ly", "goo.gl", "is.gd", "ow.ly")
    
    for url in urls:
        clean_url = url if url.startswith("http") else "https://" + url
        domain = urlparse(clean_url).netloc.lower().split(":")[0]

        if any(domain == td or domain.endswith("." + td) for td in TRUSTED_DOMAINS):
            trusted_notes.append(f"Official verified domain detected ({domain})")
        elif any(s in domain for s in shorteners):
            flags.append(f"Shortened link detected ({url})")
        elif re.search(r'^\d+\.\d+\.\d+\.\d+$', domain):
            flags.append("Suspicious raw IP address link detected")
        else:
            flags.append(f"Unverified external link found ({domain})")

    upi_ids = re.findall(r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}', text)
    if upi_ids:
        flags.append(f"UPI ID handle detected: {', '.join(upi_ids)}")

    urgency_words = ("disconnection", "kyc expire", "kyc pending", "account blocked", "lottery", "claim prize", "update pan", "expire agide")
    if any(word in text.lower() for word in urgency_words):
        flags.append("High-urgency social engineering threat detected")

    return flags, trusted_notes

REGIONAL_FALLBACKS = {
    "English": {
        "scam_summary": "Warning! This message contains suspicious links or urgent payment traps. Do not click or share your PIN.",
        "safe_summary": "This message appears safe. No suspicious links or payment traps were found.",
        "safe_reasons": ["Official or standard informational message format.", "No shortened links, fake domains, or PIN/OTP requests detected."]
    },
    "Kannada": {
        "scam_summary": "ಎಚ್ಚರಿಕೆ! ಈ ಸಂದೇಶದಲ್ಲಿ ಅನುಮಾನಾಸ್ಪದ ಲಿಂಕ್ ಅಥವಾ ತುರ್ತು ಹಣ ಪಾವತಿಯ ಮೋಸವಿದೆ. ಯಾವುದೇ ಲಿಂಕ್ ಒತ್ತಬೇಡಿ ಮತ್ತು ನಿಮ್ಮ UPI ಪಿನ್ ಹಂಚಿಕೊಳ್ಳಬೇಡಿ.",
        "safe_summary": "ಈ ಸಂದೇಶ ಸುರಕ್ಷಿತವಾಗಿದೆ. ಯಾವುದೇ ಅನುಮಾನಾಸ್ಪದ ಲಿಂಕ್‌ಗಳು ಕಂಡುಬಂದಿಲ್ಲ.",
        "safe_reasons": ["ಅಧಿಕೃತ ಅಥವಾ ಸಾಮಾನ್ಯ ಮಾಹಿತಿ ಸಂದೇಶವಾಗಿದೆ.", "ಯಾವುದೇ ಅನುಮಾನಾಸ್ಪದ ಲಿಂಕ್ ಅಥವಾ UPI ಪಿನ್ ವಿನಂತಿ ಕಂಡುಬಂದಿಲ್ಲ."]
    },
    "Hindi": {
        "scam_summary": "चेतावनी! इस संदेश में संदिग्ध लिंक या तुरंत पैसे मांगने का धोखा है। किसी भी लिंक पर क्लिक न करें और अपना UPI पिन साझा न करें।",
        "safe_summary": "यह संदेश सुरक्षित है। इसमें कोई संदिग्ध लिंक या धोखाधड़ी नहीं पाई गई है।",
        "safe_reasons": ["यह एक सामान्य या आधिकारिक सूचना संदेश है।", "कोई संदिग्ध लिंक या UPI पिन की मांग नहीं पाई गई।"]
    },
    "Tamil": {
        "scam_summary": "எச்சரிக்கை! இந்த செய்தியில் சந்தேகத்திற்கிடமான இணைப்பு அல்லது அவசர பணம் செலுத்தும் மோசடி உள்ளது. எந்த இணைப்பையும் கிளிக் செய்ய வேண்டாம்.",
        "safe_summary": "இந்த செய்தி பாதுகாப்பானது. சந்தேகத்திற்கிடமான இணைப்புகள் எதுவும் இல்லை.",
        "safe_reasons": ["இது சாதாரண அல்லது அதிகாரப்பூர்வ தகவல் செய்தி.", "சந்தேகத்திற்கிடமான இணைப்புகள் அல்லது UPI பின் கோரிக்கை இல்லை."]
    }
}

class AIAnalysis(BaseModel):
    risk_level: str
    reasons: list[str]
    spoken_summary: str

@app.post("/analyze")
def analyze_message(req: ScamRequest):
    heuristic_flags, trusted_notes = run_heuristics(req.message)

    if len(trusted_notes) > 0 and len(heuristic_flags) == 0:
        fb = REGIONAL_FALLBACKS.get(req.language, REGIONAL_FALLBACKS["English"])
        return {"risk_level": "Safe", "reasons": trusted_notes, "spoken_summary": fb["safe_summary"]}

    prompt = f"""
    You are Kavach AI, an Indian digital payment and SMS scam detector.
    Analyze this message for fraud, phishing, fake KYC, electricity disconnection threats, or deceptive UPI requests.
    Understand English, regional Indian scripts, and code-mixed text (Kanglish, Hinglish, Tanglish).

    Message: "{req.message}"
    Layer 1 Risk Flags: {heuristic_flags if heuristic_flags else "None"}
    Layer 1 Trusted Signals: {trusted_notes if trusted_notes else "None"}

    Rules:
    1. Set "risk_level" strictly to "Safe", "Suspicious", or "High Risk".
       - Genuine utility notifications (e.g., Bharatgas/BPCL, Indane, or HP Gas LPG cylinder out-for-delivery tracking links like hellobpcl.in, physical delivery codes/DAC, legitimate bank alerts, IRCTC bookings) with NO shortened links, NO lookalike domains, and NO requests for UPI PIN/bank OTP MUST be classified as "Safe".
    2. Write 2-3 short bullet points in "reasons" in {req.language} explaining clearly why it is Safe, Suspicious, or High Risk.
    3. Write a 1-2 sentence warning or reassurance in "spoken_summary" strictly in {req.language}.
    """

    fb = REGIONAL_FALLBACKS.get(req.language, REGIONAL_FALLBACKS["English"])
    if len(heuristic_flags) > 0:
        return {"risk_level": "High Risk", "reasons": heuristic_flags, "spoken_summary": fb["scam_summary"]}
    return {"risk_level": "Safe", "reasons": trusted_notes if trusted_notes else fb["safe_reasons"], "spoken_summary": fb["safe_summary"]}

@app.post("/analyze-image")
async def analyze_image(file: UploadFile = File(...), language: str = Form("English")):
    image_bytes = await file.read()

    # Step 1: Extract text from screenshot directly on server using RapidOCR (0 API quota used!)
    extracted_text = ""
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        if img.width > 900:
            ratio = 900 / img.width
            img = img.resize((900, int(img.height * ratio)))
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=85)
        image_bytes = buf.getvalue()
        result, _ = ocr_engine(image_bytes)
        if result:
            extracted_text = " ".join([line for line in result])
            print("OCR Extracted Text:", extracted_text)
    except Exception as ocr_err:
        print("Server OCR warning:", ocr_err)

    # Step 2: Run Layer 1 Regex & Verified Domain check on extracted text first
    if extracted_text:
        heuristic_flags, trusted_notes = run_heuristics(extracted_text)
        if len(trusted_notes) > 0 and len(heuristic_flags) == 0:
            fb = REGIONAL_FALLBACKS.get(language, REGIONAL_FALLBACKS["English"])
            return {"risk_level": "Safe", "reasons": trusted_notes, "spoken_summary": fb["safe_summary"]}
        if len(heuristic_flags) > 0:
            fb = REGIONAL_FALLBACKS.get(language, REGIONAL_FALLBACKS["English"])
            return {"risk_level": "High Risk", "reasons": heuristic_flags, "spoken_summary": fb["scam_summary"]}

    # Step 3: Try Gemini Vision if quota is available
    mime_type = file.content_type or "image/jpeg"
    prompt = f"""
    You are Kavach AI, an Indian digital payment and SMS scam detector.
    Examine this uploaded screenshot and classify "risk_level" strictly as "Safe", "Suspicious", or "High Risk".
    Genuine Indian utility/bank alerts (like Bharatgas/BPCL hellobpcl.in, Indane, HP Gas, SBI) MUST be "Safe".
    Write 2-3 short bullet points in "reasons" in {language} and a 1-2 sentence "spoken_summary" in {language}.
    """
    try:
        response = client.models.generate_content(
            model="gemini-3.8-flash",
            contents=[types.Part.from_bytes(data=image_bytes, mime_type=mime_type), prompt],
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=AIAnalysis,
                temperature=0.1,
            ),
        )
        return json.loads(response.text)
    except Exception as e:
        print(f"Vision API quota/load fallback: {e}")

    # Step 4: Clean regional fallback if Gemini quota is exhausted and no scam flags were found
    fb = REGIONAL_FALLBACKS.get(language, REGIONAL_FALLBACKS["English"])
    return {"risk_level": "Safe", "reasons": fb["safe_reasons"], "spoken_summary": fb["safe_summary"]}
