import os
import re
import json
import time
from pathlib import Path
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from google import genai
from google.genai import types

load_dotenv()
client = genai.Client(
    api_key=os.getenv("GEMINI_API_KEY"),
    http_options={"timeout": 12000}
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

# --- LAYER 1: HEURISTIC ENGINE (REGEX) ---
def run_heuristics(text: str) -> list[str]:
    flags = []
    urls = re.findall(r'https?://[^\s]+|www\.[^\s]+', text, re.IGNORECASE)
    shorteners = ("bit.ly", "tinyurl.com", "t.co", "rb.gy", "cutt.ly", "goo.gl", "is.gd", "ow.ly")
    
    for url in urls:
        if any(s in url.lower() for s in shorteners):
            flags.append(f"Shortened link detected ({url})")
        elif re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
            flags.append("Suspicious raw IP address link detected")
        else:
            flags.append(f"External link found ({url})")

    upi_ids = re.findall(r'[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}', text)
    if upi_ids:
        flags.append(f"UPI ID handle detected: {', '.join(upi_ids)}")

    urgency_words = ("disconnection", "kyc expire", "kyc pending", "account blocked", "lottery", "claim prize", "click here", "update pan", "pay now", "expire agide")
    if any(word in text.lower() for word in urgency_words):
        flags.append("High-urgency social engineering threat detected")

    return flags

REGIONAL_FALLBACKS = {
    "English": {
        "scam_summary": "Warning! This message contains suspicious links or urgent payment traps. Do not click or share your PIN.",
        "safe_summary": "This message appears safe. No suspicious links or payment traps were found.",
        "safe_reasons": ["No suspicious links or unknown UPI handles detected.", "Standard informational format with no urgent payment demand."]
    },
    "Kannada": {
        "scam_summary": "ಎಚ್ಚರಿಕೆ! ಈ ಸಂದೇಶದಲ್ಲಿ ಅನುಮಾನಾಸ್ಪದ ಲಿಂಕ್ ಅಥವಾ ತುರ್ತು ಹಣ ಪಾವತಿಯ ಮೋಸವಿದೆ. ಯಾವುದೇ ಲಿಂಕ್ ಒತ್ತಬೇಡಿ ಮತ್ತು ನಿಮ್ಮ UPI ಪಿನ್ ಹಂಚಿಕೊಳ್ಳಬೇಡಿ.",
        "safe_summary": "ಈ ಸಂದೇಶ ಸುರಕ್ಷಿತವಾಗಿದೆ. ಯಾವುದೇ ಅನುಮಾನಾಸ್ಪದ ಲಿಂಕ್‌ಗಳು ಕಂಡುಬಂದಿಲ್ಲ.",
        "safe_reasons": ["ಯಾವುದೇ ಅನುಮಾನಾಸ್ಪದ ಲಿಂಕ್ ಅಥವಾ UPI ಐಡಿ ಕಂಡುಬಂದಿಲ್ಲ.", "ತುರ್ತು ಹಣ ಪಾವತಿಯ ಒತ್ತಡವಿಲ್ಲದ ಸಾಮಾನ್ಯ ಸಂದೇಶ."]
    },
    "Hindi": {
        "scam_summary": "चेतावनी! इस संदेश में संदिग्ध लिंक या तुरंत पैसे मांगने का धोखा है। किसी भी लिंक पर क्लिक न करें और अपना UPI पिन साझा न करें।",
        "safe_summary": "यह संदेश सुरक्षित है। इसमें कोई संदिग्ध लिंक या धोखाधड़ी नहीं पाई गई है।",
        "safe_reasons": ["कोई संदिग्ध लिंक या अनजान UPI आईडी नहीं मिली।", "बिना किसी दबाव के सामान्य सूचनात्मक संदेश।"]
    },
    "Tamil": {
        "scam_summary": "எச்சரிக்கை! இந்த செய்தியில் சந்தேகத்திற்கிடமான இணைப்பு அல்லது அவசர பணம் செலுத்தும் மோசடி உள்ளது. எந்த இணைப்பையும் கிளிக் செய்ய வேண்டாம்.",
        "safe_summary": "இந்த செய்தி பாதுகாப்பானது. சந்தேகத்திற்கிடமான இணைப்புகள் எதுவும் இல்லை.",
        "safe_reasons": ["சந்தேகத்திற்கிடமான இணைப்புகள் அல்லது UPI ஐடி எதுவும் இல்லை.", "அவசர பணம் கேட்காத சாதாரண தகவல் செய்தி."]
    }
}

class AIAnalysis(BaseModel):
    risk_level: str
    reasons: list[str]
    spoken_summary: str

# --- TEXT ANALYSIS ENDPOINT ---
@app.post("/analyze")
def analyze_message(req: ScamRequest):
    heuristic_flags = run_heuristics(req.message)

    prompt = f"""
    You are Kavach AI, an Indian digital payment and SMS scam detector.
    Analyze this message for fraud, phishing, fake KYC, electricity disconnection threats, or deceptive UPI requests.
    Understand English, regional Indian scripts, and code-mixed text (Kanglish, Hinglish, Tanglish).

    Message: "{req.message}"
    Layer 1 Flags: {heuristic_flags if heuristic_flags else "None"}

    Rules:
    1. Set "risk_level" strictly to "Safe", "Suspicious", or "High Risk". Legitimate bank alerts with NO links/OTP/PIN requests are "Safe".
    2. Write 2-3 short bullet points in "reasons" in {req.language}.
    3. Write a 1-2 sentence warning/reassurance in "spoken_summary" strictly in {req.language}.
    """

    for attempt in range(2):
        try:
            response = client.models.generate_content(
                model="gemini-3.8-flash",
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=AIAnalysis,
                    temperature=0.2,
                ),
            )
            return json.loads(response.text)
        except Exception as e:
            print(f"Text attempt {attempt + 1} failed: {e}")
            time.sleep(0.5)

    fb = REGIONAL_FALLBACKS.get(req.language, REGIONAL_FALLBACKS["English"])
    if len(heuristic_flags) > 0:
        return {"risk_level": "High Risk", "reasons": heuristic_flags, "spoken_summary": fb["scam_summary"]}
    return {"risk_level": "Safe", "reasons": fb["safe_reasons"], "spoken_summary": fb["safe_summary"]}

# --- SCREENSHOT / IMAGE VISION ANALYSIS ENDPOINT ---
@app.post("/analyze-image")
async def analyze_image(file: UploadFile = File(...), language: str = Form("English")):
    image_bytes = await file.read()
    mime_type = file.content_type or "image/jpeg"

    prompt = f"""
    You are Kavach AI, an Indian digital payment and SMS scam detector.
    Examine this uploaded screenshot (it may be a WhatsApp message, SMS, fake bank KYC notice, or UPI QR/collect payment screen).
    Read all visible text, URLs, sender headers, QR labels, and UPI handles in the image.
    Detect fraud, phishing links, fake customer care numbers, urgency threats, or deceptive "Enter PIN to receive money" traps.

    Rules:
    1. Set "risk_level" strictly to "Safe", "Suspicious", or "High Risk". Genuine payment receipts or normal harmless screenshots are "Safe".
    2. Write 2-3 short, crystal-clear bullet points in "reasons" explaining what you spotted in the screenshot, written strictly in {language}.
    3. Write a calm 1-2 sentence warning or reassurance in "spoken_summary" strictly in {language} for Text-to-Speech.
    """

    for attempt in range(2):
        try:
            response = client.models.generate_content(
                model="gemini-3.8-flash",
                contents=[
                    types.Part.from_bytes(data=image_bytes, mime_type=mime_type),
                    prompt
                ],
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=AIAnalysis,
                    temperature=0.2,
                ),
            )
            return json.loads(response.text)
        except Exception as e:
            print(f"Image attempt {attempt + 1} failed: {e}")
            time.sleep(0.5)

    fb = REGIONAL_FALLBACKS.get(language, REGIONAL_FALLBACKS["English"])
    return {
        "risk_level": "Suspicious",
        "reasons": ["Could not reach Vision AI due to temporary server load. Verify sender and links manually before paying."],
        "spoken_summary": fb["scam_summary"]
    }
