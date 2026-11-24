# 🛡️ Kavach AI — Vernacular UPI, SMS & Screenshot Scam Detector

**Kavach AI** protects everyday users and senior citizens across India from digital payment traps, fake KYC warnings, electricity disconnection threats, money-doubling scams, and deceptive UPI collect requests—in **English, Kannada, Hindi, and Tamil** with native **Text-to-Speech voice alerts**.

## 🌐 Live Prototype & Demo
* **Live Web App (Render):** `<your-render-url>` *(Note: Hosted on Render free tier; allow ~45 seconds for initial wake-up)*
* **2-Minute Demo Video:** `<your-demo-video-url>`

## ⚙️ Hybrid 3-Layer Architecture
1. **Layer 1 — Deterministic Heuristic & Domain Engine:** Instantly flags shortened links (`bit.ly`, `tinyurl.com`), raw IP URLs, UPI collect handles (`@okicici`, `@ybl`), urgency threats, and money-doubling traps, while whitelisting verified Indian utility and bank domains (`hellobpcl.in`, `indianoil.in`, `sbi.co.in`, etc.) to prevent false alarms.
2. **Layer 2 — Server-Side OCR + Multimodal Gemini Vision (`RapidOCR` + `gemini-3.8-flash`):** Extracts text directly from uploaded WhatsApp, SMS, or QR screenshots and classifies English, regional scripts, and code-mixed text (*Kanglish*, *Hinglish*, *Tanglish*) into plain-language explanations.
3. **Layer 3 — Vernacular Voice Accessibility (`Web Speech API`):** Reads risk alerts aloud in **Kannada (`kn-IN`), Hindi (`hi-IN`), Tamil (`ta-IN`), and Indian English (`en-IN`)** at an accessible pace for senior citizens.

## 🚀 Run Locally
```bash
cd backend
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --port 8081
```
