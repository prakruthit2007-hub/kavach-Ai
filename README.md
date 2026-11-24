# 🛡️ Kavach AI — Vernacular UPI, SMS & Screenshot Scam Detector

**Kavach AI** protects everyday users and senior citizens across India from digital payment traps, fake KYC warnings, electricity disconnection threats, and deceptive UPI collect requests—in **English, Kannada, Hindi, and Tamil** with native **Text-to-Speech voice alerts**.

## 🌐 Live Prototype & Demo
* **Live App (Render):** `<your-render-url>` *(Note: Hosted on Render free tier; allow ~45 seconds on initial wake-up)*
* **Demo Video:** `<your-demo-video-url>`

## ⚙️ Hybrid 3-Layer Architecture
1. **Layer 1 — Deterministic Heuristic & Domain Engine (Regex + Domain Whitelist):** Instantly flags shortened links (`bit.ly`, `tinyurl.com`), raw IP URLs, UPI collect handles (`@okicici`, `@ybl`), and high-urgency social engineering keywords, while whitelisting verified Indian utility and bank domains (`hellobpcl.in`, `indianoil.in`, `sbi.co.in`, etc.) to eliminate false positives.
2. **Layer 2 — Server-Side OCR + Multimodal Gemini Vision (`RapidOCR` + `gemini-3.8-flash`):** Extracts text directly from uploaded WhatsApp/SMS/QR screenshots and classifies English, regional scripts, and code-mixed text (*Kanglish*, *Hinglish*, *Tanglish*) into plain-language explanations.
3. **Layer 3 — Vernacular Voice Accessibility (`Web Speech API`):** Reads risk alerts aloud in **Kannada (`kn-IN`), Hindi (`hi-IN`), Tamil (`ta-IN`), and Indian English (`en-IN`)** at an accessible pace for elderly users.

## 🚀 Run Locally
