import re
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sentence_transformers import SentenceTransformer, util
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
import torch
import uvicorn
import numpy as np

# -----------------------
# FastAPI Setup
# -----------------------
app = FastAPI(title="BaitBlock API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["*"]
)

# -----------------------
# Load multilingual model ONCE
# -----------------------
print("🔄 Loading MiniLM model...")
model = SentenceTransformer("sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2")

# -----------------------
# Train lightweight classifier with multilingual data
# -----------------------
train_texts = [
    # English phishing
    "Click here to claim your free reward",
    "Urgent: Your bank account is locked, verify immediately", 
    "Update your password now to avoid suspension",
    "Your membership will expire in 48 hours, update billing information",
    
    # Hindi phishing
    "आपकी सदस्यता अगले 48 घंटे में समाप्त होने वाली है",  # Your membership will expire in 48 hours
    "कृपया अपनी बिलिंग जानकारी अपडेट करें",  # Please update your billing information
    "आपका खाता अस्थायी रूप से निष्क्रिय हो सकता है",  # Your account may be temporarily deactivated
    
    # Spanish phishing
    "Su cuenta será suspendida, actualice ahora",  # Your account will be suspended, update now
    "Haga clic aquí para reclamar su premio gratis",  # Click here to claim your free prize
    
    # French phishing
    "Votre compte sera suspendu, mettez à jour maintenant",  # Your account will be suspended, update now
    "Cliquez ici pour réclamer votre récompense gratuite",  # Click here to claim your free reward
    
    # Legitimate messages (multilingual)
    "Your Apple Account was used to sign in to iCloud via a web browser",  # English
    "Your Microsoft account sign-in activity from Windows",  # English
    "Amazon: Your order has been shipped",  # English
    "Google: New sign-in from Chrome on Windows",  # English
    "Meeting rescheduled to tomorrow",  # English
    "这是你的课堂笔记",  # Chinese safe: "This is your class notes"
    "आज कक्षा 10 बजे शुरू होगी",  # Hindi safe: "Class will start at 10am today"
    "La reunión ha sido reprogramada para mañana",  # Spanish safe: "Meeting rescheduled for tomorrow"
    "Votre commande a été expédiée avec succès",  # French safe: "Your order has been shipped successfully"
]

train_labels = [
    1, 1, 1, 1,  # English phishing
    1, 1, 1,     # Hindi phishing  
    1, 1,        # Spanish phishing
    1, 1,        # French phishing
    0, 0, 0, 0, 0, 0, 0, 0, 0  # Safe messages
]  # 1=phishing, 0=safe

train_embeddings = model.encode(train_texts)
clf = make_pipeline(StandardScaler(), LogisticRegression())
clf.fit(train_embeddings, train_labels)

print("✅ Model & classifier ready.")

# -----------------------
# Enhanced multilingual label embeddings for semantic explanations
# -----------------------
LABELS = [
    "phishing", "safe", "urgent", "fear", "authority", "financial scam",
    # Multilingual phishing patterns
    "membership expiry urgent action required", 
    "account suspension warning immediate update",
    "billing information update required now",
    "सदस्यता समाप्त अपडेट करें",  # Hindi: membership expired, update
    "खाता निष्क्रिय हो सकता है",   # Hindi: account may be deactivated
    "cuenta suspendida actualizar ahora",  # Spanish: account suspended update now
    "compte suspendu mettre à jour maintenant"  # French: account suspended update now
]
label_embeddings = model.encode(LABELS, convert_to_tensor=True)

# -----------------------
# Helper Classes & Functions
# -----------------------
class PredictRequest(BaseModel):
    data: list

# --- Regex/Heuristic Analysis ---
SUSPICIOUS_KEYWORDS = [
    # English
    "urgent", "verify", "account", "login", "password", "bank", "click", "update", "security", 
    "alert", "confirm", "suspend", "locked", "win", "reward", "expire", "renew", "billing",
    "membership", "deactivate", "temporary", "immediately",
    
    # Hindi (Devanagari)
    "सदस्यता", "नवीनीकरण", "समाप्त", "खाता", "निष्क्रिय", "अपडेट", "बिलिंग", 
    "अस्थायी", "तुरंत", "पासवर्ड", "सत्यापन",
    
    # Spanish
    "urgente", "verificar", "cuenta", "contraseña", "banco", "actualizar", "seguridad",
    "suspender", "bloqueado", "ganar", "premio", "expirar", "renovar", "facturación",
    
    # French
    "urgent", "vérifier", "compte", "mot de passe", "banque", "mettre à jour", "sécurité",
    "suspendre", "verrouillé", "gagner", "récompense", "expirer", "renouveler", "facturation",
    
    # German
    "dringend", "überprüfen", "konto", "passwort", "bank", "aktualisieren", "sicherheit",
    "sperren", "gesperrt", "gewinnen", "belohnung", "ablaufen", "verlängern"
]
SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work", ".support"
]
URL_REGEX = re.compile(r'https?://[^\s]+')

def extract_urls(text):
    return URL_REGEX.findall(text)

def is_suspicious_url(url):
    parsed = urlparse(url)
    reasons = []
    # Not HTTPS
    if parsed.scheme != "https":
        reasons.append("URL is not HTTPS")
    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if parsed.netloc.endswith(tld):
            reasons.append(f"Suspicious TLD: {tld}")
    # IP address in domain
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", parsed.hostname or ""):
        reasons.append("URL uses IP address instead of domain")
    # Shorteners
    if any(short in parsed.netloc for short in ["bit.ly", "tinyurl", "goo.gl", "t.co"]):
        reasons.append("URL uses a known shortener")
    # Misspelled common domains (simple check)
    if re.search(r"paypa1|micros0ft|g00gle|faceb00k|amaz0n", parsed.netloc, re.I):
        reasons.append("Domain looks like a misspelled brand")
    return reasons

def contains_suspicious_keywords(text):
    found = [kw for kw in SUSPICIOUS_KEYWORDS if re.search(rf"\b{kw}\b", text, re.I)]
    return found

def has_obfuscated_content(text):
    # Hidden unicode, zero-width, or excessive symbols
    if re.search(r"[\u200B-\u200D\uFEFF]", text):
        return True
    if re.search(r"[\*\~\^\%]{5,}", text):
        return True
    return False

def has_hidden_text(text):
    # Example: white font on white bg (not visible here, but stub)
    return False

def has_misspellings(text):
    # Simple check: common phishing misspellings
    common = ["recieve", "verfy", "acount", "passwrod", "securty", "immediatly"]
    found = [w for w in common if w in text.lower()]
    return found

# --- Domain Reputation ---
def check_domain_reputation(domain):
    # Trusted domains that should never be flagged as phishing
    trusted_domains = [
        "apple.com", "email.apple.com", "account.apple.com", "support.apple.com",
        "microsoft.com", "outlook.com", "live.com", "hotmail.com",
        "google.com", "gmail.com", "accounts.google.com",
        "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr",
        "paypal.com", "facebook.com", "meta.com", "instagram.com",
        "twitter.com", "x.com", "linkedin.com", "github.com",
        "dropbox.com", "spotify.com", "netflix.com", "adobe.com"
    ]
    
    # Check if domain or any parent domain is trusted
    domain_lower = domain.lower()
    for trusted in trusted_domains:
        if domain_lower == trusted or domain_lower.endswith('.' + trusted):
            return True, "Trusted domain"
    
    # Known bad domains
    bad_domains = ["badsite.tk", "phishingsite.com"]
    if domain_lower in bad_domains:
        return False, "Domain found in phishing blacklist"
    
    return True, ""

# --- Sender Checks ---
def check_sender(sender):
    if not sender:
        return True, ""
    
    # Trusted sender domains
    trusted_senders = [
        "noreply@email.apple.com", "account-security-noreply@accountprotection.microsoft.com",
        "no-reply@accounts.google.com", "auto-confirm@amazon.com",
        "service@paypal.com", "security@facebook.com"
    ]
    
    sender_lower = sender.lower()
    if sender_lower in trusted_senders:
        return True, "Trusted sender"
    
    # Check for trusted sender domains
    trusted_sender_domains = [
        "@apple.com", "@microsoft.com", "@google.com", "@amazon.com", 
        "@paypal.com", "@facebook.com", "@meta.com"
    ]
    
    for domain in trusted_sender_domains:
        if sender_lower.endswith(domain):
            return True, "Trusted sender domain"
    
    # For demo, randomly fail some
    if "fail" in sender_lower:
        return False, "SPF/DKIM/DMARC failed"
    
    return True, ""

# --- Language Detection ---
def detect_language(text: str):
    """Simple language detection based on character patterns"""
    # Count different script characters
    hindi_chars = len([c for c in text if '\u0900' <= c <= '\u097F'])  # Devanagari
    chinese_chars = len([c for c in text if '\u4e00' <= c <= '\u9fff'])  # CJK
    arabic_chars = len([c for c in text if '\u0600' <= c <= '\u06FF'])  # Arabic
    latin_chars = len([c for c in text if c.isalpha() and ord(c) < 256])  # Latin
    
    total_chars = len([c for c in text if c.isalpha()])
    
    if total_chars == 0:
        return "unknown"
    
    # Calculate percentages
    if hindi_chars / total_chars > 0.3:
        return "hindi"
    elif chinese_chars / total_chars > 0.3:
        return "chinese"
    elif arabic_chars / total_chars > 0.3:
        return "arabic"
    elif latin_chars / total_chars > 0.7:
        # Additional heuristics for Latin-script languages
        if any(word in text.lower() for word in ["el", "la", "de", "que", "es", "con", "para"]):
            return "spanish"
        elif any(word in text.lower() for word in ["le", "de", "et", "à", "un", "il", "est", "pour"]):
            return "french"
        elif any(word in text.lower() for word in ["der", "die", "das", "und", "ist", "mit", "für"]):
            return "german"
        else:
            return "english"
    
    return "mixed"

# --- Enhanced Multilingual Semantic Analysis ---
def semantic_analysis(text: str):
    # Detect language
    detected_lang = detect_language(text)
    
    text_embedding = model.encode(text, convert_to_tensor=True)
    cosine_scores = util.cos_sim(text_embedding, label_embeddings)[0]
    findings = []
    score = 0
    label_scores = {LABELS[i]: float(cosine_scores[i]) for i in range(len(LABELS))}
    
    # Language-specific adjustments
    lang_multiplier = 1.0
    if detected_lang in ["hindi", "chinese", "arabic", "spanish", "french", "german"]:
        # For non-English languages, be more sensitive to semantic patterns
        lang_multiplier = 1.2
        findings.append(f"Non-English content detected: {detected_lang}")
    
    if label_scores["phishing"] > label_scores["safe"]:
        phishing_score = int(label_scores["phishing"] * 100 * lang_multiplier)
        score += phishing_score
        findings.append(f"Semantic similarity to phishing ({label_scores['phishing']:.2f})")
    
    # Adjust thresholds for multilingual content
    urgency_threshold = 0.25 if detected_lang != "english" else 0.3
    if label_scores["urgent"] > urgency_threshold:
        urgency_score = int(label_scores["urgent"] * 80 * lang_multiplier)
        score += urgency_score
        findings.append(f"Urgency detected ({label_scores['urgent']:.2f})")
    
    fear_threshold = 0.25 if detected_lang != "english" else 0.3
    if label_scores["fear"] > fear_threshold:
        fear_score = int(label_scores["fear"] * 80 * lang_multiplier)
        score += fear_score
        findings.append(f"Fear tactics detected ({label_scores['fear']:.2f})")
    
    if label_scores["authority"] > 0.3:
        authority_score = int(label_scores["authority"] * 70 * lang_multiplier)
        score += authority_score
        findings.append(f"Authority impersonation detected ({label_scores['authority']:.2f})")
    
    if label_scores["financial scam"] > 0.3:
        financial_score = int(label_scores["financial scam"] * 90 * lang_multiplier)
        score += financial_score
        findings.append(f"Financial scam indicators ({label_scores['financial scam']:.2f})")
    
    # Check multilingual phishing patterns
    multilingual_patterns = [
        "membership expiry urgent action required",
        "account suspension warning immediate update", 
        "billing information update required now",
        "सदस्यता समाप्त अपडेट करें",
        "खाता निष्क्रिय हो सकता है",
        "cuenta suspendida actualizar ahora",
        "compte suspendu mettre à jour maintenant"
    ]
    
    for pattern in multilingual_patterns:
        pattern_idx = LABELS.index(pattern)
        pattern_score = float(cosine_scores[pattern_idx])
        if pattern_score > 0.4:  # Lower threshold for specific patterns
            pattern_penalty = int(pattern_score * 85 * lang_multiplier)
            score += pattern_penalty
            findings.append(f"Multilingual phishing pattern detected ({pattern_score:.2f})")
            break  # Only report one pattern match to avoid double counting
    
    return min(100, score), findings

# --- Main Analysis ---
def analyze_text(text: str, sender: str = None):
    reasons = []
    risk_score = 0
    trusted_bonus = 0

    # Check for trusted sender first
    sender_ok, sender_reason = check_sender(sender)
    if sender_ok and "Trusted" in sender_reason:
        trusted_bonus = -50  # Significant reduction for trusted senders
        reasons.append(f"✓ {sender_reason}")
    elif not sender_ok:
        reasons.append(sender_reason)
        risk_score += 30

    # ML classifier
    embedding = model.encode([text])
    pred = clf.predict(embedding)[0]
    prob = clf.predict_proba(embedding)[0][pred]
    if pred == 1:
        reasons.append("ML model predicts phishing")
        risk_score += int(prob * 100)

    # Semantic
    sem_score, sem_findings = semantic_analysis(text)
    reasons.extend(sem_findings)
    risk_score += sem_score

    # Check URLs and domains
    urls = extract_urls(text)
    has_trusted_domain = False
    for url in urls:
        url_reasons = is_suspicious_url(url)
        if url_reasons:
            reasons.extend([f"URL: {url} - {r}" for r in url_reasons])
            risk_score += 20 * len(url_reasons)
        
        # Domain reputation
        domain = urlparse(url).netloc
        rep_ok, rep_reason = check_domain_reputation(domain)
        if rep_ok and "Trusted" in rep_reason:
            has_trusted_domain = True
            trusted_bonus = max(trusted_bonus, -40)  # Reduce score for trusted domains
            reasons.append(f"✓ URL: {url} - {rep_reason}")
        elif not rep_ok:
            reasons.append(f"URL: {url} - {rep_reason}")
            risk_score += 40

    # Apply trusted domain bonus
    if has_trusted_domain and trusted_bonus == 0:
        trusted_bonus = -40

    # Suspicious keywords (but reduce impact if trusted)
    found_keywords = contains_suspicious_keywords(text)
    if found_keywords:
        keyword_score = 10 * len(found_keywords)
        if trusted_bonus < 0:  # If we have trust indicators, reduce keyword impact
            keyword_score = keyword_score // 2
        reasons.append(f"Suspicious keywords: {', '.join(found_keywords)}")
        risk_score += keyword_score

    # Misspellings
    misspellings = has_misspellings(text)
    if misspellings:
        reasons.append(f"Possible phishing misspellings: {', '.join(misspellings)}")
        risk_score += 10 * len(misspellings)

    # Misspellings
    misspellings = has_misspellings(text)
    if misspellings:
        reasons.append(f"Possible phishing misspellings: {', '.join(misspellings)}")
        risk_score += 10 * len(misspellings)

    # Obfuscation/hidden
    if has_obfuscated_content(text):
        reasons.append("Obfuscated or hidden content detected")
        risk_score += 20
    if has_hidden_text(text):
        reasons.append("Hidden text detected")
        risk_score += 10

    # Apply trusted domain/sender bonus
    risk_score = max(0, risk_score + trusted_bonus)
    
    # Normalize risk score
    risk_score = min(100, risk_score)
    risk_level = "High" if risk_score >= 60 else "Medium" if risk_score >= 30 else "Low"

    return {
        "prediction": "phishing" if risk_score >= 50 else "safe",
        "confidence": round(float(prob), 2),
        "score": risk_score,
        "risk_level": risk_level,
        "reasons": reasons if reasons else ["No strong phishing indicators"]
    }

# -----------------------
# API Endpoint
# -----------------------
class PredictRequest(BaseModel):
    data: list
    sender: str = None  # Optional sender field

@app.post("/predict")
async def predict(request: PredictRequest):
    try:
        text = request.data[0]
        sender = request.sender
        result = analyze_text(text, sender)
        return {
            "data": [result["prediction"], result["confidence"]],
            "details": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    print("BaitBlock multilingual server starting...")
    uvicorn.run(app, host="localhost", port=5000)
