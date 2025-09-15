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
# Train lightweight classifier (demo: replace with real dataset)
# -----------------------
train_texts = [
    "Click here to claim your free reward",
    "Urgent: Your bank account is locked, verify immediately",
    "Update your password now to avoid suspension",
    "这是你的课堂笔记",  # Chinese safe
    "आज कक्षा 10 बजे शुरू होगी",  # Hindi safe: "Class will start at 10am"
    "Meeting rescheduled to tomorrow"
]
train_labels = [1, 1, 1, 0, 0, 0]  # 1=phishing, 0=safe

train_embeddings = model.encode(train_texts)
clf = make_pipeline(StandardScaler(), LogisticRegression())
clf.fit(train_embeddings, train_labels)

print("✅ Model & classifier ready.")

# -----------------------
# Label embeddings for semantic explanations
# -----------------------
LABELS = ["phishing", "safe", "urgent", "fear", "authority", "financial scam"]
label_embeddings = model.encode(LABELS, convert_to_tensor=True)

# -----------------------
# Helper Classes & Functions
# -----------------------
class PredictRequest(BaseModel):
    data: list

# --- Regex/Heuristic Analysis ---
SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "account", "login", "password", "bank", "click", "update", "security", "alert", "confirm", "suspend", "locked", "win", "reward"
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

# --- Domain Reputation (Stub) ---
def check_domain_reputation(domain):
    # TODO: Integrate with PhishTank, OpenPhish, VirusTotal, etc.
    # For demo, flag some known bad domains
    bad_domains = ["badsite.tk", "phishingsite.com"]
    if domain in bad_domains:
        return False, "Domain found in phishing blacklist"
    return True, ""

# --- Sender Checks (Stub) ---
def check_sender(sender):
    # TODO: Integrate with real SPF/DKIM/DMARC checks
    # For demo, randomly fail some
    if sender and "fail" in sender.lower():
        return False, "SPF/DKIM/DMARC failed"
    return True, ""

# --- Semantic Analysis ---
def semantic_analysis(text: str):
    text_embedding = model.encode(text, convert_to_tensor=True)
    cosine_scores = util.cos_sim(text_embedding, label_embeddings)[0]
    findings = []
    score = 0
    label_scores = {LABELS[i]: float(cosine_scores[i]) for i in range(len(LABELS))}
    if label_scores["phishing"] > label_scores["safe"]:
        score += int(label_scores["phishing"] * 100)
        findings.append(f"Semantic similarity to phishing ({label_scores['phishing']:.2f})")
    if label_scores["urgent"] > 0.3:
        score += int(label_scores["urgent"] * 80)
        findings.append(f"Urgency detected ({label_scores['urgent']:.2f})")
    if label_scores["fear"] > 0.3:
        score += int(label_scores["fear"] * 80)
        findings.append(f"Fear tactics detected ({label_scores['fear']:.2f})")
    if label_scores["authority"] > 0.3:
        score += int(label_scores["authority"] * 70)
        findings.append(f"Authority impersonation detected ({label_scores['authority']:.2f})")
    if label_scores["financial scam"] > 0.3:
        score += int(label_scores["financial scam"] * 90)
        findings.append(f"Financial scam indicators ({label_scores['financial scam']:.2f})")
    return min(100, score), findings

# --- Main Analysis ---
def analyze_text(text: str, sender: str = None):
    reasons = []
    risk_score = 0

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

    # Regex/Heuristics
    urls = extract_urls(text)
    for url in urls:
        url_reasons = is_suspicious_url(url)
        if url_reasons:
            reasons.extend([f"URL: {url} - {r}" for r in url_reasons])
            risk_score += 20 * len(url_reasons)
        # Domain reputation
        domain = urlparse(url).netloc
        rep_ok, rep_reason = check_domain_reputation(domain)
        if not rep_ok:
            reasons.append(f"URL: {url} - {rep_reason}")
            risk_score += 40

    # Suspicious keywords
    found_keywords = contains_suspicious_keywords(text)
    if found_keywords:
        reasons.append(f"Suspicious keywords: {', '.join(found_keywords)}")
        risk_score += 10 * len(found_keywords)

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

    # Sender checks
    sender_ok, sender_reason = check_sender(sender)
    if not sender_ok:
        reasons.append(sender_reason)
        risk_score += 30

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
    print("🛡️ BaitBlock multilingual server starting...")
    uvicorn.run(app, host="localhost", port=5000)
