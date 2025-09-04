import re
import time
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from transformers import pipeline
import uvicorn

app = FastAPI(title="PhishGuard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["*"]
)

# Load model once at startup
classifier = pipeline("zero-shot-classification", model="valhalla/distilbart-mnli-12-1")

LABELS = ["urgent", "fear", "authority", "financial scam", "safe"]

CUES = {
    "urgency": [r"\burgent\b", r"\bimmediately\b", r"\bverify now\b", r"\blast chance\b", r"\bact now\b", r"\baction needed\b", r"\brequires immediate\b", r"\bwithin \d+ hours?\b"],
    "fear": [r"\bsuspended\b", r"\block(ed)?\b", r"\blegal action\b", r"\bunauthorized\b", r"\bcompromis(e|ed)\b", r"\bdata loss\b", r"\baccess.*blocked\b", r"\bflagged\b"],
    "authority": [r"\bCEO\b", r"\badmin(istrator)?\b", r"\bIT support\b", r"\bgovernment\b", r"\bIRS\b", r"\bmicrosoft\b", r"\bsecurity policy\b", r"\bsystems? detected\b"],
    "financial": [r"\bprize\b", r"\blottery\b", r"\bmoney\b", r"\bclaim\b", r"\breward\b", r"\btransfer\b"]
}

SAFE_PHRASES = [
    "mandatory email service announcement",
    "privacy policy", 
    "unsubscribe from these emails"
]

TRUSTED_DOMAINS = ["google.com", "paypal.com", "microsoft.com", "amazon.com", "outlook.com", "office.com"]
BRAND_DOMAINS = {
    "microsoft": ["microsoft.com", "outlook.com", "office.com", "live.com"],
    "google": ["google.com", "gmail.com"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com"]
}
SUSPICIOUS_TLDS = ["xyz", "top", "tk", "gq", "cf", "ml"]
URL_PATTERN = re.compile(r"https?://[^\s<>\"]+|www\.[^\s<>\"]+|\b[a-zA-Z0-9-]+\.[a-z]{2,}\b")

class PredictRequest(BaseModel):
    data: list

def regex_analysis(text):
    score = 0
    findings = []
    
    for category, patterns in CUES.items():
        for pattern in patterns:
            matches = re.findall(pattern, text, re.I)
            if matches:
                findings.append(f"{category} cue detected: {matches[0]}")
                score += 25
    
    # Check for all caps
    if re.search(r"\b[A-Z]{5,}\b", text):
        findings.append("All-caps shouting detected")
        score += 15
    
    # Excessive punctuation
    exclamations = len(re.findall(r"!", text))
    if exclamations > 2:
        findings.append(f"Excessive exclamation marks: {exclamations}")
        score += min(20, exclamations * 5)
    
    return min(100, score), findings

def hf_analysis(text):
    try:
        result = classifier(text, LABELS)
        findings = []
        score = 0
        
        for label, conf in zip(result["labels"], result["scores"]):
            if label != "safe" and conf > 0.3:
                findings.append(f"HuggingFace: {label} (confidence {conf:.2f})")
                score += int(conf * 30)
        
        return min(100, score), findings
    except Exception as e:
        return 0, [f"HF model error: {str(e)}"]

def url_analysis(text):
    urls = URL_PATTERN.findall(text)
    if not urls:
        return 0, [], []
    
    max_score = 0
    all_findings = []
    
    for url in urls:
        score = 0
        findings = []
        
        try:
            if not url.startswith("http"):
                url = f"https://{url}"
            
            parsed = urlparse(url)
            domain = parsed.hostname.lower() if parsed.hostname else ""
            
            # Non-HTTPS
            if not url.startswith("https://"):
                findings.append("Non-HTTPS connection")
                score += 40
            
            # Suspicious TLD
            tld = domain.split(".")[-1] if "." in domain else ""
            if tld in SUSPICIOUS_TLDS:
                findings.append(f"Suspicious TLD: .{tld}")
                score += 35
            
            # IP address
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
                findings.append("IP address used instead of domain")
                score += 50
            
            # Character substitution (0 for o, etc)
            if re.search(r"[0-9]", domain.replace("-", "")):
                findings.append(f"Suspicious character substitution in domain: {domain}")
                score += 45
            
            # Brand mismatch detection
            text_lower = text.lower()
            for brand, legitimate_domains in BRAND_DOMAINS.items():
                if brand in text_lower:
                    if not any(legit in domain for legit in legitimate_domains):
                        findings.append(f"Brand mismatch: mentions {brand} but uses {domain}")
                        score += 60
            
            # Typosquatting check
            for trusted in TRUSTED_DOMAINS:
                if trusted in domain and domain != trusted:
                    findings.append(f"Possible typosquatting: {domain} vs {trusted}")
                    score += 50
            
            max_score = max(max_score, score)
            all_findings.extend([f"{url}: {f}" for f in findings])
            
        except Exception:
            all_findings.append(f"{url}: Invalid URL format")
    
    return min(100, max_score), all_findings, urls

def consolidate_findings(findings):
    consolidated = []
    seen = set()
    
    # Group similar findings
    urgency_count = sum(1 for f in findings if "urgency cue" in f.lower())
    fear_count = sum(1 for f in findings if "fear cue" in f.lower())
    authority_count = sum(1 for f in findings if "authority cue" in f.lower())
    
    if urgency_count > 0:
        consolidated.append(f"Urgency tactics detected ({urgency_count} instances)")
    if fear_count > 0:
        consolidated.append(f"Fear-based language used ({fear_count} instances)")
    if authority_count > 0:
        consolidated.append(f"Authority impersonation detected ({authority_count} instances)")
    
    # Add unique non-cue findings
    for finding in findings:
        if not any(cue in finding.lower() for cue in ["urgency cue", "fear cue", "authority cue"]):
            # Remove URL prefixes for cleaner display
            clean_finding = re.sub(r"^https?://[^\s]+:\s*", "", finding)
            if clean_finding not in seen:
                consolidated.append(clean_finding)
                seen.add(clean_finding)
    
    return consolidated[:6]  # Limit to top 6 findings

def analyze_text(text):
    regex_score, regex_findings = regex_analysis(text)
    hf_score, hf_findings = hf_analysis(text)
    url_score, url_findings, urls = url_analysis(text)
    
    # More aggressive scoring for clear phishing indicators
    total_score = min(100, int(regex_score * 0.5 + hf_score * 0.3 + url_score * 0.8))
    all_findings = regex_findings + hf_findings + url_findings
    
    # Additional checks
    text_lower = text.lower()
    
    # Fake sender detection
    if "from:" in text_lower and any(brand in text_lower for brand in BRAND_DOMAINS.keys()):
        for brand in BRAND_DOMAINS.keys():
            if brand in text_lower:
                # Check if sender domain matches brand
                sender_match = re.search(r"from:.*?([a-zA-Z0-9.-]+\.[a-z]{2,})", text_lower)
                if sender_match:
                    sender_domain = sender_match.group(1)
                    if not any(legit in sender_domain for legit in BRAND_DOMAINS[brand]):
                        all_findings.append(f"Impersonating {brand.title()} with fake domain")
                        total_score += 40
    
    # Safe phrase reduction
    for phrase in SAFE_PHRASES:
        if phrase in text_lower:
            all_findings.append(f"Safe phrase detected: {phrase}")
            total_score = max(0, total_score - 15)
    
    # Consolidate findings
    consolidated_findings = consolidate_findings(all_findings)
    
    risk_level = "High" if total_score >= 60 else "Medium" if total_score >= 30 else "Low"
    
    return {
        "score": total_score,
        "risk_level": risk_level,
        "reasons": consolidated_findings,
        "extracted_urls": urls if urls else "None detected"
    }

@app.post("/predict")
async def predict(request: PredictRequest):
    try:
        text = request.data[0]
        result = analyze_text(text)
        
        # Return in extension format
        is_phishing = result["score"] >= 50
        confidence = min(1.0, result["score"] / 100.0)  # Cap at 100%
        return {
            "data": ["phishing" if is_phishing else "safe", confidence],
            "details": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    print("🛡️ PhishGuard server starting...")
    uvicorn.run(app, host="localhost", port=5000)