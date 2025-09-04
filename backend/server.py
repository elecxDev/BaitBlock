import re
import time
from urllib.parse import urlparse
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from transformers import pipeline
import uvicorn

app = FastAPI(title="BaitBlock API")

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
    "urgency": [r"\b\d+\s*hours?\b", r"\burgent\b", r"\bimmediately\b", r"\bverify now\b", r"\blast chance\b", r"\bact now\b", r"\baction needed\b", r"\brequires immediate\b", r"\btime.?sensitive\b", r"\bexpir(e|es|ed|ing)\b"],
    "fear": [r"\blimited\b", r"\bsuspended\b", r"\block(ed)?\b", r"\bdisabled?\b", r"\bpermanently\b", r"\blegal action\b", r"\bunauthorized\b", r"\bcompromis(e|ed)\b", r"\bdata loss\b", r"\baccess.*blocked\b", r"\bflagged\b", r"\bfreeze.*account\b", r"\bfraud\b", r"\bin danger\b", r"\bno longer have access\b"],
    "authority": [r"\bCEO\b", r"\badmin(istrator)?\b", r"\bIT support\b", r"\bgovernment\b", r"\bIRS\b", r"\bmicrosoft\b", r"\bsecurity policy\b", r"\bsystems? detected\b", r"\bbank\b", r"\bfraud prevention\b", r"\bpaypal\b", r"\bcustomer\b"],
    "financial": [r"\bprize\b", r"\blottery\b", r"\bmoney\b", r"\bclaim\b", r"\breward\b", r"\btransfer\b", r"\btransaction\b", r"\b\$[0-9,]+\b", r"\baccount.*details\b", r"\bconfirm.*account\b"]
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
    "amazon": ["amazon.com"],
    "apple": ["apple.com", "icloud.com"],
    "bank": ["chase.com", "bankofamerica.com", "wellsfargo.com"]
}

# Common spelling errors in phishing emails
SPELLING_ERRORS = {
    "permanetly": "permanently",
    "recieve": "receive", 
    "seperate": "separate",
    "occured": "occurred",
    "priviledge": "privilege",
    "maintainance": "maintenance",
    "secuirty": "security",
    "verfiy": "verify",
    "accont": "account"
}

# Generic greetings (red flag)
GENERIC_GREETINGS = [
    r"dear\s+(customer|user|client|member|sir|madam)\b",
    r"dear\s+[a-z]+\s+customer\b",
    r"hello\s+(customer|user|client)\b"
]
SUSPICIOUS_TLDS = ["xyz", "top", "tk", "gq", "cf", "ml"]
URL_PATTERN = re.compile(r"\[?(https?://[^\s<>\"\]]+)\]?|\[?(www\.[^\s<>\"\]]+)\]?|\b[a-zA-Z0-9-]+\.[a-z]{2,}\b")

class PredictRequest(BaseModel):
    data: list

def regex_analysis(text):
    score = 0
    findings = []
    text_lower = text.lower()
    
    # Core phishing patterns
    for category, patterns in CUES.items():
        category_matches = 0
        for pattern in patterns:
            matches = re.findall(pattern, text, re.I)
            if matches:
                # Clean up the match display
                clean_match = matches[0][:30] + "..." if len(matches[0]) > 30 else matches[0]
                findings.append(f"{category} cue detected: {clean_match}")
                category_matches += len(matches)
        
        # Score based on category and frequency
        if category_matches > 0:
            if category == "urgency":
                score += min(50, 25 + (category_matches * 15))  # Higher for urgency
            elif category == "fear":
                score += min(45, 20 + (category_matches * 12))
            else:
                score += min(40, 20 + (category_matches * 10))
    
    # Spelling errors (major red flag)
    for wrong, correct in SPELLING_ERRORS.items():
        if wrong in text_lower:
            findings.append(f"Spelling error: '{wrong}' should be '{correct}'")
            score += 35  # High penalty for spelling errors
    
    # Generic greetings
    for greeting_pattern in GENERIC_GREETINGS:
        if re.search(greeting_pattern, text_lower):
            findings.append("Generic greeting detected (not personalized)")
            score += 30
    
    # Brand impersonation without proper domain
    for brand in BRAND_DOMAINS.keys():
        if brand in text_lower:
            # Check if there's a legitimate link
            has_legit_domain = any(domain in text_lower for domain in BRAND_DOMAINS[brand])
            if not has_legit_domain:
                findings.append(f"Claims to be {brand.title()} but no legitimate {brand} links")
                score += 45
    
    # Suspicious phrases
    suspicious_phrases = [
        r"click.*link.*below",
        r"confirm.*account.*details", 
        r"secured?\s+server",
        r"verify.*identity",
        r"update.*information"
    ]
    
    for phrase in suspicious_phrases:
        if re.search(phrase, text_lower):
            findings.append(f"Suspicious phrase: {re.search(phrase, text_lower).group()}")
            score += 25
    
    # All caps shouting
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
        
        # Human-readable label mapping
        label_descriptions = {
            "urgent": "Uses urgent language to pressure action",
            "fear": "Uses fear tactics to manipulate emotions", 
            "authority": "Impersonates authority figures or organizations",
            "financial scam": "Contains financial scam indicators"
        }
        
        for label, conf in zip(result["labels"], result["scores"]):
            if label != "safe" and conf > 0.3:
                # Convert to human-readable format
                description = label_descriptions.get(label, f"Contains {label} indicators")
                confidence_pct = int(conf * 100)
                findings.append(f"AI detected: {description} ({confidence_pct}% confidence)")
                
                # High confidence detections get much higher scores
                if conf > 0.8:
                    score += int(conf * 80)
                elif conf > 0.6:
                    score += int(conf * 60)
                else:
                    score += int(conf * 40)
        
        return min(100, score), findings
    except Exception as e:
        return 0, [f"AI model error: {str(e)}"]

def url_reputation_score(domain):
    """Advanced URL reputation scoring like Guardio/VirusTotal"""
    score = 0
    
    # Domain length heuristics
    if len(domain) > 30:
        score += 25  # Very long domains are suspicious
    elif len(domain) < 5:
        score += 15  # Very short domains can be suspicious
    
    # Subdomain analysis
    parts = domain.split('.')
    if len(parts) > 3:  # Multiple subdomains
        score += 20
    
    # Suspicious patterns in domain
    suspicious_keywords = ['secure', 'verify', 'update', 'login', 'account', 'bank', 'payment']
    for keyword in suspicious_keywords:
        if keyword in domain:
            score += 30
    
    # Random-looking domains (entropy check)
    consonant_clusters = re.findall(r'[bcdfghjklmnpqrstvwxyz]{4,}', domain.lower())
    if consonant_clusters:
        score += 25
    
    # Numbers mixed with letters (common in phishing)
    if re.search(r'[a-z][0-9][a-z]|[0-9][a-z][0-9]', domain.lower()):
        score += 20
    
    return min(100, score)

def url_analysis(text):
    # Simple and robust URL extraction
    urls = []
    
    # Find all potential URLs using simple regex, then clean them
    potential_urls = re.findall(r'(?:https?://|www\.)[^\s<>"\]\)\}]+', text)
    
    for url in potential_urls:
        # Clean up common wrapper characters
        cleaned_url = url.strip('[](){}.,;!?')
        if not cleaned_url.startswith('http'):
            cleaned_url = f"https://{cleaned_url}"
        urls.append(cleaned_url)
    
    # Also check if text contains domain-like patterns
    domain_patterns = re.findall(r'\b[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+\.[a-z]{2,}\b', text)
    for domain in domain_patterns:
        if not any(domain in url for url in urls):  # Avoid duplicates
            urls.append(f"https://{domain}")
    
    # Remove duplicates
    urls = list(set(urls))
    
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
            
            # Critical: Non-HTTPS for sensitive operations
            if not url.startswith("https://") and any(word in text.lower() for word in ['login', 'verify', 'account', 'bank', 'payment']):
                findings.append("Critical: Non-HTTPS for sensitive operations")
                score += 70  # Very high penalty
            elif not url.startswith("https://"):
                findings.append("Non-HTTPS connection")
                score += 35
            
            # Suspicious TLD (highest priority)
            tld = domain.split(".")[-1] if "." in domain else ""
            if tld in SUSPICIOUS_TLDS:
                findings.append(f"High-risk TLD: .{tld}")
                score += 80  # Very high penalty for suspicious TLDs
            
            # IP address instead of domain
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
                findings.append("IP address used instead of domain")
                score += 75
            
            # URL reputation analysis
            reputation_score = url_reputation_score(domain)
            if reputation_score > 30:  # Lower threshold
                findings.append(f"Suspicious domain characteristics (score: {reputation_score})")
                score += reputation_score
            
            # Suspicious domain patterns for corporate impersonation
            corp_patterns = ['intranet', 'internal', 'corporate', 'company', 'staff', 'employee', 'portal', 'admin']
            if any(pattern in domain for pattern in corp_patterns):
                findings.append(f"Corporate impersonation domain: {domain}")
                score += 65
            
            # Check if domain contains suspicious keywords from text context
            text_lower = text.lower()
            if ('review' in text_lower or 'report' in text_lower) and any(word in domain for word in ['review', 'report', 'q3', 'q4', 'performance']):
                findings.append(f"Context-based suspicious domain: {domain}")
                score += 55
            
            # Character substitution (homograph attacks)
            if re.search(r'[0-9]', domain.replace("-", "").replace(".", "")):
                findings.append(f"Character substitution detected: {domain}")
                score += 60
            
            # Brand impersonation (critical)
            text_lower = text.lower()
            for brand, legitimate_domains in BRAND_DOMAINS.items():
                if brand in text_lower:
                    if not any(legit in domain for legit in legitimate_domains):
                        findings.append(f"Brand impersonation: claims {brand} but uses {domain}")
                        score += 85  # Very high penalty
            
            # Typosquatting detection
            for trusted in TRUSTED_DOMAINS:
                if trusted in domain and domain != trusted:
                    # Calculate similarity
                    if len(domain) - len(trusted) <= 3:  # Close match
                        findings.append(f"Typosquatting: {domain} mimics {trusted}")
                        score += 75
            
            # URL shorteners (moderate risk)
            shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly']
            if any(short in domain for short in shorteners):
                findings.append("URL shortener detected")
                score += 40
            
            # Suspicious path patterns
            if parsed.path and re.search(r'/(verify|login|secure|update|account|review|report)/', parsed.path.lower()):
                findings.append("Suspicious URL path detected")
                score += 30
            
            # Suspicious file extensions in URLs
            if re.search(r'\.(exe|zip|rar|scr|bat|com|pif)$', parsed.path.lower()):
                findings.append("Suspicious file extension in URL")
                score += 50
            
            max_score = max(max_score, score)
            all_findings.extend([f"{url}: {f}" for f in findings])
            
        except Exception:
            all_findings.append(f"{url}: Invalid URL format")
            score += 20
    
    return min(100, max_score), all_findings, urls

def consolidate_findings(findings):
    consolidated = []
    seen = set()
    
    # Group similar findings
    urgency_count = sum(1 for f in findings if "urgency cue" in f.lower())
    fear_count = sum(1 for f in findings if "fear cue" in f.lower())
    authority_count = sum(1 for f in findings if "authority cue" in f.lower())
    financial_count = sum(1 for f in findings if "financial cue" in f.lower())
    
    if urgency_count > 0:
        consolidated.append(f"Urgency tactics detected ({urgency_count} instances)")
    if fear_count > 0:
        consolidated.append(f"Fear-based language used ({fear_count} instances)")
    if authority_count > 0:
        consolidated.append(f"Authority impersonation detected ({authority_count} instances)")
    if financial_count > 0:
        consolidated.append(f"Financial scam indicators ({financial_count} instances)")
    
    # Add unique non-cue findings
    for finding in findings:
        if not any(cue in finding.lower() for cue in ["urgency cue", "fear cue", "authority cue", "financial cue"]):
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
    
    # Check if text is too short for reliable analysis
    is_short_text = len(text.split()) < 10
    
    # Professional multi-layered scoring (like Guardio)
    # For text-based phishing (no URLs), regex patterns are primary
    if url_score >= 70:  # High-confidence URL threat
        total_score = min(100, url_score + (regex_score * 0.3) + (hf_score * 0.2))
    elif urls == []:
        # No URLs - text-based phishing detection
        total_score = min(100, int(regex_score * 0.7 + hf_score * 0.5))
    else:
        # Balanced scoring for lower URL risk
        total_score = min(100, int(regex_score * 0.5 + hf_score * 0.4 + url_score * 0.6))
    
    all_findings = regex_findings + hf_findings + url_findings
    
    # Additional checks
    text_lower = text.lower()
    
    # Short text warning
    if is_short_text:
        all_findings.append("Text is very short - analysis may be less reliable")
        # Reduce confidence for short texts
        total_score = int(total_score * 0.7)
    
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
    
    risk_level = "High" if total_score >= 50 else "Medium" if total_score >= 25 else "Low"
    
    return {
        "score": total_score,
        "risk_level": risk_level,
        "reasons": consolidated_findings,
        "extracted_urls": urls if urls else "None detected",
        "short_text": is_short_text
    }

@app.post("/predict")
async def predict(request: PredictRequest):
    try:
        text = request.data[0]
        result = analyze_text(text)
        
        # Professional threat classification
        score = result["score"]
        if score >= 60:
            is_phishing = True  # High confidence
        elif score >= 35:
            is_phishing = True  # Medium confidence
        else:
            is_phishing = False  # Low risk
        
        confidence = min(1.0, result["score"] / 100.0)
        return {
            "data": ["phishing" if is_phishing else "safe", confidence],
            "details": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    print("🛡️ BaitBlock server starting...")
    uvicorn.run(app, host="localhost", port=5000)