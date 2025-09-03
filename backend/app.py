from flask import Flask, request, jsonify
from transformers import pipeline
import re
import tldextract
from rapidfuzz import fuzz

app = Flask(__name__)

# Load lightweight zero-shot model
classifier = pipeline("zero-shot-classification", model="valhalla/distilbart-mnli-12-1")

# Define categories (psychological manipulation cues)
LABELS = ["urgent", "fear", "authority", "financial scam", "safe"]

# Regex backup for common cues
CUES = {
    "urgency": [r"\burgent\b", r"\bimmediately\b", r"\bverify now\b", r"\blimited time\b"],
    "fear": [r"\bsuspended\b", r"\block(ed)?\b", r"\blegal action\b", r"\bunauthorized\b"],
    "authority": [r"\bCEO\b", r"\badmin\b", r"\bIT support\b", r"\bgovernment\b"],
    "financial": [r"\bwin\b", r"\bprize\b", r"\blottery\b", r"\binvestment\b"]
}

# Trusted domains for comparison
TRUSTED_DOMAINS = ["google.com", "paypal.com", "microsoft.com", "amazon.com", "facebook.com", "apple.com"]

# Suspicious TLDs
SUSPICIOUS_TLDS = ["xyz", "top", "tk", "gq", "cf", "ml"]

# URL regex pattern
URL_PATTERN = re.compile(r"(https?://[^\s]+|www\.[^\s]+|\b[a-zA-Z0-9-]+\.[a-z]{2,}\b)")

def regex_analysis(text):
    findings = []
    score = 0
    for category, patterns in CUES.items():
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                findings.append(f"{category.capitalize()} cue detected: '{pat.strip(r'\\b')}'")
                score += 20
    return score, findings

def huggingface_analysis(text):
    result = classifier(text, LABELS)
    
    # Sort labels by confidence
    label_scores = list(zip(result["labels"], result["scores"]))
    label_scores.sort(key=lambda x: x[1], reverse=True)
    
    # Pick top 2
    top_two = label_scores[:2]
    findings = [f"HuggingFace: {label} (confidence {score:.2f})" for label, score in top_two if label != "safe"]
    
    # Score contribution (sum of top two)
    hf_score = sum(int(score * 30) for label, score in top_two if label != "safe")
    
    return hf_score, findings

def url_analysis(url):
    findings = []
    score = 0
    
    # Extract domain parts
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"
    
    # 1. Check HTTPS
    if not url.lower().startswith("https://"):
        findings.append("Non-HTTPS connection detected")
        score += 25

    # 2. Suspicious TLDs
    if ext.suffix in SUSPICIOUS_TLDS:
        findings.append(f"Suspicious TLD detected: .{ext.suffix}")
        score += 20

    # 3. IP address check
    if re.match(r"^https?://\d+\.\d+\.\d+\.\d+", url):
        findings.append("IP address used instead of domain")
        score += 30

    # 4. Typosquatting
    for trusted in TRUSTED_DOMAINS:
        similarity = fuzz.ratio(domain, trusted)
        if similarity > 80 and domain != trusted:
            findings.append(f"Possible typosquatting: {domain} vs {trusted} (similarity {similarity}%)")
            score += 30
            break
    
    return score, findings

def extract_url_from_text(text):
    """Find first URL or domain-like string in the text"""
    match = URL_PATTERN.search(text)
    return match.group(0) if match else None

@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Phish Detector API is running!"})

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    text = data.get("text", "")

    # Step 1: Analyze text (regex + NLP)
    regex_score, regex_findings = regex_analysis(text)
    hf_score, hf_findings = huggingface_analysis(text)
    text_score = regex_score + hf_score

    # Step 2: Try extracting URL from text
    url = extract_url_from_text(text)
    url_score, url_findings = (0, [])
    if url:
        url_score, url_findings = url_analysis(url)

    # Step 3: Weighted scoring
    text_score = min(text_score, 100) * 0.4   # 40% weight
    url_score = min(url_score, 100) * 0.6     # 60% weight
    total_score = min(100, int(text_score + url_score))

    reasons = regex_findings + hf_findings + url_findings

    # Step 4: Add final label
    if total_score < 30:
        risk_level = "Low"
    elif total_score < 70:
        risk_level = "Medium"
    else:
        risk_level = "High"

    return jsonify({
        "score": total_score,
        "risk_level": risk_level,
        "reasons": reasons,
        "extracted_url": url if url else "None detected"
    })

if __name__ == "__main__":
    app.run(debug=True)