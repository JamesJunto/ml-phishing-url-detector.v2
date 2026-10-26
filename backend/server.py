import joblib
import numpy as np
import pandas as pd
import re
import ipaddress
from urllib.parse import urlparse
from flask import Flask, request, jsonify
from flask_cors import CORS


model = joblib.load('phishing_model.joblib')

URL_ONLY_FEATURES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
]

app = Flask(__name__)
CORS(app)

def extract_url_features(url: str) -> dict:


        u = url.strip()

        # URLLength: strip scheme, replace https with http
        normalized = u.replace("https://", "http://", 1) if u.startswith("https://") else u
        url_len = len(normalized)

        # Parse host
        parse_target = u if "://" in u else "http://" + u
        host = urlparse(parse_target).netloc.split("@")[-1].split(":")[0].lower()
        parts = host.split(".")
        tld = parts[-1] if len(parts) >= 2 else ""

        # DomainLength: length of full host (matches CSV)
        domain_len = len(host)

        # IsDomainIP: strict IP check
        try:
            ipaddress.ip_address(host)
            is_ip = 1
        except ValueError:
            is_ip = 0

        # NoOfSubDomain: number of dots - 1 (floored at 0)
        no_sub = max(0, host.count(".") - 1)

        # Obfuscation: same as before (%XX)
        obf_chars = len(re.findall(r"%[0-9A-Fa-f]{2}", u))
        has_obf = int(obf_chars > 0)
        obf_ratio = obf_chars / max(1, url_len)

        # CRITICAL: host without "www." prefix
        host_wo_www = host[4:] if host.startswith("www.") else host

        # NoOfLettersInURL = letters in host_wo_www[:-1]
        sld_and_tld = host_wo_www[:-1]
        n_letters = sum(c.isalpha() for c in sld_and_tld)

        # NoOfDegitsInURL = digits in host_wo_www
        n_digits = sum(c.isdigit() for c in host_wo_www)

        # NoOfOtherSpecialCharsInURL = specials in sld_and_tld
        n_other_special = sum(1 for c in sld_and_tld if not c.isalnum())

        return {
            "URLLength": float(url_len),
            "DomainLength": float(domain_len),
            "IsDomainIP": float(is_ip),
            "TLDLength": float(len(tld)),
            "NoOfSubDomain": float(no_sub),
            "HasObfuscation": float(has_obf),
            "NoOfObfuscatedChar": float(obf_chars),
            "ObfuscationRatio": round(obf_ratio, 3),
            "NoOfLettersInURL": float(n_letters),
            "LetterRatioInURL": round(n_letters / max(1, url_len), 3),
            "NoOfDegitsInURL": float(n_digits),
            "DegitRatioInURL": round(n_digits / max(1, url_len), 3),
            "NoOfEqualsInURL": float(u.count("=")),
            "NoOfQMarkInURL": float(u.count("?")),
            "NoOfAmpersandInURL": float(u.count("&")),
            "NoOfOtherSpecialCharsInURL": float(n_other_special),
            "SpacialCharRatioInURL": round(n_other_special / max(1, url_len), 3),
            "IsHTTPS": float(u.lower().startswith("https://")),
        }

@app.route("/predict", methods=['POST'])
def predict_url():
    body = request.get_json(silent=True) or {}
    url = str(body.get("url", "")).strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400

    parsed_url = urlparse(url)
    if parsed_url.scheme not in {"http", "https"} or not parsed_url.netloc:
          return jsonify({"error": "A valid http or https URL is required"}), 400

    features = extract_url_features(url)
    input_data = pd.DataFrame([features])
    input_data = input_data[URL_ONLY_FEATURES]

    prediction = model.predict(input_data)[0]

    return jsonify({
          "url": url,
          "prediction": int(prediction),
          "phishing": bool(prediction == 0),
          "label": "Phishing" if int(prediction) ==0 else "Legitimate"
      })
