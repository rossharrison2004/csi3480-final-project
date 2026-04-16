from flask import Flask, render_template, request, jsonify, session, Response
import bcrypt
import secrets
import string
import re
import math

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

COMMON_PASSWORDS = {
    "123456",
    "password",
    "123456789",
    "qwerty",
    "abc123",
    "111111",
    "123123",
    "admin",
    "letmein",
    "welcome",
    "password1"
}


def generate_secure_password(length, use_upper, use_lower, use_digits, use_symbols):
    if length < 4 or length > 64:
        return None, "Password length must be between 4 and 64 characters."

    char_sets = []

    if use_upper:
        char_sets.append(string.ascii_uppercase)
    if use_lower:
        char_sets.append(string.ascii_lowercase)
    if use_digits:
        char_sets.append(string.digits)
    if use_symbols:
        char_sets.append("!@#$%^&*()-_=+[]{};:,.?/")

    if not char_sets:
        return None, "Please select at least one character type."

    all_chars = "".join(char_sets)

    # Ensure at least one character from each selected category
    password_chars = [secrets.choice(char_set) for char_set in char_sets]

    while len(password_chars) < length:
        password_chars.append(secrets.choice(all_chars))

    secrets.SystemRandom().shuffle(password_chars)

    return "".join(password_chars), None


def calculate_entropy(password):
    """Calculate Shannon entropy bits: log2(pool_size) * length"""
    pool = 0
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[!@#$%^&*()\-_=\+\[\]{};:,.?/]", password):
        pool += 24

    if pool == 0:
        return 0

    return round(math.log2(pool) * len(password), 1)


def estimate_crack_time(entropy_bits):
    """
    Estimate crack time assuming 10 billion guesses/second (modern GPU attack).
    Returns a human-readable string.
    """
    guesses_per_second = 1e10
    combinations = 2 ** entropy_bits
    seconds = combinations / guesses_per_second

    if seconds < 1:
        return "less than 1 second"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds // 60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds // 3600)} hours"
    elif seconds < 31536000:
        return f"{int(seconds // 86400)} days"
    elif seconds < 3.154e9:
        return f"{int(seconds // 31536000)} years"
    elif seconds < 3.154e12:
        return f"{int(seconds // 3.154e9)} thousand years"
    elif seconds < 3.154e15:
        return f"{int(seconds // 3.154e12)} million years"
    else:
        return "centuries"


def evaluate_password_strength(password):
    if not password:
        return {
            "label": "Very Weak",
            "score": 0,
            "entropy": 0,
            "crack_time": "instant",
            "feedback": ["Please enter a password."],
            "has_upper": False,
            "has_lower": False,
            "has_digits": False,
            "has_symbols": False,
            "has_length": False
        }

    if password.lower() in COMMON_PASSWORDS:
        return {
            "label": "Very Weak",
            "score": 0,
            "entropy": 0,
            "crack_time": "less than 1 second",
            "feedback": ["This password is too common and unsafe."],
            "has_upper": False,
            "has_lower": False,
            "has_digits": False,
            "has_symbols": False,
            "has_length": False
        }

    score = 0
    feedback = []

    has_upper   = bool(re.search(r"[A-Z]", password))
    has_lower   = bool(re.search(r"[a-z]", password))
    has_digits  = bool(re.search(r"\d", password))
    has_symbols = bool(re.search(r"[!@#$%^&*()\-_=\+\[\]{};:,.?/]", password))
    has_length  = len(password) >= 12

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters.")

    if has_length:
        score += 1

    if has_upper:
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")

    if has_lower:
        score += 1
    else:
        feedback.append("Add at least one lowercase letter.")

    if has_digits:
        score += 1
    else:
        feedback.append("Add at least one number.")

    if has_symbols:
        score += 1
    else:
        feedback.append("Add at least one symbol.")

    if score <= 2:
        label = "Weak"
    elif score <= 4:
        label = "Medium"
    else:
        label = "Strong"

    entropy    = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)

    return {
        "label": label,
        "score": score,
        "entropy": entropy,
        "crack_time": crack_time,
        "feedback": feedback,
        "has_upper": has_upper,
        "has_lower": has_lower,
        "has_digits": has_digits,
        "has_symbols": has_symbols,
        "has_length": has_length
    }


def analyze_bcrypt_hash(hashed):
    """
    Decode the structure of a bcrypt hash string.
    bcrypt format: $2b$<cost>$<22-char salt><31-char hash>
    """
    parts = hashed.split("$")
    # parts = ['', '2b', '12', '<salt+hash>']
    if len(parts) != 4:
        return None

    algorithm    = parts[1]         # e.g. '2b'
    cost_factor  = int(parts[2])    # e.g. 12
    rounds       = 2 ** cost_factor
    salt         = parts[3][:22]    # first 22 chars of the payload
    hash_segment = parts[3][22:]    # remaining 31 chars

    # Estimate time per guess at 1000 bcrypt hashes/sec (typical GPU bcrypt rate)
    bcrypt_hashes_per_sec = 1000
    seconds_per_guess     = 1 / bcrypt_hashes_per_sec

    return {
        "algorithm":         f"bcrypt (${algorithm}$)",
        "cost_factor":       cost_factor,
        "rounds":            f"{rounds:,}",
        "salt":              salt,
        "hash_segment":      hash_segment,
        "seconds_per_guess": seconds_per_guess,
        "why_secure":        (
            f"bcrypt runs {rounds:,} internal iterations per hash. "
            f"At a typical GPU rate of ~{bcrypt_hashes_per_sec:,} hashes/sec, "
            f"each guess takes ~{seconds_per_guess:.4f}s — making brute force "
            f"attacks {rounds // 1000:,}x slower than a simple SHA-256 hash."
        )
    }


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/generate", methods=["POST"])
def generate_password():
    data = request.get_json()

    try:
        length = int(data.get("length", 12))
    except (TypeError, ValueError):
        return jsonify({"error": "Length must be a valid number."}), 400

    use_upper   = data.get("upper", True)
    use_lower   = data.get("lower", True)
    use_digits  = data.get("digits", True)
    use_symbols = data.get("symbols", True)

    password, error = generate_secure_password(
        length,
        use_upper,
        use_lower,
        use_digits,
        use_symbols
    )

    if error:
        return jsonify({"error": error}), 400

    strength = evaluate_password_strength(password)

    # Save to session history
    if "history" not in session:
        session["history"] = []
    session["history"] = ([{"type": "password", "value": password, "label": strength["label"]}]
                          + session["history"])[:20]
    session.modified = True

    return jsonify({
        "password": password,
        "strength": strength
    })


@app.route("/hash", methods=["POST"])
def hash_password():
    data     = request.get_json()
    password = data.get("password", "").strip()

    if not password:
        return jsonify({"error": "Please enter a password to hash."}), 400

    hashed_password = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    strength = evaluate_password_strength(password)
    hash_analysis = analyze_bcrypt_hash(hashed_password)

    # Save to session history
    if "history" not in session:
        session["history"] = []
    session["history"] = ([{"type": "hash", "value": hashed_password, "label": strength["label"]}]
                          + session["history"])[:20]
    session.modified = True

    return jsonify({
        "hash": hashed_password,
        "strength": evaluate_password_strength(password)
    })


@app.route("/verify", methods=["POST"])
def verify_password():
    data        = request.get_json()
    password    = data.get("password", "")
    stored_hash = data.get("hash", "").strip()

    if not password or not stored_hash:
        return jsonify({"error": "Both password and hash are required."}), 400

    try:
        match = bcrypt.checkpw(
            password.encode("utf-8"),
            stored_hash.encode("utf-8")
        )
    except ValueError:
        return jsonify({"error": "Invalid bcrypt hash format."}), 400

    return jsonify({"match": match})


@app.route("/strength", methods=["POST"])
def check_strength():
    data     = request.get_json()
    password = data.get("password", "")

    return jsonify({
        "strength": evaluate_password_strength(password)
    })


@app.route("/history", methods=["GET"])
def get_history():
    return jsonify({"history": session.get("history", [])})


@app.route("/history/clear", methods=["POST"])
def clear_history():
    session["history"] = []
    session.modified = True
    return jsonify({"ok": True})


@app.route("/export", methods=["POST"])
def export_data():
    data  = request.get_json()
    items = data.get("items", [])

    if not items:
        return jsonify({"error": "No items to export."}), 400

    lines = ["Secure Password Toolkit — Export", "=" * 40, ""]
    for item in items:
        label = item.get("label", "")
        value = item.get("value", "")
        kind  = item.get("type", "item")
        lines.append(f"[{kind.upper()}] ({label})")
        lines.append(value)
        lines.append("")

    content = "\n".join(lines)
    return Response(
        content,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment; filename=passwords_export.txt"}
    )


if __name__ == "__main__":
    app.run(debug=True)
    
