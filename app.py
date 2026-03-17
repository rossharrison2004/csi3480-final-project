from flask import Flask, render_template, request, jsonify
import bcrypt
import secrets
import string
import re

app = Flask(__name__)

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


def evaluate_password_strength(password):
    if not password:
        return {
            "label": "Very Weak",
            "score": 0,
            "feedback": ["Please enter a password."]
        }

    if password.lower() in COMMON_PASSWORDS:
        return {
            "label": "Very Weak",
            "score": 0,
            "feedback": ["This password is too common and unsafe."]
        }

    score = 0
    feedback = []

    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters.")

    if len(password) >= 12:
        score += 1

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add at least one lowercase letter.")

    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add at least one number.")

    if re.search(r"[!@#$%^&*()\-_=\+\[\]{};:,.?/]", password):
        score += 1
    else:
        feedback.append("Add at least one symbol.")

    if score <= 2:
        label = "Weak"
    elif score <= 4:
        label = "Medium"
    else:
        label = "Strong"

    return {
        "label": label,
        "score": score,
        "feedback": feedback
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

    use_upper = data.get("upper", True)
    use_lower = data.get("lower", True)
    use_digits = data.get("digits", True)
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

    return jsonify({
        "password": password,
        "strength": evaluate_password_strength(password)
    })


@app.route("/hash", methods=["POST"])
def hash_password():
    data = request.get_json()
    password = data.get("password", "").strip()

    if not password:
        return jsonify({"error": "Please enter a password to hash."}), 400

    hashed_password = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    return jsonify({
        "hash": hashed_password,
        "strength": evaluate_password_strength(password)
    })


@app.route("/verify", methods=["POST"])
def verify_password():
    data = request.get_json()
    password = data.get("password", "")
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
    data = request.get_json()
    password = data.get("password", "")

    return jsonify({
        "strength": evaluate_password_strength(password)
    })


if __name__ == "__main__":
    app.run(debug=True)
    