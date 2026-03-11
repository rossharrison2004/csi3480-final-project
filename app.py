from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "Secure Password Toolkit is running."

if __name__ == "__main__":
    app.run(debug=True)

    