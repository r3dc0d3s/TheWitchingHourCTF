from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    Response,
    make_response,
)
import jwt
import datetime


app = Flask(__name__)


@app.after_request
def apply_caching(response):
    return response


app.config["SESSION_COOKIE_HTTPONLY"] = False
app.secret_key = "kada-wa-kada"

LEVEL_PASSWORDS = {
    "level1": "s3cr3t_p4ssw0rd",
    "level2": "5f4dcc3b5aa765d61d8327deb882cf99",
    "level3": "k1n6_c00k135",
}


@app.route("/clear")
def clear():
    session.clear()
    return redirect(url_for("index"))


@app.route("/robots.txt")
def robots():
    if not session.get("level1_complete"):
        return redirect(url_for("level1"))
    file = open("robots.txt", "r")
    return Response("".join(file.readlines()), mimetype="text/plain")


@app.route("/secrets")
def secrets():
    if not session.get("level3_complete"):
        return Response("Forbidden", status=403)
    session.clear()
    return render_template("social.html")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/check_level1", methods=["POST"])
def check_level1():
    password = request.form.get("password")
    if password == LEVEL_PASSWORDS["level1"]:
        session["level1_complete"] = True
        return redirect(url_for("level2"))
    return redirect(url_for("level1"))


@app.route("/level1")
def level1():
    return render_template("level1.html")


@app.route("/level2")
def level2():
    if not session.get("level1_complete"):
        return redirect(url_for("level1"))
    return render_template("level2.html")


@app.route("/check_level2", methods=["POST"])
def check_level2():
    password = request.form.get("password")
    if password == LEVEL_PASSWORDS["level2"]:
        session["level2_complete"] = True
        return redirect(url_for("level3"))
    return redirect(url_for("level2"))


@app.route("/level3")
def level3():
    if not session.get("level2_complete"):
        return redirect(url_for("level2"))
    response = make_response(render_template("level3.html"))
    payload = {
        "repo": "https://github.com/stylesuxx/steganography",
        "password": "x1a6_p00x135",
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
    }
    token = jwt.encode(payload, app.secret_key, algorithm="HS256")
    response.set_cookie("Libum", token, httponly=False)
    return response


@app.route("/check_level3", methods=["POST"])
def check_final():
    password = request.form.get("password")
    if password == LEVEL_PASSWORDS["level3"]:
        session["level3_complete"] = True
        return redirect(url_for("level4"))
    return redirect(url_for("chwiya"))


@app.route("/level4")
def level4():
    if not session.get("level3_complete"):
        return redirect(url_for("level3"))
    return render_template("flag.html")


@app.route("/chwiya")
def chwiya():
    return render_template(
        "chwiya.html",
        image_url="/static/rkez.png",
        redirect_url=url_for("level3"),
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
