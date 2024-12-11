import os
import random
import shutil
import logging
import sqlite3
import smtplib
import requests
import threading
import validators
import subprocess
from config import CONFIG
from functools import wraps
from flask_session import Session
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timezone, timedelta
from flask_jwt_extended import (
    JWTManager,
    verify_jwt_in_request,
    create_access_token,
    get_jwt_identity,
    get_jwt,
)
from flask import (
    g,
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    jsonify,
    render_template_string,
)
from flask_caching import Cache


######################################################################################
# App Setup Definitions...
######################################################################################
def clear_sessions_and_cache_on_startup():
    # Ensure sessions are cleared on startup
    session_dir = CONFIG.SESSION_DIR
    cache_dir = CONFIG.CACHE_DIR

    if os.path.exists(session_dir):
        shutil.rmtree(session_dir)

    if os.path.exists(cache_dir):
        shutil.rmtree(cache_dir)

    os.makedirs(session_dir, exist_ok=True)
    os.makedirs(cache_dir, exist_ok=True)


def clear_session_excluding_flash():
    # Remove specific keys instead of clearing the entire session
    keys_to_keep = ["_flashes"]
    session_keys = list(session.keys())

    for key in session_keys:
        if key not in keys_to_keep:
            session.pop(key)


def clear_flash():
    # Clear all flash messages
    session.pop("_flashes", None)


def initialize_database():
    db_path = CONFIG.DATABASE_URI
    if not os.path.exists(db_path):
        logging.info(
            "Database does not exist. Creating a new one from migrations.sql..."
        )

        try:
            with open(CONFIG.DB_MIGRATIONS_FILE, "r") as migration_file:
                migrations_sql = migration_file.read()

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.executescript(migrations_sql)
            conn.commit()
            conn.close()
            logging.info("Database created successfully.")

        except Exception as error:
            logging.error(f"Error creating database: {error}")
            raise

    else:
        logging.info("Database already exists.")


clear_sessions_and_cache_on_startup()

app = Flask(__name__)
app.config.from_object(CONFIG)

# Initialize Flask-Session
Session(app)

# Initialize JWT manager
jwt = JWTManager(app)

# Initialize application cache
cache = Cache(app)

# Add os functions to the template context for SSTI Vulnerability
app.jinja_env.globals.update({"system": subprocess.check_output, "os": os})

# Configure logging setup
logging.basicConfig(
    filename=CONFIG.FUNDAPP_LOG_PATH,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


# Database connection utility
def get_db_connection():
    conn = sqlite3.connect(CONFIG.DATABASE_URI)
    conn.row_factory = sqlite3.Row
    return conn


# Utility Functions
def generate_otp():
    # Generate a random 4-digit OTP
    return str(random.randint(0, 9999)).zfill(4)


def log_event(event):
    logging.info(f"{datetime.now(timezone.utc)}: {event}")


def gethost(request):
    return f"{request.scheme}://{request.host}"


def is_valid_domain(domain):
    try:
        domain = domain.replace("http://", "")
        domain = domain.replace("https://", "")
        # validators.domain returns True if valid, otherwise False
        return True if validators.domain(domain) else False
    except Exception as error:
        return False
        pass


def is_valid_url(url):
    # Check if URL starts with http/https and contains 'localhost' or '127.0.0.1'
    return url.startswith(("http://", "https://")) and any(
        x in url for x in ["localhost", "127.0.0.1"]
    )


def sendmail(RECIPIENT, USERNAME, OTP):
    def email_task():
        template = """Hi {},\nYour OTP verification code is {}.\nPlease ignore this email if you didn't request an OTP.\n\nRegards,\nFundAPP""".format(
            USERNAME, OTP
        )

        # Define HTML version of the template
        html_template = """
        <html>
            <body>
                <p>Hi {},</p>
                <p>Your OTP verification code is <b>{}</b>.</p>
                <p>Please ignore this email if you didn't request an OTP.</p>
                <br>
                <p>Regards,</p>
                <p>FundAPP</p>
            </body>
        </html>
        """.format(
            USERNAME, OTP
        )

        SUBJECT = "Verification OTP for FundAPP"

        # Setup the MIME
        msg = MIMEMultipart("alternative")
        msg["From"] = CONFIG.MAIL_EMAIL  # Your Gmail address
        msg["To"] = RECIPIENT
        msg["Subject"] = SUBJECT

        # Attach both plain text and HTML parts
        msg.attach(MIMEText(template, "plain"))
        msg.attach(MIMEText(html_template, "html"))

        try:
            mail = smtplib.SMTP(CONFIG.MAIL_SERVER, CONFIG.MAIL_PORT, timeout=30)
            mail.starttls()
            mail.login(CONFIG.MAIL_EMAIL, CONFIG.MAIL_APP_KEY)

            # Send the email
            mail.sendmail(CONFIG.MAIL_EMAIL, RECIPIENT, msg.as_string())

            logging.info(f"Email sent successfully: fundAPP TO {RECIPIENT}")

        except Exception as error:
            logging.error(f"Failed to send email: {error}")
            print(f"Failed to send email: {error}")

        finally:
            mail.quit()

    # Start the email task in a separate thread
    email_thread = threading.Thread(target=email_task)
    email_thread.start()


######################################################################################
# JWT Handler Definitions...
######################################################################################


def jwt_required_from_session(endpoint_type):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            try:
                # First try to get the token from the header
                verify_jwt_in_request()  # This will raise an exception if JWT is invalid
                claims = get_jwt()  # Extract JWT claims
                g.role = claims.get("role")  # Extract 'role' from the JWT claims
            except Exception:
                # If no token in headers, check the session for the token
                token = session.get("access_token")
                if token:
                    headers = {"Authorization": f"Bearer {token}"}
                    try:
                        # Manually verify the JWT token from the session
                        verify_jwt_in_request(optional=True)
                        claims = get_jwt()
                        g.role = claims.get(
                            "role"
                        )  # Extract 'role' from the JWT claims
                    except Exception:
                        if endpoint_type == "web":
                            flash("Invalid Session. Please log in.", "danger")
                            return redirect(url_for("login"))
                        if endpoint_type == "api":
                            return (
                                jsonify({"message": "Invalid or Expired JWT Token"}),
                                401,
                            )
                else:
                    # No token in the session
                    if endpoint_type == "web":
                        flash("Invalid Session. Please log in.", "danger")
                        return redirect(url_for("login"))
                    if endpoint_type == "api":
                        return jsonify({"message": "Missing JWT Token"}), 401

            return fn(*args, **kwargs)

        return decorator

    return wrapper


######################################################################################
# App Error Handler Definitions...
######################################################################################


@app.errorhandler(401)
def unauthorized_error(error):
    try:
        response = jsonify(request.get_json())
        message = response.get("message", "Unauthorized Access. Please log in first.")
        flash(message, "danger")
        return redirect(url_for("login"))

    except Exception as error:
        return redirect(url_for("login"))


@app.errorhandler(404)
def unauthorized_error(error):
    try:
        message = "The requested endpoint was not found."
        flash(message, "danger")
        return redirect(url_for("index"))

    except Exception as error:
        return redirect(url_for("index"))


######################################################################################
# Routes Definitions...
######################################################################################


@app.route("/", methods=["GET"])
def index():
    host = gethost(request=request)

    try:
        # Interact with the API endpoint /api/v1/
        api_response = requests.get(f"{host}/api/v1/")
        html_content = None

        if api_response.status_code == 200:
            response_body = api_response.json()
            html_content = response_body.get("html_content")

        return render_template("index.html", html_content=html_content)

    except requests.exceptions.RequestException as error:
        logging.error(f"Error in index route when calling /api/v1/: {error}")

        return render_template("index.html", html_content=None)


@app.route("/login", methods=["GET", "POST"])
def login():
    clear_session_excluding_flash()

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Interact with the API endpoint /api/v1/perform_login
        host = gethost(request=request)

        api_response = requests.post(
            f"{host}/api/v1/login_user",
            json={"username": username, "password": password},
        )

        if api_response.status_code == 200:
            data = api_response.json()
            # print("ACCESS TOKEN",data)
            session["username"] = username
            session["role"] = data["role"]
            session["user_id"] = data["user_id"]

            # Store JWT token in the session
            session["access_token"] = data["access_token"]

            flash("Login successful!", "success")
            return redirect(url_for("index"))

        else:
            error_message = api_response.json().get("message")
            flash(error_message, "danger")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        jsonObject = {"username": username, "email": email, "password": password}

        if "role" in request.form:
            jsonObject["role"] = request.form["role"]

        # Interact with the API endpoint /api/v1/register_user
        host = gethost(request=request)
        api_response = requests.post(
            f"{host}/api/v1/register_user",
            json=jsonObject,
        )

        if api_response.status_code == 201:
            flash("Registration successful!", "success")
            return redirect(url_for("login"))
        else:
            flash("Registration failed. Please try again.", "danger")

    return render_template("register.html")


@app.route("/admin", methods=["GET"])
@jwt_required_from_session(endpoint_type="web")
def admin():
    role = session.get("role")

    if not (role) or role != "admin":
        flash("Action Denied - Admins only!", "danger")
        return redirect(url_for("index"))

    # Interact with the API endpoint /api/v1/get_users
    host = gethost(request=request)
    token = session.get("access_token")
    headers = {"Authorization": f"Bearer {token}"}
    api_response = requests.get(f"{host}/api/v1/get_users", headers=headers)
    response_body = api_response.json()

    if api_response.status_code == 200:
        users = response_body.get("users")
        count = response_body.get("count")
        return render_template("admin.html", count=count, users=users)
    else:
        message = response_body.get("message", "Unable to fetch users.")
        flash(message, "danger")
        return redirect(url_for("admin"))


@app.route("/debug", methods=["GET"])
def debug():
    count = 0
    users = None

    # Interact with the API endpoint /api/v1/_debug
    host = gethost(request=request)
    api_response = requests.get(f"{host}/api/v1/_debug")
    response_body = api_response.json()

    if api_response.status_code == 200:
        users = response_body.get("users")
        count = response_body.get("count")
    else:
        message = response_body.get("message", "Unable to fetch users.")
        flash(message, "danger")

    return render_template("debug.html", count=count, users=users)


@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    try:
        if request.method == "GET":
            return render_template("feedback.html")

        if request.method == "POST":
            username = request.form["username"]
            feedback_message = request.form["feedback_message"]

            # Interact with the API endpoint /api/v1/feedback
            host = gethost(request=request)
            api_response = requests.post(
                f"{host}/api/v1/feedback",
                json={"username": username, "feedback_message": feedback_message},
            )

            feedbacks = None
            response_body = api_response.json()

            template = (
                """<p><b>Full Name:</b> %s </p>""" % username
                + """<p><b>Message:</b> %s</p> """ % feedback_message
            )

            if api_response.status_code == 200:
                message = response_body.get("message", "Thank you for the feedback!")
                feedback_message = response_body.get("feedback_message")
                feedbacks = response_body.get("feedbacks")
                flash(message, "success")

            else:
                message = response_body.get("message", "Unable to send feedback.")
                flash(message, "danger")

            rendered_template = render_template(
                "feedback.html",
                template=template,
                feedbacks=feedbacks,
            )

            return render_template_string(rendered_template)

    except Exception as error:
        # print(error)
        clear_flash()
        flash("Unable to send feedback.", "danger")
        return render_template("feedback.html")


@app.route("/transactions", methods=["GET"])
@jwt_required_from_session(endpoint_type="web")
def transactions():
    user_id = session.get("user_id")

    if request.args.get("user_id"):
        # Get the user_id from the query parameters
        user_id = request.args.get("user_id")

    if not user_id:
        flash("User ID is required.", "danger")
        return render_template("transactions.html")

    # Interact with the API endpoint /api/v1/get_transactions
    host = gethost(request=request)
    user_id = str(user_id)
    token = session.get("access_token")
    headers = {"Authorization": f"Bearer {token}"}

    # Make a request to the API, passing the user_id as a GET parameter
    api_response = requests.get(
        f"{host}/api/v1/get_transactions", headers=headers, params={"user_id": user_id}
    )
    response_body = api_response.json()

    if api_response.status_code == 200:
        transactions = response_body.get("transactions_list")
        count = len(transactions)
        role = response_body.get("role")

        if not (role) or role == "user":
            role = session.get("role")
        else:
            role = role

        return render_template(
            "transactions.html",
            role=role,
            count=count,
            transactions=transactions,
            user_id=user_id,
        )
    else:
        error_message = response_body.get("message", "Unable to fetch transactions.")
        flash(error_message, "danger")
        return render_template("transactions.html")


@app.route("/transfer", methods=["GET", "POST"])
@jwt_required_from_session(endpoint_type="web")
def transfer():
    try:
        users = []
        host = gethost(request=request)
        token = session.get("access_token")
        headers = {"Authorization": f"Bearer {token}"}

        # Interact with the API endpoint /api/v1/get_users
        api_response = requests.get(f"{host}/api/v1/get_users", headers=headers)
        response_body = api_response.json()
        if api_response.status_code == 200:
            users = response_body.get("users")
            username = session["username"]
            balance = None

            for user in users:
                if user["username"] == username:
                    balance = user["balance"]
                    break

            if not balance:
                balance = 0.00

            users = [user for user in users if user["username"] != username]

        else:
            flash("Unable to fetch users.", "danger")
            return redirect(url_for("transfer"))

        if request.method == "POST":
            receiver_id = request.form["receiver_id"]
            amount = float(request.form["amount"])

            # Interact with the API endpoint /api/v1/transfer
            api_response = requests.post(
                f"{host}/api/v1/transfer",
                json={"receiver_id": receiver_id, "amount": amount},
                headers=headers,
            )

            response_body = api_response.json()

            if api_response.status_code == 200:
                flash("Transfer successful!", "success")
                balance = response_body.get("balance")
                print(balance, type(balance))
                if balance <= 0:
                    balance = "0.00"
                else:
                    balance = round(balance, 2)

            else:
                message = response_body.get(
                    "message", "Transfer failed. Please try again."
                )
                flash(message, "danger")

        return render_template(
            "transfer.html", balance=str(balance).zfill(2), users=users
        )

    except Exception as error:
        # print(error)
        clear_flash()
        flash("Unable to perform transfer.", "danger")
        return render_template("transfer.html", balance=round(balance, 2), users=users)


@app.route("/change_password", methods=["GET", "POST"])
@jwt_required_from_session(endpoint_type="web")
def change_password():
    if request.method == "GET":
        user_id = session.get("user_id")

        # Optionally get the user_id from query parameters if provided
        if request.args.get("user_id"):
            user_id = request.args.get("user_id")

        if not user_id:
            flash("User ID is required.", "danger")

        return render_template("change_password.html", user_id=user_id)

    if request.method == "POST":
        # Interact with the API endpoint /api/v1/users/<user_id>/change_password
        host = gethost(request=request)
        token = session.get("access_token")
        headers = {"Authorization": f"Bearer {token}"}

        user_id = request.form.get("user_id")
        new_password = request.form.get("new_password")

        # Input Validation
        if not user_id:
            flash("User ID is required.", "danger")
            return render_template("change_password.html")

        if not new_password:
            flash("New password is required.", "danger")
            return render_template("change_password.html")

        # Interact with the API endpoint /api/v1/users/<user_id>/change_password
        api_response = requests.patch(
            f"{host}/api/v1/users/{user_id}/change_password",
            json={"new_password": new_password},
            headers=headers,
        )

        response_body = api_response.json()

        # Handle the API response
        if api_response.status_code == 200:
            message = response_body.get("message", "Password changed successfully!")
            flash(message, "success")
            return redirect(url_for("logout"))

        else:
            message = response_body.get("message", "Unable to change password!")
            flash(message, "danger")

        return render_template("change_password.html")


@app.route("/reset_password", methods=["GET", "POST"])
def web_reset_password():
    if request.method == "GET":
        return render_template("reset_password.html")

    if request.method == "POST":
        valid_email = session.get("valid_email", False)
        valid_otp = session.get("valid_otp", False)

        # Interact with the API endpoint /api/v1/users/<user_id>/change_password
        host = gethost(request=request)
        user_id = session.get("user_id")
        new_password = request.form.get("new_password")

        # Input Validation
        if not user_id:
            clear_session_excluding_flash()
            flash("Invalid Session Detected", "danger")
            return render_template("reset_password.html")

        if not new_password:
            flash("New password is required.", "danger")
            return render_template(
                "reset_password.html", valid_email=valid_email, valid_otp=valid_otp
            )

        # Interact with the API endpoint /api/v1/users/<user_id>/reset_password
        api_response = requests.patch(
            f"{host}/api/v1/users/{user_id}/reset_password",
            json={"new_password": new_password},
        )

        response_body = api_response.json()

        # Handle the API response
        if api_response.status_code == 200:
            message = response_body.get("message", "Password reset successfully!")
            flash(message, "success")
            return redirect(url_for("login"))

        else:
            clear_session_excluding_flash()
            message = response_body.get("message", "Unable to reset password!")
            flash(message, "danger")

        return render_template("reset_password.html")


@app.route("/resetdb", methods=["GET"])
@jwt_required_from_session(endpoint_type="web")
def web_reset_db():
    try:
        role = session.get("role")

        if not (role) or role != "admin":
            flash("Action Denied - Admins only!", "danger")
            return redirect(url_for("index"))

        # Call the API endpoint to reset the database
        host = gethost(request=request)
        token = session.get("access_token")
        headers = {"Authorization": f"Bearer {token}"}
        api_response = requests.get(f"{host}/api/v1/resetdb", headers=headers)
        response_body = api_response.json()

        if api_response.status_code == 200:
            flash(
                response_body.get(
                    "message", "Database reset successfully! Please login again"
                ),
                "success",
            )

            # Redirect to the /login endpoint after resetting current user session.
            return redirect(url_for("login"))

        else:
            flash(
                f"Failed to reset database: {response_body.get('message', 'Unknown error')}",
                "danger",
            )

        # Redirect to the index page
        return redirect(url_for("index"))

    except Exception as error:
        logging.error(f"Error in web_reset_db: {error}")
        flash("An error occurred while trying to reset the database.", "danger")

        return redirect(url_for("index"))


@app.route("/logout")
def logout():
    clear_session_excluding_flash()
    flash("You have been logged out!", "success")
    return redirect(url_for("index"))


@app.route("/bugs", methods=["GET", "POST"])
def web_bugs():
    try:
        if request.method == "POST":
            title = request.form.get("title")
            description = request.form.get("description")

            # Mapping origin with title for Missing CORS Attack...
            origin = title

            # Initialize a flag for the template
            flag = None
            content = None

            host = gethost(request=request)

            if origin and is_valid_domain(origin):
                headers = {"Origin": origin}
                api_response = requests.post(
                    f"{host}/api/v1/bugs",
                    headers=headers,
                    json={"title": title, "description": description},
                )

            else:
                api_response = requests.post(
                    f"{host}/api/v1/bugs",
                    json={"title": title, "description": description},
                )

            response_body = api_response.json()

            if api_response.status_code == 200:
                flag = response_body.get("flag")
                content = response_body.get("content")
                message = response_body.get(
                    "message", "Bug report submitted successfully!"
                )
                flash(message, "success")

            else:
                message = response_body.get("message", "Unable to submit bug report!")
                flash(message, "danger")

            return render_template("bugs.html", flag=flag, content=content)

        # Render the form for GET requests
        return render_template("bugs.html")

    except Exception as error:
        logging.error(f"Error in web_bugs: {error}")
        flash("An error occurred while submitting your report.", "danger")
        return render_template("bugs.html")


@app.route("/add_user", methods=["GET", "POST"])
@jwt_required_from_session(endpoint_type="web")
def add_user():
    role = session.get("role")

    if not (role) or role != "admin":
        flash("Action Denied - Admins only!", "danger")
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        email = request.form["email"]
        role = request.form["role"]

        # Interact with the API endpoint /api/v1/add_user
        host = gethost(request=request)
        token = session.get("access_token")
        headers = {"Authorization": f"Bearer {token}"}

        api_response = requests.post(
            f"{host}/api/v1/add_user",
            json={
                "username": username,
                "password": password,
                "email": email,
                "role": role,
            },
            headers=headers,
        )

        response_body = api_response.json()

        if api_response.status_code == 201:
            flash(response_body.get("message", "User added successfully!"), "success")
            return redirect(url_for("admin"))
        else:
            flash(
                response_body.get("message", "Failed to add user. Please try again."),
                "danger",
            )
            return redirect(url_for("admin"))

    return render_template("add_user.html")


@app.route("/update_user", methods=["GET", "POST"])
@jwt_required_from_session(endpoint_type="web")
def web_update_user():
    role = session.get("role")

    if not (role) or role != "admin":
        flash("Action Denied - Admins only!", "danger")
        return redirect(url_for("index"))

    if request.method == "GET":
        user_id = request.args.get("user_id")

        if not user_id:
            flash("User ID is required.", "danger")
            return redirect(url_for("admin"))

        # Interact with the API endpoint /api/v1/get_user
        host = gethost(request=request)
        token = session.get("access_token")
        headers = {"Authorization": f"Bearer {token}"}

        # Make a request to the API, passing the user_id as a GET parameter
        api_response = requests.get(
            f"{host}/api/v1/get_user", headers=headers, params={"user_id": user_id}
        )
        response_body = api_response.json()

        user = response_body.get("user")

        if not user:
            message = response_body.get("message", "Unable to fetch user information")
            flash(message, "danger")
            return redirect(url_for("admin"))

        return render_template("update_user.html", user=user)

    if request.method == "POST":
        request_data = request.form
        user_id = request_data.get("id")
        username = request_data.get("username")
        email = request_data.get("email")
        role = request_data.get("role")

        # Interact with the API endpoint /api/v1/update_user
        host = gethost(request=request)
        token = session.get("access_token")
        headers = {"Authorization": f"Bearer {token}"}
        api_response = requests.put(
            f"{host}/api/v1/update_user",
            json={
                "user_id": user_id,
                "username": username,
                "email": email,
                "role": role,
            },
            headers=headers,
        )

        response_body = api_response.json()

        if api_response.status_code == 200:
            message = response_body.get("message", "User updated successfully!")
            flash(message, "success")

            return redirect(url_for("admin"))

        else:
            message = response_body.get("message", "Unable to update user!")
            flash(message, "danger")

            return redirect(url_for("admin"))


@app.route("/delete_user", methods=["GET"])
@jwt_required_from_session(endpoint_type="web")
def web_delete_user():
    role = session.get("role")
    if not (role) or role != "admin":
        flash("Action Denied - Admins only!", "danger")
        return redirect(url_for("index"))

    user_id = request.args.get("user_id")

    if not user_id:
        flash("User ID is required.", "danger")
        return redirect(url_for("admin"))

    # Interact with the API endpoint /api/v1/delete_user
    host = gethost(request=request)
    token = session.get("access_token")
    headers = {"Authorization": f"Bearer {token}"}

    api_response = requests.delete(
        f"{host}/api/v1/delete_user", params={"user_id": user_id}, headers=headers
    )
    response_body = api_response.json()

    if api_response.status_code == 200:
        message = response_body.get("message", "User deleted successfully.")
        flash(message, "success")

    elif api_response.status_code == 403:
        message = response_body.get("message", "Action Denied - Admins only!")
        flash(message, "danger")

    else:
        message = response_body.get("message", "Unable to delete user.")
        flash(message, "danger")

    return redirect(url_for("admin"))  # Redirect back to the admin page


@app.route("/validate_email", methods=["POST"])
def web_validate_email():
    valid_email = False
    email = request.form["email"]

    # Interact with the API endpoint /api/v1/validate_email
    host = gethost(request=request)
    api_response = requests.post(f"{host}/api/v1/validate_email", json={"email": email})
    response_body = api_response.json()

    if api_response.status_code == 200:
        message = response_body.get("message", "Email validated successfully.")
        user_id = response_body.get("user_id")
        valid_email = True
        session["user_id"] = user_id
        session["valid_email"] = valid_email
        flash(message, "success")

    else:
        message = response_body.get("message", "Invalid Email!")
        flash(message, "danger")

    return render_template("reset_password.html", valid_email=valid_email)


@app.route("/validate_otp", methods=["POST"])
def web_validate_otp():
    user_id = session.get("user_id")
    valid_email = session.get("valid_email", False)

    if not user_id:
        clear_session_excluding_flash()
        flash("Invalid Session Detected", "danger")
        return render_template("reset_password.html")

    valid_otp = False
    otp = request.form["otp"]

    if not otp:
        if not valid_email:
            clear_session_excluding_flash()
            flash("Invalid Session Detected", "danger")
        else:
            flash("OTP is required.", "danger")

        return render_template("reset_password.html", valid_email=valid_email)

    # Interact with the API endpoint /api/v1/validate_otp
    host = gethost(request=request)
    api_response = requests.post(
        f"{host}/api/v1/validate_otp", json={"user_id": user_id, "otp": otp}
    )
    response_body = api_response.json()

    if api_response.status_code == 200:
        message = response_body.get("message", "OTP validated successfully.")
        valid_otp = True
        session["valid_otp"] = valid_otp
        flash(message, "success")

    else:
        message = response_body.get("message", "OTP does not match!")
        flash(message, "danger")

    return render_template(
        "reset_password.html",
        valid_email=valid_email,
        valid_otp=valid_otp,
    )


######################################################################################
# API Definitions...
######################################################################################


@app.route("/api/v1/", methods=["GET"])
def api_index():
    try:
        # HTML content to be returned by the API endpoint
        html_content = """<h1>Welcome to the Fund Transfer App</h1><p>Explore our services and manage your funds.</p>"""

        return jsonify({"html_content": html_content}), 200

    except Exception as error:
        logging.error(f"Error in api_index: {error}")
        return jsonify({"message": "Failed loading index view"}), 500


@app.route("/api/v1/register_user", methods=["POST"])
def api_register_user():
    try:
        data = request.get_json()
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")

        if not username or not email or not password:
            return (
                jsonify({"message": "Username, email, and password are required"}),
                400,
            )

        # Default role to "user" if not provided
        role = data.get("role", "user")

        # Insert user with the role (either provided or default "user")
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, email, password, role, balance) VALUES (?, ?, ?, ?, 100)",
            (username, email, password, role),
        )
        conn.commit()
        conn.close()

        return jsonify({"message": "User registered successfully"}), 201

    except Exception as error:
        logging.error(f"Error in api_register_user: {error}")
        return jsonify({"message": "User registration failed"}), 500


@app.route("/api/v1/login_user", methods=["POST"])
def api_login_user():
    try:
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"message": "Username and password are required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if not user:
            return jsonify({"message": "Invalid Credentials!"}), 404

        if user["password"] == password:
            access_token = create_access_token(
                identity=user["id"], additional_claims={"role": user["role"]}
            )
            return (
                jsonify(
                    {
                        "user_id": user["id"],
                        "role": user["role"],
                        "access_token": access_token,
                    }
                ),
                200,
            )

        else:
            return jsonify({"message": "Invalid Credentials!"}), 401

    except Exception as error:
        logging.error(f"Error in api_login_user: {error}")

        return jsonify({"message": "Login failed"}), 500


@app.route("/api/v1/get_users", methods=["GET"])
@jwt_required_from_session(endpoint_type="api")
def api_get_users():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, role, balance FROM users")
        users = cursor.fetchall()
        conn.close()

        users_list = [
            {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "role": user["role"],
                "balance": round(float(user["balance"]), 2),
            }
            for user in users
        ]

        count = len(users_list)

        return jsonify({"count": count, "users": users_list}), 200

    except Exception as error:
        logging.error(f"Error in api_get_users: {error}")

        return jsonify({"message": "Unable to fetch users"}), 500


@app.route("/api/v1/_debug", methods=["GET"])
def api_debug():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, email, password, role, balance FROM users")
        users = cursor.fetchall()
        conn.close()

        users_list = [
            {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "password": user["password"],
                "role": user["role"],
                "balance": round(float(user["balance"]), 2),
            }
            for user in users
        ]

        count = len(users_list)

        return jsonify({"count": count, "users": users_list}), 200

    except Exception as error:
        logging.error(f"Error in api_debug: {error}")

        return jsonify({"message": "Unable to fetch users"}), 500


@app.route("/api/v1/feedback", methods=["POST"])
def api_feedback():
    try:
        data = request.get_json()
        username = data.get("username")
        feedback_message = data.get("feedback_message")

        if not username or not feedback_message:
            return (
                jsonify({"message": "Username, message required."}),
                400,
            )

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            f"SELECT username, balance FROM users WHERE username = '{username}'"
        )

        feedbacks = cursor.fetchall()

        # Convert the Row objects into a list of dictionaries
        feedbacks = [dict(row) for row in feedbacks]

        conn.close()

        return (
            jsonify(
                {
                    "message": "Thank you for the feedback!",
                    "feedbacks": feedbacks,
                    "feedback_message": feedback_message,
                }
            ),
            200,
        )

    except Exception as error:
        logging.error(f"Error in api_feedback: {error}")

        return jsonify({"message": "Unable to handle the feedback."}), 500


@app.route("/api/v1/get_user", methods=["GET"])
@jwt_required_from_session(endpoint_type="api")
def api_get_user():
    try:
        # Get the user_id from the query parameters
        user_id = request.args.get("user_id")

        if not user_id:
            return jsonify({"message": "User ID is missing"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, email, role, balance FROM users where id = ?",
            (user_id,),
        )
        data = cursor.fetchone()
        conn.close()

        if not data:
            return jsonify({"message": "User does not exist!"}), 404

        user = {
            "id": data["id"],
            "username": data["username"],
            "email": data["email"],
            "role": data["role"],
            "balance": data["balance"],
        }
        return jsonify({"user": user}), 200

    except Exception as error:
        logging.error(f"Error in api_get_user: {error}")

        return jsonify({"message": "Unable to fetch user information"}), 500


@app.route("/api/v1/get_transactions", methods=["GET"])
@jwt_required_from_session(endpoint_type="api")
def api_get_transactions():
    try:
        # Get the user_id from the query parameters
        user_id = request.args.get("user_id")

        if not user_id:
            return jsonify({"message": "User ID is missing"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # Fetch transactions where the user is either sender or receiver
        cursor.execute(
            "SELECT * FROM transactions WHERE sender_id = ? OR receiver_id = ? ORDER BY timestamp DESC",
            (user_id, user_id),
        )
        transactions = cursor.fetchall()
        conn.close()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, email, role, balance FROM users where id = ?",
            (user_id,),
        )
        user = cursor.fetchone()
        user_role = user["role"] if user else "user"
        conn.close()

        transactions_list = [
            {
                "id": transaction["id"],
                "timestamp": transaction["timestamp"],
                "sender_id": str(transaction["sender_id"]),
                "sender_name": transaction["sender_name"],
                "receiver_id": str(transaction["receiver_id"]),
                "receiver_name": transaction["receiver_name"],
                "amount": round(float(transaction["amount"]), 2),
            }
            for transaction in transactions
        ]

        return jsonify({"role": user_role, "transactions_list": transactions_list}), 200

    except Exception as error:
        logging.error(f"Error in api_get_transactions: {error}")

        return jsonify({"message": "Unable to fetch transactions"}), 500


@app.route("/api/v1/update_user", methods=["PUT"])
@jwt_required_from_session(endpoint_type="api")
def api_update_user():
    try:
        # Access the role from the JWT claims
        role = g.get("role")

        if not (role) or role != "admin":
            return jsonify({"message": "Action Denied - Admins only!"}), 403

        data = request.get_json()
        user_id = data.get("user_id")
        new_username = data.get("username")
        new_email = data.get("email")
        new_role = data.get("role", "user")

        if not user_id:
            return jsonify({"message": "User ID is required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        update_fields = []
        update_values = []

        if new_username:
            update_fields.append("username = ?")
            update_values.append(new_username)

        if new_email:
            update_fields.append("email = ?")
            update_values.append(new_email)

        if new_role:
            update_fields.append("role = ?")
            update_values.append(new_role)

        if not update_fields:
            return jsonify({"message": "No fields to update"}), 400

        update_values.append(user_id)
        query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
        cursor.execute(query, update_values)
        conn.commit()
        conn.close()

        return jsonify({"message": "User updated successfully!"}), 200

    except Exception as error:
        logging.error(f"Error in api_update_user: {error}")

        return jsonify({"message": "Unable to update user!"}), 500


@app.route("/api/v1/delete_user", methods=["DELETE"])
@jwt_required_from_session(endpoint_type="api")
def api_delete_user():
    try:
        # Access the role from the JWT claims
        role = g.get("role")

        if not (role) or role != "admin":
            return jsonify({"message": "Action Denied - Admins only!"}), 403

        # Get the user_id from query parameters
        user_id = request.args.get("user_id")

        if not user_id:
            return jsonify({"message": "Bad Request - User ID is required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()

        return jsonify({"message": "User deleted successfully"}), 200

    except Exception as error:
        logging.error(f"Error in api_delete_user: {error}")

        return jsonify({"message": "Unable to delete user"}), 500


@app.route("/api/v1/add_user", methods=["POST"])
@jwt_required_from_session(endpoint_type="api")
def api_add_user():
    try:
        # Access the role from the JWT claims
        role = g.get("role")

        if not (role) or role != "admin":
            return jsonify({"message": "Action Denied - Admins only!"}), 403

        data = request.get_json()
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        role = data.get("role")

        if not username or not password or not email or not role:
            return (
                jsonify(
                    {"message": "Username, password, email, and role are required."}
                ),
                400,
            )

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))

        if cursor.fetchone():
            return jsonify({"message": "User already exists."}), 409

        cursor.execute(
            "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
            (username, password, email, role),
        )
        conn.commit()
        conn.close()

        return jsonify({"message": "User added successfully."}), 201

    except Exception as error:
        logging.error(f"Error in api_add_user: {error}")

        return jsonify({"message": "User addition failed."}), 500


@app.route("/api/v1/transfer", methods=["POST"])
@jwt_required_from_session(endpoint_type="api")
def api_perform_transfer():
    try:
        data = request.get_json()
        sender_id = get_jwt_identity()
        receiver_id = data.get("receiver_id")
        amount = float(data.get("amount"))

        invalidFractionFlag = False

        if "." in str(amount):
            fractional_value = str(amount).split(".")[1]

            if len(fractional_value) > 2:
                invalidFractionFlag = True

        if not receiver_id or (amount <= 0) or (amount < 0.01) or invalidFractionFlag:
            return (
                jsonify(
                    {"message": "Receiver and a valid positive amount are required"}
                ),
                400,
            )

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT username, balance FROM users WHERE id = ?", (sender_id,))

        sender = cursor.fetchone()
        if not sender:
            return jsonify({"message": "Sender does not exist"}), 404

        sender_name = sender["username"]
        sender_balance = sender["balance"]

        if sender_balance < amount:
            return jsonify({"message": "Insufficient balance"}), 400

        cursor.execute(
            "SELECT id, username, balance FROM users WHERE id = ?", (receiver_id,)
        )

        receiver = cursor.fetchone()
        if not receiver:
            return jsonify({"message": "Receiver does not exist"}), 404

        receiver_name = receiver["username"]
        final_balance = sender_balance - amount

        epsilon = 1e-9  # Small tolerance threshold
        if (abs(final_balance) < epsilon) or (sender_balance == amount):
            new_sender_balance = 0

        else:
            new_sender_balance = final_balance

        new_receiver_balance = receiver["balance"] + amount

        cursor.execute(
            "UPDATE users SET balance = ? WHERE id = ?", (new_sender_balance, sender_id)
        )

        cursor.execute(
            "UPDATE users SET balance = ? WHERE id = ?",
            (new_receiver_balance, receiver_id),
        )

        cursor.execute(
            "INSERT INTO transactions (sender_id, sender_name, receiver_id, receiver_name, amount, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (
                sender_id,
                sender_name,
                receiver_id,
                receiver_name,
                amount,
                datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )

        conn.commit()
        conn.close()

        return (
            jsonify({"message": "Transfer successful!", "balance": new_sender_balance}),
            200,
        )

    except Exception as error:
        logging.error(f"Error in api_transfer: {error}")

        return jsonify({"message": "Transfer failed"}), 500


@app.route("/api/v1/bugs", methods=["POST"])
def api_bugs():
    try:
        # Get the path, origin from the query parameters
        data = request.get_json()
        title = data.get("title")
        description = data.get("description")

        if not title or not description:
            return jsonify({"message": "Bug's title and description is required"}), 400

        flag = None
        content = None

        origin_header = request.headers.get("Origin")

        if origin_header and title in origin_header:
            flag = r"{M!55!NG_C0R5_4TT4CK_5UCC355FUL}"

        # For SSRF Attack...
        host = description

        if is_valid_url(host):
            ssrf_response = requests.get(host)
            content = f"{ssrf_response.text}"

        return (
            jsonify(
                {
                    "message": "Bug report submitted successfully!",
                    "flag": flag,
                    "content": content,
                }
            ),
            200,
        )

    except Exception as error:
        logging.error(f"Error in api_bugs: {error}")
        return jsonify({"message": "Unable to submit bug report!"}), 500


@app.route("/api/v1/users/<int:user_id>/change_password", methods=["PATCH"])
@jwt_required_from_session(endpoint_type="api")
def api_change_password(user_id):
    try:
        data = request.get_json()
        new_password = data.get("new_password")

        if not user_id:
            return jsonify({"message": "User ID is required."}), 400

        if not new_password:
            return jsonify({"message": "New password is required."}), 400

        # Update the password in the database
        conn = get_db_connection()
        cursor = conn.cursor()

        query = "UPDATE users SET password = ? WHERE id = ?"
        cursor.execute(query, (new_password, user_id))
        conn.commit()

        # Close the database connection
        conn.close()

        return jsonify({"message": "Password changed successfully!"}), 200

    except Exception as error:
        logging.error(f"Error in api_change_password: {error}")
        return jsonify({"message": "Unable to change password!"}), 500


@app.route("/api/v1/validate_email", methods=["POST"])
def api_validate_email():
    try:
        data = request.get_json()
        email = data.get("email")

        if not email:
            return jsonify({"message": "Email is required"}), 400

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id,username FROM users where email = ?",
            (email,),
        )
        data = cursor.fetchone()
        conn.close()

        if not data:
            return jsonify({"message": "User does not exist!"}), 404

        user_id = data["id"]
        username = data["username"].capitalize()

        try:
            otp = generate_otp()

            with open(f"flask_session/{user_id}-OTP.txt", "w") as file:
                file.write(otp)

        except Exception as error:
            raise Exception(error)

        sendmail(USERNAME=username, RECIPIENT=email, OTP=otp)

        return (
            jsonify(
                {
                    "user_id": user_id,
                    "message": "OTP sent via Email.",
                }
            ),
            200,
        )

    except Exception as error:
        logging.error(f"Error in api_validate_email: {error}")

        return (
            jsonify({"message": "Unable to validate email"}),
            500,
        )


@app.route("/api/v1/validate_otp", methods=["POST"])
def api_validate_otp():
    try:
        data = request.get_json()
        otp = data.get("otp")
        user_id = data.get("user_id")
        hardCodedOTP = 8008

        if not user_id:
            return jsonify({"message": "Invalid Session Detected"}), 400

        if not otp:
            return jsonify({"message": "OTP is required"}), 400

        validOTP = None

        try:
            with open(f"flask_session/{user_id}-OTP.txt", "r") as file:
                fileData = file.read()
                validOTP = str(fileData).strip()
        except Exception as error:
            # Hard-coded OTP in case of any error...
            validOTP = 8008

        if not (validOTP) or (len(validOTP) == 0):
            return jsonify({"message": "Request OTP first!"}), 400

        if not (str(otp) == str(validOTP) or str(otp) == str(hardCodedOTP)):
            return jsonify({"message": "OTP does not match!"}), 404

        os.remove(f"flask_session/{user_id}-OTP.txt")

        return jsonify({"message": "OTP validated successfully."}), 200

    except Exception as error:
        logging.error(f"Error in api_validate_otp: {error}")

        return (
            jsonify({"message": "Unable to fetch user information"}),
            500,
        )


@app.route("/api/v1/users/<int:user_id>/reset_password", methods=["PATCH"])
def api_reset_password(user_id):
    try:
        data = request.get_json()
        new_password = data.get("new_password")

        if not user_id:
            return jsonify({"message": "User ID is required."}), 400

        if not new_password:
            return jsonify({"message": "New password is required."}), 400

        # Update the password in the database
        conn = get_db_connection()
        cursor = conn.cursor()

        query = "UPDATE users SET password = ? WHERE id = ?"
        cursor.execute(query, (new_password, user_id))
        conn.commit()

        # Close the database connection
        conn.close()

        return jsonify({"message": "Password reset successfully!"}), 200

    except Exception as error:
        logging.error(f"Error in api_reset_password: {error}")
        return jsonify({"message": "Unable to reset password!"}), 500


# API endpoint to reset the database
@app.route("/api/v1/resetdb", methods=["GET"])
def api_reset_db():
    try:
        # Connect to the SQLite database
        conn = get_db_connection()
        cursor = conn.cursor()

        # Read the migration SQL file
        if not os.path.exists(CONFIG.DB_MIGRATIONS_FILE):
            return jsonify({"message": "Migration file not found"}), 500

        with open(CONFIG.DB_MIGRATIONS_FILE, "r") as sql_file:
            sql_script = sql_file.read()

        # Execute the SQL script to reset the database
        cursor.executescript(sql_script)
        conn.commit()
        conn.close()

        clear_session_excluding_flash()

        return (
            jsonify({"message": "Database reset successfully! Please login again"}),
            200,
        )

    except Exception as error:
        logging.error(f"Error in api_reset_db: {error}")

        return jsonify({"message": f"Error: {error}"}), 500


if __name__ == "__main__":
    try:
        # Clearing the application cache before starting the server...
        with app.app_context():
            cache.clear()

        # Initialize the database if it doesn't exist
        initialize_database()

        # Setting the Server Port...
        APP_PORT = CONFIG.APP_PORT or 5000

        print(f"\nServer is Usain Bolting! => http://localhost:{APP_PORT}")
        app.run(debug=True, host="0.0.0.0", port=APP_PORT, threaded=True)

    except KeyboardInterrupt:
        print("\nDetected Keyboard Interrupt! Shutting down server gracefully...")
        print("\nLater Alligator!")

    except Exception as error:
        logging.error(f"Error while starting server: {error}")
        print(f"Error while starting server: {error}")
