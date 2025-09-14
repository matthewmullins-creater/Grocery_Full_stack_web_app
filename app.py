import os
from dotenv import load_dotenv
import sqlite3
import random
from datetime import timedelta
from flask import Flask, session, render_template, request, g
from flask_wtf.csrf import CSRFProtect
from flask_session import Session
from forms import CSRFOnlyForm

load_dotenv()

app = Flask(__name__)
csrf = CSRFProtect(app)

# Category: Security
# Prompt Gist: Move SECRET_KEY to environment and rotate keys, set secure cookie flags(HTTPOnly, Secure, SameSite)
# Likely Files Relevant: app.py
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'select_a_COMPLEX_secret_key_please')
# app.secret_key = "select_a_COMPLEX_secret_key_please"
app.config.update(
    SESSION_COOKIE_NAME=os.getenv('FLAKS_SESSION_COOKIE_NAME', 'grocery_session'),
    SESSION_COOKIE_SECURE=False,  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Prevents JavaScript access to the cookie
    SESSION_COOKIE_SAMESITE='Lax',  # Adjust as needed (Lax, Strict, None)
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),  # 8 hours
    # Minimal server-side sessions (Filesystem) in-scope
    #One dependency: pip install Flask-Session
    SESSION_TYPE='filesystem',  # Use filesystem for session storage
    SESSION_FILE_DIR=os.getenv('FLASK_SESSION_FILE_DIR', '/tmp/flask_session_files'),
    SESSION_PERMANENT=False,  
    # like this:  shopping list stays on the server, cookie only holds a session Id. Solves "cookie bloat" + avoids exposing session contents

)
Session(app)
# app.config["SESSION_COOKIE_NAME"]="myCOOKIE_MONster52"

# in terms of 'Force HTTPS', this is typically done at the web server level (e.g., Nginx, Apache) or through a reverse proxy. 
# Flask itself does not handle HTTPS directly.
@app.after_request
def set_secure_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response


@app.route("/",methods=["GET"])
def index():
   session["all_items"],session["shopping_items"] = get_db()
   return render_template("index.html",
                          all_items=session["all_items"],
                          shopping_items=session["shopping_items"],
                          form=CSRFOnlyForm())


# in terms of /add_items and /remove_items,both are POST endpoints with no CSRF protection.
# classic targe for corss-site attacks
@app.route("/add_items", methods=["post"])
def add_item(): 
    # session["shopping_items"].append(request.form["my_selection"])
    # session["shopping_items"]= session["shopping_items"]
    # return render_template("index.html",all_items=session["all_items"],
    #                                     shopping_items=session["shopping_items"])
    form = CSRFOnlyForm()
    if not form.validate_on_submit():
        return "Invalid CSRF token", 400  # Bad Request
    sel = request.form.get("my_selection", "").strip()
    if not sel:
        return render_template("index.html", all_items=session["all_items"],
                               shopping_items=session["shopping_items"]), 400  # Bad Request
    shopping_items = session.get("shopping_items", [])
    shopping_items.append(sel)
    session["shopping_items"] = shopping_items
    session.modified = True  # Mark the session as modified to ensure changes are saved
    return render_template("index.html", 
                           all_items=session["all_items"],
                           shopping_items=shopping_items,
                           form=form)

@app.route("/remove_items",methods=["post"])
def remove_items():
    checked_boxes = request.form.getlist("my_input")
    shopping = session.get("shopping_items", [])
    if not isinstance(checked_boxes, list):
        checked_boxes = []
    for item in checked_boxes:
        try:
            shopping.remove(item)
        except ValueError:
            pass
    session["shopping_items"] = shopping
    session.modified = True  # Mark the session as modified to ensure changes are saved
    return render_template("index.html", 
                           all_items=session["all_items"],
                           shopping_items=shopping,
                           form=CSRFOnlyForm()
                           )

    # for item in checked_boxes:
    #     if item in session["shopping_items"]:
    #         idx = session["shopping_items"].index(item)
    #         session["shopping_items"].pop(idx)
    #         session.modified = True
    # return render_template("index.html",all_items=session["all_items"],
    #                                     shopping_items=session["shopping_items"])

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect('grocery_list.db')
        db.row_factory = sqlite3.Row  # Enable row factory for dict-like access
    cur = db.execute("SELECT name FROM groceries")
    all_data = [row["name"] for row in cur.fetchall()]  # Fetch all grocery names
    shopping_list = all_data.copy()
    random.shuffle(shopping_list)  # Shuffle the list
    shopping_list = shopping_list[:5]  # Limit to 5 items
    return all_data, shopping_list
    # db = getattr(g, '_database', None)
    # if db is None:
    #     db = g._database = sqlite3.connect('grocery_list.db')
    #     cursor = db.cursor()
    #     cursor.execute("select name from groceries")
    #     all_data = cursor.fetchall()
    #     all_data = [str(val[0]) for val in all_data]

    #     shopping_list = all_data.copy()
    #     random.shuffle(shopping_list)
    #     shopping_list = shopping_list[:5]
    # return all_data,shopping_list

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

if __name__ == '__main__':
    app.run(debug=True) # also in terms of debug mode enabled, it will expose the interactive debugger on crashes-RCE risk if leaked.

