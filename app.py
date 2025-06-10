import urllib.parse
from flask import Flask, redirect, request, session, url_for, render_template, abort
import pandas as pd
import requests
import os

app = Flask(__name__)
app.secret_key = 'ikke'

# Discord config ...

# === ROUTES ===

@app.route('/')
def home():
    return render_template('index.html')  # Zet index.html in /templates/

@app.route('/tracker')
def tracker():
    return render_template('tracker.html')  # Zet tracker.html in /templates/

@app.route('/login')
def login():
    redirect_uri = urllib.parse.quote_plus(DISCORD_REDIRECT_URI)
    return redirect(
        f"https://discord.com/oauth2/authorize?client_id=1377710117969203290&response_type=code&redirect_uri={redirect_uri}&scope=identify+guilds+guilds.members.read"
    )

@app.route('/callback')
def callback():
    code = request.args.get('code')
    if not code:
        return "Geen code ontvangen."
    access_token = get_token(code)
    user = get_user(access_token)
    member = get_member(access_token)
    roles = member.get('roles', [])
    session['username'] = user['username']
    session['roles'] = roles
    return redirect(url_for('secret_menu'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/secret')
def secret_menu():
    if not session.get('username'):
        return redirect('/login')
    return render_template("Secret.html")  # Zet Secret.html in /templates/

@app.route('/school')
def school():
    # Zorg dat je deze functie maakt!
    data = {}  # Maak dit werkend of laat het leeg
    return render_template("school.html", data=data)

@app.route('/millionaires')
def millionaires():
    if not session.get('username'):
        return redirect('/login')
    if not user_has_access(session.get('roles', []), ACCESS_MILLIONAIRES):
        return redirect(PATREON_URL)
    df = pd.read_excel('millionaires.xlsx')
    data = df.values.tolist()
    return render_template("millionaires.html", data=data)

@app.route('/billionaires')
def billionaires():
    if not session.get('username'):
        return redirect('/login')
    if not user_has_access(session.get('roles', []), ACCESS_BILLIONAIRES):
        return redirect(PATREON_URL)
    df = pd.read_excel('billionaires.xlsx')
    data = df.values.tolist()
    return render_template("billionaires.html", data=data)

@app.route('/trillionaires')
def trillionaires():
    if not session.get('username'):
        return redirect('/login')
    if not user_has_access(session.get('roles', []), ACCESS_TRILLIONAIRES):
        return redirect(PATREON_URL)
    df = pd.read_excel('trillionaires.xlsx')
    data = df.values.tolist()
    return render_template("trillionaires.html", data=data)

@app.errorhandler(403)
def forbidden(e):
    return "<h2>No Access</h2><p>You don't have the right discord role to see this page</p><a href='/secret'>back</a> | <a href='/logout'>Logout</a>", 403

# -------------------
# Helper functies hier (zoals get_token etc)
# -------------------

if __name__ == '__main__':
    app.run(debug=False)

# Voor Render:
application = app
