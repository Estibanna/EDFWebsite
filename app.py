import urllib.parse
from flask import Flask, redirect, request, session, url_for, send_from_directory, render_template, abort
import pandas as pd
import requests
import os


app = Flask(__name__)
app.secret_key = 'ikke'

# === Vul hier je Discord IDs in ===
DISCORD_CLIENT_ID = '1381635320658788363'
DISCORD_CLIENT_SECRET = 'HaLBh13gkBwjwOIy3suofjrdqi9z5_KQ'
DISCORD_REDIRECT_URI = 'https://edfwebsite.onrender.com/callback'  # Pas aan als je online host
DISCORD_GUILD_ID = '1334260436098355250'

# Vul hieronder de role IDs in! (rechtsklik in Discord > Copy Role ID)
ROLE_MOD = '1334261170433163385'
ROLE_OWNER = '1335385385387163698'
ROLE_MILLIONAIRE = '1335193025416269865'
ROLE_BILLIONAIRE = '1335189853062561842'
ROLE_TRILLIONAIRE = '1335190853366452254'

# Patreon link
PATREON_URL = 'https://www.patreon.com/c/edfflippingrs3/membership'


# Toegangsrollen per geheime pagina
ACCESS_MILLIONAIRES = [ROLE_MOD, ROLE_OWNER, ROLE_MILLIONAIRE, ROLE_BILLIONAIRE, ROLE_TRILLIONAIRE]
ACCESS_BILLIONAIRES = [ROLE_MOD, ROLE_OWNER, ROLE_BILLIONAIRE, ROLE_TRILLIONAIRE]
ACCESS_TRILLIONAIRES = [ROLE_MOD, ROLE_OWNER, ROLE_TRILLIONAIRE]


        
# === HELPER FUNCTIES ===
def get_token(code):
    data = {
        'client_id': DISCORD_CLIENT_ID,
        'client_secret': DISCORD_CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': DISCORD_REDIRECT_URI,
        'scope': 'identify guilds guilds.members.read'
    
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    resp = requests.post('https://discord.com/api/oauth2/token', data=data, headers=headers)
    resp.raise_for_status()
    return resp.json()['access_token']

def get_user(access_token):
    headers = {'Authorization': f'Bearer {access_token}'}
    resp = requests.get('https://discord.com/api/users/@me', headers=headers)
    return resp.json()

def get_member(access_token):
    headers = {'Authorization': f'Bearer {access_token}'}
    url = f'https://discord.com/api/users/@me/guilds/{DISCORD_GUILD_ID}/member'
    resp = requests.get(url, headers=headers)
    return resp.json()

def user_has_access(user_roles, allowed_roles):
    return any(role in allowed_roles for role in user_roles)

# === ROUTES ===

# Homepagina (iedereen toegang)
@app.route('/')
def index():
    return send_from_directory('', 'index.html')

# Tracker-pagina (iedereen toegang)
@app.route('/tracker.html')
def tracker():
    return send_from_directory('', 'tracker.html')

# CSS en andere statische bestanden (zorg dat ze werken)
@app.route('/<path:filename>')
def static_files(filename):
    if filename.endswith('.css') or filename.endswith('.png') or filename.endswith('.ico'):
        return send_from_directory('', filename)
    abort(404)


@app.route('/login')
def login():
    redirect_uri = urllib.parse.quote_plus(DISCORD_REDIRECT_URI)
    return redirect(
        f"https://discord.com/oauth2/authorize?client_id=1381635320658788363&response_type=code&redirect_uri=https%3A%2F%2Fedfwebsite.onrender.com%2Fcallback&scope=identify+guilds+guilds.members.read"
    )
    
# Discord callback
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



# Uitloggen
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# Menu voor geheime pagina's (of zelf koppelen)
@app.route('/secret')
def secret_menu():
    if not session.get('username'):
        return redirect('/login')
    return render_template("Secret.html")

# Millionaires Page - alleen voor millionaires en hoger
@app.route('/millionaires')
def millionaires():
    if not session.get('username'):
        return redirect('/login')
    if not user_has_access(session.get('roles', []), ACCESS_MILLIONAIRES):
        return redirect(PATREON_URL)
    df = pd.read_excel('millionaires.xlsx')
    data = df.values.tolist()
    return render_template("millionaires.html", data=data)

# Billionaires Page - alleen voor billionaires en hoger
@app.route('/billionaires')
def billionaires():
    if not session.get('username'):
        return redirect('/login')
    if not user_has_access(session.get('roles', []), ACCESS_BILLIONAIRES):
        return redirect(PATREON_URL)
    # HIER komt het!
    COLUMNS = ['Item', 'Abbreviation', 'Average Margin', 'Buy-limit', 'Update amount', 'Update time', 'Risk']
    df = pd.read_excel('billionaires.xlsx')
    df = df.reindex(columns=COLUMNS)
    data = df.values.tolist()
    return render_template("billionaires.html", data=data)


# Trillionaires Page - alleen voor trillionaires (en mods/owners)
@app.route('/trillionaires')
def trillionaires():
    if not session.get('username'):
        return redirect('/login')
    if not user_has_access(session.get('roles', []), ACCESS_TRILLIONAIRES):
        return redirect(PATREON_URL)
    df = pd.read_excel('trillionaires.xlsx')
    data = df.values.tolist()
    return render_template("trillionaires.html", data=data)

# 403: Geen toegang
@app.errorhandler(403)
def forbidden(e):
    return render_template_string("""
    <h2>No Access</h2>
    <p>You don't have the right discord role to see this page</p>
    <a href='/secret'>back</a> | <a href='/logout'>Logout</a>
    """), 403

if __name__ == '__main__':
    # Zet debug uit als je online host!
    app.run(debug=True)
