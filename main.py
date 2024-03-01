import json
import requests
from flask import Flask, request, jsonify, abort
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
CORS(app)


def fetch_json(key):
    current_datetime = datetime.now()
    timestamp_integer = int(current_datetime.timestamp())

    url = f'https://stundenplan.osz-lise-meitner.eu/vertretungsplan.json?_={timestamp_integer}'
    headers = {
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'Connection': 'keep-alive',
        'Cookie': f'mod_auth_openidc_session={key}'
    }

    alles = requests.get(url, headers=headers)
    data = json.loads(alles.text.lstrip("\ufeff"))

    response = jsonify(data)

    response.headers.add('Access-Control-Allow-Origin', '*')

    return response


headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Language': 'en,en-US;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'DNT': '1',
    'Sec-GPC': '1',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1'
}


def get_cookie(cookie, r):
    cook = r.headers['Set-Cookie'].split("=")

    cook = [cook[0], cook[1].rstrip("; path")]

    return {f'{cookie}': f'{cook[1]}'}


def get_location(r):
    url = r.headers['location']
    if not url.startswith("https://iserv.osz-lise-meitner.eu"):
        url = "https://iserv.osz-lise-meitner.eu" + url

    return url


@app.route('/json', methods=['GET'])
def get_date():
    key_param = request.args.get('key')
    if key_param:
        try:
            return fetch_json(key_param)
        except:
            abort(403, "Invalid token")

    else:
        return "Missing 'key' parameter", 400


@app.route('/auth', methods=['GET'])
def authenticate():
    username = request.args.get('username')
    password = request.args.get('password')

    url = 'https://stundenplan.osz-lise-meitner.eu/'

    # GET https://stundenplan.osz-lise-meitner.eu/index-alt.html STATUS: 302
    index_request = requests.get(url, headers=headers, allow_redirects=False)

    auth1_url = get_location(index_request)

    initial_mod_auth_openidc_state = index_request.headers['Set-Cookie'].split("=")

    initial_mod_auth_openidc_state = [initial_mod_auth_openidc_state[0],
                                      initial_mod_auth_openidc_state[1].rstrip("; Path")]


    # GET https://iserv.osz-lise-meitner.eu/iserv/oauth/v2/auth STATUS: 302
    auth1_request = requests.get(auth1_url, headers=headers, allow_redirects=False)

    auth2_url = get_location(auth1_request)

    # GET https://iserv.osz-lise-meitner.eu/iserv/auth/auth STATUS: 302
    auth2_request = requests.get(auth2_url, headers=headers, allow_redirects=False)

    login_url = get_location(auth2_request)

    IservAuthSession1 = get_cookie("IservAuthSession", auth2_request)

    data = {
        '_username': username,
        '_password': password
    }

    test_login_request = requests.get(login_url, allow_redirects=False, cookies=IservAuthSession1)

    login_request = requests.post(login_url, headers=headers, allow_redirects=False, data=data,
                                  cookies=IservAuthSession1)

    auth3_url = get_location(login_request)

    IservAuthSession2 = get_cookie("IservAuthSession", login_request)

    # GET https://iserv.osz-lise-meitner.eu/iserv/auth/auth STATUS: 302
    auth3_req = requests.get(auth3_url, headers=headers, allow_redirects=False, cookies=login_request.cookies)

    redirect_url = get_location(auth3_req)

    # GET https://iserv.osz-lise-meitner.eu/iserv/app/authentication/redirect STATUS: 302
    redirect_req = requests.get(redirect_url, headers=headers, allow_redirects=False)

    auth4_url = get_location(redirect_req)


    # GET https://iserv.osz-lise-meitner.eu/iserv/oauth/v2/auth STATUS: 302
    auth4_req = requests.get(auth4_url, headers=headers, allow_redirects=False, cookies=redirect_req.cookies)

    oidcallback_url = auth4_req.headers['Location']

    oidcallback_req = requests.get(oidcallback_url, headers=headers, allow_redirects=False,
                                   cookies=index_request.cookies)

    key = oidcallback_req.cookies['mod_auth_openidc_session']

    print("SessionToken: "+key)

    return jsonify(key)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=40047)
