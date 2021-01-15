import requests
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def anomali_webCall(apiCall, header, data):
    host = ''
    baseuri = 'https://' + host +  '/api/v1/'
    uri = baseuri + apiCall
    r = requests.post(uri, data=data, verify=False, headers=header)
    return json.loads(r.content)

def get_token():
    username = ''
    password = ''
    auth = {'username': username , 'password': password }
    auth = json.dumps(auth)
    header = {"Content-Type":"application/json"}
    tokenLoad = anomali_webCall('login', header,auth)
    token = str(tokenLoad['token_id'])
    return token

def export_observables():
    query = "itype = 'suspicious_domain' OR itype = 'phish_domain'"
    header = {"Content-Type":"application/json"}
    token = get_token()
    data = {}
    data['token'] = token
    data['query'] = query
    data['type'] = 'json'
    data = json.dumps(data)
    observables = anomali_webCall('intelligence', header, data)
    domains = []
    for domain in observables:
        domains.append(domain['indicator'])
    return domains
