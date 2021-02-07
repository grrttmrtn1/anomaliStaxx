import requests
import json
#using an internal site with self signed cert, comment out if not
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class anomaliCheck:

    def __init__(self, host, port,  username, password):
        self.host = host
        self.username = username
        self.password = password
        self.port = port

    def anomali_webCall(self, apiCall, header, data):
        baseuri = 'https://' + self.host + ':' + self.port + '/api/v1/'
        uri = baseuri + apiCall
        r = requests.post(uri, data=data, verify=False, headers=header)
        return json.loads(r.content)

    def get_token(self):
        auth = {'username': self.username , 'password': self.password }
        auth = json.dumps(auth)
        header = {"Content-Type":"application/json"}
        tokenLoad = self.anomali_webCall('login', header,auth)
        token = str(tokenLoad['token_id'])
        return token

    def export_observables(self, query):
        header = {"Content-Type":"application/json"}
        token = self.get_token()
        data = {}
        data['token'] = token
        data['query'] = query
        data['type'] = 'json'
        data = json.dumps(data)
        observables = self.anomali_webCall('intelligence', header, data)
        domains = []
        for domain in observables:
            domains.append(str(domain['indicator']))
        return domains
    def parseDomains(self, domains):
        parsedDomains = []
        for domain in domains:
            if 'http' in domain:
                parsedDomains.append(domain.split('//')[1].split('/')[0])
            else:
                parsedDomains.append(domain)
        return parsedDomains
