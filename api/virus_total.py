import requests

class Call(object):
    def __init__(self, path, sshash):
        self.host = 'https://www.virustotal.com'
        self.headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent":"gzip, Mozilla/5.0"
        }
        self.path = path
        self.sshash = sshash

    def check_hash(self):
        params = {'apikey': 'KEY', 'resource': self.sshash}
        req = requests.get(url=self.host + self.path, params=params,
            headers=self.headers)

        # Checking hash for infection
        if req.status_code == 200:
            return 'OK'

        else:
            return 'Bad Hash'
