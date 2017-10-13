import requests

class Call(object):
    def __init__(self, path, key, sshash):
        self.host = 'https://www.virustotal.com'
        self.headers = {
            "Accept-Encoding": "gzip, deflate",
            "User-Agent":"gzip, Mozilla/5.0"
        }
        self.path = path
        self.key = key
        self.sshash = sshash

    def check_hash(self):
        params = {'apikey': self.key, 'resource': self.sshash}
        req = requests.get(url=self.host + self.path, params=params,
            headers=self.headers)

        # Checking hash for infection
        if req.status_code == 200:
            body = req.json()
            arr = []

            if 'positives' in body:
                avg = ((body['positives'] / body['total']) * 100)

                if avg >= 35.5:
                    arr.append(True)

                else:
                    arr.append(False)

            else:
                arr.append(False)
        else:
            arr.append(False)

        return arr[0]
