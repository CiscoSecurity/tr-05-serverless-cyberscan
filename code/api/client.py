from http import HTTPStatus

import requests
from flask import current_app
from requests.exceptions import ConnectionError, SSLError, InvalidURL

from api.errors import (
    CyberScanConnectionError,
    AuthorizationError,
    CyberScanSSLError,
)

INVALID_CREDENTIALS = 'wrong api_key'

REFER_PATH = {
    'ip': 'ip/{observable}',
    'domain': 'domain/{observable}'
}


class CyberScanClient:
    def __init__(self, credentials):
        self._credentials = credentials
        self._headers = {
            'User-Agent': current_app.config['USER_AGENT']
        }
        self._ctr_entities_limit = current_app.config['CTR_ENTITIES_LIMIT']

    @property
    def _url(self):
        url = current_app.config['CYBERSCAN_API_ENDPOINT']
        return url.format(host=self._credentials.get('host').rstrip('/'))

    def _auth(self):
        payload = {
            'key': self._credentials.get('api_key')
        }
        response = self._request('token', method='POST', payload=payload)

        self._headers['Authorization'] = 'Bearer ' \
                                         f'{response.get("access_token")}'

    def health(self):
        self._auth()

    def _get_domain_ip(self, observable):
        path = f'domain/{observable["value"]}'
        response = self._request(path)
        try:
            ip = response.get('ip')
        except AttributeError:
            ip = ''

        return ip

    def get_vulnerabilities(self, observable):
        self._auth()
        ip = observable['value'] if observable['type'] == 'ip' \
            else self._get_domain_ip(observable)
        vulnerabilities = []
        path = f'vulnerabilities/ip/{ip}'
        response = self._request(path)
        if response:
            vulnerabilities = response.get('vulnerabilities')
            if len(vulnerabilities) > self._ctr_entities_limit:
                vulnerabilities = vulnerabilities[:self._ctr_entities_limit]
        return vulnerabilities

    def refer(self, observables):
        self._auth()
        relay_output = []
        for observable in observables:

            path = REFER_PATH[observable.get('type')].format(
                observable=observable.get('value')
            )
            response = self._request(path)

            relay_output.append(
                {
                    'id': ('ref-cyberscan-search-'
                           f'{observable["type"].replace("_", "-")}'
                           f'-{observable["value"]}'),
                    'title': f'Details for this {observable.get("type")}',
                    'description':
                        f'Details for this {observable["type"]} '
                        'in the CyberScan',
                    'url': response.get('details_page'),
                    'categories': ['CyberScan'],
                }
            )

        return relay_output

    def _request(self, path, method='GET', payload=None):
        url = '/'.join([self._url, path.lstrip('/')])

        try:
            response = requests.request(method, url, json=payload,
                                        headers=self._headers, timeout=10)
        except SSLError as error:
            raise CyberScanSSLError(error)
        except (ConnectionError, InvalidURL):
            raise CyberScanConnectionError(url)

        if response.ok:
            return response.json()
        elif response.status_code == HTTPStatus.FORBIDDEN:
            raise AuthorizationError(INVALID_CREDENTIALS)
