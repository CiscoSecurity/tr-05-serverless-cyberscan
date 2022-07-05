import requests
from flask import current_app
from requests.exceptions import ConnectionError
from http import HTTPStatus

from api.errors import CyberScanConnectionError, AuthorizationError

INVALID_CREDENTIALS = 'wrong api_key'


class CyberScanClient:
    def __init__(self, credentials):
        self._credentials = credentials
        self._headers = {
            'User-Agent': current_app.config['USER_AGENT']
        }

    @property
    def _url(self):
        url = current_app.config['CYBERSCAN_API_ENDPOINT']
        return url.format(host=self._credentials.get('host').rstrip('/'))

    def health(self):
        payload = {
            'key': self._credentials.get('api_key')
        }
        return self._request('token', method='POST', payload=payload)

    def _request(self, path, method='GET', payload=None):
        url = '/'.join([self._url, path.lstrip('/')])

        try:
            response = requests.request(method, url, json=payload,
                                        headers=self._headers)
        except ConnectionError:
            raise CyberScanConnectionError(url)

        if response.ok:
            return response.json()
        elif response.status_code == HTTPStatus.FORBIDDEN:
            raise AuthorizationError(INVALID_CREDENTIALS)
