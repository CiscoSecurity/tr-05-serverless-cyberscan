from http import HTTPStatus
from unittest.mock import patch

from freezegun import freeze_time
from pytest import fixture
from requests.exceptions import SSLError

from tests.unit.api.utils import get_headers
from tests.unit.conftest import mock_api_response
from tests.unit.payloads_for_tests import (
    EXPECTED_RESPONSE_OF_JWKS_ENDPOINT,
    EXPECTED_RESPONSE_OF_SUCCESS_AUTH,
    EXPECTED_RESPONSE_OF_GET_IP,
    EXPECTED_RESPONSE_OF_GET_VULNERABILITIES,
    EXPECTED_RELAY_RESPONSE,
    EXPECTED_REFER_RESPONSE,
)


def routes():
    yield '/observe/observables'
    yield '/refer/observables'


def responses():
    yield mock_api_response(payload=EXPECTED_RESPONSE_OF_SUCCESS_AUTH)
    yield mock_api_response(payload=EXPECTED_RESPONSE_OF_GET_IP)
    yield mock_api_response(payload=EXPECTED_RESPONSE_OF_GET_VULNERABILITIES)


def ids():
    yield 'c9826d98-35df-4b8b-a61f-e52313920c5a'
    yield '8d518924-a3ac-4e3f-b0fd-4d017c219cf1'
    yield 'ea815346-d9a8-4efb-9bf0-ed3a8ebabf65'
    yield 'ca6a3495-0863-4789-83ab-039a57a5a84d'
    yield 'f994a79c-6134-4334-86b3-b84165eb10a9'
    yield '0d266e2b-1f5a-40ec-9b45-80824d1672bf'
    yield '65b3711e-ed3a-46d6-adb3-78fe944ecf69'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def invalid_json_value():
    return [{'type': 'ip', 'value': ''}]


@patch('requests.get')
def test_enrich_call_with_valid_jwt_but_invalid_json_value(
        mock_request,
        route, client, valid_jwt, invalid_json_value,
        invalid_json_expected_payload
):
    mock_request.return_value = \
        mock_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
    response = client.post(route,
                           headers=get_headers(valid_jwt()),
                           json=invalid_json_value)
    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_payload(
        "{0: {'value': ['Field may not be blank.']}}"
    )


@fixture(scope='module')
def valid_json():
    return [{'type': 'domain', 'value': 'j-p.link'}]


@freeze_time("2022-07-12T09:38:46")
@patch('api.mapping.uuid4')
@patch('requests.request')
@patch('requests.get')
def test_enrich_call_success(mock_get, mock_request, mock_id,
                             route, client, valid_jwt, valid_json):
    mock_get.return_value = \
        mock_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
    mock_request.side_effect = responses()
    mock_id.side_effect = ids()
    response = client.post(route, headers=get_headers(valid_jwt()),
                           json=valid_json)
    assert response.status_code == HTTPStatus.OK
    if route == '/observe/observables':
        assert response.json == EXPECTED_RELAY_RESPONSE
    elif route == '/refer/observables':
        assert response.json == EXPECTED_REFER_RESPONSE


@patch('requests.request')
@patch('requests.get')
def test_enrich_call_with_ssl_error(mock_get, mock_request,
                                    mock_exception_for_ssl_error,
                                    client, route, valid_jwt, valid_json,
                                    ssl_error_expected_relay_response):

    mock_get.return_value = \
        mock_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
    mock_request.side_effect = [SSLError(mock_exception_for_ssl_error)]

    response = client.post(route, headers=get_headers(valid_jwt()),
                           json=valid_json)
    assert response.status_code == HTTPStatus.OK
    assert response.json == ssl_error_expected_relay_response
