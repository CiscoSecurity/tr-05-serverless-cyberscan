from functools import partial

from flask import Blueprint, g

from api.client import CyberScanClient
from api.mapping import Sighting
from api.schemas import ObservableSchema
from api.utils import get_json, get_credentials, jsonify_data, jsonify_result

enrich_api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    credentials = get_credentials()
    observables = get_observables()

    g.sightings = []
    client = CyberScanClient(credentials)

    for observable in observables:
        vulnerabilities = client.get_vulnerabilities(observable)
        mapping = Sighting(observable)

        for vulnerability in vulnerabilities:
            sighting = mapping.extract(vulnerability)
            g.sightings.append(sighting)

    return jsonify_result()


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    credentials = get_credentials()
    observables = get_observables()

    client = CyberScanClient(credentials)

    relay_output = client.refer(observables)

    return jsonify_data(relay_output)
