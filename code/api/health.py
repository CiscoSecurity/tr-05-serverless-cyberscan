from flask import Blueprint

from api.utils import get_credentials, jsonify_data
from api.client import CyberScanClient

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    credentials = get_credentials()
    client = CyberScanClient(credentials)
    client.health()

    return jsonify_data({'status': 'ok'})
