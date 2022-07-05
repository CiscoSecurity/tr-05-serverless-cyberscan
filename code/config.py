import json


class Config:
    settings = json.load(open('container_settings.json', 'r'))
    VERSION = settings["VERSION"]

    USER_AGENT = ('SecureX Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')

    CYBERSCAN_API_ENDPOINT = 'https://{host}/api/v1'

    CTR_DEFAULT_ENTITIES_LIMIT = 100
