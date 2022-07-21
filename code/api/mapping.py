from datetime import datetime
from uuid import uuid4


SIGHTING = 'sighting'

SOURCE = 'CyberScan'
CONFIDENCE = 'High'

SIGHTING_DEFAULTS = {
    'count': 1,
    'internal': True,
    'confidence': CONFIDENCE,
    'type': SIGHTING,
    'source': SOURCE,
    'schema_version': '1.1.11',
}


class Sighting:
    def __init__(self, observable):
        self.observable = observable

    @staticmethod
    def _transient_id(entity):
        uuid = uuid4()
        return f'transient:{entity}-{uuid}'

    @staticmethod
    def _time_format(time):
        return f'{time.isoformat(timespec="seconds")}Z'

    def _observed_time(self):
        observed_time = self._time_format(datetime.utcnow())
        return {
            'start_time': observed_time
        }

    @staticmethod
    def _make_data_table(message):
        data = {
            'columns': [],
            'rows': [[]]
        }

        for key, value in message.items():
            data['columns'].append({'name': key, 'type': 'string'})
            data['rows'][0].append(str(value))

        return data

    @staticmethod
    def _short_description(vulnerability):
        return f'Vulnerability {vulnerability.get("cve")} observed at ' \
               'CyberScan'

    @staticmethod
    def _description(vulnerability):
        return vulnerability.get('description')

    @staticmethod
    def _title(vulnerability):
        return vulnerability.get('name')

    def extract(self, vulnerability):
        sighting = {
            'id': self._transient_id(SIGHTING),
            'observed_time': self._observed_time(),
            'observables': [self.observable],
            'short_description': self._short_description(vulnerability),
            'description': self._description(vulnerability),
            'data': self._make_data_table(vulnerability),
            'title': self._title(vulnerability),
            **SIGHTING_DEFAULTS,
        }

        return sighting
