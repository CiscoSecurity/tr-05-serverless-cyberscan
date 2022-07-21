EXPECTED_RESPONSE_OF_JWKS_ENDPOINT = {
  'keys': [
    {
      'kty': 'RSA',
      'n': 'tSKfSeI0fukRIX38AHlKB1YPpX8PUYN2JdvfM-XjNmLfU1M74N0V'
           'mdzIX95sneQGO9kC2xMIE-AIlt52Yf_KgBZggAlS9Y0Vx8DsSL2H'
           'vOjguAdXir3vYLvAyyHin_mUisJOqccFKChHKjnk0uXy_38-1r17'
           '_cYTp76brKpU1I4kM20M__dbvLBWjfzyw9ehufr74aVwr-0xJfsB'
           'Vr2oaQFww_XHGz69Q7yHK6DbxYO4w4q2sIfcC4pT8XTPHo4JZ2M7'
           '33Ea8a7HxtZS563_mhhRZLU5aynQpwaVv2U--CL6EvGt8TlNZOke'
           'Rv8wz-Rt8B70jzoRpVK36rR-pHKlXhMGT619v82LneTdsqA25Wi2'
           'Ld_c0niuul24A6-aaj2u9SWbxA9LmVtFntvNbRaHXE1SLpLPoIp8'
           'uppGF02Nz2v3ld8gCnTTWfq_BQ80Qy8e0coRRABECZrjIMzHEg6M'
           'loRDy4na0pRQv61VogqRKDU2r3_VezFPQDb3ciYsZjWBr3HpNOkU'
           'jTrvLmFyOE9Q5R_qQGmc6BYtfk5rn7iIfXlkJAZHXhBy-ElBuiBM'
           '-YSkFM7dH92sSIoZ05V4MP09Xcppx7kdwsJy72Sust9Hnd9B7V35'
           'YnVF6W791lVHnenhCJOziRmkH4xLLbPkaST2Ks3IHH7tVltM6NsR'
           'k3jNdVM',
      'e': 'AQAB',
      'alg': 'RS256',
      'kid': '02B1174234C29F8EFB69911438F597FF3FFEE6B7',
      'use': 'sig'
    }
  ]
}

RESPONSE_OF_JWKS_ENDPOINT_WITH_WRONG_KEY = {
    'keys': [
        {
            'kty': 'RSA',
            'n': 'pSKfSeI0fukRIX38AHlKB1YPpX8PUYN2JdvfM-XjNmLfU1M74N0V'
                 'mdzIX95sneQGO9kC2xMIE-AIlt52Yf_KgBZggAlS9Y0Vx8DsSL2H'
                 'vOjguAdXir3vYLvAyyHin_mUisJOqccFKChHKjnk0uXy_38-1r17'
                 '_cYTp76brKpU1I4kM20M__dbvLBWjfzyw9ehufr74aVwr-0xJfsB'
                 'Vr2oaQFww_XHGz69Q7yHK6DbxYO4w4q2sIfcC4pT8XTPHo4JZ2M7'
                 '33Ea8a7HxtZS563_mhhRZLU5aynQpwaVv2U--CL6EvGt8TlNZOke'
                 'Rv8wz-Rt8B70jzoRpVK36rR-pHKlXhMGT619v82LneTdsqA25Wi2'
                 'Ld_c0niuul24A6-aaj2u9SWbxA9LmVtFntvNbRaHXE1SLpLPoIp8'
                 'uppGF02Nz2v3ld8gCnTTWfq_BQ80Qy8e0coRRABECZrjIMzHEg6M'
                 'loRDy4na0pRQv61VogqRKDU2r3_VezFPQDb3ciYsZjWBr3HpNOkU'
                 'jTrvLmFyOE9Q5R_qQGmc6BYtfk5rn7iIfXlkJAZHXhBy-ElBuiBM'
                 '-YSkFM7dH92sSIoZ05V4MP09Xcppx7kdwsJy72Sust9Hnd9B7V35'
                 'YnVF6W791lVHnenhCJOziRmkH4xLLbPkaST2Ks3IHH7tVltM6NsR'
                 'k3jNdVM',
            'e': 'AQAB',
            'alg': 'RS256',
            'kid': '02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            'use': 'sig'
        }
    ]
}

PRIVATE_KEY = '''-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----'''

EXPECTED_RESPONSE_OF_SUCCESS_AUTH = {
    'access_token': 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhcGlfa2V5IjoiZXl'
                    'KMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKSVV6STFOaUo5LmV5SmpkWE4'
                    'wYjIxbGNpSTZJbU5wYzJOdklIUmxjM1FnWVdOamIzVnVkQ0lzSW1Gd2F'
                    'WOXJaWGtpT2lKaGNHbGZhMlY1SWl3aWRYSnNJanB1ZFd4c0xDSmxlSEF'
                    'pT2pFMk5qQXlNRGt4TXpoOS5VWmY4cWREaWhYQ3V1eEtvdEJHUlVkcXp'
                    'CSHkxU1VkQUFLeHFtZG51bTVBIiwidXJsIjpudWxsLCJleHBpcmVzIjo'
                    'xNjU3NjIzMTM4LjAwODE4ODV9.vY_wTF1C07XIBHCtdUg3MGY1umSboo'
                    'hq4sBAA3UbPLA'
}


EXPECTED_RESPONSE_OF_GET_IP = {
    'domain': 'j-p.link',
    'ip': '116.203.177.93',
    'vulns': {
        'critical': 0,
        'high': 0,
        'medium': 7,
        'low': 0,
        'info': 30
    },
    'cvss_total': 34.4,
    'open_ports': 5,
    'details_page':
        'https://www.cyberscan.io/vulnerabilities/j-p.link/116.203.177.93'
}

EXPECTED_RESPONSE_OF_GET_VULNERABILITIES = {
    'ip': '116.203.177.93',
    'vulnerabilities': [
        {
            'name': 'OpenSSH ',
            'family': 'General',
            'description': '** DISPUTED ** scp in OpenSSH through 8.3p1 allow'
                           's command injection in the scp.c toremote functio'
                           'n, as demonstrated by backtick characters in the '
                           'destination argument. NOTE: the vendor reportedly'
                           ' has stated that they intentionally omit validati'
                           'on of \"anomalous argument transfers\" because th'
                           'at could \"stand a great chance of breaking exist'
                           'ing workflows.\"',
            'severity': 'Medium',
            'port': 22,
            'protocol': 'tcp',
            'cve': 'CVE-2020-15778',
            'cvss': 6.8,
            'confidence': 30
        },
        {
            'name': 'Diffie-Hellman Ephemeral Key Exchange DoS Vulnerability '
                    '(SSH, D(HE)ater)',
            'family': 'Denial of Service',
            'description': 'The remote SSH server is supporting Diffie-Hellma'
                           'n ephemeral\n  (DHE) Key Exchange (KEX) algorithm'
                           's and thus could be prone to a denial of service '
                           '(DoS)\n  vulnerability.',
            'severity': 'Medium',
            'port': 22,
            'protocol': 'tcp',
            'cve': 'CVE-2002-20001',
            'cvss': 5,
            'confidence': 30
        },
        {
            'name': 'SSL/TLS: Known Untrusted / Dangerous Certificate Authori'
                    'ty (CA) Detection',
            'family': 'SSL and TLS',
            'description': 'The service is using an SSL/TLS certificate from '
                           'a known\n  untrusted and/or dangerous certificate'
                           ' authority (CA).',
            'severity': 'Medium',
            'port': 443,
            'protocol': 'tcp',
            'cve': '',
            'cvss': 5,
            'confidence': 99
        },
        {
            'name': 'OpenSSH 8.2 ',
            'family': 'General',
            'description': 'ssh-agent in OpenSSH before 8.5 has a double free'
                           ' that may be relevant in a few less-common scenar'
                           'ios, such as unconstrained agent-socket access on'
                           ' a legacy operating system, or the forwarding of '
                           'an agent to an attacker-controlled host.',
            'severity': 'Medium',
            'port': 22,
            'protocol': 'tcp',
            'cve': 'CVE-2021-28041',
            'cvss': 4.6,
            'confidence': 30
        },
        {
            'name': 'OpenSSH 6.2 ',
            'family': 'Privilege escalation',
            'description': 'OpenSSH is prone to a privilege scalation vulnera'
                           'bility in\n  certain configurations.',
            'severity': 'Medium',
            'port': 22,
            'protocol': 'tcp',
            'cve': 'CVE-2021-41617',
            'cvss': 4.4,
            'confidence': 30
        },
        {
            'name': 'OpenSSH Information Disclosure Vulnerability '
                    '(CVE-2016-20012)',
            'family': 'General',
            'description': 'OpenBSD OpenSSH is prone to an information disclo'
                           'sure\n  vulnerability.',
            'severity': 'Medium',
            'port': 22,
            'protocol': 'tcp',
            'cve': 'CVE-2016-20012',
            'cvss': 4.3,
            'confidence': 50
        },
        {
            'name': 'OpenBSD OpenSSH Information Disclosure Vulnerability '
                    '(CVE-2020-14145)',
            'family': 'General',
            'description': 'The client side in OpenSSH 5.7 through 8.4 has an'
                           ' Observable Discrepancy leading to an information'
                           ' leak in the algorithm negotiation. This allows m'
                           'an-in-the-middle attackers to target initial conn'
                           'ection attempts (where no host key for the server'
                           ' has been cached by the client).',
            'severity': 'Medium',
            'port': 22,
            'protocol': 'tcp',
            'cve': 'CVE-2020-14145',
            'cvss': 4.3,
            'confidence': 30
        }
    ]
}

EXPECTED_RELAY_RESPONSE = {
    'data':
        {
            'sightings': {
                'count': 7,
                'docs': [
                    {
                        'confidence': 'High',
                        'count': 1,
                        'data': {
                            'columns': [
                                {'name': 'name', 'type': 'string'},
                                {'name': 'family', 'type': 'string'},
                                {'name': 'description', 'type': 'string'},
                                {'name': 'severity', 'type': 'string'},
                                {'name': 'port', 'type': 'string'},
                                {'name': 'protocol', 'type': 'string'},
                                {'name': 'cve', 'type': 'string'},
                                {'name': 'cvss', 'type': 'string'},
                                {'name': 'confidence', 'type': 'string'}],
                            'rows': [
                                [
                                    'OpenSSH ', 'General',
                                    '** DISPUTED ** scp in OpenSSH through 8.'
                                    '3p1 allows command injection in the scp.'
                                    'c toremote function, as demonstrated by '
                                    'backtick characters in the destination a'
                                    'rgument. NOTE: the vendor reportedly has'
                                    ' stated that they intentionally omit val'
                                    'idation of "anomalous argument transfers'
                                    '" because that could "stand a great chan'
                                    'ce of breaking existing workflows."',
                                    'Medium', '22', 'tcp', 'CVE-2020-15778',
                                    '6.8', '30'
                                ]
                            ]
                        },
                        'description': '** DISPUTED ** scp in OpenSSH through'
                                       ' 8.3p1 allows command injection in th'
                                       'e scp.c toremote function, as demonst'
                                       'rated by backtick characters in the d'
                                       'estination argument. NOTE: the vendor'
                                       ' reportedly has stated that they inte'
                                       'ntionally omit validation of "anomalo'
                                       'us argument transfers" because that c'
                                       'ould "stand a great chance of breakin'
                                       'g existing workflows."',
                        'id': 'transient:sighting-c9826d98-35df-4b8b-a61f-e52'
                              '313920c5a',
                        'internal': True,
                        'observables':
                            [{'type': 'domain', 'value': 'j-p.link'}],
                        'observed_time':
                            {'start_time': '2022-07-12T09:38:46Z'},
                        'schema_version': '1.1.11',
                        'short_description': 'Vulnerability CVE-2020-15778 ob'
                                             'served at CyberScan',
                        'source': 'CyberScan', 'title': 'OpenSSH ',
                        'type': 'sighting'
                    },
                    {
                        'confidence': 'High', 'count': 1,
                        'data': {
                            'columns': [
                                {'name': 'name', 'type': 'string'},
                                {'name': 'family', 'type': 'string'},
                                {'name': 'description', 'type': 'string'},
                                {'name': 'severity', 'type': 'string'},
                                {'name': 'port', 'type': 'string'},
                                {'name': 'protocol', 'type': 'string'},
                                {'name': 'cve', 'type': 'string'},
                                {'name': 'cvss', 'type': 'string'},
                                {'name': 'confidence', 'type': 'string'}],
                            'rows': [[
                                'Diffie-Hellman Ephemeral Key Exchange DoS Vu'
                                'lnerability (SSH, D(HE)ater)',
                                'Denial of Service',
                                'The remote SSH server is supporting Diffie-H'
                                'ellman ephemeral\n  (DHE) Key Exchange (KEX)'
                                ' algorithms and thus could be prone to a den'
                                'ial of service (DoS)\n  vulnerability.',
                                'Medium', '22', 'tcp', 'CVE-2002-20001', '5',
                                '30']]
                        },
                        'description': 'The remote SSH server is supporting D'
                                       'iffie-Hellman ephemeral\n  (DHE) Key '
                                       'Exchange (KEX) algorithms and thus co'
                                       'uld be prone to a denial of service ('
                                       'DoS)\n  vulnerability.',
                        'id': 'transient:sighting-8d518924-a3ac-4e3f-b0fd-4d0'
                              '17c219cf1',
                        'internal': True,
                        'observables':
                            [{'type': 'domain', 'value': 'j-p.link'}],
                        'observed_time':
                            {'start_time': '2022-07-12T09:38:46Z'},
                        'schema_version': '1.1.11',
                        'short_description': 'Vulnerability CVE-2002-20001 ob'
                                             'served at CyberScan',
                        'source': 'CyberScan',
                        'title': 'Diffie-Hellman Ephemeral Key Exchange DoS V'
                                 'ulnerability (SSH, D(HE)ater)',
                        'type': 'sighting'
                    },
                    {
                        'confidence': 'High', 'count': 1,
                        'data': {
                            'columns': [
                                {'name': 'name', 'type': 'string'},
                                {'name': 'family', 'type': 'string'},
                                {'name': 'description', 'type': 'string'},
                                {'name': 'severity', 'type': 'string'},
                                {'name': 'port', 'type': 'string'},
                                {'name': 'protocol', 'type': 'string'},
                                {'name': 'cve', 'type': 'string'},
                                {'name': 'cvss', 'type': 'string'},
                                {'name': 'confidence', 'type': 'string'}],
                            'rows': [[
                                'SSL/TLS: Known Untrusted / Dangerous Certifi'
                                'cate Authority (CA) Detection',
                                'SSL and TLS',
                                'The service is using an SSL/TLS certificate'
                                ' from a known\n  untrusted and/or dangerous'
                                ' certificate authority (CA).',
                                'Medium', '443', 'tcp', '', '5', '99']]
                        },
                        'description':
                            'The service is using an SSL/TLS certificate from'
                            ' a known\n  untrusted and/or dangerous certifica'
                            'te authority (CA).',
                        'id': 'transient:sighting-ea815346-d9a8-4efb-9bf0-ed3'
                              'a8ebabf65',
                        'internal': True,
                        'observables':
                            [{'type': 'domain', 'value': 'j-p.link'}],
                        'observed_time':
                            {'start_time': '2022-07-12T09:38:46Z'},
                        'schema_version': '1.1.11',
                        'short_description':
                            'Vulnerability  observed at CyberScan',
                        'source': 'CyberScan',
                        'title': 'SSL/TLS: Known Untrusted / Dangerous Certif'
                                 'icate Authority (CA) Detection',
                        'type': 'sighting'
                    },
                    {
                        'confidence': 'High', 'count': 1,
                        'data': {
                            'columns': [
                                {'name': 'name', 'type': 'string'},
                                {'name': 'family', 'type': 'string'},
                                {'name': 'description', 'type': 'string'},
                                {'name': 'severity', 'type': 'string'},
                                {'name': 'port', 'type': 'string'},
                                {'name': 'protocol', 'type': 'string'},
                                {'name': 'cve', 'type': 'string'},
                                {'name': 'cvss', 'type': 'string'},
                                {'name': 'confidence', 'type': 'string'}],
                            'rows': [[
                                'OpenSSH 8.2 ', 'General',
                                'ssh-agent in OpenSSH before 8.5 has a double'
                                ' free that may be relevant in a few less-com'
                                'mon scenarios, such as unconstrained agent-s'
                                'ocket access on a legacy operating system, o'
                                'r the forwarding of an agent to an attacker-'
                                'controlled host.', 'Medium', '22', 'tcp',
                                'CVE-2021-28041', '4.6', '30']]
                        },
                        'description': 'ssh-agent in OpenSSH before 8.5 has a'
                                       ' double free that may be relevant in '
                                       'a few less-common scenarios, such as '
                                       'unconstrained agent-socket access on '
                                       'a legacy operating system, or the for'
                                       'warding of an agent to an attacker-co'
                                       'ntrolled host.',
                        'id': 'transient:sighting-ca6a3495-0863-4789-83ab-039'
                              'a57a5a84d',
                        'internal': True,
                        'observables':
                            [{'type': 'domain', 'value': 'j-p.link'}],
                        'observed_time':
                            {'start_time': '2022-07-12T09:38:46Z'},
                        'schema_version': '1.1.11',
                        'short_description': 'Vulnerability CVE-2021-28041 ob'
                                             'served at CyberScan',
                        'source': 'CyberScan', 'title': 'OpenSSH 8.2 ',
                        'type': 'sighting'
                    },
                    {
                        'confidence': 'High', 'count': 1,
                        'data': {
                            'columns': [
                                {'name': 'name', 'type': 'string'},
                                {'name': 'family', 'type': 'string'},
                                {'name': 'description', 'type': 'string'},
                                {'name': 'severity', 'type': 'string'},
                                {'name': 'port', 'type': 'string'},
                                {'name': 'protocol', 'type': 'string'},
                                {'name': 'cve', 'type': 'string'},
                                {'name': 'cvss', 'type': 'string'},
                                {'name': 'confidence', 'type': 'string'}],
                            'rows': [[
                                'OpenSSH 6.2 ', 'Privilege escalation',
                                'OpenSSH is prone to a privilege scalation vu'
                                'lnerability in\n  certain configurations.',
                                'Medium', '22', 'tcp', 'CVE-2021-41617',
                                '4.4', '30']]
                        },
                        'description': 'OpenSSH is prone to a privilege scala'
                                       'tion vulnerability in\n  certain conf'
                                       'igurations.',
                        'id': 'transient:sighting-f994a79c-6134-4334-86b3-b84'
                              '165eb10a9',
                        'internal': True,
                        'observables':
                            [{'type': 'domain', 'value': 'j-p.link'}],
                        'observed_time':
                            {'start_time': '2022-07-12T09:38:46Z'},
                        'schema_version': '1.1.11',
                        'short_description': 'Vulnerability CVE-2021-41617 ob'
                                             'served at CyberScan',
                        'source': 'CyberScan', 'title': 'OpenSSH 6.2 ',
                        'type': 'sighting'
                    },
                    {
                        'confidence': 'High', 'count': 1,
                        'data': {
                            'columns': [
                                {'name': 'name', 'type': 'string'},
                                {'name': 'family', 'type': 'string'},
                                {'name': 'description', 'type': 'string'},
                                {'name': 'severity', 'type': 'string'},
                                {'name': 'port', 'type': 'string'},
                                {'name': 'protocol', 'type': 'string'},
                                {'name': 'cve', 'type': 'string'},
                                {'name': 'cvss', 'type': 'string'},
                                {'name': 'confidence', 'type': 'string'}],
                            'rows': [[
                                'OpenSSH Information Disclosure Vulnerability'
                                ' (CVE-2016-20012)', 'General',
                                'OpenBSD OpenSSH is prone to an information d'
                                'isclosure\n  vulnerability.', 'Medium',
                                '22', 'tcp', 'CVE-2016-20012', '4.3', '50']]
                        },
                        'description': 'OpenBSD OpenSSH is prone to an inform'
                                       'ation disclosure\n  vulnerability.',
                        'id': 'transient:sighting-0d266e2b-1f5a-40ec-9b45-808'
                              '24d1672bf',
                        'internal': True,
                        'observables':
                            [{'type': 'domain', 'value': 'j-p.link'}],
                        'observed_time':
                            {'start_time': '2022-07-12T09:38:46Z'},
                        'schema_version': '1.1.11',
                        'short_description': 'Vulnerability CVE-2016-20012 ob'
                                             'served at CyberScan',
                        'source': 'CyberScan',
                        'title': 'OpenSSH Information Disclosure Vulnerabilit'
                                 'y (CVE-2016-20012)',
                        'type': 'sighting'
                    },
                    {
                        'confidence': 'High', 'count': 1,
                        'data': {
                            'columns': [
                                {'name': 'name', 'type': 'string'},
                                {'name': 'family', 'type': 'string'},
                                {'name': 'description', 'type': 'string'},
                                {'name': 'severity', 'type': 'string'},
                                {'name': 'port', 'type': 'string'},
                                {'name': 'protocol', 'type': 'string'},
                                {'name': 'cve', 'type': 'string'},
                                {'name': 'cvss', 'type': 'string'},
                                {'name': 'confidence', 'type': 'string'}],
                            'rows': [[
                                'OpenBSD OpenSSH Information Disclosure Vulne'
                                'rability (CVE-2020-14145)', 'General',
                                'The client side in OpenSSH 5.7 through 8.4 h'
                                'as an Observable Discrepancy leading to an i'
                                'nformation leak in the algorithm negotiation'
                                '. This allows man-in-the-middle attackers to'
                                ' target initial connection attempts (where n'
                                'o host key for the server has been cached by'
                                ' the client).', 'Medium', '22', 'tcp',
                                'CVE-2020-14145', '4.3', '30']]
                        },
                        'description': 'The client side in OpenSSH 5.7 throug'
                                       'h 8.4 has an Observable Discrepancy l'
                                       'eading to an information leak in the '
                                       'algorithm negotiation. This allows ma'
                                       'n-in-the-middle attackers to target i'
                                       'nitial connection attempts (where no '
                                       'host key for the server has been cach'
                                       'ed by the client).',
                        'id': 'transient:sighting-65b3711e-ed3a-46d6-adb3-78f'
                              'e944ecf69',
                        'internal': True,
                        'observables':
                            [{'type': 'domain', 'value': 'j-p.link'}],
                        'observed_time':
                            {'start_time': '2022-07-12T09:38:46Z'},
                        'schema_version': '1.1.11',
                        'short_description': 'Vulnerability CVE-2020-14145 ob'
                                             'served at CyberScan',
                        'source': 'CyberScan',
                        'title': 'OpenBSD OpenSSH Information Disclosure Vuln'
                                 'erability (CVE-2020-14145)',
                        'type': 'sighting'
                    }
                ]
            }
        }
}

EXPECTED_REFER_RESPONSE = {
    'data': [
        {'categories': ['CyberScan'],
         'description': 'Details for this domain in the CyberScan',
         'id': 'ref-cyberscan-search-domain-j-p.link',
         'title': 'Details for this domain',
         'url': 'https://www.cyberscan.io/vulnerabilities'
                '/j-p.link/116.203.177.93'
         }
    ],
}
