datos_dummy = {
    '123456789012345': {
        'ip': '192.168.1.100',
        'apn': 'internet',
        'timestamp': '2024-05-09 12:00:00'
    },
    '987654321098765': {
        'ip': '10.0.0.1',
        'apn': 'mms',
        'timestamp': '2024-05-09 12:15:00'
    },
    '567890123456789': {
        'ip': '172.16.0.10',
        'apn': 'voz',
        'timestamp': '2024-05-09 12:30:00'
    }
}

def addDummy (ues):
    for imsi, info in datos_dummy.items():
        ues[imsi] = {
            'ip': info['ip'],
            'apn': info['apn'],
            'timestamp': info['timestamp']
        }
            