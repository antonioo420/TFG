from flask import Flask, render_template, Response
import time
import threading
from datetime import datetime
import re
import subprocess as sub
from flask_socketio import SocketIO, emit

app = Flask(__name__)
socketio = SocketIO(app)

#Variables globales
SMF = '/var/log/open5gs/smf.log'
fecha_mas_reciente = datetime(1,1,1,0,0)
MAX_PACKETS = 2

def obtener_informacion(nombre_archivo):
    global fecha_mas_reciente
    linea_mas_reciente = ""
    with open(nombre_archivo, 'r') as file:
        for linea in file:
            if 'IPv4' in linea:
                fecha_str = linea[:18]  # Extraer la fecha de la línea
                fecha = datetime.strptime(fecha_str, '%m/%d %H:%M:%S.%f')  # Convertir la cadena de fecha a un objeto datetime
                if fecha > fecha_mas_reciente:
                    fecha_mas_reciente = fecha
                    linea_mas_reciente = linea
    return linea_mas_reciente.strip()

@app.route('/')
def mostrar_informacion():
    informacion = obtener_informacion(SMF)

    ip_regex = r'IPv4\[(\d+\.\d+\.\d+\.\d+)\]'
    apn_regex = r'DNN\[(\w+)\]'
    imsi_regex = r'imsi-(\d+)'

    ip_match = re.search(ip_regex, informacion)
    apn_match = re.search(apn_regex, informacion)
    imsi_match = re.search(imsi_regex, informacion)

    # Extraer los valores
    ip = ip_match.group(1) if ip_match else None
    apn = apn_match.group(1) if apn_match else None
    imsi = imsi_match.group(1) if imsi_match else None
    
    return render_template('index.html', ip=ip, apn=apn, imsi=imsi)

def obtener_trafico():    
    p = sub.Popen(['sudo', 'tcpdump', '-i', 'enp5s0', '-l', 'host', '158.49.247.113', '-c', str(MAX_PACKETS)], stdout=sub.PIPE, bufsize=1, universal_newlines=True)
    
    for row in iter(p.stdout.readline, ''):
        yield row.rstrip()

    p.stdout.close()

def actualizar_trafico():
    while True:
        traffic_data = list(obtener_trafico())
        print("Emitiendo:", traffic_data)  # Para depuración
        socketio.emit('trafico_update', {'traffic': traffic_data}, namespace='/trafico')
        time.sleep(2)

@app.route('/trafico')
def mostrar_trafico():
    return render_template('trafico.html')

if __name__ == '__main__':
    t = threading.Thread(target=actualizar_trafico)
    t.daemon = True  # Hacer que el thread se detenga cuando la aplicación Flask se detenga
    t.start()
    print("illlllo")
    socketio.run(app, debug=True)
