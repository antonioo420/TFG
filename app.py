from collections import defaultdict
from flask import Flask, render_template, Response
import time
import threading
from datetime import datetime
import re
import subprocess as sub
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import psutil
import json
from parser_tcpdump import parse_packet

app = Flask(__name__)
cors = CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", namespace='/trafico')

#Variables globales
SMF = '/var/log/open5gs/smf.log'
AMF = '/var/log/open5gs/amf.log'
ue_mas_reciente = datetime(1,1,1,0,0)
tcpdump_process = None

ues = defaultdict(dict)

def obtener_informacion(nombre_archivo):
    global ues
    with open(nombre_archivo, 'r') as file:
        lines = file.readlines()
        reversed_lines = reversed(lines)
        ue_lines = []
        ue_removed = []
        for line in reversed_lines:
            if 'IPv4' in line:
                if 'Removed Session' in line:
                    ue_removed.append(line)
                else:
                    ue_lines.append(line)
    
    #for line in ue_removed:
        
        # ip, apn, imsi, timestamp = extraer_informacion(line)
        # if timestamp > ues[imsi]['timestamp']:
        #     print (line)
        #     ues.pop(imsi, None)
    for line in ue_lines:
        ip,apn, imsi, timestamp = extraer_informacion(line)
        ues = {
            imsi: {
                'ip': ip,
                'apn': apn,
                'timestamp': timestamp 
            }
        }
                
def extraer_informacion(linea):
    ip_regex = r'IPv4\[(\d+\.\d+\.\d+\.\d+)\]'
    apn_regex = r'DNN\[(\w+)\]'
    imsi_regex = r'imsi-(\d+)'
    
    ip_match = re.search(ip_regex, linea)
    apn_match = re.search(apn_regex, linea)
    imsi_match = re.search(imsi_regex, linea)
    
    fecha_str = linea[:18]  # Extraer la fecha de la línea
    fecha = datetime.strptime(fecha_str, '%m/%d %H:%M:%S.%f')
    
    # Extraer los valores
    ip = ip_match.group(1) if ip_match else None
    apn = apn_match.group(1) if apn_match else None
    imsi = imsi_match.group(1) if imsi_match else None
    timestamp = fecha

    return ip, apn, imsi, timestamp

def obtener_num_ues(nombre_archivo):
    global ue_mas_reciente
    linea_mas_reciente = ""
    with open(nombre_archivo, 'r', encoding='ISO-8859–1') as file:
        for linea in file:
            if 'Number of AMF-Sessions is now' in linea:
                fecha_str = linea[:18]  # Extraer la fecha de la línea
                fecha = datetime.strptime(fecha_str, '%m/%d %H:%M:%S.%f')  # Convertir la cadena de fecha a un objeto datetime
                if fecha >= ue_mas_reciente:
                    ue_mas_reciente = fecha
                    linea_mas_reciente = linea

    #print(linea_mas_reciente)
    match = re.search(r'is now (\d+)', linea_mas_reciente)
    ue = match.group(1) if match else None

    return ue

def actualizar_informacion():
    while True:
        time.sleep(1)
        global ues
        obtener_informacion(SMF)  
        num_ues = obtener_num_ues(AMF)
        print('Emitiendo:', {'ues':ues, 'num_ues':num_ues})
        socketio.emit('info_update', {'ues':ues, 'num_ues':num_ues}) #timestamp no serializable xddddddddddddddddddddddddddddddd
        time.sleep(5)   
    
@app.route('/')
def mostrar_informacion():    
    stop_tcpdump()
    t2 = threading.Thread(target=actualizar_informacion)
    t2.daemon = True  # Hacer que el thread se detenga cuando la aplicación Flask se detenga
    t2.start()  
    return render_template('index.html')

def obtener_trafico():    
    global tcpdump_process
    print('IP trafico: ', ip)
    tcpdump_process = sub.Popen(['sudo', 'tcpdump', '-n', '-i', 'ogstun', '-l', 'host', str(ip)], stdout=sub.PIPE, bufsize=1, universal_newlines=True)
    
    for row in iter(tcpdump_process.stdout.readline, ''):
        if tcpdump_process:
            #print(row)
            yield parse_packet(row)
        else:
            break

@socketio.on('continue_tcpdump')
def actualizar_trafico():
    for row in obtener_trafico():            
        socketio.emit('trafico_update', row)
        #print(json.dumps(row, indent=4))
        
@app.route('/trafico')
def mostrar_trafico():
    t = threading.Thread(target=actualizar_trafico)
    t.daemon = True  # Hacer que el thread se detenga cuando la aplicación Flask se detenga
    t.start()
    return render_template('trafico.html')

@socketio.on('connect')
def handle_connect():
    print('Cliente conectado')

@socketio.on('stop_tcpdump')
def stop_tcpdump():
    global tcpdump_process
    if tcpdump_process:
        tcpdump_process.terminate()
        tcpdump_process = None
        print("Tcpdump detenido")
        socketio.emit('tcpdump_stopped', "Tcpdump detenido")

if __name__ == '__main__':    
    socketio.run(app, debug=True)
