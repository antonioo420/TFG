from collections import defaultdict
import os
from flask import Flask, render_template, Response, request
import time
import threading
from datetime import datetime
import re
import subprocess as sub
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from dummy import addDummy
from parser_tcpdump import parse_packet
from file_read_backwards import FileReadBackwards

app = Flask(__name__)
cors = CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", namespace='/trafico')

#Variables globales
SMF = '/var/log/open5gs/smf.log'
AMF = '/var/log/open5gs/amf.log'
ue_mas_reciente = datetime(1,1,1,0,0)
tcpdump_process = None
stop_log=False
ues = defaultdict(dict)
ips = [] 

def obtener_informacion(nombre_archivo):
    global ues
    global ips
    ips.clear()
    with FileReadBackwards(nombre_archivo, encoding="utf-8") as file:
        ue_lines = []
        ue_removed = []
        for line in file:
            if 'IPv4' in line:
                if 'Removed Session' in line:
                    ue_removed.append(line)
                else:
                    ue_lines.append(line)
        
    for line in ue_lines:           
        ip,apn, imsi, timestamp_str = extraer_informacion(line)    
        #Se comprueba que ese UE ya exista    
        if imsi in ues:
            timestamp = datetime.strptime(timestamp_str, '%m/%d %H:%M:%S.%f')
            timestamp_guardado_str = ues[imsi]['timestamp']
            timestamp_guardado = datetime.strptime(timestamp_guardado_str, '%m/%d %H:%M:%S.%f')
            #Si existe una entrada más nueva de ese UE, se actualiza
            if timestamp >= timestamp_guardado:
                ues[imsi] = {                  
                    'ip': ip,
                    'apn': apn,
                    'timestamp': timestamp_str 
                }
                ips.append(ip)
                print(ips)
        else: #Si no existe el UE, se inserta            
            ues[imsi] = {                  
                'ip': ip,
                'apn': apn,
                'timestamp': timestamp_str 
            }
            ips.append(ip)
            print(ips)
                
    #En el caso de que se haya eliminado la conexión
    for line in ue_removed:
        ip, apn, imsi, timestamp_str = extraer_informacion(line)
        #Se comprueba que haya una conexión activa del UE
        if imsi in ues:            
            timestamp = datetime.strptime(timestamp_str, '%m/%d %H:%M:%S.%f')
            timestamp_guardado_str = ues[imsi]['timestamp']
            timestamp_guardado = datetime.strptime(timestamp_guardado_str, '%m/%d %H:%M:%S.%f')
            #Si la desconexión es posterior a la desconexión, se elimina el UE
            if timestamp > timestamp_guardado:
                ues.pop(imsi, None)
                if ip in ips:
                    ips.remove(ip)
                
def extraer_informacion(linea):
    ip_regex = r'IPv4\[(\d+\.\d+\.\d+\.\d+)\]'
    apn_regex = r'DNN\[(\w+)\]'
    imsi_regex = r'imsi-(\d+)'
    
    ip_match = re.search(ip_regex, linea)
    apn_match = re.search(apn_regex, linea)
    imsi_match = re.search(imsi_regex, linea)
    
    fecha_str = linea[:18]  # Extraer la fecha de la línea
    
    
    # Extraer los valores
    ip = ip_match.group(1) if ip_match else None
    apn = apn_match.group(1) if apn_match else None
    imsi = imsi_match.group(1) if imsi_match else None
    timestamp = fecha_str

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
        addDummy(ues)
        socketio.emit('info_update', {'ues':ues, 'num_ues':num_ues})
        time.sleep(5)   

    
@app.route('/')
def mostrar_informacion():    
    stop_tcpdump()
    t2 = threading.Thread(target=actualizar_informacion)
    t2.daemon = True  # Hacer que el thread se detenga cuando la aplicación Flask se detenga
    t2.start()  
    current_path = request.path
    return render_template('index.html', current_path = current_path)
        
@app.route('/trafico')
def mostrar_trafico():
    global ips
    print('Ips enviadas')
    print(ips)
    current_path = request.path
    return render_template('trafico.html', ips=ips, current_path = current_path)

def obtener_trafico(ip):    
    global tcpdump_process    
    tcpdump_process = sub.Popen(['sudo', 'tcpdump', '-n', '-i', 'ogstun', '-l', 'host', ip], stdout=sub.PIPE, bufsize=1, universal_newlines=True)
    
    for row in iter(tcpdump_process.stdout.readline, ''):
        if tcpdump_process:
            #print(row)
            yield parse_packet(row)
        else:
            break

@socketio.on('continue_tcpdump')
def actualizar_trafico(data):
    for row in obtener_trafico(data['selectedIp']):            
        socketio.emit('trafico_update', row)
        #print(json.dumps(row, indent=4))

@socketio.on('stop_tcpdump')
def stop_tcpdump():
    global tcpdump_process
    if tcpdump_process:
        tcpdump_process.terminate()
        tcpdump_process = None
        print("Tcpdump detenido")
        socketio.emit('tcpdump_stopped', "Tcpdump detenido")


@socketio.on('connect')
def handle_connect():
    print('Cliente conectado')

@socketio.on('start_log')
def show_log():
    global AMF
    global stop_log
    log_file = AMF    
    stop_log = False
    try:
        file_size = os.path.getsize(log_file)

        with open(log_file, 'r', encoding='latin-1') as f:
            while True:
                if stop_log == False:
                    # Verificar si el tamaño del archivo ha cambiado (nueva entrada)
                    current_size = os.path.getsize(log_file)
                    if current_size >= file_size:
                        # Ir a la última posición en el archivo
                        f.seek(file_size)
                        # Leer y enviar nuevas líneas
                        for line in f.readlines():
                            socketio.emit('log_update', {'line': line})
                        # Actualizar el tamaño del archivo
                        file_size = current_size
                    # Esperar antes de volver a verificar el archivo
                    time.sleep(1)
                else:
                    break
    except Exception as e:
        print("Error al leer el archivo de log:", e)

@socketio.on('stop_log')
def stop_log():
    global stop_log 
    stop_log = True
    socketio.emit('log_stopped', "Captura de log detenida")

if __name__ == '__main__':    
    socketio.run(app, debug=True)
