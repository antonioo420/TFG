from collections import defaultdict
import os
from flask import Flask, render_template, Response, request
import time
import threading
import subprocess as sub
from flask_socketio import SocketIO
from flask_cors import CORS
from dummy import addDummy
from utils import *

app = Flask(__name__)
cors = CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", namespace='/trafico')

#Variables globales
SMF = '/var/log/open5gs/smf.log'
AMF = '/var/log/open5gs/amf.log'
tcpdump_process = None
stop_log=False
#ues = defaultdict(dict)

@app.route('/')
def mostrar_informacion():    
    stop_tcpdump()
    t2 = threading.Thread(target=actualizar_informacion)
    t2.daemon = True  # Hacer que el thread se detenga cuando la aplicación Flask se detenga
    t2.start()  
    current_path = request.path
    return render_template('index.html', current_path = current_path)

def actualizar_informacion():
    ues = defaultdict(dict)
    time.sleep(1)  
    while True:              
        ues = obtener_informacion(SMF,ues)  
        num_ues = obtener_num_ues(AMF)
        gnb = comprobar_gnb(AMF)
        #print('Emitiendo:', {'ues':ues, 'num_ues':num_ues, 'gnb':gnb})
        #addDummy(ues)
        socketio.emit('info_update', {'ues':ues, 'num_ues':num_ues, 'gnb': gnb})
        time.sleep(5)   

@socketio.on('start_log')
def show_log():    
    global AMF
    #global SMF
    global stop_log
    log_file = AMF
    stop_log = False
    try:
        file_size = os.path.getsize(log_file)

        with open(log_file, 'r', encoding='latin-1') as f:
            while True:
                if stop_log == False:
                    # Verificar si el tamaño del archivo ha cambiado (=nueva entrada)
                    current_size = os.path.getsize(log_file)
                    if current_size >= file_size:                        
                        # Ir a la última posición en el archivo
                        f.seek(file_size)
                        # Leer y enviar nuevas líneas                                                
                        for line in f.readlines():                            
                            socketio.emit('log_update', {'line': line})
                            print(line)
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
        
@app.route('/trafico')
def mostrar_trafico():   
    ues = defaultdict(dict) 
    ues = obtener_informacion(SMF, ues)
    ips = obtener_ips(ues)
    #print(ips)
    current_path = request.path
    select_value = request.args.get('select_value', 'opcion1')
    return render_template('trafico.html', ips=ips, current_path = current_path, select_value=select_value)

def obtener_trafico(ip):    
    global tcpdump_process    
    tcpdump_process = sub.Popen(['sudo', 'tcpdump', '-n', '-i', 'ogstun', '-l', 'host', ip], stdout=sub.PIPE, bufsize=1, universal_newlines=True)
    
    for row in iter(tcpdump_process.stdout.readline, ''):
        if tcpdump_process:
            #print(row)
            yield parse_packet(row)
        else:
            break

@socketio.on('start_tcpdump')
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

@app.route('/estadisticas')
def pruebas():
    current_path = request.path
    return render_template('estadisticas.html', current_path=current_path)

@socketio.on('connect')
def handle_connect():
    print('Cliente conectado')

if __name__ == '__main__':    
    socketio.run(app, debug=True)

