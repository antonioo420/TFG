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

app = Flask(__name__)
cors = CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", namespace='/trafico')

#Variables globales
SMF = '/var/log/open5gs/smf.log'
fecha_mas_reciente = datetime(1,1,1,0,0)
MAX_PACKETS = 2
ip = 0
continuar_tcpdump = False
def obtener_informacion(nombre_archivo):
    global fecha_mas_reciente
    global ip    
    linea_mas_reciente = ""
    with open(nombre_archivo, 'r') as file:
        for linea in file:
            if 'IPv4' in linea:
                fecha_str = linea[:18]  # Extraer la fecha de la línea
                fecha = datetime.strptime(fecha_str, '%m/%d %H:%M:%S.%f')  # Convertir la cadena de fecha a un objeto datetime
                if fecha >= fecha_mas_reciente:
                    fecha_mas_reciente = fecha
                    linea_mas_reciente = linea

    ip_regex = r'IPv4\[(\d+\.\d+\.\d+\.\d+)\]'
    apn_regex = r'DNN\[(\w+)\]'
    imsi_regex = r'imsi-(\d+)'

    ip_match = re.search(ip_regex, linea_mas_reciente)
    apn_match = re.search(apn_regex, linea_mas_reciente)
    imsi_match = re.search(imsi_regex, linea_mas_reciente)

    # Extraer los valores
    ip = ip_match.group(1) if ip_match else None
    apn = apn_match.group(1) if apn_match else None
    imsi = imsi_match.group(1) if imsi_match else None

    return ip, apn, imsi

def actualizar_informacion():
    global ip
    ip, apn, imsi = obtener_informacion(SMF)  
    print('Emitiendo:', {'ip':ip, 'apn':apn, 'imsi':imsi})
    socketio.emit('info_update', {'ip':ip, 'apn':apn, 'imsi':imsi})    
    
@app.route('/')
def mostrar_informacion():    
    # t2 = threading.Thread(target=actualizar_informacion)
    # t2.daemon = True  # Hacer que el thread se detenga cuando la aplicación Flask se detenga
    # t2.start()   
    global continuar_tcpdump
    continuar_tcpdump = False  # Reiniciar tcpdump   
    ip, apn, imsi = obtener_informacion(SMF)    
    return render_template('index.html', ip=ip, apn=apn, imsi=imsi)

def obtener_trafico():    
    print('IP trafico: ', ip)
    p = sub.Popen(['sudo', 'tcpdump', '-n', '-i', 'ogstun', '-l', 'host', str(ip)], stdout=sub.PIPE, bufsize=1, universal_newlines=True)
    
    for row in iter(p.stdout.readline, ''):
        #print (continuar_tcpdump)
        if not continuar_tcpdump:
            break
        print(row)
        yield parse_packet(row)
        #yield row.rstrip()

    parent = psutil.Process(p.pid)
    for child in parent.children(recursive=True):
        child.kill()
    parent.kill()
    p.stdout.close()

def actualizar_trafico():
    for row in obtener_trafico():            
        #socketio.emit('trafico_update', row)
        #print("Emitiendo:", row)  # Para depuración     
        print(json.dumps(row, indent=4))
        
@app.route('/trafico')
def mostrar_trafico():
    t = threading.Thread(target=actualizar_trafico)
    t.daemon = True  # Hacer que el thread se detenga cuando la aplicación Flask se detenga
    t.start()
    global continuar_tcpdump
    continuar_tcpdump = True
    return render_template('trafico.html')

@socketio.on('connect')
def handle_connect():
    print('Cliente conectado')

def parse_packet(line):
    # Expresión regular para hacer coincidir los elementos de la línea
    patternS = r'(\d{2}:\d{2}:\d{2}\.\d+)\sIP\s((?:\d+\.){3}\d+)\.(\d+)\s>\s((?:\d+\.){3}\d+)\.(\d+):\sFlags\s\[(\S+)\],\sseq\s(\d+(?::\d+)?),\sack\s(\d+),\swin\s(\d+),\soptions\s\[(.*?)\],\slength\s(\d+)'
    patternNoSeq = r'(\d{2}:\d{2}:\d{2}\.\d+)\sIP\s((?:\d+\.){3}\d+)\.(\d+)\s>\s((?:\d+\.){3}\d+)\.(\d+):\sFlags\s\[(\S+)\],\sack\s(\d+),\swin\s(\d+),\soptions\s\[(.*?)\],\slength\s(\d+)'
    patternNoSeqNoOpt = r'(\d{2}:\d{2}:\d{2}\.\d+)\sIP\s((?:\d+\.){3}\d+)\.(\d+)\s>\s((?:\d+\.){3}\d+)\.(\d+):\sFlags\s\[(\S+)\],\sack\s(\d+),\swin\s(\d+),\slength\s(\d+)'
    patternNoAck = r'(\d{2}:\d{2}:\d{2}\.\d+)\sIP\s((?:\d+\.){3}\d+)\.(\d+)\s>\s((?:\d+\.){3}\d+)\.(\d+):\sFlags\s\[(\S+)\],\sseq\s(\d+),\swin\s(\d+),\soptions\s\[(.*?)\],\slength\s(\d+)'
    patternNoAckNoOpt = r'(\d{2}:\d{2}:\d{2}\.\d+)\sIP\s((?:\d+\.){3}\d+)\.(\d+)\s>\s((?:\d+\.){3}\d+)\.(\d+):\sFlags\s\[(\S+)\],\sseq\s(\d+(?::\d+)?),\swin\s(\d+),\slength\s(\d+)'
    patternNoOpt = r'(\d{2}:\d{2}:\d{2}\.\d+)\sIP\s((?:\d+\.){3}\d+)\.(\d+)\s>\s((?:\d+\.){3}\d+)\.(\d+):\sFlags\s\[(\S+)\],\sseq\s(\d+(?::\d+)?),\sack\s(\d+),\swin\s(\d+),\slength\s(\d+)'
    patternUdp = r'(\d{2}:\d{2}:\d{2}\.\d+)\sIP\s((?:\d+\.){3}\d+)\.(\d+)\s>\s((?:\d+\.){3}\d+)\.(\d+):\sUDP,\slength\s(\d+)'

   
    algun_match = False
    match = re.match(patternS, line)
    match3 = re.match(patternNoSeq, line)
    match4 = re.match(patternNoSeqNoOpt, line)
    match5 = re.match(patternNoAck, line)
    match6 = re.match(patternNoAckNoOpt, line)
    match7 = re.match(patternNoOpt, line)
    match8 = re.match(patternUdp, line)
    if match:
        timestamp = match.group(1)
        src_ip = match.group(2)
        src_port = match.group(3)
        dst_ip = match.group(4)
        dst_port = match.group(5)
        flags = match.group(6)
        seq = match.group(7)
        ack = match.group(8)
        win = match.group(9)
        options = match.group(10)
        len = match.group(11)
        algun_match = True
    else :
        if match3:
            timestamp = match3.group(1)
            src_ip = match3.group(2)
            src_port = match3.group(3)
            dst_ip = match3.group(4)
            dst_port = match3.group(5)
            flags = match3.group(6)
            seq = ""
            ack = match3.group(7)
            win = match3.group(8)
            options = match3.group(9)
            len = match3.group(10)
            algun_match = True
        else:
            if match4:
                timestamp = match4.group(1)
                src_ip = match4.group(2)
                src_port = match4.group(3)
                dst_ip = match4.group(4)
                dst_port = match4.group(5)
                flags = match4.group(6)
                seq = ""
                ack = match4.group(7)
                win = match4.group(8)
                options = ""
                len = match4.group(9)
                algun_match = True
            else:
                if match5: 
                    timestamp = match5.group(1)
                    src_ip = match5.group(2)
                    src_port = match5.group(3)
                    dst_ip = match5.group(4)
                    dst_port = match5.group(5)
                    flags = match5.group(6)
                    seq = match5.group(7)
                    ack = ""
                    win = match5.group(8)
                    options = match5.group(9)
                    len = match5.group(10)
                    algun_match = True
                else:
                    if match6:
                        timestamp = match6.group(1)
                        src_ip = match6.group(2)
                        src_port = match6.group(3)
                        dst_ip = match6.group(4)
                        dst_port = match6.group(5)
                        flags = match6.group(6)
                        seq = match6.group(7)
                        ack = ""
                        win = match6.group(8)
                        options = ""
                        len = match6.group(9)
                        algun_match = True
                    else:
                        if match7:
                            timestamp = match7.group(1)
                            src_ip = match7.group(2)
                            src_port = match7.group(3)
                            dst_ip = match7.group(4)
                            dst_port = match7.group(5)
                            flags = match7.group(6)
                            seq = match7.group(7)
                            ack = match7.group(8)
                            win = match7.group(9)
                            options = ""
                            len = match7.group(10)
                            algun_match = True
                        else:
                            if match8: 
                                timestamp = match8.group(1)
                                src_ip = match8.group(2)
                                src_port = match8.group(3)
                                dst_ip = match8.group(4)
                                dst_port = match8.group(5)
                                flags = ""
                                seq = ""
                                ack = ""
                                win = ""
                                options = "UDP"
                                len = match8.group(6)
                                algun_match = True

    if algun_match:       
        return {
                    "timestamp": timestamp,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "flags": flags,
                    "seq": seq,
                    "ack": ack,
                    "win": win,
                    "options": options,
                    "len": len
                }
    else:
        print("---------------------------------No match--------------------------------")
        return None

if __name__ == '__main__':    
    socketio.run(app, debug=True)
