from flask import Flask, render_template
import time
import threading
from datetime import datetime
import re

app = Flask(__name__)

#Variables globales
SMF = '/var/log/open5gs/smf.log'
fecha_mas_reciente = datetime(1,1,1,0,0)

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


def actualizar_informacion():
    while True:
        informacion = obtener_informacion(SMF)
        app.config['INFORMACION'] = informacion
        time.sleep(5)  # Esperar 5 segundos antes de volver a obtener la información

@app.route('/')
def mostrar_informacion():
    #informacion = app.config.get('INFORMACION', '')
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

if __name__ == '__main__':
    thread = threading.Thread(target=actualizar_informacion)
    thread.start()
    app.run(debug=True)
