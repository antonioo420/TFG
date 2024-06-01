from datetime import datetime
from file_read_backwards import FileReadBackwards
import re

def obtener_informacion(nombre_archivo, ues):    
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
        else: #Si no existe el UE, se inserta            
            ues[imsi] = {                  
                'ip': ip,
                'apn': apn,
                'timestamp': timestamp_str 
            }                        
                
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
    return ues
                
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
    linea_mas_reciente = ""
    fecha_mas_reciente = datetime(1,1,1,0,0)
    with open(nombre_archivo, 'r', encoding='ISO-8859–1') as file:
        for linea in file:
            if 'Number of gNB-UEs is now' in linea:
                fecha_str = linea[:18]  # Extraer la fecha de la línea
                fecha = datetime.strptime(fecha_str, '%m/%d %H:%M:%S.%f')  # Convertir la cadena de fecha a un objeto datetime
                if fecha >= fecha_mas_reciente:
                    fecha_mas_reciente = fecha
                    linea_mas_reciente = linea

    #print(linea_mas_reciente)
    match = re.search(r'is now (\d+)', linea_mas_reciente)
    ue = match.group(1) if match else None

    return ue

def comprobar_apn(nombre_archivo):
    fecha_mas_reciente = datetime(1,1,1,0,0)
    linea_mas_reciente = ""
    with open(nombre_archivo, 'r', encoding='ISO-8859–1') as file:
        for linea in file:
            if 'Number of gNBs is now' in linea:
                fecha_str = linea[:18]  # Extraer la fecha de la línea
                fecha = datetime.strptime(fecha_str, '%m/%d %H:%M:%S.%f')  # Convertir la cadena de fecha a un objeto datetime
                if fecha >= fecha_mas_reciente:
                    fecha_mas_reciente = fecha
                    linea_mas_reciente = linea

    #print(linea_mas_reciente)
    match = re.search(r'is now (\d+)', linea_mas_reciente)
    apn = match.group(1) if match else None

    return apn

def obtener_ips(ues):
    lista_ips = []
    for clave, valor in ues.items():
        if 'ip' in valor:
            lista_ips.append(valor['ip'])
    
    return lista_ips
