def obtener_informacion(nombre_archivo):
    with open(nombre_archivo, 'r') as file:
        for linea in file:
            if 'IPv4' in linea:
                fecha_str = linea[:18]  # Extraer la fecha de la línea
                fecha = datetime.strptime(fecha_str, '%m/%d %H:%M:%S.%f')  # Convertir la cadena de fecha a un objeto datetime
                if fecha >= ip_mas_reciente:
                    ip_mas_reciente = fecha
                    linea_mas_reciente = linea

    ip_regex = r'IPv4\[(\d+\.\d+\.\d+\.\d+)\]'
    apn_regex = r'DNN\[(\w+)\]'
    imsi_regex = r'imsi-(\d+)'
    removed_regex = r'Removed Session'

    removed_match = re.search(removed_regex, linea_mas_reciente)

    if not removed_match:
        ip_match = re.search(ip_regex, linea_mas_reciente)
        apn_match = re.search(apn_regex, linea_mas_reciente)
        imsi_match = re.search(imsi_regex, linea_mas_reciente)
        
        # Extraer los valores
        ip = ip_match.group(1) if ip_match else None
        apn = apn_match.group(1) if apn_match else None
        imsi = imsi_match.group(1) if imsi_match else None
    else:
        ip = None
        apn = None 
        imsi = None

    return ip, apn, imsi