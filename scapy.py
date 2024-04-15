from scapy.all import sniff, IP
from collections import deque

# Estructura de datos para almacenar los paquetes capturados
captured_packets = deque(maxlen=100)  # Almacena los ultimos 100 paquetes capturados

ip_a_filtrar = "10.45.0.7"
# Funcion para procesar el paquete capturado
def process_packet(packet):
    # Filtrar solo paquetes IP

    # Aqui puedes realizar el procesamiento adicional segun tus necesidades
    # Por ejemplo, podrias extraer la direccion IP de origen y destino, el protocolo, etc.
    # Luego, podrias almacenar estos datos en una base de datos u otra estructura de datos
    
    # Aqui solo imprimiremos un resumen del paquete
    packet_summary = packet.summary()
    print(packet_summary)
    
    # Almacenar el paquete en la estructura de datos
    captured_packets.append(packet_summary)

# Captura de paquetes en tiempo real
print("Capturando paquetes de red...")
sniff(iface="ogstun", prn=process_packet, filter="host 10.45.0.2")  # Filtra solo paquetes IP
