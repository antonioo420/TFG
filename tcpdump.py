import subprocess as sub

# Ejecutar tcpdump con sudo para capturar el tráfico de red en tiempo real
p = sub.Popen(('sudo', 'tcpdump', '-l', 'host', '10.45.0.7'), stdout=sub.PIPE)

# Leer la salida de tcpdump línea por línea
for row in iter(p.stdout.readline, b''):
    print(row.decode('utf-8').rstrip())  # Imprimir la línea procesada

# Esperar a que termine el proceso de tcpdump
p.communicate()
