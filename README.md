# CriptoLab

## Códigos usados:

### Cesar
```
def encrypt(text, s):
    result = ""
    for i in range(len(text)):
        char = text[i]
        if char.isupper():
            result += chr((ord(char) + s - 65) % 26 + 65)
        else:
            result += chr((ord(char) + s - 97) % 26 + 97)
    return result
text = input(" ")
s = int(input(" "))
print("Cifrado: " + encrypt(text, s))
```
**Uso terminal: sudo python3 cesar.py "texto" "numero"**

### PINGV4
```
from scapy.all import *
import time

def generate_data_payload(identifier, first_byte):
    sequence = bytes.fromhex("9a 4f 07 00 00 00 00 00 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37") #Secuencia "base" para rellenar el payload
    timestamp = int(time.time())   #Generación del timestamp y manejo de bits para que quede con formato correcto
    timestamp_bytes = struct.pack("!Q", timestamp)  
    
    non_zero_index = next((i for i, byte in enumerate(timestamp_bytes) if byte != 0), None)
    trimmed_timestamp = timestamp_bytes[non_zero_index:] if non_zero_index is not None else b'\x00'
    
    num_zeros = non_zero_index if non_zero_index is not None else 0
    padded_timestamp = trimmed_timestamp + b'\x00' * num_zeros
    
    data_payload =  padded_timestamp +bytes([ord(first_byte)]) + sequence[1:48]   #Payload a usar
    return identifier, data_payload
    
  
def send_ping_with_data_payload(destination_ip, data_string):
    identifier = 9     #Variables a usar
    message_count = 0
    seq = 1
    
    for char in data_string:
        icmp_packet = IP(dst=destination_ip) / ICMP(type="echo-request", id=identifier, seq=seq) / Raw(load=generate_data_payload(identifier, char)[1])  #Se genera un paquete icmp de tipo request, se le asigna id, numero de secuencia 
        					      # y se le asigna su payload

        send(icmp_packet)

        message_count += 1
        seq += 1
        
        if message_count % 3 == 0:
            identifier += 1

if _name_ == "_main_":
    destination_ip = "8.8.8.8" #IP a transmitir designada en el lab
    data_string = input("Ingrese string: ")
    send_ping_with_data_payload(destination_ip, data_string)
```
**Uso terminal:  sudo python3 pingv4.py "texto"**

### Decriptor
```
```
**Uso terminal: sudo python3 decriptor.py "nombrepcap".pcap**
