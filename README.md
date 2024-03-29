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
from scapy.all import rdpcap

def get_icmp_byte_ascii(file_path, byte_index): #Función para sacar los valores ascii del byte
    packets = rdpcap(file_path)

    byte_values = []

    for packet in packets:
        if packet.haslayer("ICMP"):
            icmp_data = bytes(packet["ICMP"])

            if byte_index < len(icmp_data):
                byte_value = icmp_data[byte_index]
                byte_ascii = chr(byte_value)
                byte_values.append(byte_ascii)

    return byte_values

def caesar_decipher(text, shift):	#Función para decriptar el cifrado cesar
    decrypted_text = ""
    for char in text:
        if char.isupper():
            decrypted_text += chr((ord(char) - shift - 65) % 26 + 65)
        elif char.islower():
            decrypted_text += chr((ord(char) - shift - 97) % 26 + 97)
        else:
            decrypted_text += char
    return decrypted_text
    

file_name = input("Ingresar el nombre del archivo pcapng (con extension): ")

file_path = "/tmp/" + file_name

byte_index = 16 

byte_ascii_values = get_icmp_byte_ascii(file_path, byte_index)

if byte_ascii_values:
	string_original = ''.join(byte_ascii_values)
	
	for shift in range(26):
		decrypted_string = caesar_decipher(string_original,shift) #Se imprimen los valores, si ese el que posee llave 9, se imprime verde
		if shift==9:
			print(f"\033[92mLlave {shift}: {decrypted_string}\033[0m")
		else:
			print(f"Llave {shift}: {decrypted_string}")
else:
    print("No ICMP packets with the specified byte index found in the capture file.")
```
**Uso terminal: sudo python3 readv2.py "nombrepcap.pcap"**
