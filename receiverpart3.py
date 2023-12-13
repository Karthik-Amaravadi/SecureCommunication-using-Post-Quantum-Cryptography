import socket, sys,time
from secrets import compare_digest
import client_server
import pqcrypto.kem.kyber512 as kyber
import pqcrypto.sign.falcon_512 as falcon
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

s = socket.socket()
host="0.tcp.in.ngrok.io"
port_sender = 12345
port_receiver = 15824
#s.connect(("192.168.1.129", port))


client_server.receive_file_from_server(host,port_receiver,'falcon512_public_key')
time.sleep(3)
with open('falcon512_public_key','rb') as f:
    public_key_sender = f.read()
print(public_key_sender)
public_key_receiver,private_key_receiver=kyber.generate_keypair()
with open("kyber512_public_key",'wb') as f:
    f.write(public_key_receiver)
time.sleep(1)
client_server.send_file_to_client("0.0.0.0",port_sender,"kyber512_public_key")
#print(public_key_receiver)
time.sleep(1)
#ct1=s.recv(769)
#print(ct1)
#ct1=s.recv(int.from_bytes(s_ct1, byteorder='big'))
#ct_size = s.recv(30).decode()
#print(int(ct_size))
a = input("Press Enter when other end is listening")
client_server.receive_file_from_server(host,port_receiver,"ciphertext")
with open('ciphertext','rb') as f:
    ct = f.read()
#ct=s.recv(int(ct_size))
#print("size of ct:"+str(sys.getsizeof(ct)))
ct1 = ct.split(b"\n\nC1---C2---SEP\n\n")[0]
#print("size of ct1:"+str(sys.getsizeof(ct1)))
ct2 = ct.split(b"\n\nC1---C2---SEP\n\n")[1]
#print("size of ct2:"+str(sys.getsizeof(ct2)))
pt_1 = kyber.decrypt(private_key_receiver, ct1)
#print("size of pt1:"+str(sys.getsizeof(pt_1)))

kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'message_key')
key = kdf.derive(pt_1)
#print(b'message key is :'+key)
si_public_key,si_private_key=falcon.generate_keypair()
#s.send(si_public_key)
nonce = b'000000000000'
aad = b'CS645/745 Modern Cryptography' 
cipher = ChaCha20Poly1305(key)
pt_2= cipher.decrypt(nonce, ct2,aad)
#print("size of pt2:"+str(sys.getsizeof(pt_2)))
msg=pt_2.split(b"\nsig----data---sep\n")
#print(msg[0])

ver = falcon.verify(public_key_sender,msg[0], msg[1])
print(ver)
if ver==True:
    f = open("received.txt",'wb')
    f.write(msg[0])
    f.close()

#s.send(signature)
#print("signature sent")

s.close()
