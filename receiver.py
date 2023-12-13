import socket, sys,time
from secrets import compare_digest
import pqcrypto.kem.kyber512 as kyber
import pqcrypto.sign.falcon_512 as falcon
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

s = socket.socket()
host="192.168.1.129"
port = 12345
s.connect((host, port))


public_key_sender=s.recv(1024)
public_key_receiver,private_key_receiver=kyber.generate_keypair()
s.send(public_key_receiver)
#print(public_key_receiver)
time.sleep(1)
#ct1=s.recv(769)
#print(ct1)
#ct1=s.recv(int.from_bytes(s_ct1, byteorder='big'))
ct_size = s.recv(30).decode()
#print(int(ct_size))
ct = b''
while True:
    chunk = s.recv(1024)
    if not chunk:
        break
    ct += chunk
#ct=s.recv(int(ct_size))
print("size of ct:"+str(sys.getsizeof(ct)))
ct1 = ct.split(b"ciphertext2 :")[0]
print("size of ct1:"+str(sys.getsizeof(ct1)))
ct2 = ct.split(b"ciphertext2 :")[1]
print("size of ct2:"+str(sys.getsizeof(ct2)))
pt_1 = kyber.decrypt(private_key_receiver, ct1)
print("size of pt1:"+str(sys.getsizeof(pt_1)))

kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'message_key')
key = kdf.derive(pt_1)
#print(b'message key is :'+key)
si_public_key,si_private_key=falcon.generate_keypair()
#s.send(si_public_key)
nonce = b'00000000'
aad = b'CS645/745 Modern Cryptography' 
cipher = AESGCM(key)
pt_2= cipher.decrypt(nonce, ct2,aad)
print("size of pt2:"+str(sys.getsizeof(pt_2)))
msg=pt_2.split(b"signature :")
print(msg[0])

ver = falcon.verify(public_key_sender,msg[0], msg[1])
print(ver)
if ver==True:
    f = open("received.txt",'wb')
    f.write(msg[0])
    f.close()

#s.send(signature)
#print("signature sent")

s.close()
