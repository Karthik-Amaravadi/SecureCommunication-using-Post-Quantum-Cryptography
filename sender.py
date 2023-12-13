import socket, sys, time,os		
from secrets import compare_digest
import pqcrypto.kem.kyber512 as kyber
import pqcrypto.sign.falcon_512 as falcon
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('192.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP
 

s = socket.socket()		
host=get_local_ip()
port = 12345			
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)	
s.bind((host, port))		
print ("socket binded to  %s" %(host)+":%s"%(port))
s.listen(5)	
print ("socket is listening")		

while True:
  c, addr = s.accept()	
  print ('Got connection from', addr )

  public_key_sender, secret_key_sender = falcon.generate_keypair()
  c.send(public_key_sender)

  public_key_recevier=c.recv(1024)
#   print(public_key_recevier)
  f = open("test_file_2.txt", 'rb')
  data=f.read()
  f.close()
#   data=b'otha'
  signature_sigma = falcon.sign(secret_key_sender, data)

  ciphertext1, pt_1 = kyber.encrypt(public_key_recevier)
  time.sleep(1)
  kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'message_key')
  message_key = kdf.derive(pt_1)


  nonce = b'00000000'
  aad = b'CS645/745 Modern Cryptography'  # insert any additional associated data to be authenticated here
  cipher = AESGCM(message_key)
  pt_2= data +b'signature :'+ signature_sigma
  ciphertext2= cipher.encrypt(nonce, pt_2, aad)
  time.sleep(1)
  ct=ciphertext1 +b'ciphertext2 :'+ciphertext2
  s_ct=bytes(str(sys.getsizeof(ct)),'utf-8')
  time.sleep(1)
  print("size of ct:"+str(s_ct))
#   print("size of ct1:"+str(sys.getsizeof(ciphertext1)))
#   print("size of ct2:"+str(sys.getsizeof(ciphertext2)))
#   print("size of pt_1:"+str(sys.getsizeof(pt_1)))
#   print("size of pt_2:"+str(sys.getsizeof(pt_2)))
  c.send(s_ct)
  time.sleep(1)

  c.sendall(ct)
  c.close()
  s.close()
  break
