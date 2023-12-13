import socket, sys, time,os		
from secrets import compare_digest
import pqcrypto.kem.kyber512 as kyber
import client_server
import pqcrypto.sign.falcon_512 as falcon
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

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
port_sender = 12345		
port_receiver = 15824
ip_receiver = "0.tcp.in.ngrok.io"

#s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)	
FILE_path = "falcon512_public_key"
#s.bind((host, port))		
print ("socket binded to  %s" %(host)+":%s"%(port))
#s.listen(5)	
print ("socket is listening")		

while True:
  #c, addr = s.accept()	
  #print ('Got connection from', addr )
  

  public_key_sender, secret_key_sender = falcon.generate_keypair()
  with open(FILE_path, 'wb') as f:
        f.write(public_key_sender)
  client_server.send_file_to_client('0.0.0.0',port_sender,FILE_path)
  public_key_recevier = b''
  a = input("Press enter when other end is listening")
  client_server.receive_file_from_server(ip_receiver,port_receiver,"kyber512_public_key")
  time.sleep(5)
  with open("kyber512_public_key",'rb') as f:
      public_key_recevier = f.read()
    
  #public_key_recevier=c.recv(1024)
  
  print(public_key_recevier)
  f = open("test_file_2.txt", 'rb')
  data=f.read()
  f.close()
#   data=b'otha'
  signature_sigma = falcon.sign(secret_key_sender, data)

  ciphertext1, pt_1 = kyber.encrypt(public_key_recevier)
  time.sleep(1)
  kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'message_key')
  message_key = kdf.derive(pt_1)

  #print("Seed :"+str(pt_1))
  nonce = b"000000000000"
  aad = b"CS645/745 Modern Cryptography"  # insert any additional associated data to be authenticated here
  cipher = ChaCha20Poly1305(message_key)
  pt_2= data +b'\nsig----data---sep\n'+ signature_sigma
  ciphertext2= cipher.encrypt(nonce, pt_2, aad)
  time.sleep(1)
  ct=ciphertext1 +b"\n\nC1---C2---SEP\n\n"+ciphertext2
  s_ct=bytes(str(sys.getsizeof(ct)),'utf-8')
  #time.sleep(1)
  print("size of ct:"+str(s_ct))
#   print("size of ct1:"+str(sys.getsizeof(ciphertext1)))
#   print("size of ct2:"+str(sys.getsizeof(ciphertext2)))
#   print("size of pt_1:"+str(sys.getsizeof(pt_1)))
#   print("size of pt_2:"+str(sys.getsizeof(pt_2)))
  #c.send(s_ct)
  time.sleep(1)
  with open("ciphertext",'wb') as f:
      f.write(ct)
  client_server.send_file_to_client('0.0.0.0',port_sender,"ciphertext")
  #c.sendall(ct)
  #c.close()
  #s.close()
  break
