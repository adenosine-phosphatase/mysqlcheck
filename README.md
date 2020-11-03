# mysqlcheck
Login bruteforce/password cracker for mysql Secure Password Authentication

This is ,functionality wise, relative close to the Metasploit auxiliary/scanner/mysql_login.
Essentially, the code asks you to enter IP address of the MySQL server and the username.
Then it loads passwords in clear text from a dictionary file, calculates the password hash, sends it to the server and checks response.
If the reponose contains no error, it displays the password.
Bear in mind this is more Proof of Concept so the code may fail to parse Server Greetings response if some unusal fields are contained in the payload.

python mysqlcheck4.py <ip address> <username>
