import subprocess
import time
import sys
import os

if len(sys.argv) != 2:
	print ("Usage: python run.py <number_of_faults>")
	sys.exit(-1)

servers = 3*int(sys.argv[1]) + 1

os.chdir("..\\scripts\\")

subprocess.call('sh cleanup.sh', shell=True)

for i in range(servers):
	subprocess.call('sh generate_keystore.sh server ' + str(i), shell=True)

os.chdir("..\\ServerSide\\")

for i in range(servers):
	subprocess.call('start cmd /k java -cp "target/classes/;../Interface/target/classes" main.java.PasswordServer ' + str(i), shell=True)
	time.sleep(0.5)

os.chdir("..\\ClientSide\\")
subprocess.call('start cmd /k java -cp "target/classes/;../Interface/target/classes" main.java.Client 0 banana ' + sys.argv[1], shell=True)