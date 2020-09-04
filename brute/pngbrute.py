#!/bin/env python3
import sys, subprocess, os

"""
pngbrute.py made by Donovan Medina

This program looks through a file system that would not necessarily work with sleuthkit tools
such as fsstat or fls to find a png file.
"""


## functions
def usage():
	print("Usage: " + sys.argv[0] + " <block_size> <device>")


def find_potential(block_size, device):
	cmd = "sigfind -b " + str(block_size) + " 89504E47 " + device
	os.system(cmd + " > temp.temp")

	with open("temp.temp") as sig_file:
		cnt_line = 0
		for line in sig_file:
			if cnt_line != 0:
				line_tokens = line.split()
				starter_token = line_tokens[1]
				#obtained sector that starts with 89504E47
				
				#now run dd to find sector that ends with 
				counter = 1
				found = 0
				
				while found == 0:
					cmd_dd = "dd if=" + device + " bs=" + str(block_size) + " skip=" + str(starter_token) + " count=" + str(counter) + " | xxd | grep -i -w iend"
					if os.system(cmd_dd) == 0:
						found = 1
					else:
						counter += 100
				if found == 0:
					print("there was no trailer found for a jpeg image at sector starting at " + str(starter_token))

				elif found == 1:
					trailer_token = counter
					newfile = "s"+str(starter_token)+"c"+str(trailer_token)+".png"
					cmd_recover = "dd if=" + device + " bs=" + str(block_size) + " skip=" + str(starter_token) + " count=" + str(trailer_token) + " of=" + newfile
					os.system(cmd_recover)
				else:
					print("error with running script...")
					exit()
				
			cnt_line += 1

	os.system("rm temp.temp")

## variables saved

if len(sys.argv) != 3:
	usage()
	exit()

find_potential(sys.argv[1], sys.argv[2])
