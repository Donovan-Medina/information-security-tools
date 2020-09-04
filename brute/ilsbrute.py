#!/bin/env python3
import sys, os

# use ils to get files




def usage():
	print (sys.argv[0] + " <file to save to> <device>")


def mnfile(file_to_save, device):
	cmd_maketemp = "ils " + device + " > temp.file"
	print(cmd_maketemp)
	os.system(cmd_maketemp)
	
	newfile = open(file_to_save, "w")
	
	with open("temp.file", "r") as fp:
		for line in fp:
			token = line.split("|")
			newfile.write(token[0] + "\n")
			newfile.flush()
	newfile.close()
	print("file saved at " + file_to_save)
	os.system("rm temp.file")


if len(sys.argv) != 3 or sys.argv[1] == "-h":
	usage()
	quit()

file_to_save = sys.argv[1]
device = sys.argv[2]

mnfile(file_to_save, device)
