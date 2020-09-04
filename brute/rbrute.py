#!/bin/env python3
import sys, os


# iteratively recovers files

def usage():
	print ("USAGE: " + sys.argv[0] + " <.extension to add> <file of inodes> <image>")

def rbrute(filename, image, extend):
	cnt = 0
	with open(filename) as fp:
		for lines in fp:
			cnt += 1
			newfile = lines.rstrip() + "." + extend
			cmd = "icat " + image + " " + lines.rstrip() + " > ./recovered/" + newfile
			os.system(cmd) 


if len(sys.argv) != 4 or sys.argv[1] == "-h":
	usage()
	quit()

filename = sys.argv[2]
image = sys.argv[3]
extend = sys.argv[1]

rbrute(filename, image, extend)
