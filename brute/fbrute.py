#!/bin/env python3
import sys, os


def usage(helper):
	print ("USAGE: " + sys.argv[0] + " [data | png | jpeg | apple | riff | iso | matroska | mp4] [filename]")
	if helper == -1:
		print ("fbrute looks for files with the specified extension, either opening a file or piping with stdin.\nif no filename is provided, we are assuming stdin")
	if helper == 0:
		print ("Error: Missing arguments")
	if helper == 2:
		print ("Error: pipe is empty")
	if helper == 22:
		print ("Error: " + sys.argv[2] + " is not a file")
	quit()

def findme_fileuse(ext, filename):
	with open(filename) as fp:
		found = 0
		file_list = []
		for line in fp:
			suspect = line.rstrip()
			cmd = "cat " + suspect + " | file - | grep -w -i " + ext
			
			print ("checking file: " + suspect + " if " + ext + " type")
			if os.system(cmd) == 0:
				print("yes this is")
				found += 1
				file_list.append(suspect)

	printout(found, file_list)		


def findme_stdin(ext):
	found = 0
	file_list = []
	for line in sys.stdin:
		suspect = line.rstrip()
		cmd = "cat " + suspect + " | file - | grep -w -i " + ext
		
		print ("checking file: " + suspect + " if " + ext + " type")
		if os.system(cmd) == 0:
			print("yes this is")
			found += 1
			file_list.append(suspect)

	printout(found, file_list)


def printout(found, file_list):
	print ("\nFound: " + str(found) + ", file(s)")
	if not_piping != 1 and found > 0:
		user_input = input("Would you like to save the file(s) to a folder? ")
		if user_input == "yes" or user_input == "y":
			user_folder = input("Enter folder to save: ")
			os.system("mkdir " + user_folder)
		
			for item in file_list:
				os.system("mv " + item + " " + user_folder + "/")
			print("File(s) moved:")
	
		else:
			print("ok not moving.. here's the File(s):")
	else:
		print("File(s)")
	print(*file_list, sep = "\n")


not_piping = 0
if len(sys.argv) == 2 and (sys.argv[1] == "-h" or sys.argv[1] == "--help"):
	usage(-1)

if len(sys.argv) < 2:
	usage(0)

if len(sys.argv) == 2:
	if not sys.stdin.isatty():
		not_piping = 1
		findme_stdin(sys.argv[1].lower())
	else:
		usage(2)
else:
	if os.path.isfile(sys.argv[2]):
		findme_fileuse(sys.argv[1], sys.argv[2].lower())
	else:
		usage(22)
