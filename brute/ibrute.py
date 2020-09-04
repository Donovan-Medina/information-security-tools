#!/bin/env python3
import sys, subprocess, os

# ibrute by Donovan
# This is not the fastest method, 
# but this script goes through saved inodes (from fls -rd <image>) for example
# then catagorizes based on if it is just data, png, jpg, etc


def usage():
	print ("USAGE: " + sys.argv[0] + " <filename> <image>")
	print ("OR " + sys.argv[0] + " <inode.save file>, if you have a save file already in place")


def ibrute(filename, image):
	print ("iteratively going through file to look for images")
	savefile = filename + ".save"
	fpsave = open(savefile, "a")
	with open(filename) as fp:
		found = 0
		savedinodes = []
		for line in fp:
			# get the inode from the line
			tokens = line.split()
			newtoken = tokens[2].split(":")
			cleantoken = newtoken[0].split("(")
			# then use the file command to find what it is
			print (cleantoken[0])
			cmd = "icat " + image + " " + cleantoken[0] + " | file -"
			fpsave.write(cleantoken[0]) 
			fpsave.flush()
			os.system(cmd + " >> " + savefile)
		fpsave.close()
	
	makefiles(savefile);

# after ibrute has found all the inodes that 
def makefiles(savefile):
	print ("making various files")
	# we know there will be png, jpg, mov, avi, and more
	pngsave = "png_" + savefile
	jpgsave = "jpg_" + savefile
	movsave = "mov_" + savefile
	avisave = "avi_" + savefile	
	
	# parse the old savefile with grep and make new savefile
	grepit("PNG", pngsave, savefile)
	grepit("JPEG", jpgsave, savefile)
	grepit("MOV", movsave, savefile)
	grepit("AVI", avisave, savefile)


def grepit(look_for,newsave, savefile):
	# grep for specific inodes to a temp file first before
	# reading and tokenizing each line for the inode to the
	# designated save file
	temp = "tempfile"
	finalsave = look_for + "_finalsave"
	ptemp = open(temp, "a")
	cmd_grep = "cat " + savefile + " | grep \"" + look_for + "\""
	os.system(cmd_grep + " >> " + temp)
	ptemp.flush()
	ptemp.close()
	
	# now read the temp file and tokenize it into save file
	# just save the respective inodes
	p_newsave = open(newsave, "a");
	with open(temp) as fp:
		for line in fp:
			tokens = line.split("/")
			string = tokens[0] + "\n"
			p_newsave.write(string)
			p_newsave.flush()
		p_newsave.close()
	
	# use sed to clean up the save file if it contains (realloc) # if it truly contains it (should be fixed from above mar 14)
	cmd_sed = "sed -E 's/\(realloc\)/|/g' " + newsave + " | tr '|' '\n'"

	os.system(cmd_sed + " >> " + finalsave)
	print ("done with creating " + newsave + " as " + finalsave)
	
	#clean up and remove temp and the old save file
	os.system("rm " + temp)
	os.system("rm " + newsave)

if len(sys.argv) == 2:
	makefiles(sys.argv[1])
	quit()

if len(sys.argv) != 3 or sys.argv[1] == "-h":
	usage()
	quit()

inode_file = sys.argv[1]
image = sys.argv[2]

ibrute(inode_file, image)
