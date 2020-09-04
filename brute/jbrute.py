#!/bin/env python3
import sys, os, subprocess, math


# you will have to change this one manually in here
inode_table_offset = 131
block_size = 4096
block_groups = 22
blocks_per_bg = 32768
inode_size = 256
inode_per_bg = 8192
total_inodes = block_groups * inode_per_bg


def usage(block_size, block_groups, blocks_per_bg, inode_size, inode_per_bg, inode_table_offset):
	print ("USAGE: " + sys.argv[0] + " <file_of_inodes> <device>\n")
	print ("the following are hard coded values and must be changed to your need: ")
	print ("Amount of block groups: " + str(block_groups))
	print ("Amount of blocks per block group: " + str(blocks_per_bg))
	print ("Block size: " + str(block_size))
	print ("Amount of inodes per block group : " + str(inode_per_bg))
	print ("Inode size: " + str(inode_size))
	print ("where the inode table is in relation to the start of block group: " + str(inode_table_offset) + "\n")
	print("Again, please ensure the device in use is backed up, this could severly mess up")


####### DANGER #######
# make sure "device" is backed up. could severly mess up journal inode table
def replace_journal_node(block_size, jcat_file, inode_block, c_inode, device):
	file_len = sum(1 for line in open("jcat_file"))
	print ("HOLD YOUR BUTTS, attempting to replace " + str(file_len) + " inode table block entrys")
	
	with open("jcat_file") as fp:
		for line in fp:
			newfile = str(line.rstrip()) + ".jcatE"
			# save output of the jcat file which should be the size of a block
			cmd_jcat = "jcat " + device + " " + str(line.rstrip()) + " > " + newfile
			print(cmd_jcat)
			os.system(cmd_jcat)
			print ("filename: " + newfile)
			
			# replace inode table block entry
			cmd_replace = "dd if=" + str(newfile) + " count=1 of=" + device + " seek=" + str(inode_block) + " bs=" + str(block_size) + " conv=notrunc"
			print(cmd_replace)
			os.system(cmd_replace)
			
			# now to recover it
			print ("recovering inode: " + str(c_inode))
			recovered_file = str(c_inode) + ".file"
			cmd_recover = "icat " + device + " " + str(c_inode) + " > ./recovered/" + recovered_file
			print(cmd_recover)
			os.system(cmd_recover)

			# now clean up
			cmd_clean = "rm " + newfile
			os.system(cmd_clean)
			print("\n")


def jls_grepping(block_size, inode_block, c_inode, device):
	# look for the inode_block in journal using grep
	# then save into a temporary jls_found file
	cmd_jls = "jls " + device + " | grep -w " + "\"" + str(inode_block) + "\""
	os.system(cmd_jls + " > jls_found")
	
	# now we must clean up the file and write to jcat_file
	jcat_file = open("jcat_file", "w")
	with open("jls_found") as fp:
		for line in fp:
			token = line.split(":")
			if str(inode_block) != str(token[0]):
				jcat_file.write(token[0] + "\n")

	jcat_file.close()
			
	#final call...... this may take a while and may mess up things. HOLD YOUR BUTTS
	replace_journal_node(block_size, jcat_file, inode_block, c_inode, device)



def convert_to_block(file_of_inodes, block_size, blocks_per_bg, inode_size, inode_per_bg, inode_table_offset, device):
	
	with open(file_of_inodes) as fp:
		for line in fp:
			c_inode = int(line.rstrip())
			
			# block group = (inode - 1)/inode per block group  rounded down
			block_group = math.floor((c_inode - 1)/inode_per_bg)
			
			# Find the start of the inode table ***Beware if there is a backup super block
			if block_group == 0 or block_group == 1 or block_group == 3 or block_group == 5 or block_group == 7 or block_group == 9: 
				inode_table_start = (block_group * blocks_per_bg) + inode_table_offset
			else:
				inode_table_start = (block_group * blocks_per_bg) + 2
			
			# find the block (in inode table) our inode is in
			inode_block = math.floor( inode_table_start + ((c_inode - 1) % inode_per_bg) * inode_size / block_size )
			print("deleted inode: " + str(c_inode) + " bg: " + str(block_group) + " inode table starts: " + str(inode_table_start) + " inode block: " + str(inode_block))
			
			## at this point we could file carve manually/look for the offset within the block to look for inodes
			## instead we are going to look for the journal entry and replace the whole block (this is the dangerous part)
			jls_grepping(block_size, inode_block, c_inode, device)
			



# check usage from usr
if len(sys.argv) != 3 or sys.argv[1] == "-h":
	usage(block_size, block_groups, blocks_per_bg, inode_size, inode_per_bg, inode_table_offset)
	quit()
else:
	print ("Did you make a copy of " + sys.argv[2] + " and changed the variables?")
	user_input = input()
	if user_input != "yes":
		print("Please make a copy. To understand why try " + sys.argv[0] + " -h")
		quit()

# passed usage
file_of_inodes = sys.argv[1]
device = sys.argv[2]

convert_to_block(file_of_inodes, block_size, blocks_per_bg, inode_size, inode_per_bg, inode_table_offset, device)




"""
Journal recovering brute force
(jbrute.py)

created by Donovan Medina

COPYRIGHT 2020:
	 free for open source and modifications, please credit me if
	distributing. No part of this code may be used for monetary gain.

WARNING:
	You are liable and responsible for the misuse of this program and
	its result on your computer. PLEASE BACKUP whatever filesystem you
	are trying to use this program on.


ABOUT:
	This program uses a primative method in using the journal
	of a file system (say ext3) to recover deleted files which
	their current inodes no longer point to the direct blocks.
	This does not exactly file carve per say, but rather replaces
	the inode table block by using tools from sluethkit

	STEPS:
		1. Use 'fsstat' to know the block size, group size,
		   inodes per block group, total inodes, inode size

		2. Using 'fls -rd <device>' to find the deleted files
		choose which inode you wish to try and recover the
		direct blocks for.

		3. Use 'jls' and 'grep' to find the specific inode
		   we are trying to find

		4. Save the output of 'jcat' resulting from the found block
		   on 'jls' to a temporary file

		5. Replace that block of the inode table with the new temp
		   file

		6. Try running 'icat' | 'file -' to see if it works and
		   recovers files.

		GOOD LUCK!

		

DEPENDENCIES:
	- sluethkit (specifically fls, jls, jcat, icat)
	- the filesystem must not be corrupted in which the
	  inode table is unrecoverable/not replacable

"""
