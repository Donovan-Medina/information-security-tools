#!/bin/env python3
import sys, os, subprocess, math


# values
inode_table_offset = 0
block_size = 0
block_groups = 0
blocks_per_bg = 0
inode_size = 0
inode_per_bg = 0
total_inodes = block_groups * inode_per_bg


def usage():
	print ("USAGE: " + sys.argv[0] + " <file_of_inodes> <device>\n")
	print("Again, please ensure the device in use is backed up, this could severly mess up")




def get_sizes(file_of_inodes, device):
	cmd_block = "dumpe2fs " + device + " | grep -i \"block size\""
	out = subprocess.Popen(cmd_block, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	stdout, stderr = out.communicate()
	blocksize_token = stdout.decode("utf-8").split(":")
	block_size = int(blocksize_token[1].strip())
	
	cmd_inode = "dumpe2fs " + device + " | grep -i \"inode size\""
	out = subprocess.Popen(cmd_inode, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	stdout, stderr = out.communicate()
	inode_token = stdout.decode("utf-8").split(":")
	inode_size = int(inode_token[1].strip())
	
	cmd_bg = "fsstat " + device + " | grep -i \"number of block groups\""
	out = subprocess.Popen(cmd_bg, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	stdout, stderr = out.communicate()
	num_bg_token = stdout.decode("utf-8").split(":")
	num_bg = int(num_bg_token[1].strip())

	cmd_bpg ="fsstat " + device + " | grep -i \"blocks per group\""
	out = subprocess.Popen(cmd_bpg, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	stdout, stderr = out.communicate()
	num_bpg_token = stdout.decode("utf-8").split(":")
	num_bpg = int(num_bpg_token[1].strip())

	cmd_ipg ="fsstat " + device + " | grep -i \"inodes per group\""
	out = subprocess.Popen(cmd_ipg, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	stdout, stderr = out.communicate()
	num_ipg_token = stdout.decode("utf-8").split(":")
	num_ipg = int(num_ipg_token[1].strip())

	# Get inode offset per group and make dictionary
	inode_offset_dict = {
		-1: "test"
	}
	for bg in range(num_bg):
		cmd_iof ="dumpe2fs " + device + " | grep -w -A 5 -i \"group " + str(bg) + "\" | grep -i \"inode table\""
		out = subprocess.Popen(cmd_iof, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
		stdout, stderr = out.communicate()
		num_iof_dumpline = stdout.decode("utf-8").split("\n")
		num_iof_token = num_iof_dumpline[1]
		num_iof_secondtoken = num_iof_token.split("+")
		num_iof = num_iof_secondtoken[1].strip()
		inode_offset = int(num_iof[:-1])
		inode_offset_dict[bg] = inode_offset

	print("my block size: " + str(block_size))
	print("my number of block groups: " + str(num_bg))
	print("my number of blocks per group: " + str(num_bpg))
	print("my inode size: " + str(inode_size))
	print("my number of inode per group: " + str(num_ipg))
	print("my inode offsets:")
	for offsets in inode_offset_dict:
		offset = inode_offset_dict[offsets]
		print("\tblockgroup: " + str(offsets) + " offset: " + str(offset)) 

	### now continue program
	convert_to_block(file_of_inodes, block_size, num_bpg, num_bg, inode_size, num_ipg, inode_offset_dict, device)



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



def convert_to_block(file_of_inodes, block_size, blocks_per_bg, number_of_bg, inode_size, inode_per_bg, inode_offset_dict, device):
	
	with open(file_of_inodes) as fp:
		for line in fp:
			c_inode = int(line.rstrip())
			
			# block group = (inode - 1)/inode per block group  rounded down
			block_group = math.floor((c_inode - 1)/inode_per_bg)
			
			# Find the start of the inode table
			inode_table_start = (block_group * blocks_per_bg) + inode_offset_dict[block_group]
			
			# find the block (in inode table) our inode is in
			inode_block = math.floor( inode_table_start + ((c_inode - 1) % inode_per_bg) * inode_size / block_size )
			print("deleted inode: " + str(c_inode) + " bg: " + str(block_group) + " inode table starts: " + str(inode_table_start) + " inode block: " + str(inode_block))
			
			## at this point we could file carve manually/look for the offset within the block to look for inodes
			## instead we are going to look for the journal entry and replace the whole block (this is the dangerous part)
			jls_grepping(block_size, inode_block, c_inode, device)
			



# check usage from usr
if len(sys.argv) != 3 or sys.argv[1] == "-h":
	usage()
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

get_sizes(file_of_inodes, device)



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
