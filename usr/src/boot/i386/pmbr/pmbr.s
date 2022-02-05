#-
# Copyright (c) 2007 Yahoo!, Inc.
# All rights reserved.
# Written by: John Baldwin <jhb@FreeBSD.org>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the author nor the names of any co-contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $FreeBSD$
#
# Partly from: src/sys/boot/i386/mbr/mbr.s 1.7

# A 512 byte PMBR boot manager to read a boot program and run it.
# The embedded MBR is set up for PMBR and default bootblock sector
# is hardcoded to 256 and size 1. The actual values are supposed to be
# updated by installboot.

		.set LOAD,0x7c00		# Load address
		.set EXEC,0x600 		# Execution address
		.set MAGIC,0xaa55		# Magic: bootable
		.set SECSIZE,0x200		# Size of a single disk sector
		.set DISKSIG,440		# Disk signature offset
		.set STACK,EXEC+SECSIZE*4	# Stack address
		.set DPBUF,STACK

		.set NHRDRV,0x475		# Number of hard drives

		.globl start			# Entry point
		.code16
		.text

start:		jmp real_code
		.fill 0x3c,0x1,0x90		# fill with nop to ease disasm
#
# BIOS Parameter Block. Reserved space from 0xb to 0x3e, the FAT32 BPB
# is 60 (3Ch) bytes.
#
		. = start + 0x3e

#
# Setup the segment registers for flat addressing and setup the stack.
#
real_code:	cld				# String ops inc
		xorw %ax,%ax			# Zero
		movw %ax,%es			# Address
		movw %ax,%ds			#  data
		movw %ax,%ss			# Set up
		movw $STACK,%sp			#  stack
#
# Relocate ourself to a lower address so that we have more room to load
# other sectors.
# 
		movw $main-EXEC+LOAD,%si	# Source
		movw $main,%di			# Destination
		movw $SECSIZE-(main-start),%cx	# Byte count
		rep				# Relocate
		movsb				#  code
#
# Jump to the relocated code.
#
		jmp main-LOAD+EXEC		# To relocated code
#
# Validate drive number in %dl.
#
main:	 	cmpb $0x80,%dl			# Drive valid?
		jb main.1			# No
		movb NHRDRV,%dh			# Calculate the highest
		addb $0x80,%dh			#  drive number available
		cmpb %dh,%dl			# Within range?
		jb main.2			# Yes
main.1: 	movb $0x80,%dl			# Assume drive 0x80
#
# Load stage2 and start it. location and size is written by installboot
# and if size is 0, we can not do anything...
#
main.2:		movw stage2_size, %ax
		cmpw $0, %ax
		je err_noboot			# the stage2 size is not set
		pushw %dx			# save drive
		movb $0x41, %ah			# check extensions
		movw $0x55aa, %bx
		int $0x13
		popw %dx			# restore drive
		jc err_rd			# need lba mode for now
		cmpw $0xaa55, %bx		# chs support is not
		jne err_rd			# implemented.
		movw $stage2_sector, %si	# pointer to lba
		movw $LOAD/16,%bx		# set buffer segment
		movw %bx,%es
		xorw %bx,%bx			# and offset
load_boot:	push %si			# Save %si
		call read
		pop %si				# Restore
		decw stage2_size		# stage2_size--
		jnz next_boot
boot:		mov %bx,%es			# Reset %es to zero
		jmp LOAD			# Jump to boot code
next_boot:	incl (%si)			# Next LBA
		adcl $0,4(%si)
		mov %es,%ax			# Adjust segment for next
		addw $SECSIZE/16,%ax		#  sector
		mov %ax,%es			#
		jmp load_boot
#
# Load a sector (64-bit LBA at %si) from disk %dl into %es:%bx by creating
# a EDD packet on the stack and passing it to the BIOS.  Trashes %ax and %si.
#
read:		pushl 0x4(%si)			# Set the LBA
		pushl 0x0(%si)			#  address
		pushw %es			# Set the address of
		pushw %bx			#  the transfer buffer
		pushw $0x1			# Read 1 sector
		pushw $0x10			# Packet length
		movw %sp,%si			# Packer pointer
		movw $0x4200,%ax		# BIOS:	LBA Read from disk
		int $0x13			# Call the BIOS
		add $0x10,%sp			# Restore stack
		jc err_rd			# If error
		ret
#
# Various error message entry points.
#
err_rd: 	movw $msg_rd,%si		# "I/O error loading
		jmp putstr			#  boot loader"

err_noboot: 	movw $msg_noboot,%si		# "Missing boot
		jmp putstr			#  loader"
#
# Output an ASCIZ string to the console via the BIOS.
# 
putstr.0:	movw $0x7,%bx	 		# Page:attribute
		movb $0xe,%ah			# BIOS: Display
		int $0x10			#  character
putstr: 	lodsb				# Get character
		testb %al,%al			# End of string?
		jnz putstr.0			# No
putstr.1:	jmp putstr.1			# Await reset

msg_rd: 	.asciz "I/O error"
msg_noboot: 	.asciz "No boot loader"

		nop
mbr_version:	.byte 1, 1			# 1.1
		.align 4
stage2_size:	.word 1				# bootblock size in sectors
stage2_sector:	.quad 256			# lba of bootblock
disk_uuid:	.quad 0				# uuid
		.quad 0

# this is the end of the code block we can use, next is space for
# signature, partition table 4 entries and signature.
		.org DISKSIG,0x1b8		#
sig:		.long 0				# OS Disk Signature
		.word 0				# "Unknown" in PMBR

partbl:		.byte 0x00			# non-bootable
		.byte 0x00			# head 0
		.byte 0x02			# sector
		.byte 0x00			# cylinder
		.byte 0xEE			# ID
		.byte 0xFF			# ending head
		.byte 0xFF			# ending sector
		.byte 0xFF			# ending cylinder
		.long 0x00000001		# starting LBA
		.long 0xFFFFFFFF		# size
		.fill 0x10,0x3,0x0		# other 3 entries
		.word MAGIC			# Magic number
