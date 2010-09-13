/* -*-Asm-*- */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2004   Free Software Foundation, Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stage1.h>
	
/*
 *  defines for the code go here
 */

	/* Absolute addresses
	   This makes the assembler generate the address without support
	   from the linker. (ELF can't relocate 16-bit addresses!) */
#define ABS(x) (x-_start+0x7c00)

	/* Print message string */
#define MSG(x)	movw $ABS(x), %si; call message

	/* XXX:	binutils-2.9.1.0.x doesn't produce a short opcode for this. */
#define	MOV_MEM_TO_AL(x)	.byte 0xa0;  .word x
	
	.file	"stage1.S"

	.text

	/* Tell GAS to generate 16-bit instructions so that this code works
	   in real mode. */
	.code16

.globl _start; _start:
	/*
	 * _start is loaded at 0x7c00 and is jumped to with CS:IP 0:0x7c00
	 */

	/*
	 * Beginning of the sector is compatible with the FAT/HPFS BIOS
	 * parameter block.
	 */

	jmp	after_BPB
	nop	/* do I care about this ??? */

	/*
	 * This space is for the BIOS parameter block!!!!  Don't change
	 * the first jump, nor start the code anywhere but right after
	 * this area.
	 */

	. = _start + 4

	/* scratch space */
mode:
	.byte	0
disk_address_packet:	
sectors:
	.long	0
heads:
	.long	0
cylinders:
	.word	0
sector_start:
	.byte	0
head_start:
	.byte	0
cylinder_start:
	.word	0
	/* more space... */

	. = _start + STAGE1_BPBEND

	/*
	 * End of BIOS parameter block.
	 */

stage1_version:	
	.byte	COMPAT_VERSION_MAJOR, COMPAT_VERSION_MINOR
boot_drive:	
	.byte	GRUB_INVALID_DRIVE	/* the disk to load stage2 from */
force_lba:
	.byte	0
stage2_address:
	.word	0x8000
stage2_sector:
	.long	1
stage2_segment:
	.word	0x800

after_BPB:

/* general setup */
	cli		/* we're not safe here! */

	/*
	 * This is a workaround for buggy BIOSes which don't pass boot
	 * drive correctly. If GRUB is installed into a HDD, check if
	 * DL is masked correctly. If not, assume that the BIOS passed
	 * a bogus value and set DL to 0x80, since this is the only
	 * possible boot drive. If GRUB is installed into a floppy,
	 * this does nothing (only jump).
	 */
boot_drive_check:
	jmp	1f
	testb	$0x80, %dl
	jnz	1f
	movb	$0x80, %dl
1:

	/*
	 * ljmp to the next instruction because some bogus BIOSes
	 * jump to 07C0:0000 instead of 0000:7C00.
	 */
	ljmp	$0, $ABS(real_start)

real_start:	

	/* set up %ds and %ss as offset from 0 */
	xorw	%ax, %ax
	movw	%ax, %ds
	movw	%ax, %ss

	/* set up the REAL stack */
	movw	$STAGE1_STACKSEG, %sp

	sti		/* we're safe again */

	/*
	 *  Check if we have a forced disk reference here
	 */
	MOV_MEM_TO_AL(ABS(boot_drive))	/* movb	ABS(boot_drive), %al */
	cmpb	$GRUB_INVALID_DRIVE, %al
	je	1f
	movb	%al, %dl
1:
	/* save drive reference first thing! */
	pushw	%dx

	/* print a notification message on the screen */
	MSG(notification_string)

	/* do not probe LBA if the drive is a floppy */
	testb	$STAGE1_BIOS_HD_FLAG, %dl
	jz	chs_mode
			
	/* check if LBA is supported */
	movb	$0x41, %ah
	movw	$0x55aa, %bx
	int	$0x13

	/* 
	 *  %dl may have been clobbered by INT 13, AH=41H.
	 *  This happens, for example, with AST BIOS 1.04.
	 */
	popw	%dx
	pushw	%dx

	/* use CHS if fails */
	jc	chs_mode
	cmpw	$0xaa55, %bx
	jne	chs_mode

	/* check if AH=0x42 is supported if FORCE_LBA is zero */
	MOV_MEM_TO_AL(ABS(force_lba))	/* movb	ABS(force_lba), %al */
	testb	%al, %al
	jnz	lba_mode
	andw	$1, %cx
	jz	chs_mode
	
lba_mode:
	/* save the total number of sectors */
	movl	0x10(%si), %ecx

	/* set %si to the disk address packet */
	movw	$ABS(disk_address_packet), %si

	/* set the mode to non-zero */
	movb	$1, -1(%si)
	
	movl	ABS(stage2_sector), %ebx

	/* the size and the reserved byte */
	movw	$0x0010, (%si)

	/* the blocks */
	movw	$1, 2(%si)
	
	/* the absolute address (low 32 bits) */
	movl	%ebx, 8(%si)

	/* the segment of buffer address */
	movw	$STAGE1_BUFFERSEG, 6(%si)

	xorl	%eax, %eax
	movw	%ax, 4(%si)
	movl	%eax, 12(%si)
	
/*
 * BIOS call "INT 0x13 Function 0x42" to read sectors from disk into memory
 *	Call with	%ah = 0x42
 *			%dl = drive number
 *			%ds:%si = segment:offset of disk address packet
 *	Return:
 *			%al = 0x0 on success; err code on failure
 */

	movb	$0x42, %ah
	int	$0x13

	/* LBA read is not supported, so fallback to CHS.  */
	jc	chs_mode

	movw	$STAGE1_BUFFERSEG, %bx
	jmp	copy_buffer
		
chs_mode:	
	/*
	 *  Determine the hard disk geometry from the BIOS!
	 *  We do this first, so that LS-120 IDE floppies work correctly.
	 */
	movb	$8, %ah
	int	$0x13
	jnc	final_init

	/*
	 *  The call failed, so maybe use the floppy probe instead.
	 */
	testb	$STAGE1_BIOS_HD_FLAG, %dl
	jz	floppy_probe

	/* Nope, we definitely have a hard disk, and we're screwed. */
	jmp	hd_probe_error

final_init:
	
	movw	$ABS(sectors), %si

	/* set the mode to zero */
	movb	$0, -1(%si)
	
	/* save number of heads */
	xorl	%eax, %eax
	movb	%dh, %al
	incw	%ax
	movl	%eax, 4(%si)

	xorw	%dx, %dx
	movb	%cl, %dl
	shlw	$2, %dx
	movb	%ch, %al
	movb	%dh, %ah

	/* save number of cylinders */
	incw	%ax
	movw	%ax, 8(%si)

	xorw	%ax, %ax
	movb	%dl, %al
	shrb	$2, %al

	/* save number of sectors */
	movl	%eax, (%si)

setup_sectors:
	/* load logical sector start (bottom half) */
	movl	ABS(stage2_sector), %eax

	/* zero %edx */
	xorl	%edx, %edx

	/* divide by number of sectors */
	divl	(%si)

	/* save sector start */
	movb	%dl, 10(%si)

	xorl	%edx, %edx	/* zero %edx */
	divl	4(%si)		/* divide by number of heads */

	/* save head start */
	movb	%dl, 11(%si)

	/* save cylinder start */
	movw	%ax, 12(%si)

	/* do we need too many cylinders? */
	cmpw	8(%si), %ax
	jge	geometry_error

/*
 *  This is the loop for taking care of BIOS geometry translation (ugh!)
 */

	/* get high bits of cylinder */
	movb	13(%si), %dl

	shlb	$6, %dl		/* shift left by 6 bits */
	movb	10(%si), %cl	/* get sector */

	incb	%cl		/* normalize sector (sectors go
					from 1-N, not 0-(N-1) ) */
	orb	%dl, %cl	/* composite together */
	movb	12(%si), %ch	/* sector+hcyl in cl, cylinder in ch */

	/* restore %dx */
	popw	%dx
	
	/* head number */
	movb	11(%si), %dh

/*
 * BIOS call "INT 0x13 Function 0x2" to read sectors from disk into memory
 *	Call with	%ah = 0x2
 *			%al = number of sectors
 *			%ch = cylinder
 *			%cl = sector (bits 6-7 are high bits of "cylinder")
 *			%dh = head
 *			%dl = drive (0x80 for hard disk, 0x0 for floppy disk)
 *			%es:%bx = segment:offset of buffer
 *	Return:
 *			%al = 0x0 on success; err code on failure
 */

	movw	$STAGE1_BUFFERSEG, %bx
	movw	%bx, %es	/* load %es segment with disk buffer */

	xorw	%bx, %bx	/* %bx = 0, put it at 0 in the segment */
	movw	$0x0201, %ax	/* function 2 */
	int	$0x13

	jc	read_error

	movw	%es, %bx
	
copy_buffer:
	movw	ABS(stage2_segment), %es

	/*
	 * We need to save %cx and %si because the startup code in
	 * stage2 uses them without initializing them.
	 */
	pusha
	pushw	%ds
	
	movw	$0x100, %cx
	movw	%bx, %ds
	xorw	%si, %si
	xorw	%di, %di
	
	cld
	
	rep
	movsw

	popw	%ds
	popa

	/* boot stage2 */
	jmp	*(stage2_address)

/* END OF MAIN LOOP */

/*
 * BIOS Geometry translation error (past the end of the disk geometry!).
 */
geometry_error:
	MSG(geometry_error_string)
	jmp	general_error

/*
 * Disk probe failure.
 */
hd_probe_error:
	MSG(hd_probe_error_string)
	jmp	general_error

/*
 * Read error on the disk.
 */
read_error:
	MSG(read_error_string)

general_error:
	MSG(general_error_string)

/* go here when you need to stop the machine hard after an error condition */
stop:	jmp	stop

notification_string:	.string "GRUB "
geometry_error_string:	.string "Geom"
hd_probe_error_string:	.string "Hard Disk"
read_error_string:	.string "Read"
general_error_string:	.string " Error"

/*
 * message: write the string pointed to by %si
 *
 *   WARNING: trashes %si, %ax, and %bx
 */

	/*
	 * Use BIOS "int 10H Function 0Eh" to write character in teletype mode
	 *	%ah = 0xe	%al = character
	 *	%bh = page	%bl = foreground color (graphics modes)
	 */
1:
	movw	$0x0001, %bx
	movb	$0xe, %ah
	int	$0x10		/* display a byte */
message:
	lodsb
	cmpb	$0, %al
	jne	1b	/* if not end of string, jmp to display */
	ret

	/*
	 *  Windows NT breaks compatibility by embedding a magic
	 *  number here.
	 */

	. = _start + STAGE1_WINDOWS_NT_MAGIC
nt_magic:	
	.long 0
	.word 0

	/*
	 *  This is where an MBR would go if on a hard disk.  The code
	 *  here isn't even referenced unless we're on a floppy.  Kinda
	 *  sneaky, huh?
	 */

part_start:	
	. = _start + STAGE1_PARTSTART

probe_values:
	.byte	36, 18, 15, 9, 0

floppy_probe:
/*
 *  Perform floppy probe.
 */

	movw	$ABS(probe_values-1), %si

probe_loop:
	/* reset floppy controller INT 13h AH=0 */
	xorw	%ax, %ax
	int	$0x13

	incw	%si
	movb	(%si), %cl

	/* if number of sectors is 0, display error and die */
	cmpb	$0, %cl
	jne	1f

/*
 * Floppy disk probe failure.
 */
	MSG(fd_probe_error_string)
	jmp	general_error

fd_probe_error_string:	.string "Floppy"

1:
	/* perform read */
	movw	$STAGE1_BUFFERSEG, %bx
	movw	$0x201, %ax
	movb	$0, %ch
	movb	$0, %dh
	int	$0x13

	/* if error, jump to "probe_loop" */
	jc	probe_loop

	/* %cl is already the correct value! */
	movb	$1, %dh
	movb	$79, %ch

	jmp	final_init

	. = _start + STAGE1_PARTEND

/* the last 2 bytes in the sector 0 contain the signature */
	.word	STAGE1_SIGNATURE
