/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2000   Free Software Foundation, Inc.
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

#include <nbi.h>
#include <diskless_size.h>
			
	.file	"nbloader.S"
	.text
	.code16
	
	/* Just a dummy entry */
.globl _start; _start:

	/*
	 * netboot image header
	 */

	.long	NBI_MAGIC
	.long	0x00000004
	/* load address of the first block  */
	.word	NBI_DEST_OFF
	.word	NBI_DEST_SEG
	/* start addr of the relocation code */
	.word	NBI_DEST_OFF + (relocate - _start)
	.word	NBI_DEST_SEG

	.long	0x04000004
	.long	NBI_DEST_ADDR + 0x0200
	.long	DISKLESS_SIZE
	.long	DISKLESS_SIZE

relocate:
	/*
	 * This code is for now located at 0x10000.
	 * Relocate the code in two steps:
	 * 1. Copy the first 32k to 0x8000 and jump to the relocated area.
	 * 2. Copy the rest to 0x10000 (0x8000 + 32k).
	 */

	/* Copy the first 32k  */
	movw	$NBI_DEST_SEG, %ax
	movw	%ax, %ds
	movw	$RELOCATED_SEG, %ax
	movw	%ax, %es
	xorw	%si, %si
	xorw	%di, %di
	/* Always copy 32k bytes */
	movw	$0x4000, %cx

	cld
	rep
	movsw

	/* Jump to the relocated address */
	ljmp	$0, $(RELOCATED_ADDR + copy_rest - _start)

	/* Copy the rest */
copy_rest:
	/* Set %edx to the number of bytes */
	movl	$(DISKLESS_SIZE + 0x200 - 0x8000), %edx
	
copy_loop:
	/* Check the rest */
	orl	%edx, %edx
	jz	boot_stage2

	/* Copy by 32k, as that is easy to implement */
	movl	$0x8000, %ecx
	cmpl	%ecx, %edx
	jg	copy
	movl	%edx, %ecx
	
copy:
	/* Update the number of rest bytes */
	subl	%ecx, %edx

	/* Add 0x0800 (32k >> 4) into %es and %ds */
	movw	%es, %ax
	addw	$0x0800, %ax
	movw	%ax, %es
	movw	%ds, %ax
	addw	$0x800, %ax
	movw	%ax, %ds
	
	/* Zero the offsets */
	xorw	%si, %si
	xorw	%di, %di
	
	/* Use word-size copy */
	addw	$1, %cx
	shrw	$1, %cx

	/* The direction is already correct */
	rep
	movsw

	jmp	copy_loop

	/* Jump to the stage2 */
boot_stage2:
	ljmp	$0, $STAGE2_START_ADDR
	
	/* This ensures that the length of this image will be 1 sector */
	. = _start + 0x200 - 1
	.byte	0
