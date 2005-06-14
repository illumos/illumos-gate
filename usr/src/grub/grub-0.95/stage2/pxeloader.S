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

	.file	"pxeloader.S"
	.text

	/* Start with the prehistoric environment... */
	.code16
	
	/* Let's go */
.globl _start; _start:

	/* Jump to the real world */
	ljmp	$0, $0x8200

	/* This region is a junk. Do you say that this is wasteful?
	   But I like that the memory layout of the body is consistent
	   among different stage2s rather than scamping just for 1.5KB. */
	. = _start + 0x8200 - 0x7C00 - 1
	.byte	0
