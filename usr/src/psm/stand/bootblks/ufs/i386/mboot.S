/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2012 OmniTI Computer Consulting, Inc.  All rights reserved.
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Copyright 2012 OmniTI Computer Consulting, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * SOLARIS MASTER BOOT:
 *
 * PURPOSE: loads the primary boot from the active fdisk partition.
 *          in effect, this routine mimics the functionality of INT 0x19.
 *
 * resides on the first physical sector of the hard drive media.
 * loaded by INT 0x19 (ROM bootstrap loader) at address 0x7C00
 * limited to 512 bytes total, including embedded fdisk table.
 *
 * for compatibility with the ROM BIOS, we contain standard DOS structures:
 *
 *	the fdisk partition table (at offset 0x1BE-0x1FE)
 *	boot signature bytes (0x55, 0xAA at 0x1FE, 0x1FF)
 *
 * the above two entities are required in order to be compatible with
 * the manner in which the DOS BIOS has always performed its boot operation.
 * In the event that our master boot record is inadvertently replaced by
 * a standard DOS boot sector, the booting operation will still succeed!
 *
 * This master boot record uses the relsect/numsect fields of the partition
 * table entry, to compute the start of the active partition; therefore,
 * it is geometry independent.  This means that the drive could be "built"
 * on a system with a disk controller that uses a given disk geometry, but
 * would run on any other controller.
 *
 * SYNOPSIS:
 *     begins execution at 0:0x7C00
 *     relocates to 0:0x600 (to get out of the way!)
 *     reads fdisk table to locate bootable partition
 *     load boot record from the active fdisk partition at 0x7C00
 *     verify boot record signature bytes
 *     jump to/execute the SOLARIS PARTITION PRIMARY BOOT
 *     error handler - can either reboot, or invoke INT 0x18.
 *
 * interface from DOS INT 0x19:  BootDev in DL
 * (this fails sometimes, so we look for a signature to determine whether
 *  to rely on DL from the floppy boot, or if we should assume 0x80 from
 *  the BIOS)
 *
 * interface to partition boot: BootDev in DL
 *
 *=============================================================================
 * Master boot record: resides on first physical sector of device
 */

/*
 * This file is written in GNU as syntax using Intel assembler syntax.  The
 * startup label _start will be executed at address PBOOT_ADDR (0x7C00), but
 * the text section must be set at address RELOC_ADDR (0x600).  With GNU ld
 * this can be done using the "-Ttext 600" option.
 */


#define	PBOOT_ADDR	0x7C00
#define	RELOC_ADDR	0x600

#define	FDISK_START	0x1BE
#define	BOOT_SIG	0xAA55
#define	N_RETRIES	5

#define	FD_NUMPART	4
#define	FD_PTESIZE	0x10
#define	ACTIVE		0x80

/*
 * A convenience macro for declaring a message string (using .ascii directive--
 * NOT nul-terminated) surrounded by two labels, which can then be used with
 * the SIZEOF() macro to get its length.
 */
#define	MSG(label, string)	label: .ascii string; label##_end:

/*
 * Returns the length of some consecutive bytes.  These bytes must be placed
 * between two labels.  The ending label must be the same as the starting label
 * but with a suffix "_end".
 */
#define	SIZEOF(label)	(label##_end - label)


	.title	"Solaris_Master_Boot"

	.intel_syntax noprefix		/* use Intel syntax */
	.code16				/* 16-bit mode (real mode) */

	.text				/* code segment begins here */

	.global	BootDev
	.global _start

_start:					/* _start is loaded at PBOOT_ADDR */
	jmp	bootrun

Version:
	.ascii	"M3.0"			/* ident string */

bootrun:
	cli				/* don't bother me now! */

	/* prepare to relocate ourselves */
	cld				/* prepare for relocation */
	mov	si, PBOOT_ADDR
	mov	di, RELOC_ADDR

	/* set up segment registers */
	mov	ax, cs			/* initialize segment registers */
	mov	ss, ax
	mov	sp, si			/* stack starts down from 7C00 */
	mov	es, ax
	mov	ds, ax

	push	cx 			/* save possible signature on stack */
	mov	cx, 0x100
	rep	movsw
	pop	cx			/* restore saved cx */

	/* running at PBOOT_ADDR, jump to RELOC_ADDR-rel addr */
	jmp	(new_home - PBOOT_ADDR + RELOC_ADDR)

new_home:
	sti				/* re-enable interrupts */

	/*
	 * assuming boot device number is in dl has caused problems in the past
	 * since we still don't absolutely have to rely on it, I've just
	 * removed the now-pointless code to check for the FACE-CAFE signature
	 * from mdexec, which doesn't do anything anymore, but left the
	 * assumption that BootDev is 0x80 and nothing but.  If we ever need to
	 * have BIOS load us from a drive not numbered 0x80, we'll need to
	 * uncomment the following line; otherwise, the initialized value of
	 * BootDev, namely 0x80, will be used for disk accesses.
	 */
	/* mov BootDev, dl */

	/* set debug flag based on seeing "both shift down" */
	mov	ah, 2		/* get shift state */
	int	0x16
	and	al, 3		/* isolate shift-key bits */
	cmp	al, 3
	jne	nodbg
	mov	byte ptr [debugmode], 1		/* set to 1 */

nodbg:
	/*
	 * Search the fdisk table sequentially to find a physical partition
	 * that is marked as "active" (bootable).
	 */
	mov	bx, RELOC_ADDR + FDISK_START
	mov	cx, FD_NUMPART

nxtpart:
	cmp	byte ptr [bx], ACTIVE
	je	got_active_part
	add	bx, FD_PTESIZE
	loop	nxtpart

noparts:
	mov	bp, offset NoActiveErrMsg
	mov	cx, SIZEOF(NoActiveErrMsg)
	jmp	fatal_err

got_active_part:
	mov	ah, 0		/* reset disk */
	int	0x13

	push	bx		/* save partition pointer */

	/* Check for LBA BIOS */
	mov	ah, 0x41	/* chkext function */
	mov	bx, 0x55AA	/* signature to change */
	mov	cx, 0
	int	0x13
	jc	noLBA		/* carry == failure */
	cmp	bx, 0xAA55
	jne	noLBA		/* bad signature in BX == failure */
	test	cx, 1		/* cx & 1 must be true, or... */
	jz	noLBA		/* ...no LBA */

	mov	bp, offset lbastring
	mov	cx, SIZEOF(lbastring)
	call	debugout

	/*
	 * LBA case: form a packet on the stack and call fn 0x42 to read
	 * packet, backwards (from hi to lo addresses):
	 * 8-byte LBA
	 * seg:ofs buffer address
	 * byte reserved
	 * byte nblocks
	 * byte reserved
	 * packet size in bytes (>= 0x10)
	 */

	pop	bx		/* restore partition pointer */
	push	bx		/* and save again */
	mov	cx, N_RETRIES	/* retry count */
retryLBA:
	pushd	0		/* hi 32 bits of 64-bit sector number */
	push	dword ptr [bx+8]	/* relsect (lo 32 of 64-bit number) */
	push	dword ptr [solaris_priboot]	/* seg:ofs of buffer */
	push	1		/* reserved, one block */
	push	0x10		/* reserved, size (0x10) */
	mov	ah, 0x42	/* "read LBA" */
	mov	si, sp		/* (ds already == ss) */
	int	0x13
	lahf			/* save flags */
	add	sp, 16		/* restore stack */
	sahf			/* restore flags */
	jnc	readok		/* got it */
	mov	ah, 0		/* reset disk */
	int	0x13
	loop	retryLBA	/* try again */
	jmp	readerr		/* exhausted retries; give up */

noLBA:
	mov	bp, offset chsstring
	mov	cx, SIZEOF(chsstring)
	call	debugout

	pop	bx		/* restore partition pointer */
	push	bx		/* and save again */

	/* get BIOS disk parameters */
	mov	dl, byte ptr [BootDev]
	mov	ah, 0x8
	int	0x13

	jnc	geomok

	/* error reading geom; die */
	mov	bp, offset GeomErrMsg
	mov	cx, SIZEOF(GeomErrMsg)
	jmp	fatal_err

geomok:
	/* calculate sectors per track */
	mov	al, cl		/* ah doesn't matter; mul dh will set it */
	and	al, 0x3F
	mov	byte ptr [secPerTrk], al

	/* calculate sectors per cylinder */
	inc	dh
	mul	dh
	mov	word ptr [secPerCyl], ax

	/* calculate cylinder # */
	mov	ax, [bx+8]	/* ax = loword(relsect) */
	mov	dx, [bx+10]	/* dx:ax = relsect */
	div	word ptr [secPerCyl]	/* ax = cyl, */
					/* dx = sect in cyl (0 - cylsize-1) */
	mov	bx, ax		/* bx = cyl */

	/* calculate head/sector # */
	mov	ax, dx		/* ax = sect in cyl (0 - cylsize-1) */
	div	byte ptr [secPerTrk]	/* al = head, */
					/* ah = 0-rel sect in track */
	inc	ah		/* ah = 1-rel sector */

	xor	cl,cl		/* cl = 0 */
	mov	ch, bh		/* ch = hi bits of cyl (if any) */
	shr	cx, 2		/* cl{7:6} = cyl{9:8} (if any) */
	and	cl, 0xC0	/* cl = cyl{9:8} to merge with sect (if any) */

	or	cl, ah		/* cl{7:6} = cyl bits, cl{5:0} = sect */
	mov	ch, bl		/* ch = lo cyl bits */
	mov	dh, al		/* dh = head */
	mov	dl, byte ptr [BootDev]		/* dl = drivenum */
	les	bx, solaris_priboot		/* es:bx points to buffer */

	mov	si, N_RETRIES
retry_noLBA:
	mov	ax, 0x201	/* 02=read, sector count = 1 */

	int	0x13
	jnc	readok
	mov	ah, 0		/* reset disk */
	int	0x13
	dec	si
	cmp	si, 0
	jne	retry_noLBA	/* retry, or fall through to read error */

readerr:
	mov	bp, offset ReadErrMsg
	mov	cx, SIZEOF(ReadErrMsg)
	jmp	fatal_err

readok:
	/* verify boot record signature */
	mov	bx, PBOOT_ADDR
	cmp	word ptr [bx+0x1FE], BOOT_SIG
	je	sigok

	mov	bp, offset SigErrMsg
	mov	cx, SIZEOF(SigErrMsg)
	jmp	fatal_err

sigok:
	mov	dl, byte ptr [BootDev]	/* pass BootDev to next boot phase */
	pop	si			/* and pass partition pointer ds:si */
	call	dword ptr [solaris_priboot]	/* call doesn't return! */

	mov	bp, offset ReturnErrMsg
	mov	cx, SIZEOF(ReturnErrMsg)

fatal_err:			/* land of no return....... */
	/*
	 * bp contains pointer to error message string,
	 * cx contains string length
	 */
	mov	bx, 0x4F	/* video page, attribute */
	call	msgout
	int	0x18

debugout:
	/* call with string pointer in es:bp, len in cx */
	cmp	byte ptr [debugmode], 0
	je	debugout_ret	/* skip if not in debug mode */

	mov	bx, 0x1F	/* page, attr (white on blue) */

	/* alternate entry for fatal_err */
msgout:
	pusha
	mov	ax, 0x1301
	mov	dx, 0x1700	/* row, col */
	int	0x10

	mov	al, 7		/* BEL */
	mov	cx, 1
	int	0x10

	mov	ah, 0		/* get key */
	int	0x16
	popa

debugout_ret:
	ret

secPerTrk:
	.byte	0
secPerCyl:
	.word	0
solaris_priboot:
	.long	PBOOT_ADDR
BootDev:
	.byte	0x80		/* assumes drive 80 (see comment above) */
debugmode:
	.byte	0

MSG(GeomErrMsg,		"Can't read geometry")
MSG(NoActiveErrMsg,	"No active partition")
MSG(ReadErrMsg,		"Can't read PBR")
MSG(SigErrMsg,		"Bad PBR sig")
MSG(ReturnErrMsg,	"!!!")
MSG(lbastring,		"LBA")
MSG(chsstring,		"CHS")

/*
 * For debugging:  Here's a representative FDISK table entry
 *
 * .org   0x1BE
 * .byte  0x80,1,1,0,0x82,0xfe,0x7f,4,0x3f,0,0,0,0x86,0xfa,0x3f,0
 */
	.org 	0x1FE

	.word	BOOT_SIG
