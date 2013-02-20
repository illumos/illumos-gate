/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2004 Free Software Foundation, Inc.
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


/*
 * Note: These functions defined in this file may be called from C.
 *       Be careful of that you must not modify some registers. Quote
 *       from gcc-2.95.2/gcc/config/i386/i386.h:
	
   1 for registers not available across function calls.
   These must include the FIXED_REGISTERS and also any
   registers that can be used without being saved.
   The latter must include the registers where values are returned
   and the register where structure-value addresses are passed.
   Aside from that, you can include as many other registers as you like.

  ax,dx,cx,bx,si,di,bp,sp,st,st1,st2,st3,st4,st5,st6,st7,arg
{  1, 1, 1, 0, 0, 0, 0, 1, 1,  1,  1,  1,  1,  1,  1,  1,  1 }
 */

#define ASM_FILE

#include "shared.h"

#ifdef STAGE1_5
# define	ABS(x)	((x) - EXT_C(main) + 0x2200)
#else
# define	ABS(x)	((x) - EXT_C(main) + 0x8200)
#endif
	
	.file	"asm.S"

	.text

	/* Tell GAS to generate 16-bit instructions so that this code works
	   in real mode. */
	.code16

#ifndef STAGE1_5
	/* 
	 * In stage2, do not link start.S with the rest of the source
	 * files directly, so define the start symbols here just to
	 * force ld quiet. These are not referred anyway.
	 */
	.globl	start, _start
start:
_start:
#endif /* ! STAGE1_5 */
	
ENTRY(main)
	/*
	 *  Guarantee that "main" is loaded at 0x0:0x8200 in stage2 and
	 *  at 0x0:0x2200 in stage1.5.
	 */
	ljmp $0, $ABS(codestart)

	/*
	 *  Compatibility version number
	 *
	 *  These MUST be at byte offset 6 and 7 of the executable
	 *  DO NOT MOVE !!!
	 */
	. = EXT_C(main) + 0x6
	.byte	COMPAT_VERSION_MAJOR, COMPAT_VERSION_MINOR

	/*
	 *  This is a special data area 8 bytes from the beginning.
	 */

	. = EXT_C(main) + 0x8

VARIABLE(install_partition)
	.long	0xFFFFFF
/* This variable is here only because of a historical reason.  */
VARIABLE(saved_entryno)
	.long	0
VARIABLE(stage2_id)
	.byte	STAGE2_ID
VARIABLE(force_lba)
	.byte	0
VARIABLE(version_string)
	.string VERSION
VARIABLE(config_file)
#ifndef STAGE1_5
	.string "/boot/grub/menu.lst"
#else   /* STAGE1_5 */
	.long	0xffffffff
	.string "/boot/grub/stage2"
#endif  /* STAGE1_5 */

	/*
	 *  Leave some breathing room for the config file name.
	 */

	. = EXT_C(main) + 0x60
VARIABLE(fake_mboot)
	.long	0x1BADB002
	.long   0x00010003 
	.long	-0x1BAEB005	
	/* 
	 * installgrub will place the rest of the fake 
	 * multiboot header here.
	 */
	.= EXT_C(main) + 0x140
/* the real mode code continues... */
codestart:
	cli		/* we're not safe here! */

	/* set up %ds, %ss, and %es */
	xorw	%ax, %ax
	movw	%ax, %ds
	movw	%ax, %ss
	movw	%ax, %es

#ifndef SUPPORT_DISKLESS
	/*
	 * Save the sector number of the second sector (i.e. this sector)
	 * in INSTALL_SECOND_SECTOR. See also "stage2/start.S".
	 */
	ADDR32	movl	%ebp, EXT_C(install_second_sector)
#endif
	
	/* set up the real mode/BIOS stack */
	movl	$STACKOFF, %ebp
	movl	%ebp, %esp

	sti		/* we're safe again */

#ifndef SUPPORT_DISKLESS
	/* save boot drive reference */
	ADDR32	movb	%dl, EXT_C(boot_drive)

	/* reset disk system (%ah = 0) */
	int	$0x13
#endif

	/* transition to protected mode */
	DATA32	call EXT_C(real_to_prot)

	/* The ".code32" directive takes GAS out of 16-bit mode. */
	.code32

	/* clean out the bss */

	/* set %edi to the bss starting address */
#if defined(HAVE_USCORE_USCORE_BSS_START_SYMBOL)
	movl	$__bss_start, %edi
#elif defined(HAVE_USCORE_EDATA_SYMBOL)
	movl	$_edata, %edi
#elif defined(HAVE_EDATA_SYMBOL)
	movl	$edata, %edi
#endif

	/* set %ecx to the bss end */	
#if defined(HAVE_END_SYMBOL)
	movl	$end, %ecx
#elif defined(HAVE_USCORE_END_SYMBOL)
	movl	$_end, %ecx
#endif

	/* compute the bss length */
	subl	%edi, %ecx
	
	/* zero %al */
	xorb	%al, %al

	/* set the direction */
	cld
	
	/* clean out */
	rep
	stosb
	
	/*
	 *  Call the start of main body of C code, which does some
	 *  of it's own initialization before transferring to "cmain".
	 */
	call EXT_C(init_bios_info)


/*
 *  This call is special...  it never returns...  in fact it should simply
 *  hang at this point!
 */

ENTRY(stop)
	call	EXT_C(prot_to_real)

	/*
	 * This next part is sort of evil.  It takes advantage of the
	 * byte ordering on the x86 to work in either 16-bit or 32-bit
	 * mode, so think about it before changing it.
	 */

ENTRY(hard_stop)
	hlt
	jmp EXT_C(hard_stop)

#ifndef STAGE1_5

/**************************************************************************
UNDI_CALL - wrapper around real-mode UNDI API calls
**************************************************************************/
ENTRY(__undi_call)
       pushl   %ebp
       movl    %esp,%ebp
       pushl   %esi
       pushl   %edi
       pushl   %ebx

       movw    8(%ebp),%cx     /* Seg:off addr of undi_call_info_t struct */
       movw    12(%ebp),%dx    /* Pass to 16-bit code in %cx:%dx */

       call EXT_C(prot_to_real)
       .code16

       movw    %cx,%es         /* Seg:off addr of undi_call_info_t struct */
       movw    %dx,%bx         /* into %es:%bx */

       movw    %es:8(%bx),%ax  /* Transfer contents of undi_call_info_t */
       pushw   %ax             /* structure to the real-mode stack */
       movw    %es:6(%bx),%ax
       pushw   %ax
       movw    %es:4(%bx),%ax
       pushw   %ax

       lcall   *%es:0(%bx)     /* Do the UNDI call */
       cld                     /* Don't know whether or not we need this */
                               /* but pxelinux includes it for some reason, */
                               /* so we put it in just in case. */

       popw    %cx             /* Tidy up the stack */
       popw    %cx
       popw    %cx
       movw    %ax,%cx         /* Return %ax via %cx */

       DATA32 call EXT_C(real_to_prot)
       .code32

       xorl    %eax,%eax       /* %ax is returned via %cx */
       movw    %cx,%ax

       popl    %ebx
       popl    %edi
       popl	%esi
       popl	%ebp
       ret

/**************************************************************************
UNDI_IRQ_HANDLER - UNDI IRQ handler: calls PXENV_UNDI_ISR and send EOI
NOTE: For some reason, this handler needs to be aligned. Else, the
	undi driver won't get the trigger count on some platforms.
**************************************************************************/
	.align 4
ENTRY(_undi_irq_handler)
	.code16
	pushw	%ax
	pushw	%bx
	pushw	%cx
	call	1f		/* Position-independent access to */
1:	popw	%bx		/* various locations.		  */
	pushw	%bx		/* save for after UNDI call */

	/* set funcflag to PXENV_UNDI_ISR_IN_START */
	movw	$1,%cs:(pxenv_undi_isr-1b+2)(%bx)

	/* push pxenv_undi_isr struct on stack */
	movl	$(ABS(pxenv_undi_isr)),%eax
	movw	%ax,%cx
	shrl	$4,%eax		/* get segment */
	pushw	%ax
	andw	$0xf,%cx	/* get offset */
	pushw	%cx
	movw    $0x14,%ax	/* opcode PXENV_UNDI_ISR */
	pushw   %ax

	lcall   *%cs:(pxenv_entrypointsp-1b)(%bx)	/* Do the UNDI call */
	cld                     /* Don't know whether or not we need this */
				/* but pxelinux includes it for some reason, */
				/* so we put it in just in case. */
	popw    %cx             /* Tidy up the stack */
	popw    %cx
	popw    %cx

	popw	%bx		/* restore old position reg */

	cmpw	$0,%ax		/* did the UNDI call succeed? */
	jne	3f
	movw	%cs:(pxenv_undi_isr-1b+2)(%bx),%ax
	cmpw	$0,%ax		/* is this our interrupt? */
	jne	3f

	/* send EOI -- non specific for now */
	movw	$0x20,%ax		/* ICR_EOI_NON_SPECIFIC */
	movb	%cs:(pxenv_undi_irq-1b),%cl
	cmpb	$8,%cl
	jg	2f
	outb	$0xa0			/* PIC2_ICR */
2:	outb	$0x20			/* PIC1_ICR */

	/* increment trigger count */
	incw	%cs:(EXT_C(_undi_irq_trigger_count)-1b)(%bx)

	/* restore other registers */
3:	popw	%cx
	popw	%bx
	popw	%ax
	iret
ENTRY(_undi_irq_trigger_count)
undi_irq_trigger_count:
	.word	0
ENTRY(_undi_irq_chain_to)
	.long	0
ENTRY(_undi_irq_chain)
	.byte	0
ENTRY(_pxenv_undi_irq)
pxenv_undi_irq:
	.byte	0
ENTRY(_pxenv_undi_entrypointsp)
pxenv_entrypointsp:
	.word	0	/* offset */
	.word	0	/* segment */
pxenv_undi_isr:
	.word	0	/* status */
	.word	0	/* funcflag */
	.long	0	/* struct padding not used by ISR */
	.long	0
	.long	0

	.code32

/*
 * stop_floppy()
 *
 * Stops the floppy drive from spinning, so that other software is
 * jumped to with a known state.
 */
ENTRY(stop_floppy)
	pusha
	call	EXT_C(prot_to_real)
	.code16
	xorb	%dl, %dl
	int	$0x13
	DATA32  call EXT_C(real_to_prot)
	.code32
	popa
	ret

/*
 * grub_reboot()
 *
 * Reboot the system. At the moment, rely on BIOS.
 */
ENTRY(grub_reboot)
	call	EXT_C(prot_to_real)
	.code16
	/* cold boot */
	movw	$0x0472, %di
	movw	%ax, (%di)
	ljmp	$0xFFFF, $0x0000
	.code32
	
/*
 * grub_halt(int no_apm)
 *
 * Halt the system, using APM if possible. If NO_APM is true, don't use
 * APM even if it is available.
 */
ENTRY(grub_halt)
	/* get the argument */
	movl	4(%esp), %eax
	
	/* see if zero */
	testl	%eax, %eax
	jnz	EXT_C(stop)

	call	EXT_C(prot_to_real)
	.code16
	
	/* detect APM */
	movw	$0x5300, %ax
	xorw	%bx, %bx
	int	$0x15
	jc	EXT_C(hard_stop)
	/* don't check %bx for buggy BIOSes... */

	/* disconnect APM first */
	movw	$0x5304, %ax
	xorw	%bx, %bx
	int	$0x15

	/* connect APM */
	movw	$0x5301, %ax
	xorw	%bx, %bx
	int	$0x15
	jc	EXT_C(hard_stop)

	/* set APM protocol level - 1.1 or bust. (this covers APM 1.2 also) */
	movw	$0x530E, %ax
	xorw	%bx, %bx
	movw	$0x0101, %cx
	int	$0x15
	jc	EXT_C(hard_stop)
	
	/* set the power state to off */
	movw	$0x5307, %ax
	movw	$1, %bx
	movw	$3, %cx
	int	$0x15

	/* shouldn't reach here */
	jmp	EXT_C(hard_stop)
	.code32
	
/*
 * track_int13(int drive)
 *
 * Track the int13 handler to probe I/O address space.
 */
ENTRY(track_int13)
	pushl	%ebp
	movl	%esp, %ebp

	pushl	%ebx
	pushl	%edi

	/* copy the original int13 handler segment:offset */
	movl	$0x4c, %edi
	movl	(%edi), %eax
	movl	%eax, track_int13_addr
		
	/* replace the int1 handler */
	movl	$0x4, %edi
	pushl	(%edi)
	movl	$ABS(int1_handler), %eax
	movl	%eax, (%edi)

	/* read the MBR to call int13 successfully */
	movb	8(%ebp), %dl
	
	call	EXT_C(prot_to_real)
	.code16

	movw	$SCRATCHSEG, %ax
	movw	%ax, %es
	xorw	%bx, %bx
	movw	$1, %cx
	xorb	%dh, %dh

	/* save FLAGS on the stack to emulate int13 */
	pushfw
	
	/* set the TF flag */
	/* FIXME: this can be simplified not to use AX */
	pushfw
	popw	%ax
	orw	$0x100, %ax
	pushw	%ax
	popfw

	movw	$0x0201, %ax

	.byte	0x9a		/* lcall */
track_int13_addr:
	.word	0		/* offset */
	.word	0		/* segment */

	/* TF is cleared here automatically */
	
	DATA32	call	EXT_C(real_to_prot)
	.code32

	/* restore the int1 handler */
	movl	$0x4, %edi
	popl	(%edi)

	popl	%edi
	popl	%ebx
	popl	%ebp
	
	ret


/*
 * Check if the next instruction is I/O, and if this is true, add the
 * port into the io map.
 *
 * Note: Probably this will make the execution of int13 very slow.
 *
 * Note2: In this implementation, all we can know is I/O-mapped I/O. It
 * is impossible to detect memory-mapped I/O.
 */
int1_handler:
	.code16
	
	pushw	%bp
	movw	%sp, %bp
	pushw	%ds
	pushw	%ax
	pushw	%si
	pushw	%dx
	
	/* IP */
	movw	2(%bp), %si
	/* CS */
	movw	4(%bp), %ax
	movw	%ax, %ds

	/* examine the next instruction */
1:	lodsb	(%si), %al
	/* skip this code if it is a prefix */
	cmpb	$0x2E, %al
	je	1b
	cmpb	$0x36, %al
	je	1b
	cmpb	$0x3E, %al
	je	1b
	cmpb	$0x26, %al
	je	1b
	cmpb	$0x64, %al
	jl	2f
	cmpb	$0x67, %al
	jle	1b
2:	cmpb	$0xF0, %al
	jl	3f
	cmpb	$0xF3, %al
	jle	1b
	
3:	/* check if this code is out* or in* */

	/* ins? or outs? */
	cmpb	$0x6C, %al
	jl	4f
	cmpb	$0x6F, %al
	jle	5f

4:	/* in? or out? (register operand version) */
	cmpb	$0xEC, %al
	jl	6f
	cmpb	$0xEF, %al
	jle	5f
	
6:	/* in? or out? (immediate operand version) */
	cmpb	$0xE4, %al
	jl	8f
	cmpb	$0xE7, %al
	jg	8f

7:	/* immediate has a port */
	lodsb	(%si), %al
	movzbw	%al, %dx
	
5:	/* %dx has a port */

	/* set %ds to zero */
	xorw	%ax, %ax
	movw	%ax, %ds
		
	/* set %si to the io map */
	movw	$ABS(EXT_C(io_map)), %si

		
9:	/* check if the io map already has the port */
	lodsw	(%si), %ax
	/* check if this is the end */
	testw	%ax, %ax
	jz	1f
	/* check if this matches the port */
	cmpw	%ax, %dx
	jne	9b
	/* if so, leave from this handler */
	jmp	8f
	
1:	/* check for the buffer overrun */
	cmpw	$(ABS(EXT_C(io_map)) + (IO_MAP_SIZE + 1) * 2), %si
	je	8f
	/* add the port into the io map */
	movw	%dx, -2(%si)

8:	/* restore registers */	
	popw	%dx
	popw	%si
	popw	%ax
	popw	%ds
	popw	%bp

	iret
	
	.code32

ENTRY(io_map)
	.space	(IO_MAP_SIZE + 1) * 2
	
	
/*
 * set_int15_handler(void)
 *
 * Set up int15_handler.
 */
ENTRY(set_int15_handler)
	pushl	%edi
	
	/* save the original int15 handler */
	movl	$0x54, %edi
	movw	(%edi), %ax
	movw	%ax, ABS(int15_offset)
	movw	2(%edi), %ax
	movw	%ax, ABS(int15_segment)

	/* save the new int15 handler */
	movw	$ABS(int15_handler), %ax
	movw	%ax, (%edi)
	xorw	%ax, %ax
	movw	%ax, 2(%edi)

	popl	%edi
	ret


/*
 * unset_int15_handler(void)
 *
 * Restore the original int15 handler
 */
ENTRY(unset_int15_handler)
	pushl	%edi
	
	/* check if int15_handler is set */
	movl	$0x54, %edi
	movw	$ABS(int15_handler), %ax
	cmpw	%ax, (%edi)
	jne	1f
	xorw	%ax, %ax
	cmpw	%ax, 2(%edi)
	jne	1f

	/* restore the original */
	movw	ABS(int15_offset), %ax
	movw	%ax, (%edi)
	movw	ABS(int15_segment), %ax
	movw	%ax, 2(%edi)

1:
	popl	%edi
	ret


/*
 * Translate a key code to another.
 *
 * Note: This implementation cannot handle more than one length
 * scancodes (such as Right Ctrl).
 */
	.code16
int15_handler:
	/* if non-carrier, ignore it */
	jnc	1f
	/* check if AH=4F */
	cmpb	$0x4F, %ah
	jne	1f

	/* E0 and E1 are special */
	cmpb	$0xE1, %al
	je	4f
	cmpb	$0xE0, %al
	/* this flag is actually the machine code (je or jmp) */
int15_skip_flag:	
	je	4f
	
	pushw	%bp
	movw	%sp, %bp
	
	pushw	%bx
	pushw	%dx
	pushw	%ds
	pushw	%si

	/* save bits 0-6 of %al in %dl */
	movw	%ax, %dx
	andb	$0x7f, %dl
	/* save the highest bit in %bl */
	movb	%al, %bl
	xorb	%dl, %bl
	/* set %ds to 0 */
	xorw	%ax, %ax
	movw	%ax, %ds
	/* set %si to the key map */
	movw	$ABS(EXT_C(bios_key_map)), %si

	/* find the key code from the key map */
2:
	lodsw
	/* check if this is the end */
	testw	%ax, %ax
	jz	3f
	/* check if this matches the key code */
	cmpb	%al, %dl
	jne	2b
	/* if so, perform the mapping */
	movb	%ah, %dl
3:
	/* restore %ax */
	movw	%dx, %ax
	orb	%bl, %al
	/* make sure that CF is set */
	orw	$1, 6(%bp)
	/* restore other registers */
	popw	%si
	popw	%ds
	popw	%dx
	popw	%bx
	popw	%bp
	iret
	
4:
	/* tricky: jmp (0x74) <-> je (0xeb) */
	xorb	$(0x74 ^ 0xeb), ABS(int15_skip_flag)
1:
	/* just cascade to the original */
	/* ljmp */
	.byte	0xea
int15_offset:	.word	0
int15_segment:	.word	0

	.code32

	.align	4	
ENTRY(bios_key_map)
	.space	(KEY_MAP_SIZE + 1) * 2
	
	
/*
 * set_int13_handler(map)
 *
 * Copy MAP to the drive map and set up int13_handler.
 */
ENTRY(set_int13_handler)
	pushl	%ebp
	movl	%esp, %ebp

	pushl	%edi
	pushl	%esi

	/* copy MAP to the drive map */
	movl	$(DRIVE_MAP_SIZE * 2), %ecx
	movl	$ABS(drive_map), %edi
	movl	8(%ebp), %esi
	cld
	rep
	movsb

	/* save the original int13 handler */
	movl	$0x4c, %edi
	movw	(%edi), %ax
	movw	%ax, ABS(int13_offset)
	movw	2(%edi), %ax
	movw	%ax, ABS(int13_segment)
	
	/* decrease the lower memory size and set it to the BIOS memory */
	movl	$0x413, %edi
	decw	(%edi)
	xorl	%eax, %eax
	movw	(%edi), %ax
	
	/* compute the segment */
	shll	$6, %eax

	/* save the new int13 handler */
	movl	$0x4c, %edi
	movw	%ax, 2(%edi)
	xorw	%cx, %cx
	movw	%cx, (%edi)

	/* copy int13_handler to the reserved area */
	shll	$4, %eax
	movl	%eax, %edi
	movl	$ABS(int13_handler), %esi
	movl	$(int13_handler_end - int13_handler), %ecx
	rep
	movsb

	popl	%esi
	popl	%edi
	popl	%ebp
	ret

	
/* 
 * Map a drive to another drive.
 */
	
	.code16
	
int13_handler:
	pushw	%ax
	pushw	%bp
	movw	%sp, %bp
	
	pushw	%si

	/* set %si to the drive map */
	movw	$(drive_map - int13_handler), %si
	/* find the drive number from the drive map */
	cld
1:	
	lodsw	%cs:(%si), %ax
	/* check if this is the end */
	testw	%ax, %ax
	jz	2f
	/* check if this matches the drive number */
	cmpb	%al, %dl
	jne	1b
	/* if so, perform the mapping */
	movb	%ah, %dl
2:
	/* restore %si */
	popw	%si
	/* save %ax in the stack */
	pushw	%ax
	/* simulate the interrupt call */
	pushw	8(%bp)
	/* set %ax and %bp to the original values */
	movw	2(%bp), %ax
	movw	(%bp), %bp
	/* lcall */
	.byte	0x9a
int13_offset:	.word	0
int13_segment:	.word	0
	/* save flags */
	pushf
	/* restore %bp */
	movw	%sp, %bp
	/* save %ax */
	pushw	%ax
	/* set the flags in the stack to the value returned by int13 */
	movw	(%bp), %ax
	movw	%ax, 0xc(%bp)
	/* check if should map the drive number */
	movw	6(%bp), %ax
	cmpw	$0x8, %ax
	jne	3f
	cmpw	$0x15, %ax
	jne	3f
	/* check if the mapping was performed */
	movw	2(%bp), %ax
	testw	%ax, %ax
	jz	3f
	/* perform the mapping */
	movb	%al, %dl
3:
	popw	%ax
	movw	4(%bp), %bp
	addw	$8, %sp
	iret

	.align	4
drive_map:	.space	(DRIVE_MAP_SIZE + 1) * 2
int13_handler_end:
	
	.code32
	
	
/*
 * chain_stage1(segment, offset, part_table_addr)
 *
 *  This starts another stage1 loader, at segment:offset.
 */

ENTRY(chain_stage1)
	/* no need to save anything, just use %esp */

	/* store %ESI, presuming %ES is 0 */
	movl	0xc(%esp), %esi

	/* store new offset */
	movl	0x8(%esp), %eax
	movl	%eax, offset

	/* store new segment */
	movw	0x4(%esp), %ax
	movw	%ax, segment

	/* set up to pass boot drive */
	movb	EXT_C(boot_drive), %dl

	call	EXT_C(prot_to_real)
	.code16

#ifdef ABSOLUTE_WITHOUT_ASTERISK
	DATA32	ADDR32	ljmp	(offset)
#else
	DATA32	ADDR32	ljmp	*(offset)
#endif
	.code32
#endif /* STAGE1_5 */


#ifdef STAGE1_5
/*
 * chain_stage2(segment, offset, second_sector)
 *
 *  This starts another stage2 loader, at segment:offset.  It presumes
 *  that the other one starts with this same "asm.S" file, and passes
 *  parameters by writing the embedded install variables.
 */

ENTRY(chain_stage2)
	/* no need to save anything, just use %esp */

	/* store new offset */
	movl	0x8(%esp), %eax
	movl	%eax, offset
	movl	%eax, %ebx

	/* store new segment */
	movw	0x4(%esp), %ax
	movw	%ax, segment
	shll	$4, %eax

	/* generate linear address */
	addl	%eax, %ebx

	/* set up to pass the partition where stage2 is located in */
	movl	EXT_C(current_partition), %eax
	movl	%eax, (EXT_C(install_partition)-EXT_C(main))(%ebx)

	/* set up to pass the drive where stage2 is located in */
	movb	EXT_C(current_drive), %dl

	/* set up to pass the second sector of stage2 */
	movl	0xc(%esp), %ecx

	call	EXT_C(prot_to_real)
	.code16

	movl	%ecx, %ebp

#ifdef ABSOLUTE_WITHOUT_ASTERISK
	DATA32	ADDR32	ljmp	(offset)
#else
	DATA32	ADDR32	ljmp	*(offset)
#endif

	.code32
#endif /* STAGE1_5 */
	
/*
 *  These next two routines, "real_to_prot" and "prot_to_real" are structured
 *  in a very specific way.  Be very careful when changing them.
 *
 *  NOTE:  Use of either one messes up %eax and %ebp.
 */

ENTRY(real_to_prot)
	.code16
	cli

	/* load the GDT register */
	DATA32	ADDR32	lgdt	gdtdesc

	/* turn on protected mode */
	movl	%cr0, %eax
	orl	$CR0_PE_ON, %eax
	movl	%eax, %cr0

	/* jump to relocation, flush prefetch queue, and reload %cs */
	DATA32	ljmp	$PROT_MODE_CSEG, $protcseg

	/*
	 *  The ".code32" directive only works in GAS, the GNU assembler!
	 *  This gets out of "16-bit" mode.
	 */
	.code32

protcseg:
	/* reload other segment registers */
	movw	$PROT_MODE_DSEG, %ax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %fs
	movw	%ax, %gs
	movw	%ax, %ss

	/* put the return address in a known safe location */
	movl	(%esp), %eax
	movl	%eax, STACKOFF

	/* get protected mode stack */
	movl	protstack, %eax
	movl	%eax, %esp
	movl	%eax, %ebp

	/* get return address onto the right stack */
	movl	STACKOFF, %eax
	movl	%eax, (%esp)

	/* zero %eax */
	xorl	%eax, %eax

	/* return on the old (or initialized) stack! */
	ret


ENTRY(prot_to_real)
	/* just in case, set GDT */
	lgdt	gdtdesc

	/* save the protected mode stack */
	movl	%esp, %eax
	movl	%eax, protstack

	/* get the return address */
	movl	(%esp), %eax
	movl	%eax, STACKOFF

	/* set up new stack */
	movl	$STACKOFF, %eax
	movl	%eax, %esp
	movl	%eax, %ebp

	/* set up segment limits */
	movw	$PSEUDO_RM_DSEG, %ax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %fs
	movw	%ax, %gs
	movw	%ax, %ss

	/* this might be an extra step */
	ljmp	$PSEUDO_RM_CSEG, $tmpcseg	/* jump to a 16 bit segment */

tmpcseg:
	.code16

	/* clear the PE bit of CR0 */
	movl	%cr0, %eax
	andl 	$CR0_PE_OFF, %eax
	movl	%eax, %cr0

	/* flush prefetch queue, reload %cs */
	DATA32	ljmp	$0, $realcseg

realcseg:
	/* we are in real mode now
	 * set up the real mode segment registers : DS, SS, ES
	 */
	/* zero %eax */
	xorl	%eax, %eax

	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %fs
	movw	%ax, %gs
	movw	%ax, %ss

	/* restore interrupts */
	sti

	/* return on new stack! */
	DATA32	ret

	.code32


/*
 *   int biosdisk_int13_extensions (int ax, int drive, void *dap)
 *
 *   Call IBM/MS INT13 Extensions (int 13 %ax=AX) for DRIVE. DAP
 *   is passed for disk address packet. If an error occurs, return
 *   non-zero, otherwise zero.
 */

ENTRY(biosdisk_int13_extensions)
	pushl	%ebp
	movl	%esp, %ebp

	pushl	%esi
	pushl	%ebx

	/* compute the address of disk_address_packet */
	movl	0x10(%ebp), %eax
	movw	%ax, %si
	xorw	%ax, %ax
	shrl	$4, %eax
	movw	%ax, %cx	/* save the segment to cx */

	/* drive */
	movb	0xc(%ebp), %dl
	/* ax */
	movw	0x8(%ebp), %bx
	/* enter real mode */
	call	EXT_C(prot_to_real)
	
	.code16
	movw	%bx, %ax
	movw	%cx, %ds
	int	$0x13		/* do the operation */
	movb	%ah, %dl	/* save return value */
	/* clear the data segment */
	xorw	%ax, %ax
	movw	%ax, %ds
	/* back to protected mode */
	DATA32	call	EXT_C(real_to_prot)
	.code32

	movb	%dl, %al	/* return value in %eax */

	popl	%ebx
	popl	%esi
	popl	%ebp

	ret
	
/*
 *   int biosdisk_standard (int ah, int drive, int coff, int hoff, int soff,
 *                          int nsec, int segment)
 *
 *   Call standard and old INT13 (int 13 %ah=AH) for DRIVE. Read/write
 *   NSEC sectors from COFF/HOFF/SOFF into SEGMENT. If an error occurs,
 *   return non-zero, otherwise zero.
 */

ENTRY(biosdisk_standard)
	pushl	%ebp
	movl	%esp, %ebp

	pushl	%ebx
	pushl	%edi
	pushl	%esi

	/* set up CHS information */
	movl	0x10(%ebp), %eax
	movb	%al, %ch
	movb	0x18(%ebp), %al
	shlb	$2, %al
	shrw	$2, %ax
	movb	%al, %cl
	movb	0x14(%ebp), %dh
	/* drive */
	movb	0xc(%ebp), %dl
	/* segment */
	movw	0x20(%ebp), %bx
	/* save nsec and ah to %di */
	movb	0x8(%ebp), %ah
	movb	0x1c(%ebp), %al
	movw	%ax, %di
	/* enter real mode */
	call	EXT_C(prot_to_real)

	.code16
	movw	%bx, %es
	xorw	%bx, %bx
	movw	$3, %si		/* attempt at least three times */

1:	
	movw	%di, %ax
	int	$0x13		/* do the operation */
	jnc	2f		/* check if successful */

	movb	%ah, %bl	/* save return value */
	/* if fail, reset the disk system */
	xorw	%ax, %ax
	int	$0x13
	
	decw	%si
	cmpw	$0, %si
	je	2f
	xorb	%bl, %bl
	jmp	1b		/* retry */
2:	
	/* back to protected mode */
	DATA32	call	EXT_C(real_to_prot)
	.code32

	movb	%bl, %al	/* return value in %eax */
	
	popl	%esi
	popl	%edi
	popl	%ebx
	popl	%ebp

	ret


/*
 *   int check_int13_extensions (int drive)
 *
 *   Check if LBA is supported for DRIVE. If it is supported, then return
 *   the major version of extensions, otherwise zero.
 */

ENTRY(check_int13_extensions)
	pushl	%ebp
	movl	%esp, %ebp

	pushl	%ebx

	/* drive */
	movb	0x8(%ebp), %dl
	/* enter real mode */
	call	EXT_C(prot_to_real)

	.code16
	movb	$0x41, %ah
	movw	$0x55aa, %bx
	int	$0x13		/* do the operation */
	
	/* check the result */
	jc	1f
	cmpw	$0xaa55, %bx
	jne	1f

	movb	%ah, %bl	/* save the major version into %bl */

	/* check if AH=0x42 is supported if FORCE_LBA is zero */
	movb	EXT_C(force_lba), %al
	testb	%al, %al
	jnz	2f
	andw	$1, %cx
	jnz	2f
	
1:
	xorb	%bl, %bl
2:
	/* back to protected mode */
	DATA32	call	EXT_C(real_to_prot)
	.code32

	movb	%bl, %al	/* return value in %eax */

	popl	%ebx
	popl	%ebp

	ret


/*
 *   int get_diskinfo_standard (int drive, unsigned long *cylinders, 
 *                              unsigned long *heads, unsigned long *sectors)
 *
 *   Return the geometry of DRIVE in CYLINDERS, HEADS and SECTORS. If an
 *   error occurs, then return non-zero, otherwise zero.
 */

ENTRY(get_diskinfo_standard)
	pushl	%ebp
	movl	%esp, %ebp

	pushl	%ebx
	pushl	%edi

	/* drive */
	movb	0x8(%ebp), %dl
	/* enter real mode */
	call	EXT_C(prot_to_real)

	.code16
	movb	$0x8, %ah
	int	$0x13		/* do the operation */
	/* check if successful */
	testb	%ah, %ah
	jnz	1f
	/* bogus BIOSes may not return an error number */
	testb	$0x3f, %cl	/* 0 sectors means no disk */
	jnz	1f		/* if non-zero, then succeed */
	/* XXX 0x60 is one of the unused error numbers */
	movb	$0x60, %ah
1:
	movb	%ah, %bl	/* save return value in %bl */
	/* back to protected mode */
	DATA32	call	EXT_C(real_to_prot)
	.code32

	/* restore %ebp */
	leal	0x8(%esp), %ebp
	
	/* heads */
	movb	%dh, %al
	incl	%eax		/* the number of heads is counted from zero */
	movl	0x10(%ebp), %edi
	movl	%eax, (%edi)

	/* sectors */
	xorl	%eax, %eax
	movb	%cl, %al
	andb	$0x3f, %al
	movl	0x14(%ebp), %edi
	movl	%eax, (%edi)

	/* cylinders */
	shrb	$6, %cl
	movb	%cl, %ah
	movb	%ch, %al
	incl	%eax		/* the number of cylinders is 
				   counted from zero */
	movl	0xc(%ebp), %edi
	movl	%eax, (%edi)

	xorl	%eax, %eax
	movb	%bl, %al	/* return value in %eax */

	popl	%edi
	popl	%ebx
	popl	%ebp

	ret


#if 0		
/*
 *   int get_diskinfo_floppy (int drive, unsigned long *cylinders, 
 *                            unsigned long *heads, unsigned long *sectors)
 *
 *   Return the geometry of DRIVE in CYLINDERS, HEADS and SECTORS. If an
 *   error occurs, then return non-zero, otherwise zero.
 */

ENTRY(get_diskinfo_floppy)
	pushl	%ebp
	movl	%esp, %ebp

	pushl	%ebx
	pushl	%esi

	/* drive */
	movb	0x8(%ebp), %dl
	/* enter real mode */
	call	EXT_C(prot_to_real)

	.code16
	/* init probe value */
	movl	$probe_values-1, %esi
1:
	xorw	%ax, %ax
	int	$0x13		/* reset floppy controller */

	incw	%si
	movb	(%si), %cl
	cmpb	$0, %cl		/* probe failed if zero */
	je	2f

	/* perform read */
	movw	$SCRATCHSEG, %ax
	movw	%ax, %es
	xorw	%bx, %bx
	movw	$0x0201, %ax
	movb	$0, %ch
	movb	$0, %dh
	int	$0x13

	/* FIXME: Read from floppy may fail even if the geometry is correct.
	   So should retry at least three times.  */
	jc	1b		/* next value */
	
	/* succeed */
	jmp	2f
	
probe_values:
	.byte	36, 18, 15, 9, 0
	
2:
	/* back to protected mode */
	DATA32	call	EXT_C(real_to_prot)
	.code32

	/* restore %ebp */
	leal	0x8(%esp), %ebp
	
	/* cylinders */
	movl	0xc(%ebp), %eax
	movl	$80, %ebx
	movl	%ebx, (%eax)
	/* heads */
	movl	0x10(%ebp), %eax
	movl	$2, %ebx
	movl	%ebx, (%eax)
	/* sectors */
	movl	0x14(%ebp), %eax
	movzbl	%cl, %ebx
	movl	%ebx, (%eax)

	/* return value in %eax */
	xorl	%eax, %eax
	cmpb	$0, %cl
	jne	3f
	incl	%eax		/* %eax = 1 (non-zero) */
3:
	popl	%esi
	popl	%ebx
	popl	%ebp

	ret
#endif
	

/* Source files are splitted, as they have different copyrights.  */
#ifndef STAGE1_5
# include "setjmp.S"
# include "apm.S"
#endif /* ! STAGE1_5 */
		
	

#ifndef STAGE1_5
/* get_code_end() :  return the address of the end of the code
 * This is here so that it can be replaced by asmstub.c.
 */
ENTRY(get_code_end)
	/* will be the end of the bss */
# if defined(HAVE_END_SYMBOL)
	movl	$end, %eax
# elif defined(HAVE_USCORE_END_SYMBOL)
	movl	$_end, %eax
# endif
	shrl	$2, %eax		/* Round up to the next word. */
	incl	%eax
	shll	$2, %eax
	ret
#endif /* ! STAGE1_5 */

/*
 *
 * get_memsize(i) :  return the memory size in KB. i == 0 for conventional
 *		memory, i == 1 for extended memory
 *	BIOS call "INT 12H" to get conventional memory size
 *	BIOS call "INT 15H, AH=88H" to get extended memory size
 *		Both have the return value in AX.
 *
 */

ENTRY(get_memsize)
	push	%ebp
	push	%ebx

	mov	0xc(%esp), %ebx

	call	EXT_C(prot_to_real)	/* enter real mode */
	.code16

	cmpb	$0x1, %bl
	DATA32	je	xext

	int	$0x12
	DATA32	jmp	xdone

xext:
	movb	$0x88, %ah
	int	$0x15

xdone:
	movw	%ax, %bx

	DATA32	call	EXT_C(real_to_prot)
	.code32

	movw	%bx, %ax
	pop	%ebx
	pop	%ebp
	ret


#ifndef STAGE1_5

/*
 *
 * get_eisamemsize() :  return packed EISA memory map, lower 16 bits is
 *		memory between 1M and 16M in 1K parts, upper 16 bits is
 *		memory above 16M in 64K parts.  If error, return -1.
 *	BIOS call "INT 15H, AH=E801H" to get EISA memory map,
 *		AX = memory between 1M and 16M in 1K parts.
 *		BX = memory above 16M in 64K parts.
 *
 */

ENTRY(get_eisamemsize)
	push	%ebp
	push	%ebx

	call	EXT_C(prot_to_real)	/* enter real mode */
	.code16

	movw	$0xe801, %ax
	int	$0x15

	shll	$16, %ebx
	movw	%ax, %bx

	DATA32	call	EXT_C(real_to_prot)
	.code32

	movl	$0xFFFFFFFF, %eax
	cmpb	$0x86, %bh
	je	xnoteisa

	movl	%ebx, %eax

xnoteisa:
	pop	%ebx
	pop	%ebp
	ret

/*
 *
 * get_mmap_entry(addr, cont) :  address and old continuation value (zero to
 *		start), for the Query System Address Map BIOS call.
 *
 *  Sets the first 4-byte int value of "addr" to the size returned by
 *  the call.  If the call fails, sets it to zero.
 *
 *	Returns:  new (non-zero) continuation value, 0 if done.
 *
 * NOTE: Currently hard-coded for a maximum buffer length of 1024.
 */

ENTRY(get_mmap_entry)
	push	%ebp
	push	%ebx
	push	%edi
	push	%esi

	/* place address (+4) in ES:DI */
	movl	0x14(%esp), %eax
	addl	$4, %eax
	movl	%eax, %edi
	andl	$0xf, %edi
	shrl	$4, %eax
	movl	%eax, %esi

	/* set continuation value */
	movl	0x18(%esp), %ebx

	/* set default maximum buffer size */
	movl	$0x14, %ecx

	/* set EDX to 'SMAP' */
	movl	$0x534d4150, %edx

	call	EXT_C(prot_to_real)	/* enter real mode */
	.code16

	movw	%si, %es
	movl	$0xe820, %eax
	int	$0x15

	DATA32	jc	xnosmap

	cmpl	$0x534d4150, %eax
	DATA32	jne	xnosmap

	cmpl	$0x14, %ecx
	DATA32	jl	xnosmap

	cmpl	$0x400, %ecx
	DATA32	jg	xnosmap

	DATA32	jmp	xsmap

xnosmap:
	movl	$0, %ecx

xsmap:
	DATA32	call	EXT_C(real_to_prot)
	.code32

	/* write length of buffer (zero if error) into "addr" */
	movl	0x14(%esp), %eax
	movl	%ecx, (%eax)

	/* set return value to continuation */
	movl	%ebx, %eax

	pop	%esi
	pop	%edi
	pop	%ebx
	pop	%ebp
	ret

/*
 * get_rom_config_table()
 *
 * Get the linear address of a ROM configuration table. Return zero,
 * if fails.
 */
	
ENTRY(get_rom_config_table)
	pushl	%ebp
	pushl	%ebx

	/* zero %ebx for simplicity */
	xorl	%ebx, %ebx
	
	call	EXT_C(prot_to_real)
	.code16

	movw	$0xc0, %ax
	int	$0x15

	jc	no_rom_table
	testb	%ah, %ah
	jnz	no_rom_table
	
	movw	%es, %dx
	jmp	found_rom_table
	
no_rom_table:
	xorw	%dx, %dx
	xorw	%bx, %bx
	
found_rom_table:
	DATA32	call	EXT_C(real_to_prot)
	.code32

	/* compute the linear address */
	movw	%dx, %ax
	shll	$4, %eax
	addl	%ebx, %eax

	popl	%ebx
	popl	%ebp
	ret


/*
 * int get_vbe_controller_info (struct vbe_controller *controller_ptr)
 *
 * Get VBE controller information.
 */

ENTRY(get_vbe_controller_info)
	pushl	%ebp
	movl	%esp, %ebp
	
	pushl	%edi
	pushl	%ebx

	/* Convert the linear address to segment:offset */
	movl	8(%ebp), %eax
	movl	%eax, %edi
	andl	$0x0000000f, %edi
	shrl	$4, %eax
	movl	%eax, %ebx

	call	EXT_C(prot_to_real)
	.code16

	movw	%bx, %es
	movw	$0x4F00, %ax
	int	$0x10

	movw	%ax, %bx
	DATA32	call	EXT_C(real_to_prot)
	.code32

	movzwl	%bx, %eax

	popl	%ebx
	popl	%edi
	popl	%ebp
	ret

	
/*
 * int get_vbe_mode_info (int mode_number, struct vbe_mode *mode_ptr)
 *
 * Get VBE mode information.
 */

ENTRY(get_vbe_mode_info)
	pushl	%ebp
	movl	%esp, %ebp
	
	pushl	%edi
	pushl	%ebx

	/* Convert the linear address to segment:offset */
	movl	0xc(%ebp), %eax
	movl	%eax, %edi
	andl	$0x0000000f, %edi
	shrl	$4, %eax
	movl	%eax, %ebx

	/* Save the mode number in %cx */
	movl	0x8(%ebp), %ecx
	
	call	EXT_C(prot_to_real)
	.code16

	movw	%bx, %es
	movw	$0x4F01, %ax
	int	$0x10

	movw	%ax, %bx
	DATA32	call	EXT_C(real_to_prot)
	.code32

	movzwl	%bx, %eax

	popl	%ebx
	popl	%edi
	popl	%ebp
	ret

	
/*
 * int set_vbe_mode (int mode_number)
 *
 * Set VBE mode. Don't support user-specified CRTC information.
 */

ENTRY(set_vbe_mode)
	pushl	%ebp
	movl	%esp, %ebp
	
	pushl	%ebx

	/* Save the mode number in %bx */
	movl	0x8(%ebp), %ebx
	/* Clear bit D11 */
	andl	$0xF7FF, %ebx
	
	call	EXT_C(prot_to_real)
	.code16

	movw	$0x4F02, %ax
	int	$0x10

	movw	%ax, %bx
	DATA32	call	EXT_C(real_to_prot)
	.code32

	movzwl	%bx, %eax

	popl	%ebx
	popl	%ebp
	ret

		
/*
 * gateA20(int linear)
 *
 * Gate address-line 20 for high memory.
 *
 * This routine is probably overconservative in what it does, but so what?
 *
 * It also eats any keystrokes in the keyboard buffer.  :-(
 */

ENTRY(gateA20)
	/* first, try a BIOS call */
	pushl	%ebp
	movl	8(%esp), %edx
	
	call	EXT_C(prot_to_real)
	
	.code16
	movw	$0x2400, %ax
	testw	%dx, %dx
	jz	1f
	incw	%ax
1:	stc
	int	$0x15
	jnc	2f

	/* set non-zero if failed */
	movb	$1, %ah

	/* save the status */
2:	movb	%ah, %dl

	DATA32	call	EXT_C(real_to_prot)
	.code32

	popl	%ebp
	testb	%dl, %dl
	jnz	3f
	ret

3:	/*
	 * try to switch gateA20 using PORT92, the "Fast A20 and Init"
	 * register
	 */
	mov	$0x92, %dx
	inb	%dx, %al
	/* skip the port92 code if it's unimplemented (read returns 0xff) */
	cmpb	$0xff, %al
	jz	6f

	/* set or clear bit1, the ALT_A20_GATE bit */
	movb	4(%esp), %ah
	testb	%ah, %ah
	jz	4f
	orb	$2, %al
	jmp	5f
4:	and	$0xfd, %al

	/* clear the INIT_NOW bit; don't accidently reset the machine */
5:	and	$0xfe, %al
	outb	%al, %dx

6:	/* use keyboard controller */
	pushl	%eax

	call    gloop1

	movb	$KC_CMD_WOUT, %al
	outb	$K_CMD

gloopint1:
	inb	$K_STATUS
	cmpb    $0xff, %al
	jz      gloopint1_done
	andb	$K_IBUF_FUL, %al
	jnz	gloopint1

gloopint1_done:
	movb	$KB_OUTPUT_MASK, %al
	cmpb	$0, 0x8(%esp)
	jz	gdoit

	orb	$KB_A20_ENABLE, %al
gdoit:
	outb	$K_RDWR

	call	gloop1

	/* output a dummy command (USB keyboard hack) */
	movb	$0xff, %al
	outb	$K_CMD
	call	gloop1
	
	popl	%eax
	ret

gloop1:
	inb	$K_STATUS
	cmpb	$0xff, %al
	jz	gloop2ret
	andb	$K_IBUF_FUL, %al
	jnz	gloop1

gloop2:
	inb	$K_STATUS
	andb	$K_OBUF_FUL, %al
	jz	gloop2ret
	inb	$K_RDWR
	jmp	gloop2

gloop2ret:
	ret


ENTRY(patch_code)	/* labels start with "pc_" */
	.code16

	mov	%cs, %ax
	mov	%ax, %ds
	mov	%ax, %es
	mov	%ax, %fs
	mov	%ax, %gs
	ADDR32	movl	$0, 0
pc_stop:
	hlt
	DATA32	jmp	pc_stop
ENTRY(patch_code_end)

	.code32


/*
 * linux_boot()
 *
 * Does some funky things (including on the stack!), then jumps to the
 * entry point of the Linux setup code.
 */

VARIABLE(linux_text_len)
	.long	0
	
VARIABLE(linux_data_tmp_addr)
	.long	0
	
VARIABLE(linux_data_real_addr)
	.long	0
	
ENTRY(linux_boot)
	/* don't worry about saving anything, we're committed at this point */
	cld	/* forward copying */

	/* copy kernel */
	movl	EXT_C(linux_text_len), %ecx
	addl	$3, %ecx
	shrl	$2, %ecx
	movl	$LINUX_BZIMAGE_ADDR, %esi
	movl	$LINUX_ZIMAGE_ADDR, %edi

	rep
	movsl

ENTRY(big_linux_boot)
	movl	EXT_C(linux_data_real_addr), %ebx
	
	/* copy the real mode part */
	movl	EXT_C(linux_data_tmp_addr), %esi
	movl	%ebx, %edi
	movl	$LINUX_SETUP_MOVE_SIZE, %ecx
	cld
	rep
	movsb

	/* change %ebx to the segment address */
	shrl	$4, %ebx
	movl	%ebx, %eax
	addl	$0x20, %eax
	movl	%eax, linux_setup_seg
			
	/* XXX new stack pointer in safe area for calling functions */
	movl	$0x4000, %esp
	call	EXT_C(stop_floppy)

	/* final setup for linux boot */

	call	EXT_C(prot_to_real)
	.code16

	/* final setup for linux boot */
	cli
	movw	%bx, %ss
	movw	$LINUX_SETUP_STACK, %sp
	
	movw	%bx, %ds
	movw	%bx, %es
	movw	%bx, %fs
	movw	%bx, %gs

	/* jump to start */
	/* ljmp */
	.byte	0xea
	.word	0
linux_setup_seg:	
	.word	0
	.code32


/*
 * multi_boot(int start, int mb_info)
 *
 *  This starts a kernel in the manner expected of the multiboot standard.
 */

ENTRY(multi_boot)
	/* no need to save anything */
	call	EXT_C(stop_floppy)

	movl	$0x2BADB002, %eax
	movl	0x8(%esp), %ebx

	/* boot kernel here (absolute address call) */
	call	*0x4(%esp)

	/* error */
	call	EXT_C(stop)

#endif /* ! STAGE1_5 */
	
/*
 * void console_putchar (int c)
 *
 * Put the character C on the console. Because GRUB wants to write a
 * character with an attribute, this implementation is a bit tricky.
 * If C is a control character (CR, LF, BEL, BS), use INT 10, AH = 0Eh
 * (TELETYPE OUTPUT). Otherwise, save the original position, put a space,
 * save the current position, restore the original position, write the
 * character and the attribute, and restore the current position.
 *
 * The reason why this is so complicated is that there is no easy way to
 * get the height of the screen, and the TELETYPE OUPUT BIOS call doesn't
 * support setting a background attribute.
 */
ENTRY(console_putchar)
	movl	0x4(%esp), %edx
	pusha
#ifdef STAGE1_5
	movb	$0x07, %bl
#else
	movl	EXT_C(console_current_color), %ebx
#endif
	
	call	EXT_C(prot_to_real)
	.code16
	movb	%dl, %al
	xorb	%bh, %bh

#ifndef STAGE1_5
	/* use teletype output if control character */
	cmpb	$0x7, %al
	je	1f
	cmpb	$0x8, %al
	je	1f
	cmpb	$0xa, %al
	je	1f
	cmpb	$0xd, %al
	je	1f

	/* save the character and the attribute on the stack */
	pushw	%ax
	pushw	%bx
	
	/* get the current position */
	movb	$0x3, %ah
	int	$0x10

	/* check the column with the width */
	cmpb	$79, %dl
	jl	2f
	
	/* print CR and LF, if next write will exceed the width */	
	movw	$0x0e0d, %ax
	int	$0x10
	movb	$0x0a, %al
	int	$0x10
	
	/* get the current position */
	movb	$0x3, %ah
	int	$0x10

2:	
	/* restore the character and the attribute */
	popw	%bx
	popw	%ax
	
	/* write the character with the attribute */
	movb	$0x9, %ah
	movw	$1, %cx
	int	$0x10

	/* move the cursor forward */
	incb	%dl
	movb	$0x2, %ah
	int	$0x10

	jmp	3f
#endif /* ! STAGE1_5 */
	
1:	movb	$0xe, %ah
	int	$0x10
	
3:	DATA32	call	EXT_C(real_to_prot)
	.code32
	
	popa
	ret


#ifndef STAGE1_5

/* this table is used in translate_keycode below */
translation_table:
	.word	KEY_LEFT, 2
	.word	KEY_RIGHT, 6
	.word	KEY_UP, 16
	.word	KEY_DOWN, 14
	.word	KEY_HOME, 1
	.word	KEY_END, 5
	.word	KEY_DC, 4
	.word	KEY_BACKSPACE, 8
	.word	KEY_PPAGE, 7
	.word	KEY_NPAGE, 3
	.word	0
	
/*
 * translate_keycode translates the key code %dx to an ascii code.
 */
	.code16

translate_keycode:
	pushw	%bx
	pushw	%si
	
	movw	$ABS(translation_table), %si
	
1:	lodsw
	/* check if this is the end */
	testw	%ax, %ax
	jz	2f
	/* load the ascii code into %ax */
	movw	%ax, %bx
	lodsw
	/* check if this matches the key code */
	cmpw	%bx, %dx
	jne	1b
	/* translate %dx, if successful */
	movw	%ax, %dx

2:	popw	%si
	popw	%bx
	ret

	.code32
	

/*
 * remap_ascii_char remaps the ascii code %dl to another if the code is
 * contained in ASCII_KEY_MAP.
 */
	.code16
	
remap_ascii_char:
	pushw	%si
	
	movw	$ABS(EXT_C(ascii_key_map)), %si
1:
	lodsw
	/* check if this is the end */
	testw	%ax, %ax
	jz	2f
	/* check if this matches the ascii code */
	cmpb	%al, %dl
	jne	1b
	/* if so, perform the mapping */
	movb	%ah, %dl
2:
	/* restore %si */
	popw	%si

	ret

	.code32

	.align	4
ENTRY(ascii_key_map)
	.space	(KEY_MAP_SIZE + 1) * 2
	

/*
 * int console_getkey (void)
 * BIOS call "INT 16H Function 00H" to read character from keyboard
 *	Call with	%ah = 0x0
 *	Return:		%ah = keyboard scan code
 *			%al = ASCII character
 */

ENTRY(console_getkey)
	push	%ebp

wait_for_key:
	call	EXT_C(console_checkkey)
	incl	%eax
	jz	wait_for_key

	call	EXT_C(prot_to_real)
	.code16

	int	$0x16

	movw	%ax, %dx		/* real_to_prot uses %eax */
	call	translate_keycode
	call	remap_ascii_char
	
	DATA32	call	EXT_C(real_to_prot)
	.code32

	movw	%dx, %ax

	pop	%ebp
	ret


/*
 * int console_checkkey (void)
 *	if there is a character pending, return it; otherwise return -1
 * BIOS call "INT 16H Function 01H" to check whether a character is pending
 *	Call with	%ah = 0x1
 *	Return:
 *		If key waiting to be input:
 *			%ah = keyboard scan code
 *			%al = ASCII character
 *			Zero flag = clear
 *		else
 *			Zero flag = set
 */
ENTRY(console_checkkey)
	push	%ebp
	xorl	%edx, %edx
	
	call	EXT_C(prot_to_real)	/* enter real mode */
	.code16

	movb	$0x1, %ah
	int	$0x16

	DATA32	jz	notpending
	
	movw	%ax, %dx
	call	translate_keycode
	call	remap_ascii_char
	DATA32	jmp	pending

notpending:
	movl	$0xFFFFFFFF, %edx

pending:
	DATA32	call	EXT_C(real_to_prot)
	.code32

	mov	%edx, %eax

	pop	%ebp
	ret

	
/*
 * int console_getxy (void)
 * BIOS call "INT 10H Function 03h" to get cursor position
 *	Call with	%ah = 0x03
 *			%bh = page
 *      Returns         %ch = starting scan line
 *                      %cl = ending scan line
 *                      %dh = row (0 is top)
 *                      %dl = column (0 is left)
 */


ENTRY(console_getxy)
	push	%ebp
	push	%ebx                    /* save EBX */

	call	EXT_C(prot_to_real)
	.code16

        xorb	%bh, %bh                /* set page to 0 */
	movb	$0x3, %ah
	int	$0x10			/* get cursor position */

	DATA32	call	EXT_C(real_to_prot)
	.code32

	movb	%dl, %ah
	movb	%dh, %al

	pop	%ebx
	pop	%ebp
	ret


/*
 * void console_gotoxy(int x, int y)
 * BIOS call "INT 10H Function 02h" to set cursor position
 *	Call with	%ah = 0x02
 *			%bh = page
 *                      %dh = row (0 is top)
 *                      %dl = column (0 is left)
 */


ENTRY(console_gotoxy)
	push	%ebp
	push	%ebx                    /* save EBX */

	movb	0xc(%esp), %dl           /* %dl = x */
	movb	0x10(%esp), %dh          /* %dh = y */

	call	EXT_C(prot_to_real)
	.code16

        xorb	%bh, %bh                /* set page to 0 */
	movb	$0x2, %ah
	int	$0x10			/* set cursor position */

	DATA32	call	EXT_C(real_to_prot)
	.code32

	pop	%ebx
	pop	%ebp
	ret

	
/*
 * void console_cls (void)
 * BIOS call "INT 10H Function 09h" to write character and attribute
 *	Call with	%ah = 0x09
 *                      %al = (character)
 *                      %bh = (page number)
 *                      %bl = (attribute)
 *                      %cx = (number of times)
 */


ENTRY(console_cls)
	push	%ebp
	push	%ebx                    /* save EBX */

	call	EXT_C(prot_to_real)
	.code16

	/* move the cursor to the beginning */
	movb	$0x02, %ah
	xorb	%bh, %bh
	xorw	%dx, %dx
	int	$0x10

	/* write spaces to the entire screen */
	movw	$0x0920, %ax
	movw	$0x07, %bx
	movw	$(80 * 25), %cx
        int	$0x10

	/* move back the cursor */
	movb	$0x02, %ah
	int	$0x10

	DATA32	call	EXT_C(real_to_prot)
	.code32

	pop	%ebx
	pop	%ebp
	ret

	
/*
 * int console_setcursor (int on)
 * BIOS call "INT 10H Function 01h" to set cursor type
 *      Call with       %ah = 0x01
 *                      %ch = cursor starting scanline
 *                      %cl = cursor ending scanline
 */

console_cursor_state:
	.byte	1
console_cursor_shape:
	.word	0
	
ENTRY(console_setcursor)
	push	%ebp
	push	%ebx

	/* check if the standard cursor shape has already been saved */
	movw	console_cursor_shape, %ax
	testw	%ax, %ax
	jne	1f

	call	EXT_C(prot_to_real)
	.code16

	movb	$0x03, %ah
	xorb	%bh, %bh
	int	$0x10

	DATA32	call	EXT_C(real_to_prot)
	.code32

	movw	%cx, console_cursor_shape
1:
	/* set %cx to the designated cursor shape */
	movw	$0x2000, %cx
	movl	0xc(%esp), %ebx
	testl	%ebx, %ebx
	jz	2f
	movw	console_cursor_shape, %cx
2:	
	call	EXT_C(prot_to_real)
	.code16

	movb    $0x1, %ah
	int     $0x10 

	DATA32	call	EXT_C(real_to_prot)
	.code32

	movzbl	console_cursor_state, %eax
	movb	%bl, console_cursor_state
	
	pop	%ebx
	pop	%ebp
	ret

/* graphics mode functions */
#ifdef SUPPORT_GRAPHICS
VARIABLE(cursorX)
.word	0
VARIABLE(cursorY)
.word	0
VARIABLE(cursorCount)
.word 0
VARIABLE(cursorBuf)
.byte	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0

	
/*
 * int set_videomode(mode)
 * BIOS call "INT 10H Function 0h" to set video mode
 *	Call with	%ah = 0x0
 *			%al = video mode
 *      Returns old videomode.
 */
ENTRY(set_videomode)
	push	%ebp
	push	%ebx
	push	%ecx

	movb	0x10(%esp), %cl

	call	EXT_C(prot_to_real)
	.code16

	xorw	%bx, %bx
	movb	$0xf, %ah
	int	$0x10			/* Get Current Video mode */
	movb	%al, %ch
	xorb	%ah, %ah
	movb	%cl, %al
        int	$0x10			/* Set Video mode */

	DATA32	call	EXT_C(real_to_prot)
	.code32

	xorb	%ah, %ah
	movb	%ch, %al

	pop	%ecx
	pop	%ebx
	pop	%ebp
	ret


/*
 * unsigned char * graphics_get_font()
 * BIOS call "INT 10H Function 11h" to set font
 *      Call with       %ah = 0x11
 */
ENTRY(graphics_get_font)
	push	%ebp
	push	%ebx
	push	%ecx
	push	%edx

	call	EXT_C(prot_to_real)
	.code16

	movw	$0x1130, %ax
	movb	$6, %bh		/* font 8x16 */
	int	$0x10
	movw	%bp, %dx
	movw	%es, %cx

	DATA32	call	EXT_C(real_to_prot)
	.code32

	xorl	%eax, %eax
	movw	%cx, %ax
	shll	$4, %eax
	movw	%dx, %ax

	pop	%edx
	pop	%ecx
	pop	%ebx
	pop	%ebp
	ret
	

	
/*
 * graphics_set_palette(index, red, green, blue)
 * BIOS call "INT 10H Function 10h" to set individual dac register
 *	Call with	%ah = 0x10
 *			%bx = register number
 *			%ch = new value for green (0-63)
 *			%cl = new value for blue (0-63)
 *			%dh = new value for red (0-63)
 */

ENTRY(graphics_set_palette)
	push	%ebp
	push	%eax
	push	%ebx
	push	%ecx
	push	%edx

	movw	$0x3c8, %bx		/* address write mode register */

	/* wait vertical retrace */

	movw	$0x3da, %dx
l1b:	inb	%dx, %al	/* wait vertical active display */
	test	$8, %al
	jnz	l1b

l2b:	inb	%dx, %al	/* wait vertical retrace */
	test	$8, %al
	jnz	l2b

	mov	%bx, %dx
	movb	0x18(%esp), %al		/* index */
	outb	%al, %dx
	inc	%dx

	movb	0x1c(%esp), %al		/* red */
	outb	%al, %dx

	movb	0x20(%esp), %al		/* green */
	outb	%al, %dx

	movb	0x24(%esp), %al		/* blue */
	outb	%al, %dx

	movw	0x18(%esp), %bx

	call	EXT_C(prot_to_real)
	.code16

	movb	%bl, %bh
	movw	$0x1000, %ax
	int	$0x10

	DATA32	call	EXT_C(real_to_prot)
	.code32	

	pop	%edx
	pop	%ecx
	pop	%ebx
	pop	%eax
	pop	%ebp
	ret

#endif /* SUPPORT_GRAPHICS */
		
/*
 * getrtsecs()
 *	if a seconds value can be read, read it and return it (BCD),
 *      otherwise return 0xFF
 * BIOS call "INT 1AH Function 02H" to check whether a character is pending
 *	Call with	%ah = 0x2
 *	Return:
 *		If RT Clock can give correct values
 *			%ch = hour (BCD)
 *			%cl = minutes (BCD)
 *                      %dh = seconds (BCD)
 *                      %dl = daylight savings time (00h std, 01h daylight)
 *			Carry flag = clear
 *		else
 *			Carry flag = set
 *                         (this indicates that the clock is updating, or
 *                          that it isn't running)
 */
ENTRY(getrtsecs)
	push	%ebp

	call	EXT_C(prot_to_real)	/* enter real mode */
	.code16

	movb	$0x2, %ah
	int	$0x1a

	DATA32	jnc	gottime
	movb	$0xff, %dh

gottime:
	DATA32	call	EXT_C(real_to_prot)
	.code32

	movb	%dh, %al

	pop	%ebp
	ret

	
/*
 * currticks()
 *	return the real time in ticks, of which there are about
 *	18-20 per second
 */
ENTRY(currticks)
	pushl	%ebp

	call	EXT_C(prot_to_real)	/* enter real mode */
	.code16

	/* %ax is already zero */
        int	$0x1a

	DATA32	call	EXT_C(real_to_prot)
	.code32

	movl	%ecx, %eax
	shll	$16, %eax
	movw	%dx, %ax

	popl	%ebp
	ret

ENTRY(amd64_rdmsr)
	movl	4(%esp), %ecx
	rdmsr
	movl	8(%esp), %ecx
	movl	%eax, (%ecx)
	movl	%edx, 4(%ecx)
	ret

ENTRY(amd64_wrmsr)
	movl	8(%esp), %ecx
	movl	(%ecx), %eax
	movl	4(%ecx), %edx
	movl	4(%esp), %ecx
	wrmsr
	ret

ENTRY(amd64_cpuid_insn)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	pushl	%esi
	movl	0x8(%ebp), %eax
	movl	0xc(%ebp), %esi
	cpuid
	movl	%eax, 0x0(%esi)
	movl	%ebx, 0x4(%esi)
	movl	%ecx, 0x8(%esi)
	movl	%edx, 0xc(%esi)
	popl	%esi
	popl	%ebx
	popl	%ebp
	ret

	/*
	 * Based on code from AMD64 Volume 3
	 */
ENTRY(amd64_cpuid_supported)
	pushf
	popl	%eax
	mov	%eax, %edx		/* save %eax for later */
	xorl	%eax, 0x200000		/* toggle bit 21 */
	pushl	%eax
	popf				/* save new %eax to EFLAGS */
	pushf				/* save new EFLAGS */
	popl	%ecx			/* copy EFLAGS to %eax */
	xorl	%eax, %eax
	cmpl	%ecx, %edx		/* see if bit 21 has changes */
	jne	1f
	incl	%eax
1:
	ret

ENTRY(get_target_operating_mode)
	pusha

	call	EXT_C(prot_to_real)
	.code16

	movw	$0xec00, %ax
	movw	$0x03, %bx
	int	$0x15

	setc	%al
	movw	%ax, %cx

	DATA32	call	EXT_C(real_to_prot)
	.code32

	xorl	%eax, %eax
	movw	%cx, %ax
	movl	%eax, 0x1c(%esp)

	popa
	ret

#endif /* ! STAGE1_5 */

/*
 *  This is the area for all of the special variables.
 */

	.p2align	2	/* force 4-byte alignment */

protstack:
	.long	PROTSTACKINIT

VARIABLE(boot_drive)
#ifdef SUPPORT_DISKLESS
	.long	NETWORK_DRIVE
#else
	.long	0
#endif

VARIABLE(install_second_sector)
	.long	0
	
	/* an address can only be long-jumped to if it is in memory, this
	   is used by multiple routines */
offset:
	.long	0x8000
segment:
	.word	0

VARIABLE(apm_bios_info)
	.word	0	/* version */
	.word	0	/* cseg */
	.long	0	/* offset */
	.word	0	/* cseg_16 */
	.word	0	/* dseg_16 */
	.word	0	/* cseg_len */
	.word	0	/* cseg_16_len */
	.word	0	/* dseg_16_len */
	
/*
 * This is the Global Descriptor Table
 *
 *  An entry, a "Segment Descriptor", looks like this:
 *
 * 31          24         19   16                 7           0
 * ------------------------------------------------------------
 * |             | |B| |A|       | |   |1|0|E|W|A|            |
 * | BASE 31..24 |G|/|0|V| LIMIT |P|DPL|  TYPE   | BASE 23:16 |
 * |             | |D| |L| 19..16| |   |1|1|C|R|A|            |
 * ------------------------------------------------------------
 * |                             |                            |
 * |        BASE 15..0           |       LIMIT 15..0          |
 * |                             |                            |
 * ------------------------------------------------------------
 *
 *  Note the ordering of the data items is reversed from the above
 *  description.
 */

	.p2align	2	/* force 4-byte alignment */
gdt:
	.word	0, 0
	.byte	0, 0, 0, 0

	/* code segment */
	.word	0xFFFF, 0
	.byte	0, 0x9A, 0xCF, 0

	/* data segment */
	.word	0xFFFF, 0
	.byte	0, 0x92, 0xCF, 0

	/* 16 bit real mode CS */
	.word	0xFFFF, 0
	.byte	0, 0x9E, 0, 0

	/* 16 bit real mode DS */
	.word	0xFFFF, 0
	.byte	0, 0x92, 0, 0


/* this is the GDT descriptor */
gdtdesc:
	.word	0x27			/* limit */
	.long	gdt			/* addr */
