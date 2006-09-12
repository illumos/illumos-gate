/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc. */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T */
/*	  All Rights Reserved */

#ifndef _SYS_SYSI86_H
#define	_SYS_SYSI86_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef DIRSIZ
#define	DIRSIZ	14
#endif

/*
 * Commands for sysi86 system call (1-?)
 */

#define	SI86SWPI	1	/* General swap interface. */
#define	SI86SYM		2	/* acquire boot-built symbol table */
#define	SI86CONF	4	/* acquire boot-built configuration table */
#define	SI86BOOT	5	/* acquire timestamp and name of program */
				/*	booted */
#define	SI86AUTO	9	/* was an auto-config boot done? */
#define	SI86EDT		10	/* copy contents of EDT to user */
#define	SI86SWAP	12	/* Declare swap space */
#define	SI86FPHW	40	/* what (if any?) floating-point hardware */
#define	SI86FPSTART	41	/* extended version of SI86FPHW */

#define	GRNON		52	/* set green light to solid on state */
#define	GRNFLASH	53	/* start green light flashing */
#define	STIME		54	/* set internal time */
#define	SETNAME		56	/* rename the system */
#define	RNVR		58	/* read NVRAM */
#define	WNVR		59	/* write NVRAM */
#define	RTODC		60	/* read time of day clock */
#define	CHKSER		61	/* check soft serial number */
#define	SI86NVPRT	62	/* print an xtra_nvr structure */
#define	SANUPD		63	/* sanity update of kernel buffers */
#define	SI86KSTR	64	/* make a copy of a kernel string */
#define	SI86MEM		65	/* return the memory size of system */
#define	SI86TODEMON	66	/* Transfer control to firmware. */
#define	SI86CCDEMON	67	/* Control character access to demon. */
#define	SI86CACHE	68	/* Turn cache on and off. */
#define	SI86DELMEM	69	/* Delete available memory for testing. */
#define	SI86ADDMEM	70	/* Add back deleted memory. */
/*	71 through 74 reserved for VPIX */
#define	SI86V86		71	/* V86 system calls (see below) */
#define	SI86SLTIME	72	/* Set local time correction */
#define	SI86DSCR	75	/* Set a segment or gate descriptor */
#define	RDUBLK		76	/* Read U Block */
/* NFA entry point */
#define	SI86NFA		77	/* make nfa_sys system call */
#define	SI86VM86	81
#define	SI86VMENABLE	82
#define	SI86LIMUSER	91	/* license interface */
#define	SI86RDID	92	/* ROM BIOS Machid ID */
#define	SI86RDBOOT	93	/* Bootable Non-SCSI Hard Disk */
/* XENIX Support */
#define	SI86SHFIL	100	/* map a file into addr space of a proc */
#define	SI86PCHRGN	101	/* make globally visible change to a region */
#define	SI86BADVISE	102	/* badvise subcommand - see below for */
				/*	badvise subfunction definitions */
#define	SI86SHRGN	103	/* enable/disable XENIX small model shared */
				/*	data context switching */
#define	SI86CHIDT	104	/* set user level int 0xf0, ... 0xff handlers */
#define	SI86EMULRDA	105	/* remove special emulator read access */

/*
 *	NOTE: Numbers 106 - 110 have been registered and are reserved
 *	for future use for AT&T hardware.
 */

/*
 *	Commands for allowing the real time clock to keep local time.
 */

#define	WTODC		111	/* write tod clock */
#define	SGMTL		112	/* set GMT lag */
#define	GGMTL		113	/* get GMT lag */
#define	RTCSYNC		114	/* set UNIX 'time' based on RTC and GMT lag */

#define	V86SC_IOPL	4	/* The only supported V86 system call */

/*
 *  The SI86DSCR subcommand of the sysi86() system call
 *  sets a segment or gate descriptor in the kernel.
 *  The following descriptor types are accepted:
 *    - executable and data segments in the LDT at DPL 3
 *    - a call gate in the GDT at DPL 3 that points to a segment in the LDT
 *  The request structure declared below is used to pass the values
 *  to be placed in the descriptor.  A pointer to the structure is
 *  passed as the second argument of the system call.
 *  If acc1 is zero, the descriptor is cleared.
 */

/*
 * XX64 Do we need to support this for 64-bit apps?
 *
 * request structure passed by user
 */
struct ssd {
	unsigned int	sel;   /* descriptor selector */
	unsigned int	bo;    /* segment base or gate offset */
	unsigned int	ls;    /* segment limit or gate selector */
	unsigned int	acc1;  /* access byte 5 */
	unsigned int	acc2;  /* access bits in byte 6 or gate count */
};

#define	SI86SSD_TYPE(ssd)	((ssd)->acc1 & 0x1F)
#define	SI86SSD_DPL(ssd)	(((ssd)->acc1 >> 5) & 0x3)
#define	SI86SSD_PRES(ssd)	(((ssd)->acc1 >> 7) & 1)
#define	SI86SSD_ISUSEG(ssd)	(SI86SSD_TYPE(ssd) >= SDT_MEMRO)
#define	SI86SSD_ISLONG(ssd)	((ssd)->acc2 & 0x2)

#ifdef _KERNEL
extern void usd_to_ssd(user_desc_t *, struct ssd *, selector_t);
extern int setdscr(struct ssd *);
#endif	/* _KERNEL */

/*
 *  The SI86SHFIL subcommand of the sysi86() system call
 *  maps a file into a region in user address space.
 *  The request structure declared below is used to pass the
 *  system call parameters.  A pointer to the structure is
 *  passed as the second argument of the system call.
 */
struct mmf {
	char	*mf_filename;	/* path name of file */
	long	mf_filesz;	/* Size in bytes of section of file */
				/* from which this region is mapped. */
	long	mf_regsz;	/* Size of region in bytes */
	short	mf_flags;	/* Either 0 or RG_NOSHARE */
};

/*
 *  The SI86PCHRGN subcommand of the sysi86() system call
 *  change the memory mapped image of a file.
 *  The request structure declared below is used to pass the values
 *  system call parameters.  A pointer to the structure is
 *  passed as the second argument of the system call.
 */
struct cmf {
	char	*cf_srcva;	/* modified image address */
	char	*cf_dstva;	/* location to patch */
	long	cf_count;	/* size of patch */
};

/*
 * The SI86BADVISE subcommand of the sysi86() system call specifies
 * XENIX variant behavior for certain system calls and kernel routines.
 * The 'arg' argument of sysi86() for SI86BADVISE is an integer.  Bits
 * 8..15 specify SI86B_SET or SI86B_GET.  Bits 0..7 contain
 * SI86B_PRE_SV, SI86B_XOUT, or SI86B_XSDSWTCH.  All these constants are
 * defined below.  The 'arg' argument thus consists of either SI86B_SET
 * OR'ed with zero or more of SI86B_PRE_SV, SI86B_XOUT, and SI86B_XSDSWTCH,
 * or of SI86B_GET.
 */
#define	SI86B_SET		0x0100	/* set badvise bits */
#define	SI86B_GET		0x0200	/* retrieve badvise bits */

#define	SI86B_PRE_SV		0x0008	/* follow pre-System V x.out behavior */
#define	SI86B_XOUT		0x0010 	/* follow XENIX x.out behavior */
#define	SI86B_XSDSWTCH		0x0080	/* XENIX small model shared data */
					/*	context switching enabled */

/*
 *   The request structure declared below is used by the XENIX 286 emulator
 *   (/bin/x286emul) in conjunction with the SI86SHRGN subcommand of sysi86().
 *   The SI86SHRGN subcommand is used by the XENIX 286 emulator to support
 *   XENIX shared data.  The second argument passed to sysi86() is a
 *   pointer to an xsdbuf struct.
 *
 *   If the 'xsd_cmd' field of xsdbuf is SI86SHR_CP, the XENIX 286 emulator is
 *   using the SI86SHRGN subcommand to set up XENIX small model shared data
 *   context switching support for a given XENIX shared data segment.  In this
 *   case, the xsdbuf struct contains the start addr for the shared data in
 *   386 space, followed by the start addr for the shared data in the 286
 *   executable's private data.
 *
 *   If the 'xsd_cmd' field is SI86SHR_SZ, the XENIX 286 emulator is using the
 *   SI86SHRGN subcommand to retrieve the size of an existing XENIX shared
 *   data segment.  In this case, the xsdbuf struct contains the start addr
 *   for the shared data in 386 space.
 *   The size of the shared data segment starting at 'xsd_386vaddr' will
 *   be returned in the 'xsd_size' field by sysi86().
 */

#define	SI86SHR_CP	0x1	/* SI86SHRGN used for XENIX sd context switch */
#define	SI86SHR_SZ	0x2	/* SI86SHRGN used to get XENIX sd seg size */

struct xsdbuf {
	unsigned xsd_cmd;	/* SI86SHRGN subcommand, either SI86SHR_CP */
				/* or SI86SHR_SZ. */
	char	*xsd_386vaddr;	/* Addr of "real" XENIX shared data seg in */
				/* the emulator. */
	union {
		char	*xsd_286vaddr;	/* Addr of XENIX shared data seg */
					/* in the 286 data portion of the */
					/* emulator. */
		unsigned long xsd_size;	/* Size of XENIX shared data seg */
	} xsd_un;
};
/* End XENIX Support */

/*
 * Cascade defines
 */

#define	C2	'E'
#define	C3	'F'
#define	C4	'G'
#define	C6	'K'

/* Enterprise IDNO defines */
#define	E8R1	'R'

#ifndef _KERNEL
#ifdef __STDC__
extern	int	sysi86(int, ...);
#else
extern	int	sysi86();
#endif	/* __STDC__ */
#endif	/* !_KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SYSI86_H */
