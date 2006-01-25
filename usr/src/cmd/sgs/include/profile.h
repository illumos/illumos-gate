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
 *	Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

#ifndef	_PROFILE_H
#define	_PROFILE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_ASM

#include <sys/types.h>
#include <synch.h>
#include <link.h>

/*
 * The profile buffer created by ld.so.1 consists of 3 sections; the header,
 * the profil(2) buffer, and an array of call graph arc structures.
 */

typedef struct l_hdr {			/* Linker profile buffer header */
	unsigned int	hd_magic;	/* identifier for file */
	unsigned int	hd_version;	/* version for rtld prof file */
	lwp_mutex_t	hd_mutex;	/* Provides for process locking */
	caddr_t		hd_hpc;		/* Relative high pc address */
	unsigned int	hd_psize;	/* Size of profil(2) buffer */
	unsigned int	hd_fsize;	/* Size of file */
	unsigned int	hd_ncndx;	/* Next (and last) index into */
	unsigned int	hd_lcndx;	/*	call graph arc structure */
} L_hdr;


/*
 * The *64 structs are for gprof, as a 32-bit program,
 * to read 64-bit profiles correctly.
 */

typedef struct l_hdr64 {		/* Linker profile buffer header */
	unsigned int	hd_magic;	/* identifier for file */
	unsigned int	hd_version;	/* version for rtld prof file */
	lwp_mutex_t	hd_mutex;	/* Provides for process locking */
	u_longlong_t	hd_hpc;		/* Relative high pc address */
	unsigned int	hd_psize;	/* Size of profil(2) buffer */
	unsigned int	hd_fsize;	/* Size of file */
	unsigned int	hd_ncndx;	/* Next (and last) index into */
	unsigned int	hd_lcndx;	/*	call graph arc structure */
} L_hdr64;



typedef struct l_cgarc {		/* Linker call graph arc entry */
	caddr_t		cg_from;	/* Source of call */
	caddr_t		cg_to;		/* Destination of call */
	unsigned int	cg_count;	/* Instance count */
	unsigned int	cg_next;	/* Link index for multiple sources */
} L_cgarc;


typedef struct l_cgarc64 {		/* Linker call graph arc entry */
	u_longlong_t	cg_from;	/* Source of call */
	u_longlong_t	cg_to;		/* Destination of call */
	unsigned int	cg_count;	/* Instance count */
	unsigned int	cg_next;	/* Link index for multiple sources */
} L_cgarc64;



/*
 * Generic defines for creating profiled output buffer.
 */

#define	PRF_BARSIZE	2		/* No. of program bytes that */
					/* correspond to each histogram */
					/* bar in the profil(2) buffer */
#define	PRF_SCALE	0x8000		/* Scale to provide above */
					/* histogram correspondence */
#define	PRF_CGNUMB	256		/* Size of call graph extension */
#define	PRF_CGINIT	2		/* Initial symbol blocks to allocate */
					/*	for the call graph structure */
#define	PRF_OUTADDR	(caddr_t)-1	/* Function addresses outside of */
					/*	the range being monitored */
#define	PRF_OUTADDR64	(u_longlong_t)-1	/* Function addresses outside */
					/*	of the range being monitored */
#define	PRF_UNKNOWN	(caddr_t)-2	/* Unknown function address */

#define	PRF_ROUNDUP(x, a) (((x) + ((a) - 1)) & ~((a) - 1))
#define	PRF_ROUNDWN(x, a) ((x) & ~((a) - 1))

#define	PRF_MAGIC	0xffffffff	/* unique number to differentiate */
					/* profiled file from gmon.out for */
					/* gprof */
#define	PRF_VERSION	0x1		/* current PROF file version */
#define	PRF_VERSION_64	0x2		/* 64-bit current PROF file version */


/*
 * Related data and function definitions.
 */

extern	int		profile_rtld;		/* Rtld is being profiled */

extern	uintptr_t (*	p_cg_interp)(int, caddr_t, caddr_t);

#endif

#ifdef	__cplusplus
}
#endif

#endif /* _PROFILE_H */
