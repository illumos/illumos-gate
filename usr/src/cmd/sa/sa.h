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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 1992-1994, 2000, 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SA_H
#define	_SA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * sa.h contains struct sa and defines variables used in sadc.c and sar.c.
 * RESTRICTION: the data types defined in this file must not be changed.
 * sar writes these types to disk as binary data and to ensure version to
 * version compatibility they must not be changed.
 */

#include <sys/kstat.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct iodevinfo {
	struct iodevinfo *next;
	kstat_t *ksp;
	kstat_t ks;
	kstat_io_t kios;
} iodevinfo_t;

#define	KMEM_SMALL  0		/* small KMEM request index		*/
#define	KMEM_LARGE  1		/* large KMEM request index		*/
#define	KMEM_OSIZE  2		/* outsize KMEM request index		*/
#define	KMEM_NCLASS 3		/* # of KMEM request classes		*/

typedef struct kmeminfo {
	ulong_t	km_mem[KMEM_NCLASS];	/* amount of mem owned by KMEM	*/
	ulong_t	km_alloc[KMEM_NCLASS];  /* amount of mem allocated	*/
	ulong_t	km_fail[KMEM_NCLASS];	/* # of failed requests		*/
} kmeminfo_t;

/*
 * structure sa defines the data structure of system activity data file
 */

struct sa {
	int		valid;		/* non-zero for valid data	*/
	time_t		ts;		/* time stamp			*/

	cpu_sysinfo_t	csi;		/* per-CPU system information	*/
	cpu_vminfo_t	cvmi;		/* per-CPU vm information	*/
	sysinfo_t	si;		/* global system information	*/
	vminfo_t	vmi;		/* global vm information	*/
	kmeminfo_t	kmi;		/* kernel mem allocation info	*/

	ulong_t		szinode;	/* inode table size		*/
	ulong_t		szfile;		/* file table size		*/
	ulong_t		szproc;		/* proc table size		*/
	ulong_t		szlckr;		/* file record lock table size	*/

	ulong_t		mszinode;	/* max inode table size		*/
	ulong_t		mszfile;	/* max file table size		*/
	ulong_t		mszproc;	/* max proc table size		*/
	ulong_t		mszlckr;	/* max file rec lock table size	*/

	ulong_t	niodevs;		/* number of I/O devices	*/

	/* An array of iodevinfo structs come next in the sadc files	*/
};

extern struct sa sa;

#ifdef	__cplusplus
}
#endif

#endif /* _SA_H */
