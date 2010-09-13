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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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

typedef struct cpu64_sysinfo {
	uint64_t	cpu[CPU_STATES];
	uint64_t	wait[W_STATES];
	uint64_t	bread;
	uint64_t	bwrite;
	uint64_t	lread;
	uint64_t	lwrite;
	uint64_t	phread;
	uint64_t	phwrite;
	uint64_t	pswitch;
	uint64_t	trap;
	uint64_t	intr;
	uint64_t	syscall;
	uint64_t	sysread;
	uint64_t	syswrite;
	uint64_t	sysfork;
	uint64_t	sysvfork;
	uint64_t	sysexec;
	uint64_t	readch;
	uint64_t	writech;
	uint64_t	rcvint;
	uint64_t	xmtint;
	uint64_t	mdmint;
	uint64_t	rawch;
	uint64_t	canch;
	uint64_t	outch;
	uint64_t	msg;
	uint64_t	sema;
	uint64_t	namei;
	uint64_t	ufsiget;
	uint64_t	ufsdirblk;
	uint64_t	ufsipage;
	uint64_t	ufsinopage;
	uint64_t	inodeovf;
	uint64_t	fileovf;
	uint64_t	procovf;
	uint64_t	intrthread;
	uint64_t	intrblk;
	uint64_t	idlethread;
	uint64_t	inv_swtch;
	uint64_t	nthreads;
	uint64_t	cpumigrate;
	uint64_t	xcalls;
	uint64_t	mutex_adenters;
	uint64_t	rw_rdfails;
	uint64_t	rw_wrfails;
	uint64_t	modload;
	uint64_t	modunload;
	uint64_t	bawrite;
	uint64_t	rw_enters;
	uint64_t	win_uo_cnt;
	uint64_t	win_uu_cnt;
	uint64_t	win_so_cnt;
	uint64_t	win_su_cnt;
	uint64_t	win_suo_cnt;
} cpu64_sysinfo_t;

typedef struct cpu64_vminfo {
	uint64_t	pgrec;
	uint64_t	pgfrec;
	uint64_t	pgin;
	uint64_t	pgpgin;
	uint64_t	pgout;
	uint64_t	pgpgout;
	uint64_t	swapin;
	uint64_t	pgswapin;
	uint64_t	swapout;
	uint64_t	pgswapout;
	uint64_t	zfod;
	uint64_t	dfree;
	uint64_t	scan;
	uint64_t	rev;
	uint64_t	hat_fault;
	uint64_t	as_fault;
	uint64_t	maj_fault;
	uint64_t	cow_fault;
	uint64_t	prot_fault;
	uint64_t	softlock;
	uint64_t	kernel_asflt;
	uint64_t	pgrrun;
	uint64_t	execpgin;
	uint64_t	execpgout;
	uint64_t	execfree;
	uint64_t	anonpgin;
	uint64_t	anonpgout;
	uint64_t	anonfree;
	uint64_t	fspgin;
	uint64_t	fspgout;
	uint64_t	fsfree;
} cpu64_vminfo_t;

typedef struct sysinfo64 {
	uint64_t	updates;
	uint64_t	runque;
	uint64_t	runocc;
	uint64_t	swpque;
	uint64_t	swpocc;
	uint64_t	waiting;
} sysinfo64_t;

struct sa64 {
	int		valid;
	time_t		ts;

	cpu64_sysinfo_t	csi;
	cpu64_vminfo_t	cvmi;
	sysinfo64_t	si;
	vminfo_t	vmi;
	kmeminfo_t	kmi;

	ulong_t		szinode;
	ulong_t		szfile;
	ulong_t		szproc;
	ulong_t		szlckr;

	ulong_t		mszinode;
	ulong_t		mszfile;
	ulong_t		mszproc;
	ulong_t		mszlckr;

	ulong_t	niodevs;
};

extern struct sa sa;

#ifdef	__cplusplus
}
#endif

#endif /* _SA_H */
