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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_DUMPHDR_H
#define	_SYS_DUMPHDR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/utsname.h>
#include <sys/log.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The dump header describes the contents of a crash dump.  Two headers
 * are written out: one at the beginning of the dump, and the other at
 * the very end of the dump device.  The terminal header is at a known
 * location (end of device) so we can always find it.  The initial header
 * is redundant, but helps savecore(1M) determine whether the dump has been
 * overwritten by swap activity.  See dumpadm(1M) for dump configuration.
 */
#define	DUMP_MAGIC	0xdefec8edU		/* dump magic number */
#define	DUMP_VERSION	9			/* version of this dumphdr */
#define	DUMP_WORDSIZE	(sizeof (long) * NBBY)	/* word size (32 or 64) */
#define	DUMP_PANICSIZE	200			/* Max panic string copied */
#define	DUMP_COMPRESS_RATIO	2		/* conservative; usually 2.5+ */
#define	DUMP_OFFSET	65536			/* pad at start/end of dev */
#define	DUMP_LOGSIZE	(2 * LOG_HIWAT)		/* /dev/log message save area */
#define	DUMP_ERPTSIZE   (P2ROUNDUP(	\
	(ERPT_DATA_SZ / 2) *		\
	(ERPT_EVCH_MAX +		\
	ERPT_MAX_ERRS * ERPT_HIWAT),	\
	DUMP_OFFSET))				/* ereport save area */

typedef struct dumphdr {
	uint32_t dump_magic;		/* magic number */
	uint32_t dump_version;		/* version number */
	uint32_t dump_flags;		/* flags; see below */
	uint32_t dump_wordsize;		/* 32 or 64 */
	offset_t dump_start;		/* starting offset on dump device */
	offset_t dump_ksyms;		/* offset of compressed symbol table */
	offset_t dump_pfn;		/* offset of pfn table for all pages */
	offset_t dump_map;		/* offset of page translation map */
	offset_t dump_data;		/* offset of actual dump data */
	struct utsname dump_utsname;	/* copy of utsname structure */
	char	dump_platform[SYS_NMLN]; /* platform name (uname -i) */
	char	dump_panicstring[DUMP_PANICSIZE]; /* copy of panicstr */
	time_t	dump_crashtime;		/* time of crash */
	long	dump_pageshift;		/* log2(pagesize) */
	long	dump_pagesize;		/* pagesize */
	long	dump_hashmask;		/* page translation hash mask */
	long	dump_nvtop;		/* number of vtop table entries */
	pgcnt_t	dump_npages;		/* number of data pages */
	size_t	dump_ksyms_size;	/* kernel symbol table size */
	size_t	dump_ksyms_csize;	/* compressed symbol table size */
} dumphdr_t;

/*
 * Values for dump_flags
 */
#define	DF_VALID	0x00000001	/* Dump is valid (savecore clears) */
#define	DF_COMPLETE	0x00000002	/* All pages present as configured */
#define	DF_LIVE		0x00000004	/* Dump was taken on a live system */
#define	DF_KERNEL	0x00010000	/* Contains kernel pages only */
#define	DF_ALL		0x00020000	/* Contains all pages */
#define	DF_CURPROC	0x00040000	/* Contains kernel + cur proc pages */
#define	DF_CONTENT	0xffff0000	/* The set of all dump content flags */

/*
 * Dump translation map hash table entry.
 */
typedef struct dump_map {
	offset_t	dm_first;
	offset_t	dm_next;
	offset_t	dm_data;
	struct as	*dm_as;
	uintptr_t	dm_va;
} dump_map_t;

/*
 * Dump translation map hash function.
 */
#define	DUMP_HASH(dhp, as, va)	\
	((((uintptr_t)(as) >> 3) + ((va) >> (dhp)->dump_pageshift)) & \
	(dhp)->dump_hashmask)

#ifdef _KERNEL

extern kmutex_t dump_lock;
extern struct vnode *dumpvp;
extern u_offset_t dumpvp_size;
extern struct dumphdr *dumphdr;
extern int dump_conflags;
extern char *dumppath;

extern int dump_timeout;
extern int dump_timeleft;
extern int dump_ioerr;
extern int sync_timeout;
extern int sync_timeleft;

extern int dumpinit(struct vnode *, char *, int);
extern void dumpfini(void);
extern void dump_resize(void);
extern void dump_page(pfn_t);
extern void dump_addpage(struct as *, void *, pfn_t);
extern void dumpsys(void);
extern void dump_messages(void);
extern void dump_ereports(void);
extern void dumpvp_write(const void *, size_t);
extern int dump_plat_addr(void);
extern void dump_plat_pfn(void);
extern int dump_plat_data(void *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DUMPHDR_H */
