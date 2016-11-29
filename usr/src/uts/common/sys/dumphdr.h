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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#ifndef _SYS_DUMPHDR_H
#define	_SYS_DUMPHDR_H

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
#define	DUMP_VERSION	10			/* version of this dumphdr */
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
#define	DUMP_SUMMARYSIZE (P2ROUNDUP(    \
	(STACK_BUF_SIZE +	       \
	sizeof (summary_dump_t) + 1024), \
	DUMP_OFFSET))				/* summary save area */

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
	uint32_t dump_fm_panic;		/* initiated from fm subsystems */
	char	dump_uuid[36 + 1];	/* os image uuid */
} dumphdr_t;

/*
 * Values for dump_flags
 */
#define	DF_VALID	0x00000001	/* Dump is valid (savecore clears) */
#define	DF_COMPLETE	0x00000002	/* All pages present as configured */
#define	DF_LIVE		0x00000004	/* Dump was taken on a live system */
#define	DF_COMPRESSED	0x00000008	/* Dump is compressed */
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

/*
 * Encoding of the csize word used to provide meta information
 * between dumpsys and savecore.
 *
 *	tag	size
 *	1-4095	1..dump_maxcsize	stream block
 *	0	1..pagesize		one lzjb page
 *	0	0			marks end of data
 */
typedef uint32_t dumpcsize_t;

#define	DUMP_MAX_TAG		(0xfffU)
#define	DUMP_MAX_CSIZE		(0xfffffU)
#define	DUMP_SET_TAG(w, v)	(((w) & DUMP_MAX_CSIZE) | ((v) << 20))
#define	DUMP_GET_TAG(w)		(((w) >> 20) & DUMP_MAX_TAG)
#define	DUMP_SET_CSIZE(w, v)	\
	(((w) & (DUMP_MAX_TAG << 20)) | ((v) & DUMP_MAX_CSIZE))
#define	DUMP_GET_CSIZE(w)	((w) & DUMP_MAX_CSIZE)

typedef struct dumpstreamhdr {
	char		stream_magic[8];	/* "StrmHdr" */
	pgcnt_t		stream_pagenum;		/* starting pfn */
	pgcnt_t		stream_npages;		/* uncompressed size */
} dumpstreamhdr_t;

#define	DUMP_STREAM_MAGIC	"StrmHdr"

/* The number of helpers is limited by the number of stream tags. */
#define	DUMP_MAX_NHELPER	DUMP_MAX_TAG

/*
 * The dump data header is placed after the dumphdr in the compressed
 * image. It is not needed after savecore runs and the data pages have
 * been decompressed.
 */
typedef struct dumpdatahdr {
	uint32_t dump_datahdr_magic;	/* data header presence */
	uint32_t dump_datahdr_version;	/* data header version */
	uint64_t dump_data_csize;	/* compressed data size */
	uint32_t dump_maxcsize;		/* compressed data max block size */
	uint32_t dump_maxrange;		/* max number of pages per range */
	uint16_t dump_nstreams;		/* number of compression streams */
	uint16_t dump_clevel;		/* compression level (0-9) */
	uint32_t dump_metrics;		/* size of metrics data */
} dumpdatahdr_t;

#define	DUMP_DATAHDR_MAGIC	('d' << 24 | 'h' << 16 | 'd' << 8 | 'r')

#define	DUMP_DATAHDR_VERSION	1
#define	DUMP_CLEVEL_LZJB	1	/* parallel lzjb compression */
#define	DUMP_CLEVEL_BZIP2	2	/* parallel bzip2 level 1 */

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

extern int dumpinit(struct vnode *, char *, int);
extern void dumpfini(void);
extern void dump_resize(void);
extern void dump_page(pfn_t);
extern void dump_addpage(struct as *, void *, pfn_t);
extern void dumpsys(void);
extern void dumpsys_helper(void);
extern void dumpsys_helper_nw(void);
extern void dump_messages(void);
extern void dump_ereports(void);
extern void dumpvp_write(const void *, size_t);
extern int dumpvp_resize(void);
extern int dump_plat_addr(void);
extern void dump_plat_pfn(void);
extern int dump_plat_data(void *);
extern int dump_set_uuid(const char *);
extern const char *dump_get_uuid(void);

/*
 * Define a CPU count threshold that determines when to employ
 * bzip2. This value is defined per-platform.
 */
extern uint_t dump_plat_mincpu_default;

#define	DUMP_PLAT_SUN4U_MINCPU		0
#define	DUMP_PLAT_SUN4U_OPL_MINCPU	0
#define	DUMP_PLAT_SUN4V_MINCPU		0
#define	DUMP_PLAT_X86_64_MINCPU		0
#define	DUMP_PLAT_X86_32_MINCPU		0

/*
 * Override the per-platform default by setting this variable with
 * /etc/system.  The value 0 disables parallelism, and the old format
 * dump is produced.
 */
extern uint_t dump_plat_mincpu;

/*
 * Pages may be stolen at dump time. Prevent the pages from ever being
 * allocated while dump is running.
 */
#define	IS_DUMP_PAGE(pp) (dump_check_used && dump_test_used((pp)->p_pagenum))

extern int dump_test_used(pfn_t);
extern int dump_check_used;

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DUMPHDR_H */
