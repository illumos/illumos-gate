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
 *
 *			cfsd_logfile.h
 *
 * Include file for the cfsd_logfile class.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* Copyright (c) 1994 by Sun Microsystems, Inc. */

#ifndef CFSD_LOGFILE
#define	CFSD_LOGFILE

/* should come up with a standard dlog version size */
/* XXX should move these to <sys/fs/cachefs_dlog.h> */
#define	LOGFILE_ENTRY_START	sizeof (long)
#define	CFS_DLOG_ENTRY_MINSIZE  sizeof (long)

/* mmap info */
typedef struct mmap_info {
	caddr_t		i_pa;		/* address of mmap section */
	size_t		i_palen;	/* length of mmap section */
	off_t		i_paoff;	/* offset of mmap section */
	off_t		i_paend;	/* end offset of mmap section */
}mmap_info_t;

typedef struct cfsd_logfile_object {
	char		i_name[MAXPATHLEN * 3];	/* name of file */
	int		i_fid;			/* fid of file */
	off_t		i_size;			/* file size */
	int		i_stat_nextcnt;		/* number of next calls */
	int		i_stat_offcnt;		/* number of offset calls */
	int		i_stat_mapmove;		/* number of times map moved */
	long		i_stat_mapdist;		/* how far we move the map */

	mmap_info_t	i_map_entry;		/* mmap for log entries */
	mmap_info_t	i_map_offset;		/* mmap for arbitrary offsets */

	off_t		i_cur_offset;		/* offset to log entry */
	cfs_dlog_entry_t *i_cur_entry;		/* ptr to log entry */

	long		i_pagesize;		/* size of a page */
	u_long		i_pagemask;		/* page alignment mask */
	long		i_maplen;		/* amount to map */
	int		i_maxmap;		/* max amount referenced */
} cfsd_logfile_object_t;

cfsd_logfile_object_t *cfsd_logfile_create(void);
void cfsd_logfile_destroy(cfsd_logfile_object_t *cfsd_logfile_object_p);

int logfile_domap(cfsd_logfile_object_t *logfile_object_p, off_t off, int map);
caddr_t logfile_getaddr(cfsd_logfile_object_t *logfile_object_p,
    off_t start, int map);

/* performs setup for the specified file */
int logfile_setup(cfsd_logfile_object_t *logfile_object_p,
    const char *filename, int maxmap);
void logfile_teardown(cfsd_logfile_object_t *logfile_object_p);

/* returns ptr to a log file entry */
int logfile_entry(cfsd_logfile_object_t *logfile_object_p, off_t offset,
    cfs_dlog_entry_t **entpp);

/* returns ptr to arbitrary point in log */
int logfile_offset(cfsd_logfile_object_t *logfile_object_p, off_t offset,
    caddr_t *addrp);

/* syncs the logfile to disk */
int logfile_sync(cfsd_logfile_object_t *logfile_object_p);

/* prints out various stats how the log file is used */
void logfile_dumpstats(cfsd_logfile_object_t *logfile_object_p);

#endif /* CFSD_LOGFILE */
