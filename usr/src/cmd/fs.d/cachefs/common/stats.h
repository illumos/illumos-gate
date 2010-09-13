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
 * Copyright 1996-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _CACHEFS_LIB_STATS_H
#define	_CACHEFS_LIB_STATS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_log.h>
#include <kstat.h>
#include <ndbm.h>

#ifndef DEBUG
#define	NDEBUG
#endif /* DEBUG */

#define	STATS_MAGIC	54545

typedef struct stats_cookie {
	int st_magic;

	char *st_progname;

	uint_t st_flags;	/* misc. flags */
	int st_fsid;		/* id # for kstat `cachefs.#.stat' */

	FILE *st_logstream;	/* stream for logfile */
	XDR st_logxdr;
	struct cachefs_log_logfile_header st_loghead;
	char st_asciirec[BUFSIZ];

	DBM *st_dbm;
	char st_dbm_name[MAXPATHLEN];

	int st_ws_init;
	u_offset_t st_ws_current;
	u_offset_t st_ws_high;
	int st_ws_expensive;

	char st_errorstr[BUFSIZ];
	int st_errno;

	kstat_ctl_t *st_kstat_cookie;
} stats_cookie_t;

/*
 * error types for the API (given by stats_errno())
 */

enum stats_error {
	SE_NOERROR,	/* placeholder so no errors == 0 */
	SE_INVAL,	/* invalid use of the API */
	SE_NOMEM,	/* ran out of memory */
	SE_FILE,	/* trouble with file i/o */
	SE_CORRUPT,	/* trouble with a corrupt file */
	SE_KERNEL	/* trouble coming from communication with the kernel */
};

/*
 * flags in cookie->st_flags
 */

#define	ST_VALID	0x0001 /* initialized completely */
#define	ST_BOUND	0x0002 /* bound to a particular filesystem or cache */
#define	ST_ERROR	0x0004 /* an error has occured */
#define	ST_LFOPEN	0x0008 /* logstream is open */
#define	ST_DBMOPEN	0x0010 /* dbm descriptor is open */
#define	ST_WSCOMP	0x0020 /* working set size computed */

/*
 * flags for logfile-to-workingset
 */

#define	GRI_ADD		0x01	/* we may have added to the alloc map	*/
#define	GRI_TRUNC	0x02	/* we may have truncated the alloc map	*/
#define	GRI_MODIFY	0x04	/* we modified this file		*/
#define	GRI_METADATA	0x08	/* we created metadata			*/
#define	GRI_EXPENSIVE	0x10	/* record indicates `expensive' logging */

/*
 * structures for logfile-to-workingset
 */

#define	FI_METADATA	0x01	/* this file has metadata */

/*
 * len and offset are now u_offset_t in sync with struct cachefs_allocmap in
 * file cachefs_fs.h
 */
typedef struct fid_info {
	int fi_magic;

	uint_t fi_flags;

	caddr_t fi_vfsp;

	uint_t fi_ent_n;
	struct fid_info_allocent {
		u_offset_t offset;
		u_offset_t len;
	} fi_ent[C_MAX_ALLOCINFO_SLOTS];

	u_offset_t fi_total;
} fid_info;

#define	FI_MAGIC	(3748321)

typedef struct mount_info {
	int mi_magic;

	uint_t mi_mounted:1;
	uint_t mi_used:1;

	u_offset_t mi_current;
	u_offset_t mi_high;

	uint_t mi_flags;
	uint_t mi_filegrp_size;
	char mi_path[2];
} mount_info;

#define	MI_MAGIC	(837492)

/*
 * Define the maximum size of char mi_path[]
 *
 * The maximum size of mi_path is a path (MAXPATHLEN) and a cacheid
 * (C_MAX_MOUNT_FSCDIRNAME) plus terminating nulls (2).
 *
 * Additional space is allocated to mi_path at runtime using malloc().
 */

#define	MI_MAX_MI_PATH	(MAXPATHLEN + C_MAX_MOUNT_FSCDIRNAME + 2)

typedef struct filegrp_info {
	int fg_magic;

	uint_t fg_count;  /* high-water known # of attrcache entries */
	uint_t fg_bcount; /* # of bits set in fg_bits */
	uchar_t fg_bits[DEF_FILEGRP_SIZE / NBBY];

	size_t fg_size;	 /* high-water attrcache size (MAXBSIZE ceiling) */
} fg_info;

#define	FG_MAGIC	(673492)

/*
 * the cachefs stats (stats_*) API.
 */

/* stats_create.c */
stats_cookie_t *stats_create_mountpath(char *, char *);
stats_cookie_t *stats_create_unbound(char *);
cachefs_kstat_key_t *stats_next(stats_cookie_t *);
cachefs_kstat_key_t *stats_getkey(stats_cookie_t *);
void stats_destroy(stats_cookie_t *);
int stats_good(stats_cookie_t *);
char *stats_errorstr(stats_cookie_t *);
int stats_errno(stats_cookie_t *);
int stats_inerror(stats_cookie_t *);
void stats_perror(stats_cookie_t *, int, char *, ...);

/* stats_log.c */
int stats_log_kernel_setname(stats_cookie_t *, char *);
int stats_log_which(stats_cookie_t *, int, int);
char *stats_log_kernel_getname(stats_cookie_t *);
int stats_log_logfile_open(stats_cookie_t *, char *);
void *stats_log_logfile_read(stats_cookie_t *, int *);
char *stats_log_record_toascii(stats_cookie_t *, void *);
uint_t stats_log_get_record_info(stats_cookie_t *,
    void *, caddr_t *, cfs_fid_t **, ino64_t *, u_offset_t *, u_offset_t *);
void stats_log_fi_add(stats_cookie_t *, fid_info *, u_offset_t, u_offset_t);
void stats_log_fi_trunc(stats_cookie_t *, fid_info *, u_offset_t, u_offset_t);
struct cachefs_log_logfile_header *stats_log_getheader(stats_cookie_t *);
void stats_log_compute_wssize(stats_cookie_t *);
int stats_log_wssize_init(stats_cookie_t *);
u_offset_t stats_log_wssize_current(stats_cookie_t *);
u_offset_t stats_log_wssize_high(stats_cookie_t *);
int stats_log_wssize_expensive(stats_cookie_t *);

/* stats_stats.c */
uint_t stats_hits(stats_cookie_t *);
uint_t stats_misses(stats_cookie_t *);
uint_t stats_passes(stats_cookie_t *);
uint_t stats_fails(stats_cookie_t *);
uint_t stats_modifies(stats_cookie_t *);
uint_t stats_gc_count(stats_cookie_t *);
time_t stats_gc_time(stats_cookie_t *);
time_t stats_gc_before(stats_cookie_t *);
time_t stats_gc_after(stats_cookie_t *);
int stats_zero_stats(stats_cookie_t *);

/* stats_dbm.c */
void stats_dbm_open(stats_cookie_t *);
void stats_dbm_rm(stats_cookie_t *);
void stats_dbm_close(stats_cookie_t *);
fid_info *stats_dbm_fetch_byfid(stats_cookie_t *, cfs_fid_t *);
void stats_dbm_store_byfid(stats_cookie_t *, cfs_fid_t *, fid_info *);
mount_info *stats_dbm_fetch_byvfsp(stats_cookie_t *, caddr_t);
void stats_dbm_store_byvfsp(stats_cookie_t *, caddr_t, mount_info *);
void stats_dbm_delete_byvfsp(stats_cookie_t *, caddr_t);
size_t stats_dbm_attrcache_addsize(stats_cookie_t *, mount_info *,
    ino64_t, uint_t);
datum stats_dbm_firstkey(stats_cookie_t *);
datum stats_dbm_nextkey(stats_cookie_t *);

#ifdef __cplusplus
}
#endif

#endif /* _CACHEFS_LIB_STATS_H */
