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
 *			cfsd_maptbl.h
 *
 * Include file for the maptbl class.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/* Copyright (c) 1994 by Sun Microsystems, Inc. */

#ifndef CFSD_MAPTBL
#define	CFSD_MAPTBL

typedef struct cfsd_maptbl_object {
	char		i_name[MAXPATHLEN * 3];	/* name of file */
	int		i_fid;			/* fid of file */
	off_t		i_size;			/* file size */
	int		i_entries;		/* number of entries */
	int		i_hash2mod;		/* second hash module value */
	int		i_stat_filled;		/* number of filled entries */
	int		i_stat_requests;	/* number of lookups done */
	int		i_stat_probes;		/* number of probes */
	int		i_stat_mapmove;		/* number of times map moved */
	long		i_stat_mapdist;		/* how far we move the map */
	caddr_t	i_pa;				/* address of mmap section */
	size_t	i_palen;			/* length of mmap section */
	off_t		i_paoff;		/* offset of mmap section */
	off_t		i_paend;		/* end offset of mmap section */
	long		i_pagesize;		/* size of a page */
	u_long	i_pagemask;			/* page alignment mask */
	long		i_maplen;		/* amount to map */
} cfsd_maptbl_object_t;

cfsd_maptbl_object_t *cfsd_maptbl_create(void);
void cfsd_maptbl_destroy(cfsd_maptbl_object_t *maptbl_object_p);

int maptbl_domap(cfsd_maptbl_object_t *maptbl_object_p, off_t off);
caddr_t maptbl_getaddr(cfsd_maptbl_object_t *maptbl_object_p, int index);
int maptbll_cidhashaddr(cfsd_maptbl_object_t *maptbl_object_p,
    cfs_cid_t cid, caddr_t *addrp);
int maptbl_hash1(cfsd_maptbl_object_t *maptbl_object_p, cfs_cid_t cid);
int maptbl_hash2(cfsd_maptbl_object_t *maptbl_object_p, cfs_cid_t cid,
    int index);

/* performs setup for the specified file */
int maptbl_setup(cfsd_maptbl_object_t *maptbl_object_p, const char *filename);
void maptbl_teardown(cfsd_maptbl_object_t *maptbl_object_p);

/* gets/sets cid mapping */
int maptbl_get(cfsd_maptbl_object_t *maptbl_object_p, cfs_cid_t cid,
    struct cfs_dlog_mapping_space *valuep);
int maptbl_set(cfsd_maptbl_object_t *maptbl_object_p,
    struct cfs_dlog_mapping_space *valuep, int insert);

/* prints out various stats about the hashing */
void maptbl_dumpstats(cfsd_maptbl_object_t *maptbl_object_p);

#endif /* CFSD_MAPTBL */
