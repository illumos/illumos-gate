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

#ifndef _FHTAB_H
#define	_FHTAB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Support for the fh mapping file for nfslog.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RPC dispatch table for file handles
 * Indexed by program, version, proc
 * Based on NFS dispatch table.
 * Differences: no xdr of args/res.
 */
struct nfsl_fh_proc_disp {
	void	(*nfsl_dis_args)();	/* dispatch routine for proc */
	bool_t	(*xdr_args)();		/* XDR function for arguments */
	bool_t	(*xdr_res)();		/* XDR function for results */
	int	args_size;		/* size of arguments struct */
	int	res_size;		/* size of results struct */
};

struct nfsl_fh_vers_disp {
	int	nfsl_dis_nprocs;			/* number of procs */
	struct nfsl_fh_proc_disp *nfsl_dis_proc_table;	/* proc array */
};

struct nfsl_fh_prog_disp {
	int	nfsl_dis_prog;		/* program number */
	int	nfsl_dis_versmin;	/* minimum version number */
	int	nfsl_dis_nvers;		/* number of version values */
	struct nfsl_fh_vers_disp *nfsl_dis_vers_table;	/* versions array */
};

/* key comprised of inode/gen, currenly 8 or 10 bytes */
#define	PRIMARY_KEY_LEN_MAX	16
typedef char	fh_primary_key[PRIMARY_KEY_LEN_MAX];

/* link key - directory primary key plus name (upto 2 components) */
#define	SECONDARY_KEY_LEN_MAX	(PRIMARY_KEY_LEN_MAX + MAXPATHLEN)
typedef char	fh_secondary_key[SECONDARY_KEY_LEN_MAX];

/*
 * This is the runtime filehandle table entry.   Because an fhandle_t is
 * used for both Version 2 and Version 3, we don't need two different types
 * of entries in the table.
 */
typedef struct fhlist_ent {
	fhandle_t fh;		/* filehandle for this component */
	time32_t mtime;		/* modification time of entry */
	time32_t atime;		/* access time of entry */
	fhandle_t dfh;		/* parent filehandle for this component */
	ushort_t flags;
	short	reclen;		/* length of record */
	char	name[MAXPATHLEN];	/* variable record */
} fhlist_ent;

/* flags values */
#define	EXPORT_POINT	0x01	/* if this is export point */
#define	NAME_DELETED	0x02	/* is the dir info still valid for this fh? */
#define	PUBLIC_PATH	0x04	/* is the dir info still valid for this fh? */

/*
 * Information maintained for the secondary key
 * Note that this is a variable length record with 4 variable size fields:
 *	fhkey	- primary key (must be there)
 *	name	- component name (must be there)
 *	next	- next link in list (could be null)
 *	prev	- previous link in list (could be null)
 */
#define	MAX_LINK_VARBUF		(3 * SECONDARY_KEY_LEN_MAX)

typedef struct linkinfo_ent {
	fhandle_t dfh;		/* directory filehandle */
	time32_t mtime;		/* modification time of entry */
	time32_t atime;		/* access time of entry */
	ushort_t flags;
	short	reclen;		/* Actual record length */
	short	fhkey_offset;	/* offset of fhkey, from head of record */
	short	name_offset;	/* offset of name */
	short	next_offset;	/* offset of next link key */
	short	prev_offset;	/* offset of prev link key */
	char	varbuf[MAX_LINK_VARBUF]; /* max size for above */
} linkinfo_ent;

/* Macros for lengths of the various fields */
#define	LN_FHKEY_LEN(link)	((link)->name_offset - (link)->fhkey_offset)

#define	LN_NAME_LEN(link)	((link)->next_offset - (link)->name_offset)

#define	LN_NEXT_LEN(link)	((link)->prev_offset - (link)->next_offset)

#define	LN_PREV_LEN(link)	((link)->reclen - (link)->prev_offset)

/* Macros for address of the various fields */
#define	LN_FHKEY(link)	(char *)((uintptr_t)(link) + (link)->fhkey_offset)

#define	LN_NAME(link)	(char *)((uintptr_t)(link) + (link)->name_offset)

#define	LN_NEXT(link)	(char *)((uintptr_t)(link) + (link)->next_offset)

#define	LN_PREV(link)	(char *)((uintptr_t)(link) + (link)->prev_offset)

/* Which record can reside in database */
typedef union {
	fhlist_ent	fhlist_rec;
	linkinfo_ent	link_rec;
} db_record;

void debug_opaque_print(FILE *, void *buf, int size);
int db_add(char *fhpath, fhandle_t *dfh, char *name, fhandle_t *fh,
	uint_t flags);
fhlist_ent *db_lookup(char *fhpath, fhandle_t *fh, fhlist_ent *fhrecp,
	int *errorp);
fhlist_ent *db_lookup_link(char *fhpath, fhandle_t *dfh, char *name,
	fhlist_ent *fhrecp, int *errorp);
int db_delete(char *fhpath, fhandle_t *fh);
int db_delete_link(char *fhpath, fhandle_t *dfh, char *name);
int db_rename_link(char *fhpath, fhandle_t *from_dfh, char *from_name,
	fhandle_t *to_dfh, char *to_name);
void db_print_all_keys(char *fhpath, fsid_t *fsidp, FILE *fp);

char *nfslog_get_path(fhandle_t *fh, char *name, char *fhpath, char *prtstr);

extern fhandle_t	public_fh;

/*
 * Macro to determine which fhandle to use - input or public fh
 */
#define	NFSLOG_GET_FHANDLE2(fh)						\
	(((fh)->fh_len > 0) ? fh : &public_fh)

/*
 * Macro to determine which fhandle to use - input or public fh
 */
#define	NFSLOG_GET_FHANDLE3(fh3)					\
	(((fh3)->fh3_length == sizeof (fhandle_t)) ?			\
		(fhandle_t *)&(fh3)->fh3_u.data : &public_fh)

#ifdef __cplusplus
}
#endif

#endif /* _FHTAB_H */
