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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Code to maintain the runtime and on-disk filehandle mapping table for
 * nfslog.
 */

#include <assert.h>
#include <errno.h>
#include <nfs/nfs.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <libintl.h>
#include <unistd.h>
#include <nfs/nfs.h>
#include <nfs/nfs_log.h>
#include "fhtab.h"
#include "nfslogd.h"

#define	ROUNDUP32(val)		(((val) + 3) & ~3)

#define	IS_DOT_FILENAME(name)						\
	((strcmp(name, ".") == 0) || (strcmp(name, "..") == 0))

#define	PRINT_LINK_DATA(fp, func, dfh, name, str)			\
	(void) fprintf(fp, "%s: name '%s', dfh ",			\
		func, (((name) != NULL) ? name : ""));			\
	debug_opaque_print(fp, dfh, sizeof (*(dfh)));			\
	(void) fprintf(fp, "%s\n", str);


#define	PRINT_FULL_DATA(fp, func, dfh, fh, name, str)			\
	(void) fprintf(fp, "%s: name '%s', dfh ",			\
		func, (((name) != NULL) ? name : ""));			\
	debug_opaque_print(fp, dfh, sizeof (*(dfh)));			\
	if ((fh) != NULL) {						\
		(void) fprintf(fp, ", fh ");				\
		debug_opaque_print(fp, fh, sizeof (*(fh)));		\
	}								\
	(void) fprintf(fp, "%s\n", str);

/*
 * export handle cache
 */
struct export_handle_cache {
	fhandle_t			fh;
	char				*name;
	struct export_handle_cache	*next;
};

static struct export_handle_cache	*exp_handle_cache = NULL;

extern bool_t nfsl_prin_fh;

static int	fh_add(char *, fhandle_t *, fhandle_t *, char *);

static char *get_export_path(fhandle_t *, char *);
static void sprint_fid(char *, uint_t, const fhandle_t *);
static void fh_print_all_keys(char *fhpath, fhandle_t *fh);
static int fh_compare(fhandle_t *fh1, fhandle_t *fh2);
static fhlist_ent *fh_lookup(char *fhpath, fhandle_t *fh, fhlist_ent *fhrecp,
	int *errorp);
static int fh_remove_mc_link(char *fhpath, fhandle_t *dfh, char *name,
	char **pathp);
static int fh_remove(char *fhpath, fhandle_t *dfh, char *name, char **pathp);
static int fh_rename(char *fhpath, fhandle_t *from_dfh, char *from_name,
	char **from_pathp, fhandle_t *to_dfh, char *to_name);

static fhlist_ent *fh_lookup_link(char *fhpath, fhandle_t *dfh, fhandle_t *fh,
	char *name, fhlist_ent *fhrecp, int *errorp);
static struct nfsl_fh_proc_disp *nfslog_find_fh_dispatch(
	nfslog_request_record *);
static struct export_handle_cache *find_fh_in_export_cache(fhandle_t *fh);
static void add_fh_to_export_cache(fhandle_t *fh, char *path);
static char *update_export_point(char *fhpath, fhandle_t *fh, char *path);
static char *fh_print_absolute(char *fhpath, fhandle_t *fh, char *name);
static void nfslog_null_fhargs(caddr_t *nfsl_args, caddr_t *nfsl_res,
	char *fhpath, char **pathp1, char **pathp2);
static void nfslog_LOOKUP_calc(fhandle_t *dfh, char *name, fhandle_t *fh,
	char *fhpath, char **pathp1, char **pathp2, char *str);

/*
 * NFS VERSION 2
 */

/*
 * Functions for updating the fhtable for fhtoppath and for returning
 * the absolute pathname
 */
static void nfslog_GETATTR2_fhargs(fhandle_t *,
	nfsstat *, char *fhpath, char **, char **);
static void nfslog_SETATTR2_fhargs(nfslog_setattrargs *, nfsstat *,
	char *, char **, char **);
static void nfslog_LOOKUP2_fhargs(nfslog_diropargs *, nfslog_diropres *,
	char *, char **, char **);
static void nfslog_READLINK2_fhargs(fhandle_t *, nfslog_rdlnres *,
	char *, char **, char **);
static void nfslog_READ2_fhargs(nfslog_nfsreadargs *, nfslog_rdresult *,
	char *, char **, char **);
static void nfslog_WRITE2_fhargs(nfslog_writeargs *, nfslog_writeresult *,
	char *, char **, char **);
static void nfslog_CREATE2_fhargs(nfslog_createargs *, nfslog_diropres*,
	char *, char **, char **);
static void nfslog_REMOVE2_fhargs(nfslog_diropargs *, nfsstat *,
	char *, char **, char **);
static void nfslog_RENAME2_fhargs(nfslog_rnmargs *, nfsstat *,
	char *, char **, char **);
static void nfslog_LINK2_fhargs(nfslog_linkargs *, nfsstat *,
	char *, char **, char **);
static void nfslog_SYMLINK2_fhargs(nfslog_symlinkargs *, nfsstat *,
	char *, char **, char **);
static void nfslog_READDIR2_fhargs(nfslog_rddirargs *, nfslog_rddirres *,
	char *, char **, char **);
static void nfslog_STATFS2_fhargs(fhandle_t *, nfsstat *,
	char *, char **, char **);

/*
 * NFS VERSION 3
 *
 * Functions for updating the fhtable for fhtoppath
 */
static void nfslog_GETATTR3_fhargs(nfs_fh3 *, nfsstat3 *,
	char *, char **, char **);
static void nfslog_SETATTR3_fhargs(nfslog_SETATTR3args *,	nfsstat3 *,
	char *, char **, char **);
static void nfslog_LOOKUP3_fhargs(nfslog_diropargs3 *, nfslog_LOOKUP3res *,
	char *, char **, char **);
static void nfslog_ACCESS3_fhargs(nfs_fh3 *, nfsstat3 *,
	char *, char **, char **);
static void nfslog_READLINK3_fhargs(nfs_fh3 *, nfslog_READLINK3res *,
	char *, char **, char **);
static void nfslog_READ3_fhargs(nfslog_READ3args *, nfslog_READ3res *,
	char *, char **, char **);
static void nfslog_WRITE3_fhargs(nfslog_WRITE3args *, nfslog_WRITE3res *,
	char *, char **, char **);
static void nfslog_CREATE3_fhargs(nfslog_CREATE3args *, nfslog_CREATE3res *,
	char *, char **, char **);
static void nfslog_MKDIR3_fhargs(nfslog_MKDIR3args *, nfslog_MKDIR3res *,
	char *, char **, char **);
static void nfslog_SYMLINK3_fhargs(nfslog_SYMLINK3args *, nfslog_SYMLINK3res *,
	char *, char **, char **);
static void nfslog_MKNOD3_fhargs(nfslog_MKNOD3args *, nfslog_MKNOD3res *,
	char *, char **, char **);
static void nfslog_REMOVE3_fhargs(nfslog_REMOVE3args *, nfsstat3 *,
	char *, char **, char **);
static void nfslog_RMDIR3_fhargs(nfslog_RMDIR3args *, nfsstat3 *,
	char *, char **, char **);
static void nfslog_RENAME3_fhargs(nfslog_RENAME3args *, nfsstat3 *,
	char *, char **, char **);
static void nfslog_LINK3_fhargs(nfslog_LINK3args *, nfsstat3 *,
	char *, char **, char **);
static void nfslog_READDIR3_fhargs(nfs_fh3 *, nfsstat3 *,
	char *, char **, char **);
static void nfslog_READDIRPLUS3_fhargs(nfslog_READDIRPLUS3args *,
	nfslog_READDIRPLUS3res *,
	char *, char **, char **);
static void nfslog_FSSTAT3_fhargs(nfs_fh3 *, nfsstat3 *,
	char *, char **, char **);
static void nfslog_FSINFO3_fhargs(nfs_fh3 *, nfsstat3 *,
	char *, char **, char **);
static void nfslog_PATHCONF3_fhargs(nfs_fh3 *, nfsstat3 *,
	char *, char **, char **);
static void nfslog_COMMIT3_fhargs(nfslog_COMMIT3args *, nfsstat3 *,
	char *, char **, char **);

/*
 * NFSLOG VERSION 1
 *
 * Functions for updating the fhtable for fhtoppath
 */
static void nfslog_SHARE_fhargs(nfslog_sharefsargs *, nfslog_sharefsres *,
	char *, char **, char **);
static void nfslog_UNSHARE_fhargs(nfslog_sharefsargs *, nfslog_sharefsres *,
	char *, char **, char **);
static void nfslog_GETFH_fhargs(nfslog_getfhargs *, nfsstat *,
	char *, char **, char **);

/*
 * Define the actions taken per prog/vers/proc:
 *
 * In some cases, the nl types are the same as the nfs types and a simple
 * bcopy should suffice. Rather that define tens of identical procedures,
 * simply define these to bcopy. Similarly this takes care of different
 * procs that use same parameter struct.
 */

static struct nfsl_fh_proc_disp nfsl_fh_proc_v2[] = {
	/*
	 * NFS VERSION 2
	 */

	/* RFS_NULL = 0 */
	{nfslog_null_fhargs, xdr_void, xdr_void, 0, 0},

	/* RFS_GETATTR = 1 */
	{nfslog_GETATTR2_fhargs, xdr_fhandle, xdr_nfsstat,
		sizeof (fhandle_t), sizeof (nfsstat)},

	/* RFS_SETATTR = 2 */
	{nfslog_SETATTR2_fhargs, xdr_nfslog_setattrargs, xdr_nfsstat,
		sizeof (nfslog_setattrargs), sizeof (nfsstat)},

	/* RFS_ROOT = 3 *** NO LONGER SUPPORTED *** */
	{nfslog_null_fhargs, xdr_void, xdr_void, 0, 0},

	/* RFS_LOOKUP = 4 */
	{nfslog_LOOKUP2_fhargs, xdr_nfslog_diropargs, xdr_nfslog_diropres,
		sizeof (nfslog_diropargs), sizeof (nfslog_diropres)},

	/* RFS_READLINK = 5 */
	{nfslog_READLINK2_fhargs, xdr_fhandle, xdr_nfslog_rdlnres,
		sizeof (fhandle_t), sizeof (nfslog_rdlnres)},

	/* RFS_READ = 6 */
	{nfslog_READ2_fhargs, xdr_nfslog_nfsreadargs, xdr_nfslog_rdresult,
		sizeof (nfslog_nfsreadargs), sizeof (nfslog_rdresult)},

	/* RFS_WRITECACHE = 7 *** NO LONGER SUPPORTED *** */
	{nfslog_null_fhargs, xdr_void, xdr_void, 0, 0},

	/* RFS_WRITE = 8 */
	{nfslog_WRITE2_fhargs, xdr_nfslog_writeargs, xdr_nfslog_writeresult,
		sizeof (nfslog_writeargs), sizeof (nfslog_writeresult)},

	/* RFS_CREATE = 9 */
	{nfslog_CREATE2_fhargs, xdr_nfslog_createargs, xdr_nfslog_diropres,
		sizeof (nfslog_createargs), sizeof (nfslog_diropres)},

	/* RFS_REMOVE = 10 */
	{nfslog_REMOVE2_fhargs, xdr_nfslog_diropargs, xdr_nfsstat,
		sizeof (nfslog_diropargs), sizeof (nfsstat)},

	/* RFS_RENAME = 11 */
	{nfslog_RENAME2_fhargs, xdr_nfslog_rnmargs, xdr_nfsstat,
		sizeof (nfslog_rnmargs), sizeof (nfsstat)},

	/* RFS_LINK = 12 */
	{nfslog_LINK2_fhargs, xdr_nfslog_linkargs, xdr_nfsstat,
		sizeof (nfslog_linkargs), sizeof (nfsstat)},

	/* RFS_SYMLINK = 13 */
	{nfslog_SYMLINK2_fhargs, xdr_nfslog_symlinkargs, xdr_nfsstat,
		sizeof (nfslog_symlinkargs), sizeof (nfsstat)},

	/* RFS_MKDIR = 14 */
	{nfslog_CREATE2_fhargs, xdr_nfslog_createargs, xdr_nfslog_diropres,
		sizeof (nfslog_createargs), sizeof (nfslog_diropres)},

	/* RFS_RMDIR = 15 */
	{nfslog_REMOVE2_fhargs, xdr_nfslog_diropargs, xdr_nfsstat,
		sizeof (nfslog_diropargs), sizeof (nfsstat)},

	/* RFS_READDIR = 16 */
	{nfslog_READDIR2_fhargs, xdr_nfslog_rddirargs, xdr_nfslog_rddirres,
		sizeof (nfslog_rddirargs), sizeof (nfslog_rddirres)},

	/* RFS_STATFS = 17 */
	{nfslog_STATFS2_fhargs, xdr_fhandle, xdr_nfsstat,
		sizeof (fhandle_t), sizeof (nfsstat)},
};


/*
 * NFS VERSION 3
 */

static struct nfsl_fh_proc_disp nfsl_fh_proc_v3[] = {

	/* RFS_NULL = 0 */
	{nfslog_null_fhargs, xdr_void, xdr_void, 0, 0},

	/* RFS3_GETATTR = 1 */
	{nfslog_GETATTR3_fhargs, xdr_nfs_fh3, xdr_nfsstat3,
		sizeof (nfs_fh3), sizeof (nfsstat3)},

	/* RFS3_SETATTR = 2 */
	{nfslog_SETATTR3_fhargs, xdr_nfslog_SETATTR3args, xdr_nfsstat3,
		sizeof (nfslog_SETATTR3args), sizeof (nfsstat3)},

	/* RFS3_LOOKUP = 3 */
	{nfslog_LOOKUP3_fhargs, xdr_nfslog_diropargs3, xdr_nfslog_LOOKUP3res,
		sizeof (nfslog_diropargs3), sizeof (nfslog_LOOKUP3res)},

	/* RFS3_ACCESS = 4 */
	{nfslog_ACCESS3_fhargs, xdr_nfs_fh3, xdr_nfsstat3,
		sizeof (nfs_fh3), sizeof (nfsstat3)},

	/* RFS3_READLINK = 5 */
	{nfslog_READLINK3_fhargs, xdr_nfs_fh3, xdr_nfslog_READLINK3res,
		sizeof (nfs_fh3), sizeof (nfslog_READLINK3res)},

	/* RFS3_READ = 6 */
	{nfslog_READ3_fhargs, xdr_nfslog_READ3args, xdr_nfslog_READ3res,
		sizeof (nfslog_READ3args), sizeof (nfslog_READ3res)},

	/* RFS3_WRITE = 7 */
	{nfslog_WRITE3_fhargs, xdr_nfslog_WRITE3args, xdr_nfslog_WRITE3res,
		sizeof (nfslog_WRITE3args), sizeof (nfslog_WRITE3res)},

	/* RFS3_CREATE = 8 */
	{nfslog_CREATE3_fhargs, xdr_nfslog_CREATE3args, xdr_nfslog_CREATE3res,
		sizeof (nfslog_CREATE3args), sizeof (nfslog_CREATE3res)},

	/* RFS3_MKDIR = 9 */
	{nfslog_MKDIR3_fhargs, xdr_nfslog_MKDIR3args, xdr_nfslog_MKDIR3res,
		sizeof (nfslog_MKDIR3args), sizeof (nfslog_MKDIR3res)},

	/* RFS3_SYMLINK = 10 */
	{nfslog_SYMLINK3_fhargs, xdr_nfslog_SYMLINK3args,
		xdr_nfslog_SYMLINK3res,
		sizeof (nfslog_SYMLINK3args), sizeof (nfslog_SYMLINK3res)},

	/* RFS3_MKNOD = 11 */
	{nfslog_MKNOD3_fhargs, xdr_nfslog_MKNOD3args, xdr_nfslog_MKNOD3res,
		sizeof (nfslog_MKNOD3args), sizeof (nfslog_MKNOD3res)},

	/* RFS3_REMOVE = 12 */
	{nfslog_REMOVE3_fhargs, xdr_nfslog_REMOVE3args, xdr_nfsstat3,
		sizeof (nfslog_REMOVE3args), sizeof (nfsstat3)},

	/* RFS3_RMDIR = 13 */
	{nfslog_RMDIR3_fhargs, xdr_nfslog_RMDIR3args, xdr_nfsstat3,
		sizeof (nfslog_RMDIR3args), sizeof (nfsstat3)},

	/* RFS3_RENAME = 14 */
	{nfslog_RENAME3_fhargs, xdr_nfslog_RENAME3args, xdr_nfsstat3,
		sizeof (nfslog_RENAME3args), sizeof (nfsstat3)},

	/* RFS3_LINK = 15 */
	{nfslog_LINK3_fhargs, xdr_nfslog_LINK3args, xdr_nfsstat3,
		sizeof (nfslog_LINK3args), sizeof (nfsstat3)},

	/* RFS3_READDIR = 16 */
	{nfslog_READDIR3_fhargs, xdr_nfs_fh3, xdr_nfsstat3,
		sizeof (nfs_fh3), sizeof (nfsstat3)},

	/* RFS3_READDIRPLUS = 17 */
	{nfslog_READDIRPLUS3_fhargs,
		xdr_nfslog_READDIRPLUS3args, xdr_nfslog_READDIRPLUS3res,
		sizeof (nfslog_READDIRPLUS3args),
		sizeof (nfslog_READDIRPLUS3res)},

	/* RFS3_FSSTAT = 18 */
	{nfslog_FSSTAT3_fhargs, xdr_nfs_fh3, xdr_nfsstat3,
		sizeof (nfs_fh3), sizeof (nfsstat3)},

	/* RFS3_FSINFO = 19 */
	{nfslog_FSINFO3_fhargs, xdr_nfs_fh3, xdr_nfsstat3,
		sizeof (nfs_fh3), sizeof (nfsstat3)},

	/* RFS3_PATHCONF = 20 */
	{nfslog_PATHCONF3_fhargs, xdr_nfs_fh3, xdr_nfsstat3,
		sizeof (nfs_fh3), sizeof (nfsstat3)},

	/* RFS3_COMMIT = 21 */
	{nfslog_COMMIT3_fhargs, xdr_nfslog_COMMIT3args, xdr_nfsstat3,
		sizeof (nfslog_COMMIT3args), sizeof (nfsstat3)},
};

/*
 * NFSLOG VERSION 1
 */

static struct nfsl_fh_proc_disp nfsl_log_fh_proc_v1[] = {

	/* NFSLOG_NULL = 0 */
	{nfslog_null_fhargs, xdr_void, xdr_void, 0, 0},

	/* NFSLOG_SHARE = 1 */
	{nfslog_SHARE_fhargs, xdr_nfslog_sharefsargs, xdr_nfslog_sharefsres,
		sizeof (nfslog_sharefsargs), sizeof (nfslog_sharefsres)},

	/* NFSLOG_UNSHARE = 2 */
	{nfslog_UNSHARE_fhargs, xdr_nfslog_sharefsargs, xdr_nfslog_sharefsres,
		sizeof (nfslog_sharefsargs), sizeof (nfslog_sharefsres)},

	/* NFSLOG_LOOKUP3 = 3 */
	{nfslog_LOOKUP3_fhargs, xdr_nfslog_diropargs3, xdr_nfslog_LOOKUP3res,
		sizeof (nfslog_diropargs3), sizeof (nfslog_LOOKUP3res)},

	/* NFSLOG_GETFH = 4 */
	{nfslog_GETFH_fhargs, xdr_nfslog_getfhargs, xdr_nfsstat,
		sizeof (nfslog_getfhargs), sizeof (nfsstat)},
};

static struct nfsl_fh_vers_disp nfsl_fh_vers_disptable[] = {
	{sizeof (nfsl_fh_proc_v2) / sizeof (nfsl_fh_proc_v2[0]),
	    nfsl_fh_proc_v2},
	{sizeof (nfsl_fh_proc_v3) / sizeof (nfsl_fh_proc_v3[0]),
	    nfsl_fh_proc_v3},
};

static struct nfsl_fh_vers_disp nfsl_log_fh_vers_disptable[] = {
	{sizeof (nfsl_log_fh_proc_v1) / sizeof (nfsl_log_fh_proc_v1[0]),
	    nfsl_log_fh_proc_v1},
};

static struct nfsl_fh_prog_disp nfsl_fh_dispatch_table[] = {
	{NFS_PROGRAM,
	    NFS_VERSMIN,
	    sizeof (nfsl_fh_vers_disptable) /
		sizeof (nfsl_fh_vers_disptable[0]),
	    nfsl_fh_vers_disptable},
	{NFSLOG_PROGRAM,
	    NFSLOG_VERSMIN,
	    sizeof (nfsl_log_fh_vers_disptable) /
		sizeof (nfsl_log_fh_vers_disptable[0]),
	    nfsl_log_fh_vers_disptable},
};

static int	nfsl_fh_dispatch_table_arglen =
			sizeof (nfsl_fh_dispatch_table) /
			sizeof (nfsl_fh_dispatch_table[0]);

extern int debug;

/*
 * print the fid into the given string as a series of hex digits.
 * XXX Ideally, we'd like to just convert the filehandle into an i-number,
 * but the fid encoding is a little tricky (see nfs_fhtovp() and
 * ufs_vget()) and may be private to UFS.
 */

static void
sprint_fid(char *buf, uint_t buflen, const fhandle_t *fh)
{
	int i;
	uchar_t byte;
	uint_t fhlen;

	/*
	 * If the filehandle somehow got corrupted, only print the part
	 * that makes sense.
	 */
	if (fh->fh_len > NFS_FHMAXDATA)
		fhlen = NFS_FHMAXDATA;
	else
		fhlen = fh->fh_len;
	assert(2 * fhlen < buflen);

	for (i = 0; i < fhlen; i++) {
		byte = fh->fh_data[i];
		(void) sprintf(buf + 2 * i, "%02x", byte);
	}
}

static void
fh_print_all_keys(char *fhpath, fhandle_t *fh)
{
	if ((fhpath == NULL) || (fh == NULL) || (debug <= 1))
		return;
	(void) printf("\nBegin all database keys\n");
	db_print_all_keys(fhpath, &fh->fh_fsid, stdout);
	(void) printf("\nEnd   all database keys\n");
}

#define	FH_ADD(path, dfh, fh, name) \
	fh_add(path, dfh, fh, name)

/*
 * Add the filehandle "fh", which has the name "name" and lives in
 * directory "dfh", to the table "fhlist".  "fhlist" will be updated if the
 * entry is added to the front of the list.
 * Return 0 for success, error code otherwise.
 */
static int
fh_add(char *fhpath, fhandle_t *dfh, fhandle_t *fh, char *name)
{
	uint_t	flags = 0;
	int	error;

	if (IS_DOT_FILENAME(name)) {
		/* we don't insert these to the database but not an error */
		if (debug > 3) {
			PRINT_FULL_DATA(stdout, "fh_add", dfh, fh, name,
				" - no dot files")
		}
		return (0);
	}
	if (dfh && (memcmp(fh, dfh, NFS_FHSIZE) == 0)) {
		flags |= EXPORT_POINT;
	}

	/* Add to database */
	error = db_add(fhpath, dfh, name, fh, flags);
	if (debug > 1) {
		if (error != 0) {
			(void) printf("db_add error %s:\n",
				((error >= 0) ? strerror(error) : "Unknown"));
			PRINT_FULL_DATA(stdout, "fh_add", dfh, fh, name, "")
		} else if (debug > 2) {
			PRINT_FULL_DATA(stdout, "fh_add", dfh, fh, name, "")
		}
	}
	return (error);
}

/*
 * fh_compare returns 0 if the file handles match, error code otherwise
 */
static int
fh_compare(fhandle_t *fh1, fhandle_t *fh2)
{
	if (memcmp(fh1, fh2, NFS_FHSIZE))
		return (errno);
	else
		return (0);
}

/*
 * Try to find the filehandle "fh" in the table.  Returns 0 and the
 * corresponding table entry if found, error otherwise.
 * If successfull and fhrecpp is non-null then *fhrecpp points to the
 * returned record. If *fhrecpp was initially null, that record had
 * been malloc'd and must be freed by caller.
 */

static fhlist_ent *
fh_lookup(char *fhpath, fhandle_t *fh, fhlist_ent *fhrecp, int *errorp)
{
	if (debug > 3) {
		(void) printf("fh_lookup: fh ");
		debug_opaque_print(stdout, fh, sizeof (*fh));
		(void) printf("\n");
	}
	return (db_lookup(fhpath, fh, fhrecp, errorp));
}

/*
 * Remove the mc link if exists when removing a regular link.
 * Return 0 for success, error code otherwise.
 */
static int
fh_remove_mc_link(char *fhpath, fhandle_t *dfh, char *name, char **pathp)
{
	int	error;
	char	*str, *str1;

	/* Delete the multi-component path if exists */
	if ((pathp == NULL) || (*pathp == NULL)) {
		str = nfslog_get_path(dfh, name, fhpath, "remove_mc_link");
		str1 = str;
	} else {
		str = *pathp;
		str1 = NULL;
	}
	error = db_delete_link(fhpath, &public_fh, str);
	if (str1 != NULL)
		free(str1);
	return (error);
}

/*
 * Remove the link entry from the fh table.
 * Return 0 for success, error code otherwise.
 */
static int
fh_remove(char *fhpath, fhandle_t *dfh, char *name, char **pathp)
{
	/*
	 * disconnect element from list
	 *
	 * Remove the link entry for the file. Remove fh entry if last link.
	 */
	if (IS_DOT_FILENAME(name)) {
		/* we don't insert these to the database but not an error */
		if (debug > 2) {
			PRINT_LINK_DATA(stdout, "fh_remove", dfh, name,
				" - no dot files")
		}
		return (0);
	}
	if (debug > 2) {
		PRINT_LINK_DATA(stdout, "fh_remove", dfh, name, "")
	}
	/* Delete the multi-component path if exists */
	(void) fh_remove_mc_link(fhpath, dfh, name, pathp);
	return (db_delete_link(fhpath, dfh, name));
}

/*
 * fh_rename - renames a link in the database (adds the new one if from link
 * did not exist).
 * Return 0 for success, error code otherwise.
 */
static int
fh_rename(char *fhpath, fhandle_t *from_dfh, char *from_name, char **from_pathp,
	fhandle_t *to_dfh, char *to_name)
{
	if (debug > 2) {
		PRINT_LINK_DATA(stdout, "fh_rename: from:", from_dfh,
		    from_name, "")
		PRINT_LINK_DATA(stdout, "fh_rename: to  :", to_dfh,
		    to_name, "")
	}
	/*
	 * if any of these are dot files (should not happen), the rename
	 * becomes a "delete" or "add" operation because the dot files
	 * don't get in the database
	 */
	if (IS_DOT_FILENAME(to_name)) {
		/* it is just a delete op */
		if (debug > 2) {
			(void) printf("to: no dot files\nDelete from: '%s'\n",
				from_name);
		}
		return (fh_remove(fhpath, from_dfh, from_name, from_pathp));
	} else if (IS_DOT_FILENAME(from_name)) {
		/* we don't insert these to the database */
		if (debug > 2) {
			(void) printf("rename - from: no dot files\n");
		}
		/* can't insert the target, because don't have a handle */
		return (EINVAL);
	}
	/* Delete the multi-component path if exists */
	(void) fh_remove_mc_link(fhpath, from_dfh, from_name, from_pathp);
	return (db_rename_link(fhpath, from_dfh, from_name, to_dfh, to_name));
}

/*
 * fh_lookup_link - search the fhtable for the link defined by (dfh,name,fh).
 * Return 0 and set *fhrecpp to the fhlist item corresponding to it if found,
 * or error if not found.
 * Possible configurations:
 * 1. dfh, fh, name are all non-null: Only exact match accepted.
 * 2. dfh,name non-null, fh null: return first match found.
 * 3. fh,name non-null, dfh null: return first match found.
 * 3. fh non-null, dfh, name null: return first match found.
 * If successfull and fhrecpp is non-null then *fhrecpp points to the
 * returned record. If *fhrecpp was initially null, that record had
 * been malloc'd and must be freed by caller.
 */
static fhlist_ent *
fh_lookup_link(char *fhpath, fhandle_t *dfh, fhandle_t *fh, char *name,
	fhlist_ent *fhrecp, int *errorp)
{
	fhlist_ent	*in_fhrecp = fhrecp;

	if ((name != NULL) && IS_DOT_FILENAME(name)) {
		/* we don't insert these to the database but not an error */
		if (debug > 2) {
			PRINT_FULL_DATA(stdout, "fh_lookup_link", dfh, fh, name,
				" - no dot files\n")
		}
		*errorp = 0;
		return (NULL);
	}
	if (debug > 3) {
		PRINT_FULL_DATA(stdout, "fh_lookup_link", dfh, fh, name, "")
	}
	/* Add to database */
	if (fh != NULL) {
		fhrecp = db_lookup(fhpath, fh, fhrecp, errorp);
		if (fhrecp == NULL) {
			if (debug > 3)
				(void) printf("fh_lookup_link: fh not found\n");
			return (NULL);
		}
		/* Check if name and dfh match, if not search link */
		if (((dfh == NULL) || !fh_compare(dfh, &fhrecp->dfh)) &&
		    ((name == NULL) || (strcmp(name, fhrecp->name) == 0))) {
			/* found it */
			goto exit;
		}
		/* Found the primary record, but it's a different link */
		if (debug == 3) {	/* Only log if >2 but already printed */
			PRINT_FULL_DATA(stdout, "fh_lookup_link", dfh, fh,
				name, "")
		}
		if (debug > 2) {
			PRINT_LINK_DATA(stdout, "Different primary link",
				&fhrecp->dfh, fhrecp->name, "")
		}
		/* can now free the record unless it was supplied by caller */
		if (fhrecp != in_fhrecp) {
			free(fhrecp);
			fhrecp = NULL;
		}
	}
	/* If here, we must search by link */
	if ((dfh == NULL) || (name == NULL)) {
		if (debug > 2)
			(void) printf("fh_lookup_link: invalid params\n");
		*errorp = EINVAL;
		return (NULL);
	}
	fhrecp = db_lookup_link(fhpath, dfh, name, fhrecp, errorp);
	if (fhrecp == NULL) {
		if (debug > 3)
			(void) printf("fh_lookup_link: link not found: %s\n",
			    ((*errorp >= 0) ? strerror(*errorp) : "Unknown"));
		return (NULL);
	}
	/* If all args supplied, check if an exact match */
	if ((fh != NULL) && fh_compare(fh, &fhrecp->fh)) {
		if (debug > 2) {
			PRINT_FULL_DATA(stderr, "fh_lookup_link", dfh, fh,
				name, "")
			PRINT_LINK_DATA(stderr, "Different primary link",
			    &fhrecp->dfh, fhrecp->name, "")
		}
		if (fhrecp != in_fhrecp)
			free(fhrecp);
		*errorp = EINVAL;
		return (NULL);
	}
exit:
	if (debug > 3)
		(void) printf("lookup: found '%s' in fhtable\n", name);
	*errorp = 0;
	return (fhrecp);
}

/*
 * Export handle cache is maintained if we see an export handle that either
 * cannot have the path for it determined, or we failed store it.
 * Usually the path of an export handle can be identified in the NFSLOGTAB
 * and since every path for that filesystem will be affected, it's worth
 * caching the ones we had problem identifying.
 */

/*
 * find_fh_in_export_cache - given an export fh, find it in the cache and
 * return the handle
 */
static struct export_handle_cache *
find_fh_in_export_cache(fhandle_t *fh)
{
	struct export_handle_cache	*p;

	for (p = exp_handle_cache; p != NULL; p = p->next) {
		if (memcmp(fh, &p->fh, sizeof (*fh)) == 0)
			break;
	}
	return (p);
}

static void
add_fh_to_export_cache(fhandle_t *fh, char *path)
{
	struct export_handle_cache	*new;

	if ((new = malloc(sizeof (*new))) == NULL) {
		syslog(LOG_ERR, gettext(
		"add_fh_to_export_cache: alloc new for '%s' Error %s\n"),
			((path != NULL) ? path : ""), strerror(errno));
		return;
	}
	if (path != NULL) {
		if ((new->name = malloc(strlen(path) + 1)) == NULL) {
			syslog(LOG_ERR, gettext(
				"add_fh_to_export_cache: alloc '%s'"
				    " Error %s\n"), path, strerror(errno));
			free(new);
			return;
		}
		(void) strcpy(new->name, path);
	} else {
		new->name = NULL;
	}
	(void) memcpy(&new->fh, fh, sizeof (*fh));
	new->next = exp_handle_cache;
	exp_handle_cache = new;
}

/*
 * update_export_point - called when the path for fh cannot be determined.
 * In the past it called get_export_path() to get the name of the
 * export point given a filehandle. This was a hack, since there's no
 * reason why the filehandle should be lost.
 *
 * If a match is found, insert the path to the database.
 * Return the inserted fhrecp is found,
 * and NULL if not. If it is an exported fs but not in the list, log a
 * error.
 * If input fhrecp is non-null, it is a valid address for result,
 * otherwise malloc it.
 */
static char *
update_export_point(char *fhpath, fhandle_t *fh, char *path)
{
	struct export_handle_cache	*p;

	if ((fh == NULL) || memcmp(&fh->fh_data, &fh->fh_xdata, fh->fh_len)) {
		/* either null fh or not the root of a shared directory */
		return (NULL);
	}
	/* Did we already see (and fail) this one? */
	if ((p = find_fh_in_export_cache(fh)) != NULL) {
		/* Found it! */
		if (debug > 2) {
			PRINT_LINK_DATA(stdout, "update_export_point",
				fh, ((p->name != NULL) ? p->name : ""), "");
		}
		if (p->name == NULL)
			return (NULL);
		/*
		 * We should not normally be here - only add to cache if
		 * fh_add failed.
		 */
		if ((path == NULL) &&
		    ((path = malloc(strlen(p->name) + 1)) == NULL)) {
			syslog(LOG_ERR, gettext(
				"update_export_point: malloc '%s' Error %s"),
				    p->name, strerror(errno));
			return (NULL);
		}
		(void) strcpy(path, p->name);
		return (path);
	}
	if ((path = get_export_path(fh, path)) == NULL) {
		add_fh_to_export_cache(fh, NULL);
		return (NULL);
	}
	/* Found it! */
	if (debug > 2) {
		PRINT_LINK_DATA(stdout, "update_export_point", fh, path, "")
	}
	if (FH_ADD(fhpath, fh, fh, path)) {
		/* cache this handle so we don't repeat the search */
		add_fh_to_export_cache(fh, path);
	}
	return (path);
}

/*
 * HACK!!! To get rid of get_export_path() use
 */
/* ARGSUSED */
static char *
get_export_path(fhandle_t *fh, char *path)
{
	return (NULL);
}

/*
 * Return the absolute pathname for the filehandle "fh", using the mapping
 * table "fhlist".  The caller must free the return string.
 * name is an optional dir component name, to be appended at the end
 * (if name is non-null, the function assumes the fh is the parent directory)
 *
 * Note: The original code was recursive, which was much more elegant but
 * ran out of stack...
 */

static char *
fh_print_absolute(char *fhpath, fhandle_t *fh, char *name)
{
	char		*str, *rootname, parent[MAXPATHLEN];
	int		i, j, k, len, error;
	fhlist_ent	fhrec, *fhrecp;
	fhandle_t	prevfh;
	int		namelen;

	if (debug > 3)
		(void) printf("fh_print_absolute: input name '%s'\n",
			((name != NULL) ? name : ""));
	/* If name starts with '/' we are done */
	if ((name != NULL) && (name[0] == '/')) {
		if ((str = strdup(name)) == NULL) {
			syslog(LOG_ERR, gettext(
				"fh_print_absolute: strdup '%s' error %s\n"),
				name, strerror(errno));
		}
		return (str);
	}
	namelen = ((name != NULL) ? strlen(name) + 2 : 0);
	parent[0] = '\0';

	/* remember the last filehandle we've seen */
	(void) memcpy((void *) &prevfh, (void *) fh, sizeof (*fh));
	fh = &prevfh;

	/* dump all names in reverse order */
	while ((fhrecp = fh_lookup(fhpath, fh, &fhrec, &error)) != NULL &&
		!(fhrecp->flags & (EXPORT_POINT | PUBLIC_PATH))) {

		if (debug > 3) {
			(void) printf("fh_print_absolute: name '%s'%s\n",
				fhrecp->name,
				((fhrecp->flags & EXPORT_POINT) ? "root" : ""));
		}
		if (memcmp(&prevfh, &fhrecp->dfh, sizeof (*fh)) == 0) {
			/* dfh == prevfh but not an export point */
			if (debug > 1) {
				(void) printf(
					"fh_print_absolute: fhrec loop:\n");
					debug_opaque_print(stdout, fhrecp,
					fhrecp->reclen);
			}
			break;
		}
		(void) strcat(parent, "/");
		(void) strcat(parent, fhrecp->name);

		/* remember the last filehandle we've seen */
		(void) memcpy(&prevfh, &fhrecp->dfh, sizeof (fhrecp->dfh));
	}
	assert(fh == &prevfh);

	if (fhrecp != NULL) {
		rootname = fhrecp->name;
	} else {
		/* Check if export point, just in case... */
		/* There should be enough room in parent, leave the '\0' */
		rootname = update_export_point(
				fhpath, fh, &parent[strlen(parent) + 1]);
	}
	/* Now need to reverse the order */
	if (rootname != NULL) {	/* *fhrecp is the export point */
		len = strlen(rootname) + 2;
	} else {
		len = 2 * (NFS_FHMAXDATA + fh->fh_len);	/* fid instead */
	}
	len = ROUNDUP32(len + namelen + strlen(parent));
	if ((str = malloc(len)) == NULL) {
		syslog(LOG_ERR, gettext(
			"fh_print_absolute: malloc %d error %s\n"),
			    len, strerror(errno));
		return (NULL);
	}
	/* first put the export point path in */
	if (rootname != NULL) {	/* *fhrecp is the export point */
		(void) strcpy(str, rootname);
	} else {
		sprint_fid(str, len, fh);
	}
	for (k = strlen(str), i = strlen(parent); (k < len) && (i >= 0); i--) {
		for (j = i; (j >= 0) && (parent[j] != '/'); j--);
		if (j < 0)
			break;
		(void) strcpy(&str[k], &parent[j]);
		k += strlen(&str[k]);
		parent[j] = '\0';
	}
	if ((name != NULL) && ((k + namelen) <= len)) {
		str[k] = '/';
		(void) strcpy(&str[k + 1], name);
	}
	if (debug > 3)
		(void) printf("fh_print_absolute: path '%s'\n", str);
	return (str);
}

/*
 * nfslog_find_fh_dispatch - get the dispatch struct for this request
 */
static struct nfsl_fh_proc_disp *
nfslog_find_fh_dispatch(nfslog_request_record *logrec)
{
	nfslog_record_header		*logrechdr = &logrec->re_header;
	struct nfsl_fh_prog_disp	*progtable;	/* prog struct */
	struct nfsl_fh_vers_disp	*verstable;	/* version struct */
	int				i, vers;

	/* Find prog element - search because can't use prog as array index */
	for (i = 0; (i < nfsl_fh_dispatch_table_arglen) &&
	    (logrechdr->rh_prognum != nfsl_fh_dispatch_table[i].nfsl_dis_prog);
		i++);
	if (i >= nfsl_fh_dispatch_table_arglen) {	/* program not logged */
		/* not an error */
		return (NULL);
	}
	progtable = &nfsl_fh_dispatch_table[i];
	/* Find vers element - no validity check - if here it's valid vers */
	vers = logrechdr->rh_version - progtable->nfsl_dis_versmin;
	verstable = &progtable->nfsl_dis_vers_table[vers];
	/* Find proc element - no validity check - if here it's valid proc */
	return (&verstable->nfsl_dis_proc_table[logrechdr->rh_procnum]);
}

/* ARGSUSED */
static void
nfslog_null_fhargs(caddr_t *nfsl_args, caddr_t *nfsl_res,
	char *fhpath, char **pathp1, char **pathp2)
{
	*pathp1 = NULL;
	*pathp2 = NULL;
}

/*
 * nfslog_LOOKUP_calc - called by both lookup3 and lookup2. Handles the
 * mclookup as well as normal lookups.
 */
/* ARGSUSED */
static void
nfslog_LOOKUP_calc(fhandle_t *dfh, char *name, fhandle_t *fh,
	char *fhpath, char **pathp1, char **pathp2, char *str)
{
	int		error;
	fhlist_ent	fhrec;
	char		*name1 = NULL;

	if (fh == &public_fh) {
		/* a fake lookup to inform us of the public fs path */
		if (error = FH_ADD(fhpath, fh, fh, name)) {
			syslog(LOG_ERR, gettext(
				"%s: Add Public fs '%s' failed: %s\n"),
				str, name,
				((error >= 0) ? strerror(error) : "Unknown"));
		}
		if (pathp1 != NULL) {
			*pathp1 = nfslog_get_path(dfh, NULL, fhpath, str);
			*pathp2 = NULL;
		}
		return;
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(dfh, name, fhpath, str);
		*pathp2 = NULL;
	}

	/* If public fh mclookup, then insert complete path */
	if (dfh == &public_fh) {
		if (pathp1 != NULL) {
			name = *pathp1;
		} else {
			name = nfslog_get_path(dfh, name, fhpath, str);
			name1 = name;
		}
	}
	if (fh_lookup_link(fhpath, dfh, fh, name, &fhrec, &error) != NULL) {
		/* link already in table */
		if (name1 != NULL)
			free(name1);
		return;
	}
	/* A new link so add it */
	if (error = FH_ADD(fhpath, dfh, fh, name)) {
		syslog(LOG_ERR, gettext(
			"%s: Add fh for '%s' failed: %s\n"), str,
			    name, ((error >= 0) ? strerror(error) : "Unknown"));
	}
	if (name1 != NULL)
		free(name1);
}

/*
 * NFS VERSION 2
 */

/* Functions for updating the fhtable for fhtoppath */

/*
 * nfslog_GETATTR2_fhargs - updates path1 but no fhtable changes
 */
/* ARGSUSED */
static void
nfslog_GETATTR2_fhargs(fhandle_t *args, nfsstat *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	if (debug > 2) {
		(void) printf("=============\nGETATTR2: fh ");
		debug_opaque_print(stdout, args, sizeof (*args));
		(void) printf("\n");
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(NFSLOG_GET_FHANDLE2(args),
				NULL, fhpath, "getattr2");
		*pathp2 = NULL;
	}
}

/*
 * nfslog_SETATTR2_fhargs - updates path1 but no fhtable changes
 */
/* ARGSUSED */
static void
nfslog_SETATTR2_fhargs(nfslog_setattrargs *args, nfsstat *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	if (debug > 2) {
		(void) printf("=============\nSETATTR2: fh ");
		debug_opaque_print(stdout, &args->saa_fh,
			sizeof (args->saa_fh));
		(void) printf("\n");
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(NFSLOG_GET_FHANDLE2(&args->saa_fh),
				NULL, fhpath, "setattr2");
		*pathp2 = NULL;
	}
}

/*
 * nfslog_LOOKUP2_fhargs - search the table to ensure we have not added this
 * one already. Note that if the response status was anything but okay,
 * there is no fh to check...
 */
/* ARGSUSED */
static void
nfslog_LOOKUP2_fhargs(nfslog_diropargs *args, nfslog_diropres *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	char		*name;
	fhandle_t	*dfh, *fh;

	dfh = &args->da_fhandle;
	name = args->da_name;
	if (debug > 2) {
		if (res->dr_status == NFS_OK)
			fh = &res->nfslog_diropres_u.dr_ok.drok_fhandle;
		else
			fh = NULL;
		PRINT_FULL_DATA(stdout, "=============\nLOOKUP2",
			dfh, fh, name, "")
		if (res->dr_status !=  NFS_OK)
			(void) printf("status %d\n", res->dr_status);
	}
	dfh = NFSLOG_GET_FHANDLE2(dfh);
	if ((dfh == &public_fh) && (name[0] == '\x80')) {
		/* special mclookup */
		name = &name[1];
	}
	if (res->dr_status != NFS_OK) {
		if (pathp1 != NULL) {
			*pathp1 = nfslog_get_path(dfh, name, fhpath, "lookup2");
			*pathp2 = NULL;
		}
		return;
	}
	fh = NFSLOG_GET_FHANDLE2(&res->nfslog_diropres_u.dr_ok.drok_fhandle);
	nfslog_LOOKUP_calc(dfh, name, fh, fhpath, pathp1, pathp2, "Lookup2");
}

/*
 * nfslog_READLINK2_fhargs - updates path1 but no fhtable changes
 */
/* ARGSUSED */
static void
nfslog_READLINK2_fhargs(fhandle_t *args, nfslog_rdlnres *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	if (debug > 2) {
		(void) printf("=============\nREADLINK2: fh ");
		debug_opaque_print(stdout, args, sizeof (*args));
		(void) printf("\n");
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(NFSLOG_GET_FHANDLE2(args),
				NULL, fhpath, "readlink2");
		*pathp2 = NULL;
	}
}

/*
 * nfslog_READ2_fhargs - updates path1 but no fhtable changes
 */
/* ARGSUSED */
static void
nfslog_READ2_fhargs(nfslog_nfsreadargs *args, nfslog_rdresult *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	if (debug > 2) {
		(void) printf("=============\nREAD2: fh ");
		debug_opaque_print(stdout, &args->ra_fhandle,
			sizeof (args->ra_fhandle));
		(void) printf("\n");
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(
				NFSLOG_GET_FHANDLE2(&args->ra_fhandle),
				NULL, fhpath, "read2");
		*pathp2 = NULL;
	}
}

/*
 * nfslog_WRITE2_fhargs - updates path1 but no fhtable changes
 */
/* ARGSUSED */
static void
nfslog_WRITE2_fhargs(nfslog_writeargs *args, nfslog_writeresult *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	if (debug > 2) {
		(void) printf("=============\nWRITE2: fh ");
		debug_opaque_print(stdout, &args->waargs_fhandle,
			sizeof (args->waargs_fhandle));
		(void) printf("\n");
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(
			NFSLOG_GET_FHANDLE2(&args->waargs_fhandle),
			NULL, fhpath, "write2");
		*pathp2 = NULL;
	}
}

/*
 * nfslog_CREATE2_fhargs - if the operation succeeded, we are sure there can
 * be no such link in the fhtable, so just add it.
 */
/* ARGSUSED */
static void
nfslog_CREATE2_fhargs(nfslog_createargs *args, nfslog_diropres *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	char		*name;
	fhandle_t	*dfh, *fh;
	int		error;

	name = args->ca_da.da_name;
	dfh = &args->ca_da.da_fhandle;
	if (debug > 2) {
		if (res->dr_status == NFS_OK)
			fh = &res->nfslog_diropres_u.dr_ok.drok_fhandle;
		else
			fh = NULL;
		PRINT_FULL_DATA(stdout, "=============\nCREATE2",
			dfh, fh, name, "")
		if (res->dr_status != NFS_OK)
			(void) printf("status %d\n", res->dr_status);
	}
	dfh = NFSLOG_GET_FHANDLE2(dfh);
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(dfh, name, fhpath, "create2");
		*pathp2 = NULL;
	}

	if (res->dr_status != NFS_OK)
		/* no returned fh so nothing to add */
		return;

	/* A new file handle so add it */
	fh = NFSLOG_GET_FHANDLE2(&res->nfslog_diropres_u.dr_ok.drok_fhandle);
	if (error = FH_ADD(fhpath, dfh, fh, name)) {
		syslog(LOG_ERR, gettext(
			"Create2: Add fh for '%s' failed: %s\n"),
			    name, ((error >= 0) ? strerror(error) : "Unknown"));
	}
}

/*
 * nfslog_REMOVE2_fhargs - if the operation succeeded, remove the link from
 * the fhtable.
 */
/* ARGSUSED */
static void
nfslog_REMOVE2_fhargs(nfslog_diropargs *args, nfsstat *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	char		*name;
	fhandle_t	*dfh;
	int		error;

	name = args->da_name;
	dfh = &args->da_fhandle;
	if (debug > 2) {
		PRINT_LINK_DATA(stdout, "=============\nREMOVE2", dfh, name, "")
		if (*res != NFS_OK)
			(void) printf("status %d\n", *res);
	}
	dfh = NFSLOG_GET_FHANDLE2(dfh);
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(dfh, name, fhpath, "remove2");
		*pathp2 = NULL;
	}

	if (*res != NFS_OK)
		/* remove failed so nothing to update */
		return;

	if (error = fh_remove(fhpath, dfh, name, pathp1)) {
		syslog(LOG_ERR, gettext("Remove2: '%s' failed: %s\n"),
			name, ((error >= 0) ? strerror(error) : "Unknown"));
	}
}

/*
 * nfsl_RENAME2_fhargs - updates the dfh and name fields for the given fh
 *	to change them to the new name.
 */
/* ARGSUSED */
static void
nfslog_RENAME2_fhargs(nfslog_rnmargs *args, nfsstat *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	char			*from_name, *to_name;
	fhandle_t		*from_dfh, *to_dfh;
	int			error;

	from_name = args->rna_from.da_name;
	from_dfh = &args->rna_from.da_fhandle;
	to_name = args->rna_to.da_name;
	to_dfh = &args->rna_to.da_fhandle;
	if (debug > 2) {
		PRINT_LINK_DATA(stdout, "=============\nRENAME2: from",
			from_dfh, from_name, "")
		PRINT_LINK_DATA(stdout, "RENAME2: to  ", to_dfh,
			to_name, "")
		if (*res != NFS_OK)
			(void) printf("status %d\n", *res);
	}
	from_dfh = NFSLOG_GET_FHANDLE2(from_dfh);
	to_dfh = NFSLOG_GET_FHANDLE2(to_dfh);
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(from_dfh, from_name, fhpath,
			"rename2 from");
		*pathp2 = nfslog_get_path(to_dfh, to_name, fhpath,
			"rename2 to");
	}

	if (*res != NFS_OK)
		/* rename failed so nothing to update */
		return;

	/* Rename the link in the database */
	if (error = fh_rename(fhpath, from_dfh, from_name, pathp1,
			to_dfh, to_name)) {
		syslog(LOG_ERR, gettext(
			"Rename2: Update from '%s' to '%s' failed: %s\n"),
				from_name, to_name,
				((error >= 0) ? strerror(error) : "Unknown"));
	}
}

/*
 * nfslog_LINK2_fhargs - adds link name and fh to fhlist. Note that as a
 *	result we may have more than one name for an fh.
 */
/* ARGSUSED */
static void
nfslog_LINK2_fhargs(nfslog_linkargs *args, nfsstat *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	char		*name;
	fhandle_t	*dfh, *fh;
	int		error;

	fh = &args->la_from;
	name = args->la_to.da_name;
	dfh = &args->la_to.da_fhandle;
	if (debug > 2) {
		PRINT_FULL_DATA(stdout, "=============\nLINK2",
			dfh, fh, name, "")
		if (*res != NFS_OK)
			(void) printf("status %d\n", *res);
	}
	dfh = NFSLOG_GET_FHANDLE2(dfh);
	fh = NFSLOG_GET_FHANDLE2(fh);
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(fh, NULL, fhpath, "link2 from");
		*pathp2 = nfslog_get_path(dfh, name, fhpath, "link2 to");
	}

	if (*res != NFS_OK)
		/* no returned fh so nothing to add */
		return;

	/* A new link so add it, have fh_add find the link count */
	if (error = FH_ADD(fhpath, dfh, fh, name)) {
		syslog(LOG_ERR, gettext(
			"Link2: Add fh for '%s' failed: %s\n"),
			    name, ((error >= 0) ? strerror(error) : "Unknown"));
	}
}

/*
 * nfslog_SYMLINK2_fhargs - adds symlink name and fh to fhlist if fh returned.
 */
/* ARGSUSED */
static void
nfslog_SYMLINK2_fhargs(nfslog_symlinkargs *args, nfsstat *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	char		*name;
	fhandle_t	*dfh;

	name = args->sla_from.da_name;
	dfh = &args->sla_from.da_fhandle;
	if (debug > 2) {
		PRINT_LINK_DATA(stdout, "=============\nSYMLINK2",
			dfh, name, "")
	}
	dfh = NFSLOG_GET_FHANDLE2(dfh);
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(dfh, name, fhpath, "symlink2");
		*pathp2 = NULL;
	}
}

/*
 * nfslog_READDIR2_fhargs - updates path1 but no fhtable changes
 */
/* ARGSUSED */
static void
nfslog_READDIR2_fhargs(nfslog_rddirargs *args, nfslog_rddirres *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	if (debug > 2) {
		(void) printf("=============\nREADDIR2: fh ");
		debug_opaque_print(stdout, &args->rda_fh,
			sizeof (args->rda_fh));
		(void) printf("\n");
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(NFSLOG_GET_FHANDLE2(&args->rda_fh),
				NULL, fhpath, "readdir2");
		*pathp2 = NULL;
	}
}

/*
 * nfslog_STATFS2_fhargs - updates path1 but no fhtable changes
 */
/* ARGSUSED */
static void
nfslog_STATFS2_fhargs(fhandle_t *args, nfsstat *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	if (debug > 2) {
		(void) printf("=============\nSTATFS2: fh ");
		debug_opaque_print(stdout, args, sizeof (*args));
		(void) printf("\n");
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(NFSLOG_GET_FHANDLE2(args),
				NULL, fhpath, "statfs2");
		*pathp2 = NULL;
	}
}

/*
 * NFS VERSION 3
 */

/* Functions for updating the fhtable for fhtoppath */

/*
 * nfslog_GETATTR3_fhargs - updates path1 but no fhtable changes
 */
/* ARGSUSED */
static void
nfslog_GETATTR3_fhargs(nfs_fh3 *args, nfsstat3 *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	if (debug > 2) {
		(void) printf("=============\nGETATTR3: fh ");
		debug_opaque_print(stdout, args, sizeof (*args));
		(void) printf("\n");
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(NFSLOG_GET_FHANDLE3(args), NULL,
			fhpath, "getattr3");
		*pathp2 = NULL;
	}
}

/*
 * nfslog_SETATTR3_fhargs - updates path1 but no fhtable changes
 */
/* ARGSUSED */
static void
nfslog_SETATTR3_fhargs(nfslog_SETATTR3args *args,	nfsstat3 *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	if (debug > 2) {
		(void) printf("=============\nSETATTR3: fh ");
		debug_opaque_print(stdout, &args->object,
			sizeof (args->object));
		(void) printf("\n");
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(NFSLOG_GET_FHANDLE3(&args->object),
			NULL, fhpath, "setattr3");
		*pathp2 = NULL;
	}
}

/*
 * nfslog_LOOKUP3_fhargs - search the table to ensure we have not added this
 * one already. Note that if the response status was anything but okay,
 * there is no fh to check...
 */
/* ARGSUSED */
static void
nfslog_LOOKUP3_fhargs(nfslog_diropargs3 *args, nfslog_LOOKUP3res *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	char		*name;
	fhandle_t	*dfh, *fh;

	name = args->name;
	dfh = NFSLOG_GET_FHANDLE3(&args->dir);

	if (debug > 2) {
		if (res->status == NFS3_OK)
			fh = NFSLOG_GET_FHANDLE3(
				&res->nfslog_LOOKUP3res_u.object);
		else
			fh = NULL;
		PRINT_FULL_DATA(stdout, "=============\nLOOKUP3",
			dfh, fh, name, "")
		if (res->status != NFS3_OK)
			(void) printf("status %d\n", res->status);
	}
	if ((dfh == &public_fh) && (name[0] == '\x80')) {
		/* special mclookup */
		name = &name[1];
	}
	if (res->status != NFS3_OK) {
		if (pathp1 != NULL) {
			*pathp1 = nfslog_get_path(dfh, name, fhpath, "lookup3");
			*pathp2 = NULL;
		}
		return;
	}
	fh = NFSLOG_GET_FHANDLE3(&res->nfslog_LOOKUP3res_u.object);
	nfslog_LOOKUP_calc(dfh, name, fh, fhpath, pathp1, pathp2, "Lookup3");
}

/*
 * nfslog_ACCESS3_fhargs - updates path1 but no fhtable changes
 */
/* ARGSUSED */
static void
nfslog_ACCESS3_fhargs(nfs_fh3 *args, nfsstat3 *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	if (debug > 2) {
		(void) printf("=============\nACCESS3: fh ");
		debug_opaque_print(stdout, args,
			sizeof (*args));
		(void) printf("\n");
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(NFSLOG_GET_FHANDLE3(args),
			NULL, fhpath, "access3");
		*pathp2 = NULL;
	}
}

/*
 * nfslog_READLINK3_fhargs - updates path1 but no fhtable changes
 */
/* ARGSUSED */
static void
nfslog_READLINK3_fhargs(nfs_fh3 *args, nfslog_READLINK3res *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	if (debug > 2) {
		(void) printf("=============\nREADLINK3: fh ");
		debug_opaque_print(stdout, args, sizeof (*args));
		(void) printf("\n");
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(NFSLOG_GET_FHANDLE3(args), NULL,
			fhpath, "readlink3");
		*pathp2 = NULL;
	}
}

/*
 * nfslog_READ3_fhargs - updates path1 but no fhtable changes
 */
/* ARGSUSED */
static void
nfslog_READ3_fhargs(nfslog_READ3args *args, nfslog_READ3res *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	if (debug > 2) {
		(void) printf("=============\nREAD3: fh ");
		debug_opaque_print(stdout, &args->file,
			sizeof (args->file));
		(void) printf("\n");
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(NFSLOG_GET_FHANDLE3(&args->file),
			NULL, fhpath, "read3");
		*pathp2 = NULL;
	}
}

/*
 * nfslog_WRITE3_fhargs - updates path1 but no fhtable changes
 */
/* ARGSUSED */
static void
nfslog_WRITE3_fhargs(nfslog_WRITE3args *args, nfslog_WRITE3res *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	if (debug > 2) {
		(void) printf("=============\nWRITE3: fh ");
		debug_opaque_print(stdout, &args->file,
			sizeof (args->file));
		(void) printf("\n");
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(NFSLOG_GET_FHANDLE3(&args->file),
			NULL, fhpath, "write3");
		*pathp2 = NULL;
	}
}

/*
 * nfslog_CREATE3_fhargs - if the operation succeeded, we are sure there can
 * be no such link in the fhtable, so just add it.
 */
/* ARGSUSED */
static void
nfslog_CREATE3_fhargs(nfslog_CREATE3args *args, nfslog_CREATE3res *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	char		*name;
	fhandle_t	*dfh, *fh;
	int		error;

	name = args->where.name;
	dfh = NFSLOG_GET_FHANDLE3(&args->where.dir);

	if (debug > 2) {
		if (res->status == NFS3_OK)
			fh = NFSLOG_GET_FHANDLE3(
				&res->nfslog_CREATE3res_u.ok.obj.handle);
		else
			fh = NULL;
		PRINT_FULL_DATA(stdout, "=============\nCREATE3",
			dfh, fh, name, "")
		if (res->status != NFS3_OK)
			(void) printf("status %d\n", res->status);
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(dfh, name, fhpath, "create3");
		*pathp2 = NULL;
	}

	if ((res->status != NFS3_OK) ||
		!res->nfslog_CREATE3res_u.ok.obj.handle_follows)
		/* no returned fh so nothing to add */
		return;

	/* A new file handle so add it */
	fh = NFSLOG_GET_FHANDLE3(&res->nfslog_CREATE3res_u.ok.obj.handle);
	if (error = FH_ADD(fhpath, dfh, fh, name)) {
		syslog(LOG_ERR, gettext(
			"Create3: Add fh for '%s' failed: %s\n"),
			    name, ((error >= 0) ? strerror(error) : "Unknown"));
	}
}

/*
 * nfslog_MKDIR3_fhargs - if the operation succeeded, we are sure there can
 * be no such link in the fhtable, so just add it.
 */
/* ARGSUSED */
static void
nfslog_MKDIR3_fhargs(nfslog_MKDIR3args *args, nfslog_MKDIR3res *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	char		*name;
	fhandle_t	*dfh, *fh;
	int		error;

	name = args->where.name;
	dfh = NFSLOG_GET_FHANDLE3(&args->where.dir);

	if (debug > 2) {
		if (res->status == NFS3_OK)
			fh = NFSLOG_GET_FHANDLE3(
				&res->nfslog_MKDIR3res_u.obj.handle);
		else
			fh = NULL;
		PRINT_FULL_DATA(stdout, "=============\nMKDIR3",
			dfh, fh, name, "")
		if (res->status != NFS3_OK)
			(void) printf("status %d\n", res->status);
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(dfh, name, fhpath, "mkdir3");
		*pathp2 = NULL;
	}

	if ((res->status != NFS3_OK) ||
		!res->nfslog_MKDIR3res_u.obj.handle_follows)
		/* no returned fh so nothing to add */
		return;

	/* A new file handle so add it */
	fh = NFSLOG_GET_FHANDLE3(&res->nfslog_MKDIR3res_u.obj.handle);
	if (error = FH_ADD(fhpath, dfh, fh, name)) {
		syslog(LOG_ERR, gettext(
			"Mkdir3: Add fh for '%s' failed: %s\n"),
			    name, ((error >= 0) ? strerror(error) : "Unknown"));
	}
}

/*
 * nfslog_REMOVE3_fhargs - if the operation succeeded, remove the link from
 * the fhtable.
 */
/* ARGSUSED */
static void
nfslog_REMOVE3_fhargs(nfslog_REMOVE3args *args, nfsstat3 *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	char		*name;
	fhandle_t	*dfh;
	int		error;

	name = args->object.name;
	dfh = NFSLOG_GET_FHANDLE3(&args->object.dir);

	if (debug > 2) {
		PRINT_LINK_DATA(stdout, "=============\nREMOVE3", dfh, name, "")
		if (*res != NFS3_OK)
			(void) printf("status %d\n", *res);
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(dfh, name, fhpath, "remove3");
		*pathp2 = NULL;
	}

	if (*res != NFS3_OK)
		/* remove failed so nothing to update */
		return;

	if (error = fh_remove(fhpath, dfh, name, pathp1)) {
		syslog(LOG_ERR, gettext("Remove3: '%s' failed: %s\n"),
			name, ((error >= 0) ? strerror(error) : "Unknown"));
	}
}

/*
 * nfslog_RMDIR3_fhargs - if the operation succeeded, remove the link from
 * the fhtable.
 */
/* ARGSUSED */
static void
nfslog_RMDIR3_fhargs(nfslog_RMDIR3args *args, nfsstat3 *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	char		*name;
	fhandle_t	*dfh;
	int		error;

	name = args->object.name;
	dfh = NFSLOG_GET_FHANDLE3(&args->object.dir);

	if (debug > 2) {
		PRINT_LINK_DATA(stdout, "=============\nRMDIR3", dfh, name, "")
		if (*res != NFS3_OK)
			(void) printf("status %d\n", *res);
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(dfh, name, fhpath, "rmdir3");
		*pathp2 = NULL;
	}

	if (*res != NFS3_OK)
		/* rmdir failed so nothing to update */
		return;

	if (error = fh_remove(fhpath, dfh, name, pathp1)) {
		syslog(LOG_ERR, gettext("Rmdir3: '%s' failed: %s\n"),
			name, ((error >= 0) ? strerror(error) : "Unknown"));
	}
}

/*
 * nfslog_RENAME3_fhargs - if the operation succeeded, update the existing
 * fhtable entry to point to new dir and name.
 */
/* ARGSUSED */
static void
nfslog_RENAME3_fhargs(nfslog_RENAME3args *args, nfsstat3 *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	char			*from_name, *to_name;
	fhandle_t		*from_dfh, *to_dfh;
	int			error;

	from_name = args->from.name;
	from_dfh = NFSLOG_GET_FHANDLE3(&args->from.dir);
	to_name = args->to.name;
	to_dfh = NFSLOG_GET_FHANDLE3(&args->to.dir);

	if (debug > 2) {
		PRINT_LINK_DATA(stdout, "=============\nRENAME3: from",
			from_dfh, from_name, "")
		PRINT_LINK_DATA(stdout, "=============\nRENAME3: to  ",
			to_dfh, to_name, "")
		if (*res != NFS3_OK)
			(void) printf("status %d\n", *res);
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(from_dfh, from_name, fhpath,
			"rename3 from");
		*pathp2 = nfslog_get_path(to_dfh, to_name, fhpath,
			"rename3 to");
	}
	if (*res != NFS3_OK)
		/* rename failed so nothing to update */
		return;

	if (error = fh_rename(fhpath, from_dfh, from_name, pathp1,
			to_dfh, to_name)) {
		syslog(LOG_ERR, gettext(
			"Rename3: Update from '%s' to '%s' failed: %s\n"),
				from_name, to_name,
				((error >= 0) ? strerror(error) : "Unknown"));
	}
}

/*
 * nfslog_LINK3_fhargs - if the operation succeeded, we are sure there can
 * be no such link in the fhtable, so just add it.
 */
/* ARGSUSED */
static void
nfslog_LINK3_fhargs(nfslog_LINK3args *args, nfsstat3 *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	char			*name;
	fhandle_t		*dfh, *fh;
	int			error;

	fh = NFSLOG_GET_FHANDLE3(&args->file);
	name = args->link.name;
	dfh = NFSLOG_GET_FHANDLE3(&args->link.dir);

	if (debug > 2) {
		PRINT_FULL_DATA(stdout, "=============\nLINK3",
			dfh, fh, name, "")
		if (*res != NFS3_OK)
			(void) printf("status %d\n", *res);
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(fh, NULL, fhpath, "link3 from");
		*pathp2 = nfslog_get_path(dfh, name, fhpath, "link3 to");
	}

	if (*res != NFS3_OK)
		/* link failed so nothing to add */
		return;

	/* A new link so add it, have fh_add find link count */
	if (error = FH_ADD(fhpath, dfh, fh, name)) {
		syslog(LOG_ERR, gettext(
			"Link3: Add fh for '%s' failed: %s\n"),
			    name, ((error >= 0) ? strerror(error) : "Unknown"));
	}
}

/*
 * nfslog_MKNOD3_fhargs - if the operation succeeded, we are sure there can
 * be no such link in the fhtable, so just add it.
 */
/* ARGSUSED */
static void
nfslog_MKNOD3_fhargs(nfslog_MKNOD3args *args, nfslog_MKNOD3res *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	char		*name;
	fhandle_t	*dfh, *fh;
	int		error;

	name = args->where.name;
	dfh = NFSLOG_GET_FHANDLE3(&args->where.dir);

	if (debug > 2) {
		if (res->status == NFS3_OK)
			fh = NFSLOG_GET_FHANDLE3(
				&res->nfslog_MKNOD3res_u.obj.handle);
		else
			fh = NULL;
		PRINT_FULL_DATA(stdout, "=============\nMKNOD3",
			dfh, fh, name, "")
		if (res->status != NFS3_OK)
			(void) printf("status %d\n", res->status);
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(dfh, name, fhpath, "mknod3");
		*pathp2 = NULL;
	}
	if ((res->status != NFS3_OK) ||
		!res->nfslog_MKNOD3res_u.obj.handle_follows)
		/* no returned fh so nothing to add */
		return;

	/* A new file handle so add it */
	fh = NFSLOG_GET_FHANDLE3(&res->nfslog_MKNOD3res_u.obj.handle);
	if (error = FH_ADD(fhpath, dfh, fh, name)) {
		syslog(LOG_ERR, gettext("Mknod3: Add fh for '%s' failed: %s\n"),
			name, ((error >= 0) ? strerror(error) : "Unknown"));
	}
}

/*
 * nfslog_SYMLINK3_fhargs - if the operation succeeded, we are sure there can
 * be no such link in the fhtable, so just add it.
 */
/* ARGSUSED */
static void
nfslog_SYMLINK3_fhargs(nfslog_SYMLINK3args *args, nfslog_SYMLINK3res *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	char		*name;
	fhandle_t	*dfh, *fh;
	int		error;

	name = args->where.name;
	dfh = NFSLOG_GET_FHANDLE3(&args->where.dir);

	if (debug > 2) {
		if (res->status == NFS3_OK)
			fh = NFSLOG_GET_FHANDLE3(
				&res->nfslog_SYMLINK3res_u.obj.handle);
		else
			fh = NULL;
		PRINT_FULL_DATA(stdout, "=============\nSYMLINK3",
			dfh, fh, name, "")
		if (res->status != NFS3_OK)
			(void) printf("status %d\n", res->status);
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(dfh, name, fhpath, "symlink3");
		*pathp2 = NULL;
	}

	if ((res->status != NFS3_OK) ||
		!res->nfslog_SYMLINK3res_u.obj.handle_follows)
		/* no returned fh so nothing to add */
		return;

	/* A new file handle so add it */
	fh = NFSLOG_GET_FHANDLE3(&res->nfslog_SYMLINK3res_u.obj.handle);
	if (error = FH_ADD(fhpath, dfh, fh, name)) {
		syslog(LOG_ERR, gettext(
			"Symlink3: Add fh for '%s' failed: %s\n"),
			    name, ((error >= 0) ? strerror(error) : "Unknown"));
	}
}

/*
 * nfslog_READDIR3_fhargs - updates path1 but no fhtable changes
 */
/* ARGSUSED */
static void
nfslog_READDIR3_fhargs(nfs_fh3 *args, nfsstat3 *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	if (debug > 2) {
		(void) printf("=============\nREADDIR3: fh ");
		debug_opaque_print(stdout, args,
			sizeof (*args));
		(void) printf("\n");
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(NFSLOG_GET_FHANDLE3(args),
			NULL, fhpath, "readdir3");
		*pathp2 = NULL;
	}
}

/*
 * nfslog_READDIRPLUS3_fhargs - updates path1 but no fhtable changes
 */
/* ARGSUSED */
static void
nfslog_READDIRPLUS3_fhargs(nfslog_READDIRPLUS3args *args,
	nfslog_READDIRPLUS3res *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	char		*name;
	fhandle_t	*dfh, *fh;
	nfslog_entryplus3 *ep;

	if (debug > 2) {
		(void) printf("=============\nREADDIRPLUS3: fh ");
		debug_opaque_print(stdout, &args->dir,
			sizeof (args->dir));
		(void) printf("\n");
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(NFSLOG_GET_FHANDLE3(&args->dir),
			NULL, fhpath, "readdirplus3");
		*pathp2 = NULL;
	}

	if (res->status == NFS3_OK) {

		dfh = NFSLOG_GET_FHANDLE3(&args->dir);

		/*
		 * Loop through the fh/name pair and add them
		 * to the mappings.
		 */
		for (ep = res->nfslog_READDIRPLUS3res_u.ok.reply.entries;
			ep != NULL;
			ep = ep->nextentry) {

			name = ep->name;

			fh = NFSLOG_GET_FHANDLE3(&ep->name_handle.handle);

			nfslog_LOOKUP_calc(dfh, name, fh,
				fhpath, NULL, NULL,
				"ReaddirPlus3");
		}
	}
}

/*
 * nfslog_FSSTAT3_fhargs - updates path1 but no fhtable changes
 */
/* ARGSUSED */
static void
nfslog_FSSTAT3_fhargs(nfs_fh3 *args, nfsstat3 *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	if (debug > 2) {
		(void) printf("=============\nFSSTAT3: fh ");
		debug_opaque_print(stdout, args,
			sizeof (*args));
		(void) printf("\n");
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(NFSLOG_GET_FHANDLE3(args), NULL,
			fhpath, "fsstat3");
		*pathp2 = NULL;
	}
}

/*
 * nfslog_FSINFO3_fhargs - updates path1 but no fhtable changes
 */
/* ARGSUSED */
static void
nfslog_FSINFO3_fhargs(nfs_fh3 *args, nfsstat3 *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	if (debug > 2) {
		(void) printf("=============\nFSINFO3: fh ");
		debug_opaque_print(stdout, args,
			sizeof (*args));
		(void) printf("\n");
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(NFSLOG_GET_FHANDLE3(args), NULL,
			fhpath, "fsinfo3");
		*pathp2 = NULL;
	}
}

/*
 * nfslog_PATHCONF3_fhargs - updates path1 but no fhtable changes
 */
/* ARGSUSED */
static void
nfslog_PATHCONF3_fhargs(nfs_fh3 *args, nfsstat3 *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	if (debug > 2) {
		(void) printf("=============\nPATHCONF3: fh ");
		debug_opaque_print(stdout, args,
			sizeof (*args));
		(void) printf("\n");
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(NFSLOG_GET_FHANDLE3(args), NULL,
			fhpath, "pathconf3");
		*pathp2 = NULL;
	}
}

/*
 * nfslog_COMMIT3_fhargs - updates path1 but no fhtable changes
 */
/* ARGSUSED */
static void
nfslog_COMMIT3_fhargs(nfslog_COMMIT3args *args, nfsstat3 *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	if (debug > 2) {
		(void) printf("=============\nCOMMIT3: fh ");
		debug_opaque_print(stdout, &args->file,
			sizeof (args->file));
		(void) printf("\n");
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(NFSLOG_GET_FHANDLE3(&args->file),
			NULL, fhpath, "commit3");
		*pathp2 = NULL;
	}
}

/*
 * NFSLOG VERSION 1
 */

/*
 * nfslog_SHARE_fhargs - adds export path and handle to fhlist
 */
/* ARGSUSED */
static void
nfslog_SHARE_fhargs(nfslog_sharefsargs *args, nfslog_sharefsres *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	fhlist_ent	fhrec;
	fhandle_t	*fh;
	int		error;

	if (debug > 2) {
		(void) printf(
			"=============\nSHARE: name '%s', fh ", args->sh_path);
		debug_opaque_print(stdout, &args->sh_fh_buf,
			sizeof (fhandle_t));
		(void) printf("\n");
	}

	fh = &args->sh_fh_buf;

	/*
	 * This bcopy is done because the fh_data for the export/share directory
	 * is not meaningful with respect to the database keys.  Therefore, we
	 * copy the export or fh_xdata fid to the fh_data so that a reasonable
	 * entry will be added in the data base.
	 */
	bcopy(fh->fh_xdata, fh->fh_data, fh->fh_xlen);

	/* If debug print the database */
	if (debug > 10) {
		fh_print_all_keys(fhpath, fh);
	}
	if (fh_lookup_link(fhpath, fh, fh,
		args->sh_path, &fhrec, &error) == NULL) {
		if (error = FH_ADD(fhpath, fh, fh, args->sh_path)) {
			syslog(LOG_ERR, gettext(
				"Share: Add fh for '%s' failed: %s\n"),
				    args->sh_path, ((error >= 0) ?
				    strerror(error) : "Unknown"));
		}
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(fh, NULL, fhpath, "share");
		*pathp2 = NULL;
	}
}

/*
 * nfslog_UNSHARE_fhargs - remove export path and handle from fhlist
 */
/* ARGSUSED */
static void
nfslog_UNSHARE_fhargs(nfslog_sharefsargs *args, nfslog_sharefsres *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	fhandle_t	*fh;
	int		error;

	if (debug > 2) {
		(void) printf("=============\nUNSHARE: name '%s', fh ",
			args->sh_path);
		debug_opaque_print(stdout, &args->sh_fh_buf,
			sizeof (fhandle_t));
		(void) printf("\n");
	}

	fh = &args->sh_fh_buf;

	/*
	 * This bcopy is done because the fh_data for the export/share directory
	 * is not meaningful with respect to the database keys.  Therefore, we
	 * copy the export or fh_xdata fid to the fh_data so that a reasonable
	 * entry will be added in the data base.
	 */
	bcopy(fh->fh_xdata, fh->fh_data, fh->fh_xlen);

	/* If debug print the database */
	if (debug > 10) {
		fh_print_all_keys(fhpath, fh);
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(fh, NULL, fhpath, "share");
		*pathp2 = NULL;
	}
	if (error = fh_remove(fhpath, fh, args->sh_path, pathp1)) {
		syslog(LOG_ERR, gettext("Unshare: '%s' failed: %s\n"),
			args->sh_path, ((error >= 0) ? strerror(error) :
			"Unknown"));
	}
}

/* ARGSUSED */
static void
nfslog_GETFH_fhargs(nfslog_getfhargs *args, nfsstat *res,
	char *fhpath, char **pathp1, char **pathp2)
{
	fhlist_ent	fhrec;
	fhandle_t	*fh;
	int		error;

	if (debug > 2) {
		(void) printf("=============\nGETFH3: name '%s', fh ",
			args->gfh_path);
		debug_opaque_print(stdout, &args->gfh_fh_buf,
			sizeof (fhandle_t));
		(void) printf("\n");
	}

	fh = &args->gfh_fh_buf;

	/* If debug print the database */
	if (debug > 10) {
		fh_print_all_keys(fhpath, fh);
	}
	if (fh_lookup_link(fhpath, fh, fh,
		args->gfh_path, &fhrec, &error) == NULL) {
		if (error = FH_ADD(fhpath, fh, fh, args->gfh_path)) {
			syslog(LOG_ERR, gettext(
				"Getfh: Add fh for '%s' failed: %s\n"),
				    args->gfh_path, ((error >= 0) ?
				    strerror(error) : "Unknown"));
		}
	}
	if (pathp1 != NULL) {
		*pathp1 = nfslog_get_path(fh, NULL, fhpath, "getfh");
		*pathp2 = NULL;
	}
}

/*
 * Exported function
 */

/*
 * nfslog_get_path - gets the path for this file. fh must be supplied,
 * name may be null. If name is supplied, fh is assumed to be a directory
 * filehandle, with name as its component. fhpath is the generic path for the
 * fhtopath table and prtstr is the name of the caller (for debug purposes).
 * Returns the malloc'd path. The caller must free it later.
 */
char *
nfslog_get_path(fhandle_t *fh, char *name, char *fhpath, char *prtstr)
{
	char	*pathp = fh_print_absolute(fhpath, fh, name);

	if (debug > 3) {
		(void) printf("   %s: path '%s', fh ", prtstr, pathp);
		debug_opaque_print(stdout, fh, sizeof (*fh));
		(void) printf("\n");
	}
	return (pathp);
}

/*
 * nfslog_process_fh_rec - updates the fh table based on the rpc req
 * Return 0 for success, error otherwise. If success return the path
 * for the input file handle(s) if so indicated.
 */
int
nfslog_process_fh_rec(struct nfslog_lr *lrp, char *fhpath, char **pathp1,
	char **pathp2, bool_t return_path)
{
	struct nfsl_fh_proc_disp	*disp;
	nfslog_request_record 		*logrec = &lrp->log_record;
	nfslog_record_header		*logrechdr = &logrec->re_header;

	if ((disp = nfslog_find_fh_dispatch(logrec)) != NULL) {
		/*
		 * Allocate space for the args and results and decode
		 */
		logrec->re_rpc_arg = calloc(1, disp->args_size);

		if (!(*disp->xdr_args)(&lrp->xdrs, logrec->re_rpc_arg)) {
			free(logrec->re_rpc_arg);
			logrec->re_rpc_arg = NULL;
			syslog(LOG_ERR, gettext("argument decode failed"));
			return (FALSE);
		}
		/* used later for free of data structures */
		lrp->xdrargs = disp->xdr_args;

		logrec->re_rpc_res = calloc(1, disp->res_size);
		if (!(*disp->xdr_res)(&lrp->xdrs, logrec->re_rpc_res)) {
			free(logrec->re_rpc_res);
			logrec->re_rpc_res = NULL;
			syslog(LOG_ERR, gettext("results decode failed"));
			return (FALSE);
		}
		/* used later for free of data structures */
		lrp->xdrres = disp->xdr_res;

		/*
		 * Process the operation within the context of the file handle
		 * mapping process
		 */
		if (return_path) {
			(*disp->nfsl_dis_args)(logrec->re_rpc_arg,
				logrec->re_rpc_res, fhpath, pathp1, pathp2);
		} else {
			if ((logrechdr->rh_version == NFS_VERSION &&
				logrechdr->rh_procnum == RFS_LINK) ||
				(logrechdr->rh_version == NFS_V3 &&
				logrechdr->rh_procnum == NFSPROC3_LINK)) {

				(*disp->nfsl_dis_args)(logrec->re_rpc_arg,
					logrec->re_rpc_res,
					fhpath,	pathp1, pathp2);
			} else {
				(*disp->nfsl_dis_args)(logrec->re_rpc_arg,
					logrec->re_rpc_res,
					fhpath, NULL, NULL);
			}
		}
		return (TRUE);
	} else {
		syslog(LOG_ERR, gettext("procedure unknown"));
		return (FALSE);
	}
}
