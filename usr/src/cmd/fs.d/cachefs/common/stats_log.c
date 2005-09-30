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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Routines for cachefs logging.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/param.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libintl.h>
#include <time.h>
#include <string.h>
#include <sys/fs/cachefs_fs.h>
#include <sys/fs/cachefs_log.h>
#include <malloc.h>
#include <limits.h>
#include "stats.h"
#include <assert.h>

/* forward declarations of statics */
static kstat_t *stats_log_kstat_read(stats_cookie_t *);
static char *stats_log_fmtfid(cfs_fid_t *);
static bool_t stats_xdr_loghead(XDR *, struct cachefs_log_logfile_header *);
static int stats_log_fi_comp(const void *a, const void *b);

int
stats_log_kernel_setname(stats_cookie_t *st, char *path)
{
	int error = 0;
	kstat_t *log;
	cachefs_log_control_t *lc;
	int exists = 0;

	assert(stats_good(st));

	if ((log = stats_log_kstat_read(st)) == NULL) {
		error = stats_errno(st);
		goto out;
	}

	lc = (cachefs_log_control_t *)log->ks_data;

	/*
	 * the stats_ API allows a NULL or an empty path to turn off
	 * logging, but the kstat interface has the string buffered,
	 * so we need to make an empty string.
	 */

	if (path == NULL)
		path = "";
	if ((lc->lc_path[0] == 0) && (path[0] == 0))
		goto out;

	(void) strlcpy(lc->lc_path, path, sizeof (lc->lc_path));

	if (path[0] != '\0') {
		struct stat64 s;
		int f;

		exists = access(path, F_OK);
		/* logfile will be <2GB */
		f = open(path, O_WRONLY | O_CREAT, 0666);
		if (f < 0) {
			stats_perror(st, error = SE_FILE,
			    gettext("Cannot open/create logfile: %s"),
			    strerror(errno));
			goto out;
		}

		if (fstat64(f, &s) < 0) {
			stats_perror(st, error = SE_FILE,
			    gettext("Cannot stat logfile: %s"),
			    strerror(errno));
			(void) close(f);
			goto out;
		}

		/*
		 * the kernel will accept an empty file as a logfile.  we must
		 * make sure that we created this empty file, i.e. that it's
		 * not an already existing file that happened to be empty.
		 *
		 * if we hand the kernel a nonempty file, it will check the
		 * magic number.  thus, if they hand it something like
		 * /etc/passwd, the kernel should reject it.  we just have to
		 * catch the cases of empty files we don't want to be
		 * logfiles.
		 */

		if ((exists == 0) && (s.st_size == 0LL)) {
			stats_perror(st, error = SE_INVAL,
			    gettext(
			    "Cannot use existing empty file as a logfile"));
			(void) close(f);
			goto out;
		}

		(void) close(f);
	}

	if (kstat_write(st->st_kstat_cookie, log, NULL) < 0) {
		stats_perror(st, error = SE_KERNEL,
		    gettext("Cannot set logfile path for this filesystem"));
		goto out;
	}

out:
	if ((error != 0) && (path[0] != '\0') && (exists != 0))
		(void) unlink(path);

	return (error);
}

int
stats_log_which(stats_cookie_t *st, int which, int onoff)
{
	int error = 0;
	kstat_t *log;
	cachefs_log_control_t *lc;

	assert(stats_good(st));

	if ((log = stats_log_kstat_read(st)) == NULL) {
		error = stats_errno(st);
		goto out;
	}

	lc = (cachefs_log_control_t *)log->ks_data;

	if (onoff)
		CACHEFS_LOG_SET(lc, which);
	else
		CACHEFS_LOG_CLEAR(lc, which);

	if (kstat_write(st->st_kstat_cookie, log, NULL) < 0) {
		stats_perror(st, error = SE_KERNEL,
		    gettext("Cannot set log bitmap for this filesystem"));
		goto out;
	}

out:
	return (error);
}

char *
stats_log_kernel_getname(stats_cookie_t *st)
{
	char *rc = NULL;
	kstat_t *log;
	cachefs_log_control_t *lc;

	assert(stats_good(st));

	if ((log = stats_log_kstat_read(st)) == NULL)
		goto out;

	lc = (cachefs_log_control_t *)log->ks_data;

	rc = lc->lc_path; /* rc[0] will be '\0' if we're not logging */

out:
	return (rc);
}

static kstat_t *
stats_log_kstat_read(stats_cookie_t *st)
{
	kstat_t *rc;

	assert(stats_good(st));
	assert(st->st_flags & ST_BOUND);

	if ((rc = kstat_lookup(st->st_kstat_cookie,
	    "cachefs", st->st_fsid, "log")) == NULL) {
		/*
		 * XXX if st was created for a particular cachedir, we
		 * should scan for another st->st_fsid that'll get us
		 * the same cache.
		 */
		stats_perror(st, SE_KERNEL,
		    gettext("Cannot lookup kstats for this filesystem"));
		goto out;
	}
	if (kstat_read(st->st_kstat_cookie, rc, NULL) < 0) {
		stats_perror(st, SE_KERNEL,
		    gettext("Cannot read kstats for this filesystem"));
		rc = NULL;
		goto out;
	}

out:
	return (rc);
}

int
stats_log_logfile_open(stats_cookie_t *st, char *fname)
{
	int rc = 0;

	assert(stats_good(st));

	if ((fname == NULL) || (fname[0] == '\0')) {
		kstat_t *log;
		cachefs_log_control_t *lc;

		if ((log = stats_log_kstat_read(st)) == NULL) {
			rc = -1;
			goto out;
		}
		lc = (cachefs_log_control_t *)log->ks_data;
		fname = lc->lc_path;
	}

	/* logfile will be <2GB */
	if ((st->st_logstream = fopen(fname, "r")) == NULL) {
		stats_perror(st, SE_FILE,
		    gettext("Cannot open logfile %s"), fname);
		rc = -1;
		goto out;
	}
	xdrstdio_create(&st->st_logxdr, st->st_logstream, XDR_DECODE);

	if (! stats_xdr_loghead(&st->st_logxdr, &st->st_loghead)) {
		stats_perror(st, SE_CORRUPT,
		    gettext("Cannot read header from logfile %s"), fname);
		rc = -1;
		goto out;
	}
	if (st->st_loghead.lh_magic != CACHEFS_LOG_MAGIC) {
		stats_perror(st, SE_CORRUPT,
		    gettext("%s: Invalid log file header"), fname);
		rc = -1;
		goto out;
	}
	if (st->st_loghead.lh_revision > CACHEFS_LOG_FILE_REV) {
		stats_perror(st, SE_CORRUPT,
		    gettext("%s: Revision too high"), fname);
		rc = -1;
		goto out;
	}

	st->st_flags |= ST_LFOPEN;

out:
	if (rc != 0) {
		if (st->st_logstream != NULL) {
			(void) fclose(st->st_logstream);
			st->st_logstream = NULL;
		}
		if (st->st_logxdr.x_ops != NULL) {
			xdr_destroy(&st->st_logxdr);
			st->st_logxdr.x_ops = NULL;
		}
	}
	return (rc);
}

static bool_t
stats_xdr_loghead(XDR *xdrs, struct cachefs_log_logfile_header *lh)
{
	if ((! xdr_u_int(xdrs, &lh->lh_magic)) ||
	    (! xdr_u_int(xdrs, &lh->lh_revision)) ||
	    (! xdr_int(xdrs, &lh->lh_errno)) ||
	    (! xdr_u_int(xdrs, &lh->lh_blocks)) ||
	    (! xdr_u_int(xdrs, &lh->lh_files)) ||
	    (! xdr_u_int(xdrs, &lh->lh_maxbsize)) ||
	    (! xdr_u_int(xdrs, &lh->lh_pagesize)))
		return (FALSE);

	return (TRUE);
}

void *
stats_log_logfile_read(stats_cookie_t *st, int *type)
{
	void *rc = NULL;
	size_t size;
	int ttype;
	XDR *xdrs;
	char *string1, *string2;

	assert(stats_good(st));

	xdrs = &st->st_logxdr;

	if (! (st->st_flags & ST_LFOPEN)) {
		stats_perror(st, SE_INVAL,
		    gettext("Logfile was not open"));
		goto out;
	}

	if (type == NULL)
		type = &ttype;

	if (! xdr_int(xdrs, type))
		goto out;

	switch (*type) {
		struct cachefs_log_mount_record mount, *mountp;
		struct cachefs_log_umount_record umount;
		struct cachefs_log_getpage_record getpage;
		struct cachefs_log_readdir_record readdir;
		struct cachefs_log_readlink_record readlink;
		struct cachefs_log_remove_record remove;
		struct cachefs_log_rmdir_record rmdir;
		struct cachefs_log_truncate_record truncate;
		struct cachefs_log_putpage_record putpage;
		struct cachefs_log_create_record create;
		struct cachefs_log_mkdir_record mkdir;
		struct cachefs_log_rename_record rename;
		struct cachefs_log_symlink_record symlink;
		struct cachefs_log_populate_record populate;
		struct cachefs_log_csymlink_record csymlink;
		struct cachefs_log_filldir_record filldir;
		struct cachefs_log_mdcreate_record mdcreate;
		struct cachefs_log_gpfront_record gpfront;
		struct cachefs_log_rfdir_record rfdir;
		struct cachefs_log_ualloc_record ualloc;
		struct cachefs_log_calloc_record challoc;
		struct cachefs_log_nocache_record nocache;

	case CACHEFS_LOG_MOUNT:
		if ((! xdr_int(xdrs, &mount.error)) ||
		    (! xdr_int(xdrs, (int *)&mount.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&mount.vfsp,
		    sizeof (mount.vfsp))) ||
		    (! xdr_u_int(xdrs, &mount.flags)) ||
		    (! xdr_u_int(xdrs, &mount.popsize)) ||
		    (! xdr_u_int(xdrs, &mount.fgsize)) ||
		    (! xdr_u_short(xdrs, &mount.pathlen)) ||
		    (! xdr_u_short(xdrs, &mount.cacheidlen))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated mount record"));
			goto out;
		}
		mount.type = *type;
		size = sizeof (mount) + mount.pathlen + mount.cacheidlen -
			CLPAD(cachefs_log_mount_record, path);
		if ((rc = mountp =
		    (struct cachefs_log_mount_record *)
		    calloc(1, size)) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &mount, size);
		string1 = mountp->path;
		string2 = mountp->path + mount.pathlen + 1;
		(void) xdr_wrapstring(xdrs, &string1);
		(void) xdr_wrapstring(xdrs, &string2);
		break;

	case CACHEFS_LOG_UMOUNT:
		if ((! xdr_int(xdrs, &umount.error)) ||
		    (! xdr_int(xdrs, (int *)&umount.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&umount.vfsp,
		    sizeof (umount.vfsp)))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated umount record"));
			goto out;
		}
		umount.type = *type;
		size = sizeof (umount);
		if ((rc = (caddr_t)calloc(1, size)) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &umount, size);
		break;

	case CACHEFS_LOG_GETPAGE:
		if ((! xdr_int(xdrs, &getpage.error)) ||
		    (! xdr_int(xdrs, (int *)&getpage.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&getpage.vfsp,
		    sizeof (getpage.vfsp))) ||
		    (! xdr_opaque(xdrs, (caddr_t)&getpage.fid,
		    sizeof (getpage.fid))) ||
		    (! xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&getpage.fileno)) ||
		    (! xdr_int(xdrs, (int *)&getpage.uid)) ||
		    (! xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&getpage.offset)) ||
		    (! xdr_u_int(xdrs, &getpage.len))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated getpage record"));
			goto out;
		}
		getpage.type = *type;
		size = sizeof (getpage);
		if ((rc = (caddr_t)calloc(1, size)) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &getpage, size);
		break;

	case CACHEFS_LOG_READDIR:
		if ((! xdr_int(xdrs, &readdir.error)) ||
		    (! xdr_int(xdrs, (int *)&readdir.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&readdir.vfsp,
		    sizeof (readdir.vfsp))) ||
		    (! xdr_opaque(xdrs, (caddr_t)&readdir.fid,
		    sizeof (readdir.fid))) ||
		    (! xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&readdir.fileno)) ||
		    (! xdr_int(xdrs, (int *)&readdir.uid)) ||
		    (! xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&readdir.offset)) ||
		    (! xdr_int(xdrs, &readdir.eof))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated readdir record"));
			goto out;
		}
		readdir.type = *type;
		size = sizeof (readdir);
		if ((rc = (caddr_t)calloc(1, size)) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &readdir, size);
		break;

	case CACHEFS_LOG_READLINK:
		if ((! xdr_int(xdrs, &readlink.error)) ||
		    (! xdr_int(xdrs, (int *)&readlink.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&readlink.vfsp,
		    sizeof (readlink.vfsp))) ||
		    (! xdr_opaque(xdrs, (caddr_t)&readlink.fid,
		    sizeof (readlink.fid))) ||
		    (! xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&readlink.fileno)) ||
		    (! xdr_int(xdrs, (int *)&readlink.uid)) ||
		    (! xdr_u_int(xdrs,
		    &readlink.length))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated readlink record"));
			goto out;
		}
		readlink.type = *type;
		size = sizeof (readlink);
		if ((rc = (caddr_t)calloc(1, size)) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &readlink, size);
		break;

	case CACHEFS_LOG_REMOVE:
		if ((! xdr_int(xdrs, &remove.error)) ||
		    (! xdr_int(xdrs, (int *)&remove.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&remove.vfsp,
		    sizeof (remove.vfsp))) ||
		    (! xdr_opaque(xdrs, (caddr_t)&remove.fid,
		    sizeof (remove.fid))) ||
		    (! xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&remove.fileno)) ||
		    (! xdr_int(xdrs, (int *)&remove.uid))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated remove record"));
			goto out;
		}
		remove.type = *type;
		size = sizeof (remove);
		if ((rc = (caddr_t)calloc(1, size)) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &remove, size);
		break;

	case CACHEFS_LOG_RMDIR:
		if ((! xdr_int(xdrs, &rmdir.error)) ||
		    (! xdr_int(xdrs, (int *)&rmdir.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&rmdir.vfsp,
		    sizeof (rmdir.vfsp))) ||
		    (! xdr_opaque(xdrs, (caddr_t)&rmdir.fid,
		    sizeof (rmdir.fid))) ||
		    (! xdr_u_longlong_t(xdrs, (u_longlong_t *)&rmdir.fileno)) ||
		    (! xdr_int(xdrs, (int *)&rmdir.uid))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated rmdir record"));
			goto out;
		}
		rmdir.type = *type;
		size = sizeof (rmdir);
		if ((rc = (caddr_t)calloc(1, size)) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &rmdir, size);
		break;

	case CACHEFS_LOG_TRUNCATE:
		if ((! xdr_int(xdrs, &truncate.error)) ||
		    (! xdr_int(xdrs, (int *)&truncate.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&truncate.vfsp,
		    sizeof (truncate.vfsp))) ||
		    (! xdr_opaque(xdrs, (caddr_t)&truncate.fid,
		    sizeof (truncate.fid))) ||
		    (! xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&truncate.fileno)) ||
		    (! xdr_int(xdrs, (int *)&truncate.uid)) ||
		    (! xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&truncate.size))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated truncate record"));
			goto out;
		}
		truncate.type = *type;
		size = sizeof (truncate);
		if ((rc = (caddr_t)calloc(1, size)) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &truncate, size);
		break;

	case CACHEFS_LOG_PUTPAGE:
		if ((! xdr_int(xdrs, &putpage.error)) ||
		    (! xdr_int(xdrs, (int *)&putpage.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&putpage.vfsp,
		    sizeof (putpage.vfsp))) ||
		    (! xdr_opaque(xdrs, (caddr_t)&putpage.fid,
		    sizeof (putpage.fid))) ||
		    (! xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&putpage.fileno)) ||
		    (! xdr_int(xdrs, (int *)&putpage.uid)) ||
		    (! xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&putpage.offset)) ||
		    (! xdr_u_int(xdrs, &putpage.len))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated putpage record"));
			goto out;
		}
		putpage.type = *type;
		size = sizeof (putpage);
		if ((rc = (caddr_t)calloc(1, size)) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &putpage, size);
		break;

	case CACHEFS_LOG_CREATE:
		if ((! xdr_int(xdrs, &create.error)) ||
		    (! xdr_int(xdrs, (int *)&create.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&create.vfsp,
		    sizeof (create.vfsp))) ||
		    (! xdr_opaque(xdrs, (caddr_t)&create.fid,
		    sizeof (create.fid))) ||
		    (! xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&create.fileno)) ||
		    (! xdr_int(xdrs, (int *)&create.uid))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated create record"));
			goto out;
		}
		create.type = *type;
		size = sizeof (create);
		if ((rc = (struct cachefs_log_create_record *)
		    calloc(1, size)) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &create, size);
		break;

	case CACHEFS_LOG_MKDIR:
		if ((! xdr_int(xdrs, &mkdir.error)) ||
		    (! xdr_int(xdrs, (int *)&mkdir.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&mkdir.vfsp,
		    sizeof (mkdir.vfsp))) ||
		    (! xdr_opaque(xdrs, (caddr_t)&mkdir.fid,
		    sizeof (mkdir.fid))) ||
		    (! xdr_u_longlong_t(xdrs, (u_longlong_t *)&mkdir.fileno)) ||
		    (! xdr_int(xdrs, (int *)&mkdir.uid))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated mkdir record"));
			goto out;
		}
		mkdir.type = *type;
		size = sizeof (mkdir);
		if ((rc = (struct cachefs_log_mkdir_record *)
		    calloc(1, size)) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &mkdir, size);
		break;

	case CACHEFS_LOG_RENAME:
		if ((! xdr_int(xdrs, &rename.error)) ||
		    (! xdr_int(xdrs, (int *)&rename.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&rename.vfsp,
		    sizeof (rename.vfsp))) ||
		    (! xdr_opaque(xdrs, (caddr_t)&rename.gone,
		    sizeof (rename.gone))) ||
		    (! xdr_int(xdrs, &rename.removed)) ||
		    (! xdr_int(xdrs, (int *)&rename.uid))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated rename record"));
			goto out;
		}
		rename.type = *type;
		size = sizeof (rename);
		if ((rc = (struct cachefs_log_rename_record *)
		    calloc(1, size)) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &rename, size);
		break;

	case CACHEFS_LOG_SYMLINK:
		if ((! xdr_int(xdrs, &symlink.error)) ||
		    (! xdr_int(xdrs, (int *)&symlink.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&symlink.vfsp,
		    sizeof (symlink.vfsp))) ||
		    (! xdr_opaque(xdrs, (caddr_t)&symlink.fid,
		    sizeof (symlink.fid))) ||
		    (! xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&symlink.fileno)) ||
		    (! xdr_int(xdrs, (int *)&symlink.uid)) ||
		    (! xdr_u_int(xdrs, &symlink.size))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated symlink record"));
			goto out;
		}
		symlink.type = *type;
		size = sizeof (symlink);
		if ((rc = (struct cachefs_log_symlink_record *)
		    calloc(1, size)) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &symlink, size);
		break;

	case CACHEFS_LOG_POPULATE:
		if ((! xdr_int(xdrs, &populate.error)) ||
		    (! xdr_int(xdrs, (int *)&populate.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&populate.vfsp,
		    sizeof (populate.vfsp))) ||
		    (! xdr_opaque(xdrs, (caddr_t)&populate.fid,
		    sizeof (populate.fid))) ||
		    (! xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&populate.fileno)) ||
		    (! xdr_u_longlong_t(xdrs, (u_longlong_t *)&populate.off)) ||
		    (! xdr_u_int(xdrs, &populate.size))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated populate record"));
			goto out;
		}
		populate.type = *type;
		if ((rc = (struct cachefs_log_populate_record *)
		    calloc(1, sizeof (populate))) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &populate, sizeof (populate));
		break;

	case CACHEFS_LOG_CSYMLINK:
		if ((! xdr_int(xdrs, &csymlink.error)) ||
		    (! xdr_int(xdrs, (int *)&csymlink.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&csymlink.vfsp,
		    sizeof (csymlink.vfsp))) ||
		    (! xdr_opaque(xdrs, (caddr_t)&csymlink.fid,
		    sizeof (csymlink.fid))) ||
		    (! xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&csymlink.fileno)) ||
		    (! xdr_int(xdrs, &csymlink.size))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated csymlink record"));
			goto out;
		}
		csymlink.type = *type;
		if ((rc = (struct cachefs_log_csymlink_record *)
		    calloc(1, sizeof (csymlink))) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &csymlink, sizeof (csymlink));
		break;

	case CACHEFS_LOG_FILLDIR:
		if ((! xdr_int(xdrs, &filldir.error)) ||
		    (! xdr_int(xdrs, (int *)&filldir.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&filldir.vfsp,
		    sizeof (filldir.vfsp))) ||
		    (! xdr_opaque(xdrs, (caddr_t)&filldir.fid,
		    sizeof (filldir.fid))) ||
		    (! xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&filldir.fileno)) ||
		    (! xdr_int(xdrs, &filldir.size))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated filldir record"));
			goto out;
		}
		filldir.type = *type;
		if ((rc = (struct cachefs_log_filldir_record *)
		    calloc(1, sizeof (filldir))) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &filldir, sizeof (filldir));
		break;

	case CACHEFS_LOG_MDCREATE:
		if ((! xdr_int(xdrs, &mdcreate.error)) ||
		    (! xdr_int(xdrs, (int *)&mdcreate.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&mdcreate.vfsp,
		    sizeof (mdcreate.vfsp))) ||
		    (! xdr_opaque(xdrs, (caddr_t)&mdcreate.fid,
		    sizeof (mdcreate.fid))) ||
		    (! xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&mdcreate.fileno)) ||
		    (! xdr_u_int(xdrs, &mdcreate.count))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated mdcreate record"));
			goto out;
		}
		mdcreate.type = *type;
		if ((rc = (struct cachefs_log_mdcreate_record *)
		    calloc(1, sizeof (mdcreate))) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &mdcreate, sizeof (mdcreate));
		break;

	case CACHEFS_LOG_GPFRONT:
		if ((! xdr_int(xdrs, &gpfront.error)) ||
		    (! xdr_int(xdrs, (int *)&gpfront.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&gpfront.vfsp,
		    sizeof (gpfront.vfsp))) ||
		    (! xdr_opaque(xdrs, (caddr_t)&gpfront.fid,
		    sizeof (gpfront.fid))) ||
		    (! xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&gpfront.fileno)) ||
		    (! xdr_int(xdrs, (int *)&gpfront.uid)) ||
		    (! xdr_u_longlong_t(xdrs, (u_longlong_t *)&gpfront.off)) ||
		    (! xdr_u_int(xdrs, &gpfront.len))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated gpfront record"));
			goto out;
		}
		gpfront.type = *type;
		if ((rc = (struct cachefs_log_gpfront_record *)
		    calloc(1, sizeof (gpfront))) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &gpfront, sizeof (gpfront));
		break;

	case CACHEFS_LOG_RFDIR:
		if ((! xdr_int(xdrs, &rfdir.error)) ||
		    (! xdr_int(xdrs, (int *)&rfdir.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&rfdir.vfsp,
		    sizeof (rfdir.vfsp))) ||
		    (! xdr_opaque(xdrs, (caddr_t)&rfdir.fid,
		    sizeof (rfdir.fid))) ||
		    (! xdr_u_longlong_t(xdrs, (u_longlong_t *)&rfdir.fileno)) ||
		    (! xdr_int(xdrs, (int *)&rfdir.uid))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated rfdir record"));
			goto out;
		}
		rfdir.type = *type;
		if ((rc = (struct cachefs_log_rfdir_record *)
		    calloc(1, sizeof (rfdir))) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &rfdir, sizeof (rfdir));
		break;

	case CACHEFS_LOG_UALLOC:
		if ((! xdr_int(xdrs, &ualloc.error)) ||
		    (! xdr_int(xdrs, (int *)&ualloc.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&ualloc.vfsp,
		    sizeof (ualloc.vfsp))) ||
		    (! xdr_opaque(xdrs, (caddr_t)&ualloc.fid,
		    sizeof (ualloc.fid))) ||
		    (! xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&ualloc.fileno)) ||
		    (! xdr_u_longlong_t(xdrs, (u_longlong_t *)&ualloc.off)) ||
		    (! xdr_u_int(xdrs, &ualloc.len))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated ualloc record"));
			goto out;
		}
		ualloc.type = *type;
		if ((rc = (struct cachefs_log_ualloc_record *)
		    calloc(1, sizeof (ualloc))) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &ualloc, sizeof (ualloc));
		break;

	case CACHEFS_LOG_CALLOC:
		if ((! xdr_int(xdrs, &challoc.error)) ||
		    (! xdr_int(xdrs, (int *)&challoc.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&challoc.vfsp,
		    sizeof (challoc.vfsp))) ||
		    (! xdr_opaque(xdrs, (caddr_t)&challoc.fid,
		    sizeof (challoc.fid))) ||
		    (! xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&challoc.fileno)) ||
		    (! xdr_u_longlong_t(xdrs, (u_longlong_t *)&challoc.off)) ||
		    (! xdr_u_int(xdrs, &challoc.len))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated calloc record"));
			goto out;
		}
		challoc.type = *type;
		if ((rc = (struct cachefs_log_calloc_record *)
		    calloc(1, sizeof (challoc))) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &challoc, sizeof (challoc));
		break;

	case CACHEFS_LOG_NOCACHE:
		if ((! xdr_int(xdrs, &nocache.error)) ||
		    (! xdr_int(xdrs, (int *)&nocache.time)) ||
		    (! xdr_opaque(xdrs, (caddr_t)&nocache.vfsp,
		    sizeof (nocache.vfsp))) ||
		    (! xdr_opaque(xdrs, (caddr_t)&nocache.fid,
		    sizeof (nocache.fid))) ||
		    (! xdr_u_longlong_t(xdrs,
		    (u_longlong_t *)&nocache.fileno))) {
			stats_perror(st, SE_CORRUPT,
			    gettext("Truncated nocache record"));
			goto out;
		}
		nocache.type = *type;
		if ((rc = (struct cachefs_log_nocache_record *)
		    calloc(1, sizeof (nocache))) == NULL) {
			stats_perror(st, SE_NOMEM,
			    gettext("Cannot malloc record"));
			goto out;
		}
		memcpy(rc, &nocache, sizeof (nocache));
		break;

	default:
		stats_perror(st, SE_CORRUPT,
		    gettext("Corrupt logfile (position %x)"),
		    ftell(st->st_logstream));
		break;
	}

out:
	return (rc);
}

/*
 * convert a logfile record (read by stats_log_logfile_read()) to
 * ascii.  probably not for end-user consumption, but this should be
 * the official way to do it.
 */

char *
stats_log_record_toascii(stats_cookie_t *st, void *recp)
{
	int rectype = *((int *)recp);
	int recerror = *((int *)recp + 1);
	time_t tt = *((time_t *)((int *)recp + 2));
	struct tm *tm = localtime(&tt);
	char buffy[BUFSIZ], *fidstr, *fidstr2, *fidstr3;

	struct cachefs_log_mount_record *mountp;
	struct cachefs_log_umount_record *umountp;
	struct cachefs_log_getpage_record *getpagep;
	struct cachefs_log_readdir_record *readdirp;
	struct cachefs_log_readlink_record *readlinkp;
	struct cachefs_log_remove_record *removep;
	struct cachefs_log_rmdir_record *rmdirp;
	struct cachefs_log_truncate_record *truncatep;
	struct cachefs_log_putpage_record *putpagep;
	struct cachefs_log_create_record *createp;
	struct cachefs_log_mkdir_record *mkdirp;
	struct cachefs_log_rename_record *renamep;
	struct cachefs_log_symlink_record *symlinkp;
	struct cachefs_log_populate_record *populatep;
	struct cachefs_log_csymlink_record *csymlinkp;
	struct cachefs_log_filldir_record *filldirp;
	struct cachefs_log_mdcreate_record *mdcreatep;
	struct cachefs_log_gpfront_record *gpfrontp;
	struct cachefs_log_rfdir_record *rfdirp;
	struct cachefs_log_ualloc_record *uallocp;
	struct cachefs_log_calloc_record *callocp;
	struct cachefs_log_nocache_record *nocachep;

	assert(stats_good(st));

	(void) sprintf(st->st_asciirec, "%2d/%-2d %2d:%.2d %2d",
	    tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min,
	    recerror);

	switch (rectype) {
	case CACHEFS_LOG_MOUNT:
		mountp = (struct cachefs_log_mount_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %8x %d %d %s (%s)", "Mount", mountp->vfsp,
		    mountp->flags, mountp->popsize,
		    mountp->fgsize, mountp->path,
		    mountp->path + mountp->pathlen + 1);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		break;

	case CACHEFS_LOG_UMOUNT:
		umountp = (struct cachefs_log_umount_record *)recp;
		(void) snprintf(buffy, sizeof (buffy), " %-8s %llx",
		    "Umount", umountp->vfsp);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		break;

	case CACHEFS_LOG_GETPAGE:
		getpagep = (struct cachefs_log_getpage_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %s %llu %ld %llu %u",
		    "Getpage",
		    getpagep->vfsp, fidstr = stats_log_fmtfid(&getpagep->fid),
		    getpagep->fileno,
		    getpagep->uid, getpagep->offset, getpagep->len);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		free(fidstr);
		break;

	case CACHEFS_LOG_READDIR:
		readdirp = (struct cachefs_log_readdir_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %s %llu %d %llx %d", "Readdir",
		    readdirp->vfsp, fidstr = stats_log_fmtfid(&readdirp->fid),
		    readdirp->fileno,
		    readdirp->uid, readdirp->offset, readdirp->eof);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		free(fidstr);
		break;

	case CACHEFS_LOG_READLINK:
		readlinkp = (struct cachefs_log_readlink_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %s %llu %d %u", "Readlink",
		    readlinkp->vfsp,
		    fidstr = stats_log_fmtfid(&readlinkp->fid),
		    readlinkp->fileno,
		    readlinkp->uid, readlinkp->length);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		free(fidstr);
		break;

	case CACHEFS_LOG_REMOVE:
		removep = (struct cachefs_log_remove_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %s %llu %d", "Remove",
		    removep->vfsp, fidstr = stats_log_fmtfid(&removep->fid),
		    removep->fileno,
		    removep->uid);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		free(fidstr);
		break;

	case CACHEFS_LOG_RMDIR:
		rmdirp = (struct cachefs_log_rmdir_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %s %llu %d", "Rmdir",
		    rmdirp->vfsp, fidstr = stats_log_fmtfid(&rmdirp->fid),
		    rmdirp->fileno,
		    rmdirp->uid);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		free(fidstr);
		break;

	case CACHEFS_LOG_TRUNCATE:
		truncatep = (struct cachefs_log_truncate_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %s %llu %d %llu", "Truncate",
		    truncatep->vfsp,
		    fidstr = stats_log_fmtfid(&truncatep->fid),
		    truncatep->fileno,
		    truncatep->uid, truncatep->size);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		free(fidstr);
		break;

	case CACHEFS_LOG_PUTPAGE:
		putpagep = (struct cachefs_log_putpage_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %s %llu %d %llu %u", "Putpage",
		    putpagep->vfsp, fidstr = stats_log_fmtfid(&putpagep->fid),
		    putpagep->fileno,
		    putpagep->uid, putpagep->offset, putpagep->len);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		free(fidstr);
		break;

	case CACHEFS_LOG_CREATE:
		createp = (struct cachefs_log_create_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %s %llu %d", "Create",
		    createp->vfsp,
		    fidstr = stats_log_fmtfid(&createp->fid),
		    createp->fileno,
		    createp->uid);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		free(fidstr);
		break;

	case CACHEFS_LOG_MKDIR:
		mkdirp = (struct cachefs_log_mkdir_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %s %llu %d", "Mkdir",
		    mkdirp->vfsp,
		    fidstr = stats_log_fmtfid(&mkdirp->fid),
		    mkdirp->fileno,
		    mkdirp->uid);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		free(fidstr);
		break;

	case CACHEFS_LOG_RENAME:
		renamep = (struct cachefs_log_rename_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %s %llu %d %d", "Rename",
		    renamep->vfsp,
		    fidstr = stats_log_fmtfid(&renamep->gone),
		    renamep->fileno,
		    renamep->removed, renamep->uid);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		free(fidstr);
		break;

	case CACHEFS_LOG_SYMLINK:
		symlinkp = (struct cachefs_log_symlink_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %s %llu %d %u", "Symlink",
		    symlinkp->vfsp,
		    fidstr = stats_log_fmtfid(&symlinkp->fid),
		    symlinkp->fileno,
		    symlinkp->uid, symlinkp->size);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		free(fidstr);
		break;

	case CACHEFS_LOG_POPULATE:
		populatep = (struct cachefs_log_populate_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %s %llu %llu %d", "Populate",
		    populatep->vfsp,
		    fidstr = stats_log_fmtfid(&populatep->fid),
		    populatep->fileno,
		    populatep->off, populatep->size);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		free(fidstr);
		break;

	case CACHEFS_LOG_CSYMLINK:
		csymlinkp = (struct cachefs_log_csymlink_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %s %llu %d", "Csymlink",
		    csymlinkp->vfsp,
		    fidstr = stats_log_fmtfid(&csymlinkp->fid),
		    csymlinkp->fileno,
		    csymlinkp->size);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		free(fidstr);
		break;

	case CACHEFS_LOG_FILLDIR:
		filldirp = (struct cachefs_log_filldir_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %s %llu %d", "Filldir",
		    filldirp->vfsp,
		    fidstr = stats_log_fmtfid(&filldirp->fid),
		    filldirp->fileno,
		    filldirp->size);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		free(fidstr);
		break;

	case CACHEFS_LOG_MDCREATE:
		mdcreatep = (struct cachefs_log_mdcreate_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %s %llu %u", "Mdcreate",
		    mdcreatep->vfsp,
		    fidstr = stats_log_fmtfid(&mdcreatep->fid),
		    mdcreatep->fileno, mdcreatep->count);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		free(fidstr);
		break;

	case CACHEFS_LOG_GPFRONT:
		gpfrontp = (struct cachefs_log_gpfront_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %s %llu %d %llu %u", "Gpfront",
		    gpfrontp->vfsp,
		    fidstr = stats_log_fmtfid(&gpfrontp->fid),
		    gpfrontp->fileno,
		    gpfrontp->uid, gpfrontp->off, gpfrontp->len);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		free(fidstr);
		break;

	case CACHEFS_LOG_RFDIR:
		rfdirp = (struct cachefs_log_rfdir_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %s %llu %d", "Rfdir",
		    rfdirp->vfsp,
		    fidstr = stats_log_fmtfid(&rfdirp->fid),
		    rfdirp->fileno,
		    rfdirp->uid);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		free(fidstr);
		break;

	case CACHEFS_LOG_UALLOC:
		uallocp = (struct cachefs_log_ualloc_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %s %llu %llu %u", "Ualloc",
		    uallocp->vfsp,
		    fidstr = stats_log_fmtfid(&uallocp->fid),
		    uallocp->fileno,
		    uallocp->off, uallocp->len);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		free(fidstr);
		break;

	case CACHEFS_LOG_CALLOC:
		callocp = (struct cachefs_log_calloc_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %s %llu %llu %u", "Calloc",
		    callocp->vfsp,
		    fidstr = stats_log_fmtfid(&callocp->fid),
		    callocp->fileno, callocp->off, callocp->len);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		free(fidstr);
		break;

	case CACHEFS_LOG_NOCACHE:
		nocachep = (struct cachefs_log_nocache_record *)recp;
		(void) snprintf(buffy, sizeof (buffy),
		    " %-8s %llx %s %llu", "Nocache",
		    nocachep->vfsp,
		    fidstr = stats_log_fmtfid(&nocachep->fid),
		    nocachep->fileno);
		(void) strlcat(st->st_asciirec, buffy,
		    sizeof (st->st_asciirec));
		free(fidstr);
		break;

	default:
		stats_perror(st, SE_CORRUPT,
		    gettext(
		    "Attempt to format invalid log type=%d (position %x)"),
		    rectype, ftell(st->st_logstream));
		return (NULL);
	}

	return (st->st_asciirec);
}

uint_t
stats_log_get_record_info(stats_cookie_t *sc,
    void *recp, caddr_t *vfsp, cfs_fid_t **fidp, ino64_t *filenop,
    u_offset_t *offp, u_offset_t *lenp)
{
	int type = ((int *)recp)[0];
	int error = ((int *)recp)[1];
	uint_t rc = 0;

	struct cachefs_log_getpage_record *getpagep;
	struct cachefs_log_readdir_record *readdirp;
	struct cachefs_log_readlink_record *readlinkp;
	struct cachefs_log_remove_record *removep;
	struct cachefs_log_rmdir_record *rmdirp;
	struct cachefs_log_truncate_record *truncatep;
	struct cachefs_log_putpage_record *putpagep;
	struct cachefs_log_create_record *createp;
	struct cachefs_log_mkdir_record *mkdirp;
	struct cachefs_log_rename_record *renamep;
	struct cachefs_log_symlink_record *symlinkp;
	struct cachefs_log_populate_record *populatep;
	struct cachefs_log_csymlink_record *csymlinkp;
	struct cachefs_log_filldir_record *filldirp;
	struct cachefs_log_mdcreate_record *mdcreatep;
	struct cachefs_log_gpfront_record *gpfrontp;
	struct cachefs_log_rfdir_record *rfdirp;
	struct cachefs_log_ualloc_record *uallocp;
	struct cachefs_log_calloc_record *callocp;
	struct cachefs_log_nocache_record *nocachep;

	switch (type) {
	case CACHEFS_LOG_RFDIR:
		if ((error == EINVAL) || (error == ENOENT))
			error = 0;
		break;
	}

	if (error != 0)
		return (0);

	switch (type) {
	case CACHEFS_LOG_GETPAGE:
		getpagep = (struct cachefs_log_getpage_record *)recp;
		*fidp = &getpagep->fid;
		*filenop = getpagep->fileno;
		*vfsp = (caddr_t)(uintptr_t)getpagep->vfsp;
		*offp = getpagep->offset;
		*lenp = (u_offset_t)getpagep->len;
		rc = (GRI_ADD | GRI_EXPENSIVE);
		break;

	case CACHEFS_LOG_READDIR:
		readdirp = (struct cachefs_log_readdir_record *)recp;
		*fidp = &readdirp->fid;
		*filenop = readdirp->fileno;
		*vfsp = (caddr_t)(uintptr_t)readdirp->vfsp;
		*offp = readdirp->offset;
		*lenp = (u_offset_t)sc->st_loghead.lh_maxbsize;
		rc = (GRI_ADD | GRI_EXPENSIVE);
		break;

	case CACHEFS_LOG_READLINK:
		readlinkp = (struct cachefs_log_readlink_record *)recp;
		*fidp = &readlinkp->fid;
		*filenop = readlinkp->fileno;
		*vfsp = (caddr_t)(uintptr_t)readlinkp->vfsp;
		*offp = 0LL;
		*lenp = (u_offset_t)((readlinkp->length > C_FSL_SIZE) ?
		    readlinkp->length : 0);
		rc = (GRI_ADD | GRI_EXPENSIVE);
		break;

	case CACHEFS_LOG_REMOVE:
		removep = (struct cachefs_log_remove_record *)recp;
		*fidp = &removep->fid;
		*filenop = removep->fileno;
		*vfsp = (caddr_t)(uintptr_t)removep->vfsp;
		*offp = *lenp = 0LL;
		rc = (GRI_TRUNC | GRI_MODIFY);
		break;

	case CACHEFS_LOG_RMDIR:
		rmdirp = (struct cachefs_log_rmdir_record *)recp;
		*fidp = &rmdirp->fid;
		*filenop = rmdirp->fileno;
		*vfsp = (caddr_t)(uintptr_t)rmdirp->vfsp;
		*offp = *lenp = 0LL;
		rc = (GRI_TRUNC | GRI_MODIFY);
		break;

	case CACHEFS_LOG_TRUNCATE:
		truncatep = (struct cachefs_log_truncate_record *)recp;
		*fidp = &truncatep->fid;
		*filenop = truncatep->fileno;
		*vfsp = (caddr_t)(uintptr_t)truncatep->vfsp;
		*offp = 0LL;
		*lenp = truncatep->size;
		rc = (GRI_TRUNC | GRI_MODIFY);
		break;

	case CACHEFS_LOG_PUTPAGE:
		putpagep = (struct cachefs_log_putpage_record *)recp;
		*fidp = &putpagep->fid;
		*filenop = putpagep->fileno;
		*vfsp = (caddr_t)(uintptr_t)putpagep->vfsp;
		*offp = putpagep->offset;
		*lenp = (u_offset_t)putpagep->len;
		rc = (GRI_ADD | GRI_MODIFY);
		break;

	case CACHEFS_LOG_CREATE:
		createp = (struct cachefs_log_create_record *)recp;
		*fidp = &createp->fid;
		*filenop = createp->fileno;
		*vfsp = (caddr_t)(uintptr_t)createp->vfsp;
		*offp = *lenp = 0LL;
		rc = (GRI_ADD | GRI_MODIFY);
		break;

	case CACHEFS_LOG_MKDIR:
		mkdirp = (struct cachefs_log_mkdir_record *)recp;
		*fidp = &mkdirp->fid;
		*filenop = mkdirp->fileno;
		*vfsp = (caddr_t)(uintptr_t)mkdirp->vfsp;
		*offp = *lenp = 0LL;
		rc = (GRI_ADD | GRI_MODIFY);
		break;

	case CACHEFS_LOG_RENAME:
		renamep = (struct cachefs_log_rename_record *)recp;
		*fidp = &renamep->gone;
		*filenop = renamep->fileno;
		*vfsp = (caddr_t)(uintptr_t)renamep->vfsp;
		*offp = *lenp = 0LL;
		rc = GRI_MODIFY;
		if (renamep->removed)
			rc |= GRI_TRUNC;
		break;

	case CACHEFS_LOG_SYMLINK:
		symlinkp = (struct cachefs_log_symlink_record *)recp;
		*fidp = &symlinkp->fid;
		*filenop = symlinkp->fileno;
		*vfsp = (caddr_t)(uintptr_t)symlinkp->vfsp;
		*offp = 0LL;
		*lenp = (u_offset_t)((symlinkp->size > C_FSL_SIZE) ?
		    symlinkp->size : 0);
		rc = (GRI_ADD | GRI_MODIFY);
		break;

	case CACHEFS_LOG_POPULATE:
		populatep = (struct cachefs_log_populate_record *)recp;
		*fidp = &populatep->fid;
		*filenop = populatep->fileno;
		*vfsp = (caddr_t)(uintptr_t)populatep->vfsp;
		*offp = populatep->off;
		*lenp = (u_offset_t)populatep->size;
		rc = GRI_ADD;
		break;

	case CACHEFS_LOG_CSYMLINK:
		csymlinkp = (struct cachefs_log_csymlink_record *)recp;
		*fidp = &csymlinkp->fid;
		*filenop = csymlinkp->fileno;
		*vfsp = (caddr_t)(uintptr_t)csymlinkp->vfsp;
		*offp = 0LL;
		*lenp = (u_offset_t)((csymlinkp->size > C_FSL_SIZE) ?
		    csymlinkp->size : 0);
		rc = GRI_ADD;
		break;

	case CACHEFS_LOG_FILLDIR:
		filldirp = (struct cachefs_log_filldir_record *)recp;
		*fidp = &filldirp->fid;
		*filenop = filldirp->fileno;
		*vfsp = (caddr_t)(uintptr_t)filldirp->vfsp;
		*offp = 0LL;
		*lenp = (u_offset_t)(filldirp->size);
		rc = GRI_ADD;
		break;

	case CACHEFS_LOG_MDCREATE:
		mdcreatep = (struct cachefs_log_mdcreate_record *)recp;
		*fidp = &mdcreatep->fid;
		*filenop = mdcreatep->fileno;
		*vfsp = (caddr_t)(uintptr_t)mdcreatep->vfsp;
		*lenp = (u_offset_t)mdcreatep->count;
		rc = GRI_METADATA;
		break;

	case CACHEFS_LOG_GPFRONT:
		gpfrontp = (struct cachefs_log_gpfront_record *)recp;
		*fidp = &gpfrontp->fid;
		*filenop = gpfrontp->fileno;
		*vfsp = (caddr_t)(uintptr_t)gpfrontp->vfsp;
		*offp = gpfrontp->off;
		*lenp = (u_offset_t)sc->st_loghead.lh_pagesize;
		rc = (GRI_ADD | GRI_EXPENSIVE);
		break;

	case CACHEFS_LOG_RFDIR:
		rfdirp = (struct cachefs_log_rfdir_record *)recp;
		rfdirp->error = 0;
		*fidp = &rfdirp->fid;
		*filenop = rfdirp->fileno;
		*vfsp = (caddr_t)(uintptr_t)rfdirp->vfsp;
		*offp = 0LL;
		*lenp = (u_offset_t)sc->st_loghead.lh_maxbsize;
		rc = (GRI_ADD | GRI_EXPENSIVE);
		break;

	case CACHEFS_LOG_UALLOC:
		uallocp = (struct cachefs_log_ualloc_record *)recp;
		*fidp = &uallocp->fid;
		*filenop = uallocp->fileno;
		*vfsp = (caddr_t)(uintptr_t)uallocp->vfsp;
		*offp = uallocp->off;
		*lenp = (u_offset_t)uallocp->len;
		rc = (GRI_ADD);
		break;

	case CACHEFS_LOG_CALLOC:
		callocp = (struct cachefs_log_calloc_record *)recp;
		*fidp = &callocp->fid;
		*filenop = callocp->fileno;
		*vfsp = (caddr_t)(uintptr_t)callocp->vfsp;
		*offp = callocp->off;
		*lenp = (u_offset_t)callocp->len;
		rc = (GRI_ADD | GRI_EXPENSIVE);
		break;

	case CACHEFS_LOG_NOCACHE:
		nocachep = (struct cachefs_log_nocache_record *)recp;
		*fidp = &nocachep->fid;
		*filenop = nocachep->fileno;
		*vfsp = (caddr_t)(uintptr_t)nocachep->vfsp;
		*offp = *lenp = 0LL;
		rc = (GRI_TRUNC);
		break;
	}

	return (rc);
}

/*
 * ascii formatter for fids.  returns a malloc()ed string -- it's up to
 * the caller to free it.
 */

static char *
stats_log_fmtfid(cfs_fid_t *fidp)
{
	char buffy[BUFSIZ], *rc;

(void) strcpy(buffy, "<fid>");

	rc = strdup(buffy);
	if (rc == NULL)
		rc = "out of memory";

	return (rc);
}

void
stats_log_fi_add(stats_cookie_t *st, fid_info *fip, u_offset_t off,
u_offset_t len)
{
	int i, j;
	u_offset_t iend, jend, tmp;

	assert(stats_good(st));
	assert(st->st_flags & ST_DBMOPEN);
	assert(st->st_flags & ST_LFOPEN);

	/* shortcut if we had some sort of zero-length thing */

	if (len == 0LL)
		return;

	/* `smear' the offset and length to block boundaries */

	/*
	 * pre-largefiles: iend = off & ~(st->st_loghead.lh_maxbsize - 1);
	 * largefiles:  make sure that we ~ all bits in the 64 bit
	 * version of (st->st_loghead.lh_maxbsize - 1)
	 */
	tmp = (u_offset_t)(st->st_loghead.lh_maxbsize - 1);
	iend = off & ~tmp;

	jend = off + len;
	jend += (u_offset_t)(st->st_loghead.lh_maxbsize - 1);
	/*
	 * pre-largefiles:  jend &= ~(st->st_loghead.lh_maxbsize - 1);
	 * largefiles: make sure that we ~ all bits in the 64 bit
	 * version of (st->st_loghead.lh_maxbsize - 1)
	 */
	jend &= ~tmp;

	off = iend;
	len = jend - off;

	/* see if our offset falls within an existing chunk */
	for (i = 0; i < fip->fi_ent_n; i++) {
		iend = fip->fi_ent[i].offset + fip->fi_ent[i].len;
		if ((fip->fi_ent[i].offset <= off) && (iend >= off))
			break;
	}

	/* update the chunk, or make a new one */
	if (i < fip->fi_ent_n) {
		if ((off + len) > iend)
			fip->fi_ent[i].len = off + len - fip->fi_ent[i].offset;
	} else if (i < C_MAX_ALLOCINFO_SLOTS) {
		fip->fi_ent_n = i + 1;
		fip->fi_ent[i].offset = off;
		fip->fi_ent[i].len = len;
	} else {
		/* cachefs does a nocache, so we'll immitate */

		/*
		 * XXX we're free to grow again.  assume we got
		 * inactivated right away -- the worst case!
		 */

		fip->fi_ent_n = 0;
		fip->fi_total = 0LL;
	}

	/* quit for the trivial (hopefully the usual) case... */
	if (fip->fi_ent_n <= 1) {
		if (fip->fi_ent_n == 0)
			fip->fi_total = 0LL;
		else
			fip->fi_total = fip->fi_ent[0].len;
		return;
	}

	/*
	 * we have to see if we can consolidate any chunks.  the
	 * chunks aren't guaranteed to be in any kind of order, so we
	 * do a qsort.  otherwise, the consolidation would be N^2 (but
	 * we're probably close here).
	 */

	qsort(fip->fi_ent, fip->fi_ent_n, sizeof (fip->fi_ent[0]),
	    stats_log_fi_comp);

	/* tag non-essential entries with offset == -1, and consolidate */
	for (i = 0; i < fip->fi_ent_n - 1; i++) {
		if ((offset_t)fip->fi_ent[i].offset < 0)
			continue;
		iend = fip->fi_ent[i].offset + fip->fi_ent[i].len;

		for (j = i + 1; j < fip->fi_ent_n; j++) {
			if (iend < fip->fi_ent[j].offset)
				break;
			jend = fip->fi_ent[j].offset + fip->fi_ent[j].len;
			if (jend >= iend)
				fip->fi_ent[i].len =
				    jend - fip->fi_ent[i].offset;
			fip->fi_ent[j].offset = (u_offset_t)-1;
		}
	}

	/* get rid of non-essential entries (without preserving order) */
	for (i = 0; i < fip->fi_ent_n; i++)
		if ((offset_t)fip->fi_ent[i].offset < 0)
			fip->fi_ent[i--] = fip->fi_ent[--(fip->fi_ent_n)];

	/* add up the new total size */
	for (i = fip->fi_total = 0LL; i < fip->fi_ent_n; i++)
		fip->fi_total += fip->fi_ent[i].len;
}

static int
stats_log_fi_comp(const void *a, const void *b)
{
	struct fid_info_allocent *fa = (struct fid_info_allocent *)a;
	struct fid_info_allocent *fb = (struct fid_info_allocent *)b;

	if ((offset_t)(fa->offset - fb->offset) > 0)
		return (1);
	if ((offset_t)(fa->offset - fb->offset) < 0)
		return (-1);
	return (0);
}

void
stats_log_fi_trunc(stats_cookie_t *st, fid_info *fip, u_offset_t off,
u_offset_t len)
{
	fip->fi_ent_n = 1;
	fip->fi_ent[0].offset = off;
	fip->fi_ent[0].len = len;
	fip->fi_total = len;
}

struct cachefs_log_logfile_header *
stats_log_getheader(stats_cookie_t *st)
{
	assert(stats_good(st));
	assert(st->st_flags & ST_LFOPEN);

	return (&st->st_loghead);
}

void
stats_log_compute_wssize(stats_cookie_t *st)
{
	void *record;
	int type;
	struct cachefs_log_mount_record *mountp;
	struct cachefs_log_umount_record *umountp;
	datum key;
	caddr_t vfsp;
	mount_info *mi = NULL, *mip;
	size_t len1, len2, maxlen;
	char *string1, *string2;
	uint_t rflags;
	fid_info fi, *fip;
	cfs_fid_t *fidp;
	ino64_t fileno;
	u_offset_t off;
	u_offset_t len;
	struct cachefs_log_logfile_header *lh = &st->st_loghead;
	size_t delta;

	assert(stats_good(st));
	assert(st->st_flags & ST_LFOPEN);
	assert(st->st_flags & ST_DBMOPEN);

	/*
	 * The maximum size of a mount_info structure is the size of
	 * the structure less the space already defined for char mi_path[]
	 * plus the maximum size of mi_path.
	 *
	 * Additional space is allocated to mi_path at runtime using
	 * malloc(). The size needs to be calculated in-situ as ANSI C
	 * will only allow 'sizeof expression' or 'sizeof (type)'.
	 */

	mi = malloc(sizeof (*mi) - sizeof (mi->mi_path) + MI_MAX_MI_PATH);
	if (mi == NULL) {
		stats_perror(st, SE_NOMEM, gettext("Out of memory"));
		goto out;
	}

	st->st_ws_init = st->st_loghead.lh_blocks;

	while (record = stats_log_logfile_read(st, &type)) {
		switch (type) {
		case CACHEFS_LOG_MOUNT:
			mountp = (struct cachefs_log_mount_record *)record;
			if (mountp->error != 0)
				break;
			for (key = stats_dbm_firstkey(st);
			    key.dptr != NULL;
			    key = stats_dbm_nextkey(st)) {
				if (key.dsize != sizeof (vfsp))
					continue;

				memcpy((caddr_t)&vfsp, key.dptr,
				    sizeof (vfsp));
				mip = stats_dbm_fetch_byvfsp(st, vfsp);
				if (mip == NULL)
					continue;

				len1 = strlen(mip->mi_path);
				len2 = strlen(mip->mi_path + len1 + 1);
				memcpy((caddr_t)mi, mip, sizeof (*mi) +
				    len1 + len2 - CLPAD(mount_info, mi_path));
				free(mip);

				string1 = mi->mi_path + len1 + 1;
				string2 = mountp->path + mountp->pathlen + 1;
				if (strcmp(string1, string2) == 0) {
					stats_dbm_delete_byvfsp(st, vfsp);
					break;
				}
			}
			if (key.dptr == NULL) {
				/* non-idempotent setup stuff */
				memset(mi, '\0', sizeof (*mi));
				mi->mi_flags = mountp->flags;
				mi->mi_filegrp_size = mountp->fgsize;
			}

			/*
			 * idempotent setup stuff
			 *
			 * Careful string handling around mi_path
			 * is required as it contains two NULL
			 * terminated strings.
			 */

			mi->mi_mounted = 1;
			maxlen = MI_MAX_MI_PATH - 1;
			len1 = strlcpy(mi->mi_path, mountp->path, maxlen);
			if (len1 >= maxlen) {
				stats_perror(st, SE_CORRUPT,
				    gettext("Path too long in log file"));
				break;
			}

			len1 = strlen(mi->mi_path);
			maxlen = MI_MAX_MI_PATH - (len1 + 1);
			len2 = strlcpy(mi->mi_path + len1 + 1,
			    mountp->path + mountp->pathlen + 1, maxlen);
			if (len2 >= maxlen) {
				stats_perror(st, SE_CORRUPT,
				    gettext("CacheID too long in log file"));
				break;
			}

			stats_dbm_store_byvfsp(st,
					(caddr_t)(uintptr_t)mountp->vfsp, mi);
			break;

		case CACHEFS_LOG_UMOUNT:
			umountp = (struct cachefs_log_umount_record *)record;
			if (umountp->error != 0)
				break;
			mip = stats_dbm_fetch_byvfsp(st,
					(caddr_t)(uintptr_t)umountp->vfsp);
			if (mip == NULL)
				break;
			mip->mi_mounted = 0;
			stats_dbm_store_byvfsp(st,
					(caddr_t)(uintptr_t)umountp->vfsp, mip);
			free(mip);
			break;

		default:
			rflags = stats_log_get_record_info(st, record,
			    &vfsp, &fidp, &fileno, &off, &len);
			if (rflags == 0) /* shortcut */
				break;

			mip = stats_dbm_fetch_byvfsp(st, vfsp);
			if (mip == NULL) /* hopefully very rare */
				break;

			fip = stats_dbm_fetch_byfid(st, fidp);
			if (fip == NULL) {
				fip = &fi;
				memset(&fi, '\0', sizeof (fi));
				fi.fi_vfsp = vfsp;
			}

			/* account for the creation of the fscache */
			if (! mip->mi_used) {
				mip->mi_used = 1;

				/* account for the .cfs_option file */
				mip->mi_current += (u_offset_t)lh->lh_maxbsize;
				st->st_ws_current +=
				    (u_offset_t)lh->lh_maxbsize;
			}

			/*
			 * Add in the size-growth of the attrcache.
			 * len will be non-zero only for the record type
			 * CACHEFS_LOG_MDCREATE, and len can't be > 2GB because
			 * it refers to the number of entries in
			 * the attribute cache file.
			 */
			assert(len <= UINT_MAX);
			delta = stats_dbm_attrcache_addsize(st, mip, fileno,
			    (type == CACHEFS_LOG_MDCREATE) ? (uint_t)len : 0);
			st->st_ws_current += (u_offset_t)delta;
			mip->mi_current += (u_offset_t)delta;

			/* see if this is an `expensive' logfile */
			if ((! st->st_ws_expensive) && (rflags & GRI_EXPENSIVE))
				st->st_ws_expensive = 1;

			/* subtract current frontfile size ... */
			st->st_ws_current -= fip->fi_total;
			mip->mi_current -= fip->fi_total;

			/* compute new frontfile size */
			if ((mip->mi_flags & CFS_WRITE_AROUND) &&
			    (rflags & GRI_MODIFY)) {
				fip->fi_total = 0LL;
				fip->fi_ent_n = 0;
			} else if (rflags & GRI_ADD) {
				stats_log_fi_add(st, fip, off, len);
			} else if (rflags & GRI_TRUNC) {
				stats_log_fi_trunc(st, fip, off, len);
			}
			if (rflags & GRI_METADATA)
				fip->fi_flags |= FI_METADATA;

			/* add back in new frontfile size */
			mip->mi_current += fip->fi_total;
			if (mip->mi_current > mip->mi_high)
				mip->mi_high = mip->mi_current;
			stats_dbm_store_byvfsp(st, vfsp, mip);
			free(mip);
			st->st_ws_current += fip->fi_total;
			if (st->st_ws_current > st->st_ws_high)
				st->st_ws_high = st->st_ws_current;

			stats_dbm_store_byfid(st, fidp, fip);
			if (fip != &fi)
				free(fip);
			break;
		}

		free(record);

		if (stats_inerror(st))
			break;
	}

out:
	if (mi != NULL)
		free(mi);
	if (! stats_inerror(st))
		st->st_flags |= ST_WSCOMP;
}

int
stats_log_wssize_init(stats_cookie_t *st)
{
	assert(stats_good(st));
	assert(st->st_flags & ST_WSCOMP);

	return (st->st_ws_init);
}

u_offset_t
stats_log_wssize_current(stats_cookie_t *st)
{
	assert(stats_good(st));
	assert(st->st_flags & ST_WSCOMP);

	return (st->st_ws_current);
}

u_offset_t
stats_log_wssize_high(stats_cookie_t *st)
{
	assert(stats_good(st));
	assert(st->st_flags & ST_WSCOMP);

	return (st->st_ws_high);
}


int
stats_log_wssize_expensive(stats_cookie_t *st)
{
	assert(stats_good(st));
	assert(st->st_flags & ST_WSCOMP);

	return (st->st_ws_expensive);
}
