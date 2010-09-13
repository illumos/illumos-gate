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
 * Copyright (c) 1996-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *
 *			stats_dbm.c
 *
 * Routines for dbm access.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/param.h>
#include <fcntl.h>
#include <libintl.h>
#include <time.h>
#include <string.h>
#include <sys/fs/cachefs_fs.h>
#include "stats.h"
#include <assert.h>
#include <ndbm.h>

void
stats_dbm_open(stats_cookie_t *st)
{
	char *tmpdir;
	pid_t	getpid();

	assert(stats_good(st));
	assert(! (st->st_flags & ST_DBMOPEN));

	if ((tmpdir = getenv("TMPDIR")) == NULL)
		tmpdir = "/tmp";

	(void) snprintf(st->st_dbm_name, sizeof (st->st_dbm_name), "%s/%s-%d",
	    tmpdir, st->st_progname, getpid());
	st->st_dbm = dbm_open(st->st_dbm_name, O_RDWR | O_CREAT, 0666);
	if (st->st_dbm == NULL) {
		stats_perror(st, SE_FILE,
		    gettext("Cannot open dbm file %s"), st->st_dbm_name);
		return;
	}

	st->st_flags |= ST_DBMOPEN;
}

void
stats_dbm_rm(stats_cookie_t *st)
{
	char buffy[MAXPATHLEN], *eobase;
	int unlink(), buflen, eobaselen;

	assert(stats_good(st));

	if (! (st->st_flags & ST_DBMOPEN))
		return;

	if (strlcpy(buffy, st->st_dbm_name, sizeof (buffy)) >
	    ((sizeof (buffy)) - (sizeof (".xxx"))))
		return; /* No space for the file extensions */
	buflen = strlen(buffy);
	eobase = buffy + buflen;
	eobaselen = (sizeof (buffy)) - buflen;

	(void) strlcpy(eobase, ".dir", eobaselen);
	(void) unlink(buffy);

	(void) strlcpy(eobase, ".pag", eobaselen);
	(void) unlink(buffy);
}

void
stats_dbm_close(stats_cookie_t *st)
{
	assert(stats_good(st));

	if (! (st->st_flags & ST_DBMOPEN))
		return;

	st->st_flags &= ~ST_DBMOPEN;

	if (st->st_dbm == NULL)
		return;

	dbm_close(st->st_dbm);
}

fid_info *
stats_dbm_fetch_byfid(stats_cookie_t *st, cfs_fid_t *fidp)
{
	datum key, value;
	fid_info *rc;

	assert(stats_good(st));
	assert(st->st_flags & ST_DBMOPEN);

	key.dptr = (char *)fidp;
	key.dsize = sizeof (*fidp);
	value = dbm_fetch(st->st_dbm, key);

	assert((value.dptr == NULL) || (value.dsize == sizeof (fid_info)));
	if (value.dptr == NULL)
		return (NULL);

	if ((rc = malloc(sizeof (*rc))) == NULL) {
		stats_perror(st, SE_NOMEM,
		    gettext("Cannot malloc memory for fid_info record"));
		return (NULL);
	}

	memcpy(rc, value.dptr, sizeof (*rc));
	if (rc->fi_magic != FI_MAGIC) {
		free(rc);
		return (NULL);
	}

	return (rc);
}

void
stats_dbm_store_byfid(stats_cookie_t *st, cfs_fid_t *fidp, fid_info *fi)
{
	datum key, value;

	assert(stats_good(st));
	assert(st->st_flags & ST_DBMOPEN);

	fi->fi_magic = FI_MAGIC;

	key.dptr = (char *)fidp;
	key.dsize = sizeof (*fidp);

	value.dptr = (char *)fi;
	value.dsize = sizeof (*fi);

	if (dbm_store(st->st_dbm, key, value, DBM_REPLACE) != 0) {
		stats_perror(st, SE_FILE,
		    gettext("Cannot store fid info"));
		return;
	}
}

mount_info *
stats_dbm_fetch_byvfsp(stats_cookie_t *st, caddr_t vfsp)
{
	mount_info *rc, *mi;
	int len1, len2, size;

	datum key, value;

	assert(stats_good(st));
	assert(st->st_flags & ST_DBMOPEN);

	key.dptr = (char *)&vfsp;
	key.dsize = sizeof (vfsp);
	value = dbm_fetch(st->st_dbm, key);

	if (value.dptr == NULL)
		return (NULL);

	mi = (mount_info *)value.dptr;

	len1 = strlen(mi->mi_path);
	len2 = strlen(mi->mi_path + len1 + 1);
	size = sizeof (*rc) + len1 + len2 - CLPAD(mount_info, mi_path);

	if ((rc = malloc(size)) == NULL) {
		stats_perror(st, SE_NOMEM,
		    gettext("Cannot malloc memory for mountinfo"));
		return (NULL);
	}
	memcpy(rc, mi, size);

	if (rc->mi_magic != MI_MAGIC) {
		free(rc);
		return (NULL);
	}

	return (rc);
}

void
stats_dbm_store_byvfsp(stats_cookie_t *st, caddr_t vfsp, mount_info *mi)
{
	datum key, value;
	int len1, len2;

	assert(stats_good(st));
	assert(st->st_flags & ST_DBMOPEN);

	mi->mi_magic = MI_MAGIC;

	key.dptr = (char *)&vfsp;
	key.dsize = sizeof (vfsp);

	len1 = strlen(mi->mi_path);
	len2 = strlen(mi->mi_path + len1 + 1);
	value.dptr = (char *)mi;
	value.dsize = sizeof (*mi) +
	    len1 + len2 -
	    CLPAD(mount_info, mi_path);

	if (dbm_store(st->st_dbm, key, value, DBM_REPLACE) != 0) {
		stats_perror(st, SE_FILE,
		    gettext("Cannot store mount info"));
		return;
	}
}

void
stats_dbm_delete_byvfsp(stats_cookie_t *st, caddr_t vfsp)
{
	datum key;

	assert(stats_good(st));
	assert(st->st_flags & ST_DBMOPEN);

	key.dptr = (caddr_t)&vfsp;
	key.dsize = sizeof (vfsp);

	(void) dbm_delete(st->st_dbm, key);
}

datum
stats_dbm_firstkey(stats_cookie_t *st)
{
	assert(stats_good(st));
	assert(st->st_flags & ST_DBMOPEN);

	return (dbm_firstkey(st->st_dbm));
}

datum
stats_dbm_nextkey(stats_cookie_t *st)
{
	assert(stats_good(st));
	assert(st->st_flags & ST_DBMOPEN);

	return (dbm_nextkey(st->st_dbm));
}

/*
 * count var will be non-zero only for the record type CACHEFS_LOG_MDCREATE
 * and count can't be >2GB because it refers to the number of entries in
 * the attribute cache file.
 */
size_t
stats_dbm_attrcache_addsize(stats_cookie_t *st, mount_info *mi,
    ino64_t fileno, uint_t count)
{
	char keystring[BUFSIZ];
	datum key, value;
	char *cacheid;
	fg_info fg, *fgp = NULL;
	size_t size = 0, overhead = 0;
	uchar_t tbits;
	int i;
	uint_t gfileno;

	assert(stats_good(st));
	assert(st->st_flags & ST_DBMOPEN);

	/* look up any known data about this filegrp */
	cacheid = mi->mi_path + strlen(mi->mi_path) + 1;
	(void) snprintf(keystring, sizeof (keystring), "%s.%lld", cacheid,
	    fileno / (ino64_t)mi->mi_filegrp_size);
	gfileno = (uint_t)(fileno % (ino64_t)mi->mi_filegrp_size);
	key.dsize = strlen(keystring); /* no need to null terminate */
	key.dptr = keystring;
	value = dbm_fetch(st->st_dbm, key);

	size = sizeof (struct attrcache_header);
	size += mi->mi_filegrp_size * sizeof (struct attrcache_index);
	size += mi->mi_filegrp_size / NBBY;

	if ((value.dptr != NULL) && (value.dsize == sizeof (fg))) {
		/* align the structure */
		memcpy((char *)&fg, value.dptr, sizeof (fg));
		fgp = &fg;
		if (fgp->fg_magic != FG_MAGIC)
			fgp = NULL; /* oops -- key collision! */
	}

	/* if we haven't seen this filegrp yet */
	if (fgp == NULL) {
		memset((char *)&fg, '\0', sizeof (fg));
		fgp = &fg;
		fgp->fg_magic = FG_MAGIC;

		/* filegrp frontfile directory */
		overhead += st->st_loghead.lh_maxbsize;
	}

	/* high-water the given count (if any) with our known count */
	if (count > fgp->fg_count)
		fgp->fg_count = count;

	/* set a bit for this file */
	if ((gfileno / NBBY) < sizeof (fgp->fg_bits)) {
		tbits = 1 << (gfileno % NBBY);
		if (! (fgp->fg_bits[gfileno / NBBY] & tbits))
			fgp->fg_bcount++;
		fgp->fg_bits[gfileno / NBBY] |= tbits;
	}

	/* high-water our derived count with our known count */
	if (fgp->fg_bcount > fgp->fg_count)
		fgp->fg_count = fgp->fg_bcount;

	/* account for the size of all known attrcache entries */
	size += fgp->fg_count * sizeof (struct cachefs_metadata);

	/* round to the ceiling block boundary */
	size += st->st_loghead.lh_maxbsize - 1;
	size &= ~ (st->st_loghead.lh_maxbsize - 1);

	/* sneaky :-) -- high-water fg_size, and make size the delta */
	size -= fgp->fg_size;
	fgp->fg_size += size;

	value.dptr = (char *)fgp;
	value.dsize = sizeof (*fgp);
	if (dbm_store(st->st_dbm, key, value, DBM_REPLACE) != 0)
		stats_perror(st, SE_FILE,
		    gettext("Cannot store attrcache info"));

	return (size + overhead);
}
