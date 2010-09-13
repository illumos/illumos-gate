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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains public functions for managing the dhcptab container.
 * For the semantics of these functions, please see the Enterprise DHCP
 * Architecture Document.
 *
 * This module uses synchronization guarantees provided by dsvclockd(1M);
 * please see $SRC/lib/libdhcpsvc/private/README.synch for details.
 *
 * Big Theory Statement for the SUNWbinfiles DHCP Table Module
 * ===========================================================
 *
 * Since the dhcptab container does not have any performance-critical
 * consumers, this module focuses on being simple and robust rather than
 * fast.  The on-disk structure consists of a minimal header followed by a
 * list of dt_filerec_t's in no particular order.  Note that the dt_rec_t's
 * dt_value can be arbitrarily large, which means each dt_filerec_t is also
 * of arbitrary size; we deal with this by storing the on-disk size of each
 * record in the record itself.
 *
 * To meet our robustness requirements (see the Big Theory Statement in
 * dhcp_network.c), each update operation does its work on a copy of the
 * dhcptab, which is then atomically renamed to the name of the actual
 * dhcptab upon completion (yes, this is *very slow*).  To speed this up a
 * little, we use mmap(2) to generate the copy, which is about twice as
 * fast as using read(2)/write(2).
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dhcp_svc_public.h>
#include <sys/stat.h>
#include <sys/isa_defs.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <alloca.h>

#include "dhcptab.h"
#include "util.h"

/*
 * We compute the RECSIZE using the offset of `rec_dtval' rather than the
 * sizeof (dt_filerec_t) so that we don't include any trailing structure
 * padding in the size calculation.
 */
#define	RECSIZE(rec) (offsetof(dt_filerec_t, rec_dtval) + ((rec).rec_dtvalsize))

static int	read_header(int, dt_header_t *);
static int	write_header(int, dt_header_t *);
static int	read_rec(int, dt_filerec_t *, off_t);
static int	write_rec(int, dt_filerec_t *, off_t);
static void	dt2path(char *, size_t, const char *, const char *);
static boolean_t record_match(const dt_rec_t *, const dt_rec_t *, uint_t);
static int	find_dt(int, uint_t, uint_t, int, const dt_rec_t *,
		    dt_rec_list_t **, uint_t *);

int
open_dt(void **handlep, const char *location, uint_t flags)
{
	dt_handle_t	*dhp;
	dt_header_t	header = { 0 };
	char		dtpath[MAXPATHLEN];
	int		retval;
	int		fd;

	dhp = malloc(sizeof (dt_handle_t));
	if (dhp == NULL)
		return (DSVC_NO_MEMORY);

	dhp->dh_oflags = flags;
	(void) strlcpy(dhp->dh_location, location, MAXPATHLEN);

	dt2path(dtpath, MAXPATHLEN, location, "");
	retval = open_file(dtpath, flags, &fd);
	if (retval != DSVC_SUCCESS) {
		free(dhp);
		return (retval);
	}

	if (flags & DSVC_CREATE) {
		/*
		 * We just created the per-network container; initialize
		 * the header and put it out on disk.
		 */
		header.dth_magic   = DT_MAGIC;
		header.dth_version = DSVC_CONVER;

		if (write_header(fd, &header) == -1) {
			retval = syserr_to_dsvcerr(errno);
			(void) close(fd);
			(void) remove_dt(location);
			(void) close_dt((void **)&dhp);
			return (retval);
		}
	} else {
		/*
		 * Container already exists; sanity check against the
		 * header that's on-disk.
		 */
		if (read_header(fd, &header) == -1) {
			retval = syserr_to_dsvcerr(errno);
			(void) close(fd);
			(void) close_dt((void **)&dhp);
			return (retval);
		}

		if (header.dth_magic != DT_MAGIC ||
		    header.dth_version != DSVC_CONVER) {
			(void) close(fd);
			(void) close_dt((void **)&dhp);
			return (DSVC_INTERNAL);
		}
	}

	(void) close(fd);
	*handlep = dhp;
	return (DSVC_SUCCESS);
}

int
close_dt(void **handlep)
{
	free(*handlep);
	return (DSVC_SUCCESS);
}

int
remove_dt(const char *location)
{
	char dtpath[MAXPATHLEN];

	dt2path(dtpath, MAXPATHLEN, location, "");
	if (unlink(dtpath) == -1)
		return (syserr_to_dsvcerr(errno));

	return (DSVC_SUCCESS);
}

int
lookup_dt(void *handle, boolean_t partial, uint_t query, int count,
    const dt_rec_t *targetp, dt_rec_list_t **recordsp, uint_t *nrecordsp)
{
	int		fd;
	int		retval;
	char		dtpath[MAXPATHLEN];
	dt_handle_t	*dhp = (dt_handle_t *)handle;

	if ((dhp->dh_oflags & DSVC_READ) == 0)
		return (DSVC_ACCESS);

	dt2path(dtpath, MAXPATHLEN, dhp->dh_location, "");
	fd = open(dtpath, O_RDONLY);
	if (fd == -1)
		return (syserr_to_dsvcerr(errno));

	retval = find_dt(fd, partial ? FIND_PARTIAL : 0, query, count, targetp,
	    recordsp, nrecordsp);

	(void) close(fd);
	return (retval);
}

/*
 * Internal version of lookup_dt() used by lookup_dt(), modify_dt(),
 * add_dt(), and delete_dt(); same semantics as lookup_dt() except that the
 * `partial' argument has been generalized into a `flags' field and the
 * handle has been turned into a file descriptor.
 */
static int
find_dt(int fd, uint_t flags, uint_t query, int count,
    const dt_rec_t *targetp, dt_rec_list_t **recordsp, uint_t *nrecordsp)
{
	int		retval = DSVC_SUCCESS;
	uint_t		nrecords = 0, n = 0;
	dt_rec_t	*recordp;
	dt_rec_list_t	*records, *new_records;
	dt_header_t	header;
	dt_filerec_t	rec;
	off_t		recoff = sizeof (dt_header_t);
	struct stat	st;

	if (read_header(fd, &header) == -1)
		return (syserr_to_dsvcerr(errno));

	if (fstat(fd, &st) == -1)
		return (DSVC_INTERNAL);

	records = NULL;
	for (; (recoff < st.st_size) && (count < 0 || nrecords < count);
	    n++, recoff += RECSIZE(rec)) {

		if (read_rec(fd, &rec, recoff) == -1) {
			retval = syserr_to_dsvcerr(errno);
			break;
		}

		/*
		 * See if we've got a match...
		 */
		if (!record_match(&rec.rec_dt, targetp, query))
			continue;

		/*
		 * Caller just wants a count of the number of matching
		 * records, not the records themselves; continue.
		 */
		if (recordsp == NULL) {
			nrecords++;
			continue;
		}

		/*
		 * Allocate record; if FIND_POSITION flag is set, then
		 * we need to allocate an extended (dt_recpos_t) record.
		 */
		if (flags & FIND_POSITION)
			recordp = malloc(sizeof (dt_recpos_t));
		else
			recordp = malloc(sizeof (dt_rec_t));

		if (recordp == NULL) {
			if ((flags & FIND_PARTIAL) == 0)
				retval = DSVC_NO_MEMORY;
			break;
		}
		/*
		 * Fill in record; do a structure copy from our automatic
		 * record.  If FIND_POSITION flag is on, pass back
		 * additional location information.
		 */
		*recordp = rec.rec_dt;
		recordp->dt_value = malloc(rec.rec_dtvalsize);
		if (recordp->dt_value == NULL) {
			free_dtrec(recordp);
			if ((flags & FIND_PARTIAL) == 0)
				retval = DSVC_NO_MEMORY;
			break;
		}
		if (pnread(fd, recordp->dt_value, rec.rec_dtvalsize,
		    recoff + offsetof(dt_filerec_t, rec_dtval)) == -1) {
			if ((flags & FIND_PARTIAL) == 0)
				retval = syserr_to_dsvcerr(errno);
			free_dtrec(recordp);
			break;
		}

		if (flags & FIND_POSITION) {
			((dt_recpos_t *)recordp)->dtp_off  = recoff;
			((dt_recpos_t *)recordp)->dtp_size = RECSIZE(rec);
		}

		/*
		 * Chuck the record on the list and up the counter.
		 */
		new_records = add_dtrec_to_list(recordp, records);
		if (new_records == NULL) {
			free_dtrec(recordp);
			if ((flags & FIND_PARTIAL) == 0)
				retval = DSVC_NO_MEMORY;
			break;
		}

		records = new_records;
		nrecords++;
	}

	if (retval == DSVC_SUCCESS) {
		*nrecordsp = nrecords;
		if (recordsp != NULL)
			*recordsp = records;
		return (DSVC_SUCCESS);
	}

	if (records != NULL)
		free_dtrec_list(records);

	return (retval);
}

/*
 * Compares `dtp' to the target `targetp', using `query' to decide what
 * fields to compare.  Returns B_TRUE if `dtp' matches `targetp', B_FALSE
 * if not.
 */
static boolean_t
record_match(const dt_rec_t *dtp, const dt_rec_t *targetp, uint_t query)
{
	if (DSVC_QISEQ(query, DT_QTYPE) && targetp->dt_type != dtp->dt_type)
		return (B_FALSE);
	if (DSVC_QISNEQ(query, DT_QTYPE) && targetp->dt_type == dtp->dt_type)
		return (B_FALSE);

	if (DSVC_QISEQ(query, DT_QKEY) &&
	    strcmp(targetp->dt_key, dtp->dt_key) != 0)
		return (B_FALSE);

	if (DSVC_QISNEQ(query, DT_QKEY) &&
	    strcmp(targetp->dt_key, dtp->dt_key) == 0)
		return (B_FALSE);

	return (B_TRUE);
}

int
add_dt(void *handle, dt_rec_t *addp)
{
	unsigned int	found;
	int		query;
	int		fd, newfd;
	int		retval;
	dt_filerec_t	*rec;
	struct stat	st;
	dt_handle_t	*dhp = (dt_handle_t *)handle;
	char		newpath[MAXPATHLEN], dtpath[MAXPATHLEN];

	if ((dhp->dh_oflags & DSVC_WRITE) == 0)
		return (DSVC_ACCESS);

	dt2path(dtpath, MAXPATHLEN, dhp->dh_location, "");
	fd = open(dtpath, O_RDWR);
	if (fd == -1)
		return (syserr_to_dsvcerr(errno));

	/*
	 * Make sure the record wasn't created when we weren't looking.
	 */
	DSVC_QINIT(query);
	DSVC_QEQ(query, DT_QKEY|DT_QTYPE);

	retval = find_dt(fd, 0, query, 1, addp, NULL, &found);
	if (retval != DSVC_SUCCESS) {
		(void) close(fd);
		return (retval);
	}
	if (found != 0) {
		(void) close(fd);
		return (DSVC_EXISTS);
	}

	/*
	 * Make a new copy of the dhcptab with the new record appended.
	 * Once done, atomically rename the new dhcptab to the old name.
	 */
	if (fstat(fd, &st) == -1) {
		(void) close(fd);
		return (DSVC_INTERNAL);
	}

	dt2path(newpath, MAXPATHLEN, dhp->dh_location, ".new");
	(void) unlink(newpath);
	newfd = open(newpath, O_WRONLY|O_CREAT|O_EXCL, 0644);
	if (newfd == -1) {
		retval = syserr_to_dsvcerr(errno);
		goto out;
	}

	retval = copy_range(fd, 0, newfd, 0, st.st_size);
	if (retval != DSVC_SUCCESS)
		goto out;

	addp->dt_sig = gensig();
	rec = alloca(sizeof (dt_filerec_t) + strlen(addp->dt_value));
	rec->rec_dt = *addp;
	rec->rec_dtvalsize = strlen(addp->dt_value) + 1;
	(void) strcpy(rec->rec_dtval, addp->dt_value);

	if (write_rec(newfd, rec, st.st_size) == -1) {
		retval = syserr_to_dsvcerr(errno);
		goto out;
	}

	/*
	 * Note: we close these descriptors before the rename(2) (rather
	 * than just having the `out:' label clean them up) to save NFS
	 * some work (otherwise, NFS has to save `dtpath' to an alternate
	 * name since its vnode would still be active).
	 */
	(void) close(fd);
	(void) close(newfd);

	if (rename(newpath, dtpath) == -1)
		retval = syserr_to_dsvcerr(errno);

	return (retval);
out:
	(void) close(fd);
	(void) close(newfd);
	(void) unlink(newpath);
	return (retval);
}

int
modify_dt(void *handle, const dt_rec_t *origp, dt_rec_t *newp)
{
	unsigned int	found;
	int		query;
	int		fd, newfd;
	int		retval;
	dt_filerec_t	*rec;
	off_t		recoff, recnext;
	dt_rec_list_t	*reclist;
	struct stat	st;
	dt_handle_t	*dhp = (dt_handle_t *)handle;
	char		newpath[MAXPATHLEN], dtpath[MAXPATHLEN];

	if ((dhp->dh_oflags & DSVC_WRITE) == 0)
		return (DSVC_ACCESS);

	dt2path(dtpath, MAXPATHLEN, dhp->dh_location, "");
	fd = open(dtpath, O_RDWR);
	if (fd == -1)
		return (syserr_to_dsvcerr(errno));

	DSVC_QINIT(query);
	DSVC_QEQ(query, DT_QKEY|DT_QTYPE);

	/*
	 * If we're changing the key for this record, make sure the key
	 * we're changing to doesn't already exist.
	 */
	if (origp->dt_type != newp->dt_type ||
	    strcmp(origp->dt_key, newp->dt_key) != 0) {
		retval = find_dt(fd, 0, query, 1, newp, NULL, &found);
		if (retval != DSVC_SUCCESS) {
			(void) close(fd);
			return (retval);
		}
		if (found != 0) {
			(void) close(fd);
			return (DSVC_EXISTS);
		}
	}

	/*
	 * Fetch the original again to make sure it didn't go stale.
	 */
	retval = find_dt(fd, FIND_POSITION, query, 1, origp, &reclist, &found);
	if (retval != DSVC_SUCCESS) {
		(void) close(fd);
		return (retval);
	}
	if (found == 0) {
		(void) close(fd);
		return (DSVC_NOENT);
	}

	if (reclist->dtl_rec->dt_sig != origp->dt_sig) {
		(void) close(fd);
		free_dtrec_list(reclist);
		return (DSVC_COLLISION);
	}

	recoff  = ((dt_recpos_t *)reclist->dtl_rec)->dtp_off;
	recnext = recoff + ((dt_recpos_t *)reclist->dtl_rec)->dtp_size;

	free_dtrec_list(reclist);

	/*
	 * Make a new copy of the dhcptab, sans the record we're modifying,
	 * then append modified record at the end.  Once done, atomically
	 * rename the new dhcptab to the old name.
	 */
	if (fstat(fd, &st) == -1) {
		(void) close(fd);
		return (DSVC_INTERNAL);
	}

	dt2path(newpath, MAXPATHLEN, dhp->dh_location, ".new");
	(void) unlink(newpath);
	newfd = open(newpath, O_WRONLY|O_CREAT|O_EXCL, 0644);
	if (newfd == -1) {
		retval = syserr_to_dsvcerr(errno);
		goto out;
	}

	retval = copy_range(fd, 0, newfd, 0, recoff);
	if (retval != DSVC_SUCCESS)
		goto out;

	retval = copy_range(fd, recnext, newfd, recoff, st.st_size - recnext);
	if (retval != DSVC_SUCCESS)
		goto out;

	newp->dt_sig = origp->dt_sig + 1;
	rec = alloca(sizeof (dt_filerec_t) + strlen(newp->dt_value));
	rec->rec_dt = *newp;
	rec->rec_dtvalsize = strlen(newp->dt_value) + 1;
	(void) strcpy(rec->rec_dtval, newp->dt_value);

	if (write_rec(newfd, rec, st.st_size - (recnext - recoff)) == -1) {
		retval = syserr_to_dsvcerr(errno);
		goto out;
	}

	/*
	 * See comment in add_dt() regarding the next two lines.
	 */
	(void) close(fd);
	(void) close(newfd);

	if (rename(newpath, dtpath) == -1)
		retval = syserr_to_dsvcerr(errno);

	return (retval);
out:
	(void) close(fd);
	(void) close(newfd);
	(void) unlink(newpath);
	return (retval);
}

int
delete_dt(void *handle, const dt_rec_t *delp)
{
	unsigned int	found;
	int		query;
	int		fd, newfd;
	int		retval;
	off_t		recoff, recnext;
	dt_rec_list_t	*reclist;
	struct stat	st;
	dt_handle_t	*dhp = (dt_handle_t *)handle;
	char		newpath[MAXPATHLEN], dtpath[MAXPATHLEN];

	if ((dhp->dh_oflags & DSVC_WRITE) == 0)
		return (DSVC_ACCESS);

	dt2path(dtpath, MAXPATHLEN, dhp->dh_location, "");
	fd = open(dtpath, O_RDWR);
	if (fd == -1)
		return (syserr_to_dsvcerr(errno));

	/*
	 * Make sure the record exists and also that the signatures match;
	 * if `delp->dt_sig' is zero, then skip signature comparison (this
	 * is so one can delete records that were not looked up).
	 */
	DSVC_QINIT(query);
	DSVC_QEQ(query, DT_QKEY|DT_QTYPE);

	retval = find_dt(fd, FIND_POSITION, query, 1, delp, &reclist, &found);
	if (retval != DSVC_SUCCESS) {
		(void) close(fd);
		return (retval);
	}
	if (found == 0) {
		(void) close(fd);
		return (DSVC_NOENT);
	}

	if (delp->dt_sig != 0 && reclist->dtl_rec->dt_sig != delp->dt_sig) {
		(void) close(fd);
		free_dtrec_list(reclist);
		return (DSVC_COLLISION);
	}

	recoff  = ((dt_recpos_t *)reclist->dtl_rec)->dtp_off;
	recnext = recoff + ((dt_recpos_t *)reclist->dtl_rec)->dtp_size;

	free_dtrec_list(reclist);

	/*
	 * Make a new copy of the dhcptab, sans the record we're deleting.
	 * Once done, atomically rename the new dhcptab to the old name.
	 */
	if (fstat(fd, &st) == -1) {
		(void) close(fd);
		return (DSVC_INTERNAL);
	}

	dt2path(newpath, MAXPATHLEN, dhp->dh_location, ".new");
	(void) unlink(newpath);
	newfd = open(newpath, O_WRONLY|O_CREAT|O_EXCL, 0644);
	if (newfd == -1) {
		retval = syserr_to_dsvcerr(errno);
		goto out;
	}

	retval = copy_range(fd, 0, newfd, 0, recoff);
	if (retval != DSVC_SUCCESS)
		goto out;

	retval = copy_range(fd, recnext, newfd, recoff, st.st_size - recnext);
	if (retval != DSVC_SUCCESS)
		goto out;

	/*
	 * See comment in add_dt() regarding the next two lines.
	 */
	(void) close(fd);
	(void) close(newfd);

	if (rename(newpath, dtpath) == -1)
		retval = syserr_to_dsvcerr(errno);

	return (retval);
out:
	(void) close(fd);
	(void) close(newfd);
	(void) unlink(newpath);
	return (retval);
}

int
list_dt(const char *location, char ***listppp, uint_t *countp)
{
	char	dtpath[MAXPATHLEN];
	char	**listpp;

	if (access(location, F_OK|R_OK) == -1) {
		switch (errno) {
		case EACCES:
		case EPERM:
			return (DSVC_ACCESS);
		case ENOENT:
			return (DSVC_NO_LOCATION);
		default:
			break;
		}
		return (DSVC_INTERNAL);
	}

	dt2path(dtpath, MAXPATHLEN, location, "");
	if (access(dtpath, F_OK|R_OK) == -1) {
		*countp = 0;
		*listppp = NULL;
		return (DSVC_SUCCESS);
	}

	listpp = malloc(sizeof (char **));
	if (listpp == NULL)
		return (DSVC_NO_MEMORY);
	listpp[0] = strdup(DT_DHCPTAB);
	if (listpp[0] == NULL) {
		free(listpp);
		return (DSVC_NO_MEMORY);
	}

	*listppp = listpp;
	*countp = 1;
	return (DSVC_SUCCESS);
}

/*
 * Given a buffer `path' of `pathlen' bytes, fill it in with a path to the
 * dhcptab in directory `dir' with a suffix of `suffix'.
 */
static void
dt2path(char *path, size_t pathlen, const char *dir, const char *suffix)
{
	(void) snprintf(path, pathlen, "%s/SUNWbinfiles%u_%s%s", dir,
	    DSVC_CONVER, DT_DHCPTAB, suffix);
}

/*
 * Convert dt_header_t pointed to by `headerp' from native (host) to
 * network order or the other way.
 */
/* ARGSUSED */
static void
nhconvert_header(dt_header_t *headerp)
{
#ifdef	_LITTLE_ENDIAN
	nhconvert(&headerp->dth_magic, &headerp->dth_magic, sizeof (uint32_t));
#endif
}

/*
 * Convert dt_filerec_t pointed to by `rec' from native (host) to network
 * order or the other way.
 */
/* ARGSUSED */
static void
nhconvert_rec(dt_filerec_t *rec)
{
#ifdef	_LITTLE_ENDIAN
	dt_rec_t *dtp = &rec->rec_dt;

	nhconvert(&rec->rec_dtvalsize, &rec->rec_dtvalsize, sizeof (uint32_t));
	nhconvert(&dtp->dt_sig, &dtp->dt_sig, sizeof (uint64_t));
#endif
}

/*
 * Read the dt_header_t in the container at open file `fd' into the header
 * pointed to by `headerp'.  Returns 0 on success, -1 on failure (errno is
 * set).
 */
static int
read_header(int fd, dt_header_t *headerp)
{
	if (pnread(fd, headerp, sizeof (dt_header_t), 0) == -1)
		return (-1);

	nhconvert_header(headerp);
	return (0);
}

/*
 * Write the dt_header_t pointed to by `headerp' to the container at open
 * file `fd'.  Returns 0 on success, -1 on failure (errno is set).
 */
static int
write_header(int fd, dt_header_t *headerp)
{
	int retval;

	nhconvert_header(headerp);
	retval = pnwrite(fd, headerp, sizeof (dt_header_t), 0);
	nhconvert_header(headerp);
	return (retval);
}


/*
 * Read the dt_filerec_t in the container from offset `recoff' in the
 * container at open file `fd'.  Note that this only returns the fixed
 * sized part of the dt_filerec_t; the caller must retrieve `rev_dtval' on
 * their own.  Returns 0 on success, -1 on failure (errno is set).
 */
static int
read_rec(int fd, dt_filerec_t *rec, off_t recoff)
{
	if (pnread(fd, rec, sizeof (dt_filerec_t), recoff) == -1)
		return (-1);

	nhconvert_rec(rec);
	return (0);
}

/*
 * Write the dt_filerec_t pointed to be `rec' to offset `recoff' in the
 * container at open file `fd'.  Returns 0 on success, -1 on failure (errno
 * is set).
 */
static int
write_rec(int fd, dt_filerec_t *rec, off_t recoff)
{
	int	retval;
	size_t	recsize = RECSIZE(*rec);

	nhconvert_rec(rec);
	retval = pnwrite(fd, rec, recsize, recoff);
	nhconvert_rec(rec);
	return (retval);
}
