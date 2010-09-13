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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains public API functions for managing the legacy dhcptab
 * container format.  For the semantics of these functions, please see the
 * Enterprise DHCP Architecture Document.
 */

#include <alloca.h>
#include <dhcp_svc_public.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "dhcptab.h"
#include "util.h"

static void dt2path(char *, size_t, const char *, const char *);
static int write_rec(int, dt_rec_t *, off_t);

int
open_dt(void **handlep, const char *location, uint_t flags)
{
	dt_handle_t	*dhp;
	int		retval;
	int		fd;
	char		dtpath[MAXPATHLEN];

	dhp = malloc(sizeof (dt_handle_t));
	if (dhp == NULL)
		return (DSVC_NO_MEMORY);

	dhp->dh_oflags = flags;
	(void) strlcpy(dhp->dh_location, location, MAXPATHLEN);

	/*
	 * This is a legacy format which has no header, so we neither write
	 * nor verify a header (we just create the file or make sure it
	 * exists, depending on the value of `flags').
	 */
	dt2path(dtpath, MAXPATHLEN, dhp->dh_location, "");
	retval = open_file(dtpath, flags, &fd);
	if (retval != DSVC_SUCCESS) {
		free(dhp);
		return (retval);
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

/*
 * Internal version of lookup_dt() used by both lookup_dt() and
 * update_dt(); same semantics as lookup_dt() except that the `partial'
 * argument has been generalized into a `flags' field and the handle has
 * been turned into a FILE pointer.
 */
static int
find_dt(FILE *fp, uint_t flags, uint_t query, int count,
    const dt_rec_t *targetp, dt_rec_list_t **recordsp, uint_t *nrecordsp)
{
	int		retval = DSVC_SUCCESS;
	char 		*buf = NULL, *fields[DTF_MAX_FIELDS];
	uint_t		nrecords;
	dt_rec_t	*recordp;
	dt_rec_list_t	*records, *new_records;
	unsigned int	nfields;
	off_t		recoff;

	if (fseek(fp, 0, SEEK_SET) == -1)
		return (DSVC_INTERNAL);

	records = NULL;
	for (nrecords = 0; count < 0 || nrecords < count; ) {
		free(buf);

		if (flags & FIND_POSITION)
			recoff = ftello(fp);

		buf = read_entry(fp);
		if (buf == NULL) {
			if (!feof(fp))
				retval = DSVC_NO_MEMORY;
			break;
		}

		/*
		 * Skip pure comment lines; for now this just skips the
		 * header information at the top of the container.
		 */
		if (buf[0] == DTF_COMMENT_CHAR)
			continue;

		/*
		 * Parse out the entry into the dt_rec_t
		 */
		nfields = field_split(buf, DTF_MAX_FIELDS, fields, " \t");
		if (nfields < DTF_MAX_FIELDS)
			continue;

		/*
		 * See if we've got a match.  If so, allocate the new
		 * record, fill it in, and continue.
		 */
		if (DSVC_QISEQ(query, DT_QTYPE) &&
		    targetp->dt_type != fields[DTF_TYPE][0])
			continue;
		else if (DSVC_QISNEQ(query, DT_QTYPE) &&
		    targetp->dt_type == fields[DTF_TYPE][0])
			continue;

		if (DSVC_QISEQ(query, DT_QKEY) &&
		    strcmp(targetp->dt_key, fields[DTF_KEY]) != 0)
			continue;
		else if (DSVC_QISNEQ(query, DT_QKEY) &&
		    strcmp(targetp->dt_key, fields[DTF_KEY]) == 0)
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
		 * Allocate record; if FIND_POSITION flag is set, then we
		 * need to allocate an extended (dt_recpos_t) record.
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
		 * Fill in record; if FIND_POSITION flag is set, then pass
		 * back additional location information.
		 */
		(void) strlcpy(recordp->dt_key, fields[DTF_KEY],
		    sizeof (recordp->dt_key));
		recordp->dt_sig = 1;
		recordp->dt_type = fields[DTF_TYPE][0];
		recordp->dt_value = strdup(fields[DTF_VALUE]);
		if (recordp->dt_value == NULL) {
			free(recordp);
			if ((flags & FIND_PARTIAL) == 0)
				retval = DSVC_NO_MEMORY;
			break;
		}

		if (flags & FIND_POSITION) {
			((dt_recpos_t *)recordp)->dtp_off = recoff;
			((dt_recpos_t *)recordp)->dtp_size = ftello(fp) -
			    recoff;
		}

		/*
		 * Chuck the record on the list; up the counter.
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

	free(buf);

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

int
lookup_dt(void *handle, boolean_t partial, uint_t query, int count,
    const dt_rec_t *targetp, dt_rec_list_t **recordsp, uint_t *nrecordsp)
{
	int		retval;
	char		dtpath[MAXPATHLEN];
	FILE		*fp;
	dt_handle_t	*dhp = (dt_handle_t *)handle;

	if ((dhp->dh_oflags & DSVC_READ) == 0)
		return (DSVC_ACCESS);

	dt2path(dtpath, MAXPATHLEN, dhp->dh_location, "");
	fp = fopen(dtpath, "r");
	if (fp == NULL)
		return (syserr_to_dsvcerr(errno));

	retval = find_dt(fp, partial ? FIND_PARTIAL : 0, query, count, targetp,
	    recordsp, nrecordsp);

	(void) fclose(fp);
	return (retval);
}

/*
 * Internal dhcptab record update routine, used to factor out the
 * common code between add_dt(), delete_dt(), and modify_dt().  If
 * `origp' is NULL, then act like add_dt(); if `newp' is NULL, then
 * act like delete_dt(); otherwise act like modify_dt().
 */
static int
update_dt(const dt_handle_t *dhp, const dt_rec_t *origp, dt_rec_t *newp)
{
	char		dtpath[MAXPATHLEN], newpath[MAXPATHLEN];
	int		retval = DSVC_SUCCESS;
	off_t		recoff, recnext;
	dt_rec_list_t	*reclist;
	FILE		*fp;
	int		newfd;
	uint_t		found;
	int		query;
	struct stat	st;

	if ((dhp->dh_oflags & DSVC_WRITE) == 0)
		return (DSVC_ACCESS);

	/*
	 * Open the container to update and a new container file which we
	 * will store the updated version of the container in.  When the
	 * update is done, rename the new file to be the real container.
	 */
	dt2path(dtpath, MAXPATHLEN, dhp->dh_location, "");
	fp = fopen(dtpath, "r");
	if (fp == NULL)
		return (syserr_to_dsvcerr(errno));

	dt2path(newpath, MAXPATHLEN, dhp->dh_location, ".new");
	(void) unlink(newpath);
	newfd = open(newpath, O_CREAT|O_EXCL|O_WRONLY, 0644);
	if (newfd == -1) {
		(void) fclose(fp);
		return (syserr_to_dsvcerr(errno));
	}

	DSVC_QINIT(query);
	DSVC_QEQ(query, DT_QKEY|DT_QTYPE);

	/*
	 * If we're adding a new record or changing a key for an existing
	 * record, bail if the record we want to add already exists.
	 */
	if (newp != NULL) {
		if (origp == NULL || origp->dt_type != newp->dt_type ||
		    strcmp(origp->dt_key, newp->dt_key) != 0) {
			retval = find_dt(fp, 0, query, 1, newp, NULL, &found);
			if (retval != DSVC_SUCCESS)
				goto out;
			if (found != 0) {
				retval = DSVC_EXISTS;
				goto out;
			}
		}
	}

	/*
	 * If we're deleting or modifying record, make sure the record
	 * still exists.  Note that we don't check signatures because this
	 * is a legacy format that has no signatures.
	 */
	if (origp != NULL) {
		retval = find_dt(fp, FIND_POSITION, query, 1, origp, &reclist,
		    &found);
		if (retval != DSVC_SUCCESS)
			goto out;
		if (found == 0) {
			retval = DSVC_NOENT;
			goto out;
		}

		/*
		 * Note the offset of the record we're modifying or deleting
		 * for use down below.
		 */
		recoff  = ((dt_recpos_t *)reclist->dtl_rec)->dtp_off;
		recnext = recoff + ((dt_recpos_t *)reclist->dtl_rec)->dtp_size;

		free_dtrec_list(reclist);
	} else {
		/*
		 * No record to modify or delete, so set `recoff' and
		 * `recnext' appropriately.
		 */
		recoff = 0;
		recnext = 0;
	}

	/*
	 * Make a new copy of the container.  If we're deleting or
	 * modifying a record, don't copy that record to the new container.
	 */
	if (fstat(fileno(fp), &st) == -1) {
		retval = DSVC_INTERNAL;
		goto out;
	}

	retval = copy_range(fileno(fp), 0, newfd, 0, recoff);
	if (retval != DSVC_SUCCESS)
		goto out;

	retval = copy_range(fileno(fp), recnext, newfd, recoff,
	    st.st_size - recnext);
	if (retval != DSVC_SUCCESS)
		goto out;

	/*
	 * If there's a new record, append it to the new container.
	 */
	if (newp != NULL) {
		retval = write_rec(newfd, newp, recoff + st.st_size - recnext);
		if (retval != DSVC_SUCCESS)
			goto out;
	}

	/*
	 * Note: we close these descriptors before the rename(2) (rather
	 * than just having the `out:' label clean them up) to save NFS
	 * some work (otherwise, NFS has to save `dtpath' to an alternate
	 * name since its vnode would still be active).
	 */
	(void) fclose(fp);
	(void) close(newfd);

	if (rename(newpath, dtpath) == -1)
		retval = syserr_to_dsvcerr(errno);

	return (retval);
out:
	(void) fclose(fp);
	(void) close(newfd);
	(void) unlink(newpath);
	return (retval);
}

int
delete_dt(void *handle, const dt_rec_t *delp)
{
	return (update_dt((dt_handle_t *)handle, delp, NULL));
}

int
add_dt(void *handle, dt_rec_t *addp)
{
	return (update_dt((dt_handle_t *)handle, NULL, addp));
}

int
modify_dt(void *handle, const dt_rec_t *origp, dt_rec_t *newp)
{
	return (update_dt((dt_handle_t *)handle, origp, newp));
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
 * Given a buffer `path' of `pathlen' bytes, fill it in with a path to
 * the dhcptab in directory `dir' with a suffix of `suffix'.
 */
static void
dt2path(char *path, size_t pathlen, const char *dir, const char *suffix)
{
	(void) snprintf(path, pathlen, "%s/%s%s", dir, DT_DHCPTAB, suffix);
}

/*
 * Write the dt_rec_t pointed to by `recp' into the open container `fd' at
 * offset `recoff'.  Returns DSVC_* error code.
 */
static int
write_rec(int fd, dt_rec_t *recp, off_t recoff)
{
	char	entbuf[1024], *ent = entbuf;
	size_t	entsize = sizeof (entbuf);
	int	entlen;

again:
	entlen = snprintf(ent, entsize, "%s\t%c\t%s\n", recp->dt_key,
	    recp->dt_type, recp->dt_value);
	if (entlen == -1)
		return (syserr_to_dsvcerr(errno));

	if (entlen > entsize) {
		entsize = entlen;
		ent = alloca(entlen);
		goto again;
	}

	if (pnwrite(fd, ent, entlen, recoff) == -1)
		return (syserr_to_dsvcerr(errno));

	return (DSVC_SUCCESS);
}
