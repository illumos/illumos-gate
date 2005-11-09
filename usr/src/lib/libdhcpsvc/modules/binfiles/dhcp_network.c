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
 * This file contains public functions for managing DHCP network
 * containers.  For the semantics of these functions, please see the
 * Enterprise DHCP Architecture Document.
 *
 * This module uses synchronization guarantees provided by dsvclockd(1M);
 * please see $SRC/lib/libdhcpsvc/private/README.synch for details.
 *
 * Big Theory Statement for the SUNWbinfiles DHCP Network Module
 * =============================================================
 *
 * 1. On-disk Structure
 *
 * Each container consists of two basic pieces on-disk: a header and an
 * array of records.  In order to provide fast client IP lookup, the array
 * of records is directly indexed by client IP address (using a simple
 * mapping function).  In order to provide fast client id lookup, each
 * in-use record is also on exactly one doubly-linked client id hash chain;
 * the hash chains heads are contained in the header).  For all other
 * lookups, we can restrict our search to only the in-use records by merely
 * walking all of the hash chains.  Here's a crude illustration of what
 * this looks like on-disk (note that hash chains 2 and 3 are empty):
 *
 *              _______________________________________________
 *             | container info   | hash chain heads (buckets) |
 *    header   |                  | 1 | 2 | 3 |  [ .... ]  | N |
 *             |                  | | |   |   |            | | |
 *             |__________________|_|________________________|_|
 *             | rec1      | rec2   |  | rec3      | rec4    | |
 *             |           |        +--->          |         | |
 *             | unused    | unused    | hash1     | unused  | |
 *             |___________|___________|________^|_|_________|_|
 *             | rec5      | rec6      | rec7   |v | rec8    | |
 *             |           |           |           ->        | |
 *    records  | unused    | hashN     | hash1    <- hash1   | |
 *             |___________|________^|_|___________|_________|_|
 *             |           :        :: :           :         : |
 *             |           :        :: : [ more records... ] : |
 *             |           :        :: :           :         : |
 *             |___________:________::_:___________:_________:_|
 *             | recN-3    | recN-2 || | recN-1    | recN    v |
 *             |           |        |+-->          ->          |
 *             | unused    | unused +--- hashN    <- hashN     |
 *             |___________|___________|___________|___________|
 *
 * Note that the actual on-disk format is a bit more complicated than this
 * due to robustness issues; see section 3 below for details.
 *
 * 2. Robustness Requirements
 *
 * This module has been designed to be as efficient as possible while still
 * retaining the robustness minimally required for an enterprise-level
 * environment.  In particular, it is designed to handle the following
 * failure situations:
 *
 *	1. An update operation (add, modify, delete) on a container is
 *	   unable to complete due to an unexpected internal error at
 *	   any point in the update code.
 *
 *	2. An update operation (add, modify, delete) on a container is
 *	   unable to complete due to unexpected program termination while
 *	   at any point in the update code.
 *
 * If either of these situations occur, the container in question must be
 * left in a consistent (and viable) state.  In addition, only the pending
 * transaction (at most) may be lost.
 *
 * 3. Robustness Techniques
 *
 * This module uses a few different techniques to meet our robustness goals
 * while maintaining high performance.  The biggest problem we encounter
 * when trying to achieve robustness is updating the client id hash chain.
 * In particular, it is not possible to atomically add, move, or delete an
 * item from a doubly linked list, thus creating a window where a crash
 * could leave our hash chains in an inconsistent state.
 *
 * To address this problem, we actually maintain two images (copies) of all
 * the hash chains in the container.  At any point in time, exactly one of
 * the two images is active (and thus considered authoritative), as
 * indicated by a byte in the container header.  When performing an update
 * operation, all hash chain modifications are done on the *inactive*
 * image, then, once the inactive image has completed the hash chain
 * operations required by the update, the active and inactive images are
 * atomically switched, making the formerly-inactive image authoritative.
 * After the image switch, the update code then updates the formerly-active
 * image's hash chains to match the active image's hash chains.
 *
 * This approach has the nice property that internal container consistency
 * can always be restored after a crash by just resynchronizing the
 * inactive image's hash chains with the active image's chains.  Note that
 * the atomic image switch serves as the "commit point" for the operation:
 * if we crash before this point, we roll back the operation upon recovery
 * and it appears as though the operation never happened; if we crash after
 * this point, we roll forward the rest of the operation upon recovery as
 * if the crash had not happened.
 *
 * This technique is enough to robustly implement our add and delete
 * operations, but modify has an additional complication due to our direct
 * mapping of client IP addresses to records.  In particular, unless the
 * record modification includes changing the client IP address, the
 * modified record must be written at the same location as the original
 * record -- however, if the modify operation fails part way through
 * writing out the new client record, the record will be corrupt and we
 * will have no way to return the record to a consistent state.  To address
 * this issue, we allocate a spare record in the container header called
 * the "temporary" record.  Upon a modification of this type, we first
 * write the modified record to the temporary record and indicate that the
 * temporary record is currently proxying for the actual record.  We then
 * copy the temporary record to the actual record and make the temporary
 * record available again for future use.  If a crash occurs before the
 * copy to the temporary record is complete, then we just roll back as if
 * the modify never happened (since we have not modified the actual
 * record).  If a crash occurs after copying the temporary record, we roll
 * forward and complete the copy operation as if the crash never happened.
 * Note that there are some additional subtle complications here; see the
 * comments in the code for details.
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/isa_defs.h>
#include <netinet/in.h>
#include <dhcp_svc_public.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <libgen.h>
#include <errno.h>
#include <stddef.h>
#include <assert.h>

#include "dhcp_network.h"
#include "util.h"

static uint16_t	cidhash(const uchar_t *, size_t);
static void	net2path(char *, size_t, const char *, ipaddr_t);
static int	check_dn(dn_handle_t *);
static int	getabyte(int, off_t, uchar_t *);
static int	setabyte(int, off_t, uchar_t);
static int	read_rec(int, dn_filerec_t *, dn_recid_t);
static int	write_rec(int, dn_filerec_t *, dn_recid_t);
static int	read_header(int, dn_header_t *, boolean_t);
static int	write_header(int, dn_header_t *);
static int	read_hashhead(int, dn_recid_t *, uint16_t, uchar_t);
static int	write_hashhead(int, dn_recid_t, uint16_t, uchar_t);
static boolean_t record_match(const dn_rec_t *, const dn_rec_t *, uint_t);

int
open_dn(void **handlep, const char *dir, uint_t flags,
    const struct in_addr *netp, const struct in_addr *maskp)
{
	dn_handle_t	*dhp;
	dn_header_t	header = { 0 };
	char		dnpath[MAXPATHLEN];
	int		i, retval;
	off_t		filesz;

	dhp = malloc(sizeof (dn_handle_t));
	if (dhp == NULL)
		return (DSVC_NO_MEMORY);

	/*
	 * As a safeguard, check that the size of a dn_header_t hasn't
	 * changed (since it contains a dn_rec_t, this will probably catch
	 * a change in that structure as well).  If it has, bail rather
	 * than totally corrupting the container (by continuing).  Note
	 * that this situation indicates an internal programming error,
	 * which is why we prefer assert() to just returning DSVC_INTERNAL.
	 */
	/* CONSTCOND */
	assert(sizeof (header) == 32768);

	net2path(dnpath, MAXPATHLEN, dir, netp->s_addr);
	retval = open_file(dnpath, flags, &dhp->dh_fd);
	if (retval != DSVC_SUCCESS) {
		free(dhp);
		return (retval);
	}

	if (flags & DSVC_CREATE) {
		/*
		 * We just created the per-network container; initialize
		 * the header and put it out on disk.  Note that we leave
		 * `dnh_version' zero until the entire header has been
		 * written, so we can detect partial failure.
		 */
		header.dnh_version	= 0;
		header.dnh_network	= netp->s_addr;
		header.dnh_netmask	= maskp->s_addr;
		header.dnh_magic	= DN_MAGIC;
		header.dnh_tempimage	= DN_NOIMAGE;
		header.dnh_image	= 0;
		header.dnh_errors	= 0;
		header.dnh_checks	= 0;
		for (i = 0; i < DN_CIDHASHSZ; i++) {
			header.dnh_cidhash[i][header.dnh_image]  = DN_NOREC;
			header.dnh_cidhash[i][!header.dnh_image] = DN_NOREC;
		}

		if (write_header(dhp->dh_fd, &header) == -1) {
			retval = syserr_to_dsvcerr(errno);
			(void) remove_dn(dir, netp);
			(void) close_dn((void **)&dhp);
			return (retval);
		}

		/*
		 * Virtually reserve all the space we're going to need for
		 * the dn_rec_t's ahead of time, so that we don't have to
		 * worry about "growing" the file later (though it may
		 * increase in size as we fill in holes).  We're guaranteed
		 * that we'll read these holes as zeros, which we take
		 * advantage of since a dn_filerec_t with a rec_prev of
		 * DN_NOREC (which is 0) indicates that a record is unused.
		 */
		filesz = RECID2OFFSET(RECID(~0, header.dnh_netmask) + 1);
		retval = setabyte(dhp->dh_fd, filesz - 1, 0);
		if (retval != DSVC_SUCCESS) {
			(void) remove_dn(dir, netp);
			(void) close_dn((void **)&dhp);
			return (retval);
		}

		/*
		 * Set the version field on the container, effectively
		 * making it available for use.
		 */
		retval = setabyte(dhp->dh_fd, offsetof(dn_header_t,
		    dnh_version), DSVC_CONVER);
		if (retval != DSVC_SUCCESS) {
			(void) remove_dn(dir, netp);
			(void) close_dn((void **)&dhp);
			return (retval);
		}
	} else {
		/*
		 * Container already exists; sanity check against the
		 * header that's on-disk.  If we detect a problem then
		 * either someone scribbled on our container or we
		 * terminated abnormally when creating the container.
		 */
		if (read_header(dhp->dh_fd, &header, B_FALSE) == -1) {
			retval = syserr_to_dsvcerr(errno);
			(void) close_dn((void **)&dhp);
			return (retval);
		}

		if (header.dnh_network != netp->s_addr ||
		    header.dnh_version != DSVC_CONVER ||
		    header.dnh_magic != DN_MAGIC) {
			(void) close_dn((void **)&dhp);
			return (DSVC_INTERNAL);
		}
	}

	dhp->dh_netmask	= header.dnh_netmask;
	dhp->dh_oflags	= flags;

	*handlep = dhp;
	return (DSVC_SUCCESS);
}

int
close_dn(void **handlep)
{
	dn_handle_t *dhp = (dn_handle_t *)*handlep;

	if (close(dhp->dh_fd) == -1)
		return (DSVC_INTERNAL);

	free(dhp);
	return (DSVC_SUCCESS);
}

int
remove_dn(const char *dir, const struct in_addr *netp)
{
	char dnpath[MAXPATHLEN];

	net2path(dnpath, MAXPATHLEN, dir, netp->s_addr);
	if (unlink(dnpath) == -1)
		return (syserr_to_dsvcerr(errno));

	return (DSVC_SUCCESS);
}

int
lookup_dn(void *handle, boolean_t partial, uint_t query, int count,
    const dn_rec_t *targetp, dn_rec_list_t **recordsp, uint_t *nrecordsp)
{
	dn_handle_t	*dhp = (dn_handle_t *)handle;
	int		retval = DSVC_SUCCESS;
	uint_t		nrecords, n;
	uint16_t	hash;
	dn_rec_t	*recordp;
	dn_rec_list_t	*records, *new_records;
	dn_recid_t	recid, temp_recid = DN_NOREC;
	dn_filerec_t	rec;
	dn_header_t	header;
	uchar_t		image;
	int		fd = dhp->dh_fd;

	if ((dhp->dh_oflags & DSVC_READ) == 0)
		return (DSVC_ACCESS);

	if (read_header(fd, &header, B_FALSE) == -1)
		return (syserr_to_dsvcerr(errno));

	/*
	 * It's possible that a previous update to this container failed
	 * part-way through.  In general, this is fine since we always keep
	 * our active image's hash chains correct and only swap to the
	 * alternate image when the other image is completely safe to use.
	 * However, for reasons explained in modify_dn(), it's possible
	 * that a record being modified was not completely updated before a
	 * failure occurred.  In this case, the actual data for that record
	 * is contained in the temporary record in the header.  We need to
	 * be careful to use that temporary record anywhere we'd otherwise
	 * refer to the partially updated record.  Note that we do this
	 * rather than attempting to restore the consistency of the
	 * container because we're MT-hot here.
	 */
	if (header.dnh_dirty && header.dnh_tempimage == header.dnh_image) {
		temp_recid = RECID(header.dnh_temp.rec_dn.dn_cip.s_addr,
		    header.dnh_netmask);
	}

	image = header.dnh_image;
	records = NULL;
	for (n = 0, nrecords = 0; count < 0 || nrecords < count; n++) {
		if (DSVC_QISEQ(query, DN_QCIP)) {
			/*
			 * Lookup scenario 1: Caller has requested a QN_CIP
			 * query lookup; set `recid' to the only possible
			 * entry (which may not be in-use).
			 */
			if (n != 0)
				break;
			recid = RECID(targetp->dn_cip.s_addr, dhp->dh_netmask);
		} else if (DSVC_QISEQ(query, DN_QCID)) {
			/*
			 * Lookup scenario 2: Caller has requested a
			 * QN_CID-based lookup.  Walk the `cidhash' chain
			 * (one call at a time) and set `recid' to hash
			 * bucket candidates.
			 *
			 * Note that it's possible for the client id value
			 * 00 to appear more than once, and it's not
			 * impossible for other duplicate client ids to
			 * occur, so continue until we reach `nrecords'.
			 */
			if (n == 0) {
				hash = cidhash(targetp->dn_cid,
				    targetp->dn_cid_len);
				if (read_hashhead(fd, &recid, hash, image)
				    == -1)
					return (syserr_to_dsvcerr(errno));
			} else {
				/* sanity check */
				if (recid == rec.rec_next[image])
					break;
				recid = rec.rec_next[image];
			}
		} else {
			/*
			 * Lookup scenario 3: Caller has requested any
			 * other type of search.  Walk the all the client
			 * id hashes.
			 */
			if (n == 0) {
				hash = 0;
				if (read_header(fd, &header, B_TRUE) == -1)
					return (syserr_to_dsvcerr(errno));
				recid = header.dnh_cidhash[hash][image];
			} else {
				/* sanity check */
				if (recid == rec.rec_next[image])
					break;
				recid = rec.rec_next[image];
			}

			while (recid == DN_NOREC && ++hash < DN_CIDHASHSZ)
				recid = header.dnh_cidhash[hash][image];
		}

		/*
		 * No more records; bail.
		 */
		if (recid == DN_NOREC)
			break;

		if (recid == temp_recid) {
			/*
			 * The temporary record is actually authoritative
			 * for this record's contents; use it instead.
			 */
			recid = DN_TEMPREC;
		}

		if (read_rec(dhp->dh_fd, &rec, recid) == -1) {
			retval = syserr_to_dsvcerr(errno);
			break;
		}

		/*
		 * If the record isn't in-use, then skip...
		 */
		if (rec.rec_prev[image] == DN_NOREC)
			continue;

		/*
		 * See if we've got a match...
		 */
		if (!record_match(&rec.rec_dn, targetp, query))
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
		 * Allocate the record and fill it in.
		 */
		recordp = malloc(sizeof (dn_rec_t));
		if (recordp == NULL) {
			if (!partial)
				retval = DSVC_NO_MEMORY;
			break;
		}
		*recordp = rec.rec_dn;

		/*
		 * Chuck the record on the list and up the counter.
		 */
		new_records = add_dnrec_to_list(recordp, records);
		if (new_records == NULL) {
			free(recordp);
			if (!partial)
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
		free_dnrec_list(records);

	return (retval);
}

/*
 * Compares `dnp' to the target `targetp', using `query' to decide what
 * fields to compare.  Returns B_TRUE if `dnp' matches `targetp', B_FALSE
 * if not.
 */
static boolean_t
record_match(const dn_rec_t *dnp, const dn_rec_t *targetp, uint_t query)
{
	unsigned int qflags[] = { DN_QFDYNAMIC, DN_QFAUTOMATIC, DN_QFMANUAL,
				DN_QFUNUSABLE, DN_QFBOOTP_ONLY };
	unsigned int flags[]  = { DN_FDYNAMIC, DN_FAUTOMATIC, DN_FMANUAL,
				DN_FUNUSABLE, DN_FBOOTP_ONLY };
	unsigned int i;
	unsigned int query0;

	/*
	 * As an optimization, skip any checks if the query is empty.
	 */
	DSVC_QINIT(query0);
	if (query == query0)
		return (B_TRUE);

	if (DSVC_QISEQ(query, DN_QLEASE) &&
	    targetp->dn_lease != dnp->dn_lease)
		return (B_FALSE);
	if (DSVC_QISNEQ(query, DN_QLEASE) &&
	    targetp->dn_lease == dnp->dn_lease)
		return (B_FALSE);

	if (DSVC_QISEQ(query, DN_QCIP) &&
	    dnp->dn_cip.s_addr != targetp->dn_cip.s_addr)
		return (B_FALSE);
	if (DSVC_QISNEQ(query, DN_QCIP) &&
	    dnp->dn_cip.s_addr == targetp->dn_cip.s_addr)
		return (B_FALSE);

	if (DSVC_QISEQ(query, DN_QCID) &&
	    (dnp->dn_cid_len != targetp->dn_cid_len ||
	    (memcmp(dnp->dn_cid, targetp->dn_cid, dnp->dn_cid_len) != 0)))
		return (B_FALSE);
	if (DSVC_QISNEQ(query, DN_QCID) &&
	    (dnp->dn_cid_len == targetp->dn_cid_len &&
	    (memcmp(dnp->dn_cid, targetp->dn_cid, dnp->dn_cid_len) == 0)))
		return (B_FALSE);

	if (DSVC_QISEQ(query, DN_QSIP) &&
	    dnp->dn_sip.s_addr != targetp->dn_sip.s_addr)
		return (B_FALSE);
	if (DSVC_QISNEQ(query, DN_QSIP) &&
	    dnp->dn_sip.s_addr == targetp->dn_sip.s_addr)
		return (B_FALSE);

	if (DSVC_QISEQ(query, DN_QMACRO) &&
	    strcmp(targetp->dn_macro, dnp->dn_macro) != 0)
		return (B_FALSE);
	if (DSVC_QISNEQ(query, DN_QMACRO) &&
	    strcmp(targetp->dn_macro, dnp->dn_macro) == 0)
		return (B_FALSE);

	for (i = 0; i < sizeof (qflags) / sizeof (unsigned int); i++) {
		if (DSVC_QISEQ(query, qflags[i]) &&
		    (dnp->dn_flags & flags[i]) !=
		    (targetp->dn_flags & flags[i]))
			return (B_FALSE);
		if (DSVC_QISNEQ(query, qflags[i]) &&
		    (dnp->dn_flags & flags[i]) ==
		    (targetp->dn_flags & flags[i]))
			return (B_FALSE);
	}

	return (B_TRUE);
}

int
add_dn(void *handle, dn_rec_t *addp)
{
	dn_filerec_t	rec, rec_next;
	dn_recid_t	recid, recid_head;
	uint16_t	hash;
	uchar_t		image;
	int		retval;
	dn_handle_t	*dhp = (dn_handle_t *)handle;
	int		fd = dhp->dh_fd;

	if ((dhp->dh_oflags & DSVC_WRITE) == 0)
		return (DSVC_ACCESS);

	retval = check_dn(dhp);
	if (retval != DSVC_SUCCESS)
		return (retval);

	hash = cidhash(addp->dn_cid, addp->dn_cid_len);

	/*
	 * Get the active image.
	 */
	retval = getabyte(fd, offsetof(dn_header_t, dnh_image), &image);
	if (retval != DSVC_SUCCESS)
		return (retval);

	/*
	 * Doublecheck to make sure this entry doesn't exist already.
	 */
	recid = RECID(addp->dn_cip.s_addr, dhp->dh_netmask);
	if (read_rec(fd, &rec, recid) == -1)
		return (syserr_to_dsvcerr(errno));

	if (rec.rec_prev[image] != DN_NOREC)
		return (DSVC_EXISTS);

	/*
	 * We're going to insert `rec' at the head of the `hash' hash
	 * chain; get it ready-to-go.  Note that we update the alternate
	 * image's hash record id pointers so that the record will
	 * atomically become in-use when we switch to the alternate image.
	 */
	if (read_hashhead(fd, &recid_head, hash, image) == -1)
		return (syserr_to_dsvcerr(errno));

	rec.rec_dn = *addp;
	rec.rec_dn.dn_sig = gensig();
	rec.rec_prev[!image] = DN_HASHHEAD;
	rec.rec_next[!image] = recid_head;

	/*
	 * If there's a record currently on the hash chain (i.e, we're
	 * not the first) then load the record.
	 */
	if (rec.rec_next[!image] != DN_NOREC) {
		if (read_rec(fd, &rec_next, rec.rec_next[!image]) == -1)
			return (syserr_to_dsvcerr(errno));
	}

	/*
	 * Before we update any information on disk, mark the container as
	 * dirty so that there's no chance the container is inconsistent
	 * without us knowing about it.
	 */
	retval = setabyte(fd, offsetof(dn_header_t, dnh_dirty), 1);
	if (retval != DSVC_SUCCESS)
		return (retval);

	/*
	 * Update the new record on-disk; note that it's not yet reachable
	 * via hash.
	 */
	if (write_rec(fd, &rec, recid) == -1)
		return (syserr_to_dsvcerr(errno));

	/*
	 * Update the alternate image's on-disk hash pointers.  We need to
	 * do this before we switch to the alternate image so we cannot
	 * abort with an inconsistent active image.
	 */
	if (rec.rec_next[!image] != DN_NOREC) {
		rec_next.rec_prev[!image] = recid;
		if (write_rec(fd, &rec_next, rec.rec_next[!image]) == -1)
			return (syserr_to_dsvcerr(errno));
	}
	if (write_hashhead(fd, recid, hash, !image) == -1)
		return (syserr_to_dsvcerr(errno));

	/*
	 * Activate the alternate image.  This is our commit point -- if we
	 * fail after this point, we will roll forward on recovery.
	 */
	image = !image;
	retval = setabyte(fd, offsetof(dn_header_t, dnh_image), image);
	if (retval != DSVC_SUCCESS)
		return (retval);

	/*
	 * Update the old record id pointers to match
	 */
	rec.rec_prev[!image] = rec.rec_prev[image];
	rec.rec_next[!image] = rec.rec_next[image];
	if (write_rec(fd, &rec, recid) == -1)
		return (syserr_to_dsvcerr(errno));

	if (rec.rec_next[!image] != DN_NOREC) {
		rec_next.rec_prev[!image] = recid;
		if (write_rec(fd, &rec_next, rec.rec_next[!image]) == -1)
			return (syserr_to_dsvcerr(errno));
	}
	if (write_hashhead(fd, recid, hash, !image) == -1)
		return (syserr_to_dsvcerr(errno));

	/*
	 * Update the signature on the record handed back to the caller.
	 */
	addp->dn_sig = rec.rec_dn.dn_sig;

	/*
	 * Finally, mark the container as clean.
	 */
	return (setabyte(fd, offsetof(dn_header_t, dnh_dirty), 0));
}

int
delete_dn(void *handle, const dn_rec_t *delp)
{
	dn_filerec_t	rec, rec_prev, rec_next;
	dn_recid_t	recid;
	uint16_t	hash;
	uchar_t		image;
	int		retval;
	dn_handle_t	*dhp = (dn_handle_t *)handle;
	int		fd = dhp->dh_fd;

	if ((dhp->dh_oflags & DSVC_WRITE) == 0)
		return (DSVC_ACCESS);

	retval = check_dn(dhp);
	if (retval != DSVC_SUCCESS)
		return (retval);

	/*
	 * Get the active image.
	 */
	retval = getabyte(fd, offsetof(dn_header_t, dnh_image), &image);
	if (retval != DSVC_SUCCESS)
		return (retval);

	/*
	 * Find the original entry in the network table, make sure the
	 * record is in-use, and check the signature field (to guard
	 * against collisions).
	 */
	recid = RECID(delp->dn_cip.s_addr, dhp->dh_netmask);
	if (read_rec(fd, &rec, recid) == -1)
		return (syserr_to_dsvcerr(errno));

	if (rec.rec_prev[image] == DN_NOREC)
		return (DSVC_NOENT);

	hash = cidhash(rec.rec_dn.dn_cid, rec.rec_dn.dn_cid_len);

	/*
	 * The signatures must match to delete a record, *except* when
	 * delp->dn_sig == 0.  This is so records can be deleted that
	 * weren't retrieved via lookup_dn()
	 */
	if (delp->dn_sig != 0 && rec.rec_dn.dn_sig != delp->dn_sig)
		return (DSVC_COLLISION);

	/*
	 * Read our neighboring records.
	 */
	if (rec.rec_next[image] != DN_NOREC) {
		if (read_rec(fd, &rec_next, rec.rec_next[image]) == -1)
			return (syserr_to_dsvcerr(errno));
	}

	if (rec.rec_prev[image] != DN_HASHHEAD) {
		if (read_rec(fd, &rec_prev, rec.rec_prev[image]) == -1)
			return (syserr_to_dsvcerr(errno));
	}

	/*
	 * Before we update the alternate image's on-disk hash pointers,
	 * mark the container as dirty so that there's no chance the
	 * container is inconsistent without us knowing about it.
	 */
	retval = setabyte(fd, offsetof(dn_header_t, dnh_dirty), 1);
	if (retval != DSVC_SUCCESS)
		return (retval);

	/*
	 * Update the alternate image's on-disk hash pointers.  We need to
	 * do this before we switch to the alternate image so we do not
	 * abort with an inconsistent active image.  Also reset the
	 * record's alternate image record id pointers, so that the old
	 * record will not be in-use when we switch to the alternate image.
	 */
	if (rec.rec_next[image] != DN_NOREC) {
		rec_next.rec_prev[!image] = rec.rec_prev[image];
		if (write_rec(fd, &rec_next, rec.rec_next[image]) == -1)
			return (syserr_to_dsvcerr(errno));
	}

	if (rec.rec_prev[image] != DN_HASHHEAD) {
		rec_prev.rec_next[!image] = rec.rec_next[image];
		if (write_rec(fd, &rec_prev, rec.rec_prev[image]) == -1)
			return (syserr_to_dsvcerr(errno));
	} else {
		if (write_hashhead(fd, rec.rec_next[image], hash, !image) == -1)
			return (syserr_to_dsvcerr(errno));
	}

	rec.rec_next[!image] = DN_NOREC;
	rec.rec_prev[!image] = DN_NOREC;
	if (write_rec(fd, &rec, recid) == -1)
		return (syserr_to_dsvcerr(errno));

	/*
	 * Activate the alternate image.  This is our commit point -- if we
	 * fail after this point, we will roll forward on recovery.
	 */
	image = !image;
	retval = setabyte(fd, offsetof(dn_header_t, dnh_image), image);
	if (retval != DSVC_SUCCESS)
		return (retval);

	/*
	 * Update the old record id pointers to match.
	 */
	if (rec.rec_next[!image] != DN_NOREC) {
		rec_next.rec_prev[!image] = rec.rec_prev[!image];
		if (write_rec(fd, &rec_next, rec.rec_next[!image]) == -1)
			return (syserr_to_dsvcerr(errno));
	}

	if (rec.rec_prev[!image] != DN_HASHHEAD) {
		rec_prev.rec_next[!image] = rec.rec_next[!image];
		if (write_rec(fd, &rec_prev, rec.rec_prev[!image]) == -1)
			return (syserr_to_dsvcerr(errno));
	} else {
		if (write_hashhead(fd, rec.rec_next[!image], hash, !image)
		    == -1)
			return (syserr_to_dsvcerr(errno));
	}

	rec.rec_next[!image] = DN_NOREC;
	rec.rec_prev[!image] = DN_NOREC;
	if (write_rec(fd, &rec, recid) == -1)
		return (syserr_to_dsvcerr(errno));

	/*
	 * Finally, mark the container as clean.
	 */
	return (setabyte(fd, offsetof(dn_header_t, dnh_dirty), 0));
}

int
modify_dn(void *handle, const dn_rec_t *origp, dn_rec_t *newp)
{
	dn_filerec_t	rec, new_rec, rec_head, rec_next, rec_prev;
	dn_recid_t	recid, new_recid, recid_head;
	uint16_t	hash, new_hash;
	uchar_t		image;
	int		retval;
	dn_handle_t	*dhp = (dn_handle_t *)handle;
	int		fd = dhp->dh_fd;

	if ((dhp->dh_oflags & DSVC_WRITE) == 0)
		return (DSVC_ACCESS);

	retval = check_dn(dhp);
	if (retval != DSVC_SUCCESS)
		return (retval);

	/*
	 * Get the active image
	 */
	retval = getabyte(fd, offsetof(dn_header_t, dnh_image), &image);
	if (retval != DSVC_SUCCESS)
		return (retval);

	/*
	 * Find the original entry in the network table, make sure the
	 * entry is in-use, and check the signature field (to guard against
	 * collisions).
	 */
	recid = RECID(origp->dn_cip.s_addr, dhp->dh_netmask);
	if (read_rec(fd, &rec, recid) == -1)
		return (syserr_to_dsvcerr(errno));

	if (rec.rec_prev[image] == DN_NOREC)
		return (DSVC_NOENT);

	if (rec.rec_dn.dn_sig != origp->dn_sig)
		return (DSVC_COLLISION);

	/*
	 * Check if the record id is changing (as a result of modifying the
	 * IP address). If it is, then make sure the new one is available
	 * (if not, fail with DSVC_EXISTS).
	 */
	new_recid = RECID(newp->dn_cip.s_addr, dhp->dh_netmask);
	if (recid != new_recid) {
		if (read_rec(fd, &new_rec, new_recid) == -1)
			return (syserr_to_dsvcerr(errno));
		if (new_rec.rec_prev[image] != DN_NOREC)
			return (DSVC_EXISTS);
	}

	/*
	 * Update the record with the new information.
	 */
	new_rec.rec_dn = *newp;
	new_rec.rec_dn.dn_sig = origp->dn_sig + 1;

	/*
	 * Find out if our hash chain is changing.  If so, then update the
	 * new record's record id pointers to be on the new chain;
	 * otherwise just take the original record's pointers.  Note that
	 * in either case, only update the alternate image pointers, so
	 * that the new record becomes in-use when we switch to the
	 * alternate image.
	 */
	hash = cidhash(rec.rec_dn.dn_cid, rec.rec_dn.dn_cid_len);
	new_hash = cidhash(newp->dn_cid, newp->dn_cid_len);

	if (hash == new_hash) {
		new_rec.rec_prev[!image] = rec.rec_prev[image];
		new_rec.rec_next[!image] = rec.rec_next[image];
	} else {
		if (read_hashhead(fd, &recid_head, new_hash, image) == -1)
			return (syserr_to_dsvcerr(errno));

		new_rec.rec_prev[!image] = DN_HASHHEAD;
		new_rec.rec_next[!image] = recid_head;
	}

	/*
	 * Write the record out; if this means overwriting the old record,
	 * then write to a temporary record instead.
	 */
	if (write_rec(fd, &new_rec, new_recid == recid ? DN_TEMPREC : new_recid)
	    == -1)
		return (syserr_to_dsvcerr(errno));

	/*
	 * Mark the container as dirty so that there's no chance the
	 * container is inconsistent without us knowing about it.
	 */
	retval = setabyte(fd, offsetof(dn_header_t, dnh_dirty), 1);
	if (retval != DSVC_SUCCESS)
		return (retval);

	/*
	 * If we've changed either the hash chain or the record id, then
	 * update our neighboring records' record id pointers.  If we're
	 * changing hash chains, then remove ourselves from the old
	 * hash chain and insert ourselves on the new one -- otherwise, if
	 * we're changing record id's, then update our neighbors with our
	 * new record id.  Note that we only apply these changes to the
	 * alternate image for now so that we can recover upon failure.
	 */
	if (hash != new_hash || recid != new_recid) {
		if (rec.rec_next[image] != DN_NOREC) {
			if (read_rec(fd, &rec_next, rec.rec_next[image]) == -1)
				return (syserr_to_dsvcerr(errno));
		}
		if (rec.rec_prev[image] != DN_HASHHEAD) {
			if (read_rec(fd, &rec_prev, rec.rec_prev[image]) == -1)
				return (syserr_to_dsvcerr(errno));
		}

		if (hash != new_hash) {
			rec_next.rec_prev[!image] = rec.rec_prev[!image];
			rec_prev.rec_next[!image] = rec.rec_next[!image];
		} else {
			rec_next.rec_prev[!image] = new_recid;
			rec_prev.rec_next[!image] = new_recid;
		}

		if (rec.rec_next[image] != DN_NOREC) {
			if (write_rec(fd, &rec_next, rec.rec_next[image]) == -1)
				return (syserr_to_dsvcerr(errno));
		}
		if (rec.rec_prev[image] != DN_HASHHEAD) {
			if (write_rec(fd, &rec_prev, rec.rec_prev[image]) == -1)
				return (syserr_to_dsvcerr(errno));
		} else {
			if (write_hashhead(fd, rec_prev.rec_next[!image], hash,
			    !image) == -1)
				return (syserr_to_dsvcerr(errno));
		}

		/*
		 * If our hash is changing, update the alternate image
		 * record id pointers to point to our moved record.
		 */
		if (hash != new_hash) {
			if (recid_head != DN_NOREC) {
				if (read_rec(fd, &rec_head, recid_head) == -1)
					return (syserr_to_dsvcerr(errno));
				rec_head.rec_prev[!image] = new_recid;
				if (write_rec(fd, &rec_head, recid_head) == -1)
					return (syserr_to_dsvcerr(errno));
			}
			if (write_hashhead(fd, new_recid, new_hash, !image)
			    == -1)
				return (syserr_to_dsvcerr(errno));
		}

		/*
		 * If our record id is changing, reset the old record's
		 * alternate image record id pointers, so that the old
		 * record will not be in-use once we switch over to the
		 * alternate image.
		 */
		if (recid != new_recid) {
			rec.rec_prev[!image] = DN_NOREC;
			rec.rec_next[!image] = DN_NOREC;
			if (write_rec(fd, &rec, recid) == -1)
				return (syserr_to_dsvcerr(errno));
		}
	}

	/*
	 * If we're using the temporary record, then set `dnh_tempimage' to
	 * the image that will be active when we're done.  This piece of
	 * state is critical in the case of failure, since it indicates
	 * both that the temporary record is valid, and tells us whether we
	 * failed before or after activating the alternate image (below).
	 * If we failed before activating the alternate image, then the
	 * failure code can just reset `dnh_tempimage' to DN_NOIMAGE and
	 * resynchronize the pointers.  Otherwise, we failed somewhere
	 * after making the alternate image active but before we completed
	 * copying the temporary record over to the actual record, which
	 * the recovery code will then complete on our behalf before
	 * resynchronizing the pointers.
	 */
	if (recid == new_recid) {
		retval = setabyte(fd, offsetof(dn_header_t, dnh_tempimage),
		    !image);
		if (retval != DSVC_SUCCESS)
			return (retval);
	}

	/*
	 * Activate the alternate image.  This is our commit point -- if we
	 * fail after this point, we will roll forward on recovery.
	 */
	image = !image;
	retval = setabyte(fd, offsetof(dn_header_t, dnh_image), image);
	if (retval != DSVC_SUCCESS)
		return (retval);

	/*
	 * If we used the temporary record, copy the data into the actual
	 * record.  Once finished, reset `dnh_tempimage' to DN_NOIMAGE
	 * since the temporary record no longer needs to be used.
	 */
	if (recid == new_recid) {
		if (write_rec(fd, &new_rec, new_recid) == -1)
			return (syserr_to_dsvcerr(errno));

		retval = setabyte(fd, offsetof(dn_header_t, dnh_tempimage),
		    DN_NOIMAGE);
		if (retval != DSVC_SUCCESS)
			return (retval);
	}

	/*
	 * Update the old record id pointers to match.
	 */
	new_rec.rec_prev[!image] = new_rec.rec_prev[image];
	new_rec.rec_next[!image] = new_rec.rec_next[image];
	if (write_rec(fd, &new_rec, new_recid) == -1)
		return (syserr_to_dsvcerr(errno));

	if (hash != new_hash || recid != new_recid) {
		if (rec.rec_next[image] != DN_NOREC) {
			rec_next.rec_prev[!image] = rec.rec_prev[image];
			if (write_rec(fd, &rec_next, rec.rec_next[image]) == -1)
				return (syserr_to_dsvcerr(errno));
		}
		if (rec.rec_prev[image] != DN_HASHHEAD) {
			rec_prev.rec_next[!image] = rec.rec_next[image];
			if (write_rec(fd, &rec_prev, rec.rec_prev[image]) == -1)
				return (syserr_to_dsvcerr(errno));
		} else {
			if (write_hashhead(fd, rec.rec_next[image], hash,
			    !image) == -1)
				return (syserr_to_dsvcerr(errno));
		}

		/*
		 * If our hash changed, update the alternate image record
		 * id pointers to point to our moved record.
		 */
		if (hash != new_hash) {
			if (recid_head != DN_NOREC) {
				rec_head.rec_prev[!image] =
				    rec_head.rec_prev[image];
				if (write_rec(fd, &rec_head, recid_head) == -1)
					return (syserr_to_dsvcerr(errno));
			}
			if (write_hashhead(fd, new_recid, new_hash, !image)
			    == -1)
				return (syserr_to_dsvcerr(errno));
		}

		/*
		 * If our record id changed, then finish marking the old
		 * record as "not in use".
		 */
		if (recid != new_recid) {
			rec.rec_prev[!image] = DN_NOREC;
			rec.rec_next[!image] = DN_NOREC;
			if (write_rec(fd, &rec, recid) == -1)
				return (syserr_to_dsvcerr(errno));
		}
	}

	/*
	 * Update the signature on the new record handed back to the caller.
	 */
	newp->dn_sig = new_rec.rec_dn.dn_sig;

	/*
	 * Finally, mark the container as clean.
	 */
	return (setabyte(fd, offsetof(dn_header_t, dnh_dirty), 0));
}

int
list_dn(const char *location, char ***listppp, uint_t *countp)
{
	char		ipaddr[INET_ADDRSTRLEN];
	struct dirent	*result;
	DIR		*dirp;
	unsigned int	i, count = 0;
	char		*re, **new_listpp, **listpp = NULL;
	char		conver[4];
	int		error;

	dirp = opendir(location);
	if (dirp == NULL) {
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

	/*
	 * Compile a regular expression matching "SUNWbinfilesX_" (where X
	 * is a container version number) followed by an IP address
	 * (roughly speaking).  Note that the $N constructions allow us to
	 * get the container version and IP address when calling regex(3C).
	 */
	re = regcmp("^SUNWbinfiles([0-9]{1,3})$0_"
	    "(([0-9]{1,3}_){3}[0-9]{1,3})$1$", (char *)0);
	if (re == NULL)
		return (DSVC_NO_MEMORY);

	while ((result = readdir(dirp)) != NULL) {

		if (regex(re, result->d_name, conver, ipaddr) != NULL) {
			if (atoi(conver) != DSVC_CONVER)
				continue;

			for (i = 0; ipaddr[i] != '\0'; i++)
				if (ipaddr[i] == '_')
					ipaddr[i] = '.';

			new_listpp = realloc(listpp,
			    (sizeof (char **)) * (count + 1));
			if (new_listpp == NULL) {
				error = DSVC_NO_MEMORY;
				goto fail;
			}
			listpp = new_listpp;
			listpp[count] = strdup(ipaddr);
			if (listpp[count] == NULL) {
				error = DSVC_NO_MEMORY;
				goto fail;
			}
			count++;
		}
	}
	free(re);
	(void) closedir(dirp);

	*countp = count;
	*listppp = listpp;
	return (DSVC_SUCCESS);
fail:
	free(re);
	(void) closedir(dirp);

	for (i = 0; i < count; i++)
		free(listpp[i]);
	free(listpp);
	return (error);
}

/*
 * Check (a la fsck) that a given DHCP network container is in a consistent
 * state.  If not, then attempt to restore internal consistency; this should
 * always be possible unless the container has been externally corrupted.
 */
static int
check_dn(dn_handle_t *dhp)
{
	dn_header_t	header;
	uchar_t		image, dirty;
	uint16_t	hash;
	dn_filerec_t	rec;
	dn_recid_t	recid, maxrecid;
	int		retval;

	/*
	 * Reading the whole header is a very expensive operation; only do
	 * it once we're sure the container is actually dirty.  On an
	 * E4500, this optimization lowers the wall-clock cost of creating
	 * a 5000-record datastore by 20 percent.
	 */
	retval = getabyte(dhp->dh_fd, offsetof(dn_header_t, dnh_dirty), &dirty);
	if (retval != DSVC_SUCCESS)
		return (retval);

	if (dirty == 0)
		return (DSVC_SUCCESS);

	if (read_header(dhp->dh_fd, &header, B_TRUE) == -1)
		return (syserr_to_dsvcerr(errno));

	/*
	 * If `dnh_tempimage' matches the current working image, then we
	 * crashed in the middle of a modify_dn() operation.  Complete
	 * writing out the temporary record before restoring internal
	 * consistency.  This is a bit of a kludge but there doesn't seem
	 * to be another way.
	 */
	if (header.dnh_tempimage == header.dnh_image) {
		recid = RECID(header.dnh_temp.rec_dn.dn_cip.s_addr,
		    header.dnh_netmask);
		if (write_rec(dhp->dh_fd, &header.dnh_temp, recid) == -1)
			return (syserr_to_dsvcerr(errno));

		header.dnh_tempimage = DN_NOIMAGE;
	}

	/*
	 * Blindly update all the header hashhead pointers since we're
	 * going to have to re-write the header anyway.
	 */
	image = header.dnh_image;
	for (hash = 0; hash < DN_CIDHASHSZ; hash++) {
		header.dnh_cidhash[hash][!image] =
		    header.dnh_cidhash[hash][image];
	}

	/*
	 * Synchronize the record pointers of all in-use records.  We do
	 * this instead of just walking the hashheads because not all dirty
	 * records are hashed (for instance, we may have failed part way
	 * through an add_dn()).
	 */
	maxrecid = RECID(~0, header.dnh_netmask);
	for (recid = RECID(0, header.dnh_netmask); recid <= maxrecid; recid++) {
		if (read_rec(dhp->dh_fd, &rec, recid) == -1)
			return (syserr_to_dsvcerr(errno));

		/*
		 * Verify the pointers match.  If not, then correct
		 * the record and write it back to disk.
		 */
		if (rec.rec_next[image] != rec.rec_next[!image] ||
		    rec.rec_prev[image] != rec.rec_prev[!image]) {
			header.dnh_errors++;

			rec.rec_prev[!image] = rec.rec_prev[image];
			rec.rec_next[!image] = rec.rec_next[image];

			if (write_rec(dhp->dh_fd, &rec, recid) == -1)
				return (syserr_to_dsvcerr(errno));
		}
	}

	header.dnh_checks++;
	if (write_header(dhp->dh_fd, &header) == -1)
		return (syserr_to_dsvcerr(errno));

	/*
	 * Clear the dirty bit on the container.
	 */
	return (setabyte(dhp->dh_fd, offsetof(dn_header_t, dnh_dirty), 0));
}

/*
 * Given a buffer `path' of `pathlen' bytes, fill it in with a path to the
 * DHCP Network table for IP network `ip' located in directory `dir'.
 */
static void
net2path(char *path, size_t pathlen, const char *dir, ipaddr_t ip)
{
	(void) snprintf(path, pathlen, "%s/SUNWbinfiles%u_%d_%d_%d_%d", dir,
	    DSVC_CONVER, ip >> 24, (ip >> 16) & 0xff, (ip >> 8) & 0xff,
	    ip & 0xff);
}

/*
 * Given a `cid' that's `cidlen' bytes long, hash it to a value between 0
 * and DN_CIDHASHSZ - 1.  We use CRC16 for our hash since it's known to be
 * very evenly distributed.
 */
static uint16_t
cidhash(const uchar_t *cid, size_t cidlen)
{
	uchar_t		bit;
	uint16_t	result = 0xffff;
	const uint16_t	crc16_poly = 0x8408; /* mutated CRC-CCITT polynomial */

	while (cidlen-- != 0) {
		result ^= *cid++;
		for (bit = 0; bit < 8; bit++) {
			if (result & 1)
				result = (result >> 1) ^ crc16_poly;
			else
				result >>= 1;
		}
	}
	return (result % DN_CIDHASHSZ);
}

/*
 * Convert the dn_filerec_t pointed to by `rec' from native (host) to
 * network order or the other way.
 */
/* ARGSUSED */
static void
nhconvert_rec(dn_filerec_t *rec)
{
#ifdef	_LITTLE_ENDIAN
	dn_rec_t *dnp = &rec->rec_dn;

	nhconvert(&rec->rec_prev[0], &rec->rec_prev[0], sizeof (dn_recid_t));
	nhconvert(&rec->rec_prev[1], &rec->rec_prev[1], sizeof (dn_recid_t));
	nhconvert(&rec->rec_next[0], &rec->rec_next[0], sizeof (dn_recid_t));
	nhconvert(&rec->rec_next[1], &rec->rec_next[1], sizeof (dn_recid_t));

	nhconvert(&dnp->dn_cip.s_addr, &dnp->dn_cip.s_addr, sizeof (ipaddr_t));
	nhconvert(&dnp->dn_sip.s_addr, &dnp->dn_sip.s_addr, sizeof (ipaddr_t));
	nhconvert(&dnp->dn_lease, &dnp->dn_lease, sizeof (lease_t));
	nhconvert(&dnp->dn_sig, &dnp->dn_sig, sizeof (uint64_t));
#endif
}

/*
 * Convert the header pointed to by `hdrp' from native (host) to network
 * order or the other way.  If `hash' is false, then don't bother
 * converting the hash chains.
 */
/* ARGSUSED */
static void
nhconvert_header(dn_header_t *hdrp, boolean_t hash)
{
#ifdef	_LITTLE_ENDIAN
	unsigned int i;

	nhconvert(&hdrp->dnh_network, &hdrp->dnh_network, sizeof (ipaddr_t));
	nhconvert(&hdrp->dnh_netmask, &hdrp->dnh_netmask, sizeof (ipaddr_t));
	nhconvert(&hdrp->dnh_magic, &hdrp->dnh_magic, sizeof (uint32_t));
	nhconvert_rec(&hdrp->dnh_temp);

	if (hash) {
		for (i = 0; i < DN_CIDHASHSZ; i++) {
			nhconvert(&hdrp->dnh_cidhash[i][0],
			    &hdrp->dnh_cidhash[i][0], sizeof (dn_recid_t));
			nhconvert(&hdrp->dnh_cidhash[i][1],
			    &hdrp->dnh_cidhash[i][1], sizeof (dn_recid_t));
		}
	}
#endif
}

/*
 * Read the dn_filerec_t identified by `recid' from open container `fd'
 * into `rec'.  Returns 0 on success, -1 on failure (errno is set).
 */
static int
read_rec(int fd, dn_filerec_t *rec, dn_recid_t recid)
{
	if (pnread(fd, rec, sizeof (*rec), RECID2OFFSET(recid)) == -1)
		return (-1);

	nhconvert_rec(rec);
	return (0);
}

/*
 * Write the dn_filerec_t `rec' identified by `recid' into the open
 * container `fd'.  Returns 0 on success, -1 on failure (errno is set).
 */
static int
write_rec(int fd, dn_filerec_t *rec, dn_recid_t recid)
{
	int retval;

	nhconvert_rec(rec);
	retval = pnwrite(fd, rec, sizeof (*rec), RECID2OFFSET(recid));
	nhconvert_rec(rec);
	return (retval);
}

/*
 * Read the dn_header_t from the open container `fd' into the dn_header_t
 * pointed to by `hdrp'; if `hash' is not set, then skip reading the
 * dn_header_t hash chains.  Returns 0 on success, -1 on failure (errno is
 * set).
 */
static int
read_header(int fd, dn_header_t *hdrp, boolean_t hash)
{
	size_t size;

	size = hash ? sizeof (dn_header_t) : offsetof(dn_header_t, dnh_cidhash);
	if (pnread(fd, hdrp, size, 0) == -1)
		return (-1);

	nhconvert_header(hdrp, hash);
	return (0);
}

/*
 * Write the dn_header_t pointed to by `hdrp' into open container `fd'.
 * Returns 0 on success, -1 on failure (errno is set).
 */
static int
write_header(int fd, dn_header_t *hdrp)
{
	int retval;

	nhconvert_header(hdrp, B_TRUE);
	retval = pnwrite(fd, hdrp, sizeof (dn_header_t), 0);
	nhconvert_header(hdrp, B_TRUE);
	return (retval);
}

/*
 * Read in the head of the `cidhash' hash chain from open container `fd'
 * into `recid_headp', using image `image'.  Returns 0 on success, -1 on
 * failure (errno is set).
 */
static int
read_hashhead(int fd, dn_recid_t *recid_headp, uint16_t cidhash, uchar_t image)
{
	if (pnread(fd, recid_headp, sizeof (dn_recid_t),
	    offsetof(dn_header_t, dnh_cidhash[cidhash][image])) == -1)
		return (-1);

	nhconvert(recid_headp, recid_headp, sizeof (dn_recid_t));
	return (0);
}

/*
 * Write out the head of the `cidhash' hash chain into open container `fd'
 * from `recid_head', using image `image'.  Returns 0 on success, -1 on
 * failure (errno is set).
 */
static int
write_hashhead(int fd, dn_recid_t recid_head, uint16_t cidhash, uchar_t image)
{
	nhconvert(&recid_head, &recid_head, sizeof (dn_recid_t));
	return (pnwrite(fd, &recid_head, sizeof (dn_recid_t),
	    offsetof(dn_header_t, dnh_cidhash[cidhash][image])));
}

/*
 * Get the byte `offset' bytes into open file `fd', and store in `bytep'.
 * Returns a DSVC_* return code.
 */
static int
getabyte(int fd, off_t offset, uchar_t *bytep)
{
	switch (pread(fd, bytep, 1, offset)) {
	case 1:
		return (DSVC_SUCCESS);
	case -1:
		return (syserr_to_dsvcerr(errno));
	default:
		break;
	}

	return (DSVC_INTERNAL);
}

/*
 * Set the byte `offset' bytes into open file `fd' to `byte'.  Returns a
 * DSVC_* return code.
 */
static int
setabyte(int fd, off_t offset, uchar_t byte)
{
	switch (pwrite(fd, &byte, 1, offset)) {
	case 1:
		return (DSVC_SUCCESS);
	case -1:
		return (syserr_to_dsvcerr(errno));
	default:
		break;
	}

	return (DSVC_INTERNAL);
}
