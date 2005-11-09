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
 * This file contains public functions for managing legacy DHCP network
 * containers.  For the semantics of these functions, please see the
 * Enterprise DHCP Architecture Document.
 */

#include <alloca.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <dhcp_svc_public.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <libinetutil.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "dhcp_network.h"
#include "util.h"

static void net2path(char *, size_t, const char *, ipaddr_t, const char *);
static boolean_t record_match(char *[], dn_rec_t *, const dn_rec_t *, uint_t);
static int write_rec(int, dn_rec_t *, off_t);

/* ARGSUSED */
int
open_dn(void **handlep, const char *location, uint_t flags,
    const struct in_addr *netp, const struct in_addr *maskp)
{
	char		dnpath[MAXPATHLEN];
	dn_handle_t	*dhp;
	int		retval;
	int		fd;

	dhp = malloc(sizeof (dn_handle_t));
	if (dhp == NULL)
		return (DSVC_NO_MEMORY);

	dhp->dh_net = netp->s_addr;
	dhp->dh_oflags = flags;
	(void) strlcpy(dhp->dh_location, location, MAXPATHLEN);

	/*
	 * This is a legacy format which has no header, so we neither write
	 * nor verify a header (we just create the file or make sure it
	 * exists, depending on the value of `flags').
	 */
	net2path(dnpath, MAXPATHLEN, location, netp->s_addr, "");
	retval = open_file(dnpath, flags, &fd);
	if (retval != DSVC_SUCCESS) {
		free(dhp);
		return (retval);
	}
	(void) close(fd);

	*handlep = dhp;
	return (DSVC_SUCCESS);
}

int
close_dn(void **handlep)
{
	free(*handlep);
	return (DSVC_SUCCESS);
}

int
remove_dn(const char *dir, const struct in_addr *netp)
{
	char dnpath[MAXPATHLEN];

	net2path(dnpath, MAXPATHLEN, dir, netp->s_addr, "");
	if (unlink(dnpath) == -1)
		return (syserr_to_dsvcerr(errno));

	return (DSVC_SUCCESS);
}

static int
find_dn(FILE *fp, uint_t flags, uint_t query, int count,
    const dn_rec_t *targetp, dn_rec_list_t **recordsp, uint_t *nrecordsp)
{
	int		retval = DSVC_SUCCESS;
	char		*commentp, *fields[DNF_MAX_FIELDS];
	char 		*buf = NULL;
	uint_t		nrecords;
	dn_rec_t	dn, *recordp;
	dn_rec_list_t	*records, *new_records;
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
		if (buf[0] == DNF_COMMENT_CHAR)
			continue;

		/*
		 * Tell field_split() that there's one less field than
		 * there really is.  We do this so that the comment and the
		 * macro field both end up in the DNF_MACRO field, since
		 * both fields are optional and it requires some fancy
		 * footwork (below) to tell which (if any) the record
		 * contains.
		 */
		nfields = field_split(buf, DNF_MAX_FIELDS - 1, fields, " \t");
		if (nfields < DNF_REQ_FIELDS)
			continue;

		if (nfields == DNF_REQ_FIELDS) {
			fields[DNF_MACRO] = "";
			fields[DNF_COMMENT] = "";
		} else {
			/*
			 * Assume there is a comment; if we hit a comment
			 * delimiter char (DNF_COMMENT_CHAR), then simply
			 * change it to a NUL and advance commentp.  If we
			 * hit whitespace, replace the first instance with
			 * NUL, and go searching for DNF_COMMENT_CHAR.
			 * This step is important since it efficiently
			 * handles the common case where a comment is
			 * preceded by a space.
			 */
			commentp = fields[DNF_MACRO];
			while (!isspace(*commentp) &&
			    *commentp != DNF_COMMENT_CHAR && *commentp != '\0')
				commentp++;

			if (isspace(*commentp)) {
				*commentp++ = '\0';
				commentp = strchr(commentp, DNF_COMMENT_CHAR);
				if (commentp == NULL)
					commentp = "";
			}

			if (*commentp == DNF_COMMENT_CHAR)
				*commentp++ = '\0';

			fields[DNF_COMMENT] = commentp;
		}

		/*
		 * See if we've got a match, filling in dnf.dnf_rec as
		 * we go.  If record_match() succeeds, dnf.dnf_rec will
		 * be completely filled in.
		 */
		if (!record_match(fields, &dn, targetp, query))
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
		 * we need to allocate an extended (dn_recpos_t) record.
		 */
		if (flags & FIND_POSITION)
			recordp = malloc(sizeof (dn_recpos_t));
		else
			recordp = malloc(sizeof (dn_rec_t));

		if (recordp == NULL) {
			if ((flags & FIND_PARTIAL) == 0)
				retval = DSVC_NO_MEMORY;
			break;
		}

		/*
		 * Fill in record; do a structure copy from our automatic
		 * dn.  If FIND_POSITION flag is on, pass back additional
		 * position information.
		 */
		*recordp = dn;
		if (flags & FIND_POSITION) {
			((dn_recpos_t *)recordp)->dnp_off = recoff;
			((dn_recpos_t *)recordp)->dnp_size = ftello(fp) -
			    recoff;
		}

		/*
		 * Chuck the record on the list and up the counter.
		 */
		new_records = add_dnrec_to_list(recordp, records);
		if (new_records == NULL) {
			free(recordp);
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
		free_dnrec_list(records);

	return (retval);
}

int
lookup_dn(void *handle, boolean_t partial, uint_t query, int count,
    const dn_rec_t *targetp, dn_rec_list_t **recordsp, uint_t *nrecordsp)
{
	int		retval;
	char		dnpath[MAXPATHLEN];
	FILE		*fp;
	dn_handle_t	*dhp = (dn_handle_t *)handle;

	if ((dhp->dh_oflags & DSVC_READ) == 0)
		return (DSVC_ACCESS);

	net2path(dnpath, MAXPATHLEN, dhp->dh_location, dhp->dh_net, "");
	fp = fopen(dnpath, "r");
	if (fp == NULL)
		return (syserr_to_dsvcerr(errno));

	retval = find_dn(fp, partial ? FIND_PARTIAL : 0, query, count, targetp,
	    recordsp, nrecordsp);

	(void) fclose(fp);
	return (retval);
}

/*
 * Compares the fields in fields[] agains the fields in target `targetp',
 * using `query' to decide what fields to compare.  Returns B_TRUE if `dnp'
 * matches `targetp', B_FALSE if not.  On success, `dnp' is completely
 * filled in.
 */
static boolean_t
record_match(char *fields[], dn_rec_t *dnp, const dn_rec_t *targetp,
    uint_t query)
{
	unsigned int	qflags[] = { DN_QFDYNAMIC, DN_QFAUTOMATIC, DN_QFMANUAL,
				    DN_QFUNUSABLE, DN_QFBOOTP_ONLY };
	unsigned int	flags[]  = { DN_FDYNAMIC, DN_FAUTOMATIC, DN_FMANUAL,
				    DN_FUNUSABLE, DN_FBOOTP_ONLY };
	unsigned int	i;
	uint_t		dn_cid_len;

	dnp->dn_cip.s_addr = ntohl(inet_addr(fields[DNF_CIP]));
	if (DSVC_QISEQ(query, DN_QCIP) &&
	    dnp->dn_cip.s_addr != targetp->dn_cip.s_addr)
		return (B_FALSE);
	if (DSVC_QISNEQ(query, DN_QCIP) &&
	    dnp->dn_cip.s_addr == targetp->dn_cip.s_addr)
		return (B_FALSE);

	dnp->dn_lease = atoi(fields[DNF_LEASE]);
	if (DSVC_QISEQ(query, DN_QLEASE) && targetp->dn_lease != dnp->dn_lease)
		return (B_FALSE);
	if (DSVC_QISNEQ(query, DN_QLEASE) && targetp->dn_lease == dnp->dn_lease)
		return (B_FALSE);

	/*
	 * We use dn_cid_len since dnp->dn_cid_len is of type uchar_t but
	 * hexascii_to_octet() expects a uint_t *
	 */
	dn_cid_len = DN_MAX_CID_LEN;
	if (hexascii_to_octet(fields[DNF_CID], strlen(fields[DNF_CID]),
	    dnp->dn_cid, &dn_cid_len) != 0)
		return (B_FALSE);

	dnp->dn_cid_len = dn_cid_len;
	if (DSVC_QISEQ(query, DN_QCID) &&
	    (dnp->dn_cid_len != targetp->dn_cid_len ||
	    (memcmp(dnp->dn_cid, targetp->dn_cid, dnp->dn_cid_len) != 0)))
		return (B_FALSE);
	if (DSVC_QISNEQ(query, DN_QCID) &&
	    (dnp->dn_cid_len == targetp->dn_cid_len &&
	    (memcmp(dnp->dn_cid, targetp->dn_cid, dnp->dn_cid_len) == 0)))
		return (B_FALSE);

	dnp->dn_sip.s_addr = ntohl(inet_addr(fields[DNF_SIP]));
	if (DSVC_QISEQ(query, DN_QSIP) &&
	    dnp->dn_sip.s_addr != targetp->dn_sip.s_addr)
		return (B_FALSE);
	if (DSVC_QISNEQ(query, DN_QSIP) &&
	    dnp->dn_sip.s_addr == targetp->dn_sip.s_addr)
		return (B_FALSE);

	(void) strlcpy(dnp->dn_macro, fields[DNF_MACRO],
	    sizeof (dnp->dn_macro));
	if (DSVC_QISEQ(query, DN_QMACRO) &&
	    strcmp(targetp->dn_macro, dnp->dn_macro) != 0)
		return (B_FALSE);
	if (DSVC_QISNEQ(query, DN_QMACRO) &&
	    strcmp(targetp->dn_macro, dnp->dn_macro) == 0)
		return (B_FALSE);

	dnp->dn_flags = atoi(fields[DNF_FLAGS]);
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
	(void) strlcpy(dnp->dn_comment, fields[DNF_COMMENT],
	    sizeof (dnp->dn_comment));

	return (B_TRUE);
}

/*
 * Internal dhcp_network record update routine, used to factor out the
 * common code between add_dn(), delete_dn(), and modify_dn().  If `origp'
 * is NULL, then act like add_dn(); if `newp' is NULL, then act like
 * delete_dn(); otherwise act like modify_dn().
 */
static int
update_dn(const dn_handle_t *dhp, const dn_rec_t *origp, dn_rec_t *newp)
{
	char		dnpath[MAXPATHLEN], newpath[MAXPATHLEN];
	int		retval = DSVC_SUCCESS;
	off_t		recoff, recnext;
	dn_rec_list_t	*reclist;
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
	net2path(dnpath, MAXPATHLEN, dhp->dh_location, dhp->dh_net, "");
	fp = fopen(dnpath, "r");
	if (fp == NULL)
		return (syserr_to_dsvcerr(errno));

	net2path(newpath, MAXPATHLEN, dhp->dh_location, dhp->dh_net, ".new");
	newfd = open(newpath, O_CREAT|O_TRUNC|O_WRONLY, 0644);
	if (newfd == -1) {
		(void) fclose(fp);
		return (syserr_to_dsvcerr(errno));
	}

	DSVC_QINIT(query);
	DSVC_QEQ(query, DN_QCIP);

	/*
	 * If we're adding a new record or changing a key for an existing
	 * record, bail if the record we want to add already exists.
	 */
	if (newp != NULL) {
		if (origp == NULL ||
		    origp->dn_cip.s_addr != newp->dn_cip.s_addr) {
			retval = find_dn(fp, 0, query, 1, newp, NULL, &found);
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
		retval = find_dn(fp, FIND_POSITION, query, 1, origp, &reclist,
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
		recoff  = ((dn_recpos_t *)reclist->dnl_rec)->dnp_off;
		recnext = recoff + ((dn_recpos_t *)reclist->dnl_rec)->dnp_size;

		free_dnrec_list(reclist);
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
	 * If there's a new/modified record, append it to the new container.
	 */
	if (newp != NULL) {
		retval = write_rec(newfd, newp, recoff + st.st_size - recnext);
		if (retval != DSVC_SUCCESS)
			goto out;
	}

	/*
	 * Note: we close these descriptors before the rename(2) (rather
	 * than just having the `out:' label clean them up) to save NFS
	 * some work (otherwise, NFS has to save `dnpath' to an alternate
	 * name since its vnode would still be active).
	 */
	(void) fclose(fp);
	(void) close(newfd);

	if (rename(newpath, dnpath) == -1)
		retval = syserr_to_dsvcerr(errno);

	return (retval);
out:
	(void) fclose(fp);
	(void) close(newfd);
	(void) unlink(newpath);
	return (retval);
}

int
add_dn(void *handle, dn_rec_t *addp)
{
	return (update_dn((dn_handle_t *)handle, NULL, addp));
}

int
modify_dn(void *handle, const dn_rec_t *origp, dn_rec_t *newp)
{
	return (update_dn((dn_handle_t *)handle, origp, newp));
}

int
delete_dn(void *handle, const dn_rec_t *delp)
{
	return (update_dn((dn_handle_t *)handle, delp, NULL));
}

int
list_dn(const char *location, char ***listppp, uint_t *countp)
{
	char		ipaddr[INET_ADDRSTRLEN];
	struct dirent	*result;
	DIR		*dirp;
	unsigned int	i, count = 0;
	char		*re, **new_listpp, **listpp = NULL;
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
	 * Compile a regular expression matching an IP address delimited by
	 * underscores. Note that the `$0' at the end allows us to save the
	 * IP address in ipaddr when calling regex(3C).
	 */
	re = regcmp("^(([0-9]{1,3}\\_){3}[0-9]{1,3})$0$", (char *)0);
	if (re == NULL)
		return (DSVC_NO_MEMORY);

	while ((result = readdir(dirp)) != NULL) {
		if (regex(re, result->d_name, ipaddr) != NULL) {
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

			/*
			 * Change all underscores to dots.
			 */
			for (i = 0; listpp[count][i] != '\0'; i++) {
				if (listpp[count][i] == '_')
					listpp[count][i] = '.';
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
 * Given a buffer `path' of `pathlen' bytes, fill it in with a path to the
 * DHCP Network table for IP network `ip' located in directory `dir' with a
 * suffix of `suffix'.
 */
static void
net2path(char *path, size_t pathlen, const char *dir, ipaddr_t ip,
    const char *suffix)
{
	(void) snprintf(path, pathlen, "%s/%d_%d_%d_%d%s", dir, ip >> 24,
	    (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff, suffix);
}

/*
 * Write the dn_rec_t `recp' into the open container `fd' at offset
 * `recoff'.  Returns DSVC_* error code.
 */
static int
write_rec(int fd, dn_rec_t *recp, off_t recoff)
{
	char		entbuf[1024], *ent = entbuf;
	size_t		entsize = sizeof (entbuf);
	int		entlen;
	char		dn_cip[INET_ADDRSTRLEN], dn_sip[INET_ADDRSTRLEN];
	char		dn_cid[DN_MAX_CID_LEN * 2 + 1];
	unsigned int	dn_cid_len = sizeof (dn_cid);
	struct in_addr	nip;

	if (octet_to_hexascii(recp->dn_cid, recp->dn_cid_len, dn_cid,
	    &dn_cid_len) != 0)
		return (DSVC_INTERNAL);

	nip.s_addr = htonl(recp->dn_cip.s_addr);
	(void) inet_ntop(AF_INET, &nip, dn_cip, sizeof (dn_cip));
	nip.s_addr = htonl(recp->dn_sip.s_addr);
	(void) inet_ntop(AF_INET, &nip, dn_sip, sizeof (dn_sip));
again:
	if (recp->dn_comment[0] != '\0') {
		entlen = snprintf(ent, entsize, "%s %02hu %s %s %u %s %c%s\n",
		    dn_cid, recp->dn_flags, dn_cip, dn_sip, recp->dn_lease,
		    recp->dn_macro, DNF_COMMENT_CHAR, recp->dn_comment);
	} else {
		entlen = snprintf(ent, entsize, "%s %02hu %s %s %u %s\n",
		    dn_cid, recp->dn_flags, dn_cip, dn_sip, recp->dn_lease,
		    recp->dn_macro);
	}

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
