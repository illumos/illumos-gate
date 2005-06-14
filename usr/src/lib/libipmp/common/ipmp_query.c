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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * IPMP query interfaces (PSARC/2002/615).
 */

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include "ipmp_impl.h"
#include "ipmp_mpathd.h"
#include "ipmp_query_impl.h"

#define	IPMP_REQTIMEOUT	5	/* seconds */

static ipmp_ifinfo_t	*ipmp_ifinfo_clone(ipmp_ifinfo_t *);
static ipmp_grouplist_t	*ipmp_grouplist_clone(ipmp_grouplist_t *);
static ipmp_groupinfo_t	*ipmp_groupinfo_clone(ipmp_groupinfo_t *);
static ipmp_groupinfo_t *ipmp_snap_getgroupinfo(ipmp_snap_t *, const char *);
static ipmp_ifinfo_t	*ipmp_snap_getifinfo(ipmp_snap_t *, const char *);
static int		ipmp_snap_take(ipmp_state_t *, ipmp_snap_t **);
static boolean_t	ipmp_checktlv(ipmp_infotype_t, size_t, void *);
static int		ipmp_querydone(ipmp_state_t *, int);

/*
 * Using `statep', send a query request for `type' to in.mpathd, and if
 * necessary wait until at least `endtp' for a response.  Returns an IPMP
 * error code.  If successful, the caller may then read additional query
 * information through ipmp_readinfo(), and must eventually call
 * ipmp_querydone() to complete the query operation.  Only one query may be
 * outstanding on a given `statep' at a time.
 */
static int
ipmp_sendquery(ipmp_state_t *statep, ipmp_infotype_t type, const char *name,
    struct timeval *endtp)
{
	mi_query_t	query;
	mi_result_t	result;
	int		retval;

	query.miq_command = MI_QUERY;
	query.miq_inforeq = type;

	switch (type) {
	case IPMP_GROUPINFO:
		(void) strlcpy(query.miq_grname, name, LIFGRNAMSIZ);
		break;

	case IPMP_IFINFO:
		(void) strlcpy(query.miq_ifname, name, LIFNAMSIZ);
		break;

	case IPMP_GROUPLIST:
	case IPMP_SNAP:
		break;

	default:
		assert(0);
	}

	if (gettimeofday(endtp, NULL) == -1)
		return (IPMP_FAILURE);

	endtp->tv_sec += IPMP_REQTIMEOUT;

	assert(statep->st_fd == -1);
	retval = ipmp_connect(&statep->st_fd);
	if (retval != IPMP_SUCCESS)
		return (retval);

	retval = ipmp_write(statep->st_fd, &query, sizeof (query));
	if (retval != IPMP_SUCCESS)
		return (ipmp_querydone(statep, retval));

	retval = ipmp_read(statep->st_fd, &result, sizeof (result), endtp);
	if (retval != IPMP_SUCCESS)
		return (ipmp_querydone(statep, retval));

	if (result.me_mpathd_error != IPMP_SUCCESS)
		return (ipmp_querydone(statep, result.me_mpathd_error));

	return (IPMP_SUCCESS);
}

/*
 * Using `statep', read a query response of type `infotype' into a dynamically
 * allocated buffer pointed to by `*infop', before the current time becomes
 * `endtp'.  Returns an IPMP error code.
 */
static int
ipmp_readinfo(ipmp_state_t *statep, ipmp_infotype_t infotype, void **infop,
    const struct timeval *endtp)
{
	int		retval;
	size_t		len;
	ipmp_infotype_t	type;

	retval = ipmp_readtlv(statep->st_fd, &type, &len, infop, endtp);
	if (retval != IPMP_SUCCESS)
		return (retval);

	if (type != infotype || !ipmp_checktlv(type, len, *infop)) {
		free(*infop);
		return (IPMP_EPROTO);
	}

	return (IPMP_SUCCESS);
}

/*
 * Complete the query operation started in ipmp_sendquery().  The interface is
 * designed to be easy to use in the `return' statement of a function, and
 * thus returns the passed in `retval' and preserves `errno'.
 */
static int
ipmp_querydone(ipmp_state_t *statep, int retval)
{
	int error = errno;

	(void) close(statep->st_fd);
	statep->st_fd = -1;
	errno = error;
	return (retval);
}

/*
 * Using `handle', get the group list and store the results in a dynamically
 * allocated buffer pointed to by `*grlistpp'.  Returns an IPMP error code.
 */
int
ipmp_getgrouplist(ipmp_handle_t handle, ipmp_grouplist_t **grlistpp)
{
	ipmp_state_t	*statep = handle;
	struct timeval	end;
	int		retval;

	if (statep->st_snap != NULL) {
		*grlistpp = ipmp_grouplist_clone(statep->st_snap->sn_grlistp);
		return (*grlistpp != NULL ? IPMP_SUCCESS : IPMP_ENOMEM);
	}

	retval = ipmp_sendquery(statep, IPMP_GROUPLIST, NULL, &end);
	if (retval != IPMP_SUCCESS)
		return (retval);

	retval = ipmp_readinfo(statep, IPMP_GROUPLIST, (void **)grlistpp, &end);
	return (ipmp_querydone(statep, retval));
}

/*
 * Free the group list pointed to by `grlistp'.
 */
void
ipmp_freegrouplist(ipmp_grouplist_t *grlistp)
{
	free(grlistp);
}

/*
 * Using `handle', get the group information associated with group `name' and
 * store the results in a dynamically allocated buffer pointed to by
 * `*grinfopp'.  Returns an IPMP error code.
 */
int
ipmp_getgroupinfo(ipmp_handle_t handle, const char *name,
    ipmp_groupinfo_t **grinfopp)
{
	ipmp_state_t	*statep = handle;
	ipmp_iflist_t	*iflistp;
	int		retval;
	struct timeval	end;
	ipmp_groupinfo_t *grinfop;

	if (statep->st_snap != NULL) {
		grinfop = ipmp_snap_getgroupinfo(statep->st_snap, name);
		if (grinfop == NULL)
			return (IPMP_EUNKGROUP);

		*grinfopp = ipmp_groupinfo_clone(grinfop);
		return (*grinfopp != NULL ? IPMP_SUCCESS : IPMP_ENOMEM);
	}

	retval = ipmp_sendquery(statep, IPMP_GROUPINFO, name, &end);
	if (retval != IPMP_SUCCESS)
		return (retval);

	retval = ipmp_readinfo(statep, IPMP_GROUPINFO, (void **)grinfopp, &end);
	if (retval != IPMP_SUCCESS)
		return (ipmp_querydone(statep, retval));

	retval = ipmp_readinfo(statep, IPMP_IFLIST, (void **)&iflistp, &end);
	if (retval != IPMP_SUCCESS)
		free(*grinfopp);
	else
		(*grinfopp)->gr_iflistp = iflistp;

	return (ipmp_querydone(statep, retval));
}

/*
 * Free the group information pointed to by `grinfop'.
 */
void
ipmp_freegroupinfo(ipmp_groupinfo_t *grinfop)
{
	free(grinfop->gr_iflistp);
	free(grinfop);
}

/*
 * Using `handle', get the interface information associated with interface
 * `name' and store the results in a dynamically allocated buffer pointed to
 * by `*ifinfopp'.  Returns an IPMP error code.
 */
int
ipmp_getifinfo(ipmp_handle_t handle, const char *name, ipmp_ifinfo_t **ifinfopp)
{
	ipmp_state_t	*statep = handle;
	ipmp_ifinfo_t	*ifinfop;
	int		retval;
	struct timeval	end;

	if (statep->st_snap != NULL) {
		ifinfop = ipmp_snap_getifinfo(statep->st_snap, name);
		if (ifinfop == NULL)
			return (IPMP_EUNKIF);

		*ifinfopp = ipmp_ifinfo_clone(ifinfop);
		return (*ifinfopp != NULL ? IPMP_SUCCESS : IPMP_ENOMEM);
	}

	retval = ipmp_sendquery(statep, IPMP_IFINFO, name, &end);
	if (retval != IPMP_SUCCESS)
		return (retval);

	retval = ipmp_readinfo(statep, IPMP_IFINFO, (void **)ifinfopp, &end);
	return (ipmp_querydone(statep, retval));
}

/*
 * Free the interface information pointed to by `ifinfop'.
 */
void
ipmp_freeifinfo(ipmp_ifinfo_t *ifinfop)
{
	free(ifinfop);
}

/*
 * Check if `buf' has a NUL byte in its first `bufsize' bytes.
 */
static boolean_t
hasnulbyte(const char *buf, size_t bufsize)
{
	while (bufsize-- > 0) {
		if (buf[bufsize] == '\0')
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Check that the TLV triplet named by `type', `len' and `value' is correctly
 * formed.
 */
static boolean_t
ipmp_checktlv(ipmp_infotype_t type, size_t len, void *value)
{
	ipmp_iflist_t		*iflistp;
	ipmp_ifinfo_t		*ifinfop;
	ipmp_grouplist_t	*grlistp;
	ipmp_groupinfo_t	*grinfop;
	unsigned int		i;

	switch (type) {
	case IPMP_IFLIST:
		iflistp = (ipmp_iflist_t *)value;
		if (len < IPMP_IFLIST_MINSIZE ||
		    len < IPMP_IFLIST_SIZE(iflistp->il_nif))
			return (B_FALSE);

		for (i = 0; i < iflistp->il_nif; i++)
			if (!hasnulbyte(iflistp->il_ifs[i], LIFNAMSIZ))
				return (B_FALSE);
		break;

	case IPMP_IFINFO:
		ifinfop = (ipmp_ifinfo_t *)value;
		if (len != sizeof (ipmp_ifinfo_t))
			return (B_FALSE);

		if (!hasnulbyte(ifinfop->if_name, LIFNAMSIZ) ||
		    !hasnulbyte(ifinfop->if_group, LIFGRNAMSIZ))
			return (B_FALSE);
		break;

	case IPMP_GROUPLIST:
		grlistp = (ipmp_grouplist_t *)value;
		if (len < IPMP_GROUPLIST_MINSIZE ||
		    len < IPMP_GROUPLIST_SIZE(grlistp->gl_ngroup))
			return (B_FALSE);

		for (i = 0; i < grlistp->gl_ngroup; i++)
			if (!hasnulbyte(grlistp->gl_groups[i], LIFGRNAMSIZ))
				return (B_FALSE);
		break;

	case IPMP_GROUPINFO:
		grinfop = (ipmp_groupinfo_t *)value;
		if (len != sizeof (ipmp_groupinfo_t))
			return (B_FALSE);

		if (!hasnulbyte(grinfop->gr_name, LIFGRNAMSIZ))
			return (B_FALSE);
		break;

	case IPMP_SNAP:
		if (len != sizeof (ipmp_snap_t))
			return (B_FALSE);
		break;

	default:
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Create a group list with signature `sig' containing `ngroup' groups named
 * by `groups'.  Returns a pointer to the new group list on success, or NULL
 * on failure.
 */
ipmp_grouplist_t *
ipmp_grouplist_create(uint64_t sig, unsigned int ngroup,
    char (*groups)[LIFGRNAMSIZ])
{
	unsigned int i;
	ipmp_grouplist_t *grlistp;

	grlistp = malloc(IPMP_GROUPLIST_SIZE(ngroup));
	if (grlistp == NULL)
		return (NULL);

	grlistp->gl_sig = sig;
	grlistp->gl_ngroup = ngroup;
	for (i = 0; i < ngroup; i++)
		(void) strlcpy(grlistp->gl_groups[i], groups[i], LIFGRNAMSIZ);

	return (grlistp);
}

/*
 * Clone the group list named by `grlistp'.  Returns a pointer to the clone on
 * success, or NULL on failure.
 */
ipmp_grouplist_t *
ipmp_grouplist_clone(ipmp_grouplist_t *grlistp)
{
	return (ipmp_grouplist_create(grlistp->gl_sig, grlistp->gl_ngroup,
	    grlistp->gl_groups));
}

/*
 * Create an interface information structure for interface `name' and
 * associate `group', `state' and `type' with it.  Returns a pointer to the
 * interface information on success, or NULL on failure.
 */
ipmp_ifinfo_t *
ipmp_ifinfo_create(const char *name, const char *group, ipmp_if_state_t state,
    ipmp_if_type_t type)
{
	ipmp_ifinfo_t *ifinfop;

	ifinfop = malloc(sizeof (ipmp_ifinfo_t));
	if (ifinfop == NULL)
		return (NULL);

	(void) strlcpy(ifinfop->if_name, name, LIFNAMSIZ);
	(void) strlcpy(ifinfop->if_group, group, LIFGRNAMSIZ);
	ifinfop->if_state = state;
	ifinfop->if_type = type;

	return (ifinfop);
}

/*
 * Clone the interface information named by `ifinfop'.  Returns a pointer to
 * the clone on success, or NULL on failure.
 */
ipmp_ifinfo_t *
ipmp_ifinfo_clone(ipmp_ifinfo_t *ifinfop)
{
	return (ipmp_ifinfo_create(ifinfop->if_name, ifinfop->if_group,
	    ifinfop->if_state, ifinfop->if_type));
}

/*
 * Create a group named `name' with signature `sig', in state `state', and
 * with the `nif' interfaces named by `ifs' as members.  Returns a pointer
 * to the new group on success, or NULL on failure.
 */
ipmp_groupinfo_t *
ipmp_groupinfo_create(const char *name, uint64_t sig, ipmp_group_state_t state,
    unsigned int nif, char (*ifs)[LIFNAMSIZ])
{
	ipmp_groupinfo_t *grinfop;
	ipmp_iflist_t	*iflistp;
	unsigned int	i;

	grinfop = malloc(sizeof (ipmp_groupinfo_t));
	if (grinfop == NULL)
		return (NULL);

	iflistp = malloc(IPMP_IFLIST_SIZE(nif));
	if (iflistp == NULL) {
		free(grinfop);
		return (NULL);
	}

	grinfop->gr_sig = sig;
	grinfop->gr_state = state;
	grinfop->gr_iflistp = iflistp;
	(void) strlcpy(grinfop->gr_name, name, LIFGRNAMSIZ);

	iflistp->il_nif = nif;
	for (i = 0; i < nif; i++)
		(void) strlcpy(iflistp->il_ifs[i], ifs[i], LIFNAMSIZ);

	return (grinfop);
}

/*
 * Clone the group information named by `grinfop'.  Returns a pointer to
 * the clone on success, or NULL on failure.
 */
ipmp_groupinfo_t *
ipmp_groupinfo_clone(ipmp_groupinfo_t *grinfop)
{
	return (ipmp_groupinfo_create(grinfop->gr_name, grinfop->gr_sig,
	    grinfop->gr_state, grinfop->gr_iflistp->il_nif,
	    grinfop->gr_iflistp->il_ifs));
}

/*
 * Set the query context associated with `handle' to `qcontext', which must be
 * either IPMP_QCONTEXT_LIVE or IPMP_QCONTEXT_SNAP.  Upon success, any
 * previous snapshot associated with `handle' is discarded.  Returns an IPMP
 * error code.
 */
int
ipmp_setqcontext(ipmp_handle_t handle, ipmp_qcontext_t qcontext)
{
	ipmp_state_t	*statep = handle;
	ipmp_snap_t	*snap;
	int		retval;

	switch (qcontext) {
	case IPMP_QCONTEXT_LIVE:
		snap = NULL;
		break;

	case IPMP_QCONTEXT_SNAP:
		retval = ipmp_snap_take(statep, &snap);
		if (retval != IPMP_SUCCESS)
			return (retval);
		break;

	default:
		return (IPMP_EINVAL);
	}

	if (statep->st_snap != NULL)
		ipmp_snap_free(statep->st_snap);
	statep->st_snap = snap;

	return (IPMP_SUCCESS);
}

/*
 * Create an empty snapshot.  Returns a pointer to the snapshot on success,
 * or NULL on failure.
 */
ipmp_snap_t *
ipmp_snap_create(void)
{
	ipmp_snap_t *snap;

	snap = malloc(sizeof (ipmp_snap_t));
	if (snap == NULL)
		return (NULL);

	snap->sn_grlistp = NULL;
	snap->sn_grinfolistp = NULL;
	snap->sn_ifinfolistp = NULL;
	snap->sn_ngroup = 0;
	snap->sn_nif = 0;

	return (snap);
}

/*
 * Free all of the resources associated with snapshot `snap'.
 */
void
ipmp_snap_free(ipmp_snap_t *snap)
{
	ipmp_ifinfolist_t	*iflp, *ifnext;
	ipmp_groupinfolist_t	*grlp, *grnext;

	ipmp_freegrouplist(snap->sn_grlistp);

	for (grlp = snap->sn_grinfolistp; grlp != NULL; grlp = grnext) {
		grnext = grlp->grl_next;
		ipmp_freegroupinfo(grlp->grl_grinfop);
		free(grlp);
	}

	for (iflp = snap->sn_ifinfolistp; iflp != NULL; iflp = ifnext) {
		ifnext = iflp->ifl_next;
		ipmp_freeifinfo(iflp->ifl_ifinfop);
		free(iflp);
	}

	free(snap);
}

/*
 * Add the group information in `grinfop' to the snapshot named by `snap'.
 * Returns an IPMP error code.
 */
int
ipmp_snap_addgroupinfo(ipmp_snap_t *snap, ipmp_groupinfo_t *grinfop)
{
	ipmp_groupinfolist_t *grlp;

	/*
	 * If the information for this group is already in the snapshot,
	 * in.mpathd is broken.
	 */
	if (ipmp_snap_getgroupinfo(snap, grinfop->gr_name) != NULL)
		return (IPMP_EPROTO);

	grlp = malloc(sizeof (ipmp_groupinfolist_t));
	if (grlp == NULL)
		return (IPMP_ENOMEM);

	grlp->grl_grinfop = grinfop;
	grlp->grl_next = snap->sn_grinfolistp;
	snap->sn_grinfolistp = grlp;
	snap->sn_ngroup++;

	return (IPMP_SUCCESS);
}

/*
 * Add the interface information in `ifinfop' to the snapshot named by `snap'.
 * Returns an IPMP error code.
 */
int
ipmp_snap_addifinfo(ipmp_snap_t *snap, ipmp_ifinfo_t *ifinfop)
{
	ipmp_ifinfolist_t *iflp;

	/*
	 * If the information for this interface is already in the snapshot,
	 * in.mpathd is broken.
	 */
	if (ipmp_snap_getifinfo(snap, ifinfop->if_name) != NULL)
		return (IPMP_EPROTO);

	iflp = malloc(sizeof (ipmp_ifinfolist_t));
	if (iflp == NULL)
		return (IPMP_ENOMEM);

	iflp->ifl_ifinfop = ifinfop;
	iflp->ifl_next = snap->sn_ifinfolistp;
	snap->sn_ifinfolistp = iflp;
	snap->sn_nif++;

	return (IPMP_SUCCESS);
}

/*
 * Retrieve the information for the group `name' in snapshot `snap'.
 * Returns a pointer to the group information on success, or NULL on failure.
 */
static ipmp_groupinfo_t *
ipmp_snap_getgroupinfo(ipmp_snap_t *snap, const char *name)
{
	ipmp_groupinfolist_t *grlp;

	for (grlp = snap->sn_grinfolistp; grlp != NULL; grlp = grlp->grl_next) {
		if (strcmp(grlp->grl_grinfop->gr_name, name) == 0)
			break;
	}

	return (grlp != NULL ? grlp->grl_grinfop : NULL);
}

/*
 * Retrieve the information for the interface `name' in snapshot `snap'.
 * Returns a pointer to the interface information on success, or NULL on
 * failure.
 */
static ipmp_ifinfo_t *
ipmp_snap_getifinfo(ipmp_snap_t *snap, const char *name)
{
	ipmp_ifinfolist_t *iflp;

	for (iflp = snap->sn_ifinfolistp; iflp != NULL; iflp = iflp->ifl_next) {
		if (strcmp(iflp->ifl_ifinfop->if_name, name) == 0)
			break;
	}

	return (iflp != NULL ? iflp->ifl_ifinfop : NULL);
}

/*
 * Using `statep', take a snapshot of the IPMP subsystem and if successful
 * return it in a dynamically allocated snapshot pointed to by `*snapp'.
 * Returns an IPMP error code.
 */
static int
ipmp_snap_take(ipmp_state_t *statep, ipmp_snap_t **snapp)
{
	ipmp_snap_t	*snap, *osnap;
	ipmp_infotype_t	type;
	ipmp_iflist_t	*iflistp;
	int		retval;
	size_t		len;
	void		*infop;
	struct timeval	end;

	snap = ipmp_snap_create();
	if (snap == NULL)
		return (IPMP_ENOMEM);

	retval = ipmp_sendquery(statep, IPMP_SNAP, NULL, &end);
	if (retval != IPMP_SUCCESS) {
		ipmp_snap_free(snap);
		return (retval);
	}

	retval = ipmp_readinfo(statep, IPMP_SNAP, (void **)&osnap, &end);
	if (retval != IPMP_SUCCESS) {
		ipmp_snap_free(snap);
		return (ipmp_querydone(statep, retval));
	}

	/*
	 * Using the information in the passed `osnap' snapshot, build up our
	 * own snapshot.  If we receive more than one grouplist, or more than
	 * the expected number of interfaces or groups, then bail out.  Note
	 * that there's only so much we can do to check that the information
	 * sent by in.mpathd makes sense.  We know there will always be at
	 * least one TLV (IPMP_GROUPLIST).
	 */
	do {
		infop = NULL;
		retval = ipmp_readtlv(statep->st_fd, &type, &len, &infop, &end);
		if (retval != IPMP_SUCCESS)
			goto fail;

		if (!ipmp_checktlv(type, len, infop)) {
			retval = IPMP_EPROTO;
			goto fail;
		}

		switch (type) {
		case IPMP_GROUPLIST:
			if (snap->sn_grlistp != NULL) {
				retval = IPMP_EPROTO;
				break;
			}
			snap->sn_grlistp = infop;
			break;

		case IPMP_IFINFO:
			if (snap->sn_nif == osnap->sn_nif) {
				retval = IPMP_EPROTO;
				break;
			}
			retval = ipmp_snap_addifinfo(snap, infop);
			break;

		case IPMP_GROUPINFO:
			if (snap->sn_ngroup == osnap->sn_ngroup) {
				retval = IPMP_EPROTO;
				break;
			}

			/*
			 * An IPMP_IFLIST TLV always follows the
			 * IPMP_GROUPINFO TLV; read it in.
			 */
			retval = ipmp_readinfo(statep, IPMP_IFLIST,
			    (void **)&iflistp, &end);
			if (retval != IPMP_SUCCESS)
				break;

			((ipmp_groupinfo_t *)infop)->gr_iflistp = iflistp;
			retval = ipmp_snap_addgroupinfo(snap, infop);
			if (retval != IPMP_SUCCESS)
				free(iflistp);
			break;

		default:
			retval = IPMP_EPROTO;
			break;
		}
fail:
		if (retval != IPMP_SUCCESS) {
			free(infop);
			free(osnap);
			ipmp_snap_free(snap);
			return (ipmp_querydone(statep, retval));
		}
	} while (snap->sn_grlistp == NULL || snap->sn_nif < osnap->sn_nif ||
	    snap->sn_ngroup < osnap->sn_ngroup);

	free(osnap);
	*snapp = snap;
	return (ipmp_querydone(statep, IPMP_SUCCESS));
}
