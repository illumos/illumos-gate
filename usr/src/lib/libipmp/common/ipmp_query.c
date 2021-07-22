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
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * IPMP query interfaces (see PSARC/2002/615 and PSARC/2007/272).
 */

#include <assert.h>
#include <errno.h>
#include <libinetutil.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include "ipmp_impl.h"
#include "ipmp_mpathd.h"
#include "ipmp_query_impl.h"

static ipmp_ifinfo_t	*ipmp_ifinfo_clone(ipmp_ifinfo_t *);
static ipmp_addrinfo_t	*ipmp_addrinfo_clone(ipmp_addrinfo_t *);
static ipmp_addrlist_t	*ipmp_addrlist_clone(ipmp_addrlist_t *);
static ipmp_grouplist_t	*ipmp_grouplist_clone(ipmp_grouplist_t *);
static ipmp_groupinfo_t	*ipmp_groupinfo_clone(ipmp_groupinfo_t *);
static ipmp_iflist_t	*ipmp_iflist_create(uint_t, char (*)[LIFNAMSIZ]);
static void		ipmp_freeiflist(ipmp_iflist_t *);
static ipmp_addrlist_t *ipmp_addrlist_create(uint_t, struct sockaddr_storage *);
static void		ipmp_freeaddrlist(ipmp_addrlist_t *);
static ipmp_groupinfo_t *ipmp_snap_getgroupinfo(ipmp_snap_t *, const char *);
static ipmp_ifinfo_t	*ipmp_snap_getifinfo(ipmp_snap_t *, const char *);
static ipmp_addrinfo_t  *ipmp_snap_getaddrinfo(ipmp_snap_t *, const char *,
			    struct sockaddr_storage *);
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
    const void *addr, struct timeval *endtp)
{
	mi_query_t	query;
	mi_result_t	result;
	int		retval;

	query.miq_command = MI_QUERY;
	query.miq_inforeq = type;

	switch (type) {
	case IPMP_ADDRINFO:
		(void) strlcpy(query.miq_grname, name, LIFGRNAMSIZ);
		query.miq_addr = *(struct sockaddr_storage *)addr;
		break;

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
 * Using `statep', read in the remaining IPMP group information TLVs from
 * in.mpathd into `grinfop' before the current time becomes `endtp'.  Returns
 * an IPMP error code.  On failure, `grinfop' will have its original contents.
 */
static int
ipmp_readgroupinfo_lists(ipmp_state_t *statep, ipmp_groupinfo_t *grinfop,
    const struct timeval *endtp)
{
	int retval;
	ipmp_iflist_t *iflistp;
	ipmp_addrlist_t *adlistp;

	retval = ipmp_readinfo(statep, IPMP_IFLIST, (void **)&iflistp, endtp);
	if (retval != IPMP_SUCCESS)
		return (retval);

	retval = ipmp_readinfo(statep, IPMP_ADDRLIST, (void **)&adlistp, endtp);
	if (retval != IPMP_SUCCESS) {
		ipmp_freeiflist(iflistp);
		return (retval);
	}

	grinfop->gr_iflistp = iflistp;
	grinfop->gr_adlistp = adlistp;
	return (IPMP_SUCCESS);
}

/*
 * Using `statep', read in the remaining IPMP interface information TLVs from
 * in.mpathd into `ifinfop' before the current time becomes `endtp'.  Returns
 * an IPMP error code.  On failure, `ifinfop' will have its original contents.
 */
static int
ipmp_readifinfo_lists(ipmp_state_t *statep, ipmp_ifinfo_t *ifinfop,
    const struct timeval *endtp)
{
	int retval;
	ipmp_addrlist_t *tlist4p, *tlist6p;

	retval = ipmp_readinfo(statep, IPMP_ADDRLIST, (void **)&tlist4p, endtp);
	if (retval != IPMP_SUCCESS)
		return (retval);

	retval = ipmp_readinfo(statep, IPMP_ADDRLIST, (void **)&tlist6p, endtp);
	if (retval != IPMP_SUCCESS) {
		ipmp_freeaddrlist(tlist4p);
		return (retval);
	}

	ifinfop->if_targinfo4.it_targlistp = tlist4p;
	ifinfop->if_targinfo6.it_targlistp = tlist6p;
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

	retval = ipmp_sendquery(statep, IPMP_GROUPLIST, NULL, NULL, &end);
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
 * Convert a ipmp_groupinfo_xfer_t used for communication with in.mpathd
 * into a newly allocated ipmp_groupinfo_t. Free the ipmp_groupinfo_xfer_t,
 * regardless of failure.
 */
static ipmp_groupinfo_t *
ipmp_convertgroupinfo(ipmp_groupinfo_xfer_t *grxferp)
{
	ipmp_groupinfo_t *grinfop;

	grinfop = calloc(1, sizeof (ipmp_groupinfo_t));
	if (grinfop != NULL) {
		memcpy(grinfop->gr_name, grxferp->grx_name,
		    sizeof (grinfop->gr_name));
		grinfop->gr_sig = grxferp->grx_sig;
		grinfop->gr_state = grxferp->grx_state;
		memcpy(grinfop->gr_ifname, grxferp->grx_ifname,
		    sizeof (grinfop->gr_ifname));
		memcpy(grinfop->gr_m4ifname, grxferp->grx_m4ifname,
		    sizeof (grinfop->gr_m4ifname));
		memcpy(grinfop->gr_m6ifname, grxferp->grx_m6ifname,
		    sizeof (grinfop->gr_m6ifname));
		memcpy(grinfop->gr_bcifname, grxferp->grx_bcifname,
		    sizeof (grinfop->gr_bcifname));
		grinfop->gr_fdt = grxferp->grx_fdt;
	}

	free(grxferp);

	return (grinfop);
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
	int		retval;
	struct timeval	end;
	ipmp_groupinfo_t *grinfop;
	ipmp_groupinfo_xfer_t *grxferp;

	if (statep->st_snap != NULL) {
		grinfop = ipmp_snap_getgroupinfo(statep->st_snap, name);
		if (grinfop == NULL)
			return (IPMP_EUNKGROUP);

		*grinfopp = ipmp_groupinfo_clone(grinfop);
		return (*grinfopp != NULL ? IPMP_SUCCESS : IPMP_ENOMEM);
	}

	retval = ipmp_sendquery(statep, IPMP_GROUPINFO, name, NULL, &end);
	if (retval != IPMP_SUCCESS)
		return (retval);

	retval = ipmp_readinfo(statep, IPMP_GROUPINFO, (void **)&grxferp, &end);
	if (retval != IPMP_SUCCESS)
		return (ipmp_querydone(statep, retval));

	*grinfopp = ipmp_convertgroupinfo(grxferp);
	if (*grinfopp == NULL)
		return (ipmp_querydone(statep, IPMP_ENOMEM));

	retval = ipmp_readgroupinfo_lists(statep, *grinfopp, &end);
	if (retval != IPMP_SUCCESS)
		free(*grinfopp);

	return (ipmp_querydone(statep, retval));
}

/*
 * Free the group information pointed to by `grinfop'.
 */
void
ipmp_freegroupinfo(ipmp_groupinfo_t *grinfop)
{
	ipmp_freeaddrlist(grinfop->gr_adlistp);
	ipmp_freeiflist(grinfop->gr_iflistp);
	free(grinfop);
}

/*
 * Convert a ipmp_ifinfo_xfer_t used for communication with in.mpathd
 * into a newly allocated ipmp_ifinfo_t. Free the ipmp_ifinfo_xfer_t,
 * regardless of failure.
 */
static ipmp_ifinfo_t *
ipmp_convertifinfo(ipmp_ifinfo_xfer_t *ifxferp)
{
	ipmp_ifinfo_t *ifinfop;

	ifinfop = calloc(1, sizeof (ipmp_ifinfo_t));
	if (ifinfop != NULL) {
		memcpy(ifinfop->if_name, ifxferp->ifx_name,
		    sizeof (ifinfop->if_name));
		memcpy(ifinfop->if_group, ifxferp->ifx_group,
		    sizeof (ifinfop->if_group));
		ifinfop->if_state = ifxferp->ifx_state;
		ifinfop->if_type = ifxferp->ifx_type;
		ifinfop->if_linkstate = ifxferp->ifx_linkstate;
		ifinfop->if_probestate = ifxferp->ifx_probestate;
		ifinfop->if_flags = ifxferp->ifx_flags;
		memcpy(ifinfop->if_targinfo4.it_name,
		    ifxferp->ifx_targinfo4.itx_name,
		    sizeof (ifinfop->if_targinfo4.it_name));
		ifinfop->if_targinfo4.it_testaddr =
		    ifxferp->ifx_targinfo4.itx_testaddr;
		ifinfop->if_targinfo4.it_targmode =
		    ifxferp->ifx_targinfo4.itx_targmode;
		memcpy(ifinfop->if_targinfo6.it_name,
		    ifxferp->ifx_targinfo6.itx_name,
		    sizeof (ifinfop->if_targinfo6.it_name));
		ifinfop->if_targinfo6.it_testaddr =
		    ifxferp->ifx_targinfo6.itx_testaddr;
		ifinfop->if_targinfo6.it_targmode =
		    ifxferp->ifx_targinfo6.itx_targmode;
	}

	free(ifxferp);

	return (ifinfop);
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
	ipmp_ifinfo_xfer_t *ifxferp;
	int		retval;
	struct timeval	end;

	if (statep->st_snap != NULL) {
		ifinfop = ipmp_snap_getifinfo(statep->st_snap, name);
		if (ifinfop == NULL)
			return (IPMP_EUNKIF);

		*ifinfopp = ipmp_ifinfo_clone(ifinfop);
		return (*ifinfopp != NULL ? IPMP_SUCCESS : IPMP_ENOMEM);
	}

	retval = ipmp_sendquery(statep, IPMP_IFINFO, name, NULL, &end);
	if (retval != IPMP_SUCCESS)
		return (retval);

	retval = ipmp_readinfo(statep, IPMP_IFINFO, (void **)&ifxferp, &end);
	if (retval != IPMP_SUCCESS)
		return (ipmp_querydone(statep, retval));

	*ifinfopp = ipmp_convertifinfo(ifxferp);
	if (*ifinfopp == NULL)
		return (ipmp_querydone(statep, IPMP_ENOMEM));

	retval = ipmp_readifinfo_lists(statep, *ifinfopp, &end);
	if (retval != IPMP_SUCCESS)
		free(*ifinfopp);

	return (ipmp_querydone(statep, retval));
}

/*
 * Free the interface information pointed to by `ifinfop'.
 */
void
ipmp_freeifinfo(ipmp_ifinfo_t *ifinfop)
{
	ipmp_freeaddrlist(ifinfop->if_targinfo4.it_targlistp);
	ipmp_freeaddrlist(ifinfop->if_targinfo6.it_targlistp);
	free(ifinfop);
}

/*
 * Using `handle', get the address information associated with address `addrp'
 * on group `grname' and store the results in a dynamically allocated buffer
 * pointed to by `*adinfopp'.  Returns an IPMP error code.
 */
int
ipmp_getaddrinfo(ipmp_handle_t handle, const char *grname,
    struct sockaddr_storage *addrp, ipmp_addrinfo_t **adinfopp)
{
	ipmp_state_t	*statep = handle;
	ipmp_addrinfo_t	*adinfop;
	int		retval;
	struct timeval	end;

	if (statep->st_snap != NULL) {
		adinfop = ipmp_snap_getaddrinfo(statep->st_snap, grname, addrp);
		if (adinfop == NULL)
			return (IPMP_EUNKADDR);

		*adinfopp = ipmp_addrinfo_clone(adinfop);
		return (*adinfopp != NULL ? IPMP_SUCCESS : IPMP_ENOMEM);
	}

	retval = ipmp_sendquery(statep, IPMP_ADDRINFO, grname, addrp, &end);
	if (retval != IPMP_SUCCESS)
		return (retval);

	retval = ipmp_readinfo(statep, IPMP_ADDRINFO, (void **)adinfopp, &end);
	return (ipmp_querydone(statep, retval));
}

/*
 * Free the address information pointed to by `adinfop'.
 */
void
ipmp_freeaddrinfo(ipmp_addrinfo_t *adinfop)
{
	free(adinfop);
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
	ipmp_ifinfo_xfer_t	*ifxferp;
	ipmp_grouplist_t	*grlistp;
	ipmp_groupinfo_xfer_t	*grxferp;
	ipmp_addrlist_t		*adlistp;
	unsigned int		i;

	switch (type) {
	case IPMP_ADDRINFO:
		if (len != sizeof (ipmp_addrinfo_t))
			return (B_FALSE);
		break;

	case IPMP_ADDRLIST:
		adlistp = (ipmp_addrlist_t *)value;
		if (len < IPMP_ADDRLIST_SIZE(0) ||
		    len < IPMP_ADDRLIST_SIZE(adlistp->al_naddr))
			return (B_FALSE);
		break;

	case IPMP_IFLIST:
		iflistp = (ipmp_iflist_t *)value;
		if (len < IPMP_IFLIST_SIZE(0) ||
		    len < IPMP_IFLIST_SIZE(iflistp->il_nif))
			return (B_FALSE);

		for (i = 0; i < iflistp->il_nif; i++)
			if (!hasnulbyte(iflistp->il_ifs[i], LIFNAMSIZ))
				return (B_FALSE);
		break;

	case IPMP_IFINFO:
		ifxferp = (ipmp_ifinfo_xfer_t *)value;
		if (len != sizeof (ipmp_ifinfo_xfer_t))
			return (B_FALSE);

		if (!hasnulbyte(ifxferp->ifx_name, LIFNAMSIZ) ||
		    !hasnulbyte(ifxferp->ifx_group, LIFGRNAMSIZ))
			return (B_FALSE);
		break;

	case IPMP_GROUPLIST:
		grlistp = (ipmp_grouplist_t *)value;
		if (len < IPMP_GROUPLIST_SIZE(0) ||
		    len < IPMP_GROUPLIST_SIZE(grlistp->gl_ngroup))
			return (B_FALSE);

		for (i = 0; i < grlistp->gl_ngroup; i++)
			if (!hasnulbyte(grlistp->gl_groups[i], LIFGRNAMSIZ))
				return (B_FALSE);
		break;

	case IPMP_GROUPINFO:
		grxferp = (ipmp_groupinfo_xfer_t *)value;
		if (len != sizeof (ipmp_groupinfo_xfer_t))
			return (B_FALSE);

		if (!hasnulbyte(grxferp->grx_name, LIFGRNAMSIZ))
			return (B_FALSE);
		break;

	case IPMP_ADDRCNT:
	case IPMP_GROUPCNT:
	case IPMP_IFCNT:
		if (len != sizeof (uint32_t))
			return (B_FALSE);
		break;

	default:
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Create a group list; arguments match ipmp_grouplist_t fields.  Returns a
 * pointer to the new group list on success, or NULL on failure.
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
 * Create target information; arguments match ipmp_targinfo_t fields.  Returns
 * a pointer to the new target info on success, or NULL on failure.
 */
ipmp_targinfo_t *
ipmp_targinfo_create(const char *name, struct sockaddr_storage *testaddrp,
    ipmp_if_targmode_t targmode, uint_t ntarg, struct sockaddr_storage *targs)
{
	ipmp_targinfo_t *targinfop;

	targinfop = malloc(sizeof (ipmp_targinfo_t));
	if (targinfop == NULL)
		return (NULL);

	targinfop->it_testaddr = *testaddrp;
	targinfop->it_targmode = targmode;
	targinfop->it_targlistp = ipmp_addrlist_create(ntarg, targs);
	if (targinfop->it_targlistp == NULL) {
		ipmp_freetarginfo(targinfop);
		return (NULL);
	}
	(void) strlcpy(targinfop->it_name, name, LIFNAMSIZ);

	return (targinfop);
}

/*
 * Free the target information pointed to by `targinfop'.
 */
void
ipmp_freetarginfo(ipmp_targinfo_t *targinfop)
{
	free(targinfop->it_targlistp);
	free(targinfop);
}

/*
 * Create an interface list; arguments match ipmp_iflist_t fields.  Returns a
 * pointer to the new interface list on success, or NULL on failure.
 */
static ipmp_iflist_t *
ipmp_iflist_create(uint_t nif, char (*ifs)[LIFNAMSIZ])
{
	unsigned int i;
	ipmp_iflist_t *iflistp;

	iflistp = malloc(IPMP_IFLIST_SIZE(nif));
	if (iflistp == NULL)
		return (NULL);

	iflistp->il_nif = nif;
	for (i = 0; i < nif; i++)
		(void) strlcpy(iflistp->il_ifs[i], ifs[i], LIFNAMSIZ);

	return (iflistp);
}

/*
 * Free the interface list pointed to by `iflistp'.
 */
static void
ipmp_freeiflist(ipmp_iflist_t *iflistp)
{
	free(iflistp);
}

/*
 * Create an interface; arguments match ipmp_ifinfo_t fields.  Returns a
 * pointer to the new interface on success, or NULL on failure.
 */
ipmp_ifinfo_t *
ipmp_ifinfo_create(const char *name, const char *group, ipmp_if_state_t state,
    ipmp_if_type_t type, ipmp_if_linkstate_t linkstate,
    ipmp_if_probestate_t probestate, ipmp_if_flags_t flags,
    ipmp_targinfo_t *targinfo4p, ipmp_targinfo_t *targinfo6p)
{
	ipmp_ifinfo_t *ifinfop;

	ifinfop = malloc(sizeof (ipmp_ifinfo_t));
	if (ifinfop == NULL)
		return (NULL);

	(void) strlcpy(ifinfop->if_name, name, LIFNAMSIZ);
	(void) strlcpy(ifinfop->if_group, group, LIFGRNAMSIZ);

	ifinfop->if_state	= state;
	ifinfop->if_type	= type;
	ifinfop->if_linkstate	= linkstate;
	ifinfop->if_probestate	= probestate;
	ifinfop->if_flags	= flags;
	ifinfop->if_targinfo4	= *targinfo4p;
	ifinfop->if_targinfo6	= *targinfo6p;

	ifinfop->if_targinfo4.it_targlistp =
	    ipmp_addrlist_clone(targinfo4p->it_targlistp);
	ifinfop->if_targinfo6.it_targlistp =
	    ipmp_addrlist_clone(targinfo6p->it_targlistp);

	if (ifinfop->if_targinfo4.it_targlistp == NULL ||
	    ifinfop->if_targinfo6.it_targlistp == NULL) {
		ipmp_freeifinfo(ifinfop);
		return (NULL);
	}

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
	    ifinfop->if_state, ifinfop->if_type, ifinfop->if_linkstate,
	    ifinfop->if_probestate, ifinfop->if_flags, &ifinfop->if_targinfo4,
	    &ifinfop->if_targinfo6));
}

/*
 * Create a group; arguments match ipmp_groupinfo_t fields.  Returns a pointer
 * to the new group on success, or NULL on failure.
 */
ipmp_groupinfo_t *
ipmp_groupinfo_create(const char *name, uint64_t sig, uint_t fdt,
    ipmp_group_state_t state, uint_t nif, char (*ifs)[LIFNAMSIZ],
    const char *grifname, const char *m4ifname, const char *m6ifname,
    const char *bcifname, uint_t naddr, struct sockaddr_storage *addrs)
{
	ipmp_groupinfo_t *grinfop;

	grinfop = malloc(sizeof (ipmp_groupinfo_t));
	if (grinfop == NULL)
		return (NULL);

	grinfop->gr_sig	= sig;
	grinfop->gr_fdt = fdt;
	grinfop->gr_state = state;
	grinfop->gr_iflistp = ipmp_iflist_create(nif, ifs);
	grinfop->gr_adlistp = ipmp_addrlist_create(naddr, addrs);
	if (grinfop->gr_iflistp == NULL || grinfop->gr_adlistp == NULL) {
		ipmp_freegroupinfo(grinfop);
		return (NULL);
	}
	(void) strlcpy(grinfop->gr_name, name, LIFGRNAMSIZ);
	(void) strlcpy(grinfop->gr_ifname, grifname, LIFNAMSIZ);
	(void) strlcpy(grinfop->gr_m4ifname, m4ifname, LIFNAMSIZ);
	(void) strlcpy(grinfop->gr_m6ifname, m6ifname, LIFNAMSIZ);
	(void) strlcpy(grinfop->gr_bcifname, bcifname, LIFNAMSIZ);

	return (grinfop);
}

/*
 * Clone the group information named by `grinfop'.  Returns a pointer to
 * the clone on success, or NULL on failure.
 */
ipmp_groupinfo_t *
ipmp_groupinfo_clone(ipmp_groupinfo_t *grinfop)
{
	ipmp_addrlist_t *adlistp = grinfop->gr_adlistp;

	return (ipmp_groupinfo_create(grinfop->gr_name, grinfop->gr_sig,
	    grinfop->gr_fdt, grinfop->gr_state, grinfop->gr_iflistp->il_nif,
	    grinfop->gr_iflistp->il_ifs, grinfop->gr_ifname,
	    grinfop->gr_m4ifname, grinfop->gr_m6ifname, grinfop->gr_bcifname,
	    adlistp->al_naddr, adlistp->al_addrs));
}

/*
 * Create an address list; arguments match ipmp_addrlist_t fields.  Returns
 * a pointer to the new address list on success, or NULL on failure.
 */
static ipmp_addrlist_t *
ipmp_addrlist_create(uint_t naddr, struct sockaddr_storage *addrs)
{
	unsigned int i;
	ipmp_addrlist_t *adlistp;

	adlistp = malloc(IPMP_ADDRLIST_SIZE(naddr));
	if (adlistp == NULL)
		return (NULL);

	adlistp->al_naddr = naddr;
	for (i = 0; i < naddr; i++)
		adlistp->al_addrs[i] = addrs[i];

	return (adlistp);
}

/*
 * Clone the address list named by `adlistp'.  Returns a pointer to the clone
 * on success, or NULL on failure.
 */
static ipmp_addrlist_t *
ipmp_addrlist_clone(ipmp_addrlist_t *adlistp)
{
	return (ipmp_addrlist_create(adlistp->al_naddr, adlistp->al_addrs));
}

/*
 * Free the address list pointed to by `adlistp'.
 */
static void
ipmp_freeaddrlist(ipmp_addrlist_t *adlistp)
{
	free(adlistp);
}

/*
 * Create an address; arguments match ipmp_addrinfo_t fields.  Returns a
 * pointer to the new address on success, or NULL on failure.
 */
ipmp_addrinfo_t *
ipmp_addrinfo_create(struct sockaddr_storage *addrp, ipmp_addr_state_t state,
    const char *group, const char *binding)
{
	ipmp_addrinfo_t *adinfop;

	adinfop = malloc(sizeof (ipmp_addrinfo_t));
	if (adinfop == NULL)
		return (NULL);

	adinfop->ad_addr = *addrp;
	adinfop->ad_state = state;
	(void) strlcpy(adinfop->ad_group, group, LIFGRNAMSIZ);
	(void) strlcpy(adinfop->ad_binding, binding, LIFNAMSIZ);

	return (adinfop);
}

/*
 * Clone the address information named by `adinfop'.  Returns a pointer to
 * the clone on success, or NULL on failure.
 */
ipmp_addrinfo_t *
ipmp_addrinfo_clone(ipmp_addrinfo_t *adinfop)
{
	return (ipmp_addrinfo_create(&adinfop->ad_addr, adinfop->ad_state,
	    adinfop->ad_group, adinfop->ad_binding));
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
	snap->sn_adinfolistp = NULL;
	snap->sn_ngroup = 0;
	snap->sn_nif = 0;
	snap->sn_naddr = 0;

	return (snap);
}

/*
 * Free all of the resources associated with snapshot `snap'.
 */
void
ipmp_snap_free(ipmp_snap_t *snap)
{
	ipmp_ifinfolist_t	*iflp, *ifnext;
	ipmp_addrinfolist_t	*adlp, *adnext;
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

	for (adlp = snap->sn_adinfolistp; adlp != NULL; adlp = adnext) {
		adnext = adlp->adl_next;
		ipmp_freeaddrinfo(adlp->adl_adinfop);
		free(adlp);
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
 * Add the address information in `adinfop' to the snapshot named by `snap'.
 * Returns an IPMP error code.
 */
int
ipmp_snap_addaddrinfo(ipmp_snap_t *snap, ipmp_addrinfo_t *adinfop)
{
	ipmp_addrinfolist_t *adlp;

	/*
	 * Any duplicate addresses should've already been weeded by in.mpathd.
	 */
	if (ipmp_snap_getaddrinfo(snap, adinfop->ad_group,
	    &adinfop->ad_addr) != NULL)
		return (IPMP_EPROTO);

	adlp = malloc(sizeof (ipmp_addrinfolist_t));
	if (adlp == NULL)
		return (IPMP_ENOMEM);

	adlp->adl_adinfop = adinfop;
	adlp->adl_next = snap->sn_adinfolistp;
	snap->sn_adinfolistp = adlp;
	snap->sn_naddr++;

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
 * Retrieve the information for the address `addrp' on group `grname' in
 * snapshot `snap'.  Returns a pointer to the address information on success,
 * or NULL on failure.
 */
static ipmp_addrinfo_t *
ipmp_snap_getaddrinfo(ipmp_snap_t *snap, const char *grname,
    struct sockaddr_storage *addrp)
{
	ipmp_addrinfolist_t *adlp;

	for (adlp = snap->sn_adinfolistp; adlp != NULL; adlp = adlp->adl_next) {
		if (strcmp(grname, adlp->adl_adinfop->ad_group) == 0 &&
		    sockaddrcmp(addrp, &adlp->adl_adinfop->ad_addr))
			break;
	}

	return (adlp != NULL ? adlp->adl_adinfop : NULL);
}

/*
 * Using `statep', take a snapshot of the IPMP subsystem and if successful
 * return it in a dynamically allocated snapshot pointed to by `*snapp'.
 * Returns an IPMP error code.
 */
static int
ipmp_snap_take(ipmp_state_t *statep, ipmp_snap_t **snapp)
{
	uint64_t	naddr, ngroup, nif;
	ipmp_snap_t	*snap;
	ipmp_infotype_t	type;
	int		retval;
	size_t		len;
	void		*infop;
	struct timeval	end;

	naddr = ngroup = nif = UINT64_MAX;

	snap = ipmp_snap_create();
	if (snap == NULL)
		return (IPMP_ENOMEM);

	retval = ipmp_sendquery(statep, IPMP_SNAP, NULL, NULL, &end);
	if (retval != IPMP_SUCCESS) {
		ipmp_snap_free(snap);
		return (retval);
	}

	/*
	 * Build up our snapshot.  We know there will always be at least four
	 * TLVs for IPMP_GROUPLIST, IPMP_IFCNT, IPMP_GROUPCNT, and IPMP_ADDRCNT.
	 * If we receive anything illogical (e.g., more than the expected number
	 * of interfaces), then bail out.  However, to a large extent we have to
	 * trust the information sent by in.mpathd.
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
			if (snap->sn_nif == nif) {
				retval = IPMP_EPROTO;
				break;
			}

			infop = ipmp_convertifinfo(infop);
			if (infop == NULL) {
				retval = IPMP_ENOMEM;
				break;
			}

			/*
			 * Read in V4 and V6 targlist TLVs that follow.
			 */
			retval = ipmp_readifinfo_lists(statep, infop, &end);
			if (retval != IPMP_SUCCESS)
				break;

			retval = ipmp_snap_addifinfo(snap, infop);
			if (retval != IPMP_SUCCESS) {
				ipmp_freeifinfo(infop);
				infop = NULL;
			}
			break;

		case IPMP_ADDRINFO:
			if (snap->sn_naddr == naddr) {
				retval = IPMP_EPROTO;
				break;
			}

			retval = ipmp_snap_addaddrinfo(snap, infop);
			/*
			 * NOTE: since we didn't call ipmp_read*info_lists(),
			 * no need to use ipmp_freeaddrinfo() on failure.
			 */
			break;

		case IPMP_GROUPINFO:
			if (snap->sn_ngroup == ngroup) {
				retval = IPMP_EPROTO;
				break;
			}

			infop = ipmp_convertgroupinfo(infop);
			if (infop == NULL) {
				retval = IPMP_ENOMEM;
				break;
			}

			/*
			 * Read in IPMP groupinfo list TLVs that follow.
			 */
			retval = ipmp_readgroupinfo_lists(statep, infop, &end);
			if (retval != IPMP_SUCCESS)
				break;

			retval = ipmp_snap_addgroupinfo(snap, infop);
			if (retval != IPMP_SUCCESS) {
				ipmp_freegroupinfo(infop);
				infop = NULL;
			}
			break;

		case IPMP_ADDRCNT:
			if (naddr != UINT64_MAX) {
				retval = IPMP_EPROTO;
				break;
			}

			naddr = *(uint32_t *)infop;
			break;

		case IPMP_GROUPCNT:
			if (ngroup != UINT64_MAX) {
				retval = IPMP_EPROTO;
				break;
			}

			ngroup = *(uint32_t *)infop;
			break;

		case IPMP_IFCNT:
			if (nif != UINT64_MAX) {
				retval = IPMP_EPROTO;
				break;
			}

			nif = *(uint32_t *)infop;
			break;

		default:
			retval = IPMP_EPROTO;
			break;
		}
fail:
		if (retval != IPMP_SUCCESS) {
			free(infop);
			ipmp_snap_free(snap);
			return (ipmp_querydone(statep, retval));
		}
	} while (snap->sn_grlistp == NULL || snap->sn_nif < nif ||
	    snap->sn_ngroup < ngroup || snap->sn_naddr < naddr);

	*snapp = snap;
	return (ipmp_querydone(statep, IPMP_SUCCESS));
}
