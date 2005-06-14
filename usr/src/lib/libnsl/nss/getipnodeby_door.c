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
 * Copyright 1998-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <pwd.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/door.h>
#include <errno.h>
#include <fcntl.h>
#include <synch.h>
#include <getxby_door.h>
#include <nss_dbdefs.h>
#include "nss.h"

#ifdef PIC

static struct hostent *__process_getipnode(struct hostent *, char *, int, int *,
    nsc_data_t *);

struct hostent *
_door_getipnodebyname_r(const char *name, struct hostent *result, char *buffer,
	int buflen, int af_family, int flags, int *h_errnop)
{

	/*
	 * allocate space on the stack for the nscd to return
	 * host and host alias information
	 */
	union {
		nsc_data_t 	s_d;
		char		s_b[8192];
	} space;
	nsc_data_t	*sptr;
	int		ndata;
	int		adata;
	struct	hostent *resptr = NULL;

	if ((name == (const char *)NULL) ||
	    (strlen(name) >= (sizeof (space) - sizeof (nsc_data_t)
					- 2 * sizeof (int)))) {
		errno = ERANGE;
		if (h_errnop)
			*h_errnop = HOST_NOT_FOUND;
		return (NULL);
	}

	adata = (sizeof (nsc_call_t) + strlen(name) + 1 + 2 * sizeof (int));
	ndata = sizeof (space);
	space.s_d.nsc_call.nsc_callnumber = GETIPNODEBYNAME;
	space.s_d.nsc_call.nsc_u.ipnode.af_family = af_family;
	space.s_d.nsc_call.nsc_u.ipnode.flags = flags;
	strcpy(space.s_d.nsc_call.nsc_u.ipnode.name, name);
	sptr = &space.s_d;

	switch (_nsc_trydoorcall(&sptr, &ndata, &adata)) {
	    case SUCCESS:	/* positive cache hit */
		break;
	    case NOTFOUND:	/* negative cache hit */
		if (h_errnop)
		    *h_errnop = space.s_d.nsc_ret.nsc_errno;
		return (NULL);
	    default:
		return ((struct hostent *)_switch_getipnodebyname_r(name,
		    result, buffer, buflen, af_family, flags, h_errnop));
	}
	resptr = __process_getipnode(result, buffer, buflen, h_errnop, sptr);

	/*
	 * check if doors realloced buffer underneath of us....
	 * munmap or suffer a memory leak
	 */

	if (sptr != &space.s_d) {
		munmap((char *)sptr, ndata); /* return memory */
	}

	return (resptr);
}

struct hostent *
_door_getipnodebyaddr_r(const char *addr, int length, int type,
	struct hostent *result, char *buffer, int buflen, int *h_errnop)
{
	/*
	 * allocate space on the stack for the nscd to return
	 * host and host alias information
	 */
	union {
		nsc_data_t 	s_d;
		char		s_b[8192];
	} space;
	nsc_data_t 	*sptr;
	int		ndata;
	int		adata;
	struct	hostent *resptr = NULL;

	if (addr == (const char *)NULL) {
		if (h_errnop)
			*h_errnop = HOST_NOT_FOUND;
		return (NULL);
	}

	ndata = sizeof (space);
	adata = length + sizeof (nsc_call_t) + 1;
	sptr = &space.s_d;

	space.s_d.nsc_call.nsc_callnumber = GETIPNODEBYADDR;
	space.s_d.nsc_call.nsc_u.addr.a_type = type;
	space.s_d.nsc_call.nsc_u.addr.a_length = length;
	memcpy(space.s_d.nsc_call.nsc_u.addr.a_data, addr, length);

	switch (_nsc_trydoorcall(&sptr, &ndata, &adata)) {
	    case SUCCESS:	/* positive cache hit */
		break;
	    case NOTFOUND:	/* negative cache hit */
		if (h_errnop)
		    *h_errnop = space.s_d.nsc_ret.nsc_errno;
		return (NULL);
	    default:
		return ((struct hostent *)_switch_getipnodebyaddr_r(addr,
		    length, type, result, buffer, buflen, h_errnop));
	}

	resptr = __process_getipnode(result, buffer, buflen, h_errnop, sptr);

	/*
	 * check if doors realloced buffer underneath of us....
	 * munmap it or suffer a memory leak
	 */

	if (sptr != &space.s_d) {
		munmap((char *)sptr, ndata); /* return memory */
	}

	return (resptr);
}

#if !defined(_LP64)

static struct hostent *
__process_getipnode(struct hostent *result, char *buffer, int buflen,
	int *h_errnop, nsc_data_t *sptr)
{
	int i;

	char *fixed;

	fixed = (char *)ROUND_UP((int)buffer, sizeof (char *));
	buflen -= fixed - buffer;
	buffer = fixed;

	if (buflen + sizeof (struct hostent)
	    < sptr->nsc_ret.nsc_bufferbytesused) {
		/*
		 * no enough space allocated by user
		 */
		errno = ERANGE;
		if (h_errnop)
			*h_errnop = HOST_NOT_FOUND;
		return (NULL);
	}

	memcpy(buffer, sptr->nsc_ret.nsc_u.buff + sizeof (struct hostent),
	    sptr->nsc_ret.nsc_bufferbytesused - sizeof (struct hostent));

	sptr->nsc_ret.nsc_u.hst.h_name += (int)buffer;
	sptr->nsc_ret.nsc_u.hst.h_aliases =
	    (char **)((char *)sptr->nsc_ret.nsc_u.hst.h_aliases + (int)buffer);
	sptr->nsc_ret.nsc_u.hst.h_addr_list =
	    (char **)((char *)sptr->nsc_ret.nsc_u.hst.h_addr_list +
	    (int)buffer);
	for (i = 0; sptr->nsc_ret.nsc_u.hst.h_aliases[i]; i++) {
		sptr->nsc_ret.nsc_u.hst.h_aliases[i] += (int)buffer;
	}
	for (i = 0; sptr->nsc_ret.nsc_u.hst.h_addr_list[i]; i++) {
		sptr->nsc_ret.nsc_u.hst.h_addr_list[i] += (int)buffer;
	}

	*result = sptr->nsc_ret.nsc_u.hst;

	return (result);
}

#else /* _LP64 */

static struct hostent *
__process_getipnode(struct hostent *result, char *buffer, int buflen,
	int *h_errnop, nsc_data_t *sptr)
{
	char *fixed;
	char *dest;
	char *start;
	char **aliaseslist;
	char **addrlist;
	int *alias;
	int *address;
	size_t strs;
	int numaliases;
	int numaddrs;
	int i;

	fixed = (char *)ROUND_UP(buffer, sizeof (char *));
	buflen -= fixed - buffer;
	buffer = fixed;
	if (buflen < 0) {
		/* no enough space allocated by user */
		errno = ERANGE;
		if (h_errnop)
			*h_errnop = HOST_NOT_FOUND;
		return (NULL);
	}

	/*
	 * find out whether the user has provided sufficient space
	 */
	start = sptr->nsc_ret.nsc_u.buff + sizeof (struct hostent32);
	/*
	 * Length of hostname + null
	 */
	strs = 1 + strlen(sptr->nsc_ret.nsc_u.hst.h_name + start);
	/*
	 * length of all aliases + null
	 */
	alias = (int *)(start + sptr->nsc_ret.nsc_u.hst.h_aliases);
	for (numaliases = 0; alias[numaliases]; numaliases++)
	    strs += 1 + strlen(start + alias[numaliases]);
	/*
	 * Realign on word boundary
	 */
	strs = ROUND_UP(strs, sizeof (char *));
	/*
	 * Count the array of pointers to all aliases + null pointer
	 */
	strs += sizeof (char *) * (numaliases + 1);
	/*
	 * length of all addresses + null. Also, account for word alignment.
	 */
	address = (int *)(start + sptr->nsc_ret.nsc_u.hst.h_addr_list);
	for (numaddrs = 0; address[numaddrs]; numaddrs++) {
		strs += sptr->nsc_ret.nsc_u.hst.h_length;
		strs = ROUND_UP(strs, sizeof (char *));
	}
	/*
	 * Count the array of pointers to all addresses + null pointer
	 */
	strs += sizeof (char *) * (numaddrs + 1);

	if (buflen < strs) {

		/* no enough space allocated by user */

		errno = ERANGE;
		if (h_errnop)
			*h_errnop = HOST_NOT_FOUND;
		return (NULL);
	}

	/*
	 * allocat the h_aliases list and the h_addr_list first to align 'em.
	 */
	dest = buffer;
	aliaseslist = (char **)dest;
	dest += sizeof (char *) * (numaliases + 1);
	addrlist = (char **)dest;
	dest += sizeof (char *) * (numaddrs + 1);
	/*
	 * fill out h_name
	 */
	start = sptr->nsc_ret.nsc_u.buff + sizeof (struct hostent32);
	strcpy(dest, sptr->nsc_ret.nsc_u.hst.h_name + start);
	strs = 1 + strlen(sptr->nsc_ret.nsc_u.hst.h_name + start);
	result->h_name = dest;
	dest += strs;
	/*
	 * fill out the h_aliases list
	 */
	alias = (int *)(start + sptr->nsc_ret.nsc_u.hst.h_aliases);
	for (i = 0; i < numaliases; i++) {
		strcpy(dest, start + alias[i]);
		aliaseslist[i] = dest;
		dest += 1 + strlen(start + alias[i]);
	}
	aliaseslist[i] = 0;	/* null term ptr chain */
	result->h_aliases = aliaseslist;

	/*
	 * fill out the h_addr list
	 */
	dest = (char *)ROUND_UP(dest, sizeof (char *));
	address = (int *)(start + sptr->nsc_ret.nsc_u.hst.h_addr_list);
	for (i = 0; i < numaddrs; i++) {
		memcpy(dest, start + address[i],
		    sptr->nsc_ret.nsc_u.hst.h_length);
		addrlist[i] = dest;
		dest += sptr->nsc_ret.nsc_u.hst.h_length;
		dest = (char *)ROUND_UP(dest, sizeof (char *));
	}

	addrlist[i] = 0;	/* null term ptr chain */

	result->h_addr_list = addrlist;

	result->h_length = sptr->nsc_ret.nsc_u.hst.h_length;
	result->h_addrtype = sptr->nsc_ret.nsc_u.hst.h_addrtype;

	return (result);
}
#endif /* _LP64 */

#endif /* PIC */
