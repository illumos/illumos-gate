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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stropts.h>
#include <errno.h>
#include <sys/sysmacros.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <netinet/in.h>

int
getsourcefilter(int s, uint32_t interface, struct sockaddr *group,
    socklen_t grouplen, uint32_t *fmode, uint_t *numsrc,
    struct sockaddr_storage *slist)
{
	struct group_filter *gf;
	int mallocsize, orig_numsrc, cpsize, rtnerr;

	mallocsize = (*numsrc == 0) ?
	    sizeof (struct group_filter) : GROUP_FILTER_SIZE(*numsrc);
	gf = (struct group_filter *)malloc(mallocsize);
	if (gf == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	gf->gf_interface = interface;
	gf->gf_numsrc = orig_numsrc = *numsrc;
	switch (group->sa_family) {
	case AF_INET:
		if (grouplen < sizeof (struct sockaddr_in)) {
			rtnerr = ENOPROTOOPT;
			goto done;
		}
		(void) memcpy((void *)&gf->gf_group, (void *)group,
		    sizeof (struct sockaddr_in));
		break;
	case AF_INET6:
		if (grouplen < sizeof (struct sockaddr_in6)) {
			rtnerr = ENOPROTOOPT;
			goto done;
		}
		(void) memcpy((void *)&gf->gf_group, (void *)group,
		    sizeof (struct sockaddr_in6));
		break;
	default:
		rtnerr = EAFNOSUPPORT;
		goto done;
	}

	rtnerr = ioctl(s, SIOCGMSFILTER, (void *)gf);
	if (rtnerr == -1) {
		rtnerr = errno;
		goto done;
	}

	*fmode = gf->gf_fmode;
	*numsrc = gf->gf_numsrc;
	cpsize = MIN(orig_numsrc, *numsrc) * sizeof (struct sockaddr_storage);
	(void) memcpy((void *)slist, (void *)gf->gf_slist, cpsize);

done:
	free(gf);
	errno = rtnerr;
	if (errno != 0)
		return (-1);

	return (0);
}

int
setsourcefilter(int s, uint32_t interface, struct sockaddr *group,
    socklen_t grouplen, uint32_t fmode, uint_t numsrc,
    struct sockaddr_storage *slist)
{
	struct group_filter *gf;
	int mallocsize, rtnerr;

	mallocsize = (numsrc == 0) ?
	    sizeof (struct group_filter) : GROUP_FILTER_SIZE(numsrc);
	gf = (struct group_filter *)malloc(mallocsize);
	if (gf == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	switch (group->sa_family) {
	case AF_INET:
		if (grouplen < sizeof (struct sockaddr_in)) {
			rtnerr = ENOPROTOOPT;
			goto done;
		}
		(void) memcpy((void *)&gf->gf_group, (void *)group,
		    sizeof (struct sockaddr_in));
		break;
	case AF_INET6:
		if (grouplen < sizeof (struct sockaddr_in6)) {
			rtnerr = ENOPROTOOPT;
			goto done;
		}
		(void) memcpy((void *)&gf->gf_group, (void *)group,
		    sizeof (struct sockaddr_in6));
		break;
	default:
		rtnerr = EAFNOSUPPORT;
		goto done;
	}
	gf->gf_interface = interface;
	gf->gf_fmode = fmode;
	gf->gf_numsrc = numsrc;
	(void) memcpy((void *)gf->gf_slist, (void *)slist,
	    (numsrc * sizeof (struct sockaddr_storage)));

	rtnerr = ioctl(s, SIOCSMSFILTER, (void *)gf);
	if (rtnerr == -1) {
		rtnerr = errno;
	}

done:
	free(gf);
	errno = rtnerr;
	if (errno != 0)
		return (-1);

	return (0);
}

int
getipv4sourcefilter(int s, struct in_addr interface, struct in_addr group,
    uint32_t *fmode, uint32_t *numsrc, struct in_addr *slist)
{
	struct ip_msfilter *imsf;
	int mallocsize, orig_numsrc, cpsize, rtnerr;

	mallocsize = (*numsrc == 0) ?
	    sizeof (struct ip_msfilter) : IP_MSFILTER_SIZE(*numsrc);
	imsf = (struct ip_msfilter *)malloc(mallocsize);
	if (imsf == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	imsf->imsf_interface = interface;
	imsf->imsf_numsrc = orig_numsrc = *numsrc;
	imsf->imsf_multiaddr = group;

	rtnerr = ioctl(s, SIOCGIPMSFILTER, (void *)imsf);
	if (rtnerr == -1) {
		rtnerr = errno;
		goto done;
	}

	*fmode = imsf->imsf_fmode;
	*numsrc = imsf->imsf_numsrc;
	cpsize = MIN(orig_numsrc, *numsrc) * sizeof (struct in_addr);
	(void) memcpy((void *)slist, (void *)imsf->imsf_slist, cpsize);

done:
	free(imsf);
	errno = rtnerr;
	if (errno != 0)
		return (-1);

	return (0);
}

int
setipv4sourcefilter(int s, struct in_addr interface, struct in_addr group,
    uint32_t fmode, uint32_t numsrc, struct in_addr *slist)
{
	struct ip_msfilter *imsf;
	int mallocsize, rtnerr;

	mallocsize = (numsrc == 0) ?
	    sizeof (struct ip_msfilter) : IP_MSFILTER_SIZE(numsrc);
	imsf = (struct ip_msfilter *)malloc(mallocsize);
	if (imsf == NULL) {
		errno = ENOMEM;
		return (-1);
	}

	imsf->imsf_multiaddr = group;
	imsf->imsf_interface = interface;
	imsf->imsf_fmode = fmode;
	imsf->imsf_numsrc = numsrc;
	(void) memcpy((void *)imsf->imsf_slist, (void *)slist,
	    (numsrc * sizeof (struct in_addr)));

	rtnerr = ioctl(s, SIOCSIPMSFILTER, (void *)imsf);
	if (rtnerr == -1) {
		rtnerr = errno;
	}

	free(imsf);
	errno = rtnerr;
	if (errno != 0)
		return (-1);

	return (0);
}
