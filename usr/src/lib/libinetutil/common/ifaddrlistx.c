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
 */

#include <errno.h>
#include <libinetutil.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/sockio.h>

/*
 * Create a list of the addresses on physical interface `ifname' with at least
 * one of the flags in `set' set and all of the flags in `clear' clear.
 * Return the number of items in the list, or -1 on failure.
 */
int
ifaddrlistx(const char *ifname, uint64_t set, uint64_t clear,
    ifaddrlistx_t **ifaddrsp)
{
	struct lifconf	lifc;
	struct lifnum	lifn;
	struct lifreq	*lifrp;
	ifaddrlistx_t	*ifaddrp, *ifaddrs = NULL;
	int		i, nlifr, naddr = 0;
	char		*cp;
	uint_t		flags;
	int		s4, s6 = -1;
	boolean_t	isv6;
	int		save_errno;
	struct sockaddr_storage addr;

	(void) memset(&lifc, 0, sizeof (lifc));
	flags = LIFC_NOXMIT | LIFC_ALLZONES | LIFC_TEMPORARY | LIFC_UNDER_IPMP;

	/*
	 * We need both IPv4 and IPv6 sockets to query both IPv4 and IPv6
	 * interfaces below.
	 */
	if ((s4 = socket(AF_INET, SOCK_DGRAM, 0)) == -1 ||
	    (s6 = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
		goto fail;
	}

	/*
	 * Get the number of network interfaces of type `family'.
	 */
	lifn.lifn_family = AF_UNSPEC;
	lifn.lifn_flags = flags;
again:
	if (ioctl(s4, SIOCGLIFNUM, &lifn) == -1)
		goto fail;

	/*
	 * Pad the interface count to detect when additional interfaces have
	 * been configured between SIOCGLIFNUM and SIOCGLIFCONF.
	 */
	lifn.lifn_count += 4;

	lifc.lifc_flags = flags;
	lifc.lifc_family = AF_UNSPEC;
	lifc.lifc_len = lifn.lifn_count * sizeof (struct lifreq);
	if ((lifc.lifc_buf = realloc(lifc.lifc_buf, lifc.lifc_len)) == NULL)
		goto fail;

	if (ioctl(s4, SIOCGLIFCONF, &lifc) == -1)
		goto fail;

	/*
	 * If every lifr_req slot is taken, then additional interfaces must
	 * have been plumbed between the SIOCGLIFNUM and the SIOCGLIFCONF.
	 * Recalculate to make sure we didn't miss any interfaces.
	 */
	nlifr = lifc.lifc_len / sizeof (struct lifreq);
	if (nlifr >= lifn.lifn_count)
		goto again;

	/*
	 * Populate the ifaddrlistx by querying each matching interface.  If a
	 * query ioctl returns ENXIO, then the interface must have been
	 * removed after the SIOCGLIFCONF completed -- so we just ignore it.
	 */
	for (lifrp = lifc.lifc_req, i = 0; i < nlifr; i++, lifrp++) {
		if ((cp = strchr(lifrp->lifr_name, ':')) != NULL)
			*cp = '\0';

		if (strcmp(lifrp->lifr_name, ifname) != 0)
			continue;

		if (cp != NULL)
			*cp = ':';

		addr = lifrp->lifr_addr;
		isv6 = addr.ss_family == AF_INET6;
		if (ioctl(isv6 ? s6 : s4, SIOCGLIFFLAGS, lifrp) == -1) {
			if (errno == ENXIO)
				continue;
			goto fail;
		}

		if (set != 0 && ((lifrp->lifr_flags & set) == 0) ||
		    (lifrp->lifr_flags & clear) != 0)
			continue;

		/*
		 * We've got a match; allocate a new record.
		 */
		if ((ifaddrp = malloc(sizeof (ifaddrlistx_t))) == NULL)
			goto fail;

		(void) strlcpy(ifaddrp->ia_name, lifrp->lifr_name, LIFNAMSIZ);
		ifaddrp->ia_flags = lifrp->lifr_flags;
		ifaddrp->ia_addr = addr;
		ifaddrp->ia_next = ifaddrs;
		ifaddrs = ifaddrp;
		naddr++;
	}

	(void) close(s4);
	(void) close(s6);
	free(lifc.lifc_buf);
	*ifaddrsp = ifaddrs;
	return (naddr);
fail:
	save_errno = errno;
	(void) close(s4);
	(void) close(s6);
	free(lifc.lifc_buf);
	ifaddrlistx_free(ifaddrs);
	errno = save_errno;
	return (-1);
}

/*
 * Free the provided ifaddrlistx_t.
 */
void
ifaddrlistx_free(ifaddrlistx_t *ifaddrp)
{
	ifaddrlistx_t *next_ifaddrp;

	for (; ifaddrp != NULL; ifaddrp = next_ifaddrp) {
		next_ifaddrp = ifaddrp->ia_next;
		free(ifaddrp);
	}
}
