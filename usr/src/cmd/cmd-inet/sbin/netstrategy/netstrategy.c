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
 * This program does the following:
 *
 * a) Returns:
 *	0	- if the program successfully determined the net strategy.
 *	!0	- if an error occurred.
 *
 * b) If the program is successful, it prints three tokens to
 *    stdout: <root fs type> <interface name> <net config strategy>.
 *    where:
 *	<root fs type>		-	"nfs" or "ufs"
 *	<interface name>	-	"hme0" or "none"
 *	<net config strategy>	-	"dhcp", "rarp", or "none"
 *
 *    Eg:
 *	# /sbin/netstrategy
 *	ufs hme0 dhcp
 *
 *    <root fs type> identifies the system's root file system type.
 *
 *    <interface name> is the 16 char name of the root interface, and is only
 *	set if rarp/dhcp was used to configure the interface.
 *
 *    <net config strategy> can be either "rarp", "dhcp", or "none" depending
 *	on which strategy was used to configure the interface. Is "none" if
 *	no interface was configured using a net-based strategy.
 *
 * CAVEATS: what about autoclient systems? XXX
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <alloca.h>
#include <sys/systeminfo.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <sys/statvfs.h>

/* ARGSUSED */
int
main(int argc, char *argv[])
{
	struct statvfs	vfs;
	char		*root, *interface, *strategy, dummy;
	long		len;
	int		fd, nifs, nlifr;
	struct lifreq	*lifr;
	struct lifconf	lifc;

	/* root location */
	if (statvfs("/", &vfs) < 0)
		root = "none";
	else {
		if (strncmp(vfs.f_basetype, "nfs", sizeof ("nfs") - 1) == 0)
			vfs.f_basetype[sizeof ("nfs") - 1] = '\0';
		root = vfs.f_basetype;
	}

	/*
	 * Handle the simple case where diskless dhcp tells us everything
	 * we need to know.
	 */
	if ((len = sysinfo(SI_DHCP_CACHE, &dummy, sizeof (dummy))) > 1) {
		/* interface is first thing in cache. */
		strategy = "dhcp";
		interface = alloca(len);
		(void) sysinfo(SI_DHCP_CACHE, interface, len);
		(void) printf("%s %s %s\n", root, interface, strategy);
		return (0);
	}

	/*
	 * We're not "nfs dhcp", "nfs none" is impossible, and we don't handle
	 * "ufs rarp" (consumers are coded to deal with this reality), so
	 * there are three possible situations:
	 *
	 *	1. We're "ufs dhcp" if there are any interfaces which have
	 *	   obtained their addresses through DHCP.  That is, if there
	 *	   are any IFF_UP and non-IFF_VIRTUAL interfaces also have
	 *	   IFF_DHCPRUNNING set.
	 *
	 *	2. We're "ufs none" if our filesystem is local and there
	 *	   are no interfaces which have obtained their addresses
	 *	   through DHCP.
	 *
	 *	3. We're "nfs rarp" if our filesystem is remote and there's
	 *	   at least IFF_UP non-IFF_VIRTUAL interface (which there
	 *	   *must* be, since we're running over NFS somehow), then
	 *	   it must be RARP since SI_DHCP_CACHE call above failed.
	 *	   It's too bad there isn't an IFF_RARPRUNNING flag.
	 */

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		(void) fprintf(stderr, "%s: socket: %s\n", argv[0],
		    strerror(errno));
		return (2);
	}

	if (ioctl(fd, SIOCGIFNUM, &nifs) < 0) {
		(void) fprintf(stderr, "%s: SIOCGIFNUM: %s\n", argv[0],
		    strerror(errno));
		(void) close(fd);
		return (2);
	}

	lifc.lifc_len = nifs * sizeof (struct lifreq);
	lifc.lifc_buf = alloca(lifc.lifc_len);
	lifc.lifc_flags = 0;
	lifc.lifc_family = AF_INET;

	if (ioctl(fd, SIOCGLIFCONF, &lifc) < 0) {
		(void) fprintf(stderr, "%s: SIOCGLIFCONF: %s\n", argv[0],
		    strerror(errno));
		(void) close(fd);
		return (2);
	}

	strategy = NULL;
	interface = NULL;

	nlifr = lifc.lifc_len / sizeof (struct lifreq);
	for (lifr = lifc.lifc_req; nlifr > 0; lifr++, nlifr--) {

		if (strchr(lifr->lifr_name, ':') != NULL)
			continue;	/* skip logical interfaces */

		if (ioctl(fd, SIOCGLIFFLAGS, lifr) < 0) {
			(void) fprintf(stderr, "%s: SIOCGLIFFLAGS: %s\n",
			    argv[0], strerror(errno));
			continue;
		}

		if (lifr->lifr_flags & (IFF_VIRTUAL|IFF_POINTOPOINT))
			continue;

		if (lifr->lifr_flags & IFF_UP) {
			/*
			 * For the "nfs rarp" case, we assume that the first
			 * IFF_UP interface is the one using RARP, so stash
			 * away the first interface in case we need it.
			 *
			 * Since the order of the interfaces retrieved via
			 * SIOCGLIFCONF is not deterministic, this is largely
			 * silliness, but (a) "it's always been this way", (b)
			 * machines booted via diskless RARP typically only
			 * have one interface, and (c) no one consumes the
			 * interface name in the RARP case anyway.
			 */
			if (interface == NULL)
				interface = lifr->lifr_name;

			if (lifr->lifr_flags & IFF_DHCPRUNNING) {
				interface = lifr->lifr_name;
				strategy = "dhcp";
				break;
			}
		}
	}

	(void) close(fd);

	if (strcmp(root, "nfs") == 0 || strcmp(root, "cachefs") == 0) {
		if (interface == NULL) {
			(void) fprintf(stderr,
			    "%s: cannot identify root interface.\n", argv[0]);
			return (2);
		}
		if (strategy == NULL)
			strategy = "rarp";	/*  must be rarp/bootparams */
	} else {
		if (interface == NULL || strategy == NULL)
			interface = strategy = "none";
	}

	(void) printf("%s %s %s\n", root, interface, strategy);
	return (0);
}
