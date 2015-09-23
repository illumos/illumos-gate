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
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */


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
 *	<root fs type>		-	"nfs", "ufs" or "zfs"
 *	<interface name>	-	"hme0" or "none"
 *	<net config strategy>	-	"dhcp", "rarp", "bootprops"
 *					or "none"
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
 *    <net config strategy> can be either "rarp", "dhcp", "bootprops", or
 *	"none" depending on which strategy was used to configure the
 *	interface. Is "none" if no interface was configured using a
 *	net-based strategy.
 *
 * CAVEATS: what about autoclient systems? XXX
 *
 * The logic here must match that in usr/src/uts/common/fs/nfs/nfs_dlinet.c,
 * in particular that code (which implements diskless boot) imposes an
 * ordering on possible ways of configuring network interfaces.
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
#include <libdevinfo.h>

static char *program;

static int s4, s6;	/* inet and inet6 sockets */

static boolean_t
open_sockets(void)
{
	if ((s4 = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		(void) fprintf(stderr, "%s: inet socket: %s\n", program,
		    strerror(errno));
		return (B_FALSE);
	}
	if ((s6 = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
		(void) fprintf(stderr, "%s: inet6 socket: %s\n", program,
		    strerror(errno));
		return (B_FALSE);
	}
	return (B_TRUE);
}

static void
close_sockets(void)
{
	(void) close(s4);
	(void) close(s6);
}

static char *
get_root_fstype()
{
	static struct statvfs vfs;

	/* root location */
	if (statvfs("/", &vfs) < 0) {
		return ("none");
	} else {
		if (strncmp(vfs.f_basetype, "nfs", sizeof ("nfs") - 1) == 0)
			vfs.f_basetype[sizeof ("nfs") - 1] = '\0';
		return (vfs.f_basetype);
	}
}

/*
 * The following boot properties can be used to configure a network
 * interface in the case of a diskless boot.
 *	host-ip, subnet-mask, server-path, server-name, server-ip.
 *
 * XXX non-diskless case requires "network-interface"?
 */
static boolean_t
boot_properties_present()
{
	/* XXX should use sys/bootprops.h, but it's not delivered */
	const char *required_properties[] = {
		"host-ip",
		"subnet-mask",
		"server-path",
		"server-name",
		"server-ip",
		NULL,
	};
	const char **prop = required_properties;
	char *prop_value;
	di_node_t dn;

	if ((dn = di_init("/", DINFOPROP)) == DI_NODE_NIL) {
		(void) fprintf(stderr, "%s: di_init: %s\n", program,
		    strerror(errno));
		di_fini(dn);
		return (B_FALSE);
	}

	while (*prop != NULL) {
		if (di_prop_lookup_strings(DDI_DEV_T_ANY,
		    dn, *prop, &prop_value) != 1) {
			di_fini(dn);
			return (B_FALSE);
		}
		prop++;
	}
	di_fini(dn);

	return (B_TRUE);
}

static char *
get_first_interface(boolean_t *dhcpflag)
{
	struct lifnum ifnum;
	struct lifconf ifconf;
	struct lifreq *ifr;
	static char interface[LIFNAMSIZ];
	boolean_t isv4, found_one = B_FALSE;

	ifnum.lifn_family = AF_UNSPEC;
	ifnum.lifn_flags = 0;
	ifnum.lifn_count = 0;

	if (ioctl(s4, SIOCGLIFNUM, &ifnum) < 0) {
		(void) fprintf(stderr, "%s: SIOCGLIFNUM: %s\n", program,
		    strerror(errno));
		return (NULL);
	}

	ifconf.lifc_family = AF_UNSPEC;
	ifconf.lifc_flags = 0;
	ifconf.lifc_len = ifnum.lifn_count * sizeof (struct lifreq);
	ifconf.lifc_buf = alloca(ifconf.lifc_len);

	if (ioctl(s4, SIOCGLIFCONF, &ifconf) < 0) {
		(void) fprintf(stderr, "%s: SIOCGLIFCONF: %s\n", program,
		    strerror(errno));
		return (NULL);
	}

	for (ifr = ifconf.lifc_req; ifr < &ifconf.lifc_req[ifconf.lifc_len /
	    sizeof (ifconf.lifc_req[0])]; ifr++) {
		struct lifreq flifr;
		struct sockaddr_in *sin;

		if (strchr(ifr->lifr_name, ':') != NULL)
			continue;	/* skip logical interfaces */

		isv4 = ifr->lifr_addr.ss_family == AF_INET;

		(void) strncpy(flifr.lifr_name, ifr->lifr_name, LIFNAMSIZ);

		if (ioctl(isv4 ? s4 : s6, SIOCGLIFFLAGS, &flifr) < 0) {
			(void) fprintf(stderr, "%s: SIOCGLIFFLAGS: %s\n",
			    program, strerror(errno));
			continue;
		}

		if (!(flifr.lifr_flags & IFF_UP) ||
		    (flifr.lifr_flags & (IFF_VIRTUAL|IFF_POINTOPOINT)))
			continue;

		/*
		 * For the "nfs rarp" and "nfs bootprops"
		 * cases, we assume that the first non-virtual
		 * IFF_UP interface with a non-zero address is
		 * the one used.
		 *
		 * For the non-zero address check, we only check
		 * v4 interfaces, as it's not possible to set the
		 * the first logical interface (the only ones we
		 * look at here) to ::0; that interface must have
		 * a link-local address.
		 *
		 * If we don't find an IFF_UP interface with a
		 * non-zero address, we'll return the last IFF_UP
		 * interface seen.
		 *
		 * Since the order of the interfaces retrieved
		 * via SIOCGLIFCONF is not deterministic, this
		 * is largely silliness, but (a) "it's always
		 * been this way", and (b) no one consumes the
		 * interface name in the RARP case anyway.
		 */

		found_one = B_TRUE;
		(void) strncpy(interface, ifr->lifr_name, LIFNAMSIZ);
		*dhcpflag = (flifr.lifr_flags & IFF_DHCPRUNNING) != 0;
		sin = (struct sockaddr_in *)&ifr->lifr_addr;
		if (isv4 && (sin->sin_addr.s_addr == INADDR_ANY)) {
			/* keep looking for a non-zero address */
			continue;
		}
		return (interface);
	}

	return (found_one ? interface : NULL);
}

/* ARGSUSED */
int
main(int argc, char *argv[])
{
	char *root, *interface, *strategy, dummy;
	long len;
	boolean_t dhcp_running = B_FALSE;

	root = interface = strategy = NULL;
	program = argv[0];

	root = get_root_fstype();

	if (!open_sockets()) {
		(void) fprintf(stderr,
		    "%s: cannot get interface information\n", program);
		return (2);
	}

	/*
	 * If diskless, perhaps boot properties were used to configure
	 * the interface.
	 */
	if ((strcmp(root, "nfs") == 0) && boot_properties_present()) {
		strategy = "bootprops";

		interface = get_first_interface(&dhcp_running);
		if (interface == NULL) {
			(void) fprintf(stderr,
			    "%s: cannot identify root interface.\n", program);
			close_sockets();
			return (2);
		}

		(void) printf("%s %s %s\n", root, interface, strategy);
		close_sockets();
		return (0);
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
		close_sockets();
		return (0);
	}

	/*
	 * We're not "nfs dhcp", "nfs none" is impossible, and we don't handle
	 * "ufs rarp" (consumers are coded to deal with this reality), so
	 * there are three possible situations:
	 *
	 *	1. We're either "ufs dhcp" or "zfs dhcp" if there are any
	 *	   interfaces which have obtained their addresses through DHCP.
	 *	   That is, if there are any IFF_UP and non-IFF_VIRTUAL
	 *	   interfaces also have IFF_DHCPRUNNING set.
	 *
	 *	2. We're either "ufs none" or "zfs none" if our filesystem
	 *	   is local and there are no interfaces which have obtained
	 *	   their addresses through DHCP.
	 *
	 *	3. We're "nfs rarp" if our filesystem is remote and there's
	 *	   at least IFF_UP non-IFF_VIRTUAL interface (which there
	 *	   *must* be, since we're running over NFS somehow), then
	 *	   it must be RARP since SI_DHCP_CACHE call above failed.
	 *	   It's too bad there isn't an IFF_RARPRUNNING flag.
	 */

	interface = get_first_interface(&dhcp_running);

	if (dhcp_running)
		strategy = "dhcp";

	if (strcmp(root, "nfs") == 0) {
		if (interface == NULL) {
			(void) fprintf(stderr,
			    "%s: cannot identify root interface.\n", program);
			close_sockets();
			return (2);
		}
		if (strategy == NULL)
			strategy = "rarp";	/*  must be rarp/bootparams */
	} else {
		if (interface == NULL || strategy == NULL)
			interface = strategy = "none";
	}

	(void) printf("%s %s %s\n", root, interface, strategy);
	close_sockets();
	return (0);
}
