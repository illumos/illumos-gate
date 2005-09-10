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

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <errno.h>
#include <strings.h>
#include <ipmp_mpathd.h>
#include <libintl.h>

static int		if_down(int ifsock, struct lifreq *lifr);
static int		if_up(int ifsock, struct lifreq *lifr);
static void		send_cmd(int cmd, char *ifname);
static int		connect_to_mpathd(sa_family_t family);
static void		do_offline(char *ifname);
static void		undo_offline(char *ifname);
static boolean_t	offline_set(char *ifname);

#define	IF_SEPARATOR	':'
#define	MAX_RETRIES	3

static void
usage()
{
	(void) fprintf(stderr, "Usage : if_mpadm [-d | -r] <interface_name>\n");
}

static void
print_mpathd_error_msg(uint32_t error)
{
	switch (error) {
	case MPATHD_MIN_RED_ERROR:
		(void) fprintf(stderr, gettext(
			"Offline failed as there is no other functional "
			"interface available in the multipathing group "
			"for failing over the network access.\n"));
		break;

	case MPATHD_FAILBACK_PARTIAL:
		(void) fprintf(stderr, gettext(
			"Offline cannot be undone because multipathing "
			"configuration is not consistent across all the "
			"interfaces in the group.\n"));
		break;

	default:
		/*
		 * We shouldn't get here.  All errors should have a
		 * meaningful error message, as shown in the above
		 * cases.  If we get here, someone has made a mistake.
		 */
		(void) fprintf(stderr, gettext(
			"Operation returned an unrecognized error: %u\n"),
			error);
		break;
	}
}

int
main(int argc, char **argv)
{
	char *ifname;
	int cmd = 0;
	int c;

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "d:r:")) != EOF) {
		switch (c) {
		case 'd':
			ifname = optarg;
			cmd = MI_OFFLINE;
			if (offline_set(ifname)) {
				(void) fprintf(stderr, gettext("Interface "
				    "already offlined\n"));
				exit(1);
			}
			break;
		case 'r':
			ifname = optarg;
			cmd = MI_UNDO_OFFLINE;
			if (!offline_set(ifname)) {
				(void) fprintf(stderr, gettext("Interface not "
				    "offlined\n"));
				exit(1);
			}
			break;
		default :
			usage();
			exit(1);
		}
	}

	if (cmd == 0) {
		usage();
		exit(1);
	}

	/*
	 * Send the command to in.mpathd which is generic to
	 * both the commands. send_cmd returns only if there
	 * is no error.
	 */
	send_cmd(cmd, ifname);
	if (cmd == MI_OFFLINE) {
		do_offline(ifname);
	} else {
		undo_offline(ifname);
	}

	return (0);
}

/*
 * Is IFF_OFFLINE set ?
 * Returns B_FALSE on failure and B_TRUE on success.
 */
boolean_t
offline_set(char *ifname)
{
	struct lifreq lifr;
	int s4;
	int s6;
	int ret;

	s4 = socket(AF_INET, SOCK_DGRAM, 0);
	if (s4 < 0) {
		perror("socket");
		exit(1);
	}
	s6 = socket(AF_INET6, SOCK_DGRAM, 0);
	if (s6 < 0) {
		perror("socket");
		exit(1);
	}
	(void) strncpy(lifr.lifr_name, ifname, sizeof (lifr.lifr_name));
	ret = ioctl(s4, SIOCGLIFFLAGS, (caddr_t)&lifr);
	if (ret < 0) {
		if (errno != ENXIO) {
			perror("ioctl: SIOCGLIFFLAGS");
			exit(1);
		}
		ret = ioctl(s6, SIOCGLIFFLAGS, (caddr_t)&lifr);
		if (ret < 0) {
			perror("ioctl: SIOCGLIFFLAGS");
			exit(1);
		}
	}
	(void) close(s4);
	(void) close(s6);
	if (lifr.lifr_flags & IFF_OFFLINE)
		return (B_TRUE);
	else
		return (B_FALSE);
}

/*
 * Sends the command to in.mpathd. If not successful, prints
 * an error message and exits.
 */
void
send_cmd(int cmd, char *ifname)
{
	struct mi_offline mio;
	struct mi_undo_offline miu;
	struct mi_result me;
	int ret;
	int cmd_len;
	int i;
	int s;

	for (i = 0; i < MAX_RETRIES; i++) {
		s = connect_to_mpathd(AF_INET);
		if (s == -1) {
			s = connect_to_mpathd(AF_INET6);
			if (s == -1) {
				(void) fprintf(stderr, gettext("Cannot "
				    "establish communication with "
				    "in.mpathd.\n"));
				exit(1);
			}
		}
		switch (cmd) {
		case MI_OFFLINE :
			cmd_len = sizeof (struct mi_offline);
			bzero(&mio, cmd_len);
			mio.mio_command = cmd;
			(void) strncpy(mio.mio_ifname, ifname, LIFNAMSIZ);
			mio.mio_min_redundancy = 1;
			ret = write(s, &mio, cmd_len);
			if (ret != cmd_len) {
				/* errno is set only when ret is -1 */
				if (ret == -1)
					perror("write");
				(void) fprintf(stderr, gettext("Failed to "
				    "successfully send command to "
				    "in.mpathd.\n"));
				exit(1);
			}
			break;
		case MI_UNDO_OFFLINE:
			cmd_len = sizeof (struct mi_undo_offline);
			bzero(&miu, cmd_len);
			miu.miu_command = cmd;
			(void) strncpy(miu.miu_ifname, ifname, LIFNAMSIZ);
			ret = write(s, &miu, cmd_len);
			if (ret != cmd_len) {
				/* errno is set only when ret is -1 */
				if (ret == -1)
					perror("write");
				(void) fprintf(stderr, gettext("Failed to "
				    "successfully send command to "
				    "in.mpathd.\n"));
				exit(1);
			}
			break;
		default :
			(void) fprintf(stderr, "Unknown command \n");
			exit(1);
		}

		/* Read the result from mpathd */
		ret = read(s, &me, sizeof (me));
		if (ret != sizeof (me)) {
			/* errno is set only when ret is -1 */
			if (ret == -1)
				perror("read");
			(void) fprintf(stderr, gettext("Failed to successfully "
			    "read result from in.mpathd.\n"));
			exit(1);
		}
		if (me.me_mpathd_error == 0) {
			if (i != 0) {
				/*
				 * We retried at least once. Tell the user
				 * that things succeeded now.
				 */
				(void) fprintf(stderr,
				    gettext("Retry Successful.\n"));
			}
			return;			/* Successful */
		}

		if (me.me_mpathd_error == MPATHD_SYS_ERROR) {
			if (me.me_sys_error == EAGAIN) {
				(void) close(s);
				(void) sleep(1);
				(void) fprintf(stderr,
				    gettext("Retrying ...\n"));
				continue;		/* Retry */
			}
			errno = me.me_sys_error;
			perror("if_mpadm");
		} else {
			print_mpathd_error_msg(me.me_mpathd_error);
		}
		exit(1);
	}
	/*
	 * We come here only if we retry the operation multiple
	 * times and did not succeed. Let the user try it again
	 * later.
	 */
	(void) fprintf(stderr,
	    gettext("Device busy. Retry the operation later.\n"));
	exit(1);
}

static void
do_offline(char *ifname)
{
	struct lifreq lifr;
	struct lifreq *lifcr;
	struct lifnum	lifn;
	struct lifconf	lifc;
	char *buf;
	int numifs;
	int n;
	char	pi_name[LIFNAMSIZ + 1];
	char	*cp;
	int ifsock_v4;
	int ifsock_v6;
	int af;
	int ret;

	/*
	 * Verify whether IFF_OFFLINE is not set as a sanity check.
	 */
	if (!offline_set(ifname)) {
		(void) fprintf(stderr, gettext("Operation failed : in.mpathd "
		    "has not set IFF_OFFLINE on %s\n"), ifname);
		exit(1);
	}
	/*
	 * Get both the sockets as we may need to bring both
	 * IPv4 and IPv6 interfaces down.
	 */
	ifsock_v4 = socket(AF_INET, SOCK_DGRAM, 0);
	if (ifsock_v4 < 0) {
		perror("socket");
		exit(1);
	}
	ifsock_v6 = socket(AF_INET6, SOCK_DGRAM, 0);
	if (ifsock_v6 < 0) {
		perror("socket");
		exit(1);
	}
	/*
	 * Get all the logicals for "ifname" and mark them down.
	 * There is no easy way of doing this. We get all the
	 * interfaces in the system using SICGLIFCONF and mark the
	 * ones matching the name down.
	 */
	lifn.lifn_family = AF_UNSPEC;
	lifn.lifn_flags = 0;
	if (ioctl(ifsock_v4, SIOCGLIFNUM, (char *)&lifn) < 0) {
		perror("ioctl : SIOCGLIFNUM");
		exit(1);
	}
	numifs = lifn.lifn_count;

	buf = calloc(numifs, sizeof (struct lifreq));
	if (buf == NULL) {
		perror("calloc");
		exit(1);
	}

	lifc.lifc_family = AF_UNSPEC;
	lifc.lifc_flags = 0;
	lifc.lifc_len = numifs * sizeof (struct lifreq);
	lifc.lifc_buf = buf;

	if (ioctl(ifsock_v4, SIOCGLIFCONF, (char *)&lifc) < 0) {
		perror("ioctl : SIOCGLIFCONF");
		exit(1);
	}

	lifcr = (struct lifreq *)lifc.lifc_req;
	for (n = lifc.lifc_len / sizeof (struct lifreq); n > 0; n--, lifcr++) {
		af = lifcr->lifr_addr.ss_family;
		(void) strncpy(pi_name, lifcr->lifr_name,
		    sizeof (pi_name));
		pi_name[sizeof (pi_name) - 1] = '\0';
		if ((cp = strchr(pi_name, IF_SEPARATOR)) != NULL)
			*cp = '\0';
		if (strcmp(pi_name, ifname) == 0) {
			/* It matches the interface name that was offlined */
			(void) strncpy(lifr.lifr_name, lifcr->lifr_name,
			    sizeof (lifr.lifr_name));
			if (af == AF_INET)
				ret = if_down(ifsock_v4, &lifr);
			else
				ret = if_down(ifsock_v6, &lifr);
			if (ret != 0) {
				(void) fprintf(stderr, gettext("Bringing down "
				    "the interfaces failed.\n"));
				exit(1);
			}
		}
	}
}

static void
undo_offline(char *ifname)
{
	struct lifreq lifr;
	struct lifreq *lifcr;
	struct lifnum	lifn;
	struct lifconf	lifc;
	char *buf;
	int numifs;
	int n;
	char	pi_name[LIFNAMSIZ + 1];
	char	*cp;
	int ifsock_v4;
	int ifsock_v6;
	int af;
	int ret;

	/*
	 * Verify whether IFF_OFFLINE is set as a sanity check.
	 */
	if (offline_set(ifname)) {
		(void) fprintf(stderr, gettext("Operation failed : in.mpathd "
		    "has not cleared IFF_OFFLINE on %s\n"), ifname);
		exit(1);
	}
	/*
	 * Get both the sockets as we may need to bring both
	 * IPv4 and IPv6 interfaces UP.
	 */
	ifsock_v4 = socket(AF_INET, SOCK_DGRAM, 0);
	if (ifsock_v4 < 0) {
		perror("socket");
		exit(1);
	}
	ifsock_v6 = socket(AF_INET6, SOCK_DGRAM, 0);
	if (ifsock_v6 < 0) {
		perror("socket");
		exit(1);
	}
	/*
	 * Get all the logicals for "ifname" and mark them up.
	 * There is no easy way of doing this. We get all the
	 * interfaces in the system using SICGLIFCONF and mark the
	 * ones matching the name up.
	 */
	lifn.lifn_family = AF_UNSPEC;
	lifn.lifn_flags = 0;
	if (ioctl(ifsock_v4, SIOCGLIFNUM, (char *)&lifn) < 0) {
		perror("ioctl : SIOCGLIFNUM");
		exit(1);
	}
	numifs = lifn.lifn_count;

	buf = calloc(numifs, sizeof (struct lifreq));
	if (buf == NULL) {
		perror("calloc");
		exit(1);
	}

	lifc.lifc_family = AF_UNSPEC;
	lifc.lifc_flags = 0;
	lifc.lifc_len = numifs * sizeof (struct lifreq);
	lifc.lifc_buf = buf;

	if (ioctl(ifsock_v4, SIOCGLIFCONF, (char *)&lifc) < 0) {
		perror("ioctl : SIOCGLIFCONF");
		exit(1);
	}

	lifcr = (struct lifreq *)lifc.lifc_req;
	for (n = lifc.lifc_len / sizeof (struct lifreq); n > 0; n--, lifcr++) {
		af = lifcr->lifr_addr.ss_family;
		(void) strncpy(pi_name, lifcr->lifr_name,
		    sizeof (pi_name));
		pi_name[sizeof (pi_name) - 1] = '\0';
		if ((cp = strchr(pi_name, IF_SEPARATOR)) != NULL)
			*cp = '\0';

		if (strcmp(pi_name, ifname) == 0) {
			/* It matches the interface name that was offlined */
			(void) strncpy(lifr.lifr_name, lifcr->lifr_name,
			    sizeof (lifr.lifr_name));
			if (af == AF_INET)
				ret = if_up(ifsock_v4, &lifr);
			else
				ret = if_up(ifsock_v6, &lifr);
			if (ret != 0) {
				(void) fprintf(stderr, gettext("Bringing up "
				    "the interfaces failed.\n"));
				exit(1);
			}
		}
	}
}

/*
 * Returns -1 on failure. Returns the socket file descriptor on
 * success.
 */
static int
connect_to_mpathd(sa_family_t family)
{
	int s;
	struct sockaddr_storage ss;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
	struct in6_addr loopback_addr = IN6ADDR_LOOPBACK_INIT;
	int addrlen;
	int ret;
	int on;

	s = socket(family, SOCK_STREAM, 0);
	if (s < 0) {
		perror("socket");
		return (-1);
	}
	bzero((char *)&ss, sizeof (ss));
	ss.ss_family = family;
	/*
	 * Need to bind to a privileged port. For non-root, this
	 * will fail. in.mpathd verifies that only commands coming
	 * from privileged ports succeed so that the ordinary user
	 * can't issue offline commands.
	 */
	on = 1;
	if (setsockopt(s, IPPROTO_TCP, TCP_ANONPRIVBIND, &on,
	    sizeof (on)) < 0) {
		perror("setsockopt : TCP_ANONPRIVBIND");
		exit(1);
	}
	switch (family) {
	case AF_INET:
		sin->sin_port = 0;
		sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addrlen = sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		sin6->sin6_port = 0;
		sin6->sin6_addr = loopback_addr;
		addrlen = sizeof (struct sockaddr_in6);
		break;
	}
	ret = bind(s, (struct sockaddr *)&ss, addrlen);
	if (ret != 0) {
		perror("bind");
		return (-1);
	}
	switch (family) {
	case AF_INET:
		sin->sin_port = htons(MPATHD_PORT);
		break;
	case AF_INET6:
		sin6->sin6_port = htons(MPATHD_PORT);
		break;
	}
	ret = connect(s, (struct sockaddr *)&ss, addrlen);
	if (ret != 0) {
		perror("connect");
		return (-1);
	}
	on = 0;
	if (setsockopt(s, IPPROTO_TCP, TCP_ANONPRIVBIND, &on,
	    sizeof (on)) < 0) {
		perror("setsockopt : TCP_ANONPRIVBIND");
		return (-1);
	}
	return (s);
}

/*
 * Bring down the interface specified by the name lifr->lifr_name.
 *
 * Returns -1 on failure. Returns 0 on success.
 */
static int
if_down(int ifsock, struct lifreq *lifr)
{
	int ret;

	ret = ioctl(ifsock, SIOCGLIFFLAGS, (caddr_t)lifr);
	if (ret < 0) {
		perror("ioctl: SIOCGLIFFLAGS");
		return (-1);
	}

	/* IFF_OFFLINE was set to start with. Is it still there ? */
	if (!(lifr->lifr_flags & (IFF_OFFLINE))) {
		(void) fprintf(stderr, gettext("IFF_OFFLINE disappeared on "
		    "%s\n"), lifr->lifr_name);
		return (-1);
	}
	lifr->lifr_flags &= ~IFF_UP;
	ret = ioctl(ifsock, SIOCSLIFFLAGS, (caddr_t)lifr);
	if (ret < 0) {
		perror("ioctl: SIOCSLIFFLAGS");
		return (-1);
	}
	return (0);
}

/*
 * Bring up the interface specified by the name lifr->lifr_name.
 *
 * Returns -1 on failure. Returns 0 on success.
 */
static int
if_up(int ifsock, struct lifreq *lifr)
{
	int ret;
	boolean_t zeroaddr = B_FALSE;
	struct sockaddr_in *addr;

	ret = ioctl(ifsock, SIOCGLIFADDR, lifr);
	if (ret < 0) {
		perror("ioctl: SIOCGLIFADDR");
		return (-1);
	}

	addr = (struct sockaddr_in *)&lifr->lifr_addr;
	switch (addr->sin_family) {
	case AF_INET:
		zeroaddr = (addr->sin_addr.s_addr == INADDR_ANY);
		break;

	case AF_INET6:
		zeroaddr = IN6_IS_ADDR_UNSPECIFIED(
		    &((struct sockaddr_in6 *)addr)->sin6_addr);
		break;

	default:
		break;
	}

	ret = ioctl(ifsock, SIOCGLIFFLAGS, lifr);
	if (ret < 0) {
		perror("ioctl: SIOCGLIFFLAGS");
		return (-1);
	}
	/*
	 * Don't affect the state of addresses that failed back.
	 *
	 * XXX Link local addresses that are not marked IFF_NOFAILOVER
	 * will not be brought up. Link local addresses never failover.
	 * When the interface was offlined, we brought the link local
	 * address down. We will not bring it up now if IFF_NOFAILOVER
	 * is not marked. We check for IFF_NOFAILOVER below so that
	 * we want to maintain the state of all other addresses as it
	 * was before offline. Normally link local addresses are marked
	 * IFF_NOFAILOVER and hence this is not an issue. These can
	 * be fixed in future with RCM and it is beyond the scope
	 * of if_mpadm to maintain state and do this correctly.
	 */
	if (!(lifr->lifr_flags & IFF_NOFAILOVER))
		return (0);

	/*
	 * When a data address associated with the physical interface itself
	 * is failed over (e.g., qfe0, rather than qfe0:1), the kernel must
	 * fill the ipif data structure for qfe0 with a placeholder entry (the
	 * "replacement ipif").	 Replacement ipif's cannot be brought IFF_UP
	 * (nor would it make any sense to do so), so we must be careful to
	 * skip them; thankfully they can be easily identified since they
	 * all have a zeroed address.
	 */
	if (zeroaddr)
		return (0);

	/* IFF_OFFLINE was not set to start with. Is it there ? */
	if (lifr->lifr_flags & IFF_OFFLINE) {
		(void) fprintf(stderr,
		    gettext("IFF_OFFLINE set wrongly on %s\n"),
		    lifr->lifr_name);
		return (-1);
	}
	lifr->lifr_flags |= IFF_UP;
	ret = ioctl(ifsock, SIOCSLIFFLAGS, lifr);
	if (ret < 0) {
		perror("ioctl: SIOCSLIFFLAGS");
		return (-1);
	}
	return (0);
}
