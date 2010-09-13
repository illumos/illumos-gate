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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/dhcp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <string.h>			/* memcpy */
#include <fcntl.h>
#include <limits.h>

#include "dhcp_hostconf.h"

static void		relativize_time(DHCP_OPT *, time_t, time_t);
static void		relativize_v6(uint32_t *, time_t, time_t);

/*
 * ifname_to_hostconf(): converts an interface name into a hostconf file for
 *			 that interface
 *
 *   input: const char *: the interface name
 *	    boolean_t: B_TRUE if using DHCPv6
 *  output: char *: the hostconf filename
 *    note: uses an internal static buffer (not threadsafe)
 */

char *
ifname_to_hostconf(const char *ifname, boolean_t isv6)
{
	static char filename[sizeof (DHCP_HOSTCONF_TMPL6) + LIFNAMSIZ];

	(void) snprintf(filename, sizeof (filename), "%s%s%s",
	    DHCP_HOSTCONF_PREFIX, ifname,
	    isv6 ? DHCP_HOSTCONF_SUFFIX6 : DHCP_HOSTCONF_SUFFIX);

	return (filename);
}

/*
 * remove_hostconf(): removes an interface.dhc file
 *
 *   input: const char *: the interface name
 *	    boolean_t: B_TRUE if using DHCPv6
 *  output: int: 0 if the file is removed, -1 if it can't be removed
 *          (errno is set)
 */

int
remove_hostconf(const char *ifname, boolean_t isv6)
{
	return (unlink(ifname_to_hostconf(ifname, isv6)));
}

/*
 * read_hostconf(): reads the contents of an <if>.dhc file into a PKT_LIST
 *
 *   input: const char *: the interface name
 *	    PKT_LIST **: a pointer to a PKT_LIST * to store the info in
 *	    uint_t: the length of the list of PKT_LISTs
 *	    boolean_t: B_TRUE if using DHCPv6
 *  output: int: >0 if the file is read and loaded into the PKT_LIST *
 *	    successfully, -1 otherwise (errno is set)
 *    note: the PKT and PKT_LISTs are dynamically allocated here
 */

int
read_hostconf(const char *ifname, PKT_LIST **plpp, uint_t plplen,
    boolean_t isv6)
{
	PKT_LIST	*plp = NULL;
	PKT		*pkt = NULL;
	int		fd;
	time_t		orig_time, current_time = time(NULL);
	uint32_t	lease;
	uint32_t	magic;
	int		pcnt = 0;
	int		retval;

	fd = open(ifname_to_hostconf(ifname, isv6), O_RDONLY);
	if (fd == -1)
		return (-1);

	if (read(fd, &magic, sizeof (magic)) != sizeof (magic))
		goto failure;

	if (magic != (isv6 ? DHCP_HOSTCONF_MAGIC6 : DHCP_HOSTCONF_MAGIC))
		goto failure;

	if (read(fd, &orig_time, sizeof (orig_time)) != sizeof (orig_time))
		goto failure;

	/*
	 * read the packet back in from disk, and for v4, run it through
	 * dhcp_options_scan(). note that we use calloc() because
	 * dhcp_options_scan() relies on the structure being zeroed.
	 */

	for (pcnt = 0; pcnt < plplen; pcnt++) {

		plp = NULL;
		pkt = NULL;

		if ((plp = calloc(1, sizeof (PKT_LIST))) == NULL)
			goto failure;

		retval = read(fd, &plp->len, sizeof (plp->len));
		if (retval == 0 && pcnt != 0) {
			/*
			 * Reached end of file on a boundary, but after
			 * we've read at least one packet, so we consider
			 * this successful, allowing us to use files from
			 * older versions of the agent happily.
			 */
			free(plp);
			break;
		} else if (retval != sizeof (plp->len))
			goto failure;

		if ((pkt = malloc(plp->len)) == NULL)
			goto failure;

		if (read(fd, pkt, plp->len) != plp->len)
			goto failure;

		plp->pkt = pkt;

		plpp[pcnt] = plp;

		if (!isv6 && dhcp_options_scan(plp, B_TRUE) != 0)
			goto failure;

		/*
		 * First packet used to validate that we're interested,
		 * the rest are presumed to be historical reference and
		 * are not relativized
		 */
		if (pcnt == 0)
			continue;

		if (isv6) {
			dhcpv6_option_t	d6o;
			dhcpv6_ia_na_t	d6in;
			dhcpv6_iaaddr_t	d6ia;
			uchar_t		*opts, *optmax, *subomax;

			/*
			 * Loop over contents of the packet to find the address
			 * options.
			 */
			opts = (uchar_t *)pkt + sizeof (dhcpv6_message_t);
			optmax = (uchar_t *)pkt + plp->len;
			while (opts + sizeof (d6o) <= optmax) {

				/*
				 * Extract option header and make sure option
				 * is intact.
				 */
				(void) memcpy(&d6o, opts, sizeof (d6o));
				d6o.d6o_code = ntohs(d6o.d6o_code);
				d6o.d6o_len = ntohs(d6o.d6o_len);
				subomax = opts + sizeof (d6o) + d6o.d6o_len;
				if (subomax > optmax)
					break;

				/*
				 * If this isn't an option that contains
				 * address or prefix leases, then skip over it.
				 */
				if (d6o.d6o_code != DHCPV6_OPT_IA_NA &&
				    d6o.d6o_code != DHCPV6_OPT_IA_TA &&
				    d6o.d6o_code != DHCPV6_OPT_IA_PD) {
					opts = subomax;
					continue;
				}

				/*
				 * Handle the option first.
				 */
				if (d6o.d6o_code == DHCPV6_OPT_IA_TA) {
					/* no timers in this structure */
					opts += sizeof (dhcpv6_ia_ta_t);
				} else {
					/* both na and pd */
					if (opts + sizeof (d6in) > subomax) {
						opts = subomax;
						continue;
					}
					(void) memcpy(&d6in, opts,
					    sizeof (d6in));
					relativize_v6(&d6in.d6in_t1, orig_time,
					    current_time);
					relativize_v6(&d6in.d6in_t2, orig_time,
					    current_time);
					(void) memcpy(opts, &d6in,
					    sizeof (d6in));
					opts += sizeof (d6in);
				}

				/*
				 * Now handle each suboption (address) inside.
				 */
				while (opts + sizeof (d6o) <= subomax) {
					/*
					 * Verify the suboption header first.
					 */
					(void) memcpy(&d6o, opts,
					    sizeof (d6o));
					d6o.d6o_code = ntohs(d6o.d6o_code);
					d6o.d6o_len = ntohs(d6o.d6o_len);
					if (opts + sizeof (d6o) + d6o.d6o_len >
					    subomax)
						break;
					if (d6o.d6o_code != DHCPV6_OPT_IAADDR) {
						opts += sizeof (d6o) +
						    d6o.d6o_len;
						continue;
					}

					/*
					 * Now process the contents.
					 */
					if (opts + sizeof (d6ia) > subomax)
						break;
					(void) memcpy(&d6ia, opts,
					    sizeof (d6ia));
					relativize_v6(&d6ia.d6ia_preflife,
					    orig_time, current_time);
					relativize_v6(&d6ia.d6ia_vallife,
					    orig_time, current_time);
					(void) memcpy(opts, &d6ia,
					    sizeof (d6ia));
					opts += sizeof (d6o) + d6o.d6o_len;
				}
				opts = subomax;
			}
		} else {

			/*
			 * make sure the IPv4 DHCP lease is still valid.
			 */

			if (plp->opts[CD_LEASE_TIME] != NULL &&
			    plp->opts[CD_LEASE_TIME]->len ==
			    sizeof (lease_t)) {

				(void) memcpy(&lease,
				    plp->opts[CD_LEASE_TIME]->value,
				    sizeof (lease_t));

				lease = ntohl(lease);
				if ((lease != DHCP_PERM) &&
				    (orig_time + lease) <= current_time)
					goto failure;
			}

			relativize_time(plp->opts[CD_T1_TIME], orig_time,
			    current_time);
			relativize_time(plp->opts[CD_T2_TIME], orig_time,
			    current_time);
			relativize_time(plp->opts[CD_LEASE_TIME], orig_time,
			    current_time);
		}
	}

	(void) close(fd);
	return (pcnt);

failure:
	free(pkt);
	free(plp);
	while (pcnt-- > 0) {
		free(plpp[pcnt]->pkt);
		free(plpp[pcnt]);
	}
	(void) close(fd);
	return (-1);
}

/*
 * write_hostconf(): writes the contents of a PKT_LIST into an <if>.dhc file
 *
 *   input: const char *: the interface name
 *	    PKT_LIST **: a list of pointers to PKT_LIST to write
 *	    uint_t: length of the list of PKT_LIST pointers
 *	    time_t: a starting time to treat the relative lease times
 *		    in the first packet as relative to
 *	    boolean_t: B_TRUE if using DHCPv6
 *  output: int: 0 if the file is written successfully, -1 otherwise
 *	    (errno is set)
 */

int
write_hostconf(
    const char *ifname,
    PKT_LIST *pl[],
    uint_t pllen,
    time_t relative_to,
    boolean_t isv6)
{
	int		fd;
	struct iovec	iov[IOV_MAX];
	int		retval;
	uint32_t	magic;
	ssize_t		explen = 0; /* Expected length of write */
	int		i, iovlen = 0;

	fd = open(ifname_to_hostconf(ifname, isv6), O_WRONLY|O_CREAT|O_TRUNC,
	    0600);
	if (fd == -1)
		return (-1);

	/*
	 * first write our magic number, then the relative time of the
	 * leases, then for each packet we write the length of the packet
	 * followed by the packet.  we will then use the relative time in
	 * read_hostconf() to recalculate the lease times for the first packet.
	 */

	magic = isv6 ? DHCP_HOSTCONF_MAGIC6 : DHCP_HOSTCONF_MAGIC;
	iov[iovlen].iov_base = (caddr_t)&magic;
	explen += iov[iovlen++].iov_len  = sizeof (magic);
	iov[iovlen].iov_base = (caddr_t)&relative_to;
	explen += iov[iovlen++].iov_len  = sizeof (relative_to);
	for (i = 0; i < pllen && iovlen < (IOV_MAX - 1); i++) {
		iov[iovlen].iov_base = (caddr_t)&pl[i]->len;
		explen += iov[iovlen++].iov_len  = sizeof (pl[i]->len);
		iov[iovlen].iov_base = (caddr_t)pl[i]->pkt;
		explen += iov[iovlen++].iov_len  = pl[i]->len;
	}

	retval = writev(fd, iov, iovlen);

	(void) close(fd);

	if (retval != explen)
		return (-1);

	return (0);
}

/*
 * relativize_time(): re-relativizes a time in a DHCP option
 *
 *   input: DHCP_OPT *: the DHCP option parameter to convert
 *	    time_t: the time the leases in the packet are currently relative to
 *	    time_t: the current time which leases will become relative to
 *  output: void
 */

static void
relativize_time(DHCP_OPT *option, time_t orig_time, time_t current_time)
{
	uint32_t	pkt_time;
	time_t		time_diff = current_time - orig_time;

	if (option == NULL || option->len != sizeof (lease_t))
		return;

	(void) memcpy(&pkt_time, option->value, option->len);
	if (ntohl(pkt_time) != DHCP_PERM)
		pkt_time = htonl(ntohl(pkt_time) - time_diff);

	(void) memcpy(option->value, &pkt_time, option->len);
}

/*
 * relativize_v6(): re-relativizes a time in a DHCPv6 option
 *
 *   input: uint32_t *: the time value to convert
 *	    time_t: the time the leases in the packet are currently relative to
 *	    time_t: the current time which leases will become relative to
 *  output: void
 */

static void
relativize_v6(uint32_t *val, time_t orig_time, time_t current_time)
{
	uint32_t	hval;
	time_t		time_diff = current_time - orig_time;

	hval = ntohl(*val);
	if (hval != DHCPV6_INFTIME) {
		if (hval < time_diff)
			*val = 0;
		else
			*val = htonl(hval - time_diff);
	}
}
