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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * From	"tsol_tndb_parser.c	7.24	01/09/05 SMI; TSOL 2.x"
 *
 * These functions parse entries in the "thrhdb" (remote host database) file.
 * Each entry in the file has two fields, separated by a colon.  The first
 * field is the IP host or network address.  The second is the name of the
 * template to use (from tnrhtp).
 *
 * In order to help preserve sanity, we do not allow more than one unescaped
 * colon in a line.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <libtsnet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <inet/ip.h>
#include <arpa/inet.h>
#include <nss.h>
#include <errno.h>

/*
 * This routine deals with old pre-CIDR subnet address specifications.  In the
 * bad old days, a subnet was represented as:
 *
 *	Expression	Implied Prefix
 *	10.1.1.0	/24
 *	10.1.0.0	/16
 *	10.0.0.0	/8
 *	0.0.0.0		/0
 */
static int
get_classful_prefix(in_addr_t addr)
{
	int bits;

	if (addr == 0)
		return (0);
	addr = ntohl(addr);
	for (bits = IP_ABITS; bits > 0 && (addr & 0xFF) == 0; bits -= 8)
		addr >>= 8;

	return (bits);
}

/*
 * This routine deals with old pre-CIDR network address specifications.  In the
 * bad old days, a network was represented as:
 *
 *	Expression	Implied Prefix
 *	10.1.1		/24
 *	10.1		/16
 *	10		/8
 *
 * This routine must compute the mask and left-align the address.
 */
static int
get_network_prefix(in_addr_t *addrp)
{
	int bits;
	in_addr_t addr;

	addr = ntohl(*addrp);
	for (bits = IP_ABITS; bits > 0 && addr < 0x01000000; bits -= 8)
		addr <<= 8;
	*addrp = htonl(addr);

	return (bits);
}

static boolean_t
parse_address(tsol_rhent_t *rh, const char *addrbuf)
{
	int upper_lim;
	int len;
	const uchar_t *aptr;

	if (strchr(addrbuf, ':') == NULL) {
		/* IPv4 address */
		rh->rh_address.ta_family = AF_INET;
		if (inet_pton(AF_INET, addrbuf,
		    &rh->rh_address.ta_addr_v4) > 0) {
			if (rh->rh_prefix == -1)
				rh->rh_prefix = get_classful_prefix(rh->
				    rh_address.ta_addr_v4.s_addr);
		} else if ((rh->rh_address.ta_addr_v4.s_addr =
		    inet_network(addrbuf)) != (in_addr_t)-1) {
			len = get_network_prefix(&rh->rh_address.ta_addr_v4.
			    s_addr);
			if (rh->rh_prefix == -1)
				rh->rh_prefix = len;
		} else {
			return (B_FALSE);
		}
		upper_lim = IP_ABITS;
		aptr = (const uchar_t *)&rh->rh_address.ta_addr_v4;
	} else {
		/* IPv6 address */
		rh->rh_address.ta_family = AF_INET6;
		if (inet_pton(AF_INET6, addrbuf,
		    &rh->rh_address.ta_addr_v6) <= 0)
			return (B_FALSE);
		if (rh->rh_prefix == -1)
			rh->rh_prefix = IPV6_ABITS;
		upper_lim = IPV6_ABITS;
		aptr = (const uchar_t *)&rh->rh_address.ta_addr_v6;
	}

	if (rh->rh_prefix < 0 || rh->rh_prefix > upper_lim)
		return (B_FALSE);

	/*
	 * Verify that there are no bits set in the "host" portion of the
	 * IP address.
	 */
	len = rh->rh_prefix;
	aptr += len / 8;
	if ((len & 7) != 0) {
		if ((*aptr++ & (0xff >> (len & 7))) != 0)
			return (B_FALSE);
		len = (len + 7) & ~7;
	}
	while (len < upper_lim) {
		if (*aptr++ != 0)
			return (B_FALSE);
		len += 8;
	}

	return (B_TRUE);
}

tsol_rhent_t *
rhstr_to_ent(tsol_rhstr_t *rhstrp, int *errp, char **errstrp)
{
	int		len;
	int		err = 0;
	char		*cp, *cp2, *errstr;
	char		*address = rhstrp->address;
	char		*template = rhstrp->template;
	char		addrbuf[1024];
	tsol_rhent_t	*rhentp = NULL;

	/*
	 * The user can specify NULL pointers for these.  Make sure that we
	 * don't have to deal with checking for NULL everywhere by just
	 * pointing to our own variables if the user gives NULL.
	 */
	if (errp == NULL)
		errp = &err;
	if (errstrp == NULL)
		errstrp = &errstr;
	/* The default, unless we find a more specific error locus. */
	*errstrp = address;

	if (address == NULL || *address == '#' || *address == '\n') {
		*errp = LTSNET_EMPTY;
		if (template && *template != '\0' && *template != '#' &&
		    *template != '\n')
			*errstrp = template;
		else if (address == NULL)
			*errstrp = "   ";
		goto err_ret;
	}
	if (*address == '\0') {
		*errp = LTSNET_NO_ADDR;
		if (template && *template != '\0' && *template != '#' &&
		    *template != '\n')
			*errstrp = template;
		goto err_ret;
	}
	if (template == NULL || *template == '#' || *template == '\n' ||
	    *template == '\0') {
		*errp = LTSNET_NO_HOSTTYPE;
		goto err_ret;
	}
	if ((rhentp = calloc(1, sizeof (*rhentp))) == NULL) {
		*errp = LTSNET_SYSERR;
		return (NULL);
	}
	if ((cp = strrchr(address, '/')) != NULL) {
		len = cp - address;
		if (len >= sizeof (addrbuf)) {
			*errp = LTSNET_ILL_ADDR;
			goto err_ret;
		}
		(void) memset(addrbuf, '\0', sizeof (addrbuf));
		(void) memcpy(addrbuf, address, len);
		cp++;
		errno = 0;
		rhentp->rh_prefix = strtol(cp, &cp2, 0);
		if (errno != 0) {
			*errp = LTSNET_SYSERR;
			*errstrp = cp2;
			goto err_ret;
		}
		if ((isdigit(*cp) == 0)) {
			*errp = LTSNET_ILL_ADDR;
			*errstrp = address;
			goto err_ret;
		}
	} else {
		rhentp->rh_prefix = -1;
		(void) strlcpy(addrbuf, address, sizeof (addrbuf));
	}
	if (strlcpy(rhentp->rh_template, template,
	    sizeof (rhentp->rh_template)) >= sizeof (rhentp->rh_template)) {
		*errstrp = template;
		*errp = LTSNET_ILL_NAME;
		goto err_ret;
	}
	if (!parse_address(rhentp, addrbuf)) {
		*errp = LTSNET_ILL_ADDR;
		*errstrp = address;
		goto err_ret;
	}

#ifdef	DEBUG
	(void) fprintf(stdout, "rhstr_to_ent: %s:%s\n",
	    address, rhentp->rh_template);
#endif	/* DEBUG */

	return (rhentp);

err_ret:
	err = errno;
	tsol_freerhent(rhentp);
	errno = err;
#ifdef	DEBUG
	(void) fprintf(stderr, "\nrhstr_to_ent: %s: %s\n",
	    *errstrp, (char *)tsol_strerror(*errp, errno));
#endif	/* DEBUG */

	return (NULL);
}

void
tsol_freerhent(tsol_rhent_t *rh)
{
	if (rh != NULL)
		free(rh);
}
