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
 */

#include <sys/t_kuser.h>
#include <sys/netconfig.h>
#include <netinet/in.h>
#include <net/route.h>
#include <net/if.h>
#include <sys/kstr.h>
#include <rpc/clnt.h>
#include <sys/stropts.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/bootprops.h>

static int
kivoid_to_sock(int af, void *source, void *dest)
{
	struct sockaddr_in  *sin    =	NULL;
	struct sockaddr_in6 *sin6   =	NULL;

	if (source == NULL || dest == NULL) {
		return (-1);
	}
	if (af == AF_INET) {
		sin = (struct sockaddr_in *)dest;
		(void) bcopy(source, &sin->sin_addr,
		    sizeof (struct in_addr));
		sin->sin_family = af;
	} else if (af == AF_INET6) {
		sin6 = (struct sockaddr_in6 *)dest;
		(void) bcopy(source, &sin6->sin6_addr,
		    sizeof (struct in6_addr));
		sin6->sin6_family = af;
	} else {
		return (-1);
	}
	return (0);
}

int
kdlifconfig(TIUSER *tiptr, int af, void *myIPaddr, void *mymask,
    struct in_addr *mybraddr, struct in_addr *gateway, char *ifname)
{
	int			rc;
	struct netbuf		sbuf;
	struct sockaddr_in	sin;
	struct sockaddr_in6	sin6;
	struct rtentry		route;
	struct sockaddr_in	*rt_sin;

	if (myIPaddr == NULL || mymask == NULL) {
		return (-1);
	}

	if (af == AF_INET) {
		rc = kivoid_to_sock(af, mymask, &sin);
		if (rc != 0) {
			return (rc);
		}
		sbuf.buf = (caddr_t)&sin;
		sbuf.maxlen = sbuf.len = sizeof (sin);
	} else {
		rc = kivoid_to_sock(af, mymask, &sin6);
		if (rc != 0) {
			return (rc);
		}
		sbuf.buf = (caddr_t)&sin6;
		sbuf.maxlen = sbuf.len = sizeof (sin6);
	}
	if (rc = kifioctl(tiptr, SIOCSLIFNETMASK, &sbuf, ifname)) {
		return (rc);
	}

	if (af == AF_INET) {
		rc = kivoid_to_sock(af, myIPaddr, &sin);
		if (rc != 0) {
			return (rc);
		}
		sbuf.buf = (caddr_t)&sin;
		sbuf.maxlen = sbuf.len = sizeof (sin);
	} else {
		rc = kivoid_to_sock(af, myIPaddr, &sin6);
		if (rc != 0) {
			return (rc);
		}
		sbuf.buf = (caddr_t)&sin6;
		sbuf.maxlen = sbuf.len = sizeof (sin6);
	}

	if (rc = kifioctl(tiptr, SIOCSLIFADDR, &sbuf, ifname)) {
		return (rc);
	}
	/*
	 * Only IPv4 has brocadcast address.
	 */
	if (af == AF_INET && mybraddr != NULL) {
		if (mybraddr->s_addr != INADDR_BROADCAST) {
			rc = kivoid_to_sock(af, mybraddr, &sin);
			if (rc != 0) {
				return (rc);
			}
			sbuf.buf = (caddr_t)&sin;
			sbuf.maxlen = sbuf.len = sizeof (sin);
			if (rc = kifioctl(tiptr, SIOCSLIFBRDADDR, &sbuf,
			    ifname)) {
				return (rc);
			}
		}
	}

	/*
	 * Now turn on the interface.
	 */
	if (rc = ksetifflags(tiptr, IFF_UP, ifname)) {
		return (rc);
	}

	/*
	 * Set the default gateway.
	 */
	if (af == AF_INET && gateway != NULL) {
		(void) memset(&route, 0, sizeof (route));
		rt_sin = (struct sockaddr_in *)&route.rt_dst;
		rt_sin->sin_family = AF_INET;

		rt_sin = (struct sockaddr_in *)&route.rt_gateway;
		rt_sin->sin_addr.s_addr = gateway->s_addr;
		route.rt_flags = RTF_GATEWAY | RTF_UP;
		sbuf.buf = (caddr_t)&route;
		sbuf.maxlen = sbuf.len = sizeof (route);
		if (rc = kifioctl(tiptr, SIOCADDRT, &sbuf, ifname)) {
			return (rc);
		}
	}
	return (0);
}

int
kifioctl(TIUSER *tiptr, int cmd, struct netbuf *nbuf, char *ifname)
{
	struct strioctl	    iocb;
	struct lifreq	    lifr;
	vnode_t		    *vp	    =	NULL;
	char		    *buf    =	NULL;
	int		    rc	    =	0;

	(void) memset(&lifr, 0, sizeof (lifr));
	/*
	 * Now do the one requested.
	 */
	if (nbuf->len) {
		if (nbuf->len == sizeof (struct rtentry)) {
			if (cmd != SIOCADDRT) {
				return (-1);
			}
			/*
			 * Set up gateway parameters.
			 */
			iocb.ic_len = nbuf->len;
			iocb.ic_dp = nbuf->buf;
		} else {
			if (nbuf->len != sizeof (struct sockaddr_in) &&
			    nbuf->len != sizeof (struct sockaddr_in6)) {
				return (-1);
			}
			buf = (char *)&lifr.lifr_addr;
			bcopy(nbuf->buf, buf, nbuf->len);
			iocb.ic_len = sizeof (lifr);
			iocb.ic_dp = (caddr_t)&lifr;
		}
	} else {
		iocb.ic_len = sizeof (lifr);
		iocb.ic_dp = (caddr_t)&lifr;
	}
	(void) strncpy((caddr_t)&lifr.lifr_name, ifname,
	    sizeof (lifr.lifr_name));
	iocb.ic_cmd = cmd;
	iocb.ic_timout = 0;

	vp = tiptr->fp->f_vnode;
	rc = kstr_ioctl(vp, I_STR, (intptr_t)&iocb);
	if (rc) {
		return (rc);
	}

	return (0);
}

int
ksetifflags(TIUSER *tiptr, uint_t value, char *ifname)
{
	int rc;
	struct strioctl iocb;
	struct lifreq lifr;

	if (ifname == NULL) {
		return (-1);
	}

	(void) memset(&lifr, 0, sizeof (lifr));

	(void) strncpy((caddr_t)&lifr.lifr_name, ifname,
	    sizeof (lifr.lifr_name));
	iocb.ic_cmd = SIOCGLIFFLAGS;
	iocb.ic_timout = 0;
	iocb.ic_len = sizeof (lifr);
	iocb.ic_dp = (caddr_t)&lifr;
	if (rc = kstr_ioctl(tiptr->fp->f_vnode, I_STR, (intptr_t)&iocb))
		return (rc);

	lifr.lifr_flags |= value;
	iocb.ic_cmd = SIOCSLIFFLAGS;
	return (kstr_ioctl(tiptr->fp->f_vnode, I_STR, (intptr_t)&iocb));
}
