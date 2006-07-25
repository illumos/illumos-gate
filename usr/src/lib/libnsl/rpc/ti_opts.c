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
 */

/* Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */
/*
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "mt.h"
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <inttypes.h>
#include <sys/types.h>
#include <tiuser.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/sockio.h>
#include <rpc/rpc.h>
#include <sys/tl.h>
#include <sys/stropts.h>
#include <errno.h>
#include <libintl.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <ucred.h>
#include <alloca.h>
#include <stdlib.h>
#include <zone.h>
#include <tsol/label.h>

extern bool_t __svc_get_door_ucred(const SVCXPRT *, ucred_t *);

/*
 * This routine is typically called on the server side if the server
 * wants to know the caller ucred.  Called typically by rpcbind.  It
 * depends upon the t_optmgmt call to local transport driver so that
 * return the uid value in options in T_CONN_IND, T_CONN_CON and
 * T_UNITDATA_IND.
 * With the advent of the credential in the mblk, this is simply
 * extended to all transports when the packet travels over the
 * loopback network; for UDP we use a special socket option and for
 * tcp we don't need to do any setup, we just call getpeerucred()
 * later.
 */

/*
 * Version for Solaris with new local transport code and ucred.
 */
int
__rpc_negotiate_uid(int fd)
{
	struct strioctl strioc;
	unsigned int set = 1;

	/* For tcp we use getpeerucred and it needs no initialization. */
	if (ioctl(fd, I_FIND, "tcp") > 0)
		return (0);

	strioc.ic_cmd = TL_IOC_UCREDOPT;
	strioc.ic_timout = -1;
	strioc.ic_len = (int)sizeof (unsigned int);
	strioc.ic_dp = (char *)&set;

	if (ioctl(fd, I_STR, &strioc) == -1 &&
	    __rpc_tli_set_options(fd, SOL_SOCKET, SO_RECVUCRED, 1) == -1) {
		syslog(LOG_ERR, "rpc_negotiate_uid (%s): %m",
		    "ioctl:I_STR:TL_IOC_UCREDOPT/SO_RECVUCRED");
		return (-1);
	}
	return (0);
}

void
svc_fd_negotiate_ucred(int fd)
{
	(void) __rpc_negotiate_uid(fd);
}


/*
 * This returns the ucred of the caller.  It assumes that the optbuf
 * information is stored at xprt->xp_p2.
 * There are three distinct cases: the option buffer is headed
 * with a "struct opthdr" and the credential option is the only
 * one, or it's a T_opthdr and our option may follow others; or there
 * are no options and we attempt getpeerucred().
 */
static int
find_ucred_opt(const SVCXPRT *trans, ucred_t *uc, bool_t checkzone)
{
	/* LINTED pointer alignment */
	struct netbuf *abuf = (struct netbuf *)trans->xp_p2;
	char *bufp, *maxbufp;
	struct opthdr *opth;
	static zoneid_t myzone = MIN_ZONEID - 1;	/* invalid */

	if (abuf == NULL || abuf->buf == NULL) {
		if (getpeerucred(trans->xp_fd, &uc) == 0)
			goto verifyzone;
		return (-1);
	}

#ifdef RPC_DEBUG
	syslog(LOG_INFO, "find_ucred_opt %p %x", abuf->buf, abuf->len);
#endif
	/* LINTED pointer cast */
	opth = (struct opthdr *)abuf->buf;
	if (opth->level == TL_PROT_LEVEL &&
	    opth->name == TL_OPT_PEER_UCRED &&
	    opth->len + sizeof (*opth) == abuf->len) {
#ifdef RPC_DEBUG
		syslog(LOG_INFO, "find_ucred_opt (opthdr): OK!");
#endif
		(void) memcpy(uc, &opth[1], opth->len);
		/*
		 * Always from inside our zone because zones use a separate name
		 * space for loopback; at this time, the kernel may send a
		 * packet pretending to be from the global zone when it's
		 * really from our zone so we skip the zone check.
		 */
		return (0);
	}

	bufp = abuf->buf;
	maxbufp = bufp + abuf->len;

	while (bufp + sizeof (struct T_opthdr) < maxbufp) {
		/* LINTED pointer cast */
		struct T_opthdr *opt = (struct T_opthdr *)bufp;

#ifdef RPC_DEBUG
		syslog(LOG_INFO, "find_ucred_opt opt: %p %x, %d %d", opt,
			opt->len, opt->name, opt->level);
#endif
		if (opt->len > maxbufp - bufp || (opt->len & 3))
			return (-1);
		if (opt->level == SOL_SOCKET && opt->name == SCM_UCRED &&
		    opt->len - sizeof (struct T_opthdr) <= ucred_size()) {
#ifdef RPC_DEBUG
			syslog(LOG_INFO, "find_ucred_opt (T_opthdr): OK!");
#endif
			(void) memcpy(uc, &opt[1],
			    opt->len - sizeof (struct T_opthdr));
			goto verifyzone;
		}
		bufp += opt->len;
	}
	if (getpeerucred(trans->xp_fd, &uc) != 0)
		return (-1);
verifyzone:
	if (!checkzone)
		return (0);

	if (myzone == MIN_ZONEID - 1)
		myzone = getzoneid();

	/* Return 0 only for the local zone */
	return (ucred_getzoneid(uc) == myzone ? 0 : -1);
}

/*
 * Version for Solaris with new local transport code
 */
int
__rpc_get_local_uid(SVCXPRT *trans, uid_t *uid_out)
{
	ucred_t *uc = alloca(ucred_size());
	int err;

	/* LINTED - pointer alignment */
	if (svc_type(trans) == SVC_DOOR)
		err = __svc_get_door_ucred(trans, uc) == FALSE;
	else
		err = find_ucred_opt(trans, uc, B_TRUE);

	if (err != 0)
		return (-1);
	*uid_out = ucred_geteuid(uc);
	return (0);
}

/*
 * Return local credentials.
 */
bool_t
__rpc_get_local_cred(SVCXPRT *xprt, svc_local_cred_t *lcred)
{
	ucred_t *uc = alloca(ucred_size());
	int err;

	/* LINTED - pointer alignment */
	if (svc_type(xprt) == SVC_DOOR)
		err = __svc_get_door_ucred(xprt, uc) == FALSE;
	else
		err = find_ucred_opt(xprt, uc, B_TRUE);

	if (err != 0)
		return (FALSE);

	lcred->euid = ucred_geteuid(uc);
	lcred->egid = ucred_getegid(uc);
	lcred->ruid = ucred_getruid(uc);
	lcred->rgid = ucred_getrgid(uc);
	lcred->pid = ucred_getpid(uc);
	return (TRUE);
}

/*
 * Return local ucred.
 */
int
svc_getcallerucred(const SVCXPRT *trans, ucred_t **uc)
{
	ucred_t *ucp = *uc;
	int err;

	if (ucp == NULL) {
		ucp = malloc(ucred_size());
		if (ucp == NULL)
			return (-1);
	}

	/* LINTED - pointer alignment */
	if (svc_type(trans) == SVC_DOOR)
		err = __svc_get_door_ucred(trans, ucp) == FALSE;
	else
		err = find_ucred_opt(trans, ucp, B_FALSE);

	if (err != 0) {
		if (*uc == NULL)
			free(ucp);
		return (-1);
	}

	if (*uc == NULL)
		*uc = ucp;

	return (0);
}


/*
 * get local ip address
 */
int
__rpc_get_ltaddr(struct netbuf *nbufp, struct netbuf *ltaddr)
{
	unsigned int total_optlen;
	struct T_opthdr *opt, *opt_start = NULL, *opt_end;
	struct sockaddr_in *ipv4sa;
	struct sockaddr_in6 *ipv6sa;
	int s;
	struct sioc_addrreq areq;

	if (nbufp == (struct netbuf *)0 || ltaddr == (struct netbuf *)0) {
		t_errno = TBADOPT;
		return (-1);
	}

	total_optlen = nbufp->len;
	if (total_optlen == 0)
		return (1);

	/* LINTED pointer alignment */
	opt_start = (struct T_opthdr *)nbufp->buf;
	if (opt_start == NULL) {
		t_errno = TBADOPT;
		return (-1);
	}

	/* Make sure the start of the buffer is aligned */
	if (!(__TPI_TOPT_ISALIGNED(opt_start))) {
		t_errno = TBADOPT;
		return (-1);
	}

	/* LINTED pointer alignment */
	opt_end = (struct T_opthdr *)((uchar_t *)opt_start + total_optlen);
	opt = opt_start;

	/*
	 * Look for the desired option header
	 */
	do {
		if (((uchar_t *)opt + sizeof (struct T_opthdr)) >
		    (uchar_t *)opt_end) {
			t_errno = TBADOPT;
			return (-1);
		}
		if (opt->len < sizeof (struct T_opthdr)) {
			t_errno = TBADOPT;
			return (-1);
		}
		if (((uchar_t *)opt + opt->len) > (uchar_t *)opt_end) {
			t_errno = TBADOPT;
			return (-1);
		}
		switch (opt->level) {
		case IPPROTO_IP:
			if (opt->name == IP_RECVDSTADDR) {
				struct sockaddr_in v4tmp;

				opt++;
				if (((uchar_t *)opt + sizeof (struct in_addr)) >
				    (uchar_t *)opt_end) {
					t_errno = TBADOPT;
					return (-1);
				}
				bzero(&v4tmp, sizeof (v4tmp));
				v4tmp.sin_family = AF_INET;
				v4tmp.sin_addr = *(struct in_addr *)opt;
#ifdef RPC_DEBUG
				{
				struct in_addr ia;
				char str[INET_ADDRSTRLEN];

				ia = *(struct in_addr *)opt;
				(void) inet_ntop(AF_INET, &ia,
						str, sizeof (str));
				syslog(LOG_INFO,
				    "__rpc_get_ltaddr for IP_RECVDSTADDR: %s",
					str);
				}
#endif
				if ((s = open("/dev/udp", O_RDONLY)) < 0) {
#ifdef RPC_DEBUG
					syslog(LOG_ERR, "__rpc_get_ltaddr: "
					    "dev udp open failed");
#endif
					return (1);
				}

				(void) memcpy(&areq.sa_addr, &v4tmp,
								sizeof (v4tmp));
				areq.sa_res = -1;
				if (ioctl(s, SIOCTMYADDR, (caddr_t)&areq) < 0) {
					syslog(LOG_ERR,
					    "get_ltaddr:ioctl for udp failed");
					(void) close(s);
					return (1);
				}
				(void) close(s);
				if (areq.sa_res == 1) {
				    /* LINTED pointer cast */
				    ipv4sa = (struct sockaddr_in *)ltaddr->buf;
				    ipv4sa->sin_family = AF_INET;
				    ipv4sa->sin_addr = *(struct in_addr *)opt;
				    return (0);
				} else
				    return (1);

			}
			break;
		case IPPROTO_IPV6:
			if (opt->name == IPV6_PKTINFO) {
				struct sockaddr_in6 v6tmp;
				opt++;
				if (((uchar_t *)opt +
				    sizeof (struct in6_pktinfo)) >
				    (uchar_t *)opt_end) {
					t_errno = TBADOPT;
					return (-1);
				}
				bzero(&v6tmp, sizeof (v6tmp));
				v6tmp.sin6_family = AF_INET6;
				v6tmp.sin6_addr =
					((struct in6_pktinfo *)opt)->ipi6_addr;
#ifdef RPC_DEBUG
				{
				struct in6_pktinfo *in6_pkt;
				char str[INET6_ADDRSTRLEN];

				in6_pkt = (struct in6_pktinfo *)opt;
				(void) inet_ntop(AF_INET6, &in6_pkt->ipi6_addr,
						str, sizeof (str));
				syslog(LOG_INFO,
					"__rpc_get_ltaddr for IPV6_PKTINFO: %s",
					str);
				}
#endif
				if ((s = open("/dev/udp6", O_RDONLY)) < 0) {
#ifdef RPC_DEBUG
					syslog(LOG_ERR, "__rpc_get_ltaddr: "
					    "dev udp6 open failed");
#endif
					return (1);
				}

				(void) memcpy(&areq.sa_addr, &v6tmp,
								sizeof (v6tmp));
				areq.sa_res = -1;
				if (ioctl(s, SIOCTMYADDR, (caddr_t)&areq) < 0) {
					syslog(LOG_ERR,
					    "get_ltaddr:ioctl for udp6 failed");
					(void) close(s);
					return (1);
				}
				(void) close(s);
				if (areq.sa_res == 1) {
				    /* LINTED pointer cast */
				    ipv6sa = (struct sockaddr_in6 *)ltaddr->buf;
				    ipv6sa->sin6_family = AF_INET6;
				    ipv6sa->sin6_addr =
					((struct in6_pktinfo *)opt)->ipi6_addr;

				    return (0);
				} else
				    return (1);
			}
			break;
		default:
			break;
		}
		/* LINTED improper alignment */
		opt = (struct T_opthdr *)((uchar_t *)opt +
			    __TPI_ALIGN(opt->len));
	} while (opt < opt_end);
	return (1);
}

#define	__TRANSPORT_INDSZ	128

int
__rpc_tli_set_options(int fd, int optlevel, int optname, int optval)
{
	struct t_optmgmt oreq, ores;
	struct opthdr *topt;
	int *ip;
	int optsz;
	char buf[__TRANSPORT_INDSZ];


	switch (optname) {
	case SO_DONTLINGER: {
		struct linger *ling;
		/* LINTED */
		ling = (struct linger *)
			(buf + sizeof (struct opthdr));
		ling->l_onoff = 0;
		optsz = sizeof (struct linger);
		break;
	}

	case SO_LINGER: {
		struct linger *ling;
		/* LINTED */
		ling = (struct linger *)
			(buf + sizeof (struct opthdr));
		ling->l_onoff = 1;
		ling->l_linger = (int)optval;
		optsz = sizeof (struct linger);
		break;
	}
	case IP_RECVDSTADDR:
	case IPV6_RECVPKTINFO:
	case SO_DEBUG:
	case SO_KEEPALIVE:
	case SO_DONTROUTE:
	case SO_USELOOPBACK:
	case SO_REUSEADDR:
	case SO_DGRAM_ERRIND:
	case SO_RECVUCRED:
	case SO_ANON_MLP:
	case SO_MAC_EXEMPT:
	case SO_EXCLBIND:
	case TCP_EXCLBIND:
	case UDP_EXCLBIND:
		/* LINTED */
		ip = (int *)(buf + sizeof (struct opthdr));
		*ip = optval;
		optsz = sizeof (int);
		break;
	default:
		return (-1);
	}

	/* LINTED */
	topt = (struct opthdr *)buf;
	topt->level =  optlevel;
	topt->name = optname;
	topt->len = optsz;
	oreq.flags = T_NEGOTIATE;
	oreq.opt.len = sizeof (struct opthdr) + optsz;
	oreq.opt.buf = buf;

	ores.flags = 0;
	ores.opt.buf = buf;
	ores.opt.maxlen = __TRANSPORT_INDSZ;
	if (t_optmgmt(fd, &oreq, &ores) < 0 ||
	    ores.flags != T_SUCCESS) {
		return (-1);
	}
	return (0);
}

/*
 * Format an error message corresponding to the given TLI and system error
 * codes.
 */

void
__tli_sys_strerror(char *buf, size_t buflen, int tli_err, int sys_err)
{
	char *errorstr;

	if (tli_err == TSYSERR) {
		errorstr = strerror(sys_err);
		if (errorstr == NULL)
			(void) snprintf(buf, buflen,
					dgettext(__nsl_dom,
						"Unknown system error %d"),
					sys_err);
		else
			(void) strlcpy(buf, errorstr, buflen);
	} else {
		errorstr = t_strerror(tli_err);
		(void) strlcpy(buf, errorstr, buflen);
	}
}

/*
 * Depending on the specified RPC number, attempt to set mac_exempt
 * option on the opened socket; these requests need to be able to do MAC
 * MAC read-down operations.  Privilege is needed to set this option.
 */

void
__rpc_set_mac_options(int fd, const struct netconfig *nconf, rpcprog_t prognum)
{
	int ret = 0;

	if (!is_system_labeled())
		return;

	if (strcmp(nconf->nc_protofmly, NC_INET) != 0 &&
	    strcmp(nconf->nc_protofmly, NC_INET6) != 0)
		return;

	if (is_multilevel(prognum)) {
		ret = __rpc_tli_set_options(fd, SOL_SOCKET, SO_MAC_EXEMPT, 1);
		if (ret < 0) {
			char errorstr[100];

			__tli_sys_strerror(errorstr, sizeof (errorstr),
			    t_errno, errno);
			(void) syslog(LOG_ERR, "rpc_set_mac_options: %s",
			    errorstr);
		}
	}
}
