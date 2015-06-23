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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* SVr4.0 1.1 */

/*
 * Miscellaneous support routines for kernel implementation of RPC.
 */

#include <sys/param.h>
#include <sys/t_lock.h>
#include <sys/user.h>
#include <sys/vnode.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strsubr.h>
#include <sys/socket.h>
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/tiuser.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/sdt.h>
#include <netinet/in.h>
#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpcb_prot.h>
#include <rpc/pmap_prot.h>

static int strtoi(char *, char **);
static void grow_netbuf(struct netbuf *, size_t);
static void loopb_u2t(const char *, struct netbuf *);

#define	RPC_PMAP_TIMEOUT	15
/*
 * define for max length of an ip address and port address, the value was
 * calculated using INET6_ADDRSTRLEN (46) + max port address (12) +
 * seperator "."'s in port address (2) + null (1) = 61.
 * Then there is IPV6_TOKEN_LEN which is 64, so the value is 64 to be safe.
 */
#define	RPC_MAX_IP_LENGTH	64

/*
 * Kernel level debugging aid. The global variable "rpclog" is a bit
 * mask which allows various types of debugging messages to be printed
 * out.
 *
 *	rpclog & 1 	will cause actual failures to be printed.
 *	rpclog & 2	will cause informational messages to be
 *			printed on the client side of rpc.
 *	rpclog & 4	will cause informational messages to be
 *			printed on the server side of rpc.
 *	rpclog & 8	will cause informational messages for rare events to be
 *			printed on the client side of rpc.
 *	rpclog & 16	will cause informational messages for rare events to be
 *			printed on the server side of rpc.
 *	rpclog & 32	will cause informational messages for rare events to be
 *			printed on the common client/server code paths of rpc.
 *	rpclog & 64	will cause informational messages for manipulation
 *			client-side COTS dispatch list to be printed.
 */

uint_t rpclog = 0;


void
rpc_poptimod(vnode_t *vp)
{
	int error, isfound, ret;

	error = strioctl(vp, I_FIND, (intptr_t)"timod", 0, K_TO_K, kcred,
	    &isfound);
	if (error) {
		RPCLOG(1, "rpc_poptimod: I_FIND strioctl error %d\n", error);
		return;
	}
	if (isfound) {
		/*
		 * Pop timod module
		 */
		error = strioctl(vp, I_POP, 0, 0, K_TO_K, kcred, &ret);
		if (error) {
			RPCLOG(1, "rpc_poptimod: I_POP strioctl error %d\n",
			    error);
			return;
		}
	}
}

/*
 * Check the passed in ip address for correctness (limited) and return its
 * type.
 *
 * an ipv4 looks like this:
 * "IP.IP.IP.IP.PORT[top byte].PORT[bottom byte]"
 *
 * an ipv6 looks like this:
 * fec0:A02::2:202:4FCD
 * or
 * ::10.9.2.1
 */
int
rpc_iptype(
	char	*ipaddr,
	int	*typeval)
{
	char	*cp;
	int	chcnt = 0;
	int	coloncnt = 0;
	int	dotcnt = 0;
	int	numcnt = 0;
	int	hexnumcnt = 0;
	int	othercnt = 0;

	cp = ipaddr;

	/* search for the different type of characters in the ip address */
	while ((*cp != '\0') && (chcnt < RPC_MAX_IP_LENGTH)) {
		switch (*cp) {
		case ':':
			coloncnt++;
			break;
		case '.':
			dotcnt++;
			break;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			numcnt++;
			break;
		case 'a':
		case 'A':
		case 'b':
		case 'B':
		case 'c':
		case 'C':
		case 'd':
		case 'D':
		case 'e':
		case 'E':
		case 'f':
		case 'F':
			hexnumcnt++;
			break;
		default:
			othercnt++;
			break;
		}
		chcnt++;
		cp++;
	}

	/* check for bad ip strings */
	if ((chcnt == RPC_MAX_IP_LENGTH) || (othercnt))
		return (-1);

	/* if we have a coloncnt, it can only be an ipv6 address */
	if (coloncnt) {
		if ((coloncnt < 2) || (coloncnt > 7))
			return (-1);

		*typeval = AF_INET6;
	} else {
		/* since there are no colons, make sure it is ipv4 */
		if ((hexnumcnt) || (dotcnt != 5))
			return (-1);

		*typeval = AF_INET;
	}
	return (0);
}

/*
 * Return a port number from a sockaddr_in expressed in universal address
 * format.  Note that this routine does not work for address families other
 * than INET.  Eventually, we should replace this routine with one that
 * contacts the rpcbind running locally.
 */
int
rpc_uaddr2port(int af, char *addr)
{
	int p1;
	int p2;
	char *next, *p;

	if (af == AF_INET) {
		/*
		 * A struct sockaddr_in expressed in universal address
		 * format looks like:
		 *
		 *	"IP.IP.IP.IP.PORT[top byte].PORT[bottom byte]"
		 *
		 * Where each component expresses as a character,
		 * the corresponding part of the IP address
		 * and port number.
		 * Thus 127.0.0.1, port 2345 looks like:
		 *
		 *	49 50 55 46 48 46 48 46 49 46 57 46 52 49
		 *	1  2  7  .  0  .  0  .  1  .  9  .  4  1
		 *
		 * 2345 = 929base16 = 9.32+9 = 9.41
		 */
		(void) strtoi(addr, &next);
		(void) strtoi(next, &next);
		(void) strtoi(next, &next);
		(void) strtoi(next, &next);
		p1 = strtoi(next, &next);
		p2 = strtoi(next, &next);

	} else if (af == AF_INET6) {
		/*
		 * An IPv6 address is expressed in following two formats
		 * fec0:A02::2:202:4FCD or
		 * ::10.9.2.1
		 * An universal address will have porthi.portlo appended to
		 * v6 address. So always look for the last two dots when
		 * extracting port number.
		 */
		next = addr;
		while (next = strchr(next, '.')) {
			p = ++next;
			next = strchr(next, '.');
			next++;
		}
		p1 = strtoi(p, &p);
		p2 = strtoi(p, &p);
		RPCLOG(1, "rpc_uaddr2port: IPv6 port %d\n", ((p1 << 8) + p2));
	}

	return ((p1 << 8) + p2);
}

/*
 * Modified strtol(3).  Should we be using mi_strtol() instead?
 */
static int
strtoi(char *str, char **ptr)
{
	int c;
	int val;

	for (val = 0, c = *str++; c >= '0' && c <= '9'; c = *str++) {
		val *= 10;
		val += c - '0';
	}
	*ptr = str;
	return (val);
}

/*
 * Utilities for manipulating netbuf's.
 *
 * Note that loopback addresses are not null-terminated, so these utilities
 * typically use the strn* string routines.
 */

/*
 * Utilities to patch a port number (for NC_INET protocols) or a
 *	port name (for NC_LOOPBACK) into a network address.
 */


/*
 * PSARC 2003/523 Contract Private Interface
 * put_inet_port
 * Changes must be reviewed by Solaris File Sharing
 * Changes must be communicated to contract-2003-523@sun.com
 */
void
put_inet_port(struct netbuf *addr, ushort_t port)
{
	/*
	 * Easy - we always patch an unsigned short on top of an
	 * unsigned short.  No changes to addr's len or maxlen are
	 * necessary.
	 */
	((struct sockaddr_in *)(addr->buf))->sin_port = port;
}

void
put_inet6_port(struct netbuf *addr, ushort_t port)
{
	((struct sockaddr_in6 *)(addr->buf))->sin6_port = port;
}

void
put_loopback_port(struct netbuf *addr, char *port)
{
	char *dot;
	char *newbuf;
	int newlen;


	/*
	 * We must make sure the addr has enough space for us,
	 * patch in `port', and then adjust addr's len and maxlen
	 * to reflect the change.
	 */
	if ((dot = strnrchr(addr->buf, '.', addr->len)) == (char *)NULL)
		return;

	newlen = (int)((dot - addr->buf + 1) + strlen(port));
	if (newlen > addr->maxlen) {
		newbuf = kmem_zalloc(newlen, KM_SLEEP);
		bcopy(addr->buf, newbuf, addr->len);
		kmem_free(addr->buf, addr->maxlen);
		addr->buf = newbuf;
		addr->len = addr->maxlen = newlen;
		dot = strnrchr(addr->buf, '.', addr->len);
	} else {
		addr->len = newlen;
	}

	(void) strncpy(++dot, port, strlen(port));
}

/*
 * Convert a loopback universal address to a loopback transport address.
 */
static void
loopb_u2t(const char *ua, struct netbuf *addr)
{
	size_t stringlen = strlen(ua) + 1;
	const char *univp;		/* ptr into universal addr */
	char *transp;			/* ptr into transport addr */

	/* Make sure the netbuf will be big enough. */
	if (addr->maxlen < stringlen) {
		grow_netbuf(addr, stringlen);
	}

	univp = ua;
	transp = addr->buf;
	while (*univp != NULL) {
		if (*univp == '\\' && *(univp+1) == '\\') {
			*transp = '\\';
			univp += 2;
		} else if (*univp == '\\') {
			/* octal character */
			*transp = (((*(univp+1) - '0') & 3) << 6) +
			    (((*(univp+2) - '0') & 7) << 3) +
			    ((*(univp+3) - '0') & 7);
			univp += 4;
		} else {
			*transp = *univp;
			univp++;
		}
		transp++;
	}

	addr->len = (unsigned int)(transp - addr->buf);
	ASSERT(addr->len <= addr->maxlen);
}

/*
 * Make sure the given netbuf has a maxlen at least as big as the given
 * length.
 */
static void
grow_netbuf(struct netbuf *nb, size_t length)
{
	char *newbuf;

	if (nb->maxlen >= length)
		return;

	newbuf = kmem_zalloc(length, KM_SLEEP);
	bcopy(nb->buf, newbuf, nb->len);
	kmem_free(nb->buf, nb->maxlen);
	nb->buf = newbuf;
	nb->maxlen = (unsigned int)length;
}

/*
 * XXX: xdr_pmap is here, because it's the only XDR function
 * of portmap protocol. If there'll be more portmap functions,
 * it would be better to put them to a separate file.
 */
bool_t
xdr_pmap(XDR *xdrs, PMAP *objp)
{
	if (!xdr_rpcprog(xdrs, &objp->pm_prog))
		return (FALSE);
	if (!xdr_rpcvers(xdrs, &objp->pm_vers))
		return (FALSE);
	if (!xdr_rpcprot(xdrs, &objp->pm_prot))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->pm_port))
		return (FALSE);

	return (TRUE);
}

/*
 * Get remote port via PORTMAP protocol version 2 (works for IPv4 only)
 * according to RFC 1833, section 3.
 */
static enum clnt_stat
portmap_getport(struct knetconfig *config, rpcprog_t prog, rpcvers_t vers,
    struct netbuf *addr, struct timeval tmo)
{
	enum clnt_stat status;
	CLIENT *client = NULL;
	k_sigset_t oldmask;
	k_sigset_t newmask;
	ushort_t port = 0;
	struct pmap parms;

	ASSERT(strcmp(config->knc_protofmly, NC_INET) == 0);

	bzero(&parms, sizeof (parms));
	parms.pm_prog = prog;
	parms.pm_vers = vers;
	if (strcmp(config->knc_proto, NC_TCP) == 0) {
		parms.pm_prot = IPPROTO_TCP;
	} else { /*  NC_UDP */
		parms.pm_prot = IPPROTO_UDP;
	}


	/*
	 * Mask all signals before doing RPC network operations
	 * in the same way rpcbind_getaddr() does (see comments
	 * there).
	 */
	sigfillset(&newmask);
	sigreplace(&newmask, &oldmask);

	if (clnt_tli_kcreate(config, addr, PMAPPROG,
	    PMAPVERS, 0, 0, CRED(), &client)) {
		sigreplace(&oldmask, (k_sigset_t *)NULL);
		return (RPC_TLIERROR);
	}

	client->cl_nosignal = 1;
	status = CLNT_CALL(client, PMAPPROC_GETPORT,
	    xdr_pmap, (char *)&parms,
	    xdr_u_short, (char *)&port, tmo);

	sigreplace(&oldmask, (k_sigset_t *)NULL);
	if (status != RPC_SUCCESS)
		goto out;
	if (port == 0) {
		status = RPC_PROGNOTREGISTERED;
		goto out;
	}

	put_inet_port(addr, ntohs(port));

out:
	auth_destroy(client->cl_auth);
	clnt_destroy(client);

	return (status);
}

/*
 * Try to get the address for the desired service by using the rpcbind
 * protocol.  Ignores signals.  If addr is a loopback address, it is
 * expected to be initialized to "localhost.".
 * rpcbind_getaddr() is able to work with RPCBIND protocol version 3 and 4
 * and PORTMAP protocol version 2.
 * It tries version 4 at first, then version 3 and finally (if both failed)
 * it tries portmapper protocol version 2.
 */
enum clnt_stat
rpcbind_getaddr(struct knetconfig *config, rpcprog_t prog, rpcvers_t vers,
    struct netbuf *addr)
{
	char *ua = NULL;
	enum clnt_stat status;
	RPCB parms;
	struct timeval tmo;
	k_sigset_t oldmask;
	k_sigset_t newmask;
	ushort_t port;
	int iptype;
	rpcvers_t rpcbv;

	/*
	 * Call rpcbind (local or remote) to get an address we can use
	 * in an RPC client handle.
	 */
	tmo.tv_sec = RPC_PMAP_TIMEOUT;
	tmo.tv_usec = 0;
	parms.r_prog = prog;
	parms.r_vers = vers;
	parms.r_addr = parms.r_owner = "";

	if (strcmp(config->knc_protofmly, NC_INET) == 0) {
		put_inet_port(addr, htons(PMAPPORT));

		if (strcmp(config->knc_proto, NC_TCP) == 0)
			parms.r_netid = "tcp";
		else
			parms.r_netid = "udp";

	} else if (strcmp(config->knc_protofmly, NC_INET6) == 0) {
		if (strcmp(config->knc_proto, NC_TCP) == 0)
			parms.r_netid = "tcp6";
		else
			parms.r_netid = "udp6";
		put_inet6_port(addr, htons(PMAPPORT));
	} else if (strcmp(config->knc_protofmly, NC_LOOPBACK) == 0) {
		ASSERT(strnrchr(addr->buf, '.', addr->len) != NULL);
		if (config->knc_semantics == NC_TPI_COTS_ORD)
			parms.r_netid = "ticotsord";
		else if (config->knc_semantics == NC_TPI_COTS)
			parms.r_netid = "ticots";
		else
			parms.r_netid = "ticlts";

		put_loopback_port(addr, "rpc");
	} else {
		status = RPC_UNKNOWNPROTO;
		goto out;
	}

	/*
	 * Try RPCBIND versions 4 and 3 (if 4 fails).
	 */
	for (rpcbv = RPCBVERS4; rpcbv >= RPCBVERS; rpcbv--) {
		CLIENT *client = NULL;

		if (ua != NULL) {
			xdr_free(xdr_wrapstring, (char *)&ua);
			ua = NULL;
		}

		/*
		 * Mask signals for the duration of the handle creation and
		 * RPC calls.  This allows relatively normal operation with a
		 * signal already posted to our thread (e.g., when we are
		 * sending an NLM_CANCEL in response to catching a signal).
		 *
		 * Any further exit paths from this routine must restore
		 * the original signal mask.
		 */
		sigfillset(&newmask);
		sigreplace(&newmask, &oldmask);

		if (clnt_tli_kcreate(config, addr, RPCBPROG,
		    rpcbv, 0, 0, CRED(), &client)) {
			status = RPC_TLIERROR;
			sigreplace(&oldmask, (k_sigset_t *)NULL);
			continue;
		}

		client->cl_nosignal = 1;
		status = CLNT_CALL(client, RPCBPROC_GETADDR,
		    xdr_rpcb, (char *)&parms,
		    xdr_wrapstring, (char *)&ua, tmo);

		sigreplace(&oldmask, (k_sigset_t *)NULL);
		auth_destroy(client->cl_auth);
		clnt_destroy(client);

		if (status == RPC_SUCCESS) {
			if (ua == NULL || *ua == NULL) {
				status = RPC_PROGNOTREGISTERED;
				continue;
			}

			break;
		}
	}
	if (status != RPC_SUCCESS)
		goto try_portmap;

	/*
	 * Convert the universal address to the transport address.
	 * Theoretically, we should call the local rpcbind to translate
	 * from the universal address to the transport address, but it gets
	 * complicated (e.g., there's no direct way to tell rpcbind that we
	 * want an IP address instead of a loopback address).  Note that
	 * the transport address is potentially host-specific, so we can't
	 * just ask the remote rpcbind, because it might give us the wrong
	 * answer.
	 */
	if (strcmp(config->knc_protofmly, NC_INET) == 0) {
		/* make sure that the ip address is the correct type */
		if (rpc_iptype(ua, &iptype) != 0) {
			status = RPC_UNKNOWNADDR;
			goto try_portmap;
		}
		port = rpc_uaddr2port(iptype, ua);
		put_inet_port(addr, ntohs(port));
	} else if (strcmp(config->knc_protofmly, NC_INET6) == 0) {
		/* make sure that the ip address is the correct type */
		if (rpc_iptype(ua, &iptype) != 0) {
			status = RPC_UNKNOWNADDR;
			goto try_portmap;
		}
		port = rpc_uaddr2port(iptype, ua);
		put_inet6_port(addr, ntohs(port));
	} else if (strcmp(config->knc_protofmly, NC_LOOPBACK) == 0) {
		loopb_u2t(ua, addr);
	} else {
		/* "can't happen" - should have been checked for above */
		cmn_err(CE_PANIC, "rpcbind_getaddr: bad protocol family");
	}

try_portmap:
	if (status != RPC_SUCCESS &&
	    strcmp(config->knc_protofmly, NC_INET) == 0) {
		/*
		 * For IPv4 try to get remote port via PORTMAP protocol.
		 * NOTE: if we're here, then all attempts to get remote
		 * port via RPCBIND protocol failed.
		 */

		DTRACE_PROBE1(try__portmap, enum clnt_stat, status);
		status = portmap_getport(config, prog, vers, addr, tmo);
	}

out:
	if (ua != NULL)
		xdr_free(xdr_wrapstring, (char *)&ua);
	return (status);
}

static const char *tpiprims[] = {
	"T_CONN_REQ      0        connection request",
	"T_CONN_RES      1        connection response",
	"T_DISCON_REQ    2        disconnect request",
	"T_DATA_REQ      3        data request",
	"T_EXDATA_REQ    4        expedited data request",
	"T_INFO_REQ      5        information request",
	"T_BIND_REQ      6        bind request",
	"T_UNBIND_REQ    7        unbind request",
	"T_UNITDATA_REQ  8        unitdata request",
	"T_OPTMGMT_REQ   9        manage options req",
	"T_ORDREL_REQ    10       orderly release req",
	"T_CONN_IND      11       connection indication",
	"T_CONN_CON      12       connection confirmation",
	"T_DISCON_IND    13       disconnect indication",
	"T_DATA_IND      14       data indication",
	"T_EXDATA_IND    15       expeditied data indication",
	"T_INFO_ACK      16       information acknowledgment",
	"T_BIND_ACK      17       bind acknowledment",
	"T_ERROR_ACK     18       error acknowledgment",
	"T_OK_ACK        19       ok acknowledgment",
	"T_UNITDATA_IND  20       unitdata indication",
	"T_UDERROR_IND   21       unitdata error indication",
	"T_OPTMGMT_ACK   22       manage options ack",
	"T_ORDREL_IND    23       orderly release ind"
};


const char *
rpc_tpiprim2name(uint_t prim)
{
	if (prim > (sizeof (tpiprims) / sizeof (tpiprims[0]) - 1))
		return ("unknown primitive");

	return (tpiprims[prim]);
}

static const char *tpierrs[] = {
	"error zero      0",
	"TBADADDR        1        incorrect addr format",
	"TBADOPT         2        incorrect option format",
	"TACCES          3        incorrect permissions",
	"TBADF           4        illegal transport fd",
	"TNOADDR         5        couldn't allocate addr",
	"TOUTSTATE       6        out of state",
	"TBADSEQ         7        bad call sequnce number",
	"TSYSERR         8        system error",
	"TLOOK           9        event requires attention",
	"TBADDATA        10       illegal amount of data",
	"TBUFOVFLW       11       buffer not large enough",
	"TFLOW           12       flow control",
	"TNODATA         13       no data",
	"TNODIS          14       discon_ind not found on q",
	"TNOUDERR        15       unitdata error not found",
	"TBADFLAG        16       bad flags",
	"TNOREL          17       no ord rel found on q",
	"TNOTSUPPORT     18       primitive not supported",
	"TSTATECHNG      19       state is in process of changing"
};


const char *
rpc_tpierr2name(uint_t err)
{
	if (err > (sizeof (tpierrs) / sizeof (tpierrs[0]) - 1))
		return ("unknown error");

	return (tpierrs[err]);
}

/*
 * derive  the code from user land inet_top6
 * convert IPv6 binary address into presentation (printable) format
 */
#define	INADDRSZ	4
#define	IN6ADDRSZ	16
#define	INT16SZ	2
const char *
kinet_ntop6(src, dst, size)
	uchar_t *src;
	char *dst;
	size_t size;
{
	/*
	 * Note that int32_t and int16_t need only be "at least" large enough
	 * to contain a value of the specified size.  On some systems, like
	 * Crays, there is no such thing as an integer variable with 16 bits.
	 * Keep this in mind if you think this function should have been coded
	 * to use pointer overlays.  All the world's not a VAX.
	 */
	char tmp[sizeof ("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")];
	char *tp;
	struct { int base, len; } best, cur;
	uint_t words[IN6ADDRSZ / INT16SZ];
	int i;
	size_t len; /* this is used to track the sprintf len */

	/*
	 * Preprocess:
	 * Copy the input (bytewise) array into a wordwise array.
	 * Find the longest run of 0x00's in src[] for :: shorthanding.
	 */

	bzero(words, sizeof (words));
	for (i = 0; i < IN6ADDRSZ; i++)
		words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));
	best.base = -1;
	cur.base = -1;

	for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
		if (words[i] == 0) {
			if (cur.base == -1)
				cur.base = i, cur.len = 1;
			else
				cur.len++;
		} else {
			if (cur.base != -1) {
				if (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	if (cur.base != -1) {
		if (best.base == -1 || cur.len > best.len)
			best = cur;
	}

	if (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	for (i = 0; i < (IN6ADDRSZ / INT16SZ); i++) {
		/* Are we inside the best run of 0x00's? */
		if (best.base != -1 && i >= best.base &&
		    i < (best.base + best.len)) {
			if (i == best.base)
				*tp++ = ':';
			continue;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		if (i != 0)
			*tp++ = ':';
		(void) sprintf(tp, "%x", words[i]);
		len = strlen(tp);
		tp += len;
	}
	/* Was it a trailing run of 0x00's? */
	if (best.base != -1 && (best.base + best.len) == (IN6ADDRSZ / INT16SZ))
		*tp++ = ':';
	*tp++ = '\0';

	/*
	 * Check for overflow, copy, and we're done.
	 */
	if ((int)(tp - tmp) > size) {
		return (NULL);
	}
	(void) strcpy(dst, tmp);
	return (dst);
}
