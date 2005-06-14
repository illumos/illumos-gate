/*
 * Copyright (C) 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stream.h>
#include <stropts.h>
#include <sys/strstat.h>
#include <sys/sysmacros.h>
#include <sys/tihdr.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/route.h>
#include <inet/common.h>
#include <inet/mib2.h>
#include <inet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/systeminfo.h>
#include <arpa/inet.h>
#include "pfild.h"

#ifndef MIN
#define	MIN(a, b)	(((a) < (b)) ? (a) : (b))
#endif

extern int pfil_msg(uint32_t, void *, size_t);

/*
 * vas.c:  Valid Address Set computation and communication for pfild
 *
 * pfild computes a "valid source address set" for each interface and hands the
 * resulting data to the pfil module which makes it available to pfil clients.
 * The ipf module uses the valid address sets to implement the fr_chksrc
 * feature (automatic protection from source address spoofing).
 *
 * A valid source address for a packet received on given interface is defined
 * as an address which, if used as a destination, would be routed to that
 * interface.  This code assumes that only inbound traffic will be tested
 * against the valid address sets; thus all local and loopback addresses are
 * considered invalid.
 *
 * The TPI MIB interface is used to read the current routing table.  A
 * request (T_SVR4_OPTMGMT_REQ) is sent to /dev/arp and the replies are read,
 * discarding most of them, but saving the two that contain the IPv4 and IPv6
 * routing tables.  Also inspected are two other messages that each happen to
 * contain a constant needed to parse the routing table messages.
 *
 * An address set is represented as a sorted list of mutually discontiguous
 * non-empty inclusive spans.  In the kernel, this list can be efficiently
 * binary-searched.  In user space, we can compute unions and intersections of
 * address sets.  In either case, IPv4 addresses are stored in host byte order
 * for efficient numerical comparisons.  IPv6 addresses will be compared
 * byte-at-a-time so they are kept in conventional struct in6_addr form
 * (network byte order).
 *
 * General note:  For the moment, only v4 is supported, but most of the
 * structure for v6 support is in place.
 */


/*
 * User space uses a linked list of spans, rather than the array that is
 * used in the kernel and in the /dev/pfil messages.
 */

static struct spannode {
	struct spannode *next;
	union {
		struct pfil_v4span v4;
		struct pfil_v6span v6;
	} span;
};

static struct addrset {
	const char *name;
	uint8_t af;
	struct spannode *head;
};

/*
 * Allocate and initialize a new struct addrset.
 * Returns pointer to new instance or NULL for allocation failure.
 */
static struct addrset *
new_addrset(const char *name, uint8_t af)
{
	struct addrset *asp = malloc(sizeof (*asp));

	if (asp == NULL)
		return (NULL);

	asp->name = name;
	asp->af = af;
	asp->head = NULL;

	return (asp);
}

/*
 * Free an addrset instance.
 */
static void
delete_addrset(struct addrset *asp)
{
	struct spannode *tmp;
	while (asp->head != NULL) {
		tmp = asp->head->next;
		free(asp->head);
		asp->head = tmp;
	}
	free(asp);
}

/*
 * Add a single IPv4 address or a prefix to a set.
 * Returns 0 for success, non-zero for failure (allocation error).
 * addr and mask are passed in network byte order, but immediately converted
 * to host byte order for comparisons.
 */
static int
addrset_add_v4(struct addrset *asp, ipaddr_t addr, ipaddr_t mask)
{
	struct spannode **ptpn, *p;
	uint32_t first, last;		/* host byte order */

	assert(asp->af == AF_INET);

	first = ntohl(addr & mask);
	last = ntohl(addr | ~mask);

	/*
	 * Search through the list linearly, looking for either:  an entry
	 * contiguous to the one being added (with which we will merge) or a
	 * discontiguous entry with a lower address (before which we will
	 * insert).  If no match, we will append at the end.
	 */
	for (ptpn = &asp->head; (p = *ptpn) != NULL; ptpn = &p->next) {
		if (first > 0 && first-1 > p->span.v4.last)
			continue;
		if (last == 0xFFFFFFFF || last+1 >= p->span.v4.first) {
			/* Merge with this entry. */
			if (first < p->span.v4.first)
				p->span.v4.first = first;
			while (last > p->span.v4.last) {
				struct spannode *next = p->next;

				if (next != NULL &&
				    last >= next->span.v4.first - 1) {
					/* Merge this span with the next. */
					p->span.v4.last = next->span.v4.last;
					p->next = next->next;
					free(next);
				} else {
					p->span.v4.last = last;
				}
			}
			return (0);
		} else {
			/* Found the insertion point; exit the loop. */
			break;
		}
	}

	/* ptpn now points to the "previous next" where we need to insert. */

	p = malloc(sizeof (*p));
	if (p == NULL)
		return (1);
	p->span.v4.first = first;
	p->span.v4.last = last;
	p->next = *ptpn;
	*ptpn = p;

	return (0);
}

/*
 * Remove one range of addresses from a set.
 */
static int
addrset_delete_v4(struct addrset *asp, uint32_t first, uint32_t last)
{
	struct spannode **ptpn, *p;

	/*
	 * Search through the list linearly, looking for any of:  an entry
	 * entirely contained with the range being deleted (which we will
	 * delete from the list) or an entry overlapping the first address of
	 * the range (which we will truncate at its end) or an entry
	 * overlapping the last address of the range (which we will truncate at
	 * its beginning) or an entry which entirely contains the range being
	 * deleted plus at least one address beyond in each direction (which we
	 * will split into two entries) or an entry with a higher address than
	 * we are deleting (at which point we are done).
	 */
	for (ptpn = &asp->head; (p = *ptpn) != NULL; ptpn = &p->next) {
		if (p->span.v4.first > last)
			return (0);		/* all done */
		if (p->span.v4.last < first)
			continue;	/* keep searching */
		while (p->span.v4.first >= first &&
		    p->span.v4.last <= last) {
			/* Delete a span entirely. */
			*ptpn = p->next;
			free(p);
			p = *ptpn;
			if (p == NULL || p->span.v4.first > last)
				return (0);	/* all done */
		}
		if (p->span.v4.first >= first) {
			/* Truncate a span at its beginning. */
			p->span.v4.first = last + 1;
		} else if (p->span.v4.last <= last) {
			/* Truncate a span at its end. */
			p->span.v4.last = first - 1;
		} else {
			/* Split a span into two. */
			struct spannode *p2 = malloc(sizeof (*p2));
			if (p2 == NULL)
				return (1);
			p2->span.v4.first = last + 1;
			p2->span.v4.last = p->span.v4.last;
			p2->next = p->next;
			p->span.v4.last = first - 1;
			p->next = p2;
		}
	}

	return (0);
}

/*
 * Compute the set difference (remove elements in set 2 from set 1).
 */
static void
addrset_diff(struct addrset *asp1, struct addrset *asp2)
{
	struct spannode *p;

	if (asp1->af != asp2->af)
		return;

	assert(asp1->af == AF_INET);

	/* For each span in set 2, delete it from set 1. */
	for (p = asp2->head; p; p = p->next)
		(void) addrset_delete_v4(asp1,
		    p->span.v4.first, p->span.v4.last);
}


typedef struct mib_item_s {
	int			group;
	int			mib_id;
	void			*valp;
	size_t			length;
} mib_item_t;

static void	mibload(int sd);
static void	mibfree(mib_item_t *item);
static void	mib_get_constants(mib_item_t *item);

static int ipRouteEntrySize;
static int ipv6RouteEntrySize;

static mib_item_t *ipv4Table;
static mib_item_t *ipv6Table;

/*
 * Copy and NUL-terminate a MIB octet-string.
 */
static void
octetstr(Octet_t *op, char *dst, uint_t dstlen)
{
	size_t n = MIN(dstlen - 1, op->o_length);
	memcpy(dst, op->o_bytes, n);
	dst[n] = '\0';
}

/*
 * Read the whole IP MIB, looking for the routing related entries.
 * Save the IPv4 and IPv6 route table items and peek into a couple other
 * items to learn the increments between records in the route table items.
 */
static void
mibload(int sd)
{
	/*
	 * buf is an automatic for this function, so the
	 * compiler has complete control over its alignment;
	 * it is assumed this alignment is satisfactory for
	 * it to be casted to certain other struct pointers
	 * here, such as struct T_optmgmt_ack * .
	 */
	uintptr_t		buf[512 / sizeof (uintptr_t)];
	int			flags;
	int			j, getcode;
	struct strbuf		ctlbuf, databuf;
	struct T_optmgmt_req	*tor = (struct T_optmgmt_req *)buf;
	struct T_optmgmt_ack	*toa = (struct T_optmgmt_ack *)buf;
	struct T_error_ack	*tea = (struct T_error_ack *)buf;
	struct opthdr		*req;
	mib_item_t		*temp;

	ipv4Table = NULL;
	ipv6Table = NULL;

	tor->PRIM_type = T_SVR4_OPTMGMT_REQ;
	tor->OPT_offset = sizeof (struct T_optmgmt_req);
	tor->OPT_length = sizeof (struct opthdr);
	tor->MGMT_flags = T_CURRENT;
	req = (struct opthdr *)&tor[1];
	req->level = MIB2_IP;		/* any MIB2_xxx value ok here */
	req->name  = 0;
	req->len   = 0;

	ctlbuf.buf = (char *)buf;
	ctlbuf.len = tor->OPT_length + tor->OPT_offset;
	flags = 0;
	if (putmsg(sd, &ctlbuf, (struct strbuf *)0, flags) == -1) {
		perror("mibget: putmsg(ctl) failed");
		goto error_exit;
	}

	/*
	 * Each reply consists of a ctl part for one fixed structure
	 * or table, as defined in mib2.h.  The format is a T_OPTMGMT_ACK,
	 * containing an opthdr structure.  level/name identify the entry,
	 * len is the size of the data part of the message.
	 */
	req = (struct opthdr *)&toa[1];
	ctlbuf.maxlen = sizeof (buf);
	j = 1;
	for (;;) {
		flags = 0;
		getcode = getmsg(sd, &ctlbuf, (struct strbuf *)0, &flags);
		if (getcode == -1) {
			perror("mibget getmsg(ctl) failed");
			goto error_exit;
		}
		if (getcode == 0 &&
		    ctlbuf.len >= sizeof (struct T_optmgmt_ack) &&
		    toa->PRIM_type == T_OPTMGMT_ACK &&
		    toa->MGMT_flags == T_SUCCESS &&
		    req->len == 0)
			return;

		if (ctlbuf.len >= sizeof (struct T_error_ack) &&
		    tea->PRIM_type == T_ERROR_ACK) {
			(void) fprintf(stderr,
			    "mibget %d gives T_ERROR_ACK: TLI_error = 0x%lx, "
			    "UNIX_error = 0x%lx\n",
			    j, tea->TLI_error, tea->UNIX_error);

			errno = (tea->TLI_error == TSYSERR) ?
			    tea->UNIX_error : EPROTO;
			goto error_exit;
		}

		if (getcode != MOREDATA ||
		    ctlbuf.len < sizeof (struct T_optmgmt_ack) ||
		    toa->PRIM_type != T_OPTMGMT_ACK ||
		    toa->MGMT_flags != T_SUCCESS) {
			(void) printf("mibget getmsg(ctl) %d returned %d, "
			    "ctlbuf.len = %d, PRIM_type = %ld\n",
			    j, getcode, ctlbuf.len, toa->PRIM_type);

			if (toa->PRIM_type == T_OPTMGMT_ACK)
				(void) printf("T_OPTMGMT_ACK: "
				    "MGMT_flags = 0x%lx, req->len = %ld\n",
				    toa->MGMT_flags, req->len);
			errno = ENOMSG;
			goto error_exit;
		}

		temp = malloc(sizeof (mib_item_t));
		if (temp == NULL) {
			perror("mibget malloc failed");
			goto error_exit;
		}
		temp->group = req->level;
		temp->mib_id = req->name;
		temp->length = req->len;
		temp->valp = malloc(req->len);
		if (temp->valp == NULL) {
			free(temp);
			goto error_exit;
		}

		databuf.maxlen = temp->length;
		databuf.buf    = temp->valp;
		databuf.len    = 0;
		flags = 0;
		getcode = getmsg(sd, (struct strbuf *)0, &databuf, &flags);
		if (getcode == -1) {
			perror("mibload getmsg(data) failed");
			mibfree(temp);
			goto error_exit;
		} else if (getcode != 0) {
			(void) printf("mibload getmsg(data) returned %d, "
			    "databuf.maxlen = %d, databuf.len = %d\n",
			    getcode, databuf.maxlen, databuf.len);
			mibfree(temp);
			goto error_exit;
		}

		j++;

		if (temp->group != MIB2_IP &&
		    temp->group != MIB2_IP6) {
			mibfree(temp);
			continue;
		}

		switch (temp->mib_id) {
		case MIB2_IP_ROUTE:
			if (ipv4Table)
				mibfree(ipv4Table);
			ipv4Table = temp;
			break;
		case MIB2_IP6_ROUTE:
			if (ipv6Table)
				mibfree(ipv6Table);
			ipv6Table = temp;
			break;
		case 0:
			mib_get_constants(temp);
			/* FALLTHROUGH */
		default:
			mibfree(temp);
			break;
		}
	}
	/* NOTREACHED */

error_exit:;
}

/*
 * mibfree: frees a (mib_item_t *) loaded by mibload()
 */
static void
mibfree(mib_item_t *item)
{
	if (item->valp != NULL)
		free(item->valp);
	free(item);
}

#define	IPROUTEENTRYALIGNMENT 4
#define	IP6ROUTEENTRYALIGNMENT 4

/* Extract constant sizes. */
static void
mib_get_constants(mib_item_t *item)
{
	switch (item->group) {
	case MIB2_IP: {
		mib2_ip_t *ip = item->valp;

		ipRouteEntrySize = ip->ipRouteEntrySize;
		assert(IS_P2ALIGNED(ipRouteEntrySize, IPROUTEENTRYALIGNMENT));
		break;
	}
	case MIB2_IP6: {
		mib2_ipv6IfStatsEntry_t *ip6 = item->valp;
		/* Just use the first entry */

		ipv6RouteEntrySize = ip6->ipv6RouteEntrySize;
		assert(IS_P2ALIGNED(ipv6RouteEntrySize,
		    IP6ROUTEENTRYALIGNMENT));
		break;
	}
	}
}


/*
 * Compose a PFILCMD_IFADDRSET message for each interface and deliver them to
 * pfil.  Returns 0 for success, non-zero for failure.
 */
static int
pfil_ifaddrset_msg(struct addrset **ifs, int numifs)
{
	int status = 0, i;
	struct pfil_ifaddrset *ifaddrset = NULL;

	for (i = 0; i < numifs; i++)
		if (ifs[i]->af == AF_INET) {
			struct spannode *p1;
			struct pfil_v4span *p2;
			int nspans = 0;
			size_t size;

			for (p1 = ifs[i]->head; p1; p1 = p1->next)
				nspans++;
			size = sizeof (struct pfil_ifaddrset) +
			    nspans * sizeof (struct pfil_v4span);
			ifaddrset = realloc(ifaddrset, size);
			if (ifaddrset == NULL)
				return (-1);

			(void) strlcpy(ifaddrset->name, ifs[i]->name,
			    LIFNAMSIZ);
			ifaddrset->af = ifs[i]->af;
			ifaddrset->nspans = nspans;
			p2 = (struct pfil_v4span *)(ifaddrset + 1);
			for (p1 = ifs[i]->head; p1; p1 = p1->next) {
				p2->first = p1->span.v4.first;
				p2->last = p1->span.v4.last;
				++p2;
			}

			status = pfil_msg(PFILCMD_IFADDRSET, ifaddrset, size);
			if (status != 0)
				break;
		}

	if (ifaddrset != NULL)
		free(ifaddrset);

	return (status);
}

/*
 * Find an interface through which the gateway is reachable and return its
 * name in the specififed buffer.
 */
static void
findgwif_v4(in_addr_t gw, char outif[], size_t size)
{
	mib2_ipRouteEntry_t *rp;

	for (rp = ipv4Table->valp;
	    (char *)rp < (char *)ipv4Table->valp + ipv4Table->length;
	    rp = (mib2_ipRouteEntry_t *)
	    ((char *)rp + ipRouteEntrySize)) {
		if ((rp->ipRouteInfo.re_ire_type & IRE_INTERFACE) &&
		    (rp->ipRouteIfIndex.o_length > 0) &&
		    ((gw & rp->ipRouteMask) == rp->ipRouteDest)) {
			octetstr(&rp->ipRouteIfIndex,
			    outif, size);
			return;
		}
	}
	outif[0] = '\0';
}

/*
 * Compute the valid address sets for the specified interfaces, then compose a
 * series of PFILCMD_IFADDRSET messages and deliver them to pfil.  Returns 0 for
 * success, non-zero for failure.
 */
int
vas(const struct pfil_ifaddrs *ifaddrlist, int numifs)
{
	struct addrset **ifs = NULL, *illegal_v4 = NULL;
	int sd, i, status;

	sd = open("/dev/arp", O_RDWR);
	if (sd == -1)
		return (-1);
	mibload(sd);
	(void) close(sd);

	ifs = calloc(numifs, sizeof (*ifs));
	if (ifs == NULL)
		goto err;
	for (i = 0; i < numifs; i++) {
		ifs[i] = new_addrset(ifaddrlist[i].name,
		    ifaddrlist[i].localaddr.in.sin_family);
		if (ifs[i] == NULL)
			goto err;
	}

	illegal_v4 = new_addrset("[illegal]", AF_INET);
	if (illegal_v4 == NULL)
		goto err;

	/* Multicast addresses are always illegal as source address. */
	if (addrset_add_v4(illegal_v4,
	    htonl(INADDR_UNSPEC_GROUP), htonl(IN_CLASSD_NET)))
		goto err;

	/* Loopback addresses are illegal on non-loopback interfaces. */
	if (addrset_add_v4(illegal_v4,
	    htonl(INADDR_LOOPBACK), htonl(IN_CLASSA_NET)))
		goto err;

	if (ipRouteEntrySize < sizeof (mib2_ipRouteEntry_t) ||
	    ipv6RouteEntrySize < sizeof (mib2_ipv6RouteEntry_t) ||
	    (!ipv4Table && !ipv6Table)) {
		errno = ENOENT;
err:
		status = -1;
		goto done;
	}

	if (ipv4Table != NULL) {
		mib2_ipRouteEntry_t *rp;

		for (rp = ipv4Table->valp;
		    (char *)rp < (char *)ipv4Table->valp + ipv4Table->length;
		    rp = (mib2_ipRouteEntry_t *)
		    ((char *)rp + ipRouteEntrySize)) {
			struct addrset *asp = NULL;
			char outif[LIFNAMSIZ + 1];

			switch (rp->ipRouteInfo.re_ire_type) {
			case IRE_CACHE:
				continue;
			case IRE_BROADCAST:
			case IRE_LOCAL:
				asp = illegal_v4;
				break;
			default:
				if (rp->ipRouteIfIndex.o_length > 0) {
					octetstr(&rp->ipRouteIfIndex,
					    outif, sizeof (outif));
				} else {
					findgwif_v4(rp->ipRouteNextHop,
					    outif, sizeof (outif));
				}
				if (outif[0] != '\0') {
					for (i = 0; i < numifs; i++) {
						if (ifs[i]->af == AF_INET &&
						    strncmp(outif, ifs[i]->name,
						    LIFNAMSIZ) == 0) {
							asp = ifs[i];
							break;
						}
					}
				}
				break;
			}
			if (asp != NULL &&
			    addrset_add_v4(asp,
			    rp->ipRouteDest, rp->ipRouteMask) != 0)
				goto err;
		}
	}

	if (ipv6Table != NULL) {
#ifdef LATER_IPV6
		mib2_ipv6RouteEntry_t *rp;

		for (rp = ipv6Table->valp;
		    (char *)rp < (char *)ipv6Table->valp + ipv6Table->length;
		    rp = (mib2_ipv6RouteEntry_t *)
		    ((char *)rp + ipv6RouteEntrySize)) {
			if (addrset_add_v6(rp) != 0)
				goto err;
		}
#endif
	}

	for (i = 0; i < numifs; i++)
		if (ifs[i]->af == AF_INET)
			addrset_diff(ifs[i], illegal_v4);

	status = pfil_ifaddrset_msg(ifs, numifs);
#ifdef DEBUG
	pfil_ifaddrset_msg(&illegal_v4, 1);
#endif

done:
	if (ipv4Table != NULL)
		mibfree(ipv4Table);
	if (ipv6Table != NULL)
		mibfree(ipv6Table);

	for (i = 0; i < numifs; i++)
		if (ifs[i] != NULL)
			delete_addrset(ifs[i]);
	free(ifs);
	if (illegal_v4 != NULL)
		delete_addrset(illegal_v4);

	return (status);
}

#ifdef DEBUG
static void
fatal(int errcode, char *format, ...)
{
	va_list argp;

	if (format == NULL)
		return;

	va_start(argp, format);
	(void) vfprintf(stderr, format, argp);
	va_end(argp);

	exit(errcode);
}

static void
pr_net(ipaddr_t addr, ipaddr_t mask, char *dst, size_t dstlen)
{
	struct in_addr in;
	char *cp;
	int slen;

	if (addr == INADDR_ANY && mask == INADDR_ANY) {
		(void) strlcpy(dst, "default", dstlen);
		return;
	}
	in.s_addr = addr;
	if (inet_ntop(AF_INET, &in, dst, dstlen) == NULL) {
		(void) strlcpy(dst, "****", dstlen);
		return;
	}
	if (mask != IP_HOST_MASK) {
		slen = strlen(dst);
		cp = dst + slen;
		dstlen -= slen;
		if (mask == 0) {
			/* Illegal on non-zero addresses */
			(void) strlcpy(cp, "/0", dstlen);
		} else if ((mask | (mask - 1)) == IP_HOST_MASK) {
			(void) snprintf(cp, dstlen, "/%d",
			    IP_ABITS - ffs(mask) + 1);
		} else {
			/* Ungood; non-contiguous mask */
			uint8_t	*ip_addr = (uint8_t *)&mask;
			(void) snprintf(cp, dstlen, "%d.%d.%d.%d",
			    ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]);
		}
	}
}

static void
pr_span(const struct spannode *p, char *buf, size_t size)
{
	ipaddr_t addr;
	char buf1[50], buf2[50];

	addr = htonl(p->span.v4.first);
	(void) inet_ntop(AF_INET, &addr, buf1, sizeof (buf1));

	if (p->span.v4.first == p->span.v4.last) {
		(void) strncpy(buf, buf1, size);
	} else {
		addr = htonl(p->span.v4.last);
		(void) inet_ntop(AF_INET, &addr, buf2, sizeof (buf2));
		(void) snprintf(buf, size, "%s - %s", buf1, buf2);
	}
}

static void
pr_addrset(const struct addrset *asp)
{
	(void) printf("addrset %s (%u):\n", asp->name, asp->af);

	if (asp->head == 0) {
		(void) puts(" [empty]");
		return;
	}

	if (asp->af == AF_INET) {
		struct spannode *p = asp->head;

		while (p != NULL) {
			char buf[100];

			(void) putchar(' ');
			pr_span(p, buf, sizeof (buf));
			(void) fputs(buf, stdout);
			if (p->next)
				(void) putchar(',');
			p = p->next;
		}
		(void) putchar('\n');
	}
}

static void
pr_ifaddrset(const struct pfil_ifaddrset *asp)
{
	int i;

	(void) printf("addrset %s (%u):\n", asp->name, asp->af);

	if (asp->nspans == 0) {
		(void) puts(" [empty]");
		return;
	}

	if (asp->af == AF_INET) {
		struct pfil_v4span *p = (struct pfil_v4span *)(asp + 1);

		for (i = 0; i < asp->nspans; i++) {
			ipaddr_t addr;
			char buf[20];

			addr = htonl(p->first);
			(void) inet_ntop(AF_INET, &addr, buf, sizeof (buf));
			(void) printf(" %s", buf);

			if (p->first != p->last) {
				addr = htonl(p->last);
				(void) inet_ntop(AF_INET, &addr,
				    buf, sizeof (buf));
				(void) printf(" - %s", buf);
			}

			if (i+1 < asp->nspans)
				(void) putchar(',');
			p++;
		}
		(void) putchar('\n');
	}
}

int
pfil_msg(uint32_t cmd, void *buf, size_t len)
{
	struct pfil_ifaddrset *ifaddrset = buf;
	pr_ifaddrset(ifaddrset);
	return (0);
}

int
main(int argc, char *argv[])
{
	int numifs, i;
	struct pfil_ifaddrs *ifaddrlist;

	numifs = argc-1;
	ifaddrlist = calloc(numifs, sizeof (ifaddrlist[0]));
	for (i = 0; i < numifs; i++) {
		(void) strlcpy(ifaddrlist[i].name, argv[i+1], LIFNAMSIZ);
		ifaddrlist[i].localaddr.in.sin_family = AF_INET;
	}

	return (vas(ifaddrlist, numifs));
}
#endif
