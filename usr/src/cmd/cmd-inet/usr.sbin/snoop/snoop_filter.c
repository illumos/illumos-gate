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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <stddef.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/vlan.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <inet/ip6.h>
#include <inet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <rpc/rpc.h>
#include <rpc/rpcent.h>
#include <sys/dlpi.h>

#include <snoop.h>
#include "snoop_vlan.h"

#define	IPV4_ONLY	0
#define	IPV6_ONLY	1
#define	IPV4_AND_IPV6	2

/*
 * The following constants represent the offsets in bytes from the beginning
 * of the IP(v6) header of the source and destination IP(v6) addresses.
 * These are useful when generating filter code.
 */
#define	IPV4_SRCADDR_OFFSET	12
#define	IPV4_DSTADDR_OFFSET	16
#define	IPV6_SRCADDR_OFFSET	8
#define	IPV6_DSTADDR_OFFSET	24
#define	IP_VERS(p)	(((*(uchar_t *)p) & 0xf0) >> 4)
#define	MASKED_IPV4_VERS	0x40
#define	MASKED_IPV6_VERS	0x60
#define	IP_HDR_LEN(p)	(((*(uchar_t *)p) & 0xf) * 4)
#define	TCP_HDR_LEN(p)	((((*((uchar_t *)p+12)) >> 4) & 0xf) * 4)

/*
 * Coding the constant below is tacky, but the compiler won't let us
 * be more clever.  E.g., &((struct ip *)0)->ip_xxx
 */
#define	IP_PROTO_OF(p)	(((uchar_t *)p)[9])

/*
 * AppleTalk uses 802.2 Ethernet encapsulation with LLC/SNAP headers,
 * for 8 octets of overhead, and the common AppleTalk DDP Ethernet
 * header is another 4 octets.
 *
 * The following constants represents the offsets in bytes from the beginning
 * of the Ethernet payload to various parts of the DDP header.
 */

#define	AT_DST_NET_OFFSET	12
#define	AT_SRC_NET_OFFSET	14
#define	AT_DST_NODE_OFFSET	16
#define	AT_SRC_NODE_OFFSET	17

/*
 * Offset for the source and destination zoneid in the ipnet header.
 */
#define	IPNET_SRCZONE_OFFSET 16
#define	IPNET_DSTZONE_OFFSET 20

int eaddr;	/* need ethernet addr */

int opstack;	/* operand stack depth */

/*
 * These are the operators of the user-level filter.
 * STOP ends execution of the filter expression and
 * returns the truth value at the top of the stack.
 * OP_LOAD_OCTET, OP_LOAD_SHORT and OP_LOAD_LONG pop
 * an offset value from the stack and load a value of
 * an appropriate size from the packet (octet, short or
 * long).  The offset is computed from a base value that
 * may be set via the OP_OFFSET operators.
 * OP_EQ, OP_NE, OP_GT, OP_GE, OP_LT, OP_LE pop two values
 * from the stack and return the result of their comparison.
 * OP_AND, OP_OR, OP_XOR pop two values from the stack and
 * do perform a bitwise operation on them - returning a result
 * to the stack.  OP_NOT inverts the bits of the value on the
 * stack.
 * OP_BRFL and OP_BRTR branch to an offset in the code array
 * depending on the value at the top of the stack: true (not 0)
 * or false (0).
 * OP_ADD, OP_SUB, OP_MUL, OP_DIV and OP_REM pop two values
 * from the stack and perform arithmetic.
 * The OP_OFFSET operators change the base from which the
 * OP_LOAD operators compute their offsets.
 * OP_OFFSET_ZERO sets the offset to zero - beginning of packet.
 * OP_OFFSET_LINK sets the base to the first octet after
 * the link (DLC) header.  OP_OFFSET_IP, OP_OFFSET_TCP,
 * and OP_OFFSET_UDP do the same for those headers - they
 * set the offset base to the *end* of the header - not the
 * beginning.  The OP_OFFSET_RPC operator is a bit unusual.
 * It points the base at the cached RPC header.  For the
 * purposes of selection, RPC reply headers look like call
 * headers except for the direction value.
 * OP_OFFSET_ETHERTYPE sets base according to the following
 * algorithm:
 *   if the packet is not VLAN tagged, then set base to
 *         the ethertype field in the ethernet header
 *   else set base to the ethertype field of the VLAN header
 * OP_OFFSET_POP restores the offset base to the value prior
 * to the most recent OP_OFFSET call.
 */
enum optype {
	OP_STOP = 0,
	OP_LOAD_OCTET,
	OP_LOAD_SHORT,
	OP_LOAD_LONG,
	OP_LOAD_CONST,
	OP_LOAD_LENGTH,
	OP_EQ,
	OP_NE,
	OP_GT,
	OP_GE,
	OP_LT,
	OP_LE,
	OP_AND,
	OP_OR,
	OP_XOR,
	OP_NOT,
	OP_BRFL,
	OP_BRTR,
	OP_ADD,
	OP_SUB,
	OP_MUL,
	OP_DIV,
	OP_REM,
	OP_OFFSET_POP,
	OP_OFFSET_ZERO,
	OP_OFFSET_LINK,
	OP_OFFSET_IP,
	OP_OFFSET_TCP,
	OP_OFFSET_UDP,
	OP_OFFSET_RPC,
	OP_OFFSET_SLP,
	OP_OFFSET_ETHERTYPE,
	OP_LAST
};

static char *opnames[] = {
	"STOP",
	"LOAD_OCTET",
	"LOAD_SHORT",
	"LOAD_LONG",
	"LOAD_CONST",
	"LOAD_LENGTH",
	"EQ",
	"NE",
	"GT",
	"GE",
	"LT",
	"LE",
	"AND",
	"OR",
	"XOR",
	"NOT",
	"BRFL",
	"BRTR",
	"ADD",
	"SUB",
	"MUL",
	"DIV",
	"REM",
	"OFFSET_POP",
	"OFFSET_ZERO",
	"OFFSET_ETHER",
	"OFFSET_IP",
	"OFFSET_TCP",
	"OFFSET_UDP",
	"OFFSET_RPC",
	"OP_OFFSET_SLP",
	"OFFSET_ETHERTYPE",
	""
};

#define	MAXOPS 1024
#define	MAXSS	64
static uint_t oplist[MAXOPS];	/* array of operators */
static uint_t *curr_op;		/* last op generated */

extern int valid_slp(uchar_t *, int);	/* decides if a SLP msg is valid */
extern struct hostent *lgetipnodebyname(const char *, int, int, int *);

static void alternation();
static uint_t chain();
static void codeprint();
static void emitop();
static void emitval();
static void expression();
static struct xid_entry *find_rpc();
static void optimize();
static void ethertype_match();

/*
 * Get a ushort from a possibly unaligned character buffer.
 *
 * INPUTS:  buffer - where the data is.  Must be at least
 *          sizeof(uint16_t) bytes long.
 * OUPUTS:  An unsigned short that contains the data at buffer.
 *          No calls to ntohs or htons are done on the data.
 */
static uint16_t
get_u16(uchar_t *buffer)
{
	uint8_t	*bufraw = buffer;

	/*
	 * ntohs is used only as a cheap way to flip the bits
	 * around on a little endian platform.  The value will
	 * still be in host order or network order, depending on
	 * the order it was in when it was passed in.
	 */
	return (ntohs(bufraw[0] << 8 | bufraw[1]));
}

/*
 * Returns the ULP for an IPv4 or IPv6 packet
 * Assumes that the packet has already been checked to verify
 * that it's either IPv4 or IPv6
 *
 * XXX Will need to be updated for AH and ESP
 * XXX when IPsec is supported for v6.
 */
static uchar_t
ip_proto_of(uchar_t *ip)
{
	uchar_t		nxt;
	boolean_t	not_done = B_TRUE;
	uchar_t		*ptr = ip;

	switch (IP_VERS(ip)) {
	case IPV4_VERSION:
		return (IP_PROTO_OF(ip));
	case IPV6_VERSION:

		nxt = ip[6];
		ptr += 40;		/* size of ip6 header */
		do {
			switch (nxt) {
			/*
			 * XXX Add IPsec headers here when supported for v6
			 * XXX (the AH will have a different size...)
			 */
			case IPPROTO_HOPOPTS:
			case IPPROTO_ROUTING:
			case IPPROTO_FRAGMENT:
			case IPPROTO_DSTOPTS:
				ptr += (8 * (ptr[1] + 1));
				nxt = *ptr;
				break;

			default:
				not_done = B_FALSE;
				break;
			}
		} while (not_done);
		return (nxt);
	default:
		break;			/* shouldn't get here... */
	}
	return (0);
}

/*
 * Returns the total IP header length.
 * For v4, this includes any options present.
 * For v6, this is the length of the IPv6 header plus
 * any extension headers present.
 *
 * XXX Will need to be updated for AH and ESP
 * XXX when IPsec is supported for v6.
 */
static int
ip_hdr_len(uchar_t *ip)
{
	uchar_t		nxt;
	int		hdr_len;
	boolean_t	not_done = B_TRUE;
	int		len = 40;	/* IPv6 header size */
	uchar_t		*ptr = ip;

	switch (IP_VERS(ip)) {
	case IPV4_VERSION:
		return (IP_HDR_LEN(ip));
	case IPV6_VERSION:
		nxt = ip[6];
		ptr += len;
		do {
			switch (nxt) {
			/*
			 * XXX Add IPsec headers here when supported for v6
			 * XXX (the AH will have a different size...)
			 */
			case IPPROTO_HOPOPTS:
			case IPPROTO_ROUTING:
			case IPPROTO_FRAGMENT:
			case IPPROTO_DSTOPTS:
				hdr_len = (8 * (ptr[1] + 1));
				len += hdr_len;
				ptr += hdr_len;
				nxt = *ptr;
				break;

			default:
				not_done = B_FALSE;
				break;
			}
		} while (not_done);
		return (len);
	default:
		break;
	}
	return (0);			/* not IP */
}

static void
codeprint()
{
	uint_t *op;

	printf("User filter:\n");

	for (op = oplist; *op; op++) {
		if (*op <= OP_LAST)
			printf("\t%2d: %s\n", op - oplist, opnames[*op]);
		else
			printf("\t%2d: (%d)\n", op - oplist, *op);

		switch (*op) {
		case OP_LOAD_CONST:
		case OP_BRTR:
		case OP_BRFL:
			op++;
			if ((int)*op < 0)
				printf("\t%2d:   0x%08x (%d)\n",
				    op - oplist, *op, *op);
			else
				printf("\t%2d:   %d (0x%08x)\n",
				    op - oplist, *op, *op);
		}
	}
	printf("\t%2d: STOP\n", op - oplist);
	printf("\n");
}


/*
 * Take a pass through the generated code and optimize
 * branches.  A branch true (BRTR) that has another BRTR
 * at its destination can use the address of the destination
 * BRTR.  A BRTR that points to a BRFL (branch false) should
 * point to the address following the BRFL.
 * A similar optimization applies to BRFL operators.
 */
static void
optimize(uint_t *oplistp)
{
	uint_t *op;

	for (op = oplistp; *op; op++) {
		switch (*op) {
		case OP_LOAD_CONST:
			op++;
			break;
		case OP_BRTR:
			op++;
			optimize(&oplist[*op]);
			if (oplist[*op] == OP_BRFL)
				*op += 2;
			else if (oplist[*op] == OP_BRTR)
				*op = oplist[*op + 1];
			break;
		case OP_BRFL:
			op++;
			optimize(&oplist[*op]);
			if (oplist[*op] == OP_BRTR)
				*op += 2;
			else if (oplist[*op] == OP_BRFL)
				*op = oplist[*op + 1];
			break;
		}
	}
}

/*
 * RPC packets are tough to filter.
 * While the call packet has all the interesting
 * info: program number, version, procedure etc,
 * the reply packet has none of this information.
 * If we want to do useful filtering based on this
 * information then we have to stash the information
 * from the call packet, and use the XID in the reply
 * to find the stashed info.  The stashed info is
 * kept in a circular lifo, assuming that a call packet
 * will be followed quickly by its reply.
 */

struct xid_entry {
	unsigned	x_xid;		/* The XID (32 bits) */
	unsigned	x_dir;		/* CALL or REPLY */
	unsigned	x_rpcvers;	/* Protocol version (2) */
	unsigned	x_prog;		/* RPC program number */
	unsigned	x_vers;		/* RPC version number */
	unsigned	x_proc;		/* RPC procedure number */
};
static struct xid_entry	xe_table[XID_CACHE_SIZE];
static struct xid_entry	*xe_first = &xe_table[0];
static struct xid_entry	*xe	  = &xe_table[0];
static struct xid_entry	*xe_last  = &xe_table[XID_CACHE_SIZE - 1];

static struct xid_entry *
find_rpc(struct rpc_msg *rpc)
{
	struct xid_entry *x;

	for (x = xe; x >= xe_first; x--)
		if (x->x_xid == rpc->rm_xid)
			return (x);
	for (x = xe_last; x > xe; x--)
		if (x->x_xid == rpc->rm_xid)
			return (x);
	return (NULL);
}

static void
stash_rpc(struct rpc_msg *rpc)
{
	struct xid_entry *x;

	if (find_rpc(rpc))
		return;

	x = xe++;
	if (xe > xe_last)
		xe = xe_first;
	x->x_xid  = rpc->rm_xid;
	x->x_dir  = htonl(REPLY);
	x->x_prog = rpc->rm_call.cb_prog;
	x->x_vers = rpc->rm_call.cb_vers;
	x->x_proc = rpc->rm_call.cb_proc;
}

/*
 * SLP can multicast requests, and recieve unicast replies in which
 * neither the source nor destination port is identifiable as a SLP
 * port. Hence, we need to do as RPC does, and keep track of packets we
 * are interested in. For SLP, however, we use ports, not XIDs, and
 * a smaller cache size is more efficient since every incoming packet
 * needs to be checked.
 */

#define	SLP_CACHE_SIZE 64
static uint_t slp_table[SLP_CACHE_SIZE];
static int slp_index	= 0;

/*
 * Returns the index of dport in the table if found, otherwise -1.
 */
static int
find_slp(uint_t dport) {
    int i;

    if (!dport)
	return (0);

    for (i = slp_index; i >= 0; i--)
	if (slp_table[i] == dport) {
	    return (i);
	}
    for (i = SLP_CACHE_SIZE - 1; i > slp_index; i--)
	if (slp_table[i] == dport) {
	    return (i);
	}
    return (-1);
}

static void stash_slp(uint_t sport) {
    if (slp_table[slp_index - 1] == sport)
	/* avoid redundancy due to multicast retransmissions */
	return;

    slp_table[slp_index++] = sport;
    if (slp_index == SLP_CACHE_SIZE)
	slp_index = 0;
}

/*
 * This routine takes a packet and returns true or false
 * according to whether the filter expression selects it
 * or not.
 * We assume here that offsets for short and long values
 * are even - we may die with an alignment error if the
 * CPU doesn't support odd addresses.  Note that long
 * values are loaded as two shorts so that 32 bit word
 * alignment isn't important.
 *
 * IPv6 is a bit stickier to handle than IPv4...
 */

int
want_packet(uchar_t *pkt, int len, int origlen)
{
	uint_t stack[MAXSS];	/* operand stack */
	uint_t *op;		/* current operator */
	uint_t *sp;		/* top of operand stack */
	uchar_t *base;		/* base for offsets into packet */
	uchar_t *ip;		/* addr of IP header, unaligned */
	uchar_t *tcp;		/* addr of TCP header, unaligned */
	uchar_t *udp;		/* addr of UDP header, unaligned */
	struct rpc_msg rpcmsg;	/* addr of RPC header */
	struct rpc_msg *rpc;
	int newrpc = 0;
	uchar_t *slphdr;		/* beginning of SLP header */
	uint_t slp_sport, slp_dport;
	int off, header_size;
	uchar_t *offstack[MAXSS];	/* offset stack */
	uchar_t **offp;		/* current offset */
	uchar_t *opkt = NULL;
	uint_t olen;

	sp = stack;
	*sp = 1;
	base = pkt;
	offp = offstack;

	header_size = (*interface->header_len)((char *)pkt, len);

	for (op = oplist; *op; op++) {
		switch ((enum optype) *op) {
		case OP_LOAD_OCTET:
			if ((base + *sp) > (pkt + len))
				return (0); /* packet too short */

			*sp = *((uchar_t *)(base + *sp));
			break;
		case OP_LOAD_SHORT:
			off = *sp;

			if ((base + off + sizeof (uint16_t) - 1) > (pkt + len))
				return (0); /* packet too short */

			*sp = ntohs(get_u16((uchar_t *)(base + off)));
			break;
		case OP_LOAD_LONG:
			off = *sp;

			if ((base + off + sizeof (uint32_t) - 1) > (pkt + len))
				return (0); /* packet too short */

			/*
			 * Handle 3 possible alignments
			 */
			switch ((((unsigned)base) + off) % sizeof (uint_t)) {
			case 0:
				*sp = *(uint_t *)(base + off);
				break;

			case 2:
				*((ushort_t *)(sp)) =
				    *((ushort_t *)(base + off));
				*(((ushort_t *)sp) + 1) =
				    *((ushort_t *)(base + off) + 1);
				break;

			case 1:
			case 3:
				*((uchar_t *)(sp)) =
				    *((uchar_t *)(base + off));
				*(((uchar_t *)sp) + 1) =
				    *((uchar_t *)(base + off) + 1);
				*(((uchar_t *)sp) + 2) =
				    *((uchar_t *)(base + off) + 2);
				*(((uchar_t *)sp) + 3) =
				    *((uchar_t *)(base + off) + 3);
				break;
			}
			*sp = ntohl(*sp);
			break;
		case OP_LOAD_CONST:
			if (sp >= &stack[MAXSS])
				return (0);
			*(++sp) = *(++op);
			break;
		case OP_LOAD_LENGTH:
			if (sp >= &stack[MAXSS])
				return (0);
			*(++sp) = origlen;
			break;
		case OP_EQ:
			if (sp < &stack[1])
				return (0);
			sp--;
			*sp = *sp == *(sp + 1);
			break;
		case OP_NE:
			if (sp < &stack[1])
				return (0);
			sp--;
			*sp = *sp != *(sp + 1);
			break;
		case OP_GT:
			if (sp < &stack[1])
				return (0);
			sp--;
			*sp = *sp > *(sp + 1);
			break;
		case OP_GE:
			if (sp < &stack[1])
				return (0);
			sp--;
			*sp = *sp >= *(sp + 1);
			break;
		case OP_LT:
			if (sp < &stack[1])
				return (0);
			sp--;
			*sp = *sp < *(sp + 1);
			break;
		case OP_LE:
			if (sp < &stack[1])
				return (0);
			sp--;
			*sp = *sp <= *(sp + 1);
			break;
		case OP_AND:
			if (sp < &stack[1])
				return (0);
			sp--;
			*sp &= *(sp + 1);
			break;
		case OP_OR:
			if (sp < &stack[1])
				return (0);
			sp--;
			*sp |= *(sp + 1);
			break;
		case OP_XOR:
			if (sp < &stack[1])
				return (0);
			sp--;
			*sp ^= *(sp + 1);
			break;
		case OP_NOT:
			*sp = !*sp;
			break;
		case OP_BRFL:
			op++;
			if (!*sp)
				op = &oplist[*op] - 1;
			break;
		case OP_BRTR:
			op++;
			if (*sp)
				op = &oplist[*op] - 1;
			break;
		case OP_ADD:
			if (sp < &stack[1])
				return (0);
			sp--;
			*sp += *(sp + 1);
			break;
		case OP_SUB:
			if (sp < &stack[1])
				return (0);
			sp--;
			*sp -= *(sp + 1);
			break;
		case OP_MUL:
			if (sp < &stack[1])
				return (0);
			sp--;
			*sp *= *(sp + 1);
			break;
		case OP_DIV:
			if (sp < &stack[1])
				return (0);
			sp--;
			*sp /= *(sp + 1);
			break;
		case OP_REM:
			if (sp < &stack[1])
				return (0);
			sp--;
			*sp %= *(sp + 1);
			break;
		case OP_OFFSET_POP:
			if (offp < &offstack[0])
				return (0);
			base = *offp--;
			if (opkt != NULL) {
				pkt = opkt;
				len = olen;
				opkt = NULL;
			}
			break;
		case OP_OFFSET_ZERO:
			if (offp >= &offstack[MAXSS])
				return (0);
			*++offp = base;
			base = pkt;
			break;
		case OP_OFFSET_LINK:
			if (offp >= &offstack[MAXSS])
				return (0);
			*++offp = base;
			base = pkt + header_size;
			/*
			 * If the offset exceeds the packet length,
			 * we should not be interested in this packet...
			 * Just return 0.
			 */
			if (base > pkt + len) {
				return (0);
			}
			break;
		case OP_OFFSET_IP:
			if (offp >= &offstack[MAXSS])
				return (0);
			*++offp = base;
			ip = pkt + header_size;
			base = ip + ip_hdr_len(ip);
			if (base == ip) {
				return (0);			/* not IP */
			}
			if (base > pkt + len) {
				return (0);			/* bad pkt */
			}
			break;
		case OP_OFFSET_TCP:
			if (offp >= &offstack[MAXSS])
				return (0);
			*++offp = base;
			ip = pkt + header_size;
			tcp = ip + ip_hdr_len(ip);
			if (tcp == ip) {
				return (0);			    /* not IP */
			}
			base = tcp + TCP_HDR_LEN(tcp);
			if (base > pkt + len) {
				return (0);
			}
			break;
		case OP_OFFSET_UDP:
			if (offp >= &offstack[MAXSS])
				return (0);
			*++offp = base;
			ip = pkt + header_size;
			udp = ip + ip_hdr_len(ip);
			if (udp == ip) {
				return (0);			    /* not IP */
			}
			base = udp + sizeof (struct udphdr);
			if (base > pkt + len) {
				return (0);
			}
			break;
		case OP_OFFSET_RPC:
			if (offp >= &offstack[MAXSS])
				return (0);
			*++offp = base;
			ip = pkt + header_size;
			rpc = NULL;

			if (IP_VERS(ip) != IPV4_VERSION &&
			    IP_VERS(ip) != IPV6_VERSION) {
				if (sp >= &stack[MAXSS])
					return (0);
				*(++sp) = 0;
				break;
			}

			switch (ip_proto_of(ip)) {
			case IPPROTO_UDP:
				udp = ip + ip_hdr_len(ip);
				rpc = (struct rpc_msg *)(udp +
				    sizeof (struct udphdr));
				break;
			case IPPROTO_TCP:
				tcp = ip + ip_hdr_len(ip);
				/*
				 * Need to skip an extra 4 for the xdr_rec
				 * field.
				 */
				rpc = (struct rpc_msg *)(tcp +
				    TCP_HDR_LEN(tcp) + 4);
				break;
			}
			/*
			 * We need to have at least 24 bytes of a RPC
			 * packet to look at to determine the validity
			 * of it.
			 */
			if (rpc == NULL || (uchar_t *)rpc + 24 > pkt + len) {
				if (sp >= &stack[MAXSS])
					return (0);
				*(++sp) = 0;
				break;
			}
			/* align */
			(void) memcpy(&rpcmsg, rpc, 24);
			if (!valid_rpc((char *)&rpcmsg, 24)) {
				if (sp >= &stack[MAXSS])
					return (0);
				*(++sp) = 0;
				break;
			}
			if (ntohl(rpcmsg.rm_direction) == CALL) {
				base = (uchar_t *)rpc;
				newrpc = 1;
				if (sp >= &stack[MAXSS])
					return (0);
				*(++sp) = 1;
			} else {
				opkt = pkt;
				olen = len;

				pkt = base = (uchar_t *)find_rpc(&rpcmsg);
				len = sizeof (struct xid_entry);
				if (sp >= &stack[MAXSS])
					return (0);
				*(++sp) = base != NULL;
			}
			break;
		case OP_OFFSET_SLP:
			slphdr = NULL;
			ip = pkt + header_size;

			if (IP_VERS(ip) != IPV4_VERSION &&
			    IP_VERS(ip) != IPV6_VERSION) {
				if (sp >= &stack[MAXSS])
					return (0);
				*(++sp) = 0;
				break;
			}

			switch (ip_proto_of(ip)) {
				struct udphdr udp_h;
				struct tcphdr tcp_h;
			case IPPROTO_UDP:
				udp = ip + ip_hdr_len(ip);
				/* align */
				memcpy(&udp_h, udp, sizeof (udp_h));
				slp_sport = ntohs(udp_h.uh_sport);
				slp_dport = ntohs(udp_h.uh_dport);
				slphdr = udp + sizeof (struct udphdr);
				break;
			case IPPROTO_TCP:
				tcp = ip + ip_hdr_len(ip);
				/* align */
				memcpy(&tcp_h, tcp, sizeof (tcp_h));
				slp_sport = ntohs(tcp_h.th_sport);
				slp_dport = ntohs(tcp_h.th_dport);
				slphdr = tcp + TCP_HDR_LEN(tcp);
				break;
			}
			if (slphdr == NULL || slphdr > pkt + len) {
				if (sp >= &stack[MAXSS])
					return (0);
				*(++sp) = 0;
				break;
			}
			if (slp_sport == 427 || slp_dport == 427) {
				if (sp >= &stack[MAXSS])
					return (0);
				*(++sp) = 1;
				if (slp_sport != 427 && slp_dport == 427)
					stash_slp(slp_sport);
				break;
			} else if (find_slp(slp_dport) != -1) {
				if (valid_slp(slphdr, len)) {
					if (sp >= &stack[MAXSS])
						return (0);
					*(++sp) = 1;
					break;
				}
				/* else fallthrough to reject */
			}
			if (sp >= &stack[MAXSS])
				return (0);
			*(++sp) = 0;
			break;
		case OP_OFFSET_ETHERTYPE:
			/*
			 * Set base to the location of the ethertype as
			 * appropriate for this link type.  Note that it's
			 * not called "ethertype" for every link type, but
			 * we need to call it something.
			 */
			if (offp >= &offstack[MAXSS])
				return (0);
			*++offp = base;
			base = pkt + interface->network_type_offset;

			/*
			 * Below, we adjust the offset for unusual
			 * link-layer headers that may have the protocol
			 * type in a variable location beyond what was set
			 * above.
			 */
			switch (interface->mac_type) {
			case DL_ETHER:
			case DL_CSMACD:
				/*
				 * If this is a VLAN-tagged packet, we need
				 * to point to the ethertype field in the
				 * VLAN header.  Move past the ethertype
				 * field in the ethernet header.
				 */
				if (ntohs(get_u16(base)) == ETHERTYPE_VLAN)
					base += (ENCAP_ETHERTYPE_OFF);
				break;
			}
			if (base > pkt + len) {
				/* Went too far, drop the packet */
				return (0);
			}
			break;
		}
	}

	if (*sp && newrpc)
		stash_rpc(&rpcmsg);

	return (*sp);
}

static void
load_const(uint_t constval)
{
	emitop(OP_LOAD_CONST);
	emitval(constval);
}

static void
load_value(int offset, int len)
{
	if (offset >= 0)
		load_const(offset);

	switch (len) {
		case 1:
			emitop(OP_LOAD_OCTET);
			break;
		case 2:
			emitop(OP_LOAD_SHORT);
			break;
		case 4:
			emitop(OP_LOAD_LONG);
			break;
	}
}

/*
 * Emit code to compare a field in
 * the packet against a constant value.
 */
static void
compare_value(uint_t offset, uint_t len, uint_t val)
{
	load_const(val);
	load_value(offset, len);
	emitop(OP_EQ);
}

static void
compare_addr_v4(uint_t offset, uint_t len, uint_t val)
{
	load_const(ntohl(val));
	load_value(offset, len);
	emitop(OP_EQ);
}

static void
compare_addr_v6(uint_t offset, uint_t len, struct in6_addr val)
{
	int i;
	uint32_t value;

	for (i = 0; i < len; i += 4) {
		value = ntohl(*(uint32_t *)&val.s6_addr[i]);
		load_const(value);
		load_value(offset + i, 4);
		emitop(OP_EQ);
		if (i != 0)
			emitop(OP_AND);
	}
}

/*
 * Same as above except do the comparison
 * after and'ing a mask value.  Useful
 * for comparing IP network numbers
 */
static void
compare_value_mask(uint_t offset, uint_t len, uint_t val, int mask)
{
	load_value(offset, len);
	load_const(mask);
	emitop(OP_AND);
	load_const(val);
	emitop(OP_EQ);
}

/*
 * Compare two zoneid's. The arg val passed in is stored in network
 * byte order.
 */
static void
compare_value_zone(uint_t offset, uint32_t val)
{
	load_const(ntohl(val));
	load_value(offset, 4);
	emitop(OP_EQ);
}

/* Emit an operator into the code array */
static void
emitop(enum optype opcode)
{
	if (curr_op >= &oplist[MAXOPS])
		pr_err("expression too long");
	*curr_op++ = opcode;
}

/*
 * Remove n operators recently emitted into
 * the code array.  Used by alternation().
 */
static void
unemit(int numops)
{
	curr_op -= numops;
}


/*
 * Same as emitop except that we're emitting
 * a value that's not an operator.
 */
static void
emitval(uint_t val)
{
	if (curr_op >= &oplist[MAXOPS])
		pr_err("expression too long");
	*curr_op++ = val;
}

/*
 * Used to chain forward branches together
 * for later resolution by resolve_chain().
 */
static uint_t
chain(int p)
{
	uint_t pos = curr_op - oplist;

	emitval(p);
	return (pos);
}

/*
 * Proceed backward through the code array
 * following a chain of forward references.
 * At each reference install the destination
 * branch offset.
 */
static void
resolve_chain(uint_t p)
{
	uint_t n;
	uint_t pos = curr_op - oplist;

	while (p) {
		n = oplist[p];
		oplist[p] = pos;
		p = n;
	}
}

#define	EQ(val) (strcmp(token, val) == 0)

char *tkp, *sav_tkp;
char *token;
enum { EOL, ALPHA, NUMBER, FIELD, ADDR_IP, ADDR_ETHER, SPECIAL,
	ADDR_IP6, ADDR_AT } tokentype;
uint_t tokenval;

/*
 * This is the scanner.  Each call returns the next
 * token in the filter expression.  A token is either:
 * EOL:		The end of the line - no more tokens.
 * ALPHA:	A name that begins with a letter and contains
 *		letters or digits, hyphens or underscores.
 * NUMBER:	A number.  The value can be represented as
 * 		a decimal value (1234) or an octal value
 *		that begins with zero (066) or a hex value
 *		that begins with 0x or 0X (0xff).
 * FIELD:	A name followed by a left square bracket.
 * ADDR_IP:	An IP address.  Any sequence of digits
 *		separated by dots e.g. 109.104.40.13
 * ADDR_ETHER:	An ethernet address.  Any sequence of hex
 *		digits separated by colons e.g. 8:0:20:0:76:39
 * SPECIAL:	A special character e.g. ">" or "(".  The scanner
 *		correctly handles digraphs - two special characters
 *		that constitute a single token e.g. "==" or ">=".
 * ADDR_IP6:    An IPv6 address.
 *
 * ADDR_AT:	An AppleTalk Phase II address. A sequence of two numbers
 *		separated by a dot.
 *
 * The current token is maintained in "token" and and its
 * type in "tokentype".  If tokentype is NUMBER then the
 * value is held in "tokenval".
 */

static const char *namechars =
	"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.";
static const char *numchars = "0123456789abcdefABCDEFXx:.";

void
next()
{
	static int savechar;
	char *p;
	int size, size1;
	int base, colons, dots, alphas, double_colon;

	colons = 0;
	double_colon = 0;

	if (*tkp == '\0') {
		token = tkp;
		*tkp = savechar;
	}

	sav_tkp = tkp;

	while (isspace(*tkp)) tkp++;
	token = tkp;
	if (*token == '\0') {
		tokentype = EOL;
		return;
	}

	/* A token containing ':' cannot be ALPHA type */
	tkp = token + strspn(token, numchars);
	for (p = token; p < tkp; p++) {
		if (*p == ':') {
			colons++;
			if (*(p+1) == ':')
				double_colon++;
		}
	}

	tkp = token;
	if (isalpha(*tkp) && !colons) {
		tokentype = ALPHA;
		tkp += strspn(tkp, namechars);
		if (*tkp == '[') {
			tokentype = FIELD;
			*tkp++ = '\0';
		}
	} else

	/*
	 * RFC1123 states that host names may now start with digits. Need
	 * to change parser to account for this. Also, need to distinguish
	 * between 1.2.3.4 and 1.2.3.a where the first case is an IP address
	 * and the second is a domain name. 333aaa needs to be distinguished
	 * from 0x333aaa. The first is a host name and the second is a number.
	 *
	 * The (colons > 1) conditional differentiates between ethernet
	 * and IPv6 addresses, and an expression of the form base[expr:size],
	 * which can only contain one ':' character.
	 */
	if (isdigit(*tkp) || colons > 1) {
		tkp = token + strspn(token, numchars);
		dots = alphas = 0;
		for (p = token; p < tkp; p++) {
			if (*p == '.')
				dots++;
			else if (isalpha(*p))
				alphas = 1;
		}
		if (colons > 1) {
			if (colons == 5 && double_colon == 0) {
				tokentype = ADDR_ETHER;
			} else {
				tokentype = ADDR_IP6;
			}
		} else if (dots) {
			size = tkp - token;
			size1 = strspn(token, "0123456789.");
			if (dots == 1 && size == size1) {
				tokentype = ADDR_AT;
			} else
				if (dots != 3 || size != size1) {
					tokentype = ALPHA;
					if (*tkp != '\0' && !isspace(*tkp)) {
						tkp += strspn(tkp, namechars);
						if (*tkp == '[') {
							tokentype = FIELD;
							*tkp++ = '\0';
						}
					}
				} else
					tokentype = ADDR_IP;
		} else if (token + strspn(token, namechars) <= tkp) {
			/*
			 * With the above check, if there are more
			 * characters after the last digit, assume
			 * that it is not a number.
			 */
			tokentype = NUMBER;
			p = tkp;
			tkp = token;
			base = 10;
			if (*tkp == '0') {
				base = 8;
				tkp++;
				if (*tkp == 'x' || *tkp == 'X')
					base = 16;
			}
			if ((base == 10 || base == 8) && alphas) {
				tokentype = ALPHA;
				tkp = p;
			} else if (base == 16) {
				size = 2 + strspn(token+2,
				    "0123456789abcdefABCDEF");
				size1 = p - token;
				if (size != size1) {
					tokentype = ALPHA;
					tkp = p;
				} else
				/*
				 * handles the case of 0x so an error message
				 * is not printed. Treats 0x as 0.
				 */
				if (size == 2) {
					tokenval = 0;
					tkp = token +2;
				} else {
					tokenval = strtoul(token, &tkp, base);
				}
			} else {
				tokenval = strtoul(token, &tkp, base);
			}
		} else {
			tokentype = ALPHA;
			tkp += strspn(tkp, namechars);
			if (*tkp == '[') {
				tokentype = FIELD;
				*tkp++ = '\0';
			}
		}
	} else {
		tokentype = SPECIAL;
		tkp++;
		if ((*token == '=' && *tkp == '=') ||
		    (*token == '>' && *tkp == '=') ||
		    (*token == '<' && *tkp == '=') ||
		    (*token == '!' && *tkp == '='))
				tkp++;
	}

	savechar = *tkp;
	*tkp = '\0';
}

typedef struct match_type {
	char		*m_name;
	int		m_offset;
	int		m_size;
	int		m_value;
	int		m_depend;
	enum optype	m_optype;
} match_type_t;

static match_type_t ether_match_types[] = {
	/*
	 * Table initialized assuming Ethernet data link headers.
	 * m_offset is an offset beyond the offset op, which is why
	 * the offset is zero for when snoop needs to check an ethertype.
	 */
	"ip",		0,  2, ETHERTYPE_IP,	 -1,	OP_OFFSET_ETHERTYPE,
	"ip6",		0,  2, ETHERTYPE_IPV6,	 -1,	OP_OFFSET_ETHERTYPE,
	"arp",		0,  2, ETHERTYPE_ARP,	 -1,	OP_OFFSET_ETHERTYPE,
	"rarp",		0,  2, ETHERTYPE_REVARP, -1,	OP_OFFSET_ETHERTYPE,
	"pppoed",	0,  2, ETHERTYPE_PPPOED, -1,	OP_OFFSET_ETHERTYPE,
	"pppoes",	0,  2, ETHERTYPE_PPPOES, -1,	OP_OFFSET_ETHERTYPE,
	"tcp",		9,  1, IPPROTO_TCP,	 0,	OP_OFFSET_LINK,
	"tcp",		6,  1, IPPROTO_TCP,	 1,	OP_OFFSET_LINK,
	"udp",		9,  1, IPPROTO_UDP,	 0,	OP_OFFSET_LINK,
	"udp",		6,  1, IPPROTO_UDP,	 1,	OP_OFFSET_LINK,
	"icmp",		9,  1, IPPROTO_ICMP,	 0,	OP_OFFSET_LINK,
	"icmp6",	6,  1, IPPROTO_ICMPV6,	 1,	OP_OFFSET_LINK,
	"ospf",		9,  1, IPPROTO_OSPF,	 0,	OP_OFFSET_LINK,
	"ospf",		6,  1, IPPROTO_OSPF,	 1,	OP_OFFSET_LINK,
	"ip-in-ip",	9,  1, IPPROTO_ENCAP,	 0,	OP_OFFSET_LINK,
	"esp",		9,  1, IPPROTO_ESP,	 0,	OP_OFFSET_LINK,
	"esp",		6,  1, IPPROTO_ESP,	 1,	OP_OFFSET_LINK,
	"ah",		9,  1, IPPROTO_AH,	 0,	OP_OFFSET_LINK,
	"ah",		6,  1, IPPROTO_AH,	 1,	OP_OFFSET_LINK,
	"sctp",		9,  1, IPPROTO_SCTP,	 0,	OP_OFFSET_LINK,
	"sctp",		6,  1, IPPROTO_SCTP,	 1,	OP_OFFSET_LINK,
	0,		0,  0, 0,		 0,	0
};

static match_type_t ipnet_match_types[] = {
	/*
	 * Table initialized assuming Ethernet data link headers.
	 * m_offset is an offset beyond the offset op, which is why
	 * the offset is zero for when snoop needs to check an ethertype.
	 */
	"ip",		0,  1, IPV4_VERSION,    -1,	OP_OFFSET_ETHERTYPE,
	"ip6",		0,  1, IPV6_VERSION,    -1,	OP_OFFSET_ETHERTYPE,
	"tcp",		9,  1, IPPROTO_TCP,	 0,	OP_OFFSET_LINK,
	"tcp",		6,  1, IPPROTO_TCP,	 1,	OP_OFFSET_LINK,
	"udp",		9,  1, IPPROTO_UDP,	 0,	OP_OFFSET_LINK,
	"udp",		6,  1, IPPROTO_UDP,	 1,	OP_OFFSET_LINK,
	"icmp",		9,  1, IPPROTO_ICMP,	 0,	OP_OFFSET_LINK,
	"icmp6",	6,  1, IPPROTO_ICMPV6,	 1,	OP_OFFSET_LINK,
	"ospf",		9,  1, IPPROTO_OSPF,	 0,	OP_OFFSET_LINK,
	"ospf",		6,  1, IPPROTO_OSPF,	 1,	OP_OFFSET_LINK,
	"ip-in-ip",	9,  1, IPPROTO_ENCAP,	 0,	OP_OFFSET_LINK,
	"esp",		9,  1, IPPROTO_ESP,	 0,	OP_OFFSET_LINK,
	"esp",		6,  1, IPPROTO_ESP,	 1,	OP_OFFSET_LINK,
	"ah",		9,  1, IPPROTO_AH,	 0,	OP_OFFSET_LINK,
	"ah",		6,  1, IPPROTO_AH,	 1,	OP_OFFSET_LINK,
	"sctp",		9,  1, IPPROTO_SCTP,	 0,	OP_OFFSET_LINK,
	"sctp",		6,  1, IPPROTO_SCTP,	 1,	OP_OFFSET_LINK,
	0,		0,  0, 0,		 0,	0
};

static match_type_t iptun_match_types[] = {
	"ip",		0,  1, IPPROTO_ENCAP,	-1,	OP_OFFSET_ETHERTYPE,
	"ip6",		0,  1, IPPROTO_IPV6,	-1,	OP_OFFSET_ETHERTYPE,
	"tcp",		9,  1, IPPROTO_TCP,	0,	OP_OFFSET_LINK,
	"tcp",		6,  1, IPPROTO_TCP,	1,	OP_OFFSET_LINK,
	"udp",		9,  1, IPPROTO_UDP,	0,	OP_OFFSET_LINK,
	"udp",		6,  1, IPPROTO_UDP,	1,	OP_OFFSET_LINK,
	"icmp",		9,  1, IPPROTO_ICMP,	0,	OP_OFFSET_LINK,
	"icmp6",	6,  1, IPPROTO_ICMPV6,	1,	OP_OFFSET_LINK,
	"ospf",		9,  1, IPPROTO_OSPF,	0,	OP_OFFSET_LINK,
	"ospf",		6,  1, IPPROTO_OSPF,	1,	OP_OFFSET_LINK,
	"ip-in-ip",	9,  1, IPPROTO_ENCAP,	0,	OP_OFFSET_LINK,
	"esp",		9,  1, IPPROTO_ESP,	0,	OP_OFFSET_LINK,
	"esp",		6,  1, IPPROTO_ESP,	1,	OP_OFFSET_LINK,
	"ah",		9,  1, IPPROTO_AH,	0,	OP_OFFSET_LINK,
	"ah",		6,  1, IPPROTO_AH,	1,	OP_OFFSET_LINK,
	"sctp",		9,  1, IPPROTO_SCTP,	0,	OP_OFFSET_LINK,
	"sctp",		6,  1, IPPROTO_SCTP,	1,	OP_OFFSET_LINK,
	0,		0,  0, 0,		0,	0
};

static void
generate_check(match_type_t match_types[], int index, int type)
{
	match_type_t *mtp = &match_types[index];
	/*
	 * Note: this code assumes the above dependencies are
	 * not cyclic.  This *should* always be true.
	 */
	if (mtp->m_depend != -1)
		generate_check(match_types, mtp->m_depend, type);

	emitop(mtp->m_optype);
	load_value(mtp->m_offset, mtp->m_size);
	load_const(mtp->m_value);
	emitop(OP_OFFSET_POP);

	emitop(OP_EQ);

	if (mtp->m_depend != -1)
		emitop(OP_AND);
}

/*
 * Generate code based on the keyword argument.
 * This word is looked up in the match_types table
 * and checks a field within the packet for a given
 * value e.g. ether or ip type field.  The match
 * can also have a dependency on another entry e.g.
 * "tcp" requires that the packet also be "ip".
 */
static int
comparison(char *s)
{
	unsigned int	i, n_checks = 0;
	match_type_t	*match_types;

	switch (interface->mac_type) {
	case DL_ETHER:
		match_types = ether_match_types;
		break;
	case DL_IPNET:
		match_types = ipnet_match_types;
		break;
	case DL_IPV4:
	case DL_IPV6:
	case DL_6TO4:
		match_types = iptun_match_types;
		break;
	default:
		return (0);
	}

	for (i = 0; match_types[i].m_name != NULL; i++) {
		if (strcmp(s, match_types[i].m_name) != 0)
			continue;

		n_checks++;
		generate_check(match_types, i, interface->mac_type);
		if (n_checks > 1)
			emitop(OP_OR);
	}

	return (n_checks > 0);
}

enum direction { ANY, TO, FROM };
enum direction dir;

/*
 * Generate code to match an IP address.  The address
 * may be supplied either as a hostname or in dotted format.
 * For source packets both the IP source address and ARP
 * src are checked.
 * Note: we don't check packet type here - whether IP or ARP.
 * It's possible that we'll do an improper match.
 */
static void
ipaddr_match(enum direction which, char *hostname, int inet_type)
{
	bool_t found_host;
	int m = 0, n = 0;
	uint_t *addr4ptr;
	uint_t addr4;
	struct in6_addr *addr6ptr;
	int h_addr_index;
	struct hostent *hp = NULL;
	int error_num = 0;
	boolean_t freehp = B_FALSE;
	boolean_t first = B_TRUE;

	/*
	 * The addr4offset and addr6offset variables simplify the code which
	 * generates the address comparison filter.  With these two variables,
	 * duplicate code need not exist for the TO and FROM case.
	 * A value of -1 describes the ANY case (TO and FROM).
	 */
	int addr4offset;
	int addr6offset;

	found_host = 0;

	if (tokentype == ADDR_IP) {
		hp = lgetipnodebyname(hostname, AF_INET, 0, &error_num);
		if (hp == NULL) {
			hp = getipnodebyname(hostname, AF_INET, 0, &error_num);
			freehp = 1;
		}
		if (hp == NULL) {
			if (error_num == TRY_AGAIN) {
				pr_err("couldn't resolve %s (try again later)",
				    hostname);
			} else {
				pr_err("couldn't resolve %s", hostname);
			}
		}
		inet_type = IPV4_ONLY;
	} else if (tokentype == ADDR_IP6) {
		hp = lgetipnodebyname(hostname, AF_INET6, 0, &error_num);
		if (hp == NULL) {
			hp = getipnodebyname(hostname, AF_INET6, 0, &error_num);
			freehp = 1;
		}
		if (hp == NULL) {
			if (error_num == TRY_AGAIN) {
				pr_err("couldn't resolve %s (try again later)",
				    hostname);
			} else {
				pr_err("couldn't resolve %s", hostname);
			}
		}
		inet_type = IPV6_ONLY;
	} else {
		/* Some hostname i.e. tokentype is ALPHA */
		switch (inet_type) {
		case IPV4_ONLY:
			/* Only IPv4 address is needed */
			hp = lgetipnodebyname(hostname, AF_INET, 0, &error_num);
			if (hp == NULL) {
				hp = getipnodebyname(hostname, AF_INET,	0,
				    &error_num);
				freehp = 1;
			}
			if (hp != NULL) {
				found_host = 1;
			}
			break;
		case IPV6_ONLY:
			/* Only IPv6 address is needed */
			hp = lgetipnodebyname(hostname, AF_INET6, 0,
			    &error_num);
			if (hp == NULL) {
				hp = getipnodebyname(hostname, AF_INET6, 0,
				    &error_num);
				freehp = 1;
			}
			if (hp != NULL) {
				found_host = 1;
			}
			break;
		case IPV4_AND_IPV6:
			/* Both IPv4 and IPv6 are needed */
			hp = lgetipnodebyname(hostname, AF_INET6,
			    AI_ALL | AI_V4MAPPED, &error_num);
			if (hp == NULL) {
				hp = getipnodebyname(hostname, AF_INET6,
				    AI_ALL | AI_V4MAPPED, &error_num);
				freehp = 1;
			}
			if (hp != NULL) {
				found_host = 1;
			}
			break;
		default:
			found_host = 0;
		}

		if (!found_host) {
			if (error_num == TRY_AGAIN) {
				pr_err("could not resolve %s (try again later)",
				    hostname);
			} else {
				pr_err("could not resolve %s", hostname);
			}
		}
	}

	if (hp == NULL)
		return;

	switch (which) {
	case TO:
		addr4offset = IPV4_DSTADDR_OFFSET;
		addr6offset = IPV6_DSTADDR_OFFSET;
		break;
	case FROM:
		addr4offset = IPV4_SRCADDR_OFFSET;
		addr6offset = IPV6_SRCADDR_OFFSET;
		break;
	case ANY:
		addr4offset = -1;
		addr6offset = -1;
		break;
	}

	/*
	 * The code below generates the filter.
	 */
	if (hp->h_addrtype == AF_INET) {
		ethertype_match(interface->network_type_ip);
		emitop(OP_BRFL);
		n = chain(n);
		emitop(OP_OFFSET_LINK);
		h_addr_index = 0;
		addr4ptr = (uint_t *)hp->h_addr_list[h_addr_index];
		while (addr4ptr != NULL) {
			if (addr4offset == -1) {
				compare_addr_v4(IPV4_SRCADDR_OFFSET, 4,
				    *addr4ptr);
				emitop(OP_BRTR);
				m = chain(m);
				compare_addr_v4(IPV4_DSTADDR_OFFSET, 4,
				    *addr4ptr);
			} else {
				compare_addr_v4(addr4offset, 4, *addr4ptr);
			}
			addr4ptr = (uint_t *)hp->h_addr_list[++h_addr_index];
			if (addr4ptr != NULL) {
				emitop(OP_BRTR);
				m = chain(m);
			}
		}
		if (m != 0) {
			resolve_chain(m);
		}
		emitop(OP_OFFSET_POP);
		resolve_chain(n);
	} else {
		/* first pass: IPv4 addresses */
		h_addr_index = 0;
		addr6ptr = (struct in6_addr *)hp->h_addr_list[h_addr_index];
		first = B_TRUE;
		while (addr6ptr != NULL) {
			if (IN6_IS_ADDR_V4MAPPED(addr6ptr)) {
				if (first) {
					ethertype_match(
					    interface->network_type_ip);
					emitop(OP_BRFL);
					n = chain(n);
					emitop(OP_OFFSET_LINK);
					first = B_FALSE;
				} else {
					emitop(OP_BRTR);
					m = chain(m);
				}
				IN6_V4MAPPED_TO_INADDR(addr6ptr,
				    (struct in_addr *)&addr4);
				if (addr4offset == -1) {
					compare_addr_v4(IPV4_SRCADDR_OFFSET, 4,
					    addr4);
					emitop(OP_BRTR);
					m = chain(m);
					compare_addr_v4(IPV4_DSTADDR_OFFSET, 4,
					    addr4);
				} else {
					compare_addr_v4(addr4offset, 4, addr4);
				}
			}
			addr6ptr = (struct in6_addr *)
			    hp->h_addr_list[++h_addr_index];
		}
		/* second pass: IPv6 addresses */
		h_addr_index = 0;
		addr6ptr = (struct in6_addr *)hp->h_addr_list[h_addr_index];
		first = B_TRUE;
		while (addr6ptr != NULL) {
			if (!IN6_IS_ADDR_V4MAPPED(addr6ptr)) {
				if (first) {
					/*
					 * bypass check for IPv6 addresses
					 * when we have an IPv4 packet
					 */
					if (n != 0) {
						emitop(OP_BRTR);
						m = chain(m);
						emitop(OP_BRFL);
						m = chain(m);
						resolve_chain(n);
						n = 0;
					}
					ethertype_match(
					    interface->network_type_ipv6);
					emitop(OP_BRFL);
					n = chain(n);
					emitop(OP_OFFSET_LINK);
					first = B_FALSE;
				} else {
					emitop(OP_BRTR);
					m = chain(m);
				}
				if (addr6offset == -1) {
					compare_addr_v6(IPV6_SRCADDR_OFFSET,
					    16, *addr6ptr);
					emitop(OP_BRTR);
					m = chain(m);
					compare_addr_v6(IPV6_DSTADDR_OFFSET,
					    16, *addr6ptr);
				} else {
					compare_addr_v6(addr6offset, 16,
					    *addr6ptr);
				}
			}
			addr6ptr = (struct in6_addr *)
			    hp->h_addr_list[++h_addr_index];
		}
		if (m != 0) {
			resolve_chain(m);
		}
		emitop(OP_OFFSET_POP);
		resolve_chain(n);
	}

	/* only free struct hostent returned by getipnodebyname() */
	if (freehp) {
		freehostent(hp);
	}
}

/*
 * Match on zoneid. The arg zone passed in is in network byte order.
 */
static void
zone_match(enum direction which, uint32_t zone)
{

	switch (which) {
	case TO:
		compare_value_zone(IPNET_DSTZONE_OFFSET, zone);
		break;
	case FROM:
		compare_value_zone(IPNET_SRCZONE_OFFSET, zone);
		break;
	case ANY:
		compare_value_zone(IPNET_SRCZONE_OFFSET, zone);
		compare_value_zone(IPNET_DSTZONE_OFFSET, zone);
		emitop(OP_OR);
	}
}

/*
 * Generate code to match an AppleTalk address.  The address
 * must be given as two numbers with a dot between
 *
 */
static void
ataddr_match(enum direction which, char *hostname)
{
	uint_t net;
	uint_t node;
	uint_t m, n;

	sscanf(hostname, "%u.%u", &net, &node);

	emitop(OP_OFFSET_LINK);
	switch (which) {
	case TO:
		compare_value(AT_DST_NET_OFFSET, 2, net);
		emitop(OP_BRFL);
		m = chain(0);
		compare_value(AT_DST_NODE_OFFSET, 1, node);
		resolve_chain(m);
		break;
	case FROM:
		compare_value(AT_SRC_NET_OFFSET, 2, net);
		emitop(OP_BRFL);
		m = chain(0);
		compare_value(AT_SRC_NODE_OFFSET, 1, node);
		resolve_chain(m);
		break;
	case ANY:
		compare_value(AT_DST_NET_OFFSET, 2, net);
		emitop(OP_BRFL);
		m = chain(0);
		compare_value(AT_DST_NODE_OFFSET, 1, node);
		resolve_chain(m);
		emitop(OP_BRTR);
		n = chain(0);
		compare_value(AT_SRC_NET_OFFSET, 2, net);
		emitop(OP_BRFL);
		m = chain(0);
		compare_value(AT_SRC_NODE_OFFSET, 1, node);
		resolve_chain(m);
		resolve_chain(n);
		break;
	}
	emitop(OP_OFFSET_POP);
}

/*
 * Compare ethernet addresses. The address may
 * be provided either as a hostname or as a
 * 6 octet colon-separated address.
 */
static void
etheraddr_match(enum direction which, char *hostname)
{
	uint_t addr;
	ushort_t *addrp;
	int to_offset, from_offset;
	struct ether_addr e, *ep = NULL;
	int m;

	/*
	 * First, check the interface type for whether src/dest address
	 * is determinable; if not, retreat early.
	 */
	switch (interface->mac_type) {
	case DL_ETHER:
		from_offset = ETHERADDRL;
		to_offset = 0;
		break;

	case DL_IB:
		/*
		 * If an ethernet address is attempted to be used
		 * on an IPoIB interface, flag error. Link address
		 * based filtering is unsupported on IPoIB, so there
		 * is no ipibaddr_match() or parsing support for IPoIB
		 * 20 byte link addresses.
		 */
		pr_err("filter option unsupported on media");
		break;

	case DL_FDDI:
		from_offset = 7;
		to_offset = 1;
		break;

	default:
		/*
		 * Where do we find "ether" address for FDDI & TR?
		 * XXX can improve?  ~sparker
		 */
		load_const(1);
		return;
	}

	if (isxdigit(*hostname))
		ep = ether_aton(hostname);
	if (ep == NULL) {
		if (ether_hostton(hostname, &e))
			if (!arp_for_ether(hostname, &e))
				pr_err("cannot obtain ether addr for %s",
				    hostname);
		ep = &e;
	}
	memcpy(&addr, (ushort_t *)ep, 4);
	addrp = (ushort_t *)ep + 2;

	emitop(OP_OFFSET_ZERO);
	switch (which) {
	case TO:
		compare_value(to_offset, 4, ntohl(addr));
		emitop(OP_BRFL);
		m = chain(0);
		compare_value(to_offset + 4, 2, ntohs(*addrp));
		resolve_chain(m);
		break;
	case FROM:
		compare_value(from_offset, 4, ntohl(addr));
		emitop(OP_BRFL);
		m = chain(0);
		compare_value(from_offset + 4, 2, ntohs(*addrp));
		resolve_chain(m);
		break;
	case ANY:
		compare_value(to_offset, 4, ntohl(addr));
		compare_value(to_offset + 4, 2, ntohs(*addrp));
		emitop(OP_AND);
		emitop(OP_BRTR);
		m = chain(0);

		compare_value(from_offset, 4, ntohl(addr));
		compare_value(from_offset + 4, 2, ntohs(*addrp));
		emitop(OP_AND);
		resolve_chain(m);
		break;
	}
	emitop(OP_OFFSET_POP);
}

static void
ethertype_match(int val)
{
	int ether_offset = interface->network_type_offset;

	/*
	 * If the user is interested in ethertype VLAN,
	 * then we need to set the offset to the beginning of the packet.
	 * But if the user is interested in another ethertype,
	 * such as IPv4, then we need to take into consideration
	 * the fact that the packet might be VLAN tagged.
	 */
	if (interface->mac_type == DL_ETHER ||
	    interface->mac_type == DL_CSMACD) {
		if (val != ETHERTYPE_VLAN) {
			/*
			 * OP_OFFSET_ETHERTYPE puts us at the ethertype
			 * field whether or not there is a VLAN tag,
			 * so ether_offset goes to zero if we get here.
			 */
			emitop(OP_OFFSET_ETHERTYPE);
			ether_offset = 0;
		} else {
			emitop(OP_OFFSET_ZERO);
		}
	}
	compare_value(ether_offset, interface->network_type_len, val);
	if (interface->mac_type == DL_ETHER ||
	    interface->mac_type == DL_CSMACD) {
		emitop(OP_OFFSET_POP);
	}
}

/*
 * Match a network address.  The host part
 * is masked out.  The network address may
 * be supplied either as a netname or in
 * IP dotted format.  The mask to be used
 * for the comparison is assumed from the
 * address format (see comment below).
 */
static void
netaddr_match(enum direction which, char *netname)
{
	uint_t addr;
	uint_t mask = 0xff000000;
	uint_t m;
	struct netent *np;

	if (isdigit(*netname)) {
		addr = inet_network(netname);
	} else {
		np = getnetbyname(netname);
		if (np == NULL)
			pr_err("net %s not known", netname);
		addr = np->n_net;
	}

	/*
	 * Left justify the address and figure
	 * out a mask based on the supplied address.
	 * Set the mask according to the number of zero
	 * low-order bytes.
	 * Note: this works only for whole octet masks.
	 */
	if (addr) {
		while ((addr & ~mask) != 0) {
			mask |= (mask >> 8);
		}
	}

	emitop(OP_OFFSET_LINK);
	switch (which) {
	case TO:
		compare_value_mask(16, 4, addr, mask);
		break;
	case FROM:
		compare_value_mask(12, 4, addr, mask);
		break;
	case ANY:
		compare_value_mask(12, 4, addr, mask);
		emitop(OP_BRTR);
		m = chain(0);
		compare_value_mask(16, 4, addr, mask);
		resolve_chain(m);
		break;
	}
	emitop(OP_OFFSET_POP);
}

/*
 * Match either a UDP or TCP port number.
 * The port number may be provided either as
 * port name as listed in /etc/services ("nntp") or as
 * the port number itself (2049).
 */
static void
port_match(enum direction which, char *portname)
{
	struct servent *sp;
	uint_t m, port;

	if (isdigit(*portname)) {
		port = atoi(portname);
	} else {
		sp = getservbyname(portname, NULL);
		if (sp == NULL)
			pr_err("invalid port number or name: %s", portname);
		port = ntohs(sp->s_port);
	}

	emitop(OP_OFFSET_IP);

	switch (which) {
	case TO:
		compare_value(2, 2, port);
		break;
	case FROM:
		compare_value(0, 2, port);
		break;
	case ANY:
		compare_value(2, 2, port);
		emitop(OP_BRTR);
		m = chain(0);
		compare_value(0, 2, port);
		resolve_chain(m);
		break;
	}
	emitop(OP_OFFSET_POP);
}

/*
 * Generate code to match packets with a specific
 * RPC program number.  If the progname is a name
 * it is converted to a number via /etc/rpc.
 * The program version and/or procedure may be provided
 * as extra qualifiers.
 */
static void
rpc_match_prog(enum direction which, char *progname, int vers, int proc)
{
	struct rpcent *rpc;
	uint_t prog;
	uint_t m, n;

	if (isdigit(*progname)) {
		prog = atoi(progname);
	} else {
		rpc = (struct rpcent *)getrpcbyname(progname);
		if (rpc == NULL)
			pr_err("invalid program name: %s", progname);
		prog = rpc->r_number;
	}

	emitop(OP_OFFSET_RPC);
	emitop(OP_BRFL);
	n = chain(0);

	compare_value(12, 4, prog);
	emitop(OP_BRFL);
	m = chain(0);
	if (vers >= 0) {
		compare_value(16, 4, vers);
		emitop(OP_BRFL);
		m = chain(m);
	}
	if (proc >= 0) {
		compare_value(20, 4, proc);
		emitop(OP_BRFL);
		m = chain(m);
	}

	switch (which) {
	case TO:
		compare_value(4, 4, CALL);
		emitop(OP_BRFL);
		m = chain(m);
		break;
	case FROM:
		compare_value(4, 4, REPLY);
		emitop(OP_BRFL);
		m = chain(m);
		break;
	}
	resolve_chain(m);
	resolve_chain(n);
	emitop(OP_OFFSET_POP);
}

/*
 * Generate code to parse a field specification
 * and load the value of the field from the packet
 * onto the operand stack.
 * The field offset may be specified relative to the
 * beginning of the ether header, IP header, UDP header,
 * or TCP header.  An optional size specification may
 * be provided following a colon.  If no size is given
 * one byte is assumed e.g.
 *
 *	ether[0]	The first byte of the ether header
 *	ip[2:2]		The second 16 bit field of the IP header
 */
static void
load_field()
{
	int size = 1;
	int s;


	if (EQ("ether"))
		emitop(OP_OFFSET_ZERO);
	else if (EQ("ip") || EQ("ip6") || EQ("pppoed") || EQ("pppoes"))
		emitop(OP_OFFSET_LINK);
	else if (EQ("udp") || EQ("tcp") || EQ("icmp") || EQ("ip-in-ip") ||
	    EQ("ah") || EQ("esp"))
		emitop(OP_OFFSET_IP);
	else
		pr_err("invalid field type");
	next();
	s = opstack;
	expression();
	if (opstack != s + 1)
		pr_err("invalid field offset");
	opstack--;
	if (*token == ':') {
		next();
		if (tokentype != NUMBER)
			pr_err("field size expected");
		size = tokenval;
		if (size != 1 && size != 2 && size != 4)
			pr_err("field size invalid");
		next();
	}
	if (*token != ']')
		pr_err("right bracket expected");

	load_value(-1, size);
	emitop(OP_OFFSET_POP);
}

/*
 * Check that the operand stack
 * contains n arguments
 */
static void
checkstack(int numargs)
{
	if (opstack != numargs)
		pr_err("invalid expression at \"%s\".", token);
}

static void
primary()
{
	int m, m2, s;

	for (;;) {
		if (tokentype == FIELD) {
			load_field();
			opstack++;
			next();
			break;
		}

		if (comparison(token)) {
			opstack++;
			next();
			break;
		}

		if (EQ("not") || EQ("!")) {
			next();
			s = opstack;
			primary();
			checkstack(s + 1);
			emitop(OP_NOT);
			break;
		}

		if (EQ("(")) {
			next();
			s = opstack;
			expression();
			checkstack(s + 1);
			if (!EQ(")"))
				pr_err("right paren expected");
			next();
		}

		if (EQ("to") || EQ("dst")) {
			dir = TO;
			next();
			continue;
		}

		if (EQ("from") || EQ("src")) {
			dir = FROM;
			next();
			continue;
		}

		if (EQ("ether")) {
			eaddr = 1;
			next();
			continue;
		}

		if (EQ("proto")) {
			next();
			if (tokentype != NUMBER)
				pr_err("IP proto type expected");
			emitop(OP_OFFSET_LINK);
			compare_value(IPV4_TYPE_HEADER_OFFSET, 1, tokenval);
			emitop(OP_OFFSET_POP);
			opstack++;
			next();
			continue;
		}

		if (EQ("broadcast")) {
			/*
			 * Be tricky: FDDI ether dst address begins at
			 * byte one.  Since the address is really six
			 * bytes long, this works for FDDI & ethernet.
			 * XXX - Token ring?
			 */
			emitop(OP_OFFSET_ZERO);
			if (interface->mac_type == DL_IB)
				pr_err("filter option unsupported on media");
			compare_value(1, 4, 0xffffffff);
			emitop(OP_OFFSET_POP);
			opstack++;
			next();
			break;
		}

		if (EQ("multicast")) {
			/* XXX Token ring? */
			emitop(OP_OFFSET_ZERO);
			if (interface->mac_type == DL_FDDI) {
				compare_value_mask(1, 1, 0x01, 0x01);
			} else if (interface->mac_type == DL_IB) {
				pr_err("filter option unsupported on media");
			} else {
				compare_value_mask(0, 1, 0x01, 0x01);
			}
			emitop(OP_OFFSET_POP);
			opstack++;
			next();
			break;
		}

		if (EQ("decnet")) {
			/* XXX Token ring? */
			if (interface->mac_type == DL_FDDI) {
				load_value(19, 2);	/* ether type */
				load_const(0x6000);
				emitop(OP_GE);
				emitop(OP_BRFL);
				m = chain(0);
				load_value(19, 2);	/* ether type */
				load_const(0x6009);
				emitop(OP_LE);
				resolve_chain(m);
			} else {
				emitop(OP_OFFSET_ETHERTYPE);
				load_value(0, 2);	/* ether type */
				load_const(0x6000);
				emitop(OP_GE);
				emitop(OP_BRFL);
				m = chain(0);
				load_value(0, 2);	/* ether type */
				load_const(0x6009);
				emitop(OP_LE);
				resolve_chain(m);
				emitop(OP_OFFSET_POP);
			}
			opstack++;
			next();
			break;
		}

		if (EQ("vlan-id")) {
			next();
			if (tokentype != NUMBER)
				pr_err("vlan id expected");
			emitop(OP_OFFSET_ZERO);
			ethertype_match(ETHERTYPE_VLAN);
			emitop(OP_BRFL);
			m = chain(0);
			compare_value_mask(VLAN_ID_OFFSET, 2, tokenval,
			    VLAN_ID_MASK);
			resolve_chain(m);
			emitop(OP_OFFSET_POP);
			opstack++;
			next();
			break;
		}

		if (EQ("apple")) {
			/*
			 * Appletalk also appears in 802.2
			 * packets, so check for the ethertypes
			 * at offset 12 and 20 in the MAC header.
			 */
			ethertype_match(ETHERTYPE_AT);
			emitop(OP_BRTR);
			m = chain(0);
			ethertype_match(ETHERTYPE_AARP);
			emitop(OP_BRTR);
			m = chain(m);
			compare_value(20, 2, ETHERTYPE_AT); /* 802.2 */
			emitop(OP_BRTR);
			m = chain(m);
			compare_value(20, 2, ETHERTYPE_AARP); /* 802.2 */
			resolve_chain(m);
			opstack++;
			next();
			break;
		}

		if (EQ("vlan")) {
			ethertype_match(ETHERTYPE_VLAN);
			compare_value_mask(VLAN_ID_OFFSET, 2, 0, VLAN_ID_MASK);
			emitop(OP_NOT);
			emitop(OP_AND);
			opstack++;
			next();
			break;
		}

		if (EQ("bootp") || EQ("dhcp")) {
			ethertype_match(interface->network_type_ip);
			emitop(OP_BRFL);
			m = chain(0);
			emitop(OP_OFFSET_LINK);
			compare_value(9, 1, IPPROTO_UDP);
			emitop(OP_OFFSET_POP);
			emitop(OP_BRFL);
			m = chain(m);
			emitop(OP_OFFSET_IP);
			compare_value(0, 4,
			    (IPPORT_BOOTPS << 16) | IPPORT_BOOTPC);
			emitop(OP_BRTR);
			m2 = chain(0);
			compare_value(0, 4,
			    (IPPORT_BOOTPC << 16) | IPPORT_BOOTPS);
			resolve_chain(m2);
			emitop(OP_OFFSET_POP);
			resolve_chain(m);
			opstack++;
			dir = ANY;
			next();
			break;
		}

		if (EQ("dhcp6")) {
			ethertype_match(interface->network_type_ipv6);
			emitop(OP_BRFL);
			m = chain(0);
			emitop(OP_OFFSET_LINK);
			compare_value(6, 1, IPPROTO_UDP);
			emitop(OP_OFFSET_POP);
			emitop(OP_BRFL);
			m = chain(m);
			emitop(OP_OFFSET_IP);
			compare_value(2, 2, IPPORT_DHCPV6S);
			emitop(OP_BRTR);
			m2 = chain(0);
			compare_value(2, 2, IPPORT_DHCPV6C);
			resolve_chain(m2);
			emitop(OP_OFFSET_POP);
			resolve_chain(m);
			opstack++;
			dir = ANY;
			next();
			break;
		}

		if (EQ("ethertype")) {
			next();
			if (tokentype != NUMBER)
				pr_err("ether type expected");
			ethertype_match(tokenval);
			opstack++;
			next();
			break;
		}

		if (EQ("pppoe")) {
			ethertype_match(ETHERTYPE_PPPOED);
			ethertype_match(ETHERTYPE_PPPOES);
			emitop(OP_OR);
			opstack++;
			next();
			break;
		}

		if (EQ("inet")) {
			next();
			if (EQ("host"))
				next();
			if (tokentype != ALPHA && tokentype != ADDR_IP)
				pr_err("host/IPv4 addr expected after inet");
			ipaddr_match(dir, token, IPV4_ONLY);
			opstack++;
			next();
			break;
		}

		if (EQ("inet6")) {
			next();
			if (EQ("host"))
				next();
			if (tokentype != ALPHA && tokentype != ADDR_IP6)
				pr_err("host/IPv6 addr expected after inet6");
			ipaddr_match(dir, token, IPV6_ONLY);
			opstack++;
			next();
			break;
		}

		if (EQ("length")) {
			emitop(OP_LOAD_LENGTH);
			opstack++;
			next();
			break;
		}

		if (EQ("less")) {
			next();
			if (tokentype != NUMBER)
				pr_err("packet length expected");
			emitop(OP_LOAD_LENGTH);
			load_const(tokenval);
			emitop(OP_LT);
			opstack++;
			next();
			break;
		}

		if (EQ("greater")) {
			next();
			if (tokentype != NUMBER)
				pr_err("packet length expected");
			emitop(OP_LOAD_LENGTH);
			load_const(tokenval);
			emitop(OP_GT);
			opstack++;
			next();
			break;
		}

		if (EQ("nofrag")) {
			emitop(OP_OFFSET_LINK);
			compare_value_mask(6, 2, 0, 0x1fff);
			emitop(OP_OFFSET_POP);
			emitop(OP_BRFL);
			m = chain(0);
			ethertype_match(interface->network_type_ip);
			resolve_chain(m);
			opstack++;
			next();
			break;
		}

		if (EQ("net") || EQ("dstnet") || EQ("srcnet")) {
			if (EQ("dstnet"))
				dir = TO;
			else if (EQ("srcnet"))
				dir = FROM;
			next();
			netaddr_match(dir, token);
			dir = ANY;
			opstack++;
			next();
			break;
		}

		if (EQ("port") || EQ("srcport") || EQ("dstport")) {
			if (EQ("dstport"))
				dir = TO;
			else if (EQ("srcport"))
				dir = FROM;
			next();
			port_match(dir, token);
			dir = ANY;
			opstack++;
			next();
			break;
		}

		if (EQ("rpc")) {
			uint_t vers, proc;
			char savetoken[32];

			vers = proc = -1;
			next();
			(void) strlcpy(savetoken, token, sizeof (savetoken));
			next();
			if (*token == ',') {
				next();
				if (tokentype != NUMBER)
					pr_err("version number expected");
				vers = tokenval;
				next();
			}
			if (*token == ',') {
				next();
				if (tokentype != NUMBER)
					pr_err("proc number expected");
				proc = tokenval;
				next();
			}
			rpc_match_prog(dir, savetoken, vers, proc);
			dir = ANY;
			opstack++;
			break;
		}

		if (EQ("slp")) {
			/* filter out TCP handshakes */
			emitop(OP_OFFSET_LINK);
			compare_value(9, 1, IPPROTO_TCP);
			emitop(OP_LOAD_CONST);
			emitval(52);
			emitop(OP_LOAD_CONST);
			emitval(2);
			emitop(OP_LOAD_SHORT);
			emitop(OP_GE);
			emitop(OP_AND);	/* proto == TCP && len < 52 */
			emitop(OP_NOT);
			emitop(OP_BRFL); /* pkt too short to be a SLP call */
			m = chain(0);

			emitop(OP_OFFSET_POP);
			emitop(OP_OFFSET_SLP);
			resolve_chain(m);
			opstack++;
			next();
			break;
		}

		if (EQ("ldap")) {
			dir = ANY;
			port_match(dir, "ldap");
			opstack++;
			next();
			break;
		}

		if (EQ("and") || EQ("or")) {
			break;
		}

		if (EQ("zone")) {
			next();
			if (tokentype != NUMBER)
				pr_err("zoneid expected");
			zone_match(dir, BE_32((uint32_t)(tokenval)));
			opstack++;
			next();
			break;
		}

		if (EQ("gateway")) {
			next();
			if (eaddr || tokentype != ALPHA)
				pr_err("hostname required: %s", token);
			etheraddr_match(dir, token);
			dir = ANY;
			emitop(OP_BRFL);
			m = chain(0);
			ipaddr_match(dir, token, IPV4_AND_IPV6);
			emitop(OP_NOT);
			resolve_chain(m);
			opstack++;
			next();
		}

		if (EQ("host") || EQ("between") ||
		    tokentype == ALPHA ||	/* assume its a hostname */
		    tokentype == ADDR_IP ||
		    tokentype == ADDR_IP6 ||
		    tokentype == ADDR_AT ||
		    tokentype == ADDR_ETHER) {
			if (EQ("host") || EQ("between"))
				next();
			if (eaddr || tokentype == ADDR_ETHER) {
				etheraddr_match(dir, token);
			} else if (tokentype == ALPHA) {
				ipaddr_match(dir, token, IPV4_AND_IPV6);
			} else if (tokentype == ADDR_AT) {
				ataddr_match(dir, token);
			} else if (tokentype == ADDR_IP) {
				ipaddr_match(dir, token, IPV4_ONLY);
			} else {
				ipaddr_match(dir, token, IPV6_ONLY);
			}
			dir = ANY;
			eaddr = 0;
			opstack++;
			next();
			break;
		}

		if (tokentype == NUMBER) {
			load_const(tokenval);
			opstack++;
			next();
			break;
		}

		break;	/* unknown token */
	}
}

struct optable {
	char *op_tok;
	enum optype op_type;
};

static struct optable
mulops[] = {
	"*",	OP_MUL,
	"/",	OP_DIV,
	"%",	OP_REM,
	"&",	OP_AND,
	"",	OP_STOP,
};

static struct optable
addops[] = {
	"+",	OP_ADD,
	"-",	OP_SUB,
	"|",	OP_OR,
	"^",	OP_XOR,
	"",	OP_STOP,
};

static struct optable
compareops[] = {
	"==",	OP_EQ,
	"=",	OP_EQ,
	"!=",	OP_NE,
	">",	OP_GT,
	">=",	OP_GE,
	"<",	OP_LT,
	"<=",	OP_LE,
	"",	OP_STOP,
};

/*
 * Using the table, find the operator
 * that corresponds to the token.
 * Return 0 if not found.
 */
static int
find_op(char *tok, struct optable *table)
{
	struct optable *op;

	for (op = table; *op->op_tok; op++) {
		if (strcmp(tok, op->op_tok) == 0)
			return (op->op_type);
	}

	return (0);
}

static void
expr_mul()
{
	int op;
	int s = opstack;

	primary();
	while (op = find_op(token, mulops)) {
		next();
		primary();
		checkstack(s + 2);
		emitop(op);
		opstack--;
	}
}

static void
expr_add()
{
	int op, s = opstack;

	expr_mul();
	while (op = find_op(token, addops)) {
		next();
		expr_mul();
		checkstack(s + 2);
		emitop(op);
		opstack--;
	}
}

static void
expr_compare()
{
	int op, s = opstack;

	expr_add();
	while (op = find_op(token, compareops)) {
		next();
		expr_add();
		checkstack(s + 2);
		emitop(op);
		opstack--;
	}
}

/*
 * Alternation ("and") is difficult because
 * an implied "and" is acknowledge between
 * two adjacent primaries.  Just keep calling
 * the lower-level expression routine until
 * no value is added to the opstack.
 */
static void
alternation()
{
	int m = 0;
	int s = opstack;

	expr_compare();
	checkstack(s + 1);
	for (;;) {
		if (EQ("and"))
			next();
		emitop(OP_BRFL);
		m = chain(m);
		expr_compare();
		if (opstack != s + 2)
			break;
		opstack--;
	}
	unemit(2);
	resolve_chain(m);
}

static void
expression()
{
	int m = 0;
	int s = opstack;

	alternation();
	while (EQ("or") || EQ(",")) {
		emitop(OP_BRTR);
		m = chain(m);
		next();
		alternation();
		checkstack(s + 2);
		opstack--;
	}
	resolve_chain(m);
}

/*
 * Take n args from the argv list
 * and concatenate them into a single string.
 */
char *
concat_args(char **argv, int argc)
{
	int i, len;
	char *str, *p;

	/* First add the lengths of all the strings */
	len = 0;
	for (i = 0; i < argc; i++)
		len += strlen(argv[i]) + 1;

	/* allocate the big string */
	str = (char *)malloc(len);
	if (str == NULL)
		pr_err("no mem");

	p = str;

	/*
	 * Concat the strings into the big
	 * string using a space as separator
	 */
	for (i = 0; i < argc; i++) {
		strcpy(p, argv[i]);
		p += strlen(p);
		*p++ = ' ';
	}
	*--p = '\0';

	return (str);
}

/*
 * Take the expression in the string "expr"
 * and compile it into the code array.
 * Print the generated code if the print
 * arg is set.
 */
void
compile(char *expr, int print)
{
	expr = strdup(expr);
	if (expr == NULL)
		pr_err("no mem");
	curr_op = oplist;
	tkp = expr;
	dir = ANY;

	next();
	if (tokentype != EOL)
		expression();
	emitop(OP_STOP);
	if (tokentype != EOL)
		pr_err("invalid expression");
	optimize(oplist);
	if (print)
		codeprint();
}

/*
 * Lookup hostname in the arp cache.
 */
boolean_t
arp_for_ether(char *hostname, struct ether_addr *ep)
{
	struct arpreq ar;
	struct hostent *hp;
	struct sockaddr_in *sin;
	int error_num;
	int s;

	memset(&ar, 0, sizeof (ar));
	sin = (struct sockaddr_in *)&ar.arp_pa;
	sin->sin_family = AF_INET;
	hp = getipnodebyname(hostname, AF_INET, 0, &error_num);
	if (hp == NULL) {
		return (B_FALSE);
	}
	memcpy(&sin->sin_addr, hp->h_addr, sizeof (sin->sin_addr));
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		return (B_FALSE);
	}
	if (ioctl(s, SIOCGARP, &ar) < 0) {
		close(s);
		return (B_FALSE);
	}
	close(s);
	memcpy(ep->ether_addr_octet, ar.arp_ha.sa_data, sizeof (*ep));
	return (B_TRUE);
}
