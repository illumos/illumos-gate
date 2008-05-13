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

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS	*/

#include <stdio.h>
#include <stddef.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/isa_defs.h>

#include <sys/socket.h>
#include <sys/vlan.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <rpc/rpc.h>
#include <setjmp.h>

#include <sys/pfmod.h>
#include "snoop.h"
#include "snoop_vlan.h"

/*
 * This module generates code for the kernel packet filter.
 * The kernel packet filter is more efficient since it
 * operates without context switching or moving data into
 * the capture buffer.  On the other hand, it is limited
 * in its filtering ability i.e. can't cope with variable
 * length headers, can't compare the packet size, 1 and 4 octet
 * comparisons are awkward, code space is limited to ENMAXFILTERS
 * halfwords, etc.
 * The parser is the same for the user-level packet filter though
 * more limited in the variety of expressions it can generate
 * code for.  If the pf compiler finds an expression it can't
 * handle, it tries to set up a split filter in kernel and do the
 * remaining filtering in userland. If that also fails, it resorts
 * to userland filter. (See additional comment in pf_compile)
 */

extern struct Pf_ext_packetfilt pf;
static ushort_t *pfp;
jmp_buf env;

int eaddr;	/* need ethernet addr */

int opstack;	/* operand stack depth */

#define	EQ(val)		(strcmp(token, val) == 0)
#define	IPV4_ONLY	0
#define	IPV6_ONLY	1
#define	IPV4_AND_IPV6	2

/*
 * The following constants represent the offsets in bytes from the beginning
 * of the packet of the link and IP(v6) layer source/destination/type fields,
 * initialized for Ethernet. Media specific code can set any unavailable
 * link layer property's offset to -1 to indicate that the property's value
 * is not available from the frame.
 */
static int link_header_len = 14, link_type_offset = 12;
static int link_dest_offset = 0, link_src_offset = 6;
static int link_addr_len = 6;

#define	IPV4_SRCADDR_OFFSET	(link_header_len + 12)
#define	IPV4_DSTADDR_OFFSET	(link_header_len + 16)
#define	IPV6_SRCADDR_OFFSET	(link_header_len + 8)
#define	IPV6_DSTADDR_OFFSET	(link_header_len + 24)

static int inBrace = 0, inBraceOR = 0;
static int foundOR = 0;
char *tkp, *sav_tkp;
char *token;
enum { EOL, ALPHA, NUMBER, FIELD, ADDR_IP, ADDR_ETHER, SPECIAL,
	ADDR_IP6 } tokentype;
uint_t tokenval;

enum direction { ANY, TO, FROM };
enum direction dir;

extern void next();

static void pf_expression();
static void pf_check_vlan_tag(uint_t offset);
static void pf_clear_offset_register();
static void pf_emit_load_offset(uint_t offset);
static void pf_match_ethertype(uint_t ethertype);
static void pf_check_transport_protocol(uint_t transport_protocol);
static void pf_compare_value_mask_generic(int offset, uint_t len,
    uint_t val, int mask, uint_t op);

/*
 * This pointer points to the function that last generated
 * instructions to change the offset register.  It's used
 * for comparisons to see if we need to issue more instructions
 * to change the register.
 *
 * It's initialized to pf_clear_offset_register because the offset
 * register in pfmod is initialized to zero, similar to the state
 * it would be in after executing the instructions issued by
 * pf_clear_offset_register.
 */
static void *last_offset_operation = (void*)pf_clear_offset_register;

static void
pf_emit(x)
	ushort_t x;
{
	if (pfp > &pf.Pf_Filter[PF_MAXFILTERS - 1])
		longjmp(env, 1);
	*pfp++ = x;
}

static void
pf_codeprint(code, len)
	ushort_t *code;
	int len;
{
	ushort_t *pc;
	ushort_t *plast = code + len;
	int op, action;

	if (len > 0) {
		printf("Kernel Filter:\n");
	}

	for (pc = code; pc < plast; pc++) {
		printf("\t%3d: ", pc - code);

		op = *pc & 0xfc00;	/* high 10 bits */
		action = *pc & 0x3ff;	/* low   6 bits */

		switch (action) {
		case ENF_PUSHLIT:
			printf("PUSHLIT ");
			break;
		case ENF_PUSHZERO:
			printf("PUSHZERO ");
			break;
#ifdef ENF_PUSHONE
		case ENF_PUSHONE:
			printf("PUSHONE ");
			break;
#endif
#ifdef ENF_PUSHFFFF
		case ENF_PUSHFFFF:
			printf("PUSHFFFF ");
			break;
#endif
#ifdef ENF_PUSHFF00
		case ENF_PUSHFF00:
			printf("PUSHFF00 ");
			break;
#endif
#ifdef ENF_PUSH00FF
		case ENF_PUSH00FF:
			printf("PUSH00FF ");
			break;
#endif
		case ENF_LOAD_OFFSET:
			printf("LOAD_OFFSET ");
			break;
		case ENF_BRTR:
			printf("BRTR ");
			break;
		case ENF_BRFL:
			printf("BRFL ");
			break;
		case ENF_POP:
			printf("POP ");
			break;
		}

		if (action >= ENF_PUSHWORD)
			printf("PUSHWORD %d ", action - ENF_PUSHWORD);

		switch (op) {
		case ENF_EQ:
			printf("EQ ");
			break;
		case ENF_LT:
			printf("LT ");
			break;
		case ENF_LE:
			printf("LE ");
			break;
		case ENF_GT:
			printf("GT ");
			break;
		case ENF_GE:
			printf("GE ");
			break;
		case ENF_AND:
			printf("AND ");
			break;
		case ENF_OR:
			printf("OR ");
			break;
		case ENF_XOR:
			printf("XOR ");
			break;
		case ENF_COR:
			printf("COR ");
			break;
		case ENF_CAND:
			printf("CAND ");
			break;
		case ENF_CNOR:
			printf("CNOR ");
			break;
		case ENF_CNAND:
			printf("CNAND ");
			break;
		case ENF_NEQ:
			printf("NEQ ");
			break;
		}

		if (action == ENF_PUSHLIT ||
		    action == ENF_LOAD_OFFSET ||
		    action == ENF_BRTR ||
		    action == ENF_BRFL) {
			pc++;
			printf("\n\t%3d:   %d (0x%04x)", pc - code, *pc, *pc);
		}

		printf("\n");
	}
}

/*
 * Emit packet filter code to check a
 * field in the packet for a particular value.
 * Need different code for each field size.
 * Since the pf can only compare 16 bit quantities
 * we have to use masking to compare byte values.
 * Long word (32 bit) quantities have to be done
 * as two 16 bit comparisons.
 */
static void
pf_compare_value(int offset, uint_t len, uint_t val)
{
	/*
	 * If the property being filtered on is absent in the media
	 * packet, error out.
	 */
	if (offset == -1)
		pr_err("filter option unsupported on media");

	switch (len) {
	case 1:
		pf_emit(ENF_PUSHWORD + offset / 2);
#if defined(_BIG_ENDIAN)
		if (offset % 2)
#else
		if (!(offset % 2))
#endif
		{
#ifdef ENF_PUSH00FF
			pf_emit(ENF_PUSH00FF | ENF_AND);
#else
			pf_emit(ENF_PUSHLIT | ENF_AND);
			pf_emit(0x00FF);
#endif
			pf_emit(ENF_PUSHLIT | ENF_EQ);
			pf_emit(val);
		} else {
#ifdef ENF_PUSHFF00
			pf_emit(ENF_PUSHFF00 | ENF_AND);
#else
			pf_emit(ENF_PUSHLIT | ENF_AND);
			pf_emit(0xFF00);
#endif
			pf_emit(ENF_PUSHLIT | ENF_EQ);
			pf_emit(val << 8);
		}
		break;

	case 2:
		pf_emit(ENF_PUSHWORD + offset / 2);
		pf_emit(ENF_PUSHLIT | ENF_EQ);
		pf_emit((ushort_t)val);
		break;

	case 4:
		pf_emit(ENF_PUSHWORD + offset / 2);
		pf_emit(ENF_PUSHLIT | ENF_EQ);
#if defined(_BIG_ENDIAN)
		pf_emit(val >> 16);
#elif defined(_LITTLE_ENDIAN)
		pf_emit(val & 0xffff);
#else
#error One of _BIG_ENDIAN and _LITTLE_ENDIAN must be defined
#endif
		pf_emit(ENF_PUSHWORD + (offset / 2) + 1);
		pf_emit(ENF_PUSHLIT | ENF_EQ);
#if defined(_BIG_ENDIAN)
		pf_emit(val & 0xffff);
#else
		pf_emit(val >> 16);
#endif
		pf_emit(ENF_AND);
		break;
	}
}

/*
 * same as pf_compare_value, but only for emiting code to
 * compare ipv6 addresses.
 */
static void
pf_compare_value_v6(int offset, uint_t len, struct in6_addr val)
{
	int i;

	for (i = 0; i < len; i += 2) {
		pf_emit(ENF_PUSHWORD + offset / 2 + i / 2);
		pf_emit(ENF_PUSHLIT | ENF_EQ);
		pf_emit(*(uint16_t *)&val.s6_addr[i]);
		if (i != 0)
			pf_emit(ENF_AND);
	}
}


/*
 * Same as above except mask the field value
 * before doing the comparison.  The comparison checks
 * to make sure the values are equal.
 */
static void
pf_compare_value_mask(int offset, uint_t len, uint_t val, int mask)
{
	pf_compare_value_mask_generic(offset, len, val, mask, ENF_EQ);
}

/*
 * Same as above except the values are compared to see if they are not
 * equal.
 */
static void
pf_compare_value_mask_neq(int offset, uint_t len, uint_t val, int mask)
{
	pf_compare_value_mask_generic(offset, len, val, mask, ENF_NEQ);
}

/*
 * Similar to pf_compare_value.
 *
 * This is the utility function that does the actual work to compare
 * two values using a mask.  The comparison operation is passed into
 * the function.
 */
static void
pf_compare_value_mask_generic(int offset, uint_t len, uint_t val, int mask,
    uint_t op)
{
	/*
	 * If the property being filtered on is absent in the media
	 * packet, error out.
	 */
	if (offset == -1)
		pr_err("filter option unsupported on media");

	switch (len) {
	case 1:
		pf_emit(ENF_PUSHWORD + offset / 2);
#if defined(_BIG_ENDIAN)
		if (offset % 2)
#else
		if (!offset % 2)
#endif
		{
			pf_emit(ENF_PUSHLIT | ENF_AND);
			pf_emit(mask & 0x00ff);
			pf_emit(ENF_PUSHLIT | op);
			pf_emit(val);
		} else {
			pf_emit(ENF_PUSHLIT | ENF_AND);
			pf_emit((mask << 8) & 0xff00);
			pf_emit(ENF_PUSHLIT | op);
			pf_emit(val << 8);
		}
		break;

	case 2:
		pf_emit(ENF_PUSHWORD + offset / 2);
		pf_emit(ENF_PUSHLIT | ENF_AND);
		pf_emit(htons((ushort_t)mask));
		pf_emit(ENF_PUSHLIT | op);
		pf_emit(htons((ushort_t)val));
		break;

	case 4:
		pf_emit(ENF_PUSHWORD + offset / 2);
		pf_emit(ENF_PUSHLIT | ENF_AND);
		pf_emit(htons((ushort_t)((mask >> 16) & 0xffff)));
		pf_emit(ENF_PUSHLIT | op);
		pf_emit(htons((ushort_t)((val >> 16) & 0xffff)));

		pf_emit(ENF_PUSHWORD + (offset / 2) + 1);
		pf_emit(ENF_PUSHLIT | ENF_AND);
		pf_emit(htons((ushort_t)(mask & 0xffff)));
		pf_emit(ENF_PUSHLIT | op);
		pf_emit(htons((ushort_t)(val & 0xffff)));

		pf_emit(ENF_AND);
		break;
	}
}

/*
 * Generate pf code to match an IPv4 or IPv6 address.
 */
static void
pf_ipaddr_match(which, hostname, inet_type)
	enum direction which;
	char *hostname;
	int inet_type;
{
	bool_t found_host;
	uint_t *addr4ptr;
	uint_t addr4;
	struct in6_addr *addr6ptr;
	int h_addr_index;
	struct hostent *hp = NULL;
	int error_num = 0;
	boolean_t first = B_TRUE;
	int pass = 0;

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
		hp = getipnodebyname(hostname, AF_INET, 0, &error_num);
		if (hp == NULL) {
			if (error_num == TRY_AGAIN) {
				pr_err("could not resolve %s (try again later)",
				    hostname);
			} else {
				pr_err("could not resolve %s", hostname);
			}
		}
		inet_type = IPV4_ONLY;
	} else if (tokentype == ADDR_IP6) {
		hp = getipnodebyname(hostname, AF_INET6, 0, &error_num);
		if (hp == NULL) {
			if (error_num == TRY_AGAIN) {
				pr_err("could not resolve %s (try again later)",
				    hostname);
			} else {
				pr_err("could not resolve %s", hostname);
			}
		}
		inet_type = IPV6_ONLY;
	} else if (tokentype == ALPHA) {
		/* Some hostname i.e. tokentype is ALPHA */
		switch (inet_type) {
		case IPV4_ONLY:
			/* Only IPv4 address is needed */
			hp = getipnodebyname(hostname, AF_INET, 0, &error_num);
			if (hp != NULL) {
				found_host = 1;
			}
			break;
		case IPV6_ONLY:
			/* Only IPv6 address is needed */
			hp = getipnodebyname(hostname, AF_INET6, 0, &error_num);
			if (hp != NULL) {
				found_host = 1;
			}
			break;
		case IPV4_AND_IPV6:
			/* Both IPv4 and IPv6 are needed */
			hp = getipnodebyname(hostname, AF_INET6,
			    AI_ALL | AI_V4MAPPED, &error_num);
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
	} else {
		pr_err("unknown token type: %s", hostname);
	}

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

	if (hp != NULL && hp->h_addrtype == AF_INET) {
		pf_match_ethertype(ETHERTYPE_IP);
		pf_check_vlan_tag(ENCAP_ETHERTYPE_OFF/2);
		h_addr_index = 0;
		addr4ptr = (uint_t *)hp->h_addr_list[h_addr_index];
		while (addr4ptr != NULL) {
			if (addr4offset == -1) {
				pf_compare_value(IPV4_SRCADDR_OFFSET, 4,
				    *addr4ptr);
				if (h_addr_index != 0)
					pf_emit(ENF_OR);
				pf_compare_value(IPV4_DSTADDR_OFFSET, 4,
				    *addr4ptr);
				pf_emit(ENF_OR);
			} else {
				pf_compare_value(addr4offset, 4,
				    *addr4ptr);
				if (h_addr_index != 0)
					pf_emit(ENF_OR);
			}
			addr4ptr = (uint_t *)hp->h_addr_list[++h_addr_index];
		}
		pf_emit(ENF_AND);
	} else {
		/* first pass: IPv4 addresses */
		h_addr_index = 0;
		addr6ptr = (struct in6_addr *)hp->h_addr_list[h_addr_index];
		first = B_TRUE;
		while (addr6ptr != NULL) {
			if (IN6_IS_ADDR_V4MAPPED(addr6ptr)) {
				if (first) {
					pf_match_ethertype(ETHERTYPE_IP);
					pf_check_vlan_tag(
					    ENCAP_ETHERTYPE_OFF/2);
					pass++;
				}
				IN6_V4MAPPED_TO_INADDR(addr6ptr,
				    (struct in_addr *)&addr4);
				if (addr4offset == -1) {
					pf_compare_value(IPV4_SRCADDR_OFFSET, 4,
					    addr4);
					if (!first)
						pf_emit(ENF_OR);
					pf_compare_value(IPV4_DSTADDR_OFFSET, 4,
					    addr4);
					pf_emit(ENF_OR);
				} else {
					pf_compare_value(addr4offset, 4,
					    addr4);
					if (!first)
						pf_emit(ENF_OR);
				}
				if (first)
					first = B_FALSE;
			}
			addr6ptr = (struct in6_addr *)
				hp->h_addr_list[++h_addr_index];
		}
		if (!first) {
			pf_emit(ENF_AND);
		}
		/* second pass: IPv6 addresses */
		h_addr_index = 0;
		addr6ptr = (struct in6_addr *)hp->h_addr_list[h_addr_index];
		first = B_TRUE;
		while (addr6ptr != NULL) {
			if (!IN6_IS_ADDR_V4MAPPED(addr6ptr)) {
				if (first) {
					pf_match_ethertype(ETHERTYPE_IPV6);
					pf_check_vlan_tag(
					    ENCAP_ETHERTYPE_OFF/2);
					pass++;
				}
				if (addr6offset == -1) {
					pf_compare_value_v6(IPV6_SRCADDR_OFFSET,
					    16, *addr6ptr);
					if (!first)
						pf_emit(ENF_OR);
					pf_compare_value_v6(IPV6_DSTADDR_OFFSET,
					    16, *addr6ptr);
					pf_emit(ENF_OR);
				} else {
					pf_compare_value_v6(addr6offset, 16,
					    *addr6ptr);
					if (!first)
						pf_emit(ENF_OR);
				}
				if (first)
					first = B_FALSE;
			}
			addr6ptr = (struct in6_addr *)
				hp->h_addr_list[++h_addr_index];
		}
		if (!first) {
			pf_emit(ENF_AND);
		}
		if (pass == 2) {
			pf_emit(ENF_OR);
		}
	}

	if (hp != NULL) {
		freehostent(hp);
	}
}


static void
pf_compare_address(int offset, uint_t len, uchar_t *addr)
{
	uint32_t val;
	uint16_t sval;
	boolean_t didone = B_FALSE;

	/*
	 * If the property being filtered on is absent in the media
	 * packet, error out.
	 */
	if (offset == -1)
		pr_err("filter option unsupported on media");

	while (len > 0) {
		if (len >= 4) {
			(void) memcpy(&val, addr, 4);
			pf_compare_value(offset, 4, val);
			addr += 4;
			offset += 4;
			len -= 4;
		} else if (len >= 2) {
			(void) memcpy(&sval, addr, 2);
			pf_compare_value(offset, 2, sval);
			addr += 2;
			offset += 2;
			len -= 2;
		} else {
			pf_compare_value(offset++, 1, *addr++);
			len--;
		}
		if (didone)
			pf_emit(ENF_AND);
		didone = B_TRUE;
	}
}

/*
 * Compare ethernet addresses.
 */
static void
pf_etheraddr_match(which, hostname)
	enum direction which;
	char *hostname;
{
	struct ether_addr e, *ep = NULL;

	if (isxdigit(*hostname))
		ep = ether_aton(hostname);
	if (ep == NULL) {
		if (ether_hostton(hostname, &e))
			if (!arp_for_ether(hostname, &e))
				pr_err("cannot obtain ether addr for %s",
					hostname);
		ep = &e;
	}

	pf_clear_offset_register();

	switch (which) {
	case TO:
		pf_compare_address(link_dest_offset, link_addr_len,
		    (uchar_t *)ep);
		break;
	case FROM:
		pf_compare_address(link_src_offset, link_addr_len,
		    (uchar_t *)ep);
		break;
	case ANY:
		pf_compare_address(link_dest_offset, link_addr_len,
		    (uchar_t *)ep);
		pf_compare_address(link_src_offset, link_addr_len,
		    (uchar_t *)ep);
		pf_emit(ENF_OR);
		break;
	}
}

/*
 * Emit code to compare the network part of
 * an IP address.
 */
static void
pf_netaddr_match(which, netname)
	enum direction which;
	char *netname;
{
	uint_t addr;
	uint_t mask = 0xff000000;
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

	pf_check_vlan_tag(ENCAP_ETHERTYPE_OFF/2);

	switch (which) {
	case TO:
		pf_compare_value_mask(IPV4_DSTADDR_OFFSET, 4, addr, mask);
		break;
	case FROM:
		pf_compare_value_mask(IPV4_SRCADDR_OFFSET, 4, addr, mask);
		break;
	case ANY:
		pf_compare_value_mask(IPV4_SRCADDR_OFFSET, 4, addr, mask);
		pf_compare_value_mask(IPV4_DSTADDR_OFFSET, 4, addr, mask);
		pf_emit(ENF_OR);
		break;
	}
}

/*
 * A helper function to keep the code to emit instructions
 * to change the offset register in one place.
 *
 * INPUTS: offset - An value representing an offset in 16-bit
 *                  words.
 * OUTPUTS:  If there is enough room in the storage for the
 *           packet filtering program, instructions to load
 *           a constant to the offset register.  Otherwise,
 *           nothing.
 */
static void
pf_emit_load_offset(uint_t offset)
{
	pf_emit(ENF_LOAD_OFFSET | ENF_NOP);
	pf_emit(offset);
}

/*
 * Clear pfmod's offset register.
 *
 * INPUTS:  none
 * OUTPUTS:  Instructions to clear the offset register if
 *           there is enough space remaining in the packet
 *           filtering program structure's storage, and
 *           the last thing done to the offset register was
 *           not clearing the offset register.  Otherwise,
 *           nothing.
 */
static void
pf_clear_offset_register()
{
	if (last_offset_operation != (void*)pf_clear_offset_register) {
		pf_emit_load_offset(0);
		last_offset_operation = (void*)pf_clear_offset_register;
	}
}

/*
 * This function will issue opcodes to check if a packet
 * is VLAN tagged, and if so, update the offset register
 * with the appropriate offset.
 *
 * Note that if the packet is not VLAN tagged, then the offset
 * register will be cleared.
 *
 * If the interface type is not an ethernet type, then this
 * function returns without doing anything.
 *
 * If the last attempt to change the offset register occured because
 * of a call to this function that was called with the same offset,
 * then we don't issue packet filtering instructions.
 *
 * INPUTS:  offset - an offset in 16 bit words.  The function
 *                   will set the offset register to this
 *                   value if the packet is VLAN tagged.
 * OUTPUTS:  If the conditions are met, packet filtering instructions.
 */
static void
pf_check_vlan_tag(uint_t offset)
{
	static uint_t last_offset = 0;

	if ((interface->mac_type == DL_ETHER ||
	    interface->mac_type == DL_CSMACD) &&
	    (last_offset_operation != (void*)pf_check_vlan_tag ||
	    last_offset != offset)) {
		/*
		 * First thing is to clear the offset register.
		 * We don't know what state it is in, and if it
		 * is not zero, then we have no idea what we load
		 * when we execute ENF_PUSHWORD.
		 */
		pf_clear_offset_register();

		/*
		 * Check the ethertype.
		 */
		pf_compare_value(link_type_offset, 2, htons(ETHERTYPE_VLAN));

		/*
		 * And if it's not VLAN, don't load offset to the offset
		 * register.
		 */
		pf_emit(ENF_BRFL | ENF_NOP);
		pf_emit(3);

		/*
		 * Otherwise, load offset to the offset register.
		 */
		pf_emit_load_offset(offset);

		/*
		 * Now get rid of the results of the comparison,
		 * we don't want the results of the comparison to affect
		 * other logic in the packet filtering program.
		 */
		pf_emit(ENF_POP | ENF_NOP);

		/*
		 * Set the last operation at the end, or any time
		 * after the call to pf_clear_offset because
		 * pf_clear_offset uses it.
		 */
		last_offset_operation = (void*)pf_check_vlan_tag;
		last_offset = offset;
	}
}

/*
 * Utility function used to emit packet filtering code
 * to match an ethertype.
 *
 * INPUTS:  ethertype - The ethertype we want to check for.
 *                      Don't call htons on the ethertype before
 *                      calling this function.
 * OUTPUTS:  If there is sufficient storage available, packet
 *           filtering code to check an ethertype.  Otherwise,
 *           nothing.
 */
static void
pf_match_ethertype(uint_t ethertype)
{
	/*
	 * If the user wants to filter on ethertype VLAN,
	 * then clear the offset register so that the offset
	 * for ENF_PUSHWORD points to the right place in the
	 * packet.
	 *
	 * Otherwise, call pf_check_vlan_tag to set the offset
	 * register such that the contents of the offset register
	 * plus the argument for ENF_PUSHWORD point to the right
	 * part of the packet, whether or not the packet is VLAN
	 * tagged.  We call pf_check_vlan_tag with an offset of
	 * two words because if the packet is VLAN tagged, we have
	 * to move past the ethertype in the ethernet header, and
	 * past the lower two octets of the VLAN header to get to
	 * the ethertype in the VLAN header.
	 */
	if (ethertype == ETHERTYPE_VLAN)
		pf_clear_offset_register();
	else
		pf_check_vlan_tag(2);

	pf_compare_value(link_type_offset, 2, htons(ethertype));
}

typedef struct {
	int	transport_protocol;
	int	network_protocol;
	/*
	 * offset is the offset in bytes from the beginning
	 * of the network protocol header to where the transport
	 * protocol type is.
	 */
	int	offset;
} transport_protocol_table_t;

static transport_protocol_table_t mapping_table[] = {
	{IPPROTO_TCP, ETHERTYPE_IP,   IPV4_TYPE_HEADER_OFFSET},
	{IPPROTO_TCP, ETHERTYPE_IPV6, IPV6_TYPE_HEADER_OFFSET},
	{IPPROTO_UDP, ETHERTYPE_IP,   IPV4_TYPE_HEADER_OFFSET},
	{IPPROTO_UDP, ETHERTYPE_IPV6, IPV6_TYPE_HEADER_OFFSET},
	{IPPROTO_OSPF, ETHERTYPE_IP,   IPV4_TYPE_HEADER_OFFSET},
	{IPPROTO_OSPF, ETHERTYPE_IPV6, IPV6_TYPE_HEADER_OFFSET},
	{IPPROTO_SCTP, ETHERTYPE_IP,   IPV4_TYPE_HEADER_OFFSET},
	{IPPROTO_SCTP, ETHERTYPE_IPV6, IPV6_TYPE_HEADER_OFFSET},
	{IPPROTO_ICMP, ETHERTYPE_IP,   IPV4_TYPE_HEADER_OFFSET},
	{IPPROTO_ICMPV6, ETHERTYPE_IPV6, IPV6_TYPE_HEADER_OFFSET},
	{IPPROTO_ENCAP, ETHERTYPE_IP,   IPV4_TYPE_HEADER_OFFSET},
	{IPPROTO_ESP, ETHERTYPE_IP,   IPV4_TYPE_HEADER_OFFSET},
	{IPPROTO_ESP, ETHERTYPE_IPV6, IPV6_TYPE_HEADER_OFFSET},
	{IPPROTO_AH, ETHERTYPE_IP,   IPV4_TYPE_HEADER_OFFSET},
	{IPPROTO_AH, ETHERTYPE_IPV6, IPV6_TYPE_HEADER_OFFSET},
	{-1, 0, 0}	/* must be the final entry */
};

/*
 * This function uses the table above to generate a
 * piece of a packet filtering program to check a transport
 * protocol type.
 *
 * INPUTS:  tranport_protocol - the transport protocol we're
 *                              interested in.
 * OUTPUTS:  If there is sufficient storage, then packet filtering
 *           code to check a transport protocol type.  Otherwise,
 *           nothing.
 */
static void
pf_check_transport_protocol(uint_t transport_protocol)
{
	int i = 0;
	uint_t number_of_matches = 0;

	for (i = 0; mapping_table[i].transport_protocol != -1; i++) {
		if (transport_protocol ==
		    (uint_t)mapping_table[i].transport_protocol) {
			number_of_matches++;
			pf_match_ethertype(mapping_table[i].network_protocol);
			pf_check_vlan_tag(ENCAP_ETHERTYPE_OFF/2);
			pf_compare_value(
			    mapping_table[i].offset + link_header_len, 1,
			    transport_protocol);
			pf_emit(ENF_AND);
			if (number_of_matches > 1) {
				/*
				 * Since we have two or more matches, in
				 * order to have a correct and complete
				 * program we need to OR the result of
				 * each block of comparisons together.
				 */
				pf_emit(ENF_OR);
			}
		}
	}
}

static void
pf_primary()
{
	for (;;) {
		if (tokentype == FIELD)
			break;

		if (EQ("ip")) {
			pf_match_ethertype(ETHERTYPE_IP);
			opstack++;
			next();
			break;
		}

		if (EQ("ip6")) {
			pf_match_ethertype(ETHERTYPE_IPV6);
			opstack++;
			next();
			break;
		}

		if (EQ("pppoe")) {
			pf_match_ethertype(ETHERTYPE_PPPOED);
			pf_match_ethertype(ETHERTYPE_PPPOES);
			pf_emit(ENF_OR);
			opstack++;
			next();
			break;
		}

		if (EQ("pppoed")) {
			pf_match_ethertype(ETHERTYPE_PPPOED);
			opstack++;
			next();
			break;
		}

		if (EQ("pppoes")) {
			pf_match_ethertype(ETHERTYPE_PPPOES);
			opstack++;
			next();
			break;
		}

		if (EQ("arp")) {
			pf_match_ethertype(ETHERTYPE_ARP);
			opstack++;
			next();
			break;
		}

		if (EQ("vlan")) {
			pf_match_ethertype(ETHERTYPE_VLAN);
			pf_compare_value_mask_neq(VLAN_ID_OFFSET, 2,
			    0, VLAN_ID_MASK);
			pf_emit(ENF_AND);
			opstack++;
			next();
			break;
		}

		if (EQ("vlan-id")) {
			next();
			if (tokentype != NUMBER)
				pr_err("VLAN ID expected");
			pf_match_ethertype(ETHERTYPE_VLAN);
			pf_compare_value_mask(VLAN_ID_OFFSET, 2, tokenval,
			    VLAN_ID_MASK);
			pf_emit(ENF_AND);
			opstack++;
			next();
			break;
		}

		if (EQ("rarp")) {
			pf_match_ethertype(ETHERTYPE_REVARP);
			opstack++;
			next();
			break;
		}

		if (EQ("tcp")) {
			pf_check_transport_protocol(IPPROTO_TCP);
			opstack++;
			next();
			break;
		}

		if (EQ("udp")) {
			pf_check_transport_protocol(IPPROTO_UDP);
			opstack++;
			next();
			break;
		}

		if (EQ("ospf")) {
			pf_check_transport_protocol(IPPROTO_OSPF);
			opstack++;
			next();
			break;
		}


		if (EQ("sctp")) {
			pf_check_transport_protocol(IPPROTO_SCTP);
			opstack++;
			next();
			break;
		}

		if (EQ("icmp")) {
			pf_check_transport_protocol(IPPROTO_ICMP);
			opstack++;
			next();
			break;
		}

		if (EQ("icmp6")) {
			pf_check_transport_protocol(IPPROTO_ICMPV6);
			opstack++;
			next();
			break;
		}

		if (EQ("ip-in-ip")) {
			pf_check_transport_protocol(IPPROTO_ENCAP);
			opstack++;
			next();
			break;
		}

		if (EQ("esp")) {
			pf_check_transport_protocol(IPPROTO_ESP);
			opstack++;
			next();
			break;
		}

		if (EQ("ah")) {
			pf_check_transport_protocol(IPPROTO_AH);
			opstack++;
			next();
			break;
		}

		if (EQ("(")) {
			inBrace++;
			next();
			pf_expression();
			if (EQ(")")) {
				if (inBrace)
					inBraceOR--;
				inBrace--;
				next();
			}
			break;
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

		if (EQ("inet")) {
			next();
			if (EQ("host"))
				next();
			if (tokentype != ALPHA && tokentype != ADDR_IP)
				pr_err("host/IPv4 addr expected after inet");
			pf_ipaddr_match(dir, token, IPV4_ONLY);
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
			pf_ipaddr_match(dir, token, IPV6_ONLY);
			opstack++;
			next();
			break;
		}

		if (EQ("proto")) {
			next();
			if (tokentype != NUMBER)
				pr_err("IP proto type expected");
			pf_check_vlan_tag(ENCAP_ETHERTYPE_OFF/2);
			pf_compare_value(
			    IPV4_TYPE_HEADER_OFFSET + link_header_len, 1,
			    tokenval);
			opstack++;
			next();
			break;
		}

		if (EQ("broadcast")) {
			pf_clear_offset_register();
			pf_compare_value(link_dest_offset, 4, 0xffffffff);
			opstack++;
			next();
			break;
		}

		if (EQ("multicast")) {
			pf_clear_offset_register();
			pf_compare_value_mask(link_dest_offset, 1, 0x01, 0x01);
			opstack++;
			next();
			break;
		}

		if (EQ("ethertype")) {
			next();
			if (tokentype != NUMBER)
				pr_err("ether type expected");
			pf_match_ethertype(tokenval);
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
			pf_netaddr_match(dir, token);
			dir = ANY;
			opstack++;
			next();
			break;
		}

		/*
		 * Give up on anything that's obviously
		 * not a primary.
		 */
		if (EQ("and") || EQ("or") ||
		    EQ("not") || EQ("decnet") || EQ("apple") ||
		    EQ("length") || EQ("less") || EQ("greater") ||
		    EQ("port") || EQ("srcport") || EQ("dstport") ||
		    EQ("rpc") || EQ("gateway") || EQ("nofrag") ||
		    EQ("bootp") || EQ("dhcp") || EQ("dhcp6") ||
		    EQ("slp") || EQ("ldap")) {
			break;
		}

		if (EQ("host") || EQ("between") ||
		    tokentype == ALPHA || /* assume its a hostname */
		    tokentype == ADDR_IP ||
		    tokentype == ADDR_IP6 ||
		    tokentype == ADDR_ETHER) {
			if (EQ("host") || EQ("between"))
				next();
			if (eaddr || tokentype == ADDR_ETHER) {
				pf_etheraddr_match(dir, token);
			} else if (tokentype == ALPHA) {
				pf_ipaddr_match(dir, token, IPV4_AND_IPV6);
			} else if (tokentype == ADDR_IP) {
				pf_ipaddr_match(dir, token, IPV4_ONLY);
			} else {
				pf_ipaddr_match(dir, token, IPV6_ONLY);
			}
			dir = ANY;
			eaddr = 0;
			opstack++;
			next();
			break;
		}

		break;	/* unknown token */
	}
}

static void
pf_alternation()
{
	int s = opstack;

	pf_primary();
	for (;;) {
		if (EQ("and"))
			next();
		pf_primary();
		if (opstack != s + 2)
			break;
		pf_emit(ENF_AND);
		opstack--;
	}
}

static void
pf_expression()
{
	pf_alternation();
	while (EQ("or") || EQ(",")) {
		if (inBrace)
			inBraceOR++;
		else
			foundOR++;
		next();
		pf_alternation();
		pf_emit(ENF_OR);
		opstack--;
	}
}

/*
 * Attempt to compile the expression
 * in the string "e".  If we can generate
 * pf code for it then return 1 - otherwise
 * return 0 and leave it up to the user-level
 * filter.
 */
int
pf_compile(e, print)
	char *e;
	int print;
{
	char *argstr;
	char *sav_str, *ptr, *sav_ptr;
	int inBr = 0, aheadOR = 0;

	argstr = strdup(e);
	sav_str = e;
	tkp = argstr;
	dir = ANY;

	pfp = &pf.Pf_Filter[0];
	if (setjmp(env)) {
		return (0);
	}

	/*
	 * Set media specific packet offsets that this code uses.
	 */
	if (interface->mac_type == DL_IB) {
		link_header_len = 4;
		link_type_offset = 0;
		link_dest_offset = link_src_offset = -1;
		link_addr_len = 20;
	}

	next();
	pf_expression();

	if (tokentype != EOL) {
		/*
		 * The idea here is to do as much filtering as possible in
		 * the kernel. So even if we find a token we don't understand,
		 * we try to see if we can still set up a portion of the filter
		 * in the kernel and use the userland filter to filter the
		 * remaining stuff. Obviously, if our filter expression is of
		 * type A AND B, we can filter A in kernel and then apply B
		 * to the packets that got through. The same is not true for
		 * a filter of type A OR B. We can't apply A first and then B
		 * on the packets filtered through A.
		 *
		 * (We need to keep track of the fact when we find an OR,
		 * and the fact that we are inside brackets when we find OR.
		 * The variable 'foundOR' tells us if there was an OR behind,
		 * 'inBraceOR' tells us if we found an OR before we could find
		 * the end brace i.e. ')', and variable 'aheadOR' checks if
		 * there is an OR in the expression ahead. if either of these
		 * cases become true, we can't split the filtering)
		 */

		if (foundOR || inBraceOR) {
			/* FORGET IN KERNEL FILTERING */
			return (0);
		} else {

			/* CHECK IF NO OR AHEAD */
			sav_ptr = (char *)((uintptr_t)sav_str +
						(uintptr_t)sav_tkp -
						(uintptr_t)argstr);
			ptr = sav_ptr;
			while (*ptr != '\0') {
				switch (*ptr) {
				case '(':
					inBr++;
					break;
				case ')':
					inBr--;
					break;
				case 'o':
				case 'O':
					if ((*(ptr + 1) == 'R' ||
						*(ptr + 1) == 'r') && !inBr)
						aheadOR = 1;
					break;
				case ',':
					if (!inBr)
						aheadOR = 1;
					break;
				}
				ptr++;
			}
			if (!aheadOR) {
				/* NO OR AHEAD, SPLIT UP THE FILTERING */
				pf.Pf_FilterLen = pfp - &pf.Pf_Filter[0];
				pf.Pf_Priority = 5;
				if (print) {
					pf_codeprint(&pf.Pf_Filter[0],
							pf.Pf_FilterLen);
				}
				compile(sav_ptr, print);
				return (2);
			} else
				return (0);
		}
	}

	pf.Pf_FilterLen = pfp - &pf.Pf_Filter[0];
	pf.Pf_Priority = 5;	/* unimportant, so long as > 2 */
	if (print) {
		pf_codeprint(&pf.Pf_Filter[0], pf.Pf_FilterLen);
	}
	return (1);
}
