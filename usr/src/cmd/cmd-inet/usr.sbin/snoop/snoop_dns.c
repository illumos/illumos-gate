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

#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/tiuser.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "snoop.h"

/* The string used to indent detail lines */
#define	DNS_INDENT	"    "
/*
 * From RFC1035, the maximum size of a character-string is limited by the
 * one octet length field.  We add one character to that to make sure the
 * result is terminated.
 */
#define	MAX_CHAR_STRING_SIZE	UCHAR_MAX + 1

/* private functions */
static char *dns_opcode_string(uint_t opcode);
static char *dns_rcode_string(uint_t rcode);
static char *dns_type_string(uint_t type, int detail);
static char *dns_class_string(uint_t cls, int detail);
static size_t skip_question(const uchar_t *header, const uchar_t *data,
    const uchar_t *data_end);
static size_t print_question(char *line, const uchar_t *header,
    const uchar_t *data, const uchar_t *data_end, int detail);
static size_t print_answer(char *line, const uchar_t *header,
    const uchar_t *data, const uchar_t *data_end, int detail);
static char *binary_string(char data);
static void print_ip(int af, char *line, const uchar_t *data, uint16_t len);
static const uchar_t *get_char_string(const uchar_t *data, char *charbuf,
    uint16_t datalen);
static size_t print_char_string(char *line, const uchar_t *data, uint16_t len);
static const uchar_t *get_domain_name(const uchar_t *header,
    const uchar_t *data, const uchar_t *data_end, char *namebuf, char *namend);
static size_t print_domain_name(char *line, const uchar_t *header,
    const uchar_t *data, const uchar_t *data_end);

void
interpret_dns(int flags, int proto, const uchar_t *data, int len, int port)
{
	typedef HEADER dns_header;
	dns_header header;
	char *line;
	ushort_t id, qdcount, ancount, nscount, arcount;
	ushort_t count;
	const uchar_t *rrp;	/* Resource Record Pointer. */
	const uchar_t *data_end;
	const char *protostr;
	char *protopfxstr;
	char *protohdrstr;

	if (proto == IPPROTO_TCP) {
		/* not supported now */
		return;
	}

	if (port == IPPORT_DOMAIN) {
		protostr = "DNS";
		protopfxstr = "DNS:  ";
		protohdrstr = "DNS Header";
	} else {
		protostr = "MDNS";
		protopfxstr = "MDNS:  ";
		protohdrstr = "MDNS Header";
	}

	/* We need at least the header in order to parse a packet. */
	if (sizeof (dns_header) > len) {
		return;
	}
	data_end = data + len;
	/*
	 * Copy the header into a local structure for aligned access to
	 * each field.
	 */
	(void) memcpy(&header, data, sizeof (header));
	id = ntohs(header.id);
	qdcount = ntohs(header.qdcount);
	ancount = ntohs(header.ancount);
	nscount = ntohs(header.nscount);
	arcount = ntohs(header.arcount);

	if (flags & F_SUM) {
		line = get_sum_line();
		line += sprintf(line, "%s %c ",
		    protostr, header.qr ? 'R' : 'C');

		if (header.qr) {
			/* answer */
			if (header.rcode == 0) {
				/* reply is OK */
				rrp = data + sizeof (dns_header);
				while (qdcount--) {
					if (rrp >= data_end) {
						return;
					}
					rrp += skip_question(data,
					    rrp, data_end);
				}
				/* the answers follow the questions */
				if (ancount > 0) {
					(void) print_answer(line,
					    data, rrp, data_end, FALSE);
				}
			} else {
				(void) sprintf(line, " Error: %d(%s)",
				    header.rcode,
				    dns_rcode_string(header.rcode));
			}
		} else {
			/* question */
			rrp = data + sizeof (dns_header);
			if (rrp >= data_end) {
				return;
			}
			(void) print_question(line, data, rrp, data_end,
			    FALSE);
		}
	}
	if (flags & F_DTAIL) {
		show_header(protopfxstr, protohdrstr, sizeof (dns_header));
		show_space();
		if (header.qr) {
			/* answer */
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Response ID = %d", id);
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "%s%s%s",
			    header.aa ? "AA (Authoritative Answer) " : "",
			    header.tc ? "TC (TrunCation) " : "",
			    header.ra ? "RA (Recursion Available) ": "");
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Response Code: %d (%s)",
			    header.rcode, dns_rcode_string(header.rcode));
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Reply to %d question(s)", qdcount);
		} else {
			/* question */
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Query ID = %d", id);
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "Opcode: %s", dns_opcode_string(header.opcode));
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "%s%s",
			    header.tc ? "TC (TrunCation) " : "",
			    header.rd ? "RD (Recursion Desired) " : "");
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "%d question(s)", qdcount);
		}
		rrp = data + sizeof (dns_header);
		count = 0;
		while (qdcount--) {
			if (rrp >= data_end) {
				return;
			}
			count++;
			rrp += print_question(get_line(0, 0),
			    data, rrp, data_end, TRUE);
			show_space();
		}
		/* Only answers should hold answers, but just in case */
		if (header.qr || ancount > 0) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "%d answer(s)", ancount);
			count = 0;
			while (ancount--) {
				if (rrp >= data_end) {
					return;
				}
				count++;
				rrp += print_answer(get_line(0, 0),
				    data, rrp, data_end, TRUE);
				show_space();
			}
		}
		/* Likewise only answers should hold NS records */
		if (header.qr || nscount > 0) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "%d name server resource(s)", nscount);
			count = 0;
			while (nscount--) {
				if (rrp >= data_end) {
					return;
				}
				count++;
				rrp += print_answer(get_line(0, 0), data,
				    rrp, data_end, TRUE);
				show_space();
			}
		}
		/* Additional section may hold an EDNS0 record. */
		if (header.qr || arcount > 0) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    "%d additional record(s)", arcount);
			count = 0;
			while (arcount-- && rrp < data_end) {
				count++;
				rrp += print_answer(get_line(0, 0), data,
				    rrp, data_end, TRUE);
				show_space();
			}
		}
	}
}


static char *
dns_opcode_string(uint_t opcode)
{
	static char buffer[64];
	switch (opcode) {
	case ns_o_query:	return ("Query");
	case ns_o_iquery:	return ("Inverse Query");
	case ns_o_status:	return ("Status");
	default:
		(void) snprintf(buffer, sizeof (buffer), "Unknown (%u)",
		    opcode);
		return (buffer);
	}
}

static char *
dns_rcode_string(uint_t rcode)
{
	static char buffer[64];
	switch (rcode) {
	case ns_r_noerror:	return ("OK");
	case ns_r_formerr:	return ("Format Error");
	case ns_r_servfail:	return ("Server Fail");
	case ns_r_nxdomain:	return ("Name Error");
	case ns_r_notimpl:	return ("Unimplemented");
	case ns_r_refused:	return ("Refused");
	case ns_r_badvers:	return ("Bad Version"); /* EDNS rcode */
	default:
		(void) snprintf(buffer, sizeof (buffer), "Unknown (%u)", rcode);
		return (buffer);
	}
}

static char *
dns_type_string(uint_t type, int detail)
{
	static char buffer[64];
	switch (type) {
	case ns_t_a:	return (detail ? "Address" : "A");
	case ns_t_ns:	return (detail ? "Authoritative Name Server" : "NS");
	case ns_t_cname:	return (detail ? "Canonical Name" : "CNAME");
	case ns_t_soa:	return (detail ? "Start Of a zone Authority" : "SOA");
	case ns_t_mb:	return (detail ? "Mailbox domain name" : "MB");
	case ns_t_mg:	return (detail ? "Mailbox Group member" : "MG");
	case ns_t_mr:	return (detail ? "Mail Rename domain name" : "MR");
	case ns_t_null:	return ("NULL");
	case ns_t_wks:	return (detail ? "Well Known Service" : "WKS");
	case ns_t_ptr:	return (detail ? "Domain Name Pointer" : "PTR");
	case ns_t_hinfo:	return (detail ? "Host Information": "HINFO");
	case ns_t_minfo:
		return (detail ? "Mailbox or maillist Info" : "MINFO");
	case ns_t_mx:	return (detail ? "Mail Exchange" : "MX");
	case ns_t_txt:	return (detail ? "Text strings" : "TXT");
	case ns_t_aaaa:	return (detail ? "IPv6 Address" : "AAAA");
	case ns_t_loc:	return (detail ? "Location Information" : "LOC");
	case ns_t_srv:	return (detail ? "Server Selection" : "SRV");
	case ns_t_naptr:
		return (detail ? "Naming Authority Pointer" : "NAPTR");
	case ns_t_opt:	return (detail ? "EDNS0 option" : "OPT");
	case ns_t_cert:	return (detail ? "Certificate record" : "CERT");
	case ns_t_sshfp:
		return (detail ? "SSH Fingerprint" : "SSHFP");
	case ns_t_ipseckey:
		return (detail ? "IPsec Key" : "IPSECKEY");
	case ns_t_rrsig:
		return (detail ? "DNSSEC signature" : "RRSIG");
	case ns_t_nsec:	return (detail ? "Next Secure record" : "NSEC");
	case ns_t_dnskey:
		return (detail ? "DNS Key record" : "DNSKEY");
	case ns_t_dhcid:
		return (detail ? "DHCP identifier" : "DHCID");
	case ns_t_nsec3:
		return (detail ? "NSEC3 record" : "NSEC3");
	case ns_t_nsec3param:
		return (detail ? "NSEC3 parameter" : "NSEC3PARAM");
	case ns_t_tlsa:
		return (detail ? "TLSA certificate association" : "TLSA");
	case ns_t_smimea:
		return (detail ? "S/MIME cert association" : "SMIMEA");
	case ns_t_hip:	return (detail ? "Host Identity record" : "HIP");
	case ns_t_cds:	return (detail ? "Child DS" : "CDS");
	case ns_t_cdnskey:
		return (detail ? "Child copy of DNSKEY record" : "CDNSKEY");
	case ns_t_openpgpkey:
		return (detail ? "OpenPGP public key record" : "OPENPGPKEY");
	case ns_t_csync:
		return (detail ? "Child-to-Parent Synchronization" : "CSYNC");
	case ns_t_caa:
		return (detail ? "Certification Authority Restriction" : "CAA");
	case ns_t_axfr:	return (detail ? "Transfer of entire zone" : "AXFR");
	case ns_t_mailb:
		return (detail ? "Mailbox related records" : "MAILB");
	case ns_t_maila:	return (detail ? "Mail agent RRs" : "MAILA");
	case ns_t_any:	return (detail ? "All records" : "*");
	default:
		(void) snprintf(buffer, sizeof (buffer), "Unknown (%u)", type);
		return (buffer);
	}
}

static char *
dns_class_string(uint_t cls, int detail)
{
	static char buffer[64];
	switch (cls) {
	case ns_c_in:		return (detail ? "Internet" : "IN");
	case ns_c_chaos:	return (detail ? "CHAOS" : "CH");
	case ns_c_hs:		return (detail ? "Hesiod" : "HS");
	case ns_c_any:		return (detail ? "* (Any class)" : "*");
	default:
		(void) snprintf(buffer, sizeof (buffer), "Unknown (%u)", cls);
		return (buffer);
	}
}

static size_t
skip_question(const uchar_t *header, const uchar_t *data,
    const uchar_t *data_end)
{
	const uchar_t *data_bak = data;
	char dummy_buffer[NS_MAXDNAME];

	data = get_domain_name(header, data, data_end, dummy_buffer,
	    dummy_buffer + sizeof (dummy_buffer));
	/* Skip the 32 bits of class and type that follow the domain name */
	data += sizeof (uint32_t);
	return (data - data_bak);
}

static size_t
print_question(char *line, const uchar_t *header, const uchar_t *data,
    const uchar_t *data_end, int detail)
{
	const uchar_t *data_bak = data;
	uint16_t type;
	uint16_t cls;

	if (detail) {
		line += snprintf(line, get_line_remain(),
		    DNS_INDENT "Domain Name: ");
	}
	data += print_domain_name(line, header, data, data_end);

	/*
	 * Make sure we don't run off the end of the packet by reading the
	 * type and class.
	 *
	 * The pointer subtraction on the left side of the following
	 * expression has a signed result of type ptrdiff_t, and the right
	 * side has an unsigned result of type size_t.  We therefore need
	 * to cast the right side of the expression to be of the same
	 * signed type to keep the result of the pointer arithmetic to be
	 * automatically cast to an unsigned value.  We do a similar cast
	 * in other similar expressions throughout this file.
	 */
	if ((data_end - data) < (ptrdiff_t)(2 * sizeof (uint16_t)))
		return (data_end - data_bak);

	GETINT16(type, data);
	GETINT16(cls, data);

	/*
	 * Multicast DNS re-uses the top bit of the class field
	 * in the question and answer sections. Unicast DNS only
	 * uses 1 (Internet), 3 and 4. Hence it is safe. The top
	 * order bit is always cleared here to display the rrclass in case
	 * of Multicast DNS packets.
	 */
	cls = cls & 0x7fff;

	if (detail) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    DNS_INDENT "Class: %u (%s)",
		    cls, dns_class_string(cls, detail));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    DNS_INDENT "Type:  %u (%s)", type,
		    dns_type_string(type, detail));
	} else {
		(void) sprintf(line + strlen(line), " %s %s \?",
		    dns_class_string(cls, detail),
		    dns_type_string(type, detail));
	}
	return (data - data_bak);
}

/*
 * print_answer() is used to display the contents of a single resource
 * record (RR) from either the answer, name server or additional
 * section of the DNS packet.
 *
 * Input:
 *	*line: snoops output buffer.
 *	*header: start of the DNS packet, required for names and rcode.
 *	*data: location within header from where the RR starts.
 *	*data_end: where DNS data ends.
 *	detail: simple or verbose output.
 *
 * Returns:
 *	Pointer to next RR or data_end.
 *
 * Most RRs have the same top level format as defined in RFC 1035:
 *
 *                                     1  1  1  1  1  1
 *       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                                               |
 *    /                      NAME                     /
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                      TYPE                     |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                     CLASS                     |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                      TTL                      |
 *    |                                               |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                   RDLENGTH                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 *    /                     RDATA                     /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * However RFC 2671 introduced an exception to this rule
 * with the "Extension Mechanisms for DNS" (EDNS0).
 * When the type is 41 the remaining resource record format
 * is:
 *
 *                                     1  1  1  1  1  1
 *       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    TYPE = 41                  |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |           Sender's UDP payload size           |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |    Extended-rcode     |        Version        |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                      Zero                     |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                   RDLENGTH                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
 *    /                     RDATA                     /
 *    /                                               /
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */
static size_t
print_answer(char *line, const uchar_t *header, const uchar_t *data,
    const uchar_t *data_end, int detail)
{
	const uchar_t *data_bak = data;
	const uchar_t *data_next;
	uint16_t type;
	uint16_t cls;
	int32_t ttl;
	uint16_t rdlen;
	uint32_t serial, refresh, retry, expire, minimum;
	uint8_t protocol;
	int linepos;
	uint16_t preference;
	/* declarations for EDNS follow */
	uint16_t size;	/* Sender's UDP payload size */
	uint8_t xrcode;	/* Extended-rcode */
	uint8_t ver;	/* Version */
	uint16_t rcode;	/* Extracted from the DNS header */
	union {		/* DNS header overlay used for extraction */
		HEADER		*head;
		const uchar_t	*raw;
	} headptr;

	if (detail) {
		line += snprintf(line, get_line_remain(),
		    DNS_INDENT "Domain Name: ");
	}
	data += print_domain_name(line, header, data, data_end);

	/*
	 * Next, get the record type, being careful to make sure we
	 * don't run off the end of the packet.
	 */
	if ((data_end - data) < (ptrdiff_t)(sizeof (type))) {
		return (data_end - data_bak);
	}

	GETINT16(type, data);

	if (type == ns_t_opt) {
		/*
		 * Make sure we won't run off the end reading size,
		 * xrcode, version, zero and rdlen.
		 */
		if ((data_end - data) <
		    ((ptrdiff_t)(sizeof (size)
		    + sizeof (xrcode)
		    + sizeof (ver)
		    + sizeof (cls)	/* zero */
		    + sizeof (rdlen)))) {
			return (data_end - data_bak);
		}

		GETINT16(size, data);
		GETINT8(xrcode, data);
		/*
		 * The extended rcode represents the top half of the
		 * rcode which must be added to the rcode in the header.
		 */
		rcode = 0xff & (xrcode << 4);
		headptr.raw = header;		/* Overlay the header... */
		rcode += headptr.head->rcode;	/* And pluck out the rcode. */

		GETINT8(ver, data);
		GETINT16(cls, data); /* zero */
		GETINT16(rdlen, data);

		if (detail) {
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    DNS_INDENT "Type:  %u (%s)", type,
			    dns_type_string(type, detail));
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    DNS_INDENT "UDP payload size: %u (0x%.4x)",
			    size, size);
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    DNS_INDENT "Extended rcode: %u "
			    "(translates to %u (%s))",
			    xrcode, rcode, dns_rcode_string(rcode));
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    DNS_INDENT "EDNS0 Version: %u", ver);
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    DNS_INDENT "zero: %u", cls);
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    DNS_INDENT "Data length: %u", rdlen);
		} else {
			line += strlen(line);
			line += sprintf(line, " %s UDP %u rc %d ver %u len %u",
			    dns_type_string(type, detail), size, rcode, ver,
			    rdlen);
		}

		/*
		 * Make sure that rdlen is within data boundary.
		 */
		if (rdlen > data_end - data)
			return (data_end - data_bak);

		/* Future OPT decode code goes here. */

		data += rdlen;
		return (data - data_bak);
	}

	/*
	 * Make sure we don't run off the end of the packet by reading the
	 * class, ttl, and length.
	 */
	if ((data_end - data) <
	    ((ptrdiff_t)(sizeof (cls)
	    + sizeof (ttl)
	    + sizeof (rdlen)))) {
		return (data_end - data_bak);
	}

	GETINT16(cls, data);

	/*
	 * Multicast DNS re-uses the top bit of the class field
	 * in the question and answer sections. Unicast DNS only
	 * uses 1 (Internet), 3 and 4. Hence it is safe. The top
	 * order bit is always cleared here to display the rrclass in case
	 * of Multicast DNS packets.
	 */
	cls = cls & 0x7fff;

	if (detail) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    DNS_INDENT "Class: %d (%s)", cls,
		    dns_class_string(cls, detail));
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    DNS_INDENT "Type:  %d (%s)", type,
		    dns_type_string(type, detail));
	} else {
		line += strlen(line);
		line += sprintf(line, " %s %s ",
		    dns_class_string(cls, detail),
		    dns_type_string(type, detail));
	}

	GETINT32(ttl, data);
	if (detail) {
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    DNS_INDENT "TTL (Time To Live): %d", ttl);
	}

	GETINT16(rdlen, data);
	if (detail) {
		line = get_line(0, 0);
		line += snprintf(line, get_line_remain(), DNS_INDENT "%s: ",
		    dns_type_string(type, detail));
	}

	if (rdlen > data_end - data)
		return (data_end - data_bak);

	switch (type) {
	case ns_t_a:
		print_ip(AF_INET, line, data, rdlen);
		break;
	case ns_t_aaaa:
		print_ip(AF_INET6, line, data, rdlen);
		break;
	case ns_t_hinfo:
		line += sprintf(line, "CPU: ");
		data_next = data + print_char_string(line, data, rdlen);
		if (data_next >= data_end)
			break;
		line += strlen(line);
		line += sprintf(line, "OS: ");
		(void) print_char_string(line, data_next,
		    rdlen - (data_next - data));
		break;
	case ns_t_ns:
	case ns_t_cname:
	case ns_t_mb:
	case ns_t_mg:
	case ns_t_mr:
	case ns_t_ptr:
		(void) print_domain_name(line, header, data, data_end);
		break;
	case ns_t_mx:
		data_next = data;
		if (rdlen < sizeof (uint16_t))
			break;
		GETINT16(preference, data_next);
		if (detail) {
			(void) print_domain_name(line, header, data_next,
			    data_end);
			(void) snprintf(get_line(0, 0), get_line_remain(),
			    DNS_INDENT "Preference: %u", preference);
		} else {
			(void) print_domain_name(line, header, data_next,
			    data_end);
		}
		break;
	case ns_t_soa:
		if (!detail)
			break;
		line = get_line(0, 0);
		line += snprintf(line, get_line_remain(),
		    DNS_INDENT "MNAME (Server name): ");
		data_next = data + print_domain_name(line, header, data,
		    data_end);
		if (data_next >= data_end)
			break;
		line = get_line(0, 0);
		line += snprintf(line, get_line_remain(),
		    DNS_INDENT "RNAME (Resposible mailbox): ");
		data_next = data_next +
		    print_domain_name(line, header, data_next, data_end);
		if ((data_end - data_next) < (ptrdiff_t)(5 * sizeof (uint32_t)))
			break;
		GETINT32(serial, data_next);
		GETINT32(refresh, data_next);
		GETINT32(retry, data_next);
		GETINT32(expire, data_next);
		GETINT32(minimum, data_next);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    DNS_INDENT "Serial: %u", serial);
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    DNS_INDENT "Refresh: %u  Retry: %u  "
		    "Expire: %u Minimum: %u",
		    refresh, retry, expire, minimum);
		break;
	case ns_t_wks:
		print_ip(AF_INET, line, data, rdlen);
		if (!detail)
			break;
		data_next = data + sizeof (in_addr_t);
		if (data_next >= data_end)
			break;
		GETINT8(protocol, data_next);
		line = get_line(0, 0);
		line += snprintf(line, get_line_remain(),
		    DNS_INDENT "Protocol: %u ", protocol);
		switch (protocol) {
		case IPPROTO_UDP:
			(void) snprintf(line, get_line_remain(), "(UDP)");
			break;
		case IPPROTO_TCP:
			(void) snprintf(line, get_line_remain(), "(TCP)");
			break;
		}
		(void) snprintf(get_line(0, 0), get_line_remain(),
		    DNS_INDENT "Service bitmap:");
		(void) snprintf(line, get_line_remain(),
		    DNS_INDENT "0       8       16      24");
		linepos = 4;
		while (data_next < data + rdlen) {
			if (linepos == 4) {
				line = get_line(0, 0);
				line += snprintf(line, get_line_remain(),
				    DNS_INDENT);
				linepos = 0;
			}
			line += snprintf(line, get_line_remain(), "%s",
			    binary_string(*data_next));
			linepos++;
			data_next++;
		}
		break;
	case ns_t_minfo:
		if (!detail)
			break;
		line = get_line(0, 0);
		line += snprintf(line, get_line_remain(),
		    DNS_INDENT "RMAILBX (Resposible mailbox): ");
		data_next = data + print_domain_name(line, header, data,
		    data_end);
		line = get_line(0, 0);
		line += snprintf(line, get_line_remain(),
		    DNS_INDENT "EMAILBX (mailbox to receive err message): ");
		data_next = data_next + print_domain_name(line, header,
		    data_next, data_end);
		break;
	}
	data += rdlen;
	return (data - data_bak);
}

static char *
binary_string(char data)
{
	static char bstring[8 + 1];
	char *ptr;
	int i;
	ptr = bstring;
	for (i = 0; i < 8; i++) {
		*ptr++ = (data & 0x80) ? '1' : '0';
		data = data << 1;
	}
	*ptr = (char)0;
	return (bstring);
}

static void
print_ip(int af, char *line, const uchar_t *data, uint16_t len)
{
	in6_addr_t	addr6;
	in_addr_t	addr4;
	void		*addr;

	switch (af) {
	case AF_INET:
		if (len != sizeof (in_addr_t))
			return;
		addr = memcpy(&addr4, data, sizeof (addr4));
		break;
	case AF_INET6:
		if (len != sizeof (in6_addr_t))
			return;
		addr = memcpy(&addr6, data, sizeof (addr6));
		break;
	}

	(void) inet_ntop(af, addr, line, INET6_ADDRSTRLEN);
}

/*
 * charbuf is assumed to be of size MAX_CHAR_STRING_SIZE.
 */
static const uchar_t *
get_char_string(const uchar_t *data, char *charbuf, uint16_t datalen)
{
	int len;
	char *name = charbuf;
	int i = 0;

	/*
	 * From RFC1035, a character-string is a single length octet followed
	 * by that number of characters.
	 */
	if (datalen > 1) {
		len = *data;
		data++;
		if (len > 0 && len < MAX_CHAR_STRING_SIZE) {
			for (i = 0; i < len; i++, data++)
				name[i] = *data;
		}
	}
	name[i] = '\0';
	return (data);
}

static size_t
print_char_string(char *line, const uchar_t *data, uint16_t len)
{
	char charbuf[MAX_CHAR_STRING_SIZE];
	const uchar_t *data_bak = data;

	data = get_char_string(data, charbuf, len);
	(void) sprintf(line, "%s", charbuf);
	return (data - data_bak);
}

/*
 * header: the entire message header, this is where we start to
 *	   count the offset of the compression scheme
 * data:   the start of the domain name
 * namebuf: user supplied buffer
 * return: the next byte after what we have parsed
 */
static const uchar_t *
get_domain_name(const uchar_t *header, const uchar_t *data,
    const uchar_t *data_end, char *namebuf, char *namend)
{
	uint8_t len;
	char *name = namebuf;

	/*
	 * From RFC1035, a domain name is a sequence of labels, where each
	 * label consists of a length octet followed by that number of
	 * octets.  The domain name terminates with the zero length octet
	 * for the null label of the root.
	 */

	while (name < (namend - 1)) {
		if ((data_end - data) < (ptrdiff_t)(sizeof (uint8_t))) {
			/* The length octet is off the end of the packet. */
			break;
		}
		GETINT8(len, data);
		if (len == 0) {
			/*
			 * Domain names end with a length byte of zero,
			 * which represents the null label of the root.
			 */
			break;
		}
		/*
		 * test if we are using the compression scheme
		 */
		if ((len & 0xc0) == 0xc0) {
			uint16_t offset;
			const uchar_t *label_ptr;

			/*
			 * From RFC1035, message compression allows a
			 * domain name or a list of labels at the end of a
			 * domain name to be replaced with a pointer to a
			 * prior occurance of the same name.  In this
			 * scheme, the pointer is a two octet sequence
			 * where the most significant two bits are set, and
			 * the remaining 14 bits are the offset from the
			 * start of the message of the next label.
			 */
			data--;
			if ((data_end - data) <
			    (ptrdiff_t)(sizeof (uint16_t))) {
				/*
				 * The offset octets aren't entirely
				 * contained within this pakcet.
				 */
				data = data_end;
				break;
			}
			GETINT16(offset, data);
			label_ptr = header + (offset & 0x3fff);
			/*
			 * We must verify that the offset is valid by
			 * checking that it is less than the current data
			 * pointer and that it isn't off the end of the
			 * packet.
			 */
			if (label_ptr > data || label_ptr >= data_end)
				break;
			(void) get_domain_name(header, label_ptr, data_end,
			    name, namend);
			return (data);
		} else {
			if (len > (data_end - data)) {
				/*
				 * The label isn't entirely contained
				 * within the packet.  Don't read it.  The
				 * caller checks that the data pointer is
				 * not beyond the end after we've
				 * incremented it.
				 */
				data = data_end;
				break;
			}
			while (len > 0 && name < (namend - 2)) {
				*name = *data;
				name++;
				data++;
				len--;
			}
			*name = '.';
			name++;
		}
	}
	*name = '\0';
	return (data);
}

static size_t
print_domain_name(char *line, const uchar_t *header, const uchar_t *data,
    const uchar_t *data_end)
{
	char name[NS_MAXDNAME];
	const uchar_t *new_data;

	new_data = get_domain_name(header, data, data_end, name,
	    name + sizeof (name));

	(void) sprintf(line, "%s", name);
	return (new_data - data);
}
