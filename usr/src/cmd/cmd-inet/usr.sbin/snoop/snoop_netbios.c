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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * References used throughout this code:
 *
 * [RFC1001] :	PROTOCOL STANDARD FOR A NetBIOS SERVICE
 *			ON A TCP/UDP TRANSPORT:
 *			CONCEPTS AND METHODS
 *		NetBIOS Working Group, March 1987
 *
 * [RFC1002] :	PROTOCOL STANDARD FOR A NetBIOS SERVICE
 *			ON A TCP/UDP TRANSPORT:
 *			DETAILED SPECIFICATIONS
 *		NetBIOS Working Group, March 1987
 */

#include <fcntl.h>
#include "snoop.h"
#include <stdio.h>
#include <ctype.h>
#include "snoop.h"

extern char *dlc_header;
char *show_type();

/* See snoop_smb.c */
extern void interpret_smb(int flags, uchar_t *data, int len);

/*
 * NBT Session Packet Header
 * [RFC 1002, Sec. 4.3.1]
 */
struct nbt_ss {
	uchar_t type;
	uchar_t flags;
	ushort_t length;
};

/*
 * NBT Session Request Packet trailer
 * [RFC 1002, Sec. 4.3.2]
 */
struct callnames {
	uchar_t space;		/* padding */
	uchar_t calledname[32];
	uchar_t nullchar;		/* padding */
	uchar_t space2;		/* padding */
	uchar_t callingname[32];
	uchar_t nullchar2;	/* padding */
};


static void interpret_netbios_names(int flags, uchar_t *data, int len,
					char *xtra);
static void netbiosname2ascii(char *asciiname, uchar_t *netbiosname);

/*
 * Helpers to read network-order values,
 * with NO alignment assumed.
 */
static ushort_t
getshort(uchar_t *p) {
	return (p[1] + (p[0]<<8));
}
static uint_t
getlong(uchar_t *p)
{
	return (p[3] + (p[2]<<8) + (p[1]<<16) + (p[0]<<24));
}

/*
 * NM_FLAGS fields in the NetBIOS Name Service Packet header.
 * [RFC 1002,  Sec. 4.2.1.1]
 */
static void
print_flag_details(int headerflags)
{
	if (headerflags & 1<<4)
		sprintf(get_line(0, 0), "   - Broadcast");
	if (headerflags & 1<<7)
		sprintf(get_line(0, 0), "   - Recursion Available");
	if (headerflags & 1<<8)
		sprintf(get_line(0, 0), "   - Recursion Desired");
	if (headerflags & 1<<9)
		sprintf(get_line(0, 0), "   - Truncation Flag");
	if (headerflags & 1<<10)
		sprintf(get_line(0, 0), "   - Authoritative Answer");
}

/*
 * Possible errors in NetBIOS name service packets.
 * [RFC 1002,  Sec. 4.2.6, 4.2.11, 4.2.14]
 */
static void
getrcodeerr(int headerflags, char *errortype)
{
	int error = (headerflags & 0xf);

	switch (error) {
	case 0:
		sprintf(errortype, "Success");
		break;
	case 1:
		sprintf(errortype, "Format Error");
		break;
	case 2:
		sprintf(errortype, "Server Failure");
		break;
	case 3:
		sprintf(errortype, "Name Error");
		break;
	case 4:
		sprintf(errortype, "Unsupported Request Error");
		break;
	case 5:
		sprintf(errortype, "Refused Error");
		break;
	case 6:
		sprintf(errortype, "Active Error");
		break;
	case 7:
		sprintf(errortype, "Name in Conflict Error");
		break;
	default:
		sprintf(errortype, "Unknown Error");
		break;
	}
}

/*
 * OPCODE fields in the NetBIOS Name Service Packet header.
 * [RFC 1002, Sec. 4.2.1.1]
 */
static void
print_ns_type(int flags, int headerflags, char *xtra)
{
	int opcode = (headerflags & 0x7800)>>11;
	int response = (headerflags & 1<<15);
	char *resptype = response ? "Response" : "Request";
	char *optype;

	switch (opcode) {
	case 0:
		optype = "Query";
		break;
	case 5:
		optype = "Registration";
		break;
	case 6:
		optype = "Release";
		break;
	case 7:
		optype = "WACK";
		break;
	case 8:
		optype = "Refresh";
		break;
	default:
		optype = "Unknown";
		break;
	}

	if (flags & F_DTAIL)
		sprintf(get_line(0, 0), "Type = %s %s", optype, resptype);
	else
		sprintf(xtra, "%s %s", optype, resptype);
}


/*
 * Interpret Datagram Packets
 * [RFC 1002, Sec. 4.4]
 */
void
interpret_netbios_datagram(int flags, uchar_t *data, int len)
{
	char name[24];
	int packettype = data[0];
	int packetlen;
	data++;

	if (packettype < 0x10 || packettype > 0x11)
		return;

	if (flags & F_SUM) {
		data += 14;
		netbiosname2ascii(name, data);
		sprintf(get_sum_line(),
				"NBT Datagram Service Type=%d Source=%s",
				packettype, name);
	}

	if (flags & F_DTAIL) {
		show_header("NBT:  ", "Netbios Datagram Service Header", len);
		show_space();
		sprintf(get_line(0, 0), "Datagram Packet Type = 0x%.2x",
					packettype);
		sprintf(get_line(0, 0), "Datagram Flags = 0x%.2x",
					data[0]);
		data++;
		sprintf(get_line(0, 0), "Datagram ID = 0x%.4x",
					getshort(data));
		data += 2;
		sprintf(get_line(0, 0), "Source IP = %d.%d.%d.%d",
					data[0], data[1], data[2], data[3]);
		data += 4;
		sprintf(get_line(0, 0), "Source Port = %d",
					getshort(data));
		data += 2;
		packetlen = getshort(data);
		sprintf(get_line(0, 0), "Datagram Length = 0x%.4x",
					packetlen);
		data += 2;
		sprintf(get_line(0, 0), "Packet Offset = 0x%.4x",
					getshort(data));
		data += 3;
		netbiosname2ascii(name, data);
		sprintf(get_line(0, 0), "Source Name = %s", name);
		data += 34;
		netbiosname2ascii(name, data);
		sprintf(get_line(0, 0), "Destination Name = %s", name);
		sprintf(get_line(0, 0), "Number of data bytes remaining = %d",
					packetlen - 68);
		show_trailer();
	}
}

/*
 * Interpret NetBIOS Name Service packets.
 * [RFC 1002, Sec. 4.2]
 */
void
interpret_netbios_ns(int flags, uchar_t *data, int len)
{
	int headerflags, qcount, acount, nscount, arcount;
	int transid;
	char name[24];
	char extra[256];
	char errortype[50];
	int rdatalen;
	int rrflags;
	int nameptr;
	int nodecode;
	char *nodetype;
	uchar_t *data0 = data;

	transid = getshort(data); data += 2;
	headerflags = getshort(data); data += 2;
	qcount = getshort(data); data += 2;
	acount = getshort(data); data += 2;
	nscount = getshort(data); data += 2;
	arcount = getshort(data); data += 2;
	getrcodeerr(headerflags, errortype);

	if (flags & F_SUM) {
		print_ns_type(flags, headerflags, extra);
		data++;
		netbiosname2ascii(name, data);
		sprintf(get_sum_line(), "NBT NS %s for %s, %s",
			extra, name, errortype);

	}


	if (flags & F_DTAIL) {
		show_header("NBT:  ", "Netbios Name Service Header", len);
		show_space();
		print_ns_type(flags, headerflags, 0);
		sprintf(get_line(0, 0), "Status = %s", errortype);
		sprintf(get_line(0, 0), "Transaction ID = 0x%.4x", transid);
		sprintf(get_line(0, 0), "Flags Summary = 0x%.4x",
					headerflags);
		print_flag_details(headerflags);
		sprintf(get_line(0, 0), "Question count = %d", qcount);
		sprintf(get_line(0, 0), "Answer Count = %d", acount);
		sprintf(get_line(0, 0), "Name Service Count = %d", nscount);
		sprintf(get_line(0, 0),
				"Additional Record Count = %d", arcount);

		/*
		 * Question Section Packet Description from
		 * [RFC 1002, Sec. 4.2.1.2]
		 */

		if (qcount) {
			data++;
			netbiosname2ascii(name, data);
			sprintf(get_line(0, 0), "Question Name = %s", name);
			data += 33;
			sprintf(get_line(0, 0), "Question Type = 0x%.4x",
						getshort(data));
			data += 2;
			sprintf(get_line(0, 0), "Question Class = 0x%.4x",
						getshort(data));
			data += 2;
		}

		/*
		 * Resrouce Record Packet Description from
		 * [RFC 1002, Sec. 4.2.1.3]
		 */

		if ((acount || nscount || arcount) ||
		    (qcount+acount+nscount+arcount == 0)) {
			/* Second level encoding from RFC883 (p.31, 32) */
			if (data[0] & 0xc0) {
				nameptr = getshort(data)&0x3fff;
				netbiosname2ascii(name, (data0+nameptr+1));
				sprintf(get_line(0, 0),
					"Resource Record Name = %s", name);
				data += 2;
			} else {
				data++;
				netbiosname2ascii(name, data);
				sprintf(get_line(0, 0),
					"Resource Record Name = %s", name);
				data += 33;
			}
			sprintf(get_line(0, 0),
					"Resource Record Type = 0x%.4x",
					getshort(data));
			data += 2;
			sprintf(get_line(0, 0),
					"Resource Record Class = 0x%.4x",
					getshort(data));
			data += 2;
			sprintf(get_line(0, 0),
				"Time to Live (Milliseconds) = %d",
				getlong(data));
			data += 4;
			rdatalen = getshort(data);
			sprintf(get_line(0, 0), "RDATA Length = 0x%.4x",
						rdatalen);
			data += 2;
			/* 15.4.2.1.3 */
			if (rdatalen == 6) {
				rrflags = getshort(data);
				data += 2;
				sprintf(get_line(0, 0),
					"Resource Record Flags = 0x%.4x",
					rrflags);
				nodecode = (rrflags>>13)& 0x11;
				if (nodecode == 0) nodetype = "B";
				if (nodecode == 1) nodetype = "P";
				if (nodecode == 2) nodetype = "M";
				sprintf(get_line(0, 0), "   - %s, %s node",
					(rrflags & 1<<15) ?
					"Group NetBIOS Name":
					"Unique NetBIOS Name", nodetype);
				sprintf(get_line(0, 0),
					"Owner IP Address = %d.%d.%d.%d",
					data[0], data[1], data[2], data[3]);
			}
		}
		show_trailer();

	}
}

/*
 * Interpret NetBIOS session packets.
 * [RFC 1002, Sec. 4.3]
 */
void
interpret_netbios_ses(int flags, uchar_t *data, int len)
{
	struct nbt_ss *ss;
	uchar_t *trailer;
	int length = len - 4;   /* NBT packet length without header */
	char *type;
	char extrainfo[300];

	if (len < sizeof (struct nbt_ss))
		return;

	/*
	 * Packets that are fragments of a large NetBIOS session
	 * message will have no NetBIOS header.  (Only the first
	 * TCP segment will have a NetBIOS header.)  It turns out
	 * that very often, such fragments start with SMB data, so
	 * we should try to recognize and decode them.
	 */
	if (data[0] == 0xff &&
	    data[1] == 'S' &&
	    data[2] == 'M' &&
	    data[3] == 'B') {
		interpret_smb(flags, data, len);
		return;
	}

	/* LINTED PTRALIGN */
	ss = (struct nbt_ss *)data;
	trailer = data + sizeof (*ss);
	extrainfo[0] = '\0';

	if (flags & F_SUM) {
		switch (ss->type) {
		case 0x00:
			type = "SESSION MESSAGE";
			break;
		case 0x81:
			type = "SESSION REQUEST";
			interpret_netbios_names(flags, trailer,
						length, extrainfo);
			break;
		case 0x82:
			type = "POSITIVE SESSION RESPONSE";
			break;
		case 0x83:
			type = "NEGATIVE SESSION RESPONSE";
			break;
		case 0x84:
			type = "RETARGET SESSION RESPONSE";
			break;
		case 0x85:
			type = "SESSION KEEP ALIVE";
			break;
		default:
			type = "Unknown";
			break;
		}
		(void) sprintf(get_sum_line(),
			"NBT Type=%s %sLength=%d", type, extrainfo, length);
	}

	if (flags & F_DTAIL) {
		show_header("NBT:  ", "NBT Header", len);
		show_space();

		switch (ss->type) {
		case 0x00:
			(void) sprintf(get_line(0, 0),
			"Type = SESSION MESSAGE");
			break;
		case 0x81:
			(void) sprintf(get_line(0, 0),
			"Type = SESSION REQUEST");
			interpret_netbios_names(flags, trailer, length, 0);
			break;
		case 0x82:
			(void) sprintf(get_line(0, 0),
			"Type = POSITIVE SESSION RESPONSE");
			break;
		case 0x83:
			(void) sprintf(get_line(0, 0),
			"Type = NEGATIVE SESSION RESPONSE");
			break;
		case 0x84:
			(void) sprintf(get_line(0, 0),
			"Type = RETARGET SESSION RESPONSE");
			break;
		case 0x85:
			(void) sprintf(get_line(0, 0),
			"Type = SESSION KEEP ALIVE");
			break;
		default:
			(void) sprintf(get_line(0, 0),
			"Type = Unknown");
			break;
		}

		(void) sprintf(get_line(0, 0), "Length = %d bytes", length);
		show_trailer();
	}

	/*
	 * SMB packets have { 0xff, 'S', 'M', 'B' }
	 * in the first four bytes.  If we find that,
	 * let snoop_smb.c have a look at it.
	 */
	if (ss->type == 0x00 &&
	    length > 0 &&
	    trailer[0] == 0xff &&
	    trailer[1] == 'S' &&
	    trailer[2] == 'M' &&
	    trailer[3] == 'B')
		interpret_smb(flags, trailer, length);
}

/*
 * NetBIOS name encoding (First Level Encoding)
 * [RFC 1001, Sec. 4.1]
 */
static void
netbiosname2ascii(char *aname, uchar_t *nbname)
{
	int c, i, j;

	i = j = 0;
	for (;;) {
		c = nbname[i++] - 'A';
		c = (c << 4) +
			nbname[i++] - 'A';
		/* 16th char is the "type" */
		if (i >= 32)
			break;
		if (iscntrl(c))
			c = '.';
		if (c != ' ')
			aname[j++] = c;
	}
	sprintf(&aname[j], "[%x]", c);
}

/*
 * Interpret the names in a Session Request packet.
 * [RFC 1002, Sec. 4.3.2]
 */
static void
interpret_netbios_names(int flags, uchar_t *data, int len, char *xtra)
{
	char  calledname[24];
	char callingname[24];
	struct callnames *names = (struct callnames *)data;

	if (len < sizeof (*names))
		return;

	netbiosname2ascii(calledname, names->calledname);
	netbiosname2ascii(callingname, names->callingname);

	if (flags & F_SUM) {
		sprintf(xtra, "Dest=%s Source=%s ", calledname, callingname);
	}

	if (flags & F_DTAIL) {
		sprintf(get_line(0, 0), "Destination = %s", calledname);
		sprintf(get_line(0, 0), "Source = %s", callingname);
	}
}
