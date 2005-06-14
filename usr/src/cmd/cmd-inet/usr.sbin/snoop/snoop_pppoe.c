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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/pppoe.h>
#include "snoop.h"

/*
 * These two macros extract the version and type fields respectively from
 * the first byte of the PPPoE header.
 */
#define	POE_VERS(x)	(((x) >> 4) & 0x0f)
#define	POE_TYPE(x)	((x) & 0x0f)

typedef void interpret_func_t(uint8_t *, uint16_t);

typedef struct taginfo {
	char *tag_name;
	uint16_t tag_type;
	interpret_func_t *interpret_tagvalue;
} taginfo_t;


static char *pppoe_codetoname(int, boolean_t);
static taginfo_t *pppoe_gettaginfo(uint16_t);
static void print_hexdata(char *, uint8_t *, uint16_t);
static void print_utf8string(char *, char *, uint16_t);
static char *print_linetag(char *);
static interpret_func_t interpret_tags;
static interpret_func_t interpret_hexdata;
static interpret_func_t interpret_service;
static interpret_func_t interpret_access;
static interpret_func_t interpret_cookie;
static interpret_func_t interpret_vendor;
static interpret_func_t interpret_relay;
static interpret_func_t interpret_error;
static interpret_func_t interpret_hurl;
static interpret_func_t interpret_motm;
static interpret_func_t interpret_rteadd;


static taginfo_t taginfo_array[] = {
	{ "End-Of-List",	POETT_END,	interpret_hexdata },
	{ "Service-Name",	POETT_SERVICE,	interpret_service },
	{ "AC-Name",		POETT_ACCESS,	interpret_access },
	{ "Host-Uniq",		POETT_UNIQ,	interpret_hexdata },
	{ "AC-Cookie",		POETT_COOKIE,	interpret_cookie },
	{ "Vendor-Specific",	POETT_VENDOR,	interpret_vendor },
	{ "Relay-Session-Id",	POETT_RELAY,	interpret_relay },
	{ "Service-Name-Error",	POETT_NAMERR,	interpret_error },
	{ "AC-System-Error",	POETT_SYSERR,	interpret_error },
	{ "Generic-Error",	POETT_GENERR,	interpret_error },
	{ "Multicast-Capable",	POETT_MULTI,	interpret_hexdata },
	{ "Host-URL",		POETT_HURL,	interpret_hurl },
	{ "Message-Of-The-Minute", POETT_MOTM,	interpret_motm },
	{ "IP-Route-Add",	POETT_RTEADD,	interpret_rteadd },
	{ "Unknown TAG",	0,		NULL }
};


int
interpret_pppoe(int flags, poep_t *poep, int len)
{
	uint8_t code = poep->poep_code;
	uint8_t *payload;

	if (len < sizeof (poep_t))
		return (len);

	payload = (uint8_t *)poep + sizeof (poep_t);

	if (flags & F_SUM) {
		(void) sprintf(get_sum_line(), "PPPoE %s",
		    pppoe_codetoname(code, B_FALSE));
	} else { /* flags & F_DTAIL */
		show_header("PPPoE:  ", "PPP Over Ethernet", len);
		show_space();

		(void) sprintf(get_line(0, 0),
		    "Version = %d", POE_VERS(poep->poep_version_type));

		(void) sprintf(get_line(0, 0),
		    "Type = %d", POE_TYPE(poep->poep_version_type));

		(void) sprintf(get_line(0, 0),
		    "Code = %d (%s)", code, pppoe_codetoname(code, B_TRUE));

		(void) sprintf(get_line(0, 0),
		    "Session Id = %d", ntohs(poep->poep_session_id));

		(void) sprintf(get_line(0, 0),
		    "Length = %d bytes", ntohs(poep->poep_length));

		show_space();

		len -= sizeof (poep_t);
		len = MIN(len, ntohs(poep->poep_length));

		if (poep->poep_code != 0 && poep->poep_length > 0) {
			interpret_tags(payload, len);
		}
	}

	if (poep->poep_code == 0) {
		return (interpret_ppp(flags, payload, len));
	}
	return (len);
}


/*
 * interpret_tags() prints PPPoE Discovery Stage TAGs in detail.
 */
static void
interpret_tags(uint8_t *payload, uint16_t length)
{
	uint8_t *tagptr = payload;
	uint16_t tag_length;
	uint16_t tag_type;
	uint8_t *tag_value;
	taginfo_t *tinfo;

	while (length >= POET_HDRLEN) {
		tag_type = POET_GET_TYPE(tagptr);
		tag_length = POET_GET_LENG(tagptr);

		tinfo = pppoe_gettaginfo(tag_type);

		show_header("PPPoE:  ", tinfo->tag_name,
		    tag_length + POET_HDRLEN);

		(void) sprintf(get_line(0, 0),
		    "Tag Type = %d", tag_type);

		(void) sprintf(get_line(0, 0),
		    "Tag Length = %d bytes", tag_length);

		length -= POET_HDRLEN;
		if (tag_length > length) {
			(void) sprintf(get_line(0, 0),
			    "Warning: Truncated Packet");
			show_space();
			break;
		}

		/*
		 * unknown tags or tags which should always have 0 length
		 * are not interpreted any further.
		 */
		tag_value = POET_DATA(tagptr);
		if (tag_length != 0 && tinfo->interpret_tagvalue != NULL)
			tinfo->interpret_tagvalue(tag_value, tag_length);

		show_space();
		length -= tag_length;
		tagptr = POET_NEXT(tagptr);
	}
}

static char *
pppoe_codetoname(int code, boolean_t verbose)
{
	char *name;

	switch (code) {
	case POECODE_DATA:
		name = "Session";
		break;
	case POECODE_PADO:
		if (verbose)
			name = "Active Discovery Offer";
		else
			name = "PADO";
		break;
	case POECODE_PADI:
		if (verbose)
			name = "Active Discovery Initiation";
		else
			name = "PADI";
		break;
	case POECODE_PADR:
		if (verbose)
			name = "Active Discovery Request";
		else
			name = "PADR";
		break;
	case POECODE_PADS:
		if (verbose)
			name = "Active Discovery Session-Confirmation";
		else
			name = "PADS";
		break;
	case POECODE_PADT:
		if (verbose)
			name = "Active Discovery Terminate";
		else
			name = "PADT";
		break;
	case POECODE_PADM:
		if (verbose)
			name = "Active Discovery Message";
		else
			name = "PADM";
		break;
	case POECODE_PADN:
		if (verbose)
			name = "Active Discovery Network";
		else
			name = "PADN";
		break;
	default:
		name = "Unknown Code";
	}

	return (name);
}

static taginfo_t *
pppoe_gettaginfo(uint16_t type)
{
	taginfo_t *taginfo_ptr = &taginfo_array[0];
	int i = 0;

	while (taginfo_ptr->tag_type != type &&
	    taginfo_ptr->interpret_tagvalue != NULL) {
		taginfo_ptr = &taginfo_array[++i];
	}

	return (taginfo_ptr);
}

static void
interpret_hexdata(uint8_t *tag_value, uint16_t tag_length)
{
	char *endofline;

	endofline = print_linetag("Data = ");
	print_hexdata(endofline, tag_value, tag_length);
}

static void
interpret_service(uint8_t *tag_value, uint16_t tag_length)
{
	char *endofline;

	endofline = print_linetag("Service Name = ");
	print_utf8string(endofline, (char *)tag_value, tag_length);
}

static void
interpret_access(uint8_t *tag_value, uint16_t tag_length)
{
	char *endofline;

	endofline = print_linetag("AC Name = ");
	print_utf8string(endofline, (char *)tag_value, tag_length);
}

static void
interpret_cookie(uint8_t *tag_value, uint16_t tag_length)
{
	char *endofline;

	endofline = print_linetag("Cookie = ");
	print_hexdata(endofline, tag_value, tag_length);
}

static void
interpret_vendor(uint8_t *tag_value, uint16_t tag_length)
{
	uint8_t *vendor_data;
	uint32_t vendorid;
	char *endofline;

	vendorid = ntohl(*(uint32_t *)tag_value);
	(void) sprintf(get_line(0, 0),
	    "Vendor ID = %d", vendorid);

	if (tag_length > 4) {
		vendor_data = tag_value + 4;
		endofline = print_linetag("Vendor Data = ");
		print_hexdata(endofline, vendor_data, tag_length - 4);
	}
}

static void
interpret_relay(uint8_t *tag_value, uint16_t tag_length)
{
	char *endofline;

	endofline = print_linetag("ID = ");
	print_hexdata(endofline, tag_value, tag_length);
}

static void
interpret_error(uint8_t *tag_value, uint16_t tag_length)
{
	char *endofline;

	endofline = print_linetag("Error = ");
	print_utf8string(endofline, (char *)tag_value, tag_length);
}

static void
interpret_hurl(uint8_t *tag_value, uint16_t tag_length)
{
	char *endofline;

	endofline = print_linetag("URL = ");
	print_utf8string(endofline, (char *)tag_value, tag_length);
}

static void
interpret_motm(uint8_t *tag_value, uint16_t tag_length)
{
	char *endofline;

	endofline = print_linetag("Message = ");
	print_utf8string(endofline, (char *)tag_value, tag_length);
}

static void
interpret_rteadd(uint8_t *tag_value, uint16_t tag_length)
{
	char dest[INET_ADDRSTRLEN];
	char mask[INET_ADDRSTRLEN];
	char gateway[INET_ADDRSTRLEN];
	uint32_t metric;

	if (tag_length == 16) {
		(void) inet_ntop(AF_INET, tag_value, dest,
		    INET_ADDRSTRLEN);
		(void) inet_ntop(AF_INET, &tag_value[4], mask,
		    INET_ADDRSTRLEN);
		(void) inet_ntop(AF_INET, &tag_value[8], gateway,
		    INET_ADDRSTRLEN);
		metric = ntohl(*(uint32_t *)&tag_value[12]);
		sprintf(get_line(0, 0),
		    "Destination\tNetmask\tGateway\tMetric");
		sprintf(get_line(0, 0),
		    "%s\t%s\t%s\t%d", dest, mask, gateway, metric);
	}
}

static void
print_hexdata(char *line, uint8_t *data, uint16_t length)
{
	uint16_t index = 0;

	line += sprintf(line, "0x");

	while (index < length) {
		line += sprintf(line, "%02x", data[index++]);
	}
}

static void
print_utf8string(char *firstline, char *string, uint16_t length)
{
	(void) sprintf(firstline, "%.*s", length, string);
}

static char *
print_linetag(char *string)
{
	char *line = get_line(0, 0);
	return (line + sprintf(line, string));
}
