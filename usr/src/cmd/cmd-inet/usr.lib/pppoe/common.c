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
 * PPPoE common utilities and data.
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <assert.h>
#include <stropts.h>
#include <sys/types.h>
#include <inet/common.h>
#include <netinet/in.h>
#include <net/sppptun.h>
#include <net/pppoe.h>
#include <arpa/inet.h>

#include "common.h"

/* Not all functions are used by all applications.  Let lint know this. */
/*LINTLIBRARY*/

/* Common I/O buffers */
uint32_t pkt_input[PKT_INPUT_LEN / sizeof (uint32_t)];
uint32_t pkt_octl[PKT_OCTL_LEN / sizeof (uint32_t)];
uint32_t pkt_output[PKT_OUTPUT_LEN / sizeof (uint32_t)];

const char tunnam[] = "/dev/" PPP_TUN_NAME;

const ether_addr_t ether_bcast = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

/*
 * Wrapper for standard strerror() function -- the standard allows
 * that routine to return NULL, and that's inconvenient to handle.
 * This function never returns NULL.
 */
const char *
mystrerror(int err)
{
	const char *estr;
	static char ebuf[64];

	if ((estr = strerror(err)) != NULL)
		return (estr);
	(void) snprintf(ebuf, sizeof (ebuf), "Error:%d", err);
	return (ebuf);
}

/*
 * Wrapper for standard perror() function -- the standard definition
 * of perror doesn't include the program name in the output and is
 * thus inconvenient to use.
 */
void
myperror(const char *emsg)
{
	(void) fprintf(stderr, "%s: %s: %s\n", myname, emsg,
	    mystrerror(errno));
}

/*
 * Wrapper for standard getmsg() function.  Completely discards any
 * fragmented messages because we don't expect ever to see these from
 * a properly functioning tunnel driver.  Returns flags
 * (MORECTL|MOREDATA) as seen by interface.
 */
int
mygetmsg(int fd, struct strbuf *ctrl, struct strbuf *data, int *flags)
{
	int retv;
	int hadflags;

	hadflags = getmsg(fd, ctrl, data, flags);
	if (hadflags <= 0 || !(hadflags & (MORECTL | MOREDATA)))
		return (hadflags);

	do {
		if (flags != NULL)
			*flags = 0;
		retv = getmsg(fd, ctrl, data, flags);
	} while (retv > 0 || (retv < 0 && errno == EINTR));

	/*
	 * What remains at this point is the tail end of the
	 * truncated message.  Toss it.
	 */

	return (retv < 0 ? retv : hadflags);
}

/*
 * Common wrapper function for STREAMS I_STR ioctl.  Returns -1 on
 * failure, 0 for success.
 */
int
strioctl(int fd, int cmd, void *ptr, int ilen, int olen)
{
	struct strioctl	str;

	str.ic_cmd = cmd;
	str.ic_timout = 0;	/* Default timeout; 15 seconds */
	str.ic_len = ilen;
	str.ic_dp = ptr;

	if (ioctl(fd, I_STR, &str) == -1) {
		return (-1);
	}
	if (str.ic_len != olen) {
		errno = EINVAL;
		return (-1);
	}
	return (0);
}

/*
 * Format a PPPoE header in the user's buffer.  The returned pointer
 * is either identical to the first argument, or is NULL if it's not
 * usable.  On entry, dptr should point to the first byte after the
 * Ethertype field, codeval should be one of the POECODE_* values, and
 * sessionid should be the assigned session ID number or one of the
 * special POESESS_* values.
 */
poep_t *
poe_mkheader(void *dptr, uint8_t codeval, int sessionid)
{
	poep_t *poep;

	/* Discard obvious junk. */
	assert(dptr != NULL && IS_P2ALIGNED(dptr, sizeof (poep_t *)));

	/* Initialize the header */
	poep = (poep_t *)dptr;
	poep->poep_version_type = POE_VERSION;
	poep->poep_code = codeval;
	poep->poep_session_id = htons(sessionid);
	poep->poep_length = htons(0);
	return (poep);
}

/*
 * Validate that a given tag is intact.  This is intended to be used
 * in tag-parsing loops before attempting to access the tag data.
 */
boolean_t
poe_tagcheck(const poep_t *poep, int length, const uint8_t *tptr)
{
	int plen;
	const uint8_t *tstart, *tend;

	if (poep == NULL || !IS_P2ALIGNED(poep, sizeof (uint16_t)) ||
	    tptr == NULL || length < sizeof (*poep))
		return (B_FALSE);

	plen = poe_length(poep);
	if (plen + sizeof (*poep) > length)
		return (B_FALSE);

	tstart = (const uint8_t *)(poep+1);
	tend = tstart + plen;

	/*
	 * Note careful dereference of tptr; it might be near the end
	 * already, so we have to range check it before dereferencing
	 * to get the actual tag length.  Yes, it looks like we have
	 * duplicate array end checks.  No, they're not duplicates.
	 */
	if (tptr < tstart || tptr+POET_HDRLEN > tend ||
	    tptr+POET_HDRLEN+POET_GET_LENG(tptr) > tend)
		return (B_FALSE);
	return (B_TRUE);
}

static int
poe_tag_insert(poep_t *poep, uint16_t ttype, const void *data, size_t dlen)
{
	int plen;
	uint8_t *dp;

	plen = poe_length(poep);
	if (data == NULL)
		dlen = 0;
	if (sizeof (*poep) + plen + POET_HDRLEN + dlen > PPPOE_MSGMAX)
		return (-1);
	dp = (uint8_t *)(poep + 1) + plen;
	POET_SET_TYPE(dp, ttype);
	POET_SET_LENG(dp, dlen);
	if (dlen > 0)
		(void) memcpy(POET_DATA(dp), data, dlen);
	poep->poep_length = htons(plen + POET_HDRLEN + dlen);
	return (0);
}

/*
 * Add a tag with text string data to a PPPoE packet being
 * constructed.  Returns -1 if it doesn't fit, or 0 for success.
 */
int
poe_add_str(poep_t *poep, uint16_t ttype, const char *str)
{
	return (poe_tag_insert(poep, ttype, str, strlen(str)));
}

/*
 * Add a tag with 32-bit integer data to a PPPoE packet being
 * constructed.  Returns -1 if it doesn't fit, or 0 for success.
 */
int
poe_add_long(poep_t *poep, uint16_t ttype, uint32_t val)
{
	val = htonl(val);
	return (poe_tag_insert(poep, ttype, &val, sizeof (val)));
}

/*
 * Add a tag with two 32-bit integers to a PPPoE packet being
 * constructed.  Returns -1 if it doesn't fit, or 0 for success.
 */
int
poe_two_longs(poep_t *poep, uint16_t ttype, uint32_t val1, uint32_t val2)
{
	uint32_t vals[2];

	vals[0] = htonl(val1);
	vals[1] = htonl(val2);
	return (poe_tag_insert(poep, ttype, vals, sizeof (vals)));
}

/*
 * Copy a single tag and its data from one PPPoE packet to a PPPoE
 * packet being constructed.  Returns -1 if it doesn't fit, or 0 for
 * success.
 */
int
poe_tag_copy(poep_t *poep, const uint8_t *tagp)
{
	int tlen;
	int plen;

	tlen = POET_GET_LENG(tagp) + POET_HDRLEN;
	plen = poe_length(poep);
	if (sizeof (*poep) + plen + tlen > PPPOE_MSGMAX)
		return (-1);
	(void) memcpy((uint8_t *)(poep + 1) + plen, tagp, tlen);
	poep->poep_length = htons(tlen + plen);
	return (0);
}

struct tag_list {
	int tl_type;
	const char *tl_name;
};

/* List of PPPoE data tag types. */
static const struct tag_list tag_list[] = {
	{ POETT_END, "End-Of-List" },
	{ POETT_SERVICE, "Service-Name" },
	{ POETT_ACCESS, "AC-Name" },
	{ POETT_UNIQ, "Host-Uniq" },
	{ POETT_COOKIE, "AC-Cookie" },
	{ POETT_VENDOR, "Vendor-Specific" },
	{ POETT_RELAY, "Relay-Session-Id" },
	{ POETT_NAMERR, "Service-Name-Error" },
	{ POETT_SYSERR, "AC-System-Error" },
	{ POETT_GENERR, "Generic-Error" },
	{ POETT_MULTI, "Multicast-Capable" },
	{ POETT_HURL, "Host-URL" },
	{ POETT_MOTM, "Message-Of-The-Minute" },
	{ POETT_RTEADD, "IP-Route-Add" },
	{ 0, NULL }
};

/* List of PPPoE message code numbers. */
static const struct tag_list code_list[] = {
	{ POECODE_DATA, "Data" },
	{ POECODE_PADO, "Active Discovery Offer" },
	{ POECODE_PADI, "Active Discovery Initiation" },
	{ POECODE_PADR, "Active Discovery Request" },
	{ POECODE_PADS, "Active Discovery Session-confirmation" },
	{ POECODE_PADT, "Active Discovery Terminate" },
	{ POECODE_PADM, "Active Discovery Message" },
	{ POECODE_PADN, "Active Discovery Network" },
	{ 0, NULL }
};

/*
 * Given a tag type number, return a pointer to a string describing
 * the tag.
 */
const char *
poe_tagname(uint16_t tagtype)
{
	const struct tag_list *tlp;
	static char tname[32];

	for (tlp = tag_list; tlp->tl_name != NULL; tlp++)
		if (tagtype == tlp->tl_type)
			return (tlp->tl_name);
	(void) sprintf(tname, "Tag%d", tagtype);
	return (tname);
}

/*
 * Given a PPPoE message code number, return a pointer to a string
 * describing the message.
 */
const char *
poe_codename(uint8_t codetype)
{
	const struct tag_list *tlp;
	static char tname[32];

	for (tlp = code_list; tlp->tl_name != NULL; tlp++)
		if (codetype == tlp->tl_type)
			return (tlp->tl_name);
	(void) sprintf(tname, "Code%d", codetype);
	return (tname);
}

/*
 * Given a tunnel driver address structure, return a pointer to a
 * string naming that Ethernet host.
 */
const char *
ehost2(const struct ether_addr *ea)
{
	static char hbuf[MAXHOSTNAMELEN+1];

	if (ea == NULL)
		return ("NULL");
	if (ether_ntohost(hbuf, ea) == 0)
		return (hbuf);
	return (ether_ntoa(ea));
}

const char *
ehost(const ppptun_atype *pap)
{
	return (ehost2((const struct ether_addr *)pap));
}

/*
 * Given an Internet address (in network byte order), return a pointer
 * to a string naming the host.
 */
const char *
ihost(uint32_t haddr)
{
	struct hostent *hp;
	struct sockaddr_in sin;

	(void) memset(&sin, '\0', sizeof (sin));
	sin.sin_addr.s_addr = haddr;
	hp = gethostbyaddr((const char *)&sin, sizeof (sin), AF_INET);
	if (hp != NULL)
		return (hp->h_name);
	return (inet_ntoa(sin.sin_addr));
}

int
hexdecode(char chr)
{
	if (chr >= '0' && chr <= '9')
		return ((int)(chr - '0'));
	if (chr >= 'a' && chr <= 'f')
		return ((int)(chr - 'a' + 10));
	return ((int)(chr - 'A' + 10));
}
