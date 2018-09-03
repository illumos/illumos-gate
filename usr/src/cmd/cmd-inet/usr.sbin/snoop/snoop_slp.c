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
 * Copyright (c) 1998,2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <iconv.h>
#include "snoop.h"
#include "slp.h"

#define	MAXSUMLEN 30

/* define VERIFYSLP to enable full message checking in summary mode */
#define	VERIFYSLP

/* Globals -- ugly, yes, but fast and easy in macros */
static int msglength;
static int retlength;
static char *msgend;	/* the end of the summary message buffer */
static char *p;		/* current position in the packet */
static char *msgbuf;	/* message buffer for summary mode */
static boolean_t url_auth	= B_FALSE;
static boolean_t attr_auth	= B_FALSE;
static boolean_t fresh		= B_FALSE;
static boolean_t overflow	= B_FALSE;
static int v1_charset		= 0;	/* character set; only in V1 */

/* Entry points for parsing the protocol */
static int interpret_slp_v1(int, struct slpv1_hdr *, int);
static int interpret_slp_v2(int, struct slpv2_hdr *, int);

/* header parsing */
static int v1_header(int, struct slpv1_hdr *, int);
static int v2_header(int, struct slpv2_hdr *, int *, int);
static int v2_finish(struct slpv2_hdr *, int);

/* V2 auth blocks */
static int slpv2_authblock(int);

/*
 * Functions for parsing each protocol message
 * Each function takes the interpreter's flags argument as its input
 * parameter, and returns 1 on success, or 0 on message corruption.
 * retlength is set as a side-effect in summary mode.
 */
static int v2_srv_rqst(int);
static int v2_srv_rply(int);
static int v2_srv_reg(int);
static int v2_srv_dereg(int);
static int v2_srv_ack(int);
static int v2_attr_rqst(int);
static int v2_attr_rply(int);
static int v2_daadvert(int);
static int v2_srv_type_rqst(int);
static int v2_srv_type_rply(int);
static int v2_saadvert(int);

static int v1_srv_rqst(int);
static int v1_srv_rply(int);
static int v1_srv_reg(int);
static int v1_srv_dereg(int);
static int v1_srv_ack(int);
static int v1_attr_rqst(int);
static int v1_attr_rply(int);
static int v1_daadvert(int);
static int v1_srv_type_rqst(int);
static int v1_srv_type_rply(int);

/*
 * The dispatch tables for handling individual messages, keyed by
 * function number.
 */
typedef int function_handler();

#define	V2_MAX_FUNCTION	11

static function_handler *v2_functions[V2_MAX_FUNCTION + 1] = {
	(function_handler *) NULL,
	(function_handler *) v2_srv_rqst,
	(function_handler *) v2_srv_rply,
	(function_handler *) v2_srv_reg,
	(function_handler *) v2_srv_dereg,
	(function_handler *) v2_srv_ack,
	(function_handler *) v2_attr_rqst,
	(function_handler *) v2_attr_rply,
	(function_handler *) v2_daadvert,
	(function_handler *) v2_srv_type_rqst,
	(function_handler *) v2_srv_type_rply,
	(function_handler *) v2_saadvert };

#define	V1_MAX_FUNCTION	10

static function_handler *v1_functions[V1_MAX_FUNCTION + 1] = {
	(function_handler *) NULL,
	(function_handler *) v1_srv_rqst,
	(function_handler *) v1_srv_rply,
	(function_handler *) v1_srv_reg,
	(function_handler *) v1_srv_dereg,
	(function_handler *) v1_srv_ack,
	(function_handler *) v1_attr_rqst,
	(function_handler *) v1_attr_rply,
	(function_handler *) v1_daadvert,
	(function_handler *) v1_srv_type_rqst,
	(function_handler *) v1_srv_type_rply };

/* TCP continuation handling */
static boolean_t tcp_continuation = B_FALSE;

#define	MAX_TCPCONT	16

static struct tcp_cont {
	int dst_port;
	char *msg;
	int totallen;
	int curr_offset;
} *tcp_cont[MAX_TCPCONT];

static int current_tcp_cont;

static void reg_tcp_cont(char *, int, int, int);
static int add_tcp_cont(struct tcp_cont *, char *, int);
static struct tcp_cont *find_tcp_cont(int);
static void remove_tcp_cont(int);

/* Conversions from numbers to strings */
static char *slpv2_func(int, boolean_t);
static char *slpv2_error(unsigned short);
static char *slpv1_func(int, boolean_t);
static char *slpv1_error(unsigned short);
static char *slpv1_charset(unsigned short);

/*
 * The only external entry point to the SLP interpreter. This function
 * simply dispatches the packet based on the version.
 */
void interpret_slp(int flags, void *slp, int fraglen) {
	extern int dst_port, curr_proto;
	struct tcp_cont *tce = NULL;
	char *s;

	msglength = fraglen;
	retlength = 0;
	p = slp;

	/* check if this is a TCP continuation */
	if (flags & F_DTAIL && curr_proto == IPPROTO_TCP) {
	    tce = find_tcp_cont(dst_port);
	    if (tce) {
		if (add_tcp_cont(tce, slp, fraglen)) {
		    slp = tce->msg;
		    fraglen = tce->curr_offset;
		    tcp_continuation = B_TRUE;
		}
	    }
	}
	if (*(char *)slp == 2 || tce)
	    interpret_slp_v2(flags, slp, fraglen);
	else
	    interpret_slp_v1(flags, slp, fraglen);

	tcp_continuation = B_FALSE;
}

/*
 * Primitives. These are implemented as much as possible as macros for
 * speed.
 */

#define	FIELD_DEFAULT	0
#define	FIELD_PREVRESP	1
#define	FIELD_TYPENA	2

static long long netval = 0;	/* need signed 64 bit quantity */

/* gets two bytes from p and leaves the result in netval */
#define	nbtohs() \
	netval = ((int)(p[0] & 0xff)) << 8; \
	netval += ((int)(p[1] & 0xff))

/* gets four bytes from p and leaves the result in netval */
#define	nbtohl() \
	netval = ((int)(p[0] & 0xff)) << 24; \
	netval += ((int)(p[1] & 0xff)) << 16; \
	netval += ((int)(p[2] & 0xff)) << 8; \
	netval += ((int)(p[3] & 0xff))

#define	get_byte() \
	if (msglength >= 1) { \
		netval = *p; \
		p++; \
		msglength--; \
	} else \
		netval = -1

#define	GETBYTE(x) \
	get_byte(); \
	if ((retlength = netval) < 0) \
		return (0); \
	x = netval

#define	SKIPBYTE \
	get_byte(); \
	if ((retlength = netval) < 0) \
		return (0); \

/*
 * gets two bytes from p, leaves the result in netval, and updates
 * msglength and p.
 */
#define	get_short() \
	if (msglength >= sizeof (unsigned short)) { \
		nbtohs(); \
		p += sizeof (unsigned short); \
		msglength -= sizeof (unsigned short); \
	} else \
		netval = -1

#define	GETSHORT(x) \
	get_short(); \
	if ((retlength = netval) < 0) \
		return (0); \
	x = netval

#define	SKIPSHORT \
	get_short(); \
	if ((retlength = netval) < 0) \
		return (0)

#define	get_int24(pp) \
	netval = ((int)((pp)[0] & 0xff)) << 16; \
	netval += ((int)((pp)[1] & 0xff)) << 8; \
	netval += ((int)((pp)[2] & 0xff))

static void slp_prevresp(char *p) {
	char *p2;

	/* cycle through all entries */
	for (; p != NULL; p = p2) {
	    p2 = strchr(p, ',');
	    if (p2 != NULL)
		*p2++ = '\0';

	    /* print entry at p */
	    sprintf(get_line(0, 0), "  \"%s\"", p);
	}
}

static int skip_field(int type) {
	unsigned short stringlen;

	get_short();
	if (netval < 0) {
	    return (-1);
	}
	stringlen = netval;

	/* special case for NA field in SrvTypeRqst */
	if (type == FIELD_TYPENA && stringlen == 0xffff) {
	    stringlen = 0;
	}

	if (stringlen > msglength) {
	    return (-1);
	}

	msglength -= stringlen;
	p += stringlen;

	return (stringlen);
}

#define	SKIPFIELD(type) \
	if ((retlength = skip_field(type)) < 0) \
		return (0)

#define	GETFIELD \
	get_short(); \
	if ((retlength = netval) < 0) \
		return (0); \
	strncat(msgbuf, p, (retlength > MAXSUMLEN ? MAXSUMLEN : retlength)); \
	p += retlength; \
	msglength -= retlength

/*
 * Determines from the first five bytes of a potential SLP header
 * if the following message is really an SLP message. Returns 1 if
 * it is a real SLP message, 0 if not.
 */
int valid_slp(unsigned char *slphdr, int len) {
	struct slpv1_hdr slp1;
	struct slpv2_hdr slp2;

	len -= (8 /* udp */ + 20 /* IP */ + 14 /* ether */);
	/* a valid version will be 1 or 2 */
	switch (*slphdr) {
	case 1:
	    memcpy(&slp1, slphdr, 5);
	    /* valid function? */
	    if (slp1.function > V1_MAX_FUNCTION) {
		return (0);
	    }
	    /* valid length heuristic */
	    if (slp1.length > len) {
		return (0);
	    }
	    return (1);
	case 2:
	    memcpy(&slp2, slphdr, 5);
	    /* valid function? */
	    if (slp2.function > V2_MAX_FUNCTION) {
		return (0);
	    }
	    /* valid length heuristic */
	    get_int24(&(slp2.l1));
	    if (netval > len) {
		return (0);
	    }
	    return (1);
	default:
	    return (0);
	}
}

/*
 * Converts a V1 char encoding to UTF8. If this fails, returns 0,
 * otherwise, 1. This function is the union of iconv UTF-8
 * modules and character sets registered with IANA.
 */
static int make_utf8(char *outbuf, size_t outlen,
			const char *inbuf, size_t inlen) {
	iconv_t cd;
	size_t converted;

	switch (v1_charset) {
	case 4:
	case 1004:
	    cd = iconv_open("UTF-8", "8859-1");
	    break;
	case 5:
	    cd = iconv_open("UTF-8", "8859-2");
	    break;
	case 6:
	    cd = iconv_open("UTF-8", "8859-3");
	    break;
	case 7:
	    cd = iconv_open("UTF-8", "8859-4");
	    break;
	case 8:
	    cd = iconv_open("UTF-8", "8859-5");
	    break;
	case 9:
	    cd = iconv_open("UTF-8", "8859-6");
	    break;
	case 10:
	    cd = iconv_open("UTF-8", "8859-7");
	    break;
	case 11:
	    cd = iconv_open("UTF-8", "8859-8");
	    break;
	case 12:
	    cd = iconv_open("UTF-8", "8859-9");
	    break;
	case 13:
	    cd = iconv_open("UTF-8", "8859-10");
	    break;
	case 37:
	    cd = iconv_open("UTF-8", "ko_KR-iso2022-7");
	    break;
	case 104:
	    cd = iconv_open("UTF-8", "iso2022");
	    break;
	case 1000:
	    cd = iconv_open("UTF-8", "UCS-2");
	    break;
	case 1001:
	    cd = iconv_open("UTF-8", "UCS-4");
	    break;
	default:
		/*
		 * charset not set, or reserved, or not supported, so
		 * just copy it and hope for the best.
		 */
	    converted = outlen < inlen ? outlen : inlen;
	    memcpy(outbuf, inbuf, converted);
	    outbuf[converted] = 0;
	    return (1);
	}

	if (cd == (iconv_t)-1) {
	    return (0);
	}

	if ((converted = iconv(cd, &inbuf, &inlen, &outbuf, &outlen))
	    == (size_t)-1) {
	    return (0);
	}

	outbuf[converted] = 0;
	iconv_close(cd);

	return (1);
}

static int slp_field(char *tag, int type) {
	int length;

	get_short();
	if (netval < 0) {
	    return (-1);
	}
	length = netval;

	/* special case for NA field in SrvTypeRqst */
	if (type == FIELD_TYPENA && length == 0xffff) {
	    sprintf(get_line(0, 0), "%s: length = -1: Use all NAs", tag);
	    return (0);
	}

	sprintf(get_line(0, 0), "%s: length = %d", tag, length);
	if (length > msglength) {
	    /* framing error: message is not long enough to contain data */
	    sprintf(get_line(0, 0),
		    "  [Framing error: remaining pkt length = %u]",
		    msglength);
	    return (-1);
	}

	if (length > 0) {
	    char *buf = malloc(length + 1);
	    if (buf != NULL) {
		if (v1_charset) {
		    if (!make_utf8(buf, length, p, length)) {
			strcpy(buf, "[Invalid Character Encoding]");
		    }
		} else {
		    memcpy(buf, p, length);
		    buf[length] = '\0';		/* ensure null-terminated */
		}

		switch (type) {
		    case FIELD_PREVRESP:
			slp_prevresp(buf);
			break;

		    default:
			sprintf(get_line(0, 0), "  \"%s\"", buf);
			break;
		}
		free(buf);
	    }

	    p += length;
	    msglength -= length;
	}

	/* return ok */
	return (0);
}

static int slpv2_url(int cnt) {
	time_t exp;
	int lifetime, length, n;

	/* reserved */
	get_byte();
	if (netval < 0)
	    return (-1);

	/* lifetime */
	get_short();
	if ((lifetime = netval) < 0)
	    return (-1);

	/* length */
	get_short();
	if ((length = netval) < 0)
	    return (-1);

	/* time */
	exp = time(0) + lifetime;
	if (cnt == -1)
	    sprintf(get_line(0, 0),
		    "URL: length = %u, lifetime = %d (%24.24s)",
		    length, lifetime, ctime(&exp));
	else
	    /* number the URLs to make it easier to parse them */
	    sprintf(get_line(0, 0),
		    "URL %d: length = %u, lifetime = %d (%24.24s)",
		    cnt, length, lifetime, ctime(&exp));

	if (length > msglength) {
	    if (!tcp_continuation)
		/* framing error: message is not long enough to contain data */
		sprintf(get_line(0, 0),
			"  [Framing error: remaining pkt length = %u]",
			msglength);
	    return (-1);
	}

	if (length > 0) {
	    char *buf = malloc(length + 1);
	    if (buf != NULL) {
		memcpy(buf, p, length);
		buf[length] = '\0';		/* ensure null-terminated */
		sprintf(get_line(0, 0), "  \"%s\"", buf);
		free(buf);
	    }
	}
	msglength -= length;
	p += length;

	get_byte();
	if ((n = netval) < 0)
	    return (-1);

	if (n > 0) {
	    int i;
	    sprintf(get_line(0, 0), "%d Authentication Blocks", n);
	    for (i = 0; i < n; i++)
		if ((length = slpv2_authblock(i)) < 0)
		    return (-1);
	}
	return (0);
}

#define	DOFIELD(tag, type) \
	if (slp_field(tag, type) < 0) \
		return (0)

#define	V2_DOURL(x) \
	if (slpv2_url(x) < 0) \
		return (0)

#define	V2_DOERRCODE \
	if (msglength < sizeof (unsigned short)) \
		return (0); \
	nbtohs(); \
	errcode = netval; \
	sprintf(get_line(0, 0), "Error code = %d, %s", \
				errcode, slpv2_error(errcode)); \
	p += sizeof (unsigned short); \
	msglength -= sizeof (unsigned short); \
	if (errcode != OK) \
		msglength = 0;	/* skip rest of message */ \
	if (errcode != OK) \
		return (0)

#define	V2_DOAUTH(cnt) \
	if (slpv2_authblock(cnt) < 0) \
		return (0)

#define	V2_DOTIMESTAMP \
	if (msglength < 4) \
		return (0); \
	nbtohl(); \
	timestamp = netval; \
	sprintf(get_line(0, 0), "Timestamp = %u, %s", \
		timestamp, (timestamp ? convert_ts(timestamp) : "0")); \
	p += 4; \
	msglength -= 4

/* some V1 macros */
#define	SKIPAUTH(auth) \
	if (auth && ((retlength = skip_v1authblock()) < 0)) \
		return (0)

#define	DOERRCODE \
	if (msglength < sizeof (unsigned short)) \
		return (0); \
	nbtohs(); \
	errcode = netval; \
	sprintf(get_line(0, 0), "Error code = %d, %s", errcode, \
				slpv1_error(errcode)); \
	p += sizeof (unsigned short); \
	msglength -= sizeof (unsigned short); \
	if (errcode != OK) \
		return (0)

#define	DOURL \
	if (slpv1_url(url_auth) < 0) \
		return (0)

#define	DOAUTH(auth) \
	if (auth && slpv1_authblock() < 0) \
		return (0)

/*
 * TCP Continuation handling
 * We keep track of continuations in a fixed size cache, so as to prevent
 * memory leaks if some continuations are never finished. The continuations
 * are indexed by their destination ports.
 */
static void reg_tcp_cont(char *msg, int totallen,
			    int fraglen, int dst_port) {
	struct tcp_cont *tce = malloc(sizeof (*tce));

	/* always overwrite the entry at current_tcp_cont */
	if (tcp_cont[current_tcp_cont]) {
	    free(tcp_cont[current_tcp_cont]->msg);
	    free(tcp_cont[current_tcp_cont]);
	}

	tce->dst_port = dst_port;
	tce->msg = malloc(totallen);
	memcpy(tce->msg, msg, fraglen);
	tce->totallen = totallen;
	tce->curr_offset = fraglen;

	tcp_cont[current_tcp_cont++] = tce;
	if (current_tcp_cont == MAX_TCPCONT)
	    current_tcp_cont = 0;
}

/* returns 0 if there is a mismatch error, 1 on success */
static int add_tcp_cont(struct tcp_cont *tce, char *msg, int fraglen) {
	if ((fraglen + tce->curr_offset) > tce->totallen)
	    return (0);

	memcpy(tce->msg + tce->curr_offset, msg, fraglen);
	tce->curr_offset += fraglen;
	return (1);
}

static struct tcp_cont *find_tcp_cont(int dst_port) {
	int i;
	for (i = current_tcp_cont; i >= 0; i--)
	    if (tcp_cont[i] && tcp_cont[i]->dst_port == dst_port)
		return (tcp_cont[i]);

	for (i = MAX_TCPCONT -1; i > current_tcp_cont; i--)
	    if (tcp_cont[i] && tcp_cont[i]->dst_port == dst_port)
		return (tcp_cont[i]);

	return (NULL);
}

static void remove_tcp_cont(int dst_port) {
	int i;
	for (i = current_tcp_cont; i >= 0; i--)
	    if (tcp_cont[i] && tcp_cont[i]->dst_port == dst_port) {
		free(tcp_cont[i]->msg);
		free(tcp_cont[i]);
		tcp_cont[i] = NULL;
		return;
	    }

	for (i = MAX_TCPCONT -1; i > current_tcp_cont; i--)
	    if (tcp_cont[i] && tcp_cont[i]->dst_port == dst_port) {
		free(tcp_cont[i]->msg);
		free(tcp_cont[i]);
		tcp_cont[i] = NULL;
		return;
	    }
}

/*
 * V2 interpreter
 */

static int interpret_slp_v2(int flags, struct slpv2_hdr *slp, int fraglen) {
	extern int src_port, dst_port, curr_proto;
	char msgbuf_real[256];
	int totallen = 0;

	msgbuf = msgbuf_real;

	/*
	 * Somewhat of a hack to decode traffic from a server that does
	 * not send udp replies from its SLP src port.
	 */

	if (curr_proto == IPPROTO_UDP &&
	    dst_port == 427 &&
	    src_port != 427) {
	    add_transient(src_port, (int (*)())interpret_slp);
	}

	/* parse the header */
	if (v2_header(flags, slp, &totallen, fraglen)) {

	    if (slp->function <= V2_MAX_FUNCTION && slp->function > 0) {

		/* Parse the message body */
		if ((v2_functions[slp->function])(flags)) {

		    /* finish any remaining tasks */
		    v2_finish(slp, flags);

		}

	    }

	}

	/* summary error check */
	if (flags & F_SUM) {
	    if (retlength < 0) {
		if (curr_proto == IPPROTO_TCP)
		    sprintf(get_sum_line(),
			    "%s [partial TCP message]", msgbuf);
		else if (overflow)
		    sprintf(get_sum_line(), "%s [OVERFLOW]", msgbuf);
		else
		    sprintf(get_sum_line(), "%s [CORRUPTED MESSAGE]", msgbuf);
	    }
#ifdef VERIFYSLP
	    else if (msglength > 0)
		sprintf(get_sum_line(), "%s +%d", msgbuf, msglength);
#endif
	    else
		sprintf(get_sum_line(), "%s", msgbuf);
	} else if (flags & F_DTAIL) {
	    /* detailed error check */
	    if (msglength > 0) {
		if (tcp_continuation) {
		    sprintf(get_line(0, 0),
			    "[TCP Continuation, %d bytes remaining]",
			    totallen - fraglen);
		} else
		    sprintf(get_line(0, 0),
			"[%d extra bytes at end of SLP message]", msglength);
	    }

	    show_trailer();

	    if (tcp_continuation && msglength == 0)
		remove_tcp_cont(dst_port);
	}

	return (0);
}

static int v2_header(int flags,
			struct slpv2_hdr *slp,
			int *totallen,
			int fraglen) {
	extern int curr_proto, dst_port;
	char *prototag = (curr_proto == IPPROTO_TCP ? "/tcp" : "");

	if ((slp->flags & V2_OVERFLOW) == V2_OVERFLOW)
	    overflow = B_TRUE;

	/* summary mode header parsing */
	if (flags & F_SUM) {

	    /* make sure we have at least a header */
	    if (msglength < sizeof (*slp)) {
		sprintf(get_sum_line(), "SLP V2 [Incomplete Header]");
		return (0);
	    }

	    sprintf(msgbuf, "SLP V2 %s [%d%s] ",
		    slpv2_func(slp->function, B_TRUE),
		    ntohs(slp->xid), prototag);

	    /* skip to end of header */
	    msgend = msgbuf + strlen(msgbuf);
	    msglength -= sizeof (*slp);
	    p += sizeof (*slp);

	    /* skip language tag */
	    SKIPFIELD(FIELD_DEFAULT);
	} else if (flags & F_DTAIL) {
	    char *lang;
	    int len;

	    /* detailed mode header parsing */
	    show_header("SLP:  ", "Service Location Protocol (v2)", fraglen);
	    show_space();

	    if (msglength < sizeof (*slp)) {
		sprintf(get_line(0, 0), "==> Incomplete SLP header");
		return (0);
	    }

	    sprintf(get_line(0, 0), "Version = %d", slp->vers);
	    sprintf(get_line(0, 0), "Function = %d, %s",
		    slp->function, slpv2_func(slp->function, B_FALSE));
	    get_int24(&(slp->l1));
	    *totallen = netval;
	    sprintf(get_line(0, 0), "Message length = %u", *totallen);
	    /* check for TCP continuation */
	    if (curr_proto == IPPROTO_TCP &&
		*totallen > msglength &&
		!tcp_continuation) {
		tcp_continuation = B_TRUE;
		reg_tcp_cont((char *)slp, *totallen, msglength, dst_port);
	    }

	    if (!tcp_continuation && *totallen != msglength) {
		sprintf(get_line(0, 0),
			"  (Stated and on-the-wire lengths differ)");
	    }
	    /* flags */
	    sprintf(get_line(0, 0), "Flags = 0x%02x", slp->flags);
	    sprintf(get_line(0, 0), "      %s",
		    getflag(slp->flags, V2_OVERFLOW,
			    "overflow", "no overflow"));
	    sprintf(get_line(0, 0), "      %s",
		    getflag(slp->flags, V2_FRESH,
			    "fresh registration", "no fresh registration"));
	    sprintf(get_line(0, 0), "      %s",
		    getflag(slp->flags, V2_MCAST,
			    "request multicast / broadcast", "unicast"));
	    /* check reserved flags that must be zero */
	    if ((slp->flags & 7) != 0) {
		sprintf(get_line(0, 0),
			"      .... .xxx = %d (reserved flags nonzero)",
			slp->flags & 7);
	    }
	    /* end of flags */

	    /* language tag */
	    p = (char *)slp + sizeof (*slp);
	    msglength -= sizeof (*slp);
	    GETSHORT(len);
	    if (len > msglength) {
		sprintf(get_line(0, 0),
			"Language Tag Length = %u [CORRUPT MESSAGE]",
			len);
		return (0);
	    }

	    lang = get_line(0, 0);
	    strcpy(lang, "Language Tag = ");
	    strncat(lang,  p, len);
	    sprintf(get_line(0, 0), "XID = %u", ntohs(slp->xid));

	    /* set msglength to remaining length of SLP message */
	    p += len;
	    msglength -= len;
	}

	return (1);
}

static int v2_finish(struct slpv2_hdr *slp, int flags) {
	unsigned int firstop;

	if (!(flags & F_DTAIL))
	    return (1);

	/* check for options */
	get_int24(&(slp->o1));
	firstop = netval;

	if (firstop) {
	    unsigned short op_id;
	    unsigned short nextop;
	    char *op_class;

	    for (;;) {
		unsigned short real_oplen;

		if (msglength < 4) {
		    sprintf(get_line(0, 0),
			    "Option expected but not present");
		    return (0);
		}

		nbtohs();
		op_id = netval;
		p += sizeof (unsigned short);
		msglength -= sizeof (unsigned short);
		nbtohs();
		nextop = netval;
		p += sizeof (unsigned short);
		msglength -= sizeof (unsigned short);

		real_oplen = nextop ? nextop : msglength;

		/* known options */
		switch (op_id) {
		case 1:
		    sprintf(get_line(0, 0),
			    "Option: Required Attribute Missing");
		    DOFIELD("Template IDVer", FIELD_DEFAULT);
		    DOFIELD("Required Attrs", FIELD_DEFAULT);
		    break;
		default:
		    sprintf(get_line(0, 0), "Option: Unknown");
		    p += (real_oplen - 4);
		    msglength -= (real_oplen - 4);
		    break;
		}

		if (op_id < 0x3fff)
		    op_class = "Standardized, optional";
		else if (op_id < 0x7fff)
		    op_class = "Standardized, mandatory";
		else if (op_id < 0x8fff)
		    op_class = "Not standardized, private";
		else if (op_id < 0xffff)
		    op_class = "Reserved";
		sprintf(get_line(0, 0), "Option ID = 0x%04x, %s",
			op_id, op_class);
		if (nextop &&
		    ((nextop - 4) > msglength) &&
		    !tcp_continuation) {
		    sprintf(get_line(0, 0),
			    "[Framing error: remaining pkt length = %u]",
			    msglength);
		    return (0);
		}

		sprintf(get_line(0, 0), "Option Length = %u", real_oplen);

		if (!nextop)
		    break;
	    }
	}

	return (1);
}

#ifdef VERIFYSLP
static int skip_v2authblock() {
	unsigned short length, slen;

	/* auth header */
	if (msglength < 10)
	    return (-1);

	/* block descriptor: 2 bytes */
	p += sizeof (unsigned short);
	/* length */
	nbtohs();
	length = netval;
	p += sizeof (unsigned short);
	/* timestamp */
	p += 4;
	/* SPI String length */
	nbtohs();
	slen = netval;
	p += sizeof (unsigned short);

	msglength -= 10;
	if (slen > msglength || length > (msglength + 10))
	    return (-1);

	p += slen;
	msglength -= slen;

	/* structured auth block */
	p += (length - 10 - slen);
	msglength -= (length - 10 - slen);
	return (0);
}
#endif

static char *display_bsd(unsigned short bsd) {
	switch (bsd) {
	case 1: return ("MD5 with RSA");
	case 2: return ("DSA with SHA-1");
	case 3: return ("Keyed HMAC with MD5");
	default: return ("Unknown BSD");
	}
}

static char *slpv2_func(int t, boolean_t s) {
	static char buf[128];

	switch (t) {
	case V2_SRVRQST:	return s? "SrvRqst"  : "Service Request";
	case V2_SRVRPLY:	return s? "SrvRply"  : "Service Reply";
	case V2_SRVREG:		return s? "SrvReg"   : "Service Registration";
	case V2_SRVDEREG:
	    return (s ? "SrvDereg" : "Service Deregistration");
	case V2_SRVACK:		return s? "SrvAck"   : "Service Acknowledge";
	case V2_ATTRRQST:	return s? "AttrRqst" : "Attribute Request";
	case V2_ATTRRPLY:	return s? "AttrRply" : "Attribute Reply";
	case V2_DAADVERT:	return s? "DAAdvert" : "DA advertisement";
	case V2_SRVTYPERQST:
	    return (s ? "SrvTypeRqst" : "Service Type Request");
	case V2_SRVTYPERPLY:
	    return (s ? "SrvTypeRply" : "Service Type Reply");
	case V2_SAADVERT:	return s? "SAAdvert" : "SA advertisement";
	}
	sprintf(buf, "(func %d)", t);
	return (s ? buf : "unknown function");
}

static char *slpv2_error(unsigned short code) {
	static char buf[128];

	switch (code) {
	case OK:			return "ok";
	case LANG_NOT_SUPPORTED:	return "language not supported";
	case PROTOCOL_PARSE_ERR:	return "protocol parse error";
	case INVALID_REGISTRATION:	return "invalid registration";
	case SCOPE_NOT_SUPPORTED:	return "scope not supported";
	case AUTHENTICATION_UNKNOWN:	return "authentication unknown";
	case V2_AUTHENTICATION_ABSENT:	return "authentication absent";
	case V2_AUTHENTICATION_FAILED:	return "authentication failed";
	case V2_VER_NOT_SUPPORTED:	return "version not supported";
	case V2_INTERNAL_ERROR:		return "internal error";
	case V2_DA_BUSY_NOW:		return "DA busy";
	case V2_OPTION_NOT_UNDERSTOOD:	return "option not understood";
	case V2_INVALID_UPDATE:		return "invalid update";
	case V2_RQST_NOT_SUPPORTED:	return "request not supported";
	case INVALID_LIFETIME:		return "invalid lifetime";
	}
	sprintf(buf, "error %d", code);
	return (buf);
}

static char *convert_ts(unsigned int timestamp) {
	/* timestamp is in UNIX time */
	static char buff[128];

	strcpy(buff, ctime((time_t *)&timestamp));
	buff[strlen(buff) - 1] = '\0';
	return (buff);
}

static int slpv2_authblock(int cnt) {
	unsigned short bsd, length, slen;
	char *pp, *scopes;
	unsigned int timestamp;

	if (msglength < 10) {
	    sprintf(get_line(0, 0),
		"  [no room for auth block header: remaining msg length = %u]",
		    msglength);
	    return (-1);
	}

	/* bsd */
	nbtohs();
	bsd = netval;
	p += sizeof (unsigned short);

	/* length */
	nbtohs();
	length = netval;
	p += sizeof (unsigned short);

	/* timestamp */
	nbtohl();
	timestamp = netval;
	p += 4;

	/* SPI String length */
	nbtohs();
	slen = netval;
	p += sizeof (unsigned short);

	msglength -= 10;
	if (slen > msglength) {
	    sprintf(get_line(0, 0),
		"  [no room for auth block scopes: remaining msg length = %u]",
		    msglength);
	    return (-1);
	}

	if (length > (msglength + 10)) {
	    if (!tcp_continuation)
		/* framing error: message is not long enough to contain data */
		sprintf(get_line(0, 0),
			"  [Framing error: remaining pkt length = %u]",
			msglength);
	    return (-1);
	}

	scopes = p;
	p += slen;
	msglength -= slen;

	sprintf(get_line(0, 0),
	    "Auth block %d: timestamp = %s", cnt,
	    (timestamp) ? convert_ts(timestamp) : "0");

	pp = get_line(0, 0);
	strcpy(pp, "              SPI = ");
	strncat(pp, scopes, slen);

	sprintf(get_line(0, 0),
	    "              block desc = 0x%04x: %s", bsd, display_bsd(bsd));

	sprintf(get_line(0, 0), "              length = %u", length);

	p += (length - 10 - slen);
	msglength -= (length - 10 - slen);
	return (0);
}

static int v2_srv_rqst(int flags) {
	if (flags & F_SUM) {
		SKIPFIELD(FIELD_DEFAULT);	/* PR list */
		GETFIELD;			/* service type */
		SKIPFIELD(FIELD_DEFAULT);	/* scopes */
		strcat(msgend, " [");
		GETFIELD;			/* predicate */
		strcat(msgend, "]");
		SKIPFIELD(FIELD_DEFAULT);	/* SPI */
	} else if (flags & F_DTAIL) {
		DOFIELD("Previous responders", FIELD_DEFAULT);
		DOFIELD("Service type",  FIELD_DEFAULT);
		DOFIELD("Scopes",  FIELD_DEFAULT);
		DOFIELD("Predicate string",  FIELD_DEFAULT);
		DOFIELD("Requested SPI", FIELD_DEFAULT);
	}

	return (1);
}

static int v2_srv_rply(int flags) {
	unsigned short itemcnt, errcode;
	int n;

	if (flags & F_SUM) {
	    int i, auth_cnt;

	    GETSHORT(errcode);
	    if (errcode != OK) {
		strcat(msgbuf, slpv2_error(errcode));
		msglength = 0;	/* skip rest of message */
		return (0);
	    } else {
		GETSHORT(itemcnt);
		sprintf(msgend, "%d URL entries", itemcnt);
#ifdef VERIFYSLP
		for (n = 0; n < itemcnt; n++) {
		    SKIPBYTE;			/* reserved */
		    SKIPSHORT;			/* lifetime */
		    SKIPFIELD(FIELD_DEFAULT);	/* URL */
		    GETBYTE(auth_cnt);
		    for (i = 0; i < auth_cnt; auth_cnt++)
			if (skip_v2authblock() < 0)
			    return (0);
		}
#endif
	    }
	} else if (flags & F_DTAIL) {
	    V2_DOERRCODE;
	    GETSHORT(itemcnt);
	    sprintf(get_line(0, 0), "URL entry count = %d", itemcnt);
	    for (n = 0; n < itemcnt; n++) {
		V2_DOURL(n);
	    }
	}

	return (1);
}

static int v2_srv_reg(int flags) {
	int i, auth_cnt;

	if (flags & F_SUM) {
	    SKIPBYTE;			/* reserved */
	    SKIPSHORT;			/* lifetime */
	    GETFIELD;			/* URL */
#ifdef VERIFYSLP
	    GETBYTE(auth_cnt);
	    for (i = 0; i < auth_cnt; i++)
		if (skip_v2authblock() < 0)
		    return (0);
	    SKIPFIELD(FIELD_DEFAULT);	/* type */
	    SKIPFIELD(FIELD_DEFAULT);	/* scopes */
	    SKIPFIELD(FIELD_DEFAULT);	/* attrs */
	    GETBYTE(auth_cnt);
	    for (i = 0; i < auth_cnt; i++)
		if (skip_v2authblock() < 0)
		    return (0);
#endif
	} if (flags & F_DTAIL) {
	    V2_DOURL(-1);
	    DOFIELD("Service type", FIELD_DEFAULT);
	    DOFIELD("Scopes", FIELD_DEFAULT);
	    DOFIELD("Attribute list", FIELD_DEFAULT);
	    /* auth */
	    GETBYTE(auth_cnt);
	    for (i = 0; i < auth_cnt; i++)
		V2_DOAUTH(i);
	}

	return (1);
}

static int v2_srv_dereg(int flags) {
	if (flags & F_SUM) {
	    int i, auth_cnt;

	    SKIPFIELD(FIELD_DEFAULT);	/* scopes */
	    SKIPBYTE;			/* reserved */
	    SKIPSHORT;			/* lifetime */
	    GETFIELD;			/* URL */

#ifdef VERIFYSLP
	    GETBYTE(auth_cnt);
	    for (i = 0; i < auth_cnt; i++)
		if (skip_v2authblock() < 0)
		    return (0);
	    SKIPFIELD(FIELD_DEFAULT);	/* attrs */
#endif
	} else if (flags & F_DTAIL) {
	    DOFIELD("Scopes", FIELD_DEFAULT);
	    V2_DOURL(-1);
	    DOFIELD("Tag list",  FIELD_DEFAULT);
	}

	return (1);
}

static int v2_srv_ack(int flags) {
	unsigned short errcode;
	if (flags & F_SUM) {
	    GETSHORT(errcode);
	    strcat(msgbuf, slpv2_error(errcode));
	} else if (flags & F_DTAIL) {
	    V2_DOERRCODE;
	}

	return (1);
}

static int v2_attr_rqst(int flags) {
	if (flags  & F_SUM) {
	    SKIPFIELD(FIELD_DEFAULT);	/* PR list */
	    GETFIELD;			/* URL */
	    SKIPFIELD(FIELD_DEFAULT);	/* scopes */
	    strcat(msgend, " [");
	    GETFIELD;			/* attrs */
	    strcat(msgend, "]");

#ifdef VERIFYSLP
	    SKIPFIELD(FIELD_DEFAULT);	/* SPI */
#endif
	} else if (flags & F_DTAIL) {
	    DOFIELD("Previous responders", FIELD_DEFAULT);
	    DOFIELD("URL",  FIELD_DEFAULT);
	    DOFIELD("Scopes",  FIELD_DEFAULT);
	    DOFIELD("Tag list",  FIELD_DEFAULT);
	    DOFIELD("Requested SPI", FIELD_DEFAULT);
	}

	return (1);
}

static int v2_attr_rply(int flags) {
	int auth_cnt, i;
	unsigned short errcode;

	if (flags & F_SUM) {
	    GETSHORT(errcode);
	    if (errcode != OK) {
		strcat(msgbuf, slpv2_error(errcode));
		msglength = 0;	/* skip rest of message */
		return (0);
	    } else {
		GETFIELD;			/* attr list */

#ifdef VERIFYSLP
		GETBYTE(auth_cnt);
		for (i = 0; i < auth_cnt; i++)
		    if (skip_v2authblock() < 0)
			return (0);
#endif
	    }
	} else if (flags & F_DTAIL) {
	    V2_DOERRCODE;
	    DOFIELD("Attribute list", FIELD_DEFAULT);
	    /* auth */
	    GETBYTE(auth_cnt);
	    for (i = 0; i < auth_cnt; i++)
		V2_DOAUTH(i);
	}

	return (1);
}

static int v2_daadvert(int flags) {
	int auth_cnt, i;
	unsigned short errcode;
	unsigned int timestamp;

	if (flags & F_SUM) {
	    SKIPSHORT;			/* error code */
	    SKIPSHORT; SKIPSHORT;	/* timestamp */
	    GETFIELD;			/* URL */

#ifdef VERIFYSLP
	    SKIPFIELD(FIELD_DEFAULT);	/* scopes */
	    SKIPFIELD(FIELD_DEFAULT);	/* attrs */
	    SKIPFIELD(FIELD_DEFAULT);	/* SPIs */

	    GETBYTE(auth_cnt);
	    for (i = 0; i < auth_cnt; i++)
		if (skip_v2authblock() < 0)
		    return (0);
#endif
	} else if (flags & F_DTAIL) {
	    V2_DOERRCODE;
	    V2_DOTIMESTAMP;
	    DOFIELD("URL", FIELD_DEFAULT);
	    DOFIELD("Scope list", FIELD_DEFAULT);
	    DOFIELD("Attribute list", FIELD_DEFAULT);
	    DOFIELD("Configured SPIs", FIELD_DEFAULT);
	    /* auth */
	    GETBYTE(auth_cnt);
	    for (i = 0; i < auth_cnt; i++)
		V2_DOAUTH(i);
	}

	return (1);
}

static int v2_srv_type_rqst(int flags) {
	if (flags & F_SUM) {
	    SKIPFIELD(FIELD_DEFAULT);	/* prev responders */
	    SKIPFIELD(FIELD_TYPENA);	/* naming authority */
	    GETFIELD;			/* scope */
	} else if (flags & F_DTAIL) {
	    DOFIELD("Previous responders", FIELD_DEFAULT);
	    DOFIELD("Naming authority", FIELD_TYPENA);
	    DOFIELD("Scopes",  FIELD_DEFAULT);
	}

	return (1);
}

static int v2_srv_type_rply(int flags) {
	unsigned short errcode;

	if (flags & F_SUM) {
	    GETSHORT(errcode);
	    if (errcode != OK)
		strcat(msgbuf, slpv2_error(errcode));
	    else
		GETFIELD;
	} else if (flags & F_DTAIL) {
		V2_DOERRCODE;
		DOFIELD("Service types", FIELD_DEFAULT);
	}

	return (1);
}

static int v2_saadvert(int flags) {
	int auth_cnt, i;

	if (flags & F_SUM) {
	    GETFIELD;			/* URL */

#ifdef VERIFYSLP
	    SKIPFIELD(FIELD_DEFAULT);	/* scopes */
	    SKIPFIELD(FIELD_DEFAULT);	/* attrs */

	    GETBYTE(auth_cnt);
	    for (i = 0; i < auth_cnt; i++)
		if (skip_v2authblock() < 0)
		    return (0);
#endif
	} else if (flags & F_DTAIL) {
	    DOFIELD("URL", FIELD_DEFAULT);
	    DOFIELD("Scopes",  FIELD_DEFAULT);
	    DOFIELD("Attribute list", FIELD_DEFAULT);
	    /* auth */
	    GETBYTE(auth_cnt);
	    for (i = 0; i < auth_cnt; i++)
		V2_DOAUTH(i);
	}

	return (1);
}

/*
 * V1 Interpreter
 */

static int interpret_slp_v1(int flags, struct slpv1_hdr *slp, int fraglen) {
	char msgbuf_real[256];
	extern int src_port, dst_port, curr_proto;
	boolean_t overflow	= B_FALSE;

	msgbuf = msgbuf_real;

	if (msglength >= sizeof (*slp)) {
	    if ((slp->flags & V1_URL_AUTH) == V1_URL_AUTH)
		url_auth = B_TRUE;
	    if ((slp->flags & V1_ATTR_AUTH) == V1_ATTR_AUTH)
		attr_auth = B_TRUE;
	    if ((slp->flags & V1_FRESH_REG) == V1_FRESH_REG)
		fresh = B_TRUE;
	    if ((slp->flags & V1_OVERFLOW) == V1_OVERFLOW)
		overflow = B_TRUE;
	}

	/*
	 * Somewhat of a hack to decode traffic from a server that does
	 * not send udp replies from its SLP src port.
	 */
	if (curr_proto == IPPROTO_UDP &&
	    dst_port == 427 &&
	    src_port != 427)
		add_transient(src_port, (int (*)())interpret_slp);

	/* parse the header */
	if (v1_header(flags, slp, fraglen)) {

	    if (slp->function <= V1_MAX_FUNCTION && slp->function > 0) {

		/* Parse the message body */
		(v1_functions[slp->function])(flags);

	    }

	}

	/* summary error check */
	if (flags & F_SUM) {
	    if (retlength < 0) {
		if (curr_proto == IPPROTO_TCP)
		    sprintf(get_sum_line(),
			    "%s [partial TCP message]",
			    msgbuf);
		else if (overflow)
		    sprintf(get_sum_line(), "%s [OVERFLOW]", msgbuf);
		else
		    sprintf(get_sum_line(), "%s [CORRUPTED MESSAGE]", msgbuf);
	    }
#ifdef VERIFYSLP
	    else if (msglength > 0)
		sprintf(get_sum_line(), "%s +%d", msgbuf, msglength);
#endif
	    else
		sprintf(get_sum_line(), "%s", msgbuf);
	} else if (flags & F_DTAIL) {
	    /* detail error check */
	    if (msglength > 0) {
		sprintf(get_line(0, 0),
			"[%d extra bytes at end of SLP message]", msglength);
	    }

	    show_trailer();

	}

	v1_charset = 0;

	return (0);
}

static int v1_header(int flags,
			struct slpv1_hdr *slp,
			int fraglen) {
	extern int src_port, dst_port, curr_proto;
	char *prototag = (curr_proto == IPPROTO_TCP? "/tcp" : "");

	if (flags & F_SUM) {
	    char portflag = ' ';

	    if (msglength < sizeof (*slp)) {
		sprintf(msgbuf, "SLP V1 [incomplete header]");
		return (0);
	    }

	    if (slp->vers != 1) {
		if (curr_proto == IPPROTO_TCP)
		    sprintf(msgbuf, "SLP [TCP Continuation]");
		else
		    sprintf(msgbuf, "SLP [unknown version %d]", slp->vers);
		return (0);
	    }

	    if (src_port != 427 && dst_port != 427)
		portflag = '-';

	    sprintf(msgbuf, "SLP V1%c%s [%d%s] ", portflag,
		    slpv1_func(slp->function, B_TRUE),
		    ntohs(slp->xid), prototag);
	    msgend = msgbuf + strlen(msgbuf);
	    msglength -= sizeof (*slp);
	    p += sizeof (*slp);
	} else if (flags & F_DTAIL) {
	    show_header("SLP:  ", "Service Location Protocol (v1)", fraglen);
	    show_space();

	    if (msglength < sizeof (*slp)) {
		sprintf(get_line(0, 0), "==> Incomplete SLP header");
		return (0);
	    }

	    sprintf(get_line(0, 0), "Version = %d", slp->vers);
	    if (slp->vers != 1) {
		if (curr_proto == IPPROTO_TCP)
		    sprintf(get_line(0, 0), "==> TCP continuation");
		else
		    sprintf(get_line(0, 0), "==> Unexpected version number");
		return (0);
	    }
	    sprintf(get_line(0, 0), "Function = %d, %s",
		slp->function, slpv1_func(slp->function, B_FALSE));
	    sprintf(get_line(0, 0), "Message length = %u", ntohs(slp->length));

	    /* flags */
	    sprintf(get_line(0, 0), "Flags = 0x%02x", slp->flags);
	    sprintf(get_line(0, 0), "      %s",
		    getflag(slp->flags, V1_OVERFLOW,
			    "overflow", "no overflow"));
	    sprintf(get_line(0, 0), "      %s",
		    getflag(slp->flags, V1_MONOLINGUAL,
			    "monolingual", "not monolingual"));
	    sprintf(get_line(0, 0), "      %s",
		    getflag(slp->flags, V1_URL_AUTH,
			    "url authentication", "no url authentication"));
	    sprintf(get_line(0, 0), "      %s",
		    getflag(slp->flags, V1_ATTR_AUTH,
		"attribute authentication", "no attribute authentication"));
	    sprintf(get_line(0, 0), "      %s",
		    getflag(slp->flags, V1_FRESH_REG,
			    "fresh registration", "no fresh registration"));
	    /* check reserved flags that must be zero */
	    if ((slp->flags & 7) != 0) {
		sprintf(get_line(0, 0),
			"      .... .xxx = %d (reserved flags nonzero)",
			slp->flags & 7);
	    }
	    /* end of flags */

	    sprintf(get_line(0, 0), "Dialect = %u", slp->dialect);
	    sprintf(get_line(0, 0), "Language = 0x%02x%02x, %c%c",
		    slp->language[0], slp->language[1],
		    slp->language[0], slp->language[1]);
	    v1_charset = ntohs(slp->charset);
	    sprintf(get_line(0, 0), "Character encoding = %u, %s",
		    v1_charset,
		    slpv1_charset(v1_charset));
	    sprintf(get_line(0, 0), "XID = %u", ntohs(slp->xid));

	    /* set msglength to remaining length of SLP message */
	    msglength -= sizeof (*slp);
	    p += sizeof (*slp);
	}

	return (1);
}

static char *slpv1_func(int t, boolean_t s) {
	static char buf[128];
	switch (t) {
	case V1_SRVREQ:	return s? "SrvRqst"  : "Service Request";
	case V1_SRVRPLY:	return s? "SrvRply"  : "Service Reply";
	case V1_SRVREG:	return s? "SrvReg"   : "Service Registration";
	case V1_SRVDEREG:	return s?
					"SrvDereg" : "Service Deregistration";
	case V1_SRVACK:	return s? "SrvAck"   : "Service Acknowledge";
	case V1_ATTRRQST:	return s? "AttrRqst" : "Attribute Request";
	case V1_ATTRRPLY:	return s? "AttrRply" : "Attribute Reply";
	case V1_DAADVERT:	return s? "DAAdvert" : "DA advertisement";
	case V1_SRVTYPERQST:return s? "SrvTypeRqst" : "Service Type Request";
	case V1_SRVTYPERPLY:return s? "SrvTypeRply" : "Service Type Reply";
	}
	sprintf(buf, "(func %d)", t);
	return (s ? buf : "unknown function");
}

static char *slpv1_error(unsigned short code) {
	static char buf[128];

	switch (code) {
	    case OK:			return "ok";
	    case LANG_NOT_SUPPORTED:	return "language not supported";
	    case PROTOCOL_PARSE_ERR:	return "protocol parse error";
	    case INVALID_REGISTRATION:	return "invalid registration";
	    case SCOPE_NOT_SUPPORTED:	return "scope not supported";
	    case CHARSET_NOT_UNDERSTOOD:return "character set not understood";
	    case AUTHENTICATION_INVALID:return "invalid authentication";
	    case NOT_SUPPORTED_YET:	return "not yet supported";
	    case REQUEST_TIMED_OUT:	return "request timed out";
	    case COULD_NOT_INIT_NET_RESOURCES:
				return ("could not initialize net resources");
	    case COULD_NOT_ALLOCATE_MEMORY:
					return ("could not allocate memory");
	    case PARAMETER_BAD:		return "bad parameter";
	    case INTERNAL_NET_ERROR:	return "internal network error";
	    case INTERNAL_SYSTEM_ERROR:	return "internal system error";
	}
	sprintf(buf, "error %d", code);
	return (buf);
}

/*
 *  Character set info from
 *    www.isi.edu/in-notes/iana/assignments/character-sets
 *
 *	Assigned MIB enum Numbers
 *	-------------------------
 *	0               Reserved
 *	1               Reserved
 *	3-106           Set By Standards Organizations
 *	1000-1010       Unicode / 10646
 *	2000-2087       Vendor
 *	2250-2258       Vendor
 *
 *	MIBenum: 3
 *	Alias: US-ASCII (preferred MIME name)
 *	Source: ECMA registry [RFC1345]
 *
 *	MIBenum: 106
 *	Name: UTF-8
 *	Source: RFC 2044
 */

static char *slpv1_charset(unsigned short code) {
	if (code <= 1)
	    return ("Reserved");
	if (code == 3)
	    return ("US-ASCII");
	if (code == 4)
	    return ("latin1");
	if (code == 106)
	    return ("UTF-8");
	if (code >= 3 && code <= 106)
	    return ("set by standards organization");
	if (code >= 1000 && code <= 1010)
	    return ("Unicode variant");
	if ((code >= 2000 && code <= 2087) ||
	    (code >= 2250 && code <= 2258))
	    return ("Vendor assigned");

	return ("unknown");
}

#ifdef VERIFYSLP
static int skip_v1authblock() {
	unsigned short length;

	/* auth header: 12 bytes total */
	if (msglength < 12)
	    return (-1);

	/* timestamp: 8 bytes */
	p += 8;			/* timestamp: 8 bytes */
	p += sizeof (short);		/* block descriptor: 2 bytes */
	nbtohs();
	length = netval;
	p += sizeof (short);
	msglength -= 12;

	if (length > msglength) {
	    /* framing error: message is not long enough to contain data */
	    return (-1);
	}

	p += length;
	msglength -= length;
	return (0);
}
#endif

static int slpv1_authblock() {
	unsigned short bsd, length;
	char msgbuf[128];
	int n;

	if (msglength < 12) {
	    sprintf(get_line(0, 0),
		    "  [no room for auth block: remaining msg length = %u]",
		    msglength);
	    return (-1);
	}

	/* timestamp: 8 bytes */
	*msgbuf = '\0';
	for (n = 0; n < 8; n++, p += 1) {
	    char tmp[16];
	    sprintf(tmp, "%02x", (unsigned char)(*p));
	    strcat(msgbuf, tmp);
	}

	nbtohs();
	bsd = netval;
	p += sizeof (short);
	nbtohs();
	length = netval;
	p += sizeof (short);
	msglength -= 12;

	sprintf(get_line(0, 0),
		"  Auth block: timestamp = %s",
		msgbuf);
	sprintf(get_line(0, 0),
		"              block desc = 0x%04x, length = %u",
		bsd, length);
	if (length > msglength) {
	    /* framing error: message is not long enough to contain data */
	    sprintf(get_line(0, 0),
		"  [Framing error: remaining pkt length = %u]",  msglength);
	    return (-1);
	}

	p += length;
	msglength -= length;
	return (0);
}

static int slpv1_url(boolean_t auth_present) {
	time_t exp;
	int lifetime, length;

	get_short();
	if ((lifetime = netval) < 0)
	    return (-1);
	get_short();
	if ((length = netval) < 0)
	    return (-1);

	exp = time(0) + lifetime;
	sprintf(get_line(0, 0), "URL: length = %u, lifetime = %d (%24.24s)",
		length, lifetime, ctime(&exp));
	if (length > msglength) {
	    /* framing error: message is not long enough to contain data */
	    sprintf(get_line(0, 0),
		"  [Framing error: remaining pkt length = %u]",  msglength);
	    return (-1);
	}

	if (length > 0) {
	    char *buf = malloc(length + 1);
	    if (buf != NULL) {
		if (!make_utf8(buf, length, p, length)) {
			strcpy(buf, "[Invalid Character Encoding]");
		}
		sprintf(get_line(0, 0), "  \"%s\"", buf);
		free(buf);
	    }
	}
	msglength -= length;
	p += length;

	if (auth_present)
	    return (slpv1_authblock());

	return (0);
}

static int v1_srv_rqst(int flags) {
	if (flags & F_SUM) {
	    SKIPFIELD(FIELD_PREVRESP);	/* prev responders */
	    GETFIELD;			/* predicate */
	} else if (flags & F_DTAIL) {
	    DOFIELD("Previous responders", FIELD_PREVRESP);
	    DOFIELD("predicate string", FIELD_DEFAULT);
	}

	return (1);
}

static int v1_srv_rply(int flags) {
	unsigned short errcode, itemcnt;
	int n;

	if (flags & F_SUM) {
	    GETSHORT(errcode);
	    if (errcode != OK) {
		strcat(msgbuf, slpv1_error(errcode));
	    } else {
		GETSHORT(itemcnt);
		sprintf(msgend, "%d URL entries", itemcnt);
#ifdef VERIFYSLP
		for (n = 0; n < itemcnt; n++) {
		    SKIPSHORT;		/* lifetime */
		    SKIPFIELD(FIELD_DEFAULT);	/* URL */
		    SKIPAUTH(url_auth);		/* URL auth */
		}
#endif
	    }
	} else if (flags & F_DTAIL) {
	    DOERRCODE;
	    GETSHORT(itemcnt);
	    sprintf(get_line(0, 0), "URL entry count = %d", itemcnt);
	    for (n = 0; n < itemcnt; n++) {
		DOURL;
	    }
	}

	return (1);
}

static int v1_srv_reg(int flags) {
	if (flags & F_SUM) {
	    SKIPSHORT;			/* lifetime */
	    GETFIELD;			/* URL */
#ifdef VERIFYSLP
	    SKIPAUTH(url_auth);		/* URL auth */
	    SKIPFIELD(FIELD_DEFAULT);	/* attribute list */
	    SKIPAUTH(attr_auth);		/* attr auth */
#endif
	} else if (flags & F_DTAIL) {
	    DOURL;
	    DOFIELD("Attribute list", FIELD_DEFAULT);
	    DOAUTH(attr_auth);
	}

	return (1);
}

static int v1_srv_ack(int flags) {
	unsigned short errcode;

	if (flags & F_SUM) {
	    GETSHORT(errcode);
	    strcat(msgbuf, slpv1_error(errcode));
	    if (errcode == OK && fresh) {
		strcat(msgbuf, " [Fresh]");
	    }
	} else if (flags & F_DTAIL) {
	    DOERRCODE;
	}

	return (1);
}

static int v1_srv_dereg(int flags) {
	if (flags & F_SUM) {
	    GETFIELD;			/* URL */
#ifdef VERIFYSLP
	    SKIPAUTH(url_auth);
	    SKIPFIELD(FIELD_DEFAULT);	/* tag spec */
#endif
	} else if (flags & F_DTAIL) {
	    DOFIELD("URL", FIELD_DEFAULT);
	    DOAUTH(url_auth);
	    DOFIELD("Tag spec", FIELD_DEFAULT);
	}

	return (1);
}

static int v1_attr_rqst(int flags) {
	if (flags & F_SUM) {
	    SKIPFIELD(FIELD_PREVRESP);	/* prev responders */
	    GETFIELD;			/* URL */
#ifdef VERIFYSLP
	    SKIPFIELD(FIELD_DEFAULT);	/* scope */
	    SKIPFIELD(FIELD_DEFAULT);	/* select list */
#endif
	} else if (flags & F_DTAIL) {
	    DOFIELD("Previous responders", FIELD_PREVRESP);
	    DOFIELD("URL", FIELD_DEFAULT);
	    DOFIELD("Scope", FIELD_DEFAULT);
	    DOFIELD("Select list", FIELD_DEFAULT);
	}

	return (1);
}

static int v1_attr_rply(int flags) {
	unsigned short errcode;

	if (flags & F_SUM) {
	    GETSHORT(errcode);
	    if (errcode != OK) {
		strcat(msgbuf, slpv1_error(errcode));
	    } else {
		GETFIELD;			/* attr list */
#ifdef VERIFYSLP
		SKIPAUTH(attr_auth);
#endif
	    }
	} else if (flags & F_DTAIL) {
	    DOERRCODE;
	    DOFIELD("Attribute list", FIELD_DEFAULT);
	    DOAUTH(attr_auth);
	}

	return (1);
}

static int v1_daadvert(int flags) {
	unsigned short errcode;

	if (flags & F_SUM) {
	    GETSHORT(errcode);
	    if (errcode != OK) {
		strcat(msgbuf, slpv1_error(errcode));
	    } else {
		    GETFIELD;			/* URL */
#ifdef VERIFYSLP
		    SKIPFIELD(FIELD_DEFAULT);	/* scope list */
#endif
	    }
	} else if (flags & F_DTAIL) {
	    DOERRCODE;
	    DOFIELD("URL", FIELD_DEFAULT);
	    DOFIELD("Scope list", FIELD_DEFAULT);
	}

	return (1);
}

static int v1_srv_type_rqst(int flags) {
	if (flags & F_SUM) {
	    SKIPFIELD(FIELD_PREVRESP);	/* prev responders */
	    SKIPFIELD(FIELD_TYPENA);	/* naming authority */
	    GETFIELD;			/* scope */
	} else if (flags & F_DTAIL) {
	    DOFIELD("Previous responders", FIELD_PREVRESP);
	    DOFIELD("Naming authority", FIELD_TYPENA);
	    DOFIELD("Scope string", FIELD_DEFAULT);
	}

	return (1);
}

static int v1_srv_type_rply(int flags) {
	unsigned short errcode, itemcnt;
	int n;

	if (flags & F_SUM) {
	    GETSHORT(errcode);
	    if (errcode != OK) {
		strcat(msgbuf, slpv1_error(errcode));
	    } else {
		GETSHORT(itemcnt);
		sprintf(msgend, "%d type entries", itemcnt);
#ifdef VERIFYSLP
		for (n = 0; n < itemcnt; n++) {
		    SKIPFIELD(FIELD_DEFAULT);  /* Service type item */
		}
#endif
	    }
	} else if (flags & F_DTAIL) {
	    DOERRCODE;
	    GETSHORT(itemcnt);
	    sprintf(get_line(0, 0), "Service type count = %d", itemcnt);
	    for (n = 0; n < itemcnt; n++) {
		DOFIELD("  Service type item", FIELD_DEFAULT);
	    }
	}

	return (1);
}
