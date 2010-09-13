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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <sys/time.h>
#include <sys/bufmod.h>
#include <setjmp.h>
#include <varargs.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <inttypes.h>

#include "snoop.h"

char *dlc_header;
char *src_name, *dst_name;
int pi_frame;
int pi_time_hour;
int pi_time_min;
int pi_time_sec;
int pi_time_usec;

#ifndef MIN
#define	MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

static void hexdump(char *, int);

/*
 * This routine invokes the packet interpreters
 * on a packet.  There's some messing around
 * setting up a few packet-externals before
 * starting with the ethernet interpreter.
 * Yes, we assume here that all packets will
 * be ethernet packets.
 */
void
process_pkt(struct sb_hdr *hdrp, char *pktp, int num, int flags)
{
	int drops, pktlen;
	struct timeval *tvp;
	struct tm *tm;
	extern int x_offset;
	extern int x_length;
	int offset, length;
	static struct timeval ptv;

	if (hdrp == NULL)
		return;

	tvp = &hdrp->sbh_timestamp;
	if (ptv.tv_sec == 0)
		ptv = *tvp;
	drops  = hdrp->sbh_drops;
	pktlen = hdrp->sbh_msglen;
	if (pktlen <= 0)
		return;

	/* set up externals */
	dlc_header = pktp;
	pi_frame = num;
	tm = localtime(&tvp->tv_sec);
	pi_time_hour = tm->tm_hour;
	pi_time_min  = tm->tm_min;
	pi_time_sec  = tm->tm_sec;
	pi_time_usec = tvp->tv_usec;

	src_name = "?";
	dst_name = "*";

	click(hdrp->sbh_origlen);

	(*interface->interpreter)(flags, dlc_header, hdrp->sbh_msglen,
	    hdrp->sbh_origlen);

	show_pktinfo(flags, num, src_name, dst_name, &ptv, tvp, drops,
	    hdrp->sbh_origlen);

	if (x_offset >= 0) {
		offset = MIN(x_offset, hdrp->sbh_msglen);
		offset -= (offset % 2);  /* round down */
		length = MIN(hdrp->sbh_msglen - offset, x_length);

		hexdump(dlc_header + offset, length);
	}

	ptv = *tvp;
}


/*
 * *************************************************************
 * The following routines constitute a library
 * used by the packet interpreters to facilitate
 * the display of packet data.  This library
 * of routines helps provide a consistent
 * "look and feel".
 */


/*
 * Display the value of a flag bit in
 * a byte together with some text that
 * corresponds to its value - whether
 * true or false.
 */
char *
getflag(int val, int mask, char *s_true, char *s_false)
{
	static char buff[80];
	char *p;
	int set;

	(void) strcpy(buff, ".... .... = ");
	if (s_false == NULL)
		s_false = s_true;

	for (p = &buff[8]; p >= buff; p--) {
		if (*p == ' ')
			p--;
		if (mask & 0x1) {
			set = val & mask & 0x1;
			*p = set ? '1':'0';
			(void) strcat(buff, set ? s_true: s_false);
			break;
		}
		mask >>= 1;
		val  >>= 1;
	}
	return (buff);
}

XDR xdrm;
jmp_buf xdr_err;
int xdr_totlen;
char *prot_prefix;
char *prot_nest_prefix = "";
char *prot_title;

void
show_header(char *pref, char *str, int len)
{
	prot_prefix = pref;
	prot_title = str;
	(void) sprintf(get_detail_line(0, len), "%s%s----- %s -----",
	    prot_nest_prefix, pref, str);
}

void
xdr_init(char *addr, int len)
{
	xdr_totlen = len;
	xdrmem_create(&xdrm, addr, len, XDR_DECODE);
}

char *
get_line(int begin, int end)
{
	char *line;

	line = get_detail_line(begin, end);
	(void) strcpy(line, prot_nest_prefix);
	(void) strcat(line, prot_prefix);
	return (line + strlen(line));
}

int
get_line_remain(void)
{
	return (MAXLINE - strlen(prot_nest_prefix) - strlen(prot_prefix));
}

void
show_line(char *str)
{
	(void) strcpy(get_line(0, 0), str);
}

char
getxdr_char()
{
	char s;

	if (xdr_char(&xdrm, &s))
		return (s);
	longjmp(xdr_err, 1);
	/* NOTREACHED */
}

char
showxdr_char(char *fmt)
{
	int pos; char val;

	pos = getxdr_pos();
	val = getxdr_char();
	(void) sprintf(get_line(pos, getxdr_pos()), fmt, val);
	return (val);
}

uchar_t
getxdr_u_char()
{
	uchar_t s;

	if (xdr_u_char(&xdrm, &s))
		return (s);
	longjmp(xdr_err, 1);
	/* NOTREACHED */
}

uchar_t
showxdr_u_char(char *fmt)
{
	int pos;
	uchar_t val;

	pos = getxdr_pos();
	val = getxdr_u_char();
	(void) sprintf(get_line(pos, getxdr_pos()), fmt, val);
	return (val);
}

short
getxdr_short()
{
	short s;

	if (xdr_short(&xdrm, &s))
		return (s);
	longjmp(xdr_err, 1);
	/* NOTREACHED */
}

short
showxdr_short(char *fmt)
{
	int pos; short val;

	pos = getxdr_pos();
	val = getxdr_short();
	(void) sprintf(get_line(pos, getxdr_pos()), fmt, val);
	return (val);
}

ushort_t
getxdr_u_short()
{
	ushort_t s;

	if (xdr_u_short(&xdrm, &s))
		return (s);
	longjmp(xdr_err, 1);
	/* NOTREACHED */
}

ushort_t
showxdr_u_short(char *fmt)
{
	int pos;
	ushort_t val;

	pos = getxdr_pos();
	val = getxdr_u_short();
	(void) sprintf(get_line(pos, getxdr_pos()), fmt, val);
	return (val);
}

long
getxdr_long()
{
	long l;

	if (xdr_long(&xdrm, &l))
		return (l);
	longjmp(xdr_err, 1);
	/* NOTREACHED */
}

long
showxdr_long(char *fmt)
{
	int pos; long val;

	pos = getxdr_pos();
	val = getxdr_long();
	(void) sprintf(get_line(pos, getxdr_pos()), fmt, val);
	return (val);
}

ulong_t
getxdr_u_long()
{
	ulong_t l;

	if (xdr_u_long(&xdrm, &l))
		return (l);
	longjmp(xdr_err, 1);
	/* NOTREACHED */
}

ulong_t
showxdr_u_long(char *fmt)
{
	int pos;
	ulong_t val;

	pos = getxdr_pos();
	val = getxdr_u_long();
	(void) sprintf(get_line(pos, getxdr_pos()), fmt, val);
	return (val);
}

longlong_t
getxdr_longlong()
{
	longlong_t l;

	if (xdr_longlong_t(&xdrm, &l))
		return (l);
	longjmp(xdr_err, 1);
	/* NOTREACHED */
}

longlong_t
showxdr_longlong(char *fmt)
{
	int pos; longlong_t val;

	pos = getxdr_pos();
	val = getxdr_longlong();
	(void) sprintf(get_line(pos, getxdr_pos()), fmt, val);
	return (val);
}

u_longlong_t
getxdr_u_longlong()
{
	u_longlong_t l;

	if (xdr_u_longlong_t(&xdrm, &l))
		return (l);
	longjmp(xdr_err, 1);
	/* NOTREACHED */
}

u_longlong_t
showxdr_u_longlong(char *fmt)
{
	int pos; u_longlong_t val;

	pos = getxdr_pos();
	val = getxdr_u_longlong();
	(void) sprintf(get_line(pos, getxdr_pos()), fmt, val);
	return (val);
}

bool_t
getxdr_bool()
{
	bool_t b;

	if (xdr_bool(&xdrm, &b))
		return (b);
	longjmp(xdr_err, 1);
	/* NOTREACHED */
}

bool_t
showxdr_bool(char *fmt)
{
	int pos; bool_t val;

	pos = getxdr_pos();
	val = getxdr_bool();
	(void) sprintf(get_line(pos, getxdr_pos()), fmt,
	    val ? "True" : "False");
	return (val);
}

char *
getxdr_opaque(char *p, int len)
{
	if (xdr_opaque(&xdrm, p, len))
		return (p);
	longjmp(xdr_err, 1);
	/* NOTREACHED */
}

char *
getxdr_string(char *p, /* len+1 bytes or longer */
	int len)
{
	if (xdr_string(&xdrm, &p, len))
		return (p);
	longjmp(xdr_err, 1);
	/* NOTREACHED */
}

char *
showxdr_string(int len, /* XDR length */
	char *fmt)
{
	static int buff_len = 0;
	static char *buff = NULL;
	int pos;

	/*
	 * XDR strings don't necessarily have a trailing null over the
	 * wire.  However, the XDR code will put one in for us.  Make sure
	 * we have allocated room for it.
	 */
	len++;

	if ((len > buff_len) || (buff_len == 0)) {
		if (buff)
			free(buff);
		if ((buff = (char *)malloc(len)) == NULL)
			pr_err("showxdr_string: no mem");
		buff_len = len;
	}
	pos = getxdr_pos();
	getxdr_string(buff, len);
	(void) strcpy(buff+60, "...");
	(void) sprintf(get_line(pos, getxdr_pos()), fmt, buff);
	return (buff);
}

char *
getxdr_bytes(uint_t *lenp)
{
	static char buff[1024];
	char *p = buff;

	if (xdr_bytes(&xdrm, &p, lenp, 1024))
		return (buff);
	longjmp(xdr_err, 1);
	/* NOTREACHED */
}

char *
getxdr_context(char *p, int len)
{
	ushort_t size;

	size = getxdr_u_short();
	if (((int)size > 0) && ((int)size < len) && getxdr_opaque(p, size))
		return (p);
	longjmp(xdr_err, 1);
	/* NOTREACHED */
}

char *
showxdr_context(char *fmt)
{
	ushort_t size;
	static char buff[1024];
	int pos;

	pos = getxdr_pos();
	size = getxdr_u_short();
	if (((int)size > 0) && ((int)size < 1024) &&
	    getxdr_opaque(buff, size)) {
		(void) sprintf(get_line(pos, getxdr_pos()), fmt, buff);
		return (buff);
	}
	longjmp(xdr_err, 1);
	/* NOTREACHED */
}

enum_t
getxdr_enum()
{
	enum_t e;

	if (xdr_enum(&xdrm, &e))
		return (e);
	longjmp(xdr_err, 1);
	/* NOTREACHED */
}

void
xdr_skip(int delta)
{
	uint_t pos;
	if (delta % 4 != 0 || delta < 0)
		longjmp(xdr_err, 1);
	/* Check for overflow */
	pos = xdr_getpos(&xdrm);
	if ((pos + delta) < pos)
		longjmp(xdr_err, 1);
	/* xdr_setpos() checks for buffer overrun */
	if (xdr_setpos(&xdrm, pos + delta) == FALSE)
		longjmp(xdr_err, 1);
}

int
getxdr_pos()
{
	return (xdr_getpos(&xdrm));
}

void
setxdr_pos(int pos)
{
	xdr_setpos(&xdrm, pos);
}

void
show_space()
{
	(void) get_line(0, 0);
}

void
show_trailer()
{
	show_space();
}

char *
getxdr_date()
{
	time_t sec;
	int  usec;
	static char buff[64];
	char *p;
	struct tm my_time;	/* private buffer to avoid collision */
				/* between gmtime and strftime */
	struct tm *tmp;

	sec  = getxdr_long();
	usec = getxdr_long();
	if (sec == -1)
		return ("-1 ");

	if (sec < 3600 * 24 * 365) {	/* assume not a date */
		(void) sprintf(buff, "%d.%06d", sec, usec);
	} else {
		tmp = gmtime(&sec);
		(void) memcpy(&my_time, tmp, sizeof (struct tm));
		strftime(buff, sizeof (buff), "%d-%h-%y %T.", &my_time);
		p = buff + strlen(buff);
		(void) sprintf(p, "%06d GMT", usec);
	}
	return (buff);
}

char *
showxdr_date(char *fmt)
{
	int pos;
	char *p;

	pos = getxdr_pos();
	p = getxdr_date();
	(void) sprintf(get_line(pos, getxdr_pos()), fmt, p);
	return (p);
}

char *
getxdr_date_ns(void)
{
	time_t sec, nsec;

	sec  = getxdr_long();
	nsec = getxdr_long();
	if (sec == -1)
		return ("-1 ");
	else
		return (format_time(sec, nsec));
}

/*
 * Format the given time.
 */
char *
format_time(int64_t sec, uint32_t nsec)
{
	static char buff[64];
	char *p;
	struct tm my_time;	/* private buffer to avoid collision */
				/* between gmtime and strftime */
	struct tm *tmp;

	if (sec < 3600 * 24 * 365) {
		/* assume not a date; includes negative times */
		(void) sprintf(buff, "%lld.%06d", sec, nsec);
	} else if (sec > INT32_MAX) {
		/*
		 * XXX No routines are available yet for formatting 64-bit
		 * times.
		 */
		(void) sprintf(buff, "%lld.%06d", sec, nsec);
	} else {
		time_t sec32 = (time_t)sec;

		tmp = gmtime(&sec32);
		memcpy(&my_time, tmp, sizeof (struct tm));
		strftime(buff, sizeof (buff), "%d-%h-%y %T.", &my_time);
		p = buff + strlen(buff);
		(void) sprintf(p, "%09d GMT", nsec);
	}
	return (buff);
}

char *
showxdr_date_ns(char *fmt)
{
	int pos;
	char *p;

	pos = getxdr_pos();
	p = getxdr_date_ns();
	(void) sprintf(get_line(pos, getxdr_pos()), fmt, p);
	return (p);
}

char *
getxdr_time()
{
	time_t sec;
	static char buff[64];
	struct tm my_time;	/* private buffer to avoid collision */
				/* between gmtime and strftime */
	struct tm *tmp;

	sec  = getxdr_long();
	if (sec == -1)
		return ("-1 ");

	if (sec < 3600 * 24 * 365) {	/* assume not a date */
		(void) sprintf(buff, "%d", sec);
	} else {
		tmp = gmtime(&sec);
		memcpy(&my_time, tmp, sizeof (struct tm));
		strftime(buff, sizeof (buff), "%d-%h-%y %T", &my_time);
	}
	return (buff);
}

char *
showxdr_time(char *fmt)
{
	int pos;
	char *p;

	pos = getxdr_pos();
	p = getxdr_time();
	(void) sprintf(get_line(pos, getxdr_pos()), fmt, p);
	return (p);
}

char *
getxdr_hex(int len)
{
	int i, j;
	static char hbuff[1024];
	char rbuff[1024];
	static char *hexstr = "0123456789ABCDEF";
	char toobig = 0;

	if (len == 0) {
		hbuff[0] = '\0';
		return (hbuff);
	}
	if (len > 1024)
		len = 1024;
	if (len < 0 || xdr_opaque(&xdrm, rbuff, len) == FALSE) {
		longjmp(xdr_err, 1);
	}

	if (len * 2 > sizeof (hbuff)) {
		toobig++;
		len = sizeof (hbuff) / 2;
	}

	j = 0;
	for (i = 0; i < len; i++) {
		hbuff[j++] = hexstr[rbuff[i] >> 4 & 0x0f];
		hbuff[j++] = hexstr[rbuff[i] & 0x0f];
	}

	if (toobig) {
		hbuff[len * 2 - strlen("<Too Long>")] = '\0';
		strcat(hbuff, "<Too Long>");
	} else
		hbuff[j] = '\0';

	return (hbuff);
}

char *
showxdr_hex(int len, char *fmt)
{
	int pos;
	char *p;

	pos = getxdr_pos();
	p = getxdr_hex(len);
	(void) sprintf(get_line(pos, getxdr_pos()), fmt, p);
	return (p);
}

static void
hexdump(char *data, int datalen)
{
	char *p;
	ushort_t *p16 = (ushort_t *)data;
	char *p8 = data;
	int i, left, len;
	int chunk = 16;  /* 16 bytes per line */

	printf("\n");

	for (p = data; p < data + datalen; p += chunk) {
		printf("\t%4d: ", p - data);
		left = (data + datalen) - p;
		len = MIN(chunk, left);
		for (i = 0; i < (len / 2); i++)
			printf("%04x ", ntohs(*p16++) & 0xffff);
		if (len % 2) {
			printf("%02x   ", *((unsigned char *)p16));
		}
		for (i = 0; i < (chunk - left) / 2; i++)
			printf("     ");

		printf("   ");
		for (i = 0; i < len; i++, p8++)
			printf("%c", isprint(*p8) ? *p8 : '.');
		printf("\n");
	}

	printf("\n");
}
