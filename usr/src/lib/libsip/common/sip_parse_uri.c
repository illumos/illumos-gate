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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "sip_parse_uri.h"

/*
 * SIP-URI          =  "sip:" [ userinfo ] hostport uri-parameters [ headers ]
 * SIPS-URI         =  "sips:" [ userinfo ] hostport uri-parameters [ headers ]
 * userinfo         =  ( user / telephone-subscriber ) [ ":" password ] "@"
 * user             =  1*( unreserved / escaped / user-unreserved )
 * user-unreserved  =  "&" / "=" / "+" / "$" / "," / ";" / "?" / "/"
 * password         =  *( unreserved / escaped / "&" / "=" / "+" / "$" / "," )
 * hostport         =  host [ ":" port ]
 * host             =  hostname / IPv4address / IPv6reference
 * hostname         =  *( domainlabel "." ) toplabel [ "." ]
 * domainlabel      =  alphanum / alphanum *( alphanum / "-" ) alphanum
 * toplabel         =  ALPHA / ALPHA *( alphanum / "-" ) alphanum
 * IPv4address    =  1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT
 * IPv6reference  =  "[" IPv6address "]"
 * IPv6address    =  hexpart [ ":" IPv4address ]
 * hexpart        =  hexseq / hexseq "::" [ hexseq ] / "::" [ hexseq ]
 * hexseq         =  hex4 *( ":" hex4)
 * hex4           =  1*4HEXDIG
 * port           =  1*DIGIT
 *
 * The BNF for telephone-subscriber can be found in RFC 2806 [9].  Note,
 * however, that any characters allowed there that are not allowed in
 * the user part of the SIP URI MUST be escaped.
 *
 * uri-parameters    =  *( ";" uri-parameter)
 * uri-parameter     =  transport-param / user-param / method-param
 *                      / ttl-param / maddr-param / lr-param / other-param
 * transport-param   =  "transport="( "udp" / "tcp" / "sctp" / "tls"
 *                     / other-transport)
 * other-transport   =  token
 * user-param        =  "user=" ( "phone" / "ip" / other-user)
 * other-user        =  token
 * method-param      =  "method=" Method
 * ttl-param         =  "ttl=" ttl
 * maddr-param       =  "maddr=" host
 * lr-param          =  "lr"
 * other-param       =  pname [ "=" pvalue ]
 * pname             =  1*paramchar
 * pvalue            =  1*paramchar
 * paramchar         =  param-unreserved / unreserved / escaped
 * param-unreserved  =  "[" / "]" / "/" / ":" / "&" / "+" / "$"
 * headers         =  "?" header *( "&" header )
 * header          =  hname "=" hvalue
 * hname           =  1*( hnv-unreserved / unreserved / escaped )
 * hvalue          =  *( hnv-unreserved / unreserved / escaped )
 * hnv-unreserved  =  "[" / "]" / "/" / "?" / ":" / "+" / "$"
 *
 */

#define	SIP_URI_MSG_BUF_SZ	100

#define	SIP_URI_ISHEX(c)					\
	(((int)(c) >= 0x30 && (int)(c) <= 0x39) || 	\
	((int)(c) >= 0x41 && (int)(c) <= 0x46) || 	\
	((int)(c) >= 0x61 && (int)(c) <= 0x66))

#define	SIP_URI_ISURLESCAPE(scan, end)			\
	((scan) + 2 < (end) && (scan)[0] == '%' && 	\
	SIP_URI_ISHEX((scan)[1]) && SIP_URI_ISHEX((scan[2])))

/*
 * URL character classes
 *  mark	- _ . ! ~ * ' ()
 *  reserved	; / ? : @ & = + $ ,    also [] for IPv6
 *  unreserved	alphanum mark
 *  pchar	: @ & = + $ , unreserved
 *  userinfo	; : & = + $ , unreserved escaped
 *  relsegment	; @ & = + $ , unreserved escaped
 *  reg_name	; : @ & = + $ , unreserved escaped
 *  token	- _ . ! ~ * ' %  + `
 *  param-unreserved  [ ] / : + $ &
 *  hnv-unreserved    [ ] / : + $ ?
 */
#define	SIP_URI_ALPHA_BIT		0x0001
#define	SIP_URI_DIGIT_BIT		0x0002
#define	SIP_URI_ALNUM_BITS		0x0003
#define	SIP_URI_SCHEME_BIT		0x0004	/* for - + . */
#define	SIP_URI_TOKEN_BIT		0x0008	/* for - _ . ! ~ * ' % + ` */
#define	SIP_URI_QUEST_BIT		0x0010	/* for ? */
#define	SIP_URI_AT_BIT			0x0020	/* for @ */
#define	SIP_URI_COLON_BIT		0x0040	/* for : */
#define	SIP_URI_SEMI_BIT		0x0080	/* for ; */
#define	SIP_URI_DASH_BIT		0x0100	/* for - */
#define	SIP_URI_MARK_BIT		0x0200	/* for - _ . ! ~ * ' ( ) */
#define	SIP_URI_AND_BIT			0x0400	/* for & */
#define	SIP_URI_PHCOMM_BIT		0x0800	/* for [ ] / : + $ */
#define	SIP_URI_OTHER_BIT		0x1000	/* for = + $ , */
#define	SIP_URI_SLASH_BIT		0x2000	/* for / */
#define	SIP_URI_VISUALSEP_BIT		0x4000	/* for -.() */
#define	SIP_URI_DTMFURI_DIGIT_BIT	0x8000	/* for *ABCD */

#define	a 			SIP_URI_ALPHA_BIT
#define	d 			SIP_URI_DIGIT_BIT
#define	s 			SIP_URI_SCHEME_BIT
#define	t 			SIP_URI_TOKEN_BIT
#define	q 			SIP_URI_QUEST_BIT
#define	m 			SIP_URI_AT_BIT
#define	c 			SIP_URI_COLON_BIT
#define	i 			SIP_URI_SEMI_BIT
#define	h 			SIP_URI_DASH_BIT
#define	k 			SIP_URI_MARK_BIT
#define	n 			SIP_URI_AND_BIT
#define	o 			SIP_URI_PHCOMM_BIT
#define	r 			SIP_URI_OTHER_BIT
#define	l 			SIP_URI_SLASH_BIT
#define	v 			SIP_URI_VISUALSEP_BIT
#define	f 			SIP_URI_DTMFURI_DIGIT_BIT

static const unsigned short sip_uri_table[256] = {
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	t|k,	0,	0,	o|r,	t,	n,	t|k,
	k|v,	k|v,	t|k|f, s|t|r|o,	r,  h|s|t|k|v, s|t|k|v,	o|l,
	d,	d,	d,	d,	d,	d,	d,	d,
	d,	d,	c|o,	i,	0,	r,	0,	q,
	m,	a|f,	a|f,	a|f,	a|f,	a,	a,	a,
	a,	a,	a,	a,	a,	a,	a,	a,
	a,	a,	a,	a,	a,	a,	a,	a,
	a,	a,	a,	o,	0,	o,	0,	t|k,
	t,	a,	a,	a,	a,	a,	a,	a,
	a,	a,	a,	a,	a,	a,	a,	a,
	a,	a,	a,	a,	a,	a,	a,	a,
	a,	a,	a,	0,	0,	0,	t|k,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
	0,	0,	0,	0,	0,	0,	0,	0,
};

#undef	a
#undef	d
#undef	s
#undef	t
#undef	q
#undef	m
#undef	c
#undef	i
#undef	h
#undef	k
#undef	n
#undef	o
#undef	r
#undef	l
#undef	v
#undef	f

#define	SIP_URI_UT(c)			sip_uri_table[(unsigned char)(c)]
#define	SIP_URI_ISALPHA(c)		(SIP_URI_UT(c) & SIP_URI_ALPHA_BIT)
#define	SIP_URI_ISDIGIT(c)		(SIP_URI_UT(c) & SIP_URI_DIGIT_BIT)
#define	SIP_URI_ISALNUM(c)		(SIP_URI_UT(c) & SIP_URI_ALNUM_BITS)
#define	SIP_URI_ISSCHEME(c)		\
		(SIP_URI_UT(c) & (SIP_URI_ALNUM_BITS|SIP_URI_SCHEME_BIT))
#define	SIP_URI_ISTOKEN(c)		\
		(SIP_URI_UT(c) & (SIP_URI_ALNUM_BITS|SIP_URI_TOKEN_BIT))
#define	SIP_URI_ISSIPDELIM(c)		\
		(SIP_URI_UT(c) & (SIP_URI_SEMI_BIT|SIP_URI_QUEST_BIT))
#define	SIP_URI_ISSIPHDELIM(c)					\
	(SIP_URI_UT(c) & (SIP_URI_COLON_BIT|SIP_URI_SEMI_BIT|SIP_URI_QUEST_BIT))
#define	SIP_URI_ISHOST(c)		\
		(SIP_URI_UT(c) & (SIP_URI_ALNUM_BITS|SIP_URI_DASH_BIT))
#define	SIP_URI_ISUSER(c)						\
	(SIP_URI_UT(c) & (SIP_URI_OTHER_BIT|SIP_URI_SEMI_BIT|		\
	SIP_URI_QUEST_BIT|SIP_URI_SLASH_BIT|SIP_URI_AND_BIT))

#define	SIP_URI_ISABSHDELIM(c)					\
	(SIP_URI_UT(c) & \
	(SIP_URI_SLASH_BIT|SIP_URI_COLON_BIT|SIP_URI_QUEST_BIT))
#define	SIP_URI_ISABSDELIM(c)	\
	(SIP_URI_UT(c) & (SIP_URI_SLASH_BIT|SIP_URI_QUEST_BIT))
#define	SIP_URI_ISUNRESERVED(c)	\
	(SIP_URI_UT(c) & (SIP_URI_ALNUM_BITS|SIP_URI_MARK_BIT))
#define	SIP_URI_ISPARAM(c)						\
	(SIP_URI_UT(c) & (SIP_URI_PHCOMM_BIT|SIP_URI_AND_BIT|\
	SIP_URI_ALNUM_BITS|SIP_URI_MARK_BIT))
#define	SIP_URI_ISHEADER(c)						\
	(SIP_URI_UT(c) & (SIP_URI_PHCOMM_BIT|SIP_URI_QUEST_BIT|\
	SIP_URI_ALNUM_BITS|SIP_URI_MARK_BIT))
#define	SIP_URI_ISOTHER(c)		(SIP_URI_UT(c) & SIP_URI_OTHER_BIT)
#define	SIP_URI_ISRESERVED(c)					\
	(SIP_URI_UT(c) & (SIP_URI_SEMI_BIT|SIP_URI_SLASH_BIT|	\
	SIP_URI_QUEST_BIT| SIP_URI_COLON_BIT|SIP_URI_AT_BIT|	\
	SIP_URI_AND_BIT|SIP_URI_OTHER_BIT))
#define	SIP_URI_ISPCHAR(c)	\
	(SIP_URI_UT(c) & (SIP_URI_COLON_BIT|SIP_URI_AT_BIT|	\
	SIP_URI_AND_BIT|SIP_URI_OTHER_BIT))
#define	SIP_URI_ISREGNAME(c)					\
	(SIP_URI_UT(c) & 	\
	(SIP_URI_OTHER_BIT|SIP_URI_SEMI_BIT|SIP_URI_COLON_BIT|	\
	SIP_URI_AT_BIT|SIP_URI_AND_BIT))
#define	SIP_URI_ISPHONEDIGIT(c)	\
	(SIP_URI_UT(c) & (SIP_URI_DIGIT_BIT|SIP_URI_VISUALSEP_BIT))
#define	SIP_URI_ISDTMFDIGIT(c)	(SIP_URI_UT(c) & SIP_URI_DTMFURI_DIGIT_BIT)

static int  sip_uri_url_casecmp(const char *, const char *, unsigned);
static void sip_uri_parse_params(_sip_uri_t *, char *, char *);
static void sip_uri_parse_headers(_sip_uri_t *, char *, char *);
static void sip_uri_parse_abs_opaque(_sip_uri_t *, char *, char *);
static void sip_uri_parse_abs_query(_sip_uri_t *, char *, char *);
static void sip_uri_parse_abs_path(_sip_uri_t *, char *, char *);
static void sip_uri_parse_abs_regname(_sip_uri_t *, char *, char *);
static int  sip_uri_parse_scheme(_sip_uri_t *, char *, char *);
static void sip_uri_parse_password(_sip_uri_t *, char *, char *);
static void sip_uri_parse_user(_sip_uri_t *, char *, char *);
static void sip_uri_parse_port(_sip_uri_t *, char *, char *);
static void sip_uri_parse_netpath(_sip_uri_t *, char **, char *, boolean_t);
static int  sip_uri_parse_ipv6(char *, char *);
static int  sip_uri_parse_ipv4(char *, char *);
static int  sip_uri_parse_hostname(char *, char *);
static int sip_uri_parse_tel(char *, char *);
static int sip_uri_parse_tel_areaspe(char *, char *);
static int sip_uri_parse_tel_servicepro(char *, char *);
static int sip_uri_parse_tel_futureext(char *, char *);
static int sip_uri_isTokenchar(char **, char *);
static int sip_uri_isEscapedPound(char **, char *);
static int sip_uri_hexVal(char *, char *);
static int SIP_URI_HEXVAL(int);

/*
 * get the hex value of a char
 */
static int
SIP_URI_HEXVAL(int c)
{
	if (c >= 0x30 && c <= 0x39)
		return (c - '0');
	if (c >= 0x41 && c <= 0x46)
		return (c - 'A' + 10);
	if (c >= 0x61 && c <= 0x66)
		return (c - 'a' + 10);
	return (c);
}

/*
 * basic ASCII case-insensitive comparison
 */
static int
sip_uri_url_casecmp(const char *str1, const char *str2, unsigned len)
{
	unsigned	j;

	for (j = 0; j < len && tolower(str1[j]) == tolower(str2[j]) &&
	    str1[j] != '\0'; ++j) {
		;
	}
	return (j == len ? 0 : tolower(str2[j]) - tolower(str1[j]));
}

/*
 * telephone-subscriber  = global-phone-number / local-phone-number
 * Please refer to RFC 2806
 */
static int
sip_uri_parse_tel(char *scan, char *uend)
{
	char	*mark = (char *)0;
	int	ret = 0;
	int	isGlobal = 0;
	int	quote = 0;

	if (scan == uend)
		return (0);
	if (*scan == '+') {
		++scan;
		isGlobal = 1;
	}
	mark = scan;
	if (isGlobal) {
		while (scan < uend && SIP_URI_ISPHONEDIGIT(*scan))
			++scan;
	} else {
		while (scan < uend &&
		    (SIP_URI_ISPHONEDIGIT(*scan) ||
		    SIP_URI_ISDTMFDIGIT(*scan) ||
		    sip_uri_isEscapedPound(&scan, uend) ||
		    *scan == 'p' || *scan == 'w')) {
			++scan;
		}
	}
	if (mark == scan || (scan < uend && *scan != ';'))
		return (0);

	/*
	 * parse isdn-subaddress
	 */
	if (uend - scan > 6 && !sip_uri_url_casecmp(scan, ";isub=", 6)) {
		scan += 6;
		mark = scan;
		while (scan < uend && SIP_URI_ISPHONEDIGIT(*scan))
			++scan;
		if (mark == scan || (scan < uend && *scan != ';'))
			return (0);
	}

	/*
	 * parse post-dial
	 */
	if (uend - scan > 7 && !sip_uri_url_casecmp(scan, ";postd=", 7)) {
		scan += 7;
		mark = scan;
		while (scan < uend &&
		    (SIP_URI_ISPHONEDIGIT(*scan) ||
		    SIP_URI_ISDTMFDIGIT(*scan) ||
		    sip_uri_isEscapedPound(&scan, uend) ||
		    *scan == 'p' || *scan == 'w')) {
			++scan;
		}
		if (mark == scan || (scan < uend && *scan != ';'))
			return (0);
	}

	if (!isGlobal) {
		/*
		 * parse area-specifier
		 */
		if (uend - scan > 15 &&
		    !sip_uri_url_casecmp(scan, ";phone-context=", 15)) {
			scan += 15;
			mark = scan;
			while (scan < uend && *scan != ';')
				++scan;
			ret = sip_uri_parse_tel_areaspe(mark, scan);
		}
	} else {
		ret = 1;
	}

	/*
	 * parse area-specifier, service-provider, future-extension
	 */
	while (scan < uend && ret) {
		if (uend - scan > 15 &&
			!sip_uri_url_casecmp(scan, ";phone-context=", 15)) {
			scan += 15;
			mark = scan;
			while (scan < uend && *scan != ';')
				++scan;
			ret = sip_uri_parse_tel_areaspe(mark, scan);
		} else if (uend - scan > 5 &&
		    !sip_uri_url_casecmp(scan, ";tsp=", 5)) {
			scan += 5;
			mark = scan;
			while (scan < uend && *scan != ';')
				++scan;
			ret = sip_uri_parse_tel_servicepro(mark, scan);
		} else {
			++scan;
			mark = scan;
			while (scan < uend && (*scan != ';' || quote)) {
				if (sip_uri_hexVal(scan, uend) == 0x22) {
					quote = !quote;
					scan += 3;
				} else {
					++scan;
				}
			}
			ret = sip_uri_parse_tel_futureext(mark, scan);
		}
	}
	return (ret && scan == uend);
}

/*
 * area-specifier        = ";" phone-context-tag "=" phone-context-ident
 * phone-context-tag     = "phone-context"
 * phone-context-ident   = network-prefix / private-prefix
 * network-prefix        = global-network-prefix / local-network-prefix
 * global-network-prefix = "+" 1*phonedigit
 * local-network-prefix  = 1*(phonedigit / dtmf-digit / pause-character)
 * private-prefix        = (%x21-22 / %x24-27 / %x2C / %x2F / %x3A /
 *                          %x3C-40 / %x45-4F / %x51-56 / %x58-60 /
 *                          %x65-6F / %x71-76 / %x78-7E)
 *                          *(%x21-3A / %x3C-7E)
 * phonedigit            = DIGIT / visual-separator
 * visual-separator      = "-" / "." / "(" / ")"
 * pause-character       = one-second-pause / wait-for-dial-tone
 * one-second-pause      = "p"
 * wait-for-dial-tone    = "w"
 * dtmf-digit            = "*" / "#" / "A" / "B" / "C" / "D"
 */
static int
sip_uri_parse_tel_areaspe(char *scan, char *uend)
{
	int	uri_hexValue;

	if (scan == uend)
		return (0);

	/*
	 * parse global-network-prefix
	 */
	if (*scan == '+') {
		++scan;
		if (scan == uend)
			return (0);
		while (scan < uend && SIP_URI_ISPHONEDIGIT(*scan))
			++scan;
	/*
	 * parse local-network-prefix
	 */
	} else if (SIP_URI_ISPHONEDIGIT(*scan) || SIP_URI_ISDTMFDIGIT(*scan) ||
	    sip_uri_isEscapedPound(&scan, uend) ||
	    *scan == 'p' || *scan == 'w') {
		++scan;
		while (scan < uend &&
		    (SIP_URI_ISPHONEDIGIT(*scan) ||
		    SIP_URI_ISDTMFDIGIT(*scan) ||
		    sip_uri_isEscapedPound(&scan, uend) ||
		    *scan == 'p' || *scan == 'w')) {
			++scan;
		}
	} else {
	/*
	 * parse private-prefix
	 *
	 * any characters allowed in RFC 2806 that are not allowed in
	 * the user part of the SIP URI MUST be escaped
	 *
	 * private-prefix	= (! $ & ', / = ? _
	 *			EFGHIJKLMNOQRSTUVXYZ efghijklmnoqrstuvxyz
	 *			{ } | ~ [ ] \ ^  ` " % : < > @)
	 *			*(%x21-3A / %x3C-7E)
	 *
	 * following characters are allowed in RFC 2806 and
	 * the user part of SIP URI
	 *  ! $ & ', / = ? _ EFGHIJKLMNOQRSTUVXYZ efghijklmnoqrstuvxyz
	 */
		if (*scan == '!' || *scan == '$' || *scan == '&' ||
		    *scan == '\'' || *scan == ',' || *scan == '/' ||
		    *scan == '=' || *scan == '?' || *scan == '_' ||
		    (*scan >= 'E' && *scan <= 'Z' &&
		    *scan != 'P' && *scan != 'W') ||
		    (*scan >= 'e' && *scan <= 'z' &&
		    *scan != 'p' && *scan != 'w')) {
			++scan;
		} else {
			uri_hexValue = sip_uri_hexVal(scan, uend);
			if (uri_hexValue == 0x21 || uri_hexValue == 0x22 ||
			    (uri_hexValue >= 0x24 && uri_hexValue <= 0x27) ||
			    uri_hexValue == 0x2c || uri_hexValue == 0x2f ||
			    uri_hexValue == 0x3a ||
			    (uri_hexValue >= 0x3c && uri_hexValue <= 0x40) ||
			    (uri_hexValue >= 0x45 && uri_hexValue <= 0x4f) ||
			    (uri_hexValue >= 0x51 && uri_hexValue <= 0x56) ||
			    (uri_hexValue >= 0x58 && uri_hexValue <= 0x60) ||
			    (uri_hexValue >= 0x65 && uri_hexValue <= 0x6f) ||
			    (uri_hexValue >= 0x71 && uri_hexValue <= 0x76) ||
			    (uri_hexValue >= 0x78 && uri_hexValue <= 0x7e)) {
				scan += 3;
			} else {
				return (0);
			}
		}
		/*
		 * parse *(%x21-3A / %x3C-7E)
		 */
		while (scan < uend) {
			if (SIP_URI_ISUNRESERVED(*scan) ||
			    (SIP_URI_ISUSER(*scan) && *scan != ';')) {
				++scan;
			} else {
				uri_hexValue = sip_uri_hexVal(scan, uend);
				if (uri_hexValue >= 0x21 &&
				    uri_hexValue <= 0x7e &&
				    uri_hexValue != 0x3b) {
					scan += 3;
				} else {
					return (0);
				}
			}
		}
	}
	if (scan < uend)
		return (0);
	return (1);
}

static int
sip_uri_hexVal(char *scan, char *uend)
{
	int	ret = -1;

	if (SIP_URI_ISURLESCAPE(scan, uend)) {
		ret = (SIP_URI_ISDIGIT(scan[1]) ? (scan[1] - '0') :
		    (tolower(scan[1]) - 'a' + 10)) * 16 +
		    (SIP_URI_ISDIGIT(scan[2]) ? (scan[2] - '0') :
		    (tolower(scan[2]) - 'a' + 10));
	}
	return (ret);
}

/*
 * service-provider  = ";" provider-tag "=" provider-hostname
 * provider-tag      = "tsp"
 * provider-hostname = domain
 */
static int
sip_uri_parse_tel_servicepro(char *scan, char *uend)
{
	char	*mark = (char *)0;

	if (scan == uend)
		return (0);

	/*
	 * parse domain=" "
	 */
	if (sip_uri_hexVal(scan, uend) == 0x20 && scan + 3 == uend)
		return (1);
	while (scan < uend) {
		mark = scan;
		while (scan < uend && (*scan == '-'|| SIP_URI_ISALNUM(*scan)))
			++scan;
		if ((scan < uend && *scan != '.') ||
		    !SIP_URI_ISALPHA(*mark) || !SIP_URI_ISALNUM(*(scan - 1))) {
			return (0);
		}
		if (scan < uend)
			++scan;
	}

	if (scan < uend)
		return (0);
	return (1);
}

/*
 * future-extension = ";" 1*(token-char) ["=" ((1*(token-char)
 *                    ["?" 1*(token-char)]) / quoted-string )]
 * token-char       = (%x21 / %x23-27 / %x2A-2B / %x2D-2E / %x30-39
 *                     / %x41-5A / %x5E-7A / %x7C / %x7E)
 */
static int
sip_uri_parse_tel_futureext(char *scan, char *uend)
{
	char	*mark;
	int	uri_hexValue = 0;

	if (scan == uend)
		return (0);

	/*
	 * parse 1*(token-char)
	 */
	mark = scan;
	while (scan < uend && sip_uri_isTokenchar(&scan, uend))
		;
	if (mark == scan ||
	    (scan < uend && (*scan != '=' || scan + 1 == uend))) {
		return (0);
	}
	if (scan == uend)
		return (1);
	++scan;

	/*
	 * parse 1*token-char ["?" 1*token-char]
	 */
	if (sip_uri_isTokenchar(&scan, uend)) {
		while (sip_uri_isTokenchar(&scan, uend))
			;
		if (scan < uend) {
			if (*scan != '?')
				return (0);
			++scan;
			mark = scan;
			while (sip_uri_isTokenchar(&scan, uend))
				;
			if (mark == scan)
				return (0);
		}
	} else { /* parse quoted-string */
		uri_hexValue = sip_uri_hexVal(scan, uend);
		if (uri_hexValue != 0x22)
			return (0);
		scan += 3;
		while (scan < uend && sip_uri_hexVal(scan, uend) != 0x22) {
			/*
			 * parse "\" CHAR
			 */
			if (sip_uri_hexVal(scan, uend) == 0x5c) {
				scan += 3;
				if (scan < uend) {
					if (SIP_URI_ISUNRESERVED(*scan) ||
					    SIP_URI_ISUSER(*scan)) {
						++scan;
					} else if (sip_uri_hexVal(scan, uend) >=
					    0x00 &&
					    sip_uri_hexVal(scan, uend) <=
					    0x7f) {
						scan += 3;
					} else {
						return (0);
					}
				} else {
					return (0);
				}
			} else {
				if (SIP_URI_ISUNRESERVED(*scan) ||
				    SIP_URI_ISUSER(*scan)) {
					++scan;
				} else {
					uri_hexValue =
					    sip_uri_hexVal(scan, uend);
					if ((uri_hexValue >= 0x20 &&
						uri_hexValue <= 0x21) ||
						(uri_hexValue >= 0x23 &&
						uri_hexValue <= 0x7e) ||
						(uri_hexValue >= 0x80 &&
						uri_hexValue <= 0xff)) {
						scan += 3;
					} else {
						return (0);
					}
				}
			}
		}
		if (scan == uend ||
		    (scan < uend && sip_uri_hexVal(scan, uend) != 0x22)) {
			return (0);
		}
		scan += 3;
	}

	if (scan < uend)
		return (0);
	return (1);
}

/*
 * Any characters allowed in RFC2806 tel URL that are not allowed in
 * the user part of the SIP URI MUST be escaped.
 * token-char = - _ . ! ~ * ' $ &  + DIGIT ALPHA #  % ^ ` |
 */
static int
sip_uri_isTokenchar(char **pscan, char *uend)
{
	char	*scan = *pscan;
	int	uri_hexValue = 0;

	if (scan == uend)
		return (0);

	/*
	 * for ALPAH DIGIT - _ . ! ~ * ' $ & +
	 */
	if ((SIP_URI_ISUNRESERVED(*scan) && *scan != '(' && *scan != ')') ||
	    *scan == '$' || *scan == '&' || *scan == '+') {
		++scan;
		*pscan = scan;
		return (1);
	}

	uri_hexValue = sip_uri_hexVal(scan, uend);
	if (uri_hexValue == 0x21 || uri_hexValue == 0x7c ||
	    uri_hexValue == 0x7e ||
	    (uri_hexValue >= 0x23 && uri_hexValue <= 0x27) ||
	    (uri_hexValue >= 0x2a && uri_hexValue <= 0x2b) ||
	    (uri_hexValue >= 0x2d && uri_hexValue <= 0x2e) ||
	    (uri_hexValue >= 0x30 && uri_hexValue <= 0x39) ||
	    (uri_hexValue >= 0x41 && uri_hexValue <= 0x5a) ||
	    (uri_hexValue >= 0x5e && uri_hexValue <= 0x7a)) {
		scan += 3;
		*pscan = scan;
		return (1);
	}
	return (0);
}

/*
 * '#' is not allowed in the telephone-subscriber part of SIP URI
 * it must be escaped
 */
static int
sip_uri_isEscapedPound(char **pscan, char *uend)
{
	char	*scan = *pscan;

	if (scan == uend)
		return (0);
	if (*scan == '%' && scan + 2 < uend && scan[1] == '2' &&
	    scan[2] == '3') {
		scan += 2;
		*pscan = scan;
		return (1);
	}
	return (0);
}

/*
 * scheme =  ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
 */
static int
sip_uri_parse_scheme(_sip_uri_t *outurl, char *scan, char *uend)
{
	if (scan == uend) {
		outurl->sip_uri_errflags |= SIP_URIERR_SCHEME;
		return (0);
	}
	outurl->sip_uri_scheme.sip_str_ptr = scan;
	outurl->sip_uri_scheme.sip_str_len = uend - scan;

	if (scan < uend && SIP_URI_ISALPHA(*scan)) {
		++scan;
		while (scan < uend && SIP_URI_ISSCHEME(*scan))
			++scan;
	}
	if (scan < uend)
		outurl->sip_uri_errflags |= SIP_URIERR_SCHEME;
	return (1);
}

/*
 * The format of params is supposed to be;XXX;XXX;XXX
 * uri-parameters	= *(";" uri-parameter)
 * uri-parameter	= transport-param / user-param / method-param
 * 			/ ttl-param / maddr-param / lr-param / other-param
 * transport-param	=  "transport="
 *			("udp" / "tcp" / "sctp" / "tls" / other-transport)
 * other-transport		=  token
 * user-param		=  "user=" ("phone" / "ip" / other-user)
 * other-user		=  token
 * method-param		=  "method=" Method
 * ttl-param		=  "ttl=" ttl
 * maddr-param		=  "maddr=" host
 * lr-param		=  "lr"
 * other-param		=  pname [ "=" pvalue ]
 * pname		=  1*paramchar
 * pvalue		=  1*paramchar
 * paramchar		=  param-unreserved / unreserved / escaped
 * param-unreserved	=  "[" / "]" / "/" / ":" / "&" / "+" / "$"
 */
static void
sip_uri_parse_params(_sip_uri_t *outurl, char *scan, char *uend)
{
	char		*mark = (char *)0;
	char		*equal = (char *)0;
	int		i = 0;
	int		ttl = 0;
	int		paramleftlen = 0;
	int		gothost = 0;
	sip_param_t	*param = NULL;
	sip_param_t	*new_param = NULL;

	if (scan == uend || *scan != ';' || scan + 1 == uend) {
		outurl->sip_uri_errflags |= SIP_URIERR_PARAM;
		return;
	}

	while (scan < uend) {
		mark = ++scan;
		while (scan < uend && *scan != ';')
			++scan;
		if (scan == mark) {
			outurl->sip_uri_errflags |= SIP_URIERR_PARAM;
			return;
		}

		new_param = calloc(1, sizeof (sip_param_t));
		if (new_param == NULL) {
			outurl->sip_uri_errflags |= SIP_URIERR_MEMORY;
			return;
		}

		if (param == NULL)
			outurl->sip_uri_params = new_param;
		else
			param->param_next = new_param;

		param = new_param;

		param->param_name.sip_str_ptr = mark;
		equal = memchr(mark, '=', scan - mark);
		if (equal == (char *)0) {
			param->param_name.sip_str_len = scan - mark;
			param->param_value.sip_str_ptr = NULL;
			param->param_value.sip_str_len = 0;
			while (mark < scan && (SIP_URI_ISPARAM(*mark) ||
			    SIP_URI_ISURLESCAPE(mark, scan))) {
				++mark;
			}
		} else {
			param->param_name.sip_str_len = equal - mark;
			param->param_value.sip_str_ptr = equal + 1;
			param->param_value.sip_str_len = scan - equal - 1;

			if (mark == equal || equal + 1 == scan) {
				outurl->sip_uri_errflags |= SIP_URIERR_PARAM;
				return;
			}
			paramleftlen = equal - mark + 1;
			if ((paramleftlen == 10 &&
			    !sip_uri_url_casecmp(mark, "transport=", 10)) ||
			    (paramleftlen == 5 &&
			    !sip_uri_url_casecmp(mark, "user=", 5)) ||
			    (paramleftlen == 7 &&
			    !sip_uri_url_casecmp(mark, "method=", 7))) {
				if (scan - equal == 1) {
					outurl->sip_uri_errflags |=
					    SIP_URIERR_PARAM;
					return;
				}
				mark = equal + 1;
				while (mark < scan && SIP_URI_ISTOKEN(*mark))
					++mark;
			} else if (paramleftlen == 4 &&
			    !sip_uri_url_casecmp(mark, "ttl=", 4)) {
				if (scan - equal == 1) {
					outurl->sip_uri_errflags |=
					    SIP_URIERR_PARAM;
					return;
				}
				mark = equal;
				for (i = 0; i < 3; ++i) {
					++mark;
					if (mark < scan &&
					    SIP_URI_ISDIGIT(*mark)) {
						ttl = ttl * 10 + (*mark - '0');
					}
					if (ttl > 255) {
						outurl->sip_uri_errflags |=
							SIP_URIERR_PARAM;
						return;
					}
				}
			} else if (paramleftlen == 6 &&
			    !sip_uri_url_casecmp(mark, "maddr=", 6)) {
				gothost = 0;
				mark = equal + 1;
				if (mark < scan && SIP_URI_ISDIGIT(*mark)) {
					gothost = sip_uri_parse_ipv4(mark,
					    scan);
				}
				/*
				 * not valid syntax for a host or user name,
				 * try IPv6 literal
				 */
				if (!gothost && mark < scan && *mark == '[') {
					gothost = sip_uri_parse_ipv6(mark,
					    scan);
				}
				/*
				 * look for a valid host name:
				 * *(domainlabel ".") toplabel ["."]
				 */
				if (!gothost && mark < scan) {
					if (!(gothost =
					    sip_uri_parse_hostname(mark,
					    scan))) {
						outurl->sip_uri_errflags |=
							SIP_URIERR_PARAM;
					}
				}
				if (gothost)
					mark = scan;
			} else if (paramleftlen == 3 &&
			    !sip_uri_url_casecmp(mark, "lr=", 3)) {
				outurl->sip_uri_errflags |= SIP_URIERR_PARAM;
				return;
			} else {
				while (mark < scan && (SIP_URI_ISPARAM(*mark) ||
				    SIP_URI_ISURLESCAPE(mark, scan) ||
				    mark == equal)) {
					++mark;
				}
			}
		}
		if (mark < scan) {
			outurl->sip_uri_errflags |= SIP_URIERR_PARAM;
			return;
		}
	}
}

/*
 * The format of headers is supposed to be ?XXX&XXX&XXX
 * headers         =  "?" header *("&" header
 * header          =  hname "=" hvalue
 * hname           =  1*(hnv-unreserved / unreserved / escaped
 * hvalue          =  *(hnv-unreserved / unreserved / escaped
 * hnv-unreserved  =  "[" / "]" / "/" / "?" / ":" / "+" / "$"
 */
static void
sip_uri_parse_headers(_sip_uri_t *outurl, char *scan, char *uend)
{
	char	*mark = NULL;
	char	*equal = NULL;

	if (scan == uend || *scan != '?' || scan + 1 == uend) {
		outurl->sip_uri_errflags |= SIP_URIERR_HEADER;
		return;
	}
	outurl->sip_uri_headers.sip_str_ptr = scan + 1;
	outurl->sip_uri_headers.sip_str_len = uend - (scan + 1);

	while (scan < uend) {
		mark = ++scan;
		while (scan < uend && *scan != '&')
			++scan;
		if (scan == mark) {
			outurl->sip_uri_errflags |= SIP_URIERR_HEADER;
			return;
		}
		equal = memchr(mark, '=', scan - mark);
		if (equal == mark || equal == (char *)0) {
			outurl->sip_uri_errflags |= SIP_URIERR_HEADER;
			return;
		}
		while (mark < scan &&
		    (SIP_URI_ISHEADER(*mark) ||
		    SIP_URI_ISURLESCAPE(mark, scan) || mark == equal)) {
			++mark;
		}
		if (mark < scan) {
			outurl->sip_uri_errflags |= SIP_URIERR_HEADER;
			return;
		}
	}
}

/*
 * opaque-part   =  uric-no-slash *uric
 * uric          =  reserved / unreserved / escaped
 * uric-no-slash =  unreserved / escaped / ";" / "?" / ":" / "@"
 *                  / "&" / "=" / "+" / "$" / ","
 */
static void
sip_uri_parse_abs_opaque(_sip_uri_t *outurl, char *scan, char *uend)
{
	if (scan == uend) {
		outurl->sip_uri_errflags |= SIP_URIERR_OPAQUE;
		return;
	}
	outurl->sip_uri_opaque.sip_str_ptr = scan;
	outurl->sip_uri_opaque.sip_str_len = uend - scan;

	if (SIP_URI_ISUNRESERVED(*scan) || SIP_URI_ISURLESCAPE(scan, uend) ||
	    SIP_URI_ISOTHER(*scan) || *scan == ';' || *scan == '?' ||
	    *scan == ':' || *scan == '@' || *scan == '&') {
		++scan;
	} else {
		outurl->sip_uri_errflags |= SIP_URIERR_OPAQUE;
		return;
	}
	while (scan < uend && (SIP_URI_ISRESERVED(*scan) ||
	    SIP_URI_ISUNRESERVED(*scan) || SIP_URI_ISURLESCAPE(scan, uend))) {
		++scan;
	}
	if (scan < uend)
		outurl->sip_uri_errflags |= SIP_URIERR_OPAQUE;
}

/*
 * format of query is supposed to be ?XXX
 * query =  *uric
 * uric  =  reserved / unreserved / escaped
 */
static void
sip_uri_parse_abs_query(_sip_uri_t *outurl, char *scan, char *uend)
{
	if (uend == scan || *scan != '?' || scan + 1 == uend)
		return;
	++scan;
	outurl->sip_uri_query.sip_str_ptr = scan;
	outurl->sip_uri_query.sip_str_len = uend - scan;

	while (scan < uend && (SIP_URI_ISRESERVED(*scan) ||
	    SIP_URI_ISUNRESERVED(*scan) || SIP_URI_ISURLESCAPE(scan, uend))) {
		++scan;
	}
	if (scan < uend)
		outurl->sip_uri_errflags |= SIP_URIERR_QUERY;
}

/*
 * the format of path is supposed to be /XXX;XXX/XXX;
 * abs-path       =  "/" path-segments
 * path-segments  =  segment *( "/" segment )
 * segment        =  *pchar *( ";" param )
 * param          =  *pchar
 * pchar          =  unreserved / escaped /
 *                   ":" / "@" / "&" / "=" / "+" / "$" / ","
 */
static void
sip_uri_parse_abs_path(_sip_uri_t *outurl, char *scan, char *uend)
{
	if (scan == uend || *scan != '/')
		return;
	outurl->sip_uri_path.sip_str_ptr = scan;
	outurl->sip_uri_path.sip_str_len = uend - scan;

	++scan;
	while (scan < uend && (SIP_URI_ISPCHAR(*scan) ||
	    SIP_URI_ISUNRESERVED(*scan) || SIP_URI_ISURLESCAPE(scan, uend) ||
	    *scan == '/' || *scan == ';')) {
		++scan;
	}
	if (scan < uend)
		outurl->sip_uri_errflags |= SIP_URIERR_PATH;
}
/*
 * reg-name =  1*( unreserved / escaped / "$" / "," / ";"
 *             / ":" / "@" / "&" / "=" / "+" )
 */
static void
sip_uri_parse_abs_regname(_sip_uri_t *outurl, char *scan, char *uend)
{
	if (scan == uend)
		return;
	outurl->sip_uri_regname.sip_str_ptr = scan;
	outurl->sip_uri_regname.sip_str_len = uend - scan;

	while (scan < uend && (SIP_URI_ISUNRESERVED(*scan) ||
	    SIP_URI_ISURLESCAPE(scan, uend) || SIP_URI_ISREGNAME(*scan))) {
		++scan;
	}
	if (scan < uend)
		outurl->sip_uri_errflags |= SIP_URIERR_REGNAME;
}

/*
 * The format of the password is supposed to be :XXX
 * password =  *( unreserved / escaped / "&" / "=" / "+" / "$" / "," )
 */
static void
sip_uri_parse_password(_sip_uri_t *outurl, char *scan, char *uend)
{
	if (scan == uend || *scan != ':' || scan + 1 == uend)
		return;
	++scan;
	outurl->sip_uri_password.sip_str_ptr = scan;
	outurl->sip_uri_password.sip_str_len = uend - scan;

	while (scan < uend && (SIP_URI_ISUNRESERVED(*scan) ||
	    SIP_URI_ISURLESCAPE(scan, uend) || SIP_URI_ISOTHER(*scan) ||
	    *scan == '&')) {
		++scan;
	}
	if (scan < uend)
		outurl->sip_uri_errflags |= SIP_URIERR_PASS;
}

/*
 * user =  1*( unreserved / escaped / user-unreserved )
 * user-unreserved  =  "&" / "=" / "+" / "$" / "," / ";" / "?" / "/"
 */
static void
sip_uri_parse_user(_sip_uri_t *outurl, char *scan, char *uend)
{
	if (scan == uend) {
		outurl->sip_uri_errflags |= SIP_URIERR_USER;
		return;
	}
	outurl->sip_uri_user.sip_str_ptr = scan;
	outurl->sip_uri_user.sip_str_len = uend - scan;

	if (sip_uri_parse_tel(scan, uend)) {
		outurl->sip_uri_isteluser = B_TRUE;
	} else {
		while (scan < uend && (SIP_URI_ISUNRESERVED(*scan) ||
		    SIP_URI_ISURLESCAPE(scan, uend) || SIP_URI_ISUSER(*scan))) {
			++scan;
		}
		if (scan < uend)
			outurl->sip_uri_errflags |= SIP_URIERR_USER;
	}
}

/*
 * the format of port is supposed to be :XXX
 * port =  1*DIGIT
 */
static void
sip_uri_parse_port(_sip_uri_t *outurl, char *scan, char *uend)
{
	if (scan == uend || *scan != ':' || scan + 1 == uend) {
		outurl->sip_uri_errflags |= SIP_URIERR_PORT;
		return;
	}
	++scan;
	/*
	 * parse numeric port number
	 */
	if (SIP_URI_ISDIGIT(*scan)) {
		outurl->sip_uri_port = *scan - '0';
		while (++scan < uend && SIP_URI_ISDIGIT(*scan)) {
		    outurl->sip_uri_port =
			outurl->sip_uri_port * 10 + (*scan - '0');
			if (outurl->sip_uri_port > 0xffff) {
				outurl->sip_uri_errflags |= SIP_URIERR_PORT;
				outurl->sip_uri_port = 0;
				break;
			}
		}
	}
	if (scan < uend) {
		outurl->sip_uri_errflags |= SIP_URIERR_PORT;
		outurl->sip_uri_port = 0;
	}
}

/*
 * parse an IPv4 address
 *    1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT
 *  advances pscan to end of IPv4 address, or after last "." that was
 *  a valid IPv4 or domain name.
 * returns 1 if ipv4 found, 0 otherwise
 */
static int
sip_uri_parse_ipv4(char *scan, char *uend)
{
	int	j = 0;
	int	val = 0;

	for (j = 0; j < 4; ++j) {
		if (!SIP_URI_ISDIGIT(*scan))
			break;
		val = *scan - '0';
		while (++scan < uend && SIP_URI_ISDIGIT(*scan)) {
			val = val * 10 + (*scan - '0');
			if (val > 255)
				return (0);
		}
		if (j < 3) {
			if (*scan != '.')
				break;
			++scan;
		}
	}

	if (j == 4 && scan == uend)
		return (1);

	return (0);
}

/*
 * parse an IPv6 address
 *  IPv6address = hexpart [ ":" IPv4address ]
 *  IPv4address = 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT
 *  hexpart = hexseq | hexseq "::" [ hexseq ] | "::" [ hexseq ]
 *  hexseq  = hex4 *( ":" hex4)
 *  hex4    = 1*4HEXDIG
 *  if not found, leaves pscan unchanged, otherwise advances to end
 *  returns 1 if valid,
 *  0 if invalid
 */
static int
sip_uri_parse_ipv6(char *scan, char *uend)
{
	char		*mark;
	unsigned	j = 0;			/* index for addr */
	unsigned	val = 0;		/* hex value */
	int		zpad = 0;		/* index of :: delimiter */

	if (*scan != '[')
		return (0);
	++scan;
	j = 0;

	/*
	 * check for leading "::", set zpad to the position of the "::"
	 */
	if (scan + 1 < uend && scan[0] == ':' && scan[1] == ':') {
		zpad = 0;
		scan += 2;
	} else {
		zpad = -1;
	}

	/*
	 * loop through up to 16 bytes of IPv6 address
	 */
	while (scan < uend && j < 15) {
		if (!SIP_URI_ISHEX(*scan))
			break;
		mark = scan;
		val = SIP_URI_HEXVAL(*scan);
		while (++scan < uend && SIP_URI_ISHEX(*scan)) {
			val = val * 16 + SIP_URI_HEXVAL(*scan);
			if (val > 0xffff)
				return (0);
		}

		/*
		 * always require a delimiter or ]
		 */
		if (scan == uend)
			return (0);

		if (*scan == '.' && (j == 12 || (zpad != -1 && j < 12)) &&
		    mark < uend && sip_uri_parse_ipv4(mark, uend - 1) &&
		    *(uend - 1) == ']') {
			mark = uend - 1;
			j += 4;
			scan = mark + 1;
			break;
		}

		/*
		 * set address
		 */
		j += 2;

		/*
		 * check for delimiter or ]
		 */
		if (*scan == ':') {
			/*
			 * found ":" delimiter, check for "::"
			 */
			if (++scan < uend && *scan == ':') {
				if (zpad != -1)
					return (0);
				zpad = j;
				if (++scan < uend && *scan == ']') {
					++scan;
					break;
				}
			}
		} else if (*scan == ']' && (j == 16 || zpad != -1)) {
			++scan;
			break;
		} else {
			/*
			 * not a valid delimiter
			 */
			return (0);
		}
	}
	if (zpad == -1 && j < 16)
		return (0);
	if (zpad != -1) {
		if (j > 15)
			return (0);
	}

	if (scan == uend)
		return (1);

	return (0);
}

/*
 * hostname         =  *( domainlabel "." ) toplabel [ "." ]
 * domainlabel      =  alphanum / alphanum *( alphanum / "-" ) alphanum
 * toplabel         =  ALPHA / ALPHA *( alphanum / "-" ) alphanum
 */
static int
sip_uri_parse_hostname(char *scan, char *uend)
{
	int	sawalpha = 0;

	if (scan < uend && SIP_URI_ISALNUM(*scan)) {
		do {
			sawalpha = SIP_URI_ISALPHA(*scan);
			while (SIP_URI_ISHOST(*scan))
				++scan;
			if (*scan != '.')
				break;
			++scan;
		} while (scan < uend && SIP_URI_ISALNUM(*scan));
	}

	if (sawalpha && scan == uend)
		return (1);
	return (0);
}


/*
 * parse the network path portion of a full URL
 */
static void
sip_uri_parse_netpath(_sip_uri_t *outurl, char **pscan, char *uend,
    boolean_t issip)
{
	char	*mark = (char *)0;
	char	*mark2 = (char *)0;
	char	*scan = *pscan;
	int	gothost = 0;

	/*
	 * look for the first high-level delimiter
	 */
	mark = scan;
	while (scan < uend && *scan != '@')
		++scan;
	/*
	 * handle userinfo section of URL
	 */
	if (scan < uend && *scan == '@') {
		/*
		 * parse user
		 */
		mark2 = mark;
		while (mark < scan && *mark != ':')
			++mark;
		sip_uri_parse_user(outurl, mark2, mark);
		/*
		 * parse password
		 */
		if (*mark == ':')
			sip_uri_parse_password(outurl, mark, scan);
		mark = ++scan;
	}

	scan = mark;
	if (scan < uend && *scan == '[') {	/* look for an IPv6 address */
		while (scan < uend && *scan != ']')
			++scan;
		if (scan < uend) {
			++scan;
			if (sip_uri_parse_ipv6(mark, scan))
				gothost = 1;
		}
	} else {
		while (scan < uend && ((issip && !SIP_URI_ISSIPHDELIM(*scan)) ||
		    (!issip && !SIP_URI_ISABSHDELIM(*scan)))) {
			++scan;
		}

		/*
		 * look for an IPv4 address
		 */
		if (mark < scan && SIP_URI_ISDIGIT(*mark) &&
		    sip_uri_parse_ipv4(mark, scan)) {
			gothost = 1;
		}

		/*
		 * look for a valid host name
		 */
		if (!gothost && mark < scan &&
		    sip_uri_parse_hostname(mark, scan)) {
			gothost = 1;
		}
	}
	/*
	 * handle invalid host name
	 */
	if (!gothost)
		outurl->sip_uri_errflags |= SIP_URIERR_HOST;
	/*
	 * save host name
	 */
	outurl->sip_uri_host.sip_str_ptr = mark;
	outurl->sip_uri_host.sip_str_len = scan - mark;

	mark = scan;
	/*
	 * parse the port number
	 */
	if (scan < uend && *scan == ':') {
		while (scan < uend && ((issip && !SIP_URI_ISSIPDELIM(*scan)) ||
		    (!issip && !SIP_URI_ISABSDELIM(*scan)))) {
			++scan;
		}
		sip_uri_parse_port(outurl, mark, scan);
	}

	/*
	 * set return pointer
	 */
	*pscan = scan;
}

/*
 * parse a URL
 * URL = SIP-URI / SIPS-URI / absoluteURI
 */
void
sip_uri_parse_it(_sip_uri_t *outurl, sip_str_t *uri_str)
{
	char 		*mark;
	char		*scan;
	char		*uend;
	char		*str = uri_str->sip_str_ptr;
	unsigned	urlen = uri_str->sip_str_len;

	/*
	 * reset output parameters
	 */
	(void) memset(outurl, 0, sizeof (sip_uri_t));

	/*
	 * strip enclosing angle brackets
	 */
	if (urlen > 1 && str[0] == '<' && str[urlen-1] == '>') {
		urlen -= 2;
		++str;
	}
	uend = str + urlen;

	/*
	 * strip off space prefix and trailing spaces
	 */
	while (str < uend && isspace(*str)) {
		++str;
		--urlen;
	}
	while (str < uend && isspace(*(uend - 1))) {
		--uend;
		--urlen;
	}

	/*
	 * strip off "URL:" prefix
	 */
	if (urlen > 4 && sip_uri_url_casecmp(str, "URL:", 4) == 0) {
		str += 4;
		urlen -= 4;
	}

	/*
	 * parse the scheme name
	 */
	mark = scan = str;
	while (scan < uend && *scan != ':')
		++scan;
	if (scan == uend || !sip_uri_parse_scheme(outurl, mark, scan)) {
		outurl->sip_uri_errflags |= SIP_URIERR_SCHEME;
		return;
	}

	if ((outurl->sip_uri_scheme.sip_str_len == SIP_SCHEME_LEN &&
	    !memcmp(outurl->sip_uri_scheme.sip_str_ptr, SIP_SCHEME,
	    SIP_SCHEME_LEN)) ||
	    (outurl->sip_uri_scheme.sip_str_len == SIPS_SCHEME_LEN &&
	    !memcmp(outurl->sip_uri_scheme.sip_str_ptr, SIPS_SCHEME,
	    SIPS_SCHEME_LEN))) {
		outurl->sip_uri_issip = B_TRUE;
	} else {
		outurl->sip_uri_issip = B_FALSE;
	}
	++scan; /* skip ':' */

	if (outurl->sip_uri_issip) {
		/*
		 * parse SIP URL
		 */
		sip_uri_parse_netpath(outurl, &scan, uend, B_TRUE);

		/*
		 * parse parameters
		 */
		if (scan < uend && *scan == ';') {
			mark = scan;
			while (scan < uend && *scan != '?')
				++scan;
			sip_uri_parse_params(outurl, mark, scan);
		}

		/*
		 * parse headers
		 */
		if (scan < uend && *scan == '?')
			sip_uri_parse_headers(outurl, scan, uend);
	} else if (scan < uend && scan[0] == '/') {	 /* parse absoluteURL */
		++scan;
		/*
		 * parse authority
		 * authority	= srvr / reg-name
		 * srvr		= [ [ userinfo "@" ] hostport ]
		 * reg-name	= 1*(unreserved / escaped / "$" / ","
		 *			/ ";" / ":" / "@" / "&" / "=" / "+")
		 */
		if (scan < uend && *scan == '/') {
			++scan;
			mark = scan;
			/*
			 * take authority as srvr
			 */
			sip_uri_parse_netpath(outurl, &scan, uend, B_FALSE);

			/*
			 * if srvr failed, take it as reg-name
			 * parse reg-name
			 */
			if (outurl->sip_uri_errflags & SIP_URIERR_USER ||
			    outurl->sip_uri_errflags & SIP_URIERR_PASS ||
			    outurl->sip_uri_errflags & SIP_URIERR_HOST ||
			    outurl->sip_uri_errflags & SIP_URIERR_PORT) {
				scan = mark;
				while (scan < uend && *scan != '/' &&
					*scan != '?') {
					++scan;
				}
				sip_uri_parse_abs_regname(outurl, mark, scan);
				if (!(outurl->sip_uri_errflags &
				    SIP_URIERR_REGNAME)) {
					/*
					 * remove error info of user,
					 * password, host, port
					 */
					outurl->sip_uri_user.sip_str_ptr = NULL;
					outurl->sip_uri_user.sip_str_len = 0;
					outurl->sip_uri_errflags &=
					    ~SIP_URIERR_USER;
					outurl->sip_uri_password.sip_str_ptr =
					    NULL;
					outurl->sip_uri_password.sip_str_len =
					    0;
					outurl->sip_uri_errflags &=
					    ~SIP_URIERR_PASS;
					outurl->sip_uri_host.sip_str_ptr = NULL;
					outurl->sip_uri_host.sip_str_len = 0;
					outurl->sip_uri_errflags &=
					    ~SIP_URIERR_HOST;
					outurl->sip_uri_port = 0;
					outurl->sip_uri_errflags &=
					    ~SIP_URIERR_PORT;
				}
			}
		} else {
			/*
			 * there is no net-path
			 */
			--scan;
		}
		/*
		 * parse abs-path
		 */
		if (scan < uend && *scan == '/') {
			mark = scan;
			while (scan < uend && *scan != '?')
				++scan;
			sip_uri_parse_abs_path(outurl, mark, scan);
		}

		/*
		 * parse query
		 */
		if (scan < uend && *scan == '?')
			sip_uri_parse_abs_query(outurl, scan, uend);
	} else {
		/*
		 * parse opaque-part
		 */
		sip_uri_parse_abs_opaque(outurl, scan, uend);
	}
}
