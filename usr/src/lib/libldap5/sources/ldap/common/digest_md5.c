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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1998-1999 Innosoft International, Inc.  All Rights Reserved.
 *
 * Copyright (c) 1996-1997 Critical Angle Inc. All Rights Reserved.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <md5.h>
#include <sys/time.h>

#include "lber.h"
#include "ldap.h"
#include "ldap-int.h"

/*
 * DIGEST-MD5 SASL Mechanism
 */

/* use this instead of "const unsigned char" to eliminate compiler warnings */
typedef /* const */ unsigned char CONST_UCHAR;

/* size of a digest result */
#define	DIGEST_SIZE	 16

/* size of a digest hex string */
#define	DIGEST_HEX_SIZE (DIGEST_SIZE * 2 + 1)

/*
 * extra bytes which a client response needs in addition to size of
 * server challenge */
#define	DIGEST_CLIENT_EXTRA (DIGEST_HEX_SIZE + 128)

/* erase a digest_attrs_t structure */
#define	digest_clear(attrs) memset((attrs), 0, sizeof (digest_attrs_t))

/*
 * broken-out digest attributes (with quotes removed)
 *  probably not NUL terminated.
 */
typedef struct {
	const char *realm, *nonce, *cnonce, *qop, *user, *resp, *dom;
	const char *max, *stale, *ncount, *uri, *charset;
	int rlen, nlen, clen, qlen, ulen, resplen, dlen;
	int mlen, slen, nclen, urilen, charsetlen;
	char ncbuf[9];
} digest_attrs_t;

static const char hextab[] = "0123456789abcdef";
static CONST_UCHAR colon[] = ":";

/*
 * Make a nonce (NUL terminated)
 *  buf	-- buffer for result
 *  maxlen -- max length of result
 * returns final length or -1 on error
 */
static int
digest_nonce(char *buf, int maxlen)
{
	/*
	 * it shouldn't matter too much if two threads step on this counter
	 * at the same time, but mutexing it wouldn't hurt
	 */
	static int counter;
	char *dst;
	int len;
	struct chal_info {
		time_t mytime;
		unsigned char digest[16];
	} cinfo;
	MD5_CTX ctx;
	long r;
	static int set_rand = 0;
	unsigned char *p;
	int j;
	int fd;
	int got_random;

	/* initialize challenge */
	if (maxlen < 2 * sizeof (cinfo))
		return (-1);
	dst = buf;

	/* get a timestamp */
	time(&cinfo.mytime);

	/* get some randomness */

	got_random = 0;
	fd = open("/dev/urandom", O_RDONLY);
	if (fd != -1) {
	    got_random =
		(read(fd, &r, sizeof (r)) == sizeof (r));
	    close(fd);
	}

	if (!got_random) {
	    if (set_rand == 0) {
		struct timeval tv;

		r = cinfo.mytime - (getpid() *65536) + (random() & 0xffff);

		gettimeofday(&tv, NULL);
		r ^= tv.tv_usec;
		r ^= gethostid();

		srandom(r);
		set_rand = 1;
	    }

	    r = random();
	}

	MD5Init(&ctx);
	MD5Update(&ctx, (unsigned char *) &r, sizeof (r));
	MD5Update(&ctx, (unsigned char *) &counter, sizeof (counter));
	++counter;
	MD5Final(cinfo.digest, &ctx);

	/* compute hex for result */
	for (j = 0, p = (unsigned char *)&cinfo; j < sizeof (cinfo); ++j) {
		dst[j * 2]	= hextab[p[j] >> 4];
		dst[j * 2 + 1]	= hextab[p[j] & 0xf];
	}

	/* take the entire time_t, plus at least 6 bytes of MD5 output */
	len = ((sizeof (time_t) + 6) * 2);
	dst += len;
	maxlen -= len;

	*dst = '\0';

	return (dst - buf);
}

/*
 * if the string is entirely in the 8859-1 subset of UTF-8, then translate
 * to 8859-1 prior to MD5
 */
static void
MD5_UTF8_8859_1(MD5_CTX *ctx, CONST_UCHAR *base, int len)
{
	CONST_UCHAR *scan, *end;
	unsigned char cbuf;

	end = base + len;
	for (scan = base; scan < end; ++scan) {
		if (*scan > 0xC3) break; /* abort if outside 8859-1 */
		if (*scan >= 0xC0 && *scan <= 0xC3) {
		    if (++scan == end || *scan < 0x80 || *scan > 0xBF) break;
		}
	}
	/* if we found a character outside 8859-1, don't alter string */
	if (scan < end) {
		MD5Update(ctx, base, len);
		return;
	}

	/* convert to 8859-1 prior to applying hash */
	do {
		for (scan = base; scan < end && *scan < 0xC0; ++scan)
			;
		if (scan != base) MD5Update(ctx, base, scan - base);
		if (scan + 1 >= end) break;
		cbuf = ((scan[0] & 0x3) << 6) | (scan[1] & 0x3f);
		MD5Update(ctx, &cbuf, 1);
		base = scan + 2;
	} while (base < end);
}

/*
 * Compute MD5( "<user>:<realm>:<pass>" )
 *  if use8859_1 is non-zero, then user/realm is 8859-1 charset
 *  if supplied lengths are 0, strlen() is used
 *  places result in hash_pass (of size DIGEST_SIZE) and returns it.
 */
static unsigned char *
digest_hash_pass(const char *user, int ulen, const char *realm, int rlen,
		const char *pass, int passlen, int use8859_1,
		unsigned char *hash_pass)
{
	MD5_CTX ctx;

	MD5Init(&ctx);
	if (ulen == 0) ulen = strlen(user);
	if (use8859_1) {
		MD5Update(&ctx, (CONST_UCHAR *) user, ulen);
	} else {
		MD5_UTF8_8859_1(&ctx, (CONST_UCHAR *) user, ulen);
	}
	MD5Update(&ctx, colon, 1);
	if (rlen == 0) rlen = strlen(realm);
	if (use8859_1) {
		MD5Update(&ctx, (CONST_UCHAR *) realm, rlen);
	} else {
		MD5_UTF8_8859_1(&ctx, (CONST_UCHAR *) realm, rlen);
	}
	MD5Update(&ctx, colon, 1);
	if (passlen == 0) passlen = strlen(pass);
	MD5Update(&ctx, (CONST_UCHAR *) pass, passlen);
	MD5Final(hash_pass, &ctx);

	return (hash_pass);
}

/*
 * Compute MD5("<hash_pass>:<nonce>:<cnonce>")
 * places result in hash_a1 and returns hash_a1
 * note that hash_pass and hash_a1 may be the same
 */
static unsigned char *
digest_hash_a1(const digest_attrs_t *attr, CONST_UCHAR *hash_pass,
		unsigned char *hash_a1)
{
	MD5_CTX ctx;

	MD5Init(&ctx);
	MD5Update(&ctx, hash_pass, DIGEST_SIZE);
	MD5Update(&ctx, colon, 1);
	MD5Update(&ctx, (CONST_UCHAR *) attr->nonce, attr->nlen);
	MD5Update(&ctx, colon, 1);
	MD5Update(&ctx, (CONST_UCHAR *) attr->cnonce, attr->clen);
	MD5Final(hash_a1, &ctx);

	return (hash_a1);
}

/*
 * calculate hash response for digest auth.
 *  outresp must be buffer of at least DIGEST_HEX_SIZE
 *  outresp and hex_int may be the same
 *  method may be NULL if mlen is 0
 */
static void
digest_calc_resp(const digest_attrs_t *attr,
		CONST_UCHAR *hash_a1, const char *method, int mlen,
		CONST_UCHAR *hex_int, char *outresp)
{
	static CONST_UCHAR defncount[] = ":00000001:";
	static CONST_UCHAR empty_hex_int[] =
			"00000000000000000000000000000000";
	MD5_CTX ctx;
	unsigned char resp[DIGEST_SIZE];
	unsigned char *hex_a1 = (unsigned char *) outresp;
	unsigned char *hex_a2 = (unsigned char *) outresp;
	unsigned j;

	/* compute hash of A2 and put in resp */
	MD5Init(&ctx);
	if (mlen == 0 && method != NULL) mlen = strlen(method);
	if (mlen) MD5Update(&ctx, (CONST_UCHAR *) method, mlen);
	MD5Update(&ctx, colon, 1);
	if (attr->urilen != 0) {
		MD5Update(&ctx, (CONST_UCHAR *) attr->uri, attr->urilen);
	}
	if (attr->qlen != 4 || strncasecmp(attr->qop, "auth", 4) != 0) {
		MD5Update(&ctx, colon, 1);
	if (hex_int == NULL) hex_int = empty_hex_int;
		MD5Update(&ctx, hex_int, DIGEST_SIZE * 2);
	}
	MD5Final(resp, &ctx);

	/* compute hex_a1 from hash_a1 */
	for (j = 0; j < DIGEST_SIZE; ++j) {
		hex_a1[j * 2]	 = hextab[hash_a1[j] >> 4];
		hex_a1[j * 2 + 1] = hextab[hash_a1[j] & 0xf];
	}

	/* compute response */
	MD5Init(&ctx);
	MD5Update(&ctx, hex_a1, DIGEST_SIZE * 2);
	MD5Update(&ctx, colon, 1);
	MD5Update(&ctx, (CONST_UCHAR *) attr->nonce, attr->nlen);
	if (attr->ncount != NULL) {
		MD5Update(&ctx, colon, 1);
		MD5Update(&ctx, (CONST_UCHAR *) attr->ncount, attr->nclen);
		MD5Update(&ctx, colon, 1);
	} else {
		MD5Update(&ctx, defncount, sizeof (defncount) - 1);
	}
	MD5Update(&ctx, (CONST_UCHAR *) attr->cnonce, attr->clen);
	MD5Update(&ctx, colon, 1);
	MD5Update(&ctx, (CONST_UCHAR *) attr->qop, attr->qlen);
	MD5Update(&ctx, colon, 1);

	/* compute hex_a2 from hash_a2 */
	for (j = 0; j < DIGEST_SIZE; ++j) {
		hex_a2[j * 2]	 = hextab[resp[j] >> 4];
		hex_a2[j * 2 + 1] = hextab[resp[j] & 0xf];
	}
	MD5Update(&ctx, hex_a2, DIGEST_SIZE * 2);
	MD5Final(resp, &ctx);

	/* generate hex output */
	for (j = 0; j < DIGEST_SIZE; ++j) {
		outresp[j * 2]	 = hextab[resp[j] >> 4];
		outresp[j * 2 + 1] = hextab[resp[j] & 0xf];
	}
	outresp[DIGEST_SIZE * 2] = '\0';
	memset(resp, 0, sizeof (resp));
}

/*
 * generate the client response from attributes
 *  either one of hash_pass and hash_a1 may be NULL
 *  hash_a1 is used on re-authentication and takes precedence over hash_pass
 */
static int
digest_client_resp(const char *method, int mlen,
		CONST_UCHAR *hash_pass, CONST_UCHAR *hash_a1,
		digest_attrs_t *attr, /* in/out attributes */
		char *outbuf, int maxout, int *plen)
{
#define	prefixsize (sizeof (prefix) - 4 * 4 - 1)
#define	suffixsize (sizeof (rstr) + sizeof (qstr) - 1 + DIGEST_SIZE * 2)
	static const char prefix[] =
	"username=\"%.*s\",realm=\"%.*s\",nonce=\"%.*s\",nc=%.*s,cnonce=\"";
	static const char rstr[] = "\",response=";
	static const char qstr[] = ",qop=auth";
	static const char chstr[] = "charset=";
	char *scan;
	int len;
	char hexbuf[DIGEST_HEX_SIZE];
	unsigned char hashbuf[DIGEST_SIZE];

	/* make sure we have mandatory attributes */
	if (attr->nonce == NULL || attr->nlen == 0 ||
	    attr->realm == NULL || attr->rlen == 0 ||
	    attr->qop == NULL || attr->qlen == 0 ||
	    (attr->nclen != 0 && attr->nclen != 8)) {
		return (-5);
	}
	if (mlen != 0 && method == NULL)
		return (-7);

	/* initialize ncount */
	if (attr->ncount == NULL) {
		strcpy(attr->ncbuf, "00000001");
		attr->ncount = attr->ncbuf;
		attr->nclen = 8;
	} else if (attr->ncount == attr->ncbuf) {
		/* increment ncount */
		scan = attr->ncbuf + 7;
		while (scan >= attr->ncbuf) {
			if (*scan == '9') {
				*scan = 'a';
				break;
			} else if (*scan != 'f') {
				++*scan;
				break;
			}
			*scan = '0';
			--scan;
		}
	}

	/* sanity check length */
	len = prefixsize + attr->ulen + attr->rlen + attr->nlen + attr->nclen;
	if (attr->charsetlen > 0) {
		/* includes 1 for a comma */
		len += sizeof (chstr) + attr->charsetlen;
	}
	if (len + suffixsize >= maxout)
		return (-3);

	scan = outbuf;

	/* charset */
	if (attr->charsetlen > 0 && attr->charset != NULL) {
		memcpy(scan, chstr, sizeof (chstr) - 1);
		scan += sizeof (chstr) - 1;
		memcpy(scan, attr->charset, attr->charsetlen);
		scan += attr->charsetlen;
		*scan++ = ',';
	}

	/* generate string up to the client nonce */
	sprintf(scan, prefix, attr->ulen, attr->user,
		attr->rlen, attr->realm, attr->nlen, attr->nonce,
		attr->nclen, attr->ncount);
	scan = outbuf + len;

	/* generate client nonce */
	len = digest_nonce(scan, maxout - (scan - outbuf));
	if (len < 0)
		return (len);
	attr->cnonce = scan;
	attr->clen = len;
	scan += len;
	if (scan - outbuf + suffixsize > maxout)
		return (-3);

	/* compute response */
	if (hash_a1 == NULL) {
		if (hash_pass == NULL)
			return (-7);
		hash_a1 = digest_hash_a1(attr, hash_pass, hashbuf);
	}
	digest_calc_resp(attr, hash_a1, method, mlen, NULL, hexbuf);

	/* finish it */
	memcpy(scan, rstr, sizeof (rstr) - 1);
	scan += sizeof (rstr) - 1;
	memcpy(scan, hexbuf, DIGEST_SIZE * 2);
	attr->resp = scan;
	attr->resplen = DIGEST_SIZE * 2;
	scan += DIGEST_SIZE * 2;
	memcpy(scan, qstr, sizeof (qstr));

	/* set final length */
	if (plen != NULL) *plen = scan - outbuf + sizeof (qstr) - 1;

	return (0);
}

#define	lstreqcase(conststr, val, len) ((len) == sizeof (conststr) - 1 && \
		strncasecmp((conststr), (val), sizeof (conststr) - 1) == 0)

/* parse a digest auth string */
static int
digest_parse(const char *str, int len, digest_attrs_t *attr_out)
{
	static const char rstr[] = "realm";
	static const char nstr[] = "nonce";
	static const char cstr[] = "cnonce";
	static const char qstr[] = "qop";
	static const char ustr[] = "username";
	static const char respstr[] = "response";
	static const char dstr[] = "domain";
	static const char mstr[] = "maxbuf";
	static const char sstr[] = "stale";
	static const char ncstr[] = "nc";
	static const char uristr[] = "digest-uri";
	static const char charsetstr[] = "charset";
	const char *scan, *attr, *val, *end;
	int alen, vlen;

	if (len == 0) len = strlen(str);
	scan = str;
	end = str + len;
	for (;;) {
		/* skip over commas */
		while (scan < end && (*scan == ',' || isspace(*scan))) ++scan;
		/* parse attribute */
		attr = scan;
		while (scan < end && *scan != '=') ++scan;
		alen = scan - attr;
		if (!alen || scan == end || scan + 1 == end) {
			return (-5);
		}

		/* parse value */
		if (scan[1] == '"') {
			scan += 2;
			val = scan;
			while (scan < end && *scan != '"') {
				/* skip over "\" quoting, but don't remove it */
				if (*scan == '\\') {
					if (scan + 1 == end)
						return (-5);
					scan += 2;
				} else {
					++scan;
				}
			}
			vlen = scan - val;
			if (*scan != '"')
				return (-5);
			++scan;
		} else {
			++scan;
			val = scan;
			while (scan < end && *scan != ',') ++scan;
			vlen = scan - val;
		}
		if (!vlen)
			return (-5);

		/* lookup the attribute */
		switch (*attr) {
		    case 'c':
		    case 'C':
			if (lstreqcase(cstr, attr, alen)) {
				attr_out->cnonce = val;
				attr_out->clen = vlen;
			}
			if (lstreqcase(charsetstr, attr, alen)) {
				attr_out->charset = val;
				attr_out->charsetlen = vlen;
			}
			break;
		    case 'd':
		    case 'D':
			if (lstreqcase(dstr, attr, alen)) {
				attr_out->dom = val;
				attr_out->dlen = vlen;
			}
			if (lstreqcase(uristr, attr, alen)) {
				attr_out->uri = val;
				attr_out->urilen = vlen;
			}
			break;
		    case 'm':
		    case 'M':
			if (lstreqcase(mstr, attr, alen)) {
				attr_out->max = val;
				attr_out->mlen = vlen;
			}
			break;
		    case 'n':
		    case 'N':
			if (lstreqcase(nstr, attr, alen)) {
				attr_out->nonce = val;
				attr_out->nlen = vlen;
			}
			if (lstreqcase(ncstr, attr, alen)) {
				attr_out->ncount = val;
				attr_out->nclen = vlen;
			}
			break;
		    case 'q':
		    case 'Q':
			if (lstreqcase(qstr, attr, alen)) {
				attr_out->qop = val;
				attr_out->qlen = vlen;
			}
			break;
		    case 'r':
		    case 'R':
			if (lstreqcase(rstr, attr, alen)) {
				attr_out->realm = val;
				attr_out->rlen = vlen;
			}
			if (lstreqcase(respstr, attr, alen)) {
				attr_out->resp = val;
				attr_out->resplen = vlen;
			}
			break;
		    case 's':
		    case 'S':
			if (lstreqcase(sstr, attr, alen)) {
				attr_out->stale = val;
				attr_out->slen = vlen;
			}
			break;
		    case 'u':
		    case 'U':
			if (lstreqcase(ustr, attr, alen)) {
				attr_out->user = val;
				attr_out->ulen = vlen;
			}
			break;
		}

		/* we should be at the end of the string or a comma */
		if (scan == end) break;
		if (*scan != ',')
			return (-5);
	}

	return (0);
}

static int ldap_digest_md5_encode(
	const char *challenge,
	const char *username,
	const char *passwd,
	char **digest
)
{
	unsigned char hash_pass[DIGEST_SIZE];
	digest_attrs_t attrs;
	char *outbuf;
	int outlen;
	int ret;

	/* validate args */
	if (challenge == NULL || username == NULL || passwd == NULL) {
		return (LDAP_PARAM_ERROR);
	}

	/* parse the challenge */
	digest_clear(&attrs);
	ret = digest_parse(challenge, 0, &attrs);
	if (ret != 0)
		return (LDAP_DECODING_ERROR);

	/* server MUST specify support for charset=utf-8 */
	if (attrs.charsetlen != 5 ||
	    strncasecmp(attrs.charset, "utf-8", 5) != 0) {
		LDAPDebug(LDAP_DEBUG_TRACE,
			"server did not specify charset=utf-8\n",
			0, 0, 0);
		return (LDAP_NOT_SUPPORTED);
	}

	/* set up digest attributes */
	attrs.user = username;
	attrs.ulen = strlen(attrs.user);

	/* allocate the output buffer */
	outlen = strlen(challenge) + DIGEST_CLIENT_EXTRA + 1;
	outbuf = (char *)malloc(outlen);
	if (outbuf == NULL)
		return (LDAP_NO_MEMORY);

	/* hash the password */
	digest_hash_pass(username, 0, attrs.realm, attrs.rlen,
				passwd, 0, 0, hash_pass),

	/* create the response */
	ret = digest_client_resp("AUTHENTICATE", 12, hash_pass, NULL,
			&attrs, outbuf, outlen, &outlen);
	memset(hash_pass, 0, DIGEST_SIZE);
	if (ret != 0) {
		free(outbuf);
		return (LDAP_DECODING_ERROR);
	}

	/* null terminate the response */
	*(outbuf+outlen) = '\0';

	*digest = outbuf;
	return (LDAP_SUCCESS);
}

int ldap_x_sasl_digest_md5_bind_s(
	LDAP *ld,
	char *user_name,
	struct berval *cred,
	LDAPControl **serverctrls,
	LDAPControl **clientctrls)
{
	struct berval	*challenge = NULL;
	int		errnum;
	char		*digest = NULL;
	struct berval	resp;

	LDAPDebug(LDAP_DEBUG_TRACE, "ldap_x_sasl_digest_md5_bind_s\n", 0, 0, 0);

	/* Add debug */
	if (ld == NULL || user_name == NULL || cred == NULL ||
	    cred->bv_val == NULL)
		return (LDAP_PARAM_ERROR);

	if (ld->ld_version < LDAP_VERSION3)
		return (LDAP_PARAM_ERROR);

	errnum = ldap_sasl_bind_s(ld, NULL, LDAP_SASL_DIGEST_MD5,
		NULL, serverctrls, clientctrls, &challenge);

	if (errnum == LDAP_SASL_BIND_IN_PROGRESS) {
		if (challenge != NULL) {
			LDAPDebug(LDAP_DEBUG_TRACE,
				"SASL challenge: %s\n",
				challenge->bv_val, 0, 0);
			errnum = ldap_digest_md5_encode(challenge->bv_val,
				user_name, cred->bv_val, &digest);
			ber_bvfree(challenge);
			challenge = NULL;
			if (errnum == LDAP_SUCCESS) {
				resp.bv_val = digest;
				resp.bv_len = strlen(digest);
				LDAPDebug(LDAP_DEBUG_TRACE,
					"SASL reply: %s\n",
					digest, 0, 0);
				errnum = ldap_sasl_bind_s(ld, NULL,
					LDAP_SASL_DIGEST_MD5, &resp,
					serverctrls, clientctrls, &challenge);
				free(digest);
			}
			if (challenge != NULL)
				ber_bvfree(challenge);
		} else {
			errnum = LDAP_NO_MEMORY; /* TO DO: What val? */
		}
	}

	LDAP_MUTEX_LOCK(ld, LDAP_ERR_LOCK);
	ld->ld_errno = errnum;
	LDAP_MUTEX_UNLOCK(ld, LDAP_ERR_LOCK);
	return (errnum);
}

static int
sasl_digest_md5_bind_1(
	LDAP *ld,
	char *user_name,
	LDAPControl **serverctrls,
	LDAPControl **clientctrls,
	int *msgidp)
{
	if (ld == NULL || user_name == NULL || msgidp == NULL)
		return (LDAP_PARAM_ERROR);

	if (ld->ld_version < LDAP_VERSION3)
		return (LDAP_PARAM_ERROR);

	return (ldap_sasl_bind(ld, NULL, LDAP_SASL_DIGEST_MD5,
		NULL, serverctrls, clientctrls, msgidp));
}

static int
sasl_digest_md5_bind_2(
	LDAP *ld,
	char *user_name,
	struct berval *cred,
	LDAPControl **serverctrls,
	LDAPControl **clientctrls,
	LDAPMessage *result,
	int *msgidp)
{
	struct berval	*challenge = NULL;
	struct berval	resp;
	int		errnum;
	char		*digest = NULL;
	int		err;

	if (ld == NULL || user_name == NULL || cred == NULL ||
	    cred->bv_val == NULL || result == NULL || msgidp == NULL)
		return (LDAP_PARAM_ERROR);

	if (ld->ld_version < LDAP_VERSION3)
		return (LDAP_PARAM_ERROR);

	err = ldap_result2error(ld, result, 0);
	if (err != LDAP_SASL_BIND_IN_PROGRESS)
		return (err);

	if ((err = ldap_parse_sasl_bind_result(ld, result, &challenge, 0))
			!= LDAP_SUCCESS)
		return (err);
	if (challenge == NULL)
		return (LDAP_NO_MEMORY);

	err = ldap_digest_md5_encode(challenge->bv_val,
			user_name, cred->bv_val, &digest);
	ber_bvfree(challenge);

	if (err == LDAP_SUCCESS) {
		resp.bv_val = digest;
		resp.bv_len = strlen(digest);
		LDAPDebug(LDAP_DEBUG_TRACE, "SASL reply: %s\n",
			digest, 0, 0);
		err = ldap_sasl_bind(ld, NULL, LDAP_SASL_DIGEST_MD5,
			&resp, serverctrls, clientctrls, msgidp);
		free(digest);
	}
	return (err);
}

int ldap_x_sasl_digest_md5_bind(
	LDAP *ld,
	char *user_name,
	struct berval *cred,
	LDAPControl **serverctrls,
	LDAPControl **clientctrls,
	struct timeval *timeout,
	LDAPMessage **result)
{
	LDAPMessage	*res = NULL;
	int		msgid;
	int		rc;

	if (ld == NULL || user_name == NULL || cred == NULL ||
		result == NULL)
		return (LDAP_PARAM_ERROR);

	if (ld->ld_version < LDAP_VERSION3)
		return (LDAP_PARAM_ERROR);

	*result = NULL;

	rc = sasl_digest_md5_bind_1(ld, user_name,
		serverctrls, clientctrls, &msgid);
	if (rc != LDAP_SUCCESS)
		return (rc);

	rc = ldap_result(ld, msgid, 1, timeout, &res);
	if (rc == -1) {
		if (res != NULL)
			ldap_msgfree(res);
		return (ldap_get_lderrno(ld, NULL, NULL));
	}
	rc = ldap_result2error(ld, res, 0);
	if (rc != LDAP_SASL_BIND_IN_PROGRESS) {
		*result = res;
		return (rc);
	}

	rc = sasl_digest_md5_bind_2(ld, user_name, cred,
		serverctrls, clientctrls, res, &msgid);
	ldap_msgfree(res);
	res = NULL;

	if (rc != LDAP_SUCCESS)
		return (rc);

	rc = ldap_result(ld, msgid, 1, timeout, &res);
	if (rc == -1) {
		if (res != NULL)
			ldap_msgfree(res);
		return (ldap_get_lderrno(ld, NULL, NULL));
	}
	*result = res;
	rc = ldap_result2error(ld, res, 0);
	return (rc);
}
