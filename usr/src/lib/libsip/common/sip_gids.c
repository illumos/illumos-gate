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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sip.h>
#ifdef	__linux__
#include <sasl/sasl.h>
#include <sasl/saslplug.h>
#else
#include <sys/md5.h>
#endif

#include "sip_miscdefs.h"
#include "sip_msg.h"

void	sip_md5_hash(char *, int, char *, int, char *, int,  char *, int,
	    char *, int, char *, int, uchar_t *);

#define	SIP_RANDOM_LEN	20

/*
 * Wrapper around /dev/urandom
 */
static int
sip_get_random(char *buf, int buflen)
{
	static int devrandom = -1;

	if (devrandom == -1 &&
	    (devrandom = open("/dev/urandom", O_RDONLY)) == -1) {
		return (-1);
	}

	if (read(devrandom, buf, buflen) == -1)
		return (-1);
	return (0);
}

/*
 * Get MD5 hash of call_id, from_tag, to_tag using key
 */
void
sip_md5_hash(char *str1, int lstr1, char *str2, int lstr2, char *str3,
    int lstr3, char *str4, int lstr4, char *str5, int lstr5,
    char *str6, int lstr6, uchar_t *digest)
{
	MD5_CTX	ctx;

#ifdef	__linux__
	_sasl_MD5Init(&ctx);

	_sasl_MD5Update(&ctx, (uchar_t *)&sip_hash_salt, sizeof (uint64_t));

	if (str1 != NULL)
		_sasl_MD5Update(&ctx, (uchar_t *)str1, lstr1);

	if (str2 != NULL)
		_sasl_MD5Update(&ctx, (uchar_t *)str2, lstr2);

	if (str3 != NULL)
		_sasl_MD5Update(&ctx, (uchar_t *)str3, lstr3);

	if (str4 != NULL)
		_sasl_MD5Update(&ctx, (uchar_t *)str4, lstr4);

	if (str5 != NULL)
		_sasl_MD5Update(&ctx, (uchar_t *)str5, lstr5);

	if (str6 != NULL)
		_sasl_MD5Update(&ctx, (uchar_t *)str6, lstr6);

	_sasl_MD5Final(digest, &ctx);
#else	/* solaris */
	MD5Init(&ctx);

	MD5Update(&ctx, (uchar_t *)&sip_hash_salt, sizeof (uint64_t));

	if (str1 != NULL)
		MD5Update(&ctx, (uchar_t *)str1, lstr1);

	if (str2 != NULL)
		MD5Update(&ctx, (uchar_t *)str2, lstr2);

	if (str3 != NULL)
		MD5Update(&ctx, (uchar_t *)str3, lstr3);

	if (str4 != NULL)
		MD5Update(&ctx, (uchar_t *)str4, lstr4);

	if (str5 != NULL)
		MD5Update(&ctx, (uchar_t *)str5, lstr5);

	if (str6 != NULL)
		MD5Update(&ctx, (uchar_t *)str6, lstr6);

	MD5Final(digest, &ctx);
#endif
}

/*
 * generate a guid (globally unique id)
 */
char *
sip_guid()
{
	int		i;
	uint8_t		*r;
	uint32_t 	random;
	uint32_t	time;
	char		*guid;
	int		guidlen;
#ifdef	__linux__
	struct timespec	tspec;
#endif

	guid = (char *)malloc(SIP_RANDOM_LEN + 1);
	if (guid == NULL)
		return (NULL);
	/*
	 * Get a 32-bit random #
	 */
	if (sip_get_random((char *)&random, sizeof (random)) != 0)
		return (NULL);
#ifdef	__linux__
	if (clock_gettime(CLOCK_REALTIME, &tspec) != 0)
		return (NULL);
	time = (uint32_t)tspec.tv_nsec;
#else
	/*
	 * Get 32-bits from gethrtime()
	 */
	time = (uint32_t)gethrtime();
#endif
	(void) snprintf(guid, SIP_RANDOM_LEN + 1, "%u%u", random, time);
	guidlen = strlen(guid);

	/*
	 * just throw in some alphabets too
	 */
	r = (uint8_t *)malloc(guidlen);
	if (sip_get_random((char *)r, guidlen) != 0) {
		free(guid);
		return (NULL);
	}
	for (i = 0; i < guidlen; i++) {
		if ((r[i] >= 65 && r[i] <= 90) ||
		    (r[i] >= 97 && r[i] <= 122)) {
			guid[i] = r[i];
		}
	}
	free(r);
	return (guid);
}

/*
 * Generate  branchid for a transaction
 */
char *
sip_branchid(sip_msg_t sip_msg)
{
	char		*guid;
	char		*branchid;
	_sip_header_t	*via;
	unsigned char 	md5_hash[16];
	_sip_header_t	*to;
	_sip_header_t	*from;
	_sip_header_t	*callid;
	_sip_msg_t	*_sip_msg;
	int		cseq;
	MD5_CTX		ctx;
	size_t		len;
	int		hdrlen;
	int		i;

	if (sip_msg == NULL) {
generate_bid:
		if ((branchid = (char *)malloc(SIP_BRANCHID_LEN + 1)) == NULL)
			return (NULL);
		guid = sip_guid();
		if (guid == NULL) {
			free(branchid);
			return (NULL);
		}
		(void) snprintf(branchid, SIP_BRANCHID_LEN + 1, "z9hG4bK%s",
		    guid);
		free(guid);
		return (branchid);
	}
	_sip_msg = (_sip_msg_t *)sip_msg;
	(void) pthread_mutex_lock(&_sip_msg->sip_msg_mutex);
	via = sip_search_for_header(_sip_msg, SIP_VIA, NULL);
	if (via == NULL) {
		(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
		goto generate_bid;
	}
	to = sip_search_for_header(_sip_msg, SIP_TO, NULL);
	from = sip_search_for_header(_sip_msg, SIP_FROM, NULL);
	callid = sip_search_for_header(_sip_msg, SIP_CALL_ID, NULL);
	(void) pthread_mutex_unlock(&_sip_msg->sip_msg_mutex);
	cseq = sip_get_callseq_num(_sip_msg, NULL);
	if (to == NULL || from == NULL || callid == NULL || cseq == -1)
		return (NULL);
	if (_sip_msg->sip_msg_req_res == NULL ||
	    _sip_msg->sip_msg_req_res->U.sip_request.sip_request_uri.
	    sip_str_ptr == NULL) {
		return (NULL);
	}
	len = 2 * sizeof (md5_hash) + 1;
	if ((branchid = malloc(len)) == NULL)
		return (NULL);
#ifdef	__linux__
	_sasl_MD5Init(&ctx);
	hdrlen = via->sip_hdr_end - via->sip_hdr_start;
	_sasl_MD5Update(&ctx, (uchar_t *)via->sip_hdr_start, hdrlen);
	hdrlen = to->sip_hdr_end - to->sip_hdr_start;
	_sasl_MD5Update(&ctx, (uchar_t *)to->sip_hdr_start, hdrlen);
	hdrlen = from->sip_hdr_end - from->sip_hdr_start;
	_sasl_MD5Update(&ctx, (uchar_t *)from->sip_hdr_start, hdrlen);
	hdrlen = callid->sip_hdr_end - callid->sip_hdr_start;
	_sasl_MD5Update(&ctx, (uchar_t *)callid->sip_hdr_start, hdrlen);
	_sasl_MD5Update(&ctx, (uchar_t *)_sip_msg->sip_msg_req_res->
	    U.sip_request.sip_request_uri.sip_str_ptr,
	    _sip_msg->sip_msg_req_res->U.sip_request.
	    sip_request_uri.sip_str_len);
	_sasl_MD5Update(&ctx, (uchar_t *)&cseq, sizeof (int));
	_sasl_MD5Final(md5_hash, &ctx);
#else	/* solaris */
	MD5Init(&ctx);
	hdrlen = via->sip_hdr_end - via->sip_hdr_start;
	MD5Update(&ctx, (uchar_t *)via->sip_hdr_start, hdrlen);
	hdrlen = to->sip_hdr_end - to->sip_hdr_start;
	MD5Update(&ctx, (uchar_t *)to->sip_hdr_start, hdrlen);
	hdrlen = from->sip_hdr_end - from->sip_hdr_start;
	MD5Update(&ctx, (uchar_t *)from->sip_hdr_start, hdrlen);
	hdrlen = callid->sip_hdr_end - callid->sip_hdr_start;
	MD5Update(&ctx, (uchar_t *)callid->sip_hdr_start, hdrlen);
	MD5Update(&ctx, (uchar_t *)_sip_msg->sip_msg_req_res->
	    U.sip_request.sip_request_uri.sip_str_ptr,
	    _sip_msg->sip_msg_req_res->U.sip_request.
	    sip_request_uri.sip_str_len);
	MD5Update(&ctx, (uchar_t *)&cseq, sizeof (int));
	MD5Final(md5_hash, &ctx);
#endif
	for (i = 0; i < sizeof (md5_hash); i++) {
		(void) snprintf(&branchid[2 * i], len - (2 * i), "%02x",
		    md5_hash[i]);
	}
	return (branchid);
}

uint32_t
sip_get_cseq()
{
	time_t	tval;

	tval = time(NULL);

	return ((uint32_t)tval);
}

uint32_t
sip_get_rseq()
{
	time_t	tval;

	tval = time(NULL);

	return ((uint32_t)tval);
}
