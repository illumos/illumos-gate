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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_BOOT_HTTP_H
#define	_BOOT_HTTP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/types.h>
#include <sys/errno.h>
#include <parseURL.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* State information returned by http_conn_info() */
typedef struct {
	url_t		uri;		/* URI last loaded */
	url_hport_t	proxy;		/* proxy, if any being used */
	boolean_t	keepalive;	/* Keepalive setting being used */
	uint_t		read_timeout;	/* Timeout to use for socket reads */
} http_conninfo_t;


/* Structure for version of the http file */
typedef struct {
	uint_t	maj_ver;	/* Major version */
	uint_t	min_ver;	/* Minor version */
	uint_t	micro_ver;	/* Micro version */
} boot_http_ver_t;

/* Internal Libhttp errors */
#define	EHTTP_BADARG	1	/* Function called with one+ bad arguments */
#define	EHTTP_NOMEM	2	/* Out of memory error detected */
#define	EHTTP_CONCLOSED	3	/* The ssl connection was closed (but not */
				/* necessarily the underlying transport */
				/* connection). */
#define	EHTTP_UNEXPECTED 4	/* A SSL I/O request returned an unexpected */
				/* error. */
#define	EHTTP_EOFERR	5	/* Unexpected/premature EOF */
#define	EHTTP_NOCERT	6	/* No certificate was persented */
#define	EHTTP_NOMATCH	7	/* Peer cert doesn't match hostname or */
				/* No matching entry */
#define	EHTTP_NODATA	8	/* No data was returned */
#define	EHTTP_NOT_1_1	9	/* This was not a HTTP/1.1 response */
#define	EHTTP_BADHDR	10	/* The header doesn't look to be valid */
#define	EHTTP_OORANGE	11	/* Requests header line is out of range */
#define	EHTTP_NORESP	12	/* No or partial response returned */
#define	EHTTP_BADRESP	13	/* Bad response or error returned */
#define	EHTTP_NOHEADER	14	/* Chunked header expected but not found */
#define	EHTTP_NOBOUNDARY 15	/* Boundary line expected but not found */
#define	EHTTP_NOTMULTI	16	/* This is not a multipart transfer */
#define	EHTTP_BADSIZE	17	/* Could not determine msg body size */



/* Sources of errors */
#define	ERRSRC_SYSTEM	1	/* System error occurred */
#define	ERRSRC_LIBHTTP	2	/* Internal (libhttp) error */
#define	ERRSRC_RESOLVE	3	/* Libresolv error */
#define	ERRSRC_VERIFERR	4	/* Verify error occurred */
#define	ERRSRC_LIBSSL	5	/* Libssl/libcrypto error */


typedef struct {
	uint_t	code;		/* status code */
	char	*statusmsg;	/* status message */
	uint_t	nresphdrs;	/* number of response headers */
} http_respinfo_t;


typedef void *http_handle_t;

boot_http_ver_t const *http_get_version(void);
void http_set_p12_format(int);
void http_set_verbose(boolean_t);
int  http_set_cipher_list(const char *);
http_handle_t http_srv_init(const url_t *);
int  http_set_proxy(http_handle_t, const url_hport_t *);
int  http_set_keepalive(http_handle_t, boolean_t);
int  http_set_socket_read_timeout(http_handle_t, uint_t);
int  http_set_basic_auth(http_handle_t, const char *, const char *);
int  http_set_random_file(http_handle_t, const char *);
int  http_set_certificate_authority_file(const char *);
int  http_set_client_certificate_file(http_handle_t, const char *);
int  http_set_password(http_handle_t, const char *);
int  http_set_key_file_password(http_handle_t, const char *);
int  http_set_private_key_file(http_handle_t, const char *);

int   http_srv_connect(http_handle_t);
int   http_head_request(http_handle_t, const char *);
int   http_get_request(http_handle_t, const char *);
int   http_get_range_request(http_handle_t, const char *, offset_t, offset_t);
void  http_free_respinfo(http_respinfo_t *);
int   http_process_headers(http_handle_t, http_respinfo_t **);
int   http_process_part_headers(http_handle_t, http_respinfo_t **);
char *http_get_header_value(http_handle_t, const char *);
char *http_get_response_header(http_handle_t, uint_t);
int   http_read_body(http_handle_t, char *, size_t);
int   http_srv_disconnect(http_handle_t);
int   http_srv_close(http_handle_t);
http_conninfo_t *http_get_conn_info(http_handle_t);
int   http_conn_is_https(http_handle_t, boolean_t *);
ulong_t http_get_lasterr(http_handle_t, uint_t *);
void http_decode_err(ulong_t, int *, int *, int *);
char const *http_errorstr(uint_t, ulong_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _BOOT_HTTP_H */
