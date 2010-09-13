/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * saslutil.h -- various utility functions in SASL library
 */

#ifndef	_SASL_SASLUTIL_H
#define	_SASL_SASLUTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	_SASL_SASL_H
#include <sasl/sasl.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * base64 decode
 *  in     -- input data
 *  inlen  -- length of input data
 *  out    -- output data (may be same as in, must have enough space)
 *  outmax  -- max size of output buffer
 * result:
 *  outlen -- actual output length
 *
 * returns SASL_BADPROT on bad base64,
 *  SASL_BUFOVER if result won't fit
 *  SASL_OK on success
 */
LIBSASL_API int sasl_decode64(const char *in, unsigned inlen,
			    char *out, unsigned outmax, unsigned *outlen);

/*
 * base64 encode
 *  in      -- input data
 *  inlen   -- input data length
 *  out     -- output buffer (will be NUL terminated)
 *  outmax  -- max size of output buffer
 * result:
 *  outlen  -- gets actual length of output buffer (optional)
 *
 * Returns SASL_OK on success, SASL_BUFOVER if result won't fit
 */
LIBSASL_API int sasl_encode64(const char *in, unsigned inlen,
			    char *out, unsigned outmax, unsigned *outlen);

#if 0
/*
 * The following is not supported:
 *
 * make a challenge string (NUL terminated)
 *  buf      -- buffer for result
 *  maxlen   -- max length of result
 *  hostflag -- 0 = don't include hostname, 1 = include hostname
 * returns final length or 0 if not enough space
 */
LIBSASL_API int sasl_mkchal(sasl_conn_t *conn, char *buf,
			    unsigned maxlen, unsigned hostflag);
#endif

/*
 * verify a string is valid UTF-8
 * if len == 0, strlen(str) will be used.
 * returns SASL_BADPROT on error, SASL_OK on success
 */
LIBSASL_API int sasl_utf8verify(const char *str, unsigned len);

#if 0
/* The following are not supported */

/* create random pool seeded with OS-based params */
LIBSASL_API int sasl_randcreate(sasl_rand_t **rpool);

/* free random pool from randcreate */
LIBSASL_API void sasl_randfree(sasl_rand_t **rpool);

/* seed random number generator */
LIBSASL_API void sasl_randseed(sasl_rand_t *rpool, const char *seed,
				unsigned len);

/* generate random octets */
LIBSASL_API void sasl_rand(sasl_rand_t *rpool, char *buf, unsigned len);

/* churn data into random number generator */
LIBSASL_API void sasl_churn(sasl_rand_t *rpool, const char *data,
			    unsigned len);
#endif

/*
 * erase a security sensitive buffer or password.
 *   Implementation may use recovery-resistant erase logic.
 */
LIBSASL_API void sasl_erasebuffer(char *pass, unsigned len);

#ifdef	__cplusplus
}
#endif

#endif /* _SASL_SASLUTIL_H */
