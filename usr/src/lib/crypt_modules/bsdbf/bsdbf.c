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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2026 OmniOS Community Edition (OmniOSce) Association.
 */

#include <crypt.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

extern int bcrypt_gensalt(uint8_t, char *, size_t);
extern int bcrypt(const char *, const char *, char *, size_t);

char *
crypt_gensalt_impl(char *gsbuffer, size_t gsbufflen,
    const char *oldsalt __unused, const struct passwd *userinfo __unused,
    const char **params)
{
	int logr = 4;	/* Default from pwd_gensalt.c on OpenBSD */

	if (params != NULL) {
		logr = atoi(params[0]);
	}
	if (bcrypt_gensalt(logr, gsbuffer, gsbufflen) != 0) {
		errno = EINVAL;
		return (NULL);
	}
	return (gsbuffer);
}


char *
crypt_genhash_impl(char *ctbuffer, size_t ctbufflen, const char *plaintext,
    const char *salt, const char **params __unused)
{
	/*
	 * A malformed salt yields ":", which can never match a stored hash.
	 */
	if (bcrypt(plaintext, salt, ctbuffer, ctbufflen) != 0)
		(void) strlcpy(ctbuffer, ":", ctbufflen);
	return (ctbuffer);
}
