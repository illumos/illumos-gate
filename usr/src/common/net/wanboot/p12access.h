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
 * Copyright 2002, 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_P12ACCESS_H
#define	_P12ACCESS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <p12aux.h>
#include <openssl/ssl.h>

/*
 * sunw_p12_use_certfile - read a client certificate from a pkcs12 file and
 *              pass it in to SSL.
 *
 * Read in the certificate in pkcs12-formated file.  If there is a pass phrase
 * use that to decrypt; if no pass phrase was given and there is a callback
 * routine, call it.  Pass the cert to SSL.
 *
 * Arguments:
 *   ctx        - SSL's context structure
 *   filename	- Name of file with the client certificate.
 *   passwd     - Pass phrase for pkcs12 data.
 *
 * Returns:
 *   -1 	- Error occurred.  Check the error stack for specifics.
 *   0          - Success.  Cert was successfully added.
 */
int sunw_p12_use_certfile(SSL_CTX *, char *, char *);

/*
 * sunw_p12_use_keyfile - read a RSA private key from a pkcs12 file and pass
 *              it in to SSL.
 *
 * Read in the RSA private key in pkcs12 format.  If there is a pass phrase
 * use it to decrypt; if no pass phrase was given and there is a callback
 * given, call it.  Pass the key to SSL.
 *
 * Arguments:
 *   ctx        - SSL's context structure
 *   filename	- Name of file with private key.
 *   passwd     - Pass phrase for pkcs12 data.
 *
 * Returns:
 *   -1 	- Error occurred.  Check the error stack for specifics.
 *   0          - Success.
 */
int sunw_p12_use_keyfile(SSL_CTX *, char *, char *);

/*
 * sunw_p12_use_trustfile - read a list of trustanchors from a pkcs12 file and
 *              pass the stack in to SSL.
 *
 * Read in the trust anchors from pkcs12-formated file.  If there is a pass
 * phrase use that to decrypt; if no pass phrase was given and there is a
 * callback routine, call it.  Pass the stack of certs to SSL.
 *
 * Arguments:
 *   ctx        - SSL's context structure
 *   filename	- Name of file with the certificates.
 *   passwd     - Pass phrase for pkcs12 data.
 *
 * Returns:
 *   -1 	- Error occurred.  Check the error stack for specifics.
 *   0          - Success.  Trust anchors were successfully added.
 */
int sunw_p12_use_trustfile(SSL_CTX *, char *, char *);


#ifdef	__cplusplus
}
#endif

#endif	/* _P12ACCESS_H */
