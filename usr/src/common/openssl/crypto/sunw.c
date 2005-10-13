/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if defined(SOLARIS_OPENSSL)

/*
 * This file is only needed in Sun OpenSSL releases on Solaris.
 */

/*
 * SUNWcry_installed: indicates whether SUNWcry has installed the
 *                    libcrypto_extra library.
 *
 * Stability:	Project Private
 */
#ifdef CRYPTO_UNLIMITED
int SUNWcry_installed = 1;
#else
int SUNWcry_installed = 0;
#endif /* CRYPTO_UNLIMITED */

#endif /* SOLARIS_OPENSSL */
