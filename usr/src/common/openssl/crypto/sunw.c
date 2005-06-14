/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if defined(SOLARIS_OPENSSL) 

/*
 * This file is only needed in Sun OpenSSL releases on Solaris.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/engine.h>
#include <ctype.h>
#include <dlfcn.h>

/*
 * SUNWcry_installed: return 1 if SUNWcry has installed the libcrypto_extra
 * 		      library.
 *
 * Stability:	Project Private
 */
int
SUNWcry_installed(void)
{
	static int ret = -1;
	/*
	 * The way we determine if the SUNWcry package is installed
	 * is to look for a symbol that exists only in the filter library
	 * libcrypto_extra. AES 256 seems like a reasonable choice.
	 */
	if (ret == -1) {
		ret = (dlsym(RTLD_PROBE, "EVP_aes_256_cbc") != NULL);
	}

	return (ret);
}

#endif /* SOLARIS_OPENSSL */
