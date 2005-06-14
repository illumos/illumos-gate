/*
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	__SUNW_DST_INIT_NODEFINE

#include <port_before.h>

#include <dlfcn.h>

#include <isc/dst.h>

#include <port_after.h>


static int
genInit(char *library, char *symbol, int (**initFunc)(void)) {

	void			*dlHandle;

	if (*initFunc == 0) {
		if ((dlHandle = dlopen(library, RTLD_LAZY|RTLD_GLOBAL)) == 0)
			return (0);
		if ((*(initFunc) = (int (*)(void))dlsym(dlHandle,
						symbol)) == 0) {
			/*
			 * Can't close the library, since it may be in use
			 * as a result of a previous, successful, call to
			 * this function.
			 */
			return (0);
		}
	}

	return ((**initFunc)());
}


int
sunw_dst_bsafe_init(void) {

	static int		(*initFunc)(void);

	return (genInit("/usr/lib/dns/dnssafe.so.1", "dst_bsafe_init",
			&initFunc) ||
		genInit("/usr/lib/dns/sparcv9/dnssafe.so.1", "dst_bsafe_init",
			&initFunc));
}


int
sunw_dst_eay_dss_init(void) {

	static int		(*initFunc)(void);

	return (genInit("/usr/lib/dns/cylink.so.1", "dst_eay_dss_init",
			&initFunc) ||
		genInit("/usr/lib/dns/sparcv9/cylink.so.1", "dst_eay_dss_init",
			&initFunc));
}


int
sunw_dst_cylink_init(void) {

	static int		(*initFunc)(void);

	return (genInit("/usr/lib/dns/cylink.so.1", "dst_cylink_init",
			&initFunc) ||
		genInit("/usr/lib/dns/sparcv9/cylink.so.1", "dst_cylink_init",
			&initFunc));
}


int
sunw_dst_hmac_md5_init(void) {

	static int		(*initFunc)(void);

	return (genInit("/usr/lib/dns/dnssafe.so.1", "dst_md5_hmac_init",
			&initFunc) ||
		genInit("/usr/lib/dns/sparcv9/dnssafe.so.1",
			"dst_hmac_md5_init",
			&initFunc));
}


int
sunw_dst_rsaref_init(void) {

	static int		(*initFunc)(void);

	return (genInit("/usr/lib/dns/dnssafe.so.1", "dst_rsaref_init",
			&initFunc) ||
		genInit("/usr/lib/dns/sparcv9/dnssafe.so.1", "dst_rsaref_init",
			&initFunc));
}
