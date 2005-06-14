/*
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#define	__SUNW_IRS_INIT_NODEFINE

#include <port_before.h>

#include <dlfcn.h>

#include <port_after.h>


static struct irs_acc *
genInit(char *library, char *symbol,
	struct irs_acc *(**initFunc)(const char *), const char *options) {

	void	*dlHandle;

	if (*initFunc == 0) {
		if ((dlHandle = dlopen(library, RTLD_LAZY|RTLD_GLOBAL)) == 0)
			return (0);
		if ((*(initFunc) =
			(struct irs_acc *(*)(const char *))dlsym(dlHandle,
						symbol)) == 0) {
			/*
			 * Can't close the library, since it may be in use
			 * as a result of a previous, successful, call to
			 * this function.
			 */
			return (0);
		}
	}

	return ((**initFunc)(options));
}


#ifdef	WANT_IRS_NIS
struct irs_acc *
sunw_irs_nis_acc(const char *options) {

	static struct irs_acc	*(*initFunc)(const char *);
	struct irs_acc		*ret;

	ret = genInit("/usr/lib/dns/irs.so.1", "irs_nis_acc", &initFunc,
			options);
	if (ret == 0)
		ret = genInit("/usr/lib/dns/sparcv9/irs.so.1", "irs_nis_acc",
			&initFunc, options);
	return (ret);
}
#else
struct irs_acc *
sunw_irs_nis_acc(const char *options) {
	return (0);
}
#endif	/* WANT_IRS_NIS */

struct irs_acc *
sunw_irs_irp_acc(const char *options) {

	static struct irs_acc	*(*initFunc)(const char *);
	struct irs_acc		*ret;

	ret = genInit("/usr/lib/dns/irs.so.1", "irs_irp_acc", &initFunc,
			options);
	if (ret == 0)
		ret = genInit("/usr/lib/dns/sparcv9/irs.so.1", "irs_irp_acc",
			&initFunc, options);
	return (ret);
}
