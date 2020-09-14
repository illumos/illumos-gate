/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020 Oxide Computer Company
 */

#ifndef _SYS_PROM_DEBUG_H
#define	_SYS_PROM_DEBUG_H

#include <sys/promif.h>

/*
 * These macros are used to emit coarse-grained early boot debugging
 * information when the user sets "prom_debug" in the boot environment.  They
 * should only be used for information that we cannot easily obtain through a
 * richer mechanism because the machine hangs or crashes before other debugging
 * tools are available.
 */

#ifdef __cplusplus
extern "C" {
#endif

extern int prom_debug;

/*
 * Print a string message, used to signal that we have at least reached a
 * particular point in the code:
 */
#define	PRM_POINT(q)	do {						\
		if (prom_debug) {					\
			prom_printf("%s:%d: %s\n",			\
			    __FILE__, __LINE__, (q));			\
		}							\
	} while (0)

/*
 * Print the name and value of an integer variable:
 */
#define	PRM_DEBUG(q)	do {						\
		if (prom_debug) {					\
			prom_printf("%s:%d: '%s' is 0x%llx\n",		\
			    __FILE__, __LINE__, #q, (long long)(q));	\
		}							\
	} while (0)

/*
 * Print the name and value of a string (char *) variable (which may be NULL):
 */
#define	PRM_DEBUGS(q)	do {						\
		if (prom_debug) {					\
			const char *qq = q;				\
			prom_printf("%s:%d: '%s' is '%s'\n",		\
			    __FILE__, __LINE__, #q,			\
			    qq != NULL ? qq : "<NULL>");		\
		}							\
	} while (0)

#ifdef __cplusplus
}
#endif

#endif /* _SYS_PROM_DEBUG_H */
