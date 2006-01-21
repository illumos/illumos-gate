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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SUNFM_IMPL_H
#define	_SUNFM_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <libnvpair.h>
#include <stdarg.h>

#ifdef DEBUG
extern void sunFm_panic(const char *format, ...) __NORETURN;
extern void sunFm_vpanic(const char *format, va_list ap) __NORETURN;
extern int sunFm_assert(const char *, const char *, int);
#define	ASSERT(x)	((void)((x) || sunFm_assert(#x, __FILE__, __LINE__)))
#else
extern void sunFm_panic(const char *format, ...);
extern void sunFm_vpanic(const char *format, va_list ap);
#define	ASSERT(x)
#endif

typedef int (*sunFm_table_init_func_t)(void);

typedef struct sunFm_table {
	const char		*t_name;
	sunFm_table_init_func_t	t_init;
} sunFm_table_t;

#define	TABLE_INIT(__t)	__t##_init
#define	TABLE_NAME(__t)	#__t
#define	TABLE_REG(__t)	{ TABLE_NAME(__t), TABLE_INIT(__t) }
#define	TABLE_NULL	{ NULL, NULL }

/*
 * The definition of netsnmp_table_helper_add_index in <net-snmp/agent/table.h>
 * is defective; it includes a ; at the end.  We have to use our own.
 */
#ifdef	netsnmp_table_helper_add_index
#undef	netsnmp_table_helper_add_index
#define	netsnmp_table_helper_add_index(tinfo, type) \
	snmp_varlist_add_variable(&tinfo->indexes, NULL, 0, (uchar_t)type, \
	NULL, 0)
#endif	/* netsnmp_table_helper_add_index */

extern char *sunFm_nvl2str(nvlist_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SUNFM_IMPL_H */
