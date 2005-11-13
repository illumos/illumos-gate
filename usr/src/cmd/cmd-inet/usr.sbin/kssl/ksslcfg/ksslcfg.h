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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _KSSLCFG_H
#define	_KSSLCFG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Common routines and variables used by ksslcfg files.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <libintl.h>
#include <locale.h>

#define	MAX_ADRPORT_LEN	128 /* sufficient for host name/IP address + port */

#define	SUCCESS			0
#define	FAILURE			1
#define	ERROR_USAGE		2
#define	INSTANCE_ANY_EXISTS	3
#define	INSTANCE_OTHER_EXISTS	4

extern const char *SERVICE_NAME;
extern boolean_t verbose;

extern char *create_instance_name(const char *arg, char **inaddr_any_name,
    boolean_t is_create);
int get_portnum(const char *, ushort_t *);
extern void KSSL_DEBUG(const char *format, ...);
extern int do_create(int argc, char *argv[]);
extern int do_delete(int argc, char *argv[]);
extern int delete_instance(const char *instance_name);
extern void usage_create(boolean_t do_print);
extern void usage_delete(boolean_t do_print);

#ifdef __cplusplus
}
#endif

#endif /* _KSSLCFG_H */
