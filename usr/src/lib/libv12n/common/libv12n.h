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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_LIBV12N_H
#define	_SYS_LIBV12N_H

#include <sys/types.h>
#include <uuid/uuid.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Max length of an v12n name/uuid/serialno */
#define	V12N_NAME_MAX		1024

/* Virtualization capabilities - bit mask */
#define	V12N_CAP_SUPPORTED	0x1	/* Virtualization supported */
#define	V12N_CAP_ENABLED	0x2	/* Virtualization enabled */
#define	V12N_CAP_IMPL_LDOMS	0x4	/* LDoms Implementation */

/* LDoms Domain role types - bit mask */
#define	V12N_ROLE_CONTROL	0x1	/* LDoms Ctrl domain (zero = Guest) */
#define	V12N_ROLE_IO		0x2	/* I/O domain */
#define	V12N_ROLE_SERVICE	0x4	/* Service domain */
#define	V12N_ROLE_ROOT		0x8	/* Root domain */

int v12n_capabilities(void);
int v12n_domain_roles(void);
int v12n_domain_uuid(uuid_t);
size_t v12n_domain_name(char *, size_t);
size_t v12n_ctrl_domain(char *, size_t);
size_t v12n_chassis_serialno(char *, size_t);

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_LIBV12N_H */
