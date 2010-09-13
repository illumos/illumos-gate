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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_CLCONF_H
#define	_SYS_CLCONF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This header file specifies the interface to access the
 * configuration data needed in order to boot and form a cluster.
 */

/*
 * Node identifiers are numbered 1 to clconf_maximum_nodeid().
 * The nodeid zero is used to mean unknown.
 */
#define	NODEID_UNKNOWN	0

typedef unsigned int	nodeid_t;

#if defined(_KERNEL)

extern void	clconf_init(void);
extern nodeid_t	clconf_get_nodeid(void);
extern nodeid_t	clconf_maximum_nodeid(void);
#endif /* defined(_KERNEL) */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_CLCONF_H */
