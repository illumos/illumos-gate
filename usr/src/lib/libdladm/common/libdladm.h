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

#ifndef _LIBDLADM_H
#define	_LIBDLADM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/dls.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct dladm_attr	dladm_attr_t;

struct dladm_attr {
	char		da_dev[MAXNAMELEN];
	uint_t		da_max_sdu;
	uint_t		da_port;
	uint16_t	da_vid;
};

extern int	dladm_walk(void (*)(void *, const char *), void *);
extern int	dladm_walk_vlan(void (*)(void *,
			    const char *), void *, const char *);
extern int	dladm_info(const char *, dladm_attr_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDLADM_H */
