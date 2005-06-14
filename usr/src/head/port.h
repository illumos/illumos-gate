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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PORT_H
#define	_PORT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/port.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ports API
 */

int	port_create(void);
int	port_associate(int, int, uintptr_t, int, void *);
int	port_dissociate(int, int, uintptr_t);
int	port_send(int, int, void *);
int	port_sendn(int [], int [], uint_t, int, void *);
int	port_get(int, port_event_t *, struct timespec *);
int	port_getn(int, port_event_t [], uint_t, uint_t *, struct timespec *);
int	port_alert(int, int, int, void *);

#ifdef	__cplusplus
}
#endif

#endif	/* _PORT_H */
