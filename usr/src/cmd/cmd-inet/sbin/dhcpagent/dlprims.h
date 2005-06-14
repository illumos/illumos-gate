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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	DLPRIMS_H
#define	DLPRIMS_H

#pragma ident	"%W%	%E% SMI"

#include <sys/types.h>
#include <sys/dlpi.h>

/*
 * dlprims.[ch] provide a "simpler" interface to DLPI.  in truth, it's
 * rather grotesque, but for now it's the best we can do.  remove this
 * file once DLPI routines are provided in a library.
 */

#ifdef	__cplusplus
extern "C" {
#endif

int		dlinforeq(int, dl_info_ack_t *, size_t);
int		dlattachreq(int, t_uscalar_t);
int		dlbindreq(int, t_uscalar_t, t_uscalar_t, uint16_t, uint16_t);

#ifdef	__cplusplus
}
#endif

#endif	/* DLPRIMS_H */
