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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SC_GPTWOCFG_H
#define	_SYS_SC_GPTWOCFG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Interfaces exported by Starcat Interface, kernel/misc/sc_gptwocfg
 */

typedef void *sc_gptwocfg_cookie_t;

sc_gptwocfg_cookie_t sc_probe_board(uint_t);
sc_gptwocfg_cookie_t sc_unprobe_board(uint_t);
int sc_next_node(sc_gptwocfg_cookie_t, dev_info_t *, dev_info_t **);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SC_GPTWOCFG_H */
