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

#ifndef	_SYS_PX_CB_H
#define	_SYS_PX_CB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Control block soft state structure:
 */
#define	PX_CB_MAX_LEAF 2
typedef struct px_cb px_cb_t;
struct px_cb {
	px_t	*xbc_px_p;		/* link back to px soft state */
	int	 xbc_attachcnt;
	kmutex_t xbc_fm_mutex;
	px_t	*xbc_px_list[PX_CB_MAX_LEAF];	/* list of px_p for FMA */
};

extern int px_cb_attach(px_t *px_p);
extern void px_cb_detach(px_t *px_p);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PX_CB_H */
