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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 *      Copyright (c) 1997, by Sun Microsystems, Inc.
 *      All rights reserved.
 */

#ifndef _PRIVATE_H
#define	_PRIVATE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef PANELS_H
#define	PANELS_H

#include "panel.h"

#define	_panels_intersect(p1, p2)	(!((p1)->wstarty > (p2)->wendy || \
					(p1)->wendy < (p2)->wstarty || \
					(p1)->wstartx > (p2)->wendx || \
					(p1)->wendx < (p2)->wstartx))

extern	PANEL	*_Bottom_panel;
extern	PANEL	*_Top_panel;

extern	int	_Panel_cnt;

extern void _intersect_panel(PANEL *);
extern void _remove_overlap(PANEL *);
extern int _alloc_overlap(int);
extern void _free_overlap(_obscured_list *);
extern _obscured_list *_unlink_obs(PANEL *, PANEL *);

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _PRIVATE_H */
