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
 * Copyright (c) 1991-2001 by Sun Microsystems, Inc.
 */

#ifndef	_MENU_DEFECT_H
#define	_MENU_DEFECT_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *	Prototypes for ANSI C compilers
 */
int	d_restore(void);
int	d_original(void);
int	d_extract(void);
int	d_add(void);
int	d_delete(void);
int	d_print(void);
int	d_dump(void);
int	d_load(void);
int	d_commit(void);
int	do_commit(void);
int	d_create(void);
int	d_primary(void);
int	d_grown(void);
int	d_both(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _MENU_DEFECT_H */
