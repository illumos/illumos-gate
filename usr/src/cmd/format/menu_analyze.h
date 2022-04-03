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

#ifndef	_MENU_ANALYZE_H
#define	_MENU_ANALYZE_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *	Prototypes for ANSI
 */

int	a_read(void);
int	a_refresh(void);
int	a_test(void);
int	a_write(void);
int	a_compare(void);
int	a_verify(void);
int	a_print(void);
int	a_setup(void);
int	a_config(void);
int	a_purge(void);

#ifdef	__cplusplus
}
#endif

#endif	/* _MENU_ANALYZE_H */
