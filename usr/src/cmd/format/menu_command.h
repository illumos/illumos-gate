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

#ifndef	_MENU_COMMAND_H
#define	_MENU_COMMAND_H

#ifdef	__cplusplus
extern "C" {
#endif


/*
 *	Prototypes for ANSI
 */
int	c_disk(void);
int	c_type(void);
int	c_partition(void);
int	c_current(void);
int	c_format(void);
int	c_fdisk(void);
int	c_repair(void);
int	c_show(void);
int	c_label(void);
int	c_analyze(void);
int	c_defect(void);
int	c_backup(void);
int	c_volname(void);
int	c_verify(void);
int	c_inquiry(void);


extern slist_t	ptag_choices[];
extern slist_t	pflag_choices[];

#ifdef	__cplusplus
}
#endif

#endif	/* _MENU_COMMAND_H */
