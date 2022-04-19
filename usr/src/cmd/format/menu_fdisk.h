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
 * Copyright (c) 1993-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_MENU_FDISK_H
#define	_MENU_FDISK_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *	Prototypes for ANSI
 */
int	copy_solaris_part(struct ipart *ipart);
void	open_cur_file(int);
int	auto_solaris_part(struct dk_label *);


/*
 * These flags are used to open file descriptor for current
 *	disk (cur_file) with "p0" path or cur_disk->disk_path
 */
#define	FD_USE_P0_PATH		0
#define	FD_USE_CUR_DISK_PATH	1

#ifdef	__cplusplus
}
#endif

#endif	/* _MENU_FDISK_H */
