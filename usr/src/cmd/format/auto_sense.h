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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_AUTO_SENSE_H
#define	_AUTO_SENSE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


#ifdef	__STDC__
/*
 *	Prototypes for ANSI C compilers
 */
struct disk_type	*auto_sense(
				int		fd,
				int		can_prompt,
				struct dk_label	*label);

struct disk_type	*auto_efi_sense(
				int			fd,
				struct efi_info		*label);

int			build_default_partition(
				struct dk_label *label,
				int		ctrl_type);
int			delete_disk_type(
				struct disk_type *disk_type);

struct disk_type *auto_direct_get_geom_label(int fd, struct dk_label *label);
#else

struct disk_type	*auto_sense();
struct disk_type	*auto_efi_sense();
int			build_default_partition();
struct disk_type *auto_direct_get_geom_label();


#endif	/* __STDC__ */

#ifdef	__cplusplus
}
#endif

#endif	/* _AUTO_SENSE_H */
