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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LABEL_H
#define	_LABEL_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *	Prototypes for ANSI C compilers
 */
int	checklabel(struct dk_label *label);
int	checksum(struct dk_label *label, int mode);
int	trim_id(char *id);
int	write_label(void);
int	read_label(int fd, struct dk_label *label);
int	read_efi_label(int fd, struct efi_info *label);
int	get_disk_info(int fd, struct efi_info *label);
int	label_to_vtoc(struct extvtoc *vtoc, struct dk_label *label);
int	SMI_vtoc_to_EFI(int fd, struct dk_gpt **new_vtoc);
void	err_check(struct dk_gpt *vtoc);
extern int	is_efi_type(int fd);

#ifdef	__cplusplus
}
#endif

#endif	/* _LABEL_H */
