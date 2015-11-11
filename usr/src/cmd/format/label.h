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
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

#ifndef	_LABEL_H
#define	_LABEL_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *	Prototypes for ANSI C compilers
 */
int	checklabel(struct dk_label *);
int	checksum(struct dk_label *, int);
int	trim_id(char *);
int	write_label(void);
int	read_label(int, struct dk_label *);
int	read_efi_label(int, struct efi_info *, struct disk_info *);
int	get_disk_inquiry_prop(char *, char **, char **, char **);
int	get_disk_info(int, struct efi_info *, struct disk_info *);
int	label_to_vtoc(struct extvtoc *, struct dk_label *);
int	SMI_vtoc_to_EFI(int, struct dk_gpt **);
void	err_check(struct dk_gpt *);
extern int	is_efi_type(int);

#ifdef	__cplusplus
}
#endif

#endif	/* _LABEL_H */
