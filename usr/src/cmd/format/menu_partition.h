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

#ifndef	_MENU_PARTITION_H
#define	_MENU_PARTITION_H

#ifdef	__cplusplus
extern "C" {
#endif


/*
 *	Prototypes for ANSI C compilers
 */
int	p_apart(void);
int	p_bpart(void);
int	p_cpart(void);
int	p_dpart(void);
int	p_epart(void);
int	p_fpart(void);
int	p_gpart(void);
int	p_hpart(void);
int	p_ipart(void);

#if defined(i386)
int	p_jpart(void);
#endif			/* defined(i386) */

int	p_select(void);
int	p_expand(void);
int	p_modify(void);
int	p_name(void);
int	p_print(void);

void	print_map(struct partition_info *map);
void	print_partition(struct partition_info *pinfo, int partnum,
		int want_header);
void	print_efi_partition(struct dk_gpt *map, int partnum,
		int want_header);

int	chk_volname(struct disk_info *);
void	print_volname(struct disk_info *);

#ifdef	__cplusplus
}
#endif

#endif	/* _MENU_PARTITION_H */
