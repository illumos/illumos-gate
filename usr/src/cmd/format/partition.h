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

#ifndef	_PARTITION_H
#define	_PARTITION_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Mnemonics for the partitions we recognize
 */
#define	A_PARTITION		0
#define	B_PARTITION		1
#define	C_PARTITION		2
#define	D_PARTITION		3
#define	E_PARTITION		4
#define	F_PARTITION		5
#define	G_PARTITION		6
#define	H_PARTITION		7

#if defined(i386)
/*
 * the boot and alts slices only exist in the x86 disk layout.
 */
#define	I_PARTITION		8
#define	J_PARTITION		9
#endif		/* defined(i386) */

/*
 *	Prototypes for ANSI C compilers
 */
void	change_partition(int num);
int	get_partition(void);
void	make_partition(void);
void	delete_partition(struct partition_info *parts);
void	set_vtoc_defaults(struct partition_info	*part);


extern	struct dk_map2	default_vtoc_map[NDKMAP];

#ifdef	__cplusplus
}
#endif

#endif	/* _PARTITION_H */
