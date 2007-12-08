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
 * Copyright (c) 1990-1994, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This struct keeps track of an open file in the standalone I/O system.
 *
 * It includes an IOB for device addess, a buffer for reading directory blocks
 * and a structure for volume.
 */
struct iob {
	void		*i_si;		/* I/O handle for this file */
	struct {
		off_t   si_offset;	/* byte offset */
		char	*si_ma;		/* memory address to r/w */
		int	si_cc;		/* character count to r/w */
		int	si_bn;		/* block number to r/w */
	} i_saio;
	struct inode	i_ino;		  /* Buffer for inode information */
	struct hs_volume ui_hsfs;	  /* Superblock for file system */
	char		i_buf[MAXBSIZE];  /* Buffer for reading dirs */
};

#define	i_offset	i_saio.si_offset
#define	i_bn		i_saio.si_bn
#define	i_ma		i_saio.si_ma
#define	i_cc		i_saio.si_cc
