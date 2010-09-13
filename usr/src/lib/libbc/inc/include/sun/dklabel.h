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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Copyright (c) 1987 by Sun Microsystems, Inc.
 */

#ifndef _sun_dklabel_h
#define	_sun_dklabel_h

/*
 * Miscellaneous defines
 */
#define	DKL_MAGIC	0xDABE	/* magic number */
#define	FKL_MAGIC	0xff	/* magic number for DOS floppies */
#define	NDKMAP	8		/* # of logical partitions */

/*
 * Format of a Sun SMD disk label.
 * Resides in cylinder 0, head 0, sector 0.
 *
 * sizeof (struct dk_label) should be 512 (sector size)
 */
struct dk_label {
	char	dkl_asciilabel[128];	/* for compatibility */
	char	dkl_pad[512-(128+NDKMAP*8+14*2)];
	unsigned short	dkl_rpm;	/* rotations per minute */
	unsigned short	dkl_pcyl;	/* # physical cylinders */
	unsigned short	dkl_apc;	/* alternates per cylinder */
	unsigned short	dkl_obs1;	/* obsolete */
	unsigned short	dkl_obs2;	/* obsolete */
	unsigned short	dkl_intrlv;	/* interleave factor */
	unsigned short	dkl_ncyl;	/* # of data cylinders */
	unsigned short	dkl_acyl;	/* # of alternate cylinders */
	unsigned short	dkl_nhead;	/* # of heads in this partition */
	unsigned short	dkl_nsect;	/* # of 512 byte sectors per track */
	unsigned short	dkl_obs3;	/* obsolete */
	unsigned short	dkl_obs4;	/* obsolete */
	/* */
	struct dk_map {			/* logical partitions */
		daddr_t	dkl_cylno;	/* starting cylinder */
		daddr_t dkl_nblk;	/* number of blocks */
	} dkl_map[NDKMAP];
	unsigned short	dkl_magic;	/* identifies this label format */
	unsigned short	dkl_cksum;	/* xor checksum of sector */
};

/*
 * These defines are for historic compatibility with old drivers.
 */
#define	dkl_gap1	dkl_obs1	/* used to be gap1 */
#define	dkl_gap2	dkl_obs2	/* used to be gap2 */
#define	dkl_bhead	dkl_obs3	/* used to be label head offset */
#define	dkl_ppart	dkl_obs4	/* used to by physical partition */

struct fk_label {			/* DOS floppy label */
	u_char fkl_type;
	u_char fkl_magich;
	u_char fkl_magicl;
	u_char filler;
};

#endif /*!_sun_dklabel_h*/
