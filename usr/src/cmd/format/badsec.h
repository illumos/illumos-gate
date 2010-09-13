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
 *
 * copyright (c) 1990, 1991 UNIX System Laboratories, Inc.
 * copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T
 * All Rights Reserved
 */

#ifndef	_BADSEC_H
#define	_BADSEC_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	BADSECFILE	"/etc/scsi/badsec"
#define	FAILURE	1
#define	SUCCESS	0

#define	MAXBLENT	4
struct	badsec_lst {
	uint_t	bl_cnt;
	struct	badsec_lst *bl_nxt;
	uint_t	bl_sec[MAXBLENT];
};

#define	BADSLSZ		sizeof (struct badsec_lst)
#define	BFI_FORMAT	0
#define	ATA_FORMAT	1

#define	ALTS_ADDPART	0x1	/* add alternate partition		*/
struct	alts_mempart {			/* incore alts partition info	*/
	int	ap_flag;		/* flag for alternate partition	*/
	struct	alts_parttbl *ap_tblp;	/* alts partition table		*/
	uint_t	ap_tbl_secsiz;		/* alts parttbl sector size	*/
	uchar_t	*ap_memmapp;		/* incore alternate sector map	*/
	uchar_t	*ap_mapp;		/* alternate sector map		*/
	uint_t	ap_map_secsiz;		/* alts partmap sector size	*/
	uint_t	ap_map_sectot;		/* alts partmap # sector 	*/
	struct  alts_ent *ap_entp;	/* alternate sector entry table */
	uint_t	ap_ent_secsiz;		/* alts entry sector size	*/
	struct	alts_ent *ap_gbadp;	/* growing badsec entry table	*/
	uint_t	ap_gbadcnt;		/* growing bad sector count	*/
	struct	dkl_partition part;	/* alts partition configuration */
};

/*	size of incore alternate partition memory structure		*/
#define	ALTS_MEMPART_SIZE	sizeof (struct alts_mempart)

struct	altsectbl {			/* working alts info		*/
	struct  alts_ent *ast_entp;	/* alternate sector entry table */
	uint_t	ast_entused;		/* entry used			*/
	struct	alt_info *ast_alttblp;	/* alts info			*/
	uint_t	ast_altsiz;		/* size of alts info		*/
	struct  alts_ent *ast_gbadp;	/* growing bad sector entry ptr */
	uint_t	ast_gbadcnt;		/* growing bad sector entry cnt */
};
/*	size of incore alternate partition memory structure		*/
#define	ALTSECTBL_SIZE	sizeof (struct altsectbl)

/*	macro definitions						*/
#define	byte_to_secsiz(APSIZE, BPS)	(uint_t) \
					((((APSIZE) + (BPS) - 1) \
					    / (uint_t)(BPS)) * (BPS))

#ifdef	__cplusplus
}
#endif

#endif	/* _BADSEC_H */
