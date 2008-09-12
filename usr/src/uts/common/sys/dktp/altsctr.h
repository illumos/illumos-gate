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

/* Copyright (c) 1990, 1991 UNIX System Laboratories, Inc. */
/* Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T */
/* All Rights Reserved */

/*
 * (c) Copyright INTERACTIVE Systems Corporation 1986, 1988, 1990
 * All rights reserved.
 */

#ifndef _SYS_DKTP_ALTSCTR_H
#define	_SYS_DKTP_ALTSCTR_H

#ifdef	__cplusplus
extern "C" {
#endif

/*	alternate sector partition information table			*/
struct	alts_parttbl {
	uint32_t	alts_sanity;	/* to validate correctness	*/
	uint32_t  	alts_version;	/* version number		*/
	uint32_t	alts_map_base;	/* disk offset of alts_partmap	*/
	uint32_t	alts_map_len;	/* byte length of alts_partmap	*/
	uint32_t	alts_ent_base;	/* disk offset of alts_entry	*/
	uint32_t	alts_ent_used;	/* number of alternate entries used */
	uint32_t	alts_ent_end;	/* disk offset of top of alts_entry */
	uint32_t	alts_resv_base;	/* disk offset of alts_reserved	*/
	uint32_t 	alts_pad[5];	/* reserved fields		*/
};

/*	alternate sector remap entry table				*/
struct	alts_ent {
	uint32_t	bad_start;	/* starting bad sector number	*/
	uint32_t	bad_end;	/* ending bad sector number	*/
	uint32_t	good_start;	/* starting alternate sector to use */
};

/*	size of alternate partition table structure			*/
#define	ALTS_PARTTBL_SIZE	sizeof (struct alts_parttbl)
/*	size of alternate entry table structure				*/
#define	ALTS_ENT_SIZE	sizeof (struct alts_ent)

/*	definition for alternate sector partition sector map		*/
#define	ALTS_GOOD	0	/* good alternate sectors		*/
#define	ALTS_BAD	1	/* bad alternate sectors		*/

/*	definition for alternate sector partition id			*/
#define	ALTS_SANITY	0xaabbccdd /* magic number to validate alts_part */
#define	ALTS_VERSION1	0x01	/* version of alts_parttbl		*/

#define	ALTS_ENT_EMPTY	-1	/* empty alternate entry		*/
#define	ALTS_MAP_UP	1	/* search forward with increasing sect# */
#define	ALTS_MAP_DOWN	-1	/* search backward with decreasing sect# */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DKTP_ALTSCTR_H */
