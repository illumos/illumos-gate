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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _T10_SPC_PR_H
#define	_T10_SPC_PR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SPC-3 Persistent Reservation specific structures and defines
 */

/*
 * Key Linked Lists
 */
typedef struct key_link {
	union {
		uint64_t	align;
		struct {
			struct key_link *_lnk_fwd;	/* Forward element */
			struct key_link *_lnk_bwd;	/* Backward element */
		} key_ptr;
	} key_link;
} key_link_t;
#define	lnk_fwd	key_link.key_ptr._lnk_fwd
#define	lnk_bwd	key_link.key_ptr._lnk_bwd
#define	insque(a, b) do { \
	((key_link_t *)(a))->lnk_fwd = (key_link_t *)(b); \
	((key_link_t *)(a))->lnk_bwd = ((key_link_t *)(b))->lnk_bwd; \
	((key_link_t *)(b))->lnk_bwd = (key_link_t *)(a); \
	((key_link_t *)(a))->lnk_bwd->lnk_fwd = (key_link_t *)(a); \
	} while (0)

#define	remque(A) do { \
	((key_link_t *)(A))->lnk_bwd->lnk_fwd = ((key_link_t *)(A))->lnk_fwd; \
	((key_link_t *)(A))->lnk_fwd->lnk_bwd = ((key_link_t *)(A))->lnk_bwd; \
	} while (0)

/*
 * Reservation Types (res_type).
 */
typedef enum {
	RT_NONE = 0,			/* None */
	RT_PGR				/* SCSI-3 Persistent Reservation */
} spc_reserve_types;

/*
 * Persistent reservation data.
 */
typedef struct spc_pr_key {
	key_link_t	k_link;			/* Key linked list */
	uint64_t	k_key;			/* registration key */
	uint64_t	k_isid;			/* Owner ISID */
	char		*k_transportID;		/* transport ID */
} spc_pr_key_t;

typedef struct spc_pr_rsrv {
	key_link_t	r_link;			/* Key linked list */
	uint64_t	r_key;			/* reservation key */
	uint64_t	r_isid;			/* Owner ISID */
	char		*r_transportID;		/* transport ID */
	uint8_t		r_scope;		/* reservation scope */
	uint8_t		r_type;			/* reservation type */
} spc_pr_rsrv_t;

/*
 * Persistent Reservation data
 */
typedef struct scsi3_pgr {
	uint32_t	pgr_generation;		/* PGR PRgeneration value */
	uint16_t	pgr_unused;
	uint16_t	pgr_bits	: 15,
			pgr_aptpl	: 1;	/* persistence data exists */
	int32_t		pgr_numkeys;		/* # entries in key list */
	int32_t		pgr_numrsrv;		/* # entries in rsrv list */
	key_link_t	pgr_keylist;		/* Registration key list */
	key_link_t	pgr_rsrvlist;		/* reservation list */
} scsi3_pgr_t;

typedef struct sbc_reserve {
	spc_reserve_types	res_type;	/* standard or pr active */
	pthread_rwlock_t	res_rwlock;	/* Lock for coordination */
	scsi3_pgr_t		res_scsi_3_pgr;	/* SCSI-3 PGR */
} sbc_reserve_t;

/*
 * On-disk PGR data.
 *
 * NOTE: The following three structures should be rounded up to 256 bytes each
 *	to prevent potential problems with on-disk data.
 */
typedef struct spc_pr_diskkey {
	uint32_t	rectype;		/* record type */
	uint32_t	reserved;
	uint64_t	key;			/* registration key */
	uint64_t	isid;			/* Owner ISID */
	char		transportID[228];	/* transport ID */
	char		filler[4];		/* Unsed, round to 256 bytes */
} spc_pr_diskkey_t;

typedef struct spc_pr_diskrsrv {
	uint32_t	rectype;		/* record type */
	uint16_t	reserved;
	uint8_t		scope;			/* reservation scope */
	uint8_t		type;			/* reservation type */
	uint64_t	key;			/* reservation key */
	uint64_t	isid;			/* Owner ISID */
	char		transportID[228];	/* Transport ID */
	char		filler[4];		/* Unsed, round to 256 bytes */
} spc_pr_diskrsrv_t;

typedef struct spc_pr_persist_disk {
	uint64_t	magic;			/* magic number */
	uint32_t	revision;		/* header format revision */
	uint32_t	generation;		/* pgr generation count */
	int32_t		numkeys;		/* # items in key list */
	int32_t		numrsrv;		/* # items in rsrv list */
	char		filler[232];		/* Unused, round to 256 bytes */

/*
 * After the header the data is laid out as follows:
 *	spc_pr_diskkey_t	keylist[];
 *	spc_pr_diskrsrv_t	rsrvlist[];
 */
	spc_pr_diskkey_t	keylist[1];
} spc_pr_persist_disk_t;


#define	SPC_PGR_PERSIST_DATA_REVISION 0x01	/* REVISON = 1 */
#define	PGRMAGIC	0x5047524D41474943LL	/* "PGRMAGIC" */
#define	PGRDISKKEY	0x5047526B		/* "PGRk" */
#define	PGRDISKRSRV	0x50475272		/* "PGRr" */

#ifdef __cplusplus
}
#endif

#endif /* _T10_SPC_PR_H */
