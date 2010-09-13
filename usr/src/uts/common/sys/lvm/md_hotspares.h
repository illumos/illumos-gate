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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_MD_HOTSPARES_H
#define	_SYS_MD_HOTSPARES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/lvm/mdvar.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ioctl parameter structures
 */

typedef enum set_hs_command	{
	ADD_HOT_SPARE, DELETE_HOT_SPARE, REPLACE_HOT_SPARE, FIX_HOT_SPARE
} set_hs_command_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif
typedef struct set_hs_params {
	MD_DRIVER
	md_error_t		mde;			/* error return */
	set_hs_command_t	shs_cmd;		/* ioctl command */
	hsp_t			shs_hot_spare_pool;	/* hsp identifier */
	md_dev64_t		shs_component_old; /* dev for add, del, repl */
	md_dev64_t		shs_component_new;	/* new dev for repl */
	mdkey_t			shs_key_old;		/* key */
	mdkey_t			shs_key_new;		/* new key for repl */
	uint_t			shs_options;		/* see HS_OPT_* below */
	diskaddr_t		shs_start_blk;		/* used by add/repl */
	int			shs_has_label;		/* used by add/repl */
	diskaddr_t		shs_number_blks;	/* used by add/repl */
	int			shs_size_option;	/* big or small */
} set_hs_params_t;

#define	HS_OPT_NONE	0x0000	/* Nothing special */
#define	HS_OPT_FORCE	0x0001	/* force flag */
#define	HS_OPT_POOL	0x0002	/* work on a hs pool */
#define	HS_OPT_DRYRUN	0x0004	/* just check if operation would be possible */

typedef struct get_hs_params {
	MD_DRIVER
	md_error_t		mde;		/* error return */
	mdkey_t			ghs_key;	/* hs name key */
	md_dev64_t		ghs_devnum;	/* returned hs dev_t */
	diskaddr_t		ghs_start_blk;	/* returned start blk */
	diskaddr_t		ghs_number_blks; /* returned # of blks */
	hotspare_states_t	ghs_state;	/* returned state */
	md_timeval32_t		ghs_timestamp;	/* returned timestamp */
	uint_t			ghs_revision;	/* returned revision */
} get_hs_params_t;

typedef struct get_hsp {
	hsp_t		ghsp_id;		/* hsp id */
	int		ghsp_refcount;		/* # metadevices using hsp */
	int		ghsp_nhotspares;	/* # of hs in hsp */
	mdkey_t		ghsp_hs_keys[1];	/* array of keys */
} get_hsp_t;

#define	MD_IOCSET_HS	(MDIOC_MISC|0)
#define	MD_IOCGET_HS    (MDIOC_MISC|1)
#define	HSP_REC	1
#define	HS_REC	2

/*
 * Hot spare and hot spare pool data structures
 * Note that hot_spare32_od is for old 32 bit format only
 */
typedef struct hot_spare32_od {
	uint_t			hs_revision;	/* revision number */
	mddb_recid_t		hs_record_id;	/* db record id */
	caddr32_t		xx_hs_next;	/* hs list, link */
	dev32_t			hs_devnum;	/* hs device number */
	mdkey_t			hs_key;		/* namespace key */
	daddr32_t		hs_start_blk;	/* hs starting block */
	int			hs_has_label;	/* hs has a label */
	int			hs_number_blks;	/* hs # of blocks */
	hotspare_states_t	hs_state;	/* hs state */
	int			hs_refcount;	/* # hsp using the hs */
	int			hs_isopen;	/* is open flag */
	struct timeval32	hs_timestamp;	/* time of last state change */
	/*
	 * Incore elements in this old format are not used by 64 bit kernel
	 * Comment out here for maintenance history
	 *	struct hot_spare	*hs_next;
	 */
} hot_spare32_od_t;
#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

/*
 * The pads are necessary for the hot_spare_t structure to be interpreted
 * correctly in userland on the amd64 arch.
 */
typedef struct hot_spare {
	uint_t			hs_revision;    /* revision number */
	mddb_recid_t		hs_record_id;   /* db record id */
	md_dev64_t		hs_devnum;	/* hs device number */
	mdkey_t			hs_key;		/* namespace key */
	int			hs_pad1;
	diskaddr_t		hs_start_blk;   /* hs starting block */
	int			hs_has_label;   /* hs has a label */
	int			hs_pad2;
	diskaddr_t		hs_number_blks; /* hs # of blocks */
	hotspare_states_t	hs_state;	/* hs state */
	int			hs_refcount;    /* # hsp using the hs */
	int			hs_isopen;	/* is open flag */
	md_timeval32_t		hs_timestamp;	/* time of last state change */
	/*
	 * Incore elements.
	 * they should always be at the end of this data structure.
	 */
	struct hot_spare	*hs_next;
} hot_spare_t;

#define	HS_ONDSK_STR_SIZE	offsetof(hot_spare_t, hs_next)


/*
 * Ondisk part of hot_spare_pool
 */
#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif
typedef struct hot_spare_pool_ond {
	uint_t			hsp_revision;
	hsp_t			hsp_self_id;
	mddb_recid_t		hsp_record_id;
	uint32_t		spare[4];
	int			hsp_refcount;
	int			hsp_nhotspares;
	mddb_recid_t		hsp_hotspares[1];
} hot_spare_pool_ond_t;
#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

typedef struct hot_spare_pool {
	/*
	 * incore only elements
	 */
	struct hot_spare_pool	*hsp_next;	/* hsp list, link */
	md_link_t		hsp_link;	/* next hsp (for IOCGET_NEXT) */

	/*
	 * ondisk and should be the same as hot_spare_pool_ond
	 */
	uint_t			hsp_revision;	/* revision number */
	hsp_t			hsp_self_id;	/* hsp identifier */
	mddb_recid_t		hsp_record_id;	/* db record id */
	uint32_t		spare[4];
	int			hsp_refcount;	/* # metadevices using hsp */
	int			hsp_nhotspares;	/* # hs in the pool */
	mddb_recid_t		hsp_hotspares[1];	/* array of recid's */
} hot_spare_pool_t;

#define	HSP_ONDSK_STR_OFF ((off_t)(&((hot_spare_pool_t *)0)->hsp_revision))


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MD_HOTSPARES_H */
