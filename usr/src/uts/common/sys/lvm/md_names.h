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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_MD_NAMES_H
#define	_SYS_MD_NAMES_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	NM_ALLOC_SIZE	512
#define	NM_DID_ALLOC_SIZE	1024

#define	NM_NOCOMMIT	0x0100
#define	NM_SHARED	1
#define	NM_NOTSHARED	0
#define	NM_DEVID	0x0010
#define	NM_IMP_SHARED	0x0020
#define	NM_DEVID_VALID		1
#define	NM_DEVID_INVALID	0

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

#ifdef _KERNEL
struct nm_rec_hdr {
	uint_t		r_revision;	/* revision number */
	uint_t		r_alloc_size;	/* alloc'd record size */
	uint_t		r_used_size;	/* number bytes used */
	mddb_recid_t	r_next_recid;	/* record id of next record */
	uint32_t	xr_next_rec;	/* ptr to record, calc at boot */
	mdkey_t		r_next_key;	/* Next key for alloc'd entry */
};
#else /* ! _KERNEL */
struct nm_rec_hdr {
	uint_t		r_revision;	/* revision number */
	uint_t		r_alloc_size;	/* alloc'd record size */
	uint_t		r_used_size;	/* number bytes used */
	mddb_recid_t	r_next_recid;	/* record id of next record */
	void		*r_next_rec;	/* ptr to record, calc at boot */
	mdkey_t		r_next_key;	/* Next key for alloc'd entry */
};
#endif /* _KERNEL */

struct nm_next_hdr {
	struct nm_next_hdr	*nmn_nextp;
	void			*nmn_record;
};

struct nm_shr_rec {
	struct nm_rec_hdr	sr_rec_hdr;	/* Record header */
	struct	nm_shared_name {
		mdkey_t	sn_key;		/* Unique key for this name */
		uint32_t sn_count;	/* Count of users of this name */
		uint32_t sn_data;	/* Data ptr for users (e.g., devops */
					/* sn_data NOT USED anywhere */
		ushort_t sn_namlen;	/* Length of string in nmsn_name */
		char	sn_name[1];	/* Driver/Directory name */
	} sr_name[1];
};

#define	SHR_NAMSIZ(n) \
	(((sizeof (struct nm_shared_name) - 1) + \
	    (n)->sn_namlen + (sizeof (uint_t) - 1)) & ~(sizeof (uint_t) - 1))

struct nm_rec {
	struct nm_rec_hdr	r_rec_hdr;	/* Record header */
	struct nm_name {
		side_t	n_side;		/* (key 1) side associated with */
		mdkey_t	n_key;		/* (key 2) allocated unique key */
		uint32_t n_count;	/* reference count */
		minor_t	n_minor;	/* minor number of device */
		mdkey_t	n_drv_key;	/* Key of driver name in nm_shared */
		mdkey_t	n_dir_key;	/* Key of dir. name in nm_shared */
		ushort_t n_namlen;	/* Length of string in nme_name */
		char	n_name[1];	/* Filename of device is here */
	} r_name[1];
};

#define	NAMSIZ(n) \
	(((sizeof (struct nm_name) - 1) + \
	    (n)->n_namlen + (sizeof (uint_t) - 1)) & ~(sizeof (uint_t) - 1))

/*
 * Device id support
 */
struct devid_shr_rec {
	struct nm_rec_hdr	did_rec_hdr;
	struct did_shr_name {
		mdkey_t	did_key;
		uint32_t did_count;
		uint32_t did_data;
		ushort_t did_size;
		char	did_devid[1];
	} device_id[1];
};

#define	DID_SHR_NAMSIZ(n) \
	(((sizeof (struct did_shr_name) - 1) + \
	    (n)->did_size + (sizeof (uint_t) - 1)) & ~(sizeof (uint_t) - 1))


struct devid_min_rec {
	struct nm_rec_hdr	min_rec_hdr;
	struct did_min_name {
		side_t	min_side;
		mdkey_t	min_key;
		uint32_t min_count;
		mdkey_t	min_devid_key;
		ushort_t min_namlen;
		char	min_name[1];
	} minor_name[1];
};

#define	DID_NAMSIZ(n) \
	(((sizeof (struct did_min_name) - 1) + \
	    (n)->min_namlen + (sizeof (uint_t) - 1)) & ~(sizeof (uint_t) - 1))


struct nm_header {
	uint_t			h_revision;	/* revision number */
	struct nm_rec_hdr	h_names;	/* device-name structures */
	struct nm_rec_hdr	h_shared;	/* shared structures */
};

struct nm_header_hdr {
	struct nm_header	*hh_header;
	struct nm_next_hdr	hh_names;
	struct nm_next_hdr	hh_shared;
};

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MD_NAMES_H */
