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

#ifndef __OBJ_H
#define	__OBJ_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/vtoc.h>

/*
 * local include files
 */

#include "partition.h"

/*
 * Object types
 */
#ifdef notdef
#define	OBJ_DIR		1	/* directory */
#define	OBJ_VOL		2	/* volume */
#define	OBJ_LINK	3	/* hard link */
#define	OBJ_SYMLINK	4	/* symbolic link */
#endif

/*
 * These are the object independent attributes, and control
 * structures.
 */
typedef struct obj {
	struct q	q;		/* for future use */
	struct dbops	*o_dbops;	/* database this object is in */
	char		*o_name;	/* name of the object */
	char		*o_dir;		/* directory it lives in */
	u_longlong_t	o_xid;		/* version we have a copy of */
	uint_t		o_type;		/* type of object */
	u_longlong_t	o_id;		/* unique id for the object */
	uid_t		o_uid;		/* user id of the owner */
	gid_t		o_gid;		/* group id */
	mode_t		o_mode;		/* unix permissions */
	uint_t		o_nlinks;	/* hard link count */
	struct timeval  o_atime;	/* access time */
	struct timeval  o_ctime;	/* creation time */
	struct timeval  o_mtime;	/* modified time */
	u_longlong_t	o_upmask;	/* bitmask of changed fields */
	char		*o_props;	/* property string for object */
	int		o_pad[10];	/* room to grow */
} obj_t;

#define	OBJ_UP_NAME	0x001
#define	OBJ_UP_DIR	0x002
#define	OBJ_UP_UID	0x004
#define	OBJ_UP_GID	0x008
#define	OBJ_UP_MODE	0x010
#define	OBJ_UP_ATIME	0x020
#define	OBJ_UP_CTIME	0x040
#define	OBJ_UP_MTIME	0x080
#define	OBJ_UP_LABEL	0x100
#define	OBJ_UP_LOC	0x200
#define	OBJ_UP_FLAGS	0x400
#define	OBJ_UP_NLINKS	0x800
/*
 * define enum for file systems supported by volmgt
 */
typedef	enum	volfs {
	V_FDISK,
	V_HSFS,
	V_PCFS,
	V_SOLARIS,
	V_UDFS,
	V_UFS,
	V_UNKNOWN
} volfs_t;

/*
 * The volume object.
 */
typedef struct vol {
	obj_t		v_obj;		/* object stuff */
	char		*v_mtype;	/* volume type (cdrom, floppy, ..) */
	label 		v_label;	/* volume label */
	ulong_t		v_parts;	/* per-vol partitions (bitmap) */
	bool_t		v_confirmed;	/* it is really there */
	devmap_t	*v_devmap;	/* map of devices (from v_basedev) */
	uchar_t		v_ndev;		/* number of devmaps */
	dev_t		v_basedev;	/* base device of location */
	char		*v_location;	/* location string */
	struct clue {
		minor_t		c_volume;	/* volume event happened on */
		uid_t		c_uid;		/* uid causing trouble */
		dev_t		c_tty;		/* his controlling tty */
		struct ve_error	*c_error;	/* error info */
	} v_clue; /* Hint for the various user friendy action features */
	ulong_t		v_eject;	/* count of outstanding eject acts */
	bool_t		v_ejfail;	/* failed the ejection */
	bool_t		v_ej_inprog;	/* ejection in progress */
	bool_t		v_ej_force;	/* already gone! */
	bool_t		v_checkresp;	/* respond to check request */
	ulong_t		v_flags;	/* per-vol flags (bitmap) */
	volfs_t		v_fstype;
	char		v_pcfs_part_id[4]; /* 32-bit string */
	char		v_mount_mode[4];   /* 32-bit  string */
	partition_handle_t  v_partitionp;    /* partition this volume is in */
	medium_handle_t	v_mediump;	/* medium this volume is on */
	dev_t		v_device;	/* device this volume is on */
	int32		v_pad[8];	/* room to grow */
} vol_t;

/*
 * fields in v_flags
 */
#define	V_TAPE		0x1	/* volume is a tape (not a disk) */
#define	V_NETWIDE	0x2	/* available all over the network */
#define	V_FREE1		0x4	/* unused flag */
#define	V_UNLAB		0x8	/* volume is unlabeled */
#define	V_RDONLY	0x10	/* read-only media */
#define	V_WORM		0x20	/* write once/read many */
#define	V_NEWLABEL	0x40	/* new label has been written */
#define	V_RMONEJECT	0x80	/* remove on eject */
#define	V_MEJECTABLE	0x100	/* can be easily manually ejected */
#define	V_MISSING	0x200	/* missing event has been seen */
#define	V_UNMAPPED	0x400	/* unmapping worked, so can free the unit */
#define	V_CTLVOL	0x800	/* volume for the "nomedia" device node */

/*
 * Defs to identify partitions
 */

/* for pcfs, currently only supporting 4, will change for extended p's */
#define	V_DOSFAT	0x1	/* simple dos fs with no fdisk	*/
#define	V_P1		0x2	/* fdisk, partition 'C'		*/
#define	V_P2		0x4	/* fdisk, partition 'D'		*/
#define	V_P3		0x8	/* fdsik, partition 'E'		*/
#define	V_P4		0x10	/* fdisk, partition 'F'		*/

/* for ufs, id'ing max of 16 slices */
#define	V_S0		0x1	/* slice s0 */
#define	V_S1		0x2	/* slice s1 */
#define	V_S2		0x4	/* slice s2 */
#define	V_S3		0x8	/* slice s3 */
#define	V_S4		0x10	/* slice s4 */
#define	V_S5		0x20
#define	V_S6		0x40
#define	V_S7		0x80
#define	V_S8		0x100
#define	V_S9		0x200
#define	V_S10		0x400
#define	V_S11		0x800
#define	V_S12		0x1000
#define	V_S13		0x2000
#define	V_S14		0x4000
#define	V_S15		0x8000

/* disk partition information */

#ifdef	TAPES_SUPPORTED
/* tape behavior */
#define	V_REWIND	0x100	/* rewind on close */
#define	V_SVR4		0x200	/* svr4 mode (blech) */
#define	V_DENSMSK	0xc00	/* mask for density */
#endif

/* tape and floppy densities */
#define	V_DENS_L	0x000	/* low density */
#define	V_DENS_M	0x400	/* medium density */
#define	V_DENS_H	0x800	/* high density */
#define	V_DENS_U	0xc00	/* ultra density */

#define	V_ENXIO		0x10000	/* return enxio till last close */
#ifdef	notdef
#define	V_FREE3		0x20000	/* free from here on */
#endif


/*
 * The directory object.
 */
typedef struct dirat {
	obj_t		da_obj;
	int		da_pad[10];
} dirat_t;

/*
 * For the links, we keep the pointers as paths, and only resolve
 * them to a vvnode when we actually do the lookup on them.
 */

/*
 * The symbolic link object.
 */
typedef struct symat {
	obj_t		sla_obj;
	char		*sla_ptr;	/* who it points at */
	int		sla_pad[10];
} symat_t;

/*
 * The hard link object.
 */
typedef struct linkat {
	obj_t		la_obj;
	u_longlong_t	la_id;		/* id of the object we point to */
	int		la_pad[10];
} linkat_t;

/*
 * The partition object.
 */
typedef struct partat {
	obj_t		pa_obj;
	int		pa_pad[10];
} partat_t;

/*
 * change the attribute of a database object.
 */
extern void change_name(obj_t *obj, char *name);
extern void change_dir(obj_t *obj, char *dir);
extern void change_uid(obj_t *obj, uid_t uid);
extern void change_gid(obj_t *obj, gid_t gid);
extern void change_mode(obj_t *obj, mode_t mode);
extern void change_atime(obj_t *obj, struct timeval *tv);
extern void change_mtime(obj_t *obj, struct timeval *tv);
extern void change_ctime(obj_t *obj, struct timeval *tv);

/*
 * these only apply to volumes
 */
extern void change_location(obj_t *obj, char *path);
extern void change_flags(obj_t *obj);
extern void change_label(obj_t *obj, label *la);

extern obj_t	*obj_dup(obj_t *);
extern char 	*obj_basepath(obj_t *);

#ifdef	__cplusplus
}
#endif

#endif /* __OBJ_H */
