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

/*
 * Volume Management Mux Driver Interface
 */

#ifndef	_SYS_VOL_H
#define	_SYS_VOL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/types.h>
#include <sys/ioccom.h>
#include <sys/param.h>

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * The labelent structures tell the driver where labels might be found,
 * so the driver can watch this range of addresses and tell us
 * (via the VIE_NEWLABEL event) when someone writes to one.  It
 * also allows the driver to "blot out" the label from reads and
 * writes, if desired.
 */

struct vio_labelent {
	off_t	vl_off;		/* label offset (in bytes) */
	size_t	vl_len;		/* length of the label */
	bool_t	vl_mapout;	/* map the label out? */
};

#ifdef _SYSCALL32
struct vio_labelent32 {
	off32_t	vl_off;		/* label offset (in bytes) */
	size32_t vl_len;	/* length of the label */
	int32_t vl_mapout;	/* map the label out? */
};
#endif /* _SYSCALL32 */

/*
 * Map our unit number (vim_unit) to a dev_t representing a
 * real driver (vim_dev).
 */
struct vioc_map {
	dev_t		vim_dev;	/* device (full name) to map to */
	caddr_t		vim_path;	/* path name of device */
	size_t		vim_pathlen;	/* string + 0 */
	minor_t		vim_unit;	/* unit number (minor number) */
	dev_t		vim_basedev;	/* device to return for errs &c. */
	uint64_t	vim_id;		/* id of the volume */
	uint_t		vim_nvl;	/* number of vio_labelent structs */
	struct vio_labelent *vim_vl;	/* list of where labels are */
	uint_t		vim_flags;	/* flags */
};

#ifdef _SYSCALL32

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

struct vioc_map32 {
	dev32_t		vim_dev;	/* device (full name) to map to */
	caddr32_t	vim_path;	/* path name of device */
	size32_t	vim_pathlen;	/* string + 0 */
	minor32_t	vim_unit;	/* unit number (minor number) */
	dev32_t		vim_basedev;	/* device to return for errs &c. */
	uint64_t	vim_id;		/* id of the volume */
	uint32_t	vim_nvl;	/* number of vio_labelent structs */
	caddr32_t	vim_vl;		/* list of where labels are */
	uint32_t	vim_flags;	/* flags */
};

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#endif /* _SYSCALL32 */

#define	VIM_FLOPPY	0x0001		/* device is a floppy */
#define	VIM_RDONLY	0x0002		/* volume is read only */


#define	MAX_ATTR_LEN	128		/* max size for attr or value */

struct vioc_dattr {
	minor_t	vda_unit;			/* unit number */
	char	vda_value[MAX_ATTR_LEN];	/* value */
	int	vda_errno;			/* error */
};

#ifdef _SYSCALL32
struct vioc_dattr32 {
	minor32_t vda_unit;			/* unit number */
	char	vda_value[MAX_ATTR_LEN];	/* value */
	int32_t	vda_errno;			/* error */
};
#endif /* _SYSCALL32 */

/*
 * Passed from daemon to driver to specify what action should happen on
 * eject.  This is in response to a VIE_EJECT event.
 */
enum eject_state {
	VEJ_YES, 	/* eject is okay, send eject */
	VEJ_NO, 	/* eject is denied, don't send eject */
	VEJ_YESSTOP, 	/* eject is okay, don't send eject */
	VEJ_NONE 	/* no state */
};

struct vioc_eject {
	minor_t		viej_unit;
	enum eject_state viej_state;
};

#ifdef _SYSCALL32
struct vioc_eject32 {
	minor32_t	viej_unit;
	int32_t		viej_state;
};
#endif /* _SYSCALL32 */


struct vioc_flags {
	minor_t	vfl_unit;		/* unit number */
	uint_t	vfl_flags;		/* flags to set */
};

#ifdef _SYSCALL32
struct vioc_flags32 {
	minor32_t vfl_unit;		/* unit number */
	uint32_t vfl_flags;		/* flags to set */
};
#endif /* _SYSCALL32 */

#define	VFL_ENXIO	0x0001		/* enxio on unmap */

/*
 * structure to provide buffer size of a passed in
 * string so kernel can use ddi
 */

struct vol_str {
	caddr_t		data;		/* the addr of string */
	size_t		data_len;	/* buffer size of string */
};

#ifdef _SYSCALL32
struct vol_str32 {
	caddr32_t	data;		/* the addr of string */
	size32_t	data_len;	/* buffer size of string */
};
#endif /* _SYSCALL32 */

/*
 * returned in response to VOLIOCINFO
 */
struct vioc_info {
	uint_t		vii_inuse;	/* others using volume */
	uint64_t	vii_id;		/* id of the volume */
	caddr_t		vii_devpath;	/* path name of mapped device */
	size_t		vii_pathlen;	/* buffer size of passed in devpath */
};

#ifdef _SYSCALL32

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

struct vioc_info32 {
	uint32_t	vii_inuse;	/* others using volume */
	uint64_t	vii_id;		/* id of the volume */
	caddr32_t	vii_devpath;	/* path name of mapped device */
	size32_t	vii_pathlen;	/* buffer size of passed in devpath */
};

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#endif /* _SYSCALL32 */

struct vioc_sattr {
	caddr_t		sa_attr;	/* name of the attribute */
	caddr_t		sa_value;	/* value of the attribute */
	size_t		sa_attr_len;	/* length of str sa_attr */
	size_t		sa_value_len;	/* length of value string */
};

#ifdef _SYSCALL32
struct vioc_sattr32 {
	caddr32_t	sa_attr;	/* name of the attribute */
	caddr32_t	sa_value;	/* value of the attribute */
	size32_t	sa_attr_len;	/* length of str sa_attr */
	size32_t	sa_value_len;	/* length of value string */
};
#endif /* _SYSCALL32 */

struct vioc_gattr {
	caddr_t		ga_attr;	/* name of the attribute */
	caddr_t		ga_value;	/* value of the attribute */
	size_t		ga_val_len;	/* size of value buffer */
	size_t		ga_attr_len;	/* size of attr buffer */
};

#ifdef _SYSCALL32
struct vioc_gattr32 {
	caddr32_t	ga_attr;	/* name of the attribute */
	caddr32_t	ga_value;	/* value of the attribute */
	size32_t	ga_val_len;	/* size of value buffer */
	size32_t	ga_attr_len;	/* size of attr buffer */
};
#endif /* _SYSCALL32 */

/* for the VOLIOCSYMNAME ioctl */
struct vioc_symname {
	dev_t		sn_dev;		/* dev to find symname of */
	caddr_t		sn_symname;	/* where symname gets returned */
	size_t		sn_pathlen;	/* max length to return */
};

#ifdef _SYSCALL32
struct vioc_symname32 {
	dev32_t		sn_dev;		/* dev to find symname of */
	caddr32_t	sn_symname;	/* where symname gets returned */
	size32_t	sn_pathlen;	/* max length to return */
};
#endif /* _SYSCALL32 */

/* for the VOLIOCSYMDEV ioctl */
struct vioc_symdev {
	caddr_t		sd_symname;	/* symname to find dev name for */
	caddr_t		sd_symdevname;	/* where dev pathname gets returned */
	size_t		sd_pathlen;	/* max length to return */
	size_t		sd_symnamelen;  /* length of the symname */
};

#ifdef _SYSCALL32
struct vioc_symdev32 {
	caddr32_t	sd_symname;	/* symname to find dev name for */
	caddr32_t	sd_symdevname;	/* where dev pathname gets returned */
	size32_t	sd_pathlen;	/* max length to return */
	size32_t	sd_symnamelen;  /* length of the symname */
};
#endif /* _SYSCALL32 */

#if defined(_LONGLONG_TYPE)
#define	VOLID_TMP	0xff00000000000000ull
#else
#define	VOLID_TMP	0xff000000
#endif


/*
 * max size of a device pathname in /dev (e.g. "/dev/diskette0")
 */
#define	VOL_SYMDEV_LEN	(MAXPATHLEN)

/*
 * max size of aliases pathname in /vol (e.g. "floppy0")
 */
#define	VOL_SYMNAME_LEN	(MAXNAMELEN)


/*
 * Possible events that the drive can generate for the daemon.
 */
enum vie_event {
	VIE_MISSING, 	/* driver has no mapping */
	VIE_EJECT, 	/* eject has been requested */
	VIE_DEVERR, 	/* error seen from device */
	VIE_CLOSE, 	/* last close on device from userland */
	VIE_CANCEL,	/* user has cancelled pending i/o */
	VIE_NEWLABEL, 	/* a new label has been written to device */
	VIE_INSERT, 	/* new media has arrived */
	VIE_GETATTR, 	/* get an attribute */
	VIE_SETATTR, 	/* set an attribute */
	VIE_INUSE,	/* check to see if a device is in use */
	VIE_CHECK,	/* check a device to see if media is there */
	VIE_REMOVED,	/* media was removed from device */
	VIE_SYMNAME,	/* for volmgt_symname() */
	VIE_SYMDEV,	/* for volmgt_symdev() */
	VIE_REMOUNT	/* the medium's file system structure has changed */
};

/*
 * This structure is used for communication between the daemon and
 * the driver.
 */


struct vioc_event {
	enum vie_event	vie_type;	/* type of the event */
	union {
		/*
		 * A unit has been opened for which we don't
		 * have a mapping.
		 */
		struct ve_missing {
			minor_t	viem_unit;	/* missing unit # */
			bool_t	viem_ndelay;	/* don't look for volume */
			uid_t	viem_user;	/* uid of requester */
			dev_t	viem_tty;	/* cont tty of req */
		} vie_u_missing;
		/*
		 * A request has been made to eject a unit.
		 */
		struct ve_eject {
			minor_t	viej_unit;	/* unit eject seen on */
			uid_t	viej_user;	/* uid of requester */
			dev_t	viej_tty;	/* tty of requester */
			int	viej_force;	/* DEPRECIATED */
		} vie_u_eject;

		/*
		 * New media has arrived.
		 */
		struct ve_insert {
			dev_t	viei_dev;
		} vie_u_insert;

		/*
		 * User wants us to see if a device is in use.
		 */
		struct ve_inuse {
			dev_t	vieu_dev;
		} vie_u_inuse;

		/*
		 * User wants us to see if media has arrived in a device.
		 */
		struct ve_check {
			dev_t	viec_dev;
		} vie_u_check;

		/*
		 * An error has been returned from a device
		 */
		struct ve_error {
			dev_t	viee_dev;	/* dev_t of error */
			uint_t	viee_errno;	/* errno returned */
		} vie_u_error;

		/*
		 * "last" close on a unit.
		 */
		struct ve_close {
			minor_t	viecl_unit;	/* unit # finished with */
		} vie_u_close;

		/*
		 * user has "interrupted" (^C) a pending operation.
		 */
		struct ve_cancel {
			minor_t	viec_unit;	/* unit # aborted */
		} vie_u_cancel;

		/*
		 * New label has been written.
		 */
		struct ve_newlabel {
			minor_t	vien_unit;	/* unit # new label seen on */
		} vie_u_newlabel;

		/*
		 * Set or get an attribute
		 */
		struct ve_attr {
			minor_t	viea_unit;
			char	viea_attr[MAX_ATTR_LEN+1];
			char	viea_value[MAX_ATTR_LEN+1];
			uid_t	viea_uid;
			gid_t	viea_gid;
		} vie_u_attr;

		struct ve_rm {
			minor_t	virm_unit;
		} vie_u_rm;

		/*
		 * user wants to find the symname for a dev path
		 */
		struct ve_symname {
			dev_t	vies_dev;
		} vie_u_symname;

		/*
		 * user wants to find the dev path for a symname
		 */
		struct ve_symdev {
			char	vied_symname[VOL_SYMNAME_LEN+1];
		} vie_u_symdev;

		/*
		 * Medium's partition structure has changed
		 */
		struct ve_remount {
			minor_t	vier_unit;	/* repartitioned unit #  */
		} vie_u_remount;

	} vie_un;
};

#ifdef _SYSCALL32
struct vioc_event32 {
	int32_t	vie_type;			/* type of the event */
	union {
		/*
		 * A unit has been opened for which we don't
		 * have a mapping.
		 */
		struct ve_missing32 {
			minor32_t viem_unit;	/* missing unit # */
			int32_t	viem_ndelay;	/* don't look for volume */
			uid32_t	viem_user;	/* uid of requester */
			dev32_t	viem_tty;	/* cont tty of req */
		} vie_u_missing;

		/*
		 * A request has been made to eject a unit.
		 */
		struct ve_eject32 {
			minor32_t viej_unit;	/* unit eject seen on */
			uid32_t	viej_user;	/* uid of requester */
			dev32_t	viej_tty;	/* tty of requester */
			int32_t	viej_force;	/* DEPRECIATED */
		} vie_u_eject;

		/*
		 * New media has arrived.
		 */
		struct ve_insert32 {
			dev32_t	viei_dev;
		} vie_u_insert;

		/*
		 * User wants us to see if a device is in use.
		 */
		struct ve_inuse32 {
			dev32_t	vieu_dev;
		} vie_u_inuse;

		/*
		 * User wants us to see if media has arrived in a device.
		 */
		struct ve_check32 {
			dev32_t	viec_dev;
		} vie_u_check;

		/*
		 * An error has been returned from a device
		 */
		struct ve_error32 {
			dev32_t	viee_dev;	/* dev_t of error */
			uint32_t viee_errno;	/* errno returned */
		} vie_u_error;

		/*
		 * "last" close on a unit.
		 */
		struct ve_close32 {
			minor32_t viecl_unit;	/* unit # finished with */
		} vie_u_close;

		/*
		 * user has "interrupted" (^C) a pending operation.
		 */
		struct ve_cancel32 {
			minor32_t viec_unit;	/* unit # aborted */
		} vie_u_cancel;

		/*
		 * New label has been written.
		 */
		struct ve_newlabel32 {
			minor32_t vien_unit;	/* unit # new label seen on */
		} vie_u_newlabel;

		/*
		 * Set or get an attribute
		 */
		struct ve_attr32 {
			minor32_t viea_unit;
			char	viea_attr[MAX_ATTR_LEN+1];
			char	viea_value[MAX_ATTR_LEN+1];
			uid32_t	viea_uid;
			gid32_t	viea_gid;
		} vie_u_attr;

		struct ve_rm32 {
			minor32_t virm_unit;
		} vie_u_rm;

		/*
		 * user wants to find the symname for a dev path
		 */
		struct ve_symname32 {
			dev32_t	vies_dev;
		} vie_u_symname;

		/*
		 * user wants to find the dev path for a symname
		 */
		struct ve_symdev32 {
			char	vied_symname[VOL_SYMNAME_LEN+1];
		} vie_u_symdev;
		/*
		 * Medium has new partition structure
		 */
		struct ve_remount32 {
			minor32_t vier_unit;	/* repartitioned unit # */
		} vie_u_remount;
	} vie_un;
};
#endif /* _SYSCALL32 */

#define	vie_missing	vie_un.vie_u_missing
#define	vie_eject	vie_un.vie_u_eject
#define	vie_insert	vie_un.vie_u_insert
#define	vie_error	vie_un.vie_u_error
#define	vie_close	vie_un.vie_u_close
#define	vie_cancel	vie_un.vie_u_cancel
#define	vie_newlabel	vie_un.vie_u_newlabel
#define	vie_attr	vie_un.vie_u_attr
#define	vie_inuse	vie_un.vie_u_inuse
#define	vie_check	vie_un.vie_u_check
#define	vie_rm		vie_un.vie_u_rm
#define	vie_symname	vie_un.vie_u_symname
#define	vie_symdev	vie_un.vie_u_symdev
#define	vie_remount	vie_un.vie_u_remount

/*
 * These ioctl numbers have been allocated and approved by USL.
 */
#define	VOLIOC		('v' << 8)

/* "control" ioctls (i.e. only valid on unit 0) */
#define	VOLIOCMAP	(VOLIOC|1)	/* build a volume to device mapping */
#define	VOLIOCUNMAP	(VOLIOC|2)	/* remove a mapping */
#define	VOLIOCEVENT	(VOLIOC|3)	/* read an event */
#define	VOLIOCEJECT	(VOLIOC|4)	/* allow/deny ejection */
#define	VOLIOCDGATTR	(VOLIOC|7)	/* daemon getattr */
#define	VOLIOCDSATTR	(VOLIOC|8)	/* daemon setattr */
#define	VOLIOCDCHECK	(VOLIOC|9)	/* daemon response to check */
#define	VOLIOCDINUSE	(VOLIOC|14)	/* daemon response to inuse */
#define	VOLIOCDAEMON	(VOLIOC|15)	/* daemon set's pid */
#define	VOLIOCFLAGS	(VOLIOC|16)	/* set flags on a mapping */
#define	VOLIOCDROOT	(VOLIOC|17)	/* tell driver where vol root is */
#define	VOLIOCDSYMNAME	(VOLIOC|20)	/* for volmgt_symname() */
#define	VOLIOCDSYMDEV	(VOLIOC|21)	/* for volmgt_symdev() */
#define	VOLIOCCMINOR	(VOLIOC|24)	/* create minor unit name */
#define	VOLIOCRMINOR	(VOLIOC|25)	/* remove minor unit name */

/* "user" ioctls */
#define	VOLIOCINUSE	(VOLIOC|6)	/* is a device "in use"? */
#define	VOLIOCCHECK	(VOLIOC|5)	/* check a device for media */
#define	VOLIOCCANCEL	(VOLIOC|10)	/* cancel pending i/o */
#define	VOLIOCINFO	(VOLIOC|11)	/* get info about a volume */
#define	VOLIOCSATTR	(VOLIOC|12)	/* set an attribute */
#define	VOLIOCGATTR	(VOLIOC|13)	/* get an attribute */
#define	VOLIOCROOT	(VOLIOC|18)	/* find out where vol root is */
#define	VOLIOCSYMNAME	(VOLIOC|19)	/* for volmgt_symname() */
#define	VOLIOCSYMDEV	(VOLIOC|22)	/* for volmgt_symdev() */
#define	VOLIOCREMOUNT	(VOLIOC|23)	/* medium has new partitions */

/* Name of control port (unit 0), i.e. /dev/%s */
#define	VOLCTLNAME	"volctl"
#define	VOLUNITNAME_BLK	"u%d"
#define	VOLUNITNAME_CHR	"u%d,raw"

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VOL_H */
