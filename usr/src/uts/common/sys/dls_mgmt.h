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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_DLS_MGMT_H
#define	_DLS_MGMT_H

#include <sys/types.h>
#include <sys/param.h>
#include <sys/zone.h>

/*
 * Data-Link Services Module
 */

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum {
	DATALINK_CLASS_PHYS		= 0x01,
	DATALINK_CLASS_VLAN		= 0x02,
	DATALINK_CLASS_AGGR		= 0x04,
	DATALINK_CLASS_VNIC		= 0x08,
	DATALINK_CLASS_ETHERSTUB	= 0x10,
	DATALINK_CLASS_SIMNET		= 0x20,
	DATALINK_CLASS_BRIDGE		= 0x40,
	DATALINK_CLASS_IPTUN		= 0x80,
	DATALINK_CLASS_PART		= 0x100
} datalink_class_t;

#define	DATALINK_CLASS_ALL	(DATALINK_CLASS_PHYS |	\
	DATALINK_CLASS_VLAN | DATALINK_CLASS_AGGR | DATALINK_CLASS_VNIC | \
	DATALINK_CLASS_ETHERSTUB | DATALINK_CLASS_SIMNET | \
	DATALINK_CLASS_BRIDGE | DATALINK_CLASS_IPTUN | DATALINK_CLASS_PART)

/*
 * A combination of flags and media.
 *   flags is the higher 32 bits, and if it is 0x01, it indicates all media
 *   types can be accepted; otherwise, only the given media type (specified
 *   in the lower 32 bits) is accepted.
 */
typedef uint64_t	datalink_media_t;

#define	DATALINK_ANY_MEDIATYPE		\
	((datalink_media_t)(((datalink_media_t)0x01) << 32))

#define	DATALINK_MEDIA_ACCEPTED(dmedia, media)				\
	(((uint32_t)(((dmedia) >> 32) & 0xfffffffful) & 0x01) ?		\
	B_TRUE : ((uint32_t)((dmedia) & 0xfffffffful) == (media)))

#define	MAXLINKATTRLEN		32
#define	MAXLINKATTRVALLEN	1024

/*
 * Link attributes used by the kernel.
 */
/*
 * The major number and instance number of the underlying physical device
 * are kept as FPHYMAJ and FPHYINST (major, instance + 1).
 *
 * Set for physical links only.
 */
#define	FPHYMAJ		"phymaj"	/* uint64_t */
#define	FPHYINST	"phyinst"	/* uint64_t */

/*
 * The devname of the physical link. For example, bge0, ce1. Set for physical
 * links only.
 */
#define	FDEVNAME	"devname"	/* string */

/*
 * The door file for the dlmgmtd (data-link management) daemon.
 */
#define	DLMGMT_TMPFS_DIR	"/etc/svc/volatile/dladm"
#define	DLMGMT_DOOR		DLMGMT_TMPFS_DIR "/dlmgmt_door"

/*
 * Door upcall commands.
 */
#define	DLMGMT_CMD_DLS_CREATE		1
#define	DLMGMT_CMD_DLS_GETATTR		2
#define	DLMGMT_CMD_DLS_DESTROY		3
#define	DLMGMT_CMD_GETNAME		4
#define	DLMGMT_CMD_GETLINKID		5
#define	DLMGMT_CMD_GETNEXT		6
#define	DLMGMT_CMD_DLS_UPDATE		7
#define	DLMGMT_CMD_LINKPROP_INIT	8
#define	DLMGMT_CMD_SETZONEID		9
#define	DLMGMT_CMD_BASE			128

/*
 * Indicate the link mapping is active or persistent
 */
#define	DLMGMT_ACTIVE		0x01
#define	DLMGMT_PERSIST		0x02

/* upcall argument */
typedef struct dlmgmt_door_arg {
	uint_t			ld_cmd;
} dlmgmt_door_arg_t;

typedef struct dlmgmt_upcall_arg_create {
	int			ld_cmd;
	datalink_class_t	ld_class;
	uint32_t		ld_media;
	boolean_t		ld_persist;
	uint64_t		ld_phymaj;
	uint64_t		ld_phyinst;
	char			ld_devname[MAXNAMELEN];
} dlmgmt_upcall_arg_create_t;

/*
 * Note: ld_padding is necessary to keep the size of the structure the
 * same on amd64 and i386.  The same note applies to other ld_padding
 * and lr_paddding fields in structures throughout this file.
 */
typedef struct dlmgmt_upcall_arg_destroy {
	int			ld_cmd;
	datalink_id_t		ld_linkid;
	boolean_t		ld_persist;
	int			ld_padding;
} dlmgmt_upcall_arg_destroy_t;

typedef struct dlmgmt_upcall_arg_update {
	int			ld_cmd;
	boolean_t		ld_novanity;
	uint32_t		ld_media;
	uint32_t		ld_padding;
	char			ld_devname[MAXNAMELEN];
} dlmgmt_upcall_arg_update_t;

typedef struct dlmgmt_upcall_arg_getattr {
	int			ld_cmd;
	datalink_id_t		ld_linkid;
	char			ld_attr[MAXLINKATTRLEN];
} dlmgmt_upcall_arg_getattr_t;

typedef struct dlmgmt_door_getname {
	int			ld_cmd;
	datalink_id_t		ld_linkid;
} dlmgmt_door_getname_t;

typedef struct dlmgmt_door_getlinkid {
	int			ld_cmd;
	char			ld_link[MAXLINKNAMELEN];
} dlmgmt_door_getlinkid_t;

typedef struct dlmgmt_door_getnext_s {
	int			ld_cmd;
	datalink_id_t		ld_linkid;
	datalink_class_t	ld_class;
	uint32_t		ld_flags;
	datalink_media_t	ld_dmedia;
} dlmgmt_door_getnext_t;

typedef struct dlmgmt_door_linkprop_init {
	int			ld_cmd;
	datalink_id_t		ld_linkid;
} dlmgmt_door_linkprop_init_t;

typedef struct dlmgmt_door_setzoneid {
	int			ld_cmd;
	datalink_id_t		ld_linkid;
	zoneid_t		ld_zoneid;
} dlmgmt_door_setzoneid_t;

/* upcall return value */
typedef struct dlmgmt_retval_s {
	uint_t			lr_err; /* return error code */
} dlmgmt_retval_t;

typedef dlmgmt_retval_t	dlmgmt_destroy_retval_t,
			dlmgmt_linkprop_init_retval_t,
			dlmgmt_setzoneid_retval_t;

struct dlmgmt_linkid_retval_s {
	uint_t			lr_err;
	datalink_id_t		lr_linkid;
	uint32_t		lr_flags;
	datalink_class_t	lr_class;
	uint32_t		lr_media;
	uint32_t		lr_padding;
};

typedef struct dlmgmt_linkid_retval_s	dlmgmt_create_retval_t,
					dlmgmt_update_retval_t,
					dlmgmt_getlinkid_retval_t,
					dlmgmt_getnext_retval_t;

typedef struct dlmgmt_getname_retval_s {
	uint_t			lr_err;
	char			lr_link[MAXLINKNAMELEN];
	datalink_class_t	lr_class;
	uint32_t		lr_media;
	uint32_t		lr_flags;
} dlmgmt_getname_retval_t;

typedef struct dlmgmt_getattr_retval_s {
	uint_t			lr_err;
	uint_t			lr_type;
	uint_t			lr_attrsz;
	uint_t			lr_padding;
	char			lr_attrval[MAXLINKATTRVALLEN];
} dlmgmt_getattr_retval_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _DLS_MGMT_H */
