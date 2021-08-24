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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file includes structures, macros used to communicate with linkmgmt
 * daemon.
 */

#ifndef _LIBDLMGMT_H
#define	_LIBDLMGMT_H

#include <sys/types.h>
#include <libdladm.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * datalink management related macros, structures.
 */

/*
 * Door call commands.
 */
#define	DLMGMT_CMD_CREATE_LINKID	(DLMGMT_CMD_BASE + 0)
#define	DLMGMT_CMD_DESTROY_LINKID	(DLMGMT_CMD_BASE + 1)
#define	DLMGMT_CMD_REMAP_LINKID		(DLMGMT_CMD_BASE + 2)
#define	DLMGMT_CMD_CREATECONF		(DLMGMT_CMD_BASE + 3)
#define	DLMGMT_CMD_OPENCONF		(DLMGMT_CMD_BASE + 4)
#define	DLMGMT_CMD_WRITECONF		(DLMGMT_CMD_BASE + 5)
#define	DLMGMT_CMD_UP_LINKID		(DLMGMT_CMD_BASE + 6)
#define	DLMGMT_CMD_SETATTR		(DLMGMT_CMD_BASE + 7)
#define	DLMGMT_CMD_UNSETATTR		(DLMGMT_CMD_BASE + 8)
#define	DLMGMT_CMD_REMOVECONF		(DLMGMT_CMD_BASE + 9)
#define	DLMGMT_CMD_DESTROYCONF		(DLMGMT_CMD_BASE + 10)
#define	DLMGMT_CMD_GETATTR		(DLMGMT_CMD_BASE + 11)
#define	DLMGMT_CMD_GETCONFSNAPSHOT	(DLMGMT_CMD_BASE + 12)
#define	DLMGMT_CMD_ZONEBOOT		(DLMGMT_CMD_BASE + 13)
#define	DLMGMT_CMD_ZONEHALT		(DLMGMT_CMD_BASE + 14)

typedef struct dlmgmt_door_createid_s {
	int			ld_cmd;
	char			ld_link[MAXLINKNAMELEN];
	datalink_class_t	ld_class;
	uint32_t		ld_media;
	boolean_t		ld_prefix;
	uint32_t		ld_flags;
} dlmgmt_door_createid_t;

typedef struct dlmgmt_door_destroyid_s {
	int		ld_cmd;
	datalink_id_t	ld_linkid;
	uint32_t	ld_flags;
} dlmgmt_door_destroyid_t;

typedef struct dlmgmt_door_remapid_s {
	int		ld_cmd;
	datalink_id_t	ld_linkid;
	char		ld_link[MAXLINKNAMELEN];
} dlmgmt_door_remapid_t;

typedef struct dlmgmt_door_upid_s {
	int		ld_cmd;
	datalink_id_t	ld_linkid;
} dlmgmt_door_upid_t;

typedef struct dlmgmt_door_createconf_s {
	int			ld_cmd;
	char			ld_link[MAXLINKNAMELEN];
	datalink_id_t		ld_linkid;
	datalink_class_t	ld_class;
	uint32_t		ld_media;
} dlmgmt_door_createconf_t;

typedef struct dlmgmt_door_setattr_s {
	int			ld_cmd;
	int			ld_confid;
	char			ld_attr[MAXLINKATTRLEN];
	uint32_t		ld_attrsz;
	dladm_datatype_t	ld_type;
	char			ld_attrval[MAXLINKATTRVALLEN];
} dlmgmt_door_setattr_t;

typedef struct dlmgmt_door_unsetattr_s {
	int		ld_cmd;
	int		ld_confid;
	char		ld_attr[MAXLINKATTRLEN];
} dlmgmt_door_unsetattr_t;

typedef struct dlmgmt_door_writeconf_s {
	int		ld_cmd;
	int		ld_confid;
} dlmgmt_door_writeconf_t;

typedef struct dlmgmt_door_removeconf_s {
	int		ld_cmd;
	datalink_id_t	ld_linkid;
} dlmgmt_door_removeconf_t;

typedef struct dlmgmt_door_destroyconf_s {
	int		ld_cmd;
	int		ld_confid;
} dlmgmt_door_destroyconf_t;

typedef struct dlmgmt_door_openconf_s {
	int		ld_cmd;
	datalink_id_t	ld_linkid;
} dlmgmt_door_openconf_t;

typedef struct dlmgmt_door_getconfsnapshot_s {
	int		ld_cmd;
	datalink_id_t	ld_linkid;
} dlmgmt_door_getconfsnapshot_t;

typedef struct dlmgmt_door_getattr_s {
	int		ld_cmd;
	int		ld_confid;
	char		ld_attr[MAXLINKATTRLEN];
} dlmgmt_door_getattr_t;

typedef struct dlmgmt_createconf_retval_s {
	uint_t			lr_err;
	int			lr_confid;
} dlmgmt_createconf_retval_t;

typedef struct dlmgmt_openconf_retval_s {
	uint_t		lr_err;
	int		lr_confid;
} dlmgmt_openconf_retval_t;

typedef struct dlmgmt_getconfsnapshot_retval_s {
	uint_t		lr_err;
	uint32_t	lr_nvlsz;
	/* buffer for nvl */
} dlmgmt_getconfsnapshot_retval_t;

typedef struct dlmgmt_door_zone_s {
	int			ld_cmd;
	zoneid_t		ld_zoneid;
} dlmgmt_door_zoneboot_t, dlmgmt_door_zonehalt_t;

typedef struct dlmgmt_retval_s	dlmgmt_remapid_retval_t,
				dlmgmt_upid_retval_t,
				dlmgmt_destroyid_retval_t,
				dlmgmt_setattr_retval_t,
				dlmgmt_unsetattr_retval_t,
				dlmgmt_writeconf_retval_t,
				dlmgmt_removeconf_retval_t,
				dlmgmt_destroyconf_retval_t,
				dlmgmt_zoneboot_retval_t,
				dlmgmt_zonehalt_retval_t;

typedef struct dlmgmt_linkid_retval_s	dlmgmt_createid_retval_t;

#ifdef __cplusplus
}
#endif

#endif /* _LIBDLMGMT_H */
