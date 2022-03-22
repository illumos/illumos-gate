/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Joyent, Inc.
 */

#ifndef _SYS_OVERLAY_COMMON_H
#define	_SYS_OVERLAY_COMMON_H

/*
 * Common overlay definitions
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum overlay_target_mode {
	OVERLAY_TARGET_NONE = 0x0,
	OVERLAY_TARGET_POINT,
	OVERLAY_TARGET_DYNAMIC
} overlay_target_mode_t;

typedef enum overlay_plugin_dest {
	OVERLAY_PLUGIN_D_INVALID	= 0x0,
	OVERLAY_PLUGIN_D_ETHERNET	= 0x1,
	OVERLAY_PLUGIN_D_IP		= 0x2,
	OVERLAY_PLUGIN_D_PORT		= 0x4,
	OVERLAY_PLUGIN_D_MASK		= 0x7
} overlay_plugin_dest_t;

typedef enum overlay_prop_type {
	OVERLAY_PROP_T_INT = 0x1,	/* signed int */
	OVERLAY_PROP_T_UINT,		/* unsigned int */
	OVERLAY_PROP_T_IP,		/* sinaddr6 */
	OVERLAY_PROP_T_STRING		/* OVERLAY_PROP_SIZEMAX */
} overlay_prop_type_t;

typedef enum overlay_prop_prot {
	OVERLAY_PROP_PERM_REQ	= 0x1,
	OVERLAY_PROP_PERM_READ	= 0x2,
	OVERLAY_PROP_PERM_WRITE	= 0x4,
	OVERLAY_PROP_PERM_RW	= 0x6,
	OVERLAY_PROP_PERM_RRW	= 0x7,
	OVERLAY_PROP_PERM_MASK	= 0x7
} overlay_prop_prot_t;

#define	OVERLAY_PROP_NAMELEN	64
#define	OVERLAY_PROP_SIZEMAX	256
#define	OVERLAY_STATUS_BUFLEN	256

#ifdef __cplusplus
}
#endif

#endif /* _SYS_OVERLAY_COMMON_H */
