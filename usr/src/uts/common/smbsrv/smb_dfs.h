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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SMB_DFS_H
#define	_SMB_DFS_H

#include <sys/param.h>
#include <sys/uuid.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * DFS root or link states
 *
 * DFS_VOLUME_STATE_OK
 *    The specified DFS root or DFS link is in the normal state.
 *
 * DFS_VOLUME_STATE_INCONSISTENT
 *    The internal DFS database is inconsistent with the specified DFS root or
 *    DFS link. Attempts to repair the inconsistency have failed. This is a
 *    read-only state and MUST NOT be set by clients.
 *
 * DFS_VOLUME_STATE_OFFLINE
 *    The specified DFS root or DFS link is offline or unavailable.
 *
 * DFS_VOLUME_STATE_ONLINE
 *    The specified DFS root or DFS link is available.
 *
 * DFS_VOLUME_FLAVOR_STANDALONE	Standalone namespace
 * DFS_VOLUME_FLAVOR_AD_BLOB	Domain-based namespace
 */
#define	DFS_VOLUME_STATE_OK			0x00000001
#define	DFS_VOLUME_STATE_INCONSISTENT		0x00000002
#define	DFS_VOLUME_STATE_OFFLINE		0x00000003
#define	DFS_VOLUME_STATE_ONLINE			0x00000004
#define	DFS_VOLUME_STATE_RESYNCHRONIZE		0x00000010
#define	DFS_VOLUME_STATE_STANDBY		0x00000020
#define	DFS_VOLUME_STATE_FORCE_SYNC		0x00000040

#define	DFS_VOLUME_FLAVOR_STANDALONE		0x00000100
#define	DFS_VOLUME_FLAVOR_AD_BLOB		0x00000200

/*
 * The following bitmasks is only relevant when reading the volume state, not
 * for setting it.
 */
#define	DFS_VOLUME_STATES			0x0000000F
#define	DFS_VOLUME_FLAVORS			0x00000300

/*
 * States specified by this mask are used to perform a server operation and are
 * not persisted to the DFS metadata
 */
#define	DFS_VOLUME_STATES_SRV_OPS		0x00000070

/*
 * DFS Storage state
 */
#define	DFS_STORAGE_STATE_OFFLINE	1
#define	DFS_STORAGE_STATE_ONLINE	2

/*
 * Flags for NetrDfsAdd operation:
 *
 * 0x00000000		This creates a new link or adds a new target to an
 * 			existing link.
 *
 * DFS_ADD_VOLUME	This creates a new link in the DFS namespace if one does
 * 			not already exist or fails if a link already exists.
 *
 * DFS_RESTORE_VOLUME	This adds a target without verifying its existence.
 */
#define	DFS_CREATE_VOLUME	0x00000000
#define	DFS_ADD_VOLUME		0x00000001
#define	DFS_RESTORE_VOLUME	0x00000002

#define	DFS_MOVE_FLAG_REPLACE_IF_EXISTS		1

/*
 * See also: dfs_target_pclass_xdr()
 */
typedef enum {
	DfsInvalidPriorityClass		= -1,
	DfsSiteCostNormalPriorityClass	= 0,
	DfsGlobalHighPriorityClass	= 1,
	DfsSiteCostHighPriorityClass	= 2,
	DfsSiteCostLowPriorityClass	= 3,
	DfsGlobalLowPriorityClass	= 4
} dfs_target_pclass_t;

#define	DFS_PRIORITY_RANK_MAX		0x001F

#define	DFS_PROPERTY_FLAG_INSITE_REFERRALS	0x00000001
#define	DFS_PROPERTY_FLAG_ROOT_SCALABILITY	0x00000002
#define	DFS_PROPERTY_FLAG_SITE_COSTING		0x00000004
#define	DFS_PROPERTY_FLAG_TARGET_FAILBACK	0x00000008
#define	DFS_PROPERTY_FLAG_CLUSTER_ENABLED	0x00000010
#define	DFS_PROPERTY_FLAG_ABDE			0x00000020

#define	DFS_NAME_MAX			MAXNAMELEN
#define	DFS_PATH_MAX			MAXPATHLEN
#define	DFS_COMMENT_MAX			256
#define	DFS_SRVNAME_MAX			MAXNAMELEN

#define	DFS_REPARSE_SVCTYPE		"SMB-DFS"

#define	DFS_OBJECT_LINK		1
#define	DFS_OBJECT_ROOT		2
#define	DFS_OBJECT_ANY		3

/*
 * Referral Request Types
 * See also: dfs_reftype_xdr()
 */
typedef enum {
	DFS_REFERRAL_INVALID = 0,
	DFS_REFERRAL_DOMAIN,
	DFS_REFERRAL_DC,
	DFS_REFERRAL_SYSVOL,
	DFS_REFERRAL_ROOT,
	DFS_REFERRAL_LINK
} dfs_reftype_t;

/*
 * See also: dfs_target_priority_xdr()
 */
typedef struct dfs_target_priority {
	dfs_target_pclass_t	p_class;
	uint16_t		p_rank;
} dfs_target_priority_t;

/*
 * t_server	a null-terminated Unicode string that specifies the DFS link
 *		target host name.
 *
 * t_share	a null-terminated Unicode DFS link target share name string.
 *		This may also be a share name with a path relative to the share,
 *		for example, "share1\mydir1\mydir2". When specified this way,
 *		each pathname component MUST be a directory
 *
 * t_state	valid states are online/offline (see DFS_STORAGE_STATE_XXX in
 * 		lmdfs.h)
 *
 * t_priority	priority class and rank
 *
 * See also: dfs_target_xdr()
 */
typedef struct dfs_target {
	char			t_server[DFS_SRVNAME_MAX];
	char			t_share[DFS_NAME_MAX];
	uint32_t		t_state;
	dfs_target_priority_t	t_priority;
} dfs_target_t;

/*
 * DFS referral response
 * See also: dfs_info_xdr()
 */
typedef struct dfs_info {
	char		i_uncpath[DFS_PATH_MAX];
	char		i_comment[DFS_COMMENT_MAX];
	char		i_guid[UUID_PRINTABLE_STRING_LENGTH];
	uint32_t	i_state;
	uint32_t	i_timeout;
	uint32_t	i_propflag_mask;
	uint32_t	i_propflags;
	uint32_t	i_type;
	uint32_t	i_ntargets;
	dfs_target_t	*i_targets;
	uint32_t	i_flavor;
} dfs_info_t;

#ifdef __cplusplus
}
#endif


#endif /* _SMB_DFS_H */
