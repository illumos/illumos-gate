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

#ifndef _SMBSRV_LMSHARE_DOOR_H
#define	_SMBSRV_LMSHARE_DOOR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <smbsrv/smbinfo.h>
#include <smbsrv/smb_common_door.h>
#include <smbsrv/smbinfo.h>

/*
 * Door interface for CIFS share management.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	LMSHR_DOOR_NAME		"/var/run/smb_lmshare_door"
#define	LMSHR_DOOR_VERSION	1

#define	LMSHR_DOOR_COOKIE	((void*)(0xdeadbeef^LMSHR_DOOR_VERSION))
#define	LMSHR_DOOR_SIZE		(sizeof (lmshare_list_t) + 32)

/*
 * Door interface
 *
 * Define door operations
 */
#define	LMSHR_DOOR_OPEN_ITERATOR	1
#define	LMSHR_DOOR_CLOSE_ITERATOR	2
#define	LMSHR_DOOR_ITERATE		3
#define	LMSHR_DOOR_NUM_SHARES		4
#define	LMSHR_DOOR_DELETE		5
#define	LMSHR_DOOR_RENAME		6
#define	LMSHR_DOOR_GETINFO		7
#define	LMSHR_DOOR_ADD			8
#define	LMSHR_DOOR_SETINFO		9
#define	LMSHR_DOOR_EXISTS		10
#define	LMSHR_DOOR_IS_SPECIAL		11
#define	LMSHR_DOOR_IS_RESTRICTED	12
#define	LMSHR_DOOR_IS_ADMIN		13
#define	LMSHR_DOOR_IS_VALID		14
#define	LMSHR_DOOR_IS_DIR		15
#define	LMSHR_DOOR_LIST			16

#define	SMB_GET_KCONFIG			17

void smb_load_kconfig(smb_kmod_cfg_t *);
void smb_dr_get_kconfig(smb_dr_ctx_t *, smb_kmod_cfg_t *);
void smb_dr_put_kconfig(smb_dr_ctx_t *, smb_kmod_cfg_t *);

/*
 * Door server status
 *
 * LMSHR_DOOR_ERROR is returned by the door server if there is problem
 * with marshalling/unmarshalling. Otherwise, LMSHR_DOOR_SUCCESS is
 * returned.
 *
 */
#define	LMSHR_DOOR_SRV_SUCCESS		0
#define	LMSHR_DOOR_SRV_ERROR		-1

/*
 * struct door_request {
 * 	int		req_type;
 *	<parameters>
 *	};
 *
 * struct door_response {
 * 	int		door_srv_status;
 *	<response>
 *	};
 */

void smb_dr_get_lmshare(smb_dr_ctx_t *, lmshare_info_t *);
void smb_dr_put_lmshare(smb_dr_ctx_t *, lmshare_info_t *);

uint64_t smb_dr_get_lmshr_iterator(smb_dr_ctx_t *);
void smb_dr_put_lmshr_iterator(smb_dr_ctx_t *, uint64_t);
void smb_dr_free_lmshr_iterator(smb_dr_ctx_t *);
void smb_dr_get_lmshr_list(smb_dr_ctx_t *, lmshare_list_t *);
void smb_dr_put_lmshr_list(smb_dr_ctx_t *, lmshare_list_t *);

void lmshrd_door_close(void);

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_LMSHARE_DOOR_H */
