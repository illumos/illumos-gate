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

#ifndef _SMBSRV_IPC_UTIL_H
#define	_SMBSRV_IPC_UTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file defines the data structure for the IPC connection and utility
 * function prototypes.
 */

#include <smbsrv/mlsvc.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	SMBRDR_IPC_MODE_ENV	  "smbrdr.ipc.mode"
#define	SMBRDR_IPC_USER_ENV	  "smbrdr.ipc.user"
#define	SMBRDR_IPC_PASSWD_ENV	  "smbrdr.ipc.passwd"

#define	IPC_MODE_STRLEN		  4
#define	IPC_MODE_ANON		  "anon"
#define	IPC_MODE_AUTH		  "auth"
#define	IPC_MODE_FALLBACK_ANON	  "fallback,anon"

#define	IPC_FLG_FALLBACK_ANON	  0x00000001
#define	IPC_FLG_NEED_VERIFY	  0x00000002

/*
 * smbrdr_ipc_t
 *
 * This structure contains information regarding the IPC configuration,
 * as well as, the authentication info needed for connecting to the
 * IPC$ share if the IPC connection is configured to be authenticated.
 *
 * IPC connection to the Primary Domain Controller [PDC] can be
 * configured to be either anonymous or authenticated. Therefore,
 * the IPC mode will be set to either one of the following values:
 *  MLSVC_IPC_ANON
 *  MLSVC_IPC_ADMIN
 *
 * The IPC_FLG_FALLBACK_ANON can be set in flags field to indicate whether
 * a fallback from authenticated IPC to anonymous IPC has occurred. This
 * flag will be unset once the join domain operation succeeds.
 */
typedef struct {
	int  mode;
	char user[MLSVC_ACCOUNT_NAME_MAX];
	char passwd[SMBAUTH_HASH_SZ];
	unsigned flags;
} smbrdr_ipc_t;


void smbrdr_ipc_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_IPC_UTIL_H */
