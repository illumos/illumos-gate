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

#ifndef _SMBD_H
#define	_SMBD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <smbsrv/smb_token.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>

extern int smb_nicmon_start(void);
extern void smb_nicmon_stop(void);
extern void smb_nicmon_reconfig(void);
extern int smb_winpipe_doorsvc_start(void);
extern void smb_winpipe_doorsvc_stop(void);
extern int smb_lmshrd_srv_start(void);
extern void smb_lmshrd_srv_stop(void);

extern int smb_doorsrv_start(void);
extern void smb_doorsrv_stop(void);
extern int smb_ntgroup_doorsrv_start(void);
extern void smb_ntgroup_doorsrv_stop(void);

extern int smb_netlogon_init(void);

extern smb_token_t *smbd_user_auth_logon(netr_client_t *);
extern void smbd_user_nonauth_logon(uint32_t);
extern void smbd_user_auth_logoff(uint32_t);

typedef struct smbd {
	const char *s_version;		/* smbd version string */
	const char *s_pname;		/* basename to use for messages */
	pid_t s_pid;			/* process-ID of current daemon */
	uid_t s_uid;			/* UID of current daemon */
	gid_t s_gid;			/* GID of current daemon */
	int s_fg;			/* Run in foreground */
	int s_drv_fd;			/* Handle for SMB kernel driver */
	int s_shutdown_flag;		/* Fields for shutdown control */
	int s_sigval;
} smbd_t;

#ifdef __cplusplus
}
#endif

#endif /* _SMBD_H */
