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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SMBD_H
#define	_SMBD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <thread.h>
#include <synch.h>
#include <smbsrv/smb_ioctl.h>
#include <smbsrv/smb_token.h>
#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>

int smbd_opipe_start(void);
void smbd_opipe_stop(void);
int smbd_share_start(void);
void smbd_share_stop(void);
boolean_t smbd_set_netlogon_cred(void);
int smbd_locate_dc_start(void);
smb_token_t *smbd_user_auth_logon(smb_logon_t *);
void smbd_user_nonauth_logon(uint32_t);
void smbd_user_auth_logoff(uint32_t);
uint32_t smbd_join(smb_joininfo_t *);
void smbd_set_secmode(int);
boolean_t smbd_online(void);

int smbd_vss_get_count(const char *, uint32_t *);
void smbd_vss_get_snapshots(const char *, uint32_t, uint32_t *,
    uint32_t *, char **);
int smbd_vss_map_gmttoken(const char *, char *, char *);

typedef struct smbd {
	const char	*s_version;	/* smbd version string */
	const char	*s_pname;	/* basename to use for messages */
	pid_t		s_pid;		/* process-ID of current daemon */
	uid_t		s_uid;		/* UID of current daemon */
	gid_t		s_gid;		/* GID of current daemon */
	int		s_fg;		/* Run in foreground */
	boolean_t	s_initialized;
	boolean_t	s_shutting_down; /* shutdown control */
	volatile uint_t	s_sigval;
	volatile uint_t	s_refreshes;
	boolean_t	s_kbound;	/* B_TRUE if bound to kernel */
	int		s_door_lmshr;
	int		s_door_srv;
	int		s_door_opipe;
	int		s_secmode;	/* Current security mode */
	boolean_t	s_nbt_listener_running;
	boolean_t	s_tcp_listener_running;
	pthread_t	s_nbt_listener_id;
	pthread_t	s_tcp_listener_id;
	boolean_t	s_fatal_error;
} smbd_t;

#define	SMBD_DOOR_NAMESZ	16

typedef struct smbd_door {
	mutex_t		sd_mutex;
	cond_t		sd_cv;
	uint32_t	sd_ncalls;
	char		sd_name[SMBD_DOOR_NAMESZ];
} smbd_door_t;

int smbd_door_start(void);
void smbd_door_stop(void);
void smbd_door_init(smbd_door_t *, const char *);
void smbd_door_fini(smbd_door_t *);
void smbd_door_enter(smbd_door_t *);
void smbd_door_return(smbd_door_t *, char *, size_t, door_desc_t *, uint_t);

#ifdef __cplusplus
}
#endif

#endif /* _SMBD_H */
