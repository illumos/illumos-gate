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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
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

void smbd_report(const char *fmt, ...);
int smbd_pipesvc_start(void);
void smbd_pipesvc_stop(void);
int smbd_share_start(void);
void smbd_share_stop(void);
int smbd_nicmon_start(const char *);
void smbd_nicmon_stop(void);
int smbd_nicmon_refresh(void);
int smbd_dc_monitor_init(void);
void smbd_dc_monitor_refresh(void);
smb_token_t *smbd_user_auth_logon(smb_logon_t *);
void smbd_user_nonauth_logon(uint32_t);
void smbd_user_auth_logoff(uint32_t);
void smbd_join(smb_joininfo_t *, smb_joinres_t *);
void smbd_set_secmode(int);
boolean_t smbd_online(void);
void smbd_online_wait(const char *);
void smbd_get_authconf(smb_kmod_cfg_t *);

void smbd_spool_start(void);
void smbd_spool_stop(void);
int smbd_cups_init(void);
void smbd_cups_fini(void);
void smbd_load_printers(void);

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
	int		s_debug;	/* Enable debug output */
	int		s_dbg_stop;	/* stop for debugger attach */
	boolean_t	s_initialized;
	boolean_t	s_shutting_down; /* shutdown control */
	volatile uint_t	s_refreshes;
	boolean_t	s_kbound;	/* B_TRUE if bound to kernel */
	int		s_authsvc_sock;
	int		s_door_lmshr;
	int		s_door_srv;
	int		s_door_opipe;
	int		s_secmode;	/* Current security mode */
	char		s_site[MAXHOSTNAMELEN];
	smb_inaddr_t	s_pdc;
	boolean_t	s_pdc_changed;
	pthread_t	s_refresh_tid;
	pthread_t	s_authsvc_tid;
	pthread_t	s_localtime_tid;
	pthread_t	s_spool_tid;
	pthread_t	s_dc_monitor_tid;
	boolean_t	s_nbt_listener_running;
	boolean_t	s_tcp_listener_running;
	pthread_t	s_nbt_listener_id;
	pthread_t	s_tcp_listener_id;
	boolean_t	s_fatal_error;
} smbd_t;

extern smbd_t smbd;

#define	SMBD_LOG_MSGSIZE	256

#define	SMBD_DOOR_NAMESZ	16

typedef struct smbd_door {
	mutex_t		sd_mutex;
	cond_t		sd_cv;
	uint32_t	sd_ncalls;
	char		sd_name[SMBD_DOOR_NAMESZ];
} smbd_door_t;

#define	SMBD_ARG_MAGIC		0x53415247	/* 'SARG' */

/*
 * Parameter for door operations.
 */
typedef struct smbd_arg {
	uint32_t	magic;
	list_node_t	lnd;
	smb_doorhdr_t	hdr;
	const char	*opname;
	char		*data;
	size_t		datalen;
	char		*rbuf;
	size_t		rsize;
	boolean_t	response_ready;
	boolean_t	response_abort;
	uint32_t	status;
} smbd_arg_t;

int smbd_door_start(void);
void smbd_door_stop(void);
void smbd_door_init(smbd_door_t *, const char *);
void smbd_door_fini(smbd_door_t *);
void smbd_door_enter(smbd_door_t *);
void smbd_door_return(smbd_door_t *, char *, size_t, door_desc_t *, uint_t);

void *smbd_door_dispatch_op(void *);

int smbd_authsvc_start(void);
void smbd_authsvc_stop(void);

/* For fksmbd */
void fksmbd_init(void);
int fksmbd_door_dispatch(smb_doorarg_t *);

#ifdef __cplusplus
}
#endif

#endif /* _SMBD_H */
