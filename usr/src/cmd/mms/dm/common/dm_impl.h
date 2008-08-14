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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef	__DM_IMPL_H
#define	__DM_IMPL_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/ksynch.h>
#include <netdb.h>
#include <mms_network.h>
#include <dmd_impl.h>
#include <mms_parser.h>
#include <dm_drive.h>
#include <mms_sock.h>

typedef	struct	dm_wka {
	uint64_t	dm_flags;
	int		dm_counter;
	pid_t		dm_pid;			/* drive manager's pid */
	pid_t		dm_app_pid;		/* targ opend by this app */
	int		dm_drm_fd;		/* drive manager dev fd */

	/*
	 * dm_drm_path is the pseudo device the DM opens for its own use.
	 */
	char		*dm_drm_path;		/* drive manager path */
						/* /devices/pseudo/dmd0:1drm */
	major_t		dm_drm_major;		/* major of dm_drm_path */
	minor_t		dm_drm_minor;		/* minor of dm_drm_path */

	/*
	 * dm_targ_base_major and dm_targ_base_minor are major and minor
	 * numbers of the target base device, i.e. /dev/rmt/x.
	 */
	char		*dm_target_base;	/* base device of target */
	major_t		dm_targ_base_major;	/* major of target base */
	minor_t		dm_targ_base_minor;	/* minor of target base */
	/*
	 * dm_targ_hdl is the pathname DM returns to the client.
	 */
	char		*dm_targ_hdl;		/* target handle for client */
	/*
	 * dm_hdl_major and dm_hdl_id are major and minor device numbers
	 * of dm_targ_hdl.
	 * dm_hdl_major is the same as dm_drm_major.
	 * dm_hdl_minor is a unique id which is used as the minor device number
	 * and is mapped to (dm_drm_minor + 1).
	 */
	major_t		dm_hdl_major;		/* handle major */
	minor_t		dm_hdl_minor;		/* handle minor == handle id */

	char		*dm_host;
	char		*dm_port;
	char		*dm_passwd;
	char		*dm_mm_passwd;
	int		dm_ssl_enabled;
	char		*dm_ssl_cert_file;
	char		*dm_ssl_pass;
	char		*dm_ssl_pass_file;
	char		*dm_ssl_crl_file;
	char		*dm_ssl_peer_file;
	char		*dm_ssl_cipher;
	void		*dm_ssl_data;
	char		*dm_hdl_prefix;
	char		dm_local_hostname[MAXHOSTNAMELEN + 1];
	/* local hostname */
	mms_t		dm_mms_conn;		/* mm connection */
	void		*dm_default_lib_hdl;
	void		*dm_dev_lib_hdl;
	int		dm_msg_level;
	int		dm_cmd_dispatchable;
	mms_list_t	dm_cmd_queue;		/* active cmd queue */
	mms_list_t	dm_pend_ack_queue;	/* cmds not accepted yet */
	pthread_cond_t	dm_accept_cv;
	char		*dm_dev_lib;
	pthread_mutex_t	dm_io_mutex;		/* lock for I/O */
	drm_request_t	*dm_request;
	drm_request_t	dm_reqbuf;
	char		*dm_pwbuf;		/* _SC_GETPW_R_SIZE_MAX */
	int		dm_pwbuf_size;

	/*
	 * If both dm_queue_mutex and dm_worker_mutex must be held,
	 * lock dm_queue_mutex first before locking dm_worker_mutex.
	 */
	pthread_mutex_t	dm_queue_mutex;		/* lock for cmd queues */
	pthread_mutex_t	dm_worker_mutex;	/* lock for worker thread */
	pthread_cond_t	dm_work_cv;
	pthread_mutex_t	dm_tdv_close_mutex;
	pthread_cond_t	dm_tdv_close_cv;
	int		dm_work_todo;		/* work todo flag */
	struct	timeval	dm_mnt_start;		/* mount start time */
	struct	timeval	dm_mnt_done;		/* mount done time */
	struct	timeval	dm_mnt_time;		/* mount time */
}	dm_wka_t;

/*
 * DM flags
 */
#define	DM_SILENT		(1LL << 0)	/* Silent - no mms_trace */
#define	DM_OPENED		(1LL << 1)	/* File opened */
#define	DM_ENABLED		(1LL << 2)	/* DM is enabled */
#define	DM_SEND_CAPACITY	(1LL << 3)	/* Send capacity */
#define	DM_HAVE_SESSION		(1LL << 4)	/* Opened session with MM */
#define	DM_NOT_USED		(1LL << 5)	/* Not used */
#define	DM_SEND_EOF_POS		(1LL << 6)
#define	DM_PREEMPT_RSV		(1LL << 7)
#define	DM_ASK_PREEMPT_RSV	(1LL << 8)	/* ask if DM_PREEMPT_RSV */
#define	DM_RESERVE_DRIVE	(1LL << 9)	/* Issue reserve drive */
#define	DM_USE_PRSV		(1LL << 10)	/* Use persistent reserve out */
#define	DM_DEV_LIB_LOADED	(1LL << 11)	/* device lib loaded */
#define	DM_DFLT_LIB_LOADED	(1LL << 12)	/* default lib loaded */
#define	DM_EXIT_NORESTART	(1LL << 13)	/* DM is terminating */


typedef	struct	dm_command	{
	mms_list_node_t	cmd_next;
	int		cmd_flags;
	int		cmd_state;		/* Continue from state */
	int		cmd_rc;			/* return code from send */
	mms_par_node_t	*cmd_root;		/* command root node */
	char		*cmd_task;		/* task string */
	int		(*cmd_func)(struct dm_command *);
	char		*cmd_textcmd;
	pthread_cond_t	cmd_done_cv;
	pthread_mutex_t	cmd_done_mutex;
}	dm_command_t;

#define	CMD_DISPATCHABLE	0x01
#define	CMD_INCOMING		0x02
#define	CMD_COMPLETE		0x04

#define	DM_OPEN_RETRIES		30
#define	DM_OPEN_INTERVAL	3	/* number of seconds between attempts */
#define	DM_CONNECT_INTERVAL	3	/* number of seconds between attempts */
#define	DM_WRITE_ACCEPT		1

#define	DM_DEV_LIB_DIR	"/usr/lib/mms/dm"
#define	DM_TRACE_DIR	"/var/log/mms/dm"
#define	MMS_AUTHNAME	"solaris.mms.io.*"

#define	DM_COMPLETE		1		/* command completed */
#define	DM_CONTINUE		2		/* will continue */
#define	DM_NOT_COMPLETE		3		/* not complete yet */
#define	DM_ERROR		(-1)
#define	DM_PARTIAL_WRITE	(-2)
#define	DM_RESTART		2
#define	DM_NO_RESTART		1

extern	dm_wka_t		*wka;

#define	DM_REP_RESPONDED	"1000"		/* Response message id */
#define	DM_REP_UNATTNDED	"1001"		/* Unattended message id */
#define	DM_REP_ERROR		(-1)
#define	DM_REP_YES		0x01
#define	DM_REP_NO		0x02
#define	DM_REP_UNATTENDED	0x04
#define	DM_REP_STRING		0x08
#define	DM_REP_ABORT		0x10
#define	DM_REP_RETRY		0x20
#define	DM_FAILED		0x01

#define	DM_EXIT(code)	dm_exit(code, _SrcFile, __LINE__)

#ifdef	__cplusplus
}
#endif

#endif	/* __DM_IMPL_H */
