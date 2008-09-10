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

#ifndef __LM_H
#define	__LM_H


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <syslog.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uuid.h>
#include <limits.h>
#include <pthread.h>
#include <libintl.h>
#include <mms_list.h>
#include <mms_parser.h>
#include <mms_cores.h>
#include <mms_sym.h>
#include <mms_network.h>
#include <mms_trace.h>
#include <mms_strapp.h>
#include <mms_cfg.h>
#include <mms_cat.h>
#include <mms_lm_msg.h>
#include <lm_cmd_fmt.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	JDP	1

#define	CMDPATH_DIRECTORY "/usr/lib/mms/lm/lib"
#define	LM_TRACE_DIR "/var/log/mms/lm"

#define	TRACEFN_LEN PATH_MAX
#define	CFGFN_LEN PATH_MAX
#define	MSGCATFN_LEN PATH_MAX

#define	SUPPORT_LMP_VERSION "1.0"

#define	SPM_CONN_MIN 1
#define	SPM_CONN_MAX 100
#define	SPM_CONN_DEFAULT 30

#define	SPM_IDLE_TIME_MIN 1
#define	SPM_IDLE_TIME_MAX 600
#define	SPM_IDLE_TIME_DEFAULT 60

#define	DB_IDLE_TIME_MIN 1
#define	DB_IDLE_TIME_MAX 60
#define	DB_IDLE_TIME_DEFAULT 5

#define	MAX_NUM_BAYS	4	/* Max number of bays in any supported */
				/* library, Needs to be updated if a new */
				/* library is added with a greater number */

typedef void *lm_cmdHandle_t;

typedef struct lm {
	mms_network_cfg_t	lm_net_cfg;		/* lm network config */
	char		lm_tracefn[TRACEFN_LEN];	/* mms_trace filename */
	char		lm_msgcatfn[MSGCATFN_LEN];	/* message catalog */
	char		lm_manf[20];		/* Manufacturer of library */
	char		*lm_name;		/* Device path if direct att */
	char		*lm_type;		/* Type of library */
	char		*lm_conn;		/* Type of library connection */
	char		lm_ip[20];	/* IP mms_address if network att */
	char		lm_path[256];		/* Device path if direct att */
	int		lm_acs;			/* ACS for STK library */
	int		lm_lsm;			/* LSM for STK library */
	int		lm_ssiport;		/* Port Number for SSI */
	int		lm_lsms;		/* Number of lsms in library */
	int		lm_panels;		/* Num of panels in library */
	int		lm_caps;		/* Number of caps in library */
	int		lm_disk_timeout;	/* Disk library timeout for */
						/* stat of files on nfs */
	void		*lm_port;		/* Ptr to struct containing */
						/* port information */
	void		*lm_drive;		/* Ptr to struct containing */
						/* drive information */
	lm_cmdHandle_t	lm_cmdHandle;		/* Handle for cmd file */
	mms_t		lm_mms_conn;		/* Used for connection */
	mms_err_t	lm_mms_err;
	void		*lm_ssl_data;		/* SSL data */
} lm_t;

/*
 *  Thread structure for LM's threads
 *  Structure representing basic threads within LM
 */

typedef struct lm_queue_ele {
	struct lm_queue_ele	*lmqe_next;
	pthread_mutex_t		lmqe_mutex;
	pthread_cond_t		lmqe_rv;
	int			lmqe_cindex;	/* cmdData index for LMPM cmd */
	char			*lmqe_tid;	/* tid of cmd being prcessed */
	void			*lmqe_cmd_tree;
} lm_queue_ele_t;


typedef struct lm_queue {
	pthread_mutex_t	lmq_mutex;	/* protect access to queues */
	pthread_cond_t	lmq_cv;		/* queue control */
	pthread_attr_t	lmq_attr;	/* create detached threads */
	lm_queue_ele_t	*lmq_first;	/* queue */
	lm_queue_ele_t	*lmq_last;	/* queue */
	int		lmq_valid;
	int		lmq_quit;	/* queue should quit */
	int		lmq_parallel;	/* maximum number of worker threads */
	int		lmq_counter;	/* current number of worker threads */
	int		lmq_idle;	/* number of idle threads */
	void		(*lmq_worker)(void *arg);	/* worker code */
} lm_queue_t;

/*
 * Structure to keep track of work and response queues
 */
#define	SIZE_RSP_ARRAY	8		/* Number of possible outstanding */
					/* LMPL commands. This should be */
					/* kept the same size as */
					/* LM_NUM_WRK_THRDS */

typedef struct lmpl_rsp_node {
	mms_list_node_t		lmpl_rsp_next;	/* ptr to the next response */
						/* used for intermediate and */
						/* final responses */
	int			lmpl_rsp_type;	/* indicates type of response */
						/* intermediate or final */
	mms_par_node_t		*lmpl_rsp_tree; /* the parse tree of the rsp */
} lmpl_rsp_node_t;

typedef struct lmpl_rsp_ele {

	mms_list_t		lmpl_rsp_list;  /* list of final responses */
						/* since there can be */
						/* intermediate and final */
						/* responses for a lmpl cmd */


	pthread_mutex_t		lmpl_rsp_mutex; /* used to tell command */
						/* processing thread a */
						/* response is available */
	pthread_cond_t		lmpl_rsp_cv;
	int			lmpl_rsp_final;	/* Indicates a final response */
						/* was received for lmpl cmd */
	void			*lmpl_acc_tree; /* the accept response parse */
						/* tree for the lmpl command */
} lmpl_rsp_ele_t;

typedef struct lmpl_rsp {
	pthread_mutex_t	rspq_mutex;	/* Controls access to response array */
					/* as a new LMPL cmd is being added */
					/* or one is being deleted */
	lmpl_rsp_ele_t	*rspq_cmd[SIZE_RSP_ARRAY];
	int		rspq_tid;	/* Task ID of LMPL cmd waiting on */
					/* an accept unaccept response from */
					/* MM. This also represents the */
					/* index into the response arrary of */
					/* the cmd being processed by MM */
} lmpl_rsp_t;

typedef struct lm_cmdData {
	char	*cmd;		/* Name of command */
	char	*cd_symName;	/* Symbol name of object */
	int	(*cd_cmdptr)();	/* Ptr to cmd entry point from shared lib */
} lm_cmdData_t;


/* Global definitions */

extern lm_t		lm;
extern int		lm_daemon_mode;
extern int		lm_message_level;
extern int		lm_state;
extern int		exit_code;
extern int		lm_internal_error;
extern lm_queue_t 	lm_cmdq;
extern lmpl_rsp_t	lm_rspq;
extern pthread_mutex_t	lm_acc_mutex;
extern pthread_mutex_t	lm_write_mutex;
extern lm_cmdData_t	lm_cmdData[];


/* Indexs for the different possible LMPM commands */

#define	LM_MOUNT	0
#define	LM_UNMOUNT	1
#define	LM_MOVE		2
#define	LM_INJECT	3
#define	LM_SCAN		4
#define	LM_ACTIVATE	5
#define	LM_RESET	6
#define	LM_EJECT	7
#define	LM_BARRIER	8
#define	LM_PRIVATE	9
#define	LM_CANCEL	10
#define	LM_EXIT		11
#define	LM_EVENT	12
#define	LM_NULL_CMD	13
#define	LM_C_ACTIVATE	14
#define	LM_C_PRIVATE	15
#define	LM_C_EXIT	16
#define	LM_C_RESET	17
#define	LM_C_EVENT	18
#define	LM_C_INTERNAL	19

/* Possible states of LM */

#define	LM_STOP		0x0
#define	LM_NOT_ACTIVE	0x1
#define	LM_NOT_READY	0x2
#define	LM_BROKEN	0x4
#define	LM_DISCONNECTED	0x8
#define	LM_ACTIVE	0x10

/* Possible state for ready command */

#define	LM_READY	0
#define	LM_NOT		1
#define	LM_DISCONN	2
#define	LM_BROKE	3
#define	LM_PRESENT	4

/* Masks that show which commands can execute in above states */

#define	LM_MASK0	0x1E	/* Cmds which can execute in not-ready */
				/* broken, disconnected, and active states */
				/* barrier, cancel */
#define	LM_MASK1	0x19	/* Cmds which can execute in not-active */
				/* disconnected, and active states only */
				/* activate */
#define	LM_MASK2	0x10	/* Cmds which can execute in active state */
				/* only. mount, unmount, move, inject, */
				/* eject, scan */

/* Exit codes for when LM exits */

#define	LM_NORMAL	0	/* Means LM exited by an exit command */
#define	LM_NON_RESTART	1	/* Means LM exited due to exit command */
#define	LM_RESTART	2	/* Means LM exited due to reset command */
#define	LM_SIG_NRESTART	3	/* Means LM exited due to a sigterm */
#define	LM_SIG_RESTART	4	/* Means LM exited due to a sighup */

#define	LM_OK 0
#define	LM_ERROR -1
#define	LM_NOMEM 1
#define	LM_NO_WCR 2
#define	LM_NO_MM 3
#define	LM_SYNTAX_ERR 4
#define	LM_SYNTAX_RSP 5
#define	LM_SYNTAX_CMD 6

#define	LM_NO	0
#define	LM_YES	1

#define	LMPL_FINAL_OK 0
#define	LMPL_FINAL_INTER 1
#define	LMPL_FINAL_ERROR 2
#define	LMPL_FINAL_CANCEL 3
#define	LMPL_FINAL_INVALID 4
#define	LMPL_UNACCEPTABLE 5
#define	LMPL_ACCEPT 6
#define	LMPL_WAITING 7

#define	LM_NUM_WRK_THRDS 8	/* Number of cmd processing threads that can */
				/* be started at one time. There can never be */
				/* more than this num of threads started to */
				/* process LMPM cmds. The current number 8 is */
				/* just an arbitray num picked. After testing */
				/* a different num may be choosen to better */
				/* fit what is needed by LM to process cmds. */
				/* Keep SIZE_RSP_ARRAY the same size as this */

#define	LM_SELECT_WAIT	5	/* Number of seconds to wait on pselect */
				/* before breaking out */
#define	LM_THREAD_WAIT	LM_SELECT_WAIT

				/* The default number of seconds to wait */
				/* on stats of disk cartridges */
#define	LM_DISK_TIMEOUT	5

/* Types of connections supported */

#define	LM_GENERIC		0
#define	LM_DIRECT_ATTACHED	1
#define	LM_NETWORK_ATTACHED	2

/* Buffer sizes */

#define	RMBUFSIZE	2048
#define	FSBUFSIZE	2056

#ifdef	__cplusplus
}
#endif

#endif	/* __LM_H */
