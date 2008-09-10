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


#ifndef __MMS_API_H
#define	__MMS_API_H

#define	MMS_API_VERSION	1000

#define	MMS_API_RSP_UNACC	0
#define	MMS_API_RSP_ACC	1
#define	MMS_API_RSP_FINAL	2
#define	MMS_API_RSP_FINAL_INTR	3
#define	MMS_API_RSP_FINAL_ERR	4
#define	MMS_API_RSP_FINAL_CANC	5
#define	MMS_API_RSP_EVENT	7

#define	MMS_API_NO	0
#define	MMS_API_YES	1

#define	MMS_API_OK	0
#define	MMS_API_ERROR	1

#define	MMS_API_UNCONFIG	0
#define	MMS_API_CONFIG		1
#define	MMS_API_FAILURE	2

#define	MMS_API_ASYNC	1
#define	MMS_API_SYNC	2

typedef struct mms_event {
	int	mms_ev_code;
	void	*mms_ev_data;
} mms_event_t;

typedef struct mms_ev_volume {
	char	*mms_ev_volume_name;
	char	*mms_ev_media_type;
} mms_ev_volume_t;

typedef struct mms_ev_library {
	char	*mms_ev_inst_name;
	char	*mms_ev_lib_name;
} mms_ev_library_t;

typedef struct mms_ev_dm {
	char	*mms_ev_inst_name;
	char	*mms_ev_drive_name;
	char	*mms_ev_host;
} mms_ev_dm_t;

typedef struct mms_ev_message {
	char	*mms_ev_who;
	char	*mms_ev_id;
	char	*mms_ev_client;
	char	*mms_ev_inst;
	char	*mms_ev_level;
	char	*mms_ev_text;
	char	*mms_ev_msg;
} mms_ev_message_t;

typedef struct mms_rsp_ele {
	mms_list_node_t	mms_rsp_next;
	int		mms_rsp_type;		/* Type of response or */
						/* event type */
	char		*mms_rsp_tid;		/* Task id of response or */
						/* event tag */
	char		*mms_rsp_str;		/* Response or event string */
	mms_par_node_t	*mms_rsp_cmd;		/* Parse tree of string */
} mms_rsp_ele_t;

typedef struct mms_send_ele {
	mms_list_node_t	mms_send_next;
	char		*mms_send_tid;		/* Task id of cmd to be sent */
						/* over a async connection */
	char		*mms_send_cmd;		/* Command to be sent */
} mms_send_ele_t;

typedef struct mms_cmd_ele {
	mms_list_node_t	mms_cmd_next;
	int		mms_cmd_type;		/* Type of command async,sync */
	char		*mms_cmd_tid;		/* Task id of outstanding cmd */
	char		*mms_cmd_cmd;		/* Outstanding command */
	void		(*mms_cmd_callbk)(void *arg, void *arg1);
						/* If async cmd, callback */
						/* function to use for */
						/* response */
	void		*mms_cmd_callbk_param;	/* User param to be sent to */
						/* callback function */
} mms_cmd_ele_t;

typedef struct	mms_callbk {
	void		(*mms_func)(void *arg); /* Callback */
	void		*mms_param;		/* Callback parameter */
} mms_callbk_t;

typedef struct	mms_rsp_callbk {
	void		(*mms_func)(void *arg, void *arg1);
						/* Callback */
	void		*mms_param;		/* Callback parameter */
} mms_rsp_callbk_t;

typedef struct mms_session {
	mms_list_t		mms_cmd_list;	/* Outstanding command list */
	mms_list_t		mms_rsp_list;	/* Sync commands final */
						/* response list */
	mms_list_t		mms_ev_list;	/* List of events received */
	int		mms_thrd_cnt;		/* Number of outstanding */
						/* threads in session */
	int		mms_api_state;		/* Current state of the */
						/* connection, config, */
						/* unconfig, or error */
	int		mms_api_mode;		/* Type of connection, SYNC */
						/* or combination with ASYNC */
	int		mms_api_errcode;	/* If a internal processing */
						/* error occurs this get */
						/* set to show what caused */
						/* the error to happen */
	int		mms_api_rstarted;	/* For async mode, tells when */
						/* reader thread has started */
	char		*mms_acc_tid;		/* Task id of cmd waiting on */
						/* accept response */
	boolean_t	mms_be_pending;	/* begin-end sequence pending */
	char		*cprefix;		/* Set by the client to tag */
						/* who is using the API */
	void	(*clog) (char *, char *);	/* Function to use to log */
						/* API errors into the */
						/* clients log file */
	mms_rsp_ele_t	*mms_acc_rsp;		/* Pointer to the latest */
						/* accept/unaccept response */
	mms_t	mms_conn;			/* MMS socket connection */
						/* structure pointer */
	pthread_mutex_t	mms_cnt_mutex;		/* Controls access to */
						/* mms_thrd_cnt */
	pthread_cond_t	mms_cnt_cv;		/* Used for waking up thread */
						/* waiting to shutdown the */
						/* session when all */
						/* outstanding threads */
						/* to MM have stopped */
	pthread_mutex_t	mms_cmd_mutex;		/* Controls access to */
						/* mms_cmd_list */
	pthread_mutex_t mms_cacc_mutex;	/* Stops other send cmds */
						/* from sending their cmds */
						/* until current cmd gets */
						/* acc/unacc response */
	pthread_mutex_t mms_acc_mutex;		/* Stops the reader thread */
						/* and the thread waiting on */
						/* acc/unacc response from */
						/* accessing shared memory */
						/* at the same time */
	pthread_cond_t	mms_acc_cv;		/* Used for waking up thread */
						/* waiting on accept/unaccept */
						/* response */
	pthread_mutex_t	mms_rsp_mutex;		/* Controls access to sync */
						/* cmds response list */
	pthread_cond_t	mms_rsp_cv;		/* Used for waking up threads */
						/* waiting on a final rsp */
	pthread_mutex_t mms_conn_mutex;	/* Controls socket access */
						/* to MMS */
	pthread_mutex_t mms_reading;		/* Controls reading from MMS */
						/* socket */
	pthread_mutex_t	mms_be_mutex;		/* Controls begin-end's to */
						/* send */
	pthread_cond_t	mms_be_cv;
						/* thread in async mode */
	pthread_attr_t	mms_reader_attr;	/* Attribute for aysnc reader */
						/* thread */
	void	(*mms_async_error)(void *arg);	/* Used in case an internal */
						/* processing error is */
						/* encountered using a ASYNC */
						/* connection to notify the */
						/* client of the failure */
	void		*mms_async_error_param; /* Error callback parameter */
	void		(*mms_ev_callbk)(void *arg, void *arg1);
						/* Event callback */
	void		*mms_ev_callbk_param;	/* Event callback parameter */
	pthread_mutex_t	mms_ev_mutex;		/* Controls access to event */
						/* list */
	pthread_cond_t	mms_ev_cv;		/* Used to wake up threads */
						/* waiting on events */
} mms_session_t;

int mms_init(void **, int *);
int mms_ainit(void **, int *, mms_callbk_t *, mms_rsp_callbk_t *);
int mms_hello(void *, char *, char *, char *, char *, char *, char *, char *,
		    void *);
int mms_hello_net(void *, mms_network_cfg_t *, char *, void *);

int mms_goodbye(void *, int);
int mms_agoodbye(void *, int);

void *mms_api_reader(void *);
void *mms_api_writer(void *);

void mms_send_errmsg(mms_session_t *sp, int msgid, ...);
int mms_handle_err_rsp(void *, int *, int *, char **);

int mms_send_cmd(void *, char *, void **);
int mms_send_acmd(void *, char *, void (*)(), void *);
int mms_read_response(void *, char *, void **);
int mms_obtain_response(mms_session_t *, char *, mms_rsp_ele_t **, int);

int mms_read_event(void *, void **);
int mms_obtain_event(mms_session_t *, mms_rsp_ele_t **);
void mms_free_event(void *);

void mms_free_rsp(void *);
void mms_free_cmd(mms_cmd_ele_t *);
void mms_free_send(mms_send_ele_t *);
char *mms_get_attribute(void *, char *, void **);

mms_rsp_ele_t *mms_gen_err_rsp(char *, int, char *);

void mms_serr(mms_trace_sev_t, char *, int, const char *, ...);

extern char mms_empty_string[];

/* This may need to be part of a session to show which events a */
/* session of the api has registered for */
extern char *mms_notify[];
extern char *mms_event[];
extern char *mms_scope[];
extern char *mms_api[];

/* MACROS */

#define	mms_set_errlog(session, log) {			\
		((mms_session_t *)session)->clog = log;	\
	}
#define	mms_set_errpfx(session, prefix) {				\
		((mms_session_t *)session)->cprefix = strdup(prefix);	\
	}
#define	mms_rsp_type(rsp) ((mms_rsp_ele_t *)rsp)->mms_rsp_type
#define	mms_event_type(rsp) ((mms_rsp_ele_t *)rsp)->mms_rsp_tid
#define	mms_get_tree(rsp) ((mms_rsp_ele_t *)rsp)->mms_rsp_cmd
#define	mms_get_str(rsp) ((mms_rsp_ele_t *)rsp)->mms_rsp_str
#define	mms_state_failed(_sess) \
	((mms_session_t *)(_sess))->mms_api_state != MMS_API_CONFIG

#endif /* __MMS_API_H */
