/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/* Copyright (c) 2007, The Storage Networking Industry Association. */
/* Copyright (c) 1996, 1997 PDC, Network Appliance. All Rights Reserved */
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_NDMP_COMMON_H
#define	_NDMP_COMMON_H

#include <thread.h>
#include <synch.h>
#include "ndmpd_log.h"
#include "ndmp.h"
#include <unistd.h>
#include <sys/types.h>
#include <rpc/rpc.h>
#include <sys/stat.h>
#include <stdio.h>
#include <bsm/adt.h>
#include <bsm/adt_event.h>


#define	XDR_AND_SIZE(func) (bool_t(*)(XDR*, ...))xdr_##func, sizeof (func)
#define	AUTH_REQUIRED	TRUE
#define	AUTH_NOT_REQUIRED	FALSE
#define	NDMP_EOM_MAGIC	"PRCMEOM"
#define	KILOBYTE	1024

#define	INT_MAXCMD	12

extern mutex_t ndmpd_zfs_fd_lock;

/* Connection data structure. */
typedef struct msg_info {
	ndmp_header mi_hdr;
	struct ndmp_msg_handler *mi_handler;
	void *mi_body;
} msg_info_t;

typedef struct ndmp_connection {
	int conn_sock;
	XDR conn_xdrs;
	ulong_t conn_my_sequence;
	boolean_t conn_authorized;
	boolean_t conn_eof;
	msg_info_t conn_msginfo; /* received request or reply message */
	ushort_t conn_version;
	void *conn_client_data;
	mutex_t conn_lock;
	adt_session_data_t *conn_ah;
} ndmp_connection_t;

typedef void (*ndmp_con_handler_func_t) (struct ndmp_connection *);

typedef void ndmp_msg_handler_func_t(struct ndmp_connection *, void *);


typedef struct ndmp_msg_handler {
	ndmp_msg_handler_func_t *mh_func;
	bool_t(*mh_xdr_request) (XDR *xdrs, ...);
	int mh_sizeof_request;
	bool_t(*mh_xdr_reply) (XDR *xdrs, ...);
	int mh_sizeof_reply;
} ndmp_msg_handler_t;

typedef struct ndmp_handler {
	int hd_cnt;
	struct hd_messages {
		ndmp_message hm_message;
		boolean_t hm_auth_required;
		ndmp_msg_handler_t hm_msg_v[3];
	} hd_msgs[INT_MAXCMD];
} ndmp_handler_t;

/*
 * Function prototypes.
 */
extern ndmp_connection_t *ndmp_create_connection(void);

extern void ndmp_destroy_connection(ndmp_connection_t *);

extern void ndmp_close(ndmp_connection_t *);

extern int ndmp_connect(ndmp_connection_t *,
    char *,
    ulong_t);

extern int ndmp_run(ulong_t,
    ndmp_con_handler_func_t);

extern int ndmp_process_requests(ndmp_connection_t *);

extern int ndmp_send_response(ndmp_connection_t *,
    ndmp_error,
    void *);

extern int ndmp_send_request(ndmp_connection_t *,
    ndmp_message,
    ndmp_error,
    void *,
    void **);

extern int ndmp_send_request_lock(ndmp_connection_t *,
    ndmp_message,
    ndmp_error,
    void *,
    void **);

extern void ndmp_free_message(ndmp_connection_t *);

extern int ndmp_get_fd(ndmp_connection_t *);

extern void ndmp_set_client_data(ndmp_connection_t *,
    void *);

extern void *ndmp_get_client_data(ndmp_connection_t *);

extern void ndmp_set_version(ndmp_connection_t *,
    ushort_t);

extern ushort_t ndmp_get_version(ndmp_connection_t *);

extern void ndmp_set_authorized(ndmp_connection_t *,
    boolean_t);


/*
 * NDMP daemon callback functions.
 * Called by backup/recover modules.
 */
typedef char *ndmpd_get_env_func_t(void *, char *);
typedef int ndmpd_add_env_func_t(void *, char *, char *);
typedef void *ndmpd_get_name_func_t(void *, ulong_t);
typedef int ndmpd_dispatch_func_t(void *, boolean_t);
typedef void ndmpd_done_func_t(void *, int);
typedef int ndmpd_log_func_t(void *, char *, ...);

typedef int ndmpd_log_func_v3_t(void *, ndmp_log_type, ulong_t,
    char *, ...);


#define	NDMPD_SELECT_MODE_READ		1
#define	NDMPD_SELECT_MODE_WRITE		2
#define	NDMPD_SELECT_MODE_EXCEPTION	4

typedef void ndmpd_file_handler_func_t(void *, int, ulong_t);

typedef int ndmpd_add_file_handler_func_t(void *, void *, int, ulong_t,
    ndmpd_file_handler_func_t *);

typedef int ndmpd_remove_file_handler_func_t(void *, int);

typedef int ndmpd_write_func_t(void *, char *, ulong_t);

typedef int ndmpd_file_history_path_func_t(void *, char *, struct stat64 *,
    u_longlong_t);

typedef int ndmpd_file_history_dir_func_t(void *, char *, ulong_t,
    ulong_t);

typedef int ndmpd_file_history_node_func_t(void *, ulong_t, struct stat64 *,
    u_longlong_t);

typedef int ndmpd_seek_func_t(void *, u_longlong_t, u_longlong_t);

typedef int ndmpd_read_func_t(void *, char *, ulong_t);

typedef int ndmpd_file_recovered_func_t(void *, char *, int);

typedef struct ndmpd_module_stats {
	u_longlong_t ms_bytes_processed;
	u_longlong_t ms_est_bytes_remaining;
	ulong_t ms_est_time_remaining;
} ndmpd_module_stats;

/*
 * Parameter structure passed to module start function.
 */
typedef struct ndmpd_module_params {
	void *mp_daemon_cookie;
	void **mp_module_cookie;
	ushort_t mp_protocol_version;
	ndmp_data_operation mp_operation;
	ndmpd_module_stats *mp_stats;
	ndmpd_get_env_func_t *mp_get_env_func;
	ndmpd_add_env_func_t *mp_add_env_func;
	ndmpd_add_env_func_t *mp_set_env_func;
	ndmpd_get_name_func_t *mp_get_name_func;
	ndmpd_dispatch_func_t *mp_dispatch_func;
	ndmpd_done_func_t *mp_done_func;
	ndmpd_log_func_t *mp_log_func;
	ndmpd_add_file_handler_func_t *mp_add_file_handler_func;
	ndmpd_remove_file_handler_func_t *mp_remove_file_handler_func;
	ndmpd_write_func_t *mp_write_func;
	ndmpd_file_history_path_func_t *mp_file_history_path_func;
	ndmpd_file_history_dir_func_t *mp_file_history_dir_func;
	ndmpd_file_history_node_func_t *mp_file_history_node_func;
	ndmpd_read_func_t *mp_read_func;
	ndmpd_seek_func_t *mp_seek_func;
	ndmpd_file_recovered_func_t *mp_file_recovered_func;
	/*
	 * NDMP V3 params.
	 */
	ndmpd_log_func_v3_t *mp_log_func_v3;
} ndmpd_module_params_t;

#define	MOD_ADDENV(m, n, v) \
	(*(m)->mp_add_env_func)((m)->mp_daemon_cookie, n, v)

#define	MOD_SETENV(m, n, v) \
	(*(m)->mp_set_env_func)((m)->mp_daemon_cookie, n, v)

#define	MOD_GETENV(m, e) \
	(*(m)->mp_get_env_func)((m)->mp_daemon_cookie, e)

#define	MOD_GETNAME(m, i) \
	(*(m)->mp_get_name_func)((m)->mp_daemon_cookie, i)

#define	MOD_LOG(m, ...)	\
	(*(m)->mp_log_func)((m)->mp_daemon_cookie, __VA_ARGS__)

#define	MOD_READ(m, b, s) \
	(*(m)->mp_read_func)((m)->mp_daemon_cookie, b, s)

#define	MOD_WRITE(m, b, s) \
	(*(m)->mp_write_func)((m)->mp_daemon_cookie, b, s)

#define	MOD_DONE(m, e) \
	(*(m)->mp_done_func)((m)->mp_daemon_cookie, e)

#define	MOD_FILERECOVERD(m, n, e) \
	(*(m)->mp_file_recovered_func)((m)->mp_daemon_cookie, n, e)

extern int ndmp_log_msg_id;

#define	MOD_LOGV3(m, t, ...) \
	(*(m)->mp_log_func_v3)((m)->mp_daemon_cookie, (t), \
	++ndmp_log_msg_id, __VA_ARGS__)

#define	MOD_LOGCONTV3(m, t, ...) \
	(*(m)->mp_log_func_v3)((m)->mp_daemon_cookie, \
	(t), ndmp_log_msg_id, __VA_ARGS__)

/*
 * Module function prototypes.
 */
typedef int module_start_func_t(void *);
typedef int module_abort_func_t(void *);
#endif	/* _NDMP_COMMON_H */
