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

#ifndef _INETD_IMPL_H
#define	_INETD_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * Header file containing inetd's shared types/data structures and
 * function declarations.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <rpc/rpc.h>
#include <assert.h>
#include <libscf.h>
#include <libinetutil.h>
#include <inetsvc.h>
#include <librestart.h>
#include <libuutil.h>
#include <wordexp.h>


/*
 * Number of consecutive retries of a repository operation that failed due
 * to a broken connection performed before giving up and failing.
 */
#define	REP_OP_RETRIES 10

/* retryable SMF method error */
#define	SMF_EXIT_ERR_OTHER 1

/* inetd's syslog ident string */
#define	SYSLOG_IDENT    "inetd"

/* Is this instance currently executing a method ? */
#define	INST_IN_TRANSITION(i)	((i)->next_istate != IIS_NONE)

/* Names of properties that inetd uses to store instance state. */
#define	PR_NAME_NON_START_PID	"non_start_pid"
#define	PR_NAME_START_PIDS	"start_pids"
#define	PR_NAME_CUR_INT_STATE	"cur_state"
#define	PR_NAME_NEXT_INT_STATE	"next_state"

/* Name of the property group that holds debug flag */
#define	PG_NAME_APPLICATION_CONFIG	"config"

/* Name of the property which holds the debug flag value */
#define	PR_NAME_DEBUG_FLAG	"debug"

/*
 * Instance states used internal to svc.inetd.
 * NOTE: The states table in cmd/cmd-inetd/inetd/inetd.c relies on the
 * ordering of this enumeration, so take care if modifying it.
 */
typedef enum {
	IIS_UNINITIALIZED,
	IIS_ONLINE,
	IIS_IN_ONLINE_METHOD,
	IIS_OFFLINE,
	IIS_IN_OFFLINE_METHOD,
	IIS_DISABLED,
	IIS_IN_DISABLE_METHOD,
	IIS_IN_REFRESH_METHOD,
	IIS_MAINTENANCE,
	IIS_OFFLINE_CONRATE,
	IIS_OFFLINE_BIND,
	IIS_OFFLINE_COPIES,
	IIS_DEGRADED,
	IIS_NONE
} internal_inst_state_t;

/*
 * inetd's instance methods.
 * NOTE: The methods table in cmd/cmd-inetd/inetd/util.c relies on the
 * ordering of this enumeration, so take care if modifying it.
 */
typedef enum {
	IM_START,
	IM_ONLINE,
	IM_OFFLINE,
	IM_DISABLE,
	IM_REFRESH,
	NUM_METHODS,
	IM_NONE
} instance_method_t;

/* Collection of information pertaining to a method */
typedef struct {
	char *exec_path;	/* path passed to exec() */

	/*
	 * Structure returned from wordexp(3c) that contains an expansion of the
	 * exec property into a form suitable for exec(2).
	 */
	wordexp_t	exec_args_we;

	/*
	 * Copy of the first argument of the above wordexp_t structure in the
	 * event that an alternate arg0 is provided, and we replace the first
	 * argument with the alternate arg0. This is necessary so the
	 * contents of the wordexp_t structure can be returned to their
	 * original form as returned from wordexp(3c), which is a requirement
	 * for calling wordfree(3c), wordexp()'s associated cleanup routine.
	 */
	const char	*wordexp_arg0_backup;

	/* time a method can run for before being considered broken */
	int		timeout;
} method_info_t;

typedef struct {
	basic_cfg_t	*basic;
	method_info_t	*methods[NUM_METHODS];
} instance_cfg_t;

/*
 * Structure used to construct a list of int64_t's and their associated
 * scf values. Used to store lists of process ids, internal states, and to
 * store the associated scf value used when writing the values back to the
 * repository.
 */
typedef struct {
	int64_t		val;
	scf_value_t	*scf_val;
	uu_list_node_t	link;
} rep_val_t;

/* Structure containing the state and configuration of a service instance. */
typedef struct {
	char			*fmri;

	/* fd we're going to take a connection on */
	int			conn_fd;

	/* number of copies of this instance active */
	int64_t			copies;

	/* connection rate counters */
	int64_t			conn_rate_count;
	time_t			conn_rate_start;

	/* failure rate counters */
	int64_t			fail_rate_count;
	time_t			fail_rate_start;
	/* bind failure count */
	int64_t			bind_fail_count;

	/* pids of currently running methods */
	uu_list_t		*non_start_pid;
	uu_list_t		*start_pids;

	/* ctids of currently running start methods */
	uu_list_t		*start_ctids;

	/* remote address, used for TCP tracing */
	struct sockaddr_storage	remote_addr;

	internal_inst_state_t	cur_istate;
	internal_inst_state_t	next_istate;

	/* repository compatible versions of the above 2 states */
	uu_list_t		*cur_istate_rep;
	uu_list_t		*next_istate_rep;

	/*
	 * Current instance configuration resulting from its repository
	 * configuration.
	 */
	instance_cfg_t		*config;

	/*
	 * Soon to be applied instance configuration. This configuration was
	 * read during a refresh when this instance was online, and the
	 * instance needed taking offline for this configuration to be applied.
	 * The instance is currently on its way offline, and this configuration
	 * will become the current configuration when it arrives there.
	 */
	instance_cfg_t		*new_config;

	/* current pending conrate-offline/method timer; -1 if none pending */
	iu_timer_id_t		timer_id;

	/* current pending bind retry timer; -1 if none pending */
	iu_timer_id_t		bind_timer_id;

	/*
	 * Flags that assist in the fanout of an instance arriving in the
	 * offline state on-route to some other state.
	 */
	boolean_t		disable_req;
	boolean_t		maintenance_req;
	boolean_t		conn_rate_exceeded;
	boolean_t		bind_retries_exceeded;

	/*
	 * Event waiting to be processed. RESTARTER_EVENT_TYPE_INVALID is used
	 * to mean no event waiting.
	 */
	restarter_event_type_t	pending_rst_event;

	/* link to next instance in list */
	uu_list_node_t		link;
} instance_t;


/* Structure used to store information pertaining to instance method types. */
typedef struct {
	instance_method_t	method;
	const char		*name;
	internal_inst_state_t	dst_state;
} method_type_info_t;


extern uu_list_t *instance_list;
extern struct pollfd *poll_fds;
extern nfds_t num_pollfds;
extern method_type_info_t methods[];
extern iu_tq_t *timer_queue;
extern uu_list_pool_t *conn_ind_pool;
extern boolean_t debug_enabled;

/*
 * util.c
 */
extern void msg_init(void);
extern void msg_fini(void);
/* PRINTFLIKE1 */
extern void debug_msg(const char *, ...);
/* PRINTFLIKE1 */
extern void error_msg(const char *, ...);
/* PRINTFLIKE1 */
extern void warn_msg(const char *, ...);
extern void poll_fini(void);
extern boolean_t isset_pollfd(int);
extern void clear_pollfd(int);
extern int set_pollfd(int, uint16_t);
extern struct pollfd *find_pollfd(int);
extern int safe_read(int, void *, size_t);
extern boolean_t copies_limit_exceeded(instance_t *);
extern void cancel_inst_timer(instance_t *);
extern void cancel_bind_timer(instance_t *);
extern void enable_blocking(int);
extern void disable_blocking(int);

/*
 * tlx.c
 */
extern rpc_info_t *create_rpc_info(const char *, const char *, const char *,
    int, int);
extern void destroy_rpc_info(rpc_info_t *);
extern boolean_t rpc_info_equal(const rpc_info_t *, const rpc_info_t *);
extern int register_rpc_service(const char *, const rpc_info_t *);
extern void unregister_rpc_service(const char *, const rpc_info_t *);
extern int create_bound_endpoint(const instance_t *, tlx_info_t *);
extern void close_net_fd(instance_t *, int);
extern int tlx_accept(const char *, tlx_info_t *, struct sockaddr_storage *);
extern struct t_call *dequeue_conind(uu_list_t *);
extern int queue_conind(uu_list_t *, struct t_call *);
extern void tlx_fini(void);
extern int tlx_init(void);
extern boolean_t tlx_info_equal(const tlx_info_t *, const tlx_info_t *,
    boolean_t);
extern void consume_wait_data(instance_t *, int);

/*
 * config.c
 */
extern int config_init(void);
extern void config_fini(void);
extern boolean_t socket_info_equal(const socket_info_t *, const socket_info_t *,
    boolean_t);
extern boolean_t method_info_equal(const method_info_t *,
    const method_info_t *);
extern struct method_context *read_method_context(const char *, const char *,
    const char *, const char **);
extern void destroy_instance_cfg(instance_cfg_t *);
extern instance_cfg_t *read_instance_cfg(const char *);
extern boolean_t bind_config_equal(const basic_cfg_t *, const basic_cfg_t *);
extern int read_enable_merged(const char *, boolean_t *);
extern void refresh_debug_flag(void);

/*
 * repval.c
 */
extern void repval_fini(void);
extern int repval_init(void);
extern uu_list_t *create_rep_val_list(void);
extern void destroy_rep_val_list(uu_list_t *);
extern scf_error_t store_rep_vals(uu_list_t *, const char *, const char *);
extern scf_error_t retrieve_rep_vals(uu_list_t *, const char *, const char *);
extern rep_val_t *find_rep_val(uu_list_t *, int64_t);
extern int set_single_rep_val(uu_list_t *, int64_t);
extern int64_t get_single_rep_val(uu_list_t *);
extern int add_rep_val(uu_list_t *, int64_t);
extern void remove_rep_val(uu_list_t *, int64_t);
extern void empty_rep_val_list(uu_list_t *);
extern int make_handle_bound(scf_handle_t *);
extern int add_remove_contract(instance_t *, boolean_t, ctid_t);
extern int iterate_repository_contracts(instance_t *, int);

/*
 * contracts.c
 */
extern int contract_init(void);
extern void contract_fini(void);
void contract_postfork(void);
int contract_prefork(const char *, int);
extern int get_latest_contract(ctid_t *cid);
extern int adopt_contract(ctid_t, const char *);
extern int abandon_contract(ctid_t);

/*
 * inetd.c
 */
extern void process_offline_inst(instance_t *);
extern void process_non_start_term(instance_t *, int);
extern void process_start_term(instance_t *);
extern void remove_method_ids(instance_t *, pid_t, ctid_t, instance_method_t);

/*
 * env.c
 */
char **set_smf_env(struct method_context *, instance_t *, const char *);

/*
 * wait.c
 */
extern int register_method(instance_t *, pid_t, ctid_t cid, instance_method_t);
extern int method_init(void);
extern void method_fini(void);
extern void process_terminated_methods(void);
extern void unregister_instance_methods(const instance_t *);
extern void method_preexec(void);

#ifdef __cplusplus
}
#endif

#endif /* _INETD_IMPL_H */
