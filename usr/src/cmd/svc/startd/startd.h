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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2015, Joyent, Inc. All rights reserved.
 */

#ifndef	_STARTD_H
#define	_STARTD_H

#include <sys/time.h>
#include <librestart.h>
#include <librestart_priv.h>
#include <libscf.h>
#include <libsysevent.h>
#include <libuutil.h>
#include <pthread.h>
#include <synch.h>
#include <stdio.h>
#include <syslog.h>
#include <umem.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * We want MUTEX_HELD, but we also want pthreads.  So we're stuck with this
 * for the native build, at least until the build machines can catch up
 * with the latest version of MUTEX_HELD() in <synch.h>.
 */
#if defined(NATIVE_BUILD)
#undef	MUTEX_HELD
#define	MUTEX_HELD(m)		_mutex_held((mutex_t *)(m))
#endif

#ifndef NDEBUG

#define	MUTEX_LOCK(mp)	{						\
	int err;							\
	if ((err = pthread_mutex_lock((mp))) != 0) {			\
		(void) fprintf(stderr,					\
		    "pthread_mutex_lock() failed on %s:%d: %s\n",	\
		    __FILE__, __LINE__, strerror(err));			\
		abort();						\
	}								\
}

#define	MUTEX_UNLOCK(mp)	{					\
	int err;							\
	if ((err = pthread_mutex_unlock((mp))) != 0) {			\
		(void) fprintf(stderr,					\
		    "pthread_mutex_unlock() failed on %s:%d: %s\n",	\
		    __FILE__, __LINE__, strerror(err));			\
		abort();						\
	}								\
}

#else

#define	MUTEX_LOCK(mp)		(void) pthread_mutex_lock((mp))
#define	MUTEX_UNLOCK(mp)	(void) pthread_mutex_unlock((mp))

#endif

#define	bad_error(func, err)					\
	uu_panic("%s:%d: %s() failed with unexpected "		\
	    "error %d.  Aborting.\n", __FILE__, __LINE__, (func), (err));

#define	min(a, b)	(((a) < (b)) ? (a) : (b))

#define	FAULT_COUNT_INCR	0
#define	FAULT_COUNT_RESET	1

#define	FAULT_THRESHOLD		3

#define	MAX_CONFIGD_RETRIES	5
#define	MAX_EMI_RETRIES		5
#define	MAX_MOUNT_RETRIES	5
#define	MAX_SULOGIN_RETRIES	5

#define	RETURN_SUCCESS		0
#define	RETURN_RETRY		-1
#define	RETURN_FATAL		-2

#define	LIBSCF_SUCCESS		0
#define	LIBSCF_PROPERTY_ABSENT	-1
#define	LIBSCF_PGROUP_ABSENT	-2
#define	LIBSCF_PROPERTY_ERROR	-3

#define	METHOD_START		0
#define	METHOD_STOP		1
#define	METHOD_REFRESH		2

#define	METHOD_TIMEOUT_INFINITE	0

/*
 * Contract cookies used by startd.
 */
#define	CONFIGD_COOKIE		0x10
#define	SULOGIN_COOKIE		0x11
#define	METHOD_START_COOKIE	0x20
#define	METHOD_OTHER_COOKIE	0x21
#define	MONITOR_COOKIE		0x30
#define	EMI_COOKIE		0x31


#define	ALLOC_RETRY		3
#define	ALLOC_DELAY		10
#define	ALLOC_DELAY_MULT	10

#define	safe_scf_scope_create(h)	\
	libscf_object_create((void *(*)(scf_handle_t *))scf_scope_create, (h))
#define	safe_scf_service_create(h)	\
	libscf_object_create((void *(*)(scf_handle_t *))scf_service_create, (h))
#define	safe_scf_instance_create(h)	libscf_object_create(	\
	(void *(*)(scf_handle_t *))scf_instance_create, (h))
#define	safe_scf_snapshot_create(h)	libscf_object_create(	\
	(void *(*)(scf_handle_t *))scf_snapshot_create, (h))
#define	safe_scf_snaplevel_create(h)	libscf_object_create(	\
	(void *(*)(scf_handle_t *))scf_snaplevel_create, (h))
#define	safe_scf_pg_create(h)		\
	libscf_object_create((void *(*)(scf_handle_t *))scf_pg_create, (h))
#define	safe_scf_property_create(h)	libscf_object_create(	\
	(void *(*)(scf_handle_t *))scf_property_create, (h))
#define	safe_scf_value_create(h)	\
	libscf_object_create((void *(*)(scf_handle_t *))scf_value_create, (h))
#define	safe_scf_iter_create(h)		\
	libscf_object_create((void *(*)(scf_handle_t *))scf_iter_create, (h))
#define	safe_scf_transaction_create(h)	libscf_object_create(	\
	(void *(*)(scf_handle_t *))	scf_transaction_create, (h))
#define	safe_scf_entry_create(h)	\
	libscf_object_create((void *(*)(scf_handle_t *))scf_entry_create, (h))

#define	startd_alloc(sz)	\
	startd_alloc_retry((void *(*)(size_t, int))umem_alloc, (sz))
#define	startd_zalloc(sz)	\
	startd_alloc_retry((void *(*)(size_t, int))umem_zalloc, (sz))


extern pthread_mutexattr_t mutex_attrs;

/*
 * Definitions for administrative actions.
 *   Note that the ordering in admin_action_t, admin_actions, and admin_events
 *   must match.  admin_actions and admin_events are defined in startd.c.
 */
#define	NACTIONS			6

typedef enum {
	ADMIN_EVENT_DEGRADED = 0x0,
	ADMIN_EVENT_MAINT_OFF,
	ADMIN_EVENT_MAINT_ON,
	ADMIN_EVENT_MAINT_ON_IMMEDIATE,
	ADMIN_EVENT_REFRESH,
	ADMIN_EVENT_RESTART
} admin_action_t;

extern const char * const admin_actions[NACTIONS];
extern const int admin_events[NACTIONS];

#define	LOG_DATE_SIZE	32	/* Max size of timestamp in log output */

extern ssize_t max_scf_name_size;
extern ssize_t max_scf_value_size;
extern ssize_t max_scf_fmri_size;

extern mode_t fmask;
extern mode_t dmask;

#define	LOG_PREFIX_EARLY	"/etc/svc/volatile/"
#define	LOG_PREFIX_NORMAL	"/var/svc/log/"

#define	LOG_SUFFIX		".log"

#define	STARTD_DEFAULT_LOG	"svc.startd.log"
#define	EMI_LOG ((const char *) "system-early-manifest-import:default.log")

extern const char *log_directory;	/* Current log directory path */

#define	FS_TIMEZONE_DIR		"/usr/share/lib/zoneinfo"
#define	FS_LOCALE_DIR		"/usr/lib/locale"

/*
 * Simple dictionary representation.
 */
typedef struct dictionary {
	uu_list_t		*dict_list;
	int			dict_new_id;
	pthread_mutex_t		dict_lock;
} dictionary_t;

typedef struct dict_entry {
	int			de_id;
	const char		*de_name;
	uu_list_node_t		de_link;
} dict_entry_t;

extern dictionary_t *dictionary;

typedef struct timeout_queue {
	uu_list_t		*tq_list;
	pthread_mutex_t		tq_lock;
} timeout_queue_t;

typedef struct timeout_entry {
	hrtime_t		te_timeout;	/* timeout expiration time */
	ctid_t			te_ctid;
	char			*te_fmri;
	char			*te_logstem;
	volatile int		te_fired;
	uu_list_node_t		te_link;
} timeout_entry_t;

extern timeout_queue_t *timeouts;

/*
 * State definitions.
 */
typedef enum {
	STATE_NONE = 0x0,
	STATE_UNINIT,
	STATE_MAINT,
	STATE_OFFLINE,
	STATE_DISABLED,
	STATE_ONLINE,
	STATE_DEGRADED
} instance_state_t;

#define	STATE_MAX	(STATE_DEGRADED + 1)

extern const char * const instance_state_str[STATE_MAX];

typedef enum {
	GVT_UNSUPPORTED = -1,
	GVT_UNKNOWN = 0,
	GVT_SVC,		/* service */
	GVT_INST,		/* instance */
	GVT_FILE,		/* file: */
	GVT_GROUP		/* dependency group */
} gv_type_t;

typedef enum {
	DEPGRP_UNSUPPORTED = -1,
	DEPGRP_REQUIRE_ANY = 1,
	DEPGRP_REQUIRE_ALL,
	DEPGRP_EXCLUDE_ALL,
	DEPGRP_OPTIONAL_ALL
} depgroup_type_t;

typedef enum {
	METHOD_RESTART_UNKNOWN = -1,
	METHOD_RESTART_ALL = 0,
	METHOD_RESTART_EXTERNAL_FAULT,
	METHOD_RESTART_ANY_FAULT,
	METHOD_RESTART_OTHER
} method_restart_t;

typedef enum {
	PROPAGATE_START,
	PROPAGATE_STOP,
	PROPAGATE_SAT
} propagate_event_t;

/*
 * Graph representation.
 */
#define	GV_CONFIGURED	0x01	/* Service exists in repository, ready */
#define	GV_ENABLED	0x02	/* Service should be online */
#define	GV_ENBLD_NOOVR	0x04	/* GV_ENABLED, ignoring override */
#define	GV_INSUBGRAPH	0x08	/* Current milestone depends on service */
#define	GV_DEATHROW	0x10	/* Service is on deathrow */
#define	GV_TOOFFLINE	0x20	/* Services in subtree to offline */
#define	GV_TODISABLE	0x40	/* Services in subtree to disable */

/* ID must come first to support search */
typedef struct graph_vertex {
	int				gv_id;
	char				*gv_name;
	uu_list_node_t			gv_link;

	uint_t				gv_flags;
	restarter_instance_state_t	gv_state;

	gv_type_t			gv_type;

	depgroup_type_t			gv_depgroup;
	restarter_error_t		gv_restart;

	void				(*gv_start_f)(struct graph_vertex *);
	void				(*gv_post_online_f)(void);
	void				(*gv_post_disable_f)(void);

	int				gv_restarter_id;
	evchan_t			*gv_restarter_channel;

	int				gv_delegate_initialized;
	evchan_t			*gv_delegate_channel;

	uu_list_t			*gv_dependencies;
	uu_list_t			*gv_dependents;

	/*
	 * gv_refs represents the number of references besides dependencies.
	 * The vertex cannot be removed when gv_refs > 0.
	 *
	 * Currently, only relevant for GVT_SVC and GVT_INST type vertices.
	 */
	int 				gv_refs;

	int32_t				gv_stn_tset;
	int32_t				gv_reason;
} graph_vertex_t;

typedef struct graph_edge {
	graph_vertex_t	*ge_vertex;
	uu_list_node_t	ge_link;
	graph_vertex_t	*ge_parent;
} graph_edge_t;

int libscf_get_info_events_all(scf_propertygroup_t *);
int32_t libscf_get_stn_tset(scf_instance_t *);

/*
 * Restarter transition outcomes
 */
typedef enum {
	MAINT_REQUESTED,
	START_REQUESTED,
	START_FAILED_REPEATEDLY,
	START_FAILED_CONFIGURATION,
	START_FAILED_FATAL,
	START_FAILED_TIMEOUT_FATAL,
	START_FAILED_OTHER
} start_outcome_t;

typedef void (*instance_hook_t)(void);

typedef struct service_hook_assn {
	char	*sh_fmri;
	instance_hook_t	sh_pre_online_hook;
	instance_hook_t	sh_post_online_hook;
	instance_hook_t	sh_post_offline_hook;
} service_hook_assn_t;

/*
 * Restarter instance stop reasons.
 */
typedef enum {
	RSTOP_EXIT = 0x0,	/* exited or empty */
	RSTOP_CORE,		/* core dumped */
	RSTOP_SIGNAL,		/* external fatal signal received */
	RSTOP_HWERR,		/* uncorrectable hardware error */
	RSTOP_DEPENDENCY,	/* dependency activity caused stop */
	RSTOP_DISABLE,		/* disabled */
	RSTOP_RESTART,		/* restart requested */
	RSTOP_ERR_CFG,		/* wait svc exited with a config. error */
	RSTOP_ERR_EXIT		/* wait svc exited with an error */
} stop_cause_t;

/*
 * Restarter instance maintenance clear reasons.
 */
typedef enum {
	RUNMAINT_CLEAR = 0x0,
	RUNMAINT_DISABLE
} unmaint_cause_t;

/*
 * Restarter instance flags
 */
#define	RINST_CONTRACT		0x00000000	/* progeny constitute inst */
#define	RINST_TRANSIENT		0x10000000	/* inst operates momentarily */
#define	RINST_WAIT		0x20000000	/* child constitutes inst */
#define	RINST_STYLE_MASK	0xf0000000

#define	RINST_RETAKE_RUNNING	0x01000000	/* pending running snapshot */
#define	RINST_RETAKE_START	0x02000000	/* pending start snapshot */

#define	RINST_RETAKE_MASK	0x0f000000

#define	RINST_START_TIMES	5		/* failures to consider */
#define	RINST_FAILURE_RATE_NS	600000000000LL	/* 1 failure/10 minutes */
#define	RINST_WT_SVC_FAILURE_RATE_NS	NANOSEC	/* 1 failure/second */

/* Number of events in the queue when we start dropping ADMIN events. */
#define	RINST_QUEUE_THRESHOLD	100

typedef struct restarter_inst {
	int			ri_id;
	instance_data_t		ri_i;
	char			*ri_common_name; /* template localized name */
	char			*ri_C_common_name; /* C locale name */

	char			*ri_logstem;	/* logfile name */
	char			*ri_utmpx_prefix;
	uint_t			ri_flags;
	instance_hook_t		ri_pre_online_hook;
	instance_hook_t		ri_post_online_hook;
	instance_hook_t		ri_post_offline_hook;

	hrtime_t		ri_start_time[RINST_START_TIMES];
	uint_t			ri_start_index;	/* times started */

	uu_list_node_t		ri_link;
	pthread_mutex_t		ri_lock;

	/*
	 * When we start a thread to we execute a method for this instance, we
	 * put the thread id in ri_method_thread.  Threads with ids other than
	 * this which acquire ri_lock while ri_method_thread is nonzero should
	 * wait on ri_method_cv.  ri_method_waiters should be incremented while
	 * waiting so the instance won't be deleted.
	 */
	pthread_t		ri_method_thread;
	pthread_cond_t		ri_method_cv;
	uint_t			ri_method_waiters;

	/*
	 * These fields are provided so functions can operate on this structure
	 * and the repository without worrying about whether the instance has
	 * been deleted from the repository (this is possible because
	 * ri_i.i_fmri names the instance this structure represents -- see
	 * libscf_reget_inst()).  ri_m_inst is the scf_instance_t for the
	 * instance, and ri_mi_deleted is true if the instance has been deleted.
	 */
	scf_instance_t		*ri_m_inst;
	boolean_t		ri_mi_deleted;

	/*
	 * We maintain a pointer to any pending timeout for this instance
	 * for quick reference/deletion.
	 */
	timeout_entry_t		*ri_timeout;

	/*
	 * Instance event queue.  Graph events are queued here as a list
	 * of restarter_instance_qentry_t's, and the lock is held separately.
	 * If both ri_lock and ri_queue_lock are grabbed, ri_lock must be
	 * grabbed first.  ri_queue_lock protects all ri_queue_* structure
	 * members.
	 */
	pthread_mutex_t		ri_queue_lock;
	pthread_cond_t		ri_queue_cv;
	uu_list_t		*ri_queue;
	int			ri_queue_thread;

} restarter_inst_t;

typedef struct restarter_instance_list {
	uu_list_t		*ril_instance_list;
	pthread_mutex_t		ril_lock;
} restarter_instance_list_t;

typedef struct restarter_instance_qentry {
	restarter_event_type_t	riq_type;
	int32_t			riq_reason;
	uu_list_node_t		riq_link;
} restarter_instance_qentry_t;

typedef struct fork_info {
	int			sf_id;
	int			sf_method_type;
	restarter_error_t	sf_event_type;
	restarter_str_t		sf_reason;
} fork_info_t;

typedef struct wait_info {
	uu_list_node_t		wi_link;

	int			wi_fd;		/* psinfo file descriptor */
	id_t			wi_pid;		/* process ID */
	const char		*wi_fmri;	/* instance FMRI */
	int			wi_parent;	/* startd is parent */
	int			wi_ignore;	/* ignore events */
} wait_info_t;

#define	STARTD_LOG_FILE		0x1
#define	STARTD_LOG_TERMINAL	0x2
#define	STARTD_LOG_SYSLOG	0x4

#define	STARTD_BOOT_QUIET	0x1
#define	STARTD_BOOT_VERBOSE	0x2

/*
 * Internal debug flags used to reduce the amount of data sent to the
 * internal debug buffer. They can be turned on & off dynamically using
 * internal_debug_flags variable in mdb. By default, they're off.
 */
#define	DEBUG_DEPENDENCIES	0x1

typedef struct startd_state {
	/* Logging configuration */
	char		*st_log_prefix;	/* directory prefix */
	char		*st_log_file;	/* startd file in above dir */
	uint_t		st_log_flags;	/* message destination */
	int		st_log_level_min; /* minimum required to log */
	int		st_log_timezone_known; /* timezone is available */
	int		st_log_locale_known; /* locale is available */
	int		st_log_login_reached; /* login service reached */

	/* Boot configuration */
	uint_t		st_boot_flags;	/* serial boot, etc. */
	uint_t		st_initial;	/* first startd on system */

	/* System configuration */
	char		*st_subgraph;	/* milestone subgraph request */

	uint_t		st_load_complete;  /* graph load completed */
	uint_t		st_load_instances; /* restarter instances to load */
	pthread_mutex_t	st_load_lock;
	pthread_cond_t	st_load_cv;

	/* Repository configuration */
	pid_t		st_configd_pid;	/* PID of our svc.configd */
					/* instance */
	int		st_configd_lives; /* configd started */
	pthread_mutex_t	st_configd_live_lock;
	pthread_cond_t	st_configd_live_cv;

	char		*st_door_path;

	/* General information */
	uint_t		st_flags;
	struct timeval	st_start_time;	/* effective system start time */
	char		*st_locale;
} startd_state_t;

extern startd_state_t *st;

extern boolean_t booting_to_single_user;

extern const char *event_names[];

/*
 * Structures for contract to instance hash table, implemented in
 * contract.c and used by restarter.c and method.c
 */
typedef struct contract_entry {
	ctid_t		ce_ctid;
	int		ce_instid;

	uu_list_node_t	ce_link;
} contract_entry_t;

extern volatile uint16_t	storing_contract;

uu_list_pool_t *contract_list_pool;

/* contract.c */
ctid_t contract_init(void);
void contract_abandon(ctid_t);
int contract_kill(ctid_t, int, const char *);
int contract_is_empty(ctid_t);
void contract_hash_init();
void contract_hash_store(ctid_t, int);
void contract_hash_remove(ctid_t);
int lookup_inst_by_contract(ctid_t);

/* dict.c */
void dict_init(void);
int dict_lookup_byname(const char *);
int dict_insert(const char *);

/* expand.c */
int expand_method_tokens(const char *, scf_instance_t *,
    scf_snapshot_t *, int, char **);

/* env.c */
void init_env(void);
char **set_smf_env(char **, size_t, const char *,
    const restarter_inst_t *, const char *);

/* file.c */
int file_ready(graph_vertex_t *);

/* fork.c */
int fork_mount(char *, char *);
void fork_sulogin(boolean_t, const char *, ...);
void fork_rc_script(char, const char *, boolean_t);

void *fork_configd_thread(void *);

pid_t startd_fork1(int *);
void fork_with_timeout(const char *, uint_t, uint_t);
void fork_emi();

/* graph.c */
void graph_init(void);
void *single_user_thread(void *);
void *graph_thread(void *);
void *graph_event_thread(void *);
void *repository_event_thread(void *);
int dgraph_add_instance(const char *, scf_instance_t *, boolean_t);
void graph_engine_start(void);
void graph_enable_by_vertex(graph_vertex_t *, int, int);
int refresh_vertex(graph_vertex_t *, scf_instance_t *);
void vertex_send_event(graph_vertex_t *, restarter_event_type_t);
void graph_start_if_satisfied(graph_vertex_t *);
int vertex_subgraph_dependencies_shutdown(scf_handle_t *, graph_vertex_t *,
    restarter_instance_state_t);
void graph_transition_sulogin(restarter_instance_state_t,
    restarter_instance_state_t);
void graph_transition_propagate(graph_vertex_t *, propagate_event_t,
    restarter_error_t);
void graph_offline_subtree_leaves(graph_vertex_t *, void *);
void offline_vertex(graph_vertex_t *);

/* libscf.c - common */
char *inst_fmri_to_svc_fmri(const char *);
void *libscf_object_create(void *(*)(scf_handle_t *), scf_handle_t *);
int libscf_instance_get_fmri(scf_instance_t *, char **);
int libscf_fmri_get_instance(scf_handle_t *, const char *, scf_instance_t **);
int libscf_lookup_instance(const char *, scf_instance_t *);
int libscf_set_reconfig(int);
scf_snapshot_t *libscf_get_or_make_running_snapshot(scf_instance_t *,
    const char *, boolean_t);
int libscf_inst_set_count_prop(scf_instance_t *, const char *,
    const char *pgtype, uint32_t, const char *, uint64_t);

/* libscf.c - used by graph.c */
int libscf_get_deathrow(scf_handle_t *, scf_instance_t *, int *);
int libscf_get_basic_instance_data(scf_handle_t *, scf_instance_t *,
    const char *, int *, int *, char **);
int libscf_inst_get_or_add_pg(scf_instance_t *, const char *, const char *,
    uint32_t, scf_propertygroup_t *);
int libscf_read_states(const scf_propertygroup_t *,
    restarter_instance_state_t *, restarter_instance_state_t *);
int depgroup_empty(scf_handle_t *, scf_propertygroup_t *);
gv_type_t depgroup_read_scheme(scf_handle_t *, scf_propertygroup_t *);
depgroup_type_t depgroup_read_grouping(scf_handle_t *, scf_propertygroup_t *);
restarter_error_t depgroup_read_restart(scf_handle_t *, scf_propertygroup_t *);
int libscf_set_enable_ovr(scf_instance_t *, int);
int libscf_set_deathrow(scf_instance_t *, int);
int libscf_delete_enable_ovr(scf_instance_t *);
int libscf_get_milestone(scf_instance_t *, scf_property_t *, scf_value_t *,
    char *, size_t);
int libscf_extract_runlevel(scf_property_t *, char *);
int libscf_clear_runlevel(scf_propertygroup_t *, const char *milestone);

typedef int (*callback_t)(void *, void *);

int walk_dependency_pgs(scf_instance_t *, callback_t, void *);
int walk_property_astrings(scf_property_t *, callback_t, void *);
void libscf_reset_start_times(restarter_inst_t *, int);

/* libscf.c - used by restarter.c/method.c/expand.c */
char *libscf_get_method(scf_handle_t *, int, restarter_inst_t *,
    scf_snapshot_t *, method_restart_t *, uint_t *, uint8_t *, uint64_t *,
    uint8_t *);
void libscf_populate_graph(scf_handle_t *h);
int update_fault_count(restarter_inst_t *, int);
int libscf_unset_action(scf_handle_t *, scf_propertygroup_t *, admin_action_t,
    int64_t);
int libscf_get_startd_properties(scf_instance_t *, scf_snapshot_t *, uint_t *,
    char **);
int libscf_get_template_values(scf_instance_t *, scf_snapshot_t *, char **,
    char **);

int libscf_read_method_ids(scf_handle_t *, scf_instance_t *, const char *,
    ctid_t *, ctid_t *, pid_t *);
int libscf_write_start_pid(scf_instance_t *, pid_t);
int libscf_write_method_status(scf_instance_t *, const char *, int);
int libscf_note_method_log(scf_instance_t *, const char *, const char *);

scf_handle_t *libscf_handle_create_bound(scf_version_t);
void libscf_handle_rebind(scf_handle_t *);
scf_handle_t *libscf_handle_create_bound_loop(void);

scf_snapshot_t *libscf_get_running_snapshot(scf_instance_t *);
int libscf_snapshots_poststart(scf_handle_t *, const char *, boolean_t);
int libscf_snapshots_refresh(scf_instance_t *, const char *);

int instance_is_transient_style(restarter_inst_t *);
int instance_is_wait_style(restarter_inst_t *);

int libscf_create_self(scf_handle_t *);

void libscf_reget_instance(restarter_inst_t *);

/* log.c */
void log_init();
void log_error(int, const char *, ...);
void log_framework(int, const char *, ...);
void log_framework2(int, int, const char *, ...);
void log_console(int, const char *, ...);
void log_preexec(void);
void setlog(const char *);
void log_transition(const restarter_inst_t *, start_outcome_t);
void log_instance(const restarter_inst_t *, boolean_t, const char *, ...);
void log_instance_fmri(const char *, const char *, boolean_t,
    const char *, ...);

/* method.c */
void *method_thread(void *);
void method_remove_contract(restarter_inst_t *, boolean_t, boolean_t);
int method_rate_critical(restarter_inst_t *);

/* misc.c */
void startd_close(int);
void startd_fclose(FILE *);
int fmri_canonify(const char *, char **, boolean_t);
int fs_is_read_only(char *, ulong_t *);
int fs_remount(char *);
void xstr_sanitize(char *);

/* restarter.c */
void restarter_init(void);
void restarter_start(void);
int instance_in_transition(restarter_inst_t *);
int restarter_instance_update_states(scf_handle_t *, restarter_inst_t *,
    restarter_instance_state_t, restarter_instance_state_t, restarter_error_t,
    restarter_str_t);
int stop_instance_fmri(scf_handle_t *, const char *, uint_t);
restarter_inst_t *inst_lookup_by_id(int);
void restarter_mark_pending_snapshot(const char *, uint_t);
void *restarter_post_fsminimal_thread(void *);
void timeout_insert(restarter_inst_t *, ctid_t, uint64_t);
void timeout_remove(restarter_inst_t *, ctid_t);
void timeout_init(void);
int is_timeout_ovr(restarter_inst_t *);

/* startd.c */
void *safe_realloc(void *, size_t);
char *safe_strdup(const char *s);
void *startd_alloc_retry(void *(*)(size_t, int), size_t);
void startd_free(void *, size_t);
uu_list_pool_t *startd_list_pool_create(const char *, size_t, size_t,
    uu_compare_fn_t *, uint32_t);
uu_list_t *startd_list_create(uu_list_pool_t *, void *, uint32_t);
pthread_t startd_thread_create(void *(*)(void *), void *);

/* special.c */
void special_null_transition(void);
void special_online_hooks_get(const char *, instance_hook_t *,
    instance_hook_t *, instance_hook_t *);

/* transition.c */
int gt_transition(scf_handle_t *, graph_vertex_t *, restarter_error_t,
    restarter_instance_state_t);

/* utmpx.c */
void utmpx_init(void);
void utmpx_clear_old(void);
int utmpx_mark_init(pid_t, char *);
void utmpx_mark_dead(pid_t, int, boolean_t);
char utmpx_get_runlevel(void);
void utmpx_set_runlevel(char, char, boolean_t);
void utmpx_write_boottime(void);
void utmpx_prefork(void);
void utmpx_postfork(void);

/* wait.c */
void wait_init(void);
void wait_prefork(void);
void wait_postfork(pid_t);
int wait_register(pid_t, const char *, int, int);
void *wait_thread(void *);
void wait_ignore_by_fmri(const char *);

/* proc.c */
ctid_t proc_get_ctid();

/* deathrow.c */
extern void deathrow_init();
extern void deathrow_fini();
extern boolean_t is_fmri_in_deathrow(const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _STARTD_H */
