/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * platform independent module to manage nodes under frutree
 */

/*
 * This file has the frutree initialization code:
 * 1) parse the config file to create all locations in the chassis
 * 2) probe each location to find fru and probe the fru recursively to
 *    create locations, port nodes
 * 3) handle hotswap picl events (dr_ap_state_change, dr_req)
 *    - update the frutree
 *    - send out picl-state-change, picl-condition-events
 * 4) Monitor the port nodes state and condition
 */

#include <stdlib.h>
#include <sys/param.h>
#include <strings.h>
#include <string.h>
#include <limits.h>
#include <syslog.h>
#include <pthread.h>
#include <thread.h>
#include <libintl.h>
#include <sys/systeminfo.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <ctype.h>
#include <time.h>
#include <poll.h>
#include <assert.h>
#include <libnvpair.h>
#include <alloca.h>
#include <stdarg.h>
#include <config_admin.h>
#include <libdevinfo.h>
#include <synch.h>
#include <sys/time.h>
#include <picl.h>
#include <picltree.h>
#include <picldefs.h>
#include <picld_pluginutil.h>
#include <libfru.h>
#include <sys/sysevent/dr.h>
#include <ptree_impl.h>
#include "piclfrutree.h"

#pragma	init(piclfrutree_register)

/*
 * following values are tunables that can be changed using
 * environment variables
 */
int frutree_debug = NONE;		/* debug switch */
static int frutree_poll_timeout = 5;	/* polling time to monitor ports */
static int frutree_drwait_time  = 10;	/* wait time for dr operation */

#define	PICL_PROP_CONF_FILE	"conf_name"
#define	PICL_ADMINLOCK_DISABLED	"disabled"
#define	PICL_ADMINLOCK_ENABLED	"enabled"
#define	HASH_TABLE_SIZE		(64)
#define	BUF_SIZE		25
#define	HASH_INDEX(s, x)	((int)((x) & ((s) - 1)))
#define	FRUDATA_PTR(_X)	((frutree_frunode_t *)(((hashdata_t *)(_X))->data))
#define	LOCDATA_PTR(_X)	((frutree_locnode_t *)(((hashdata_t *)(_X))->data))
#define	PORTDATA_PTR(_X) ((frutree_portnode_t *)(((hashdata_t *)(_X))->data))

/* Hash table structure */
typedef struct frutree_hash_elm {
	picl_nodehdl_t hdl;
	void *nodep;
	struct frutree_hash_elm	*nextp;
} frutree_hashelm_t;

typedef struct {
	int hash_size;
	frutree_hashelm_t **tbl;
} frutree_hash_t;

typedef struct {
	frutree_datatype_t type;
	void *data;
} hashdata_t;

typedef int (*callback_t)(picl_nodehdl_t, void *);
typedef enum {
	INIT_FRU = 0x0,
	CREATE_DEVICES_ENTRIES,
	CONFIGURE_FRU,
	UNCONFIGURE_FRU,
	CPU_OFFLINE,
	CPU_ONLINE,
	HANDLE_CONFIGURE,
	HANDLE_UNCONFIGURE,
	HANDLE_INSERT,
	HANDLE_REMOVE,
	HANDLE_LOCSTATE_CHANGE,
	POST_COND_EVENT,
	POST_EVENTS
} action_t;

typedef struct {
	action_t	action;
	void 		*data;
} frutree_dr_arg_t;

typedef struct event_queue {
	frutree_dr_arg_t arg;
	struct event_queue *next;
}ev_queue_t;

typedef struct {
	char node_name[PICL_PROPNAMELEN_MAX];
	picl_nodehdl_t retnodeh;
} frutree_callback_data_t;

typedef struct remove_list {
	picl_nodehdl_t nodeh;
	struct remove_list *next;
} delete_list_t;

typedef struct {
	frutree_frunode_t *frup;
	delete_list_t *first;
} frutree_init_callback_arg_t;

boolean_t frutree_connects_initiated = B_FALSE;
static ev_queue_t *queue_head = NULL;
static ev_queue_t *queue_tail = NULL;
static pthread_mutex_t ev_mutex;
static pthread_cond_t ev_cond;

static frutree_hash_t node_hash_table = {0, NULL};
static picl_nodehdl_t chassish = 0;
static picl_nodehdl_t frutreeh = 0;
static picl_nodehdl_t rooth = 0;
static picl_nodehdl_t platformh = 0;
static boolean_t post_picl_events = B_FALSE;
static int piclevent_pending = 0;
static char conf_file[MAXPATHLEN];
static char sys_name[SYS_NMLN];

static mutex_t piclevent_mutex = DEFAULTMUTEX;
static cond_t piclevent_completed_cv = DEFAULTCV;
static rwlock_t	hash_lock;

static pthread_t tid;
static void *dr_thread(void *);

static pthread_t init_threadID;
static pthread_t monitor_tid;
static pthread_mutex_t monitor_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t monitor_cv = PTHREAD_COND_INITIALIZER;
static int fini_called = 0;
static void *monitor_node_status(void *);
static ev_queue_t *remove_from_queue(void);
static picl_errno_t handle_chassis_configure(frutree_frunode_t *frup);

/*
 * location states.
 */
static char *loc_state[] = {
	PICLEVENTARGVAL_UNKNOWN,
	PICLEVENTARGVAL_EMPTY,
	PICLEVENTARGVAL_CONNECTED,
	PICLEVENTARGVAL_DISCONNECTED,
	PICLEVENTARGVAL_CONNECTING,
	PICLEVENTARGVAL_DISCONNECTING,
	NULL
};

/*
 * fru states.
 */
static char *fru_state[] = {
	PICLEVENTARGVAL_UNKNOWN,
	PICLEVENTARGVAL_CONFIGURED,
	PICLEVENTARGVAL_UNCONFIGURED,
	PICLEVENTARGVAL_CONFIGURING,
	PICLEVENTARGVAL_UNCONFIGURING,
	NULL
};

/*
 * fru condition.
 */
static char *fru_cond[] = {
	PICLEVENTARGVAL_UNKNOWN,
	PICLEVENTARGVAL_FAILED,
	PICLEVENTARGVAL_FAILING,
	PICLEVENTARGVAL_OK,
	PICLEVENTARGVAL_TESTING,
	NULL
};

/*
 * port states.
 */
static char *port_state[] = {
	PICLEVENTARGVAL_DOWN,
	PICLEVENTARGVAL_UP,
	PICLEVENTARGVAL_UNKNOWN,
	NULL
};

/*
 * port condition.
 */
static char *port_cond[] = {
	PICLEVENTARGVAL_OK,
	PICLEVENTARGVAL_FAILING,
	PICLEVENTARGVAL_FAILED,
	PICLEVENTARGVAL_TESTING,
	PICLEVENTARGVAL_UNKNOWN,
	NULL
};

/* mapping between libcfgadm error codes to picl error codes */
static const int cfg2picl_errmap[][2] =  {
	{CFGA_OK, PICL_SUCCESS},
	{CFGA_NACK, PICL_NORESPONSE},
	{CFGA_NOTSUPP, PICL_NOTSUPPORTED},
	{CFGA_OPNOTSUPP, PICL_NOTSUPPORTED},
	{CFGA_PRIV, PICL_FAILURE},
	{CFGA_BUSY, PICL_TREEBUSY},
	{CFGA_SYSTEM_BUSY, PICL_TREEBUSY},
	{CFGA_DATA_ERROR, PICL_FAILURE},
	{CFGA_LIB_ERROR, PICL_FAILURE},
	{CFGA_NO_LIB, PICL_FAILURE},
	{CFGA_INSUFFICENT_CONDITION, PICL_FAILURE},
	{CFGA_INVAL, PICL_INVALIDARG},
	{CFGA_ERROR, PICL_FAILURE},
	{CFGA_APID_NOEXIST, PICL_NODENOTFOUND},
	{CFGA_ATTR_INVAL, PICL_INVALIDARG}
};

/* local functions */
static void piclfrutree_register(void);
static void piclfrutree_init(void);
static void piclfrutree_fini(void);
static void * init_thread(void *);
static void frutree_wd_evhandler(const char *, const void *, size_t, void *);
static void frutree_dr_apstate_change_evhandler(const char *, const void *,
		size_t, void *);
static void frutree_dr_req_evhandler(const char *, const void *,
		size_t, void *);
static void frutree_cpu_state_change_evhandler(const char *, const void *,
		size_t, void *);
static void init_queue(void);
static void frutree_get_env();
static picl_errno_t hash_init(void);
static picl_errno_t hash_remove_entry(picl_nodehdl_t);
static picl_errno_t hash_lookup_entry(picl_nodehdl_t, void **);
static void hash_destroy();
static picl_errno_t initialize_frutree();
static picl_errno_t update_loc_state(frutree_locnode_t *, boolean_t *);
static int is_autoconfig_enabled(char *);
static picl_errno_t do_action(picl_nodehdl_t, int action, void *);
static picl_errno_t probe_fru(frutree_frunode_t *, boolean_t);
static picl_errno_t handle_fru_unconfigure(frutree_frunode_t *);
static picl_errno_t update_loc_state(frutree_locnode_t *, boolean_t *);
static picl_errno_t update_fru_state(frutree_frunode_t *, boolean_t *);
static picl_errno_t update_port_state(frutree_portnode_t *, boolean_t);
static picl_errno_t configure_fru(frutree_frunode_t *, cfga_flags_t);
static picl_errno_t post_piclevent(const char *, char *, char *,
			picl_nodehdl_t, frutree_wait_t);
static picl_errno_t fru_init(frutree_frunode_t *);

/* External functions */
extern boolean_t is_fru_present_under_location(frutree_locnode_t *);
extern int kstat_port_state(frutree_port_type_t, char *, int);
extern int kstat_port_cond(frutree_port_type_t, char *, int);
extern picl_errno_t probe_libdevinfo(frutree_frunode_t *,
		frutree_device_args_t **, boolean_t);
extern picl_errno_t get_scsislot_name(char *, char *, char *);
extern picl_errno_t probe_for_scsi_frus(frutree_frunode_t *);
extern picl_errno_t get_fru_path(char *, frutree_frunode_t *);
extern picl_errno_t scsi_info_init();
extern void scsi_info_fini();
extern picl_errno_t get_port_info(frutree_portnode_t *);
extern char *strtok_r(char *s1, const char *s2, char **lasts);

/* Plugin initialization */
static picld_plugin_reg_t frutree_reg_info = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_CRITICAL,
	"SUNW_piclfrutree",
	piclfrutree_init,
	piclfrutree_fini
};

/* ptree entry points */
static void
piclfrutree_register(void)
{
	FRUTREE_DEBUG0(FRUTREE_INIT, "piclfrutree register");
	(void) picld_plugin_register(&frutree_reg_info);
}

static void
piclfrutree_init(void)
{
	FRUTREE_DEBUG0(FRUTREE_INIT, "piclfrutree_init begin");
	(void) rwlock_init(&hash_lock, USYNC_THREAD, NULL);
	fini_called = 0;

	/* read the environment variables */
	frutree_get_env();

	if (sysinfo(SI_PLATFORM, sys_name, sizeof (sys_name)) == -1) {
		return;
	}

	if (hash_init() != PICL_SUCCESS) {
		return;
	}
	if (initialize_frutree() != PICL_SUCCESS) {
		return;
	}

	/* initialize the event queue */
	(void) init_queue();

	(void) pthread_cond_init(&ev_cond, NULL);
	(void) pthread_mutex_init(&ev_mutex, NULL);
	if (pthread_create(&tid, NULL, &dr_thread, NULL) != 0) {
		return;
	}
	/* register for picl events */
	if (ptree_register_handler(PICLEVENT_DR_AP_STATE_CHANGE,
		frutree_dr_apstate_change_evhandler, NULL) !=
		PICL_SUCCESS) {
		return;
	}

	if (ptree_register_handler(PICLEVENT_DR_REQ,
		frutree_dr_req_evhandler, NULL) != PICL_SUCCESS) {
		return;
	}

	if (ptree_register_handler(PICLEVENT_CPU_STATE_CHANGE,
		frutree_cpu_state_change_evhandler, NULL) !=
		PICL_SUCCESS) {
		return;
	}

	if (ptree_register_handler(PICLEVENT_STATE_CHANGE,
		frutree_wd_evhandler, NULL) != PICL_SUCCESS) {
		return;
	}
	FRUTREE_DEBUG0(FRUTREE_INIT, "piclfrutree_init end");
}

static void
piclfrutree_fini(void)
{
	ev_queue_t	*event = NULL;
	void		*exitval;

	FRUTREE_DEBUG0(EVENTS, "piclfrutree_fini begin");

	fini_called = 1;
	/* unregister event handlers */
	(void) ptree_unregister_handler(PICLEVENT_DR_AP_STATE_CHANGE,
		frutree_dr_apstate_change_evhandler, NULL);
	(void) ptree_unregister_handler(PICLEVENT_DR_REQ,
		frutree_dr_req_evhandler, NULL);
	(void) ptree_unregister_handler(PICLEVENT_CPU_STATE_CHANGE,
		frutree_cpu_state_change_evhandler, NULL);
	(void) ptree_unregister_handler(PICLEVENT_STATE_CHANGE,
		frutree_wd_evhandler, NULL);

	/* flush the event queue */
	(void) pthread_mutex_lock(&ev_mutex);
	event = remove_from_queue();
	while (event) {
		free(event);
		event = remove_from_queue();
	}
	queue_head = queue_tail = NULL;

	(void) pthread_cond_broadcast(&ev_cond);
	(void) pthread_mutex_unlock(&ev_mutex);
	(void) pthread_cancel(tid);
	(void) pthread_join(tid, &exitval);
	(void) pthread_cancel(monitor_tid);
	(void) pthread_join(monitor_tid, &exitval);
	(void) pthread_cancel(init_threadID);
	(void) pthread_join(init_threadID, &exitval);

	hash_destroy();
	(void) ptree_delete_node(frutreeh);
	(void) ptree_destroy_node(frutreeh);

	frutree_connects_initiated = B_FALSE;
	chassish = frutreeh = rooth = platformh = 0;
	post_picl_events = B_FALSE;
	piclevent_pending = 0;
	FRUTREE_DEBUG0(EVENTS, "piclfrutree_fini end");
}

/* read the ENVIRONMENT variables and initialize tunables */
static void
frutree_get_env()
{
	char *val;
	int intval = 0;

	/* read frutree debug flag value */
	if (val = getenv(FRUTREE_DEBUG)) {
		errno = 0;
		intval = strtol(val, (char **)NULL, 0);
		if (errno == 0) {
			frutree_debug = intval;
			FRUTREE_DEBUG1(PRINT_ALL, "SUNW_frutree:debug = %x",
				frutree_debug);
		}
	}

	/* read poll timeout value */
	if (val = getenv(FRUTREE_POLL_TIMEOUT)) {
		errno = 0;
		intval = strtol(val, (char **)NULL, 0);
		if (errno == 0) {
			frutree_poll_timeout = intval;
		}
	}

	/* read drwait time value */
	if (val = getenv(FRUTREE_DRWAIT)) {
		errno = 0;
		intval = strtol(val, (char **)NULL, 0);
		if (errno == 0) {
			frutree_drwait_time = intval;
		}
	}
}

/*
 * callback function for ptree_walk_tree_class to get the
 * node handle of node
 * matches a node with same class and name
 */
static int
frutree_get_nodehdl(picl_nodehdl_t nodeh, void *c_args)
{
	picl_errno_t rc;
	char name[PICL_PROPNAMELEN_MAX];
	frutree_callback_data_t *fru_arg;

	if (c_args == NULL)
		return (PICL_INVALIDARG);
	fru_arg = (frutree_callback_data_t *)c_args;

	if ((rc = ptree_get_propval_by_name(nodeh, PICL_PROP_NAME, name,
		sizeof (name))) != PICL_SUCCESS) {
		return (rc);
	}

	if (strcmp(fru_arg->node_name, name) == 0) {
		fru_arg->retnodeh = nodeh;
		return (PICL_WALK_TERMINATE);
	}
	return (PICL_WALK_CONTINUE);
}

/* queue implementation (used to  queue hotswap events) */
static void
init_queue(void)
{
	queue_head = NULL;
	queue_tail = NULL;
}

/* add an event to the queue */
static int
add_to_queue(frutree_dr_arg_t  dr_data)
{
	ev_queue_t	*new_event;

	new_event = (ev_queue_t *)malloc(sizeof (ev_queue_t));
	if (new_event == NULL)
		return (PICL_NOSPACE);

	new_event->arg.action = dr_data.action;
	new_event->arg.data = dr_data.data;
	new_event->next = NULL;

	if (queue_head == NULL) {
		queue_head = new_event;
	} else {
		queue_tail->next = new_event;
	}
	queue_tail = new_event;

	return (PICL_SUCCESS);
}

static ev_queue_t *
remove_from_queue(void)
{
	ev_queue_t	*event = NULL;

	if (queue_head == NULL)
		return (NULL);

	event = queue_head;
	queue_head = queue_head->next;

	if (queue_head == NULL)
		queue_tail = NULL;
	return (event);
}

/*
 * event handler for watchdog expiry event (picl-state-change) event on
 * watchdog-timer node
 */
/* ARGSUSED */
static void
frutree_wd_evhandler(const char	*ename, const void *earg, size_t size,
	void *cookie)
{
	nvlist_t *nvlp;
	char *wd_state = NULL;
	picl_errno_t rc;
	picl_nodehdl_t wd_nodehdl;
	char value[PICL_PROPNAMELEN_MAX];
	frutree_callback_data_t fru_arg;

	if (ename == NULL)
		return;

	if (strncmp(ename, PICLEVENT_STATE_CHANGE,
		strlen(PICLEVENT_STATE_CHANGE))) {
		return;
	}

	if (nvlist_unpack((char *)earg, size, &nvlp, NULL)) {
		return;
	}

	if (nvlist_lookup_uint64(nvlp, PICLEVENTARG_NODEHANDLE,
		&wd_nodehdl) == -1) {
		nvlist_free(nvlp);
		return;
	}

	if (nvlist_lookup_string(nvlp, PICLEVENTARG_STATE,
		&wd_state) != 0) {
		nvlist_free(nvlp);
		return;
	}

	if ((rc = ptree_get_propval_by_name(wd_nodehdl,
		PICL_PROP_CLASSNAME, value, sizeof (value))) != PICL_SUCCESS) {
		nvlist_free(nvlp);
		return;
	}

	/* if the event is not of watchdog-timer, return */
	if (strcmp(value, PICL_CLASS_WATCHDOG_TIMER) != 0) {
		nvlist_free(nvlp);
		return;
	}

	FRUTREE_DEBUG1(EVENTS, "frutree:Received WD event(%s)", wd_state);
	/* frutree plugin handles only watchdog expiry events */
	if (strcmp(wd_state, PICL_PROPVAL_WD_STATE_EXPIRED) != 0) {
		nvlist_free(nvlp);
		return;
	}

	if ((rc = ptree_get_propval_by_name(wd_nodehdl,
		PICL_PROP_WATCHDOG_ACTION, value, sizeof (value))) !=
		PICL_SUCCESS) {
		nvlist_free(nvlp);
		return;
	}

	/* if action is none, dont do anything */
	if (strcmp(value, PICL_PROPVAL_WD_ACTION_NONE) == 0) {
		nvlist_free(nvlp);
		return;
	}

	/* find the CPU nodehdl */
	(void) strncpy(fru_arg.node_name, SANIBEL_PICLNODE_CPU,
		sizeof (fru_arg.node_name));
	fru_arg.retnodeh = 0;
	if ((rc = ptree_walk_tree_by_class(chassish, PICL_CLASS_FRU,
		&fru_arg, frutree_get_nodehdl)) != PICL_SUCCESS) {
		nvlist_free(nvlp);
		return;
	}

	if (fru_arg.retnodeh == NULL) {
		nvlist_free(nvlp);
		return;
	}

	if ((rc = post_piclevent(PICLEVENT_CONDITION_CHANGE,
		PICLEVENTARGVAL_FAILED, NULL, fru_arg.retnodeh,
		NO_WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			SANIBEL_PICLNODE_CPU, PICLEVENT_CONDITION_CHANGE, rc);
	}
	nvlist_free(nvlp);
}

/*
 * event handler for dr_ap_state_change event
 * - determine the event type and queue it in dr_queue to handle it
 */
/* ARGSUSED */
static void
frutree_dr_apstate_change_evhandler(const char *ename, const void *earg,
	size_t size, void *cookie)
{
	nvlist_t *nvlp;
	char *name = NULL;
	char *ap_id = NULL;
	char *hint = NULL;
	picl_nodehdl_t	nodeh, childh;
	hashdata_t *hashptr = NULL;
	frutree_dr_arg_t dr_arg;
	frutree_frunode_t *frup = NULL;
	frutree_locnode_t *locp = NULL;
	frutree_callback_data_t fru_arg;
	boolean_t state_changed = B_FALSE;

	if (ename == NULL)
		return;

	if (strncmp(ename, PICLEVENT_DR_AP_STATE_CHANGE,
		strlen(PICLEVENT_DR_AP_STATE_CHANGE)) != 0) {
		return;
	}

	if (nvlist_unpack((char *)earg, size, &nvlp, NULL)) {
		return;
	}

	if (nvlist_lookup_string(nvlp, PICLEVENTARG_AP_ID, &ap_id) == -1) {
		nvlist_free(nvlp);
		return;
	}

	if (nvlist_lookup_string(nvlp, PICLEVENTARG_HINT, &hint) == -1) {
		nvlist_free(nvlp);
		return;
	}

	/* check for empty strings */
	if (!ap_id || !hint) {
		FRUTREE_DEBUG0(EVENTS, "Empty hint/ap_id");
		nvlist_free(nvlp);
		return;
	}

	/* get the location name */
	name = strrchr(ap_id, ':');
	if (name == NULL) {
		name = ap_id;
	} else {
		name++;
	}

	/* find the loc object */
	(void) strncpy(fru_arg.node_name, name, sizeof (fru_arg.node_name));
	fru_arg.retnodeh = 0;
	if (ptree_walk_tree_by_class(chassish, PICL_CLASS_LOCATION,
		&fru_arg, frutree_get_nodehdl) != PICL_SUCCESS) {
		nvlist_free(nvlp);
		return;
	}

	if (fru_arg.retnodeh == NULL) {
		nvlist_free(nvlp);
		return;
	}
	nodeh = fru_arg.retnodeh;

	if (hash_lookup_entry(nodeh, (void **)&hashptr) != PICL_SUCCESS) {
		nvlist_free(nvlp);
		return;
	}
	locp = LOCDATA_PTR(hashptr);
	if (locp == NULL) {
		nvlist_free(nvlp);
		return;
	}

	if (strcmp(hint, DR_HINT_INSERT) == 0) {
		dr_arg.action = HANDLE_INSERT;
		dr_arg.data   = locp;
		(void) pthread_mutex_lock(&ev_mutex);
		if (add_to_queue(dr_arg) != PICL_SUCCESS) {
			(void) pthread_mutex_unlock(&ev_mutex);
			nvlist_free(nvlp);
			return;
		}
		(void) pthread_cond_signal(&ev_cond);
		(void) pthread_mutex_unlock(&ev_mutex);
		nvlist_free(nvlp);
		return;
	}

	if (strcmp(hint, DR_HINT_REMOVE) == 0) {
		dr_arg.action = HANDLE_REMOVE;
		dr_arg.data = locp;
		(void) pthread_mutex_lock(&ev_mutex);
		if (add_to_queue(dr_arg) != PICL_SUCCESS) {
			(void) pthread_mutex_unlock(&ev_mutex);
			nvlist_free(nvlp);
			return;
		}
		(void) pthread_cond_signal(&ev_cond);
		(void) pthread_mutex_unlock(&ev_mutex);
		nvlist_free(nvlp);
		return;
	}

	if (strcmp(hint, DR_RESERVED_ATTR) != 0) {	/* unknown event */
		nvlist_free(nvlp);
		return;
	}

	/* handle DR_RESERVED_ATTR HINT */
	/* check if this is a fru event */
	if (ptree_get_propval_by_name(locp->locnodeh, PICL_PROP_CHILD,
		&childh, sizeof (childh)) == PICL_SUCCESS) {
		/* get the child fru information */
		if (hash_lookup_entry(childh, (void **)&hashptr) ==
			PICL_SUCCESS) {
			frup = FRUDATA_PTR(hashptr);
		}
	}
	if (frup == NULL) {
		nvlist_free(nvlp);
		return;
	}

	(void) pthread_mutex_lock(&frup->mutex);
	if (frup->dr_in_progress) {
		/* dr in progress, neglect the event */
		(void) pthread_mutex_unlock(&frup->mutex);
		nvlist_free(nvlp);
		return;
	}
	(void) pthread_mutex_unlock(&frup->mutex);

	if (update_fru_state(frup, &state_changed) != PICL_SUCCESS) {
		nvlist_free(nvlp);
		return;
	}

	if (state_changed) {
		(void) pthread_mutex_lock(&frup->mutex);
		/* figure out if this is config/unconfig operation */
		if (frup->state == FRU_STATE_CONFIGURED) {
			dr_arg.action = HANDLE_CONFIGURE;
			dr_arg.data = frup;
		} else if (frup->state == FRU_STATE_UNCONFIGURED) {
			dr_arg.action = HANDLE_UNCONFIGURE;
			dr_arg.data = frup;
		}
		(void) pthread_mutex_unlock(&frup->mutex);

		(void) pthread_mutex_lock(&ev_mutex);
		if (add_to_queue(dr_arg) != PICL_SUCCESS) {
			(void) pthread_mutex_unlock(&ev_mutex);
			nvlist_free(nvlp);
			return;
		}
		(void) pthread_cond_signal(&ev_cond);
		(void) pthread_mutex_unlock(&ev_mutex);
		nvlist_free(nvlp);
		return;
	}

	/* check if this event is related to location */
	(void) pthread_mutex_lock(&locp->mutex);
	if (locp->dr_in_progress) {
		/* dr in progress, neglect the event */
		(void) pthread_mutex_unlock(&locp->mutex);
		nvlist_free(nvlp);
		return;
	}
	(void) pthread_mutex_unlock(&locp->mutex);
	if (update_loc_state(locp, &state_changed) != PICL_SUCCESS) {
		nvlist_free(nvlp);
		return;
	}

	if (state_changed) {	/* location state has changed */
		dr_arg.action = HANDLE_LOCSTATE_CHANGE;
		dr_arg.data  = locp;

		(void) pthread_mutex_lock(&ev_mutex);
		if (add_to_queue(dr_arg) != PICL_SUCCESS) {
			(void) pthread_mutex_unlock(&ev_mutex);
			nvlist_free(nvlp);
			return;
		}
		(void) pthread_cond_signal(&ev_cond);
		(void) pthread_mutex_unlock(&ev_mutex);
		nvlist_free(nvlp);
		return;
	}
	/* duplicate event */
	nvlist_free(nvlp);
}

/*
 * Event handler for dr_req event
 */
/* ARGSUSED */
static void
frutree_dr_req_evhandler(const char *ename, const void *earg, size_t size,
	void *cookie)
{
	nvlist_t *nvlp;
	char *name = NULL;
	char *ap_id = NULL;
	char *dr_req = NULL;
	picl_nodehdl_t nodeh;
	frutree_dr_arg_t dr_arg;
	hashdata_t *hashptr = NULL;
	frutree_frunode_t *frup = NULL;
	frutree_callback_data_t fru_arg;

	if (ename == NULL)
		return;

	if (strncmp(ename, PICLEVENT_DR_REQ, strlen(PICLEVENT_DR_REQ)) != 0) {
		return;
	}
	if (nvlist_unpack((char *)earg, size, &nvlp, NULL)) {
		return;
	}
	if (nvlist_lookup_string(nvlp, PICLEVENTARG_AP_ID, &ap_id) == -1) {
		nvlist_free(nvlp);
		return;
	}
	if (nvlist_lookup_string(nvlp, PICLEVENTARG_DR_REQ_TYPE,
		&dr_req) == -1) {
		nvlist_free(nvlp);
		return;
	}

	if (!ap_id || !dr_req) {
		FRUTREE_DEBUG0(EVENTS, "Empty dr_req/ap_id");
		nvlist_free(nvlp);
		return;
	}

	/* get the location name */
	name = strrchr(ap_id, ':');
	if (name == NULL) {
		name = ap_id;
	} else {
		name++;
	}

	if (name == NULL) {
		nvlist_free(nvlp);
		return;
	}

	FRUTREE_DEBUG2(EVENTS, "DR_REQ:%s on %s", dr_req, name);
	(void) strncpy(fru_arg.node_name, name, sizeof (fru_arg.node_name));
	fru_arg.retnodeh = 0;
	if (ptree_walk_tree_by_class(frutreeh, PICL_CLASS_FRU,
		&fru_arg, frutree_get_nodehdl) != PICL_SUCCESS) {
		nvlist_free(nvlp);
		return;
	}

	if (fru_arg.retnodeh == NULL) {
		nvlist_free(nvlp);
		return;
	}
	nodeh = fru_arg.retnodeh;

	/* find the fru object */
	if (hash_lookup_entry(nodeh, (void **)&hashptr) != PICL_SUCCESS) {
		nvlist_free(nvlp);
		return;
	}
	frup = FRUDATA_PTR(hashptr);
	if (frup == NULL) {
		nvlist_free(nvlp);
		return;
	}

	if (strcmp(dr_req, DR_REQ_INCOMING_RES) == 0) {
		dr_arg.action = CONFIGURE_FRU;
		dr_arg.data = frup;

	} else if (strcmp(dr_req, DR_REQ_OUTGOING_RES) == 0) {
		dr_arg.action = UNCONFIGURE_FRU;
		dr_arg.data = frup;

	} else {
		nvlist_free(nvlp);
		return;
	}

	(void) pthread_mutex_lock(&ev_mutex);
	if (add_to_queue(dr_arg) != PICL_SUCCESS) {
		(void) pthread_mutex_unlock(&ev_mutex);
		nvlist_free(nvlp);
		return;
	}
	(void) pthread_cond_signal(&ev_cond);
	(void) pthread_mutex_unlock(&ev_mutex);
	nvlist_free(nvlp);
}

/*
 * Event handler for cpu_state_change event
 */
/* ARGSUSED */
static void
frutree_cpu_state_change_evhandler(const char *ename, const void *earg,
	size_t size, void *cookie)
{
	char		*hint = NULL;
	nvlist_t	*nvlp;
	frutree_frunode_t	*frup = NULL;
	hashdata_t	*hashptr = NULL;
	picl_nodehdl_t	nodeh;
	frutree_dr_arg_t dr_arg;

	if (ename == NULL)
		return;

	if (strncmp(ename, PICLEVENT_CPU_STATE_CHANGE,
		strlen(PICLEVENT_CPU_STATE_CHANGE)) != 0) {
		return;
	}

	if (nvlist_unpack((char *)earg, size, &nvlp, NULL)) {
		return;
	}
	if (nvlist_lookup_uint64(nvlp, PICLEVENTARG_NODEHANDLE, &nodeh) == -1) {
		nvlist_free(nvlp);
		return;
	}
	if (nvlist_lookup_string(nvlp, PICLEVENTARG_CPU_EV_TYPE, &hint) == -1) {
		nvlist_free(nvlp);
		return;
	}

	if (hash_lookup_entry(nodeh, (void **)&hashptr) != PICL_SUCCESS) {
		nvlist_free(nvlp);
		return;
	}
	frup = FRUDATA_PTR(hashptr);
	if (frup == NULL) {
		nvlist_free(nvlp);
		return;
	}

	if (strcmp(hint, PICLEVENTARGVAL_OFFLINE) == 0) {
		dr_arg.action = CPU_OFFLINE;
		dr_arg.data = frup;
	} else if (strcmp(hint, PICLEVENTARGVAL_ONLINE) == 0) {
		dr_arg.action = CPU_ONLINE;
		dr_arg.data = frup;
	} else {
		nvlist_free(nvlp);
		return;
	}

	(void) pthread_mutex_lock(&ev_mutex);
	if (add_to_queue(dr_arg) != PICL_SUCCESS) {
		(void) pthread_mutex_unlock(&ev_mutex);
		nvlist_free(nvlp);
		return;
	}
	(void) pthread_cond_signal(&ev_cond);
	(void) pthread_mutex_unlock(&ev_mutex);
	nvlist_free(nvlp);
}

static void
attach_driver(char *driver)
{
	char	cmd[BUF_SIZE];
	cmd[0] = '\0';
	(void) snprintf(cmd, sizeof (cmd), "%s %s",
		DEVFSADM_CMD, driver);
	(void) pclose(popen(cmd, "r"));
}

/*
 * Find the node in platform tree with given devfs-path.
 * ptree_find_node is getting a node with devfs-path /pci@1f,0/pci@1,1
 * when we want to find node with /pci@1f,0/pci@1. The fix
 * is required in libpicltree. For now use ptree_walk_tree_by_class
 * to find the node.
 */
static int
find_ref_parent(picl_nodehdl_t nodeh, void *c_args)
{
	picl_prophdl_t		proph;
	ptree_propinfo_t	propinfo;
	void			*vbuf;
	frutree_callback_data_t *fru_arg;

	if (c_args ==  NULL)
		return (PICL_INVALIDARG);
	fru_arg = (frutree_callback_data_t *)c_args;

	if (ptree_get_prop_by_name(nodeh, PICL_PROP_DEVFS_PATH,
		&proph) != PICL_SUCCESS) {
		return (PICL_WALK_CONTINUE);
	}

	if (ptree_get_propinfo(proph, &propinfo) != PICL_SUCCESS) {
		return (PICL_WALK_CONTINUE);
	}

	vbuf = alloca(propinfo.piclinfo.size);
	if (vbuf == NULL)
		return (PICL_WALK_CONTINUE);

	if (ptree_get_propval(proph, vbuf,
		propinfo.piclinfo.size) != PICL_SUCCESS) {
		return (PICL_WALK_CONTINUE);
	}

	/* compare the devfs_path */
	if (strcmp(fru_arg->node_name, (char *)vbuf) == 0) {
		fru_arg->retnodeh = nodeh;
		return (PICL_WALK_TERMINATE);
	}
	return (PICL_WALK_CONTINUE);
}
/*
 * Find the reference node in /platform tree
 * return : 0  - if node is not found
 */
static picl_nodehdl_t
get_reference_handle(picl_nodehdl_t nodeh)
{
	picl_prophdl_t		proph;
	ptree_propinfo_t	propinfo;
	void			*vbuf;
	picl_errno_t		rc = PICL_SUCCESS;
	char			devfs_path[PICL_PROPNAMELEN_MAX];
	char			value[PICL_PROPNAMELEN_MAX];
	char			class[PICL_PROPNAMELEN_MAX];
	frutree_callback_data_t fru_arg;
	picl_nodehdl_t refhdl = 0, ref_parent = 0, nodehdl = 0;

	/*
	 * for fru node, get the devfspath and bus-addr of
	 * its parent.
	 */
	if (ptree_get_propval_by_name(nodeh, PICL_PROP_CLASSNAME,
		class, sizeof (class)) != PICL_SUCCESS) {
		return (0);
	}

	if (strcmp(class, PICL_CLASS_FRU) == 0) {
		if (ptree_get_propval_by_name(nodeh, PICL_PROP_PARENT,
			&nodehdl, sizeof (nodehdl)) != PICL_SUCCESS) {
			return (0);
		}
	} else if (strcmp(class, PICL_CLASS_PORT) == 0) {
		nodehdl = nodeh;
	} else {
		return (0);
	}

	if (ptree_get_propval_by_name(nodehdl, PICL_PROP_DEVFS_PATH,
		devfs_path, sizeof (devfs_path)) != PICL_SUCCESS) {
		return (0);
	}
	if (ptree_get_propval_by_name(nodehdl, PICL_PROP_BUS_ADDR,
		value, sizeof (value)) != PICL_SUCCESS) {
		return (0);
	}

	/* find the node with same devfs-path */
	(void) strncpy(fru_arg.node_name, devfs_path,
		sizeof (fru_arg.node_name));
	fru_arg.retnodeh = 0;
	if (ptree_walk_tree_by_class(platformh, NULL,
		(void *)&fru_arg, find_ref_parent) != PICL_SUCCESS) {
		return (0);
	}

	if (fru_arg.retnodeh == NULL)
		return (0);

	ref_parent = fru_arg.retnodeh;
	/* traverse thru childeren and find the reference node */
	rc = ptree_get_propval_by_name(ref_parent, PICL_PROP_CHILD,
		&refhdl, sizeof (picl_nodehdl_t));
	while (rc == PICL_SUCCESS) {
		nodehdl = refhdl;
		rc = ptree_get_propval_by_name(refhdl, PICL_PROP_PEER,
			&refhdl, sizeof (picl_nodehdl_t));
		/*
		 * compare the bus_addr or Unit address
		 * format of bus_addr can be either (1,3 or 0x6)
		 */
		if (ptree_get_prop_by_name(nodehdl, PICL_PROP_BUS_ADDR,
			&proph) != PICL_SUCCESS) {
			if (ptree_get_prop_by_name(nodehdl,
				PICL_PROP_UNIT_ADDRESS, &proph) !=
				PICL_SUCCESS) {
				continue;
			}
		}

		if (ptree_get_propinfo(proph, &propinfo) != PICL_SUCCESS) {
			continue;
		}

		vbuf = alloca(propinfo.piclinfo.size);
		if (vbuf == NULL)
			continue;

		if (ptree_get_propval(proph, vbuf,
			propinfo.piclinfo.size) != PICL_SUCCESS) {
			continue;
		}

		if (strchr((char *)vbuf, ',') != NULL) {
			if (strcmp(value, (char *)vbuf) == 0) {
				return (nodehdl);
			}
		} else {
			if (strtoul((char *)vbuf, NULL, 16) ==
				strtoul(value, NULL, 16)) {
				return (nodehdl);
			}
		}
	}
	return (0);
}

/* Hash Table Management */
static void
free_data(frutree_datatype_t type, hashdata_t *datap)
{
	frutree_frunode_t *frup = NULL;
	frutree_locnode_t *locp = NULL;
	frutree_portnode_t *portp = NULL;

	if (datap == NULL) {
		return;
	}

	switch (type) {
	case FRU_TYPE:
		frup = (frutree_frunode_t *)datap->data;
		free(frup->name);
		(void) pthread_mutex_destroy(&frup->mutex);
		(void) pthread_cond_destroy(&frup->cond_cv);
		(void) pthread_cond_destroy(&frup->busy_cond_cv);
		free(frup);
		break;
	case LOC_TYPE:
		locp = (frutree_locnode_t *)datap->data;
		free(locp->name);
		(void) pthread_mutex_destroy(&locp->mutex);
		(void) pthread_cond_destroy(&locp->cond_cv);
		free(locp);
		break;
	case PORT_TYPE:
		portp = (frutree_portnode_t *)datap->data;
		free(portp->name);
		free(portp);
		break;
	}
	free(datap);
}

/*
 * Initialize the hash table
 */
static picl_errno_t
hash_init(void)
{
	int	i;

	FRUTREE_DEBUG0(HASHTABLE, "hash_init begin");
	node_hash_table.tbl = (frutree_hashelm_t **)malloc(
		sizeof (frutree_hashelm_t *) * HASH_TABLE_SIZE);

	if (node_hash_table.tbl == NULL) {
		return (PICL_NOSPACE);
	}

	/* initialize each entry in hashtable */
	node_hash_table.hash_size = HASH_TABLE_SIZE;
	for (i = 0; i < node_hash_table.hash_size; ++i) {
		node_hash_table.tbl[i] = NULL;
	}
	return (PICL_SUCCESS);
}

/*
 * Destroy the hash table
 */
static void
hash_destroy(void)
{
	int i;
	frutree_hashelm_t	*el;
	hashdata_t	*datap = NULL;

	(void) rw_wrlock(&hash_lock);
	if (node_hash_table.tbl == NULL) {
		(void) rw_unlock(&hash_lock);
		return;
	}

	/* loop thru each linked list in the table and free */
	for (i = 0; i < node_hash_table.hash_size; ++i) {
		while (node_hash_table.tbl[i] != NULL) {
			el = node_hash_table.tbl[i];
			node_hash_table.tbl[i] = el->nextp;
			datap = (hashdata_t *)el->nodep;
			free_data(datap->type, datap);
			el->nodep = NULL;
			free(el);
			el = NULL;
		}
	}
	free(node_hash_table.tbl);
	(void) rw_unlock(&hash_lock);
}

/*
 * Add an entry to the hash table
 */
static picl_errno_t
hash_add_entry(picl_nodehdl_t hdl, void	*nodep)
{
	int indx;
	frutree_hashelm_t *el;

	FRUTREE_DEBUG0(HASHTABLE, "hash_add_entry : begin");
	(void) rw_wrlock(&hash_lock);

	if (node_hash_table.tbl == NULL) {
		(void) rw_unlock(&hash_lock);
		return (PICL_NOTINITIALIZED);
	}

	el = (frutree_hashelm_t *)malloc(sizeof (frutree_hashelm_t));
	if (el == NULL) {
		(void) rw_unlock(&hash_lock);
		return (PICL_NOSPACE);
	}

	el->hdl = hdl;
	el->nodep = nodep;
	el->nextp = NULL;

	if (frutree_debug & HASHTABLE) {
		picl_nodehdl_t	nodeid;
		nodeid = hdl;
		cvt_ptree2picl(&nodeid);
		FRUTREE_DEBUG1(HASHTABLE, "added node: %llx", nodeid);
	}

	indx = HASH_INDEX(node_hash_table.hash_size, hdl);
	if (node_hash_table.tbl[indx] == NULL) {
		/* first element for this index */
		node_hash_table.tbl[indx] = el;
		(void) rw_unlock(&hash_lock);
		return (PICL_SUCCESS);
	}

	el->nextp = node_hash_table.tbl[indx];
	node_hash_table.tbl[indx] = el;
	(void) rw_unlock(&hash_lock);
	return (PICL_SUCCESS);
}

/*
 * Remove a hash entry from the table
 */
static picl_errno_t
hash_remove_entry(picl_nodehdl_t hdl)
{
	int i;
	hashdata_t *datap = NULL;
	frutree_hashelm_t *prev, *cur;

	(void) rw_wrlock(&hash_lock);

	if (node_hash_table.tbl == NULL) {
		(void) rw_unlock(&hash_lock);
		return (PICL_NOTINITIALIZED);
	}

	i = HASH_INDEX(node_hash_table.hash_size, hdl);

	/* check that the hash chain is not empty */
	if (node_hash_table.tbl[i] == NULL) {
		(void) rw_wrlock(&hash_lock);
		return (PICL_NODENOTFOUND);
	}

	/* search hash chain for entry to be removed */
	prev = NULL;
	cur = node_hash_table.tbl[i];
	while (cur) {
		if (cur->hdl == hdl) {
			if (prev == NULL) {	/* 1st elem in hash chain */
				node_hash_table.tbl[i] = cur->nextp;
			} else {
				prev->nextp = cur->nextp;
			}
			datap = (hashdata_t *)cur->nodep;
			free_data(datap->type, datap);
			cur->nodep = NULL;
			free(cur);
			cur = NULL;

			if (frutree_debug & HASHTABLE) {
				picl_nodehdl_t	nodeid;
				nodeid = hdl;
				cvt_ptree2picl(&nodeid);
				FRUTREE_DEBUG1(HASHTABLE, "removed node: %llx",
					nodeid);
			}

			(void) rw_unlock(&hash_lock);
			return (PICL_SUCCESS);
		}
		prev = cur;
		cur = cur->nextp;
	}

	/*  entry was not found */
	(void) rw_unlock(&hash_lock);
	return (PICL_NODENOTFOUND);
}

/*
 * Lookup a handle in the table
 */
static picl_errno_t
hash_lookup_entry(picl_nodehdl_t hdl, void **nodepp)
{
	int i;
	frutree_hashelm_t *el;

	FRUTREE_DEBUG1(HASHTABLE, "hash_lookup begin: %llx", hdl);
	(void) rw_rdlock(&hash_lock);

	if (node_hash_table.tbl == NULL) {
		(void) rw_unlock(&hash_lock);
		return (PICL_NOTINITIALIZED);
	}
	if (nodepp == NULL) {
		(void) rw_unlock(&hash_lock);
		return (PICL_INVALIDHANDLE);
	}

	i = HASH_INDEX(node_hash_table.hash_size, hdl);

	if (node_hash_table.tbl[i] == NULL) {
		(void) rw_unlock(&hash_lock);
		return (PICL_NODENOTFOUND);
	}

	el = node_hash_table.tbl[i];
	while (el) {
		if (el->hdl == hdl) {
			*nodepp = el->nodep;
			(void) rw_unlock(&hash_lock);
			return (PICL_SUCCESS);
		}
		el = el->nextp;
	}
	(void) rw_unlock(&hash_lock);
	return (PICL_NODENOTFOUND);
}

/* create and initialize data structure for a loc node */
static picl_errno_t
make_loc_data(char *full_name, hashdata_t **hashptr)
{
	char		*name_copy;
	frutree_locnode_t	*locp;
	hashdata_t	*datap = NULL;

	datap = (hashdata_t *)malloc(sizeof (hashdata_t));
	if (datap == NULL) {
		return (PICL_NOSPACE);
	}
	datap->type = LOC_TYPE;

	/* allocate the data */
	locp = (frutree_locnode_t *)malloc(sizeof (frutree_locnode_t));
	if (locp == NULL) {
		free(datap);
		return (PICL_NOSPACE);
	}

	/* make a copy of the name */
	name_copy = strdup(full_name);
	if (name_copy == NULL) {
		free(locp);
		free(datap);
		return (PICL_NOSPACE);
	}

	/* initialize the data */
	locp->name = name_copy;
	locp->locnodeh = 0;
	locp->state = LOC_STATE_UNKNOWN;
	locp->prev_state = LOC_STATE_UNKNOWN;
	locp->cpu_node = B_FALSE;
	locp->autoconfig_enabled = B_FALSE;
	locp->state_mgr = UNKNOWN;
	locp->dr_in_progress = B_FALSE;
	(void) pthread_mutex_init(&locp->mutex, NULL);
	(void) pthread_cond_init(&locp->cond_cv, NULL);

	datap->data = locp;
	*hashptr = datap;
	return (PICL_SUCCESS);
}

/* create and initialize data structure for a fru node */
static picl_errno_t
make_fru_data(char *full_name, hashdata_t **hashptr)
{
	char		*name_copy;
	frutree_frunode_t	*frup;
	hashdata_t	*datap = NULL;

	datap = (hashdata_t *)malloc(sizeof (hashdata_t));
	if (datap == NULL) {
		return (PICL_NOSPACE);
	}
	datap->type = FRU_TYPE;

	/* allocate the data */
	frup = (frutree_frunode_t *)malloc(sizeof (frutree_frunode_t));
	if (frup == NULL) {
		free(datap);
		return (PICL_NOSPACE);
	}

	/* make a copy of the name */
	name_copy = strdup(full_name);
	if (name_copy == NULL) {
		free(frup);
		free(datap);
		return (PICL_NOSPACE);
	}

	/* initialize the data */
	frup->name = name_copy;
	frup->frunodeh = 0;
	frup->state = FRU_STATE_UNCONFIGURED;
	frup->prev_state = FRU_STATE_UNKNOWN;
	frup->cond = FRU_COND_UNKNOWN;
	frup->prev_cond = FRU_COND_UNKNOWN;
	frup->cpu_node = B_FALSE;
	frup->autoconfig_enabled = B_FALSE;
	frup->dr_in_progress = B_FALSE;
	frup->busy = B_FALSE;
	frup->state_mgr = UNKNOWN;
	frup->fru_path[0] = '\0';
	(void) pthread_mutex_init(&frup->mutex, NULL);
	(void) pthread_cond_init(&frup->cond_cv, NULL);
	(void) pthread_cond_init(&frup->busy_cond_cv, NULL);

	datap->data = frup;
	*hashptr = datap;
	return (PICL_SUCCESS);
}

/* create and initialize data structure for a port node */
static picl_errno_t
make_port_data(char *full_name, hashdata_t **hashptr)
{
	char *name_copy;
	frutree_portnode_t *portp;
	hashdata_t *datap = NULL;

	datap = (hashdata_t *)malloc(sizeof (hashdata_t));
	if (datap == NULL) {
		return (PICL_NOSPACE);
	}
	datap->type = PORT_TYPE;

	/* allocate the data */
	portp = (frutree_portnode_t *)malloc(sizeof (frutree_portnode_t));
	if (portp == NULL) {
		free(datap);
		return (PICL_NOSPACE);
	}
	/* make a copy of the name */
	name_copy = strdup(full_name);
	if (name_copy == NULL) {
		free(portp);
		free(datap);
		return (PICL_NOSPACE);
	}

	/* initialize the data */
	portp->name = name_copy;
	portp->portnodeh = 0;
	portp->state = PORT_STATE_UNKNOWN;
	portp->cond = PORT_COND_UNKNOWN;
	datap->data = portp;
	*hashptr = datap;
	return (PICL_SUCCESS);
}

/*
 * utility routine to create table entries
 */
static picl_errno_t
create_table_entry(picl_prophdl_t tblhdl, picl_nodehdl_t refhdl, char *class)
{
	picl_errno_t		rc;
	ptree_propinfo_t	propinfo;
	picl_prophdl_t		prophdl[2];
	char			buf[PICL_CLASSNAMELEN_MAX];

	/* first column is class */
	if ((rc = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		PICL_PTYPE_CHARSTRING, PICL_READ, PICL_CLASSNAMELEN_MAX,
		PICL_PROP_CLASS, NULLREAD,
		NULLWRITE)) != PICL_SUCCESS) {
		return (rc);
	}

	if ((rc = ptree_create_prop(&propinfo, class,
		&prophdl[0])) != PICL_SUCCESS) {
		return (rc);
	}

	/* second column is reference property */
	(void) snprintf(buf, sizeof (buf), "_%s_", class);
	if ((rc = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		PICL_PTYPE_REFERENCE, PICL_READ,
		sizeof (picl_nodehdl_t), buf, NULLREAD,
		NULLWRITE)) != PICL_SUCCESS) {
		return (rc);
	}

	if ((rc = ptree_create_prop(&propinfo, &refhdl,
		&prophdl[1])) != PICL_SUCCESS) {
		return (rc);
	}

	/* add row to table */
	if ((rc = ptree_add_row_to_table(tblhdl, 2, prophdl)) != PICL_SUCCESS) {
		return (rc);
	}
	return (PICL_SUCCESS);
}

/*
 * Utility routine to create picl property
 */
static picl_errno_t
create_property(int ptype, int pmode, size_t psize, char *pname,
	int (*readfn)(ptree_rarg_t *, void *),
	int (*writefn)(ptree_warg_t *, const void *),
	picl_nodehdl_t nodeh, picl_prophdl_t *prophp, void *vbuf)
{
	picl_errno_t		rc;
	ptree_propinfo_t	propinfo;
	picl_prophdl_t		proph;

	if (pname == NULL || vbuf == NULL) {
		return (PICL_FAILURE);
	}

	if (ptype == PICL_PTYPE_TABLE) {
		if ((rc = ptree_create_table((picl_prophdl_t *)vbuf))
			!= PICL_SUCCESS) {
			return (rc);
		}
	}

	if ((rc = ptree_get_prop_by_name(nodeh, pname, &proph)) ==
		PICL_SUCCESS) {	/* property already exists */
		return (rc);
	}

	rc = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		ptype, pmode, psize, pname, readfn, writefn);
	if (rc != PICL_SUCCESS) {
		return (rc);
	}

	rc = ptree_create_and_add_prop(nodeh, &propinfo, vbuf, prophp);
	if (rc != PICL_SUCCESS) {
		return (rc);
	}
	return (PICL_SUCCESS);
}

/*
 *  create frutree node, chassis node
 */
static picl_errno_t
initialize_frutree()
{
	int rc = PICL_SUCCESS;
	hashdata_t *datap = NULL;
	frutree_frunode_t *frup = NULL;
	uint64_t ap_status_time;

	FRUTREE_DEBUG0(FRUTREE_INIT, "initialize_frutree begin");
	/* Get the root of the PICL tree */
	if ((rc = ptree_get_root(&rooth)) != PICL_SUCCESS) {
		return (rc);
	}
	FRUTREE_DEBUG1(FRUTREE_INIT, "roothdl = %llx", rooth);

	/* create /frutree node */
	if ((rc = ptree_create_and_add_node(rooth, PICL_NODE_FRUTREE,
		PICL_CLASS_PICL, &frutreeh)) != PICL_SUCCESS) {
		return (rc);
	}
	FRUTREE_DEBUG1(FRUTREE_INIT, "frutreeh = %llx", frutreeh);

	/* create chassis node */
	if ((rc = ptree_create_node(PICL_NODE_CHASSIS, PICL_CLASS_FRU,
		&chassish)) != PICL_SUCCESS) {
		return (rc);
	}
	FRUTREE_DEBUG1(FRUTREE_INIT, "chassish = %llx", chassish);

	/* Allocate fru data */
	if ((rc = make_fru_data(PICL_NODE_CHASSIS, &datap)) !=
		PICL_SUCCESS) {
		(void) ptree_destroy_node(chassish);
		return (rc);
	}
	/* initialise chassis handle and parent handle */
	frup = FRUDATA_PTR(datap);
	frup->frunodeh = chassish;

	/* Add the chassis node to the tree */
	if ((rc = ptree_add_node(frutreeh, chassish)) != PICL_SUCCESS) {
		free_data(datap->type, datap);
		(void) ptree_destroy_node(chassish);
		return (rc);
	}

	/* create chassis  state property */
	if ((rc = create_property(PICL_PTYPE_CHARSTRING,
		PICL_READ, PICL_PROPNAMELEN_MAX, PICL_PROP_STATE,
		NULLREAD, NULLWRITE, chassish, (picl_prophdl_t *)NULL,
		PICLEVENTARGVAL_UNCONFIGURED)) != PICL_SUCCESS) {
		free_data(datap->type, datap);
		(void) ptree_delete_node(chassish);
		(void) ptree_destroy_node(chassish);
		return (rc);
	}
	ap_status_time = (uint64_t)(time(NULL));
	if ((rc = create_property(PICL_PTYPE_TIMESTAMP, PICL_READ,
		sizeof (ap_status_time), PICL_PROP_STATUS_TIME,
		NULLREAD, NULLWRITE, chassish,
		NULL, &ap_status_time)) != PICL_SUCCESS) {
		free_data(datap->type, datap);
		(void) ptree_delete_node(chassish);
		(void) ptree_destroy_node(chassish);
		return (rc);
	}

	/* save chassis info in hashtable */
	if ((rc = hash_add_entry(chassish,
		(void *)datap)) != PICL_SUCCESS) {
		free_data(datap->type, datap);
		(void) ptree_delete_node(chassish);
		(void) ptree_destroy_node(chassish);
		return (rc);
	}
	return (PICL_SUCCESS);
}

/*
 * Read the temporary property created by platform specific
 * plugin to get the config file name.
 */
static picl_errno_t
get_configuration_file()
{
	picl_errno_t rc;
	picl_prophdl_t proph;
	char file_name[PICL_PROPNAMELEN_MAX];

	if ((rc = ptree_get_prop_by_name(chassish,
		PICL_PROP_CONF_FILE, &proph)) != PICL_SUCCESS) {
		return (rc);
	}

	if ((rc = ptree_get_propval(proph, file_name,
		sizeof (file_name))) != PICL_SUCCESS) {
		return (rc);
	}

	(void) snprintf(conf_file, sizeof (conf_file),
		PICLD_PLAT_PLUGIN_DIRF"%s", sys_name, file_name);
	/* delete the tmp prop created by platform specific plugin */
	(void) ptree_delete_prop(proph);
	(void) ptree_destroy_prop(proph);
	FRUTREE_DEBUG1(EVENTS, "Using %s conf file", conf_file);
	return (PICL_SUCCESS);
}

/*
 * Read the cfgadm data and get the latest information
 */
static picl_errno_t
get_cfgadm_state(cfga_list_data_t *data, char *ap_id)
{
	int nlist;
	cfga_err_t	ap_list_err;
	cfga_list_data_t *list = NULL;
	char * const *p = &ap_id;

	if (data == NULL || ap_id == NULL) {
		return (PICL_INVALIDARG);
	}

	ap_list_err = config_list_ext(1, p, &list, &nlist, NULL,
		NULL, NULL, 0);
	if (ap_list_err != CFGA_OK) {
		free(list);
		return (cfg2picl_errmap[ap_list_err][1]);
	}

	(void) memcpy(data, list, sizeof (cfga_list_data_t));
	free(list);
	return (PICL_SUCCESS);
}

/*
 * syncup with cfgadm data and read latest location state information
 */
static picl_errno_t
update_loc_state(frutree_locnode_t *locp, boolean_t *updated)
{
	int i = 0;
	cfga_list_data_t *list = NULL;
	picl_errno_t rc, rc1;
	char valbuf[PICL_PROPNAMELEN_MAX];
	char slot_type[PICL_PROPNAMELEN_MAX];
	uint64_t ap_status_time;

	*updated = B_FALSE;
	if (locp->state_mgr == PLUGIN_PVT) {
		if ((rc = ptree_get_propval_by_name(locp->locnodeh,
			PICL_PROP_STATE, (void *)valbuf,
			PICL_PROPNAMELEN_MAX)) != PICL_SUCCESS) {
			return (rc);
		}

		/* if there is a change in state, update the internal value */
		if (strcmp(loc_state[locp->state], valbuf) != 0) {
			ap_status_time = (uint64_t)(time(NULL));
			if ((rc = ptree_update_propval_by_name(locp->locnodeh,
				PICL_PROP_STATUS_TIME, (void *)&ap_status_time,
				sizeof (ap_status_time))) != PICL_SUCCESS) {
				FRUTREE_DEBUG3(EVENTS, PTREE_UPDATE_PROP_ERR,
					PICL_PROP_STATUS_TIME, locp->name, rc);
			}
			*updated = B_TRUE;
			locp->prev_state = locp->state;
			for (i = 0; (loc_state[i] != NULL); i++) {
				if (strcmp(loc_state[i], valbuf) == 0) {
					locp->state = i;
					return (PICL_SUCCESS);
				}
			}
		}
		return (PICL_SUCCESS);
	} else if (locp->state_mgr == STATIC_LOC) {
		return (PICL_SUCCESS);
	}

	/*  get the info from the libcfgadm interface */
	list = (cfga_list_data_t *)malloc(sizeof (cfga_list_data_t));
	if (list == NULL) {
		return (PICL_NOSPACE);
	}

	if ((rc = get_cfgadm_state(list, locp->name)) != PICL_SUCCESS) {
		if ((rc1 = ptree_get_propval_by_name(locp->locnodeh,
			PICL_PROP_SLOT_TYPE, slot_type,
			sizeof (slot_type))) != PICL_SUCCESS) {
			free(list);
			return (rc1);
		}
		if (strcmp(slot_type, SANIBEL_SCSI_SLOT) != 0 &&
			strcmp(slot_type, SANIBEL_IDE_SLOT) != 0) {
			free(list);
			return (rc);
		}
		/* this is a scsi location */
		if (rc != PICL_NODENOTFOUND) {
			free(list);
			return (rc);
		}

		/*
		 * for scsi locations, if node is not found,
		 * consider location state as empty
		 */
		(void) pthread_mutex_lock(&locp->mutex);
		if (locp->state != LOC_STATE_EMPTY) {
			*updated = B_TRUE;
			locp->prev_state = locp->state;
			locp->state = LOC_STATE_EMPTY;
			ap_status_time = (uint64_t)(time(NULL));
			if ((rc = ptree_update_propval_by_name(locp->locnodeh,
				PICL_PROP_STATUS_TIME, (void *)&ap_status_time,
				sizeof (ap_status_time))) != PICL_SUCCESS) {
				FRUTREE_DEBUG3(EVENTS, PTREE_UPDATE_PROP_ERR,
					PICL_PROP_STATUS_TIME, locp->name, rc);
			}
		}
		(void) pthread_mutex_unlock(&locp->mutex);
		free(list);
		return (PICL_SUCCESS);
	}

	(void) pthread_mutex_lock(&locp->mutex);
	switch (list->ap_r_state) {
	case CFGA_STAT_CONNECTED:
		if (locp->state != LOC_STATE_CONNECTED) {
			*updated = B_TRUE;
			locp->prev_state = locp->state;
			locp->state = LOC_STATE_CONNECTED;
		}
		break;
	case CFGA_STAT_DISCONNECTED:
		if (locp->state != LOC_STATE_DISCONNECTED) {
			*updated = B_TRUE;
			locp->prev_state = locp->state;
			locp->state = LOC_STATE_DISCONNECTED;
		}
		break;
	case CFGA_STAT_EMPTY:
		if (locp->state != LOC_STATE_EMPTY) {
			*updated = B_TRUE;
			locp->prev_state = locp->state;
			locp->state = LOC_STATE_EMPTY;
		}
		break;
	default:
		if (locp->state != LOC_STATE_UNKNOWN) {
			*updated = B_TRUE;
			locp->prev_state = locp->state;
			locp->state = LOC_STATE_UNKNOWN;
		}
	}

	if (*updated == B_TRUE) {
		ap_status_time = (uint64_t)(time(NULL));
		if ((rc = ptree_update_propval_by_name(locp->locnodeh,
			PICL_PROP_STATUS_TIME, (void *)&ap_status_time,
			sizeof (ap_status_time))) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_UPDATE_PROP_ERR,
				PICL_PROP_STATUS_TIME, locp->name, rc);
		}
	}

	/* update the autoconfig flag */
	switch (is_autoconfig_enabled(locp->name)) {
		case 1:
			locp->autoconfig_enabled = B_TRUE;
			break;
		case 0:
		default:
			locp->autoconfig_enabled = B_FALSE;
			break;
	}
	(void) pthread_mutex_unlock(&locp->mutex);

	free(list);
	return (PICL_SUCCESS);
}

/*
 * volatile callback function to return the state value for a location
 */
static int
get_loc_state(ptree_rarg_t  *rarg, void *buf)
{
	picl_errno_t rc;
	frutree_dr_arg_t dr_arg;
	hashdata_t *hashptr = NULL;
	frutree_locnode_t *locp = NULL;
	boolean_t state_change = B_FALSE;

	if (buf == NULL) {
		return (PICL_INVALIDARG);
	}

	if ((rc = hash_lookup_entry(rarg->nodeh, (void **)&hashptr)) !=
		PICL_SUCCESS) {
		return (rc);
	}

	locp = LOCDATA_PTR(hashptr);
	if (locp == NULL) {
		return (PICL_FAILURE);
	}

	(void) pthread_mutex_lock(&locp->mutex);
	if (locp->dr_in_progress == B_TRUE) {
		/* return the cached value */
		(void) strncpy((char *)buf, loc_state[locp->state],
			PICL_PROPNAMELEN_MAX);
		(void) pthread_mutex_unlock(&locp->mutex);
		return (PICL_SUCCESS);
	}
	(void) pthread_mutex_unlock(&locp->mutex);

	if ((rc = update_loc_state(locp, &state_change)) != PICL_SUCCESS) {
		FRUTREE_DEBUG2(EVENTS, GET_LOC_STATE_ERR, locp->name, rc);
		/* return the cached value */
		(void) strncpy((char *)buf, loc_state[locp->state],
			PICL_PROPNAMELEN_MAX);
		return (rc);
	}

	/* if there is a state change, handle the event */
	if (state_change) {
		(void) pthread_mutex_lock(&locp->mutex);
		if (locp->state == LOC_STATE_EMPTY) { /* card removed */
			dr_arg.action = HANDLE_REMOVE;
		} else if (locp->prev_state == LOC_STATE_EMPTY) {
			dr_arg.action = HANDLE_INSERT; /* card inserted */
		} else {
			/* loc state changed */
			dr_arg.action = HANDLE_LOCSTATE_CHANGE;
		}
		(void) pthread_mutex_unlock(&locp->mutex);
		dr_arg.data = locp;
		(void) pthread_mutex_lock(&ev_mutex);
		if ((rc = add_to_queue(dr_arg)) != PICL_SUCCESS) {
			(void) pthread_mutex_unlock(&ev_mutex);
			FRUTREE_DEBUG3(EVENTS, EVENT_NOT_HANDLED,
				"dr_ap_state_change", locp->name, rc);
		} else {
			(void) pthread_cond_signal(&ev_cond);
			(void) pthread_mutex_unlock(&ev_mutex);
		}
	}

	(void) strncpy((char *)buf, loc_state[locp->state],
		PICL_PROPNAMELEN_MAX);
	return (PICL_SUCCESS);
}

/*
 * syncup with cfgadm data and read latest fru state information
 */
static picl_errno_t
update_fru_state(frutree_frunode_t *frup, boolean_t *updated)
{
	int i;
	picl_errno_t rc;
	picl_nodehdl_t loch;
	uint64_t ap_status_time;
	hashdata_t *hashptr = NULL;
	cfga_list_data_t *list = NULL;
	frutree_locnode_t *locp = NULL;
	char valbuf[PICL_PROPNAMELEN_MAX];

	*updated = B_FALSE;
	if (frup->state_mgr == PLUGIN_PVT) {
		if ((rc = ptree_get_propval_by_name(frup->frunodeh,
			PICL_PROP_STATE, (void *)valbuf,
			PICL_PROPNAMELEN_MAX)) != PICL_SUCCESS) {
			return (rc);
		}

		/* if there is a change in state, update the internal value */
		if (strcmp(fru_state[frup->state], valbuf) != 0) {
			*updated = B_TRUE;
			frup->prev_state = frup->state;
			ap_status_time = (uint64_t)(time(NULL));
			if ((rc = ptree_update_propval_by_name(frup->frunodeh,
				PICL_PROP_STATUS_TIME, (void *)&ap_status_time,
				sizeof (ap_status_time))) != PICL_SUCCESS) {
				if (rc == PICL_PROPNOTFOUND) {
					(void) create_property(
						PICL_PTYPE_TIMESTAMP, PICL_READ,
							sizeof (ap_status_time),
							PICL_PROP_STATUS_TIME,
							NULLREAD, NULLWRITE,
							frup->frunodeh,
							NULL, &ap_status_time);
				} else {
					FRUTREE_DEBUG3(EVENTS,
						PTREE_UPDATE_PROP_ERR,
						PICL_PROP_STATUS_TIME,
						frup->name, rc);
				}
			}
			for (i = 0; (fru_state[i] != NULL); i++) {
				if (strcmp(fru_state[i], valbuf) == 0) {
					frup->state = i;
					return (PICL_SUCCESS);
				}
			}
		}
		return (PICL_SUCCESS);
	} else if (frup->state_mgr == STATIC_LOC) {
		frup->state = FRU_STATE_CONFIGURED;
		return (PICL_SUCCESS);
	}

	if ((rc = ptree_get_propval_by_name(frup->frunodeh, PICL_PROP_PARENT,
		&loch, sizeof (loch))) != PICL_SUCCESS) {
		return (rc);
	}

	if ((rc = hash_lookup_entry(loch, (void **)&hashptr)) !=
		PICL_SUCCESS) {
		return (rc);
	}
	locp = LOCDATA_PTR(hashptr);
	if (locp == NULL) {
		return (PICL_FAILURE);
	}

	list = (cfga_list_data_t *)malloc(sizeof (cfga_list_data_t));
	if (list == NULL) {
		return (PICL_NOSPACE);
	}

	if ((rc = get_cfgadm_state(list, locp->name)) != PICL_SUCCESS) {
		free(list);
		return (rc);
	}

	(void) pthread_mutex_lock(&frup->mutex);
	switch (list->ap_o_state) {
	case CFGA_STAT_CONFIGURED:
		if (frup->state != FRU_STATE_CONFIGURED) {
			*updated = B_TRUE;
			frup->prev_state = frup->state;
			frup->state = FRU_STATE_CONFIGURED;
		}
		break;
	case CFGA_STAT_UNCONFIGURED:
		if (frup->state != FRU_STATE_UNCONFIGURED) {
			*updated = B_TRUE;
			frup->prev_state = frup->state;
			frup->state = FRU_STATE_UNCONFIGURED;
		}
		break;
	default:
		if (frup->state != FRU_STATE_UNKNOWN) {
			*updated = B_TRUE;
			frup->prev_state = frup->state;
			frup->state = FRU_STATE_UNKNOWN;
		}
		break;
	}

	/* update the fru_type property */
	if (list->ap_type) {
		if ((rc = ptree_update_propval_by_name(frup->frunodeh,
			PICL_PROP_FRU_TYPE, list->ap_type,
			sizeof (list->ap_type))) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_UPDATE_PROP_ERR,
				PICL_PROP_FRU_TYPE, frup->name, rc);
		}
	}

	if (*updated == B_TRUE) {
		ap_status_time = (uint64_t)(time(NULL));
		if ((rc = ptree_update_propval_by_name(frup->frunodeh,
			PICL_PROP_STATUS_TIME, (void *)&ap_status_time,
			sizeof (ap_status_time))) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_UPDATE_PROP_ERR,
				PICL_PROP_STATUS_TIME, frup->name, rc);
		}
	}
	(void) pthread_mutex_unlock(&frup->mutex);

	free(list);
	return (PICL_SUCCESS);
}

/*
 * syncup with cfgadm data and read latest fru condition information
 */
static picl_errno_t
update_fru_condition(frutree_frunode_t *frup, boolean_t *updated)
{
	int i = 0;
	picl_errno_t rc;
	picl_nodehdl_t loch;
	uint64_t ap_cond_time;
	hashdata_t *hashptr = NULL;
	cfga_list_data_t *list = NULL;
	frutree_locnode_t *locp = NULL;
	char valbuf[PICL_PROPNAMELEN_MAX];

	*updated = B_FALSE;
	if (frup->state_mgr == PLUGIN_PVT) {
		if ((rc = ptree_get_propval_by_name(frup->frunodeh,
			PICL_PROP_CONDITION, (void *)valbuf,
			PICL_PROPNAMELEN_MAX)) != PICL_SUCCESS) {
			return (rc);
		}

		/*
		 * if there is a change in condition, update the
		 * internal value
		 */
		if (strcmp(fru_cond[frup->cond], valbuf) != 0) {
			*updated = B_TRUE;
			ap_cond_time = (uint64_t)(time(NULL));
			if ((rc = ptree_update_propval_by_name(frup->frunodeh,
				PICL_PROP_CONDITION_TIME, (void *)&ap_cond_time,
				sizeof (ap_cond_time))) != PICL_SUCCESS) {
				FRUTREE_DEBUG3(EVENTS, PTREE_UPDATE_PROP_ERR,
					PICL_PROP_CONDITION_TIME, frup->name,
					rc);
			}
			frup->prev_cond = frup->cond;

			for (i = 0; (fru_cond[i] != NULL); i++) {
				if (strcmp(fru_cond[i], valbuf) == 0) {
					frup->cond = i;
					return (PICL_SUCCESS);
				}
			}
		}
		return (PICL_SUCCESS);
	} else if (frup->state_mgr == STATIC_LOC) {
		frup->cond = FRU_COND_OK;
		return (PICL_SUCCESS);
	}

	if ((rc = ptree_get_propval_by_name(frup->frunodeh, PICL_PROP_PARENT,
		&loch, sizeof (loch))) != PICL_SUCCESS) {
		return (rc);
	}

	if ((rc = hash_lookup_entry(loch, (void **)&hashptr)) !=
		PICL_SUCCESS) {
		return (rc);
	}

	locp = LOCDATA_PTR(hashptr);
	if (locp == NULL) {
		return (PICL_FAILURE);
	}
	list = (cfga_list_data_t *)malloc(sizeof (cfga_list_data_t));
	if (list == NULL) {
		return (PICL_NOSPACE);
	}

	if ((rc = get_cfgadm_state(list, locp->name)) != PICL_SUCCESS) {
		free(list);
		return (rc);
	}

	switch (list->ap_cond) {
	case CFGA_COND_OK:
		if (frup->cond != FRU_COND_OK) {
			*updated = B_TRUE;
			frup->prev_cond = frup->cond;
			frup->cond = FRU_COND_OK;
		}
		break;
	case CFGA_COND_FAILING:
		if (frup->cond != FRU_COND_FAILING) {
			*updated = B_TRUE;
			frup->prev_cond = frup->cond;
			frup->cond = FRU_COND_FAILING;
		}
		break;
	case CFGA_COND_FAILED:
	case CFGA_COND_UNUSABLE:
		if (frup->cond != FRU_COND_FAILED) {
			*updated = B_TRUE;
			frup->prev_cond = frup->cond;
			frup->cond = FRU_COND_FAILED;
		}
		break;
	default:
		if (frup->cond != FRU_COND_UNKNOWN) {
			*updated = B_TRUE;
			frup->prev_cond = frup->cond;
			frup->cond = FRU_COND_UNKNOWN;
		}
	}

	if (*updated == B_TRUE) {
		ap_cond_time = (uint64_t)(time(NULL));
		if ((rc = ptree_update_propval_by_name(frup->frunodeh,
			PICL_PROP_CONDITION_TIME, (void *)&ap_cond_time,
			sizeof (ap_cond_time))) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_UPDATE_PROP_ERR,
				PICL_PROP_CONDITION_TIME, frup->name, rc);
		}
	}
	free(list);
	return (PICL_SUCCESS);
}

/*
 * Volatile callback function to read fru state
 */
static int
get_fru_state(ptree_rarg_t  *rarg, void *buf)
{
	picl_errno_t		rc;
	hashdata_t		*hashptr = NULL;
	frutree_frunode_t	*frup = NULL;
	boolean_t state_change = B_FALSE;
	frutree_dr_arg_t dr_arg;

	if (buf == NULL) {
		return (PICL_INVALIDARG);
	}

	if ((rc = hash_lookup_entry(rarg->nodeh, (void **)&hashptr)) !=
		PICL_SUCCESS) {
		return (rc);
	}

	frup = FRUDATA_PTR(hashptr);
	if (frup == NULL) {
		return (PICL_FAILURE);
	}

	/* return the cached value, if dr is in progress */
	(void) pthread_mutex_lock(&frup->mutex);
	if (frup->dr_in_progress) {
		(void) pthread_mutex_unlock(&frup->mutex);
		(void) strncpy((char *)buf, fru_state[frup->state],
			PICL_PROPNAMELEN_MAX);
		return (PICL_SUCCESS);
	}
	(void) pthread_mutex_unlock(&frup->mutex);

	if ((rc = update_fru_state(frup, &state_change)) != PICL_SUCCESS) {
		FRUTREE_DEBUG2(EVENTS, GET_FRU_STATE_ERR, frup->name, rc);
		/* return the cached value */
		(void) strncpy((char *)buf, fru_state[frup->state],
			PICL_PROPNAMELEN_MAX);
		return (rc);
	}

	/* if there is a state change, handle the event */
	if (state_change) {
		(void) pthread_mutex_lock(&frup->mutex);
		/* figure out if this is config/unconfig operation */
		if (frup->state == FRU_STATE_CONFIGURED) {
			dr_arg.action = HANDLE_CONFIGURE;
			dr_arg.data = frup;
		} else if (frup->state == FRU_STATE_UNCONFIGURED) {
			dr_arg.action = HANDLE_UNCONFIGURE;
			dr_arg.data = frup;
		}
		(void) pthread_mutex_unlock(&frup->mutex);

		(void) pthread_mutex_lock(&ev_mutex);
		if ((rc = add_to_queue(dr_arg)) != PICL_SUCCESS) {
			(void) pthread_mutex_unlock(&ev_mutex);
			FRUTREE_DEBUG3(EVENTS, EVENT_NOT_HANDLED,
				"dr_ap_state_chage", frup->name, rc);
		} else {
			(void) pthread_cond_signal(&ev_cond);
			(void) pthread_mutex_unlock(&ev_mutex);
		}
	}

	(void) strncpy((char *)buf, fru_state[frup->state],
		PICL_PROPNAMELEN_MAX);

	return (PICL_SUCCESS);
}

/*
 * Volatile callback function to read fru condition
 */
static int
get_fru_condition(ptree_rarg_t  *rarg, void *buf)
{
	picl_errno_t rc;
	frutree_dr_arg_t dr_arg;
	hashdata_t *hashptr = NULL;
	frutree_frunode_t *frup = NULL;
	boolean_t cond_changed = B_FALSE;

	if (buf == NULL) {
		return (PICL_INVALIDARG);
	}

	if ((rc = hash_lookup_entry(rarg->nodeh, (void **)&hashptr)) !=
		PICL_SUCCESS) {
		return (rc);
	}

	frup = FRUDATA_PTR(hashptr);
	if (frup == NULL) {
		return (PICL_FAILURE);
	}

	/* return the cached value, if dr is in progress */
	(void) pthread_mutex_lock(&frup->mutex);
	if (frup->dr_in_progress) {
		(void) pthread_mutex_unlock(&frup->mutex);
		(void) strncpy((char *)buf, fru_cond[frup->cond],
			PICL_PROPNAMELEN_MAX);
		return (PICL_SUCCESS);

	}
	(void) pthread_mutex_unlock(&frup->mutex);

	if ((rc = update_fru_condition(frup, &cond_changed)) != PICL_SUCCESS) {
		FRUTREE_DEBUG2(EVENTS, GET_FRU_COND_ERR, frup->name, rc);
		/* return the cached value */
		(void) strncpy((char *)buf, fru_cond[frup->cond],
			PICL_PROPNAMELEN_MAX);
		return (rc);
	}
	if (cond_changed) {
		dr_arg.action = POST_COND_EVENT;
		dr_arg.data = frup;
		(void) pthread_mutex_lock(&ev_mutex);
		if ((rc = add_to_queue(dr_arg)) != PICL_SUCCESS) {
			(void) pthread_mutex_unlock(&ev_mutex);
			FRUTREE_DEBUG3(EVENTS, EVENT_NOT_HANDLED,
				"condition event", frup->name, rc);
		} else {
			(void) pthread_cond_signal(&ev_cond);
			(void) pthread_mutex_unlock(&ev_mutex);
		}
	}

	/* if there is a condition change, post picl event */
	(void) strncpy((char *)buf, fru_cond[frup->cond],
		PICL_PROPNAMELEN_MAX);

	return (PICL_SUCCESS);
}

static void
free_cache(frutree_cache_t *cachep)
{
	frutree_cache_t	*tmp = NULL;
	if (cachep == NULL)
		return;

	while (cachep != NULL) {
		tmp = cachep;
		cachep = cachep->next;
		free(tmp);
	}
}

/*
 * traverse the /platform tree in PICL tree to create logical devices table
 */
static picl_errno_t
probe_platform_tree(frutree_frunode_t *frup, frutree_device_args_t **devp)
{
	picl_errno_t  rc;
	picl_nodehdl_t refhdl = 0;
	char class[PICL_CLASSNAMELEN_MAX];
	frutree_device_args_t *device = NULL;
	picl_prophdl_t tblprophdl;
	picl_prophdl_t dev_tblhdl, env_tblhdl = 0;

	if (devp == NULL) {
		return (PICL_FAILURE);
	}
	device = *(frutree_device_args_t **)devp;
	if (device == NULL) {
		return (PICL_FAILURE);
	}

	/* traverse thru platform tree and add entries to Devices table */
	if ((refhdl = get_reference_handle(frup->frunodeh)) == 0) {
		return (PICL_NODENOTFOUND);
	}

	/* create Devices table property */
	if ((rc = create_property(PICL_PTYPE_TABLE, PICL_READ,
		sizeof (picl_prophdl_t), PICL_PROP_DEVICES, NULLREAD,
		NULLWRITE, frup->frunodeh, &tblprophdl, &dev_tblhdl)) !=
		PICL_SUCCESS) {
		return (rc);
	}

	if ((rc = ptree_get_propval_by_name(refhdl, PICL_PROP_CLASSNAME,
		class, sizeof (class))) != PICL_SUCCESS) {
		return (rc);
	}

	if ((rc = create_table_entry(dev_tblhdl, refhdl, class)) !=
		PICL_SUCCESS) {
		return (rc);
	}

	/* create Environment devices table property */
	if ((rc = create_property(PICL_PTYPE_TABLE, PICL_READ,
		sizeof (picl_prophdl_t), PICL_PROP_ENV, NULLREAD,
		NULLWRITE, frup->frunodeh, &tblprophdl, &env_tblhdl)) !=
		PICL_SUCCESS) {
		return (rc);
	}

	device->nodeh  = refhdl;
	device->device_tblhdl = dev_tblhdl;
	device->env_tblhdl = env_tblhdl;
	device->first  = NULL;
	device->last   = NULL;
	device->create_cache   = B_FALSE;

	/* probe using platform tree info */
	if ((rc = do_action(refhdl, CREATE_DEVICES_ENTRIES,
		device)) != PICL_SUCCESS) {
		free_cache(device->first);
		return (rc);
	}
	return (PICL_SUCCESS);
}

/*
 * create temp conf file to pass it to picld util lib to create
 * nodes under the fru
 */
static picl_errno_t
create_fru_children(frutree_frunode_t *frup, frutree_device_args_t device)
{
	int fd;
	picl_errno_t	rc;
	char 		conffile[MAXPATHLEN];
	char 		dir[MAXPATHLEN];
	struct stat	file_stat;
	char		version[BUF_SIZE];
	frutree_cache_t	*cachep = NULL;

	cachep = device.first;
	if (cachep == NULL) {
		return (PICL_SUCCESS);
	}

	/* create the configuration file for the fru */
	(void) snprintf(dir, MAXPATHLEN, "%s%s", TEMP_DIR, frup->name);
	bzero(&file_stat, sizeof (file_stat));
	if (stat(conffile, &file_stat) == -1) {
		if (mkdir(conffile, 0755) == -1) {
			return (PICL_FAILURE);
		}
	}

	(void) snprintf(conffile, MAXPATHLEN, "%s/%s", dir, PROBE_FILE);
	if ((fd = open(conffile, O_WRONLY|O_CREAT|O_TRUNC, 0644)) == -1) {
		(void) rmdir(dir);
		return (PICL_FAILURE);
	}

	(void) snprintf(version, sizeof (version), "VERSION %d.0",
		PTREE_PROPINFO_VERSION);
	if (write(fd, version, strlen(version)) != strlen(version)) {
		(void) remove(conffile);
		(void) rmdir(dir);
		(void) close(fd);
		return (PICL_FAILURE);
	}

	/* traverse thru each cache entry and append to conf file */
	while (cachep != NULL) {
		if (write(fd, cachep->buf, strlen(cachep->buf))
			!= strlen(cachep->buf)) {
			(void) close(fd);
			(void) remove(conffile);
			(void) rmdir(dir);
			return (PICL_FAILURE);
		}
		cachep = cachep->next;
	}
	(void) close(fd);

	/* create child nodes for fru using the conffile created */
	if ((rc = picld_pluginutil_parse_config_file(frup->frunodeh,
		conffile)) != PICL_SUCCESS) {
		(void) remove(conffile);
		(void) rmdir(dir);
		return (rc);
	}
	(void) remove(conffile);
	(void) rmdir(dir);

	if ((rc = fru_init(frup)) != PICL_SUCCESS) {
		return (rc);
	}
	return (PICL_SUCCESS);
}

/*
 * probes libdevinfo and create the port nodes under a fru
 * probes for any scsi devices under a fru
 */
static picl_errno_t
probe_fru(frutree_frunode_t *frup, boolean_t load_drivers)
{
	picl_errno_t rc;
	picl_nodehdl_t child, loch;
	char slot_type[PICL_PROPNAMELEN_MAX];
	char devfs_path[PICL_PROPNAMELEN_MAX];
	char probe_path[PICL_PROPNAMELEN_MAX];
	frutree_device_args_t *device = NULL;

	if (frup == NULL) {
		return (PICL_FAILURE);
	}
	FRUTREE_DEBUG1(EVENTS, "probing :%s", frup->name);

	if ((rc = ptree_get_propval_by_name(frup->frunodeh, PICL_PROP_PARENT,
		&loch, sizeof (loch))) != PICL_SUCCESS) {
		return (rc);
	}

	bzero(devfs_path, PICL_PROPNAMELEN_MAX);
	bzero(probe_path, PICL_PROPNAMELEN_MAX);
	if ((rc = ptree_get_propval_by_name(loch, PICL_PROP_DEVFS_PATH,
		devfs_path, sizeof (devfs_path))) == PICL_SUCCESS) {
		device = (frutree_device_args_t *)malloc(
				sizeof (frutree_device_args_t));
		if (device == NULL) {
			return (PICL_NOSPACE);
		}
		device->first  = NULL;
		device->last   = NULL;
		(void) probe_platform_tree(frup, &device);
		free_cache(device->first);
		free(device);
	}

	/*
	 * if parent has NULL probe-path, skip probing this fru
	 * probe only child locations (if present).
	 * if probe-path is not present use devfs-path as path for
	 * probing the fru.
	 */
	rc = ptree_get_propval_by_name(loch, PICL_PROP_PROBE_PATH,
		probe_path, sizeof (probe_path));
	if (rc != PICL_SUCCESS) {
		if (!devfs_path[0]) {	/* devfspath is also not present */
			return (PICL_SUCCESS);	/* nothing to probe */
		} else {
			/* use devfs-path as path for probing */
			if ((rc = get_fru_path(devfs_path, frup)) !=
				PICL_SUCCESS) {
				return (rc);
			}
		}
	} else {
		/* NULL path, skip probing this fru */
		if (strlen(probe_path) == 0) {
			rc =  fru_init(frup); /* probe its children */
			return (rc);
		} else {
			/* valid probe-path */
			if ((rc = get_fru_path(probe_path, frup)) !=
				PICL_SUCCESS) {
				return (rc);
			}
		}
	}

	/* children present already, no need to probe libdevinfo */
	rc = ptree_get_propval_by_name(frup->frunodeh, PICL_PROP_CHILD,
		&child, sizeof (picl_nodehdl_t));
	if (rc == PICL_SUCCESS) {	/* child present */
		if ((rc = fru_init(frup)) != PICL_SUCCESS) {
			return (rc);
		}
		/* now create the scsi nodes for this fru */
		if ((rc = probe_for_scsi_frus(frup)) != PICL_SUCCESS) {
			return (rc);
		}
		return (PICL_SUCCESS);
	}

	if (ptree_get_propval_by_name(frup->frunodeh, PICL_PROP_PARENT,
		&loch, sizeof (loch)) != PICL_SUCCESS) {
		return (rc);
	}
	if ((rc = ptree_get_propval_by_name(loch, PICL_PROP_SLOT_TYPE,
		slot_type, sizeof (slot_type))) != PICL_SUCCESS) {
		return (rc);
	}
	/* no need to probe further for scsi frus */
	if (strcmp(slot_type, SANIBEL_SCSI_SLOT) == 0 ||
		strcmp(slot_type, SANIBEL_IDE_SLOT) == 0) {
		return (PICL_SUCCESS);
	}

	device = (frutree_device_args_t *)malloc(
			sizeof (frutree_device_args_t));
	if (device == NULL) {
		return (PICL_NOSPACE);
	}
	device->first  = NULL;
	device->last   = NULL;

	if ((rc = probe_libdevinfo(frup, &device, load_drivers)) !=
		PICL_SUCCESS) {
		free_cache(device->first);
		free(device);
		return (rc);
	}

	if (device->first != NULL) {
		if ((rc = create_fru_children(frup, *device)) != PICL_SUCCESS) {
			free_cache(device->first);
			free(device);
			return (rc);
		}
	}
	free_cache(device->first);
	free(device);

	/* now create the scsi nodes for this fru */
	if ((rc = probe_for_scsi_frus(frup)) != PICL_SUCCESS) {
		return (rc);
	}
	return (PICL_SUCCESS);
}

/*
 * callback function for ptree_walk_tree_by_class,
 * used to update hashtable during DR_HINT_REMOVE event
 */
/*ARGSUSED*/
static int
frutree_update_hash(picl_nodehdl_t nodeh, void *c_args)
{
	picl_errno_t rc = 0;
	if ((rc = hash_remove_entry(nodeh)) != PICL_SUCCESS) {
		return (rc);
	}
	return (PICL_WALK_CONTINUE);
}

/*
 * routine to handle  DR_HINT_REMOVE
 */
static picl_errno_t
handle_fru_remove(frutree_frunode_t *frup)
{
	picl_errno_t	rc = PICL_SUCCESS;

	if (frup == NULL) {
		return (PICL_FAILURE);
	}

	if ((rc = ptree_walk_tree_by_class(frup->frunodeh,
		NULL, NULL, frutree_update_hash)) != PICL_SUCCESS) {
		return (rc);
	}
	(void) ptree_delete_node(frup->frunodeh);
	(void) ptree_destroy_node(frup->frunodeh);
	if ((rc = hash_remove_entry(frup->frunodeh)) !=
		PICL_SUCCESS) {
		return (rc);
	}
	return (PICL_SUCCESS);
}

/* remove State and Condition props for all the nodes under fru */
/*ARGSUSED*/
static int
frutree_handle_unconfigure(picl_nodehdl_t nodeh, void *c_args)
{
	picl_errno_t rc = 0;
	picl_prophdl_t proph;
	char class[PICL_PROPNAMELEN_MAX];

	if (ptree_get_prop_by_name(nodeh, PICL_PROP_STATE,
		&proph) == PICL_SUCCESS) {
		(void) ptree_delete_prop(proph);
		(void) ptree_destroy_prop(proph);
	}
	if (ptree_get_prop_by_name(nodeh, PICL_PROP_STATUS_TIME,
		&proph) == PICL_SUCCESS) {
		(void) ptree_delete_prop(proph);
		(void) ptree_destroy_prop(proph);
	}

	if ((rc = ptree_get_propval_by_name(nodeh, PICL_PROP_CLASSNAME,
		class, sizeof (class))) != PICL_SUCCESS) {
		return (rc);
	}

	if (strcmp(class, PICL_CLASS_PORT) == 0) {
		if (ptree_get_prop_by_name(nodeh, PICL_PROP_CONDITION,
			&proph) == PICL_SUCCESS) {
			(void) ptree_delete_prop(proph);
			(void) ptree_destroy_prop(proph);
		}
		if (ptree_get_prop_by_name(nodeh, PICL_PROP_CONDITION_TIME,
			&proph) == PICL_SUCCESS) {
			(void) ptree_delete_prop(proph);
			(void) ptree_destroy_prop(proph);
		}
		/* delete devices table */
		if (ptree_get_prop_by_name(nodeh, PICL_PROP_DEVICES,
			&proph) ==  PICL_SUCCESS) {
			(void) ptree_delete_prop(proph);
			(void) ptree_destroy_prop(proph);
		}
	}
	return (PICL_WALK_CONTINUE);
}

/*
 * traverse thru each node fru node and do cleanup
 */
static picl_errno_t
handle_fru_unconfigure(frutree_frunode_t *frup)
{
	picl_errno_t rc = 0, retval = 0;
	picl_prophdl_t	proph;
	picl_nodehdl_t childh, peerh, nodeh;
	hashdata_t *hashptr = NULL;
	frutree_frunode_t *child_frup = NULL;
	char class[PICL_PROPNAMELEN_MAX];

	if (frup == NULL) {
		return (PICL_FAILURE);
	}

	/* delete devices table */
	if (ptree_get_prop_by_name(frup->frunodeh, PICL_PROP_DEVICES,
		&proph) == PICL_SUCCESS) {
		(void) ptree_delete_prop(proph);
		(void) ptree_destroy_prop(proph);
	}

	/* delete Environment devices table */
	if (ptree_get_prop_by_name(frup->frunodeh, PICL_PROP_ENV,
		&proph) == PICL_SUCCESS) {
		(void) ptree_delete_prop(proph);
		(void) ptree_destroy_prop(proph);
	}

	if ((rc = ptree_walk_tree_by_class(frup->frunodeh,
		NULL, NULL, frutree_handle_unconfigure)) != PICL_SUCCESS) {
		return (rc);
	}

	/* remove all the fru nodes under the child locations */
	retval = ptree_get_propval_by_name(frup->frunodeh, PICL_PROP_CHILD,
		&peerh, sizeof (peerh));
	while (retval ==  PICL_SUCCESS) {
		nodeh = peerh;
		retval = ptree_get_propval_by_name(nodeh, PICL_PROP_PEER,
			&peerh, sizeof (peerh));
		if ((rc = ptree_get_propval_by_name(nodeh, PICL_PROP_CLASSNAME,
			class, sizeof (class))) != PICL_SUCCESS) {
			return (rc);
		}

		if (strcmp(class, PICL_CLASS_PORT) == 0) {
			continue;
		}

		/* if the child location has fru, delete the fru */
		if (ptree_get_propval_by_name(nodeh, PICL_PROP_CHILD,
			&childh, sizeof (childh)) !=  PICL_SUCCESS) {
			continue;
		}

		/* child is present under the location */
		if ((rc = hash_lookup_entry(childh, (void **)&hashptr)) !=
			PICL_SUCCESS) {
			return (rc);
		}
		child_frup = FRUDATA_PTR(hashptr);
		(void) handle_fru_remove(child_frup);
	}
	return (PICL_SUCCESS);
}

/*
 * create the properties under the fru
 */
static picl_errno_t
create_fru_props(frutree_frunode_t *frup)
{
	picl_errno_t rc;
	uint64_t ap_status_time = 0;
	boolean_t state_change;

	/* create state props */
	if ((rc = create_property(PICL_PTYPE_CHARSTRING,
		PICL_READ + PICL_VOLATILE, PICL_PROPNAMELEN_MAX,
		PICL_PROP_STATE, get_fru_state, NULLWRITE,
		frup->frunodeh, NULL, fru_state[frup->state])) !=
		PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_CREATE_PROP_FAILED,
			PICL_PROP_STATE, frup->name, rc);
	}

	ap_status_time = (uint64_t)(time(NULL));
	if ((rc = create_property(PICL_PTYPE_TIMESTAMP, PICL_READ,
		sizeof (ap_status_time), PICL_PROP_STATUS_TIME,
		NULLREAD, NULLWRITE, frup->frunodeh,
		NULL, &ap_status_time)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_CREATE_PROP_FAILED,
			PICL_PROP_STATUS_TIME, frup->name, rc);
	}

	if ((rc = update_fru_state(frup, &state_change)) != PICL_SUCCESS) {
		FRUTREE_DEBUG2(EVENTS, GET_FRU_STATE_ERR, frup->name, rc);
		return (rc);
	}

	/* create condition props */
	if ((rc = create_property(PICL_PTYPE_CHARSTRING,
		PICL_READ + PICL_VOLATILE, PICL_PROPNAMELEN_MAX,
		PICL_PROP_CONDITION, get_fru_condition, NULLWRITE,
		frup->frunodeh, NULL, fru_cond[frup->cond])) !=
		PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_CREATE_PROP_FAILED,
			PICL_PROP_CONDITION, frup->name, rc);
	}
	if ((rc = create_property(PICL_PTYPE_TIMESTAMP, PICL_READ,
		sizeof (ap_status_time), PICL_PROP_CONDITION_TIME,
		NULLREAD, NULLWRITE, frup->frunodeh, NULL,
		&ap_status_time)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_CREATE_PROP_FAILED,
			PICL_PROP_CONDITION_TIME, frup->name, rc);
	}

	if ((rc = update_fru_condition(frup, &state_change)) != PICL_SUCCESS) {
		FRUTREE_DEBUG2(EVENTS, GET_FRU_COND_ERR, frup->name, rc);
		return (rc);
	}

	/* create admin lock prop */
	if ((rc = create_property(PICL_PTYPE_CHARSTRING,
		PICL_READ + PICL_WRITE, PICL_PROPNAMELEN_MAX,
		PICL_PROP_ADMIN_LOCK, NULLREAD, NULLWRITE,
		frup->frunodeh, NULL, PICL_ADMINLOCK_DISABLED)) !=
		PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_CREATE_PROP_FAILED,
			PICL_PROP_ADMIN_LOCK, frup->name, rc);
	}
	return (rc);
}

/*
 * calls libcfgadm API to do a connect on a location
 */
static picl_errno_t
connect_fru(frutree_locnode_t	*locp)
{
	picl_errno_t	rc;
	cfga_err_t	ap_list_err;
	cfga_flags_t	flags = 0;
	boolean_t	state_change;
	uint64_t	ap_status_time;
	hrtime_t	start;
	hrtime_t	end;

	if (locp == NULL) {
		return (PICL_FAILURE);
	}
	if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
		PICLEVENTARGVAL_CONNECTING, loc_state[locp->state],
		locp->locnodeh, WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			locp->name, PICLEVENT_STATE_CHANGE, rc);
	}

	(void) pthread_mutex_lock(&locp->mutex);
	locp->dr_in_progress = B_TRUE;
	(void) pthread_mutex_unlock(&locp->mutex);

	if (frutree_debug & PERF_DATA) {
		start = gethrtime();
	}
	ap_list_err = config_change_state(CFGA_CMD_CONNECT, 1, &(locp->name),
		NULL, NULL, NULL, NULL, flags);

	if (frutree_debug & PERF_DATA) {
		end = gethrtime();
		FRUTREE_DEBUG2(PERF_DATA, "time for connect on %s: %lld nsec",
			locp->name, (end - start));
	}
	if (ap_list_err != CFGA_OK) {
		(void) pthread_mutex_lock(&locp->mutex);
		locp->dr_in_progress = B_FALSE;
		(void) pthread_mutex_unlock(&locp->mutex);

		/* release mutex before updating state */
		(void) update_loc_state(locp, &state_change);
		if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
			loc_state[locp->state], PICLEVENTARGVAL_CONNECTING,
			locp->locnodeh, WAIT)) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
				locp->name, PICLEVENT_STATE_CHANGE, rc);
		}
		if (locp->state == LOC_STATE_CONNECTED) {
			/* wakeup threads sleeping on this condition */
			(void) pthread_mutex_lock(&locp->mutex);
			(void) pthread_cond_broadcast(&locp->cond_cv);
			(void) pthread_mutex_unlock(&locp->mutex);
			return (PICL_SUCCESS);
		}
		return (cfg2picl_errmap[ap_list_err][1]);
	}
	(void) pthread_mutex_lock(&locp->mutex);

	locp->dr_in_progress = B_FALSE;
	locp->prev_state = LOC_STATE_DISCONNECTED;
	locp->state = LOC_STATE_CONNECTED;
	ap_status_time = (uint64_t)(time(NULL));
	if ((rc = ptree_update_propval_by_name(locp->locnodeh,
		PICL_PROP_STATUS_TIME, (void *)&ap_status_time,
		sizeof (ap_status_time))) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_UPDATE_PROP_ERR,
			PICL_PROP_STATUS_TIME, locp->name, rc);
	}

	/* wakeup threads sleeping on this condition */
	(void) pthread_cond_broadcast(&locp->cond_cv);
	(void) pthread_mutex_unlock(&locp->mutex);

	if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
		PICLEVENTARGVAL_CONNECTED, PICLEVENTARGVAL_CONNECTING,
		locp->locnodeh, WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			locp->name, PICLEVENT_STATE_CHANGE, rc);
	}
	return (PICL_SUCCESS);
}

/*
 * calls libcfgadm API to do a disconnect on a location
 */
static picl_errno_t
disconnect_fru(frutree_locnode_t *locp)
{
	picl_errno_t rc;
	picl_nodehdl_t childh;
	hashdata_t *hashptr = NULL;
	timestruc_t to;
	struct timeval tp;
	hrtime_t start, end;
	cfga_err_t ap_list_err;
	cfga_flags_t flags = 0;
	boolean_t state_change;
	uint64_t ap_status_time;
	frutree_frunode_t *frup = NULL;

	if (locp == NULL) {
		return (PICL_FAILURE);
	}

	(void) pthread_mutex_lock(&locp->mutex);
	if (locp->state == LOC_STATE_DISCONNECTED) {
		(void) pthread_mutex_unlock(&locp->mutex);
		return (PICL_SUCCESS);
	}
	(void) pthread_mutex_unlock(&locp->mutex);

	/* get the child fru information */
	if (ptree_get_propval_by_name(locp->locnodeh, PICL_PROP_CHILD,
		&childh, sizeof (childh)) == PICL_SUCCESS) {
		if (hash_lookup_entry(childh, (void **)&hashptr) ==
			PICL_SUCCESS) {
			frup = FRUDATA_PTR(hashptr);
		}
	}

	if (frup == NULL) {
		return (PICL_SUCCESS);
	}

	(void) pthread_mutex_lock(&frup->mutex);

	(void) gettimeofday(&tp, NULL);
	to.tv_sec = tp.tv_sec + frutree_drwait_time;
	to.tv_nsec = tp.tv_usec * 1000;

	if (frup->state != FRU_STATE_UNCONFIGURED) {
		(void) pthread_cond_timedwait(&frup->cond_cv,
			&frup->mutex, &to);
	}

	if (frup->state != FRU_STATE_UNCONFIGURED) {
		FRUTREE_DEBUG1(LOG_ERR, "SUNW_frutree:Disconnect operation on"
			" %s failed", locp->name);
		(void) pthread_mutex_unlock(&frup->mutex);
		return (PICL_FAILURE);
	}
	(void) pthread_mutex_unlock(&frup->mutex);

	if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
		PICLEVENTARGVAL_DISCONNECTING, loc_state[locp->state],
		locp->locnodeh, WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			locp->name, PICLEVENT_STATE_CHANGE, rc);
	}

	(void) pthread_mutex_lock(&locp->mutex);
	locp->dr_in_progress = B_TRUE;
	(void) pthread_mutex_unlock(&locp->mutex);

	if (frutree_debug & PERF_DATA) {
		start = gethrtime();
	}

	ap_list_err = config_change_state(CFGA_CMD_DISCONNECT, 1, &(locp->name),
		NULL, NULL, NULL, NULL, flags);
	if (frutree_debug & PERF_DATA) {
		end = gethrtime();
		FRUTREE_DEBUG2(PERF_DATA, "time for disconnect on %s: %lld ns",
			locp->name, (end - start));
	}
	if (ap_list_err != CFGA_OK) {
		(void) pthread_mutex_lock(&locp->mutex);
		locp->dr_in_progress = B_FALSE;
		(void) pthread_mutex_unlock(&locp->mutex);

		/* release mutex before updating state */
		(void) update_loc_state(locp, &state_change);
		if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
			loc_state[locp->state], PICLEVENTARGVAL_DISCONNECTING,
			locp->locnodeh, WAIT)) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
				locp->name, PICLEVENT_STATE_CHANGE, rc);
		}
		(void) pthread_mutex_lock(&locp->mutex);
		if (locp->state == LOC_STATE_DISCONNECTED) {
			(void) pthread_mutex_unlock(&locp->mutex);
			return (PICL_SUCCESS);
		}
		(void) pthread_mutex_unlock(&locp->mutex);
		return (cfg2picl_errmap[ap_list_err][1]);
	}
	(void) pthread_mutex_lock(&locp->mutex);
	locp->dr_in_progress = B_FALSE;
	locp->prev_state = LOC_STATE_CONNECTED;
	locp->state = LOC_STATE_DISCONNECTED;
	ap_status_time = (uint64_t)(time(NULL));
	if ((rc = ptree_update_propval_by_name(locp->locnodeh,
		PICL_PROP_STATUS_TIME, (void *)&ap_status_time,
		sizeof (ap_status_time))) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_UPDATE_PROP_ERR,
			PICL_PROP_STATUS_TIME, locp->name, rc);
	}
	(void) pthread_mutex_unlock(&locp->mutex);

	if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
		PICLEVENTARGVAL_DISCONNECTED, PICLEVENTARGVAL_DISCONNECTING,
		locp->locnodeh, WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			locp->name, PICLEVENT_STATE_CHANGE, rc);
	}
	return (PICL_SUCCESS);
}

/*
 * Handle DR_INCOMING_RES event
 */
static void
handle_fru_configure(frutree_frunode_t *frup)
{
	picl_errno_t rc;
	boolean_t cond_changed;

	if (frup == NULL)
		return;

	if ((rc = probe_fru(frup, B_FALSE)) != PICL_SUCCESS) {
		FRUTREE_DEBUG2(EVENTS, PROBE_FRU_ERR, frup->name, rc);
	}

	/* update the  fru condition */
	(void) update_fru_condition(frup, &cond_changed);
	if (cond_changed) {
		if ((rc = post_piclevent(PICLEVENT_CONDITION_CHANGE,
			fru_cond[frup->cond], fru_cond[frup->prev_cond],
			frup->frunodeh, WAIT)) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
				frup->name, PICLEVENT_CONDITION_CHANGE, rc);
		}
	}

	if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
		fru_state[frup->state], fru_state[frup->prev_state],
		frup->frunodeh, WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			frup->name, PICLEVENT_STATE_CHANGE, rc);
	}
}

/*
 * call libcfgadm API to configure a fru
 * (Handle DR_INCOMING_RES event)
 */
static picl_errno_t
configure_fru(frutree_frunode_t *frup, cfga_flags_t flags)
{
	picl_errno_t rc;
	picl_nodehdl_t parenth;
	timestruc_t to;
	struct timeval tp;
	hrtime_t start, end;
	cfga_err_t ap_list_err;
	uint64_t ap_status_time;
	hashdata_t *hashptr = NULL;
	frutree_locnode_t *locp = NULL;
	boolean_t state_change, cond_changed;

	if (frup == NULL) {
		return (PICL_FAILURE);
	}

	(void) pthread_mutex_lock(&frup->mutex);
	if (frup->state == FRU_STATE_CONFIGURED) {
		(void) pthread_mutex_unlock(&frup->mutex);
		ap_list_err = config_change_state(CFGA_CMD_CONFIGURE, 1,
			&(frup->name), NULL, NULL, NULL, NULL, flags);
		return (PICL_SUCCESS);
	}
	(void) pthread_mutex_unlock(&frup->mutex);

	if ((rc = ptree_get_propval_by_name(frup->frunodeh, PICL_PROP_PARENT,
		&parenth, sizeof (parenth))) != PICL_SUCCESS) {
		return (rc);
	}

	if ((rc = hash_lookup_entry(parenth, (void **)&hashptr)) !=
		PICL_SUCCESS) {
		return (rc);
	}
	locp = LOCDATA_PTR(hashptr);
	if (locp == NULL) {
		return (PICL_FAILURE);
	}

	(void) pthread_mutex_lock(&locp->mutex);

	(void) gettimeofday(&tp, NULL);
	to.tv_sec = tp.tv_sec + frutree_drwait_time;
	to.tv_nsec = tp.tv_usec * 1000;

	/* wait for sometime for location to get connected */
	if (locp->state != LOC_STATE_CONNECTED) {
		(void) pthread_cond_timedwait(&locp->cond_cv,
			&locp->mutex, &to);
	}

	if (locp->state != LOC_STATE_CONNECTED) {	/* give up */
		FRUTREE_DEBUG1(EVENTS, "SUNW_frutree:Configure operation on"
			" %s failed as loc is not connected", locp->name);
		(void) pthread_mutex_unlock(&locp->mutex);
		return (PICL_FAILURE);
	}
	(void) pthread_mutex_unlock(&locp->mutex);

	if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
		PICLEVENTARGVAL_CONFIGURING, fru_state[frup->state],
		frup->frunodeh, WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			frup->name, PICLEVENT_STATE_CHANGE, rc);
	}

	(void) pthread_mutex_lock(&frup->mutex);
	frup->dr_in_progress = B_TRUE;
	(void) pthread_mutex_unlock(&frup->mutex);

	if (frutree_debug & PERF_DATA) {
		start = gethrtime();
	}
	ap_list_err = config_change_state(CFGA_CMD_CONFIGURE, 1,
		&(frup->name), NULL, NULL, NULL, NULL, flags);

	if (frutree_debug & PERF_DATA) {
		end = gethrtime();
		FRUTREE_DEBUG2(PERF_DATA, "time for configure on %s: %lld nsec",
			frup->name, (end - start));
	}

	if (ap_list_err != CFGA_OK) {
		(void) pthread_mutex_lock(&frup->mutex);
		frup->dr_in_progress = B_FALSE;
		(void) pthread_mutex_unlock(&frup->mutex);
		/* release mutex before updating state */
		(void) update_fru_state(frup, &state_change);
		if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
			fru_state[frup->state], PICLEVENTARGVAL_CONFIGURING,
			frup->frunodeh, WAIT)) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
				frup->name, PICLEVENT_STATE_CHANGE, rc);
		}
		/* update the  fru condition */
		(void) update_fru_condition(frup, &state_change);
		if (state_change) {
			if ((rc = post_piclevent(PICLEVENT_CONDITION_CHANGE,
				fru_cond[frup->cond], fru_cond[frup->prev_cond],
				frup->frunodeh, WAIT)) != PICL_SUCCESS) {
				FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
					frup->name, PICLEVENT_CONDITION_CHANGE,
					rc);
			}
		}
		return (cfg2picl_errmap[ap_list_err][1]);
	}
	(void) pthread_mutex_lock(&frup->mutex);
	frup->dr_in_progress = B_FALSE;
	frup->prev_state = FRU_STATE_UNCONFIGURED;
	frup->state = FRU_STATE_CONFIGURED;
	ap_status_time = (uint64_t)(time(NULL));
	if ((rc = ptree_update_propval_by_name(frup->frunodeh,
		PICL_PROP_STATUS_TIME, (void *)&ap_status_time,
		sizeof (ap_status_time))) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_UPDATE_PROP_ERR,
			PICL_PROP_STATUS_TIME, frup->name, rc);
	}
	(void) pthread_mutex_unlock(&frup->mutex);

	if ((rc = probe_fru(frup, B_FALSE)) != PICL_SUCCESS) {
		FRUTREE_DEBUG2(FRUTREE_INIT, PROBE_FRU_ERR, frup->name, rc);
	}
	/* update the  fru condition */
	(void) update_fru_condition(frup, &cond_changed);
	if (cond_changed) {
		if ((rc = post_piclevent(PICLEVENT_CONDITION_CHANGE,
			fru_cond[frup->cond], fru_cond[frup->prev_cond],
			frup->frunodeh, WAIT)) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
				frup->name, PICLEVENT_CONDITION_CHANGE, rc);
		}
	}

	/* send the state change event */
	if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
		fru_state[frup->state], PICLEVENTARGVAL_CONFIGURING,
		frup->frunodeh, WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			frup->name, PICLEVENT_STATE_CHANGE, rc);
	}
	return (PICL_SUCCESS);
}

/*
 * Handle DR_OUTGOING_RES event
 * (call libcfgadm API to unconfigure a fru)
 */
static picl_errno_t
unconfigure_fru(frutree_frunode_t *frup, cfga_flags_t flags)
{
	picl_errno_t	rc;
	cfga_err_t	ap_list_err;
	boolean_t	state_change;
	uint64_t	ap_status_time;
	hrtime_t	start;
	hrtime_t	end;

	if (frup == NULL) {
		return (PICL_FAILURE);
	}

	(void) pthread_mutex_lock(&frup->mutex);
	if (frup->state == FRU_STATE_UNCONFIGURED) {
		(void) pthread_mutex_unlock(&frup->mutex);
		return (PICL_SUCCESS);
	}
	(void) pthread_mutex_unlock(&frup->mutex);

	if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
		PICLEVENTARGVAL_UNCONFIGURING, fru_state[frup->state],
		frup->frunodeh, WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			frup->name, PICLEVENT_STATE_CHANGE, rc);
	}

	(void) pthread_mutex_lock(&frup->mutex);
	while (frup->busy == B_TRUE) {
		(void) pthread_cond_wait(&frup->busy_cond_cv,
			&frup->mutex);
	}

	frup->dr_in_progress = B_TRUE;
	(void) pthread_mutex_unlock(&frup->mutex);

	if (frutree_debug & PERF_DATA) {
		start = gethrtime();
	}
	ap_list_err = config_change_state(CFGA_CMD_UNCONFIGURE, 1,
		&(frup->name), NULL, NULL, NULL, NULL, flags);
	if (frutree_debug & PERF_DATA) {
		end = gethrtime();
		FRUTREE_DEBUG2(PERF_DATA, "time for unconfigure on %s: %lld ns",
			frup->name, (end - start));
	}
	if (ap_list_err != CFGA_OK) {
		/*
		 * call configure again (workaround for
		 * ENUM# to get generated for next attempt)
		 */
		config_change_state(CFGA_CMD_CONFIGURE, 1,
			&(frup->name), NULL, NULL, NULL, NULL, flags);

		(void) pthread_mutex_lock(&frup->mutex);
		frup->dr_in_progress = B_FALSE;
		(void) pthread_mutex_unlock(&frup->mutex);

		/* release mutex before updating state */
		(void) update_fru_condition(frup, &state_change);
		if (state_change) {
			if ((rc = post_piclevent(PICLEVENT_CONDITION_CHANGE,
				fru_cond[frup->cond], fru_cond[frup->prev_cond],
				frup->frunodeh, WAIT)) != PICL_SUCCESS) {
				FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
					frup->name, PICLEVENT_CONDITION_CHANGE,
					rc);
			}
		}
		(void) update_fru_state(frup, &state_change);
		if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
			fru_state[frup->state], PICLEVENTARGVAL_UNCONFIGURING,
			frup->frunodeh, WAIT)) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
				frup->name, PICLEVENT_STATE_CHANGE, rc);
		}
		return (cfg2picl_errmap[ap_list_err][1]);
	}

	(void) pthread_mutex_lock(&frup->mutex);

	frup->dr_in_progress = B_FALSE;
	frup->prev_state = FRU_STATE_CONFIGURED;
	frup->state = FRU_STATE_UNCONFIGURED;
	ap_status_time = (uint64_t)(time(NULL));
	if ((rc = ptree_update_propval_by_name(frup->frunodeh,
		PICL_PROP_STATUS_TIME, (void *)&ap_status_time,
		sizeof (ap_status_time))) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_UPDATE_PROP_ERR,
			PICL_PROP_STATUS_TIME, frup->name, rc);
	}
	/* wakeup threads sleeping on this condition */
	(void) pthread_cond_broadcast(&frup->cond_cv);
	(void) pthread_mutex_unlock(&frup->mutex);

	/* update the  fru condition */
	if ((rc = update_fru_condition(frup, &state_change)) != PICL_SUCCESS) {
			FRUTREE_DEBUG2(EVENTS, GET_FRU_STATE_ERR,
				frup->name, rc);
	}
	if (state_change) {
		if ((rc = post_piclevent(PICLEVENT_CONDITION_CHANGE,
			fru_cond[frup->cond], fru_cond[frup->prev_cond],
			frup->frunodeh, WAIT)) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
				frup->name, PICLEVENT_CONDITION_CHANGE, rc);
		}
	}

	if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
		PICLEVENTARGVAL_UNCONFIGURED, PICLEVENTARGVAL_UNCONFIGURING,
		frup->frunodeh, WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			frup->name, PICLEVENT_STATE_CHANGE, rc);
	}
	return (PICL_SUCCESS);
}

/* creates fru nodes with basic properties and sends out intializing events */
static int
create_fru_node(frutree_locnode_t *locp, frutree_frunode_t **child_frupp)
{
	picl_errno_t rc;
	hashdata_t *fru_data = NULL;
	frutree_frunode_t *frup = NULL;
	picl_nodehdl_t fruh, child;
	char slot_type[PICL_PROPNAMELEN_MAX];
	char fru_name[PICL_PROPNAMELEN_MAX];
	char apid_type[PICL_PROPNAMELEN_MAX];
	boolean_t fru_present = B_FALSE;
	boolean_t state_changed = B_FALSE;

	if (locp->state == LOC_STATE_EMPTY) {
		return (PICL_SUCCESS);
	}

	/* check if fru is present or not */
	rc = ptree_get_propval_by_name(locp->locnodeh, PICL_PROP_CHILD,
		&child, sizeof (picl_nodehdl_t));
	if (rc == PICL_SUCCESS) {
		fru_present = B_TRUE;
		fruh = child;
		(void) ptree_get_propval_by_name(child, PICL_PROP_NAME,
			fru_name, sizeof (fru_name));
	}

	/* create fru node */
	if (fru_present == B_FALSE) {
		(void) strncpy(fru_name, locp->name, sizeof (fru_name));
		if ((rc = ptree_create_node(fru_name, PICL_CLASS_FRU,
			&fruh)) != PICL_SUCCESS) {
			return (rc);
		}
	}

	/* initialize internal data structures */
	if ((rc = make_fru_data(fru_name, &fru_data)) != PICL_SUCCESS) {
		return (rc);
	}
	frup = FRUDATA_PTR(fru_data);

	frup->frunodeh = fruh;
	frup->cpu_node = locp->cpu_node;
	frup->state_mgr = locp->state_mgr;
	*child_frupp = frup;

	if ((rc = hash_add_entry(fruh, (void *)(fru_data))) != PICL_SUCCESS) {
		(void) ptree_destroy_node(fruh);
		free_data(FRU_TYPE, (fru_data));
		return (rc);
	}

	if (locp->state_mgr == STATIC_LOC) {
		if ((rc = ptree_get_propval_by_name(locp->locnodeh,
			PICL_PROP_SLOT_TYPE, slot_type,
			sizeof (slot_type))) == PICL_SUCCESS) {
			(void) strncpy(apid_type, slot_type,
				sizeof (apid_type));
		}
	}

	/* create fru type property */
	if ((rc = create_property(PICL_PTYPE_CHARSTRING, PICL_READ,
		PICL_PROPNAMELEN_MAX, PICL_PROP_FRU_TYPE, NULLREAD,
		NULLWRITE, fruh, NULL, apid_type)) !=
		PICL_SUCCESS) {
		FRUTREE_DEBUG3(FRUTREE_INIT, PTREE_CREATE_PROP_FAILED,
			PICL_PROP_FRU_TYPE, frup->name, rc);
	}

	if (fru_present == B_FALSE) {
		if ((rc = ptree_add_node(locp->locnodeh, fruh)) !=
			PICL_SUCCESS) {
			(void) ptree_destroy_node(fruh);
			(void) hash_remove_entry(fruh);
			return (rc);
		}
	}

	if (locp->state_mgr == PLUGIN_PVT) {
		(void) update_fru_state(frup, &state_changed);
		return (PICL_SUCCESS);
	}

	if ((rc = create_fru_props(frup)) != PICL_SUCCESS) {
		return (rc);
	}
	return (PICL_SUCCESS);
}

static picl_errno_t
add_node2cache(picl_nodehdl_t nodeh, char *class, frutree_cache_t **cacheptr)
{
	int instance;
	picl_errno_t rc;
	char driver[PICL_PROPNAMELEN_MAX];
	char bus_addr[PICL_PROPNAMELEN_MAX];
	char devfs_path[PICL_PROPNAMELEN_MAX];
	char node_name[PICL_PROPNAMELEN_MAX];
	char port_type[PICL_PROPNAMELEN_MAX];
	char label[PICL_PROPNAMELEN_MAX];
	frutree_cache_t	*cachep = NULL;

	if (strcmp(class, SANIBEL_NETWORK_PORT) == 0) {
		(void) strncpy(label, SANIBEL_NETWORK_LABEL, sizeof (label));
		(void) strncpy(node_name, PICL_CLASS_PORT, sizeof (node_name));
		(void) strncpy(port_type, SANIBEL_NETWORK_PORT,
			sizeof (port_type));

	} else if (strcmp(class, SANIBEL_SERIAL_PORT) == 0) {
		(void) strncpy(label, SANIBEL_SERIAL_PORT, sizeof (label));
		(void) strncpy(node_name, PICL_CLASS_PORT, sizeof (node_name));
		(void) strncpy(port_type, SANIBEL_SERIAL_PORT,
			sizeof (port_type));

	} else if (strcmp(class, SANIBEL_PARALLEL_PORT) == 0) {
		(void) strncpy(label, SANIBEL_PARALLEL_PORT, sizeof (label));
		(void) strncpy(node_name, PICL_CLASS_PORT, sizeof (node_name));
		(void) strncpy(port_type, SANIBEL_PARALLEL_PORT,
			sizeof (port_type));

	} else {
		return (PICL_FAILURE);
	}

	if ((rc = ptree_get_propval_by_name(nodeh, PICL_PROP_INSTANCE,
		&instance, sizeof (instance))) != PICL_SUCCESS) {
		return (rc);
	}

	/* load the driver */
	if (instance < 0) {
		attach_driver(driver);
	}

	if ((rc = ptree_get_propval_by_name(nodeh, PICL_PROP_DEVFS_PATH,
		devfs_path, sizeof (devfs_path))) != PICL_SUCCESS) {
		return (rc);
	}

	/* get either bus address or unit address */
	if ((rc = ptree_get_propval_by_name(nodeh, PICL_PROP_BUS_ADDR, bus_addr,
		sizeof (bus_addr))) != PICL_SUCCESS) {
		if ((rc = ptree_get_propval_by_name(nodeh,
			PICL_PROP_UNIT_ADDRESS, bus_addr,
			sizeof (bus_addr))) != PICL_SUCCESS) {
			return (rc);
		}
	}

	if ((rc = ptree_get_propval_by_name(nodeh, PICL_PROP_DRIVER_NAME,
		driver, sizeof (driver))) != PICL_SUCCESS) {
		return (rc);
	}

	cachep = (frutree_cache_t *)malloc(sizeof (frutree_cache_t));
	if (NULL == cachep) {
		return (PICL_NOSPACE);
	}
	cachep->buf[0] = '\0';

	/* update the cache buffer in PICL configuration format */
	(void) snprintf(cachep->buf, sizeof (cachep->buf),
		"\n%s %s%d %s\n"
		"\t%s %s %s %s 0 \"%s %d\"\n"
		"\t%s %s %s %s 0 \"%s\"\n"
		"\t%s %s %s %s 1 %d\n"
		"\t%s %s %s %s 0 \"%s\"\n"
		"\t%s %s %s %s 0 \"%s\"\n"
		"%s\n",
		"NODE", driver, instance, node_name,
		"PROP", PICL_PROP_LABEL, "string", "r", label, instance,
		"PROP", PICL_PROP_BUS_ADDR, "string", "r", bus_addr,
		"PROP", PICL_PROP_GEO_ADDR, "uint", "r", instance,
		"PROP", PICL_PROP_PORT_TYPE, "string", "r", port_type,
		"PROP", PICL_PROP_DEVFS_PATH, "string", "r", devfs_path,
		"ENDNODE");
	*cacheptr = cachep;
	return (PICL_SUCCESS);
}

/* ARGSUSED */
static int
create_device_entries(picl_nodehdl_t nodeh, void *c_args)
{
	char class[PICL_CLASSNAMELEN_MAX];
	char name[PICL_PROPNAMELEN_MAX];
	frutree_device_args_t *device  = NULL;
	frutree_cache_t	*cachep = NULL;

	if (c_args == NULL) { /* need not create cache */
		return (PICL_INVALIDARG);
	}
	device = (frutree_device_args_t *)c_args;

	if (ptree_get_propval_by_name(nodeh, PICL_PROP_CLASSNAME,
		class, sizeof (class)) != PICL_SUCCESS) {
		return (PICL_WALK_CONTINUE);
	}

	/* add reference handle to Devices table */
	(void) create_table_entry(device->device_tblhdl, nodeh, class);

	/* add to Environment Devices table */
	if (strcmp(class, PICL_CLASS_TEMPERATURE_SENSOR) == 0) {
		if (device->env_tblhdl) {
			(void) create_table_entry(device->env_tblhdl, nodeh,
				class);
		}
	}

	if (device->create_cache != B_TRUE) {	/* dont create cache */
		return (PICL_WALK_CONTINUE);
	}

	/* compare the classname and create the cache entry for the child */
	if (ptree_get_propval_by_name(nodeh, PICL_PROP_NAME, name,
		sizeof (name)) != PICL_SUCCESS) {
		return (PICL_WALK_CONTINUE);
	}

	if (strcmp(name, SANIBEL_PICLNODE_PARALLEL) == 0) {
		(void) strncpy(class, SANIBEL_PARALLEL_PORT, sizeof (class));
	}

	if (add_node2cache(nodeh, class, &cachep) != PICL_SUCCESS) {
		return (PICL_WALK_CONTINUE);
	}

	/* add cache to the linked list */
	if (cachep != NULL) {
		cachep->next = NULL;
		if (device->first == NULL) {		/* 1st node */
			device->first = cachep;
			device->last = NULL;

		} else if (device->last != NULL) {	 /* last node */
			device->last->next = cachep;
			device->last = cachep;

		} else {				/* 2nd node */
			device->first->next = cachep;
			device->last = cachep;
		}
	}
	return (PICL_WALK_CONTINUE);
}

/*
 * determine the state manager for this node
 */
static picl_errno_t
get_loc_type(frutree_locnode_t *locp)
{
	picl_errno_t rc;
	cfga_list_data_t *list = NULL;
	char valbuf[PICL_PROPNAMELEN_MAX];
	char slot_type[PICL_PROPNAMELEN_MAX];

	if (locp->state_mgr != UNKNOWN)
		return (PICL_SUCCESS);

	rc = ptree_get_propval_by_name(locp->locnodeh, PICL_PROP_STATE,
		(void *)valbuf, PICL_PROPNAMELEN_MAX);
	if (rc == PICL_SUCCESS) { /* managed by platform specific plugin */
		locp->state_mgr = PLUGIN_PVT;
		return (PICL_SUCCESS);
	}

	/*  get the info from the libcfgadm interface */
	list = (cfga_list_data_t *)malloc(sizeof (cfga_list_data_t));
	if (list == NULL) {
		return (PICL_NOSPACE);
	}

	if ((rc = get_cfgadm_state(list, locp->name)) == PICL_SUCCESS) {
		locp->state_mgr = CFGADM_AP;
	} else {
		if ((rc = ptree_get_propval_by_name(locp->locnodeh,
			PICL_PROP_SLOT_TYPE, slot_type,
			sizeof (slot_type))) != PICL_SUCCESS) {
			free(list);
			return (rc);
		}
		if (strcmp(slot_type, SANIBEL_SCSI_SLOT) == 0 ||
			strcmp(slot_type, SANIBEL_IDE_SLOT) == 0) {
			/*
			 * for scsi locations, if cfgadm ap is
			 * not present, then consider it as device
			 * not present
			 */
			locp->state_mgr = CFGADM_AP;
		} else {
			/*
			 * devices like PMC card doesnt showup in cfgadm
			 */
			locp->state_mgr = STATIC_LOC;
		}
	}
	free(list);
	return (PICL_SUCCESS);
}

/*
 * Initialize the location node.(create all the props)
 */
static picl_errno_t
location_init(frutree_locnode_t *locp)
{
	picl_errno_t rc;
	boolean_t state_change;
	uint64_t ap_status_time = 0;
	char valbuf[PICL_PROPNAMELEN_MAX];

	/* check if it is a CPU location node or not */
	if (ptree_get_propval_by_name(locp->locnodeh, PICL_PROP_NAME,
		(void *)valbuf, PICL_PROPNAMELEN_MAX) == PICL_SUCCESS) {
		if (strncmp(valbuf, SANIBEL_PICLNODE_CPU,
			strlen(SANIBEL_PICLNODE_CPU)) == 0) {
			locp->cpu_node = B_TRUE;
		}
	}
	/*
	 * Algorithm:
	 * if "State" prop is already created (node is managed by other plugin)
	 *  	does nothing
	 * else if cfgadm ap is found
	 *	creates State prop and intializes it
	 * else
	 *	find the nodes using libdevinfo under a given path
	 *		at given geoaddr
	 *	if node is found
	 *		mark node state a connected
	 *	else
	 *		mark node state a empty
	 */
	(void) get_loc_type(locp);
	if (locp->state_mgr == PLUGIN_PVT) {
		(void) update_loc_state(locp, &state_change);
		return (PICL_SUCCESS);
	}

	if (locp->state_mgr == STATIC_LOC) {
		/*
		 * in case of scsi locations,, loc state will be connected
		 * no need to check again if the fru is present using libdevinfo
		 */
		if (locp->state != LOC_STATE_CONNECTED) {
			if (is_fru_present_under_location(locp) == B_TRUE) {
				locp->state = LOC_STATE_CONNECTED;
			} else {
				locp->state = LOC_STATE_EMPTY;
			}
		}
	}
	/* create state property */
	if ((rc = create_property(PICL_PTYPE_CHARSTRING,
		PICL_READ + PICL_VOLATILE, PICL_PROPNAMELEN_MAX,
		PICL_PROP_STATE, get_loc_state, NULLWRITE, locp->locnodeh,
		NULL, loc_state[locp->state])) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(FRUTREE_INIT, PTREE_CREATE_PROP_FAILED,
			PICL_PROP_STATE, locp->name, rc);
		return (rc);
	}
	ap_status_time = (uint64_t)(time(NULL));

	/* create location StatusTime prop. */
	if ((rc = create_property(PICL_PTYPE_TIMESTAMP, PICL_READ,
		sizeof (uint64_t), PICL_PROP_STATUS_TIME, NULLREAD,
		NULLWRITE, locp->locnodeh, NULL, &ap_status_time)) !=
		PICL_SUCCESS) {
		FRUTREE_DEBUG3(FRUTREE_INIT, PTREE_CREATE_PROP_FAILED,
			PICL_PROP_STATUS_TIME, locp->name, rc);
		return (rc);
	}

	if ((rc = update_loc_state(locp, &state_change)) != PICL_SUCCESS) {
		FRUTREE_DEBUG2(FRUTREE_INIT, GET_LOC_STATE_ERR, locp->name, rc);
		return (rc);
	}
	return (PICL_SUCCESS);
}

static frutree_port_type_t
frutree_get_port_type(frutree_portnode_t *portp)
{
	char device_type[PICL_PROPNAMELEN_MAX];
	frutree_port_type_t port_type = UNKNOWN_PORT;

	if (portp == NULL) {
		return (port_type);
	}

	if (ptree_get_propval_by_name(portp->portnodeh,
		PICL_PROP_PORT_TYPE, device_type,
		sizeof (device_type)) == PICL_SUCCESS) {
		if (strcmp(device_type, SANIBEL_NETWORK_PORT) == 0) {
			port_type = NETWORK_PORT;
		} else if (strcmp(device_type,
			SANIBEL_SERIAL_PORT) == 0) {
			port_type = SERIAL_PORT;
		} else if (strcmp(device_type,
			SANIBEL_PARALLEL_PORT) == 0) {
			port_type = PARALLEL_PORT;
		}
	}
	return (port_type);
}

/* volatile callback function to get port condition */
static int
get_port_condition(ptree_rarg_t *rarg, void *buf)
{
	picl_errno_t rc;
	hashdata_t *hashptr = NULL;
	frutree_portnode_t *portp = NULL;
	frutree_port_type_t port_type;

	if (buf == NULL) {
		return (PICL_INVALIDARG);
	}

	if ((rc = hash_lookup_entry(rarg->nodeh, (void **)&hashptr)) !=
		PICL_SUCCESS) {
		return (rc);
	}

	portp = PORTDATA_PTR(hashptr);
	if (portp == NULL) {
		return (PICL_FAILURE);
	}
	port_type = frutree_get_port_type(portp);

	if (port_type == UNKNOWN_PORT) {
		portp->cond = PORT_COND_UNKNOWN;
		(void) strncpy((char *)buf, port_cond[portp->cond],
			PICL_PROPNAMELEN_MAX);
		return (PICL_SUCCESS);
	}

	if ((rc = update_port_state(portp, B_TRUE)) != PICL_SUCCESS) {
		return (rc);
	}

	(void) strncpy((char *)buf, port_cond[portp->cond],
		PICL_PROPNAMELEN_MAX);
	return (PICL_SUCCESS);
}

/* volatile callback function to get port state */
static int
get_port_state(ptree_rarg_t *rarg, void *buf)
{
	picl_errno_t rc;
	hashdata_t *hashptr = NULL;
	frutree_portnode_t *portp = NULL;
	frutree_port_type_t port_type;

	if (buf == NULL) {
		return (PICL_INVALIDARG);
	}
	if ((rc = hash_lookup_entry(rarg->nodeh, (void **)&hashptr)) !=
		PICL_SUCCESS) {
		return (rc);
	}
	portp = PORTDATA_PTR(hashptr);
	if (portp == NULL) {
		return (PICL_FAILURE);
	}

	port_type = frutree_get_port_type(portp);
	if (port_type == UNKNOWN_PORT) {
		portp->state = PORT_STATE_UNKNOWN;
		(void) strncpy((char *)buf, port_state[portp->state],
			PICL_PROPNAMELEN_MAX);
		return (PICL_SUCCESS);
	}

	if ((rc = update_port_state(portp, B_TRUE)) != PICL_SUCCESS) {
		return (rc);
	}
	(void) strncpy((char *)buf, port_state[portp->state],
		PICL_PROPNAMELEN_MAX);
	return (PICL_SUCCESS);
}

/*
 * Creates State and Condition property for a port node
 */
static picl_errno_t
port_init(frutree_portnode_t *portp)
{
	picl_prophdl_t		proph;
	ptree_propinfo_t	propinfo;
	void			*vbuf;
	picl_errno_t 		rc;
	uint64_t 		status_time;
	picl_nodehdl_t 		refhdl;
	frutree_device_args_t 	device;
	picl_prophdl_t 		tblprophdl, tblhdl;
	char class[PICL_PROPNAMELEN_MAX];

	if (portp == NULL) {
		return (PICL_FAILURE);
	}
	refhdl = get_reference_handle(portp->portnodeh);

	/* traverse thru platform tree and add entries to Devices table */
	if (refhdl != 0) {
		/* create Devices table property */
		if ((rc = create_property(PICL_PTYPE_TABLE, PICL_READ,
			sizeof (picl_prophdl_t), PICL_PROP_DEVICES,
			NULLREAD, NULLWRITE, portp->portnodeh, &tblprophdl,
			&tblhdl)) != PICL_SUCCESS) {
			return (rc);
		}

		/* walk down the subtree and populate Devices */
		if ((rc = ptree_get_propval_by_name(refhdl,
			PICL_PROP_CLASSNAME, class,
			sizeof (class))) != PICL_SUCCESS) {
			return (rc);
		}
		if ((rc = create_table_entry(tblhdl, refhdl, class)) !=
			PICL_SUCCESS) {
			return (rc);
		}

		device.nodeh = refhdl;
		device.device_tblhdl = tblhdl;
		device.first = NULL;
		device.last = NULL;
		device.create_cache = B_FALSE;

		if ((rc = do_action(refhdl, CREATE_DEVICES_ENTRIES,
			(void *)&device)) != PICL_SUCCESS) {
			return (rc);
		}

		if ((rc = ptree_get_prop_by_name(refhdl, PICL_PROP_INSTANCE,
			&proph)) != PICL_SUCCESS) {
			return (rc);
		}
		if ((rc = ptree_get_propinfo(proph, &propinfo)) !=
			PICL_SUCCESS) {
			return (rc);
		}
		vbuf = alloca(propinfo.piclinfo.size);
		if (vbuf == NULL)
			return (PICL_NOSPACE);

		if ((rc = ptree_get_propval(proph, vbuf,
			propinfo.piclinfo.size)) != PICL_SUCCESS) {
			return (rc);
		}
		portp->instance = *(int *)vbuf;

		if ((rc = ptree_get_prop_by_name(refhdl,
			PICL_PROP_DRIVER_NAME, &proph)) != PICL_SUCCESS) {
			return (rc);
		}
		if ((rc = ptree_get_propinfo(proph, &propinfo)) !=
			PICL_SUCCESS) {
			return (rc);
		}
		vbuf = alloca(propinfo.piclinfo.size);
		if (vbuf == NULL)
			return (PICL_NOSPACE);

		if ((rc = ptree_get_propval(proph, vbuf,
			propinfo.piclinfo.size)) != PICL_SUCCESS) {
			return (rc);
		}

		(void) strncpy(portp->driver, (char *)vbuf,
			sizeof (portp->driver));
	} else {
		/* this node is created using libdevinfo or conf file */
		if ((rc = get_port_info(portp)) != PICL_SUCCESS) {
			return (rc);
		}
	}

	/* create state and condition properties */
	if ((rc = create_property(PICL_PTYPE_CHARSTRING,
		PICL_READ | PICL_VOLATILE, PICL_PROPNAMELEN_MAX,
		PICL_PROP_STATE, get_port_state, NULLWRITE, portp->portnodeh,
		NULL, port_state[portp->state])) != PICL_SUCCESS) {
		return (rc);
	}

	status_time = (uint64_t)(time(NULL));
	if ((rc = create_property(PICL_PTYPE_TIMESTAMP, PICL_READ,
		sizeof (uint64_t), PICL_PROP_STATUS_TIME, NULLREAD,
		NULLWRITE, portp->portnodeh, NULL, &status_time)) !=
		PICL_SUCCESS) {
		return (rc);
	}

	if ((rc = create_property(PICL_PTYPE_CHARSTRING,
		PICL_READ | PICL_VOLATILE, PICL_PROPNAMELEN_MAX,
		PICL_PROP_CONDITION, get_port_condition, NULLWRITE,
		portp->portnodeh, NULL, port_cond[portp->cond])) !=
		PICL_SUCCESS) {
		return (rc);
	}
	if ((rc = create_property(PICL_PTYPE_TIMESTAMP, PICL_READ,
		sizeof (uint64_t), PICL_PROP_CONDITION_TIME, NULLREAD,
		NULLWRITE, portp->portnodeh, NULL, &status_time)) !=
		PICL_SUCCESS) {
		return (rc);
	}
	(void) update_port_state(portp, B_FALSE);
	return (PICL_SUCCESS);
}

/*
 * This routine dynamically determines the scsi name (using libcfgadm)
 * that corresponds to the node specified in configuration file
 */
static picl_errno_t
init_scsi_slot(frutree_frunode_t *frup, frutree_locnode_t **ptr2locp,
	boolean_t *node_name_changed)
{
	picl_errno_t rc;
	char devfs_path[PICL_PROPNAMELEN_MAX];
	char bus_addr[PICL_PROPNAMELEN_MAX];
	char label[PICL_PROPNAMELEN_MAX];
	char name[MAXPATHLEN];
	uint8_t	 geo_addr = 0;
	frutree_locnode_t *locp = NULL, *new_locp = NULL;
	hashdata_t *hashptr = NULL;
	picl_nodehdl_t	nodeh;

	if (ptr2locp == NULL) {
		return (PICL_INVALIDARG);
	}
	locp  = (frutree_locnode_t *)*ptr2locp;
	*node_name_changed = B_FALSE;

	if (locp == NULL) {
		return (PICL_FAILURE);
	}

	if ((rc = ptree_get_propval_by_name(locp->locnodeh,
		PICL_PROP_DEVFS_PATH, devfs_path,
		sizeof (devfs_path))) != PICL_SUCCESS) {
		return (rc);
	}

	if ((rc = ptree_get_propval_by_name(locp->locnodeh,
		PICL_PROP_BUS_ADDR, bus_addr,
		sizeof (bus_addr))) != PICL_SUCCESS) {
		return (rc);
	}

	/* find the dynamic ap_id from libcfgadm */
	if ((rc = get_scsislot_name(devfs_path, bus_addr,
		name)) != PICL_SUCCESS) {
		/* if rc is NODENOTFOUND, then slot is empty */
		if (rc != PICL_NODENOTFOUND) {
			return (rc);
		} else {
			return (PICL_SUCCESS);
		}
	}

	/* node name is same, so dont change anything */
	if (strcmp(name, locp->name) == 0) {
		return (PICL_SUCCESS);
	}

	if ((rc = ptree_get_propval_by_name(locp->locnodeh,
		PICL_PROP_GEO_ADDR, &geo_addr,
		sizeof (geo_addr))) != PICL_SUCCESS) {
		geo_addr = 0;
	}

	if ((rc = ptree_get_propval_by_name(locp->locnodeh,
		PICL_PROP_LABEL, label,
		sizeof (label))) != PICL_SUCCESS) {
		return (rc);
	}

	/* Now recreate the node with new name */
	if ((rc = ptree_create_node(name, PICL_CLASS_LOCATION,
		&nodeh)) != PICL_SUCCESS) {
		return (rc);
	}

	/* add all the properties now */
	(void) create_property(PICL_PTYPE_CHARSTRING, PICL_READ,
		PICL_PROPNAMELEN_MAX, PICL_PROP_SLOT_TYPE, NULLREAD,
		NULLWRITE, nodeh, (picl_prophdl_t *)NULL,
		SANIBEL_SCSI_SLOT);

	(void) create_property(PICL_PTYPE_CHARSTRING, PICL_READ,
		PICL_PROPNAMELEN_MAX, PICL_PROP_LABEL, NULLREAD,
		NULLWRITE, nodeh, (picl_prophdl_t *)NULL,
		label);

	(void) create_property(PICL_PTYPE_CHARSTRING, PICL_READ,
		PICL_PROPNAMELEN_MAX, PICL_PROP_BUS_ADDR, NULLREAD,
		NULLWRITE, nodeh, (picl_prophdl_t *)NULL,
		bus_addr);

	(void) create_property(PICL_PTYPE_UNSIGNED_INT, PICL_READ,
		sizeof (uint8_t), PICL_PROP_GEO_ADDR, NULLREAD,
		NULLWRITE, nodeh, (picl_prophdl_t *)NULL,
		&geo_addr);

	(void) create_property(PICL_PTYPE_CHARSTRING, PICL_READ,
		PICL_PROPNAMELEN_MAX, PICL_PROP_DEVFS_PATH, NULLREAD,
		NULLWRITE, nodeh, (picl_prophdl_t *)NULL,
		devfs_path);
	(void) ptree_add_node(frup->frunodeh, nodeh);

	if ((rc = make_loc_data(name, &hashptr)) != PICL_SUCCESS) {
		return (rc);
	}
	/* save data in hash table */
	if ((rc = hash_add_entry(nodeh, (void *)hashptr)) != PICL_SUCCESS) {
		free_data(hashptr->type, hashptr);
		return (rc);
	}

	new_locp = LOCDATA_PTR(hashptr);
	new_locp->locnodeh = nodeh;
	*ptr2locp = new_locp;
	*node_name_changed = B_TRUE;
	return (PICL_SUCCESS);
}

/*
 * find the child nodes under a fru and initialize them
 */
static int
frutree_initialize_children(picl_nodehdl_t childh, void *c_args)
{
	picl_errno_t rc;
	picl_nodehdl_t parenth;
	boolean_t node_changed = B_FALSE;
	hashdata_t *datap = NULL;
	char name[PICL_PROPNAMELEN_MAX];
	char class[PICL_PROPNAMELEN_MAX];
	frutree_frunode_t *frup = NULL;
	frutree_init_callback_arg_t *arg;

	if (c_args ==  NULL) {
		return (PICL_INVALIDARG);
	}
	arg = (frutree_init_callback_arg_t *)c_args;
	frup = arg->frup;

	if ((rc = ptree_get_propval_by_name(childh, PICL_PROP_PARENT,
		&parenth, sizeof (parenth))) != PICL_SUCCESS) {
		return (rc);
	}

	if (parenth != frup->frunodeh)
		return (PICL_WALK_CONTINUE);

	if ((rc = ptree_get_propval_by_name(childh, PICL_PROP_CLASSNAME, class,
		sizeof (class))) != PICL_SUCCESS) {
		return (rc);
	}

	if ((rc = ptree_get_propval_by_name(childh, PICL_PROP_NAME, name,
		sizeof (name))) != PICL_SUCCESS) {
		return (rc);
	}

	if (strcmp(class, PICL_CLASS_LOCATION) == 0) {
		char slot_type[PICL_PROPNAMELEN_MAX];
		frutree_locnode_t *locp = NULL;
		frutree_frunode_t *child_frup = NULL;
		/* initialize internal data structure */
		if ((rc = make_loc_data(name, &datap)) != PICL_SUCCESS) {
			return (PICL_WALK_CONTINUE);
		}
		locp = LOCDATA_PTR(datap);
		locp->locnodeh = childh;
		/* save data in hash table */
		(void) hash_add_entry(childh, (void *)datap);
		if ((rc = ptree_get_propval_by_name(locp->locnodeh,
			PICL_PROP_SLOT_TYPE, slot_type,
			sizeof (slot_type))) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(FRUTREE_INIT, PTREE_GET_PROPVAL_ERR,
				PICL_PROP_SLOT_TYPE, locp->name, rc);
			return (PICL_WALK_CONTINUE);
		} else {
			if (strcmp(slot_type, SANIBEL_SCSI_SLOT) == 0 ||
				strcmp(slot_type, SANIBEL_IDE_SLOT) == 0) {
				/*
				 * this rountine finds the valid cfgadm
				 * ap_id name for a given node and
				 * creates a new node with that name.
				 * If the node name is changed, the present
				 * node must be added to the list of nodes
				 * to be deleted from tree after ptree walk.
				 */
				(void) init_scsi_slot(frup, &locp,
					&node_changed);
				if (node_changed) {
					delete_list_t *nodep = NULL;
					/*
					 * add this node to list of nodes
					 * to be removed
					 */
					nodep = (delete_list_t *)malloc(
							sizeof (delete_list_t));
					if (nodep == NULL) {
						return (PICL_NOSPACE);
					}
					nodep->nodeh = childh;
					nodep->next = NULL;

					if (arg->first == NULL) {
						arg->first = nodep;
					} else { /* add 2 front */
						nodep->next = arg->first;
						arg->first = nodep;
					}
				}
			}
		}
		if ((rc = location_init(locp)) != PICL_SUCCESS) {
			return (PICL_WALK_CONTINUE);
		}

		/* if location is empty, done */
		if (locp->state == LOC_STATE_EMPTY ||
			locp->state == LOC_STATE_UNKNOWN) {
			return (PICL_WALK_CONTINUE);
		}

		/* create the fru node and initialize it */
		if ((rc = create_fru_node(locp, &child_frup)) !=
			PICL_SUCCESS) {
			return (PICL_WALK_CONTINUE);
		}

		/*
		 * if fru is already configured, create the
		 * subtree under the child fru
		 */
		if (child_frup->state == FRU_STATE_CONFIGURED) {
			/* initialize the fru_path */
			if ((rc = probe_fru(child_frup, B_TRUE)) !=
				PICL_SUCCESS) {
				FRUTREE_DEBUG2(EVENTS, PROBE_FRU_ERR,
					child_frup->name, rc);
			}
		}
	} else if (strcmp(class, PICL_CLASS_PORT) == 0) {
		frutree_portnode_t *portp = NULL;
		if ((rc = make_port_data(name, &datap)) != PICL_SUCCESS) {
			return (PICL_WALK_CONTINUE);
		}
		(void) hash_add_entry(childh, (void *)datap);
		portp = PORTDATA_PTR(datap);
		portp->portnodeh = childh;
		(void) port_init(portp);
	}
	return (PICL_WALK_CONTINUE);
}

/* traverse thru all locations under fru and initiate connects */
static int
initiate_connects(picl_nodehdl_t nodeh, void *args)
{
	picl_errno_t rc;
	hashdata_t *hashptr = NULL;
	picl_nodehdl_t parenth;
	frutree_frunode_t *frup = NULL;
	frutree_locnode_t *locp = NULL;

	if (args ==  NULL) {
		return (PICL_INVALIDARG);
	}
	frup = (frutree_frunode_t *)args;

	if ((rc = ptree_get_propval_by_name(nodeh, PICL_PROP_PARENT,
		&parenth, sizeof (parenth))) != PICL_SUCCESS) {
		return (rc);
	}

	if (parenth != frup->frunodeh)
		return (PICL_WALK_CONTINUE);

	if ((rc = hash_lookup_entry(nodeh, (void **)&hashptr)) !=
		PICL_SUCCESS) {
		return (PICL_WALK_CONTINUE);
	}
	locp = LOCDATA_PTR(hashptr);

	if (locp->state == LOC_STATE_EMPTY ||
		locp->state == LOC_STATE_UNKNOWN ||
		locp->state == LOC_STATE_CONNECTED) {
		return (PICL_WALK_CONTINUE);
	}

	/* if loc is not connected, do a connect operation */
	if (locp->autoconfig_enabled) {
		if ((rc = connect_fru(locp)) != PICL_SUCCESS) {
			FRUTREE_DEBUG2(EVENTS, CONNECT_FAILED_ERR,
				locp->name, rc);
		}
	}
	return (PICL_WALK_CONTINUE);
}

/*
 * Initializes the subtree under a FRU
 */
static picl_errno_t
fru_init(frutree_frunode_t *frup)
{
	picl_errno_t rc;
	delete_list_t *tmp = NULL, *curr = NULL;
	frutree_init_callback_arg_t arg;

	if (frup ==  NULL) {
		return (PICL_INVALIDARG);
	}

	arg.frup = frup;
	arg.first = NULL;

	/*
	 * this routine creates internal data structures for
	 * all the children under this fru and initializes them
	 */
	if ((rc = do_action(frup->frunodeh, INIT_FRU,
		(void *)&arg)) != PICL_SUCCESS) {
		return (rc);
	}

	/* traverse thru delete_nodes_list and delete the nodes from tree */
	curr = arg.first;
	while (curr) {
		tmp = curr;
		(void) ptree_delete_node(tmp->nodeh);
		(void) ptree_destroy_node(tmp->nodeh);
		(void) hash_remove_entry(tmp->nodeh);
		free(tmp);
		curr = curr->next;
	}

	/*
	 * dont post events during intialization (for other FRUs)
	 * chassis intialization will take care of posting events
	 * for complete frutree
	 */
	if ((frup->frunodeh == chassish) ||
		(post_picl_events == B_TRUE)) {
		if ((rc = do_action(frup->frunodeh, POST_EVENTS, NULL)) !=
			PICL_SUCCESS) {
			FRUTREE_DEBUG1(LOG_ERR, "SUNW_frutree:Error in "
				"posting picl events(error=%d)", rc);
		}
	}

	if (frup->frunodeh == chassish) {
		post_picl_events = B_TRUE;
		frutree_connects_initiated = B_TRUE;
	}

	/* initiate connects */
	if ((rc = ptree_walk_tree_by_class(frup->frunodeh, PICL_CLASS_LOCATION,
		(void *)frup, initiate_connects)) != PICL_SUCCESS) {
		return (rc);
	}
	return (PICL_SUCCESS);
}

/*ARGSUSED*/
static int
post_events(picl_nodehdl_t childh, void *c_args)
{
	int rc;
	hashdata_t *hashptr = NULL;
	frutree_frunode_t *frup = NULL;
	frutree_locnode_t *locp = NULL;
	frutree_portnode_t *portp = NULL;
	char classval[PICL_CLASSNAMELEN_MAX];

	if ((rc = ptree_get_propval_by_name(childh, PICL_PROP_CLASSNAME,
		classval, sizeof (classval))) != PICL_SUCCESS) {
		return (PICL_WALK_CONTINUE);
	}

	if ((rc = hash_lookup_entry(childh, (void **)&hashptr)) !=
		PICL_SUCCESS) {
		return (PICL_WALK_CONTINUE);
	}

	if (strcmp(classval, PICL_CLASS_LOCATION) == 0) {
		locp = LOCDATA_PTR(hashptr);
		if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
			loc_state[locp->state], loc_state[locp->prev_state],
			childh, WAIT)) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
				locp->name, PICLEVENT_STATE_CHANGE, rc);
		}
		return (PICL_WALK_CONTINUE);
	}

	if (strcmp(classval, PICL_CLASS_FRU) == 0) {
		frup = FRUDATA_PTR(hashptr);
		if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
			fru_state[frup->state], fru_state[frup->prev_state],
			childh, WAIT)) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
				frup->name, PICLEVENT_STATE_CHANGE, rc);
		}
		if ((rc = post_piclevent(PICLEVENT_CONDITION_CHANGE,
			fru_cond[frup->cond], fru_cond[frup->prev_cond],
			frup->frunodeh, WAIT)) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
				frup->name, PICLEVENT_CONDITION_CHANGE, rc);
		}
		return (PICL_WALK_CONTINUE);
	}

	if (strcmp(classval, PICL_CLASS_PORT) == 0) {
		portp = PORTDATA_PTR(hashptr);
		if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
			port_state[portp->state], NULL,
			portp->portnodeh, WAIT)) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
				portp->name, PICLEVENT_STATE_CHANGE, rc);
		}
		if ((rc = post_piclevent(PICLEVENT_CONDITION_CHANGE,
			port_cond[portp->cond], NULL,
			portp->portnodeh, WAIT)) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
				portp->name, PICLEVENT_CONDITION_CHANGE, rc);
		}
		return (PICL_WALK_CONTINUE);
	}
	return (PICL_WALK_CONTINUE);
}

/*
 * This function is a utility function that calls the
 * appropriate call back function for the all the nodes under
 * the specified root node.
 * future additions can be done by defining new action and callback.
 */
static picl_errno_t
do_action(picl_nodehdl_t root, int action, void *cargs)
{
	int rc;
	callback_t func_ptr;
	char *class = NULL;

	switch (action) {

	case INIT_FRU:
		func_ptr = frutree_initialize_children;
		class = NULL;
		break;
	case CREATE_DEVICES_ENTRIES:
		func_ptr = create_device_entries;
		class = NULL;
		break;
	case POST_EVENTS:
		func_ptr = post_events;
		class = NULL;
		break;
	default:
		return (PICL_INVALIDARG);
	}

	if ((rc = ptree_walk_tree_by_class(root, class, cargs,
		func_ptr)) != PICL_SUCCESS) {
		return (rc);
	}
	return (PICL_SUCCESS);
}

static picl_errno_t
frutree_update_chassis_state(frutree_frustate_t state,
	frutree_frustate_t prev_state)
{
	uint64_t ap_status_time;
	picl_errno_t rc = 0;
	char present_state[PICL_PROPNAMELEN_MAX];

	(void) strncpy(present_state, fru_state[state], sizeof (present_state));
	(void) ptree_update_propval_by_name(chassish,
		PICL_PROP_STATE, present_state, sizeof (present_state));

	ap_status_time = (uint64_t)(time(NULL));
	if ((rc = ptree_update_propval_by_name(chassish,
		PICL_PROP_STATUS_TIME, (void *)&ap_status_time,
		sizeof (ap_status_time))) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_UPDATE_PROP_ERR,
			PICL_PROP_STATUS_TIME, PICL_NODE_CHASSIS, rc);
	}
	if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
		fru_state[state], fru_state[prev_state],
		chassish, WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			PICL_NODE_CHASSIS, PICLEVENT_STATE_CHANGE, rc);
	}
	return (PICL_SUCCESS);
}

static picl_errno_t
frutree_init()
{
	picl_errno_t rc;
	frutree_frunode_t *frup = NULL;
	hashdata_t *hashptr = NULL;

	if ((rc = ptree_get_node_by_path(PLATFORM_PATH, &platformh)) !=
		PICL_SUCCESS) {
		return (rc);
	}

	if ((rc = hash_lookup_entry(chassish, (void **)&hashptr)) !=
		PICL_SUCCESS) {
		return (rc);
	}
	frup = FRUDATA_PTR(hashptr);

	/* create the nodes in conf file under chassis node */
	if ((rc = picld_pluginutil_parse_config_file(chassish,
		conf_file)) != PICL_SUCCESS) {
		/* update chassis state to unconfigured */
		(void) frutree_update_chassis_state(
			FRU_STATE_UNCONFIGURED, FRU_STATE_UNKNOWN);
		return (rc);
	}

	/* update chassis state to configuring */
	(void) frutree_update_chassis_state(
		FRU_STATE_CONFIGURING, FRU_STATE_UNCONFIGURED);

	if (scsi_info_init() != PICL_SUCCESS) {
		/* update chassis state to unconfigured */
		(void) frutree_update_chassis_state(
			FRU_STATE_UNCONFIGURED, FRU_STATE_CONFIGURING);
		return (PICL_FAILURE);
	}

	/* traverse thru all the nodes under chassis, initialize them */
	if ((rc = fru_init(frup)) != PICL_SUCCESS) {
		/* update chassis state to unconfigured */
		(void) frutree_update_chassis_state(
			FRU_STATE_UNCONFIGURED, FRU_STATE_CONFIGURING);
		scsi_info_fini();
		return (rc);
	}
	/* free the memory used during initialization */
	scsi_info_fini();
	/* start node monitoring thread */
	if (pthread_create(&monitor_tid, NULL, monitor_node_status,
		NULL) != 0) {
		FRUTREE_DEBUG0(EVENTS, "SUNW_frutree:Error in creating node"
			" monitoring thread");
	}

	(void) pthread_mutex_lock(&frup->mutex);
	frup->state = FRU_STATE_CONFIGURED;
	(void) pthread_mutex_unlock(&frup->mutex);

	/* update chassis state to configured */
	(void) frutree_update_chassis_state(
		FRU_STATE_CONFIGURED, FRU_STATE_CONFIGURING);
	return (PICL_SUCCESS);
}

/* ARGSUSED */
static void *
init_thread(void *arg)
{
	picl_errno_t rc;

	FRUTREE_DEBUG0(FRUTREE_INIT, "init_thread begin");

	(void) pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	(void) pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	if (get_configuration_file() != PICL_SUCCESS) {
		return (NULL);
	}
	FRUTREE_DEBUG1(FRUTREE_INIT, "conf_file = %s", conf_file);
	if ((rc = frutree_init()) != PICL_SUCCESS) {
		FRUTREE_DEBUG1(FRUTREE_INIT, "frutree_init failed, error = %d",
			rc);
	}
	FRUTREE_DEBUG0(FRUTREE_INIT, "init_thread end");
	return (NULL);
}

/* ARGSUSED */
static void
event_completion_handler(char *ename, void *earg, size_t size)
{
	if (frutree_debug & EV_COMPLETION) {
		char name[PICL_PROPNAMELEN_MAX];
		nvlist_t *nvlp;
		char *value = NULL;
		char *arg = NULL;
		picl_nodehdl_t fruhdl;
		time_t current_time;

		if (strncmp(ename, PICLEVENT_STATE_CHANGE,
			strlen(PICLEVENT_STATE_CHANGE)) == 0) {
			arg = PICLEVENTARG_STATE;
		} else if (strncmp(ename, PICLEVENT_CONDITION_CHANGE,
			strlen(PICLEVENT_CONDITION_CHANGE)) == 0) {
			arg = PICLEVENTARG_CONDITION;
		}

		(void) nvlist_unpack((char *)earg, size, &nvlp, NULL);
		(void) nvlist_lookup_uint64(nvlp, PICLEVENTARG_NODEHANDLE,
			&fruhdl);
		if (arg != NULL)
			(void) nvlist_lookup_string(nvlp, arg, &value);

		(void) ptree_get_propval_by_name(fruhdl, PICL_PROP_NAME,
			(void *)name, sizeof (name));
		current_time = (uint64_t)(time(NULL));
		if (value != NULL) {
			FRUTREE_DEBUG4(EV_COMPLETION, "ev_completed[%s]%s(%s) "
			"on %s", ctime(&current_time), ename, value, name);
		}
		nvlist_free(nvlp);
	}

	(void) mutex_lock(&piclevent_mutex);
	piclevent_pending = 0;
	(void) cond_broadcast(&piclevent_completed_cv);
	(void) mutex_unlock(&piclevent_mutex);
	free(earg);
	free(ename);
}

picl_errno_t
post_piclevent(const char *event, char *val1,
	char *val2, picl_nodehdl_t nodeh, frutree_wait_t wait)
{
	nvlist_t *nvl;
	size_t nvl_size;
	char *pack_buf = NULL;
	char *ename = NULL;
	char *arg = NULL;
	picl_errno_t rc;
	timestruc_t to;
	struct timeval tp;

	if (event == NULL || val1 == NULL) {
		return (PICL_INVALIDARG);
	}
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME_TYPE, NULL)) {
		return (PICL_FAILURE);
	}
	if (nvlist_add_uint64(nvl, PICLEVENTARG_NODEHANDLE, nodeh)) {
		nvlist_free(nvl);
		return (PICL_FAILURE);
	}

	if ((ename = strdup(event)) == NULL) {
		nvlist_free(nvl);
		return (PICL_NOSPACE);
	}

	if (strncmp(ename, PICLEVENT_STATE_CHANGE,
		strlen(PICLEVENT_STATE_CHANGE)) == 0) {
		arg = PICLEVENTARG_STATE;
	} else if (strncmp(ename, PICLEVENT_CONDITION_CHANGE,
		strlen(PICLEVENT_CONDITION_CHANGE)) == 0) {
		arg = PICLEVENTARG_CONDITION;
	} else {
		free(ename);
		nvlist_free(nvl);
		return (PICL_INVALIDARG);
	}

	if (nvlist_add_string(nvl, arg, val1)) {
		free(ename);
		nvlist_free(nvl);
		return (PICL_FAILURE);
	}

	if (strncmp(ename, PICLEVENT_CONDITION_CHANGE,
		strlen(PICLEVENT_CONDITION_CHANGE)) == 0) {
		if (nvlist_pack(nvl, &pack_buf, &nvl_size, NV_ENCODE_NATIVE,
			NULL)) {
			free(ename);
			nvlist_free(nvl);
			return (PICL_FAILURE);
		}
	} else {	/* state change event */

		if (val2 != NULL) {
			/* if there is a last state, add it to nvlist */
			if (nvlist_add_string(nvl,
				PICLEVENTARG_LAST_STATE, val2)) {
				free(ename);
				nvlist_free(nvl);
				return (PICL_FAILURE);
			}
		}
	}

	if (nvlist_pack(nvl, &pack_buf, &nvl_size, NV_ENCODE_NATIVE, NULL)) {
		free(ename);
		nvlist_free(nvl);
		return (PICL_FAILURE);
	}

	(void) mutex_lock(&piclevent_mutex);
	while (piclevent_pending) {
		(void) cond_wait(&piclevent_completed_cv,
			&piclevent_mutex);
	}
	piclevent_pending = 1;
	(void) mutex_unlock(&piclevent_mutex);

	if ((rc = ptree_post_event(ename, pack_buf, nvl_size,
		event_completion_handler)) != PICL_SUCCESS) {
		free(ename);
		free(pack_buf);
		nvlist_free(nvl);
		(void) mutex_lock(&piclevent_mutex);
		piclevent_pending = 0;
		(void) mutex_unlock(&piclevent_mutex);
		return (rc);
	}

	if (frutree_debug) {
		char	name[PICL_PROPNAMELEN_MAX];
		(void) ptree_get_propval_by_name(nodeh, PICL_PROP_NAME,
			name, sizeof (name));
		if (val2 != NULL) {
			FRUTREE_DEBUG4(EVENTS, "%s(%s -> %s) on %s", ename,
				val2, val1, name);
		} else {
			FRUTREE_DEBUG3(EVENTS, "%s(%s) on %s", ename,
				val1, name);
		}
	}

	if (wait) {	/* wait for the event to be handled */
		(void) mutex_lock(&piclevent_mutex);
		while (piclevent_pending) {
			(void) gettimeofday(&tp, NULL);
			to.tv_sec = tp.tv_sec + 1;
			to.tv_nsec = tp.tv_usec * 1000;
			(void) cond_timedwait(&piclevent_completed_cv,
				&piclevent_mutex, &to);
		}
		(void) mutex_unlock(&piclevent_mutex);
	}
	nvlist_free(nvl);
	return (PICL_SUCCESS);
}

/*
 * return values
 * -1	: error
 *  0	: not enabled
 *  1	: enabled
 */
/* ARGSUSED */
static int
is_autoconfig_enabled(char *loc_name)
{
	return (1);
}

static picl_errno_t
update_loc_type(frutree_locnode_t *locp)
{
	cfga_list_data_t *list = NULL;
	/*  get the info from the libcfgadm interface */
	list = (cfga_list_data_t *)malloc(sizeof (cfga_list_data_t));
	if (list == NULL) {
		return (PICL_NOSPACE);
	}

	if (get_cfgadm_state(list, locp->name) == PICL_SUCCESS) {
		locp->state_mgr = CFGADM_AP;
		free(list);
		return (PICL_SUCCESS);
	}
	free(list);
	return (PICL_NODENOTFOUND);
}

/*
 * handles DR_INCOMING_RES on chassis node
 * (refresh piclfrutree tree)
 */
static int
reconfigure_chassis(picl_nodehdl_t nodeh, void *args)
{
	picl_errno_t rc;
	hashdata_t *hashptr = NULL;
	picl_nodehdl_t parenth, childh;
	frutree_frunode_t *frup = NULL, *child_frup = NULL;
	frutree_locnode_t *locp = NULL;
	boolean_t state_changed = B_FALSE;
	boolean_t cond_changed = B_FALSE;
	frutree_dr_arg_t dr_arg;

	if (args ==  NULL) {
		return (PICL_INVALIDARG);
	}
	frup = (frutree_frunode_t *)args;

	if ((rc = ptree_get_propval_by_name(nodeh, PICL_PROP_PARENT,
		&parenth, sizeof (parenth))) != PICL_SUCCESS) {
		return (rc);
	}

	if (parenth != frup->frunodeh)
		return (PICL_WALK_CONTINUE);

	if ((rc = hash_lookup_entry(nodeh, (void **)&hashptr)) !=
		PICL_SUCCESS) {
		return (PICL_WALK_CONTINUE);
	}
	locp = LOCDATA_PTR(hashptr);

	/* if the location has child fru, get its information */
	if (ptree_get_propval_by_name(nodeh, PICL_PROP_CHILD,
		&childh, sizeof (childh)) == PICL_SUCCESS) {
		/* get the child fru information */
		if (hash_lookup_entry(childh, (void **)&hashptr) ==
			PICL_SUCCESS) {
			child_frup = FRUDATA_PTR(hashptr);
		}
	}

	/* for each location, update the state */
	if (locp->state_mgr == STATIC_LOC) {
		/* check if cfgadm ap_id is present */
		rc = update_loc_type(locp);
		if (rc == PICL_SUCCESS) {
			if (child_frup) {
				child_frup->state_mgr = locp->state_mgr;
				(void) update_fru_state(child_frup,
					&state_changed);
			}
		}
	}

	state_changed = B_FALSE;
	(void) update_loc_state(locp, &state_changed);
	if (state_changed) {
		switch (locp->state) {
		case LOC_STATE_CONNECTED:
		case LOC_STATE_DISCONNECTED:
		if (locp->prev_state == LOC_STATE_EMPTY ||
			locp->prev_state == LOC_STATE_UNKNOWN) {
			/* handle fru insertion */
			dr_arg.action = HANDLE_INSERT;
		} else {
			/* handle loc state change */
			dr_arg.action = HANDLE_LOCSTATE_CHANGE;
		}
		break;
		case LOC_STATE_EMPTY:
		/* handle fru removal */
		if (locp->prev_state == LOC_STATE_UNKNOWN) {
			/* post piclevent to update led */
			dr_arg.action = HANDLE_LOCSTATE_CHANGE;
		} else {
			/* disconnected fru is removed */
			dr_arg.action = HANDLE_REMOVE;
		}
		break;
		default:
		return (PICL_WALK_CONTINUE);
		} /* end of switch */

		dr_arg.data   = locp;
		(void) pthread_mutex_lock(&ev_mutex);
		if ((rc = add_to_queue(dr_arg)) != PICL_SUCCESS) {
			(void) pthread_mutex_unlock(&ev_mutex);
			return (PICL_WALK_CONTINUE);
		}
		(void) pthread_cond_signal(&ev_cond);
		(void) pthread_mutex_unlock(&ev_mutex);
		return (PICL_WALK_CONTINUE);
	} else {
		/* connect the disconnect locations */
		if (locp->state == LOC_STATE_DISCONNECTED &&
			locp->autoconfig_enabled == B_TRUE) {
			if ((rc = connect_fru(locp)) != PICL_SUCCESS) {
				FRUTREE_DEBUG2(EVENTS, CONNECT_FAILED_ERR,
					locp->name, rc);
			}
			return (PICL_WALK_CONTINUE);
		}
	}

	/* post picl event for child fru */
	if (child_frup == NULL) {
		return (PICL_WALK_CONTINUE);
	}

	/* update the state */
	(void) update_fru_state(child_frup, &state_changed);
	if (state_changed) {
		if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
			fru_state[child_frup->state],
			fru_state[child_frup->prev_state],
			child_frup->frunodeh, WAIT)) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
				child_frup->name, PICLEVENT_STATE_CHANGE, rc);
		}
	}

	/* update the condition */
	(void) update_fru_condition(child_frup, &cond_changed);
	if (cond_changed) {
		if ((rc = post_piclevent(PICLEVENT_CONDITION_CHANGE,
			fru_cond[child_frup->cond],
			fru_cond[child_frup->prev_cond],
			child_frup->frunodeh, WAIT)) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
				child_frup->name, PICLEVENT_CONDITION_CHANGE,
				rc);
		}
	}
	return (PICL_WALK_CONTINUE);
}

static picl_errno_t
handle_chassis_configure(frutree_frunode_t *frup)
{
	picl_errno_t	rc;

	if (frup ==  NULL) {
		return (PICL_INVALIDARG);
	}

	(void) pthread_mutex_lock(&frup->mutex);
	FRUTREE_DEBUG1(EVENTS, "DR_INCOMING_RES on %s", frup->name);
	if (frup->state == FRU_STATE_UNCONFIGURED) {
		frup->state = FRU_STATE_CONFIGURING;
		(void) pthread_mutex_unlock(&frup->mutex);
		/* initial probe/initialization */
		/* create a thread to do the initialization */
		if (pthread_create(&init_threadID, NULL, &init_thread,
			NULL) != 0) {
			return (PICL_FAILURE);
		}
		return (PICL_SUCCESS);
	}
	(void) pthread_mutex_unlock(&frup->mutex);

	/*
	 * 1. update the state of all the nodes in chassis
	 * 2. handle all the state changes accordingly
	 */
	if ((rc = ptree_walk_tree_by_class(chassish, PICL_CLASS_LOCATION,
		(void *)frup, reconfigure_chassis)) != PICL_SUCCESS) {
		return (rc);
	}
	return (PICL_SUCCESS);
}

static picl_errno_t
handle_chassis_unconfigure(frutree_frunode_t *frup)
{
	picl_errno_t rc;

	if (frup->state == FRU_STATE_UNCONFIGURED) {
		return (PICL_SUCCESS);
	}

	/* do any cleanups here */
	if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
		PICLEVENTARGVAL_UNCONFIGURING, PICLEVENTARGVAL_CONFIGURED,
		chassish, WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			PICL_NODE_CHASSIS, PICLEVENT_STATE_CHANGE, rc);
	}

	if ((rc = ptree_update_propval_by_name(chassish,
		PICL_PROP_STATE, PICLEVENTARGVAL_UNCONFIGURED,
		PICL_PROPNAMELEN_MAX)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_UPDATE_PROP_ERR,
			PICL_PROP_STATE, PICL_NODE_CHASSIS, rc);
	}
	frup->prev_state = FRU_STATE_CONFIGURED;
	frup->state = FRU_STATE_UNCONFIGURED;
	(void) handle_fru_unconfigure(frup);

	if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
		PICLEVENTARGVAL_UNCONFIGURED, PICLEVENTARGVAL_UNCONFIGURING,
		chassish, WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			PICL_NODE_CHASSIS, PICLEVENT_STATE_CHANGE, rc);
	}
	return (PICL_SUCCESS);
}

static picl_errno_t
configuration_fn(frutree_dr_arg_t *dr_arg)
{
	picl_errno_t rc;
	picl_nodehdl_t parenth;
	cfga_flags_t flags = 0;
	frutree_frunode_t *frup = NULL;
	frutree_locnode_t *locp = NULL;
	hashdata_t *hashptr = NULL;
	boolean_t state_changed = B_FALSE;

	if (dr_arg == NULL)
		return (PICL_FAILURE);

	frup = (frutree_frunode_t *)dr_arg->data;
	if (frup == NULL) {
		free(dr_arg);
		return (PICL_FAILURE);
	}

	if (frup->frunodeh == chassish) {
		rc = handle_chassis_configure(frup);
		free(dr_arg);
		return (rc);
	}

	if ((rc = ptree_get_propval_by_name(frup->frunodeh, PICL_PROP_PARENT,
		&parenth, sizeof (parenth))) != PICL_SUCCESS) {
		free(dr_arg);
		return (rc);
	}

	if ((rc = hash_lookup_entry(parenth, (void **)&hashptr)) !=
		PICL_SUCCESS) {
		free(dr_arg);
		return (rc);
	}
	locp = LOCDATA_PTR(hashptr);

	/*
	 * update the location state also, as this could be
	 * user initiated connect operation
	 */
	(void) update_loc_state(locp, &state_changed);
	if (state_changed)
	if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
		loc_state[locp->state], loc_state[locp->prev_state],
		locp->locnodeh, WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			locp->name, PICLEVENT_STATE_CHANGE, rc);
	}

	switch (dr_arg->action) {
	case CPU_ONLINE:
		flags |= CFGA_FLAG_FORCE;
		FRUTREE_DEBUG1(EVENTS, "CPU online on %s", frup->name);
		if (locp->state != LOC_STATE_CONNECTED) {
			if (locp->autoconfig_enabled) {
				if ((rc = connect_fru(locp)) != PICL_SUCCESS) {
					FRUTREE_DEBUG2(EVENTS,
						CONNECT_FAILED_ERR,
						locp->name, rc);
				}
			}
			break;
		} /*FALLTHRU*/

		/* do configure now */
	case CONFIGURE_FRU:	/* dr_incoming_res */
		FRUTREE_DEBUG1(EVENTS, "DR_INCOMING_RES on %s", frup->name);
		if ((rc = configure_fru(frup, flags)) != PICL_SUCCESS) {
			FRUTREE_DEBUG2(EVENTS, CONFIGURE_FAILED_ERR,
				frup->name, rc);
			break;
		}
	}
	free(dr_arg);
	return (PICL_SUCCESS);
}

/* handles all dr related events */
static picl_errno_t
handle_dr_event(frutree_dr_arg_t *dr_arg)
{
	picl_errno_t rc;
	picl_nodehdl_t loch, childh;
	hashdata_t *hashptr = NULL;
	cfga_flags_t flags = 0;
	frutree_dr_arg_t *arg = NULL;
	frutree_dr_arg_t fru_dr_arg;
	frutree_locnode_t *locp = NULL;
	frutree_frunode_t *frup = NULL, *child_frup = NULL;
	boolean_t state_changed = B_FALSE, cond_changed = B_FALSE;

	switch (dr_arg->action) {
	case CPU_ONLINE:
	case CONFIGURE_FRU:

	frup = (frutree_frunode_t *)dr_arg->data;
	arg = (frutree_dr_arg_t *)malloc(sizeof (frutree_dr_arg_t));
	if (arg == NULL) {
		FRUTREE_DEBUG2(EVENTS, CONFIGURE_FAILED_ERR,
			frup->name, PICL_NOSPACE);
		return (NULL);
	}
	arg->action = dr_arg->action;
	arg->data = dr_arg->data;
	(void) configuration_fn((void *)arg);
	break;

	case CPU_OFFLINE:
	flags |= CFGA_FLAG_FORCE;
	frup = (frutree_frunode_t *)dr_arg->data;
	if (frup == NULL) {
		break;
	}
	FRUTREE_DEBUG1(EVENTS, "CPU_OFFLINE on %s", frup->name);
	if ((rc = unconfigure_fru(frup, flags)) != PICL_SUCCESS) {
		FRUTREE_DEBUG2(EVENTS, UNCONFIG_FAILED_ERR, frup->name, rc);
		break;
	}

	if ((rc = handle_fru_unconfigure(frup)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, EVENT_NOT_HANDLED, PICLEVENT_DR_REQ,
			frup->name, rc);
	}
	break;

	case UNCONFIGURE_FRU:	/* dr_outgoing_res */
	frup = (frutree_frunode_t *)dr_arg->data;
	if (frup == NULL) {
		break;
	}
	FRUTREE_DEBUG1(EVENTS, "DR_OUTGOING_RES on %s", frup->name);
	if (frup->frunodeh == chassish) {
		(void) handle_chassis_unconfigure(frup);
		break;
	}

	if ((rc = unconfigure_fru(frup, flags)) != PICL_SUCCESS) {
		FRUTREE_DEBUG2(EVENTS, UNCONFIG_FAILED_ERR, frup->name, rc);
		break;
	}

	if ((rc = handle_fru_unconfigure(frup)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, EVENT_NOT_HANDLED,
			PICLEVENT_DR_REQ, frup->name, rc);
	}

	if (ptree_get_propval_by_name(frup->frunodeh, PICL_PROP_PARENT,
		&loch, sizeof (loch)) != PICL_SUCCESS) {
		break;
	}

	if ((rc = hash_lookup_entry(loch, (void **)&hashptr)) !=
		PICL_SUCCESS) {
		break;
	}
	locp = LOCDATA_PTR(hashptr);

	/* check the autoconfig flag */
	if (locp->autoconfig_enabled == B_FALSE) {
		break;
	}

	if ((rc = disconnect_fru(locp)) != PICL_SUCCESS) {
		FRUTREE_DEBUG2(EVENTS, "SUNW_frutree:Disconnect on %s "
			"failed(error=%d)", locp->name, rc);
	}
	break;

	case HANDLE_CONFIGURE:	/* basic hotswap operation */

	frup = (frutree_frunode_t *)dr_arg->data;
	if (frup == NULL) {
		break;
	}
	FRUTREE_DEBUG1(EVENTS, "HANDLE CONFIGURE on %s", frup->name);
	handle_fru_configure(frup);
	break;

	case HANDLE_UNCONFIGURE: /* basic hotswap operation */

	/* cleanup the internal data structures */

	frup = (frutree_frunode_t *)dr_arg->data;
	if (frup == NULL) {
		break;
	}
	FRUTREE_DEBUG1(EVENTS, "HANDLE UNCONFIGURE on %s", frup->name);

	if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
		fru_state[frup->state], fru_state[frup->prev_state],
		frup->frunodeh, WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			frup->name, PICLEVENT_STATE_CHANGE, rc);
	}

	/* update the  fru condition */
	(void) update_fru_condition(frup, &state_changed);
	if (state_changed) {
		if ((rc = post_piclevent(PICLEVENT_CONDITION_CHANGE,
			fru_cond[frup->cond], fru_cond[frup->prev_cond],
			frup->frunodeh, WAIT)) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
				frup->name, PICLEVENT_CONDITION_CHANGE, rc);
		}
	}
	if ((rc = handle_fru_unconfigure(frup)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, EVENT_NOT_HANDLED,
			PICLEVENT_DR_AP_STATE_CHANGE, frup->name, rc);
	}
	break;

	case HANDLE_LOCSTATE_CHANGE: /* basic hotswap operation */
	/* posts state change events of location */
	locp = (frutree_locnode_t *)dr_arg->data;
	if (locp == NULL) {
		break;
	}
	FRUTREE_DEBUG1(EVENTS, "HANDLE LOC STATE CHANGE on %s", locp->name);
	if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
		loc_state[locp->state], loc_state[locp->prev_state],
		locp->locnodeh, WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			locp->name, PICLEVENT_STATE_CHANGE, rc);
	}

	/* wakeup threads sleeping on this condition */
	(void) pthread_mutex_lock(&locp->mutex);
	if (locp->state == LOC_STATE_CONNECTED) {
		(void) pthread_cond_broadcast(&locp->cond_cv);
	}
	(void) pthread_mutex_unlock(&locp->mutex);

	/* if the location has child fru, get its information */
	if (ptree_get_propval_by_name(locp->locnodeh, PICL_PROP_CHILD,
		&childh, sizeof (childh)) == PICL_SUCCESS) {
		/* get the child fru information */
		if (hash_lookup_entry(childh, (void **)&hashptr) ==
			PICL_SUCCESS) {
			child_frup = FRUDATA_PTR(hashptr);
		}
	}
	/* update the child fru state and handle any state changes */
	if (child_frup == NULL) {
		break;
	}

	if ((rc = update_fru_state(child_frup, &state_changed)) !=
		PICL_SUCCESS) {
		FRUTREE_DEBUG2(EVENTS, GET_FRU_STATE_ERR, child_frup->name, rc);
		break;
	}

	if (state_changed == B_FALSE) {
		/*
		 * if there is no change in state, check for condition
		 * changes.
		 * if there is a state change, handling state change
		 * will take care of condition changes also.
		 */
		(void) update_fru_condition(child_frup, &cond_changed);
		if (cond_changed == B_FALSE) {
			break;
		}

		if ((rc = post_piclevent(PICLEVENT_CONDITION_CHANGE,
			fru_cond[child_frup->cond],
			fru_cond[child_frup->prev_cond],
			child_frup->frunodeh, WAIT)) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
				child_frup->name,
				PICLEVENT_CONDITION_CHANGE, rc);
		}
		break;
	}

	/* add to queue to handle the fru state change */
	(void) pthread_mutex_lock(&child_frup->mutex);
	/* figure out if this is config/unconfig operation */
	if (child_frup->state == FRU_STATE_CONFIGURED) {
		fru_dr_arg.action = HANDLE_CONFIGURE;
		fru_dr_arg.data = child_frup;
	} else if (child_frup->state == FRU_STATE_UNCONFIGURED) {
		fru_dr_arg.action = HANDLE_UNCONFIGURE;
		fru_dr_arg.data = child_frup;
	}
	(void) pthread_mutex_unlock(&child_frup->mutex);

	(void) pthread_mutex_lock(&ev_mutex);
	if ((rc = add_to_queue(fru_dr_arg)) != PICL_SUCCESS) {
		(void) pthread_mutex_unlock(&ev_mutex);
		break;
	}
	(void) pthread_cond_signal(&ev_cond);
	(void) pthread_mutex_unlock(&ev_mutex);
	break;

	case HANDLE_INSERT: /* dr_apstate_change (HINT_INSERT) */
	locp = (frutree_locnode_t *)dr_arg->data;
	if (locp == NULL) {
		break;
	}
	FRUTREE_DEBUG1(EVENTS, "HANDLE INSERT on %s", locp->name);
	/* if the location has child fru, get its information */
	if (ptree_get_propval_by_name(locp->locnodeh, PICL_PROP_CHILD,
		&childh, sizeof (childh)) == PICL_SUCCESS) {
		/* get the child fru information */
		if (hash_lookup_entry(childh, (void **)&hashptr) ==
			PICL_SUCCESS) {
			child_frup = FRUDATA_PTR(hashptr);
		}
	}
	if (child_frup) {
		/*
		 * if previous state is not empty, it could be a
		 * hint insert to retry connects
		 */
		(void) update_loc_state(locp, &state_changed);
		if (state_changed) {
			if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
				loc_state[locp->state],
				loc_state[locp->prev_state], locp->locnodeh,
				WAIT)) != PICL_SUCCESS) {
				FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
					locp->name, PICLEVENT_STATE_CHANGE, rc);
			}
		}

		(void) update_fru_condition(child_frup, &cond_changed);
		if (cond_changed == B_TRUE) {
			if ((rc = post_piclevent(PICLEVENT_CONDITION_CHANGE,
				fru_cond[child_frup->cond],
				fru_cond[child_frup->prev_cond],
				child_frup->frunodeh, WAIT)) != PICL_SUCCESS) {
					FRUTREE_DEBUG3(EVENTS,
						PTREE_POST_PICLEVENT_ERR,
						child_frup->name,
						PICLEVENT_CONDITION_CHANGE, rc);
				}
			}
		if (!locp->autoconfig_enabled) {
			break;
		}

		if (locp->state != LOC_STATE_CONNECTED) {
			if ((rc = connect_fru(locp)) != PICL_SUCCESS) {
				FRUTREE_DEBUG2(EVENTS, CONNECT_FAILED_ERR,
					locp->name, rc);
			}
		}
		break;
	}

	(void) update_loc_state(locp, &state_changed);
	if ((rc = create_fru_node(locp, &child_frup)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, EVENT_NOT_HANDLED,
			PICLEVENT_DR_AP_STATE_CHANGE, locp->name, rc);
		break;
	}

	if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
		loc_state[locp->state], loc_state[locp->prev_state],
		locp->locnodeh, WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			locp->name, PICLEVENT_STATE_CHANGE, rc);
	}

	if (locp->autoconfig_enabled) {
		if ((rc = connect_fru(locp)) != PICL_SUCCESS) {
			FRUTREE_DEBUG2(EVENTS, CONNECT_FAILED_ERR,
				locp->name, rc);
		}
	}
	break;

	case HANDLE_REMOVE: /* dr_apstate_change (HINT_REMOVE) */
	locp = (frutree_locnode_t *)dr_arg->data;
	if (locp == NULL) {
		break;
	}
	FRUTREE_DEBUG1(EVENTS, "HANDLE REMOVE on %s", locp->name);

	if (locp->state == LOC_STATE_EMPTY) {
		break;	/* discard the spurious event */
	}

	(void) update_loc_state(locp, &state_changed);
	/* if the location has child fru, get its information */
	if (ptree_get_propval_by_name(locp->locnodeh, PICL_PROP_CHILD,
		&childh, sizeof (childh)) == PICL_SUCCESS) {
		/* get the child fru information */
		if (hash_lookup_entry(childh, (void **)&hashptr) ==
			PICL_SUCCESS) {
			frup = FRUDATA_PTR(hashptr);
		}
	}
	if (frup == NULL) {
		break;
	}

	/*
	 * frutree need to post this event before handling the
	 * fru remove, so that other plugins (like frudata) can
	 * do the cleanup
	 */
	if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
		loc_state[locp->state], loc_state[locp->prev_state],
		locp->locnodeh, WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			locp->name, PICLEVENT_STATE_CHANGE, rc);
	}

	if ((rc = handle_fru_remove(frup)) != PICL_SUCCESS) {
		FRUTREE_DEBUG2(EVENTS, "SUNW_frutree:Error in handling"
		"removal of fru under %s(error=%d)", locp->name, rc);
	}
	break;

	case POST_COND_EVENT:
	frup = (frutree_frunode_t *)dr_arg->data;
	if (frup == NULL) {
		break;
	}
	if ((rc = post_piclevent(PICLEVENT_CONDITION_CHANGE,
		fru_cond[frup->cond], fru_cond[frup->prev_cond],
		frup->frunodeh, WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			frup->name, PICLEVENT_CONDITION_CHANGE, rc);
	}
	default:
		break;
	}
	return (PICL_SUCCESS);
}

/*ARGSUSED*/
static void*
dr_thread(void * arg)
{
	ev_queue_t	*event = NULL;

	(void) pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	(void) pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	for (;;) {
		if (fini_called)
			break;
		(void) pthread_mutex_lock(&ev_mutex);
		while (queue_head == NULL) {
			(void) pthread_cond_wait(&ev_cond, &ev_mutex);
		}

		event = remove_from_queue();
		(void) pthread_mutex_unlock(&ev_mutex);
		while (event) {
			(void) handle_dr_event(&event->arg);
			free(event);
			event = NULL;
			(void) pthread_mutex_lock(&ev_mutex);
			event = remove_from_queue();
			(void) pthread_mutex_unlock(&ev_mutex);
		}
	}
	return (NULL);
}

static picl_errno_t
update_port_state(frutree_portnode_t *portp, boolean_t post_ev)
{
	int state, cond;
	picl_errno_t rc;
	uint64_t ap_status_time;
	boolean_t state_changed = B_FALSE;
	boolean_t cond_changed = B_FALSE;
	frutree_port_type_t port_type;

	if (portp == NULL) {
		return (PICL_INVALIDARG);
	}
	port_type = frutree_get_port_type(portp);

	if (port_type == UNKNOWN_PORT) {
		return (PICL_SUCCESS);
	}
	state = kstat_port_state(port_type, portp->driver,
		portp->instance);
	cond = kstat_port_cond(port_type, portp->driver,
		portp->instance);
	switch (state) {
	case 0:
		/* DOWN */
		if (portp->state != PORT_STATE_DOWN) {
			portp->state = PORT_STATE_DOWN;
			state_changed = B_TRUE;
		}
		break;
	case 1:
		/* UP */
		if (portp->state != PORT_STATE_UP) {
			portp->state = PORT_STATE_UP;
			state_changed = B_TRUE;
		}
		break;
	default:
		/* UNKNOWN */
		if (portp->state != PORT_STATE_UNKNOWN) {
			portp->state = PORT_STATE_UNKNOWN;
			state_changed = B_TRUE;
		}
	}

	if (post_ev && state_changed) {
		ap_status_time = (uint64_t)(time(NULL));
		if ((rc = ptree_update_propval_by_name(portp->portnodeh,
			PICL_PROP_STATUS_TIME, &ap_status_time,
			sizeof (uint64_t))) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_UPDATE_PROP_ERR,
				PICL_PROP_STATUS_TIME, portp->name, rc);

		}
		if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
			port_state[portp->state], NULL,
			portp->portnodeh, WAIT)) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
				portp->name, PICLEVENT_STATE_CHANGE, rc);
		}
	}

	switch (cond) {
	case 0:
		if (portp->cond != PORT_COND_OK) {
			portp->cond = PORT_COND_OK;
			cond_changed = B_TRUE;
		}
		break;
	case 1:
		if (portp->cond != PORT_COND_FAILING) {
			portp->cond = PORT_COND_FAILING;
			cond_changed = B_TRUE;
		}
		break;
	case 2:
		if (portp->cond != PORT_COND_FAILED) {
			portp->cond = PORT_COND_FAILED;
			cond_changed = B_TRUE;
		}
		break;
	case 3:
		if (portp->cond != PORT_COND_TESTING) {
			portp->cond = PORT_COND_TESTING;
			cond_changed = B_TRUE;
		}
		break;
	default:
		if (portp->cond != PORT_COND_UNKNOWN) {
			portp->cond = PORT_COND_UNKNOWN;
			cond_changed = B_TRUE;
		}
	}

	if (post_ev && cond_changed) {
		ap_status_time = (uint64_t)(time(NULL));
		if ((rc = ptree_update_propval_by_name(portp->portnodeh,
			PICL_PROP_CONDITION_TIME, &ap_status_time,
			sizeof (uint64_t))) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_UPDATE_PROP_ERR,
				PICL_PROP_CONDITION_TIME, portp->name, rc);
		}
		if ((rc = post_piclevent(PICLEVENT_CONDITION_CHANGE,
			port_cond[portp->cond], NULL,
			portp->portnodeh, WAIT)) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
				portp->name, PICLEVENT_CONDITION_CHANGE, rc);
		}
	}
	return (PICL_SUCCESS);
}

/*
 * monitor port nodes and scsi nodes under a fru
 */
static int
monitor_nodes_under_fru(picl_nodehdl_t nodeh, void *c_args)
{
	picl_errno_t rc;
	picl_nodehdl_t parenth;
	hashdata_t *hashptr = NULL;
	boolean_t state_changed;
	frutree_portnode_t *portp = NULL;
	frutree_locnode_t *locp = NULL;
	frutree_frunode_t *frup = NULL;
	char class[PICL_PROPNAMELEN_MAX];
	char slot_type[PICL_PROPNAMELEN_MAX];

	if (c_args ==  NULL) {
		return (PICL_INVALIDARG);
	}
	frup = (frutree_frunode_t *)c_args;

	if (ptree_get_propval_by_name(nodeh, PICL_PROP_PARENT,
		&parenth, sizeof (parenth)) != PICL_SUCCESS) {
		return (PICL_WALK_CONTINUE);
	}

	if (parenth != frup->frunodeh)
		return (PICL_WALK_CONTINUE);

	if ((rc = ptree_get_propval_by_name(nodeh, PICL_PROP_CLASSNAME, class,
		sizeof (class))) != PICL_SUCCESS) {
		return (PICL_WALK_CONTINUE);
	}

	if ((rc = hash_lookup_entry(nodeh, (void **)&hashptr)) !=
		PICL_SUCCESS) {
		return (PICL_WALK_CONTINUE);
	}

	if (strcmp(class, PICL_CLASS_LOCATION) == 0) {
		locp = LOCDATA_PTR(hashptr);
		if (ptree_get_propval_by_name(locp->locnodeh,
			PICL_PROP_SLOT_TYPE, slot_type,
			sizeof (slot_type)) != PICL_SUCCESS) {
			return (PICL_WALK_CONTINUE);
		}
		if (strcmp(slot_type, SANIBEL_SCSI_SLOT) == 0 ||
			strcmp(slot_type, SANIBEL_IDE_SLOT) == 0) {
			return (PICL_WALK_CONTINUE);
		}
		(void) update_loc_state(locp, &state_changed);
		if (state_changed) {
			if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
				loc_state[locp->state],
				loc_state[locp->prev_state],
				locp->locnodeh, WAIT)) != PICL_SUCCESS) {
				FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
					locp->name, PICLEVENT_STATE_CHANGE, rc);
			}
		}
	} else if (strcmp(class, PICL_CLASS_PORT) == 0) {
		portp = PORTDATA_PTR(hashptr);
		(void) update_port_state(portp, B_TRUE);
	}
	return (PICL_WALK_CONTINUE);
}

/* This routine monitors only port node, scsi nodes */
/* ARGSUSED */
static int
monitor_fru(picl_nodehdl_t nodeh, void *c_args)
{
	picl_errno_t rc;
	picl_nodehdl_t loch;
	hashdata_t *hashptr = NULL;
	frutree_frunode_t *frup = NULL;
	boolean_t state_changed, cond_changed;
	char slot_type[PICL_PROPNAMELEN_MAX];

	if (hash_lookup_entry(nodeh, (void **)&hashptr) !=
		PICL_SUCCESS) {
		return (PICL_WALK_CONTINUE);
	}
	frup = FRUDATA_PTR(hashptr);

	(void) pthread_mutex_lock(&frup->mutex);
	if (frup->dr_in_progress) {
		(void) pthread_mutex_unlock(&frup->mutex);
		return (PICL_WALK_CONTINUE);
	}
	frup->busy = B_TRUE;
	(void) pthread_mutex_unlock(&frup->mutex);

	/* get the parent information to determine if it is scsi slot or not */
	if (ptree_get_propval_by_name(nodeh, PICL_PROP_PARENT,
		&loch, sizeof (loch)) != PICL_SUCCESS) {
		return (PICL_WALK_CONTINUE);
	}
	if (ptree_get_propval_by_name(loch, PICL_PROP_SLOT_TYPE, slot_type,
		sizeof (slot_type)) != PICL_SUCCESS) {
		return (PICL_WALK_CONTINUE);
	}

	if (strcmp(slot_type, SANIBEL_SCSI_SLOT) == 0 ||
		strcmp(slot_type, SANIBEL_IDE_SLOT) == 0) {
		/* scsi fru */
		(void) update_fru_state(frup, &state_changed);
		(void) update_fru_condition(frup, &cond_changed);
		if (state_changed) {
			if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
				fru_state[frup->state],
				fru_state[frup->prev_state],
				frup->frunodeh, WAIT)) != PICL_SUCCESS) {
				FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
					frup->name, PICLEVENT_STATE_CHANGE, rc);
			}
		}
		if (cond_changed) {
			if ((rc = post_piclevent(PICLEVENT_CONDITION_CHANGE,
				fru_cond[frup->cond], fru_cond[frup->prev_cond],
				frup->frunodeh, WAIT)) != PICL_SUCCESS) {
				FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
					frup->name, PICLEVENT_CONDITION_CHANGE,
					rc);
			}
		}
		(void) pthread_mutex_lock(&frup->mutex);
		frup->busy = B_FALSE;
		(void) pthread_cond_signal(&frup->busy_cond_cv);
		(void) pthread_mutex_unlock(&frup->mutex);
		return (PICL_WALK_CONTINUE);
	}

	if (frup->state != FRU_STATE_CONFIGURED) {
		(void) pthread_mutex_lock(&frup->mutex);
		frup->busy = B_FALSE;
		(void) pthread_cond_signal(&frup->busy_cond_cv);
		(void) pthread_mutex_unlock(&frup->mutex);
		return (PICL_WALK_CONTINUE);
	}

	(void) ptree_walk_tree_by_class(chassish,
		NULL, (void *)frup, monitor_nodes_under_fru);

	(void) pthread_mutex_lock(&frup->mutex);
	frup->busy = B_FALSE;
	(void) pthread_cond_signal(&frup->busy_cond_cv);
	(void) pthread_mutex_unlock(&frup->mutex);
	return (PICL_WALK_CONTINUE);
}

/* ARGSUSED */
static void *
monitor_node_status(void *arg)
{
	int err;
	timestruc_t	to;
	struct timeval	tp;

	(void) pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
	(void) pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	FRUTREE_DEBUG0(EVENTS, "Monitoring for port status started");
	do
	{
		(void) pthread_mutex_lock(&monitor_mutex);
		(void) gettimeofday(&tp, NULL);
		to.tv_sec = tp.tv_sec + frutree_poll_timeout;
		to.tv_nsec = tp.tv_usec * 1000;
		err = pthread_cond_timedwait(&monitor_cv, &monitor_mutex, &to);

		(void) pthread_mutex_unlock(&monitor_mutex);
		if (err == ETIMEDOUT) { /* woke up from sleep */
			(void) ptree_walk_tree_by_class(chassish,
				PICL_CLASS_FRU, (void *)NULL, monitor_fru);
		}
	} while (fini_called == 0);
	return (NULL);
}

picl_errno_t
create_children(frutree_frunode_t *frup, char *scsi_loc, char *bus_addr,
	int slot_no, char *slot_type, boolean_t is_cfgadm_ap)
{
	int i = 0;
	picl_errno_t rc;
	picl_nodehdl_t nodeh;
	uint8_t geo_addr = 0;
	hashdata_t *datap = NULL;
	frutree_locnode_t *locp = NULL;
	hashdata_t *hashptr = NULL;
	char fru_type[PICL_PROPNAMELEN_MAX];
	frutree_frunode_t *child_frup = NULL;
	frutree_callback_data_t fru_arg;

	if (frup == NULL || scsi_loc == NULL || slot_type == NULL) {
		return (PICL_FAILURE);
	}

	/* check if the location is already created */
	(void) strncpy(fru_arg.node_name, scsi_loc,
		sizeof (fru_arg.node_name));
	fru_arg.retnodeh = 0;
	if ((rc = ptree_walk_tree_by_class(chassish, PICL_CLASS_LOCATION,
		&fru_arg, frutree_get_nodehdl)) == PICL_SUCCESS) {
		if (fru_arg.retnodeh != 0) { /* node is already present */
			return (PICL_SUCCESS);
		}
	}

	/* create the location node and all its properties */
	if ((rc = ptree_create_node(scsi_loc, PICL_CLASS_LOCATION,
		&nodeh)) != PICL_SUCCESS) {
		return (rc);
	}

	if ((rc = create_property(PICL_PTYPE_CHARSTRING, PICL_READ,
		PICL_PROPNAMELEN_MAX, PICL_PROP_SLOT_TYPE, NULLREAD,
		NULLWRITE, nodeh, NULL, slot_type)) !=
		PICL_SUCCESS) {
		FRUTREE_DEBUG3(FRUTREE_INIT, PTREE_CREATE_PROP_FAILED,
			PICL_PROP_SLOT_TYPE, scsi_loc, rc);
	}

	if ((rc = create_property(PICL_PTYPE_CHARSTRING, PICL_READ,
		PICL_PROPNAMELEN_MAX, PICL_PROP_LABEL, NULLREAD,
		NULLWRITE, nodeh, NULL, bus_addr)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(FRUTREE_INIT, PTREE_CREATE_PROP_FAILED,
			PICL_PROP_LABEL, scsi_loc, rc);
	}

	if ((rc = create_property(PICL_PTYPE_CHARSTRING, PICL_READ,
		PICL_PROPNAMELEN_MAX, PICL_PROP_BUS_ADDR, NULLREAD,
		NULLWRITE, nodeh, NULL, bus_addr)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(FRUTREE_INIT, PTREE_CREATE_PROP_FAILED,
			PICL_PROP_BUS_ADDR, scsi_loc, rc);
	}

	geo_addr = slot_no;
	if ((rc = create_property(PICL_PTYPE_UNSIGNED_INT, PICL_READ,
		sizeof (uint8_t), PICL_PROP_GEO_ADDR, NULLREAD,
		NULLWRITE, nodeh, (picl_prophdl_t *)NULL,
		&geo_addr)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(FRUTREE_INIT, PTREE_CREATE_PROP_FAILED,
			PICL_PROP_GEO_ADDR, scsi_loc, rc);
	}

	if ((rc = create_property(PICL_PTYPE_CHARSTRING, PICL_READ,
		PICL_PROPNAMELEN_MAX, PICL_PROP_DEVFS_PATH, NULLREAD,
		NULLWRITE, nodeh, NULL, frup->fru_path)) !=
		PICL_SUCCESS) {
		FRUTREE_DEBUG3(FRUTREE_INIT, PTREE_CREATE_PROP_FAILED,
			PICL_PROP_DEVFS_PATH, scsi_loc, rc);
	}

	if ((rc = ptree_add_node(frup->frunodeh, nodeh)) != PICL_SUCCESS) {
		(void) ptree_destroy_node(nodeh);
		return (rc);
	}

	/* save the node in hashtable */
	if ((rc = make_loc_data(scsi_loc, &datap)) != PICL_SUCCESS) {
		return (rc);
	}
	locp = LOCDATA_PTR(datap);
	locp->locnodeh = nodeh;
	/* save data in hash table */
	(void) hash_add_entry(nodeh, (void *)datap);

	if ((rc = hash_lookup_entry(nodeh, (void **)&hashptr)) !=
		PICL_SUCCESS) {
		return (rc);
	}
	locp = LOCDATA_PTR(hashptr);

	if (is_cfgadm_ap != B_TRUE) {	/* device found in libdevinfo */
		locp->state_mgr = STATIC_LOC;
		locp->state = LOC_STATE_CONNECTED;
	}

	if ((rc = location_init(locp)) != PICL_SUCCESS) {
		return (rc);
	}

	/* if location is empty, done */
	if (locp->state == LOC_STATE_EMPTY) {
		if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
			PICLEVENTARGVAL_EMPTY, NULL,
			locp->locnodeh, WAIT)) != PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
				locp->name, PICLEVENT_STATE_CHANGE, rc);
		}
		return (PICL_SUCCESS);
	}

	/* create the fru node and initilize it */
	if ((rc = create_fru_node(locp, &child_frup)) != PICL_SUCCESS) {
		return (rc);
	}

	/* post picl event on location (frudata is consumer for these events) */
	if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
		loc_state[locp->state], PICLEVENTARGVAL_EMPTY,
		locp->locnodeh, WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			locp->name, PICLEVENT_STATE_CHANGE, rc);
	}

	if (child_frup->state_mgr == STATIC_LOC) {
		/* derive the fru_type from name */
		while (i < strlen(scsi_loc)) {
			if (isdigit(scsi_loc[i])) {
				(void) strncpy(fru_type, scsi_loc, i);
				fru_type[i] = '\0';
				break;
			}
			++i;
		}
		if ((rc = ptree_update_propval_by_name(child_frup->frunodeh,
			PICL_PROP_FRU_TYPE, fru_type, sizeof (fru_type))) !=
			PICL_SUCCESS) {
			FRUTREE_DEBUG3(EVENTS, PTREE_UPDATE_PROP_ERR,
				PICL_PROP_FRU_TYPE, child_frup->name, rc);
		}
	}

	/* post picl state change event on fru state */
	if ((rc = post_piclevent(PICLEVENT_STATE_CHANGE,
		fru_state[child_frup->state], PICLEVENTARGVAL_UNKNOWN,
		child_frup->frunodeh, WAIT)) != PICL_SUCCESS) {
		FRUTREE_DEBUG3(EVENTS, PTREE_POST_PICLEVENT_ERR,
			frup->name, PICLEVENT_STATE_CHANGE, rc);
	}
	/*  for scsi FRUs we need not probe further */
	return (PICL_SUCCESS);
}

/*
 * recursive search in the subtree
 */
/*ARGSUSED*/
boolean_t
is_location_present_in_subtree(frutree_frunode_t *frup, const char *name,
	const char *path)
{
	frutree_callback_data_t fru_arg;

	(void) strncpy(fru_arg.node_name, name,
		sizeof (fru_arg.node_name));
	fru_arg.retnodeh = 0;
	if (ptree_walk_tree_by_class(frup->frunodeh, PICL_CLASS_LOCATION,
		&fru_arg, frutree_get_nodehdl) == PICL_SUCCESS) {
		if (fru_arg.retnodeh != 0) { /* node is already present */
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}
