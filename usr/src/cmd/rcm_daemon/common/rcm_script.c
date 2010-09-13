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
 * rcm scripting module:
 *
 * This module implements rcm scripting interfaces.
 * It translates rcm module based interfaces to rcm script based
 * interfaces.
 *
 * Entry points:
 *
 *   int script_main_init()
 *	Initialize the rcm scripting framework.
 *	Called during the rcm daemon initialization
 *
 *   int script_main_fini()
 *	Called at the time of the rcm daemon exit.
 *
 *   struct rcm_mod_ops *script_init(module_t *module)
 *	Initialize the given script.
 *	module->name contains the name of the script.
 *	Called at the time of loading scripts.
 *	Semantics are similar to module init.
 *
 *   char *script_info(module_t *module)
 *	Called when the rcm daemon wishes to get the script information.
 *	module->name contains the name of the script.
 *	Semantics are similar to module info.
 *
 *   int script_fini(module_t *module)
 *	Called before removing the script.
 *	module->name contains the name of the script.
 *	Semantics are similar to module fini.
 *
 * In addition to the above entry points rcm_mod_ops structure contains
 * the other entry points. A pointer to this structure is returned when
 * script_init() is called.
 */

#include "rcm_impl.h"
#include "rcm_script_impl.h"
#include <sys/resource.h>
#include <procfs.h>
#include <sys/proc.h>
#include <ctype.h>

/*
 * All rcm scripting commands are enumerated here.
 * NOTE: command positions in script_cmd_id_t and script_cmd_name must match.
 */
typedef enum {
	C_SCRIPTINFO,
	C_RESOURCEINFO,
	C_REGISTER,
	C_QUERYREMOVE,
	C_PREREMOVE,
	C_POSTREMOVE,
	C_UNDOREMOVE,
	C_QUERYCAPACITY,
	C_PRECAPACITY,
	C_POSTCAPACITY,
	C_QUERYSUSPEND,
	C_PRESUSPEND,
	C_POSTRESUME,
	C_CANCELSUSPEND
} script_cmd_id_t;

/* NOTE: command positions in script_cmd_id_t and script_cmd_name must match */
static char *script_cmd_name[] = {
	"scriptinfo",
	"resourceinfo",
	"register",
	"queryremove",
	"preremove",
	"postremove",
	"undoremove",
	"querycapacity",
	"precapacity",
	"postcapacity",
	"querysuspend",
	"presuspend",
	"postresume",
	"cancelsuspend",
	NULL
};

/*
 * All rcm scripting data items are enumerated here.
 * NOTE: data item positions in script_data_item_id_t and
 * script_data_item_name must match.
 */
typedef	enum {
	D_SCRIPT_VERSION,
	D_SCRIPT_FUNC_INFO,
	D_CMD_TIMEOUT,
	D_RESOURCE_NAME,
	D_RESOURCE_USAGE_INFO,
	D_FAILURE_REASON,
	D_LOG_ERR,
	D_LOG_WARN,
	D_LOG_INFO,
	D_LOG_DEBUG
} script_data_item_id_t;

/*
 * NOTE: data item positions in script_data_item_id_t and
 * script_data_item_name must match.
 */
static const char *script_data_item_name[] = {
	"rcm_script_version",
	"rcm_script_func_info",
	"rcm_cmd_timeout",
	"rcm_resource_name",
	"rcm_resource_usage_info",
	"rcm_failure_reason",
	"rcm_log_err",
	"rcm_log_warn",
	"rcm_log_info",
	"rcm_log_debug",
	NULL
};

/*
 * Maximum number of rcm scripts that can run in parallel.
 * RCM daemon has no limit on the number of scripts supported. But
 * at most it runs script_max_parallelism number of scripts in parallel.
 * For each running script rcm daemon consumes two file descriptors
 * in order to communicate with the script via pipes.
 * So maximum number of file descriptor entries consumed by rcm daemon
 * on behalf of rcm scripts is "script_max_parallelism * 2"
 */
static const int script_max_parallelism = 64;

/*
 * semaphore to limit the number of rcm script processes running in
 * parallel to script_max_parallelism.
 */
static sema_t script_process_sema;

/* mutex to protect the any global data */
static mutex_t script_lock;

/* contains head to a queue of script_info structures */
static rcm_queue_t script_info_q;

/*
 * This mmapped state file is used to store the process id and
 * rcm script name of all currently running rcm scripts.
 */
static const char *script_ps_state_file = "/var/run/rcm_script_state";
static state_file_descr_t script_ps_statefd;

static char *script_env_noforce = "RCM_ENV_FORCE=FALSE";
static char *script_env_force = "RCM_ENV_FORCE=TRUE";
static char *script_env_interval = "RCM_ENV_INTERVAL=%ld";

#define	RSCR_TRACE		RCM_TRACE1

/* rcm script base environment */
static char *script_env[MAX_ENV_PARAMS];

struct rlimit file_limit;

/* function prototypes */
static void build_env(void);
static void copy_env(char *[], char *[]);
static void open_state_file(const char *, state_file_descr_t *, size_t, int,
	uint32_t);
static void truncate_state_file(state_file_descr_t *);
static void close_state_file(const char *, state_file_descr_t *);
static void grow_state_file(state_file_descr_t *);
static void *get_state_element(state_file_descr_t *, int, int *);
static void *allocate_state_element(state_file_descr_t *, int *);
static void free_state_element(void *);
static void script_ps_state_file_kill_pids(void);
static void script_ps_state_file_add_entry(pid_t, char *);
static void script_ps_state_file_remove_entry(pid_t);
static int dname_to_id(char *);
static void script_process_sema_wait(void);
static int run_script(script_info_t *, char *[], char *[], char **);
static int get_line(int fd, char *, char *, int, size_t *, time_t, int *);
static void script_exited(script_info_t *);
static int kill_pid(pid_t);
static void kill_script(script_info_t *);
static char *flags_to_name(int, char *, int);
static void fill_argv(script_info_t *, char *[], char *);
static void *read_stderr(script_info_t *);
static int process_dataitem(script_info_t *, int, char *, char **);
static int do_cmd(script_info_t *, char *[], char *[], char **);
static int do_script_info(script_info_t *);
static int do_dr(script_info_t *, char *[], char *[], char **);
static int script_get_info(rcm_handle_t *, char *, pid_t, uint_t, char **,
	char **, nvlist_t *, rcm_info_t **);
static void add_for_unregister(script_info_t *);
static void remove_from_unregister(script_info_t *, char *);
static void complete_unregister(script_info_t *);
static int script_register_interest(rcm_handle_t *);
static void add_drreq(script_info_t *, char *);
static void remove_drreq(script_info_t *, char *);
static void remove_drreq_all(script_info_t *);
static int script_request_offline(rcm_handle_t *, char *, pid_t, uint_t,
	char **, rcm_info_t **);
static int script_notify_online(rcm_handle_t *, char *, pid_t, uint_t,
	char **, rcm_info_t **);
static int script_notify_remove(rcm_handle_t *, char *, pid_t, uint_t,
	char **, rcm_info_t **);
static int script_request_suspend(rcm_handle_t *, char *, pid_t, timespec_t *,
	uint_t, char **, rcm_info_t **);
static int script_notify_resume(rcm_handle_t *, char *, pid_t, uint_t,
	char **, rcm_info_t **);
static capacity_descr_t *get_capacity_descr(char *);
static int build_env_for_capacity(script_info_t *, char *, uint_t, nvlist_t *,
	char *[], int *, char **);
static int script_request_capacity_change(rcm_handle_t *, char *, pid_t,
	uint_t, nvlist_t *, char **, rcm_info_t **);
static int script_notify_capacity_change(rcm_handle_t *, char *, pid_t,
	uint_t, nvlist_t *, char **, rcm_info_t **);
static void log_msg(script_info_t *, int, char *);
static char *dup_err(int, char *, ...);
static void rcmscript_snprintf(char **, int *, char **, char *, ...);
static char *rcmscript_strdup(char *);
static void *rcmscript_malloc(size_t);
static void *rcmscript_calloc(size_t, size_t);


static struct rcm_mod_ops script_ops =
{
	RCM_MOD_OPS_VERSION,
	script_register_interest, /* register */
	script_register_interest, /* unregister */
	script_get_info,
	script_request_suspend,
	script_notify_resume,
	script_request_offline,
	script_notify_online,
	script_notify_remove,
	script_request_capacity_change,
	script_notify_capacity_change,
	NULL
};

/*
 * Messages fall into two categories:
 *   framework messages (MF_..)
 *   errors directly attributable to scripts (MS_..)
 */
#define	MF_MEMORY_ALLOCATION_ERR \
	gettext("rcm: failed to allocate memory: %1$s\n")
#define	MF_STATE_FILE_ERR \
	gettext("rcm: state file error: %1$s: %2$s\n")
#define	MF_FUNC_CALL_ERR \
	gettext("rcm: %1$s: %2$s\n")
#define	MF_NV_ERR \
	gettext("rcm: required name-value parameters missing (%1$s)\n")
#define	MF_UNKNOWN_RSRC_ERR \
	gettext("rcm: unknown resource name %1$s (%2$s)\n")
#define	MS_REGISTER_RSRC_ERR \
	gettext("rcm script %1$s: failed to register %2$s\n")
#define	MS_REGISTER_ERR \
	gettext("rcm script %1$s: register: %2$s\n")
#define	MS_SCRIPTINFO_ERR \
	gettext("rcm script %1$s: scriptinfo: %2$s\n")
#define	MS_PROTOCOL_ERR \
	gettext("rcm script %1$s: scripting protocol error\n")
#define	MS_TIMEOUT_ERR \
	gettext("rcm script %1$s: timeout error\n")
#define	MS_UNSUPPORTED_VER \
	gettext("rcm script %1$s: unsupported version %2$d\n")
#define	MS_SCRIPT_ERR \
	gettext("rcm script %1$s: error: %2$s\n")
#define	MS_UNKNOWN_ERR \
	gettext("rcm script %1$s: unknown error\n")
#define	MS_LOG_MSG \
	gettext("rcm script %1$s: %2$s\n")


/*
 * Initialize rcm scripting framework.
 * Called during initialization of rcm daemon.
 */
int
script_main_init(void)
{
#define	PS_STATE_FILE_CHUNK_SIZE	32

	/* set base script environment */
	build_env();

	rcm_init_queue(&script_info_q);

	/*
	 * Initialize the semaphore to limit the number of rcm script
	 * process running in parallel to script_max_parallelism.
	 */
	(void) sema_init(&script_process_sema, script_max_parallelism,
			USYNC_THREAD, NULL);

	(void) mutex_init(&script_lock, USYNC_THREAD, NULL);

	/* save original file limit */
	(void) getrlimit(RLIMIT_NOFILE, &file_limit);

	open_state_file(script_ps_state_file, &script_ps_statefd,
		sizeof (ps_state_element_t),
		PS_STATE_FILE_CHUNK_SIZE,
		PS_STATE_FILE_VER);

	/*
	 * If any pids exist in the ps state file since the last incarnation of
	 * the rcm daemon, kill the pids.
	 * On a normal daemon exit no pids should exist in the ps state file.
	 * But on an abnormal daemon exit pids may exist in the ps state file.
	 */
	if (script_ps_statefd.state_file) {
		script_ps_state_file_kill_pids();
		truncate_state_file(&script_ps_statefd);
	}

	return (0);
}

/*
 * Do any cleanup.
 * Called at the time of normal rcm daemon exit.
 */
int
script_main_fini(void)
{
	script_ps_state_file_kill_pids();
	close_state_file(script_ps_state_file, &script_ps_statefd);
	return (0);
}

/*
 * Initialize the given rcm script.
 * module->name contains the name of the rcm script.
 */
struct rcm_mod_ops *
script_init(module_t *module)
{
	script_info_t *rsi;
	size_t len;
	char *script_path;

	rcm_log_message(RSCR_TRACE, "script_init: script name = %s\n",
						module->name);

	module->rsi = NULL;

	if ((script_path = rcm_get_script_dir(module->name)) == NULL)
		return (NULL);

	len = strlen(script_path) + strlen(module->name) + 2;

	/* calloc also zeros the contents */
	rsi = (script_info_t *)rcmscript_calloc(1, sizeof (script_info_t));
	rsi->script_full_name = (char *)rcmscript_calloc(1, len);

	rsi->module = module;
	rcm_init_queue(&rsi->drreq_q);

	(void) mutex_init(&rsi->channel_lock, USYNC_THREAD, NULL);

	(void) snprintf(rsi->script_full_name, len, "%s%s", script_path,
			module->name);
	rsi->script_name = strrchr(rsi->script_full_name, '/') + 1;

	(void) mutex_lock(&rsi->channel_lock);

	rsi->cmd_timeout = -1; /* don't time scriptinfo command */
	if (do_script_info(rsi) == RCM_SUCCESS) {
		/*
		 * if the script hasn't specified a timeout value set it to
		 * default
		 */
		if (rsi->cmd_timeout == -1)
			rsi->cmd_timeout = SCRIPT_CMD_TIMEOUT;
		(void) mutex_unlock(&rsi->channel_lock);

		/* put rsi on script_info_q */
		(void) mutex_lock(&script_lock);
		rcm_enqueue_tail(&script_info_q, &rsi->queue);
		(void) mutex_unlock(&script_lock);

		module->rsi = rsi;
		return (&script_ops);
	}

	(void) mutex_unlock(&rsi->channel_lock);

	free(rsi->script_full_name);
	free(rsi);
	return (NULL);
}

/*
 * Returns a string describing the script's functionality.
 * module->name contains the name of the rcm script for which information
 * is requested.
 */
char *
script_info(module_t *module)
{
	script_info_t *rsi = module->rsi;

	rcm_log_message(RSCR_TRACE, "script_info: script name = %s\n",
						rsi->script_name);
	return (rsi->func_info_buf);
}

/*
 * Called before unloading the script.
 * module->name contains the name of the rcm script which is being unloaded.
 * Do any cleanup.
 */
int
script_fini(module_t *module)
{
	script_info_t *rsi = module->rsi;

	rcm_log_message(RSCR_TRACE, "script_fini: script name = %s\n",
						rsi->script_name);

	/* remove rsi from script_info_q */
	(void) mutex_lock(&script_lock);
	rcm_dequeue(&rsi->queue);
	(void) mutex_unlock(&script_lock);

	remove_drreq_all(rsi);

	if (rsi->func_info_buf)
		free(rsi->func_info_buf);

	free(rsi->script_full_name);
	free(rsi);

	module->rsi = NULL;

	return (RCM_SUCCESS);
}

/* build base environment for scripts */
static void
build_env(void)
{
	const char *env_list[] = { "LANG", "LC_COLLATE", "LC_CTYPE",
		"LC_MESSAGES", "LC_MONETARY", "LC_NUMERIC", "LC_TIME",
		"LC_ALL", "TZ", NULL };
	char *x;
	int len;
	int i, j = 0;
	int d;
	extern int debug_level;

	script_env[j++] = rcmscript_strdup("PATH=/usr/sbin:/usr/bin");

	for (i = 0; env_list[i] != NULL; i++) {
		x = getenv(env_list[i]);
		if (x) {
			len = strlen(env_list[i]) + strlen(x) + 2;
			script_env[j] = (char *)rcmscript_malloc(len);

			(void) snprintf(script_env[j++], len, "%s=%s",
				env_list[i], x);
		}
	}

	len = strlen("RCM_ENV_DEBUG_LEVEL") + 3;
	script_env[j] = (char *)rcmscript_malloc(len);

	if (debug_level < 0)
		d = 0;
	else if (debug_level > 9)
		d = 9;
	else
		d = debug_level;

	(void) snprintf(script_env[j++], len, "RCM_ENV_DEBUG_LEVEL=%d", d);

	script_env[j] = NULL;
}

static void
copy_env(char *src[], char *dst[])
{
	int i;

	for (i = 0; src[i] != NULL; i++)
		dst[i] = src[i];

	dst[i] = NULL;
}

/*
 * Open (or create if the file does not exist) the given state file
 * and mmap it.
 */
static void
open_state_file(const char *filename,
	state_file_descr_t *statefd,
	size_t element_size,
	int chunk_size,
	uint32_t version)
{
	struct stat stats;
	int error_num;

	if ((statefd->fd = open(filename, O_CREAT|O_RDWR, 0600)) ==
			-1) {
		error_num = errno;
		rcm_log_message(RCM_ERROR, MF_STATE_FILE_ERR,
			"open", strerror(error_num));
		rcmd_exit(error_num);
		/*NOTREACHED*/
	}

	if (fstat(statefd->fd, &stats) != 0) {
		error_num = errno;
		rcm_log_message(RCM_ERROR, MF_STATE_FILE_ERR,
			"fstat", strerror(error_num));
		rcmd_exit(error_num);
		/*NOTREACHED*/
	}

	if (stats.st_size != 0) {
		/* LINTED */
		statefd->state_file = (state_file_t *)mmap(NULL,
			stats.st_size, PROT_READ|PROT_WRITE, MAP_SHARED,
			statefd->fd, 0);

		if (statefd->state_file == MAP_FAILED) {
			error_num = errno;
			rcm_log_message(RCM_ERROR, MF_STATE_FILE_ERR,
				"mmap", strerror(error_num));
			rcmd_exit(error_num);
			/*NOTREACHED*/
		}

		if (statefd->state_file->version != version) {
			(void) munmap((void *)statefd->state_file,
					stats.st_size);
			statefd->state_file = NULL;
			(void) ftruncate(statefd->fd, 0);
		}
	} else {
		statefd->state_file = NULL;
	}

	statefd->version = version;
	statefd->element_size = sizeof (state_element_t) +
				RSCR_ROUNDUP(element_size, 8);
	statefd->chunk_size = chunk_size;
	statefd->index = 0;
}

static void
truncate_state_file(state_file_descr_t *statefd)
{
	size_t size;

	if (statefd->state_file) {
		size = sizeof (state_file_t) + statefd->element_size *
			statefd->state_file->max_elements;

		(void) munmap((void *)statefd->state_file, size);
		statefd->state_file = NULL;
	}
	(void) ftruncate(statefd->fd, 0);
}

static void
close_state_file(const char *filename, state_file_descr_t *statefd)
{
	truncate_state_file(statefd);
	(void) close(statefd->fd);
	(void) unlink(filename);
}

/*
 * Grow the state file by the chunk size specified in statefd
 * and mmap it.
 */
static void
grow_state_file(state_file_descr_t *statefd)
{
	size_t size;
	int max_elements;
	int error_num;

	max_elements = statefd->chunk_size;
	if (statefd->state_file)
		max_elements += statefd->state_file->max_elements;

	size = sizeof (state_file_t) +
		statefd->element_size * max_elements;

	if (ftruncate(statefd->fd, size) != 0) {
		error_num = errno;
		rcm_log_message(RCM_ERROR, MF_STATE_FILE_ERR,
			"ftruncate", strerror(error_num));
		rcmd_exit(error_num);
		/*NOTREACHED*/
	}

	/* LINTED */
	statefd->state_file = (state_file_t *)mmap(NULL, size,
		PROT_READ|PROT_WRITE, MAP_SHARED, statefd->fd, 0);

	if (statefd->state_file == MAP_FAILED) {
		error_num = errno;
		rcm_log_message(RCM_ERROR, MF_STATE_FILE_ERR,
			"mmap", strerror(error_num));
		rcmd_exit(error_num);
		/*NOTREACHED*/
	}

	statefd->index = statefd->state_file->max_elements;
	statefd->state_file->max_elements = max_elements;
	statefd->state_file->version = statefd->version;
}

/*
 * Given index into state element array, get the pointer to the actual
 * state element.
 * If flag is non-null set *flag to
 *	TRUE if the state element is currently is use.
 *	FALSE if the state element is free.
 */
static void *
get_state_element(state_file_descr_t *statefd, int index, int *flag)
{
	char *ptr;

	if (statefd->state_file &&
	    (index < statefd->state_file->max_elements)) {

		ptr = (char *)(statefd->state_file);
		ptr += sizeof (state_file_t) +
			index * statefd->element_size;

		if (flag) {
			*flag = (((state_element_t *)((void *)ptr))->flags &
				STATE_ELEMENT_IN_USE) ? 1 : 0;
		}

		ptr += sizeof (state_element_t);
	} else
		ptr = NULL;

	return ((void *)ptr);
}

/*
 * Allocate a state element entry in the state file and return a pointer
 * to the allocated entry.
 * If index is non-null set *index to index into the state element array
 * of the allocated entry.
 */
static void *
allocate_state_element(state_file_descr_t *statefd, int *index)
{
	void *x;
	int i;
	int flag;

	if (statefd->state_file) {
		/* find an empty slot */
		for (i = 0; i < statefd->state_file->max_elements; i++) {
			x = get_state_element(statefd, statefd->index,
						&flag);
			assert(x != NULL);

			if (flag == 0)
				/* entry is free */
				break;

			statefd->index++;
			if (statefd->index >= statefd->state_file->max_elements)
				statefd->index = 0;
		}
	}

	if (statefd->state_file == NULL ||
		i == statefd->state_file->max_elements) {

		/* All entries are in use. Grow the list */
		grow_state_file(statefd);
		x = get_state_element(statefd, statefd->index, &flag);
		assert(flag == 0);
	}

	if (index != NULL)
		*index = statefd->index;

	statefd->index++;
	if (statefd->index >= statefd->state_file->max_elements)
		statefd->index = 0;

	((state_element_t *)x - 1)->flags |= STATE_ELEMENT_IN_USE;
	return (x);
}

static void
free_state_element(void *x)
{
	((state_element_t *)x - 1)->flags &= ~STATE_ELEMENT_IN_USE;
}

/*
 * Kill the pids contained in ps state file.
 */
static void
script_ps_state_file_kill_pids(void)
{
	ps_state_element_t *x;
	char procfile[80];
	psinfo_t psi;
	int fd, i, flag;

	/* LINTED */
	for (i = 0; 1; i++) {
		if ((x = (ps_state_element_t *)get_state_element(
					&script_ps_statefd, i, &flag)) == NULL)
			break;

		if (flag == 1) { /* the entry is in use */
			(void) snprintf(procfile, 80, "/proc/%ld/psinfo",
					(long)x->pid);
			if ((fd = open(procfile, O_RDONLY)) != -1 &&
				read(fd, &psi, sizeof (psi)) == sizeof (psi) &&
				strcmp(psi.pr_fname,
				x->script_name) == 0) {

				(void) close(fd);

				/*
				 * just a safety check to not to blow up
				 * system processes if the file is ever corrupt
				 */
				if (x->pid > 1) {
					rcm_log_message(RCM_DEBUG,
					"script_ps_state_file_kill_pids: "
					"killing script_name = %s pid = %ld\n",
					x->script_name, x->pid);

					/* kill the process group */
					(void) kill(-(x->pid), SIGKILL);
				}
			} else {
				if (fd != -1)
					(void) close(fd);
			}
			free_state_element((void *)x);
		}
	}
}

/*
 * Add a state element entry to ps state file.
 */
static void
script_ps_state_file_add_entry(pid_t pid, char *script_name)
{
	ps_state_element_t *x;

	(void) mutex_lock(&script_lock);

	x = (ps_state_element_t *)allocate_state_element(
		&script_ps_statefd, NULL);

	x->pid = pid;
	(void) strlcpy(x->script_name, script_name, MAXNAMELEN);

	(void) fsync(script_ps_statefd.fd);

	(void) mutex_unlock(&script_lock);
}

/*
 * Remove the state element entry corresponding to pid from the
 * ps state file.
 */
static void
script_ps_state_file_remove_entry(pid_t pid)
{
	ps_state_element_t *x;
	int flag, i;

	(void) mutex_lock(&script_lock);

	/* LINTED */
	for (i = 0; 1; i++) {
		if ((x = (ps_state_element_t *)get_state_element(
					&script_ps_statefd, i, &flag)) == NULL)
			break;

		/* if the state element entry is in use and pid matches */
		if (flag == 1 && x->pid == pid) {
			free_state_element((void *)x);
			break;
		}
	}

	(void) mutex_unlock(&script_lock);
}

/*
 * Get data item id given data item name
 */
static int
dname_to_id(char *dname)
{
	int i;

	for (i = 0; script_data_item_name[i] != NULL; i++) {
		if (strcmp(dname, script_data_item_name[i]) == 0)
			return (i);
	}

	return (-1);
}

/*
 * Called before running any script.
 * This routine waits until the number of script processes running in
 * parallel drops down below to script_max_parallelism.
 */
static void
script_process_sema_wait(void)
{
	int error_num;

	/* LINTED */
	while (1) {
		if (sema_wait(&script_process_sema) == 0)
			return;

		if (errno != EINTR && errno != EAGAIN) {
			error_num = errno;
			rcm_log_message(RCM_ERROR, MF_FUNC_CALL_ERR,
				"sema_wait", strerror(error_num));
			rcmd_exit(error_num);
			/*NOTREACHED*/
		}
	}

	/*NOTREACHED*/
}

/*
 * Fork and execute the script.
 */
static int
run_script(script_info_t *rsi, char *argv[], char *envp[], char **errmsg)
{
	int i, p1 = -1, p2 = -1;
	struct rlimit rlp;
	struct stat stats;

	rcm_log_message(RSCR_TRACE, "run_script: script name = %s\n",
					rsi->script_full_name);

	for (i = 0; argv[i] != NULL; i++)
		rcm_log_message(RSCR_TRACE, "run_script: argv[%d] = %s\n",
					i, argv[i]);

	*errmsg = NULL;

	/* check that the script exists */
	if (stat(rsi->script_full_name, &stats) != 0)
		goto error;

	/*
	 * If the syscall pipe fails because of reaching the max open file
	 * count per process then dynamically increase the limit on the max
	 * open file count.
	 *
	 * At present the rcm_daemon consumes file descriptor
	 * entries for the following files.
	 *   RCM_STATE_FILE   - /var/run/rcm_daemon_state
	 *   DAEMON_LOCK_FILE - /var/run/rcm_daemon_lock
	 *   RCM_SERVICE_DOOR - /var/run/rcm_daemon_door
	 *   proc files in the format "/proc/pid/as" for each pid
	 *	communicating with the rcm_daemon via doors
	 *   dlopen for each rcm module
	 *   When in daemon mode stdin, stdout and stderr are closed;
	 *	/dev/null opened and duped to stdout, and stderr
	 *   openlog
	 *   Some files which are opened briefly and closed such as
	 *	directory files.
	 *   Two file descriptors for each script in running state.
	 *	Note that the constant script_max_parallelism sets an
	 *	upper cap on how many rcm scripts can run in
	 *	parallel.
	 */
	if ((p1 = pipe(rsi->pipe1)) == -1 || (p2 = pipe(rsi->pipe2)) == -1) {
		if ((errno == EMFILE) &&
			(getrlimit(RLIMIT_NOFILE, &rlp) == 0)) {

			rlp.rlim_cur += 16;
			if (rlp.rlim_max < rlp.rlim_cur)
				rlp.rlim_max = rlp.rlim_cur;
			(void) setrlimit(RLIMIT_NOFILE, &rlp);

			if (p1 == -1) {
				if ((p1 = pipe(rsi->pipe1)) == -1)
					goto error;
			}
			if ((p2 = pipe(rsi->pipe2)) == -1)
				goto error;
		} else
			goto error;
	}

forkagain:
	if ((rsi->pid = fork1()) == (pid_t)-1) {
		if (errno == EINTR || errno == EAGAIN)
			goto forkagain;

		goto error;
	}

	if (rsi->pid == 0) {
		/* child process */

		(void) setsid();

		/* close stdin, stdout and stderr */
		(void) close(0);
		(void) close(1);
		(void) close(2);

		/* set stdin to /dev/null */
		(void) open("/dev/null", O_RDWR, 0);

		/* redirect stdout and stderr to pipe */
		(void) dup2(rsi->pipe1[CHILD_END_OF_PIPE], 1);
		(void) dup2(rsi->pipe2[CHILD_END_OF_PIPE], 2);

		/* close all other file descriptors */
		closefrom(3);

		/* restore original file limit */
		(void) setrlimit(RLIMIT_NOFILE, &file_limit);

		/* set current working dir */
		if (stats.st_uid == 0) {
			/* root */
			if (chdir("/var/run") == -1)
				_exit(127);
		} else {
			if (chdir("/tmp") == -1)
				_exit(127);
		}

		/*
		 * setuid sets real, effective and saved user ids to the
		 * given id.
		 * setgid sets real, effective and saved group ids to the
		 * given id.
		 */
		(void) setgid(stats.st_gid);
		(void) setuid(stats.st_uid);

		(void) execve(rsi->script_full_name, argv, envp);
		_exit(127);
		/*NOTREACHED*/
	}

	(void) close(rsi->pipe1[CHILD_END_OF_PIPE]);
	(void) close(rsi->pipe2[CHILD_END_OF_PIPE]);

	script_ps_state_file_add_entry(rsi->pid, rsi->script_name);

	return (0);

error:
	*errmsg = dup_err(RCM_ERROR, MS_SCRIPT_ERR,
			rsi->script_name, strerror(errno));

	if (p1 != -1) {
		(void) close(rsi->pipe1[PARENT_END_OF_PIPE]);
		(void) close(rsi->pipe1[CHILD_END_OF_PIPE]);
	}

	if (p2 != -1) {
		(void) close(rsi->pipe2[PARENT_END_OF_PIPE]);
		(void) close(rsi->pipe2[CHILD_END_OF_PIPE]);
	}

	return (-1);
}

/*
 * Reads one line of input (including the newline character) from the
 * given file descriptor "fd" to buf.
 * maxbuflen specifies the size of memory allocated for buf.
 * Timeoutval is the max timeout value in seconds for the script to supply
 * input. A timeoutval of 0 implies no timeout.
 *
 * Upon return *buflen contains the number of bytes read.
 *
 * Return values:
 *   0  success
 *   -1 an error occured
 *   -2 timeout occurred
 *   -3 script exited
 */
static int
get_line(int fd,
	char *fdname,
	char *buf,
	int maxbuflen,
	size_t *buflen,
	time_t timeoutval,
	int *error_num)
{
	char c = '\0';
	struct pollfd fds[1];
	int x;
	size_t len = 0;
	char *ptr;
	int timeit;
	time_t deadline;
	int rval = 0;

	if (timeoutval) {
		timeit = TRUE;
		deadline = time(NULL) + timeoutval;
		fds[0].fd = fd;
		fds[0].events = POLLIN;
	} else
		timeit = FALSE;

	ptr = buf;

	while (c != '\n' && len < (maxbuflen -1)) {
		if (timeit) {
pollagain:
			fds[0].revents = 0;
			timeoutval = deadline - time(NULL);
			if (timeoutval <= 0) {
				rval = -2;
				break;
			}
			x = poll(fds, 1, timeoutval*1000);
			if (x <= 0) {
				if (x == 0)
					/* poll timedout */
					rval = -2;
				else {
					if (errno == EINTR || errno == EAGAIN)
						goto pollagain;
					*error_num = errno;
					rval = -1;
				}
				break;
			}
		}
readagain:
		if ((x = read(fd, &c, 1)) != 1) {
			if (x == 0)
				/*
				 * Script exited. Or more specifically the
				 * script has closed its end of the pipe.
				 */
				rval = -3;
			else {
				if (errno == EINTR || errno == EAGAIN)
					goto readagain;
				*error_num = errno;
				rval = -1;
			}
			break;
		}

		*ptr++ = c;
		len++;
	}

	*ptr = '\0';
	*buflen = len;

	rcm_log_message(RSCR_TRACE,
		"get_line(%s): rval = %d buflen = %d line = %s\n",
		fdname, rval, *buflen, buf);
	return (rval);
}

static void
script_exited(script_info_t *rsi)
{
	if (rsi->flags & STDERR_THREAD_CREATED) {
		rcm_log_message(RSCR_TRACE,
		    "script_exited: doing thr_join (%s)\n", rsi->script_name);
		(void) thr_join(rsi->tid, NULL, NULL);
		rsi->flags &= ~STDERR_THREAD_CREATED;
	}

	(void) close(rsi->pipe1[PARENT_END_OF_PIPE]);
	(void) close(rsi->pipe2[PARENT_END_OF_PIPE]);
	rsi->pipe1[PARENT_END_OF_PIPE] = -1;
	rsi->pipe2[PARENT_END_OF_PIPE] = -1;

	script_ps_state_file_remove_entry(rsi->pid);
	rsi->pid = 0;
	(void) sema_post(&script_process_sema);
}

/*
 * Kill the specified process group
 */
static int
kill_pid(pid_t pid)
{
	time_t deadline, timeleft;
	int child_status;

	/* kill the entire process group */
	(void) kill(-(pid), SIGKILL);

	/* give some time for the script to be killed */
	deadline = time(NULL) + SCRIPT_KILL_TIMEOUT;
	do {
		if (waitpid(pid, &child_status, WNOHANG) == pid)
			return (0);

		/* wait for 100 ms */
		(void) poll(NULL, 0, 100);

		timeleft = deadline - time(NULL);
	} while (timeleft > 0);

	/* script process was not killed successfully */
	return (-1);
}

/*
 * Kill the specified script.
 */
static void
kill_script(script_info_t *rsi)
{
	if (rsi->pid > 1) {
		(void) kill_pid(rsi->pid);
		script_exited(rsi);
		remove_drreq_all(rsi);
	}
}

/*
 * Convert rcm flags parameter to a string.
 * Used for debug prints.
 */
static char *
flags_to_name(int flags, char *buf, int maxbuflen)
{
	(void) snprintf(buf, maxbuflen, "%s%s",
		(flags & RCM_QUERY) ? "RCM_QUERY " : "",
		(flags & RCM_FORCE) ? "RCM_FORCE" : "");

	return (buf);
}

static void
fill_argv(script_info_t *rsi, char *argv[], char *resource_name)
{
	argv[0] = rsi->script_full_name;
	argv[1] = script_cmd_name[rsi->cmd];
	if (resource_name) {
		argv[2] = resource_name;
		argv[3] = NULL;
	} else
		argv[2] = NULL;
}

/*
 * stderr thread:
 * Reads stderr and logs to syslog.
 * Runs as a separate thread.
 */
static void *
read_stderr(script_info_t *rsi)
{
	char buf[MAX_LINE_LEN];
	size_t buflen;
	int error_num;

	while ((get_line(rsi->pipe2[PARENT_END_OF_PIPE], "stderr",
		buf, MAX_LINE_LEN, &buflen, 0, &error_num)) == 0) {
		log_msg(rsi, RCM_ERROR, buf);
	}

	if (buflen)
		log_msg(rsi, RCM_ERROR, buf);

	return (NULL);
}

/* process return data items passed by scripts to the framework */
static int
process_dataitem(script_info_t *rsi, int token, char *value, char **errmsg)
{
	char *ptr;
	int status;

	*errmsg = NULL;

	if (*value == '\0')
		goto error;

	switch (token) {
	case D_SCRIPT_VERSION:
		if (rsi->cmd != C_SCRIPTINFO)
			goto error;

		/* check that value contains only digits */
		for (ptr = value; *ptr != '\0'; ptr++)
			if (isdigit((int)(*ptr)) == 0)
				break;

		if (*ptr == '\0')
			rsi->ver = atoi(value);
		else
			goto error;

		break;

	case D_SCRIPT_FUNC_INFO:
		if (rsi->cmd != C_SCRIPTINFO)
			goto error;

		rcmscript_snprintf(&rsi->func_info_buf,
			&rsi->func_info_buf_len,
			&rsi->func_info_buf_curptr,
			"%s", value);
		break;

	case D_CMD_TIMEOUT:
		if (rsi->cmd != C_SCRIPTINFO)
			goto error;

		/* check that value contains only digits */
		for (ptr = value; *ptr != '\0'; ptr++)
			if (isdigit((int)(*ptr)) == 0)
				break;

		if (*ptr == '\0')
			rsi->cmd_timeout = atoi(value);
		else
			goto error;
		break;

	case D_RESOURCE_NAME:
		if (rsi->cmd != C_REGISTER)
			goto error;

		if (get_capacity_descr(value) != NULL)
			status = rcm_register_capacity(rsi->hdl, value,
					0, NULL);
		else
			status = rcm_register_interest(rsi->hdl, value, 0,
					NULL);

		if (status == RCM_FAILURE && errno == EALREADY)
			status = RCM_SUCCESS;

		if (status != RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR, MS_REGISTER_RSRC_ERR,
				rsi->script_name, value);
		}

		remove_from_unregister(rsi, value);
		break;

	case D_RESOURCE_USAGE_INFO:
		if (rsi->cmd != C_RESOURCEINFO)
			goto error;

		rcmscript_snprintf(&rsi->resource_usage_info_buf,
			&rsi->resource_usage_info_buf_len,
			&rsi->resource_usage_info_buf_curptr,
			"%s", value);
		break;

	case D_FAILURE_REASON:
		rcmscript_snprintf(&rsi->failure_reason_buf,
			&rsi->failure_reason_buf_len,
			&rsi->failure_reason_buf_curptr,
			"%s", value);
		break;

	default:
		goto error;
	}

	return (0);

error:
	*errmsg = dup_err(RCM_ERROR, MS_PROTOCOL_ERR, rsi->script_name);
	return (-1);
}

/* Send the given command to the script and process return data */
static int
do_cmd(script_info_t *rsi, char *argv[], char *envp[], char **errmsg)
{
	char buf[MAX_LINE_LEN];
	size_t buflen;
	int loglevel = -1, continuelog = 0;
	char *ptr, *dname, *value;
	time_t maxsecs;
	time_t deadline;
	int sigaborted = 0;
	int rval, child_status, token;
	int error_num;
	int cmd_timeout = rsi->cmd_timeout;

	*errmsg = NULL;

	script_process_sema_wait();

	if (run_script(rsi, argv, envp, errmsg) == -1) {
		(void) sema_post(&script_process_sema);
		goto error2;
	}

	(void) time(&rsi->lastrun);
	deadline = rsi->lastrun + cmd_timeout;

	if (thr_create(NULL, 0, (void *(*)(void *))read_stderr, rsi,
	    0, &rsi->tid) != 0) {
		*errmsg = dup_err(RCM_ERROR, MF_FUNC_CALL_ERR,
				"thr_create", strerror(errno));
		goto error1;
	}
	rsi->flags |= STDERR_THREAD_CREATED;

	/* LINTED */
	while (1) {
		if (cmd_timeout > 0) {
			maxsecs = deadline - time(NULL);
			if (maxsecs <= 0)
				goto timedout;
		} else
			maxsecs = 0;

		rval = get_line(rsi->pipe1[PARENT_END_OF_PIPE],
				"stdout", buf, MAX_LINE_LEN, &buflen,
				maxsecs, &error_num);

		if (buflen) {
			if (continuelog)
				log_msg(rsi, loglevel, buf);
			else {
				if ((ptr = strchr(buf, '=')) == NULL)
					goto error;

				*ptr = '\0';
				dname = buf;
				value = ptr + 1;
				if ((token = dname_to_id(dname)) == -1)
					goto error;

				switch (token) {
				case D_LOG_ERR:
					loglevel = RCM_ERROR;
					break;

				case D_LOG_WARN:
					loglevel = RCM_WARNING;
					break;

				case D_LOG_INFO:
					loglevel = RCM_INFO;
					break;

				case D_LOG_DEBUG:
					loglevel = RCM_DEBUG;
					break;

				default:
					loglevel = -1;
					break;
				}

				if (loglevel != -1) {
					log_msg(rsi, loglevel, value);
					if (buf[buflen - 1] == '\n')
						continuelog = 0;
					else
						continuelog = 1;
				} else {
					if (buf[buflen - 1] != '\n')
						goto error;

					buf[buflen - 1] = '\0';
					if (process_dataitem(rsi, token,
						value, errmsg) != 0)
						goto error1;
				}
			}
		}

		if (rval == -3) {
			/* script exited */
waitagain:
			if (waitpid(rsi->pid, &child_status, 0)
					!= rsi->pid) {
				if (errno == EINTR || errno == EAGAIN)
					goto waitagain;
				*errmsg = dup_err(RCM_ERROR, MS_SCRIPT_ERR,
					rsi->script_name, strerror(errno));
				goto error1;
			}

			if (WIFEXITED(child_status)) {
				script_exited(rsi);
				rsi->exit_status = WEXITSTATUS(child_status);
			} else {
				if (sigaborted)
					*errmsg = dup_err(RCM_ERROR,
					MS_TIMEOUT_ERR, rsi->script_name);
				else
					*errmsg = dup_err(RCM_ERROR,
					MS_UNKNOWN_ERR, rsi->script_name);

				/* kill any remaining processes in the pgrp */
				(void) kill(-(rsi->pid), SIGKILL);
				script_exited(rsi);
				goto error2;
			}

			break;
		}

		if (rval == -1) {
			*errmsg = dup_err(RCM_ERROR, MS_SCRIPT_ERR,
				rsi->script_name, strerror(errno));
			goto error1;
		}

		if (rval == -2) {
timedout:
			/* timeout occurred */
			if (sigaborted == 0) {
				(void) kill(rsi->pid, SIGABRT);
				sigaborted = 1;
				/* extend deadline */
				deadline += SCRIPT_ABORT_TIMEOUT;
			} else {
				*errmsg = dup_err(RCM_ERROR,
					MS_TIMEOUT_ERR, rsi->script_name);
				goto error1;
			}
		}
	}

	return (0);

error:
	*errmsg = dup_err(RCM_ERROR, MS_PROTOCOL_ERR, rsi->script_name);

error1:
	kill_script(rsi);

error2:
	return (-1);
}

static int
do_script_info(script_info_t *rsi)
{
	char *argv[MAX_ARGS];
	int status = RCM_FAILURE;
	int err = 0;
	char *errmsg = NULL;

	rcm_log_message(RSCR_TRACE, "do_script_info: script name = %s\n",
						rsi->script_name);

	rsi->cmd = C_SCRIPTINFO;
	rsi->func_info_buf = NULL;
	rsi->failure_reason_buf = NULL;
	fill_argv(rsi, argv, NULL);

	if (do_cmd(rsi, argv, script_env, &errmsg) == 0) {
		switch (rsi->exit_status) {
		case E_SUCCESS:
			if (rsi->func_info_buf != NULL &&
				rsi->failure_reason_buf == NULL) {

				if (rsi->ver >= SCRIPT_API_MIN_VER &&
					rsi->ver <= SCRIPT_API_MAX_VER)
					status = RCM_SUCCESS;
				else
					rcm_log_message(RCM_ERROR,
					MS_UNSUPPORTED_VER, rsi->script_name,
					rsi->ver);
			} else
				err = 1;
			break;

		case E_FAILURE:
			if (rsi->failure_reason_buf != NULL) {
				rcm_log_message(RCM_ERROR, MS_SCRIPTINFO_ERR,
					rsi->script_name,
					rsi->failure_reason_buf);
			} else
				err = 1;
			break;

		default:
			err = 1;
			break;
		}
		if (err)
			rcm_log_message(RCM_ERROR, MS_PROTOCOL_ERR,
				rsi->script_name);
	} else if (errmsg)
		(void) free(errmsg);

	if (status != RCM_SUCCESS && rsi->func_info_buf != NULL)
		free(rsi->func_info_buf);

	if (rsi->failure_reason_buf)
		free(rsi->failure_reason_buf);

	return (status);
}

static int
do_dr(script_info_t *rsi, char *argv[], char *envp[], char **info)
{
	int status = RCM_FAILURE;
	int err = 0;

	rsi->failure_reason_buf = NULL;

	if (do_cmd(rsi, argv, envp, info) == 0) {
		switch (rsi->exit_status) {
		case E_SUCCESS:
		case E_UNSUPPORTED_CMD:
			if (rsi->failure_reason_buf == NULL)
				status = RCM_SUCCESS;
			else
				err = 1;
			break;

		case E_FAILURE:
		case E_REFUSE:
			if (rsi->failure_reason_buf != NULL) {
				*info = rsi->failure_reason_buf;
				rsi->failure_reason_buf = NULL;
			} else
				err = 1;
			break;

		default:
			err = 1;
			break;
		}

		if (err)
			*info = dup_err(RCM_ERROR, MS_PROTOCOL_ERR,
				rsi->script_name);
	}

	if (rsi->failure_reason_buf)
		free(rsi->failure_reason_buf);

	return (status);
}

/*
 * get_info entry point
 */
/* ARGSUSED */
static int
script_get_info(rcm_handle_t *hdl,
	char *resource_name,
	pid_t pid,
	uint_t flag,
	char **info,
	char **error,
	nvlist_t *props,
	rcm_info_t **dependent_info)
{
	script_info_t *rsi = hdl->module->rsi;
	char *argv[MAX_ARGS];
	int status = RCM_FAILURE;
	int err = 0;

	rcm_log_message(RSCR_TRACE, "script_get_info: resource = %s\n",
				resource_name);

	*info = NULL;
	*error = NULL;

	(void) mutex_lock(&rsi->channel_lock);

	rsi->hdl = hdl;
	rsi->cmd = C_RESOURCEINFO;
	rsi->resource_usage_info_buf = NULL;
	rsi->failure_reason_buf = NULL;
	fill_argv(rsi, argv, resource_name);

	if (do_cmd(rsi, argv, script_env, error) == 0) {
		switch (rsi->exit_status) {
		case E_SUCCESS:
			if (rsi->resource_usage_info_buf != NULL &&
				rsi->failure_reason_buf == NULL) {

				*info = rsi->resource_usage_info_buf;
				rsi->resource_usage_info_buf = NULL;
				status = RCM_SUCCESS;
			} else
				err = 1;
			break;

		case E_FAILURE:
			if (rsi->failure_reason_buf != NULL) {
				*error = rsi->failure_reason_buf;
				rsi->failure_reason_buf = NULL;
			} else
				err = 1;
			break;

		default:
			err = 1;
			break;
		}
		if (err)
			*error = dup_err(RCM_ERROR, MS_PROTOCOL_ERR,
				rsi->script_name);
	}

	if (rsi->resource_usage_info_buf)
		free(rsi->resource_usage_info_buf);

	if (rsi->failure_reason_buf)
		free(rsi->failure_reason_buf);

	(void) mutex_unlock(&rsi->channel_lock);

	return (status);
}

static void
add_for_unregister(script_info_t *rsi)
{
	module_t *module = rsi->module;
	client_t *client;
	rcm_queue_t *head;
	rcm_queue_t *q;

	(void) mutex_lock(&rcm_req_lock);

	head = &module->client_q;

	for (q = head->next; q != head; q = q->next) {
		client = RCM_STRUCT_BASE_ADDR(client_t, q, queue);
		client->prv_flags |= RCM_NEED_TO_UNREGISTER;
	}

	(void) mutex_unlock(&rcm_req_lock);
}

static void
remove_from_unregister(script_info_t *rsi, char *resource_name)
{
	module_t *module = rsi->module;
	client_t *client;
	rcm_queue_t *head;
	rcm_queue_t *q;

	(void) mutex_lock(&rcm_req_lock);

	head = &module->client_q;

	for (q = head->next; q != head; q = q->next) {
		client = RCM_STRUCT_BASE_ADDR(client_t, q, queue);
		if (strcmp(client->alias, resource_name) == 0) {
			client->prv_flags &= ~RCM_NEED_TO_UNREGISTER;
			break;
		}
	}

	(void) mutex_unlock(&rcm_req_lock);
}

static void
complete_unregister(script_info_t *rsi)
{
	module_t *module = rsi->module;
	client_t *client;
	rcm_queue_t *head;
	rcm_queue_t *q;

	(void) mutex_lock(&rcm_req_lock);

	head = &module->client_q;

	for (q = head->next; q != head; q = q->next) {
		client = RCM_STRUCT_BASE_ADDR(client_t, q, queue);
		if (client->prv_flags & RCM_NEED_TO_UNREGISTER) {
			client->prv_flags &= ~RCM_NEED_TO_UNREGISTER;
			client->state = RCM_STATE_REMOVE;
		}
	}

	(void) mutex_unlock(&rcm_req_lock);
}

/*
 * register_interest entry point
 */
static int
script_register_interest(rcm_handle_t *hdl)
{
	script_info_t *rsi = hdl->module->rsi;
	char *argv[MAX_ARGS];
	int status = RCM_FAILURE;
	int err = 0;
	char *errmsg = NULL;

	rcm_log_message(RSCR_TRACE,
		"script_register_interest: script name = %s\n",
		rsi->script_name);

	(void) mutex_lock(&rsi->channel_lock);

	if (rsi->drreq_q.next != &rsi->drreq_q) {
		/* if DR is already in progress no need to register again */
		(void) mutex_unlock(&rsi->channel_lock);
		return (RCM_SUCCESS);
	}

	rsi->hdl = hdl;
	rsi->cmd = C_REGISTER;
	rsi->failure_reason_buf = NULL;
	fill_argv(rsi, argv, NULL);

	add_for_unregister(rsi);

	if (do_cmd(rsi, argv, script_env, &errmsg) == 0) {
		switch (rsi->exit_status) {
		case E_SUCCESS:
			status = RCM_SUCCESS;
			break;

		case E_FAILURE:
			if (rsi->failure_reason_buf != NULL) {
				rcm_log_message(RCM_ERROR, MS_REGISTER_ERR,
					rsi->script_name,
					rsi->failure_reason_buf);
			} else
				err = 1;
			break;

		default:
			err = 1;
			break;
		}
		if (err)
			rcm_log_message(RCM_ERROR, MS_PROTOCOL_ERR,
				rsi->script_name);
	} else if (errmsg)
		(void) free(errmsg);

	complete_unregister(rsi);

	if (rsi->failure_reason_buf)
		free(rsi->failure_reason_buf);

	(void) mutex_unlock(&rsi->channel_lock);

	return (status);
}

/*
 * Add the specified resource name to the drreq_q.
 */
static void
add_drreq(script_info_t *rsi, char *resource_name)
{
	rcm_queue_t *head = &rsi->drreq_q;
	rcm_queue_t *q;
	drreq_t *drreq;

	/* check if the dr req is already in the list */
	for (q = head->next; q != head; q = q->next) {
		drreq = RCM_STRUCT_BASE_ADDR(drreq_t, q, queue);
		if (strcmp(drreq->resource_name, resource_name) == 0)
			/* dr req is already present in the queue */
			return;
	}

	drreq = (drreq_t *)rcmscript_calloc(1, sizeof (drreq_t));
	drreq->resource_name = rcmscript_strdup(resource_name);

	rcm_enqueue_tail(&rsi->drreq_q, &drreq->queue);
}

/*
 * Remove the dr req for the specified resource name from the drreq_q.
 */
static void
remove_drreq(script_info_t *rsi, char *resource_name)
{
	rcm_queue_t *head = &rsi->drreq_q;
	rcm_queue_t *q;
	drreq_t *drreq;

	/* search for dr req and remove from the list */
	for (q = head->next; q != head; q = q->next) {
		drreq = RCM_STRUCT_BASE_ADDR(drreq_t, q, queue);
		if (strcmp(drreq->resource_name, resource_name) == 0)
			break;
	}

	if (q != head) {
		/* found drreq on the queue */
		rcm_dequeue(&drreq->queue);
		free(drreq->resource_name);
		free(drreq);
	}
}

/*
 * Remove all dr req's.
 */
static void
remove_drreq_all(script_info_t *rsi)
{
	drreq_t *drreq;

	while (rsi->drreq_q.next != &rsi->drreq_q) {
		drreq = RCM_STRUCT_BASE_ADDR(drreq_t,
					rsi->drreq_q.next, queue);
		remove_drreq(rsi, drreq->resource_name);
	}
}

/*
 * request_offline entry point
 */
/* ARGSUSED */
static int
script_request_offline(rcm_handle_t *hdl,
	char *resource_name,
	pid_t pid,
	uint_t flag,
	char **info,
	rcm_info_t **dependent_info)
{
	script_info_t *rsi = hdl->module->rsi;
	char *argv[MAX_ARGS];
	char *envp[MAX_ENV_PARAMS];
	char flags_name[MAX_FLAGS_NAME_LEN];
	int status;
	int i;

	rcm_log_message(RSCR_TRACE,
		"script_request_offline: resource = %s flags = %s\n",
			resource_name,
			flags_to_name(flag, flags_name, MAX_FLAGS_NAME_LEN));

	*info = NULL;

	(void) mutex_lock(&rsi->channel_lock);

	rsi->hdl = hdl;
	rsi->cmd = (flag & RCM_QUERY) ? C_QUERYREMOVE : C_PREREMOVE;

	if (rsi->cmd == C_PREREMOVE)
		add_drreq(rsi, resource_name);

	fill_argv(rsi, argv, resource_name);
	copy_env(script_env, envp);
	for (i = 0; envp[i] != NULL; i++)
		;
	envp[i++] = (flag & RCM_FORCE) ? script_env_force : script_env_noforce;
	envp[i] = NULL;

	status = do_dr(rsi, argv, envp, info);

	(void) mutex_unlock(&rsi->channel_lock);
	return (status);
}

/*
 * notify_online entry point
 */
/* ARGSUSED */
static int
script_notify_online(rcm_handle_t *hdl,
	char *resource_name,
	pid_t pid,
	uint_t flag,
	char **info,
	rcm_info_t **dependent_info)
{
	script_info_t *rsi = hdl->module->rsi;
	char *argv[MAX_ARGS];
	int status;

	rcm_log_message(RSCR_TRACE, "script_notify_online: resource = %s\n",
				resource_name);

	*info = NULL;

	(void) mutex_lock(&rsi->channel_lock);

	rsi->hdl = hdl;
	rsi->cmd = C_UNDOREMOVE;
	fill_argv(rsi, argv, resource_name);

	status = do_dr(rsi, argv, script_env, info);

	remove_drreq(rsi, resource_name);

	(void) mutex_unlock(&rsi->channel_lock);
	return (status);
}

/*
 * notify_remove entry point
 */
/* ARGSUSED */
static int
script_notify_remove(rcm_handle_t *hdl,
	char *resource_name,
	pid_t pid,
	uint_t flag,
	char **info,
	rcm_info_t **dependent_info)
{
	script_info_t *rsi = hdl->module->rsi;
	char *argv[MAX_ARGS];
	int status;

	rcm_log_message(RSCR_TRACE, "script_notify_remove: resource = %s\n",
				resource_name);

	*info = NULL;

	(void) mutex_lock(&rsi->channel_lock);

	rsi->hdl = hdl;
	rsi->cmd = C_POSTREMOVE;
	fill_argv(rsi, argv, resource_name);

	status = do_dr(rsi, argv, script_env, info);

	remove_drreq(rsi, resource_name);

	(void) mutex_unlock(&rsi->channel_lock);
	return (status);
}

/*
 * request_suspend entry point
 */
/* ARGSUSED */
static int
script_request_suspend(rcm_handle_t *hdl,
	char *resource_name,
	pid_t pid,
	timespec_t *interval,
	uint_t flag,
	char **info,
	rcm_info_t **dependent_info)
{
	script_info_t *rsi = hdl->module->rsi;
	char *buf = NULL;
	char *curptr = NULL;
	char *argv[MAX_ARGS];
	char *envp[MAX_ENV_PARAMS];
	char flags_name[MAX_FLAGS_NAME_LEN];
	int buflen = 0;
	long seconds;
	int status;
	int i;

	rcm_log_message(RSCR_TRACE,
	    "script_request_suspend: resource = %s flags = %s\n", resource_name,
	    flags_to_name(flag, flags_name, MAX_FLAGS_NAME_LEN));

	*info = NULL;

	(void) mutex_lock(&rsi->channel_lock);

	rsi->hdl = hdl;
	rsi->cmd = (flag & RCM_QUERY) ? C_QUERYSUSPEND : C_PRESUSPEND;

	if (rsi->cmd == C_PRESUSPEND)
		add_drreq(rsi, resource_name);

	fill_argv(rsi, argv, resource_name);

	copy_env(script_env, envp);
	for (i = 0; envp[i] != NULL; i++);

	envp[i++] = (flag & RCM_FORCE) ? script_env_force : script_env_noforce;

	if (interval) {
		/*
		 * Merge the seconds and nanoseconds, rounding up if there
		 * are any remainder nanoseconds.
		 */
		seconds = interval->tv_sec + (interval->tv_nsec / 1000000000L);
		if (interval->tv_nsec % 1000000000L)
			seconds += (interval->tv_sec > 0) ? 1L : -1L;
		rcmscript_snprintf(&buf, &buflen, &curptr, script_env_interval,
		    seconds);
		envp[i++] = buf;
	}

	envp[i] = NULL;

	status = do_dr(rsi, argv, envp, info);

	(void) mutex_unlock(&rsi->channel_lock);
	if (buf)
		free(buf);
	return (status);
}

/*
 * notify_resume entry point
 */
/* ARGSUSED */
static int
script_notify_resume(rcm_handle_t *hdl,
	char *resource_name,
	pid_t pid,
	uint_t flag,
	char **info,
	rcm_info_t **dependent_info)
{
	script_info_t *rsi = hdl->module->rsi;
	char *argv[MAX_ARGS];
	int status;

	rcm_log_message(RSCR_TRACE, "script_notify_resume: resource = %s\n",
	    resource_name);

	*info = NULL;

	(void) mutex_lock(&rsi->channel_lock);

	rsi->hdl = hdl;
	rsi->cmd = (flag & RCM_SUSPENDED) ? C_POSTRESUME : C_CANCELSUSPEND;
	fill_argv(rsi, argv, resource_name);

	status = do_dr(rsi, argv, script_env, info);

	remove_drreq(rsi, resource_name);

	(void) mutex_unlock(&rsi->channel_lock);
	return (status);
}

static capacity_descr_t capacity_type[] = {
	{ "SUNW_memory", MATCH_EXACT,
		"new_pages", "RCM_ENV_CAPACITY",
		"page_size", "RCM_ENV_UNIT_SIZE",
		"", ""},
	{ "SUNW_cpu", MATCH_EXACT,
		"new_total", "RCM_ENV_CAPACITY",
		"new_cpu_list", "RCM_ENV_CPU_IDS",
		"", ""},
	{ "SUNW_cpu/set", MATCH_PREFIX,
		"new_total", "RCM_ENV_CAPACITY",
		"new_cpu_list", "RCM_ENV_CPU_IDS",
		"", ""},
	{ "", MATCH_INVALID, "", "" }
};

static capacity_descr_t *
get_capacity_descr(char *resource_name)
{
	int i;

	for (i = 0; *capacity_type[i].resource_name != '\0'; i++) {
		if ((capacity_type[i].match_type == MATCH_EXACT &&
			strcmp(capacity_type[i].resource_name,
			resource_name) == 0) ||
			(capacity_type[i].match_type == MATCH_PREFIX &&
			strncmp(capacity_type[i].resource_name,
			resource_name,
			strlen(capacity_type[i].resource_name)) == 0))

			return (&capacity_type[i]);
	}

	return (NULL);
}

static int
build_env_for_capacity(script_info_t *rsi,
	char *resource_name,
	uint_t flag,
	nvlist_t *capacity_info,
	char *envp[],
	int *dynamic_env_index,
	char **errmsg)
{
	int p, i;
	capacity_descr_t *capa = NULL;
	nvpair_t *nvpair;
	char *buf;
	char *curptr;
	int buflen;
	int error;
	uint_t n;

	copy_env(script_env, envp);
	for (p = 0; envp[p] != NULL; p++)
		;

	if (rsi->cmd == C_QUERYCAPACITY || rsi->cmd == C_PRECAPACITY)
		envp[p++] = (flag & RCM_FORCE) ? script_env_force :
						script_env_noforce;

	envp[p] = NULL;
	*dynamic_env_index = p;

	if ((capa = get_capacity_descr(resource_name)) == NULL) {
		*errmsg = dup_err(RCM_ERROR, MF_UNKNOWN_RSRC_ERR,
			resource_name, rsi->script_name);
		return (-1);
	}

	for (i = 0; *capa->param[i].nvname != '\0'; i++) {
		nvpair = NULL;
		while ((nvpair = nvlist_next_nvpair(capacity_info, nvpair))
				!= NULL) {
			if (strcmp(nvpair_name(nvpair),
					capa->param[i].nvname) == 0)
				break;
		}

		if (nvpair == NULL) {
			*errmsg = dup_err(RCM_ERROR, MF_NV_ERR,
				rsi->script_name);
			return (-1);
		}

		error = 0;
		buf = NULL;

		rcmscript_snprintf(&buf, &buflen, &curptr, "%s=",
				capa->param[i].envname);

		switch (nvpair_type(nvpair)) {
		case DATA_TYPE_INT16:
		{
			int16_t x;

			if (nvpair_value_int16(nvpair, &x) == 0) {
				rcmscript_snprintf(&buf, &buflen, &curptr,
						"%hd", (short)x);
			} else
				error = 1;
			break;
		}

		case DATA_TYPE_UINT16:
		{
			uint16_t x;

			if (nvpair_value_uint16(nvpair, &x) == 0) {
				rcmscript_snprintf(&buf, &buflen, &curptr,
						"%hu", (unsigned short)x);
			} else
				error = 1;
			break;
		}

		case DATA_TYPE_INT32:
		{
			int32_t x;

			if (nvpair_value_int32(nvpair, &x) == 0) {
				rcmscript_snprintf(&buf, &buflen, &curptr,
						"%d", (int)x);
			} else
				error = 1;
			break;
		}

		case DATA_TYPE_UINT32:
		{
			uint32_t x;

			if (nvpair_value_uint32(nvpair, &x) == 0) {
				rcmscript_snprintf(&buf, &buflen, &curptr,
						"%u", (uint_t)x);
			} else
				error = 1;
			break;
		}

		case DATA_TYPE_INT64:
		{
			int64_t x;

			if (nvpair_value_int64(nvpair, &x) == 0) {
				rcmscript_snprintf(&buf, &buflen, &curptr,
						"%lld", (long long)x);
			} else
				error = 1;
			break;
		}

		case DATA_TYPE_UINT64:
		{
			uint64_t x;

			if (nvpair_value_uint64(nvpair, &x) == 0) {
				rcmscript_snprintf(&buf, &buflen, &curptr,
					"%llu", (unsigned long long)x);
			} else
				error = 1;
			break;
		}

		case DATA_TYPE_INT16_ARRAY:
		{
			int16_t *x;

			if (nvpair_value_int16_array(nvpair, &x, &n) == 0) {
				while (n--) {
					rcmscript_snprintf(&buf, &buflen,
						&curptr, "%hd%s",
						(short)(*x),
						(n == 0) ? "" : " ");
					x++;
				}
			} else
				error = 1;
			break;
		}

		case DATA_TYPE_UINT16_ARRAY:
		{
			uint16_t *x;

			if (nvpair_value_uint16_array(nvpair, &x, &n) == 0) {
				while (n--) {
					rcmscript_snprintf(&buf, &buflen,
						&curptr, "%hu%s",
						(unsigned short)(*x),
						(n == 0) ? "" : " ");
					x++;
				}
			} else
				error = 1;
			break;
		}

		case DATA_TYPE_INT32_ARRAY:
		{
			int32_t *x;

			if (nvpair_value_int32_array(nvpair, &x, &n) == 0) {
				while (n--) {
					rcmscript_snprintf(&buf, &buflen,
						&curptr, "%d%s",
						(int)(*x),
						(n == 0) ? "" : " ");
					x++;
				}
			} else
				error = 1;
			break;
		}

		case DATA_TYPE_UINT32_ARRAY:
		{
			uint32_t *x;

			if (nvpair_value_uint32_array(nvpair, &x, &n) == 0) {
				while (n--) {
					rcmscript_snprintf(&buf, &buflen,
						&curptr, "%u%s",
						(uint_t)(*x),
						(n == 0) ? "" : " ");
					x++;
				}
			} else
				error = 1;
			break;
		}

		case DATA_TYPE_INT64_ARRAY:
		{
			int64_t *x;

			if (nvpair_value_int64_array(nvpair, &x, &n) == 0) {
				while (n--) {
					rcmscript_snprintf(&buf, &buflen,
						&curptr, "%lld%s",
						(long long)(*x),
						(n == 0) ? "" : " ");
					x++;
				}
			} else
				error = 1;
			break;
		}

		case DATA_TYPE_UINT64_ARRAY:
		{
			uint64_t *x;

			if (nvpair_value_uint64_array(nvpair, &x, &n) == 0) {
				while (n--) {
					rcmscript_snprintf(&buf, &buflen,
						&curptr, "%llu%s",
						(unsigned long long)(*x),
						(n == 0) ? "" : " ");
					x++;
				}
			} else
				error = 1;
			break;
		}

		case DATA_TYPE_STRING:
		{
			char *x;

			if (nvpair_value_string(nvpair, &x) == 0) {
				rcmscript_snprintf(&buf, &buflen, &curptr,
						"%s", x);
			} else
				error = 1;
			break;
		}


		default:
			error = 1;
			break;
		}

		envp[p++] = buf;

		if (error) {
			envp[p] = NULL;
			for (p = *dynamic_env_index; envp[p] != NULL; p++)
				free(envp[p]);
			*errmsg = dup_err(RCM_ERROR, MF_NV_ERR,
				rsi->script_name);
			return (-1);
		}
	}

	envp[p] = NULL;

	return (0);
}

/*
 * request_capacity_change entry point
 */
/* ARGSUSED */
static int
script_request_capacity_change(rcm_handle_t *hdl,
	char *resource_name,
	pid_t pid,
	uint_t flag,
	nvlist_t *capacity_info,
	char **info,
	rcm_info_t **dependent_info)
{
	script_info_t *rsi = hdl->module->rsi;
	char *argv[MAX_ARGS];
	char *envp[MAX_ENV_PARAMS];
	char flags_name[MAX_FLAGS_NAME_LEN];
	int status;
	int dynamic_env_index;

	rcm_log_message(RSCR_TRACE,
		"script_request_capacity_change: resource = %s flags = %s\n",
			resource_name,
			flags_to_name(flag, flags_name, MAX_FLAGS_NAME_LEN));

	*info = NULL;

	(void) mutex_lock(&rsi->channel_lock);

	rsi->hdl = hdl;
	rsi->cmd = (flag & RCM_QUERY) ? C_QUERYCAPACITY : C_PRECAPACITY;
	fill_argv(rsi, argv, resource_name);

	if (build_env_for_capacity(rsi, resource_name, flag,
			capacity_info, envp, &dynamic_env_index, info) == 0) {

		status = do_dr(rsi, argv, envp, info);

		while (envp[dynamic_env_index] != NULL) {
			free(envp[dynamic_env_index]);
			dynamic_env_index++;
		}
	} else
		status = RCM_FAILURE;

	(void) mutex_unlock(&rsi->channel_lock);
	return (status);
}

/*
 * notify_capacity_change entry point
 */
/* ARGSUSED */
static int
script_notify_capacity_change(rcm_handle_t *hdl,
	char *resource_name,
	pid_t pid,
	uint_t flag,
	nvlist_t *capacity_info,
	char **info,
	rcm_info_t **dependent_info)
{
	script_info_t *rsi = hdl->module->rsi;
	char *argv[MAX_ARGS];
	char *envp[MAX_ENV_PARAMS];
	int status;
	int dynamic_env_index;

	rcm_log_message(RSCR_TRACE,
	"script_notify_capacity_change: resource = %s\n", resource_name);

	*info = NULL;

	(void) mutex_lock(&rsi->channel_lock);

	rsi->hdl = hdl;
	rsi->cmd = C_POSTCAPACITY;
	fill_argv(rsi, argv, resource_name);

	if (build_env_for_capacity(rsi, resource_name, flag,
			capacity_info, envp, &dynamic_env_index, info) == 0) {

		status = do_dr(rsi, argv, envp, info);

		while (envp[dynamic_env_index] != NULL) {
			free(envp[dynamic_env_index]);
			dynamic_env_index++;
		}
	} else
		status = RCM_FAILURE;

	(void) mutex_unlock(&rsi->channel_lock);
	return (status);
}

/* Log the message to syslog */
static void
log_msg(script_info_t *rsi, int level, char *msg)
{
	rcm_log_msg(level, MS_LOG_MSG, rsi->script_name, msg);
}

/*PRINTFLIKE2*/
static char *
dup_err(int level, char *format, ...)
{
	va_list ap;
	char buf1[1];
	char *buf2;
	int n;

	va_start(ap, format);
	n = vsnprintf(buf1, 1, format, ap);
	va_end(ap);

	if (n > 0) {
		n++;
		if (buf2 = (char *)malloc(n)) {
			va_start(ap, format);
			n = vsnprintf(buf2, n, format, ap);
			va_end(ap);
			if (n > 0) {
				if (level != -1)
					rcm_log_message(level, buf2);
				return (buf2);
			}
			free(buf2);
		}
	}

	return (NULL);
}

/*PRINTFLIKE4*/
static void
rcmscript_snprintf(char **buf, int *buflen, char **curptr, char *format, ...)
{
/* must be power of 2 otherwise RSCR_ROUNDUP would break */
#define	SPRINTF_CHUNK_LEN	512
#define	SPRINTF_MIN_CHUNK_LEN	64

	va_list ap;
	int offset, bytesneeded, bytesleft, error_num;

	if (*buf == NULL) {
		*buflen = 0;
		*curptr = NULL;
	}

	offset = *curptr - *buf;
	bytesneeded = SPRINTF_MIN_CHUNK_LEN;
	bytesleft = *buflen - offset;

	/* LINTED */
	while (1) {
		if (bytesneeded > bytesleft) {
			*buflen += RSCR_ROUNDUP(bytesneeded - bytesleft,
					SPRINTF_CHUNK_LEN);
			if ((*buf = (char *)realloc(*buf, *buflen)) == NULL) {
				error_num = errno;
				rcm_log_message(RCM_ERROR,
					MF_MEMORY_ALLOCATION_ERR,
					strerror(error_num));
				rcmd_exit(error_num);
				/*NOTREACHED*/
			}
			*curptr = *buf + offset;
			bytesleft = *buflen - offset;
		}

		va_start(ap, format);
		bytesneeded = vsnprintf(*curptr, bytesleft, format, ap);
		va_end(ap);

		if (bytesneeded < 0)  {
			/* vsnprintf encountered an error */
			error_num = errno;
			rcm_log_message(RCM_ERROR, MF_FUNC_CALL_ERR,
				"vsnprintf", strerror(error_num));
			rcmd_exit(error_num);
			/*NOTREACHED*/

		} else if (bytesneeded < bytesleft) {
			/* vsnprintf succeeded */
			*curptr += bytesneeded;
			return;

		} else {
			bytesneeded++; /* to account for storage for '\0' */
		}
	}
}

static char *
rcmscript_strdup(char *str)
{
	char *dupstr;

	if ((dupstr = strdup(str)) == NULL) {
		rcm_log_message(RCM_ERROR, MF_MEMORY_ALLOCATION_ERR,
			strerror(errno));
		rcmd_exit(errno);
		/*NOTREACHED*/
	}

	return (dupstr);
}

static void *
rcmscript_malloc(size_t len)
{
	void *ptr;

	if ((ptr = malloc(len)) == NULL) {
		rcm_log_message(RCM_ERROR, MF_MEMORY_ALLOCATION_ERR,
			strerror(errno));
		rcmd_exit(errno);
		/*NOTREACHED*/
	}

	return (ptr);
}

static void *
rcmscript_calloc(size_t nelem, size_t elsize)
{
	void *ptr;

	if ((ptr = calloc(nelem, elsize)) == NULL) {
		rcm_log_message(RCM_ERROR, MF_MEMORY_ALLOCATION_ERR,
			strerror(errno));
		rcmd_exit(errno);
		/*NOTREACHED*/
	}

	return (ptr);
}
