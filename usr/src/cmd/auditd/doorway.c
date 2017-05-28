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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Threads:
 *
 * auditd is thread 0 and does signal handling
 *
 * input() is a door server that receives binary audit records and
 * queues them for handling by an instance of process() for conversion to syslog
 * message(s).  There is one process thread per plugin.
 *
 * Queues:
 *
 * Each plugin has a buffer pool and and queue for feeding the
 * the process threads.  The input thread moves buffers from the pool
 * to the queue and the process thread puts them back.
 *
 * Another pool, b_pool, contains buffers referenced by each of the
 * process queues; this is to minimize the number of buffer copies
 *
 */

#include <arpa/inet.h>
#include <assert.h>
#include <bsm/adt.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libintl.h>
#include <pthread.h>
#include <secdb.h>
#include <security/auditd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <audit_plugin.h>	/* libbsm */
#include "plugin.h"
#include <bsm/audit_door_infc.h>
#include "queue.h"

#define	DEBUG		0

/* gettext() obfuscation routine for lint */
#ifdef __lint
#define	gettext(x)	x
#endif

#if DEBUG
static FILE *dbfp;
#define	DUMP(w, x, y, z) dump_state(w, x, y, z)
#define	DPRINT(x) { (void) fprintf x; }
#else
#define	DUMP(w, x, y, z)
#define	DPRINT(x)
#endif

#define	FATAL_MESSAGE_LEN	256

#define	MIN_RECORD_SIZE	(size_t)25

#define	INPUT_MIN		2
#define	THRESHOLD_PCT		75
#define	DEFAULT_BUF_SZ		(size_t)250
#define	BASE_PRIORITY		10	/* 0 - 20 valid for user, time share */
#define	HIGH_PRIORITY		BASE_PRIORITY - 1

static thr_data_t	in_thr;		/* input thread locks and data */
static int		doorfd = -1;

static int		largest_queue = INPUT_MIN;
static au_queue_t	b_pool;
static int		b_allocated = 0;
static pthread_mutex_t	b_alloc_lock;
static pthread_mutex_t	b_refcnt_lock;

static void		input(void *, void *, int, door_desc_t *, int);
static void		process(plugin_t *);

static audit_q_t	*qpool_withdraw(plugin_t *);
static void		qpool_init(plugin_t *, int);
static void		qpool_return(plugin_t *, audit_q_t *);
static void		qpool_close(plugin_t *);

static audit_rec_t	*bpool_withdraw(char *, size_t, size_t);
static void		bpool_init();
static void		bpool_return(audit_rec_t *);

/*
 * warn_or_fatal() -- log daemon error and (optionally) exit
 */
static void
warn_or_fatal(int fatal, char *parting_shot)
{
	char	*severity;
	char	message[512];

	if (fatal)
		severity = gettext("fatal error");
	else
		severity = gettext("warning");

	(void) snprintf(message, 512, "%s:  %s", severity, parting_shot);

	__audit_syslog("auditd", LOG_PID | LOG_ODELAY | LOG_CONS,
	    LOG_DAEMON, LOG_ALERT, message);

	DPRINT((dbfp, "auditd warn_or_fatal %s: %s\n", severity, parting_shot));
	if (fatal)
		auditd_exit(1);
}

/* Internal to doorway.c errors... */
#define	INTERNAL_LOAD_ERROR	-1
#define	INTERNAL_SYS_ERROR	-2
#define	INTERNAL_CONFIG_ERROR	-3

/*
 * report_error -- handle errors returned by plugin
 *
 * rc is plugin's return code if it is a non-negative value,
 * otherwise it is a doorway.c code about a plugin.
 */
static void
report_error(int rc, char *error_text, char *plugin_path)
{
	int		warn = 0;
	char		rcbuf[100]; /* short error name string */
	char		message[FATAL_MESSAGE_LEN];
	int		bad_count = 0;
	char		*name;
	char		empty[] = "..";

	static int	no_plug = 0;
	static int	no_load = 0;
	static int	no_thread;
	static int	no_memory = 0;
	static int	invalid = 0;
	static int	retry = 0;
	static int	fail = 0;

	name = plugin_path;
	if (error_text == NULL)
		error_text = empty;
	if (name == NULL)
		name = empty;

	switch (rc) {
	case INTERNAL_LOAD_ERROR:
		warn = 1;
		bad_count = ++no_load;
		(void) strcpy(rcbuf, "load_error");
		break;
	case INTERNAL_SYS_ERROR:
		warn = 1;
		bad_count = ++no_thread;
		(void) strcpy(rcbuf, "sys_error");
		break;
	case INTERNAL_CONFIG_ERROR:
		warn = 1;
		bad_count = ++no_plug;
		(void) strcpy(rcbuf, "config_error");
		name = strdup("--");
		break;
	case AUDITD_SUCCESS:
		break;
	case AUDITD_NO_MEMORY:	/* no_memory */
		warn = 1;
		bad_count = ++no_memory;
		(void) strcpy(rcbuf, "no_memory");
		break;
	case AUDITD_INVALID:	/* invalid */
		warn = 1;
		bad_count = ++invalid;
		(void) strcpy(rcbuf, "invalid");
		break;
	case AUDITD_RETRY:
		warn = 1;
		bad_count = ++retry;
		(void) strcpy(rcbuf, "retry");
		break;
	case AUDITD_COMM_FAIL:	/* comm_fail */
		(void) strcpy(rcbuf, "comm_fail");
		break;
	case AUDITD_FATAL:	/* failure */
		warn = 1;
		bad_count = ++fail;
		(void) strcpy(rcbuf, "failure");
		break;
	default:
		(void) strcpy(rcbuf, "error");
		break;
	}
	DPRINT((dbfp, "report_error(%d - %s): %s\n\t%s\n",
	    bad_count, name, rcbuf, error_text));
	if (warn)
		__audit_dowarn2("plugin", name, rcbuf, error_text, bad_count);
	else {
		(void) snprintf(message, FATAL_MESSAGE_LEN,
		    gettext("audit plugin %s reported error = \"%s\": %s\n"),
		    name, rcbuf, error_text);
		warn_or_fatal(0, message);
	}
}

static size_t
getlen(char *buf)
{
	adr_t		adr;
	char		tokenid;
	uint32_t	len;

	adr.adr_now = buf;
	adr.adr_stream = buf;

	adrm_char(&adr, &tokenid, 1);
	if ((tokenid == AUT_OHEADER) || (tokenid == AUT_HEADER32) ||
	    (tokenid == AUT_HEADER32_EX) || (tokenid == AUT_HEADER64) ||
	    (tokenid == AUT_HEADER64_EX)) {
		adrm_u_int32(&adr, &len, 1);

		return (len);
	}
	DPRINT((dbfp, "getlen() is not looking at a header token\n"));

	return (0);
}

/*
 * load_function - call dlsym() to resolve the function address
 */
static int
load_function(plugin_t *p, char *name, auditd_rc_t (**func)())
{
	*func = (auditd_rc_t (*)())dlsym(p->plg_dlptr, name);
	if (*func == NULL) {
		char message[FATAL_MESSAGE_LEN];
		char *errmsg = dlerror();

		(void) snprintf(message, FATAL_MESSAGE_LEN,
		    gettext("dlsym failed %s: error %s"),
		    name, errmsg != NULL ? errmsg : gettext("Unknown error\n"));

		warn_or_fatal(0, message);
		return (-1);
	}
	return (0);
}

/*
 * load the auditd plug in
 */
static int
load_plugin(plugin_t *p)
{
	struct stat64	stat;
	int		fd;
	int		fail = 0;

	/*
	 * Stat the file so we can check modes and ownerships
	 */
	if ((fd = open(p->plg_path, O_NONBLOCK | O_RDONLY)) != -1) {
		if ((fstat64(fd, &stat) == -1) || (!S_ISREG(stat.st_mode)))
			fail = 1;
	} else
		fail = 1;
	if (fail) {
		char message[FATAL_MESSAGE_LEN];

		(void) snprintf(message, FATAL_MESSAGE_LEN,
		    gettext("auditd plugin: stat(%s) failed: %s\n"),
		    p->plg_path, strerror(errno));

		warn_or_fatal(0, message);
		return (-1);
	}
	/*
	 * Check the ownership of the file
	 */
	if (stat.st_uid != (uid_t)0) {
		char message[FATAL_MESSAGE_LEN];

		(void) snprintf(message, FATAL_MESSAGE_LEN,
		    gettext(
		    "auditd plugin: Owner of the module %s is not root\n"),
		    p->plg_path);

		warn_or_fatal(0, message);
		return (-1);
	}
	/*
	 * Check the modes on the file
	 */
	if (stat.st_mode&S_IWGRP) {
		char message[FATAL_MESSAGE_LEN];

		(void) snprintf(message, FATAL_MESSAGE_LEN,
		    gettext("auditd plugin: module %s writable by group\n"),
		    p->plg_path);

		warn_or_fatal(0, message);
		return (-1);
	}
	if (stat.st_mode&S_IWOTH) {
		char message[FATAL_MESSAGE_LEN];

		(void) snprintf(message, FATAL_MESSAGE_LEN,
		    gettext("auditd plugin: module %s writable by world\n"),
		    p->plg_path);

		warn_or_fatal(0, message);
		return (-1);
	}
	/*
	 * Open the plugin
	 */
	p->plg_dlptr = dlopen(p->plg_path, RTLD_LAZY);

	if (p->plg_dlptr == NULL) {
		char message[FATAL_MESSAGE_LEN];
		char *errmsg = dlerror();

		(void) snprintf(message, FATAL_MESSAGE_LEN,
		    gettext("plugin load %s failed: %s\n"),
		    p->plg_path, errmsg != NULL ? errmsg :
		    gettext("Unknown error\n"));

		warn_or_fatal(0, message);
		return (-1);
	}
	if (load_function(p, "auditd_plugin", &(p->plg_fplugin)))
		return (-1);

	if (load_function(p, "auditd_plugin_open", &(p->plg_fplugin_open)))
		return (-1);

	if (load_function(p, "auditd_plugin_close", &(p->plg_fplugin_close)))
		return (-1);

	return (0);
}

/*
 * unload_plugin() unlinks and frees the plugin_t structure after
 * freeing buffers and structures that hang off it.  It also dlcloses
 * the referenced plugin.  The return is the next entry, which may be NULL
 *
 * hold plugin_mutex for this call
 */
static plugin_t *
unload_plugin(plugin_t *p)
{
	plugin_t	*q, **r;

	assert(pthread_mutex_trylock(&plugin_mutex) != 0);

	DPRINT((dbfp, "unload_plugin: removing %s\n", p->plg_path));

	_kva_free(p->plg_kvlist);	/* _kva_free accepts NULL */
	qpool_close(p);		/* qpool_close accepts NULL pool, queue */
	DPRINT((dbfp, "unload_plugin: %s structure removed\n", p->plg_path));

	(void) dlclose(p->plg_dlptr);

	DPRINT((dbfp, "unload_plugin: %s dlclosed\n", p->plg_path));
	free(p->plg_path);

	(void) pthread_mutex_destroy(&(p->plg_mutex));
	(void) pthread_cond_destroy(&(p->plg_cv));

	q = plugin_head;
	r = &plugin_head;
	while (q != NULL) {
		if (q == p) {
			*r = p->plg_next;
			free(p);
			break;
		}
		r = &(q->plg_next);
		q = q->plg_next;
	}
	return (*r);
}

/*
 * process return values from plugin_open
 *
 * presently no attribute is defined.
 */
/* ARGSUSED */
static void
open_return(plugin_t *p, char *attrval)
{
}

/*
 * auditd_thread_init
 *	- create threads
 *	- load plugins
 *
 * auditd_thread_init is called at auditd startup with an initial list
 * of plugins and again each time audit catches a SIGHUP or SIGUSR1.
 */
int
auditd_thread_init()
{
	int		threshold;
	auditd_rc_t	rc;
	plugin_t	*p;
	char		*open_params;
	char		*error_string;
	int		plugin_count = 0;
	static int	threads_ready = 0;

	if (!threads_ready) {
		struct sched_param	param;
#if DEBUG
		dbfp = __auditd_debug_file_open();
#endif
		doorfd = door_create((void(*)())input, 0,
		    DOOR_REFUSE_DESC | DOOR_NO_CANCEL);
		if (doorfd < 0)
			return (1);	/* can't create door -> fatal */

		param.sched_priority = BASE_PRIORITY;
		(void) pthread_setschedparam(pthread_self(), SCHED_OTHER,
		    &param);

		/* input door server */
		(void) pthread_mutex_init(&(in_thr.thd_mutex), NULL);
		(void) pthread_cond_init(&(in_thr.thd_cv), NULL);
		in_thr.thd_waiting = 0;

		bpool_init();
	}
	p = plugin_head;
	while (p != NULL) {
		if (p->plg_removed) {
			DPRINT((dbfp, "start removing %s\n", p->plg_path));
			/* tell process(p) to exit and dlclose */
			(void) pthread_cond_signal(&(p->plg_cv));
		} else if (!p->plg_initialized) {
			DPRINT((dbfp, "start initial load of %s\n",
			    p->plg_path));
			if (load_plugin(p)) {
				report_error(INTERNAL_LOAD_ERROR,
				    gettext("dynamic load failed"),
				    p->plg_path);
				p = unload_plugin(p);
				continue;
			}
			open_params = NULL;
			error_string = NULL;
			if ((rc = p->plg_fplugin_open(
			    p->plg_kvlist,
			    &open_params, &error_string)) != AUDITD_SUCCESS) {
				report_error(rc, error_string, p->plg_path);
				free(error_string);
				p = unload_plugin(p);
				continue;
			}
			open_return(p, open_params);
			p->plg_reopen = 0;

			threshold = ((p->plg_qmax * THRESHOLD_PCT) + 99) / 100;
			p->plg_qmin = INPUT_MIN;

			DPRINT((dbfp,
			    "calling qpool_init for %s with qmax=%d\n",
			    p->plg_path, p->plg_qmax));

			qpool_init(p, threshold);
			audit_queue_init(&(p->plg_queue));
			p->plg_initialized = 1;

			(void) pthread_mutex_init(&(p->plg_mutex), NULL);
			(void) pthread_cond_init(&(p->plg_cv), NULL);
			p->plg_waiting = 0;

			if (pthread_create(&(p->plg_tid), NULL,
			    (void *(*)(void *))process, p)) {
				report_error(INTERNAL_SYS_ERROR,
				    gettext("thread creation failed"),
				    p->plg_path);
				p = unload_plugin(p);
				continue;
			}
		} else if (p->plg_reopen) {
			DPRINT((dbfp, "reopen %s\n", p->plg_path));
			error_string = NULL;
			if ((rc = p->plg_fplugin_open(p->plg_kvlist,
			    &open_params, &error_string)) != AUDITD_SUCCESS) {
				report_error(rc, error_string, p->plg_path);
				free(error_string);
				p = unload_plugin(p);
				continue;
			}
			open_return(p, open_params);
			p->plg_reopen = 0;

			DPRINT((dbfp, "%s qmax=%d\n",
			    p->plg_path, p->plg_qmax));

		}
		p->plg_q_threshold = ((p->plg_qmax * THRESHOLD_PCT) + 99) / 100;

		p = p->plg_next;
		plugin_count++;
	}
	if (plugin_count == 0) {
		report_error(INTERNAL_CONFIG_ERROR,
		    gettext("No plugins are configured"), NULL);
		return (-1);
	}
	if (!threads_ready) {
		/* unleash the kernel */
		rc = auditdoor(doorfd);

		DPRINT((dbfp, "%d returned from auditdoor.\n",
		    rc));
		if (rc != 0)
			return (1);	/* fatal */

		threads_ready = 1;
	}
	return (0);
}

/*
 * Door invocations that are in progress during a
 * door_revoke() invocation are allowed to complete normally.
 * -- man page for door_revoke()
 */
void
auditd_thread_close()
{
	if (doorfd == -1)
		return;
	(void) door_revoke(doorfd);
	doorfd = -1;
}

/*
 * qpool_init() sets up pool for queue entries (audit_q_t)
 *
 */
static void
qpool_init(plugin_t *p, int threshold)
{
	int		i;
	audit_q_t	*node;

	audit_queue_init(&(p->plg_pool));

	DPRINT((dbfp, "qpool_init(%d) max, min, threshhold = %d, %d, %d\n",
	    p->plg_tid, p->plg_qmax, p->plg_qmin, threshold));

	if (p->plg_qmax > largest_queue)
		largest_queue = p->plg_qmax;

	p->plg_q_threshold = threshold;

	for (i = 0; i < p->plg_qmin; i++) {
		node = malloc(sizeof (audit_q_t));
		if (node == NULL)
			warn_or_fatal(1, gettext("no memory\n"));
			/* doesn't return */

		audit_enqueue(&p->plg_pool, node);
	}
}

/*
 * bpool_init() sets up pool and queue for record entries (audit_rec_t)
 *
 */
static void
bpool_init()
{
	int		i;
	audit_rec_t	*node;

	audit_queue_init(&b_pool);
	(void) pthread_mutex_init(&b_alloc_lock, NULL);
	(void) pthread_mutex_init(&b_refcnt_lock, NULL);

	for (i = 0; i < INPUT_MIN; i++) {
		node = malloc(AUDIT_REC_HEADER + DEFAULT_BUF_SZ);
		if (node == NULL)
			warn_or_fatal(1, gettext("no memory\n"));
			/* doesn't return */

		node->abq_buf_len = DEFAULT_BUF_SZ;

		node->abq_data_len = 0;
		audit_enqueue(&b_pool, node);
		(void) pthread_mutex_lock(&b_alloc_lock);
		b_allocated++;
		(void) pthread_mutex_unlock(&b_alloc_lock);
	}
}

/*
 * qpool_close() discard queue and pool for a discontinued plugin
 *
 * there is no corresponding bpool_close() since it would only
 * be called as auditd is going down.
 */
static void
qpool_close(plugin_t *p)
{
	audit_q_t	*q_node;
	audit_rec_t	*b_node;

	if (!p->plg_initialized)
		return;

	while (audit_dequeue(&(p->plg_pool), (void *)&q_node) == 0) {
		free(q_node);
	}
	audit_queue_destroy(&(p->plg_pool));

	while (audit_dequeue(&(p->plg_queue), (void *)&q_node) == 0) {
		b_node = audit_release(&b_refcnt_lock, q_node->aqq_data);
		if (b_node != NULL)
			audit_enqueue(&b_pool, b_node);
		free(q_node);
	}
	audit_queue_destroy(&(p->plg_queue));
}

/*
 * qpool_withdraw
 */
static audit_q_t *
qpool_withdraw(plugin_t *p)
{
	audit_q_t	*node;
	int		rc;

	/* get a buffer from the pool, if any */
	rc = audit_dequeue(&(p->plg_pool), (void *)&node);
	if (rc == 0)
		return (node);

	/*
	 * the pool is empty: allocate a new element
	 */
	node = malloc(sizeof (audit_q_t));

	if (node == NULL)
		warn_or_fatal(1, gettext("no memory\n"));
		/* doesn't return */

	return (node);
}

/*
 * bpool_withdraw -- gets a buffer and fills it
 *
 */
static audit_rec_t *
bpool_withdraw(char *buffer, size_t buff_size, size_t request_size)
{
	audit_rec_t	*node;
	int		rc;
	size_t		new_length;

	new_length = (request_size > DEFAULT_BUF_SZ) ?
	    request_size : DEFAULT_BUF_SZ;

	/* get a buffer from the pool, if any */
	rc = audit_dequeue(&b_pool, (void *)&node);

	DPRINT((dbfp, "bpool_withdraw buf length=%d,"
	    " requested size=%d, dequeue rc=%d\n",
	    new_length, request_size, rc));

	if (rc == 0) {
		DPRINT((dbfp, "bpool_withdraw node=%p (pool=%d)\n",
		    (void *)node, audit_queue_size(&b_pool)));

		if (new_length > node->abq_buf_len) {
			node = realloc(node, AUDIT_REC_HEADER + new_length);
			if (node == NULL)
				warn_or_fatal(1, gettext("no memory\n"));
				/* no return */
		}
	} else {
		/*
		 * the pool is empty: allocate a new element
		 */
		(void) pthread_mutex_lock(&b_alloc_lock);
		if (b_allocated >= largest_queue) {
			(void) pthread_mutex_unlock(&b_alloc_lock);
			DPRINT((dbfp, "bpool_withdraw is over max (pool=%d)\n",
			    audit_queue_size(&b_pool)));
			return (NULL);
		}
		(void) pthread_mutex_unlock(&b_alloc_lock);

		node = malloc(AUDIT_REC_HEADER + new_length);

		if (node == NULL)
			warn_or_fatal(1, gettext("no memory\n"));
		/* no return */

		(void) pthread_mutex_lock(&b_alloc_lock);
		b_allocated++;
		(void) pthread_mutex_unlock(&b_alloc_lock);
		DPRINT((dbfp, "bpool_withdraw node=%p (alloc=%d, pool=%d)\n",
		    (void *)node, b_allocated, audit_queue_size(&b_pool)));
	}
	assert(request_size <= new_length);

	(void) memcpy(node->abq_buffer, buffer, buff_size);
	node->abq_data_len = buff_size;
	node->abq_buf_len = new_length;
	node->abq_ref_count = 0;

	return (node);
}

/*
 * qpool_return() moves queue nodes back to the pool queue.
 *
 * if the pool is over max, the node is discarded instead.
 */
static void
qpool_return(plugin_t *p, audit_q_t *node)
{
	int	qpool_size;
	int	q_size;

#if DEBUG
	uint64_t	sequence = node->aqq_sequence;
#endif
	qpool_size = audit_queue_size(&(p->plg_pool));
	q_size = audit_queue_size(&(p->plg_queue));

	if (qpool_size + q_size > p->plg_qmax)
		free(node);
	else
		audit_enqueue(&(p->plg_pool), node);

	DPRINT((dbfp,
	    "qpool_return(%d):  seq=%llu, q size=%d,"
	    " pool size=%d (total alloc=%d), threshhold=%d\n",
	    p->plg_tid, sequence, q_size, qpool_size,
	    q_size + qpool_size, p->plg_q_threshold));
}

/*
 * bpool_return() moves queue nodes back to the pool queue.
 */
static void
bpool_return(audit_rec_t *node)
{
#if DEBUG
	audit_rec_t	*copy = node;
#endif
	node = audit_release(&b_refcnt_lock, node); 	/* decrement ref cnt */

	if (node != NULL) {	/* NULL if ref cnt is not zero */
		audit_enqueue(&b_pool, node);
		DPRINT((dbfp,
		    "bpool_return: requeue %p (allocated=%d,"
		    " pool size=%d)\n", (void *)node, b_allocated,
		    audit_queue_size(&b_pool)));
	}
#if DEBUG
	else {
		DPRINT((dbfp,
		    "bpool_return: decrement count for %p (allocated=%d,"
		    " pool size=%d)\n", (void *)copy, b_allocated,
		    audit_queue_size(&b_pool)));
	}
#endif
}

#if DEBUG
static void
dump_state(char *src, plugin_t *p, uint64_t count, char *msg)
{
	struct sched_param	param;
	int			policy;
/*
 * count is message sequence
 */
	(void) pthread_getschedparam(p->plg_tid, &policy, &param);
	(void) fprintf(dbfp, "%7s(%d/%llu) %11s:"
	    " input_in_wait=%d"
	    " priority=%d"
	    " queue size=%d pool size=%d"
	    "\n\t"
	    "process wait=%d"
	    " tossed=%d"
	    " queued=%d"
	    " written=%d"
	    "\n",
	    src, p->plg_tid, count, msg,
	    in_thr.thd_waiting, param.sched_priority,
	    audit_queue_size(&(p->plg_queue)),
	    audit_queue_size(&(p->plg_pool)),
	    p->plg_waiting, p->plg_tossed,
	    p->plg_queued, p->plg_output);

	(void) fflush(dbfp);
}
#endif

/*
 * policy_is_block: return 1 if the continue policy is off for any active
 * plugin, else 0
 */
static int
policy_is_block()
{
	plugin_t *p;

	(void) pthread_mutex_lock(&plugin_mutex);
	p = plugin_head;

	while (p != NULL) {
		if (p->plg_cnt == 0) {
			(void) pthread_mutex_unlock(&plugin_mutex);
			DPRINT((dbfp,
			    "policy_is_block:  policy is to block\n"));
			return (1);
		}
		p = p->plg_next;
	}
	(void) pthread_mutex_unlock(&plugin_mutex);
	DPRINT((dbfp, "policy_is_block:  policy is to continue\n"));
	return (0);
}

/*
 * policy_update() -- the kernel has received a policy change.
 * Presently, the only policy auditd cares about is AUDIT_CNT
 */
static void
policy_update(uint32_t newpolicy)
{
	plugin_t *p;

	DPRINT((dbfp, "policy change: %X\n", newpolicy));
	(void) pthread_mutex_lock(&plugin_mutex);
	p = plugin_head;
	while (p != NULL) {
		p->plg_cnt = (newpolicy & AUDIT_CNT) ? 1 : 0;
		(void) pthread_cond_signal(&(p->plg_cv));

		DPRINT((dbfp, "policy changed for thread %d\n", p->plg_tid));
		p = p->plg_next;
	}
	(void) pthread_mutex_unlock(&plugin_mutex);
}

/*
 * queue_buffer() inputs a buffer and queues for each active plugin if
 * it represents a complete audit record.  Otherwise it builds a
 * larger buffer to hold the record and take successive buffers from
 * c2audit to build a complete record; then queues it for each plugin.
 *
 * return 0 if data is queued (or damaged and tossed).  If resources
 * are not available, return 0 if all active plugins have the cnt
 * policy set, else 1.  0 is also returned if the input is a control
 * message.  (aub_buf is aligned on a 64 bit boundary, so casting
 * it to an integer works just fine.)
 */
static int
queue_buffer(au_dbuf_t *kl)
{
	plugin_t	*p;
	audit_rec_t	*b_copy;
	audit_q_t	*q_copy;
	boolean_t	referenced = 0;
	static char	*invalid_msg = "invalid audit record discarded";
	static char	*invalid_control = "invalid audit control discarded";

	static audit_rec_t	*alt_b_copy = NULL;
	static size_t		alt_length;
	static size_t		alt_offset;

	/*
	 * the buffer may be a kernel -> auditd message.  (only
	 * the policy change message exists so far.)
	 */

	if ((kl->aub_type & AU_DBUF_NOTIFY) != 0) {
		uint32_t	control;

		control = kl->aub_type & ~AU_DBUF_NOTIFY;
		switch (control) {
		case AU_DBUF_POLICY:
			/* LINTED */
			policy_update(*(uint32_t *)kl->aub_buf);
			break;
		case AU_DBUF_SHUTDOWN:
			(void) kill(getpid(), SIGTERM);
			DPRINT((dbfp, "AU_DBUF_SHUTDOWN message\n"));
			break;
		default:
			warn_or_fatal(0, gettext(invalid_control));
			break;
		}
		return (0);
	}
	/*
	 * The test for valid continuation/completion may fail. Need to
	 * assume the failure was earlier and that this buffer may
	 * be a valid first or complete buffer after discarding the
	 * incomplete record
	 */

	if (alt_b_copy != NULL) {
		if ((kl->aub_type == AU_DBUF_FIRST) ||
		    (kl->aub_type == AU_DBUF_COMPLETE)) {
			DPRINT((dbfp, "copy is not null, partial is %d\n",
			    kl->aub_type));
			bpool_return(alt_b_copy);
			warn_or_fatal(0, gettext(invalid_msg));
			alt_b_copy = NULL;
		}
	}
	if (alt_b_copy != NULL) { /* continue collecting a long record */
		if (kl->aub_size + alt_offset > alt_length) {
			bpool_return(alt_b_copy);
			alt_b_copy = NULL;
			warn_or_fatal(0, gettext(invalid_msg));
			return (0);
		}
		(void) memcpy(alt_b_copy->abq_buffer + alt_offset, kl->aub_buf,
		    kl->aub_size);
		alt_offset += kl->aub_size;
		if (kl->aub_type == AU_DBUF_MIDDLE)
			return (0);
		b_copy = alt_b_copy;
		alt_b_copy = NULL;
		b_copy->abq_data_len = alt_length;
	} else if (kl->aub_type == AU_DBUF_FIRST) {
		/* first buffer of a multiple buffer record */
		alt_length = getlen(kl->aub_buf);
		if ((alt_length < MIN_RECORD_SIZE) ||
		    (alt_length <= kl->aub_size)) {
			warn_or_fatal(0, gettext(invalid_msg));
			return (0);
		}
		alt_b_copy = bpool_withdraw(kl->aub_buf, kl->aub_size,
		    alt_length);

		if (alt_b_copy == NULL)
			return (policy_is_block());

		alt_offset = kl->aub_size;
		return (0);
	} else { /* one buffer, one record -- the basic case */
		if (kl->aub_type != AU_DBUF_COMPLETE) {
			DPRINT((dbfp, "copy is null, partial is %d\n",
			    kl->aub_type));
			warn_or_fatal(0, gettext(invalid_msg));
			return (0);	/* tossed */
		}
		b_copy = bpool_withdraw(kl->aub_buf, kl->aub_size,
		    kl->aub_size);

		if (b_copy == NULL)
			return (policy_is_block());
	}

	(void) pthread_mutex_lock(&plugin_mutex);
	p = plugin_head;
	while (p != NULL) {
		if (!p->plg_removed) {
			/*
			 * Link the record buffer to the input queues.
			 * To avoid a race, it is necessary to wait
			 * until all reference count increments
			 * are complete before queueing q_copy.
			 */
			audit_incr_ref(&b_refcnt_lock, b_copy);

			q_copy = qpool_withdraw(p);
			q_copy->aqq_sequence = p->plg_sequence++;
			q_copy->aqq_data = b_copy;

			p->plg_save_q_copy = q_copy;	/* enqueue below */
			referenced = 1;
		} else
			p->plg_save_q_copy = NULL;
		p = p->plg_next;
	}
	/*
	 * now that the reference count is updated, queue it.
	 */
	if (referenced) {
		p = plugin_head;
		while ((p != NULL) && (p->plg_save_q_copy != NULL)) {
			audit_enqueue(&(p->plg_queue), p->plg_save_q_copy);
			(void) pthread_cond_signal(&(p->plg_cv));
			p->plg_queued++;
			p = p->plg_next;
		}
	} else
		bpool_return(b_copy);

	(void) pthread_mutex_unlock(&plugin_mutex);

	return (0);
}

/*
 * wait_a_while() -- timed wait in the door server to allow output
 * time to catch up.
 */
static void
wait_a_while()
{
	struct timespec delay = {0, 500000000};	/* 1/2 second */;

	(void) pthread_mutex_lock(&(in_thr.thd_mutex));
	in_thr.thd_waiting = 1;
	(void) pthread_cond_reltimedwait_np(&(in_thr.thd_cv),
	    &(in_thr.thd_mutex), &delay);
	in_thr.thd_waiting = 0;
	(void) pthread_mutex_unlock(&(in_thr.thd_mutex));
}

/*
 * adjust_priority() -- check queue and pools and adjust the priority
 * for process() accordingly.  If we're way ahead of output, do a
 * timed wait as well.
 */
static void
adjust_priority()
{
	int		queue_near_full;
	plugin_t	*p;
	int		queue_size;
	struct sched_param	param;

	queue_near_full = 0;
	(void) pthread_mutex_lock(&plugin_mutex);
	p = plugin_head;
	while (p != NULL) {
		queue_size = audit_queue_size(&(p->plg_queue));
		if (queue_size > p->plg_q_threshold) {
			if (p->plg_priority != HIGH_PRIORITY) {
				p->plg_priority =
				    param.sched_priority =
				    HIGH_PRIORITY;
				(void) pthread_setschedparam(p->plg_tid,
				    SCHED_OTHER, &param);
			}
			if (queue_size > p->plg_qmax - p->plg_qmin) {
				queue_near_full = 1;
				break;
			}
		}
		p = p->plg_next;
	}
	(void) pthread_mutex_unlock(&plugin_mutex);

	if (queue_near_full) {
		DPRINT((dbfp,
		    "adjust_priority:  input taking a short break\n"));
		wait_a_while();
		DPRINT((dbfp,
		    "adjust_priority:  input back from my break\n"));
	}
}

/*
 * input() is a door server; it blocks if any plugins have full queues
 * with the continue policy off. (auditconfig -setpolicy -cnt)
 *
 * input() is called synchronously from c2audit and is NOT
 * reentrant due to the (unprotected) static variables in
 * queue_buffer().  If multiple clients are created, a context
 * structure will be required for queue_buffer.
 *
 * timedwait is used when input() gets too far ahead of process();
 * the wait terminates either when the set time expires or when
 * process() signals that it has nearly caught up.
 */
/* ARGSUSED */
static void
input(void *cookie, void *argp, int arg_size, door_desc_t *dp,
    int n_descriptors)
{
	int		is_blocked;
	plugin_t	*p;
#if DEBUG
	int		loop_count = 0;
	static int	call_counter = 0;
#endif
	if (argp == NULL) {
		warn_or_fatal(0,
		    gettext("invalid data received from c2audit\n"));
		goto input_exit;
	}
	DPRINT((dbfp, "%d input new buffer: length=%u, "
	    "partial=%u, arg_size=%d\n",
	    ++call_counter, ((au_dbuf_t *)argp)->aub_size,
	    ((au_dbuf_t *)argp)->aub_type, arg_size));

	if (((au_dbuf_t *)argp)->aub_size < 1) {
		warn_or_fatal(0,
		    gettext("invalid data length received from c2audit\n"));
		goto input_exit;
	}
	/*
	 * is_blocked is true only if one or more plugins have "no
	 * continue" (-cnt) set and one of those has a full queue.
	 * All plugins block until success is met.
	 */
	for (;;) {
		DPRINT((dbfp, "%d input is calling queue_buffer\n",
		    call_counter));

		is_blocked = queue_buffer((au_dbuf_t *)argp);

		if (!is_blocked) {
			adjust_priority();
			break;
		} else {
			DPRINT((dbfp,
			    "%d input blocked (loop=%d)\n",
			    call_counter, loop_count));

			wait_a_while();

			DPRINT((dbfp, "%d input unblocked (loop=%d)\n",
			    call_counter, loop_count));
		}
#if DEBUG
		loop_count++;
#endif
	}
input_exit:
	p = plugin_head;
	while (p != NULL) {
		(void) pthread_cond_signal(&(p->plg_cv));
		p = p->plg_next;
	}
	((au_dbuf_t *)argp)->aub_size = 0;	/* return code */
	(void) door_return(argp, sizeof (uint64_t), NULL, 0);
}

/*
 * process() -- pass a buffer to a plugin
 */
static void
process(plugin_t *p)
{
	int			rc;
	audit_rec_t		*b_node;
	audit_q_t		*q_node;
	auditd_rc_t		plugrc;
	char			*error_string;
	struct timespec 	delay;
	int			sendsignal;
	int			queue_len;
	struct sched_param	param;
	static boolean_t	once = B_FALSE;

	DPRINT((dbfp, "%s is thread %d\n", p->plg_path, p->plg_tid));
	p->plg_priority = param.sched_priority = BASE_PRIORITY;
	(void) pthread_setschedparam(p->plg_tid, SCHED_OTHER, &param);

	delay.tv_nsec = 0;

	for (;;) {
		while (audit_dequeue(&(p->plg_queue), (void *)&q_node) != 0) {
			DUMP("process", p, p->plg_last_seq_out, "blocked");
			(void) pthread_cond_signal(&(in_thr.thd_cv));

			(void) pthread_mutex_lock(&(p->plg_mutex));
			p->plg_waiting++;
			(void) pthread_cond_wait(&(p->plg_cv),
			    &(p->plg_mutex));
			p->plg_waiting--;
			(void) pthread_mutex_unlock(&(p->plg_mutex));

			if (p->plg_removed)
				goto plugin_removed;

			DUMP("process", p, p->plg_last_seq_out, "unblocked");
		}
#if DEBUG
		if (q_node->aqq_sequence != p->plg_last_seq_out + 1)
			(void) fprintf(dbfp,
			    "process(%d): buffer sequence=%llu but prev=%llu\n",
			    p->plg_tid, q_node->aqq_sequence,
			    p->plg_last_seq_out);
#endif
		error_string = NULL;

		b_node = q_node->aqq_data;
retry_mode:
		plugrc = p->plg_fplugin(b_node->abq_buffer,
		    b_node->abq_data_len, q_node->aqq_sequence, &error_string);

		if (p->plg_removed)
			goto plugin_removed;
#if DEBUG
		p->plg_last_seq_out = q_node->aqq_sequence;
#endif
		switch (plugrc) {
		case AUDITD_RETRY:
			if (!once) {
				report_error(plugrc, error_string, p->plg_path);
				once = B_TRUE;
			}
			free(error_string);
			error_string = NULL;

			DPRINT((dbfp, "process(%d) AUDITD_RETRY returned."
			    " cnt=%d (if 1, enter retry)\n",
			    p->plg_tid, p->plg_cnt));

			if (p->plg_cnt)	/* if cnt is on, lose the buffer */
				break;

			delay.tv_sec = p->plg_retry_time;
			(void) pthread_mutex_lock(&(p->plg_mutex));
			p->plg_waiting++;
			(void) pthread_cond_reltimedwait_np(&(p->plg_cv),
			    &(p->plg_mutex), &delay);
			p->plg_waiting--;
			(void) pthread_mutex_unlock(&(p->plg_mutex));

			DPRINT((dbfp, "left retry mode for %d\n", p->plg_tid));
			goto retry_mode;

		case AUDITD_SUCCESS:
			p->plg_output++;
			once = B_FALSE;
			break;
		default:
			report_error(plugrc, error_string, p->plg_path);
			free(error_string);
			error_string = NULL;
			break;
		}	/* end switch */
		bpool_return(b_node);
		qpool_return(p, q_node);

		sendsignal = 0;
		queue_len = audit_queue_size(&(p->plg_queue));

		(void) pthread_mutex_lock(&(in_thr.thd_mutex));
		if (in_thr.thd_waiting && (queue_len > p->plg_qmin) &&
		    (queue_len < p->plg_q_threshold))
			sendsignal = 1;

		(void) pthread_mutex_unlock(&(in_thr.thd_mutex));

		if (sendsignal) {
			(void) pthread_cond_signal(&(in_thr.thd_cv));
			/*
			 * sched_yield(); does not help
			 * performance and in artificial tests
			 * (high sustained volume) appears to
			 * hurt by adding wide variability in
			 * the results.
			 */
		} else if ((p->plg_priority < BASE_PRIORITY) &&
		    (queue_len < p->plg_q_threshold)) {
			p->plg_priority = param.sched_priority =
			    BASE_PRIORITY;
			(void) pthread_setschedparam(p->plg_tid, SCHED_OTHER,
			    &param);
		}
	}	/* end for (;;) */
plugin_removed:
	DUMP("process", p, p->plg_last_seq_out, "exit");
	error_string = NULL;
	if ((rc = p->plg_fplugin_close(&error_string)) !=
	    AUDITD_SUCCESS)
		report_error(rc, error_string, p->plg_path);

	free(error_string);

	(void) pthread_mutex_lock(&plugin_mutex);
	(void) unload_plugin(p);
	(void) pthread_mutex_unlock(&plugin_mutex);
}
