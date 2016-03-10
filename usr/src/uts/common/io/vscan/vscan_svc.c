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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/time.h>
#include <sys/varargs.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/vnode.h>
#include <fs/fs_subr.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/disp.h>
#include <sys/sdt.h>
#include <sys/cred.h>
#include <sys/list.h>
#include <sys/vscan.h>
#include <sys/sysmacros.h>

#define	VS_REQ_MAGIC		0x52515354 /* 'RQST' */

#define	VS_REQS_DEFAULT		20000	/* pending scan requests - reql */
#define	VS_NODES_DEFAULT	128	/* concurrent file scans */
#define	VS_WORKERS_DEFAULT	32	/* worker threads */
#define	VS_SCANWAIT_DEFAULT	15*60	/* seconds to wait for scan result */
#define	VS_REQL_HANDLER_TIMEOUT	30
#define	VS_EXT_RECURSE_DEPTH	8

/* access derived from scan result (VS_STATUS_XXX) and file attributes */
#define	VS_ACCESS_UNDEFINED	0
#define	VS_ACCESS_ALLOW		1	/* return 0 */
#define	VS_ACCESS_DENY		2	/* return EACCES */

#define	tolower(C)	(((C) >= 'A' && (C) <= 'Z') ? (C) - 'A' + 'a' : (C))

/* global variables - tunable via /etc/system */
uint32_t vs_reqs_max = VS_REQS_DEFAULT;	/* max scan requests */
uint32_t vs_nodes_max = VS_NODES_DEFAULT; /* max in-progress scan requests */
uint32_t vs_workers = VS_WORKERS_DEFAULT; /* max workers send reqs to vscand */
uint32_t vs_scan_wait = VS_SCANWAIT_DEFAULT; /* secs to wait for scan result */


/*
 * vscan_svc_state
 *
 *   +-----------------+
 *   | VS_SVC_UNCONFIG |
 *   +-----------------+
 *      |           ^
 *      | svc_init  | svc_fini
 *      v           |
 *   +-----------------+
 *   | VS_SVC_IDLE     |<----|
 *   +-----------------+	 |
 *      |                    |
 *      | svc_enable         |
 *      |<----------------|  |
 *      v                 |  |
 *   +-----------------+  |  |
 *   | VS_SVC_ENABLED  |--|  |
 *   +-----------------+     |
 *      |                    |
 *      | svc_disable        | handler thread exit,
 *      v                    | all requests complete
 *   +-----------------+	 |
 *   | VS_SVC_DISABLED |-----|
 *   +-----------------+
 *
 * svc_enable may occur when we are already in the ENABLED
 * state if vscand has exited without clean shutdown and
 * then reconnected within the delayed disable time period
 * (vs_reconnect_timeout) - see vscan_drv
 */

typedef enum {
	VS_SVC_UNCONFIG,
	VS_SVC_IDLE,
	VS_SVC_ENABLED, /* service enabled and registered */
	VS_SVC_DISABLED /* service disabled and nunregistered */
} vscan_svc_state_t;
static vscan_svc_state_t vscan_svc_state = VS_SVC_UNCONFIG;


/*
 * vscan_svc_req_state
 *
 * When a scan request is received from the file system it is
 * identified in or inserted into the vscan_svc_reql (INIT).
 * If the request is asynchronous 0 is then returned to the caller.
 * If the request is synchronous the req's refcnt is incremented
 * and the caller waits for the request to complete.
 * The refcnt is also incremented when the request is inserted
 * in vscan_svc_nodes, and decremented on scan_complete.
 *
 * vscan_svc_handler processes requests from the request list,
 * inserting them into vscan_svc_nodes and the task queue (QUEUED).
 * When the task queue call back (vscan_svc_do_scan) is invoked
 * the request transitions to IN_PROGRESS state. If the request
 * is sucessfully sent to vscand (door_call) and the door response
 * is SCANNING then the scan result will be received asynchronously.
 * Although unusual, it is possible that the async response is
 * received before the door call returns (hence the ASYNC_COMPLETE
 * state).
 * When the result has been determined / received,
 * vscan_svc_scan_complete is invoked to transition the request to
 * COMPLETE state, decrement refcnt and signal all waiting callers.
 * When the last waiting caller has processed the result (refcnt == 0)
 * the request is removed from vscan_svc_reql and vscan_svc_nodes
 * and deleted.
 *
 *      |                                                     ^
 *      | reql_insert                                         | refcnt == 0
 *      v                                                     | (delete)
 *   +------------------------+	                  +---------------------+
 *   | VS_SVC_REQ_INIT        | -----DISABLE----> | VS_SVC_REQ_COMPLETE |
 *   +------------------------+	                  +---------------------+
 *      |                                                     ^
 *      | insert_req, tq_dispatch                             |
 *      v                                                     |
 *   +------------------------+	                              |
 *   | VS_SVC_REQ_QUEUED      |                           scan_complete
 *   +------------------------+	                              |
 *      |                                                     |
 *      | tq_callback (do_scan)                               |
 *      |                                                     |
 *      v                        scan not req'd, error,       |
 *   +------------------------+  or door_result != SCANNING   |
 *   | VS_SVC_REQ_IN_PROGRESS |----------------->-------------|
 *   +------------------------+	                              |
 *       |         |                                          |
 *       |         | door_result == SCANNING                  |
 *       |         v                                          |
 *       |     +---------------------------+	async result  |
 *       |     | VS_SVC_REQ_SCANNING       |-------->---------|
 *       |     +---------------------------+	              |
 *       |                                                    |
 *       | async result                                       |
 *       v                                                    |
 *    +---------------------------+	 door_result = SCANNING   |
 *    | VS_SVC_REQ_ASYNC_COMPLETE |-------->------------------|
 *    +---------------------------+
 */
typedef enum {
	VS_SVC_REQ_INIT,
	VS_SVC_REQ_QUEUED,
	VS_SVC_REQ_IN_PROGRESS,
	VS_SVC_REQ_SCANNING,
	VS_SVC_REQ_ASYNC_COMPLETE,
	VS_SVC_REQ_COMPLETE
} vscan_svc_req_state_t;


/*
 * vscan_svc_reql - the list of pending and in-progress scan requests
 */
typedef struct vscan_req {
	uint32_t vsr_magic;	/* VS_REQ_MAGIC */
	list_node_t vsr_lnode;
	vnode_t *vsr_vp;
	uint32_t vsr_idx;	/* vscan_svc_nodes index */
	uint32_t vsr_seqnum;	/* unigue request id */
	uint32_t vsr_refcnt;
	kcondvar_t vsr_cv;
	vscan_svc_req_state_t vsr_state;
} vscan_req_t;

static list_t vscan_svc_reql;


/*
 * vscan_svc_nodes - table of files being scanned
 *
 * The index into this table is passed in the door call to
 * vscand. vscand uses the idx to determine which minor node
 * to open to read the file data. Within the kernel driver
 * the minor device number can thus be used to identify the
 * table index to get the appropriate vnode.
 *
 * Instance 0 is reserved for the daemon/driver control
 * interface: enable/configure/disable
 */
typedef struct vscan_svc_node {
	vscan_req_t *vsn_req;
	uint8_t vsn_quarantined;
	uint8_t vsn_modified;
	uint64_t vsn_size;
	timestruc_t vsn_mtime;
	vs_scanstamp_t vsn_scanstamp;
	uint32_t vsn_result;
	uint32_t vsn_access;
} vscan_svc_node_t;

static vscan_svc_node_t *vscan_svc_nodes;
static int vscan_svc_nodes_sz;


/* vscan_svc_taskq - queue of requests waiting to be sent to vscand */
static taskq_t *vscan_svc_taskq = NULL;

/* counts of entries in vscan_svc_reql, vscan_svc_nodes & vscan_svc_taskq */
typedef struct {
	uint32_t vsc_reql;
	uint32_t vsc_node;
	uint32_t vsc_tq;
} vscan_svc_counts_t;
static vscan_svc_counts_t vscan_svc_counts;

/*
 * vscan_svc_mutex protects the data pertaining to scan requests:
 * request list - vscan_svc_reql
 * node table - vscan_svc_nodes
 */
static kmutex_t vscan_svc_mutex;

/* unique request id for vscand request/response correlation */
static uint32_t vscan_svc_seqnum = 0;

/*
 * vscan_svc_cfg_mutex protects the configuration data:
 * vscan_svc_config, vscan_svc_types
 */
static kmutex_t vscan_svc_cfg_mutex;

/* configuration data - for virus scan exemption */
static vs_config_t vscan_svc_config;
static char *vscan_svc_types[VS_TYPES_MAX];

/* thread to insert reql entries into vscan_svc_nodes & vscan_svc_taskq */
static kthread_t *vscan_svc_reql_thread;
static kcondvar_t vscan_svc_reql_cv;
static vscan_req_t *vscan_svc_reql_next; /* next pending scan request */

/* local functions */
int vscan_svc_scan_file(vnode_t *, cred_t *, int);
static void vscan_svc_taskq_callback(void *);
static int vscan_svc_exempt_file(vnode_t *, boolean_t *);
static int vscan_svc_exempt_filetype(char *);
static int vscan_svc_match_ext(char *, char *, int);
static void vscan_svc_do_scan(vscan_req_t *);
static vs_scan_req_t *vscan_svc_populate_req(int);
static void vscan_svc_process_scan_result(int);
static void vscan_svc_scan_complete(vscan_req_t *);
static void vscan_svc_delete_req(vscan_req_t *);
static int vscan_svc_insert_req(vscan_req_t *);
static void vscan_svc_remove_req(int);
static vscan_req_t *vscan_svc_reql_find(vnode_t *);
static vscan_req_t *vscan_svc_reql_insert(vnode_t *);
static void vscan_svc_reql_remove(vscan_req_t *);

static int vscan_svc_getattr(int);
static int vscan_svc_setattr(int, int);

/* thread to insert reql entries into vscan_svc_nodes & vscan_svc_taskq */
static void vscan_svc_reql_handler(void);


/*
 * vscan_svc_init
 */
int
vscan_svc_init()
{
	if (vscan_svc_state != VS_SVC_UNCONFIG) {
		DTRACE_PROBE1(vscan__svc__state__violation,
		    int, vscan_svc_state);
		return (-1);
	}

	mutex_init(&vscan_svc_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&vscan_svc_cfg_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&vscan_svc_reql_cv, NULL, CV_DEFAULT, NULL);

	vscan_svc_nodes_sz = sizeof (vscan_svc_node_t) * (vs_nodes_max + 1);
	vscan_svc_nodes = kmem_zalloc(vscan_svc_nodes_sz, KM_SLEEP);

	vscan_svc_counts.vsc_reql = 0;
	vscan_svc_counts.vsc_node = 0;
	vscan_svc_counts.vsc_tq = 0;

	vscan_svc_state = VS_SVC_IDLE;

	return (0);
}


/*
 * vscan_svc_fini
 */
void
vscan_svc_fini()
{
	if (vscan_svc_state != VS_SVC_IDLE) {
		DTRACE_PROBE1(vscan__svc__state__violation,
		    int, vscan_svc_state);
		return;
	}

	kmem_free(vscan_svc_nodes, vscan_svc_nodes_sz);

	cv_destroy(&vscan_svc_reql_cv);
	mutex_destroy(&vscan_svc_mutex);
	mutex_destroy(&vscan_svc_cfg_mutex);
	vscan_svc_state = VS_SVC_UNCONFIG;
}


/*
 * vscan_svc_enable
 */
int
vscan_svc_enable(void)
{
	mutex_enter(&vscan_svc_mutex);

	switch (vscan_svc_state) {
	case VS_SVC_ENABLED:
		/*
		 * it's possible (and okay) for vscan_svc_enable to be
		 * called when already enabled if vscand reconnects
		 * during a delayed disable
		 */
		break;
	case VS_SVC_IDLE:
		list_create(&vscan_svc_reql, sizeof (vscan_req_t),
		    offsetof(vscan_req_t, vsr_lnode));
		vscan_svc_reql_next = list_head(&vscan_svc_reql);

		vscan_svc_taskq = taskq_create("vscan_taskq", vs_workers,
		    MINCLSYSPRI, 1, INT_MAX, TASKQ_DYNAMIC);
		ASSERT(vscan_svc_taskq != NULL);

		vscan_svc_reql_thread = thread_create(NULL, 0,
		    vscan_svc_reql_handler, 0, 0, &p0, TS_RUN, MINCLSYSPRI);
		ASSERT(vscan_svc_reql_thread != NULL);

		/* ready to start processing requests */
		vscan_svc_state = VS_SVC_ENABLED;
		fs_vscan_register(vscan_svc_scan_file);
		break;
	default:
		DTRACE_PROBE1(vscan__svc__state__violation,
		    int, vscan_svc_state);
		return (-1);
	}

	mutex_exit(&vscan_svc_mutex);
	return (0);
}


/*
 * vscan_svc_disable
 *
 * Resources allocated during vscan_svc_enable are free'd by
 * the handler thread immediately prior to exiting
 */
void
vscan_svc_disable(void)
{
	mutex_enter(&vscan_svc_mutex);

	switch (vscan_svc_state) {
	case VS_SVC_ENABLED:
		fs_vscan_register(NULL);
		vscan_svc_state = VS_SVC_DISABLED;
		cv_signal(&vscan_svc_reql_cv); /* wake handler thread */
		break;
	default:
		DTRACE_PROBE1(vscan__svc__state__violation, int,
		    vscan_svc_state);
	}

	mutex_exit(&vscan_svc_mutex);
}


/*
 * vscan_svc_in_use
 */
boolean_t
vscan_svc_in_use()
{
	boolean_t in_use;

	mutex_enter(&vscan_svc_mutex);

	switch (vscan_svc_state) {
	case VS_SVC_IDLE:
	case VS_SVC_UNCONFIG:
		in_use = B_FALSE;
		break;
	default:
		in_use = B_TRUE;
		break;
	}

	mutex_exit(&vscan_svc_mutex);
	return (in_use);
}


/*
 * vscan_svc_get_vnode
 *
 * Get the file vnode indexed by idx.
 */
vnode_t *
vscan_svc_get_vnode(int idx)
{
	vnode_t *vp = NULL;

	ASSERT(idx > 0);
	ASSERT(idx <= vs_nodes_max);

	mutex_enter(&vscan_svc_mutex);
	if (vscan_svc_nodes[idx].vsn_req)
		vp = vscan_svc_nodes[idx].vsn_req->vsr_vp;
	mutex_exit(&vscan_svc_mutex);

	return (vp);
}


/*
 * vscan_svc_scan_file
 *
 * This function is the entry point for the file system to
 * request that a file be virus scanned.
 */
int
vscan_svc_scan_file(vnode_t *vp, cred_t *cr, int async)
{
	int access;
	vscan_req_t *req;
	boolean_t allow;
	clock_t timeout, time_left;

	if ((vp == NULL) || (vp->v_path == NULL) || cr == NULL)
		return (0);

	DTRACE_PROBE2(vscan__scan__file, char *, vp->v_path, int, async);

	/* check if size or type exempts file from scanning */
	if (vscan_svc_exempt_file(vp, &allow)) {
		if ((allow == B_TRUE) || (async != 0))
			return (0);

		return (EACCES);
	}

	mutex_enter(&vscan_svc_mutex);

	if (vscan_svc_state != VS_SVC_ENABLED) {
		DTRACE_PROBE1(vscan__svc__state__violation,
		    int, vscan_svc_state);
		mutex_exit(&vscan_svc_mutex);
		return (0);
	}

	/* insert (or find) request in list */
	if ((req = vscan_svc_reql_insert(vp)) == NULL) {
		mutex_exit(&vscan_svc_mutex);
		cmn_err(CE_WARN, "Virus scan request list full");
		return ((async != 0) ? 0 : EACCES);
	}

	/* asynchronous request: return 0 */
	if (async) {
		mutex_exit(&vscan_svc_mutex);
		return (0);
	}

	/* synchronous scan request: wait for result */
	++(req->vsr_refcnt);
	time_left = SEC_TO_TICK(vs_scan_wait);
	while ((time_left > 0) && (req->vsr_state != VS_SVC_REQ_COMPLETE)) {
		timeout = time_left;
		time_left = cv_reltimedwait_sig(&(req->vsr_cv),
		    &vscan_svc_mutex, timeout, TR_CLOCK_TICK);
	}

	if (time_left == -1) {
		cmn_err(CE_WARN, "Virus scan request timeout %s (%d) \n",
		    vp->v_path, req->vsr_seqnum);
		DTRACE_PROBE1(vscan__scan__timeout, vscan_req_t *, req);
	}

	ASSERT(req->vsr_magic == VS_REQ_MAGIC);
	if (vscan_svc_state == VS_SVC_DISABLED)
		access = VS_ACCESS_ALLOW;
	else if (req->vsr_idx == 0)
		access = VS_ACCESS_DENY;
	else
		access = vscan_svc_nodes[req->vsr_idx].vsn_access;

	if ((--req->vsr_refcnt) == 0)
		vscan_svc_delete_req(req);

	mutex_exit(&vscan_svc_mutex);
	return ((access == VS_ACCESS_ALLOW) ? 0 : EACCES);
}


/*
 * vscan_svc_reql_handler
 *
 * inserts scan requests (from vscan_svc_reql) into
 * vscan_svc_nodes and vscan_svc_taskq
 */
static void
vscan_svc_reql_handler(void)
{
	vscan_req_t *req, *next;

	for (;;) {
		mutex_enter(&vscan_svc_mutex);

		if ((vscan_svc_state == VS_SVC_DISABLED) &&
		    (vscan_svc_counts.vsc_reql == 0)) {
			/* free resources allocated durining enable */
			taskq_destroy(vscan_svc_taskq);
			vscan_svc_taskq = NULL;
			list_destroy(&vscan_svc_reql);
			vscan_svc_state = VS_SVC_IDLE;
			mutex_exit(&vscan_svc_mutex);
			return;
		}

		/*
		 * If disabled, scan_complete any pending requests.
		 * Otherwise insert pending requests into vscan_svc_nodes
		 * and vscan_svc_taskq. If no slots are available in
		 * vscan_svc_nodes break loop and wait for one
		 */
		req = vscan_svc_reql_next;

		while (req != NULL) {
			ASSERT(req->vsr_magic == VS_REQ_MAGIC);
			next = list_next(&vscan_svc_reql, req);

			if (vscan_svc_state == VS_SVC_DISABLED) {
				vscan_svc_scan_complete(req);
			} else {
				/* insert request into vscan_svc_nodes */
				if (vscan_svc_insert_req(req) == -1)
					break;

				/* add the scan request into the taskq */
				(void) taskq_dispatch(vscan_svc_taskq,
				    vscan_svc_taskq_callback,
				    (void *)req, TQ_SLEEP);
				++(vscan_svc_counts.vsc_tq);

				req->vsr_state = VS_SVC_REQ_QUEUED;
			}
			req = next;
		}

		vscan_svc_reql_next = req;

		DTRACE_PROBE2(vscan__req__counts, char *, "handler wait",
		    vscan_svc_counts_t *, &vscan_svc_counts);

		(void) cv_reltimedwait(&vscan_svc_reql_cv, &vscan_svc_mutex,
		    SEC_TO_TICK(VS_REQL_HANDLER_TIMEOUT), TR_CLOCK_TICK);

		DTRACE_PROBE2(vscan__req__counts, char *, "handler wake",
		    vscan_svc_counts_t *, &vscan_svc_counts);

		mutex_exit(&vscan_svc_mutex);
	}
}


static void
vscan_svc_taskq_callback(void *data)
{
	vscan_req_t *req;

	mutex_enter(&vscan_svc_mutex);

	req = (vscan_req_t *)data;
	ASSERT(req->vsr_magic == VS_REQ_MAGIC);
	vscan_svc_do_scan(req);
	if (req->vsr_state != VS_SVC_REQ_SCANNING)
		vscan_svc_scan_complete(req);

	--(vscan_svc_counts.vsc_tq);
	mutex_exit(&vscan_svc_mutex);
}


/*
 * vscan_svc_do_scan
 *
 * Note: To avoid potential deadlock it is important that
 * vscan_svc_mutex is not held during the call to
 * vscan_drv_create_note. vscan_drv_create_note enters
 * the vscan_drv_mutex and it is possible that a thread
 * holding that mutex could be waiting for vscan_svc_mutex.
 */
static void
vscan_svc_do_scan(vscan_req_t *req)
{
	int idx, result;
	vscan_svc_node_t *node;
	vs_scan_req_t *door_req;

	ASSERT(MUTEX_HELD(&vscan_svc_mutex));

	idx = req->vsr_idx;
	node = &vscan_svc_nodes[idx];

	req->vsr_state = VS_SVC_REQ_IN_PROGRESS;

	/* if vscan not enabled (shutting down), allow ACCESS */
	if (vscan_svc_state != VS_SVC_ENABLED) {
		node->vsn_access = VS_ACCESS_ALLOW;
		return;
	}

	if (vscan_svc_getattr(idx) != 0) {
		cmn_err(CE_WARN, "Can't access xattr for %s\n",
		    req->vsr_vp->v_path);
		node->vsn_access = VS_ACCESS_DENY;
		return;
	}

	/* valid scan_req ptr guaranteed */
	door_req = vscan_svc_populate_req(idx);

	/* free up mutex around create node and door call */
	mutex_exit(&vscan_svc_mutex);
	if (vscan_drv_create_node(idx) != B_TRUE)
		result = VS_STATUS_ERROR;
	else
		result = vscan_door_scan_file(door_req);
	kmem_free(door_req, sizeof (vs_scan_req_t));
	mutex_enter(&vscan_svc_mutex);

	if (result != VS_STATUS_SCANNING) {
		vscan_svc_nodes[idx].vsn_result = result;
		vscan_svc_process_scan_result(idx);
	} else { /* async response */
		if (req->vsr_state == VS_SVC_REQ_IN_PROGRESS)
			req->vsr_state = VS_SVC_REQ_SCANNING;
	}
}


/*
 * vscan_svc_populate_req
 *
 * Allocate a scan request to be sent to vscand, populating it
 * from the data in vscan_svc_nodes[idx].
 *
 * Returns: scan request object
 */
static vs_scan_req_t *
vscan_svc_populate_req(int idx)
{
	vs_scan_req_t *scan_req;
	vscan_req_t *req;
	vscan_svc_node_t *node;

	ASSERT(MUTEX_HELD(&vscan_svc_mutex));

	node = &vscan_svc_nodes[idx];
	req = node->vsn_req;
	scan_req = kmem_zalloc(sizeof (vs_scan_req_t), KM_SLEEP);

	scan_req->vsr_idx = idx;
	scan_req->vsr_seqnum = req->vsr_seqnum;
	(void) strncpy(scan_req->vsr_path, req->vsr_vp->v_path, MAXPATHLEN);
	scan_req->vsr_size = node->vsn_size;
	scan_req->vsr_modified = node->vsn_modified;
	scan_req->vsr_quarantined = node->vsn_quarantined;
	scan_req->vsr_flags = 0;
	(void) strncpy(scan_req->vsr_scanstamp,
	    node->vsn_scanstamp, sizeof (vs_scanstamp_t));

	return (scan_req);
}


/*
 * vscan_svc_scan_complete
 */
static void
vscan_svc_scan_complete(vscan_req_t *req)
{
	ASSERT(MUTEX_HELD(&vscan_svc_mutex));
	ASSERT(req != NULL);

	req->vsr_state = VS_SVC_REQ_COMPLETE;

	if ((--req->vsr_refcnt) == 0)
		vscan_svc_delete_req(req);
	else
		cv_broadcast(&(req->vsr_cv));
}


/*
 * vscan_svc_delete_req
 */
static void
vscan_svc_delete_req(vscan_req_t *req)
{
	int idx;

	ASSERT(MUTEX_HELD(&vscan_svc_mutex));
	ASSERT(req != NULL);
	ASSERT(req->vsr_refcnt == 0);
	ASSERT(req->vsr_state == VS_SVC_REQ_COMPLETE);

	if ((idx = req->vsr_idx) != 0)
		vscan_svc_remove_req(idx);

	vscan_svc_reql_remove(req);

	cv_signal(&vscan_svc_reql_cv);
}


/*
 * vscan_svc_scan_result
 *
 * Invoked from vscan_drv.c on receipt of an ioctl containing
 * an async scan result (VS_DRV_IOCTL_RESULT)
 * If the vsr_seqnum in the response does not match that in the
 * vscan_svc_nodes entry the result is discarded.
 */
void
vscan_svc_scan_result(vs_scan_rsp_t *scan_rsp)
{
	vscan_req_t *req;
	vscan_svc_node_t *node;

	mutex_enter(&vscan_svc_mutex);

	node = &vscan_svc_nodes[scan_rsp->vsr_idx];

	if ((req = node->vsn_req) == NULL) {
		mutex_exit(&vscan_svc_mutex);
		return;
	}

	ASSERT(req->vsr_magic == VS_REQ_MAGIC);

	if (scan_rsp->vsr_seqnum != req->vsr_seqnum) {
		mutex_exit(&vscan_svc_mutex);
		return;
	}

	node->vsn_result = scan_rsp->vsr_result;
	(void) strncpy(node->vsn_scanstamp,
	    scan_rsp->vsr_scanstamp, sizeof (vs_scanstamp_t));

	vscan_svc_process_scan_result(scan_rsp->vsr_idx);

	if (node->vsn_req->vsr_state == VS_SVC_REQ_SCANNING)
		vscan_svc_scan_complete(node->vsn_req);
	else
		node->vsn_req->vsr_state = VS_SVC_REQ_ASYNC_COMPLETE;

	mutex_exit(&vscan_svc_mutex);
}


/*
 * vscan_svc_scan_abort
 *
 * Abort in-progress scan requests.
 */
void
vscan_svc_scan_abort()
{
	int idx;
	vscan_req_t *req;

	mutex_enter(&vscan_svc_mutex);

	for (idx = 1; idx <= vs_nodes_max; idx++) {
		if ((req = vscan_svc_nodes[idx].vsn_req) == NULL)
			continue;

		ASSERT(req->vsr_magic == VS_REQ_MAGIC);

		if (req->vsr_state == VS_SVC_REQ_SCANNING) {
			DTRACE_PROBE1(vscan__abort, vscan_req_t *, req);
			vscan_svc_process_scan_result(idx);
			vscan_svc_scan_complete(req);
		}
	}

	mutex_exit(&vscan_svc_mutex);
}


/*
 * vscan_svc_process_scan_result
 *
 * Sets vsn_access and updates file attributes based on vsn_result,
 * as follows:
 *
 * VS_STATUS_INFECTED
 *  deny access, set quarantine attribute, clear scanstamp
 * VS_STATUS_CLEAN
 *  allow access, set scanstamp,
 *  if file not modified since scan initiated, clear modified attribute
 * VS_STATUS_NO_SCAN
 *  deny access if file quarantined, otherwise allow access
 * VS_STATUS_UNDEFINED, VS_STATUS_ERROR
 *  deny access if file quarantined, modified or no scanstamp
 *  otherwise, allow access
 */
static void
vscan_svc_process_scan_result(int idx)
{
	struct vattr attr;
	vnode_t *vp;
	timestruc_t *mtime;
	vscan_svc_node_t *node;

	ASSERT(MUTEX_HELD(&vscan_svc_mutex));

	node = &vscan_svc_nodes[idx];

	switch (node->vsn_result) {
	case VS_STATUS_INFECTED:
		node->vsn_access = VS_ACCESS_DENY;
		node->vsn_quarantined = 1;
		node->vsn_scanstamp[0] = '\0';
		(void) vscan_svc_setattr(idx,
		    XAT_AV_QUARANTINED | XAT_AV_SCANSTAMP);
		break;

	case VS_STATUS_CLEAN:
		node->vsn_access = VS_ACCESS_ALLOW;

		/* if mtime has changed, don't clear the modified attribute */
		vp = node->vsn_req->vsr_vp;
		mtime = &(node->vsn_mtime);
		attr.va_mask = AT_MTIME;
		if ((VOP_GETATTR(vp, &attr, 0, kcred, NULL) != 0) ||
		    (mtime->tv_sec != attr.va_mtime.tv_sec) ||
		    (mtime->tv_nsec != attr.va_mtime.tv_nsec)) {
			DTRACE_PROBE1(vscan__mtime__changed, vscan_svc_node_t *,
			    node);
			(void) vscan_svc_setattr(idx, XAT_AV_SCANSTAMP);
			break;
		}

		node->vsn_modified = 0;
		(void) vscan_svc_setattr(idx,
		    XAT_AV_SCANSTAMP | XAT_AV_MODIFIED);
		break;

	case VS_STATUS_NO_SCAN:
		if (node->vsn_quarantined)
			node->vsn_access = VS_ACCESS_DENY;
		else
			node->vsn_access = VS_ACCESS_ALLOW;
		break;

	case VS_STATUS_ERROR:
	case VS_STATUS_UNDEFINED:
	default:
		if ((node->vsn_quarantined) ||
		    (node->vsn_modified) ||
		    (node->vsn_scanstamp[0] == '\0'))
			node->vsn_access = VS_ACCESS_DENY;
		else
			node->vsn_access = VS_ACCESS_ALLOW;
		break;
	}

	DTRACE_PROBE4(vscan__result,
	    int, idx, int, node->vsn_req->vsr_seqnum,
	    int, node->vsn_result, int, node->vsn_access);
}


/*
 * vscan_svc_getattr
 *
 * Get the vscan related system attributes, AT_SIZE & AT_MTIME.
 */
static int
vscan_svc_getattr(int idx)
{
	xvattr_t xvattr;
	xoptattr_t *xoap = NULL;
	vnode_t *vp;
	vscan_svc_node_t *node;

	ASSERT(MUTEX_HELD(&vscan_svc_mutex));

	node = &vscan_svc_nodes[idx];
	if ((vp = node->vsn_req->vsr_vp) == NULL)
		return (-1);

	/* get the attributes */
	xva_init(&xvattr); /* sets AT_XVATTR */

	xvattr.xva_vattr.va_mask |= AT_SIZE;
	xvattr.xva_vattr.va_mask |= AT_MTIME;
	XVA_SET_REQ(&xvattr, XAT_AV_MODIFIED);
	XVA_SET_REQ(&xvattr, XAT_AV_QUARANTINED);
	XVA_SET_REQ(&xvattr, XAT_AV_SCANSTAMP);

	if (VOP_GETATTR(vp, (vattr_t *)&xvattr, 0, kcred, NULL) != 0)
		return (-1);

	if ((xoap = xva_getxoptattr(&xvattr)) == NULL) {
		cmn_err(CE_NOTE, "Virus scan request failed; "
		    "file system does not support virus scanning");
		return (-1);
	}

	node->vsn_size = xvattr.xva_vattr.va_size;
	node->vsn_mtime.tv_sec = xvattr.xva_vattr.va_mtime.tv_sec;
	node->vsn_mtime.tv_nsec = xvattr.xva_vattr.va_mtime.tv_nsec;

	if (XVA_ISSET_RTN(&xvattr, XAT_AV_MODIFIED) == 0)
		return (-1);
	node->vsn_modified = xoap->xoa_av_modified;

	if (XVA_ISSET_RTN(&xvattr, XAT_AV_QUARANTINED) == 0)
		return (-1);
	node->vsn_quarantined = xoap->xoa_av_quarantined;

	if (XVA_ISSET_RTN(&xvattr, XAT_AV_SCANSTAMP) != 0) {
		(void) memcpy(node->vsn_scanstamp,
		    xoap->xoa_av_scanstamp, AV_SCANSTAMP_SZ);
	}

	DTRACE_PROBE1(vscan__getattr, vscan_svc_node_t *, node);
	return (0);
}


/*
 * vscan_svc_setattr
 *
 * Set the vscan related system attributes.
 */
static int
vscan_svc_setattr(int idx, int which)
{
	xvattr_t xvattr;
	xoptattr_t *xoap = NULL;
	vnode_t *vp;
	int len;
	vscan_svc_node_t *node;

	ASSERT(MUTEX_HELD(&vscan_svc_mutex));

	node = &vscan_svc_nodes[idx];
	if ((vp = node->vsn_req->vsr_vp) == NULL)
		return (-1);

	/* update the attributes */
	xva_init(&xvattr); /* sets AT_XVATTR */
	if ((xoap = xva_getxoptattr(&xvattr)) == NULL)
		return (-1);

	if (which & XAT_AV_MODIFIED) {
		XVA_SET_REQ(&xvattr, XAT_AV_MODIFIED);
		xoap->xoa_av_modified = node->vsn_modified;
	}

	if (which & XAT_AV_QUARANTINED) {
		XVA_SET_REQ(&xvattr, XAT_AV_QUARANTINED);
		xoap->xoa_av_quarantined = node->vsn_quarantined;
	}

	if (which & XAT_AV_SCANSTAMP) {
		XVA_SET_REQ(&xvattr, XAT_AV_SCANSTAMP);
		len = strlen(node->vsn_scanstamp);
		(void) memcpy(xoap->xoa_av_scanstamp,
		    node->vsn_scanstamp, len);
	}

	/* if access is denied, set mtime to invalidate client cache */
	if (node->vsn_access != VS_ACCESS_ALLOW) {
		xvattr.xva_vattr.va_mask |= AT_MTIME;
		gethrestime(&xvattr.xva_vattr.va_mtime);
	}

	if (VOP_SETATTR(vp, (vattr_t *)&xvattr, 0, kcred, NULL) != 0)
		return (-1);

	DTRACE_PROBE2(vscan__setattr,
	    vscan_svc_node_t *, node, int, which);

	return (0);
}


/*
 * vscan_svc_configure
 *
 * store configuration in vscan_svc_config
 * set up vscan_svc_types array of pointers into
 * vscan_svc_config.vsc_types for efficient searching
 */
int
vscan_svc_configure(vs_config_t *conf)
{
	int count = 0;
	char *p, *beg, *end;

	mutex_enter(&vscan_svc_cfg_mutex);

	vscan_svc_config = *conf;

	(void) memset(vscan_svc_types, 0, sizeof (vscan_svc_types));

	beg = vscan_svc_config.vsc_types;
	end = beg + vscan_svc_config.vsc_types_len;

	for (p = beg; p < end; p += strlen(p) + 1) {
		if (count >= VS_TYPES_MAX) {
			mutex_exit(&vscan_svc_mutex);
			return (-1);
		}

		vscan_svc_types[count] = p;
		++count;
	}

	mutex_exit(&vscan_svc_cfg_mutex);
	return (0);
}


/*
 * vscan_svc_exempt_file
 *
 * check if a file's size or type exempts it from virus scanning
 *
 * If the file is exempt from virus scanning, allow will be set
 * to define whether files access should be allowed (B_TRUE) or
 * denied (B_FALSE)
 *
 * Returns: 1 exempt
 *          0 scan required
 */
static int
vscan_svc_exempt_file(vnode_t *vp, boolean_t *allow)
{
	struct vattr attr;

	ASSERT(vp != NULL);
	ASSERT(vp->v_path != NULL);

	attr.va_mask = AT_SIZE;

	if (VOP_GETATTR(vp, &attr, 0, kcred, NULL) != 0) {
		*allow = B_FALSE;
		return (0);
	}

	mutex_enter(&vscan_svc_cfg_mutex);

	if (attr.va_size > vscan_svc_config.vsc_max_size) {
		DTRACE_PROBE2(vscan__exempt__filesize, char *,
		    vp->v_path, int, *allow);

		*allow = (vscan_svc_config.vsc_allow) ? B_TRUE : B_FALSE;
		mutex_exit(&vscan_svc_cfg_mutex);
		return (1);
	}

	if (vscan_svc_exempt_filetype(vp->v_path)) {
		DTRACE_PROBE1(vscan__exempt__filetype, char *, vp->v_path);
		*allow = B_TRUE;
		mutex_exit(&vscan_svc_cfg_mutex);
		return (1);
	}

	mutex_exit(&vscan_svc_cfg_mutex);
	return (0);
}


/*
 * vscan_svc_exempt_filetype
 *
 * Each entry in vscan_svc_types includes a rule indicator (+,-)
 * followed by the match string for file types to which the rule
 * applies. Look for first match of file type in vscan_svc_types
 * and return 1 (exempt) if the indicator is '-', and 0 (not exempt)
 * if the indicator is '+'.
 * If vscan_svc_match_ext fails, or no match is found, return 0
 * (not exempt)
 *
 * Returns 1: exempt, 0: not exempt
 */
static int
vscan_svc_exempt_filetype(char *filepath)
{
	int i, rc, exempt = 0;
	char *filename, *ext;

	ASSERT(MUTEX_HELD(&vscan_svc_cfg_mutex));

	if ((filename = strrchr(filepath, '/')) == 0)
		filename = filepath;
	else
		filename++;

	if ((ext = strrchr(filename, '.')) == NULL)
		ext = "";
	else
		ext++;

	for (i = 0; i < VS_TYPES_MAX; i ++) {
		if (vscan_svc_types[i] == 0)
			break;

		rc = vscan_svc_match_ext(vscan_svc_types[i] + 1, ext, 1);
		if (rc == -1)
			break;
		if (rc > 0) {
			DTRACE_PROBE2(vscan__type__match, char *, ext,
			    char *, vscan_svc_types[i]);
			exempt = (vscan_svc_types[i][0] == '-');
			break;
		}
	}

	return (exempt);
}


/*
 *  vscan_svc_match_ext
 *
 * Performs a case-insensitive match for two strings.  The first string
 * argument can contain the wildcard characters '?' and '*'
 *
 * Returns: 0 no match
 *          1 match
 *         -1 recursion error
 */
static int
vscan_svc_match_ext(char *patn, char *str, int depth)
{
	int c1, c2;
	if (depth > VS_EXT_RECURSE_DEPTH)
		return (-1);

	for (;;) {
		switch (*patn) {
		case 0:
			return (*str == 0);

		case '?':
			if (*str != 0) {
				str++;
				patn++;
				continue;
			}
			return (0);

		case '*':
			patn++;
			if (*patn == 0)
				return (1);

			while (*str) {
				if (vscan_svc_match_ext(patn, str, depth + 1))
					return (1);
				str++;
			}
			return (0);

		default:
			if (*str != *patn) {
				c1 = *str;
				c2 = *patn;

				c1 = tolower(c1);
				c2 = tolower(c2);
				if (c1 != c2)
					return (0);
			}
			str++;
			patn++;
			continue;
		}
	}
	/* NOT REACHED */
}


/*
 * vscan_svc_insert_req
 *
 * Insert request in next available available slot in vscan_svc_nodes
 *
 * Returns: idx of slot, or -1 if no slot available
 */
static int
vscan_svc_insert_req(vscan_req_t *req)
{
	int idx;
	vscan_svc_node_t *node;

	ASSERT(MUTEX_HELD(&vscan_svc_mutex));

	if (vscan_svc_counts.vsc_node == vs_nodes_max)
		return (-1);

	for (idx = 1; idx <= vs_nodes_max; idx++) {
		if (vscan_svc_nodes[idx].vsn_req == NULL) {
			req->vsr_idx = idx;

			node = &vscan_svc_nodes[idx];
			(void) memset(node, 0, sizeof (vscan_svc_node_t));
			node->vsn_req = req;
			node->vsn_modified = 1;
			node->vsn_result = VS_STATUS_UNDEFINED;
			node->vsn_access = VS_ACCESS_UNDEFINED;

			++(vscan_svc_counts.vsc_node);
			return (idx);
		}
	}

	return (-1);
}


/*
 * vscan_svc_remove_req
 */
static void
vscan_svc_remove_req(int idx)
{
	ASSERT(MUTEX_HELD(&vscan_svc_mutex));

	if (idx != 0) {
		(void) memset(&vscan_svc_nodes[idx], 0,
		    sizeof (vscan_svc_node_t));
		--(vscan_svc_counts.vsc_node);
	}
}


/*
 * vscan_svc_reql_find
 */
static vscan_req_t *
vscan_svc_reql_find(vnode_t *vp)
{
	vscan_req_t *req;
	ASSERT(MUTEX_HELD(&vscan_svc_mutex));

	req = list_head(&vscan_svc_reql);

	while (req != NULL) {
		ASSERT(req->vsr_magic == VS_REQ_MAGIC);
		if ((req->vsr_vp == vp) &&
		    (req->vsr_state != VS_SVC_REQ_COMPLETE))
			break;

		req = list_next(&vscan_svc_reql, req);
	}

	return (req);
}


/*
 * vscan_svc_reql_insert
 */
static vscan_req_t *
vscan_svc_reql_insert(vnode_t *vp)
{
	vscan_req_t *req;

	ASSERT(MUTEX_HELD(&vscan_svc_mutex));

	/* if request already in list then return it */
	if ((req = vscan_svc_reql_find(vp)) != NULL)
		return (req);

	/* if list is full return NULL */
	if (vscan_svc_counts.vsc_reql == vs_reqs_max)
		return (NULL);

	/* create a new request and insert into list */
	VN_HOLD(vp);

	req = kmem_zalloc(sizeof (vscan_req_t), KM_SLEEP);

	req->vsr_magic = VS_REQ_MAGIC;
	if (vscan_svc_seqnum == UINT32_MAX)
		vscan_svc_seqnum = 0;
	req->vsr_seqnum = ++vscan_svc_seqnum;
	req->vsr_vp = vp;
	req->vsr_refcnt = 1; /* decremented in vscan_svc_scan_complete */
	req->vsr_state = VS_SVC_REQ_INIT;
	cv_init(&(req->vsr_cv), NULL, CV_DEFAULT, NULL);

	list_insert_tail(&vscan_svc_reql, req);
	if (vscan_svc_reql_next == NULL)
		vscan_svc_reql_next = req;

	++(vscan_svc_counts.vsc_reql);

	/* wake reql handler thread */
	cv_signal(&vscan_svc_reql_cv);

	return (req);
}


/*
 * vscan_svc_reql_remove
 */
static void
vscan_svc_reql_remove(vscan_req_t *req)
{
	ASSERT(MUTEX_HELD(&vscan_svc_mutex));
	ASSERT(req->vsr_magic == VS_REQ_MAGIC);

	if (vscan_svc_reql_next == req)
		vscan_svc_reql_next = list_next(&vscan_svc_reql, req);

	list_remove(&vscan_svc_reql, req);
	cv_destroy(&(req->vsr_cv));
	VN_RELE(req->vsr_vp);

	kmem_free(req, sizeof (vscan_req_t));
	--(vscan_svc_counts.vsc_reql);
}
