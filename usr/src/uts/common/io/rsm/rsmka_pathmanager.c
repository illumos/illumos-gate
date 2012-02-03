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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

/*
 * This module provides for the management of interconnect adapters
 * inter-node connections (aka paths), and IPC.  Adapter descriptors are
 * maintained on a linked list; one list per adapter devname.  Each
 * adapter descriptor heads a linked list of path descriptors.  There is
 * also a linked list of ipc_info descriptors; one for each node.  Each
 * ipc_info descriptor heads a circular list of ipc tokens (the tokens are
 * embedded within a path descriptor). The tokens are used in round robin
 * fashion.
 *
 *
 * The exported interface consists of the following functions:
 *	- rsmka_add_adapter
 *	- rsmka_remove_adapter
 *
 *      [add_path and remove_path only called for current adapters]
 *	- rsmka_add_path
 *	- rsmka_remove_path	[a path down request is implicit]
 *
 *	- rsmka_path_up           [called at clock ipl for Sun Cluster]
 *	- rsmka_path_down         [called at clock ipl for Sun Cluster]
 *	- rsmka_disconnect_node   [called at clock ipl for Sun Cluster;
 *				treat like path-down for all node paths;
 *				can be before node_alive; always before
 *				node_died.]
 *
 *	[node_alive and node_died are always paired]
 *	- rsmka_node_alive   called after the first cluster path is up
 *                           for this node
 *	- rsmka_node_died
 *
 *      [set the local node id]
 *      - rsmka_set_my_nodeid    called to set the variable my_nodeid to the
 *                           local node id
 *
 * Processing for these functions is setup as a state machine supported
 * by the data structures described above.
 *
 * For Sun Cluster these are called from the Path-Manager/Kernel-Agent
 * Interface (rsmka_pm_interface.cc).
 *
 * The functions rsm_path_up, rsm_path_down, and rsm_disconnect_node are
 * called at clock interrupt level from the Path-Manager/Kernel-Agent
 * Interface which precludes sleeping; so these functions may (optionally)
 * defer processing to an independent thread running at normal ipl.
 *
 *
 * lock definitions:
 *
 *	(mutex) work_queue.work_mutex
 *			protects linked list of work tokens and used
 *			with cv_wait/cv_signal thread synchronization.
 *			No other locks acquired when held.
 *
 *	(mutex) adapter_listhead_base.listlock
 *			protects linked list of adapter listheads
 *			Always acquired before listhead->mutex
 *
 *
 *	(mutex) ipc_info_lock
 *			protects ipc_info list and sendq token lists
 *			Always acquired before listhead->mutex
 *
 *      (mutex) listhead->mutex
 *			protects adapter listhead, linked list of
 *			adapters, and linked list of paths.
 *
 *      (mutex) path->mutex
 *			protects the path descriptor.
 *			work_queue.work_mutex may be acquired when holding
 *			this lock.
 *
 *	(mutex) adapter->mutex
 *			protects adapter descriptor contents.  used
 *			mainly for ref_cnt update.
 */

#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/devops.h>
#include <sys/ddi_impldefs.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/proc.h>
#include <sys/thread.h>
#include <sys/taskq.h>
#include <sys/callb.h>

#include <sys/rsm/rsm.h>
#include <rsm_in.h>
#include <sys/rsm/rsmka_path_int.h>

extern void _cplpl_init();
extern void _cplpl_fini();
extern pri_t maxclsyspri;
extern int   rsm_hash_size;

extern rsm_node_id_t my_nodeid;
extern rsmhash_table_t rsm_import_segs;
extern rsm_intr_hand_ret_t rsm_srv_func(rsm_controller_object_t *,
    rsm_intr_q_op_t, rsm_addr_t, void *, size_t, rsm_intr_hand_arg_t);
extern void rsmseg_unload(rsmseg_t *);
extern void rsm_suspend_complete(rsm_node_id_t src_node, int flag);
extern int rsmipc_send_controlmsg(path_t *path, int msgtype);
extern void rsmka_path_monitor_initialize();
extern void rsmka_path_monitor_terminate();

extern adapter_t loopback_adapter;
/*
 * Lint errors and warnings are displayed; informational messages
 * are suppressed.
 */
/* lint -w2 */


/*
 * macros SQ_TOKEN_TO_PATH and WORK_TOKEN_TO_PATH use a null pointer
 * for computational purposes.  Ignore the lint warning.
 */
/* lint -save -e413 */
/* FUNCTION PROTOTYPES */
static adapter_t *init_adapter(char *, int, rsm_addr_t,
    rsm_controller_handle_t, rsm_ops_t *, srv_handler_arg_t *);
adapter_t *rsmka_lookup_adapter(char *, int);
static ipc_info_t *lookup_ipc_info(rsm_node_id_t);
static ipc_info_t *init_ipc_info(rsm_node_id_t, boolean_t);
static path_t *lookup_path(char *, int, rsm_node_id_t, rsm_addr_t);
static void pathup_to_pathactive(ipc_info_t *, rsm_node_id_t);
static void path_importer_disconnect(path_t *);
boolean_t rsmka_do_path_active(path_t *, int);
static boolean_t do_path_up(path_t *, int);
static void do_path_down(path_t *, int);
static void enqueue_work(work_token_t *);
static boolean_t cancel_work(work_token_t *);
static void link_path(path_t *);
static void destroy_path(path_t *);
static void link_sendq_token(sendq_token_t *, rsm_node_id_t);
static void unlink_sendq_token(sendq_token_t *, rsm_node_id_t);
boolean_t rsmka_check_node_alive(rsm_node_id_t);
static void do_deferred_work(caddr_t);
static int create_ipc_sendq(path_t *);
static void destroy_ipc_info(ipc_info_t *);
void rsmka_pathmanager_cleanup();
void rsmka_release_adapter(adapter_t *);

kt_did_t rsm_thread_id;
int rsmka_terminate_workthread_loop = 0;

static struct adapter_listhead_list adapter_listhead_base;
static work_queue_t work_queue;

/* protect ipc_info descriptor manipulation */
static kmutex_t ipc_info_lock;

static ipc_info_t *ipc_info_head = NULL;

static int category = RSM_PATH_MANAGER | RSM_KERNEL_AGENT;

/* for synchronization with rsmipc_send() in rsm.c */
kmutex_t ipc_info_cvlock;
kcondvar_t ipc_info_cv;



/*
 * RSMKA PATHMANAGER INITIALIZATION AND CLEANUP ROUTINES
 *
 */


/*
 * Called from the rsm module (rsm.c)  _init() routine
 */
void
rsmka_pathmanager_init()
{
	kthread_t *tp;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_pathmanager_init enter\n"));

	/* initialization for locks and condition variables  */
	mutex_init(&work_queue.work_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ipc_info_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ipc_info_cvlock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&adapter_listhead_base.listlock, NULL,
	    MUTEX_DEFAULT, NULL);

	cv_init(&work_queue.work_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&ipc_info_cv, NULL, CV_DEFAULT, NULL);

	tp = thread_create(NULL, 0, do_deferred_work, NULL, 0, &p0,
	    TS_RUN, maxclsyspri);
	rsm_thread_id = tp->t_did;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_pathmanager_init done\n"));
}

void
rsmka_pathmanager_cleanup()
{
	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_pathmanager_cleanup enter\n"));

	ASSERT(work_queue.head == NULL);

	/*
	 * In processing the remove path callbacks from the path monitor
	 * object, all deferred work will have been completed. So
	 * awaken the deferred work thread to give it a chance to exit
	 * the loop.
	 */
	mutex_enter(&work_queue.work_mutex);
	rsmka_terminate_workthread_loop++;
	cv_signal(&work_queue.work_cv);
	mutex_exit(&work_queue.work_mutex);

	/*
	 * Wait for the deferred work thread to exit before
	 * destroying the locks and cleaning up other data
	 * structures.
	 */
	if (rsm_thread_id)
		thread_join(rsm_thread_id);

	/*
	 * Destroy locks & condition variables
	 */
	mutex_destroy(&work_queue.work_mutex);
	cv_destroy(&work_queue.work_cv);

	mutex_enter(&ipc_info_lock);
	while (ipc_info_head)
		destroy_ipc_info(ipc_info_head);
	mutex_exit(&ipc_info_lock);

	mutex_destroy(&ipc_info_lock);

	mutex_destroy(&ipc_info_cvlock);
	cv_destroy(&ipc_info_cv);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_pathmanager_cleanup done\n"));

}

void
rsmka_set_my_nodeid(rsm_node_id_t local_nodeid)
{
	my_nodeid = local_nodeid;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm: node %d \n", my_nodeid));

}

/*
 * DEFERRED WORK THREAD AND WORK QUEUE SUPPORT ROUTINES
 *
 */

/*
 * This function is the executable code of the thread which handles
 * deferred work.  Work is deferred when a function is called at
 * clock ipl and processing may require blocking.
 *
 *
 * The thread is created by a call to taskq_create in rsmka_pathmanager_init.
 * After creation, a call to taskq_dispatch causes this function to
 * execute.  It loops forever - blocked until work is enqueued from
 * rsmka_do_path_active, do_path_down, or rsmka_disconnect_node.
 * rsmka_pathmanager_cleanup (called from _fini) will
 * set rsmka_terminate_workthread_loop and the task processing will
 * terminate.
 */
static void
do_deferred_work(caddr_t arg /*ARGSUSED*/)
{

	adapter_t 			*adapter;
	path_t				*path;
	work_token_t			*work_token;
	int				work_opcode;
	rsm_send_q_handle_t		sendq_handle;
	int				error;
	timespec_t			tv;
	callb_cpr_t			cprinfo;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "do_deferred_work enter\n"));

	CALLB_CPR_INIT(&cprinfo, &work_queue.work_mutex, callb_generic_cpr,
	    "rsm_deferred_work");

	for (;;) {
		mutex_enter(&work_queue.work_mutex);

		if (rsmka_terminate_workthread_loop) {
			goto exit;
		}

		/* When there is no work to do, block here */
		while (work_queue.head == NULL) {
			/* Since no work to do, Safe to CPR */
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&work_queue.work_cv, &work_queue.work_mutex);
			CALLB_CPR_SAFE_END(&cprinfo, &work_queue.work_mutex);

			if (rsmka_terminate_workthread_loop) {
				goto exit;
			}
		}

		/*
		 * Remove a work token and begin work
		 */
		work_token = work_queue.head;
		work_queue.head = work_token->next;
		if (work_queue.tail == work_token)
			work_queue.tail = NULL;

		work_opcode = work_token->opcode;
		path = WORK_TOKEN_TO_PATH(work_token, work_opcode -1);
		work_token->next = NULL;
		mutex_exit(&work_queue.work_mutex);


		switch (work_opcode) {
		case RSMKA_IPC_UP:
			DBG_PRINTF((category, RSM_DEBUG,
			    "do_deferred_work:up,  path = %lx\n", path));
			error = create_ipc_sendq(path);
			mutex_enter(&path->mutex);
			if (path->state != RSMKA_PATH_UP) {
				/*
				 * path state has changed, if sendq was created,
				 * destroy it and return. Don't need to worry
				 * about sendq ref_cnt since no one starts
				 * using the sendq till path state becomes
				 * active
				 */
				if (error == RSM_SUCCESS) {
					sendq_handle = path->sendq_token.
					    rsmpi_sendq_handle;
					path->sendq_token.rsmpi_sendq_handle =
					    NULL;
					adapter = path->local_adapter;
					mutex_exit(&path->mutex);

					if (sendq_handle != NULL) {
						adapter->rsmpi_ops->
						    rsm_sendq_destroy(
						    sendq_handle);
					}
					mutex_enter(&path->mutex);
				}
				/* free up work token */
				work_token->opcode = 0;

				/*
				 * decrement reference count for the path
				 * descriptor and signal for synchronization
				 * with rsmka_remove_path. PATH_HOLD_NOLOCK was
				 * done by rsmka_path_up.
				 */
				PATH_RELE_NOLOCK(path);
				mutex_exit(&path->mutex);
				break;
			}

			if (error == RSM_SUCCESS) {
				DBG_PRINTF((category, RSM_DEBUG,
				    "do_deferred_work:success on up\n"));
				/* clear flag since sendq_create succeeded */
				path->flags &= ~RSMKA_SQCREATE_PENDING;
				path->state = RSMKA_PATH_ACTIVE;

				/*
				 * now that path is active we send the
				 * RSMIPC_MSG_SQREADY to the remote endpoint
				 */
				path->procmsg_cnt = 0;
				path->sendq_token.msgbuf_avail = 0;

				/* Calculate local incarnation number */
				gethrestime(&tv);
				if (tv.tv_sec == RSM_UNKNOWN_INCN)
					tv.tv_sec = 1;
				path->local_incn = (int64_t)tv.tv_sec;

				/*
				 * if send fails here its due to some
				 * non-transient error because QUEUE_FULL is
				 * not possible here since we are the first
				 * message on this sendq. The error will cause
				 * the path to go down anyways, so ignore
				 * the return value.
				 */
				(void) rsmipc_send_controlmsg(path,
				    RSMIPC_MSG_SQREADY);
				/* wait for SQREADY_ACK message */
				path->flags |= RSMKA_WAIT_FOR_SQACK;
			} else {
				/*
				 * sendq create failed possibly because
				 * the remote end is not yet ready eg.
				 * handler not registered, set a flag
				 * so that when there is an indication
				 * that the remote end is ready
				 * rsmka_do_path_active will be retried.
				 */
				path->flags |= RSMKA_SQCREATE_PENDING;
			}

			/* free up work token */
			work_token->opcode = 0;

			/*
			 * decrement reference count for the path
			 * descriptor and signal for synchronization with
			 * rsmka_remove_path. PATH_HOLD_NOLOCK was done
			 * by rsmka_path_up.
			 */
			PATH_RELE_NOLOCK(path);
			mutex_exit(&path->mutex);

			break;
		case RSMKA_IPC_DOWN:
			DBG_PRINTF((category, RSM_DEBUG,
			    "do_deferred_work:down, path = %lx\n", path));

			/*
			 * Unlike the processing of path_down in the case
			 * where the RSMKA_NO_SLEEP flag is not set, here,
			 * the state of the path is changed directly to
			 * RSMKA_PATH_DOWN. This is because in this case
			 * where the RSMKA_NO_SLEEP flag is set, any other
			 * calls referring this path will just queue up
			 * and will be processed only after the path
			 * down processing has completed.
			 */
			mutex_enter(&path->mutex);
			path->state = RSMKA_PATH_DOWN;
			/*
			 * clear the WAIT_FOR_SQACK flag since path is down.
			 */
			path->flags &= ~RSMKA_WAIT_FOR_SQACK;

			/*
			 * this wakes up any thread waiting to receive credits
			 * in rsmipc_send to tell it that the path is down
			 * thus releasing the sendq.
			 */
			cv_broadcast(&path->sendq_token.sendq_cv);

			mutex_exit(&path->mutex);

			/* drain the messages from the receive msgbuf */
			taskq_wait(path->recv_taskq);

			/*
			 * The path_importer_disconnect function has to
			 * be called after releasing the mutex on the path
			 * in order to avoid any recursive mutex enter panics
			 */
			path_importer_disconnect(path);
			DBG_PRINTF((category, RSM_DEBUG,
			    "do_deferred_work: success on down\n"));
			/*
			 * decrement reference count for the path
			 * descriptor and signal for synchronization with
			 * rsmka_remove_path. PATH_HOLD_NOLOCK was done
			 * by rsmka_path_down.
			 */
			mutex_enter(&path->mutex);

#ifdef DEBUG
			/*
			 * Some IPC messages left in the recv_buf,
			 * they'll be dropped
			 */
			if (path->msgbuf_cnt != 0)
				cmn_err(CE_NOTE,
				    "path=%lx msgbuf_cnt != 0\n",
				    (uintptr_t)path);
#endif

			/*
			 * Don't want to destroy a send queue when a token
			 * has been acquired; so wait 'til the token is
			 * no longer referenced (with a cv_wait).
			 */
			while (path->sendq_token.ref_cnt != 0)
				cv_wait(&path->sendq_token.sendq_cv,
				    &path->mutex);

			sendq_handle = path->sendq_token.rsmpi_sendq_handle;
			path->sendq_token.rsmpi_sendq_handle = NULL;

			/* destroy the send queue and release the handle */
			if (sendq_handle != NULL) {
				adapter = path->local_adapter;
				adapter->rsmpi_ops->rsm_sendq_destroy(
				    sendq_handle);
			}

			work_token->opcode = 0;
			PATH_RELE_NOLOCK(path);
			mutex_exit(&path->mutex);
			break;
		default:
			DBG_PRINTF((category, RSM_DEBUG,
			    "do_deferred_work: bad work token opcode\n"));
			break;
		}
	}

exit:
	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "do_deferred_work done\n"));
	/*
	 * CALLB_CPR_EXIT does a mutex_exit for
	 * the work_queue.work_mutex
	 */
	CALLB_CPR_EXIT(&cprinfo);
}

/*
 * Work is inserted at the tail of the list and processed from the
 * head of the list.
 */
static void
enqueue_work(work_token_t *token)
{
	work_token_t	*tail_token;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "enqueue_work enter\n"));

	ASSERT(MUTEX_HELD(&work_queue.work_mutex));

	token->next = NULL;
	if (work_queue.head == NULL) {
		work_queue.head = work_queue.tail = token;
	} else {
		tail_token = work_queue.tail;
		work_queue.tail = tail_token->next = token;
	}

	/* wake up deferred work thread */
	cv_signal(&work_queue.work_cv);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "enqueue_work done\n"));
}


/*
 * If the work_token is found on the work queue, the work is cancelled
 * by removing the token from the work queue.
 *
 * Return true if a work_token was found and cancelled, otherwise return false
 *
 * enqueue_work increments the path refcnt to make sure that the path doesn't
 * go away, callers of cancel_work need to decrement the refcnt of the path to
 * which this work_token belongs if a work_token is found in the work_queue
 * and cancelled ie. when the return value is B_TRUE.
 */
static boolean_t
cancel_work(work_token_t *work_token)
{
	work_token_t	*current_token;
	work_token_t	*prev_token = NULL;
	boolean_t	cancelled = B_FALSE;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "cancel_work enter\n"));

	ASSERT(MUTEX_HELD(&work_queue.work_mutex));


	current_token = work_queue.head;
	while (current_token != NULL) {
		if (current_token == work_token) {
			if (work_token == work_queue.head)
				work_queue.head = work_token->next;
			else
				prev_token->next = work_token->next;
			if (work_token == work_queue.tail)
				work_queue.tail = prev_token;

			current_token->opcode = 0;
			current_token->next = NULL;
			/* found and cancelled work */
			cancelled = B_TRUE;
			DBG_PRINTF((category, RSM_DEBUG,
			    "cancelled_work = 0x%p\n", work_token));
			break;
		}
		prev_token = current_token;
		current_token = current_token->next;
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "cancel_work done\n"));
	return (cancelled);
}

/*
 * EXTERNAL INTERFACES
 *
 * For Galileo Clustering, these routine are called from
 * rsmka_pm_interface.cc
 *
 */

/*
 *
 * If the adapter is supported by rsmpi then initialize an adapter descriptor
 * and link it to the list of adapters.  The adapter attributes are obtained
 * from rsmpi and stored in the descriptor.  Finally, a service handler
 * for incoming ipc on this adapter is registered with rsmpi.
 * A pointer for the adapter descriptor is returned as a cookie to the
 * caller.  The cookie may be use with subsequent calls to save the time of
 * adapter descriptor lookup.
 *
 * The adapter descriptor maintains a reference count which is intialized
 * to 1 and incremented on lookups; when a cookie is used in place of
 * a lookup, an explicit ADAPTER_HOLD is required.
 */

void *
rsmka_add_adapter(char *name, int instance, rsm_addr_t hwaddr)
{
	adapter_t		*adapter;
	rsm_controller_object_t	rsmpi_adapter_object;
	rsm_controller_handle_t	rsmpi_adapter_handle;
	rsm_ops_t		*rsmpi_ops_vector;
	int			adapter_is_supported;
	rsm_controller_attr_t	*attr;
	srv_handler_arg_t	*srv_hdlr_argp;
	int result;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmka_add_adapter enter\n"));

	DBG_PRINTF((category, RSM_DEBUG,
	    "rsmka_add_adapter: name = %s instance = %d hwaddr = %llx \n",
	    name, instance, hwaddr));

	/* verify name length */
	if (strlen(name) >= MAXNAMELEN) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmka_add_adapter done: name too long\n"));
		return (NULL);
	}


	/* Check if rsmpi supports this adapter type */
	adapter_is_supported = rsm_get_controller(name, instance,
	    &rsmpi_adapter_object, RSM_VERSION);

	if (adapter_is_supported != RSM_SUCCESS) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsmka_add_adapter done: adapter not supported\n"));
		return (NULL);
	}

	rsmpi_adapter_handle = rsmpi_adapter_object.handle;
	rsmpi_ops_vector = rsmpi_adapter_object.ops;

	/* Get adapter attributes */
	result = rsm_get_controller_attr(rsmpi_adapter_handle, &attr);
	if (result != RSM_SUCCESS) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsm: get_controller_attr(%d) Failed %x\n",
		    instance, result));
		(void) rsm_release_controller(name, instance,
		    &rsmpi_adapter_object);
		return (NULL);
	}

	DBG_PRINTF((category, RSM_DEBUG,
	    "rsmka_add_adapter: register service offset = %d\n", hwaddr));

	/*
	 * create a srv_handler_arg_t object, initialize it and register
	 * it along with rsm_srv_func. This get passed as the
	 * rsm_intr_hand_arg_t when the handler gets invoked.
	 */
	srv_hdlr_argp = kmem_zalloc(sizeof (srv_handler_arg_t), KM_SLEEP);

	(void) strcpy(srv_hdlr_argp->adapter_name, name);
	srv_hdlr_argp->adapter_instance = instance;
	srv_hdlr_argp->adapter_hwaddr = hwaddr;

	/* Have rsmpi register the ipc receive handler for this adapter */
	/*
	 * Currently, we need to pass in a separate service identifier for
	 * each adapter. In order to obtain a unique service identifier
	 * value for an adapter, we add the hardware address of the
	 * adapter to the base service identifier(RSM_SERVICE which is
	 * defined as RSM_INTR_T_KA as per the RSMPI specification).
	 * NOTE: This may result in using some of the service identifier
	 * values defined for RSM_INTR_T_XPORT(the Sun Cluster Transport).
	 */
	result = rsmpi_ops_vector->rsm_register_handler(
	    rsmpi_adapter_handle, &rsmpi_adapter_object,
	    RSM_SERVICE+(uint_t)hwaddr, rsm_srv_func,
	    (rsm_intr_hand_arg_t)srv_hdlr_argp, NULL, 0);

	if (result != RSM_SUCCESS) {
		DBG_PRINTF((category, RSM_ERR,
		    "rsmka_add_adapter done: rsm_register_handler"
		    "failed %d\n",
		    instance));
		return (NULL);
	}

	/* Initialize an adapter descriptor and add it to the adapter list */
	adapter = init_adapter(name, instance, hwaddr,
	    rsmpi_adapter_handle, rsmpi_ops_vector, srv_hdlr_argp);

	/* Copy over the attributes from the pointer returned to us */
	adapter->rsm_attr = *attr;

	/*
	 * With the addition of the topology obtainment interface, applications
	 * now get the local nodeid from the topology data structure.
	 *
	 * adapter->rsm_attr.attr_node_id = my_nodeid;
	 */
	DBG_PRINTF((category, RSM_ERR,
	    "rsmka_add_adapter: adapter = %lx\n", adapter));

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmka_add_adapter done\n"));

	/* return adapter pointer as a cookie for later fast access */
	return ((void *)adapter);
}


/*
 * Unlink the adapter descriptor and call rsmka_release_adapter which
 * will decrement the reference count and possibly free the desriptor.
 */
boolean_t
rsmka_remove_adapter(char *name, uint_t instance, void *cookie, int flags)
{
	adapter_t		*adapter;
	adapter_listhead_t	*listhead;
	adapter_t		*prev, *current;
	rsm_controller_object_t	rsm_cntl_obj;


	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_remove_adapter enter\n"));

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_remove_adapter: cookie = %lx\n", cookie));

	if (flags & RSMKA_USE_COOKIE) {
		adapter = (adapter_t *)cookie;
	} else {
		adapter = rsmka_lookup_adapter(name, instance);
		/*
		 * rsmka_lookup_adapter increments the ref_cnt; need
		 * to decrement here to get true count
		 */
		ADAPTER_RELE(adapter);
	}
	ASSERT(adapter->next_path == NULL);

	listhead = adapter->listhead;

	mutex_enter(&adapter_listhead_base.listlock);

	mutex_enter(&listhead->mutex);

	/* find the adapter in the list and remove it */
	prev = NULL;
	current = listhead->next_adapter;
	while (current != NULL) {
		if (adapter->instance == current->instance) {
			break;
		} else {
			prev = current;
			current = current->next;
		}
	}
	ASSERT(current != NULL);

	if (prev == NULL)
		listhead->next_adapter = current->next;
	else
		prev->next = current->next;

	listhead->adapter_count--;

	mutex_exit(&listhead->mutex);

	mutex_exit(&adapter_listhead_base.listlock);

	mutex_enter(&current->mutex);

	/*
	 * unregister the handler
	 */
	current->rsmpi_ops->rsm_unregister_handler(current->rsmpi_handle,
	    RSM_SERVICE+current->hwaddr, rsm_srv_func,
	    (rsm_intr_hand_arg_t)current->hdlr_argp);

	DBG_PRINTF((category, RSM_DEBUG, "rsmka_remove_adapter: unreg hdlr "
	    ":adapter=%lx, hwaddr=%lx\n", current, current->hwaddr));

	rsm_cntl_obj.handle = current->rsmpi_handle;
	rsm_cntl_obj.ops = current->rsmpi_ops;

	(void) rsm_release_controller(current->listhead->adapter_devname,
	    current->instance, &rsm_cntl_obj);

	mutex_exit(&current->mutex);

	rsmka_release_adapter(current);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_remove_adapter done\n"));

	return (B_TRUE);
}

/*
 * An adapter descriptor will exist from an earlier add_adapter. This
 * function does:
 *		initialize the path descriptor
 *		initialize the ipc descriptor (it may already exist)
 *		initialize and link a sendq token for this path
 */
void *
rsmka_add_path(char *adapter_name, int adapter_instance,
    rsm_node_id_t remote_node,
    rsm_addr_t remote_hwaddr, int rem_adapt_instance,
    void *cookie, int flags)
{

	path_t			*path;
	adapter_t		*adapter;
	char			tq_name[TASKQ_NAMELEN];

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmka_add_path enter\n"));

	/* allocate new path descriptor */
	path = kmem_zalloc(sizeof (path_t), KM_SLEEP);

	if (flags & RSMKA_USE_COOKIE) {
		adapter = (adapter_t *)cookie;
		ADAPTER_HOLD(adapter);
	} else {
		adapter = rsmka_lookup_adapter(adapter_name, adapter_instance);
	}

	DBG_PRINTF((category, RSM_DEBUG,
	    "rsmka_add_path: adapter = %lx\n", adapter));

	/*
	 * initialize path descriptor
	 * don't need to increment adapter reference count because
	 * it can't be removed if paths exist for it.
	 */
	mutex_init(&path->mutex, NULL, MUTEX_DEFAULT, NULL);

	PATH_HOLD(path);
	path->state = RSMKA_PATH_DOWN;
	path->remote_node = remote_node;
	path->remote_hwaddr = remote_hwaddr;
	path->remote_devinst = rem_adapt_instance;
	path->local_adapter = adapter;

	/* taskq is for sendq on adapter with remote_hwaddr on remote_node */
	(void) snprintf(tq_name, sizeof (tq_name), "%x_%llx",
	    remote_node, (unsigned long long) remote_hwaddr);

	path->recv_taskq = taskq_create_instance(tq_name, adapter_instance,
	    RSMKA_ONE_THREAD, maxclsyspri, RSMIPC_MAX_MESSAGES,
	    RSMIPC_MAX_MESSAGES, TASKQ_PREPOPULATE);

	/* allocate the message buffer array */
	path->msgbuf_queue = (msgbuf_elem_t *)kmem_zalloc(
	    RSMIPC_MAX_MESSAGES * sizeof (msgbuf_elem_t), KM_SLEEP);

	/*
	 * init cond variables for synch with rsmipc_send()
	 * and rsmka_remove_path
	 */
	cv_init(&path->sendq_token.sendq_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&path->hold_cv, NULL, CV_DEFAULT, NULL);

	/* link path descriptor on adapter path list */
	link_path(path);

	/* link the path sendq token on the ipc_info token list */
	link_sendq_token(&path->sendq_token, remote_node);

	/* ADAPTER_HOLD done above by rsmka_lookup_adapter */
	ADAPTER_RELE(adapter);

	DBG_PRINTF((category, RSM_DEBUG, "rsmka_add_path: path = %lx\n", path));

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmka_add_path done\n"));
	return ((void *)path);
}

/*
 * Wait for the path descriptor reference count to become zero then
 * directly call path down processing.  Finally, unlink the sendq token and
 * free the path descriptor memory.
 *
 * Note: lookup_path locks the path and increments the path hold count
 */
void
rsmka_remove_path(char *adapter_name, int instance, rsm_node_id_t remote_node,
    rsm_addr_t remote_hwaddr, void *path_cookie, int flags)
{
	path_t		*path;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmka_remove_path enter\n"));

	if (flags & RSMKA_USE_COOKIE) {
		path = (path_t *)path_cookie;
		mutex_enter(&path->mutex);
	} else {
		path = lookup_path(adapter_name, instance,  remote_node,
		    remote_hwaddr);

		/*
		 * remember, lookup_path increments the reference
		 * count - so decrement now so we can get to zero
		 */
		PATH_RELE_NOLOCK(path);
	}

	DBG_PRINTF((category, RSM_DEBUG,
	    "rsmka_remove_path: path = %lx\n", path));

	while (path->state == RSMKA_PATH_GOING_DOWN)
		cv_wait(&path->hold_cv, &path->mutex);

	/* attempt to cancel any possibly pending work */
	mutex_enter(&work_queue.work_mutex);
	if (cancel_work(&path->work_token[RSMKA_IPC_UP_INDEX])) {
		PATH_RELE_NOLOCK(path);
	}
	if (cancel_work(&path->work_token[RSMKA_IPC_DOWN_INDEX])) {
		PATH_RELE_NOLOCK(path);
	}
	mutex_exit(&work_queue.work_mutex);

	/*
	 * The path descriptor ref cnt was set to 1 initially when
	 * the path was added.  So we need to do a decrement here to
	 * balance that.
	 */
	PATH_RELE_NOLOCK(path);

	switch (path->state) {
	case RSMKA_PATH_UP:
		/* clear the flag */
		path->flags &= ~RSMKA_SQCREATE_PENDING;
		path->state = RSMKA_PATH_DOWN;
		break;
	case RSMKA_PATH_DOWN:
		break;

	case RSMKA_PATH_ACTIVE:
		/*
		 * rsmka_remove_path should not call do_path_down
		 * with the RSMKA_NO_SLEEP flag set since for
		 * this code path, the deferred work would
		 * incorrectly do a PATH_RELE_NOLOCK.
		 */
		do_path_down(path, 0);
		break;
	default:
		mutex_exit(&path->mutex);
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_remove_path: invalid path state %d\n",
		    path->state));
		return;

	}

	/*
	 * wait for all references to the path to be released. If a thread
	 * was waiting to receive credits do_path_down should wake it up
	 * since the path is going down and that will cause the sleeping
	 * thread to release its hold on the path.
	 */
	while (path->ref_cnt != 0) {
		cv_wait(&path->hold_cv, &path->mutex);
	}

	mutex_exit(&path->mutex);

	/*
	 * remove from ipc token list
	 * NOTE: use the remote_node value from the path structure
	 * since for RSMKA_USE_COOKIE being set, the remote_node
	 * value passed into rsmka_remove_path is 0.
	 */
	unlink_sendq_token(&path->sendq_token, path->remote_node);

	/* unlink from adapter path list and free path descriptor */
	destroy_path(path);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmka_remove_path done\n"));
}

/*
 *
 * LOCKING:
 * lookup_path locks the path and increments the path hold count. If the remote
 * node is not in the alive state, do_path_up will release the lock and
 * decrement the hold count.  Otherwise rsmka_do_path_active will release the
 * lock prior to waking up the work thread.
 *
 * REF_CNT:
 * The path descriptor ref_cnt is incremented here; it will be decremented
 * when path up processing is completed in do_path_up or by the work thread
 * if the path up is deferred.
 *
 */
boolean_t
rsmka_path_up(char *adapter_name, uint_t adapter_instance,
    rsm_node_id_t remote_node, rsm_addr_t remote_hwaddr,
    void *path_cookie, int flags)
{

	path_t			*path;
	boolean_t		rval = B_TRUE;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmka_path_up enter\n"));

	if (flags & RSMKA_USE_COOKIE) {
		path = (path_t *)path_cookie;
		mutex_enter(&path->mutex);
		PATH_HOLD_NOLOCK(path);
	} else {
		path = lookup_path(adapter_name, adapter_instance,
		    remote_node, remote_hwaddr);
	}

	while (path->state == RSMKA_PATH_GOING_DOWN)
		cv_wait(&path->hold_cv, &path->mutex);

	DBG_PRINTF((category, RSM_DEBUG, "rsmka_path_up: path = %lx\n", path));
	rval = do_path_up(path, flags);
	mutex_exit(&path->mutex);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmka_path_up done\n"));
	return (rval);
}

/*
 *
 * LOCKING:
 * lookup_path locks the path and increments the path hold count. If the
 * current state is ACTIVE the path lock is release prior to waking up
 * the work thread in do_path_down .  The work thread will decrement the hold
 * count when the work for this is finished.
 *
 *
 * REF_CNT:
 * The path descriptor ref_cnt is incremented here; it will be decremented
 * when path down processing is completed in do_path_down or by the work thread
 * if the path down is deferred.
 *
 */
boolean_t
rsmka_path_down(char *adapter_devname, int instance, rsm_node_id_t remote_node,
    rsm_addr_t remote_hwaddr,  void *path_cookie, int flags)
{
	path_t			*path;
	boolean_t		rval = B_TRUE;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmka_path_down enter\n"));

	if (flags & RSMKA_USE_COOKIE) {
		path = (path_t *)path_cookie;
		mutex_enter(&path->mutex);
		PATH_HOLD_NOLOCK(path);
	} else {
		path = lookup_path(adapter_devname, instance, remote_node,
		    remote_hwaddr);
	}

	while (path->state == RSMKA_PATH_GOING_DOWN)
		cv_wait(&path->hold_cv, &path->mutex);

	DBG_PRINTF((category, RSM_DEBUG,
	    "rsmka_path_down: path = %lx\n", path));

	switch (path->state) {
	case RSMKA_PATH_UP:
		/* clear the flag */
		path->flags &= ~RSMKA_SQCREATE_PENDING;
		path->state = RSMKA_PATH_GOING_DOWN;
		mutex_exit(&path->mutex);

		/*
		 * release path->mutex since enqueued tasks acquire it.
		 * Drain all the enqueued tasks.
		 */
		taskq_wait(path->recv_taskq);

		mutex_enter(&path->mutex);
		path->state = RSMKA_PATH_DOWN;
		PATH_RELE_NOLOCK(path);
		break;
	case RSMKA_PATH_DOWN:
		PATH_RELE_NOLOCK(path);
		break;
	case RSMKA_PATH_ACTIVE:
		do_path_down(path, flags);
		/*
		 * Need to release the path refcnt. Either done in do_path_down
		 * or do_deferred_work for RSMKA_NO_SLEEP being set. Has to be
		 * done here for RSMKA_NO_SLEEP not set.
		 */
		if (!(flags & RSMKA_NO_SLEEP))
			PATH_RELE_NOLOCK(path);
		break;
	default:
		DBG_PRINTF((category, RSM_ERR,
		    "rsm_path_down: invalid path state %d\n", path->state));
		rval = B_FALSE;
	}

	mutex_exit(&path->mutex);
	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmka_path_down done\n"));
	return (rval);
}


/*
 * Paths cannot become active until node_is_alive is marked true
 * in the ipc_info descriptor for the node
 *
 * In the event this is called before any paths have been added,
 * init_ipc_info if called here.
 *
 */
boolean_t
rsmka_node_alive(rsm_node_id_t remote_node)
{
	ipc_info_t *ipc_info;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmka_node_alive enter\n"));

	DBG_PRINTF((category, RSM_DEBUG,
	    "rsmka_node_alive: remote_node = %x\n", remote_node));

	ipc_info = lookup_ipc_info(remote_node);

	if (ipc_info == NULL) {
		ipc_info = init_ipc_info(remote_node, B_TRUE);
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsmka_node_alive: new ipc_info = %lx\n", ipc_info));
	} else {
		ASSERT(ipc_info->node_is_alive == B_FALSE);
		ipc_info->node_is_alive = B_TRUE;
	}

	pathup_to_pathactive(ipc_info, remote_node);

	mutex_exit(&ipc_info_lock);

	/* rsmipc_send() may be waiting for a sendq_token */
	mutex_enter(&ipc_info_cvlock);
	cv_broadcast(&ipc_info_cv);
	mutex_exit(&ipc_info_cvlock);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmka_node_alive done\n"));

	return (B_TRUE);
}



/*
 * Paths cannot become active when node_is_alive is marked false
 * in the ipc_info descriptor for the node
 */
boolean_t
rsmka_node_died(rsm_node_id_t remote_node)
{
	ipc_info_t *ipc_info;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmka_node_died enter\n"));

	DBG_PRINTF((category, RSM_DEBUG,
	    "rsmka_node_died: remote_node = %x\n", remote_node));

	ipc_info = lookup_ipc_info(remote_node);
	if (ipc_info == NULL)
		return (B_FALSE);

	ASSERT(ipc_info->node_is_alive == B_TRUE);
	ipc_info->node_is_alive = B_FALSE;

	rsm_suspend_complete(remote_node, RSM_SUSPEND_NODEDEAD);

	mutex_exit(&ipc_info_lock);

	/* rsmipc_send() may be waiting for a sendq_token */
	mutex_enter(&ipc_info_cvlock);
	cv_broadcast(&ipc_info_cv);
	mutex_exit(&ipc_info_cvlock);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsmka_node_died done\n"));

	return (B_TRUE);
}

/*
 * Treat like path_down for all paths for the specified remote node.
 * Always invoked before node died.
 *
 * NOTE: This routine is not called from the cluster path interface; the
 * rsmka_path_down is called directly for each path.
 */
void
rsmka_disconnect_node(rsm_node_id_t remote_node, int flags)
{
	ipc_info_t	*ipc_info;
	path_t		*path;
	sendq_token_t	*sendq_token;
	work_token_t 	*up_token;
	work_token_t 	*down_token;
	boolean_t	do_work = B_FALSE;
	boolean_t	cancelled = B_FALSE;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_disconnect_node enter\n"));

	DBG_PRINTF((category, RSM_DEBUG,
	    "rsmka_disconnect_node: node = %d\n", remote_node));

	if (flags & RSMKA_NO_SLEEP) {
		ipc_info = lookup_ipc_info(remote_node);

		sendq_token = ipc_info->token_list;

		while (sendq_token != NULL) {
			path = SQ_TOKEN_TO_PATH(sendq_token);
			PATH_HOLD(path);
			up_token = &path->work_token[RSMKA_IPC_UP_INDEX];
			down_token = &path->work_token[RSMKA_IPC_DOWN_INDEX];

			mutex_enter(&work_queue.work_mutex);

			/* if an up token is enqueued, remove it */
			cancelled = cancel_work(up_token);

			/*
			 * If the path is active and down work hasn't
			 * already been setup then down work is needed.
			 * else
			 * if up work wasn't canceled because it was
			 * already being processed then down work is needed
			 */
			if (path->state == RSMKA_PATH_ACTIVE) {
				if (down_token->opcode == 0)
					do_work = B_TRUE;
			} else
				if (up_token->opcode == RSMKA_IPC_UP)
					do_work = B_TRUE;

			if (do_work == B_TRUE) {
				down_token->opcode = RSMKA_IPC_DOWN;
				enqueue_work(down_token);
			}
			mutex_exit(&work_queue.work_mutex);

			if (do_work == B_FALSE)
				PATH_RELE(path);

			if (cancelled) {
				PATH_RELE(path);
			}
			sendq_token = sendq_token->next;
		}

		/*
		 * Now that all the work is enqueued, wakeup the work
		 * thread.
		 */
		mutex_enter(&work_queue.work_mutex);
		cv_signal(&work_queue.work_cv);
		mutex_exit(&work_queue.work_mutex);

		IPCINFO_RELE_NOLOCK(ipc_info);
		mutex_exit(&ipc_info_lock);

	} else {
		/* get locked ipc_info descriptor */
		ipc_info = lookup_ipc_info(remote_node);

		sendq_token = ipc_info->token_list;
		while (sendq_token != NULL) {
			path = SQ_TOKEN_TO_PATH(sendq_token);
			DBG_PRINTF((category, RSM_DEBUG,
			    "rsmka_disconnect_node: path_down"
			    "for path = %x\n",
			    path));
			(void) rsmka_path_down(0, 0, 0, 0,
			    path, RSMKA_USE_COOKIE);
			sendq_token = sendq_token->next;
			if (sendq_token == ipc_info->token_list)
				break;
		}
		mutex_exit(&ipc_info_lock);
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_disconnect_node done\n"));
}


/*
 * Called from rsm_node_alive - if a path to a remote node is in
 * state RSMKA_PATH_UP, transition the state to RSMKA_PATH_ACTIVE with a
 * call to rsmka_do_path_active.
 *
 * REF_CNT:
 * The path descriptor ref_cnt is incremented here; it will be decremented
 * when path up processing is completed in rsmka_do_path_active or by the work
 * thread if the path up is deferred.
 */
static void
pathup_to_pathactive(ipc_info_t *ipc_info, rsm_node_id_t remote_node)
{
	path_t		*path;
	sendq_token_t	*token;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "pathup_to_pathactive enter\n"));

	remote_node = remote_node;

	ASSERT(MUTEX_HELD(&ipc_info_lock));

	token = ipc_info->token_list;
	while (token != NULL) {
		path = SQ_TOKEN_TO_PATH(token);
		mutex_enter(&path->mutex);
		if (path->state == RSMKA_PATH_UP)  {
			PATH_HOLD_NOLOCK(path);
			(void) rsmka_do_path_active(path, 0);
		}
		mutex_exit(&path->mutex);
		token = token->next;
		if (token == ipc_info->token_list)
			break;
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "pathup_to_pathactive done\n"));
}

/*
 * Called from pathup_to_pathactive and do_path_up. The objective is to
 * create an ipc send queue and transition to state RSMKA_PATH_ACTIVE.
 * For the no sleep case we may need to defer the work using a token.
 *
 */
boolean_t
rsmka_do_path_active(path_t *path, int flags)
{
	work_token_t	*up_token = &path->work_token[RSMKA_IPC_UP_INDEX];
	work_token_t	*down_token = &path->work_token[RSMKA_IPC_DOWN_INDEX];
	boolean_t	do_work = B_FALSE;
	int		error;
	timespec_t	tv;
	adapter_t	*adapter;
	rsm_send_q_handle_t	sqhdl;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_do_path_active enter\n"));

	ASSERT(MUTEX_HELD(&path->mutex));

	if (flags & RSMKA_NO_SLEEP) {
		mutex_enter(&work_queue.work_mutex);

		/* if a down token is enqueued, remove it */
		if (cancel_work(down_token)) {
			PATH_RELE_NOLOCK(path);
		}

		/*
		 * If the path is not active and up work hasn't
		 * already been setup then up work is needed.
		 * else
		 * if down work wasn't canceled because it was
		 * already being processed then up work is needed
		 */
		if (path->state != RSMKA_PATH_ACTIVE) {
			if (up_token->opcode == 0)
				do_work = B_TRUE;
		} else
			if (down_token->opcode == RSMKA_IPC_DOWN)
				do_work = B_TRUE;

		if (do_work == B_TRUE) {
			up_token->opcode = RSMKA_IPC_UP;
			enqueue_work(up_token);
		}
		else
			PATH_RELE_NOLOCK(path);

		mutex_exit(&work_queue.work_mutex);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmka_do_path_active done\n"));
		return (B_TRUE);
	} else {
		/*
		 * Drop the path lock before calling create_ipc_sendq, shouldn't
		 * hold locks across calls to RSMPI routines.
		 */
		mutex_exit(&path->mutex);

		error = create_ipc_sendq(path);

		mutex_enter(&path->mutex);
		if (path->state != RSMKA_PATH_UP) {
			/*
			 * path state has changed, if sendq was created,
			 * destroy it and return
			 */
			if (error == RSM_SUCCESS) {
				sqhdl = path->sendq_token.rsmpi_sendq_handle;
				path->sendq_token.rsmpi_sendq_handle = NULL;
				adapter = path->local_adapter;
				mutex_exit(&path->mutex);

				if (sqhdl != NULL) {
					adapter->rsmpi_ops->rsm_sendq_destroy(
					    sqhdl);
				}
				mutex_enter(&path->mutex);
			}
			PATH_RELE_NOLOCK(path);

			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "rsmka_do_path_active done: path=%lx not UP\n",
			    (uintptr_t)path));
			return (error ? B_FALSE : B_TRUE);
		}

		if (error == RSM_SUCCESS) {
			/* clear flag since sendq_create succeeded */
			path->flags &= ~RSMKA_SQCREATE_PENDING;
			path->state = RSMKA_PATH_ACTIVE;
			/*
			 * now that path is active we send the
			 * RSMIPC_MSG_SQREADY to the remote endpoint
			 */
			path->procmsg_cnt = 0;
			path->sendq_token.msgbuf_avail = 0;

			/* Calculate local incarnation number */
			gethrestime(&tv);
			if (tv.tv_sec == RSM_UNKNOWN_INCN)
				tv.tv_sec = 1;
			path->local_incn = (int64_t)tv.tv_sec;

			/*
			 * if send fails here its due to some non-transient
			 * error because QUEUE_FULL is not possible here since
			 * we are the first message on this sendq. The error
			 * will cause the path to go down anyways so ignore
			 * the return value
			 */
			(void) rsmipc_send_controlmsg(path, RSMIPC_MSG_SQREADY);
			/* wait for SQREADY_ACK message */
			path->flags |= RSMKA_WAIT_FOR_SQACK;

			DBG_PRINTF((category, RSM_DEBUG,
			    "rsmka_do_path_active success\n"));
		} else {
			/*
			 * sendq create failed possibly because
			 * the remote end is not yet ready eg.
			 * handler not registered, set a flag
			 * so that when there is an indication
			 * that the remote end is ready rsmka_do_path_active
			 * will be retried.
			 */
			path->flags |= RSMKA_SQCREATE_PENDING;
		}

		PATH_RELE_NOLOCK(path);

		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmka_do_path_active done\n"));
		return (error ? B_FALSE : B_TRUE);
	}

}

/*
 * Called from rsm_path_up.
 * If the remote node state is "alive" then call rsmka_do_path_active
 * otherwise just transition path state to RSMKA_PATH_UP.
 */
static boolean_t
do_path_up(path_t *path, int flags)
{
	boolean_t	rval;
	boolean_t	node_alive;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "do_path_up enter\n"));

	ASSERT(MUTEX_HELD(&path->mutex));

	/* path moved to ACTIVE by rsm_sqcreateop_callback - just return */
	if (path->state == RSMKA_PATH_ACTIVE) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "do_path_up done: already ACTIVE\n"));
		PATH_RELE_NOLOCK(path);
		return (B_TRUE);
	}

	path->state = RSMKA_PATH_UP;

	/* initialize the receive msgbuf counters */
	path->msgbuf_head = 0;
	path->msgbuf_tail = RSMIPC_MAX_MESSAGES - 1;
	path->msgbuf_cnt = 0;
	path->procmsg_cnt = 0;
	/*
	 * rsmka_check_node_alive acquires ipc_info_lock, in order to maintain
	 * correct lock ordering drop the path lock before calling it.
	 */
	mutex_exit(&path->mutex);

	node_alive = rsmka_check_node_alive(path->remote_node);

	mutex_enter(&path->mutex);
	if (node_alive == B_TRUE)
		rval = rsmka_do_path_active(path, flags);
	else {
		PATH_RELE_NOLOCK(path);
		rval = B_TRUE;
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "do_path_up done\n"));
	return (rval);
}



/*
 * Called from rsm_remove_path, rsm_path_down, deferred_work.
 * Destroy the send queue on this path.
 * Disconnect segments being imported from the remote node
 * Disconnect segments being imported by the remote node
 *
 */
static void
do_path_down(path_t *path, int flags)
{
	work_token_t *up_token = &path->work_token[RSMKA_IPC_UP_INDEX];
	work_token_t *down_token = &path->work_token[RSMKA_IPC_DOWN_INDEX];
	boolean_t do_work = B_FALSE;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "do_path_down enter\n"));

	ASSERT(MUTEX_HELD(&path->mutex));

	if (flags & RSMKA_NO_SLEEP) {
		mutex_enter(&work_queue.work_mutex);
		DBG_PRINTF((category, RSM_DEBUG,
		    "do_path_down: after work_mutex\n"));

		/* if an up token is enqueued, remove it */
		if (cancel_work(up_token)) {
			PATH_RELE_NOLOCK(path);
		}

		/*
		 * If the path is active and down work hasn't
		 * already been setup then down work is needed.
		 * else
		 * if up work wasn't canceled because it was
		 * already being processed then down work is needed
		 */
		if (path->state == RSMKA_PATH_ACTIVE) {
			if (down_token->opcode == 0)
				do_work = B_TRUE;
		} else
			if (up_token->opcode == RSMKA_IPC_UP)
				do_work = B_TRUE;

		if (do_work == B_TRUE) {
			down_token->opcode = RSMKA_IPC_DOWN;
			enqueue_work(down_token);
		} else
			PATH_RELE_NOLOCK(path);


		mutex_exit(&work_queue.work_mutex);

	} else {

		/*
		 * Change state of the path to RSMKA_PATH_GOING_DOWN and
		 * release the path mutex. Any other thread referring
		 * this path would cv_wait till the state of the path
		 * remains RSMKA_PATH_GOING_DOWN.
		 * On completing the path down processing, change the
		 * state of RSMKA_PATH_DOWN indicating that the path
		 * is indeed down.
		 */
		path->state = RSMKA_PATH_GOING_DOWN;

		/*
		 * clear the WAIT_FOR_SQACK flag since path is going down.
		 */
		path->flags &= ~RSMKA_WAIT_FOR_SQACK;

		/*
		 * this wakes up any thread waiting to receive credits
		 * in rsmipc_send to tell it that the path is going down
		 */
		cv_broadcast(&path->sendq_token.sendq_cv);

		mutex_exit(&path->mutex);

		/*
		 * drain the messages from the receive msgbuf, the
		 * tasks in the taskq_thread acquire the path->mutex
		 * so we drop the path mutex before taskq_wait.
		 */
		taskq_wait(path->recv_taskq);

		/*
		 * Disconnect segments being imported from the remote node
		 * The path_importer_disconnect function needs to be called
		 * only after releasing the mutex on the path. This is to
		 * avoid a recursive mutex enter when doing the
		 * rsmka_get_sendq_token.
		 */
		path_importer_disconnect(path);

		/*
		 * Get the path mutex, change the state of the path to
		 * RSMKA_PATH_DOWN since the path down processing has
		 * completed and cv_signal anyone who was waiting since
		 * the state was RSMKA_PATH_GOING_DOWN.
		 * NOTE: Do not do a mutex_exit here. We entered this
		 * routine with the path lock held by the caller. The
		 * caller eventually releases the path lock by doing a
		 * mutex_exit.
		 */
		mutex_enter(&path->mutex);

#ifdef DEBUG
		/*
		 * Some IPC messages left in the recv_buf,
		 * they'll be dropped
		 */
		if (path->msgbuf_cnt != 0)
			cmn_err(CE_NOTE, "path=%lx msgbuf_cnt != 0\n",
			    (uintptr_t)path);
#endif
		while (path->sendq_token.ref_cnt != 0)
			cv_wait(&path->sendq_token.sendq_cv,
			    &path->mutex);

		/* release the rsmpi handle */
		if (path->sendq_token.rsmpi_sendq_handle != NULL)
			path->local_adapter->rsmpi_ops->rsm_sendq_destroy(
			    path->sendq_token.rsmpi_sendq_handle);

		path->sendq_token.rsmpi_sendq_handle = NULL;

		path->state = RSMKA_PATH_DOWN;

		cv_signal(&path->hold_cv);

	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "do_path_down done\n"));

}

/*
 * Search through the list of imported segments for segments using this path
 * and unload the memory mappings for each one.  The application will
 * get an error return when a barrier close is invoked.
 * NOTE: This function has to be called only after releasing the mutex on
 * the path. This is to avoid any recursive mutex panics on the path mutex
 * since the path_importer_disconnect function would end up calling
 * rsmka_get_sendq_token which requires the path mutex.
 */

static void
path_importer_disconnect(path_t *path)
{
	int i;
	adapter_t *adapter = path->local_adapter;
	rsm_node_id_t remote_node = path->remote_node;
	rsmresource_t		*p = NULL;
	rsmseg_t *seg;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "path_importer_disconnect enter\n"));

	rw_enter(&rsm_import_segs.rsmhash_rw, RW_READER);

	if (rsm_import_segs.bucket != NULL) {
		for (i = 0; i < rsm_hash_size; i++) {
			p = rsm_import_segs.bucket[i];
			for (; p; p = p->rsmrc_next) {
				if ((p->rsmrc_node == remote_node) &&
				    (p->rsmrc_adapter == adapter)) {
					seg = (rsmseg_t *)p;
			/*
			 * In order to make rsmseg_unload and
			 * path_importer_disconnect thread safe, acquire the
			 * segment lock here. rsmseg_unload is responsible for
			 * releasing the lock. rsmseg_unload releases the lock
			 * just before a call to rsmipc_send or in case of an
			 * early exit which occurs if the segment was in the
			 * state RSM_STATE_CONNECTING or RSM_STATE_NEW.
			 */
					rsmseglock_acquire(seg);
					seg->s_flags |= RSM_FORCE_DISCONNECT;
					rsmseg_unload(seg);
				}
			}
		}
	}
	rw_exit(&rsm_import_segs.rsmhash_rw);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "path_importer_disconnect done\n"));
}




/*
 *
 * ADAPTER UTILITY FUNCTIONS
 *
 */



/*
 * Allocate new adapter list head structure and add it to the beginning of
 * the list of adapter list heads.  There is one list for each adapter
 * device name (or type).
 */
static adapter_listhead_t *
init_listhead(char *name)
{
	adapter_listhead_t *listhead;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "init_listhead enter\n"));

	/* allocation and initialization */
	listhead = kmem_zalloc(sizeof (adapter_listhead_t), KM_SLEEP);
	mutex_init(&listhead->mutex, NULL, MUTEX_DEFAULT, NULL);
	(void) strcpy(listhead->adapter_devname, name);

	/* link into list of listheads */
	mutex_enter(&adapter_listhead_base.listlock);
	if (adapter_listhead_base.next == NULL) {
		adapter_listhead_base.next = listhead;
		listhead->next_listhead = NULL;
	} else {
		listhead->next_listhead = adapter_listhead_base.next;
		adapter_listhead_base.next = listhead;
	}
	mutex_exit(&adapter_listhead_base.listlock);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "init_listhead done\n"));

	return (listhead);
}


/*
 * Search the list of adapter list heads for a match on name.
 *
 */
static adapter_listhead_t *
lookup_adapter_listhead(char *name)
{
	adapter_listhead_t *listhead;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "lookup_adapter_listhead enter\n"));

	mutex_enter(&adapter_listhead_base.listlock);
	listhead = adapter_listhead_base.next;
	while (listhead != NULL) {
		if (strcmp(name, listhead->adapter_devname) == 0)
			break;
		listhead = listhead->next_listhead;
	}
	mutex_exit(&adapter_listhead_base.listlock);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "lookup_adapter_listhead done\n"));

	return (listhead);
}


/*
 * Get the adapter list head corresponding to devname and search for
 * an adapter descriptor with a match on the instance number. If
 * successful, increment the descriptor reference count and return
 * the descriptor pointer to the caller.
 *
 */
adapter_t *
rsmka_lookup_adapter(char *devname, int instance)
{
	adapter_listhead_t *listhead;
	adapter_t *current = NULL;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_lookup_adapter enter\n"));

	listhead = lookup_adapter_listhead(devname);
	if (listhead != NULL) {
		mutex_enter(&listhead->mutex);

		current = listhead->next_adapter;
		while (current != NULL) {
			if (current->instance == instance) {
				ADAPTER_HOLD(current);
				break;
			} else
				current = current->next;
		}

		mutex_exit(&listhead->mutex);
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_lookup_adapter done\n"));

	return (current);
}

/*
 * Called from rsmka_remove_adapter or rsmseg_free.
 * rsm_bind() and rsm_connect() store the adapter pointer returned
 * from rsmka_getadapter.  The pointer is kept in the segment descriptor.
 * When the segment is freed, this routine is called by rsmseg_free to decrement
 * the adapter descriptor reference count and possibly free the
 * descriptor.
 */
void
rsmka_release_adapter(adapter_t *adapter)
{
	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_release_adapter enter\n"));

	if (adapter == &loopback_adapter) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmka_release_adapter done\n"));
		return;
	}

	mutex_enter(&adapter->mutex);

	/* decrement reference count */
	ADAPTER_RELE_NOLOCK(adapter);

	/*
	 * if the adapter descriptor reference count is equal to the
	 * initialization value of one, then the descriptor has been
	 * unlinked and can now be freed.
	 */
	if (adapter->ref_cnt == 1) {
		mutex_exit(&adapter->mutex);

		mutex_destroy(&adapter->mutex);
		kmem_free(adapter->hdlr_argp, sizeof (srv_handler_arg_t));
		kmem_free(adapter, sizeof (adapter_t));
	}
	else
		mutex_exit(&adapter->mutex);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_release_adapter done\n"));

}



/*
 * Singly linked list. Add to the front.
 */
static void
link_adapter(adapter_t *adapter)
{

	adapter_listhead_t *listhead;
	adapter_t *current;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "link_adapter enter\n"));

	mutex_enter(&adapter_listhead_base.listlock);

	mutex_enter(&adapter->listhead->mutex);

	listhead = adapter->listhead;
	current = listhead->next_adapter;
	listhead->next_adapter = adapter;
	adapter->next = current;
	ADAPTER_HOLD(adapter);

	adapter->listhead->adapter_count++;

	mutex_exit(&adapter->listhead->mutex);

	mutex_exit(&adapter_listhead_base.listlock);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "link_adapter done\n"));
}


/*
 * Return adapter descriptor
 *
 * lookup_adapter_listhead returns with the the list of adapter listheads
 * locked.  After adding the adapter descriptor, the adapter listhead list
 * lock is dropped.
 */
static adapter_t *
init_adapter(char *name, int instance, rsm_addr_t hwaddr,
    rsm_controller_handle_t handle, rsm_ops_t *ops,
    srv_handler_arg_t *hdlr_argp)
{
	adapter_t *adapter;
	adapter_listhead_t *listhead;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "init_adapter enter\n"));

	adapter = kmem_zalloc(sizeof (adapter_t), KM_SLEEP);
	adapter->instance = instance;
	adapter->hwaddr = hwaddr;
	adapter->rsmpi_handle = handle;
	adapter->rsmpi_ops = ops;
	adapter->hdlr_argp = hdlr_argp;
	mutex_init(&adapter->mutex, NULL, MUTEX_DEFAULT, NULL);
	ADAPTER_HOLD(adapter);


	listhead = lookup_adapter_listhead(name);
	if (listhead == NULL)  {
		listhead = init_listhead(name);
	}

	adapter->listhead = listhead;

	link_adapter(adapter);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "init_adapter done\n"));

	return (adapter);
}

/*
 *
 * PATH UTILITY FUNCTIONS
 *
 */


/*
 * Search the per adapter path list for a match on remote node and
 * hwaddr.  The path ref_cnt must be greater than zero or the path
 * is in the process of being removed.
 *
 * Acquire the path lock and increment the path hold count.
 */
static path_t *
lookup_path(char *adapter_devname, int adapter_instance,
    rsm_node_id_t remote_node, rsm_addr_t hwaddr)
{
	path_t		*current;
	adapter_t	*adapter;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "lookup_path enter\n"));

	adapter = rsmka_lookup_adapter(adapter_devname, adapter_instance);
	ASSERT(adapter != NULL);

	mutex_enter(&adapter->listhead->mutex);

	/* start at the list head */
	current = adapter->next_path;

	while (current != NULL) {
		if ((current->remote_node == remote_node) &&
		    (current->remote_hwaddr == hwaddr) &&
		    (current->ref_cnt > 0))
			break;
		else
			current = current->next_path;
	}
	if (current != NULL) {
		mutex_enter(&current->mutex);
		PATH_HOLD_NOLOCK(current);
	}

	mutex_exit(&adapter->listhead->mutex);
	ADAPTER_RELE(adapter);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "lookup_path done\n"));

	return (current);
}

/*
 * This interface is similar to lookup_path but takes only the local
 * adapter name, instance and remote adapters hwaddr to identify the
 * path. This is used in the interrupt handler routines where nodeid
 * is not always available.
 */
path_t *
rsm_find_path(char *adapter_devname, int adapter_instance, rsm_addr_t hwaddr)
{
	path_t		*current;
	adapter_t	*adapter;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_find_path enter\n"));

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsm_find_path:adapter=%s:%d,rem=%llx\n",
	    adapter_devname, adapter_instance, hwaddr));

	adapter = rsmka_lookup_adapter(adapter_devname, adapter_instance);

	/*
	 * its possible that we are here due to an interrupt but the adapter
	 * has been removed after we received the callback.
	 */
	if (adapter == NULL)
		return (NULL);

	mutex_enter(&adapter->listhead->mutex);

	/* start at the list head */
	current = adapter->next_path;

	while (current != NULL) {
		if ((current->remote_hwaddr == hwaddr) &&
		    (current->ref_cnt > 0))
			break;
		else
			current = current->next_path;
	}
	if (current != NULL) {
		mutex_enter(&current->mutex);
		PATH_HOLD_NOLOCK(current);
	}

	mutex_exit(&adapter->listhead->mutex);

	rsmka_release_adapter(adapter);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rsm_find_path done\n"));

	return (current);
}


/*
 * Add the path to the head of the (per adapter) list of paths
 */
static void
link_path(path_t *path)
{

	adapter_t *adapter = path->local_adapter;
	path_t *first_path;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "link_path enter\n"));

	mutex_enter(&adapter_listhead_base.listlock);

	mutex_enter(&adapter->listhead->mutex);

	first_path = adapter->next_path;
	adapter->next_path = path;
	path->next_path = first_path;

	adapter->listhead->path_count++;

	mutex_exit(&adapter->listhead->mutex);

	mutex_exit(&adapter_listhead_base.listlock);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "link_path done\n"));
}

/*
 * Search the per-adapter list of paths for the specified path, beginning
 * at the head of the list.  Unlink the path and free the descriptor
 * memory.
 */
static void
destroy_path(path_t *path)
{

	adapter_t *adapter = path->local_adapter;
	path_t *prev, *current;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "destroy_path enter\n"));

	mutex_enter(&adapter_listhead_base.listlock);

	mutex_enter(&path->local_adapter->listhead->mutex);
	ASSERT(path->ref_cnt == 0);

	/* start at the list head */
	prev = NULL;
	current =  adapter->next_path;

	while (current != NULL) {
		if (path->remote_node == current->remote_node &&
		    path->remote_hwaddr == current->remote_hwaddr)
			break;
		else {
			prev = current;
			current = current->next_path;
		}
	}

	if (prev == NULL)
		adapter->next_path = current->next_path;
	else
		prev->next_path = current->next_path;

	path->local_adapter->listhead->path_count--;

	mutex_exit(&path->local_adapter->listhead->mutex);

	mutex_exit(&adapter_listhead_base.listlock);

	taskq_destroy(path->recv_taskq);

	kmem_free(path->msgbuf_queue,
	    RSMIPC_MAX_MESSAGES * sizeof (msgbuf_elem_t));

	mutex_destroy(&current->mutex);
	cv_destroy(&current->sendq_token.sendq_cv);
	cv_destroy(&path->hold_cv);
	kmem_free(current, sizeof (path_t));

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "destroy_path done\n"));
}

void
rsmka_enqueue_msgbuf(path_t *path, void *data)
{
	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_enqueue_msgbuf enter\n"));

	ASSERT(MUTEX_HELD(&path->mutex));

	ASSERT(path->msgbuf_cnt < RSMIPC_MAX_MESSAGES);

	/* increment the count and advance the tail */

	path->msgbuf_cnt++;

	if (path->msgbuf_tail == RSMIPC_MAX_MESSAGES - 1) {
		path->msgbuf_tail = 0;
	} else {
		path->msgbuf_tail++;
	}

	path->msgbuf_queue[path->msgbuf_tail].active = B_TRUE;

	bcopy(data, &(path->msgbuf_queue[path->msgbuf_tail].msg),
	    sizeof (rsmipc_request_t));

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_enqueue_msgbuf done\n"));

}

/*
 * get the head of the queue using rsmka_gethead_msgbuf and then call
 * rsmka_dequeue_msgbuf to remove it.
 */
void
rsmka_dequeue_msgbuf(path_t *path)
{
	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_dequeue_msgbuf enter\n"));

	ASSERT(MUTEX_HELD(&path->mutex));

	if (path->msgbuf_cnt == 0)
		return;

	path->msgbuf_cnt--;

	path->msgbuf_queue[path->msgbuf_head].active = B_FALSE;

	if (path->msgbuf_head == RSMIPC_MAX_MESSAGES - 1) {
		path->msgbuf_head = 0;
	} else {
		path->msgbuf_head++;
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_dequeue_msgbuf done\n"));

}

msgbuf_elem_t *
rsmka_gethead_msgbuf(path_t *path)
{
	msgbuf_elem_t	*head;

	ASSERT(MUTEX_HELD(&path->mutex));

	if (path->msgbuf_cnt == 0)
		return (NULL);

	head = &path->msgbuf_queue[path->msgbuf_head];

	return (head);

}
/*
 * Called by rsm_connect which needs the hardware address of the
 * remote adapter.  A search is done through the paths for the local
 * adapter for a match on the specified remote node.
 */
rsm_node_id_t
get_remote_nodeid(adapter_t *adapter, rsm_addr_t remote_hwaddr)
{

	rsm_node_id_t remote_node;
	path_t	   *current = adapter->next_path;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "get_remote_nodeid enter\n"));

	mutex_enter(&adapter->listhead->mutex);
	while (current != NULL) {
		if (current->remote_hwaddr == remote_hwaddr) {
			remote_node = current->remote_node;
			break;
		}
		current = current->next_path;
	}

	if (current == NULL)
		remote_node = (rsm_node_id_t)-1;

	mutex_exit(&adapter->listhead->mutex);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "get_remote_nodeid done\n"));

	return (remote_node);
}

/*
 * Called by rsm_connect which needs the hardware address of the
 * remote adapter.  A search is done through the paths for the local
 * adapter for a match on the specified remote node.
 */
rsm_addr_t
get_remote_hwaddr(adapter_t *adapter, rsm_node_id_t remote_node)
{

	rsm_addr_t remote_hwaddr;
	path_t	   *current = adapter->next_path;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "get_remote_hwaddr enter\n"));

	mutex_enter(&adapter->listhead->mutex);
	while (current != NULL) {
		if (current->remote_node == remote_node) {
			remote_hwaddr = current->remote_hwaddr;
			break;
		}
		current = current->next_path;
	}
	if (current == NULL)
		remote_hwaddr = -1;
	mutex_exit(&adapter->listhead->mutex);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "get_remote_hwaddr done\n"));

	return (remote_hwaddr);
}
/*
 * IPC UTILITY FUNCTIONS
 */


/*
 * If an entry exists, return with the ipc_info_lock held
 */
static ipc_info_t *
lookup_ipc_info(rsm_node_id_t remote_node)
{
	ipc_info_t  *ipc_info;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "lookup_ipc_info enter\n"));

	mutex_enter(&ipc_info_lock);

	ipc_info = ipc_info_head;
	if (ipc_info == NULL) {
		mutex_exit(&ipc_info_lock);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "lookup_ipc_info done: ipc_info is NULL\n"));
		return (NULL);
	}

	while (ipc_info->remote_node != remote_node) {
		ipc_info = ipc_info->next;
		if (ipc_info == NULL) {
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "lookup_ipc_info: ipc_info not found\n"));
			mutex_exit(&ipc_info_lock);
			break;
		}
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "lookup_ipc_info done\n"));

	return (ipc_info);
}

/*
 * Create an ipc_info descriptor and return with ipc_info_lock held
 */
static ipc_info_t *
init_ipc_info(rsm_node_id_t remote_node, boolean_t state)
{
	ipc_info_t *ipc_info;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "init_ipc_info enter\n"));

	/*
	 * allocate an ipc_info descriptor and add it to a
	 * singly linked list
	 */

	ipc_info = kmem_zalloc(sizeof (ipc_info_t), KM_SLEEP);
	ipc_info->remote_node = remote_node;
	ipc_info->node_is_alive = state;

	mutex_enter(&ipc_info_lock);
	if (ipc_info_head == NULL) {
		DBG_PRINTF((category, RSM_DEBUG,
		    "init_ipc_info:ipc_info_head = %lx\n", ipc_info));
		ipc_info_head = ipc_info;
		ipc_info->next = NULL;
	} else {
		ipc_info->next = ipc_info_head;
		ipc_info_head = ipc_info;
	}

	ipc_info->remote_node = remote_node;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "init_ipc_info done\n"));

	return (ipc_info);
}

static void
destroy_ipc_info(ipc_info_t *ipc_info)
{
	ipc_info_t *current = ipc_info_head;
	ipc_info_t *prev;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "destroy_ipc_info enter\n"));

	ASSERT(MUTEX_HELD(&ipc_info_lock));

	while (current != ipc_info) {
		prev = current;
		current = current->next;
	}
	ASSERT(current != NULL);

	if (current != ipc_info_head)
		prev->next = current->next;
	else
		ipc_info_head = current->next;

	kmem_free(current, sizeof (ipc_info_t));

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "destroy_ipc_info done\n"));

}

/*
 * Sendq tokens are kept on a circular list.  If tokens A, B, C, & D are
 * on the list headed by ipc_info, then ipc_info points to A, A points to
 * D, D to C, C to B, and B to A.
 */
static void
link_sendq_token(sendq_token_t *token, rsm_node_id_t remote_node)
{
	ipc_info_t *ipc_info;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "link_sendq_token enter\n"));

	ipc_info = lookup_ipc_info(remote_node);
	if (ipc_info == NULL) {
		ipc_info = init_ipc_info(remote_node, B_FALSE);
		DBG_PRINTF((category, RSM_DEBUG,
		    "link_sendq_token: new ipc_info = %lx\n", ipc_info));
	}
	else
		DBG_PRINTF((category, RSM_DEBUG,
		    "link_sendq_token: ipc_info = %lx\n", ipc_info));

	if (ipc_info->token_list == NULL) {
		ipc_info->token_list = token;
		ipc_info->current_token = token;
		DBG_PRINTF((category, RSM_DEBUG,
		    "link_sendq_token: current = %lx\n", token));
		token->next = token;
	} else {
		DBG_PRINTF((category, RSM_DEBUG,
		    "link_sendq_token: token = %lx\n", token));
		token->next = ipc_info->token_list->next;
		ipc_info->token_list->next = token;
		ipc_info->token_list = token;
	}


	mutex_exit(&ipc_info_lock);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "link_sendq_token done\n"));

}

static void
unlink_sendq_token(sendq_token_t *token, rsm_node_id_t remote_node)
{
	sendq_token_t *prev, *start,  *current;
	ipc_info_t *ipc_info;
	path_t *path = SQ_TOKEN_TO_PATH(token);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "unlink_sendq_token enter\n"));

	ASSERT(path->ref_cnt == 0);

	ipc_info = lookup_ipc_info(remote_node);
	if (ipc_info == NULL) {
		DBG_PRINTF((category, RSM_DEBUG,
		    "ipc_info for %d not found\n", remote_node));
		return;
	}

	prev = ipc_info->token_list;
	start = current = ipc_info->token_list->next;

	for (;;) {
		if (current == token) {
			if (current->next != current) {
				DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
				    "found token, removed it\n"));
				prev->next = token->next;
				if (ipc_info->token_list == token)
					ipc_info->token_list = prev;
				ipc_info->current_token = token->next;
			} else {
				/* list will be empty  */
				DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
				    "removed token, list empty\n"));
				ipc_info->token_list = NULL;
				ipc_info->current_token = NULL;
			}
			break;
		}
		prev = current;
		current = current->next;
		if (current == start) {
			DBG_PRINTF((category, RSM_DEBUG,
			    "unlink_sendq_token: token not found\n"));
			break;
		}
	}
	mutex_exit(&ipc_info_lock);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "unlink_sendq_token done\n"));
}


void
rele_sendq_token(sendq_token_t *token)
{
	path_t *path;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rele_sendq_token enter\n"));

	path = SQ_TOKEN_TO_PATH(token);
	mutex_enter(&path->mutex);
	PATH_RELE_NOLOCK(path);
	SENDQ_TOKEN_RELE(path);
	mutex_exit(&path->mutex);

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "rele_sendq_token done\n"));

}

/*
 * A valid ipc token can only be returned if the remote node is alive.
 * Tokens are on a circular list.  Starting with the current token
 * search for a token with an endpoint in state RSM_PATH_ACTIVE.
 * rsmipc_send which calls rsmka_get_sendq_token expects that if there are
 * multiple paths available between a node-pair then consecutive calls from
 * a particular invocation of rsmipc_send will return a sendq that is
 * different from the one that was used in the previous iteration. When
 * prev_used is NULL it indicates that this is the first interation in a
 * specific rsmipc_send invocation.
 *
 * Updating the current token provides round robin selection and this
 * is done only in the first iteration ie. when prev_used is NULL
 */
sendq_token_t *
rsmka_get_sendq_token(rsm_node_id_t remote_node, sendq_token_t *prev_used)
{
	sendq_token_t *token, *first_token;
	path_t *path;
	ipc_info_t *ipc_info;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
	    "rsmka_get_sendq_token enter\n"));

	ipc_info = lookup_ipc_info(remote_node);
	if (ipc_info == NULL) {
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmka_get_sendq_token done: ipc_info is NULL\n"));
		return (NULL);
	}

	if (ipc_info->node_is_alive == B_TRUE) {
		token = first_token = ipc_info->current_token;
		if (token == NULL) {
			mutex_exit(&ipc_info_lock);
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "rsmka_get_sendq_token done: token=NULL\n"));
			return (NULL);
		}

		for (;;) {
			path = SQ_TOKEN_TO_PATH(token);
			DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
			    "path %lx\n", path));
			mutex_enter(&path->mutex);
			if (path->state != RSMKA_PATH_ACTIVE ||
			    path->ref_cnt == 0) {
				mutex_exit(&path->mutex);
			} else {
				if (token != prev_used) {
					/* found a new token */
					break;
				}
				mutex_exit(&path->mutex);
			}

			token = token->next;
			if (token == first_token) {
				/*
				 * we didn't find a new token reuse prev_used
				 * if the corresponding path is still up
				 */
				if (prev_used) {
					path = SQ_TOKEN_TO_PATH(prev_used);
					DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
					    "path %lx\n", path));
					mutex_enter(&path->mutex);
					if (path->state != RSMKA_PATH_ACTIVE ||
					    path->ref_cnt == 0) {
						mutex_exit(&path->mutex);
					} else {
						token = prev_used;
						break;
					}
				}
				mutex_exit(&ipc_info_lock);
				DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
				    "rsmka_get_sendq_token: token=NULL\n"));
				return (NULL);
			}
		}

		PATH_HOLD_NOLOCK(path);
		SENDQ_TOKEN_HOLD(path);
		if (prev_used == NULL) {
			/* change current_token only the first time */
			ipc_info->current_token = token->next;
		}

		mutex_exit(&path->mutex);
		mutex_exit(&ipc_info_lock);

		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmka_get_sendq_token done\n"));
		return (token);
	} else {
		mutex_exit(&ipc_info_lock);
		DBG_PRINTF((category, RSM_DEBUG_VERBOSE,
		    "rsmka_get_sendq_token done\n"));
		return (NULL);
	}
}



/*
 */
static int
create_ipc_sendq(path_t *path)
{
	int		rval;
	sendq_token_t	*token;
	adapter_t 	*adapter;
	int64_t		srvc_offset;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "create_ipc_sendq enter\n"));

	DBG_PRINTF((category, RSM_DEBUG, "create_ipc_sendq: path = %lx\n",
	    path));

	adapter = path->local_adapter;
	token = &path->sendq_token;

	srvc_offset = path->remote_hwaddr;

	DBG_PRINTF((category, RSM_DEBUG,
	    "create_ipc_sendq: srvc_offset = %lld\n",
	    srvc_offset));

	rval = adapter->rsmpi_ops->rsm_sendq_create(adapter->rsmpi_handle,
	    path->remote_hwaddr,
	    (rsm_intr_service_t)(RSM_SERVICE+srvc_offset),
	    (rsm_intr_pri_t)RSM_PRI, (size_t)RSM_QUEUE_SZ,
	    RSM_INTR_SEND_Q_NO_FENCE,
	    RSM_RESOURCE_SLEEP, NULL, &token->rsmpi_sendq_handle);
	if (rval == RSM_SUCCESS) {
		/* rsmipc_send() may be waiting for a sendq_token */
		mutex_enter(&ipc_info_cvlock);
		cv_broadcast(&ipc_info_cv);
		mutex_exit(&ipc_info_cvlock);
	}

	DBG_PRINTF((category, RSM_DEBUG, "create_ipc_sendq: handle = %lx\n",
	    token->rsmpi_sendq_handle));
	DBG_PRINTF((category, RSM_DEBUG, "create_ipc_sendq: rval = %d\n",
	    rval));
	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "create_ipc_sendq done\n"));

	return (rval);
}


boolean_t
rsmka_check_node_alive(rsm_node_id_t remote_node)
{
	ipc_info_t *ipc_info;

	DBG_PRINTF((category, RSM_DEBUG, "rsmka_check_node_alive enter\n"));

	ipc_info = lookup_ipc_info(remote_node);
	if (ipc_info == NULL) {
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsmka_check_node_alive done: ipc_info NULL\n"));
		return (B_FALSE);
	}

	if (ipc_info->node_is_alive == B_TRUE) {
		mutex_exit(&ipc_info_lock);
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsmka_check_node_alive done: node is alive\n"));
		return (B_TRUE);
	} else {
		mutex_exit(&ipc_info_lock);
		DBG_PRINTF((category, RSM_DEBUG,
		    "rsmka_check_node_alive done: node is not alive\n"));
		return (B_FALSE);
	}
}




/*
 *  TOPOLOGY IOCTL SUPPORT
 */

static uint32_t
get_topology_size(int mode)
{
	uint32_t	topology_size;
	int		pointer_area_size;
	adapter_listhead_t	*listhead;
	int		total_num_of_adapters;
	int		total_num_of_paths;

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "get_topology_size enter\n"));

	/*
	 * Find the total number of adapters and paths by adding up the
	 * individual adapter and path counts from all the listheads
	 */
	total_num_of_adapters = 0;
	total_num_of_paths = 0;
	listhead = adapter_listhead_base.next;
	while (listhead != NULL) {
		total_num_of_adapters += listhead->adapter_count;
		total_num_of_paths += listhead->path_count;
		listhead = listhead->next_listhead;
	}

#ifdef	_MULTI_DATAMODEL
	if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32)
		/*
		 * Add extra 4-bytes to make sure connections header
		 * is double-word aligned
		 */
		pointer_area_size =
		    (total_num_of_adapters + total_num_of_adapters%2) *
		    sizeof (caddr32_t);
	else
		pointer_area_size = total_num_of_adapters * sizeof (caddr_t);
#else	/* _MULTI_DATAMODEL */
	mode = mode;
	pointer_area_size = total_num_of_adapters * sizeof (caddr_t);
#endif	/* _MULTI_DATAMODEL */


	topology_size = sizeof (rsmka_topology_hdr_t) +
	    pointer_area_size +
	    (total_num_of_adapters * sizeof (rsmka_connections_hdr_t)) +
	    (total_num_of_paths * sizeof (rsmka_remote_cntlr_t));

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "get_topology_size done\n"));

	return (topology_size);
}



static void
get_topology(caddr_t arg, char *bufp, int mode)
{

	rsmka_topology_t	*tp = (rsmka_topology_t *)bufp;
	adapter_listhead_t	*listhead;
	adapter_t		*adapter;
	path_t			*path;
	int			cntlr = 0;
	rsmka_connections_t	*connection;
	rsmka_remote_cntlr_t	*rem_cntlr;
	int			total_num_of_adapters;

#ifdef	_MULTI_DATAMODEL
	rsmka_topology32_t	*tp32 = (rsmka_topology32_t *)bufp;
#else
	mode = mode;
#endif	/* _MULTI_DATAMODEL */

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "get_topology enter\n"));

	/*
	 * Find the total number of adapters by adding up the
	 * individual adapter counts from all the listheads
	 */
	total_num_of_adapters = 0;
	listhead = adapter_listhead_base.next;
	while (listhead != NULL) {
		total_num_of_adapters += listhead->adapter_count;
		listhead = listhead->next_listhead;
	}

	/* fill topology header and adjust bufp */
	tp->topology_hdr.local_nodeid = my_nodeid;
	tp->topology_hdr.local_cntlr_count = total_num_of_adapters;
	bufp = (char *)&tp->connections[0];

	/* leave room for connection pointer area */
#ifdef	_MULTI_DATAMODEL
	if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32)
		/* make sure bufp is double-word aligned */
		bufp += (total_num_of_adapters + total_num_of_adapters%2) *
		    sizeof (caddr32_t);
	else
		bufp += total_num_of_adapters * sizeof (caddr_t);
#else	/* _MULTI_DATAMODEL */
	bufp += total_num_of_adapters * sizeof (caddr_t);
#endif	/* _MULTI_DATAMODEL */

	/* fill topology from the adapter and path data */
	listhead = adapter_listhead_base.next;
	while (listhead != NULL) {
		adapter = listhead->next_adapter;
		while (adapter != NULL) {
			/* fill in user based connection pointer */
#ifdef	_MULTI_DATAMODEL
			if ((mode & DATAMODEL_MASK) == DATAMODEL_ILP32) {
				ulong_t delta = (ulong_t)bufp - (ulong_t)tp32;
				caddr32_t userbase = (caddr32_t)((ulong_t)arg &
				    0xffffffff);
				tp32->connections[cntlr++] = userbase + delta;
			} else {
				tp->connections[cntlr++] = arg +
				    (ulong_t)bufp -
				    (ulong_t)tp;
			}
#else	/* _MULTI_DATAMODEL */
				tp->connections[cntlr++] = arg +
				    (ulong_t)bufp -
				    (ulong_t)tp;
#endif	/* _MULTI_DATAMODEL */
			connection = (rsmka_connections_t *)bufp;
			(void) snprintf(connection->hdr.cntlr_name,
			    MAXNAMELEN, "%s%d",
			    listhead->adapter_devname,
			    adapter->instance);
			connection->hdr.local_hwaddr = adapter->hwaddr;
			connection->hdr.remote_cntlr_count = 0;
			bufp += sizeof (rsmka_connections_hdr_t);
			rem_cntlr = (rsmka_remote_cntlr_t *)bufp;
			path = adapter->next_path;
			while (path != NULL) {
				connection->hdr.remote_cntlr_count++;
				rem_cntlr->remote_nodeid = path->remote_node;
				(void) snprintf(rem_cntlr->remote_cntlrname,
				    MAXNAMELEN, "%s%d",
				    listhead->adapter_devname,
				    path->remote_devinst);
				rem_cntlr->remote_hwaddr = path->remote_hwaddr;
				rem_cntlr->connection_state = path->state;
				++rem_cntlr;
				path = path->next_path;
			}
			adapter = adapter->next;
			bufp = (char *)rem_cntlr;
		}
		listhead = listhead->next_listhead;
	}

	DBG_PRINTF((category, RSM_DEBUG_VERBOSE, "get_topology done\n"));

}


/*
 * Called from rsm_ioctl() in rsm.c
 * Make sure there is no possiblity of blocking while holding
 * adapter_listhead_base.lock
 */
int
rsmka_topology_ioctl(caddr_t arg, int cmd, int mode)
{
	uint32_t	topology_size;
	uint32_t 	request_size;
	char		*bufp;
	int		error = RSM_SUCCESS;
	size_t		max_toposize;

	DBG_PRINTF((category | RSM_IOCTL, RSM_DEBUG_VERBOSE,
	    "rsmka_topology_ioctl enter\n"));

	switch (cmd) {
	case RSM_IOCTL_TOPOLOGY_SIZE:
		mutex_enter(&adapter_listhead_base.listlock);
		topology_size = get_topology_size(mode);
		mutex_exit(&adapter_listhead_base.listlock);
		if (ddi_copyout((caddr_t)&topology_size,
		    (caddr_t)arg, sizeof (uint32_t), mode))
			error = RSMERR_BAD_ADDR;
		break;
	case RSM_IOCTL_TOPOLOGY_DATA:
		/*
		 * The size of the buffer which the caller has allocated
		 * is passed in.  If the size needed for the topology data
		 * is not sufficient, E2BIG is returned
		 */
		if (ddi_copyin(arg, &request_size, sizeof (uint32_t), mode)) {
			DBG_PRINTF((category | RSM_IOCTL, RSM_DEBUG_VERBOSE,
			    "rsmka_topology_ioctl done: BAD_ADDR\n"));
			return (RSMERR_BAD_ADDR);
		}
		/* calculate the max size of the topology structure */
		max_toposize = sizeof (rsmka_topology_hdr_t) +
		    RSM_MAX_CTRL * (sizeof (caddr_t) +
		    sizeof (rsmka_connections_hdr_t)) +
		    RSM_MAX_NODE * sizeof (rsmka_remote_cntlr_t);

		if (request_size > max_toposize) { /* validate request_size */
			DBG_PRINTF((category | RSM_IOCTL, RSM_DEBUG_VERBOSE,
			    "rsmka_topology_ioctl done: size too large\n"));
			return (EINVAL);
		}
		bufp = kmem_zalloc(request_size, KM_SLEEP);
		mutex_enter(&adapter_listhead_base.listlock);
		topology_size = get_topology_size(mode);
		if (request_size < topology_size) {
			kmem_free(bufp, request_size);
			mutex_exit(&adapter_listhead_base.listlock);
			DBG_PRINTF((category | RSM_IOCTL, RSM_DEBUG_VERBOSE,
			    "rsmka_topology_ioctl done: E2BIG\n"));
			return (E2BIG);
		}

		/* get the topology data and copyout to the caller */
		get_topology(arg, bufp, mode);
		mutex_exit(&adapter_listhead_base.listlock);
		if (ddi_copyout((caddr_t)bufp, (caddr_t)arg,
		    topology_size, mode))
			error = RSMERR_BAD_ADDR;

		kmem_free(bufp, request_size);
		break;
	default:
		DBG_PRINTF((category | RSM_IOCTL, RSM_DEBUG,
		    "rsmka_topology_ioctl: cmd not supported\n"));
		error = DDI_FAILURE;
	}

	DBG_PRINTF((category | RSM_IOCTL, RSM_DEBUG_VERBOSE,
	    "rsmka_topology_ioctl done: %d\n", error));
	return (error);
}
