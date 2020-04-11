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

#include <pri.h>
#include "priplugin.h"

#pragma init(priplugin_register)	/* place in .init section */

static md_t *mdp;

static mutex_t	rebuild_lock;
static cond_t	rebuild_cv;

static thread_t pri_worker_thread_id, pri_reader_thread_id;
static boolean_t all_thr_exit = B_FALSE;
static boolean_t event_caught = B_FALSE;

static void priplugin_init(void);
static void priplugin_fini(void);
static void
event_handler(const char *ename, const void *earg, size_t size, void *cookie);
static void *pri_worker_thread(void *arg);
static void *pri_reader_thread(void *arg);
static int remove_old_segments(picl_nodehdl_t node, void *args);


picld_plugin_reg_t priplugin_reg = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_CRITICAL,
	"pri_plugin",
	priplugin_init,
	priplugin_fini
};

static void
set_prop_info(ptree_propinfo_t *propinfo, int size, char *name, int type)
{
	propinfo->version = PICLD_PLUGIN_VERSION_1;
	propinfo->read = NULL;
	propinfo->write = NULL;
	propinfo->piclinfo.type = type;
	propinfo->piclinfo.accessmode = PICL_READ;
	propinfo->piclinfo.size = size;
	(void) strlcpy(propinfo->piclinfo.name, name,
	    sizeof (propinfo->piclinfo.name));
}

boolean_t
prop_exists(picl_nodehdl_t node, char *name)
{
	int status;
	picl_prophdl_t proph;

	status = ptree_get_prop_by_name(node, name, &proph);
	if (status == PICL_SUCCESS)
		return (B_TRUE);
	else
		return (B_FALSE);
}

void
add_md_prop(picl_nodehdl_t node, int size, char *name, void* value, int type)
{
	ptree_propinfo_t propinfo;
	picl_prophdl_t proph;

	if (!prop_exists(node, name)) {
		set_prop_info(&propinfo, size, name, type);

		(void) ptree_create_and_add_prop(node, &propinfo,
		    value, &proph);
	}
}

/*ARGSUSED*/
static int
remove_old_segments(picl_nodehdl_t node, void *args)
{
	int status;

	if ((status = ptree_delete_node(node)) == PICL_SUCCESS)
		ptree_destroy_node(node);
	else
		pri_debug(LOG_NOTICE, "remove_old_segments: can't delete "
		    "segment node: %s\n", picl_strerror(status));

	return (PICL_WALK_CONTINUE);
}

static void
priplugin_init(void)
{
	int status;

	pri_debug(LOG_NOTICE, "priplugin: mem tree and io label thread "
	    "being created; callbacks being registered\n");

	all_thr_exit = B_FALSE;
	event_caught = B_FALSE;

	(void) mutex_init(&rebuild_lock, USYNC_THREAD, NULL);
	(void) cond_init(&rebuild_cv, USYNC_THREAD, NULL);

	if ((status = thr_create(NULL, 0, pri_worker_thread, NULL, THR_BOUND,
	    &pri_worker_thread_id)) < 0) {
		pri_debug(LOG_NOTICE, "priplugin: can't create worker thread: "
		    "%d\n", status);
		all_thr_exit = B_TRUE;
		(void) mutex_destroy(&rebuild_lock);
		(void) cond_destroy(&rebuild_cv);
	} else if ((status = thr_create(NULL, 0, pri_reader_thread, NULL,
	    THR_BOUND, &pri_reader_thread_id)) < 0) {
		pri_debug(LOG_NOTICE, "priplugin: can't create reader thread: "
		    "%d\n", status);
		(void) mutex_lock(&rebuild_lock);
		all_thr_exit = B_TRUE;
		(void) cond_signal(&rebuild_cv);
		(void) mutex_unlock(&rebuild_lock);
		(void) thr_join(pri_worker_thread_id, NULL, NULL);
		(void) mutex_destroy(&rebuild_lock);
		(void) cond_destroy(&rebuild_cv);
	} else {
		pri_debug(LOG_NOTICE, "priplugin_init: worker and reader "
		    "threads created - registering event handlers\n");
		/*
		 * register event_handler for both "sysevent-device-added",
		 * "sysevent_device_removed", and for
		 * "sysevent-dr-app-state-change" PICL events
		 */
		(void) ptree_register_handler(PICLEVENT_SYSEVENT_DEVICE_ADDED,
		    event_handler, NULL);
		(void) ptree_register_handler(PICLEVENT_SYSEVENT_DEVICE_REMOVED,
		    event_handler, NULL);
		(void) ptree_register_handler(PICLEVENT_DR_AP_STATE_CHANGE,
		    event_handler, NULL);
	}
}

/*
 * This thread handles the main processing of PRI data.  It is woken
 * up by either the event handler, to process a PICL event, or it is
 * woken up by the PRI reader thread which has just fetched a new
 * copy of the PRI.
 */
/*ARGSUSED*/
static void *
pri_worker_thread(void *arg)
{
	int status;
	picl_nodehdl_t picl_root_node;

	pri_debug(LOG_NOTICE, "pri_worker_thread: start\n");

	(void) mutex_lock(&rebuild_lock);
	/*LINTED E_FUNC_RET_MAYBE_IGNORED2*/
	while (1) {
		(void) cond_wait(&rebuild_cv, &rebuild_lock);

		if (all_thr_exit == B_TRUE) {
			(void) mutex_unlock(&rebuild_lock);
			pri_debug(LOG_NOTICE, "pri_worker_thread: time to "
			    "exit\n");
			break;
		}

		/*
		 * We don't get events for changes to system memory,
		 * and we do not want to interfere with other plug-ins
		 * by making changes to the picl tree.  So if we were
		 * woken up by a thread then do not destroy and rebuild
		 * the memory info.  Just go fix the labels.
		 */
		if (event_caught == B_FALSE) {
			status = ptree_get_root(&picl_root_node);
			if (status != PICL_SUCCESS) {
				pri_debug(LOG_NOTICE, "pri_worker_thread: "
				    "can't get picl tree root node: %s\n",
				    picl_strerror(status));
				continue;
			}

			pri_debug(LOG_NOTICE, "pri_worker_thread: have root "
			    "picl and PRI nodes\n");

			status = ptree_walk_tree_by_class(picl_root_node,
			    "memory-segment", NULL, remove_old_segments);
			if (status != PICL_SUCCESS) {
				pri_debug(LOG_NOTICE, "pri_worker_thread: "
				    "can't remove old memory segments: \n",
				    picl_strerror(status));
			} else
				pri_debug(LOG_NOTICE, "pri_worker_thread: "
				    "old memory segments removed\n");

			status = ptree_walk_tree_by_class(picl_root_node,
			    "memory", (void *) mdp, add_mem_prop);
			if (status != PICL_SUCCESS) {
				pri_debug(LOG_NOTICE, "pri_worker_thread: "
				    "memory segments walk failed: \n",
				    picl_strerror(status));
			} else
				pri_debug(LOG_NOTICE, "pri_worker_thread: "
				    "success walking memory node\n");
		} else
			event_caught = B_FALSE;

		io_dev_addlabel(mdp);
	}
	pri_debug(LOG_NOTICE, "pri_worker_thread: exiting\n");
	return (NULL);
}

/*
 * This thread camps out in the PRI driver, waiting for it to return
 * the contents of a new PRI.  When the PRI is changed this thread
 * reads that data and prepares it for processing by the worker thread.
 * It then signals the worker thread to process the new PRI data.
 */
/*ARGSUSED*/
static void *
pri_reader_thread(void *arg)
{
	uint64_t tok;
	int status, count;

	pri_debug(LOG_NOTICE, "pri_reader_thread: thread start\n");

	if (pri_init() != 0) {
		pri_debug(LOG_NOTICE, "pri_reader_thread: pri_init failed\n");
		return (NULL);
	}

	/*
	 * It's entirely possible that a new PRI may get pushed while
	 * the worker thread is processing the previous PRI.  We will
	 * wait until the worker is finished, then flush the old contents
	 * and wake up the worker again to process the new data.
	 */
	mdp = NULL;
	tok = 0;
	count = 0;
	/*LINTED E_FUNC_RET_MAYBE_IGNORED2*/
	while (1) {
		/*
		 * The _fini() function will close the PRI's fd, which will
		 * cause this function to break out of waiting in the PRI
		 * driver and return an error.
		 */
		status = pri_devinit(&tok);

		(void) mutex_lock(&rebuild_lock);
		if (all_thr_exit == B_TRUE) {
			(void) mutex_unlock(&rebuild_lock);
			pri_debug(LOG_NOTICE, "pri_reader_thread: time to "
			    "exit\n");
			break;
		}

		/*
		 * Wait until the worker is idle before swapping in the
		 * new PRI contents, then signal the worker to process
		 * that new data.
		 */
		if (status == 0) {
			pri_debug(LOG_NOTICE, "pri_reader_thread: got PRI\n");

			/* old buffer will be freed by pri_bufinit() */
			mdp = pri_bufinit(mdp);
			if (mdp != NULL) {
				(void) cond_signal(&rebuild_cv);
				count = 0;
			} else {
				pri_debug(LOG_NOTICE, "pri_reader_thread: "
				    "NULL mdp!\n");
				status = -1;
			}
		}

		/*
		 * Try to handle SP resets or other unexplained errors
		 * from ds by closing down and re-opening the PRI driver.
		 */
		if (status == -1) {
			if (errno != 0) {
				pri_debug(LOG_NOTICE, "pri_reader_thread: "
				    "can't get PRI contents: %s\n",
				    strerror(errno));
			}
			if (++count > 6) {
				pri_debug(LOG_NOTICE, "pci_reader_thread: "
				    "can't process PRI data\n");
				(void) mutex_unlock(&rebuild_lock);
				break;
			}
			/* old buffer will be freed by pri_fini() */
			pri_fini();
			tok = 0;
			sleep(10);
			if (pri_init() != 0) {
				pri_debug(LOG_NOTICE, "pci_reader_thread: "
				    "can't reinitialize PRI driver\n");
				(void) mutex_unlock(&rebuild_lock);
				break;
			}
		}
		(void) mutex_unlock(&rebuild_lock);
	}

	pri_debug(LOG_NOTICE, "pri_reader_thread: thread exiting\n");
	return (NULL);
}

static void
priplugin_fini(void)
{
	pri_debug(LOG_NOTICE, "priplugin_fini: called\n");

	if (all_thr_exit == B_TRUE)
		return;

	/* unregister the event handlers */
	(void) ptree_unregister_handler(PICLEVENT_SYSEVENT_DEVICE_ADDED,
	    event_handler, NULL);
	(void) ptree_unregister_handler(PICLEVENT_SYSEVENT_DEVICE_REMOVED,
	    event_handler, NULL);
	(void) ptree_unregister_handler(PICLEVENT_DR_AP_STATE_CHANGE,
	    event_handler, NULL);

	/*
	 * Set the exit flag to tell the worker thread to quit and wake
	 * up that thread.  Once that thread is reaped then pull the rug
	 * out from the PRI reader thread by calling pri_fini(), which
	 * closes the PRI fd.  That wakes the PRI reader thread and it
	 * will then exit as well.
	 */
	(void) mutex_lock(&rebuild_lock);
	all_thr_exit = B_TRUE;
	(void) cond_signal(&rebuild_cv);
	(void) mutex_unlock(&rebuild_lock);

	(void) thr_join(pri_worker_thread_id, NULL, NULL);

	pri_devfini(mdp);
	mdp = NULL;
	pri_fini();
	(void) thr_join(pri_reader_thread_id, NULL, NULL);

	(void) mutex_destroy(&rebuild_lock);
	(void) cond_destroy(&rebuild_cv);
}

void
priplugin_register(void)
{
	picld_plugin_register(&priplugin_reg);
}

/*
 * Discovery event handler
 * respond to the picl events:
 *      PICLEVENT_SYSEVENT_DEVICE_ADDED
 *      PICLEVENT_SYSEVENT_DEVICE_REMOVED
 *      PICLEVENT_DR_AP_STATE_CHANGE
 *
 * We can't do much of anything fancy since the event data doesn't contain
 * a nac for the device.  Nothing to do for remove - the devtree plug-in
 * will have removed the node for us.  For add we have to go back and
 * add labels again.
 */
static void
event_handler(const char *ename, const void *earg, size_t size, void *cookie)
{

	pri_debug(LOG_NOTICE, "pri: event_handler: caught event "
	    "%s\n", ename);
	if ((strcmp(ename, PICLEVENT_SYSEVENT_DEVICE_ADDED) == 0) ||
	    (strcmp(ename, PICLEVENT_SYSEVENT_DEVICE_REMOVED) == 0) ||
	    (strcmp(ename, PICLEVENT_DR_AP_STATE_CHANGE) == 0)) {
		pri_debug(LOG_NOTICE, "pri: event_handler: handle event "
		    "%s; waking worker thread\n", ename);

		(void) mutex_lock(&rebuild_lock);

		if (all_thr_exit == B_FALSE) {
			/*
			 * Tell the worker thread to only re-examine the
			 * IO device labels.
			 */
			event_caught = B_TRUE;
			(void) cond_signal(&rebuild_cv);
		}

		(void) mutex_unlock(&rebuild_lock);
	}
}

/*VARARGS2*/
void
pri_debug(int level, char *fmt, ...)
{
#if (PRI_DEBUG != 0)
	va_list	ap;

	va_start(ap, fmt);
	vsyslog(level, fmt, ap);
	va_end(ap);
#endif
}
