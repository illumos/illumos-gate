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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This module implements the PTree interface and the PICL to PTree calls
 */

/*
 * Note:
 * PICL Node and Property Handles Table:
 * A node or property in PICL tree has two handles: a ptree handle, which is
 * used by plug-ins and the libpicltree interface, and a picl handle
 * which is used by clients and the libpicl interface.
 * The mapping of ptree handles to the internal PICL object (picl_obj_t) is
 * kept in a ptree hash table (ptreetbl), and the mapping of a picl handle
 * to its ptree handle is kept in the picl hash table (picltbl).
 * The reader/writer lock, ptree_rwlock, is held when reading or modifying ptree
 * hash table (ptreetbl) and/or the PICL tree structure (nodes and linkages
 * between them). The reader/writer lock, picltbl_rwlock, is held when reading
 * or modifying picl hash table (picltbl).
 *
 * The mutex, ptreehdl_lock, is used to control allocation of ptree handles.
 * The mutex, piclhdl_lock, is used to control allocation of picl handles.
 *
 * The mutex, ptree_refresh_mutex, and the condition, ptree_refresh_cond,
 * are used to synchronize PICL refreshes (ptree_refresh) and to wait/signal
 * change in PICL tree structure.
 *
 * The counter, picl_hdl_hi, is the hi water mark for allocated picl handles.
 * The counter, ptree_hdl_hi, is the hi water mark for allocated ptree handles.
 * A stale handle error is returned for handle values below the hi water
 * mark, and invalid handles are returned for handle values above the hi water
 * mark or when the process id field of the handle does not match.
 *
 * Locking Scheme:
 * The structure of the PICL tree is controlled by the ptree_rwlock. The
 * properties of a node are controlled by individual node locks. The
 * piclize-ing or unpiclize-ing of a node is controlled by picltbl_rwlock.
 *
 * Two-Phase Locking scheme: lock acquire phase and lock release phase.
 *
 * Lock Ordering:
 * The ptree_rwlock and node locks are always acquired in the following order:
 *	lock ptree_rwlock
 *	lock node
 *
 * Lock Strategy:
 * There are three locks:
 *	ptree_rwlock:	a reader lock is obtained to do ptree hash table
 *			lookups and traverse tree. A writer lock is obtained
 *			when creating or destroying nodes from the ptree,
 *			or when modifying node linkages: parent, peer, child.
 *	picltbl_rwlock:	a reader lock is obtained for picl hash table lookups.
 *			A writer lock is obtained when piclize-ing or
 *			unpiclize-ing nodes or properties.
 *	node_lock:	This is a reader/writer lock for properties of a node.
 *			A reader lock is obtained before reading property
 *			values. A writer lock is obtained when adding or
 *			removing properties and when modifying a property value.
 *
 * Never hold more than one node lock at a time.
 *
 * Event Locking:
 * There are two locks:
 *	evtq_lock:	this lock protects the event queue. It is obtained
 *			to queue events that are posted and to unqueue
 *			events to be dispatched.
 *	evtq_cv:	condition variable is protected by evtq_lock. It is
 *			used by the ptree event thread to wait for events
 *			until eventqp is not NULL.
 *	evtq_empty:	condition variable protected by evtq_lock. It is
 *			used to signal when the eventq becomes empty. The
 *			reinitialization process waits on this condition.
 *     evthandler_lock: this protects the event handler list. It is obtained
 *			to add event handlers on registration and to remove
 *			event handlers on unregistration.
 *      (handler)->cv:	condition variable per handler protected by
 *			evthandler_lock.  It is used to wait until the
 *			event handler completes execution (execflg == 0)
 *			before unregistering the handler.
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdarg.h>
#include <alloca.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <libintl.h>
#include <syslog.h>
#include <pthread.h>
#include <synch.h>
#include <setjmp.h>
#include <signal.h>
#include <dlfcn.h>
#include <dirent.h>
#include <door.h>
#include <time.h>
#include <inttypes.h>
#include <sys/systeminfo.h>
#include <sys/utsname.h>
#include <picl.h>
#include <picltree.h>
#include "picldefs.h"
#include "ptree_impl.h"

#define	SO_VERS	".so.1"

static	hash_t		picltbl;	/* client handles to picl obj */
static	hash_t		ptreetbl;	/* ptree handles to picl obj */
static	pthread_mutex_t	ptreehdl_lock;
static	pthread_mutex_t	piclhdl_lock;
static	pthread_mutex_t	ptree_refresh_mutex;
static	rwlock_t	picltbl_rwlock;	/* PICL handle table lock */
static	rwlock_t	ptree_rwlock;	/* PICL tree lock */
static	pthread_cond_t	ptree_refresh_cond = PTHREAD_COND_INITIALIZER;
static	uint32_t	ptree_hdl_hi = 1;
static	uint32_t	picl_hdl_hi = 1;
static	picl_obj_t	*picl_root_obj = NULL;
static	picl_nodehdl_t	ptree_root_hdl = PICL_INVALID_PICLHDL;
static	int		ptree_generation = 0;
static	pid_t		picld_pid;
static	door_cred_t	picld_cred;
static	int		qempty_wait;	/* evtq_empty condition waiter flag */

static	picld_plugin_reg_list_t		*plugin_reg_list = NULL;
static	picld_plugin_desc_t		*plugin_desc;

static	eventq_t	*eventqp;	/* PICL events queue */
static	pthread_mutex_t	evtq_lock = PTHREAD_MUTEX_INITIALIZER;
static	pthread_cond_t	evtq_cv = PTHREAD_COND_INITIALIZER;
static	pthread_cond_t	evtq_empty = PTHREAD_COND_INITIALIZER;
static	evt_handler_t	*evt_handlers;	/* Event handler list */
static	pthread_mutex_t	evthandler_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * PICL daemon verbose level
 */
int	verbose_level;


/*
 * Event handler free functions
 */
static void
free_handler(evt_handler_t *evhp)
{
	if (evhp->ename)
		free(evhp->ename);
	(void) pthread_cond_broadcast(&evhp->cv);
	(void) pthread_cond_destroy(&evhp->cv);
	free(evhp);
}


/*
 * queue_event to events queue
 */
static void
queue_event(eventq_t *evt)
{
	eventq_t	*tmpp;

	evt->next = NULL;
	if (eventqp == NULL)
		eventqp = evt;
	else {
		tmpp = eventqp;
		while (tmpp->next != NULL)
			tmpp = tmpp->next;
		tmpp->next = evt;
	}
}

/*
 * unqueue_event from the specified eventq
 */
static eventq_t *
unqueue_event(eventq_t **qp)
{
	eventq_t	*evtp;

	evtp = *qp;
	if (evtp != NULL)
		*qp = evtp->next;
	return (evtp);
}

/*
 * register an event handler by adding it to the list
 */
int
ptree_register_handler(const char *ename,
    void (*evt_handler)(const char *ename, const void *earg, size_t size,
    void *cookie), void *cookie)
{
	evt_handler_t	*ent;
	evt_handler_t	*iter;

	if (ename == NULL)
		return (PICL_INVALIDARG);

	/*
	 * Initialize event handler entry
	 */
	ent = malloc(sizeof (*ent));
	if (ent == NULL)
		return (PICL_FAILURE);
	ent->ename = strdup(ename);
	if (ent->ename == NULL) {
		free(ent);
		return (PICL_FAILURE);
	}
	ent->cookie = cookie;
	ent->evt_handler = evt_handler;
	ent->execflg = 0;
	ent->wakeupflg = 0;
	(void) pthread_cond_init(&ent->cv, NULL);
	ent->next = NULL;

	/*
	 * add handler to the handler list
	 */
	(void) pthread_mutex_lock(&evthandler_lock);
	if (evt_handlers == NULL) {
		evt_handlers = ent;
		(void) pthread_mutex_unlock(&evthandler_lock);
		return (PICL_SUCCESS);
	}
	iter = evt_handlers;
	while (iter->next != NULL)
		iter = iter->next;
	iter->next = ent;
	(void) pthread_mutex_unlock(&evthandler_lock);

	return (PICL_SUCCESS);
}

/*
 * unregister handler
 */
void
ptree_unregister_handler(const char *ename,
    void (*evt_handler)(const char *ename, const void *earg, size_t size,
    void *cookie), void *cookie)
{
	evt_handler_t	*evhdlrp, **evhdlrpp;

	if (ename == NULL)
		return;

	/*
	 * unlink handler from handler list
	 */
	(void) pthread_mutex_lock(&evthandler_lock);

retry:
	for (evhdlrpp = &evt_handlers; (evhdlrp = *evhdlrpp) != NULL;
	    evhdlrpp = &evhdlrp->next) {
		if ((evhdlrp->cookie != cookie) ||
		    (strcmp(evhdlrp->ename, ename) != 0) ||
		    (evhdlrp->evt_handler != evt_handler))
			continue;

		/*
		 * If the handler is in execution, release the lock
		 * and wait for it to complete and retry.
		 */
		if (evhdlrp->execflg) {
			evhdlrp->wakeupflg = 1;
			(void) pthread_cond_wait(&evhdlrp->cv,
			    &evthandler_lock);
			goto retry;
		}

		/*
		 * Unlink this handler from the linked list
		 */
		*evhdlrpp = evhdlrp->next;
		free_handler(evhdlrp);
		break;
	}

	(void) pthread_mutex_unlock(&evthandler_lock);
}

/*
 * Call all registered handlers for the event
 */
static void
call_event_handlers(eventq_t *ev)
{
	evt_handler_t	*iter;
	void	(*evhandler)(const char *, const void *, size_t, void *);
	void	(*completion_handler)(char *ename, void *earg, size_t size);

	(void) pthread_mutex_lock(&evthandler_lock);
	iter = evt_handlers;
	while (iter != NULL) {
		if (strcmp(iter->ename, ev->ename) == 0) {
			evhandler = iter->evt_handler;
			iter->execflg = 1;
			(void) pthread_mutex_unlock(&evthandler_lock);
			if (evhandler) {
				dbg_print(2, "ptree_evthr: Invoking evthdlr:%p"
				    " ename:%s\n", evhandler, ev->ename);
				(*evhandler)(ev->ename, ev->earg, ev->size,
				    iter->cookie);
				dbg_print(2, "ptree_evthr: done evthdlr:%p "
				    "ename:%s\n", evhandler, ev->ename);
			}
			(void) pthread_mutex_lock(&evthandler_lock);
			iter->execflg = 0;
			if (iter->wakeupflg) {
				iter->wakeupflg = 0;
				(void) pthread_cond_broadcast(&iter->cv);
			}
		}
		iter = iter->next;
	}
	(void) pthread_mutex_unlock(&evthandler_lock);
	if ((completion_handler = ev->completion_handler) != NULL) {
		dbg_print(2,
		    "ptree_evthr: Invoking completion hdlr:%p ename:%s\n",
		    completion_handler, ev->ename);
		(*completion_handler)((char *)ev->ename, (void *)ev->earg,
		    ev->size);
		dbg_print(2, "ptree_evthr: done completion hdlr:%p ename:%s\n",
		    completion_handler, ev->ename);
	}
	(void) pthread_mutex_lock(&ptree_refresh_mutex);
	++ptree_generation;
	(void) pthread_cond_broadcast(&ptree_refresh_cond);
	(void) pthread_mutex_unlock(&ptree_refresh_mutex);
}

/*
 * This function is called by a plug-in to post an event
 */
int
ptree_post_event(const char *ename, const void *earg, size_t size,
    void (*completion_handler)(char *ename, void *earg, size_t size))
{
	eventq_t	*evt;

	if (ename == NULL)
		return (PICL_INVALIDARG);

	evt = malloc(sizeof (*evt));
	if (evt == NULL)
		return (PICL_FAILURE);
	evt->ename = ename;
	evt->earg = earg;
	evt->size = size;
	evt->completion_handler = completion_handler;

	(void) pthread_mutex_lock(&evtq_lock);
	queue_event(evt);
	(void) pthread_cond_broadcast(&evtq_cv);
	(void) pthread_mutex_unlock(&evtq_lock);
	return (PICL_SUCCESS);
}

/*
 * PICLTREE event thread
 */
/*ARGSUSED*/
static void *
ptree_event_thread(void *argp)
{
	eventq_t	*evt;

	for (;;) {
		(void) pthread_mutex_lock(&evtq_lock);
		while (eventqp == NULL) {
			/*
			 * Signal empty queue
			 */
			if (qempty_wait)
				(void) pthread_cond_broadcast(&evtq_empty);
			(void) pthread_cond_wait(&evtq_cv, &evtq_lock);
		}
		if ((evt = unqueue_event(&eventqp)) != NULL) {
			(void) pthread_mutex_unlock(&evtq_lock);
			call_event_handlers(evt);
			free(evt);
		} else
			(void) pthread_mutex_unlock(&evtq_lock);
	}
	/*NOTREACHED*/
	return (NULL);
}


/*
 * Create a new element
 */
static hash_elem_t *
hash_newobj(uint32_t hdl_val, void *obj_val)
{
	hash_elem_t	*n;

	n = malloc(sizeof (*n));
	if (n == NULL)
		return (NULL);
	n->hdl = hdl_val;
	n->hash_obj = obj_val;
	n->next = NULL;
	return (n);
}

static hash_elem_t *
hash_newhdl(uint32_t picl_hdl, uint32_t ptreeh)
{
	hash_elem_t	*n;

	n = malloc(sizeof (*n));
	if (n == NULL)
		return (NULL);
	n->hdl = picl_hdl;
	n->hash_hdl = ptreeh;
	n->next = NULL;
	return (n);
}

/*
 * Initialize a hash table by setting all entries to NULL
 */
static int
hash_init(hash_t *htbl)
{
	int	i;

	htbl->hash_size = HASH_TBL_SIZE;
	htbl->tbl = malloc(sizeof (hash_elem_t *) * HASH_TBL_SIZE);
	if (htbl->tbl == NULL)
		return (-1);
	for (i = 0; i < htbl->hash_size; ++i)
		htbl->tbl[i] = NULL;
	return (0);
}

/*
 * Lock free function to add an entry in the hash table
 */
static int
hash_add_newobj(hash_t *htbl, picl_hdl_t hdl, void *pobj)
{
	int		indx;
	hash_elem_t	*n;
	uint32_t	hash_val = HASH_VAL(hdl);

	n = hash_newobj(hash_val, pobj);
	if (n == NULL)
		return (-1);
	indx = HASH_INDEX(htbl->hash_size, hash_val);
	n->next = htbl->tbl[indx];
	htbl->tbl[indx] = n;
	return (0);
}

static int
hash_add_newhdl(hash_t *htbl, picl_hdl_t piclh, picl_hdl_t ptreeh)
{
	int		indx;
	hash_elem_t	*n;
	uint32_t	picl_val = HASH_VAL(piclh);
	uint32_t	ptree_val = HASH_VAL(ptreeh);

	n = hash_newhdl(picl_val, ptree_val);
	if (n == NULL)
		return (-1);

	indx = HASH_INDEX(htbl->hash_size, picl_val);
	n->next = htbl->tbl[indx];
	htbl->tbl[indx] = n;
	return (0);
}

/*
 * Lock free function to remove the handle from the hash table
 * Returns -1 if element not found, 0 if successful
 */
static int
hash_remove(hash_t *htbl, picl_hdl_t hdl)
{
	hash_elem_t	*nxt;
	hash_elem_t	*cur;
	int		i;
	uint32_t	hash_val = HASH_VAL(hdl);

	i = HASH_INDEX(htbl->hash_size, hash_val);
	if (htbl->tbl[i] == NULL)
		return (-1);

	cur = htbl->tbl[i];
	if (cur->hdl == hash_val) {
		htbl->tbl[i] = cur->next;
		free(cur);
		return (0);
	}
	nxt = cur->next;
	while (nxt != NULL) {
		if (nxt->hdl == hash_val) {
			cur->next = nxt->next;
			free(nxt);
			return (0);
		}
		cur = nxt;
		nxt = nxt->next;
	}
	return (-1);
}

/*
 * Lock free function to lookup the hash table for a given handle
 * Returns NULL if not found
 */
static void *
hash_lookup_obj(hash_t *htbl, picl_hdl_t hdl)
{
	hash_elem_t	*tmp;
	int		i;
	uint32_t	hash_val;

	hash_val = HASH_VAL(hdl);
	i = HASH_INDEX(htbl->hash_size, hash_val);
	tmp = htbl->tbl[i];
	while (tmp != NULL) {
		if (tmp->hdl == hash_val)
			return (tmp->hash_obj);
		tmp = tmp->next;
	}
	return (NULL);
}

static picl_hdl_t
hash_lookup_hdl(hash_t *htbl, picl_hdl_t hdl)
{
	hash_elem_t	*tmp;
	int		i;
	uint32_t	hash_val;

	hash_val = HASH_VAL(hdl);
	i = HASH_INDEX(htbl->hash_size, hash_val);
	tmp = htbl->tbl[i];
	while (tmp != NULL) {
		if (tmp->hdl == hash_val)
			return (MAKE_HANDLE(picld_pid, tmp->hash_hdl));
		tmp = tmp->next;
	}
	return (PICL_INVALID_PICLHDL);
}

/*
 * Is the PICL handle stale or invalid handle?
 */
static int
picl_hdl_error(picl_hdl_t hdl)
{
	uint32_t	hash_val = HASH_VAL(hdl);
	pid_t		pid = GET_PID(hdl);
	int		err;

	(void) pthread_mutex_lock(&piclhdl_lock);
	err = PICL_STALEHANDLE;
	if ((pid != picld_pid) || (hash_val >= picl_hdl_hi) ||
	    (hash_val == NULL))
		err = PICL_INVALIDHANDLE;
	(void) pthread_mutex_unlock(&piclhdl_lock);
	return (err);
}

/*
 * Is the Ptree handle stale or invalid handle?
 */
static int
ptree_hdl_error(picl_hdl_t hdl)
{
	uint32_t	hash_val = HASH_VAL(hdl);
	pid_t		pid = GET_PID(hdl);
	int		err;

	(void) pthread_mutex_lock(&ptreehdl_lock);
	err = PICL_STALEHANDLE;
	if ((pid != picld_pid) || (hash_val >= ptree_hdl_hi) ||
	    (hash_val == NULL))
		err = PICL_INVALIDHANDLE;
	(void) pthread_mutex_unlock(&ptreehdl_lock);
	return (err);
}

/*
 * For a PICL handle, return the PTree handle and the PICL object
 * Locks and releases the PICL table.
 */
int
cvt_picl2ptree(picl_hdl_t hdl, picl_hdl_t *ptree_hdl)
{
	picl_hdl_t 	tmph;
	int		err;

	(void) rw_rdlock(&picltbl_rwlock);		/* lock picl */
	tmph = hash_lookup_hdl(&picltbl, hdl);
	if (tmph == PICL_INVALID_PICLHDL) {
		err = picl_hdl_error(hdl);
		(void) rw_unlock(&picltbl_rwlock);	/* unlock picl */
		return (err);
	}
	*ptree_hdl = tmph;
	(void) rw_unlock(&picltbl_rwlock);		/* unlock picl */
	return (PICL_SUCCESS);
}

/*
 * Allocate a ptree handle
 */
static picl_hdl_t
alloc_ptreehdl(void)
{
	picl_hdl_t hdl;

	(void) pthread_mutex_lock(&ptreehdl_lock);	/* lock ptreehdl */
	hdl = MAKE_HANDLE(picld_pid, ptree_hdl_hi);
	++ptree_hdl_hi;
	(void) pthread_mutex_unlock(&ptreehdl_lock); /* unlock ptreehdl */
	return (hdl);
}

/*
 * Allocate a picl handle
 * A PICL handle is ptree_hdl value with 1 in MSB of handle value.
 * If a ptree handle already has 1 in MSB, then it cannot be piclized
 * and the daemon must be restarted.
 */
static picl_hdl_t
alloc_piclhdl(void)
{
	picl_hdl_t hdl;

	(void) pthread_mutex_lock(&piclhdl_lock);	/* lock piclhdl */
	hdl = MAKE_HANDLE(picld_pid, picl_hdl_hi);
	++picl_hdl_hi;
	(void) pthread_mutex_unlock(&piclhdl_lock);	/* unlock piclhdl */
	return (hdl);
}

/*
 * Allocate and add handle to PTree hash table
 */
static void
alloc_and_add_to_ptree(picl_obj_t *pobj)
{
	pobj->ptree_hdl = alloc_ptreehdl();
	(void) rw_wrlock(&ptree_rwlock);
	(void) hash_add_newobj(&ptreetbl, pobj->ptree_hdl, pobj);
	(void) rw_unlock(&ptree_rwlock);
}

/*
 * Lock a picl node object
 */
static int
lock_obj(int rw, picl_obj_t *nodep)
{
	if (rw == RDLOCK_NODE)
		(void) rw_rdlock(&nodep->node_lock);
	else if (rw == WRLOCK_NODE)
		(void) rw_wrlock(&nodep->node_lock);
	else
		return (-1);
	return (0);
}

/*
 * Release the picl node object.
 * This function may be called with a NULL object pointer.
 */
static void
unlock_node(picl_obj_t *nodep)
{
	if (nodep == NULL)
		return;
	(void) rw_unlock(&nodep->node_lock);
}

/*
 * This function locks the node of a property and returns the node object
 * and the property object.
 */
static int
lookup_and_lock_propnode(int rw, picl_prophdl_t proph, picl_obj_t **nodep,
    picl_obj_t **propp)
{
	picl_obj_t	*pobj;
	picl_obj_t	*nobj;

	pobj = hash_lookup_obj(&ptreetbl, proph);
	if (pobj == NULL)
		return (ptree_hdl_error(proph));

	/*
	 * Get the property's or table entry's node object
	 */
	nobj = NULL;
	if (pobj->obj_type == PICL_OBJ_PROP)
		nobj = pobj->prop_node;
	else if (pobj->obj_type == (PICL_OBJ_PROP|PICL_OBJ_TABLEENTRY))
		nobj = pobj->prop_table->prop_node;
	else {
		*propp = pobj;	/* return the prop */
		return (PICL_NOTPROP);
	}

	if (nobj && (lock_obj(rw, nobj) < 0))			/* Lock node */
		return (PICL_FAILURE);

	*nodep = nobj;
	*propp = pobj;

	return (PICL_SUCCESS);
}

/*
 * This function locks the node of a table and returns the node object
 * and the table object.
 */
static int
lookup_and_lock_tablenode(int rw, picl_prophdl_t tblh, picl_obj_t **nodep,
    picl_obj_t **tblobj)
{
	picl_obj_t	*pobj;
	picl_obj_t	*nobj;

	pobj = hash_lookup_obj(&ptreetbl, tblh);
	if (pobj == NULL)
		return (ptree_hdl_error(tblh));

	/*
	 * Get the property's or table entry's node object
	 */
	nobj = NULL;
	if (pobj->obj_type != PICL_OBJ_TABLE)
		return (PICL_NOTTABLE);
	nobj = pobj->prop_node;

	if (nobj && (lock_obj(rw, nobj) < 0))			/* Lock node */
		return (PICL_FAILURE);

	*nodep = nobj;
	*tblobj = pobj;

	return (PICL_SUCCESS);
}

/*
 * This locks the node of a table or a table entry and returns the
 * node object and the table or table entry object
 */
static int
lookup_and_lock_tableprop_node(int rw, picl_prophdl_t tblproph,
    picl_obj_t **nodep, picl_obj_t **tblpropp)
{
	picl_obj_t	*pobj;
	picl_obj_t	*nobj;

	pobj = hash_lookup_obj(&ptreetbl, tblproph);
	if (pobj == NULL)
		return (ptree_hdl_error(tblproph));

	/*
	 * Get the property's or table entry's node object
	 */
	nobj = NULL;
	if ((pobj->obj_type != PICL_OBJ_TABLE) &&	/* not a table */
	    !(pobj->obj_type & PICL_OBJ_TABLEENTRY))	/* or an entry */
		return (PICL_NOTTABLE);
	if (pobj->obj_type == PICL_OBJ_TABLE)
		nobj = pobj->prop_node;
	else
		nobj = pobj->prop_table->prop_node;

	if (nobj && (lock_obj(rw, nobj) < 0))			/* Lock node */
		return (PICL_FAILURE);

	*tblpropp = pobj;
	*nodep = nobj;

	return (PICL_SUCCESS);
}

/*
 * Lock the node corresponding to the given handle and return its object
 */
static int
lookup_and_lock_node(int rw, picl_nodehdl_t nodeh, picl_obj_t **nodep)
{
	picl_obj_t	*nobj;

	nobj = hash_lookup_obj(&ptreetbl, nodeh);
	if (nobj == NULL)
		return (ptree_hdl_error(nodeh));
	else if (nobj->obj_type != PICL_OBJ_NODE)
		return (PICL_NOTNODE);
	if (lock_obj(rw, nobj) < 0)			/* Lock node */
		return (PICL_FAILURE);
	*nodep = nobj;
	return (PICL_SUCCESS);
}

/*
 * Is the property name a restricted property name?
 */
static int
picl_restricted(const char *name)
{
	if (strcmp(name, PICL_PROP_CLASSNAME) == 0)
		return (0);		/* not restricted */

	if ((name[0] == '_') && (strchr(&name[1], '_') == NULL))
		return (1);
	return (0);
}

/*
 * Check the value size with the property size
 * Return PICL_INVALIDARG if the size does not match exactly for strongly
 * typed properties.
 * For charstring reads allow sizes that match the value size
 * For bytearray return PICL_VALUETOOBIG
 * if the size is greater than the buffer size.
 */
static int
check_propsize(int op, picl_obj_t *propp, size_t sz)
{
	if (propp->prop_mode & PICL_VOLATILE) {
		if (sz != propp->prop_size)
			return (PICL_INVALIDARG);
		else
			return (PICL_SUCCESS);
	}

	/*
	 * check size for non-volatile properties
	 */
	switch (propp->prop_type) {
	case PICL_PTYPE_CHARSTRING:
		if ((op == PROP_READ) &&
		    (strlen(propp->prop_val) >= sz))
			return (PICL_VALUETOOBIG);
		if ((op == PROP_WRITE) && (sz > propp->prop_size))
			return (PICL_VALUETOOBIG);
		break;
	case PICL_PTYPE_BYTEARRAY:
		if (op == PROP_WRITE) {
			if (sz > propp->prop_size)
				return (PICL_VALUETOOBIG);
			return (PICL_SUCCESS);	/* allow small writes */
		}
		/* FALLTHROUGH */
	default:
		if (propp->prop_size != sz)
			return (PICL_INVALIDARG);
		break;
	}
	return (PICL_SUCCESS);
}

void
cvt_ptree2picl(picl_hdl_t *handlep)
{
	picl_obj_t	*pobj;

	(void) rw_rdlock(&ptree_rwlock);
	pobj = hash_lookup_obj(&ptreetbl, *handlep);
	if (pobj == NULL)
		*handlep = PICL_INVALID_PICLHDL;
	else
		(void) memcpy(handlep, &pobj->picl_hdl, sizeof (*handlep));
	(void) rw_unlock(&ptree_rwlock);
}

/*
 * The caller of the piclize() set of functions is assumed to hold
 * the ptree_rwlock().
 */
static void
piclize_obj(picl_obj_t *pobj)
{
	(void) rw_wrlock(&picltbl_rwlock);
	pobj->picl_hdl = alloc_piclhdl();
	(void) hash_add_newhdl(&picltbl, pobj->picl_hdl, pobj->ptree_hdl);
	(void) rw_unlock(&picltbl_rwlock);
}

static void
piclize_table(picl_obj_t  *tbl_obj)
{
	picl_obj_t	*rowp;
	picl_obj_t	*colp;

	for (rowp = tbl_obj->next_row; rowp != NULL; rowp = rowp->next_col)
		for (colp = rowp; colp != NULL; colp = colp->next_row)
			piclize_obj(colp);
}

static void
piclize_prop(picl_obj_t *propp)
{
	picl_obj_t	*tbl_obj;
	picl_prophdl_t	tblh;

	piclize_obj(propp);
	if (!(propp->prop_mode & PICL_VOLATILE) &&
	    (propp->prop_type == PICL_PTYPE_TABLE)) {
		tblh = *(picl_prophdl_t *)propp->prop_val;
		tbl_obj = hash_lookup_obj(&ptreetbl, tblh);
		if (tbl_obj == NULL)
			return;
		piclize_obj(tbl_obj);
		piclize_table(tbl_obj);
	}
}

/*
 * Function to create PICL handles for a subtree and add them to
 * the table
 */
static void
piclize_node(picl_obj_t  *nodep)
{
	picl_obj_t	*propp;
	picl_obj_t	*chdp;

	piclize_obj(nodep);
	propp = nodep->first_prop;
	while (propp != NULL) {
		piclize_prop(propp);
		propp = propp->next_prop;
	}

	/* go through the children */
	for (chdp = nodep->child_node; chdp != NULL; chdp = chdp->sibling_node)
		piclize_node(chdp);
}

/*
 * Function to remove PICL handles
 */
static void
unpiclize_obj(picl_obj_t *pobj)
{
	(void) rw_wrlock(&picltbl_rwlock);
	(void) hash_remove(&picltbl, pobj->picl_hdl);
	pobj->picl_hdl = PICL_INVALID_PICLHDL;
	(void) rw_unlock(&picltbl_rwlock);
}

static void
unpiclize_table(picl_obj_t  *tbl_obj)
{
	picl_obj_t	*rowp;
	picl_obj_t	*colp;

	for (rowp = tbl_obj->next_row; rowp != NULL; rowp = rowp->next_col)
		for (colp = rowp; colp != NULL; colp = colp->next_row)
			unpiclize_obj(colp);
	unpiclize_obj(tbl_obj);
}

static void
unpiclize_prop(picl_obj_t *propp)
{
	picl_obj_t	*tbl_obj;
	picl_prophdl_t	tblh;

	if (!IS_PICLIZED(propp))
		return;
	unpiclize_obj(propp);
	if (!(propp->prop_mode & PICL_VOLATILE) &&
	    (propp->prop_type == PICL_PTYPE_TABLE)) {
		tblh = *(picl_prophdl_t *)propp->prop_val;
		tbl_obj = hash_lookup_obj(&ptreetbl, tblh);
		unpiclize_table(tbl_obj);
	}
}

/*
 * Function to remove PICL handles for a subtree and its
 * properties
 */
static void
unpiclize_node(picl_obj_t  *nodep)
{
	picl_obj_t	*propp;
	picl_obj_t	*chdp;


	if (!IS_PICLIZED(nodep))
		return;

	unpiclize_obj(nodep);
	propp = nodep->first_prop;
	while (propp != NULL) {
		unpiclize_prop(propp);
		propp = propp->next_prop;
	}

	/* go through the children */
	for (chdp = nodep->child_node; chdp != NULL; chdp = chdp->sibling_node)
		unpiclize_node(chdp);
}


/*
 * The caller holds the lock on the ptree_lock when calling this.
 * If ret is not NULL then this function returns the referenced object.
 */
static int
lookup_verify_ref_prop(picl_obj_t *propp, picl_obj_t **ret)
{
	picl_nodehdl_t	refh;
	picl_obj_t	*refobj;

	refh = *(picl_nodehdl_t *)propp->prop_val;
	refobj = hash_lookup_obj(&ptreetbl, refh);
	if (refobj == NULL)
		return (ptree_hdl_error(refh));
	else if (refobj->obj_type != PICL_OBJ_NODE)
		return (PICL_INVREFERENCE);
	if (ret)
		*ret = refobj;
	return (PICL_SUCCESS);
}

/*
 * The caller holds the lock on ptree_lock when calling this.
 * If ret is not NULL, then this function returns the table object
 */
static int
lookup_verify_table_prop(picl_obj_t *propp, picl_obj_t **ret)
{
	picl_prophdl_t	tblh;
	picl_obj_t	*tbl_obj;

	tblh = *(picl_prophdl_t *)propp->prop_val;
	tbl_obj = hash_lookup_obj(&ptreetbl, tblh);
	if (tbl_obj == NULL)
		return (ptree_hdl_error(tblh));
	else if (!(tbl_obj->obj_type & PICL_OBJ_TABLE))
		return (PICL_NOTTABLE);
	if (ret)
		*ret = tbl_obj;
	return (PICL_SUCCESS);
}

static int
lookup_verify_prop_handle(picl_prophdl_t proph, picl_obj_t **ret)
{
	picl_obj_t	*propp;

	propp = hash_lookup_obj(&ptreetbl, proph);
	if (propp == NULL)
		return (ptree_hdl_error(proph));
	else if (!(propp->obj_type & PICL_OBJ_PROP))
		return (PICL_NOTPROP);
	if (ret)
		*ret = propp;
	return (PICL_SUCCESS);
}

static int
lookup_verify_node_handle(picl_nodehdl_t nodeh, picl_obj_t **ret)
{
	picl_obj_t	*nodep;

	nodep = hash_lookup_obj(&ptreetbl, nodeh);
	if (nodep == NULL)
		return (ptree_hdl_error(nodeh));
	else if (nodep->obj_type != PICL_OBJ_NODE)
		return (PICL_NOTNODE);
	if (ret)
		*ret = nodep;
	return (PICL_SUCCESS);
}

static int
lookup_prop_by_name(picl_obj_t *nodep, const char *pname, picl_obj_t **ret)
{
	picl_obj_t	*propp;

	if (strcmp(pname, PICL_PROP_PARENT) == 0) {
		if (nodep->parent_node == NULL)
			return (PICL_PROPNOTFOUND);
		else
			return (PICL_SUCCESS);
	}
	if (strcmp(pname, PICL_PROP_CHILD) == 0) {
		if (nodep->child_node == NULL)
			return (PICL_PROPNOTFOUND);
		else
			return (PICL_SUCCESS);
	}
	if (strcmp(pname, PICL_PROP_PEER) == 0) {
		if (nodep->sibling_node == NULL)
			return (PICL_PROPNOTFOUND);
		else
			return (PICL_SUCCESS);
	}

	propp = nodep->first_prop;
	while (propp != NULL) {
		if (strcmp(propp->prop_name, pname) == 0) {
			if (ret)
				*ret = propp;
			return (PICL_SUCCESS);
		}
		propp = propp->next_prop;
	}
	return (PICL_PROPNOTFOUND);
}

/*
 * This function locks the ptree, verifies that the handle is a reference
 * to a node of specified class name, releases the lock
 */
static int
check_ref_handle(picl_nodehdl_t refh, char *clname)
{
	picl_obj_t	*refobj;
	picl_obj_t	*propp;
	int		err;

	(void) rw_rdlock(&ptree_rwlock);	/* Lock ptree */
	refobj = hash_lookup_obj(&ptreetbl, refh);
	if ((refobj == NULL) || !(refobj->obj_type & PICL_OBJ_NODE)) {
		(void) rw_unlock(&ptree_rwlock);
		return (PICL_INVREFERENCE);
	}

	err = lookup_prop_by_name(refobj, PICL_PROP_CLASSNAME, &propp);
	if ((err != PICL_SUCCESS) || (propp->prop_val == NULL) ||
	    (strcmp(propp->prop_val, clname) != 0))
		err = PICL_INVREFERENCE;
	(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
	return (err);
}

static int
check_table_handle(picl_prophdl_t tblh)
{
	picl_obj_t	*tbl_obj;
	int		err;

	(void) rw_rdlock(&ptree_rwlock);
	err = PICL_SUCCESS;
	tbl_obj = hash_lookup_obj(&ptreetbl, tblh);
	if ((tbl_obj == NULL) || !(tbl_obj->obj_type & PICL_OBJ_TABLE))
		err = PICL_NOTTABLE;
	(void) rw_unlock(&ptree_rwlock);
	return (err);
}

/*
 * PICLTree Interface routines for plug-in modules
 */
int
ptree_get_root(picl_nodehdl_t *rooth)
{
	*rooth = ptree_root_hdl;
	return (PICL_SUCCESS);
}

/*
 * Lock free create a property object
 */
static int
create_propobj(const ptree_propinfo_t *pinfo, const void *valbuf,
    picl_obj_t **pobjp)
{
	picl_obj_t	*pobj;

	if (pinfo->version != PTREE_PROPINFO_VERSION_1)
		return (PICL_NOTSUPPORTED);

	if (!(pinfo->piclinfo.accessmode & PICL_VOLATILE) &&
	    (pinfo->piclinfo.type != PICL_PTYPE_VOID) &&
	    (valbuf == NULL))
		return (PICL_INVALIDARG);

	pobj = malloc(sizeof (picl_obj_t));
	if (pobj == NULL)
		return (PICL_FAILURE);

	pobj->obj_type = PICL_OBJ_PROP;
	pobj->pinfo_ver = pinfo->version;
	pobj->prop_type = pinfo->piclinfo.type;
	pobj->prop_mode = pinfo->piclinfo.accessmode;
	pobj->prop_size = pinfo->piclinfo.size;
	(void) strcpy(pobj->prop_name, pinfo->piclinfo.name);
	pobj->read_func = pinfo->read;
	pobj->write_func = pinfo->write;

	pobj->prop_val = NULL;
	if (!(pinfo->piclinfo.accessmode & PICL_VOLATILE)) {
		pobj->prop_val = malloc(pinfo->piclinfo.size);
		if (pobj->prop_val == NULL) {
			free(pobj);
			return (PICL_FAILURE);
		}
		if (pobj->prop_type == PICL_PTYPE_CHARSTRING)
			(void) strlcpy(pobj->prop_val, valbuf,
			    pinfo->piclinfo.size);
		else
			(void) memcpy(pobj->prop_val, valbuf,
			    pinfo->piclinfo.size);
	}
	pobj->prop_node = NULL;
	pobj->ptree_hdl = PICL_INVALID_PICLHDL;
	pobj->picl_hdl = PICL_INVALID_PICLHDL;
	pobj->next_prop = NULL;
	pobj->next_row = NULL;
	pobj->next_col = NULL;

	*pobjp = pobj;
	return (PICL_SUCCESS);
}

/*
 * Check for valid arguments, create a property object,
 * Lock ptree_rwlock, add the new property handle, release the lock
 * For reference properties and table properties, the handles are verified
 * before creating the property.
 */
int
ptree_create_prop(const ptree_propinfo_t *pinfo, const void *valbuf,
    picl_prophdl_t *proph)
{
	picl_obj_t	*pobj;
	picl_nodehdl_t	refh;
	picl_prophdl_t	tblh;
	int		err;
	char		*ptr;
	int		refflag;
	char		classname[PICL_PROPNAMELEN_MAX];

	if (pinfo == NULL)
		return (PICL_INVALIDARG);
	if (pinfo->version != PTREE_PROPINFO_VERSION_1)
		return (PICL_NOTSUPPORTED);
	if (pinfo->piclinfo.size >= PICL_PROPSIZE_MAX)
		return (PICL_VALUETOOBIG);
	if (picl_restricted(pinfo->piclinfo.name))
		return (PICL_RESERVEDNAME);

	refflag = 0;
	if ((pinfo->piclinfo.name[0] == '_') &&
	    (strchr(&pinfo->piclinfo.name[1], '_') != NULL))
		refflag = 1;

	if (pinfo->piclinfo.type == PICL_PTYPE_REFERENCE) {
		if (refflag == 0)
			return (PICL_INVREFERENCE);
		/*
		 * check valid reference handle for non-volatiles
		 */
		if (!(pinfo->piclinfo.accessmode & PICL_VOLATILE)) {
			if (valbuf == NULL)
				return (PICL_INVREFERENCE);
			if (pinfo->piclinfo.size != sizeof (picl_nodehdl_t))
				return (PICL_INVREFERENCE);
			(void) strcpy(classname, pinfo->piclinfo.name);
			ptr = strchr(&classname[1], '_');
			*ptr = '\0';
			refh = *(picl_hdl_t *)valbuf;
			err = check_ref_handle(refh, &classname[1]);
			if (err != PICL_SUCCESS)
				return (err);
		}
	} else if (refflag == 1)
		return (PICL_INVREFERENCE);
	else if ((pinfo->piclinfo.type == PICL_PTYPE_TABLE) &&
	    (!(pinfo->piclinfo.accessmode & PICL_VOLATILE))) {
		if (pinfo->piclinfo.size != sizeof (picl_prophdl_t))
			return (PICL_INVALIDARG);
		tblh = *(picl_prophdl_t *)valbuf;
		err = check_table_handle(tblh);
		if (err != PICL_SUCCESS)
			return (err);
	} else if ((strcmp(pinfo->piclinfo.name, PICL_PROP_CLASSNAME) == 0) &&
	    ((pinfo->piclinfo.type != PICL_PTYPE_CHARSTRING) ||
	    (strlen(valbuf) >= PICL_CLASSNAMELEN_MAX)))
		return (PICL_RESERVEDNAME);
	else if ((strcmp(pinfo->piclinfo.name, PICL_PROP_NAME) == 0) &&
	    (pinfo->piclinfo.type != PICL_PTYPE_CHARSTRING))
		return (PICL_RESERVEDNAME);
	/*
	 * No locks held when you get here
	 */
	err = create_propobj(pinfo, valbuf, &pobj);
	if (err != PICL_SUCCESS)
		return (err);

	alloc_and_add_to_ptree(pobj);
	*proph = pobj->ptree_hdl;
	return (PICL_SUCCESS);
}

/*
 * Lock free routine to destroy table entries
 * This function removes the destroyed handles from the hash table
 * Uses lock free routines: hash_lookup() and hash_remove()
 */
static void
destroy_table(picl_obj_t *pobj)
{
	picl_prophdl_t  tblh;
	picl_obj_t	*tbl_obj;
	picl_obj_t	*rowp;
	picl_obj_t	*colp;
	picl_obj_t	*freep;

	tblh = *(picl_prophdl_t *)pobj->prop_val;
	tbl_obj = hash_lookup_obj(&ptreetbl, tblh);
	if (tbl_obj == NULL)
		return;

	assert(tbl_obj->obj_type & PICL_OBJ_TABLE);

	/* Delete all entries */
	rowp = tbl_obj->next_row;
	while (rowp != NULL) {
		colp = rowp;
		rowp = rowp->next_col;
		while (colp != NULL) {
			freep = colp;
			colp = colp->next_row;
			(void) hash_remove(&ptreetbl, freep->ptree_hdl);
			if (freep->prop_val)
				free(freep->prop_val);
			free(freep);
		}
	}

	(void) hash_remove(&ptreetbl, tbl_obj->ptree_hdl);
	free(tbl_obj);
}


/*
 * Lock free function that frees up a property object and removes the
 * handles from Ptree table
 */
static void
destroy_propobj(picl_obj_t *propp)
{
	if (propp->prop_type == PICL_PTYPE_TABLE)
		destroy_table(propp);

	(void) hash_remove(&ptreetbl, propp->ptree_hdl);
	if (propp->prop_val)
		free(propp->prop_val);
	free(propp);
}

/*
 * This function destroys a previously deleted property.
 * A deleted property does not have an associated node.
 * All memory allocated for this property are freed
 */
int
ptree_destroy_prop(picl_prophdl_t proph)
{
	picl_obj_t	*propp;

	(void) rw_wrlock(&ptree_rwlock);	/* Exclusive Lock ptree */

	propp = hash_lookup_obj(&ptreetbl, proph);
	if (propp == NULL) {
		(void) rw_unlock(&ptree_rwlock);	/* Unlock ptree */
		return (ptree_hdl_error(proph));
	}

	/* Is the prop still attached to a node? */
	if (propp->prop_node != NULL) {
		(void) rw_unlock(&ptree_rwlock);	/* Unlock ptree */
		return (PICL_CANTDESTROY);
	}

	destroy_propobj(propp);

	(void) rw_unlock(&ptree_rwlock);		/* Unlock ptree */
	return (PICL_SUCCESS);
}

/*
 * This function adds a property to the property list of a node and adds
 * it to the PICL table if the node has a PICL handle.
 * This function locks the picl_rwlock and ptree_rwlock.
 */
int
ptree_add_prop(picl_nodehdl_t nodeh, picl_prophdl_t proph)
{
	int		err;
	picl_obj_t	*nodep;
	picl_obj_t	*propp;
	picl_obj_t  	*tbl_obj;
	picl_obj_t	*refobj;

	(void) rw_rdlock(&ptree_rwlock);		/* RDLock ptree */

	/*
	 * Verify property handle
	 */
	err = lookup_verify_prop_handle(proph, &propp);
	if (err != PICL_SUCCESS) {
		(void) rw_unlock(&ptree_rwlock);	/* Unlock ptree */
		return (err);
	}

	if (propp->prop_node != NULL) {
		(void) rw_unlock(&ptree_rwlock);
		return (PICL_INVALIDARG);
	}

	nodep = NULL;
	/*
	 * Exclusive Lock the node's properties
	 */
	err = lookup_and_lock_node(WRLOCK_NODE, nodeh, &nodep);
	if (err != PICL_SUCCESS) {
		(void) rw_unlock(&ptree_rwlock);	/* Unlock ptree */
		return (err);
	}

	/*
	 * check if prop already exists
	 */
	err = lookup_prop_by_name(nodep, propp->prop_name, NULL);
	if (err == PICL_SUCCESS) {
		unlock_node(nodep);			/* Unlock node */
		(void) rw_unlock(&ptree_rwlock);	/* Unlock table */
		return (PICL_PROPEXISTS);
	}

	/*
	 * Verify property's value
	 */
	tbl_obj = NULL;
	switch (propp->prop_type) {
	case PICL_PTYPE_TABLE:
		if (propp->prop_mode & PICL_VOLATILE)
			break;
		err = lookup_verify_table_prop(propp, &tbl_obj);
		if (err != PICL_SUCCESS) {
			unlock_node(nodep);
			(void) rw_unlock(&ptree_rwlock);
			return (err);
		}
		tbl_obj->prop_node = nodep;	/* set table's nodep */
		tbl_obj->table_prop = propp;	/* set table prop */
		break;
	case PICL_PTYPE_REFERENCE:
		if (propp->prop_mode & PICL_VOLATILE)
			break;
		err = lookup_verify_ref_prop(propp, &refobj);
		if (err != PICL_SUCCESS) {
			unlock_node(nodep);
			(void) rw_unlock(&ptree_rwlock);
			return (err);
		}
		if (IS_PICLIZED(nodep) && !IS_PICLIZED(refobj)) {
			unlock_node(nodep);
			(void) rw_unlock(&ptree_rwlock);
			return (err);
		}
		break;
	default:
		break;
	}

	if (IS_PICLIZED(nodep))
		piclize_prop(propp);
	/*
	 * Add prop to beginning of list
	 */
	propp->prop_node = nodep;		/* set prop's nodep */
	propp->next_prop = nodep->first_prop;
	nodep->first_prop = propp;

	unlock_node(nodep);				/* Unlock node */
	(void) rw_unlock(&ptree_rwlock);		/* Unlock table */
	return (PICL_SUCCESS);
}

/*
 * Lock free function that unlinks a property from its node
 */
static int
unlink_prop(picl_obj_t *nodep, picl_obj_t *propp)
{
	picl_obj_t	*iterp;

	iterp = nodep->first_prop;
	if (iterp == propp) {	/* first property */
		nodep->first_prop = iterp->next_prop;
		return (PICL_SUCCESS);
	}
	while ((iterp != NULL) && (iterp->next_prop != propp))
		iterp = iterp->next_prop;
	if (iterp == NULL)
		return (PICL_PROPNOTFOUND);
	iterp->next_prop = propp->next_prop;
	return (PICL_SUCCESS);
}

/*
 * This function deletes the specified property from the property list
 * of its node and removes the handle from PICL table, if the node
 * was piclized.
 */
int
ptree_delete_prop(picl_prophdl_t proph)
{
	int		err;
	picl_obj_t	*nodep;
	picl_obj_t	*propp;

	(void) rw_rdlock(&ptree_rwlock);		/* lock ptree */
	/*
	 * Lookup the property's node and lock it if there is one
	 * return the objects for the property and the node
	 */
	nodep = propp = NULL;
	err = lookup_and_lock_propnode(WRLOCK_NODE, proph, &nodep, &propp);
	if (err != PICL_SUCCESS) {
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (err);
	} else if (nodep == NULL) {
		/* Nothing to do - already deleted! */
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (PICL_SUCCESS);
	}

	if (propp->obj_type & PICL_OBJ_TABLEENTRY) {
		unlock_node(nodep);			/* Unlock node */
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (PICL_NOTPROP);
	}

	err = unlink_prop(nodep, propp);
	if (err != PICL_SUCCESS) {
		unlock_node(nodep);			/* Unlock node */
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (err);
	}

	propp->prop_node = NULL;	/* reset prop's nodep */
	propp->next_prop = NULL;

	unpiclize_prop(propp);

	unlock_node(nodep);				/* Unlock node */
	(void) rw_unlock(&ptree_rwlock);		/* unlock ptree */
	return (PICL_SUCCESS);
}

/*
 * Create a table object and return its handle
 */
int
ptree_create_table(picl_prophdl_t *tblh)
{
	picl_obj_t	*pobj;

	pobj = malloc(sizeof (picl_obj_t));
	if (pobj == NULL)
		return (PICL_FAILURE);
	pobj->obj_type = PICL_OBJ_TABLE;
	pobj->prop_val = NULL;
	pobj->prop_node = NULL;
	pobj->ptree_hdl = PICL_INVALID_PICLHDL;
	pobj->picl_hdl = PICL_INVALID_PICLHDL;
	pobj->table_prop = NULL;
	pobj->next_row = NULL;
	pobj->next_col = NULL;

	alloc_and_add_to_ptree(pobj);
	*tblh = pobj->ptree_hdl;
	return (PICL_SUCCESS);
}

/*
 * Add the properties in <props> array as a row in the table
 * Add PICL handles if the table has a valid PICL handle
 */
int
ptree_add_row_to_table(picl_prophdl_t tblh, int nprops,
    const picl_prophdl_t *props)
{
	picl_obj_t	*tbl_obj;
	picl_obj_t	*nodep;
	picl_obj_t	*lastrow;
	picl_obj_t	**newrow;
	int		i;
	int		err;
	picl_obj_t	*pobj;
	int		picl_it;

	if (nprops < 1)
		return (PICL_INVALIDARG);

	newrow = malloc(sizeof (picl_obj_t *) * nprops);
	if (newrow == NULL)
		return (PICL_FAILURE);

	(void) rw_rdlock(&ptree_rwlock);		/* Lock ptree */

	err = lookup_and_lock_tablenode(WRLOCK_NODE, tblh, &nodep, &tbl_obj);
	if (err != PICL_SUCCESS) {
		free(newrow);
		(void) rw_unlock(&ptree_rwlock);	/* Unlock table */
		return (err);
	}

	/*
	 * make sure all are either props or table handles
	 */
	for (i = 0; i < nprops; ++i) {
		pobj = newrow[i] = hash_lookup_obj(&ptreetbl, props[i]);
		if (pobj == NULL) {	/* no object */
			err = ptree_hdl_error(props[i]);
			break;
		}
		if ((!(pobj->obj_type & PICL_OBJ_PROP)) &&
		    (!(pobj->obj_type & PICL_OBJ_TABLE))) {
			err = PICL_NOTPROP;
			break;
		}
		if (IS_PICLIZED(pobj) || (pobj->prop_table != NULL) ||
		    (pobj->prop_node != NULL)) {
			err = PICL_INVALIDARG;
			break;
		}

	}
	if (err != PICL_SUCCESS) {
		free(newrow);
		unlock_node(nodep);
		(void) rw_unlock(&ptree_rwlock);	/* Unlock table */
		return (err);
	}

	/*
	 * Mark all props as table entries, set up row linkages
	 */
	picl_it = 0;
	if (IS_PICLIZED(tbl_obj))
		picl_it = 1;
	for (i = 0; i < nprops; ++i) {
		newrow[i]->obj_type |= PICL_OBJ_TABLEENTRY;
		newrow[i]->prop_table = tbl_obj;
		newrow[i]->next_prop = NULL;
		newrow[i]->next_col =  NULL;
		if (picl_it)
			piclize_obj(newrow[i]);
		if (i != nprops - 1)
			newrow[i]->next_row = newrow[i+1];
	}
	newrow[nprops - 1]->next_row = NULL;

	if (tbl_obj->next_row == NULL) {	/* add first row */
		tbl_obj->next_row = newrow[0];
		tbl_obj->next_col = newrow[0];
	} else {
		lastrow = tbl_obj->next_row;
		while (lastrow->next_col != NULL)
			lastrow = lastrow->next_col;
		i = 0;
		while (lastrow != NULL) {
			lastrow->next_col = newrow[i];
			lastrow = lastrow->next_row;
			++i;
		}
	}

	unlock_node(nodep);			/* unlock node */
	(void) rw_unlock(&ptree_rwlock);	/* Unlock ptree */
	free(newrow);
	return (PICL_SUCCESS);
}

/*
 * This function returns the handle of the next property in the row
 */
int
ptree_get_next_by_row(picl_prophdl_t proph, picl_prophdl_t *nextrowh)
{
	int		err;
	picl_obj_t	*nodep;
	picl_obj_t	*propp;

	(void) rw_rdlock(&ptree_rwlock);		/* lock ptree */

	nodep = propp = NULL;
	/*
	 * proph could be a table handle or a table entry handle
	 * Look it up as a table entry handle first, check error code
	 * to see if it is a table handle
	 */
	err = lookup_and_lock_tableprop_node(RDLOCK_NODE, proph, &nodep,
	    &propp);
	if (err != PICL_SUCCESS) {
		(void) rw_unlock(&ptree_rwlock);
		return (err);
	}

	if (propp->next_row)
		*nextrowh = propp->next_row->ptree_hdl;
	else
		err = PICL_ENDOFLIST;

	unlock_node(nodep);			/* unlock node */
	(void) rw_unlock(&ptree_rwlock);		/* unlock ptree */
	return (err);
}

int
ptree_get_next_by_col(picl_prophdl_t proph, picl_prophdl_t *nextcolh)
{
	int		err;
	picl_obj_t	*propp;
	picl_obj_t	*nodep;

	(void) rw_rdlock(&ptree_rwlock);		/* lock ptree */
	nodep = propp = NULL;
	/*
	 * proph could be a table handle or a table entry handle
	 * Look it up as a table entry handle first, check error code
	 * to see if it is a table handle
	 */
	err = lookup_and_lock_tableprop_node(RDLOCK_NODE, proph, &nodep,
	    &propp);
	if (err != PICL_SUCCESS) {
		(void) rw_unlock(&ptree_rwlock);
		return (err);
	}

	if (propp->next_col)
		*nextcolh = propp->next_col->ptree_hdl;
	else
		err = PICL_ENDOFLIST;

	unlock_node(nodep);			/* unlock node */
	(void) rw_unlock(&ptree_rwlock);		/* unlock ptree */
	return (err);
}

/*
 * This function creates node object and adds its handle to the Ptree
 */
int
ptree_create_node(const char *name, const char *clname, picl_nodehdl_t *nodeh)
{
	picl_obj_t 		*pobj;
	ptree_propinfo_t 	propinfo;
	picl_prophdl_t		phdl;
	picl_prophdl_t		cphdl;
	int			err;

	if ((name == NULL) || (*name == '\0') ||
	    (clname == NULL) || (*clname == '\0'))
		return (PICL_INVALIDARG);

	if ((strlen(name) >= PICL_PROPNAMELEN_MAX) ||
	    (strlen(clname) >= PICL_CLASSNAMELEN_MAX))
		return (PICL_VALUETOOBIG);

	/*
	 * Create the picl object for node
	 */
	pobj = malloc(sizeof (picl_obj_t));
	if (pobj == NULL)
		return (PICL_FAILURE);
	pobj->obj_type = PICL_OBJ_NODE;
	pobj->first_prop = NULL;
	pobj->ptree_hdl = PICL_INVALID_PICLHDL;
	pobj->picl_hdl = PICL_INVALID_PICLHDL;
	pobj->parent_node = NULL;
	pobj->sibling_node = NULL;
	pobj->child_node = NULL;
	pobj->node_classname = strdup(clname);
	if (pobj->node_classname == NULL) {
		free(pobj);
		return (PICL_FAILURE);
	}
	(void) rwlock_init(&pobj->node_lock, USYNC_THREAD, NULL);

	alloc_and_add_to_ptree(pobj);	/* commit the node */

	/*
	 * create name property
	 */
	propinfo.version = PTREE_PROPINFO_VERSION_1;
	propinfo.piclinfo.type = PICL_PTYPE_CHARSTRING;
	propinfo.piclinfo.accessmode = PICL_READ;
	propinfo.piclinfo.size = strlen(name) + 1;
	(void) strcpy(propinfo.piclinfo.name, PICL_PROP_NAME);
	propinfo.read = NULL;
	propinfo.write = NULL;
	err = ptree_create_prop(&propinfo, (const void *)name, &phdl);
	if (err != PICL_SUCCESS) {
		(void) ptree_destroy_node(pobj->ptree_hdl);
		return (err);
	}
	err = ptree_add_prop(pobj->ptree_hdl, phdl);
	if (err != PICL_SUCCESS) {
		(void) ptree_destroy_prop(phdl);
		(void) ptree_destroy_node(pobj->ptree_hdl);
		return (err);
	}

	/*
	 * create picl classname property
	 */
	propinfo.piclinfo.size = strlen(clname) + 1;
	(void) strcpy(propinfo.piclinfo.name, PICL_PROP_CLASSNAME);
	propinfo.read = NULL;
	propinfo.write = NULL;
	err = ptree_create_prop(&propinfo, (const void *)clname, &cphdl);
	if (err != PICL_SUCCESS) {
		(void) ptree_destroy_node(pobj->ptree_hdl);
		return (err);
	}
	err = ptree_add_prop(pobj->ptree_hdl, cphdl);
	if (err != PICL_SUCCESS) {
		(void) ptree_destroy_prop(cphdl);
		(void) ptree_destroy_node(pobj->ptree_hdl);
		return (err);
	}

	*nodeh = pobj->ptree_hdl;
	return (PICL_SUCCESS);
}

/*
 * Destroy a node/subtree freeing up space
 * Removed destroyed objects' handles from PTree table
 */
static void
destroy_subtree(picl_obj_t *nodep)
{
	picl_obj_t	*iterp;
	picl_obj_t	*freep;
	picl_obj_t	*chdp;

	if (nodep == NULL)
		return;

	chdp = nodep->child_node;
	while (chdp != NULL) {
		freep = chdp;
		chdp = chdp->sibling_node;
		destroy_subtree(freep);
	}

	/*
	 * Lock the node
	 */
	(void) lock_obj(WRLOCK_NODE, nodep);

	/*
	 * destroy all properties associated with this node
	 */
	iterp = nodep->first_prop;
	while (iterp != NULL) {
		freep = iterp;
		iterp = iterp->next_prop;
		destroy_propobj(freep);
	}

	(void) hash_remove(&ptreetbl, nodep->ptree_hdl);
	(void) rwlock_destroy(&nodep->node_lock);
	free(nodep->node_classname);
	free(nodep);
}

/*
 * This function destroys a previously deleted node/subtree. All the properties
 * are freed and removed from the PTree table.
 * Only one destroy is in progress at any time.
 */
int
ptree_destroy_node(picl_nodehdl_t nodeh)
{
	picl_obj_t	*nodep;
	picl_obj_t	*parp;
	picl_obj_t	*np;
	int		err;

	(void) rw_wrlock(&ptree_rwlock);	/* exclusive wrlock ptree */
	nodep = NULL;
	err = lookup_verify_node_handle(nodeh, &nodep);
	if (err != PICL_SUCCESS) {
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (err);
	}

	/*
	 * Has this node/subtree been deleted?
	 */
	if (IS_PICLIZED(nodep)) {
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (PICL_CANTDESTROY);
	}

	/*
	 * update parent's child list to repair the tree when
	 * parent is not null
	 */
	parp = nodep->parent_node;
	if (parp == NULL) {			/* root */
		destroy_subtree(nodep);
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (PICL_SUCCESS);
	}

	np = parp->child_node;
	if (np == nodep) {  /* first child */
		parp->child_node = nodep->sibling_node;
	} else {
		while ((np != NULL) && (np->sibling_node != nodep))
			np = np->sibling_node;
		if (np != NULL)
			np->sibling_node = nodep->sibling_node;
	}

	destroy_subtree(nodep);
	(void) rw_unlock(&ptree_rwlock);		/* unlock ptree */
	return (PICL_SUCCESS);
}

/*
 * This function deletes a node/subtree from the tree and removes the handles
 * from PICL table
 */
int
ptree_delete_node(picl_nodehdl_t nodeh)
{
	picl_obj_t	*nodep;
	picl_obj_t	*parp;
	picl_obj_t	*np;
	int		err;

	(void) rw_wrlock(&ptree_rwlock);	/* exclusive wrlock ptree */

	nodep = NULL;
	err = lookup_verify_node_handle(nodeh, &nodep);
	if (err != PICL_SUCCESS) {
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (err);
	}

	/*
	 * unparent it
	 */
	parp = nodep->parent_node;
	if (parp != NULL) {
		np = parp->child_node;
		if (np == nodep)	/* first child */
			parp->child_node = nodep->sibling_node;
		else {
			while ((np != NULL) && (np->sibling_node != nodep))
				np = np->sibling_node;
			if (np != NULL)
				np->sibling_node = nodep->sibling_node;
		}
	}

	nodep->parent_node = NULL;
	nodep->sibling_node = NULL;

	unpiclize_node(nodep);

	(void) rw_unlock(&ptree_rwlock);		/* unlock ptree */
	return (PICL_SUCCESS);
}

/*
 * This function adds a node as a child of another node
 */
int
ptree_add_node(picl_nodehdl_t parh, picl_nodehdl_t chdh)
{
	picl_obj_t	*pnodep;
	picl_obj_t	*cnodep;
	picl_obj_t	*nodep;
	int		err;

	(void) rw_wrlock(&ptree_rwlock);	/* exclusive lock ptree */

	pnodep = cnodep = NULL;
	err = lookup_verify_node_handle(parh, &pnodep);
	if (err != PICL_SUCCESS) {
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (err);
	}

	err = lookup_verify_node_handle(chdh, &cnodep);
	if (err != PICL_SUCCESS) {
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (err);
	}

	/* is chdh already a child? */
	if (cnodep->parent_node != NULL) {
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (PICL_CANTPARENT);
	}

	/*
	 * append child to children list
	 */
	cnodep->parent_node = pnodep;
	if (pnodep->child_node == NULL)
		pnodep->child_node = cnodep;
	else {
		for (nodep = pnodep->child_node; nodep->sibling_node != NULL;
		    nodep = nodep->sibling_node)
			continue;
		nodep->sibling_node = cnodep;

	}

	/* piclize */
	if (IS_PICLIZED(pnodep))
		piclize_node(cnodep);
	(void) rw_unlock(&ptree_rwlock);		/* unlock ptree */
	return (PICL_SUCCESS);
}

static void
copy_propinfo_ver_1(ptree_propinfo_t *pinfo, picl_obj_t *propp)
{
	pinfo->version = propp->pinfo_ver;
	pinfo->piclinfo.type = propp->prop_type;
	pinfo->piclinfo.accessmode = propp->prop_mode;
	pinfo->piclinfo.size = propp->prop_size;
	(void) strcpy(pinfo->piclinfo.name, propp->prop_name);
	pinfo->read = propp->read_func;
	pinfo->write = propp->write_func;
}

static void
copy_reserved_propinfo_ver_1(ptree_propinfo_t *pinfo, const char *pname)
{
	pinfo->version = PTREE_PROPINFO_VERSION_1;
	pinfo->piclinfo.type = PICL_PTYPE_REFERENCE;
	pinfo->piclinfo.accessmode = PICL_READ;
	pinfo->piclinfo.size = sizeof (picl_nodehdl_t);
	(void) strcpy(pinfo->piclinfo.name, pname);
	pinfo->read = NULL;
	pinfo->write = NULL;
}

/*
 * This function returns the property information to a plug-in
 */
int
ptree_get_propinfo(picl_prophdl_t proph, ptree_propinfo_t *pinfo)
{
	int		err;
	picl_obj_t	*nodep;
	picl_obj_t  	*propp;

	(void) rw_rdlock(&ptree_rwlock);		/* lock ptree */
	nodep = propp = NULL;
	err = lookup_and_lock_propnode(RDLOCK_NODE, proph, &nodep, &propp);
	if (err != PICL_SUCCESS) {
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (err);
	}

	if (propp->pinfo_ver == PTREE_PROPINFO_VERSION_1)
		copy_propinfo_ver_1(pinfo, propp);
	else
		err = PICL_FAILURE;

	unlock_node(nodep);			/* unlock node */
	(void) rw_unlock(&ptree_rwlock);		/* unlock ptree */
	return (err);
}

/*
 * This function returns the property information to a plug-in
 */
int
xptree_get_propinfo_by_name(picl_nodehdl_t nodeh, const char *pname,
    ptree_propinfo_t *pinfo)
{
	int		err;
	picl_obj_t	*nodep;
	picl_obj_t  	*propp;

	(void) rw_rdlock(&ptree_rwlock);		/* lock ptree */
	nodep = propp = NULL;
	err = lookup_and_lock_node(RDLOCK_NODE, nodeh, &nodep); /* lock node */
	if (err != PICL_SUCCESS) {
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (err);
	}

	err = lookup_prop_by_name(nodep, pname, &propp);
	if (err != PICL_SUCCESS) {
		unlock_node(nodep);
		(void) rw_unlock(&ptree_rwlock);
		return (err);
	}

	if (picl_restricted(pname))
		copy_reserved_propinfo_ver_1(pinfo, pname);
	else if (propp->pinfo_ver == PTREE_PROPINFO_VERSION_1)
		copy_propinfo_ver_1(pinfo, propp);
	else
		err = PICL_FAILURE;

	unlock_node(nodep);			/* unlock node */
	(void) rw_unlock(&ptree_rwlock);		/* unlock ptree */
	return (err);
}

/*
 * This function must be called only after a lookup_prop_by_name() returns
 * success and only if picl_restricted() returns true.
 */
static int
read_reserved_propval_and_unlock(picl_obj_t *nodep, const char *pname,
    void *vbuf, size_t size)
{
	void		*srcp;

	if (size != sizeof (picl_nodehdl_t))
		return (PICL_VALUETOOBIG);

	if (strcmp(pname, PICL_PROP_PARENT) == 0)
		srcp = &nodep->parent_node->ptree_hdl;
	else if (strcmp(pname, PICL_PROP_CHILD) == 0)
		srcp = &nodep->child_node->ptree_hdl;
	else if (strcmp(pname, PICL_PROP_PEER) == 0)
		srcp = &nodep->sibling_node->ptree_hdl;
	else
		return (PICL_FAILURE);

	(void) memcpy(vbuf, srcp, sizeof (picl_nodehdl_t));
	unlock_node(nodep);
	(void) rw_unlock(&ptree_rwlock);
	return (PICL_SUCCESS);
}

/*
 * Returns the property value in the buffer and releases the node and
 * ptree locks.
 * For volatile properties, this function releases the locks on ptree
 * table and the node before calling the plug-in provided access function
 */
static int
read_propval_and_unlock(picl_obj_t *nodep, picl_obj_t *propp, void *vbuf,
    door_cred_t cred)
{
	int		err;
	int		(*volrd)(ptree_rarg_t *arg, void *buf);

	err = PICL_SUCCESS;
	if (propp->prop_mode & PICL_VOLATILE) {
		ptree_rarg_t  rarg;

		if (nodep)
			rarg.nodeh = nodep->ptree_hdl;
		else
			rarg.nodeh = PICL_INVALID_PICLHDL;
		rarg.proph = propp->ptree_hdl;
		rarg.cred = cred;
		volrd = propp->read_func;

		unlock_node(nodep);		/* unlock node */
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */

		if (volrd == NULL)
			err = PICL_FAILURE;
		else
			err = (volrd)(&rarg, vbuf);
		return (err);
	} else if (propp->prop_type == PICL_PTYPE_CHARSTRING)
		(void) strlcpy(vbuf, propp->prop_val, propp->prop_size);
	else
		(void) memcpy(vbuf, propp->prop_val, propp->prop_size);

	unlock_node(nodep);
	(void) rw_unlock(&ptree_rwlock);
	return (err);
}

int
xptree_get_propval_with_cred(picl_prophdl_t proph, void *vbuf, size_t size,
    door_cred_t cred)
{
	picl_obj_t	*propp;
	picl_obj_t	*nodep;
	int		err;

	(void) rw_rdlock(&ptree_rwlock);		/* lock ptree */
	nodep = propp = NULL;
	err = lookup_and_lock_propnode(RDLOCK_NODE, proph, &nodep, &propp);
	if (err != PICL_SUCCESS) {
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (err);
	}

	err = check_propsize(PROP_READ, propp, size);
	if (err != PICL_SUCCESS) {
		unlock_node(nodep);		/* unlock node */
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (err);
	}

	return (read_propval_and_unlock(nodep, propp, vbuf, cred));
}

/*
 * This function gets the credentials and  calls get_propval_with_cred.
 */
int
ptree_get_propval(picl_prophdl_t proph, void *vbuf, size_t size)
{
	return (xptree_get_propval_with_cred(proph, vbuf, size, picld_cred));
}

/*
 * This function retrieves a property's value by by its name
 * For volatile properties, the locks on ptree and node are released
 * before calling the plug-in provided access function
 */
int
xptree_get_propval_by_name_with_cred(picl_nodehdl_t nodeh, const char *pname,
    void *vbuf, size_t size, door_cred_t cred)
{
	picl_obj_t	*nodep;
	picl_obj_t	*propp;
	int		err;

	(void) rw_rdlock(&ptree_rwlock);		/* lock ptree */

	nodep = NULL;
	err = lookup_and_lock_node(RDLOCK_NODE, nodeh, &nodep);	/* lock node */
	if (err != PICL_SUCCESS) {
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (err);
	}

	err = lookup_prop_by_name(nodep, pname, &propp);
	if (err != PICL_SUCCESS) {
		unlock_node(nodep);
		(void) rw_unlock(&ptree_rwlock);
		return (err);
	}

	if (picl_restricted(pname))
		return (read_reserved_propval_and_unlock(nodep, pname, vbuf,
		    size));

	err = check_propsize(PROP_READ, propp, size);
	if (err != PICL_SUCCESS) {
		unlock_node(nodep);
		(void) rw_unlock(&ptree_rwlock);
		return (err);
	}

	return (read_propval_and_unlock(nodep, propp, vbuf, cred));
}

/*
 * This function is used by plugins to get a value of a property
 * looking it up by its name.
 */
int
ptree_get_propval_by_name(picl_nodehdl_t nodeh, const char *pname, void *vbuf,
    size_t size)
{
	return (xptree_get_propval_by_name_with_cred(nodeh, pname, vbuf, size,
	    picld_cred));
}

/*
 * This function updates a property's value.
 * For volatile properties, the locks on the node and the ptree table
 * are released before calling the plug-in provided access function.
 */
static int
write_propval_and_unlock(picl_obj_t *nodep, picl_obj_t *propp, const void *vbuf,
    size_t size, door_cred_t cred)
{
	int		err;
	int		(*volwr)(ptree_warg_t *arg, const void *buf);

	err = PICL_SUCCESS;
	if (propp->prop_mode & PICL_VOLATILE) {
		ptree_warg_t  warg;

		if (nodep)
			warg.nodeh = nodep->ptree_hdl;
		else
			warg.nodeh = PICL_INVALID_PICLHDL;
		warg.proph = propp->ptree_hdl;
		warg.cred = cred;
		volwr = propp->write_func;

		unlock_node(nodep);		/* unlock node */
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */

		if (volwr == NULL)
			err = PICL_FAILURE;
		else
			err = (volwr)(&warg, vbuf);
		return (err);
	} else
		(void) memcpy(propp->prop_val, vbuf, size);

	unlock_node(nodep);		/* unlock node */
	(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
	return (err);
}

int
xptree_update_propval_with_cred(picl_prophdl_t proph, const void *vbuf,
    size_t size, door_cred_t cred)
{
	picl_obj_t	*nodep;
	picl_obj_t	*propp;
	int		err;

	(void) rw_rdlock(&ptree_rwlock);		/* lock ptree */
	nodep = propp = NULL;
	err = lookup_and_lock_propnode(WRLOCK_NODE, proph, &nodep, &propp);
	if (err != PICL_SUCCESS) {
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (err);
	}

	err = check_propsize(PROP_WRITE, propp, size);
	if (err != PICL_SUCCESS) {
		unlock_node(nodep);		/* unlock node */
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (err);
	}

	return (write_propval_and_unlock(nodep, propp, vbuf, size, cred));
}

/*
 * Ptree function used by plug-ins to update a property's value
 * calls update_propval_with_cred(), which releases locks for volatile props
 */
int
ptree_update_propval(picl_prophdl_t proph, const void *vbuf, size_t size)
{
	return (xptree_update_propval_with_cred(proph, vbuf, size, picld_cred));
}

/*
 * This function writes/updates a property's value by looking it up
 * by its name.
 * For volatile properties this function releases the locks on the
 * node and the ptree table.
 */
int
xptree_update_propval_by_name_with_cred(picl_nodehdl_t nodeh, const char *pname,
    const void *vbuf, size_t size, door_cred_t cred)
{
	picl_obj_t	*nodep;
	picl_obj_t	*propp;
	int		err;

	(void) rw_rdlock(&ptree_rwlock);		/* lock ptree */
	nodep = NULL;
	err = lookup_and_lock_node(WRLOCK_NODE, nodeh, &nodep);	/* lock node */
	if (err != PICL_SUCCESS) {
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (err);
	}

	if (picl_restricted(pname)) {
		unlock_node(nodep);
		(void) rw_unlock(&ptree_rwlock);
		return (PICL_RESERVEDNAME);
	}

	err = lookup_prop_by_name(nodep, pname, &propp);
	if (err != PICL_SUCCESS) {
		unlock_node(nodep);
		(void) rw_unlock(&ptree_rwlock);
		return (err);
	}

	err = check_propsize(PROP_WRITE, propp, size);
	if (err != PICL_SUCCESS) {
		unlock_node(nodep);
		(void) rw_unlock(&ptree_rwlock);
		return (err);
	}

	return (write_propval_and_unlock(nodep, propp, vbuf, size, cred));
}

/*
 * This function updates the value of a property specified by its name
 */
int
ptree_update_propval_by_name(picl_nodehdl_t nodeh, const char *pname,
    const void *vbuf, size_t size)
{
	return (xptree_update_propval_by_name_with_cred(nodeh, pname, vbuf,
	    size, picld_cred));
}

/*
 * This function retrieves the handle of a property by its name
 */
int
ptree_get_prop_by_name(picl_nodehdl_t nodeh, const char *pname,
    picl_prophdl_t *proph)
{
	picl_obj_t	*nodep;
	picl_obj_t	*propp;
	int		err;

	(void) rw_rdlock(&ptree_rwlock);		/* lock ptree */
	nodep = NULL;
	err = lookup_and_lock_node(RDLOCK_NODE, nodeh, &nodep);	/* lock node */
	if (err != PICL_SUCCESS) {
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (err);
	}

	if (picl_restricted(pname)) {
		err = PICL_RESERVEDNAME;
		unlock_node(nodep);			/* unlock node */
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (err);
	}

	err = lookup_prop_by_name(nodep, pname, &propp);
	if (err == PICL_SUCCESS)
		*proph = propp->ptree_hdl;

	unlock_node(nodep);			/* unlock node */
	(void) rw_unlock(&ptree_rwlock);		/* unlock ptree */
	return (err);
}

/*
 * This function returns the handle of the first property
 */
int
ptree_get_first_prop(picl_nodehdl_t nodeh, picl_prophdl_t *proph)
{
	picl_obj_t	*pobj;
	int		err;

	(void) rw_rdlock(&ptree_rwlock);		/* lock ptree */
	pobj = NULL;
	err = lookup_and_lock_node(RDLOCK_NODE, nodeh, &pobj);	/* lock node */
	if (err != PICL_SUCCESS) {
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (err);
	}

	if (pobj->first_prop)
		*proph = pobj->first_prop->ptree_hdl;
	else
		err = PICL_ENDOFLIST;

	unlock_node(pobj);			/* unlock node */
	(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
	return (err);
}

/*
 * This function returns the handle of next property in the list
 */
int
ptree_get_next_prop(picl_prophdl_t proph, picl_prophdl_t *nextproph)
{
	picl_obj_t	*nodep;
	picl_obj_t	*propp;
	int		err;

	(void) rw_rdlock(&ptree_rwlock);		/* lock ptree */
	nodep = propp = NULL;
	err = lookup_and_lock_propnode(RDLOCK_NODE, proph, &nodep, &propp);
	if (err != PICL_SUCCESS) {
		(void) rw_unlock(&ptree_rwlock);	/* unlock ptree */
		return (err);
	}

	if (propp->next_prop) {
		*nextproph = propp->next_prop->ptree_hdl;
	} else
		err = PICL_ENDOFLIST;

	unlock_node(nodep);				/* unlock node */
	(void) rw_unlock(&ptree_rwlock);		/* unlock ptree */
	return (err);
}

/*
 * These functions are called by ptree_get_node_by_path()
 * Append a prop expression entry to the list
 */
static prop_list_t *
append_entry_to_list(prop_list_t *el, prop_list_t *list)
{
	prop_list_t	*ptr;

	if (el == NULL)
		return (list);

	if (list == NULL) {
		list = el;
		return (list);
	}

	/*
	 * Add it to the end of list
	 */
	ptr = list;

	while (ptr->next != NULL)
		ptr = ptr->next;

	ptr->next = el;

	return (list);
}

/*
 * Free the property expression list
 */
static void
free_list(prop_list_t *list)
{
	prop_list_t	*ptr;
	prop_list_t	*tmp;

	for (ptr = list; ptr != NULL; ptr = tmp) {
		tmp = ptr->next;
		free(ptr);
	}
}

static int
parse_prl(char *prl, char **name, char **baddr, prop_list_t **plist)
{
	char		*propptr;
	char		*ptr;
	char		*pname;
	char		*pval;
	prop_list_t	*el;

	if (prl == NULL)
		return (PICL_FAILURE);

	if ((prl[0] == '@') || (prl[0] == '?'))
		return (PICL_FAILURE);

	*name = prl;

	/*
	 * get property expression
	 */
	ptr = strchr(prl, '?');

	if (ptr != NULL) {
		*ptr = '\0';
		propptr = ptr + 1;
	} else
		propptr = NULL;

	/*
	 * get bus value
	 */
	ptr = strchr(prl, '@');

	if (ptr != NULL) {
		*ptr = '\0';
		*baddr = ptr + 1;
		if (strlen(*baddr) == 0)	/* no bus value after @ */
			return (PICL_FAILURE);
	}

	/*
	 * create the prop list
	 */
	while (propptr != NULL) {
		pname = propptr;
		pval = NULL;

		ptr = strchr(propptr, '?');

		if (ptr != NULL) {  /* more ?<prop>=<propval> */
			*ptr = '\0';
			propptr = ptr + 1;
		} else
			propptr = NULL;

		if (strlen(pname) == 0)	/* no prop exp after ? */
			return (PICL_FAILURE);

		ptr = strchr(pname, '=');
		if (ptr != NULL) { /* not void prop */
			*ptr = '\0';
			pval = ptr + 1;
			/*
			 * <prop>= is treated as void property
			 */
			if (strlen(pval) == 0)
				pval = NULL;
		}

		el = (prop_list_t *)malloc(sizeof (prop_list_t));
		el->pname = pname;
		el->pval = pval;
		el->next = NULL;
		*plist = append_entry_to_list(el, *plist);
	}

	return (PICL_SUCCESS);
}

static int
prop_match(ptree_propinfo_t pinfo, void *vbuf, char *val)
{
	int8_t		cval;
	uint8_t		ucval;
	int16_t		sval;
	uint16_t	usval;
	int32_t		intval;
	uint32_t	uintval;
	int64_t		llval;
	uint64_t	ullval;
	float		fval;
	double		dval;

	switch (pinfo.piclinfo.type) {
	case PICL_PTYPE_CHARSTRING:
		if (strcasecmp(pinfo.piclinfo.name, PICL_PROP_CLASSNAME) == 0) {
			if (strcmp(val, PICL_CLASS_PICL) == 0)
				return (1);
		}
		if (strcmp(val, (char *)vbuf) == 0)
			return (1);
		else
			return (0);
	case PICL_PTYPE_INT:
		switch (pinfo.piclinfo.size) {
		case sizeof (int8_t):
			cval = (int8_t)strtol(val, (char **)NULL, 0);
			return (cval == *(char *)vbuf);
		case sizeof (int16_t):
			sval = (int16_t)strtol(val, (char **)NULL, 0);
			return (sval == *(int16_t *)vbuf);
		case sizeof (int32_t):
			intval = (int32_t)strtol(val, (char **)NULL, 0);
			return (intval == *(int32_t *)vbuf);
		case sizeof (int64_t):
			llval = strtoll(val, (char **)NULL, 0);
			return (llval == *(int64_t *)vbuf);
		default:
			return (0);
		}
	case PICL_PTYPE_UNSIGNED_INT:
		switch (pinfo.piclinfo.size) {
		case sizeof (uint8_t):
			ucval = (uint8_t)strtoul(val, (char **)NULL, 0);
			return (ucval == *(uint8_t *)vbuf);
		case sizeof (uint16_t):
			usval = (uint16_t)strtoul(val, (char **)NULL, 0);
			return (usval == *(uint16_t *)vbuf);
		case sizeof (uint32_t):
			uintval = (uint32_t)strtoul(val, (char **)NULL, 0);
			return (uintval == *(uint32_t *)vbuf);
		case sizeof (uint64_t):
			ullval = strtoull(val, (char **)NULL, 0);
			return (ullval == *(uint64_t *)vbuf);
		default:
			return (0);
		}
	case PICL_PTYPE_FLOAT:
		switch (pinfo.piclinfo.size) {
		case sizeof (float):
			fval = (float)strtod(val, (char **)NULL);
			return (fval == *(float *)vbuf);
		case sizeof (double):
			dval = strtod(val, (char **)NULL);
			return (dval == *(double *)vbuf);
		default:
			return (0);
		}
	case PICL_PTYPE_VOID:
	case PICL_PTYPE_TIMESTAMP:
	case PICL_PTYPE_TABLE:
	case PICL_PTYPE_REFERENCE:
	case PICL_PTYPE_BYTEARRAY:
	case PICL_PTYPE_UNKNOWN:
	default:
		return (0);
	}
}

static int
check_propval(picl_nodehdl_t nodeh, char *pname, char *pval)
{
	int			err;
	picl_prophdl_t		proph;
	ptree_propinfo_t 	pinfo;
	void			*vbuf;

	err = ptree_get_prop_by_name(nodeh, pname, &proph);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_get_propinfo(proph, &pinfo);
	if (err != PICL_SUCCESS)
		return (err);

	if (pval == NULL) {	/* void type */
		if (pinfo.piclinfo.type != PICL_PTYPE_VOID)
			return (PICL_FAILURE);
	} else {
		vbuf = alloca(pinfo.piclinfo.size);
		if (vbuf == NULL)
			return (PICL_FAILURE);
		err = ptree_get_propval(proph, vbuf,
		    pinfo.piclinfo.size);
		if (err != PICL_SUCCESS)
			return (err);

		if (!prop_match(pinfo, vbuf, pval))
			return (PICL_FAILURE);
	}
	return (PICL_SUCCESS);
}

static int
get_child_by_path(picl_nodehdl_t rooth, char *prl,
    picl_nodehdl_t *nodeh, char *pname)
{
	picl_nodehdl_t		chdh;
	int			err;
	char			*nameval;
	char			*nodename;
	char			*path;
	char			*baddr;
	char			*busval;
	prop_list_t		*plist;
	prop_list_t		*ptr;

	if (prl == NULL)
		return (PICL_FAILURE);

	path = strdupa(prl);
	if (path == NULL)
		return (PICL_FAILURE);

	plist = NULL;
	nodename = NULL;
	baddr = NULL;

	err = parse_prl(path, &nodename, &baddr, &plist);
	if (err != PICL_SUCCESS) {
		free_list(plist);
		return (err);
	}

	if (nodename == NULL)
		return (PICL_FAILURE);

	nameval = alloca(strlen(nodename) + 1);
	if (nameval == NULL) {
		free_list(plist);
		return (PICL_FAILURE);
	}

	if (baddr != NULL) {
		busval = alloca(strlen(baddr) + 1);
		if (busval == NULL) {
			free_list(plist);
			return (PICL_FAILURE);
		}
	}

	for (err = ptree_get_propval_by_name(rooth, PICL_PROP_CHILD, &chdh,
	    sizeof (picl_nodehdl_t)); err != PICL_PROPNOTFOUND;
	    err = ptree_get_propval_by_name(chdh, PICL_PROP_PEER, &chdh,
	    sizeof (picl_nodehdl_t))) {
		if (err != PICL_SUCCESS) {
			free_list(plist);
			return (PICL_FAILURE);
		}

		/*
		 * compare name
		 */
		if ((strcmp(pname, PICL_PROP_CLASSNAME) != 0) ||
		    (strcmp(nodename, PICL_CLASS_PICL) != 0)) {
			err = ptree_get_propval_by_name(chdh, pname,
			    nameval, (strlen(nodename) + 1));

			if (err != PICL_SUCCESS)
				continue;
			if (strcmp(nameval, nodename) != 0)
				continue;
		}

		/*
		 * compare device address with bus-addr prop first
		 * then with UnitAddress property
		 */
		if (baddr != NULL) { /* compare bus-addr prop */
			if ((ptree_get_propval_by_name(chdh, PICL_PROP_BUS_ADDR,
			    busval, (strlen(baddr) + 1)) != PICL_SUCCESS) &&
			    (ptree_get_propval_by_name(chdh,
			    PICL_PROP_UNIT_ADDRESS, busval,
			    (strlen(baddr) + 1)) != PICL_SUCCESS))
				continue;

			if (strcmp(busval, baddr) != 0)
				continue; /* not match */
		}

		if (plist == NULL) { /* no prop expression */
			*nodeh = chdh;
			return (PICL_SUCCESS);
		}

		/*
		 * compare the property expression list
		 */
		ptr = plist;

		while (ptr != NULL) {
			err = check_propval(chdh, ptr->pname, ptr->pval);
			if (err != PICL_SUCCESS)
				break;

			ptr = ptr->next;
		}
		if (ptr == NULL) {
			*nodeh = chdh;
			free_list(plist);
			return (PICL_SUCCESS);
		}
	}
	free_list(plist);
	return (PICL_NOTNODE);
}

/*
 * This functions returns the handle of node specified by its path
 */
int
ptree_get_node_by_path(const char *piclprl, picl_nodehdl_t *handle)
{
	picl_nodehdl_t	rooth;
	picl_nodehdl_t	chdh;
	char		*path;
	char		*ptr;
	char		*defprop;
	char		*tokindex;
	int 		err;
	int		len;
	int		npflg;	/* namepath flag */


	path = strdupa(piclprl);
	if (path == NULL)
		return (PICL_FAILURE);

	npflg = 1;	/* default */
	defprop = path;
	if (path[0] == '/') {
		ptr = &path[1];
	} else if ((tokindex = strchr(path, ':')) != NULL) {
		*tokindex = '\0';
		++tokindex;
		if (*tokindex == '/')
			ptr = tokindex + 1;
		else
			return (PICL_NOTNODE);
		npflg = 0;
	} else
		return (PICL_NOTNODE);

	err = ptree_get_root(&rooth);
	if (err != PICL_SUCCESS)
		return (err);

	for (chdh = rooth, tokindex = strchr(ptr, '/');
	    tokindex != NULL;
	    ptr = tokindex + 1, tokindex = strchr(ptr, '/')) {
		*tokindex = '\0';
		if (npflg)
			err = get_child_by_path(chdh, ptr, &chdh,
			    PICL_PROP_NAME);
		else
			err = get_child_by_path(chdh, ptr, &chdh,
			    defprop);

		if (err != PICL_SUCCESS)
			return (err);
	}

	/*
	 * check if last token is empty or not
	 * eg. /a/b/c/ or /a/b/c
	 */
	if (*ptr == '\0') {
		*handle = chdh;
		return (PICL_SUCCESS);
	}

	len = strcspn(ptr, " \t\n");
	if (len == 0) {
		*handle = chdh;
		return (PICL_SUCCESS);
	}

	ptr[len] = '\0';
	if (npflg)
		err = get_child_by_path(chdh, ptr, &chdh, PICL_PROP_NAME);
	else
		err = get_child_by_path(chdh, ptr, &chdh, defprop);

	if (err != PICL_SUCCESS)
		return (err);

	*handle = chdh;
	return (PICL_SUCCESS);
}

/*
 * Initialize propinfo
 */
int
ptree_init_propinfo(ptree_propinfo_t *infop, int version, int ptype, int pmode,
    size_t psize, char *pname, int (*readfn)(ptree_rarg_t *, void *),
    int (*writefn)(ptree_warg_t *, const void *))
{
	if (version != PTREE_PROPINFO_VERSION_1)
		return (PICL_NOTSUPPORTED);
	if ((infop == NULL) || (pname == NULL))
		return (PICL_INVALIDARG);
	infop->version = version;
	infop->piclinfo.type = ptype;
	infop->piclinfo.accessmode = pmode;
	infop->piclinfo.size = psize;
	infop->read = readfn;
	infop->write = writefn;
	(void) strlcpy(infop->piclinfo.name, pname, PICL_PROPNAMELEN_MAX);
	return (PICL_SUCCESS);
}

/*
 * Creates a property, adds it to the node, and returns the property
 * handle to the caller if successful and proph is not NULL
 */
int
ptree_create_and_add_prop(picl_nodehdl_t nodeh, ptree_propinfo_t *infop,
    void *vbuf, picl_prophdl_t *proph)
{
	int		err;
	picl_prophdl_t	tmph;

	err = ptree_create_prop(infop, vbuf, &tmph);
	if (err != PICL_SUCCESS)
		return (err);
	err = ptree_add_prop(nodeh, tmph);
	if (err != PICL_SUCCESS) {
		(void) ptree_destroy_prop(tmph);
		return (err);
	}
	if (proph)
		*proph = tmph;
	return (PICL_SUCCESS);
}

/*
 * Creates a node, adds it to its parent node, and returns the node
 * handle to the caller if successful
 */
int
ptree_create_and_add_node(picl_nodehdl_t rooth, const char *name,
    const char *classname, picl_nodehdl_t *nodeh)
{
	picl_nodehdl_t	tmph;
	int		err;

	err = ptree_create_node(name, classname, &tmph);

	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_add_node(rooth, tmph);
	if (err != PICL_SUCCESS) {
		(void) ptree_destroy_node(tmph);
		return (err);
	}

	*nodeh = tmph;
	return (PICL_SUCCESS);
}


/*
 * recursively visit all nodes
 */
static int
do_walk(picl_nodehdl_t rooth, const char *classname,
    void *c_args, int (*callback_fn)(picl_nodehdl_t hdl, void *args))
{
	int		err;
	picl_nodehdl_t	chdh;
	char		classval[PICL_CLASSNAMELEN_MAX];

	err = ptree_get_propval_by_name(rooth, PICL_PROP_CHILD, &chdh,
	    sizeof (chdh));
	while (err == PICL_SUCCESS) {
		err = ptree_get_propval_by_name(chdh, PICL_PROP_CLASSNAME,
		    classval, sizeof (classval));
		if (err != PICL_SUCCESS)
			return (err);

		if ((classname == NULL) || (strcmp(classname, classval) == 0)) {
			err = callback_fn(chdh, c_args);
			if (err != PICL_WALK_CONTINUE)
				return (err);
		}

		if ((err = do_walk(chdh, classname, c_args, callback_fn)) !=
		    PICL_WALK_CONTINUE)
			return (err);

		err = ptree_get_propval_by_name(chdh, PICL_PROP_PEER, &chdh,
		    sizeof (chdh));
	}
	if (err == PICL_PROPNOTFOUND)	/* end of a branch */
		return (PICL_WALK_CONTINUE);
	return (err);

}

/*
 * This function visits all the nodes in the subtree rooted at <rooth>.
 * For each node that matches the class name specified, the callback
 * function is invoked.
 */
int
ptree_walk_tree_by_class(picl_nodehdl_t rooth, const char *classname,
    void *c_args, int (*callback_fn)(picl_nodehdl_t hdl, void *args))
{
	int		err;

	if (callback_fn == NULL)
		return (PICL_INVALIDARG);
	err = do_walk(rooth, classname, c_args, callback_fn);
	if ((err == PICL_WALK_CONTINUE) || (err == PICL_WALK_TERMINATE))
		return (PICL_SUCCESS);
	return (err);
}

static int
compare_propval(picl_nodehdl_t nodeh, char *pname, picl_prop_type_t ptype,
    void *pval, size_t valsize)
{
	int			err;
	picl_prophdl_t		proph;
	ptree_propinfo_t	propinfo;
	void			*vbuf;

	err = ptree_get_prop_by_name(nodeh, pname, &proph);
	if (err != PICL_SUCCESS)
		return (0);
	err = ptree_get_propinfo(proph, &propinfo);
	if (err != PICL_SUCCESS)
		return (0);
	if (propinfo.piclinfo.type != ptype)
		return (0);
	if (propinfo.piclinfo.type == PICL_PTYPE_VOID)
		return (1);
	if (pval == NULL)
		return (0);
	if (valsize > propinfo.piclinfo.size)
		return (0);
	vbuf = alloca(propinfo.piclinfo.size);
	if (vbuf == NULL)
		return (0);
	err = ptree_get_propval(proph, vbuf, propinfo.piclinfo.size);
	if (err != PICL_SUCCESS)
		return (0);
	if (memcmp(vbuf, pval, valsize) == 0)
		return (1);
	return (0);
}


/*
 * This function traverses the subtree and finds a node that has a property
 * of the specified name and type with the specified value.
 * The matched node in the tree is returned in retnodeh. If there is
 * no node with that property, then PICL_NODENOTFOUND is returned.
 */
int
ptree_find_node(picl_nodehdl_t rooth, char *pname, picl_prop_type_t ptype,
    void *pval, size_t valsize, picl_nodehdl_t *retnodeh)
{
	int			err;
	picl_nodehdl_t		chdh;

	if (pname == NULL)
		return (PICL_INVALIDARG);
	err = ptree_get_propval_by_name(rooth, PICL_PROP_CHILD, &chdh,
	    sizeof (chdh));

	while (err == PICL_SUCCESS) {
		if (compare_propval(chdh, pname, ptype, pval, valsize)) {
			if (retnodeh)
				*retnodeh = chdh;
			return (PICL_SUCCESS);
		}

		err = ptree_find_node(chdh, pname, ptype, pval, valsize,
		    retnodeh);
		if (err != PICL_NODENOTFOUND)
			return (err);

		err = ptree_get_propval_by_name(chdh, PICL_PROP_PEER, &chdh,
		    sizeof (chdh));
	}
	if (err == PICL_PROPNOTFOUND)
		return (PICL_NODENOTFOUND);
	return (err);
}

/*
 * This function gets the frutree parent for a given node.
 * Traverse up the tree and look for the following properties:
 * Frutree parent reference properties:
 *  _fru_parent
 *  _location_parent
 *  _port_parent
 * If the frutree reference property is found, return its value.
 * Else, return the handle of /frutree/chassis.
 */
int
ptree_get_frutree_parent(picl_nodehdl_t nodeh, picl_nodehdl_t *fruh)
{
	int		err;
	picl_nodehdl_t	nparh;
	picl_nodehdl_t	fruparh;

	err = PICL_SUCCESS;
	nparh = nodeh;
	while (err == PICL_SUCCESS) {
		err = ptree_get_propval_by_name(nparh, PICL_REFPROP_FRU_PARENT,
		    &fruparh, sizeof (fruparh));
		if (err == PICL_SUCCESS) {
			*fruh = fruparh;
			return (PICL_SUCCESS);
		}
		err = ptree_get_propval_by_name(nparh,
		    PICL_REFPROP_LOC_PARENT, &fruparh, sizeof (fruparh));
		if (err == PICL_SUCCESS) {
			*fruh = fruparh;
			return (PICL_SUCCESS);
		}
		err = ptree_get_propval_by_name(nparh, PICL_REFPROP_PORT_PARENT,
		    &fruparh, sizeof (fruparh));
		if (err == PICL_SUCCESS) {
			*fruh = fruparh;
			return (PICL_SUCCESS);
		}

		err = ptree_get_propval_by_name(nparh, PICL_PROP_PARENT, &nparh,
		    sizeof (nparh));
	}

	if (err == PICL_PROPNOTFOUND) {	/* return /frutree/chassis handle */
		err = ptree_get_node_by_path(PICL_FRUTREE_CHASSIS, &fruparh);
		if (err == PICL_SUCCESS) {
			*fruh = fruparh;
			return (PICL_SUCCESS);
		}
	}
	return (err);
}

/*
 * This function is called by plug-ins to register with the daemon
 */
int
picld_plugin_register(picld_plugin_reg_t *regp)
{
	picld_plugin_reg_list_t	*el;
	picld_plugin_reg_list_t	*tmp;

	if (regp == NULL)
		return (PICL_FAILURE);

	if (regp->version != PICLD_PLUGIN_VERSION_1)
		return (PICL_NOTSUPPORTED);

	el = malloc(sizeof (picld_plugin_reg_list_t));
	if (el == NULL)
		return (PICL_FAILURE);
	el->reg.version = regp->version;
	el->reg.critical = regp->critical;
	if (regp->name)
		el->reg.name = strdup(regp->name);
	if (el->reg.name == NULL)
		return (PICL_FAILURE);

	el->reg.plugin_init = regp->plugin_init;
	el->reg.plugin_fini = regp->plugin_fini;
	el->next = NULL;

	if (plugin_reg_list == NULL) {
		plugin_reg_list = el;
	} else {	/* add to end */
		tmp = plugin_reg_list;
		while (tmp->next != NULL)
			tmp = tmp->next;
		tmp->next = el;
	}

	return (PICL_SUCCESS);
}

/*
 * Call fini routines of the registered plugins
 */
static void
plugin_fini(picld_plugin_reg_list_t *p)
{
	if (p == NULL)
		return;

	plugin_fini(p->next);
	if (p->reg.plugin_fini)
		(p->reg.plugin_fini)();
}

/*
 * Create PICL Tree
 */

static void
init_plugin_reg_list(void)
{
	plugin_reg_list = NULL;
}

static int
picltree_set_root(picl_nodehdl_t rooth)
{
	picl_obj_t 	*pobj;
	int		err;

	(void) rw_rdlock(&ptree_rwlock);		/* lock ptree */
	pobj = NULL;
	err = lookup_and_lock_node(RDLOCK_NODE, rooth, &pobj); /* lock node */
	if (err != PICL_SUCCESS) {
		(void) rw_unlock(&ptree_rwlock);
		return (PICL_FAILURE);
	}
	piclize_node(pobj);
	picl_root_obj = pobj;
	ptree_root_hdl = pobj->ptree_hdl;
	unlock_node(pobj);			/* unlock node */
	(void) rw_unlock(&ptree_rwlock);		/* unlock ptree */
	return (PICL_SUCCESS);
}

static int
picltree_init(void)
{
	(void) rwlock_init(&ptree_rwlock, USYNC_THREAD, NULL);
	(void) rwlock_init(&picltbl_rwlock, USYNC_THREAD, NULL);

	if (hash_init(&picltbl) < 0)
		return (PICL_FAILURE);
	if (hash_init(&ptreetbl) < 0)
		return (PICL_FAILURE);

	if (pthread_mutex_init(&ptreehdl_lock, NULL) != 0)
		return (PICL_FAILURE);

	if (pthread_mutex_init(&piclhdl_lock, NULL) != 0)
		return (PICL_FAILURE);

	if (pthread_mutex_init(&evtq_lock, NULL) != 0)
		return (PICL_FAILURE);
	if (pthread_cond_init(&evtq_cv, NULL) != 0)
		return (PICL_FAILURE);
	if (pthread_mutex_init(&evthandler_lock, NULL) != 0)
		return (PICL_FAILURE);

	picl_root_obj = NULL;
	eventqp = NULL;
	evt_handlers = NULL;
	ptree_root_hdl = PICL_INVALID_PICLHDL;

	return (PICL_SUCCESS);
}

static void
add_unique_plugin_to_list(char *path, char *name)
{
	char	*buf;
	picld_plugin_desc_t	*pl;
	picld_plugin_desc_t	*tmp;

	pl = plugin_desc;
	while (pl != NULL) {
		if (strcmp(pl->libname, name) == 0)
			return;
		else
			pl = pl->next;
	}

	pl = malloc(sizeof (picld_plugin_desc_t));
	if (pl == NULL)
		return;

	pl->libname = strdup(name);
	if (pl->libname == NULL)
		return;
	buf = alloca(strlen(name) + strlen(path) + 2);
	if (buf == NULL)
		return;
	(void) strcpy(buf, path);
	(void) strcat(buf, name);
	pl->pathname = strdup(buf);
	if (pl->pathname == NULL)
		return;

	pl->next = NULL;

	if (plugin_desc == NULL)
		plugin_desc = pl;
	else {
		tmp = plugin_desc;
		while (tmp->next != NULL)
			tmp = tmp->next;
		tmp->next = pl;
	}
}

static void
get_plugins_from_dir(char *dirname)
{
	struct dirent	*ent;
	DIR	*dir;
	int	len;
	int	solen = strlen(SO_VERS) + 1;

	if ((dir = opendir(dirname)) == NULL)
		return;

	while ((ent = readdir(dir)) != NULL) {
		if ((strcmp(ent->d_name, ".") == 0) ||
		    (strcmp(ent->d_name, "..") == 0))
			continue;

		len = strlen(ent->d_name) + 1;
		if (len < solen)
			continue;

		if (strcmp(ent->d_name + (len - solen), SO_VERS) == 0)
			add_unique_plugin_to_list(dirname, ent->d_name);
	}

	(void) closedir(dir);
}


static void
init_plugin_list(void)
{
	char	nmbuf[SYS_NMLN];
	char	pname[PATH_MAX];

	plugin_desc = NULL;
	if (sysinfo(SI_PLATFORM, nmbuf, sizeof (nmbuf)) != -1) {
		(void) snprintf(pname, PATH_MAX, PICLD_PLAT_PLUGIN_DIRF, nmbuf);
		if (access(pname, R_OK) == 0)
			get_plugins_from_dir(pname);
	}

	if (sysinfo(SI_MACHINE, nmbuf, sizeof (nmbuf)) != -1) {
		(void) snprintf(pname, PATH_MAX, PICLD_PLAT_PLUGIN_DIRF, nmbuf);
		if (access(pname, R_OK) == 0)
			get_plugins_from_dir(pname);
	}

	(void) snprintf(pname, PATH_MAX, "%s/", PICLD_COMMON_PLUGIN_DIR);
	if (access(pname, R_OK) == 0)
		get_plugins_from_dir(pname);
}

static void
load_plugins(void)
{
	picld_plugin_desc_t	*pl;

	pl = plugin_desc;
	while (pl != NULL) {
		pl->dlh = dlopen(pl->pathname, RTLD_LAZY|RTLD_LOCAL);
		if (pl->dlh == NULL) {
			syslog(LOG_CRIT, dlerror());
			return;
		}
		pl = pl->next;
	}
}



static int
add_root_props(picl_nodehdl_t rooth)
{
	int			err;
	picl_prophdl_t		proph;
	ptree_propinfo_t	pinfo;
	float			picl_vers;

#define	PICL_PROP_PICL_VERSION		"PICLVersion"
#define	PICL_VERSION			1.1

	err = ptree_init_propinfo(&pinfo, PTREE_PROPINFO_VERSION_1,
	    PICL_PTYPE_FLOAT, PICL_READ, sizeof (picl_vers),
	    PICL_PROP_PICL_VERSION, NULL, NULL);
	if (err != PICL_SUCCESS)
		return (err);

	picl_vers = PICL_VERSION;
	err = ptree_create_and_add_prop(rooth, &pinfo, &picl_vers, &proph);
	return (err);
}

static int
construct_picltree(void)
{
	int			err;
	picld_plugin_reg_list_t	*iter;
	picl_nodehdl_t		rhdl;

	/*
	 * Create "/" node
	 */
	if ((err = ptree_create_node(PICL_NODE_ROOT, PICL_CLASS_PICL,
	    &rhdl)) != PICL_SUCCESS) {
		return (err);
	}

	if (picltree_set_root(rhdl) != PICL_SUCCESS) {
		return (PICL_FAILURE);
	}

	err = add_root_props(rhdl);
	if (err != PICL_SUCCESS)
		return (err);

	/*
	 * Initialize the registered plug-in modules
	 */
	iter = plugin_reg_list;
	while (iter != NULL) {
		if (iter->reg.plugin_init)
			(iter->reg.plugin_init)();
		iter = iter->next;
	}
	return (PICL_SUCCESS);
}

void
xptree_destroy(void)
{
	dbg_print(1, "xptree_destroy: picl_root_obj = %s\n",
	    (picl_root_obj == NULL ? "NULL" : "not-NULL"));

	if (picl_root_obj == NULL)
		return;

	dbg_print(1, "xptree_destroy: call plugin_fini\n");
	plugin_fini(plugin_reg_list);
	dbg_print(1, "xptree_destroy: plugin_fini DONE\n");

	(void) ptree_delete_node(picl_root_obj->ptree_hdl);
	(void) ptree_destroy_node(picl_root_obj->ptree_hdl);

	(void) rw_wrlock(&ptree_rwlock);
	picl_root_obj = NULL;
	(void) rw_unlock(&ptree_rwlock);
}

/*ARGSUSED*/
int
xptree_initialize(int flg)
{
	int		err;
	pthread_attr_t	attr;
	pthread_t	tid;

	picld_pid = getpid();
	picld_cred.dc_euid = geteuid();
	picld_cred.dc_egid = getegid();
	picld_cred.dc_ruid = getuid();
	picld_cred.dc_rgid = getgid();
	picld_cred.dc_pid = getpid();

	picl_hdl_hi = 1;
	ptree_hdl_hi = 1;
	ptree_generation = 1;
	qempty_wait = 0;

	if (pthread_mutex_init(&ptree_refresh_mutex, NULL) != 0)
		return (PICL_FAILURE);

	if (picltree_init() != PICL_SUCCESS)
		return (PICL_FAILURE);

	init_plugin_reg_list();
	init_plugin_list();
	load_plugins();

	err = construct_picltree();
	if (err != PICL_SUCCESS)
		return (err);

	/*
	 * Dispatch events after all plug-ins have initialized
	 */
	if (pthread_attr_init(&attr) != 0)
		return (PICL_FAILURE);

	(void) pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
	if (pthread_create(&tid, &attr, ptree_event_thread, NULL))
		return (PICL_FAILURE);

	return (PICL_SUCCESS);
}

int
xptree_reinitialize(void)
{
	int	err;

	/*
	 * Wait for eventq to become empty
	 */
	dbg_print(1, "xptree_reinitialize: wait for evtq empty\n");
	(void) pthread_mutex_lock(&evtq_lock);
	qempty_wait = 1;
	while (eventqp != NULL)
		(void) pthread_cond_wait(&evtq_empty, &evtq_lock);
	qempty_wait = 0;
	(void) pthread_mutex_unlock(&evtq_lock);
	dbg_print(1, "xptree_reinitialize: evtq empty is EMPTY\n");

	(void) rw_wrlock(&ptree_rwlock);
	picl_root_obj = NULL;
	ptree_root_hdl = PICL_INVALID_PICLHDL;
	(void) rw_unlock(&ptree_rwlock);
	(void) pthread_mutex_lock(&ptree_refresh_mutex);
	++ptree_generation;
	(void) pthread_mutex_unlock(&ptree_refresh_mutex);

	err = construct_picltree();
	(void) pthread_mutex_lock(&ptree_refresh_mutex);
	(void) pthread_cond_broadcast(&ptree_refresh_cond);
	(void) pthread_mutex_unlock(&ptree_refresh_mutex);

	(void) pthread_mutex_lock(&evtq_lock);
	(void) pthread_cond_broadcast(&evtq_cv);
	(void) pthread_mutex_unlock(&evtq_lock);

	return (err);
}

/*
 * This function is called by the PICL daemon on behalf of clients to
 * wait for a tree refresh
 */
int
xptree_refresh_notify(uint32_t secs)
{
	int	curgen;
	int	ret;
	timespec_t	to;

	if (secs != 0) {
		if (pthread_mutex_lock(&ptree_refresh_mutex) != 0)
			return (PICL_FAILURE);

		curgen = ptree_generation;

		while (curgen == ptree_generation) {
			if (secs == UINT32_MAX)	/* wait forever */
				(void) pthread_cond_wait(&ptree_refresh_cond,
				    &ptree_refresh_mutex);
			else {
				to.tv_sec = secs;
				to.tv_nsec = 0;
				ret = pthread_cond_reltimedwait_np(
				    &ptree_refresh_cond,
				    &ptree_refresh_mutex, &to);
				if (ret == ETIMEDOUT)
					break;
			}
		}

		(void) pthread_mutex_unlock(&ptree_refresh_mutex);
	}

	return (PICL_SUCCESS);
}

/*VARARGS2*/
void
dbg_print(int level, const char *fmt, ...)
{
	if (verbose_level >= level) {
		va_list	ap;

		va_start(ap, fmt);
		(void) vprintf(fmt, ap);
		va_end(ap);
	}
}

/*ARGSUSED*/
void
dbg_exec(int level, void (*fn)(void *args), void *args)
{
	if (verbose_level > level)
		(*fn)(args);
}
