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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Kernel framework functions for the fcode interpreter
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/esunddi.h>
#include <sys/ksynch.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/fcode.h>

#ifdef	DEBUG
int fcode_debug = 0;
#else
int fcode_debug = 0;
#endif

static kmutex_t fc_request_lock;
static kmutex_t fc_resource_lock;
static kmutex_t fc_hash_lock;
static kmutex_t fc_device_tree_lock;
static kmutex_t fc_phandle_lock;
static kcondvar_t fc_request_cv;
static struct fc_request *fc_request_head;
static int fc_initialized;

static void fcode_timer(void *);

int fcode_timeout = 300;	/* seconds */

int fcodem_unloadable;

extern int hz;

/*
 * Initialize the fcode interpreter framework ... must be called
 * prior to activating any of the fcode interpreter framework including
 * the driver.
 */
static void
fcode_init(void)
{
	if (fc_initialized)
		return;

	mutex_init(&fc_request_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&fc_resource_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&fc_hash_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&fc_device_tree_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&fc_phandle_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&fc_request_cv, NULL, CV_DRIVER, NULL);
	++fc_initialized;
}

static void
fcode_fini(void)
{
	mutex_destroy(&fc_request_lock);
	mutex_destroy(&fc_resource_lock);
	mutex_destroy(&fc_hash_lock);
	cv_destroy(&fc_request_cv);
	fc_initialized = 0;
}

/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
	&mod_miscops, "FCode framework 1.13"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init(void)
{
	int error;

	fcode_init();
	if ((error = mod_install(&modlinkage)) != 0)
		fcode_fini();
	return (error);
}

int
_fini(void)
{
	int error = EBUSY;

	if (fcodem_unloadable)
		if ((error = mod_remove(&modlinkage)) == 0)
			fcode_fini();

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Framework function to invoke the interpreter. Wait and return when the
 * interpreter is done. See fcode.h for details.
 */
int
fcode_interpreter(dev_info_t *ap, fc_ops_t *ops, fco_handle_t handle)
{
	struct fc_request *fp, *qp;
	int error;

	ASSERT(fc_initialized);
	ASSERT(ap);
	ASSERT(ops);
	ASSERT(handle);

	/*
	 * Create a request structure
	 */
	fp = kmem_zalloc(sizeof (struct fc_request), KM_SLEEP);

	fp->next = NULL;
	fp->busy = FC_R_INIT;
	fp->error = FC_SUCCESS;
	fp->ap_dip = ap;
	fp->ap_ops = ops;
	fp->handle = handle;

	/*
	 * Add the request to the end of the request list.
	 */
	mutex_enter(&fc_request_lock);

	if (fc_request_head == NULL)
		fc_request_head = fp;
	else {
		for (qp = fc_request_head; qp->next != NULL; qp = qp->next)
			/* empty */;
		qp->next = fp;
	}
	mutex_exit(&fc_request_lock);

	/*
	 * log a message (ie: i_ddi_log_event) indicating that a request
	 * has been queued to start the userland fcode interpreter.
	 * This call is the glue to the eventd and automates the process.
	 */

	/*
	 * Signal the driver if it's waiting for a request to be queued.
	 */
	cv_broadcast(&fc_request_cv);

	/*
	 * Wait for the request to be serviced
	 */
	mutex_enter(&fc_request_lock);
	fp->timeout = timeout(fcode_timer, fp, hz * fcode_timeout);
	while (fp->busy != FC_R_DONE)
		cv_wait(&fc_request_cv, &fc_request_lock);

	if (fp->timeout) {
		(void) untimeout(fp->timeout);
		fp->timeout = NULL;
	}

	/*
	 * Remove the request from the queue (while still holding the lock)
	 */
	if (fc_request_head == fp)
		fc_request_head = fp->next;
	else {
		for (qp = fc_request_head; qp->next != fp; qp = qp->next)
			/* empty */;
		qp->next = fp->next;
	}
	mutex_exit(&fc_request_lock);

	FC_DEBUG1(2, CE_CONT, "fcode_interpreter: request finished, fp %p\n",
	    fp);

	/*
	 * Free the request structure and return any errors.
	 */
	error = fp->error;
	kmem_free(fp, sizeof (struct fc_request));
	return (error);
}

/*
 * Timeout requests thet don't get picked up by the interpreter.  This
 * would happen if the daemon is not running.  If the timer goes off
 * and it's state is not FC_R_INIT, then the interpreter has picked up the
 * request.
 */
static void
fcode_timer(void *arg)
{
	struct fc_request *fp = arg;

	mutex_enter(&fc_request_lock);
	fp->timeout = 0;
	if (fp->busy == FC_R_INIT) {
		cmn_err(CE_WARN, "fcode_timer: Timeout waiting for "
		    "interpreter - Interpreter did not pick up request\n");
		fp->busy = FC_R_DONE;
		fp->error = FC_TIMEOUT;
		mutex_exit(&fc_request_lock);
		cv_broadcast(&fc_request_cv);
		return;
	} else if (fp->error != FC_SUCCESS) {
		/*
		 * An error was detected, but didn't close the driver.
		 * This will allow the process to error out, returning
		 * the interpreter error code instead of FC_TIMEOUT.
		 */
		fp->busy = FC_R_DONE;
		cv_broadcast(&fc_request_cv);
		mutex_exit(&fc_request_lock);
		return;
	} else {
		cmn_err(CE_WARN, "fcode_timer: Timeout waiting for "
		    "interpreter - Interpreter is executing request\n");
	}
	mutex_exit(&fc_request_lock);
}

/*
 * This is the function the driver calls to wait for and get
 * a request.  The call should be interruptable since it's done
 * at read(2) time, so allow for signals to interrupt us.
 *
 * Return NULL if the wait was interrupted, else return a pointer
 * to the fc_request structure (marked as busy).
 *
 * Note that we have to check for a request first, before waiting,
 * in case the request is already queued. In this case, the signal
 * may have already been delivered.
 */
struct fc_request *
fc_get_request(void)
{
	struct fc_request *fp;

	ASSERT(fc_initialized);

	mutex_enter(&fc_request_lock);

	/*CONSTANTCONDITION*/
	while (1) {
		for (fp = fc_request_head; fp != NULL; fp = fp->next) {
			if (fp->busy == FC_R_INIT) {
				fp->busy = FC_R_BUSY;
				mutex_exit(&fc_request_lock);
				return (fp);
			}
		}
		if (cv_wait_sig(&fc_request_cv, &fc_request_lock) == 0) {
			mutex_exit(&fc_request_lock);
			return (NULL);
		}
	}
	/*NOTREACHED*/
}

/*
 * This is the function the driver calls when it's finished with
 * a request.  Mark the request as done and signal the thread that
 * enqueued the request.
 */
void
fc_finish_request(struct fc_request *fp)
{
	ASSERT(fc_initialized);
	ASSERT(fp);
	ASSERT(fp->busy == FC_R_BUSY);

	mutex_enter(&fc_request_lock);
	fp->busy = FC_R_DONE;
	mutex_exit(&fc_request_lock);

	cv_broadcast(&fc_request_cv);
}

/*
 * Generic resource list management subroutines
 */
void
fc_add_resource(fco_handle_t rp, struct fc_resource *ip)
{
	ASSERT(rp);
	ASSERT(ip);

	mutex_enter(&fc_resource_lock);
	ip->next = NULL;
	if (rp->head != NULL)
		ip->next = rp->head;
	rp->head = ip;
	mutex_exit(&fc_resource_lock);
}

void
fc_rem_resource(fco_handle_t rp, struct fc_resource *ip)
{
	struct fc_resource *fp;

	ASSERT(rp);
	ASSERT(ip);

	if (rp->head == NULL)  {
		cmn_err(CE_CONT, "fc_rem_resource: NULL list head!\n");
		return;
	}

	mutex_enter(&fc_resource_lock);
	if (rp->head == ip) {
		rp->head = ip->next;
		mutex_exit(&fc_resource_lock);
		return;
	}

	for (fp = rp->head; fp && (fp->next != ip); fp = fp->next)
		/* empty */;

	if (fp == NULL)  {
		mutex_exit(&fc_resource_lock);
		cmn_err(CE_CONT, "fc_rem_resource: Item not on list!\n");
		return;
	}

	fp->next = ip->next;
	mutex_exit(&fc_resource_lock);
}

/*ARGSUSED*/
void
fc_lock_resource_list(fco_handle_t rp)
{
	mutex_enter(&fc_resource_lock);
}

/*ARGSUSED*/
void
fc_unlock_resource_list(fco_handle_t rp)
{
	mutex_exit(&fc_resource_lock);
}

/*
 * Common helper ops and subroutines
 */
/*ARGSUSED*/
int
fc_syntax_error(fc_ci_t *cp, char *msg)
{
	cp->error = fc_int2cell(-1);
	cp->nresults = fc_int2cell(0);
	return (0);
}

/*ARGSUSED*/
int
fc_priv_error(fc_ci_t *cp, char *msg)
{
	cp->priv_error = fc_int2cell(-1);
	cp->error = fc_int2cell(0);
	cp->nresults = fc_int2cell(0);
	return (0);
}

/*ARGSUSED*/
int
fc_success_op(dev_info_t *ap, fco_handle_t handle, fc_ci_t *cp)
{
	cp->priv_error = cp->error = fc_int2cell(0);
	return (0);
}

/*
 * fc_fail_op: This 'handles' a request by specifically failing it,
 * as opposed to not handling it and returning '-1' to indicate
 * 'service unknown' and allowing somebody else in the chain to
 * handle it.
 */
/*ARGSUSED*/
int
fc_fail_op(dev_info_t *ap, fco_handle_t handle, fc_ci_t *cp)
{
	cmn_err(CE_CONT, "fcode ops: fail service name <%s>\n",
	    (char *)fc_cell2ptr(cp->svc_name));

	cp->nresults = fc_int2cell(0);
	cp->error = fc_int2cell(-1);
	return (0);
}

/*
 * Functions to manage the set of handles we give to the interpreter.
 * The handles are opaque and internally represent dev_info_t pointers.
 */
struct fc_phandle_entry **
fc_handle_to_phandle_head(fco_handle_t rp)
{
	while (rp->next_handle)
		rp = rp->next_handle;

	return (&rp->ptable);
}

/*ARGSUSED*/
void
fc_phandle_table_alloc(struct fc_phandle_entry **head)
{
}

void
fc_phandle_table_free(struct fc_phandle_entry **head)
{
	struct fc_phandle_entry *ip, *np;

	/*
	 * Free each entry in the table.
	 */
	for (ip = *head; ip; ip = np) {
		np = ip->next;
		kmem_free(ip, sizeof (struct fc_phandle_entry));
	}
	*head = NULL;
}

dev_info_t *
fc_phandle_to_dip(struct fc_phandle_entry **head, fc_phandle_t handle)
{
	struct fc_phandle_entry *ip;

	mutex_enter(&fc_hash_lock);

	for (ip = *head; ip; ip = ip->next)
		if (ip->h == handle)
			break;

	mutex_exit(&fc_hash_lock);

	return (ip ? ip->dip : NULL);
}

fc_phandle_t
fc_dip_to_phandle(struct fc_phandle_entry **head, dev_info_t *dip)
{
	struct fc_phandle_entry *hp, *np;
	fc_phandle_t h;

	ASSERT(dip);
	h = (fc_phandle_t)ddi_get_nodeid(dip);

	/*
	 * Just in case, allocate a new entry ...
	 */
	np = kmem_zalloc(sizeof (struct fc_phandle_entry), KM_SLEEP);

	mutex_enter(&fc_hash_lock);

	/*
	 * If we already have this dip in the table, just return the handle
	 */
	for (hp = *head; hp; hp = hp->next) {
		if (hp->dip == dip) {
			mutex_exit(&fc_hash_lock);
			kmem_free(np, sizeof (struct fc_phandle_entry));
			return (h);
		}
	}

	/*
	 * Insert this entry to the list of known entries
	 */
	np->next = *head;
	np->dip = dip;
	np->h = h;
	*head = np;
	mutex_exit(&fc_hash_lock);
	return (h);
}

/*
 * We won't need this function once the ddi is modified to handle
 * unique non-prom nodeids.  For now, this allows us to add a given
 * nodeid to the device tree without dereferencing the value in the
 * devinfo node, so we have a parallel mechanism.
 */
void
fc_add_dip_to_phandle(struct fc_phandle_entry **head, dev_info_t *dip,
    fc_phandle_t h)
{
	struct fc_phandle_entry *hp, *np;

	ASSERT(dip);

	/*
	 * Just in case, allocate a new entry ...
	 */
	np = kmem_zalloc(sizeof (struct fc_phandle_entry), KM_SLEEP);

	mutex_enter(&fc_hash_lock);

	/*
	 * If we already have this dip in the table, just return the handle
	 */
	for (hp = *head; hp; hp = hp->next) {
		if (hp->dip == dip) {
			mutex_exit(&fc_hash_lock);
			kmem_free(np, sizeof (struct fc_phandle_entry));
			return;
		}
	}

	/*
	 * Insert this entry to the list of known entries
	 */
	np->next = *head;
	np->dip = dip;
	np->h = h;
	*head = np;
	mutex_exit(&fc_hash_lock);
}

/*
 * Functions to manage our copy of our subtree.
 *
 * The head of the device tree is always stored in the last 'handle'
 * in the handle chain.
 */
struct fc_device_tree **
fc_handle_to_dtree_head(fco_handle_t rp)
{
	while (rp->next_handle)
		rp = rp->next_handle;

	return (&rp->dtree);
}

struct fc_device_tree *
fc_handle_to_dtree(fco_handle_t rp)
{
	struct fc_device_tree **head = fc_handle_to_dtree_head(rp);

	return (*head);
}

/*
 * The root of the subtree is the attachment point ...
 * Thus, there is never an empty device tree.
 */
void
fc_create_device_tree(dev_info_t *ap, struct fc_device_tree **head)
{
	struct fc_device_tree *dp;

	dp = kmem_zalloc(sizeof (struct fc_device_tree), KM_SLEEP);
	dp->dip = ap;
	*head = dp;
}

#ifdef	notdef
static void
fc_remove_subtree(struct fc_device_tree *dp)
{
	struct fc_device_tree *np;

	if (dp->child) {
		fc_remove_subtree(dp->child);
		dp->child = NULL;
	}

	/*
	 * Remove each peer node, working our way backwards from the
	 * last peer node to the first peer node.
	 */
	if (dp->peer != NULL) {
		for (np = dp->peer; np->peer; np = dp->peer) {
			for (/* empty */; np->peer; np = np->peer)
				/* empty */;
			fc_remove_subtree(np->peer);
			np->peer = NULL;
		}
		fc_remove_subtree(dp->peer)
		dp->peer = NULL;
	}

	ASSERT((dp->child == NULL) && (dp->peer == NULL));
	kmem_free(dp, sizeof (struct fc_device_tree));
}

void
fc_remove_device_tree(struct fc_device_tree **head)
{
	ASSERT(head && (*head != NULL));

	fc_remove_subtree(*head);
	*head = NULL;
}
#endif	/* notdef */

void
fc_remove_device_tree(struct fc_device_tree **head)
{
	struct fc_device_tree *dp;

	ASSERT(head && (*head != NULL));

	dp = *head;

	if (dp->child)
		fc_remove_device_tree(&dp->child);

	if (dp->peer)
		fc_remove_device_tree(&dp->peer);

	ASSERT((dp->child == NULL) && (dp->peer == NULL));

	kmem_free(dp, sizeof (struct fc_device_tree));
	*head = NULL;
}

struct fc_device_tree *
fc_find_node(dev_info_t *dip, struct fc_device_tree *hp)
{
	struct fc_device_tree *p;

	while (hp) {
		if (hp->dip == dip)
			return (hp);

		if (hp->child)
			if ((p = fc_find_node(dip, hp->child)) != NULL)
				return (p);

		hp = hp->peer;
	}
	return (NULL);
}

void
fc_add_child(dev_info_t *child, dev_info_t *parent, struct fc_device_tree *hp)
{
	struct fc_device_tree *p, *q;

	q = kmem_zalloc(sizeof (struct fc_device_tree), KM_SLEEP);
	q->dip = child;

	mutex_enter(&fc_device_tree_lock);

#ifdef	DEBUG
	/* XXX: Revisit ASSERT vs PANIC */
	p = fc_find_node(child, hp);
	ASSERT(p == NULL);
#endif

	p = fc_find_node(parent, hp);
	ASSERT(p != NULL);

	q->peer = p->child;
	p->child = q;

	mutex_exit(&fc_device_tree_lock);
}

void
fc_remove_child(dev_info_t *child, struct fc_device_tree *head)
{
	struct fc_device_tree *p, *c, *n;
	dev_info_t *parent = ddi_get_parent(child);

	mutex_enter(&fc_device_tree_lock);

	p = fc_find_node(parent, head);
	ASSERT(p != NULL);

	/*
	 * Find the child within the parent's subtree ...
	 */
	c = fc_find_node(child, p);
	ASSERT(c != NULL);
	ASSERT(c->child == NULL);

	/*
	 * If it's the first child, remove it, otherwise
	 * remove it from the child's peer list.
	 */
	if (p->child == c) {
		p->child = c->peer;
	} else {
		int found = 0;
		for (n = p->child; n->peer; n = n->peer) {
			if (n->peer == c) {
				n->peer = c->peer;
				found = 1;
				break;
			}
		}
		if (!found)
			cmn_err(CE_PANIC, "fc_remove_child: not found\n");
	}
	mutex_exit(&fc_device_tree_lock);

	kmem_free(c, sizeof (struct fc_device_tree));
}

dev_info_t *
fc_child_node(dev_info_t *parent, struct fc_device_tree *hp)
{
	struct fc_device_tree *p;
	dev_info_t *dip = NULL;

	mutex_enter(&fc_device_tree_lock);
	p = fc_find_node(parent, hp);
	if (p && p->child)
		dip = p->child->dip;
	mutex_exit(&fc_device_tree_lock);

	return (dip);
}

dev_info_t *
fc_peer_node(dev_info_t *devi, struct fc_device_tree *hp)
{
	struct fc_device_tree *p;
	dev_info_t *dip = NULL;

	mutex_enter(&fc_device_tree_lock);
	p = fc_find_node(devi, hp);
	if (p && p->peer)
		dip = p->peer->dip;
	mutex_exit(&fc_device_tree_lock);

	return (dip);
}
