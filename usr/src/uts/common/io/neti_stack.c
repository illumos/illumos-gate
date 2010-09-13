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

#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/kmem.h>
#include <sys/rwlock.h>
#include <sys/errno.h>
#include <sys/queue.h>
#include <sys/sunddi.h>
#include <inet/common.h>
#include <inet/led.h>
#include <inet/ip.h>
#include <sys/neti.h>
#include <sys/zone.h>
#include <sys/sdt.h>


typedef boolean_t napplyfn_t(neti_stack_t *, void *);

static void *neti_stack_init(netstackid_t stackid, netstack_t *ns);
static void neti_stack_fini(netstackid_t stackid, void *arg);
static net_instance_int_t *net_instance_int_create(net_instance_t *nin,
    net_instance_int_t *parent);
static void neti_stack_shutdown(netstackid_t stackid, void *arg);
static void net_instance_int_free(net_instance_int_t *nini);

static boolean_t neti_stack_apply_create(neti_stack_t *, void *);
static boolean_t neti_stack_apply_destroy(neti_stack_t *, void *);
static boolean_t neti_stack_apply_shutdown(neti_stack_t *, void *);
static void neti_apply_all_instances(neti_stack_t *, napplyfn_t *);
static void neti_apply_all_stacks(void *, napplyfn_t *);
static boolean_t wait_for_nini_inprogress(neti_stack_t *,
    net_instance_int_t *, uint32_t);

static nini_head_t neti_instance_list;
static neti_stack_head_t neti_stack_list;
static kmutex_t neti_stack_lock;

void
neti_init()
{
	mutex_init(&neti_stack_lock, NULL, MUTEX_DRIVER, NULL);

	LIST_INIT(&neti_instance_list);
	LIST_INIT(&neti_stack_list);
	/*
	 * We want to be informed each time a netstack is created or
	 * destroyed in the kernel.
	 */
	netstack_register(NS_NETI, neti_stack_init, neti_stack_shutdown,
	    neti_stack_fini);
}

void
neti_fini()
{
	ASSERT(LIST_EMPTY(&neti_instance_list));
	ASSERT(LIST_EMPTY(&neti_stack_list));

	netstack_unregister(NS_NETI);

	mutex_destroy(&neti_stack_lock);
}

/*
 * Initialize the neti stack instance.  Because this is called out of the
 * netstack framework, it is not possible for it to be called twice with
 * the same values for (stackid,ns).  The same also applies to the other
 * two functions used with netstack_register: neti_stack_shutdown and
 * neti_stack_fini.
 */
static void *
neti_stack_init(netstackid_t stackid, netstack_t *ns)
{
	net_instance_int_t *dup;
	net_instance_int_t *n;
	neti_stack_t *nts;

	nts = kmem_zalloc(sizeof (*nts), KM_SLEEP);
	LIST_INIT(&nts->nts_instances);
	nts->nts_id = (netid_t)stackid;
	nts->nts_stackid = stackid;
	nts->nts_netstack = ns;
	nts->nts_zoneid = netstackid_to_zoneid(stackid);
	nts->nts_flags = NSF_ZONE_CREATE;
	cv_init(&nts->nts_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&nts->nts_lock, NULL, MUTEX_DRIVER, NULL);

	mutex_enter(&neti_stack_lock);
	LIST_INSERT_HEAD(&neti_stack_list, nts, nts_next);

	LIST_FOREACH(n, &neti_instance_list, nini_next) {
		/*
		 * This function returns with the NSS_CREATE_NEEDED flag
		 * set in "dup", so it is adequately prepared for the
		 * upcoming apply.
		 */
		dup = net_instance_int_create(n->nini_instance, n);

		mutex_enter(&nts->nts_lock);
		LIST_INSERT_HEAD(&nts->nts_instances, dup, nini_next);
		mutex_exit(&nts->nts_lock);
	}

	neti_apply_all_instances(nts, neti_stack_apply_create);

	mutex_enter(&nts->nts_lock);
	nts->nts_flags &= ~NSF_ZONE_CREATE;
	mutex_exit(&nts->nts_lock);

	mutex_exit(&neti_stack_lock);

	return (nts);
}

/*
 * Run the shutdown for all of the hooks.
 */
/*ARGSUSED*/
static void
neti_stack_shutdown(netstackid_t stackid, void *arg)
{
	neti_stack_t *nts = arg;
	net_instance_int_t *n;
	struct net_data *nd;

	ASSERT(nts != NULL);

	mutex_enter(&neti_stack_lock);
	mutex_enter(&nts->nts_lock);
	/*
	 * Walk through all of the protocol stacks and mark them as shutting
	 * down.
	 */
	LIST_FOREACH(nd, &nts->nts_netd_head, netd_list) {
		nd->netd_condemned = 1;
	}

	/*
	 * Now proceed to see which callbacks are waiting to hear about the
	 * impending shutdown...
	 */
	LIST_FOREACH(n, &nts->nts_instances, nini_next) {
		if (n->nini_instance->nin_shutdown == NULL) {
			/*
			 * If there is no shutdown function registered,
			 * fake that we have completed it.
			 */
			n->nini_flags |= NSS_SHUTDOWN_COMPLETED;
			continue;
		}

		/*
		 * We need to ensure that we don't try and shutdown something
		 * that is already in the process of being shutdown or
		 * destroyed. If it is still being created, that's ok, the
		 * shtudown flag is added to the mix of things to do.
		 */
		if ((n->nini_flags & (NSS_DESTROY_ALL|NSS_SHUTDOWN_ALL)) == 0)
			n->nini_flags |= NSS_SHUTDOWN_NEEDED;
	}
	nts->nts_flags |= NSF_ZONE_SHUTDOWN;
	mutex_exit(&nts->nts_lock);

	neti_apply_all_instances(nts, neti_stack_apply_shutdown);

	mutex_enter(&nts->nts_lock);

	nts->nts_netstack = NULL;
	nts->nts_flags &= ~NSF_ZONE_SHUTDOWN;
	mutex_exit(&nts->nts_lock);

	mutex_exit(&neti_stack_lock);
	ASSERT(nts != NULL);
}

/*
 * Free the neti stack instance.
 * This function relies on the netstack framework only calling the _destroy
 * callback once for each stackid.  The netstack framework also provides us
 * with assurance that nobody else will be doing any work (_create, _shutdown)
 * on it, so there is no need to set and use flags to guard against
 * simultaneous execution (ie. no need to set NSF_CLOSING.)
 * What is required, however, is to make sure that we don't corrupt the
 * list of neti_stack_t's for other code that walks it.
 */
/*ARGSUSED*/
static void
neti_stack_fini(netstackid_t stackid, void *arg)
{
	neti_stack_t *nts = arg;
	net_instance_int_t *n;
	struct net_data *nd;

	mutex_enter(&neti_stack_lock);
	mutex_enter(&nts->nts_lock);

	LIST_REMOVE(nts, nts_next);

	/*
	 * Walk through all of the protocol stacks and mark them as being
	 * destroyed.
	 */
	LIST_FOREACH(nd, &nts->nts_netd_head, netd_list) {
		nd->netd_condemned = 2;
	}

	LIST_FOREACH(n, &nts->nts_instances, nini_next) {
		ASSERT((n->nini_flags & NSS_SHUTDOWN_ALL) != 0);
		if ((n->nini_flags & NSS_DESTROY_ALL) == 0)
			n->nini_flags |= NSS_DESTROY_NEEDED;
	}
	mutex_exit(&nts->nts_lock);

	neti_apply_all_instances(nts, neti_stack_apply_destroy);

	while (!LIST_EMPTY(&nts->nts_instances)) {
		n = LIST_FIRST(&nts->nts_instances);
		LIST_REMOVE(n, nini_next);

		net_instance_int_free(n);
	}
	mutex_exit(&neti_stack_lock);

	ASSERT(LIST_EMPTY(&nts->nts_netd_head));

	mutex_destroy(&nts->nts_lock);
	cv_destroy(&nts->nts_cv);

	kmem_free(nts, sizeof (*nts));
}

static net_instance_int_t *
net_instance_int_create(net_instance_t *nin, net_instance_int_t *parent)
{
	net_instance_int_t *nini;

	nini = kmem_zalloc(sizeof (net_instance_int_t), KM_SLEEP);
	nini->nini_instance = nin;
	nini->nini_parent = parent;
	if (parent != NULL) {
		/*
		 * If the parent pointer is non-NULL then we take that as
		 * an indication that the net_instance_int_t is being
		 * created for an active instance and there will expect
		 * the create function to be called.  In contrast, if
		 * parent is NULL then this code assumes the object is
		 * being prepared for insertion onto the master list of
		 * callbacks to be called when an instance is created, etc.
		 */
		parent->nini_ref++;
		nini->nini_flags |= NSS_CREATE_NEEDED;
	}

	cv_init(&nini->nini_cv, NULL, CV_DRIVER, NULL);

	return (nini);
}

/*
 * Free'ing of a net_instance_int_t is only to be done when we know nobody
 * else has is using it. For both parents and clones, this is indicated by
 * nini_ref being greater than 0, however, nini_ref is managed differently
 * for its two uses. For parents, nini_ref is increased when a new clone is
 * created and it is decremented here. For clones, nini_ref is adjusted by
 * code elsewhere (e.g. in neti_stack_apply_*) and is not changed here.
 */
static void
net_instance_int_free(net_instance_int_t *nini)
{
	/*
	 * This mutex guards the use of nini_ref.
	 */
	ASSERT(mutex_owned(&neti_stack_lock));

	/*
	 * For 'parent' structures, nini_ref will drop to 0 when
	 * the last clone has been free'd... but for clones, it
	 * is possible for nini_ref to be non-zero if we get in
	 * here when all the locks have been given up to execute
	 * a callback or wait_for_nini_inprogress. In that case,
	 * we do not want to free the structure and just indicate
	 * that it is on the "doomed" list, thus we set the
	 * condemned flag.
	 */
	if (nini->nini_parent != NULL) {
		if (nini->nini_ref > 0)
			nini->nini_condemned = B_TRUE;
		nini->nini_parent->nini_ref--;
		if (nini->nini_parent->nini_ref == 0)
			net_instance_int_free(nini->nini_parent);
		nini->nini_parent = NULL;
	}

	if (nini->nini_ref == 0) {
		cv_destroy(&nini->nini_cv);
		kmem_free(nini, sizeof (*nini));
	}
}

net_instance_t *
net_instance_alloc(const int version)
{
	net_instance_t *nin;

	if (version != NETINFO_VERSION)
		return (NULL);

	nin = kmem_zalloc(sizeof (net_instance_t), KM_SLEEP);
	nin->nin_version = version;

	return (nin);
}

void
net_instance_free(net_instance_t *nin)
{
	kmem_free(nin, sizeof (*nin));
}

int
net_instance_register(net_instance_t *nin)
{
	net_instance_int_t *parent;
	net_instance_int_t *tmp;
	neti_stack_t *nts;

	ASSERT(nin->nin_name != NULL);

	if (nin->nin_create == NULL || nin->nin_destroy == NULL)
		return (DDI_FAILURE);

	mutex_enter(&neti_stack_lock);
	/*
	 * Search for duplicate, either on the global list or on any
	 * of the known instances.
	 */
	LIST_FOREACH(tmp, &neti_instance_list, nini_next) {
		if (strcmp(nin->nin_name, tmp->nini_instance->nin_name) == 0) {
			mutex_exit(&neti_stack_lock);
			return (DDI_FAILURE);
		}
	}

	/*
	 * Now insert and activate.
	 */
	parent = net_instance_int_create(nin, NULL);
	ASSERT(parent != NULL);
	LIST_INSERT_HEAD(&neti_instance_list, parent, nini_next);

	LIST_FOREACH(nts, &neti_stack_list, nts_next) {
		mutex_enter(&nts->nts_lock);
		/*
		 * If shutdown of the zone has begun then do not add a new
		 * instance of the object being registered.
		 */
		if ((nts->nts_flags & NSF_ZONE_SHUTDOWN) ||
		    (nts->nts_netstack == NULL)) {
			mutex_exit(&nts->nts_lock);
			continue;
		}

		/*
		 * This function returns with the NSS_CREATE_NEEDED flag
		 * set in "dup", so it is adequately prepared for the
		 * upcoming apply.
		 */
		tmp = net_instance_int_create(nin, parent);
		ASSERT(tmp != NULL);
		LIST_INSERT_HEAD(&nts->nts_instances, tmp, nini_next);
		mutex_exit(&nts->nts_lock);

	}

	neti_apply_all_stacks(parent, neti_stack_apply_create);
	mutex_exit(&neti_stack_lock);

	return (DDI_SUCCESS);
}

/*
 * While net_instance_register() isn't likely to be racing against itself,
 * net_instance_unregister() can be entered from various directions that
 * can compete: shutdown of a zone, unloading of a module (and it calling
 * _unregister() as part of that) and the module doing an _unregister()
 * anyway.
 */
int
net_instance_unregister(net_instance_t *nin)
{
	net_instance_int_t *parent;
	net_instance_int_t *tmp;
	neti_stack_t *nts;

	mutex_enter(&neti_stack_lock);

	LIST_FOREACH(tmp, &neti_instance_list, nini_next) {
		if (strcmp(tmp->nini_instance->nin_name, nin->nin_name) == 0) {
			LIST_REMOVE(tmp, nini_next);
			break;
		}
	}

	if (tmp == NULL) {
		mutex_exit(&neti_stack_lock);
		return (DDI_FAILURE);
	}
	parent = tmp;

	LIST_FOREACH(nts, &neti_stack_list, nts_next) {
		mutex_enter(&nts->nts_lock);
		LIST_FOREACH(tmp, &nts->nts_instances, nini_next) {
			if (tmp->nini_parent != parent)
				continue;
			/*
			 * Netstack difference:
			 * In netstack.c, there is a check for
			 * NSS_CREATE_COMPLETED before setting the other
			 * _NEEDED flags.  If we consider that a list
			 * member must always have at least the _CREATE_NEEDED
			 * flag set and that wait_for_nini_inprogress will
			 * also wait for that flag to be cleared in both of
			 * the shutdown and destroy apply functions.
			 *
			 * It is possible to optimize out the case where
			 * all three _NEEDED flags are set to being able
			 * to pretend everything has been done and just
			 * set all three _COMPLETE flags.  This makes a
			 * special case that we then need to consider in
			 * other locations, so for the sake of simplicity,
			 * we leave it as it is.
			 */
			if ((tmp->nini_flags & NSS_SHUTDOWN_ALL) == 0)
				tmp->nini_flags |= NSS_SHUTDOWN_NEEDED;
			if ((tmp->nini_flags & NSS_DESTROY_ALL) == 0)
				tmp->nini_flags |= NSS_DESTROY_NEEDED;
			break;
		}
		mutex_exit(&nts->nts_lock);
	}

	/*
	 * Each of these functions ensures that the requisite _COMPLETED
	 * flag is present before calling the apply function. So we are
	 * guaranteed to have NSS_CREATE_COMPLETED|NSS_SHUTDOWN_COMPLETED
	 * both set after the first call here and when the second completes,
	 * NSS_DESTROY_COMPLETED is also set.
	 */
	neti_apply_all_stacks(parent, neti_stack_apply_shutdown);
	neti_apply_all_stacks(parent, neti_stack_apply_destroy);

	/*
	 * Remove the instance callback information from each stack.
	 */
	LIST_FOREACH(nts, &neti_stack_list, nts_next) {
		mutex_enter(&nts->nts_lock);
		LIST_FOREACH(tmp, &nts->nts_instances, nini_next) {
			if ((tmp->nini_parent == parent) &&
			    (tmp->nini_flags & NSS_SHUTDOWN_COMPLETED) &&
			    (tmp->nini_flags & NSS_DESTROY_COMPLETED)) {
				/*
				 * There should only be one entry that has a
				 * matching nini_parent so there is no need to
				 * worry about continuing a loop where we are
				 * free'ing the structure holding the 'next'
				 * pointer.
				 */
				LIST_REMOVE(tmp, nini_next);
				net_instance_int_free(tmp);
				break;
			}
		}
		mutex_exit(&nts->nts_lock);
	}

	mutex_exit(&neti_stack_lock);

	return (DDI_SUCCESS);
}

static void
neti_apply_all_instances(neti_stack_t *nts, napplyfn_t *applyfn)
{
	net_instance_int_t *n;

	ASSERT(mutex_owned(&neti_stack_lock));

	n = LIST_FIRST(&nts->nts_instances);
	while (n != NULL) {
		if ((applyfn)(nts, n->nini_parent)) {
			/* Lock dropped - restart at head */
			n = LIST_FIRST(&nts->nts_instances);
		} else {
			n = LIST_NEXT(n, nini_next);
		}
	}
}

static void
neti_apply_all_stacks(void *parent, napplyfn_t *applyfn)
{
	neti_stack_t *nts;

	ASSERT(mutex_owned(&neti_stack_lock));

	nts = LIST_FIRST(&neti_stack_list);
	while (nts != NULL) {
		/*
		 * This function differs, in that it doesn't have a call to
		 * a "wait_creator" call, from the zsd/netstack code.  The
		 * waiting is pushed into the apply functions which cause
		 * the waiting to be done in wait_for_nini_progress with
		 * the passing in of cmask.
		 */
		if ((applyfn)(nts, parent)) {
			/* Lock dropped - restart at head */
			nts = LIST_FIRST(&neti_stack_list);
		} else {
			nts = LIST_NEXT(nts, nts_next);
		}
	}
}

static boolean_t
neti_stack_apply_create(neti_stack_t *nts, void *parent)
{
	void *result;
	boolean_t dropped = B_FALSE;
	net_instance_int_t *tmp;
	net_instance_t *nin;

	ASSERT(parent != NULL);
	ASSERT(mutex_owned(&neti_stack_lock));

	mutex_enter(&nts->nts_lock);

	LIST_FOREACH(tmp, &nts->nts_instances, nini_next) {
		if (tmp->nini_parent == parent)
			break;
	}
	if (tmp == NULL) {
		mutex_exit(&nts->nts_lock);
		return (dropped);
	}

	tmp->nini_ref++;

	if (wait_for_nini_inprogress(nts, tmp, 0))
		dropped = B_TRUE;

	if ((tmp->nini_flags & NSS_CREATE_NEEDED) && !tmp->nini_condemned) {
		nin = tmp->nini_instance;
		tmp->nini_flags &= ~NSS_CREATE_NEEDED;
		tmp->nini_flags |= NSS_CREATE_INPROGRESS;
		DTRACE_PROBE2(neti__stack__create__inprogress,
		    neti_stack_t *, nts, net_instance_int_t *, tmp);
		mutex_exit(&nts->nts_lock);
		mutex_exit(&neti_stack_lock);
		dropped = B_TRUE;

		ASSERT(tmp->nini_created == NULL);
		ASSERT(nin->nin_create != NULL);
		DTRACE_PROBE2(neti__stack__create__start,
		    netstackid_t, nts->nts_id,
		    neti_stack_t *, nts);
		result = (nin->nin_create)(nts->nts_id);
		DTRACE_PROBE2(neti__stack__create__end,
		    void *, result, neti_stack_t *, nts);

		ASSERT(result != NULL);
		mutex_enter(&neti_stack_lock);
		mutex_enter(&nts->nts_lock);
		tmp->nini_created = result;
		tmp->nini_flags &= ~NSS_CREATE_INPROGRESS;
		tmp->nini_flags |= NSS_CREATE_COMPLETED;
		cv_broadcast(&tmp->nini_cv);
		DTRACE_PROBE2(neti__stack__create__completed,
		    neti_stack_t *, nts, net_instance_int_t *, tmp);
	}
	tmp->nini_ref--;

	if (tmp->nini_condemned) {
		net_instance_int_free(tmp);
		dropped = B_TRUE;
	}
	mutex_exit(&nts->nts_lock);
	return (dropped);
}


static boolean_t
neti_stack_apply_shutdown(neti_stack_t *nts, void *parent)
{
	boolean_t dropped = B_FALSE;
	net_instance_int_t *tmp;
	net_instance_t *nin;

	ASSERT(parent != NULL);
	ASSERT(mutex_owned(&neti_stack_lock));

	mutex_enter(&nts->nts_lock);

	LIST_FOREACH(tmp, &nts->nts_instances, nini_next) {
		if (tmp->nini_parent == parent)
			break;
	}
	if (tmp == NULL) {
		mutex_exit(&nts->nts_lock);
		return (dropped);
	}
	ASSERT((tmp->nini_flags & NSS_SHUTDOWN_ALL) != 0);

	tmp->nini_ref++;

	if (wait_for_nini_inprogress(nts, tmp, NSS_CREATE_NEEDED))
		dropped = B_TRUE;

	nin = tmp->nini_instance;
	if (nin->nin_shutdown == NULL) {
		/*
		 * If there is no shutdown function, fake having completed it.
		 */
		if (tmp->nini_flags & NSS_SHUTDOWN_NEEDED) {
			tmp->nini_flags &= ~NSS_SHUTDOWN_NEEDED;
			tmp->nini_flags |= NSS_SHUTDOWN_COMPLETED;
		}
		tmp->nini_ref--;

		if (tmp->nini_condemned) {
			net_instance_int_free(tmp);
			dropped = B_TRUE;
		}

		mutex_exit(&nts->nts_lock);
		return (dropped);
	}

	if ((tmp->nini_flags & NSS_SHUTDOWN_NEEDED) && !tmp->nini_condemned) {
		ASSERT((tmp->nini_flags & NSS_CREATE_COMPLETED) != 0);
		tmp->nini_flags &= ~NSS_SHUTDOWN_NEEDED;
		tmp->nini_flags |= NSS_SHUTDOWN_INPROGRESS;
		DTRACE_PROBE2(neti__stack__shutdown__inprogress,
		    neti_stack_t *, nts, net_instance_int_t *, tmp);
		mutex_exit(&nts->nts_lock);
		mutex_exit(&neti_stack_lock);
		dropped = B_TRUE;

		ASSERT(nin->nin_shutdown != NULL);
		DTRACE_PROBE2(neti__stack__shutdown__start,
		    netstackid_t, nts->nts_id,
		    neti_stack_t *, nts);
		(nin->nin_shutdown)(nts->nts_id, tmp->nini_created);
		DTRACE_PROBE1(neti__stack__shutdown__end,
		    neti_stack_t *, nts);

		mutex_enter(&neti_stack_lock);
		mutex_enter(&nts->nts_lock);
		tmp->nini_flags &= ~NSS_SHUTDOWN_INPROGRESS;
		tmp->nini_flags |= NSS_SHUTDOWN_COMPLETED;
		cv_broadcast(&tmp->nini_cv);
		DTRACE_PROBE2(neti__stack__shutdown__completed,
		    neti_stack_t *, nts, net_instance_int_t *, tmp);
	}
	ASSERT((tmp->nini_flags & NSS_SHUTDOWN_COMPLETED) != 0);
	tmp->nini_ref--;

	if (tmp->nini_condemned) {
		net_instance_int_free(tmp);
		dropped = B_TRUE;
	}
	mutex_exit(&nts->nts_lock);
	return (dropped);
}

static boolean_t
neti_stack_apply_destroy(neti_stack_t *nts, void *parent)
{
	boolean_t dropped = B_FALSE;
	net_instance_int_t *tmp;
	net_instance_t *nin;

	ASSERT(parent != NULL);
	ASSERT(mutex_owned(&neti_stack_lock));

	mutex_enter(&nts->nts_lock);

	LIST_FOREACH(tmp, &nts->nts_instances, nini_next) {
		if (tmp->nini_parent == parent)
			break;
	}
	if (tmp == NULL) {
		mutex_exit(&nts->nts_lock);
		return (dropped);
	}

	tmp->nini_ref++;

	/*
	 * We pause here so that when we continue we know that we're the
	 * only one doing anything active with this node.
	 */
	if (wait_for_nini_inprogress(nts, tmp,
	    NSS_CREATE_NEEDED|NSS_SHUTDOWN_NEEDED))
		dropped = B_TRUE;

	if ((tmp->nini_flags & NSS_DESTROY_NEEDED) && !tmp->nini_condemned) {
		ASSERT((tmp->nini_flags & NSS_SHUTDOWN_COMPLETED) != 0);
		nin = tmp->nini_instance;
		tmp->nini_flags &= ~NSS_DESTROY_NEEDED;
		tmp->nini_flags |= NSS_DESTROY_INPROGRESS;
		DTRACE_PROBE2(neti__stack__destroy__inprogress,
		    neti_stack_t *, nts, net_instance_int_t *, tmp);
		mutex_exit(&nts->nts_lock);
		mutex_exit(&neti_stack_lock);
		dropped = B_TRUE;

		ASSERT(nin->nin_destroy != NULL);
		DTRACE_PROBE2(neti__stack__destroy__start,
		    netstackid_t, nts->nts_id,
		    neti_stack_t *, nts);
		(nin->nin_destroy)(nts->nts_id, tmp->nini_created);
		DTRACE_PROBE1(neti__stack__destroy__end,
		    neti_stack_t *, nts);

		mutex_enter(&neti_stack_lock);
		mutex_enter(&nts->nts_lock);
		tmp->nini_flags &= ~NSS_DESTROY_INPROGRESS;
		tmp->nini_flags |= NSS_DESTROY_COMPLETED;
		cv_broadcast(&tmp->nini_cv);
		DTRACE_PROBE2(neti__stack__destroy__completed,
		    neti_stack_t *, nts, net_instance_int_t *, tmp);
	}
	tmp->nini_ref--;

	if (tmp->nini_condemned) {
		net_instance_int_free(tmp);
		dropped = B_TRUE;
	}
	mutex_exit(&nts->nts_lock);
	return (dropped);
}

static boolean_t
wait_for_nini_inprogress(neti_stack_t *nts, net_instance_int_t *nini,
    uint32_t cmask)
{
	boolean_t dropped = B_FALSE;

	ASSERT(mutex_owned(&neti_stack_lock));

	while (nini->nini_flags & (NSS_ALL_INPROGRESS|cmask)) {
		DTRACE_PROBE2(neti__wait__nini__inprogress,
		    neti_stack_t *, nts, net_instance_int_t *, nini);
		dropped = B_TRUE;
		mutex_exit(&neti_stack_lock);

		cv_wait(&nini->nini_cv, &nts->nts_lock);

		/* First drop netstack_lock to preserve order */
		mutex_exit(&nts->nts_lock);
		DTRACE_PROBE2(wait__nini__inprogress__pause,
		    neti_stack_t *, nts, net_instance_int_t *, nini);
		mutex_enter(&neti_stack_lock);
		mutex_enter(&nts->nts_lock);
	}
	DTRACE_PROBE2(neti__wait__nini__inprogress__complete,
	    neti_stack_t *, nts, net_instance_int_t *, nini);
	return (dropped);
}

/* ======================================================================= */

netid_t
net_zoneidtonetid(zoneid_t zoneid)
{

	neti_stack_t *nts;

	mutex_enter(&neti_stack_lock);
	LIST_FOREACH(nts, &neti_stack_list, nts_next) {
		if (nts->nts_zoneid == zoneid) {
			mutex_exit(&neti_stack_lock);
			return (nts->nts_id);
		}
	}
	mutex_exit(&neti_stack_lock);

	return (-1);
}

zoneid_t
net_getzoneidbynetid(netid_t netid)
{
	neti_stack_t *nts;

	mutex_enter(&neti_stack_lock);
	LIST_FOREACH(nts, &neti_stack_list, nts_next) {
		if (nts->nts_id == netid) {
			mutex_exit(&neti_stack_lock);
			return (nts->nts_zoneid);
		}
	}
	mutex_exit(&neti_stack_lock);

	return (-1);
}

netstackid_t
net_getnetstackidbynetid(netid_t netid)
{
	neti_stack_t *nts;

	mutex_enter(&neti_stack_lock);
	LIST_FOREACH(nts, &neti_stack_list, nts_next) {
		if (nts->nts_id == netid) {
			mutex_exit(&neti_stack_lock);
			return (nts->nts_stackid);
		}
	}
	mutex_exit(&neti_stack_lock);

	return (-1);
}

netid_t
net_getnetidbynetstackid(netstackid_t netstackid)
{
	neti_stack_t *nts;

	mutex_enter(&neti_stack_lock);
	LIST_FOREACH(nts, &neti_stack_list, nts_next) {
		if (nts->nts_stackid == netstackid) {
			mutex_exit(&neti_stack_lock);
			return (nts->nts_id);
		}
	}
	mutex_exit(&neti_stack_lock);

	return (-1);
}

neti_stack_t *
net_getnetistackbyid(netid_t netid)
{
	neti_stack_t *nts;

	mutex_enter(&neti_stack_lock);
	LIST_FOREACH(nts, &neti_stack_list, nts_next) {
		if (nts->nts_id == netid) {
			mutex_exit(&neti_stack_lock);
			return (nts);
		}
	}
	mutex_exit(&neti_stack_lock);

	return (NULL);
}

int
net_instance_notify_register(netid_t netid, hook_notify_fn_t callback,
    void *arg)
{

	return (hook_stack_notify_register(net_getnetstackidbynetid(netid),
	    callback, arg));
}

int
net_instance_notify_unregister(netid_t netid, hook_notify_fn_t callback)
{

	return (hook_stack_notify_unregister(net_getnetstackidbynetid(netid),
	    callback));
}
