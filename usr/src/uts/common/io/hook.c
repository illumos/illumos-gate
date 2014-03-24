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
 *
 * Copyright 2013 Joyent, Inc.  All rights reserved.
 */
#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/modctl.h>
#include <sys/hook_impl.h>
#include <sys/sdt.h>
#include <sys/cmn_err.h>

/*
 * This file provides kernel hook framework.
 */

static struct modldrv modlmisc = {
	&mod_miscops,				/* drv_modops */
	"Hooks Interface v1.0",			/* drv_linkinfo */
};

static struct modlinkage modlinkage = {
	MODREV_1,				/* ml_rev */
	&modlmisc,				/* ml_linkage */
	NULL
};

static const char *hook_hintvalue_none = "<none>";

/*
 * How it works.
 * =============
 * Use of the hook framework here is tied up with zones - when a new zone
 * is created, we create a new hook_stack_t and are open to business for
 * allowing new hook families and their events.
 *
 * A consumer of these hooks is expected to operate in this fashion:
 * 1) call hook_family_add() to create a new family of hooks. It is a
 *    current requirement that this call must be made with the value
 *    returned from hook_stack_init, by way of infrastructure elsewhere.
 * 2) add events to the registered family with calls to hook_event_add.
 *
 * At this point, the structures in place should be open to others to
 * add hooks to the event or add notifiers for when the contents of the
 * hook stack changes.
 *
 * The interesting stuff happens on teardown.
 *
 * It is a requirement that the provider of hook events work in the reverse
 * order to the above, so that the first step is:
 * 1) remove events from each hook family created earlier
 * 2) remove hook families from the hook stack.
 *
 * When doing teardown of both events and families, a check is made to see
 * if either structure is still "busy". If so then a boolean flag (FWF_DESTROY)
 * is set to say that the structure is condemned. The presence of this flag
 * being set must be checked for in _add()/_register()/ functions and a
 * failure returned if it is set. It is ignored by the _find() functions
 * because they're used by _remove()/_unregister().
 * While setting the condemned flag when trying to delete a structure would
 * normally be keyed from the presence of a reference count being greater
 * than 1, in this implementation there are no reference counts required:
 * instead the presence of objects on linked lists is taken to mean
 * something is still "busy."
 *
 * ONLY the caller that adds the family and the events ever has a direct
 * reference to the internal structures and thus ONLY it should be doing
 * the removal of either the event or family.  In practise, what this means
 * is that in ip_netinfo.c, we have calls to net_protocol_register(), followed
 * by net_event_register() (these interface to hook_family_add() and
 * hook_event_add(), respectively) that are made when we create an instance
 * of IP and when the IP instance is shutdown/destroyed, it calls
 * net_event_unregister() and net_protocol_unregister(), which in turn call
 * hook_event_remove() and hook_family_remove() respectively. Nobody else
 * is entitled to call the _unregister() functions.  It is imperative that
 * there be only one _remove() call for every _add() call.
 *
 * It is possible that code which is interfacing with this hook framework
 * won't do all the cleaning up that it needs to at the right time. While
 * we can't prevent programmers from creating memory leaks, we can synchronise
 * when we clean up data structures to prevent code accessing free'd memory.
 *
 * A simple diagram showing the ownership is as follows:
 *
 *  Owned       +--------------+
 *   by         | hook_stack_t |
 *   the        +--------------+
 *  Instance      |
 * - - - - - - - -|- - - - - - - - - - - - - - - - - -
 *                V
 *  Owned       +-------------------+     +-------------------+
 *              | hook_family_int_t |---->| hook_family_int_t |
 *   by         +-------------------+     +-------------------+
 *                | \+---------------+        \+---------------+
 *  network       |  | hook_family_t |         | hook_family_t |
 *                V  +---------------+         +---------------+
 *  protocol   +------------------+     +------------------+
 *             | hook_event_int_t |---->| hook_event_int_t |
 * (ipv4,ipv6) +------------------+     +------------------+
 *                | \+--------------+        \+--------------+
 *                |  | hook_event_t |         | hook_event_t |
 *                |  +--------------+         +--------------+
 * - - - - - - - -|- - - - - - - - - - - - - - - - - -
 *                V
 *  Owned      +------------+
 *             | hook_int_t |
 *   by        +------------+
 *                  \+--------+
 * the consumer      | hook_t |
 *                   +--------+
 *
 * The consumers, such as IPFilter, do not have any pointers or hold any
 * references to hook_int_t, hook_event_t or hook_event_int_t. By placing
 * a hook on an event through net_hook_register(), an implicit reference
 * to the hook_event_int_t is returned with a successful call.  Additionally,
 * IPFilter does not see the hook_family_int_t or hook_family_t directly.
 * Rather it is returned a net_handle_t (from net_protocol_lookup()) that
 * contains a pointer to hook_family_int_t.  The structure behind the
 * net_handle_t (struct net_data) *is* reference counted and managed
 * appropriately.
 *
 * A more detailed picture that describes how the family/event structures
 * are linked together can be found in <sys/hook_impl.h>
 *
 * Notification callbacks.
 * =======================
 * For each of the hook stack, hook family and hook event, it is possible
 * to request notificatin of change to them. Why?
 * First, lets equate the hook stack to an IP instance, a hook family to
 * a network protocol and a hook event to IP packets on the input path.
 * If a kernel module wants to apply security from the very start of
 * things, it needs to know as soon as a new instance of networking
 * is initiated. Whilst for the global zone, it is taken for granted that
 * this instance will always exist before any interaction takes place,
 * that is not true for zones running with an exclusive networking instance.
 * Thus when a local zone is started and a new instance is created to support
 * that, parties that wish to monitor it and apply a security policy from
 * the onset need to be informed as early as possible - quite probably
 * before any networking is started by the zone's boot scripts.
 * Inside each instance, it is possible to have a number of network protocols
 * (hook families) in operation. Inside the context of the global zone,
 * it is possible to have code run before the kernel module providing the
 * IP networking is loaded. From here, to apply the appropriate security,
 * it is necessary to become informed of when IP is being configured into
 * the zone and this is done by registering a notification callback with
 * the hook stack for changes to it. The next step is to know when packets
 * can be received through the physical_in, etc, events. This is achieved
 * by registering a callback with the appropriate network protocol (or in
 * this file, the correct hook family.) Thus when IP finally attaches a
 * physical_in event to inet, the module looking to enforce a security
 * policy can become aware of it being present. Of course there's no
 * requirement for such a module to be present before all of the above
 * happens and in such a case, it is reasonable for the same module to
 * work after everything has been put in place. For this reason, when
 * a notification callback is added, a series of fake callback events
 * is generated to simulate the arrival of those entities. There is one
 * final series of callbacks that can be registered - those to monitor
 * actual hooks that are added or removed from an event. In practice,
 * this is useful when there are multiple kernel modules participating
 * in the processing of packets and there are behaviour dependencies
 * involved, such that one kernel module might only register its hook
 * if another is already present and also might want to remove its hook
 * when the other disappears.
 *
 * If you know a kernel module will not be loaded before the infrastructure
 * used in this file is present then it is not necessary to use this
 * notification callback mechanism.
 */

/*
 * Locking
 * =======
 * The use of CVW_* macros to do locking is driven by the need to allow
 * recursive locking with read locks when we're processing packets. This
 * is necessary because various netinfo functions need to hold read locks,
 * by design, as they can be called in or out of packet context.
 */
/*
 * Hook internal functions
 */
static hook_int_t *hook_copy(hook_t *src);
static hook_event_int_t *hook_event_checkdup(hook_event_t *he,
    hook_stack_t *hks);
static hook_event_int_t *hook_event_copy(hook_event_t *src);
static hook_event_int_t *hook_event_find(hook_family_int_t *hfi, char *event);
static void hook_event_free(hook_event_int_t *hei, hook_family_int_t *hfi);
static hook_family_int_t *hook_family_copy(hook_family_t *src);
static hook_family_int_t *hook_family_find(char *family, hook_stack_t *hks);
static void hook_family_free(hook_family_int_t *hfi, hook_stack_t *hks);
static hook_int_t *hook_find(hook_event_int_t *hei, hook_t *h);
static void hook_int_free(hook_int_t *hi, netstackid_t);
static void hook_init(void);
static void hook_fini(void);
static void *hook_stack_init(netstackid_t stackid, netstack_t *ns);
static void hook_stack_fini(netstackid_t stackid, void *arg);
static void hook_stack_shutdown(netstackid_t stackid, void *arg);
static int hook_insert(hook_int_head_t *head, hook_int_t *new);
static void hook_insert_plain(hook_int_head_t *head, hook_int_t *new);
static int hook_insert_afterbefore(hook_int_head_t *head, hook_int_t *new);
static hook_int_t *hook_find_byname(hook_int_head_t *head, char *name);
static void hook_event_init_kstats(hook_family_int_t *, hook_event_int_t *);
static void hook_event_notify_run(hook_event_int_t *, hook_family_int_t *,
    char *event, char *name, hook_notify_cmd_t cmd);
static void hook_init_kstats(hook_family_int_t *hfi, hook_event_int_t *hei,
    hook_int_t *hi);
static int hook_notify_register(hook_notify_head_t *head,
    hook_notify_fn_t callback, void *arg);
static int hook_notify_unregister(hook_notify_head_t *head,
    hook_notify_fn_t callback, void **);
static void hook_notify_run(hook_notify_head_t *head, char *family,
    char *event, char *name, hook_notify_cmd_t cmd);
static void hook_stack_notify_run(hook_stack_t *hks, char *name,
    hook_notify_cmd_t cmd);
static void hook_stack_remove(hook_stack_t *hks);

/*
 * A list of the hook stacks is kept here because we need to enable
 * net_instance_notify_register() to be called during the creation
 * of a new instance. Previously hook_stack_get() would just use
 * the netstack functions for this work but they will return NULL
 * until the zone has been fully initialised.
 */
static hook_stack_head_t hook_stacks;
static kmutex_t hook_stack_lock;

/*
 * Module entry points.
 */
int
_init(void)
{
	int error;

	hook_init();
	error = mod_install(&modlinkage);
	if (error != 0)
		hook_fini();

	return (error);
}

int
_fini(void)
{
	int error;

	error = mod_remove(&modlinkage);
	if (error == 0)
		hook_fini();

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * Function:	hook_init
 * Returns:	None
 * Parameters:	None
 *
 * Initialize hooks
 */
static void
hook_init(void)
{
	mutex_init(&hook_stack_lock, NULL, MUTEX_DRIVER, NULL);
	SLIST_INIT(&hook_stacks);

	/*
	 * We want to be informed each time a stack is created or
	 * destroyed in the kernel.
	 */
	netstack_register(NS_HOOK, hook_stack_init, hook_stack_shutdown,
	    hook_stack_fini);
}

/*
 * Function:	hook_fini
 * Returns:	None
 * Parameters:	None
 *
 * Deinitialize hooks
 */
static void
hook_fini(void)
{
	netstack_unregister(NS_HOOK);

	mutex_destroy(&hook_stack_lock);
	ASSERT(SLIST_EMPTY(&hook_stacks));
}

/*
 * Function:	hook_wait_setflag
 * Returns:     -1 = setting flag is disallowed, 0 = flag set and did
 *              not have to wait (ie no lock droped), 1 = flag set but
 *              it was necessary to drop locks to set it.
 * Parameters:  waiter(I)  - control data structure
 *              busyset(I) - set of flags that we don't want set while
 *                           we are active.
 *              wanted(I)  - flag associated with newflag to indicate
 *                           what we want to do.
 *              newflag(I) - the new ACTIVE flag we want to set that
 *                           indicates what we are doing.
 *
 * The set of functions hook_wait_* implement an API that builds on top of
 * the kcondvar_t to provide controlled execution through a critical region.
 * For each flag that indicates work is being done (FWF_*_ACTIVE) there is
 * also a flag that we set to indicate that we want to do it (FWF_*_WANTED).
 * The combination of flags is required as when this function exits to do
 * the task, the structure is then free for another caller to use and
 * to indicate that it wants to do work.  The flags used when a caller wants
 * to destroy an object take precedence over those that are used for making
 * changes to it (add/remove.) In this case, we don't try to secure the
 * ability to run and return with an error.
 *
 * "wantedset" is used here to determine who has the right to clear the
 * wanted but from the fw_flags set: only he that sets the flag has the
 * right to clear it at the bottom of the loop, even if someone else
 * wants to set it.
 *
 * wanted - the FWF_*_WANTED flag that describes the action being requested
 * busyset- the set of FWF_* flags we don't want set when we run
 * newflag- the FWF_*_ACTIVE flag we will set to indicate we are busy
 */
int
hook_wait_setflag(flagwait_t *waiter, uint32_t busyset, fwflag_t wanted,
    fwflag_t newflag)
{
	boolean_t wantedset;
	int waited = 0;

	mutex_enter(&waiter->fw_lock);
	if (waiter->fw_flags & FWF_DESTROY) {
		cv_signal(&waiter->fw_cv);
		mutex_exit(&waiter->fw_lock);
		return (-1);
	}
	while (waiter->fw_flags & busyset) {
		wantedset = ((waiter->fw_flags & wanted) == wanted);
		if (!wantedset)
			waiter->fw_flags |= wanted;
		CVW_EXIT_WRITE(waiter->fw_owner);
		cv_wait(&waiter->fw_cv, &waiter->fw_lock);
		/*
		 * This lock needs to be dropped here to preserve the order
		 * of acquisition that is fw_owner followed by fw_lock, else
		 * we can deadlock.
		 */
		mutex_exit(&waiter->fw_lock);
		waited = 1;
		CVW_ENTER_WRITE(waiter->fw_owner);
		mutex_enter(&waiter->fw_lock);
		if (!wantedset)
			waiter->fw_flags &= ~wanted;
		if (waiter->fw_flags & FWF_DESTROY) {
			cv_signal(&waiter->fw_cv);
			mutex_exit(&waiter->fw_lock);
			return (-1);
		}
	}
	waiter->fw_flags &= ~wanted;
	ASSERT((waiter->fw_flags & wanted) == 0);
	ASSERT((waiter->fw_flags & newflag) == 0);
	waiter->fw_flags |= newflag;
	mutex_exit(&waiter->fw_lock);
	return (waited);
}

/*
 * Function:	hook_wait_unsetflag
 * Returns:     None
 * Parameters:  waiter(I)  - control data structure
 *              oldflag(I) - flag to reset
 *
 * Turn off the bit that we had set to run and let others know that
 * they should now check to see if they can run.
 */
void
hook_wait_unsetflag(flagwait_t *waiter, fwflag_t oldflag)
{
	mutex_enter(&waiter->fw_lock);
	waiter->fw_flags &= ~oldflag;
	cv_signal(&waiter->fw_cv);
	mutex_exit(&waiter->fw_lock);
}

/*
 * Function:	hook_wait_destroy
 * Returns:     None
 * Parameters:  waiter(I)  - control data structure
 *
 * Since outer locking (on fw_owner) should ensure that only one function
 * at a time gets to call hook_wait_destroy() on a given object, there is
 * no need to guard against setting FWF_DESTROY_WANTED already being set.
 * It is, however, necessary to wait for all activity on the owning
 * structure to cease.
 */
int
hook_wait_destroy(flagwait_t *waiter)
{
	ASSERT((waiter->fw_flags & FWF_DESTROY_WANTED) == 0);
	mutex_enter(&waiter->fw_lock);
	if (waiter->fw_flags & FWF_DESTROY_WANTED) {
		cv_signal(&waiter->fw_cv);
		mutex_exit(&waiter->fw_lock);
		return (EINPROGRESS);
	}
	waiter->fw_flags |= FWF_DESTROY_WANTED;
	while (!FWF_DESTROY_OK(waiter)) {
		CVW_EXIT_WRITE(waiter->fw_owner);
		cv_wait(&waiter->fw_cv, &waiter->fw_lock);
		CVW_ENTER_WRITE(waiter->fw_owner);
	}
	/*
	 * There should now be nothing else using "waiter" or its
	 * owner, so we can safely assign here without risk of wiiping
	 * out someone's bit.
	 */
	waiter->fw_flags = FWF_DESTROY_ACTIVE;
	cv_signal(&waiter->fw_cv);
	mutex_exit(&waiter->fw_lock);

	return (0);
}

/*
 * Function:	hook_wait_init
 * Returns:     None
 * Parameters:  waiter(I)  - control data structure
 *              ownder(I)  - pointer to lock that the owner of this
 *                           waiter uses
 *
 * "owner" gets passed in here so that when we need to call cv_wait,
 * for example in hook_wait_setflag(), we can drop the lock for the
 * next layer out, which is likely to be held in an exclusive manner.
 */
void
hook_wait_init(flagwait_t *waiter, cvwaitlock_t *owner)
{
	cv_init(&waiter->fw_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&waiter->fw_lock, NULL, MUTEX_DRIVER, NULL);
	waiter->fw_flags = FWF_NONE;
	waiter->fw_owner = owner;
}

/*
 * Function:	hook_stack_init
 * Returns:     void *     - pointer to new hook stack structure
 * Parameters:  stackid(I) - identifier for the network instance that owns this
 *              ns(I)      - pointer to the network instance data structure
 *
 * Allocate and initialize the hook stack instance. This function is not
 * allowed to fail, so KM_SLEEP is used here when allocating memory. The
 * value returned is passed back into the shutdown and destroy hooks.
 */
/*ARGSUSED*/
static void *
hook_stack_init(netstackid_t stackid, netstack_t *ns)
{
	hook_stack_t	*hks;

#ifdef NS_DEBUG
	printf("hook_stack_init(stack %d)\n", stackid);
#endif

	hks = (hook_stack_t *)kmem_zalloc(sizeof (*hks), KM_SLEEP);
	hks->hks_netstack = ns;
	hks->hks_netstackid = stackid;

	CVW_INIT(&hks->hks_lock);
	TAILQ_INIT(&hks->hks_nhead);
	SLIST_INIT(&hks->hks_familylist);

	hook_wait_init(&hks->hks_waiter, &hks->hks_lock);

	mutex_enter(&hook_stack_lock);
	SLIST_INSERT_HEAD(&hook_stacks, hks, hks_entry);
	mutex_exit(&hook_stack_lock);

	return (hks);
}

/*
 * Function:	hook_stack_shutdown
 * Returns:     void
 * Parameters:  stackid(I) - identifier for the network instance that owns this
 *              arg(I)     - pointer returned by hook_stack_init
 *
 * Set the shutdown flag to indicate that we should stop accepting new
 * register calls as we're now in the cleanup process. The cleanup is a
 * two stage process and we're not required to free any memory here.
 *
 * The curious would wonder why isn't there any code that walks through
 * all of the data structures and sets the flag(s) there? The answer is
 * that it is expected that this will happen when the zone shutdown calls
 * the shutdown callbacks for other modules that they will initiate the
 * free'ing and shutdown of the hooks themselves.
 */
/*ARGSUSED*/
static void
hook_stack_shutdown(netstackid_t stackid, void *arg)
{
	hook_stack_t *hks = (hook_stack_t *)arg;

	mutex_enter(&hook_stack_lock);
	/*
	 * Once this flag gets set to one, no more additions are allowed
	 * to any of the structures that make up this stack.
	 */
	hks->hks_shutdown = 1;
	mutex_exit(&hook_stack_lock);
}

/*
 * Function:	hook_stack_destroy
 * Returns:     void
 * Parameters:  stackid(I) - identifier for the network instance that owns this
 *              arg(I)     - pointer returned by hook_stack_init
 *
 * Free the hook stack instance.
 *
 * The rationale for the shutdown being lazy (see the comment above for
 * hook_stack_shutdown) also applies to the destroy being lazy. Only if
 * the hook_stack_t data structure is unused will it go away. Else it
 * is left up to the last user of a data structure to actually free it.
 */
/*ARGSUSED*/
static void
hook_stack_fini(netstackid_t stackid, void *arg)
{
	hook_stack_t *hks = (hook_stack_t *)arg;

	mutex_enter(&hook_stack_lock);
	hks->hks_shutdown = 2;
	hook_stack_remove(hks);
	mutex_exit(&hook_stack_lock);
}

/*
 * Function:	hook_stack_remove
 * Returns:     void
 * Parameters:  hks(I) - pointer to an instance of a hook_stack_t
 *
 * This function assumes that it is called with hook_stack_lock held.
 * It functions differently to hook_family/event_remove in that it does
 * the checks to see if it can be removed. This difference exists
 * because this structure has nothing higher up that depends on it.
 */
static void
hook_stack_remove(hook_stack_t *hks)
{

	ASSERT(mutex_owned(&hook_stack_lock));

	/*
	 * Is the structure still in use?
	 */
	if (!SLIST_EMPTY(&hks->hks_familylist) ||
	    !TAILQ_EMPTY(&hks->hks_nhead))
		return;

	SLIST_REMOVE(&hook_stacks, hks, hook_stack, hks_entry);

	VERIFY(hook_wait_destroy(&hks->hks_waiter) == 0);
	CVW_DESTROY(&hks->hks_lock);
	kmem_free(hks, sizeof (*hks));
}

/*
 * Function:	hook_stack_get
 * Returns:     hook_stack_t * - NULL if not found, else matching instance
 * Parameters:  stackid(I)     - instance id to search for
 *
 * Search the list of currently active hook_stack_t structures for one that
 * has a matching netstackid_t to the value passed in. The linked list can
 * only ever have at most one match for this value.
 */
static hook_stack_t *
hook_stack_get(netstackid_t stackid)
{
	hook_stack_t *hks;

	SLIST_FOREACH(hks, &hook_stacks, hks_entry) {
		if (hks->hks_netstackid == stackid)
			break;
	}

	return (hks);
}

/*
 * Function:	hook_stack_notify_register
 * Returns:	int        - 0 = success, else failure
 * Parameters:	stackid(I) - netstack identifier
 *              callback(I)- function to be called
 *              arg(I)     - arg to provide callback when it is called
 *
 * If we're not shutting down this instance, append a new function to the
 * list of those to call when a new family of hooks is added to this stack.
 * If the function can be successfully added to the list of callbacks
 * activated when there is a change to the stack (addition or removal of
 * a hook family) then generate a fake HN_REGISTER event by directly
 * calling the callback with the relevant information for each hook
 * family that currently exists (and isn't being shutdown.)
 */
int
hook_stack_notify_register(netstackid_t stackid, hook_notify_fn_t callback,
    void *arg)
{
	hook_family_int_t *hfi;
	hook_stack_t *hks;
	boolean_t canrun;
	char buffer[16];
	int error;

	ASSERT(callback != NULL);

	canrun = B_FALSE;
	mutex_enter(&hook_stack_lock);
	hks = hook_stack_get(stackid);
	if (hks != NULL) {
		if (hks->hks_shutdown != 0) {
			error = ESHUTDOWN;
		} else {
			CVW_ENTER_WRITE(&hks->hks_lock);
			canrun = (hook_wait_setflag(&hks->hks_waiter,
			    FWF_ADD_WAIT_MASK, FWF_ADD_WANTED,
			    FWF_ADD_ACTIVE) != -1);
			error = hook_notify_register(&hks->hks_nhead,
			    callback, arg);
			CVW_EXIT_WRITE(&hks->hks_lock);
		}
	} else {
		error = ESRCH;
	}
	mutex_exit(&hook_stack_lock);

	if (error == 0 && canrun) {
		/*
		 * Generate fake register event for callback that
		 * is being added, letting it know everything that
		 * already exists.
		 */
		(void) snprintf(buffer, sizeof (buffer), "%u",
		    hks->hks_netstackid);

		SLIST_FOREACH(hfi, &hks->hks_familylist, hfi_entry) {
			if (hfi->hfi_condemned || hfi->hfi_shutdown)
				continue;
			callback(HN_REGISTER, arg, buffer, NULL,
			    hfi->hfi_family.hf_name);
		}
	}

	if (canrun)
		hook_wait_unsetflag(&hks->hks_waiter, FWF_ADD_ACTIVE);

	return (error);
}

/*
 * Function:	hook_stack_notify_unregister
 * Returns:	int         - 0 = success, else failure
 * Parameters:	stackid(I)  - netstack identifier
 *              callback(I) - function to be called
 *
 * Attempt to remove a registered function from a hook stack's list of
 * callbacks to activiate when protocols are added/deleted.
 * As with hook_stack_notify_register, if all things are going well then
 * a fake unregister event is delivered to the callback being removed
 * for each hook family that presently exists.
 */
int
hook_stack_notify_unregister(netstackid_t stackid, hook_notify_fn_t callback)
{
	hook_family_int_t *hfi;
	hook_stack_t *hks;
	boolean_t canrun;
	char buffer[16];
	void *arg;
	int error;

	mutex_enter(&hook_stack_lock);
	hks = hook_stack_get(stackid);
	if (hks != NULL) {
		CVW_ENTER_WRITE(&hks->hks_lock);
		canrun = (hook_wait_setflag(&hks->hks_waiter, FWF_ADD_WAIT_MASK,
		    FWF_ADD_WANTED, FWF_ADD_ACTIVE) != -1);

		error = hook_notify_unregister(&hks->hks_nhead, callback, &arg);
		CVW_EXIT_WRITE(&hks->hks_lock);
	} else {
		error = ESRCH;
	}
	mutex_exit(&hook_stack_lock);

	if (error == 0) {
		if (canrun) {
			/*
			 * Generate fake unregister event for callback that
			 * is being removed, letting it know everything that
			 * currently exists is now "disappearing."
			 */
			(void) snprintf(buffer, sizeof (buffer), "%u",
			    hks->hks_netstackid);

			SLIST_FOREACH(hfi, &hks->hks_familylist, hfi_entry) {
				callback(HN_UNREGISTER, arg, buffer, NULL,
				    hfi->hfi_family.hf_name);
			}

			hook_wait_unsetflag(&hks->hks_waiter, FWF_ADD_ACTIVE);
		}

		mutex_enter(&hook_stack_lock);
		hks = hook_stack_get(stackid);
		if ((error == 0) && (hks->hks_shutdown == 2))
			hook_stack_remove(hks);
		mutex_exit(&hook_stack_lock);
	}

	return (error);
}

/*
 * Function:	hook_stack_notify_run
 * Returns:	None
 * Parameters:	hks(I)  - hook stack pointer to execute callbacks for
 *              name(I) - name of a hook family
 *              cmd(I)  - either HN_UNREGISTER or HN_REGISTER
 *
 * Run through the list of callbacks on the hook stack to be called when
 * a new hook family is added
 *
 * As hook_notify_run() expects 3 names, one for the family that is associated
 * with the cmd (HN_REGISTER or HN_UNREGISTER), one for the event and one
 * for the object being introduced and we really only have one name (that
 * of the new hook family), fake the hook stack's name by converting the
 * integer to a string and for the event just pass NULL.
 */
static void
hook_stack_notify_run(hook_stack_t *hks, char *name,
    hook_notify_cmd_t cmd)
{
	char buffer[16];

	ASSERT(hks != NULL);
	ASSERT(name != NULL);

	(void) snprintf(buffer, sizeof (buffer), "%u", hks->hks_netstackid);

	hook_notify_run(&hks->hks_nhead, buffer, NULL, name, cmd);
}

/*
 * Function:	hook_run
 * Returns:	int      - return value according to callback func
 * Parameters:	token(I) - event pointer
 *		info(I)  - message
 *
 * Run hooks for specific provider.  The hooks registered are stepped through
 * until either the end of the list is reached or a hook function returns a
 * non-zero value.  If a non-zero value is returned from a hook function, we
 * return that value back to our caller.  By design, a hook function can be
 * called more than once, simultaneously.
 */
int
hook_run(hook_family_int_t *hfi, hook_event_token_t token, hook_data_t info)
{
	hook_event_int_t *hei;
	hook_int_t *hi;
	int rval = 0;

	ASSERT(token != NULL);

	hei = (hook_event_int_t *)token;
	DTRACE_PROBE2(hook__run__start,
	    hook_event_token_t, token,
	    hook_data_t, info);

	/*
	 * If we consider that this function is only called from within the
	 * stack while an instance is currently active,
	 */
	CVW_ENTER_READ(&hfi->hfi_lock);

	TAILQ_FOREACH(hi, &hei->hei_head, hi_entry) {
		ASSERT(hi->hi_hook.h_func != NULL);
		DTRACE_PROBE3(hook__func__start,
		    hook_event_token_t, token,
		    hook_data_t, info,
		    hook_int_t *, hi);
		rval = (*hi->hi_hook.h_func)(token, info, hi->hi_hook.h_arg);
		DTRACE_PROBE4(hook__func__end,
		    hook_event_token_t, token,
		    hook_data_t, info,
		    hook_int_t *, hi,
		    int, rval);
		hi->hi_kstats.hook_hits.value.ui64++;
		if (rval != 0)
			break;
	}

	hei->hei_kstats.events.value.ui64++;

	CVW_EXIT_READ(&hfi->hfi_lock);

	DTRACE_PROBE3(hook__run__end,
	    hook_event_token_t, token,
	    hook_data_t, info,
	    hook_int_t *, hi);

	return (rval);
}

/*
 * Function:	hook_family_add
 * Returns:	internal family pointer - NULL = Fail
 * Parameters:	hf(I)    - family pointer
 *              hks(I)   - pointer to an instance of a hook_stack_t
 *              store(O) - where returned pointer will be stored
 *
 * Add new family to the family list. The requirements for the addition to
 * succeed are that the family name must not already be registered and that
 * the hook stack is not being shutdown.
 * If store is non-NULL, it is expected to be a pointer to the same variable
 * that is awaiting to be assigned the return value of this function.
 * In its current use, the returned value is assigned to netd_hooks in
 * net_family_register. The use of "store" allows the return value to be
 * used before this function returns. How can this happen? Through the
 * callbacks that can be activated at the bottom of this function, when
 * hook_stack_notify_run is called.
 */
hook_family_int_t *
hook_family_add(hook_family_t *hf, hook_stack_t *hks, void **store)
{
	hook_family_int_t *hfi, *new;

	ASSERT(hf != NULL);
	ASSERT(hf->hf_name != NULL);

	new = hook_family_copy(hf);
	if (new == NULL)
		return (NULL);

	mutex_enter(&hook_stack_lock);
	CVW_ENTER_WRITE(&hks->hks_lock);

	if (hks->hks_shutdown != 0) {
		CVW_EXIT_WRITE(&hks->hks_lock);
		mutex_exit(&hook_stack_lock);
		hook_family_free(new, NULL);
		return (NULL);
	}

	/* search family list */
	hfi = hook_family_find(hf->hf_name, hks);
	if (hfi != NULL) {
		CVW_EXIT_WRITE(&hks->hks_lock);
		mutex_exit(&hook_stack_lock);
		hook_family_free(new, NULL);
		return (NULL);
	}

	/*
	 * Try and set the FWF_ADD_ACTIVE flag so that we can drop all the
	 * lock further down when calling all of the functions registered
	 * for notification when a new hook family is added.
	 */
	if (hook_wait_setflag(&hks->hks_waiter, FWF_ADD_WAIT_MASK,
	    FWF_ADD_WANTED, FWF_ADD_ACTIVE) == -1) {
		CVW_EXIT_WRITE(&hks->hks_lock);
		mutex_exit(&hook_stack_lock);
		hook_family_free(new, NULL);
		return (NULL);
	}

	CVW_INIT(&new->hfi_lock);
	SLIST_INIT(&new->hfi_head);
	TAILQ_INIT(&new->hfi_nhead);

	hook_wait_init(&new->hfi_waiter, &new->hfi_lock);

	new->hfi_stack = hks;
	if (store != NULL)
		*store = new;

	/* Add to family list head */
	SLIST_INSERT_HEAD(&hks->hks_familylist, new, hfi_entry);

	CVW_EXIT_WRITE(&hks->hks_lock);
	mutex_exit(&hook_stack_lock);

	hook_stack_notify_run(hks, hf->hf_name, HN_REGISTER);

	hook_wait_unsetflag(&hks->hks_waiter, FWF_ADD_ACTIVE);

	return (new);
}

/*
 * Function:	hook_family_remove
 * Returns:	int    - 0 = success, else = failure
 * Parameters:	hfi(I) - internal family pointer
 *
 * Remove family from family list. This function has been designed to be
 * called once and once only per hook_family_int_t. Thus when cleaning up
 * this structure as an orphan, callers should only call hook_family_free.
 */
int
hook_family_remove(hook_family_int_t *hfi)
{
	hook_stack_t *hks;
	boolean_t notifydone;

	ASSERT(hfi != NULL);
	hks = hfi->hfi_stack;

	CVW_ENTER_WRITE(&hfi->hfi_lock);
	notifydone = hfi->hfi_shutdown;
	hfi->hfi_shutdown = B_TRUE;
	CVW_EXIT_WRITE(&hfi->hfi_lock);

	CVW_ENTER_WRITE(&hks->hks_lock);

	if (hook_wait_setflag(&hks->hks_waiter, FWF_DEL_WAIT_MASK,
	    FWF_DEL_WANTED, FWF_DEL_ACTIVE) == -1) {
		/*
		 * If we're trying to destroy the hook_stack_t...
		 */
		CVW_EXIT_WRITE(&hks->hks_lock);
		return (ENXIO);
	}

	/*
	 * Check if the family is in use by the presence of either events
	 * or notify callbacks on the hook family.
	 */
	if (!SLIST_EMPTY(&hfi->hfi_head) || !TAILQ_EMPTY(&hfi->hfi_nhead)) {
		hfi->hfi_condemned = B_TRUE;
	} else {
		VERIFY(hook_wait_destroy(&hfi->hfi_waiter) == 0);
		/*
		 * Although hfi_condemned = B_FALSE is implied from creation,
		 * putting a comment here inside the else upsets lint.
		 */
		hfi->hfi_condemned = B_FALSE;
	}
	CVW_EXIT_WRITE(&hks->hks_lock);

	if (!notifydone)
		hook_stack_notify_run(hks, hfi->hfi_family.hf_name,
		    HN_UNREGISTER);

	hook_wait_unsetflag(&hks->hks_waiter, FWF_DEL_ACTIVE);

	/*
	 * If we don't have to wait for anything else to disappear from this
	 * structure then we can free it up.
	 */
	if (!hfi->hfi_condemned)
		hook_family_free(hfi, hks);

	return (0);
}


/*
 * Function:	hook_family_free
 * Returns:	None
 * Parameters:	hfi(I) - internal family pointer
 *
 * Free alloc memory for family
 */
static void
hook_family_free(hook_family_int_t *hfi, hook_stack_t *hks)
{

	/*
	 * This lock gives us possession of the hks pointer after the
	 * SLIST_REMOVE, for which it is not needed, when hks_shutdown
	 * is checked and hook_stack_remove called.
	 */
	mutex_enter(&hook_stack_lock);

	ASSERT(hfi != NULL);

	if (hks != NULL) {
		CVW_ENTER_WRITE(&hks->hks_lock);
		/* Remove from family list */
		SLIST_REMOVE(&hks->hks_familylist, hfi, hook_family_int,
		    hfi_entry);

		CVW_EXIT_WRITE(&hks->hks_lock);
	}

	/* Free name space */
	if (hfi->hfi_family.hf_name != NULL) {
		kmem_free(hfi->hfi_family.hf_name,
		    strlen(hfi->hfi_family.hf_name) + 1);
	}

	/* Free container */
	kmem_free(hfi, sizeof (*hfi));

	if (hks->hks_shutdown == 2)
		hook_stack_remove(hks);

	mutex_exit(&hook_stack_lock);
}

/*
 * Function:	hook_family_shutdown
 * Returns:	int    - 0 = success, else = failure
 * Parameters:	hfi(I) - internal family pointer
 *
 * As an alternative to removing a family, we may desire to just generate
 * a series of callbacks to indicate that we will be going away in the
 * future. The hfi_condemned flag isn't set because we aren't trying to
 * remove the structure.
 */
int
hook_family_shutdown(hook_family_int_t *hfi)
{
	hook_stack_t *hks;
	boolean_t notifydone;

	ASSERT(hfi != NULL);
	hks = hfi->hfi_stack;

	CVW_ENTER_WRITE(&hfi->hfi_lock);
	notifydone = hfi->hfi_shutdown;
	hfi->hfi_shutdown = B_TRUE;
	CVW_EXIT_WRITE(&hfi->hfi_lock);

	CVW_ENTER_WRITE(&hks->hks_lock);

	if (hook_wait_setflag(&hks->hks_waiter, FWF_DEL_WAIT_MASK,
	    FWF_DEL_WANTED, FWF_DEL_ACTIVE) == -1) {
		/*
		 * If we're trying to destroy the hook_stack_t...
		 */
		CVW_EXIT_WRITE(&hks->hks_lock);
		return (ENXIO);
	}

	CVW_EXIT_WRITE(&hks->hks_lock);

	if (!notifydone)
		hook_stack_notify_run(hks, hfi->hfi_family.hf_name,
		    HN_UNREGISTER);

	hook_wait_unsetflag(&hks->hks_waiter, FWF_DEL_ACTIVE);

	return (0);
}

/*
 * Function:	hook_family_copy
 * Returns:	internal family pointer - NULL = Failed
 * Parameters:	src(I) - family pointer
 *
 * Allocate internal family block and duplicate incoming family
 * No locks should be held across this function as it may sleep.
 */
static hook_family_int_t *
hook_family_copy(hook_family_t *src)
{
	hook_family_int_t *new;
	hook_family_t *dst;

	ASSERT(src != NULL);
	ASSERT(src->hf_name != NULL);

	new = (hook_family_int_t *)kmem_zalloc(sizeof (*new), KM_SLEEP);

	/* Copy body */
	dst = &new->hfi_family;
	*dst = *src;

	SLIST_INIT(&new->hfi_head);
	TAILQ_INIT(&new->hfi_nhead);

	/* Copy name */
	dst->hf_name = (char *)kmem_alloc(strlen(src->hf_name) + 1, KM_SLEEP);
	(void) strcpy(dst->hf_name, src->hf_name);

	return (new);
}

/*
 * Function:	hook_family_find
 * Returns:	internal family pointer - NULL = Not match
 * Parameters:	family(I) - family name string
 *
 * Search family list with family name
 * 	A lock on hfi_lock must be held when called.
 */
static hook_family_int_t *
hook_family_find(char *family, hook_stack_t *hks)
{
	hook_family_int_t *hfi = NULL;

	ASSERT(family != NULL);

	SLIST_FOREACH(hfi, &hks->hks_familylist, hfi_entry) {
		if (strcmp(hfi->hfi_family.hf_name, family) == 0)
			break;
	}
	return (hfi);
}

/*
 * Function:	hook_family_notify_register
 * Returns:	int         - 0 = success, else failure
 * Parameters:	hfi(I)      - hook family
 *              callback(I) - function to be called
 *              arg(I)      - arg to provide callback when it is called
 *
 * So long as this hook stack isn't being shut down, register a new
 * callback to be activated each time a new event is added to this
 * family.
 *
 * To call this function we must have an active handle in use on the family,
 * so if we take this into account, then neither the hook_family_int_t nor
 * the hook_stack_t that owns it can disappear. We have to put some trust
 * in the callers to be properly synchronised...
 *
 * Holding hks_lock is required to provide synchronisation for hks_shutdown.
 */
int
hook_family_notify_register(hook_family_int_t *hfi,
    hook_notify_fn_t callback, void *arg)
{
	hook_event_int_t *hei;
	hook_stack_t *hks;
	boolean_t canrun;
	int error;

	ASSERT(hfi != NULL);
	canrun = B_FALSE;
	hks = hfi->hfi_stack;

	CVW_ENTER_READ(&hks->hks_lock);

	if ((hfi->hfi_stack->hks_shutdown != 0) ||
	    hfi->hfi_condemned || hfi->hfi_shutdown) {
		CVW_EXIT_READ(&hks->hks_lock);
		return (ESHUTDOWN);
	}

	CVW_ENTER_WRITE(&hfi->hfi_lock);
	canrun = (hook_wait_setflag(&hfi->hfi_waiter, FWF_ADD_WAIT_MASK,
	    FWF_ADD_WANTED, FWF_ADD_ACTIVE) != -1);
	error = hook_notify_register(&hfi->hfi_nhead, callback, arg);
	CVW_EXIT_WRITE(&hfi->hfi_lock);

	CVW_EXIT_READ(&hks->hks_lock);

	if (error == 0 && canrun) {
		SLIST_FOREACH(hei, &hfi->hfi_head, hei_entry) {
			callback(HN_REGISTER, arg,
			    hfi->hfi_family.hf_name, NULL,
			    hei->hei_event->he_name);
		}
	}

	if (canrun)
		hook_wait_unsetflag(&hfi->hfi_waiter, FWF_ADD_ACTIVE);

	return (error);
}

/*
 * Function:	hook_family_notify_unregister
 * Returns:	int         - 0 = success, else failure
 * Parameters:	hfi(I)      - hook family
 *              callback(I) - function to be called
 *
 * Remove a callback from the list of those executed when a new event is
 * added to a hook family. If the family is not in the process of being
 * destroyed then simulate an unregister callback for each event that is
 * on the family. This pairs up with the hook_family_notify_register
 * action that simulates register events.
 * The order of what happens here is important and goes like this.
 * 1) Remove the callback from the list of functions to be called as part
 *    of the notify operation when an event is added or removed from the
 *    hook family.
 * 2) If the hook_family_int_t structure is on death row (free_family will
 *    be set to true) then there's nothing else to do than let it be free'd.
 * 3) If the structure isn't about to die, mark it up as being busy using
 *    hook_wait_setflag and then drop the lock so the loop can be run.
 * 4) if hook_wait_setflag was successful, tell all of the notify callback
 *    functions that this family has been unregistered.
 * 5) Cleanup
 */
int
hook_family_notify_unregister(hook_family_int_t *hfi,
    hook_notify_fn_t callback)
{
	hook_event_int_t *hei;
	boolean_t free_family;
	boolean_t canrun;
	int error;
	void *arg;

	canrun = B_FALSE;

	CVW_ENTER_WRITE(&hfi->hfi_lock);

	(void) hook_wait_setflag(&hfi->hfi_waiter, FWF_DEL_WAIT_MASK,
	    FWF_DEL_WANTED, FWF_DEL_ACTIVE);

	error = hook_notify_unregister(&hfi->hfi_nhead, callback, &arg);

	hook_wait_unsetflag(&hfi->hfi_waiter, FWF_DEL_ACTIVE);

	/*
	 * If hook_family_remove has been called but the structure was still
	 * "busy" ... but we might have just made it "unbusy"...
	 */
	if ((error == 0) && hfi->hfi_condemned &&
	    SLIST_EMPTY(&hfi->hfi_head) && TAILQ_EMPTY(&hfi->hfi_nhead)) {
		free_family = B_TRUE;
	} else {
		free_family = B_FALSE;
	}

	if (error == 0 && !free_family) {
		canrun = (hook_wait_setflag(&hfi->hfi_waiter, FWF_ADD_WAIT_MASK,
		    FWF_ADD_WANTED, FWF_ADD_ACTIVE) != -1);
	}

	CVW_EXIT_WRITE(&hfi->hfi_lock);

	if (canrun) {
		SLIST_FOREACH(hei, &hfi->hfi_head, hei_entry) {
			callback(HN_UNREGISTER, arg,
			    hfi->hfi_family.hf_name, NULL,
			    hei->hei_event->he_name);
		}

		hook_wait_unsetflag(&hfi->hfi_waiter, FWF_ADD_ACTIVE);
	} else if (free_family) {
		hook_family_free(hfi, hfi->hfi_stack);
	}

	return (error);
}

/*
 * Function:	hook_event_add
 * Returns:	internal event pointer - NULL = Fail
 * Parameters:	hfi(I) - internal family pointer
 *		he(I)  - event pointer
 *
 * Add new event to event list on specific family.
 * This function can fail to return successfully if (1) it cannot allocate
 * enough memory for its own internal data structures, (2) the event has
 * already been registered (for any hook family.)
 */
hook_event_int_t *
hook_event_add(hook_family_int_t *hfi, hook_event_t *he)
{
	hook_event_int_t *hei, *new;
	hook_stack_t *hks;

	ASSERT(hfi != NULL);
	ASSERT(he != NULL);
	ASSERT(he->he_name != NULL);

	new = hook_event_copy(he);
	if (new == NULL)
		return (NULL);

	hks = hfi->hfi_stack;
	CVW_ENTER_READ(&hks->hks_lock);

	hks = hfi->hfi_stack;
	if (hks->hks_shutdown != 0) {
		CVW_EXIT_READ(&hks->hks_lock);
		hook_event_free(new, NULL);
		return (NULL);
	}

	/* Check whether this event pointer is already registered */
	hei = hook_event_checkdup(he, hks);
	if (hei != NULL) {
		CVW_EXIT_READ(&hks->hks_lock);
		hook_event_free(new, NULL);
		return (NULL);
	}

	CVW_ENTER_WRITE(&hfi->hfi_lock);

	if (hfi->hfi_condemned || hfi->hfi_shutdown) {
		CVW_EXIT_WRITE(&hfi->hfi_lock);
		CVW_EXIT_READ(&hks->hks_lock);
		hook_event_free(new, NULL);
		return (NULL);
	}
	CVW_EXIT_READ(&hks->hks_lock);

	if (hook_wait_setflag(&hfi->hfi_waiter, FWF_ADD_WAIT_MASK,
	    FWF_ADD_WANTED, FWF_ADD_ACTIVE) == -1) {
		CVW_EXIT_WRITE(&hfi->hfi_lock);
		hook_event_free(new, NULL);
		return (NULL);
	}

	TAILQ_INIT(&new->hei_nhead);

	hook_event_init_kstats(hfi, new);
	hook_wait_init(&new->hei_waiter, &new->hei_lock);

	/* Add to event list head */
	SLIST_INSERT_HEAD(&hfi->hfi_head, new, hei_entry);

	CVW_EXIT_WRITE(&hfi->hfi_lock);

	hook_notify_run(&hfi->hfi_nhead,
	    hfi->hfi_family.hf_name, NULL, he->he_name, HN_REGISTER);

	hook_wait_unsetflag(&hfi->hfi_waiter, FWF_ADD_ACTIVE);

	return (new);
}

/*
 * Function:	hook_event_init_kstats
 * Returns:	None
 * Parameters:  hfi(I) - pointer to the family that owns this event.
 *              hei(I) - pointer to the hook event that needs some kstats.
 *
 * Create a set of kstats that relate to each event registered with
 * the hook framework.  A counter is kept for each time the event is
 * activated and for each time a hook is added or removed.  As the
 * kstats just count the events as they happen, the total number of
 * hooks registered must be obtained by subtractived removed from added.
 */
static void
hook_event_init_kstats(hook_family_int_t *hfi, hook_event_int_t *hei)
{
	hook_event_kstat_t template = {
		{ "hooksAdded",		KSTAT_DATA_UINT64 },
		{ "hooksRemoved",	KSTAT_DATA_UINT64 },
		{ "events",		KSTAT_DATA_UINT64 }
	};
	hook_stack_t *hks;

	hks = hfi->hfi_stack;
	hei->hei_kstatp = kstat_create_netstack(hfi->hfi_family.hf_name, 0,
	    hei->hei_event->he_name, "hook_event", KSTAT_TYPE_NAMED,
	    sizeof (hei->hei_kstats) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL, hks->hks_netstackid);

	bcopy((char *)&template, &hei->hei_kstats, sizeof (template));

	if (hei->hei_kstatp != NULL) {
		hei->hei_kstatp->ks_data = (void *)&hei->hei_kstats;
		hei->hei_kstatp->ks_private =
		    (void *)(uintptr_t)hks->hks_netstackid;

		kstat_install(hei->hei_kstatp);
	}
}

/*
 * Function:	hook_event_remove
 * Returns:	int    - 0 = success, else = failure
 * Parameters:	hfi(I) - internal family pointer
 *		he(I)  - event pointer
 *
 * Remove event from event list on specific family
 *
 * This function assumes that the caller has received a pointer to a the
 * hook_family_int_t via a call to net_protocol_lookup or net_protocol_unreg'.
 * This the hook_family_int_t is guaranteed to be around for the life of this
 * call, unless the caller has decided to call net_protocol_release or
 * net_protocol_unregister before calling net_event_unregister - an error.
 */
int
hook_event_remove(hook_family_int_t *hfi, hook_event_t *he)
{
	boolean_t free_family;
	hook_event_int_t *hei;
	boolean_t notifydone;

	ASSERT(hfi != NULL);
	ASSERT(he != NULL);

	CVW_ENTER_WRITE(&hfi->hfi_lock);

	/*
	 * Set the flag so that we can call hook_event_notify_run without
	 * holding any locks but at the same time prevent other changes to
	 * the event at the same time.
	 */
	if (hook_wait_setflag(&hfi->hfi_waiter, FWF_DEL_WAIT_MASK,
	    FWF_DEL_WANTED, FWF_DEL_ACTIVE) == -1) {
		CVW_EXIT_WRITE(&hfi->hfi_lock);
		return (ENXIO);
	}

	hei = hook_event_find(hfi, he->he_name);
	if (hei == NULL) {
		hook_wait_unsetflag(&hfi->hfi_waiter, FWF_DEL_ACTIVE);
		CVW_EXIT_WRITE(&hfi->hfi_lock);
		return (ESRCH);
	}

	free_family = B_FALSE;

	CVW_ENTER_WRITE(&hei->hei_lock);
	/*
	 * The hei_shutdown flag is used to indicate whether or not we have
	 * done a shutdown and thus already walked through the notify list.
	 */
	notifydone = hei->hei_shutdown;
	hei->hei_shutdown = B_TRUE;
	/*
	 * If there are any hooks still registered for this event or
	 * there are any notifiers registered, return an error indicating
	 * that the event is still busy.
	 */
	if (!TAILQ_EMPTY(&hei->hei_head) || !TAILQ_EMPTY(&hei->hei_nhead)) {
		hei->hei_condemned = B_TRUE;
		CVW_EXIT_WRITE(&hei->hei_lock);
	} else {
		/* hei_condemned = B_FALSE is implied from creation */
		/*
		 * Even though we know the notify list is empty, we call
		 * hook_wait_destroy here to synchronise wait removing a
		 * hook from an event.
		 */
		VERIFY(hook_wait_destroy(&hei->hei_waiter) == 0);

		CVW_EXIT_WRITE(&hei->hei_lock);

		if (hfi->hfi_condemned && SLIST_EMPTY(&hfi->hfi_head) &&
		    TAILQ_EMPTY(&hfi->hfi_nhead))
			free_family = B_TRUE;
	}

	CVW_EXIT_WRITE(&hfi->hfi_lock);

	if (!notifydone)
		hook_notify_run(&hfi->hfi_nhead,
		    hfi->hfi_family.hf_name, NULL, he->he_name, HN_UNREGISTER);

	hook_wait_unsetflag(&hfi->hfi_waiter, FWF_DEL_ACTIVE);

	if (!hei->hei_condemned) {
		hook_event_free(hei, hfi);
		if (free_family)
			hook_family_free(hfi, hfi->hfi_stack);
	}

	return (0);
}

/*
 * Function:	hook_event_shutdown
 * Returns:	int    - 0 = success, else = failure
 * Parameters:	hfi(I) - internal family pointer
 *		he(I)  - event pointer
 *
 * As with hook_family_shutdown, we want to generate the notify callbacks
 * as if the event was being removed but not actually do the remove.
 */
int
hook_event_shutdown(hook_family_int_t *hfi, hook_event_t *he)
{
	hook_event_int_t *hei;
	boolean_t notifydone;

	ASSERT(hfi != NULL);
	ASSERT(he != NULL);

	CVW_ENTER_WRITE(&hfi->hfi_lock);

	/*
	 * Set the flag so that we can call hook_event_notify_run without
	 * holding any locks but at the same time prevent other changes to
	 * the event at the same time.
	 */
	if (hook_wait_setflag(&hfi->hfi_waiter, FWF_DEL_WAIT_MASK,
	    FWF_DEL_WANTED, FWF_DEL_ACTIVE) == -1) {
		CVW_EXIT_WRITE(&hfi->hfi_lock);
		return (ENXIO);
	}

	hei = hook_event_find(hfi, he->he_name);
	if (hei == NULL) {
		hook_wait_unsetflag(&hfi->hfi_waiter, FWF_DEL_ACTIVE);
		CVW_EXIT_WRITE(&hfi->hfi_lock);
		return (ESRCH);
	}

	CVW_ENTER_WRITE(&hei->hei_lock);
	notifydone = hei->hei_shutdown;
	hei->hei_shutdown = B_TRUE;
	CVW_EXIT_WRITE(&hei->hei_lock);

	CVW_EXIT_WRITE(&hfi->hfi_lock);

	if (!notifydone)
		hook_notify_run(&hfi->hfi_nhead,
		    hfi->hfi_family.hf_name, NULL, he->he_name, HN_UNREGISTER);

	hook_wait_unsetflag(&hfi->hfi_waiter, FWF_DEL_ACTIVE);

	return (0);
}

/*
 * Function:	hook_event_free
 * Returns:	None
 * Parameters:	hei(I) - internal event pointer
 *
 * Free alloc memory for event
 */
static void
hook_event_free(hook_event_int_t *hei, hook_family_int_t *hfi)
{
	boolean_t free_family;

	ASSERT(hei != NULL);

	if (hfi != NULL) {
		CVW_ENTER_WRITE(&hfi->hfi_lock);
		/*
		 * Remove the event from the hook family's list.
		 */
		SLIST_REMOVE(&hfi->hfi_head, hei, hook_event_int, hei_entry);
		if (hfi->hfi_condemned && SLIST_EMPTY(&hfi->hfi_head) &&
		    TAILQ_EMPTY(&hfi->hfi_nhead)) {
			free_family = B_TRUE;
		} else {
			free_family = B_FALSE;
		}
		CVW_EXIT_WRITE(&hfi->hfi_lock);
	}

	if (hei->hei_kstatp != NULL) {
		ASSERT(hfi != NULL);

		kstat_delete_netstack(hei->hei_kstatp,
		    hfi->hfi_stack->hks_netstackid);
		hei->hei_kstatp = NULL;
	}

	/* Free container */
	kmem_free(hei, sizeof (*hei));

	if (free_family)
		hook_family_free(hfi, hfi->hfi_stack);
}

/*
 * Function:    hook_event_checkdup
 * Returns:     internal event pointer - NULL = Not match
 * Parameters:  he(I) - event pointer
 *
 * Search all of the hook families to see if the event being passed in
 * has already been associated with one.
 */
static hook_event_int_t *
hook_event_checkdup(hook_event_t *he, hook_stack_t *hks)
{
	hook_family_int_t *hfi;
	hook_event_int_t *hei;

	ASSERT(he != NULL);

	CVW_ENTER_READ(&hks->hks_lock);
	SLIST_FOREACH(hfi, &hks->hks_familylist, hfi_entry) {
		SLIST_FOREACH(hei, &hfi->hfi_head, hei_entry) {
			if (hei->hei_event == he) {
				CVW_EXIT_READ(&hks->hks_lock);
				return (hei);
			}
		}
	}
	CVW_EXIT_READ(&hks->hks_lock);

	return (NULL);
}

/*
 * Function:	hook_event_copy
 * Returns:	internal event pointer - NULL = Failed
 * Parameters:	src(I) - event pointer
 *
 * Allocate internal event block and duplicate incoming event
 * No locks should be held across this function as it may sleep.
 */
static hook_event_int_t *
hook_event_copy(hook_event_t *src)
{
	hook_event_int_t *new;

	ASSERT(src != NULL);
	ASSERT(src->he_name != NULL);

	new = (hook_event_int_t *)kmem_zalloc(sizeof (*new), KM_SLEEP);

	/* Copy body */
	TAILQ_INIT(&new->hei_head);
	new->hei_event = src;

	return (new);
}

/*
 * Function:	hook_event_find
 * Returns:	internal event pointer - NULL = Not match
 * Parameters:	hfi(I)   - internal family pointer
 *		event(I) - event name string
 *
 * Search event list with event name
 * 	A lock on hfi->hfi_lock must be held when called.
 */
static hook_event_int_t *
hook_event_find(hook_family_int_t *hfi, char *event)
{
	hook_event_int_t *hei = NULL;

	ASSERT(hfi != NULL);
	ASSERT(event != NULL);

	SLIST_FOREACH(hei, &hfi->hfi_head, hei_entry) {
		if ((strcmp(hei->hei_event->he_name, event) == 0) &&
		    ((hei->hei_waiter.fw_flags & FWF_UNSAFE) == 0))
			break;
	}
	return (hei);
}

/*
 * Function:	hook_event_notify_register
 * Returns:	int         - 0 = success, else failure
 * Parameters:	hfi(I)      - hook family
 *              event(I)    - name of the event
 *              callback(I) - function to be called
 *              arg(I)      - arg to provide callback when it is called
 *
 * Adds a new callback to the event named by "event" (we must find it)
 * that will be executed each time a new hook is added to the event.
 * Of course, if the stack is being shut down, this call should fail.
 */
int
hook_event_notify_register(hook_family_int_t *hfi, char *event,
    hook_notify_fn_t callback, void *arg)
{
	hook_event_int_t *hei;
	hook_stack_t *hks;
	boolean_t canrun;
	hook_int_t *h;
	int error;

	canrun = B_FALSE;
	hks = hfi->hfi_stack;
	CVW_ENTER_READ(&hks->hks_lock);
	if (hks->hks_shutdown != 0) {
		CVW_EXIT_READ(&hks->hks_lock);
		return (ESHUTDOWN);
	}

	CVW_ENTER_READ(&hfi->hfi_lock);

	if (hfi->hfi_condemned || hfi->hfi_shutdown) {
		CVW_EXIT_READ(&hfi->hfi_lock);
		CVW_EXIT_READ(&hks->hks_lock);
		return (ESHUTDOWN);
	}

	hei = hook_event_find(hfi, event);
	if (hei == NULL) {
		CVW_EXIT_READ(&hfi->hfi_lock);
		CVW_EXIT_READ(&hks->hks_lock);
		return (ESRCH);
	}

	if (hei->hei_condemned || hei->hei_shutdown) {
		CVW_EXIT_READ(&hfi->hfi_lock);
		CVW_EXIT_READ(&hks->hks_lock);
		return (ESHUTDOWN);
	}

	CVW_ENTER_WRITE(&hei->hei_lock);
	canrun = (hook_wait_setflag(&hei->hei_waiter, FWF_ADD_WAIT_MASK,
	    FWF_ADD_WANTED, FWF_ADD_ACTIVE) != -1);
	error = hook_notify_register(&hei->hei_nhead, callback, arg);
	CVW_EXIT_WRITE(&hei->hei_lock);

	CVW_EXIT_READ(&hfi->hfi_lock);
	CVW_EXIT_READ(&hks->hks_lock);

	if (error == 0 && canrun) {
		TAILQ_FOREACH(h, &hei->hei_head, hi_entry) {
			callback(HN_REGISTER, arg,
			    hfi->hfi_family.hf_name, hei->hei_event->he_name,
			    h->hi_hook.h_name);
		}
	}

	if (canrun)
		hook_wait_unsetflag(&hei->hei_waiter, FWF_ADD_ACTIVE);

	return (error);
}

/*
 * Function:	hook_event_notify_unregister
 * Returns:	int         - 0 = success, else failure
 * Parameters:	hfi(I)      - hook family
 *              event(I)    - name of the event
 *              callback(I) - function to be called
 *
 * Remove the given callback from the named event's list of functions
 * to call when a hook is added or removed.
 */
int
hook_event_notify_unregister(hook_family_int_t *hfi, char *event,
    hook_notify_fn_t callback)
{
	hook_event_int_t *hei;
	boolean_t free_event;
	boolean_t canrun;
	hook_int_t *h;
	void *arg;
	int error;

	canrun = B_FALSE;

	CVW_ENTER_READ(&hfi->hfi_lock);

	hei = hook_event_find(hfi, event);
	if (hei == NULL) {
		CVW_EXIT_READ(&hfi->hfi_lock);
		return (ESRCH);
	}

	CVW_ENTER_WRITE(&hei->hei_lock);

	(void) hook_wait_setflag(&hei->hei_waiter, FWF_DEL_WAIT_MASK,
	    FWF_DEL_WANTED, FWF_DEL_ACTIVE);

	error = hook_notify_unregister(&hei->hei_nhead, callback, &arg);

	hook_wait_unsetflag(&hei->hei_waiter, FWF_DEL_ACTIVE);

	/*
	 * hei_condemned has been set if someone tried to remove the
	 * event but couldn't because there were still things attached to
	 * it. Now that we've done a successful remove, if it is now empty
	 * then by all rights we should be free'ing it too.  Note that the
	 * expectation is that only the caller of hook_event_add will ever
	 * call hook_event_remove.
	 */
	if ((error == 0) && hei->hei_condemned &&
	    TAILQ_EMPTY(&hei->hei_head) && TAILQ_EMPTY(&hei->hei_nhead)) {
		free_event = B_TRUE;
	} else {
		free_event = B_FALSE;
	}

	if (error == 0 && !free_event) {
		canrun = (hook_wait_setflag(&hei->hei_waiter, FWF_ADD_WAIT_MASK,
		    FWF_ADD_WANTED, FWF_ADD_ACTIVE) != -1);
	}

	CVW_EXIT_WRITE(&hei->hei_lock);
	CVW_EXIT_READ(&hfi->hfi_lock);

	if (canrun) {
		TAILQ_FOREACH(h, &hei->hei_head, hi_entry) {
			callback(HN_UNREGISTER, arg,
			    hfi->hfi_family.hf_name, hei->hei_event->he_name,
			    h->hi_hook.h_name);
		}

		hook_wait_unsetflag(&hei->hei_waiter, FWF_ADD_ACTIVE);
	}

	if (free_event) {
		/*
		 * It is safe to pass in hfi here, without a lock, because
		 * our structure (hei) is still on one of its lists and thus
		 * it won't be able to disappear yet...
		 */
		hook_event_free(hei, hfi);
	}

	return (error);
}

/*
 * Function:	hook_event_notify_run
 * Returns:	None
 * Parameters:	nrun(I) - pointer to the list of callbacks to execute
 *              hfi(I)  - hook stack pointer to execute callbacks for
 *              name(I) - name of a hook family
 *              cmd(I)  - either HN_UNREGISTER or HN_REGISTER
 *
 * Execute all of the callbacks registered for this event.
 */
static void
hook_event_notify_run(hook_event_int_t *hei, hook_family_int_t *hfi,
    char *event, char *name, hook_notify_cmd_t cmd)
{

	hook_notify_run(&hei->hei_nhead, hfi->hfi_family.hf_name,
	    event, name, cmd);
}

/*
 * Function:	hook_register
 * Returns:	int      - 0 = success, else = failure
 * Parameters:	hfi(I)   - internal family pointer
 *		event(I) - event name string
 *		h(I)     - hook pointer
 *
 * Add new hook to hook list on the specified family and event.
 */
int
hook_register(hook_family_int_t *hfi, char *event, hook_t *h)
{
	hook_event_int_t *hei;
	hook_int_t *hi, *new;
	int error;

	ASSERT(hfi != NULL);
	ASSERT(event != NULL);
	ASSERT(h != NULL);

	if (hfi->hfi_stack->hks_shutdown)
		return (NULL);

	/* Alloc hook_int_t and copy hook */
	new = hook_copy(h);
	if (new == NULL)
		return (ENOMEM);

	/*
	 * Since hook add/remove only impact event, so it is unnecessary
	 * to hold global family write lock. Just get read lock here to
	 * ensure event will not be removed when doing hooks operation
	 */
	CVW_ENTER_WRITE(&hfi->hfi_lock);

	hei = hook_event_find(hfi, event);
	if (hei == NULL) {
		CVW_EXIT_WRITE(&hfi->hfi_lock);
		hook_int_free(new, hfi->hfi_stack->hks_netstackid);
		return (ENXIO);
	}

	CVW_ENTER_WRITE(&hei->hei_lock);

	/*
	 * If we've run either the remove() or shutdown(), do not allow any
	 * more hooks to be added to this event.
	 */
	if (hei->hei_shutdown) {
		error = ESHUTDOWN;
		goto bad_add;
	}

	hi = hook_find(hei, h);
	if (hi != NULL) {
		error = EEXIST;
		goto bad_add;
	}

	if (hook_wait_setflag(&hei->hei_waiter, FWF_ADD_WAIT_MASK,
	    FWF_ADD_WANTED, FWF_ADD_ACTIVE) == -1) {
		error = ENOENT;
bad_add:
		CVW_EXIT_WRITE(&hei->hei_lock);
		CVW_EXIT_WRITE(&hfi->hfi_lock);
		hook_int_free(new, hfi->hfi_stack->hks_netstackid);
		return (error);
	}

	/* Add to hook list head */
	error = hook_insert(&hei->hei_head, new);
	if (error == 0) {
		hei->hei_event->he_interested = B_TRUE;
		hei->hei_kstats.hooks_added.value.ui64++;

		hook_init_kstats(hfi, hei, new);
	}

	CVW_EXIT_WRITE(&hei->hei_lock);
	CVW_EXIT_WRITE(&hfi->hfi_lock);

	/*
	 * Note that the name string passed through to the notify callbacks
	 * is from the original hook being registered, not the copy being
	 * inserted.
	 */
	if (error == 0)
		hook_event_notify_run(hei, hfi, event, h->h_name, HN_REGISTER);

	hook_wait_unsetflag(&hei->hei_waiter, FWF_ADD_ACTIVE);

	return (error);
}

/*
 * Function:	hook_insert
 * Returns:	int     - 0 = success, else = failure
 * Parameters:	head(I) - pointer to hook list to insert hook onto
 *		new(I)  - pointer to hook to be inserted
 *
 * Try to insert the hook onto the list of hooks according to the hints
 * given in the hook to be inserted and those that already exist on the
 * list.  For now, the implementation permits only a single hook to be
 * either first or last and names provided with before or after are only
 * loosely coupled with the action.
 */
static int
hook_insert(hook_int_head_t *head, hook_int_t *new)
{
	hook_int_t *before;
	hook_int_t *hi;
	hook_t *hih;
	hook_t *h = &new->hi_hook;

	switch (new->hi_hook.h_hint) {
	case HH_NONE :
		before = NULL;
		/*
		 * If there is no hint present (or not one that can be
		 * satisfied now) then try to at least respect the wishes
		 * of those that want to be last.  If there are none wanting
		 * to be last then add the new hook to the tail of the
		 * list - this means we keep any wanting to be first
		 * happy without having to search for HH_FIRST.
		 */
		TAILQ_FOREACH(hi, head, hi_entry) {
			hih = &hi->hi_hook;
			if ((hih->h_hint == HH_AFTER) &&
			    (strcmp(h->h_name,
			    (char *)hih->h_hintvalue) == 0)) {
				TAILQ_INSERT_BEFORE(hi, new, hi_entry);
				return (0);
			}
			if ((hih->h_hint == HH_BEFORE) && (before == NULL) &&
			    (strcmp(h->h_name,
			    (char *)hih->h_hintvalue) == 0)) {
				before = hi;
			}
		}
		if (before != NULL) {
			TAILQ_INSERT_AFTER(head, before, new, hi_entry);
			return (0);
		}
		hook_insert_plain(head, new);
		break;

	case HH_FIRST :
		hi = TAILQ_FIRST(head);
		if ((hi != NULL) && (hi->hi_hook.h_hint == HH_FIRST))
			return (EBUSY);
		TAILQ_INSERT_HEAD(head, new, hi_entry);
		break;

	case HH_LAST :
		hi = TAILQ_LAST(head, hook_int_head);
		if ((hi != NULL) && (hi->hi_hook.h_hint == HH_LAST))
			return (EBUSY);
		TAILQ_INSERT_TAIL(head, new, hi_entry);
		break;

	case HH_BEFORE :
		hi = hook_find_byname(head, (char *)new->hi_hook.h_hintvalue);
		if (hi == NULL)
			return (hook_insert_afterbefore(head, new));

		if (hi->hi_hook.h_hint == HH_FIRST)
			return (EBUSY);

		TAILQ_INSERT_BEFORE(hi, new, hi_entry);
		break;

	case HH_AFTER :
		hi = hook_find_byname(head, (char *)new->hi_hook.h_hintvalue);
		if (hi == NULL)
			return (hook_insert_afterbefore(head, new));

		if (hi->hi_hook.h_hint == HH_LAST)
			return (EBUSY);

		TAILQ_INSERT_AFTER(head, hi, new, hi_entry);
		break;

	default :
		return (EINVAL);
	}

	return (0);
}

/*
 * Function:	hook_insert_plain
 * Returns:	int     - 0 = success, else = failure
 * Parameters:	head(I) - pointer to hook list to insert hook onto
 *		new(I)  - pointer to hook to be inserted
 *
 * Insert a hook such that it respects the wishes of those that want to
 * be last.  If there are none wanting to be last then add the new hook
 * to the tail of the list - this means we keep any wanting to be first
 * happy without having to search for HH_FIRST.
 */
static void
hook_insert_plain(hook_int_head_t *head, hook_int_t *new)
{
	hook_int_t *hi;

	hi = TAILQ_FIRST(head);
	if (hi != NULL) {
		if (hi->hi_hook.h_hint == HH_LAST) {
			TAILQ_INSERT_BEFORE(hi, new, hi_entry);
		} else {
			TAILQ_INSERT_TAIL(head, new, hi_entry);
		}
	} else {
		TAILQ_INSERT_TAIL(head, new, hi_entry);
	}
}

/*
 * Function:	hook_insert_afterbefore
 * Returns:	int     - 0 = success, else = failure
 * Parameters:	head(I) - pointer to hook list to insert hook onto
 *		new(I)  - pointer to hook to be inserted
 *
 * Simple insertion of a hook specifying a HH_BEFORE or HH_AFTER was not
 * possible, so now we need to be more careful.  The first pass is to go
 * through the list and look for any other hooks that also specify the
 * same hint name as the new one.  The object of this exercise is to make
 * sure that hooks with HH_BEFORE always appear on the list before those
 * with HH_AFTER so that when said hook arrives, it can be placed in the
 * middle of the BEFOREs and AFTERs.  If this condition does not arise,
 * just use hook_insert_plain() to try and insert the hook somewhere that
 * is innocuous to existing efforts.
 */
static int
hook_insert_afterbefore(hook_int_head_t *head, hook_int_t *new)
{
	hook_int_t *hi;
	hook_t *nh;
	hook_t *h;

	nh = &new->hi_hook;
	ASSERT(new->hi_hook.h_hint != HH_NONE);
	ASSERT(new->hi_hook.h_hint != HH_LAST);
	ASSERT(new->hi_hook.h_hint != HH_FIRST);

	/*
	 * First, look through the list to see if there are any other
	 * before's or after's that have a matching hint name.
	 */
	TAILQ_FOREACH(hi, head, hi_entry) {
		h = &hi->hi_hook;
		switch (h->h_hint) {
		case HH_FIRST :
		case HH_LAST :
		case HH_NONE :
			break;
		case HH_BEFORE :
			if ((nh->h_hint == HH_BEFORE) &&
			    (strcmp((char *)h->h_hintvalue,
			    (char *)nh->h_hintvalue) == 0)) {
				TAILQ_INSERT_AFTER(head, hi, new, hi_entry);
				return (0);
			}
			if ((nh->h_hint == HH_AFTER) &&
			    (strcmp((char *)h->h_hintvalue,
			    (char *)nh->h_hintvalue) == 0)) {
				TAILQ_INSERT_BEFORE(hi, new, hi_entry);
				return (0);
			}
			break;
		case HH_AFTER :
			if ((nh->h_hint == HH_AFTER) &&
			    (strcmp((char *)h->h_hintvalue,
			    (char *)nh->h_hintvalue) == 0)) {
				TAILQ_INSERT_AFTER(head, hi, new, hi_entry);
				return (0);
			}
			if ((nh->h_hint == HH_BEFORE) &&
			    (strcmp((char *)h->h_hintvalue,
			    (char *)nh->h_hintvalue) == 0)) {
				TAILQ_INSERT_BEFORE(hi, new, hi_entry);
				return (0);
			}
			break;
		}
	}

	hook_insert_plain(head, new);

	return (0);
}

/*
 * Function:	hook_unregister
 * Returns:	int      - 0 = success, else = failure
 * Parameters:	hfi(I)   - internal family pointer
 *		event(I) - event name string
 *		h(I)     - hook pointer
 *
 * Remove hook from hook list on specific family, event
 */
int
hook_unregister(hook_family_int_t *hfi, char *event, hook_t *h)
{
	hook_event_int_t *hei;
	hook_int_t *hi;
	boolean_t free_event;

	ASSERT(hfi != NULL);
	ASSERT(h != NULL);

	CVW_ENTER_WRITE(&hfi->hfi_lock);

	hei = hook_event_find(hfi, event);
	if (hei == NULL) {
		CVW_EXIT_WRITE(&hfi->hfi_lock);
		return (ENXIO);
	}

	/* Hold write lock for event */
	CVW_ENTER_WRITE(&hei->hei_lock);

	hi = hook_find(hei, h);
	if (hi == NULL) {
		CVW_EXIT_WRITE(&hei->hei_lock);
		CVW_EXIT_WRITE(&hfi->hfi_lock);
		return (ENXIO);
	}

	if (hook_wait_setflag(&hei->hei_waiter, FWF_DEL_WAIT_MASK,
	    FWF_DEL_WANTED, FWF_DEL_ACTIVE) == -1) {
		CVW_EXIT_WRITE(&hei->hei_lock);
		CVW_EXIT_WRITE(&hfi->hfi_lock);
		return (ENOENT);
	}

	/* Remove from hook list */
	TAILQ_REMOVE(&hei->hei_head, hi, hi_entry);

	free_event = B_FALSE;
	if (TAILQ_EMPTY(&hei->hei_head)) {
		hei->hei_event->he_interested = B_FALSE;
		/*
		 * If the delete pending flag has been set and there are
		 * no notifiers on the event (and we've removed the last
		 * hook) then we need to free this event after we're done.
		 */
		if (hei->hei_condemned && TAILQ_EMPTY(&hei->hei_nhead))
			free_event = B_TRUE;
	}
	hei->hei_kstats.hooks_removed.value.ui64++;

	CVW_EXIT_WRITE(&hei->hei_lock);
	CVW_EXIT_WRITE(&hfi->hfi_lock);
	/*
	 * While the FWF_DEL_ACTIVE flag is set, the hook_event_int_t
	 * will not be free'd and thus the hook_family_int_t wil not
	 * be free'd either.
	 */
	hook_event_notify_run(hei, hfi, event, h->h_name, HN_UNREGISTER);
	hook_wait_unsetflag(&hei->hei_waiter, FWF_DEL_ACTIVE);

	hook_int_free(hi, hfi->hfi_stack->hks_netstackid);

	if (free_event)
		hook_event_free(hei, hfi);

	return (0);
}

/*
 * Function:	hook_find_byname
 * Returns:	internal hook pointer - NULL = Not match
 * Parameters:	hei(I) - internal event pointer
 *		name(I)- hook name
 *
 * Search an event's list of hooks to see if there is a hook present that
 * has a matching name to the one being looked for.
 */
static hook_int_t *
hook_find_byname(hook_int_head_t *head, char *name)
{
	hook_int_t *hi;

	TAILQ_FOREACH(hi, head, hi_entry) {
		if (strcmp(hi->hi_hook.h_name, name) == 0)
			return (hi);
	}

	return (NULL);
}

/*
 * Function:	hook_find
 * Returns:	internal hook pointer - NULL = Not match
 * Parameters:	hei(I) - internal event pointer
 *		h(I)   - hook pointer
 *
 * Search an event's list of hooks to see if there is already one that
 * matches the hook being passed in.  Currently the only criteria for a
 * successful search here is for the names to be the same.
 */
static hook_int_t *
hook_find(hook_event_int_t *hei, hook_t *h)
{

	ASSERT(hei != NULL);
	ASSERT(h != NULL);

	return (hook_find_byname(&hei->hei_head, h->h_name));
}

/*
 * Function:	hook_copy
 * Returns:	internal hook pointer - NULL = Failed
 * Parameters:	src(I) - hook pointer
 *
 * Allocate internal hook block and duplicate incoming hook.
 * No locks should be held across this function as it may sleep.
 * Because hook_copy() is responsible for the creation of the internal
 * hook structure that is used here, it takes on population the structure
 * with the kstat information.  Note that while the kstat bits are
 * seeded here, their installation of the kstats is handled elsewhere.
 */
static hook_int_t *
hook_copy(hook_t *src)
{
	hook_int_t *new;
	hook_t *dst;
	int len;

	ASSERT(src != NULL);
	ASSERT(src->h_name != NULL);

	new = (hook_int_t *)kmem_zalloc(sizeof (*new), KM_SLEEP);

	/* Copy body */
	dst = &new->hi_hook;
	*dst = *src;

	/* Copy name */
	len = strlen(src->h_name);
	dst->h_name = (char *)kmem_alloc(len + 1, KM_SLEEP);
	(void) strcpy(dst->h_name, src->h_name);

	/*
	 * This is initialised in this manner to make it safer to use the
	 * same pointer in the kstats field.
	 */
	dst->h_hintvalue = (uintptr_t)"";

	if (dst->h_hint == HH_BEFORE || dst->h_hint == HH_AFTER) {
		len = strlen((char *)src->h_hintvalue);
		if (len > 0) {
			dst->h_hintvalue = (uintptr_t)kmem_alloc(len + 1,
			    KM_SLEEP);
			(void) strcpy((char *)dst->h_hintvalue,
			    (char *)src->h_hintvalue);
		}
	}

	return (new);
}

/*
 * Function:	hook_init_kstats
 * Returns:	None
 * Parameters:  hfi(I) - pointer to the family that owns the event.
 *              hei(I) - pointer to the event that owns this hook
 *              hi(I)  - pointer to the hook for which we create kstats for
 *
 * Each hook that is registered with this framework has its own kstats
 * set up so that we can provide an easy way in which to observe the
 * look of hooks (using the kstat command.) The position is set to 0
 * here but is recalculated after we know the insertion has been a
 * success.
 */
static void
hook_init_kstats(hook_family_int_t *hfi, hook_event_int_t *hei, hook_int_t *hi)
{
	hook_hook_kstat_t template = {
		{ "version",			KSTAT_DATA_INT32 },
		{ "flags",			KSTAT_DATA_UINT32 },
		{ "hint",			KSTAT_DATA_INT32 },
		{ "hint_value",			KSTAT_DATA_STRING },
		{ "position",			KSTAT_DATA_INT32 },
		{ "hook_hits",			KSTAT_DATA_UINT64 }
	};
	hook_stack_t *hks;
	size_t kslen;
	int position;
	hook_int_t *h;

	kslen = strlen(hfi->hfi_family.hf_name) +
	    strlen(hei->hei_event->he_name) + 2;

	hi->hi_ksname = (char *)kmem_zalloc(kslen, KM_SLEEP);
	(void) snprintf(hi->hi_ksname, kslen, "%s/%s",
	    hfi->hfi_family.hf_name, hei->hei_event->he_name);

	hks = hfi->hfi_stack;
	hi->hi_kstatp = kstat_create_netstack(hi->hi_ksname, 0,
	    hi->hi_hook.h_name, "hook", KSTAT_TYPE_NAMED,
	    sizeof (hi->hi_kstats) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL, hks->hks_netstackid);

	/* Initialise the kstats for the structure */
	bcopy(&template, &hi->hi_kstats, sizeof (template));
	hi->hi_kstats.hook_version.value.i32 = hi->hi_hook.h_version;
	hi->hi_kstats.hook_flags.value.ui32 = hi->hi_hook.h_flags;
	hi->hi_kstats.hook_hint.value.i32 = hi->hi_hook.h_hint;
	hi->hi_kstats.hook_position.value.i32 = 0;
	hi->hi_kstats.hook_hits.value.ui64 = 0;

	switch (hi->hi_hook.h_hint) {
	case HH_BEFORE :
	case HH_AFTER :
		kstat_named_setstr(&(hi->hi_kstats.hook_hintvalue),
		    (const char *)hi->hi_hook.h_hintvalue);
		break;
	default :
		kstat_named_setstr(&(hi->hi_kstats.hook_hintvalue),
		    hook_hintvalue_none);
		break;
	}

	if (hi->hi_kstatp != NULL) {
		hi->hi_kstatp->ks_data = (void *)&hi->hi_kstats;
		hi->hi_kstatp->ks_private =
		    (void *)(uintptr_t)hks->hks_netstackid;
		hi->hi_kstatp->ks_data_size +=
		    KSTAT_NAMED_STR_BUFLEN(&(hi->hi_kstats.hook_hintvalue)) + 1;

		kstat_install(hi->hi_kstatp);
	}

	position = 1;
	TAILQ_FOREACH(h, &hei->hei_head, hi_entry) {
		h->hi_kstats.hook_position.value.ui32 = position++;
	}
}

/*
 * Function:	hook_int_free
 * Returns:	None
 * Parameters:	hi(I) - internal hook pointer
 *
 * Free memory allocated to support a hook.
 */
static void
hook_int_free(hook_int_t *hi, netstackid_t stackid)
{
	int len;

	ASSERT(hi != NULL);

	/* Free name space */
	if (hi->hi_hook.h_name != NULL) {
		kmem_free(hi->hi_hook.h_name, strlen(hi->hi_hook.h_name) + 1);
	}
	if (hi->hi_ksname != NULL) {
		kmem_free(hi->hi_ksname, strlen(hi->hi_ksname) + 1);
	}

	/* Free the name used with the before/after hints. */
	switch (hi->hi_hook.h_hint) {
	case HH_BEFORE :
	case HH_AFTER :
		len = strlen((char *)hi->hi_hook.h_hintvalue);
		if (len > 0)
			kmem_free((void *)hi->hi_hook.h_hintvalue, len + 1);
		break;
	default :
		break;
	}

	if (hi->hi_kstatp != NULL)
		kstat_delete_netstack(hi->hi_kstatp, stackid);

	/* Free container */
	kmem_free(hi, sizeof (*hi));
}

/*
 * Function:	hook_alloc
 * Returns:	hook_t *   - pointer to new hook structure
 * Parameters:	version(I) - version number of the API when compiled
 *
 * This function serves as the interface for consumers to obtain a hook_t
 * structure.  At this point in time, there is only a single "version" of
 * it, leading to a straight forward function.  In a perfect world the
 * h_vesion would be a protected data structure member, but C isn't that
 * advanced...
 */
hook_t *
hook_alloc(const int h_version)
{
	hook_t *h;

	h = kmem_zalloc(sizeof (hook_t), KM_SLEEP);
	h->h_version = h_version;
	return (h);
}

/*
 * Function:	hook_free
 * Returns:	None
 * Parameters:	h(I) - external hook pointer
 *
 * This function only free's memory allocated with hook_alloc(), so that if
 * (for example) kernel memory was allocated for h_name, this needs to be
 * free'd before calling hook_free().
 */
void
hook_free(hook_t *h)
{
	kmem_free(h, sizeof (*h));
}

/*
 * Function:	hook_notify_register
 * Returns:	int         - 0 = success, else failure
 * Parameters:	head(I)     - top of the list of callbacks
 *              callback(I) - function to be called
 *              arg(I)      - arg to pass back to the function
 *
 * This function implements the modification of the list of callbacks
 * that are registered when someone wants to be advised of a change
 * that has happened.
 */
static int
hook_notify_register(hook_notify_head_t *head, hook_notify_fn_t callback,
    void *arg)
{
	hook_notify_t *hn;

	TAILQ_FOREACH(hn, head, hn_entry) {
		if (hn->hn_func == callback) {
			return (EEXIST);
		}
	}

	hn = (hook_notify_t *)kmem_alloc(sizeof (*hn), KM_SLEEP);
	hn->hn_func = callback;
	hn->hn_arg = arg;
	TAILQ_INSERT_TAIL(head, hn, hn_entry);

	return (0);
}

/*
 * Function:	hook_notify_unregister
 * Returns:	int         - 0 = success, else failure
 * Parameters:	stackid(I)  - netstack identifier
 *              callback(I) - function to be called
 *              parg(O)     - pointer to storage for pointer
 *
 * When calling this function, the provision of a valid pointer in parg
 * allows the caller to be made aware of what argument the hook function
 * was expecting. This then allows the simulation of HN_UNREGISTER events
 * when a notify-unregister is performed.
 */
static int
hook_notify_unregister(hook_notify_head_t *head,
    hook_notify_fn_t callback, void **parg)
{
	hook_notify_t *hn;

	ASSERT(parg != NULL);

	TAILQ_FOREACH(hn, head, hn_entry) {
		if (hn->hn_func == callback)
			break;
	}

	if (hn == NULL)
		return (ESRCH);

	*parg = hn->hn_arg;

	TAILQ_REMOVE(head, hn, hn_entry);

	kmem_free(hn, sizeof (*hn));

	return (0);
}

/*
 * Function:	hook_notify_run
 * Returns:	None
 * Parameters:	head(I)   - top of the list of callbacks
 *              family(I) - name of the hook family that owns the event
 *              event(I)  - name of the event being changed
 *              name(I)   - name of the object causing change
 *              cmd(I)    - either HN_UNREGISTER or HN_REGISTER
 *
 * This function walks through the list of registered callbacks and
 * executes each one, passing back the arg supplied when registered
 * and the name of the family (that owns the event), event (the thing
 * to which we're making a change) and finally a name that describes
 * what is being added or removed, as indicated by cmd.
 *
 * This function does not acquire or release any lock as it is required
 * that code calling it do so before hand.  The use of hook_notify_head_t
 * is protected by the use of flagwait_t in the structures that own this
 * list and with the use of the FWF_ADD/DEL_ACTIVE flags.
 */
static void
hook_notify_run(hook_notify_head_t *head, char *family, char *event,
    char *name, hook_notify_cmd_t cmd)
{
	hook_notify_t *hn;

	TAILQ_FOREACH(hn, head, hn_entry) {
		(*hn->hn_func)(cmd, hn->hn_arg, family, event, name);
	}
}
