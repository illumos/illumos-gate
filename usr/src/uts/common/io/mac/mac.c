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

/*
 * MAC Services Module
 *
 * The GLDv3 framework locking -  The MAC layer
 * --------------------------------------------
 *
 * The MAC layer is central to the GLD framework and can provide the locking
 * framework needed for itself and for the use of MAC clients. MAC end points
 * are fairly disjoint and don't share a lot of state. So a coarse grained
 * multi-threading scheme is to single thread all create/modify/delete or set
 * type of control operations on a per mac end point while allowing data threads
 * concurrently.
 *
 * Control operations (set) that modify a mac end point are always serialized on
 * a per mac end point basis, We have at most 1 such thread per mac end point
 * at a time.
 *
 * All other operations that are not serialized are essentially multi-threaded.
 * For example a control operation (get) like getting statistics which may not
 * care about reading values atomically or data threads sending or receiving
 * data. Mostly these type of operations don't modify the control state. Any
 * state these operations care about are protected using traditional locks.
 *
 * The perimeter only serializes serial operations. It does not imply there
 * aren't any other concurrent operations. However a serialized operation may
 * sometimes need to make sure it is the only thread. In this case it needs
 * to use reference counting mechanisms to cv_wait until any current data
 * threads are done.
 *
 * The mac layer itself does not hold any locks across a call to another layer.
 * The perimeter is however held across a down call to the driver to make the
 * whole control operation atomic with respect to other control operations.
 * Also the data path and get type control operations may proceed concurrently.
 * These operations synchronize with the single serial operation on a given mac
 * end point using regular locks. The perimeter ensures that conflicting
 * operations like say a mac_multicast_add and a mac_multicast_remove on the
 * same mac end point don't interfere with each other and also ensures that the
 * changes in the mac layer and the call to the underlying driver to say add a
 * multicast address are done atomically without interference from a thread
 * trying to delete the same address.
 *
 * For example, consider
 * mac_multicst_add()
 * {
 *	mac_perimeter_enter();	serialize all control operations
 *
 *	grab list lock		protect against access by data threads
 *	add to list
 *	drop list lock
 *
 *	call driver's mi_multicst
 *
 *	mac_perimeter_exit();
 * }
 *
 * To lessen the number of serialization locks and simplify the lock hierarchy,
 * we serialize all the control operations on a per mac end point by using a
 * single serialization lock called the perimeter. We allow recursive entry into
 * the perimeter to facilitate use of this mechanism by both the mac client and
 * the MAC layer itself.
 *
 * MAC client means an entity that does an operation on a mac handle
 * obtained from a mac_open/mac_client_open. Similarly MAC driver means
 * an entity that does an operation on a mac handle obtained from a
 * mac_register. An entity could be both client and driver but on different
 * handles eg. aggr. and should only make the corresponding mac interface calls
 * i.e. mac driver interface or mac client interface as appropriate for that
 * mac handle.
 *
 * General rules.
 * -------------
 *
 * R1. The lock order of upcall threads is natually opposite to downcall
 * threads. Hence upcalls must not hold any locks across layers for fear of
 * recursive lock enter and lock order violation. This applies to all layers.
 *
 * R2. The perimeter is just another lock. Since it is held in the down
 * direction, acquiring the perimeter in an upcall is prohibited as it would
 * cause a deadlock. This applies to all layers.
 *
 * Note that upcalls that need to grab the mac perimeter (for example
 * mac_notify upcalls) can still achieve that by posting the request to a
 * thread, which can then grab all the required perimeters and locks in the
 * right global order. Note that in the above example the mac layer iself
 * won't grab the mac perimeter in the mac_notify upcall, instead the upcall
 * to the client must do that. Please see the aggr code for an example.
 *
 * MAC client rules
 * ----------------
 *
 * R3. A MAC client may use the MAC provided perimeter facility to serialize
 * control operations on a per mac end point. It does this by by acquring
 * and holding the perimeter across a sequence of calls to the mac layer.
 * This ensures atomicity across the entire block of mac calls. In this
 * model the MAC client must not hold any client locks across the calls to
 * the mac layer. This model is the preferred solution.
 *
 * R4. However if a MAC client has a lot of global state across all mac end
 * points the per mac end point serialization may not be sufficient. In this
 * case the client may choose to use global locks or use its own serialization.
 * To avoid deadlocks, these client layer locks held across the mac calls
 * in the control path must never be acquired by the data path for the reason
 * mentioned below.
 *
 * (Assume that a control operation that holds a client lock blocks in the
 * mac layer waiting for upcall reference counts to drop to zero. If an upcall
 * data thread that holds this reference count, tries to acquire the same
 * client lock subsequently it will deadlock).
 *
 * A MAC client may follow either the R3 model or the R4 model, but can't
 * mix both. In the former, the hierarchy is Perim -> client locks, but in
 * the latter it is client locks -> Perim.
 *
 * R5. MAC clients must make MAC calls (excluding data calls) in a cv_wait'able
 * context since they may block while trying to acquire the perimeter.
 * In addition some calls may block waiting for upcall refcnts to come down to
 * zero.
 *
 * R6. MAC clients must make sure that they are single threaded and all threads
 * from the top (in particular data threads) have finished before calling
 * mac_client_close. The MAC framework does not track the number of client
 * threads using the mac client handle. Also mac clients must make sure
 * they have undone all the control operations before calling mac_client_close.
 * For example mac_unicast_remove/mac_multicast_remove to undo the corresponding
 * mac_unicast_add/mac_multicast_add.
 *
 * MAC framework rules
 * -------------------
 *
 * R7. The mac layer itself must not hold any mac layer locks (except the mac
 * perimeter) across a call to any other layer from the mac layer. The call to
 * any other layer could be via mi_* entry points, classifier entry points into
 * the driver or via upcall pointers into layers above. The mac perimeter may
 * be acquired or held only in the down direction, for e.g. when calling into
 * a mi_* driver enty point to provide atomicity of the operation.
 *
 * R8. Since it is not guaranteed (see R14) that drivers won't hold locks across
 * mac driver interfaces, the MAC layer must provide a cut out for control
 * interfaces like upcall notifications and start them in a separate thread.
 *
 * R9. Note that locking order also implies a plumbing order. For example
 * VNICs are allowed to be created over aggrs, but not vice-versa. An attempt
 * to plumb in any other order must be failed at mac_open time, otherwise it
 * could lead to deadlocks due to inverse locking order.
 *
 * R10. MAC driver interfaces must not block since the driver could call them
 * in interrupt context.
 *
 * R11. Walkers must preferably not hold any locks while calling walker
 * callbacks. Instead these can operate on reference counts. In simple
 * callbacks it may be ok to hold a lock and call the callbacks, but this is
 * harder to maintain in the general case of arbitrary callbacks.
 *
 * R12. The MAC layer must protect upcall notification callbacks using reference
 * counts rather than holding locks across the callbacks.
 *
 * R13. Given the variety of drivers, it is preferable if the MAC layer can make
 * sure that any pointers (such as mac ring pointers) it passes to the driver
 * remain valid until mac unregister time. Currently the mac layer achieves
 * this by using generation numbers for rings and freeing the mac rings only
 * at unregister time.  The MAC layer must provide a layer of indirection and
 * must not expose underlying driver rings or driver data structures/pointers
 * directly to MAC clients.
 *
 * MAC driver rules
 * ----------------
 *
 * R14. It would be preferable if MAC drivers don't hold any locks across any
 * mac call. However at a minimum they must not hold any locks across data
 * upcalls. They must also make sure that all references to mac data structures
 * are cleaned up and that it is single threaded at mac_unregister time.
 *
 * R15. MAC driver interfaces don't block and so the action may be done
 * asynchronously in a separate thread as for example handling notifications.
 * The driver must not assume that the action is complete when the call
 * returns.
 *
 * R16. Drivers must maintain a generation number per Rx ring, and pass it
 * back to mac_rx_ring(); They are expected to increment the generation
 * number whenever the ring's stop routine is invoked.
 * See comments in mac_rx_ring();
 *
 * R17 Similarly mi_stop is another synchronization point and the driver must
 * ensure that all upcalls are done and there won't be any future upcall
 * before returning from mi_stop.
 *
 * R18. The driver may assume that all set/modify control operations via
 * the mi_* entry points are single threaded on a per mac end point.
 *
 * Lock and Perimeter hierarchy scenarios
 * ---------------------------------------
 *
 * i_mac_impl_lock -> mi_rw_lock -> srs_lock -> s_ring_lock[i_mac_tx_srs_notify]
 *
 * ft_lock -> fe_lock [mac_flow_lookup]
 *
 * mi_rw_lock -> fe_lock [mac_bcast_send]
 *
 * srs_lock -> mac_bw_lock [mac_rx_srs_drain_bw]
 *
 * cpu_lock -> mac_srs_g_lock -> srs_lock -> s_ring_lock [mac_walk_srs_and_bind]
 *
 * i_dls_devnet_lock -> mac layer locks [dls_devnet_rename]
 *
 * Perimeters are ordered P1 -> P2 -> P3 from top to bottom in order of mac
 * client to driver. In the case of clients that explictly use the mac provided
 * perimeter mechanism for its serialization, the hierarchy is
 * Perimeter -> mac layer locks, since the client never holds any locks across
 * the mac calls. In the case of clients that use its own locks the hierarchy
 * is Client locks -> Mac Perim -> Mac layer locks. The client never explicitly
 * calls mac_perim_enter/exit in this case.
 *
 * Subflow creation rules
 * ---------------------------
 * o In case of a user specified cpulist present on underlying link and flows,
 * the flows cpulist must be a subset of the underlying link.
 * o In case of a user specified fanout mode present on link and flow, the
 * subflow fanout count has to be less than or equal to that of the
 * underlying link. The cpu-bindings for the subflows will be a subset of
 * the underlying link.
 * o In case if no cpulist specified on both underlying link and flow, the
 * underlying link relies on a  MAC tunable to provide out of box fanout.
 * The subflow will have no cpulist (the subflow will be unbound)
 * o In case if no cpulist is specified on the underlying link, a subflow can
 * carry  either a user-specified cpulist or fanout count. The cpu-bindings
 * for the subflow will not adhere to restriction that they need to be subset
 * of the underlying link.
 * o In case where the underlying link is carrying either a user specified
 * cpulist or fanout mode and for a unspecified subflow, the subflow will be
 * created unbound.
 * o While creating unbound subflows, bandwidth mode changes attempt to
 * figure a right fanout count. In such cases the fanout count will override
 * the unbound cpu-binding behavior.
 * o In addition to this, while cycling between flow and link properties, we
 * impose a restriction that if a link property has a subflow with
 * user-specified attributes, we will not allow changing the link property.
 * The administrator needs to reset all the user specified properties for the
 * subflows before attempting a link property change.
 * Some of the above rules can be overridden by specifying additional command
 * line options while creating or modifying link or subflow properties.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/id_space.h>
#include <sys/esunddi.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/dlpi.h>
#include <sys/modhash.h>
#include <sys/mac_provider.h>
#include <sys/mac_client_impl.h>
#include <sys/mac_soft_ring.h>
#include <sys/mac_impl.h>
#include <sys/mac.h>
#include <sys/dls.h>
#include <sys/dld.h>
#include <sys/modctl.h>
#include <sys/fs/dv_node.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/callb.h>
#include <sys/cpuvar.h>
#include <sys/atomic.h>
#include <sys/bitmap.h>
#include <sys/sdt.h>
#include <sys/mac_flow.h>
#include <sys/ddi_intr_impl.h>
#include <sys/disp.h>
#include <sys/sdt.h>
#include <sys/vnic.h>
#include <sys/vnic_impl.h>
#include <sys/vlan.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <sys/exacct.h>
#include <sys/exacct_impl.h>
#include <inet/nd.h>
#include <sys/ethernet.h>

#define	IMPL_HASHSZ	67	/* prime */

kmem_cache_t	*i_mac_impl_cachep;
mod_hash_t		*i_mac_impl_hash;
krwlock_t		i_mac_impl_lock;
uint_t			i_mac_impl_count;
static kmem_cache_t	*mac_ring_cache;
static id_space_t	*minor_ids;
static uint32_t		minor_count;

/*
 * Logging stuff. Perhaps mac_logging_interval could be broken into
 * mac_flow_log_interval and mac_link_log_interval if we want to be
 * able to schedule them differently.
 */
uint_t			mac_logging_interval;
boolean_t		mac_flow_log_enable;
boolean_t		mac_link_log_enable;
timeout_id_t		mac_logging_timer;

/* for debugging, see MAC_DBG_PRT() in mac_impl.h */
int mac_dbg = 0;

#define	MACTYPE_KMODDIR	"mac"
#define	MACTYPE_HASHSZ	67
static mod_hash_t	*i_mactype_hash;
/*
 * i_mactype_lock synchronizes threads that obtain references to mactype_t
 * structures through i_mactype_getplugin().
 */
static kmutex_t		i_mactype_lock;

/*
 * mac_tx_percpu_cnt
 *
 * Number of per cpu locks per mac_client_impl_t. Used by the transmit side
 * in mac_tx to reduce lock contention. This is sized at boot time in mac_init.
 * mac_tx_percpu_cnt_max is settable in /etc/system and must be a power of 2.
 * Per cpu locks may be disabled by setting mac_tx_percpu_cnt_max to 1.
 */
int mac_tx_percpu_cnt;
int mac_tx_percpu_cnt_max = 128;

static int i_mac_constructor(void *, void *, int);
static void i_mac_destructor(void *, void *);
static int i_mac_ring_ctor(void *, void *, int);
static void i_mac_ring_dtor(void *, void *);
static mblk_t *mac_rx_classify(mac_impl_t *, mac_resource_handle_t, mblk_t *);
void mac_tx_client_flush(mac_client_impl_t *);
void mac_tx_client_block(mac_client_impl_t *);
static void mac_rx_ring_quiesce(mac_ring_t *, uint_t);
static int mac_start_group_and_rings(mac_group_t *);
static void mac_stop_group_and_rings(mac_group_t *);

/*
 * Module initialization functions.
 */

void
mac_init(void)
{
	mac_tx_percpu_cnt = ((boot_max_ncpus == -1) ? max_ncpus :
	    boot_max_ncpus);

	/* Upper bound is mac_tx_percpu_cnt_max */
	if (mac_tx_percpu_cnt > mac_tx_percpu_cnt_max)
		mac_tx_percpu_cnt = mac_tx_percpu_cnt_max;

	if (mac_tx_percpu_cnt < 1) {
		/* Someone set max_tx_percpu_cnt_max to 0 or less */
		mac_tx_percpu_cnt = 1;
	}

	ASSERT(mac_tx_percpu_cnt >= 1);
	mac_tx_percpu_cnt = (1 << highbit(mac_tx_percpu_cnt - 1));
	/*
	 * Make it of the form 2**N - 1 in the range
	 * [0 .. mac_tx_percpu_cnt_max - 1]
	 */
	mac_tx_percpu_cnt--;

	i_mac_impl_cachep = kmem_cache_create("mac_impl_cache",
	    sizeof (mac_impl_t), 0, i_mac_constructor, i_mac_destructor,
	    NULL, NULL, NULL, 0);
	ASSERT(i_mac_impl_cachep != NULL);

	mac_ring_cache = kmem_cache_create("mac_ring_cache",
	    sizeof (mac_ring_t), 0, i_mac_ring_ctor, i_mac_ring_dtor, NULL,
	    NULL, NULL, 0);
	ASSERT(mac_ring_cache != NULL);

	i_mac_impl_hash = mod_hash_create_extended("mac_impl_hash",
	    IMPL_HASHSZ, mod_hash_null_keydtor, mod_hash_null_valdtor,
	    mod_hash_bystr, NULL, mod_hash_strkey_cmp, KM_SLEEP);
	rw_init(&i_mac_impl_lock, NULL, RW_DEFAULT, NULL);

	mac_flow_init();
	mac_soft_ring_init();
	mac_bcast_init();
	mac_client_init();

	i_mac_impl_count = 0;

	i_mactype_hash = mod_hash_create_extended("mactype_hash",
	    MACTYPE_HASHSZ,
	    mod_hash_null_keydtor, mod_hash_null_valdtor,
	    mod_hash_bystr, NULL, mod_hash_strkey_cmp, KM_SLEEP);

	/*
	 * Allocate an id space to manage minor numbers. The range of the
	 * space will be from MAC_MAX_MINOR+1 to MAXMIN32 (maximum legal
	 * minor number is MAXMIN, but id_t is type of integer and does not
	 * allow MAXMIN).
	 */
	minor_ids = id_space_create("mac_minor_ids", MAC_MAX_MINOR+1, MAXMIN32);
	ASSERT(minor_ids != NULL);
	minor_count = 0;

	/* Let's default to 20 seconds */
	mac_logging_interval = 20;
	mac_flow_log_enable = B_FALSE;
	mac_link_log_enable = B_FALSE;
	mac_logging_timer = 0;
}

int
mac_fini(void)
{
	if (i_mac_impl_count > 0 || minor_count > 0)
		return (EBUSY);

	id_space_destroy(minor_ids);
	mac_flow_fini();

	mod_hash_destroy_hash(i_mac_impl_hash);
	rw_destroy(&i_mac_impl_lock);

	mac_client_fini();
	kmem_cache_destroy(mac_ring_cache);

	mod_hash_destroy_hash(i_mactype_hash);
	mac_soft_ring_finish();
	return (0);
}

void
mac_init_ops(struct dev_ops *ops, const char *name)
{
	dld_init_ops(ops, name);
}

void
mac_fini_ops(struct dev_ops *ops)
{
	dld_fini_ops(ops);
}

/*ARGSUSED*/
static int
i_mac_constructor(void *buf, void *arg, int kmflag)
{
	mac_impl_t	*mip = buf;

	bzero(buf, sizeof (mac_impl_t));

	mip->mi_linkstate = LINK_STATE_UNKNOWN;
	mip->mi_nclients = 0;

	mutex_init(&mip->mi_lock, NULL, MUTEX_DRIVER, NULL);
	rw_init(&mip->mi_rw_lock, NULL, RW_DRIVER, NULL);
	mutex_init(&mip->mi_notify_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&mip->mi_promisc_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&mip->mi_ring_lock, NULL, MUTEX_DEFAULT, NULL);

	mip->mi_notify_cb_info.mcbi_lockp = &mip->mi_notify_lock;
	cv_init(&mip->mi_notify_cb_info.mcbi_cv, NULL, CV_DRIVER, NULL);
	mip->mi_promisc_cb_info.mcbi_lockp = &mip->mi_promisc_lock;
	cv_init(&mip->mi_promisc_cb_info.mcbi_cv, NULL, CV_DRIVER, NULL);
	return (0);
}

/*ARGSUSED*/
static void
i_mac_destructor(void *buf, void *arg)
{
	mac_impl_t	*mip = buf;
	mac_cb_info_t	*mcbi;

	ASSERT(mip->mi_ref == 0);
	ASSERT(mip->mi_active == 0);
	ASSERT(mip->mi_linkstate == LINK_STATE_UNKNOWN);
	ASSERT(mip->mi_devpromisc == 0);
	ASSERT(mip->mi_promisc == 0);
	ASSERT(mip->mi_ksp == NULL);
	ASSERT(mip->mi_kstat_count == 0);
	ASSERT(mip->mi_nclients == 0);
	ASSERT(mip->mi_nactiveclients == 0);
	ASSERT(mip->mi_state_flags == 0);
	ASSERT(mip->mi_factory_addr == NULL);
	ASSERT(mip->mi_factory_addr_num == 0);
	ASSERT(mip->mi_default_tx_ring == NULL);

	mcbi = &mip->mi_notify_cb_info;
	ASSERT(mcbi->mcbi_del_cnt == 0 && mcbi->mcbi_walker_cnt == 0);
	ASSERT(mip->mi_notify_bits == 0);
	ASSERT(mip->mi_notify_thread == NULL);
	ASSERT(mcbi->mcbi_lockp == &mip->mi_notify_lock);
	mcbi->mcbi_lockp = NULL;

	mcbi = &mip->mi_promisc_cb_info;
	ASSERT(mcbi->mcbi_del_cnt == 0 && mip->mi_promisc_list == NULL);
	ASSERT(mip->mi_promisc_list == NULL);
	ASSERT(mcbi->mcbi_lockp == &mip->mi_promisc_lock);
	mcbi->mcbi_lockp = NULL;

	ASSERT(mip->mi_bcast_ngrps == 0 && mip->mi_bcast_grp == NULL);
	ASSERT(mip->mi_perim_owner == NULL && mip->mi_perim_ocnt == 0);

	mutex_destroy(&mip->mi_lock);
	rw_destroy(&mip->mi_rw_lock);

	mutex_destroy(&mip->mi_promisc_lock);
	cv_destroy(&mip->mi_promisc_cb_info.mcbi_cv);
	mutex_destroy(&mip->mi_notify_lock);
	cv_destroy(&mip->mi_notify_cb_info.mcbi_cv);
	mutex_destroy(&mip->mi_ring_lock);
}

/* ARGSUSED */
static int
i_mac_ring_ctor(void *buf, void *arg, int kmflag)
{
	mac_ring_t *ring = (mac_ring_t *)buf;

	bzero(ring, sizeof (mac_ring_t));
	cv_init(&ring->mr_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&ring->mr_lock, NULL, MUTEX_DEFAULT, NULL);
	ring->mr_state = MR_FREE;
	return (0);
}

/* ARGSUSED */
static void
i_mac_ring_dtor(void *buf, void *arg)
{
	mac_ring_t *ring = (mac_ring_t *)buf;

	cv_destroy(&ring->mr_cv);
	mutex_destroy(&ring->mr_lock);
}

/*
 * Common functions to do mac callback addition and deletion. Currently this is
 * used by promisc callbacks and notify callbacks. List addition and deletion
 * need to take care of list walkers. List walkers in general, can't hold list
 * locks and make upcall callbacks due to potential lock order and recursive
 * reentry issues. Instead list walkers increment the list walker count to mark
 * the presence of a walker thread. Addition can be carefully done to ensure
 * that the list walker always sees either the old list or the new list.
 * However the deletion can't be done while the walker is active, instead the
 * deleting thread simply marks the entry as logically deleted. The last walker
 * physically deletes and frees up the logically deleted entries when the walk
 * is complete.
 */
void
mac_callback_add(mac_cb_info_t *mcbi, mac_cb_t **mcb_head,
    mac_cb_t *mcb_elem)
{
	mac_cb_t	*p;
	mac_cb_t	**pp;

	/* Verify it is not already in the list */
	for (pp = mcb_head; (p = *pp) != NULL; pp = &p->mcb_nextp) {
		if (p == mcb_elem)
			break;
	}
	VERIFY(p == NULL);

	/*
	 * Add it to the head of the callback list. The membar ensures that
	 * the following list pointer manipulations reach global visibility
	 * in exactly the program order below.
	 */
	ASSERT(MUTEX_HELD(mcbi->mcbi_lockp));

	mcb_elem->mcb_nextp = *mcb_head;
	membar_producer();
	*mcb_head = mcb_elem;
}

/*
 * Mark the entry as logically deleted. If there aren't any walkers unlink
 * from the list. In either case return the corresponding status.
 */
boolean_t
mac_callback_remove(mac_cb_info_t *mcbi, mac_cb_t **mcb_head,
    mac_cb_t *mcb_elem)
{
	mac_cb_t	*p;
	mac_cb_t	**pp;

	ASSERT(MUTEX_HELD(mcbi->mcbi_lockp));
	/*
	 * Search the callback list for the entry to be removed
	 */
	for (pp = mcb_head; (p = *pp) != NULL; pp = &p->mcb_nextp) {
		if (p == mcb_elem)
			break;
	}
	VERIFY(p != NULL);

	/*
	 * If there are walkers just mark it as deleted and the last walker
	 * will remove from the list and free it.
	 */
	if (mcbi->mcbi_walker_cnt != 0) {
		p->mcb_flags |= MCB_CONDEMNED;
		mcbi->mcbi_del_cnt++;
		return (B_FALSE);
	}

	ASSERT(mcbi->mcbi_del_cnt == 0);
	*pp = p->mcb_nextp;
	p->mcb_nextp = NULL;
	return (B_TRUE);
}

/*
 * Wait for all pending callback removals to be completed
 */
void
mac_callback_remove_wait(mac_cb_info_t *mcbi)
{
	ASSERT(MUTEX_HELD(mcbi->mcbi_lockp));
	while (mcbi->mcbi_del_cnt != 0) {
		DTRACE_PROBE1(need_wait, mac_cb_info_t *, mcbi);
		cv_wait(&mcbi->mcbi_cv, mcbi->mcbi_lockp);
	}
}

/*
 * The last mac callback walker does the cleanup. Walk the list and unlik
 * all the logically deleted entries and construct a temporary list of
 * removed entries. Return the list of removed entries to the caller.
 */
mac_cb_t *
mac_callback_walker_cleanup(mac_cb_info_t *mcbi, mac_cb_t **mcb_head)
{
	mac_cb_t	*p;
	mac_cb_t	**pp;
	mac_cb_t	*rmlist = NULL;		/* List of removed elements */
	int	cnt = 0;

	ASSERT(MUTEX_HELD(mcbi->mcbi_lockp));
	ASSERT(mcbi->mcbi_del_cnt != 0 && mcbi->mcbi_walker_cnt == 0);

	pp = mcb_head;
	while (*pp != NULL) {
		if ((*pp)->mcb_flags & MCB_CONDEMNED) {
			p = *pp;
			*pp = p->mcb_nextp;
			p->mcb_nextp = rmlist;
			rmlist = p;
			cnt++;
			continue;
		}
		pp = &(*pp)->mcb_nextp;
	}

	ASSERT(mcbi->mcbi_del_cnt == cnt);
	mcbi->mcbi_del_cnt = 0;
	return (rmlist);
}

boolean_t
mac_callback_lookup(mac_cb_t **mcb_headp, mac_cb_t *mcb_elem)
{
	mac_cb_t	*mcb;

	/* Verify it is not already in the list */
	for (mcb = *mcb_headp; mcb != NULL; mcb = mcb->mcb_nextp) {
		if (mcb == mcb_elem)
			return (B_TRUE);
	}

	return (B_FALSE);
}

boolean_t
mac_callback_find(mac_cb_info_t *mcbi, mac_cb_t **mcb_headp, mac_cb_t *mcb_elem)
{
	boolean_t	found;

	mutex_enter(mcbi->mcbi_lockp);
	found = mac_callback_lookup(mcb_headp, mcb_elem);
	mutex_exit(mcbi->mcbi_lockp);

	return (found);
}

/* Free the list of removed callbacks */
void
mac_callback_free(mac_cb_t *rmlist)
{
	mac_cb_t	*mcb;
	mac_cb_t	*mcb_next;

	for (mcb = rmlist; mcb != NULL; mcb = mcb_next) {
		mcb_next = mcb->mcb_nextp;
		kmem_free(mcb->mcb_objp, mcb->mcb_objsize);
	}
}

/*
 * The promisc callbacks are in 2 lists, one off the 'mip' and another off the
 * 'mcip' threaded by mpi_mi_link and mpi_mci_link respectively. However there
 * is only a single shared total walker count, and an entry can't be physically
 * unlinked if a walker is active on either list. The last walker does this
 * cleanup of logically deleted entries.
 */
void
i_mac_promisc_walker_cleanup(mac_impl_t *mip)
{
	mac_cb_t	*rmlist;
	mac_cb_t	*mcb;
	mac_cb_t	*mcb_next;
	mac_promisc_impl_t	*mpip;

	/*
	 * Construct a temporary list of deleted callbacks by walking the
	 * the mi_promisc_list. Then for each entry in the temporary list,
	 * remove it from the mci_promisc_list and free the entry.
	 */
	rmlist = mac_callback_walker_cleanup(&mip->mi_promisc_cb_info,
	    &mip->mi_promisc_list);

	for (mcb = rmlist; mcb != NULL; mcb = mcb_next) {
		mcb_next = mcb->mcb_nextp;
		mpip = (mac_promisc_impl_t *)mcb->mcb_objp;
		VERIFY(mac_callback_remove(&mip->mi_promisc_cb_info,
		    &mpip->mpi_mcip->mci_promisc_list, &mpip->mpi_mci_link));
		mcb->mcb_flags = 0;
		mcb->mcb_nextp = NULL;
		kmem_cache_free(mac_promisc_impl_cache, mpip);
	}
}

void
i_mac_notify(mac_impl_t *mip, mac_notify_type_t type)
{
	mac_cb_info_t	*mcbi;

	/*
	 * Signal the notify thread even after mi_ref has become zero and
	 * mi_disabled is set. The synchronization with the notify thread
	 * happens in mac_unregister and that implies the driver must make
	 * sure it is single-threaded (with respect to mac calls) and that
	 * all pending mac calls have returned before it calls mac_unregister
	 */
	rw_enter(&i_mac_impl_lock, RW_READER);
	if (mip->mi_state_flags & MIS_DISABLED)
		goto exit;

	/*
	 * Guard against incorrect notifications.  (Running a newer
	 * mac client against an older implementation?)
	 */
	if (type >= MAC_NNOTE)
		goto exit;

	mcbi = &mip->mi_notify_cb_info;
	mutex_enter(mcbi->mcbi_lockp);
	mip->mi_notify_bits |= (1 << type);
	cv_broadcast(&mcbi->mcbi_cv);
	mutex_exit(mcbi->mcbi_lockp);

exit:
	rw_exit(&i_mac_impl_lock);
}

/*
 * Mac serialization primitives. Please see the block comment at the
 * top of the file.
 */
void
i_mac_perim_enter(mac_impl_t *mip)
{
	mac_client_impl_t	*mcip;

	if (mip->mi_state_flags & MIS_IS_VNIC) {
		/*
		 * This is a VNIC. Return the lower mac since that is what
		 * we want to serialize on.
		 */
		mcip = mac_vnic_lower(mip);
		mip = mcip->mci_mip;
	}

	mutex_enter(&mip->mi_perim_lock);
	if (mip->mi_perim_owner == curthread) {
		mip->mi_perim_ocnt++;
		mutex_exit(&mip->mi_perim_lock);
		return;
	}

	while (mip->mi_perim_owner != NULL)
		cv_wait(&mip->mi_perim_cv, &mip->mi_perim_lock);

	mip->mi_perim_owner = curthread;
	ASSERT(mip->mi_perim_ocnt == 0);
	mip->mi_perim_ocnt++;
#ifdef DEBUG
	mip->mi_perim_stack_depth = getpcstack(mip->mi_perim_stack,
	    MAC_PERIM_STACK_DEPTH);
#endif
	mutex_exit(&mip->mi_perim_lock);
}

int
i_mac_perim_enter_nowait(mac_impl_t *mip)
{
	/*
	 * The vnic is a special case, since the serialization is done based
	 * on the lower mac. If the lower mac is busy, it does not imply the
	 * vnic can't be unregistered. But in the case of other drivers,
	 * a busy perimeter or open mac handles implies that the mac is busy
	 * and can't be unregistered.
	 */
	if (mip->mi_state_flags & MIS_IS_VNIC) {
		i_mac_perim_enter(mip);
		return (0);
	}

	mutex_enter(&mip->mi_perim_lock);
	if (mip->mi_perim_owner != NULL) {
		mutex_exit(&mip->mi_perim_lock);
		return (EBUSY);
	}
	ASSERT(mip->mi_perim_ocnt == 0);
	mip->mi_perim_owner = curthread;
	mip->mi_perim_ocnt++;
	mutex_exit(&mip->mi_perim_lock);

	return (0);
}

void
i_mac_perim_exit(mac_impl_t *mip)
{
	mac_client_impl_t *mcip;

	if (mip->mi_state_flags & MIS_IS_VNIC) {
		/*
		 * This is a VNIC. Return the lower mac since that is what
		 * we want to serialize on.
		 */
		mcip = mac_vnic_lower(mip);
		mip = mcip->mci_mip;
	}

	ASSERT(mip->mi_perim_owner == curthread && mip->mi_perim_ocnt != 0);

	mutex_enter(&mip->mi_perim_lock);
	if (--mip->mi_perim_ocnt == 0) {
		mip->mi_perim_owner = NULL;
		cv_signal(&mip->mi_perim_cv);
	}
	mutex_exit(&mip->mi_perim_lock);
}

/*
 * Returns whether the current thread holds the mac perimeter. Used in making
 * assertions.
 */
boolean_t
mac_perim_held(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	mac_client_impl_t *mcip;

	if (mip->mi_state_flags & MIS_IS_VNIC) {
		/*
		 * This is a VNIC. Return the lower mac since that is what
		 * we want to serialize on.
		 */
		mcip = mac_vnic_lower(mip);
		mip = mcip->mci_mip;
	}
	return (mip->mi_perim_owner == curthread);
}

/*
 * mac client interfaces to enter the mac perimeter of a mac end point, given
 * its mac handle, or macname or linkid.
 */
void
mac_perim_enter_by_mh(mac_handle_t mh, mac_perim_handle_t *mphp)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	i_mac_perim_enter(mip);
	/*
	 * The mac_perim_handle_t returned encodes the 'mip' and whether a
	 * mac_open has been done internally while entering the perimeter.
	 * This information is used in mac_perim_exit
	 */
	MAC_ENCODE_MPH(*mphp, mip, 0);
}

int
mac_perim_enter_by_macname(const char *name, mac_perim_handle_t *mphp)
{
	int	err;
	mac_handle_t	mh;

	if ((err = mac_open(name, &mh)) != 0)
		return (err);

	mac_perim_enter_by_mh(mh, mphp);
	MAC_ENCODE_MPH(*mphp, mh, 1);
	return (0);
}

int
mac_perim_enter_by_linkid(datalink_id_t linkid, mac_perim_handle_t *mphp)
{
	int	err;
	mac_handle_t	mh;

	if ((err = mac_open_by_linkid(linkid, &mh)) != 0)
		return (err);

	mac_perim_enter_by_mh(mh, mphp);
	MAC_ENCODE_MPH(*mphp, mh, 1);
	return (0);
}

void
mac_perim_exit(mac_perim_handle_t mph)
{
	mac_impl_t	*mip;
	boolean_t	need_close;

	MAC_DECODE_MPH(mph, mip, need_close);
	i_mac_perim_exit(mip);
	if (need_close)
		mac_close((mac_handle_t)mip);
}

int
mac_hold(const char *macname, mac_impl_t **pmip)
{
	mac_impl_t	*mip;
	int		err;

	/*
	 * Check the device name length to make sure it won't overflow our
	 * buffer.
	 */
	if (strlen(macname) >= MAXNAMELEN)
		return (EINVAL);

	/*
	 * Look up its entry in the global hash table.
	 */
	rw_enter(&i_mac_impl_lock, RW_WRITER);
	err = mod_hash_find(i_mac_impl_hash, (mod_hash_key_t)macname,
	    (mod_hash_val_t *)&mip);

	if (err != 0) {
		rw_exit(&i_mac_impl_lock);
		return (ENOENT);
	}

	if (mip->mi_state_flags & MIS_DISABLED) {
		rw_exit(&i_mac_impl_lock);
		return (ENOENT);
	}

	if (mip->mi_state_flags & MIS_EXCLUSIVE_HELD) {
		rw_exit(&i_mac_impl_lock);
		return (EBUSY);
	}

	mip->mi_ref++;
	rw_exit(&i_mac_impl_lock);

	*pmip = mip;
	return (0);
}

void
mac_rele(mac_impl_t *mip)
{
	rw_enter(&i_mac_impl_lock, RW_WRITER);
	ASSERT(mip->mi_ref != 0);
	if (--mip->mi_ref == 0) {
		ASSERT(mip->mi_nactiveclients == 0 &&
		    !(mip->mi_state_flags & MIS_EXCLUSIVE));
	}
	rw_exit(&i_mac_impl_lock);
}

/*
 * This function is called only by mac_client_open.
 */
int
mac_start(mac_impl_t *mip)
{
	int		err = 0;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));
	ASSERT(mip->mi_start != NULL);

	/*
	 * Check whether the device is already started.
	 */
	if (mip->mi_active++ == 0) {
		mac_ring_t *ring = NULL;

		/*
		 * Start the device.
		 */
		err = mip->mi_start(mip->mi_driver);
		if (err != 0) {
			mip->mi_active--;
			return (err);
		}

		/*
		 * Start the default tx ring.
		 */
		if (mip->mi_default_tx_ring != NULL) {

			ring = (mac_ring_t *)mip->mi_default_tx_ring;
			err = mac_start_ring(ring);
			if (err != 0) {
				mip->mi_active--;
				return (err);
			}
			ring->mr_state = MR_INUSE;
		}

		if (mip->mi_rx_groups != NULL) {
			/*
			 * Start the default ring, since it will be needed
			 * to receive broadcast and multicast traffic for
			 * both primary and non-primary MAC clients.
			 */
			mac_group_t *grp = &mip->mi_rx_groups[0];

			ASSERT(grp->mrg_state == MAC_GROUP_STATE_REGISTERED);
			err = mac_start_group_and_rings(grp);
			if (err != 0) {
				mip->mi_active--;
				if (ring != NULL) {
					mac_stop_ring(ring);
					ring->mr_state = MR_FREE;
				}
				return (err);
			}
			mac_set_rx_group_state(grp, MAC_GROUP_STATE_SHARED);
		}
	}

	return (err);
}

/*
 * This function is called only by mac_client_close.
 */
void
mac_stop(mac_impl_t *mip)
{
	ASSERT(mip->mi_stop != NULL);
	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	/*
	 * Check whether the device is still needed.
	 */
	ASSERT(mip->mi_active != 0);
	if (--mip->mi_active == 0) {
		if (mip->mi_rx_groups != NULL) {
			/*
			 * There should be no more active clients since the
			 * MAC is being stopped. Stop the default RX group
			 * and transition it back to registered state.
			 */
			mac_group_t *grp = &mip->mi_rx_groups[0];

			/*
			 * When clients are torn down, the groups
			 * are release via mac_release_rx_group which
			 * knows the the default group is always in
			 * started mode since broadcast uses it. So
			 * we can assert that their are no clients
			 * (since mac_bcast_add doesn't register itself
			 * as a client) and group is in SHARED state.
			 */
			ASSERT(grp->mrg_state == MAC_GROUP_STATE_SHARED);
			ASSERT(MAC_RX_GROUP_NO_CLIENT(grp) &&
			    mip->mi_nactiveclients == 0);
			mac_stop_group_and_rings(grp);
			mac_set_rx_group_state(grp, MAC_GROUP_STATE_REGISTERED);
		}

		if (mip->mi_default_tx_ring != NULL) {
			mac_ring_t *ring;

			ring = (mac_ring_t *)mip->mi_default_tx_ring;
			mac_stop_ring(ring);
			ring->mr_state = MR_FREE;
		}

		/*
		 * Stop the device.
		 */
		mip->mi_stop(mip->mi_driver);
	}
}

int
i_mac_promisc_set(mac_impl_t *mip, boolean_t on, mac_promisc_type_t ptype)
{
	int		err = 0;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));
	ASSERT(mip->mi_setpromisc != NULL);
	ASSERT(ptype == MAC_DEVPROMISC || ptype == MAC_PROMISC);

	/*
	 * Determine whether we should enable or disable promiscuous mode.
	 * For details on the distinction between "device promiscuous mode"
	 * and "MAC promiscuous mode", see PSARC/2005/289.
	 */
	if (on) {
		/*
		 * Enable promiscuous mode on the device if not yet enabled.
		 */
		if (mip->mi_devpromisc++ == 0) {
			err = mip->mi_setpromisc(mip->mi_driver, B_TRUE);
			if (err != 0) {
				mip->mi_devpromisc--;
				return (err);
			}
			i_mac_notify(mip, MAC_NOTE_DEVPROMISC);
		}

		/*
		 * Enable promiscuous mode on the MAC if not yet enabled.
		 */
		if (ptype == MAC_PROMISC && mip->mi_promisc++ == 0)
			i_mac_notify(mip, MAC_NOTE_PROMISC);
	} else {
		if (mip->mi_devpromisc == 0)
			return (EPROTO);

		/*
		 * Disable promiscuous mode on the device if this is the last
		 * enabling.
		 */
		if (--mip->mi_devpromisc == 0) {
			err = mip->mi_setpromisc(mip->mi_driver, B_FALSE);
			if (err != 0) {
				mip->mi_devpromisc++;
				return (err);
			}
			i_mac_notify(mip, MAC_NOTE_DEVPROMISC);
		}

		/*
		 * Disable promiscuous mode on the MAC if this is the last
		 * enabling.
		 */
		if (ptype == MAC_PROMISC && --mip->mi_promisc == 0)
			i_mac_notify(mip, MAC_NOTE_PROMISC);
	}

	return (0);
}

int
mac_promisc_set(mac_handle_t mh, boolean_t on, mac_promisc_type_t ptype)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	int		rv;

	i_mac_perim_enter(mip);
	rv = i_mac_promisc_set(mip, on, ptype);
	i_mac_perim_exit(mip);

	return (rv);
}

/*
 * The promiscuity state can change any time. If the caller needs to take
 * actions that are atomic with the promiscuity state, then the caller needs
 * to bracket the entire sequence with mac_perim_enter/exit
 */
boolean_t
mac_promisc_get(mac_handle_t mh, mac_promisc_type_t ptype)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;

	ASSERT(ptype == MAC_DEVPROMISC || ptype == MAC_PROMISC);

	/*
	 * Return the current promiscuity.
	 */
	if (ptype == MAC_DEVPROMISC)
		return (mip->mi_devpromisc != 0);
	else
		return (mip->mi_promisc != 0);
}

/*
 * Invoked at MAC instance attach time to initialize the list
 * of factory MAC addresses supported by a MAC instance. This function
 * builds a local cache in the mac_impl_t for the MAC addresses
 * supported by the underlying hardware. The MAC clients themselves
 * use the mac_addr_factory*() functions to query and reserve
 * factory MAC addresses.
 */
void
mac_addr_factory_init(mac_impl_t *mip)
{
	mac_capab_multifactaddr_t capab;
	uint8_t *addr;
	int i;

	/*
	 * First round to see how many factory MAC addresses are available.
	 */
	bzero(&capab, sizeof (capab));
	if (!i_mac_capab_get((mac_handle_t)mip, MAC_CAPAB_MULTIFACTADDR,
	    &capab) || (capab.mcm_naddr == 0)) {
		/*
		 * The MAC instance doesn't support multiple factory
		 * MAC addresses, we're done here.
		 */
		return;
	}

	/*
	 * Allocate the space and get all the factory addresses.
	 */
	addr = kmem_alloc(capab.mcm_naddr * MAXMACADDRLEN, KM_SLEEP);
	capab.mcm_getaddr(mip->mi_driver, capab.mcm_naddr, addr);

	mip->mi_factory_addr_num = capab.mcm_naddr;
	mip->mi_factory_addr = kmem_zalloc(mip->mi_factory_addr_num *
	    sizeof (mac_factory_addr_t), KM_SLEEP);

	for (i = 0; i < capab.mcm_naddr; i++) {
		bcopy(addr + i * MAXMACADDRLEN,
		    mip->mi_factory_addr[i].mfa_addr,
		    mip->mi_type->mt_addr_length);
		mip->mi_factory_addr[i].mfa_in_use = B_FALSE;
	}

	kmem_free(addr, capab.mcm_naddr * MAXMACADDRLEN);
}

void
mac_addr_factory_fini(mac_impl_t *mip)
{
	if (mip->mi_factory_addr == NULL) {
		ASSERT(mip->mi_factory_addr_num == 0);
		return;
	}

	kmem_free(mip->mi_factory_addr, mip->mi_factory_addr_num *
	    sizeof (mac_factory_addr_t));

	mip->mi_factory_addr = NULL;
	mip->mi_factory_addr_num = 0;
}

/*
 * Reserve a factory MAC address. If *slot is set to -1, the function
 * attempts to reserve any of the available factory MAC addresses and
 * returns the reserved slot id. If no slots are available, the function
 * returns ENOSPC. If *slot is not set to -1, the function reserves
 * the specified slot if it is available, or returns EBUSY is the slot
 * is already used. Returns ENOTSUP if the underlying MAC does not
 * support multiple factory addresses. If the slot number is not -1 but
 * is invalid, returns EINVAL.
 */
int
mac_addr_factory_reserve(mac_client_handle_t mch, int *slot)
{
	mac_client_impl_t *mcip = (mac_client_impl_t *)mch;
	mac_impl_t *mip = mcip->mci_mip;
	int i, ret = 0;

	i_mac_perim_enter(mip);
	/*
	 * Protect against concurrent readers that may need a self-consistent
	 * view of the factory addresses
	 */
	rw_enter(&mip->mi_rw_lock, RW_WRITER);

	if (mip->mi_factory_addr_num == 0) {
		ret = ENOTSUP;
		goto bail;
	}

	if (*slot != -1) {
		/* check the specified slot */
		if (*slot < 1 || *slot > mip->mi_factory_addr_num) {
			ret = EINVAL;
			goto bail;
		}
		if (mip->mi_factory_addr[*slot-1].mfa_in_use) {
			ret = EBUSY;
			goto bail;
		}
	} else {
		/* pick the next available slot */
		for (i = 0; i < mip->mi_factory_addr_num; i++) {
			if (!mip->mi_factory_addr[i].mfa_in_use)
				break;
		}

		if (i == mip->mi_factory_addr_num) {
			ret = ENOSPC;
			goto bail;
		}
		*slot = i+1;
	}

	mip->mi_factory_addr[*slot-1].mfa_in_use = B_TRUE;
	mip->mi_factory_addr[*slot-1].mfa_client = mcip;

bail:
	rw_exit(&mip->mi_rw_lock);
	i_mac_perim_exit(mip);
	return (ret);
}

/*
 * Release the specified factory MAC address slot.
 */
void
mac_addr_factory_release(mac_client_handle_t mch, uint_t slot)
{
	mac_client_impl_t *mcip = (mac_client_impl_t *)mch;
	mac_impl_t *mip = mcip->mci_mip;

	i_mac_perim_enter(mip);
	/*
	 * Protect against concurrent readers that may need a self-consistent
	 * view of the factory addresses
	 */
	rw_enter(&mip->mi_rw_lock, RW_WRITER);

	ASSERT(slot > 0 && slot <= mip->mi_factory_addr_num);
	ASSERT(mip->mi_factory_addr[slot-1].mfa_in_use);

	mip->mi_factory_addr[slot-1].mfa_in_use = B_FALSE;

	rw_exit(&mip->mi_rw_lock);
	i_mac_perim_exit(mip);
}

/*
 * Stores in mac_addr the value of the specified MAC address. Returns
 * 0 on success, or EINVAL if the slot number is not valid for the MAC.
 * The caller must provide a string of at least MAXNAMELEN bytes.
 */
void
mac_addr_factory_value(mac_handle_t mh, int slot, uchar_t *mac_addr,
    uint_t *addr_len, char *client_name, boolean_t *in_use_arg)
{
	mac_impl_t *mip = (mac_impl_t *)mh;
	boolean_t in_use;

	ASSERT(slot > 0 && slot <= mip->mi_factory_addr_num);

	/*
	 * Readers need to hold mi_rw_lock. Writers need to hold mac perimeter
	 * and mi_rw_lock
	 */
	rw_enter(&mip->mi_rw_lock, RW_READER);
	bcopy(mip->mi_factory_addr[slot-1].mfa_addr, mac_addr, MAXMACADDRLEN);
	*addr_len = mip->mi_type->mt_addr_length;
	in_use = mip->mi_factory_addr[slot-1].mfa_in_use;
	if (in_use && client_name != NULL) {
		bcopy(mip->mi_factory_addr[slot-1].mfa_client->mci_name,
		    client_name, MAXNAMELEN);
	}
	if (in_use_arg != NULL)
		*in_use_arg = in_use;
	rw_exit(&mip->mi_rw_lock);
}

/*
 * Returns the number of factory MAC addresses (in addition to the
 * primary MAC address), 0 if the underlying MAC doesn't support
 * that feature.
 */
uint_t
mac_addr_factory_num(mac_handle_t mh)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	return (mip->mi_factory_addr_num);
}


void
mac_rx_group_unmark(mac_group_t *grp, uint_t flag)
{
	mac_ring_t	*ring;

	for (ring = grp->mrg_rings; ring != NULL; ring = ring->mr_next)
		ring->mr_flag &= ~flag;
}

/*
 * The following mac_hwrings_xxx() functions are private mac client functions
 * used by the aggr driver to access and control the underlying HW Rx group
 * and rings. In this case, the aggr driver has exclusive control of the
 * underlying HW Rx group/rings, it calls the following functions to
 * start/stop the HW Rx rings, disable/enable polling, add/remove mac'
 * addresses, or set up the Rx callback.
 */
/* ARGSUSED */
static void
mac_hwrings_rx_process(void *arg, mac_resource_handle_t srs,
    mblk_t *mp_chain, boolean_t loopback)
{
	mac_soft_ring_set_t	*mac_srs = (mac_soft_ring_set_t *)srs;
	mac_srs_rx_t		*srs_rx = &mac_srs->srs_rx;
	mac_direct_rx_t		proc;
	void			*arg1;
	mac_resource_handle_t	arg2;

	proc = srs_rx->sr_func;
	arg1 = srs_rx->sr_arg1;
	arg2 = mac_srs->srs_mrh;

	proc(arg1, arg2, mp_chain, NULL);
}

/*
 * This function is called to get the list of HW rings that are reserved by
 * an exclusive mac client.
 *
 * Return value: the number of HW rings.
 */
int
mac_hwrings_get(mac_client_handle_t mch, mac_group_handle_t *hwgh,
    mac_ring_handle_t *hwrh)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	flow_entry_t		*flent = mcip->mci_flent;
	mac_group_t		*grp = flent->fe_rx_ring_group;
	mac_ring_t		*ring;
	int			cnt = 0;

	/*
	 * The mac client did not reserve any RX group, return directly.
	 * This is probably because the underlying MAC does not support
	 * any RX groups.
	 */
	*hwgh = NULL;
	if (grp == NULL)
		return (0);

	/*
	 * This RX group must be reserved by this mac client.
	 */
	ASSERT((grp->mrg_state == MAC_GROUP_STATE_RESERVED) &&
	    (mch == (mac_client_handle_t)(MAC_RX_GROUP_ONLY_CLIENT(grp))));

	for (ring = grp->mrg_rings; ring != NULL; ring = ring->mr_next) {
		ASSERT(cnt < MAX_RINGS_PER_GROUP);
		hwrh[cnt++] = (mac_ring_handle_t)ring;
	}
	*hwgh = (mac_group_handle_t)grp;
	return (cnt);
}

/*
 * Setup the RX callback of the mac client which exclusively controls HW ring.
 */
void
mac_hwring_setup(mac_ring_handle_t hwrh, mac_resource_handle_t prh)
{
	mac_ring_t		*hw_ring = (mac_ring_t *)hwrh;
	mac_soft_ring_set_t	*mac_srs = hw_ring->mr_srs;

	mac_srs->srs_mrh = prh;
	mac_srs->srs_rx.sr_lower_proc = mac_hwrings_rx_process;
}

void
mac_hwring_teardown(mac_ring_handle_t hwrh)
{
	mac_ring_t		*hw_ring = (mac_ring_t *)hwrh;
	mac_soft_ring_set_t	*mac_srs = hw_ring->mr_srs;

	mac_srs->srs_rx.sr_lower_proc = mac_rx_srs_process;
	mac_srs->srs_mrh = NULL;
}

int
mac_hwring_disable_intr(mac_ring_handle_t rh)
{
	mac_ring_t *rr_ring = (mac_ring_t *)rh;
	mac_intr_t *intr = &rr_ring->mr_info.mri_intr;

	return (intr->mi_disable(intr->mi_handle));
}

int
mac_hwring_enable_intr(mac_ring_handle_t rh)
{
	mac_ring_t *rr_ring = (mac_ring_t *)rh;
	mac_intr_t *intr = &rr_ring->mr_info.mri_intr;

	return (intr->mi_enable(intr->mi_handle));
}

int
mac_hwring_start(mac_ring_handle_t rh)
{
	mac_ring_t *rr_ring = (mac_ring_t *)rh;

	MAC_RING_UNMARK(rr_ring, MR_QUIESCE);
	return (0);
}

void
mac_hwring_stop(mac_ring_handle_t rh)
{
	mac_ring_t *rr_ring = (mac_ring_t *)rh;

	mac_rx_ring_quiesce(rr_ring, MR_QUIESCE);
}

mblk_t *
mac_hwring_poll(mac_ring_handle_t rh, int bytes_to_pickup)
{
	mac_ring_t *rr_ring = (mac_ring_t *)rh;
	mac_ring_info_t *info = &rr_ring->mr_info;

	return (info->mri_poll(info->mri_driver, bytes_to_pickup));
}

int
mac_hwgroup_addmac(mac_group_handle_t gh, const uint8_t *addr)
{
	mac_group_t *group = (mac_group_t *)gh;

	return (mac_group_addmac(group, addr));
}

int
mac_hwgroup_remmac(mac_group_handle_t gh, const uint8_t *addr)
{
	mac_group_t *group = (mac_group_t *)gh;

	return (mac_group_remmac(group, addr));
}

/*
 * Set the RX group to be shared/reserved. Note that the group must be
 * started/stopped outside of this function.
 */
void
mac_set_rx_group_state(mac_group_t *grp, mac_group_state_t state)
{
	/*
	 * If there is no change in the group state, just return.
	 */
	if (grp->mrg_state == state)
		return;

	switch (state) {
	case MAC_GROUP_STATE_RESERVED:
		/*
		 * Successfully reserved the group.
		 *
		 * Given that there is an exclusive client controlling this
		 * group, we enable the group level polling when available,
		 * so that SRSs get to turn on/off individual rings they's
		 * assigned to.
		 */
		ASSERT(MAC_PERIM_HELD(grp->mrg_mh));

		if (GROUP_INTR_DISABLE_FUNC(grp) != NULL)
			GROUP_INTR_DISABLE_FUNC(grp)(GROUP_INTR_HANDLE(grp));

		break;

	case MAC_GROUP_STATE_SHARED:
		/*
		 * Set all rings of this group to software classified.
		 * If the group has an overriding interrupt, then re-enable it.
		 */
		ASSERT(MAC_PERIM_HELD(grp->mrg_mh));

		if (GROUP_INTR_ENABLE_FUNC(grp) != NULL)
			GROUP_INTR_ENABLE_FUNC(grp)(GROUP_INTR_HANDLE(grp));

		/* The ring is not available for reservations any more */
		break;

	case MAC_GROUP_STATE_REGISTERED:
		/* Also callable from mac_register, perim is not held */
		break;

	default:
		ASSERT(B_FALSE);
		break;
	}

	grp->mrg_state = state;
}

/*
 * Quiesce future hardware classified packets for the specified Rx ring
 */
static void
mac_rx_ring_quiesce(mac_ring_t *rx_ring, uint_t ring_flag)
{
	ASSERT(rx_ring->mr_classify_type == MAC_HW_CLASSIFIER);
	ASSERT(ring_flag == MR_CONDEMNED || ring_flag  == MR_QUIESCE);

	mutex_enter(&rx_ring->mr_lock);
	rx_ring->mr_flag |= ring_flag;
	while (rx_ring->mr_refcnt != 0)
		cv_wait(&rx_ring->mr_cv, &rx_ring->mr_lock);
	mutex_exit(&rx_ring->mr_lock);
}

/*
 * Please see mac_tx for details about the per cpu locking scheme
 */
static void
mac_tx_lock_all(mac_client_impl_t *mcip)
{
	int	i;

	for (i = 0; i <= mac_tx_percpu_cnt; i++)
		mutex_enter(&mcip->mci_tx_pcpu[i].pcpu_tx_lock);
}

static void
mac_tx_unlock_all(mac_client_impl_t *mcip)
{
	int	i;

	for (i = mac_tx_percpu_cnt; i >= 0; i--)
		mutex_exit(&mcip->mci_tx_pcpu[i].pcpu_tx_lock);
}

static void
mac_tx_unlock_allbutzero(mac_client_impl_t *mcip)
{
	int	i;

	for (i = mac_tx_percpu_cnt; i > 0; i--)
		mutex_exit(&mcip->mci_tx_pcpu[i].pcpu_tx_lock);
}

static int
mac_tx_sum_refcnt(mac_client_impl_t *mcip)
{
	int	i;
	int	refcnt = 0;

	for (i = 0; i <= mac_tx_percpu_cnt; i++)
		refcnt += mcip->mci_tx_pcpu[i].pcpu_tx_refcnt;

	return (refcnt);
}

/*
 * Stop future Tx packets coming down from the client in preparation for
 * quiescing the Tx side. This is needed for dynamic reclaim and reassignment
 * of rings between clients
 */
void
mac_tx_client_block(mac_client_impl_t *mcip)
{
	mac_tx_lock_all(mcip);
	mcip->mci_tx_flag |= MCI_TX_QUIESCE;
	while (mac_tx_sum_refcnt(mcip) != 0) {
		mac_tx_unlock_allbutzero(mcip);
		cv_wait(&mcip->mci_tx_cv, &mcip->mci_tx_pcpu[0].pcpu_tx_lock);
		mutex_exit(&mcip->mci_tx_pcpu[0].pcpu_tx_lock);
		mac_tx_lock_all(mcip);
	}
	mac_tx_unlock_all(mcip);
}

void
mac_tx_client_unblock(mac_client_impl_t *mcip)
{
	mac_tx_lock_all(mcip);
	mcip->mci_tx_flag &= ~MCI_TX_QUIESCE;
	mac_tx_unlock_all(mcip);
}

/*
 * Wait for an SRS to quiesce. The SRS worker will signal us when the
 * quiesce is done.
 */
static void
mac_srs_quiesce_wait(mac_soft_ring_set_t *srs, uint_t srs_flag)
{
	mutex_enter(&srs->srs_lock);
	while (!(srs->srs_state & srs_flag))
		cv_wait(&srs->srs_quiesce_done_cv, &srs->srs_lock);
	mutex_exit(&srs->srs_lock);
}

/*
 * Quiescing an Rx SRS is achieved by the following sequence. The protocol
 * works bottom up by cutting off packet flow from the bottommost point in the
 * mac, then the SRS, and then the soft rings. There are 2 use cases of this
 * mechanism. One is a temporary quiesce of the SRS, such as say while changing
 * the Rx callbacks. Another use case is Rx SRS teardown. In the former case
 * the QUIESCE prefix/suffix is used and in the latter the CONDEMNED is used
 * for the SRS and MR flags. In the former case the threads pause waiting for
 * a restart, while in the latter case the threads exit. The Tx SRS teardown
 * is also mostly similar to the above.
 *
 * 1. Stop future hardware classified packets at the lowest level in the mac.
 *    Remove any hardware classification rule (CONDEMNED case) and mark the
 *    rings as CONDEMNED or QUIESCE as appropriate. This prevents the mr_refcnt
 *    from increasing. Upcalls from the driver that come through hardware
 *    classification will be dropped in mac_rx from now on. Then we wait for
 *    the mr_refcnt to drop to zero. When the mr_refcnt reaches zero we are
 *    sure there aren't any upcall threads from the driver through hardware
 *    classification. In the case of SRS teardown we also remove the
 *    classification rule in the driver.
 *
 * 2. Stop future software classified packets by marking the flow entry with
 *    FE_QUIESCE or FE_CONDEMNED as appropriate which prevents the refcnt from
 *    increasing. We also remove the flow entry from the table in the latter
 *    case. Then wait for the fe_refcnt to reach an appropriate quiescent value
 *    that indicates there aren't any active threads using that flow entry.
 *
 * 3. Quiesce the SRS and softrings by signaling the SRS. The SRS poll thread,
 *    SRS worker thread, and the soft ring threads are quiesced in sequence
 *    with the SRS worker thread serving as a master controller. This
 *    mechansim is explained in mac_srs_worker_quiesce().
 *
 * The restart mechanism to reactivate the SRS and softrings is explained
 * in mac_srs_worker_restart(). Here we just signal the SRS worker to start the
 * restart sequence.
 */
void
mac_rx_srs_quiesce(mac_soft_ring_set_t *srs, uint_t srs_quiesce_flag)
{
	flow_entry_t	*flent = srs->srs_flent;
	uint_t	mr_flag, srs_done_flag;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)FLENT_TO_MIP(flent)));
	ASSERT(!(srs->srs_type & SRST_TX));

	if (srs_quiesce_flag == SRS_CONDEMNED) {
		mr_flag = MR_CONDEMNED;
		srs_done_flag = SRS_CONDEMNED_DONE;
		if (srs->srs_type & SRST_CLIENT_POLL_ENABLED)
			mac_srs_client_poll_disable(srs->srs_mcip, srs);
	} else {
		ASSERT(srs_quiesce_flag == SRS_QUIESCE);
		mr_flag = MR_QUIESCE;
		srs_done_flag = SRS_QUIESCE_DONE;
		if (srs->srs_type & SRST_CLIENT_POLL_ENABLED)
			mac_srs_client_poll_quiesce(srs->srs_mcip, srs);
	}

	if (srs->srs_ring != NULL) {
		mac_rx_ring_quiesce(srs->srs_ring, mr_flag);
	} else {
		/*
		 * SRS is driven by software classification. In case
		 * of CONDEMNED, the top level teardown functions will
		 * deal with flow removal.
		 */
		if (srs_quiesce_flag != SRS_CONDEMNED) {
			FLOW_MARK(flent, FE_QUIESCE);
			mac_flow_wait(flent, FLOW_DRIVER_UPCALL);
		}
	}

	/*
	 * Signal the SRS to quiesce itself, and then cv_wait for the
	 * SRS quiesce to complete. The SRS worker thread will wake us
	 * up when the quiesce is complete
	 */
	mac_srs_signal(srs, srs_quiesce_flag);
	mac_srs_quiesce_wait(srs, srs_done_flag);
}

/*
 * Remove an SRS.
 */
void
mac_rx_srs_remove(mac_soft_ring_set_t *srs)
{
	flow_entry_t *flent = srs->srs_flent;
	int i;

	mac_rx_srs_quiesce(srs, SRS_CONDEMNED);
	/*
	 * Locate and remove our entry in the fe_rx_srs[] array, and
	 * adjust the fe_rx_srs array entries and array count by
	 * moving the last entry into the vacated spot.
	 */
	mutex_enter(&flent->fe_lock);
	for (i = 0; i < flent->fe_rx_srs_cnt; i++) {
		if (flent->fe_rx_srs[i] == srs)
			break;
	}

	ASSERT(i != 0 && i < flent->fe_rx_srs_cnt);
	if (i != flent->fe_rx_srs_cnt - 1) {
		flent->fe_rx_srs[i] =
		    flent->fe_rx_srs[flent->fe_rx_srs_cnt - 1];
		i = flent->fe_rx_srs_cnt - 1;
	}

	flent->fe_rx_srs[i] = NULL;
	flent->fe_rx_srs_cnt--;
	mutex_exit(&flent->fe_lock);

	mac_srs_free(srs);
}

static void
mac_srs_clear_flag(mac_soft_ring_set_t *srs, uint_t flag)
{
	mutex_enter(&srs->srs_lock);
	srs->srs_state &= ~flag;
	mutex_exit(&srs->srs_lock);
}

void
mac_rx_srs_restart(mac_soft_ring_set_t *srs)
{
	flow_entry_t	*flent = srs->srs_flent;
	mac_ring_t	*mr;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)FLENT_TO_MIP(flent)));
	ASSERT((srs->srs_type & SRST_TX) == 0);

	/*
	 * This handles a change in the number of SRSs between the quiesce and
	 * and restart operation of a flow.
	 */
	if (!SRS_QUIESCED(srs))
		return;

	/*
	 * Signal the SRS to restart itself. Wait for the restart to complete
	 * Note that we only restart the SRS if it is not marked as
	 * permanently quiesced.
	 */
	if (!SRS_QUIESCED_PERMANENT(srs)) {
		mac_srs_signal(srs, SRS_RESTART);
		mac_srs_quiesce_wait(srs, SRS_RESTART_DONE);
		mac_srs_clear_flag(srs, SRS_RESTART_DONE);

		mac_srs_client_poll_restart(srs->srs_mcip, srs);
	}

	/* Finally clear the flags to let the packets in */
	mr = srs->srs_ring;
	if (mr != NULL) {
		MAC_RING_UNMARK(mr, MR_QUIESCE);
		/* In case the ring was stopped, safely restart it */
		(void) mac_start_ring(mr);
	} else {
		FLOW_UNMARK(flent, FE_QUIESCE);
	}
}

/*
 * Temporary quiesce of a flow and associated Rx SRS.
 * Please see block comment above mac_rx_classify_flow_rem.
 */
/* ARGSUSED */
int
mac_rx_classify_flow_quiesce(flow_entry_t *flent, void *arg)
{
	int		i;

	for (i = 0; i < flent->fe_rx_srs_cnt; i++) {
		mac_rx_srs_quiesce((mac_soft_ring_set_t *)flent->fe_rx_srs[i],
		    SRS_QUIESCE);
	}
	return (0);
}

/*
 * Restart a flow and associated Rx SRS that has been quiesced temporarily
 * Please see block comment above mac_rx_classify_flow_rem
 */
/* ARGSUSED */
int
mac_rx_classify_flow_restart(flow_entry_t *flent, void *arg)
{
	int		i;

	for (i = 0; i < flent->fe_rx_srs_cnt; i++)
		mac_rx_srs_restart((mac_soft_ring_set_t *)flent->fe_rx_srs[i]);

	return (0);
}

void
mac_srs_perm_quiesce(mac_client_handle_t mch, boolean_t on)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	flow_entry_t		*flent = mcip->mci_flent;
	mac_impl_t		*mip = mcip->mci_mip;
	mac_soft_ring_set_t	*mac_srs;
	int			i;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	if (flent == NULL)
		return;

	for (i = 0; i < flent->fe_rx_srs_cnt; i++) {
		mac_srs = flent->fe_rx_srs[i];
		mutex_enter(&mac_srs->srs_lock);
		if (on)
			mac_srs->srs_state |= SRS_QUIESCE_PERM;
		else
			mac_srs->srs_state &= ~SRS_QUIESCE_PERM;
		mutex_exit(&mac_srs->srs_lock);
	}
}

void
mac_rx_client_quiesce(mac_client_handle_t mch)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_impl_t		*mip = mcip->mci_mip;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	if (MCIP_DATAPATH_SETUP(mcip)) {
		(void) mac_rx_classify_flow_quiesce(mcip->mci_flent,
		    NULL);
		(void) mac_flow_walk_nolock(mcip->mci_subflow_tab,
		    mac_rx_classify_flow_quiesce, NULL);
	}
}

void
mac_rx_client_restart(mac_client_handle_t mch)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_impl_t		*mip = mcip->mci_mip;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	if (MCIP_DATAPATH_SETUP(mcip)) {
		(void) mac_rx_classify_flow_restart(mcip->mci_flent, NULL);
		(void) mac_flow_walk_nolock(mcip->mci_subflow_tab,
		    mac_rx_classify_flow_restart, NULL);
	}
}

/*
 * This function only quiesces the Tx SRS and softring worker threads. Callers
 * need to make sure that there aren't any mac client threads doing current or
 * future transmits in the mac before calling this function.
 */
void
mac_tx_srs_quiesce(mac_soft_ring_set_t *srs, uint_t srs_quiesce_flag)
{
	mac_client_impl_t	*mcip = srs->srs_mcip;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mcip->mci_mip));

	ASSERT(srs->srs_type & SRST_TX);
	ASSERT(srs_quiesce_flag == SRS_CONDEMNED ||
	    srs_quiesce_flag == SRS_QUIESCE);

	/*
	 * Signal the SRS to quiesce itself, and then cv_wait for the
	 * SRS quiesce to complete. The SRS worker thread will wake us
	 * up when the quiesce is complete
	 */
	mac_srs_signal(srs, srs_quiesce_flag);
	mac_srs_quiesce_wait(srs, srs_quiesce_flag == SRS_QUIESCE ?
	    SRS_QUIESCE_DONE : SRS_CONDEMNED_DONE);
}

void
mac_tx_srs_restart(mac_soft_ring_set_t *srs)
{
	/*
	 * Resizing the fanout could result in creation of new SRSs.
	 * They may not necessarily be in the quiesced state in which
	 * case it need be restarted
	 */
	if (!SRS_QUIESCED(srs))
		return;

	mac_srs_signal(srs, SRS_RESTART);
	mac_srs_quiesce_wait(srs, SRS_RESTART_DONE);
	mac_srs_clear_flag(srs, SRS_RESTART_DONE);
}

/*
 * Temporary quiesce of a flow and associated Rx SRS.
 * Please see block comment above mac_rx_srs_quiesce
 */
/* ARGSUSED */
int
mac_tx_flow_quiesce(flow_entry_t *flent, void *arg)
{
	/*
	 * The fe_tx_srs is null for a subflow on an interface that is
	 * not plumbed
	 */
	if (flent->fe_tx_srs != NULL)
		mac_tx_srs_quiesce(flent->fe_tx_srs, SRS_QUIESCE);
	return (0);
}

/* ARGSUSED */
int
mac_tx_flow_restart(flow_entry_t *flent, void *arg)
{
	/*
	 * The fe_tx_srs is null for a subflow on an interface that is
	 * not plumbed
	 */
	if (flent->fe_tx_srs != NULL)
		mac_tx_srs_restart(flent->fe_tx_srs);
	return (0);
}

void
mac_tx_client_quiesce(mac_client_impl_t *mcip, uint_t srs_quiesce_flag)
{
	ASSERT(MAC_PERIM_HELD((mac_handle_t)mcip->mci_mip));

	mac_tx_client_block(mcip);
	if (MCIP_TX_SRS(mcip) != NULL) {
		mac_tx_srs_quiesce(MCIP_TX_SRS(mcip), srs_quiesce_flag);
		(void) mac_flow_walk_nolock(mcip->mci_subflow_tab,
		    mac_tx_flow_quiesce, NULL);
	}
}

void
mac_tx_client_restart(mac_client_impl_t *mcip)
{
	ASSERT(MAC_PERIM_HELD((mac_handle_t)mcip->mci_mip));

	mac_tx_client_unblock(mcip);
	if (MCIP_TX_SRS(mcip) != NULL) {
		mac_tx_srs_restart(MCIP_TX_SRS(mcip));
		(void) mac_flow_walk_nolock(mcip->mci_subflow_tab,
		    mac_tx_flow_restart, NULL);
	}
}

void
mac_tx_client_flush(mac_client_impl_t *mcip)
{
	ASSERT(MAC_PERIM_HELD((mac_handle_t)mcip->mci_mip));

	mac_tx_client_quiesce(mcip, SRS_QUIESCE);
	mac_tx_client_restart(mcip);
}

void
mac_client_quiesce(mac_client_impl_t *mcip)
{
	mac_rx_client_quiesce((mac_client_handle_t)mcip);
	mac_tx_client_quiesce(mcip, SRS_QUIESCE);
}

void
mac_client_restart(mac_client_impl_t *mcip)
{
	mac_rx_client_restart((mac_client_handle_t)mcip);
	mac_tx_client_restart(mcip);
}

/*
 * Allocate a minor number.
 */
minor_t
mac_minor_hold(boolean_t sleep)
{
	minor_t	minor;

	/*
	 * Grab a value from the arena.
	 */
	atomic_add_32(&minor_count, 1);

	if (sleep)
		minor = (uint_t)id_alloc(minor_ids);
	else
		minor = (uint_t)id_alloc_nosleep(minor_ids);

	if (minor == 0) {
		atomic_add_32(&minor_count, -1);
		return (0);
	}

	return (minor);
}

/*
 * Release a previously allocated minor number.
 */
void
mac_minor_rele(minor_t minor)
{
	/*
	 * Return the value to the arena.
	 */
	id_free(minor_ids, minor);
	atomic_add_32(&minor_count, -1);
}

uint32_t
mac_no_notification(mac_handle_t mh)
{
	mac_impl_t *mip = (mac_impl_t *)mh;
	return (mip->mi_unsup_note);
}

/*
 * Prevent any new opens of this mac in preparation for unregister
 */
int
i_mac_disable(mac_impl_t *mip)
{
	mac_client_impl_t	*mcip;

	rw_enter(&i_mac_impl_lock, RW_WRITER);
	if (mip->mi_state_flags & MIS_DISABLED) {
		/* Already disabled, return success */
		rw_exit(&i_mac_impl_lock);
		return (0);
	}
	/*
	 * See if there are any other references to this mac_t (e.g., VLAN's).
	 * If so return failure. If all the other checks below pass, then
	 * set mi_disabled atomically under the i_mac_impl_lock to prevent
	 * any new VLAN's from being created or new mac client opens of this
	 * mac end point.
	 */
	if (mip->mi_ref > 0) {
		rw_exit(&i_mac_impl_lock);
		return (EBUSY);
	}

	/*
	 * mac clients must delete all multicast groups they join before
	 * closing. bcast groups are reference counted, the last client
	 * to delete the group will wait till the group is physically
	 * deleted. Since all clients have closed this mac end point
	 * mi_bcast_ngrps must be zero at this point
	 */
	ASSERT(mip->mi_bcast_ngrps == 0);

	/*
	 * Don't let go of this if it has some flows.
	 * All other code guarantees no flows are added to a disabled
	 * mac, therefore it is sufficient to check for the flow table
	 * only here.
	 */
	mcip = mac_primary_client_handle(mip);
	if ((mcip != NULL) && mac_link_has_flows((mac_client_handle_t)mcip)) {
		rw_exit(&i_mac_impl_lock);
		return (ENOTEMPTY);
	}

	mip->mi_state_flags |= MIS_DISABLED;
	rw_exit(&i_mac_impl_lock);
	return (0);
}

int
mac_disable_nowait(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	int err;

	if ((err = i_mac_perim_enter_nowait(mip)) != 0)
		return (err);
	err = i_mac_disable(mip);
	i_mac_perim_exit(mip);
	return (err);
}

int
mac_disable(mac_handle_t mh)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	int err;

	i_mac_perim_enter(mip);
	err = i_mac_disable(mip);
	i_mac_perim_exit(mip);

	/*
	 * Clean up notification thread and wait for it to exit.
	 */
	if (err == 0)
		i_mac_notify_exit(mip);

	return (err);
}

/*
 * Called when the MAC instance has a non empty flow table, to de-multiplex
 * incoming packets to the right flow.
 * The MAC's rw lock is assumed held as a READER.
 */
/* ARGSUSED */
static mblk_t *
mac_rx_classify(mac_impl_t *mip, mac_resource_handle_t mrh, mblk_t *mp)
{
	flow_entry_t	*flent = NULL;
	uint_t		flags = FLOW_INBOUND;
	int		err;

	/*
	 * If the mac is a port of an aggregation, pass FLOW_IGNORE_VLAN
	 * to mac_flow_lookup() so that the VLAN packets can be successfully
	 * passed to the non-VLAN aggregation flows.
	 *
	 * Note that there is possibly a race between this and
	 * mac_unicast_remove/add() and VLAN packets could be incorrectly
	 * classified to non-VLAN flows of non-aggregation mac clients. These
	 * VLAN packets will be then filtered out by the mac module.
	 */
	if ((mip->mi_state_flags & MIS_EXCLUSIVE) != 0)
		flags |= FLOW_IGNORE_VLAN;

	err = mac_flow_lookup(mip->mi_flow_tab, mp, flags, &flent);
	if (err != 0) {
		/* no registered receive function */
		return (mp);
	} else {
		mac_client_impl_t	*mcip;

		/*
		 * This flent might just be an additional one on the MAC client,
		 * i.e. for classification purposes (different fdesc), however
		 * the resources, SRS et. al., are in the mci_flent, so if
		 * this isn't the mci_flent, we need to get it.
		 */
		if ((mcip = flent->fe_mcip) != NULL &&
		    mcip->mci_flent != flent) {
			FLOW_REFRELE(flent);
			flent = mcip->mci_flent;
			FLOW_TRY_REFHOLD(flent, err);
			if (err != 0)
				return (mp);
		}
		(flent->fe_cb_fn)(flent->fe_cb_arg1, flent->fe_cb_arg2, mp,
		    B_FALSE);
		FLOW_REFRELE(flent);
	}
	return (NULL);
}

mblk_t *
mac_rx_flow(mac_handle_t mh, mac_resource_handle_t mrh, mblk_t *mp_chain)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	mblk_t		*bp, *bp1, **bpp, *list = NULL;

	/*
	 * We walk the chain and attempt to classify each packet.
	 * The packets that couldn't be classified will be returned
	 * back to the caller.
	 */
	bp = mp_chain;
	bpp = &list;
	while (bp != NULL) {
		bp1 = bp;
		bp = bp->b_next;
		bp1->b_next = NULL;

		if (mac_rx_classify(mip, mrh, bp1) != NULL) {
			*bpp = bp1;
			bpp = &bp1->b_next;
		}
	}
	return (list);
}

static int
mac_tx_flow_srs_wakeup(flow_entry_t *flent, void *arg)
{
	mac_ring_handle_t ring = arg;

	if (flent->fe_tx_srs)
		mac_tx_srs_wakeup(flent->fe_tx_srs, ring);
	return (0);
}

void
i_mac_tx_srs_notify(mac_impl_t *mip, mac_ring_handle_t ring)
{
	mac_client_impl_t	*cclient;
	mac_soft_ring_set_t	*mac_srs;

	/*
	 * After grabbing the mi_rw_lock, the list of clients can't change.
	 * If there are any clients mi_disabled must be B_FALSE and can't
	 * get set since there are clients. If there aren't any clients we
	 * don't do anything. In any case the mip has to be valid. The driver
	 * must make sure that it goes single threaded (with respect to mac
	 * calls) and wait for all pending mac calls to finish before calling
	 * mac_unregister.
	 */
	rw_enter(&i_mac_impl_lock, RW_READER);
	if (mip->mi_state_flags & MIS_DISABLED) {
		rw_exit(&i_mac_impl_lock);
		return;
	}

	/*
	 * Get MAC tx srs from walking mac_client_handle list.
	 */
	rw_enter(&mip->mi_rw_lock, RW_READER);
	for (cclient = mip->mi_clients_list; cclient != NULL;
	    cclient = cclient->mci_client_next) {
		if ((mac_srs = MCIP_TX_SRS(cclient)) != NULL)
			mac_tx_srs_wakeup(mac_srs, ring);
		if (!FLOW_TAB_EMPTY(cclient->mci_subflow_tab)) {
			(void) mac_flow_walk_nolock(cclient->mci_subflow_tab,
			    mac_tx_flow_srs_wakeup, ring);
		}
	}
	rw_exit(&mip->mi_rw_lock);
	rw_exit(&i_mac_impl_lock);
}

/* ARGSUSED */
void
mac_multicast_refresh(mac_handle_t mh, mac_multicst_t refresh, void *arg,
    boolean_t add)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	i_mac_perim_enter((mac_impl_t *)mh);
	/*
	 * If no specific refresh function was given then default to the
	 * driver's m_multicst entry point.
	 */
	if (refresh == NULL) {
		refresh = mip->mi_multicst;
		arg = mip->mi_driver;
	}

	mac_bcast_refresh(mip, refresh, arg, add);
	i_mac_perim_exit((mac_impl_t *)mh);
}

void
mac_promisc_refresh(mac_handle_t mh, mac_setpromisc_t refresh, void *arg)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;

	/*
	 * If no specific refresh function was given then default to the
	 * driver's m_promisc entry point.
	 */
	if (refresh == NULL) {
		refresh = mip->mi_setpromisc;
		arg = mip->mi_driver;
	}
	ASSERT(refresh != NULL);

	/*
	 * Call the refresh function with the current promiscuity.
	 */
	refresh(arg, (mip->mi_devpromisc != 0));
}

/*
 * The mac client requests that the mac not to change its margin size to
 * be less than the specified value.  If "current" is B_TRUE, then the client
 * requests the mac not to change its margin size to be smaller than the
 * current size. Further, return the current margin size value in this case.
 *
 * We keep every requested size in an ordered list from largest to smallest.
 */
int
mac_margin_add(mac_handle_t mh, uint32_t *marginp, boolean_t current)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mac_margin_req_t	**pp, *p;
	int			err = 0;

	rw_enter(&(mip->mi_rw_lock), RW_WRITER);
	if (current)
		*marginp = mip->mi_margin;

	/*
	 * If the current margin value cannot satisfy the margin requested,
	 * return ENOTSUP directly.
	 */
	if (*marginp > mip->mi_margin) {
		err = ENOTSUP;
		goto done;
	}

	/*
	 * Check whether the given margin is already in the list. If so,
	 * bump the reference count.
	 */
	for (pp = &mip->mi_mmrp; (p = *pp) != NULL; pp = &p->mmr_nextp) {
		if (p->mmr_margin == *marginp) {
			/*
			 * The margin requested is already in the list,
			 * so just bump the reference count.
			 */
			p->mmr_ref++;
			goto done;
		}
		if (p->mmr_margin < *marginp)
			break;
	}


	p = kmem_zalloc(sizeof (mac_margin_req_t), KM_SLEEP);
	p->mmr_margin = *marginp;
	p->mmr_ref++;
	p->mmr_nextp = *pp;
	*pp = p;

done:
	rw_exit(&(mip->mi_rw_lock));
	return (err);
}

/*
 * The mac client requests to cancel its previous mac_margin_add() request.
 * We remove the requested margin size from the list.
 */
int
mac_margin_remove(mac_handle_t mh, uint32_t margin)
{
	mac_impl_t		*mip = (mac_impl_t *)mh;
	mac_margin_req_t	**pp, *p;
	int			err = 0;

	rw_enter(&(mip->mi_rw_lock), RW_WRITER);
	/*
	 * Find the entry in the list for the given margin.
	 */
	for (pp = &(mip->mi_mmrp); (p = *pp) != NULL; pp = &(p->mmr_nextp)) {
		if (p->mmr_margin == margin) {
			if (--p->mmr_ref == 0)
				break;

			/*
			 * There is still a reference to this address so
			 * there's nothing more to do.
			 */
			goto done;
		}
	}

	/*
	 * We did not find an entry for the given margin.
	 */
	if (p == NULL) {
		err = ENOENT;
		goto done;
	}

	ASSERT(p->mmr_ref == 0);

	/*
	 * Remove it from the list.
	 */
	*pp = p->mmr_nextp;
	kmem_free(p, sizeof (mac_margin_req_t));
done:
	rw_exit(&(mip->mi_rw_lock));
	return (err);
}

boolean_t
mac_margin_update(mac_handle_t mh, uint32_t margin)
{
	mac_impl_t	*mip = (mac_impl_t *)mh;
	uint32_t	margin_needed = 0;

	rw_enter(&(mip->mi_rw_lock), RW_WRITER);

	if (mip->mi_mmrp != NULL)
		margin_needed = mip->mi_mmrp->mmr_margin;

	if (margin_needed <= margin)
		mip->mi_margin = margin;

	rw_exit(&(mip->mi_rw_lock));

	if (margin_needed <= margin)
		i_mac_notify(mip, MAC_NOTE_MARGIN);

	return (margin_needed <= margin);
}

/*
 * MAC Type Plugin functions.
 */

mactype_t *
mactype_getplugin(const char *pname)
{
	mactype_t	*mtype = NULL;
	boolean_t	tried_modload = B_FALSE;

	mutex_enter(&i_mactype_lock);

find_registered_mactype:
	if (mod_hash_find(i_mactype_hash, (mod_hash_key_t)pname,
	    (mod_hash_val_t *)&mtype) != 0) {
		if (!tried_modload) {
			/*
			 * If the plugin has not yet been loaded, then
			 * attempt to load it now.  If modload() succeeds,
			 * the plugin should have registered using
			 * mactype_register(), in which case we can go back
			 * and attempt to find it again.
			 */
			if (modload(MACTYPE_KMODDIR, (char *)pname) != -1) {
				tried_modload = B_TRUE;
				goto find_registered_mactype;
			}
		}
	} else {
		/*
		 * Note that there's no danger that the plugin we've loaded
		 * could be unloaded between the modload() step and the
		 * reference count bump here, as we're holding
		 * i_mactype_lock, which mactype_unregister() also holds.
		 */
		atomic_inc_32(&mtype->mt_ref);
	}

	mutex_exit(&i_mactype_lock);
	return (mtype);
}

mactype_register_t *
mactype_alloc(uint_t mactype_version)
{
	mactype_register_t *mtrp;

	/*
	 * Make sure there isn't a version mismatch between the plugin and
	 * the framework.  In the future, if multiple versions are
	 * supported, this check could become more sophisticated.
	 */
	if (mactype_version != MACTYPE_VERSION)
		return (NULL);

	mtrp = kmem_zalloc(sizeof (mactype_register_t), KM_SLEEP);
	mtrp->mtr_version = mactype_version;
	return (mtrp);
}

void
mactype_free(mactype_register_t *mtrp)
{
	kmem_free(mtrp, sizeof (mactype_register_t));
}

int
mactype_register(mactype_register_t *mtrp)
{
	mactype_t	*mtp;
	mactype_ops_t	*ops = mtrp->mtr_ops;

	/* Do some sanity checking before we register this MAC type. */
	if (mtrp->mtr_ident == NULL || ops == NULL)
		return (EINVAL);

	/*
	 * Verify that all mandatory callbacks are set in the ops
	 * vector.
	 */
	if (ops->mtops_unicst_verify == NULL ||
	    ops->mtops_multicst_verify == NULL ||
	    ops->mtops_sap_verify == NULL ||
	    ops->mtops_header == NULL ||
	    ops->mtops_header_info == NULL) {
		return (EINVAL);
	}

	mtp = kmem_zalloc(sizeof (*mtp), KM_SLEEP);
	mtp->mt_ident = mtrp->mtr_ident;
	mtp->mt_ops = *ops;
	mtp->mt_type = mtrp->mtr_mactype;
	mtp->mt_nativetype = mtrp->mtr_nativetype;
	mtp->mt_addr_length = mtrp->mtr_addrlen;
	if (mtrp->mtr_brdcst_addr != NULL) {
		mtp->mt_brdcst_addr = kmem_alloc(mtrp->mtr_addrlen, KM_SLEEP);
		bcopy(mtrp->mtr_brdcst_addr, mtp->mt_brdcst_addr,
		    mtrp->mtr_addrlen);
	}

	mtp->mt_stats = mtrp->mtr_stats;
	mtp->mt_statcount = mtrp->mtr_statcount;

	mtp->mt_mapping = mtrp->mtr_mapping;
	mtp->mt_mappingcount = mtrp->mtr_mappingcount;

	if (mod_hash_insert(i_mactype_hash,
	    (mod_hash_key_t)mtp->mt_ident, (mod_hash_val_t)mtp) != 0) {
		kmem_free(mtp->mt_brdcst_addr, mtp->mt_addr_length);
		kmem_free(mtp, sizeof (*mtp));
		return (EEXIST);
	}
	return (0);
}

int
mactype_unregister(const char *ident)
{
	mactype_t	*mtp;
	mod_hash_val_t	val;
	int 		err;

	/*
	 * Let's not allow MAC drivers to use this plugin while we're
	 * trying to unregister it.  Holding i_mactype_lock also prevents a
	 * plugin from unregistering while a MAC driver is attempting to
	 * hold a reference to it in i_mactype_getplugin().
	 */
	mutex_enter(&i_mactype_lock);

	if ((err = mod_hash_find(i_mactype_hash, (mod_hash_key_t)ident,
	    (mod_hash_val_t *)&mtp)) != 0) {
		/* A plugin is trying to unregister, but it never registered. */
		err = ENXIO;
		goto done;
	}

	if (mtp->mt_ref != 0) {
		err = EBUSY;
		goto done;
	}

	err = mod_hash_remove(i_mactype_hash, (mod_hash_key_t)ident, &val);
	ASSERT(err == 0);
	if (err != 0) {
		/* This should never happen, thus the ASSERT() above. */
		err = EINVAL;
		goto done;
	}
	ASSERT(mtp == (mactype_t *)val);

	kmem_free(mtp->mt_brdcst_addr, mtp->mt_addr_length);
	kmem_free(mtp, sizeof (mactype_t));
done:
	mutex_exit(&i_mactype_lock);
	return (err);
}

/*
 * Returns TRUE when the specified property is intended for the MAC framework,
 * as opposed to driver defined properties.
 */
static boolean_t
mac_is_macprop(mac_prop_t *macprop)
{
	switch (macprop->mp_id) {
	case MAC_PROP_MAXBW:
	case MAC_PROP_PRIO:
	case MAC_PROP_BIND_CPU:
		return (B_TRUE);
	default:
		return (B_FALSE);
	}
}

/*
 * mac_set_prop() sets mac or hardware driver properties:
 * 	mac properties include maxbw, priority, and cpu binding list. Driver
 *	properties are private properties to the hardware, such as mtu, speed
 *	etc.
 * If the property is a driver property, mac_set_prop() calls driver's callback
 * function to set it.
 * If the property is a mac property, mac_set_prop() invokes mac_set_resources()
 * which will cache the property value in mac_impl_t and may call
 * mac_client_set_resource() to update property value of the primary mac client,
 * if it exists.
 */
int
mac_set_prop(mac_handle_t mh, mac_prop_t *macprop, void *val, uint_t valsize)
{
	int err = ENOTSUP;
	mac_impl_t *mip = (mac_impl_t *)mh;

	ASSERT(MAC_PERIM_HELD(mh));

	/* If it is mac property, call mac_set_resources() */
	if (mac_is_macprop(macprop)) {
		mac_resource_props_t mrp;

		if (valsize < sizeof (mac_resource_props_t))
			return (EINVAL);
		bzero(&mrp, sizeof (mac_resource_props_t));
		bcopy(val, &mrp, sizeof (mrp));
		return (mac_set_resources(mh, &mrp));
	}
	/* For driver properties, call driver's callback */
	if (mip->mi_callbacks->mc_callbacks & MC_SETPROP) {
		err = mip->mi_callbacks->mc_setprop(mip->mi_driver,
		    macprop->mp_name, macprop->mp_id, valsize, val);
	}

	return (err);
}

/*
 * mac_get_prop() gets mac or hardware driver properties.
 *
 * If the property is a driver property, mac_get_prop() calls driver's callback
 * function to get it.
 * If the property is a mac property, mac_get_prop() invokes mac_get_resources()
 * which returns the cached value in mac_impl_t.
 */
int
mac_get_prop(mac_handle_t mh, mac_prop_t *macprop, void *val, uint_t valsize,
    uint_t *perm)
{
	int err = ENOTSUP;
	mac_impl_t *mip = (mac_impl_t *)mh;
	uint32_t sdu;
	link_state_t link_state;

	/* If mac property, read from cache */
	if (mac_is_macprop(macprop)) {
		mac_resource_props_t mrp;

		if (valsize < sizeof (mac_resource_props_t))
			return (EINVAL);
		bzero(&mrp, sizeof (mac_resource_props_t));
		mac_get_resources(mh, &mrp);
		bcopy(&mrp, val, sizeof (mac_resource_props_t));
		return (0);
	}

	switch (macprop->mp_id) {
	case MAC_PROP_MTU:
		if (valsize < sizeof (sdu))
			return (EINVAL);
		if ((macprop->mp_flags & MAC_PROP_DEFAULT) == 0) {
			mac_sdu_get(mh, NULL, &sdu);
			bcopy(&sdu, val, sizeof (sdu));
			if (mac_set_prop(mh, macprop, val, sizeof (sdu)) != 0)
				*perm = MAC_PROP_PERM_READ;
			else
				*perm = MAC_PROP_PERM_RW;
			return (0);
		} else {
			if (mip->mi_info.mi_media == DL_ETHER) {
				sdu = ETHERMTU;
				bcopy(&sdu, val, sizeof (sdu));
				return (0);
			}
			/*
			 * ask driver for its default.
			 */
			break;
		}
	case MAC_PROP_STATUS:
		if (valsize < sizeof (link_state))
			return (EINVAL);
		*perm = MAC_PROP_PERM_READ;
		link_state = mac_link_get(mh);
		bcopy(&link_state, val, sizeof (link_state));
		return (0);
	default:
		break;

	}
	/* If driver property, request from driver */
	if (mip->mi_callbacks->mc_callbacks & MC_GETPROP) {
		err = mip->mi_callbacks->mc_getprop(mip->mi_driver,
		    macprop->mp_name, macprop->mp_id, macprop->mp_flags,
		    valsize, val, perm);
	}
	return (err);
}

void
mac_register_priv_prop(mac_impl_t *mip, mac_priv_prop_t *mpp, uint_t nprop)
{
	mac_priv_prop_t *mpriv;

	if (mpp == NULL)
		return;

	mpriv = kmem_zalloc(nprop * sizeof (*mpriv), KM_SLEEP);
	(void) memcpy(mpriv, mpp, nprop * sizeof (*mpriv));
	mip->mi_priv_prop = mpriv;
	mip->mi_priv_prop_count = nprop;
}

void
mac_unregister_priv_prop(mac_impl_t *mip)
{
	mac_priv_prop_t	*mpriv;

	mpriv = mip->mi_priv_prop;
	if (mpriv != NULL) {
		kmem_free(mpriv, mip->mi_priv_prop_count * sizeof (*mpriv));
		mip->mi_priv_prop = NULL;
	}
	mip->mi_priv_prop_count = 0;
}

/*
 * mac_ring_t 'mr' macros. Some rogue drivers may access ring structure
 * (by invoking mac_rx()) even after processing mac_stop_ring(). In such
 * cases if MAC free's the ring structure after mac_stop_ring(), any
 * illegal access to the ring structure coming from the driver will panic
 * the system. In order to protect the system from such inadverent access,
 * we maintain a cache of rings in the mac_impl_t after they get free'd up.
 * When packets are received on free'd up rings, MAC (through the generation
 * count mechanism) will drop such packets.
 */
static mac_ring_t *
mac_ring_alloc(mac_impl_t *mip, mac_capab_rings_t *cap_rings)
{
	mac_ring_t *ring;

	if (cap_rings->mr_type == MAC_RING_TYPE_RX) {
		mutex_enter(&mip->mi_ring_lock);
		if (mip->mi_ring_freelist != NULL) {
			ring = mip->mi_ring_freelist;
			mip->mi_ring_freelist = ring->mr_next;
			bzero(ring, sizeof (mac_ring_t));
		} else {
			ring = kmem_cache_alloc(mac_ring_cache, KM_SLEEP);
		}
		mutex_exit(&mip->mi_ring_lock);
	} else {
		ring = kmem_zalloc(sizeof (mac_ring_t), KM_SLEEP);
	}
	ASSERT((ring != NULL) && (ring->mr_state == MR_FREE));
	return (ring);
}

static void
mac_ring_free(mac_impl_t *mip, mac_ring_t *ring)
{
	if (ring->mr_type == MAC_RING_TYPE_RX) {
		mutex_enter(&mip->mi_ring_lock);
		ring->mr_state = MR_FREE;
		ring->mr_flag = 0;
		ring->mr_next = mip->mi_ring_freelist;
		mip->mi_ring_freelist = ring;
		mutex_exit(&mip->mi_ring_lock);
	} else {
		kmem_free(ring, sizeof (mac_ring_t));
	}
}

static void
mac_ring_freeall(mac_impl_t *mip)
{
	mac_ring_t *ring_next;
	mutex_enter(&mip->mi_ring_lock);
	mac_ring_t *ring = mip->mi_ring_freelist;
	while (ring != NULL) {
		ring_next = ring->mr_next;
		kmem_cache_free(mac_ring_cache, ring);
		ring = ring_next;
	}
	mip->mi_ring_freelist = NULL;
	mutex_exit(&mip->mi_ring_lock);
}

int
mac_start_ring(mac_ring_t *ring)
{
	int rv = 0;

	if (ring->mr_start != NULL)
		rv = ring->mr_start(ring->mr_driver, ring->mr_gen_num);

	return (rv);
}

void
mac_stop_ring(mac_ring_t *ring)
{
	if (ring->mr_stop != NULL)
		ring->mr_stop(ring->mr_driver);

	/*
	 * Increment the ring generation number for this ring.
	 */
	ring->mr_gen_num++;
}

int
mac_start_group(mac_group_t *group)
{
	int rv = 0;

	if (group->mrg_start != NULL)
		rv = group->mrg_start(group->mrg_driver);

	return (rv);
}

void
mac_stop_group(mac_group_t *group)
{
	if (group->mrg_stop != NULL)
		group->mrg_stop(group->mrg_driver);
}

/*
 * Called from mac_start() on the default Rx group. Broadcast and multicast
 * packets are received only on the default group. Hence the default group
 * needs to be up even if the primary client is not up, for the other groups
 * to be functional. We do this by calling this function at mac_start time
 * itself. However the broadcast packets that are received can't make their
 * way beyond mac_rx until a mac client creates a broadcast flow.
 */
static int
mac_start_group_and_rings(mac_group_t *group)
{
	mac_ring_t	*ring;
	int		rv = 0;

	ASSERT(group->mrg_state == MAC_GROUP_STATE_REGISTERED);
	if ((rv = mac_start_group(group)) != 0)
		return (rv);

	for (ring = group->mrg_rings; ring != NULL; ring = ring->mr_next) {
		ASSERT(ring->mr_state == MR_FREE);
		if ((rv = mac_start_ring(ring)) != 0)
			goto error;
		ring->mr_state = MR_INUSE;
		ring->mr_classify_type = MAC_SW_CLASSIFIER;
	}
	return (0);

error:
	mac_stop_group_and_rings(group);
	return (rv);
}

/* Called from mac_stop on the default Rx group */
static void
mac_stop_group_and_rings(mac_group_t *group)
{
	mac_ring_t	*ring;

	for (ring = group->mrg_rings; ring != NULL; ring = ring->mr_next) {
		if (ring->mr_state != MR_FREE) {
			mac_stop_ring(ring);
			ring->mr_state = MR_FREE;
			ring->mr_flag = 0;
			ring->mr_classify_type = MAC_NO_CLASSIFIER;
		}
	}
	mac_stop_group(group);
}


static mac_ring_t *
mac_init_ring(mac_impl_t *mip, mac_group_t *group, int index,
    mac_capab_rings_t *cap_rings)
{
	mac_ring_t *ring;
	mac_ring_info_t ring_info;

	ring = mac_ring_alloc(mip, cap_rings);

	/* Prepare basic information of ring */
	ring->mr_index = index;
	ring->mr_type = group->mrg_type;
	ring->mr_gh = (mac_group_handle_t)group;

	/* Insert the new ring to the list. */
	ring->mr_next = group->mrg_rings;
	group->mrg_rings = ring;

	/* Zero to reuse the info data structure */
	bzero(&ring_info, sizeof (ring_info));

	/* Query ring information from driver */
	cap_rings->mr_rget(mip->mi_driver, group->mrg_type, group->mrg_index,
	    index, &ring_info, (mac_ring_handle_t)ring);

	ring->mr_info = ring_info;

	/* Update ring's status */
	ring->mr_state = MR_FREE;
	ring->mr_flag = 0;

	/* Update the ring count of the group */
	group->mrg_cur_count++;
	return (ring);
}

/*
 * Rings are chained together for easy regrouping.
 */
static void
mac_init_group(mac_impl_t *mip, mac_group_t *group, int size,
    mac_capab_rings_t *cap_rings)
{
	int index;

	/*
	 * Initialize all ring members of this group. Size of zero will not
	 * enter the loop, so it's safe for initializing an empty group.
	 */
	for (index = size - 1; index >= 0; index--)
		(void) mac_init_ring(mip, group, index, cap_rings);
}

int
mac_init_rings(mac_impl_t *mip, mac_ring_type_t rtype)
{
	mac_capab_rings_t *cap_rings;
	mac_group_t *group, *groups;
	mac_group_info_t group_info;
	uint_t group_free = 0;
	uint_t ring_left;
	mac_ring_t *ring;
	int g, err = 0;

	switch (rtype) {
	case MAC_RING_TYPE_RX:
		ASSERT(mip->mi_rx_groups == NULL);

		cap_rings = &mip->mi_rx_rings_cap;
		cap_rings->mr_type = MAC_RING_TYPE_RX;
		break;
	case MAC_RING_TYPE_TX:
		ASSERT(mip->mi_tx_groups == NULL);

		cap_rings = &mip->mi_tx_rings_cap;
		cap_rings->mr_type = MAC_RING_TYPE_TX;
		break;
	default:
		ASSERT(B_FALSE);
	}

	if (!i_mac_capab_get((mac_handle_t)mip, MAC_CAPAB_RINGS,
	    cap_rings))
		return (0);

	/*
	 * Allocate a contiguous buffer for all groups.
	 */
	groups = kmem_zalloc(sizeof (mac_group_t) * (cap_rings->mr_gnum + 1),
	    KM_SLEEP);

	ring_left = cap_rings->mr_rnum;

	/*
	 * Get all ring groups if any, and get their ring members
	 * if any.
	 */
	for (g = 0; g < cap_rings->mr_gnum; g++) {
		group = groups + g;

		/* Prepare basic information of the group */
		group->mrg_index = g;
		group->mrg_type = rtype;
		group->mrg_state = MAC_GROUP_STATE_UNINIT;
		group->mrg_mh = (mac_handle_t)mip;
		group->mrg_next = group + 1;

		/* Zero to reuse the info data structure */
		bzero(&group_info, sizeof (group_info));

		/* Query group information from driver */
		cap_rings->mr_gget(mip->mi_driver, rtype, g, &group_info,
		    (mac_group_handle_t)group);

		switch (cap_rings->mr_group_type) {
		case MAC_GROUP_TYPE_DYNAMIC:
			if (cap_rings->mr_gaddring == NULL ||
			    cap_rings->mr_gremring == NULL) {
				DTRACE_PROBE3(
				    mac__init__rings_no_addremring,
				    char *, mip->mi_name,
				    mac_group_add_ring_t,
				    cap_rings->mr_gaddring,
				    mac_group_add_ring_t,
				    cap_rings->mr_gremring);
				err = EINVAL;
				goto bail;
			}

			switch (rtype) {
			case MAC_RING_TYPE_RX:
				/*
				 * The first RX group must have non-zero
				 * rings, and the following groups must
				 * have zero rings.
				 */
				if (g == 0 && group_info.mgi_count == 0) {
					DTRACE_PROBE1(
					    mac__init__rings__rx__def__zero,
					    char *, mip->mi_name);
					err = EINVAL;
					goto bail;
				}
				if (g > 0 && group_info.mgi_count != 0) {
					DTRACE_PROBE3(
					    mac__init__rings__rx__nonzero,
					    char *, mip->mi_name,
					    int, g, int, group_info.mgi_count);
					err = EINVAL;
					goto bail;
				}
				break;
			case MAC_RING_TYPE_TX:
				/*
				 * All TX ring groups must have zero rings.
				 */
				if (group_info.mgi_count != 0) {
					DTRACE_PROBE3(
					    mac__init__rings__tx__nonzero,
					    char *, mip->mi_name,
					    int, g, int, group_info.mgi_count);
					err = EINVAL;
					goto bail;
				}
				break;
			}
			break;
		case MAC_GROUP_TYPE_STATIC:
			/*
			 * Note that an empty group is allowed, e.g., an aggr
			 * would start with an empty group.
			 */
			break;
		default:
			/* unknown group type */
			DTRACE_PROBE2(mac__init__rings__unknown__type,
			    char *, mip->mi_name,
			    int, cap_rings->mr_group_type);
			err = EINVAL;
			goto bail;
		}


		/*
		 * Driver must register group->mgi_addmac/remmac() for rx groups
		 * to support multiple MAC addresses.
		 */
		if (rtype == MAC_RING_TYPE_RX) {
			if ((group_info.mgi_addmac == NULL) ||
			    (group_info.mgi_addmac == NULL))
				goto bail;
		}

		/* Cache driver-supplied information */
		group->mrg_info = group_info;

		/* Update the group's status and group count. */
		mac_set_rx_group_state(group, MAC_GROUP_STATE_REGISTERED);
		group_free++;

		group->mrg_rings = NULL;
		group->mrg_cur_count = 0;
		mac_init_group(mip, group, group_info.mgi_count, cap_rings);
		ring_left -= group_info.mgi_count;

		/* The current group size should be equal to default value */
		ASSERT(group->mrg_cur_count == group_info.mgi_count);
	}

	/* Build up a dummy group for free resources as a pool */
	group = groups + cap_rings->mr_gnum;

	/* Prepare basic information of the group */
	group->mrg_index = -1;
	group->mrg_type = rtype;
	group->mrg_state = MAC_GROUP_STATE_UNINIT;
	group->mrg_mh = (mac_handle_t)mip;
	group->mrg_next = NULL;

	/*
	 * If there are ungrouped rings, allocate a continuous buffer for
	 * remaining resources.
	 */
	if (ring_left != 0) {
		group->mrg_rings = NULL;
		group->mrg_cur_count = 0;
		mac_init_group(mip, group, ring_left, cap_rings);

		/* The current group size should be equal to ring_left */
		ASSERT(group->mrg_cur_count == ring_left);

		ring_left = 0;

		/* Update this group's status */
		mac_set_rx_group_state(group, MAC_GROUP_STATE_REGISTERED);
	} else
		group->mrg_rings = NULL;

	ASSERT(ring_left == 0);

bail:
	/* Cache other important information to finalize the initialization */
	switch (rtype) {
	case MAC_RING_TYPE_RX:
		mip->mi_rx_group_type = cap_rings->mr_group_type;
		mip->mi_rx_group_count = cap_rings->mr_gnum;
		mip->mi_rx_groups = groups;
		break;
	case MAC_RING_TYPE_TX:
		mip->mi_tx_group_type = cap_rings->mr_group_type;
		mip->mi_tx_group_count = cap_rings->mr_gnum;
		mip->mi_tx_group_free = group_free;
		mip->mi_tx_groups = groups;

		/*
		 * Ring 0 is used as the default one and it could be assigned
		 * to a client as well.
		 */
		group = groups + cap_rings->mr_gnum;
		ring = group->mrg_rings;
		while ((ring->mr_index != 0) && (ring->mr_next != NULL))
			ring = ring->mr_next;
		ASSERT(ring->mr_index == 0);
		mip->mi_default_tx_ring = (mac_ring_handle_t)ring;
		break;
	default:
		ASSERT(B_FALSE);
	}

	if (err != 0)
		mac_free_rings(mip, rtype);

	return (err);
}

/*
 * Called to free all ring groups with particular type. It's supposed all groups
 * have been released by clinet.
 */
void
mac_free_rings(mac_impl_t *mip, mac_ring_type_t rtype)
{
	mac_group_t *group, *groups;
	uint_t group_count;

	switch (rtype) {
	case MAC_RING_TYPE_RX:
		if (mip->mi_rx_groups == NULL)
			return;

		groups = mip->mi_rx_groups;
		group_count = mip->mi_rx_group_count;

		mip->mi_rx_groups = NULL;
		mip->mi_rx_group_count = 0;
		break;
	case MAC_RING_TYPE_TX:
		ASSERT(mip->mi_tx_group_count == mip->mi_tx_group_free);

		if (mip->mi_tx_groups == NULL)
			return;

		groups = mip->mi_tx_groups;
		group_count = mip->mi_tx_group_count;

		mip->mi_tx_groups = NULL;
		mip->mi_tx_group_count = 0;
		mip->mi_tx_group_free = 0;
		mip->mi_default_tx_ring = NULL;
		break;
	default:
		ASSERT(B_FALSE);
	}

	for (group = groups; group != NULL; group = group->mrg_next) {
		mac_ring_t *ring;

		if (group->mrg_cur_count == 0)
			continue;

		ASSERT(group->mrg_rings != NULL);

		while ((ring = group->mrg_rings) != NULL) {
			group->mrg_rings = ring->mr_next;
			mac_ring_free(mip, ring);
		}
	}

	/* Free all the cached rings */
	mac_ring_freeall(mip);
	/* Free the block of group data strutures */
	kmem_free(groups, sizeof (mac_group_t) * (group_count + 1));
}

/*
 * Associate a MAC address with a receive group.
 *
 * The return value of this function should always be checked properly, because
 * any type of failure could cause unexpected results. A group can be added
 * or removed with a MAC address only after it has been reserved. Ideally,
 * a successful reservation always leads to calling mac_group_addmac() to
 * steer desired traffic. Failure of adding an unicast MAC address doesn't
 * always imply that the group is functioning abnormally.
 *
 * Currently this function is called everywhere, and it reflects assumptions
 * about MAC addresses in the implementation. CR 6735196.
 */
int
mac_group_addmac(mac_group_t *group, const uint8_t *addr)
{
	ASSERT(group->mrg_type == MAC_RING_TYPE_RX);
	ASSERT(group->mrg_info.mgi_addmac != NULL);

	return (group->mrg_info.mgi_addmac(group->mrg_info.mgi_driver, addr));
}

/*
 * Remove the association between MAC address and receive group.
 */
int
mac_group_remmac(mac_group_t *group, const uint8_t *addr)
{
	ASSERT(group->mrg_type == MAC_RING_TYPE_RX);
	ASSERT(group->mrg_info.mgi_remmac != NULL);

	return (group->mrg_info.mgi_remmac(group->mrg_info.mgi_driver, addr));
}

/*
 * Release a ring in use by marking it MR_FREE.
 * Any other client may reserve it for its use.
 */
void
mac_release_tx_ring(mac_ring_handle_t rh)
{
	mac_ring_t *ring = (mac_ring_t *)rh;
	mac_group_t *group = (mac_group_t *)ring->mr_gh;
	mac_impl_t *mip = (mac_impl_t *)group->mrg_mh;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));
	ASSERT(ring->mr_state != MR_FREE);

	/*
	 * Default tx ring will be released by mac_stop().
	 */
	if (rh == mip->mi_default_tx_ring)
		return;

	mac_stop_ring(ring);

	ring->mr_state = MR_FREE;
	ring->mr_flag = 0;
}

/*
 * Send packets through a selected tx ring.
 */
mblk_t *
mac_ring_tx(mac_ring_handle_t rh, mblk_t *mp)
{
	mac_ring_t *ring = (mac_ring_t *)rh;
	mac_ring_info_t *info = &ring->mr_info;

	ASSERT(ring->mr_type == MAC_RING_TYPE_TX);
	ASSERT(ring->mr_state >= MR_INUSE);
	ASSERT(info->mri_tx != NULL);

	return (info->mri_tx(info->mri_driver, mp));
}

/*
 * Find a ring from its index.
 */
mac_ring_t *
mac_find_ring(mac_group_t *group, int index)
{
	mac_ring_t *ring = group->mrg_rings;

	for (ring = group->mrg_rings; ring != NULL; ring = ring->mr_next)
		if (ring->mr_index == index)
			break;

	return (ring);
}
/*
 * Add a ring to an existing group.
 *
 * The ring must be either passed directly (for example if the ring
 * movement is initiated by the framework), or specified through a driver
 * index (for example when the ring is added by the driver.
 *
 * The caller needs to call mac_perim_enter() before calling this function.
 */
int
i_mac_group_add_ring(mac_group_t *group, mac_ring_t *ring, int index)
{
	mac_impl_t *mip = (mac_impl_t *)group->mrg_mh;
	mac_capab_rings_t *cap_rings;
	boolean_t driver_call = (ring == NULL);
	mac_group_type_t group_type;
	int ret = 0;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	switch (group->mrg_type) {
	case MAC_RING_TYPE_RX:
		cap_rings = &mip->mi_rx_rings_cap;
		group_type = mip->mi_rx_group_type;
		break;
	case MAC_RING_TYPE_TX:
		cap_rings = &mip->mi_tx_rings_cap;
		group_type = mip->mi_tx_group_type;
		break;
	default:
		ASSERT(B_FALSE);
	}

	/*
	 * There should be no ring with the same ring index in the target
	 * group.
	 */
	ASSERT(mac_find_ring(group, driver_call ? index : ring->mr_index) ==
	    NULL);

	if (driver_call) {
		/*
		 * The function is called as a result of a request from
		 * a driver to add a ring to an existing group, for example
		 * from the aggregation driver. Allocate a new mac_ring_t
		 * for that ring.
		 */
		ring = mac_init_ring(mip, group, index, cap_rings);
		ASSERT(group->mrg_state > MAC_GROUP_STATE_UNINIT);
	} else {
		/*
		 * The function is called as a result of a MAC layer request
		 * to add a ring to an existing group. In this case the
		 * ring is being moved between groups, which requires
		 * the underlying driver to support dynamic grouping,
		 * and the mac_ring_t already exists.
		 */
		ASSERT(group_type == MAC_GROUP_TYPE_DYNAMIC);
		ASSERT(cap_rings->mr_gaddring != NULL);
		ASSERT(ring->mr_gh == NULL);
	}

	/*
	 * At this point the ring should not be in use, and it should be
	 * of the right for the target group.
	 */
	ASSERT(ring->mr_state < MR_INUSE);
	ASSERT(ring->mr_srs == NULL);
	ASSERT(ring->mr_type == group->mrg_type);

	if (!driver_call) {
		/*
		 * Add the driver level hardware ring if the process was not
		 * initiated by the driver, and the target group is not the
		 * group.
		 */
		if (group->mrg_driver != NULL) {
			cap_rings->mr_gaddring(group->mrg_driver,
			    ring->mr_driver, ring->mr_type);
		}

		/*
		 * Insert the ring ahead existing rings.
		 */
		ring->mr_next = group->mrg_rings;
		group->mrg_rings = ring;
		ring->mr_gh = (mac_group_handle_t)group;
		group->mrg_cur_count++;
	}

	/*
	 * If the group has not been actively used, we're done.
	 */
	if (group->mrg_index != -1 &&
	    group->mrg_state < MAC_GROUP_STATE_RESERVED)
		return (0);

	/*
	 * Set up SRS/SR according to the ring type.
	 */
	switch (ring->mr_type) {
	case MAC_RING_TYPE_RX:
		/*
		 * Setup SRS on top of the new ring if the group is
		 * reserved for someones exclusive use.
		 */
		if (group->mrg_state == MAC_GROUP_STATE_RESERVED) {
			flow_entry_t *flent;
			mac_client_impl_t *mcip;

			mcip = MAC_RX_GROUP_ONLY_CLIENT(group);
			ASSERT(mcip != NULL);
			flent = mcip->mci_flent;
			ASSERT(flent->fe_rx_srs_cnt > 0);
			mac_srs_group_setup(mcip, flent, group, SRST_LINK);
		}
		break;
	case MAC_RING_TYPE_TX:
		/*
		 * For TX this function is only invoked during the
		 * initial creation of a group when a share is
		 * associated with a MAC client. So the datapath is not
		 * yet setup, and will be setup later after the
		 * group has been reserved and populated.
		 */
		break;
	default:
		ASSERT(B_FALSE);
	}

	/*
	 * Start the ring if needed. Failure causes to undo the grouping action.
	 */
	if ((ret = mac_start_ring(ring)) != 0) {
		if (ring->mr_type == MAC_RING_TYPE_RX) {
			if (ring->mr_srs != NULL) {
				mac_rx_srs_remove(ring->mr_srs);
				ring->mr_srs = NULL;
			}
		}
		if (!driver_call) {
			cap_rings->mr_gremring(group->mrg_driver,
			    ring->mr_driver, ring->mr_type);
		}
		group->mrg_cur_count--;
		group->mrg_rings = ring->mr_next;

		ring->mr_gh = NULL;

		if (driver_call)
			mac_ring_free(mip, ring);

		return (ret);
	}

	/*
	 * Update the ring's state.
	 */
	ring->mr_state = MR_INUSE;
	MAC_RING_UNMARK(ring, MR_INCIPIENT);
	return (0);
}

/*
 * Remove a ring from it's current group. MAC internal function for dynamic
 * grouping.
 *
 * The caller needs to call mac_perim_enter() before calling this function.
 */
void
i_mac_group_rem_ring(mac_group_t *group, mac_ring_t *ring,
    boolean_t driver_call)
{
	mac_impl_t *mip = (mac_impl_t *)group->mrg_mh;
	mac_capab_rings_t *cap_rings = NULL;
	mac_group_type_t group_type;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	ASSERT(mac_find_ring(group, ring->mr_index) == ring);
	ASSERT((mac_group_t *)ring->mr_gh == group);
	ASSERT(ring->mr_type == group->mrg_type);

	switch (ring->mr_type) {
	case MAC_RING_TYPE_RX:
		group_type = mip->mi_rx_group_type;
		cap_rings = &mip->mi_rx_rings_cap;

		if (group->mrg_state >= MAC_GROUP_STATE_RESERVED)
			mac_stop_ring(ring);

		/*
		 * Only hardware classified packets hold a reference to the
		 * ring all the way up the Rx path. mac_rx_srs_remove()
		 * will take care of quiescing the Rx path and removing the
		 * SRS. The software classified path neither holds a reference
		 * nor any association with the ring in mac_rx.
		 */
		if (ring->mr_srs != NULL) {
			mac_rx_srs_remove(ring->mr_srs);
			ring->mr_srs = NULL;
		}
		ring->mr_state = MR_FREE;
		ring->mr_flag = 0;

		break;
	case MAC_RING_TYPE_TX:
		/*
		 * For TX this function is only invoked in two
		 * cases:
		 *
		 * 1) In the case of a failure during the
		 * initial creation of a group when a share is
		 * associated with a MAC client. So the SRS is not
		 * yet setup, and will be setup later after the
		 * group has been reserved and populated.
		 *
		 * 2) From mac_release_tx_group() when freeing
		 * a TX SRS.
		 *
		 * In both cases the SRS and its soft rings are
		 * already quiesced.
		 */
		ASSERT(!driver_call);
		group_type = mip->mi_tx_group_type;
		cap_rings = &mip->mi_tx_rings_cap;
		break;
	default:
		ASSERT(B_FALSE);
	}

	/*
	 * Remove the ring from the group.
	 */
	if (ring == group->mrg_rings)
		group->mrg_rings = ring->mr_next;
	else {
		mac_ring_t *pre;

		pre = group->mrg_rings;
		while (pre->mr_next != ring)
			pre = pre->mr_next;
		pre->mr_next = ring->mr_next;
	}
	group->mrg_cur_count--;

	if (!driver_call) {
		ASSERT(group_type == MAC_GROUP_TYPE_DYNAMIC);
		ASSERT(cap_rings->mr_gremring != NULL);

		/*
		 * Remove the driver level hardware ring.
		 */
		if (group->mrg_driver != NULL) {
			cap_rings->mr_gremring(group->mrg_driver,
			    ring->mr_driver, ring->mr_type);
		}
	}

	ring->mr_gh = NULL;
	if (driver_call) {
		mac_ring_free(mip, ring);
	} else {
		ring->mr_state = MR_FREE;
		ring->mr_flag = 0;
	}
}

/*
 * Move a ring to the target group. If needed, remove the ring from the group
 * that it currently belongs to.
 *
 * The caller need to enter MAC's perimeter by calling mac_perim_enter().
 */
static int
mac_group_mov_ring(mac_impl_t *mip, mac_group_t *d_group, mac_ring_t *ring)
{
	mac_group_t *s_group = (mac_group_t *)ring->mr_gh;
	int rv;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));
	ASSERT(d_group != NULL);
	ASSERT(s_group->mrg_mh == d_group->mrg_mh);

	if (s_group == d_group)
		return (0);

	/*
	 * Remove it from current group first.
	 */
	if (s_group != NULL)
		i_mac_group_rem_ring(s_group, ring, B_FALSE);

	/*
	 * Add it to the new group.
	 */
	rv = i_mac_group_add_ring(d_group, ring, 0);
	if (rv != 0) {
		/*
		 * Failed to add ring back to source group. If
		 * that fails, the ring is stuck in limbo, log message.
		 */
		if (i_mac_group_add_ring(s_group, ring, 0)) {
			cmn_err(CE_WARN, "%s: failed to move ring %p\n",
			    mip->mi_name, (void *)ring);
		}
	}

	return (rv);
}

/*
 * Find a MAC address according to its value.
 */
mac_address_t *
mac_find_macaddr(mac_impl_t *mip, uint8_t *mac_addr)
{
	mac_address_t *map;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	for (map = mip->mi_addresses; map != NULL; map = map->ma_next) {
		if (bcmp(mac_addr, map->ma_addr, map->ma_len) == 0)
			break;
	}

	return (map);
}

/*
 * Check whether the MAC address is shared by multiple clients.
 */
boolean_t
mac_check_macaddr_shared(mac_address_t *map)
{
	ASSERT(MAC_PERIM_HELD((mac_handle_t)map->ma_mip));

	return (map->ma_nusers > 1);
}

/*
 * Enable a MAC address by enabling promiscuous mode.
 */
static int
mac_add_macaddr_promisc(mac_impl_t *mip, mac_group_t *group)
{
	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	/*
	 * Current interface only allow to set promiscuous mode with the
	 * default group. Note, mip->mi_rx_groups might be NULL.
	 */
	ASSERT(group == mip->mi_rx_groups);

	if (group == mip->mi_rx_groups)
		return (i_mac_promisc_set(mip, B_TRUE, MAC_DEVPROMISC));
	else
		return (ENOTSUP);
}

/*
 * Remove a MAC address that was added by enabling promiscuous mode.
 */
static int
mac_remove_macaddr_promisc(mac_impl_t *mip, mac_group_t *group)
{
	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));
	ASSERT(group == mip->mi_rx_groups);

	return (i_mac_promisc_set(mip, B_FALSE, MAC_DEVPROMISC));
}

/*
 * Remove the specified MAC address from the MAC address list and free it.
 */
static void
mac_free_macaddr(mac_address_t *map)
{
	mac_impl_t *mip = map->ma_mip;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));
	ASSERT(mip->mi_addresses != NULL);

	map = mac_find_macaddr(mip, map->ma_addr);

	ASSERT(map != NULL);
	ASSERT(map->ma_nusers == 0);

	if (map == mip->mi_addresses) {
		mip->mi_addresses = map->ma_next;
	} else {
		mac_address_t *pre;

		pre = mip->mi_addresses;
		while (pre->ma_next != map)
			pre = pre->ma_next;
		pre->ma_next = map->ma_next;
	}

	kmem_free(map, sizeof (mac_address_t));
}

/*
 * Add a MAC address reference for a client. If the desired MAC address
 * exists, add a reference to it. Otherwise, add the new address by adding
 * it to a reserved group or setting promiscuous mode. Won't try different
 * group is the group is non-NULL, so the caller must explictly share
 * default group when needed.
 *
 * Note, the primary MAC address is initialized at registration time, so
 * to add it to default group only need to activate it if its reference
 * count is still zero. Also, some drivers may not have advertised RINGS
 * capability.
 */
int
mac_add_macaddr(mac_impl_t *mip, mac_group_t *group, uint8_t *mac_addr)
{
	mac_address_t *map;
	int err = 0;
	boolean_t allocated_map = B_FALSE;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	map = mac_find_macaddr(mip, mac_addr);

	/*
	 * If the new MAC address has not been added. Allocate a new one
	 * and set it up.
	 */
	if (map == NULL) {
		map = kmem_zalloc(sizeof (mac_address_t), KM_SLEEP);
		map->ma_len = mip->mi_type->mt_addr_length;
		bcopy(mac_addr, map->ma_addr, map->ma_len);
		map->ma_nusers = 0;
		map->ma_group = group;
		map->ma_mip = mip;

		/* add the new MAC address to the head of the address list */
		map->ma_next = mip->mi_addresses;
		mip->mi_addresses = map;

		allocated_map = B_TRUE;
	}

	ASSERT(map->ma_group == group);

	/*
	 * If the MAC address is already in use, simply account for the
	 * new client.
	 */
	if (map->ma_nusers++ > 0)
		return (0);

	/*
	 * Activate this MAC address by adding it to the reserved group.
	 */
	if (group != NULL) {
		err = mac_group_addmac(group, (const uint8_t *)mac_addr);
		if (err == 0) {
			map->ma_type = MAC_ADDRESS_TYPE_UNICAST_CLASSIFIED;
			return (0);
		}
	}

	/*
	 * Try promiscuous mode. Note that rx_groups could be NULL, so we
	 * need to handle drivers that don't advertise the RINGS capability.
	 */
	if (group == mip->mi_rx_groups) {
		/*
		 * For drivers that don't advertise RINGS capability, do
		 * nothing for the primary address.
		 */
		if ((group == NULL) &&
		    (bcmp(map->ma_addr, mip->mi_addr, map->ma_len) == 0)) {
			map->ma_type = MAC_ADDRESS_TYPE_UNICAST_CLASSIFIED;
			return (0);
		}

		/*
		 * Enable promiscuous mode in order to receive traffic
		 * to the new MAC address.
		 */
		err = mac_add_macaddr_promisc(mip, group);
		if (err == 0) {
			map->ma_type = MAC_ADDRESS_TYPE_UNICAST_PROMISC;
			return (0);
		}
	}

	/*
	 * Free the MAC address that could not be added. Don't free
	 * a pre-existing address, it could have been the entry
	 * for the primary MAC address which was pre-allocated by
	 * mac_init_macaddr(), and which must remain on the list.
	 */
	map->ma_nusers--;
	if (allocated_map)
		mac_free_macaddr(map);
	return (err);
}

/*
 * Remove a reference to a MAC address. This may cause to remove the MAC
 * address from an associated group or to turn off promiscuous mode.
 * The caller needs to handle the failure properly.
 */
int
mac_remove_macaddr(mac_address_t *map)
{
	mac_impl_t *mip = map->ma_mip;
	int err = 0;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	ASSERT(map == mac_find_macaddr(mip, map->ma_addr));

	/*
	 * If it's not the last client using this MAC address, only update
	 * the MAC clients count.
	 */
	if (--map->ma_nusers > 0)
		return (0);

	/*
	 * The MAC address is no longer used by any MAC client, so remove
	 * it from its associated group, or turn off promiscuous mode
	 * if it was enabled for the MAC address.
	 */
	switch (map->ma_type) {
	case MAC_ADDRESS_TYPE_UNICAST_CLASSIFIED:
		/*
		 * Don't free the preset primary address for drivers that
		 * don't advertise RINGS capability.
		 */
		if (map->ma_group == NULL)
			return (0);

		err = mac_group_remmac(map->ma_group, map->ma_addr);
		break;
	case MAC_ADDRESS_TYPE_UNICAST_PROMISC:
		err = mac_remove_macaddr_promisc(mip, map->ma_group);
		break;
	default:
		ASSERT(B_FALSE);
	}

	if (err != 0)
		return (err);

	/*
	 * We created MAC address for the primary one at registration, so we
	 * won't free it here. mac_fini_macaddr() will take care of it.
	 */
	if (bcmp(map->ma_addr, mip->mi_addr, map->ma_len) != 0)
		mac_free_macaddr(map);

	return (0);
}

/*
 * Update an existing MAC address. The caller need to make sure that the new
 * value has not been used.
 */
int
mac_update_macaddr(mac_address_t *map, uint8_t *mac_addr)
{
	mac_impl_t *mip = map->ma_mip;
	int err = 0;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));
	ASSERT(mac_find_macaddr(mip, mac_addr) == NULL);

	switch (map->ma_type) {
	case MAC_ADDRESS_TYPE_UNICAST_CLASSIFIED:
		/*
		 * Update the primary address for drivers that are not
		 * RINGS capable.
		 */
		if (map->ma_group == NULL) {
			err = mip->mi_unicst(mip->mi_driver, (const uint8_t *)
			    mac_addr);
			if (err != 0)
				return (err);
			break;
		}

		/*
		 * If this MAC address is not currently in use,
		 * simply break out and update the value.
		 */
		if (map->ma_nusers == 0)
			break;

		/*
		 * Need to replace the MAC address associated with a group.
		 */
		err = mac_group_remmac(map->ma_group, map->ma_addr);
		if (err != 0)
			return (err);

		err = mac_group_addmac(map->ma_group, mac_addr);

		/*
		 * Failure hints hardware error. The MAC layer needs to
		 * have error notification facility to handle this.
		 * Now, simply try to restore the value.
		 */
		if (err != 0)
			(void) mac_group_addmac(map->ma_group, map->ma_addr);

		break;
	case MAC_ADDRESS_TYPE_UNICAST_PROMISC:
		/*
		 * Need to do nothing more if in promiscuous mode.
		 */
		break;
	default:
		ASSERT(B_FALSE);
	}

	/*
	 * Successfully replaced the MAC address.
	 */
	if (err == 0)
		bcopy(mac_addr, map->ma_addr, map->ma_len);

	return (err);
}

/*
 * Freshen the MAC address with new value. Its caller must have updated the
 * hardware MAC address before calling this function.
 * This funcitons is supposed to be used to handle the MAC address change
 * notification from underlying drivers.
 */
void
mac_freshen_macaddr(mac_address_t *map, uint8_t *mac_addr)
{
	mac_impl_t *mip = map->ma_mip;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));
	ASSERT(mac_find_macaddr(mip, mac_addr) == NULL);

	/*
	 * Freshen the MAC address with new value.
	 */
	bcopy(mac_addr, map->ma_addr, map->ma_len);
	bcopy(mac_addr, mip->mi_addr, map->ma_len);

	/*
	 * Update all MAC clients that share this MAC address.
	 */
	mac_unicast_update_clients(mip, map);
}

/*
 * Set up the primary MAC address.
 */
void
mac_init_macaddr(mac_impl_t *mip)
{
	mac_address_t *map;

	/*
	 * The reference count is initialized to zero, until it's really
	 * activated.
	 */
	map = kmem_zalloc(sizeof (mac_address_t), KM_SLEEP);
	map->ma_len = mip->mi_type->mt_addr_length;
	bcopy(mip->mi_addr, map->ma_addr, map->ma_len);

	/*
	 * If driver advertises RINGS capability, it shouldn't have initialized
	 * its primary MAC address. For other drivers, including VNIC, the
	 * primary address must work after registration.
	 */
	if (mip->mi_rx_groups == NULL)
		map->ma_type = MAC_ADDRESS_TYPE_UNICAST_CLASSIFIED;

	/*
	 * The primary MAC address is reserved for default group according
	 * to current design.
	 */
	map->ma_group = mip->mi_rx_groups;
	map->ma_mip = mip;

	mip->mi_addresses = map;
}

/*
 * Clean up the primary MAC address. Note, only one primary MAC address
 * is allowed. All other MAC addresses must have been freed appropriately.
 */
void
mac_fini_macaddr(mac_impl_t *mip)
{
	mac_address_t *map = mip->mi_addresses;

	/* there should be exactly one entry left on the list */
	ASSERT(map != NULL);
	ASSERT(map->ma_nusers == 0);
	ASSERT(map->ma_next == NULL);

	kmem_free(map, sizeof (mac_address_t));
	mip->mi_addresses = NULL;
}

/*
 * Logging related functions.
 */

/* Write the Flow description to the log file */
int
mac_write_flow_desc(flow_entry_t *flent, mac_client_impl_t *mcip)
{
	flow_desc_t		*fdesc;
	mac_resource_props_t	*mrp;
	net_desc_t		ndesc;

	bzero(&ndesc, sizeof (net_desc_t));

	/*
	 * Grab the fe_lock to see a self-consistent fe_flow_desc.
	 * Updates to the fe_flow_desc are done under the fe_lock
	 */
	mutex_enter(&flent->fe_lock);
	fdesc = &flent->fe_flow_desc;
	mrp = &flent->fe_resource_props;

	ndesc.nd_name = flent->fe_flow_name;
	ndesc.nd_devname = mcip->mci_name;
	bcopy(fdesc->fd_src_mac, ndesc.nd_ehost, ETHERADDRL);
	bcopy(fdesc->fd_dst_mac, ndesc.nd_edest, ETHERADDRL);
	ndesc.nd_sap = htonl(fdesc->fd_sap);
	ndesc.nd_isv4 = (uint8_t)fdesc->fd_ipversion == IPV4_VERSION;
	ndesc.nd_bw_limit = mrp->mrp_maxbw;
	if (ndesc.nd_isv4) {
		ndesc.nd_saddr[3] = htonl(fdesc->fd_local_addr.s6_addr32[3]);
		ndesc.nd_daddr[3] = htonl(fdesc->fd_remote_addr.s6_addr32[3]);
	} else {
		bcopy(&fdesc->fd_local_addr, ndesc.nd_saddr, IPV6_ADDR_LEN);
		bcopy(&fdesc->fd_remote_addr, ndesc.nd_daddr, IPV6_ADDR_LEN);
	}
	ndesc.nd_sport = htons(fdesc->fd_local_port);
	ndesc.nd_dport = htons(fdesc->fd_remote_port);
	ndesc.nd_protocol = (uint8_t)fdesc->fd_protocol;
	mutex_exit(&flent->fe_lock);

	return (exacct_commit_netinfo((void *)&ndesc, EX_NET_FLDESC_REC));
}

/* Write the Flow statistics to the log file */
int
mac_write_flow_stats(flow_entry_t *flent)
{
	flow_stats_t	*fl_stats;
	net_stat_t	nstat;

	fl_stats = &flent->fe_flowstats;
	nstat.ns_name = flent->fe_flow_name;
	nstat.ns_ibytes = fl_stats->fs_rbytes;
	nstat.ns_obytes = fl_stats->fs_obytes;
	nstat.ns_ipackets = fl_stats->fs_ipackets;
	nstat.ns_opackets = fl_stats->fs_opackets;
	nstat.ns_ierrors = fl_stats->fs_ierrors;
	nstat.ns_oerrors = fl_stats->fs_oerrors;

	return (exacct_commit_netinfo((void *)&nstat, EX_NET_FLSTAT_REC));
}

/* Write the Link Description to the log file */
int
mac_write_link_desc(mac_client_impl_t *mcip)
{
	net_desc_t		ndesc;
	flow_entry_t		*flent = mcip->mci_flent;

	bzero(&ndesc, sizeof (net_desc_t));

	ndesc.nd_name = mcip->mci_name;
	ndesc.nd_devname = mcip->mci_name;
	ndesc.nd_isv4 = B_TRUE;
	/*
	 * Grab the fe_lock to see a self-consistent fe_flow_desc.
	 * Updates to the fe_flow_desc are done under the fe_lock
	 * after removing the flent from the flow table.
	 */
	mutex_enter(&flent->fe_lock);
	bcopy(flent->fe_flow_desc.fd_src_mac, ndesc.nd_ehost, ETHERADDRL);
	mutex_exit(&flent->fe_lock);

	return (exacct_commit_netinfo((void *)&ndesc, EX_NET_LNDESC_REC));
}

/* Write the Link statistics to the log file */
int
mac_write_link_stats(mac_client_impl_t *mcip)
{
	net_stat_t	nstat;

	nstat.ns_name = mcip->mci_name;
	nstat.ns_ibytes = mcip->mci_stat_ibytes;
	nstat.ns_obytes = mcip->mci_stat_obytes;
	nstat.ns_ipackets = mcip->mci_stat_ipackets;
	nstat.ns_opackets = mcip->mci_stat_opackets;
	nstat.ns_ierrors = mcip->mci_stat_ierrors;
	nstat.ns_oerrors = mcip->mci_stat_oerrors;

	return (exacct_commit_netinfo((void *)&nstat, EX_NET_LNSTAT_REC));
}

/*
 * For a given flow, if the descrition has not been logged before, do it now.
 * If it is a VNIC, then we have collected information about it from the MAC
 * table, so skip it.
 */
/*ARGSUSED*/
static int
mac_log_flowinfo(flow_entry_t *flent, void *args)
{
	mac_client_impl_t	*mcip = flent->fe_mcip;

	if (mcip == NULL)
		return (0);

	/*
	 * If the name starts with "vnic", and fe_user_generated is true (to
	 * exclude the mcast and active flow entries created implicitly for
	 * a vnic, it is a VNIC flow.  i.e. vnic1 is a vnic flow,
	 * vnic/bge1/mcast1 is not and neither is vnic/bge1/active.
	 */
	if (strncasecmp(flent->fe_flow_name, "vnic", 4) == 0 &&
	    (flent->fe_type & FLOW_USER) != 0) {
		return (0);
	}

	if (!flent->fe_desc_logged) {
		/*
		 * We don't return error because we want to continu the
		 * walk in case this is the last walk which means we
		 * need to reset fe_desc_logged in all the flows.
		 */
		if (mac_write_flow_desc(flent, mcip) != 0)
			return (0);
		flent->fe_desc_logged = B_TRUE;
	}

	/*
	 * Regardless of the error, we want to proceed in case we have to
	 * reset fe_desc_logged.
	 */
	(void) mac_write_flow_stats(flent);

	if (mcip != NULL && !(mcip->mci_state_flags & MCIS_DESC_LOGGED))
		flent->fe_desc_logged = B_FALSE;

	return (0);
}

typedef struct i_mac_log_state_s {
	boolean_t	mi_last;
	int		mi_fenable;
	int		mi_lenable;
} i_mac_log_state_t;

/*
 * Walk the mac_impl_ts and log the description for each mac client of this mac,
 * if it hasn't already been done. Additionally, log statistics for the link as
 * well. Walk the flow table and log information for each flow as well.
 * If it is the last walk (mci_last), then we turn off mci_desc_logged (and
 * also fe_desc_logged, if flow logging is on) since we want to log the
 * description if and when logging is restarted.
 */
/*ARGSUSED*/
static uint_t
i_mac_log_walker(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	mac_impl_t		*mip = (mac_impl_t *)val;
	i_mac_log_state_t	*lstate = (i_mac_log_state_t *)arg;
	int			ret;
	mac_client_impl_t	*mcip;

	/*
	 * Only walk the client list for NIC and etherstub
	 */
	if ((mip->mi_state_flags & MIS_DISABLED) ||
	    ((mip->mi_state_flags & MIS_IS_VNIC) &&
	    (mac_get_lower_mac_handle((mac_handle_t)mip) != NULL)))
		return (MH_WALK_CONTINUE);

	for (mcip = mip->mi_clients_list; mcip != NULL;
	    mcip = mcip->mci_client_next) {
		if (!MCIP_DATAPATH_SETUP(mcip))
			continue;
		if (lstate->mi_lenable) {
			if (!(mcip->mci_state_flags & MCIS_DESC_LOGGED)) {
				ret = mac_write_link_desc(mcip);
				if (ret != 0) {
				/*
				 * We can't terminate it if this is the last
				 * walk, else there might be some links with
				 * mi_desc_logged set to true, which means
				 * their description won't be logged the next
				 * time logging is started (similarly for the
				 * flows within such links). We can continue
				 * without walking the flow table (i.e. to
				 * set fe_desc_logged to false) because we
				 * won't have written any flow stuff for this
				 * link as we haven't logged the link itself.
				 */
					if (lstate->mi_last)
						return (MH_WALK_CONTINUE);
					else
						return (MH_WALK_TERMINATE);
				}
				mcip->mci_state_flags |= MCIS_DESC_LOGGED;
			}
		}

		if (mac_write_link_stats(mcip) != 0 && !lstate->mi_last)
			return (MH_WALK_TERMINATE);

		if (lstate->mi_last)
			mcip->mci_state_flags &= ~MCIS_DESC_LOGGED;

		if (lstate->mi_fenable) {
			if (mcip->mci_subflow_tab != NULL) {
				(void) mac_flow_walk(mcip->mci_subflow_tab,
				    mac_log_flowinfo, mip);
			}
		}
	}
	return (MH_WALK_CONTINUE);
}

/*
 * The timer thread that runs every mac_logging_interval seconds and logs
 * link and/or flow information.
 */
/* ARGSUSED */
void
mac_log_linkinfo(void *arg)
{
	i_mac_log_state_t	lstate;

	rw_enter(&i_mac_impl_lock, RW_READER);
	if (!mac_flow_log_enable && !mac_link_log_enable) {
		rw_exit(&i_mac_impl_lock);
		return;
	}
	lstate.mi_fenable = mac_flow_log_enable;
	lstate.mi_lenable = mac_link_log_enable;
	lstate.mi_last = B_FALSE;
	rw_exit(&i_mac_impl_lock);

	mod_hash_walk(i_mac_impl_hash, i_mac_log_walker, &lstate);

	rw_enter(&i_mac_impl_lock, RW_WRITER);
	if (mac_flow_log_enable || mac_link_log_enable) {
		mac_logging_timer = timeout(mac_log_linkinfo, NULL,
		    SEC_TO_TICK(mac_logging_interval));
	}
	rw_exit(&i_mac_impl_lock);
}

/*
 * Start the logging timer.
 */
void
mac_start_logusage(mac_logtype_t type, uint_t interval)
{
	rw_enter(&i_mac_impl_lock, RW_WRITER);
	switch (type) {
	case MAC_LOGTYPE_FLOW:
		if (mac_flow_log_enable) {
			rw_exit(&i_mac_impl_lock);
			return;
		}
		mac_flow_log_enable = B_TRUE;
		/* FALLTHRU */
	case MAC_LOGTYPE_LINK:
		if (mac_link_log_enable) {
			rw_exit(&i_mac_impl_lock);
			return;
		}
		mac_link_log_enable = B_TRUE;
		break;
	default:
		ASSERT(0);
	}
	mac_logging_interval = interval;
	rw_exit(&i_mac_impl_lock);
	mac_log_linkinfo(NULL);
}

/*
 * Stop the logging timer if both Link and Flow logging are turned off.
 */
void
mac_stop_logusage(mac_logtype_t type)
{
	i_mac_log_state_t	lstate;

	rw_enter(&i_mac_impl_lock, RW_WRITER);
	lstate.mi_fenable = mac_flow_log_enable;
	lstate.mi_lenable = mac_link_log_enable;

	/* Last walk */
	lstate.mi_last = B_TRUE;

	switch (type) {
	case MAC_LOGTYPE_FLOW:
		if (lstate.mi_fenable) {
			ASSERT(mac_link_log_enable);
			mac_flow_log_enable = B_FALSE;
			mac_link_log_enable = B_FALSE;
			break;
		}
		/* FALLTHRU */
	case MAC_LOGTYPE_LINK:
		if (!lstate.mi_lenable || mac_flow_log_enable) {
			rw_exit(&i_mac_impl_lock);
			return;
		}
		mac_link_log_enable = B_FALSE;
		break;
	default:
		ASSERT(0);
	}
	rw_exit(&i_mac_impl_lock);
	(void) untimeout(mac_logging_timer);
	mac_logging_timer = 0;

	/* Last walk */
	mod_hash_walk(i_mac_impl_hash, i_mac_log_walker, &lstate);
}

/*
 * Walk the rx and tx SRS/SRs for a flow and update the priority value.
 */
void
mac_flow_update_priority(mac_client_impl_t *mcip, flow_entry_t *flent)
{
	pri_t			pri;
	int			count;
	mac_soft_ring_set_t	*mac_srs;

	if (flent->fe_rx_srs_cnt <= 0)
		return;

	if (((mac_soft_ring_set_t *)flent->fe_rx_srs[0])->srs_type ==
	    SRST_FLOW) {
		pri = FLOW_PRIORITY(mcip->mci_min_pri,
		    mcip->mci_max_pri,
		    flent->fe_resource_props.mrp_priority);
	} else {
		pri = mcip->mci_max_pri;
	}

	for (count = 0; count < flent->fe_rx_srs_cnt; count++) {
		mac_srs = flent->fe_rx_srs[count];
		mac_update_srs_priority(mac_srs, pri);
	}
	/*
	 * If we have a Tx SRS, we need to modify all the threads associated
	 * with it.
	 */
	if (flent->fe_tx_srs != NULL)
		mac_update_srs_priority(flent->fe_tx_srs, pri);
}

/*
 * RX and TX rings are reserved according to different semantics depending
 * on the requests from the MAC clients and type of rings:
 *
 * On the Tx side, by default we reserve individual rings, independently from
 * the groups.
 *
 * On the Rx side, the reservation is at the granularity of the group
 * of rings, and used for v12n level 1 only. It has a special case for the
 * primary client.
 *
 * If a share is allocated to a MAC client, we allocate a TX group and an
 * RX group to the client, and assign TX rings and RX rings to these
 * groups according to information gathered from the driver through
 * the share capability.
 *
 * The foreseable evolution of Rx rings will handle v12n level 2 and higher
 * to allocate individual rings out of a group and program the hw classifier
 * based on IP address or higher level criteria.
 */

/*
 * mac_reserve_tx_ring()
 * Reserve a unused ring by marking it with MR_INUSE state.
 * As reserved, the ring is ready to function.
 *
 * Notes for Hybrid I/O:
 *
 * If a specific ring is needed, it is specified through the desired_ring
 * argument. Otherwise that argument is set to NULL.
 * If the desired ring was previous allocated to another client, this
 * function swaps it with a new ring from the group of unassigned rings.
 */
mac_ring_t *
mac_reserve_tx_ring(mac_impl_t *mip, mac_ring_t *desired_ring)
{
	mac_group_t *group;
	mac_ring_t *ring;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	if (mip->mi_tx_groups == NULL)
		return (NULL);

	/*
	 * Find an available ring and start it before changing its status.
	 * The unassigned rings are at the end of the mi_tx_groups
	 * array.
	 */
	group = mip->mi_tx_groups + mip->mi_tx_group_count;

	for (ring = group->mrg_rings; ring != NULL;
	    ring = ring->mr_next) {
		if (desired_ring == NULL) {
			if (ring->mr_state == MR_FREE)
				/* wanted any free ring and found one */
				break;
		} else {
			mac_ring_t *sring;
			mac_client_impl_t *client;
			mac_soft_ring_set_t *srs;

			if (ring != desired_ring)
				/* wants a desired ring but this one ain't it */
				continue;

			if (ring->mr_state == MR_FREE)
				break;

			/*
			 * Found the desired ring but it's already in use.
			 * Swap it with a new ring.
			 */

			/* find the client which owns that ring */
			for (client = mip->mi_clients_list; client != NULL;
			    client = client->mci_client_next) {
				srs = MCIP_TX_SRS(client);
				if (srs != NULL && mac_tx_srs_ring_present(srs,
				    desired_ring)) {
					/* found our ring */
					break;
				}
			}
			ASSERT(client != NULL);

			/*
			 * Note that we cannot simply invoke the group
			 * add/rem routines since the client doesn't have a
			 * TX group. So we need to instead add/remove
			 * the rings from the SRS.
			 */
			ASSERT(client->mci_share == NULL);

			/* first quiece the client */
			mac_tx_client_quiesce(client, SRS_QUIESCE);

			/* give a new ring to the client... */
			sring = mac_reserve_tx_ring(mip, NULL);
			if (sring != NULL) {
				/*
				 * There are no other available ring
				 * on that MAC instance. The client
				 * will fallback to the shared TX
				 * ring.
				 *
				 * XXX if the user required the client
				 * to have a hardware transmit ring,
				 * we need to ensure we don't remove
				 * the last ring from the client.
				 * In that case look for a repacement
				 * ring from a client which does not
				 * require a hardware ring, we could
				 * add an argument to
				 * mac_reserve_tx_ring() which causes
				 * it to take a ring from such a client
				 * even if the desired ring is NULL.
				 * This will have to be done as part
				 * of the fix for CR 6758935. If that still
				 * fails, i.e. if all rings are allocated
				 * to clients which require rings, then
				 * cleanly fail the operation.
				 */
				mac_tx_srs_add_ring(srs, sring);
			}

			/* ... in exchange for our desired ring */
			mac_tx_srs_del_ring(srs, desired_ring);

			/* restart the client */
			mac_tx_client_restart(client);

			break;
		}
	}

	if (ring != NULL) {
		if (mac_start_ring(ring) != 0)
			return (NULL);
		ring->mr_state = MR_INUSE;
	}

	return (ring);
}

/*
 * Minimum number of rings to leave in the default TX group when allocating
 * rings to new clients.
 */
static uint_t mac_min_rx_default_rings = 1;

/*
 * Populate a zero-ring group with rings. If the share is non-NULL,
 * the rings are chosen according to that share.
 * Invoked after allocating a new RX or TX group through
 * mac_reserve_rx_group() or mac_reserve_tx_group(), respectively.
 * Returns zero on success, an errno otherwise.
 */
int
i_mac_group_allocate_rings(mac_impl_t *mip, mac_ring_type_t ring_type,
    mac_group_t *src_group, mac_group_t *new_group, mac_share_handle_t share)
{
	mac_ring_t **rings, *tmp_ring[1], *ring;
	uint_t nrings;
	int rv, i, j;

	ASSERT(mip->mi_rx_group_type == MAC_GROUP_TYPE_DYNAMIC &&
	    mip->mi_tx_group_type == MAC_GROUP_TYPE_DYNAMIC);
	ASSERT(new_group->mrg_cur_count == 0);

	/*
	 * First find the rings to allocate to the group.
	 */
	if (share != NULL) {
		/* get rings through ms_squery() */
		mip->mi_share_capab.ms_squery(share, ring_type, NULL, &nrings);
		ASSERT(nrings != 0);
		rings = kmem_alloc(nrings * sizeof (mac_ring_handle_t),
		    KM_SLEEP);
		mip->mi_share_capab.ms_squery(share, ring_type,
		    (mac_ring_handle_t *)rings, &nrings);
	} else {
		/* this function is called for TX only with a share */
		ASSERT(ring_type == MAC_RING_TYPE_RX);
		/*
		 * Pick one ring from default group.
		 *
		 * for now pick the second ring which requires the first ring
		 * at index 0 to stay in the default group, since it is the
		 * ring which carries the multicast traffic.
		 * We need a better way for a driver to indicate this,
		 * for example a per-ring flag.
		 */
		for (ring = src_group->mrg_rings; ring != NULL;
		    ring = ring->mr_next) {
			if (ring->mr_index != 0)
				break;
		}
		ASSERT(ring != NULL);
		nrings = 1;
		tmp_ring[0] = ring;
		rings = tmp_ring;
	}

	switch (ring_type) {
	case MAC_RING_TYPE_RX:
		if (src_group->mrg_cur_count - nrings <
		    mac_min_rx_default_rings) {
			/* we ran out of rings */
			return (ENOSPC);
		}

		/* move receive rings to new group */
		for (i = 0; i < nrings; i++) {
			rv = mac_group_mov_ring(mip, new_group, rings[i]);
			if (rv != 0) {
				/* move rings back on failure */
				for (j = 0; j < i; j++) {
					(void) mac_group_mov_ring(mip,
					    src_group, rings[j]);
				}
				return (rv);
			}
		}
		break;

	case MAC_RING_TYPE_TX: {
		mac_ring_t *tmp_ring;

		/* move the TX rings to the new group */
		ASSERT(src_group == NULL);
		for (i = 0; i < nrings; i++) {
			/* get the desired ring */
			tmp_ring = mac_reserve_tx_ring(mip, rings[i]);
			ASSERT(tmp_ring == rings[i]);
			rv = mac_group_mov_ring(mip, new_group, rings[i]);
			if (rv != 0) {
				/* cleanup on failure */
				for (j = 0; j < i; j++) {
					(void) mac_group_mov_ring(mip,
					    mip->mi_tx_groups +
					    mip->mi_tx_group_count, rings[j]);
				}
			}
		}
		break;
	}
	}

	if (share != NULL) {
		/* add group to share */
		mip->mi_share_capab.ms_sadd(share, new_group->mrg_driver);
		/* free temporary array of rings */
		kmem_free(rings, nrings * sizeof (mac_ring_handle_t));
	}

	return (0);
}

void
mac_rx_group_add_client(mac_group_t *grp, mac_client_impl_t *mcip)
{
	mac_grp_client_t *mgcp;

	for (mgcp = grp->mrg_clients; mgcp != NULL; mgcp = mgcp->mgc_next) {
		if (mgcp->mgc_client == mcip)
			break;
	}

	VERIFY(mgcp == NULL);

	mgcp = kmem_zalloc(sizeof (mac_grp_client_t), KM_SLEEP);
	mgcp->mgc_client = mcip;
	mgcp->mgc_next = grp->mrg_clients;
	grp->mrg_clients = mgcp;

}

void
mac_rx_group_remove_client(mac_group_t *grp, mac_client_impl_t *mcip)
{
	mac_grp_client_t *mgcp, **pprev;

	for (pprev = &grp->mrg_clients, mgcp = *pprev; mgcp != NULL;
	    pprev = &mgcp->mgc_next, mgcp = *pprev) {
		if (mgcp->mgc_client == mcip)
			break;
	}

	ASSERT(mgcp != NULL);

	*pprev = mgcp->mgc_next;
	kmem_free(mgcp, sizeof (mac_grp_client_t));
}

/*
 * mac_reserve_rx_group()
 *
 * Finds an available group and exclusively reserves it for a client.
 * The group is chosen to suit the flow's resource controls (bandwidth and
 * fanout requirements) and the address type.
 * If the requestor is the pimary MAC then return the group with the
 * largest number of rings, otherwise the default ring when available.
 */
mac_group_t *
mac_reserve_rx_group(mac_client_impl_t *mcip, uint8_t *mac_addr,
    mac_rx_group_reserve_type_t rtype)
{
	mac_share_handle_t	share = mcip->mci_share;
	mac_impl_t		*mip = mcip->mci_mip;
	mac_group_t		*grp = NULL;
	int			i, start, loopcount;
	int			err;
	mac_address_t		*map;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	/* Check if a group already has this mac address (case of VLANs) */
	if ((map = mac_find_macaddr(mip, mac_addr)) != NULL)
		return (map->ma_group);

	if (mip->mi_rx_groups == NULL || mip->mi_rx_group_count == 0 ||
	    rtype == MAC_RX_NO_RESERVE)
		return (NULL);

	/*
	 * Try to exclusively reserve a RX group.
	 *
	 * For flows requires SW_RING it always goes to the default group
	 * (Until we can explicitely call out default groups (CR 6695600),
	 * we assume that the default group is always at position zero);
	 *
	 * For flows requires HW_DEFAULT_RING (unicast flow of the primary
	 * client), try to reserve the default RX group only.
	 *
	 * For flows requires HW_RING (unicast flow of other clients), try
	 * to reserve non-default RX group then the default group.
	 */
	switch (rtype) {
	case MAC_RX_RESERVE_DEFAULT:
		start = 0;
		loopcount = 1;
		break;
	case MAC_RX_RESERVE_NONDEFAULT:
		start = 1;
		loopcount = mip->mi_rx_group_count;
	}

	for (i = start; i < start + loopcount; i++) {
		grp = &mip->mi_rx_groups[i % mip->mi_rx_group_count];

		DTRACE_PROBE3(rx__group__trying, char *, mip->mi_name,
		    int, grp->mrg_index, mac_group_state_t, grp->mrg_state);

		/*
		 * Check to see whether this mac client is the only client
		 * on this RX group. If not, we cannot exclusively reserve
		 * this RX group.
		 */
		if (!MAC_RX_GROUP_NO_CLIENT(grp) &&
		    (MAC_RX_GROUP_ONLY_CLIENT(grp) != mcip)) {
			continue;
		}

		/*
		 * This group could already be SHARED by other multicast
		 * flows on this client. In that case, the group would
		 * be shared and has already been started.
		 */
		ASSERT(grp->mrg_state != MAC_GROUP_STATE_UNINIT);

		if ((grp->mrg_state == MAC_GROUP_STATE_REGISTERED) &&
		    (mac_start_group(grp) != 0)) {
			continue;
		}

		if ((i % mip->mi_rx_group_count) == 0 ||
		    mip->mi_rx_group_type != MAC_GROUP_TYPE_DYNAMIC) {
			break;
		}

		ASSERT(grp->mrg_cur_count == 0);

		/*
		 * Populate the group. Rings should be taken
		 * from the default group at position 0 for now.
		 */

		err = i_mac_group_allocate_rings(mip, MAC_RING_TYPE_RX,
		    &mip->mi_rx_groups[0], grp, share);
		if (err == 0)
			break;

		DTRACE_PROBE3(rx__group__reserve__alloc__rings, char *,
		    mip->mi_name, int, grp->mrg_index, int, err);

		/*
		 * It's a dynamic group but the grouping operation failed.
		 */
		mac_stop_group(grp);
	}

	if (i == start + loopcount)
		return (NULL);

	ASSERT(grp != NULL);

	DTRACE_PROBE2(rx__group__reserved,
	    char *, mip->mi_name, int, grp->mrg_index);
	return (grp);
}

/*
 * mac_rx_release_group()
 *
 * This is called when there are no clients left for the group.
 * The group is stopped and marked MAC_GROUP_STATE_REGISTERED,
 * and if it is a non default group, the shares are removed and
 * all rings are assigned back to default group.
 */
void
mac_release_rx_group(mac_client_impl_t *mcip, mac_group_t *group)
{
	mac_impl_t	*mip = mcip->mci_mip;
	mac_ring_t	*ring;

	ASSERT(group != &mip->mi_rx_groups[0]);

	/*
	 * This is the case where there are no clients left. Any
	 * SRS etc on this group have also be quiesced.
	 */
	for (ring = group->mrg_rings; ring != NULL; ring = ring->mr_next) {
		if (ring->mr_classify_type == MAC_HW_CLASSIFIER) {
			ASSERT(group->mrg_state == MAC_GROUP_STATE_RESERVED);
			/*
			 * Remove the SRS associated with the HW ring.
			 * As a result, polling will be disabled.
			 */
			ring->mr_srs = NULL;
		}
		ASSERT(ring->mr_state == MR_INUSE);
		mac_stop_ring(ring);
		ring->mr_state = MR_FREE;
		ring->mr_flag = 0;
	}

	/* remove group from share */
	if (mcip->mci_share != NULL) {
		mip->mi_share_capab.ms_sremove(mcip->mci_share,
		    group->mrg_driver);
	}

	if (mip->mi_rx_group_type == MAC_GROUP_TYPE_DYNAMIC) {
		mac_ring_t *ring;

		/*
		 * Rings were dynamically allocated to group.
		 * Move rings back to default group.
		 */
		while ((ring = group->mrg_rings) != NULL) {
			(void) mac_group_mov_ring(mip,
			    &mip->mi_rx_groups[0], ring);
		}
	}
	mac_stop_group(group);
	/*
	 * Possible improvement: See if we can assign the group just released
	 * to a another client of the mip
	 */
}

/*
 * Reserves a TX group for the specified share. Invoked by mac_tx_srs_setup()
 * when a share was allocated to the client.
 */
mac_group_t *
mac_reserve_tx_group(mac_impl_t *mip, mac_share_handle_t share)
{
	mac_group_t *grp;
	int rv, i;

	/*
	 * TX groups are currently allocated only to MAC clients
	 * which are associated with a share. Since we have a fixed
	 * number of share and groups, and we already successfully
	 * allocated a share, find an available TX group.
	 */
	ASSERT(share != NULL);
	ASSERT(mip->mi_tx_group_free > 0);

	for (i = 0; i <  mip->mi_tx_group_count; i++) {
		grp = &mip->mi_tx_groups[i];

		if ((grp->mrg_state == MAC_GROUP_STATE_RESERVED) ||
		    (grp->mrg_state == MAC_GROUP_STATE_UNINIT))
			continue;

		rv = mac_start_group(grp);
		ASSERT(rv == 0);

		grp->mrg_state = MAC_GROUP_STATE_RESERVED;
		break;
	}

	ASSERT(grp != NULL);

	/*
	 * Populate the group. Rings should be taken from the group
	 * of unassigned rings, which is past the array of TX
	 * groups adversized by the driver.
	 */
	rv = i_mac_group_allocate_rings(mip, MAC_RING_TYPE_TX, NULL,
	    grp, share);
	if (rv != 0) {
		DTRACE_PROBE3(tx__group__reserve__alloc__rings,
		    char *, mip->mi_name, int, grp->mrg_index, int, rv);

		mac_stop_group(grp);
		grp->mrg_state = MAC_GROUP_STATE_UNINIT;

		return (NULL);
	}

	mip->mi_tx_group_free--;

	return (grp);
}

void
mac_release_tx_group(mac_impl_t *mip, mac_group_t *grp)
{
	mac_client_impl_t *mcip = grp->mrg_tx_client;
	mac_share_handle_t share = mcip->mci_share;
	mac_ring_t *ring;

	ASSERT(mip->mi_tx_group_type == MAC_GROUP_TYPE_DYNAMIC);
	ASSERT(share != NULL);
	ASSERT(grp->mrg_state == MAC_GROUP_STATE_RESERVED);

	mip->mi_share_capab.ms_sremove(share, grp->mrg_driver);
	while ((ring = grp->mrg_rings) != NULL) {
		/* move the ring back to the pool */
		(void) mac_group_mov_ring(mip, mip->mi_tx_groups +
		    mip->mi_tx_group_count, ring);
	}
	mac_stop_group(grp);
	mac_set_rx_group_state(grp, MAC_GROUP_STATE_REGISTERED);
	grp->mrg_tx_client = NULL;
	mip->mi_tx_group_free++;
}

/*
 * This is a 1-time control path activity initiated by the client (IP).
 * The mac perimeter protects against other simultaneous control activities,
 * for example an ioctl that attempts to change the degree of fanout and
 * increase or decrease the number of softrings associated with this Tx SRS.
 */
static mac_tx_notify_cb_t *
mac_client_tx_notify_add(mac_client_impl_t *mcip,
    mac_tx_notify_t notify, void *arg)
{
	mac_cb_info_t *mcbi;
	mac_tx_notify_cb_t *mtnfp;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mcip->mci_mip));

	mtnfp = kmem_zalloc(sizeof (mac_tx_notify_cb_t), KM_SLEEP);
	mtnfp->mtnf_fn = notify;
	mtnfp->mtnf_arg = arg;
	mtnfp->mtnf_link.mcb_objp = mtnfp;
	mtnfp->mtnf_link.mcb_objsize = sizeof (mac_tx_notify_cb_t);
	mtnfp->mtnf_link.mcb_flags = MCB_TX_NOTIFY_CB_T;

	mcbi = &mcip->mci_tx_notify_cb_info;
	mutex_enter(mcbi->mcbi_lockp);
	mac_callback_add(mcbi, &mcip->mci_tx_notify_cb_list, &mtnfp->mtnf_link);
	mutex_exit(mcbi->mcbi_lockp);
	return (mtnfp);
}

static void
mac_client_tx_notify_remove(mac_client_impl_t *mcip, mac_tx_notify_cb_t *mtnfp)
{
	mac_cb_info_t	*mcbi;
	mac_cb_t	**cblist;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mcip->mci_mip));

	if (!mac_callback_find(&mcip->mci_tx_notify_cb_info,
	    &mcip->mci_tx_notify_cb_list, &mtnfp->mtnf_link)) {
		cmn_err(CE_WARN,
		    "mac_client_tx_notify_remove: callback not "
		    "found, mcip 0x%p mtnfp 0x%p", (void *)mcip, (void *)mtnfp);
		return;
	}

	mcbi = &mcip->mci_tx_notify_cb_info;
	cblist = &mcip->mci_tx_notify_cb_list;
	mutex_enter(mcbi->mcbi_lockp);
	if (mac_callback_remove(mcbi, cblist, &mtnfp->mtnf_link))
		kmem_free(mtnfp, sizeof (mac_tx_notify_cb_t));
	else
		mac_callback_remove_wait(&mcip->mci_tx_notify_cb_info);
	mutex_exit(mcbi->mcbi_lockp);
}

/*
 * mac_client_tx_notify():
 * call to add and remove flow control callback routine.
 */
mac_tx_notify_handle_t
mac_client_tx_notify(mac_client_handle_t mch, mac_tx_notify_t callb_func,
    void *ptr)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_tx_notify_cb_t	*mtnfp = NULL;

	i_mac_perim_enter(mcip->mci_mip);

	if (callb_func != NULL) {
		/* Add a notify callback */
		mtnfp = mac_client_tx_notify_add(mcip, callb_func, ptr);
	} else {
		mac_client_tx_notify_remove(mcip, (mac_tx_notify_cb_t *)ptr);
	}
	i_mac_perim_exit(mcip->mci_mip);

	return ((mac_tx_notify_handle_t)mtnfp);
}
