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
 * Copyright (c) 2017 by Delphix. All rights reserved.
 */

/*
 * Contracts
 * ---------
 *
 * Contracts are a primitive which enrich the relationships between
 * processes and system resources.  The primary purpose of contracts is
 * to provide a means for the system to negotiate the departure from a
 * binding relationship (e.g. pages locked in memory or a thread bound
 * to processor), but they can also be used as a purely asynchronous
 * error reporting mechanism as they are with process contracts.
 *
 * More information on how one interfaces with contracts and what
 * contracts can do for you can be found in:
 *   PSARC 2003/193 Solaris Contracts
 *   PSARC 2004/460 Contracts addendum
 *
 * This file contains the core contracts framework.  By itself it is
 * useless: it depends the contracts filesystem (ctfs) to provide an
 * interface to user processes and individual contract types to
 * implement the process/resource relationships.
 *
 * Data structure overview
 * -----------------------
 *
 * A contract is represented by a contract_t, which itself points to an
 * encapsulating contract-type specific contract object.  A contract_t
 * contains the contract's static identity (including its terms), its
 * linkage to various bookkeeping structures, the contract-specific
 * event queue, and a reference count.
 *
 * A contract template is represented by a ct_template_t, which, like a
 * contract, points to an encapsulating contract-type specific template
 * object.  A ct_template_t contains the template's terms.
 *
 * An event queue is represented by a ct_equeue_t, and consists of a
 * list of events, a list of listeners, and a list of listeners who are
 * waiting for new events (affectionately referred to as "tail
 * listeners").  There are three queue types, defined by ct_listnum_t
 * (an enum).  An event may be on one of each type of queue
 * simultaneously; the list linkage used by a queue is determined by
 * its type.
 *
 * An event is represented by a ct_kevent_t, which contains mostly
 * static event data (e.g. id, payload).  It also has an array of
 * ct_member_t structures, each of which contains a list_node_t and
 * represent the event's linkage in a specific event queue.
 *
 * Each open of an event endpoint results in the creation of a new
 * listener, represented by a ct_listener_t.  In addition to linkage
 * into the aforementioned lists in the event_queue, a ct_listener_t
 * contains a pointer to the ct_kevent_t it is currently positioned at
 * as well as a set of status flags and other administrative data.
 *
 * Each process has a list of contracts it owns, p_ct_held; a pointer
 * to the process contract it is a member of, p_ct_process; the linkage
 * for that membership, p_ct_member; and an array of event queue
 * structures representing the process bundle queues.
 *
 * Each LWP has an array of its active templates, lwp_ct_active; and
 * the most recently created contracts, lwp_ct_latest.
 *
 * A process contract has a list of member processes and a list of
 * inherited contracts.
 *
 * There is a system-wide list of all contracts, as well as per-type
 * lists of contracts.
 *
 * Lock ordering overview
 * ----------------------
 *
 * Locks at the top are taken first:
 *
 *                   ct_evtlock
 *                   regent ct_lock
 *                   member ct_lock
 *                   pidlock
 *                   p_lock
 *    contract ctq_lock         contract_lock
 *    pbundle ctq_lock
 *    cte_lock
 *                   ct_reflock
 *
 * contract_lock and ctq_lock/cte_lock are not currently taken at the
 * same time.
 *
 * Reference counting and locking
 * ------------------------------
 *
 * A contract has a reference count, protected by ct_reflock.
 * (ct_reflock is also used in a couple other places where atomic
 * access to a variable is needed in an innermost context).  A process
 * maintains a hold on each contract it owns.  A process contract has a
 * hold on each contract is has inherited.  Each event has a hold on
 * the contract which generated it.  Process contract templates have
 * holds on the contracts referred to by their transfer terms.  CTFS
 * contract directory nodes have holds on contracts.  Lastly, various
 * code paths may temporarily take holds on contracts to prevent them
 * from disappearing while other processing is going on.  It is
 * important to note that the global contract lists do not hold
 * references on contracts; a contract is removed from these structures
 * atomically with the release of its last reference.
 *
 * At a given point in time, a contract can either be owned by a
 * process, inherited by a regent process contract, or orphaned.  A
 * contract_t's  owner and regent pointers, ct_owner and ct_regent, are
 * protected by its ct_lock.  The linkage in the holder's (holder =
 * owner or regent) list of contracts, ct_ctlist, is protected by
 * whatever lock protects the holder's data structure.  In order for
 * these two directions to remain consistent, changing the holder of a
 * contract requires that both locks be held.
 *
 * Events also have reference counts.  There is one hold on an event
 * per queue it is present on, in addition to those needed for the
 * usual sundry reasons.  Individual listeners are associated with
 * specific queues, and increase a queue-specific reference count
 * stored in the ct_member_t structure.
 *
 * The dynamic contents of an event (reference count and flags) are
 * protected by its cte_lock, while the contents of the embedded
 * ct_member_t structures are protected by the locks of the queues they
 * are linked into.  A ct_listener_t's contents are also protected by
 * its event queue's ctq_lock.
 *
 * Resource controls
 * -----------------
 *
 * Control:      project.max-contracts (rc_project_contract)
 * Description:  Maximum number of contracts allowed a project.
 *
 *   When a contract is created, the project's allocation is tested and
 *   (assuming success) increased.  When the last reference to a
 *   contract is released, the creating project's allocation is
 *   decreased.
 */

#include <sys/mutex.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/thread.h>
#include <sys/id_space.h>
#include <sys/avl.h>
#include <sys/list.h>
#include <sys/sysmacros.h>
#include <sys/proc.h>
#include <sys/ctfs.h>
#include <sys/contract_impl.h>
#include <sys/contract/process_impl.h>
#include <sys/dditypes.h>
#include <sys/contract/device_impl.h>
#include <sys/systm.h>
#include <sys/atomic.h>
#include <sys/cmn_err.h>
#include <sys/model.h>
#include <sys/policy.h>
#include <sys/zone.h>
#include <sys/task.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

extern rctl_hndl_t rc_project_contract;

static id_space_t	*contract_ids;
static avl_tree_t	contract_avl;
static kmutex_t		contract_lock;

int			ct_ntypes = CTT_MAXTYPE;
static ct_type_t	*ct_types_static[CTT_MAXTYPE];
ct_type_t		**ct_types = ct_types_static;
int			ct_debug;

static void cte_queue_create(ct_equeue_t *, ct_listnum_t, int, int);
static void cte_queue_destroy(ct_equeue_t *);
static void cte_queue_drain(ct_equeue_t *, int);
static void cte_trim(ct_equeue_t *, contract_t *);
static void cte_copy(ct_equeue_t *, ct_equeue_t *);

/*
 * contract_compar
 *
 * A contract comparator which sorts on contract ID.
 */
int
contract_compar(const void *x, const void *y)
{
	const contract_t *ct1 = x;
	const contract_t *ct2 = y;

	if (ct1->ct_id < ct2->ct_id)
		return (-1);
	if (ct1->ct_id > ct2->ct_id)
		return (1);
	return (0);
}

/*
 * contract_init
 *
 * Initializes the contract subsystem, the specific contract types, and
 * process 0.
 */
void
contract_init(void)
{
	/*
	 * Initialize contract subsystem.
	 */
	contract_ids = id_space_create("contracts", 1, INT_MAX);
	avl_create(&contract_avl, contract_compar, sizeof (contract_t),
	    offsetof(contract_t, ct_ctavl));
	mutex_init(&contract_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Initialize contract types.
	 */
	contract_process_init();
	contract_device_init();

	/*
	 * Initialize p0/lwp0 contract state.
	 */
	avl_create(&p0.p_ct_held, contract_compar, sizeof (contract_t),
	    offsetof(contract_t, ct_ctlist));
}

/*
 * contract_dtor
 *
 * Performs basic destruction of the common portions of a contract.
 * Called from the failure path of contract_ctor and from
 * contract_rele.
 */
static void
contract_dtor(contract_t *ct)
{
	cte_queue_destroy(&ct->ct_events);
	list_destroy(&ct->ct_vnodes);
	mutex_destroy(&ct->ct_reflock);
	mutex_destroy(&ct->ct_lock);
	mutex_destroy(&ct->ct_evtlock);
}

/*
 * contract_ctor
 *
 * Called by a contract type to initialize a contract.  Fails if the
 * max-contract resource control would have been exceeded.  After a
 * successful call to contract_ctor, the contract is unlocked and
 * visible in all namespaces; any type-specific initialization should
 * be completed before calling contract_ctor.  Returns 0 on success.
 *
 * Because not all callers can tolerate failure, a 0 value for canfail
 * instructs contract_ctor to ignore the project.max-contracts resource
 * control.  Obviously, this "out" should only be employed by callers
 * who are sufficiently constrained in other ways (e.g. newproc).
 */
int
contract_ctor(contract_t *ct, ct_type_t *type, ct_template_t *tmpl, void *data,
    ctflags_t flags, proc_t *author, int canfail)
{
	avl_index_t where;
	klwp_t *curlwp = ttolwp(curthread);

	ASSERT(author == curproc);

	mutex_init(&ct->ct_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ct->ct_reflock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&ct->ct_evtlock, NULL, MUTEX_DEFAULT, NULL);
	ct->ct_id = id_alloc(contract_ids);

	cte_queue_create(&ct->ct_events, CTEL_CONTRACT, 20, 0);
	list_create(&ct->ct_vnodes, sizeof (contract_vnode_t),
	    offsetof(contract_vnode_t, ctv_node));

	/*
	 * Instance data
	 */
	ct->ct_ref = 2;		/* one for the holder, one for "latest" */
	ct->ct_cuid = crgetuid(CRED());
	ct->ct_type = type;
	ct->ct_data = data;
	gethrestime(&ct->ct_ctime);
	ct->ct_state = CTS_OWNED;
	ct->ct_flags = flags;
	ct->ct_regent = author->p_ct_process ?
	    &author->p_ct_process->conp_contract : NULL;
	ct->ct_ev_info = tmpl->ctmpl_ev_info;
	ct->ct_ev_crit = tmpl->ctmpl_ev_crit;
	ct->ct_cookie = tmpl->ctmpl_cookie;
	ct->ct_owner = author;
	ct->ct_ntime.ctm_total = -1;
	ct->ct_qtime.ctm_total = -1;
	ct->ct_nevent = NULL;

	/*
	 * Test project.max-contracts.
	 */
	mutex_enter(&author->p_lock);
	mutex_enter(&contract_lock);
	if (canfail && rctl_test(rc_project_contract,
	    author->p_task->tk_proj->kpj_rctls, author, 1,
	    RCA_SAFE) & RCT_DENY) {
		id_free(contract_ids, ct->ct_id);
		mutex_exit(&contract_lock);
		mutex_exit(&author->p_lock);
		ct->ct_events.ctq_flags |= CTQ_DEAD;
		contract_dtor(ct);
		return (1);
	}
	ct->ct_proj = author->p_task->tk_proj;
	ct->ct_proj->kpj_data.kpd_contract++;
	(void) project_hold(ct->ct_proj);
	mutex_exit(&contract_lock);

	/*
	 * Insert into holder's avl of contracts.
	 * We use an avl not because order is important, but because
	 * readdir of /proc/contracts requires we be able to use a
	 * scalar as an index into the process's list of contracts
	 */
	ct->ct_zoneid = author->p_zone->zone_id;
	ct->ct_czuniqid = ct->ct_mzuniqid = author->p_zone->zone_uniqid;
	VERIFY(avl_find(&author->p_ct_held, ct, &where) == NULL);
	avl_insert(&author->p_ct_held, ct, where);
	mutex_exit(&author->p_lock);

	/*
	 * Insert into global contract AVL
	 */
	mutex_enter(&contract_lock);
	VERIFY(avl_find(&contract_avl, ct, &where) == NULL);
	avl_insert(&contract_avl, ct, where);
	mutex_exit(&contract_lock);

	/*
	 * Insert into type AVL
	 */
	mutex_enter(&type->ct_type_lock);
	VERIFY(avl_find(&type->ct_type_avl, ct, &where) == NULL);
	avl_insert(&type->ct_type_avl, ct, where);
	type->ct_type_timestruc = ct->ct_ctime;
	mutex_exit(&type->ct_type_lock);

	if (curlwp->lwp_ct_latest[type->ct_type_index])
		contract_rele(curlwp->lwp_ct_latest[type->ct_type_index]);
	curlwp->lwp_ct_latest[type->ct_type_index] = ct;

	return (0);
}

/*
 * contract_rele
 *
 * Releases a reference to a contract.  If the caller had the last
 * reference, the contract is removed from all namespaces, its
 * allocation against the max-contracts resource control is released,
 * and the contract type's free entry point is invoked for any
 * type-specific deconstruction and to (presumably) free the object.
 */
void
contract_rele(contract_t *ct)
{
	uint64_t nref;

	mutex_enter(&ct->ct_reflock);
	ASSERT(ct->ct_ref > 0);
	nref = --ct->ct_ref;
	mutex_exit(&ct->ct_reflock);
	if (nref == 0) {
		/*
		 * ct_owner is cleared when it drops its reference.
		 */
		ASSERT(ct->ct_owner == NULL);
		ASSERT(ct->ct_evcnt == 0);

		/*
		 * Remove from global contract AVL
		 */
		mutex_enter(&contract_lock);
		avl_remove(&contract_avl, ct);
		mutex_exit(&contract_lock);

		/*
		 * Remove from type AVL
		 */
		mutex_enter(&ct->ct_type->ct_type_lock);
		avl_remove(&ct->ct_type->ct_type_avl, ct);
		mutex_exit(&ct->ct_type->ct_type_lock);

		/*
		 * Release the contract's ID
		 */
		id_free(contract_ids, ct->ct_id);

		/*
		 * Release project hold
		 */
		mutex_enter(&contract_lock);
		ct->ct_proj->kpj_data.kpd_contract--;
		project_rele(ct->ct_proj);
		mutex_exit(&contract_lock);

		/*
		 * Free the contract
		 */
		contract_dtor(ct);
		ct->ct_type->ct_type_ops->contop_free(ct);
	}
}

/*
 * contract_hold
 *
 * Adds a reference to a contract
 */
void
contract_hold(contract_t *ct)
{
	mutex_enter(&ct->ct_reflock);
	ASSERT(ct->ct_ref < UINT64_MAX);
	ct->ct_ref++;
	mutex_exit(&ct->ct_reflock);
}

/*
 * contract_getzuniqid
 *
 * Get a contract's zone unique ID.  Needed because 64-bit reads and
 * writes aren't atomic on x86.  Since there are contexts where we are
 * unable to take ct_lock, we instead use ct_reflock; in actuality any
 * lock would do.
 */
uint64_t
contract_getzuniqid(contract_t *ct)
{
	uint64_t zuniqid;

	mutex_enter(&ct->ct_reflock);
	zuniqid = ct->ct_mzuniqid;
	mutex_exit(&ct->ct_reflock);

	return (zuniqid);
}

/*
 * contract_setzuniqid
 *
 * Sets a contract's zone unique ID.   See contract_getzuniqid.
 */
void
contract_setzuniqid(contract_t *ct, uint64_t zuniqid)
{
	mutex_enter(&ct->ct_reflock);
	ct->ct_mzuniqid = zuniqid;
	mutex_exit(&ct->ct_reflock);
}

/*
 * contract_abandon
 *
 * Abandons the specified contract.  If "explicit" is clear, the
 * contract was implicitly abandoned (by process exit) and should be
 * inherited if its terms allow it and its owner was a member of a
 * regent contract.  Otherwise, the contract type's abandon entry point
 * is invoked to either destroy or orphan the contract.
 */
int
contract_abandon(contract_t *ct, proc_t *p, int explicit)
{
	ct_equeue_t *q = NULL;
	contract_t *parent = &p->p_ct_process->conp_contract;
	int inherit = 0;

	VERIFY(p == curproc);

	mutex_enter(&ct->ct_lock);

	/*
	 * Multiple contract locks are taken contract -> subcontract.
	 * Check if the contract will be inherited so we can acquire
	 * all the necessary locks before making sensitive changes.
	 */
	if (!explicit && (ct->ct_flags & CTF_INHERIT) &&
	    contract_process_accept(parent)) {
		mutex_exit(&ct->ct_lock);
		mutex_enter(&parent->ct_lock);
		mutex_enter(&ct->ct_lock);
		inherit = 1;
	}

	if (ct->ct_owner != p) {
		mutex_exit(&ct->ct_lock);
		if (inherit)
			mutex_exit(&parent->ct_lock);
		return (EINVAL);
	}

	mutex_enter(&p->p_lock);
	if (explicit)
		avl_remove(&p->p_ct_held, ct);
	ct->ct_owner = NULL;
	mutex_exit(&p->p_lock);

	/*
	 * Since we can't call cte_trim with the contract lock held,
	 * we grab the queue pointer here.
	 */
	if (p->p_ct_equeue)
		q = p->p_ct_equeue[ct->ct_type->ct_type_index];

	/*
	 * contop_abandon may destroy the contract so we rely on it to
	 * drop ct_lock.  We retain a reference on the contract so that
	 * the cte_trim which follows functions properly.  Even though
	 * cte_trim doesn't dereference the contract pointer, it is
	 * still necessary to retain a reference to the contract so
	 * that we don't trim events which are sent by a subsequently
	 * allocated contract infortuitously located at the same address.
	 */
	contract_hold(ct);

	if (inherit) {
		ct->ct_state = CTS_INHERITED;
		VERIFY(ct->ct_regent == parent);
		contract_process_take(parent, ct);

		/*
		 * We are handing off the process's reference to the
		 * parent contract.  For this reason, the order in
		 * which we drop the contract locks is also important.
		 */
		mutex_exit(&ct->ct_lock);
		mutex_exit(&parent->ct_lock);
	} else {
		ct->ct_regent = NULL;
		ct->ct_type->ct_type_ops->contop_abandon(ct);
	}

	/*
	 * ct_lock has been dropped; we can safely trim the event
	 * queue now.
	 */
	if (q) {
		mutex_enter(&q->ctq_lock);
		cte_trim(q, ct);
		mutex_exit(&q->ctq_lock);
	}

	contract_rele(ct);

	return (0);
}

int
contract_newct(contract_t *ct)
{
	return (ct->ct_type->ct_type_ops->contop_newct(ct));
}

/*
 * contract_adopt
 *
 * Adopts a contract.  After a successful call to this routine, the
 * previously inherited contract will belong to the calling process,
 * and its events will have been appended to its new owner's process
 * bundle queue.
 */
int
contract_adopt(contract_t *ct, proc_t *p)
{
	avl_index_t where;
	ct_equeue_t *q;
	contract_t *parent;

	ASSERT(p == curproc);

	/*
	 * Ensure the process has an event queue.  Checked by ASSERTs
	 * below.
	 */
	(void) contract_type_pbundle(ct->ct_type, p);

	mutex_enter(&ct->ct_lock);
	parent = ct->ct_regent;
	if (ct->ct_state != CTS_INHERITED ||
	    &p->p_ct_process->conp_contract != parent ||
	    p->p_zone->zone_uniqid != ct->ct_czuniqid) {
		mutex_exit(&ct->ct_lock);
		return (EINVAL);
	}

	/*
	 * Multiple contract locks are taken contract -> subcontract.
	 */
	mutex_exit(&ct->ct_lock);
	mutex_enter(&parent->ct_lock);
	mutex_enter(&ct->ct_lock);

	/*
	 * It is possible that the contract was adopted by someone else
	 * while its lock was dropped.  It isn't possible for the
	 * contract to have been inherited by a different regent
	 * contract.
	 */
	if (ct->ct_state != CTS_INHERITED) {
		mutex_exit(&parent->ct_lock);
		mutex_exit(&ct->ct_lock);
		return (EBUSY);
	}
	ASSERT(ct->ct_regent == parent);

	ct->ct_state = CTS_OWNED;

	contract_process_adopt(ct, p);

	mutex_enter(&p->p_lock);
	ct->ct_owner = p;
	VERIFY(avl_find(&p->p_ct_held, ct, &where) == NULL);
	avl_insert(&p->p_ct_held, ct, where);
	mutex_exit(&p->p_lock);

	ASSERT(ct->ct_owner->p_ct_equeue);
	ASSERT(ct->ct_owner->p_ct_equeue[ct->ct_type->ct_type_index]);
	q = ct->ct_owner->p_ct_equeue[ct->ct_type->ct_type_index];
	cte_copy(&ct->ct_events, q);
	mutex_exit(&ct->ct_lock);

	return (0);
}

/*
 * contract_ack
 *
 * Acknowledges receipt of a critical event.
 */
int
contract_ack(contract_t *ct, uint64_t evid, int ack)
{
	ct_kevent_t *ev;
	list_t *queue = &ct->ct_events.ctq_events;
	int error = ESRCH;
	int nego = 0;
	uint_t evtype;

	ASSERT(ack == CT_ACK || ack == CT_NACK);

	mutex_enter(&ct->ct_lock);
	mutex_enter(&ct->ct_events.ctq_lock);
	/*
	 * We are probably ACKing something near the head of the queue.
	 */
	for (ev = list_head(queue); ev; ev = list_next(queue, ev)) {
		if (ev->cte_id == evid) {
			if (ev->cte_flags & CTE_NEG)
				nego = 1;
			else if (ack == CT_NACK)
				break;
			if ((ev->cte_flags & (CTE_INFO | CTE_ACK)) == 0) {
				ev->cte_flags |= CTE_ACK;
				ct->ct_evcnt--;
				evtype = ev->cte_type;
				error = 0;
			}
			break;
		}
	}
	mutex_exit(&ct->ct_events.ctq_lock);
	mutex_exit(&ct->ct_lock);

	/*
	 * Not all critical events are negotiation events, however
	 * every negotiation event is a critical event. NEGEND events
	 * are critical events but are not negotiation events
	 */
	if (error || !nego)
		return (error);

	if (ack == CT_ACK)
		error = ct->ct_type->ct_type_ops->contop_ack(ct, evtype, evid);
	else
		error = ct->ct_type->ct_type_ops->contop_nack(ct, evtype, evid);

	return (error);
}

/*ARGSUSED*/
int
contract_ack_inval(contract_t *ct, uint_t evtype, uint64_t evid)
{
	cmn_err(CE_PANIC, "contract_ack_inval: unsupported call: ctid: %u",
	    ct->ct_id);
	return (ENOSYS);
}

/*ARGSUSED*/
int
contract_qack_inval(contract_t *ct, uint_t evtype, uint64_t evid)
{
	cmn_err(CE_PANIC, "contract_ack_inval: unsupported call: ctid: %u",
	    ct->ct_id);
	return (ENOSYS);
}

/*ARGSUSED*/
int
contract_qack_notsup(contract_t *ct, uint_t evtype, uint64_t evid)
{
	return (ERANGE);
}

/*
 * contract_qack
 *
 * Asks that negotiations be extended by another time quantum
 */
int
contract_qack(contract_t *ct, uint64_t evid)
{
	ct_kevent_t *ev;
	list_t *queue = &ct->ct_events.ctq_events;
	int nego = 0;
	uint_t evtype;

	mutex_enter(&ct->ct_lock);
	mutex_enter(&ct->ct_events.ctq_lock);

	for (ev = list_head(queue); ev; ev = list_next(queue, ev)) {
		if (ev->cte_id == evid) {
			if ((ev->cte_flags & (CTE_NEG | CTE_ACK)) == CTE_NEG) {
				evtype = ev->cte_type;
				nego = 1;
			}
			break;
		}
	}
	mutex_exit(&ct->ct_events.ctq_lock);
	mutex_exit(&ct->ct_lock);

	/*
	 * Only a negotiated event (which is by definition also a critical
	 * event) which has not yet been acknowledged can provide
	 * time quanta to a negotiating owner process.
	 */
	if (!nego)
		return (ESRCH);

	return (ct->ct_type->ct_type_ops->contop_qack(ct, evtype, evid));
}

/*
 * contract_orphan
 *
 * Icky-poo.  This is a process-contract special, used to ACK all
 * critical messages when a contract is orphaned.
 */
void
contract_orphan(contract_t *ct)
{
	ct_kevent_t *ev;
	list_t *queue = &ct->ct_events.ctq_events;

	ASSERT(MUTEX_HELD(&ct->ct_lock));
	ASSERT(ct->ct_state != CTS_ORPHAN);

	mutex_enter(&ct->ct_events.ctq_lock);
	ct->ct_state = CTS_ORPHAN;
	for (ev = list_head(queue); ev; ev = list_next(queue, ev)) {
		if ((ev->cte_flags & (CTE_INFO | CTE_ACK)) == 0) {
			ev->cte_flags |= CTE_ACK;
			ct->ct_evcnt--;
		}
	}
	mutex_exit(&ct->ct_events.ctq_lock);

	ASSERT(ct->ct_evcnt == 0);
}

/*
 * contract_destroy
 *
 * Explicit contract destruction.  Called when contract is empty.
 * The contract will actually stick around until all of its events are
 * removed from the bundle and and process bundle queues, and all fds
 * which refer to it are closed.  See contract_dtor if you are looking
 * for what destroys the contract structure.
 */
void
contract_destroy(contract_t *ct)
{
	ASSERT(MUTEX_HELD(&ct->ct_lock));
	ASSERT(ct->ct_state != CTS_DEAD);
	ASSERT(ct->ct_owner == NULL);

	ct->ct_state = CTS_DEAD;
	cte_queue_drain(&ct->ct_events, 1);
	mutex_exit(&ct->ct_lock);
	mutex_enter(&ct->ct_type->ct_type_events.ctq_lock);
	cte_trim(&ct->ct_type->ct_type_events, ct);
	mutex_exit(&ct->ct_type->ct_type_events.ctq_lock);
	mutex_enter(&ct->ct_lock);
	ct->ct_type->ct_type_ops->contop_destroy(ct);
	mutex_exit(&ct->ct_lock);
	contract_rele(ct);
}

/*
 * contract_vnode_get
 *
 * Obtains the contract directory vnode for this contract, if there is
 * one.  The caller must VN_RELE the vnode when they are through using
 * it.
 */
vnode_t *
contract_vnode_get(contract_t *ct, vfs_t *vfsp)
{
	contract_vnode_t *ctv;
	vnode_t *vp = NULL;

	mutex_enter(&ct->ct_lock);
	for (ctv = list_head(&ct->ct_vnodes); ctv != NULL;
	    ctv = list_next(&ct->ct_vnodes, ctv))
		if (ctv->ctv_vnode->v_vfsp == vfsp) {
			vp = ctv->ctv_vnode;
			VN_HOLD(vp);
			break;
		}
	mutex_exit(&ct->ct_lock);
	return (vp);
}

/*
 * contract_vnode_set
 *
 * Sets the contract directory vnode for this contract.  We don't hold
 * a reference on the vnode because we don't want to prevent it from
 * being freed.  The vnode's inactive entry point will take care of
 * notifying us when it should be removed.
 */
void
contract_vnode_set(contract_t *ct, contract_vnode_t *ctv, vnode_t *vnode)
{
	mutex_enter(&ct->ct_lock);
	ctv->ctv_vnode = vnode;
	list_insert_head(&ct->ct_vnodes, ctv);
	mutex_exit(&ct->ct_lock);
}

/*
 * contract_vnode_clear
 *
 * Removes this vnode as the contract directory vnode for this
 * contract.  Called from a contract directory's inactive entry point,
 * this may return 0 indicating that the vnode gained another reference
 * because of a simultaneous call to contract_vnode_get.
 */
int
contract_vnode_clear(contract_t *ct, contract_vnode_t *ctv)
{
	vnode_t *vp = ctv->ctv_vnode;
	int result;

	mutex_enter(&ct->ct_lock);
	mutex_enter(&vp->v_lock);
	if (vp->v_count == 1) {
		list_remove(&ct->ct_vnodes, ctv);
		result = 1;
	} else {
		VN_RELE_LOCKED(vp);
		result = 0;
	}
	mutex_exit(&vp->v_lock);
	mutex_exit(&ct->ct_lock);

	return (result);
}

/*
 * contract_exit
 *
 * Abandons all contracts held by process p, and drains process p's
 * bundle queues.  Called on process exit.
 */
void
contract_exit(proc_t *p)
{
	contract_t *ct;
	void *cookie = NULL;
	int i;

	ASSERT(p == curproc);

	/*
	 * Abandon held contracts.  contract_abandon knows enough not
	 * to remove the contract from the list a second time.  We are
	 * exiting, so no locks are needed here.  But because
	 * contract_abandon will take p_lock, we need to make sure we
	 * aren't holding it.
	 */
	ASSERT(MUTEX_NOT_HELD(&p->p_lock));
	while ((ct = avl_destroy_nodes(&p->p_ct_held, &cookie)) != NULL)
		VERIFY(contract_abandon(ct, p, 0) == 0);

	/*
	 * Drain pbundles.  Because a process bundle queue could have
	 * been passed to another process, they may not be freed right
	 * away.
	 */
	if (p->p_ct_equeue) {
		for (i = 0; i < CTT_MAXTYPE; i++)
			if (p->p_ct_equeue[i])
				cte_queue_drain(p->p_ct_equeue[i], 0);
		kmem_free(p->p_ct_equeue, CTT_MAXTYPE * sizeof (ct_equeue_t *));
	}
}

static int
get_time_left(struct ct_time *t)
{
	clock_t ticks_elapsed;
	int secs_elapsed;

	if (t->ctm_total == -1)
		return (-1);

	ticks_elapsed = ddi_get_lbolt() - t->ctm_start;
	secs_elapsed = t->ctm_total - (drv_hztousec(ticks_elapsed)/MICROSEC);
	return (secs_elapsed > 0 ? secs_elapsed : 0);
}

/*
 * contract_status_common
 *
 * Populates a ct_status structure.  Used by contract types in their
 * status entry points and ctfs when only common information is
 * requested.
 */
void
contract_status_common(contract_t *ct, zone_t *zone, void *status,
    model_t model)
{
	STRUCT_HANDLE(ct_status, lstatus);

	STRUCT_SET_HANDLE(lstatus, model, status);
	ASSERT(MUTEX_HELD(&ct->ct_lock));
	if (zone->zone_uniqid == GLOBAL_ZONEUNIQID ||
	    zone->zone_uniqid == ct->ct_czuniqid) {
		zone_t *czone;
		zoneid_t zoneid = -1;

		/*
		 * Contracts don't have holds on the zones they were
		 * created by.  If the contract's zone no longer
		 * exists, we say its zoneid is -1.
		 */
		if (zone->zone_uniqid == ct->ct_czuniqid ||
		    ct->ct_czuniqid == GLOBAL_ZONEUNIQID) {
			zoneid = ct->ct_zoneid;
		} else if ((czone = zone_find_by_id(ct->ct_zoneid)) != NULL) {
			if (czone->zone_uniqid == ct->ct_mzuniqid)
				zoneid = ct->ct_zoneid;
			zone_rele(czone);
		}

		STRUCT_FSET(lstatus, ctst_zoneid, zoneid);
		STRUCT_FSET(lstatus, ctst_holder,
		    (ct->ct_state == CTS_OWNED) ? ct->ct_owner->p_pid :
		    (ct->ct_state == CTS_INHERITED) ? ct->ct_regent->ct_id : 0);
		STRUCT_FSET(lstatus, ctst_state, ct->ct_state);
	} else {
		/*
		 * We are looking at a contract which was created by a
		 * process outside of our zone.  We provide fake zone,
		 * holder, and state information.
		 */

		STRUCT_FSET(lstatus, ctst_zoneid, zone->zone_id);
		/*
		 * Since "zone" can't disappear until the calling ctfs
		 * is unmounted, zone_zsched must be valid.
		 */
		STRUCT_FSET(lstatus, ctst_holder, (ct->ct_state < CTS_ORPHAN) ?
		    zone->zone_zsched->p_pid : 0);
		STRUCT_FSET(lstatus, ctst_state, (ct->ct_state < CTS_ORPHAN) ?
		    CTS_OWNED : ct->ct_state);
	}
	STRUCT_FSET(lstatus, ctst_nevents, ct->ct_evcnt);
	STRUCT_FSET(lstatus, ctst_ntime, get_time_left(&ct->ct_ntime));
	STRUCT_FSET(lstatus, ctst_qtime, get_time_left(&ct->ct_qtime));
	STRUCT_FSET(lstatus, ctst_nevid,
	    ct->ct_nevent ? ct->ct_nevent->cte_id : 0);
	STRUCT_FSET(lstatus, ctst_critical, ct->ct_ev_crit);
	STRUCT_FSET(lstatus, ctst_informative, ct->ct_ev_info);
	STRUCT_FSET(lstatus, ctst_cookie, ct->ct_cookie);
	STRUCT_FSET(lstatus, ctst_type, ct->ct_type->ct_type_index);
	STRUCT_FSET(lstatus, ctst_id, ct->ct_id);
}

/*
 * contract_checkcred
 *
 * Determines if the specified contract is owned by a process with the
 * same effective uid as the specified credential.  The caller must
 * ensure that the uid spaces are the same.  Returns 1 on success.
 */
static int
contract_checkcred(contract_t *ct, const cred_t *cr)
{
	proc_t *p;
	int fail = 1;

	mutex_enter(&ct->ct_lock);
	if ((p = ct->ct_owner) != NULL) {
		mutex_enter(&p->p_crlock);
		fail = crgetuid(cr) != crgetuid(p->p_cred);
		mutex_exit(&p->p_crlock);
	}
	mutex_exit(&ct->ct_lock);

	return (!fail);
}

/*
 * contract_owned
 *
 * Determines if the specified credential can view an event generated
 * by the specified contract.  If locked is set, the contract's ct_lock
 * is held and the caller will need to do additional work to determine
 * if they truly can see the event.  Returns 1 on success.
 */
int
contract_owned(contract_t *ct, const cred_t *cr, int locked)
{
	int owner, cmatch, zmatch;
	uint64_t zuniqid, mzuniqid;
	uid_t euid;

	ASSERT(locked || MUTEX_NOT_HELD(&ct->ct_lock));

	zuniqid = curproc->p_zone->zone_uniqid;
	mzuniqid = contract_getzuniqid(ct);
	euid = crgetuid(cr);

	/*
	 * owner: we own the contract
	 * cmatch: we are in the creator's (and holder's) zone and our
	 *   uid matches the creator's or holder's
	 * zmatch: we are in the effective zone of a contract created
	 *   in the global zone, and our uid matches that of the
	 *   virtualized holder's (zsched/kcred)
	 */
	owner = (ct->ct_owner == curproc);
	cmatch = (zuniqid == ct->ct_czuniqid) &&
	    ((ct->ct_cuid == euid) || (!locked && contract_checkcred(ct, cr)));
	zmatch = (ct->ct_czuniqid != mzuniqid) && (zuniqid == mzuniqid) &&
	    (crgetuid(kcred) == euid);

	return (owner || cmatch || zmatch);
}


/*
 * contract_type_init
 *
 * Called by contract types to register themselves with the contracts
 * framework.
 */
ct_type_t *
contract_type_init(ct_typeid_t type, const char *name, contops_t *ops,
    ct_f_default_t *dfault)
{
	ct_type_t *result;

	ASSERT(type < CTT_MAXTYPE);

	result = kmem_alloc(sizeof (ct_type_t), KM_SLEEP);

	mutex_init(&result->ct_type_lock, NULL, MUTEX_DEFAULT, NULL);
	avl_create(&result->ct_type_avl, contract_compar, sizeof (contract_t),
	    offsetof(contract_t, ct_cttavl));
	cte_queue_create(&result->ct_type_events, CTEL_BUNDLE, 20, 0);
	result->ct_type_name = name;
	result->ct_type_ops = ops;
	result->ct_type_default = dfault;
	result->ct_type_evid = 0;
	gethrestime(&result->ct_type_timestruc);
	result->ct_type_index = type;

	ct_types[type] = result;

	return (result);
}

/*
 * contract_type_count
 *
 * Obtains the number of contracts of a particular type.
 */
int
contract_type_count(ct_type_t *type)
{
	ulong_t count;

	mutex_enter(&type->ct_type_lock);
	count = avl_numnodes(&type->ct_type_avl);
	mutex_exit(&type->ct_type_lock);

	return (count);
}

/*
 * contract_type_max
 *
 * Obtains the maximum contract id of of a particular type.
 */
ctid_t
contract_type_max(ct_type_t *type)
{
	contract_t *ct;
	ctid_t res;

	mutex_enter(&type->ct_type_lock);
	ct = avl_last(&type->ct_type_avl);
	res = ct ? ct->ct_id : -1;
	mutex_exit(&type->ct_type_lock);

	return (res);
}

/*
 * contract_max
 *
 * Obtains the maximum contract id.
 */
ctid_t
contract_max(void)
{
	contract_t *ct;
	ctid_t res;

	mutex_enter(&contract_lock);
	ct = avl_last(&contract_avl);
	res = ct ? ct->ct_id : -1;
	mutex_exit(&contract_lock);

	return (res);
}

/*
 * contract_lookup_common
 *
 * Common code for contract_lookup and contract_type_lookup.  Takes a
 * pointer to an AVL tree to search in.  Should be called with the
 * appropriate tree-protecting lock held (unfortunately unassertable).
 */
static ctid_t
contract_lookup_common(avl_tree_t *tree, uint64_t zuniqid, ctid_t current)
{
	contract_t template, *ct;
	avl_index_t where;
	ctid_t res;

	template.ct_id = current;
	ct = avl_find(tree, &template, &where);
	if (ct == NULL)
		ct = avl_nearest(tree, where, AVL_AFTER);
	if (zuniqid != GLOBAL_ZONEUNIQID)
		while (ct && (contract_getzuniqid(ct) != zuniqid))
			ct = AVL_NEXT(tree, ct);
	res = ct ? ct->ct_id : -1;

	return (res);
}

/*
 * contract_type_lookup
 *
 * Returns the next type contract after the specified id, visible from
 * the specified zone.
 */
ctid_t
contract_type_lookup(ct_type_t *type, uint64_t zuniqid, ctid_t current)
{
	ctid_t res;

	mutex_enter(&type->ct_type_lock);
	res = contract_lookup_common(&type->ct_type_avl, zuniqid, current);
	mutex_exit(&type->ct_type_lock);

	return (res);
}

/*
 * contract_lookup
 *
 * Returns the next contract after the specified id, visible from the
 * specified zone.
 */
ctid_t
contract_lookup(uint64_t zuniqid, ctid_t current)
{
	ctid_t res;

	mutex_enter(&contract_lock);
	res = contract_lookup_common(&contract_avl, zuniqid, current);
	mutex_exit(&contract_lock);

	return (res);
}

/*
 * contract_plookup
 *
 * Returns the next contract held by process p after the specified id,
 * visible from the specified zone.  Made complicated by the fact that
 * contracts visible in a zone but held by processes outside of the
 * zone need to appear as being held by zsched to zone members.
 */
ctid_t
contract_plookup(proc_t *p, ctid_t current, uint64_t zuniqid)
{
	contract_t template, *ct;
	avl_index_t where;
	ctid_t res;

	template.ct_id = current;
	if (zuniqid != GLOBAL_ZONEUNIQID &&
	    (p->p_flag & (SSYS|SZONETOP)) == (SSYS|SZONETOP)) {
		/* This is inelegant. */
		mutex_enter(&contract_lock);
		ct = avl_find(&contract_avl, &template, &where);
		if (ct == NULL)
			ct = avl_nearest(&contract_avl, where, AVL_AFTER);
		while (ct && !(ct->ct_state < CTS_ORPHAN &&
		    contract_getzuniqid(ct) == zuniqid &&
		    ct->ct_czuniqid == GLOBAL_ZONEUNIQID))
			ct = AVL_NEXT(&contract_avl, ct);
		res = ct ? ct->ct_id : -1;
		mutex_exit(&contract_lock);
	} else {
		mutex_enter(&p->p_lock);
		ct = avl_find(&p->p_ct_held, &template, &where);
		if (ct == NULL)
			ct = avl_nearest(&p->p_ct_held, where, AVL_AFTER);
		res = ct ? ct->ct_id : -1;
		mutex_exit(&p->p_lock);
	}

	return (res);
}

/*
 * contract_ptr_common
 *
 * Common code for contract_ptr and contract_type_ptr.  Takes a pointer
 * to an AVL tree to search in.  Should be called with the appropriate
 * tree-protecting lock held (unfortunately unassertable).
 */
static contract_t *
contract_ptr_common(avl_tree_t *tree, ctid_t id, uint64_t zuniqid)
{
	contract_t template, *ct;

	template.ct_id = id;
	ct = avl_find(tree, &template, NULL);
	if (ct == NULL || (zuniqid != GLOBAL_ZONEUNIQID &&
	    contract_getzuniqid(ct) != zuniqid)) {
		return (NULL);
	}

	/*
	 * Check to see if a thread is in the window in contract_rele
	 * between dropping the reference count and removing the
	 * contract from the type AVL.
	 */
	mutex_enter(&ct->ct_reflock);
	if (ct->ct_ref) {
		ct->ct_ref++;
		mutex_exit(&ct->ct_reflock);
	} else {
		mutex_exit(&ct->ct_reflock);
		ct = NULL;
	}

	return (ct);
}

/*
 * contract_type_ptr
 *
 * Returns a pointer to the contract with the specified id.  The
 * contract is held, so the caller needs to release the reference when
 * it is through with the contract.
 */
contract_t *
contract_type_ptr(ct_type_t *type, ctid_t id, uint64_t zuniqid)
{
	contract_t *ct;

	mutex_enter(&type->ct_type_lock);
	ct = contract_ptr_common(&type->ct_type_avl, id, zuniqid);
	mutex_exit(&type->ct_type_lock);

	return (ct);
}

/*
 * contract_ptr
 *
 * Returns a pointer to the contract with the specified id.  The
 * contract is held, so the caller needs to release the reference when
 * it is through with the contract.
 */
contract_t *
contract_ptr(ctid_t id, uint64_t zuniqid)
{
	contract_t *ct;

	mutex_enter(&contract_lock);
	ct = contract_ptr_common(&contract_avl, id, zuniqid);
	mutex_exit(&contract_lock);

	return (ct);
}

/*
 * contract_type_time
 *
 * Obtains the last time a contract of a particular type was created.
 */
void
contract_type_time(ct_type_t *type, timestruc_t *time)
{
	mutex_enter(&type->ct_type_lock);
	*time = type->ct_type_timestruc;
	mutex_exit(&type->ct_type_lock);
}

/*
 * contract_type_bundle
 *
 * Obtains a type's bundle queue.
 */
ct_equeue_t *
contract_type_bundle(ct_type_t *type)
{
	return (&type->ct_type_events);
}

/*
 * contract_type_pbundle
 *
 * Obtain's a process's bundle queue.  If one doesn't exist, one is
 * created.  Often used simply to ensure that a bundle queue is
 * allocated.
 */
ct_equeue_t *
contract_type_pbundle(ct_type_t *type, proc_t *pp)
{
	/*
	 * If there isn't an array of bundle queues, allocate one.
	 */
	if (pp->p_ct_equeue == NULL) {
		size_t size = CTT_MAXTYPE * sizeof (ct_equeue_t *);
		ct_equeue_t **qa = kmem_zalloc(size, KM_SLEEP);

		mutex_enter(&pp->p_lock);
		if (pp->p_ct_equeue)
			kmem_free(qa, size);
		else
			pp->p_ct_equeue = qa;
		mutex_exit(&pp->p_lock);
	}

	/*
	 * If there isn't a bundle queue of the required type, allocate
	 * one.
	 */
	if (pp->p_ct_equeue[type->ct_type_index] == NULL) {
		ct_equeue_t *q = kmem_zalloc(sizeof (ct_equeue_t), KM_SLEEP);
		cte_queue_create(q, CTEL_PBUNDLE, 20, 1);

		mutex_enter(&pp->p_lock);
		if (pp->p_ct_equeue[type->ct_type_index])
			cte_queue_drain(q, 0);
		else
			pp->p_ct_equeue[type->ct_type_index] = q;
		mutex_exit(&pp->p_lock);
	}

	return (pp->p_ct_equeue[type->ct_type_index]);
}

/*
 * ctparam_copyin
 *
 * copyin a ct_param_t for CT_TSET or CT_TGET commands.
 * If ctparam_copyout() is not called after ctparam_copyin(), then
 * the caller must kmem_free() the buffer pointed by kparam->ctpm_kbuf.
 *
 * The copyin/out of ct_param_t is not done in ctmpl_set() and ctmpl_get()
 * because prctioctl() calls ctmpl_set() and ctmpl_get() while holding a
 * process lock.
 */
int
ctparam_copyin(const void *uaddr, ct_kparam_t *kparam, int flag, int cmd)
{
	uint32_t size;
	void *ubuf;
	ct_param_t *param = &kparam->param;
	STRUCT_DECL(ct_param, uarg);

	STRUCT_INIT(uarg, flag);
	if (copyin(uaddr, STRUCT_BUF(uarg), STRUCT_SIZE(uarg)))
		return (EFAULT);
	size = STRUCT_FGET(uarg, ctpm_size);
	ubuf = STRUCT_FGETP(uarg, ctpm_value);

	if (size > CT_PARAM_MAX_SIZE || size == 0)
		return (EINVAL);

	kparam->ctpm_kbuf = kmem_alloc(size, KM_SLEEP);
	if (cmd == CT_TSET) {
		if (copyin(ubuf, kparam->ctpm_kbuf, size)) {
			kmem_free(kparam->ctpm_kbuf, size);
			return (EFAULT);
		}
	}
	param->ctpm_id = STRUCT_FGET(uarg, ctpm_id);
	param->ctpm_size = size;
	param->ctpm_value = ubuf;
	kparam->ret_size = 0;

	return (0);
}

/*
 * ctparam_copyout
 *
 * copyout a ct_kparam_t and frees the buffer pointed by the member
 * ctpm_kbuf of ct_kparam_t
 */
int
ctparam_copyout(ct_kparam_t *kparam, void *uaddr, int flag)
{
	int r = 0;
	ct_param_t *param = &kparam->param;
	STRUCT_DECL(ct_param, uarg);

	STRUCT_INIT(uarg, flag);

	STRUCT_FSET(uarg, ctpm_id, param->ctpm_id);
	STRUCT_FSET(uarg, ctpm_size, kparam->ret_size);
	STRUCT_FSETP(uarg, ctpm_value, param->ctpm_value);
	if (copyout(STRUCT_BUF(uarg), uaddr, STRUCT_SIZE(uarg))) {
		r = EFAULT;
		goto error;
	}
	if (copyout(kparam->ctpm_kbuf, param->ctpm_value,
	    MIN(kparam->ret_size, param->ctpm_size))) {
		r = EFAULT;
	}

error:
	kmem_free(kparam->ctpm_kbuf, param->ctpm_size);

	return (r);
}

/*
 * ctmpl_free
 *
 * Frees a template.
 */
void
ctmpl_free(ct_template_t *template)
{
	mutex_destroy(&template->ctmpl_lock);
	template->ctmpl_ops->ctop_free(template);
}

/*
 * ctmpl_dup
 *
 * Creates a copy of a template.
 */
ct_template_t *
ctmpl_dup(ct_template_t *template)
{
	ct_template_t *new;

	if (template == NULL)
		return (NULL);

	new = template->ctmpl_ops->ctop_dup(template);
	/*
	 * ctmpl_lock was taken by ctop_dup's call to ctmpl_copy and
	 * should have remain held until now.
	 */
	mutex_exit(&template->ctmpl_lock);

	return (new);
}

/*
 * ctmpl_set
 *
 * Sets the requested terms of a template.
 */
int
ctmpl_set(ct_template_t *template, ct_kparam_t *kparam, const cred_t *cr)
{
	int result = 0;
	ct_param_t *param = &kparam->param;
	uint64_t param_value;

	if (param->ctpm_id == CTP_COOKIE ||
	    param->ctpm_id == CTP_EV_INFO ||
	    param->ctpm_id == CTP_EV_CRITICAL) {
		if (param->ctpm_size < sizeof (uint64_t)) {
			return (EINVAL);
		} else {
			param_value = *(uint64_t *)kparam->ctpm_kbuf;
		}
	}

	mutex_enter(&template->ctmpl_lock);
	switch (param->ctpm_id) {
	case CTP_COOKIE:
		template->ctmpl_cookie = param_value;
		break;
	case CTP_EV_INFO:
		if (param_value & ~(uint64_t)template->ctmpl_ops->allevents)
			result = EINVAL;
		else
			template->ctmpl_ev_info = param_value;
		break;
	case CTP_EV_CRITICAL:
		if (param_value & ~(uint64_t)template->ctmpl_ops->allevents) {
			result = EINVAL;
			break;
		} else if ((~template->ctmpl_ev_crit & param_value) == 0) {
			/*
			 * Assume that a pure reduction of the critical
			 * set is allowed by the contract type.
			 */
			template->ctmpl_ev_crit = param_value;
			break;
		}
		/*
		 * There may be restrictions on what we can make
		 * critical, so we defer to the judgement of the
		 * contract type.
		 */
		/* FALLTHROUGH */
	default:
		result = template->ctmpl_ops->ctop_set(template, kparam, cr);
	}
	mutex_exit(&template->ctmpl_lock);

	return (result);
}

/*
 * ctmpl_get
 *
 * Obtains the requested terms from a template.
 *
 * If the term requested is a variable-sized term and the buffer
 * provided is too small for the data, we truncate the data and return
 * the buffer size necessary to fit the term in kparam->ret_size. If the
 * term requested is fix-sized (uint64_t) and the buffer provided is too
 * small, we return EINVAL.  This should never happen if you're using
 * libcontract(3LIB), only if you call ioctl with a hand constructed
 * ct_param_t argument.
 *
 * Currently, only contract specific parameters have variable-sized
 * parameters.
 */
int
ctmpl_get(ct_template_t *template, ct_kparam_t *kparam)
{
	int result = 0;
	ct_param_t *param = &kparam->param;
	uint64_t *param_value;

	if (param->ctpm_id == CTP_COOKIE ||
	    param->ctpm_id == CTP_EV_INFO ||
	    param->ctpm_id == CTP_EV_CRITICAL) {
		if (param->ctpm_size < sizeof (uint64_t)) {
			return (EINVAL);
		} else {
			param_value = kparam->ctpm_kbuf;
			kparam->ret_size = sizeof (uint64_t);
		}
	}

	mutex_enter(&template->ctmpl_lock);
	switch (param->ctpm_id) {
	case CTP_COOKIE:
		*param_value = template->ctmpl_cookie;
		break;
	case CTP_EV_INFO:
		*param_value = template->ctmpl_ev_info;
		break;
	case CTP_EV_CRITICAL:
		*param_value = template->ctmpl_ev_crit;
		break;
	default:
		result = template->ctmpl_ops->ctop_get(template, kparam);
	}
	mutex_exit(&template->ctmpl_lock);

	return (result);
}

/*
 * ctmpl_makecurrent
 *
 * Used by ctmpl_activate and ctmpl_clear to set the current thread's
 * active template.  Frees the old active template, if there was one.
 */
static void
ctmpl_makecurrent(ct_template_t *template, ct_template_t *new)
{
	klwp_t *curlwp = ttolwp(curthread);
	proc_t *p = curproc;
	ct_template_t *old;

	mutex_enter(&p->p_lock);
	old = curlwp->lwp_ct_active[template->ctmpl_type->ct_type_index];
	curlwp->lwp_ct_active[template->ctmpl_type->ct_type_index] = new;
	mutex_exit(&p->p_lock);

	if (old)
		ctmpl_free(old);
}

/*
 * ctmpl_activate
 *
 * Copy the specified template as the current thread's activate
 * template of that type.
 */
void
ctmpl_activate(ct_template_t *template)
{
	ctmpl_makecurrent(template, ctmpl_dup(template));
}

/*
 * ctmpl_clear
 *
 * Clears the current thread's activate template of the same type as
 * the specified template.
 */
void
ctmpl_clear(ct_template_t *template)
{
	ctmpl_makecurrent(template, NULL);
}

/*
 * ctmpl_create
 *
 * Creates a new contract using the specified template.
 */
int
ctmpl_create(ct_template_t *template, ctid_t *ctidp)
{
	return (template->ctmpl_ops->ctop_create(template, ctidp));
}

/*
 * ctmpl_init
 *
 * Initializes the common portion of a new contract template.
 */
void
ctmpl_init(ct_template_t *new, ctmplops_t *ops, ct_type_t *type, void *data)
{
	mutex_init(&new->ctmpl_lock, NULL, MUTEX_DEFAULT, NULL);
	new->ctmpl_ops = ops;
	new->ctmpl_type = type;
	new->ctmpl_data = data;
	new->ctmpl_ev_info = new->ctmpl_ev_crit = 0;
	new->ctmpl_cookie = 0;
}

/*
 * ctmpl_copy
 *
 * Copies the common portions of a contract template.  Intended for use
 * by a contract type's ctop_dup template op.  Returns with the old
 * template's lock held, which will should remain held until the
 * template op returns (it is dropped by ctmpl_dup).
 */
void
ctmpl_copy(ct_template_t *new, ct_template_t *old)
{
	mutex_init(&new->ctmpl_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_enter(&old->ctmpl_lock);
	new->ctmpl_ops = old->ctmpl_ops;
	new->ctmpl_type = old->ctmpl_type;
	new->ctmpl_ev_crit = old->ctmpl_ev_crit;
	new->ctmpl_ev_info = old->ctmpl_ev_info;
	new->ctmpl_cookie = old->ctmpl_cookie;
}

/*
 * ctmpl_create_inval
 *
 * Returns EINVAL.  Provided for the convenience of those contract
 * types which don't support ct_tmpl_create(3contract) and would
 * otherwise need to create their own stub for the ctop_create template
 * op.
 */
/*ARGSUSED*/
int
ctmpl_create_inval(ct_template_t *template, ctid_t *ctidp)
{
	return (EINVAL);
}


/*
 * cte_queue_create
 *
 * Initializes a queue of a particular type.  If dynamic is set, the
 * queue is to be freed when its last listener is removed after being
 * drained.
 */
static void
cte_queue_create(ct_equeue_t *q, ct_listnum_t list, int maxinf, int dynamic)
{
	mutex_init(&q->ctq_lock, NULL, MUTEX_DEFAULT, NULL);
	q->ctq_listno = list;
	list_create(&q->ctq_events, sizeof (ct_kevent_t),
	    offsetof(ct_kevent_t, cte_nodes[list].ctm_node));
	list_create(&q->ctq_listeners, sizeof (ct_listener_t),
	    offsetof(ct_listener_t, ctl_allnode));
	list_create(&q->ctq_tail, sizeof (ct_listener_t),
	    offsetof(ct_listener_t, ctl_tailnode));
	gethrestime(&q->ctq_atime);
	q->ctq_nlisteners = 0;
	q->ctq_nreliable = 0;
	q->ctq_ninf = 0;
	q->ctq_max = maxinf;

	/*
	 * Bundle queues and contract queues are embedded in other
	 * structures and are implicitly referenced counted by virtue
	 * of their vnodes' indirect hold on their contracts.  Process
	 * bundle queues are dynamically allocated and may persist
	 * after the death of the process, so they must be explicitly
	 * reference counted.
	 */
	q->ctq_flags = dynamic ? CTQ_REFFED : 0;
}

/*
 * cte_queue_destroy
 *
 * Destroys the specified queue.  The queue is freed if referenced
 * counted.
 */
static void
cte_queue_destroy(ct_equeue_t *q)
{
	ASSERT(q->ctq_flags & CTQ_DEAD);
	ASSERT(q->ctq_nlisteners == 0);
	ASSERT(q->ctq_nreliable == 0);
	list_destroy(&q->ctq_events);
	list_destroy(&q->ctq_listeners);
	list_destroy(&q->ctq_tail);
	mutex_destroy(&q->ctq_lock);
	if (q->ctq_flags & CTQ_REFFED)
		kmem_free(q, sizeof (ct_equeue_t));
}

/*
 * cte_hold
 *
 * Takes a hold on the specified event.
 */
static void
cte_hold(ct_kevent_t *e)
{
	mutex_enter(&e->cte_lock);
	ASSERT(e->cte_refs > 0);
	e->cte_refs++;
	mutex_exit(&e->cte_lock);
}

/*
 * cte_rele
 *
 * Releases a hold on the specified event.  If the caller had the last
 * reference, frees the event and releases its hold on the contract
 * that generated it.
 */
static void
cte_rele(ct_kevent_t *e)
{
	mutex_enter(&e->cte_lock);
	ASSERT(e->cte_refs > 0);
	if (--e->cte_refs) {
		mutex_exit(&e->cte_lock);
		return;
	}

	contract_rele(e->cte_contract);

	mutex_destroy(&e->cte_lock);
	nvlist_free(e->cte_data);
	nvlist_free(e->cte_gdata);
	kmem_free(e, sizeof (ct_kevent_t));
}

/*
 * cte_qrele
 *
 * Remove this listener's hold on the specified event, removing and
 * releasing the queue's hold on the event if appropriate.
 */
static void
cte_qrele(ct_equeue_t *q, ct_listener_t *l, ct_kevent_t *e)
{
	ct_member_t *member = &e->cte_nodes[q->ctq_listno];

	ASSERT(MUTEX_HELD(&q->ctq_lock));

	if (l->ctl_flags & CTLF_RELIABLE)
		member->ctm_nreliable--;
	if ((--member->ctm_refs == 0) && member->ctm_trimmed) {
		member->ctm_trimmed = 0;
		list_remove(&q->ctq_events, e);
		cte_rele(e);
	}
}

/*
 * cte_qmove
 *
 * Move this listener to the specified event in the queue.
 */
static ct_kevent_t *
cte_qmove(ct_equeue_t *q, ct_listener_t *l, ct_kevent_t *e)
{
	ct_kevent_t *olde;

	ASSERT(MUTEX_HELD(&q->ctq_lock));
	ASSERT(l->ctl_equeue == q);

	if ((olde = l->ctl_position) == NULL)
		list_remove(&q->ctq_tail, l);

	while (e != NULL && e->cte_nodes[q->ctq_listno].ctm_trimmed)
		e = list_next(&q->ctq_events, e);

	if (e != NULL) {
		e->cte_nodes[q->ctq_listno].ctm_refs++;
		if (l->ctl_flags & CTLF_RELIABLE)
			e->cte_nodes[q->ctq_listno].ctm_nreliable++;
	} else {
		list_insert_tail(&q->ctq_tail, l);
	}

	l->ctl_position = e;
	if (olde)
		cte_qrele(q, l, olde);

	return (e);
}

/*
 * cte_checkcred
 *
 * Determines if the specified event's contract is owned by a process
 * with the same effective uid as the specified credential.  Called
 * after a failed call to contract_owned with locked set.  Because it
 * drops the queue lock, its caller (cte_qreadable) needs to make sure
 * we're still in the same place after we return.  Returns 1 on
 * success.
 */
static int
cte_checkcred(ct_equeue_t *q, ct_kevent_t *e, const cred_t *cr)
{
	int result;
	contract_t *ct = e->cte_contract;

	cte_hold(e);
	mutex_exit(&q->ctq_lock);
	result = curproc->p_zone->zone_uniqid == ct->ct_czuniqid &&
	    contract_checkcred(ct, cr);
	mutex_enter(&q->ctq_lock);
	cte_rele(e);

	return (result);
}

/*
 * cte_qreadable
 *
 * Ensures that the listener is pointing to a valid event that the
 * caller has the credentials to read.  Returns 0 if we can read the
 * event we're pointing to.
 */
static int
cte_qreadable(ct_equeue_t *q, ct_listener_t *l, const cred_t *cr,
    uint64_t zuniqid, int crit)
{
	ct_kevent_t *e, *next;
	contract_t *ct;

	ASSERT(MUTEX_HELD(&q->ctq_lock));
	ASSERT(l->ctl_equeue == q);

	if (l->ctl_flags & CTLF_COPYOUT)
		return (1);

	next = l->ctl_position;
	while (e = cte_qmove(q, l, next)) {
		ct = e->cte_contract;
		/*
		 * Check obvious things first.  If we are looking for a
		 * critical message, is this one?  If we aren't in the
		 * global zone, is this message meant for us?
		 */
		if ((crit && (e->cte_flags & (CTE_INFO | CTE_ACK))) ||
		    (cr != NULL && zuniqid != GLOBAL_ZONEUNIQID &&
		    zuniqid != contract_getzuniqid(ct))) {

			next = list_next(&q->ctq_events, e);

		/*
		 * Next, see if our effective uid equals that of owner
		 * or author of the contract.  Since we are holding the
		 * queue lock, contract_owned can't always check if we
		 * have the same effective uid as the contract's
		 * owner.  If it comes to that, it fails and we take
		 * the slow(er) path.
		 */
		} else if (cr != NULL && !contract_owned(ct, cr, B_TRUE)) {

			/*
			 * At this point we either don't have any claim
			 * to this contract or we match the effective
			 * uid of the owner but couldn't tell.  We
			 * first test for a NULL holder so that events
			 * from orphans and inherited contracts avoid
			 * the penalty phase.
			 */
			if (e->cte_contract->ct_owner == NULL &&
			    !secpolicy_contract_observer_choice(cr))
				next = list_next(&q->ctq_events, e);

			/*
			 * cte_checkcred will juggle locks to see if we
			 * have the same uid as the event's contract's
			 * current owner.  If it succeeds, we have to
			 * make sure we are in the same point in the
			 * queue.
			 */
			else if (cte_checkcred(q, e, cr) &&
			    l->ctl_position == e)
				break;

			/*
			 * cte_checkcred failed; see if we're in the
			 * same place.
			 */
			else if (l->ctl_position == e)
				if (secpolicy_contract_observer_choice(cr))
					break;
				else
					next = list_next(&q->ctq_events, e);

			/*
			 * cte_checkcred failed, and our position was
			 * changed.  Start from there.
			 */
			else
				next = l->ctl_position;
		} else {
			break;
		}
	}

	/*
	 * We check for CTLF_COPYOUT again in case we dropped the queue
	 * lock in cte_checkcred.
	 */
	return ((l->ctl_flags & CTLF_COPYOUT) || (l->ctl_position == NULL));
}

/*
 * cte_qwakeup
 *
 * Wakes up any waiting listeners and points them at the specified event.
 */
static void
cte_qwakeup(ct_equeue_t *q, ct_kevent_t *e)
{
	ct_listener_t *l;

	ASSERT(MUTEX_HELD(&q->ctq_lock));

	while (l = list_head(&q->ctq_tail)) {
		list_remove(&q->ctq_tail, l);
		e->cte_nodes[q->ctq_listno].ctm_refs++;
		if (l->ctl_flags & CTLF_RELIABLE)
			e->cte_nodes[q->ctq_listno].ctm_nreliable++;
		l->ctl_position = e;
		cv_signal(&l->ctl_cv);
		pollwakeup(&l->ctl_pollhead, POLLIN);
	}
}

/*
 * cte_copy
 *
 * Copies events from the specified contract event queue to the
 * end of the specified process bundle queue.  Only called from
 * contract_adopt.
 *
 * We copy to the end of the target queue instead of mixing the events
 * in their proper order because otherwise the act of adopting a
 * contract would require a process to reset all process bundle
 * listeners it needed to see the new events.  This would, in turn,
 * require the process to keep track of which preexisting events had
 * already been processed.
 */
static void
cte_copy(ct_equeue_t *q, ct_equeue_t *newq)
{
	ct_kevent_t *e, *first = NULL;

	VERIFY(q->ctq_listno == CTEL_CONTRACT);
	VERIFY(newq->ctq_listno == CTEL_PBUNDLE);

	mutex_enter(&q->ctq_lock);
	mutex_enter(&newq->ctq_lock);

	/*
	 * For now, only copy critical events.
	 */
	for (e = list_head(&q->ctq_events); e != NULL;
	    e = list_next(&q->ctq_events, e)) {
		if ((e->cte_flags & (CTE_INFO | CTE_ACK)) == 0) {
			if (first == NULL)
				first = e;
			/*
			 * It is possible for adoption to race with an owner's
			 * cte_publish_all(); we must only enqueue events that
			 * have not already been enqueued.
			 */
			if (!list_link_active((list_node_t *)
			    ((uintptr_t)e + newq->ctq_events.list_offset))) {
				list_insert_tail(&newq->ctq_events, e);
				cte_hold(e);
			}
		}
	}

	mutex_exit(&q->ctq_lock);

	if (first)
		cte_qwakeup(newq, first);

	mutex_exit(&newq->ctq_lock);
}

/*
 * cte_trim
 *
 * Trims unneeded events from an event queue.  Algorithm works as
 * follows:
 *
 *   Removes all informative and acknowledged critical events until the
 *   first referenced event is found.
 *
 *   If a contract is specified, removes all events (regardless of
 *   acknowledgement) generated by that contract until the first event
 *   referenced by a reliable listener is found.  Reference events are
 *   removed by marking them "trimmed".  Such events will be removed
 *   when the last reference is dropped and will be skipped by future
 *   listeners.
 *
 * This is pretty basic.  Ideally this should remove from the middle of
 * the list (i.e. beyond the first referenced event), and even
 * referenced events.
 */
static void
cte_trim(ct_equeue_t *q, contract_t *ct)
{
	ct_kevent_t *e, *next;
	int flags, stopper;
	int start = 1;

	VERIFY(MUTEX_HELD(&q->ctq_lock));

	for (e = list_head(&q->ctq_events); e != NULL; e = next) {
		next = list_next(&q->ctq_events, e);
		flags = e->cte_flags;
		stopper = (q->ctq_listno != CTEL_PBUNDLE) &&
		    (e->cte_nodes[q->ctq_listno].ctm_nreliable > 0);
		if (e->cte_nodes[q->ctq_listno].ctm_refs == 0) {
			if ((start && (flags & (CTE_INFO | CTE_ACK))) ||
			    (e->cte_contract == ct)) {
				/*
				 * Toss informative and ACKed critical messages.
				 */
				list_remove(&q->ctq_events, e);
				cte_rele(e);
			}
		} else if ((e->cte_contract == ct) && !stopper) {
			ASSERT(q->ctq_nlisteners != 0);
			e->cte_nodes[q->ctq_listno].ctm_trimmed = 1;
		} else if (ct && !stopper) {
			start = 0;
		} else {
			/*
			 * Don't free messages past the first reader.
			 */
			break;
		}
	}
}

/*
 * cte_queue_drain
 *
 * Drain all events from the specified queue, and mark it dead.  If
 * "ack" is set, acknowledge any critical events we find along the
 * way.
 */
static void
cte_queue_drain(ct_equeue_t *q, int ack)
{
	ct_kevent_t *e, *next;
	ct_listener_t *l;

	mutex_enter(&q->ctq_lock);

	for (e = list_head(&q->ctq_events); e != NULL; e = next) {
		next = list_next(&q->ctq_events, e);
		if (ack && ((e->cte_flags & (CTE_INFO | CTE_ACK)) == 0)) {
			/*
			 * Make sure critical messages are eventually
			 * removed from the bundle queues.
			 */
			mutex_enter(&e->cte_lock);
			e->cte_flags |= CTE_ACK;
			mutex_exit(&e->cte_lock);
			ASSERT(MUTEX_HELD(&e->cte_contract->ct_lock));
			e->cte_contract->ct_evcnt--;
		}
		list_remove(&q->ctq_events, e);
		e->cte_nodes[q->ctq_listno].ctm_refs = 0;
		e->cte_nodes[q->ctq_listno].ctm_nreliable = 0;
		e->cte_nodes[q->ctq_listno].ctm_trimmed = 0;
		cte_rele(e);
	}

	/*
	 * This is necessary only because of CTEL_PBUNDLE listeners;
	 * the events they point to can move from one pbundle to
	 * another.  Fortunately, this only happens if the contract is
	 * inherited, which (in turn) only happens if the process
	 * exits, which means it's an all-or-nothing deal.  If this
	 * wasn't the case, we would instead need to keep track of
	 * listeners on a per-event basis, not just a per-queue basis.
	 * This would have the side benefit of letting us clean up
	 * trimmed events sooner (i.e. immediately), but would
	 * unfortunately make events even bigger than they already
	 * are.
	 */
	for (l = list_head(&q->ctq_listeners); l;
	    l = list_next(&q->ctq_listeners, l)) {
		l->ctl_flags |= CTLF_DEAD;
		if (l->ctl_position) {
			l->ctl_position = NULL;
			list_insert_tail(&q->ctq_tail, l);
		}
		cv_broadcast(&l->ctl_cv);
	}

	/*
	 * Disallow events.
	 */
	q->ctq_flags |= CTQ_DEAD;

	/*
	 * If we represent the last reference to a reference counted
	 * process bundle queue, free it.
	 */
	if ((q->ctq_flags & CTQ_REFFED) && (q->ctq_nlisteners == 0))
		cte_queue_destroy(q);
	else
		mutex_exit(&q->ctq_lock);
}

/*
 * cte_publish
 *
 * Publishes an event to a specific queue.  Only called by
 * cte_publish_all.
 */
static void
cte_publish(ct_equeue_t *q, ct_kevent_t *e, timespec_t *tsp, boolean_t mayexist)
{
	ASSERT(MUTEX_HELD(&q->ctq_lock));

	q->ctq_atime = *tsp;

	/*
	 * If this event may already exist on this queue, check to see if it
	 * is already there and return if so.
	 */
	if (mayexist && list_link_active((list_node_t *)((uintptr_t)e +
	    q->ctq_events.list_offset))) {
		mutex_exit(&q->ctq_lock);
		cte_rele(e);
		return;
	}

	/*
	 * Don't publish if the event is informative and there aren't
	 * any listeners, or if the queue has been shut down.
	 */
	if (((q->ctq_nlisteners == 0) && (e->cte_flags & (CTE_INFO|CTE_ACK))) ||
	    (q->ctq_flags & CTQ_DEAD)) {
		mutex_exit(&q->ctq_lock);
		cte_rele(e);
		return;
	}

	/*
	 * Enqueue event
	 */
	VERIFY(!list_link_active((list_node_t *)
	    ((uintptr_t)e + q->ctq_events.list_offset)));
	list_insert_tail(&q->ctq_events, e);

	/*
	 * Check for waiting listeners
	 */
	cte_qwakeup(q, e);

	/*
	 * Trim unnecessary events from the queue.
	 */
	cte_trim(q, NULL);
	mutex_exit(&q->ctq_lock);
}

/*
 * cte_publish_all
 *
 * Publish an event to all necessary event queues.  The event, e, must
 * be zallocated by the caller, and the event's flags and type must be
 * set.  The rest of the event's fields are initialized here.
 */
uint64_t
cte_publish_all(contract_t *ct, ct_kevent_t *e, nvlist_t *data, nvlist_t *gdata)
{
	ct_equeue_t *q;
	timespec_t ts;
	uint64_t evid;
	ct_kevent_t *negev;
	int negend;

	e->cte_contract = ct;
	e->cte_data = data;
	e->cte_gdata = gdata;
	e->cte_refs = 3;
	evid = e->cte_id = atomic_inc_64_nv(&ct->ct_type->ct_type_evid);
	contract_hold(ct);

	/*
	 * For a negotiation event we set the ct->ct_nevent field of the
	 * contract for the duration of the negotiation
	 */
	negend = 0;
	if (e->cte_flags & CTE_NEG) {
		cte_hold(e);
		ct->ct_nevent = e;
	} else if (e->cte_type == CT_EV_NEGEND) {
		negend = 1;
	}

	gethrestime(&ts);

	/*
	 * ct_evtlock simply (and only) ensures that two events sent
	 * from the same contract are delivered to all queues in the
	 * same order.
	 */
	mutex_enter(&ct->ct_evtlock);

	/*
	 * CTEL_CONTRACT - First deliver to the contract queue, acking
	 * the event if the contract has been orphaned.
	 */
	mutex_enter(&ct->ct_lock);
	mutex_enter(&ct->ct_events.ctq_lock);
	if ((e->cte_flags & CTE_INFO) == 0) {
		if (ct->ct_state >= CTS_ORPHAN)
			e->cte_flags |= CTE_ACK;
		else
			ct->ct_evcnt++;
	}
	mutex_exit(&ct->ct_lock);
	cte_publish(&ct->ct_events, e, &ts, B_FALSE);

	/*
	 * CTEL_BUNDLE - Next deliver to the contract type's bundle
	 * queue.
	 */
	mutex_enter(&ct->ct_type->ct_type_events.ctq_lock);
	cte_publish(&ct->ct_type->ct_type_events, e, &ts, B_FALSE);

	/*
	 * CTEL_PBUNDLE - Finally, if the contract has an owner,
	 * deliver to the owner's process bundle queue.
	 */
	mutex_enter(&ct->ct_lock);
	if (ct->ct_owner) {
		/*
		 * proc_exit doesn't free event queues until it has
		 * abandoned all contracts.
		 */
		ASSERT(ct->ct_owner->p_ct_equeue);
		ASSERT(ct->ct_owner->p_ct_equeue[ct->ct_type->ct_type_index]);
		q = ct->ct_owner->p_ct_equeue[ct->ct_type->ct_type_index];
		mutex_enter(&q->ctq_lock);
		mutex_exit(&ct->ct_lock);

		/*
		 * It is possible for this code to race with adoption; we
		 * publish the event indicating that the event may already
		 * be enqueued because adoption beat us to it (in which case
		 * cte_pubish() does nothing).
		 */
		cte_publish(q, e, &ts, B_TRUE);
	} else {
		mutex_exit(&ct->ct_lock);
		cte_rele(e);
	}

	if (negend) {
		mutex_enter(&ct->ct_lock);
		negev = ct->ct_nevent;
		ct->ct_nevent = NULL;
		cte_rele(negev);
		mutex_exit(&ct->ct_lock);
	}

	mutex_exit(&ct->ct_evtlock);

	return (evid);
}

/*
 * cte_add_listener
 *
 * Add a new listener to an event queue.
 */
void
cte_add_listener(ct_equeue_t *q, ct_listener_t *l)
{
	cv_init(&l->ctl_cv, NULL, CV_DEFAULT, NULL);
	l->ctl_equeue = q;
	l->ctl_position = NULL;
	l->ctl_flags = 0;

	mutex_enter(&q->ctq_lock);
	list_insert_head(&q->ctq_tail, l);
	list_insert_head(&q->ctq_listeners, l);
	q->ctq_nlisteners++;
	mutex_exit(&q->ctq_lock);
}

/*
 * cte_remove_listener
 *
 * Remove a listener from an event queue.  No other queue activities
 * (e.g. cte_get event) may be in progress at this endpoint when this
 * is called.
 */
void
cte_remove_listener(ct_listener_t *l)
{
	ct_equeue_t *q = l->ctl_equeue;
	ct_kevent_t *e;

	mutex_enter(&q->ctq_lock);

	ASSERT((l->ctl_flags & (CTLF_COPYOUT|CTLF_RESET)) == 0);

	if ((e = l->ctl_position) != NULL)
		cte_qrele(q, l, e);
	else
		list_remove(&q->ctq_tail, l);
	l->ctl_position = NULL;

	q->ctq_nlisteners--;
	list_remove(&q->ctq_listeners, l);

	if (l->ctl_flags & CTLF_RELIABLE)
		q->ctq_nreliable--;

	/*
	 * If we are a the last listener of a dead reference counted
	 * queue (i.e. a process bundle) we free it.  Otherwise we just
	 * trim any events which may have been kept around for our
	 * benefit.
	 */
	if ((q->ctq_flags & CTQ_REFFED) && (q->ctq_flags & CTQ_DEAD) &&
	    (q->ctq_nlisteners == 0)) {
		cte_queue_destroy(q);
	} else {
		cte_trim(q, NULL);
		mutex_exit(&q->ctq_lock);
	}
}

/*
 * cte_reset_listener
 *
 * Moves a listener's queue pointer to the beginning of the queue.
 */
void
cte_reset_listener(ct_listener_t *l)
{
	ct_equeue_t *q = l->ctl_equeue;

	mutex_enter(&q->ctq_lock);

	/*
	 * We allow an asynchronous reset because it doesn't make a
	 * whole lot of sense to make reset block or fail.  We already
	 * have most of the mechanism needed thanks to queue trimming,
	 * so implementing it isn't a big deal.
	 */
	if (l->ctl_flags & CTLF_COPYOUT)
		l->ctl_flags |= CTLF_RESET;

	(void) cte_qmove(q, l, list_head(&q->ctq_events));

	/*
	 * Inform blocked readers.
	 */
	cv_broadcast(&l->ctl_cv);
	pollwakeup(&l->ctl_pollhead, POLLIN);
	mutex_exit(&q->ctq_lock);
}

/*
 * cte_next_event
 *
 * Moves the event pointer for the specified listener to the next event
 * on the queue.  To avoid races, this movement only occurs if the
 * specified event id matches that of the current event.  This is used
 * primarily to skip events that have been read but whose extended data
 * haven't been copied out.
 */
int
cte_next_event(ct_listener_t *l, uint64_t id)
{
	ct_equeue_t *q = l->ctl_equeue;
	ct_kevent_t *old;

	mutex_enter(&q->ctq_lock);

	if (l->ctl_flags & CTLF_COPYOUT)
		l->ctl_flags |= CTLF_RESET;

	if (((old = l->ctl_position) != NULL) && (old->cte_id == id))
		(void) cte_qmove(q, l, list_next(&q->ctq_events, old));

	mutex_exit(&q->ctq_lock);

	return (0);
}

/*
 * cte_get_event
 *
 * Reads an event from an event endpoint.  If "nonblock" is clear, we
 * block until a suitable event is ready.  If "crit" is set, we only
 * read critical events.  Note that while "cr" is the caller's cred,
 * "zuniqid" is the unique id of the zone the calling contract
 * filesystem was mounted in.
 */
int
cte_get_event(ct_listener_t *l, int nonblock, void *uaddr, const cred_t *cr,
    uint64_t zuniqid, int crit)
{
	ct_equeue_t *q = l->ctl_equeue;
	ct_kevent_t *temp;
	int result = 0;
	int partial = 0;
	size_t size, gsize, len;
	model_t mdl = get_udatamodel();
	STRUCT_DECL(ct_event, ev);
	STRUCT_INIT(ev, mdl);

	/*
	 * cte_qreadable checks for CTLF_COPYOUT as well as ensures
	 * that there exists, and we are pointing to, an appropriate
	 * event.  It may temporarily drop ctq_lock, but that doesn't
	 * really matter to us.
	 */
	mutex_enter(&q->ctq_lock);
	while (cte_qreadable(q, l, cr, zuniqid, crit)) {
		if (nonblock) {
			result = EAGAIN;
			goto error;
		}
		if (q->ctq_flags & CTQ_DEAD) {
			result = EIDRM;
			goto error;
		}
		result = cv_wait_sig(&l->ctl_cv, &q->ctq_lock);
		if (result == 0) {
			result = EINTR;
			goto error;
		}
	}
	temp = l->ctl_position;
	cte_hold(temp);
	l->ctl_flags |= CTLF_COPYOUT;
	mutex_exit(&q->ctq_lock);

	/*
	 * We now have an event.  Copy in the user event structure to
	 * see how much space we have to work with.
	 */
	result = copyin(uaddr, STRUCT_BUF(ev), STRUCT_SIZE(ev));
	if (result)
		goto copyerr;

	/*
	 * Determine what data we have and what the user should be
	 * allowed to see.
	 */
	size = gsize = 0;
	if (temp->cte_data) {
		VERIFY(nvlist_size(temp->cte_data, &size,
		    NV_ENCODE_NATIVE) == 0);
		ASSERT(size != 0);
	}
	if (zuniqid == GLOBAL_ZONEUNIQID && temp->cte_gdata) {
		VERIFY(nvlist_size(temp->cte_gdata, &gsize,
		    NV_ENCODE_NATIVE) == 0);
		ASSERT(gsize != 0);
	}

	/*
	 * If we have enough space, copy out the extended event data.
	 */
	len = size + gsize;
	if (len) {
		if (STRUCT_FGET(ev, ctev_nbytes) >= len) {
			char *buf = kmem_alloc(len, KM_SLEEP);

			if (size)
				VERIFY(nvlist_pack(temp->cte_data, &buf, &size,
				    NV_ENCODE_NATIVE, KM_SLEEP) == 0);
			if (gsize) {
				char *tmp = buf + size;

				VERIFY(nvlist_pack(temp->cte_gdata, &tmp,
				    &gsize, NV_ENCODE_NATIVE, KM_SLEEP) == 0);
			}

			/* This shouldn't have changed */
			ASSERT(size + gsize == len);
			result = copyout(buf, STRUCT_FGETP(ev, ctev_buffer),
			    len);
			kmem_free(buf, len);
			if (result)
				goto copyerr;
		} else {
			partial = 1;
		}
	}

	/*
	 * Copy out the common event data.
	 */
	STRUCT_FSET(ev, ctev_id, temp->cte_contract->ct_id);
	STRUCT_FSET(ev, ctev_evid, temp->cte_id);
	STRUCT_FSET(ev, ctev_cttype,
	    temp->cte_contract->ct_type->ct_type_index);
	STRUCT_FSET(ev, ctev_flags, temp->cte_flags &
	    (CTE_ACK|CTE_INFO|CTE_NEG));
	STRUCT_FSET(ev, ctev_type, temp->cte_type);
	STRUCT_FSET(ev, ctev_nbytes, len);
	STRUCT_FSET(ev, ctev_goffset, size);
	result = copyout(STRUCT_BUF(ev), uaddr, STRUCT_SIZE(ev));

copyerr:
	/*
	 * Only move our location in the queue if all copyouts were
	 * successful, the caller provided enough space for the entire
	 * event, and our endpoint wasn't reset or otherwise moved by
	 * another thread.
	 */
	mutex_enter(&q->ctq_lock);
	if (result)
		result = EFAULT;
	else if (!partial && ((l->ctl_flags & CTLF_RESET) == 0) &&
	    (l->ctl_position == temp))
		(void) cte_qmove(q, l, list_next(&q->ctq_events, temp));
	l->ctl_flags &= ~(CTLF_COPYOUT|CTLF_RESET);
	/*
	 * Signal any readers blocked on our CTLF_COPYOUT.
	 */
	cv_signal(&l->ctl_cv);
	cte_rele(temp);

error:
	mutex_exit(&q->ctq_lock);
	return (result);
}

/*
 * cte_set_reliable
 *
 * Requests that events be reliably delivered to an event endpoint.
 * Unread informative and acknowledged critical events will not be
 * removed from the queue until this listener reads or skips them.
 * Because a listener could maliciously request reliable delivery and
 * then do nothing, this requires that PRIV_CONTRACT_EVENT be in the
 * caller's effective set.
 */
int
cte_set_reliable(ct_listener_t *l, const cred_t *cr)
{
	ct_equeue_t *q = l->ctl_equeue;
	int error;

	if ((error = secpolicy_contract_event(cr)) != 0)
		return (error);

	mutex_enter(&q->ctq_lock);
	if ((l->ctl_flags & CTLF_RELIABLE) == 0) {
		l->ctl_flags |= CTLF_RELIABLE;
		q->ctq_nreliable++;
		if (l->ctl_position != NULL)
			l->ctl_position->cte_nodes[q->ctq_listno].
			    ctm_nreliable++;
	}
	mutex_exit(&q->ctq_lock);

	return (0);
}
