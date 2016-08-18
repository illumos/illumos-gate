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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
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
#include <sys/contract.h>
#include <sys/contract_impl.h>
#include <sys/contract/device.h>
#include <sys/contract/device_impl.h>
#include <sys/cmn_err.h>
#include <sys/nvpair.h>
#include <sys/policy.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi_implfuncs.h>
#include <sys/systm.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/ddi.h>
#include <sys/fs/dv_node.h>
#include <sys/sunndi.h>
#undef ct_lock	/* needed because clnt.h defines ct_lock as a macro */

/*
 * Device Contracts
 * -----------------
 * This file contains the core code for the device contracts framework.
 * A device contract is an agreement or a contract between a process and
 * the kernel regarding the state of the device. A device contract may be
 * created when a relationship is formed between a device and a process
 * i.e. at open(2) time, or it may be created at some point after the device
 * has been opened. A device contract once formed may be broken by either party.
 * A device contract can be broken by the process by an explicit abandon of the
 * contract or by an implicit abandon when the process exits. A device contract
 * can be broken by the kernel either asynchronously (without negotiation) or
 * synchronously (with negotiation). Exactly which happens depends on the device
 * state transition. The following state diagram shows the transitions between
 * device states. Only device state transitions currently supported by device
 * contracts is shown.
 *
 *                              <-- A -->
 *                       /-----------------> DEGRADED
 *                       |                      |
 *                       |                      |
 *                       |                      | S
 *                       |                      | |
 *                       |                      | v
 *                       v       S -->          v
 *                      ONLINE ------------> OFFLINE
 *
 *
 * In the figure above, the arrows indicate the direction of transition. The
 * letter S refers to transitions which are inherently synchronous i.e.
 * require negotiation and the letter A indicates transitions which are
 * asynchronous i.e. are done without contract negotiations. A good example
 * of a synchronous transition is the ONLINE -> OFFLINE transition. This
 * transition cannot happen as long as there are consumers which have the
 * device open. Thus some form of negotiation needs to happen between the
 * consumers and the kernel to ensure that consumers either close devices
 * or disallow the move to OFFLINE. Certain other transitions such as
 * ONLINE --> DEGRADED for example, are inherently asynchronous i.e.
 * non-negotiable. A device that suffers a fault that degrades its
 * capabilities will become degraded irrespective of what consumers it has,
 * so a negotiation in this case is pointless.
 *
 * The following device states are currently defined for device contracts:
 *
 *      CT_DEV_EV_ONLINE
 *              The device is online and functioning normally
 *      CT_DEV_EV_DEGRADED
 *              The device is online but is functioning in a degraded capacity
 *      CT_DEV_EV_OFFLINE
 *              The device is offline and is no longer configured
 *
 * A typical consumer of device contracts starts out with a contract
 * template and adds terms to that template. These include the
 * "acceptable set" (A-set) term, which is a bitset of device states which
 * are guaranteed by the contract. If the device moves out of a state in
 * the A-set, the contract is broken. The breaking of the contract can
 * be asynchronous in which case a critical contract event is sent to the
 * contract holder but no negotiations take place. If the breaking of the
 * contract is synchronous, negotations are opened between the affected
 * consumer and the kernel. The kernel does this by sending a critical
 * event to the consumer with the CTE_NEG flag set indicating that this
 * is a negotiation event. The consumer can accept this change by sending
 * a ACK message to the kernel. Alternatively, if it has the necessary
 * privileges, it can send a NACK message to the kernel which will block
 * the device state change. To NACK a negotiable event, a process must
 * have the {PRIV_SYS_DEVICES} privilege asserted in its effective set.
 *
 * Other terms include the "minor path" term, specified explicitly if the
 * contract is not being created at open(2) time or specified implicitly
 * if the contract is being created at open time via an activated template.
 *
 * A contract event is sent on any state change to which the contract
 * owner has subscribed via the informative or critical event sets. Only
 * critical events are guaranteed to be delivered. Since all device state
 * changes are controlled by the kernel and cannot be arbitrarily generated
 * by a non-privileged user, the {PRIV_CONTRACT_EVENT} privilege does not
 * need to be asserted in a process's effective set to designate an event as
 * critical. To ensure privacy, a process must either have the same effective
 * userid as the contract holder or have the {PRIV_CONTRACT_OBSERVER} privilege
 * asserted in its effective set in order to observe device contract events
 * off the device contract type specific endpoint.
 *
 * Yet another term available with device contracts is the "non-negotiable"
 * term. This term is used to pre-specify a NACK to any contract negotiation.
 * This term is ignored for asynchronous state changes. For example, a
 * provcess may have the A-set {ONLINE|DEGRADED} and make the contract
 * non-negotiable. In this case, the device contract framework assumes a
 * NACK for any transition to OFFLINE and blocks the offline. If the A-set
 * is {ONLINE} and the non-negotiable term is set, transitions to OFFLINE
 * are NACKed but transitions to DEGRADE succeed.
 *
 * The OFFLINE negotiation (if OFFLINE state is not in the A-set for a contract)
 * happens just before the I/O framework attempts to offline a device
 * (i.e. detach a device and set the offline flag so that it cannot be
 * reattached). A device contract holder is expected to either NACK the offline
 * (if privileged) or release the device and allow the offline to proceed.
 *
 * The DEGRADE contract event (if DEGRADE is not in the A-set for a contract)
 * is generated just before the I/O framework transitions the device state
 * to "degraded" (i.e. DEVI_DEVICE_DEGRADED in I/O framework terminology).
 *
 * The contract holder is expected to ACK or NACK a negotiation event
 * within a certain period of time. If the ACK/NACK is not received
 * within the timeout period, the device contract framework will behave
 * as if the contract does not exist and will proceed with the event.
 *
 * Unlike a process contract a device contract does not need to exist
 * once it is abandoned, since it does not define a fault boundary. It
 * merely represents an agreement between a process and the kernel
 * regarding the state of the device. Once the process has abandoned
 * the contract (either implicitly via a process exit or explicitly)
 * the kernel has no reason to retain the contract. As a result
 * device contracts are neither inheritable nor need to exist in an
 * orphan state.
 *
 * A device unlike a process may exist in multiple contracts and has
 * a "life" outside a device contract. A device unlike a process
 * may exist without an associated contract. Unlike a process contract
 * a device contract may be formed after a binding relationship is
 * formed between a process and a device.
 *
 *	IMPLEMENTATION NOTES
 *	====================
 * DATA STRUCTURES
 * ----------------
 * 	The heart of the device contracts implementation is the device contract
 * 	private cont_device_t (or ctd for short) data structure. It encapsulates
 * 	the generic contract_t data structure and has a number of private
 *	fields.
 * 	These include:
 *		cond_minor: The minor device that is the subject of the contract
 *		cond_aset:  The bitset of states which are guaranteed by the
 *			   contract
 *		cond_noneg: If set, indicates that the result of negotiation has
 *			    been predefined to be a NACK
 * 	In addition, there are other device identifiers such the devinfo node,
 * 	dev_t and spec_type of the minor node. There are also a few fields that
 * 	are used during negotiation to maintain state. See
 *		uts/common/sys/contract/device_impl.h
 * 	for details.
 * 	The ctd structure represents the device private part of a contract of
 * 	type "device"
 *
 * 	Another data structure used by device contracts is ctmpl_device. It is
 * 	the device contracts private part of the contract template structure. It
 *	encapsulates the generic template structure "ct_template_t" and includes
 *	the following device contract specific fields
 *		ctd_aset:   The bitset of states that should be guaranteed by a
 *			    contract
 *		ctd_noneg:  If set, indicates that contract should NACK a
 *			    negotiation
 *		ctd_minor:  The devfs_path (without the /devices prefix) of the
 *			    minor node that is the subject of the contract.
 *
 * ALGORITHMS
 * ---------
 * There are three sets of routines in this file
 * 	Template related routines
 * 	-------------------------
 *	These routines provide support for template related operations initated
 *	via the generic template operations. These include routines that dup
 *	a template, free it, and set various terms in the template
 *	(such as the minor node path, the acceptable state set (or A-set)
 *	and the non-negotiable term) as well as a routine to query the
 *	device specific portion of the template for the abovementioned terms.
 *	There is also a routine to create (ctmpl_device_create) that is used to
 *	create a contract from a template. This routine calls (after initial
 *	setup) the common function used to create a device contract
 *	(contract_device_create).
 *
 *	core device contract implementation
 *	----------------------------------
 *	These routines support the generic contract framework to provide
 *	functionality that allows contracts to be created, managed and
 *	destroyed. The contract_device_create() routine is a routine used
 *	to create a contract from a template (either via an explicit create
 *	operation on a template or implicitly via an open with an
 *	activated template.). The contract_device_free() routine assists
 *	in freeing the device contract specific parts. There are routines
 *	used to abandon (contract_device_abandon) a device contract as well
 *	as a routine to destroy (which despite its name does not destroy,
 *	it only moves a contract to a dead state) a contract.
 *	There is also a routine to return status information about a
 *	contract - the level of detail depends on what is requested by the
 *	user. A value of CTD_FIXED only returns fixed length fields such
 *	as the A-set, state of device and value of the "noneg" term. If
 *	CTD_ALL is specified, the minor node path is returned as well.
 *
 *	In addition there are interfaces (contract_device_ack/nack) which
 *	are used to support negotiation between userland processes and
 *	device contracts. These interfaces record the acknowledgement
 *	or lack thereof for negotiation events and help determine if the
 *	negotiated event should occur.
 *
 *	"backend routines"
 *	-----------------
 *	The backend routines form the interface between the I/O framework
 *	and the device contract subsystem. These routines, allow the I/O
 *	framework to call into the device contract subsystem to notify it of
 *	impending changes to a device state as well as to inform of the
 *	final disposition of such attempted state changes. Routines in this
 *	class include contract_device_offline() that indicates an attempt to
 *	offline a device, contract_device_degrade() that indicates that
 *	a device is moving to the degraded state and contract_device_negend()
 *	that is used by the I/O framework to inform the contracts subsystem of
 *	the final disposition of an attempted operation.
 *
 *	SUMMARY
 *	-------
 *      A contract starts its life as a template. A process allocates a device
 *	contract template and sets various terms:
 *		The A-set
 *		The device minor node
 *		Critical and informative events
 *		The noneg i.e. no negotition term
 *	Setting of these terms in the template is done via the
 *	ctmpl_device_set() entry point in this file. A process can query a
 *	template to determine the terms already set in the template - this is
 *	facilitated by the ctmpl_device_get() routine.
 *
 *	Once all the appropriate terms are set, the contract is instantiated via
 *	one of two methods
 *	- via an explicit create operation - this is facilitated by the
 *	  ctmpl_device_create() entry point
 *	- synchronously with the open(2) system call - this is achieved via the
 *	  contract_device_open() routine.
 *	The core work for both these above functions is done by
 *	contract_device_create()
 *
 *	A contract once created can be queried for its status. Support for
 *	status info is provided by both the common contracts framework and by
 *	the "device" contract type. If the level of detail requested is
 *	CTD_COMMON, only the common contract framework data is used. Higher
 *	levels of detail result in calls to contract_device_status() to supply
 *	device contract type specific status information.
 *
 *	A contract once created may be abandoned either explicitly or implictly.
 *	In either case, the contract_device_abandon() function is invoked. This
 * 	function merely calls contract_destroy() which moves the contract to
 *	the DEAD state. The device contract portion of destroy processing is
 *	provided by contract_device_destroy() which merely disassociates the
 *	contract from its device devinfo node. A contract in the DEAD state is
 *	not freed. It hanbgs around until all references to the contract are
 *	gone. When that happens, the contract is finally deallocated. The
 *	device contract specific portion of the free is done by
 *	contract_device_free() which finally frees the device contract specific
 *	data structure (cont_device_t).
 *
 *	When a device undergoes a state change, the I/O framework calls the
 *	corresponding device contract entry point. For example, when a device
 *	is about to go OFFLINE, the routine contract_device_offline() is
 *	invoked. Similarly if a device moves to DEGRADED state, the routine
 *	contract_device_degrade() function is called. These functions call the
 *	core routine contract_device_publish(). This function determines via
 *	the function is_sync_neg() whether an event is a synchronous (i.e.
 *	negotiable) event or not. In the former case contract_device_publish()
 *	publishes a CTE_NEG event and then waits in wait_for_acks() for ACKs
 *	and/or NACKs from contract holders. In the latter case, it simply
 *	publishes the event and does not wait. In the negotiation case, ACKs or
 *	NACKs from userland consumers results in contract_device_ack_nack()
 *	being called where the result of the negotiation is recorded in the
 *	contract data structure. Once all outstanding contract owners have
 *	responded, the device contract code in wait_for_acks() determines the
 *	final result of the negotiation. A single NACK overrides all other ACKs
 *	If there is no NACK, then a single ACK will result in an overall ACK
 *	result. If there are no ACKs or NACKs, then the result CT_NONE is
 *	returned back to the I/O framework. Once the event is permitted or
 *	blocked, the I/O framework proceeds or aborts the state change. The
 *	I/O framework then calls contract_device_negend() with a result code
 *	indicating final disposition of the event. This call releases the
 *	barrier and other state associated with the previous negotiation,
 *	which permits the next event (if any) to come into the device contract
 *	framework.
 *
 *	Finally, a device that has outstanding contracts may be removed from
 *	the system which results in its devinfo node being freed. The devinfo
 *	free routine in the I/O framework, calls into the device contract
 *	function - contract_device_remove_dip(). This routine, disassociates
 *	the dip from all contracts associated with the contract being freed,
 *	allowing the devinfo node to be freed.
 *
 * LOCKING
 * ---------
 * 	There are four sets of data that need to be protected by locks
 *
 *	i) device contract specific portion of the contract template - This data
 *	is protected by the template lock ctmpl_lock.
 *
 *	ii) device contract specific portion of the contract - This data is
 *	protected by the contract lock ct_lock
 *
 *	iii) The linked list of contracts hanging off a devinfo node - This
 *	list is protected by the per-devinfo node lock devi_ct_lock
 *
 *	iv) Finally there is a barrier, controlled by devi_ct_lock, devi_ct_cv
 *	and devi_ct_count that controls state changes to a dip
 *
 *	The template lock is independent in that none of the other locks in this
 *	file may be taken while holding the template lock (and vice versa).
 *
 *	The remaining three locks have the following lock order
 *
 *	devi_ct_lock  -> ct_count barrier ->  ct_lock
 *
 */

static cont_device_t *contract_device_create(ctmpl_device_t *dtmpl, dev_t dev,
    int spec_type, proc_t *owner, int *errorp);

/* barrier routines */
static void ct_barrier_acquire(dev_info_t *dip);
static void ct_barrier_release(dev_info_t *dip);
static int ct_barrier_held(dev_info_t *dip);
static int ct_barrier_empty(dev_info_t *dip);
static void ct_barrier_wait_for_release(dev_info_t *dip);
static int ct_barrier_wait_for_empty(dev_info_t *dip, int secs);
static void ct_barrier_decr(dev_info_t *dip);
static void ct_barrier_incr(dev_info_t *dip);

ct_type_t *device_type;

/*
 * Macro predicates for determining when events should be sent and how.
 */
#define	EVSENDP(ctd, flag) \
	((ctd->cond_contract.ct_ev_info | ctd->cond_contract.ct_ev_crit) & flag)

#define	EVINFOP(ctd, flag) \
	((ctd->cond_contract.ct_ev_crit & flag) == 0)

/*
 * State transition table showing which transitions are synchronous and which
 * are not.
 */
struct ct_dev_negtable {
	uint_t	st_old;
	uint_t	st_new;
	uint_t	st_neg;
} ct_dev_negtable[] = {
	{CT_DEV_EV_ONLINE, CT_DEV_EV_OFFLINE,	1},
	{CT_DEV_EV_ONLINE, CT_DEV_EV_DEGRADED,	0},
	{CT_DEV_EV_DEGRADED, CT_DEV_EV_ONLINE,	0},
	{CT_DEV_EV_DEGRADED, CT_DEV_EV_OFFLINE,	1},
	{0}
};

/*
 * Device contract template implementation
 */

/*
 * ctmpl_device_dup
 *
 * The device contract template dup entry point.
 * This simply copies all the fields (generic as well as device contract
 * specific) fields of the original.
 */
static struct ct_template *
ctmpl_device_dup(struct ct_template *template)
{
	ctmpl_device_t *new;
	ctmpl_device_t *old = template->ctmpl_data;
	char *buf;
	char *minor;

	new = kmem_zalloc(sizeof (ctmpl_device_t), KM_SLEEP);
	buf = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	/*
	 * copy generic fields.
	 * ctmpl_copy returns with old template lock held
	 */
	ctmpl_copy(&new->ctd_ctmpl, template);

	new->ctd_ctmpl.ctmpl_data = new;
	new->ctd_aset = old->ctd_aset;
	new->ctd_minor = NULL;
	new->ctd_noneg = old->ctd_noneg;

	if (old->ctd_minor) {
		ASSERT(strlen(old->ctd_minor) + 1 <= MAXPATHLEN);
		bcopy(old->ctd_minor, buf, strlen(old->ctd_minor) + 1);
	} else {
		kmem_free(buf, MAXPATHLEN);
		buf = NULL;
	}

	mutex_exit(&template->ctmpl_lock);
	if (buf) {
		minor = i_ddi_strdup(buf, KM_SLEEP);
		kmem_free(buf, MAXPATHLEN);
		buf = NULL;
	} else {
		minor = NULL;
	}
	mutex_enter(&template->ctmpl_lock);

	if (minor) {
		new->ctd_minor = minor;
	}

	ASSERT(buf == NULL);
	return (&new->ctd_ctmpl);
}

/*
 * ctmpl_device_free
 *
 * The device contract template free entry point.  Just
 * frees the template.
 */
static void
ctmpl_device_free(struct ct_template *template)
{
	ctmpl_device_t *dtmpl = template->ctmpl_data;

	if (dtmpl->ctd_minor)
		kmem_free(dtmpl->ctd_minor, strlen(dtmpl->ctd_minor) + 1);

	kmem_free(dtmpl, sizeof (ctmpl_device_t));
}

/*
 * SAFE_EV is the set of events which a non-privileged process is
 * allowed to make critical. An unprivileged device contract owner has
 * no control over when a device changes state, so all device events
 * can be in the critical set.
 *
 * EXCESS tells us if "value", a critical event set, requires
 * additional privilege. For device contracts EXCESS currently
 * evaluates to 0.
 */
#define	SAFE_EV		(CT_DEV_ALLEVENT)
#define	EXCESS(value)	((value) & ~SAFE_EV)


/*
 * ctmpl_device_set
 *
 * The device contract template set entry point. Sets various terms in the
 * template. The non-negotiable  term can only be set if the process has
 * the {PRIV_SYS_DEVICES} privilege asserted in its effective set.
 */
static int
ctmpl_device_set(struct ct_template *tmpl, ct_kparam_t *kparam,
    const cred_t *cr)
{
	ctmpl_device_t *dtmpl = tmpl->ctmpl_data;
	ct_param_t *param = &kparam->param;
	int error;
	dev_info_t *dip;
	int spec_type;
	uint64_t param_value;
	char *str_value;

	ASSERT(MUTEX_HELD(&tmpl->ctmpl_lock));

	if (param->ctpm_id == CTDP_MINOR) {
		str_value = (char *)kparam->ctpm_kbuf;
		str_value[param->ctpm_size - 1] = '\0';
	} else {
		if (param->ctpm_size < sizeof (uint64_t))
			return (EINVAL);
		param_value = *(uint64_t *)kparam->ctpm_kbuf;
	}

	switch (param->ctpm_id) {
	case CTDP_ACCEPT:
		if (param_value & ~CT_DEV_ALLEVENT)
			return (EINVAL);
		if (param_value == 0)
			return (EINVAL);
		if (param_value == CT_DEV_ALLEVENT)
			return (EINVAL);

		dtmpl->ctd_aset = param_value;
		break;
	case CTDP_NONEG:
		if (param_value != CTDP_NONEG_SET &&
		    param_value != CTDP_NONEG_CLEAR)
			return (EINVAL);

		/*
		 * only privileged processes can designate a contract
		 * non-negotiatble.
		 */
		if (param_value == CTDP_NONEG_SET &&
		    (error = secpolicy_sys_devices(cr)) != 0) {
			return (error);
		}

		dtmpl->ctd_noneg = param_value;
		break;

	case CTDP_MINOR:
		if (*str_value != '/' ||
		    strncmp(str_value, "/devices/",
		    strlen("/devices/")) == 0 ||
		    strstr(str_value, "../devices/") != NULL ||
		    strchr(str_value, ':') == NULL) {
			return (EINVAL);
		}

		spec_type = 0;
		dip = NULL;
		if (resolve_pathname(str_value, &dip, NULL, &spec_type) != 0) {
			return (ERANGE);
		}
		ddi_release_devi(dip);

		if (spec_type != S_IFCHR && spec_type != S_IFBLK) {
			return (EINVAL);
		}

		if (dtmpl->ctd_minor != NULL) {
			kmem_free(dtmpl->ctd_minor,
			    strlen(dtmpl->ctd_minor) + 1);
		}
		dtmpl->ctd_minor = i_ddi_strdup(str_value, KM_SLEEP);
		break;
	case CTP_EV_CRITICAL:
		/*
		 * Currently for device contracts, any event
		 * may be added to the critical set. We retain the
		 * following code however for future enhancements.
		 */
		if (EXCESS(param_value) &&
		    (error = secpolicy_contract_event(cr)) != 0)
			return (error);
		tmpl->ctmpl_ev_crit = param_value;
		break;
	default:
		return (EINVAL);
	}

	return (0);
}

/*
 * ctmpl_device_get
 *
 * The device contract template get entry point.  Simply fetches and
 * returns the value of the requested term.
 */
static int
ctmpl_device_get(struct ct_template *template, ct_kparam_t *kparam)
{
	ctmpl_device_t *dtmpl = template->ctmpl_data;
	ct_param_t *param = &kparam->param;
	uint64_t *param_value = kparam->ctpm_kbuf;

	ASSERT(MUTEX_HELD(&template->ctmpl_lock));

	if (param->ctpm_id == CTDP_ACCEPT ||
	    param->ctpm_id == CTDP_NONEG) {
		if (param->ctpm_size < sizeof (uint64_t))
			return (EINVAL);
		kparam->ret_size = sizeof (uint64_t);
	}

	switch (param->ctpm_id) {
	case CTDP_ACCEPT:
		*param_value = dtmpl->ctd_aset;
		break;
	case CTDP_NONEG:
		*param_value = dtmpl->ctd_noneg;
		break;
	case CTDP_MINOR:
		if (dtmpl->ctd_minor) {
			kparam->ret_size = strlcpy((char *)kparam->ctpm_kbuf,
			    dtmpl->ctd_minor, param->ctpm_size);
			kparam->ret_size++;
		} else {
			return (ENOENT);
		}
		break;
	default:
		return (EINVAL);
	}

	return (0);
}

/*
 * Device contract type specific portion of creating a contract using
 * a specified template
 */
/*ARGSUSED*/
int
ctmpl_device_create(ct_template_t *template, ctid_t *ctidp)
{
	ctmpl_device_t *dtmpl;
	char *buf;
	dev_t dev;
	int spec_type;
	int error;
	cont_device_t *ctd;

	if (ctidp == NULL)
		return (EINVAL);

	buf = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	dtmpl = template->ctmpl_data;

	mutex_enter(&template->ctmpl_lock);
	if (dtmpl->ctd_minor == NULL) {
		/* incomplete template */
		mutex_exit(&template->ctmpl_lock);
		kmem_free(buf, MAXPATHLEN);
		return (EINVAL);
	} else {
		ASSERT(strlen(dtmpl->ctd_minor) < MAXPATHLEN);
		bcopy(dtmpl->ctd_minor, buf, strlen(dtmpl->ctd_minor) + 1);
	}
	mutex_exit(&template->ctmpl_lock);

	spec_type = 0;
	dev = NODEV;
	if (resolve_pathname(buf, NULL, &dev, &spec_type) != 0 ||
	    dev == NODEV || dev == DDI_DEV_T_ANY || dev == DDI_DEV_T_NONE ||
	    (spec_type != S_IFCHR && spec_type != S_IFBLK)) {
		CT_DEBUG((CE_WARN,
		    "tmpl_create: failed to find device: %s", buf));
		kmem_free(buf, MAXPATHLEN);
		return (ERANGE);
	}
	kmem_free(buf, MAXPATHLEN);

	ctd = contract_device_create(template->ctmpl_data,
	    dev, spec_type, curproc, &error);

	if (ctd == NULL) {
		CT_DEBUG((CE_WARN, "Failed to create device contract for "
		    "process (%d) with device (devt = %lu, spec_type = %s)",
		    curproc->p_pid, dev,
		    spec_type == S_IFCHR ? "S_IFCHR" : "S_IFBLK"));
		return (error);
	}

	mutex_enter(&ctd->cond_contract.ct_lock);
	*ctidp = ctd->cond_contract.ct_id;
	mutex_exit(&ctd->cond_contract.ct_lock);

	return (0);
}

/*
 * Device contract specific template entry points
 */
static ctmplops_t ctmpl_device_ops = {
	ctmpl_device_dup,		/* ctop_dup */
	ctmpl_device_free,		/* ctop_free */
	ctmpl_device_set,		/* ctop_set */
	ctmpl_device_get,		/* ctop_get */
	ctmpl_device_create,		/* ctop_create */
	CT_DEV_ALLEVENT			/* all device events bitmask */
};


/*
 * Device contract implementation
 */

/*
 * contract_device_default
 *
 * The device contract default template entry point.  Creates a
 * device contract template with a default A-set and no "noneg" ,
 * with informative degrade events and critical offline events.
 * There is no default minor path.
 */
static ct_template_t *
contract_device_default(void)
{
	ctmpl_device_t *new;

	new = kmem_zalloc(sizeof (ctmpl_device_t), KM_SLEEP);
	ctmpl_init(&new->ctd_ctmpl, &ctmpl_device_ops, device_type, new);

	new->ctd_aset = CT_DEV_EV_ONLINE | CT_DEV_EV_DEGRADED;
	new->ctd_noneg = 0;
	new->ctd_ctmpl.ctmpl_ev_info = CT_DEV_EV_DEGRADED;
	new->ctd_ctmpl.ctmpl_ev_crit = CT_DEV_EV_OFFLINE;

	return (&new->ctd_ctmpl);
}

/*
 * contract_device_free
 *
 * Destroys the device contract specific portion of a contract and
 * frees the contract.
 */
static void
contract_device_free(contract_t *ct)
{
	cont_device_t *ctd = ct->ct_data;

	ASSERT(ctd->cond_minor);
	ASSERT(strlen(ctd->cond_minor) < MAXPATHLEN);
	kmem_free(ctd->cond_minor, strlen(ctd->cond_minor) + 1);

	ASSERT(ctd->cond_devt != DDI_DEV_T_ANY &&
	    ctd->cond_devt != DDI_DEV_T_NONE && ctd->cond_devt != NODEV);

	ASSERT(ctd->cond_spec == S_IFBLK || ctd->cond_spec == S_IFCHR);

	ASSERT(!(ctd->cond_aset & ~CT_DEV_ALLEVENT));
	ASSERT(ctd->cond_noneg == 0 || ctd->cond_noneg == 1);

	ASSERT(!(ctd->cond_currev_type & ~CT_DEV_ALLEVENT));
	ASSERT(!(ctd->cond_currev_ack & ~(CT_ACK | CT_NACK)));

	ASSERT((ctd->cond_currev_id > 0) ^ (ctd->cond_currev_type == 0));
	ASSERT((ctd->cond_currev_id > 0) || (ctd->cond_currev_ack == 0));

	ASSERT(!list_link_active(&ctd->cond_next));

	kmem_free(ctd, sizeof (cont_device_t));
}

/*
 * contract_device_abandon
 *
 * The device contract abandon entry point.
 */
static void
contract_device_abandon(contract_t *ct)
{
	ASSERT(MUTEX_HELD(&ct->ct_lock));

	/*
	 * device contracts cannot be inherited or orphaned.
	 * Move the contract to the DEAD_STATE. It will be freed
	 * once all references to it are gone.
	 */
	contract_destroy(ct);
}

/*
 * contract_device_destroy
 *
 * The device contract destroy entry point.
 * Called from contract_destroy() to do any type specific destroy. Note
 * that destroy is a misnomer - this does not free the contract, it only
 * moves it to the dead state. A contract is actually freed via
 * 	contract_rele() -> contract_dtor(), contop_free()
 */
static void
contract_device_destroy(contract_t *ct)
{
	cont_device_t	*ctd;
	dev_info_t	*dip;

	ASSERT(MUTEX_HELD(&ct->ct_lock));

	for (;;) {
		ctd = ct->ct_data;
		dip = ctd->cond_dip;
		if (dip == NULL) {
			/*
			 * The dip has been removed, this is a dangling contract
			 * Check that dip linkages are NULL
			 */
			ASSERT(!list_link_active(&ctd->cond_next));
			CT_DEBUG((CE_NOTE, "contract_device_destroy:"
			    " contract has no devinfo node. contract ctid : %d",
			    ct->ct_id));
			return;
		}

		/*
		 * The intended lock order is : devi_ct_lock -> ct_count
		 * barrier -> ct_lock.
		 * However we can't do this here as dropping the ct_lock allows
		 * a race condition with i_ddi_free_node()/
		 * contract_device_remove_dip() which may free off dip before
		 * we can take devi_ct_lock. So use mutex_tryenter to avoid
		 * dropping ct_lock until we have acquired devi_ct_lock.
		 */
		if (mutex_tryenter(&(DEVI(dip)->devi_ct_lock)) != 0)
			break;
		mutex_exit(&ct->ct_lock);
		delay(drv_usectohz(1000));
		mutex_enter(&ct->ct_lock);
	}
	mutex_exit(&ct->ct_lock);

	/*
	 * Waiting for the barrier to be released is strictly speaking not
	 * necessary. But it simplifies the implementation of
	 * contract_device_publish() by establishing the invariant that
	 * device contracts cannot go away during negotiation.
	 */
	ct_barrier_wait_for_release(dip);
	mutex_enter(&ct->ct_lock);

	list_remove(&(DEVI(dip)->devi_ct), ctd);
	ctd->cond_dip = NULL; /* no longer linked to dip */
	contract_rele(ct);	/* remove hold for dip linkage */

	mutex_exit(&ct->ct_lock);
	mutex_exit(&(DEVI(dip)->devi_ct_lock));
	mutex_enter(&ct->ct_lock);
}

/*
 * contract_device_status
 *
 * The device contract status entry point. Called when level of "detail"
 * is either CTD_FIXED or CTD_ALL
 *
 */
static void
contract_device_status(contract_t *ct, zone_t *zone, int detail, nvlist_t *nvl,
    void *status, model_t model)
{
	cont_device_t *ctd = ct->ct_data;

	ASSERT(detail == CTD_FIXED || detail == CTD_ALL);

	mutex_enter(&ct->ct_lock);
	contract_status_common(ct, zone, status, model);

	/*
	 * There's no need to hold the contract lock while accessing static
	 * data like aset or noneg. But since we need the lock to access other
	 * data like state, we hold it anyway.
	 */
	VERIFY(nvlist_add_uint32(nvl, CTDS_STATE, ctd->cond_state) == 0);
	VERIFY(nvlist_add_uint32(nvl, CTDS_ASET, ctd->cond_aset) == 0);
	VERIFY(nvlist_add_uint32(nvl, CTDS_NONEG, ctd->cond_noneg) == 0);

	if (detail == CTD_FIXED) {
		mutex_exit(&ct->ct_lock);
		return;
	}

	ASSERT(ctd->cond_minor);
	VERIFY(nvlist_add_string(nvl, CTDS_MINOR, ctd->cond_minor) == 0);

	mutex_exit(&ct->ct_lock);
}

/*
 * Converts a result integer into the corresponding string. Used for printing
 * messages
 */
static char *
result_str(uint_t result)
{
	switch (result) {
	case CT_ACK:
		return ("CT_ACK");
	case CT_NACK:
		return ("CT_NACK");
	case CT_NONE:
		return ("CT_NONE");
	default:
		return ("UNKNOWN");
	}
}

/*
 * Converts a device state integer constant into the corresponding string.
 * Used to print messages.
 */
static char *
state_str(uint_t state)
{
	switch (state) {
	case CT_DEV_EV_ONLINE:
		return ("ONLINE");
	case CT_DEV_EV_DEGRADED:
		return ("DEGRADED");
	case CT_DEV_EV_OFFLINE:
		return ("OFFLINE");
	default:
		return ("UNKNOWN");
	}
}

/*
 * Routine that determines if a particular CT_DEV_EV_? event corresponds to a
 * synchronous state change or not.
 */
static int
is_sync_neg(uint_t old, uint_t new)
{
	int	i;

	ASSERT(old & CT_DEV_ALLEVENT);
	ASSERT(new & CT_DEV_ALLEVENT);

	if (old == new) {
		CT_DEBUG((CE_WARN, "is_sync_neg: transition to same state: %s",
		    state_str(new)));
		return (-2);
	}

	for (i = 0; ct_dev_negtable[i].st_new != 0; i++) {
		if (old == ct_dev_negtable[i].st_old &&
		    new == ct_dev_negtable[i].st_new) {
			return (ct_dev_negtable[i].st_neg);
		}
	}

	CT_DEBUG((CE_WARN, "is_sync_neg: Unsupported state transition: "
	    "old = %s -> new = %s", state_str(old), state_str(new)));

	return (-1);
}

/*
 * Used to cleanup cached dv_nodes so that when a device is released by
 * a contract holder, its devinfo node can be successfully detached.
 */
static int
contract_device_dvclean(dev_info_t *dip)
{
	char		*devnm;
	dev_info_t	*pdip;

	ASSERT(dip);

	/* pdip can be NULL if we have contracts against the root dip */
	pdip = ddi_get_parent(dip);

	if (pdip && DEVI_BUSY_OWNED(pdip) || !pdip && DEVI_BUSY_OWNED(dip)) {
		char		*path;

		path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		(void) ddi_pathname(dip, path);
		CT_DEBUG((CE_WARN, "ct_dv_clean: Parent node is busy owned, "
		    "device=%s", path));
		kmem_free(path, MAXPATHLEN);
		return (EDEADLOCK);
	}

	if (pdip) {
		devnm = kmem_alloc(MAXNAMELEN + 1, KM_SLEEP);
		(void) ddi_deviname(dip, devnm);
		(void) devfs_clean(pdip, devnm + 1, DV_CLEAN_FORCE);
		kmem_free(devnm, MAXNAMELEN + 1);
	} else {
		(void) devfs_clean(dip, NULL, DV_CLEAN_FORCE);
	}

	return (0);
}

/*
 * Endpoint of a ct_ctl_ack() or ct_ctl_nack() call from userland.
 * Results in the ACK or NACK being recorded on the dip for one particular
 * contract. The device contracts framework evaluates the ACK/NACKs for all
 * contracts against a device to determine if a particular device state change
 * should be allowed.
 */
static int
contract_device_ack_nack(contract_t *ct, uint_t evtype, uint64_t evid,
    uint_t cmd)
{
	cont_device_t *ctd = ct->ct_data;
	dev_info_t *dip;
	ctid_t	ctid;
	int error;

	ctid = ct->ct_id;

	CT_DEBUG((CE_NOTE, "ack_nack: entered: ctid %d", ctid));

	mutex_enter(&ct->ct_lock);
	CT_DEBUG((CE_NOTE, "ack_nack: contract lock acquired: %d", ctid));

	dip = ctd->cond_dip;

	ASSERT(ctd->cond_minor);
	ASSERT(strlen(ctd->cond_minor) < MAXPATHLEN);

	/*
	 * Negotiation only if new state is not in A-set
	 */
	ASSERT(!(ctd->cond_aset & evtype));

	/*
	 * Negotiation only if transition is synchronous
	 */
	ASSERT(is_sync_neg(ctd->cond_state, evtype));

	/*
	 * We shouldn't be negotiating if the "noneg" flag is set
	 */
	ASSERT(!ctd->cond_noneg);

	if (dip)
		ndi_hold_devi(dip);

	mutex_exit(&ct->ct_lock);

	/*
	 * dv_clean only if !NACK and offline state change
	 */
	if (cmd != CT_NACK && evtype == CT_DEV_EV_OFFLINE && dip) {
		CT_DEBUG((CE_NOTE, "ack_nack: dv_clean: %d", ctid));
		error = contract_device_dvclean(dip);
		if (error != 0) {
			CT_DEBUG((CE_NOTE, "ack_nack: dv_clean: failed: %d",
			    ctid));
			ddi_release_devi(dip);
		}
	}

	mutex_enter(&ct->ct_lock);

	if (dip)
		ddi_release_devi(dip);

	if (dip == NULL) {
		if (ctd->cond_currev_id != evid) {
			CT_DEBUG((CE_WARN, "%sACK for non-current event "
			    "(type=%s, id=%llu) on removed device",
			    cmd == CT_NACK ? "N" : "",
			    state_str(evtype), (unsigned long long)evid));
			CT_DEBUG((CE_NOTE, "ack_nack: error: ESRCH, ctid: %d",
			    ctid));
		} else {
			ASSERT(ctd->cond_currev_type == evtype);
			CT_DEBUG((CE_WARN, "contract_ack: no such device: "
			    "ctid: %d", ctid));
		}
		error = (ct->ct_state == CTS_DEAD) ? ESRCH :
		    ((cmd == CT_NACK) ? ETIMEDOUT : 0);
		mutex_exit(&ct->ct_lock);
		return (error);
	}

	/*
	 * Must follow lock order: devi_ct_lock -> ct_count barrier - >ct_lock
	 */
	mutex_exit(&ct->ct_lock);

	mutex_enter(&DEVI(dip)->devi_ct_lock);
	mutex_enter(&ct->ct_lock);
	if (ctd->cond_currev_id != evid) {
		char *buf;
		mutex_exit(&ct->ct_lock);
		mutex_exit(&DEVI(dip)->devi_ct_lock);
		ndi_hold_devi(dip);
		buf = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		(void) ddi_pathname(dip, buf);
		ddi_release_devi(dip);
		CT_DEBUG((CE_WARN, "%sACK for non-current event"
		    "(type=%s, id=%llu) on device %s",
		    cmd == CT_NACK ? "N" : "",
		    state_str(evtype), (unsigned long long)evid, buf));
		kmem_free(buf, MAXPATHLEN);
		CT_DEBUG((CE_NOTE, "ack_nack: error: %d, ctid: %d",
		    cmd == CT_NACK ? ETIMEDOUT : 0, ctid));
		return (cmd == CT_ACK ? 0 : ETIMEDOUT);
	}

	ASSERT(ctd->cond_currev_type == evtype);
	ASSERT(cmd == CT_ACK || cmd == CT_NACK);

	CT_DEBUG((CE_NOTE, "ack_nack: setting %sACK for ctid: %d",
	    cmd == CT_NACK ? "N" : "", ctid));

	ctd->cond_currev_ack = cmd;
	mutex_exit(&ct->ct_lock);

	ct_barrier_decr(dip);
	mutex_exit(&DEVI(dip)->devi_ct_lock);

	CT_DEBUG((CE_NOTE, "ack_nack: normal exit: ctid: %d", ctid));

	return (0);
}

/*
 * Invoked when a userland contract holder approves (i.e. ACKs) a state change
 */
static int
contract_device_ack(contract_t *ct, uint_t evtype, uint64_t evid)
{
	return (contract_device_ack_nack(ct, evtype, evid, CT_ACK));
}

/*
 * Invoked when a userland contract holder blocks (i.e. NACKs) a state change
 */
static int
contract_device_nack(contract_t *ct, uint_t evtype, uint64_t evid)
{
	return (contract_device_ack_nack(ct, evtype, evid, CT_NACK));
}

/*
 * Creates a new contract synchronously with the breaking of an existing
 * contract. Currently not supported.
 */
/*ARGSUSED*/
static int
contract_device_newct(contract_t *ct)
{
	return (ENOTSUP);
}

/*
 * Core device contract implementation entry points
 */
static contops_t contract_device_ops = {
	contract_device_free,		/* contop_free */
	contract_device_abandon,	/* contop_abandon */
	contract_device_destroy,	/* contop_destroy */
	contract_device_status,		/* contop_status */
	contract_device_ack,		/* contop_ack */
	contract_device_nack,		/* contop_nack */
	contract_qack_notsup,		/* contop_qack */
	contract_device_newct		/* contop_newct */
};

/*
 * contract_device_init
 *
 * Initializes the device contract type.
 */
void
contract_device_init(void)
{
	device_type = contract_type_init(CTT_DEVICE, "device",
	    &contract_device_ops, contract_device_default);
}

/*
 * contract_device_create
 *
 * create a device contract given template "tmpl" and the "owner" process.
 * May fail and return NULL if project.max-contracts would have been exceeded.
 *
 * Common device contract creation routine called for both open-time and
 * non-open time device contract creation
 */
static cont_device_t *
contract_device_create(ctmpl_device_t *dtmpl, dev_t dev, int spec_type,
    proc_t *owner, int *errorp)
{
	cont_device_t *ctd;
	char *minor;
	char *path;
	dev_info_t *dip;

	ASSERT(dtmpl != NULL);
	ASSERT(dev != NODEV && dev != DDI_DEV_T_ANY && dev != DDI_DEV_T_NONE);
	ASSERT(spec_type == S_IFCHR || spec_type == S_IFBLK);
	ASSERT(errorp);

	*errorp = 0;

	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	mutex_enter(&dtmpl->ctd_ctmpl.ctmpl_lock);
	ASSERT(strlen(dtmpl->ctd_minor) < MAXPATHLEN);
	bcopy(dtmpl->ctd_minor, path, strlen(dtmpl->ctd_minor) + 1);
	mutex_exit(&dtmpl->ctd_ctmpl.ctmpl_lock);

	dip = e_ddi_hold_devi_by_path(path, 0);
	if (dip == NULL) {
		cmn_err(CE_WARN, "contract_create: Cannot find devinfo node "
		    "for device path (%s)", path);
		kmem_free(path, MAXPATHLEN);
		*errorp = ERANGE;
		return (NULL);
	}

	/*
	 * Lock out any parallel contract negotiations
	 */
	mutex_enter(&(DEVI(dip)->devi_ct_lock));
	ct_barrier_acquire(dip);
	mutex_exit(&(DEVI(dip)->devi_ct_lock));

	minor = i_ddi_strdup(path, KM_SLEEP);
	kmem_free(path, MAXPATHLEN);

	(void) contract_type_pbundle(device_type, owner);

	ctd = kmem_zalloc(sizeof (cont_device_t), KM_SLEEP);

	/*
	 * Only we hold a refernce to this contract. Safe to access
	 * the fields without a ct_lock
	 */
	ctd->cond_minor = minor;
	/*
	 * It is safe to set the dip pointer in the contract
	 * as the contract will always be destroyed before the dip
	 * is released
	 */
	ctd->cond_dip = dip;
	ctd->cond_devt = dev;
	ctd->cond_spec = spec_type;

	/*
	 * Since we are able to lookup the device, it is either
	 * online or degraded
	 */
	ctd->cond_state = DEVI_IS_DEVICE_DEGRADED(dip) ?
	    CT_DEV_EV_DEGRADED : CT_DEV_EV_ONLINE;

	mutex_enter(&dtmpl->ctd_ctmpl.ctmpl_lock);
	ctd->cond_aset = dtmpl->ctd_aset;
	ctd->cond_noneg = dtmpl->ctd_noneg;

	/*
	 * contract_ctor() initailizes the common portion of a contract
	 * contract_dtor() destroys the common portion of a contract
	 */
	if (contract_ctor(&ctd->cond_contract, device_type, &dtmpl->ctd_ctmpl,
	    ctd, 0, owner, B_TRUE)) {
		mutex_exit(&dtmpl->ctd_ctmpl.ctmpl_lock);
		/*
		 * contract_device_free() destroys the type specific
		 * portion of a contract and frees the contract.
		 * The "minor" path and "cred" is a part of the type specific
		 * portion of the contract and will be freed by
		 * contract_device_free()
		 */
		contract_device_free(&ctd->cond_contract);

		/* release barrier */
		mutex_enter(&(DEVI(dip)->devi_ct_lock));
		ct_barrier_release(dip);
		mutex_exit(&(DEVI(dip)->devi_ct_lock));

		ddi_release_devi(dip);
		*errorp = EAGAIN;
		return (NULL);
	}
	mutex_exit(&dtmpl->ctd_ctmpl.ctmpl_lock);

	mutex_enter(&ctd->cond_contract.ct_lock);
	ctd->cond_contract.ct_ntime.ctm_total = CT_DEV_ACKTIME;
	ctd->cond_contract.ct_qtime.ctm_total = CT_DEV_ACKTIME;
	ctd->cond_contract.ct_ntime.ctm_start = -1;
	ctd->cond_contract.ct_qtime.ctm_start = -1;
	mutex_exit(&ctd->cond_contract.ct_lock);

	/*
	 * Insert device contract into list hanging off the dip
	 * Bump up the ref-count on the contract to reflect this
	 */
	contract_hold(&ctd->cond_contract);
	mutex_enter(&(DEVI(dip)->devi_ct_lock));
	list_insert_tail(&(DEVI(dip)->devi_ct), ctd);

	/* release barrier */
	ct_barrier_release(dip);
	mutex_exit(&(DEVI(dip)->devi_ct_lock));

	ddi_release_devi(dip);

	return (ctd);
}

/*
 * Called when a device is successfully opened to create an open-time contract
 * i.e. synchronously with a device open.
 */
int
contract_device_open(dev_t dev, int spec_type, contract_t **ctpp)
{
	ctmpl_device_t *dtmpl;
	ct_template_t  *tmpl;
	cont_device_t *ctd;
	char *path;
	klwp_t *lwp;
	int error;

	if (ctpp)
		*ctpp = NULL;

	/*
	 * Check if we are in user-context i.e. if we have an lwp
	 */
	lwp = ttolwp(curthread);
	if (lwp == NULL) {
		CT_DEBUG((CE_NOTE, "contract_open: Not user-context"));
		return (0);
	}

	tmpl = ctmpl_dup(lwp->lwp_ct_active[device_type->ct_type_index]);
	if (tmpl == NULL) {
		return (0);
	}
	dtmpl = tmpl->ctmpl_data;

	/*
	 * If the user set a minor path in the template before an open,
	 * ignore it. We use the minor path of the actual minor opened.
	 */
	mutex_enter(&tmpl->ctmpl_lock);
	if (dtmpl->ctd_minor != NULL) {
		CT_DEBUG((CE_NOTE, "contract_device_open(): Process %d: "
		    "ignoring device minor path in active template: %s",
		    curproc->p_pid, dtmpl->ctd_minor));
		/*
		 * This is a copy of the actual activated template.
		 * Safe to make changes such as freeing the minor
		 * path in the template.
		 */
		kmem_free(dtmpl->ctd_minor, strlen(dtmpl->ctd_minor) + 1);
		dtmpl->ctd_minor = NULL;
	}
	mutex_exit(&tmpl->ctmpl_lock);

	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);

	if (ddi_dev_pathname(dev, spec_type, path) != DDI_SUCCESS) {
		CT_DEBUG((CE_NOTE, "contract_device_open(): Failed to derive "
		    "minor path from dev_t,spec {%lu, %d} for process (%d)",
		    dev, spec_type, curproc->p_pid));
		ctmpl_free(tmpl);
		kmem_free(path, MAXPATHLEN);
		return (1);
	}

	mutex_enter(&tmpl->ctmpl_lock);
	ASSERT(dtmpl->ctd_minor == NULL);
	dtmpl->ctd_minor = path;
	mutex_exit(&tmpl->ctmpl_lock);

	ctd = contract_device_create(dtmpl, dev, spec_type, curproc, &error);

	mutex_enter(&tmpl->ctmpl_lock);
	ASSERT(dtmpl->ctd_minor);
	dtmpl->ctd_minor = NULL;
	mutex_exit(&tmpl->ctmpl_lock);
	ctmpl_free(tmpl);
	kmem_free(path, MAXPATHLEN);

	if (ctd == NULL) {
		cmn_err(CE_NOTE, "contract_device_open(): Failed to "
		    "create device contract for process (%d) holding "
		    "device (devt = %lu, spec_type = %d)",
		    curproc->p_pid, dev, spec_type);
		return (1);
	}

	if (ctpp) {
		mutex_enter(&ctd->cond_contract.ct_lock);
		*ctpp = &ctd->cond_contract;
		mutex_exit(&ctd->cond_contract.ct_lock);
	}
	return (0);
}

/*
 * Called during contract negotiation by the device contract framework to wait
 * for ACKs or NACKs from contract holders. If all responses are not received
 * before a specified timeout, this routine times out.
 */
static uint_t
wait_for_acks(dev_info_t *dip, dev_t dev, int spec_type, uint_t evtype)
{
	cont_device_t *ctd;
	int timed_out = 0;
	int result = CT_NONE;
	int ack;
	char *f = "wait_for_acks";

	ASSERT(MUTEX_HELD(&(DEVI(dip)->devi_ct_lock)));
	ASSERT(dip);
	ASSERT(evtype & CT_DEV_ALLEVENT);
	ASSERT(dev != NODEV && dev != DDI_DEV_T_NONE);
	ASSERT((dev == DDI_DEV_T_ANY && spec_type == 0) ||
	    (spec_type == S_IFBLK || spec_type == S_IFCHR));

	CT_DEBUG((CE_NOTE, "%s: entered: dip: %p", f, (void *)dip));

	if (ct_barrier_wait_for_empty(dip, CT_DEV_ACKTIME) == -1) {
		/*
		 * some contract owner(s) didn't respond in time
		 */
		CT_DEBUG((CE_NOTE, "%s: timed out: %p", f, (void *)dip));
		timed_out = 1;
	}

	ack = 0;
	for (ctd = list_head(&(DEVI(dip)->devi_ct)); ctd != NULL;
	    ctd = list_next(&(DEVI(dip)->devi_ct), ctd)) {

		mutex_enter(&ctd->cond_contract.ct_lock);

		ASSERT(ctd->cond_dip == dip);

		if (dev != DDI_DEV_T_ANY && dev != ctd->cond_devt) {
			mutex_exit(&ctd->cond_contract.ct_lock);
			continue;
		}
		if (dev != DDI_DEV_T_ANY && spec_type != ctd->cond_spec) {
			mutex_exit(&ctd->cond_contract.ct_lock);
			continue;
		}

		/* skip if non-negotiable contract */
		if (ctd->cond_noneg) {
			mutex_exit(&ctd->cond_contract.ct_lock);
			continue;
		}

		ASSERT(ctd->cond_currev_type == evtype);
		if (ctd->cond_currev_ack == CT_NACK) {
			CT_DEBUG((CE_NOTE, "%s: found a NACK,result = NACK: %p",
			    f, (void *)dip));
			mutex_exit(&ctd->cond_contract.ct_lock);
			return (CT_NACK);
		} else if (ctd->cond_currev_ack == CT_ACK) {
			ack = 1;
			CT_DEBUG((CE_NOTE, "%s: found a ACK: %p",
			    f, (void *)dip));
		}
		mutex_exit(&ctd->cond_contract.ct_lock);
	}

	if (ack) {
		result = CT_ACK;
		CT_DEBUG((CE_NOTE, "%s: result = ACK, dip=%p", f, (void *)dip));
	} else if (timed_out) {
		result = CT_NONE;
		CT_DEBUG((CE_NOTE, "%s: result = NONE (timed-out), dip=%p",
		    f, (void *)dip));
	} else {
		CT_DEBUG((CE_NOTE, "%s: result = NONE, dip=%p",
		    f, (void *)dip));
	}


	return (result);
}

/*
 * Determines the current state of a device (i.e a devinfo node
 */
static int
get_state(dev_info_t *dip)
{
	if (DEVI_IS_DEVICE_OFFLINE(dip) || DEVI_IS_DEVICE_DOWN(dip))
		return (CT_DEV_EV_OFFLINE);
	else if (DEVI_IS_DEVICE_DEGRADED(dip))
		return (CT_DEV_EV_DEGRADED);
	else
		return (CT_DEV_EV_ONLINE);
}

/*
 * Sets the current state of a device in a device contract
 */
static void
set_cond_state(dev_info_t *dip)
{
	uint_t state = get_state(dip);
	cont_device_t *ctd;

	/* verify that barrier is held */
	ASSERT(ct_barrier_held(dip));

	for (ctd = list_head(&(DEVI(dip)->devi_ct)); ctd != NULL;
	    ctd = list_next(&(DEVI(dip)->devi_ct), ctd)) {
		mutex_enter(&ctd->cond_contract.ct_lock);
		ASSERT(ctd->cond_dip == dip);
		ctd->cond_state = state;
		mutex_exit(&ctd->cond_contract.ct_lock);
	}
}

/*
 * Core routine called by event-specific routines when an event occurs.
 * Determines if an event should be be published, and if it is to be
 * published, whether a negotiation should take place. Also implements
 * NEGEND events which publish the final disposition of an event after
 * negotiations are complete.
 *
 * When an event occurs on a minor node, this routine walks the list of
 * contracts hanging off a devinfo node and for each contract on the affected
 * dip, evaluates the following cases
 *
 *	a. an event that is synchronous, breaks the contract and NONEG not set
 *		- bumps up the outstanding negotiation counts on the dip
 *		- marks the dip as undergoing negotiation (devi_ct_neg)
 *		- event of type CTE_NEG is published
 *	b. an event that is synchronous, breaks the contract and NONEG is set
 *		- sets the final result to CT_NACK, event is blocked
 *		- does not publish an event
 *	c. event is asynchronous and breaks the contract
 *		- publishes a critical event irrespect of whether the NONEG
 *		  flag is set, since the contract will be broken and contract
 *		  owner needs to be informed.
 *	d. No contract breakage but the owner has subscribed to the event
 *		- publishes the event irrespective of the NONEG event as the
 *		  owner has explicitly subscribed to the event.
 *	e. NEGEND event
 *		- publishes a critical event. Should only be doing this if
 *		  if NONEG is not set.
 *	f. all other events
 *		- Since a contract is not broken and this event has not been
 *		  subscribed to, this event does not need to be published for
 *		  for this contract.
 *
 *	Once an event is published, what happens next depends on the type of
 *	event:
 *
 *	a. NEGEND event
 *		- cleanup all state associated with the preceding negotiation
 *		  and return CT_ACK to the caller of contract_device_publish()
 *	b. NACKed event
 *		- One or more contracts had the NONEG term, so the event was
 *		  blocked. Return CT_NACK to the caller.
 *	c. Negotiated event
 *		- Call wait_for_acks() to wait for responses from contract
 *		holders. The end result is either CT_ACK (event is permitted),
 *		CT_NACK (event is blocked) or CT_NONE (no contract owner)
 *		responded. This result is returned back to the caller.
 *	d. All other events
 *		- If the event was asynchronous (i.e. not negotiated) or
 *		a contract was not broken return CT_ACK to the caller.
 */
static uint_t
contract_device_publish(dev_info_t *dip, dev_t dev, int spec_type,
    uint_t evtype, nvlist_t *tnvl)
{
	cont_device_t *ctd;
	uint_t result = CT_NONE;
	uint64_t evid = 0;
	uint64_t nevid = 0;
	char *path = NULL;
	int negend;
	int match;
	int sync = 0;
	contract_t *ct;
	ct_kevent_t *event;
	nvlist_t *nvl;
	int broken = 0;

	ASSERT(dip);
	ASSERT(dev != NODEV && dev != DDI_DEV_T_NONE);
	ASSERT((dev == DDI_DEV_T_ANY && spec_type == 0) ||
	    (spec_type == S_IFBLK || spec_type == S_IFCHR));
	ASSERT(evtype == 0 || (evtype & CT_DEV_ALLEVENT));

	/* Is this a synchronous state change ? */
	if (evtype != CT_EV_NEGEND) {
		sync = is_sync_neg(get_state(dip), evtype);
		/* NOP if unsupported transition */
		if (sync == -2 || sync == -1) {
			DEVI(dip)->devi_flags |= DEVI_CT_NOP;
			result = (sync == -2) ? CT_ACK : CT_NONE;
			goto out;
		}
		CT_DEBUG((CE_NOTE, "publish: is%s sync state change",
		    sync ? "" : " not"));
	} else if (DEVI(dip)->devi_flags & DEVI_CT_NOP) {
		DEVI(dip)->devi_flags &= ~DEVI_CT_NOP;
		result = CT_ACK;
		goto out;
	}

	path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
	(void) ddi_pathname(dip, path);

	mutex_enter(&(DEVI(dip)->devi_ct_lock));

	/*
	 * Negotiation end - set the state of the device in the contract
	 */
	if (evtype == CT_EV_NEGEND) {
		CT_DEBUG((CE_NOTE, "publish: negend: setting cond state"));
		set_cond_state(dip);
	}

	/*
	 * If this device didn't go through negotiation, don't publish
	 * a NEGEND event - simply release the barrier to allow other
	 * device events in.
	 */
	negend = 0;
	if (evtype == CT_EV_NEGEND && !DEVI(dip)->devi_ct_neg) {
		CT_DEBUG((CE_NOTE, "publish: no negend reqd. release barrier"));
		ct_barrier_release(dip);
		mutex_exit(&(DEVI(dip)->devi_ct_lock));
		result = CT_ACK;
		goto out;
	} else if (evtype == CT_EV_NEGEND) {
		/*
		 * There are negotiated contract breakages that
		 * need a NEGEND event
		 */
		ASSERT(ct_barrier_held(dip));
		negend = 1;
		CT_DEBUG((CE_NOTE, "publish: setting negend flag"));
	} else {
		/*
		 * This is a new event, not a NEGEND event. Wait for previous
		 * contract events to complete.
		 */
		ct_barrier_acquire(dip);
	}


	match = 0;
	for (ctd = list_head(&(DEVI(dip)->devi_ct)); ctd != NULL;
	    ctd = list_next(&(DEVI(dip)->devi_ct), ctd)) {

		ctid_t ctid;
		size_t len = strlen(path);

		mutex_enter(&ctd->cond_contract.ct_lock);

		ASSERT(ctd->cond_dip == dip);
		ASSERT(ctd->cond_minor);
		ASSERT(strncmp(ctd->cond_minor, path, len) == 0 &&
		    ctd->cond_minor[len] == ':');

		if (dev != DDI_DEV_T_ANY && dev != ctd->cond_devt) {
			mutex_exit(&ctd->cond_contract.ct_lock);
			continue;
		}
		if (dev != DDI_DEV_T_ANY && spec_type != ctd->cond_spec) {
			mutex_exit(&ctd->cond_contract.ct_lock);
			continue;
		}

		/* We have a matching contract */
		match = 1;
		ctid = ctd->cond_contract.ct_id;
		CT_DEBUG((CE_NOTE, "publish: found matching contract: %d",
		    ctid));

		/*
		 * There are 4 possible cases
		 * 1. A contract is broken (dev not in acceptable state) and
		 *    the state change is synchronous - start negotiation
		 *    by sending a CTE_NEG critical event.
		 * 2. A contract is broken and the state change is
		 *    asynchronous - just send a critical event and
		 *    break the contract.
		 * 3. Contract is not broken, but consumer has subscribed
		 *    to the event as a critical or informative event
		 *    - just send the appropriate event
		 * 4. contract waiting for negend event - just send the critical
		 *    NEGEND event.
		 */
		broken = 0;
		if (!negend && !(evtype & ctd->cond_aset)) {
			broken = 1;
			CT_DEBUG((CE_NOTE, "publish: Contract broken: %d",
			    ctid));
		}

		/*
		 * Don't send event if
		 *	- contract is not broken AND
		 *	- contract holder has not subscribed to this event AND
		 *	- contract not waiting for a NEGEND event
		 */
		if (!broken && !EVSENDP(ctd, evtype) &&
		    !ctd->cond_neg) {
			CT_DEBUG((CE_NOTE, "contract_device_publish(): "
			    "contract (%d): no publish reqd: event %d",
			    ctd->cond_contract.ct_id, evtype));
			mutex_exit(&ctd->cond_contract.ct_lock);
			continue;
		}

		/*
		 * Note: need to kmem_zalloc() the event so mutexes are
		 * initialized automatically
		 */
		ct = &ctd->cond_contract;
		event = kmem_zalloc(sizeof (ct_kevent_t), KM_SLEEP);
		event->cte_type = evtype;

		if (broken && sync) {
			CT_DEBUG((CE_NOTE, "publish: broken + sync: "
			    "ctid: %d", ctid));
			ASSERT(!negend);
			ASSERT(ctd->cond_currev_id == 0);
			ASSERT(ctd->cond_currev_type == 0);
			ASSERT(ctd->cond_currev_ack == 0);
			ASSERT(ctd->cond_neg == 0);
			if (ctd->cond_noneg) {
				/* Nothing to publish. Event has been blocked */
				CT_DEBUG((CE_NOTE, "publish: sync and noneg:"
				    "not publishing blocked ev: ctid: %d",
				    ctid));
				result = CT_NACK;
				kmem_free(event, sizeof (ct_kevent_t));
				mutex_exit(&ctd->cond_contract.ct_lock);
				continue;
			}
			event->cte_flags = CTE_NEG; /* critical neg. event */
			ctd->cond_currev_type = event->cte_type;
			ct_barrier_incr(dip);
			DEVI(dip)->devi_ct_neg = 1; /* waiting for negend */
			ctd->cond_neg = 1;
		} else if (broken && !sync) {
			CT_DEBUG((CE_NOTE, "publish: broken + async: ctid: %d",
			    ctid));
			ASSERT(!negend);
			ASSERT(ctd->cond_currev_id == 0);
			ASSERT(ctd->cond_currev_type == 0);
			ASSERT(ctd->cond_currev_ack == 0);
			ASSERT(ctd->cond_neg == 0);
			event->cte_flags = 0; /* critical event */
		} else if (EVSENDP(ctd, event->cte_type)) {
			CT_DEBUG((CE_NOTE, "publish: event suscrib: ctid: %d",
			    ctid));
			ASSERT(!negend);
			ASSERT(ctd->cond_currev_id == 0);
			ASSERT(ctd->cond_currev_type == 0);
			ASSERT(ctd->cond_currev_ack == 0);
			ASSERT(ctd->cond_neg == 0);
			event->cte_flags = EVINFOP(ctd, event->cte_type) ?
			    CTE_INFO : 0;
		} else if (ctd->cond_neg) {
			CT_DEBUG((CE_NOTE, "publish: NEGEND: ctid: %d", ctid));
			ASSERT(negend);
			ASSERT(ctd->cond_noneg == 0);
			nevid = ctd->cond_contract.ct_nevent ?
			    ctd->cond_contract.ct_nevent->cte_id : 0;
			ASSERT(ctd->cond_currev_id == nevid);
			event->cte_flags = 0;	/* NEGEND is always critical */
			ctd->cond_currev_id = 0;
			ctd->cond_currev_type = 0;
			ctd->cond_currev_ack = 0;
			ctd->cond_neg = 0;
		} else {
			CT_DEBUG((CE_NOTE, "publish: not publishing event for "
			    "ctid: %d, evtype: %d",
			    ctd->cond_contract.ct_id, event->cte_type));
			ASSERT(!negend);
			ASSERT(ctd->cond_currev_id == 0);
			ASSERT(ctd->cond_currev_type == 0);
			ASSERT(ctd->cond_currev_ack == 0);
			ASSERT(ctd->cond_neg == 0);
			kmem_free(event, sizeof (ct_kevent_t));
			mutex_exit(&ctd->cond_contract.ct_lock);
			continue;
		}

		nvl = NULL;
		if (tnvl) {
			VERIFY(nvlist_dup(tnvl, &nvl, 0) == 0);
			if (negend) {
				int32_t newct = 0;
				ASSERT(ctd->cond_noneg == 0);
				VERIFY(nvlist_add_uint64(nvl, CTS_NEVID, nevid)
				    == 0);
				VERIFY(nvlist_lookup_int32(nvl, CTS_NEWCT,
				    &newct) == 0);
				VERIFY(nvlist_add_int32(nvl, CTS_NEWCT,
				    newct == 1 ? 0 :
				    ctd->cond_contract.ct_id) == 0);
				CT_DEBUG((CE_NOTE, "publish: negend: ctid: %d "
				    "CTS_NEVID: %llu, CTS_NEWCT: %s",
				    ctid, (unsigned long long)nevid,
				    newct ? "success" : "failure"));

			}
		}

		if (ctd->cond_neg) {
			ASSERT(ctd->cond_contract.ct_ntime.ctm_start == -1);
			ASSERT(ctd->cond_contract.ct_qtime.ctm_start == -1);
			ctd->cond_contract.ct_ntime.ctm_start = ddi_get_lbolt();
			ctd->cond_contract.ct_qtime.ctm_start =
			    ctd->cond_contract.ct_ntime.ctm_start;
		}

		/*
		 * by holding the dip's devi_ct_lock we ensure that
		 * all ACK/NACKs are held up until we have finished
		 * publishing to all contracts.
		 */
		mutex_exit(&ctd->cond_contract.ct_lock);
		evid = cte_publish_all(ct, event, nvl, NULL);
		mutex_enter(&ctd->cond_contract.ct_lock);

		if (ctd->cond_neg) {
			ASSERT(!negend);
			ASSERT(broken);
			ASSERT(sync);
			ASSERT(!ctd->cond_noneg);
			CT_DEBUG((CE_NOTE, "publish: sync break, setting evid"
			    ": %d", ctid));
			ctd->cond_currev_id = evid;
		} else if (negend) {
			ctd->cond_contract.ct_ntime.ctm_start = -1;
			ctd->cond_contract.ct_qtime.ctm_start = -1;
		}
		mutex_exit(&ctd->cond_contract.ct_lock);
	}

	/*
	 * If "negend" set counter back to initial state (-1) so that
	 * other events can be published. Also clear the negotiation flag
	 * on dip.
	 *
	 * 0 .. n are used for counting.
	 * -1 indicates counter is available for use.
	 */
	if (negend) {
		/*
		 * devi_ct_count not necessarily 0. We may have
		 * timed out in which case, count will be non-zero.
		 */
		ct_barrier_release(dip);
		DEVI(dip)->devi_ct_neg = 0;
		CT_DEBUG((CE_NOTE, "publish: negend: reset dip state: dip=%p",
		    (void *)dip));
	} else if (DEVI(dip)->devi_ct_neg) {
		ASSERT(match);
		ASSERT(!ct_barrier_empty(dip));
		CT_DEBUG((CE_NOTE, "publish: sync count=%d, dip=%p",
		    DEVI(dip)->devi_ct_count, (void *)dip));
	} else {
		/*
		 * for non-negotiated events or subscribed events or no
		 * matching contracts
		 */
		ASSERT(ct_barrier_empty(dip));
		ASSERT(DEVI(dip)->devi_ct_neg == 0);
		CT_DEBUG((CE_NOTE, "publish: async/non-nego/subscrib/no-match: "
		    "dip=%p", (void *)dip));

		/*
		 * only this function when called from contract_device_negend()
		 * can reset the counter to READY state i.e. -1. This function
		 * is so called for every event whether a NEGEND event is needed
		 * or not, but the negend event is only published if the event
		 * whose end they signal is a negotiated event for the contract.
		 */
	}

	if (!match) {
		/* No matching contracts */
		CT_DEBUG((CE_NOTE, "publish: No matching contract"));
		result = CT_NONE;
	} else if (result == CT_NACK) {
		/* a non-negotiable contract exists and this is a neg. event */
		CT_DEBUG((CE_NOTE, "publish: found 1 or more NONEG contract"));
		(void) wait_for_acks(dip, dev, spec_type, evtype);
	} else if (DEVI(dip)->devi_ct_neg) {
		/* one or more contracts going through negotations  */
		CT_DEBUG((CE_NOTE, "publish: sync contract: waiting"));
		result = wait_for_acks(dip, dev, spec_type, evtype);
	} else {
		/* no negotiated contracts or no broken contracts or NEGEND */
		CT_DEBUG((CE_NOTE, "publish: async/no-break/negend"));
		result = CT_ACK;
	}

	/*
	 * Release the lock only now so that the only point where we
	 * drop the lock is in wait_for_acks(). This is so that we don't
	 * miss cv_signal/cv_broadcast from contract holders
	 */
	CT_DEBUG((CE_NOTE, "publish: dropping devi_ct_lock"));
	mutex_exit(&(DEVI(dip)->devi_ct_lock));

out:
	nvlist_free(tnvl);
	if (path)
		kmem_free(path, MAXPATHLEN);


	CT_DEBUG((CE_NOTE, "publish: result = %s", result_str(result)));
	return (result);
}


/*
 * contract_device_offline
 *
 * Event publishing routine called by I/O framework when a device is offlined.
 */
ct_ack_t
contract_device_offline(dev_info_t *dip, dev_t dev, int spec_type)
{
	nvlist_t *nvl;
	uint_t result;
	uint_t evtype;

	VERIFY(nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP) == 0);

	evtype = CT_DEV_EV_OFFLINE;
	result = contract_device_publish(dip, dev, spec_type, evtype, nvl);

	/*
	 * If a contract offline is NACKED, the framework expects us to call
	 * NEGEND ourselves, since we know the final result
	 */
	if (result == CT_NACK) {
		contract_device_negend(dip, dev, spec_type, CT_EV_FAILURE);
	}

	return (result);
}

/*
 * contract_device_degrade
 *
 * Event publishing routine called by I/O framework when a device
 * moves to degrade state.
 */
/*ARGSUSED*/
void
contract_device_degrade(dev_info_t *dip, dev_t dev, int spec_type)
{
	nvlist_t *nvl;
	uint_t evtype;

	VERIFY(nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP) == 0);

	evtype = CT_DEV_EV_DEGRADED;
	(void) contract_device_publish(dip, dev, spec_type, evtype, nvl);
}

/*
 * contract_device_undegrade
 *
 * Event publishing routine called by I/O framework when a device
 * moves from degraded state to online state.
 */
/*ARGSUSED*/
void
contract_device_undegrade(dev_info_t *dip, dev_t dev, int spec_type)
{
	nvlist_t *nvl;
	uint_t evtype;

	VERIFY(nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP) == 0);

	evtype = CT_DEV_EV_ONLINE;
	(void) contract_device_publish(dip, dev, spec_type, evtype, nvl);
}

/*
 * For all contracts which have undergone a negotiation (because the device
 * moved out of the acceptable state for that contract and the state
 * change is synchronous i.e. requires negotiation) this routine publishes
 * a CT_EV_NEGEND event with the final disposition of the event.
 *
 * This event is always a critical event.
 */
void
contract_device_negend(dev_info_t *dip, dev_t dev, int spec_type, int result)
{
	nvlist_t *nvl;
	uint_t evtype;

	ASSERT(result == CT_EV_SUCCESS || result == CT_EV_FAILURE);

	CT_DEBUG((CE_NOTE, "contract_device_negend(): entered: result: %d, "
	    "dip: %p", result, (void *)dip));

	VERIFY(nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP) == 0);
	VERIFY(nvlist_add_int32(nvl, CTS_NEWCT,
	    result == CT_EV_SUCCESS ? 1 : 0) == 0);

	evtype = CT_EV_NEGEND;
	(void) contract_device_publish(dip, dev, spec_type, evtype, nvl);

	CT_DEBUG((CE_NOTE, "contract_device_negend(): exit dip: %p",
	    (void *)dip));
}

/*
 * Wrapper routine called by other subsystems (such as LDI) to start
 * negotiations when a synchronous device state change occurs.
 * Returns CT_ACK or CT_NACK.
 */
ct_ack_t
contract_device_negotiate(dev_info_t *dip, dev_t dev, int spec_type,
    uint_t evtype)
{
	int	result;

	ASSERT(dip);
	ASSERT(dev != NODEV);
	ASSERT(dev != DDI_DEV_T_ANY);
	ASSERT(dev != DDI_DEV_T_NONE);
	ASSERT(spec_type == S_IFBLK || spec_type == S_IFCHR);

	switch (evtype) {
	case CT_DEV_EV_OFFLINE:
		result = contract_device_offline(dip, dev, spec_type);
		break;
	default:
		cmn_err(CE_PANIC, "contract_device_negotiate(): Negotiation "
		    "not supported: event (%d) for dev_t (%lu) and spec (%d), "
		    "dip (%p)", evtype, dev, spec_type, (void *)dip);
		result = CT_NACK;
		break;
	}

	return (result);
}

/*
 * A wrapper routine called by other subsystems (such as the LDI) to
 * finalize event processing for a state change event. For synchronous
 * state changes, this publishes NEGEND events. For asynchronous i.e.
 * non-negotiable events this publishes the event.
 */
void
contract_device_finalize(dev_info_t *dip, dev_t dev, int spec_type,
    uint_t evtype, int ct_result)
{
	ASSERT(dip);
	ASSERT(dev != NODEV);
	ASSERT(dev != DDI_DEV_T_ANY);
	ASSERT(dev != DDI_DEV_T_NONE);
	ASSERT(spec_type == S_IFBLK || spec_type == S_IFCHR);

	switch (evtype) {
	case CT_DEV_EV_OFFLINE:
		contract_device_negend(dip, dev, spec_type, ct_result);
		break;
	case CT_DEV_EV_DEGRADED:
		contract_device_degrade(dip, dev, spec_type);
		contract_device_negend(dip, dev, spec_type, ct_result);
		break;
	case CT_DEV_EV_ONLINE:
		contract_device_undegrade(dip, dev, spec_type);
		contract_device_negend(dip, dev, spec_type, ct_result);
		break;
	default:
		cmn_err(CE_PANIC, "contract_device_finalize(): Unsupported "
		    "event (%d) for dev_t (%lu) and spec (%d), dip (%p)",
		    evtype, dev, spec_type, (void *)dip);
		break;
	}
}

/*
 * Called by I/O framework when a devinfo node is freed to remove the
 * association between a devinfo node and its contracts.
 */
void
contract_device_remove_dip(dev_info_t *dip)
{
	cont_device_t *ctd;
	cont_device_t *next;
	contract_t *ct;

	mutex_enter(&(DEVI(dip)->devi_ct_lock));
	ct_barrier_wait_for_release(dip);

	for (ctd = list_head(&(DEVI(dip)->devi_ct)); ctd != NULL; ctd = next) {
		next = list_next(&(DEVI(dip)->devi_ct), ctd);
		list_remove(&(DEVI(dip)->devi_ct), ctd);
		ct = &ctd->cond_contract;
		/*
		 * Unlink the dip associated with this contract
		 */
		mutex_enter(&ct->ct_lock);
		ASSERT(ctd->cond_dip == dip);
		ctd->cond_dip = NULL; /* no longer linked to dip */
		contract_rele(ct);	/* remove hold for dip linkage */
		CT_DEBUG((CE_NOTE, "ct: remove_dip: removed dip from contract: "
		    "ctid: %d", ct->ct_id));
		mutex_exit(&ct->ct_lock);
	}
	ASSERT(list_is_empty(&(DEVI(dip)->devi_ct)));
	mutex_exit(&(DEVI(dip)->devi_ct_lock));
}

/*
 * Barrier related routines
 */
static void
ct_barrier_acquire(dev_info_t *dip)
{
	ASSERT(MUTEX_HELD(&(DEVI(dip)->devi_ct_lock)));
	CT_DEBUG((CE_NOTE, "ct_barrier_acquire: waiting for barrier"));
	while (DEVI(dip)->devi_ct_count != -1)
		cv_wait(&(DEVI(dip)->devi_ct_cv), &(DEVI(dip)->devi_ct_lock));
	DEVI(dip)->devi_ct_count = 0;
	CT_DEBUG((CE_NOTE, "ct_barrier_acquire: thread owns barrier"));
}

static void
ct_barrier_release(dev_info_t *dip)
{
	ASSERT(MUTEX_HELD(&(DEVI(dip)->devi_ct_lock)));
	ASSERT(DEVI(dip)->devi_ct_count != -1);
	DEVI(dip)->devi_ct_count = -1;
	cv_broadcast(&(DEVI(dip)->devi_ct_cv));
	CT_DEBUG((CE_NOTE, "ct_barrier_release: Released barrier"));
}

static int
ct_barrier_held(dev_info_t *dip)
{
	ASSERT(MUTEX_HELD(&(DEVI(dip)->devi_ct_lock)));
	return (DEVI(dip)->devi_ct_count != -1);
}

static int
ct_barrier_empty(dev_info_t *dip)
{
	ASSERT(MUTEX_HELD(&(DEVI(dip)->devi_ct_lock)));
	ASSERT(DEVI(dip)->devi_ct_count != -1);
	return (DEVI(dip)->devi_ct_count == 0);
}

static void
ct_barrier_wait_for_release(dev_info_t *dip)
{
	ASSERT(MUTEX_HELD(&(DEVI(dip)->devi_ct_lock)));
	while (DEVI(dip)->devi_ct_count != -1)
		cv_wait(&(DEVI(dip)->devi_ct_cv), &(DEVI(dip)->devi_ct_lock));
}

static void
ct_barrier_decr(dev_info_t *dip)
{
	CT_DEBUG((CE_NOTE, "barrier_decr:  ct_count before decr: %d",
	    DEVI(dip)->devi_ct_count));

	ASSERT(MUTEX_HELD(&(DEVI(dip)->devi_ct_lock)));
	ASSERT(DEVI(dip)->devi_ct_count > 0);

	DEVI(dip)->devi_ct_count--;
	if (DEVI(dip)->devi_ct_count == 0) {
		cv_broadcast(&DEVI(dip)->devi_ct_cv);
		CT_DEBUG((CE_NOTE, "barrier_decr: cv_broadcast"));
	}
}

static void
ct_barrier_incr(dev_info_t *dip)
{
	ASSERT(ct_barrier_held(dip));
	DEVI(dip)->devi_ct_count++;
}

static int
ct_barrier_wait_for_empty(dev_info_t *dip, int secs)
{
	clock_t abstime;

	ASSERT(MUTEX_HELD(&(DEVI(dip)->devi_ct_lock)));

	abstime = ddi_get_lbolt() + drv_usectohz(secs*1000000);
	while (DEVI(dip)->devi_ct_count) {
		if (cv_timedwait(&(DEVI(dip)->devi_ct_cv),
		    &(DEVI(dip)->devi_ct_lock), abstime) == -1) {
			return (-1);
		}
	}
	return (0);
}
