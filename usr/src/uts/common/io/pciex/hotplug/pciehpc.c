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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 * Copyright 2023 Oxide Computer Company
 */

/*
 * This file contains Standard PCI Express HotPlug functionality that is
 * compatible with the PCI Express ver 1.1 specification.
 *
 * NOTE: This file is compiled and delivered through misc/pcie module.
 *
 * The main purpose of this is to take the PCIe slot logic, which is found on a
 * PCIe bridge that indicates it is hotplug capable, and map the DDI hotplug
 * controller states to this. This is an imperfect mapping as the definition of
 * the pciehpc_slot_power_t shows. This file assumes that a device can be
 * removed at any time without notice. This is what the spec calls 'surprise
 * removal'.
 *
 * Not all PCIe slots are the same. In particular this can handle the following
 * features which may or may not exist on the slot:
 *
 *  o Power Controllers: With the rise of NVMe based hotplug and the Enterprise
 *    SSD specification, you can have hotplug, but not specific power control
 *    over the device.
 *  o MRL sensor: Manually-operated Retention latches are an optional item and
 *    less common with U.2, E.1, and E.3 based form factors, but there is the
 *    ability to see their state.
 *  o EMI: Electromechanical Interlock. This is used to lock the device in place
 *    and is often paired with an MRL. This similarly isn't as common.
 *  o Attention Button: A button which can be pressed to say please do
 *    something. This is more of a holdover from the world of coordinated
 *    removal from the PCI Standard Hot-Plug Controller (SHPC).
 *  o Power Fault: The ability to tell whether or not a power fault has
 *    occurred.
 *  o Power and Attention Indicators: These are LEDs that are supposed to be
 *    enabled in response to specific actions in the spec, but some of that is
 *    ultimately policy. It's worth noting that not all controllers support both
 *    LEDs and so platforms may want to munge the logical states here a bit
 *    more.
 *
 * There are four primary states that a slot is considered to exist in that
 * roughly have the following state transition diagram:
 *
 *      +-------+
 *      | Empty |<---------------<------------+
 *      +-------+                             |
 *          |                                 |
 * Device   |                                 |
 * Inserted .                                 ^
 *          |                                 |
 *          |                                 |
 *          v                                 |
 *     +---------+                            . . . Device
 *     | Present |<------+                    |     Removed
 *     +---------+       |                    |
 *          |            |                    |
 * Slot     |            |                    |
 * Power  . .            . . Slot Power       |
 * Enabled  |            |   Disabled,        |
 *          |            |   Power Fault,     |
 *          v            |   or specific      |
 *     +---------+       |   request          |
 *     | Powered |-->----+                    |
 *     +---------+       |                    |
 *          |            |                    |
 *          |            |                    |
 * Request  |            ^                    ^
 * or auto- |            |                    |
 * online . *            |                    |
 *          |            |                    |
 *          v            |                    |
 *     +---------+       |                    |
 *     | Enabled |-->----+--------->----------+
 *     +---------+
 *
 * These four states are all related to the DDI_HP_CN_STATE_* values. For
 * example, the empty state above is DDI_HP_CN_STATE_EMPTY and enabled is
 * DDI_HP_CN_STATE_ENABLED. These changes can happen initially because of
 * outside action that is taken or because an explicit state change has been
 * requested via cfgadm/libhotplug. Note that one cannot enter or leave empty
 * without removing or inserting a device.
 *
 * A device node is created in the devinfo tree as a side effect of
 * transitioning to the enabled state and removed when transitioning away from
 * enabled. This is initiated by the DDI hotplug framework making a probe
 * (DDI_HPOP_CN_PROBE) and unprobe (DDI_HPOP_CN_UNPROBE) request which will
 * ultimately get us to pcicfg_configure() which dynamically sets up child
 * nodes.
 *
 * State Initialization
 * --------------------
 *
 * Initializing the state of the world is a bit tricky here. In particular,
 * there are a few things that we need to understand and deal with:
 *
 * 1. A PCIe slot may or may not have been powered prior to us initializing this
 * module. In particular, the PCIe firmware specification generally expects
 * occupied slots to have both their MRL and power indicator match the slot
 * occupancy state (3.5 Device State at Firmware/Operating System Handoff). Of
 * course, we must not assume that firmware has done this or not.
 *
 * This is further complicated by the fact that while the PCIe default is that
 * power is enabled at reset, some controllers require an explicit first write
 * to enact the reset behavior. You cannot do things like enable or disable
 * interrupts without doing a write to the PCIe Slot Control register and
 * turning power on. Those are just the breaks from the spec. The spec also
 * doesn't have a way to tell us if power is actually on or not, we just have to
 * hope. All we can see is if we've commanded power on and if a power fault was
 * detected at some point.
 *
 * 2. Because of (1), the normal platform-specific startup logic for PCIe may or
 * may not have found any devices and initialized them depending on at what
 * state in the initialization point it was at.
 *
 * 3. To actually enumerate a hotplug device, our DDI_HPOP_CN_PROBE entry point
 * needs to be called, which is pciehpc_slot_probe(). This will ultimately call
 * pcicfg_configure(). There is a wrinkle here. If we have done (2), we don't
 * want to call the probe entry point. However, if we haven't, then at start up,
 * the broader hotplug unfortunately, won't assume that there is anything to do
 * here to make this happen. The kernel framework won't call this unless it sees
 * a transition from a lesser state to DDI_HP_CN_STATE_ENABLED.
 *
 * The cases described above are not our only problem. In particular, there are
 * some other complications that happen here. In particular, it's worth
 * understanding how we actually keep all of our state in sync. The core idea is
 * that changes are coming from one of two places: either a user has explicitly
 * requested a state change or we have had external activity that has injected a
 * hotplug interrupt. This is due to something such as a surprise insertion,
 * removal, power fault, or similar activity.
 *
 * The general construction and assumption is that we know the valid state at
 * the moment before an interrupt occurs, so then the slot status register will
 * indicate to us what has changed. Once we know what we should transition to,
 * then we will go ahead and ask the system to make a state change request to
 * change our state to a given target. While this is similar in spirit to what a
 * user could request, they could not imitate a state transition to EMPTY. The
 * transition to EMPTY or to ENABLED is what kicks off the probe and unprobe
 * operations.
 *
 * This system is all well and good, but it is dependent on the fact that we
 * have an interrupt enabled for changes and that the various interrupt cause
 * bits in the slot status register have been cleared as they are generally RW1C
 * (read, write 1 to clear). This means that in addition to the issues with case
 * (1) and what firmware has or hasn't done, it is also possible that additional
 * changes may occur without us recording them or noticing them in an interrupt.
 *
 * This steady state is a great place to be, but because of the races we
 * discussed above, we need to do a bit of additional work here to ensure that
 * we can reliably enter it. As such, we're going to address the three
 * complications above in reverse order. If we start with (3), while in the
 * steady state, we basically treat the DDI states as the main states we can
 * transition to and from (again see the pciehpc_slot_power_t comment for the
 * fact that this is somewhat factious). This means that if we are ENABLED, a
 * probe must have happened (or the semi-equivalent in (2)).
 *
 * Normally, we assume that if we got all the way up and have a powered device
 * that the state we should return to the system is ENABLED. However, that only
 * works if we can ensure that the state transition from less than ENABLED to
 * ENABLED occurs so a probe can occur.
 *
 * This window is made larger because of (1) and (2). However, this is not
 * unique to the ENABLED state and these cases can happen by having a device
 * that was probed at initial time be removed prior to the interrupt being
 * enabled. While this is honestly a very tight window and something that may
 * not happen in practice, it highlights many of the things that can occur and
 * that we need to handle.
 *
 * To deal with this we are a little more careful with our startup state. When
 * we reach our module's main initialization entry point for a given controller,
 * pciehpc_init(), we know that at that point (2) has completed. We also know
 * that the interrupt shouldn't be initiated at that point, but that isn't
 * guaranteed until we finish calling the pciehpc_hpc_init() entry point. We
 * subsequently will enable the interrupt via the enable_phc_intr() function
 * pointer, which is called from pcie_hpintr_enable(). This gap is to allow the
 * overall driver (say pcieb) to ensure that it has allocated and attached
 * interrupts prior to us enabling it.
 *
 * At the point that we are initialized, we can look and see if we have any
 * children. If we do, then we know that (2) performed initialization and it's
 * safe for us to set our initial state to ENABLED and allow that to be the
 * first thing the kernel hotplug framework sees, assuming our state would
 * otherwise suggest we'd be here. If we do not see a child device and we have
 * enabled power, then we basically need to mimic the normal act of having
 * transitioned to an ENABLED state. This needs to happen ahead of us first
 * communicating our state to the DDI.
 *
 * The next set of things we need to do happen when we go to enable interrupts.
 * It's worth keeping in mind that at this point the rest of the system is fully
 * operational. One of three events can be injected at this point, a removal,
 * insertion, or a power fault. We also need to consider that a removal or
 * insertion happened in an intervening point. To make this all happen, let's
 * discuss the different pieces that are involved in tracking what's going on:
 *
 * 1) During pciehpc_slotinfo_init() we check to see if we have a child devinfo
 * node or not. We only mark a node as ENABLED if we have a child and it is
 * already POWERED. This ensures that we aren't ahead of ourselves. The normal
 * state determination logic will not put us at enabled prior to being there.
 *
 * 2) We have added a pair of flags to the pcie_hp_ctrl_t called
 * PCIE_HP_SYNC_PENDING and PCIE_HP_SYNC_RUNNING. The former indicates that we
 * have identified that we need to perform a state correction and have
 * dispatched a task to the system taskq to deal with it. The
 * PCIE_HP_SYNC_RUNNING flag is used to indicate that a state transition request
 * is actually being made due to this right now. This is used to tweak a bit of
 * the slot upgrade path, discussed below.
 *
 * 3) Immediately after enabling interrupts, while still holding the hotplug
 * controller mutex, we investigate what our current state is and what we have
 * previously set it to. Depending on the transition that needs to occur and if
 * it has a side effect of needing to probe or unprobe a connection, then we'll
 * end up scheduling a task in the system taskq to perform that transition.
 * Otherwise, we will simply fix up the LED state as we have no reason to
 * believe that it is currently correct for our state.
 *
 * Using the taskq has a major benefit for us in that it allows us to leverage
 * the existing code paths for state transitions. This means that if things are
 * already powered on and the data link layer is active, there won't be any
 * extra delay and if not, it will honor the same 1s timeout, take advantage of
 * the datalink layer active bit if supported, and on failure it will turn off
 * the controller.
 *
 * 4) We are reliant on an important property of pciehpc_get_slot_state(): if it
 * finds itself in the POWERED state, it will not change from that. This is half
 * of the reason that we opt to go to the POWERED state when this occurs. The
 * other half is that it is factually accurate and doing otherwise would get in
 * the way of our logic which attempts to correct the state in
 * pciehpc_change_slot_state() which corrects for the state being incorrect.
 * While it is tempting to use the PRESENT state and try to avoid a special case
 * in pciehpc_upgrade_slot_state(), that ends up breaking more invariants than
 * the logic described below.
 *
 * 5) Finally, when the PCIE_HP_SYNC_RUNNING bit is set, that tells us when
 * we're doing a power on exercise that we need to do so again regardless of
 * what we think we've done. Because of our attempts to try to have things be
 * idempotent, this ends up being a relatively safe operation to perform again
 * and being able to reuse this helps a lot.
 *
 * It is our hope that after this point everything will be in line such that we
 * can enter the steady state. If devices have come or gone, the use of the
 * normal state machine transitions should allow us to get them to be attached
 * or not.
 */

#include <sys/types.h>
#include <sys/note.h>
#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/vtrace.h>
#include <sys/autoconf.h>
#include <sys/varargs.h>
#include <sys/ddi_impldefs.h>
#include <sys/time.h>
#include <sys/callb.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/sysevent/dr.h>
#include <sys/pci_impl.h>
#include <sys/hotplug/pci/pcie_hp.h>
#include <sys/hotplug/pci/pciehpc.h>

/* XXX /etc/system is NOT a policy interface */
int pcie_auto_online = 1;

typedef struct pciehpc_prop {
	char	*prop_name;
	char	*prop_value;
} pciehpc_prop_t;

static pciehpc_prop_t	pciehpc_props[] = {
	{ PCIEHPC_PROP_LED_FAULT,	PCIEHPC_PROP_VALUE_LED },
	{ PCIEHPC_PROP_LED_POWER,	PCIEHPC_PROP_VALUE_LED },
	{ PCIEHPC_PROP_LED_ATTN,	PCIEHPC_PROP_VALUE_LED },
	{ PCIEHPC_PROP_LED_ACTIVE,	PCIEHPC_PROP_VALUE_LED },
	{ PCIEHPC_PROP_CARD_TYPE,	PCIEHPC_PROP_VALUE_TYPE },
	{ PCIEHPC_PROP_BOARD_TYPE,	PCIEHPC_PROP_VALUE_TYPE },
	{ PCIEHPC_PROP_SLOT_CONDITION,	PCIEHPC_PROP_VALUE_TYPE }
};

/*
 * Ideally, it would be possible to represent the state of a slot with a single
 * ddi_hp_cn_state_t; after all, that's the purpose of that data type.
 * Unfortunately it wasn't designed very well and cannot even represent the
 * range of possible power states of a PCIe slot.  It is possible for a slot to
 * be powered on or off with or without a device present, and it is possible for
 * a slot not to have a power controller at all.  Finally, it's possible for a
 * power fault to be detected regardless of whether power is on or off or a
 * device is present or not.  This state attempts to represent all possible
 * power states that a slot can have, which is important for implementing our
 * state machine that has to expose only the very limited DDI states.
 *
 * These are bits that may be ORed together.  Not all combinations comply with
 * the standards, but these definitions were chosen to make it harder to
 * construct invalid combinations.  In particular, if there is no controller,
 * there is also no possibility of the slot being turned off, nor is it possible
 * for there to be a fault.
 */
typedef enum pciehpc_slot_power {
	PSP_NO_CONTROLLER = 0,
	PSP_HAS_CONTROLLER = (1U << 0),
	PSP_OFF = (1U << 1),
	PSP_FAULT = (1U << 2)
} pciehpc_slot_power_t;

typedef struct {
	pcie_hp_ctrl_t *pst_ctrl;
	ddi_hp_cn_state_t pst_targ;
	ddi_hp_cn_state_t pst_cur;
} pciehpc_sync_task_t;

/* Local functions prototype */
static int pciehpc_hpc_init(pcie_hp_ctrl_t *ctrl_p);
static int pciehpc_hpc_uninit(pcie_hp_ctrl_t *ctrl_p);
static int pciehpc_slotinfo_init(pcie_hp_ctrl_t *ctrl_p);
static int pciehpc_slotinfo_uninit(pcie_hp_ctrl_t *ctrl_p);
static int pciehpc_enable_intr(pcie_hp_ctrl_t *ctrl_p);
static int pciehpc_disable_intr(pcie_hp_ctrl_t *ctrl_p);
static pcie_hp_ctrl_t *pciehpc_create_controller(dev_info_t *dip);
static void pciehpc_destroy_controller(dev_info_t *dip);
static int pciehpc_register_slot(pcie_hp_ctrl_t *ctrl_p);
static int pciehpc_unregister_slot(pcie_hp_ctrl_t *ctrl_p);
static int pciehpc_slot_get_property(pcie_hp_slot_t *slot_p,
    ddi_hp_property_t *arg, ddi_hp_property_t *rval);
static int pciehpc_slot_set_property(pcie_hp_slot_t *slot_p,
    ddi_hp_property_t *arg, ddi_hp_property_t *rval);
static void pciehpc_issue_hpc_command(pcie_hp_ctrl_t *ctrl_p, uint16_t control);
static void pciehpc_attn_btn_handler(pcie_hp_ctrl_t *ctrl_p);
static pcie_hp_led_state_t pciehpc_led_state_to_hpc(uint16_t state);
static pcie_hp_led_state_t pciehpc_get_led_state(pcie_hp_ctrl_t *ctrl_p,
    pcie_hp_led_t led);
static void pciehpc_set_led_state(pcie_hp_ctrl_t *ctrl_p, pcie_hp_led_t led,
    pcie_hp_led_state_t state);

static int pciehpc_upgrade_slot_state(pcie_hp_slot_t *slot_p,
    ddi_hp_cn_state_t target_state);
static int pciehpc_downgrade_slot_state(pcie_hp_slot_t *slot_p,
    ddi_hp_cn_state_t target_state);
static int pciehpc_change_slot_state(pcie_hp_slot_t *slot_p,
    ddi_hp_cn_state_t target_state);
static int
    pciehpc_slot_poweron(pcie_hp_slot_t *slot_p, ddi_hp_cn_state_t *result);
static int
    pciehpc_slot_poweroff(pcie_hp_slot_t *slot_p, ddi_hp_cn_state_t *result);
static int pciehpc_slot_probe(pcie_hp_slot_t *slot_p);
static int pciehpc_slot_unprobe(pcie_hp_slot_t *slot_p);
static void pciehpc_handle_power_fault(dev_info_t *dip);
static void pciehpc_power_fault_handler(void *arg);

#ifdef	DEBUG
static void pciehpc_dump_hpregs(pcie_hp_ctrl_t *ctrl_p);
#endif	/* DEBUG */

/*
 * Global functions (called by other drivers/modules)
 */

/*
 * Initialize Hot Plug Controller if present. The arguments are:
 *	dip	- Devinfo node pointer to the hot plug bus node
 *	regops	- register ops to access HPC registers for non-standard
 *		  HPC hw implementations (e.g: HPC in host PCI-E brdiges)
 *		  This is NULL for standard HPC in PCIe bridges.
 * Returns:
 *	DDI_SUCCESS for successful HPC initialization
 *	DDI_FAILURE for errors or if HPC hw not found
 */
int
pciehpc_init(dev_info_t *dip, caddr_t arg)
{
	pcie_hp_regops_t	*regops = (pcie_hp_regops_t *)(void *)arg;
	pcie_hp_ctrl_t		*ctrl_p;

	PCIE_DBG("pciehpc_init() called (dip=%p)\n", (void *)dip);

	/* Make sure that it is not already initialized */
	if ((ctrl_p = PCIE_GET_HP_CTRL(dip)) != NULL) {
		PCIE_DBG("%s%d: pciehpc instance already initialized!\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_SUCCESS);
	}

	/* Allocate a new hotplug controller and slot structures */
	ctrl_p = pciehpc_create_controller(dip);

	/* setup access handle for HPC regs */
	if (regops != NULL) {
		/* HPC access is non-standard; use the supplied reg ops */
		ctrl_p->hc_regops = *regops;
	}

	/*
	 * Setup resource maps for this bus node.
	 */
	(void) pci_resource_setup(dip);

	PCIE_DISABLE_ERRORS(dip);

	/*
	 * Set the platform specific hot plug mode.
	 */
	ctrl_p->hc_ops.init_hpc_hw = pciehpc_hpc_init;
	ctrl_p->hc_ops.uninit_hpc_hw = pciehpc_hpc_uninit;
	ctrl_p->hc_ops.init_hpc_slotinfo = pciehpc_slotinfo_init;
	ctrl_p->hc_ops.uninit_hpc_slotinfo = pciehpc_slotinfo_uninit;
	ctrl_p->hc_ops.poweron_hpc_slot = pciehpc_slot_poweron;
	ctrl_p->hc_ops.poweroff_hpc_slot = pciehpc_slot_poweroff;

	ctrl_p->hc_ops.enable_hpc_intr = pciehpc_enable_intr;
	ctrl_p->hc_ops.disable_hpc_intr = pciehpc_disable_intr;

#if	defined(__x86)
	pciehpc_update_ops(ctrl_p);
#endif

	/* initialize hot plug controller hw */
	if ((ctrl_p->hc_ops.init_hpc_hw)(ctrl_p) != DDI_SUCCESS)
		goto cleanup1;

	/* initialize slot information soft state structure */
	if ((ctrl_p->hc_ops.init_hpc_slotinfo)(ctrl_p) != DDI_SUCCESS)
		goto cleanup2;

	/* register the hot plug slot with DDI HP framework */
	if (pciehpc_register_slot(ctrl_p) != DDI_SUCCESS)
		goto cleanup3;

	/* create minor node for this slot */
	if (pcie_create_minor_node(ctrl_p, 0) != DDI_SUCCESS)
		goto cleanup4;

	/*
	 * While we disabled errors upon entry, if we were initialized and
	 * entered the ENABLED state that indicates we have children and
	 * therefore we should go back and enable errors.
	 */
	if (ctrl_p->hc_slots[0]->hs_info.cn_state == DDI_HP_CN_STATE_ENABLED) {
		PCIE_ENABLE_ERRORS(dip);
	}

	/* HPC initialization is complete now */
	ctrl_p->hc_flags |= PCIE_HP_INITIALIZED_FLAG;

#ifdef	DEBUG
	/* For debug, dump the HPC registers */
	pciehpc_dump_hpregs(ctrl_p);
#endif	/* DEBUG */

	return (DDI_SUCCESS);
cleanup4:
	(void) pciehpc_unregister_slot(ctrl_p);
cleanup3:
	(void) (ctrl_p->hc_ops.uninit_hpc_slotinfo)(ctrl_p);

cleanup2:
	(void) (ctrl_p->hc_ops.uninit_hpc_hw)(ctrl_p);

cleanup1:
	PCIE_ENABLE_ERRORS(dip);
	(void) pci_resource_destroy(dip);

	pciehpc_destroy_controller(dip);
	return (DDI_FAILURE);
}

/*
 * Uninitialize HPC soft state structure and free up any resources
 * used for the HPC instance.
 */
int
pciehpc_uninit(dev_info_t *dip)
{
	pcie_hp_ctrl_t *ctrl_p;
	taskqid_t id;

	PCIE_DBG("pciehpc_uninit() called (dip=%p)\n", (void *)dip);

	/* get the soft state structure for this dip */
	if ((ctrl_p = PCIE_GET_HP_CTRL(dip)) == NULL) {
		return (DDI_FAILURE);
	}

	/*
	 * Prior to taking any action, we want to remove the initialized flag.
	 * Any interrupts should have already been quiesced prior to this. There
	 * may be an outstanding startup synchronization timeout(9F) call.
	 */
	mutex_enter(&ctrl_p->hc_mutex);
	ctrl_p->hc_flags &= ~PCIE_HP_INITIALIZED_FLAG;
	id = ctrl_p->hc_startup_sync;
	ctrl_p->hc_startup_sync = TASKQID_INVALID;
	mutex_exit(&ctrl_p->hc_mutex);

	if (id != TASKQID_INVALID)
		taskq_wait_id(system_taskq, id);

	pcie_remove_minor_node(ctrl_p, 0);

	/* unregister the slot */
	(void) pciehpc_unregister_slot(ctrl_p);

	/* uninit any slot info data structures */
	(void) (ctrl_p->hc_ops.uninit_hpc_slotinfo)(ctrl_p);

	/* uninitialize hpc, remove interrupt handler, etc. */
	(void) (ctrl_p->hc_ops.uninit_hpc_hw)(ctrl_p);

	PCIE_ENABLE_ERRORS(dip);

	/*
	 * Destroy resource maps for this bus node.
	 */
	(void) pci_resource_destroy(dip);

	/* destroy the soft state structure */
	pciehpc_destroy_controller(dip);

	return (DDI_SUCCESS);
}

/*
 * pciehpc_intr()
 *
 * Interrupt handler for PCI-E Hot plug controller interrupts.
 *
 * Note: This is only for native mode hot plug. This is called
 * by the nexus driver at interrupt context. Interrupt Service Routine
 * registration is done by the nexus driver for both hot plug and
 * non-hot plug interrupts. This function is called from the ISR
 * of the nexus driver to handle hot-plug interrupts.
 *
 * We must check whether or not we have a pending synchronization event and if
 * so, cancel it. In particular, there are several cases that may cause us to
 * request an asynchronous state transition (e.g. a drive was removed or
 * inserted). When that occurs, we effectively cancel the pending
 * synchronization taskq activity. It will still execute, but do nothing. If it
 * has already started executing, then its state change request will already
 * have been dispatched and we let things shake out with the additional logic we
 * have present in pciehpc_change_slot_state().
 */
int
pciehpc_intr(dev_info_t *dip)
{
	pcie_hp_ctrl_t	*ctrl_p;
	pcie_hp_slot_t	*slot_p;
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	uint16_t	status, control;
	boolean_t	clear_pend = B_FALSE;

	/* get the soft state structure for this dip */
	if ((ctrl_p = PCIE_GET_HP_CTRL(dip)) == NULL)
		return (DDI_INTR_UNCLAIMED);

	mutex_enter(&ctrl_p->hc_mutex);

	/* make sure the controller soft state is initialized */
	if (!(ctrl_p->hc_flags & PCIE_HP_INITIALIZED_FLAG)) {
		mutex_exit(&ctrl_p->hc_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	/* if it is not NATIVE hot plug mode then return */
	if (bus_p->bus_hp_curr_mode != PCIE_NATIVE_HP_MODE) {
		mutex_exit(&ctrl_p->hc_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	slot_p = ctrl_p->hc_slots[0];

	/* read the current slot status register */
	status = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS);

	/* check if there are any hot plug interrupts occurred */
	if (!(status & PCIE_SLOTSTS_STATUS_EVENTS)) {
		/* no hot plug events occurred */
		mutex_exit(&ctrl_p->hc_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	/* clear the interrupt status bits */
	pciehpc_reg_put16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS, status);

	/* check for CMD COMPLETE interrupt */
	if (status & PCIE_SLOTSTS_COMMAND_COMPLETED) {
		PCIE_DBG("pciehpc_intr(): CMD COMPLETED interrupt received\n");
		/* wake up any one waiting for Command Completion event */
		cv_signal(&ctrl_p->hc_cmd_comp_cv);
	}

	/* check for ATTN button interrupt */
	if (status & PCIE_SLOTSTS_ATTN_BTN_PRESSED) {
		PCIE_DBG("pciehpc_intr(): ATTN BUTTON interrupt received\n");

		/* if ATTN button event is still pending then cancel it */
		if (slot_p->hs_attn_btn_pending == B_TRUE)
			slot_p->hs_attn_btn_pending = B_FALSE;
		else
			slot_p->hs_attn_btn_pending = B_TRUE;

		/* wake up the ATTN event handler */
		cv_signal(&slot_p->hs_attn_btn_cv);
	}

	/* check for power fault interrupt */
	if (status & PCIE_SLOTSTS_PWR_FAULT_DETECTED) {

		PCIE_DBG("pciehpc_intr(): POWER FAULT interrupt received"
		    " on slot %d\n", slot_p->hs_phy_slot_num);
		control =  pciehpc_reg_get16(ctrl_p,
		    bus_p->bus_pcie_off + PCIE_SLOTCTL);

		if (control & PCIE_SLOTCTL_PWR_FAULT_EN) {
			slot_p->hs_condition = AP_COND_FAILED;

			/* disable power fault detection interrupt */
			pciehpc_reg_put16(ctrl_p, bus_p->bus_pcie_off +
			    PCIE_SLOTCTL, control & ~PCIE_SLOTCTL_PWR_FAULT_EN);

			pciehpc_handle_power_fault(dip);
			clear_pend = B_TRUE;
		}
	}

	/* check for MRL SENSOR CHANGED interrupt */
	if (status & PCIE_SLOTSTS_MRL_SENSOR_CHANGED) {
		/* For now (phase-I), no action is taken on this event */
		PCIE_DBG("pciehpc_intr(): MRL SENSOR CHANGED interrupt received"
		    " on slot %d\n", slot_p->hs_phy_slot_num);
	}

	/* check for PRESENCE CHANGED interrupt */
	if (status & PCIE_SLOTSTS_PRESENCE_CHANGED) {

		PCIE_DBG("pciehpc_intr(): PRESENCE CHANGED interrupt received"
		    " on slot %d\n", slot_p->hs_phy_slot_num);

		if (status & PCIE_SLOTSTS_PRESENCE_DETECTED) {
			ddi_hp_cn_state_t tgt_state = (pcie_auto_online != 0) ?
			    DDI_HP_CN_STATE_ENABLED : DDI_HP_CN_STATE_PRESENT;
			/*
			 * card is inserted into the slot, ask DDI Hotplug
			 * framework to change state to Present.
			 */
			cmn_err(CE_NOTE, "pciehpc (%s%d): card is inserted"
			    " in the slot %s",
			    ddi_driver_name(dip),
			    ddi_get_instance(dip),
			    slot_p->hs_info.cn_name);

			(void) ndi_hp_state_change_req(dip,
			    slot_p->hs_info.cn_name,
			    tgt_state, DDI_HP_REQ_ASYNC);
		} else { /* card is removed from the slot */
			cmn_err(CE_NOTE, "pciehpc (%s%d): card is removed"
			    " from the slot %s",
			    ddi_driver_name(dip),
			    ddi_get_instance(dip),
			    slot_p->hs_info.cn_name);

			if (slot_p->hs_info.cn_state ==
			    DDI_HP_CN_STATE_ENABLED) {
				/* Card is removed when slot is enabled */
				slot_p->hs_condition = AP_COND_FAILED;
			} else {
				slot_p->hs_condition = AP_COND_UNKNOWN;
			}
			/* make sure to disable power fault detction intr */
			control =  pciehpc_reg_get16(ctrl_p,
			    bus_p->bus_pcie_off + PCIE_SLOTCTL);

			if (control & PCIE_SLOTCTL_PWR_FAULT_EN)
				pciehpc_reg_put16(ctrl_p, bus_p->bus_pcie_off +
				    PCIE_SLOTCTL,
				    control & ~PCIE_SLOTCTL_PWR_FAULT_EN);

			/*
			 * If supported, notify the child device driver that the
			 * device is being removed.
			 */
			dev_info_t *cdip = ddi_get_child(dip);
			if (cdip != NULL) {
				ddi_eventcookie_t rm_cookie;
				if (ddi_get_eventcookie(cdip,
				    DDI_DEVI_REMOVE_EVENT,
				    &rm_cookie) == DDI_SUCCESS) {
					ndi_post_event(dip, cdip, rm_cookie,
					    NULL);
				}
			}

			/*
			 * Ask DDI Hotplug framework to change state to Empty
			 */
			(void) ndi_hp_state_change_req(dip,
			    slot_p->hs_info.cn_name,
			    DDI_HP_CN_STATE_EMPTY,
			    DDI_HP_REQ_ASYNC);
		}

		clear_pend = B_TRUE;
	}

	/* check for DLL state changed interrupt */
	if (ctrl_p->hc_dll_active_rep &&
	    (status & PCIE_SLOTSTS_DLL_STATE_CHANGED)) {
		PCIE_DBG("pciehpc_intr(): DLL STATE CHANGED interrupt received"
		    " on slot %d\n", slot_p->hs_phy_slot_num);

		cv_signal(&slot_p->hs_dll_active_cv);
	}

	if (clear_pend) {
		ctrl_p->hc_flags &= ~PCIE_HP_SYNC_PENDING;
	}
	mutex_exit(&ctrl_p->hc_mutex);

	return (DDI_INTR_CLAIMED);
}

/*
 * Handle hotplug commands
 *
 * Note: This function is called by DDI HP framework at kernel context only
 */
/* ARGSUSED */
int
pciehpc_hp_ops(dev_info_t *dip, char *cn_name, ddi_hp_op_t op,
    void *arg, void *result)
{
	pcie_hp_ctrl_t	*ctrl_p;
	pcie_hp_slot_t	*slot_p;
	int		ret = DDI_SUCCESS;

	PCIE_DBG("pciehpc_hp_ops: dip=%p cn_name=%s op=%x arg=%p\n",
	    dip, cn_name, op, arg);

	if ((ctrl_p = PCIE_GET_HP_CTRL(dip)) == NULL)
		return (DDI_FAILURE);

	slot_p = ctrl_p->hc_slots[0];

	if (strcmp(cn_name, slot_p->hs_info.cn_name) != 0)
		return (DDI_EINVAL);

	switch (op) {
	case DDI_HPOP_CN_GET_STATE:
	{
		mutex_enter(&slot_p->hs_ctrl->hc_mutex);

		/* get the current slot state */
		pciehpc_get_slot_state(slot_p);

		*((ddi_hp_cn_state_t *)result) = slot_p->hs_info.cn_state;

		mutex_exit(&slot_p->hs_ctrl->hc_mutex);
		break;
	}
	case DDI_HPOP_CN_CHANGE_STATE:
	{
		ddi_hp_cn_state_t target_state = *(ddi_hp_cn_state_t *)arg;

		mutex_enter(&slot_p->hs_ctrl->hc_mutex);

		ret = pciehpc_change_slot_state(slot_p, target_state);
		*(ddi_hp_cn_state_t *)result = slot_p->hs_info.cn_state;

		mutex_exit(&slot_p->hs_ctrl->hc_mutex);
		break;
	}
	case DDI_HPOP_CN_PROBE:

		ret = pciehpc_slot_probe(slot_p);

		break;
	case DDI_HPOP_CN_UNPROBE:
		ret = pciehpc_slot_unprobe(slot_p);

		break;
	case DDI_HPOP_CN_GET_PROPERTY:
		ret = pciehpc_slot_get_property(slot_p,
		    (ddi_hp_property_t *)arg, (ddi_hp_property_t *)result);
		break;
	case DDI_HPOP_CN_SET_PROPERTY:
		ret = pciehpc_slot_set_property(slot_p,
		    (ddi_hp_property_t *)arg, (ddi_hp_property_t *)result);
		break;
	default:
		ret = DDI_ENOTSUP;
		break;
	}

	return (ret);
}

/*
 * Get the current state of the slot from the hw.
 *
 * The slot state should have been initialized before this function gets called.
 */
void
pciehpc_get_slot_state(pcie_hp_slot_t *slot_p)
{
	pcie_hp_ctrl_t	*ctrl_p = slot_p->hs_ctrl;
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	control, status;
	ddi_hp_cn_state_t curr_state = slot_p->hs_info.cn_state;

	ASSERT(MUTEX_HELD(&ctrl_p->hc_mutex));

	/* read the Slot Control Register */
	control = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);

	slot_p->hs_fault_led_state = PCIE_HP_LED_OFF; /* no fault led */
	slot_p->hs_active_led_state = PCIE_HP_LED_OFF; /* no active led */

	/* read the current Slot Status Register */
	status = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS);

	/* get POWER led state */
	slot_p->hs_power_led_state =
	    pciehpc_led_state_to_hpc(pcie_slotctl_pwr_indicator_get(control));

	/* get ATTN led state */
	slot_p->hs_attn_led_state =
	    pciehpc_led_state_to_hpc(pcie_slotctl_attn_indicator_get(control));

	if (!(status & PCIE_SLOTSTS_PRESENCE_DETECTED)) {
		/* no device present; slot is empty */
		slot_p->hs_info.cn_state = DDI_HP_CN_STATE_EMPTY;
		return;
	}

	/* device is present */
	slot_p->hs_info.cn_state = DDI_HP_CN_STATE_PRESENT;

	/*
	 * If we have power control and power control is disabled, then we are
	 * merely present. We cannot be POWERED or ENABLED without this being
	 * active.
	 */
	if (ctrl_p->hc_has_pwr && (control & PCIE_SLOTCTL_PWR_CONTROL) != 0) {
		return;
	}

	/*
	 * To be in the ENABLED state that means that we have verified that the
	 * device is ready to be used. This happens at different points in time
	 * right now depending on whether or not we have a power controller and
	 * should be consolidated in the future. Our main constraint is that the
	 * kernel expects that when something is in the ENABLED state that probe
	 * should succeed.
	 *
	 * For devices with a power controller, this is guaranteed as part of
	 * the PRESENT->POWERED transition. For devices without a power
	 * controller, we must assume that power is always applied (the slot
	 * control register bit for power status is undefined). This means that
	 * the POWERED->ENABLED transition point is where this occurs.
	 *
	 * This is all a long way of justifying the logic below. If our current
	 * state is enabled then we will stay in enabled; however, if it is
	 * anything else we will go to powered and allow the normal state
	 * transition to take effect.
	 */
	if (curr_state == DDI_HP_CN_STATE_ENABLED) {
		slot_p->hs_info.cn_state = curr_state;
	} else {
		slot_p->hs_info.cn_state = DDI_HP_CN_STATE_POWERED;
	}
}

/*
 * setup slot name/slot-number info.
 */
void
pciehpc_set_slot_name(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_hp_slot_t	*slot_p = ctrl_p->hc_slots[0];
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uchar_t		*slotname_data;
	int		*slotnum;
	uint_t		count;
	int		len;
	int		invalid_slotnum = 0;
	uint32_t	slot_capabilities;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, ctrl_p->hc_dip,
	    DDI_PROP_DONTPASS, "physical-slot#", &slotnum, &count) ==
	    DDI_PROP_SUCCESS) {
		slot_p->hs_phy_slot_num = slotnum[0];
		ddi_prop_free(slotnum);
	} else {
		slot_capabilities = pciehpc_reg_get32(ctrl_p,
		    bus_p->bus_pcie_off + PCIE_SLOTCAP);
		slot_p->hs_phy_slot_num =
		    PCIE_SLOTCAP_PHY_SLOT_NUM(slot_capabilities);
	}

	/* platform may not have initialized it */
	if (!slot_p->hs_phy_slot_num) {
		PCIE_DBG("%s#%d: Invalid slot number!\n",
		    ddi_driver_name(ctrl_p->hc_dip),
		    ddi_get_instance(ctrl_p->hc_dip));
		slot_p->hs_phy_slot_num = pciehpc_reg_get8(ctrl_p,
		    PCI_BCNF_SECBUS);
		invalid_slotnum = 1;
	}
	slot_p->hs_info.cn_num = slot_p->hs_phy_slot_num;
	slot_p->hs_info.cn_num_dpd_on = DDI_HP_CN_NUM_NONE;

	/*
	 * construct the slot_name:
	 *	if "slot-names" property exists then use that name
	 *	else if valid slot number exists then it is "pcie<slot-num>".
	 *	else it will be "pcie<sec-bus-number>dev0"
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, ctrl_p->hc_dip, DDI_PROP_DONTPASS,
	    "slot-names", (caddr_t)&slotname_data, &len) == DDI_PROP_SUCCESS) {
		char tmp_name[256];

		/*
		 * Note: for PCI-E slots, the device number is always 0 so the
		 * first (and only) string is the slot name for this slot.
		 */
		(void) snprintf(tmp_name, sizeof (tmp_name),
		    (char *)slotname_data + 4);
		slot_p->hs_info.cn_name = ddi_strdup(tmp_name, KM_SLEEP);
		kmem_free(slotname_data, len);
	} else {
		if (invalid_slotnum) {
			/* use device number ie. 0 */
			slot_p->hs_info.cn_name = ddi_strdup("pcie0",
			    KM_SLEEP);
		} else {
			char tmp_name[256];

			(void) snprintf(tmp_name, sizeof (tmp_name), "pcie%d",
			    slot_p->hs_phy_slot_num);
			slot_p->hs_info.cn_name = ddi_strdup(tmp_name,
			    KM_SLEEP);
		}
	}
}

/*
 * Read/Write access to HPC registers. If platform nexus has non-standard
 * HPC access mechanism then regops functions are used to do reads/writes.
 */
uint8_t
pciehpc_reg_get8(pcie_hp_ctrl_t *ctrl_p, uint_t off)
{
	if (ctrl_p->hc_regops.get != NULL) {
		return ((uint8_t)ctrl_p->hc_regops.get(
		    ctrl_p->hc_regops.cookie, (off_t)off));
	} else {
		pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);

		return (pci_config_get8(bus_p->bus_cfg_hdl, off));
	}
}

uint16_t
pciehpc_reg_get16(pcie_hp_ctrl_t *ctrl_p, uint_t off)
{
	if (ctrl_p->hc_regops.get != NULL) {
		return ((uint16_t)ctrl_p->hc_regops.get(
		    ctrl_p->hc_regops.cookie, (off_t)off));
	} else {
		pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);

		return (pci_config_get16(bus_p->bus_cfg_hdl, off));
	}
}

uint32_t
pciehpc_reg_get32(pcie_hp_ctrl_t *ctrl_p, uint_t off)
{
	if (ctrl_p->hc_regops.get != NULL) {
		return ((uint32_t)ctrl_p->hc_regops.get(
		    ctrl_p->hc_regops.cookie, (off_t)off));
	} else {
		pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);

		return (pci_config_get32(bus_p->bus_cfg_hdl, off));
	}
}

void
pciehpc_reg_put8(pcie_hp_ctrl_t *ctrl_p, uint_t off, uint8_t val)
{
	if (ctrl_p->hc_regops.put != NULL) {
		ctrl_p->hc_regops.put(ctrl_p->hc_regops.cookie,
		    (off_t)off, (uint_t)val);
	} else {
		pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);

		pci_config_put8(bus_p->bus_cfg_hdl, off, val);
	}
}

void
pciehpc_reg_put16(pcie_hp_ctrl_t *ctrl_p, uint_t off, uint16_t val)
{
	if (ctrl_p->hc_regops.put != NULL) {
		ctrl_p->hc_regops.put(ctrl_p->hc_regops.cookie,
		    (off_t)off, (uint_t)val);
	} else {
		pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);

		pci_config_put16(bus_p->bus_cfg_hdl, off, val);
	}
}

void
pciehpc_reg_put32(pcie_hp_ctrl_t *ctrl_p, uint_t off, uint32_t val)
{
	if (ctrl_p->hc_regops.put != NULL) {
		ctrl_p->hc_regops.put(ctrl_p->hc_regops.cookie,
		    (off_t)off, (uint_t)val);
	} else {
		pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);

		pci_config_put32(bus_p->bus_cfg_hdl, off, val);
	}
}

/*
 * ************************************************************************
 * ***	Local functions (called within this file)
 * ***	PCIe Native Hotplug mode specific functions
 * ************************************************************************
 */

/*
 * Initialize HPC hardware, install interrupt handler, etc. It doesn't
 * enable hot plug interrupts.
 *
 * (Note: It is called only from pciehpc_init().)
 */
static int
pciehpc_hpc_init(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	reg;

	/* read the Slot Control Register */
	reg = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);

	/* disable all interrupts */
	reg &= ~(PCIE_SLOTCTL_INTR_MASK);
	pciehpc_reg_put16(ctrl_p, bus_p->bus_pcie_off +
	    PCIE_SLOTCTL, reg);

	/* clear any interrupt status bits */
	reg = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS);
	pciehpc_reg_put16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS, reg);

	return (DDI_SUCCESS);
}

/*
 * Uninitialize HPC hardware, uninstall interrupt handler, etc.
 *
 * (Note: It is called only from pciehpc_uninit().)
 */
static int
pciehpc_hpc_uninit(pcie_hp_ctrl_t *ctrl_p)
{
	/* disable interrupts */
	(void) pciehpc_disable_intr(ctrl_p);

	return (DDI_SUCCESS);
}

/*
 * Setup slot information for use with DDI HP framework. Per the theory
 * statement, this is where we need to go through and look at whether or not we
 * have a child and whether or not we want the 1s later timeout to get things
 * into a reasonable state.
 */
static int
pciehpc_slotinfo_init(pcie_hp_ctrl_t *ctrl_p)
{
	uint32_t	slot_capabilities, link_capabilities;
	pcie_hp_slot_t	*slot_p = ctrl_p->hc_slots[0];
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	boolean_t	have_child;

	/*
	 * First we look to see if we have any children at all. If we do, then
	 * we assume that things were initialized prior to our existence as
	 * discussed by state initialization (2).
	 */
	ndi_devi_enter(ctrl_p->hc_dip);
	have_child = ddi_get_child(ctrl_p->hc_dip) != NULL;
	ndi_devi_exit(ctrl_p->hc_dip);

	mutex_enter(&ctrl_p->hc_mutex);
	/*
	 * setup DDI HP framework slot information structure
	 */
	slot_p->hs_device_num = 0;

	slot_p->hs_info.cn_type = DDI_HP_CN_TYPE_PCIE;
	slot_p->hs_info.cn_type_str = (ctrl_p->hc_regops.get == NULL) ?
	    PCIE_NATIVE_HP_TYPE : PCIE_PROP_HP_TYPE;
	slot_p->hs_info.cn_child = NULL;

	slot_p->hs_minor =
	    PCI_MINOR_NUM(ddi_get_instance(ctrl_p->hc_dip),
	    slot_p->hs_device_num);
	slot_p->hs_condition = AP_COND_UNKNOWN;

	/* read Slot Capabilities Register */
	slot_capabilities = pciehpc_reg_get32(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCAP);

	/* set slot-name/slot-number info */
	pciehpc_set_slot_name(ctrl_p);

	/* check if Attn Button present */
	ctrl_p->hc_has_attn = (slot_capabilities & PCIE_SLOTCAP_ATTN_BUTTON) ?
	    B_TRUE : B_FALSE;

	/* check if Manual Retention Latch sensor present */
	ctrl_p->hc_has_mrl = (slot_capabilities & PCIE_SLOTCAP_MRL_SENSOR) ?
	    B_TRUE : B_FALSE;

	/*
	 * Contrary to what one might expect, not all systems actually have
	 * power control despite having hot-swap capabilities. This is most
	 * commonly due to the Enterprise SSD specification which doesn't call
	 * for power-control in the PCIe native hotplug implementation.
	 */
	ctrl_p->hc_has_pwr = (slot_capabilities &
	    PCIE_SLOTCAP_POWER_CONTROLLER) ? B_TRUE: B_FALSE;

	/*
	 * PCI-E version 1.1 defines EMI Lock Present bit
	 * in Slot Capabilities register. Check for it.
	 */
	ctrl_p->hc_has_emi_lock = (slot_capabilities &
	    PCIE_SLOTCAP_EMI_LOCK_PRESENT) ? B_TRUE : B_FALSE;

	link_capabilities = pciehpc_reg_get32(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_LINKCAP);
	ctrl_p->hc_dll_active_rep = (link_capabilities &
	    PCIE_LINKCAP_DLL_ACTIVE_REP_CAPABLE) ? B_TRUE : B_FALSE;
	if (ctrl_p->hc_dll_active_rep)
		cv_init(&slot_p->hs_dll_active_cv, NULL, CV_DRIVER, NULL);

	/* setup thread for handling ATTN button events */
	if (ctrl_p->hc_has_attn) {
		PCIE_DBG("pciehpc_slotinfo_init: setting up ATTN button event "
		    "handler thread for slot %d\n", slot_p->hs_phy_slot_num);

		cv_init(&slot_p->hs_attn_btn_cv, NULL, CV_DRIVER, NULL);
		slot_p->hs_attn_btn_pending = B_FALSE;
		slot_p->hs_attn_btn_threadp = thread_create(NULL, 0,
		    pciehpc_attn_btn_handler,
		    (void *)ctrl_p, 0, &p0, TS_RUN, minclsyspri);
		slot_p->hs_attn_btn_thread_exit = B_FALSE;
	}

	/* get current slot state from the hw */
	slot_p->hs_info.cn_state = DDI_HP_CN_STATE_EMPTY;
	pciehpc_get_slot_state(slot_p);

	/*
	 * If the kernel has enumerated a device, note that we have performed
	 * the enabled transition.
	 */
	if (slot_p->hs_info.cn_state == DDI_HP_CN_STATE_POWERED &&
	    have_child) {
		slot_p->hs_info.cn_state = DDI_HP_CN_STATE_ENABLED;
	}

	if (slot_p->hs_info.cn_state >= DDI_HP_CN_STATE_ENABLED)
		slot_p->hs_condition = AP_COND_OK;
	mutex_exit(&ctrl_p->hc_mutex);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
pciehpc_slotinfo_uninit(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_hp_slot_t *slot_p = ctrl_p->hc_slots[0];

	if (slot_p->hs_attn_btn_threadp != NULL) {
		mutex_enter(&ctrl_p->hc_mutex);
		slot_p->hs_attn_btn_thread_exit = B_TRUE;
		cv_signal(&slot_p->hs_attn_btn_cv);
		PCIE_DBG("pciehpc_slotinfo_uninit: "
		    "waiting for ATTN thread exit\n");
		cv_wait(&slot_p->hs_attn_btn_cv, &ctrl_p->hc_mutex);
		PCIE_DBG("pciehpc_slotinfo_uninit: ATTN thread exit\n");
		cv_destroy(&slot_p->hs_attn_btn_cv);
		slot_p->hs_attn_btn_threadp = NULL;
		mutex_exit(&ctrl_p->hc_mutex);
	}

	if (ctrl_p->hc_dll_active_rep)
		cv_destroy(&slot_p->hs_dll_active_cv);
	if (slot_p->hs_info.cn_name)
		kmem_free(slot_p->hs_info.cn_name,
		    strlen(slot_p->hs_info.cn_name) + 1);

	return (DDI_SUCCESS);
}

/*
 * This is the synchronization function that is discussed in the 'State
 * Initialization' portion of the theory statement in this file. It is
 * responsible for trying to make sure that devices are in a usable state during
 * a potentially turbulent start up sequence.
 */
static void
pciehpc_state_sync(void *arg)
{
	pciehpc_sync_task_t *sync = arg;
	pcie_hp_ctrl_t *ctrl_p = sync->pst_ctrl;
	dev_info_t *dip = ctrl_p->hc_dip;
	pcie_hp_slot_t *slot_p = ctrl_p->hc_slots[0];

	mutex_enter(&ctrl_p->hc_mutex);
	if (ctrl_p->hc_startup_sync == TASKQID_INVALID) {
		mutex_exit(&ctrl_p->hc_mutex);
		kmem_free(sync, sizeof (pciehpc_sync_task_t));
		return;
	}

	if ((ctrl_p->hc_flags & PCIE_HP_SYNC_PENDING) == 0) {
		goto done;
	}

	cmn_err(CE_NOTE, "pciehpc (%s%d): synchronizing state in slot %s to "
	    "0x%x", ddi_driver_name(dip), ddi_get_instance(dip),
	    slot_p->hs_info.cn_name, sync->pst_targ);

	ASSERT3U(slot_p->hs_info.cn_state, ==, sync->pst_cur);

	ctrl_p->hc_flags &= ~PCIE_HP_SYNC_PENDING;
	ctrl_p->hc_flags |= PCIE_HP_SYNC_RUNNING;
	mutex_exit(&ctrl_p->hc_mutex);

	(void) ndi_hp_state_change_req(dip, slot_p->hs_info.cn_name,
	    sync->pst_targ, DDI_HP_REQ_SYNC);

	/*
	 * Now that we're done with operating this way, go ahead and clear
	 * things up.
	 */
	mutex_enter(&ctrl_p->hc_mutex);
done:
	ctrl_p->hc_flags &= ~PCIE_HP_SYNC_RUNNING;
	ctrl_p->hc_startup_sync = TASKQID_INVALID;
	mutex_exit(&ctrl_p->hc_mutex);
	kmem_free(sync, sizeof (pciehpc_sync_task_t));
}

static void
pciehpc_dispatch_state_sync(pcie_hp_ctrl_t *ctrl_p, ddi_hp_cn_state_t targ)
{
	pciehpc_sync_task_t *sync;
	pcie_hp_slot_t *slot_p = ctrl_p->hc_slots[0];

	ASSERT(MUTEX_HELD(&ctrl_p->hc_mutex));
	sync = kmem_alloc(sizeof (pciehpc_sync_task_t), KM_SLEEP);
	sync->pst_ctrl = ctrl_p;
	sync->pst_targ = targ;
	sync->pst_cur = slot_p->hs_info.cn_state;

	ctrl_p->hc_flags |= PCIE_HP_SYNC_PENDING;
	ctrl_p->hc_startup_sync = taskq_dispatch(system_taskq,
	    pciehpc_state_sync, sync, TQ_SLEEP);
}

static void
pciehpc_enable_state_sync_leds(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_hp_slot_t *slot_p = ctrl_p->hc_slots[0];

	switch (slot_p->hs_info.cn_state) {
	case DDI_HP_CN_STATE_ENABLED:
	case DDI_HP_CN_STATE_POWERED:
		pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED,
		    PCIE_HP_LED_ON);
		pciehpc_set_led_state(ctrl_p, PCIE_HP_ATTN_LED,
		    PCIE_HP_LED_OFF);
		break;
	case DDI_HP_CN_STATE_PRESENT:
	case DDI_HP_CN_STATE_EMPTY:
		pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED,
		    PCIE_HP_LED_OFF);
		pciehpc_set_led_state(ctrl_p, PCIE_HP_ATTN_LED,
		    PCIE_HP_LED_OFF);
		break;
	default:
		dev_err(ctrl_p->hc_dip, CE_PANIC, "encountered invalid "
		    "connector state: 0x%x", slot_p->hs_info.cn_state);
		break;
	}
}

/*
 * We have just enabled interrupts and cleared any changes that may or may not
 * have been valid from the hardware perspective. There are a few key
 * assumptions that we're making right now as discussed in the theory statement:
 *
 *  o If we are currently enabled, then we know that we have children and
 *    nothing has changed from our init.
 *  o Because we have just enabled interrupts, but have not relinquished our
 *    exclusion on the controller hardware, nothing else could have come in and
 *    started reacting to an actual change.
 *  o Even though someone could come and call DDI_HPOP_CN_GET_STATE, that could
 *    not transition us to enabled yet.
 *  o Because interrupt enable is still called in attach context, we cannot have
 *    a user accessing the node and requesting a state change.
 *
 * Finally there are a few things that we need to be mindful of. We must set any
 * updates to the state prior to calling into any request to update the LED
 * state as that may rely on getting an async callback.
 */
static void
pciehpc_enable_state_sync(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_bus_t *bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	pcie_hp_slot_t *slot_p = ctrl_p->hc_slots[0];
	uint16_t control, status;
	ddi_hp_cn_state_t curr_state, online_targ;

	online_targ = (pcie_auto_online != 0) ?  DDI_HP_CN_STATE_ENABLED :
	    DDI_HP_CN_STATE_PRESENT;
	ASSERT(MUTEX_HELD(&ctrl_p->hc_mutex));

	/*
	 * We manually compute the status from a single read of things rather
	 * than go through and use pciehpc_get_slot_state(). This is important
	 * to make sure that we can get hardware in sync with the kernel.
	 */
	curr_state = slot_p->hs_info.cn_state;
	control = pciehpc_reg_get16(ctrl_p, bus_p->bus_pcie_off + PCIE_SLOTCTL);
	status = pciehpc_reg_get16(ctrl_p, bus_p->bus_pcie_off + PCIE_SLOTSTS);

	if (!(status & PCIE_SLOTSTS_PRESENCE_DETECTED)) {
		switch (curr_state) {
		case DDI_HP_CN_STATE_ENABLED:
			pciehpc_dispatch_state_sync(ctrl_p,
			    DDI_HP_CN_STATE_EMPTY);
			break;
		case DDI_HP_CN_STATE_EMPTY:
		case DDI_HP_CN_STATE_PRESENT:
		case DDI_HP_CN_STATE_POWERED:
			if (ctrl_p->hc_has_pwr &&
			    (control & PCIE_SLOTCTL_PWR_CONTROL) == 0) {
				slot_p->hs_info.cn_state =
				    DDI_HP_CN_STATE_POWERED;
				pciehpc_dispatch_state_sync(ctrl_p,
				    DDI_HP_CN_STATE_EMPTY);
			} else {
				slot_p->hs_info.cn_state =
				    DDI_HP_CN_STATE_EMPTY;
				pciehpc_enable_state_sync_leds(ctrl_p);
			}
			break;
		default:
			dev_err(ctrl_p->hc_dip, CE_PANIC, "encountered invalid "
			    "connector state: 0x%x", curr_state);
			break;
		}

		return;
	}

	/*
	 * If we don't have a power controller, don't bother looking at this.
	 * There's nothing we can really do and we'll let the main case attempt
	 * to online this.
	 */
	if (ctrl_p->hc_has_pwr && (control & PCIE_SLOTCTL_PWR_CONTROL) != 0) {
		switch (curr_state) {
		case DDI_HP_CN_STATE_EMPTY:
			pciehpc_dispatch_state_sync(ctrl_p, online_targ);
			break;
		case DDI_HP_CN_STATE_PRESENT:
			if (curr_state == online_targ) {
				pciehpc_enable_state_sync_leds(ctrl_p);
				break;
			}
			pciehpc_dispatch_state_sync(ctrl_p, online_targ);
			break;
		case DDI_HP_CN_STATE_POWERED:
			dev_err(ctrl_p->hc_dip, CE_WARN, "device powered off "
			    "somehow from prior powered state, attempting "
			    "recovery");
			slot_p->hs_info.cn_state = DDI_HP_CN_STATE_PRESENT;
			if (online_targ > DDI_HP_CN_STATE_PRESENT) {
				pciehpc_dispatch_state_sync(ctrl_p,
				    online_targ);
			} else {
				pciehpc_enable_state_sync_leds(ctrl_p);
			}
			break;
		case DDI_HP_CN_STATE_ENABLED:
			/*
			 * This case seems very strange. We had a device that we
			 * enumerated and was online and something that wasn't
			 * us powerd off the slot. This is possibly a
			 * recoverable state, but it seems hard to understand
			 * what the proper path to go here is. While we could
			 * try to unprobe it, it's a real mystery how that
			 * happened and even that path might not be safe. If
			 * this kind of state is actually encountered in the
			 * wild and during this startup window of the device,
			 * then we'll need to figure out how to handle it there.
			 * Odds are it's either a software bug in this driver or
			 * something is going very wrong with hardware and as
			 * such, it's hard to predict what the solution is.
			 */
			dev_err(ctrl_p->hc_dip, CE_PANIC, "device powered off "
			    "somehow from prior enabled state unable to "
			    "recover");
			break;
		default:
			dev_err(ctrl_p->hc_dip, CE_PANIC, "encountered invalid "
			    "connector state: 0x%x", curr_state);
		}
		return;
	}

	/*
	 * While we should consider checking for a power fault here, if it was
	 * injected just after we cleared everythign as part of interrupt
	 * enable, then we'll get that injected normally and allow that to
	 * happen naturally.
	 */

	switch (curr_state) {
	case DDI_HP_CN_STATE_ENABLED:
		pciehpc_enable_state_sync_leds(ctrl_p);
		break;
	case DDI_HP_CN_STATE_POWERED:
	case DDI_HP_CN_STATE_EMPTY:
	case DDI_HP_CN_STATE_PRESENT:
		if (curr_state == online_targ) {
			pciehpc_enable_state_sync_leds(ctrl_p);
		} else {
			pciehpc_dispatch_state_sync(ctrl_p, online_targ);
		}
		break;
	default:
		dev_err(ctrl_p->hc_dip, CE_PANIC, "encountered invalid "
		    "connector state: 0x%x", curr_state);
	}
}

/*
 * Enable hot plug interrupts.
 * Note: this is only for Native hot plug mode.
 */
static int
pciehpc_enable_intr(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_hp_slot_t	*slot_p = ctrl_p->hc_slots[0];
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	reg;
	uint16_t	intr_mask = PCIE_SLOTCTL_INTR_MASK;

	mutex_enter(&ctrl_p->hc_mutex);

	/*
	 * power fault detection interrupt is enabled only
	 * when the slot is powered ON
	 */
	if (slot_p->hs_info.cn_state < DDI_HP_CN_STATE_POWERED)
		intr_mask &= ~PCIE_SLOTCTL_PWR_FAULT_EN;

	/*
	 * enable interrupt sources but leave the top-level
	 * interrupt disabled. some sources may generate a
	 * spurrious event when they are first enabled.
	 * by leaving the top-level interrupt disabled, those
	 * can be cleared first.
	 */
	reg = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);
	pciehpc_reg_put16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL,
	    reg | (intr_mask & ~PCIE_SLOTCTL_HP_INTR_EN));

	/* clear any interrupt status bits */
	reg = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS);
	pciehpc_reg_put16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS, reg);

	/* enable top-level interrupt */
	reg = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);
	pciehpc_reg_put16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL,
	    reg | intr_mask);

	/*
	 * Now, and only now that interrupts are enabled can we go back and
	 * perform state synchronization that is required of the system. This
	 * happens in a few steps. We have previously checked to see if we
	 * should be in the ENABLED or POWERED state. However, it is quite
	 * possible that hardware was left at its PCIe default of power being
	 * enabled, even if no device is present. Because we have interrupts
	 * enabled, if there is a change after this point, then it will be
	 * caught. See the theory statement for more information.
	 */
	pciehpc_enable_state_sync(ctrl_p);
	mutex_exit(&ctrl_p->hc_mutex);

	return (DDI_SUCCESS);
}

/*
 * Disable hot plug interrupts.
 * Note: this is only for Native hot plug mode.
 */
static int
pciehpc_disable_intr(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	reg;

	/* read the Slot Control Register */
	reg = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);

	/* disable all interrupts */
	reg &= ~(PCIE_SLOTCTL_INTR_MASK);
	pciehpc_reg_put16(ctrl_p, bus_p->bus_pcie_off + PCIE_SLOTCTL, reg);

	/* clear any interrupt status bits */
	reg = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS);
	pciehpc_reg_put16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS, reg);

	return (DDI_SUCCESS);
}

/*
 * Allocate a new hotplug controller and slot structures for HPC
 * associated with this dip.
 */
static pcie_hp_ctrl_t *
pciehpc_create_controller(dev_info_t *dip)
{
	pcie_hp_ctrl_t	*ctrl_p;
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	ctrl_p = kmem_zalloc(sizeof (pcie_hp_ctrl_t), KM_SLEEP);
	ctrl_p->hc_dip = dip;

	/* Allocate a new slot structure. */
	ctrl_p->hc_slots[0] = kmem_zalloc(sizeof (pcie_hp_slot_t), KM_SLEEP);
	ctrl_p->hc_slots[0]->hs_num = 0;
	ctrl_p->hc_slots[0]->hs_ctrl = ctrl_p;

	/* Initialize the interrupt mutex */
	mutex_init(&ctrl_p->hc_mutex, NULL, MUTEX_DRIVER,
	    (void *)PCIE_INTR_PRI);

	/* Initialize synchronization conditional variable */
	cv_init(&ctrl_p->hc_cmd_comp_cv, NULL, CV_DRIVER, NULL);
	ctrl_p->hc_cmd_pending = B_FALSE;

	bus_p->bus_hp_curr_mode = PCIE_NATIVE_HP_MODE;
	PCIE_SET_HP_CTRL(dip, ctrl_p);

	return (ctrl_p);
}

/*
 * Remove the HPC controller and slot structures
 */
static void
pciehpc_destroy_controller(dev_info_t *dip)
{
	pcie_hp_ctrl_t	*ctrl_p;
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	/* get the soft state structure for this dip */
	if ((ctrl_p = PCIE_GET_HP_CTRL(dip)) == NULL)
		return;

	PCIE_SET_HP_CTRL(dip, NULL);
	bus_p->bus_hp_curr_mode = PCIE_NONE_HP_MODE;

	mutex_destroy(&ctrl_p->hc_mutex);
	cv_destroy(&ctrl_p->hc_cmd_comp_cv);
	kmem_free(ctrl_p->hc_slots[0], sizeof (pcie_hp_slot_t));
	kmem_free(ctrl_p, sizeof (pcie_hp_ctrl_t));
}

/*
 * Register the PCI-E hot plug slot with DDI HP framework.
 */
static int
pciehpc_register_slot(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_hp_slot_t	*slot_p = ctrl_p->hc_slots[0];
	dev_info_t	*dip = ctrl_p->hc_dip;

	/* register the slot with DDI HP framework */
	if (ndi_hp_register(dip, &slot_p->hs_info) != NDI_SUCCESS) {
		PCIE_DBG("pciehpc_register_slot() failed to register slot %d\n",
		    slot_p->hs_phy_slot_num);
		return (DDI_FAILURE);
	}

	pcie_hp_create_occupant_props(dip, makedevice(ddi_driver_major(dip),
	    slot_p->hs_minor), slot_p->hs_device_num);

	PCIE_DBG("pciehpc_register_slot(): registered slot %d\n",
	    slot_p->hs_phy_slot_num);

	return (DDI_SUCCESS);
}

/*
 * Unregister the PCI-E hot plug slot from DDI HP framework.
 */
static int
pciehpc_unregister_slot(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_hp_slot_t *slot_p = ctrl_p->hc_slots[0];
	dev_info_t	*dip = ctrl_p->hc_dip;

	pcie_hp_delete_occupant_props(dip, makedevice(ddi_driver_major(dip),
	    slot_p->hs_minor));

	/* unregister the slot with DDI HP framework */
	if (ndi_hp_unregister(dip, slot_p->hs_info.cn_name) != NDI_SUCCESS) {
		PCIE_DBG("pciehpc_unregister_slot() "
		    "failed to unregister slot %d\n", slot_p->hs_phy_slot_num);
		return (DDI_FAILURE);
	}

	PCIE_DBG("pciehpc_unregister_slot(): unregistered slot %d\n",
	    slot_p->hs_phy_slot_num);

	return (DDI_SUCCESS);
}

static pciehpc_slot_power_t
pciehpc_slot_power_state(pcie_hp_slot_t *slot_p)
{
	pcie_hp_ctrl_t	*ctrl_p = slot_p->hs_ctrl;
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t control, status;
	pciehpc_slot_power_t state = 0;

	ASSERT(MUTEX_HELD(&ctrl_p->hc_mutex));

	if (!ctrl_p->hc_has_pwr) {
		return (PSP_NO_CONTROLLER);
	} else {
		state |= PSP_HAS_CONTROLLER;
	}

	control = pciehpc_reg_get16(ctrl_p, bus_p->bus_pcie_off + PCIE_SLOTCTL);
	status = pciehpc_reg_get16(ctrl_p, bus_p->bus_pcie_off + PCIE_SLOTSTS);

	if ((control & PCIE_SLOTCTL_PWR_CONTROL) != 0)
		state |= PSP_OFF;

	if ((status & PCIE_SLOTSTS_PWR_FAULT_DETECTED) != 0)
		state |= PSP_FAULT;

	return (state);
}

/*
 * Wait for a PCIe slot to be considered active per the PCIe hotplug rules. If
 * there is no DLL active reporting capability then we wait up to 1 second and
 * just assume it was successful. Regardless of whether or not we have explicit
 * power control, the device is still powering on and may not be ready to work.
 */
static boolean_t
pciehpc_slot_wait_for_active(pcie_hp_slot_t *slot_p)
{
	pcie_hp_ctrl_t *ctrl_p = slot_p->hs_ctrl;
	pcie_bus_t *bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);

	ASSERT(MUTEX_HELD(&ctrl_p->hc_mutex));

	if (ctrl_p->hc_dll_active_rep) {
		clock_t deadline;
		uint16_t status;

		/* wait 1 sec for the DLL State Changed event */
		status = pciehpc_reg_get16(ctrl_p,
		    bus_p->bus_pcie_off + PCIE_LINKSTS);

		deadline = ddi_get_lbolt() +
		    SEC_TO_TICK(PCIE_HP_DLL_STATE_CHANGE_TIMEOUT);

		while ((status & PCIE_LINKSTS_DLL_LINK_ACTIVE) == 0 &&
		    ddi_get_lbolt() < deadline) {
			(void) cv_timedwait(&slot_p->hs_dll_active_cv,
			    &ctrl_p->hc_mutex, deadline);

			/* check Link status */
			status =  pciehpc_reg_get16(ctrl_p,
			    bus_p->bus_pcie_off +
			    PCIE_LINKSTS);
		}

		if ((status & PCIE_LINKSTS_DLL_LINK_ACTIVE) == 0) {
			return (B_FALSE);
		}
	} else {
		/* wait 1 sec for link to come up */
		delay(drv_usectohz(1000000));
	}

	return (B_TRUE);
}

/*
 * This takes care of all the logic for trying to verify a slot's state that
 * does not have an explicit power controller. If this is a surprise insertion,
 * we still need to wait for the data link layer to become active even if we
 * don't explicitly control power. We do this in three steps:
 *
 * 1) Verify the slot is powered at least.
 * 2) Wait for the slot to be active.
 * 3) Verify the slot is still powered after that.
 */
static int
pciehpc_slot_noctrl_active(pcie_hp_slot_t *slot_p, ddi_hp_cn_state_t *result)
{
	pcie_hp_ctrl_t *ctrl_p = slot_p->hs_ctrl;

	VERIFY3U(ctrl_p->hc_has_pwr, ==, B_FALSE);
	ASSERT(MUTEX_HELD(&ctrl_p->hc_mutex));

	pciehpc_get_slot_state(slot_p);
	if (slot_p->hs_info.cn_state < DDI_HP_CN_STATE_POWERED) {
		return (DDI_FAILURE);
	}

	/*
	 * Regardless of whether this worked or failed we must check the slot
	 * state again.
	 */
	if (!pciehpc_slot_wait_for_active(slot_p)) {
		cmn_err(CE_WARN, "pciehpc_slot_poweron_noctrl (slot %d): "
		    "device failed to become active", slot_p->hs_phy_slot_num);
		return (DDI_FAILURE);
	}
	pciehpc_get_slot_state(slot_p);
	*result = slot_p->hs_info.cn_state;
	if (slot_p->hs_info.cn_state >= DDI_HP_CN_STATE_POWERED) {
		return (DDI_SUCCESS);
	} else {
		return (DDI_FAILURE);
	}
}

/*
 * Poweron/Enable the slot.
 *
 * Note: This function is called by DDI HP framework at kernel context only
 *
 * We intend for this function to be idempotent.  That is, when we return, if
 * the slot we've been asked to turn on has a device present, and has a power
 * controller, then a successful return guarantees all of the following,
 * regardless of the hardware or software state that existed when called:
 *
 * 1. The power controller enable bit is clear (asserted).
 * 2. If DLL State Change is supported by the bridge, we waited until DLL Active
 *    was asserted; otherwise we waited at least one second after the first
 *    moment we knew for certain that the power controller was enabled.
 * 3. Any power fault that was previously asserted in the status register has
 *    been acknowledged and cleared, allowing detection of subsequent faults if
 *    supported by hardware.
 * 4. The power indicator is on (if it exists).
 * 5. The MRL, if it exists, is latched.
 *
 * If we fail, either this slot has no power control capability or the following
 * guarantees are made:
 *
 * 1. We have attempted to disable the power controller for this slot.
 * 2. We have attempted to disable the power indicator for this slot.
 *
 * In the failure case, *result has undefined contents.  This function does not
 * change the contents of slot_p->hs_info.cn_state.  This allows callers to act
 * upon the previous software state (preserved by this function), the new
 * software state (in *result if successful), and the current hardware state
 * which can be obtained via pciehpc_get_slot_state().
 */
static int
pciehpc_slot_poweron(pcie_hp_slot_t *slot_p, ddi_hp_cn_state_t *result)
{
	pcie_hp_ctrl_t	*ctrl_p = slot_p->hs_ctrl;
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	status, control;

	ASSERT(MUTEX_HELD(&ctrl_p->hc_mutex));

	/*
	 * If the hardware doesn't have support for a power controller, then
	 * that generally means that power is already on or at the least there
	 * isn't very much else we can do and the PCIe spec says it's the
	 * responsibility of the controller to have turned it on if a device is
	 * present.  We don't care whether a device is present in this case,
	 * though, because we've been asked to turn on power and we know that we
	 * cannot.  Either a device is present and power is already on, in which
	 * case calling code can figure that out, or no device is present and
	 * we'd fail even if we had a controller.  Either way, we still indicate
	 * that is a failure since we can't change it and instead rely on code
	 * executing the actual state machine to figure out how to handle this.
	 */
	if (!ctrl_p->hc_has_pwr) {
		PCIE_DBG("pciehpc_slot_poweron (slot %d): no power control "
		    "capability, but was asked to power on\n",
		    slot_p->hs_phy_slot_num);
		return (DDI_FAILURE);
	}

	/*
	 * We need the current state of the slot control register to figure out
	 * whether the power controller is enabled already.  Note that this is
	 * not a status bit: it can't tell us whether power is actually on or
	 * off, only what the last control input was.  We also grab the status
	 * register here as we need several bits from it.
	 */
	control = pciehpc_reg_get16(ctrl_p, bus_p->bus_pcie_off + PCIE_SLOTCTL);
	status = pciehpc_reg_get16(ctrl_p, bus_p->bus_pcie_off + PCIE_SLOTSTS);

	/*
	 * If there's no device present, we need to fail.
	 */
	if (!(status & PCIE_SLOTSTS_PRESENCE_DETECTED)) {
		/* slot is empty */
		PCIE_DBG("pciehpc_slot_poweron (slot %d): slot is empty\n",
		    slot_p->hs_phy_slot_num);
		goto cleanup;
	}

	/*
	 * If there's an MRL and it's open, we need to fail.
	 */
	if ((ctrl_p->hc_has_mrl) && (status & PCIE_SLOTSTS_MRL_SENSOR_OPEN)) {
		cmn_err(CE_WARN, "pciehpc_slot_poweron (slot %d): MRL switch "
		    "is open", slot_p->hs_phy_slot_num);
		goto cleanup;
	}

	/*
	 * The power controller is already on, but we're in a state below
	 * POWERED.  This shouldn't happen, but there are any number of ways
	 * that it can; we simply note this if debugging and move on.
	 */
	if ((control & PCIE_SLOTCTL_PWR_CONTROL) == 0 &&
	    slot_p->hs_info.cn_state < DDI_HP_CN_STATE_POWERED) {
		PCIE_DBG("pciehpc_slot_poweron (slot %d): controller is "
		    "already enabled in SW state %d; continuing\n",
		    slot_p->hs_phy_slot_num, slot_p->hs_info.cn_state);
		goto alreadyon;
	}

	/*
	 * The power controller has been turned off (which doesn't mean it *is*
	 * off), but software thinks it's on.  This is pretty bad, and we
	 * probably need to consider doing something here to reset the state
	 * machine because upper layers are likely to be confused.  We will
	 * nevertheless turn on the controller and hope the right things happen
	 * above us.
	 */
	if ((control & PCIE_SLOTCTL_PWR_CONTROL) != 0 &&
	    slot_p->hs_info.cn_state >= DDI_HP_CN_STATE_POWERED) {
		cmn_err(CE_WARN, "pciehpc_slot_poweron (slot %d): SW state is "
		    "already %d but power controller is disabled; continuing",
		    slot_p->hs_phy_slot_num, slot_p->hs_info.cn_state);
	}

	/*
	 * Enable power to the slot involves:
	 *	1. Set power LED to blink and ATTN led to OFF.
	 *	2. Set power control ON in Slot Control Reigster and
	 *	   wait for Command Completed Interrupt or 1 sec timeout.
	 *	3. If Data Link Layer State Changed events are supported
	 *	   then wait for the event to indicate Data Layer Link
	 *	   is active. The time out value for this event is 1 second.
	 *	   This is specified in PCI-E version 1.1.
	 *	4. Set power LED to be ON.
	 */

	/* 1. set power LED to blink & ATTN led to OFF */
	pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED, PCIE_HP_LED_BLINK);

alreadyon:
	pciehpc_set_led_state(ctrl_p, PCIE_HP_ATTN_LED, PCIE_HP_LED_OFF);

	/* 2. set power control to ON */
	control =  pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);
	control &= ~PCIE_SLOTCTL_PWR_CONTROL;
	pciehpc_issue_hpc_command(ctrl_p, control);

	/* 3. wait for DLL State Change event, if it's supported */
	if (!pciehpc_slot_wait_for_active(slot_p))
		goto cleanup;

	/* check power is really turned ON */
	control = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);

	if (control & PCIE_SLOTCTL_PWR_CONTROL) {
		PCIE_DBG("pciehpc_slot_poweron (slot %d): power controller "
		    "enable was disabled autonomously after SW enable",
		    slot_p->hs_phy_slot_num);

		goto cleanup;
	}

	/* clear power fault status */
	status = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTSTS);
	status |= PCIE_SLOTSTS_PWR_FAULT_DETECTED;
	pciehpc_reg_put16(ctrl_p, bus_p->bus_pcie_off + PCIE_SLOTSTS,
	    status);

	/* enable power fault detection interrupt */
	control |= PCIE_SLOTCTL_PWR_FAULT_EN;
	pciehpc_issue_hpc_command(ctrl_p, control);

	/* 4. Set power LED to be ON */
	pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED, PCIE_HP_LED_ON);

	/* if EMI is present, turn it ON */
	if (ctrl_p->hc_has_emi_lock) {
		status = pciehpc_reg_get16(ctrl_p,
		    bus_p->bus_pcie_off + PCIE_SLOTSTS);

		if (!(status & PCIE_SLOTSTS_EMI_LOCK_SET)) {
			control = pciehpc_reg_get16(ctrl_p,
			    bus_p->bus_pcie_off + PCIE_SLOTCTL);
			control |= PCIE_SLOTCTL_EMI_LOCK_CONTROL;
			pciehpc_issue_hpc_command(ctrl_p, control);

			/* wait 1 sec after toggling the state of EMI lock */
			delay(drv_usectohz(1000000));
		}
	}

	*result = slot_p->hs_info.cn_state = DDI_HP_CN_STATE_POWERED;

	return (DDI_SUCCESS);

cleanup:
	control = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);

	/* if power is ON, set power control to OFF */
	if ((control & PCIE_SLOTCTL_PWR_CONTROL) == 0) {
		control |= PCIE_SLOTCTL_PWR_CONTROL;
		pciehpc_issue_hpc_command(ctrl_p, control);
	}

	/* set power led to OFF XXX what if HW/FW refused to turn off? */
	pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED, PCIE_HP_LED_OFF);

	return (DDI_FAILURE);
}

/*
 * All the same considerations apply to poweroff; see notes above.
 */
static int
pciehpc_slot_poweroff(pcie_hp_slot_t *slot_p, ddi_hp_cn_state_t *result)
{
	pcie_hp_ctrl_t	*ctrl_p = slot_p->hs_ctrl;
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	status, control;

	ASSERT(MUTEX_HELD(&ctrl_p->hc_mutex));

	/*
	 * Some devices do not have a power controller. In such cases we need to
	 * fail any request to power it off. If a device is being pulled, the
	 * state will generally have automatically been updated; however, if
	 * someone is asking for us to do something via an explicit request,
	 * then this will fail.
	 */
	if (!ctrl_p->hc_has_pwr) {
		PCIE_DBG("pciehpc_slot_poweroff (slot %d): no power control "
		    "capability, but was asked to power off\n",
		    slot_p->hs_phy_slot_num);
		return (DDI_ENOTSUP);
	}

	/*
	 * SW thinks the slot is already powered off.  Note this unexpected
	 * condition and continue.
	 */
	if (slot_p->hs_info.cn_state < DDI_HP_CN_STATE_POWERED) {
		PCIE_DBG("pciehpc_slot_poweroff (slot %d): SW state is "
		    "already %d; continuing\n",
		    slot_p->hs_phy_slot_num, slot_p->hs_info.cn_state);
	}

	control = pciehpc_reg_get16(ctrl_p, bus_p->bus_pcie_off + PCIE_SLOTCTL);
	status = pciehpc_reg_get16(ctrl_p, bus_p->bus_pcie_off + PCIE_SLOTSTS);

	/*
	 * The power controller has been turned off (which doesn't mean it *is*
	 * off), but software thinks it's on.  Note this unexpected condition
	 * for debugging and continue; we'll do what we can to get the state
	 * machines back in sync.
	 */
	if ((control & PCIE_SLOTCTL_PWR_CONTROL) != 0 &&
	    slot_p->hs_info.cn_state >= DDI_HP_CN_STATE_POWERED) {
		cmn_err(CE_WARN, "pciehpc_slot_poweroff (slot %d): SW state is "
		    "%d but power controller is already disabled; continuing",
		    slot_p->hs_phy_slot_num, slot_p->hs_info.cn_state);
		goto alreadyoff;
	}

	if (!(status & PCIE_SLOTSTS_PRESENCE_DETECTED)) {
		PCIE_DBG("pciehpc_slot_poweroff (slot %d): powering off "
		    "empty slot\n", slot_p->hs_phy_slot_num);
	}

	/*
	 * Disable power to the slot involves:
	 *	1. Set power LED to blink.
	 *	2. Set power control OFF in Slot Control Reigster and
	 *	   wait for Command Completed Interrupt or 1 sec timeout.
	 *	3. Set POWER led and ATTN led to be OFF.
	 */

	/* 1. set power LED to blink */
	pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED, PCIE_HP_LED_BLINK);

alreadyoff:
	/* disable power fault detection interrupt */
	control = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);
	control &= ~PCIE_SLOTCTL_PWR_FAULT_EN;
	pciehpc_issue_hpc_command(ctrl_p, control);

	/* 2. set power control to OFF */
	control = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);
	control |= PCIE_SLOTCTL_PWR_CONTROL;
	pciehpc_issue_hpc_command(ctrl_p, control);

	/*
	 * Make sure our control input has been acknowledged.  Some
	 * implementations may clear the control bit if the power controller
	 * couldn't be disabled for some reasons, or if firmware decided to
	 * disallow our command.
	 */
	control = pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);
	if ((control & PCIE_SLOTCTL_PWR_CONTROL) == 0) {
		/*
		 * Well, this is unfortunate: we couldn't turn power off.
		 * XXX Should we turn on the ATTN indicator?  For now we just
		 * log a warning and fail.
		 */
		cmn_err(CE_WARN, "pciehpc_slot_poweroff (slot %d): power "
		    "controller completed our disable command but is still "
		    "enabled", slot_p->hs_phy_slot_num);
		pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED,
		    PCIE_HP_LED_ON);

		return (DDI_FAILURE);
	}

	/* 3. Set power LED to be OFF */
	pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED, PCIE_HP_LED_OFF);
	pciehpc_set_led_state(ctrl_p, PCIE_HP_ATTN_LED, PCIE_HP_LED_OFF);

	/* if EMI is present, turn it OFF */
	if (ctrl_p->hc_has_emi_lock) {
		status =  pciehpc_reg_get16(ctrl_p,
		    bus_p->bus_pcie_off + PCIE_SLOTSTS);

		if (status & PCIE_SLOTSTS_EMI_LOCK_SET) {
			control =  pciehpc_reg_get16(ctrl_p,
			    bus_p->bus_pcie_off + PCIE_SLOTCTL);
			control |= PCIE_SLOTCTL_EMI_LOCK_CONTROL;
			pciehpc_issue_hpc_command(ctrl_p, control);

			/* wait 1 sec after toggling the state of EMI lock */
			delay(drv_usectohz(1000000));
		}
	}

	/* get the current state of the slot */
	pciehpc_get_slot_state(slot_p);

	*result = slot_p->hs_info.cn_state;

	return (DDI_SUCCESS);
}

/*
 * pciehpc_slot_probe()
 *
 * Probe the slot.
 *
 * Note: This function is called by DDI HP framework at kernel context only
 */
/*ARGSUSED*/
static int
pciehpc_slot_probe(pcie_hp_slot_t *slot_p)
{
	pcie_hp_ctrl_t	*ctrl_p = slot_p->hs_ctrl;
	int		ret = DDI_SUCCESS;

	mutex_enter(&ctrl_p->hc_mutex);

	/* get the current state of the slot */
	pciehpc_get_slot_state(slot_p);

	/*
	 * Probe a given PCIe Hotplug Connection (CN).
	 */
	PCIE_DISABLE_ERRORS(ctrl_p->hc_dip);
	ret = pcie_hp_probe(slot_p);

	if (ret != DDI_SUCCESS) {
		PCIE_DBG("pciehpc_slot_probe() failed\n");

		/* turn the ATTN led ON for configure failure */
		pciehpc_set_led_state(ctrl_p, PCIE_HP_ATTN_LED, PCIE_HP_LED_ON);

		/* if power to the slot is still on then set Power led to ON */
		if (slot_p->hs_info.cn_state >= DDI_HP_CN_STATE_POWERED)
			pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED,
			    PCIE_HP_LED_ON);

		mutex_exit(&ctrl_p->hc_mutex);
		return (DDI_FAILURE);
	}

	PCIE_ENABLE_ERRORS(ctrl_p->hc_dip);

	/* get the current state of the slot */
	pciehpc_get_slot_state(slot_p);

	mutex_exit(&ctrl_p->hc_mutex);
	return (DDI_SUCCESS);
}

/*
 * pciehpc_slot_unprobe()
 *
 * Unprobe the slot.
 *
 * Note: This function is called by DDI HP framework at kernel context only
 */
/*ARGSUSED*/
static int
pciehpc_slot_unprobe(pcie_hp_slot_t *slot_p)
{
	pcie_hp_ctrl_t	*ctrl_p = slot_p->hs_ctrl;
	int		ret;

	mutex_enter(&ctrl_p->hc_mutex);

	/* get the current state of the slot */
	pciehpc_get_slot_state(slot_p);

	/*
	 * Unprobe a given PCIe Hotplug Connection (CN).
	 */
	PCIE_DISABLE_ERRORS(ctrl_p->hc_dip);
	ret = pcie_hp_unprobe(slot_p);

	if (ret != DDI_SUCCESS) {
		PCIE_DBG("pciehpc_slot_unprobe() failed\n");

		/* if power to the slot is still on then set Power led to ON */
		if (slot_p->hs_info.cn_state >= DDI_HP_CN_STATE_POWERED)
			pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED,
			    PCIE_HP_LED_ON);

		PCIE_ENABLE_ERRORS(ctrl_p->hc_dip);

		mutex_exit(&ctrl_p->hc_mutex);
		return (DDI_FAILURE);
	}

	/* get the current state of the slot */
	pciehpc_get_slot_state(slot_p);

	mutex_exit(&ctrl_p->hc_mutex);
	return (DDI_SUCCESS);
}

static int
pciehpc_upgrade_slot_state(pcie_hp_slot_t *slot_p,
    ddi_hp_cn_state_t target_state)
{
	ddi_hp_cn_state_t curr_state;
	int rv = DDI_SUCCESS;
	pcie_hp_ctrl_t *ctrl_p = slot_p->hs_ctrl;

	if (target_state > DDI_HP_CN_STATE_ENABLED) {
		return (DDI_EINVAL);
	}

	curr_state = slot_p->hs_info.cn_state;
	while ((curr_state < target_state) && (rv == DDI_SUCCESS)) {

		switch (curr_state) {
		case DDI_HP_CN_STATE_EMPTY:
			/*
			 * From EMPTY to PRESENT, just check the hardware
			 * slot state.
			 */
			pciehpc_get_slot_state(slot_p);
			curr_state = slot_p->hs_info.cn_state;
			if (curr_state < DDI_HP_CN_STATE_PRESENT)
				rv = DDI_FAILURE;
			break;
		case DDI_HP_CN_STATE_PRESENT:
			if (!ctrl_p->hc_has_pwr) {
				pciehpc_get_slot_state(slot_p);
				curr_state = slot_p->hs_info.cn_state;
				if (curr_state < DDI_HP_CN_STATE_POWERED)
					rv = DDI_FAILURE;
				break;
			}

			rv = (ctrl_p->hc_ops.poweron_hpc_slot)(slot_p,
			    &curr_state);

			break;
		case DDI_HP_CN_STATE_POWERED:
			/*
			 * If we're performing a synchronization, then the
			 * POWERED state isn't quite accurate. Power is enabled,
			 * but we haven't really done all the actual steps that
			 * are expected. As such, we will do another call to
			 * power on and if successful, then do the change to
			 * ENABLED. If the call to power on did not work, then
			 * we must transition back to PRESENT. If there is no
			 * power controller, then this is a no-op.
			 */
			if ((ctrl_p->hc_flags & PCIE_HP_SYNC_RUNNING) != 0 &&
			    ctrl_p->hc_has_pwr) {
				rv = (ctrl_p->hc_ops.poweron_hpc_slot)(slot_p,
				    &curr_state);
				if (rv != DDI_SUCCESS) {
					slot_p->hs_info.cn_state =
					    DDI_HP_CN_STATE_PRESENT;
					break;
				}
			} else if (!ctrl_p->hc_has_pwr) {
				rv = pciehpc_slot_noctrl_active(slot_p,
				    &curr_state);
				if (rv != DDI_SUCCESS)
					break;
			}

			curr_state = slot_p->hs_info.cn_state =
			    DDI_HP_CN_STATE_ENABLED;
			break;
		default:
			/* should never reach here */
			ASSERT("unknown devinfo state");
		}
	}

	return (rv);
}

static int
pciehpc_downgrade_slot_state(pcie_hp_slot_t *slot_p,
    ddi_hp_cn_state_t target_state)
{
	ddi_hp_cn_state_t curr_state;
	int rv = DDI_SUCCESS;


	curr_state = slot_p->hs_info.cn_state;
	while ((curr_state > target_state) && (rv == DDI_SUCCESS)) {

		switch (curr_state) {
		case DDI_HP_CN_STATE_PRESENT:
			/*
			 * From PRESENT to EMPTY, just check hardware slot
			 * state.
			 */
			pciehpc_get_slot_state(slot_p);
			curr_state = slot_p->hs_info.cn_state;
			if (curr_state >= DDI_HP_CN_STATE_PRESENT)
				rv = DDI_FAILURE;
			break;
		case DDI_HP_CN_STATE_POWERED:
			/*
			 * If the device doesn't have power control then we
			 * cannot ask it to power off the slot. However, a
			 * device may have been removed and therefore we need to
			 * manually check if the device was removed by getting
			 * the state. Otherwise we let power control do
			 * everything.
			 */
			if (!slot_p->hs_ctrl->hc_has_pwr) {
				pciehpc_get_slot_state(slot_p);
				curr_state = slot_p->hs_info.cn_state;
				if (curr_state >= DDI_HP_CN_STATE_POWERED)
					rv = DDI_FAILURE;
				break;
			}

			rv = (slot_p->hs_ctrl->hc_ops.poweroff_hpc_slot)(
			    slot_p, &curr_state);

			break;
		case DDI_HP_CN_STATE_ENABLED:
			curr_state = slot_p->hs_info.cn_state =
			    DDI_HP_CN_STATE_POWERED;

			break;
		default:
			/* should never reach here */
			ASSERT("unknown devinfo state");
		}
	}

	return (rv);
}

/* Change slot state to a target state */
static int
pciehpc_change_slot_state(pcie_hp_slot_t *slot_p,
    ddi_hp_cn_state_t target_state)
{
	ddi_hp_cn_state_t curr_state;
	pciehpc_slot_power_t pwr_state;
	boolean_t sync = B_FALSE;
	int rv = 0;

	ASSERT(MUTEX_HELD(&slot_p->hs_ctrl->hc_mutex));

	pciehpc_get_slot_state(slot_p);
	curr_state = slot_p->hs_info.cn_state;
	pwr_state = pciehpc_slot_power_state(slot_p);

	/*
	 * We've been asked to change the slot state. If we still had an
	 * outstanding synchronization task, then we should remove that because
	 * we've had an explicit state change. In essence we take over that sync
	 * and note that it's running.
	 */
	if ((slot_p->hs_ctrl->hc_flags & PCIE_HP_SYNC_PENDING) != 0 &&
	    slot_p->hs_info.cn_state == DDI_HP_CN_STATE_POWERED) {
		sync = B_TRUE;
		slot_p->hs_ctrl->hc_flags |= PCIE_HP_SYNC_RUNNING;
	}
	slot_p->hs_ctrl->hc_flags &= ~PCIE_HP_SYNC_PENDING;

	/*
	 * We need to see whether the power controller state (if there is one)
	 * matches the DDI slot state.  If not, it may be necessary to perform
	 * the upgrade or downgrade procedure even if the DDI slot state matches
	 * the target already.  We'll make sure that curr_state reflects the
	 * state of the power controller with respect to our desired target
	 * state, even if the slot is empty.
	 */
	if (pwr_state == PSP_NO_CONTROLLER)
		goto skip_sync;

	switch (target_state) {
	case DDI_HP_CN_STATE_EMPTY:
	case DDI_HP_CN_STATE_PRESENT:
		/*
		 * Power controller is on but software doesn't know that, and
		 * wants to enter a state in which power should be off.
		 */
		if ((pwr_state & PSP_OFF) == 0 &&
		    curr_state < DDI_HP_CN_STATE_POWERED) {
			curr_state = DDI_HP_CN_STATE_POWERED;
		}
		break;
	case DDI_HP_CN_STATE_POWERED:
	case DDI_HP_CN_STATE_ENABLED:
		/*
		 * Power controller is off but software doesn't know that, and
		 * wants to enter a state in which power should be on.
		 */
		if ((pwr_state & PSP_OFF) != 0 &&
		    curr_state >= DDI_HP_CN_STATE_POWERED) {
			curr_state = DDI_HP_CN_STATE_PRESENT;
		}
		break;
	default:
		break;
	}

	slot_p->hs_info.cn_state = curr_state;

skip_sync:
	if (curr_state == target_state) {
		return (DDI_SUCCESS);
	}

	if (curr_state < target_state) {
		rv = pciehpc_upgrade_slot_state(slot_p, target_state);
	} else {
		rv = pciehpc_downgrade_slot_state(slot_p, target_state);
	}

	if (sync) {
		slot_p->hs_ctrl->hc_flags &= ~PCIE_HP_SYNC_RUNNING;
	}

	return (rv);
}

int
pciehpc_slot_get_property(pcie_hp_slot_t *slot_p, ddi_hp_property_t *arg,
    ddi_hp_property_t *rval)
{
	ddi_hp_property_t request, result;
#ifdef _SYSCALL32_IMPL
	ddi_hp_property32_t request32, result32;
#endif
	pcie_hp_ctrl_t	*ctrl_p = slot_p->hs_ctrl;
	nvlist_t	*prop_list;
	nvlist_t	*prop_rlist; /* nvlist for return values */
	nvpair_t	*prop_pair;
	char		*name, *value;
	int		ret = DDI_SUCCESS;
	int		i, n;
	boolean_t	get_all_prop = B_FALSE;

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyin(arg, &request, sizeof (ddi_hp_property_t)) ||
		    copyin(rval, &result, sizeof (ddi_hp_property_t)))
			return (DDI_FAILURE);
	}
#ifdef _SYSCALL32_IMPL
	else {
		bzero(&request, sizeof (request));
		bzero(&result, sizeof (result));
		if (copyin(arg, &request32, sizeof (ddi_hp_property32_t)) ||
		    copyin(rval, &result32, sizeof (ddi_hp_property32_t)))
			return (DDI_FAILURE);
		request.nvlist_buf = (char *)(uintptr_t)request32.nvlist_buf;
		request.buf_size = request32.buf_size;
		result.nvlist_buf = (char *)(uintptr_t)result32.nvlist_buf;
		result.buf_size = result32.buf_size;
	}
#endif

	if ((ret = pcie_copyin_nvlist(request.nvlist_buf, request.buf_size,
	    &prop_list)) != DDI_SUCCESS)
		return (ret);

	if (nvlist_alloc(&prop_rlist, NV_UNIQUE_NAME, 0)) {
		ret = DDI_ENOMEM;
		goto get_prop_cleanup;
	}

	/* check whether the requested property is "all" or "help" */
	prop_pair = nvlist_next_nvpair(prop_list, NULL);
	if (prop_pair && !nvlist_next_nvpair(prop_list, prop_pair)) {
		name = nvpair_name(prop_pair);
		n = sizeof (pciehpc_props) / sizeof (pciehpc_prop_t);

		if (strcmp(name, PCIEHPC_PROP_ALL) == 0) {
			(void) nvlist_remove_all(prop_list, PCIEHPC_PROP_ALL);

			/*
			 * Add all properties into the request list, so that we
			 * will get the values in the following for loop.
			 */
			for (i = 0; i < n; i++) {
				if (nvlist_add_string(prop_list,
				    pciehpc_props[i].prop_name, "") != 0) {
					ret = DDI_FAILURE;
					goto get_prop_cleanup1;
				}
			}
			get_all_prop = B_TRUE;
		} else if (strcmp(name, PCIEHPC_PROP_HELP) == 0) {
			/*
			 * Empty the request list, and add help strings into the
			 * return list. We will pass the following for loop.
			 */
			(void) nvlist_remove_all(prop_list, PCIEHPC_PROP_HELP);

			for (i = 0; i < n; i++) {
				if (nvlist_add_string(prop_rlist,
				    pciehpc_props[i].prop_name,
				    pciehpc_props[i].prop_value) != 0) {
					ret = DDI_FAILURE;
					goto get_prop_cleanup1;
				}
			}
		}
	}

	mutex_enter(&ctrl_p->hc_mutex);

	/* get the current slot state */
	pciehpc_get_slot_state(slot_p);

	/* for each requested property, get the value and add it to nvlist */
	prop_pair = NULL;
	while ((prop_pair = nvlist_next_nvpair(prop_list, prop_pair)) != NULL) {
		name = nvpair_name(prop_pair);
		value = NULL;

		if (strcmp(name, PCIEHPC_PROP_LED_FAULT) == 0) {
			value = pcie_led_state_text(
			    slot_p->hs_fault_led_state);
		} else if (strcmp(name, PCIEHPC_PROP_LED_POWER) == 0) {
			value = pcie_led_state_text(
			    slot_p->hs_power_led_state);
		} else if (strcmp(name, PCIEHPC_PROP_LED_ATTN) == 0) {
			value = pcie_led_state_text(
			    slot_p->hs_attn_led_state);
		} else if (strcmp(name, PCIEHPC_PROP_LED_ACTIVE) == 0) {
			value = pcie_led_state_text(
			    slot_p->hs_active_led_state);
		} else if (strcmp(name, PCIEHPC_PROP_CARD_TYPE) == 0) {
			ddi_acc_handle_t handle;
			dev_info_t	*cdip;
			uint8_t		prog_class, base_class, sub_class;
			size_t		i;

			mutex_exit(&ctrl_p->hc_mutex);
			cdip = pcie_hp_devi_find(
			    ctrl_p->hc_dip, slot_p->hs_device_num, 0);
			mutex_enter(&ctrl_p->hc_mutex);

			if ((slot_p->hs_info.cn_state
			    != DDI_HP_CN_STATE_ENABLED) || (cdip == NULL)) {
				/*
				 * When getting all properties, just ignore the
				 * one that's not available under certain state.
				 */
				if (get_all_prop)
					continue;

				ret = DDI_ENOTSUP;
				goto get_prop_cleanup2;
			}

			if (pci_config_setup(cdip, &handle) != DDI_SUCCESS) {
				ret = DDI_FAILURE;
				goto get_prop_cleanup2;
			}

			prog_class = pci_config_get8(handle,
			    PCI_CONF_PROGCLASS);
			base_class = pci_config_get8(handle, PCI_CONF_BASCLASS);
			sub_class = pci_config_get8(handle, PCI_CONF_SUBCLASS);
			pci_config_teardown(&handle);

			for (i = 0; i < class_pci_items; i++) {
				if ((base_class == class_pci[i].base_class) &&
				    (sub_class == class_pci[i].sub_class) &&
				    (prog_class == class_pci[i].prog_class)) {
					value = class_pci[i].short_desc;
					break;
				}
			}
			if (i == class_pci_items)
				value = PCIEHPC_PROP_VALUE_UNKNOWN;
		} else if (strcmp(name, PCIEHPC_PROP_BOARD_TYPE) == 0) {
			if (slot_p->hs_info.cn_state <= DDI_HP_CN_STATE_EMPTY)
				value = PCIEHPC_PROP_VALUE_UNKNOWN;
			else
				value = PCIEHPC_PROP_VALUE_PCIHOTPLUG;
		} else if (strcmp(name, PCIEHPC_PROP_SLOT_CONDITION) == 0) {
			value = pcie_slot_condition_text(slot_p->hs_condition);
		} else {
			/* unsupported property */
			PCIE_DBG("Unsupported property: %s\n", name);

			ret = DDI_ENOTSUP;
			goto get_prop_cleanup2;
		}
		if (nvlist_add_string(prop_rlist, name, value) != 0) {
			ret = DDI_FAILURE;
			goto get_prop_cleanup2;
		}
	}

	/* pack nvlist and copyout */
	if ((ret = pcie_copyout_nvlist(prop_rlist, result.nvlist_buf,
	    &result.buf_size)) != DDI_SUCCESS) {
		goto get_prop_cleanup2;
	}
	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyout(&result, rval, sizeof (ddi_hp_property_t)))
			ret = DDI_FAILURE;
	}
#ifdef _SYSCALL32_IMPL
	else {
		if (result.buf_size > UINT32_MAX) {
			ret = DDI_FAILURE;
		} else {
			result32.buf_size = (uint32_t)result.buf_size;
			if (copyout(&result32, rval,
			    sizeof (ddi_hp_property32_t)))
				ret = DDI_FAILURE;
		}
	}
#endif

get_prop_cleanup2:
	mutex_exit(&ctrl_p->hc_mutex);
get_prop_cleanup1:
	nvlist_free(prop_rlist);
get_prop_cleanup:
	nvlist_free(prop_list);
	return (ret);
}

int
pciehpc_slot_set_property(pcie_hp_slot_t *slot_p, ddi_hp_property_t *arg,
    ddi_hp_property_t *rval)
{
	ddi_hp_property_t	request, result;
#ifdef _SYSCALL32_IMPL
	ddi_hp_property32_t	request32, result32;
#endif
	pcie_hp_ctrl_t		*ctrl_p = slot_p->hs_ctrl;
	nvlist_t		*prop_list;
	nvlist_t		*prop_rlist;
	nvpair_t		*prop_pair;
	char			*name, *value;
	pcie_hp_led_state_t	led_state;
	int			ret = DDI_SUCCESS;

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyin(arg, &request, sizeof (ddi_hp_property_t)))
			return (DDI_FAILURE);
		if (rval &&
		    copyin(rval, &result, sizeof (ddi_hp_property_t)))
			return (DDI_FAILURE);
	}
#ifdef _SYSCALL32_IMPL
	else {
		bzero(&request, sizeof (request));
		bzero(&result, sizeof (result));
		if (copyin(arg, &request32, sizeof (ddi_hp_property32_t)))
			return (DDI_FAILURE);
		if (rval &&
		    copyin(rval, &result32, sizeof (ddi_hp_property32_t)))
			return (DDI_FAILURE);
		request.nvlist_buf = (char *)(uintptr_t)request32.nvlist_buf;
		request.buf_size = request32.buf_size;
		if (rval) {
			result.nvlist_buf =
			    (char *)(uintptr_t)result32.nvlist_buf;
			result.buf_size = result32.buf_size;
		}
	}
#endif

	if ((ret = pcie_copyin_nvlist(request.nvlist_buf, request.buf_size,
	    &prop_list)) != DDI_SUCCESS)
		return (ret);

	/* check whether the requested property is "help" */
	prop_pair = nvlist_next_nvpair(prop_list, NULL);
	if (prop_pair && !nvlist_next_nvpair(prop_list, prop_pair) &&
	    (strcmp(nvpair_name(prop_pair), PCIEHPC_PROP_HELP) == 0)) {
		if (!rval) {
			ret = DDI_ENOTSUP;
			goto set_prop_cleanup;
		}

		if (nvlist_alloc(&prop_rlist, NV_UNIQUE_NAME, 0)) {
			ret = DDI_ENOMEM;
			goto set_prop_cleanup;
		}
		if (nvlist_add_string(prop_rlist, PCIEHPC_PROP_LED_ATTN,
		    PCIEHPC_PROP_VALUE_LED) != 0) {
			ret = DDI_FAILURE;
			goto set_prop_cleanup1;
		}

		if ((ret = pcie_copyout_nvlist(prop_rlist, result.nvlist_buf,
		    &result.buf_size)) != DDI_SUCCESS) {
			goto set_prop_cleanup1;
		}
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			if (copyout(&result, rval,
			    sizeof (ddi_hp_property_t))) {
				ret =  DDI_FAILURE;
				goto set_prop_cleanup1;
			}
		}
#ifdef _SYSCALL32_IMPL
		else {
			if (result.buf_size > UINT32_MAX) {
				ret =  DDI_FAILURE;
				goto set_prop_cleanup1;
			} else {
				result32.buf_size = (uint32_t)result.buf_size;
				if (copyout(&result32, rval,
				    sizeof (ddi_hp_property32_t))) {
					ret =  DDI_FAILURE;
					goto set_prop_cleanup1;
				}
			}
		}
#endif
set_prop_cleanup1:
		nvlist_free(prop_rlist);
		nvlist_free(prop_list);
		return (ret);
	}

	/* Validate the request */
	prop_pair = NULL;
	while ((prop_pair = nvlist_next_nvpair(prop_list, prop_pair)) != NULL) {
		name = nvpair_name(prop_pair);
		if (nvpair_type(prop_pair) != DATA_TYPE_STRING) {
			PCIE_DBG("Unexpected data type of setting "
			    "property %s.\n", name);
			ret = DDI_EINVAL;
			goto set_prop_cleanup;
		}
		if (nvpair_value_string(prop_pair, &value)) {
			PCIE_DBG("Get string value failed for property %s.\n",
			    name);
			ret = DDI_FAILURE;
			goto set_prop_cleanup;
		}

		if (strcmp(name, PCIEHPC_PROP_LED_ATTN) == 0) {
			if ((strcmp(value, PCIEHPC_PROP_VALUE_ON) != 0) &&
			    (strcmp(value, PCIEHPC_PROP_VALUE_OFF) != 0) &&
			    (strcmp(value, PCIEHPC_PROP_VALUE_BLINK) != 0)) {
				PCIE_DBG("Unsupported value of setting "
				    "property %s\n", name);
				ret = DDI_ENOTSUP;
				goto set_prop_cleanup;
			}
		} else {
			PCIE_DBG("Unsupported property: %s\n", name);
			ret = DDI_ENOTSUP;
			goto set_prop_cleanup;
		}
	}
	mutex_enter(&ctrl_p->hc_mutex);

	/* get the current slot state */
	pciehpc_get_slot_state(slot_p);

	/* set each property */
	prop_pair = NULL;
	while ((prop_pair = nvlist_next_nvpair(prop_list, prop_pair)) != NULL) {
		name = nvpair_name(prop_pair);

		/*
		 * The validity of the property was checked above.
		 */
		if (strcmp(name, PCIEHPC_PROP_LED_ATTN) == 0) {
			if (strcmp(value, PCIEHPC_PROP_VALUE_ON) == 0)
				led_state = PCIE_HP_LED_ON;
			else if (strcmp(value, PCIEHPC_PROP_VALUE_OFF) == 0)
				led_state = PCIE_HP_LED_OFF;
			else if (strcmp(value, PCIEHPC_PROP_VALUE_BLINK) == 0)
				led_state = PCIE_HP_LED_BLINK;
			else
				continue;

			pciehpc_set_led_state(ctrl_p, PCIE_HP_ATTN_LED,
			    led_state);
		}
	}
	if (rval) {
		if (get_udatamodel() == DATAMODEL_NATIVE) {
			result.buf_size = 0;
			if (copyout(&result, rval, sizeof (ddi_hp_property_t)))
				ret =  DDI_FAILURE;
		}
#ifdef _SYSCALL32_IMPL
		else {
			result32.buf_size = 0;
			if (copyout(&result32, rval,
			    sizeof (ddi_hp_property32_t)))
				ret =  DDI_FAILURE;
		}
#endif
	}

	mutex_exit(&ctrl_p->hc_mutex);
set_prop_cleanup:
	nvlist_free(prop_list);
	return (ret);
}

/*
 * Send a command to the PCI-E Hot Plug Controller.
 *
 * NOTES: The PCI-E spec defines the following semantics for issuing hot plug
 * commands.
 * 1) If Command Complete events/interrupts are supported then software
 *    waits for Command Complete event after issuing a command (i.e writing
 *    to the Slot Control register). The command completion could take as
 *    long as 1 second so software should be prepared to wait for 1 second
 *    before issuing another command.
 *
 * 2) If Command Complete events/interrupts are not supported then
 *    software could issue multiple Slot Control writes without any delay
 *    between writes.
 */
static void
pciehpc_issue_hpc_command(pcie_hp_ctrl_t *ctrl_p, uint16_t control)
{
	pcie_hp_slot_t	*slot_p = ctrl_p->hc_slots[0];
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	status;
	uint32_t	slot_cap;

	/*
	 * PCI-E version 1.1 spec defines No Command Completed
	 * Support bit (bit#18) in Slot Capabilities register. If this
	 * bit is set then slot doesn't support notification of command
	 * completion events.
	 */
	slot_cap =  pciehpc_reg_get32(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCAP);

	/*
	 * If no Command Completion event is supported or it is ACPI
	 * hot plug mode then just issue the command and return.
	 */
	if ((slot_cap & PCIE_SLOTCAP_NO_CMD_COMP_SUPP) ||
	    (bus_p->bus_hp_curr_mode == PCIE_ACPI_HP_MODE)) {
		pciehpc_reg_put16(ctrl_p,
		    bus_p->bus_pcie_off + PCIE_SLOTCTL, control);
		return;
	}

	/*
	 * **************************************
	 * Command Complete events are supported.
	 * **************************************
	 */

	/*
	 * If HPC is not yet initialized then just poll for the Command
	 * Completion interrupt.
	 */
	if (!(ctrl_p->hc_flags & PCIE_HP_INITIALIZED_FLAG)) {
		int retry = PCIE_HP_CMD_WAIT_RETRY;

		/* write the command to the HPC */
		pciehpc_reg_put16(ctrl_p,
		    bus_p->bus_pcie_off + PCIE_SLOTCTL, control);

		/* poll for status completion */
		while (retry--) {
			/* wait for 10 msec before checking the status */
			delay(drv_usectohz(PCIE_HP_CMD_WAIT_TIME));

			status = pciehpc_reg_get16(ctrl_p,
			    bus_p->bus_pcie_off + PCIE_SLOTSTS);

			if (status & PCIE_SLOTSTS_COMMAND_COMPLETED) {
				/* clear the status bits */
				pciehpc_reg_put16(ctrl_p,
				    bus_p->bus_pcie_off + PCIE_SLOTSTS, status);
				break;
			}
		}
		return;
	}

	/* HPC is already initialized */

	ASSERT(MUTEX_HELD(&ctrl_p->hc_mutex));

	/*
	 * If previous command is still pending then wait for its
	 * completion. i.e cv_wait()
	 */

	while (ctrl_p->hc_cmd_pending == B_TRUE)
		cv_wait(&ctrl_p->hc_cmd_comp_cv, &ctrl_p->hc_mutex);

	/*
	 * Issue the command and wait for Command Completion or
	 * the 1 sec timeout.
	 */
	pciehpc_reg_put16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL, control);

	ctrl_p->hc_cmd_pending = B_TRUE;

	if (cv_timedwait(&ctrl_p->hc_cmd_comp_cv, &ctrl_p->hc_mutex,
	    ddi_get_lbolt() + SEC_TO_TICK(1)) == -1) {

		/* it is a timeout */
		PCIE_DBG("pciehpc_issue_hpc_command: Command Complete"
		    " interrupt is not received for slot %d\n",
		    slot_p->hs_phy_slot_num);

		/* clear the status info in case interrupts are disabled? */
		status = pciehpc_reg_get16(ctrl_p,
		    bus_p->bus_pcie_off + PCIE_SLOTSTS);

		if (status & PCIE_SLOTSTS_COMMAND_COMPLETED) {
			/* clear the status bits */
			pciehpc_reg_put16(ctrl_p,
			    bus_p->bus_pcie_off + PCIE_SLOTSTS, status);
		}
	}

	ctrl_p->hc_cmd_pending = B_FALSE;

	/* wake up any one waiting for issuing another command to HPC */
	cv_signal(&ctrl_p->hc_cmd_comp_cv);
}

/*
 * pciehcp_attn_btn_handler()
 *
 * This handles ATTN button pressed event as per the PCI-E 1.1 spec.
 */
static void
pciehpc_attn_btn_handler(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_hp_slot_t		*slot_p = ctrl_p->hc_slots[0];
	pcie_hp_led_state_t	power_led_state;
	callb_cpr_t		cprinfo;

	PCIE_DBG("pciehpc_attn_btn_handler: thread started\n");

	CALLB_CPR_INIT(&cprinfo, &ctrl_p->hc_mutex, callb_generic_cpr,
	    "pciehpc_attn_btn_handler");

	mutex_enter(&ctrl_p->hc_mutex);

	/* wait for ATTN button event */
	cv_wait(&slot_p->hs_attn_btn_cv, &ctrl_p->hc_mutex);

	while (slot_p->hs_attn_btn_thread_exit == B_FALSE) {
		if (slot_p->hs_attn_btn_pending == B_TRUE) {
			/* get the current state of power LED */
			power_led_state = pciehpc_get_led_state(ctrl_p,
			    PCIE_HP_POWER_LED);

			/* Blink the Power LED while we wait for 5 seconds */
			pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED,
			    PCIE_HP_LED_BLINK);

			/* wait for 5 seconds before taking any action */
			if (cv_timedwait(&slot_p->hs_attn_btn_cv,
			    &ctrl_p->hc_mutex,
			    ddi_get_lbolt() + SEC_TO_TICK(5)) == -1) {
				/*
				 * It is a time out; make sure the ATTN pending
				 * flag is still ON before sending the event to
				 * DDI HP framework.
				 */
				if (slot_p->hs_attn_btn_pending == B_TRUE) {
					int hint;

					slot_p->hs_attn_btn_pending = B_FALSE;
					pciehpc_get_slot_state(slot_p);

					if (slot_p->hs_info.cn_state <=
					    DDI_HP_CN_STATE_PRESENT) {
						/*
						 * Insertion.
						 */
						hint = SE_INCOMING_RES;
					} else {
						/*
						 * Want to remove;
						 */
						hint = SE_OUTGOING_RES;
					}

					/*
					 * We can't call ddihp_cn_gen_sysevent
					 * here since it's not a DDI interface.
					 */
					pcie_hp_gen_sysevent_req(
					    slot_p->hs_info.cn_name,
					    hint,
					    ctrl_p->hc_dip,
					    KM_SLEEP);
				}
			}

			/* restore the power LED state */
			pciehpc_set_led_state(ctrl_p, PCIE_HP_POWER_LED,
			    power_led_state);
			continue;
		}

		/* wait for another ATTN button event */
		cv_wait(&slot_p->hs_attn_btn_cv, &ctrl_p->hc_mutex);
	}

	PCIE_DBG("pciehpc_attn_btn_handler: thread exit\n");
	cv_signal(&slot_p->hs_attn_btn_cv);
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
}

/*
 * convert LED state from PCIE HPC definition to pcie_hp_led_state_t
 * definition.
 */
static pcie_hp_led_state_t
pciehpc_led_state_to_hpc(uint16_t state)
{
	switch (state) {
	case PCIE_SLOTCTL_INDICATOR_STATE_ON:
		return (PCIE_HP_LED_ON);
	case PCIE_SLOTCTL_INDICATOR_STATE_BLINK:
		return (PCIE_HP_LED_BLINK);
	case PCIE_SLOTCTL_INDICATOR_STATE_OFF:
	default:
		return (PCIE_HP_LED_OFF);
	}
}

/*
 * Get the state of an LED.
 */
static pcie_hp_led_state_t
pciehpc_get_led_state(pcie_hp_ctrl_t *ctrl_p, pcie_hp_led_t led)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	control, state;

	/* get the current state of Slot Control register */
	control =  pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);

	switch (led) {
	case PCIE_HP_POWER_LED:
		state = pcie_slotctl_pwr_indicator_get(control);
		break;
	case PCIE_HP_ATTN_LED:
		state = pcie_slotctl_attn_indicator_get(control);
		break;
	default:
		PCIE_DBG("pciehpc_get_led_state() invalid LED %d\n", led);
		return (PCIE_HP_LED_OFF);
	}

	switch (state) {
	case PCIE_SLOTCTL_INDICATOR_STATE_ON:
		return (PCIE_HP_LED_ON);

	case PCIE_SLOTCTL_INDICATOR_STATE_BLINK:
		return (PCIE_HP_LED_BLINK);

	case PCIE_SLOTCTL_INDICATOR_STATE_OFF:
	default:
		return (PCIE_HP_LED_OFF);
	}
}

/*
 * Set the state of an LED. It updates both hw and sw state.
 */
static void
pciehpc_set_led_state(pcie_hp_ctrl_t *ctrl_p, pcie_hp_led_t led,
    pcie_hp_led_state_t state)
{
	pcie_hp_slot_t	*slot_p = ctrl_p->hc_slots[0];
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	control, orig_control;

	/* get the current state of Slot Control register */
	orig_control = control =  pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);

	switch (led) {
	case PCIE_HP_POWER_LED:
		/* clear led mask */
		control &= ~PCIE_SLOTCTL_PWR_INDICATOR_MASK;
		slot_p->hs_power_led_state = state;
		break;
	case PCIE_HP_ATTN_LED:
		/* clear led mask */
		control &= ~PCIE_SLOTCTL_ATTN_INDICATOR_MASK;
		slot_p->hs_attn_led_state = state;
		break;
	default:
		PCIE_DBG("pciehpc_set_led_state() invalid LED %d\n", led);
		return;
	}

	switch (state) {
	case PCIE_HP_LED_ON:
		if (led == PCIE_HP_POWER_LED)
			control = pcie_slotctl_pwr_indicator_set(control,
			    PCIE_SLOTCTL_INDICATOR_STATE_ON);
		else if (led == PCIE_HP_ATTN_LED)
			control = pcie_slotctl_attn_indicator_set(control,
			    PCIE_SLOTCTL_INDICATOR_STATE_ON);
		break;
	case PCIE_HP_LED_OFF:
		if (led == PCIE_HP_POWER_LED)
			control = pcie_slotctl_pwr_indicator_set(control,
			    PCIE_SLOTCTL_INDICATOR_STATE_OFF);
		else if (led == PCIE_HP_ATTN_LED)
			control = pcie_slotctl_attn_indicator_set(control,
			    PCIE_SLOTCTL_INDICATOR_STATE_OFF);
		break;
	case PCIE_HP_LED_BLINK:
		if (led == PCIE_HP_POWER_LED)
			control = pcie_slotctl_pwr_indicator_set(control,
			    PCIE_SLOTCTL_INDICATOR_STATE_BLINK);
		else if (led == PCIE_HP_ATTN_LED)
			control = pcie_slotctl_attn_indicator_set(control,
			    PCIE_SLOTCTL_INDICATOR_STATE_BLINK);
		break;

	default:
		PCIE_DBG("pciehpc_set_led_state() invalid LED state %d\n",
		    state);
		return;
	}

	/*
	 * Update hardware if we're actually changing anything here. If things
	 * are instead saying the same (because a user asked us to update state
	 * or we're already in the state we think we should be), then we just
	 * leave it as is.
	 */
	if (control != orig_control) {
		pciehpc_issue_hpc_command(ctrl_p, control);
	}

#ifdef DEBUG
	/* get the current state of Slot Control register */
	control =  pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);

	PCIE_DBG("pciehpc_set_led_state: slot %d power-led %s attn-led %s\n",
	    slot_p->hs_phy_slot_num, pcie_led_state_text(
	    pciehpc_led_state_to_hpc(pcie_slotctl_pwr_indicator_get(control))),
	    pcie_led_state_text(pciehpc_led_state_to_hpc(
	    pcie_slotctl_attn_indicator_get(control))));
#endif
}

static void
pciehpc_handle_power_fault(dev_info_t *dip)
{
	/*
	 * Hold the parent's ref so that it won't disappear when the taskq is
	 * scheduled to run.
	 */
	ndi_hold_devi(dip);

	if (taskq_dispatch(system_taskq, pciehpc_power_fault_handler, dip,
	    TQ_NOSLEEP) == TASKQID_INVALID) {
		ndi_rele_devi(dip);
		PCIE_DBG("pciehpc_intr(): "
		    "Failed to dispatch power fault handler, dip %p\n", dip);
	}
}

static void
pciehpc_power_fault_handler(void *arg)
{
	dev_info_t *dip = (dev_info_t *)arg;
	pcie_hp_ctrl_t  *ctrl_p;
	pcie_hp_slot_t  *slot_p;

	/* get the soft state structure for this dip */
	if ((ctrl_p = PCIE_GET_HP_CTRL(dip)) == NULL) {
		ndi_rele_devi(dip);
		return;
	}
	slot_p = ctrl_p->hc_slots[0];

	/*
	 * Send the event to DDI Hotplug framework, power off
	 * the slot
	 */
	(void) ndi_hp_state_change_req(dip,
	    slot_p->hs_info.cn_name,
	    DDI_HP_CN_STATE_PRESENT, DDI_HP_REQ_SYNC);

	mutex_enter(&ctrl_p->hc_mutex);
	pciehpc_set_led_state(ctrl_p, PCIE_HP_ATTN_LED,
	    PCIE_HP_LED_ON);
	mutex_exit(&ctrl_p->hc_mutex);
	ndi_rele_devi(dip);
}

#ifdef DEBUG
/*
 * Dump PCI-E Hot Plug registers.
 */
static void
pciehpc_dump_hpregs(pcie_hp_ctrl_t *ctrl_p)
{
	pcie_hp_slot_t	*slot_p = ctrl_p->hc_slots[0];
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(ctrl_p->hc_dip);
	uint16_t	control;
	uint32_t	capabilities;

	if (!pcie_debug_flags)
		return;

	capabilities = pciehpc_reg_get32(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCAP);

	control =  pciehpc_reg_get16(ctrl_p,
	    bus_p->bus_pcie_off + PCIE_SLOTCTL);

	PCIE_DBG("pciehpc_dump_hpregs: Found PCI-E hot plug slot %d\n",
	    slot_p->hs_phy_slot_num);

	PCIE_DBG("Attention Button Present = %s\n",
	    capabilities & PCIE_SLOTCAP_ATTN_BUTTON ? "Yes":"No");

	PCIE_DBG("Power controller Present = %s\n",
	    capabilities & PCIE_SLOTCAP_POWER_CONTROLLER ? "Yes":"No");

	PCIE_DBG("MRL Sensor Present	   = %s\n",
	    capabilities & PCIE_SLOTCAP_MRL_SENSOR ? "Yes":"No");

	PCIE_DBG("Attn Indicator Present   = %s\n",
	    capabilities & PCIE_SLOTCAP_ATTN_INDICATOR ? "Yes":"No");

	PCIE_DBG("Power Indicator Present  = %s\n",
	    capabilities & PCIE_SLOTCAP_PWR_INDICATOR ? "Yes":"No");

	PCIE_DBG("HotPlug Surprise	   = %s\n",
	    capabilities & PCIE_SLOTCAP_HP_SURPRISE ? "Yes":"No");

	PCIE_DBG("HotPlug Capable	   = %s\n",
	    capabilities & PCIE_SLOTCAP_HP_CAPABLE ? "Yes":"No");

	PCIE_DBG("Physical Slot Number	   = %d\n",
	    PCIE_SLOTCAP_PHY_SLOT_NUM(capabilities));

	PCIE_DBG("Attn Button interrupt Enabled  = %s\n",
	    control & PCIE_SLOTCTL_ATTN_BTN_EN ? "Yes":"No");

	PCIE_DBG("Power Fault interrupt Enabled  = %s\n",
	    control & PCIE_SLOTCTL_PWR_FAULT_EN ? "Yes":"No");

	PCIE_DBG("MRL Sensor INTR Enabled   = %s\n",
	    control & PCIE_SLOTCTL_MRL_SENSOR_EN ? "Yes":"No");

	PCIE_DBG("Presence interrupt Enabled	 = %s\n",
	    control & PCIE_SLOTCTL_PRESENCE_CHANGE_EN ? "Yes":"No");

	PCIE_DBG("Cmd Complete interrupt Enabled = %s\n",
	    control & PCIE_SLOTCTL_CMD_INTR_EN ? "Yes":"No");

	PCIE_DBG("HotPlug interrupt Enabled	 = %s\n",
	    control & PCIE_SLOTCTL_HP_INTR_EN ? "Yes":"No");

	PCIE_DBG("Power Indicator LED = %s", pcie_led_state_text(
	    pciehpc_led_state_to_hpc(pcie_slotctl_pwr_indicator_get(control))));

	PCIE_DBG("Attn Indicator LED = %s\n",
	    pcie_led_state_text(pciehpc_led_state_to_hpc(
	    pcie_slotctl_attn_indicator_get(control))));
}
#endif	/* DEBUG */
