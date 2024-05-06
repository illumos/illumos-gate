/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Racktop Systems, Inc.
 */

/*
 * This driver targets the LSI/Broadcom/AVAGO Megaraid SAS controllers
 * of the 3rd generation, in particular the models Aero and Ventura.
 *
 * This file contains the interfaces to DDI.
 *
 * Driver attach:
 * --------------
 *
 * For each HBA, the driver will attach three instances. The first will be for
 * the controller, carrying out hardware and driver initialzation, while the
 * remaining two are SCSA instances for the RAID (LD) and physical (PD) iports.
 *
 * Controller Initialization:
 * --------------------------
 *
 * The initialization of the controller hardware is split across multiple
 * functions which are called during lmrc_ctrl_attach():
 * 1. As soon as the device registers are mapped, lmrc_adapter_init() will
 *    be called. This will attempt to bring the firmware to a ready state,
 *    after which control registers are read to fetch basic hardware properties
 *    and calculate the sizes of various data structures used by the driver.
 * 2. After setting up interrupts and initializing mutexes, the expected number
 *    of MFI and MPT commands will be pre-allocated. Then, the I/O controller
 *    will be initialized by sending a IOC INIT command.
 * 3. At this point the driver is able to send commands to the controller and
 *    receive replies. This will first be used to retrieve controller firmware
 *    properties to finish driver setup based on the information received.
 * 4. As part of the remaining firmware configuration, we'll post a set of long-
 *    running commands to keep us informed about RAID map and PD map changes.
 *    These commands will complete asynchronously and will be rescheduled every
 *    time they have completed.
 *
 * While it's not really part of the controller initialization, it is worthwhile
 * to mention here that we send a CTRL SHUTDOWN command to the controller during
 * our quiesce(9e).
 *
 *
 * SCSA HBA Setup:
 * ---------------
 *
 * The driver is written to conform to SCSAv3.
 *
 * The driver will attach two iport(9) instances, one for physical devices that
 * are directly exposed by the HBA to the host, and another for logical devices.
 * The latter category not only includes RAID volumes but also physical disks
 * when the controller is in JBOD mode.
 *
 * The attach function for either iport will enumerate the physical and logical
 * devices, respectively, and populate a tgtmap(9). The driver itself maintains
 * target state state in lmrc_tgt_t. It will attempt to get the SAS WWN of the
 * target and use it as a device address, falling back to the target ID as used
 * by the controller hardware.
 *
 * The array of target states is initialized once during controller attach. The
 * initial portion of each target state contains a back link to the controller
 * soft state and a mutex, neither of which need changing when a new target is
 * discovered or a target disappears. The array of target states is indexed by
 * the target ID as used by the controller hardware. Unused targets will have
 * their target ID set to LMRC_DEVHDL_INVALID.
 *
 *
 * MPT I/O request sending and reply processing:
 * -----------------------------------------
 *
 * The hardware expects to have access to two large areas of DMA memory that the
 * driver will use to send I/O requests and receive replies. The size of these
 * DMA buffers are based on the fixed size of I/O requests and the number of
 * such requests that the controller may accept, and the size of the replies,
 * the queue depth supported by the hardware, and the number interrupt vectors
 * available for this driver.
 *
 * Based on these numbers, the driver will pre-allocate enough MPT and MFI
 * commands to match the size of the I/O request buffer. In addition, each
 * MPT command will have a SGL chain frame and a sense buffer pre-allocated.
 * A set of functions are available to get a initialized command structure to
 * send a request, and to return it to the command list after use.
 *
 * Sending a MPT I/O request to the controller is done by filling out the I/O
 * frame with all the parameters needed for the request and creating a request
 * descriptor, filling in the SMID of the I/O frame used and the queue number
 * where the reply should be posted. The request descriptor is then written
 * into the appropriate device registers.
 *
 * On completion, an interrupt may or may not be posted, depending the I/O
 * request flags and the overall system state, such as whether interrupts are
 * enabled at all. If an interrupt is received, any new replies posted into the
 * queue associated with the interrupt vector are processed and their callbacks,
 * if any, will be called. The hardware will be informed about the last reply
 * index processed by writing the appropriate register.
 *
 * Polled I/O is facilitated by repeatedly checking for the presence of a reply,
 * waiting a short time in between, up to a pre-defined timeout.
 *
 *
 * MFI (MegaRAID Firmware Interface) commands:
 * -------------------------------------------
 *
 * MFI commands are used internally by the driver or by user space via the ioctl
 * interface. Except for the initial IOC INIT command, all MFI commands will be
 * sent using MPT MFI passthru commands. As the driver uses a only small number
 * of MFI commands, each MFI command has a MPT command preallocated.
 *
 * MFI commands can be sent synchronously in "blocked" or "polled" mode, which
 * differ only in the way the driver waits for completion. When sending a
 * "blocked" command, the driver will set a callback and wait for the hardware
 * to return the command through the normal interrupt driven code path. In
 * "polled" mode, the command has a flag set to indicate to the hardware it
 * should not be posted to a reply queue, and the driver repeatedly checks its
 * status until it changes to indicate completion.
 *
 * MFI commands can also be sent asynchronously, in which case they are always
 * completed through the interrupt code path and have a callback. This is used
 * for RAID and PD map updates and Asynchronous Event Notifications (AENs). In
 * all these cases, the commands are usually send to the hardware again after
 * having been completed, avoiding unnecessary reallocation.
 *
 * As asynchronous commands can still be outstanding during detach, they can and
 * will be aborted by sending a MFI ABORT command when the driver is shutting
 * down.
 *
 * Asynchronous Event Notifications:
 * ---------------------------------
 *
 * The driver will always have one AEN request outstanding to receive events
 * from the controller. These events aren't very well documented, but it is
 * known that they include a "locale" describing to which aspect of the HBA
 * they apply, which is either the controller itself, physical devices, or
 * logical devices.
 *
 * Most events will be logged but otherwise ignored by the driver, but some
 * inform us about changes to the physical or logical drives connected to the
 * HBA, in which case we update the respective target map.
 *
 *
 * DMA considerations:
 * -------------------
 *
 * Most of the MPT structures can hold a 64bit physical address for DMA, but
 * some don't. Additionally, the hardware may indicate that it doesn't handle
 * 64bit DMA, even though the structures could hold an address this wide.
 *
 * Consequently, the driver keeps two sets of DMA attributes in its soft state,
 * one decidedly for 32bit DMA and another one for all other uses which could
 * potentially support 64bit DMA. The latter will be modified to fit what the
 * hardware actually supports.
 *
 *
 * Interrupt considerations:
 * -------------------------
 *
 * Unless we're in the unlikely situation that the hardware claims to not
 * actually support it, the driver will prefer to get MSI-X interrupts. If that
 * fails it'll do with MSI interrupts, falling back to FIXED interrupts if that
 * fails as well.
 *
 * The number of queues supported is set to the minimum of what the hardware
 * claims to support, and the number of interrupt vectors we can allocate. It is
 * expected that the hardware will support much more queues and interrupt
 * vectors than what the OS gives us by default.
 *
 *
 * Locking considerations:
 * -----------------------
 *
 * The driver uses several mutexes, rwlocks, and one semaphore to serialize
 * accessess to various parts of its internal state.
 *
 * The semaphore lmrc->l_ioctl_sema is used to limit the amount of MFI commands
 * concurrently in use by user space. This semaphore needs to be decremented by
 * the ioctl code path before any other locks may be acquired.
 *
 * The PD and RAID maps are each protected by a rwlock, lrmc->l_pdmap_lock and
 * lmrc->l_raidmap_lock. Either map is write-locked only when we recieve an
 * updated map from the firmware and copy it over our map, which happens only
 * in the context of the MFI command completion for respective MAP GET INFO
 * with the respective MFI command mutex being held. Read-locking of either map
 * does not require any specific lock ordering.
 *
 * Each lmrc_tgt_t has its own rwlock, tgt->tgt_lock, which is write-locked only
 * during lmrc_tgt_clear(), lmrc_tgt_init(), and lmrc_raid_get_wwn(), all of
 * which run to update our internal target state as the hardware notifies us
 * about a target change. No other locks are held during target state changes.
 * During lmrc_tran_start() and lmrc_task_mgmt(), all other required command and
 * map locks are acquired and released as necessary with the addressed target
 * being read-locked, preventing target state updates while I/O is being done.
 *
 * Each MPT and MFI command has an associated mutex (mpt_lock and mfi_lock,
 * respectively) and condition variable used for synchronization and completion
 * signalling. In general, the mutex should be held while the command is set up
 * until it has been sent to the hardware. The interrupt handler acquires the
 * mutex of each completed command before signalling completion. In case of
 * command abortion, the mutex of a command to be aborted is held to block
 * completion until the ABORT or TASK MGMT command is sent to the hardware to
 * avoid races.
 *
 * To simplify MPT command handling, the function lmrc_get_mpt() used to get a
 * MPT command from the free list always returns the command locked. Mirroring
 * that, lmrc_put_mpt() expects the MPT command to be locked when it is put back
 * on the free list, unlocking it only once it had been linked onto that list.
 *
 * Additionally, each lmrc_tgt_t has an active command list to keep track of all
 * MPT I/O commands send to a target, protected by its own mutex. When iterating
 * the active command list of a target, the mutex protecting this list must be
 * held while the command mutexes are entered and exited. When adding a command
 * to an active command list, the mutex protecting the list is acquired while
 * the command mutex is held. Care must be taken to avoid a deadlock against the
 * iterating functions when removing a command from an active command list: The
 * command mutex must not be held when the mutex protecting the list is entered.
 * Using the functions for active command list management ensures lock ordering.
 */

#include <sys/class.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/dditypes.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/pci.h>
#include <sys/policy.h>
#include <sys/scsi/scsi.h>

#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>

#include "lmrc.h"
#include "lmrc_reg.h"
#include "lmrc_ioctl.h"
#include "lmrc_phys.h"

#define	INST2LSIRDCTL(x)	((x) << INST_MINOR_SHIFT)

void *lmrc_state;

/*
 * Since the max sgl length can vary, we create a per-instance copy of
 * lmrc_dma_attr and fill in .dma_attr_sgllen with the correct value
 * during attach.
 */
static const ddi_dma_attr_t lmrc_dma_attr = {
	.dma_attr_version =		DMA_ATTR_V0,
	.dma_attr_addr_lo =		0x00000000,
	.dma_attr_addr_hi =		0xFFFFFFFFFFFFFFFF,
	.dma_attr_count_max =		0xFFFFFFFF,
	.dma_attr_align =		8,
	.dma_attr_burstsizes =		0x7,
	.dma_attr_minxfer =		1,
	.dma_attr_maxxfer =		0xFFFFFFFF,
	.dma_attr_seg =			0xFFFFFFFF,
	.dma_attr_sgllen =		0,
	.dma_attr_granular =		512,
	.dma_attr_flags =		0,
};

static struct ddi_device_acc_attr lmrc_acc_attr = {
	.devacc_attr_version =		DDI_DEVICE_ATTR_V1,
	.devacc_attr_endian_flags =	DDI_STRUCTURE_LE_ACC,
	.devacc_attr_dataorder =	DDI_STRICTORDER_ACC,
	.devacc_attr_access =		DDI_DEFAULT_ACC,
};

static int lmrc_attach(dev_info_t *, ddi_attach_cmd_t);
static int lmrc_detach(dev_info_t *, ddi_detach_cmd_t);
static int lmrc_ctrl_attach(dev_info_t *);
static int lmrc_ctrl_detach(dev_info_t *);
static int lmrc_cleanup(lmrc_t *, boolean_t);
static lmrc_adapter_class_t lmrc_get_class(lmrc_t *);
static int lmrc_regs_init(lmrc_t *);
static uint_t lmrc_isr(caddr_t, caddr_t);
static int lmrc_add_intrs(lmrc_t *, int);
static int lmrc_intr_init(lmrc_t *);
static void lmrc_intr_fini(lmrc_t *);
static int lmrc_fm_error_cb(dev_info_t *, ddi_fm_error_t *, const void *);
static void lmrc_fm_init(lmrc_t *);
static void lmrc_fm_fini(lmrc_t *);
static int lmrc_alloc_mpt_cmds(lmrc_t *, const size_t);
static void lmrc_free_mpt_cmds(lmrc_t *, const size_t);
static int lmrc_alloc_mfi_cmds(lmrc_t *, const size_t);
static void lmrc_free_mfi_cmds(lmrc_t *, const size_t);

static int
lmrc_ctrl_attach(dev_info_t *dip)
{
	char name[64]; /* large enough fo the taskq name */
	lmrc_t *lmrc;
	uint32_t instance;
	int ret;
	int i;

	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(lmrc_state, instance) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "could not allocate soft state");
		return (DDI_FAILURE);
	}

	lmrc = ddi_get_soft_state(lmrc_state, instance);
	lmrc->l_dip = dip;

	lmrc->l_ctrl_info = kmem_zalloc(sizeof (mfi_ctrl_info_t), KM_SLEEP);
	INITLEVEL_SET(lmrc, LMRC_INITLEVEL_BASIC);

	lmrc->l_class = lmrc_get_class(lmrc);

	if (lmrc->l_class == LMRC_ACLASS_OTHER) {
		dev_err(dip, CE_WARN, "unknown controller class");
		goto fail;
	}

	lmrc->l_acc_attr = lmrc_acc_attr;
	lmrc->l_dma_attr = lmrc_dma_attr;
	lmrc->l_dma_attr_32 = lmrc_dma_attr;

	lmrc_fm_init(lmrc);
	INITLEVEL_SET(lmrc, LMRC_INITLEVEL_FM);

	if (lmrc_regs_init(lmrc) != DDI_SUCCESS)
		goto fail;
	INITLEVEL_SET(lmrc, LMRC_INITLEVEL_REGS);

	if (lmrc_adapter_init(lmrc) != DDI_SUCCESS)
		goto fail;

	lmrc->l_dma_attr_32.dma_attr_addr_hi = 0xFFFFFFFF;

	/* Restrict all DMA to the lower 32bit address space if necessary. */
	if (!lmrc->l_64bit_dma_support)
		lmrc->l_dma_attr.dma_attr_addr_hi = 0xFFFFFFFF;

	if (lmrc_intr_init(lmrc) != DDI_SUCCESS)
		goto fail;
	INITLEVEL_SET(lmrc, LMRC_INITLEVEL_INTR);

	mutex_init(&lmrc->l_mpt_cmd_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(lmrc->l_intr_pri));
	list_create(&lmrc->l_mpt_cmd_list, sizeof (lmrc_mpt_cmd_t),
	    offsetof(lmrc_mpt_cmd_t, mpt_node));

	mutex_init(&lmrc->l_mfi_cmd_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(lmrc->l_intr_pri));
	list_create(&lmrc->l_mfi_cmd_list, sizeof (lmrc_mfi_cmd_t),
	    offsetof(lmrc_mfi_cmd_t, mfi_node));

	mutex_init(&lmrc->l_reg_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(lmrc->l_intr_pri));

	rw_init(&lmrc->l_raidmap_lock, NULL, RW_DRIVER,
	    DDI_INTR_PRI(lmrc->l_intr_pri));
	rw_init(&lmrc->l_pdmap_lock, NULL, RW_DRIVER,
	    DDI_INTR_PRI(lmrc->l_intr_pri));

	sema_init(&lmrc->l_ioctl_sema, LMRC_MAX_IOCTL_CMDS, NULL, SEMA_DRIVER,
	    NULL);

	mutex_init(&lmrc->l_thread_lock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(lmrc->l_intr_pri));
	cv_init(&lmrc->l_thread_cv, NULL, CV_DRIVER, NULL);


	for (i = 0; i < ARRAY_SIZE(lmrc->l_targets); i++) {
		lmrc_tgt_t *tgt = &lmrc->l_targets[i];

		rw_init(&tgt->tgt_lock, NULL, RW_DRIVER,
		    DDI_INTR_PRI(lmrc->l_intr_pri));
		mutex_init(&tgt->tgt_mpt_active_lock, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(lmrc->l_intr_pri));
		list_create(&tgt->tgt_mpt_active, sizeof (lmrc_mpt_cmd_t),
		    offsetof(lmrc_mpt_cmd_t, mpt_node));
		tgt->tgt_lmrc = lmrc;
		tgt->tgt_dev_id = LMRC_DEVHDL_INVALID;
	}

	INITLEVEL_SET(lmrc, LMRC_INITLEVEL_SYNC);

	if (lmrc_alloc_mpt_cmds(lmrc, lmrc->l_max_fw_cmds) != DDI_SUCCESS)
		goto fail;
	INITLEVEL_SET(lmrc, LMRC_INITLEVEL_MPTCMDS);

	if (lmrc_alloc_mfi_cmds(lmrc, LMRC_MAX_MFI_CMDS) != DDI_SUCCESS)
		goto fail;
	INITLEVEL_SET(lmrc, LMRC_INITLEVEL_MFICMDS);

	lmrc->l_thread = thread_create(NULL, 0, lmrc_thread, lmrc, 0, &p0,
	    TS_RUN, minclsyspri);
	INITLEVEL_SET(lmrc, LMRC_INITLEVEL_THREAD);

	if (lmrc_ioc_init(lmrc) != DDI_SUCCESS)
		goto fail;

	lmrc_enable_intr(lmrc);

	if (lmrc_fw_init(lmrc) != DDI_SUCCESS)
		goto fail;
	INITLEVEL_SET(lmrc, LMRC_INITLEVEL_FW);

	if (lmrc_hba_attach(lmrc) != DDI_SUCCESS)
		goto fail;
	INITLEVEL_SET(lmrc, LMRC_INITLEVEL_HBA);

	(void) snprintf(lmrc->l_iocname, sizeof (lmrc->l_iocname),
	    "%d:lsirdctl", instance);
	if (ddi_create_minor_node(dip, lmrc->l_iocname, S_IFCHR,
	    INST2LSIRDCTL(instance), DDI_PSEUDO, 0) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to create ioctl node.");
		goto fail;
	}
	INITLEVEL_SET(lmrc, LMRC_INITLEVEL_NODE);

	(void) snprintf(name, sizeof (name), "%s%d_taskq",
	    ddi_driver_name(dip), ddi_get_instance(dip));

	lmrc->l_taskq = taskq_create(name, lmrc->l_max_reply_queues,
	    minclsyspri, 64, INT_MAX, TASKQ_PREPOPULATE);
	if (lmrc->l_taskq == NULL) {
		dev_err(dip, CE_WARN, "failed to create taskq.");
		goto fail;
	}
	INITLEVEL_SET(lmrc, LMRC_INITLEVEL_TASKQ);

	if (lmrc_start_aen(lmrc) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "failed to initiate AEN.");
		goto fail;
	}
	INITLEVEL_SET(lmrc, LMRC_INITLEVEL_AEN);

	ddi_report_dev(dip);

	if (lmrc_check_acc_handle(lmrc->l_reghandle) != DDI_SUCCESS) {
		lmrc_fm_ereport(lmrc, DDI_FM_DEVICE_NO_RESPONSE);
		ddi_fm_service_impact(lmrc->l_dip, DDI_SERVICE_LOST);
	}

	return (DDI_SUCCESS);

fail:
	ret = lmrc_cleanup(lmrc, B_TRUE);
	VERIFY3U(ret, ==, DDI_SUCCESS);

	return (DDI_FAILURE);
}

static int
lmrc_ctrl_detach(dev_info_t *dip)
{
	lmrc_t *lmrc = ddi_get_soft_state(lmrc_state, ddi_get_instance(dip));
	VERIFY(lmrc != NULL);

	return (lmrc_cleanup(lmrc, B_FALSE));
}

static int
lmrc_cleanup(lmrc_t *lmrc, boolean_t failed)
{
	int i, ret;

	if (lmrc->l_raid_dip != NULL || lmrc->l_phys_dip != NULL)
		return (DDI_FAILURE);

	/*
	 * Before doing anything else, abort any outstanding commands.
	 * The first commands are issued during FW initialisation, so check
	 * that we're past this point.
	 */
	if (INITLEVEL_ACTIVE(lmrc, LMRC_INITLEVEL_FW)) {
		ret = lmrc_abort_outstanding_mfi(lmrc, LMRC_MAX_MFI_CMDS);
		lmrc_disable_intr(lmrc);
		if (ret != DDI_SUCCESS)
			return (ret);
	}

	if (INITLEVEL_ACTIVE(lmrc, LMRC_INITLEVEL_AEN)) {
		/* The AEN command was aborted above already. */
		INITLEVEL_CLEAR(lmrc, LMRC_INITLEVEL_AEN);
	}

	if (INITLEVEL_ACTIVE(lmrc, LMRC_INITLEVEL_TASKQ)) {
		taskq_destroy(lmrc->l_taskq);
		INITLEVEL_CLEAR(lmrc, LMRC_INITLEVEL_TASKQ);
	}

	if (INITLEVEL_ACTIVE(lmrc, LMRC_INITLEVEL_NODE)) {
		ddi_remove_minor_node(lmrc->l_dip, lmrc->l_iocname);
		INITLEVEL_CLEAR(lmrc, LMRC_INITLEVEL_NODE);
	}

	if (INITLEVEL_ACTIVE(lmrc, LMRC_INITLEVEL_HBA)) {
		(void) lmrc_hba_detach(lmrc);
		INITLEVEL_CLEAR(lmrc, LMRC_INITLEVEL_HBA);
	}


	if (INITLEVEL_ACTIVE(lmrc, LMRC_INITLEVEL_FW)) {
		lmrc_free_pdmap(lmrc);
		lmrc_free_raidmap(lmrc);
		INITLEVEL_CLEAR(lmrc, LMRC_INITLEVEL_FW);
	}

	if (INITLEVEL_ACTIVE(lmrc, LMRC_INITLEVEL_THREAD)) {
		mutex_enter(&lmrc->l_thread_lock);
		lmrc->l_thread_stop = B_TRUE;
		cv_signal(&lmrc->l_thread_cv);
		mutex_exit(&lmrc->l_thread_lock);
		thread_join(lmrc->l_thread->t_did);
		INITLEVEL_CLEAR(lmrc, LMRC_INITLEVEL_THREAD);
	}

	if (INITLEVEL_ACTIVE(lmrc, LMRC_INITLEVEL_MFICMDS)) {
		lmrc_free_mfi_cmds(lmrc, LMRC_MAX_MFI_CMDS);
		INITLEVEL_CLEAR(lmrc, LMRC_INITLEVEL_MFICMDS);
	}

	if (INITLEVEL_ACTIVE(lmrc, LMRC_INITLEVEL_MPTCMDS)) {
		lmrc_free_mpt_cmds(lmrc, lmrc->l_max_fw_cmds);
		INITLEVEL_CLEAR(lmrc, LMRC_INITLEVEL_MPTCMDS);
	}

	if (INITLEVEL_ACTIVE(lmrc, LMRC_INITLEVEL_SYNC)) {
		for (i = 0; i < ARRAY_SIZE(lmrc->l_targets); i++) {
			lmrc_tgt_t *tgt = &lmrc->l_targets[i];

			list_destroy(&tgt->tgt_mpt_active);
			mutex_destroy(&tgt->tgt_mpt_active_lock);
			rw_destroy(&tgt->tgt_lock);
		}

		mutex_destroy(&lmrc->l_thread_lock);
		cv_destroy(&lmrc->l_thread_cv);

		sema_destroy(&lmrc->l_ioctl_sema);

		mutex_destroy(&lmrc->l_mfi_cmd_lock);
		list_destroy(&lmrc->l_mfi_cmd_list);

		mutex_destroy(&lmrc->l_mpt_cmd_lock);
		list_destroy(&lmrc->l_mpt_cmd_list);

		rw_destroy(&lmrc->l_pdmap_lock);
		rw_destroy(&lmrc->l_raidmap_lock);
		mutex_destroy(&lmrc->l_reg_lock);
		INITLEVEL_CLEAR(lmrc, LMRC_INITLEVEL_SYNC);
	}

	if (INITLEVEL_ACTIVE(lmrc, LMRC_INITLEVEL_INTR)) {
		lmrc_intr_fini(lmrc);
		INITLEVEL_CLEAR(lmrc, LMRC_INITLEVEL_INTR);
	}

	if (INITLEVEL_ACTIVE(lmrc, LMRC_INITLEVEL_REGS)) {
		ddi_regs_map_free(&lmrc->l_reghandle);
		lmrc->l_regmap = NULL;
		INITLEVEL_CLEAR(lmrc, LMRC_INITLEVEL_REGS);
	}

	if (INITLEVEL_ACTIVE(lmrc, LMRC_INITLEVEL_FM)) {
		lmrc_fm_fini(lmrc);
		INITLEVEL_CLEAR(lmrc, LMRC_INITLEVEL_FM);
	}

	if (INITLEVEL_ACTIVE(lmrc, LMRC_INITLEVEL_BASIC)) {
		kmem_free(lmrc->l_ctrl_info, sizeof (mfi_ctrl_info_t));
		INITLEVEL_CLEAR(lmrc, LMRC_INITLEVEL_BASIC);
	}

	VERIFY0(lmrc->l_init_level);
	ddi_soft_state_free(lmrc_state, ddi_get_instance(lmrc->l_dip));

	return (DDI_SUCCESS);
}

static int
lmrc_regs_init(lmrc_t *lmrc)
{
	uint_t regno;
	off_t regsize;

	switch (lmrc->l_class) {
	case LMRC_ACLASS_VENTURA:
	case LMRC_ACLASS_AERO:
		regno = 1;
		break;
	default:
		regno = 2;
		break;
	}

	if (ddi_dev_regsize(lmrc->l_dip, regno, &regsize) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (regsize < LMRC_MFI_MIN_MEM) {
		dev_err(lmrc->l_dip, CE_WARN, "reg %d size (%ld) is too small",
		    regno, regsize);
		return (DDI_FAILURE);
	}

	if (ddi_regs_map_setup(lmrc->l_dip, regno, &lmrc->l_regmap, 0, 0,
	    &lmrc->l_acc_attr, &lmrc->l_reghandle)
	    != DDI_SUCCESS) {
		dev_err(lmrc->l_dip, CE_WARN,
		    "unable to map control registers");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static uint_t
lmrc_isr(caddr_t arg1, caddr_t arg2)
{
	lmrc_t *lmrc = (lmrc_t *)arg1;
	int queue = (int)(uintptr_t)arg2;
	uint_t ret = DDI_INTR_UNCLAIMED;

	if (lmrc->l_intr_type == DDI_INTR_TYPE_FIXED) {
		ret = lmrc_intr_ack(lmrc);
		if (ret != DDI_INTR_CLAIMED)
			return (ret);
	}

	ret = lmrc_process_replies(lmrc, queue);
	return (ret);
}

static int
lmrc_add_intrs(lmrc_t *lmrc, int intr_type)
{
	int navail, nintrs, count;
	int ret;
	int i;

	if (lmrc->l_intr_types == 0) {
		ret = ddi_intr_get_supported_types(lmrc->l_dip,
		    &lmrc->l_intr_types);
		if (ret != DDI_SUCCESS) {
			dev_err(lmrc->l_dip, CE_WARN,
			    "!%s: ddi_intr_get_supported_types failed",
			    __func__);
			return (ret);
		}
	}

	if ((lmrc->l_intr_types & intr_type) == 0)
		return (DDI_FAILURE);

	/* Don't use MSI-X if the firmware doesn't support it. */
	if (intr_type == DDI_INTR_TYPE_MSIX && !lmrc->l_fw_msix_enabled)
		return (DDI_FAILURE);

	ret = ddi_intr_get_nintrs(lmrc->l_dip, intr_type, &nintrs);
	if (ret != DDI_SUCCESS) {
		dev_err(lmrc->l_dip, CE_WARN,
		    "!%s: ddi_intr_get_nintrs failed", __func__);
		return (ret);
	}

	ret = ddi_intr_get_navail(lmrc->l_dip, intr_type, &navail);
	if (ret != DDI_SUCCESS) {
		dev_err(lmrc->l_dip, CE_WARN,
		    "!%s: ddi_intr_get_navail failed", __func__);
		return (ret);
	}

	/*
	 * There's no point in having more interrupts than queues supported by
	 * the hardware.
	 */
	if (navail > lmrc->l_max_reply_queues)
		navail = lmrc->l_max_reply_queues;

	lmrc->l_intr_htable_size = navail * sizeof (ddi_intr_handle_t);
	lmrc->l_intr_htable = kmem_zalloc(lmrc->l_intr_htable_size, KM_SLEEP);

	ret = ddi_intr_alloc(lmrc->l_dip, lmrc->l_intr_htable, intr_type, 0,
	    navail, &count, DDI_INTR_ALLOC_NORMAL);
	if (ret != DDI_SUCCESS) {
		dev_err(lmrc->l_dip, CE_WARN, "!%s: ddi_intr_alloc failed",
		    __func__);
		goto fail;
	}

	if (count < navail) {
		dev_err(lmrc->l_dip, CE_CONT,
		    "?requested %d interrupts, received %d\n", navail, count);
	}

	lmrc->l_intr_count = count;

	ret = ddi_intr_get_pri(lmrc->l_intr_htable[0], &lmrc->l_intr_pri);
	if (ret != DDI_SUCCESS) {
		dev_err(lmrc->l_dip, CE_WARN, "!%s: ddi_intr_get_pri failed",
		    __func__);
		goto fail;
	}

	if (lmrc->l_intr_pri >= ddi_intr_get_hilevel_pri()) {
		dev_err(lmrc->l_dip, CE_WARN,
		    "high level interrupts not supported");
		goto fail;
	}

	for (i = 0; i < lmrc->l_intr_count; i++) {
		ret = ddi_intr_add_handler(lmrc->l_intr_htable[i], lmrc_isr,
		    (caddr_t)lmrc, (caddr_t)(uintptr_t)i);
		if (ret != DDI_SUCCESS) {
			dev_err(lmrc->l_dip, CE_WARN,
			    "!%s: ddi_intr_add_handler failed", __func__);
			goto fail;
		}
	}

	ret = ddi_intr_get_cap(lmrc->l_intr_htable[0], &lmrc->l_intr_cap);
	if (ret != DDI_SUCCESS) {
		dev_err(lmrc->l_dip, CE_WARN,
		    "!%s: ddi_intr_get_cap failed", __func__);
		goto fail;
	}

	if ((lmrc->l_intr_cap & DDI_INTR_FLAG_BLOCK) != 0) {
		ret = ddi_intr_block_enable(lmrc->l_intr_htable, count);
		if (ret != DDI_SUCCESS) {
			dev_err(lmrc->l_dip, CE_WARN,
			    "!%s: ddi_intr_block_enable failed", __func__);
			goto fail;
		}
	} else {
		for (i = 0; i < lmrc->l_intr_count; i++) {
			ret = ddi_intr_enable(lmrc->l_intr_htable[i]);
			if (ret != DDI_SUCCESS) {
				dev_err(lmrc->l_dip, CE_WARN,
				    "!%s: ddi_entr_enable failed", __func__);
				goto fail;
			}
		}
	}

	lmrc->l_intr_type = intr_type;
	return (DDI_SUCCESS);

fail:
	lmrc_intr_fini(lmrc);
	return (ret);
}

static int
lmrc_intr_init(lmrc_t *lmrc)
{
	int ret;

	lmrc_disable_intr(lmrc);

	if ((lmrc_add_intrs(lmrc, DDI_INTR_TYPE_MSIX) != DDI_SUCCESS) &&
	    (lmrc_add_intrs(lmrc, DDI_INTR_TYPE_MSI) != DDI_SUCCESS) &&
	    (lmrc_add_intrs(lmrc, DDI_INTR_TYPE_FIXED) != DDI_SUCCESS)) {
		dev_err(lmrc->l_dip, CE_WARN, "failed to set up interrupts");
		return (DDI_FAILURE);
	}

	dev_err(lmrc->l_dip, CE_NOTE, "!got %d %s interrupts",
	    lmrc->l_intr_count,
	    lmrc->l_intr_type == DDI_INTR_TYPE_MSIX ? "MSI-X" :
	    lmrc->l_intr_type == DDI_INTR_TYPE_MSI ? "MSI" : "FIXED");

	/* Don't use more queues than we got interrupts for. */
	if (lmrc->l_max_reply_queues > lmrc->l_intr_count)
		lmrc->l_max_reply_queues = lmrc->l_intr_count;

	lmrc->l_last_reply_idx =
	    kmem_zalloc(sizeof (uint16_t) * lmrc->l_max_reply_queues, KM_SLEEP);

	/*
	 * While here, allocate the reply descriptor DMA memory and the array
	 * keeping the last reply index for each queue. Each queue will have
	 * space for reply_q_depth MPI2 descriptors (reply_alloc_sz).
	 */
	ret = lmrc_dma_alloc(lmrc, lmrc->l_dma_attr, &lmrc->l_reply_dma,
	    lmrc->l_reply_alloc_sz * lmrc->l_max_reply_queues, 16,
	    DDI_DMA_CONSISTENT);
	if (ret != DDI_SUCCESS) {
		lmrc_intr_fini(lmrc);
		return (ret);
	}
	memset(lmrc->l_reply_dma.ld_buf, -1, lmrc->l_reply_dma.ld_len);

	return (DDI_SUCCESS);
}

static void
lmrc_intr_fini(lmrc_t *lmrc)
{
	uint_t i;

	if (lmrc->l_intr_htable[0] == NULL)
		return;

	if ((lmrc->l_intr_cap & DDI_INTR_FLAG_BLOCK) != 0) {
		(void) ddi_intr_block_disable(lmrc->l_intr_htable,
		    lmrc->l_intr_count);
	}

	for (i = 0; i < lmrc->l_intr_count; i++) {
		if (lmrc->l_intr_htable[i] == NULL)
			break;

		if ((lmrc->l_intr_cap & DDI_INTR_FLAG_BLOCK) == 0)
			(void) ddi_intr_disable(lmrc->l_intr_htable[i]);
		(void) ddi_intr_remove_handler(lmrc->l_intr_htable[i]);
		(void) ddi_intr_free(lmrc->l_intr_htable[i]);
	}

	if (lmrc->l_intr_htable != NULL)
		kmem_free(lmrc->l_intr_htable, lmrc->l_intr_htable_size);

	lmrc->l_intr_htable = NULL;
	lmrc->l_intr_htable_size = 0;

	if (lmrc->l_last_reply_idx != NULL)
		kmem_free(lmrc->l_last_reply_idx,
		    sizeof (uint16_t) * lmrc->l_max_reply_queues);

	lmrc_dma_free(&lmrc->l_reply_dma);
}

static int
lmrc_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err_status,
    const void *arg)
{
	pci_ereport_post(dip, err_status, NULL);
	return (err_status->fme_status);
}

static void
lmrc_fm_init(lmrc_t *lmrc)
{
	ddi_iblock_cookie_t fm_ibc;

	lmrc->l_fm_capabilities = ddi_prop_get_int(DDI_DEV_T_ANY,
	    lmrc->l_dip, DDI_PROP_DONTPASS, "fm-capable",
	    DDI_FM_EREPORT_CAPABLE | DDI_FM_ACCCHK_CAPABLE |
	    DDI_FM_DMACHK_CAPABLE | DDI_FM_ERRCB_CAPABLE);

	if (lmrc->l_fm_capabilities == 0)
		return;

	lmrc->l_dma_attr.dma_attr_flags = DDI_DMA_FLAGERR;
	lmrc->l_dma_attr_32.dma_attr_flags = DDI_DMA_FLAGERR;
	lmrc->l_acc_attr.devacc_attr_access = DDI_FLAGERR_ACC;

	ddi_fm_init(lmrc->l_dip, &lmrc->l_fm_capabilities, &fm_ibc);

	if (DDI_FM_EREPORT_CAP(lmrc->l_fm_capabilities) ||
	    DDI_FM_ERRCB_CAP(lmrc->l_fm_capabilities)) {
		pci_ereport_setup(lmrc->l_dip);
	}

	if (DDI_FM_ERRCB_CAP(lmrc->l_fm_capabilities)) {
		ddi_fm_handler_register(lmrc->l_dip, lmrc_fm_error_cb,
		    lmrc);
	}
}

static void
lmrc_fm_fini(lmrc_t *lmrc)
{
	if (lmrc->l_fm_capabilities == 0)
		return;

	if (DDI_FM_ERRCB_CAP(lmrc->l_fm_capabilities))
		ddi_fm_handler_unregister(lmrc->l_dip);

	if (DDI_FM_EREPORT_CAP(lmrc->l_fm_capabilities) ||
	    DDI_FM_ERRCB_CAP(lmrc->l_fm_capabilities)) {
		pci_ereport_teardown(lmrc->l_dip);
	}

	ddi_fm_fini(lmrc->l_dip);
}

void
lmrc_fm_ereport(lmrc_t *lmrc, const char *detail)
{
	uint64_t ena;
	char buf[FM_MAX_CLASS];

	(void) snprintf(buf, sizeof (buf), "%s.%s", DDI_FM_DEVICE, detail);
	ena = fm_ena_generate(0, FM_ENA_FMT1);
	if (DDI_FM_EREPORT_CAP(lmrc->l_fm_capabilities)) {
		ddi_fm_ereport_post(lmrc->l_dip, buf, ena, DDI_NOSLEEP,
		    FM_VERSION, DATA_TYPE_UINT8, FM_EREPORT_VERSION, NULL);
	}
}

int
lmrc_check_acc_handle(ddi_acc_handle_t h)
{
	ddi_fm_error_t de;

	if (h == NULL)
		return (DDI_FAILURE);

	ddi_fm_acc_err_get(h, &de, DDI_FME_VERSION);
	return (de.fme_status);
}

int
lmrc_check_dma_handle(ddi_dma_handle_t h)
{
	ddi_fm_error_t de;

	if (h == NULL)
		return (DDI_FAILURE);

	ddi_fm_dma_err_get(h, &de, DDI_FME_VERSION);
	return (de.fme_status);
}

static int
lmrc_alloc_mpt_cmds(lmrc_t *lmrc, const size_t ncmd)
{
	lmrc_mpt_cmd_t **cmds;
	lmrc_mpt_cmd_t *cmd;
	uint32_t i;
	int ret;

	/*
	 * The hardware expects to find MPI I/O request frames in a big chunk
	 * of DMA memory, indexed by the MPT cmd SMID.
	 */
	ret = lmrc_dma_alloc(lmrc, lmrc->l_dma_attr, &lmrc->l_ioreq_dma,
	    lmrc->l_io_frames_alloc_sz, 256, DDI_DMA_CONSISTENT);
	if (ret != DDI_SUCCESS)
		return (ret);

	cmds = kmem_zalloc(ncmd * sizeof (lmrc_mpt_cmd_t *), KM_SLEEP);
	for (i = 0; i < ncmd; i++) {
		cmd = kmem_zalloc(sizeof (lmrc_mpt_cmd_t), KM_SLEEP);

		/* XXX: allocate on demand in tran_start / build_sgl? */
		ret = lmrc_dma_alloc(lmrc, lmrc->l_dma_attr,
		    &cmd->mpt_chain_dma, lmrc->l_max_chain_frame_sz, 4,
		    DDI_DMA_CONSISTENT);
		if (ret != DDI_SUCCESS)
			goto fail;

		cmd->mpt_chain = cmd->mpt_chain_dma.ld_buf;

		/*
		 * We request a few bytes more for sense so that we can fit our
		 * arq struct before the actual sense data. We must make sure to
		 * put sts_sensedata at a 64 byte aligned address.
		 */
		ret = lmrc_dma_alloc(lmrc, lmrc->l_dma_attr_32,
		    &cmd->mpt_sense_dma, LMRC_SENSE_LEN + P2ROUNDUP(
		    offsetof(struct scsi_arq_status, sts_sensedata), 64), 64,
		    DDI_DMA_CONSISTENT);
		if (ret != DDI_SUCCESS)
			goto fail;

		/*
		 * Now that we have a sufficiently sized and 64 byte aligned DMA
		 * buffer for sense, calculate mpt_sense so that it points at a
		 * struct scsi_arq_status somewhere within the first 64 bytes in
		 * the DMA buffer, making sure its sts_sensedata is aligned at
		 * 64 bytes as well.
		 */
		cmd->mpt_sense = cmd->mpt_sense_dma.ld_buf + 64 -
		    offsetof(struct scsi_arq_status, sts_sensedata);
		VERIFY(IS_P2ALIGNED(&(((struct scsi_arq_status *)cmd->mpt_sense)
		    ->sts_sensedata), 64));

		cmd->mpt_smid = i + 1;

		/*
		 * Calculate address of this commands I/O frame within the DMA
		 * memory allocated earlier.
		 */
		cmd->mpt_io_frame =
		    LMRC_MPI2_RAID_DEFAULT_IO_FRAME_SIZE * cmd->mpt_smid +
		    lmrc->l_ioreq_dma.ld_buf;

		cmd->mpt_lmrc = lmrc;

		mutex_init(&cmd->mpt_lock, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(lmrc->l_intr_pri));

		cmds[i] = cmd;
		list_insert_tail(&lmrc->l_mpt_cmd_list, cmd);
	}

	lmrc->l_mpt_cmds = cmds;
	return (DDI_SUCCESS);

fail:
	if (cmd->mpt_chain != NULL)
		lmrc_dma_free(&cmd->mpt_chain_dma);
	kmem_free(cmd, sizeof (lmrc_mpt_cmd_t));

	lmrc_free_mpt_cmds(lmrc, ncmd);

	return (ret);
}

static void
lmrc_free_mpt_cmds(lmrc_t *lmrc, const size_t ncmd)
{
	lmrc_mpt_cmd_t *cmd;
	size_t count = 0;

	for (cmd = list_remove_head(&lmrc->l_mpt_cmd_list);
	    cmd != NULL;
	    cmd = list_remove_head(&lmrc->l_mpt_cmd_list)) {
		lmrc_dma_free(&cmd->mpt_chain_dma);
		lmrc_dma_free(&cmd->mpt_sense_dma);
		mutex_destroy(&cmd->mpt_lock);
		kmem_free(cmd, sizeof (lmrc_mpt_cmd_t));
		count++;
	}
	VERIFY3U(count, ==, ncmd);
	VERIFY(list_is_empty(&lmrc->l_mpt_cmd_list));

	kmem_free(lmrc->l_mpt_cmds, ncmd * sizeof (lmrc_mpt_cmd_t *));

	lmrc_dma_free(&lmrc->l_ioreq_dma);
}

static int
lmrc_alloc_mfi_cmds(lmrc_t *lmrc, const size_t ncmd)
{
	int ret = DDI_SUCCESS;
	lmrc_mfi_cmd_t **cmds;
	lmrc_mfi_cmd_t *mfi;
	uint32_t i;

	cmds = kmem_zalloc(ncmd * sizeof (lmrc_mfi_cmd_t *), KM_SLEEP);
	for (i = 0; i < ncmd; i++) {
		mfi = kmem_zalloc(sizeof (lmrc_mfi_cmd_t), KM_SLEEP);
		ret = lmrc_dma_alloc(lmrc, lmrc->l_dma_attr,
		    &mfi->mfi_frame_dma, sizeof (mfi_frame_t), 256,
		    DDI_DMA_CONSISTENT);
		if (ret != DDI_SUCCESS)
			goto fail;

		mfi->mfi_lmrc = lmrc;
		mfi->mfi_frame = mfi->mfi_frame_dma.ld_buf;
		mfi->mfi_idx = i;

		if (lmrc_build_mptmfi_passthru(lmrc, mfi) != DDI_SUCCESS) {
			lmrc_dma_free(&mfi->mfi_frame_dma);
			goto fail;
		}

		mutex_init(&mfi->mfi_lock, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(lmrc->l_intr_pri));

		cmds[i] = mfi;
		list_insert_tail(&lmrc->l_mfi_cmd_list, mfi);
	}

	lmrc->l_mfi_cmds = cmds;
	return (DDI_SUCCESS);

fail:
	kmem_free(mfi, sizeof (lmrc_mfi_cmd_t));
	lmrc_free_mfi_cmds(lmrc, ncmd);

	return (ret);
}

static void
lmrc_free_mfi_cmds(lmrc_t *lmrc, const size_t ncmd)
{
	lmrc_mfi_cmd_t *mfi;
	size_t count = 0;

	for (mfi = list_remove_head(&lmrc->l_mfi_cmd_list);
	    mfi != NULL;
	    mfi = list_remove_head(&lmrc->l_mfi_cmd_list)) {
		ASSERT(lmrc->l_mfi_cmds[mfi->mfi_idx] == mfi);
		lmrc->l_mfi_cmds[mfi->mfi_idx] = NULL;

		/*
		 * lmrc_put_mpt() requires the command to be locked, unlocking
		 * after it has been put back on the free list.
		 */
		mutex_enter(&mfi->mfi_mpt->mpt_lock);
		lmrc_put_mpt(mfi->mfi_mpt);

		lmrc_dma_free(&mfi->mfi_frame_dma);
		mutex_destroy(&mfi->mfi_lock);
		kmem_free(mfi, sizeof (lmrc_mfi_cmd_t));
		count++;
	}
	VERIFY3U(count, ==, ncmd);
	VERIFY(list_is_empty(&lmrc->l_mfi_cmd_list));

	kmem_free(lmrc->l_mfi_cmds, ncmd * sizeof (lmrc_mfi_cmd_t *));
}


void
lmrc_dma_build_sgl(lmrc_t *lmrc, lmrc_mpt_cmd_t *mpt,
    const ddi_dma_cookie_t *cookie, uint_t ncookies)
{
	Mpi25SCSIIORequest_t *io_req = mpt->mpt_io_frame;
	Mpi25IeeeSgeChain64_t *sgl_ptr = &io_req->SGL.IeeeChain;
	uint_t nsge, max_sge;
	uint_t i;

	ASSERT(ncookies > 0);

	/* Start with the 8 SGEs in the I/O frame. */
	max_sge = lmrc->l_max_sge_in_main_msg;

	for (;;) {
		nsge = min(ncookies, max_sge);

		for (i = 0; i < nsge; i++, cookie++) {
			*(uint64_t *)&sgl_ptr[i].Address =
			    cookie->dmac_laddress;
			sgl_ptr[i].Length = cookie->dmac_size;
			sgl_ptr[i].Flags = 0;
		}

		ncookies -= nsge;

		if (ncookies == 0)
			break;

		/*
		 * There's more. Roll back to the last cookie processed,
		 * setup SGE chain and repeat.
		 */
		cookie--;
		ncookies++;

		if ((io_req->IoFlags &
		    MPI25_SAS_DEVICE0_FLAGS_ENABLED_FAST_PATH) == 0)
			/* XXX: Why? And why only if not fast path? */
			io_req->ChainOffset = lmrc->l_chain_offset_io_request;
		else
			io_req->ChainOffset = 0;

		sgl_ptr[i - 1].Flags = MPI2_IEEE_SGE_FLAGS_CHAIN_ELEMENT;
		sgl_ptr[i - 1].Length = sizeof (Mpi25SGEIOUnion_t) * ncookies;
		lmrc_dma_set_addr64(&mpt->mpt_chain_dma,
		    (uint64_t *)&sgl_ptr[i - 1].Address);
		sgl_ptr = mpt->mpt_chain;

		nsge = ncookies;
		max_sge = lmrc->l_max_sge_in_chain;

		VERIFY3U(nsge, <=, max_sge);
	}

	sgl_ptr[i - 1].Flags = MPI25_IEEE_SGE_FLAGS_END_OF_LIST;

	(void) ddi_dma_sync(mpt->mpt_chain_dma.ld_hdl, 0,
	    mpt->mpt_chain_dma.ld_len, DDI_DMA_SYNC_FORDEV);
}

size_t
lmrc_dma_get_size(lmrc_dma_t *dmap)
{
	const ddi_dma_cookie_t *cookie = ddi_dma_cookie_one(dmap->ld_hdl);

	return (cookie->dmac_size);
}

void
lmrc_dma_set_addr64(lmrc_dma_t *dmap, uint64_t *addr)
{
	const ddi_dma_cookie_t *cookie = ddi_dma_cookie_one(dmap->ld_hdl);

	*addr = cookie->dmac_laddress;
}

void
lmrc_dma_set_addr32(lmrc_dma_t *dmap, uint32_t *addr)
{
	const ddi_dma_cookie_t *cookie = ddi_dma_cookie_one(dmap->ld_hdl);

	*addr = cookie->dmac_address;
}

int
lmrc_dma_alloc(lmrc_t *lmrc, ddi_dma_attr_t attr, lmrc_dma_t *dmap, size_t len,
    uint64_t align, uint_t flags)
{
	int ret;

	VERIFY3U(len, >, 0);
	VERIFY3U(align, >=, 1);

	bzero(dmap, sizeof (*dmap));

	attr.dma_attr_align = align;
	attr.dma_attr_sgllen = 1;
	attr.dma_attr_granular = 1;


	ret = ddi_dma_alloc_handle(lmrc->l_dip, &attr, DDI_DMA_SLEEP, NULL,
	    &dmap->ld_hdl);
	if (ret != DDI_SUCCESS) {
		/*
		 * Due to DDI_DMA_SLEEP this can't be DDI_DMA_NORESOURCES, and
		 * the only other possible error is DDI_DMA_BADATTR which
		 * indicates a driver bug which should cause a panic.
		 */
		dev_err(lmrc->l_dip, CE_PANIC,
		    "failed to allocate DMA handle, check DMA attributes");
		return (ret);
	}

	ret = ddi_dma_mem_alloc(dmap->ld_hdl, len, &lmrc->l_acc_attr,
	    flags, DDI_DMA_SLEEP, NULL, (caddr_t *)&dmap->ld_buf,
	    &dmap->ld_len, &dmap->ld_acc);
	if (ret != DDI_SUCCESS) {
		/*
		 * When DDI_DMA_NOSLEEP is specified, ddi_dma_mem_alloc() can
		 * only fail if the flags are conflicting, which indicates a
		 * driver bug and should cause a panic.
		 */
		dev_err(lmrc->l_dip, CE_PANIC,
		    "failed to allocate DMA memory, check DMA flags (%x)",
		    flags);
		return (ret);
	}

	ret = ddi_dma_addr_bind_handle(dmap->ld_hdl, NULL, dmap->ld_buf,
	    dmap->ld_len, DDI_DMA_RDWR | flags, DDI_DMA_SLEEP, NULL, NULL,
	    NULL);
	if (ret != DDI_DMA_MAPPED) {
		ddi_dma_mem_free(&dmap->ld_acc);
		ddi_dma_free_handle(&dmap->ld_hdl);
		return (ret);
	}

	bzero(dmap->ld_buf, dmap->ld_len);
	return (DDI_SUCCESS);
}

void
lmrc_dma_free(lmrc_dma_t *dmap)
{
	if (dmap->ld_hdl != NULL)
		(void) ddi_dma_unbind_handle(dmap->ld_hdl);
	if (dmap->ld_acc != NULL)
		ddi_dma_mem_free(&dmap->ld_acc);
	if (dmap->ld_hdl != NULL)
		ddi_dma_free_handle(&dmap->ld_hdl);
	bzero(dmap, sizeof (lmrc_dma_t));
}

static lmrc_adapter_class_t
lmrc_get_class(lmrc_t *lmrc)
{
	int device_id = ddi_prop_get_int(DDI_DEV_T_ANY, lmrc->l_dip,
	    DDI_PROP_DONTPASS, "device-id", 0);

	switch (device_id) {
	case LMRC_VENTURA:
	case LMRC_CRUSADER:
	case LMRC_HARPOON:
	case LMRC_TOMCAT:
	case LMRC_VENTURA_4PORT:
	case LMRC_CRUSADER_4PORT:
		return (LMRC_ACLASS_VENTURA);

	case LMRC_AERO_10E1:
	case LMRC_AERO_10E5:
		dev_err(lmrc->l_dip, CE_CONT,
		    "?Adapter is in configurable secure mode\n");
		/*FALLTHRU*/
	case LMRC_AERO_10E2:
	case LMRC_AERO_10E6:
		return (LMRC_ACLASS_AERO);

	case LMRC_AERO_10E0:
	case LMRC_AERO_10E3:
	case LMRC_AERO_10E4:
	case LMRC_AERO_10E7:
		dev_err(lmrc->l_dip, CE_CONT,
		    "?Adapter is in non-secure mode\n");
	}

	return (LMRC_ACLASS_OTHER);
}

static int
lmrc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	const char *addr = scsi_hba_iport_unit_address(dip);

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (addr == NULL)
		return (lmrc_ctrl_attach(dip));

	if (strcmp(addr, LMRC_IPORT_RAID) == 0)
		return (lmrc_raid_attach(dip));

	if (strcmp(addr, LMRC_IPORT_PHYS) == 0)
		return (lmrc_phys_attach(dip));

	return (DDI_FAILURE);
}

static int
lmrc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	const char *addr = scsi_hba_iport_unit_address(dip);

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	if (addr == NULL)
		return (lmrc_ctrl_detach(dip));

	if (strcmp(addr, LMRC_IPORT_RAID) == 0)
		return (lmrc_raid_detach(dip));

	if (strcmp(addr, LMRC_IPORT_PHYS) == 0)
		return (lmrc_phys_detach(dip));

	return (DDI_FAILURE);
}

static int
lmrc_quiesce(dev_info_t *dip)
{
	lmrc_t *lmrc = ddi_get_soft_state(lmrc_state, ddi_get_instance(dip));

	if (lmrc == NULL)
		return (DDI_SUCCESS);

	return (lmrc_ctrl_shutdown(lmrc));
}

static struct cb_ops lmrc_cb_ops = {
	.cb_rev =		CB_REV,
	.cb_flag =		D_NEW | D_MP,

	.cb_open =		scsi_hba_open,
	.cb_close =		scsi_hba_close,

	.cb_ioctl =		lmrc_ioctl,

	.cb_strategy =		nodev,
	.cb_print =		nodev,
	.cb_dump =		nodev,
	.cb_read =		nodev,
	.cb_write =		nodev,
	.cb_devmap =		nodev,
	.cb_mmap =		nodev,
	.cb_segmap =		nodev,
	.cb_chpoll =		nochpoll,
	.cb_prop_op =		ddi_prop_op,
	.cb_str =		NULL,
	.cb_aread =		nodev,
	.cb_awrite =		nodev,
};

static struct dev_ops lmrc_dev_ops = {
	.devo_rev =		DEVO_REV,
	.devo_refcnt =		0,

	.devo_attach =		lmrc_attach,
	.devo_detach =		lmrc_detach,

	.devo_cb_ops =		&lmrc_cb_ops,

	.devo_getinfo =		ddi_no_info,
	.devo_identify =	nulldev,
	.devo_probe =		nulldev,
	.devo_reset =		nodev,
	.devo_bus_ops =		NULL,
	.devo_power =		nodev,
	.devo_quiesce =		lmrc_quiesce,
};

static struct modldrv lmrc_modldrv = {
	.drv_modops =		&mod_driverops,
	.drv_linkinfo =		"Broadcom MegaRAID 12G SAS RAID",
	.drv_dev_ops =		&lmrc_dev_ops,
};

static struct modlinkage lmrc_modlinkage = {
	.ml_rev =		MODREV_1,
	.ml_linkage =		{ &lmrc_modldrv, NULL },
};

int
_init(void)
{
	int ret;

	ret = ddi_soft_state_init(&lmrc_state, sizeof (lmrc_t), 1);
	if (ret != DDI_SUCCESS)
		return (ret);

	ret = scsi_hba_init(&lmrc_modlinkage);
	if (ret != 0) {
		ddi_soft_state_fini(&lmrc_state);
		return (ret);
	}

	ret = mod_install(&lmrc_modlinkage);
	if (ret != DDI_SUCCESS) {
		scsi_hba_fini(&lmrc_modlinkage);
		ddi_soft_state_fini(&lmrc_state);
		return (ret);
	}

	return (DDI_SUCCESS);
}

int
_fini(void)
{
	int ret;

	ret = mod_remove(&lmrc_modlinkage);
	if (ret == DDI_SUCCESS) {
		scsi_hba_fini(&lmrc_modlinkage);
		ddi_soft_state_fini(&lmrc_state);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&lmrc_modlinkage, modinfop));
}
