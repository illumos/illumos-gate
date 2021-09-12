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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_IB_ADAPTERS_TAVOR_H
#define	_SYS_IB_ADAPTERS_TAVOR_H


/*
 * tavor.h
 *    Contains the #defines and typedefs necessary for the Tavor softstate
 *    structure and for proper attach() and detach() processing.  Also
 *    includes all the other Tavor header files (and so is the only header
 *    file that is directly included by the Tavor source files).
 *    Lastly, this file includes everything necessary for implementing the
 *    devmap interface and for maintaining the "mapped resource database".
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/taskq.h>

#include <sys/ib/ibtl/ibci.h>
#include <sys/ib/adapters/mlnx_umap.h>

/*
 * First include all the Tavor typedefs, then include all the other Tavor
 * specific headers (many of which depend on the typedefs having already
 * been defined.
 */
#include <sys/ib/adapters/tavor/tavor_typedef.h>

#include <sys/ib/adapters/tavor/tavor_agents.h>
#include <sys/ib/adapters/tavor/tavor_cfg.h>
#include <sys/ib/adapters/tavor/tavor_cmd.h>
#include <sys/ib/adapters/tavor/tavor_cq.h>
#include <sys/ib/adapters/tavor/tavor_event.h>
#include <sys/ib/adapters/tavor/tavor_hw.h>
#include <sys/ib/adapters/tavor/tavor_ioctl.h>
#include <sys/ib/adapters/tavor/tavor_misc.h>
#include <sys/ib/adapters/tavor/tavor_mr.h>
#include <sys/ib/adapters/tavor/tavor_qp.h>
#include <sys/ib/adapters/tavor/tavor_srq.h>
#include <sys/ib/adapters/tavor/tavor_rsrc.h>
#include <sys/ib/adapters/tavor/tavor_wr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	TAVOR_VPD_HDR_DWSIZE		0x10 /* 16 Dwords */
#define	TAVOR_VPD_HDR_BSIZE		0x40 /* 64 Bytes */

/*
 * Number of initial states to setup. Used in call to ddi_soft_state_init()
 */
#define	TAVOR_INITIAL_STATES		3

/*
 * Macro and defines used to calculate device instance number from minor
 * number (and vice versa).
 */
#define	TAVOR_MINORNUM_SHIFT		3
#define	TAVOR_DEV_INSTANCE(dev)	(getminor((dev)) &			\
	((1 << TAVOR_MINORNUM_SHIFT) - 1))

/*
 * Locations for the various Tavor hardware PCI BARs (CMD, UAR, DDR)
 */
#define	TAVOR_CMD_BAR			1
#define	TAVOR_UAR_BAR			2
#define	TAVOR_DDR_BAR			3

/*
 * Some defines for the software reset.  These define the value that should
 * be written to begin the reset (TAVOR_SW_RESET_START), the delay before
 * beginning to poll for completion (TAVOR_SW_RESET_DELAY), the in-between
 * polling delay (TAVOR_SW_RESET_POLL_DELAY), and the value that indicates
 * that the reset has not completed (TAVOR_SW_RESET_NOTDONE).
 */
#define	TAVOR_SW_RESET_START		0x00000001
#define	TAVOR_SW_RESET_DELAY		100000		/* 100 ms */
#define	TAVOR_SW_RESET_POLL_DELAY	100		/* 100 us */
#define	TAVOR_SW_RESET_NOTDONE		0xFFFFFFFF

/*
 * These defines are used in the Tavor software reset operation.  They define
 * the total number PCI registers to read/restore during the reset.  And they
 * also specify two config registers which should not be read or restored.
 */
#define	TAVOR_SW_RESET_NUMREGS		0x40
#define	TAVOR_SW_RESET_REG22_RSVD	0x16
#define	TAVOR_SW_RESET_REG23_RSVD	0x17

/*
 * Macro used to output Tavor warning messages.  Note: Tavor warning messages
 * are only generated when an unexpected condition has been detected.  This
 * can be the result of a software bug or some other problem, but it is more
 * often an indication that the Tavor firmware (and/or hardware) has done
 * something unexpected.  This warning message means that the driver state
 * in unpredictable and that shutdown/restart is suggested.
 */
#define	TAVOR_WARNING(state, string)					\
	cmn_err(CE_WARN, "tavor%d: "string, (state)->ts_instance)

/*
 * Macro used to set attach failure messages.  Also, the attach message buf
 * size is set here.
 */
#define	TAVOR_ATTACH_MSGSIZE	80
#define	TAVOR_ATTACH_MSG(attach_buf, attach_msg)			\
	(void) snprintf((attach_buf), TAVOR_ATTACH_MSGSIZE, (attach_msg));
#define	TAVOR_ATTACH_MSG_INIT(attach_buf)				\
	(attach_buf)[0] = '\0';

/*
 * Macros used for controlling whether or not event callbacks will be forwarded
 * to the IBTF.  This is necessary because there are certain race conditions
 * that can occur (e.g. calling IBTF with an asynch event before the IBTF
 * registration has successfully completed or handling an event after we've
 * detached from the IBTF.)
 *
 * TAVOR_ENABLE_IBTF_CALLB() initializes the "ts_ibtfpriv" field in the Tavor
 *    softstate.  When "ts_ibtfpriv" is non-NULL, it is OK to forward asynch
 *    and CQ events to the IBTF.
 *
 * TAVOR_DO_IBTF_ASYNC_CALLB() and TAVOR_DO_IBTF_CQ_CALLB() both set and clear
 *    the "ts_in_evcallb" flag, as necessary, to indicate that an IBTF
 *    callback is currently in progress.  This is necessary so that we can
 *    block on this condition in tavor_detach().
 *
 * TAVOR_QUIESCE_IBTF_CALLB() is used in tavor_detach() to set the
 *    "ts_ibtfpriv" to NULL (thereby disabling any further IBTF callbacks)
 *    and to poll on the "ts_in_evcallb" flag.  When this flag is zero, all
 *    IBTF callbacks have quiesced and it is safe to continue with detach
 *    (i.e. continue detaching from IBTF).
 */
#define	TAVOR_ENABLE_IBTF_CALLB(state, tmp_ibtfpriv)			\
	(state)->ts_ibtfpriv = (tmp_ibtfpriv);

#define	TAVOR_DO_IBTF_ASYNC_CALLB(state, type, event)			\
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS((state)->ts_in_evcallb))	\
	(state)->ts_in_evcallb = 1;					\
	ibc_async_handler((state)->ts_ibtfpriv, (type), (event));	\
	(state)->ts_in_evcallb = 0;

#define	TAVOR_DO_IBTF_CQ_CALLB(state, cq)				\
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS((state)->ts_in_evcallb))	\
	(state)->ts_in_evcallb = 1;					\
	ibc_cq_handler((state)->ts_ibtfpriv, (cq)->cq_hdlrarg);		\
	(state)->ts_in_evcallb = 0;

#define	TAVOR_QUIESCE_IBTF_CALLB(state)					\
{									\
	uint_t		count = 0;					\
									\
	state->ts_ibtfpriv = NULL;					\
	while (((state)->ts_in_evcallb != 0) &&				\
	    (count++ < TAVOR_QUIESCE_IBTF_CALLB_POLL_MAX)) {		\
		drv_usecwait(TAVOR_QUIESCE_IBTF_CALLB_POLL_DELAY);	\
	}								\
}

/*
 * Defines used by the TAVOR_QUIESCE_IBTF_CALLB() macro to determine the
 * duration and number of times (at maximum) to poll while waiting for IBTF
 * callbacks to quiesce.
 */
#define	TAVOR_QUIESCE_IBTF_CALLB_POLL_DELAY	1
#define	TAVOR_QUIESCE_IBTF_CALLB_POLL_MAX	1000000

/*
 * Define used to determine the device mode to which Tavor driver has been
 * attached.  TAVOR_IS_MAINTENANCE_MODE() returns true when the device has
 * come up in the "maintenance mode".  In this mode, no InfiniBand interfaces
 * are enabled, but the device's firmware can be updated/flashed (and
 * test/debug interfaces should be useable).
 * TAVOR_IS_HCA_MODE() returns true when the device has come up in the normal
 * HCA mode.  In this mode, all necessary InfiniBand interfaces are enabled
 * (and, if necessary, Tavor firmware can be updated/flashed).
 */
#define	TAVOR_IS_MAINTENANCE_MODE(dip)					\
	(((ddi_prop_get_int(DDI_DEV_T_ANY, (dip), DDI_PROP_DONTPASS,	\
	"device-id", -1) == 0x5a45) ||					\
	(ddi_prop_get_int(DDI_DEV_T_ANY, (dip), DDI_PROP_DONTPASS,	\
	"device-id", -1) == 0x6279)) &&					\
	(ddi_prop_get_int(DDI_DEV_T_ANY, (dip), DDI_PROP_DONTPASS,	\
	"vendor-id", -1) == 0x15b3))
#define	TAVOR_IS_COMPAT_MODE(dip)					\
	((ddi_prop_get_int(DDI_DEV_T_ANY, (dip), DDI_PROP_DONTPASS,	\
	"device-id", -1) == 0x6278) &&					\
	(ddi_prop_get_int(DDI_DEV_T_ANY, (dip), DDI_PROP_DONTPASS,	\
	"vendor-id", -1) == 0x15b3))
#define	TAVOR_IS_HCA_MODE(dip)						\
	((ddi_prop_get_int(DDI_DEV_T_ANY, (dip), DDI_PROP_DONTPASS,	\
	"device-id", -1) == 0x5a44) &&					\
	(ddi_prop_get_int(DDI_DEV_T_ANY, (dip), DDI_PROP_DONTPASS,	\
	"vendor-id", -1) == 0x15b3))

#define	TAVOR_MAINTENANCE_MODE		1
#define	TAVOR_COMPAT_MODE		2
#define	TAVOR_HCA_MODE			3

/*
 * Used to determine if the device is operational, or not in maintenance mode.
 * This means either the driver has attached successfully against an arbel
 * device in tavor compatibility mode, or against a tavor device in full HCA
 * mode.
 */
#define	TAVOR_IS_OPERATIONAL(mode)					\
	(mode == TAVOR_COMPAT_MODE || mode == TAVOR_HCA_MODE)

/*
 * Used to determine if parent bridge is a PCI bridge; used in software reset
 */
#define	TAVOR_PARENT_IS_BRIDGE(dip)					\
	((ddi_prop_get_int(DDI_DEV_T_ANY, (dip), DDI_PROP_DONTPASS,	\
	"device-id", -1) == 0x5a46))

/*
 * The following define is used (in tavor_umap_db_set_onclose_cb()) to
 * indicate that a cleanup callback is needed to undo initialization done
 * by the firmware flash burn code.
 */
#define	TAVOR_ONCLOSE_FLASH_INPROGRESS		(1 << 0)

/*
 * The following enumerated type and structures are used during driver
 * initialization.  Note: The TAVOR_DRV_CLEANUP_ALL type is used as a marker
 * for end of the cleanup steps.  No cleanup steps should be added after
 * TAVOR_DRV_CLEANUP_ALL.  Any addition steps should be added before it.
 */
typedef enum {
	TAVOR_DRV_CLEANUP_LEVEL0,
	TAVOR_DRV_CLEANUP_LEVEL1,
	TAVOR_DRV_CLEANUP_LEVEL2,
	TAVOR_DRV_CLEANUP_LEVEL3,
	TAVOR_DRV_CLEANUP_LEVEL4,
	TAVOR_DRV_CLEANUP_LEVEL5,
	TAVOR_DRV_CLEANUP_LEVEL6,
	TAVOR_DRV_CLEANUP_LEVEL7,
	TAVOR_DRV_CLEANUP_LEVEL8,
	TAVOR_DRV_CLEANUP_LEVEL9,
	TAVOR_DRV_CLEANUP_LEVEL10,
	TAVOR_DRV_CLEANUP_LEVEL11,
	TAVOR_DRV_CLEANUP_LEVEL12,
	TAVOR_DRV_CLEANUP_LEVEL13,
	TAVOR_DRV_CLEANUP_LEVEL14,
	/* No more driver cleanup steps below this point! */
	TAVOR_DRV_CLEANUP_ALL
} tavor_drv_cleanup_level_t;

/*
 *  tavor_mem_alloc_hdl_t structure store DMA handles for the new
 * ibc_alloc_io_mem calls
 */
typedef struct tavor_mem_alloc_hdl_s {
	ddi_dma_handle_t tavor_dma_hdl;
	ddi_acc_handle_t tavor_acc_hdl;
} *tavor_mem_alloc_hdl_t;


/*
 * The tavor_cmd_reg_t structure is used to hold the address of the each of
 * the most frequently accessed hardware registers.  Specifically, it holds
 * the HCA Command Registers (HCR, used to pass command and mailbox
 * information back and forth to Tavor firmware) and the lock used to guarantee
 * mutually exclusive access to the registers.  It also holds the Event Cause
 * Register (ECR) and its related clear register.  These are used to indicate
 * during interrupt processing which EQs have fired and require servicing.
 * Related to this, is the "clr_int" register which is used to clear the
 * interrupt once all EQs have been services.
 * Finally, there is the software reset register which is used to reinitialize
 * the Tavor device and to put it into a known state at driver startup time.
 * Below we also have the offsets (into the CMD register space) for each of
 * the various registers.
 */
typedef struct tavor_cmd_reg_s {
	tavor_hw_hcr_t	*hcr;
	kmutex_t	hcr_lock;
	uint64_t	*ecr;
	uint64_t	*clr_ecr;
	uint64_t	*clr_int;
	uint32_t	*sw_reset;
} tavor_cmd_reg_t;
_NOTE(MUTEX_PROTECTS_DATA(tavor_cmd_reg_t::hcr_lock,
    tavor_cmd_reg_t::hcr))


/*
 * The tavor_state_t structure is the Tavor software state structure.  It
 * contains all the pointers and placeholder for everything that the Tavor
 * driver needs to properly operate.  One of these structures exists for
 * every instance of the Tavor driver.
 */
struct tavor_state_s {
	dev_info_t		*ts_dip;
	int			ts_instance;

	/* Tavor interrupt/MSI information */
	int			ts_intr_types_avail;
	uint_t			ts_intr_type_chosen;
	int			ts_intrmsi_count;
	int			ts_intrmsi_avail;
	int			ts_intrmsi_allocd;
	ddi_intr_handle_t	ts_intrmsi_hdl;
	uint_t			ts_intrmsi_pri;
	int			ts_intrmsi_cap;

	/* Tavor device operational mode */
	int			ts_operational_mode;

	/* Attach buffer saved per state to store detailed attach errors */
	char			ts_attach_buf[TAVOR_ATTACH_MSGSIZE];

	/*
	 * Tavor NodeGUID, SystemImageGUID, NodeDescription, HCA name,
	 * and HCA part number.
	 */
	uint64_t		ts_nodeguid;
	uint64_t		ts_sysimgguid;
	char			ts_nodedesc[64];
	char			ts_hca_name[64];
	char			ts_hca_pn[64];
	int			ts_hca_pn_len;

	/* Info passed to IBTF during registration */
	ibc_hca_info_t		ts_ibtfinfo;
	ibc_clnt_hdl_t		ts_ibtfpriv;

	/*
	 * Tavor register mapping.  Holds the device access attributes,
	 * kernel mapped addresses, and DDI access handles for each of
	 * Tavor's three types of address register (CMD, UAR, and DDR).
	 */
	ddi_device_acc_attr_t	ts_reg_accattr;
	caddr_t			ts_reg_cmd_baseaddr;	/* Tavor CMD BAR */
	ddi_acc_handle_t	ts_reg_cmdhdl;
	caddr_t			ts_reg_uar_baseaddr;	/* Tavor UAR BAR */
	ddi_acc_handle_t	ts_reg_uarhdl;
	caddr_t			ts_reg_ddr_baseaddr;	/* Tavor DDR BAR */
	ddi_acc_handle_t	ts_reg_ddrhdl;

	/*
	 * Tavor PCI config space registers.  These two arrays are used to
	 * save and restore the PCI config registers before and after a
	 * software reset.  Note: We must save away both our own registers
	 * and our parent's (the "virtual" PCI bridge in the device) because
	 * the software reset will reset both sets.
	 */
	uint32_t		ts_cfg_data[TAVOR_SW_RESET_NUMREGS];
	uint32_t		ts_cfg_pdata[TAVOR_SW_RESET_NUMREGS];

	/*
	 * Tavor UAR page resources.  Holds the resource pointers for
	 * UAR page #0 (reserved) and for UAR page #1 (used for kernel
	 * driver doorbells).  In addition, we save a pointer to the
	 * UAR page #1 doorbells which will be used throughout the driver
	 * whenever it is necessary to ring one of them.  And, in case we
	 * are unable to do 64-bit writes to the page (because of system
	 * architecture), we include a lock (to ensure atomic 64-bit access).
	 */
	tavor_rsrc_t		*ts_uarpg0_rsrc_rsrvd;
	tavor_rsrc_t		*ts_uarpg1_rsrc;
	tavor_hw_uar_t		*ts_uar;
	kmutex_t		ts_uar_lock;

	/*
	 * Used during a call to open() if we are in maintenance mode, this
	 * field serves as a semi-unique rolling count index value, used only
	 * in the setup of umap_db entries.  This is primarily needed to
	 * firmware device access ioctl operations can still be guaranteed to
	 * close in the event of an unplanned process exit, even in maintenance
	 * mode.
	 */
	uint_t			ts_open_tr_indx;

	/*
	 * Tavor command registers.  This structure contains the addresses
	 * for each of the most frequently accessed CMD registers.  Since
	 * almost all accesses to the Tavor hardware are through the Tavor
	 * command interface (i.e. the HCR), we save away the pointer to
	 * the HCR, as well as pointers to the ECR and INT registers (as
	 * well as their corresponding "clear" registers) for interrupt
	 * processing.  And we also save away a pointer to the software
	 * reset register (see above).
	 */
	tavor_cmd_reg_t		ts_cmd_regs;

	/*
	 * Tavor resource pointers.  The following are pointers to the vmem
	 * arena (created to manage the DDR memory), the kmem cache (from
	 * which the Tavor resource handles are allocated), and the array
	 * of "resource pools" (which store all the pertinent information
	 * necessary to manage each of the various types of resources that
	 * are used by the Tavor driver.  See tavor_rsrc.h for more detail.
	 */
	vmem_t			*ts_ddrvmem;
	kmem_cache_t		*ts_rsrc_cache;
	tavor_rsrc_pool_info_t	*ts_rsrc_hdl;

	/*
	 * Tavor mailbox lists.  These hold the information necessary to
	 * manage the pools of pre-allocated Tavor mailboxes (both "In" and
	 * "Out" type).  See tavor_cmd.h for more detail.
	 */
	tavor_mboxlist_t	ts_in_mblist;
	tavor_mboxlist_t	ts_out_mblist;

	/*
	 * Tavor interrupt mailbox lists.  We allocate both an "In" mailbox
	 * and an "Out" type mailbox for the interrupt context.  This is in
	 * order to guarantee that a mailbox entry will always be available in
	 * the interrupt context, and we can NOSLEEP without having to worry
	 * about possible failure allocating the mbox.  We create this as an
	 * mboxlist so that we have the potential for having multiple mboxes
	 * available based on the number of interrupts we can receive at once.
	 */
	tavor_mboxlist_t		ts_in_intr_mblist;
	tavor_mboxlist_t		ts_out_intr_mblist;

	/*
	 * Tavor outstanding command list.  Used to hold all the information
	 * necessary to manage the Tavor "outstanding command list".  See
	 * tavor_cmd.h for more detail.
	 */
	tavor_cmdlist_t		ts_cmd_list;

	/*
	 * This structure contains the Tavor driver's "configuration profile".
	 * This is the collected set of configuration information, such as
	 * number of QPs, CQs, mailboxes and other resources, sizes of
	 * individual resources, other system level configuration information,
	 * etc.  See tavor_cfg.h for more detail.
	 */
	tavor_cfg_profile_t	*ts_cfg_profile;

	/*
	 * This flag contains the profile setting, selecting which profile the
	 * driver would use.  This is needed in the case where we have to
	 * fallback to a smaller profile based on some DDR conditions.  If we
	 * don't fallback, then it is set to the size of DDR in the system.
	 */
	uint32_t		ts_cfg_profile_setting;

	/*
	 * The following are a collection of resource handles used by the
	 * Tavor driver (internally).  First is the protection domain (PD)
	 * handle that is used when mapping all kernel memory (work queues,
	 * completion queues, etc).  Next is an array of EQ handles.  This
	 * array is indexed by EQ number and allows the Tavor driver to quickly
	 * convert an EQ number into the software structure associated with the
	 * given EQ.  Likewise, we have three arrays for CQ, QP and SRQ
	 * handles.  These arrays are also indexed by CQ, QP or SRQ number and
	 * allow the driver to quickly find the corresponding CQ, QP or SRQ
	 * software structure.  Note: while the EQ table is of fixed size
	 * (because there are a maximum of 64 EQs), each of the CQ, QP and SRQ
	 * handle lists must be allocated at driver startup.
	 */
	tavor_pdhdl_t		ts_pdhdl_internal;
	tavor_eqhdl_t		ts_eqhdl[TAVOR_NUM_EQ];
	tavor_cqhdl_t		*ts_cqhdl;
	tavor_qphdl_t		*ts_qphdl;
	tavor_srqhdl_t		*ts_srqhdl;

	/*
	 * The AVL tree is used to store information regarding QP number
	 * allocations.  The lock protects access to the AVL tree.
	 */
	avl_tree_t		ts_qpn_avl;
	kmutex_t		ts_qpn_avl_lock;

	/*
	 * This field is used to indicate whether or not the Tavor driver is
	 * currently in an IBTF event callback elsewhere in the system.  Note:
	 * It is "volatile" because we intend to poll on this value - in
	 * tavor_detach() - until we are assured that no further IBTF callbacks
	 * are currently being processed.
	 */
	volatile uint32_t	ts_in_evcallb;

	/*
	 * The following structures are used to store the results of several
	 * device query commands passed to the Tavor hardware at startup.
	 * Specifically, we have hung onto the results of QUERY_DDR (which
	 * gives information about how much DDR memory is present and where
	 * it is located), QUERY_FW (which gives information about firmware
	 * version numbers and the location and extent of firmware's footprint
	 * in DDR, QUERY_DEVLIM (which gives the device limitations/resource
	 * maximums), QUERY_ADAPTER (which gives additional miscellaneous
	 * information), and INIT/QUERY_HCA (which serves the purpose of
	 * recording what configuration information was passed to the firmware
	 * when the HCA was initialized).
	 */
	struct tavor_hw_queryddr_s	ts_ddr;
	struct tavor_hw_queryfw_s	ts_fw;
	struct tavor_hw_querydevlim_s	ts_devlim;
	struct tavor_hw_queryadapter_s	ts_adapter;
	struct tavor_hw_initqueryhca_s	ts_hcaparams;

	/*
	 * The following are used for managing special QP resources.
	 * Specifically, we have a lock, a set of flags (in "ts_spec_qpflags")
	 * used to track the special QP resources, and two Tavor resource
	 * handle pointers.  Each resource handle actually corresponds to two
	 * consecutive QP contexts (one per port) for each special QP type.
	 */
	kmutex_t		ts_spec_qplock;
	uint_t			ts_spec_qpflags;
	tavor_rsrc_t		*ts_spec_qp0;
	tavor_rsrc_t		*ts_spec_qp1;

	/*
	 * Related in some ways to the special QP handling above are these
	 * resources which are used specifically for implementing the Tavor
	 * agents (SMA, PMA, and BMA).  Although, each of these agents does
	 * little more that intercept the appropriate incoming MAD and forward
	 * it along to the firmware (see tavor_agents.c for more details), we
	 * do still use a task queue to queue them up.  We can also configure
	 * the driver to force firmware handling for certain classes of MAD,
	 * and, therefore, we require the agent list and number of agents
	 * in order to know what needs to be torn down at detach() time.
	 */
	tavor_agent_list_t	*ts_agents;
	ddi_taskq_t		*ts_taskq_agents;
	uint_t			ts_num_agents;

	/*
	 * Multicast group lists.  These are used to track the "shadow" MCG
	 * lists that speed up the processing of attach and detach multicast
	 * group operations.  See tavor_misc.h for more details.  Note: we
	 * need the pointer to the "temporary" MCG entry here primarily
	 * because the size of a given MCG entry is configurable.  Therefore,
	 * it is impossible to put this variable on the stack.  And rather
	 * than allocate and deallocate the entry multiple times, we choose
	 * instead to preallocate it once and reuse it over and over again.
	 */
	kmutex_t		ts_mcglock;
	tavor_mcghdl_t		ts_mcghdl;
	tavor_hw_mcg_t		*ts_mcgtmp;

	/*
	 * Used for tracking Tavor kstat information
	 */
	tavor_ks_info_t		*ts_ks_info;

	/*
	 * Used for Tavor info ioctl used by VTS
	 */
	kmutex_t		ts_info_lock;

	/*
	 * Used for Tavor FW flash burning.  They are used exclusively
	 * within the ioctl calls for use when accessing the tavor
	 * flash device.
	 */
	kmutex_t		ts_fw_flashlock;
	int			ts_fw_flashstarted;
	dev_t			ts_fw_flashdev;
	uint32_t		ts_fw_log_sector_sz;
	uint32_t		ts_fw_device_sz;
	uint32_t		ts_fw_flashbank;
	uint32_t		*ts_fw_sector;
	uint32_t		ts_fw_gpio[4];
	ddi_acc_handle_t	ts_pci_cfghdl;		/* PCI cfg handle */
	int			ts_fw_cmdset;

	/* Tavor fastreboot support */
	boolean_t		ts_quiescing;		/* in fastreboot */
};
_NOTE(MUTEX_PROTECTS_DATA(tavor_state_s::ts_fw_flashlock,
    tavor_state_s::ts_fw_flashstarted
    tavor_state_s::ts_fw_flashdev
    tavor_state_s::ts_fw_log_sector_sz
    tavor_state_s::ts_fw_device_sz))
_NOTE(MUTEX_PROTECTS_DATA(tavor_state_s::ts_spec_qplock,
    tavor_state_s::ts_spec_qpflags
    tavor_state_s::ts_spec_qp0
    tavor_state_s::ts_spec_qp1))
_NOTE(MUTEX_PROTECTS_DATA(tavor_state_s::ts_mcglock,
    tavor_state_s::ts_mcghdl
    tavor_state_s::ts_mcgtmp))
_NOTE(DATA_READABLE_WITHOUT_LOCK(tavor_state_s::ts_in_evcallb
    tavor_state_s::ts_fw_log_sector_sz
    tavor_state_s::ts_fw_device_sz
    tavor_state_s::ts_fw_sector
    tavor_state_s::ts_spec_qpflags
    tavor_state_s::ts_spec_qp0
    tavor_state_s::ts_spec_qp1))
_NOTE(MUTEX_PROTECTS_DATA(tavor_state_s::ts_qpn_avl_lock,
    tavor_state_s::ts_qpn_avl))

/*
 * TAVOR_IN_FASTREBOOT() shows if Hermon driver is at fastreboot.
 * This macro should be used to check if the mutex lock can be used
 * since the lock cannot be used if the driver is in the quiesce mode.
 */
#define	TAVOR_IN_FASTREBOOT(state)	(state->ts_quiescing == B_TRUE)

/*
 * Bit positions in the "ts_spec_qpflags" field above.  The flags are (from
 * least significant to most): (QP0,Port1), (QP0,Port2), (QP1,Port1), and
 * (QP1,Port2).  The masks are there to help with some specific allocation
 * and freeing operations
 */
#define	TAVOR_SPECIAL_QP0_RSRC		0
#define	TAVOR_SPECIAL_QP0_RSRC_MASK	0x3
#define	TAVOR_SPECIAL_QP1_RSRC		2
#define	TAVOR_SPECIAL_QP1_RSRC_MASK	0xC


/*
 * These flags specifies additional behaviors on database access.
 * TAVOR_UMAP_DB_REMOVE, for example, specifies that (if found) the database
 * entry should be removed from the database.  TAVOR_UMAP_DB_IGNORE_INSTANCE
 * specifies that a particular database query should ignore value in the
 * "tdb_instance" field as a criterion for the search.
 */
#define	TAVOR_UMAP_DB_REMOVE		(1 << 0)
#define	TAVOR_UMAP_DB_IGNORE_INSTANCE	(1 << 1)


/*
 * The tavor_umap_db_t structure contains what is referred to throughout the
 * driver code as the "userland resources database".  This structure contains
 * all the necessary information to track resources that have been prepared
 * for direct-from-userland access.  There is an AVL tree ("tdl_umapdb_avl")
 * which consists of the "tavor_umap_db_entry_t" (below) and a lock to ensure
 * atomic access when adding or removing entries from the database.
 */
typedef struct tavor_umap_db_s {
	kmutex_t		tdl_umapdb_lock;
	avl_tree_t		tdl_umapdb_avl;
} tavor_umap_db_t;

/*
 * The tavor_umap_db_priv_t structure currently contains information necessary
 * to provide the "on close" callback to the firmware flash interfaces.  It
 * is intended that this structure could be extended to enable other "on
 * close" callbacks as well.
 */
typedef struct tavor_umap_db_priv_s {
	void		(*tdp_cb)(void *);
	void		*tdp_arg;
} tavor_umap_db_priv_t;

/*
 * The tavor_umap_db_common_t structure contains fields which are common
 * between the database entries ("tavor_umap_db_entry_t") and the structure
 * used to contain the search criteria ("tavor_umap_db_query_t").  This
 * structure contains a key, a resource type (described above), an instance
 * (corresponding to the driver instance which inserted the database entry),
 * and a "value" field.  Typically, "tdb_value" is a pointer to a Tavor
 * resource object.  Although for memory regions, the value field corresponds
 * to the ddi_umem_cookie_t for the pinned userland memory.
 * The structure also includes a placeholder for private data ("tdb_priv").
 * Currently this data is being used for holding "on close" callback
 * information to allow certain kinds of cleanup even if a userland process
 * prematurely exits.
 */
typedef struct tavor_umap_db_common_s {
	uint64_t		tdb_key;
	uint64_t		tdb_value;
	uint_t			tdb_type;
	uint_t			tdb_instance;
	void			*tdb_priv;
} tavor_umap_db_common_t;

/*
 * The tavor_umap_db_entry_t structure is the entry in "userland resources
 * database".  As required by the AVL framework, each entry contains an
 * "avl_node_t".  Then, as required to implement the database, each entry
 * contains a "tavor_umap_db_common_t" structure used to contain all of the
 * relevant entries.
 */
typedef struct tavor_umap_db_entry_s {
	avl_node_t		tdbe_avlnode;
	tavor_umap_db_common_t	tdbe_common;
} tavor_umap_db_entry_t;

/*
 * The tavor_umap_db_query_t structure is used in queries to the "userland
 * resources database".  In addition to the "tavor_umap_db_common_t" structure
 * used to contain the various search criteria, this structure also contains
 * a flags field "tqdb_flags" which can be used to specify additional behaviors
 * (as described above).  Specifically, the flags field can be used to specify
 * that an entry should be removed from the database, if found, and to
 * specify whether the database lookup should consider "tdb_instance" in the
 * search.
 */
typedef struct tavor_umap_db_query_s {
	uint_t			tqdb_flags;
	tavor_umap_db_common_t	tqdb_common;
} tavor_umap_db_query_t;
_NOTE(MUTEX_PROTECTS_DATA(tavor_umap_db_s::tdl_umapdb_lock,
    tavor_umap_db_entry_s::tdbe_avlnode
    tavor_umap_db_entry_s::tdbe_common.tdb_key
    tavor_umap_db_entry_s::tdbe_common.tdb_value
    tavor_umap_db_entry_s::tdbe_common.tdb_type
    tavor_umap_db_entry_s::tdbe_common.tdb_instance))

/*
 * The tavor_devmap_track_t structure contains all the necessary information
 * to track resources that have been mapped through devmap.  There is a
 * back-pointer to the Tavor softstate, the logical offset corresponding with
 * the mapped resource, the size of the mapped resource (zero indicates an
 * "invalid mapping"), and a reference count and lock used to determine when
 * to free the structure (specifically, this is necessary to handle partial
 * unmappings).
 */
typedef struct tavor_devmap_track_s {
	tavor_state_t	*tdt_state;
	uint64_t	tdt_offset;
	uint_t		tdt_size;
	int		tdt_refcnt;
	kmutex_t	tdt_lock;
} tavor_devmap_track_t;


/* Defined in tavor_umap.c */
int tavor_devmap(dev_t dev, devmap_cookie_t dhp, offset_t off, size_t len,
    size_t *maplen, uint_t model);
ibt_status_t tavor_umap_ci_data_in(tavor_state_t *state,
    ibt_ci_data_flags_t flags, ibt_object_type_t object, void *hdl,
    void *data_p, size_t data_sz);
ibt_status_t tavor_umap_ci_data_out(tavor_state_t *state,
    ibt_ci_data_flags_t flags, ibt_object_type_t object, void *hdl,
    void *data_p, size_t data_sz);
void tavor_umap_db_init(void);
void tavor_umap_db_fini(void);
tavor_umap_db_entry_t *tavor_umap_db_alloc(uint_t instance, uint64_t key,
    uint_t type, uint64_t value);
void tavor_umap_db_free(tavor_umap_db_entry_t *umapdb);
void tavor_umap_db_add(tavor_umap_db_entry_t *umapdb);
void tavor_umap_db_add_nolock(tavor_umap_db_entry_t *umapdb);
int tavor_umap_db_find(uint_t instance, uint64_t key, uint_t type,
    uint64_t *value, uint_t flags, tavor_umap_db_entry_t **umapdb);
int tavor_umap_db_find_nolock(uint_t instance, uint64_t key, uint_t type,
    uint64_t *value, uint_t flags, tavor_umap_db_entry_t **umapdb);
void tavor_umap_umemlock_cb(ddi_umem_cookie_t *umem_cookie);
int tavor_umap_db_set_onclose_cb(dev_t dev, uint64_t flag,
    void (*callback)(void *), void *arg);
int tavor_umap_db_clear_onclose_cb(dev_t dev, uint64_t flag);
void tavor_umap_db_handle_onclose_cb(tavor_umap_db_priv_t *priv);

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_TAVOR_H */
