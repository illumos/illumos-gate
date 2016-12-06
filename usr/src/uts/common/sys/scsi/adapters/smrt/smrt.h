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
 * Copyright 2016 Joyent, Inc.
 */

#ifndef	_SMRT_H
#define	_SMRT_H

#include <sys/types.h>
#include <sys/pci.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/map.h>
#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/impl/spc3_types.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sdt.h>
#include <sys/policy.h>
#include <sys/ctype.h>

#if !defined(_LITTLE_ENDIAN) || !defined(_BIT_FIELDS_LTOH)
/*
 * This driver contains a number of multi-byte bit fields and other structs
 * that are only correct on a system with the same ordering as x86.
 */
#error "smrt: driver works only on little endian systems"
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Some structures are statically sized based on the expected number of logical
 * drives and controllers in the system.  These definitions are used throughout
 * other driver-specific header files, and must appear prior to their
 * inclusion.
 */
#define	SMRT_MAX_LOGDRV		64	/* Maximum number of logical drives */

#include <sys/scsi/adapters/smrt/smrt_ciss.h>
#include <sys/scsi/adapters/smrt/smrt_scsi.h>

#ifdef	__cplusplus
extern "C" {
#endif

extern ddi_device_acc_attr_t smrt_dev_attributes;

typedef enum smrt_init_level {
	SMRT_INITLEVEL_BASIC =			(0x1 << 0),
	SMRT_INITLEVEL_I2O_MAPPED =		(0x1 << 1),
	SMRT_INITLEVEL_CFGTBL_MAPPED =		(0x1 << 2),
	SMRT_INITLEVEL_PERIODIC =		(0x1 << 3),
	SMRT_INITLEVEL_INT_ALLOC =		(0x1 << 4),
	SMRT_INITLEVEL_INT_ADDED =		(0x1 << 5),
	SMRT_INITLEVEL_INT_ENABLED =		(0x1 << 6),
	SMRT_INITLEVEL_SCSA =			(0x1 << 7),
	SMRT_INITLEVEL_MUTEX =			(0x1 << 8),
} smrt_init_level_t;

/*
 * Commands issued to the controller carry a (generally 32-bit, though with
 * two reserved signalling bits) identifying tag number.  In order to avoid
 * having the controller confuse us by double-reporting the completion of a
 * particular tag, we try to reuse them as infrequently as possible.  In
 * practice, this means looping through a range of values.  The minimum and
 * maximum value are defined below.  A single command tag value is set aside
 * for polled commands sent prior to full initialisation of the driver.
 */
#define	SMRT_PRE_TAG_NUMBER			0x00000bad
#define	SMRT_MIN_TAG_NUMBER			0x00001000
#define	SMRT_MAX_TAG_NUMBER			0x0fffffff

/*
 * Definitions to support waiting for the controller to converge on a
 * particular state: ready or not ready.  These are used with
 * smrt_ctlr_wait_for_state().
 */
#define	SMRT_WAIT_DELAY_SECONDS			120
typedef enum smrt_wait_state {
	SMRT_WAIT_STATE_READY = 1,
	SMRT_WAIT_STATE_UNREADY
} smrt_wait_state_t;

typedef enum smrt_ctlr_mode {
	SMRT_CTLR_MODE_UNKNOWN = 0,
	SMRT_CTLR_MODE_SIMPLE
} smrt_ctlr_mode_t;

/*
 * In addition to Logical Volumes, we also expose the controller at a
 * pseudo target address on the SCSI bus we are essentially pretending to be.
 */
#define	SMRT_CONTROLLER_TARGET			128

/*
 * When waiting for logical volume discovery to complete, we wait for a maximum
 * duration (in seconds) before giving up.
 */
#define	SMRT_LOGVOL_DISCOVER_TIMEOUT		30

/*
 * The maintenance routine which checks for controller lockup and aborts
 * commands that have passed their timeout runs periodically.  The time is
 * expressed in seconds.
 */
#define	SMRT_PERIODIC_RATE			5

/*
 * At times, we need to check if the controller is still responding.  To do
 * that, we send a Nop message to the controller and make sure it completes
 * successfully.  So that we don't wait forever, we set a timeout (in seconds).
 */
#define	SMRT_PING_CHECK_TIMEOUT			60


typedef enum smrt_controller_status {
	/*
	 * A Logical Volume discovery is currently occuring.
	 */
	SMRT_CTLR_STATUS_DISCOVERY =		(0x1 << 0),

	/*
	 * An attempt is being made to detach the controller instance.
	 */
	SMRT_CTLR_STATUS_DETACHING =		(0x1 << 1),

	/*
	 * The controller is believed to be functioning correctly.  The driver
	 * is to allow command submission, process interrupts, and perform
	 * periodic background maintenance.
	 */
	SMRT_CTLR_STATUS_RUNNING =		(0x1 << 2),

	/*
	 * The controller is currently being reset.
	 */
	SMRT_CTLR_STATUS_RESETTING =		(0x1 << 3),
} smrt_controller_status_t;

typedef struct smrt_stats {
	uint64_t smrts_tran_aborts;
	uint64_t smrts_tran_resets;
	uint64_t smrts_tran_starts;
	uint64_t smrts_ctlr_resets;
	unsigned smrts_max_inflight;
	uint64_t smrts_unclaimed_interrupts;
	uint64_t smrts_claimed_interrupts;
	uint64_t smrts_ignored_scsi_cmds;
} smrt_stats_t;

typedef struct smrt_versions {
	uint8_t smrtv_hardware_version;

	/*
	 * These strings must be large enough to hold the 4 byte version string
	 * retrieved from an IDENTIFY CONTROLLER response, as well as the
	 * terminating NUL byte:
	 */
	char smrtv_firmware_rev[5];
	char smrtv_recovery_rev[5];
	char smrtv_bootblock_rev[5];
} smrt_versions_t;

/*
 * Per-Controller Structure
 */
typedef struct smrt smrt_t;
struct smrt {
	dev_info_t *smrt_dip;
	int smrt_instance;
	smrt_controller_status_t smrt_status;
	smrt_stats_t smrt_stats;

	/*
	 * Controller configuration discovered during initialisation.
	 */
	uint32_t smrt_host_support;
	uint32_t smrt_bus_support;
	uint32_t smrt_maxcmds;
	uint32_t smrt_sg_cnt;
	smrt_versions_t smrt_versions;

	/*
	 * The transport mode of the controller.
	 */
	smrt_ctlr_mode_t smrt_ctlr_mode;

	/*
	 * The current initialisation level of the driver.  Bits in this field
	 * are set during initialisation and unset during cleanup of the
	 * allocated resources.
	 */
	smrt_init_level_t smrt_init_level;

	/*
	 * Essentially everything is protected by "smrt_mutex".  When the
	 * completion queue is updated, threads sleeping on "smrt_cv_finishq"
	 * are awoken.
	 */
	kmutex_t smrt_mutex;
	kcondvar_t smrt_cv_finishq;

	/*
	 * List of enumerated logical volumes (smrt_volume_t).
	 */
	list_t smrt_volumes;

	/*
	 * List of attached SCSA target drivers (smrt_target_t).
	 */
	list_t smrt_targets;

	/*
	 * Controller Heartbeat Tracking
	 */
	uint32_t smrt_last_heartbeat;
	hrtime_t smrt_last_heartbeat_time;

	hrtime_t smrt_last_interrupt_claimed;
	hrtime_t smrt_last_interrupt_unclaimed;
	hrtime_t smrt_last_discovery;
	hrtime_t smrt_last_reset_start;
	hrtime_t smrt_last_reset_finish;

	/*
	 * Command object tracking.  These lists, and all commands within the
	 * lists, are protected by "smrt_mutex".
	 */
	uint32_t smrt_next_tag;
	avl_tree_t smrt_inflight;
	list_t smrt_commands;		/* List of all commands. */
	list_t smrt_finishq;		/* List of completed commands. */
	list_t smrt_abortq;		/* List of commands to abort. */

	/*
	 * Controller interrupt handler registration.
	 */
	int smrt_interrupt_type;
	int smrt_interrupt_cap;
	uint_t smrt_interrupt_pri;
	ddi_intr_handle_t smrt_interrupts[1];
	int smrt_ninterrupts;

	ddi_periodic_t smrt_periodic;

	scsi_hba_tran_t *smrt_hba_tran;

	ddi_dma_attr_t smrt_dma_attr;

	/*
	 * Access to the I2O Registers:
	 */
	unsigned smrt_i2o_bar;
	caddr_t smrt_i2o_space;
	ddi_acc_handle_t smrt_i2o_handle;

	/*
	 * Access to the Configuration Table:
	 */
	unsigned smrt_ct_bar;
	uint32_t smrt_ct_baseaddr;
	CfgTable_t *smrt_ct;
	ddi_acc_handle_t smrt_ct_handle;
};

/*
 * Logical Volume Structure
 */
typedef enum smrt_volume_flags {
	SMRT_VOL_FLAG_WWN =			(0x1 << 0),
} smrt_volume_flags_t;

typedef struct smrt_volume {
	LogDevAddr_t smlv_addr;
	smrt_volume_flags_t smlv_flags;

	uint8_t smlv_wwn[16];

	smrt_t *smlv_ctlr;
	list_node_t smlv_link;

	/*
	 * List of SCSA targets currently attached to this Logical Volume:
	 */
	list_t smlv_targets;
} smrt_volume_t;

/*
 * Per-Target Structure
 */
typedef struct smrt_target {
	struct scsi_device *smtg_scsi_dev;
	boolean_t smtg_controller_target;

	/*
	 * Linkage back to the Logical Volume that this target represents:
	 */
	smrt_volume_t *smtg_volume;
	list_node_t smtg_link_volume;

	/*
	 * Linkage back to the controller:
	 */
	smrt_t *smtg_ctlr;
	list_node_t smtg_link_ctlr;
} smrt_target_t;

/*
 * DMA Resource Tracking Structure
 */
typedef enum smrt_dma_level {
	SMRT_DMALEVEL_HANDLE_ALLOC =		(0x1 << 0),
	SMRT_DMALEVEL_MEMORY_ALLOC =		(0x1 << 1),
	SMRT_DMALEVEL_HANDLE_BOUND =		(0x1 << 2),
} smrt_dma_level_t;

typedef struct smrt_dma {
	smrt_dma_level_t smdma_level;
	size_t smdma_real_size;
	ddi_dma_handle_t smdma_dma_handle;
	ddi_acc_handle_t smdma_acc_handle;
	ddi_dma_cookie_t smdma_dma_cookies[1];
	uint_t smdma_dma_ncookies;
} smrt_dma_t;


typedef struct smrt_command smrt_command_t;
typedef struct smrt_command_internal smrt_command_internal_t;
typedef struct smrt_command_scsa smrt_command_scsa_t;
typedef struct smrt_pkt smrt_pkt_t;

typedef enum smrt_command_status {
	/*
	 * When a command is submitted to the controller, it is marked USED
	 * to avoid accidental reuse of the command without reinitialising
	 * critical fields.  The submitted command is also marked INFLIGHT
	 * to reflect its inclusion in the "smrt_inflight" AVL tree.  When
	 * the command is completed by the controller, INFLIGHT is unset.
	 */
	SMRT_CMD_STATUS_USED =			(0x1 << 0),
	SMRT_CMD_STATUS_INFLIGHT =		(0x1 << 1),

	/*
	 * This flag is set during abort queue processing to record that this
	 * command was aborted in response to an expired timeout, and not some
	 * other cancellation.  If the controller is able to abort the command,
	 * we use this flag to let the SCSI framework know that the command
	 * timed out.
	 */
	SMRT_CMD_STATUS_TIMEOUT =		(0x1 << 2),

	/*
	 * The controller set the error bit when completing this command.
	 * Details of the particular fault may be read from the error
	 * information written by the controller.
	 */
	SMRT_CMD_STATUS_ERROR =			(0x1 << 3),

	/*
	 * This command has been abandoned by the original submitter.  This
	 * could happen if the command did not complete in a timely fashion.
	 * When it reaches the finish queue it will be freed without further
	 * processing.
	 */
	SMRT_CMD_STATUS_ABANDONED =		(0x1 << 4),

	/*
	 * This command has made it through the completion queue and had final
	 * processing performed.
	 */
	SMRT_CMD_STATUS_COMPLETE =		(0x1 << 5),

	/*
	 * A polled message will be ignored by the regular processing of the
	 * completion queue.  The blocking function doing the polling is
	 * responsible for watching the command on which it has set the POLLED
	 * flag.  Regular completion queue processing (which might happen in
	 * the polling function, or it might happen in the interrupt handler)
	 * will set POLL_COMPLETE once it is out of the finish queue
	 * altogether.
	 */
	SMRT_CMD_STATUS_POLLED =		(0x1 << 6),
	SMRT_CMD_STATUS_POLL_COMPLETE =		(0x1 << 7),

	/*
	 * An abort message has been sent to the controller in an attempt to
	 * cancel this command.
	 */
	SMRT_CMD_STATUS_ABORT_SENT =		(0x1 << 8),

	/*
	 * This command has been passed to our tran_start(9E) handler.
	 */
	SMRT_CMD_STATUS_TRAN_START =		(0x1 << 9),

	/*
	 * This command was for a SCSI command that we are explicitly avoiding
	 * sending to the controller.
	 */
	SMRT_CMD_STATUS_TRAN_IGNORED =		(0x1 << 10),

	/*
	 * This command has been submitted once, and subsequently passed to
	 * smrt_command_reuse().
	 */
	SMRT_CMD_STATUS_REUSED =		(0x1 << 11),

	/*
	 * A controller reset has been issued, so a response for this command
	 * is not expected.  If one arrives before the controller reset has
	 * taken effect, it likely cannot be trusted.
	 */
	SMRT_CMD_STATUS_RESET_SENT =		(0x1 << 12),
} smrt_command_status_t;

typedef enum smrt_command_type {
	SMRT_CMDTYPE_INTERNAL = 1,
	SMRT_CMDTYPE_ABORTQ,
	SMRT_CMDTYPE_SCSA,
	SMRT_CMDTYPE_PREINIT,
} smrt_command_type_t;

struct smrt_command {
	uint32_t smcm_tag;
	smrt_command_type_t smcm_type;
	smrt_command_status_t smcm_status;

	smrt_t *smcm_ctlr;
	smrt_target_t *smcm_target;

	list_node_t smcm_link;		/* Linkage for allocated list. */
	list_node_t smcm_link_finish;	/* Linkage for completion list. */
	list_node_t smcm_link_abort;	/* Linkage for abort list. */
	avl_node_t smcm_node;		/* Inflight AVL membership. */

	hrtime_t smcm_time_submit;
	hrtime_t smcm_time_complete;

	hrtime_t smcm_expiry;

	/*
	 * The time at which an abort message was sent to try and terminate
	 * this command, as well as the tag of the abort message itself:
	 */
	hrtime_t smcm_abort_time;
	uint32_t smcm_abort_tag;

	/*
	 * Ancillary data objects.  Only one of these will be allocated for any
	 * given command, but we nonetheless resist the temptation to use a
	 * union of pointers in order to make incorrect usage obvious.
	 */
	smrt_command_scsa_t *smcm_scsa;
	smrt_command_internal_t *smcm_internal;

	/*
	 * Physical allocation tracking for the actual command to send to the
	 * controller.
	 */
	smrt_dma_t smcm_contig;

	CommandList_t *smcm_va_cmd;
	uint32_t smcm_pa_cmd;

	ErrorInfo_t *smcm_va_err;
	uint32_t smcm_pa_err;
};

/*
 * Commands issued internally to the driver (as opposed to by the HBA
 * framework) generally require a buffer in which to assemble the command body,
 * and for receiving the response from the controller.  The following object
 * tracks this (optional) extra buffer.
 */
struct smrt_command_internal {
	smrt_dma_t smcmi_contig;

	void *smcmi_va;
	uint32_t smcmi_pa;
	size_t smcmi_len;
};

/*
 * Commands issued via the SCSI framework have a number of additional
 * properties.
 */
struct smrt_command_scsa {
	struct scsi_pkt *smcms_pkt;
	smrt_command_t *smcms_command;
};


/*
 * CISS transport routines.
 */
void smrt_periodic(void *);
void smrt_lockup_check(smrt_t *);
int smrt_submit(smrt_t *, smrt_command_t *);
void smrt_submit_simple(smrt_t *, smrt_command_t *);
int smrt_retrieve(smrt_t *);
void smrt_retrieve_simple(smrt_t *);
int smrt_poll_for(smrt_t *, smrt_command_t *);
int smrt_preinit_command_simple(smrt_t *, smrt_command_t *);

/*
 * Interrupt service routines.
 */
int smrt_interrupts_setup(smrt_t *);
int smrt_interrupts_enable(smrt_t *);
void smrt_interrupts_teardown(smrt_t *);
uint32_t smrt_isr_hw_simple(caddr_t, caddr_t);

/*
 * Interrupt enable/disable routines.
 */
void smrt_intr_set(smrt_t *, boolean_t);

/*
 * Controller initialisation routines.
 */
int smrt_ctlr_init(smrt_t *);
void smrt_ctlr_teardown(smrt_t *);
int smrt_ctlr_reset(smrt_t *);
int smrt_ctlr_wait_for_state(smrt_t *, smrt_wait_state_t);
int smrt_ctlr_init_simple(smrt_t *);
void smrt_ctlr_teardown_simple(smrt_t *);
int smrt_cfgtbl_flush(smrt_t *);
int smrt_cfgtbl_transport_has_support(smrt_t *, int);
void smrt_cfgtbl_transport_set(smrt_t *, int);
int smrt_cfgtbl_transport_confirm(smrt_t *, int);
uint32_t smrt_ctlr_get_cmdsoutmax(smrt_t *);
uint32_t smrt_ctlr_get_maxsgelements(smrt_t *);

/*
 * Device enumeration routines.
 */
int smrt_logvol_discover(smrt_t *, uint16_t);
void smrt_logvol_teardown(smrt_t *);
smrt_volume_t *smrt_logvol_lookup_by_id(smrt_t *, unsigned);
smrt_volume_t *smrt_logvol_lookup_by_addr(smrt_t *, struct scsi_address *);

/*
 * SCSI framework routines.
 */
int smrt_hba_setup(smrt_t *);
void smrt_hba_teardown(smrt_t *);

void smrt_hba_complete(smrt_command_t *);

void smrt_process_finishq(smrt_t *);
void smrt_process_abortq(smrt_t *);

/*
 * Command block management.
 */
smrt_command_t *smrt_command_alloc(smrt_t *, smrt_command_type_t,
    int);
smrt_command_t *smrt_command_alloc_preinit(smrt_t *, size_t, int);
int smrt_command_attach_internal(smrt_t *, smrt_command_t *, size_t,
    int);
void smrt_command_free(smrt_command_t *);
smrt_command_t *smrt_lookup_inflight(smrt_t *, uint32_t);
void smrt_command_reuse(smrt_command_t *);

/*
 * Device message construction routines.
 */
void smrt_write_lun_addr_phys(LUNAddr_t *, boolean_t, unsigned, unsigned);
void smrt_write_message_abort_one(smrt_command_t *, uint32_t);
void smrt_write_message_abort_all(smrt_command_t *, LogDevAddr_t *);
void smrt_write_message_nop(smrt_command_t *, int);

/*
 * Device management routines.
 */
int smrt_device_setup(smrt_t *);
void smrt_device_teardown(smrt_t *);
uint32_t smrt_get32(smrt_t *, offset_t);
void smrt_put32(smrt_t *, offset_t, uint32_t);


#ifdef	__cplusplus
}
#endif

#endif	/* _SMRT_H */
