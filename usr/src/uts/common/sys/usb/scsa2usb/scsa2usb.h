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
 *
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2016 Joyent, Inc.
 */

#ifndef _SYS_USB_SCSA2USB_H
#define	_SYS_USB_SCSA2USB_H


#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/usb/usba/usbai_private.h>

/*
 * SCSA2USB: This header file contains the internal structures
 * and variable definitions used in USB mass storage disk driver.
 */


#define	SCSA2USB_MAX_CLONE	256
#define	SCSA2USB_INITIAL_ALLOC	4	/* initial soft space alloc */

#define	MAX_COMPAT_NAMES	1	/* max compatible names for children */
#define	SERIAL_NUM_LEN		64	/* for reading string descriptor */
#define	SCSA2USB_SERIAL_LEN	12	/* len of serial no in scsi_inquiry */

#define	SCSA2USB_MAX_LUNS	0x10	/* maximum luns supported. */

/*
 * limit the max transfer size to under <= 64K. Some devices
 * have problems with large transfers
 */
#define	SCSA2USB_MAX_BULK_XFER_SIZE	(64 * 1024)

/* Blacklist some vendors whose devices could cause problems */
#define	MS_HAGIWARA_SYS_COM_VID	0x693	/* VendorId of Hagiwara Sys-Com */
#define	MS_HAGIWARA_SYSCOM_PID1	0x1	/* PID for SmartMedia(SM) device */
#define	MS_HAGIWARA_SYSCOM_PID2	0x3	/* PID for CompactFlash(CF) device */
#define	MS_HAGIWARA_SYSCOM_PID3	0x5	/* PID for SM/CF Combo device */
#define	MS_HAGIWARA_SYSCOM_PID4	0x2	/* PID for new SM device */
#define	MS_HAGIWARA_SYSCOM_PID5	0x4	/* PID for new CF device */

#define	MS_IOMEGA_VID		0x59b	/* VendorId of Iomega */
#define	MS_IOMEGA_PID1_ZIP100	0x1	/* PID of an Older Iomega Zip100 */
#define	MS_IOMEGA_PID2_ZIP100	0x2	/* PID of Newer Iomega Zip100 */
#define	MS_IOMEGA_PID3_ZIP100	0x31	/* PID of Newer Iomega Zip100 */
#define	MS_IOMEGA_PID_ZIP250	0x30	/* PID of Newer Iomega Zip250 */
#define	MS_IOMEGA_PID_CLIK	0x60	/* PID of Iomega Clik! drive */

#define	MS_MITSUMI_VID		0x3ee	/* VendorId of Mitsumi Inc */
#define	MS_MITSUMI_DEVICE_242	0x242	/* bcdDevice of Mitsumi CR-4804TU */
#define	MS_MITSUMI_DEVICE_24	0x24	/* bcdDevice of Mitsumi CR-4802TU */

#define	MS_YEDATA_VID		0x57b	/* VendorId of Y-E Data Corp */
#define	MS_SMSC_VID		0x424	/* Vendor Id of SMSC */
#define	MS_SMSC_PID0		0xfdc	/* floppy from SMSC */

#define	MS_NEODIO_VID		0xaec	/* Neodio Technologies Corporation */
#define	MS_NEODIO_DEVICE_3050	0x3050	/* PID of ND3050/Soyo BayOne */
					/* SM/CF/MS/SD */
#define	MS_SONY_FLASH_VID	0x54c	/* sony flash device */
#define	MS_SONY_FLASH_PID	0x8b

#define	MS_TREK_FLASH_VID	0xa16	/* Trek flash device */
#define	MS_TREK_FLASH_PID	0x9988

#define	MS_PENN_FLASH_VID	0xd7d	/* Penn flash device */
#define	MS_PENN_FLASH_PID	0x1320

#define	MS_SIMPLETECH_VID	0x7c4	/* VendorId of Simpltech */
#define	MS_SIMPLETECH_PID1	0xa400	/* PID for UCF-100 device */

#define	MS_ADDONICS_CARD_READER_VID 0x7cc /* addonics */
#define	MS_ADDONICS_CARD_READER_PID 0x320

#define	MS_ACOMDATA_VID		0xc0b	/* VendorId of DMI (Acomdata) */
#define	MS_ACOMDATA_PID1	0x5fab	/* PID for 80GB USB/1394 disk */

#define	MS_OTI_VID		0xea0	/* VendorID of OTI */
#define	MS_OTI_DEVICE_6828	0x6828	/* PID for 6828 flash disk */

#define	MS_SCANLOGIC_VID	0x04ce	/* VendorID of ScanLogic */
#define	MS_SCANLOGIC_PID1	0x0002	/* SL USB Storage Device */

#define	MS_SUPERTOP_VID		0x14cd	/* Super Top USB 2.0 IDE enclosure */
#define	MS_SUPERTOP_DEVICE_6600	0x6600

#define	MS_AIGO_VID		0xed1	/* VendorID of Aigo */
#define	MS_AIGO_DEVICE_6981	0x6981	/* Aigo Miniking Device NEHFSP14 */

#define	MS_ALCOR_VID	0x58f	/* Vendor ID of Alcor Micro Corp */
#define	MS_ALCOR_PID0	0x6387	/* PID for 6387 flash disk */

#define	MS_TOSHIBA_VID	0x930	/* Vendor ID of Toshiba Corp */
#define	MS_TOSHIBA_PID0	0x6545	/* Kingston DataTraveler / PNY Attache Stick */

#define	MS_PNY_VID	0x154b	/* Vendor ID of PNY Corp */
#define	MS_PNY_PID0	0x16	/* PNY floppy drive */

#define	MS_WD_VID	0x1058	/* Vendor ID of Western Digital */
#define	MS_WD_PID   0x1001  /* PID for Western Digital USB External HDD */

/*
 * The AMI virtual floppy device is not a real USB storage device, but
 * emulated by the SP firmware shipped together with important Sun x86
 * products such as Galaxy and Thumper platforms. The device causes
 * very long delay in boot process of these platforms which is a big
 * performance issue. Improvement in firmware may solve the issue, but
 * before the firmware is fixed, it needs to be taken care of by software
 * to avoid the huge impact on user experience.
 *
 * The long boot delay is caused by timeouts and retries of READ CAPACITY
 * command issued to the device. The device is a USB ufi subclass device
 * using CBI protocol. When READ CAPACITY command is issued, the device
 * returns STALL on the bulk endpoint during the data stage, however, it
 * doesn't return status on the intr pipe during status stage, so the intr
 * pipe can only fail with timeout.
 *
 * Reducing timeout value to 1 second can help a little bit, but the delay
 * is still noticeable, because the target driver would make many retries
 * for this command. It is not desirable to mess with the target driver
 * for a broken USB device. So adding the device to the scsa2usb blacklist
 * is the best choice we have.
 *
 * It is found that the READ CAPACITY failure only happens when there is
 * no media in the floppy drive. When there is a media, the device works
 * just fine. So READ CAPACITY command cannot be arbitrarily disabled.
 * Media status needs to be checked before issuing the command by sending
 * an additional TEST UNIT READY command. If TEST UNIT READY command
 * return STATUS_GOOD, it means the media is ready and then READ CAPACITY
 * can be issued.
 *
 * SCSA2USB_ATTRS_NO_MEDIA_CHECK is added below for this purpose. It is
 * overrided in scsa2usb.c for the AMI virtual floppy device to take care
 * of the special need.
 */
#define	MS_AMI_VID		0x46b	/* VendorId of AMI */
#define	MS_AMI_VIRTUAL_FLOPPY	0xff40	/* PID for AMI virtual floppy */

/*
 * List the attributes that need special case in the driver
 * SCSA2USB_ATTRS_GET_LUN: Bulk Only Transport Get_Max_Lun class specific
 *		command is not implemented by these devices
 * SCSA2USB_ATTRS_PM: Some devices don't like being power managed.
 * SCSA2USB_ATTRS_START_STOP: Some devices don't do anything with
 *		SCMD_START_STOP opcode (for e.g. SmartMedia/CompactFlash/
 *		Clik!/MemoryStick/MMC USB readers/writers.
 * SCSA2USB_ATTRS_GET_CONF: SCMD_GET_CONFIGURATION is not supported
 * SCMD_TEST_UNIT_READY: for floppies this needs to be converted to
 *		SCMD_START_STOP as floppies don't support this
 * SCSA2USB_ATTRS_GET_PERF: SCMD_GET_PERFORMANCE not supported by
 *		Mitsumi's CD-RW devices.
 * SCSA2USB_ATTRS_BIG_TIMEOUT: Mitsumi's CD-RW devices need large
 *		timeout with SCMD_START_STOP cmd
 * SCSA2USB_ATTRS_RMB: Pay attention to the device's RMB setting,
 *		instead of automatically treating it as removable
 * SCSA2USB_ATTRS_USE_CSW_RESIDUE: Some devices report false residue in
 *		the CSW of bulk-only transfer status stage though data
 *		was successfully transfered, so need to ignore residue.
 * SCSA2USB_ATTRS_NO_MEDIA_CHECK: AMI Virtual Floppy devices need to
 *		check if media is ready before issuing READ CAPACITY.
 * SCSA2USB_ATTRS_NO_CAP_ADJUST: Some devices return total logical block number
 * 		instead of highest logical block address on READ_CAPACITY cmd.
 *
 * NOTE: If a device simply STALLs the GET_MAX_LUN BO class-specific command
 * and recovers then it will not be added to the scsa2usb_blacklist[] table
 * in scsa2usb.c. The other attributes will not be taken of the table unless
 * their inclusion causes a recovery and retries (thus seriously affecting
 * the driver performance).
 */
#define	SCSA2USB_ATTRS_GET_LUN		0x01	/* GET_MAX_LUN (Bulk Only) */
#define	SCSA2USB_ATTRS_PM		0x02	/* Some don't support PM */
#define	SCSA2USB_ATTRS_START_STOP	0x04	/* SCMD_START_STOP */
#define	SCSA2USB_ATTRS_GET_CONF		0x08	/* SCMD_GET_CONFIGURATION */
#define	SCSA2USB_ATTRS_GET_PERF		0x10	/* SCMD_GET_PERFORMANCE */
#define	SCSA2USB_ATTRS_BIG_TIMEOUT	0x40	/* for SCMD_START_STOP */
#define	SCSA2USB_ATTRS_DOORLOCK		0x80	/* for SCMD_DOORLOCK */
#define	SCSA2USB_ATTRS_RMB		0x100	/* Pay attention to RMB */
#define	SCSA2USB_ATTRS_MODE_SENSE	0x200	/* SCMD_MODE_SENSE */
#define	SCSA2USB_ATTRS_INQUIRY		0x400	/* SCMD_INQUIRY */
#define	SCSA2USB_ATTRS_USE_CSW_RESIDUE	0x800	/* for residue checking */
#define	SCSA2USB_ATTRS_NO_MEDIA_CHECK	0x1000	/* for media checking */
#define	SCSA2USB_ATTRS_NO_CAP_ADJUST	0x2000	/* for CAPACITY adjusting */
#define	SCSA2USB_ATTRS_INQUIRY_EVPD	0x4000	/* SCMD_INQUIRY with evpd */
#define	SCSA2USB_ATTRS_REDUCED_CMD	\
	(SCSA2USB_ATTRS_DOORLOCK|SCSA2USB_ATTRS_MODE_SENSE| \
	SCSA2USB_ATTRS_START_STOP|SCSA2USB_ATTRS_INQUIRY| \
	SCSA2USB_ATTRS_USE_CSW_RESIDUE)

#define	SCSA2USB_ALL_ATTRS		0xFFFF	/* All of the above */

/* max inquiry length */
#define	SCSA2USB_MAX_INQ_LEN (offsetof(struct scsi_inquiry, inq_serial))

/* page code of scsi mode page */
#ifndef SD_MODE_SENSE_PAGE3_CODE
#define	SD_MODE_SENSE_PAGE3_CODE	0x03
#endif

#ifndef SD_MODE_SENSE_PAGE4_CODE
#define	SD_MODE_SENSE_PAGE4_CODE	0x04
#endif

#define	SD_MODE_SENSE_PAGE_MASK		0x3F

/*
 * PM support
 */
typedef struct scsa2usb_power  {
	/* device busy accounting */
	int		scsa2usb_pm_busy;
	/* this is the bit mask of the power states that device has */
	uint8_t		scsa2usb_pwr_states;

	uint8_t		scsa2usb_wakeup_enabled;

	/* current power level the device is in */
	uint8_t		scsa2usb_current_power;
} scsa2usb_power_t;

/*
 * CPR support:
 *	keep track of the last command issued to the drive. If it
 *	was TUR or EJECT then allow issuing a CPR suspend.
 */
#define	LOEJECT	2		/* eject bit in start/stop cmd */

typedef struct scsa2usb_last_cmd {
	/* this is the cdb of the last command issued */
	uchar_t		cdb[SCSI_CDB_SIZE];

	/* this is the status of the last command issued */
	uint_t		status;
} scsa2usb_last_cmd_t;

/*
 * override values
 *	These values may be set in scsa2usb.conf for particular devices
 */
typedef struct scsa2usb_ov {
	int	vid;		/* vendor id */
	int	pid;		/* product id */
	int	rev;		/* revision */
	int	subclass;	/* subclass override */
	int	protocol;	/* protocol override */
	int	pmoff;		/* power management override */
	int	fake_removable;	/* removable device override */
	int	no_modesense;	/* no mode sense */
				/* no modesense, doorlock, PM, start/stop */
	int	reduced_cmd_support;
} scsa2usb_ov_t;


/*
 * Per bulk device "state" data structure.
 */
typedef struct scsa2usb_state {
	int			scsa2usb_instance;	/* Instance number    */
	int			scsa2usb_dev_state;	/* USB device state   */
	int			scsa2usb_flags; 	/* Per instance flags */
	int			scsa2usb_intfc_num;	/* Interface number   */
	dev_info_t		*scsa2usb_dip;		/* Per device. info   */
	scsa2usb_power_t	*scsa2usb_pm;		/* PM state info */

	int			scsa2usb_transport_busy; /* ugen/sd traffic */
	int			scsa2usb_ugen_open_count;
	kcondvar_t		scsa2usb_transport_busy_cv;
	struct proc		*scsa2usb_busy_proc; /* owner of the hardware */

	kmutex_t		scsa2usb_mutex;		/* Per instance lock  */

	struct scsi_hba_tran	*scsa2usb_tran;		/* SCSI transport ptr */
	struct scsi_pkt		*scsa2usb_cur_pkt;	/* SCSI packet ptr    */

	usba_list_entry_t	scsa2usb_waitQ[SCSA2USB_MAX_LUNS];
							/* waitQ list */
	struct scsa2usb_cmd	*scsa2usb_arq_cmd;	/* ARQ cmd */
	struct buf		*scsa2usb_arq_bp;	/* ARQ buf */

	dev_info_t		*scsa2usb_lun_dip[SCSA2USB_MAX_LUNS];
						/* store devinfo per LUN  */
	struct scsi_inquiry	scsa2usb_lun_inquiry[SCSA2USB_MAX_LUNS];
						/* store inquiry per LUN  */
	usb_if_descr_t		scsa2usb_intfc_descr;	/* Interface descr    */
	usb_ep_xdescr_t		scsa2usb_bulkin_xept;	/* Bulk In descriptor */
	usb_ep_xdescr_t		scsa2usb_bulkout_xept;	/* Bulkout descriptor */
	usb_ep_xdescr_t		scsa2usb_intr_xept;	/* Intr ept descr */

	usb_pipe_handle_t	scsa2usb_default_pipe;	/* Default pipe	Hndle */
	usb_pipe_handle_t	scsa2usb_intr_pipe;	/* Intr polling Hndle */
	usb_pipe_handle_t	scsa2usb_bulkin_pipe;	/* Bulk Inpipe Handle */
	usb_pipe_handle_t	scsa2usb_bulkout_pipe;	/* Bulk Outpipe Hndle */

	uint_t			scsa2usb_pipe_state;	/* resetting state */
	uint_t			scsa2usb_tag;		/* current tag */
	uint_t			scsa2usb_pkt_state;	/* packet state */
	uint_t			scsa2usb_n_luns;	/* number of luns */

	usb_log_handle_t	scsa2usb_log_handle;	/* log handle */
	struct scsa2usb_cpr	*scsa2usb_panic_info;	/* for cpr info */

	size_t			scsa2usb_lbasize[SCSA2USB_MAX_LUNS];
							/* sector size */
	size_t			scsa2usb_totalsec[SCSA2USB_MAX_LUNS];
							/* total sectors */
	size_t			scsa2usb_secsz[SCSA2USB_MAX_LUNS];
							/* sector size */
	size_t			scsa2usb_max_bulk_xfer_size; /* from HCD */

	usb_client_dev_data_t	*scsa2usb_dev_data;	/* USB registration */
	scsa2usb_last_cmd_t	scsa2usb_last_cmd;	/* last/prev command */

	uint_t			scsa2usb_attrs;		/* for bad devices */
	uint_t			scsa2usb_cmd_protocol;	/* CMD protocol used */
	kthread_t		*scsa2usb_work_thread_id; /* handle commands */

				/* conf file override values */
	uint_t			scsa2usb_subclass_override;
	uint_t			scsa2usb_protocol_override;
	char			*scsa2usb_override_str;

				/* suppress repetitive disconnect warnings */
	boolean_t		scsa2usb_warning_given;

	boolean_t		scsa2usb_rcvd_not_ready; /* received NOT */
							/* READY sense data */

	usb_ugen_hdl_t		scsa2usb_ugen_hdl;	/* ugen support */

	uint8_t			scsa2usb_clones[SCSA2USB_MAX_CLONE];
} scsa2usb_state_t;

/*
 * These macros were added as part of updating scsa2usb to support USB 3.0 and
 * newer devices to minimize driver changes. There's no reason these can't be
 * expanded by someone who wants to.
 */
#define	scsa2usb_bulkin_ept	scsa2usb_bulkin_xept.uex_ep
#define	scsa2usb_bulkout_ept	scsa2usb_bulkout_xept.uex_ep
#define	scsa2usb_intr_ept	scsa2usb_intr_xept.uex_ep


/* for warlock */
_NOTE(MUTEX_PROTECTS_DATA(scsa2usb_state::scsa2usb_mutex, scsa2usb_state))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scsa2usb_state::scsa2usb_instance))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scsa2usb_state::scsa2usb_dip))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scsa2usb_state::scsa2usb_arq_cmd))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scsa2usb_state::scsa2usb_arq_bp))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scsa2usb_state::scsa2usb_intr_ept))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scsa2usb_state::scsa2usb_default_pipe))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scsa2usb_state::scsa2usb_intr_pipe))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scsa2usb_state::scsa2usb_bulkin_pipe))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scsa2usb_state::scsa2usb_log_handle))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scsa2usb_state::scsa2usb_intfc_num))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scsa2usb_state::scsa2usb_dev_data))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scsa2usb_state::scsa2usb_ugen_hdl))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scsa2usb_state::scsa2usb_pm))
_NOTE(SCHEME_PROTECTS_DATA("stable data", scsa2usb_power_t))
_NOTE(SCHEME_PROTECTS_DATA("stable data", scsi_hba_tran_t))
_NOTE(SCHEME_PROTECTS_DATA("unshared data", usb_bulk_req_t))

/* scsa2usb_pipe_state values */
#define	SCSA2USB_PIPE_NORMAL		0x00	/* no reset or clearing	*/
#define	SCSA2USB_PIPE_CLOSING		0x01	/* closing all pipes */
#define	SCSA2USB_PIPE_DEV_RESET		0x02	/* device specific reset */

/* pkt xfer state machine */
#define	SCSA2USB_PKT_NONE		0	/* device is idle */
#define	SCSA2USB_PKT_PROCESS_CSW	1	/* device doing status again */
#define	SCSA2USB_PKT_DO_COMP		2	/* device is done xfer */

/* scsa2usb_flags values */
#define	SCSA2USB_FLAGS_PIPES_OPENED	0x001	/* usb pipes are open */
#define	SCSA2USB_FLAGS_HBA_ATTACH_SETUP	0x002	/* scsi hba setup done */
#define	SCSA2USB_FLAGS_LOCKS_INIT	0x004	/* basic inits done */

/* scsa2usb_cmd_protocol values */
#define	SCSA2USB_UNKNOWN_PROTOCOL	0x0000	/* unknown wire protocol */
#define	SCSA2USB_CB_PROTOCOL		0x0001	/* CBI wire protocol */
#define	SCSA2USB_CBI_PROTOCOL		0x0002	/* CBI w/ intr wire protocol */
#define	SCSA2USB_BULK_ONLY_PROTOCOL	0x0004	/* Bulk Only wire protocol */

#define	SCSA2USB_SCSI_CMDSET		0x1000	/* SCSI command set followed */
#define	SCSA2USB_ATAPI_CMDSET		0x2000	/* ATAPI command set followed */
#define	SCSA2USB_UFI_CMDSET		0x4000	/* UFI command set followed */
#define	SCSA2USB_CMDSET_MASK		0x7000	/* OR al the above */

#define	SCSA2USB_IS_UFI_CMDSET(s) \
	(((s)->scsa2usb_cmd_protocol & SCSA2USB_UFI_CMDSET))
#define	SCSA2USB_IS_SCSI_CMDSET(s) \
	(((s)->scsa2usb_cmd_protocol & SCSA2USB_SCSI_CMDSET))
#define	SCSA2USB_IS_ATAPI_CMDSET(s) \
	(((s)->scsa2usb_cmd_protocol & SCSA2USB_ATAPI_CMDSET))

#define	SCSA2USB_IS_CB(s) \
	(((s)->scsa2usb_cmd_protocol & SCSA2USB_CB_PROTOCOL))

#define	SCSA2USB_IS_CBI(s) \
	(((s)->scsa2usb_cmd_protocol & SCSA2USB_CBI_PROTOCOL))

#define	SCSA2USB_IS_BULK_ONLY(s) \
	(((s)->scsa2usb_cmd_protocol & SCSA2USB_BULK_ONLY_PROTOCOL))

/* check if it is ok to access the device and send command to it */
#define	SCSA2USB_DEVICE_ACCESS_OK(s) \
	((s)->scsa2usb_dev_state == USB_DEV_ONLINE)

/* check if we are in any reset */
#define	SCSA2USB_IN_RESET(s) \
	(((s)->scsa2usb_pipe_state & SCSA2USB_PIPE_DEV_RESET) != 0)

/* check if the device is busy */
#define	SCSA2USB_BUSY(s) \
	(((s)->scsa2usb_cur_pkt) || \
	((s)->scsa2usb_pipe_state != SCSA2USB_PIPE_NORMAL) || \
	((s)->scsa2usb_pkt_state != SCSA2USB_PKT_NONE))

/* check if we're doing cpr */
#define	SCSA2USB_CHK_CPR(s) \
	(((s)->scsa2usb_dev_state == USB_DEV_SUSPENDED))

/* check if we're either paniced or in cpr state */
#define	SCSA2USB_CHK_PANIC_CPR(s) \
	(ddi_in_panic() || SCSA2USB_CHK_CPR(s))

/* reset scsa2usb state after pkt_comp is called */
#define	SCSA2USB_RESET_CUR_PKT(s) \
	(s)->scsa2usb_cur_pkt = NULL; \
	(s)->scsa2usb_pkt_state = SCSA2USB_PKT_NONE;

/* print a panic sync message to the console */
#define	SCSA2USB_PRINT_SYNC_MSG(m, s) \
	if ((m) == B_TRUE) { \
		USB_DPRINTF_L1(DPRINT_MASK_SCSA, (s)->scsa2usb_log_handle, \
		    "syncing not supported"); \
		(m) = B_FALSE; \
	}

/* Cancel callbacks registered during attach time */
#define	SCSA2USB_CANCEL_CB(id) \
	if ((id)) { \
		(void) callb_delete((id)); \
		(id) = 0; \
	}

/* Set SCSA2USB_PKT_DO_COMP state if there is active I/O */
#define	SCSA2USB_SET_PKT_DO_COMP_STATE(s) \
	if ((s)->scsa2usb_cur_pkt) { \
		(s)->scsa2usb_pkt_state = SCSA2USB_PKT_DO_COMP; \
	}

#define	SCSA2USB_FREE_MSG(data) \
	if ((data)) { \
		freemsg((data)); \
	}

#define	SCSA2USB_FREE_BULK_REQ(req) \
	if ((req)) { \
		usb_free_bulk_req((req));	/* Free request */ \
	}


/* SCSA related */
#define	ADDR2TRAN(ap)		((ap)->a_hba_tran)
#define	TRAN2SCSA2USB(tran)	((scsa2usb_state_t *)(tran)->tran_hba_private)
#define	ADDR2SCSA2USB(ap)	(TRAN2SCSA2USB(ADDR2TRAN(ap)))

#define	PKT_PRIV_LEN		16

#define	PKT_DEFAULT_TIMEOUT	5

/*
 * auto request sense
 */
#define	RQ_MAKECOM_COMMON(pktp, flag, cmd) \
	(pktp)->pkt_flags = (flag), \
	((union scsi_cdb *)(pktp)->pkt_cdbp)->scc_cmd = (cmd), \
	((union scsi_cdb *)(pktp)->pkt_cdbp)->scc_lun = \
	    (pktp)->pkt_address.a_lun

#define	RQ_MAKECOM_G0(pktp, flag, cmd, addr, cnt) \
	RQ_MAKECOM_COMMON((pktp), (flag), (cmd)), \
	FORMG0ADDR(((union scsi_cdb *)(pktp)->pkt_cdbp), (addr)), \
	FORMG0COUNT(((union scsi_cdb *)(pktp)->pkt_cdbp), (cnt))


/* transport related */
#define	SCSA2USB_JUST_ACCEPT	0
#define	SCSA2USB_TRANSPORT	1
#define	SCSA2USB_REJECT		-1

/*
 * The scsa2usb_cpr_info data structure is used for cpr related
 * callbacks. It is used for panic callbacks as well.
 */
typedef struct scsa2usb_cpr {
	callb_cpr_t		cpr;		/* for cpr related info */
	struct scsa2usb_state	*statep;	/* for scsa2usb state info */
	kmutex_t		lockp;		/* mutex used by cpr_info_t */
} scsa2usb_cpr_t;

_NOTE(DATA_READABLE_WITHOUT_LOCK(scsa2usb_cpr_t::cpr))
_NOTE(DATA_READABLE_WITHOUT_LOCK(scsa2usb_cpr_t::statep))

/*
 * The scsa2usb_cmd data structure is defined here. It gets
 * initialized per command that is sent to the device.
 */
typedef struct scsa2usb_cmd {
	struct scsi_pkt		*cmd_pkt;		/* copy of pkt ptr */
	struct	buf		*cmd_bp;		/* copy of bp ptr */
	size_t			cmd_xfercount;		/* current xfer count */
	size_t			cmd_resid_xfercount;	/* last xfer resid */
	int			cmd_scblen;		/* status length */
	int			cmd_tag;		/* tag */
	int			cmd_timeout;		/* copy of pkt_time */
	uchar_t			cmd_cdb[SCSI_CDB_SIZE];	/* CDB */
	uchar_t			cmd_dir;		/* direction */
	uchar_t			cmd_actual_len; 	/* cdb len */
	uchar_t			cmd_cdblen;		/* requested  cdb len */
	struct scsi_arq_status	cmd_scb;		/* status, w/ arq */

	/* used in multiple xfers */
	size_t			cmd_total_xfercount;	/* total xfer val */
	size_t			cmd_offset;		/* offset into buf */
	int			cmd_lba;		/* current xfer lba */
	int			cmd_done;		/* command done? */
	int			cmd_blksize;		/* block size */
	usba_list_entry_t	cmd_waitQ;		/* waitQ element */
} scsa2usb_cmd_t;

/* for warlock */
_NOTE(SCHEME_PROTECTS_DATA("unique per packet or safe sharing",
    scsi_cdb scsi_status scsi_pkt buf scsa2usb_cmd scsi_arq_status))
_NOTE(SCHEME_PROTECTS_DATA("stable data", scsi_device scsi_address))

/* scsa2usb_cdb position of fields in CDB */
#define	SCSA2USB_OPCODE		0		/* Opcode field */
#define	SCSA2USB_LUN		1		/* LUN field */
#define	SCSA2USB_LBA_0		2		/* LBA[0] field */
#define	SCSA2USB_LBA_1		3		/* LBA[1] field */
#define	SCSA2USB_LBA_2		4		/* LBA[2] field */
#define	SCSA2USB_LBA_3		5		/* LBA[3] field */
#define	SCSA2USB_LEN_0		7		/* LEN[0] field */
#define	SCSA2USB_LEN_1		8		/* LEN[1] field */

/* macros to calculate LBA for 6/10/12-byte commands */
#define	SCSA2USB_LBA_6BYTE(pkt) \
	(((pkt)->pkt_cdbp[1] & 0x1f) << 16) + \
	((pkt)->pkt_cdbp[2] << 8) + (pkt)->pkt_cdbp[3]
#define	SCSA2USB_LEN_6BYTE(pkt)		(pkt)->pkt_cdbp[4]

#define	SCSA2USB_LEN_10BYTE(pkt) \
	((pkt)->pkt_cdbp[7] << 8) + (pkt)->pkt_cdbp[8]
#define	SCSA2USB_LBA_10BYTE(pkt) \
	((pkt)->pkt_cdbp[2] << 24) + ((pkt)->pkt_cdbp[3] << 16) + \
	    ((pkt)->pkt_cdbp[4] << 8) +  (pkt)->pkt_cdbp[5]

#define	SCSA2USB_LEN_12BYTE(pkt) \
	((pkt)->pkt_cdbp[6] << 24) + ((pkt)->pkt_cdbp[7] << 16) + \
	    ((pkt)->pkt_cdbp[8] << 8) +  (pkt)->pkt_cdbp[9]
#define	SCSA2USB_LBA_12BYTE(pkt) \
	((pkt)->pkt_cdbp[2] << 24) + ((pkt)->pkt_cdbp[3] << 16) + \
	    ((pkt)->pkt_cdbp[4] << 8) +  (pkt)->pkt_cdbp[5]

/* macros to convert a pkt to cmd and vice-versa */
#define	PKT2CMD(pkt)		((scsa2usb_cmd_t *)(pkt)->pkt_ha_private)
#define	CMD2PKT(sp)		((sp)->cmd_pkt

/* bulk pipe default timeout value - how long the command to be tried? */
#define	SCSA2USB_BULK_PIPE_TIMEOUT	(2 * USB_PIPE_TIMEOUT)

/* drain timeout in seconds on the work thread */
#define	SCSA2USB_DRAIN_TIMEOUT		60

/* scsa2usb pkt xfer status phase retry times */
#define	SCSA2USB_STATUS_RETRIES		3

/*
 * limit on the number of requests that can be queued per LUN:
 * 3 for untagged queueing, 1 for scsiwatch and a margin of 2
 */
#define	SCSA2USB_MAX_REQ_PER_LUN	6

/*
 * The following data structure is used to save the values returned
 * by the READ_CAPACITY command. lba is the max allowed logical block
 * address and blen is max allowed block size.
 */
typedef struct scsa2usb_read_cap {
	uchar_t	scsa2usb_read_cap_lba3;		/* Max lba supported */
	uchar_t	scsa2usb_read_cap_lba2;
	uchar_t	scsa2usb_read_cap_lba1;
	uchar_t	scsa2usb_read_cap_lba0;
	uchar_t	scsa2usb_read_cap_blen3;	/* Max block size supported */
	uchar_t	scsa2usb_read_cap_blen2;
	uchar_t	scsa2usb_read_cap_blen1;
	uchar_t	scsa2usb_read_cap_blen0;
} scsa2usb_read_cap_t;

#define	SCSA2USB_MK_32BIT(a, b, c, d) \
		(((a) << 24) | ((b) << 16) | ((c) << 8) | (d))

/* position of fields for SCMD_READ_CD CDB */
#define	SCSA2USB_READ_CD_LEN_0	6	/* LEN[0] of SCMD_READ_CD */
#define	SCSA2USB_READ_CD_LEN_1	7	/* LEN[1] of SCMD_READ_CD */
#define	SCSA2USB_READ_CD_LEN_2	8	/* LEN[2] of SCMD_READ_CD */

/* macro to calculate LEN for SCMD_READ_CD command */
#define	SCSA2USB_LEN_READ_CD(pkt) \
	(((pkt)->pkt_cdbp[SCSA2USB_READ_CD_LEN_0] << 16) +\
	    ((pkt)->pkt_cdbp[SCSA2USB_READ_CD_LEN_1] << 8) +\
	    (pkt)->pkt_cdbp[SCSA2USB_READ_CD_LEN_2])

/* Figure out Block Size before issuing a WRITE to CD-RW device */
#define	SCSA2USB_CDRW_BLKSZ(bcount, len)	((bcount) / (len));
#define	SCSA2USB_VALID_CDRW_BLKSZ(blksz) \
	(((blksz) == CDROM_BLK_2048) || ((blksz) == CDROM_BLK_2352) || \
	((blksz) == CDROM_BLK_2336) || ((blksz) == CDROM_BLK_2324) || \
	((blksz) == 0))

/* debug and error msg logging */
#define	DPRINT_MASK_SCSA	0x0001		/* for SCSA */
#define	DPRINT_MASK_ATTA	0x0002		/* for ATTA */
#define	DPRINT_MASK_EVENTS	0x0004		/* for event handling */
#define	DPRINT_MASK_CALLBACKS	0x0008		/* for callbacks  */
#define	DPRINT_MASK_TIMEOUT	0x0010		/* for timeouts */
#define	DPRINT_MASK_DUMPING	0x0020		/* for dumping */
#define	DPRINT_MASK_PM		0x0040		/* for pwr mgmt */
#define	DPRINT_MASK_ALL		0xffffffff	/* for everything */

#ifdef	DEBUG
#define	SCSA2USB_PRINT_CDB	scsa2usb_print_cdb
#else
#define	SCSA2USB_PRINT_CDB	0 &&
#endif

/* ugen support */
#define	SCSA2USB_MINOR_UGEN_BITS_MASK	0xff
#define	SCSA2USB_MINOR_INSTANCE_MASK	~SCSA2USB_MINOR_UGEN_BITS_MASK
#define	SCSA2USB_MINOR_INSTANCE_SHIFT	8

#define	SCSA2USB_MINOR_TO_INSTANCE(minor)	\
		(((minor) & SCSA2USB_MINOR_INSTANCE_MASK) >> \
		SCSA2USB_MINOR_INSTANCE_SHIFT)

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_SCSA2USB_H */
