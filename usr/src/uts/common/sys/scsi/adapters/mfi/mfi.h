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

#ifndef	_MFI_H
#define	_MFI_H

#include <sys/bitext.h>
#include <sys/debug.h>
#include <sys/stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Forward declaration of various types defined by the MFI headers.
 */
typedef struct mfi_drv_ver		mfi_drv_ver_t;
typedef struct mfi_pci_info		mfi_pci_info_t;
typedef struct mfi_ioctl		mfi_ioctl_t;

typedef union mfi_cap			mfi_cap_t;
typedef union mfi_sgl			mfi_sgl_t;
typedef struct mfi_header		mfi_header_t;
typedef	struct mfi_init_payload		mfi_init_payload_t;
typedef struct mfi_io_payload		mfi_io_payload_t;
typedef struct mfi_pthru_payload	mfi_pthru_payload_t;
typedef struct mfi_dcmd_payload		mfi_dcmd_payload_t;
typedef struct mfi_abort_payload	mfi_abort_payload_t;
typedef struct mfi_frame		mfi_frame_t;

typedef struct mfi_array		mfi_array_t;
typedef struct mfi_spare		mfi_spare_t;

typedef struct mfi_ld_config		mfi_ld_config_t;
typedef struct mfi_ld_info		mfi_ld_info_t;
typedef struct mfi_ld_list		mfi_ld_list_t;
typedef struct mfi_ld_parameters	mfi_ld_parameters_t;
typedef struct mfi_ld_progress		mfi_ld_progress_t;
typedef struct mfi_ld_properties	mfi_ld_properties_t;
typedef struct mfi_ld_ref		mfi_ld_ref_t;
typedef struct mfi_ld_tgtid_list	mfi_ld_tgtid_list_t;
typedef struct mfi_span			mfi_span_t;

typedef struct mfi_config_data		mfi_config_data_t;

typedef struct mfi_pd_ref		mfi_pd_ref_t;
typedef struct mfi_pd_info		mfi_pd_info_t;
typedef struct mfi_pd_cfg		mfi_pd_cfg_t;
typedef struct mfi_pd_map		mfi_pd_map_t;
typedef struct mfi_pd_addr		mfi_pd_addr_t;
typedef struct mfi_pd_list		mfi_pd_list_t;

typedef struct mfi_ctrl_props		mfi_ctrl_props_t;
typedef struct mfi_image_comp		mfi_image_comp_t;
typedef struct mfi_ctrl_info		mfi_ctrl_info_t;

typedef struct mfi_bbu_capacity		mfi_bbu_capacity_t;
typedef struct mfi_bbu_design_info	mfi_bbu_design_info_t;
typedef struct mfi_bbu_properties	mfi_bbu_properties_t;
typedef struct mfi_ibbu_state		mfi_ibbu_state_t;
typedef struct mfi_bbu_state		mfi_bbu_state_t;
typedef struct mfi_bbu_status		mfi_bbu_status_t;

typedef struct mfi_pr_properties	mfi_pr_properties_t;
typedef struct mfi_pr_status		mfi_pr_status_t;

typedef struct mfi_progress		mfi_progress_t;

/*
 * MegaRAID Firmware Interface
 *
 * MFI stands for MegaRAID Firmware Interface. This is just a moniker
 * for the protocol between the software and the firmware. Commands are
 * issued using "message frames".
 */

#define	MFI_MAX_LOGICAL_DRIVES		64
#define	MFI_MAX_PHYSICAL_DRIVES		256

/*
 * During FW init, clear pending cmds & reset state using the doorbell register
 *
 * ABORT:		Abort all pending cmds
 * READY:		Move from OPERATIONAL to READY state; discard queue info
 * MFIMODE:		Discard (possible) low MFA posted in 64-bit mode (??)
 * CLEAR_HANDSHAKE:	FW is waiting for HANDSHAKE from BIOS or Driver
 * HOTPLUG:		Resume from Hotplug
 * MFI_STOP_ADP:	Send signal to FW to stop processing
 */
#define	MFI_INIT_ABORT				0x00000001
#define	MFI_INIT_READY				0x00000002
#define	MFI_INIT_MFIMODE			0x00000004
#define	MFI_INIT_CLEAR_HANDSHAKE		0x00000008
#define	MFI_INIT_HOTPLUG			0x00000010
#define	MFI_STOP_ADP				0x00000020
#define	MFI_RESET_FLAGS	(MFI_INIT_READY | MFI_INIT_MFIMODE | MFI_INIT_ABORT)

/*
 * MFI frame flags
 */
#define	MFI_FRAME_DONT_POST_IN_REPLY_QUEUE	0x0001
#define	MFI_FRAME_SGL64				0x0002
#define	MFI_FRAME_SENSE64			0x0004
#define	MFI_FRAME_DIR_NONE			0
#define	MFI_FRAME_DIR_WRITE			0x0008
#define	MFI_FRAME_DIR_READ			0x0010
#define	MFI_FRAME_DIR_BOTH			0x0018
#define	MFI_FRAME_IEEE				0x0020

/*
 * MFI command opcodes
 */
#define	MFI_CMD_INIT				0x00
#define	MFI_CMD_LD_READ				0x01
#define	MFI_CMD_LD_WRITE			0x02
#define	MFI_CMD_LD_SCSI_IO			0x03
#define	MFI_CMD_PD_SCSI_IO			0x04
#define	MFI_CMD_DCMD				0x05
#define	MFI_CMD_ABORT				0x06
#define	MFI_CMD_SMP				0x07
#define	MFI_CMD_STP				0x08
#define	MFI_CMD_INVALID				0xff

/*
 * MFI command status completion codes
 */
#define	MFI_STAT_OK				0x00
#define	MFI_STAT_INVALID_CMD			0x01
#define	MFI_STAT_INVALID_DCMD			0x02
#define	MFI_STAT_INVALID_PARAMETER		0x03
#define	MFI_STAT_INVALID_SEQUENCE_NUMBER	0x04
#define	MFI_STAT_ABORT_NOT_POSSIBLE		0x05
#define	MFI_STAT_APP_HOST_CODE_NOT_FOUND	0x06
#define	MFI_STAT_APP_IN_USE			0x07
#define	MFI_STAT_APP_NOT_INITIALIZED		0x08
#define	MFI_STAT_ARRAY_INDEX_INVALID		0x09
#define	MFI_STAT_ARRAY_ROW_NOT_EMPTY		0x0a
#define	MFI_STAT_CONFIG_RESOURCE_CONFLICT	0x0b
#define	MFI_STAT_DEVICE_NOT_FOUND		0x0c
#define	MFI_STAT_DRIVE_TOO_SMALL		0x0d
#define	MFI_STAT_FLASH_ALLOC_FAIL		0x0e
#define	MFI_STAT_FLASH_BUSY			0x0f
#define	MFI_STAT_FLASH_ERROR			0x10
#define	MFI_STAT_FLASH_IMAGE_BAD		0x11
#define	MFI_STAT_FLASH_IMAGE_INCOMPLETE		0x12
#define	MFI_STAT_FLASH_NOT_OPEN			0x13
#define	MFI_STAT_FLASH_NOT_STARTED		0x14
#define	MFI_STAT_FLUSH_FAILED			0x15
#define	MFI_STAT_HOST_CODE_NOT_FOUNT		0x16
#define	MFI_STAT_LD_CC_IN_PROGRESS		0x17
#define	MFI_STAT_LD_INIT_IN_PROGRESS		0x18
#define	MFI_STAT_LD_LBA_OUT_OF_RANGE		0x19
#define	MFI_STAT_LD_MAX_CONFIGURED		0x1a
#define	MFI_STAT_LD_NOT_OPTIMAL			0x1b
#define	MFI_STAT_LD_RBLD_IN_PROGRESS		0x1c
#define	MFI_STAT_LD_RECON_IN_PROGRESS		0x1d
#define	MFI_STAT_LD_WRONG_RAID_LEVEL		0x1e
#define	MFI_STAT_MAX_SPARES_EXCEEDED		0x1f
#define	MFI_STAT_MEMORY_NOT_AVAILABLE		0x20
#define	MFI_STAT_MFC_HW_ERROR			0x21
#define	MFI_STAT_NO_HW_PRESENT			0x22
#define	MFI_STAT_NOT_FOUND			0x23
#define	MFI_STAT_NOT_IN_ENCL			0x24
#define	MFI_STAT_PD_CLEAR_IN_PROGRESS		0x25
#define	MFI_STAT_PD_TYPE_WRONG			0x26
#define	MFI_STAT_PR_DISABLED			0x27
#define	MFI_STAT_ROW_INDEX_INVALID		0x28
#define	MFI_STAT_SAS_CONFIG_INVALID_ACTION	0x29
#define	MFI_STAT_SAS_CONFIG_INVALID_DATA	0x2a
#define	MFI_STAT_SAS_CONFIG_INVALID_PAGE	0x2b
#define	MFI_STAT_SAS_CONFIG_INVALID_TYPE	0x2c
#define	MFI_STAT_SCSI_DONE_WITH_ERROR		0x2d
#define	MFI_STAT_SCSI_IO_FAILED			0x2e
#define	MFI_STAT_SCSI_RESERVATION_CONFLICT	0x2f
#define	MFI_STAT_SHUTDOWN_FAILED		0x30
#define	MFI_STAT_TIME_NOT_SET			0x31
#define	MFI_STAT_WRONG_STATE			0x32
#define	MFI_STAT_LD_OFFLINE			0x33
#define	MFI_STAT_PEER_NOTIFICATION_REJECTED	0x34
#define	MFI_STAT_PEER_NOTIFICATION_FAILED	0x35
#define	MFI_STAT_RESERVATION_IN_PROGRESS	0x36
#define	MFI_STAT_I2C_ERRORS_DETECTED		0x37
#define	MFI_STAT_PCI_ERRORS_DETECTED		0x38
#define	MFI_STAT_CONFIG_SEQ_MISMATCH		0x67

#define	MFI_STAT_INVALID_STATUS			0xFF

/*
 * MFI DCMDs
 */
#define	MFI_DCMD_CTRL_GET_INFO			0x01010000
#define	MFI_DCMD_CTRL_GET_PROPS			0x01020100
#define	MFI_DCMD_CTRL_SET_PROPS			0x01020200
#define	MFI_DCMD_CTRL_EVENT_GET_INFO		0x01040100
#define	MFI_DCMD_CTRL_EVENT_GET			0x01040300
#define	MFI_DCMD_CTRL_EVENT_WAIT		0x01040500
#define	MFI_DCMD_CTRL_SHUTDOWN			0x01050000
#define	MFI_DCMD_PR_GET_STATUS			0x01070100
#define	MFI_DCMD_PR_GET_PROPERTIES		0x01070200
#define	MFI_DCMD_PR_SET_PROPERTIES		0x01070300
#define	MFI_DCMD_PR_START			0x01070400
#define	MFI_DCMD_PR_STOP			0x01070500
#define	MFI_DCMD_TIME_SECS_GET			0x01080201
#define	MFI_DCMD_FLASH_FW_OPEN			0x010f0100
#define	MFI_DCMD_FLASH_FW_DOWNLOAD		0x010f0200
#define	MFI_DCMD_FLASH_FW_FLASH			0x010f0300
#define	MFI_DCMD_FLASH_FW_CLOSE			0x010f0400
#define	MFI_DCMD_SYSTEM_PD_MAP_GET_INFO		0x0200e102
#define	MFI_DCMD_PD_GET_LIST			0x02010000
#define	MFI_DCMD_PD_LIST_QUERY			0x02010100
#define	MFI_DCMD_PD_GET_INFO			0x02020000
#define	MFI_DCMD_PD_STATE_SET			0x02030100
#define	MFI_DCMD_PD_REBUILD_START		0x02040100
#define	MFI_DCMD_PD_REBUILD_ABORT		0x02040200
#define	MFI_DCMD_PD_CLEAR_START			0x02050100
#define	MFI_DCMD_PD_CLEAR_ABORT			0x02050200
#define	MFI_DCMD_PD_LOCATE_START		0x02070100
#define	MFI_DCMD_PD_LOCATE_STOP			0x02070200
#define	MFI_DCMD_LD_MAP_GET_INFO		0x0300e101
#define	MFI_DCMD_LD_GET_LIST			0x03010000
#define	MFI_DCMD_LD_GET_INFO			0x03020000
#define	MFI_DCMD_LD_GET_PROP			0x03030000
#define	MFI_DCMD_LD_SET_PROP			0x03040000
#define	MFI_DCMD_LD_LIST_QUERY			0x03010100
#define	MFI_DCMD_LD_DELETE			0x03090000
#define	MFI_DCMD_CFG_READ			0x04010000
#define	MFI_DCMD_CFG_ADD			0x04020000
#define	MFI_DCMD_CFG_CLEAR			0x04030000
#define	MFI_DCMD_CFG_MAKE_SPARE			0x04040000
#define	MFI_DCMD_CFG_REMOVE_SPARE		0x04050000
#define	MFI_DCMD_CFG_FOREIGN_SCAN		0x04060100
#define	MFI_DCMD_CFG_FOREIGN_DISPLAY		0x04060200
#define	MFI_DCMD_CFG_FOREIGN_PREVIEW		0x04060300
#define	MFI_DCMD_CFG_FOREIGN_IMPORT		0x04060400
#define	MFI_DCMD_CFG_FOREIGN_CLEAR		0x04060500
#define	MFI_DCMD_BBU_GET_STATUS			0x05010000
#define	MFI_DCMD_BBU_GET_CAPACITY_INFO		0x05020000
#define	MFI_DCMD_BBU_GET_DESIGN_INFO		0x05030000
#define	MFI_DCMD_BBU_START_LEARN		0x05040000
#define	MFI_DCMD_BBU_GET_PROP			0x05050100
#define	MFI_DCMD_BBU_SET_PROP			0x05050200

#define	MFI_BBU_TYPE_NONE			0
#define	MFI_BBU_TYPE_IBBU			1
#define	MFI_BBU_TYPE_BBU			2

#define	MFI_PR_STATE_STOPPED			0
#define	MFI_PR_STATE_READY			1
#define	MFI_PR_STATE_ACTIVE			2
#define	MFI_PR_STATE_ABORTED			3

#define	MFI_PR_OPMODE_AUTO			0
#define	MFI_PR_OPMODE_MANUAL			1
#define	MFI_PR_OPMODE_DISABLED			2

#define	MFI_PD_QUERY_TYPE_ALL			0
#define	MFI_PD_QUERY_TYPE_STATE			1
#define	MFI_PD_QUERY_TYPE_POWER_STATE		2
#define	MFI_PD_QUERY_TYPE_MEDIA_TYPE		3
#define	MFI_PD_QUERY_TYPE_SPEED			4
#define	MFI_PD_QUERY_TYPE_EXPOSED_TO_HOST	5

#define	MFI_LD_QUERY_TYPE_ALL			0
#define	MFI_LD_QUERY_TYPE_EXPOSED_TO_HOST	1
#define	MFI_LD_QUERY_TYPE_USED_TGT_IDS		2
#define	MFI_LD_QUERY_TYPE_CLUSTER_ACCESS	3
#define	MFI_LD_QUERY_TYPE_CLUSTER_LOCALE	4

#define	MFI_DCMD_MBOX_PEND_FLAG	0x01

#pragma pack(1)

union mfi_cap {
	struct {
		uint32_t mc_support_fp_remote_lun:1;
		uint32_t mc_support_additional_msix:1;
		uint32_t mc_support_fastpath_wb:1;
		uint32_t mc_support_max_255lds:1;
		uint32_t mc_support_ndrive_r1_lb:1;
		uint32_t mc_support_core_affinity:1;
		uint32_t mc_support_security_protocol_cmds_fw:1;
		uint32_t mc_support_ext_queue_depth:1;
		uint32_t mc_support_ext_io_size:1;
		uint32_t mc_reserved:23;
	};
	uint32_t	mc_reg;
};
CTASSERT(sizeof (mfi_cap_t) == 4);

union mfi_sgl {
	struct {
		uint32_t	ms32_phys_addr;
		uint32_t	ms32_length;
	};
	struct {
		uint64_t	ms64_phys_addr;
		uint32_t	ms64_length;
	};
};

struct mfi_header {
	uint8_t		mh_cmd;				/* 0x00 */
	uint8_t		mh_sense_len;			/* 0x01 */
	uint8_t		mh_cmd_status;			/* 0x02 */
	uint8_t		mh_scsi_status;			/* 0x03 */

	union {
		mfi_cap_t	mh_drv_opts;		/* 0x04 */
		struct {
			uint8_t	mh_target_id;		/* 0x04 */
			union {
				uint8_t	mh_lun;		/* 0x05 */
				uint8_t mh_access_byte;	/* 0x05 */
			};
			uint8_t mh_cdb_len;		/* 0x06 */
			uint8_t mh_sge_count;		/* 0x07 */
		};
	};

	uint32_t	mh_context;			/* 0x08 */
	uint32_t	mh_pad_0;			/* 0x0c */

	uint16_t	mh_flags;			/* 0x10 */
	uint16_t	mh_timeout;			/* 0x12 */
	union {
		uint32_t mh_data_xfer_len;		/* 0x14 */
		uint32_t mh_lba_count;			/* 0x14 */
	};
};

struct mfi_init_payload {
	uint64_t	mi_queue_info_new_phys_addr;	/* 0x18 */
	uint64_t	mi_queue_info_old_phys_addr;	/* 0x20 */
	uint64_t	mi_driver_ver_phys_addr;	/* 0x28 */
};

struct mfi_io_payload {
	uint64_t	mio_sense_buf_phys_addr;	/* 0x18 */
	uint64_t	mio_start_lba;			/* 0x20 */
	mfi_sgl_t	mio_sgl;			/* 0x28 */
};

struct mfi_pthru_payload {
	uint64_t	mp_sense_buf_phys_addr;		/* 0x18 */
	uint8_t		mp_cdb[16];			/* 0x20 */
	mfi_sgl_t	mp_sgl;				/* 0x30 */
};

struct mfi_dcmd_payload {
	uint32_t	md_opcode;			/* 0x18 */

	union {						/* 0x1c */
		uint8_t		md_mbox_8[12];
		uint16_t	md_mbox_16[6];
		uint32_t	md_mbox_32[3];
	};

	mfi_sgl_t	md_sgl;				/* 0x28 */
};

struct mfi_abort_payload {
	uint32_t	ma_abort_context;		/* 0x18 */
	uint32_t	ma_pad_1;			/* 0x1c */
	uint64_t	ma_abort_mfi_phys_addr;		/* 0x20 */
};

struct mfi_frame {
	mfi_header_t	mf_hdr;
	union {
		mfi_init_payload_t	mf_init;
		mfi_io_payload_t	mf_io;
		mfi_pthru_payload_t	mf_pthru;
		mfi_dcmd_payload_t	mf_dcmd;
		mfi_abort_payload_t	mf_abort;
		uint8_t mf_raw[64 - sizeof (mfi_header_t)];
	};
};
CTASSERT(offsetof(mfi_frame_t, mf_init) == 0x18);
CTASSERT(sizeof (mfi_frame_t) == 64);


/*
 * MFI controller properties
 */
struct mfi_ctrl_props {
	uint16_t cp_seq_num;
	uint16_t cp_pred_fail_poll_interval;
	uint16_t cp_intr_throttle_count;
	uint16_t cp_intr_throttle_timeouts;
	uint8_t cp_rebuild_rate;
	uint8_t cp_patrol_read_rate;
	uint8_t cp_bgi_rate;
	uint8_t cp_cc_rate;
	uint8_t cp_recon_rate;
	uint8_t cp_cache_flush_interval;
	uint8_t cp_spinup_drv_count;
	uint8_t cp_spinup_delay;
	uint8_t cp_cluster_enable;
	uint8_t cp_coercion_mode;
	uint8_t cp_alarm_enable;
	uint8_t cp_disable_auto_rebuild;
	uint8_t cp_disable_battery_warn;
	uint8_t cp_ecc_bucket_size;
	uint16_t cp_ecc_bucket_leak_rate;
	uint8_t cp_restore_hotspare_on_insertion;
	uint8_t cp_expose_encl_devices;
	uint8_t cp_maintain_pd_fail_history;
	uint8_t cp_disallow_host_request_reordering;
	uint8_t cp_abort_cc_on_error;
	uint8_t cp_load_balance_mode;
	uint8_t cp_disable_auto_detect_backplane;
	uint8_t cp_snap_vd_space;

	struct {
		uint32_t cp_copy_back_disabled:1;
		uint32_t cp_smarter_enabled:1;
		uint32_t cp_pr_correct_unconfigured_areas:1;
		uint32_t cp_use_FDE_only:1;
		uint32_t cp_disable_NCQ:1;
		uint32_t cp_SSD_smarter_enabled:1;
		uint32_t cp_SSD_patrol_read_enabled:1;
		uint32_t cp_enable_spin_down_unconfigured:1;
		uint32_t cp_auto_enhanced_import:1;
		uint32_t cp_enable_secret_key_control:1;
		uint32_t cp_disable_online_ctrl_reset:1;
		uint32_t cp_allow_boot_with_pinned_cache:1;
		uint32_t cp_disable_spin_down_HS:1;
		uint32_t cp_enable_JBOD:1;
		uint32_t cp_disable_cache_bypass:1;
		uint32_t cp_use_disk_activity_for_locate:1;
		uint32_t cp_enable_PI:1;
		uint32_t cp_prevent_PI_import:1;
		uint32_t cp_use_global_spares_for_emergency:1;
		uint32_t cp_use_unconf_good_for_emergency:1;
		uint32_t cp_use_emergency_spares_for_smarter:1;
		uint32_t cp_force_sgpio_for_quad_only:1;
		uint32_t cp_enable_config_auto_balance:1;
		uint32_t cp_enable_virtual_cache:1;
		uint32_t cp_enable_auto_lock_recovery:1;
		uint32_t cp_disable_immediate_io:1;
		uint32_t cp_disable_T10_rebuild_assist:1;
		uint32_t cp_ignore64_ld_restriction:1;
		uint32_t cp_enable_sw_zone:1;
		uint32_t cp_limit_max_rate_SATA_3G:1;
		uint32_t cp_reserved:2;
	};
	uint8_t cp_auto_snap_vd_space;
	uint8_t cp_view_space;
	uint16_t cp_spin_down_time;
	uint8_t cp_reserved2[24];
};
CTASSERT(sizeof (mfi_ctrl_props_t) == 64);

/*
 * MFI firmware image component
 */
struct mfi_image_comp {
	char ic_name[8];
	char ic_version[32];
	char ic_build_date[16];
	char ic_build_time[16];
};
CTASSERT(sizeof (mfi_image_comp_t) == 72);

/*
 * MFI controller information
 */
struct mfi_ctrl_info {
	/* PCI device information */
	struct {
		uint16_t pci_vendor_id;
		uint16_t pci_device_id;
		uint16_t pci_sub_vendor_id;
		uint16_t pci_sub_device_id;
		uint8_t pci_reserved[24];
	} ci_pci;

	/* Host interface information */
	struct {
		uint8_t hi_PCIX:1;
		uint8_t hi_PCIE:1;
		uint8_t hi_iSCSI:1;
		uint8_t hi_SAS_3G:1;
		uint8_t hi_reserved_0:4;
		uint8_t hi_reserved_1[6];
		uint8_t hi_port_count;
		uint64_t hi_port_addr[8];
	} ci_host_interface;

	/* Target interface information */
	struct {
		uint8_t di_SPI:1;
		uint8_t di_SAS_3G:1;
		uint8_t di_SATA_1_5G:1;
		uint8_t di_SATA_3G:1;
		uint8_t di_reserved_0:4;
		uint8_t di_reserved_1[6];
		uint8_t di_port_count;
		uint64_t di_port_addr[8];
	} ci_device_interface;

	uint32_t ci_image_check_word;

	uint32_t ci_image_component_count;
	mfi_image_comp_t ci_image_component[8];

	uint32_t ci_pending_image_component_count;
	mfi_image_comp_t ci_pending_image_component[8];

	uint8_t ci_max_arms;
	uint8_t ci_max_spans;
	uint8_t ci_max_arrays;
	uint8_t ci_max_lds;
	char ci_product_name[80];
	char ci_serial_no[32];

	/*
	 * Hardware features
	 */
	struct {
		uint32_t hw_bbu:1;
		uint32_t hw_alarm:1;
		uint32_t hw_nvram:1;
		uint32_t hw_uart:1;
		uint32_t hw_reserved:28;
	} ci_hw_present;

	uint32_t ci_current_fw_time;

	/* Maximum data transfer sizes */
	uint16_t ci_max_concurrent_cmds;
	uint16_t ci_max_sge_count;
	uint32_t ci_max_request_size;

	/* Logical and physical device counts */
	uint16_t ci_ld_present_count;
	uint16_t ci_ld_degraded_count;
	uint16_t ci_ld_offline_count;

	uint16_t ci_pd_present_count;
	uint16_t ci_pd_disk_present_count;
	uint16_t ci_pd_disk_pred_failure_count;
	uint16_t ci_pd_disk_failed_count;

	/* Memory size information */
	uint16_t ci_nvram_size;
	uint16_t ci_memory_size;
	uint16_t ci_flash_size;

	/* Error counters */
	uint16_t ci_mem_correctable_error_count;
	uint16_t ci_mem_uncorrectable_error_count;

	/* Cluster information */
	uint8_t ci_cluster_permitted;
	uint8_t ci_cluster_active;

	/* Additional max data transfer sizes */
	uint16_t ci_max_stripes_per_io;

	/* Controller capabilities structures */
	struct {
		uint32_t rl_raid_level_0:1;
		uint32_t rl_raid_level_1:1;
		uint32_t rl_raid_level_5:1;
		uint32_t rl_raid_level_1E:1;
		uint32_t rl_raid_level_6:1;
		uint32_t rl_reserved:27;
	} ci_raid_levels;

	struct {
		uint32_t ao_rbld_rate:1;
		uint32_t ao_cc_rate:1;
		uint32_t ao_bgi_rate:1;
		uint32_t ao_recon_rate:1;
		uint32_t ao_patrol_rate:1;
		uint32_t ao_alarm_control:1;
		uint32_t ao_cluster_supported:1;
		uint32_t ao_bbu:1;
		uint32_t ao_spanning_allowed:1;
		uint32_t ao_dedicated_hotspares:1;
		uint32_t ao_revertible_hotspares:1;
		uint32_t ao_foreign_config_import:1;
		uint32_t ao_self_diagnostic:1;
		uint32_t ao_mixed_redundancy_arr:1;
		uint32_t ao_global_hot_spares:1;
		uint32_t ao_reserved:17;
	} ci_adapter_opts;

	struct {
		uint32_t ld_read_policy:1;
		uint32_t ld_write_policy:1;
		uint32_t ld_io_policy:1;
		uint32_t ld_access_policy:1;
		uint32_t ld_disk_cache_policy:1;
		uint32_t ld_reserved:27;
	} ci_ld_opts;

	struct {
		uint8_t raid_stripe_sz_min;
		uint8_t raid_stripe_sz_max;
		uint8_t raid_reserved[2];
	} ci_raid_opts;

	struct {
		uint32_t pd_force_online:1;
		uint32_t pd_force_offline:1;
		uint32_t pd_force_rebuild:1;
		uint32_t pd_reserved:29;
	} ci_pd_opts;

	struct {
		uint32_t pd_ctrl_supports_sas:1;
		uint32_t pd_ctrl_supports_sata:1;
		uint32_t pd_allow_mix_in_encl:1;
		uint32_t pd_allow_mix_in_ld:1;
		uint32_t pd_allow_sata_in_cluster:1;
		uint32_t pd_reserved:27;
	} ci_pd_mix_support;

	/* ECC single-bit error bucket information */
	uint8_t ci_ecc_bucket_count;
	uint8_t ci_reserved_2[11];

	/* Controller properties */
	mfi_ctrl_props_t ci_prop;

	char ci_package_version[0x60];

	uint64_t ci_device_interface_port_addr2[8];
	uint8_t ci_reserved3[128];

	struct {
		uint16_t pd_min_pd_raid_level_0:4;
		uint16_t pd_max_pd_raid_level_0:12;

		uint16_t pd_min_pd_raid_level_1:4;
		uint16_t pd_max_pd_raid_level_1:12;

		uint16_t pd_min_pd_raid_level_5:4;
		uint16_t pd_max_pd_raid_level_5:12;

		uint16_t pd_min_pd_raid_level_1E:4;
		uint16_t pd_max_pd_raid_level_1E:12;

		uint16_t pd_min_pd_raid_level_6:4;
		uint16_t pd_max_pd_raid_level_6:12;

		uint16_t pd_min_pd_raid_level_10:4;
		uint16_t pd_max_pd_raid_level_10:12;

		uint16_t pd_min_pd_raid_level_50:4;
		uint16_t pd_max_pd_raid_level_50:12;

		uint16_t pd_min_pd_raid_level_60:4;
		uint16_t pd_max_pd_raid_level_60:12;

		uint16_t pd_min_pd_raid_level_1E_RLQ0:4;
		uint16_t pd_max_pd_raid_level_1E_RLQ0:12;

		uint16_t pd_min_pd_raid_level_1E0_RLQ0:4;
		uint16_t pd_max_pd_raid_level_1E0_RLQ0:12;

		uint16_t pd_reserved[6];
	} ci_pds_for_raid_levels;

	uint16_t ci_max_pds;			/* 0x780 */
	uint16_t ci_max_ded_HSPs;		/* 0x782 */
	uint16_t ci_max_global_HSPs;		/* 0x784 */
	uint16_t ci_ddf_size;			/* 0x786 */
	uint8_t ci_max_lds_per_array;		/* 0x788 */
	uint8_t ci_partitions_in_DDF;		/* 0x789 */
	uint8_t ci_lock_key_binding;		/* 0x78a */
	uint8_t ci_max_PITs_per_ld;		/* 0x78b */
	uint8_t ci_max_views_per_ld;		/* 0x78c */
	uint8_t ci_max_target_id;		/* 0x78d */
	uint16_t ci_max_bvl_vd_size;		/* 0x78e */

	uint16_t ci_max_configurable_SSC_size;	/* 0x790 */
	uint16_t ci_current_SSC_size;		/* 0x792 */

	char ci_expander_fw_version[12];	/* 0x794 */

	uint16_t ci_PFK_trial_time_remaining;	/* 0x7A0 */

	uint16_t ci_cache_memory_size;		/* 0x7A2 */

	struct {				/* 0x7A4 */
		uint32_t ao2_support_PI_controller:1;
		uint32_t ao2_support_ld_PI_type1:1;
		uint32_t ao2_support_ld_PI_type2:1;
		uint32_t ao2_support_ld_PI_type3:1;
		uint32_t ao2_support_ld_BBM_info:1;
		uint32_t ao2_support_shield_state:1;
		uint32_t ao2_block_SSD_write_cache_change:1;
		uint32_t ao2_support_suspend_resume_b_Gops:1;
		uint32_t ao2_support_emergency_spares:1;
		uint32_t ao2_support_set_link_speed:1;
		uint32_t ao2_support_boot_time_PFK_change:1;
		uint32_t ao2_support_JBOD:1;
		uint32_t ao2_disable_online_PFK_change:1;
		uint32_t ao2_support_perf_tuning:1;
		uint32_t ao2_support_SSD_patrol_read:1;
		uint32_t ao2_real_time_scheduler:1;

		uint32_t ao2_support_reset_now:1;
		uint32_t ao2_support_emulated_drives:1;
		uint32_t ao2_headless_mode:1;
		uint32_t ao2_dedicated_hot_spares_limited:1;

		uint32_t ao2_support_uneven_spans:1;
		uint32_t ao2_reserved:11;
	} ci_adapter_opts2;

	uint8_t ci_driver_version[32];		/* 0x7A8 */
	uint8_t ci_max_DAP_d_count_spinup60;	/* 0x7C8 */
	uint8_t ci_temperature_ROC;		/* 0x7C9 */
	uint8_t ci_temperature_ctrl;		/* 0x7CA */
	uint8_t ci_reserved4;			/* 0x7CB */
	uint16_t ci_max_configurable_pds;	/* 0x7CC */

	uint8_t ci_reserved5[2];		/* 0x7CD reserved */

	struct {
		uint32_t cl_peer_is_present:1;
		uint32_t cl_peer_is_incompatible:1;

		uint32_t cl_hw_incompatible:1;
		uint32_t cl_fw_version_mismatch:1;
		uint32_t cl_ctrl_prop_incompatible:1;
		uint32_t cl_premium_feature_mismatch:1;
		uint32_t cl_reserved:26;
	} ci_cluster;

	char ci_cluster_id[16];			/* 0x7D4 */

	char ci_reserved6[4];			/* 0x7E4 RESERVED FOR IOV */

	struct {				/* 0x7E8 */
		uint32_t ao3_support_personality_change:2;
		uint32_t ao3_support_thermal_poll_interval:1;
		uint32_t ao3_support_disable_immediate_IO:1;
		uint32_t ao3_support_T10_rebuild_assist:1;
		uint32_t ao3_support_max_ext_lds:1;
		uint32_t ao3_support_crash_dump:1;
		uint32_t ao3_support_sw_zone:1;
		uint32_t ao3_support_debug_queue:1;
		uint32_t ao3_support_NV_cache_erase:1;
		uint32_t ao3_support_force_to_512e:1;
		uint32_t ao3_support_HOQ_rebuild:1;
		uint32_t ao3_support_allowed_opsfor_drv_removal:1;
		uint32_t ao3_support_drv_activity_LED_setting:1;
		uint32_t ao3_support_NVDRAM:1;
		uint32_t ao3_support_force_flash:1;
		uint32_t ao3_support_disable_SES_monitoring:1;
		uint32_t ao3_support_cache_bypass_modes:1;
		uint32_t ao3_support_securityon_JBOD:1;
		uint32_t ao3_discard_cache_during_ld_delete:1;
		uint32_t ao3_support_TTY_log_compression:1;
		uint32_t ao3_support_CPLD_update:1;
		uint32_t ao3_support_disk_cache_setting_for_sys_pds:1;
		uint32_t ao3_support_extended_SSC_size:1;
		uint32_t ao3_use_seq_num_jbod_FP:1;
		uint32_t ao3_reserved:7;
	} ci_adapter_opts3;

	uint8_t ci_pad_cpld[16];

	struct {
		uint16_t ao4_ctrl_info_ext_supported:1;
		uint16_t ao4_support_ibutton_less:1;
		uint16_t ao4_supported_enc_algo:1;
		uint16_t ao4_support_encrypted_mfc:1;
		uint16_t ao4_image_upload_supported:1;
		uint16_t ao4_support_SES_ctrl_in_multipath_cfg:1;
		uint16_t ao4_support_pd_map_target_id:1;
		uint16_t ao4_fw_swaps_bbu_vpd_info:1;
		uint16_t ao4_reserved:8;
	} ci_adapter_opts4;

	uint8_t ci_pad[0x800 - 0x7FE];	/* 0x7FE */
};
CTASSERT(sizeof (mfi_ctrl_info_t) == 0x800);

/*
 * PR (patrol read) properties & status
 */
struct mfi_pr_properties {
	uint8_t		pp_op_mode;
	uint8_t		pp_max_pd;
	uint8_t		pp_rsvd;
	uint8_t		pp_exclude_ld_cnt;
	uint16_t	pp_excluded_ld[MFI_MAX_LOGICAL_DRIVES];
	uint8_t		pp_cur_pd_map[MFI_MAX_PHYSICAL_DRIVES / 8];
	uint8_t		pp_last_pd_map[MFI_MAX_PHYSICAL_DRIVES / 8];
	uint32_t	pp_next_exec;
	uint32_t	pp_exec_freq;
	uint32_t	pp_clear_freq;
};

struct mfi_pr_status {
	uint32_t	ps_num_iteration;
	uint8_t		ps_state;
	uint8_t		ps_num_pd_done;
	uint8_t		ps_rsvd[10];
};

struct mfi_progress {
	uint16_t	mp_progress;
	uint16_t	mp_elapsed;
};
CTASSERT(sizeof (mfi_progress_t) == 4);

#pragma pack(0)

#ifdef __cplusplus
}
#endif

#endif	/* _MFI_H */
