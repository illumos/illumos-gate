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
 * Copyright 2013 STEC, Inc.  All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SKD_H
#define	_SKD_H

#include	<sys/types.h>
#include	<sys/stropts.h>
#include	<sys/stream.h>
#include	<sys/cmn_err.h>
#include	<sys/kmem.h>
#include	<sys/modctl.h>
#include	<sys/ddi.h>
#include	<sys/sunddi.h>
#include	<sys/strsun.h>
#include	<sys/kstat.h>
#include 	<sys/conf.h>
#include 	<sys/debug.h>
#include 	<sys/modctl.h>
#include 	<sys/errno.h>
#include 	<sys/pci.h>
#include 	<sys/memlist.h>
#include 	<sys/param.h>
#include	<sys/queue.h>

#define	DRV_NAME 	"skd"
#define	DRV_VERSION 	"2.2.1"
#define	DRV_BUILD_ID 	"0264"
#define	PFX DRV_NAME    ": "
#define	DRV_BIN_VERSION 0x100
#define	DRV_VER_COMPL   DRV_VERSION "." DRV_BUILD_ID
#define	VERSIONSTR 	DRV_VERSION


#define	SG_BOUNDARY		0x20000


#ifdef _BIG_ENDIAN
#define	be64_to_cpu(x) (x)
#define	be32_to_cpu(x) (x)
#define	cpu_to_be64(x) (x)
#define	cpu_to_be32(x) (x)
#else
#define	be64_to_cpu(x) BSWAP_64(x)
#define	be32_to_cpu(x) BSWAP_32(x)
#define	cpu_to_be64(x) BSWAP_64(x)
#define	cpu_to_be32(x) BSWAP_32(x)
#endif

#define	ATYPE_64BIT		0
#define	ATYPE_32BIT		1

#define	BIT_0			0x00001
#define	BIT_1			0x00002
#define	BIT_2			0x00004
#define	BIT_3			0x00008
#define	BIT_4			0x00010
#define	BIT_5			0x00020
#define	BIT_6			0x00040
#define	BIT_7			0x00080
#define	BIT_8			0x00100
#define	BIT_9			0x00200
#define	BIT_10			0x00400
#define	BIT_11			0x00800
#define	BIT_12			0x01000
#define	BIT_13			0x02000
#define	BIT_14			0x04000
#define	BIT_15			0x08000
#define	BIT_16			0x10000
#define	BIT_17			0x20000
#define	BIT_18			0x40000
#define	BIT_19			0x80000

/* Attach progress flags */
#define	SKD_ATTACHED			BIT_0
#define	SKD_SOFT_STATE_ALLOCED		BIT_1
#define	SKD_CONFIG_SPACE_SETUP		BIT_3
#define	SKD_IOBASE_MAPPED		BIT_4
#define	SKD_IOMAP_IOBASE_MAPPED		BIT_5
#define	SKD_REGS_MAPPED			BIT_6
#define	SKD_DEV_IOBASE_MAPPED		BIT_7
#define	SKD_CONSTRUCTED			BIT_8
#define	SKD_PROBED			BIT_9
#define	SKD_INTR_ADDED			BIT_10
#define	SKD_PATHNAME_ALLOCED		BIT_11
#define	SKD_SUSPENDED			BIT_12
#define	SKD_CMD_ABORT_TMO		BIT_13
#define	SKD_MUTEX_INITED		BIT_14
#define	SKD_MUTEX_DESTROYED		BIT_15

#define	SKD_IODONE_WIOC			1	/* I/O done */
#define	SKD_IODONE_WNIOC		2	/* I/O NOT done */
#define	SKD_IODONE_WDEBUG		3	/* I/O - debug stuff */

#ifdef SKD_PM
#define	MAX_POWER_LEVEL			0
#define	LOW_POWER_LEVEL			(BIT_1 | BIT_0)
#endif

#define	SKD_MSIX_AIF		0x0
#define	SKD_MSIX_RSPQ		0x1
#define	SKD_MSIX_MAXAIF		SKD_MSIX_RSPQ + 1

/*
 * Stuff from Linux
 */
#define	SAM_STAT_GOOD			0x00
#define	SAM_STAT_CHECK_CONDITION	0x02

#define	TEST_UNIT_READY		0x00
#define	INQUIRY			0x12
#define	INQUIRY2		(0x12 + 0xe0)
#define	READ_CAPACITY		0x25
#define	READ_CAPACITY_EXT	0x9e
#define	SYNCHRONIZE_CACHE	0x35

/*
 *  SENSE KEYS
 */
#define	NO_SENSE	    0x00
#define	RECOVERED_ERROR	    0x01
#define	UNIT_ATTENTION	    0x06
#define	ABORTED_COMMAND	    0x0b

typedef struct dma_mem_t {
	void			*bp;
	ddi_acc_handle_t	acc_handle;
	ddi_dma_handle_t	dma_handle;
	ddi_dma_cookie_t	cookie;
	ddi_dma_cookie_t	*cookies;
	uint32_t		size;
} dma_mem_t;

#define	SKD_WRITEL(DEV, VAL, OFF)	skd_reg_write32(DEV, VAL, OFF)
#define	SKD_READL(DEV, OFF)		skd_reg_read32(DEV, OFF)
#define	SKD_WRITEQ(DEV, VAL, OFF)	skd_reg_write64(DEV, VAL, OFF)

/* Capability lists */
#define	PCI_CAP_ID_EXP		0x10	/* PCI Express */

/*
 * End Stuff from Linux
 */

#define	SKD_DMA_MAXXFER			(2048 * DEV_BSIZE)

#define	SKD_DMA_LOW_ADDRESS		(uint64_t)0
#define	SKD_DMA_HIGH_64BIT_ADDRESS	(uint64_t)0xffffffffffffffff
#define	SKD_DMA_HIGH_32BIT_ADDRESS	(uint64_t)0xffffffff
#define	SKD_DMA_XFER_COUNTER		(uint64_t)0xffffffff
#define	SKD_DMA_ADDRESS_ALIGNMENT	(uint64_t)SG_BOUNDARY
#define	SKD_DMA_BURSTSIZES		0xff
#define	SKD_DMA_MIN_XFER_SIZE		1
#define	SKD_DMA_MAX_XFER_SIZE		(uint64_t)0xfffffe00
#define	SKD_DMA_SEGMENT_BOUNDARY	(uint64_t)0xffffffff
#define	SKD_DMA_SG_LIST_LENGTH		256
#define	SKD_DMA_XFER_FLAGS		0
#define	SKD_DMA_GRANULARITY		512 /* 1 */

#define	PCI_VENDOR_ID_STEC  0x1B39
#define	PCI_DEVICE_ID_SUMO  0x0001

#define	SKD_N_FITMSG_BYTES	(512u)

#define	SKD_N_SPECIAL_CONTEXT	64u
#define	SKD_N_SPECIAL_FITMSG_BYTES (128u)
#define	SKD_N_SPECIAL_DATA_BYTES  (8u*1024u)


/*
 * SG elements are 32 bytes, so we can make this 4096 and still be under the
 * 128KB limit.	 That allows 4096*4K = 16M xfer size
 */
#define	SKD_N_SG_PER_REQ_DEFAULT 256u
#define	SKD_N_SG_PER_SPECIAL	256u

#define	SKD_N_COMPLETION_ENTRY		256u
#define	SKD_N_READ_CAP_BYTES		(8u)
#define	SKD_N_READ_CAP_EXT_BYTES	(16)

#define	SKD_N_INTERNAL_BYTES   (512u)

/* 5 bits of uniqifier, 0xF800 */
#define	SKD_ID_INCR		(0x400)
#define	SKD_ID_TABLE_MASK	(3u << 8u)
#define	SKD_ID_RW_REQUEST	(0u << 8u)
#define	SKD_ID_INTERNAL		(1u << 8u)
#define	SKD_ID_FIT_MSG		(3u << 8u)
#define	SKD_ID_SLOT_MASK	0x00FFu
#define	SKD_ID_SLOT_AND_TABLE_MASK 0x03FFu

#define	SKD_N_TIMEOUT_SLOT	8u
#define	SKD_TIMEOUT_SLOT_MASK	7u

#define	SKD_TIMER_SECONDS(seconds) (seconds)
#define	SKD_TIMER_MINUTES(minutes) ((minutes)*(60))

/*
 * NOTE:  INTR_LOCK() should be held prior to grabbing WAITQ_LOCK() if both
 * are needed.
 */
#define	INTR_LOCK(skdev)		mutex_enter(&skdev->skd_intr_mutex)
#define	INTR_UNLOCK(skdev)		mutex_exit(&skdev->skd_intr_mutex)
#define	INTR_LOCK_HELD(skdev)		MUTEX_HELD(&skdev->skd_intr_mutex)

#define	WAITQ_LOCK(skdev) \
	mutex_enter(&skdev->waitqueue_mutex)
#define	WAITQ_UNLOCK(skdev) \
	mutex_exit(&skdev->waitqueue_mutex)
#define	WAITQ_LOCK_HELD(skdev) \
	MUTEX_HELD(&skdev->waitqueue_mutex)

#define	ADAPTER_STATE_LOCK(skdev)	mutex_enter(&skdev->skd_lock_mutex)
#define	ADAPTER_STATE_UNLOCK(skdev)	mutex_exit(&skdev->skd_lock_mutex)

enum skd_drvr_state {
	SKD_DRVR_STATE_LOAD,			/* 0 when driver first loaded */
	SKD_DRVR_STATE_IDLE,			/* 1 when device goes offline */
	SKD_DRVR_STATE_BUSY,			/* 2 */
	SKD_DRVR_STATE_STARTING,		/* 3 */
	SKD_DRVR_STATE_ONLINE,			/* 4 */
	SKD_DRVR_STATE_PAUSING,			/* 5 */
	SKD_DRVR_STATE_PAUSED,			/* 6 */
	SKD_DRVR_STATE_DRAINING_TIMEOUT,	/* 7 */
	SKD_DRVR_STATE_RESTARTING,		/* 8 */
	SKD_DRVR_STATE_RESUMING,		/* 9 */
	SKD_DRVR_STATE_STOPPING,	/* 10 when driver is unloading */
	SKD_DRVR_STATE_FAULT,			/* 11 */
	SKD_DRVR_STATE_DISAPPEARED,		/* 12 */
	SKD_DRVR_STATE_PROTOCOL_MISMATCH,	/* 13 */
	SKD_DRVR_STATE_BUSY_ERASE,		/* 14 */
	SKD_DRVR_STATE_BUSY_SANITIZE,		/* 15 */
	SKD_DRVR_STATE_BUSY_IMMINENT,		/* 16 */
	SKD_DRVR_STATE_WAIT_BOOT,		/* 17 */
	SKD_DRVR_STATE_SYNCING			/* 18 */
};

#define	SKD_WAIT_BOOT_TO 90u
#define	SKD_STARTING_TO	 248u

enum skd_req_state {
	SKD_REQ_STATE_IDLE,
	SKD_REQ_STATE_SETUP,
	SKD_REQ_STATE_BUSY,
	SKD_REQ_STATE_COMPLETED,
	SKD_REQ_STATE_TIMEOUT,
	SKD_REQ_STATE_ABORTED,
};

enum skd_fit_msg_state {
	SKD_MSG_STATE_IDLE,
	SKD_MSG_STATE_BUSY,
};

enum skd_check_status_action {
	SKD_CHECK_STATUS_REPORT_GOOD,
	SKD_CHECK_STATUS_REPORT_SMART_ALERT,
	SKD_CHECK_STATUS_REQUEUE_REQUEST,
	SKD_CHECK_STATUS_REPORT_ERROR,
	SKD_CHECK_STATUS_BUSY_IMMINENT,
};

/* NOTE:  mbu_t users should name this field "mbu". */
typedef union {
	uint8_t *mb8;
	uint64_t *mb64;
} mbu_t;
#define	msg_buf mbu.mb8
#define	msg_buf64 mbu.mb64

struct skd_fitmsg_context {
	enum skd_fit_msg_state state;
	struct skd_fitmsg_context *next;
	uint32_t	id;
	uint16_t	outstanding;
	uint32_t	length;
	uint32_t	offset;
	mbu_t		mbu;	/* msg_buf & msg_buf64 */
	dma_mem_t	mb_dma_address;
};

struct skd_request_context {
	enum skd_req_state		state;
	struct skd_request_context	*next;
	uint16_t			did_complete;
	uint16_t			id;
	uint32_t			fitmsg_id;
	struct skd_buf_private		*pbuf;
	uint32_t			timeout_stamp;
	uint8_t				sg_data_dir;
	uint32_t			n_sg;
	ddi_dma_handle_t		io_dma_handle;
	struct fit_sg_descriptor	*sksg_list;
	dma_mem_t			sksg_dma_address;
	struct fit_completion_entry_v1	completion;
	struct fit_comp_error_info	err_info;
	int				total_sg_bcount;
};

#define	SKD_DATA_DIR_HOST_TO_CARD	1
#define	SKD_DATA_DIR_CARD_TO_HOST	2

struct skd_special_context {
	struct skd_request_context req;
	uint8_t			   orphaned;
	uint32_t		   sg_byte_count;
	void			   *data_buf;
	dma_mem_t		   db_dma_address;
	mbu_t			   mbu;	/* msg_buf & msg_buf64 */
	dma_mem_t		   mb_dma_address;
	int			   io_pending;
};

typedef struct skd_buf_private {
	SIMPLEQ_ENTRY(skd_buf_private) sq;
	struct skd_request_context *skreq;
	bd_xfer_t *x_xfer;
	int dir;
} skd_buf_private_t;

SIMPLEQ_HEAD(waitqueue, skd_buf_private);

typedef struct skd_device skd_device_t;

struct skd_device {
	int		irq_type;
	int		gendisk_on;
	int		sync_done;

	char		name[32];

	enum		skd_drvr_state state;
	uint32_t		drive_state;

	uint32_t	queue_depth_busy;
	uint32_t	queue_depth_limit;
	uint32_t	queue_depth_lowat;
	uint32_t	soft_queue_depth_limit;
	uint32_t	hard_queue_depth_limit;

	uint32_t	num_fitmsg_context;
	uint32_t	num_req_context;

	uint32_t	timeout_slot[SKD_N_TIMEOUT_SLOT];
	uint32_t	timeout_stamp;

	struct skd_fitmsg_context *skmsg_free_list;
	struct skd_fitmsg_context *skmsg_table;

	struct skd_request_context *skreq_free_list;
	struct skd_request_context *skreq_table;
	struct skd_special_context internal_skspcl;

	uint64_t	read_cap_last_lba;
	uint32_t	read_cap_blocksize;
	int		read_cap_is_valid;
	int		inquiry_is_valid;
	char		inq_serial_num[13]; /* 12 chars plus null term */
	char		inq_vendor_id[9];
	char		inq_product_id[17];
	char		inq_product_rev[5];
	char		id_str[128]; /* holds a composite name (pci + sernum) */

	uint8_t		skcomp_cycle;
	uint32_t	skcomp_ix;
	struct fit_completion_entry_v1 *skcomp_table;
	struct fit_comp_error_info *skerr_table;
	dma_mem_t	cq_dma_address;

	uint32_t	timer_active;
	uint32_t	timer_countdown;
	uint32_t	timer_substate;

	int		sgs_per_request;
	uint32_t	last_mtd;

	uint32_t	proto_ver;

	int		dbg_level;

	uint32_t	timo_slot;

	ddi_acc_handle_t	pci_handle;
	ddi_acc_handle_t	iobase_handle;
	ddi_acc_handle_t	iomap_handle;
	caddr_t			iobase;
	caddr_t			iomap_iobase;

	ddi_acc_handle_t	dev_handle;
	caddr_t			dev_iobase;
	int			dev_memsize;

	char			*pathname;

	dev_info_t		*dip;

	int			instance;
	uint16_t		vendor_id;
	uint16_t		device_id;

	kmutex_t		skd_lock_mutex;
	kmutex_t		skd_intr_mutex;
	kmutex_t		skd_fit_mutex;

	uint32_t		flags;

#ifdef SKD_PM
	uint8_t			power_level;
#endif

	/* AIF (Advanced Interrupt Framework) support */
	ddi_intr_handle_t	*htable;
	uint32_t		hsize;
	int32_t			intr_cnt;
	uint32_t		intr_pri;
	int32_t			intr_cap;

	uint64_t		Nblocks;

	ddi_iblock_cookie_t	iblock_cookie;

	int		n_req;
	uint32_t	progress;
	uint64_t	intr_cntr;
	uint64_t	fitmsg_sent1;
	uint64_t	fitmsg_sent2;
	uint64_t	active_cmds;

	kmutex_t	skd_internalio_mutex;
	kcondvar_t	cv_waitq;

	kmutex_t	waitqueue_mutex;
	struct waitqueue waitqueue;
	int		disks_initialized;

	ddi_devid_t	s1120_devid;
	char		devid_str[80];

	uint32_t	d_blkshift;

	int		attached;

	int		ios_queued;
	int		ios_started;
	int		ios_completed;
	int		ios_errors;
	int		iodone_wioc;
	int		iodone_wnioc;
	int		iodone_wdebug;
	int		iodone_unknown;

	bd_handle_t	s_bdh;
	int		bd_attached;

#ifdef USE_SKE_EMULATOR
	ske_device_t *ske_handle;
#endif

	timeout_id_t	skd_timer_timeout_id;
};

static void skd_disable_interrupts(struct skd_device *skdev);
static void skd_isr_completion_posted(struct skd_device *skdev);
static void skd_recover_requests(struct skd_device *skdev);
static void skd_log_skdev(struct skd_device *skdev, const char *event);
static void skd_restart_device(struct skd_device *skdev);
static void skd_destruct(struct skd_device *skdev);
static int skd_unquiesce_dev(struct skd_device *skdev);
static void skd_send_special_fitmsg(struct skd_device *skdev,
    struct skd_special_context *skspcl);
static void skd_end_request(struct skd_device *skdev,
    struct skd_request_context *skreq, int error);
static void skd_log_skmsg(struct skd_device *skdev,
    struct skd_fitmsg_context *skmsg, const char *event);
static void skd_log_skreq(struct skd_device *skdev,
    struct skd_request_context *skreq, const char *event);
static void skd_send_fitmsg(struct skd_device *skdev,
    struct skd_fitmsg_context *skmsg);

static const char *skd_drive_state_to_str(int state);
static const char *skd_skdev_state_to_str(enum skd_drvr_state state);

#endif /* _SKD_H */
