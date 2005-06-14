/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	I2O Message module, which implements OSM interfaces to provides
 *	transport functionality for the OSMs. It depends on the I2O nexus
 *	driver for bus specific transport mechanisms.
 *
 *	Note: The current implementation assumes only 32bit virtual
 *	addresses and 32bit context fields in I2O messages.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/errno.h>
#include <sys/ddidmareq.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/pci.h>
#include <sys/avintr.h>
#include <sys/bustypes.h>
#include <sys/kmem.h>
#include <sys/archsystm.h>
#include <sys/disp.h>

#include "i2o_impl.h"
#include <sys/i2o/i2oexec.h>

#ifndef I2O_BOOT_SUPPORT
#include <sys/sunndi.h>

char _depends_on[] = "misc/busra";
#endif

/*
 * ************************************************************************
 * *** Implementation specific data structures/definitions.		***
 * ************************************************************************
 */

/*
 * Implementation of i2o_iop_handle_t data structure.
 *
 *	dip	devinfo node pointer of the I2O device
 *	tid	IOP assigned TID for this device.
 *	iop	pointer to iop_instance_t data structure.
 */

typedef struct i2o_iop_impl_hdl {
	dev_info_t		*dip;
	uint32_t		tid;
	struct iop_instance	*iop;
} i2o_iop_impl_hdl_t;

/*
 * Implementation of i2o_msg_handle_t data structure.
 *
 *	next		pointer to the next handle (used when the requests
 *			are queued up)
 *	dma_handle	DMA handle associated with this message buffer
 *	msgp		pointer to the message frame.
 *	acc_hdl		DDI access handle for this message frame.
 */

typedef struct i2o_msg_impl_hdl {
	struct i2o_msg_impl_hdl	*next;
	ddi_dma_handle_t	dma_handle;
	ddi_acc_handle_t	acc_hdl;
	void			*msgp;
} i2o_msg_impl_hdl_t;

/*
 * Per IOP instance data structure maintained by the I2O Message
 * module.
 *
 * Locks used:
 *	iop_ib_mutex	Used to serialize access to the inbound message
 *			queue and to protect send_queue_* fields.
 *
 *	iop_ob_mutex	Used to serialize access to the outbound message
 *			queue.
 */
typedef struct iop_instance {

	struct iop_instance			*next;
	uint_t					iop_id;
	volatile int				iop_flags;
	i2o_msg_trans_t				*nexus_trans;
	dev_info_t				*dip;
	kmutex_t				iop_ib_mutex;
	kmutex_t				iop_ob_mutex;
	uint32_t				event_mask;
	uint_t					ib_msg_frame_size;

	/* IOP Status Block structure */
	struct {
		i2o_exec_status_get_reply_t	*bufp;
		ddi_acc_handle_t		acc_hdl;
		ddi_dma_handle_t		dma_handle;
	} status;

	/* Logical Configuration Table (LCT) */
	struct {
		i2o_lct_t			*bufp;
		ddi_acc_handle_t		acc_hdl;
		size_t				size;
		ddi_dma_handle_t		dma_handle;
		kmutex_t			lct_mutex;
	} lct;

	/* Hardware Resource Table (HRT) */
	struct {
		i2o_hrt_t			*bufp;
		ddi_acc_handle_t		acc_hdl;
		uint_t				size;
		ddi_dma_handle_t		dma_handle;
	} hrt;

	/* outbound message queue */
	struct {
		caddr_t				base_addr;
		uint_t				base_paddr;
		ddi_acc_handle_t		acc_hdl;
		uint_t				nframes;
		uint_t				framesize;
		ddi_dma_handle_t		dma_handle;
	} ob_msg_queue;

	/* private memory/io space allocated for IOP hw configuration */
	struct {
		uint_t				mem_base;
		uint_t				mem_size;
		uint_t				io_base;
		uint_t				io_size;
	} hw_config;

	/* System Table Entry for this IOP */
	struct {
		ddi_dma_handle_t		dma_handle;
		i2o_iop_entry_t			*bufp;
		ddi_acc_handle_t		acc_hdl;
	} systab;

	/* OSM registration book keeping */
	struct {
		i2o_iop_impl_hdl_t		*iop_handle_tab;
		uint_t				max_tid;
		kmutex_t			osm_mutex;
	} osm_registry;

	/*
	 * i2o_send_msg() queue information. The fields send_queue_head
	 * and send_queue_tail are protected under iop_ib_mutex.
	 */
	i2o_msg_impl_hdl_t	*send_queue_head;
	i2o_msg_impl_hdl_t	*send_queue_tail;
	ulong_t			send_queue_count;
	kcondvar_t		send_queue_cv;
} iop_instance_t;

/* common transaction context structure */

typedef struct tcontext {
	iop_instance_t	*iop;
	kmutex_t	cv_mutex;
	kcondvar_t	cv;
	int		status;
	int		done_flag;
} tcontext_t;

/* definitions for iop_flags values */
#define	IOP_IS_IN_INIT			1    /* IOP is being initialized */
#define	IOP_IS_ONLINE			2    /* IOP is initilized */
#define	IOP_IS_IN_UNINIT		4    /* IOP is being uninitialized */
#define	IOP_SEND_QUEUE_PROC_RUNNING	8    /* i2o_msg_send_proc() running */

/*
 * DMA attribute structure for I2O Spec version 1.5.
 *
 * (Note: Specifies sg list length to 1 to get contiguous memory)
 */
static ddi_dma_attr_t dma_attr_contig = {
	DMA_ATTR_VERSION,	/* version number */
	(uint64_t)0,		/* low DMA address range */
	(uint64_t)0xFFFFFFFF,	/* high DMA address range */
	(uint64_t)0x00FFFFFF,	/* DMA counter register */
	1,			/* DMA address alignment */
	1,			/* DMA burstsizes */
	1,			/* min effective DMA size */
	(uint64_t)0xFFFFFFFF,	/* max DMA xfer size */
	(uint64_t)0xFFFFFFFF,	/* segment boundary */
	0x1,			/* s/g length */
	1,			/* granularity of device */
	0			/* Bus specific DMA flags */
};

/*
 * Device attribute structure for I2O version 1.5.
 *
 * I2O data structures (whether it is in IOP's memory or host memory)
 * are in Little Endian format.
 */
static ddi_device_acc_attr_t i2o_dev_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,	/* devacc_attr_endian_flags for LE access */
	DDI_STRICTORDER_ACC	/* devacc_attr_dataorder */
};

/* Function prototypes for local functions */

static int i2o_get_iop_status(iop_instance_t *iop);
static int i2o_init_outbound_queue(iop_instance_t *iop);
static int i2o_get_hrt(iop_instance_t *iop);
static int i2o_create_systab(iop_instance_t *iop);
static int i2o_send_exec_enable(iop_instance_t *iop);
static int i2o_get_lct(iop_instance_t *iop);
static int i2o_iop_event_register(iop_instance_t *iop);
static void i2o_msg_iop_event_reply(void *p, ddi_acc_handle_t acc_hdl);
static void i2o_msg_common_reply(void *p, ddi_acc_handle_t acc_hdl);
static int i2o_send_exec_iop_reset(iop_instance_t *iop);
static void i2o_msg_send_proc(iop_instance_t *iop);

static void i2o_return_mem(dev_info_t *, uint_t, uint_t);
static uint_t i2o_get_mem(dev_info_t *, uint_t, uint_t *);
static uint_t i2o_get_io(dev_info_t *, uint_t, uint_t *);
static void i2o_return_io(dev_info_t *, uint_t, uint_t);

#ifdef I2O_DEBUG
/* function prototypes for debug functions */
static void dump_reply_message(iop_instance_t *iop,
		i2o_single_reply_message_frame_t *rmp);
static void dump_hrt(iop_instance_t *iop);
static void dump_lct(iop_instance_t *iop);
static void dump_iop_status_buf(iop_instance_t *iop);
static void dump_message(uint32_t *mp, char *name);
#endif

/*
 * Local Data definitions.
 *
 * niop
 *	number of active IOPs initialized to OP state.
 *
 * next_iop_id
 *	Counter to assign unique ID (IOP_ID) to the next IOP that
 *	gets initialized by the i2o nexus.
 *
 * ioplist
 *	pointer to the linked list of IOP data structures (i.e iop_instance
 *	structures) that are initilized.
 *
 * iop_reset_time_delay_in_ticks
 *	This is the time delay to get a valid mfa from the inbound freelist
 *	after doing ExecIopReset. This delay really depends on the platform
 *	specific hardware. Here we are using 2 seconds and this seems to
 *	work fine for the Madrona platform.
 */

#define	BASE_IOP_ID	2 	/* IOP IDs 0 and 1 are reserved */

static uint_t	niop = 0;
static uint_t	next_iop_id = BASE_IOP_ID;
static iop_instance_t *ioplist;
int iop_reset_time_delay_in_ticks = 200;

kmutex_t i2o_mutex;	/* protects common data like ioplist, etc. */

/*
 * Debug flag definitions.
 */
#define	I2O_DEBUG_DEBUG		0x80000000	/* general debugging info */
#define	I2O_DEBUG_MSG		0x00000001	/* dump message frames */
#define	I2O_DEBUG_HRT		0x40000000	/* dump HRT table */
#define	I2O_DEBUG_STATUS	0x20000000	/* dump IOP Status block */
#define	I2O_DEBUG_LCT		0x10000000	/* dump LCT table */
#define	I2O_DEBUG_IOP_PARAMS	0x08000000	/* dump IOP parameters */

#ifdef	I2O_DEBUG
int i2o_debug = I2O_DEBUG_LCT;

#define	DEBUGF(flag, args) \
	{ if (i2o_debug & (flag)) cmn_err args; }
#else
#define	DEBUGF(level, args)	/* nothing */
#endif

#define	SUCCESS	1
#define	FAILURE	0

/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_miscops;
static struct modlmisc modlmisc = {
	&mod_miscops,
	"I2O Message Module version 1.5",
};


static struct modlinkage modlinkage = {
	MODREV_1,
	&modlmisc,
	NULL
};

int
_init(void)
{
	int error;

	mutex_init(&i2o_mutex, NULL, MUTEX_DRIVER, NULL);

	if ((error = mod_install(&modlinkage)) != 0)
		mutex_destroy(&i2o_mutex);

	return (error);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) == 0)
		mutex_destroy(&i2o_mutex);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * Utility macros to initialize message structures.
 */
/* initialize standard message header */
#define	init_std_msghdr(iop, mp, ver_off, msg_flags, msg_size, func) 	\
	{								\
	    (mp)->VersionOffset = (ver_off) | I2O_VERSION_11;		\
	    (mp)->MsgFlags = (msg_flags);				\
	    ddi_put16((iop)->nexus_trans->acc_handle,			\
		&(mp)->MessageSize, (msg_size) >> 2);			\
	    put_msg_Function((mp), (func), (iop)->nexus_trans->acc_hdl); \
	    put_msg_InitiatorAddress((mp), I2O_HOST_TID,		\
		(iop)->nexus_trans->acc_hdl);				\
	    put_msg_TargetAddress((mp), I2O_IOP_TID,			\
		(iop)->nexus_trans->acc_hdl);				\
	}

/* initialize standard SGL Simple Element structure */
#define	init_sgl_simple_ele(iop, sgl, flags, count, addr)		\
	{								\
	    put_flags_count_Flags(&(sgl)->FlagsCount,			\
		(flags) | I2O_SGL_FLAGS_SIMPLE_ADDRESS_ELEMENT,		\
		(iop)->nexus_trans->acc_hdl);				\
	    ddi_put32((iop)->nexus_trans->acc_handle,			\
		&(sgl)->PhysicalAddress, (uint_t)(addr));		\
	    put_flags_count_Count(&(sgl)->FlagsCount, (count),		\
		(iop)->nexus_trans->acc_hdl);				\
	    DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT, "SGL(0x%p): %x %x",	\
		(void *)sgl, ((uint32_t *)sgl)[0], ((uint32_t *)sgl)[1])); \
	}

/*
 * ************************************************************************
 * Tunable parameters/properties.
 *	ob_msg_framesize_default
 *		Default frame size for Outbound Message queue. The minimum
 *		size is 64 bytes. It should be multiple of 4.
 *	ob_msg_queue_length_default
 *		Default size (i.e #of MFAs) in the Outbound Queue. The
 *		minimum is 16.
 * ************************************************************************
 */
int	ob_msg_framesize_default = 128;
int	ob_msg_queue_length_default = 32;

/*
 * ************************************************************************
 * Transport utility functions/macros used in IOP initialization.
 * ************************************************************************
 */

#define	iop_msg_send(iop, msgp) \
	(* iop->nexus_trans->i2o_trans_msg_send)		\
				(iop->nexus_trans->nexus_handle, \
	(caddr_t)(msgp) - iop->nexus_trans->iop_base_addr)


#define	iop_msg_free(iop, rmp)	\
	(* iop->nexus_trans->i2o_trans_msg_freebuf)	 \
		(iop->nexus_trans->nexus_handle,	 \
	((caddr_t)(rmp) - iop->ob_msg_queue.base_addr) + \
		iop->ob_msg_queue.base_paddr)

static i2o_single_reply_message_frame_t *
iop_poll_reply_msg(iop_instance_t *iop)
{
	uint_t mfa;
	uint_t ticks = 10000;	/* time out polling for 10 seconds */

	mfa = (* iop->nexus_trans->i2o_trans_msg_recv)
		(iop->nexus_trans->nexus_handle);

	while (mfa == (uint_t)0xFFFFFFFF) {
	    delay(1);
	    mfa = (* iop->nexus_trans->i2o_trans_msg_recv)
					(iop->nexus_trans->nexus_handle);
	    if (--ticks == 0) {
		DEBUGF(I2O_DEBUG_DEBUG,
			(CE_CONT, "iop_poll_reply_msg: timed out"));
		return (NULL);	/* time out - possible hang? */
	    }
	}

	return ((i2o_single_reply_message_frame_t *)
		((mfa - iop->ob_msg_queue.base_paddr) +
		iop->ob_msg_queue.base_addr));
}

void *
iop_msg_alloc(iop_instance_t *iop)
{
	uint32_t mfa;

	mfa = (* iop->nexus_trans->i2o_trans_msg_alloc)
		(iop->nexus_trans->nexus_handle);

	/*
	 * If we don't have a valid frame then wait for a while and
	 * try again. This may be necessary at the beginning if
	 * the IOP is in the INITIALIZATION state.
	 */
	if (mfa == (uint_t)0xFFFFFFFF) {
		delay(100);
		mfa = (* iop->nexus_trans->i2o_trans_msg_alloc)
			(iop->nexus_trans->nexus_handle);
	}

	return (mfa == (uint_t)0xFFFFFFFF ? NULL :
		(void *)(mfa + iop->nexus_trans->iop_base_addr));
}


/*
 * ************************************************************************
 * ********* Private interfaces used by the I2O Nexus driver.	***********
 * ************************************************************************
 */

/*
 * i2o_msg_iop_init()
 *
 * Called from the attach(9E) function in the i2o nexus driver.
 * Initializes the IOP to the OPERATIONAL state. Returns an access
 * handle (i.e i2o_iop_handle_t) for successful initialization,
 * otherwise it returns NULL.
 *
 * Assumption(s):
 *	1. The IOP interrupts are not enabled when this function is
 *	   called. The caller (i.e attach(9E)) enables the IOP interrupts
 *	   upon the successful return from this function.
 *	2. It is assumed that the I2O nexus driver will create the
 *	   devinfo nodes for the I2O devices if necessary. i.e the
 *	   caller of this function will create the devinfo tree
 *	   based on the LCT/HRT information if the boot firmware hasn't
 *	   already created it.
 */

i2o_iop_handle_t
i2o_msg_iop_init(dev_info_t *dip, i2o_msg_trans_t *trans)
{
	iop_instance_t	*iop;
	uint32_t	priv_mem_size;
	uint32_t	priv_io_size;
	i2o_iop_impl_hdl_t *hdl;
	i2o_lct_entry_t	*lct_entp;
	uint_t		lct_entries;
	int		i;
	int		reset_done = 0; /* only one IOP_RESET operation */
	int		init_time;

	/*
	 * Allocate an iop instance data.
	 */
	iop = (iop_instance_t *)kmem_zalloc(sizeof (iop_instance_t), KM_SLEEP);

	mutex_enter(&i2o_mutex);

	iop->dip = dip;
	iop->iop_flags |= IOP_IS_IN_INIT;	/* IOP is being initialized */
	iop->nexus_trans = trans;

	niop++;
	iop->iop_id = next_iop_id++;	/* assign a unique ID to this IOP */

	mutex_init(&iop->iop_ib_mutex, NULL, MUTEX_DRIVER,
	    (void *)iop->nexus_trans->iblock_cookie);
	mutex_init(&iop->iop_ob_mutex, NULL, MUTEX_DRIVER,
	    (void *)iop->nexus_trans->iblock_cookie);
	mutex_init(&iop->osm_registry.osm_mutex, NULL, MUTEX_DRIVER,
	    (void *)iop->nexus_trans->iblock_cookie);
	mutex_init(&iop->lct.lct_mutex, NULL, MUTEX_DRIVER,
	    (void *)iop->nexus_trans->iblock_cookie);

	/*
	 * **************************************************************
	 * Step 1: Get the IOP status block by sending ExecStatusGet
	 *	   message.
	 *
	 * NOTE: Normally we expect IOP to be in 'RESET' state or 'OP'
	 * state. Any other state is really doubtful!
	 * **************************************************************
	 */

	/*
	 * We give 5 minutes for IOP to reset before complaining to user;
	 * the time for IOP to come to RESET state after it receives the
	 * EXEC_IOP_RESET really depends on the I2O hardware configured
	 * under the IOP.
	 */
	init_time = 5 * 60 * 100; /* ~5 min of clock ticks */

try_again:
	if (i2o_get_iop_status(iop) == FAILURE)
		goto cleanup;

	/* Check for I2O Version; we only support version 1.5 */
	if (get_i2o_exec_status_reply_I2oVersion(iop->status.bufp,
	    iop->status.acc_hdl) != I2O_VERSION_11)
		goto cleanup;

	DEBUGF(I2O_DEBUG_DEBUG,
		(CE_CONT, "i2o_msg_iop_init: Initial IOP state %x",
		iop->status.bufp->IopState));

	switch (iop->status.bufp->IopState) {
	case I2O_IOP_STATE_RESET:
		break;

	case I2O_IOP_STATE_INITIALIZING:
		if (init_time <= 0)
		    cmn_err(CE_WARN,
			"IOP is still in I2O_IOP_STATE_INITIALIZING state!!");
		else
			init_time -= 100;
		delay(100);
		goto try_again;

	case I2O_IOP_STATE_OPERATIONAL:
		/* reset the IOP and wait for a while for the IOP to reset */
		if (reset_done || i2o_send_exec_iop_reset(iop) != SUCCESS)
			goto cleanup;
		reset_done = 1;
		delay(iop_reset_time_delay_in_ticks);
		goto try_again;

	case I2O_IOP_STATE_HOLD:
	case I2O_IOP_STATE_READY:
	case I2O_IOP_STATE_FAILED:
	case I2O_IOP_STATE_FAULTED:
		/* reset the IOP and try again */
		if (!reset_done && i2o_send_exec_iop_reset(iop) == SUCCESS) {
			delay(iop_reset_time_delay_in_ticks);
			reset_done = 1;
			goto try_again;
		}
	default:
		cmn_err(CE_CONT, "?i2o_msg_iop_init: Invalid IOP state %x",
			iop->status.bufp->IopState);
		goto cleanup;
	}

#ifdef I2O_DEBUG
	if (i2o_debug & I2O_DEBUG_STATUS)
		dump_iop_status_buf(iop);
#endif

	/*
	 * **************************************************************
	 * Step 2: Initialize the Outbound message queue.
	 * **************************************************************
	 */
	if (i2o_init_outbound_queue(iop) == FAILURE)
		goto cleanup;

	/*
	 * **************************************************************
	 * Step 3: Get the Hardware Resource Table (HRT).
	 * **************************************************************
	 */
	if (i2o_get_hrt(iop) == FAILURE)
		goto cleanup;

#if !defined(I2O_BOOT_SUPPORT)
	/*
	 * **************************************************************
	 * Step 4: Allocate Memory/IO spaces required by the IOP to
	 *	   configure the hidden adapters. The IOP status buffer
	 *	   has the required information.
	 *
	 * XXX Does IOP handle multiple chunks for PCI memory/io space
	 * allocated by the host? Currently the IRTOS always reports
	 * the CurrentPrivateMemSize as zero.
	 * **************************************************************
	 */
	priv_mem_size = ddi_get32(iop->status.acc_hdl,
				&iop->status.bufp->DesiredPrivateMemSize);
	if (priv_mem_size > (uint32_t)0) {
	    /* need to allocate PCI memory space */
	    if (i2o_get_mem(dip, priv_mem_size, &iop->hw_config.mem_base) == 0)
			goto cleanup;
	    iop->hw_config.mem_size = priv_mem_size;
	}

	priv_io_size = ddi_get32(iop->status.acc_hdl,
				&iop->status.bufp->DesiredPrivateIOSize);
	if (priv_io_size > (uint32_t)0) {
	    /* need to allocate PCI i/o space */
	    if (i2o_get_io(dip, priv_io_size, &iop->hw_config.io_base) == 0)
			goto cleanup;
	    iop->hw_config.io_size = priv_io_size;
	}
#endif

	/*
	 * **************************************************************
	 * Step 5: Create the System Table entry for this IOP and send
	 *	   ExecSysTabSet to all the IOPs. It enables the IOP
	 *	   to OPERATIONAL state.
	 * **************************************************************
	 */
	if (i2o_create_systab(iop) == FAILURE)
		goto cleanup;

	ASSERT(iop->status.bufp->IopState == I2O_IOP_STATE_OPERATIONAL);

	/*
	 * **************************************************************
	 * Step 6: Read LCT by sending ExecLctNotify message.
	 * **************************************************************
	 */
	if (i2o_get_lct(iop) == FAILURE)
		goto cleanup;

	/*
	 * **************************************************************
	 * Step 7: Set event notification request for the events that
	 *	   we are interested.
	 * **************************************************************
	 */
	if (i2o_iop_event_register(iop) == FAILURE)
		goto cleanup;

	if (ioplist == NULL) {
		ioplist = iop;
		iop->next = NULL;
	} else {
		iop->next = ioplist;
		ioplist = iop;
	}
	iop->iop_flags |= IOP_IS_ONLINE;
	iop->ib_msg_frame_size = ddi_get16(iop->nexus_trans->acc_handle,
			&iop->status.bufp->InboundMFrameSize) << 2;

	/* find the max TIDs allocated by the IOP */
	iop->osm_registry.max_tid = 0;
	lct_entries =
		((ddi_get16(iop->lct.acc_hdl, &iop->lct.bufp->TableSize) << 2) -
		sizeof (i2o_lct_t) + sizeof (i2o_lct_entry_t)) /
		sizeof (i2o_lct_entry_t);
	lct_entp = iop->lct.bufp->LCTEntry;
	for (i = 0; i < lct_entries; i++) {
		uint_t tid;

		tid = get_lct_entry_LocalTID(&lct_entp[i], iop->lct.acc_hdl);
		if (tid > iop->osm_registry.max_tid)
			iop->osm_registry.max_tid = tid;
	}

	/* allocate the IOP handle table */
	iop->osm_registry.iop_handle_tab = (i2o_iop_impl_hdl_t *)
	    kmem_zalloc(sizeof (i2o_iop_impl_hdl_t) *
			(iop->osm_registry.max_tid + 1), KM_SLEEP);
	/*
	 * initialize the IOP handle (i2o_iop_handle_t) for the nexus to use and
	 * return the handle.
	 */
	hdl = &iop->osm_registry.iop_handle_tab[I2O_IOP_TID];
	hdl->dip = dip;
	hdl->iop = iop;
	hdl->tid = I2O_IOP_TID;

	mutex_exit(&i2o_mutex);

	DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT, "i2o_msg_iop_init: SUCCEEDED"));

	return ((i2o_iop_handle_t *)hdl);

	/*
	 * Error return; free up the allocated resources and return NULL.
	 */
cleanup:

	if (iop->status.bufp != NULL) {
		ddi_dma_mem_free(&iop->status.acc_hdl);
		ddi_dma_free_handle(&iop->status.dma_handle);
	}

	if (iop->lct.bufp != NULL) {
		ddi_dma_mem_free(&iop->lct.acc_hdl);
		ddi_dma_free_handle(&iop->lct.dma_handle);
	}

	if (iop->hrt.bufp != NULL) {
		ddi_dma_mem_free(&iop->hrt.acc_hdl);
		ddi_dma_free_handle(&iop->hrt.dma_handle);
	}

	if (iop->ob_msg_queue.base_addr != NULL) {
		ddi_dma_mem_free(&iop->ob_msg_queue.acc_hdl);
		ddi_dma_free_handle(&iop->ob_msg_queue.dma_handle);
	}

	if (iop->hw_config.mem_base != NULL) {
		i2o_return_mem(dip, iop->hw_config.mem_base,
					iop->hw_config.mem_size);
	}

	if (iop->hw_config.io_base != NULL) {
		i2o_return_io(dip, iop->hw_config.io_base,
					iop->hw_config.io_size);
	}

	mutex_destroy(&iop->iop_ib_mutex);
	mutex_destroy(&iop->iop_ob_mutex);
	mutex_destroy(&iop->lct.lct_mutex);

	kmem_free((void *)iop, sizeof (iop_instance_t));

	--niop;

	mutex_exit(&i2o_mutex);

	DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT, "i2o_msg_iop_init: FAILED"));

	return (NULL);
}

/*
 * i2o_msg_iop_unint()
 *
 * Called from the detach(9E) function in the i2o nexus driver.
 * It would uninitialize IOP by sending ExecIopReset to bring the
 * IOP to RESET state. And then it will free up any resources/data-structures
 * allocated for this IOP instance.
 *
 * Assumption(s):
 *	1. It is assumed that all the I2O devices are quiesced before calling
 *	   this function. Which means all OSMs have already done the
 *	   i2o_msg_osm_unregister() for the devices they claimed.
 */

int
i2o_msg_iop_uninit(i2o_iop_handle_t *handlep)
{
	i2o_iop_handle_t h = *handlep;
	iop_instance_t *iop = ((i2o_iop_impl_hdl_t *)(h))->iop;
	ddi_dma_handle_t dma_handle = NULL;
	ddi_acc_handle_t acc_hdl;
	i2o_exec_iop_reset_status_t *buf = NULL;
	i2o_exec_sys_quiesce_message_t *qmsgp;
	i2o_single_reply_message_frame_t *rmp = NULL;
	iop_instance_t *p;

	mutex_enter(&iop->iop_ib_mutex);
	mutex_enter(&iop->iop_ob_mutex);
	mutex_enter(&iop->osm_registry.osm_mutex);
	mutex_enter(&iop->lct.lct_mutex);
	mutex_enter(&i2o_mutex);

	/*
	 * First, disable the IOP hardware interrupts.
	 */
	(* iop->nexus_trans->i2o_trans_disable_intr)
			(iop->nexus_trans->nexus_handle);

	/*
	 * *********************************************************
	 * if there are multiple IOPs then we need to send
	 * ExecPathQuiesce message to other IOPs before
	 * resetting this IOP.
	 * *********************************************************
	 */

	if (niop > 1) { /* we have multiple IOPs */
	    tcontext_t tcxt; /* transaction context structure */

	    cv_init(&tcxt.cv, NULL, CV_DEFAULT, NULL);
	    mutex_init(&tcxt.cv_mutex, NULL, MUTEX_DRIVER, NULL);

	    for (p = ioplist; p != NULL; p = p->next) {
		i2o_exec_path_quiesce_message_t	*mp;

		if (p == iop)
			continue;

		/*
		 * Send ExecPathQuiesce message to this IOP.
		 */

		mp = (i2o_exec_path_quiesce_message_t *)iop_msg_alloc(p);

		if (mp == NULL) {
			DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
				"i2o_msg_iop_uninit: trans_msg_alloc failed"));
			cv_destroy(&tcxt.cv);
			mutex_destroy(&tcxt.cv_mutex);
			goto cleanup;
		}

		/* initialize the transcation context structure */
		tcxt.iop = p;
		tcxt.done_flag = 0;

		/* construct the ExecPathQuiesce message */

		init_std_msghdr(p, &mp->StdMessageFrame, 0x0, 0,
			sizeof (i2o_exec_path_quiesce_message_t),
			I2O_EXEC_PATH_QUIESCE);
		ddi_put32(p->nexus_trans->acc_handle,
			&mp->TransactionContext, (uint32_t)(uintptr_t)&tcxt);
		ddi_put32(p->nexus_trans->acc_handle,
			(uint32_t *)&mp->StdMessageFrame.InitiatorContext.
			initiator_context_32bits,
			(uint32_t)i2o_msg_common_reply);
		put_i2o_exec_path_quiesce_IOP_ID(mp, iop->iop_id,
			p->nexus_trans->acc_handle);
		ddi_put16(p->nexus_trans->acc_handle,
			&mp->HostUnitID, iop->status.bufp->HostUnitID);

		/* send the message to the IOP and wait for the reply */

		(void) iop_msg_send(p, (void *)mp);

		mutex_enter(&tcxt.cv_mutex);
		while (!tcxt.done_flag)	/* wait for the reply */
			cv_wait(&tcxt.cv, &tcxt.cv_mutex);
		mutex_exit(&tcxt.cv_mutex);
	    }

	    cv_destroy(&tcxt.cv);
	    mutex_destroy(&tcxt.cv_mutex);
	}


	/*
	 * *********************************************************
	 * Send an ExecSysQuiesce message to the IOP.
	 * *********************************************************
	 */

	/* allocate a message frame from Inbound queue */
	qmsgp = (i2o_exec_sys_quiesce_message_t *)iop_msg_alloc(iop);
	if (qmsgp == NULL) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_msg_iop_uninit: trans_msg_alloc failed"));
		goto cleanup;
	}

	/* construct the ExecSysQuiesce message */
	init_std_msghdr(iop, &qmsgp->StdMessageFrame, 0x0, 0,
		sizeof (i2o_exec_sys_quiesce_message_t),
		I2O_EXEC_SYS_QUIESCE);

#ifdef I2O_DEBUG
	if (i2o_debug & I2O_DEBUG_MSG)
		dump_message((uint32_t *)qmsgp, "ExecSysQuiesce");
#endif

	/* send the message to the IOP */
	(void) iop_msg_send(iop, (void *)qmsgp);

	/*
	 * Since interrupts are disabled, we poll for the reply message
	 * for ExecSysQuiesce request. Could we expect any other reply
	 * messages for previous activity on this IOP (like some
	 * event notification)? For now, we can safely ignore any other
	 * reply messages.
	 */
	for (;;) {

		if ((rmp = iop_poll_reply_msg(iop)) == NULL)
			goto cleanup;

		/* ignore reply messages other than for ExecSysQuiesce */
		if (get_msg_Function((i2o_message_frame_t *)rmp,
		    iop->ob_msg_queue.acc_hdl) != I2O_EXEC_SYS_QUIESCE) {
			iop_msg_free(iop, rmp);
			continue;
		}

		if (rmp->ReqStatus == I2O_REPLY_STATUS_SUCCESS)
			break;	/* successful */

		/* message failed */
		iop_msg_free(iop, rmp);
		goto cleanup;
	}

	/* free up the reply message buffer */
	iop_msg_free(iop, rmp);

	/*
	 * *********************************************************
	 * Now, send an ExecIopReset message to the IOP.
	 * *********************************************************
	 */

	if (i2o_send_exec_iop_reset(iop) == FAILURE)
		goto cleanup;

	iop->iop_flags |= IOP_IS_IN_UNINIT;

	/*
	 * *********************************************************
	 * Free up the system resources.
	 * *********************************************************
	 */
	if (iop->status.bufp != NULL) {
		ddi_dma_mem_free(&iop->status.acc_hdl);
		ddi_dma_free_handle(&iop->status.dma_handle);
	}

	if (iop->lct.bufp != NULL) {
		ddi_dma_mem_free(&iop->lct.acc_hdl);
		ddi_dma_free_handle(&iop->lct.dma_handle);
	}

	if (iop->hrt.bufp != NULL) {
		ddi_dma_mem_free(&iop->hrt.acc_hdl);
		ddi_dma_free_handle(&iop->hrt.dma_handle);
	}

	if (iop->ob_msg_queue.base_addr != NULL) {
		ddi_dma_mem_free(&iop->ob_msg_queue.acc_hdl);
		ddi_dma_free_handle(&iop->ob_msg_queue.dma_handle);
	}

	if (iop->hw_config.mem_base != NULL) {
		i2o_return_mem(iop->dip, iop->hw_config.mem_base,
					iop->hw_config.mem_size);
	}

	if (iop->hw_config.io_base != NULL) {
		i2o_return_io(iop->dip, iop->hw_config.io_base,
					iop->hw_config.io_size);
	}

	/*
	 * If i2o_msg_send_proc() is running then wait for it to exit.
	 */
	if (iop->iop_flags & IOP_SEND_QUEUE_PROC_RUNNING) {

		mutex_exit(&iop->iop_ib_mutex);

		/* wake up the i2o_msg_send_proc() thread */
		cv_broadcast(&iop->send_queue_cv);

		/* wait until the i2o_msg_send_proc() stops running */
		while (iop->iop_flags & IOP_SEND_QUEUE_PROC_RUNNING)
			delay(1);

		cv_destroy(&iop->send_queue_cv);
	}

	mutex_destroy(&iop->iop_ib_mutex);
	mutex_destroy(&iop->iop_ob_mutex);
	mutex_destroy(&iop->osm_registry.osm_mutex);
	mutex_destroy(&iop->lct.lct_mutex);

	if (iop == ioplist) {
		ioplist = ioplist->next;
	} else {
		iop_instance_t *p, *prev;

		for (prev = ioplist, p = ioplist->next; p; p = p->next) {
			if (p == iop) {
				prev->next = iop->next;
				break;
			}
			prev = p;
		}

		ASSERT((p != NULL) && (p == iop));
	}

	--niop;	/* number of active IOPs */

	mutex_exit(&i2o_mutex);

	/* free up the IOP handle table */
	kmem_free((void *)iop->osm_registry.iop_handle_tab,
		sizeof (i2o_iop_impl_hdl_t) * (iop->osm_registry.max_tid + 1));

	*handlep = NULL;

	kmem_free((void *)iop, sizeof (iop_instance_t));

	DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT, "i2o_msg_iop_uninit: SUCCEEDED"));

	return (DDI_SUCCESS);

	/*
	 * Error return; free up the allocated resources and return NULL.
	 */
cleanup:
	if (buf != NULL)
		ddi_dma_mem_free(&acc_hdl);

	if (dma_handle != NULL)
		ddi_dma_free_handle(&dma_handle);

	DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT, "i2o_msg_iop_uninit: FAILED"));

	mutex_exit(&i2o_mutex);
	mutex_exit(&iop->lct.lct_mutex);
	mutex_exit(&iop->osm_registry.osm_mutex);
	mutex_exit(&iop->iop_ob_mutex);
	mutex_exit(&iop->iop_ib_mutex);

	return (DDI_FAILURE);
}

/*
 * Send ExecStatusGet message to get IOP status. It allocates the
 * buffer resources if they are not already allocated.
 *
 * Returns SUCCESS if it succeeds in getting the IOP status.
 */
static int
i2o_get_iop_status(iop_instance_t *iop)
{
	size_t real_length;
	ddi_dma_cookie_t dma_cookie;
	uint_t ncookies;
	i2o_exec_status_get_message_t *msgp;
	i2o_exec_status_get_reply_t *s = 0;

	if (iop->status.dma_handle == NULL) {

	    /* allocate a DMA handle */
	    if (ddi_dma_alloc_handle(iop->dip, &dma_attr_contig, DDI_DMA_SLEEP,
		    NULL, &iop->status.dma_handle) != DDI_SUCCESS) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_get_iop_status: ddi_dma_alloc_handle failed"));
		goto cleanup;
	    }
	}

	if (iop->status.bufp == NULL) {

	    /* allocate the buffer for the IOP status block */
	    if (ddi_dma_mem_alloc(iop->status.dma_handle,
		sizeof (i2o_exec_status_get_reply_t), &i2o_dev_acc_attr,
		DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
		(caddr_t *)&iop->status.bufp, &real_length,
		&iop->status.acc_hdl) != DDI_SUCCESS) {

		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_get_iop_status: ddi_dma_mem_alloc failed"));
		goto cleanup;
	    }

	    bzero((caddr_t)iop->status.bufp, real_length);
	}

	if (ddi_dma_addr_bind_handle(iop->status.dma_handle, NULL,
	    (caddr_t)iop->status.bufp, sizeof (i2o_exec_status_get_reply_t),
	    DDI_DMA_READ | DDI_DMA_STREAMING, DDI_DMA_SLEEP,
	    NULL, &dma_cookie, &ncookies) != DDI_SUCCESS) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_get_iop_status: cannot bind memory"));
		goto cleanup;
	}

	ASSERT(ncookies == 1);

	DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
		"i2o_get_iop_status: dma_bind (vaddr %p paddr %x length %x)",
		(void *)iop->status.bufp, dma_cookie.dmac_address,
		(int)dma_cookie.dmac_size));

	/* allocate a message frame from Inbound queue */
	msgp = (i2o_exec_status_get_message_t *)iop_msg_alloc(iop);
	if (msgp == NULL) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_get_iop_status: trans_msg_alloc failed"));
		(void) ddi_dma_unbind_handle(iop->status.dma_handle);
		goto cleanup;
	}

	/* construct the ExecStatusGet message */
	init_std_msghdr(iop, (i2o_message_frame_t *)msgp, 0x0, 0,
		sizeof (i2o_exec_status_get_message_t),
		I2O_EXEC_STATUS_GET);
	ddi_put32(iop->nexus_trans->acc_handle, &msgp->ReplyBufferAddressLow,
		dma_cookie.dmac_address);
	ddi_put32(iop->nexus_trans->acc_handle,
		&msgp->ReplyBufferAddressHigh, 0);
	ddi_put32(iop->nexus_trans->acc_handle, &msgp->ReplyBufferLength,
		sizeof (i2o_exec_status_get_reply_t));
	iop->status.bufp->SyncByte = 0;

#ifdef I2O_DEBUG
	if (i2o_debug & I2O_DEBUG_MSG)
		dump_message((uint32_t *)msgp, "ExecStatusGet");
#endif

	/* send the message to the IOP */
	(void) iop_msg_send(iop, (void *)msgp);

	/*
	 * Poll on the status block field 'SyncByte' because there is
	 * no reply to ExecStatusGet message. The IOP writes '0xFF'
	 * to 'SyncByte' field when it finished writing to the status
	 * block structure.
	 */

	while (iop->status.bufp->SyncByte != 0xFF) {
		delay(1);
		/* sync DMA memory */
		(void) ddi_dma_sync(iop->status.dma_handle,
			(off_t)&s->SyncByte, 1, DDI_DMA_SYNC_FORCPU);
	}

	(void) ddi_dma_unbind_handle(iop->status.dma_handle);

	DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT, "i2o_get_iop_status: SUCCEEDED"));

	return (SUCCESS);

	/*
	 * Error return; free up the allocated resources and return NULL.
	 */
cleanup:

	if (iop->status.bufp != NULL) {
		ddi_dma_mem_free(&iop->status.acc_hdl);
		iop->status.bufp = NULL;
	}

	if (iop->status.dma_handle != NULL) {
		ddi_dma_free_handle(&iop->status.dma_handle);
		iop->status.dma_handle = NULL;
	}

	DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT, "i2o_get_iop_status: FAILED"));

	return (FAILURE);
}

/*
 * Allocate message frames for the Outbound queue and send ExecOutboundInit
 * message to the IOP.
 *
 * Description:
 *	Since we don't know how to determine how many frames to be
 *	allocated, we either depend on the user specified property
 *	(i.e ob-msg-queue-length) or use the current IOP's default.
 *	Allocate the message queue as one physically contiguous chunk.
 *	Send ExecOutboundInit message with the list of MFAs.
 */
static int
i2o_init_outbound_queue(iop_instance_t *iop)
{
	size_t real_length;
	ddi_dma_cookie_t dma_cookie;
	uint_t ncookies;
	i2o_exec_outbound_init_message_t *msgp;
	int nframes, max_nframes;
	int frame_size;
	i2o_sge_simple_element_t *sgl;
	i2o_exec_outbound_init_status_t *stat;
	uint_t	mfa;
	int	count;

	if (iop->ob_msg_queue.dma_handle == NULL) {

	    /* allocate a DMA handle */
	    if (ddi_dma_alloc_handle(iop->dip, &dma_attr_contig, DDI_DMA_SLEEP,
		    NULL, &iop->ob_msg_queue.dma_handle) != DDI_SUCCESS) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
		    "i2o_init_outbound_queue: ddi_dma_alloc_handle failed"));
		goto cleanup;
	    }
	}

	if (iop->ob_msg_queue.base_addr == NULL) {

	    nframes = ddi_prop_get_int(DDI_DEV_T_ANY, iop->dip,
		DDI_PROP_DONTPASS, "ob-msg-queue-length",
		ob_msg_queue_length_default);

	    max_nframes = ddi_get32(iop->status.acc_hdl,
		&iop->status.bufp->MaxOutboundMFrames);

	    if (nframes == 0 || nframes > max_nframes)
		nframes = max_nframes;

	    frame_size = ddi_prop_get_int(DDI_DEV_T_ANY, iop->dip,
		DDI_PROP_DONTPASS, "ob-msg-framesize",
		ob_msg_framesize_default);

	    /* allocate the buffer for the message frames */
	    if (ddi_dma_mem_alloc(iop->ob_msg_queue.dma_handle,
		(size_t)(nframes * frame_size), &i2o_dev_acc_attr,
		DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
		(caddr_t *)&iop->ob_msg_queue.base_addr, &real_length,
		&iop->ob_msg_queue.acc_hdl) != DDI_SUCCESS) {

		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_init_outbound_queue: ddi_dma_mem_alloc failed"));
		goto cleanup;
	    }
	    bzero((caddr_t)iop->ob_msg_queue.base_addr, real_length);
	    iop->ob_msg_queue.nframes = nframes;
	    iop->ob_msg_queue.framesize = frame_size;
	}

	if (ddi_dma_addr_bind_handle(iop->ob_msg_queue.dma_handle, NULL,
	    iop->ob_msg_queue.base_addr,
	    (iop->ob_msg_queue.nframes * iop->ob_msg_queue.framesize),
	    DDI_DMA_READ | DDI_DMA_STREAMING, DDI_DMA_SLEEP,
	    NULL, &dma_cookie, &ncookies) != DDI_SUCCESS) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_init_outbound_queue: cannot bind memory"));
		goto cleanup;
	}

	ASSERT(ncookies == 1);

	DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
	    "i2o_init_outbound_queue: dma_bind (vaddr %p paddr %x length %x)",
	    (void *)iop->ob_msg_queue.base_addr, dma_cookie.dmac_address,
	    (int)dma_cookie.dmac_size));

	iop->ob_msg_queue.base_paddr = (uint_t)dma_cookie.dmac_address;

	/* allocate a message frame from Inbound queue */
	msgp = (i2o_exec_outbound_init_message_t *)iop_msg_alloc(iop);
	if (msgp == NULL) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_init_outbound_queue: trans_msg_alloc failed"));

		(void) ddi_dma_unbind_handle(iop->ob_msg_queue.dma_handle);
		goto cleanup;
	}

	/*
	 * Construct the ExecOutboundInit message. Use the base address
	 * of the outbound message queue buffer for the status word structure
	 * instead of allocating a new word.
	 */
	init_std_msghdr(iop, &msgp->StdMessageFrame, 0x60, 0,
		sizeof (i2o_exec_outbound_init_message_t),
		I2O_EXEC_OUTBOUND_INIT);
	ddi_put32(iop->nexus_trans->acc_handle, &msgp->HostPageFrameSize,
		MMU_PAGESIZE);
	msgp->InitCode = I2O_MESSAGE_IF_INIT_CODE_OS;
	ddi_put16(iop->nexus_trans->acc_handle, &msgp->OutboundMFrameSize,
		((uint16_t)frame_size) >> 2);

	sgl = (i2o_sge_simple_element_t *)&msgp->SGL;
	init_sgl_simple_ele(iop, sgl,
	    I2O_SGL_FLAGS_LAST_ELEMENT | I2O_SGL_FLAGS_END_OF_BUFFER,
	    4, (uint_t)iop->ob_msg_queue.base_paddr);

	stat = (i2o_exec_outbound_init_status_t *)iop->ob_msg_queue.base_addr;
	stat->InitStatus = 0;

#ifdef I2O_DEBUG
	if (i2o_debug & I2O_DEBUG_MSG)
		dump_message((uint32_t *)msgp, "ExecOutboundInit");
#endif

	/* send the message to the IOP */
	(void) iop_msg_send(iop, (void *)msgp);

	/*
	 * Poll on the status word for completion.
	 */
	while ((stat->InitStatus == 0) ||
		(stat->InitStatus == I2O_EXEC_OUTBOUND_INIT_IN_PROGRESS)) {

		delay(2);
		/* sync DMA memory */
		(void) ddi_dma_sync(iop->ob_msg_queue.dma_handle,
			0, 1, DDI_DMA_SYNC_FORCPU);
	}

	(void) ddi_dma_unbind_handle(iop->ob_msg_queue.dma_handle);

	if (stat->InitStatus != I2O_EXEC_OUTBOUND_INIT_COMPLETE) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_init_outbound_queue: FAILED (InitStatus %x)",
			stat->InitStatus));
		goto cleanup;
	}

	/*
	 * Now, write the MFAs to the Outbound FIFO.
	 */
	mfa = iop->ob_msg_queue.base_paddr;
	for (count = 0; count < iop->ob_msg_queue.nframes; count ++) {
	    (* iop->nexus_trans->i2o_trans_msg_freebuf)
		(iop->nexus_trans->nexus_handle, mfa);
	    mfa += iop->ob_msg_queue.framesize;
	}

	DEBUGF(I2O_DEBUG_DEBUG,
		(CE_CONT, "i2o_init_outbound_queue: SUCCEEDED"));

	return (SUCCESS);


	/*
	 * Error return; free up the allocated resources and return NULL.
	 */
cleanup:

	if (iop->ob_msg_queue.base_addr != NULL) {
		ddi_dma_mem_free(&iop->ob_msg_queue.acc_hdl);
		iop->ob_msg_queue.base_addr = NULL;
	}

	if (iop->ob_msg_queue.dma_handle != NULL) {
		ddi_dma_free_handle(&iop->ob_msg_queue.dma_handle);
		iop->ob_msg_queue.dma_handle = NULL;
	}

	DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT, "i2o_init_outbound_queue: FAILED"));

	return (FAILURE);
}

/*
 * Get HRT by sending ExecHrtGet message to the IOP.
 * It is assumed that Outbound queue is already initialized
 * so that the IOP can send a reply to the ExecHrtGet message.
 * Also it is assumed that the IOP interrupts are disabled.
 */
static int
i2o_get_hrt(iop_instance_t *iop)
{
	size_t real_length;
	ddi_dma_cookie_t dma_cookie;
	uint_t ncookies;
	i2o_exec_hrt_get_message_t *msgp;
	i2o_hrt_t *buf = NULL;
	ddi_acc_handle_t acc_hdl;
	i2o_single_reply_message_frame_t *rmp = NULL;
	uint_t hrt_size;

	/* allocate a DMA handle if necessary */
	if (iop->hrt.dma_handle == NULL) {
	    if (ddi_dma_alloc_handle(iop->dip, &dma_attr_contig, DDI_DMA_SLEEP,
		    NULL, &iop->hrt.dma_handle) != DDI_SUCCESS) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
		    "i2o_get_hrt: ddi_dma_alloc_handle failed"));
		goto cleanup;
	    }
	}

	/*
	 * Allocate a temporary buffer to get the HRT size information
	 * (i.e only header part of the HRT).
	 */
	if (ddi_dma_mem_alloc(iop->hrt.dma_handle,
		sizeof (i2o_hrt_t), &i2o_dev_acc_attr,
		DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, (caddr_t *)&buf,
		&real_length, &acc_hdl) != DDI_SUCCESS) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_get_hrt: ddi_dma_mem_alloc failed"));
		goto cleanup;
	}

	bzero((caddr_t)buf, real_length);

	if (ddi_dma_addr_bind_handle(iop->hrt.dma_handle, NULL, (caddr_t)buf,
	    real_length, DDI_DMA_READ | DDI_DMA_STREAMING, DDI_DMA_SLEEP,
	    NULL, &dma_cookie, &ncookies) != DDI_SUCCESS) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_get_hrt: cannot bind memory"));
		goto cleanup;
	}

	ASSERT(ncookies == 1);

	DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
		"i2o_get_hrt: dma_bind (vaddr %p paddr %x length %x)",
		(void *)buf, dma_cookie.dmac_address,
		(int)dma_cookie.dmac_size));

	/* allocate a message frame from Inbound queue */
	msgp = (i2o_exec_hrt_get_message_t *)iop_msg_alloc(iop);
	if (msgp == NULL) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_get_hrt: trans_msg_alloc failed"));
		(void) ddi_dma_unbind_handle(iop->hrt.dma_handle);
		goto cleanup;
	}

	/*
	 * Construct the ExecHrtGet message.
	 */
	init_std_msghdr(iop, &msgp->StdMessageFrame, 0x40, 0,
		sizeof (i2o_exec_hrt_get_message_t), I2O_EXEC_HRT_GET);
	init_sgl_simple_ele(iop, msgp->SGL.u1.Simple,
	    I2O_SGL_FLAGS_LAST_ELEMENT | I2O_SGL_FLAGS_END_OF_BUFFER,
	    sizeof (i2o_hrt_t), (uint_t)dma_cookie.dmac_address);

#ifdef I2O_DEBUG
	if (i2o_debug & I2O_DEBUG_MSG)
		dump_message((uint32_t *)msgp, "ExecHrtGet");
#endif

	/* send the message to the IOP */
	(void) iop_msg_send(iop, (void *)msgp);

	/* since interrupts are disabled, we poll for the reply message */
	rmp = iop_poll_reply_msg(iop);
	if ((rmp == NULL) || (rmp->ReqStatus != I2O_REPLY_STATUS_SUCCESS)) {
		if (rmp)
		    iop_msg_free(iop, rmp);
		(void) ddi_dma_unbind_handle(iop->hrt.dma_handle);
		goto cleanup;
	}

	ASSERT(get_msg_Function((i2o_message_frame_t *)rmp,
		iop->ob_msg_queue.acc_hdl) == I2O_EXEC_HRT_GET); /* paranoia? */

	/* free up the reply message buffer */
	iop_msg_free(iop, rmp);

	ASSERT(buf->HRTVersion == 0);	/* HRT version for 1.5 is 0x00 */

	hrt_size = (sizeof (i2o_hrt_t) - sizeof (i2o_hrt_entry_t)) +
		(sizeof (i2o_hrt_entry_t) *
		ddi_get16(acc_hdl, &buf->NumberEntries));

	/*
	 * NOTE: Some old versions of RTOS is not setting the EntryLength
	 * correctly. Also, I am not sure if all implementations of RTOS
	 * set this field. So, the following ASSERTION is disabled.
	 *
	 * ASSERT((buf->EntryLength * 4) == sizeof (i2o_hrt_entry_t));
	 */

	/* free up the temporary buffer */
	(void) ddi_dma_unbind_handle(iop->hrt.dma_handle);
	ddi_dma_mem_free(&acc_hdl);
	buf = NULL;

	/*
	 * Now, allocate the correct size buffer for HRT and send another
	 * ExecHrtGet message.
	 */
	if (iop->hrt.bufp == NULL || (iop->hrt.size < hrt_size)) {

	    /* free up any old buffer */
	    if (iop->hrt.bufp != NULL) {
		ddi_dma_mem_free(&iop->hrt.acc_hdl);
		iop->hrt.bufp = NULL;
	    }

	    iop->hrt.size = hrt_size;

	    /* allocate a new buffer for HRT */
	    if (ddi_dma_mem_alloc(iop->hrt.dma_handle,
		iop->hrt.size, &i2o_dev_acc_attr, DDI_DMA_CONSISTENT,
		DDI_DMA_SLEEP, NULL, (caddr_t *)&iop->hrt.bufp,
		&real_length, &iop->hrt.acc_hdl) != DDI_SUCCESS) {

		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_get_hrt: ddi_dma_mem_alloc failed"));
		goto cleanup;
	    }
	    bzero((caddr_t)iop->hrt.bufp, real_length);
	}

	if (ddi_dma_addr_bind_handle(iop->hrt.dma_handle, NULL,
	    (caddr_t)iop->hrt.bufp, iop->hrt.size,
	    DDI_DMA_READ | DDI_DMA_STREAMING, DDI_DMA_SLEEP,
	    NULL, &dma_cookie, &ncookies) != DDI_SUCCESS) {

		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_get_hrt: cannot bind memory"));
		goto cleanup;
	}

	ASSERT(ncookies == 1);

	DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
		"i2o_get_hrt: dma_bind (vaddr %p paddr %x length %x)",
		(void *)iop->hrt.bufp, dma_cookie.dmac_address,
		(int)dma_cookie.dmac_size));

	/* allocate a message frame from Inbound queue */
	msgp = (i2o_exec_hrt_get_message_t *)iop_msg_alloc(iop);
	if (msgp == NULL) {

		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_get_hrt: trans_msg_alloc failed"));
		(void) ddi_dma_unbind_handle(iop->hrt.dma_handle);
		goto cleanup;
	}

	/*
	 * Construct the ExecHrtGet message (again!).
	 */
	init_std_msghdr(iop, &msgp->StdMessageFrame, 0x40, 0,
		sizeof (i2o_exec_hrt_get_message_t), I2O_EXEC_HRT_GET);
	init_sgl_simple_ele(iop, msgp->SGL.u1.Simple,
	    I2O_SGL_FLAGS_LAST_ELEMENT | I2O_SGL_FLAGS_END_OF_BUFFER,
	    hrt_size, (uint_t)dma_cookie.dmac_address);

#ifdef I2O_DEBUG
	if (i2o_debug & I2O_DEBUG_MSG)
		dump_message((uint32_t *)msgp, "ExecHrtGet");
#endif

	/* send the message to the IOP */
	(void) iop_msg_send(iop, (void *)msgp);

	/* since interrupts are disabled, we poll for the reply message */
	rmp = iop_poll_reply_msg(iop);
	if ((rmp == NULL) || (rmp->ReqStatus != I2O_REPLY_STATUS_SUCCESS)) {
		if (rmp)
		    iop_msg_free(iop, rmp);
#ifdef I2O_DEBUG
		if (i2o_debug & I2O_DEBUG_MSG)
			dump_reply_message(iop, rmp);
#endif
		(void) ddi_dma_unbind_handle(iop->hrt.dma_handle);
		goto cleanup;
	}

	ASSERT(get_msg_Function((i2o_message_frame_t *)rmp,
		iop->ob_msg_queue.acc_hdl) == I2O_EXEC_HRT_GET); /* paranoia? */

	/* free up the reply message buffer */
	iop_msg_free(iop, rmp);

	(void) ddi_dma_unbind_handle(iop->hrt.dma_handle);

#ifdef I2O_DEBUG
	if (i2o_debug & I2O_DEBUG_HRT)
		dump_hrt(iop);
#endif

	return (SUCCESS);

	/*
	 * Error return; free up the allocated resources and return NULL.
	 */
cleanup:

	if (buf != NULL)
		ddi_dma_mem_free(&acc_hdl);

	if (iop->hrt.bufp != NULL) {
		ddi_dma_mem_free(&iop->hrt.acc_hdl);
		iop->hrt.bufp = NULL;
	}

	if (iop->hrt.dma_handle != NULL) {
		ddi_dma_free_handle(&iop->hrt.dma_handle);
		iop->hrt.dma_handle = NULL;
	}

	return (FAILURE);
}


/*
 * Create the system table entry for the IOP and update all IOPs with
 * the latest System Table. It sends ExecSysTabSet message to all
 * IOPs. If necessary it sends the ExecSysEnable to the new IOP that
 * is being initialized.
 *
 * Note: It is assumed that this routine is called from the IOP init
 * routine.
 */
static int
i2o_create_systab(iop_instance_t *iop)
{
	ddi_dma_handle_t	dma_handle = NULL;
	ddi_acc_handle_t	acc_hdl;
	size_t			real_length;
	ddi_dma_cookie_t	dma_cookie;
	uint_t			ncookies;
	i2o_iop_entry_t		*entp;
	i2o_set_systab_header_t	*systab = NULL;
	i2o_iop_entry_t		*systab_entryp;
	int			i;
	iop_instance_t		*p;
	i2o_exec_sys_tab_set_message_t	*msgp;
	i2o_single_reply_message_frame_t *rmp = NULL;
	uint_t			systab_size;
	tcontext_t		tcxt; /* transaction context structure */


	/*
	 * *********************************************************
	 * Create SysTab entry for this IOP.
	 * *********************************************************
	 */
	if (ddi_dma_alloc_handle(iop->dip, &dma_attr_contig, DDI_DMA_SLEEP,
	    NULL, &iop->systab.dma_handle) != DDI_SUCCESS) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
		    "i2o_create_systab: ddi_dma_alloc_handle failed"));
		goto cleanup;
	}

	/* allocate the buffer for systab entry */
	if (ddi_dma_mem_alloc(iop->systab.dma_handle, sizeof (i2o_iop_entry_t),
	    &i2o_dev_acc_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    (caddr_t *)&iop->systab.bufp, &real_length,
	    &iop->systab.acc_hdl) != DDI_SUCCESS) {

		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_create_systab: ddi_dma_mem_alloc failed"));
		goto cleanup;
	}

	bzero((caddr_t)iop->systab.bufp, real_length);

	/*
	 * initialize the systab entry with the information from the iop
	 * status buffer.
	 */
	entp = iop->systab.bufp;
	entp->OrganizationID = iop->status.bufp->OrganizationID;
	entp->IopCapabilities = iop->status.bufp->IopCapabilities;
	entp->InboundMessageFrameSize =
		iop->status.bufp->InboundMFrameSize;
	entp->MessengerType = iop->status.bufp->MessengerType;
	entp->IopState = I2O_IOP_STATE_OPERATIONAL; /* expected state */
	put_i2o_iop_entry_I2oVersion(entp,
	    get_i2o_exec_status_reply_I2oVersion(iop->status.bufp,
		iop->status.acc_hdl), iop->systab.acc_hdl);
	put_i2o_iop_entry_SegmentNumber(entp,
	    get_i2o_exec_status_reply_SegmentNumber(iop->status.bufp,
	    iop->status.acc_hdl), iop->systab.acc_hdl);
	put_i2o_iop_entry_IOP_ID(entp, iop->iop_id, iop->systab.acc_hdl);
	ddi_put32(iop->systab.acc_hdl,
		&entp->MessengerInfo.InboundMessagePortAddressLow,
		iop->nexus_trans->iop_inbound_fifo_paddr);
	ddi_put32(iop->systab.acc_hdl,
		&entp->MessengerInfo.InboundMessagePortAddressHigh, 0);

	/*
	 * *********************************************************
	 * Create a System Table for sending ExecSysTabSet message
	 * to all IOP(s).
	 * *********************************************************
	 */
	/* allocate the buffer for systab header and for the systab entries */
	systab_size = sizeof (i2o_set_systab_header_t) +
		(niop * sizeof (i2o_iop_entry_t));

	if (ddi_dma_alloc_handle(iop->dip, &dma_attr_contig, DDI_DMA_SLEEP,
	    NULL, &dma_handle) != DDI_SUCCESS) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
		    "i2o_create_systab: ddi_dma_alloc_handle failed"));
		goto cleanup;
	}

	if (ddi_dma_mem_alloc(dma_handle, systab_size,
	    &i2o_dev_acc_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    (caddr_t *)&systab, &real_length,
	    &acc_hdl) != DDI_SUCCESS) {

		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_create_systab: ddi_dma_mem_alloc failed"));
		goto cleanup;
	}

	bzero((caddr_t)systab, real_length);

	/* fill in the systab header and systab entries */
	systab->NumberEntries = niop;
	systab->SysTabVersion = I2O_VERSION_11;
	ddi_put32(iop->systab.acc_hdl, &systab->CurrentChangeIndicator,
		(uint32_t)(iop->iop_id - BASE_IOP_ID));

	systab_entryp = (i2o_iop_entry_t *)&systab[1];
	iop->next = ioplist;

	for (p = iop, i = 0; i < niop; i++) {
		systab_entryp[i] = p->systab.bufp[0];
		p = p->next;
	}

	if (ddi_dma_addr_bind_handle(dma_handle, NULL, (caddr_t)systab,
	    real_length, DDI_DMA_WRITE | DDI_DMA_STREAMING, DDI_DMA_SLEEP,
	    NULL, &dma_cookie, &ncookies) != DDI_SUCCESS) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_create_systab: cannot bind memory"));
		goto cleanup;
	}

	ASSERT(ncookies == 1);

	DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
		"i2o_create_systab: dma_bind (vaddr %p paddr %x length %x)",
		(void *)systab, dma_cookie.dmac_address,
		(int)dma_cookie.dmac_size));

	/* Now, send ExecSysTabSet message to each of the IOPs */
	for (p = iop, i = 0; i < niop; i++) {

		/* allocate a message frame from Inbound queue */
		msgp = (i2o_exec_sys_tab_set_message_t *)iop_msg_alloc(p);
		if (msgp == NULL) {

		    DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_create_systab: trans_msg_alloc failed"));
		    (void) ddi_dma_unbind_handle(dma_handle);
		    goto cleanup;
		}
		/*
		 * Construct the ExecSysTabSet message.
		 *
		 * Note: The implied assumption is that the message frame has
		 * enough room for 3 SGL elements.
		 */

		init_std_msghdr(p, &msgp->StdMessageFrame, 0x40, 0,
		    sizeof (i2o_exec_sys_tab_set_message_t) +
		    2 * sizeof (i2o_sg_element_t), I2O_EXEC_SYS_TAB_SET);
		msgp->HostUnitID = 0;
		put_i2o_exec_sys_tab_set_SegmentNumber(msgp,
		    get_i2o_exec_status_reply_SegmentNumber(p->status.bufp,
		    p->status.acc_hdl), p->systab.acc_hdl);
		put_i2o_exec_sys_tab_set_IOP_ID(msgp, p->iop_id,
			p->systab.acc_hdl);

		if (p != iop) {
			/*
			 * For other IOPs we don't poll the reply, so
			 * setup the InitiatorContext/TransactionContext.
			 */
			cv_init(&tcxt.cv, NULL, CV_DEFAULT, NULL);
			mutex_init(&tcxt.cv_mutex, NULL, MUTEX_DRIVER, NULL);
			/* initialize the transcation context structure */
			tcxt.iop = p;
			tcxt.done_flag = 0;
			ddi_put32(p->nexus_trans->acc_handle,
			    &msgp->TransactionContext,
			    (uint32_t)(uintptr_t)&tcxt);
			ddi_put32(p->nexus_trans->acc_handle,
			    (uint32_t *)&msgp->StdMessageFrame.InitiatorContext.
			    initiator_context_32bits,
			    (uint32_t)i2o_msg_common_reply);
		}

		/* First buffer is for systab itself */
		init_sgl_simple_ele(p, &msgp->SGL.u1.Simple[0],
		    I2O_SGL_FLAGS_END_OF_BUFFER, systab_size,
		    (uint_t)dma_cookie.dmac_address);

		/*
		 * Second buffer is for Private Memory Space allocation.
		 *
		 * Note: The spec is not clear if this buffer can be NULL
		 * for the IOP which was already initialized to OP state
		 * and there is no change to its configuration. Here, we
		 * will set it to NULL assuming that it is ignored.
		 */
		if (p == iop) {
		    init_sgl_simple_ele(p, &msgp->SGL.u1.Simple[1],
			I2O_SGL_FLAGS_END_OF_BUFFER,
			p->hw_config.mem_size, (uint_t)p->hw_config.mem_base);
		} else {
		    init_sgl_simple_ele(p, &msgp->SGL.u1.Simple[1],
			I2O_SGL_FLAGS_END_OF_BUFFER, 0, 0);
		}

		/*
		 * Third buffer is for Private IO Space allocation.
		 *
		 * Note: The spec is not clear if this buffer can be NULL
		 * for the IOP which was already initialized to OP state
		 * and there is no change to its configuration. Here, we
		 * will set it to NULL assuming that it is ignored.
		 */
		if (p == iop) {
		    init_sgl_simple_ele(p, &msgp->SGL.u1.Simple[2],
			I2O_SGL_FLAGS_LAST_ELEMENT |
			I2O_SGL_FLAGS_END_OF_BUFFER,
			p->hw_config.io_size, (uint_t)p->hw_config.io_base);
		} else {
		    init_sgl_simple_ele(p, &msgp->SGL.u1.Simple[2],
			I2O_SGL_FLAGS_LAST_ELEMENT |
			I2O_SGL_FLAGS_END_OF_BUFFER, 0, 0);
		}

#ifdef I2O_DEBUG
		if (i2o_debug & I2O_DEBUG_MSG)
			dump_message((uint32_t *)msgp, "ExecSysTabSet");
#endif

		/* send the message to the IOP */
		(void) iop_msg_send(p, (void *)msgp);

		/* wait for the reply message */
		if (p == iop) {
			/*
			 * For this IOP, interrupts are disabled. So, we poll
			 * for the reply message.
			 */
			rmp = iop_poll_reply_msg(p);

			if ((rmp == NULL) ||
				(rmp->ReqStatus != I2O_REPLY_STATUS_SUCCESS)) {

				if (rmp)
					iop_msg_free(p, rmp);
#ifdef I2O_DEBUG
				if (i2o_debug & I2O_DEBUG_MSG)
					dump_reply_message(p, rmp);
#endif
				(void) ddi_dma_unbind_handle(dma_handle);
				goto cleanup;
			}

			/* paranoia? */
			ASSERT(get_msg_Function((i2o_message_frame_t *)rmp,
			    iop->ob_msg_queue.acc_hdl) == I2O_EXEC_SYS_TAB_SET);

			/* free up the reply message buffer */
			iop_msg_free(p, rmp);

		} else {
			/* For other IOPs, wait for the reply message */
			mutex_enter(&tcxt.cv_mutex);
			while (!tcxt.done_flag)	/* wait for the reply */
				cv_wait(&tcxt.cv, &tcxt.cv_mutex);
			mutex_exit(&tcxt.cv_mutex);

			cv_destroy(&tcxt.cv);
			mutex_destroy(&tcxt.cv_mutex);

			/* check the status for SUCCESS */
			if (tcxt.status != I2O_REPLY_STATUS_SUCCESS) {
				(void) ddi_dma_unbind_handle(dma_handle);
				goto cleanup;
			}
		}

		/*
		 * For the new IOP, send the ExecSysEnable message.
		 */
		if (p == iop) {
			if (i2o_send_exec_enable(iop) != SUCCESS) {
				(void) ddi_dma_unbind_handle(dma_handle);
				goto cleanup;
			}
		}
	}

	(void) ddi_dma_unbind_handle(dma_handle);

	if (iop->status.bufp->IopState != I2O_IOP_STATE_OPERATIONAL) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_create_systab: invalid IOP state"));
		goto cleanup;
	}

	ddi_dma_mem_free(&acc_hdl); /* free the systab buffer */

	ddi_dma_free_handle(&dma_handle);

	return (SUCCESS);

	/*
	 * Error return; free up the allocated resources and return NULL.
	 */
cleanup:

	if (iop->systab.bufp != NULL) {
		ddi_dma_mem_free(&iop->systab.acc_hdl);
		iop->systab.bufp = NULL;
	}

	if (iop->systab.dma_handle != NULL) {
		ddi_dma_free_handle(&iop->systab.dma_handle);
		iop->systab.dma_handle = NULL;
	}

	if (systab != NULL)
		ddi_dma_mem_free(&acc_hdl);

	if (dma_handle != NULL)
		ddi_dma_free_handle(&dma_handle);

	return (FAILURE);
}

/*
 * Send the ExecSysEnable message to the IOP if it is in the
 * READY state. It assumes that the IOP interrupts are disabled.
 */
static int
i2o_send_exec_enable(iop_instance_t *iop)
{
	i2o_exec_sys_enable_message_t	*mp;
	i2o_single_reply_message_frame_t *rmp = NULL;

	/*
	 * Get the current state of IOP.
	 */
	if (i2o_get_iop_status(iop) == FAILURE)
		goto cleanup;

	if (iop->status.bufp->IopState == I2O_IOP_STATE_READY) {
	    /* allocate a message frame from Inbound queue */
	    mp = (i2o_exec_sys_enable_message_t *)iop_msg_alloc(iop);
	    if (mp == NULL) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_create_systab: trans_msg_alloc failed"));
		goto cleanup;
	    }

	    /* Construct the ExecSysEanble message. */
	    init_std_msghdr(iop, &mp->StdMessageFrame, 0x0, 0,
		sizeof (i2o_exec_sys_enable_message_t), I2O_EXEC_SYS_ENABLE);

#ifdef I2O_DEBUG
	    if (i2o_debug & I2O_DEBUG_MSG)
		dump_message((uint32_t *)mp, "ExecSysEnable");
#endif

	    /* send the message to the IOP */
	    (void) iop_msg_send(iop, (void *)mp);

	    /* since interrupts are disabled, we poll for the reply message */
	    rmp = iop_poll_reply_msg(iop);
	    if ((rmp == NULL) || (rmp->ReqStatus != I2O_REPLY_STATUS_SUCCESS)) {
#ifdef I2O_DEBUG
		if (i2o_debug & I2O_DEBUG_MSG)
			dump_reply_message(iop, rmp);
#endif
		if (rmp)
			iop_msg_free(iop, rmp);
		goto cleanup;
	    }

	    /* paranoia? */
	    ASSERT(get_msg_Function((i2o_message_frame_t *)rmp,
		iop->ob_msg_queue.acc_hdl) == I2O_EXEC_SYS_ENABLE);

	    iop_msg_free(iop, rmp); /* free up the reply message buffer */

	    /* get the IOP state now; it should be in OPERATIONAL state */
	    if (i2o_get_iop_status(iop) == FAILURE)
		goto cleanup;
	}

	return (SUCCESS);

cleanup:
	return (FAILURE);
}

/*
 * Send an ExecIopReset message. This function is called from the
 * i2o_msg_iop_init() with interrupts disabled.
 */
static int
i2o_send_exec_iop_reset(iop_instance_t *iop)
{
	ddi_dma_handle_t dma_handle = NULL;
	ddi_acc_handle_t acc_hdl;
	i2o_exec_iop_reset_status_t *buf = NULL;
	i2o_exec_iop_reset_message_t *rmsgp;
	size_t real_length;
	ddi_dma_cookie_t dma_cookie;
	uint_t ncookies;

	/* allocate a DMA handle */
	if (ddi_dma_alloc_handle(iop->dip, &dma_attr_contig, DDI_DMA_SLEEP,
		    NULL, &dma_handle) != DDI_SUCCESS) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
		    "i2o_send_exec_iop_reset: ddi_dma_alloc_handle failed"));
		goto cleanup;
	}

	/*
	 * Allocate a temporary buffer for the status word structure.
	 */
	if (ddi_dma_mem_alloc(dma_handle,
		sizeof (i2o_exec_iop_reset_status_t), &i2o_dev_acc_attr,
		DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, (caddr_t *)&buf,
		&real_length, &acc_hdl) != DDI_SUCCESS) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_send_exec_iop_reset: ddi_dma_mem_alloc failed"));
		goto cleanup;
	}

	if (ddi_dma_addr_bind_handle(dma_handle, NULL, (caddr_t)buf,
	    real_length, DDI_DMA_READ | DDI_DMA_STREAMING, DDI_DMA_SLEEP,
	    NULL, &dma_cookie, &ncookies) != DDI_SUCCESS) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_send_exec_iop_reset: cannot bind memory"));
		goto cleanup;
	}

	DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
	    "i2o_send_exec_iop_reset: dma_bind (vaddr %p paddr %x length %x)",
	    (void *)buf, dma_cookie.dmac_address, (int)dma_cookie.dmac_size));

	/* allocate a message frame from Inbound queue */
	rmsgp = (i2o_exec_iop_reset_message_t *)iop_msg_alloc(iop);
	if (rmsgp == NULL) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_send_exec_iop_reset: trans_msg_alloc failed"));
		(void) ddi_dma_unbind_handle(dma_handle);
		goto cleanup;
	}

	/* construct the ExecIopReset message */
	init_std_msghdr(iop, (i2o_message_frame_t *)rmsgp, 0x0, 0,
		sizeof (i2o_exec_iop_reset_message_t),
		I2O_EXEC_IOP_RESET);
	ddi_put32(iop->nexus_trans->acc_handle, &rmsgp->StatusWordLowAddress,
		dma_cookie.dmac_address);
	ddi_put32(iop->nexus_trans->acc_handle,
		&rmsgp->StatusWordHighAddress, 0);
	buf->ResetStatus = 0;

#ifdef I2O_DEBUG
	if (i2o_debug & I2O_DEBUG_MSG)
		dump_message((uint32_t *)rmsgp, "ExecIopReset");
#endif

	/* send the message to the IOP */
	(void) iop_msg_send(iop, (void *)rmsgp);

	/* poll on the status word for IN_PROGRESS state */
	while (buf->ResetStatus != I2O_EXEC_IOP_RESET_IN_PROGRESS) {
		int mseconds = 60000; /* 60 seconds */

		if (buf->ResetStatus == I2O_EXEC_IOP_RESET_REJECTED)
			goto cleanup;

		if (--mseconds < 0) {
			DEBUGF(I2O_DEBUG_DEBUG,
				(CE_CONT, "iop_reset: timed out"));
			goto cleanup;
		}

		drv_usecwait(1000);	/* wait for 1msec */

		/* sync DMA memory */
		(void) ddi_dma_sync(dma_handle, 0, 1, DDI_DMA_SYNC_FORCPU);
	}

	(void) ddi_dma_unbind_handle(dma_handle);

	ddi_dma_mem_free(&acc_hdl);

	ddi_dma_free_handle(&dma_handle);

	return (SUCCESS);

	/*
	 * Error return; free up the allocated resources and return NULL.
	 */
cleanup:
	if (buf != NULL)
		ddi_dma_mem_free(&acc_hdl);

	if (dma_handle != NULL)
		ddi_dma_free_handle(&dma_handle);

	return (FAILURE);
}


static int
i2o_get_lct(iop_instance_t *iop)
{
	size_t real_length;
	ddi_dma_cookie_t dma_cookie;
	uint_t ncookies;
	i2o_exec_lct_notify_message_t *msgp;
	i2o_single_reply_message_frame_t *rmp = NULL;
	uint_t lct_size;

	/* allocate a DMA handle if necessary */
	if (iop->lct.dma_handle == NULL) {
	    if (ddi_dma_alloc_handle(iop->dip, &dma_attr_contig, DDI_DMA_SLEEP,
		    NULL, &iop->lct.dma_handle) != DDI_SUCCESS) {
		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
		    "i2o_get_lct: ddi_dma_alloc_handle failed"));
		goto cleanup;
	    }
	}

	lct_size = ddi_get32(iop->status.acc_hdl,
		&iop->status.bufp->ExpectedLCTSize);
	/*
	 * Allocate the buffer for LCT and send ExecLctNotify message.
	 */
	if (iop->lct.bufp == NULL || (iop->lct.size < lct_size)) {

	    /* free up any old buffer */
	    if (iop->lct.bufp != NULL) {
		ddi_dma_mem_free(&iop->lct.acc_hdl);
		iop->lct.bufp = NULL;
	    }

	    iop->lct.size = lct_size;

	    /* allocate a new buffer for LCT */
	    if (ddi_dma_mem_alloc(iop->lct.dma_handle,
		iop->lct.size, &i2o_dev_acc_attr, DDI_DMA_CONSISTENT,
		DDI_DMA_SLEEP, NULL, (caddr_t *)&iop->lct.bufp,
		&real_length, &iop->lct.acc_hdl) != DDI_SUCCESS) {

		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_get_lct: ddi_dma_mem_alloc failed"));
		goto cleanup;
	    }

	    bzero((caddr_t)iop->lct.bufp, real_length);
	}

	if (ddi_dma_addr_bind_handle(iop->lct.dma_handle, NULL,
	    (caddr_t)iop->lct.bufp, iop->lct.size,
	    DDI_DMA_READ | DDI_DMA_STREAMING, DDI_DMA_SLEEP,
	    NULL, &dma_cookie, &ncookies) != DDI_SUCCESS) {

		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_get_lct: cannot bind memory"));
		goto cleanup;
	}

	ASSERT(ncookies == 1);

	DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
		"i2o_get_lct: dma_bind (vaddr %p paddr %x length %x)",
		(void *)iop->lct.bufp, dma_cookie.dmac_address,
		(int)dma_cookie.dmac_size));

	/* allocate a message frame from Inbound queue */
	msgp = (i2o_exec_lct_notify_message_t *)iop_msg_alloc(iop);
	if (msgp == NULL) {

		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_get_lct: trans_msg_alloc failed"));
		(void) ddi_dma_unbind_handle(iop->lct.dma_handle);
		goto cleanup;
	}

	/*
	 * Construct the ExecLctNotify message.
	 */
	init_std_msghdr(iop, &msgp->StdMessageFrame, 0x60, 0,
		sizeof (i2o_exec_lct_notify_message_t), I2O_EXEC_LCT_NOTIFY);
	msgp->ClassIdentifier = (uint32_t)0xFFFFFFFF;
	msgp->LastReportedChangeIndicator = 0x0;
	init_sgl_simple_ele(iop, msgp->SGL.u1.Simple,
	    I2O_SGL_FLAGS_LAST_ELEMENT | I2O_SGL_FLAGS_END_OF_BUFFER,
	    iop->lct.size, (uint_t)dma_cookie.dmac_address);

#ifdef I2O_DEBUG
	if (i2o_debug & I2O_DEBUG_MSG)
		dump_message((uint32_t *)msgp, "ExecLctNotify");
#endif

	/* send the message to the IOP */
	(void) iop_msg_send(iop, (void *)msgp);

	/* since interrupts are disabled, we poll for the reply message */
	rmp = iop_poll_reply_msg(iop);
	if ((rmp == NULL) || (rmp->ReqStatus != I2O_REPLY_STATUS_SUCCESS)) {

#ifdef I2O_DEBUG
		if (i2o_debug & I2O_DEBUG_MSG)
			dump_reply_message(iop, rmp);
#endif
		if (rmp)
			iop_msg_free(iop, rmp);
		(void) ddi_dma_unbind_handle(iop->lct.dma_handle);
		goto cleanup;
	}

	/* paranoia? */
	ASSERT(get_msg_Function((i2o_message_frame_t *)rmp,
		iop->ob_msg_queue.acc_hdl) == I2O_EXEC_LCT_NOTIFY);

	/* free up the reply message buffer */
	iop_msg_free(iop, rmp);

	(void) ddi_dma_unbind_handle(iop->lct.dma_handle);

#ifdef I2O_DEBUG
	if (i2o_debug & I2O_DEBUG_LCT)
		dump_lct(iop);
#endif

	return (SUCCESS);

	/*
	 * Error return; free up the allocated resources and return NULL.
	 */
cleanup:

	if (iop->lct.bufp != NULL) {
		ddi_dma_mem_free(&iop->lct.acc_hdl);
		iop->lct.bufp = NULL;
	}

	if (iop->lct.dma_handle != NULL) {
		ddi_dma_free_handle(&iop->lct.dma_handle);
		iop->lct.dma_handle = NULL;
	}

	return (FAILURE);
}

#define	EXEC_CLASS_EVENT_MASK	\
	(I2O_EVENT_IND_RESOURCE_LIMIT |	I2O_EVENT_IND_CONNECTION_FAIL |	\
	I2O_EVENT_IND_ADAPTER_FAULT | I2O_EVENT_IND_POWER_FAIL |	\
	I2O_EVENT_IND_RESET_PENDING | I2O_EVENT_IND_RESET_IMMINENT |	\
	I2O_EVENT_IND_HARDWARE_FAIL | I2O_EVENT_IND_XCT_CHANGE |	\
	I2O_EVENT_IND_NEW_LCT_ENTRY | I2O_EVENT_IND_MODIFIED_LCT |	\
	I2O_EVENT_IND_DDM_AVAILABILITY)

/*
 * Register Executive Class events to get notified by the IOP when
 * any of these events occur.
 *
 * Assumpition: IOP interrupts are disabled.
 */
static int
i2o_iop_event_register(iop_instance_t *iop)
{
	i2o_util_event_register_message_t *msgp;

	/* allocate a message frame from Inbound queue */
	msgp = (i2o_util_event_register_message_t *)iop_msg_alloc(iop);
	if (msgp == NULL) {

		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
			"i2o_iop_event_register: trans_msg_alloc failed"));
		return (FAILURE);
	}

	/*
	 * Construct the UtilEventRegister message. There is no reply
	 * to this message until one of the specified events occurs.
	 */
	init_std_msghdr(iop, &msgp->StdMessageFrame, 0x0, 0,
	    sizeof (i2o_util_event_register_message_t),
	    I2O_UTIL_EVENT_REGISTER);
	ddi_put32(iop->nexus_trans->acc_handle,
	    &msgp->TransactionContext, (uint32_t)(uintptr_t)iop);
	ddi_put32(iop->nexus_trans->acc_handle,
	    (uint32_t *)&msgp->StdMessageFrame.InitiatorContext.
	    initiator_context_32bits, (uint32_t)i2o_msg_iop_event_reply);
	/* Fow now, specify only the Executive Class events and */
	/* Config Dialog request event */
	ddi_put32(iop->nexus_trans->acc_handle, &msgp->EventMask,
	    EXEC_CLASS_EVENT_MASK | I2O_EVENT_IND_CONFIGURATION_FLAG);

	iop->event_mask = EXEC_CLASS_EVENT_MASK;

#ifdef I2O_DEBUG
	if (i2o_debug & I2O_DEBUG_MSG)
		dump_message((uint32_t *)msgp, "UtilEventRegister");
#endif

	/* send the message to the IOP */
	(void) iop_msg_send(iop, (void *)msgp);

	return (SUCCESS);
}

/*
 * called by the I2O nexus driver from i2o_create_devinfo().
 */
void
i2o_msg_get_lct_info(i2o_iop_handle_t *handlep, i2o_lct_t **lctp,
	ddi_acc_handle_t *acc_handlep)
{
	iop_instance_t *iop = ((i2o_iop_impl_hdl_t *)handlep)->iop;

	if (lctp)
		*lctp = iop->lct.bufp;

	if (acc_handlep)
		*acc_handlep = iop->lct.acc_hdl;
}


/*
 * ************************************************************************
 * *** Reply Message Processing functions				***
 * ************************************************************************
 */

/*
 * Call back function to process the Executive Class event notification
 * messages.
 *
 * For now, we process only the MODIFY_LCT event to update the local
 * copy of the LCT. For other events we simply print the event information
 * and ignore it. XXX FIX IT WHEN NEEDED XXX
 */
static void
i2o_msg_iop_event_reply(void *p, ddi_acc_handle_t acc_hdl)
{
	i2o_util_event_register_reply_t *msgp;
	iop_instance_t *iop;
	uint32_t event_indicator;
	i2o_hrt_entry_t *hrt_entp;
	i2o_lct_entry_t *lct_entp;
	i2o_lct_entry_t	*lp;
	uint_t tid;
	int i, n;
	uint32_t event_data;

	msgp = (i2o_util_event_register_reply_t *)p;
	iop = (iop_instance_t *)
	    (uintptr_t)ddi_get32(acc_hdl, &msgp->TransactionContext);
	event_indicator = ddi_get32(acc_hdl, &msgp->EventIndicator);

	switch (event_indicator) {

	case I2O_EVENT_IND_ADAPTER_FAULT:
		hrt_entp = (i2o_hrt_entry_t *)msgp->EventData;
		cmn_err(CE_CONT,
			"^Received ADAPTER_FAULT event from the IOP %x",
			iop->iop_id);
		cmn_err(CE_CONT, "^\tAdapterID: %x\n", ddi_get32(acc_hdl,
			&hrt_entp->AdapterID));
		cmn_err(CE_CONT, "^\tControllingTID: %x\n",
		    get_hrt_entry_ControllingTID(hrt_entp, acc_hdl));
		cmn_err(CE_CONT, "^\tAdapterState: %x\n",
		    get_hrt_entry_AdapterState(hrt_entp, acc_hdl));
		cmn_err(CE_CONT, "^\tBusType: %x\n", hrt_entp->BusType);
		cmn_err(CE_CONT, "^\tBusNumber: %x\n", hrt_entp->BusNumber);
		break;

	case I2O_EVENT_IND_CONNECTION_FAIL:
		cmn_err(CE_CONT,
			"^Received CONNECTION_FAIL event from the IOP %x",
			iop->iop_id);
		break;

	case I2O_EVENT_IND_DDM_AVAILABILITY:
		cmn_err(CE_CONT,
			"^Received DDM_AVAILABILITY event from the IOP %x",
			iop->iop_id);
		event_data = ddi_get32(acc_hdl, msgp->EventData);
		cmn_err(CE_CONT, "^\tTID %x Error Code %x", event_data & 0xFFF,
			(event_data >> 12) & 0xF);
		break;

	case I2O_EVENT_IND_HARDWARE_FAIL:
		cmn_err(CE_CONT,
			"^Received HARDWARE_FAIL event from the IOP %x",
			iop->iop_id);
		event_data = ddi_get32(acc_hdl, msgp->EventData);
		cmn_err(CE_CONT, "^\tError Code %x", event_data);
		break;

	case I2O_EVENT_IND_MODIFIED_LCT:
		/*
		 * LCT entry is modified. Need to update the local
		 * copy of the LCT.
		 */

		lct_entp = (i2o_lct_entry_t *)msgp->EventData;
		tid = get_lct_entry_LocalTID(lct_entp, acc_hdl);

		/*
		 * locate the entry in the local copy of the LCT that
		 * matches the TID that has changed. And update the entry.
		 */
		mutex_enter(&iop->lct.lct_mutex);

		lp = iop->lct.bufp->LCTEntry;
		n = ((ddi_get16(iop->lct.acc_hdl, &iop->lct.bufp->TableSize) <<
			2) - sizeof (i2o_lct_t) + sizeof (i2o_lct_entry_t)) /
			sizeof (i2o_lct_entry_t);

		for (i = 0; i < n; i++) {
		    if (tid == get_lct_entry_LocalTID(&lp[i], iop->lct.acc_hdl))
			break;
		}

		ASSERT(i < n);

		/* copy the modified entry */
		lp[i] = *lct_entp;

		mutex_exit(&iop->lct.lct_mutex);

#ifdef I2O_DEBUG
		cmn_err(CE_CONT, "!Received MODIFY_LCT event from the IOP %x",
			iop->iop_id);
		cmn_err(CE_CONT, "!\tLocalTID: %x\n",
		    get_lct_entry_LocalTID(lct_entp, acc_hdl));
		cmn_err(CE_CONT, "!\tDeviceFlags: %x\n",
		    ddi_get32(acc_hdl, &lct_entp->DeviceFlags));
		cmn_err(CE_CONT, "!\tChangeIndicator: %x\n",
		    ddi_get32(acc_hdl, &lct_entp->ChangeIndicator));
		cmn_err(CE_CONT, "!\tClass: %x\n",
		    get_lct_entry_Class(lct_entp, acc_hdl));
		cmn_err(CE_CONT, "!\tSubClassInfo: %x\n",
		    ddi_get32(acc_hdl, &lct_entp->SubClassInfo));
		cmn_err(CE_CONT, "!\tParentTID: %x\n",
		    get_lct_entry_ParentTID(lct_entp, acc_hdl));
		cmn_err(CE_CONT, "!\tUserTID: %x\n",
		    get_lct_entry_UserTID(lct_entp, acc_hdl));
		cmn_err(CE_CONT, "!\tEventCapabilities: %x\n",
		    ddi_get32(acc_hdl, &lct_entp->EventCapabilities));
#endif
		break;

	case I2O_EVENT_IND_NEW_LCT_ENTRY:
		cmn_err(CE_CONT,
			"^Received NEW_LCT_ENTRY event from the IOP %x",
			iop->iop_id);
		lct_entp = (i2o_lct_entry_t *)msgp->EventData;
		cmn_err(CE_CONT, "^\tLocalTID: %x\n",
		    get_lct_entry_LocalTID(lct_entp, acc_hdl));
		cmn_err(CE_CONT, "^\tDeviceFlags: %x\n",
		    ddi_get32(acc_hdl, &lct_entp->DeviceFlags));
		cmn_err(CE_CONT, "^\tChangeIndicator: %x\n",
		    ddi_get32(acc_hdl, &lct_entp->ChangeIndicator));
		cmn_err(CE_CONT, "^\tClass: %x\n",
		    get_lct_entry_Class(lct_entp, acc_hdl));
		cmn_err(CE_CONT, "^\tSubClassInfo: %x\n",
		    ddi_get32(acc_hdl, &lct_entp->SubClassInfo));
		cmn_err(CE_CONT, "^\tParentTID: %x\n",
		    get_lct_entry_ParentTID(lct_entp, acc_hdl));
		cmn_err(CE_CONT, "^\tUserTID: %x\n",
		    get_lct_entry_UserTID(lct_entp, acc_hdl));
		cmn_err(CE_CONT, "^\tEventCapabilities: %x\n",
		    ddi_get32(acc_hdl, &lct_entp->EventCapabilities));
		break;

	case I2O_EVENT_IND_POWER_FAIL:
		cmn_err(CE_CONT, "^Received POWER_FAIL event from the IOP %x",
			iop->iop_id);
		break;

	case I2O_EVENT_IND_RESOURCE_LIMIT:
		cmn_err(CE_CONT,
			"^Received RESOURCE_LIMITS event from the IOP %x",
			iop->iop_id);
		event_data = ddi_get32(acc_hdl, msgp->EventData);
		cmn_err(CE_CONT, "^\tError Code %x", event_data);
		break;

	case I2O_EVENT_IND_XCT_CHANGE:
		cmn_err(CE_CONT, "^Received XCT_CHANGE event from the IOP %x",
			iop->iop_id);
		break;

	case I2O_EVENT_IND_RESET_IMMINENT:
		cmn_err(CE_CONT,
			"^Received RESET_IMMINENT event from the IOP %x",
			iop->iop_id);
		break;

	case I2O_EVENT_IND_RESET_PENDING:
		cmn_err(CE_CONT,
			"^Received RESET_PENDING event from the IOP %x",
			iop->iop_id);
		break;

	case I2O_EVENT_IND_CONFIGURATION_FLAG:
		cmn_err(CE_CONT,
			"^Received CONFIGURATION_FLAG event from the IOP %x",
			iop->iop_id);
		break;
	}
}

/*
 * Common reply message processing function: It simply copies the status
 * code and sets the done_flag in the tcontext structure.
 */
static void
i2o_msg_common_reply(void *p, ddi_acc_handle_t acc_hdl)
{
	tcontext_t *tp;

	tp = (tcontext_t *)(uintptr_t)ddi_get32(acc_hdl,
		&((i2o_single_reply_message_frame_t *)p)->TransactionContext);

	mutex_enter(&tp->cv_mutex);
	tp->status = (int)((i2o_single_reply_message_frame_t *)p)->ReqStatus;
	tp->done_flag = 1;
	cv_broadcast(&tp->cv);
	mutex_exit(&tp->cv_mutex);
}

/*
 * ************************************************************************
 * *** Implementation of OSM interfaces (PSARC: 1997/173)               ***
 * ************************************************************************
 */

/*
 * Register the OSM for the specified I2O device.
 *
 * Implementation: The simplest implementation is to use the TID of
 * the I2O device as the key to avoid multiple registrations. Since
 * the max number of TIDs allocated is not big (< 32) we can simply
 * maintain an array and use TID as the index. From the dip we need
 * to find the IOP that this device belongs to. Currently, we do
 * this by looking into the ioplist that matches with the devinfo
 * node pointer of the parent for this device.
 */
int
i2o_msg_osm_register(dev_info_t *dip, i2o_iop_handle_t *handlep)
{
	uint_t			tid;
	dev_info_t		*pdip;
	iop_instance_t		*iop;
	i2o_iop_impl_hdl_t	*hdl;

	/* get the TID for this device */
	tid = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS, "i2o-device-id", -1);
	if (tid == (uint_t)-1)
		return (DDI_FAILURE);

	/*
	 * Find the IOP that matches the parent of this device.
	 */
	pdip = ddi_get_parent(dip);
	mutex_enter(&i2o_mutex);
	for (iop = ioplist; iop; iop = iop->next) {
		if (iop->dip == pdip)
			break;
	}
	mutex_exit(&i2o_mutex);

	if (iop == NULL)
		return (DDI_FAILURE);

	mutex_enter(&iop->osm_registry.osm_mutex);

	ASSERT(tid <= iop->osm_registry.max_tid);

	hdl = &iop->osm_registry.iop_handle_tab[tid];

	/* verify that the device is not already registerd. */
	if (hdl->dip != NULL) {
		mutex_exit(&iop->osm_registry.osm_mutex);
		return (DDI_FAILURE);
	}

	hdl->dip = dip;
	hdl->iop = iop;
	hdl->tid = tid;

	mutex_exit(&iop->osm_registry.osm_mutex);

	*handlep = (i2o_iop_handle_t *)hdl;

	return (DDI_SUCCESS);
}

void
i2o_msg_osm_unregister(i2o_iop_handle_t *handlep)
{
	iop_instance_t	*iop;
	i2o_iop_impl_hdl_t *hdl = *(i2o_iop_impl_hdl_t **)handlep;

	iop = hdl->iop;

	ASSERT(hdl->tid <= iop->osm_registry.max_tid);

	mutex_enter(&iop->osm_registry.osm_mutex);

	hdl->dip = NULL;
	hdl->iop = NULL;
	hdl->tid = NULL;

	mutex_exit(&iop->osm_registry.osm_mutex);

	*handlep = NULL;
}

/*
 * Allocate a message frame for sending an I2O request message.
 *
 * Description: We allocate a system memory buffer so that the caller
 * can take his own time to prepare the message. When the caller
 * calls i2o_msg_send() then we allocate the real message frame
 * from the inbound queue and free up the system memory buffer
 * after copying the data.
 */
int
i2o_msg_alloc(i2o_iop_handle_t iop_hdl, int (*waitfp)(caddr_t),
	caddr_t arg, void **msgp, i2o_msg_handle_t *msg_handlep,
	ddi_acc_handle_t *acc_handlep)
{
	iop_instance_t *iop = ((i2o_iop_impl_hdl_t *)iop_hdl)->iop;
	i2o_msg_impl_hdl_t *hdl;
	ddi_acc_handle_t acc_hdl;
	ddi_dma_handle_t dma_handle;
	caddr_t buf;
	size_t real_length;
	size_t size;

	/*
	 * Allocate the message frame buffer from the system memory.
	 *
	 * Note:
	 * For now, the allocation is done by directly calling
	 * the DDI framework. Later this should be fixed to allocate
	 * it from a local pool for performance reasons.
	 */

	if (ddi_dma_alloc_handle(iop->dip, &dma_attr_contig, waitfp,
		    arg, &dma_handle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/* size of the buffer includes the i2o_msg_impl_hdl_t structure */
	size = iop->ib_msg_frame_size + sizeof (i2o_msg_impl_hdl_t);

	if (ddi_dma_mem_alloc(dma_handle, size, &i2o_dev_acc_attr,
	    DDI_DMA_CONSISTENT, waitfp, arg, &buf,
	    &real_length, &acc_hdl) != DDI_SUCCESS) {

		ddi_dma_free_handle(&dma_handle);
		return (DDI_FAILURE);
	}

	hdl = (i2o_msg_impl_hdl_t *)buf;
	hdl->dma_handle = dma_handle;
	hdl->acc_hdl = acc_hdl;
	hdl->msgp = (void *)(buf + sizeof (i2o_msg_impl_hdl_t));

	/* set the message size field in the message header */
	ddi_put16(hdl->acc_hdl,
		&((i2o_message_frame_t *)(hdl->msgp))->MessageSize,
		iop->ib_msg_frame_size >> 2);

	*msg_handlep = (i2o_msg_handle_t *)hdl;
	*acc_handlep = acc_hdl;
	*msgp = hdl->msgp;

	return (DDI_SUCCESS);
}


/*
 * Send the I2O message to the IOP.
 *
 * Description: We need to do the following.
 *	1. If the inbound message queue freelist is empty (i.e no
 *	   valid mfa available) then queue up this request for
 *	   the i2o_msg_send_process() thread and return DDI_SUCCESS.
 *	2. We have a valid mfa. Copy the data from the system memory
 *	   message buffer into the real message frame and send the
 *	   message.
 *	3. Free up the system memory message buffer.
 *
 * Note:
 * For now, we return the system memory buffer back to the DDI
 * framework. Fix this later to put the buffer into the local pool
 * for better performance.
 */
int
i2o_msg_send(i2o_iop_handle_t iop_hdl, void *msg, i2o_msg_handle_t msg_hdl)
{
	uint32_t mfa;
	iop_instance_t *iop = ((i2o_iop_impl_hdl_t *)iop_hdl)->iop;
	i2o_msg_impl_hdl_t *hdl = (i2o_msg_impl_hdl_t *)msg_hdl;
	i2o_message_frame_t *real_msgp;
	size_t msg_size;
	ddi_acc_handle_t acc_hdl;
	ddi_dma_handle_t dma_handle;

	ASSERT(hdl->msgp == msg);

	mutex_enter(&iop->iop_ib_mutex);

	/* get a valid mfa from the inbound message freelist FIFO */

	mfa = (* iop->nexus_trans->i2o_trans_msg_alloc)
		(iop->nexus_trans->nexus_handle);

	if (mfa == (uint_t)0xFFFFFFFF) {
		/*
		 * No valid MFA available. Queue up the request.
		 */
		if (iop->send_queue_head == NULL) {
			iop->send_queue_head = iop->send_queue_tail = hdl;
			hdl->next = NULL;
		} else {
			hdl->next = NULL;
			iop->send_queue_tail->next = hdl;
			iop->send_queue_tail = hdl;
		}

		if (iop->iop_flags & IOP_SEND_QUEUE_PROC_RUNNING)
			/* wakeup the i2o_msg_send_proc() */
			cv_broadcast(&iop->send_queue_cv);
		else {
			/*
			 * Create the i2o_msg_send_proc() thread and
			 * run it.
			 */
			cv_init(&iop->send_queue_cv, NULL, CV_DEFAULT, NULL);
			(void) thread_create(NULL, 0, i2o_msg_send_proc,
			    iop, 0, &p0, TS_RUN, minclsyspri);
			iop->iop_flags |= IOP_SEND_QUEUE_PROC_RUNNING;
		}

		iop->send_queue_count++;

		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT, "i2o_msg_send: req queued"));

		mutex_exit(&iop->iop_ib_mutex);

		return (DDI_SUCCESS);
	}

	mutex_exit(&iop->iop_ib_mutex);

	real_msgp = (i2o_message_frame_t *)
				(mfa + iop->nexus_trans->iop_base_addr);

	/*
	 * Copy the message to the real message frame.
	 */
	msg_size = ddi_get16(hdl->acc_hdl,
			&((i2o_message_frame_t *)msg)->MessageSize) << 2;
	ASSERT(msg_size <= iop->ib_msg_frame_size);
	bcopy(msg, (void *)real_msgp, msg_size);

	/* send the message to the IOP */
	(void) (* iop->nexus_trans->i2o_trans_msg_send)
		(iop->nexus_trans->nexus_handle,
		(caddr_t)(real_msgp) - iop->nexus_trans->iop_base_addr);

	/*
	 * Now, free up the system resources allocated for this message
	 */
	acc_hdl = hdl->acc_hdl;
	dma_handle = hdl->dma_handle;
	ddi_dma_mem_free(&acc_hdl);
	ddi_dma_free_handle(&dma_handle);

	return (DDI_SUCCESS);
}

/*
 * Copy the LCT contents to the specified buffer.
 */
int
i2o_msg_get_lct(i2o_iop_handle_t iop_hdl, void *buf, size_t buf_size,
	size_t *lct_sizep, size_t *real_sizep)
{
	iop_instance_t *iop = ((i2o_iop_impl_hdl_t *)iop_hdl)->iop;
	size_t copy_size;

	mutex_enter(&iop->lct.lct_mutex);

	if (lct_sizep != NULL)
		*lct_sizep = iop->lct.size;

	if (buf == NULL)
		copy_size = 0;
	else {
		copy_size = min(buf_size, iop->lct.size);
		bcopy((void *)iop->lct.bufp, buf, copy_size);
	}

	if (real_sizep)
		*real_sizep = copy_size;

	mutex_exit(&iop->lct.lct_mutex);

	return (DDI_SUCCESS);
}

/*
 * Process the reply message queue. This routine is called at the time of
 * IOP hw interrupt. Current implementation is a simple while loop which
 * reads the outbound postlist FIFO and if the MFA is a valid MFA
 * (i.e MFA != 0xFFFFFFFF) then it calls the callback function in the
 * InitiatorContext field of the message.
 */
void
i2o_msg_process_reply_queue(i2o_iop_handle_t handle)
{
	uint32_t	mfa;
	iop_instance_t	*iop = ((i2o_iop_impl_hdl_t *)handle)->iop;
	void (* initiator_context)();
	i2o_single_reply_message_frame_t *rmp;

	mutex_enter(&iop->iop_ob_mutex);

	mfa = (* iop->nexus_trans->i2o_trans_msg_recv)
			(iop->nexus_trans->nexus_handle);

	/*
	 * WORKAROUND for i960 chip bug. It seems that sometimes the i960
	 * is dropping the write request when IxWorks writes the MFA to
	 * the FIFO before generating the interrupt. As a workaround, IxWorks
	 * writes 0xFFFFFFFF first and then correct MFA. Two successive
	 * reads to the postlist FIFO should confirm if the FIFO is
	 * really empty. In the absence of reading the FIFO second time
	 * results in another call to IOP interrupt service routine.
	 * For better performance we do the second read of FIFO here.
	 */
	if (mfa == (uint_t)0xFFFFFFFF) {
		/* read the FIFO again */
		mfa = (* iop->nexus_trans->i2o_trans_msg_recv)
			(iop->nexus_trans->nexus_handle);
	}

	while (mfa != (uint_t)0xFFFFFFFF) {

		rmp = (i2o_single_reply_message_frame_t *)
			((mfa - iop->ob_msg_queue.base_paddr) +
			iop->ob_msg_queue.base_addr);

		initiator_context = (void (*)())
			(uintptr_t)ddi_get32(iop->ob_msg_queue.acc_hdl,
			(uint32_t *)&rmp->StdMessageFrame.InitiatorContext);

		/*
		 * Check for NULL Initiator Context field. If it is NULL
		 * (should not happen) then ignore the message.
		 */
		if (initiator_context == NULL) {
			cmn_err(CE_WARN, "I2O: No Initiator Context in the MSG"
			    " (Function: 0x%x Transaction Context: 0x%x"
			    " TID: 0x%x) - reply msg ignored",
			    get_msg_Function((i2o_message_frame_t *)rmp,
				iop->ob_msg_queue.acc_hdl),
			    ddi_get32(iop->ob_msg_queue.acc_hdl,
				(uint32_t *)&rmp->TransactionContext),
			    get_msg_TargetAddress((i2o_message_frame_t *)rmp,
				iop->ob_msg_queue.acc_hdl));
		} else {

			/*
			 * We need to do the DMA sync for the message frame
			 * because the reply message buffers are allocated
			 * from the system memory and the IOP does DMA to
			 * write to this memory.
			 */
			(void) ddi_dma_sync(iop->ob_msg_queue.dma_handle,
				(off_t)(mfa - iop->ob_msg_queue.base_paddr),
				(size_t)iop->ob_msg_queue.framesize,
				DDI_DMA_SYNC_FORCPU);

			/*
			 * Call the callback function of the OSM to process
			 * the message.
			 */
			(* initiator_context)((void *)rmp,
						iop->ob_msg_queue.acc_hdl);

		}

		/* Now, putback the MFA into the outbound freelist FIFO */
		(* iop->nexus_trans->i2o_trans_msg_freebuf)
			(iop->nexus_trans->nexus_handle, mfa);

		/* get the next MFA from the FIFO */
		mfa = (* iop->nexus_trans->i2o_trans_msg_recv)
			(iop->nexus_trans->nexus_handle);
	}

	mutex_exit(&iop->iop_ob_mutex);
}

/*
 * Process the I2O request message queue. The request messages are
 * queued up for this IOP because there was no free mfa available
 * from the inbound freelist. Currently, there is no mechanism
 * where IOP can inform the host when the freelist is not empty.
 * So, we just have to poll on the inbound message queue fifo until
 * we find a valid frame. But, starvation on the inbound MFAs should
 * not happen with the current implementations of IRTOS where the
 * IRTOS copies the message into local buffer and puts the MFA back
 * on the freelist immediately. So, this code may never get executed
 * in practice!
 *
 */
static void
i2o_msg_send_proc(iop_instance_t *iop)
{
	uint32_t mfa;
	i2o_message_frame_t *real_msgp;
	size_t msg_size;
	ddi_acc_handle_t acc_hdl;
	ddi_dma_handle_t dma_handle;
	i2o_msg_impl_hdl_t *q;

	mutex_enter(&iop->iop_ib_mutex);

	for (;;) {

		q = iop->send_queue_head; /* head of the queue */

		DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT, "i2o_msg_send_proc: called"));

		while (q != NULL) {

			ASSERT((iop->iop_flags & IOP_IS_IN_UNINIT) != 0);

			/*
			 * get a valid mfa from the inbound message
			 * freelist FIFO
			 */

			mfa = (* iop->nexus_trans->i2o_trans_msg_alloc)
				(iop->nexus_trans->nexus_handle);

			if (mfa == (uint_t)0xFFFFFFFF) {
				/*
				 * No valid MFA available. Wait for a while
				 * and try again.
				 */
				delay(1);
				continue; /* try again */
			}

			real_msgp = (i2o_message_frame_t *)
				(mfa + iop->nexus_trans->iop_base_addr);

			/* Copy the message to the real message frame */
			msg_size = 4 * ddi_get16(q->acc_hdl,
			    &((i2o_message_frame_t *)(q->msgp))->MessageSize);
			ASSERT(msg_size <= iop->ib_msg_frame_size);
			bcopy(q->msgp, (void *)real_msgp, msg_size);


			/* send the message to the IOP */
			(void) (* iop->nexus_trans->i2o_trans_msg_send)
			    (iop->nexus_trans->nexus_handle,
			    (caddr_t)(real_msgp) -
			    iop->nexus_trans->iop_base_addr);

			/* free up the associated system resources */
			acc_hdl = q->acc_hdl;
			dma_handle = q->dma_handle;
			q = q->next;
			ddi_dma_mem_free(&acc_hdl);
			ddi_dma_free_handle(&dma_handle);
		}

		iop->send_queue_head = NULL;
		iop->send_queue_tail = NULL;

		/* if the IOP is being uninitialized then exit */

		if (iop->iop_flags & IOP_IS_IN_UNINIT) {
			iop->iop_flags &= ~IOP_SEND_QUEUE_PROC_RUNNING;

			thread_exit();

			DEBUGF(I2O_DEBUG_DEBUG, (CE_CONT,
				"i2o_msg_send_proc: exit..."));
		}

		/* otherwise, wait for the wakeup call from i2o_msg_send() */
		cv_wait(&iop->send_queue_cv, &iop->iop_ib_mutex);
	}
}

/*
 * ************************************************************************
 * *** Functions used for Debugging only				***
 * ************************************************************************
 */

#ifdef I2O_DEBUG

static void
dump_iop_status_buf(iop_instance_t *iop)
{
	int i;
	uint32_t *p = (uint32_t *)iop->status.bufp;

	cmn_err(CE_CONT, "?IOP Status Block: ");
	for (i = 0; i < sizeof (i2o_exec_status_get_reply_t); i += 4)
		cmn_err(CE_CONT, "0x%x", *p++);
	cmn_err(CE_CONT,
		"?\tOrganizationID: %x\n", ddi_get16(iop->status.acc_hdl,
		&iop->status.bufp->OrganizationID));
	cmn_err(CE_CONT, "?\tIOP_ID: %x\n",
		get_i2o_exec_status_reply_IOP_ID(iop->status.bufp,
		iop->status.acc_hdl));
	cmn_err(CE_CONT, "?\tHostUnitID: %x\n", ddi_get16(iop->status.acc_hdl,
		&iop->status.bufp->HostUnitID));
	cmn_err(CE_CONT, "?\tI2oVersion: %x\n",
		get_i2o_exec_status_reply_I2oVersion(iop->status.bufp,
		iop->status.acc_hdl));
	cmn_err(CE_CONT, "?\tSegmentNumber: %x\n",
		get_i2o_exec_status_reply_SegmentNumber(iop->status.bufp,
		iop->status.acc_hdl));
	cmn_err(CE_CONT, "?\tIopState: %x\n", ddi_get8(iop->status.acc_hdl,
		&iop->status.bufp->IopState));
	cmn_err(CE_CONT, "?\tMessengerType: %x\n", ddi_get8(iop->status.acc_hdl,
		&iop->status.bufp->MessengerType));
	cmn_err(CE_CONT,
		"?\tInboundMFrameSize: %x\n", ddi_get16(iop->status.acc_hdl,
		&iop->status.bufp->InboundMFrameSize));
	cmn_err(CE_CONT, "?\tInitCode: %x\n", ddi_get8(iop->status.acc_hdl,
		&iop->status.bufp->InitCode));
	cmn_err(CE_CONT,
		"?\tMaxInboundMFrames: %x\n", ddi_get32(iop->status.acc_hdl,
		&iop->status.bufp->MaxInboundMFrames));
	cmn_err(CE_CONT,
		"?\tCurrentInboundMFrames: %x\n", ddi_get32(iop->status.acc_hdl,
		&iop->status.bufp->CurrentInboundMFrames));
	cmn_err(CE_CONT,
		"?\tMaxOutboundMFrames: %x\n", ddi_get32(iop->status.acc_hdl,
		&iop->status.bufp->MaxOutboundMFrames));
	cmn_err(CE_CONT,
		"?\tProductIDString: %s\n", iop->status.bufp->ProductIDString);
	cmn_err(CE_CONT,
		"?\tExpectedLCTSize: %x\n", ddi_get32(iop->status.acc_hdl,
		&iop->status.bufp->ExpectedLCTSize));
	cmn_err(CE_CONT,
		"?\tIopCapabilities: %x\n", ddi_get32(iop->status.acc_hdl,
		&iop->status.bufp->IopCapabilities));
	cmn_err(CE_CONT,
		"?\tDesiredPrivateMemSize: %x\n", ddi_get32(iop->status.acc_hdl,
		&iop->status.bufp->DesiredPrivateMemSize));
	cmn_err(CE_CONT,
		"?\tCurrentPrivateMemSize: %x\n", ddi_get32(iop->status.acc_hdl,
		&iop->status.bufp->CurrentPrivateMemSize));
	cmn_err(CE_CONT,
		"?\tCurrentPrivateMemBase: %x\n", ddi_get32(iop->status.acc_hdl,
		&iop->status.bufp->CurrentPrivateMemBase));
	cmn_err(CE_CONT,
		"?\tDesiredPrivateIOSize: %x\n", ddi_get32(iop->status.acc_hdl,
		&iop->status.bufp->DesiredPrivateIOSize));
	cmn_err(CE_CONT,
		"?\tCurrentPrivateIOSize: %x\n", ddi_get32(iop->status.acc_hdl,
		&iop->status.bufp->CurrentPrivateIOSize));
	cmn_err(CE_CONT,
		"?\tCurrentPrivateIOBase: %x\n", ddi_get32(iop->status.acc_hdl,
		&iop->status.bufp->CurrentPrivateIOBase));
}

static void
dump_hrt(iop_instance_t *iop)
{
	int i, n;
	i2o_hrt_entry_t *entp;
	uint32_t *p;

	n = ddi_get16(iop->hrt.acc_hdl, &iop->hrt.bufp->NumberEntries);

	entp = &iop->hrt.bufp->HRTEntry[0];

	cmn_err(CE_CONT,
		"?Hardware Resource Table (IOP_ID %x HRTVersion %x #ent %x):\n",
		iop->iop_id, iop->hrt.bufp->HRTVersion, n);

	for (i = 0; i < n; i++, entp++) {

		p = (uint32_t *)entp;

		if (get_hrt_entry_AdapterState(entp, iop->hrt.acc_hdl) == 0)
			continue;

		cmn_err(CE_CONT, "0x%x 0x%x 0x%x 0x%x", p[0], p[1],
			p[2], p[3]);
		cmn_err(CE_CONT,
		"?\tAdapterID: %x\n", ddi_get32(iop->hrt.acc_hdl,
			&entp->AdapterID));
		cmn_err(CE_CONT, "?\tControllingTID: %x\n",
		    get_hrt_entry_ControllingTID(entp, iop->hrt.acc_hdl));
		cmn_err(CE_CONT, "?\tAdapterState: %x\n",
		    get_hrt_entry_AdapterState(entp, iop->hrt.acc_hdl));
		cmn_err(CE_CONT, "?\tBusType: %x\n", entp->BusType);
		cmn_err(CE_CONT, "?\tBusNumber: %x\n", entp->BusNumber);

		switch (entp->BusType) {
		case I2O_PCI_BUS:
		    cmn_err(CE_CONT, "?\t\tPciFunctionNumber: %x",
			entp->uBus.PCIBus.PciFunctionNumber);
		    cmn_err(CE_CONT, "?\t\tPciDeviceNumber: %x",
			entp->uBus.PCIBus.PciDeviceNumber);
		    cmn_err(CE_CONT, "?\t\tPciBusNumber: %x",
			entp->uBus.PCIBus.PciBusNumber);
		    cmn_err(CE_CONT, "?\t\tPciVendorID: %x",
			entp->uBus.PCIBus.PciVendorID);
		    cmn_err(CE_CONT, "?\t\tPciDeviceID: %x",
			entp->uBus.PCIBus.PciDeviceID);
			break;
		default:
			break;
		}
	}
}


static void
dump_lct(iop_instance_t *iop)
{
	int i, j, n;
	i2o_lct_entry_t *entp;

	n = (ddi_get16(iop->lct.acc_hdl, &iop->lct.bufp->TableSize) * 4) /
		sizeof (i2o_lct_entry_t);
	entp = &iop->lct.bufp->LCTEntry[0];

	cmn_err(CE_CONT, "?Logical Config Table (IopFlags %x LctVer %x)\n",
		ddi_get32(iop->lct.acc_hdl, &iop->lct.bufp->IopFlags),
		get_lct_LctVer(iop->lct.bufp, iop->lct.acc_hdl));

	for (i = 0; i < n; i++) {
		cmn_err(CE_CONT, "?\tLocalTID: %x\n",
		    get_lct_entry_LocalTID(entp, iop->lct.acc_hdl));
		cmn_err(CE_CONT, "?\tDeviceFlags: %x\n",
		    ddi_get32(iop->lct.acc_hdl, &entp->DeviceFlags));
		cmn_err(CE_CONT, "?\tChangeIndicator: %x\n",
		    ddi_get32(iop->lct.acc_hdl, &entp->ChangeIndicator));
		cmn_err(CE_CONT, "?\tClass: %x\n",
		    get_lct_entry_Class(entp, iop->lct.acc_hdl));
		cmn_err(CE_CONT, "?\tVersion: %x\n",
		    get_lct_entry_Version(entp, iop->lct.acc_hdl));
		cmn_err(CE_CONT, "?\tOrganizationID: %x\n",
		    get_lct_entry_OrganizationID(entp, iop->lct.acc_hdl));
		cmn_err(CE_CONT, "?\tSubClassInfo: %x\n",
		    ddi_get32(iop->lct.acc_hdl, &entp->SubClassInfo));
		cmn_err(CE_CONT, "?\tBiosInfo: %x\n",
		    get_lct_entry_BiosInfo(entp, iop->lct.acc_hdl));
		cmn_err(CE_CONT, "?\tParentTID: %x\n",
		    get_lct_entry_ParentTID(entp, iop->lct.acc_hdl));
		cmn_err(CE_CONT, "?\tUserTID: %x\n",
		    get_lct_entry_UserTID(entp, iop->lct.acc_hdl));
		cmn_err(CE_CONT, "?\tEventCapabilities: %x\n",
		    ddi_get32(iop->lct.acc_hdl, &entp->EventCapabilities));
		cmn_err(CE_CONT, "?\tIdentityTag: ");
		for (j = 0; j < 8; j++)
			cmn_err(CE_CONT, "?\t%x ", entp->IdentityTag[j]);
		cmn_err(CE_CONT, "?\n");

		entp++;
	}
}


static void
dump_message(uint32_t *mp, char *name)
{
	cmn_err(CE_CONT, "%s: MSGHDR(%p): %x %x %x %x", name, (void *)mp, mp[0],
		mp[1], mp[2], mp[3]);
	cmn_err(CE_CONT, "PAYLOAD(%p): %x %x %x %x %x %x",
		(void *)&mp[4], mp[4], mp[5], mp[6], mp[7], mp[8], mp[9]);
}

static void
dump_reply_message(iop_instance_t *iop, i2o_single_reply_message_frame_t *rmp)
{
	if (rmp == NULL)
		return;

	cmn_err(CE_CONT,
	    "?Reply Message Frame (IOP %x Function %x):", iop->iop_id,
	    get_msg_Function(&rmp->StdMessageFrame, iop->ob_msg_queue.acc_hdl));
	cmn_err(CE_CONT,
		"?\tReqStatus: %x DetailedStatusCode %x\n", rmp->ReqStatus,
		ddi_get16(iop->ob_msg_queue.acc_hdl, &rmp->DetailedStatusCode));
}

#endif



static uint_t
i2o_get_mem(dev_info_t *dip, uint_t len, uint_t *base)
{
	ndi_ra_request_t req;
	uint64_t retlen;
	uint64_t retbase;
#ifdef lint
	dip = dip;
#endif

	bzero((caddr_t)&req, sizeof (req));

	req.ra_addr = (uint64_t)*base;
	if (*base != 0)
		req.ra_flags |= NDI_RA_ALLOC_SPECIFIED;
	req.ra_len = (uint64_t)len;
	req.ra_boundbase = 0;
	req.ra_boundlen = 0xffffffffUL;
	req.ra_flags |= NDI_RA_ALLOC_BOUNDED;

	if (ndi_ra_alloc(ddi_root_node(), &req, &retbase, &retlen,
					NDI_RA_TYPE_MEM, 0) == NDI_FAILURE) {
		*base = 0;
		return (0);
	} else {
		*base = retbase;
		return (*base);
	}
}


static void
i2o_return_mem(dev_info_t *dip, uint_t base, uint_t len)
{
#ifdef lint
	dip = dip;
#endif
	(void) ndi_ra_free(ddi_root_node(), (uint64_t)base, (uint64_t)len,
			NDI_RA_TYPE_MEM, 0);
}


static uint_t
i2o_get_io(dev_info_t *dip, uint_t len, uint_t *base)
{
	ndi_ra_request_t req;
	uint64_t retbase, retlen;

#ifdef lint
	dip = dip;
#endif
	bzero((caddr_t)&req, sizeof (req));
	if (*base != 0)
		req.ra_flags |= NDI_RA_ALLOC_SPECIFIED;
	req.ra_flags |= NDI_RA_ALIGN_SIZE;
	req.ra_addr = (uint64_t)*base;
	req.ra_boundbase = 0;
	req.ra_boundlen = 0xffffffffUL;
	req.ra_flags |= NDI_RA_ALLOC_BOUNDED;
	req.ra_len = (uint64_t)len;
	if (ndi_ra_alloc(ddi_root_node(), &req, &retbase, &retlen,
			    NDI_RA_TYPE_IO, 0) == NDI_FAILURE) {
		*base = 0;
		return (0);
	} else {
		*base = retbase;
		return (*base);
	}
}

static void
i2o_return_io(dev_info_t *dip, uint_t base, uint_t len)
{
#ifdef lint
	dip = dip;
#endif
	(void) ndi_ra_free(ddi_root_node(), (uint64_t)base, (uint64_t)len,
			NDI_RA_TYPE_IO, 0);
}
