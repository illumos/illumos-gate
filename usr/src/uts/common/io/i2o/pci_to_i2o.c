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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	PCI-to-I2O bus nexus driver.
 *
 *	The current implementation complies with the I2O Specification
 *	Version 1.5. So, it assumes only 32bit virtual addresses and
 *	32bit context fields in I2O messages.
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/ddidmareq.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/pci.h>
#include <sys/avintr.h>
#include <sys/bustypes.h>
#include <sys/kmem.h>
#include <sys/archsystm.h>
#include <sys/i2o/i2oexec.h>
#include "i2o_impl.h"

char _depends_on[] = "misc/i2o_msg";

/*
 * function prototypes for bus ops routines:
 */
static int
i2o_dma_allochdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_attr_t *attr,
    int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *handlep);

static int
i2o_bus_ctl(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t opt, void *a, void *v);

static int
i2o_intr_op(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t op,
    ddi_intr_handle_impl_t *hdlp, void *result);

struct bus_ops i2o_bus_ops = {
	BUSO_REV,
	nullbusmap,
	NULL,
	NULL,
	NULL,
	i_ddi_map_fault,
	ddi_no_dma_map,		/* 2.4 DDI only - not supported */
	i2o_dma_allochdl,
	ddi_dma_freehdl,
	ddi_dma_bindhdl,
	ddi_dma_unbindhdl,
	ddi_dma_flush,
	ddi_dma_win,
	ddi_dma_mctl,
	i2o_bus_ctl,
	ddi_bus_prop_op,
	NULL,			/* (* bus_get_eventcookie)() */
	NULL,			/* (* bus_add_eventcall)() */
	NULL,			/* (* bus_remove_eventcall)() */
	NULL,			/* (* bus_post_event)() */
	NULL,			/* interrupt control	*/
	0,			/* bus_config		*/
	0,			/* bus_unconfig		*/
	0,			/* bus_fm_init		*/
	0,			/* bus_fm_fini		*/
	0,			/* bus_fm_access_enter	*/
	0,			/* bus_fm_access_exit	*/
	0,			/* bus_power		*/
	i2o_intr_op		/* bus_intr_op		*/
};


/*
 * Function prototypes for dev_ops entry points.
 */

static int i2o_probe(dev_info_t *);
static int i2o_attach(dev_info_t *, ddi_attach_cmd_t);
static int i2o_detach(dev_info_t *, ddi_detach_cmd_t);

struct dev_ops i2o_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	ddi_no_info,		/* info */
	nulldev,		/* identify */
	i2o_probe,		/* probe */
	i2o_attach,		/* attach */
	i2o_detach,		/* detach */
	nodev,			/* reset */
	(struct cb_ops *)0,	/* driver operations */
	&i2o_bus_ops		/* bus operations */
};

/*
 * Per IOP instance data maintained by the i2o nexus driver.
 */

typedef struct iop_nexus_instance {
    dev_info_t		*dip;		/* devinfo pointer */
    caddr_t		iop_base_addr;	/* base address of shared memory */
    int			iop_state;	/* state of IOP */
    off_t		shared_memsize;	/* size of shared memory */
    int			iop_intr_pri;	/* interrupt priority */
    ddi_acc_handle_t 	acc_handle; 	/* DDI access handle for shared mem */
    i2o_iop_handle_t	i2o_iop_handle; /* IOP handle from the i2o_msg module */
    ddi_iblock_cookie_t	iblock_cookie;
    ddi_idevice_cookie_t idevice_cookie;
    i2o_msg_trans_t	i2o_msg_trans;
#ifdef I2O_DEBUG
    uint_t		intr_count;	/* IOP interrupt counter */
#endif
} iop_nexus_instance_t;


/* Function prototypes for local functions */

static uint_t i2o_intr(caddr_t);
static uint_t i2o_alloc_msg(i2o_nexus_handle_t handle);
static int i2o_send_msg(i2o_nexus_handle_t handle, uint_t mfa);
static uint_t i2o_recv_msg(i2o_nexus_handle_t handle);
static void i2o_disable_intr(i2o_nexus_handle_t handle);
static void i2o_enable_intr(i2o_nexus_handle_t handle);
static void i2o_free_msg(i2o_nexus_handle_t handle, uint_t mfa);
static void i2o_create_devinfo(iop_nexus_instance_t *iop);
#ifdef I2O_DEBUG
static void dump_exec_params_0001(iop_nexus_instance_t *iop);
void i2o_msg_reply(void *m, ddi_acc_handle_t acc_hdl);
#endif

/*
 * DMA attribute structure for I2O Spec version 1.5.
 */
static ddi_dma_attr_t i2o_dma_attr = {
	DMA_ATTR_VERSION,	/* version number */
	(uint64_t)0,		/* low DMA address range */
	(uint64_t)0xFFFFFFFF,	/* high DMA address range */
	(uint64_t)0x00FFFFFF,	/* DMA counter register */
	1,			/* DMA address alignment */
	1,			/* DMA burstsizes */
	1,			/* min effective DMA size */
	(uint64_t)0xFFFFFFFF,	/* max DMA xfer size */
	(uint64_t)0xFFFFFFFF,	/* segment boundary */
	0xFFFF,			/* s/g length */
	1,			/* granularity of device */
	0			/* Bus specific DMA flags */
};


/* local definitions for iop_state values */
#define	IOP_INIT	0	/* IOP is being initialized */
#define	IOP_ONLINE	1	/* IOP initialization is complete */


/* Default interrupt priority for IOP interrupt */
#define	IOP_INTR_PRI_DEFAULT	5


#ifdef	I2O_DEBUG
int i2o_nexus_debug = 0;
#define	DEBUGF(level, args) \
	{ if (i2o_nexus_debug >= (level)) cmn_err args; }
#else
#define	DEBUGF(level, args)	/* nothing */
#endif


/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,
	"Nexus for I2O Spec v1.5, driver %I%",
	&i2o_dev_ops,
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


static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

static void *i2o_nexus_state;

int
_init(void)
{
	int error;

	if ((error = ddi_soft_state_init(&i2o_nexus_state,
		sizeof (struct iop_nexus_instance), 1)) != 0)
		return (error);

	if ((error = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&i2o_nexus_state);

	return (error);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) == 0)
		ddi_soft_state_fini(&i2o_nexus_state);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * **********************************************************************
 * *			bus_ops entry points				*
 * **********************************************************************
 */


/*
 * NOTE: THIS FUNCTION IS NOT APPLICABLE FOR I2O. RETURN ERROR.
 */
/*ARGSUSED*/
static int
i2o_intr_op(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	return (DDI_FAILURE);
}

static int
i2o_dma_allochdl(dev_info_t *dip, dev_info_t *rdip, ddi_dma_attr_t *attr,
    int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *handlep)
{
	/*
	 * Adjust DMA attributes structure as per I2O Spec version 1.5.
	 */
	ddi_dma_attr_merge(attr, &i2o_dma_attr);

	return (ddi_dma_allochdl(dip, rdip, attr, waitfp, arg, handlep));
}

static int
i2o_bus_ctl(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t opt, void *a, void *v)
{
	char	name[16];
	uint_t	tid;
	int	error;

	switch (opt) {
	case DDI_CTLOPS_INITCHILD:
		tid = ddi_prop_get_int(DDI_DEV_T_ANY, (dev_info_t *)a,
			DDI_PROP_DONTPASS, "i2o-device-id", -1);
		if (tid == (uint_t)-1)
			return (DDI_FAILURE);
		(void) sprintf(name, "%x", tid);
		error = impl_ddi_sunbus_initchild((dev_info_t *)a);
		if (error != DDI_SUCCESS)
			return (DDI_FAILURE);
		ddi_set_name_addr((dev_info_t *)a, name);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_UNINITCHILD:
		impl_ddi_sunbus_removechild(a);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REPORTDEV:
	{
		cmn_err(CE_CONT, "?%s%d at %s%d: TID %s\n",
		    ddi_driver_name(rdip), ddi_get_instance(rdip),
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    ddi_get_name_addr(rdip));

		return (DDI_SUCCESS);
	}

	/*
	 * These functions shouldn't be called by the OSMs. Return error.
	 */
	case DDI_CTLOPS_DMAPMAPC:
	case DDI_CTLOPS_SIDDEV:
	case DDI_CTLOPS_SLAVEONLY:
	case DDI_CTLOPS_AFFINITY:
	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
	case DDI_CTLOPS_POKE:
	case DDI_CTLOPS_PEEK:
		return (DDI_FAILURE);

	default:
		/* let the parent handle the rest */
		return (ddi_ctlops(dip, rdip, opt, a, v));
	}
}

/*
 * **********************************************************************
 * *			dev_ops entry points				*
 * **********************************************************************
 */

/*
 * Determine if the IOP is present.
 */
static int
i2o_probe(dev_info_t *dip)
{
	ddi_acc_handle_t handle;
	uint8_t base_class, sub_class, prog_class;

	if (pci_config_setup(dip, &handle) != DDI_SUCCESS)
		return (DDI_PROBE_FAILURE);

	base_class = pci_config_get8(handle, PCI_CONF_BASCLASS);
	sub_class = pci_config_get8(handle, PCI_CONF_SUBCLASS);
	prog_class = pci_config_get8(handle, PCI_CONF_PROGCLASS);

	pci_config_teardown(&handle);

	if ((base_class != PCI_I2O_BASE_CLASS) ||
	    (sub_class != PCI_I2O_SUB_CLASS) ||
	    (prog_class != PCI_I2O_PROG_CLASS1))

		return (DDI_PROBE_FAILURE);

	return (DDI_PROBE_SUCCESS);
}

/*
 * attach(9E)
 */

static int
i2o_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	iop_nexus_instance_t *iop = NULL;
	ddi_acc_handle_t handle;
	int nregs;
	int csr;
	uint32_t base_reg0;
	int instance;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (pci_config_setup(dip, &handle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * turn on Master Enable and Memory Access Enable bits.
	 */
	csr = pci_config_get32(handle, PCI_CONF_COMM);
	pci_config_put32(handle, PCI_CONF_COMM,
			csr | PCI_COMM_ME | PCI_COMM_MAE);

	base_reg0 = pci_config_get32(handle, PCI_CONF_BASE0);

	ASSERT((base_reg0 & PCI_BASE_SPACE_M) == 0);

	pci_config_teardown(&handle);

	/*
	 * Allocate iop_nexus_instance soft state structure for this
	 * IOP instance.
	 */
	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(i2o_nexus_state, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);
	iop = (iop_nexus_instance_t *)ddi_get_soft_state(i2o_nexus_state,
								instance);

	iop->dip = dip;
	iop->iop_state = IOP_INIT;

	/*
	 * Map the device memory (i.e IOP's shared local memory).
	 *
	 * ISSUE: Mapping the whole shared memory (4 to 16M) may be too
	 * much. But, to map the pages that we really need it requires
	 * reading the inbound FIFO to find out the range of offsets used
	 * for allocating inbound message frames by the IOP. It is possible
	 * to find the range of MFAs and then map only those pages. But,
	 * this will bring up the following issues:
	 *
	 *	1. IOP reset may reallocate the message frames so the
	 *	   range may change. (Note: currently i2o_msg_iop_init()
	 *	   does IOP reset so it will be a problem.)
	 *	2. I2O Spec doesn't restrict the IOP allocating inbound
	 *	   message frames dynamically.
	 *	3. Reading the MFAs should be done when no other external
	 *	   agent (e.g other IOPs) is accessing the IOP.
	 *
	 * This issue is addressed by the I2O Spec version 2.0 where
	 * IOP gives additional parameters which gives us the information
	 * we need to map only the pages that have the MFAs. For now, we
	 * will map the whole thing.
	 */

	if ((ddi_dev_nregs(dip, &nregs) != DDI_SUCCESS) || (nregs < 2) ||
	    (ddi_dev_regsize(dip, 1, &iop->shared_memsize) != DDI_SUCCESS))
		goto cleanup;

	DEBUGF(1, (CE_CONT, "!i2o_attach: IOP shared memory size 0x%x",
		(int)iop->shared_memsize));

	if (ddi_regs_map_setup(dip, 1, &iop->iop_base_addr, 0,
	    iop->shared_memsize, &i2o_dev_acc_attr,
	    &iop->acc_handle) != DDI_SUCCESS) {
		DEBUGF(1, (CE_CONT, "i2o_attach: ddi_regs_map_setup failed"));
		goto cleanup;
	}

	/*
	 * Initialize i2o_msg_trans data structure for i2o_msg module.
	 */
	iop->i2o_msg_trans.version = I2O_MSG_TRANS_VER;
	iop->i2o_msg_trans.iop_base_addr = iop->iop_base_addr;
	iop->i2o_msg_trans.iop_inbound_fifo_paddr =
	    (base_reg0 & PCI_BASE_M_ADDR_M) + PCI_IOP_INBOUND_FREELIST_FIFO;
	iop->i2o_msg_trans.acc_handle = iop->acc_handle;
	iop->i2o_msg_trans.nexus_handle = (i2o_nexus_handle_t)iop;
	iop->i2o_msg_trans.iblock_cookie = iop->iblock_cookie;
	iop->i2o_msg_trans.i2o_trans_msg_alloc = i2o_alloc_msg;
	iop->i2o_msg_trans.i2o_trans_msg_send = i2o_send_msg;
	iop->i2o_msg_trans.i2o_trans_msg_recv = i2o_recv_msg;
	iop->i2o_msg_trans.i2o_trans_msg_freebuf = i2o_free_msg;
	iop->i2o_msg_trans.i2o_trans_disable_intr = i2o_disable_intr;
	iop->i2o_msg_trans.i2o_trans_enable_intr = i2o_enable_intr;

	/* Disable IOP interrupts */
	i2o_disable_intr((i2o_nexus_handle_t)iop);

	/*
	 * Register an interrupt handler for IOP interrupts. If the
	 * property 'iop_intr_pri' is set then use that otherwise
	 * set the priority to 5.
	 */
	iop->iop_intr_pri = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS, "iop_intr_pri", IOP_INTR_PRI_DEFAULT);

	if (ddi_add_intr(dip, 0, &iop->iblock_cookie, &iop->idevice_cookie,
	    i2o_intr, (caddr_t)iop) != DDI_SUCCESS)
		goto cleanup;

	/*
	 * Call i2o_msg_iop_init() to initialize the IOP.
	 */

	cmn_err(CE_CONT, "\rI2O Nexus: Initializing IO Processor %d...",
								instance);

	iop->i2o_iop_handle = i2o_msg_iop_init(dip, &iop->i2o_msg_trans);

	if (iop->i2o_iop_handle == NULL) { /* IOP Initialization failed */
		ddi_remove_intr(dip, 0, iop->iblock_cookie);
		cmn_err(CE_CONT, "FAILED.\n");
		goto cleanup;
	}

	cmn_err(CE_CONT, "done.\n");

	/* Enable IOP interrupts now */
	i2o_enable_intr((i2o_nexus_handle_t)iop);

	iop->iop_state = IOP_ONLINE;	/* now IOP is ready */

	ddi_report_dev(dip);

#ifdef I2O_DEBUG
	if (i2o_nexus_debug >= 2)
		dump_exec_params_0001(iop);
#endif

#ifndef I2O_BOOT_SUPPORT

	/*
	 * Create the devinfo nodes for the I2O devices.
	 */
	i2o_create_devinfo(iop);

#endif
	return (DDI_SUCCESS);

cleanup:
	/*
	 * free up the allocated resources and return error.
	 */

	if (iop->iop_base_addr != 0)
		ddi_regs_map_free(&iop->acc_handle);

	/* free up the soft state structure for this instance */
	ddi_soft_state_free(i2o_nexus_state, instance);

	return (DDI_FAILURE);
}

/*
 * detach(9E)
 */

static int
i2o_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	iop_nexus_instance_t *iop = NULL;
	int instance;

	instance = ddi_get_instance(dip);
	iop = (iop_nexus_instance_t *)ddi_get_soft_state(i2o_nexus_state,
								instance);

	if (iop == NULL)
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_DETACH:

		/* reset the IOP */
		if (i2o_msg_iop_uninit(iop->i2o_iop_handle) != DDI_SUCCESS)
			return (DDI_FAILURE);

		/* unregister the interrupt handler */
		ddi_remove_intr(dip, 0, iop->iblock_cookie);

		/* unmap the shared device memory */
		ddi_regs_map_free(&iop->acc_handle);

		/* free up the soft state structure for this instance */
		ddi_soft_state_free(i2o_nexus_state, instance);

		return (DDI_SUCCESS);

	case DDI_SUSPEND:	/* XXX FIX IT LATER */
	case DDI_PM_SUSPEND:	/* XXX FIX IT LATER */
		/* fall thru */

	default:
		return (DDI_FAILURE);
	}
}

/*
 * IOP interrupt handler.
 *
 * Note: In the current I2O Spec (version 1.5) only Outbound PostList
 *	 service interrupt is defined. So, this routine handles this
 *	 interrupt.
 *
 * This function simply calls i2o_msg_process_reply_queue() to process
 * the reply messages. It is assumed that the i2o_msg_process_reply_queue()
 * will putback the processed messages into the freelist.
 */

static uint_t
i2o_intr(caddr_t arg)
{
	register iop_nexus_instance_t	*iop;
	uint32_t intr_state;
	uint32_t intr_mask;

	iop = (iop_nexus_instance_t *)arg;

	if (iop->iop_state != IOP_ONLINE)
		return (DDI_INTR_UNCLAIMED);

	intr_state = ddi_get32(iop->acc_handle,
		(uint32_t *)(iop->iop_base_addr + PCI_IOP_INTR_STATUS_REG));

	intr_mask = ddi_get32(iop->acc_handle,
		(uint32_t *)(iop->iop_base_addr + PCI_IOP_INTR_MASK_REG));

	if (((intr_state & I2O_OUTBOUND_POSTLIST_SERVICE_INTR_MASK) == 0) ||
	    ((intr_mask & I2O_OUTBOUND_POSTLIST_SERVICE_INTR_MASK) != 0))
		/* No interrupt from this IOP */
		return (DDI_INTR_UNCLAIMED);

	/* Let the I2O Message module process the reply message queue */
	i2o_msg_process_reply_queue(iop->i2o_iop_handle);

#ifdef I2O_DEBUG
	iop->intr_count++; /* debugging */
#endif

	return (DDI_INTR_CLAIMED);
}

/*
 * ***********************************************************************
 * ** Transport functions to support the I2O Message module		**
 * ** 									**
 * ** NOTE: Locking for these functions are done within the I2O		**
 * ** Message module.							**
 * ***********************************************************************
 */

/*
 * Get an MFA from the Inbound FreeList FIFO.
 */
static uint_t
i2o_alloc_msg(i2o_nexus_handle_t handle)
{
	register iop_nexus_instance_t	*iop;

	iop = (iop_nexus_instance_t *)handle;

	return (ddi_get32(iop->acc_handle, (uint32_t *)(iop->iop_base_addr +
		PCI_IOP_INBOUND_FREELIST_FIFO)));
}

/*
 * Post the MFA to Inbound PostList FIFO.
 */
static int
i2o_send_msg(i2o_nexus_handle_t handle, uint_t mfa)
{
	register iop_nexus_instance_t	*iop;

	iop = (iop_nexus_instance_t *)handle;

	if (mfa < iop->shared_memsize) {
		ddi_put32(iop->acc_handle, (uint32_t *)(iop->iop_base_addr +
		    PCI_IOP_INBOUND_POSTLIST_FIFO), mfa);

		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);	/* invalid argument(s) */
}

/*
 * Get the reply MFA from the Outbound PostList FIFO.
 */
static uint_t
i2o_recv_msg(i2o_nexus_handle_t handle)
{
	register iop_nexus_instance_t	*iop;

	iop = (iop_nexus_instance_t *)handle;

	return (ddi_get32(iop->acc_handle, (uint32_t *)(iop->iop_base_addr +
				PCI_IOP_OUTBOUND_POSTLIST_FIFO)));
}

/*
 * Return reply MFA to the Outbound FreeList FIFO.
 */
static void
i2o_free_msg(i2o_nexus_handle_t handle, uint_t mfa)
{
	register iop_nexus_instance_t	*iop;

	iop = (iop_nexus_instance_t *)handle;

	ddi_put32(iop->acc_handle, (uint32_t *)(iop->iop_base_addr +
			PCI_IOP_OUTBOUND_FREELIST_FIFO), mfa);
}

/*
 * Disable IOP hardware interrupts. Currently only bit 3 in the Interrupt
 * Mask register is defined and it is for outbound postlist service
 * interrupt. (See section 4.2.1.5).
 */

static void
i2o_disable_intr(i2o_nexus_handle_t handle)
{
	register iop_nexus_instance_t	*iop;
	uint_t intr_mask;

	iop = (iop_nexus_instance_t *)handle;

	intr_mask = ddi_get32(iop->acc_handle,
		(uint32_t *)(iop->iop_base_addr + PCI_IOP_INTR_MASK_REG));

	ddi_put32(iop->acc_handle,
		(uint32_t *)(iop->iop_base_addr + PCI_IOP_INTR_MASK_REG),
		intr_mask | I2O_OUTBOUND_POSTLIST_SERVICE_INTR_MASK);
}

/*
 * Enable IOP hardware interrupts. Currently only bit 3 in the Interrupt
 * Mask register is defined and it is for outbound postlist service
 * interrupt. (See section 4.2.1.5).
 */

static void
i2o_enable_intr(i2o_nexus_handle_t handle)
{
	register iop_nexus_instance_t	*iop;
	uint_t intr_mask;

	iop = (iop_nexus_instance_t *)handle;

	intr_mask = ddi_get32(iop->acc_handle,
		(uint32_t *)(iop->iop_base_addr + PCI_IOP_INTR_MASK_REG));

	ddi_put32(iop->acc_handle, (uint32_t *)(iop->iop_base_addr +
		PCI_IOP_INTR_MASK_REG),
		intr_mask & ~I2O_OUTBOUND_POSTLIST_SERVICE_INTR_MASK);
}

#ifndef I2O_BOOT_SUPPORT

/*
 * Since we don't have boot support yet, we need to create the devinfo
 * nodes for the I2O devices here. No devinfo nodes are created for
 * SCSI Peripheral class devices. For adapter devices, if the adapter
 * is host visible (HRT has this information) then there may be a
 * devinfo node else where in the devinfo tree. For each host visible
 * adapter device we need to prune any other devinfo nodes for this
 * adapter in the system.
 */

static void
i2o_create_devinfo(iop_nexus_instance_t *iop)
{
	i2o_lct_t		*lct;
	ddi_acc_handle_t	acc_hdl;
	uint_t			nent;
	uint_t			local_tid;
	uint_t			user_tid;
	uint_t			class;
	uint_t			sub_class;
	dev_info_t		*cdip;
	char			*nodename, *compat_name, *dev_type;
	int			i;

	/*
	 * Step 1
	 *
	 * Get HRT and look for any adapters that are present, assigned to
	 * IOP but not hidden. For each of those adapters we need to
	 * remove any devinfo nodes that may be present else where in
	 * devinfo tree.
	 */

	/*
	 * For now, we assume that all adpaters that are controlled
	 * by the IOP are hidden from the host. This step can be
	 * implemented easily in the boot system (i.e devconf on x86)
	 * when that phase is implemented.
	 */

	/* XXX DEFER IT FOR NOW XXX */

	/*
	 * Step 2
	 *
	 * Create the devinfo nodes for each I2O class device that
	 * is not claimed (i.e UserTID == 0xFFF) and is not of
	 * SCSI peripheral type.
	 */

	i2o_msg_get_lct_info(iop->i2o_iop_handle, &lct, &acc_hdl);
	nent = ((ddi_get16(acc_hdl, &lct->TableSize) << 2) - sizeof (i2o_lct_t)
		+ sizeof (i2o_lct_entry_t)) / sizeof (i2o_lct_entry_t);

	for (i = 0; i < nent; i++) {

		/* If the device is already claimed then continue */
		user_tid = get_lct_entry_UserTID(&lct->LCTEntry[i], acc_hdl);
		if (user_tid != 0xFFF)
			continue;

		class = get_lct_entry_Class(&lct->LCTEntry[i], acc_hdl);
		sub_class = ddi_get32(acc_hdl, &lct->LCTEntry[i].SubClassInfo);

		switch (class) {
		case I2O_CLASS_EXECUTIVE:
		case I2O_CLASS_DDM:
			continue;

		case I2O_CLASS_ATE_PORT:
		case I2O_CLASS_ATE_PERIPHERAL:
		case I2O_CLASS_FLOPPY_CONTROLLER:
		case I2O_CLASS_FLOPPY_DEVICE:
		case I2O_CLASS_SEQUENTIAL_STORAGE:
		case I2O_CLASS_LAN:
		case I2O_CLASS_WAN:
		case I2O_CLASS_FIBRE_CHANNEL_PORT:
		case I2O_CLASS_FIBRE_CHANNEL_PERIPHERAL:
			/* For now, ingore these types */
			continue;

		case I2O_CLASS_SCSI_PERIPHERAL:
			continue;

		case I2O_CLASS_RANDOM_BLOCK_STORAGE:
			nodename = "disk";
			compat_name = "i2o_bs";
			dev_type = "block";
			break;
		case I2O_CLASS_BUS_ADAPTER_PORT:
			nodename = "adapter";
			compat_name = "i2o_scsi";
			/*
			 * sub_class should indicate the type of bus.
			 * XXX Check this with Symbios.
			 */
			if (sub_class == 0x3)
				dev_type = "scsi-3";
			else if (sub_class == 0x2)
				dev_type = "scsi-2";
			else
				dev_type = "scsi";
			break;
		default:
			continue;
		}

		local_tid = get_lct_entry_LocalTID(&lct->LCTEntry[i], acc_hdl);

		cdip = NULL;

		/* create the devinfo node */
		if (ndi_devi_alloc(iop->dip, nodename,
			(dnode_t)DEVI_SID_NODEID, &cdip) != NDI_SUCCESS) {
			cmn_err(CE_WARN,
				"i2o_create_devinfo: ndi_devi_alloc failed");
			goto fail;
		}

		/* create the properties */

		if (ndi_prop_update_int(DDI_DEV_T_NONE, cdip, "i2o-device-id",
			local_tid) != DDI_PROP_SUCCESS)
			goto fail;
		if (ndi_prop_update_string(DDI_DEV_T_NONE, cdip, "device-type",
			dev_type) != DDI_PROP_SUCCESS)
			goto fail;
		if (ndi_prop_update_string(DDI_DEV_T_NONE, cdip,
			"compatible", compat_name) != DDI_PROP_SUCCESS)
			goto fail;

		/* now, attach the driver */
		(void) ndi_devi_online(cdip, NDI_ONLINE_ATTACH);
	}

	return;

fail:
	if (cdip != NULL) {
		(void) ndi_prop_remove(DDI_DEV_T_NONE, cdip, "i2o-device-id");
		(void) ndi_prop_remove(DDI_DEV_T_NONE, cdip, "compatible");
		(void) ndi_prop_remove(DDI_DEV_T_NONE, cdip, "device-type");
		if (ndi_devi_free(cdip) != NDI_SUCCESS) {
		    cmn_err(CE_WARN,
			"i2o_create_devinfo: ndi_devi_free failed");
		}
	}
}

#endif

#ifdef I2O_DEBUG

static ddi_dma_attr_t i2o_dma_attr_contig = {
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

kmutex_t test_mutex;
kcondvar_t test_cv;
volatile int test_result;

static void
dump_exec_params_0001(iop_nexus_instance_t *iop)
{
	ddi_dma_handle_t dma_handle = NULL;
	ddi_acc_handle_t acc_hdl, acc_hdl2;
	size_t real_length;
	ddi_dma_cookie_t dma_cookie;
	uint_t ncookies;
	caddr_t buf = NULL;
	uint32_t ops_block_size, results_block_size;
	i2o_util_params_get_message_t		*msgp;
	i2o_sge_simple_element_t 		*sgl;
	/* operations block info */
	i2o_param_operations_list_header_t	*ops_block_head;
	i2o_param_operation_all_template_t 	*ops_block;
	/* scalar parameters */
	i2o_exec_iop_message_if_scalar_t	*message_if;
	i2o_msg_handle_t			msg_handle;

	/* allocate a DMA handle */
	if (ddi_dma_alloc_handle(iop->dip, &i2o_dma_attr_contig, DDI_DMA_SLEEP,
		    NULL, &dma_handle) != DDI_SUCCESS) {
		goto cleanup;
	}

	ops_block_size =  sizeof (*ops_block_head) + sizeof (*ops_block);

	results_block_size =
		sizeof (i2o_param_results_list_header_t) +
		sizeof (i2o_param_read_operation_result_t) +
		sizeof (*message_if) +
		sizeof (i2o_param_error_info_template_t);

	/* Allocate a buffer for operation block */
	if (ddi_dma_mem_alloc(dma_handle, ops_block_size + results_block_size,
		&i2o_dev_acc_attr, DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
		&buf, &real_length, &acc_hdl) != DDI_SUCCESS) {
		goto cleanup;
	}

	bzero((caddr_t)buf, real_length);

	if (ddi_dma_addr_bind_handle(dma_handle, NULL, buf,
	    real_length, DDI_DMA_READ | DDI_DMA_STREAMING, DDI_DMA_SLEEP,
	    NULL, &dma_cookie, &ncookies) != DDI_SUCCESS) {

		DEBUGF(1, (CE_CONT,
			"dump_exec_params_0001: cannot bind memory"));
		goto cleanup;
	}

	DEBUGF(1, (CE_CONT,
		"dump_exec_params_0001: dma_bind (vaddr %p paddr %x length %x)",
		(void *)buf, dma_cookie.dmac_address,
		(int)dma_cookie.dmac_size));

	ops_block_head = (i2o_param_operations_list_header_t *)buf;
	ops_block = (i2o_param_operation_all_template_t *)
		(buf + sizeof (*ops_block_head));

	/* initialize the operations block header */
	ddi_put16(acc_hdl, &ops_block_head->OperationCount, 1);

	/* initialize operations block for group 0001 */
	ddi_put16(acc_hdl, &ops_block[0].Operation,
		I2O_PARAMS_OPERATION_FIELD_GET);
	ddi_put16(acc_hdl, &ops_block[0].GroupNumber,
		I2O_EXEC_IOP_MESSAGE_IF_GROUP_NO);
	ddi_put16(acc_hdl, &ops_block[0].FieldCount, -1); /* all fields */

	/* allocate the message frame */
	if (i2o_msg_alloc(iop->i2o_iop_handle, I2O_MSG_SLEEP, NULL,
		(void **)&msgp, &msg_handle, &acc_hdl2) != DDI_SUCCESS) {
		DEBUGF(1, (CE_CONT,
			"dump_exec_params_0001: i2o_msg_alloc failed"));
		(void) ddi_dma_unbind_handle(dma_handle);
		goto cleanup;
	}

	/* construct the UtilParamsGet message */
	msgp->StdMessageFrame.VersionOffset = I2O_VERSION_11;
	msgp->StdMessageFrame.MsgFlags = 0;
	ddi_put16(acc_hdl2, &msgp->StdMessageFrame.MessageSize,
		(sizeof (i2o_util_params_get_message_t) +
		sizeof (i2o_sg_element_t)) >> 2);
	put_msg_Function(&msgp->StdMessageFrame, I2O_UTIL_PARAMS_GET, acc_hdl2);
	put_msg_InitiatorAddress(&msgp->StdMessageFrame,
		I2O_HOST_TID, acc_hdl2);
	put_msg_TargetAddress(&msgp->StdMessageFrame,
		I2O_IOP_TID, acc_hdl2);
	ddi_put32(acc_hdl2,
	    &msgp->StdMessageFrame.InitiatorContext.initiator_context_32bits,
	    (uint32_t)i2o_msg_reply);

	sgl = msgp->SGL.u1.Simple;

	put_flags_count_Flags(&sgl->FlagsCount, I2O_SGL_FLAGS_END_OF_BUFFER |
		I2O_SGL_FLAGS_SIMPLE_ADDRESS_ELEMENT, acc_hdl2);
	put_flags_count_Count(&sgl->FlagsCount,  ops_block_size, acc_hdl2);
	ddi_put32(acc_hdl2, &sgl->PhysicalAddress,
		(uint_t)dma_cookie.dmac_address);

	put_flags_count_Flags(&sgl[1].FlagsCount,
		I2O_SGL_FLAGS_LAST_ELEMENT |
		I2O_SGL_FLAGS_END_OF_BUFFER |
		I2O_SGL_FLAGS_SIMPLE_ADDRESS_ELEMENT, acc_hdl2);
	put_flags_count_Count(&sgl[1].FlagsCount,
		results_block_size, acc_hdl2);
	ddi_put32(acc_hdl2, &sgl[1].PhysicalAddress,
		(uint_t)dma_cookie.dmac_address + ops_block_size);

	mutex_init(&test_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&test_cv, NULL, CV_DEFAULT, NULL);

	mutex_enter(&test_mutex);

	test_result = 0;

	/* send the message to the IOP */
	(void) i2o_msg_send(iop->i2o_iop_handle, (void *)msgp, msg_handle);

	/* wait for the reply */
	if (test_result == 0)
		cv_wait(&test_cv, &test_mutex);

	mutex_exit(&test_mutex);

	(void) ddi_dma_unbind_handle(dma_handle);

	/*
	 * **************************************************************
	 * Now, print all the parameters.
	 * **************************************************************
	 */

	/* group 0001h - Message Interface */

	message_if = (i2o_exec_iop_message_if_scalar_t *)
			(buf + ops_block_size +
			sizeof (i2o_param_results_list_header_t) +
			sizeof (i2o_param_read_operation_result_t));
	cmn_err(CE_CONT,
		"?IOP Message Interface Parameters - Group 0001h:");
	cmn_err(CE_CONT, "?\tInboundFrameSize: %x\n", ddi_get32(acc_hdl,
			&message_if->InboundFrameSize));
	cmn_err(CE_CONT, "?\tInboundSizeTarget: %x\n", ddi_get32(acc_hdl,
			&message_if->InboundSizeTarget));
	cmn_err(CE_CONT, "?\tInboundMax: %x\n", ddi_get32(acc_hdl,
			&message_if->InboundMax));
	cmn_err(CE_CONT, "?\tInboundTarget: %x\n", ddi_get32(acc_hdl,
			&message_if->InboundTarget));
	cmn_err(CE_CONT, "?\tInboundPoolCount: %x\n", ddi_get32(acc_hdl,
			&message_if->InboundPoolCount));
	cmn_err(CE_CONT, "?\tInboundCurrentFree: %x\n", ddi_get32(acc_hdl,
			&message_if->InboundCurrentFree));
	cmn_err(CE_CONT, "?\tInboundCurrentPost: %x\n", ddi_get32(acc_hdl,
			&message_if->InboundCurrentPost));
	cmn_err(CE_CONT, "?\tStaticCount: %x\n", ddi_get16(acc_hdl,
			&message_if->StaticCount));
	cmn_err(CE_CONT, "?\tStaticInstanceCount: %x\n", ddi_get16(acc_hdl,
			&message_if->StaticInstanceCount));
	cmn_err(CE_CONT, "?\tStaticLimit: %x\n", ddi_get16(acc_hdl,
			&message_if->StaticLimit));
	cmn_err(CE_CONT, "?\tStaticInstanceLimit: %x\n", ddi_get16(acc_hdl,
			&message_if->StaticInstanceLimit));
	cmn_err(CE_CONT, "?\tOutboundFrameSize: %x\n", ddi_get32(acc_hdl,
			&message_if->OutboundFrameSize));
	cmn_err(CE_CONT, "?\tOutboundMax: %x\n", ddi_get32(acc_hdl,
			&message_if->OutboundMax));
	cmn_err(CE_CONT, "?\tOutboundTarget: %x\n", ddi_get32(acc_hdl,
			&message_if->OutboundMaxTarget));
	cmn_err(CE_CONT, "?\tOutboundCurrentFree: %x\n", ddi_get32(acc_hdl,
			&message_if->OutboundCurrentFree));
	cmn_err(CE_CONT, "?\tInboundCurrentPost: %x\n", ddi_get32(acc_hdl,
			&message_if->InboundCurrentPost));
	cmn_err(CE_CONT, "?\tInitCode: %x\n", message_if->InitCode);

cleanup:
	if (buf != NULL)
		ddi_dma_mem_free(&acc_hdl);

	if (dma_handle != NULL)
		ddi_dma_free_handle(&dma_handle);
}

void
i2o_msg_reply(void *m, ddi_acc_handle_t acc_hdl)
{
	i2o_single_reply_message_frame_t 	*rmp;

	mutex_enter(&test_mutex);

	rmp = (i2o_single_reply_message_frame_t *)m;
	if (rmp->ReqStatus != I2O_REPLY_STATUS_SUCCESS) {
	    cmn_err(CE_CONT, "i2o_msg_reply: Reply Message Frame:");
	    cmn_err(CE_CONT,
		"?Reply Message Frame (Function %x):",
		get_msg_Function(&rmp->StdMessageFrame, acc_hdl));
	    cmn_err(CE_CONT,
		"?\tReqStatus: %x DetailedStatusCode %x\n", rmp->ReqStatus,
		ddi_get16(acc_hdl, &rmp->DetailedStatusCode));
	}

	test_result = 1;

	cv_broadcast(&test_cv);

	mutex_exit(&test_mutex);
}
#endif
