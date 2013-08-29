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
 * Copyright (C) 2013 Hewlett-Packard Development Company, L.P.
 */

#include "cpqary3.h"

/*
 * Local Autoconfiguration Function Prototype Declations
 */

int cpqary3_attach(dev_info_t *, ddi_attach_cmd_t);
int cpqary3_detach(dev_info_t *, ddi_detach_cmd_t);
int cpqary3_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

/*
 * Local Functions Definitions
 */

static void cpqary3_cleanup(cpqary3_t *, uint32_t);
static uint8_t cpqary3_update_ctlrdetails(cpqary3_t *, uint32_t *);
int8_t cpqary3_detect_target_geometry(cpqary3_t *);

/*
 * External Variable Definitions
 */

extern cpqary3_driver_info_t gdriver_info;

/*
 * Global Variables Definitions
 */

static char cpqary3_brief[]    =	"HP Smart Array Driver";
void *cpqary3_state;

/* HPQaculi Changes */

/*
 * HBA minor number schema
 *
 * The minor numbers for any minor device nodes that we create are
 * governed by the SCSA framework.  We use the macros below to
 * fabricate minor numbers for nodes that we own.
 *
 * See sys/impl/transport.h for more info.
 */

/* Macro to extract interface from minor number */
#define	CPQARY3_MINOR2INTERFACE(_x)  ((_x) & (TRAN_MINOR_MASK))

/* Base of range assigned to HBAs: */
#define	SCSA_MINOR_HBABASE  (32)

/* Our minor nodes: */
#define	CPQARY3_MINOR  (0 + SCSA_MINOR_HBABASE)

/* Convenience macros to convert device instances to minor numbers */
#define	CPQARY3_INST2x(_i, _x)    (((_i) << INST_MINOR_SHIFT) | (_x))
#define	CPQARY3_INST2CPQARY3(_i)  CPQARY3_INST2x(_i, CPQARY3_MINOR)

/* HPQacucli Changes */

/*
 * The Driver DMA Limit structure.
 * Data used for SMART Integrated Array Controller shall be used.
 */

ddi_dma_attr_t cpqary3_dma_attr = {
	DMA_ATTR_V0,		/* ddi_dma_attr version */
	0,			/* Low Address */
	0xFFFFFFFFFFFFFFFF,	/* High Address */
	0x00FFFFFF,		/* Max DMA Counter register */
	0x20,			/* Byte Alignment */
	0x20,			/* Burst Sizes : 32 Byte */
	DMA_UNIT_8,		/* Minimum DMA xfer Size */
	0xFFFFFFFF,		/* Maximum DMA xfer Size */
	/*
	 * Segment boundary restrictions
	 * The addr should not cross 4GB boundry.
	 * This is required to address an issue
	 * in the Surge ASIC, with earlier FW versions.
	 */
	0xFFFFFFFF,
	CPQARY3_SG_CNT,		/* Scatter/Gather List Length */
	512,			/* Device Granularity */
	0			/* DMA flags */
};

/*
 * The Device Access Attribute Structure.
 */

ddi_device_acc_attr_t cpqary3_dev_attributes = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};

/*
 * Character-Block Operations Structure
 */

static struct cb_ops cpqary3_cb_ops = {
	/* HPQacucli Changes */
	scsi_hba_open,
	scsi_hba_close,
	/* HPQacucli Changes */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	cpqary3_ioctl,		/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_stream */
	(int)(D_NEW|D_MP),	/* cb_flag */
	CB_REV,
	nodev,
	nodev
};

/*
 * Device Operations Structure
 */

static struct dev_ops cpqary3_dev_ops = {
	DEVO_REV,		/* Driver Build Version */
	0,			/* Driver reference count */
	nodev,			/* Get Info */
	nulldev,		/* Identify not required */
	nulldev,		/* Probe, obselete for s2.6 and up */
	cpqary3_attach,		/* Attach routine */
	cpqary3_detach,		/* Detach routine */
	nodev,			/* Reset */
	&cpqary3_cb_ops,	/* Entry Points for C&B drivers */
	NULL,			/* Bus ops */
	nodev			/* cpqary3_power */
};

/*
 * Linkage structures
 */

static struct modldrv cpqary3_modldrv = {
	&mod_driverops,		/* Module Type - driver */
	cpqary3_brief,		/* Driver Desc */
	&cpqary3_dev_ops	/* Driver Ops */
};

static struct modlinkage cpqary3_modlinkage = {
	MODREV_1,		/* Loadable module rev. no. */
	&cpqary3_modldrv, 	/* Loadable module */
	NULL 			/* end */
};


/*
 * Function	:	_init
 * Description	:	This routine allocates soft state resources for the
 *			driver, registers the HBA with the system and
 *			adds the driver(loadable module).
 * Called By	:	Kernel
 * Parameters	:	None
 * Return Values:	0 / Non-Zero
 *			[as returned by the mod_install OS function]
 */
int
_init()
{
	int  retvalue;

	/*
	 * Allocate Soft State Resources; if failure, return.
	 */
	retvalue = ddi_soft_state_init(&cpqary3_state,
	    sizeof (cpqary3_t), MAX_CTLRS);
	VERIFY(retvalue == 0);

	/*
	 * Initialise the HBA Interface.
	 */
	if (!(retvalue = scsi_hba_init(&cpqary3_modlinkage))) {
		/* Load the driver */
		if ((retvalue = mod_install(&cpqary3_modlinkage))) {
			/*
			 * Failed to load the driver, undo HBA interface
			 * and soft state allocation.
			 */
			scsi_hba_fini(&cpqary3_modlinkage);
			ddi_soft_state_fini(&cpqary3_state);
		}
	} else {
		/*
		 * Failed to register HBA interface, undo all soft state
		 * allocation
		 */
		ddi_soft_state_fini(&cpqary3_state);
	}

	return (retvalue);
}

/*
 * Function	: 	_fini
 * Description	: 	This routine removes the loadable module, cancels the
 *			HBA registration and deallocates soft state resources.
 * Called By	: 	Kernel
 * Parameters	: 	None
 * Return Values: 	0 - Success / Non-Zero - Failure
 *			[as returned by the mod_remove(OS provided) function]
 */
int
_fini()
{
	int  retvalue;

	/* Unload the Driver(loadable module) */

	if ((retvalue = mod_remove(&cpqary3_modlinkage)) == 0) {

		/* Cancel the registeration for the HBA Interface */
		scsi_hba_fini(&cpqary3_modlinkage);

		/* dealloacte soft state resources of the driver */
		ddi_soft_state_fini(&cpqary3_state);
	}

	return (retvalue);
}

/*
 * Function	: 	_info
 * Description	: 	This routine returns information about the driver.
 * Called By	: 	Kernel
 * Parameters	: 	None
 * Return Values: 	0 / Non-Zero
 *			[as returned by mod_info(OS provided) function]
 */
int
_info(struct modinfo *modinfop)
{
	/*
	 * Get the module information.
	 */
	return (mod_info(&cpqary3_modlinkage, modinfop));
}


/*
 * Function	: 	cpqary3_attach
 * Description	: 	This routine initializes the driver specific soft state
 *			structure, initializes the HBA, interrupt handlers,
 *			memory pool, timeout handler, various mutex, creates the
 *			minor node.
 * Called By	: 	kernel
 * Parameters	: 	dip, command for attach
 * Return Values: 	DDI_SUCCESS / DDI_FAILURE
 *			[Success on overall initialization & configuration
 *			being successful. Failure if any of the initialization
 *			or any driver-specific mandatory configuration fails]
 */
int
cpqary3_attach(dev_info_t *dip, ddi_attach_cmd_t attach_cmd)
{
	int8_t		minor_node_name[14];
	uint32_t	instance;
	uint32_t	retvalue;
	uint32_t	cleanstatus = 0;
	cpqary3_t	*cpqary3p;		/* per-controller */
	ddi_dma_attr_t	tmp_dma_attr;

	/* Return Failure, If the Command is other than - DDI_ATTACH. */

	if (attach_cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	/* Get the Instance of the Device */

	instance = ddi_get_instance(dip);

	/* Allocate the per-device-instance soft state structure */

	retvalue = ddi_soft_state_zalloc(cpqary3_state, instance);
	VERIFY(retvalue == 0);

	cleanstatus |= CPQARY3_SOFTSTATE_ALLOC_DONE;

	/* Per Controller Pointer */
	cpqary3p = ddi_get_soft_state(cpqary3_state, instance);
	if (!cpqary3p) {
		cmn_err(CE_WARN, "CPQary3: Soft State Retrieval Failed");
		cpqary3_cleanup(cpqary3p, cleanstatus);
		return (DDI_FAILURE);
	}

	/* Maintain a record in per-ctlr structure */
	cpqary3p->dip = dip;
	cpqary3p->instance = instance;

	/* Get the User Configuration information from Driver's conf File */
	cpqary3_read_conf_file(dip, cpqary3p);

	/* Get and Map the HW Configuration */
	retvalue = cpqary3_update_ctlrdetails(cpqary3p, &cleanstatus);
	if (retvalue == CPQARY3_FAILURE) {
		cpqary3_cleanup(cpqary3p, cleanstatus);
		return (DDI_FAILURE);
	}

	/* Get the Cookie for hardware Interrupt Handler */
	if (ddi_get_iblock_cookie(dip, 0, &cpqary3p->hw_iblock_cookie) !=
	    DDI_SUCCESS) {
		cpqary3_cleanup(cpqary3p, cleanstatus);
		return (DDI_FAILURE);
	}

	/* Initialize Per Controller Mutex */
	mutex_init(&cpqary3p->hw_mutex, NULL, MUTEX_DRIVER,
	    (void *)cpqary3p->hw_iblock_cookie);

	cleanstatus |= CPQARY3_MUTEX_INIT_DONE;

	/* Get the Cookie for Soft(low level) Interrupt Handler */
	if (ddi_get_soft_iblock_cookie(dip, DDI_SOFTINT_HIGH,
	    &cpqary3p->sw_iblock_cookie) != DDI_SUCCESS) {
		cpqary3_cleanup(cpqary3p, cleanstatus);
		return (DDI_FAILURE);
	}

	/* Initialize the s/w Mutex */
	mutex_init(&cpqary3p->sw_mutex, NULL, MUTEX_DRIVER,
	    (void *)cpqary3p->sw_iblock_cookie);
	cleanstatus |= CPQARY3_SW_MUTEX_INIT_DONE;

	/* Initialize per Controller private details */
	retvalue = cpqary3_init_ctlr_resource(cpqary3p);
	if (retvalue != CPQARY3_SUCCESS) {
		cpqary3_cleanup(cpqary3p, cleanstatus);
		return (DDI_FAILURE);
	}
	cleanstatus |= CPQARY3_CTLR_CONFIG_DONE;

	/*
	 * Allocate HBA transport structure
	 */
	cpqary3p->hba_tran = scsi_hba_tran_alloc(dip, SCSI_HBA_CANSLEEP);
	if (!cpqary3p->hba_tran) {
		cpqary3_cleanup(cpqary3p, cleanstatus);
		return (DDI_FAILURE);
	}
	cleanstatus |= CPQARY3_HBA_TRAN_ALLOC_DONE;

	/*
	 * Set private field for the HBA tran structure.
	 * Initialise the HBA tran entry points.
	 * Attach the controller to HBA.
	 */
	cpqary3_init_hbatran(cpqary3p);

	/* PERF */
	/* SG */
	tmp_dma_attr = cpqary3_dma_attr;
	tmp_dma_attr.dma_attr_sgllen = cpqary3p->sg_cnt;
	/* SG */
	/* PERF */
	/*
	 * Register the DMA attributes and the transport vectors
	 * of each instance of the  HBA device.
	 */
	if (scsi_hba_attach_setup(dip, &tmp_dma_attr, cpqary3p->hba_tran,
	    SCSI_HBA_TRAN_CLONE) == DDI_FAILURE) {
		cpqary3_cleanup(cpqary3p, cleanstatus);
		return (DDI_FAILURE);
	}
	cleanstatus |= CPQARY3_HBA_TRAN_ATTACH_DONE;

	/*
	 * Create a minor node for Ioctl interface.
	 * The nomenclature used will be "cpqary3" immediately followed by
	 * the current driver instance in the system.
	 * for e.g.: 	for 0th instance : cpqary3,0
	 * 				for 1st instance : cpqary3,1
	 */

	(void) sprintf(minor_node_name, "cpqary3,%d", instance);

	/* HPQacucli Changes */
	if (ddi_create_minor_node(dip, minor_node_name, S_IFCHR,
	    CPQARY3_INST2CPQARY3(instance), DDI_NT_SCSI_NEXUS, 0) ==
	    DDI_SUCCESS) {
		/* HPQacucli Changes */
		cleanstatus |= CPQARY3_CREATE_MINOR_NODE;
	} else {
		cmn_err(CE_NOTE, "CPQary3 : Failed to create minor node");
		cpqary3_cleanup(cpqary3p, cleanstatus);
		return (DDI_FAILURE);
	}


	/* Register a timeout driver-routine to be called every 2 secs */
	cpqary3p->tick_tmout_id = timeout(cpqary3_tick_hdlr,
	    (caddr_t)cpqary3p, drv_usectohz(CPQARY3_TICKTMOUT_VALUE));
	cleanstatus |= CPQARY3_TICK_TMOUT_REGD;

	/* Register Software Interrupt Handler */
	if (ddi_add_softintr(dip,  DDI_SOFTINT_HIGH,
	    &cpqary3p->cpqary3_softintr_id, &cpqary3p->sw_iblock_cookie, NULL,
	    cpqary3_sw_isr, (caddr_t)cpqary3p) != DDI_SUCCESS) {
		cpqary3_cleanup(cpqary3p, cleanstatus);
		return (DDI_FAILURE);
	}
	cleanstatus |= CPQARY3_SW_INTR_HDLR_SET;

	/* Register Interrupt Handler */
	if (ddi_add_intr(dip, 0, &cpqary3p->hw_iblock_cookie, NULL,
	    cpqary3_hw_isr, (caddr_t)cpqary3p) != DDI_SUCCESS) {
		cpqary3_cleanup(cpqary3p, cleanstatus);
		return (DDI_FAILURE);
	}
	cleanstatus |= CPQARY3_INTR_HDLR_SET;

	/* Enable the Controller Interrupt */
	cpqary3_intr_onoff(cpqary3p, CPQARY3_INTR_ENABLE);
	if (cpqary3p->host_support & 0x4)
		cpqary3_lockup_intr_onoff(cpqary3p, CPQARY3_LOCKUP_INTR_ENABLE);

	/*
	 * We have come with hmaeventd - which logs the storage events on
	 * console as well as in IML. So we are commenting the NOE support in
	 * the driver
	 */

	/* NOE */
	if (cpqary3p->noe_support == 1) {
		/* Enable the Notification on Event in this controller */
		if (CPQARY3_SUCCESS ==
		    cpqary3_send_NOE_command(cpqary3p,
		    NULL, CPQARY3_NOE_INIT)) {
			cleanstatus |= CPQARY3_NOE_INIT_DONE;
		} else {
			cmn_err(CE_CONT, "CPQary3 : Failed to initialize "
			    "NOTIFICATION ON EVENT \n");
		}
	}
	/* NOE */

	/* Report that an Instance of the Driver is Attached Successfully */
	ddi_report_dev(dip);

	/*
	 * Now update the num_ctlr
	 * This is required for the agents
	 */

	gdriver_info.num_ctlr++;

	return (DDI_SUCCESS);

}

/*
 * Function	: 	cpqary3_detach
 * Description	: 	This routine removes the state associated with a
 * 			given instance of a device node prior to the
 * 			removal of that instance from the system
 * Called By	: 	kernel
 * Parameters	: 	dip, command for detach
 * Return Values: 	DDI_SUCCESS / DDI_FAILURE
 *			[failure ONLY if the command sent with this function
 *			as a paramter is not DETACH]
 */
int
cpqary3_detach(dev_info_t *dip, ddi_detach_cmd_t detach_cmd)
{
	cpqary3_t	*cpqary3p;
	scsi_hba_tran_t	*hba_tran;

	/* Return failure, If Command is not DDI_DETACH */

	if (DDI_DETACH != detach_cmd)
		return (DDI_FAILURE);

	/*
	 *  Get scsi_hba_tran structure.
	 *  Get per controller structure.
	 */

	hba_tran = (scsi_hba_tran_t *)ddi_get_driver_private(dip);
	cpqary3p = (cpqary3_t *)hba_tran->tran_hba_private;

	/* Flush the cache */

	cpqary3_flush_cache(cpqary3p);

	/* Undo cpqary3_attach */

	cpqary3_cleanup(cpqary3p, CPQARY3_CLEAN_ALL);

	return (DDI_SUCCESS);

}

/*
 *	Function	: 	cpary3_ioctl
 *	Description	: 	This routine services ioctl requests.
 *	Called By	: 	kernel
 *	Parameters	: 	Too many to list. Please look below !!!
 *	Return Values:  	0 / EINVAL / EFAULT /
 *				[0 on normal successful completion of the ioctl
 *				request]
 */
int
cpqary3_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *retvaluep)
{
	minor_t		cpqary3_minor_num;
	cpqary3_t	*cpqary3p;
	int		instance;

	/*
	 * Get the soft state structure for this instance
	 * Return ENODEV if the structure does not exist.
	 */

	/*
	 * minor() call used in cpqary3_ioctl() returns minor number of the
	 * device which are in the
	 * range 0-255. if the minor number of the device is greater than 255,
	 * data will get truncated. so we are now using getminor(),
	 * instead of minor()
	 */

	if (EINVAL == (cpqary3_minor_num = getminor(dev))) {
		*retvaluep = ENODEV;
		return (*retvaluep);
	}

	/* HPQacucli Changes */

	/* get instance */
	instance = MINOR2INST(cpqary3_minor_num);

	cpqary3p = (cpqary3_t *)ddi_get_soft_state(cpqary3_state, instance);

	/* HPQacucli Changes */

	if (!cpqary3p) {
		*retvaluep = ENODEV;
		return (*retvaluep);
	}

	/* HPQacucli Changes */

	/* check which interface is being requested */
	if (CPQARY3_MINOR2INTERFACE(cpqary3_minor_num) != CPQARY3_MINOR) {
		/* defer to SCSA */
		return (scsi_hba_ioctl(dev, cmd, arg, mode, credp, retvaluep));
	}

	/* HPQacucli Changes */

	switch (cmd) {
		case CPQARY3_IOCTL_DRIVER_INFO:
			*retvaluep =
			    cpqary3_ioctl_driver_info(arg, mode);
			break;

		case CPQARY3_IOCTL_CTLR_INFO:
			*retvaluep =
			    cpqary3_ioctl_ctlr_info(arg, cpqary3p, mode);
			break;

		case CPQARY3_IOCTL_BMIC_PASS:
			*retvaluep =
			    cpqary3_ioctl_bmic_pass(arg, cpqary3p, mode);
			break;

		case CPQARY3_IOCTL_SCSI_PASS:
			*retvaluep =
			    cpqary3_ioctl_scsi_pass(arg, cpqary3p, mode);
			break;

		default:
			*retvaluep = EINVAL;
			break;
	}
		return (*retvaluep);


}


/*
 * Function	: 	cqpary3_cleanup
 * Description	: 	This routine frees all allocated resources.
 * Called By	: 	kernel
 * Parameters	: 	per-controller, bit-map(stating what all to clean)
 * Return Values: 	None
 */
static void
cpqary3_cleanup(cpqary3_t *cpqary3p, uint32_t status)
{
	int8_t		node_name[10];
	clock_t		cpqary3_lbolt;
	uint32_t	targ;

	ASSERT(cpqary3p != NULL);

	/*
	 * Disable the NOE command
	 * Free the Command Memory Pool
	 * destroy all conditional variables
	 */

	/*
	 * We have removed NOE functionality from the
	 * driver. So commenting the below piece of code
	 */

	if (status & CPQARY3_NOE_INIT_DONE) {
		if (CPQARY3_SUCCESS == cpqary3_disable_NOE_command(cpqary3p)) {
			mutex_enter(&cpqary3p->hw_mutex);
			cpqary3_lbolt = ddi_get_lbolt();
			if (DDI_FAILURE ==
			    cv_timedwait_sig(&cpqary3p->cv_noe_wait,
			    &cpqary3p->hw_mutex,
			    cpqary3_lbolt + drv_usectohz(3000000))) {
				cmn_err(CE_NOTE,
				    "CPQary3: Resume signal for disable NOE "
				    "command not received \n");
			}
			mutex_exit(&cpqary3p->hw_mutex);
		}
	}

	/*
	 * Detach the device
	 * Free / Release / Destroy the following entities/resources:
	 * transport layer
	 * h/w & s/w interrupt handlers
	 * all mutex
	 * timeout handler
	 * target structure
	 * minor node
	 * soft state
	 * any register/memory mapping
	 */

	if (status & CPQARY3_INTR_HDLR_SET)
		ddi_remove_intr(cpqary3p->dip, 0, cpqary3p->hw_iblock_cookie);

	if (status & CPQARY3_SW_INTR_HDLR_SET)
		ddi_remove_softintr(cpqary3p->cpqary3_softintr_id);

	if ((status & CPQARY3_TICK_TMOUT_REGD) && cpqary3p->tick_tmout_id) {
		VERIFY(untimeout(cpqary3p->tick_tmout_id) >= 0);
		cpqary3p->tick_tmout_id = NULL;
	}

	if (status & CPQARY3_CREATE_MINOR_NODE) {
		(void) sprintf(node_name, "cpqary3%d", cpqary3p->instance);
		ddi_remove_minor_node(cpqary3p->dip, node_name);
	}

	if (status & CPQARY3_HBA_TRAN_ATTACH_DONE)
		(void) scsi_hba_detach(cpqary3p->dip);

	if (status & CPQARY3_HBA_TRAN_ALLOC_DONE)
		scsi_hba_tran_free(cpqary3p->hba_tran);

	if (status & CPQARY3_CTLR_CONFIG_DONE) {
		mutex_enter(&cpqary3p->hw_mutex);

		cv_destroy(&cpqary3p->cv_abort_wait);
		cv_destroy(&cpqary3p->cv_flushcache_wait);
		cv_destroy(&cpqary3p->cv_noe_wait);
		cv_destroy(&cpqary3p->cv_immediate_wait);
		cv_destroy(&cpqary3p->cv_ioctl_wait);

		for (targ = 0; targ < CPQARY3_MAX_TGT;  targ++) {
			if (cpqary3p->cpqary3_tgtp[targ] == NULL)
				continue;
			MEM_SFREE(cpqary3p->cpqary3_tgtp[targ],
			    sizeof (cpqary3_tgt_t));
		}

		mutex_exit(&cpqary3p->hw_mutex);

		cpqary3_memfini(cpqary3p, CPQARY3_MEMLIST_DONE |
		    CPQARY3_PHYCTGS_DONE | CPQARY3_CMDMEM_DONE);
	}

	if (status & CPQARY3_SW_MUTEX_INIT_DONE)
		mutex_destroy(&cpqary3p->sw_mutex);

	if (status & CPQARY3_MUTEX_INIT_DONE)
		mutex_destroy(&cpqary3p->hw_mutex);

	/*
	 * If this flag is set, free all mapped registers
	 */
	if (status & CPQARY3_MEM_MAPPED) {
		if (cpqary3p->idr_handle)
			ddi_regs_map_free(&cpqary3p->idr_handle);
		if (cpqary3p->isr_handle)
			ddi_regs_map_free(&cpqary3p->isr_handle);
		if (cpqary3p->imr_handle)
			ddi_regs_map_free(&cpqary3p->imr_handle);
		if (cpqary3p->ipq_handle)
			ddi_regs_map_free(&cpqary3p->ipq_handle);
		if (cpqary3p->opq_handle)
			ddi_regs_map_free(&cpqary3p->opq_handle);
		if (cpqary3p->ct_handle)
			ddi_regs_map_free(&cpqary3p->ct_handle);
	}

	if (status & CPQARY3_SOFTSTATE_ALLOC_DONE) {
		ddi_soft_state_free(cpqary3_state,
		    ddi_get_instance(cpqary3p->dip));
	}
}

/*
 * Function	: 	cpqary3_update_ctlrdetails
 * Description	: 	Performs Sanity check of the hw, Updates PCI Config
 *			Information, Verifies the supported board-id and
 *			Sets up a mapping for the Primary I2O Memory BAR and
 *			the Primary DRAM 1 BAR to access Host Interface
 *			registers and the Transport Configuration table.
 * Called By	: 	cpqary3_attach()
 * Parameters	: 	per-controller, bitmap (used for cleaning operations)
 * Return Values: 	SUCCESS / FAILURE
 *			[Success / failure depending upon the outcome of all
 *			checks and mapping. If any of them fail, a failure is
 *			sent back]
 */
static uint8_t
cpqary3_update_ctlrdetails(cpqary3_t *cpqary3p, uint32_t *cleanstatus)
{
	int8_t			retvalue;
	uint8_t			mem_bar0_set = 0;
	uint8_t			mem_64_bar0_set = 0;
	uint8_t			mem_bar1_set = 0;
	uint8_t			mem_64_bar1_set = 0;
	int32_t			reglen;
	uint32_t		*regp;
	uint32_t		mem_bar0 = 0;
	uint32_t		mem_64_bar0;
	uint32_t		mem_bar1 = 0;
	uint32_t		mem_64_bar1 = 0;
	uint32_t		ct_mem_bar = 0;
	uint32_t		ct_cfgmem_val = 0;
	uint32_t		ct_memoff_val = 0;
	uint32_t		ct_cfg_bar = 0;
	uint32_t		ct_mem_len = 0;
	offset_t		map_len = 0;
	uint32_t		regset_index;
	ddi_acc_handle_t 	pci_handle;
	uint32_t		*ct_cfg_offset;
	ddi_acc_handle_t	ct_cfgoff_handle;
	uint32_t		*ct_mem_offset;
	ddi_acc_handle_t	ct_memoff_handle;

	RETURN_FAILURE_IF_NULL(cpqary3p);

	/*
	 * Check if the bus, or part of the bus  that  the  device  is installed
	 * on, permits the device to become a DMA master.
	 * If our device is not permitted to become master, return
	 */
	if (ddi_slaveonly(cpqary3p->dip) == DDI_SUCCESS)
		return (CPQARY3_FAILURE);

	/*
	 * Get the HW Configuration
	 * Get Bus #, Dev # and Func # for this device
	 * Free the memory that regp points towards after the
	 * ddi_getlongprop() call
	 */
	if (ddi_getlongprop(DDI_DEV_T_NONE, cpqary3p->dip, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)&regp, &reglen) != DDI_PROP_SUCCESS)
		return (CPQARY3_FAILURE);

	cpqary3p->bus = PCI_REG_BUS_G(*regp);
	cpqary3p->dev = PCI_REG_DEV_G(*regp);
	cpqary3p->fun = PCI_REG_FUNC_G(*regp);

	for (regset_index = 0; regset_index < reglen / 20; regset_index ++) {
		if (PCI_REG_ADDR_G(*(regp + regset_index * 5)) == 0x2) {
			if (!mem_bar0_set) {
				mem_bar0 = regset_index;
				mem_bar0_set = 1;
			} else if (!mem_bar1_set) {
				mem_bar1 = regset_index;
				mem_bar1_set = 1;
			}
		}
	}

	mem_64_bar0 = mem_bar0;
	mem_64_bar1 = mem_bar1;

	for (regset_index = 0; regset_index < reglen / 20; regset_index ++) {
		if (PCI_REG_ADDR_G(*(regp + regset_index * 5)) == 0x3) {
			if (!mem_64_bar0_set) {
				mem_64_bar0 = regset_index;
				mem_64_bar0_set = 1;
			} else if (!mem_64_bar1_set) {
				mem_64_bar1 = regset_index;
				mem_64_bar1_set = 1;
			}
		}
	}

	mem_bar0 = mem_64_bar0;
	mem_bar1 = mem_64_bar1;

	MEM_SFREE(regp, reglen);

	/*
	 * Setup resources to access the Local PCI Bus
	 * If unsuccessful, return.
	 * Else, read the following from the PCI space:
	 * 	Sub-System Vendor ID
	 * 	Sub-System Device ID
	 * 	Interrupt Line
	 * 	Command Register
	 * Free the just allocated resources.
	 */
	if (pci_config_setup(cpqary3p->dip, &pci_handle) != DDI_SUCCESS)
		return (CPQARY3_FAILURE);

	cpqary3p->irq = pci_config_get8(pci_handle, PCI_CONF_ILINE);
	cpqary3p->board_id =
	    (pci_config_get16(pci_handle, PCI_CONF_SUBVENID) << 16)
	    | pci_config_get16(pci_handle, PCI_CONF_SUBSYSID);

	pci_config_teardown(&pci_handle);

	/*
	 * Verify Board Id
	 * If unsupported boards are detected, return.
	 * Update name for controller for driver use.
	 */
	cpqary3p->bddef = cpqary3_bd_getbybid(cpqary3p->board_id);
	if (cpqary3p->bddef == NULL) {
		cmn_err(CE_WARN,
		    "CPQary3: <Bid 0x%X> Controller NOT Supported",
		    cpqary3p->board_id);
		return (CPQARY3_FAILURE);
	}
	map_len = cpqary3p->bddef->bd_maplen;
	(void) strcpy(cpqary3p->hba_name, cpqary3p->bddef->bd_dispname);

	/*
	 * Set up a mapping for the following registers:
	 * 	Inbound Doorbell
	 * 	Outbound List Status
	 * 	Outbound Interrupt Mask
	 * 	Host Inbound Queue
	 * 	Host Outbound Queue
	 * 	Host Transport Configuration Table
	 * Mapping of the above has been done in that order.
	 */
	retvalue = ddi_regs_map_setup(cpqary3p->dip,
	    mem_bar0, /* INDEX_PCI_BASE0, */
	    (caddr_t *)&cpqary3p->idr, (offset_t)I2O_IBDB_SET, map_len,
	    &cpqary3_dev_attributes, &cpqary3p->idr_handle);

	if (retvalue != DDI_SUCCESS) {
		if (DDI_REGS_ACC_CONFLICT == retvalue) {
			cmn_err(CE_WARN,
			    "CPQary3 : Registers Mapping Conflict");
		}
		cmn_err(CE_WARN, "CPQary3 : Inbound Doorbell "
		    "Register Mapping Failed");
		return (CPQARY3_FAILURE);
	}

	/* PERF */
	retvalue = ddi_regs_map_setup(cpqary3p->dip,
	    mem_bar0, /* INDEX_PCI_BASE0, */
	    (caddr_t *)&cpqary3p->odr, (offset_t)I2O_OBDB_STATUS, map_len,
	    &cpqary3_dev_attributes, &cpqary3p->odr_handle);

	if (retvalue != DDI_SUCCESS) {
		if (DDI_REGS_ACC_CONFLICT == retvalue) {
			cmn_err(CE_WARN,
			    "CPQary3 : Registers Mapping Conflict");
		}
		cmn_err(CE_WARN,
		    "CPQary3 : Outbound Doorbell Register Mapping Failed");
		return (CPQARY3_FAILURE);
	}

	retvalue = ddi_regs_map_setup(cpqary3p->dip,
	    mem_bar0, /* INDEX_PCI_BASE0, */
	    (caddr_t *)&cpqary3p->odr_cl, (offset_t)I2O_OBDB_CLEAR, map_len,
	    &cpqary3_dev_attributes, &cpqary3p->odr_cl_handle);

	if (retvalue != DDI_SUCCESS) {
		if (DDI_REGS_ACC_CONFLICT == retvalue) {
			cmn_err(CE_WARN,
			    "CPQary3 : Registers Mapping Conflict");
		}
		cmn_err(CE_WARN, "CPQary3 : Outbound Doorbell "
		    "Register Clear Mapping Failed");
		return (CPQARY3_FAILURE);
	}

	/* LOCKUP CODE */
	retvalue = ddi_regs_map_setup(cpqary3p->dip,
	    mem_bar0, /* INDEX_PCI_BASE0, */
	    (caddr_t *)&cpqary3p->spr0, (offset_t)I2O_CTLR_INIT, map_len,
	    &cpqary3_dev_attributes, &cpqary3p->spr0_handle);

	if (retvalue != DDI_SUCCESS) {
		if (DDI_REGS_ACC_CONFLICT == retvalue) {
			cmn_err(CE_WARN,
			    "CPQary3 : Registers Mapping Conflict");
		}
		cmn_err(CE_WARN,
		    "CPQary3 : Scratch Pad register zero Mapping Failed");
		return (CPQARY3_FAILURE);
	}
	/* LOCKUP CODE */
	/* PERF */

	*cleanstatus |= CPQARY3_MEM_MAPPED;

	retvalue = ddi_regs_map_setup(cpqary3p->dip,
	    mem_bar0, /* INDEX_PCI_BASE0, */
	    (caddr_t *)&cpqary3p->isr, (offset_t)I2O_INT_STATUS, map_len,
	    &cpqary3_dev_attributes, &cpqary3p->isr_handle);

	if (retvalue != DDI_SUCCESS) {
		if (retvalue == DDI_REGS_ACC_CONFLICT) {
			cmn_err(CE_WARN,
			    "CPQary3 : Registers Mapping Conflict");
		}
		cmn_err(CE_WARN,
		    "CPQary3 : Interrupt Status Register Mapping Failed");
		return (CPQARY3_FAILURE);
	}

	retvalue = ddi_regs_map_setup(cpqary3p->dip,
	    mem_bar0, /* INDEX_PCI_BASE0, */
	    (caddr_t *)&cpqary3p->imr, (offset_t)I2O_INT_MASK, map_len,
	    &cpqary3_dev_attributes, &cpqary3p->imr_handle);

	if (retvalue != DDI_SUCCESS) {
		if (retvalue == DDI_REGS_ACC_CONFLICT) {
			cmn_err(CE_WARN,
			    "CPQary3 : Registers Mapping Conflict");
		}
		cmn_err(CE_WARN,
		    "CPQary3 : Interrupt Mask Register Mapping Failed");
		return (CPQARY3_FAILURE);
	}

	retvalue = ddi_regs_map_setup(cpqary3p->dip,
	    mem_bar0, /* INDEX_PCI_BASE0, */
	    (caddr_t *)&cpqary3p->ipq, (offset_t)I2O_IBPOST_Q, map_len,
	    &cpqary3_dev_attributes, &cpqary3p->ipq_handle);

	if (retvalue != DDI_SUCCESS) {
		if (retvalue == DDI_REGS_ACC_CONFLICT) {
			cmn_err(CE_WARN,
			    "CPQary3 : Registers Mapping Conflict");
		}
		cmn_err(CE_WARN,
		    "CPQary3 : Inbound Queue Register Mapping Failed");
		return (CPQARY3_FAILURE);
	}

	retvalue = ddi_regs_map_setup(cpqary3p->dip,
	    mem_bar0, /* INDEX_PCI_BASE0, */ (caddr_t *)&cpqary3p->opq,
	    (offset_t)I2O_OBPOST_Q, map_len, &cpqary3_dev_attributes,
	    &cpqary3p->opq_handle);

	if (retvalue != DDI_SUCCESS) {
		if (retvalue == DDI_REGS_ACC_CONFLICT) {
			cmn_err(CE_WARN,
			    "CPQary3 : Registers Mapping Conflict");
		}
		cmn_err(CE_WARN, "CPQary3 : Outbound Post Queue "
		    "Register Mapping Failed");
		return (CPQARY3_FAILURE);
	}


	/*
	 * The config offset and memory offset have to be obtained in order to
	 * locate the config table.
	 */
	retvalue = ddi_regs_map_setup(cpqary3p->dip,
	    mem_bar0, /* INDEX_PCI_BASE0, */ (caddr_t *)&ct_cfg_offset,
	    (offset_t)CT_CFG_OFFSET, map_len, &cpqary3_dev_attributes,
	    &ct_cfgoff_handle);

	if (retvalue != DDI_SUCCESS) {
		if (retvalue == DDI_REGS_ACC_CONFLICT) {
			cmn_err(CE_WARN,
			    "CPQary3 : Registers Mapping Conflict");
		}
		cmn_err(CE_WARN, "CPQary3 : Configuration Table "
		    "Register Mapping Failed");
		return (CPQARY3_FAILURE);
	}

	retvalue = ddi_regs_map_setup(cpqary3p->dip,
	    mem_bar0, /* INDEX_PCI_BASE0, */
	    (caddr_t *)&ct_mem_offset, (offset_t)CT_MEM_OFFSET, map_len,
	    &cpqary3_dev_attributes, &ct_memoff_handle);

	if (retvalue != DDI_SUCCESS) {
		if (retvalue == DDI_REGS_ACC_CONFLICT) {
			cmn_err(CE_WARN,
			    "CPQary3 : Registers Mapping Conflict");
		}
		cmn_err(CE_WARN, "CPQary3 : Configuration Table "
		    "Register Mapping Failed");
		return (CPQARY3_FAILURE);
	}

	ct_cfgmem_val = (uint32_t)ddi_get32(ct_cfgoff_handle, ct_cfg_offset);
	ct_memoff_val = (uint32_t)ddi_get32(ct_memoff_handle, ct_mem_offset);

	ddi_regs_map_free(&ct_cfgoff_handle);
	ddi_regs_map_free(&ct_memoff_handle);

	ct_cfg_bar = (ct_cfgmem_val & 0x0000ffff);
	ct_mem_len = (ct_cfgmem_val & 0xffff0000);
	ct_mem_len = (ct_mem_len >> 16);

	if (ct_cfg_bar == 0x10) {
		if (ct_mem_len) {
			ct_mem_bar = mem_64_bar0;
		} else {
			ct_mem_bar = mem_bar0;
		}

	} else if (ct_cfg_bar == 0x14) {
		if (ct_mem_len) {
			ct_mem_bar = mem_64_bar1;
		} else {
			ct_mem_bar = mem_bar1;
		}
	} else {
		return (CPQARY3_FAILURE);
	}


	/*
	 * The Configuration Table(CT) shall be mapped in the form of a
	 * structure since several members in the CT need to be accessed
	 * to read and write.
	 */
	retvalue = ddi_regs_map_setup(cpqary3p->dip,
	    ct_mem_bar, /* INDEX_PCI_BASE0/1, */
	    (caddr_t *)&cpqary3p->ct, (offset_t)ct_memoff_val,
	    sizeof (CfgTable_t), &cpqary3_dev_attributes, &cpqary3p->ct_handle);

	if (retvalue != DDI_SUCCESS) {
		if (retvalue == DDI_REGS_ACC_CONFLICT) {
			cmn_err(CE_WARN,
			    "CPQary3 : Registers Mapping Conflict");
		}
		cmn_err(CE_WARN, "CPQary3 : Configuration Table "
		    "Register Mapping Failed");
		return (CPQARY3_FAILURE);
	}

	/* PERF */

	retvalue = ddi_regs_map_setup(cpqary3p->dip,
	    ct_mem_bar, /* INDEX_PCI_BASE0/1, */
	    (caddr_t *)&cpqary3p->cp,
	    (offset_t)(ct_memoff_val + cpqary3p->ct->TransportMethodOffset),
	    sizeof (CfgTrans_Perf_t), &cpqary3_dev_attributes,
	    &cpqary3p->cp_handle);

	if (retvalue != DDI_SUCCESS) {
		if (retvalue == DDI_REGS_ACC_CONFLICT)
			cmn_err(CE_WARN,
			    "CPQary3 : Registers Mapping Conflict");
		cmn_err(CE_WARN, "CPQary3 : Performant Transport Method Table "
		    "Mapping Failed");
		return (CPQARY3_FAILURE);
	}

	/* PERF */

	return (CPQARY3_SUCCESS);
}
