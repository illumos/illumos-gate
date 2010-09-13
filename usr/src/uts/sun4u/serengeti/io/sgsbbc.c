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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * PCI SBBC Device Driver that provides interfaces into
 * EPLD and IO-SRAM
 *
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/stropts.h>
#include <sys/kmem.h>
#include <sys/sunndi.h>
#include <sys/conf.h>		/* req. by dev_ops flags MTSAFE etc. */
#include <sys/modctl.h>		/* for modldrv */
#include <sys/promif.h>
#include <sys/stat.h>
#include <sys/ddi.h>

#include <sys/serengeti.h>
#include <sys/sgsbbc_priv.h>
#include <sys/sgsbbc_iosram_priv.h>
#include <sys/sgsbbc_mailbox_priv.h>

#ifdef DEBUG
/* debug flag */
uint_t sgsbbc_debug = 0;
#endif /* DEBUG */

/* driver entry point fn definitions */
static int	sbbc_attach(dev_info_t *, ddi_attach_cmd_t);
static int	sbbc_detach(dev_info_t *, ddi_detach_cmd_t);

/*
 * SBBC soft state hook
 */
static void    *sbbcp;

/*
 * Chosen IOSRAM
 */
struct chosen_iosram *master_iosram = NULL;

/*
 * define new iosram's sbbc and liked list of sbbc.
 */
struct sbbc_softstate *sgsbbc_instances = NULL;

/*
 * At attach time, check if the device is the 'chosen' node
 * if it is, set up the IOSRAM Solaris<->SC Comm tunnel
 * Its like 'Highlander' - there can be only one !
 */
static int	master_chosen = FALSE;
kmutex_t	chosen_lock;

/*
 * Local variable to save intr_in_enabled when the driver is suspended
 */
static uint32_t	intr_in_enabled;

/*
 * Local declarations
 */
static void	softsp_init(sbbc_softstate_t *, dev_info_t *);
static void	sbbc_chosen_init(sbbc_softstate_t *);
static void	sbbc_add_instance(sbbc_softstate_t *);
static void	sbbc_remove_instance(sbbc_softstate_t *);
static int	sbbc_find_dip(dev_info_t *, void *);
static void	sbbc_unmap_regs(sbbc_softstate_t *);

/*
 * ops stuff.
 */
static struct cb_ops sbbc_cb_ops = {
	nodev,					/* cb_open */
	nodev,					/* cb_close */
	nodev,					/* cb_strategy */
	nodev,					/* cb_print */
	nodev,					/* cb_dump */
	nodev,					/* cb_read */
	nodev,					/* cb_write */
	nodev,					/* cb_ioctl */
	nodev,					/* cb_devmap */
	nodev,					/* cb_mmap */
	nodev,					/* cb_segmap */
	nochpoll,				/* cb_chpoll */
	ddi_prop_op,				/* cb_prop_op */
	NULL,					/* cb_stream */
	D_NEW | D_MP				/* cb_flag */
};

/*
 * Declare ops vectors for auto configuration.
 */
struct dev_ops  sbbc_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	ddi_getinfo_1to1,	/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	sbbc_attach,		/* devo_attach */
	sbbc_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&sbbc_cb_ops,		/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	nulldev,		/* devo_power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/*
 * Loadable module support.
 */
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* type of module - driver */
	"PCI SBBC",
	&sbbc_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	int    error;

	if ((error = ddi_soft_state_init(&sbbcp,
	    sizeof (sbbc_softstate_t), 1)) != 0)
		return (error);

	if ((error = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&sbbcp);
		return (error);
	}

	/*
	 * Initialise the global 'chosen' IOSRAM mutex
	 */
	mutex_init(&chosen_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Initialise the iosram driver
	 */
	iosram_init();

	/*
	 * Initialize the mailbox
	 */
	sbbc_mbox_init();

	return (error);

}

int
_fini(void)
{
	int    error;

	if ((error = mod_remove(&modlinkage)) == 0)
		ddi_soft_state_fini(&sbbcp);

	master_chosen = FALSE;

	mutex_destroy(&chosen_lock);

	/*
	 * remove the mailbox
	 */
	sbbc_mbox_fini();

	/*
	 * remove the iosram driver
	 */
	iosram_fini();

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
sbbc_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int			instance;
	sbbc_softstate_t	*softsp;
	uint32_t		*pci_intr_enable_reg;
	int			len;
#ifdef	DEBUG
	char			name[8];
#endif	/* DEBUG */

	instance = ddi_get_instance(devi);

	switch (cmd) {
	case DDI_ATTACH:

		if (ddi_soft_state_zalloc(sbbcp, instance) != 0)
			return (DDI_FAILURE);

		softsp = ddi_get_soft_state(sbbcp, instance);
		softsp->sbbc_instance = instance;

		/*
		 * Set the dip in the soft state
		 * And get interrupt cookies and initialize the
		 * per instance mutex.
		 */
		softsp_init(softsp, devi);


		/*
		 * Verify that an 'interrupts' property exists for
		 * this device. If not, this instance will be ignored.
		 */
		if (ddi_getproplen(DDI_DEV_T_ANY, softsp->dip,
		    DDI_PROP_DONTPASS, "interrupts",
		    &len) != DDI_PROP_SUCCESS) {
			SBBC_ERR1(CE_WARN, "No 'interrupts' property for the "
			    "SBBC instance %d\n", instance);
			return (DDI_FAILURE);
		}
		/*
		 * Add this instance to the sbbc chosen iosram list
		 * so that it can be used for tunnel switch.
		 */
		mutex_enter(&chosen_lock);
		softsp->sbbc_state = SBBC_STATE_INIT;
		sbbc_add_instance(softsp);

		/*
		 * If this is the chosen IOSRAM and there is no master IOSRAM
		 * yet, then let's set this instance as the master.
		 * if there is a master alreay due to the previous tunnel switch
		 * then keep as is even though this is the chosen.
		 */
		if (sgsbbc_iosram_is_chosen(softsp)) {
			ASSERT(master_iosram);
			softsp->iosram = master_iosram;
			master_iosram->sgsbbc = softsp;

			/* Do 'chosen' init only */
			sbbc_chosen_init(softsp);
		}

		mutex_exit(&chosen_lock);
#ifdef	DEBUG
		(void) sprintf(name, "sbbc%d", instance);

		if (ddi_create_minor_node(devi, name, S_IFCHR, instance,
		    NULL, NULL) == DDI_FAILURE) {
			mutex_destroy(&softsp->sbbc_lock);
			ddi_remove_minor_node(devi, NULL);
			ddi_soft_state_free(sbbcp, instance);
			return (DDI_FAILURE);
		}
#endif	/* DEBUG */

		ddi_report_dev(devi);

		return (DDI_SUCCESS);

	case DDI_RESUME:

		if (!(softsp = ddi_get_soft_state(sbbcp, instance)))
			return (DDI_FAILURE);

		mutex_enter(&softsp->sbbc_lock);
		if ((softsp->suspended == TRUE) && (softsp->chosen == TRUE)) {
			/*
			 * Enable Interrupts now, turn on both INT#A lines
			 */
			pci_intr_enable_reg =  (uint32_t *)
			    ((char *)softsp->sbbc_regs +
			    SBBC_PCI_INT_ENABLE);

			ddi_put32(softsp->sbbc_reg_handle1,
			    pci_intr_enable_reg,
			    (uint32_t)SBBC_PCI_ENABLE_INT_A);

			/*
			 * Reset intr_in_enabled to the original value
			 * so the SC can send us interrupt.
			 */
			if (iosram_write(SBBC_SC_INTR_ENABLED_KEY,
			    0, (caddr_t)&intr_in_enabled,
			    sizeof (intr_in_enabled))) {

				mutex_exit(&softsp->sbbc_lock);
				return (DDI_FAILURE);
			}
		}
		softsp->suspended = FALSE;

		mutex_exit(&softsp->sbbc_lock);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static int
sbbc_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	sbbc_softstate_t	*softsp;
	int			instance;
	uint32_t		*pci_intr_enable_reg;
	int			rc = DDI_SUCCESS;

	instance = ddi_get_instance(devi);

	if (!(softsp = ddi_get_soft_state(sbbcp, instance)))
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_DETACH:
		mutex_enter(&chosen_lock);
		softsp->sbbc_state |= SBBC_STATE_DETACH;
		mutex_exit(&chosen_lock);

		/* only tunnel switch the instance with iosram chosen */
		if (softsp->chosen == TRUE) {
			if (sgsbbc_iosram_switchfrom(softsp) == DDI_FAILURE) {
				SBBC_ERR(CE_WARN, "Cannot unconfigure: "
				    "tunnel switch failed\n");
				return (DDI_FAILURE);
			}
		}

		/* Adjust linked list */
		mutex_enter(&chosen_lock);
		sbbc_remove_instance(softsp);
		mutex_exit(&chosen_lock);

		sbbc_unmap_regs(softsp);
		mutex_destroy(&softsp->sbbc_lock);
		ddi_soft_state_free(sbbcp, instance);

		return (DDI_SUCCESS);

	case DDI_SUSPEND:

		mutex_enter(&softsp->sbbc_lock);

		if ((softsp->suspended == FALSE) && (softsp->chosen == TRUE)) {
			uint32_t	tmp_intr_enabled = 0;

			/*
			 * Disable Interrupts now, turn OFF both INT#A lines
			 */
			pci_intr_enable_reg =  (uint32_t *)
			    ((char *)softsp->sbbc_regs +
			    SBBC_PCI_INT_ENABLE);

			ddi_put32(softsp->sbbc_reg_handle1,
			    pci_intr_enable_reg, 0);

			/*
			 * Set intr_in_enabled to 0 so the SC won't send
			 * us interrupt.
			 */
			rc = iosram_read(SBBC_SC_INTR_ENABLED_KEY,
			    0, (caddr_t)&intr_in_enabled,
			    sizeof (intr_in_enabled));

			if (rc) {
				mutex_exit(&softsp->sbbc_lock);
				return (DDI_FAILURE);
			}

			rc = iosram_write(SBBC_SC_INTR_ENABLED_KEY,
			    0, (caddr_t)&tmp_intr_enabled,
			    sizeof (tmp_intr_enabled));

			if (rc) {
				mutex_exit(&softsp->sbbc_lock);
				return (DDI_FAILURE);
			}
		}
		softsp->suspended = TRUE;

		mutex_exit(&softsp->sbbc_lock);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

}

static void
softsp_init(sbbc_softstate_t *softsp, dev_info_t *devi)
{
	softsp->dip = devi;

	/*
	 * XXXX
	 * ddi_get_iblock_cookie() here because we need
	 * to initialise the mutex regardless of whether
	 * or not this SBBC will eventually
	 * register an interrupt handler
	 */

	(void) ddi_get_iblock_cookie(devi, 0, &softsp->iblock);

	mutex_init(&softsp->sbbc_lock, NULL, MUTEX_DRIVER,
	    (void *)softsp->iblock);

	softsp->suspended = FALSE;
	softsp->chosen = FALSE;
}

static int
sbbc_find_dip(dev_info_t *dip, void *arg)
{
	char		*node_name;
	sbbc_find_dip_t	*dip_struct = (sbbc_find_dip_t *)arg;
	char		status[OBP_MAXPROPNAME];

	/*
	 * Need to find a node named "bootbus-controller" that is neither
	 * disabled nor failed.  If a node is not ok, there will be an
	 * OBP status property.  Therefore, we will look for a node
	 * without the status property.
	 */
	node_name = ddi_node_name(dip);
	if (strcmp(node_name, "bootbus-controller") == 0 && DDI_CF2(dip) &&
	    (prom_getprop(ddi_get_nodeid(dip),
	    "status", (caddr_t)status) == -1) &&
	    (prom_getprop(ddi_get_nodeid(ddi_get_parent(dip)),
	    "status", (caddr_t)status) == -1)) {

		if (dip != dip_struct->cur_dip) {
			dip_struct->new_dip = (void *)dip;
			return (DDI_WALK_TERMINATE);
		}
	}

	return (DDI_WALK_CONTINUE);
}

/*
 * SBBC Interrupt Handler
 *
 * Check the SBBC Port Interrupt Status
 * register to verify that its our interrupt.
 * If yes, clear the register.
 *
 * Then read the 'interrupt reason' field from SRAM,
 * this triggers the appropriate soft_intr handler
 */
uint_t
sbbc_intr_handler(caddr_t arg)
{
	sbbc_softstate_t	*softsp = (sbbc_softstate_t *)arg;
	uint32_t		*port_int_reg;
	volatile uint32_t	port_int_status;
	volatile uint32_t	intr_reason;
	uint32_t		intr_enabled;
	sbbc_intrs_t		*intr;
	int			i, intr_mask;
	struct tunnel_key	tunnel_key;
	ddi_acc_handle_t	intr_in_handle;
	uint32_t		*intr_in_reason;

	if (softsp == (sbbc_softstate_t *)NULL) {

		return (DDI_INTR_UNCLAIMED);
	}

	mutex_enter(&softsp->sbbc_lock);

	if (softsp->port_int_regs == NULL) {
		mutex_exit(&softsp->sbbc_lock);
		return (DDI_INTR_UNCLAIMED);
	}

	/*
	 * Normally if port_int_status is 0, we assume it is not
	 * our interrupt.  However, we don't want to miss the
	 * ones that come in during tunnel switch.  Therefore,
	 * we always check the interrupt reason bits in IOSRAM
	 * to be sure.
	 */
	port_int_reg = softsp->port_int_regs;

	port_int_status = ddi_get32(softsp->sbbc_reg_handle1, port_int_reg);

	/*
	 * Generate a softint for each interrupt
	 * bit set in the intr_in_reason field in SRAM
	 * that has a corresponding bit set in the
	 * intr_in_enabled field in SRAM
	 */

	if (iosram_read(SBBC_SC_INTR_ENABLED_KEY, 0,
	    (caddr_t)&intr_enabled, sizeof (intr_enabled))) {

		goto intr_handler_exit;
	}

	tunnel_key = master_iosram->tunnel->tunnel_keys[SBBC_SC_INTR_KEY];
	intr_in_reason = (uint32_t *)tunnel_key.base;
	intr_in_handle = tunnel_key.reg_handle;

	intr_reason = ddi_get32(intr_in_handle, intr_in_reason);

	SGSBBC_DBG_INTR(CE_CONT, "intr_reason = %x\n", intr_reason);

	intr_reason &= intr_enabled;

	for (i = 0; i < SBBC_MAX_INTRS; i++) {
		intr_mask = (1 << i);
		if (intr_reason & intr_mask) {
			intr = &softsp->intr_hdlrs[i];
			if ((intr != NULL) &&
			    (intr->sbbc_intr_id != 0)) {
				/*
				 * XXXX
				 * The model we agree with a handler
				 * is that they run until they have
				 * exhausted all work. To avoid
				 * triggering them again, they pass
				 * a state flag and lock when registering.
				 * We check the flag, if they are idle,
				 * we trigger.
				 * The interrupt handler should so
				 *   intr_func()
				 *	mutex_enter(sbbc_intr_lock);
				 *	sbbc_intr_state = RUNNING;
				 *	mutex_exit(sbbc_intr_lock);
				 *	  ..........
				 *	  ..........
				 *	  ..........
				 *	mutex_enter(sbbc_intr_lock);
				 *	sbbc_intr_state = IDLE;
				 *	mutex_exit(sbbc_intr_lock);
				 *
				 * XXXX
				 */
				mutex_enter(intr->sbbc_intr_lock);
				if (*(intr->sbbc_intr_state) ==
				    SBBC_INTR_IDLE) {
					mutex_exit(intr->sbbc_intr_lock);
					ddi_trigger_softintr(
					    intr->sbbc_intr_id);
				} else {
					/*
					 * The handler is running
					 */
					mutex_exit(intr->sbbc_intr_lock);
				}
				intr_reason &= ~intr_mask;
				/*
				 * Clear the corresponding reason bit in SRAM
				 *
				 * Since there is no interlocking between
				 * Solaris and the SC when writing to SRAM,
				 * it is possible for the SC to set another
				 * bit in the interrupt reason field while
				 * we are handling the current interrupt.
				 * To minimize the window in which an
				 * additional bit can be set, reading
				 * and writing the interrupt reason
				 * in SRAM must be as close as possible.
				 */
				ddi_put32(intr_in_handle, intr_in_reason,
				    ddi_get32(intr_in_handle,
				    intr_in_reason) & ~intr_mask);
			}
		}
		if (intr_reason == 0)	/* No more interrupts to be processed */
			break;
	}

	/*
	 * Clear the Interrupt Status Register (RW1C)
	 */
	ddi_put32(softsp->sbbc_reg_handle1, port_int_reg, port_int_status);

	port_int_status = ddi_get32(softsp->sbbc_reg_handle1, port_int_reg);

intr_handler_exit:

	mutex_exit(&softsp->sbbc_lock);

	return (DDI_INTR_CLAIMED);

}

/*
 * If we don't already have a master SBBC selected,
 * get the <sbbc> property from the /chosen node. If
 * the pathname matches, this is the master SBBC and
 * we set up the console/TOD SRAM mapping here.
 */
static void
sbbc_chosen_init(sbbc_softstate_t *softsp)
{
	char		master_sbbc[MAXNAMELEN];
	char		pn[MAXNAMELEN];
	int		nodeid, len;
	pnode_t		dnode;

	if (master_chosen != FALSE) {
		/*
		 * We've got one already
		 */
		return;
	}

	/*
	 * Get /chosen node info. prom interface will handle errors.
	 */
	dnode = prom_chosennode();

	/*
	 * Look for the "iosram" property on the chosen node with a prom
	 * interface as ddi_find_devinfo() couldn't be used (calls
	 * ddi_walk_devs() that creates one extra lock on the device tree).
	 */
	if (prom_getprop(dnode, IOSRAM_CHOSEN_PROP, (caddr_t)&nodeid) <= 0) {
		/*
		 * No I/O Board SBBC set up as console, what to do ?
		 */
		SBBC_ERR(CE_PANIC, "No SBBC found for Console/TOD \n");
	}

	if (prom_getprop(dnode, IOSRAM_TOC_PROP,
	    (caddr_t)&softsp->sram_toc) <= 0) {
		/*
		 * SRAM TOC Offset defaults to 0
		 */
		SBBC_ERR(CE_WARN, "No SBBC TOC Offset found\n");
		softsp->sram_toc = 0;
	}

	/*
	 * get the full OBP pathname of this node
	 */
	if (prom_phandle_to_path((phandle_t)nodeid, master_sbbc,
	    sizeof (master_sbbc)) < 0) {

		SBBC_ERR1(CE_PANIC, "prom_phandle_to_path(%d) failed\n",
		    nodeid);
	}
	SGSBBC_DBG_ALL("chosen pathname : %s\n", master_sbbc);
	SGSBBC_DBG_ALL("device pathname : %s\n", ddi_pathname(softsp->dip, pn));
	if (strcmp(master_sbbc, ddi_pathname(softsp->dip, pn)) == 0) {

		/*
		 * map in the SBBC regs
		 */

		if (sbbc_map_regs(softsp) != DDI_SUCCESS) {
			SBBC_ERR(CE_PANIC, "Can't map the SBBC regs \n");
		}
		/*
		 * Only the 'chosen' node is used for iosram_read()/_write()
		 * Must initialise the tunnel before the console/tod
		 *
		 */
		if (iosram_tunnel_init(softsp) == DDI_FAILURE) {
			SBBC_ERR(CE_PANIC, "Can't create the SRAM <-> SC "
			    "comm. tunnel \n");
		}

		master_chosen = TRUE;

		/*
		 * Verify that an 'interrupts' property
		 * exists for this device
		 */

		if (ddi_getproplen(DDI_DEV_T_ANY, softsp->dip,
		    DDI_PROP_DONTPASS, "interrupts",
		    &len) != DDI_PROP_SUCCESS) {

			SBBC_ERR(CE_PANIC, "No 'interrupts' property for the "
			    "'chosen' SBBC \n");
		}

		/*
		 * add the interrupt handler
		 * NB
		 * should this be a high-level interrupt ?
		 * NB
		 */
		if (sbbc_add_intr(softsp) == DDI_FAILURE) {
			SBBC_ERR(CE_PANIC, "Can't add interrupt handler for "
			    "'chosen' SBBC \n");
		}

		sbbc_enable_intr(softsp);

		/*
		 * Create the mailbox
		 */
		if (sbbc_mbox_create(softsp) != 0) {
			cmn_err(CE_WARN, "No IOSRAM MailBox created!\n");
		}

	}
}
/*
 * sbbc_add_instance
 * Must be called to hold chosen_lock.
 */
static void
sbbc_add_instance(sbbc_softstate_t *softsp)
{
#ifdef DEBUG
	struct  sbbc_softstate *sp;
#endif

	ASSERT(mutex_owned(&chosen_lock));

#if defined(DEBUG)
	/* Verify that this instance is not in the list yet */
	for (sp = sgsbbc_instances; sp != NULL; sp = sp->next) {
		ASSERT(sp != softsp);
	}
#endif

	/*
	 * Add this instance to the front of the list.
	 */
	if (sgsbbc_instances != NULL) {
		sgsbbc_instances->prev = softsp;
	}

	softsp->next = sgsbbc_instances;
	softsp->prev = NULL;
	sgsbbc_instances = softsp;
}

static void
sbbc_remove_instance(sbbc_softstate_t *softsp)
{
	struct sbbc_softstate *sp;

	for (sp = sgsbbc_instances; sp != NULL; sp = sp->next) {
		if (sp == softsp) {
			if (sp->next != NULL) {
				sp->next->prev = sp->prev;
			}
			if (sp->prev != NULL) {
				sp->prev->next = sp->next;
			}
			if (sgsbbc_instances == softsp) {
				sgsbbc_instances = sp->next;
			}
			break;
		}
	}
}

/*
 * Generate an SBBC interrupt to the SC
 * Called from iosram_send_intr()
 *
 * send_intr == 0, check if EPLD register clear
 *	           for sync'ing SC/OS
 * send_intr == 1, send the interrupt
 */
int
sbbc_send_intr(sbbc_softstate_t *softsp, int send_intr)
{

	uchar_t			*epld_int;
	volatile uchar_t 	epld_status;

	ASSERT(MUTEX_HELD(&master_iosram->iosram_lock));

	if ((softsp == (sbbc_softstate_t *)NULL) ||
	    (softsp->epld_regs == (struct sbbc_epld_regs *)NULL))
		return (ENXIO);

	/*
	 * Check the L1 EPLD Interrupt register. If the
	 * interrupt bit is set, theres an interrupt outstanding
	 * (we assume) so return (EBUSY).
	 */

	epld_int = &softsp->epld_regs->epld_reg[EPLD_INTERRUPT];

	epld_status = ddi_get8(softsp->sbbc_reg_handle2, epld_int);

	if (epld_status & INTERRUPT_ON)
		return (EBUSY);

	if (send_intr == TRUE)
		ddi_put8(softsp->sbbc_reg_handle2, epld_int,
		    (epld_status | INTERRUPT_ON));

	return (0);
}

/*
 * Map SBBC Internal registers
 *
 * The call to function should be protected by
 * chosen_lock or master_iosram->iosram_lock
 * to make sure a tunnel switch will not occur
 * in a middle of mapping.
 */
int
sbbc_map_regs(sbbc_softstate_t *softsp)
{
	struct ddi_device_acc_attr attr;

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/*
	 * Map in register set 1, Common Device Regs
	 * SBCC offset 0x0
	 */
	if (ddi_regs_map_setup(softsp->dip, RNUM_SBBC_REGS,
	    (caddr_t *)&softsp->sbbc_regs,
	    SBBC_REGS_OFFSET, SBBC_REGS_SIZE,
	    &attr, &softsp->sbbc_reg_handle1) != DDI_SUCCESS) {

		cmn_err(CE_WARN, "sbbc%d: unable to map interrupt "
		    "registers", ddi_get_instance(softsp->dip));
		return (DDI_FAILURE);
	}
	/*
	 * Map in using register set 1, EPLD
	 * SBCC offset 0xe000
	 */
	if (ddi_regs_map_setup(softsp->dip, RNUM_SBBC_REGS,
	    (caddr_t *)&softsp->epld_regs,
	    SBBC_EPLD_OFFSET, SBBC_EPLD_SIZE,
	    &attr, &softsp->sbbc_reg_handle2) != DDI_SUCCESS) {

		cmn_err(CE_WARN, "sbbc%d: unable to map EPLD "
		    "registers", ddi_get_instance(softsp->dip));
		return (DDI_FAILURE);
	}

	/*
	 * Set up pointers for registers
	 */
	softsp->port_int_regs =  (uint32_t *)((char *)softsp->sbbc_regs +
	    SBBC_PCI_INT_STATUS);

map_regs_exit:
	return (DDI_SUCCESS);
}


/*
 * Unmap SBBC Internal registers
 */
static void
sbbc_unmap_regs(sbbc_softstate_t *softsp)
{
	if (softsp == NULL)
		return;

	mutex_enter(&master_iosram->iosram_lock);

	if (softsp->sbbc_regs) {
		ddi_regs_map_free(&softsp->sbbc_reg_handle1);
		softsp->sbbc_regs = NULL;
		softsp->port_int_regs = NULL;
	}

	if (softsp->epld_regs) {
		ddi_regs_map_free(&softsp->sbbc_reg_handle2);
		softsp->epld_regs = NULL;
	}

	mutex_exit(&master_iosram->iosram_lock);

	return;

}
/*
 * This is here to allow the IOSRAM driver get the softstate
 * for a chosen node when doing a tunnel switch. Just enables
 * us to avoid exporting the sbbcp softstate hook
 */
sbbc_softstate_t *
sbbc_get_soft_state(int instance)
{
	return (ddi_get_soft_state(sbbcp, instance));
}

/*
 * Add interrupt handlers
 */
int
sbbc_add_intr(sbbc_softstate_t *softsp)
{
	int		rc = DDI_SUCCESS;

	/*
	 * map in the SBBC interrupts
	 * Note that the iblock_cookie was initialised
	 * in the 'attach' routine
	 */

	if (ddi_add_intr(softsp->dip, 0, &softsp->iblock,
	    &softsp->idevice, sbbc_intr_handler,
	    (caddr_t)softsp) != DDI_SUCCESS) {

		cmn_err(CE_WARN, "Can't register SBBC "
		    " interrupt handler\n");
		rc = DDI_FAILURE;
	}

	return (rc);
}

void
sbbc_enable_intr(sbbc_softstate_t *softsp)
{
	uint32_t	*pci_intr_enable_reg;

	/*
	 * Enable Interrupts now, turn on both INT#A lines
	 */
	pci_intr_enable_reg =  (uint32_t *)((char *)softsp->sbbc_regs +
	    SBBC_PCI_INT_ENABLE);
	ddi_put32(softsp->sbbc_reg_handle1, pci_intr_enable_reg,
	    (uint32_t)SBBC_PCI_ENABLE_INT_A);
}

void
sbbc_disable_intr(sbbc_softstate_t *softsp)
{
	uint32_t	*pci_intr_enable_reg;

	/*
	 * Disable Interrupts now, turn off both INT#A lines
	 */
	pci_intr_enable_reg =  (uint32_t *)((char *)softsp->sbbc_regs +
	    SBBC_PCI_INT_ENABLE);
	ddi_put32(softsp->sbbc_reg_handle1, pci_intr_enable_reg, 0);
}
