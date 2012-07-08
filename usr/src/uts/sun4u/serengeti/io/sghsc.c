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


/*
 *
 *	Serengeti CompactPCI Hot Swap Controller Driver.
 *
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/cpuvar.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/ksynch.h>
#include <sys/pci.h>
#include <sys/serengeti.h>
#include <sys/sghsc.h>
#include <sys/promif.h>

/*
 * Debug flags
 */

int	sghsc_configure_ack = 0;
int	cpci_enable = 1;
#ifdef	DEBUG
#define	SGHSC_DEBUG
#endif

#ifdef	SGHSC_DEBUG
int	sghsc_debug = 0;
#define	DEBUGF(level, args) \
	{ if (sghsc_debug >= (level)) cmn_err args; }
#define	DEBUGON  sghsc_debug = 3
#define	DEBUGOFF sghsc_debug = 0
#else
#define	DEBUGF(level, args)	/* nothing */
#define	DEBUGON
#define	DEBUGOFF
#endif

/*
 * Global data
 */
static void *sghsc_state;		/* soft state */
static sghsc_rb_head_t sghsc_rb_header;	/* ring buffer header */

/*
 * Definitions for events thread (outside interrupt context), mutex and
 * condition variable.
 */
static kthread_t *sghsc_event_thread;
static kmutex_t sghsc_event_thread_mutex;
static kcondvar_t sghsc_event_thread_cv;
static boolean_t sghsc_event_thread_exit = B_FALSE;

static struct cb_ops sghsc_cb_ops = {
	nodev,			/* open */
	nodev,			/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	nodev,			/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP,		/* Driver compatibility flag */
	CB_REV,			/* rev */
	nodev,			/* int (*cb_aread)() */
	nodev			/* int (*cb_awrite)() */
};

/*
 * Function prototype for dev_ops
 */

static int sghsc_attach(dev_info_t *, ddi_attach_cmd_t);
static int sghsc_detach(dev_info_t *, ddi_detach_cmd_t);

static struct dev_ops sghsc_dev_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	nulldev,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	sghsc_attach,		/* attach */
	sghsc_detach,		/* detach */
	nodev,			/* reset */
	&sghsc_cb_ops,		/* driver operations */
	(struct bus_ops *)0,	/* no bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"Serengeti CompactPCI HSC",
	&sghsc_dev_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/*
 * Function prototype for HP support
 */
static int sghsc_connect(caddr_t, hpc_slot_t slot, void *, uint_t);
static int sghsc_disconnect(caddr_t, hpc_slot_t, void *, uint_t);
static int sghsc_control(caddr_t, hpc_slot_t, int, caddr_t);

/*
 * Function prototypes for internal functions
 */
static int sghsc_register_slots(sghsc_t *, int);
static int sghsc_get_slotnum(sghsc_t *, hpc_slot_t);
static int sghsc_scctl(int, int, int, int, int *);
static void sghsc_freemem(sghsc_t *);
static hpc_slot_t sghsc_find_sloth(int, int, int);
static sghsc_t *sghsc_find_softstate(int, int, int);
static int sghsc_led_state(sghsc_t *, hpc_slot_t, int, hpc_led_info_t *);
static void sghsc_rb_setup(sghsc_rb_head_t *);
static void sghsc_rb_teardown(sghsc_rb_head_t *);
static int sghsc_rb_get(sghsc_rb_head_t *, sghsc_event_t *);
static int sghsc_rb_put(sghsc_rb_head_t *, sghsc_event_t *);

/*
 * Patchable timeout value
 */
int sghsc_mbx_timeout = SGHSC_MBX_TIMEOUT;

/*
 * Data for self-identification. This will help enumerate all soft states.
 */
static int sghsc_maxinst;

/*
 * Six slot boat and four slot boats are different in topology (slot to
 * bus assignment) and here we should have 2 separate maps (the first 3
 * slots have the same topology). The map is in the "delta" form. Logical
 * slots correspond to indexes in the map.
 */
static sdesc_t four_slot_wib_bd[] = {
	0, 6, 1, HPC_SLOT_TYPE_CPCI, /* logical/physical slot 0 - Schizo0/A */
	1, 0, 2, 0,		/* logical/physical slot 1 - paroli2 */
	1, 0, 0, 0,		/* logical/physical slot 2 - paroli0 */
	0, 7, 1, HPC_SLOT_TYPE_CPCI  /* logical/physical slot 3 - Schizo0/B */
};
static sdesc_t four_slot_bd[] = {
	0, 6, 1, HPC_SLOT_TYPE_CPCI, /* logical/physical slot 0 - Schizo0/A */
	1, 6, 1, HPC_SLOT_TYPE_CPCI, /* logical/physical slot 1 - Schizo1/A */
	0, 7, 1, HPC_SLOT_TYPE_CPCI, /* logical/physical slot 2 - Schizo0/B */
	1, 7, 1, HPC_SLOT_TYPE_CPCI  /* logical/physical slot 3 - Schizo1/B */
};
static sdesc_t six_slot_wib_bd[] = {
	0, 6, 1, HPC_SLOT_TYPE_CPCI, /* logical/physical slot 0 - Schizo0/A */
	1, 0, 2, 0,		/* logical/physical slot 1 - paroli2 */
	1, 0, 0, 0,		/* logical/physical slot 2 - paroli0 */
	0, 7, 1, HPC_SLOT_TYPE_CPCI, /* logical/physical slot 3 - Schizo0/B */
	0, 7, 2, HPC_SLOT_TYPE_CPCI, /* logical/physical slot 4 - Schizo0/B */
	0, 7, 3, HPC_SLOT_TYPE_CPCI  /* logical/physical slot 5 - Schizo0/B */
};
static sdesc_t six_slot_bd[] = {
	0, 6, 1, HPC_SLOT_TYPE_CPCI, /* logical/physical slot 0 - Schizo0/A */
	1, 6, 1, HPC_SLOT_TYPE_CPCI, /* logical/physical slot 1 - Schizo1/A */
	0, 7, 1, HPC_SLOT_TYPE_CPCI, /* logical/physical slot 2 - Schizo0/B */
	0, 7, 2, HPC_SLOT_TYPE_CPCI, /* logical/physical slot 3 - Schizo0/B */
	1, 7, 1, HPC_SLOT_TYPE_CPCI, /* logical/physical slot 4 - Schizo1/B */
	1, 7, 2, HPC_SLOT_TYPE_CPCI  /* logical/physical slot 5 - Schizo1/B */
};

/*
 * DR event handlers
 * We want to register the event handlers once for all instances. In the
 * other hand we have register them after the sghsc has been attached.
 * event_initialize gives us the logic of only registering the events only
 * once. The event thread will do all the work when called from interrupts.
 */
int sghsc_event_init = 0;
static uint_t sghsc_event_handler(char *);
static void sghsc_event_thread_code(void);

/*
 * DR event msg and payload
 */
static sbbc_msg_t event_msg;
static sghsc_event_t payload;

/*
 * Event lock and state
 */
static kmutex_t sghsc_event_lock;
int sghsc_event_state;

int
_init(void)
{
	int error;

	sghsc_maxinst = 0;

	if ((error = ddi_soft_state_init(&sghsc_state,
	    sizeof (sghsc_t), 1)) != 0)
		return (error);

	if ((error = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&sghsc_state);
		return (error);
	}

	sghsc_rb_header.buf = NULL;

	mutex_init(&sghsc_event_thread_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&sghsc_event_thread_cv, NULL, CV_DRIVER, NULL);

	return (error);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) != 0)
		return (error);
	/*
	 * Unregister the event handler
	 */
	(void) sbbc_mbox_unreg_intr(MBOX_EVENT_CPCI_ENUM, sghsc_event_handler);
	mutex_destroy(&sghsc_event_lock);

	/*
	 * Kill the event thread if it is running.
	 */
	if (sghsc_event_thread != NULL) {
		mutex_enter(&sghsc_event_thread_mutex);
		sghsc_event_thread_exit = B_TRUE;
		/*
		 * Goes to the thread at once.
		 */
		cv_signal(&sghsc_event_thread_cv);
		/*
		 * Waiting for the response from the thread.
		 */
		cv_wait(&sghsc_event_thread_cv, &sghsc_event_thread_mutex);
		mutex_exit(&sghsc_event_thread_mutex);
		sghsc_event_thread = NULL;
	}
	mutex_destroy(&sghsc_event_thread_mutex);
	cv_destroy(&sghsc_event_thread_cv);

	/*
	 * tear down shared, global ring buffer now that it is safe to
	 * do so because sghsc_event_handler has been unregistered and
	 * sghsc_event_thread_code has exited
	 */
	sghsc_rb_teardown(&sghsc_rb_header);

	sghsc_maxinst = 0;
	ddi_soft_state_fini(&sghsc_state);

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * sghsc_attach()
 */
/* ARGSUSED */
static int
sghsc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	sghsc_t *sghsc;
	uint_t instance;
	uint_t portid;
	int rc;
	int board_type = 0;

	instance = ddi_get_instance(dip);

	switch (cmd) {
		case DDI_RESUME:
			return (DDI_SUCCESS);

		case DDI_ATTACH:
			break;
		default:
			cmn_err(CE_WARN, "sghsc%d: unsupported cmd %d",
			    instance, cmd);
			return (DDI_FAILURE);
	}

	DEBUGF(1, (CE_NOTE, "attach sghsc driver. "));

	/* Fetch Safari Extended Agent ID of this device. */
	portid = (uint_t)ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "portid", -1);

	if (!SG_PORTID_IS_IO_TYPE(portid)) {
		cmn_err(CE_WARN, "sghsc%d: property %s out of bounds %d\n",
		    instance, "portid", portid);
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(sghsc_state, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	sghsc = (sghsc_t *)ddi_get_soft_state(sghsc_state, instance);

	sghsc->sghsc_dip = dip;
	sghsc->sghsc_instance = instance;
	sghsc->sghsc_board = SG_PORTID_TO_BOARD_NUM(portid);
	sghsc->sghsc_node_id = SG_PORTID_TO_NODEID(portid);
	sghsc->sghsc_portid = portid;

	ddi_set_driver_private(dip, sghsc);

	mutex_init(SGHSC_MUTEX(sghsc), NULL, MUTEX_DRIVER, NULL);

	rc = sghsc_scctl(SGHSC_GET_NUM_SLOTS, sghsc->sghsc_node_id,
	    sghsc->sghsc_board, 0, (int *)&sghsc->sghsc_num_slots);

	if (rc) {
		cmn_err(CE_WARN, "sghsc%d: unable to size node %d / board %d",
		    instance, sghsc->sghsc_node_id, sghsc->sghsc_board);
		goto cleanup_stage2;
	}

	DEBUGF(1, (CE_NOTE, "sghsc%d: node %d / board %d  has %d slots",
	    instance, sghsc->sghsc_node_id, sghsc->sghsc_board,
	    sghsc->sghsc_num_slots));

	switch (sghsc->sghsc_num_slots) {
		case 4:
		case 6:
			rc = 0;
			break;
		default:
			rc = -1;
			break;
	}

	if (rc) {
		cmn_err(CE_WARN, "sghsc%d: wrong num of slots %d for node %d"
		    " / board %d", instance, sghsc->sghsc_num_slots,
		    sghsc->sghsc_node_id, sghsc->sghsc_board);
		goto cleanup_stage2;
	}

	rc = sghsc_scctl(SGHSC_GET_CPCI_BOARD_TYPE, sghsc->sghsc_node_id,
	    sghsc->sghsc_board, 0, &board_type);

	DEBUGF(1, (CE_NOTE, "sghsc%d: node %d / board %d is type %d",
	    instance, sghsc->sghsc_node_id, sghsc->sghsc_board, board_type));

	sghsc->sghsc_slot_table = (sghsc_slot_t *)kmem_zalloc((size_t)
	    (sghsc->sghsc_num_slots * sizeof (sghsc_slot_t)), KM_SLEEP);


	if (sghsc_register_slots(sghsc, board_type) != DDI_SUCCESS) {
		DEBUGF(1, (CE_NOTE, "sghsc%d: sghsc_register_slots"
		    " failed for node %d / board %d",
		    instance, sghsc->sghsc_node_id, sghsc->sghsc_board));
		goto cleanup;
	}

	if (sghsc_connect((caddr_t)sghsc, 0, 0, SGHSC_ALL_SLOTS_ENABLE)
	    != HPC_SUCCESS) {
		DEBUGF(1, (CE_NOTE, "sghsc%d: sghsc_connect failed for"
		    " node %d / board %d", instance, sghsc->sghsc_node_id,
		    sghsc->sghsc_board));
		goto cleanup;
	}


	if (sghsc_event_init == 0) {

		/*
		 * allocate shared, global ring buffer before registering
		 * sghsc_event_handler and before starting
		 * sghsc_event_thread_code
		 */
		sghsc_rb_setup(&sghsc_rb_header);

		/*
		 * Regiter cpci DR event handler
		 *
		 */
		mutex_init(&sghsc_event_lock,  NULL, MUTEX_DRIVER, NULL);
		event_msg.msg_buf = (caddr_t)&payload;
		event_msg.msg_len = sizeof (payload);
		rc = sbbc_mbox_reg_intr(MBOX_EVENT_CPCI_ENUM,
		    sghsc_event_handler, &event_msg,
		    (uint_t *)&sghsc_event_state, &sghsc_event_lock);

		if (rc != 0)
			cmn_err(CE_WARN, "sghsc%d: failed to register events"
			    " for node %d", instance, sghsc->sghsc_node_id);

		sghsc_event_init = 1;

		/*
		 * Create the event thread if it is not already created.
		 */
		if (sghsc_event_thread == NULL) {
			DEBUGF(1, (CE_NOTE, "sghsc: creating event thread"
			    "for node %d", sghsc->sghsc_node_id));
			sghsc_event_thread = thread_create(NULL, 0,
			    sghsc_event_thread_code, NULL, 0, &p0,
			    TS_RUN, minclsyspri);
		}
	}

	ddi_report_dev(dip);

	/*
	 * Grossly bump up the instance counter. We may have holes inside.
	 */
	sghsc_maxinst++;
	sghsc->sghsc_valid = 1;

	return (DDI_SUCCESS);

cleanup:
	/*
	 * Free up allocated resources and return error
	 * sghsc_register_slots => unregister all slots
	 */
	sghsc_freemem(sghsc);

cleanup_stage2:
	DEBUGF(1, (CE_NOTE, "sghsc%d: attach failed for node %d",
	    instance, sghsc->sghsc_node_id));
	mutex_destroy(SGHSC_MUTEX(sghsc));
	ddi_set_driver_private(dip, NULL);
	ddi_soft_state_free(sghsc_state, instance);
	return (DDI_FAILURE);
}

/*
 * detach(9E)
 */
/* ARGSUSED */
static int
sghsc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	sghsc_t *sghsc;
	int instance;
	int i;

	instance = ddi_get_instance(dip);
	sghsc = (sghsc_t *)ddi_get_soft_state(sghsc_state, instance);

	if (sghsc == NULL)
		return (DDI_FAILURE);

	switch (cmd) {
		case DDI_DETACH:
		/*
		 * We don't allow to detach in case the pci nexus
		 * didn't run pcihp_uninit(). The buses should be
		 * unregistered by now, otherwise slot info will be
		 * corrupted on the next 'cfgadm'.
		 */
		for (i = 0; i < sghsc->sghsc_num_slots; i++) {
			if (sghsc->sghsc_slot_table[i].handle &&
			    hpc_bus_registered(
			    sghsc->sghsc_slot_table[i].handle)) {
				cmn_err(CE_WARN,
				    "sghsc: must detach buses first");
				return (DDI_FAILURE);
			}
		}

		if (mutex_tryenter(&sghsc_event_thread_mutex) == 0)
			return (EBUSY);

		sghsc->sghsc_valid = 0;
		sghsc_freemem(sghsc);
		mutex_destroy(SGHSC_MUTEX(sghsc));
		ddi_set_driver_private(dip, NULL);
		ddi_soft_state_free(sghsc_state, instance);

		/*
		 * Grossly decrement the counter. We may have holes inside.
		 */
		if (instance == (sghsc_maxinst - 1))
			sghsc_maxinst--;
		mutex_exit(&sghsc_event_thread_mutex);
		return (DDI_SUCCESS);

		case DDI_SUSPEND:
		return (DDI_SUCCESS);

		default:
		return (DDI_FAILURE);
	}
}


/*
 * Set up and register slot 0 to num_slots with hotplug
 *     framework
 * 	Assume SGHSC_MUTEX is held
 *
 * Return val: DDI_SUCCESS
 *	       DDI_FAILURE
 */
static int
sghsc_register_slots(sghsc_t *sghsc, int board_type)
{
	int  i;
	dev_info_t	*dip = sghsc->sghsc_dip;
	hpc_slot_ops_t	*slot_ops = NULL;
	sdesc_t 	*slot2bus;


	DEBUGF(1, (CE_NOTE, "sghsc%d: slot table has %d entries for "
	    "node %d / board %d", sghsc->sghsc_instance, sghsc->sghsc_num_slots,
	    sghsc->sghsc_node_id, sghsc->sghsc_board));

	if ((cpci_enable == 0) || (sg_prom_cpci_dr_check() != 0))
		return (DDI_SUCCESS);

	if (sghsc->sghsc_slot_table == NULL)
		return (DDI_FAILURE);

	switch (board_type) {
		/*
		 * If the GET_CPCI_BOARD_TYPE request failed, board type
		 * will be NO_BOARD_TYPE.  In that case, assume it is an
		 * io boat and make board type determination based on the
		 * number of slots.
		 */
		case NO_BOARD_TYPE:
		case CPCI_BOARD:
		case SP_CPCI_BOARD:
			switch (sghsc->sghsc_num_slots) {
			case 4:
				slot2bus = four_slot_bd;
				break;
			case 6:
				slot2bus = six_slot_bd;
				break;
			default:
				cmn_err(CE_WARN, "sghsc%d: unknown size %d for"
				    " node %d / board %d",
				    sghsc->sghsc_instance,
				    sghsc->sghsc_num_slots,
				    sghsc->sghsc_node_id, sghsc->sghsc_board);
				break;
			}
			break;
		case WCI_CPCI_BOARD:
			slot2bus = four_slot_wib_bd;
			break;
		case WCI_SP_CPCI_BOARD:
			slot2bus = six_slot_wib_bd;
			break;
		default:
			cmn_err(CE_WARN, "sghsc%d: unknown type %d  for"
			    " node %d / board %d", sghsc->sghsc_instance,
			    board_type, sghsc->sghsc_node_id,
			    sghsc->sghsc_board);
			return (DDI_FAILURE);
	}

	/*
	 * constructing the slot table array and register the
	 * slot with the HPS
	 * we don't depend on the .conf file
	 */
	for (i = 0; i < sghsc->sghsc_num_slots; i++) {
		char	*nexuspath;
		hpc_slot_info_t  *slot_info;
		uint32_t base_id;

		/*
		 * Some kind of black list may be needed
		 */

		/*
		 * Need to talk to SC and get slot info and set slot state:
		 * 1. slot status
		 * 2. slot capabilities
		 * 3. LED status
		 * 4. get bus num
		 */

		/*
		 * fill up nexuspath, extended id is used instead of the
		 * local one, the node id is encoded in the path twice.
		 */
		base_id = sghsc->sghsc_portid & SGHSC_SAFARI_ID_EVEN;
		nexuspath = sghsc->sghsc_slot_table[i].nexus_path;

		(void) sprintf(nexuspath, SGHSC_PATH, sghsc->sghsc_node_id,
		    (base_id + slot2bus[i].agent_delta), slot2bus[i].off);
		sghsc->sghsc_slot_table[i].pci_device_num =
		    slot2bus[i].pcidev;

		/*
		 * fill up slot_info
		 */
		slot_info = &sghsc->sghsc_slot_table[i].slot_info;

		slot_info->version = HPC_SLOT_INFO_VERSION;
		slot_info->slot_type = slot2bus[i].slot_type;
		/* capabilities need to be discovered via SC */
		slot_info->pci_slot_capabilities = HPC_SLOT_64BITS;
		slot_info->pci_dev_num = slot2bus[i].pcidev;

		(void) sprintf(slot_info->pci_slot_name,
		    "sg%dslot%d", sghsc->sghsc_board, i);
		DEBUGF(1, (CE_NOTE, "pci_slot_name is %s at pci_dev_num %d"
		    " on node %d / board %d", slot_info->pci_slot_name,
		    slot_info->pci_dev_num, sghsc->sghsc_node_id,
		    sghsc->sghsc_board));

		/*
		 * allocate and fill up slot_ops
		 */
		slot_ops = hpc_alloc_slot_ops(KM_SLEEP);
		sghsc->sghsc_slot_table[i].slot_ops = slot_ops;

		/* assign slot ops for HPS */
		slot_ops->hpc_version = HPC_SLOT_OPS_VERSION;
		slot_ops->hpc_op_connect = sghsc_connect;
		slot_ops->hpc_op_disconnect = sghsc_disconnect;
		slot_ops->hpc_op_insert = nodev;
		slot_ops->hpc_op_remove = nodev;
		slot_ops->hpc_op_control = sghsc_control;

		/*
		 * HA (Full Hot Swap) is the default mode of operation
		 * but the type of the board is set conservstively as
		 * sghsc has no way of knowing it. The HP Framwork will
		 * overwrite the value set at boot time.
		 */
		sghsc->sghsc_slot_table[i].flags = SGHSC_SLOT_AUTO_CFG_EN;
		sghsc->sghsc_slot_table[i].board_type = HPC_BOARD_UNKNOWN;

		/* Only register CPCI slots */
		if (slot_info->slot_type != HPC_SLOT_TYPE_CPCI) {
			DEBUGF(1, (CE_NOTE, "sghsc_register_slots: "
			    "slot %d is non-cpci", i));
			continue;
		}

		/*
		 *  register slots
		 */
		if ((hpc_slot_register(dip, nexuspath, slot_info,
		    &sghsc->sghsc_slot_table[i].handle,
		    slot_ops, (caddr_t)sghsc, 0)) != 0) {

			/*
			 * return failure and let attach()
			 * do the cleanup
			 */
			cmn_err(CE_WARN, "sghsc%d: Slot <%s> failed during HPS"
			    " registration process for node %d / board %d",
			    sghsc->sghsc_instance, slot_info->pci_slot_name,
			    sghsc->sghsc_node_id, sghsc->sghsc_board);
			return (DDI_FAILURE);
		}

	}
	DEBUGF(1, (CE_NOTE, "sghsc registered successfully for"
	    " node %d / board %d", sghsc->sghsc_node_id, sghsc->sghsc_board));
	return (DDI_SUCCESS);
}

/*
 * Connecting a slot or all slots
 *	State Diagram:
 *	     states
 *	hw bits		EMPTY	DISCONNECT	CONNECT
 *	slot_enable	 NO	   NO		  YES
 *	card_present	 NO	   YES		  YES
 *	slot_switch	 N/A	   NO/YES	  YES
 *
 * Return val:	HPC_SUCCESS if the slot(s) are enabled
 * 		HPC_ERR_FAILED if the slot can't be enabled
 */
/* ARGSUSED */
static int
sghsc_connect(caddr_t op_arg, hpc_slot_t sloth, void *data,
    uint_t flag)
{
	int i = 0;
	sghsc_t *sghsc = (sghsc_t *)op_arg;
	int rc;
	int result;
	int	slot_num = sghsc_get_slotnum(sghsc, sloth);

	switch (flag) {

		case SGHSC_ALL_SLOTS_ENABLE:
		for (i = 0; i < sghsc->sghsc_num_slots; i++) {
			/*
			 * All slots will be marked 'empty' as HP Framework
			 * will try to connect those which have no kernel node.
			 */
			sghsc->sghsc_slot_table[i].slot_status =
			    HPC_SLOT_EMPTY;
		}

		return (HPC_SUCCESS);
	}

	if (slot_num == -1)
		return (HPC_ERR_INVALID);

	SGHSC_MUTEX_ENTER(sghsc);

	DEBUGF(1, (CE_NOTE, "sghsc%d: connecting logical slot%d for"
	    " node %d / board %d", sghsc->sghsc_instance, slot_num,
	    sghsc->sghsc_node_id, sghsc->sghsc_board));

	/*
	 * Powering an empty slot is highly illegal so far
	 * (before SC implemented a constant poll). Otherwise
	 * it breaks ddi framework and HP. The workaround
	 * is to check for a card first.
	 */
	rc = sghsc_scctl(SGHSC_GET_SLOT_STATUS, sghsc->sghsc_node_id,
	    sghsc->sghsc_board, slot_num, &result);

	if (rc == ETIMEDOUT) {
		SGHSC_MUTEX_EXIT(sghsc);
		return (HPC_ERR_FAILED);
	}

	if (rc) {
		cmn_err(CE_NOTE, "sghsc%d: unable to stat slot %d for"
		    " node %d / board %d", sghsc->sghsc_instance, slot_num,
		    sghsc->sghsc_node_id, sghsc->sghsc_board);
		sghsc->sghsc_slot_table[i].slot_status = HPC_SLOT_UNKNOWN;
		SGHSC_MUTEX_EXIT(sghsc);
		return (HPC_ERR_FAILED);
	}


	if ((result >> CPCI_STAT_SLOT_EMPTY_SHIFT) & ONE_BIT) {
		sghsc->sghsc_slot_table[i].slot_status = HPC_SLOT_EMPTY;
		SGHSC_MUTEX_EXIT(sghsc);
		return (HPC_ERR_FAILED);
	}

	rc = sghsc_scctl(SGHSC_SET_SLOT_POWER_ON, sghsc->sghsc_node_id,
	    sghsc->sghsc_board, slot_num, &result);
	if (rc) {
		cmn_err(CE_WARN, "sghsc%d: unable to poweron slot %d for"
		    " node %d / board %d", sghsc->sghsc_instance,
		    slot_num, sghsc->sghsc_node_id, sghsc->sghsc_board);
		SGHSC_MUTEX_EXIT(sghsc);
		return (HPC_ERR_FAILED);
	} else {
		sghsc->sghsc_slot_table[slot_num].slot_status =
		    HPC_SLOT_CONNECTED;
	}

	SGHSC_MUTEX_EXIT(sghsc);

	return (HPC_SUCCESS);
}


/*
 * Disconnecting a slot or slots
 *
 * return:  HPC_SUCCESS if slot(s) are successfully disconnected
 *          HPC_ERR_FAILED if slot(s) can't be disconnected
 *
 */
/* ARGSUSED */
static int
sghsc_disconnect(caddr_t op_arg, hpc_slot_t sloth, void *data,
    uint_t flag)
{
	sghsc_t *sghsc = (sghsc_t *)op_arg;
	int rc;
	int result;
	int slot_num = sghsc_get_slotnum(sghsc, sloth);

	switch (flag) {
		case SGHSC_ALL_SLOTS_DISABLE:
		return (HPC_SUCCESS);

	}

	if (slot_num == -1)
		return (HPC_ERR_INVALID);

	SGHSC_MUTEX_ENTER(sghsc);

	/*
	 * Disconnecting an empty or disconnected slot
	 * does't make sense.
	 */
	if (sghsc->sghsc_slot_table[slot_num].slot_status !=
	    HPC_SLOT_CONNECTED) {
		SGHSC_MUTEX_EXIT(sghsc);
		return (HPC_SUCCESS);
	}

	rc = sghsc_scctl(SGHSC_SET_SLOT_POWER_OFF, sghsc->sghsc_node_id,
	    sghsc->sghsc_board, slot_num, &result);
	if (rc) {
		cmn_err(CE_WARN, "sghsc%d: unable to poweroff slot %d for"
		    " node %d / board %d", sghsc->sghsc_instance,
		    slot_num, sghsc->sghsc_node_id, sghsc->sghsc_board);
		SGHSC_MUTEX_EXIT(sghsc);
		return (HPC_ERR_FAILED);
	} else {
		sghsc->sghsc_slot_table[slot_num].slot_status =
		    HPC_SLOT_DISCONNECTED;
	}

	SGHSC_MUTEX_EXIT(sghsc);

	return (HPC_SUCCESS);
}

/*
 * Entry point from the hotplug framework to do
 *   the main hotplug operations
 * Return val:	HPC_SUCCESS  success on ops
 *		HPC_NOT_SUPPORTED not supported feature
 *		HPC_ERR_FAILED	ops failed
 */
/*ARGSUSED*/
static int
sghsc_control(caddr_t op_arg, hpc_slot_t sloth, int request,
    caddr_t arg)
{
	sghsc_t *sghsc = (sghsc_t *)op_arg;
	int slot = sghsc_get_slotnum(sghsc, sloth);
	int error = HPC_SUCCESS;
	int rc;
	int result;

	if ((sghsc == NULL) || (slot < 0) ||
	    (slot >= sghsc->sghsc_num_slots)) {
		cmn_err(CE_WARN, "sghsc%d: sghsc_control fails with slot = %d"
		    " max = %d, sloth = 0x%p for node %d / board %d",
		    sghsc->sghsc_instance, slot, sghsc->sghsc_num_slots,
		    sloth, sghsc->sghsc_node_id, sghsc->sghsc_board);
		return (HPC_ERR_INVALID);
	}

	SGHSC_MUTEX_ENTER(sghsc);

	switch (request) {
	case HPC_CTRL_GET_LED_STATE: {
		/* arg == hpc_led_info_t */

		hpc_led_info_t *ledinfo;

		ledinfo = (hpc_led_info_t *)arg;

		DEBUGF(1, (CE_NOTE, "sghsc%d: sghsc_control"
		    " HPC_CTRL_GET_LED_STATE for node %d / board %d slot %d",
		    sghsc->sghsc_instance, sghsc->sghsc_node_id,
		    sghsc->sghsc_board, slot));

		switch (ledinfo->led) {
		case HPC_POWER_LED:
		case HPC_ATTN_LED:
		case HPC_FAULT_LED:
		case HPC_ACTIVE_LED:
			error = sghsc_led_state(sghsc, sloth,
			    HPC_CTRL_GET_LED_STATE, ledinfo);
			break;
		default:
			cmn_err(CE_WARN, "sghsc%d: sghsc_control"
			    " HPC_CTRL_GET_LED_STATE "
			    " unknown led state %d for node %d / board %d"
			    " slot handle 0x%p", sghsc->sghsc_instance,
			    ledinfo->led, sghsc->sghsc_node_id,
			    sghsc->sghsc_board, sloth);
			error = HPC_ERR_NOTSUPPORTED;
			break;
		}

		break;
	}

	case HPC_CTRL_SET_LED_STATE: {
		/* arg == hpc_led_info_t */
		hpc_led_info_t *ledinfo;

		ledinfo = (hpc_led_info_t *)arg;

		DEBUGF(1, (CE_NOTE, "sghsc%d: sghsc_control"
		    " HPC_CTRL_SET_LED_STATE for node %d / board %d slot %d",
		    sghsc->sghsc_instance, sghsc->sghsc_node_id,
		    sghsc->sghsc_board, slot));

		switch (ledinfo->led) {
		case HPC_POWER_LED:
		case HPC_ATTN_LED:
		case HPC_FAULT_LED:
		case HPC_ACTIVE_LED:
			DEBUGF(1, (CE_NOTE, "sghsc:"
			    " LED writing not supported "));
			break;

		default:
			DEBUGF(1, (CE_NOTE, "sghsc:"
			    " LED not supported "));
			error = HPC_ERR_NOTSUPPORTED;
		}
		break;
	}

	case HPC_CTRL_GET_SLOT_STATE: {
		DEBUGF(1, (CE_NOTE, "sghsc%d: sghsc_control"
		    " HPC_CTRL_GET_SLOT_STATE for node %d / board %d slot %d",
		    sghsc->sghsc_instance, sghsc->sghsc_node_id,
		    sghsc->sghsc_board, slot));

		/*
		 * Send mailbox cmd to SC to query the latest state
		 */
		rc = sghsc_scctl(SGHSC_GET_SLOT_STATUS, sghsc->sghsc_node_id,
		    sghsc->sghsc_board, slot, &result);

		if (rc == ETIMEDOUT) {
			error = HPC_ERR_FAILED;
			break;
		}

		if (rc) {
			cmn_err(CE_NOTE, "sghsc%d: unable to stat slot %d for "
			    "node %d / board %d", sghsc->sghsc_instance, slot,
			    sghsc->sghsc_node_id, sghsc->sghsc_board);
			sghsc->sghsc_slot_table[slot].slot_status =
			    HPC_SLOT_UNKNOWN;
			*(hpc_slot_state_t *)arg = HPC_SLOT_UNKNOWN;
			break;
		}

		/*
		 * Update the cached state if needed. Initally all
		 * slots are marked as empty for the Hot Plug Framwork.
		 */
		if ((result >> CPCI_STAT_SLOT_EMPTY_SHIFT) & ONE_BIT) {
			sghsc->sghsc_slot_table[slot].slot_status =
			    HPC_SLOT_EMPTY;
		} else if ((result >> CPCI_STAT_POWER_ON_SHIFT) & ONE_BIT) {
			sghsc->sghsc_slot_table[slot].slot_status =
			    HPC_SLOT_CONNECTED;
		} else if (sghsc->sghsc_slot_table[slot].slot_status ==
		    HPC_SLOT_EMPTY ||
		    sghsc->sghsc_slot_table[slot].slot_status ==
		    HPC_SLOT_UNKNOWN) {
			sghsc->sghsc_slot_table[slot].slot_status =
			    HPC_SLOT_DISCONNECTED;
		}
		/*
		 * No change
		 */
		*(hpc_slot_state_t *)arg =
		    sghsc->sghsc_slot_table[slot].slot_status;

		break;
	}

	case HPC_CTRL_DEV_CONFIGURED:
		DEBUGF(1, (CE_NOTE, "sghsc%d: sghsc_control"
		    " HPC_CTRL_DEV_CONFIGURED for node %d / board %d slot %d",
		    sghsc->sghsc_instance, sghsc->sghsc_node_id,
		    sghsc->sghsc_board, slot));

		if (sghsc_configure_ack)
			cmn_err(CE_NOTE, "sghsc%d:"
			    " node %d / board %d slot %d configured",
			    sghsc->sghsc_instance, sghsc->sghsc_node_id,
			    sghsc->sghsc_board, slot);
		/*
		 * This is important to tell SC:
		 * "start looking for ENUMs"
		 */
		if (sghsc->sghsc_slot_table[slot].flags &
		    SGHSC_SLOT_AUTO_CFG_EN)
			(void) sghsc_scctl(SGHSC_SET_ENUM_CLEARED,
			    sghsc->sghsc_node_id, sghsc->sghsc_board,
			    slot, &result);

		break;

	case HPC_CTRL_DEV_UNCONFIGURED:
		/*
		 * due to unclean drivers, unconfigure may leave
		 * some state on card, configure may actually
		 * use these invalid values. therefore, may force
		 * disconnect.
		 */

		DEBUGF(1, (CE_NOTE, "sghsc%d: sghsc_control "
		    "HPC_CTRL_DEV_UNCONFIGURED for node %d / board %d slot %d",
		    sghsc->sghsc_instance, sghsc->sghsc_node_id,
		    sghsc->sghsc_board, slot));

		SGHSC_MUTEX_EXIT(sghsc);
		if (sghsc_disconnect(op_arg, sloth, 0,
		    0) != HPC_SUCCESS) {
			DEBUGF(1, (CE_NOTE, "sghsc_control: "
			    "disconnect failed"));
			error = HPC_ERR_FAILED;
		}

		cmn_err(CE_NOTE, "sghsc%d: node %d / board %d "
		    "slot %d unconfigured", sghsc->sghsc_instance,
		    sghsc->sghsc_node_id, sghsc->sghsc_board, slot);
		return (error);


	case HPC_CTRL_GET_BOARD_TYPE: {
		/* arg = hpc_board_type_t */

		DEBUGF(1, (CE_NOTE, "sghsc%d: sghsc_control"
		    " HPC_CTRL_GET_BOARD_TYPE for node %d / board %d slot %d",
		    sghsc->sghsc_instance, sghsc->sghsc_node_id,
		    sghsc->sghsc_board, slot));

		*(hpc_board_type_t *)arg =
		    sghsc->sghsc_slot_table[slot].board_type;

		break;
	}

	case HPC_CTRL_ENABLE_AUTOCFG:
		DEBUGF(1, (CE_NOTE, "sghsc%d: sghsc_control"
		    " HPC_CTRL_ENABLE_AUTOCFG for node %d / board %d slot %d",
		    sghsc->sghsc_instance, sghsc->sghsc_node_id,
		    sghsc->sghsc_board, slot));

		sghsc->sghsc_slot_table[slot].flags |= SGHSC_SLOT_AUTO_CFG_EN;
		(void) hpc_slot_event_notify(sloth, HPC_EVENT_ENABLE_ENUM,
		    HPC_EVENT_NORMAL);

		/*
		 * Tell SC to start looking for ENUMs on this slot.
		 */
		rc = sghsc_scctl(SGHSC_SET_ENUM_CLEARED, sghsc->sghsc_node_id,
		    sghsc->sghsc_board, slot, &result);

		if (rc)
			cmn_err(CE_WARN, "sghsc%d: unable to arm ENUM for"
			    " node %d / board %d, slot %d",
			    sghsc->sghsc_instance, sghsc->sghsc_node_id,
			    sghsc->sghsc_board, slot);
		break;

	case HPC_CTRL_DISABLE_AUTOCFG:
		DEBUGF(1, (CE_NOTE, "sghsc%d: sghsc_control"
		    " HPC_CTRL_DISABLE_AUTOCFG for node %d / board %d slot %d",
		    sghsc->sghsc_instance, sghsc->sghsc_node_id,
		    sghsc->sghsc_board, slot));

		sghsc->sghsc_slot_table[slot].flags &= ~SGHSC_SLOT_AUTO_CFG_EN;
		(void) hpc_slot_event_notify(sloth, HPC_EVENT_DISABLE_ENUM,
		    HPC_EVENT_NORMAL);
		break;

	case HPC_CTRL_DISABLE_SLOT:
	case HPC_CTRL_ENABLE_SLOT:
		break;

	/*  need to add support for enable/disable_ENUM */
	case HPC_CTRL_DISABLE_ENUM:
	case HPC_CTRL_ENABLE_ENUM:
	default:
		DEBUGF(1, (CE_CONT, "sghsc%d: sghsc_control "
		    "request (0x%x) not supported", sghsc->sghsc_instance,
		    request));

		/* invalid request */
		error = HPC_ERR_NOTSUPPORTED;
	}

	SGHSC_MUTEX_EXIT(sghsc);

	return (error);
}

/*
 * Read/write slot's led
 *	Assume MUTEX_HELD
 *
 * return:  HPC_SUCCESS if the led's status is avaiable,
 *          SC return status otherwise.
 */
static int
sghsc_led_state(sghsc_t *sghsc, hpc_slot_t sloth, int op,
    hpc_led_info_t *ledinfo)
{
	int rval;
	int slot_num;
	int result;

	slot_num = sghsc_get_slotnum(sghsc, sloth);
	rval = sghsc_scctl(SGHSC_GET_SLOT_STATUS, sghsc->sghsc_node_id,
	    sghsc->sghsc_board, slot_num, &result);
	if (rval != HPC_SUCCESS)
		return (rval);

	switch (op) {
	case HPC_CTRL_GET_LED_STATE:
		switch (ledinfo->led) {
		case HPC_POWER_LED:
			if ((result >> CPCI_STAT_LED_POWER_SHIFT) & ONE_BIT)
				ledinfo->state = HPC_LED_ON;
			else
				ledinfo->state = HPC_LED_OFF;
			break;

		case HPC_ATTN_LED:
		case HPC_FAULT_LED:
			if ((result >> CPCI_STAT_LED_FAULT_SHIFT) & ONE_BIT)
				ledinfo->state = HPC_LED_ON;
			else
				ledinfo->state = HPC_LED_OFF;
			break;

		case HPC_ACTIVE_LED:
			if ((result >> CPCI_STAT_LED_HP_SHIFT) & ONE_BIT)
				ledinfo->state = HPC_LED_ON;
			else
				ledinfo->state = HPC_LED_OFF;
			break;
		}

		break;

	case HPC_CTRL_SET_LED_STATE:
		return (HPC_ERR_NOTSUPPORTED);
	}

	return (HPC_SUCCESS);
}

/*
 * sghsc_get_slotnum()
 *	get slot number from the slot handle
 * returns non-negative value to indicate slot number
 *	  -1 for failure
 */
static int
sghsc_get_slotnum(sghsc_t *sghsc, hpc_slot_t sloth)
{
	int i;

	if (sloth == NULL || sghsc == NULL)
		return (-1);

	for (i = 0; i < sghsc->sghsc_num_slots; i++) {

		if (sghsc->sghsc_slot_table[i].handle == sloth)
			return (i);
	}

	return (-1);

}

/*
 * sghsc_scctl()
 *      mailbox interface
 *
 * return result code from mailbox operation
 */
static int
sghsc_scctl(int cmd, int node_id, int board, int slot, int *resultp)
{
	int		ret = 0xbee;
	bitcmd_info_t	cmd_info, *cmd_infop = &cmd_info;
	bitcmd_resp_t	cmd_info_r, *cmd_info_r_p = &cmd_info_r;
	sbbc_msg_t	request, *reqp = &request;
	sbbc_msg_t	response, *resp = &response;

	cmd_infop->cmd_id = 0x01234567;
	cmd_infop->node_id = node_id;
	cmd_infop->board = board;
	cmd_infop->slot = slot;

	reqp->msg_type.type = CPCI_MBOX;
	reqp->msg_status = 0xeeeeffff;
	reqp->msg_len = sizeof (cmd_info);
	reqp->msg_bytes = 8;
	reqp->msg_buf = (caddr_t)cmd_infop;
	reqp->msg_data[0] = 0;
	reqp->msg_data[1] = 0;

	bzero(resp, sizeof (*resp));
	bzero(cmd_info_r_p, sizeof (*cmd_info_r_p));

	resp->msg_buf = (caddr_t)cmd_info_r_p;
	resp->msg_len = sizeof (cmd_info_r);

	resp->msg_type.type = CPCI_MBOX;
	resp->msg_bytes = 8;
	resp->msg_status = 0xddddffff;

	switch (cmd) {
	case SGHSC_GET_SLOT_STATUS:
		reqp->msg_type.sub_type = CPCI_GET_SLOT_STATUS;
		resp->msg_type.sub_type = CPCI_GET_SLOT_STATUS;
		reqp->msg_len -= 4;
		break;
	case SGHSC_GET_NUM_SLOTS:
		reqp->msg_type.sub_type = CPCI_GET_NUM_SLOTS;
		resp->msg_type.sub_type = CPCI_GET_NUM_SLOTS;
		reqp->msg_len -= 8;
		break;
	case SGHSC_SET_SLOT_STATUS_RESET:
		reqp->msg_type.sub_type = CPCI_SET_SLOT_STATUS;
		resp->msg_type.sub_type = CPCI_SET_SLOT_STATUS;
		cmd_infop->info = CPCI_SET_STATUS_SLOT_RESET;
		break;
	case SGHSC_SET_SLOT_STATUS_READY:
		reqp->msg_type.sub_type = CPCI_SET_SLOT_STATUS;
		resp->msg_type.sub_type = CPCI_SET_SLOT_STATUS;
		cmd_infop->info = CPCI_SET_STATUS_SLOT_READY;
		break;
	case SGHSC_SET_SLOT_FAULT_LED_ON:
		reqp->msg_type.sub_type = CPCI_SET_SLOT_FAULT_LED;
		resp->msg_type.sub_type = CPCI_SET_SLOT_FAULT_LED;
		cmd_infop->info = CPCI_SET_FAULT_LED_ON;
		break;
	case SGHSC_SET_SLOT_FAULT_LED_OFF:
		reqp->msg_type.sub_type = CPCI_SET_SLOT_FAULT_LED;
		resp->msg_type.sub_type = CPCI_SET_SLOT_FAULT_LED;
		cmd_infop->info = CPCI_SET_FAULT_LED_OFF;
		break;
	case SGHSC_SET_SLOT_FAULT_LED_KEEP:
		reqp->msg_type.sub_type = CPCI_SET_SLOT_FAULT_LED;
		resp->msg_type.sub_type = CPCI_SET_SLOT_FAULT_LED;
		cmd_infop->info = CPCI_SET_FAULT_LED_KEEP;
		break;
	case SGHSC_SET_SLOT_FAULT_LED_TOGGLE:
		reqp->msg_type.sub_type = CPCI_SET_SLOT_FAULT_LED;
		resp->msg_type.sub_type = CPCI_SET_SLOT_FAULT_LED;
		cmd_infop->info = CPCI_SET_FAULT_LED_TOGGLE;
		break;
	case SGHSC_SET_SLOT_POWER_OFF:
		reqp->msg_type.sub_type = CPCI_SET_SLOT_POWER;
		resp->msg_type.sub_type = CPCI_SET_SLOT_POWER;
		cmd_infop->info = CPCI_POWER_OFF;
		break;
	case SGHSC_SET_SLOT_POWER_ON:
		reqp->msg_type.sub_type = CPCI_SET_SLOT_POWER;
		resp->msg_type.sub_type = CPCI_SET_SLOT_POWER;
		cmd_infop->info = CPCI_POWER_ON;
		break;
	case SGHSC_GET_CPCI_BOARD_TYPE:
		reqp->msg_type.sub_type = CPCI_BOARD_TYPE;
		resp->msg_type.sub_type = CPCI_BOARD_TYPE;
		reqp->msg_len -= 8;
		break;
	case SGHSC_SET_ENUM_CLEARED:
		reqp->msg_type.sub_type = CPCI_SET_ENUM_CLEARED;
		resp->msg_type.sub_type = CPCI_SET_ENUM_CLEARED;
		break;
	default:
		cmn_err(CE_WARN, "sghsc: unrecognized action code 0x%x\n",
		    cmd);
	}

	DEBUGF(1, (CE_NOTE,
	    "sghsc: sending mbox command type=%d subtype=0x%x size=%d buf=%p",
	    reqp->msg_type.type, reqp->msg_type.sub_type,
	    reqp->msg_len, (void *)reqp->msg_buf));

	DEBUGF(1, (CE_NOTE,
	    "sghsc: sending buf  cmd_id=0x%x node_id=0x%x board=0x%x "
	    "slot=0x%x info=0x%x", cmd_infop->cmd_id, cmd_infop->node_id,
	    cmd_infop->board, cmd_infop->slot, cmd_infop->info));


	ret = sbbc_mbox_request_response(reqp, resp, sghsc_mbx_timeout);

	/*
	 * The resp->msg_status field may contain an SC error or a common
	 * error such as ETIMEDOUT.
	 */
	if ((ret != 0) || (resp->msg_status != SG_MBOX_STATUS_SUCCESS)) {
		DEBUGF(1, (CE_NOTE, "sghsc: mailbox command error = 0x%x, "
		    "status = 0x%x", ret, resp->msg_status));
		return (-1);
	}

	DEBUGF(1, (CE_NOTE, "sghsc: reply request status=0x%x",
	    reqp->msg_status));
	DEBUGF(1, (CE_NOTE, "sghsc: reply resp status=0x%x",
	    resp->msg_status));
	DEBUGF(1, (CE_NOTE, "sghsc: reply buf  cmd_id=0x%x result=0x%x\n",
	    cmd_info_r_p->cmd_id, cmd_info_r_p->result));

#ifdef DEBUG_EXTENDED
	if (cmd == SGHSC_GET_NUM_SLOTS) {
		DEBUGF(1, (CE_NOTE, "sghsc:  node %d / board %d has %d slots",
		    cmd_infop->node_id, cmd_infop->board,
		    cmd_info_r_p->result));
		*resultp = cmd_info_r_p->result;
		return (0);
	}

	if ((cmd_info_r_p->result >> CPCI_STAT_POWER_ON_SHIFT) & ONE_BIT)
		DEBUGF(1, (CE_NOTE, "sghsc: cpower on"));

	if ((cmd_info_r_p->result >> CPCI_STAT_LED_POWER_SHIFT) & ONE_BIT)
		DEBUGF(1, (CE_NOTE, "sghsc: power led on"));

	if ((cmd_info_r_p->result >> CPCI_STAT_LED_FAULT_SHIFT) & ONE_BIT)
		DEBUGF(1, (CE_NOTE, "sghsc: fault led on"));

	if ((cmd_info_r_p->result >> CPCI_STAT_LED_HP_SHIFT) & ONE_BIT)
		DEBUGF(1, (CE_NOTE, "sghsc: remove(hp) led on"));

	if ((cmd_info_r_p->result >> CPCI_STAT_SLOT_EMPTY_SHIFT) & ONE_BIT)
		DEBUGF(1, (CE_NOTE, "sghsc: slot empty"));

	tmp = ((cmd_info_r_p->result >> CPCI_STAT_HOT_SWAP_STATUS_SHIFT) &
	    THREE_BITS);
	if (tmp)
		DEBUGF(1, (CE_NOTE,
		    "sghsc: slot condition(hot swap status) is 0x%x", tmp));

	if (cmd_info_r_p->result & CPCI_GET_STAT_SLOT_HZ_CAP)
		DEBUGF(1, (CE_NOTE,
		    "sghsc: freq cap %x", cmd_info_r_p->result &
		    CPCI_GET_STAT_SLOT_HZ_CAP));

	if (cmd_info_r_p->result & CPCI_GET_STAT_SLOT_HZ_SET)
		DEBUGF(1, (CE_NOTE,
		    "sghsc: freq setting %x", cmd_info_r_p->result &
		    CPCI_GET_STAT_SLOT_HZ_SET));


	if ((cmd_info_r_p->result >> CPCI_STAT_HEALTHY_SHIFT) & ONE_BIT)
		DEBUGF(1, (CE_NOTE, "sghsc: healthy"));

	if ((cmd_info_r_p->result >> CPCI_STAT_RESET_SHIFT) & ONE_BIT)
		DEBUGF(1, (CE_NOTE, "sghsc: in reset"));

	if (cmd_info_r_p->result & CPCI_GET_STAT_POWER_GOOD)
		DEBUGF(1, (CE_NOTE, "sghsc: power good"));

	if (cmd_info_r_p->result & CPCI_GET_STAT_POWER_FAULT)
		DEBUGF(1, (CE_NOTE, "sghsc: power fault"));

	if (cmd_info_r_p->result & CPCI_GET_STAT_PCI_PRESENT)
		DEBUGF(1, (CE_NOTE, "sghsc: pci present"));
#endif

	*resultp = cmd_info_r_p->result;
	return (0);
}


/*
 * sghsc_freemem()
 *	deallocates memory resources
 *
 */
static void
sghsc_freemem(sghsc_t *sghsc)
{
	int i;

	/*
	 * Free up allocated resources
	 * sghsc_register_slots => unregister all slots
	 */
	for (i = 0; i < sghsc->sghsc_num_slots; i++) {
		if (sghsc->sghsc_slot_table[i].slot_ops)
			hpc_free_slot_ops(sghsc->sghsc_slot_table[i].slot_ops);
		if (sghsc->sghsc_slot_table[i].handle)
			(void) hpc_slot_unregister(
			    &sghsc->sghsc_slot_table[i].handle);
	}

	/* finally free up slot_table */
	kmem_free(sghsc->sghsc_slot_table,
	    (size_t)(sghsc->sghsc_num_slots * sizeof (sghsc_slot_t)));

}

/*
 * sghsc_find_sloth()
 *      Find slot handle by node id, board number and slot numbert
 * Returns slot handle or 0 if slot not found.
 */
static hpc_slot_t
sghsc_find_sloth(int node_id, int board, int slot)
{
	int instance;
	sghsc_t *sghsc;

	for (instance = 0; instance < sghsc_maxinst; instance++) {
		sghsc = (sghsc_t *)ddi_get_soft_state(sghsc_state, instance);

		if (sghsc == NULL || sghsc->sghsc_node_id != node_id ||
		    sghsc->sghsc_board != board)
			continue;

		DEBUGF(1, (CE_NOTE, "sghsc_find_sloth on board %d at node %d"
		    " slot %d", board, node_id, slot))

		if (sghsc->sghsc_num_slots < (slot + 1)) {
			cmn_err(CE_WARN, "sghsc%d: slot data corruption at"
			    "node %d / board %d", instance, node_id, board);
			return (NULL);
		}

		if (sghsc->sghsc_valid == 0)
			return (NULL);

		/*
		 * Found matching slot, return handle.
		 */
		return (sghsc->sghsc_slot_table[slot].handle);
	}

	DEBUGF(1, (CE_WARN, "sghsc_find_sloth: slot %d not found for node %d"
	" / board %d", slot, node_id, board));
	return (NULL);
}

/*
 * sghsc_event_handler()
 *      Event Handler. This is what for other platforms was an interrupt
 * Handler servicing events. It accepts an event and signals it to
 * non-interrupt thread.
 */
uint_t
sghsc_event_handler(char *arg)
{
	sghsc_event_t *rsp_data;
	hpc_slot_t sloth;
	sghsc_t *enum_state;

	DEBUGF(1, (CE_NOTE, "sghsc: sghsc_event_handler called"))

	rsp_data = (sghsc_event_t *)(((sbbc_msg_t *)arg)->msg_buf);

	if (rsp_data == NULL) {
		cmn_err(CE_WARN,
		    ("sghsc: sghsc_event_handler argument is null\n"));
		return (DDI_INTR_CLAIMED);
	}

	sloth = sghsc_find_sloth(rsp_data->node_id, rsp_data->board,
	    rsp_data->slot);
	/*
	 * On a board disconnect sghsc soft state may not exist
	 * when the interrupt occurs. We should treat these
	 * interrupts as noise and but them.
	 */
	if (sloth == NULL) {
		DEBUGF(1, (CE_WARN, "sghsc: slot info not available for"
		    " node %d / board %d slot %d. CPCI event rejected",
		    rsp_data->node_id, rsp_data->board, rsp_data->slot));
		return (DDI_INTR_CLAIMED);
	}

	enum_state = sghsc_find_softstate(rsp_data->node_id, rsp_data->board,
	    rsp_data->slot);
	if (enum_state == NULL) {
		cmn_err(CE_WARN, "sghsc: soft state not available for"
		    " node %d / board %d slot %d", rsp_data->node_id,
		    rsp_data->board, rsp_data->slot);
		return (DDI_INTR_UNCLAIMED);
	}

	DEBUGF(1, (CE_NOTE, "sghsc: node %d", rsp_data->node_id));
	DEBUGF(1, (CE_NOTE, "sghsc: board %d", rsp_data->board));
	DEBUGF(1, (CE_NOTE, "sghsc: slot %d", rsp_data->slot));
	DEBUGF(1, (CE_NOTE, "sghsc: event info %d", rsp_data->info));

	switch (rsp_data->info) {
	case SGHSC_EVENT_CARD_INSERT:
		DEBUGF(1, (CE_NOTE, "sghsc: card inserted node %d / board %d"
		    " slot %d", rsp_data->node_id, rsp_data->board,
		    rsp_data->slot));
		enum_state->sghsc_slot_table[rsp_data->slot].board_type =
		    HPC_BOARD_CPCI_HS;
		enum_state->sghsc_slot_table[rsp_data->slot].slot_status =
		    HPC_SLOT_DISCONNECTED;
		break;
	case SGHSC_EVENT_CARD_REMOVE:
		DEBUGF(1, (CE_NOTE, "sghsc: card removed node %d / board %d"
		    " slot %d", rsp_data->node_id, rsp_data->board,
		    rsp_data->slot));
		enum_state->sghsc_slot_table[rsp_data->slot].board_type =
		    HPC_BOARD_UNKNOWN;
		enum_state->sghsc_slot_table[rsp_data->slot].slot_status =
		    HPC_SLOT_EMPTY;
		return (DDI_INTR_CLAIMED);
	case SGHSC_EVENT_POWER_ON:
		DEBUGF(1, (CE_NOTE, "sghsc: power on node %d / board %d"
		    " slot %d", rsp_data->node_id, rsp_data->board,
		    rsp_data->slot));
		return (DDI_INTR_CLAIMED);
	case SGHSC_EVENT_POWER_OFF:
		DEBUGF(1, (CE_NOTE, "sghsc: power off node %d / board %d"
		    " slot %d", rsp_data->node_id, rsp_data->board,
		    rsp_data->slot));
		return (DDI_INTR_CLAIMED);
	case SGHSC_EVENT_HEALTHY_LOST:
		DEBUGF(1, (CE_NOTE, "sghsc: healthy lost node %d / board %d"
		    " slot %d", rsp_data->node_id, rsp_data->board,
		    rsp_data->slot));
		return (DDI_INTR_CLAIMED);
	case SGHSC_EVENT_LEVER_ACTION:
		DEBUGF(1, (CE_NOTE, "sghsc: ENUM generated for node %d /"
		    "board %d slot %d", rsp_data->node_id, rsp_data->board,
		    rsp_data->slot));
		break;
	default:
		DEBUGF(1, (CE_NOTE, "sghsc: unrecognized event info for"
		    " node %d / board %d slot %d", rsp_data->node_id,
		    rsp_data->board, rsp_data->slot));
		return (DDI_INTR_CLAIMED);
	}

	/*
	 * Signal the ENUM event to the non-interrupt thread as the Hot
	 * Plug Framework will eventually call sghsc_control() but all
	 * the mailbox messages are not allowed from interrupt context.
	 */

	if (sghsc_rb_put(&sghsc_rb_header, rsp_data) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "sghsc: no space to store #ENUM info");
		return (DDI_INTR_UNCLAIMED);
	}

	cv_signal(&sghsc_event_thread_cv);

	return (DDI_INTR_CLAIMED);
}

/*
 * sghsc_event_thread_code()
 *      Event Thread. This is non-interrupt thread servicing #ENUM, Insert,
 *      Remove, Power on/off, Healthy lost events.
 */
static void
sghsc_event_thread_code(void)
{
	int	rc;
	int	result;
	hpc_slot_t sloth;
	sghsc_t *sghsc;
	sghsc_event_t rsp_data;

	mutex_enter(&sghsc_event_thread_mutex);

	for (;;) {
		/*
		 * Wait for Event handler to signal event or self destruction.
		 * Assuming the mutex will be automatically reaccuired.
		 */
		cv_wait(&sghsc_event_thread_cv, &sghsc_event_thread_mutex);

		if (sghsc_event_thread_exit)
			break;

		/*
		 * Pick up all the relevant events from the ring buffer.
		 */
		while (sghsc_rb_get(&sghsc_rb_header, &rsp_data) ==
		    DDI_SUCCESS) {

			sghsc = sghsc_find_softstate(rsp_data.node_id,
			    rsp_data.board, rsp_data.slot);
			if (sghsc == NULL)
				continue;
			sloth = sghsc_find_sloth(rsp_data.node_id,
			    rsp_data.board, rsp_data.slot);
			if (sloth == NULL)
				continue;

			if (!(sghsc->sghsc_slot_table[rsp_data.slot].flags &
			    SGHSC_SLOT_AUTO_CFG_EN))
				continue;
			/*
			 * Insert event leads only to the electrical
			 * connection.
			 */
			if (rsp_data.info == SGHSC_EVENT_CARD_INSERT) {
				rc = sghsc_connect((caddr_t)sghsc, sloth,
				    NULL, 0);
				if (rc != HPC_SUCCESS)
					cmn_err(CE_WARN, "sghsc:"
					    " could not connect inserted card,"
					    " node %d / board %d slot %d",
					    rsp_data.node_id, rsp_data.board,
					    rsp_data.slot);
				continue;
			}

			/*
			 * ENUM event received.
			 * Reset ENUM and notify SC to poll for the next one.
			 */
			rc = hpc_slot_event_notify(sloth, HPC_EVENT_CLEAR_ENUM,
			    HPC_EVENT_SYNCHRONOUS);

			if (rc == HPC_EVENT_UNCLAIMED) {
				DEBUGF(1, (CE_WARN,
				    "sghsc: unable to clear ENUM"));
				continue;
			}

			rc = sghsc_scctl(SGHSC_SET_ENUM_CLEARED,
			    rsp_data.node_id, rsp_data.board,
			    rsp_data.slot, &result);
			if (rc) {
				DEBUGF(1, (CE_WARN,
				    "sghsc: unable to ACK cleared ENUM"));
				continue;
			}

			/*
			 * process the ENUM.
			 */
			rc = hpc_slot_event_notify(sloth,
			    HPC_EVENT_PROCESS_ENUM, HPC_EVENT_SYNCHRONOUS);

			if (rc == HPC_EVENT_UNCLAIMED) {
				DEBUGF(1, (CE_WARN,
				    "sghsc: could not process ENUM"));
			}
		}
	}

	DEBUGF(1, (CE_NOTE, "sghsc: thread_exit"));
	cv_signal(&sghsc_event_thread_cv);
	mutex_exit(&sghsc_event_thread_mutex);
	thread_exit();
}

/*
 * sghsc_find_softstate()
 *      Find softstate by node id and board number. Slot number is used for
 *      verification.
 * Returns board's softstate or 0 if not found.
 */
static sghsc_t *
sghsc_find_softstate(int node_id, int board, int slot)
{
	int instance;
	sghsc_t *sghsc;

	for (instance = 0; instance < sghsc_maxinst; instance++) {
		sghsc = (sghsc_t *)ddi_get_soft_state(sghsc_state, instance);

		if (sghsc == NULL || sghsc->sghsc_node_id != node_id ||
		    sghsc->sghsc_board != board)
			continue;

		if (sghsc->sghsc_num_slots < (slot + 1)) {
			cmn_err(CE_WARN, "sghsc%d: "
			    "slot data corruption", instance);
			return (NULL);
		}

		if (sghsc->sghsc_valid == 0)
			return (NULL);

		/*
		 * Found matching data, return soft state.
		 */
		return (sghsc);
	}

	cmn_err(CE_WARN, "sghsc: soft state not found");
	return (NULL);
}

/*
 * sghsc_rb_setup()
 *      Initialize the event ring buffer with a fixed size. It may require
 *      a more elaborate scheme with buffer extension
 */
static void
sghsc_rb_setup(sghsc_rb_head_t *rb_head)
{
	if (rb_head->buf == NULL) {
		rb_head->put_idx = 0;
		rb_head->get_idx = 0;
		rb_head->size = SGHSC_RING_BUFFER_SZ;
		rb_head->state = SGHSC_RB_EMPTY;

		/*
		 * Allocate space for event ring buffer
		 */
		rb_head->buf = (sghsc_event_t *)kmem_zalloc(
		    sizeof (sghsc_event_t) * rb_head->size, KM_SLEEP);
	}
}

/*
 * sghsc_rb_teardown()
 *      Free event ring buffer resources.
 */
static void
sghsc_rb_teardown(sghsc_rb_head_t *rb_head)
{
	if (rb_head->buf != NULL) {
		/*
		 * Deallocate space for event ring buffer
		 */
		kmem_free(rb_head->buf,
		    (size_t)(sizeof (sghsc_event_t) * rb_head->size));

		rb_head->buf = NULL;
		rb_head->put_idx = 0;
		rb_head->get_idx = 0;
		rb_head->size = 0;
		rb_head->state = SGHSC_RB_EMPTY;
	}
}

/*
 * sghsc_rb_put()
 *      Insert an event info into the event ring buffer.
 * Returns DDI_FAILURE if the buffer is full, DDI_SUCCESS otherwise
 */
static int
sghsc_rb_put(sghsc_rb_head_t *rb_head, sghsc_event_t *event)
{
	if (rb_head->state == SGHSC_RB_FULL)
		return (DDI_FAILURE);

	rb_head->buf[rb_head->put_idx] = *event;

	rb_head->put_idx = (rb_head->put_idx + 1) & (rb_head->size - 1);

	if (rb_head->put_idx == rb_head->get_idx)
		rb_head->state = SGHSC_RB_FULL;
	else
		rb_head->state = SGHSC_RB_FLOAT;

	return (DDI_SUCCESS);
}
/*
 * sghsc_rb_get()
 *      Remove an event info from the event  ring buffer.
 * Returns DDI_FAILURE if the buffer is empty, DDI_SUCCESS otherwise.
 */
static int
sghsc_rb_get(sghsc_rb_head_t *rb_head, sghsc_event_t *event)
{

	if (rb_head->state == SGHSC_RB_EMPTY)
		return (DDI_FAILURE);

	*event = rb_head->buf[rb_head->get_idx];

	rb_head->get_idx = (rb_head->get_idx + 1) & (rb_head->size - 1);

	if (rb_head->get_idx == rb_head->put_idx)
		rb_head->state = SGHSC_RB_EMPTY;
	else
		rb_head->state = SGHSC_RB_FLOAT;

	return (DDI_SUCCESS);
}
