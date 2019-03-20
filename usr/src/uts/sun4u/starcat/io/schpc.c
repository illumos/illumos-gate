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
 * Starcat IOSRAM/Tunnel PCI Hot Plug Controller Driver
 */

#define	CPCI_ENUM

#include <sys/note.h>
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/modctl.h>
#include <sys/disp.h>
#include <sys/async.h>
#include <sys/hotplug/hpcsvc.h>
#include <sys/mboxsc.h>
#include <sys/schpc_msg.h>
#include <sys/schpc.h>
#include <post/scat_dcd.h>
#include <sys/taskq.h>

#ifdef DEBUG
int schpc_dump_save_regs = 0;
static uint_t schpc_debug_flags = 0;
#define	SCHPC_DEBUG0(f, s) if ((f)& schpc_debug_flags) \
	cmn_err(CE_CONT, "schpc: " s "\n")
#define	SCHPC_DEBUG1(f, s, a) if ((f)& schpc_debug_flags) \
	cmn_err(CE_CONT, "schpc: " s "\n", a)
#define	SCHPC_DEBUG2(f, s, a, b) if ((f)& schpc_debug_flags) \
	cmn_err(CE_CONT, "schpc: " s "\n", a, b)
#define	SCHPC_DEBUG3(f, s, a, b, c) if ((f)& schpc_debug_flags) \
	cmn_err(CE_CONT, "schpc: " s "\n", a, b, c)
#define	SCHPC_DEBUG4(f, s, a, b, c, d) if ((f)& schpc_debug_flags) \
	cmn_err(CE_CONT, "schpc: " s "\n", a, b, c, d)
#define	SCHPC_DEBUG5(f, s, a, b, c, d, e) if ((f)& schpc_debug_flags) \
	cmn_err(CE_CONT, "schpc: " s "\n", a, b, c, d, e)
#define	SCHPC_DEBUG6(f, s, a, b, c, d, e, ff) if ((f)& schpc_debug_flags) \
	cmn_err(CE_CONT, "schpc: " s "\n", a, b, c, d, e, ff)
#else

#define	SCHPC_DEBUG0(f, s)
#define	SCHPC_DEBUG1(f, s, a)
#define	SCHPC_DEBUG2(f, s, a, b)
#define	SCHPC_DEBUG3(f, s, a, b, c)
#define	SCHPC_DEBUG4(f, s, a, b, c, d)
#define	SCHPC_DEBUG5(f, s, a, b, c, d, e)
#define	SCHPC_DEBUG6(f, s, a, b, c, d, e, ff)

#endif

#define	D_IDENTIFY	0x00000001
#define	D_ATTACH	0x00000002
#define	D_DETACH	0x00000004
#define	D_OPEN		0x00000008
#define	D_GETSLOTSTATUS	0x00000010
#define	D_SETSLOTSTATUS	0x00000020
#define	D_IOCTL		0x00010000
#define	D_IOC_CONNECT	0x00020000
#define	D_IOC_CONTROL	0x00040000
#define	D_IOC_CONFIG	0x00080000
#define	D_IOC_STATUS	0x00100000
#define	D_IOC_MSG	0x00200000
#define	D_IOC_TEST	0x00400000
#define	D_IOC_LED	0x00800000
#define	D_EVENT		0x01000000
#define	D_THREAD	0x02000000
#define	D_TRANSID	0x04000000
#define	D_SLOTTABLE	0x08000000
#define	D_FREQCHG	0x10000000
#define	D_APID		0x20000000

/*
 * driver global data:
 */
static void *per_schpc_state;		/* soft state head */
dev_info_t *schpc_devi;
static schpc_t	*schpc_p;

clock_t schpc_timeout_putmsg = 60 * 1000; /* 60 seconds */
clock_t schpc_timeout_getmsg = 60 * 1000; /* 60 seconds */
clock_t schpc_timeout_event = 60 * 5 * 1000; /* 5 minutes */

int schpc_use_legacy_apid = 0;

static mboxsc_timeout_range_t schpc_putmsg_timeout_range;
static mboxsc_timeout_range_t schpc_getmsg_timeout_range;

static taskq_t *schpc_event_taskq = NULL;

/*
 * replies to mboxsc_getmsg() are handled asynchronously by the
 * schpc_msg_thread using a linked list of schpc_replylist_t
 * elements
 */
typedef struct schpc_replylist {
	struct schpc_replylist	*prev;		/* link to previous entry */
	struct schpc_replylist	*next;		/* link to next entry */
	kcondvar_t		reply_cv;	/* condvar for getting reply */
	kmutex_t		reply_lock;	/* mutex for getting reply */
	uint32_t		type;		/* mboxsc_xxxmsg() msg type */
	uint32_t		cmd;		/* mboxsc_xxxmsg() cmd */
	uint64_t		transid;	/* mboxsc_xxxmsg() trans id */
	uint32_t		length;		/* mboxsc_xxxmsg() length */
	pcimsg_t		reply;		/* mboxsc_xxxmsg() reply msg */
	boolean_t		reply_recvd;	/* msg reply received */
	boolean_t		reply_cexit;	/* client early exit */
} schpc_replylist_t;

static kmutex_t schpc_replylist_mutex; /* replylist mutex */
static uint32_t schpc_replylist_count; /* replylist size */
static schpc_replylist_t *schpc_replylist_first; /* replylist 1st elem */
static schpc_replylist_t *schpc_replylist_last; /* replylist last elem */
static boolean_t slots_registered = B_FALSE; /* slots registered? */

typedef struct {
	char		*cname;
	char		*caddr;
	char		schizo;
	char		leaf;
	dev_info_t	*dip;
} find_dev_t;

/*
 * Function prototypes for local functions
 */
static int schpc_getexpander(dev_info_t *);
static int schpc_getboard(dev_info_t *);
static void schpc_event_handler(void *);
static void schpc_event_filter(pcimsg_t	*msg);
static void schpc_reply_handler(pcimsg_t *pmsg, uint32_t type, uint32_t cmd,
				uint64_t transid, uint32_t length);
static uint64_t schpc_gettransid(schpc_t *, int);
static int schpc_slot_get_index(schpc_t *, hpc_slot_t);
static void schpc_register_all_slots(schpc_t *);
static void schpc_setslotled(int, int, int, uint32_t);
static void schpc_init_setslot_message(pci_setslot_t *);
static void schpc_test(caddr_t, int, void *, uint_t);
static int schpc_getslotstatus(uint32_t, uint32_t, uint32_t, pci_getslot_t *);
static int schpc_setslotstatus(uint32_t, uint32_t, uint32_t,  pci_setslot_t *);
static int schpc_match_dip(dev_info_t *, void *);
static void schpc_buildapid(dev_info_t *, int, char *);
static int schpc_get_slot_status(uint_t, uint_t, uint_t);
static void schpc_replylist_unlink(schpc_replylist_t *entry);
static schpc_replylist_t *schpc_replylist_link(uint32_t cmd, uint64_t transid,
						uint32_t length);
static void schpc_msg_thread(void);
static int schpc_putrequest(uint32_t key, uint32_t type, uint32_t cmd,
				uint64_t *transidp, uint32_t length,
				void *datap, clock_t timeout,
				schpc_replylist_t **entryp);
static int schpc_getreply(uint32_t key, uint32_t *typep, uint32_t *cmdp,
			uint64_t *transidp, uint32_t *lengthp, void *datap,
			clock_t timeout, schpc_replylist_t *listp);

static int schpc_slot_freq(pci_getslot_t *);
static int schpc_find_dip(dev_info_t *, void *);

static int schpc_save_leaf(int slot);
static void schpc_restore_leaf(int slot);
static int schpc_is_leaf_reset_required(int slot);
static int schpc_is_freq_switchable(int slot);
static void schpc_save_entry(int slot, int list_entry, int save_entry);
static void schpc_restore_entry(int slot, int list_entry, int save_entry);

/*
 * Function prototype for Hot Plug Services
 */
static int schpc_connect(caddr_t, hpc_slot_t, void *, uint_t);
static int schpc_disconnect(caddr_t, hpc_slot_t, void *, uint_t);
static int schpc_cpci_control(caddr_t, hpc_slot_t, int, caddr_t);
static int schpc_pci_control(caddr_t, hpc_slot_t, int, caddr_t);

extern int iosram_rd(uint32_t, uint32_t, uint32_t, caddr_t);

/*
 * cb_ops and dev_ops:
 */
static struct cb_ops schpc_cb_ops = {
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
	D_NEW | D_MP | D_HOTPLUG /* Driver compatibility flag */
};

/*
 * Function prototype for dev_ops
 */
static int schpc_attach(dev_info_t *, ddi_attach_cmd_t);
static int schpc_detach(dev_info_t *, ddi_detach_cmd_t);
static int schpc_info(dev_info_t *, ddi_info_cmd_t, void *, void **);

static struct dev_ops schpc_dev_ops = {
	DEVO_REV,			/* devo_rev, */
	0,				/* refcnt  */
	schpc_info,			/* get_dev_info */
	nulldev,			/* identify */
	nulldev,			/* probe */
	schpc_attach,			/* attach */
	schpc_detach,			/* detach */
	nodev,				/* reset */
	&schpc_cb_ops,			/* driver operations */
	(struct bus_ops *)0,		/* no bus operations */
	NULL,				/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/*
 * loadable module declarations:
 */
static struct modldrv modldrv = {
	&mod_driverops,
	"PCI Hot Plug Controller Driver (schpc)",
	&schpc_dev_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	int		ret;
	int		rv;

	SCHPC_DEBUG0(D_ATTACH, "_init() installing module");

	ret = ddi_soft_state_init(&per_schpc_state, sizeof (schpc_t), 1);
	if (ret != 0) {
		return (ret);
	}

	/*
	 * Initialize Outgoing Mailbox.
	 */
	ret = mboxsc_init(KEY_PCSC, MBOXSC_MBOX_OUT, NULL);

	if (ret != 0) {
		ddi_soft_state_fini(&per_schpc_state);
		return (ret);
	}

	ret = mboxsc_ctrl(KEY_PCSC, MBOXSC_CMD_PUTMSG_TIMEOUT_RANGE,
	    (void *) &schpc_putmsg_timeout_range);

	if (ret != 0) {
		ddi_soft_state_fini(&per_schpc_state);
		return (ret);
	}

	if (schpc_timeout_putmsg < schpc_putmsg_timeout_range.min_timeout) {
		schpc_timeout_putmsg = schpc_putmsg_timeout_range.min_timeout;
		cmn_err(CE_WARN, " schpc: resetting putmsg timeout to %ld\n",
		    schpc_timeout_putmsg);
	}

	if (schpc_timeout_putmsg > schpc_putmsg_timeout_range.max_timeout) {
		schpc_timeout_putmsg = schpc_putmsg_timeout_range.max_timeout;
		cmn_err(CE_WARN, " schpc: resetting putmsg timeout to %ld\n",
		    schpc_timeout_putmsg);
	}

	/*
	 * Create the schpc_event_taskq for MBOXSC_MSG_EVENT processing.
	 */
	schpc_event_taskq = taskq_create("schpc_event_taskq", 2,
	    minclsyspri, 4, 4, TASKQ_PREPOPULATE);

	/*
	 * Initialize Incoming Mailbox.
	 * NOTE: the callback is null because the schpc_msg_thread will
	 * handle all incoming MBOXSC_MSG_EVENT and MBOXSC_MSG_REPLY
	 * messages.
	 */
	ret = mboxsc_init(KEY_SCPC, MBOXSC_MBOX_IN, NULL);

	if (ret != 0) {
		cmn_err(CE_WARN, "schpc: can not initialize KEY_SCPC as "
		    "MBOXSC_MBOX_IN");
		ddi_soft_state_fini(&per_schpc_state);
		return (ret);
	}

	ret = mboxsc_ctrl(KEY_SCPC, MBOXSC_CMD_GETMSG_TIMEOUT_RANGE,
	    (void *) &schpc_getmsg_timeout_range);

	if (ret != 0) {
		ddi_soft_state_fini(&per_schpc_state);
		return (ret);
	}

	if (schpc_timeout_getmsg < schpc_getmsg_timeout_range.min_timeout) {
		schpc_timeout_getmsg = schpc_getmsg_timeout_range.min_timeout;
		cmn_err(CE_WARN, " schpc: resetting getmsg timeout to %ld\n",
		    schpc_timeout_getmsg);
	}

	if (schpc_timeout_getmsg > schpc_getmsg_timeout_range.max_timeout) {
		schpc_timeout_getmsg = schpc_getmsg_timeout_range.max_timeout;
		cmn_err(CE_WARN, " schpc: resetting putmsg timeout to %ld\n",
		    schpc_timeout_putmsg);
	}

	if (schpc_timeout_event < schpc_getmsg_timeout_range.min_timeout) {
		schpc_timeout_event = schpc_getmsg_timeout_range.min_timeout;
		cmn_err(CE_WARN, " schpc: resetting event timeout to %ld\n",
		    schpc_timeout_event);
	}

	if (schpc_timeout_event > schpc_getmsg_timeout_range.max_timeout) {
		schpc_timeout_event = schpc_getmsg_timeout_range.max_timeout;
		cmn_err(CE_WARN, " schpc: resetting event timeout to %ld\n",
		    schpc_timeout_event);
	}

	ret = mod_install(&modlinkage);
	if (ret != 0) {
		if ((rv = mboxsc_fini(KEY_PCSC)) != 0) {
			cmn_err(CE_WARN, "schpc: _init() - "
			    "mboxsc_fini(KEY_PCSC) failed: 0x%x", rv);
		}
		if ((rv = mboxsc_fini(KEY_SCPC)) != 0) {
			cmn_err(CE_WARN, "schpc: _init() - "
			    "mboxsc_fini(KEY_SCPC) failed: 0x%x", rv);
		}
		taskq_destroy(schpc_event_taskq);
		ddi_soft_state_fini(&per_schpc_state);
		return (ret);
	}

	SCHPC_DEBUG0(D_ATTACH, "_init() module installed");

	/*
	 * Start the schpc_msg_thread to continuously monitor the
	 * MBOXSC_MBOX_IN mailbox for incoming MBOXSC_MSG_EVENTs and
	 * MBOXSC_MSG_REPLYs.
	 */
	mutex_init(&schpc_replylist_mutex, NULL, MUTEX_DRIVER, NULL);
	(void) thread_create(NULL, 0, schpc_msg_thread,
	    NULL, 0, &p0, TS_RUN, minclsyspri);

	SCHPC_DEBUG0(D_ATTACH, "_init() started schpc_msg_thread");

	return (ret);
}

int
_fini(void)
{
	SCHPC_DEBUG0(D_ATTACH, "_fini()");

	return (DDI_FAILURE);
}

int
_info(struct modinfo *modinfop)
{
	SCHPC_DEBUG0(D_ATTACH, "_info() called.");

	return (mod_info(&modlinkage, modinfop));
}

static int
schpc_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int		instance = ddi_get_instance(devi);
	int		rval;

	SCHPC_DEBUG1(D_ATTACH, "attach(%x) ATTACH", instance);

	switch (cmd) {
	case DDI_ATTACH:

		/*
		 * Allocate the soft state structure for this instance.
		 */
		rval = ddi_soft_state_zalloc(per_schpc_state, instance);

		if (rval != DDI_SUCCESS) {
			SCHPC_DEBUG1(D_ATTACH,
			    "schpc_attach(%x) Can not allocate "
			    "soft state structure", instance);
			return (DDI_FAILURE);
		}

		schpc_p = (schpc_t *)ddi_get_soft_state(per_schpc_state,
		    instance);

		if (schpc_p == NULL) {
			return (DDI_FAILURE);
		}

		mutex_init(&schpc_p->schpc_mutex, NULL, MUTEX_DRIVER, NULL);
		cv_init(&schpc_p->schpc_cv, NULL, CV_DRIVER, NULL);

		/*
		 * Put schpc structure on global linked list.
		 */

		/*
		 * Initialize starting transaction ID.
		 */
		schpc_p->schpc_transid = 0;

		schpc_p->schpc_number_of_slots = STARCAT_MAX_SLOTS;

		SCHPC_DEBUG2(D_ATTACH, "schpc_attach(%x) slot-table property "
		    "describes %d slots", instance,
		    schpc_p->schpc_number_of_slots);

		schpc_p->schpc_hotplugmodel = ddi_getprop(DDI_DEV_T_ANY,
		    devi, 0, "hot-plug-model", SCHPC_HOTPLUGTYPE_CPCIHOTPLUG);

		SCHPC_DEBUG2(D_ATTACH, "attach(%x) ATTACH - Hot Plug Model=%x",
		    instance, schpc_p->schpc_hotplugmodel);

		/*
		 * What type of hot plug do these slots support?  The only
		 * types of slots we support is the cPCI Hot Plug Model
		 * and Not Hot Pluggable.
		 */
		if (schpc_p->schpc_hotplugmodel !=
		    SCHPC_HOTPLUGTYPE_CPCIHOTPLUG) {
			schpc_p->schpc_hotplugmodel =
			    SCHPC_HOTPLUGTYPE_NOTHOTPLUGGABLE;
		}

		schpc_p->schpc_slot = (schpc_slot_t *)kmem_zalloc((size_t)
		    (schpc_p->schpc_number_of_slots * sizeof (schpc_slot_t)),
		    KM_SLEEP);

		schpc_p->schpc_devi = devi;
		schpc_p->schpc_instance = instance;

		/*
		 * Start thread to search the device tree and register
		 * all found pci slots.
		 */
		(void) thread_create(NULL, 0, schpc_register_all_slots,
		    (void *)schpc_p, 0, &p0, TS_RUN, minclsyspri);

		break;

	case DDI_PM_RESUME:
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		cmn_err(CE_WARN, "schpc%d: Cmd != DDI_ATTACH/DDI_RESUME",
		    instance);

		return (DDI_FAILURE);
	}

	SCHPC_DEBUG1(D_ATTACH,
	    "schpc_attach(%x) Attach - DDI_SUCCESS", instance);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
schpc_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int	instance = ddi_get_instance(devi);

	SCHPC_DEBUG1(D_DETACH, "detach(%x) DETACH", instance);

	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
schpc_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
	void **result)
{
	int	error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)schpc_devi;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/*
 * schpc_connect()
 *
 * Called by Hot Plug Services to connect a slot to the bus.
 */

/*ARGSUSED*/
static int
schpc_connect(caddr_t ops_arg, hpc_slot_t slot_hdl, void *data, uint_t flags)
{
	int		rval;
	int		expander, board;
	pci_setslot_t	setslot;
	pci_getslot_t	getslot;
	int		slot;

	SCHPC_DEBUG2(D_IOC_CONNECT, "schpc_connect( ops_arg=%p slot_hdl=%p)",
	    (void *)ops_arg, (void *)slot_hdl);

	mutex_enter(&schpc_p->schpc_mutex);

	slot = schpc_slot_get_index(schpc_p, slot_hdl);

	if (!(schpc_p->schpc_slot[slot].state & SCHPC_SLOTSTATE_HPCINITED)) {
		SCHPC_DEBUG0(D_IOC_CONNECT, "schpc_connect - HPC Not Inited");
		mutex_exit(&schpc_p->schpc_mutex);
		return (HPC_ERR_FAILED);
	}

	/*
	 * Check to see if the slot is already connected.
	 */
	if (schpc_p->schpc_slot[slot].state & SCHPC_SLOTSTATE_CONNECTED) {
		mutex_exit(&schpc_p->schpc_mutex);
		return (0);
	}

	/*
	 * Block if another thread is executing a HPC command.
	 */
	while (schpc_p->schpc_slot[slot].state & SCHPC_SLOTSTATE_EXECUTING) {
		cv_wait(&schpc_p->schpc_cv, &schpc_p->schpc_mutex);
	}

	schpc_p->schpc_slot[slot].state |= SCHPC_SLOTSTATE_EXECUTING;

	mutex_exit(&schpc_p->schpc_mutex);

	expander = schpc_p->schpc_slot[slot].expander; /* get expander */
	board = schpc_p->schpc_slot[slot].board; /* get board */

	SCHPC_DEBUG3(D_IOC_CONNECT,
	    "schpc_connect Expander=%x Board=%x Slot=%x",
	    expander, board, SCHPC_SLOT_NUM(slot));


	if (!(schpc_p->schpc_slot[slot].state & SCHPC_SLOTSTATE_OCC_GOOD)) {
		cmn_err(CE_WARN, "schpc: Hot Plug - Unable to complete "
		    "connection on Expander %d Board %d Slot %d - "
		    "Ap_Id=%s : Occupant is in failed state",
		    expander, board, SCHPC_SLOT_NUM(slot),
		    schpc_p->schpc_slot[slot].ap_id);

		/* Fault LED should already be illuminated */

		goto failed;
	}

	if (!(schpc_p->schpc_slot[slot].state & SCHPC_SLOTSTATE_REC_GOOD)) {
		cmn_err(CE_WARN, "schpc: Hot Plug - Unable to complete "
		    "connection on Expander %d Board %d Slot %d - "
		    "Ap_Id=%s : Receptacle is in failed state",
		    expander, board, SCHPC_SLOT_NUM(slot),
		    schpc_p->schpc_slot[slot].ap_id);

		/* Fault LED should already be illuminated */

		goto failed;
	}

	rval = schpc_getslotstatus(expander, board, slot, &getslot);

	if (rval) {
		/*
		 * System Controller/Mailbox failure.
		 */
		cmn_err(CE_WARN, "schpc - Hot Plug Connection Failed on "
		    "Expander %d Board %d PCI Slot %d - Ap_Id=%s : Unable to "
		    "Communicate with System Controller", expander, board,
		    SCHPC_SLOT_NUM(slot), schpc_p->schpc_slot[slot].ap_id);

		schpc_setslotled(expander, board, slot, FAULT_LED_ON);

		goto failed;
	}

	if (getslot.slot_replystatus != PCIMSG_REPLY_GOOD) {

		cmn_err(CE_WARN, "schpc - Hot Plug Connection Failed on "
		    "Expander %d Board %d PCI Slot %d - Ap_Id=%s : Unable to "
		    "Read Slot Status", expander, board,
		    SCHPC_SLOT_NUM(slot), schpc_p->schpc_slot[slot].ap_id);

		schpc_setslotled(expander, board, slot, FAULT_LED_ON);

		goto failed;
	}

	if (getslot.slot_empty) {
		/*
		 * If the slot is empty - fail the connection request.
		 */
		goto failed;
	}

	SCHPC_DEBUG3(D_FREQCHG, "Slot %d - slot_freq_setting %d "
	    "slot_freq_cap %d", slot, getslot.slot_freq_setting,
	    getslot.slot_freq_cap);

	if (!schpc_is_freq_switchable(slot) &&
	    (getslot.slot_freq_setting > getslot.slot_freq_cap)) {

		cmn_err(CE_WARN, "schpc - Hot Plug Connection Failed "
		    "on Expander %d Board %d PCI Slot %d - Ap_Id=%s : "
		    "Bus Speed Mismatch", expander,
		    board, SCHPC_SLOT_NUM(slot),
		    schpc_p->schpc_slot[slot].ap_id);

		schpc_setslotled(expander, board, slot, FAULT_LED_ON);

		goto failed;
	}

	if (schpc_is_leaf_reset_required(slot) &&
	    (schpc_p->schpc_slot[slot].saved_regs == NULL)) {

		SCHPC_DEBUG1(D_FREQCHG, "Slot %d - Save Regs before connect",
		    slot);

		/*
		 * A prior disconnect had not saved off the leaf so lets
		 * save it now. This is probably due to the domain being
		 * booted with a slot with no cassette.
		 */
		if (schpc_save_leaf(slot) != 0) {
			cmn_err(CE_WARN, "schpc - Unable to save leaf regs on "

			    "Expander %d Board %d PCI Slot %d - Ap_Id=%s : ",
			    expander, board, slot & 3,
			    schpc_p->schpc_slot[slot].ap_id);

			schpc_setslotled(expander, board, slot, FAULT_LED_ON);

			goto failed;
		}
	}

	/*
	 * Initialize Set Slot Command.
	 */
	schpc_init_setslot_message(&setslot);

	setslot.slot_power_on = PCIMSG_ON;	   /* Turn slot power on */

	setslot.slot_led_fault = PCIMSG_LED_FLASH; /* Flash Fault LED */

	rval = schpc_setslotstatus(expander, board, slot, &setslot);

	if (rval != 0) {
		/*
		 * System Controller/Mailbox failure.
		 */
		cmn_err(CE_WARN, "schpc - Hot Plug Connection Failed on "
		    "Expander %d Board %d PCI Slot %d - Ap_Id=%s : Unable to "
		    "Communicate with System Controller", expander, board,
		    SCHPC_SLOT_NUM(slot), schpc_p->schpc_slot[slot].ap_id);

		schpc_setslotled(expander, board, slot, FAULT_LED_ON);

		goto failed;
	}

	if (setslot.slot_replystatus == PCIMSG_REPLY_GOOD) {

		/*
		 * The Request was successfully completed.
		 */

		SCHPC_DEBUG0(D_IOC_CONNECT, "schpc_connect() - setslotstatus "
		    "succeeded");

		/*
		 * Need to check HEALTHY# signal.
		 */
		rval = schpc_getslotstatus(expander, board, slot, &getslot);

		if (rval) {
			/*
			 * System Controller/Mailbox failure.
			 */
			cmn_err(CE_WARN, "schpc - Hot Plug Connection Failed "
			    "on Expander %d Board %d PCI Slot %d - Ap_Id=%s : "
			    "Unable to Communicate with System Controller",
			    expander, board, SCHPC_SLOT_NUM(slot),
			    schpc_p->schpc_slot[slot].ap_id);

			schpc_setslotled(expander, board, slot, FAULT_LED_ON);

			goto failed;
		}

		if (getslot.slot_replystatus != PCIMSG_REPLY_GOOD) {

			cmn_err(CE_WARN, "schpc - Hot Plug Connection Failed "
			    "on Expander %d Board %d PCI Slot %d - Ap_Id=%s : "
			    "Unable to Read Slot Status", expander, board,
			    SCHPC_SLOT_NUM(slot),
			    schpc_p->schpc_slot[slot].ap_id);

			schpc_setslotled(expander, board, slot, FAULT_LED_ON);

			goto failed;
		}

		if ((getslot.slot_powergood != PCIMSG_ON) ||
		    (getslot.slot_powerfault == PCIMSG_ON)) {
			cmn_err(CE_WARN, "schpc - Hot Plug Connection Failed "
			    "on Expander %d Board %d PCI Slot %d - Ap_Id=%s : "
			    "Power failure detected", expander, board,
			    SCHPC_SLOT_NUM(slot),
			    schpc_p->schpc_slot[slot].ap_id);

			/*
			 * Initialize Set Slot Command.
			 */
			schpc_init_setslot_message(&setslot);

			/*
			 * Turn slot power off.
			 */
			setslot.slot_power_off = PCIMSG_ON;

			(void) schpc_setslotstatus(expander, board,
			    slot, &setslot);

			schpc_setslotled(expander, board, slot,
			    (SERVICE_LED_ON | FAULT_LED_ON));

			goto failed;
		}

		if (!getslot.slot_HEALTHY) {
			cmn_err(CE_WARN, "schpc - Hot Plug Connection Failed "
			    "on Expander %d Board %d PCI Slot %d - Ap_Id=%s : "
			    "Adapter did not assert HEALTHY#", expander, board,
			    SCHPC_SLOT_NUM(slot),
			    schpc_p->schpc_slot[slot].ap_id);

			/*
			 * Initialize Set Slot Command.
			 */
			schpc_init_setslot_message(&setslot);

			/*
			 * Turn slot power off.
			 */
			setslot.slot_power_off = PCIMSG_ON;

			(void) schpc_setslotstatus(expander, board, slot,
			    &setslot);

			schpc_setslotled(expander, board, slot,
			    (SERVICE_LED_ON | FAULT_LED_ON));

			goto failed;
		}

		/*
		 * Initialize Set Slot Command.
		 */
		schpc_init_setslot_message(&setslot);

		/*
		 * Start monitoring ENUM# and HEALTHY#
		 */
		setslot.slot_enable_HEALTHY = PCIMSG_ON;
		setslot.slot_enable_ENUM = PCIMSG_ON;

		rval = schpc_setslotstatus(expander, board, slot, &setslot);

		if (rval != 0) {
			/*
			 * System Controller/Mailbox failure.
			 */
			cmn_err(CE_WARN, "schpc - Hot Plug Connection Failed "
			    "on Expander %d Board %d PCI Slot %d - Ap_Id=%s : "
			    "Unable to Communicate with System Controller",
			    expander, board, SCHPC_SLOT_NUM(slot),
			    schpc_p->schpc_slot[slot].ap_id);

			schpc_setslotled(expander, board, slot, FAULT_LED_ON);

			goto failed;
		}
		if (setslot.slot_replystatus == PCIMSG_REPLY_GOOD) {

			int		freq;
			find_dev_t	find_dev;

			/*
			 * The Request was successfully completed.
			 */

			SCHPC_DEBUG0(D_IOC_CONNECT,
			    "schpc_connect() - setslotstatus succeeded");

			schpc_p->schpc_slot[slot].state |=
			    SCHPC_SLOTSTATE_CONNECTED;

			schpc_setslotled(expander, board, slot,
			    (POWER_LED_ON | SERVICE_LED_OFF | FAULT_LED_OFF));

			find_dev.cname = schpc_p->schpc_slot[slot].nexus_path;
			find_dev.caddr = (char *)kmem_alloc(MAXPATHLEN,
			    KM_SLEEP);
			find_dev.dip = NULL;

			/* root node doesn't have to be held */
			ddi_walk_devs(ddi_root_node(), schpc_find_dip,
			    &find_dev);
			if (find_dev.dip != NULL) {
				/*
				 * Update the clock-frequency property to
				 * reflect the new slot-frequency.
				 */
				freq = schpc_slot_freq(&getslot);
				SCHPC_DEBUG2(D_FREQCHG,
				    "schpc_connect: updating dip=%p freq=%dHZ",
				    (void *)find_dev.dip, freq);
				if (ndi_prop_update_int(DDI_DEV_T_NONE,
				    find_dev.dip, "clock-frequency", freq)
				    != DDI_SUCCESS) {
					cmn_err(CE_WARN,
					    "schpc: - failed to update "
					    "clock-frequency property for %s",
					    find_dev.cname);
				}
				ndi_rele_devi(find_dev.dip);
			} else {
				cmn_err(CE_WARN,
				    "schpc: couldn't find dip for %s ",
				    find_dev.cname);
			}
			kmem_free(find_dev.caddr, MAXPATHLEN);

			mutex_enter(&schpc_p->schpc_mutex);
			schpc_p->schpc_slot[slot].state &=
			    ~SCHPC_SLOTSTATE_EXECUTING;

			/*
			 * If leaf registers were saved off, then they
			 * need to be restored.
			 */
			schpc_restore_leaf(slot);

			/*
			 * Since the device saw a PCI Reset, we need to
			 * wait 2^25 clock cycles before the first
			 * Configuration access. The worst case is 33MHz,
			 * which is a 1 second wait.
			 */
			drv_usecwait(1000000);

			cv_signal(&schpc_p->schpc_cv);
			mutex_exit(&schpc_p->schpc_mutex);

			return (0);
		} else {
			/*
			 * The System Controller Rejected the
			 * connection request.
			 */
			cmn_err(CE_WARN, "schpc - Hot Plug Connection Failed "
			    "on Expander %d Board %d PCI Slot %d - Ap_Id=%s :"
			    "System Controller failed connection request",
			    expander, board, SCHPC_SLOT_NUM(slot),
			    schpc_p->schpc_slot[slot].ap_id);

			schpc_setslotled(expander, board, slot, FAULT_LED_ON);

			goto failed;
		}
	}

	/*
	 * The System Controller Rejected the connection request.
	 */
	cmn_err(CE_WARN, "schpc - Hot Plug Connection Failed on "
	    "Expander %d Board %d PCI Slot %d - Ap_Id=%s : System Controller "
	    "failed connection request", expander, board, SCHPC_SLOT_NUM(slot),
	    schpc_p->schpc_slot[slot].ap_id);

	schpc_setslotled(expander, board, slot, FAULT_LED_ON);

failed:
	mutex_enter(&schpc_p->schpc_mutex);
	schpc_p->schpc_slot[slot].state &=
	    ~SCHPC_SLOTSTATE_EXECUTING;
	cv_signal(&schpc_p->schpc_cv);
	mutex_exit(&schpc_p->schpc_mutex);

	return (HPC_ERR_FAILED);
}

/*
 * schpc_disconnect()
 *
 * Called by Hot Plug Services to disconnect a slot to the bus.
 */

/*ARGSUSED*/
static int
schpc_disconnect(caddr_t ops_arg, hpc_slot_t slot_hdl, void *data,
	uint_t flags)
{
	int		rval;
	int		expander, board, slot;
	pci_setslot_t	setslot;

	SCHPC_DEBUG2(D_IOC_CONNECT,
	    "schpc_disconnect( ops_arg=%p slot_hdl=%p)", (void *)ops_arg,
	    slot_hdl);

	mutex_enter(&schpc_p->schpc_mutex);

	slot = schpc_slot_get_index(schpc_p, slot_hdl);

	if (!(schpc_p->schpc_slot[slot].state & SCHPC_SLOTSTATE_HPCINITED)) {
		SCHPC_DEBUG0(D_IOC_CONNECT,
		    "schpc_disconnect - HPC Not Inited");
		mutex_exit(&schpc_p->schpc_mutex);
		return (HPC_ERR_FAILED);
	}

	/*
	 * Check to see if we are already disconnected.
	 */
	if (!(schpc_p->schpc_slot[slot].state & SCHPC_SLOTSTATE_CONNECTED)) {
		mutex_exit(&schpc_p->schpc_mutex);
		return (0);
	}

	/*
	 * Block if another thread is executing a HPC command.
	 */
	while (schpc_p->schpc_slot[slot].state & SCHPC_SLOTSTATE_EXECUTING) {
		cv_wait(&schpc_p->schpc_cv, &schpc_p->schpc_mutex);
	}

	schpc_p->schpc_slot[slot].state |= SCHPC_SLOTSTATE_EXECUTING;

	mutex_exit(&schpc_p->schpc_mutex);

	expander = schpc_p->schpc_slot[slot].expander; /* get expander */
	board = schpc_p->schpc_slot[slot].board; /* get board */

	/*
	 * If a leaf reset is going to be asserted due to a mode/freq.
	 * change, then the leaf registers of the XMITS bridge will need
	 * to be saved off prior to the connect.
	 */
	if (schpc_is_leaf_reset_required(slot)) {
		if (schpc_save_leaf(slot) != 0) {

			cmn_err(CE_WARN, "schpc - Unable to save leaf regs on "
			    "Expander %d Board %d PCI Slot %d - Ap_Id=%s : ",
			    expander, board, slot & 3,
			    schpc_p->schpc_slot[slot].ap_id);

			schpc_setslotled(expander, board, slot, FAULT_LED_ON);

			goto failed;
		}
	}

	/*
	 * Initialize Set Slot Command.
	 */
	schpc_init_setslot_message(&setslot);

	setslot.slot_power_off = PCIMSG_ON;	   /* Turn Power Off */

	setslot.slot_led_fault = PCIMSG_LED_FLASH; /* Flash the Fault LED */

	setslot.slot_disable_ENUM = PCIMSG_ON;	   /* Mask the ENUM# signal */
	setslot.slot_disable_HEALTHY = PCIMSG_ON;  /* Mask the HEALTHY# sig */

	rval = schpc_setslotstatus(expander, board, slot, &setslot);

	SCHPC_DEBUG1(D_IOC_CONNECT, "schpc_disconnect() - "
	    "setslotstatus returned 0x%x", rval);

	if (rval != 0) {
		/*
		 * System Controller/Mailbox failure.
		 */
		cmn_err(CE_WARN, "schpc - Hot Plug Disconnection Failed on "
		    "Expander %d Board %d PCI Slot %d - Ap_Id=%s : Unable to "
		    "Communicate with System Controller", expander, board,
		    SCHPC_SLOT_NUM(slot), schpc_p->schpc_slot[slot].ap_id);

		schpc_setslotled(expander, board, slot, FAULT_LED_ON);

		goto failed;
	}

	SCHPC_DEBUG1(D_IOC_CONNECT, "schpc_disconnect() - "
	    "slot_replystatus returned 0x%x", setslot.slot_replystatus);

	if (setslot.slot_replystatus == PCIMSG_REPLY_GOOD) {

		/*
		 * The Request was successfully completed.
		 */
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_CONNECTED;

		schpc_setslotled(expander, board, slot,
		    (POWER_LED_OFF | SERVICE_LED_ON | FAULT_LED_OFF));

		SCHPC_DEBUG0(D_IOC_CONNECT,
		    "schpc_disconnect() - setslotstatus succeeded");

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		return (0);
	}
	/*
	 * System Controller/Mailbox failure.
	 */
	cmn_err(CE_WARN, "schpc - Hot Plug Disconnection Failed on "
	    "Expander %d Board %d PCI Slot %d - Ap_Id=%s : System Controller "
	    "failed disconnection request", expander, board,
	    SCHPC_SLOT_NUM(slot),
	    schpc_p->schpc_slot[slot].ap_id);

	schpc_setslotled(expander, board, slot, FAULT_LED_ON);

failed:
	schpc_restore_leaf(slot);
	mutex_enter(&schpc_p->schpc_mutex);
	schpc_p->schpc_slot[slot].state &=
	    ~SCHPC_SLOTSTATE_EXECUTING;
	cv_signal(&schpc_p->schpc_cv);
	mutex_exit(&schpc_p->schpc_mutex);

	return (HPC_ERR_FAILED);
}

/*
 * schpc_cpci_control
 *
 * Called by Hot Plug Services to perform a attachment point specific
 * on a Hot Pluggable Compact PCI Slot.
 */
/*ARGSUSED*/
static int
schpc_cpci_control(caddr_t ops_arg, hpc_slot_t slot_hdl, int request,
    caddr_t arg)
{
	int		rval;
	int		expander, board, slot;
	pci_setslot_t	setslot;
	pci_getslot_t   slotstatus;
	hpc_led_info_t	*hpc_led_info;

	SCHPC_DEBUG3(D_IOC_CONTROL,
	    "schpc_cpci_control(op_args=%p slot_hdl=%p request=%x)",
	    (void *)ops_arg, (void *)slot_hdl, request);

	mutex_enter(&schpc_p->schpc_mutex);

	slot = schpc_slot_get_index(schpc_p, slot_hdl);

	if (!(schpc_p->schpc_slot[slot].state & SCHPC_SLOTSTATE_HPCINITED)) {
		SCHPC_DEBUG0(D_IOC_CONNECT,
		    "schpc_disconnect - HPC Not Inited");
		mutex_exit(&schpc_p->schpc_mutex);
		return (HPC_ERR_FAILED);
	}

	/*
	 * Block if another thread is executing a HPC command.
	 */
	while (schpc_p->schpc_slot[slot].state & SCHPC_SLOTSTATE_EXECUTING) {
		cv_wait(&schpc_p->schpc_cv, &schpc_p->schpc_mutex);
	}

	schpc_p->schpc_slot[slot].state |= SCHPC_SLOTSTATE_EXECUTING;

	mutex_exit(&schpc_p->schpc_mutex);

	expander = schpc_p->schpc_slot[slot].expander; /* get expander */
	board = schpc_p->schpc_slot[slot].board; /* get board */

	/*
	 * Initialize Set Slot Command.
	 */
	schpc_init_setslot_message(&setslot);

	/*
	 * Initialize LED to last know state.
	 */
	switch (schpc_p->schpc_slot[slot].led.led_power) {
	case LED_ON:
		setslot.slot_led_power = PCIMSG_LED_ON;
		break;
	case LED_OFF:
		setslot.slot_led_power = PCIMSG_LED_OFF;
		break;
	case LED_FLASH:
		setslot.slot_led_power = PCIMSG_LED_FLASH;
		break;
	}

	switch (schpc_p->schpc_slot[slot].led.led_service) {
	case LED_ON:
		setslot.slot_led_service = PCIMSG_LED_ON;
		break;
	case LED_OFF:
		setslot.slot_led_service = PCIMSG_LED_OFF;
		break;
	case LED_FLASH:
		setslot.slot_led_service = PCIMSG_LED_FLASH;
		break;
	}

	switch (schpc_p->schpc_slot[slot].led.led_fault) {
	case LED_ON:
		setslot.slot_led_fault = PCIMSG_LED_ON;
		break;
	case LED_OFF:
		setslot.slot_led_fault = PCIMSG_LED_OFF;
		break;
	case LED_FLASH:
		setslot.slot_led_fault = PCIMSG_LED_FLASH;
		break;
	}

	switch (request) {

	case HPC_CTRL_GET_LED_STATE:
		SCHPC_DEBUG0(D_IOC_CONTROL, "schpc_cpci_control() - "
		    "HPC_CTRL_GET_LED_STATE");
		hpc_led_info = (hpc_led_info_t *)arg;

		switch (hpc_led_info->led) {
		case HPC_FAULT_LED:
			switch (schpc_p->schpc_slot[slot].led.led_fault) {
			case LED_OFF:
				hpc_led_info->state = HPC_LED_OFF;
				break;
			case LED_ON:
				hpc_led_info->state = HPC_LED_ON;
				break;
			case LED_FLASH:
				hpc_led_info->state = HPC_LED_BLINK;
				break;
			}
			break;

		case HPC_POWER_LED:
			switch (schpc_p->schpc_slot[slot].led.led_power) {
			case LED_OFF:
				hpc_led_info->state = HPC_LED_OFF;
				break;
			case LED_ON:
				hpc_led_info->state = HPC_LED_ON;
				break;
			case LED_FLASH:
				hpc_led_info->state = HPC_LED_BLINK;
				break;
			}
			break;
		case HPC_ATTN_LED:
			switch (schpc_p->schpc_slot[slot].led.led_fault) {
			case LED_OFF:
				hpc_led_info->state = HPC_LED_OFF;
				break;
			case LED_ON:
				hpc_led_info->state = HPC_LED_OFF;
				break;
			case LED_FLASH:
				hpc_led_info->state = HPC_LED_ON;
				break;
			}
			break;
		case HPC_ACTIVE_LED:
			switch (schpc_p->schpc_slot[slot].led.led_service) {
			case LED_OFF:
				hpc_led_info->state = HPC_LED_OFF;
				break;
			case LED_ON:
				hpc_led_info->state = HPC_LED_ON;
				break;
			case LED_FLASH:
				hpc_led_info->state = HPC_LED_BLINK;
				break;
			}
			break;
		default:
			SCHPC_DEBUG1(D_IOC_CONTROL, "schpc_cpci_control() - "
			    "Invalid LED %x", hpc_led_info->led);

			mutex_enter(&schpc_p->schpc_mutex);
			schpc_p->schpc_slot[slot].state &=
			    ~SCHPC_SLOTSTATE_EXECUTING;
			cv_signal(&schpc_p->schpc_cv);
			mutex_exit(&schpc_p->schpc_mutex);

			return (HPC_ERR_FAILED);
		}

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		return (0);

	case HPC_CTRL_SET_LED_STATE:
		hpc_led_info = (hpc_led_info_t *)arg;

		SCHPC_DEBUG1(D_IOC_CONTROL, "schpc_cpci_control() - "
		    "HPC_CTRL_SET_LED_STATE hpc_led_info=%p",
		    (void *)hpc_led_info);

		switch (hpc_led_info->led) {
		case HPC_FAULT_LED:
			switch (hpc_led_info->state) {
			case HPC_LED_OFF:
				schpc_p->schpc_slot[slot].led.led_fault =
				    LED_OFF;
				setslot.slot_led_fault = PCIMSG_LED_OFF;
				break;
			case HPC_LED_ON:
				schpc_p->schpc_slot[slot].led.led_fault =
				    LED_ON;
				setslot.slot_led_fault = PCIMSG_LED_ON;
				break;
			case HPC_LED_BLINK:
				schpc_p->schpc_slot[slot].led.led_fault =
				    LED_FLASH;
				setslot.slot_led_fault = PCIMSG_LED_FLASH;
				break;
			}
			break;
		case HPC_POWER_LED:
			switch (hpc_led_info->state) {
			case HPC_LED_OFF:
				schpc_p->schpc_slot[slot].led.led_power =
				    LED_OFF;
				setslot.slot_led_power = PCIMSG_LED_OFF;
				break;
			case HPC_LED_ON:
				schpc_p->schpc_slot[slot].led.led_power =
				    LED_ON;
				setslot.slot_led_power = PCIMSG_LED_ON;
				break;
			case HPC_LED_BLINK:
				schpc_p->schpc_slot[slot].led.led_power =
				    LED_FLASH;
				setslot.slot_led_power = PCIMSG_LED_FLASH;
				break;
			}
			break;
		case HPC_ATTN_LED:
			switch (hpc_led_info->state) {
			case HPC_LED_OFF:
				schpc_p->schpc_slot[slot].led.led_fault =
				    LED_OFF;
				setslot.slot_led_fault = PCIMSG_LED_OFF;
				break;
			case HPC_LED_ON:
				schpc_p->schpc_slot[slot].led.led_fault =
				    LED_FLASH;
				setslot.slot_led_fault = PCIMSG_LED_FLASH;
				break;
			case HPC_LED_BLINK:
				schpc_p->schpc_slot[slot].led.led_fault =
				    LED_FLASH;
				setslot.slot_led_fault = PCIMSG_LED_FLASH;
				break;
			}
			break;
		case HPC_ACTIVE_LED:
			switch (hpc_led_info->state) {
			case HPC_LED_OFF:
				schpc_p->schpc_slot[slot].led.led_service =
				    LED_OFF;
				setslot.slot_led_service = PCIMSG_LED_OFF;
				break;
			case HPC_LED_ON:
				schpc_p->schpc_slot[slot].led.led_service =
				    LED_ON;
				setslot.slot_led_service = PCIMSG_LED_ON;
				break;
			case HPC_LED_BLINK:
				schpc_p->schpc_slot[slot].led.led_service =
				    LED_FLASH;
				setslot.slot_led_service = PCIMSG_LED_FLASH;
				break;
			}
			break;
		default:
			mutex_enter(&schpc_p->schpc_mutex);
			schpc_p->schpc_slot[slot].state &=
			    ~SCHPC_SLOTSTATE_EXECUTING;
			cv_signal(&schpc_p->schpc_cv);
			mutex_exit(&schpc_p->schpc_mutex);

			return (0);
		}

		(void) schpc_setslotstatus(expander, board, slot, &setslot);

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		return (0);

	case HPC_CTRL_GET_SLOT_STATE: {
		hpc_slot_state_t	*hpc_slot_state;

		hpc_slot_state = (hpc_slot_state_t *)arg;

		SCHPC_DEBUG1(D_IOC_CONTROL, "schpc_cpci_control() - "
		    "HPC_CTRL_GET_SLOT_STATE hpc_slot_state=%p",
		    (void *)hpc_slot_state);

		rval = schpc_getslotstatus(expander, board, slot, &slotstatus);

		if (!rval) {

			if (slotstatus.slot_replystatus != PCIMSG_REPLY_GOOD) {
				return (HPC_ERR_FAILED);
			}

			if (slotstatus.slot_empty == PCIMSG_ON) {
				*hpc_slot_state = HPC_SLOT_EMPTY;
				SCHPC_DEBUG0(D_IOC_CONTROL, "Slot Empty");
			} else if (slotstatus.slot_power_on == PCIMSG_ON) {
				*hpc_slot_state = HPC_SLOT_CONNECTED;
				SCHPC_DEBUG0(D_IOC_CONTROL, "Slot Connected");
				schpc_p->schpc_slot[slot].state |=
				    SCHPC_SLOTSTATE_CONNECTED;
			} else {
				*hpc_slot_state = HPC_SLOT_DISCONNECTED;
				SCHPC_DEBUG0(D_IOC_CONTROL,
				    "Slot Disconnected");
				schpc_p->schpc_slot[slot].state &=
				    ~SCHPC_SLOTSTATE_CONNECTED;
			}
		} else {
			SCHPC_DEBUG0(D_IOC_CONTROL, "Mailbox Command failed");

			mutex_enter(&schpc_p->schpc_mutex);
			schpc_p->schpc_slot[slot].state &=
			    ~SCHPC_SLOTSTATE_EXECUTING;
			cv_signal(&schpc_p->schpc_cv);
			mutex_exit(&schpc_p->schpc_mutex);

			return (HPC_ERR_FAILED);
		}

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		return (0);
	}
	case HPC_CTRL_GET_BOARD_TYPE: {
		hpc_board_type_t	*hpc_board_type;

		hpc_board_type = (hpc_board_type_t *)arg;

		SCHPC_DEBUG0(D_IOC_CONTROL, "schpc_cpci_control() - "
		    "HPC_CTRL_GET_BOARD_TYPE");

		/*
		 * The HPC driver does not know what board type
		 * is plugged in.
		 */
		*hpc_board_type = HPC_BOARD_CPCI_HS;

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		return (0);

	}
	case HPC_CTRL_DEV_CONFIGURED:
		SCHPC_DEBUG0(D_IOC_CONTROL, "schpc_cpci_control() - "
		    "HPC_CTRL_DEV_CONFIGURED");

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		return (0);

	case HPC_CTRL_DEV_UNCONFIGURED:
		SCHPC_DEBUG0(D_IOC_CONTROL, "schpc_cpci_control() - "
		    "HPC_CTRL_DEV_UNCONFIGURED");

		if (schpc_p->schpc_slot[slot].state & SCHPC_SLOTSTATE_ENUM) {
			/*
			 * When the occupant is unconfigured, power
			 * down the slot.
			 */
			rval = schpc_disconnect((caddr_t)schpc_p,
			    schpc_p->schpc_slot[slot].slot_handle,
			    0, 0);

			schpc_p->schpc_slot[slot].state &=
			    ~SCHPC_SLOTSTATE_ENUM;
		}

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		return (0);

	case HPC_CTRL_ENABLE_AUTOCFG:
		SCHPC_DEBUG0(D_IOC_CONTROL, "schpc_cpci_control() - "
		    "HPC_CTRL_ENABLE_AUTOCFG");

		schpc_p->schpc_slot[slot].state |=
		    SCHPC_SLOTSTATE_AUTOCFG_ENABLE;

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		return (0);

	case HPC_CTRL_DISABLE_AUTOCFG:
		SCHPC_DEBUG0(D_IOC_CONTROL, "schpc_cpci_control() - "
		    "HPC_CTRL_DISABLE_AUTOCFG");
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_AUTOCFG_ENABLE;

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		return (0);

	case HPC_CTRL_DISABLE_ENUM:
		SCHPC_DEBUG0(D_IOC_CONTROL, "schpc_cpci_control() - "
		    "HPC_CTRL_DISABLE_ENUM");

		setslot.slot_disable_ENUM = PCIMSG_ON;

		rval = schpc_setslotstatus(expander, board, slot, &setslot);

		if (rval)
			rval = HPC_ERR_FAILED;

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		return (rval);

	case HPC_CTRL_ENABLE_ENUM:
		SCHPC_DEBUG0(D_IOC_CONTROL, "schpc_cpci_control() - "
		    "HPC_CTRL_ENABLE_ENUM");

		setslot.slot_enable_ENUM = PCIMSG_ON;

		rval = schpc_setslotstatus(expander, board, slot, &setslot);

		if (rval)
			rval = HPC_ERR_FAILED;

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		return (rval);

	default:
		SCHPC_DEBUG0(D_IOC_CONTROL, "schpc_cpci_control() - "
		    "****NOT SUPPORTED CONTROL CMD");

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		return (HPC_ERR_NOTSUPPORTED);
	}
}

/*
 * schpc_pci_control
 *
 * Called by Hot Plug Services to perform a attachment point specific
 * on a Hot Pluggable Standard PCI Slot.
 */
/*ARGSUSED*/
static int
schpc_pci_control(caddr_t ops_arg, hpc_slot_t slot_hdl, int request,
    caddr_t arg)
{
	int		rval;
	int		expander, board, slot;
	pci_setslot_t	setslot;
	pci_getslot_t   slotstatus;
	hpc_led_info_t	*hpc_led_info;

	SCHPC_DEBUG3(D_IOC_CONTROL,
	    "schpc_pci_control(op_args=%p slot_hdl=%p request=%x)",
	    (void *)ops_arg, (void *)slot_hdl, request);

	mutex_enter(&schpc_p->schpc_mutex);

	slot = schpc_slot_get_index(schpc_p, slot_hdl);

	if (!(schpc_p->schpc_slot[slot].state & SCHPC_SLOTSTATE_HPCINITED)) {
		SCHPC_DEBUG0(D_IOC_CONNECT,
		    "schpc_disconnect - HPC Not Inited");
		mutex_exit(&schpc_p->schpc_mutex);
		return (HPC_ERR_FAILED);
	}

	/*
	 * Block if another thread is executing a HPC command.
	 */
	while (schpc_p->schpc_slot[slot].state & SCHPC_SLOTSTATE_EXECUTING) {
		cv_wait(&schpc_p->schpc_cv, &schpc_p->schpc_mutex);
	}

	schpc_p->schpc_slot[slot].state |= SCHPC_SLOTSTATE_EXECUTING;

	mutex_exit(&schpc_p->schpc_mutex);

	expander = schpc_p->schpc_slot[slot].expander; /* get expander */
	board = schpc_p->schpc_slot[slot].board; /* get board */

	/*
	 * Initialize Set Slot Command.
	 */
	schpc_init_setslot_message(&setslot);

	/*
	 * Initialize LED to last know state.
	 */
	switch (schpc_p->schpc_slot[slot].led.led_power) {
	case LED_ON:
		setslot.slot_led_power = PCIMSG_LED_ON;
		break;
	case LED_OFF:
		setslot.slot_led_power = PCIMSG_LED_OFF;
		break;
	case LED_FLASH:
		setslot.slot_led_power = PCIMSG_LED_FLASH;
		break;
	}

	switch (schpc_p->schpc_slot[slot].led.led_service) {
	case LED_ON:
		setslot.slot_led_service = PCIMSG_LED_ON;
		break;
	case LED_OFF:
		setslot.slot_led_service = PCIMSG_LED_OFF;
		break;
	case LED_FLASH:
		setslot.slot_led_service = PCIMSG_LED_FLASH;
		break;
	}

	switch (schpc_p->schpc_slot[slot].led.led_fault) {
	case LED_ON:
		setslot.slot_led_fault = PCIMSG_LED_ON;
		break;
	case LED_OFF:
		setslot.slot_led_fault = PCIMSG_LED_OFF;
		break;
	case LED_FLASH:
		setslot.slot_led_fault = PCIMSG_LED_FLASH;
		break;
	}

	switch (request) {


	case HPC_CTRL_GET_SLOT_STATE: {
		hpc_slot_state_t	*hpc_slot_state;

		hpc_slot_state = (hpc_slot_state_t *)arg;

		SCHPC_DEBUG1(D_IOC_CONTROL, "schpc_pci_control() - "
		    "HPC_CTRL_GET_SLOT_STATE hpc_slot_state=%p",
		    (void *)hpc_slot_state);

		rval = schpc_getslotstatus(expander, board, slot, &slotstatus);

		if (!rval) {

			if (slotstatus.slot_replystatus != PCIMSG_REPLY_GOOD) {

				mutex_enter(&schpc_p->schpc_mutex);
				schpc_p->schpc_slot[slot].state &=
				    ~SCHPC_SLOTSTATE_EXECUTING;
				cv_signal(&schpc_p->schpc_cv);
				mutex_exit(&schpc_p->schpc_mutex);

				return (HPC_ERR_FAILED);
			}

			if (slotstatus.slot_empty == PCIMSG_ON) {
				*hpc_slot_state = HPC_SLOT_EMPTY;
				SCHPC_DEBUG0(D_IOC_CONTROL, "Slot Empty");
			} else if (slotstatus.slot_power_on == PCIMSG_ON) {
				*hpc_slot_state = HPC_SLOT_CONNECTED;
				SCHPC_DEBUG0(D_IOC_CONTROL, "Slot Connected");
				schpc_p->schpc_slot[slot].state |=
				    SCHPC_SLOTSTATE_CONNECTED;
			} else {
				*hpc_slot_state = HPC_SLOT_DISCONNECTED;
				SCHPC_DEBUG0(D_IOC_CONTROL,
				    "Slot Disconnected");
				schpc_p->schpc_slot[slot].state &=
				    ~SCHPC_SLOTSTATE_CONNECTED;
			}
		} else {
			SCHPC_DEBUG0(D_IOC_CONTROL, "Mailbox Command failed");

			mutex_enter(&schpc_p->schpc_mutex);
			schpc_p->schpc_slot[slot].state &=
			    ~SCHPC_SLOTSTATE_EXECUTING;
			cv_signal(&schpc_p->schpc_cv);
			mutex_exit(&schpc_p->schpc_mutex);

			return (HPC_ERR_FAILED);
		}

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		return (0);
	}
	case HPC_CTRL_GET_BOARD_TYPE: {
		hpc_board_type_t	*hpc_board_type;

		hpc_board_type = (hpc_board_type_t *)arg;

		SCHPC_DEBUG0(D_IOC_CONTROL, "schpc_pci_control() - "
		    "HPC_CTRL_GET_BOARD_TYPE");


		/*
		 * The HPC driver does not know what board type
		 * is plugged in.
		 */
		*hpc_board_type = HPC_BOARD_PCI_HOTPLUG;

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		return (0);

	}
	case HPC_CTRL_DEV_UNCONFIG_START:
	case HPC_CTRL_DEV_CONFIG_START:
	case HPC_CTRL_DEV_CONFIGURED:
	case HPC_CTRL_DEV_UNCONFIGURED:
		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		return (0);

	case HPC_CTRL_GET_LED_STATE:
		SCHPC_DEBUG0(D_IOC_CONTROL, "schpc_pci_control() - "
		    "HPC_CTRL_GET_LED_STATE");
		hpc_led_info = (hpc_led_info_t *)arg;

		switch (hpc_led_info->led) {
		case HPC_FAULT_LED:
			switch (schpc_p->schpc_slot[slot].led.led_fault) {
			case LED_OFF:
				hpc_led_info->state = HPC_LED_OFF;
				break;
			case LED_ON:
				hpc_led_info->state = HPC_LED_ON;
				break;
			case LED_FLASH:
				hpc_led_info->state = HPC_LED_BLINK;
				break;
			}
			break;

		case HPC_POWER_LED:
			switch (schpc_p->schpc_slot[slot].led.led_power) {
			case LED_OFF:
				hpc_led_info->state = HPC_LED_OFF;
				break;
			case LED_ON:
				hpc_led_info->state = HPC_LED_ON;
				break;
			case LED_FLASH:
				hpc_led_info->state = HPC_LED_BLINK;
				break;
			}
			break;
		case HPC_ATTN_LED:
			switch (schpc_p->schpc_slot[slot].led.led_fault) {
			case LED_OFF:
				hpc_led_info->state = HPC_LED_OFF;
				break;
			case LED_ON:
				hpc_led_info->state = HPC_LED_OFF;
				break;
			case LED_FLASH:
				hpc_led_info->state = HPC_LED_ON;
				break;
			}
			break;
		case HPC_ACTIVE_LED:
			switch (schpc_p->schpc_slot[slot].led.led_service) {
			case LED_OFF:
				hpc_led_info->state = HPC_LED_OFF;
				break;
			case LED_ON:
				hpc_led_info->state = HPC_LED_ON;
				break;
			case LED_FLASH:
				hpc_led_info->state = HPC_LED_BLINK;
				break;
			}
			break;
		default:
			SCHPC_DEBUG1(D_IOC_CONTROL, "schpc_pci_control() - "
			    "Invalid LED %x", hpc_led_info->led);

			mutex_enter(&schpc_p->schpc_mutex);
			schpc_p->schpc_slot[slot].state &=
			    ~SCHPC_SLOTSTATE_EXECUTING;
			cv_signal(&schpc_p->schpc_cv);
			mutex_exit(&schpc_p->schpc_mutex);

			return (HPC_ERR_FAILED);
		}

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		return (0);

	case HPC_CTRL_SET_LED_STATE:
		hpc_led_info = (hpc_led_info_t *)arg;

		SCHPC_DEBUG1(D_IOC_CONTROL, "schpc_pci_control() - "
		    "HPC_CTRL_SET_LED_STATE hpc_led_info=%p",
		    (void *)hpc_led_info);

		switch (hpc_led_info->led) {
		case HPC_FAULT_LED:
			switch (hpc_led_info->state) {
			case HPC_LED_OFF:
				schpc_p->schpc_slot[slot].led.led_fault =
				    LED_OFF;
				setslot.slot_led_fault = PCIMSG_LED_OFF;
				break;
			case HPC_LED_ON:
				schpc_p->schpc_slot[slot].led.led_fault =
				    LED_ON;
				setslot.slot_led_fault = PCIMSG_LED_ON;
				break;
			case HPC_LED_BLINK:
				schpc_p->schpc_slot[slot].led.led_fault =
				    LED_FLASH;
				setslot.slot_led_fault = PCIMSG_LED_FLASH;
				break;
			}
			break;
		case HPC_POWER_LED:
			switch (hpc_led_info->state) {
			case HPC_LED_OFF:
				schpc_p->schpc_slot[slot].led.led_power =
				    LED_OFF;
				setslot.slot_led_power = PCIMSG_LED_OFF;
				break;
			case HPC_LED_ON:
				schpc_p->schpc_slot[slot].led.led_power =
				    LED_ON;
				setslot.slot_led_power = PCIMSG_LED_ON;
				break;
			case HPC_LED_BLINK:
				schpc_p->schpc_slot[slot].led.led_power =
				    LED_FLASH;
				setslot.slot_led_power = PCIMSG_LED_FLASH;
				break;
			}
			break;
		case HPC_ATTN_LED:
			switch (hpc_led_info->state) {
			case HPC_LED_OFF:
				schpc_p->schpc_slot[slot].led.led_fault =
				    LED_OFF;
				setslot.slot_led_fault = PCIMSG_LED_OFF;
				break;
			case HPC_LED_ON:
				schpc_p->schpc_slot[slot].led.led_fault =
				    LED_FLASH;
				setslot.slot_led_fault = PCIMSG_LED_FLASH;
				break;
			case HPC_LED_BLINK:
				schpc_p->schpc_slot[slot].led.led_fault =
				    LED_FLASH;
				setslot.slot_led_fault = PCIMSG_LED_FLASH;
				break;
			}
			break;
		case HPC_ACTIVE_LED:
			switch (hpc_led_info->state) {
			case HPC_LED_OFF:
				schpc_p->schpc_slot[slot].led.led_service =
				    LED_OFF;
				setslot.slot_led_service = PCIMSG_LED_OFF;
				break;
			case HPC_LED_ON:
				schpc_p->schpc_slot[slot].led.led_service =
				    LED_ON;
				setslot.slot_led_service = PCIMSG_LED_ON;
				break;
			case HPC_LED_BLINK:
				schpc_p->schpc_slot[slot].led.led_service =
				    LED_FLASH;
				setslot.slot_led_service = PCIMSG_LED_FLASH;
				break;
			}
			break;
		default:
			mutex_enter(&schpc_p->schpc_mutex);
			schpc_p->schpc_slot[slot].state &=
			    ~SCHPC_SLOTSTATE_EXECUTING;
			cv_signal(&schpc_p->schpc_cv);
			mutex_exit(&schpc_p->schpc_mutex);

			return (0);
		}

		(void) schpc_setslotstatus(expander, board, slot, &setslot);

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		return (0);

	case HPC_CTRL_ENABLE_AUTOCFG:
		SCHPC_DEBUG0(D_IOC_CONTROL, "schpc_pci_control() - "
		    "HPC_CTRL_ENABLE_AUTOCFG");

		schpc_p->schpc_slot[slot].state |=
		    SCHPC_SLOTSTATE_AUTOCFG_ENABLE;

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		return (0);

	case HPC_CTRL_DISABLE_AUTOCFG:
		SCHPC_DEBUG0(D_IOC_CONTROL, "schpc_pci_control() - "
		    "HPC_CTRL_DISABLE_AUTOCFG");
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_AUTOCFG_ENABLE;

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		return (0);

	case HPC_CTRL_DISABLE_ENUM:
	case HPC_CTRL_ENABLE_ENUM:
	default:
		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		return (HPC_ERR_NOTSUPPORTED);
	}
}

/*
 * schpc_test
 *
 * Tests the slot.
 */
/*ARGSUSED*/
static void
schpc_test(caddr_t ops_arg, int slot, void *data, uint_t flags)
{
	pci_getslot_t	slotstatus;
	pci_setslot_t	setslot;
	int		expander, board;
	int		rval;
	int		retry = 1;

	SCHPC_DEBUG2(D_IOC_TEST, "schpc_test(op_args=%p slot=%x)",
	    (void *)ops_arg, SCHPC_SLOT_NUM(slot));

	SCHPC_DEBUG3(D_IOC_TEST,
	    "    schpc_test() Expander=%d Board=%d Slot=%d",
	    schpc_p->schpc_slot[slot].expander,
	    schpc_p->schpc_slot[slot].board, SCHPC_SLOT_NUM(slot));

	expander = schpc_p->schpc_slot[slot].expander;
	board = schpc_p->schpc_slot[slot].board;

restart_test:
	/*
	 * Initial the slot with its occupant and receptacle in good condition.
	 */
	schpc_p->schpc_slot[slot].state |=  SCHPC_SLOTSTATE_REC_GOOD;
	schpc_p->schpc_slot[slot].state |=  SCHPC_SLOTSTATE_OCC_GOOD;


	rval = schpc_getslotstatus(expander, board, slot, &slotstatus);

	if (rval) {
		/*
		 * System Controller/Mailbox failure.
		 */
		cmn_err(CE_WARN, "schpc - Hot Plug Slot Test Failed on "
		    "Expander %d Board %d PCI Slot %d - Ap_Id=%s : Unable to "
		    "Communicate with System Controller", expander, board,
		    SCHPC_SLOT_NUM(slot), schpc_p->schpc_slot[slot].ap_id);

		schpc_p->schpc_slot[slot].state &=  ~SCHPC_SLOTSTATE_REC_GOOD;
		return;
	}

	if (slotstatus.slot_replystatus != PCIMSG_REPLY_GOOD) {

		cmn_err(CE_WARN, "schpc - Expander %d Board %d PCI Slot %d "
		    "is not hot pluggable\n", expander, board,
		    SCHPC_SLOT_NUM(slot));

		schpc_p->schpc_slot[slot].state &=  ~SCHPC_SLOTSTATE_REC_GOOD;
		return;
	}

	switch (slotstatus.slot_condition) {
	case PCIMSG_SLOTCOND_OCC_FAIL:
		cmn_err(CE_WARN, "schpc - Hot Plug Slot Test Failed on "
		    "Expander %d Board %d PCI Slot %d - Ap_Id=%s : "
		    "System Controller/Occupant Failed",
		    expander, board, SCHPC_SLOT_NUM(slot),
		    schpc_p->schpc_slot[slot].ap_id);

		schpc_setslotled(expander, board, slot,
		    (POWER_LED_OFF | SERVICE_LED_ON | FAULT_LED_ON));

		schpc_p->schpc_slot[slot].state &=  ~SCHPC_SLOTSTATE_OCC_GOOD;
		return;
	case PCIMSG_SLOTCOND_REC_FAIL:
		cmn_err(CE_WARN, "schpc - Hot Plug Slot Test Failed on "
		    "Expander %d Board %d PCI Slot %d - Ap_Id=%s : "
		    "System Controller/Receptacle Failed",
		    expander, board, SCHPC_SLOT_NUM(slot),
		    schpc_p->schpc_slot[slot].ap_id);

		schpc_setslotled(expander, board, slot,
		    (POWER_LED_OFF | SERVICE_LED_OFF | FAULT_LED_ON));

		schpc_p->schpc_slot[slot].state &=  ~SCHPC_SLOTSTATE_REC_GOOD;
		return;
	}

	if (slotstatus.slot_power_on) {
		schpc_p->schpc_slot[slot].led.led_power = PCIMSG_LED_ON;

		if (!slotstatus.slot_HEALTHY) {
			/*
			 * cPCI Adapter is not asserting HEALTHY#.
			 */
			cmn_err(CE_WARN, "schpc - Hot Plug Slot Test Failed on "
			    "Expander %d Board %d PCI Slot %d - Ap_Id=%s : "
			    "PCI adapter not HEALTHY", expander, board,
			    SCHPC_SLOT_NUM(slot),
			    schpc_p->schpc_slot[slot].ap_id);

			schpc_setslotled(expander, board, slot,
			    (POWER_LED_ON | SERVICE_LED_OFF | FAULT_LED_ON));

			schpc_p->schpc_slot[slot].state &=
			    ~SCHPC_SLOTSTATE_OCC_GOOD;

			return;
		}

		if (!slotstatus.slot_powergood) {
			/*
			 * PCI Power Input is not good.
			 */
			cmn_err(CE_WARN, "schpc - Hot Plug Slot Test Failed on "
			    "Expander %d Board %d PCI Slot %d - Ap_Id=%s : "
			    "System Controller PCI Power Input Not Good",
			    expander, board, SCHPC_SLOT_NUM(slot),
			    schpc_p->schpc_slot[slot].ap_id);

			schpc_setslotled(expander, board, slot,
			    (POWER_LED_ON | SERVICE_LED_OFF | FAULT_LED_ON));

			schpc_p->schpc_slot[slot].state &=
			    ~SCHPC_SLOTSTATE_OCC_GOOD;

			return;
		}

		if (slotstatus.slot_powerfault) {
			/*
			 * PCI Power Fault.
			 */
			cmn_err(CE_WARN, "schpc - Hot Plug Slot Test Failed on "
			    "Expander %d Board %d PCI Slot %d - Ap_Id=%s : "
			    "System Controller PCI Power Fault",
			    expander, board, SCHPC_SLOT_NUM(slot),
			    schpc_p->schpc_slot[slot].ap_id);

			schpc_setslotled(expander, board, slot,
			    (POWER_LED_ON | SERVICE_LED_OFF | FAULT_LED_ON));

			schpc_p->schpc_slot[slot].state &=
			    ~SCHPC_SLOTSTATE_OCC_GOOD;

			return;
		}
	}

	SCHPC_DEBUG0(D_IOC_TEST, "schpc_test() Test Successful - ret 0");

	/*
	 * Is the slot empty?
	 */
	if (slotstatus.slot_empty) {
		SCHPC_DEBUG0(D_IOC_TEST, "schpc_test() Slot Empty");

		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_PRESENT;

		if (slotstatus.slot_power_on) {

			SCHPC_DEBUG0(D_IOC_TEST, "schpc_test() Empty Slot "
			    "is powered ON");

			/*
			 * Tests will be retried once after powering off
			 * an empty slot.
			 */
			if (retry) {

				/*
				 * Turn off the slot and restart test.
				 */
				SCHPC_DEBUG0(D_IOC_TEST, "schpc_test() "
				    "Turning Empty Slot OFF");

				schpc_init_setslot_message(&setslot);
				setslot.slot_power_off = PCIMSG_ON;
				(void) schpc_setslotstatus(
				    expander, board, slot, &setslot);

				retry = 0;

				goto restart_test;
			}
		}
	} else {
		SCHPC_DEBUG0(D_IOC_TEST, "schpc_test() Adapter Present");

		if (!slotstatus.slot_power_on) {
			if (retry) {
				/*
				 * If there is a cassette present and the
				 * power is off, try turning the power on and
				 * restart the test. This allows access to
				 * the FRUID when an empty cassette is
				 * installed.
				 */
				SCHPC_DEBUG0(D_IOC_TEST,
				    "schpc_test() Power On Adapter");
				schpc_init_setslot_message(&setslot);
				setslot.slot_power_on = PCIMSG_ON;
				(void) schpc_setslotstatus(
				    expander, board, slot, &setslot);
				retry = 0;
				goto restart_test;
			}
		}

		schpc_p->schpc_slot[slot].state |=
		    SCHPC_SLOTSTATE_PRESENT;
	}

	/*
	 * Is the slot powered up?
	 */
	schpc_init_setslot_message(&setslot);

	if (slotstatus.slot_power_on) {
		SCHPC_DEBUG0(D_IOC_TEST, "schpc_test() Slot Power On");

		schpc_p->schpc_slot[slot].state |=
		    SCHPC_SLOTSTATE_CONNECTED;

		setslot.slot_led_power = PCIMSG_LED_ON;
		setslot.slot_led_service = PCIMSG_LED_OFF;
		setslot.slot_enable_ENUM = PCIMSG_ON;
		setslot.slot_enable_HEALTHY = PCIMSG_ON;
	} else {
		SCHPC_DEBUG0(D_IOC_TEST, "schpc_test() Slot Power Off");

		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_CONNECTED;

		setslot.slot_led_power = PCIMSG_LED_OFF;
		setslot.slot_led_service = PCIMSG_LED_ON;
		setslot.slot_disable_ENUM = PCIMSG_ON;
		setslot.slot_disable_HEALTHY = PCIMSG_ON;
	}

	setslot.slot_led_fault = PCIMSG_LED_OFF;

	(void) schpc_setslotstatus(expander, board, slot, &setslot);

	/*
	 * Save LED State.
	 */
	switch (setslot.slot_led_power) {
	case PCIMSG_LED_ON:
		schpc_p->schpc_slot[slot].led.led_power = LED_ON;
		break;
	case PCIMSG_LED_OFF:
		schpc_p->schpc_slot[slot].led.led_power = LED_OFF;
		break;
	case PCIMSG_LED_FLASH:
		schpc_p->schpc_slot[slot].led.led_power = LED_FLASH;
		break;
	}
	switch (setslot.slot_led_service) {
	case PCIMSG_LED_ON:
		schpc_p->schpc_slot[slot].led.led_service = LED_ON;
		break;
	case PCIMSG_LED_OFF:
		schpc_p->schpc_slot[slot].led.led_service = LED_OFF;
		break;
	case PCIMSG_LED_FLASH:
		schpc_p->schpc_slot[slot].led.led_service = LED_FLASH;
		break;
	}
	switch (setslot.slot_led_fault) {
	case PCIMSG_LED_ON:
		schpc_p->schpc_slot[slot].led.led_fault = LED_ON;
		break;
	case PCIMSG_LED_OFF:
		schpc_p->schpc_slot[slot].led.led_fault = LED_OFF;
		break;
	case PCIMSG_LED_FLASH:
		schpc_p->schpc_slot[slot].led.led_fault = LED_FLASH;
		break;
	}
}


/*
 * schpc_event_handler
 *
 * Placed on the schpc_event_taskq by schpc_event_filter when an
 * unsolicited MBOXSC_MSG_EVENT is received from the SC.  It handles
 * things like power insertion/removal, ENUM#, etc.
 */
static void
schpc_event_handler(void *arg)
{
	pci_getslot_t	slotstatus;
	uint8_t		expander, board, slot;
	int		rval;
	pcimsg_t *event = (pcimsg_t *)arg;

	/*
	 * OK, we got an event message. Since the event message only tells
	 * us something has changed and not changed to what, we need to get
	 * the current slot status to find how WHAT was change to WHAT.
	 */

	slot = event->pcimsg_slot;
	expander = event->pcimsg_node; /* get expander */
	board = event->pcimsg_board; /* get board */

	SCHPC_DEBUG3(D_EVENT,
	    "schpc_event_handler() - exp=%d board=%d slot=%d",
	    expander, board, slot);

	/* create a slot table index */
	slot = SCHPC_MAKE_SLOT_INDEX2(expander, slot);

	SCHPC_DEBUG1(D_EVENT,
	    "schpc_event_handler() - expanded slot %d", slot);

	if (schpc_p == NULL) {
		cmn_err(CE_WARN, "schpc/Event Handler - Can not find schpc");
		kmem_free(event, sizeof (pcimsg_t));
		return;
	}

	mutex_enter(&schpc_p->schpc_mutex);

	if (!(schpc_p->schpc_slot[slot].state & SCHPC_SLOTSTATE_HPCINITED)) {
		SCHPC_DEBUG0(D_EVENT, "schpc_event_handler - HPC Not Inited");
		mutex_exit(&schpc_p->schpc_mutex);
		kmem_free(event, sizeof (pcimsg_t));
		return;
	}
	/*
	 * Block if another thread is executing a HPC command.
	 */
	while (schpc_p->schpc_slot[slot].state & SCHPC_SLOTSTATE_EXECUTING) {
		SCHPC_DEBUG0(D_EVENT, "schpc_event_handler - Slot is busy");
		cv_wait(&schpc_p->schpc_cv, &schpc_p->schpc_mutex);
	}

	schpc_p->schpc_slot[slot].state |= SCHPC_SLOTSTATE_EXECUTING;

	mutex_exit(&schpc_p->schpc_mutex);

	rval = schpc_getslotstatus(expander, board, slot, &slotstatus);

	if (rval) {
		cmn_err(CE_WARN, "schpc/Event Handler - Can not get status "
		    "for expander=%d board=%d slot=%d\n",
		    expander, board, SCHPC_SLOT_NUM(slot));

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);
		kmem_free(event, sizeof (pcimsg_t));
		return;
	}

	if (slotstatus.slot_replystatus != PCIMSG_REPLY_GOOD) {
		cmn_err(CE_WARN, "schpc/Event Handler - Can not get good "
		    "status for expander=%d board=%d slot=%d\n",
		    expander, board, SCHPC_SLOT_NUM(slot));

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		kmem_free(event, sizeof (pcimsg_t));
		return;
	}

	SCHPC_DEBUG3(D_EVENT, "Event Received - Expander %d Board %d Slot %d",
	    expander, board, SCHPC_SLOT_NUM(slot));

	if (schpc_p->schpc_slot[slot].slot_ops == NULL) {
		SCHPC_DEBUG3(D_EVENT, "schpc/Event Handler - Received event "
		    "for unregistered slot for expander=%d board=%d slot=%d",
		    expander, board, SCHPC_SLOT_NUM(slot));

		mutex_enter(&schpc_p->schpc_mutex);
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_EXECUTING;
		cv_signal(&schpc_p->schpc_cv);
		mutex_exit(&schpc_p->schpc_mutex);

		kmem_free(event, sizeof (pcimsg_t));
		return;
	}

	/* Slot Power Event */

	if (event->pcimsg_type.pcimsg_slotevent.slot_power) {
		SCHPC_DEBUG0(D_EVENT, "Event Type: Slot Power Event");
		/*
		 * The SC may have changed to slot power status.
		 */
		if (slotstatus.slot_power_on) {
			schpc_p->schpc_slot[slot].state |=
			    SCHPC_SLOTSTATE_CONNECTED;

			(void) hpc_slot_event_notify(
			    schpc_p->schpc_slot[slot].slot_handle,
			    HPC_EVENT_SLOT_POWER_ON, 0);
		} else {
			schpc_p->schpc_slot[slot].state &=
			    ~SCHPC_SLOTSTATE_CONNECTED;

			(void) hpc_slot_event_notify(
			    schpc_p->schpc_slot[slot].slot_handle,
			    HPC_EVENT_SLOT_POWER_OFF, 0);
		}
	}

	/* Adapter Insertion/Removal Event */

	if (event->pcimsg_type.pcimsg_slotevent.slot_presence) {
		if (slotstatus.slot_empty == PCIMSG_ON) {

			/* Adapter Removed */

			SCHPC_DEBUG0(D_EVENT, "Event Type: Adapter Removed");

			if (schpc_p->schpc_slot[slot].state &
			    SCHPC_SLOTSTATE_CONNECTED) {
				/*
				 * If the adapter has been removed while
				 * there the slot is connected, it could be
				 * due to a ENUM handling.
				 */
				cmn_err(CE_WARN, "Card removed from "
				    "powered on slot at "
				    "expander=%d board=%d slot=%d\n",
				    expander, board, SCHPC_SLOT_NUM(slot));

				schpc_p->schpc_slot[slot].state &=
				    ~SCHPC_SLOTSTATE_EXECUTING;
				rval = schpc_disconnect((caddr_t)schpc_p,
				    schpc_p->schpc_slot[slot].slot_handle,
				    0, 0);
				mutex_enter(&schpc_p->schpc_mutex);
				while (schpc_p->schpc_slot[slot].state &
				    SCHPC_SLOTSTATE_EXECUTING) {
					SCHPC_DEBUG0(D_EVENT,
					    "schpc_event_handler - "
					    "Slot is busy");
					cv_wait(&schpc_p->schpc_cv,
					    &schpc_p->schpc_mutex);
				}

				schpc_p->schpc_slot[slot].state |=
				    SCHPC_SLOTSTATE_EXECUTING;

				mutex_exit(&schpc_p->schpc_mutex);
			}
			schpc_p->schpc_slot[slot].state |=
			    SCHPC_SLOTSTATE_OCC_GOOD;

			schpc_p->schpc_slot[slot].state &=
			    ~SCHPC_SLOTSTATE_PRESENT;

			(void) hpc_slot_event_notify(
			    schpc_p->schpc_slot[slot].slot_handle,
			    HPC_EVENT_SLOT_REMOVAL, 0);
		} else {

			/* Adapter Inserted */

			SCHPC_DEBUG0(D_EVENT, "Event Type: Adapter Inserted");

			if (schpc_p->schpc_slot[slot].state &
			    SCHPC_SLOTSTATE_PRESENT) {
				/*
				 * If the adapter is already present
				 * throw the this event away.
				 */

				SCHPC_DEBUG0(D_EVENT,
				    "Adapter is already present");

				mutex_enter(&schpc_p->schpc_mutex);
				schpc_p->schpc_slot[slot].state &=
				    ~SCHPC_SLOTSTATE_EXECUTING;
				cv_signal(&schpc_p->schpc_cv);
				mutex_exit(&schpc_p->schpc_mutex);

				kmem_free(event, sizeof (pcimsg_t));
				return;
			}

			schpc_p->schpc_slot[slot].state |=
			    SCHPC_SLOTSTATE_PRESENT;

			schpc_p->schpc_slot[slot].state &=
			    ~SCHPC_SLOTSTATE_CONNECTED;

			(void) hpc_slot_event_notify(
			    schpc_p->schpc_slot[slot].slot_handle,
			    HPC_EVENT_SLOT_INSERTION, 0);

			if (schpc_p->schpc_slot[slot].state &
			    SCHPC_SLOTSTATE_AUTOCFG_ENABLE) {
				SCHPC_DEBUG0(D_EVENT, "Auto Configuration "
				    "(Connect/Configure) Started");

				schpc_p->schpc_slot[slot].state &=
				    ~SCHPC_SLOTSTATE_EXECUTING;

				rval = schpc_connect((caddr_t)schpc_p,
				    schpc_p->schpc_slot[slot].slot_handle,
				    0, 0);

				if (rval) {
					cmn_err(CE_WARN, "schpc/Event Handler -"
					    " Can not connect");

					mutex_enter(&schpc_p->schpc_mutex);
					schpc_p->schpc_slot[slot].state &=
					    ~SCHPC_SLOTSTATE_EXECUTING;
					cv_signal(&schpc_p->schpc_cv);
					mutex_exit(&schpc_p->schpc_mutex);

					kmem_free(event, sizeof (pcimsg_t));
					return;
				}
				mutex_enter(&schpc_p->schpc_mutex);
				while (schpc_p->schpc_slot[slot].state &
				    SCHPC_SLOTSTATE_EXECUTING) {
					SCHPC_DEBUG0(D_EVENT,
					    "schpc_event_handler - "
					    "Slot is busy");
					cv_wait(&schpc_p->schpc_cv,
					    &schpc_p->schpc_mutex);
				}

				schpc_p->schpc_slot[slot].state |=
				    SCHPC_SLOTSTATE_EXECUTING;

				mutex_exit(&schpc_p->schpc_mutex);

				(void) hpc_slot_event_notify(
				    schpc_p->schpc_slot[slot].slot_handle,
				    HPC_EVENT_SLOT_CONFIGURE, 0);
			} else {
				schpc_setslotled(expander, board, slot,
				    SERVICE_LED_ON);
			}
		}
	}

	/* ENUM# signal change event */

	if (event->pcimsg_type.pcimsg_slotevent.slot_ENUM) {
		/*
		 * ENUM should only be received to the adapter remove
		 * procedure.
		 */

		SCHPC_DEBUG0(D_EVENT, "Event Type: ENUM Asserted");

		schpc_setslotled(expander, board, slot, FAULT_LED_FLASH);

		schpc_p->schpc_slot[slot].state |= SCHPC_SLOTSTATE_ENUM;

		(void) hpc_slot_event_notify(
		    schpc_p->schpc_slot[slot].slot_handle,
		    HPC_EVENT_SLOT_ENUM, 0);
	}

	/* HEALTHY# signal change event */

	if (event->pcimsg_type.pcimsg_slotevent.slot_HEALTHY) {

		if (!slotstatus.slot_HEALTHY) {

			SCHPC_DEBUG0(D_EVENT, "Event Type: !HEALTHY ASSERTED");

			schpc_p->schpc_slot[slot].state &=
			    ~SCHPC_SLOTSTATE_OCC_GOOD;

			(void) hpc_slot_event_notify(
			    schpc_p->schpc_slot[slot].slot_handle,
			    HPC_EVENT_SLOT_NOT_HEALTHY, 0);

			schpc_setslotled(expander, board, slot, FAULT_LED_ON);
		} else {
			SCHPC_DEBUG0(D_EVENT, "Event Type: HEALTHY OK");

			schpc_p->schpc_slot[slot].state |=
			    SCHPC_SLOTSTATE_OCC_GOOD;

			(void) hpc_slot_event_notify(
			    schpc_p->schpc_slot[slot].slot_handle,
			    HPC_EVENT_SLOT_HEALTHY_OK, 0);

			schpc_setslotled(expander, board, slot,
			    FAULT_LED_OFF);
		}
	}

	/* Good Power change event */

	if (event->pcimsg_type.pcimsg_slotevent.slot_powergood) {
		if (slotstatus.slot_powergood == PCIMSG_ON) {

			SCHPC_DEBUG0(D_EVENT,
			    "Event Type: Slot Power Good Detected");

			schpc_p->schpc_slot[slot].state |=
			    SCHPC_SLOTSTATE_OCC_GOOD;

			(void) hpc_slot_event_notify(
			    schpc_p->schpc_slot[slot].slot_handle,
			    HPC_EVENT_SLOT_HEALTHY_OK, 0);

			schpc_setslotled(expander, board, slot,
			    FAULT_LED_OFF);
		} else {
			SCHPC_DEBUG0(D_EVENT, "Event Type: Slot Power Not Good "
			    "Detected");

			if (schpc_p->schpc_slot[slot].state &
			    SCHPC_SLOTSTATE_CONNECTED) {

				SCHPC_DEBUG0(D_EVENT, "Slot Power Not Good: "
				    "power failed");

				schpc_p->schpc_slot[slot].state &=
				    ~SCHPC_SLOTSTATE_OCC_GOOD;

				(void) hpc_slot_event_notify(
				    schpc_p->schpc_slot[slot].slot_handle,
				    HPC_EVENT_SLOT_NOT_HEALTHY, 0);

				schpc_setslotled(expander, board, slot,
				    FAULT_LED_ON);
			}
		}
	}

	/* Power Fault change event */

	if (event->pcimsg_type.pcimsg_slotevent.slot_powerfault) {
		if (slotstatus.slot_powerfault == PCIMSG_ON) {

			SCHPC_DEBUG0(D_EVENT, "Event Type: Slot Power Fault "
			    "Detected");

			schpc_p->schpc_slot[slot].state &=
			    ~SCHPC_SLOTSTATE_OCC_GOOD;

			(void) hpc_slot_event_notify(
			    schpc_p->schpc_slot[slot].slot_handle,
			    HPC_EVENT_SLOT_NOT_HEALTHY, 0);

			schpc_setslotled(expander, board, slot, FAULT_LED_ON);
		} else {
			SCHPC_DEBUG0(D_EVENT, "Event Type: Slot Power Fault "
			    "Cleared");

			schpc_p->schpc_slot[slot].state |=
			    SCHPC_SLOTSTATE_OCC_GOOD;

			(void) hpc_slot_event_notify(
			    schpc_p->schpc_slot[slot].slot_handle,
			    HPC_EVENT_SLOT_HEALTHY_OK, 0);

			schpc_setslotled(expander, board, slot,
			    FAULT_LED_OFF);
		}
	}
	mutex_enter(&schpc_p->schpc_mutex);
	schpc_p->schpc_slot[slot].state &=
	    ~SCHPC_SLOTSTATE_EXECUTING;
	cv_signal(&schpc_p->schpc_cv);
	mutex_exit(&schpc_p->schpc_mutex);

	kmem_free(event, sizeof (pcimsg_t));
}


/*
 * schpc_event_filter
 *
 * The schpc_event_filter enqueues MBOXSC_MSG_EVENTs into the
 * schpc_event_taskq for processing by the schpc_event_handler _if_
 * hotpluggable pci slots have been registered; otherwise, the
 * MBOXSC_MSG_EVENTs are discarded in order to keep the incoming mailbox
 * open for future messages.
 */
static void
schpc_event_filter(pcimsg_t *pmsg)
{
	if (slots_registered == B_TRUE) {

		pcimsg_t *pevent;

		/*
		 * If hotpluggable pci slots have been registered then enqueue
		 * the event onto the schpc_event_taskq for processing.
		 */

		SCHPC_DEBUG0(D_EVENT, "schpc_event_filter() - "
		    "slots_registered = B_TRUE");

		pevent = (pcimsg_t *)kmem_zalloc(sizeof (pcimsg_t), KM_SLEEP);
		bcopy(pmsg, pevent, sizeof (pcimsg_t));

		SCHPC_DEBUG0(D_EVENT, "schpc_event_filter() - "
		    "event alloc'd");

		if (taskq_dispatch(schpc_event_taskq, schpc_event_handler,
		    (void *)pevent, TQ_SLEEP) == TASKQID_INVALID) {
			cmn_err(CE_WARN, "schpc: schpc_event_filter - "
			    "taskq_dispatch failed to enqueue event");
			kmem_free(pevent, sizeof (pcimsg_t));
			return;
		}

		SCHPC_DEBUG0(D_EVENT, "schpc_event_filter() - "
		    "event was taskq_dispatch'ed to schpc_event_handler");
	} else {
		/*
		 * Oops, schpc received an event _before_ the slots have been
		 * registered. In that case there is no choice but to toss
		 * the event.
		 */
		cmn_err(CE_WARN, "schpc: schpc_event_filter - discarding "
		    "premature event");
	}
}


/*
 * schpc_msg_thread
 * A stand-alone thread that monitors the incoming mailbox for
 * MBOXSC_MSG_REPLYs and MBOXSC_MSG_EVENTs, and removes them from
 * the mailbox for processing.
 *
 * MBOXSC_MSG_REPLYs are matched against outstanding REPLYs in the
 * schpc_replylist, and the waiting thread is notified that its REPLY
 * message has arrived; otherwise, if no REPLY match is found, then it is
 * discarded.
 *
 * MBOXSC_MSG_EVENTs are enqueued into the schpc_event_taskq and processed
 * by the schpc_event_handler.
 *
 * The schpc_msg_thread is started in _init().
 */
void
schpc_msg_thread(void)
{
	int			err;
	uint32_t		type;
	uint32_t		cmd;
	uint64_t		transid;
	uint32_t		length;
	pcimsg_t		msg;

	SCHPC_DEBUG0(D_THREAD, "schpc_msg_thread() running");

	/* CONSTCOND */
	while (1) {

		/* setup wildcard arguments */
		type = 0;
		cmd = 0;
		transid = 0;
		length = sizeof (pcimsg_t);
		bzero(&msg, sizeof (pcimsg_t));

		err = mboxsc_getmsg(KEY_SCPC, &type, &cmd,
		    &transid, &length, (void *)&msg,
		    schpc_timeout_getmsg);

		if (err) {
			switch (err) {

			/*FALLTHROUGH*/
			case ETIMEDOUT:
			case EAGAIN:
				continue;

			default:
				/*
				 * unfortunately, we can't do very much here
				 * because we're wildcarding mboxsc_getmsg
				 * so if it encounters an error, we can't
				 * identify which transid it belongs to.
				 */
				cmn_err(CE_WARN,
				"schpc - mboxsc_getmsg failed, err=0x%x", err);
				delay(drv_usectohz(100000));
				continue;
			}
		}

		if (msg.pcimsg_revision != PCIMSG_REVISION) {
			/*
			 * This version of the schpc driver only understands
			 * version 1.0 of the PCI Hot Plug Message format.
			 */
			cmn_err(CE_WARN, " schpc: schpc_msg_thread - "
			    "discarding event w/ unknown message version %x",
			    msg.pcimsg_revision);
			continue;
		}

		switch (type) {

		case MBOXSC_MSG_EVENT:
			schpc_event_filter(&msg);
			break;

		case MBOXSC_MSG_REPLY:
			schpc_reply_handler(&msg, type, cmd, transid, length);
			break;

		default:
			cmn_err(CE_WARN,
			    "schpc - mboxsc_getmsg unknown msg"
			    " type=0x%x", type);
			break;
		}
	}
	/* this thread never exits */
}


void
schpc_reply_handler(pcimsg_t *pmsg, uint32_t type, uint32_t cmd,
			uint64_t transid, uint32_t length)
{
	schpc_replylist_t	*entry;

	mutex_enter(&schpc_replylist_mutex);
	entry = schpc_replylist_first;
	while (entry != NULL) {
		if (entry->transid == transid) {
			break;
		} else
			entry = entry->next;
	}
	if (entry) {
		SCHPC_DEBUG1(D_GETSLOTSTATUS|D_SETSLOTSTATUS,
		    "schpc_reply_handler() - 0x%lx transid reply "
		    "received", transid);

		mutex_enter(&entry->reply_lock);
		if (entry->reply_cexit == B_FALSE) {
			SCHPC_DEBUG1(D_GETSLOTSTATUS|D_SETSLOTSTATUS,
			    "schpc_reply_handler() - 0x%lx transid"
			    " cv_signal waiting thread", transid);

			/*
			 * emulate mboxsc_getmsg by copying the reply
			 */
			entry->type = type;
			entry->cmd = cmd;
			entry->transid = transid;
			entry->length = length;
			bcopy((caddr_t)pmsg, &entry->reply, length);

			/* reply was received */
			entry->reply_recvd = B_TRUE;

			/*
			 * wake up thread waiting for reply with transid
			 */
			cv_signal(&entry->reply_cv);
		}
		mutex_exit(&entry->reply_lock);
	} else {
		cmn_err(CE_WARN, "schpc - no match for transid 0x%lx",
		    transid);
	}
	mutex_exit(&schpc_replylist_mutex);
}


/*
 * schpc_putrequest
 *
 * A wrapper around the synchronous call mboxsc_putmsg().
 */
int
schpc_putrequest(uint32_t key, uint32_t type, uint32_t cmd, uint64_t *transidp,
		uint32_t length, void *datap, clock_t timeout,
		schpc_replylist_t **entryp)
{
	int rval;

	/* add the request to replylist to keep track of outstanding requests */
	*entryp = schpc_replylist_link(cmd, *transidp, length);

	SCHPC_DEBUG1(D_GETSLOTSTATUS|D_SETSLOTSTATUS, "schpc_putrequest() - "
	    "0x%lx transid mboxsc_putmsg called", *transidp);

	/* wait synchronously for request to be sent */
	rval = mboxsc_putmsg(key, type, cmd, transidp, length,
	    (void *)datap, timeout);

	SCHPC_DEBUG2(D_GETSLOTSTATUS|D_SETSLOTSTATUS, "schpc_putrequest() - "
	    "0x%lx transid mboxsc_putmsg returned 0x%x", *transidp, rval);

	/* if problem is encountered then remove the request from replylist */
	if (rval)
		schpc_replylist_unlink(*entryp);

	return (rval);
}


/*
 * schpc_getreply
 *
 * Wait for the schpc_msg_thread to respond that a matching reply has
 * arrived; otherwise, timeout and remove the entry from the schpc_replylist.
 */
/*ARGSUSED*/
int
schpc_getreply(uint32_t key, uint32_t *typep, uint32_t *cmdp,
		uint64_t *transidp, uint32_t *lengthp, void *datap,
		clock_t timeout, schpc_replylist_t *listp)
{
	int rc = 0;

	SCHPC_DEBUG1(D_GETSLOTSTATUS|D_SETSLOTSTATUS,
	    "schpc_getreply() - 0x%lx transid waiting for reply",
	    *transidp);

	/*
	 * wait here until schpc_msg_thread because it's always
	 * looking for reply messages
	 */
	mutex_enter(&listp->reply_lock);

	while (listp->reply_recvd == B_FALSE) {
		/*
		 * wait for reply or timeout
		 */
		rc = cv_timedwait(&listp->reply_cv, &listp->reply_lock,
		    ddi_get_lbolt() + drv_usectohz(timeout * 1000));
		switch (rc) {
		case -1: /* most likely a timeout, but check anyway */

			/* message was received after all */
			if (listp->reply_recvd == B_TRUE)
				break;

			/* no, it's really a timeout */
			listp->reply_cexit = B_TRUE;
			mutex_exit(&listp->reply_lock);
			cmn_err(CE_WARN,
			"schpc - 0x%lx transid reply timed out", *transidp);
			schpc_replylist_unlink(listp);
			return (ETIMEDOUT);

		default:
			break;
		}
	}

	*typep = listp->type;
	*cmdp = listp->cmd;
	*transidp = listp->transid;
	*lengthp = listp->length;
	bcopy((caddr_t)&listp->reply, datap, *lengthp);
	mutex_exit(&listp->reply_lock);
	SCHPC_DEBUG1(D_GETSLOTSTATUS|D_SETSLOTSTATUS,
	    "schpc_getreply() - 0x%lx transid received", *transidp);
	schpc_replylist_unlink(listp);
	return (0);
}


/*
 * schpc_replylist_unlink
 *
 * Deallocate a schpc_replylist_t element.
 */
void
schpc_replylist_unlink(schpc_replylist_t *entry)
{
#if DEBUG
	schpc_replylist_t *dbg_entry;
#endif	/* DEBUG */

	SCHPC_DEBUG1(D_GETSLOTSTATUS|D_SETSLOTSTATUS,
	    "schpc_replylist_unlink() - 0x%lx transid deleted from replylist",
	    entry->transid);

	mutex_enter(&schpc_replylist_mutex);
	if (entry->prev) {
		entry->prev->next = entry->next;
		if (entry->next)
			entry->next->prev = entry->prev;
	} else {
		schpc_replylist_first = entry->next;
		if (entry->next)
			entry->next->prev = NULL;
	}
	if (entry == schpc_replylist_last) {
		schpc_replylist_last = entry->prev;
	}
	kmem_free(entry, sizeof (schpc_replylist_t));
	schpc_replylist_count--;

#if DEBUG
	if (schpc_debug_flags & (D_GETSLOTSTATUS|D_SETSLOTSTATUS)) {
		dbg_entry = schpc_replylist_first;
		cmn_err(CE_CONT, "schpc: schpc_replylist_unlink() - replylist "
		    "count = %d\n", schpc_replylist_count);
		while (dbg_entry != NULL) {
			cmn_err(CE_CONT, "schpc: schpc_replylist_unlink() - "
			    "0x%lx transid\n", dbg_entry->transid);
			dbg_entry = dbg_entry->next;
		}
	}
#endif	/* DEBUG  */

	mutex_exit(&schpc_replylist_mutex);
}


/*
 * schpc_replylist_link
 *
 * Allocate and initialize a schpc_replylist_t element.
 */
schpc_replylist_t *
schpc_replylist_link(uint32_t cmd, uint64_t transid, uint32_t length)
{
	schpc_replylist_t *entry;
#if DEBUG
	schpc_replylist_t *dbg_entry;
#endif	/* DEBUG */

	SCHPC_DEBUG1(D_GETSLOTSTATUS|D_SETSLOTSTATUS,
	    "schpc_replylist_link() - 0x%lx transid inserting into replylist",
	    transid);

	entry = kmem_zalloc(sizeof (schpc_replylist_t), KM_SLEEP);
	mutex_init(&entry->reply_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&entry->reply_cv, NULL, CV_DRIVER, NULL);
	entry->type = MBOXSC_MSG_REPLY;
	entry->cmd  = cmd;
	entry->transid  = transid;
	entry->length  = length;
	entry->reply_recvd = B_FALSE;
	entry->reply_cexit = B_FALSE;

	mutex_enter(&schpc_replylist_mutex);
	if (schpc_replylist_last) {
		entry->prev = schpc_replylist_last;
		schpc_replylist_last->next = entry;
		schpc_replylist_last = entry;
	} else {
		schpc_replylist_last = schpc_replylist_first = entry;
	}

	schpc_replylist_count++;

#if DEBUG
	if (schpc_debug_flags & (D_GETSLOTSTATUS|D_SETSLOTSTATUS)) {
		dbg_entry = schpc_replylist_first;
		cmn_err(CE_CONT, "schpc: schpc_replylist_link() - replylist "
		    "count = %d\n", schpc_replylist_count);
		while (dbg_entry != NULL) {
			cmn_err(CE_CONT, "schpc: schpc_replylist_link() - "
			    "0x%lx transid\n", dbg_entry->transid);
			dbg_entry = dbg_entry->next;
		}
	}
#endif	/* DEBUG  */

	mutex_exit(&schpc_replylist_mutex);

	return (entry);
}


/*
 * schpc_getslotstatus
 *
 * Issues a Get Slot Status command to the System Controller
 * for a specific slot.
 */
static int
schpc_getslotstatus(uint32_t expander, uint32_t board, uint32_t slot,
    pci_getslot_t *slotstatus)
{
	pcimsg_t	request;
	pcimsg_t	reply;
	int		rval;
	uint32_t	type, cmd, length;
	uint64_t	transid;
	schpc_replylist_t *entry;

	SCHPC_DEBUG4(D_GETSLOTSTATUS,
	    "schpc_getslotstatus(expander=%d board=%d "
	    "slot=%d slotstatus=0x%p", expander, board,
	    SCHPC_SLOT_NUM(slot), (void *)slotstatus);

	if (schpc_p == NULL) {
		return (1);
	}

	bzero(&request, sizeof (pcimsg_t));

	request.pcimsg_node = expander;
	request.pcimsg_board = board;
	request.pcimsg_slot = SCHPC_SLOT_NUM(slot);
	request.pcimsg_revision = PCIMSG_REVISION;
	request.pcimsg_command = PCIMSG_GETSLOTSTATUS;

	type = MBOXSC_MSG_REQUEST;
	cmd = PCIMSG_GETSLOTSTATUS;
	transid =  schpc_gettransid(schpc_p, slot);
	length = sizeof (pcimsg_t);

	SCHPC_DEBUG1(D_GETSLOTSTATUS, "schpc_getslotstatus() - "
	    "0x%lx transid schpc_putrequest called", transid);

	rval = schpc_putrequest(KEY_PCSC, type, cmd, &transid, length,
	    (void *)&request, schpc_timeout_putmsg, &entry);

	SCHPC_DEBUG2(D_GETSLOTSTATUS, "schpc_getslotstatus() - "
	    "0x%lx transid schpc_putrequest returned 0x%x", transid, rval);

	if (rval) {
		return (rval);
	}

	bzero(&reply, sizeof (pcimsg_t));
	type = MBOXSC_MSG_REPLY;

	SCHPC_DEBUG1(D_GETSLOTSTATUS, "schpc_getslotstatus() - "
	    "0x%lx transid schpc_getreply called", transid);

	rval = schpc_getreply(KEY_SCPC, &type, &cmd, &transid, &length,
	    (void *)&reply, schpc_timeout_getmsg, entry);

	SCHPC_DEBUG2(D_GETSLOTSTATUS, "schpc_getslotstatus() - "
	    "0x%lx transid schpc_getreply returned 0x%x", transid, rval);

	if (rval == 0) {
		*slotstatus = reply.pcimsg_type.pcimsg_getslot;

		SCHPC_DEBUG0(D_GETSLOTSTATUS, "schpc_getslotstatus()");
		SCHPC_DEBUG1(D_GETSLOTSTATUS, "    slot_power_on %x",
		    reply.pcimsg_type.pcimsg_getslot.slot_power_on);
		SCHPC_DEBUG1(D_GETSLOTSTATUS, "    slot_powergood %x",
		    reply.pcimsg_type.pcimsg_getslot.slot_powergood);
		SCHPC_DEBUG1(D_GETSLOTSTATUS, "    slot_powerfault %x",
		    reply.pcimsg_type.pcimsg_getslot.slot_powerfault);
		SCHPC_DEBUG1(D_GETSLOTSTATUS, "    slot_empty %x",
		    reply.pcimsg_type.pcimsg_getslot.slot_empty);
		SCHPC_DEBUG1(D_GETSLOTSTATUS, "    slot_freq_cap %x",
		    reply.pcimsg_type.pcimsg_getslot.slot_freq_cap);
		SCHPC_DEBUG1(D_GETSLOTSTATUS, "    slot_freq_setting %x",
		    reply.pcimsg_type.pcimsg_getslot.slot_freq_setting);
		SCHPC_DEBUG1(D_GETSLOTSTATUS, "    slot_condition %x",
		    reply.pcimsg_type.pcimsg_getslot.slot_condition);
		SCHPC_DEBUG1(D_GETSLOTSTATUS, "    slot_HEALTHY %x",
		    reply.pcimsg_type.pcimsg_getslot.slot_HEALTHY);
		SCHPC_DEBUG1(D_GETSLOTSTATUS, "    slot_ENUM %x",
		    reply.pcimsg_type.pcimsg_getslot.slot_ENUM);
	}

	return (rval);
}


/*
 * schpc_setslotstatus
 *
 * Issues a Set Slot Status command to the System Controller
 * for a specific slot.
 */
static int
schpc_setslotstatus(uint32_t expander, uint32_t board, uint32_t slot,
    pci_setslot_t *slotstatus)
{
	pcimsg_t	request;
	pcimsg_t	reply;
	int		rval;
	uint32_t	type, cmd, length;
	uint64_t	transid;
	schpc_replylist_t *entry;

	SCHPC_DEBUG4(D_SETSLOTSTATUS,
	    "schpc_setslotstatus(expander=%d board=%d "
	    "slot=%d slotstatus=0x%p", expander, board,
	    SCHPC_SLOT_NUM(slot), (void *)slotstatus);

	bzero(&request, sizeof (pcimsg_t));

	if (schpc_p == NULL) {
		return (1);
	}

	request.pcimsg_node = expander;
	request.pcimsg_board = board;
	request.pcimsg_slot = SCHPC_SLOT_NUM(slot);
	request.pcimsg_revision = PCIMSG_REVISION;
	request.pcimsg_command = PCIMSG_SETSLOTSTATUS;

	request.pcimsg_type.pcimsg_setslot = *slotstatus;

	SCHPC_DEBUG0(D_IOC_LED, "schpc_setslotstatus() - LED state change");
	SCHPC_DEBUG3(D_IOC_LED, "LED Power %d Service %d Fault %d",
	    slotstatus->slot_led_power,
	    slotstatus->slot_led_service,
	    slotstatus->slot_led_fault);

	type = MBOXSC_MSG_REQUEST;
	cmd = PCIMSG_SETSLOTSTATUS;
	transid =  schpc_gettransid(schpc_p, slot);
	length = sizeof (pcimsg_t);

	SCHPC_DEBUG1(D_SETSLOTSTATUS, "schpc_setslotstatus() - "
	    "0x%lx transid schpc_putrequest called", transid);

	rval = schpc_putrequest(KEY_PCSC, type, cmd, &transid, length,
	    (void *)&request, schpc_timeout_putmsg, &entry);

	SCHPC_DEBUG2(D_SETSLOTSTATUS, "schpc_setslotstatus() - "
	    "0x%lx transid schpc_putrequest returned 0x%x", transid, rval);

	if (rval) {
		return (rval);
	}

	bzero(&reply, sizeof (pcimsg_t));
	type = MBOXSC_MSG_REPLY;

	SCHPC_DEBUG1(D_SETSLOTSTATUS, "schpc_setslotstatus() - "
	    "0x%lx transid schpc_getreply called", transid);

	rval = schpc_getreply(KEY_SCPC, &type, &cmd, &transid, &length,
	    (void *)&reply, schpc_timeout_getmsg, entry);

	SCHPC_DEBUG2(D_SETSLOTSTATUS, "schpc_setslotstatus() - "
	    "0x%lx transid schpc_getreply returned 0x%x", transid, rval);

	if (rval == 0) {
		slotstatus->slot_replystatus =
		    reply.pcimsg_type.pcimsg_setslot.slot_replystatus;
	}

	return (rval);
}

/*
 * schpc_setslotled
 *
 * Changes the attention indicators for a given slot.
 */
static void
schpc_setslotled(int expander, int board, int slot, uint32_t led_state)
{

	pci_setslot_t	setslot;

	if (schpc_p == NULL) {
		return;
	}

	schpc_init_setslot_message(&setslot);

	if (led_state & POWER_LED_ON) {
		schpc_p->schpc_slot[slot].led.led_power = PCIMSG_LED_ON;
	}
	if (led_state & POWER_LED_OFF) {
		schpc_p->schpc_slot[slot].led.led_power = PCIMSG_LED_OFF;
	}
	if (led_state & POWER_LED_FLASH) {
		schpc_p->schpc_slot[slot].led.led_power = PCIMSG_LED_FLASH;
	}
	if (led_state & SERVICE_LED_ON) {
		schpc_p->schpc_slot[slot].led.led_service = PCIMSG_LED_ON;
	}
	if (led_state & SERVICE_LED_OFF) {
		schpc_p->schpc_slot[slot].led.led_service = PCIMSG_LED_OFF;
	}
	if (led_state & SERVICE_LED_FLASH) {
		schpc_p->schpc_slot[slot].led.led_service = PCIMSG_LED_FLASH;
	}
	if (led_state & FAULT_LED_ON) {
		schpc_p->schpc_slot[slot].led.led_fault = PCIMSG_LED_ON;
	}
	if (led_state & FAULT_LED_OFF) {
		schpc_p->schpc_slot[slot].led.led_fault = PCIMSG_LED_OFF;
	}
	if (led_state & FAULT_LED_FLASH) {
		schpc_p->schpc_slot[slot].led.led_fault = PCIMSG_LED_FLASH;
	}

	switch (schpc_p->schpc_slot[slot].led.led_power) {
	case PCIMSG_LED_ON:
		setslot.slot_led_power = PCIMSG_LED_ON;
		break;
	case PCIMSG_LED_OFF:
		setslot.slot_led_power = PCIMSG_LED_OFF;
		break;
	case PCIMSG_LED_FLASH:
		setslot.slot_led_power = PCIMSG_LED_FLASH;
		break;
	}
	switch (schpc_p->schpc_slot[slot].led.led_service) {
	case PCIMSG_LED_ON:
		setslot.slot_led_service = PCIMSG_LED_ON;
		break;
	case PCIMSG_LED_OFF:
		setslot.slot_led_service = PCIMSG_LED_OFF;
		break;
	case PCIMSG_LED_FLASH:
		setslot.slot_led_service = PCIMSG_LED_FLASH;
		break;
	}
	switch (schpc_p->schpc_slot[slot].led.led_fault) {
	case PCIMSG_LED_ON:
		setslot.slot_led_fault = PCIMSG_LED_ON;
		break;
	case PCIMSG_LED_OFF:
		setslot.slot_led_fault = PCIMSG_LED_OFF;
		break;
	case PCIMSG_LED_FLASH:
		setslot.slot_led_fault = PCIMSG_LED_FLASH;
		break;
	}

	(void) schpc_setslotstatus(expander, board, slot, &setslot);
}

/*
 * schpc_init_setslot_message
 *
 * Initialize Set Slot Message before using it.
 */
static void
schpc_init_setslot_message(pci_setslot_t *setslot)
{
	/*
	 * Initialize Set Slot Command.
	 */
	setslot->slot_power_on = PCIMSG_OFF;
	setslot->slot_power_off = PCIMSG_OFF;
	setslot->slot_led_power = PCIMSG_LED_OFF;
	setslot->slot_led_service = PCIMSG_LED_OFF;
	setslot->slot_led_fault = PCIMSG_LED_OFF;
	setslot->slot_disable_ENUM = PCIMSG_OFF;
	setslot->slot_enable_ENUM = PCIMSG_OFF;
	setslot->slot_disable_HEALTHY = PCIMSG_OFF;
	setslot->slot_enable_HEALTHY = PCIMSG_OFF;
}

/*
 * schpc_gettransid
 *
 * Builds a unique transaction ID.
 */
static uint64_t
schpc_gettransid(schpc_t *schpc_p, int slot)
{
	uint64_t	trans_id;

	mutex_enter(&schpc_p->schpc_mutex);

	if (++schpc_p->schpc_transid == 0)
		schpc_p->schpc_transid = 1;

	trans_id = (schpc_p->schpc_slot[slot].expander<<24) |
	    (schpc_p->schpc_slot[slot].board << 16) | schpc_p->schpc_transid;

	mutex_exit(&schpc_p->schpc_mutex);

	SCHPC_DEBUG1(D_TRANSID, "schpc_gettransid() - 0x%lx transid returning",
	    trans_id);

	return (trans_id);
}

/*
 * schpc_slot_get_index
 *
 * get slot table index from the slot handle
 */
static int
schpc_slot_get_index(schpc_t *schpc_p, hpc_slot_t slot)
{
	int	i;
	int	rval = -1;

	ASSERT(MUTEX_HELD(&schpc_p->schpc_mutex));

	for (i = 0; i < schpc_p->schpc_number_of_slots; i++) {
		if (schpc_p->schpc_slot[i].slot_handle == slot)
			return (i);
	}

	return (rval);
}

/*
 * schpc_register_all_slots
 *
 * Search device tree for pci nodes and register attachment points
 * for all hot pluggable slots.
 */
/*ARGSUSED*/
static void
schpc_register_all_slots(schpc_t *schpc_p)
{
	int		slot = 0;
	char		caddr[64];
	dev_info_t	*pci_dip = NULL;
	find_dev_t	find_dev;
	int		leaf, schizo, expander, portid, offset;

	SCHPC_DEBUG1(D_ATTACH,
	    "schpc_register_all_slots(schpc_p=%p)", (void *)schpc_p);

	/*
	 * Allow the event_handler to start processing unsolicited
	 * events now that slots are about to be registered.
	 */
	slots_registered = B_TRUE;

	for (slot = 0; slot < STARCAT_MAX_SLOTS; slot++) {

		leaf = SCHPC_SLOT_LEAF(slot);
		schizo = SCHPC_SLOT_SCHIZO(slot);
		expander = SCHPC_SLOT_EXPANDER(slot);

		if (schizo == 0)
			portid = 0x1c;
		else
			portid = 0x1d;

		if (leaf == 0)
			offset = 0x600000;
		else
			offset = 0x700000;

		portid = (expander << 5) | portid;

		(void) sprintf(caddr, "%x,%x", portid, offset);

		SCHPC_DEBUG3(D_ATTACH,
		    "schpc_register_all_slots: searching for pci@%s"
		    " schizo=%d, leaf=%d", caddr, schizo, leaf);

		find_dev.cname = "pci";
		find_dev.caddr = caddr;
		find_dev.schizo = schizo;
		find_dev.leaf = leaf;
		find_dev.dip = NULL;

		/* root node doesn't have to be held */
		ddi_walk_devs(ddi_root_node(), schpc_match_dip,
		    &find_dev);

		pci_dip = find_dev.dip;

		if (pci_dip == NULL) {

			SCHPC_DEBUG1(D_ATTACH,
			    "schpc_register_all_slots: pci@%s NOT FOUND",
			    caddr);

			continue;
		}

		SCHPC_DEBUG2(D_ATTACH,
		    "schpc_register_all_slots: pci@%s FOUND dip=0x%p",
		    caddr, (void *)pci_dip);

		(void) schpc_add_pci(pci_dip);

		/*
		 * Release hold acquired in schpc_match_dip()
		 */
		ndi_rele_devi(pci_dip);
	}

	SCHPC_DEBUG0(D_ATTACH, "schpc_register_all_slots: Thread Exit");

	thread_exit();
}

/*
 * schpc_add_pci
 *
 * Routine to add attachments points associated with a pci node.
 * Can be call externally by DR when configuring a PCI I/O Board.
 */
int
schpc_add_pci(dev_info_t *bdip)
{
	int		portid;
	int		expander, board, schizo, leaf, slot, status;
	char		ap_id[MAXNAMELEN];
	char		caddr[64];
	char		*naddr;
	hpc_slot_info_t	slot_info;
	hpc_slot_ops_t	*slot_ops;
	dev_info_t 	*sdip = bdip;

	SCHPC_DEBUG1(D_ATTACH, "schpc_add_pci(dip=0x%p)", (void *)sdip);

	if (schpc_p == NULL) {
		/*
		 * The schpc driver has not been attached yet.
		 */
		return (DDI_SUCCESS);
	}

	if ((portid = ddi_getprop(DDI_DEV_T_ANY, sdip, 0, "portid", -1)) < 0) {
		cmn_err(CE_WARN, "schpc_add_pci(dip=0x%p) - no portid\n",
		    (void *)sdip);
		return (DDI_FAILURE);
	}

	expander = schpc_getexpander(sdip);
	board = schpc_getboard(sdip);

	switch (portid & 0x1f) {

	case 0x1c:
		schizo = 0;
		break;
	case 0x1d:
		schizo = 1;
		break;
	default:
		cmn_err(CE_WARN, "schpc_add_pci(dip=0x%p) - "
		    "Invalid pci portid 0x%x\n", (void *)sdip, portid);
		return (DDI_FAILURE);
	}

	naddr = ddi_get_name_addr(sdip);
	if (naddr == NULL) {
		SCHPC_DEBUG1(D_ATTACH, "schpc_add_pci: ddi_get_name_addr"
		    "(0x%p) returns null", (void *)sdip);
		return (DDI_FAILURE);
	}

	(void) sprintf(caddr, "%x,600000", portid);

	if (strcmp(caddr, naddr) == 0) {
		leaf = 0;
	} else {
		(void) sprintf(caddr, "%x,700000", portid);
		if (strcmp(caddr, naddr) == 0) {
			char *name;

			leaf = 1;
			name = ddi_binding_name(sdip);
			if ((strcmp(name, "pci108e,8002") == 0) &&
			    (schizo == 0)) {
				int circ;
				dev_info_t *cdip;
				/*
				 * XMITS 0 Leaf B will have its hot
				 * pluggable slot off a PCI-PCI bridge,
				 * which is the only child.
				 */
				ndi_devi_enter(sdip, &circ);
				cdip = ddi_get_child(sdip);
				if (cdip == NULL) {
					cmn_err(CE_WARN,
					    "schpc_add_pci(dip=0x%p) - "
					    "Invalid pci name addr %s\n",
					    (void *)sdip, naddr);
					ndi_devi_exit(sdip, circ);
					return (DDI_FAILURE);
				}
				ndi_devi_exit(sdip, circ);
				sdip = cdip;
			}
		} else {
			cmn_err(CE_WARN, "schpc_add_pci(dip=0x%p) - "
			    "Invalid pci name addr %s\n", (void *)sdip, naddr);
			return (DDI_FAILURE);
		}
	}

	/* create a slot table index */
	slot = SCHPC_MAKE_SLOT_INDEX3(expander, schizo, leaf);

	if (schpc_p->schpc_slot[slot].devi) {
		cmn_err(CE_WARN, "schpc_add_pci(dip=0x%p) - "
		    "pci node already registered\n", (void *)sdip);
		return (DDI_FAILURE);
	}

	/*
	 * There is no need to hold the dip while saving it in
	 * the devi field below. The dip is never dereferenced.
	 * (If that changes, this code should be modified).
	 * We want to avoid holding the dip here because it
	 * prevents DR.
	 *
	 * NOTE: Even though the slot on XMITS0 Leaf-B
	 * is connected to a pci_pci bridge, we will be saving
	 * the busdip in this datastructure. This will make
	 * it easier to identify the dip being removed in
	 * schpc_remove_pci().
	 */
	schpc_p->schpc_slot[slot].devi = bdip;

	schpc_p->schpc_slot[slot].expander = expander;
	schpc_p->schpc_slot[slot].board = board;
	schpc_p->schpc_slot[slot].schizo = schizo;
	schpc_p->schpc_slot[slot].leaf = leaf;

	/*
	 * Starcat PCI slots are always PCI device 1.
	 */
	schpc_p->schpc_slot[slot].pci_id = 1;

	schpc_buildapid(sdip, slot, (char *)&ap_id);

	(void) strcpy(schpc_p->schpc_slot[slot].ap_id, (char *)&ap_id);

	/* safe to call ddi_pathname(): bdip is held */
	(void) ddi_pathname(sdip, schpc_p->schpc_slot[slot].nexus_path);

	status = schpc_get_slot_status(expander, board, SCHPC_SLOT_NUM(slot));
	switch (status) {
		case RSV_UNKNOWN:
		case RSV_PRESENT:
		case RSV_MISS:
		case RSV_PASS:
		case RSV_EMPTY_CASSETTE:

			/*
			 * Test the condition of the slot.
			 */
			schpc_test((caddr_t)schpc_p, slot, 0, 0);
			break;
		case RSV_BLACK:
			schpc_p->schpc_slot[slot].state = 0;
			cmn_err(CE_WARN, "schpc: PCI card blacklisted: "
			    "expander=%d board=%d slot=%d\n", expander,
			    board, SCHPC_SLOT_NUM(slot));
			break;
		default:
			schpc_p->schpc_slot[slot].state = 0;
			cmn_err(CE_WARN, "schpc: PCI card failed by POST: "
			    "expander=%d board=%d slot=%d failure=0x%x\n",
			    expander, board, SCHPC_SLOT_NUM(slot), status);
			break;
	}

	if (schpc_p->schpc_slot[slot].state & SCHPC_SLOTSTATE_REC_GOOD) {

		/* allocate slot ops */

		slot_ops = hpc_alloc_slot_ops(KM_SLEEP);
		schpc_p->schpc_slot[slot].slot_ops = slot_ops;

		/*
		 * Default to Autoconfiguration disabled.
		 */
		schpc_p->schpc_slot[slot].state &=
		    ~SCHPC_SLOTSTATE_AUTOCFG_ENABLE;

		/*
		 * Fill in the slot information structure that
		 * describes the slot.
		 */
		slot_info.version = HPC_SLOT_OPS_VERSION;

		if (schpc_p->schpc_hotplugmodel ==
		    SCHPC_HOTPLUGTYPE_CPCIHOTPLUG)
			slot_info.slot_type = HPC_SLOT_TYPE_PCI;
		else
			slot_info.slot_type = HPC_SLOT_TYPE_CPCI;

		slot_info.slot.pci.device_number =
		    schpc_p->schpc_slot[slot].pci_id;

		slot_info.slot.pci.slot_capabilities = HPC_SLOT_64BITS;

		if (schpc_use_legacy_apid)
			slot_info.slot_flags = HPC_SLOT_NO_AUTO_ENABLE;
		else
			slot_info.slot_flags = HPC_SLOT_NO_AUTO_ENABLE |
			    HPC_SLOT_CREATE_DEVLINK;

		(void) strcpy(slot_info.slot.pci.slot_logical_name,
		    schpc_p->schpc_slot[slot].ap_id);

		/*
		 * Fill in the slot ops structure that tells
		 * the Hot Plug Services what function we
		 * support.
		 */
		slot_ops->hpc_version = HPC_SLOT_OPS_VERSION;
		if (schpc_p->schpc_hotplugmodel ==
		    SCHPC_HOTPLUGTYPE_CPCIHOTPLUG) {
			slot_ops->hpc_op_connect = schpc_connect;
			slot_ops->hpc_op_disconnect = schpc_disconnect;
			slot_ops->hpc_op_insert = NULL;
			slot_ops->hpc_op_remove = NULL;
			slot_ops->hpc_op_control = schpc_pci_control;
		} else {
			slot_ops->hpc_op_connect = NULL;
			slot_ops->hpc_op_disconnect = NULL;
			slot_ops->hpc_op_insert = NULL;
			slot_ops->hpc_op_remove = NULL;
			slot_ops->hpc_op_control = schpc_cpci_control;
		}

		SCHPC_DEBUG5(D_ATTACH, "schpc_add_pci: Registering HPC "
		    "- nexus =%s schpc_p=%p slot=%d pci number=%d ap_id=%s",
		    schpc_p->schpc_slot[slot].nexus_path,
		    (void *)schpc_p, SCHPC_SLOT_NUM(slot),
		    slot_info.slot.pci.device_number,
		    slot_info.slot.pci.slot_logical_name);

		if (hpc_slot_register(schpc_p->schpc_devi,
		    schpc_p->schpc_slot[slot].nexus_path, &slot_info,
		    &schpc_p->schpc_slot[slot].slot_handle,
		    slot_ops, (caddr_t)schpc_p, 0) != 0) {

			/*
			 * If the slot can not be registered,
			 * then the slot_ops need to be freed.
			 */
			cmn_err(CE_WARN, "schpc%d Unable to Register "
			    "Slot %s", schpc_p->schpc_instance,
			    slot_info.slot.pci.slot_logical_name);

			hpc_free_slot_ops(schpc_p->schpc_slot[slot].slot_ops);

			schpc_p->schpc_slot[slot].slot_ops = NULL;

			return (DDI_FAILURE);
		}

		/*
		 * We are ready to take commands from the HPC Services.
		 */
		schpc_p->schpc_slot[slot].state |= SCHPC_SLOTSTATE_HPCINITED;
	}

	return (DDI_SUCCESS);
}

/*
 * schpc_remove_pci
 *
 * Routine to remove attachments points associated with a pci node.
 * Can be call externally by DR when unconfiguring a PCI I/O Board.
 */
int
schpc_remove_pci(dev_info_t *dip)
{
	int slot;

	SCHPC_DEBUG1(D_DETACH, "schpc_remove_pci(dip=0x%p)", (void *)dip);

	if (schpc_p == NULL) {
		/*
		 * The schpc driver has not been attached yet.
		 */
		return (DDI_SUCCESS);
	}

	for (slot = 0; slot < schpc_p->schpc_number_of_slots; slot++) {
		if (schpc_p->schpc_slot[slot].devi == dip) {

			if (schpc_p->schpc_slot[slot].slot_ops) {
				if (hpc_slot_unregister(
				    &schpc_p->schpc_slot[slot].slot_handle)) {
					cmn_err(CE_WARN,
					    "schpc_remove_pci(dip=0x%p) - "
					    "unable to unregister pci slots\n",
					    (void *)dip);
					return (DDI_FAILURE);
				} else {
					hpc_free_slot_ops(
					    schpc_p->schpc_slot[slot].slot_ops);

					schpc_p->schpc_slot[slot].slot_ops =
					    NULL;

					schpc_p->schpc_slot[slot].devi = NULL;

					return (DDI_SUCCESS);
				}
			} else {
				schpc_p->schpc_slot[slot].devi = NULL;

				return (DDI_SUCCESS);
			}
		}
	}

	cmn_err(CE_WARN, "schpc_remove_pci(dip=0x%p) "
	    "dip not found\n", (void *)dip);

	return (DDI_SUCCESS);
}

/*
 * schpc_match_dip
 *
 * Used by ddi_walk_devs to find PCI Nexus nodes associated with
 * Hot Plug Controllers.
 */
static int
schpc_match_dip(dev_info_t *dip, void *arg)
{
	char		*naddr;
	find_dev_t	*find_dev = (find_dev_t *)arg;

	if (strcmp(find_dev->cname, ddi_node_name(dip)) == 0 &&
	    ((((naddr = ddi_get_name_addr(dip)) != NULL) &&
	    (strcmp(find_dev->caddr, naddr) == 0)) ||
	    ((naddr == NULL) && (strlen(find_dev->caddr) == 0)))) {
		/*
		 * While ddi_walk_devs() holds dips when invoking this
		 * callback, this dip is being saved and will be accessible
		 * to the caller outside ddi_walk_devs(). Therefore it must be
		 * held.
		 */
		ndi_hold_devi(dip);
		find_dev->dip = dip;

		SCHPC_DEBUG2(D_ATTACH,
		    "schpc_match_dip: pci@%s FOUND dip=0x%p",
		    find_dev->caddr, (void *)find_dev->dip);

		return (DDI_WALK_TERMINATE);
	}

	ASSERT(find_dev->dip == NULL);
	return (DDI_WALK_CONTINUE);
}

/*
 * schpc_buildapid
 *
 * Takes a component address and translates it into a ap_id prefix.
 */
static void
schpc_buildapid(dev_info_t *dip, int slot, char *ap_id)
{
	int r, pci_id_cnt, pci_id_bit;
	int slots_before, found;
	unsigned char *slot_names_data, *s;
	int slot_names_size;
	int slot_num;
	unsigned int bit_mask;

	slot_num = SCHPC_SLOT_NUM(slot);

	if (schpc_use_legacy_apid) {
		SCHPC_DEBUG1(D_APID, "Slot %d - Using Legacy ap-id", slot);

		(void) sprintf(ap_id, "e%02db%dslot%d", schpc_getexpander(dip),
		    schpc_getboard(dip), slot_num);

		SCHPC_DEBUG2(D_APID, "Slot %d - ap-id=%s", slot, ap_id);

		return;
	}

	r = ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "slot-names", (caddr_t)&slot_names_data,
	    &slot_names_size);

	if (r == DDI_PROP_SUCCESS) {

		/*
		 * We can try to use the slot-names property to
		 * build our ap-id.
		 */
		bit_mask = slot_names_data[3] | (slot_names_data[2] << 8) |
		    (slot_names_data[1] << 16) | (slot_names_data[0] << 24);

		pci_id_bit = 1;
		pci_id_cnt = slots_before = found = 0;

		SCHPC_DEBUG2(D_APID, "Slot %d - slot-names bitmask=%x",
		    slot, bit_mask);

		/*
		 * Walk the bit mask until we find the bit that corresponds
		 * to our slots device number.  We count how many bits
		 * we find before we find our slot's bit.
		 */
		while (!found && (pci_id_cnt < 32)) {

			while (schpc_p->schpc_slot[slot].pci_id
			    != pci_id_cnt) {

				/*
				 * Find the next bit set.
				 */
				while (!(bit_mask & pci_id_bit) &&
				    (pci_id_cnt < 32)) {
					pci_id_bit = pci_id_bit << 1;
					pci_id_cnt++;
				}

				if (schpc_p->schpc_slot[slot].pci_id !=
				    pci_id_cnt)
					slots_before++;
				else
					found = 1;
			}
		}

		if (pci_id_cnt < 32) {

			/*
			 * Set ptr to first string.
			 */
			s = slot_names_data + 4;

			/*
			 * Increment past all the strings for the slots
			 * before ours.
			 */
			while (slots_before) {
				while (*s != NULL)
					s++;
				s++;
				slots_before--;
			}

			/*
			 * We should be at our string.
			 */

			(void) sprintf(ap_id, "IO%d_%s",
			    schpc_getexpander(dip), s);

			SCHPC_DEBUG2(D_APID, "Slot %d - ap-id=%s",
			    slot, ap_id);

			kmem_free(slot_names_data, slot_names_size);
			return;
		}

		SCHPC_DEBUG1(D_APID, "Slot %d - slot-names entry not found",
		    slot);

		kmem_free(slot_names_data, slot_names_size);
	} else
		SCHPC_DEBUG1(D_APID, "Slot %d - No slot-names prop found",
		    slot);

	/*
	 * Build the ap-id using the legacy naming scheme.
	 */
	(void) sprintf(ap_id, "e%02db%dslot%d", schpc_getexpander(dip),
	    schpc_getboard(dip), slot_num);

	SCHPC_DEBUG2(D_APID, "Slot %d - ap-id=%s", slot, ap_id);
}

/*
 * schpc_getexpander
 *
 * Returns the Expander Number (0-17) for the dip passed in. The Expander
 * Number is extracted from the portid property of the pci node. Portid
 * consists of <Expbrd#><1110x>, where x is the schizo number.
 */
static int
schpc_getexpander(dev_info_t *dip)
{
	int	id;

	id = ddi_getprop(DDI_DEV_T_ANY, dip, 0, "portid", -1);

	if (id != -1)
		return (id >> 5);
	else {
		id = ddi_getprop(DDI_DEV_T_ANY, dip, 0, "expander", -1);
		return (id);
	}
}

/*
 * schpc_getboard
 *
 * Returns the board number (0 or 1) for the dip passed in.
 */
static int
schpc_getboard(dev_info_t *dip)
{
	_NOTE(ARGUNUSED(dip))

	/*
	 * Hot Pluggable PCI/cPCI slots are only available on
	 * Board 1 (half-bandwidth slot).
	 */
	return (1);
}

/*ARGSUSED*/
static int
schpc_get_slot_status(uint_t expander, uint_t board, uint_t slot)
{
	gdcd_t *gdcd;
	int prd_slot, status, bus;

	SCHPC_DEBUG3(D_ATTACH, "schpc_get_slot_status() "
	    "exp=%d board=%d slot=%d", expander, board, slot);

	if ((gdcd = (gdcd_t *)kmem_zalloc(sizeof (gdcd_t),
	    KM_SLEEP)) == NULL) {
		return (RSV_UNDEFINED);
	}

	/*
	 * Get the Starcat Specific Global DCD Structure from the golden
	 * IOSRAM.
	 */
	if (iosram_rd(GDCD_MAGIC, 0, sizeof (gdcd_t), (caddr_t)gdcd)) {
		cmn_err(CE_WARN, "sc_gptwocfg: Unable To Read GDCD "
		    "From IOSRAM\n");
		kmem_free(gdcd, sizeof (gdcd_t));
		return (RSV_UNDEFINED);
	}

	if (gdcd->h.dcd_magic != GDCD_MAGIC) {

		cmn_err(CE_WARN, "schpc: GDCD Bad Magic 0x%x\n",
		    gdcd->h.dcd_magic);

		kmem_free(gdcd, sizeof (gdcd_t));
		return (RSV_UNDEFINED);
	}

	if (gdcd->h.dcd_version != DCD_VERSION) {
		cmn_err(CE_WARN, "schpc: GDCD Bad Version: "
		    "GDCD Version 0x%x Expecting 0x%x\n",
		    gdcd->h.dcd_version, DCD_VERSION);

		kmem_free(gdcd, sizeof (gdcd_t));
		return (RSV_UNDEFINED);
	}

	if (slot < 2)
		prd_slot = 4;
	else
		prd_slot = 5;

	bus = slot & 0x1;

	status = gdcd->dcd_prd[expander][prd_slot].prd_iocard_rsv[bus][0];

	kmem_free(gdcd, sizeof (gdcd_t));

	SCHPC_DEBUG3(D_ATTACH, "schpc_get_slot_status() "
	    "prd_slot=%d bus=%d status=%d", prd_slot, bus, status);

	return (status);
}

#define	LEAF_SAVE_END			0xff

typedef struct {
	int	reg;
	int	offset;
	int	access_size;
	int	number;
} save_reg_list_t;

/*
 * Save List Array.  Describes the leaf registers that need to
 * be restored after a leaf reset.
 *
 * Entry 1 - Reg Entry: 0=PCI Leaf CSRs, 2=PCI Config Space
 * Entry 2 - Offset Start
 * Entry 3 - Access Size: 8=64 bit, 4=32 bit, 2=16 bit, 1=8 bit
 * Entry 4 - # of registers to be saved starting at offset,
 */
save_reg_list_t	save_reg_list[] = {	0, 0x110, 8, 1,
					0, 0x200, 8, 2,
					0, 0x1000, 8, 0x18,
					0, 0x1a00, 8, 1,
					0, 0x2000, 8, 1,
					0, 0x2020, 8, 1,
					0, 0x2040, 8, 1,
					0, 0x2308, 8, 2,
					0, 0x2800, 8, 1,
					2, 0x04, 2, 1,		/* Command */
					2, 0x0d, 1, 1,		/* Latency */
					2, 0x40, 1, 1,		/* Bus # */
					2, 0x41, 1, 1,		/* Sub. Bus # */
					LEAF_SAVE_END, 0, 0, 0};

static int
schpc_save_leaf(int slot)
{
	int		save_entry, list_entry, reg;
	caddr_t		leaf_regs;
	ddi_device_acc_attr_t attr;

	SCHPC_DEBUG1(D_FREQCHG, "Slot %d - Leaf Registers Saved", slot);

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	attr.devacc_attr_endian_flags = DDI_NEVERSWAP_ACC;

	/*
	 * Map in the 3 addresses spaces defined for XMITS.
	 */
	for (reg = 0; reg < 3; reg++) {
		if (ddi_regs_map_setup(schpc_p->schpc_slot[slot].devi, reg,
		    &leaf_regs, 0, 0, &attr, &schpc_p->schpc_slot[slot].
		    saved_handle[reg]) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Mapin failed\n");
			schpc_p->schpc_slot[slot].saved_regs_va[reg] = NULL;
			return (1);
		}

		schpc_p->schpc_slot[slot].saved_regs_va[reg] = leaf_regs;
	}


	/*
	 * Determine how many entries are in the list so we can
	 * allocate the save space.
	 */
	list_entry = 0;
	save_entry = 0;
	while (save_reg_list[list_entry].reg != LEAF_SAVE_END) {
		save_entry += save_reg_list[list_entry].number;
		list_entry++;
	}

	schpc_p->schpc_slot[slot].saved_size = (save_entry * sizeof (uint64_t));

	if (schpc_p->schpc_slot[slot].saved_size == 0)
		return (0);

	schpc_p->schpc_slot[slot].saved_regs =
	    (uint64_t *)kmem_zalloc(schpc_p->schpc_slot[slot].saved_size,
	    KM_SLEEP);

	/*
	 * Walk through the register list and save contents.
	 */
	list_entry = 0;
	save_entry = 0;
	while (save_reg_list[list_entry].reg != LEAF_SAVE_END) {
		schpc_save_entry(slot, list_entry, save_entry);
		save_entry += save_reg_list[list_entry].number;
		list_entry ++;
	}

	SCHPC_DEBUG1(D_FREQCHG, "Slot %d - Leaf Registers Saved", slot);

	return (0);
}

static void
schpc_restore_leaf(int slot)
{
	int	save_entry, list_entry, reg;

	if (schpc_p->schpc_slot[slot].saved_regs == NULL)
		return;

	/*
	 * Walk through the register list and restore contents.
	 */
	list_entry = 0;
	save_entry = 0;
	while (save_reg_list[list_entry].reg != LEAF_SAVE_END) {

		schpc_restore_entry(slot, list_entry, save_entry);

		save_entry += save_reg_list[list_entry].number;
		list_entry ++;
	}

	/*
	 * Free the mapped in registers.
	 */
	for (reg = 0; reg < 3; reg++) {
		if (schpc_p->schpc_slot[slot].saved_regs_va[reg]) {

			ddi_regs_map_free(
			    &schpc_p->schpc_slot[slot].saved_handle[reg]);

			schpc_p->schpc_slot[slot].saved_regs_va[reg] = NULL;
		}
	}

	kmem_free(schpc_p->schpc_slot[slot].saved_regs,
	    schpc_p->schpc_slot[slot].saved_size);

	schpc_p->schpc_slot[slot].saved_size = 0;
	schpc_p->schpc_slot[slot].saved_regs = NULL;

	SCHPC_DEBUG1(D_FREQCHG, "Slot %d - Leaf Registers Restored", slot);
}

static void
schpc_save_entry(int slot, int list_entry, int save_entry)
{
	int reg, reads = 0;

	reg = save_reg_list[list_entry].reg;

	while (reads < save_reg_list[list_entry].number) {
		switch (save_reg_list[list_entry].access_size) {
		case 8:
			schpc_p->schpc_slot[slot].saved_regs[save_entry] =
			    ddi_get64(
			    schpc_p->schpc_slot[slot].saved_handle[reg],
			    (uint64_t *)(schpc_p->schpc_slot[slot].
			    saved_regs_va[reg]
			    + save_reg_list[list_entry].offset +
			    (reads * sizeof (uint64_t))));
#ifdef DEBUG
			if (schpc_dump_save_regs)
				cmn_err(CE_WARN, "Save 64 %x %lx %lx\n", reg,
				    save_reg_list[list_entry].offset +
				    (reads * sizeof (uint64_t)),
				    schpc_p->schpc_slot[slot].
				    saved_regs[save_entry]);
#endif

			break;
		case 4:
			schpc_p->schpc_slot[slot].saved_regs[save_entry] =
			    ddi_get32(
			    schpc_p->schpc_slot[slot].saved_handle[reg],
			    (uint32_t *)(schpc_p->schpc_slot[slot].
			    saved_regs_va[reg]
			    + save_reg_list[list_entry].offset +
			    (reads * sizeof (uint32_t))));

#ifdef DEBUG
			if (schpc_dump_save_regs)
				cmn_err(CE_WARN, "Save 32 %x %lx %lx\n", reg,
				    save_reg_list[list_entry].offset +
				    (reads * sizeof (uint32_t)),
				    schpc_p->schpc_slot[slot].
				    saved_regs[save_entry]);
#endif

			break;
		case 2:
			schpc_p->schpc_slot[slot].saved_regs[save_entry] =
			    ddi_get16(
			    schpc_p->schpc_slot[slot].saved_handle[reg],
			    (uint16_t *)(schpc_p->schpc_slot[slot].
			    saved_regs_va[reg]
			    + save_reg_list[list_entry].offset +
			    (reads * sizeof (uint16_t))));

#ifdef DEBUG
			if (schpc_dump_save_regs)
				cmn_err(CE_WARN, "Save 16 %x %lx %lx\n", reg,
				    save_reg_list[list_entry].offset +
				    (reads * sizeof (uint16_t)),
				    schpc_p->schpc_slot[slot].
				    saved_regs[save_entry]);
#endif

			break;
		case 1:
			schpc_p->schpc_slot[slot].saved_regs[save_entry] =
			    ddi_get8(
			    schpc_p->schpc_slot[slot].saved_handle[reg],
			    (uint8_t *)(schpc_p->schpc_slot[slot].
			    saved_regs_va[reg]
			    + save_reg_list[list_entry].offset +
			    (reads * sizeof (uint8_t))));

#ifdef DEBUG
			if (schpc_dump_save_regs)
				cmn_err(CE_WARN, "Save 8 %x %lx %lx\n", reg,
				    save_reg_list[list_entry].offset +
				    (reads * sizeof (uint8_t)),
				    schpc_p->schpc_slot[slot].
				    saved_regs[save_entry]);
#endif

			break;
		default:
			cmn_err(CE_WARN,
			    "schpc: Illegal List Entry\n");
		}
		reads++;
		save_entry++;
	}
}

static void
schpc_restore_entry(int slot, int list_entry, int save_entry)
{
	int reg, writes = 0;

	reg = save_reg_list[list_entry].reg;

	while (writes < save_reg_list[list_entry].number) {
		switch (save_reg_list[list_entry].access_size) {
		case 8:
#ifdef DEBUG
			if (schpc_dump_save_regs)
				cmn_err(CE_WARN, "Restore 64 %x %lx %lx\n", reg,
				    save_reg_list[list_entry].offset +
				    (writes * sizeof (uint64_t)),
				    schpc_p->schpc_slot[slot].
				    saved_regs[save_entry]);
#endif

			ddi_put64(schpc_p->schpc_slot[slot].saved_handle[reg],
			    (uint64_t *)(schpc_p->schpc_slot[slot].
			    saved_regs_va[reg]
			    + save_reg_list[list_entry].offset +
			    (writes * sizeof (uint64_t))),
			    schpc_p->schpc_slot[slot].saved_regs[save_entry]);

			break;
		case 4:
#ifdef DEBUG
			if (schpc_dump_save_regs)
				cmn_err(CE_WARN, "Restore 32 %x %lx %lx\n", reg,
				    save_reg_list[list_entry].offset +
				    (writes * sizeof (uint32_t)),
				    schpc_p->schpc_slot[slot].
				    saved_regs[save_entry]);
#endif

			ddi_put32(schpc_p->schpc_slot[slot].saved_handle[reg],
			    (uint32_t *)(schpc_p->schpc_slot[slot].
			    saved_regs_va[reg]
			    + save_reg_list[list_entry].offset +
			    (writes * sizeof (uint32_t))),
			    schpc_p->schpc_slot[slot].saved_regs[save_entry]);

			break;
		case 2:
#ifdef DEBUG
			if (schpc_dump_save_regs)
				cmn_err(CE_WARN, "Restore 16 %x %lx %lx\n", reg,
				    save_reg_list[list_entry].offset +
				    (writes * sizeof (uint16_t)),
				    schpc_p->schpc_slot[slot].
				    saved_regs[save_entry]);
#endif

			ddi_put16(schpc_p->schpc_slot[slot].saved_handle[reg],
			    (uint16_t *)(schpc_p->schpc_slot[slot].
			    saved_regs_va[reg]
			    + save_reg_list[list_entry].offset +
			    (writes * sizeof (uint16_t))),
			    schpc_p->schpc_slot[slot].saved_regs[save_entry]);

			break;
		case 1:
#ifdef DEBUG
			if (schpc_dump_save_regs)
				cmn_err(CE_WARN, "Restore 8 %x %lx %lx\n", reg,
				    save_reg_list[list_entry].offset +
				    (writes * sizeof (uint8_t)),
				    schpc_p->schpc_slot[slot].
				    saved_regs[save_entry]);
#endif

			ddi_put8(schpc_p->schpc_slot[slot].saved_handle[reg],
			    (uint8_t *)(schpc_p->schpc_slot[slot].
			    saved_regs_va[reg]
			    + save_reg_list[list_entry].offset +
			    (writes * sizeof (uint8_t))),
			    schpc_p->schpc_slot[slot].saved_regs[save_entry]);

			break;
		default:
			cmn_err(CE_WARN,
			    "schpc: Illegal List Entry\n");
		}
		writes++;
		save_entry++;
	}
}

/*
 * Returns TRUE if a leaf reset is required to change frequencies/mode.
 */
static int
schpc_is_leaf_reset_required(int slot)
{
	char *name;
	int32_t mod_rev;

	/*
	 * Only XMITS 3.0 and greater connected slots will require a
	 * reset to switch frequency and/or mode.
	 */
	name = ddi_binding_name(schpc_p->schpc_slot[slot].devi);

	if (strcmp(name, "pci108e,8002") == 0) {
		mod_rev = ddi_prop_get_int(DDI_DEV_T_ANY,
		    schpc_p->schpc_slot[slot].devi,
		    DDI_PROP_DONTPASS, "module-revision#", 0);

		SCHPC_DEBUG2(D_FREQCHG, "Slot %d - mod_rev=%x", slot, mod_rev);

		/*
		 * Check for XMITS 3.0 or greater.
		 */
		if (mod_rev >= XMITS_30) {

			/*
			 * The leaf attached to C5V0 (slot 1) should
			 * not be reset.
			 */
			if ((slot & 3) == 1) {

				SCHPC_DEBUG1(D_FREQCHG, "Slot %d - Leaf Reset "
				    "Not Required - C5V0", slot);

				return (0);
			}

			SCHPC_DEBUG1(D_FREQCHG, "Slot %d - Leaf Reset "
			    "Required", slot);

			return (1);
		}
	}
	SCHPC_DEBUG1(D_FREQCHG, "Slot %d - Leaf Reset NOT Required", slot);

	return (0);
}

/*
 * Returns TRUE if the bus can change frequencies.
 */
static int
schpc_is_freq_switchable(int slot)
{
	char *name;
	int32_t mod_rev;

	name = ddi_binding_name(schpc_p->schpc_slot[slot].devi);

	if (strcmp(name, "pci108e,8002") == 0) {
		mod_rev = ddi_prop_get_int(DDI_DEV_T_ANY,
		    schpc_p->schpc_slot[slot].devi,
		    DDI_PROP_DONTPASS, "module-revision#", 0);

		SCHPC_DEBUG2(D_FREQCHG, "Slot %d - mod_rev=%x", slot, mod_rev);

		/*
		 * We will only report back that XMITS 2.0 (mod_rev = 2)
		 * or greater will have the ability to switch frequencies.
		 */
		if (mod_rev >= XMITS_20) {
			SCHPC_DEBUG1(D_FREQCHG, "Slot %d - "
			    "Frequency is switchable", slot);
			return (1);
		}
	}

	SCHPC_DEBUG1(D_FREQCHG, "Slot %d - Frequency is NOT switchable", slot);
	return (0);
}

/*
 * schpc_slot_freq
 *
 * Convert the slot frequency setting to integer value.
 */
static int
schpc_slot_freq(pci_getslot_t *getslotp)
{
	switch (getslotp->slot_freq_setting) {
	case PCIMSG_FREQ_33MHZ:
		return (SCHPC_33MHZ);
	case PCIMSG_FREQ_66MHZ:
		return (SCHPC_66MHZ);
	case PCIMSG_FREQ_90MHZ:
		return (SCHPC_90MHZ);
	case PCIMSG_FREQ_133MHZ:
		return (SCHPC_133MHZ);
	default:
		return (0);
	}
}

/*
 * schpc_find_dip
 *
 * Used by ddi_walk_devs to find the dip which belongs
 * to a certain slot.
 *
 * When this function returns, the dip is held.  It is the
 * responsibility of the caller to release the dip.
 */
static int
schpc_find_dip(dev_info_t *dip, void *arg)
{
	find_dev_t	*find_dev = (find_dev_t *)arg;
	char		*pathname = find_dev->caddr;

	(void) ddi_pathname(dip, pathname);
	if (strcmp(find_dev->cname, pathname) == 0) {
		ndi_hold_devi(dip);
		find_dev->dip = dip;
		return (DDI_WALK_TERMINATE);
	}
	return (DDI_WALK_CONTINUE);
}
