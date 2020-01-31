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
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 */


#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/obpdefs.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <vm/hat_sfmmu.h>
#include <sys/autoconf.h>
#include <sys/open.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/fhc.h>
#include <sys/ac.h>
#include <sys/cpu_module.h>
#include <sys/x_call.h>
#include <sys/fpu/fpusystm.h>
#include <sys/lgrp.h>

/* Useful debugging Stuff */
#include <sys/nexusdebug.h>

/*
 * Function prototypes
 */

static int ac_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int ac_attach(dev_info_t *, ddi_attach_cmd_t);
static int ac_detach(dev_info_t *, ddi_detach_cmd_t);
static int ac_open(dev_t *, int, int, cred_t *);
static int ac_close(dev_t, int, int, cred_t *);
static int ac_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static void ac_add_kstats(struct ac_soft_state *);
static void ac_del_kstats(struct ac_soft_state *);
static int ac_misc_kstat_update(kstat_t *, int);
static void ac_add_picN_kstats(dev_info_t *dip);
static int ac_counters_kstat_update(kstat_t *, int);
static void ac_get_memory_status(struct ac_soft_state *, enum ac_bank_id);
static void ac_eval_memory_status(struct ac_soft_state *, enum ac_bank_id);
static void ac_ecache_flush(uint64_t, uint64_t);
static int ac_pkt_init(ac_cfga_pkt_t *pkt, intptr_t arg, int flag);
static int ac_pkt_fini(ac_cfga_pkt_t *pkt, intptr_t arg, int flag);
static int ac_reset_timeout(int rw);
static void ac_timeout(void *);
static int ac_enter_transition(void);
static void ac_exit_transition(void);


int ac_add_memory(ac_cfga_pkt_t *);
int ac_del_memory(ac_cfga_pkt_t *);
int ac_mem_stat(ac_cfga_pkt_t *, int);
int ac_mem_test_start(ac_cfga_pkt_t *, int);
int ac_mem_test_stop(ac_cfga_pkt_t *, int);
int ac_mem_test_read(ac_cfga_pkt_t *, int);
int ac_mem_test_write(ac_cfga_pkt_t *, int);
void ac_mem_test_stop_on_close(uint_t, uint_t);
/*
 * ac audit message events
 */
typedef enum {
	AC_AUDIT_OSTATE_CONFIGURE,
	AC_AUDIT_OSTATE_UNCONFIGURE,
	AC_AUDIT_OSTATE_SUCCEEDED,
	AC_AUDIT_OSTATE_CONFIGURE_FAILED,
	AC_AUDIT_OSTATE_UNCONFIGURE_FAILED
} ac_audit_evt_t;
static void ac_policy_audit_messages(ac_audit_evt_t event, ac_cfga_pkt_t *pkt);
static char *ac_ostate_typestr(sysc_cfga_ostate_t ostate, ac_audit_evt_t event);

/* The memory ioctl interface version of this driver. */
static ac_mem_version_t ac_mem_version = AC_MEM_ADMIN_VERSION;

static int ac_mem_exercise(ac_cfga_pkt_t *, int);

/*
 * Configuration data structures
 */
static struct cb_ops ac_cb_ops = {
	ac_open,			/* open */
	ac_close,			/* close */
	nulldev,			/* strategy */
	nulldev,			/* print */
	nodev,				/* dump */
	nulldev,			/* read */
	nulldev,			/* write */
	ac_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* cb_prop_op */
	0,				/* streamtab */
	D_MP | D_NEW | D_HOTPLUG,	/* Driver compatibility flag */
	CB_REV,				/* rev */
	nodev,				/* cb_aread */
	nodev				/* cb_awrite */
};

static struct dev_ops ac_ops = {
	DEVO_REV,			/* devo_rev, */
	0,				/* refcnt */
	ac_info,			/* getinfo */
	nulldev,			/* identify */
	nulldev,			/* probe */
	ac_attach,			/* attach */
	ac_detach,			/* detach */
	nulldev,			/* reset */
	&ac_cb_ops,			/* cb_ops */
	(struct bus_ops *)0,		/* bus_ops */
	nulldev,			/* power */
	ddi_quiesce_not_needed,			/* quiesce */
};

/*
 * Driver globals
 */
void *acp;				/* ac soft state hook */
static kstat_t	*ac_picN_ksp[AC_NUM_PICS];	/* performance picN kstats */
static int	ac_attachcnt = 0;	/* number of instances attached */
static kmutex_t ac_attachcnt_mutex;	/* ac_attachcnt lock - attach/detach */
static kmutex_t ac_hot_plug_mode_mutex;
static timeout_id_t	ac_hot_plug_timeout;
static int		ac_hot_plug_timeout_interval = 10;

#define	AC_GETSOFTC(I) \
	((struct ac_soft_state *)ddi_get_soft_state(acp, (I)))

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"AC Leaf",		/* name of module */
	&ac_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

/*
 * These are the module initialization routines.
 */

int
_init(void)
{
	int error;

	if ((error = ddi_soft_state_init(&acp, sizeof (struct ac_soft_state),
	    1)) != 0)
		return (error);

	if ((error = mod_install(&modlinkage)) != 0) {
		ddi_soft_state_fini(&acp);
		return (error);
	}
	/* Initialize global mutex */
	mutex_init(&ac_attachcnt_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ac_hot_plug_mode_mutex, NULL, MUTEX_DRIVER, NULL);
	return (0);
}

int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&acp);
		mutex_destroy(&ac_attachcnt_mutex);
		mutex_destroy(&ac_hot_plug_mode_mutex);
	}
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
ac_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t	dev;
	int	instance;

	if (infocmd == DDI_INFO_DEVT2INSTANCE) {
		dev = (dev_t)arg;
		instance = AC_GETINSTANCE(getminor(dev));
		*result = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
ac_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int instance;
	struct ac_soft_state *softsp;
	struct bd_list *list = NULL;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}

	instance = ddi_get_instance(devi);

	if (ddi_soft_state_zalloc(acp, instance) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "ddi_soft_state_zalloc failed for ac%d",
		    instance);
		return (DDI_FAILURE);
	}

	softsp = ddi_get_soft_state(acp, instance);

	/* Set the dip in the soft state */
	softsp->dip = devi;

	/* Get the board number from this nodes parent */
	softsp->pdip = ddi_get_parent(softsp->dip);
	if ((softsp->board = (int)ddi_getprop(DDI_DEV_T_ANY, softsp->pdip,
	    DDI_PROP_DONTPASS, OBP_BOARDNUM, -1)) == -1) {
		cmn_err(CE_WARN, "ac%d: unable to retrieve %s property",
		    instance, OBP_BOARDNUM);
		goto bad;
	}

	DPRINTF(AC_ATTACH_DEBUG, ("ac%d: devi= 0x%p\n,"
	    " softsp=0x%p\n", instance, (void *)devi, (void *)softsp));

	/* map in the registers for this device. */
	if (ddi_map_regs(softsp->dip, 0, (caddr_t *)&softsp->ac_base, 0, 0)) {
		cmn_err(CE_WARN, "ac%d: unable to map registers", instance);
		goto bad;
	}

	/* Setup the pointers to the hardware registers */
	softsp->ac_id = (uint32_t *)softsp->ac_base;
	softsp->ac_memctl = (uint64_t *)((char *)softsp->ac_base +
	    AC_OFF_MEMCTL);
	softsp->ac_memdecode0 = (uint64_t *)((char *)softsp->ac_base +
	    AC_OFF_MEMDEC0);
	softsp->ac_memdecode1 = (uint64_t *)((char *)softsp->ac_base +
	    AC_OFF_MEMDEC1);
	softsp->ac_counter = (uint64_t *)((char *)softsp->ac_base +
	    AC_OFF_CNTR);
	softsp->ac_mccr = (uint32_t *)((char *)softsp->ac_base +
	    AC_OFF_MCCR);

	/* nothing to suspend/resume here */
	(void) ddi_prop_update_string(DDI_DEV_T_NONE, devi,
	    "pm-hardware-state", "no-suspend-resume");

	/* setup the the AC counter registers to allow for hotplug. */
	list = fhc_bdlist_lock(softsp->board);

	if (list == NULL) {
		cmn_err(CE_PANIC, "ac%d: Board %d not found in database",
		    instance, softsp->board);
	}

	/* set the AC rev into the bd list structure */
	list->sc.ac_compid = *softsp->ac_id;

	list->ac_softsp = softsp;

	if (list->sc.type == CPU_BOARD || list->sc.type == MEM_BOARD) {
		/* Create the minor nodes */
		if (ddi_create_minor_node(devi, NAME_BANK0, S_IFCHR,
		    (AC_PUTINSTANCE(instance) | 0),
		    DDI_NT_ATTACHMENT_POINT, 0) == DDI_FAILURE) {
			cmn_err(CE_WARN, "ac%d: \"%s\" "
			    "ddi_create_minor_node failed", instance,
			    NAME_BANK0);
		}
		if (ddi_create_minor_node(devi, NAME_BANK1, S_IFCHR,
		    (AC_PUTINSTANCE(instance) | 1),
		    DDI_NT_ATTACHMENT_POINT, 0) == DDI_FAILURE) {
			cmn_err(CE_WARN, "ac%d: \"%s\" "
			    "ddi_create_minor_node failed", instance,
			    NAME_BANK0);
		}

		/* purge previous fhc pa database entries */
		fhc_del_memloc(softsp->board);

		/* Inherit Memory Bank Status */
		ac_get_memory_status(softsp, Bank0);
		ac_get_memory_status(softsp, Bank1);
		/* Final Memory Bank Status evaluation and messaging */
		ac_eval_memory_status(softsp, Bank0);
		ac_eval_memory_status(softsp, Bank1);
	}

	fhc_bdlist_unlock();

	/* create the kstats for this device. */
	ac_add_kstats(softsp);

	ddi_report_dev(devi);

	return (DDI_SUCCESS);

bad:
	ddi_soft_state_free(acp, instance);
	return (DDI_FAILURE);
}

/* ARGSUSED */
static int
ac_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	int instance;
	struct ac_soft_state *softsp;
	struct bd_list *list;

	/* get the instance of this devi */
	instance = ddi_get_instance(devi);

	/* get the soft state pointer for this device node */
	softsp = ddi_get_soft_state(acp, instance);

	switch (cmd) {
	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	case DDI_DETACH:
		list = fhc_bdlist_lock(softsp->board);

		if (fhc_bd_detachable(softsp->board))
			break;
		else
			fhc_bdlist_unlock();
		/* FALLTHROUGH */

	default:
		return (DDI_FAILURE);
	}

	ASSERT(list->ac_softsp == softsp);

	if (list->sc.type == CPU_BOARD || list->sc.type == MEM_BOARD) {
		int cpui;

		/*
		 * Test to see if memory is in use on a CPU/MEM board.
		 * In the case of a DR operation this condition
		 * will have been assured when the board was unconfigured.
		 */
		if (softsp->bank[Bank0].busy != 0 ||
		    softsp->bank[Bank0].ostate == SYSC_CFGA_OSTATE_CONFIGURED ||
		    softsp->bank[Bank1].busy != 0 ||
		    softsp->bank[Bank1].ostate == SYSC_CFGA_OSTATE_CONFIGURED) {
			fhc_bdlist_unlock();
			return (DDI_FAILURE);
		}
		/*
		 * CPU busy test is done by the DR sequencer before
		 * device detach called.
		 */

		/*
		 * Flush all E-caches to remove references to this
		 * board's memory.
		 *
		 * Do this one CPU at a time to avoid stalls and timeouts
		 * due to all CPUs flushing concurrently.
		 * xc_one returns silently for non-existant CPUs.
		 */
		for (cpui = 0; cpui < NCPU; cpui++)
			xc_one(cpui, ac_ecache_flush, 0, 0);
	}

	list->ac_softsp = NULL;

	/* delete the kstat for this driver. */
	ac_del_kstats(softsp);

	/* unmap the registers */
	ddi_unmap_regs(softsp->dip, 0, (caddr_t *)&softsp->ac_base, 0, 0);

	fhc_bdlist_unlock();

	/* Remove the minor nodes. */
	ddi_remove_minor_node(devi, NULL);

	/* free the soft state structure */
	ddi_soft_state_free(acp, instance);
	ddi_prop_remove_all(devi);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
ac_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int instance;
	dev_t dev;
	struct ac_soft_state *softsp;
	struct bd_list *board;
	int vis;

	dev = *devp;
	instance = AC_GETINSTANCE(getminor(dev));
	softsp = AC_GETSOFTC(instance);

	/* Is the instance attached? */
	if (softsp == NULL) {
#ifdef DEBUG
		cmn_err(CE_WARN, "ac%d device not attached", instance);
#endif /* DEBUG */
		return (ENXIO);
	}

	/*
	 * If the board is not configured, hide the memory APs
	 */
	board = fhc_bdlist_lock(softsp->board);
	vis = (board != NULL) && MEM_BOARD_VISIBLE(board);
	fhc_bdlist_unlock();

	if (!vis)
		return (ENXIO);

	/* verify that otyp is appropriate */
	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
ac_close(dev_t devt, int flag, int otyp, cred_t *credp)
{
	struct ac_soft_state *softsp;
	int instance;

	instance = AC_GETINSTANCE(getminor(devt));
	softsp = AC_GETSOFTC(instance);
	ASSERT(softsp != NULL);
	ac_mem_test_stop_on_close(softsp->board, AC_GETBANK(getminor(devt)));
	return (DDI_SUCCESS);
}

static int
ac_pkt_init(ac_cfga_pkt_t *pkt, intptr_t arg, int flag)
{
#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(flag & FMODELS) == DDI_MODEL_ILP32) {
		ac_cfga_cmd32_t ac_cmd32;

		if (ddi_copyin((void *)arg, &ac_cmd32,
		    sizeof (ac_cfga_cmd32_t), flag) != 0) {
			return (EFAULT);
		}
		pkt->cmd_cfga.force = ac_cmd32.force;
		pkt->cmd_cfga.test = ac_cmd32.test;
		pkt->cmd_cfga.arg = ac_cmd32.arg;
		pkt->cmd_cfga.errtype = ac_cmd32.errtype;
		pkt->cmd_cfga.outputstr =
		    (char *)(uintptr_t)ac_cmd32.outputstr;
		pkt->cmd_cfga.private =
		    (void *)(uintptr_t)ac_cmd32.private;
	} else
#endif /* _MULTI_DATAMODEL */
	if (ddi_copyin((void *)arg, &(pkt->cmd_cfga),
	    sizeof (ac_cfga_cmd_t), flag) != 0) {
		return (EFAULT);
	}
	pkt->errbuf = kmem_zalloc(SYSC_OUTPUT_LEN, KM_SLEEP);
	return (0);
}

static int
ac_pkt_fini(ac_cfga_pkt_t *pkt, intptr_t arg, int flag)
{
	int ret = TRUE;

#ifdef _MULTI_DATAMODEL
	if (ddi_model_convert_from(flag & FMODELS) == DDI_MODEL_ILP32) {

		if (ddi_copyout(&(pkt->cmd_cfga.errtype),
		    (void *)&(((ac_cfga_cmd32_t *)arg)->errtype),
		    sizeof (ac_err_t), flag) != 0) {
			ret = FALSE;
		}
	} else
#endif
	if (ddi_copyout(&(pkt->cmd_cfga.errtype),
	    (void *)&(((ac_cfga_cmd_t *)arg)->errtype),
	    sizeof (ac_err_t), flag) != 0) {
		ret = FALSE;
	}

	if ((ret != FALSE) && ((pkt->cmd_cfga.outputstr != NULL) &&
	    (ddi_copyout(pkt->errbuf, pkt->cmd_cfga.outputstr,
	    SYSC_OUTPUT_LEN, flag) != 0))) {
			ret = FALSE;
	}

	kmem_free(pkt->errbuf, SYSC_OUTPUT_LEN);
	return (ret);
}

/* ARGSUSED */
static int
ac_ioctl(
	dev_t devt,
	int cmd,
	intptr_t arg,
	int flag,
	cred_t *cred_p,
	int *rval_p)
{
	struct ac_soft_state *softsp;
	ac_cfga_pkt_t cfga_pkt, *pkt;
	int instance;
	int retval;

	instance = AC_GETINSTANCE(getminor(devt));
	softsp = AC_GETSOFTC(instance);
	if (softsp == NULL) {
#ifdef DEBUG
		cmn_err(CE_NOTE, "ac%d device not attached", instance);
#endif /* DEBUG */
		return (ENXIO);
	}

	/*
	 * Dispose of the easy ones first.
	 */
	switch (cmd) {
	case AC_MEM_ADMIN_VER:
		/*
		 * Specify the revision of this ioctl interface driver.
		 */
		if (ddi_copyout(&ac_mem_version, (void *)arg,
		    sizeof (ac_mem_version_t), flag) != 0)
			return (EFAULT);
		return (DDI_SUCCESS);

	case AC_MEM_CONFIGURE:
	case AC_MEM_UNCONFIGURE:
	case AC_MEM_STAT:
	case AC_MEM_TEST_START:
	case AC_MEM_TEST_STOP:
	case AC_MEM_TEST_READ:
	case AC_MEM_TEST_WRITE:
	case AC_MEM_EXERCISE:
		break;

	default:
		return (ENOTTY);
	}
	if (cmd != AC_MEM_STAT && !fpu_exists) {
		return (ENOTSUP);
	}

	pkt = &cfga_pkt;
	if ((retval = ac_pkt_init(pkt, arg, flag)) != 0)
		return (retval);
	pkt->softsp = softsp;
	pkt->bank = AC_GETBANK(getminor(devt));

	switch (cmd) {
	case AC_MEM_CONFIGURE:
		if ((flag & FWRITE) == 0) {
			retval = EBADF;
			break;
		}

		if (pkt->cmd_cfga.private != NULL) {
			retval = EINVAL;
			break;
		}
		ac_policy_audit_messages(AC_AUDIT_OSTATE_CONFIGURE, pkt);
		retval = ac_add_memory(pkt);
		if (!retval)
			ac_policy_audit_messages(
			    AC_AUDIT_OSTATE_SUCCEEDED, pkt);
		else
			ac_policy_audit_messages(
			    AC_AUDIT_OSTATE_CONFIGURE_FAILED, pkt);
		break;

	case AC_MEM_UNCONFIGURE:
		if ((flag & FWRITE) == 0) {
			retval = EBADF;
			break;
		}

		if (pkt->cmd_cfga.private != NULL) {
			retval = EINVAL;
			break;
		}
		ac_policy_audit_messages(AC_AUDIT_OSTATE_UNCONFIGURE, pkt);
		retval = ac_del_memory(pkt);
		if (!retval) {
			ac_policy_audit_messages(
			    AC_AUDIT_OSTATE_SUCCEEDED, pkt);
		} else
			ac_policy_audit_messages(
			    AC_AUDIT_OSTATE_UNCONFIGURE_FAILED, pkt);
		break;

	case AC_MEM_STAT:
		/*
		 * Query usage of a bank of memory.
		 */
		retval = ac_mem_stat(pkt, flag);
		break;

	case AC_MEM_TEST_START:
		if ((flag & FWRITE) == 0) {
			retval = EBADF;
			break;
		}

		retval = ac_mem_test_start(pkt, flag);
		break;

	case AC_MEM_TEST_STOP:
		if ((flag & FWRITE) == 0) {
			retval = EBADF;
			break;
		}

		retval =  ac_mem_test_stop(pkt, flag);
		break;

	case AC_MEM_TEST_READ:
		/*
		 * read a 'page' (or less) of memory safely.
		 */
		if ((flag & FWRITE) == 0) {
			retval = EBADF;
			break;
		}

		retval = ac_mem_test_read(pkt, flag);
		break;

	case AC_MEM_TEST_WRITE:
		/*
		 * write a 'page' (or less) of memory safely.
		 */
		if ((flag & FWRITE) == 0) {
			retval = EBADF;
			break;
		}

		retval = ac_mem_test_write(pkt, flag);
		break;

	case AC_MEM_EXERCISE:
		retval = ac_mem_exercise(pkt, flag);
		break;

	default:
		ASSERT(0);
		retval = ENOTTY;
		break;
	}

	if (ac_pkt_fini(pkt, arg, flag) != TRUE)
		retval = EFAULT;

	return (retval);
}

static void
ac_add_kstats(struct ac_soft_state *softsp)
{
	struct kstat *ac_ksp, *ac_counters_ksp;
	struct ac_kstat *ac_named_ksp;
	struct kstat_named *ac_counters_named_data;

	/*
	 * create the unix-misc kstat for address controller
	 * using the board number as the instance.
	 */
	if ((ac_ksp = kstat_create("unix", softsp->board,
	    AC_KSTAT_NAME, "misc", KSTAT_TYPE_NAMED,
	    sizeof (struct ac_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_PERSISTENT)) == NULL) {
		cmn_err(CE_WARN, "ac%d: kstat_create failed",
		    ddi_get_instance(softsp->dip));
		return;
	}

	ac_named_ksp = (struct ac_kstat *)(ac_ksp->ks_data);

	/* initialize the named kstats */
	kstat_named_init(&ac_named_ksp->ac_memctl,
	    MEMCTL_KSTAT_NAMED,
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ac_named_ksp->ac_memdecode0,
	    MEMDECODE0_KSTAT_NAMED,
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ac_named_ksp->ac_memdecode1,
	    MEMDECODE1_KSTAT_NAMED,
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ac_named_ksp->ac_mccr,
	    MCCR_KSTAT_NAMED,
	    KSTAT_DATA_UINT32);

	kstat_named_init(&ac_named_ksp->ac_counter,
	    CNTR_KSTAT_NAMED,
	    KSTAT_DATA_UINT64);

	kstat_named_init(&ac_named_ksp->ac_bank0_status,
	    BANK_0_KSTAT_NAMED,
	    KSTAT_DATA_CHAR);

	kstat_named_init(&ac_named_ksp->ac_bank1_status,
	    BANK_1_KSTAT_NAMED,
	    KSTAT_DATA_CHAR);

	ac_ksp->ks_update = ac_misc_kstat_update;
	ac_ksp->ks_private = (void *)softsp;
	softsp->ac_ksp = ac_ksp;
	kstat_install(ac_ksp);

	/*
	 * Create the picN kstats if we are the first instance
	 * to attach. We use ac_attachcnt as a count of how
	 * many instances have attached. This is protected by
	 * a mutex.
	 */
	mutex_enter(&ac_attachcnt_mutex);
	if (ac_attachcnt == 0)
		ac_add_picN_kstats(softsp->dip);

	ac_attachcnt ++;
	mutex_exit(&ac_attachcnt_mutex);

	/*
	 * Create the "counter" kstat for each AC instance.
	 * This provides access to the %pcr and %pic
	 * registers for that instance.
	 *
	 * The size of this kstat is AC_NUM_PICS + 1 for %pcr
	 */
	if ((ac_counters_ksp = kstat_create("ac",
	    ddi_get_instance(softsp->dip), "counters",
	    "bus", KSTAT_TYPE_NAMED, AC_NUM_PICS + 1,
	    KSTAT_FLAG_WRITABLE)) == NULL) {

		cmn_err(CE_WARN, "ac%d counters: kstat_create failed",
		    ddi_get_instance(softsp->dip));
		return;
	}
	ac_counters_named_data =
	    (struct kstat_named *)(ac_counters_ksp->ks_data);

	/* initialize the named kstats */
	kstat_named_init(&ac_counters_named_data[0],
	    "pcr", KSTAT_DATA_UINT64);

	kstat_named_init(&ac_counters_named_data[1],
	    "pic0", KSTAT_DATA_UINT64);

	kstat_named_init(&ac_counters_named_data[2],
	    "pic1", KSTAT_DATA_UINT64);

	ac_counters_ksp->ks_update = ac_counters_kstat_update;
	ac_counters_ksp->ks_private = (void *)softsp;
	kstat_install(ac_counters_ksp);

	/* update the sofstate */
	softsp->ac_counters_ksp = ac_counters_ksp;
}

/*
 * called from ac_add_kstats() to create a kstat for each %pic
 * that the AC supports. These (read-only) kstats export the
 * event names and %pcr masks that each %pic supports.
 *
 * if we fail to create any of these kstats we must remove any
 * that we have already created and return;
 *
 * NOTE: because all AC's use the same events we only need to
 *       create the picN kstats once. All instances can use
 *       the same picN kstats.
 *
 *       The flexibility exists to allow each device specify it's
 *       own events by creating picN kstats with the instance number
 *       set to ddi_get_instance(softsp->dip).
 *
 *       When searching for a picN kstat for a device you should
 *       first search for a picN kstat using the instance number
 *       of the device you are interested in. If that fails you
 *       should use the first picN kstat found for that device.
 */
static void
ac_add_picN_kstats(dev_info_t *dip)
{
	typedef struct ac_event_mask {
		char *event_name;
		uint64_t pcr_mask;
	} ac_event_mask_t;

	/*
	 * AC Performance Events.
	 *
	 * We declare an array of event-names and event-masks.
	 */
	ac_event_mask_t ac_events_arr[] = {
		{"mem_bank0_rds", 0x1}, {"mem_bank0_wrs", 0x2},
		{"mem_bank0_stall", 0x3}, {"mem_bank1_rds", 0x4},
		{"mem_bank1_wrs", 0x5}, {"mem_bank1_stall", 0x6},
		{"clock_cycles", 0x7}, {"addr_pkts", 0x8},
		{"data_pkts", 0x9}, {"flow_ctl_cyc", 0xa},
		{"fast_arb_pkts", 0xb}, {"bus_cont_cyc", 0xc},
		{"data_bus_can", 0xd}, {"ac_addr_pkts", 0xe},
		{"ac_data_pkts", 0xf}, {"rts_pkts", 0x10},
		{"rtsa_pkts", 0x11}, {"rto_pkts", 0x12},
		{"rs_pkts", 0x13}, {"wb_pkts", 0x14},
		{"ws_pkts", 0x15}, {"rio_pkts", 0x16},
		{"rbio_pkts", 0x17}, {"wio_pkts", 0x18},
		{"wbio_pkts", 0x19}, {"upa_a_rds_m", 0x1a},
		{"upa_a_rdo_v", 0x1b}, {"upa_b_rds_m", 0x1c},
		{"upa_b_rdo_v", 0x1d}, {"upa_a_preqs_fr", 0x20},
		{"upa_a_sreqs_to", 0x21}, {"upa_a_preqs_to", 0x22},
		{"upa_a_rds_fr", 0x23}, {"upa_a_rdsa_fr", 0x24},
		{"upa_a_rdo_fr", 0x25}, {"upa_a_rdd_fr", 0x26},
		{"upa_a_rio_rbio", 0x27}, {"upa_a_wio_wbio", 0x28},
		{"upa_a_cpb_to", 0x29}, {"upa_a_inv_to", 0x2a},
		{"upa_a_hits_buff", 0x2b}, {"upa_a_wb", 0x2c},
		{"upa_a_wi", 0x2d}, {"upa_b_preqs_fr", 0x30},
		{"upa_b_sreqs_to", 0x31}, {"upa_b_preqs_to", 0x32},
		{"upa_b_rds_fr", 0x33}, {"upa_b_rdsa_fr", 0x34},
		{"upa_b_rdo_fr", 0x35}, {"upa_b_rdd_fr", 0x36},
		{"upa_b_rio_rbio", 0x37}, {"upa_b_wio_wbio", 0x38},
		{"upa_b_cpb_to", 0x39}, {"upa_b_inv_to", 0x3a},
		{"upa_b_hits_buff", 0x3b}, {"upa_b_wb", 0x3c},
		{"upa_b_wi", 0x3d}
	};

#define	AC_NUM_EVENTS sizeof (ac_events_arr) / sizeof (ac_events_arr[0])

	/*
	 * array of clear masks for each pic.
	 * These masks are used to clear the %pcr bits for
	 * each pic.
	 */
	ac_event_mask_t ac_clear_pic[AC_NUM_PICS] = {
		/* pic0 */
		{"clear_pic", (uint64_t)~(0x3f)},
		/* pic1 */
		{"clear_pic", (uint64_t)~(0x3f << 8)}
	};

	struct kstat_named *ac_pic_named_data;
	int		event, pic;
	char		pic_name[30];
	int		instance = ddi_get_instance(dip);
	int		pic_shift = 0;

	for (pic = 0; pic < AC_NUM_PICS; pic++) {
		/*
		 * create the picN kstat. The size of this kstat is
		 * AC_NUM_EVENTS + 1 for the clear_event_mask
		 */
		(void) sprintf(pic_name, "pic%d", pic);	/* pic0, pic1 ... */
		if ((ac_picN_ksp[pic] = kstat_create("ac",
		    instance, pic_name, "bus", KSTAT_TYPE_NAMED,
		    AC_NUM_EVENTS + 1, 0)) == NULL) {

				cmn_err(CE_WARN, "ac %s: kstat_create failed",
				    pic_name);

				/* remove pic0 kstat if pic1 create fails */
				if (pic == 1) {
					kstat_delete(ac_picN_ksp[0]);
					ac_picN_ksp[0] = NULL;
				}
				return;
		}
		ac_pic_named_data =
		    (struct kstat_named *)(ac_picN_ksp[pic]->ks_data);

		/*
		 * when we are storing pcr_masks we need to shift bits
		 * left by 8 for pic1 events.
		 */
		if (pic == 1)
			pic_shift = 8;

		/*
		 * for each picN event we need to write a kstat record
		 * (name = EVENT, value.ui64 = PCR_MASK)
		 */
		for (event = 0; event < AC_NUM_EVENTS; event ++) {

			/* pcr_mask */
			ac_pic_named_data[event].value.ui64 =
			    ac_events_arr[event].pcr_mask << pic_shift;

			/* event-name */
			kstat_named_init(&ac_pic_named_data[event],
			    ac_events_arr[event].event_name,
			    KSTAT_DATA_UINT64);
		}

		/*
		 * we add the clear_pic event and mask as the last
		 * record in the kstat
		 */
		/* pcr mask */
		ac_pic_named_data[AC_NUM_EVENTS].value.ui64 =
		    ac_clear_pic[pic].pcr_mask;

		/* event-name */
		kstat_named_init(&ac_pic_named_data[AC_NUM_EVENTS],
		    ac_clear_pic[pic].event_name,
		    KSTAT_DATA_UINT64);

		kstat_install(ac_picN_ksp[pic]);
	}
}


static void
ac_del_kstats(struct ac_soft_state *softsp)
{
	struct kstat *ac_ksp;
	int pic;

	/* remove "misc" kstat */
	ac_ksp = softsp->ac_ksp;
	softsp->ac_ksp = NULL;
	if (ac_ksp != NULL) {
		ASSERT(ac_ksp->ks_private == (void *)softsp);
		kstat_delete(ac_ksp);
	}

	/* remove "bus" kstat */
	ac_ksp = softsp->ac_counters_ksp;
	softsp->ac_counters_ksp = NULL;
	if (ac_ksp != NULL) {
		ASSERT(ac_ksp->ks_private == (void *)softsp);
		kstat_delete(ac_ksp);
	}

	/*
	 * if we are the last instance to detach we need to
	 * remove the picN kstats. We use ac_attachcnt as a
	 * count of how many instances are still attached. This
	 * is protected by a mutex.
	 */
	mutex_enter(&ac_attachcnt_mutex);
	ac_attachcnt --;
	if (ac_attachcnt == 0) {
		for (pic = 0; pic < AC_NUM_PICS; pic++) {
			if (ac_picN_ksp[pic] != (kstat_t *)NULL) {
				kstat_delete(ac_picN_ksp[pic]);
				ac_picN_ksp[pic] = NULL;
			}
		}
	}
	mutex_exit(&ac_attachcnt_mutex);
}

static enum ac_bank_status
ac_kstat_stat(sysc_cfga_rstate_t rst, sysc_cfga_ostate_t ost)
{
	switch (rst) {
	case SYSC_CFGA_RSTATE_EMPTY:
		return (StNoMem);
	case SYSC_CFGA_RSTATE_DISCONNECTED:
		return (StBad);
	case SYSC_CFGA_RSTATE_CONNECTED:
		switch (ost) {
		case SYSC_CFGA_OSTATE_UNCONFIGURED:
			return (StSpare);
		case SYSC_CFGA_OSTATE_CONFIGURED:
			return (StActive);
		default:
			return (StUnknown);
		}
	default:
		return (StUnknown);
	}
}

static enum ac_bank_condition
ac_kstat_cond(sysc_cfga_cond_t cond)
{
	switch (cond) {
	case SYSC_CFGA_COND_UNKNOWN:
		return (ConUnknown);
	case SYSC_CFGA_COND_OK:
		return (ConOK);
	case SYSC_CFGA_COND_FAILING:
		return (ConFailing);
	case SYSC_CFGA_COND_FAILED:
		return (ConFailed);
	case SYSC_CFGA_COND_UNUSABLE:
		return (ConBad);
	default:
		return (ConUnknown);
	}
}

static int
ac_misc_kstat_update(kstat_t *ksp, int rw)
{
	struct ac_kstat *acksp;
	struct ac_soft_state *softsp;

	acksp = (struct ac_kstat *)ksp->ks_data;
	softsp = (struct ac_soft_state *)ksp->ks_private;
	/* Need the NULL check in case kstat is about to be deleted. */
	ASSERT(softsp->ac_ksp == NULL || ksp == softsp->ac_ksp);

	/* this is a read-only kstat. Bail out on a write */
	if (rw == KSTAT_WRITE) {
		return (EACCES);
	} else {
		/*
		 * copy the current state of the hardware into the
		 * kstat structure.
		 */
		acksp->ac_memctl.value.ui64 = *softsp->ac_memctl;
		acksp->ac_memdecode0.value.ui64 = *softsp->ac_memdecode0;
		acksp->ac_memdecode1.value.ui64 = *softsp->ac_memdecode1;
		acksp->ac_mccr.value.ui32 = *softsp->ac_mccr;
		acksp->ac_counter.value.ui64 = *softsp->ac_counter;
		acksp->ac_bank0_status.value.c[0] =
		    ac_kstat_stat(softsp->bank[0].rstate,
		    softsp->bank[0].ostate);
		acksp->ac_bank0_status.value.c[1] =
		    ac_kstat_cond(softsp->bank[0].condition);
		acksp->ac_bank1_status.value.c[0] =
		    ac_kstat_stat(softsp->bank[1].rstate,
		    softsp->bank[1].ostate);
		acksp->ac_bank1_status.value.c[1] =
		    ac_kstat_cond(softsp->bank[1].condition);
	}
	return (0);
}

static int
ac_counters_kstat_update(kstat_t *ksp, int rw)
{
	struct kstat_named *ac_counters_data;
	struct ac_soft_state *softsp;
	uint64_t pic_register;

	ac_counters_data = (struct kstat_named *)ksp->ks_data;
	softsp = (struct ac_soft_state *)ksp->ks_private;

	/*
	 * We need to start/restart the ac_timeout that will
	 * return the AC counters to hot-plug mode after the
	 * ac_hot_plug_timeout_interval has expired. We tell
	 * ac_reset_timeout() whether this is a kstat_read or a
	 * kstat_write call. If this fails we reject the kstat
	 * operation.
	 */
	if (ac_reset_timeout(rw) != 0)
		return (-1);


	if (rw == KSTAT_WRITE) {
		/*
		 * Write the %pcr value to the softsp->ac_mccr.
		 * This interface does not support writing to the
		 * %pic.
		 */
		*softsp->ac_mccr =
		    (uint32_t)ac_counters_data[0].value.ui64;
	} else {
		/*
		 * Read %pcr and %pic register values and write them
		 * into counters kstat.
		 */

		/* pcr */
		ac_counters_data[0].value.ui64 = *softsp->ac_mccr;

		pic_register = *softsp->ac_counter;
		/*
		 * ac pic register:
		 *  (63:32) = pic1
		 *  (31:00) = pic0
		 */

		/* pic0 */
		ac_counters_data[1].value.ui64 =
		    AC_COUNTER_TO_PIC0(pic_register);
		/* pic1 */
		ac_counters_data[2].value.ui64 =
		    AC_COUNTER_TO_PIC1(pic_register);
	}
	return (0);
}

/*
 * Decode the memory state given to us and plug it into the soft state
 */
static void
ac_get_memory_status(struct ac_soft_state *softsp, enum ac_bank_id id)
{
	char	*property = (id == Bank0) ? AC_BANK0_STATUS : AC_BANK1_STATUS;
	char	*propval;
	int	proplen;
	uint64_t memdec = (id == Bank0) ?
	    *(softsp->ac_memdecode0) : *(softsp->ac_memdecode1);
	uint_t		grp_size;

	softsp->bank[id].busy = 0;
	softsp->bank[id].status_change = ddi_get_time();

	if (GRP_SIZE_IS_SET(memdec)) {
		grp_size = GRP_SPANMB(memdec);

		/* determine the memory bank size (in MB) */
		softsp->bank[id].real_size = softsp->bank[id].use_size =
		    (id == Bank0) ? (grp_size / INTLV0(*softsp->ac_memctl)) :
		    (grp_size / INTLV1(*softsp->ac_memctl));
	} else {
		softsp->bank[id].real_size = softsp->bank[id].use_size = 0;
	}

	/*
	 * decode the memory bank property.  set condition based
	 * on the values.
	 */
	if (ddi_prop_op(DDI_DEV_T_ANY, softsp->dip, PROP_LEN_AND_VAL_ALLOC,
	    DDI_PROP_DONTPASS, property, (caddr_t)&propval, &proplen) ==
	    DDI_PROP_SUCCESS) {
		if (strcmp(propval, AC_BANK_NOMEM) == 0) {
			softsp->bank[id].rstate = SYSC_CFGA_RSTATE_EMPTY;
			softsp->bank[id].ostate = SYSC_CFGA_OSTATE_UNCONFIGURED;
			softsp->bank[id].condition = SYSC_CFGA_COND_UNKNOWN;
		} else if (strcmp(propval, AC_BANK_OK) == 0) {
			softsp->bank[id].rstate = SYSC_CFGA_RSTATE_CONNECTED;
			softsp->bank[id].ostate = SYSC_CFGA_OSTATE_CONFIGURED;
			softsp->bank[id].condition = SYSC_CFGA_COND_OK;
		} else if (strcmp(propval, AC_BANK_SPARE) == 0) {
			softsp->bank[id].rstate = SYSC_CFGA_RSTATE_CONNECTED;
			softsp->bank[id].ostate = SYSC_CFGA_OSTATE_UNCONFIGURED;
			softsp->bank[id].condition = SYSC_CFGA_COND_UNKNOWN;
		} else if (strcmp(propval, AC_BANK_FAILED) == 0) {
			softsp->bank[id].rstate = SYSC_CFGA_RSTATE_DISCONNECTED;
			softsp->bank[id].ostate = SYSC_CFGA_OSTATE_UNCONFIGURED;
			softsp->bank[id].condition = SYSC_CFGA_COND_UNUSABLE;
		} else {
			cmn_err(CE_WARN, "ac%d: board %d, bank %d: "
			    "unknown %smemory state [%s]",
			    ddi_get_instance(softsp->dip), softsp->board, id,
			    (memdec & AC_MEM_VALID) ? "connected " : "",
			    propval);
			if (memdec & AC_MEM_VALID) {
				softsp->bank[id].rstate =
				    SYSC_CFGA_RSTATE_CONNECTED;
				softsp->bank[id].ostate =
				    SYSC_CFGA_OSTATE_CONFIGURED;
				softsp->bank[id].condition =
				    SYSC_CFGA_COND_OK;
			} else {
				softsp->bank[id].rstate =
				    SYSC_CFGA_RSTATE_DISCONNECTED;
				softsp->bank[id].ostate =
				    SYSC_CFGA_OSTATE_UNCONFIGURED;
				softsp->bank[id].condition =
				    SYSC_CFGA_COND_UNUSABLE;
			}
		}

		kmem_free(propval, proplen);
	} else {
		/* we don't have the property, deduce the state of memory */
		if (memdec & AC_MEM_VALID) {
			softsp->bank[id].rstate = SYSC_CFGA_RSTATE_CONNECTED;
			softsp->bank[id].ostate = SYSC_CFGA_OSTATE_CONFIGURED;
			softsp->bank[id].condition = SYSC_CFGA_COND_OK;
		} else {
			/* could be an i/o board... */
			softsp->bank[id].rstate = SYSC_CFGA_RSTATE_EMPTY;
			softsp->bank[id].ostate = SYSC_CFGA_OSTATE_UNCONFIGURED;
			softsp->bank[id].condition = SYSC_CFGA_COND_UNKNOWN;
		}
	}

	/* we assume that all other bank statuses are NOT valid */
	if (softsp->bank[id].rstate == SYSC_CFGA_RSTATE_CONNECTED) {
		if ((memdec & AC_MEM_VALID) != 0) {
			uint64_t	base_pa;

			ASSERT((*softsp->ac_memctl & AC_CSR_REFEN) != 0);
			/* register existence in the memloc database */
			base_pa = GRP_REALBASE(memdec);
			fhc_add_memloc(softsp->board, base_pa, grp_size);
		}
	}
}

static void
ac_eval_memory_status(struct ac_soft_state *softsp, enum ac_bank_id id)
{
	uint64_t memdec = (id == Bank0) ?
	    *(softsp->ac_memdecode0) : *(softsp->ac_memdecode1);
	uint64_t	base_pa;

	/*
	 * Downgrade the status of any bank that did not get
	 * programmed.
	 */
	if (softsp->bank[id].rstate == SYSC_CFGA_RSTATE_CONNECTED &&
	    softsp->bank[id].ostate == SYSC_CFGA_OSTATE_UNCONFIGURED &&
	    (memdec & AC_MEM_VALID) == 0) {
		cmn_err(CE_WARN, "ac%d: board %d, bank %d: "
		    "spare memory bank not valid - it was ",
		    ddi_get_instance(softsp->dip), softsp->board, id);
		cmn_err(CE_WARN, "misconfigured by the system "
		    "firmware.  Disabling...");
		softsp->bank[id].rstate = SYSC_CFGA_RSTATE_DISCONNECTED;
		softsp->bank[id].ostate = SYSC_CFGA_OSTATE_UNCONFIGURED;
		softsp->bank[id].condition = SYSC_CFGA_COND_UNUSABLE;
	}
	/*
	 * Log a message about good banks.
	 */
	if (softsp->bank[id].rstate == SYSC_CFGA_RSTATE_CONNECTED) {
		ASSERT((memdec & AC_MEM_VALID) != 0);
		base_pa = GRP_REALBASE(memdec);

		cmn_err(CE_CONT, "?ac%d board %d bank %d: "
		    "base 0x%" PRIx64 " size %dmb rstate %d "
		    "ostate %d condition %d\n",
		    ddi_get_instance(softsp->dip),
		    softsp->board, id, base_pa, softsp->bank[id].real_size,
		    softsp->bank[id].rstate, softsp->bank[id].ostate,
		    softsp->bank[id].condition);
	}
}

/*ARGSUSED*/
static void
ac_ecache_flush(uint64_t a, uint64_t b)
{
	cpu_flush_ecache();
}

static char *
ac_ostate_typestr(sysc_cfga_ostate_t ostate, ac_audit_evt_t event)
{
	char *type_str;

	switch (ostate) {
	case SYSC_CFGA_OSTATE_UNCONFIGURED:
		switch (event) {
		case AC_AUDIT_OSTATE_UNCONFIGURE:
			type_str = "unconfiguring";
			break;
		case AC_AUDIT_OSTATE_SUCCEEDED:
		case AC_AUDIT_OSTATE_UNCONFIGURE_FAILED:
			type_str = "unconfigured";
			break;
		default:
			type_str = "unconfigure?";
			break;
		}
		break;
	case SYSC_CFGA_OSTATE_CONFIGURED:
		switch (event) {
		case AC_AUDIT_OSTATE_CONFIGURE:
			type_str = "configuring";
			break;
		case AC_AUDIT_OSTATE_SUCCEEDED:
		case AC_AUDIT_OSTATE_CONFIGURE_FAILED:
			type_str = "configured";
			break;
		default:
			type_str = "configure?";
			break;
		}
		break;

	default:
		type_str = "undefined occupant state";
		break;
	}
	return (type_str);
}

static void
ac_policy_audit_messages(ac_audit_evt_t event, ac_cfga_pkt_t *pkt)
{
	struct ac_soft_state *softsp = pkt->softsp;

	switch (event) {
		case AC_AUDIT_OSTATE_CONFIGURE:
			cmn_err(CE_NOTE,
			    "%s memory bank %d in slot %d",
			    ac_ostate_typestr(SYSC_CFGA_OSTATE_CONFIGURED,
			    event), pkt->bank,
			    softsp->board);
			break;
		case AC_AUDIT_OSTATE_UNCONFIGURE:
			cmn_err(CE_NOTE,
			    "%s memory bank %d in slot %d",
			    ac_ostate_typestr(
			    SYSC_CFGA_OSTATE_UNCONFIGURED,
			    event), pkt->bank,
			    softsp->board);
			break;
		case AC_AUDIT_OSTATE_SUCCEEDED:
			cmn_err(CE_NOTE,
			    "memory bank %d in slot %d is %s",
			    pkt->bank, softsp->board,
			    ac_ostate_typestr(
			    softsp->bank[pkt->bank].ostate,
			    event));
			break;
		case AC_AUDIT_OSTATE_CONFIGURE_FAILED:
			cmn_err(CE_NOTE,
			"memory bank %d in slot %d not %s",
			    pkt->bank,
			    softsp->board,
			    ac_ostate_typestr(
			    SYSC_CFGA_OSTATE_CONFIGURED,
			    event));
			break;
		case AC_AUDIT_OSTATE_UNCONFIGURE_FAILED:
			cmn_err(CE_NOTE,
			    "memory bank %d in slot %d not %s",
			    pkt->bank,
			    softsp->board,
			    ac_ostate_typestr(
			    SYSC_CFGA_OSTATE_UNCONFIGURED,
			    event));
			break;
		default:
			cmn_err(CE_NOTE,
			    "unknown audit of memory bank %d in slot %d",
			    pkt->bank, softsp->board);
			break;
	}
}

#include <vm/page.h>
#include <vm/hat.h>

static int
ac_mem_exercise(ac_cfga_pkt_t *pkt, int flag)
{
	struct ac_mem_info *mem_info;
	pfn_t base;
	pgcnt_t npgs;

	mem_info = &pkt->softsp->bank[pkt->bank];
	if (mem_info->rstate == SYSC_CFGA_RSTATE_CONNECTED) {
		uint64_t base_pa, bank_size;
		uint64_t decode;

		decode = (pkt->bank == Bank0) ?
		    *pkt->softsp->ac_memdecode0 : *pkt->softsp->ac_memdecode1;
		base_pa = GRP_REALBASE(decode);
		bank_size = GRP_UK2SPAN(decode);

		base = base_pa >> PAGESHIFT;
		npgs = bank_size >> PAGESHIFT;
	} else {
		base = 0;
		npgs = 0;
	}
	switch (pkt->cmd_cfga.arg) {
	case AC_MEMX_RELOCATE_ALL: {
		pfn_t pfn, pglim;
		struct ac_memx_relocate_stats rstat;

		if (npgs == 0 ||
		    mem_info->ostate != SYSC_CFGA_OSTATE_CONFIGURED) {
			return (EINVAL);
		}
		if (mem_info->busy != FALSE) {
			return (EBUSY);
		}
		bzero(&rstat, sizeof (rstat));
		rstat.base = (uint_t)base;
		rstat.npgs = (uint_t)npgs;
		pglim = base + npgs;
		for (pfn = base; pfn < pglim; pfn++) {
			page_t *pp, *pp_repl;

		retry:
			pp = page_numtopp_nolock(pfn);
			if (pp != NULL) {
				if (!page_trylock(pp, SE_EXCL)) {
					pp = NULL;
					rstat.nolock++;
				}
				if (pp != NULL && page_pptonum(pp) != pfn) {
					page_unlock(pp);
					goto retry;
				}
			} else {
				rstat.nopaget++;
			}
			if (pp != NULL && PP_ISFREE(pp)) {
				page_unlock(pp);
				rstat.isfree++;
				pp = NULL;
			}
			if (pp != NULL) {
				spgcnt_t npgs;
				int result;

				pp_repl = NULL;
				result = page_relocate(&pp, &pp_repl, 1, 1,
				    &npgs, NULL);
				if (result == 0) {
					while (npgs-- > 0) {
						page_t *tpp;

						ASSERT(pp_repl != NULL);
						tpp = pp_repl;
						page_sub(&pp_repl, tpp);
						page_unlock(tpp);
					}

					rstat.reloc++;
				} else {
					page_unlock(pp);
					rstat.noreloc++;
				}
			}
		}
		if (pkt->cmd_cfga.private != NULL && ddi_copyout(&rstat,
		    pkt->cmd_cfga.private, sizeof (rstat), flag) != 0)
			return (EFAULT);
		return (DDI_SUCCESS);
	}

	default:
		return (EINVAL);
	}
}

static int
ac_reset_timeout(int rw)
{
	mutex_enter(&ac_hot_plug_mode_mutex);

	if ((ac_hot_plug_timeout == (timeout_id_t)NULL) &&
	    (rw == KSTAT_READ)) {
		/*
		 * We are in hot-plug mode. A kstat_read is not
		 * going to affect this. return 0 to allow the
		 * kstat_read to continue.
		 */
		mutex_exit(&ac_hot_plug_mode_mutex);
		return (0);

	} else if ((ac_hot_plug_timeout == (timeout_id_t)NULL) &&
	    (rw == KSTAT_WRITE)) {
		/*
		 * There are no pending timeouts and we have received a
		 * kstat_write request so we must be transitioning
		 * from "hot-plug" mode to non "hot-plug" mode.
		 * Try to lock all boards before allowing the kstat_write.
		 */
		if (ac_enter_transition() == TRUE)
			fhc_bdlist_unlock();
		else {
			/* cannot lock boards so fail */
			mutex_exit(&ac_hot_plug_mode_mutex);
			return (-1);
		}

		/*
		 * We need to display a Warning about hot-plugging any
		 * boards. This message is only needed when we are
		 * transitioning out of "hot-plug" mode.
		 */
		cmn_err(CE_WARN, "This machine is being taken out of "
		    "hot-plug mode.");
		cmn_err(CE_CONT, "Do not attempt to hot-plug boards "
		    "or power supplies in this system until further notice.");

	} else if (ac_hot_plug_timeout != (timeout_id_t)NULL) {
		/*
		 * There is a pending timeout so we must already be
		 * in non "hot-plug" mode. It doesn't matter if the
		 * kstat request is a read or a write.
		 *
		 * We need to cancel the existing timeout.
		 */
		(void) untimeout(ac_hot_plug_timeout);
		ac_hot_plug_timeout = NULL;
	}

	/*
	 * create a new timeout.
	 */
	ac_hot_plug_timeout = timeout(ac_timeout, NULL,
	    drv_usectohz(ac_hot_plug_timeout_interval * 1000000));

	mutex_exit(&ac_hot_plug_mode_mutex);
	return (0);
}

static void
ac_timeout(void *arg)
{
	struct ac_soft_state *softsp;
	fhc_bd_t	*board;

#ifdef lint
	arg = arg;
#endif /* lint */

	ac_hot_plug_timeout = (timeout_id_t)NULL;

	(void) fhc_bdlist_lock(-1);

	/*
	 * Foreach ac in the board list we need to
	 * re-program the pcr into "hot-plug" mode.
	 * We also program the pic register with the
	 * bus pause timing
	 */
	board = fhc_bd_first();
	while (board != NULL) {
		softsp = board->ac_softsp;
		if (softsp == NULL) {
			/*
			 * This board must not have an AC.
			 * Skip it and move on.
			 */
			board = fhc_bd_next(board);
			continue;
		}
		/* program the pcr into hot-plug mode */
		*softsp->ac_mccr = AC_CLEAR_PCR(*softsp->ac_mccr);
		*softsp->ac_mccr = AC_SET_HOT_PLUG(*softsp->ac_mccr);

		/* program the pic with the bus pause time value */
		*softsp->ac_counter = AC_SET_PIC_BUS_PAUSE(softsp->board);

		/* get the next board */
		board = fhc_bd_next(board);
	}

	ac_exit_transition();

	fhc_bdlist_unlock();

	/*
	 * It is now safe to start hot-plugging again. We need
	 * to display a message.
	 */
	cmn_err(CE_NOTE, "This machine is now in hot-plug mode.");
	cmn_err(CE_CONT, "Board and power supply hot-plug operations "
	    "can be resumed.");
}

/*
 * This function will acquire the lock and set the in_transition
 * bit for all the slots.  If the slots are being used,
 * we return FALSE; else set in_transition and return TRUE.
 */
static int
ac_enter_transition(void)
{
	fhc_bd_t	*list;
	sysc_cfga_stat_t *sysc_stat_lk;

	/* mutex lock the structure */
	(void) fhc_bdlist_lock(-1);

	list = fhc_bd_clock();

	/* change the in_transition bit */
	sysc_stat_lk = &list->sc;
	if (sysc_stat_lk->in_transition == TRUE) {
		fhc_bdlist_unlock();
		return (FALSE);
	} else {
		sysc_stat_lk->in_transition = TRUE;
		return (TRUE);
	}
}

/*
 * clear the in_transition bit for all the slots.
 */
static void
ac_exit_transition(void)
{
	fhc_bd_t	*list;
	sysc_cfga_stat_t *sysc_stat_lk;

	ASSERT(fhc_bdlist_locked());

	list = fhc_bd_clock();

	sysc_stat_lk = &list->sc;
	ASSERT(sysc_stat_lk->in_transition == TRUE);
	sysc_stat_lk->in_transition = FALSE;
}
