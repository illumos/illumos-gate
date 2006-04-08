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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/devops.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/scfd/scfparam.h>


/*
 * character/block entry point structure
 */
static struct cb_ops scf_cb_ops = {
	scf_open,			/* open */
	scf_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	nodev,				/* read */
	nodev,				/* write */
	scf_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* prop_op */
	(struct streamtab *)NULL,	/* streamtab */
	D_NEW | D_MP			/* flag */
};

/*
 * device operations structure
 */
static struct dev_ops scf_dev_ops = {
	DEVO_REV,			/* dev_ops revision */
	0,				/* reference */
	scf_getinfo,			/* getinfo */
	nulldev,			/* identify */
	nulldev,			/* probe */
	scf_attach,			/* attach */
	scf_detach,			/* detach */
	nodev,				/* reset */
	&scf_cb_ops,			/* cb_ops */
	(struct bus_ops *)NULL,		/* bus_ops */
	NULL				/* power entry */
};

/*
 * linkage structure for loadable driver
 */
extern struct mod_ops mod_driverops;
static struct modldrv scf_modldrv = {
	&mod_driverops,			/* mod_driverops */
	SCF_DRIVER_VERSION,		/* version number */
	&scf_dev_ops			/* dev_ops */
};

/*
 * module linkage structure
 */
static struct modlinkage scf_modlinkage = {
	MODREV_1,			/* modlinkage revision */
	(void *)&scf_modldrv,		/* linkage */
	(void *)NULL			/* (end of linkage) */
};

/*
 * Function list
 */
void	scf_free_resource(void);

/*
 * _init()
 *
 * Description: Install and initialization processing of module.
 *
 */
int
_init(void)
{
#define	SCF_FUNC_NAME		"_init() "
	int			error;

	SCFDBGMSG(SCF_DBGFLAG_DDI, SCF_FUNC_NAME ": start");

	/* initialize software state */
	error = ddi_soft_state_init(&scfstate, sizeof (scf_state_t), 0);
	if (error != 0) {
		cmn_err(CE_WARN, "%s: _init: ddi_soft_state_init failed.\n",
			scf_driver_name);
		goto END_init;
	}

	SCF_DBG_DRV_TRACE_INIT;

	/* Last report code initialize */
	scf_comtbl.scf_last_report = NOT_SEND_REPORT;

	/* XSCF status initialize */
	scf_comtbl.scf_status = SCF_STATUS_UNKNOWN;

	/* allocate memory */
	scf_comtbl.report_sensep =
		(scfreport_t *)kmem_zalloc((size_t)(sizeof (scfreport_t) *
		scf_report_sense_pool_max), KM_SLEEP);
	scf_comtbl.getevent_sensep =
		(scfevent_t *)kmem_zalloc((size_t)(sizeof (scfevent_t) *
		scf_getevent_pool_max), KM_SLEEP);
	scf_comtbl.resource_flag |= DID_ALLOCBUF;

	/* initialize mutex */
	mutex_init(&scf_comtbl.attach_mutex, NULL, MUTEX_DRIVER, 0);
	scf_comtbl.resource_flag |= DID_MUTEX_ATH;
	mutex_init(&scf_comtbl.si_mutex, NULL, MUTEX_DRIVER, 0);
	scf_comtbl.resource_flag |= DID_MUTEX_SI;
	mutex_init(&scf_comtbl.trc_mutex, NULL, MUTEX_DRIVER, 0);
	scf_comtbl.resource_flag |= DID_MUTEX_TRC;

	/* initialize cv */
	cv_init(&scf_comtbl.cmd_cv, NULL, CV_DRIVER, NULL);
	cv_init(&scf_comtbl.cmdend_cv, NULL, CV_DRIVER, NULL);
	cv_init(&scf_comtbl.cmdwait_cv, NULL, CV_DRIVER, NULL);
	cv_init(&scf_comtbl.cmdbusy_cv, NULL, CV_DRIVER, NULL);
	cv_init(&scf_comtbl.rsense_cv, NULL, CV_DRIVER, NULL);
	cv_init(&scf_comtbl.rdcsense_cv, NULL, CV_DRIVER, NULL);
	cv_init(&scf_comtbl.rdctrl_cv, NULL, CV_DRIVER, NULL);
	cv_init(&scf_comtbl.getevent_cv, NULL, CV_DRIVER, NULL);
	cv_init(&scf_comtbl.suspend_wait_cv, NULL, CV_DRIVER, NULL);
	scf_comtbl.resource_flag |= DID_CV;

	/* install module into system */
	error = mod_install(&scf_modlinkage);
	if (error != 0) {
		cmn_err(CE_WARN, "%s: _init: mod_install failed.\n",
			scf_driver_name);
		/* release driver resources */
		scf_free_resource();
	}

/*
 * END_init
 */
	END_init:

	SCFDBGMSG1(SCF_DBGFLAG_DDI, SCF_FUNC_NAME ": end return = %d", error);
	return (error);
}


/*
 * _fini()
 *
 * Description: Remove processing of module.
 *
 */
int
_fini(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"_fini() "
	int			error;

	SCFDBGMSG(SCF_DBGFLAG_DDI, SCF_FUNC_NAME ": start");

	/* remove module from system */
	error = mod_remove(&scf_modlinkage);
	if (error == 0) {
		/* release driver resources */
		scf_free_resource();
	}

	SCFDBGMSG1(SCF_DBGFLAG_DDI, SCF_FUNC_NAME ": end return = %d", error);
	return (error);
}


/*
 * _info()
 *
 * Description: Return module information.
 *
 */
int
_info(struct modinfo *modinfop)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"_info() "
	int			error;

	SCFDBGMSG(SCF_DBGFLAG_DDI, SCF_FUNC_NAME ": start");

	/* return module infomarion */
	error = mod_info(&scf_modlinkage, modinfop);

	SCFDBGMSG1(SCF_DBGFLAG_DDI, SCF_FUNC_NAME ": end return = %d", error);
	return (error);
}


/*
 * scf_free_resource()
 *
 * Description: Release processing of driver resources.
 *
 */
/* ARGSUSED */
void
scf_free_resource(void)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_free_resource() "

	SCFDBGMSG(SCF_DBGFLAG_DDI, SCF_FUNC_NAME ": start");

	SCF_DBG_IOMP_FREE;

	/* System interface area release */
	if (scf_comtbl.report_sensep != NULL) {
		kmem_free((void *)scf_comtbl.report_sensep,
			(size_t)(sizeof (scfreport_t) *
			scf_report_sense_pool_max));
		scf_comtbl.report_sensep = NULL;
	}
	if (scf_comtbl.getevent_sensep != NULL) {
		kmem_free((void *)scf_comtbl.getevent_sensep,
			(size_t)(sizeof (scfevent_t) * scf_getevent_pool_max));
		scf_comtbl.getevent_sensep = NULL;
	}
	scf_comtbl.resource_flag &= (~DID_ALLOCBUF);

	/* destroy cv */
	if (scf_comtbl.resource_flag & DID_CV) {
		cv_destroy(&scf_comtbl.cmd_cv);
		cv_destroy(&scf_comtbl.cmdend_cv);
		cv_destroy(&scf_comtbl.cmdwait_cv);
		cv_destroy(&scf_comtbl.cmdbusy_cv);
		cv_destroy(&scf_comtbl.rsense_cv);
		cv_destroy(&scf_comtbl.rdcsense_cv);
		cv_destroy(&scf_comtbl.rdctrl_cv);
		cv_destroy(&scf_comtbl.getevent_cv);
		cv_destroy(&scf_comtbl.suspend_wait_cv);
		scf_comtbl.resource_flag &= (~DID_CV);
	}

	/* remove softint */
	if (scf_comtbl.resource_flag & DID_SOFTINTR) {
		ddi_remove_softintr(scf_comtbl.scf_softintr_id);
		scf_comtbl.resource_flag &= (~DID_SOFTINTR);
	}

	/* destroy mutex */
	if (scf_comtbl.resource_flag & DID_MUTEX_TRC) {
		mutex_destroy(&scf_comtbl.trc_mutex);
		scf_comtbl.resource_flag &= (~DID_MUTEX_TRC);
	}
	if (scf_comtbl.resource_flag & DID_MUTEX_ALL) {
		mutex_destroy(&scf_comtbl.all_mutex);
		scf_comtbl.resource_flag &= (~DID_MUTEX_ALL);
	}
	if (scf_comtbl.resource_flag & DID_MUTEX_SI) {
		mutex_destroy(&scf_comtbl.si_mutex);
		scf_comtbl.resource_flag &= (~DID_MUTEX_SI);
	}
	if (scf_comtbl.resource_flag & DID_MUTEX_ATH) {
		mutex_destroy(&scf_comtbl.attach_mutex);
		scf_comtbl.resource_flag &= (~DID_MUTEX_ATH);
	}

	/* release software state */
	ddi_soft_state_fini(&scfstate);

	SCFDBGMSG(SCF_DBGFLAG_DDI, SCF_FUNC_NAME ": end");
}
