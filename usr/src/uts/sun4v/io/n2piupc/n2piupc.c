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
 * Driver interconnect for the N2 PIU performance counter driver.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/hsvc.h>
#include <n2piupc_tables.h>
#include <n2piupc.h>

/* Debugging level. */
#ifdef DEBUG
int n2piupc_debug = 0;
#endif /* DEBUG */

/* State structure anchor. */
void *n2piupc_state_p;

static int n2piupc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int n2piupc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);

/*
 * Support for hypervisor versioning.
 * Need to negotiate for the N2PIU_PERF_COUNTER_GROUP
 */

#define	N2PIUPC_REQ_MAJOR_VER		1
#define	N2PIUPC_REQ_MINOR_VER		0

static hsvc_info_t n2piupc_hsvc = {
	HSVC_REV_1,
	NULL,
	N2PIU_PERF_COUNTER_GROUP_ID,
	N2PIUPC_REQ_MAJOR_VER,
	N2PIUPC_REQ_MINOR_VER,
	MODULE_NAME	/* Passed in as a #define from Makefile */
};

static uint64_t	n2piupc_sup_minor;

/* Driver boilerplate stuff.  Having no minor nodes keep things very simple. */

static struct dev_ops n2piupc_ops = {
	DEVO_REV,
	0,
	nulldev,
	nulldev,
	nulldev,
	n2piupc_attach,
	n2piupc_detach,
	nodev,
	NULL,
	NULL,
	nodev,
	ddi_quiesce_not_needed,
};

extern struct mod_ops mod_driverops;

static struct modldrv md = {
	&mod_driverops,
	"N2 PIU Perf Counter",
	&n2piupc_ops,
};

static struct modlinkage ml = {
	MODREV_1,
	(void *)&md,
	NULL
};


/*
 * One-time module-wide initialization.
 */
int
_init(void)
{
	int rval;

	/* Negotiate for hypervisor support. */
	if ((rval = hsvc_register(&n2piupc_hsvc, &n2piupc_sup_minor)) !=
	    DDI_SUCCESS) {
		N2PIUPC_DBG1("%s: Could not hsvc_register: %d\n",
		    MODULE_NAME, rval);
		goto bad_hv_register;
	}

	/* Initialize per-leaf soft state pointer. */
	if ((rval = ddi_soft_state_init(&n2piupc_state_p,
	    sizeof (n2piupc_t), 1)) != DDI_SUCCESS)
		goto bad_softstate_init;

	/* Initialize one-time kstat structures. */
	if ((rval = n2piupc_kstat_init()) != DDI_SUCCESS)
		goto bad_kstat_init;

	/* If all checks out, install the module. */
	if ((rval = mod_install(&ml)) == DDI_SUCCESS)

		return (DDI_SUCCESS);

bad_mod_install:
	n2piupc_kstat_fini();
bad_kstat_init:
	ddi_soft_state_fini(&n2piupc_state_p);
bad_softstate_init:
	(void) hsvc_unregister(&n2piupc_hsvc);
bad_hv_register:
	return (rval);
}

/*
 * One-time module-wide cleanup, after last detach is done.
 */
int
_fini(void)
{
	int rval;

	/*
	 * Remove the module first as this operation is the only thing here
	 * which can fail.
	 */
	rval = mod_remove(&ml);
	if (rval != DDI_SUCCESS)
		return (rval);

	/* One-shot kstat data structure cleanup. */
	n2piupc_kstat_fini();

	/* Free px soft state */
	ddi_soft_state_fini(&n2piupc_state_p);

	/* Unregister with hypervisor. */
	(void) hsvc_unregister(&n2piupc_hsvc);

	return (rval);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ml, modinfop));
}

/*
 * Per-instance initialization.  Suspend/resume not supported.
 */
static int
n2piupc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	n2piupc_t *n2piupc_p;
	uint32_t regprop[4];
	int len;
	int instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_RESUME:
	case DDI_ATTACH:
		if (ddi_soft_state_zalloc(n2piupc_state_p, instance) !=
		    DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: Can't allocate softstate.\n",
			    NAMEINST(dip));
			goto bad_softstate;
		}

		n2piupc_p = (n2piupc_t *)ddi_get_soft_state(n2piupc_state_p,
		    instance);

		n2piupc_p->n2piupc_dip = dip;

		/* Get handle for hypervisor access of performance counters. */
		len = sizeof (regprop);
		if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    "reg", (caddr_t)regprop, &len) != DDI_SUCCESS) {

			cmn_err(CE_WARN,
			    "%s%d: Cannot get reg property\n",
			    NAMEINST(dip));
			goto bad_handle;
		}

		/* Look only at the lower 28 bits of the highest cell. */
		n2piupc_p->n2piupc_handle = regprop[0] & 0xfffffff;

		/* Set up kstats. */
		if (n2piupc_kstat_attach(n2piupc_p) != DDI_SUCCESS)
			goto bad_kstat_attach;

		return (DDI_SUCCESS);

bad_kstat_attach:
bad_handle:
		(void) ddi_soft_state_free(n2piupc_state_p, instance);
bad_softstate:
		return (DDI_FAILURE);

	default:
		return (DDI_FAILURE);
	}
}

/*
 * Per-instance cleanup.  Suspend/resume not supported.
 */
static int
n2piupc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);

	n2piupc_t *n2piupc_p = (n2piupc_t *)ddi_get_soft_state(
	    n2piupc_state_p, instance);

	switch (cmd) {
	case DDI_SUSPEND:
	case DDI_DETACH:
		n2piupc_kstat_detach(n2piupc_p);
		(void) ddi_soft_state_free(n2piupc_state_p, instance);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}
