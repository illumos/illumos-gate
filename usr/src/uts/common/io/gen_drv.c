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
 * generic character driver
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/uio.h>
#include <sys/buf.h>
#include <sys/modctl.h>
#include <sys/open.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>


#define	NUMEVENTS 6
#define	COMPONENTS 2
#define	COMP_0_MAXPWR	3
#define	COMP_1_MAXPWR	2
#define	MINPWR		0
static int maxpwr[] = { COMP_0_MAXPWR, COMP_1_MAXPWR };

/*
 * The state for each generic device.
 * NOTE: We save the node_type in the state structure. The node_type string
 * (and not a copy) is stashed in a minor node by  ddi_create_minor_node(),
 * so ddi_remove_minor_node() must occur prior to state free.
 */
typedef struct dstate {
	uint_t		flag;
	dev_info_t	*dip;			/* my devinfo handle */
	char		*node_type;	/* stable node_type copy */
	ddi_callback_id_t gen_cb_ids[NUMEVENTS];
	kmutex_t	lock;
	char		*nodename;
	int		level[COMPONENTS];	/* pm level */
	int		busy[COMPONENTS];	/* busy state */
} dstate_t;


static void *dstates;

static int gen_debug = 0;

#ifdef DEBUG
#define	gen_debug gen_debug_on
static int gen_debug_on = 0;
#define	GEN_DEBUG(args) if (gen_debug) cmn_err args
#else
#define	GEN_DEBUG(args)
#endif

extern void prom_printf(const char *fmt, ...);

static int gen_open(dev_t *devp, int flag, int otyp, cred_t *cred);
static int gen_close(dev_t devp, int flag, int otyp, cred_t *cred);
static int gen_read(dev_t dev, struct uio *uiop, cred_t *credp);
static int gen_write(dev_t dev, struct uio *uiop, cred_t *credp);
static int gen_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp);
static int gen_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int gen_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static void gen_event_cb(dev_info_t *dip, ddi_eventcookie_t cookie,
    void *arg, void *impl_data);

static int gen_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result);
static int gen_create_minor_nodes(dev_info_t *, struct dstate *);
static int gen_power(dev_info_t *, int, int);

static struct cb_ops gen_cb_ops = {
	gen_open,			/* open */
	gen_close,			/* close */
	nodev,				/* strategy */
	nodev,				/* print */
	nodev,				/* dump */
	gen_read,			/* read */
	gen_write,			/* write */
	gen_ioctl,			/* ioctl */
	nodev,				/* devmap */
	nodev,				/* mmap */
	nodev,				/* segmap */
	nochpoll,			/* poll */
	ddi_prop_op,			/* prop_op */
	NULL,				/* streamtab */
	D_NEW | D_MP | D_HOTPLUG,	/* flag */
	CB_REV,				/* cb_rev */
	nodev,				/* aread */
	nodev				/* awrite */
};


static struct dev_ops gen_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	gen_info,		/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	gen_attach,		/* attach */
	gen_detach,		/* detach */
	nodev,			/* reset */
	&gen_cb_ops,		/* driver ops */
	(struct bus_ops *)0,	/* bus ops */
	gen_power,		/* power */
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

/*
 * INST_TO_MINOR() gives the starting minor number for a given gen_drv driver
 * instance. A shift left by 6 bits allows for each instance to have upto
 * 64 (2^6) minor numbers. The maximum minor number allowed by the system
 * is L_MAXMIN32 (0x3ffff). This effectively limits the gen_drv instance
 * numbers from 0 to 0xfff for a total of 4096 instances.
 */
#define	INST_TO_MINOR(i)	(i << 6)
#define	MINOR_TO_INST(mn)	(mn >> 6)

static char *mnodetypes[] = {
	"ddi_nt",
	"ddi_nt:device_type",
	"ddi_nt:device_class:bus_class",
	"ddi_nt2",
	"ddi_nt2:device_type",
	"ddi_nt2:device_type:bus_class",
};
#define	N_NTYPES	(sizeof (mnodetypes) / sizeof (char *))

static struct modldrv modldrv = {
	&mod_driverops,
	"generic test driver",
	&gen_ops
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};


/*
 * flags
 */
#define	OPEN_FLAG			0x001
#define	PWR_HAS_CHANGED_ON_RESUME_FLAG	0x002
#define	FAIL_SUSPEND_FLAG		0x004
#define	PUP_WITH_PWR_HAS_CHANGED_FLAG	0x008
#define	POWER_FLAG			0x010
#define	LOWER_POWER_FLAG		0x020
#define	NO_INVOL_FLAG			0x040
#define	PM_SUPPORTED_FLAG		0x080

/*
 * ioctl commands (non-devctl ioctl commands)
 */
#define	GENDRV_IOCTL				('P' << 8)
#define	GENDRV_IOFAULT_SIMULATE			(GENDRV_IOCTL | 0)
#define	GENDRV_NDI_EVENT_TEST			(GENDRV_IOCTL | 1)

int
_init(void)
{
	int e;

	if ((e = ddi_soft_state_init(&dstates,
	    sizeof (struct dstate), 0)) != 0) {
		return (e);
	}

	if ((e = mod_install(&modlinkage)) != 0)  {
		ddi_soft_state_fini(&dstates);
	}

	return (e);
}

int
_fini(void)
{
	int e;

	if ((e = mod_remove(&modlinkage)) != 0)  {
		return (e);
	}
	ddi_soft_state_fini(&dstates);
	return (e);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

static int
gen_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int instance = ddi_get_instance(devi);
	struct dstate *dstatep;
	int rval;
	int n_devs;
	int n_minorcomps;
	int isclone;
	ddi_eventcookie_t dev_offline_cookie, dev_reset_cookie;
	ddi_eventcookie_t bus_reset_cookie, bus_quiesce_cookie;
	ddi_eventcookie_t bus_unquiesce_cookie, bus_test_post_cookie;
	int i_init = 0;
	int level_tmp;

	int i;
	char *pm_comp[] = {
		"NAME=leaf0",
		"0=D0",
		"1=D1",
		"2=D2",
		"3=D3",
		"NAME=leaf1",
		"0=off",
		"1=blank",
		"2=on"};
	char *pm_hw_state = {"needs-suspend-resume"};


	switch (cmd) {
	case DDI_ATTACH:

		if (ddi_soft_state_zalloc(dstates, instance) !=
		    DDI_SUCCESS) {
			cmn_err(CE_CONT, "%s%d: can't allocate state\n",
			    ddi_get_name(devi), instance);

			return (DDI_FAILURE);
		}

		dstatep = ddi_get_soft_state(dstates, instance);
		dstatep->dip = devi;
		mutex_init(&dstatep->lock, NULL, MUTEX_DRIVER, NULL);

		n_devs = ddi_prop_get_int(DDI_DEV_T_ANY, devi, 0,
		    "ndevs", 1);

		isclone = ddi_prop_get_int(DDI_DEV_T_ANY, devi, 0,
		    "isclone", 0);

		n_minorcomps = ddi_prop_get_int(DDI_DEV_T_ANY, devi, 0,
		    "ncomps", 1);

		GEN_DEBUG((CE_CONT,
		    "%s%d attaching: n_devs=%d n_minorcomps=%d isclone=%d",
		    ddi_get_name(devi), ddi_get_instance(devi),
		    n_devs, n_minorcomps, isclone));

		if (isclone) {
			if (ddi_create_minor_node(devi, "gen", S_IFCHR,
			    INST_TO_MINOR(instance), mnodetypes[0],
			    isclone) != DDI_SUCCESS) {
				ddi_remove_minor_node(devi, NULL);
				ddi_soft_state_free(dstates, instance);
				cmn_err(CE_WARN, "%s%d: can't create minor "
				"node", ddi_get_name(devi), instance);

				return (DDI_FAILURE);
			}
			rval = DDI_SUCCESS;
		} else {
			rval = gen_create_minor_nodes(devi, dstatep);
			if (rval != DDI_SUCCESS) {
				ddi_prop_remove_all(devi);
				ddi_remove_minor_node(devi, NULL);
				ddi_soft_state_free(dstates, instance);
				cmn_err(CE_WARN, "%s%d: can't create minor "
				"nodes", ddi_get_name(devi), instance);

				return (DDI_FAILURE);
			}
		}

		if (ddi_get_eventcookie(devi, "pshot_dev_offline",
		    &dev_offline_cookie) == DDI_SUCCESS) {
			(void) ddi_add_event_handler(devi, dev_offline_cookie,
			    gen_event_cb, NULL, &(dstatep->gen_cb_ids[0]));
		}

		if (ddi_get_eventcookie(devi, "pshot_dev_reset",
		    &dev_reset_cookie) == DDI_SUCCESS) {
			(void) ddi_add_event_handler(devi, dev_reset_cookie,
			    gen_event_cb, NULL, &(dstatep->gen_cb_ids[1]));
		}

		if (ddi_get_eventcookie(devi, "pshot_bus_reset",
		    &bus_reset_cookie) == DDI_SUCCESS) {
			(void) ddi_add_event_handler(devi, bus_reset_cookie,
			    gen_event_cb, NULL, &(dstatep->gen_cb_ids[2]));
		}

		if (ddi_get_eventcookie(devi, "pshot_bus_quiesce",
		    &bus_quiesce_cookie) == DDI_SUCCESS) {
			(void) ddi_add_event_handler(devi, bus_quiesce_cookie,
			    gen_event_cb, NULL, &(dstatep->gen_cb_ids[3]));
		}

		if (ddi_get_eventcookie(devi, "pshot_bus_unquiesce",
		    &bus_unquiesce_cookie) == DDI_SUCCESS) {
			(void) ddi_add_event_handler(devi,
			    bus_unquiesce_cookie, gen_event_cb,
			    NULL, &(dstatep->gen_cb_ids[4]));
		}

		if (ddi_get_eventcookie(devi, "pshot_bus_test_post",
		    &bus_test_post_cookie) == DDI_SUCCESS) {
			(void) ddi_add_event_handler(devi,
			    bus_test_post_cookie, gen_event_cb,
			    NULL, &(dstatep->gen_cb_ids[5]));
		}

		/*
		 * initialize the devices' pm state
		 */
		mutex_enter(&dstatep->lock);
		dstatep->flag &= ~OPEN_FLAG;
		dstatep->flag &= ~PWR_HAS_CHANGED_ON_RESUME_FLAG;
		dstatep->flag &= ~FAIL_SUSPEND_FLAG;
		dstatep->flag &= ~PUP_WITH_PWR_HAS_CHANGED_FLAG;
		dstatep->flag |= LOWER_POWER_FLAG;
		dstatep->flag &= ~NO_INVOL_FLAG;
		dstatep->flag |= PM_SUPPORTED_FLAG;
		dstatep->busy[0] = 0;
		dstatep->busy[1] = 0;
		dstatep->level[0] = -1;
		dstatep->level[1] = -1;
		mutex_exit(&dstatep->lock);

		/*
		 * stash the nodename
		 */
		dstatep->nodename = ddi_node_name(devi);

		/*
		 * Check if the no-involuntary-power-cycles property
		 * was created. Set NO_INVOL_FLAG if so.
		 */
		if (ddi_prop_exists(DDI_DEV_T_ANY, dstatep->dip,
		    (DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
		    "no-involuntary-power-cycles") == 1) {
			GEN_DEBUG((CE_CONT,
			    "%s%d: DDI_ATTACH:\n\tno-involuntary-power-cycles"
			    " property was created",
			    ddi_node_name(devi), ddi_get_instance(devi)));
			mutex_enter(&dstatep->lock);
			dstatep->flag |= NO_INVOL_FLAG;
			mutex_exit(&dstatep->lock);
		}

		/*
		 * Check if the dependency-property property
		 * was created.
		 */
		if (ddi_prop_exists(DDI_DEV_T_ANY, dstatep->dip,
		    (DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
		    "dependency-property") == 1) {
			GEN_DEBUG((CE_CONT,
			    "%s%d: DDI_ATTACH:\n\tdependency-property"
			    " property was created",
			    ddi_node_name(devi), ddi_get_instance(devi)));
		}

		/*
		 * create the pm-components property. two comps:
		 * 4 levels on comp0, 3 on comp 1.
		 * - skip for a "tape" device, clear PM_SUPPORTED_FLAG
		 */
		if (strcmp(ddi_node_name(devi), "tape") != 0) {
			if (ddi_prop_update_string_array(DDI_DEV_T_NONE, devi,
			    "pm-components", pm_comp, 9) != DDI_PROP_SUCCESS) {
				cmn_err(CE_WARN, "%s%d: %s\n",
				    ddi_node_name(devi),
				    ddi_get_instance(devi),
				    "unable to create \"pm-components\" "
				    " property.");

				return (DDI_FAILURE);
			}
		} else {
			mutex_enter(&dstatep->lock);
			dstatep->flag &= ~PM_SUPPORTED_FLAG;
			mutex_exit(&dstatep->lock);
		}

		/*
		 * Check if the pm-components property was created
		 */
		if (dstatep->flag & PM_SUPPORTED_FLAG) {
			if (ddi_prop_exists(DDI_DEV_T_ANY, dstatep->dip,
			    (DDI_PROP_DONTPASS | DDI_PROP_NOTPROM),
			    "pm-components") != 1) {
				cmn_err(CE_WARN, "%s%d: DDI_ATTACH:\n\t%s",
				    ddi_node_name(devi),
				    ddi_get_instance(devi),
				    "\"pm-components\" property does"
				    " not exist");

				return (DDI_FAILURE);

			} else {
				GEN_DEBUG((CE_CONT, "%s%d: DDI_ATTACH:"
				    " created pm-components property",
				    ddi_node_name(devi),
				    ddi_get_instance(devi)));
			}
		}

		/*
		 * create the pm-hardware-state property.
		 * needed to get DDI_SUSPEND and DDI_RESUME calls
		 */
		if (ddi_prop_update_string(DDI_DEV_T_NONE, devi,
		    "pm-hardware-state", pm_hw_state) != DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "%s%d: DDI_ATTACH:\n\t%s\n",
			    ddi_node_name(devi), ddi_get_instance(devi),
			    "unable to create \"pm-hardware-state\" "
			    " property.");

			return (DDI_FAILURE);
		}

		/*
		 * set power levels to max via pm_raise_power(),
		 */
		mutex_enter(&dstatep->lock);
		i_init = (dstatep->flag & PM_SUPPORTED_FLAG) ? 0 : COMPONENTS;
		mutex_exit(&dstatep->lock);
		for (i = i_init; i < COMPONENTS; i++) {
			GEN_DEBUG((CE_CONT,
			    "%s%d: DDI_ATTACH: pm_raise_power comp %d "
			    "to level %d", ddi_node_name(devi),
			    ddi_get_instance(devi), i, maxpwr[i]));
			if (pm_raise_power(dstatep->dip, i, maxpwr[i]) !=
			    DDI_SUCCESS) {
				cmn_err(CE_WARN,
				    "%s%d: DDI_ATTACH: pm_raise_power failed\n",
				    ddi_node_name(devi),
				    ddi_get_instance(devi));
				dstatep->level[i] = -1;

				return (DDI_FAILURE);
			}
		}

		if (rval == DDI_SUCCESS) {
			ddi_report_dev(devi);
		}
		return (rval);


	case DDI_RESUME:
		GEN_DEBUG((CE_CONT, "%s%d: DDI_RESUME", ddi_node_name(devi),
		    ddi_get_instance(devi)));

		dstatep = ddi_get_soft_state(dstates, ddi_get_instance(devi));
		if (dstatep == NULL) {

			return (DDI_FAILURE);
		}

		/*
		 * Call pm_power_has_changed() if flag
		 * PWR_HAS_CHANGED_ON_RESUME_FLAG is set,
		 * then clear the flag
		 */
		mutex_enter(&dstatep->lock);
		i_init = (dstatep->flag & PM_SUPPORTED_FLAG) ? 0 : COMPONENTS;
		mutex_exit(&dstatep->lock);
		if (dstatep->flag & PWR_HAS_CHANGED_ON_RESUME_FLAG) {
			for (i = i_init; i < COMPONENTS; i++) {
				GEN_DEBUG((CE_CONT,
				    "%s%d: DDI_RESUME: pm_power_has_changed "
				    "comp %d to level %d", ddi_node_name(devi),
				    ddi_get_instance(devi), i, maxpwr[i]));
				mutex_enter(&dstatep->lock);
				level_tmp = dstatep->level[i];
				dstatep->level[i] = maxpwr[i];
				if (pm_power_has_changed(dstatep->dip, i,
				    maxpwr[i]) != DDI_SUCCESS) {
					cmn_err(CE_WARN,
					    "%s%d: DDI_RESUME:\n\t"
					    " pm_power_has_changed"
					    " failed: comp %d to level %d\n",
					    ddi_node_name(devi),
					    ddi_get_instance(devi),
					    i, maxpwr[i]);
					dstatep->level[i] = level_tmp;
				}
				mutex_exit(&dstatep->lock);
			}
		} else {
			/*
			 * Call pm_raise_power() instead
			 */
			for (i = i_init; i < COMPONENTS; i++) {
				GEN_DEBUG((CE_CONT,
				    "%s%d: DDI_RESUME: pm_raise_power"
				    " comp %d to level %d",
				    ddi_node_name(devi), ddi_get_instance(devi),
				    i, maxpwr[i]));
				if (pm_raise_power(dstatep->dip, i, maxpwr[i])
				    != DDI_SUCCESS) {
					cmn_err(CE_WARN,
					    "%s%d: DDI_RESUME:"
					    "\n\tpm_raise_power"
					    "failed: comp %d to level %d\n",
					    ddi_node_name(devi),
					    ddi_get_instance(devi),
					    i, maxpwr[i]);
				}
			}
		}

		return (DDI_SUCCESS);

	default:
		GEN_DEBUG((CE_WARN, "attach: default"));
		return (DDI_FAILURE);
	}
}

static int
gen_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	struct dstate *dstatep;
	int instance;
	int i;
	int rv;
	int rm_power;
	int level_tmp;

#ifdef DEBUG
	int n_devs;
	int n_minorcomps;
	int isclone;
#endif

	switch (cmd) {
	case DDI_DETACH:
		GEN_DEBUG((CE_CONT, "%s%d: DDI_DETACH", ddi_node_name(devi),
		    ddi_get_instance(devi)));

		instance = ddi_get_instance(devi);
		dstatep = ddi_get_soft_state(dstates, instance);
		if (dstatep == NULL) {

			return (DDI_FAILURE);
}

#ifdef DEBUG
		n_devs = ddi_prop_get_int(DDI_DEV_T_ANY, devi, 0,
		    "ndevs", 1);

		isclone = ddi_prop_get_int(DDI_DEV_T_ANY, devi, 0,
		    "isclone", 0);

		n_minorcomps = ddi_prop_get_int(DDI_DEV_T_ANY, devi, 0,
		    "ncomps", 1);
#endif /* DEBUG */

		/*
		 * power off component 1.
		 */
		if (dstatep->flag & PM_SUPPORTED_FLAG) {
			GEN_DEBUG((CE_CONT,
			    "%s%d: DDI_DETACH: pm_lower_power comp 1 level %d",
			    ddi_node_name(devi), ddi_get_instance(devi),
			    MINPWR));
			if (pm_lower_power(dstatep->dip, 1, MINPWR)
			    != DDI_SUCCESS) {
				cmn_err(CE_WARN, "%s%d: DDI_DETACH:\n\t"
				    "pm_lower_power failed for comp 1 to"
				    " level %d\n", ddi_node_name(devi),
				    ddi_get_instance(devi), MINPWR);

				return (DDI_FAILURE);
			}

			/*
			 * check power level. Issue pm_power_has_changed
			 * if not at MINPWR.
			 */
			mutex_enter(&dstatep->lock);
			level_tmp = dstatep->level[1];
			dstatep->level[1] = MINPWR;
			if (dstatep->level[1] != MINPWR) {
				GEN_DEBUG((CE_NOTE, "%s%d: DDI_DETACH:"
				    " power off via pm_power_has_changed"
				    " instead", ddi_node_name(devi),
				    ddi_get_instance(devi)));
				if (pm_power_has_changed(dstatep->dip,
				    1, MINPWR) != DDI_SUCCESS) {
					GEN_DEBUG((CE_NOTE, "%s%d: DDI_DETACH:"
					    " pm_power_has_changed failed for"
					    " comp 1 to level %d",
					    ddi_node_name(devi),
					    ddi_get_instance(devi),
					    MINPWR));
					dstatep->level[1] = level_tmp;
					mutex_exit(&dstatep->lock);

					return (DDI_FAILURE);
				}
			}
			mutex_exit(&dstatep->lock);
		}

		/*
		 * If the LOWER_POWER_FLAG flag is not set,
		 * don't call pm_lowr_power() for comp 0.
		 * This should be used only for the XXXXX@XX,no_invol
		 * devices that export the
		 * no-involuntary-power-cycles property
		 */
		if (!(dstatep->flag & LOWER_POWER_FLAG) &&
		    dstatep->flag & PM_SUPPORTED_FLAG) {
			cmn_err(CE_NOTE, "%s%d: DDI_DETACH:\n\t"
			    " NOT CALLING PM_LOWER_POWER():"
			    " LOWER_POWER_FLAG NOT SET\n",
			    ddi_node_name(devi), ddi_get_instance(devi));
		} else if (dstatep->flag & PM_SUPPORTED_FLAG) {
			GEN_DEBUG((CE_CONT,
			    "%s%d: DDI_DETACH: pm_lower_power comp 0 level %d",
			    ddi_node_name(devi), ddi_get_instance(devi),
			    MINPWR));
			if (pm_lower_power(dstatep->dip, 0, MINPWR)
			    != DDI_SUCCESS) {
				cmn_err(CE_WARN, "%s%d: DDI_DETACH:\n\t"
				    "pm_lower_power failed for comp 0 to"
				    " level %d\n", ddi_node_name(devi),
				    ddi_get_instance(devi), MINPWR);

				return (DDI_FAILURE);
			}

			/*
			 * check power level. Issue pm_power_has_changed
			 * if not at MINPWR.
			 */
			mutex_enter(&dstatep->lock);
			level_tmp = dstatep->level[0];
			dstatep->level[0] = MINPWR;
			if (dstatep->level[0] != MINPWR) {
				GEN_DEBUG((CE_NOTE, "%s%d: DDI_DETACH:"
				    " power off via pm_power_has_changed"
				    " instead", ddi_node_name(devi),
				    ddi_get_instance(devi)));
				if (pm_power_has_changed(dstatep->dip,
				    0, MINPWR) != DDI_SUCCESS) {
					GEN_DEBUG((CE_NOTE, "%s%d: DDI_DETACH:"
					    " pm_power_has_changed failed for"
					    " comp 0 to level %d",
					    ddi_node_name(devi),
					    ddi_get_instance(devi),
					    MINPWR));
					dstatep->level[0] = level_tmp;
					mutex_exit(&dstatep->lock);

					return (DDI_FAILURE);
				}
			}
			mutex_exit(&dstatep->lock);
		}

		GEN_DEBUG((CE_CONT,
		    "%s%d detaching: n_devs=%d n_minorcomps=%d isclone=%d",
		    ddi_node_name(devi), ddi_get_instance(devi),
		    n_devs, n_minorcomps, isclone));

		for (i = 0; i < NUMEVENTS; i++) {
			if (dstatep->gen_cb_ids[i]) {
		(void) ddi_remove_event_handler(dstatep->gen_cb_ids[i]);
				dstatep->gen_cb_ids[i] = NULL;
			}
		}

		ddi_prop_remove_all(devi);
		ddi_remove_minor_node(devi, NULL);
		if (dstatep->node_type)
			kmem_free(dstatep->node_type,
			    strlen(dstatep->node_type) + 1);
		ddi_soft_state_free(dstates, instance);
		return (DDI_SUCCESS);

	case DDI_SUSPEND:
		GEN_DEBUG((CE_CONT, "%s%d: DDI_SUSPEND",
		    ddi_node_name(devi), ddi_get_instance(devi)));

		instance = ddi_get_instance(devi);
		dstatep = ddi_get_soft_state(dstates, instance);
		if (dstatep == NULL) {

			return (DDI_FAILURE);
		}

		/*
		 * fail the suspend if FAIL_SUSPEND_FLAG is set.
		 * clear the FAIL_SUSPEND_FLAG flag
		 */
		mutex_enter(&dstatep->lock);
		if (dstatep->flag & FAIL_SUSPEND_FLAG) {
			GEN_DEBUG((CE_CONT, "%s%d: DDI_SUSPEND:"
			    " FAIL_SUSPEND_FLAG is set,"
			    " fail suspend",
			    ddi_node_name(devi), ddi_get_instance(devi)));
			dstatep->flag &= ~FAIL_SUSPEND_FLAG;
			rv = DDI_FAILURE;
		} else {
			rv = DDI_SUCCESS;
		}
		mutex_exit(&dstatep->lock);

		/*
		 * Issue ddi_removing_power() to determine if the suspend
		 * was initiated by either CPR or DR. If CPR, the system
		 * will be powered OFF; if this driver has set the
		 * NO_INVOL_FLAG, then refuse to suspend. If DR, power
		 * will not be removed, thus allow the suspend.
		 */
		if (dstatep->flag & NO_INVOL_FLAG &&
		    dstatep->flag & PM_SUPPORTED_FLAG) {
			GEN_DEBUG((CE_CONT, "%s%d: DDI_SUSPEND:"
			    " check via ddi_removing_power()",
			    ddi_node_name(devi), ddi_get_instance(devi)));

			rm_power = ddi_removing_power(dstatep->dip);

			if (rm_power < 0) {
				cmn_err(CE_WARN, "%s%d: DDI_SUSPEND:"
				    " ddi_removing_power() failed\n",
				    ddi_node_name(devi),
				    ddi_get_instance(devi));
			} else if (rm_power == 1) {
				/*
				 * CPR: power will be removed
				 */
				GEN_DEBUG((CE_CONT, "%s%d: DDI_SUSPEND:\n\t"
				    " CPR: POWER WILL BE REMOVED, THEREFORE"
				    " REFUSE TO SUSPEND", ddi_node_name(devi),
				    ddi_get_instance(devi)));
				rv = DDI_FAILURE;
			} else if (rm_power == 0) {
				/*
				 * DR: power will not be removed
				 */
				GEN_DEBUG((CE_CONT, "%s%d: DDI_SUSPEND:\n\t"
				    " DR: POWER WILL NOT BE REMOVED, THEREFORE"
				    " ALLOW THE SUSPEND", ddi_node_name(devi),
				    ddi_get_instance(devi)));
				rv = DDI_SUCCESS;
			}
		}

		/*
		 * power OFF via pm_power_has_changed()
		 */
		mutex_enter(&dstatep->lock);
		if (dstatep->flag & PM_SUPPORTED_FLAG &&
		    !(dstatep->flag & NO_INVOL_FLAG)) {
			level_tmp = dstatep->level[0];
			dstatep->level[0] = MINPWR;
			GEN_DEBUG((CE_CONT,
			    "%s%d: DDI_SUSPEND: pm_power_has_changed comp 0"
			    " level %d", ddi_node_name(devi),
			    ddi_get_instance(devi), MINPWR));
			if (pm_power_has_changed(dstatep->dip, 0, MINPWR)
			    != DDI_SUCCESS) {
				cmn_err(CE_WARN, "%s%d: DDI_SUSPEND:\n\t"
				    "pm_power_has_changed failed for comp 0 to"
				    " level %d\n", ddi_node_name(devi),
				    ddi_get_instance(devi), MINPWR);
				dstatep->level[0] = level_tmp;
				mutex_exit(&dstatep->lock);

				return (DDI_FAILURE);
			}
		}
		mutex_exit(&dstatep->lock);

		return (rv);

	default:

		return (DDI_FAILURE);
	}
}

/* ARGSUSED */
static int
gen_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	dev_t	dev;
	int	instance;

	if (infocmd != DDI_INFO_DEVT2INSTANCE)
		return (DDI_FAILURE);

	dev = (dev_t)arg;
	instance = MINOR_TO_INST(getminor(dev));
	*result = (void *)(uintptr_t)instance;
	return (DDI_SUCCESS);
}


/*ARGSUSED*/
static int
gen_open(dev_t *devp, int flag, int otyp, cred_t *cred)
{
	minor_t minor;
	struct dstate *dstatep;

	if (otyp != OTYP_BLK && otyp != OTYP_CHR)
		return (EINVAL);

	minor = getminor(*devp);
	if ((dstatep = ddi_get_soft_state(dstates,
	    MINOR_TO_INST(minor))) == NULL)
		return (ENXIO);

	mutex_enter(&dstatep->lock);
	dstatep->flag |= OPEN_FLAG;
	mutex_exit(&dstatep->lock);

	GEN_DEBUG((CE_CONT,
	    "%s%d open",
	    dstatep->nodename, MINOR_TO_INST(minor)));

	return (0);
}

/*ARGSUSED*/
static int
gen_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	struct dstate *dstatep;
	minor_t minor = getminor(dev);

	if (otyp != OTYP_BLK && otyp != OTYP_CHR)
		return (EINVAL);

	dstatep = ddi_get_soft_state(dstates, MINOR_TO_INST(minor));

	if (dstatep == NULL)
		return (ENXIO);

	mutex_enter(&dstatep->lock);
	dstatep->flag &= ~OPEN_FLAG;
	mutex_exit(&dstatep->lock);

	GEN_DEBUG((CE_CONT,
	    "%s%d close",
	    dstatep->nodename, MINOR_TO_INST(minor)));

	return (0);
}

/*ARGSUSED*/
static int
gen_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	struct dstate *dstatep;
	ddi_eventcookie_t cookie;
	int instance;
	int rval = 0;
	char *nodename;
	int i;
	struct devctl_iocdata *dcp;
	uint_t state;
	int ret;
	int level_tmp;

	instance = MINOR_TO_INST(getminor(dev));
	dstatep = ddi_get_soft_state(dstates, instance);
	nodename = dstatep->nodename;

	if (dstatep == NULL)
		return (ENXIO);

	/*
	 * read devctl ioctl data
	 */
	if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS)
		return (EFAULT);

	switch (cmd) {
	case GENDRV_IOFAULT_SIMULATE:
		if (ddi_get_eventcookie(dstatep->dip, DDI_DEVI_FAULT_EVENT,
		    &(cookie)) != NDI_SUCCESS)
			return (DDI_FAILURE);

		return (ndi_post_event(dstatep->dip, dstatep->dip, cookie,
		    NULL));

	case GENDRV_NDI_EVENT_TEST:
		if (ddi_get_eventcookie(dstatep->dip, "pshot_dev_offline",
		    &cookie) == NDI_SUCCESS) {
			(void) ndi_post_event(dstatep->dip, dstatep->dip,
			    cookie, NULL);
		}

		if (ddi_get_eventcookie(dstatep->dip, "pshot_dev_reset",
		    &cookie) == NDI_SUCCESS) {
			(void) ndi_post_event(dstatep->dip, dstatep->dip,
			    cookie, NULL);
		}

		if (ddi_get_eventcookie(dstatep->dip, "pshot_bus_reset",
		    &cookie) == NDI_SUCCESS) {
			(void) ndi_post_event(dstatep->dip, dstatep->dip,
			    cookie, NULL);
		}

		if (ddi_get_eventcookie(dstatep->dip, "pshot_bus_quiesce",
		    &cookie) == NDI_SUCCESS) {
			(void) ndi_post_event(dstatep->dip, dstatep->dip,
			    cookie, NULL);
		}

		if (ddi_get_eventcookie(dstatep->dip, "pshot_bus_unquiesce",
		    &cookie) == NDI_SUCCESS) {
			(void) ndi_post_event(dstatep->dip, dstatep->dip,
			    cookie, NULL);
		}

		if (ddi_get_eventcookie(dstatep->dip, "pshot_bus_test_post",
		    &cookie) == NDI_SUCCESS) {
			(void) ndi_post_event(dstatep->dip, dstatep->dip,
			    cookie, NULL);
		}

		break;

	case DEVCTL_PM_PWR_HAS_CHANGED_ON_RESUME:
		/*
		 * Issue pm_power_has_changed() call on DDI_RESUME
		 */
		mutex_enter(&dstatep->lock);
		dstatep->flag |= PWR_HAS_CHANGED_ON_RESUME_FLAG;
		mutex_exit(&dstatep->lock);
		GEN_DEBUG((CE_CONT, "%s%d:"
		    " DEVCTL_PM_PWR_HAS_CHANGED_ON_RESUME", nodename,
		    instance));

		break;

	case DEVCTL_PM_FAIL_SUSPEND:
		/*
		 * Fail the suspend attempt in DDI_SUSPEND
		 */
		mutex_enter(&dstatep->lock);
		dstatep->flag |= FAIL_SUSPEND_FLAG;
		mutex_exit(&dstatep->lock);
		GEN_DEBUG((CE_CONT, "%s%d: DEVCTL_PM_FAIL_SUSPEND",
		    nodename, instance));

		break;

	case DEVCTL_PM_PUP_WITH_PWR_HAS_CHANGED:
		/*
		 * Use pm_power_has_changed() to power up comp 0 when
		 * enforcing the comp 0 vs comp-not 0 dependency:
		 * Power up comp 0 first, if request for comp-not-0
		 * comes in.
		 * Else, default to pm_raise_power().
		 */
		mutex_enter(&dstatep->lock);
		dstatep->flag |= PUP_WITH_PWR_HAS_CHANGED_FLAG;
		mutex_exit(&dstatep->lock);
		GEN_DEBUG((CE_CONT, "%s%d: DEVCTL_PM_PUP_WITH_PWR_HAS_CHANGED",
		    nodename, instance));

		break;

	case DEVCTL_PM_BUSY_COMP:
		/*
		 * mark component 0 busy via a pm_busy_component() call.
		 * update the busy[] array.
		 */
		mutex_enter(&dstatep->lock);
		++dstatep->busy[0];
		GEN_DEBUG((CE_CONT, "%s%d: DEVCTL_PM_BUSY_COMP: comp 0:"
		    " busy=%d", nodename, instance, dstatep->busy[0]));
		mutex_exit(&dstatep->lock);
		ret = pm_busy_component(dstatep->dip, 0);
		ASSERT(ret == DDI_SUCCESS);

		break;

	case DEVCTL_PM_BUSY_COMP_TEST:
		/*
		 * test busy state on component 0
		 */
		mutex_enter(&dstatep->lock);
		state = dstatep->busy[0];
		if (copyout(&state, dcp->cpyout_buf,
		    sizeof (uint_t)) != 0) {
			cmn_err(CE_WARN, "%s%d:"
			    " DEVCTL_PM_BUSY_COMP_TEST: copyout failed\n",
			    nodename, instance);
			rval = EINVAL;
		}
		GEN_DEBUG((CE_CONT, "%s%d: DEVCTL_PM_BUSY_COMP_TEST:"
		    " comp 0 busy %d",
		    nodename, instance, state));
		mutex_exit(&dstatep->lock);

		break;

	case DEVCTL_PM_IDLE_COMP:
		/*
		 * mark component 0 idle via a pm_idle_component() call.
		 * NOP if dstatep->busy[0] == 0.
		 */
		mutex_enter(&dstatep->lock);
		if (dstatep->busy[0] > 0) {
			--dstatep->busy[0];
			GEN_DEBUG((CE_CONT, "%s%d: DEVCTL_PM_IDLE_COMP:"
			    " comp 0: busy=%d", nodename, instance,
			    dstatep->busy[0]));
			mutex_exit(&dstatep->lock);
			ret = pm_idle_component(dstatep->dip, 0);
			ASSERT(ret == DDI_SUCCESS);
		} else {
			mutex_exit(&dstatep->lock);
		}

		break;

	case DEVCTL_PM_PROM_PRINTF:
		(void) prom_printf("%s%d: PROM_PRINTF FROM GEN_DRV\n",
		    nodename, instance);

		break;

	case DEVCTL_PM_RAISE_PWR:
		/*
		 * power up both components to MAXPWR via
		 * pm_raise_power() calls. this ioctl() cmd
		 * assumes that the current level is 0
		 */
		for (i = 0; i < COMPONENTS; i++) {
			GEN_DEBUG((CE_CONT, "%s%d: DEVCTL_PM_RAISE_PWR:"
			    " comp %d old 0 new %d",
			    nodename, instance, i, maxpwr[i]));
			if (pm_raise_power(dstatep->dip, 0, maxpwr[i])
			    != DDI_SUCCESS) {
				rval = EINVAL;
			}
		}

		break;

	case DEVCTL_PM_CHANGE_PWR_LOW:
		/*
		 * power off both components via pm_power_has_changed() calls
		 */
		for (i = (COMPONENTS - 1); i >= 0; --i) {
			GEN_DEBUG((CE_CONT, "%s%d: DEVCTL_PM_CHANGE_PWR_LOW:"
			    " comp %d new 0",
			    nodename, instance, i));
			mutex_enter(&dstatep->lock);
			level_tmp = dstatep->level[i];
			dstatep->level[i] = 0;
			if (pm_power_has_changed(dstatep->dip, i, 0)
			    != DDI_SUCCESS) {
				dstatep->level[i] = level_tmp;
				rval = EINVAL;
			}
			mutex_exit(&dstatep->lock);
		}

		break;

	case DEVCTL_PM_CHANGE_PWR_HIGH:
		/*
		 * power up both components to MAXPWR via
		 * pm_power_has_changed() calls
		 */
		for (i = 0; i < COMPONENTS; i++) {
			GEN_DEBUG((CE_CONT, "%s%d: DEVCTL_PM_CHANGE_PWR_HIGH:"
			    " comp %d new %d",
			    nodename, instance, i, maxpwr[i]));
			mutex_enter(&dstatep->lock);
			level_tmp = dstatep->level[i];
			dstatep->level[i] = maxpwr[i];
			if (pm_power_has_changed(dstatep->dip, i, maxpwr[i])
			    != DDI_SUCCESS) {
				dstatep->level[i] = level_tmp;
				rval = EINVAL;
			}
			mutex_exit(&dstatep->lock);
		}

		break;

	case DEVCTL_PM_POWER:
		/*
		 * test if the gen_drv_power() routine has been called,
		 * then clear
		 */
		mutex_enter(&dstatep->lock);
		state = (dstatep->flag & POWER_FLAG) ? 1 : 0;
		if (copyout(&state, dcp->cpyout_buf,
		    sizeof (uint_t)) != 0) {
			cmn_err(CE_WARN, "%s%d: DEVCTL_PM_POWER:"
			    " copyout failed\n", nodename, instance);
			rval = EINVAL;
		}
		GEN_DEBUG((CE_CONT, "%s%d: %s POWER_FLAG: %d",
		    nodename, instance, "DEVCTL_PM_POWER", state));
		dstatep->flag &= ~POWER_FLAG;
		mutex_exit(&dstatep->lock);
		break;

	case DEVCTL_PM_NO_LOWER_POWER:
		/*
		 * issue to not invoke pm_lower_power() on detach
		 */
		mutex_enter(&dstatep->lock);
		dstatep->flag &= ~LOWER_POWER_FLAG;
		mutex_exit(&dstatep->lock);
		GEN_DEBUG((CE_CONT, "%s%d: DEVCTL_PM_NO_LOWER_POWER",
		    nodename, instance));
		break;

	default:
		return (ENOTTY);
	}

	return (rval);
}

/*ARGSUSED*/
static int
gen_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	return (0);
}

/*ARGSUSED*/
static int
gen_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	return (0);
}

/*ARGSUSED0*/
static int
gen_power(dev_info_t *dip, int cmpt, int level)
{
	struct dstate *dstatep;
	int instance = ddi_get_instance(dip);
	char *nodename = ddi_node_name(dip);
	int level_tmp;

	GEN_DEBUG((CE_CONT, "%s%d: power: cmpt %d to level %d",
	    nodename, instance, cmpt, level));

	dstatep = ddi_get_soft_state(dstates, instance);
	if (dstatep == NULL) {

		return (DDI_FAILURE);
	}

	/*
	 * Keep track of the power levels for both components
	 * in the dstatep->comp[] array.
	 * Set comp 0 to full level if non-zero comps
	 * are being set to a higher, non-zero level.
	 */
	if (cmpt == 0) {
		mutex_enter(&dstatep->lock);
		dstatep->level[cmpt] = level;
		mutex_exit(&dstatep->lock);
	} else if (level > dstatep->level[cmpt] && level != 0 &&
	    dstatep->level[0] != COMP_0_MAXPWR) {
		/*
		 * If component 0 is not at COMP_0_MAXPWR, and component 1
		 * is being powered ON, invoke pm_raise_power() or
		 * pm_power_has_changed() based on the
		 * PUP_WITH_PWR_HAS_CHANGED_FLAG flag.
		 * PUP_WITH_PWR_HAS_CHANGED_FLAG = FALSE by default, invoking
		 * pm_raise_power().
		 */
		if (!(dstatep->flag & PUP_WITH_PWR_HAS_CHANGED_FLAG)) {
			/*
			 * first set comp 0 to level COMP_0_MAXPWR
			 */
			GEN_DEBUG((CE_CONT, "%s%d: power:  "
			    "pm_raise_power: comp 0 to level %d",
			    nodename, instance, COMP_0_MAXPWR));
			if (pm_raise_power(dip, 0, COMP_0_MAXPWR) !=
			    DDI_SUCCESS) {
				cmn_err(CE_WARN,
				    "%s%d: power: pm_raise_power() "
				    "failed: comp 0 to level %d\n",
				    nodename, instance, COMP_0_MAXPWR);

				return (DDI_FAILURE);

			} else {
				mutex_enter(&dstatep->lock);
				dstatep->level[0] = COMP_0_MAXPWR;
				/*
				 * now set the level on the non-zero comp
				 */
				dstatep->level[cmpt] = level;
				mutex_exit(&dstatep->lock);
				GEN_DEBUG((CE_CONT, "%s%d: power: "
				    "comp %d to level %d",
				    nodename, instance, cmpt, level));
			}
		} else {
			GEN_DEBUG((CE_CONT, "%s%d: power: "
			    "pm_power_has_changed: comp 0 to level %d",
			    nodename, instance, COMP_0_MAXPWR));
			mutex_enter(&dstatep->lock);
			level_tmp = dstatep->level[0];
			dstatep->level[0] = COMP_0_MAXPWR;
			if (pm_power_has_changed(dip, 0, COMP_0_MAXPWR) !=
			    DDI_SUCCESS) {
				cmn_err(CE_WARN,
				    "%s%d: power: pm_power_has_changed() "
				    "failed: comp 0 to level %d\n",
				    nodename, instance, COMP_0_MAXPWR);
				dstatep->level[0] = level_tmp;
			} else {
				/*
				 * now set the level on the non-zero comp
				 */
				GEN_DEBUG((CE_CONT, "%s%d: power:"
				    " pm_power_has_changed: comp %d"
				    " to level %d", nodename, instance,
				    cmpt, level));
				dstatep->level[cmpt] = level;
			}
			mutex_exit(&dstatep->lock);
		}
	} else {
		mutex_enter(&dstatep->lock);
		dstatep->level[cmpt] = level;
		mutex_exit(&dstatep->lock);
	}

	return (DDI_SUCCESS);
}


/*
 * Create properties of various data types for testing devfs events.
 */
static int
gen_create_properties(dev_info_t *devi)
{
	int int_val = 3023;
	int int_array[] = { 3, 10, 304, 230, 4};
	int64_t int64_val = 20;
	int64_t int64_array[] = { 12, 24, 36, 48};
	char *string_val = "Dev_node_prop";
	char *string_array[] = {"Dev_node_prop:0",
	    "Dev_node_prop:1", "Dev_node_prop:2", "Dev_node_prop:3"};
	uchar_t byte_array[] = { (uchar_t)0xaa, (uchar_t)0x55,
	    (uchar_t)0x12, (uchar_t)0xcd };
	char bytes[] = { (char)0x00, (char)0xef, (char)0xff };

	if (ddi_prop_update_int(DDI_DEV_T_NONE, devi, "int", int_val)
	    != DDI_PROP_SUCCESS)
		return (DDI_FAILURE);

	if (ddi_prop_update_int_array(DDI_DEV_T_NONE, devi, "int-array",
	    int_array, sizeof (int_array) / sizeof (int)) != DDI_PROP_SUCCESS)
		return (DDI_FAILURE);

	if (ddi_prop_update_int64(DDI_DEV_T_NONE, devi, "int64", int64_val)
	    != DDI_PROP_SUCCESS)
		return (DDI_FAILURE);

	if (ddi_prop_update_int64_array(DDI_DEV_T_NONE, devi, "int64-array",
	    int64_array, sizeof (int64_array) / sizeof (int64_t))
	    != DDI_PROP_SUCCESS)
		return (DDI_FAILURE);

	if (ddi_prop_update_string(DDI_DEV_T_NONE, devi, "string", string_val)
	    != DDI_PROP_SUCCESS)
		return (DDI_FAILURE);

	if (ddi_prop_update_string_array(DDI_DEV_T_NONE, devi, "string-array",
	    string_array, sizeof (string_array) / sizeof (char *))
	    != DDI_PROP_SUCCESS)
		return (DDI_FAILURE);

	if (ddi_prop_create(DDI_DEV_T_NONE, devi, DDI_PROP_CANSLEEP,
	    "boolean", NULL, 0) != DDI_PROP_SUCCESS)
		return (DDI_FAILURE);

	if (ddi_prop_update_byte_array(DDI_DEV_T_NONE, devi, "byte-array",
	    byte_array, sizeof (byte_array)) != DDI_PROP_SUCCESS)
		return (DDI_FAILURE);

	/* untyped property */
	if (ddi_prop_create(DDI_DEV_T_NONE, devi, DDI_PROP_CANSLEEP, "untyped",
	    (caddr_t)bytes, sizeof (bytes)) != DDI_PROP_SUCCESS)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

static struct driver_minor_data {
	char	*name;
	minor_t	minor;
	int	type;
} disk_minor_data[] = {
	{"a", 0, S_IFBLK},
	{"b", 1, S_IFBLK},
	{"c", 2, S_IFBLK},
	{"d", 3, S_IFBLK},
	{"e", 4, S_IFBLK},
	{"f", 5, S_IFBLK},
	{"g", 6, S_IFBLK},
	{"h", 7, S_IFBLK},
	{"a,raw", 0, S_IFCHR},
	{"b,raw", 1, S_IFCHR},
	{"c,raw", 2, S_IFCHR},
	{"d,raw", 3, S_IFCHR},
	{"e,raw", 4, S_IFCHR},
	{"f,raw", 5, S_IFCHR},
	{"g,raw", 6, S_IFCHR},
	{"h,raw", 7, S_IFCHR},
	{0}
};


static struct driver_serial_minor_data {
	char	*name;
	minor_t minor;
	int	type;
	char	*node_type;
}  serial_minor_data[] = {
	{"0", 0, S_IFCHR, "ddi_serial"},
	{"1", 1, S_IFCHR, "ddi_serial"},
	{"0,cu", 2, S_IFCHR, "ddi_serial:dialout"},
	{"1,cu", 3, S_IFCHR, "ddi_serial:dialout"},
	{0}
};


static int
gen_create_display(dev_info_t *devi)
{

	int instance = ddi_get_instance(devi);
	char minor_name[15];

	(void) sprintf(minor_name, "cgtwenty%d", instance);

	return (ddi_create_minor_node(devi, minor_name, S_IFCHR,
	    INST_TO_MINOR(instance), DDI_NT_DISPLAY, 0));
}

static int
gen_create_mn_disk_chan(dev_info_t *devi)
{
	struct driver_minor_data *dmdp;
	int instance = ddi_get_instance(devi);

	if (gen_create_properties(devi) != DDI_SUCCESS)
		return (DDI_FAILURE);

	for (dmdp = disk_minor_data; dmdp->name != NULL; dmdp++) {
		if (ddi_create_minor_node(devi, dmdp->name, dmdp->type,
		    (INST_TO_MINOR(instance)) | dmdp->minor,
		    DDI_NT_BLOCK_CHAN, 0) != DDI_SUCCESS) {

			return (DDI_FAILURE);
		}
	}
	return (DDI_SUCCESS);
}

static uint_t
atod(char *s)
{
	uint_t val = 0;
	uint_t digit;

	while (*s) {
		if (*s >= '0' && *s <= '9')
			digit = *s++ - '0';
		else
			break;
		val = (val * 10) + digit;
	}
	return (val);
}


static int
gen_create_mn_disk_wwn(dev_info_t *devi)
{
	struct driver_minor_data *dmdp;
	int instance = ddi_get_instance(devi);
	char *address = ddi_get_name_addr(devi);
	int target, lun;

	if (address[0] >= '0' && address[0] <= '9' &&
	    strchr(address, ',')) {
		target = atod(address);
		address = strchr(address, ',');
		lun = atod(++address);
	} else { /* this hack is for rm_stale_link() testing */
		target = 10;
		lun = 5;
	}

	if (ddi_prop_create(DDI_DEV_T_NONE, devi, DDI_PROP_CANSLEEP,
	    "target", (caddr_t)&target, sizeof (int))
	    != DDI_PROP_SUCCESS) {
		return (DDI_FAILURE);
	}
	if (ddi_prop_create(DDI_DEV_T_NONE, devi, DDI_PROP_CANSLEEP,
	    "lun", (caddr_t)&lun, sizeof (int))
	    != DDI_PROP_SUCCESS) {
		return (DDI_FAILURE);
	}

	for (dmdp = disk_minor_data; dmdp->name != NULL; dmdp++) {
		if (ddi_create_minor_node(devi, dmdp->name, dmdp->type,
		    (INST_TO_MINOR(instance)) | dmdp->minor,
		    DDI_NT_BLOCK_WWN, 0) != DDI_SUCCESS) {

			return (DDI_FAILURE);
		}
	}
	return (DDI_SUCCESS);
}

static int
gen_create_mn_disk_cdrom(dev_info_t *devi)
{
	struct driver_minor_data *dmdp;
	int instance = ddi_get_instance(devi);

	for (dmdp = disk_minor_data; dmdp->name != NULL; dmdp++) {
		if (ddi_create_minor_node(devi, dmdp->name, dmdp->type,
		    (INST_TO_MINOR(instance)) | dmdp->minor,
		    DDI_NT_CD_CHAN, 0) != DDI_SUCCESS) {

			return (DDI_FAILURE);
		}
	}
	return (DDI_SUCCESS);
}

static int
gen_create_mn_disk_fd(dev_info_t *devi)
{
	struct driver_minor_data *dmdp;
	int instance = ddi_get_instance(devi);

	for (dmdp = disk_minor_data; dmdp->name != NULL; dmdp++) {
		if (ddi_create_minor_node(devi, dmdp->name, dmdp->type,
		    (INST_TO_MINOR(instance)) | dmdp->minor,
		    DDI_NT_BLOCK_CHAN, 0) != DDI_SUCCESS) {

			return (DDI_FAILURE);
		}
	}
	return (DDI_SUCCESS);
}

static int
gen_create_serial(dev_info_t *devi)
{
	struct driver_serial_minor_data *dmdp;
	int instance = ddi_get_instance(devi);

	for (dmdp = serial_minor_data; dmdp->name != NULL; dmdp++) {
		if (ddi_create_minor_node(devi, dmdp->name, dmdp->type,
		    (INST_TO_MINOR(instance)) | dmdp->minor,
		    dmdp->node_type, 0) != DDI_SUCCESS) {

			return (DDI_FAILURE);
		}
	}
	return (DDI_SUCCESS);
}

static int
gen_create_net(dev_info_t *devi)
{
	int instance = ddi_get_instance(devi);
	char minorname[32];

	if (gen_create_properties(devi) != DDI_SUCCESS)
		return (DDI_FAILURE);

	(void) snprintf(minorname, sizeof (minorname), "gen_drv%d", instance);
	return (ddi_create_minor_node(devi, minorname, S_IFCHR,
	    INST_TO_MINOR(instance), DDI_NT_NET, 0));
}

static int
gen_create_minor_nodes(dev_info_t *devi, struct dstate *dstatep)
{
	int rval = DDI_SUCCESS;
	char *node_name;

	node_name = ddi_node_name(devi);

	if (strcmp(node_name, "disk_chan") == 0) {
		rval = gen_create_mn_disk_chan(devi);
	} else if (strcmp(node_name, "disk_wwn") == 0) {
		rval = gen_create_mn_disk_wwn(devi);
	} else if (strcmp(node_name, "disk_cdrom") == 0) {
		rval = gen_create_mn_disk_cdrom(devi);
	} else if (strcmp(node_name, "disk_fd") == 0) {
		rval = gen_create_mn_disk_fd(devi);
	} else if (strcmp(node_name, "cgtwenty") == 0) {
		rval = gen_create_display(devi);
	} else if (strcmp(node_name, "genzs") == 0) {
		rval = gen_create_serial(devi);
	} else if (strcmp(node_name, "net") == 0) {
		rval = gen_create_net(devi);
	} else {
		int instance = ddi_get_instance(devi);
		char *node_type;

		/*
		 * Solaris may directly hang the node_type off the minor node
		 * (without making a copy).  Since we free the node_type
		 * property below we need to make a private copy to pass
		 * to ddi_create_minor_node to avoid devinfo snapshot panics.
		 * We store a pointer to our copy in dstate and free it in
		 * gen_detach after the minor nodes have been deleted by
		 * ddi_remove_minor_node.
		 */
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, devi,
		    DDI_PROP_DONTPASS, "node-type", &node_type) != 0) {
			cmn_err(CE_WARN, "couldn't get node-type\n");
			return (DDI_FAILURE);
		}
		if (node_type) {
			dstatep->node_type = kmem_alloc(
			    strlen(node_type) + 1, KM_SLEEP);
			(void) strcpy(dstatep->node_type, node_type);
		}
		ddi_prop_free(node_type);

		/* the minor name is the same as the node name */
		if (ddi_create_minor_node(devi, node_name, S_IFCHR,
		    (INST_TO_MINOR(instance)), dstatep->node_type, 0) !=
		    DDI_SUCCESS) {
			if (dstatep->node_type) {
				kmem_free(dstatep->node_type,
				    strlen(dstatep->node_type) + 1);
				dstatep->node_type = NULL;
			}
			return (DDI_FAILURE);
		}
		return (DDI_SUCCESS);
	}

	if (rval != DDI_SUCCESS) {
		ddi_prop_remove_all(devi);
		ddi_remove_minor_node(devi, NULL);
	}

	return (rval);
}

/*ARGSUSED*/
static void
gen_event_cb(dev_info_t *dip, ddi_eventcookie_t cookie, void *arg,
    void *impl_data)
{
	if (gen_debug)
		cmn_err(CE_NOTE, "gen_event_cb invoked");

}
