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
 * Copyright (c) 2009,  Intel Corporation.
 * All Rights Reserved.
 */


/*
 * Platform Power Management master pseudo driver -
 *    - attaches only  when ppm.conf file is present, indicating a
 *      workstation (since Excalibur era ) that is designed to
 *      be MOU-3 EPA compliant and which uses platform-specific
 *	hardware to do so;
 *    - this pseudo driver uses a set of simple satellite
 *      device drivers responsible for accessing platform
 *      specific devices to modify the registers they own.
 *	ppm drivers tells these	satellite drivers what to do
 *	according to using command values taken from ppm.conf.
 */
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/open.h>
#include <sys/callb.h>
#include <sys/va_list.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>
#include <sys/ddi_impldefs.h>
#include <sys/promif.h>
#include <sys/epm.h>
#include <sys/sunpm.h>
#include <sys/ppmio.h>
#include <sys/sunldi.h>
#include <sys/ppmvar.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ppm_plat.h>

/*
 * Note: When pm_power() is called (directly or indirectly) to change the
 * power level of a device and the call returns failure, DO NOT assume the
 * level is unchanged.  Doublecheck it against ppmd->level.
 */

/*
 * cb_ops
 */
static int	ppm_open(dev_t *, int, int, cred_t *);
static int	ppm_close(dev_t, int, int, cred_t *);
static int	ppm_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static struct cb_ops ppm_cb_ops = {
	ppm_open,		/* open	*/
	ppm_close,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	ppm_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* streamtab */
	D_MP | D_NEW,		/* driver compatibility flag */
	CB_REV,			/* cb_ops revision */
	nodev,			/* async read */
	nodev			/* async write */
};

/*
 * bus_ops
 */
static int	ppm_ctlops(dev_info_t *, dev_info_t *, ddi_ctl_enum_t, void *,
    void *);

static struct bus_ops ppm_bus_ops = {
	BUSO_REV,		/* busops_rev		*/
	0,			/* bus_map		*/
	0,			/* bus_get_intrspec	*/
	0,			/* bus_add_intrspec	*/
	0,			/* bus_remove_intrspec	*/
	0,			/* bus_map_fault	*/
	ddi_no_dma_map,		/* bus_dma_map		*/
	ddi_no_dma_allochdl,	/* bus_dma_allochdl	*/
	NULL,			/* bus_dma_freehdl	*/
	NULL,			/* bus_dma_bindhdl	*/
	NULL,			/* bus_dma_unbindhdl	*/
	NULL,			/* bus_dma_flush	*/
	NULL,			/* bus_dma_win		*/
	NULL,			/* bus_dma_ctl		*/
	ppm_ctlops,		/* bus_ctl		*/
	0,			/* bus_prop_op		*/
	0,			/* bus_get_eventcookie	*/
	0,			/* bus_add_eventcall	*/
	0,			/* bus_remove_eventcall	*/
	0,			/* bus_post_event	*/
	0			/* bus_intr_ctl		*/
};

/*
 * dev_ops
 */
static int	ppm_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int	ppm_attach(dev_info_t *, ddi_attach_cmd_t);
static int	ppm_detach(dev_info_t *, ddi_detach_cmd_t);

static struct dev_ops ppm_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	ppm_getinfo,		/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	ppm_attach,		/* attach */
	ppm_detach,		/* detach */
	nodev,			/* reset */
	&ppm_cb_ops,		/* cb_ops */
	&ppm_bus_ops,		/* bus_ops */
	nulldev,		/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,
	"platform pm driver",
	&ppm_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/*
 * Global data structure and variables
 */
int	ppm_inst = -1;
void	*ppm_statep;
ppm_domain_t *ppm_domain_p;
callb_id_t   *ppm_cprcb_id;
static kmutex_t ppm_cpr_window_lock;	/* guard ppm_cpr_window_flag */
static	boolean_t ppm_cpr_window_flag;	/* set indicating chpt-resume period */

/* LED actions */
#define	PPM_LED_SOLIDON		0
#define	PPM_LED_BLINKING	1

/*
 * Debug
 */
#ifdef	DEBUG
uint_t	ppm_debug = 0;
#endif

/*
 * Local function prototypes and data
 */
static boolean_t	ppm_cpr_callb(void *, int);
static int		ppm_fetset(ppm_domain_t *, uint8_t);
static int		ppm_fetget(ppm_domain_t *, uint8_t *);
static int		ppm_gpioset(ppm_domain_t *, int);
static int		ppm_manage_cpus(dev_info_t *, power_req_t *, int *);
static int		ppm_manage_pci(dev_info_t *, power_req_t *, int *);
static int		ppm_manage_pcie(dev_info_t *, power_req_t *, int *);
static int		ppm_manage_fet(dev_info_t *, power_req_t *, int *);
static void		ppm_manage_led(int);
static void		ppm_set_led(ppm_domain_t *, int);
static void		ppm_blink_led(void *);
static void		ppm_svc_resume_ctlop(dev_info_t *, power_req_t *);
static int		ppm_set_level(ppm_dev_t *, int, int, boolean_t);
static int		ppm_change_power_level(ppm_dev_t *, int, int);
static int		ppm_record_level_change(ppm_dev_t *, int, int);
static int		ppm_switch_clock(ppm_domain_t *, int);
static int		ppm_pcie_pwr(ppm_domain_t *, int);
static int		ppm_power_up_domain(dev_info_t *dip);
static int		ppm_power_down_domain(dev_info_t *dip);

int
_init(void)
{
	if (ddi_soft_state_init(
	    &ppm_statep, sizeof (ppm_unit_t), 1) != DDI_SUCCESS) {
		PPMD(D_INIT, ("ppm: soft state init\n"))
		return (DDI_FAILURE);
	}

	if (mod_install(&modlinkage) != DDI_SUCCESS) {
		ddi_soft_state_fini(&ppm_statep);
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}


int
_fini(void)
{
	int error;

	if ((error = mod_remove(&modlinkage)) == DDI_SUCCESS)
		ddi_soft_state_fini(&ppm_statep);

	return (error);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/* ARGSUSED */
int
ppm_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	struct ppm_unit *unitp;
	dev_t	dev;
	int	instance;
	int	rval;

	if (ppm_inst == -1)
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (unitp = ddi_get_soft_state(ppm_statep, (dev_t)arg)) {
			*resultp = unitp->dip;
			rval = DDI_SUCCESS;
		} else
			rval = DDI_FAILURE;

		return (rval);

	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		instance = getminor(dev);
		*resultp = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}


/*
 * attach(9E)
 */
static int
ppm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ppm_unit_t *unitp;
	int ret;
#ifdef	DEBUG
	char *str = "ppm_attach";
#endif


	switch (cmd) {
	case DDI_ATTACH:
		PPMD(D_ATTACH, ("%s: attaching ...\n", str))
		break;

	case DDI_RESUME:
		PPMD(D_ATTACH, ("%s: Resuming ...\n", str))
		unitp = ddi_get_soft_state(ppm_statep, ppm_inst);
		mutex_enter(&unitp->lock);
		unitp->states &= ~PPM_STATE_SUSPENDED;
		mutex_exit(&unitp->lock);
		return (DDI_SUCCESS);

	default:
		cmn_err(CE_WARN, "ppm_attach: unknown command %d, dip(0x%p)",
		    cmd, (void *)dip);
		return (DDI_FAILURE);
	}

	if (ppm_inst != -1) {
		PPMD(D_ATTACH, ("%s: Already attached !", str))
		return (DDI_FAILURE);
	}

	ppm_inst = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(ppm_statep, ppm_inst) != DDI_SUCCESS) {
		PPMD(D_ATTACH, ("%s: soft states alloc error!\n", str))
		return (DDI_FAILURE);
	}
	unitp = ddi_get_soft_state(ppm_statep, ppm_inst);

	ret = ddi_create_minor_node(dip, "ppm", S_IFCHR, ppm_inst,
	    "ddi_ppm", 0);
	if (ret != DDI_SUCCESS) {
		PPMD(D_ATTACH, ("%s: can't create minor node!\n", str))
		goto fail1;
	}

	unitp->dip = dip;
	mutex_init(&unitp->lock, NULL, MUTEX_DRIVER, NULL);

	/*
	 * read ppm.conf, construct ppm_domain data structure and
	 * their sub data structure.
	 */
	if ((ret = ppm_create_db(dip)) != DDI_SUCCESS)
		goto fail2;

	/*
	 * walk down ppm domain control from each domain, initialize
	 * domain control orthogonal function call handle
	 */
	ppm_init_cb(dip);

	if ((ret = pm_register_ppm(ppm_claim_dev, dip)) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "ppm_attach: can't register ppm handler!");
		goto fail2;
	}

	mutex_init(&ppm_cpr_window_lock, NULL, MUTEX_DRIVER, NULL);
	ppm_cpr_window_flag = B_FALSE;
	ppm_cprcb_id = callb_add(ppm_cpr_callb, (void *)NULL,
	    CB_CL_CPR_PM, "ppm_cpr");

#if defined(__x86)
	/*
	 * Register callback so that once CPUs have been added to
	 * the device tree, ppm CPU domains can be allocated using ACPI
	 * data.
	 */
	cpupm_ppm_alloc_pstate_domains = ppm_alloc_pstate_domains;
	cpupm_ppm_free_pstate_domains = ppm_free_pstate_domains;

	/*
	 * Register callback so that whenever max speed throttle requests
	 * are received, ppm can redefine the high power level for
	 * all CPUs in the domain.
	 */
	cpupm_redefine_topspeed = ppm_redefine_topspeed;
#endif

	ddi_report_dev(dip);
	return (DDI_SUCCESS);

fail2:
	ddi_remove_minor_node(dip, "ddi_ppm");
	mutex_destroy(&unitp->lock);
fail1:
	ddi_soft_state_free(ppm_statep, ppm_inst);
	ppm_inst = -1;
	return (DDI_FAILURE);
}


/* ARGSUSED */
static int
ppm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	ppm_unit_t *unitp;
#ifdef	DEBUG
	char *str = "ppm_detach";
#endif

	switch (cmd) {
	case DDI_DETACH:
		PPMD(D_DETACH, ("%s: detach not allowed.\n", str))
		return (DDI_FAILURE);

	case DDI_SUSPEND:
		PPMD(D_DETACH, ("%s: suspending ...\n", str))
		unitp = ddi_get_soft_state(ppm_statep, ppm_inst);
		mutex_enter(&unitp->lock);
		unitp->states |= PPM_STATE_SUSPENDED;
		mutex_exit(&unitp->lock);

		/*
		 * Suspend requires that timeout callouts to be canceled.
		 * Turning off the LED blinking will cancel the timeout.
		 */
		ppm_manage_led(PPM_LED_SOLIDON);
		return (DDI_SUCCESS);

	default:
		cmn_err(CE_WARN, "ppm_detach: unsupported command %d, dip(%p)",
		    cmd, (void *)dip);
		return (DDI_FAILURE);
	}
}


/* ARGSUSED */
int
ppm_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	if (otyp != OTYP_CHR)
		return (EINVAL);
	PPMD(D_OPEN, ("ppm_open: devp 0x%p, flag 0x%x, otyp %d\n",
	    (void *)devp, flag, otyp))
	return (0);
}


/* ARGSUSED */
int
ppm_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	PPMD(D_CLOSE, ("ppm_close: dev 0x%lx, flag 0x%x, otyp %d\n",
	    dev, flag, otyp))
	return (0);
}


/* ARGSUSED */
int
ppm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred_p,
    int *rval_p)
{
#ifdef DEBUG
	char *str = "ppm_ioctl";
#endif
	ppm_domain_t *domp = NULL;
	uint8_t level, lvl;
	int ret = 0;

	PPMD(D_IOCTL, ("%s: dev 0x%lx, cmd 0x%x, mode 0x%x\n",
	    str, dev, cmd, mode))

	switch (cmd) {
	case PPMGET_DPWR:
	{
		STRUCT_DECL(ppm_dpwr, dpwr);
		struct ppm_unit *unitp;
		char *domain;

		STRUCT_INIT(dpwr, mode);
		ret = ddi_copyin((caddr_t)arg, STRUCT_BUF(dpwr),
		    STRUCT_SIZE(dpwr), mode);
		if (ret != 0)
			return (EFAULT);

		/* copyin domain name */
		domain = kmem_zalloc(MAXNAMELEN, KM_SLEEP);
		ret = copyinstr(
		    STRUCT_FGETP(dpwr, domain), domain, MAXNAMELEN, NULL);
		if (ret != 0) {
			PPMD(D_IOCTL, ("%s: can't copyin domain, line(%d)\n",
			    str, __LINE__))
			ret = EFAULT;
			goto err_dpwr;
		}

		/* locate domain */
		if ((domp = ppm_lookup_domain(domain)) == NULL) {
			PPMD(D_IOCTL, ("%s: no such domain %s\n", str, domain))
			ret = ENODEV;
			goto err_dpwr;
		}

		switch (domp->model) {
		case PPMD_FET:	/* report power fet ON or OFF */
			if ((ret = ppm_fetget(domp, &lvl)) != 0) {
				ret = EIO;
				goto err_dpwr;
			}
			level = (lvl == PPMD_ON) ?
			    PPMIO_POWER_ON : PPMIO_POWER_OFF;
			break;

		case PPMD_PCI:	/* report pci slot clock ON or OFF */
		case PPMD_PCI_PROP:
		case PPMD_PCIE:
			level = (domp->status == PPMD_ON) ?
			    PPMIO_POWER_ON : PPMIO_POWER_OFF;
			break;

		case PPMD_LED:	/* report LED blinking or solid on */

			unitp = ddi_get_soft_state(ppm_statep, ppm_inst);
			if (unitp->led_tid == 0)
				level = PPMIO_LED_SOLIDON;
			else
				level = PPMIO_LED_BLINKING;
			break;

		case PPMD_CPU:	/* report cpu speed divisor */
			level = domp->devlist->level;
			break;

		default:
			ret = EINVAL;
			goto err_dpwr;
		}

		STRUCT_FSET(dpwr, level, level);
		ret = ddi_copyout(STRUCT_BUF(dpwr), (caddr_t)arg,
		    STRUCT_SIZE(dpwr), mode);
		if (ret != 0) {
			PPMD(D_IOCTL, ("%s: can't copyout, line(%d)\n",
			    str, __LINE__))
			ret = EFAULT;
		}
err_dpwr:
		kmem_free(domain, MAXNAMELEN);

		break;
	}

	case PPMGET_DOMBYDEV:
	{
		STRUCT_DECL(ppm_bydev, bydev);
		char *path = NULL;
		size_t   size, l;

		STRUCT_INIT(bydev, mode);
		ret = ddi_copyin((caddr_t)arg, STRUCT_BUF(bydev),
		    STRUCT_SIZE(bydev), mode);
		if (ret != 0)
			return (EFAULT);

		/* copyin .path */
		path = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
		ret = copyinstr(
		    STRUCT_FGETP(bydev, path), path, MAXPATHLEN, NULL);
		if (ret != 0) {
			PPMD(D_IOCTL, ("%s: can't copyin path, line(%d)\n",
			    str, __LINE__))
			kmem_free(path, MAXPATHLEN);
			return (EFAULT);
		}

		/* so far we have up to one domain for a given device */
		size = STRUCT_FGET(bydev, size);
		domp = ppm_get_domain_by_dev(path);
		kmem_free(path, MAXPATHLEN);
		if (domp != NULL) {
			l = strlen(domp->name) + 1;
			if (l > size) {
				PPMD(D_IOCTL, ("%s: buffer too small\n", str))
				return ((size == 0) ? EINVAL : EFAULT);
			}
		} else	/* no domain found to be associated with given device */
			return (ENODEV);

		ret = copyoutstr(
		    domp->name, STRUCT_FGETP(bydev, domlist), l, &l);
		if (ret != 0) {
			PPMD(D_IOCTL, ("%s: can't copyout domlist, line(%d)"
			    " \n", str, __LINE__))
			return (EFAULT);
		}

		break;
	}


	case PPMGET_DEVBYDOM:
	{
		STRUCT_DECL(ppm_bydom, bydom);
		char *domain = NULL;
		char *devlist = NULL;
		ppm_dev_t *ppmd;
		dev_info_t *odip = NULL;
		char *s, *d;
		size_t  size, l;

		STRUCT_INIT(bydom, mode);
		ret = ddi_copyin((caddr_t)arg, STRUCT_BUF(bydom),
		    STRUCT_SIZE(bydom), mode);
		if (ret != 0)
			return (EFAULT);

		/* copyin .domain */
		domain = kmem_zalloc(MAXNAMELEN, KM_SLEEP);
		ret = copyinstr(STRUCT_FGETP(bydom, domain), domain,
		    MAXNAMELEN, NULL);
		if (ret != 0) {
			PPMD(D_IOCTL, ("%s: can't copyin domain, line(%d)\n",
			    str, __LINE__))
			ret = EFAULT;
			goto err_bydom;
		}

		/* locate domain */
		if ((domp = ppm_lookup_domain(domain)) == NULL) {
			ret = ENODEV;
			goto err_bydom;
		}

		l = 0;
		if ((size = STRUCT_FGET(bydom, size)) == 0)
			ret = EINVAL;
		else
			if ((d = devlist = kmem_zalloc(size, KM_SLEEP)) == NULL)
				ret = EFAULT;
		if (ret != 0)
			goto err_bydom;

		for (ppmd = domp->devlist; ppmd;
		    odip = ppmd->dip, ppmd = ppmd->next) {

			if (ppmd->dip == odip)
				continue;
			if (ppmd != domp->devlist)
				*d++ = ' ';

			l += strlen(ppmd->path) + 1;
			if (l > size) {
				PPMD(D_IOCTL, ("%s: buffer overflow\n", str))
				ret = EFAULT;
				goto err_bydom;
			}

			for (s = ppmd->path; *s != 0; )
				*d++ = *s++;
		}
		*d = 0;

		if (*devlist == 0)
			goto err_bydom;

		ret = copyoutstr(
		    devlist, STRUCT_FGETP(bydom, devlist), l, &l);
		if (ret != 0) {
			PPMD(D_IOCTL, ("%s: can't copyout devlist, line(%d)"
			    " \n", str, __LINE__))
			ret = EFAULT;
		}

err_bydom:
		if (devlist)
			kmem_free(devlist, size);
		if (domain)
			kmem_free(domain, MAXNAMELEN);

		break;
	}

#if defined(__x86)
	/*
	 * Note that these two ioctls exist for test purposes only.
	 * Unfortunately, there really isn't any other good way of
	 * unit testing the dynamic redefinition of the top speed as it
	 * usually occurs due to environmental conditions.
	 */
	case PPMGET_NORMAL:
	case PPMSET_NORMAL:
	{
		STRUCT_DECL(ppm_norm, norm);
		char *path = NULL;
		struct pm_component *dcomps;
		struct pm_comp *pm_comp;
		ppm_dev_t *ppmd;
		int i;

		STRUCT_INIT(norm, mode);
		ret = ddi_copyin((caddr_t)arg, STRUCT_BUF(norm),
		    STRUCT_SIZE(norm), mode);
		if (ret != 0)
			return (EFAULT);

		/* copyin .path */
		path = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
		ret = copyinstr(
		    STRUCT_FGETP(norm, path), path, MAXPATHLEN, NULL);
		if (ret != 0) {
			PPMD(D_IOCTL, ("%s: can't copyin path, line(%d)\n",
			    str, __LINE__))
			kmem_free(path, MAXPATHLEN);
			return (EFAULT);
		}

		domp = ppm_get_domain_by_dev(path);
		kmem_free(path, MAXPATHLEN);

		if (domp == NULL)
			return (ENODEV);

		ppmd = domp->devlist;
		if (cmd == PPMSET_NORMAL) {
			if (domp->model != PPMD_CPU)
				return (EINVAL);
			level = STRUCT_FGET(norm, norm);
			dcomps = DEVI(ppmd->dip)->devi_pm_components;
			pm_comp = &dcomps[ppmd->cmpt].pmc_comp;
			for (i = pm_comp->pmc_numlevels; i > 0; i--) {
				if (pm_comp->pmc_lvals[i-1] == level)
					break;
			}
			if (i == 0)
				return (EINVAL);

			ppm_set_topspeed(ppmd, pm_comp->pmc_numlevels - i);
		}

		level = pm_get_normal_power(ppmd->dip, 0);

		STRUCT_FSET(norm, norm, level);
		ret = ddi_copyout(STRUCT_BUF(norm), (caddr_t)arg,
		    STRUCT_SIZE(norm), mode);
		if (ret != 0) {
			PPMD(D_IOCTL, ("%s: can't copyout, line(%d)\n",
			    str, __LINE__))
			ret = EFAULT;
		}
		break;
	}
#endif
	default:
		PPMD(D_IOCTL, ("%s: unsupported ioctl command(%d)\n", str, cmd))
		return (EINVAL);
	}

	return (ret);
}


static int	ppm_manage_sx(s3a_t *, int);
static int	ppm_search_list(pm_searchargs_t *);

/*
 * interface between pm framework and ppm driver
 */
/* ARGSUSED */
static int
ppm_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t ctlop, void *arg, void *result)
{
	power_req_t	*reqp = (power_req_t *)arg;
	ppm_unit_t	*unitp;
	ppm_domain_t	*domp;
	ppm_dev_t	*ppmd;
	char		path[MAXNAMELEN];
	ppm_owned_t	*owned;
	int		mode;
	int		ret = DDI_SUCCESS;
	int		*res = (int *)result;
	s3a_t s3args;

	domp = NULL;
#ifdef DEBUG
	char	*str = "ppm_ctlops";
	int	mask = ppm_debug & (D_CTLOPS1 | D_CTLOPS2);
	char *ctlstr = ppm_get_ctlstr(reqp->request_type, mask);
	if (mask && ctlstr)
		PPMD(mask, ("%s: %s, %s\n",
		    str, ddi_binding_name(rdip), ctlstr))
#endif

	if (ctlop != DDI_CTLOPS_POWER) {
		return (DDI_FAILURE);
	}

	unitp = (ppm_unit_t *)ddi_get_soft_state(ppm_statep, ppm_inst);

	switch (reqp->request_type) {

	/* attempt to blink led if indeed all at lowest */
	case PMR_PPM_ALL_LOWEST:
		mode = (reqp->req.ppm_all_lowest_req.mode == PM_ALL_LOWEST);
		if (!(unitp->states & PPM_STATE_SUSPENDED) && mode)
			ppm_manage_led(PPM_LED_BLINKING);
		else
			ppm_manage_led(PPM_LED_SOLIDON);
		return (DDI_SUCCESS);

	/* undo the claiming of 'rdip' at attach time */
	case PMR_PPM_POST_DETACH:
		ASSERT(reqp->req.ppm_set_power_req.who == rdip);
		mutex_enter(&unitp->lock);
		if (reqp->req.ppm_config_req.result != DDI_SUCCESS ||
		    (PPM_GET_PRIVATE(rdip) == NULL)) {
			mutex_exit(&unitp->lock);
			return (DDI_FAILURE);
		}
		mutex_exit(&unitp->lock);
		ppm_rem_dev(rdip);
		return (DDI_SUCCESS);

	/* chance to adjust pwr_cnt if resume is about to power up rdip */
	case PMR_PPM_PRE_RESUME:
		ppm_svc_resume_ctlop(rdip, reqp);
		return (DDI_SUCCESS);

	/*
	 * synchronizing, so that only the owner of the power lock is
	 * permitted to change device and component's power level.
	 */
	case PMR_PPM_UNLOCK_POWER:
	case PMR_PPM_TRY_LOCK_POWER:
	case PMR_PPM_LOCK_POWER:
		ppmd = PPM_GET_PRIVATE(rdip);
		if (ppmd)
			domp = ppmd->domp;
		else if (reqp->request_type != PMR_PPM_UNLOCK_POWER) {
			domp = ppm_lookup_dev(rdip);
			ASSERT(domp);
			ppmd = ppm_get_dev(rdip, domp);
		}

		if (domp == NULL)
			return (DDI_FAILURE);

		PPMD(D_LOCKS, ("ppm_lock_%s: %s, %s\n",
		    (domp->dflags & PPMD_LOCK_ALL) ? "all" : "one",
		    ppmd->path, ppm_get_ctlstr(reqp->request_type, D_LOCKS)))

		if (domp->dflags & PPMD_LOCK_ALL)
			ppm_lock_all(domp, reqp, result);
		else
			ppm_lock_one(ppmd, reqp, result);
		return (DDI_SUCCESS);

	case PMR_PPM_POWER_LOCK_OWNER:
		ASSERT(reqp->req.ppm_power_lock_owner_req.who == rdip);
		ppmd = PPM_GET_PRIVATE(rdip);
		if (ppmd) {
			domp = ppmd->domp;
		} else {
			domp = ppm_lookup_dev(rdip);
			ASSERT(domp);
			ppmd = ppm_get_dev(rdip, domp);
		}

		if (domp == NULL)
			return (DDI_FAILURE);

		/*
		 * In case of LOCK_ALL, effective owner of the power lock
		 * is the owner of the domain lock. otherwise, it is the owner
		 * of the power lock.
		 */
		if (domp->dflags & PPMD_LOCK_ALL)
			reqp->req.ppm_power_lock_owner_req.owner =
			    mutex_owner(&domp->lock);
		else {
			reqp->req.ppm_power_lock_owner_req.owner =
			    DEVI(rdip)->devi_busy_thread;
		}
		return (DDI_SUCCESS);

	case PMR_PPM_INIT_CHILD:
		ASSERT(reqp->req.ppm_lock_power_req.who == rdip);
		if ((domp = ppm_lookup_dev(rdip)) == NULL)
			return (DDI_SUCCESS);

		/*
		 * We keep track of power-manageable devices starting with
		 * initialization process.  The initializing flag remains
		 * set until it is cleared by ppm_add_dev().  Power management
		 * policy for some domains are affected even during device
		 * initialization.  For example, PCI domains should leave
		 * their clock running meanwhile a device in that domain
		 * is initializing.
		 */
		mutex_enter(&domp->lock);
		owned = ppm_add_owned(rdip, domp);
		ASSERT(owned->initializing == 0);
		owned->initializing = 1;

		if (PPMD_IS_PCI(domp->model) && domp->status == PPMD_OFF) {
			ret = ppm_switch_clock(domp, PPMD_ON);
			if (ret == DDI_SUCCESS)
				domp->dflags |= PPMD_INITCHILD_CLKON;
		}
		mutex_exit(&domp->lock);
		return (ret);

	case PMR_PPM_POST_ATTACH:
		ASSERT(reqp->req.ppm_config_req.who == rdip);
		domp = ppm_lookup_dev(rdip);
		ASSERT(domp);
		ASSERT(domp->status == PPMD_ON);
		if (reqp->req.ppm_config_req.result == DDI_SUCCESS) {
			/*
			 * call ppm_get_dev, which will increment the
			 * domain power count by the right number.
			 * Undo the power count increment, done in PRE_PROBE.
			 */
			if (PM_GET_PM_INFO(rdip))
				ppmd = ppm_get_dev(rdip, domp);
			mutex_enter(&domp->lock);
			ASSERT(domp->pwr_cnt > 0);
			domp->pwr_cnt--;
			mutex_exit(&domp->lock);
			return (DDI_SUCCESS);
		}

		ret = ppm_power_down_domain(rdip);
		/* FALLTHROUGH */
	case PMR_PPM_UNINIT_CHILD:
		ASSERT(reqp->req.ppm_lock_power_req.who == rdip);
		if ((domp = ppm_lookup_dev(rdip)) == NULL)
			return (DDI_SUCCESS);

		(void) ddi_pathname(rdip, path);
		mutex_enter(&domp->lock);
		for (owned = domp->owned; owned; owned = owned->next)
			if (strcmp(owned->path, path) == 0)
				break;

		/*
		 * In case we didn't go through a complete attach and detach,
		 * the initializing flag will still be set, so clear it.
		 */
		if ((owned != NULL) && (owned->initializing))
			owned->initializing = 0;

		if (PPMD_IS_PCI(domp->model) &&
		    domp->status == PPMD_ON && domp->pwr_cnt == 0 &&
		    (domp->dflags & PPMD_INITCHILD_CLKON) &&
		    ppm_none_else_holds_power(domp)) {
			ret = ppm_switch_clock(domp, PPMD_OFF);
			if (ret == DDI_SUCCESS)
				domp->dflags &= ~PPMD_INITCHILD_CLKON;
		}
		mutex_exit(&domp->lock);
		return (ret);

	/* place holders */
	case PMR_PPM_UNMANAGE:
	case PMR_PPM_PRE_DETACH:
		return (DDI_SUCCESS);

	case PMR_PPM_PRE_PROBE:
		ASSERT(reqp->req.ppm_config_req.who == rdip);
		return (ppm_power_up_domain(rdip));

	case PMR_PPM_POST_PROBE:
		ASSERT(reqp->req.ppm_config_req.who == rdip);
		if (reqp->req.ppm_config_req.result == DDI_PROBE_SUCCESS ||
		    reqp->req.ppm_config_req.result == DDI_PROBE_DONTCARE)
			return (DDI_SUCCESS);

		/* Probe failed */
		PPMD(D_CTLOPS1 | D_CTLOPS2, ("%s: probe failed for %s@%s "
		    "rv %d\n", str, PM_NAME(rdip), PM_ADDR(rdip),
		    reqp->req.ppm_config_req.result))
		return (ppm_power_down_domain(rdip));

	case PMR_PPM_PRE_ATTACH:
		ASSERT(reqp->req.ppm_config_req.who == rdip);
		/* Domain has already been powered up in PRE_PROBE */
		domp = ppm_lookup_dev(rdip);
		ASSERT(domp);
		ASSERT(domp->status == PPMD_ON);
		return (DDI_SUCCESS);

	/* ppm intercepts power change process to the claimed devices */
	case PMR_PPM_SET_POWER:
	case PMR_PPM_POWER_CHANGE_NOTIFY:
		if ((ppmd = PPM_GET_PRIVATE(rdip)) == NULL) {
			domp = ppm_lookup_dev(rdip);
			ASSERT(domp);
			ppmd = ppm_get_dev(rdip, domp);
		}
		switch (ppmd->domp->model) {
		case PPMD_CPU:
			return (ppm_manage_cpus(rdip, reqp, result));
		case PPMD_FET:
			return (ppm_manage_fet(rdip, reqp, result));
		case PPMD_PCI:
		case PPMD_PCI_PROP:
			return (ppm_manage_pci(rdip, reqp, result));
		case PPMD_PCIE:
			return (ppm_manage_pcie(rdip, reqp, result));
		default:
			cmn_err(CE_WARN, "ppm_ctlops: domain model %d does"
			    " not support PMR_PPM_SET_POWER ctlop",
			    ppmd->domp->model);
			return (DDI_FAILURE);
		}

	case PMR_PPM_ENTER_SX:
	case PMR_PPM_EXIT_SX:
		s3args.s3a_state = reqp->req.ppm_power_enter_sx_req.sx_state;
		s3args.s3a_test_point =
		    reqp->req.ppm_power_enter_sx_req.test_point;
		s3args.s3a_wakephys = reqp->req.ppm_power_enter_sx_req.wakephys;
		s3args.s3a_psr = reqp->req.ppm_power_enter_sx_req.psr;
		ret = ppm_manage_sx(&s3args,
		    reqp->request_type == PMR_PPM_ENTER_SX);
		if (ret) {
			PPMD(D_CPR, ("ppm_manage_sx returns %d\n", ret))
			return (DDI_FAILURE);
		} else {
			return (DDI_SUCCESS);
		}

	case PMR_PPM_SEARCH_LIST:
		ret = ppm_search_list(reqp->req.ppm_search_list_req.searchlist);
		reqp->req.ppm_search_list_req.result = ret;
		*res = ret;
		if (ret) {
			PPMD(D_CPR, ("ppm_search_list returns %d\n", ret))
			return (DDI_FAILURE);
		} else {
			PPMD(D_CPR, ("ppm_search_list returns %d\n", ret))
			return (DDI_SUCCESS);
		}

	default:
		cmn_err(CE_WARN, "ppm_ctlops: unrecognized ctlops req(%d)",
		    reqp->request_type);
		return (DDI_FAILURE);
	}
}


/*
 * Raise the power level of a subrange of cpus.  Used when cpu driver
 * failed an attempt to lower the power of a cpu (probably because
 * it got busy).  Need to revert the ones we already changed.
 *
 * ecpup = the ppm_dev_t for the cpu which failed to lower power
 * level = power level to reset prior cpus to
 */
int
ppm_revert_cpu_power(ppm_dev_t *ecpup, int level)
{
	ppm_dev_t *cpup;
	int ret = DDI_SUCCESS;

	for (cpup = ecpup->domp->devlist; cpup != ecpup; cpup = cpup->next) {
		PPMD(D_CPU, ("ppm_revert_cpu_power: \"%s\", revert to "
		    "level %d\n", cpup->path, level))

		ret = pm_power(cpup->dip, 0, level);
		if (ret == DDI_SUCCESS) {
			cpup->level = level;
			cpup->rplvl = PM_LEVEL_UNKNOWN;
		}
	}
	return (ret);
}


/*
 * ppm_manage_cpus - Process a request to change the power level of a cpu.
 * If not all cpus want to be at the same level, OR if we are currently
 * refusing slowdown requests due to thermal stress, we cache the request.
 * Otherwise, set all cpus to the new power level.
 */
/* ARGSUSED */
static int
ppm_manage_cpus(dev_info_t *dip, power_req_t *reqp, int *result)
{
#ifdef	DEBUG
	char *str = "ppm_manage_cpus";
#endif
	int old, new, ret, kmflag;
	ppm_dev_t *ppmd, *cpup;
	int change_notify = 0;
	pm_ppm_devlist_t *devlist = NULL, *p;
	int		do_rescan = 0;

	*result = DDI_SUCCESS;

	switch (reqp->request_type) {
	case PMR_PPM_SET_POWER:
		break;

	case PMR_PPM_POWER_CHANGE_NOTIFY:
		change_notify = 1;
		break;

	default:
		return (DDI_FAILURE);
	}

	ppmd = PPM_GET_PRIVATE(dip);
	ASSERT(MUTEX_HELD(&ppmd->domp->lock));
	old = reqp->req.ppm_set_power_req.old_level;
	new = reqp->req.ppm_set_power_req.new_level;

	if (change_notify) {
		ppmd->level = new;
		ppmd->rplvl = PM_LEVEL_UNKNOWN;

		PPMD(D_CPU, ("%s: Notify cpu dip %p power level has changed "
		    "from %d to %d", str, (void *)dip, old, new))
		return (DDI_SUCCESS);
	}

	if (ppm_manage_early_cpus(dip, new, result))
		return (*result);

	if (new == ppmd->level) {
		PPMD(D_CPU, ("%s: already at power level %d\n", str, new))
		return (DDI_SUCCESS);
	}

	/*
	 * A request from lower to higher level transition is granted and
	 * made effective on all cpus. A request from higher to lower must
	 * be agreed upon by all cpus.
	 */
	ppmd->rplvl = new;
	for (cpup = ppmd->domp->devlist; cpup; cpup = cpup->next) {
		if (cpup->rplvl == new)
			continue;

		if (new < old) {
			PPMD(D_SOME, ("%s: not all cpus wants to be at new "
			    "level %d yet.\n", str, new))
			return (DDI_SUCCESS);
		}

		/*
		 * If a single cpu requests power up, honor the request
		 * powering up all cpus.
		 */
		if (new > old) {
			PPMD(D_SOME, ("%s: powering up device(%s@%s, %p) "
			    "because of request from dip(%s@%s, %p), "
			    "need pm_rescan\n", str, PM_NAME(cpup->dip),
			    PM_ADDR(cpup->dip), (void *)cpup->dip,
			    PM_NAME(dip), PM_ADDR(dip), (void *)dip))
			do_rescan++;
		}
	}

	PPMD(D_SETLVL, ("%s: \"%s\" set power level old %d, new %d \n",
	    str, ppmd->path, ppmd->level, new))
	ret = ppm_change_cpu_power(ppmd, new);
	*result = ret;

	if (ret == DDI_SUCCESS) {
		if (reqp->req.ppm_set_power_req.canblock == PM_CANBLOCK_BLOCK)
			kmflag = KM_SLEEP;
		else
			kmflag = KM_NOSLEEP;

		for (cpup = ppmd->domp->devlist; cpup; cpup = cpup->next) {
			if (cpup->dip == dip)
				continue;

			if ((p = kmem_zalloc(sizeof (pm_ppm_devlist_t),
			    kmflag)) == NULL) {
				break;
			}
			p->ppd_who = cpup->dip;
			p->ppd_cmpt = cpup->cmpt;
			p->ppd_old_level = old;
			p->ppd_new_level = new;
			p->ppd_next = devlist;

			PPMD(D_SETLVL, ("%s: devlist entry[\"%s\"] %d -> %d\n",
			    str, cpup->path, old, new))

			devlist = p;
		}
		reqp->req.ppm_set_power_req.cookie = (void *) devlist;

		if (do_rescan > 0) {
			for (cpup = ppmd->domp->devlist; cpup;
			    cpup = cpup->next) {
				if (cpup->dip == dip)
					continue;
				pm_rescan(cpup->dip);
			}
		}
	}

	return (ret);
}


/*
 * ppm_svc_resume_ctlop - this is a small bookkeeping ppm does -
 * increments its FET domain power count, in anticipation of that
 * the indicated device(dip) would be powered up by its driver as
 * a result of cpr resuming.
 */
/* ARGSUSED */
static void
ppm_svc_resume_ctlop(dev_info_t *dip, power_req_t *reqp)
{
	ppm_domain_t *domp;
	ppm_dev_t *ppmd;
	int powered;	/* power up count per dip */

	ppmd = PPM_GET_PRIVATE(dip);
	if (ppmd == NULL)
		return;

	/*
	 * Maintain correct powered count for domain which cares
	 */
	powered = 0;
	domp = ppmd->domp;
	mutex_enter(&domp->lock);
	if ((domp->model == PPMD_FET) || PPMD_IS_PCI(domp->model) ||
	    (domp->model == PPMD_PCIE)) {
		for (ppmd = domp->devlist; ppmd; ppmd = ppmd->next) {
			if (ppmd->dip == dip && ppmd->level)
				powered++;
		}

		/*
		 * All fets and clocks are held on during suspend -
		 * resume window regardless their domain devices' power
		 * level.
		 */
		ASSERT(domp->status == PPMD_ON);

		/*
		 * The difference indicates the number of components
		 * being off prior to suspend operation, that is the
		 * amount needs to be compensated in order to sync up
		 * bookkeeping with reality, for PROM reset would have
		 * brought up all devices.
		 */
		if (powered < PM_NUMCMPTS(dip))
			domp->pwr_cnt += PM_NUMCMPTS(dip) - powered;
	}
	for (ppmd = domp->devlist; ppmd; ppmd = ppmd->next) {
		if (ppmd->dip == dip)
			ppmd->level = ppmd->rplvl = PM_LEVEL_UNKNOWN;
	}
	mutex_exit(&domp->lock);
}

#ifdef	DEBUG
static int ppmbringup = 0;
#endif

int
ppm_bringup_domains()
{
#ifdef DEBUG
	char *str = "ppm_bringup_domains";
#endif
	ppm_domain_t	*domp;
	int	ret = DDI_SUCCESS;

	PPMD(D_CPR, ("%s[%d]: enter\n", str, ++ppmbringup))
	for (domp = ppm_domain_p; domp; domp = domp->next) {
		if ((!PPMD_IS_PCI(domp->model) && (domp->model != PPMD_FET) &&
		    (domp->model != PPMD_PCIE)) || (domp->devlist == NULL))
			continue;

		mutex_enter(&domp->lock);
		if (domp->status == PPMD_ON) {
			mutex_exit(&domp->lock);
			continue;
		}
		switch (domp->model) {
		case PPMD_FET:
			ret = ppm_fetset(domp, PPMD_ON);
			break;
		case PPMD_PCI:
		case PPMD_PCI_PROP:
			ret = ppm_switch_clock(domp, PPMD_ON);
			break;
		case PPMD_PCIE:
			ret = ppm_pcie_pwr(domp, PPMD_ON);
			break;
		default:
			break;
		}
		mutex_exit(&domp->lock);
	}
	PPMD(D_CPR, ("%s[%d]: exit\n", str, ppmbringup))

	return (ret);
}

#ifdef	DEBUG
static int ppmsyncbp = 0;
#endif

int
ppm_sync_bookkeeping()
{
#ifdef DEBUG
	char *str = "ppm_sync_bookkeeping";
#endif
	ppm_domain_t	*domp;
	int	ret = DDI_SUCCESS;

	PPMD(D_CPR, ("%s[%d]: enter\n", str, ++ppmsyncbp))
	for (domp = ppm_domain_p; domp; domp = domp->next) {
		if ((!PPMD_IS_PCI(domp->model) && (domp->model != PPMD_FET) &&
		    (domp->model != PPMD_PCIE)) || (domp->devlist == NULL))
			continue;

		mutex_enter(&domp->lock);
		if ((domp->pwr_cnt != 0) || !ppm_none_else_holds_power(domp)) {
			mutex_exit(&domp->lock);
			continue;
		}

		/*
		 * skip NULL .devlist slot, for some may host pci device
		 * that can not tolerate clock off or not even participate
		 * in PM.
		 */
		if (domp->devlist == NULL)
			continue;

		switch (domp->model) {
		case PPMD_FET:
			ret = ppm_fetset(domp, PPMD_OFF);
			break;
		case PPMD_PCI:
		case PPMD_PCI_PROP:
			ret = ppm_switch_clock(domp, PPMD_OFF);
			break;
		case PPMD_PCIE:
			ret = ppm_pcie_pwr(domp, PPMD_OFF);
			break;
		default:
			break;
		}
		mutex_exit(&domp->lock);
	}
	PPMD(D_CPR, ("%s[%d]: exit\n", str, ppmsyncbp))

	return (ret);
}



/*
 * pre-suspend window;
 *
 * power up every FET and PCI clock that are off;
 *
 * set ppm_cpr_window global flag to indicate
 * that even though all pm_scan requested power transitions
 * will be honored as usual but that until we're out
 * of this window,  no FET or clock will be turned off
 * for domains with pwr_cnt decremented down to 0.
 * Such is to avoid accessing the orthogonal drivers that own
 * the FET and clock registers that may not be resumed yet.
 *
 * at post-resume window, walk through each FET and PCI domains,
 * bring pwr_cnt and domp->status to sense: if pwr-cnt == 0,
 * and noinvol check okays, power down the FET or PCI.  At last,
 * clear the global flag ppm_cpr_window.
 *
 * ASSERT case 1, during cpr window, checks pwr_cnt against power
 *	transitions;
 * ASSERT case 2, out of cpr window, checks four things:
 *	pwr_cnt <> power transition in/out of 0
 *	<> status <> record of noinvol device detached
 *
 */
/* ARGSUSED */
static boolean_t
ppm_cpr_callb(void *arg, int code)
{
	int	ret;

	switch (code) {
	case CB_CODE_CPR_CHKPT:

		/* pre-suspend: start of cpr window */
		mutex_enter(&ppm_cpr_window_lock);
		ASSERT(ppm_cpr_window_flag == B_FALSE);
		ppm_cpr_window_flag = B_TRUE;
		mutex_exit(&ppm_cpr_window_lock);

		ret = ppm_bringup_domains();

		break;

	case CB_CODE_CPR_RESUME:

		/* post-resume: end of cpr window */
		ret = ppm_sync_bookkeeping();

		mutex_enter(&ppm_cpr_window_lock);
		ASSERT(ppm_cpr_window_flag == B_TRUE);
		ppm_cpr_window_flag = B_FALSE;
		mutex_exit(&ppm_cpr_window_lock);

		break;
	default:
		ret = DDI_SUCCESS;
		break;
	}

	return (ret == DDI_SUCCESS);
}


/*
 * Initialize our private version of real power level
 * as well as lowest and highest levels the device supports;
 * relate to ppm_add_dev
 */
void
ppm_dev_init(ppm_dev_t *ppmd)
{
	struct pm_component *dcomps;
	struct pm_comp *pm_comp;
	dev_info_t *dip;
	int maxi, i;

	ASSERT(MUTEX_HELD(&ppmd->domp->lock));
	ppmd->level = PM_LEVEL_UNKNOWN;
	ppmd->rplvl = PM_LEVEL_UNKNOWN;

	/* increment pwr_cnt per component */
	if ((ppmd->domp->model == PPMD_FET) ||
	    PPMD_IS_PCI(ppmd->domp->model) ||
	    (ppmd->domp->model == PPMD_PCIE))
		ppmd->domp->pwr_cnt++;

	dip = ppmd->dip;

	/*
	 * ppm exists to handle power-manageable devices which require
	 * special handling on the current platform.  However, a
	 * driver for such a device may choose not to support power
	 * management on a particular load/attach.  In this case we
	 * we create a structure to represent a single-component device
	 * for which "level" = PM_LEVEL_UNKNOWN and "lowest" = 0
	 * are effectively constant.
	 */
	if (PM_GET_PM_INFO(dip)) {
		dcomps = DEVI(dip)->devi_pm_components;
		pm_comp = &dcomps[ppmd->cmpt].pmc_comp;

		ppmd->lowest = pm_comp->pmc_lvals[0];
		ASSERT(ppmd->lowest >= 0);
		maxi = pm_comp->pmc_numlevels - 1;
		ppmd->highest = pm_comp->pmc_lvals[maxi];

		/*
		 * If 66mhz PCI device on pci 66mhz bus supports D2 state
		 * (config reg PMC bit 10 set), ppm could turn off its bus
		 * clock once it is at D3hot.
		 */
		if (ppmd->domp->dflags & PPMD_PCI66MHZ) {
			for (i = 0; i < maxi; i++)
				if (pm_comp->pmc_lvals[i] == PM_LEVEL_D2) {
					ppmd->flags |= PPMDEV_PCI66_D2;
					break;
				}
		}
	}

	/*
	 * If device is in PCI_PROP domain and has exported the
	 * property listed in ppm.conf, its clock will be turned
	 * off when all pm'able devices in that domain are at D3.
	 */
	if ((ppmd->domp->model == PPMD_PCI_PROP) &&
	    (ppmd->domp->propname != NULL) &&
	    ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    ppmd->domp->propname))
		ppmd->flags |= PPMDEV_PCI_PROP_CLKPM;
}


/*
 * relate to ppm_rem_dev
 */
void
ppm_dev_fini(ppm_dev_t *ppmd)
{
	ASSERT(MUTEX_HELD(&ppmd->domp->lock));

	/* decrement pwr_cnt per component */
	if ((ppmd->domp->model == PPMD_FET) ||
	    PPMD_IS_PCI(ppmd->domp->model) ||
	    (ppmd->domp->model == PPMD_PCIE))
		if (ppmd->level != ppmd->lowest)
			ppmd->domp->pwr_cnt--;
}

/*
 * Each power fet controls the power of one or more platform
 * device(s) within their domain.  Hence domain devices' power
 * level change has been monitored, such that once all devices
 * are powered off, the fet is turned off to save more power.
 *
 * To power on any domain device, the domain power fet
 * needs to be turned on first. always one fet per domain.
 */
static int
ppm_manage_fet(dev_info_t *dip, power_req_t *reqp, int *result)
{
#ifdef DEBUG
	char *str = "ppm_manage_fet";
#endif
	int (*pwr_func)(ppm_dev_t *, int, int);
	int		new, old, cmpt;
	ppm_dev_t	*ppmd;
	ppm_domain_t	*domp;
	int		incr = 0;
	int		dummy_ret;


	*result = DDI_SUCCESS;
	switch (reqp->request_type) {
	case PMR_PPM_SET_POWER:
		pwr_func = ppm_change_power_level;
		old = reqp->req.ppm_set_power_req.old_level;
		new = reqp->req.ppm_set_power_req.new_level;
		cmpt = reqp->req.ppm_set_power_req.cmpt;
		break;
	case PMR_PPM_POWER_CHANGE_NOTIFY:
		pwr_func = ppm_record_level_change;
		old = reqp->req.ppm_notify_level_req.old_level;
		new = reqp->req.ppm_notify_level_req.new_level;
		cmpt = reqp->req.ppm_notify_level_req.cmpt;
		break;
	default:
		*result = DDI_FAILURE;
		PPMD(D_FET, ("%s: unknown request type %d for %s@%s\n",
		    str, reqp->request_type, PM_NAME(dip), PM_ADDR(dip)))
		return (DDI_FAILURE);
	}

	for (ppmd = PPM_GET_PRIVATE(dip); ppmd; ppmd = ppmd->next)
		if (cmpt == ppmd->cmpt)
			break;
	if (!ppmd) {
		PPMD(D_FET, ("%s: dip(%p): old(%d)->new(%d): no ppm_dev"
		    " found for cmpt(%d)", str, (void *)dip, old, new, cmpt))
		*result = DDI_FAILURE;
		return (DDI_FAILURE);
	}
	domp = ppmd->domp;
	PPMD(D_FET, ("%s: %s@%s %s old %d, new %d, c%d, level %d, "
	    "status %s\n", str, PM_NAME(dip), PM_ADDR(dip),
	    ppm_get_ctlstr(reqp->request_type, ~0), old, new, cmpt,
	    ppmd->level, (domp->status == PPMD_OFF ? "off" : "on")))


	ASSERT(old == ppmd->level);

	if (new == ppmd->level) {
		PPMD(D_FET, ("nop\n"))
		return (DDI_SUCCESS);
	}

	PPM_LOCK_DOMAIN(domp);

	/*
	 * In general, a device's published lowest power level does not
	 * have to be 0 if power-off is not tolerated. i.e. a device
	 * instance may export its lowest level > 0.  It is reasonable to
	 * assume that level 0 indicates off state, positive level values
	 * indicate power states above off, include full power state.
	 */
	if (new > 0) { /* device powering up or to different positive level */
		if (domp->status == PPMD_OFF) {

			/* can not be in (chpt, resume) window */
			ASSERT(ppm_cpr_window_flag == B_FALSE);

			ASSERT(old == 0 && domp->pwr_cnt == 0);

			PPMD(D_FET, ("About to turn fet on for %s@%s c%d\n",
			    PM_NAME(dip), PM_ADDR(dip), cmpt))

			*result = ppm_fetset(domp, PPMD_ON);
			if (*result != DDI_SUCCESS) {
				PPMD(D_FET, ("\tCan't turn on power FET: "
				    "ret(%d)\n", *result))
				PPM_UNLOCK_DOMAIN(domp);
				return (DDI_FAILURE);
			}
		}

		/*
		 * If powering up, pre-increment the count before
		 * calling pwr_func, because we are going to release
		 * the domain lock and another thread might turn off
		 * domain power otherwise.
		 */
		if (old == 0) {
			domp->pwr_cnt++;
			incr = 1;
		}

		PPMD(D_FET, ("\t%s domain power count: %d\n",
		    domp->name, domp->pwr_cnt))
	}


	PPM_UNLOCK_DOMAIN(domp);

	ASSERT(domp->pwr_cnt > 0);

	if ((*result = (*pwr_func)(ppmd, cmpt, new)) != DDI_SUCCESS) {
		PPMD(D_FET, ("\t%s power change failed: ret(%d)\n",
		    ppmd->path, *result))
	}

	PPM_LOCK_DOMAIN(domp);

	/*
	 * Decr the power count in two cases:
	 *
	 *   1) request was to power device down and was successful
	 *   2) request was to power up (we pre-incremented count), but failed.
	 */
	if ((*result == DDI_SUCCESS && ppmd->level == 0) ||
	    (*result != DDI_SUCCESS && incr)) {
		ASSERT(domp->pwr_cnt > 0);
		domp->pwr_cnt--;
	}

	PPMD(D_FET, ("\t%s domain power count: %d\n",
	    domp->name, domp->pwr_cnt))

	/*
	 * call to pwr_func will update ppm data structures, if it
	 * succeeds. ppm should return whatever is the return value
	 * from call to pwr_func. This way pm and ppm data structures
	 * always in sync. Use dummy_ret from here for any further
	 * return values.
	 */
	if ((domp->pwr_cnt == 0) &&
	    (ppm_cpr_window_flag == B_FALSE) &&
	    ppm_none_else_holds_power(domp)) {

		PPMD(D_FET, ("About to turn FET off for %s@%s c%d\n",
		    PM_NAME(dip), PM_ADDR(dip), cmpt))

		dummy_ret = ppm_fetset(domp, PPMD_OFF);
		if (dummy_ret != DDI_SUCCESS) {
			PPMD(D_FET, ("\tCan't turn off FET: ret(%d)\n",
			    dummy_ret))
		}
	}

	PPM_UNLOCK_DOMAIN(domp);
	ASSERT(domp->pwr_cnt >= 0);
	return (*result);
}


/*
 * the actual code that turn on or off domain power fet and
 * update domain status
 */
static int
ppm_fetset(ppm_domain_t *domp, uint8_t value)
{
	char	*str = "ppm_fetset";
	int	key;
	ppm_dc_t *dc;
	int	ret;
	clock_t	temp;
	clock_t delay = 0;

	key = (value == PPMD_ON) ? PPMDC_FET_ON : PPMDC_FET_OFF;
	for (dc = domp->dc; dc; dc = dc->next)
		if (dc->cmd == key)
			break;
	if (!dc || !dc->lh) {
		PPMD(D_FET, ("%s: %s domain: NULL ppm_dc handle\n",
		    str, domp->name))
		return (DDI_FAILURE);
	}

	if (key == PPMDC_FET_ON) {
		PPM_GET_IO_DELAY(dc, delay);
		if (delay > 0 && domp->last_off_time > 0) {
			/*
			 * provide any delay required before turning on.
			 * some devices e.g. Samsung DVD require minimum
			 * of 1 sec between OFF->ON. no delay is required
			 * for the first time.
			 */
			temp = ddi_get_lbolt();
			temp -= domp->last_off_time;
			temp = drv_hztousec(temp);

			if (temp < delay) {
				/*
				 * busy wait untill we meet the
				 * required delay. Since we maintain
				 * time stamps in terms of clock ticks
				 * we might wait for longer than required
				 */
				PPMD(D_FET, ("%s : waiting %lu micro seconds "
				    "before on\n", domp->name,
				    delay - temp));
				drv_usecwait(delay - temp);
			}
		}
	}
	switch (dc->method) {
#ifdef sun4u
	case PPMDC_I2CKIO: {
		i2c_gpio_t i2c_req;
		i2c_req.reg_mask = dc->m_un.i2c.mask;
		i2c_req.reg_val = dc->m_un.i2c.val;
		ret = ldi_ioctl(dc->lh, dc->m_un.i2c.iowr,
		    (intptr_t)&i2c_req, FWRITE | FKIOCTL, kcred, NULL);
		break;
	}
#endif

	case PPMDC_KIO:
		ret = ldi_ioctl(dc->lh, dc->m_un.kio.iowr,
		    (intptr_t)&(dc->m_un.kio.val), FWRITE | FKIOCTL, kcred,
		    NULL);
		break;

	default:
		PPMD(D_FET, ("\t%s: unsupported domain control method %d\n",
		    str, domp->dc->method))
		return (DDI_FAILURE);
	}

	PPMD(D_FET, ("%s: %s domain(%s) FET from %s to %s\n", str,
	    (ret == 0) ? "turned" : "failed to turn",
	    domp->name,
	    (domp->status == PPMD_ON) ? "ON" : "OFF",
	    (value == PPMD_ON) ? "ON" : "OFF"))

	if (ret == DDI_SUCCESS) {
		domp->status = value;

		if (key == PPMDC_FET_OFF)
			/*
			 * record the time, when it is off. time is recorded
			 * in clock ticks
			 */
			domp->last_off_time = ddi_get_lbolt();

		/* implement any post op delay. */
		if (key == PPMDC_FET_ON) {
			PPM_GET_IO_POST_DELAY(dc, delay);
			PPMD(D_FET, ("%s : waiting %lu micro seconds "
			    "after on\n", domp->name, delay))
			if (delay > 0)
				drv_usecwait(delay);
		}
	}

	return (ret);
}


/*
 * read power fet status
 */
static int
ppm_fetget(ppm_domain_t *domp, uint8_t *lvl)
{
	char	*str = "ppm_fetget";
	ppm_dc_t *dc = domp->dc;
	uint_t	kio_val;
	int	off_val;
	int	ret;

	if (!dc->lh) {
		PPMD(D_FET, ("%s: %s domain NULL ppm_dc layered handle\n",
		    str, domp->name))
		return (DDI_FAILURE);
	}
	if (!dc->next) {
		cmn_err(CE_WARN, "%s: expect both fet on and fet off ops "
		    "defined, found only one in domain(%s)", str, domp->name);
		return (DDI_FAILURE);
	}

	switch (dc->method) {
#ifdef sun4u
	case PPMDC_I2CKIO: {
		i2c_gpio_t i2c_req;
		i2c_req.reg_mask = dc->m_un.i2c.mask;
		ret = ldi_ioctl(dc->lh, dc->m_un.i2c.iord,
		    (intptr_t)&i2c_req, FWRITE | FKIOCTL, kcred, NULL);

		if (ret) {
			PPMD(D_FET, ("%s: PPMDC_I2CKIO failed: ret(%d)\n",
			    str, ret))
			return (ret);
		}

		off_val = (dc->cmd == PPMDC_FET_OFF) ? dc->m_un.i2c.val :
		    dc->next->m_un.i2c.val;
		*lvl = (i2c_req.reg_val == off_val) ? PPMD_OFF : PPMD_ON;

		PPMD(D_FET, ("%s: %s domain FET %s\n", str, domp->name,
		    (i2c_req.reg_val == off_val) ? "OFF" : "ON"))

		break;
	}
#endif

	case PPMDC_KIO:
		ret = ldi_ioctl(dc->lh, dc->m_un.kio.iord,
		    (intptr_t)&kio_val, FWRITE | FKIOCTL, kcred, NULL);
		if (ret) {
			PPMD(D_FET, ("%s: PPMDC_KIO failed: ret(%d)\n",
			    str, ret))
			return (ret);
		}

		off_val = (dc->cmd == PPMDC_FET_OFF) ? dc->m_un.kio.val :
		    dc->next->m_un.kio.val;
		*lvl = (kio_val == off_val) ? PPMD_OFF : PPMD_ON;

		PPMD(D_FET, ("%s: %s domain FET %s\n", str, domp->name,
		    (kio_val == off_val) ? "OFF" : "ON"))

		break;

	default:
		PPMD(D_FET, ("%s: unsupported domain control method %d\n",
		    str, domp->dc->method))
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * the actual code that switches pci clock and update domain status
 */
static int
ppm_switch_clock(ppm_domain_t *domp, int onoff)
{
#ifdef DEBUG
	char *str = "ppm_switch_clock";
#endif
	int	cmd, pio_save;
	ppm_dc_t *dc;
	int ret;
	extern int do_polled_io;
	extern uint_t cfb_inuse;
	ppm_dev_t	*pdev;

	cmd = (onoff == PPMD_ON) ? PPMDC_CLK_ON : PPMDC_CLK_OFF;
	dc = ppm_lookup_dc(domp, cmd);
	if (!dc) {
		PPMD(D_PCI, ("%s: no ppm_dc found for domain (%s)\n",
		    str, domp->name))
		return (DDI_FAILURE);
	}

	switch (dc->method) {
	case PPMDC_KIO:
		/*
		 * If we're powering up cfb on a Stop-A, we only
		 * want to do polled i/o to turn ON the clock
		 */
		pio_save = do_polled_io;
		if ((cfb_inuse) && (cmd == PPMDC_CLK_ON)) {
			for (pdev = domp->devlist; pdev; pdev = pdev->next) {
				if (pm_is_cfb(pdev->dip)) {
					do_polled_io = 1;
					break;
				}
			}
		}

		ret = ldi_ioctl(dc->lh, dc->m_un.kio.iowr,
		    (intptr_t)&(dc->m_un.kio.val), FWRITE | FKIOCTL,
		    kcred, NULL);

		do_polled_io = pio_save;

		if (ret == 0) {
			if (cmd == PPMDC_CLK_ON) {
				domp->status = PPMD_ON;

				/*
				 * PCI PM spec requires 50ms delay
				 */
				drv_usecwait(50000);
			} else
				domp->status = PPMD_OFF;
		}

		PPMD(D_PCI, ("%s: %s pci clock %s for domain (%s)\n", str,
		    (ret == 0) ? "turned" : "failed to turn",
		    (cmd == PPMDC_CLK_OFF) ? "OFF" : "ON",
		    domp->name))

		break;

	default:
		PPMD(D_PCI, ("%s: unsupported domain control method %d\n",
		    str, dc->method))
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}


/*
 * pci slot domain is formed of pci device(s) reside in a pci slot.
 * This function monitors domain device's power level change, such
 * that,
 *   when all domain power count has gone to 0, it attempts to turn off
 *        the pci slot's clock;
 *   if any domain device is powering up, it'll turn on the pci slot's
 *        clock as the first thing.
 */
/* ARGUSED */
static int
ppm_manage_pci(dev_info_t *dip, power_req_t *reqp, int *result)
{
#ifdef DEBUG
	char *str = "ppm_manage_pci";
#endif
	int (*pwr_func)(ppm_dev_t *, int, int);
	int old, new, cmpt;
	ppm_dev_t *ppmd;
	ppm_domain_t *domp;
	int incr = 0;
	int dummy_ret;

	*result = DDI_SUCCESS;
	switch (reqp->request_type) {
	case PMR_PPM_SET_POWER:
		pwr_func = ppm_change_power_level;
		old = reqp->req.ppm_set_power_req.old_level;
		new = reqp->req.ppm_set_power_req.new_level;
		cmpt = reqp->req.ppm_set_power_req.cmpt;
		break;

	case PMR_PPM_POWER_CHANGE_NOTIFY:
		pwr_func = ppm_record_level_change;
		old = reqp->req.ppm_notify_level_req.old_level;
		new = reqp->req.ppm_notify_level_req.new_level;
		cmpt = reqp->req.ppm_notify_level_req.cmpt;
		break;

	default:
		*result = DDI_FAILURE;
		return (DDI_FAILURE);
	}

	for (ppmd = PPM_GET_PRIVATE(dip); ppmd; ppmd = ppmd->next)
		if (cmpt == ppmd->cmpt)
			break;
	if (!ppmd) {
		PPMD(D_PCI, ("%s: dip(%p): old(%d), new(%d): no ppm_dev"
		    " found for cmpt(%d)", str, (void *)dip, old, new, cmpt))
		*result = DDI_FAILURE;
		return (DDI_FAILURE);
	}
	domp = ppmd->domp;
	PPMD(D_PCI, ("%s: %s, dev(%s), c%d, old %d, new %d\n", str,
	    ppm_get_ctlstr(reqp->request_type, ~0),
	    ppmd->path, cmpt, old, new))

	ASSERT(old == ppmd->level);
	if (new == ppmd->level)
		return (DDI_SUCCESS);

	PPM_LOCK_DOMAIN(domp);

	if (new > 0) {		/* device powering up */
		if (domp->status == PPMD_OFF) {

			/* cannot be off during (chpt, resume) window */
			ASSERT(ppm_cpr_window_flag == B_FALSE);

			/* either both OFF or both ON */
			ASSERT(!((old == 0) ^ (domp->pwr_cnt == 0)));

			PPMD(D_PCI, ("About to turn clock on for %s@%s c%d\n",
			    PM_NAME(dip), PM_ADDR(dip), cmpt))

			*result = ppm_switch_clock(domp, PPMD_ON);
			if (*result != DDI_SUCCESS) {
				PPMD(D_PCI, ("\tcan't switch on pci clock: "
				    "ret(%d)\n", *result))
				PPM_UNLOCK_DOMAIN(domp);
				return (DDI_FAILURE);
			}
		}

		if (old == 0) {
			domp->pwr_cnt++;
			incr = 1;
		}

		PPMD(D_PCI, ("\t%s domain power count: %d\n",
		    domp->name, domp->pwr_cnt))
	}

	PPM_UNLOCK_DOMAIN(domp);

	ASSERT(domp->pwr_cnt > 0);

	if ((*result = (*pwr_func)(ppmd, cmpt, new)) != DDI_SUCCESS) {
		PPMD(D_PCI, ("\t%s power change failed: ret(%d)\n",
		    ppmd->path, *result))
	}

	PPM_LOCK_DOMAIN(domp);

	/*
	 * Decr the power count in two cases:
	 *
	 *   1) request was to power device down and was successful
	 *   2) request was to power up (we pre-incremented count), but failed.
	 */
	if ((*result == DDI_SUCCESS && ppmd->level == 0) ||
	    (*result != DDI_SUCCESS && incr)) {
		ASSERT(domp->pwr_cnt > 0);
		domp->pwr_cnt--;
	}

	PPMD(D_PCI, ("\t%s domain power count: %d\n",
	    domp->name, domp->pwr_cnt))

	/*
	 * call to pwr_func will update ppm data structures, if it
	 * succeeds. ppm should return whatever is the return value
	 * from call to pwr_func. This way pm and ppm data structures
	 * always in sync. Use dummy_ret from here for any further
	 * return values.
	 */
	if ((domp->pwr_cnt == 0) &&
	    (ppm_cpr_window_flag == B_FALSE) &&
	    ppm_none_else_holds_power(domp)) {

		PPMD(D_PCI, ("About to turn clock off for %s@%s c%d\n",
		    PM_NAME(dip), PM_ADDR(dip), cmpt))

		dummy_ret = ppm_switch_clock(domp, PPMD_OFF);
		if (dummy_ret != DDI_SUCCESS) {
			PPMD(D_PCI, ("\tCan't switch clock off: "
			    "ret(%d)\n", dummy_ret))
		}
	}

	PPM_UNLOCK_DOMAIN(domp);
	ASSERT(domp->pwr_cnt >= 0);
	return (*result);
}

/*
 * When the driver for the primary PCI-Express child has set the device to
 * lowest power (D3hot), we come here to save even more power by transitioning
 * the slot to D3cold.  Similarly, if the slot is in D3cold and we need to
 * power up the child, we come here first to power up the slot.
 */
/* ARGUSED */
static int
ppm_manage_pcie(dev_info_t *dip, power_req_t *reqp, int *result)
{
#ifdef DEBUG
	char *str = "ppm_manage_pcie";
#endif
	int (*pwr_func)(ppm_dev_t *, int, int);
	int old, new, cmpt;
	ppm_dev_t *ppmd;
	ppm_domain_t *domp;
	int incr = 0;
	int dummy_ret;

	*result = DDI_SUCCESS;
	switch (reqp->request_type) {
	case PMR_PPM_SET_POWER:
		pwr_func = ppm_change_power_level;
		old = reqp->req.ppm_set_power_req.old_level;
		new = reqp->req.ppm_set_power_req.new_level;
		cmpt = reqp->req.ppm_set_power_req.cmpt;
		break;

	case PMR_PPM_POWER_CHANGE_NOTIFY:
		pwr_func = ppm_record_level_change;
		old = reqp->req.ppm_notify_level_req.old_level;
		new = reqp->req.ppm_notify_level_req.new_level;
		cmpt = reqp->req.ppm_notify_level_req.cmpt;
		break;

	default:
		*result = DDI_FAILURE;
		return (DDI_FAILURE);
	}

	for (ppmd = PPM_GET_PRIVATE(dip); ppmd; ppmd = ppmd->next)
		if (cmpt == ppmd->cmpt)
			break;
	if (!ppmd) {
		PPMD(D_PCI, ("%s: dip(%p): old(%d), new(%d): no ppm_dev"
		    " found for cmpt(%d)", str, (void *)dip, old, new, cmpt))
		*result = DDI_FAILURE;
		return (DDI_FAILURE);
	}
	domp = ppmd->domp;
	PPMD(D_PCI, ("%s: %s, dev(%s), c%d, old %d, new %d\n", str,
	    ppm_get_ctlstr(reqp->request_type, ~0),
	    ppmd->path, cmpt, old, new))

	ASSERT(old == ppmd->level);
	if (new == ppmd->level)
		return (DDI_SUCCESS);

	PPM_LOCK_DOMAIN(domp);

	if (new > 0) {		/* device powering up */
		if (domp->status == PPMD_OFF) {

			/* cannot be off during (chpt, resume) window */
			ASSERT(ppm_cpr_window_flag == B_FALSE);

			/* either both OFF or both ON */
			ASSERT(!((old == 0) ^ (domp->pwr_cnt == 0)));

			PPMD(D_PCI, ("About to turn on pcie slot for "
			    "%s@%s c%d\n", PM_NAME(dip), PM_ADDR(dip), cmpt))

			*result = ppm_pcie_pwr(domp, PPMD_ON);
			if (*result != DDI_SUCCESS) {
				PPMD(D_PCI, ("\tcan't switch on pcie slot: "
				    "ret(%d)\n", *result))
				PPM_UNLOCK_DOMAIN(domp);
				return (DDI_FAILURE);
			}
		}

		if (old == 0) {
			domp->pwr_cnt++;
			incr = 1;
		}

		PPMD(D_PCI, ("\t%s domain power count: %d\n",
		    domp->name, domp->pwr_cnt))
	}

	PPM_UNLOCK_DOMAIN(domp);

	ASSERT(domp->pwr_cnt > 0);

	if ((*result = (*pwr_func)(ppmd, cmpt, new)) != DDI_SUCCESS) {
		PPMD(D_PCI, ("\t%s power change failed: ret(%d)\n",
		    ppmd->path, *result))
	}

	PPM_LOCK_DOMAIN(domp);

	/*
	 * Decr the power count in two cases:
	 *
	 *   1) request was to power device down and was successful
	 *   2) request was to power up (we pre-incremented count), but failed.
	 */
	if ((*result == DDI_SUCCESS && ppmd->level == 0) ||
	    (*result != DDI_SUCCESS && incr)) {
		ASSERT(domp->pwr_cnt > 0);
		domp->pwr_cnt--;
	}

	PPMD(D_PCI, ("\t%s domain power count: %d\n",
	    domp->name, domp->pwr_cnt))

	/*
	 * call to pwr_func will update ppm data structures, if it
	 * succeeds. ppm should return whatever is the return value
	 * from call to pwr_func. This way pm and ppm data structures
	 * always in sync. Use dummy_ret from here for any further
	 * return values.
	 */
	if ((domp->pwr_cnt == 0) &&
	    (ppm_cpr_window_flag == B_FALSE) &&
	    ppm_none_else_holds_power(domp)) {

		PPMD(D_PCI, ("About to turn off pcie slot for %s@%s c%d\n",
		    PM_NAME(dip), PM_ADDR(dip), cmpt))

		dummy_ret = ppm_pcie_pwr(domp, PPMD_OFF);
		if (dummy_ret != DDI_SUCCESS) {
			PPMD(D_PCI, ("\tCan't switch pcie slot off: "
			    "ret(%d)\n", dummy_ret))
		}
	}

	PPM_UNLOCK_DOMAIN(domp);
	ASSERT(domp->pwr_cnt >= 0);
	return (*result);

}

/*
 * Set or clear a bit on a GPIO device.  These bits are used for various device-
 * specific purposes.
 */
static int
ppm_gpioset(ppm_domain_t *domp, int key)
{
#ifdef DEBUG
	char	*str = "ppm_gpioset";
#endif
	ppm_dc_t *dc;
	int	ret;
	clock_t delay = 0;

	for (dc = domp->dc; dc; dc = dc->next)
		if (dc->cmd == key)
			break;
	if (!dc || !dc->lh) {
		PPMD(D_GPIO, ("%s: %s domain: NULL ppm_dc handle\n",
		    str, domp->name))
		return (DDI_FAILURE);
	}

	PPM_GET_IO_DELAY(dc, delay);
	if (delay > 0) {
		PPMD(D_GPIO, ("%s : waiting %lu micro seconds "
		    "before change\n", domp->name, delay))
		drv_usecwait(delay);
	}

	switch (dc->method) {
#ifdef sun4u
	case PPMDC_I2CKIO: {
		i2c_gpio_t i2c_req;
		ppm_dev_t *pdev;
		int pio_save;
		extern int do_polled_io;
		extern uint_t cfb_inuse;
		i2c_req.reg_mask = dc->m_un.i2c.mask;
		i2c_req.reg_val = dc->m_un.i2c.val;

		pio_save = do_polled_io;
		if (cfb_inuse) {
			for (pdev = domp->devlist; pdev; pdev = pdev->next) {
				if (pm_is_cfb(pdev->dip)) {
					do_polled_io = 1;
					PPMD(D_GPIO, ("%s: cfb is in use, "
					    "i2c transaction is done in "
					    "poll-mode.\n", str))
					break;
				}
			}
		}
		ret = ldi_ioctl(dc->lh, dc->m_un.i2c.iowr,
		    (intptr_t)&i2c_req, FWRITE | FKIOCTL, kcred, NULL);
		do_polled_io = pio_save;

		PPMD(D_GPIO, ("%s: %s domain(%s) from %s by writing %x "
		    "to gpio\n",
		    str, (ret == 0) ? "turned" : "FAILed to turn",
		    domp->name,
		    (domp->status == PPMD_ON) ? "ON" : "OFF",
		    dc->m_un.i2c.val))

		break;
	}
#endif

	case PPMDC_KIO:
		ret = ldi_ioctl(dc->lh, dc->m_un.kio.iowr,
		    (intptr_t)&(dc->m_un.kio.val), FWRITE | FKIOCTL, kcred,
		    NULL);

		PPMD(D_GPIO, ("%s: %s domain(%s) from %s by writing %x "
		    "to gpio\n",
		    str, (ret == 0) ? "turned" : "FAILed to turn",
		    domp->name,
		    (domp->status == PPMD_ON) ? "ON" : "OFF",
		    dc->m_un.kio.val))

		break;

	default:
		PPMD(D_GPIO, ("\t%s: unsupported domain control method %d\n",
		    str, domp->dc->method))
		return (DDI_FAILURE);
	}

	/* implement any post op delay. */
	PPM_GET_IO_POST_DELAY(dc, delay);
	if (delay > 0) {
		PPMD(D_GPIO, ("%s : waiting %lu micro seconds "
		    "after change\n", domp->name, delay))
		drv_usecwait(delay);
	}

	return (ret);
}

static int
ppm_pcie_pwr(ppm_domain_t *domp, int onoff)
{
#ifdef DEBUG
	char *str = "ppm_pcie_pwr";
#endif
	int ret = DDI_FAILURE;
	ppm_dc_t *dc;
	clock_t delay;

	ASSERT(onoff == PPMD_OFF || onoff == PPMD_ON);

	dc = ppm_lookup_dc(domp,
	    onoff == PPMD_ON ? PPMDC_PRE_PWR_ON : PPMDC_PRE_PWR_OFF);
	if (dc) {

		/*
		 * Invoke layered ioctl for pcie root complex nexus to
		 * transition the link
		 */
		ASSERT(dc->method == PPMDC_KIO);
		delay = dc->m_un.kio.delay;
		if (delay > 0) {
			PPMD(D_GPIO, ("%s : waiting %lu micro seconds "
			    "before change\n", domp->name, delay))
			drv_usecwait(delay);
		}
		ret = ldi_ioctl(dc->lh, dc->m_un.kio.iowr,
		    (intptr_t)&(dc->m_un.kio.val),
		    FWRITE | FKIOCTL, kcred, NULL);
		if (ret == DDI_SUCCESS) {
			delay = dc->m_un.kio.post_delay;
			if (delay > 0) {
				PPMD(D_GPIO, ("%s : waiting %lu micro seconds "
				    "after change\n", domp->name, delay))
				drv_usecwait(delay);
			}
		} else {
			PPMD(D_PCI, ("%s: ldi_ioctl FAILED for domain(%s)\n",
			    str, domp->name))
			return (ret);
		}
	}

	switch (onoff) {
	case PPMD_OFF:
		/* Turn off the clock for this slot. */
		if ((ret = ppm_gpioset(domp, PPMDC_CLK_OFF)) != DDI_SUCCESS) {
			PPMD(D_GPIO,
			    ("%s: failed to turn off domain(%s) clock\n",
			    str, domp->name))
			return (ret);
		}

		/* Turn off the power to this slot */
		if ((ret = ppm_gpioset(domp, PPMDC_PWR_OFF)) != DDI_SUCCESS) {
			PPMD(D_GPIO,
			    ("%s: failed to turn off domain(%s) power\n",
			    str, domp->name))
			return (ret);
		}
		break;
	case PPMD_ON:
		/* Assert RESET for this slot. */
		if ((ret = ppm_gpioset(domp, PPMDC_RESET_ON)) != DDI_SUCCESS) {
			PPMD(D_GPIO,
			    ("%s: failed to assert reset for domain(%s)\n",
			    str, domp->name))
			return (ret);
		}

		/* Turn on the power to this slot */
		if ((ret = ppm_gpioset(domp, PPMDC_PWR_ON)) != DDI_SUCCESS) {
			PPMD(D_GPIO,
			    ("%s: failed to turn on domain(%s) power\n",
			    str, domp->name))
			return (ret);
		}

		/* Turn on the clock for this slot */
		if ((ret = ppm_gpioset(domp, PPMDC_CLK_ON)) != DDI_SUCCESS) {
			PPMD(D_GPIO,
			    ("%s: failed to turn on domain(%s) clock\n",
			    str, domp->name))
			return (ret);
		}

		/* De-assert RESET for this slot. */
		if ((ret = ppm_gpioset(domp, PPMDC_RESET_OFF)) != DDI_SUCCESS) {
			PPMD(D_GPIO,
			    ("%s: failed to de-assert reset for domain(%s)\n",
			    str, domp->name))
			return (ret);
		}

		dc = ppm_lookup_dc(domp, PPMDC_POST_PWR_ON);
		if (dc) {
			/*
			 * Invoke layered ioctl to PCIe root complex nexus
			 * to transition the link.
			 */
			ASSERT(dc->method == PPMDC_KIO);
			delay = dc->m_un.kio.delay;
			if (delay > 0) {
				PPMD(D_GPIO, ("%s: waiting %lu micro seconds "
				    "before change\n", domp->name, delay))
				drv_usecwait(delay);
			}
			ret = ldi_ioctl(dc->lh, dc->m_un.kio.iowr,
			    (intptr_t)&(dc->m_un.kio.val),
			    FWRITE | FKIOCTL, kcred, NULL);

			if (ret != DDI_SUCCESS) {
				PPMD(D_PCI, ("%s: layered ioctl to PCIe"
				    "root complex nexus FAILed\n", str))
				return (ret);
			}

			delay = dc->m_un.kio.post_delay;
			if (delay > 0) {
				PPMD(D_GPIO, ("%s: waiting %lu micro "
				    "seconds after change\n",
				    domp->name, delay))
				drv_usecwait(delay);
			}
		}
		break;
	default:
		ASSERT(0);
	}

	PPMD(D_PCI, ("%s: turned domain(%s) PCIe slot power from %s to %s\n",
	    str, domp->name, (domp->status == PPMD_ON) ? "ON" : "OFF",
	    onoff == PPMD_ON ? "ON" : "OFF"))

	domp->status = onoff;
	return (ret);
}


/*
 * Change the power level for a component of a device.  If the change
 * arg is true, we call the framework to actually change the device's
 * power; otherwise, we just update our own copy of the power level.
 */
static int
ppm_set_level(ppm_dev_t *ppmd, int cmpt, int level, boolean_t change)
{
#ifdef DEBUG
	char *str = "ppm_set_level";
#endif
	int ret;

	ret = DDI_SUCCESS;
	if (change)
		ret = pm_power(ppmd->dip, cmpt, level);

	PPMD(D_SETLVL, ("%s: %s change=%d, old %d, new %d, ret %d\n",
	    str, ppmd->path, change, ppmd->level, level, ret))

	if (ret == DDI_SUCCESS) {
		ppmd->level = level;
		ppmd->rplvl = PM_LEVEL_UNKNOWN;
	}

	return (ret);
}


static int
ppm_change_power_level(ppm_dev_t *ppmd, int cmpt, int level)
{
	return (ppm_set_level(ppmd, cmpt, level, B_TRUE));
}


static int
ppm_record_level_change(ppm_dev_t *ppmd, int cmpt, int level)
{
	return (ppm_set_level(ppmd, cmpt, level, B_FALSE));
}


static void
ppm_manage_led(int action)
{
	ppm_domain_t *domp;
	ppm_unit_t *unitp;
	timeout_id_t	tid;


	PPMD(D_LED, ("ppm_manage_led: action: %s\n",
	    (action == PPM_LED_BLINKING) ? "PPM_LED_BLINKING" :
	    "PPM_LED_SOLIDON"))

	/*
	 * test whether led operation is practically supported,
	 * if not, we waive without pressing for reasons
	 */
	if (!ppm_lookup_dc(NULL, PPMDC_LED_ON))
		return;

	unitp = ddi_get_soft_state(ppm_statep, ppm_inst);
	for (domp = ppm_domain_p; (domp && (domp->model != PPMD_LED)); )
		domp = domp->next;

	mutex_enter(&unitp->lock);
	if (action == PPM_LED_BLINKING) {
		ppm_set_led(domp, PPMD_OFF);
		unitp->led_tid = timeout(
		    ppm_blink_led, domp, PPM_LEDOFF_INTERVAL);

	} else {	/* PPM_LED_SOLIDON */
		ASSERT(action == PPM_LED_SOLIDON);
		tid = unitp->led_tid;
		unitp->led_tid = 0;

		mutex_exit(&unitp->lock);
		(void) untimeout(tid);

		mutex_enter(&unitp->lock);
		ppm_set_led(domp, PPMD_ON);
	}
	mutex_exit(&unitp->lock);
}


static void
ppm_set_led(ppm_domain_t *domp, int val)
{
	int ret;

	ret = ppm_gpioset(domp,
	    (val == PPMD_ON) ? PPMDC_LED_ON : PPMDC_LED_OFF);

	PPMD(D_LED, ("ppm_set_led:  %s LED from %s\n",
	    (ret == 0) ? "turned" : "FAILed to turn",
	    (domp->status == PPMD_ON) ? "ON to OFF" : "OFF to ON"))

	if (ret == DDI_SUCCESS)
		domp->status = val;
}


static void
ppm_blink_led(void *arg)
{
	ppm_unit_t *unitp;
	clock_t intvl;
	ppm_domain_t *domp = arg;

	unitp = ddi_get_soft_state(ppm_statep, ppm_inst);

	mutex_enter(&unitp->lock);
	if (unitp->led_tid == 0) {
		mutex_exit(&unitp->lock);
		return;
	}

	if (domp->status == PPMD_ON) {
		ppm_set_led(domp, PPMD_OFF);
		intvl = PPM_LEDOFF_INTERVAL;
	} else {
		ppm_set_led(domp, PPMD_ON);
		intvl = PPM_LEDON_INTERVAL;
	}

	unitp->led_tid = timeout(ppm_blink_led, domp, intvl);
	mutex_exit(&unitp->lock);
}

/*
 * Function to power up a domain, if required. It also increments the
 * domain pwr_cnt to prevent it from going down.
 */
static int
ppm_power_up_domain(dev_info_t *dip)
{
	int		ret = DDI_SUCCESS;
	ppm_domain_t	*domp;
	char		*str = "ppm_power_up_domain";

	domp = ppm_lookup_dev(dip);
	ASSERT(domp);
	mutex_enter(&domp->lock);
	switch (domp->model) {
	case PPMD_FET:
		if (domp->status == PPMD_OFF) {
			if ((ret = ppm_fetset(domp,  PPMD_ON)) ==
			    DDI_SUCCESS) {
				PPMD(D_FET, ("%s: turned on fet for %s@%s\n",
				    str, PM_NAME(dip), PM_ADDR(dip)))
			} else {
				PPMD(D_FET, ("%s: couldn't turn on fet "
				    "for %s@%s\n", str, PM_NAME(dip),
				    PM_ADDR(dip)))
			}
		}
		break;

	case PPMD_PCI:
	case PPMD_PCI_PROP:
		if (domp->status == PPMD_OFF) {
			if ((ret = ppm_switch_clock(domp, PPMD_ON)) ==
			    DDI_SUCCESS) {
				PPMD(D_PCI, ("%s: turned on clock for "
				    "%s@%s\n", str, PM_NAME(dip),
				    PM_ADDR(dip)))
			} else {
				PPMD(D_PCI, ("%s: couldn't turn on clock "
				    "for %s@%s\n", str, PM_NAME(dip),
				    PM_ADDR(dip)))
			}
		}
		break;

	case PPMD_PCIE:
		if (domp->status == PPMD_OFF) {
			if ((ret = ppm_pcie_pwr(domp, PPMD_ON)) ==
			    DDI_SUCCESS) {
				PPMD(D_PCI, ("%s: turned on link for "
				    "%s@%s\n", str, PM_NAME(dip),
				    PM_ADDR(dip)))
			} else {
				PPMD(D_PCI, ("%s: couldn't turn on link "
				    "for %s@%s\n", str, PM_NAME(dip),
				    PM_ADDR(dip)))
			}
		}
		break;

	default:
		break;
	}
	if (ret == DDI_SUCCESS)
		domp->pwr_cnt++;
	mutex_exit(&domp->lock);
	return (ret);
}

/*
 * Decrements the domain pwr_cnt. if conditions to power down the domain
 * are met, powers down the domain,.
 */
static int
ppm_power_down_domain(dev_info_t *dip)
{
	int		ret = DDI_SUCCESS;
	char		*str = "ppm_power_down_domain";
	ppm_domain_t	*domp;

	domp = ppm_lookup_dev(dip);
	ASSERT(domp);
	mutex_enter(&domp->lock);
	ASSERT(domp->pwr_cnt > 0);
	domp->pwr_cnt--;
	switch (domp->model) {
	case PPMD_FET:
		if ((domp->pwr_cnt == 0) &&
		    (ppm_cpr_window_flag == B_FALSE) &&
		    ppm_none_else_holds_power(domp)) {
			if ((ret = ppm_fetset(domp, PPMD_OFF)) ==
			    DDI_SUCCESS) {
				PPMD(D_FET, ("%s: turned off FET for %s@%s \n",
				    str, PM_NAME(dip), PM_ADDR(dip)))
			} else {
				PPMD(D_FET, ("%s: couldn't turn off FET for "
				    " %s@%s\n", str, PM_NAME(dip),
				    PM_ADDR(dip)))
			}
		}
		break;

	case PPMD_PCI:
	case PPMD_PCI_PROP:
		if ((domp->pwr_cnt == 0) &&
		    (ppm_cpr_window_flag == B_FALSE) &&
		    ppm_none_else_holds_power(domp)) {
			if ((ret = ppm_switch_clock(domp, PPMD_OFF)) ==
			    DDI_SUCCESS) {
				PPMD(D_PCI, ("%s: turned off clock for %s@%s\n",
				    str, PM_NAME(dip), PM_ADDR(dip)))
			} else {
				PPMD(D_PCI, ("%s: couldn't turn off clock "
				    "for %s@%s\n", str, PM_NAME(dip),
				    PM_ADDR(dip)))
			}
		}
		break;

	case PPMD_PCIE:
		if ((domp->pwr_cnt == 0) &&
		    (ppm_cpr_window_flag == B_FALSE) &&
		    ppm_none_else_holds_power(domp)) {
			if ((ret = ppm_pcie_pwr(domp, PPMD_OFF)) ==
			    DDI_SUCCESS) {
				PPMD(D_PCI, ("%s: turned off link for %s@%s\n",
				    str, PM_NAME(dip), PM_ADDR(dip)))
			} else {
				PPMD(D_PCI, ("%s: couldn't turn off link "
				    "for %s@%s\n", str, PM_NAME(dip),
				    PM_ADDR(dip)))
			}
		}
		break;

	default:
		break;
	}
	mutex_exit(&domp->lock);
	return (ret);
}

static int
ppm_manage_sx(s3a_t *s3ap, int enter)
{
	ppm_domain_t *domp = ppm_lookup_domain("domain_estar");
	ppm_dc_t *dc;
	int ret = 0;

	if (domp == NULL) {
		PPMD(D_CPR, ("ppm_manage_sx: can't find estar domain\n"))
		return (ENODEV);
	}
	PPMD(D_CPR, ("ppm_manage_sx %x, enter %d\n", s3ap->s3a_state,
	    enter))
	switch (s3ap->s3a_state) {
	case S3:
		if (enter) {
			dc = ppm_lookup_dc(domp, PPMDC_ENTER_S3);
		} else {
			dc = ppm_lookup_dc(domp, PPMDC_EXIT_S3);
		}
		ASSERT(dc && dc->method == PPMDC_KIO);
		PPMD(D_CPR,
		    ("ppm_manage_sx: calling acpi driver (handle %p)"
		    " with %x\n", (void *)dc->lh, dc->m_un.kio.iowr))
		ret = ldi_ioctl(dc->lh, dc->m_un.kio.iowr,
		    (intptr_t)s3ap, FWRITE | FKIOCTL, kcred, NULL);
		break;

	case S4:
		/* S4 is not supported yet */
		return (EINVAL);
	default:
		ASSERT(0);
	}
	return (ret);
}

/*
 * Search enable/disable lists, which are encoded in ppm.conf as an array
 * of char strings.
 */
static int
ppm_search_list(pm_searchargs_t *sl)
{
	int i;
	int flags = DDI_PROP_DONTPASS;
	ppm_unit_t *unitp = ddi_get_soft_state(ppm_statep, ppm_inst);
	char **pp;
	char *starp;
	uint_t nelements;
	char *manuf = sl->pms_manufacturer;
	char *prod = sl->pms_product;

	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, unitp->dip, flags,
	    sl->pms_listname, &pp, &nelements) != DDI_PROP_SUCCESS) {
		PPMD(D_CPR, ("ppm_search_list prop lookup %s failed--EINVAL\n",
		    sl->pms_listname))
		return (EINVAL);
	}
	ASSERT((nelements & 1) == 0);		/* must be even */

	PPMD(D_CPR, ("ppm_search_list looking for %s, %s\n", manuf, prod))

	for (i = 0; i < nelements; i += 2) {
		PPMD(D_CPR, ("checking %s, %s", pp[i], pp[i+1]))
		/* we support only a trailing '*' pattern match */
		if ((starp = strchr(pp[i], '*')) != NULL && *(starp + 1) == 0) {
			/* LINTED - ptrdiff overflow */
			if (strncmp(manuf, pp[i], (starp - pp[i])) != 0) {
				PPMD(D_CPR, (" no match %s with %s\n",
				    manuf, pp[i + 1]))
				continue;
			}
		}
		if ((starp = strchr(pp[i + 1], '*')) != NULL &&
		    *(starp + 1) == 0) {
			if (strncmp(prod,
			    /* LINTED - ptrdiff overflow */
			    pp[i + 1], (starp - pp[i + 1])) != 0) {
				PPMD(D_CPR, (" no match %s with %s\n",
				    prod, pp[i + 1]))
				continue;
			}
		}
		if (strcmp(manuf, pp[i]) == 0 &&
		    (strcmp(prod, pp[i + 1]) == 0)) {
			PPMD(D_CPR, (" match\n"))
			ddi_prop_free(pp);
			return (0);
		}
		PPMD(D_CPR, (" no match %s with %s or %s with %s\n",
		    manuf, pp[i], prod, pp[i + 1]))
	}
	ddi_prop_free(pp);
	return (ENODEV);
}
