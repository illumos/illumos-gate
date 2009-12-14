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
 * common code for ppm drivers
 */
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ppmvar.h>
#include <sys/ppmio.h>
#include <sys/epm.h>
#include <sys/open.h>
#include <sys/file.h>
#include <sys/policy.h>


#ifdef DEBUG
uint_t	ppm_debug = 0;
#endif

int	ppm_inst = -1;
char	*ppm_prefix;
void	*ppm_statep;


/*
 * common module _init
 */
int
ppm_init(struct modlinkage *mlp, size_t size, char *prefix)
{
#ifdef DEBUG
	char *str = "ppm_init";
#endif
	int error;

	ppm_prefix = prefix;

	error = ddi_soft_state_init(&ppm_statep, size, 1);
	DPRINTF(D_INIT, ("%s: ss init %d\n", str, error));
	if (error != DDI_SUCCESS)
		return (error);

	if (error = mod_install(mlp))
		ddi_soft_state_fini(&ppm_statep);
	DPRINTF(D_INIT, ("%s: mod_install %d\n", str, error));

	return (error);
}


/* ARGSUSED */
int
ppm_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	struct ppm_unit *overlay;
	int rval;

	if (ppm_inst == -1)
		return (DDI_FAILURE);

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (overlay = ddi_get_soft_state(ppm_statep, ppm_inst)) {
			*resultp = overlay->dip;
			rval = DDI_SUCCESS;
		} else
			rval = DDI_FAILURE;
		return (rval);

	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(uintptr_t)ppm_inst;
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}


/* ARGSUSED */
int
ppm_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	if (otyp != OTYP_CHR)
		return (EINVAL);
	DPRINTF(D_OPEN, ("ppm_open: \"%s\", devp 0x%p, flag 0x%x, otyp %d\n",
	    ppm_prefix, (void *)devp, flag, otyp));
	return (0);
}


/* ARGSUSED */
int
ppm_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	DPRINTF(D_CLOSE, ("ppm_close: \"%s\", dev 0x%lx, flag 0x%x, otyp %d\n",
	    ppm_prefix, dev, flag, otyp));
	return (DDI_SUCCESS);
}


/*
 * lookup arrays of strings from configuration data (XXppm.conf)
 */
static int
ppm_get_confdata(struct ppm_cdata **cdp, dev_info_t *dip)
{
	struct ppm_cdata *cinfo;
	int err;

	for (; (cinfo = *cdp) != NULL; cdp++) {
		err = ddi_prop_lookup_string_array(
		    DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    cinfo->name, &cinfo->strings, &cinfo->cnt);
		if (err != DDI_PROP_SUCCESS) {
			DPRINTF(D_ERROR,
			    ("ppm_get_confdata: no %s found\n", cinfo->name));
			break;
		}
	}
	return (err);
}


/*
 * free allocated ddi prop strings, and free
 * ppm_db_t lists where there's an error.
 */
static int
ppm_attach_err(struct ppm_cdata **cdp, int err)
{
	ppm_domain_t **dompp;
	ppm_db_t *db, *tmp;

	if (cdp) {
		for (; *cdp; cdp++) {
			if ((*cdp)->strings) {
				ddi_prop_free((*cdp)->strings);
				(*cdp)->strings = NULL;
			}
		}
	}

	if (err != DDI_SUCCESS) {
		for (dompp = ppm_domains; *dompp; dompp++) {
			for (db = (*dompp)->conflist; (tmp = db) != NULL; ) {
				db = db->next;
				kmem_free(tmp->name, strlen(tmp->name) + 1);
				kmem_free(tmp, sizeof (*tmp));
			}
			(*dompp)->conflist = NULL;
		}
		err = DDI_FAILURE;
	}

	return (err);
}


ppm_domain_t *
ppm_lookup_domain(char *dname)
{
	ppm_domain_t **dompp;

	for (dompp = ppm_domains; *dompp; dompp++)
		if (strcmp(dname, (*dompp)->name) == 0)
			break;
	return (*dompp);
}


/*
 * create a ppm-private database from parsed .conf data; we start with
 * two string arrays (device pathnames and domain names) and treat them
 * as matched pairs where device[N] is part of domain[N]
 */
int
ppm_create_db(dev_info_t *dip)
{
#ifdef DEBUG
	char *str = "ppm_create_db";
#endif
	struct ppm_cdata devdata, domdata, *cdata[3];
	ppm_domain_t *domp;
	ppm_db_t *new;
	char **dev_namep, **dom_namep;
	char *wild;
	int err;

	bzero(&devdata, sizeof (devdata));
	bzero(&domdata, sizeof (domdata));
	devdata.name = "ppm-devices";
	domdata.name = "ppm-domains";
	cdata[0] = &devdata;
	cdata[1] = &domdata;
	cdata[2] = NULL;
	if (err = ppm_get_confdata(cdata, dip))
		return (ppm_attach_err(cdata, err));
	else if (devdata.cnt != domdata.cnt) {
		DPRINTF(D_ERROR,
		    ("%s: %sppm.conf has a mismatched number of %s and %s\n",
		    str, ppm_prefix, devdata.name, domdata.name));
		return (ppm_attach_err(cdata, DDI_FAILURE));
	}

	/*
	 * loop through device/domain pairs and build
	 * a linked list of devices within known domains
	 */
	for (dev_namep = devdata.strings, dom_namep = domdata.strings;
	    *dev_namep; dev_namep++, dom_namep++) {
		domp = ppm_lookup_domain(*dom_namep);
		if (domp == NULL) {
			DPRINTF(D_ERROR, ("%s: invalid domain \"%s\" for "
			    "device \"%s\"\n", str, *dom_namep, *dev_namep));
			return (ppm_attach_err(cdata, DDI_FAILURE));
		}

		/*
		 * allocate a new ppm db entry and link it to
		 * the front of conflist within this domain
		 */
		new = kmem_zalloc(sizeof (*new), KM_SLEEP);
		new->name = kmem_zalloc(strlen(*dev_namep) + 1, KM_SLEEP);
		(void) strcpy(new->name, *dev_namep);
		new->next = domp->conflist;
		domp->conflist = new;

		/*
		 * when the device name contains a wildcard,
		 * save the length of the preceding string
		 */
		if (wild = strchr(new->name, '*'))
			new->plen = (wild - new->name);
		DPRINTF(D_CREATEDB, ("%s: \"%s\", added \"%s\"\n",
		    str, domp->name, new->name));
	}

	return (ppm_attach_err(cdata, DDI_SUCCESS));
}


/*
 * scan conf devices within each domain for a matching device name
 */
ppm_domain_t *
ppm_lookup_dev(dev_info_t *dip)
{
	char path[MAXNAMELEN];
	ppm_domain_t **dompp;
	ppm_db_t *dbp;

	(void) ddi_pathname(dip, path);
	for (dompp = ppm_domains; *dompp; dompp++) {
		for (dbp = (*dompp)->conflist; dbp; dbp = dbp->next) {
			if (dbp->plen == 0) {
				if (strcmp(path, dbp->name) == 0)
					return (*dompp);
			} else if (strncmp(path, dbp->name, dbp->plen) == 0)
				return (*dompp);
		}
	}

	return (NULL);
}


/*
 * returns 1 (claimed), 0 (not claimed)
 */
int
ppm_claim_dev(dev_info_t *dip)
{
	ppm_domain_t *domp;

	domp = ppm_lookup_dev(dip);

#ifdef DEBUG
	if (domp) {
		char path[MAXNAMELEN];
		DPRINTF(D_CLAIMDEV,
		    ("ppm_claim_dev: \"%s\", matched \"%s\"\n",
		    domp->name, ddi_pathname(dip, path)));
	}

#endif

	return (domp != NULL);
}


/*
 * create/init a new ppm device and link into the domain
 */
ppm_dev_t *
ppm_add_dev(dev_info_t *dip, ppm_domain_t *domp)
{
	char path[MAXNAMELEN];
	ppm_dev_t *new = NULL;
	int cmpt;

	ASSERT(MUTEX_HELD(&domp->lock));
	(void) ddi_pathname(dip, path);
	/*
	 * For devs which have exported "pm-components" we want to create
	 * a data structure for each component.  When a driver chooses not
	 * to export the prop we treat its device as having a single
	 * component and build a structure for it anyway.  All other ppm
	 * logic will act as if this device were always up and can thus
	 * make correct decisions about it in relation to other devices
	 * in its domain.
	 */
	for (cmpt = PM_GET_PM_INFO(dip) ? PM_NUMCMPTS(dip) : 1; cmpt--; ) {
		new = kmem_zalloc(sizeof (*new), KM_SLEEP);
		new->path = kmem_zalloc(strlen(path) + 1, KM_SLEEP);
		(void) strcpy(new->path, path);
		new->domp = domp;
		new->dip = dip;
		new->cmpt = cmpt;
		if (ppmf.dev_init)
			(*ppmf.dev_init)(new);
		new->next = domp->devlist;
		domp->devlist = new;
		DPRINTF(D_ADDDEV,
		    ("ppm_add_dev: \"%s\", \"%s\", ppm_dev 0x%p\n",
		    new->path, domp->name, (void *)new));
	}

	ASSERT(new != NULL);
	/*
	 * devi_pm_ppm_private should be set only after all
	 * ppm_dev s related to all components have been
	 * initialized and domain's pwr_cnt is incremented
	 * for each of them.
	 */
	PPM_SET_PRIVATE(dip, new);

	return (new);
}


/*
 * returns an existing or newly created ppm device reference
 */
ppm_dev_t *
ppm_get_dev(dev_info_t *dip, ppm_domain_t *domp)
{
	ppm_dev_t *pdp;

	mutex_enter(&domp->lock);
	pdp = PPM_GET_PRIVATE(dip);
	if (pdp == NULL)
		pdp = ppm_add_dev(dip, domp);
	mutex_exit(&domp->lock);

	return (pdp);
}


/*
 * scan a domain's device list and remove those with .dip
 * matching the arg *dip; we need to scan the entire list
 * for the case of devices with multiple components
 */
void
ppm_rem_dev(dev_info_t *dip)
{
	ppm_dev_t *pdp, **devpp;
	ppm_domain_t *domp;

	pdp = PPM_GET_PRIVATE(dip);
	ASSERT(pdp);
	domp = pdp->domp;
	ASSERT(domp);

	mutex_enter(&domp->lock);
	for (devpp = &domp->devlist; (pdp = *devpp) != NULL; ) {
		if (pdp->dip != dip) {
			devpp = &pdp->next;
			continue;
		}

		DPRINTF(D_REMDEV, ("ppm_rem_dev: path \"%s\", ppm_dev 0x%p\n",
		    pdp->path, (void *)pdp));

		PPM_SET_PRIVATE(dip, NULL);
		*devpp = pdp->next;
		if (ppmf.dev_fini)
			(*ppmf.dev_fini)(pdp);
		kmem_free(pdp->path, strlen(pdp->path) + 1);
		kmem_free(pdp, sizeof (*pdp));
	}
	mutex_exit(&domp->lock);
}


/* ARGSUSED */
int
ppm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *cred_p, int *rval_p)
{
#ifdef DEBUG
	char *str = "ppm_ioctl";
	char *rwfmt = "%s: mode error: 0x%x is missing %s perm, cmd 0x%x\n";
	char *iofmt = "%s: copy%s error, arg 0x%p\n";
#endif
	ppmreq_t req;
	uint8_t level;

	DPRINTF(D_IOCTL, ("%s: dev 0x%lx, cmd 0x%x, arg 0x%lx, mode 0x%x\n",
	    str, dev, cmd, arg, mode));

	if (ddi_copyin((caddr_t)arg, &req, sizeof (req), mode)) {
		DPRINTF(D_IOCTL, (iofmt, str, "in", arg));
		return (EFAULT);
	}

	/*
	 * Currently, only PPM_INTERNAL_DEVICE_POWER device type is supported
	 */
	if (req.ppmdev != PPM_INTERNAL_DEVICE_POWER) {
		DPRINTF(D_IOCTL, ("%s: unrecognized device type %d\n",
		    str, req.ppmdev));
		return (EINVAL);
	}

	switch (cmd) {
	case PPMIOCSET:
		if (secpolicy_power_mgmt(cred_p) != 0) {
			DPRINTF(D_IOCTL, ("%s: bad cred for cmd 0x%x\n",
			    str, cmd));
			return (EPERM);
		} else if (!(mode & FWRITE)) {
			DPRINTF(D_IOCTL, (rwfmt, str, mode, "write"));
			return (EPERM);
		}

		level = req.ppmop.idev_power.level;
		if ((level != PPM_IDEV_POWER_ON) &&
		    (level != PPM_IDEV_POWER_OFF)) {
			DPRINTF(D_IOCTL,
			    ("%s: invalid power level %d, cmd 0x%x\n",
			    str, level, cmd));
			return (EINVAL);
		}
		if (ppmf.iocset == NULL)
			return (ENOTSUP);
		(*ppmf.iocset)(level);
		break;

	case PPMIOCGET:
		if (!(mode & FREAD)) {
			DPRINTF(D_IOCTL, (rwfmt, str, mode, "read"));
			return (EPERM);
		}

		if (ppmf.iocget == NULL)
			return (ENOTSUP);
		req.ppmop.idev_power.level = (*ppmf.iocget)();
		if (ddi_copyout((const void *)&req, (void *)arg,
		    sizeof (req), mode)) {
			DPRINTF(D_ERROR, (iofmt, str, "out", arg));
			return (EFAULT);
		}
		break;

	default:
		DPRINTF(D_IOCTL, ("%s: unrecognized cmd 0x%x\n", str, cmd));
		return (EINVAL);
	}

	return (0);
}


#ifdef DEBUG
#define	FLINTSTR(flags, sym) { flags, sym, #sym }
#define	PMR_UNKNOWN -1
/*
 * convert a ctlop integer to a char string.  this helps printing
 * meaningful info when cltops are received from the pm framework.
 * since some ctlops are so frequent, we use mask to limit output:
 * a valid string is returned when ctlop is found and when
 * (cmd.flags & mask) is true; otherwise NULL is returned.
 */
char *
ppm_get_ctlstr(int ctlop, uint_t mask)
{
	struct ctlop_cmd {
		uint_t flags;
		int ctlop;
		char *str;
	};

	struct ctlop_cmd *ccp;
	static struct ctlop_cmd cmds[] = {
		FLINTSTR(D_SETPWR, PMR_SET_POWER),
		FLINTSTR(D_CTLOPS2, PMR_SUSPEND),
		FLINTSTR(D_CTLOPS2, PMR_RESUME),
		FLINTSTR(D_CTLOPS2, PMR_PRE_SET_POWER),
		FLINTSTR(D_CTLOPS2, PMR_POST_SET_POWER),
		FLINTSTR(D_CTLOPS2, PMR_PPM_SET_POWER),
		FLINTSTR(0, PMR_PPM_ATTACH),
		FLINTSTR(0, PMR_PPM_DETACH),
		FLINTSTR(D_CTLOPS1, PMR_PPM_POWER_CHANGE_NOTIFY),
		FLINTSTR(D_CTLOPS1, PMR_REPORT_PMCAP),
		FLINTSTR(D_CTLOPS1, PMR_CHANGED_POWER),
		FLINTSTR(D_CTLOPS2, PMR_PPM_PRE_PROBE),
		FLINTSTR(D_CTLOPS2, PMR_PPM_POST_PROBE),
		FLINTSTR(D_CTLOPS2, PMR_PPM_PRE_ATTACH),
		FLINTSTR(D_CTLOPS2, PMR_PPM_POST_ATTACH),
		FLINTSTR(D_CTLOPS2, PMR_PPM_PRE_DETACH),
		FLINTSTR(D_CTLOPS2, PMR_PPM_POST_DETACH),
		FLINTSTR(D_CTLOPS1, PMR_PPM_UNMANAGE),
		FLINTSTR(D_CTLOPS2, PMR_PPM_PRE_RESUME),
		FLINTSTR(D_CTLOPS1, PMR_PPM_ALL_LOWEST),
		FLINTSTR(D_LOCKS, PMR_PPM_LOCK_POWER),
		FLINTSTR(D_LOCKS, PMR_PPM_UNLOCK_POWER),
		FLINTSTR(D_LOCKS, PMR_PPM_TRY_LOCK_POWER),
		FLINTSTR(D_CTLOPS1 | D_CTLOPS2, PMR_UNKNOWN),
	};

	for (ccp = cmds; ccp->ctlop != PMR_UNKNOWN; ccp++)
		if (ctlop == ccp->ctlop)
			break;

	if (ccp->flags & mask)
		return (ccp->str);
	return (NULL);
}
#endif
