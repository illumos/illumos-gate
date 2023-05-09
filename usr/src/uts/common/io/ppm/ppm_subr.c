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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * ppm driver subroutines
 */

#include <sys/open.h>
#include <sys/file.h>
#include <sys/conf.h>
#include <sys/epm.h>
#include <sys/sunldi.h>
#include <sys/ppmvar.h>
#include <sys/ppmio.h>
#include <sys/promif.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
/*
 * Append address to the device path, if it is set.  Routine
 * ddi_pathname does not look for device address if the node is in
 * DS_INITIALIZED state.
 */
#define	PPM_GET_PATHNAME(dip, path)				\
	(void) ddi_pathname((dip), (path));			\
	if ((i_ddi_node_state((dip)) < DS_INITIALIZED) &&	\
	    (ddi_get_name_addr((dip)) != NULL)) {		\
		(void) strcat((path), "@");			\
		(void) strcat((path), ddi_get_name_addr((dip)));\
	}

int	ppm_parse_dc(char **, ppm_dc_t *);
int	ppm_match_devs(char *, ppm_db_t *);
ppm_db_t *ppm_parse_pattern(struct ppm_db **, char *);
int	ppm_count_char(char *, char);
int	ppm_stoi(char *, uint_t *);
int	ppm_convert(char *, uint_t *);
void	ppm_prop_free(struct ppm_cdata **);

/*
 * lookup string property from configuration file ppm.conf
 */
static int
ppm_get_confdata(struct ppm_cdata **cdp, dev_info_t *dip)
{
#ifdef	DEBUG
	char *str = "ppm_get_confdata";
#endif
	struct ppm_cdata *cinfo;
	int err;

	for (; (cinfo = *cdp) != NULL; cdp++) {
		err = ddi_prop_lookup_string_array(
		    DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
		    cinfo->name, &cinfo->strings, &cinfo->cnt);
		if (err != DDI_PROP_SUCCESS) {
			PPMD(D_ERROR, ("%s: no %s found, err(%d)\n",
			    str, cinfo->name, err))
			break;
		}
	}
	return (err);
}

void
ppm_prop_free(struct ppm_cdata **cdp)
{
	if (cdp) {
		for (; *cdp; cdp++) {
			if ((*cdp)->name) {
				kmem_free((*cdp)->name,
				    strlen((*cdp)->name) + 1);
				(*cdp)->name = NULL;
			}
			if ((*cdp)->strings) {
				ddi_prop_free((*cdp)->strings);
				(*cdp)->strings = NULL;
			}
		}
	}
}


/*
 * free ddi prop strings. Under error condition, free ppm_db_t lists as well.
 */
static int
ppm_attach_err(struct ppm_cdata **cdp, int err)
{
	ppm_domain_t *domp;
	ppm_db_t *db, *tmp;

	ppm_prop_free(cdp);
	if (err != DDI_SUCCESS) {
		for (domp = ppm_domain_p; domp; domp = domp->next) {
			for (db = domp->conflist; (tmp = db) != NULL; ) {
				db = db->next;
				kmem_free(tmp->name, strlen(tmp->name) + 1);
				kmem_free(tmp, sizeof (*tmp));
			}
			domp->conflist = NULL;
		}
		err = DDI_FAILURE;
	}

	return (err);
}


ppm_domain_t *
ppm_lookup_domain(char *dname)
{
	ppm_domain_t	*domp;

	for (domp = ppm_domain_p; domp; domp = domp->next) {
		if (strcmp(dname, domp->name) == 0)
			break;
	}
	return (domp);
}


/*
 * for the purpose of optimizing we search for identical dc->path
 * that has been opened per previous visit here.  If search results
 * in a hit, copy the device handle, else open the device.
 */
ppm_dc_t *
ppm_lookup_hndl(int model, ppm_dc_t *key_dc)
{
#ifdef	DEBUG
	char *str = "ppm_lookup_hndl";
#endif
	char *key_path = key_dc->path;
	ppm_domain_t *domp;
	ppm_dc_t *dc;

	/* search domain by domain.model */
	for (domp = ppm_domain_p; domp; domp = domp->next) {
		if (domp->model == model)
			break;
	}

	/* lookup hndl from same domain model */
	if (domp && PPM_DOMAIN_UP(domp)) {
		for (dc = domp->dc; dc; dc = dc->next) {
			if ((strcmp(dc->path, key_path) == 0) &&
			    (dc->lh != NULL)) {
				PPMD(D_PPMDC, ("%s: Hit(dc_path:%s) from SAME "
				    "domain %s.\n", str, key_path, domp->name))
				key_dc->lh = dc->lh;
				return (key_dc);
			}
		}
	}

	/* otherwise, check other domains */
	for (domp = ppm_domain_p;
	    domp && (domp->model != model); domp = domp->next) {
		if (PPM_DOMAIN_UP(domp)) {
			for (dc = domp->dc; dc; dc = dc->next) {
				if ((strcmp(dc->path, key_path) == 0) &&
				    (dc->lh != NULL)) {
					PPMD(D_PPMDC, ("%s: Hit(dc_path:%s) "
					    "from domain %s\n",
					    str, key_path, domp->name))
					key_dc->lh = dc->lh;
					return (key_dc);
				}
			}
		}
	}

	PPMD(D_PPMDC, ("%s: Miss(dc_path:%s)\n", str, key_path))
	return (NULL);
}


#define	PPM_DOMAIN_PROP			"ppm-domains"
#define	PPM_DEV_PROP_SUFFIX		"-devices"
#define	PPM_MODEL_PROP_SUFFIX		"-model"
#define	PPM_PROPNAME_PROP_SUFFIX	"-propname"
#define	PPM_CTRL_PROP_SUFFIX		"-control"

struct ppm_domit ppm_domit_data[] = {
	"SX",  PPMD_SX, 0, PPMD_ON,
	"CPU", PPMD_CPU, PPMD_LOCK_ALL, PPMD_ON,
	"FET", PPMD_FET, PPMD_LOCK_ONE, PPMD_ON,
	"PCI", PPMD_PCI, PPMD_LOCK_ONE, PPMD_ON,
	"PCI_PROP", PPMD_PCI_PROP, PPMD_LOCK_ONE, PPMD_ON,
	"LED", PPMD_LED, 0, PPMD_ON,
	"PCIE", PPMD_PCIE, PPMD_LOCK_ONE, PPMD_ON,
	NULL
};

/*
 * store up platform dependent information provided by ppm.conf file
 * into private data base
 */
int
ppm_create_db(dev_info_t *dip)
{
#ifdef	DEBUG
	char *str = "ppm_create_db";
#endif
	ppm_domain_t *domp;
	ppm_db_t *db;
	ppm_dc_t *dc;
	struct ppm_cdata domdata;	/* hold "ppm-domains" property */
	struct ppm_cdata modeldata;	/* hold "domain_xy-model" property */
	struct ppm_cdata propnamedata;	/* hold "domain_xy-propname" property */
	struct ppm_cdata devdata;	/* hold "domain_xy-devices" property */
	struct ppm_cdata dcdata;	/* hold "domain_xy-control" property */
	struct ppm_cdata *cdata[2];
	char **dom_namep, **model_namep, **dev_namep, **dc_namep;
	struct ppm_domit	*domit_p;
	int err;

	/*
	 * get "ppm-domains" property
	 */
	bzero(&domdata, sizeof (domdata));
	domdata.name = kmem_zalloc(strlen(PPM_DOMAIN_PROP) + 1, KM_SLEEP);
	(void) strcpy(domdata.name, PPM_DOMAIN_PROP);
	cdata[0] = &domdata;
	cdata[1] = NULL;
	if (err = ppm_get_confdata(cdata, dip)) {
		PPMD(D_CREATEDB, ("%s: failed to get prop \"%s\"!\n",
		    str, PPM_DOMAIN_PROP))
		return (ppm_attach_err(cdata, err));
	}

	for (dom_namep = domdata.strings; *dom_namep; dom_namep++) {
		domp = kmem_zalloc(sizeof (*domp), KM_SLEEP);
		domp->name = kmem_zalloc(strlen(*dom_namep) + 1, KM_SLEEP);
		(void) strcpy(domp->name, *dom_namep);
		mutex_init(&domp->lock, NULL, MUTEX_DRIVER, NULL);
		if (ppm_domain_p == NULL)
			ppm_domain_p = domp;
		else {
			domp->next = ppm_domain_p;
			ppm_domain_p = domp;
		}
	}
	ppm_prop_free(cdata);

	/*
	 * more per domain property strings in ppm.conf file tell us
	 * what the nature of domain, how to performe domain control, etc.
	 * Even the property names of those per domain properties are
	 * formed consisting its domain name string.
	 * Here we walk through our domain list, and fullfill the details.
	 */
	for (domp = ppm_domain_p; domp; domp = domp->next) {
		size_t	plen;

		/*
		 * get "domain_xy-model" property
		 */
		bzero(&modeldata, sizeof (modeldata));
		plen = strlen(domp->name) + strlen(PPM_MODEL_PROP_SUFFIX) + 1;
		modeldata.name = kmem_zalloc(plen, KM_SLEEP);
		(void) sprintf(modeldata.name, "%s%s",
		    domp->name, PPM_MODEL_PROP_SUFFIX);

		cdata[0] = &modeldata;
		cdata[1] = NULL;
		if (err = ppm_get_confdata(cdata, dip)) {
			PPMD(D_CREATEDB, ("%s: Can't read property %s!\n",
			    str, modeldata.name))
			return (ppm_attach_err(cdata, err));
		}

		model_namep = modeldata.strings;
		for (domit_p = ppm_domit_data; domit_p->name; domit_p++) {
			if (strcmp(domit_p->name,  *model_namep) == 0) {
				domp->model = domit_p->model;
				domp->dflags = domit_p->dflags;
				domp->status = domit_p->status;
				break;
			}
		}
		ASSERT(domit_p);

		ppm_prop_free(cdata);


		/* get "domain_xy-propname" property */
		bzero(&propnamedata, sizeof (propnamedata));
		plen = strlen(domp->name) +
		    strlen(PPM_PROPNAME_PROP_SUFFIX) + 1;
		propnamedata.name = kmem_zalloc(plen, KM_SLEEP);
		(void) sprintf(propnamedata.name, "%s%s",
		    domp->name, PPM_PROPNAME_PROP_SUFFIX);

		cdata[0] = &propnamedata;
		cdata[1] = NULL;
		if (ppm_get_confdata(cdata, dip) == DDI_PROP_SUCCESS) {
			domp->propname = kmem_zalloc(
			    (strlen(*propnamedata.strings) + 1), KM_SLEEP);
			(void) strcpy(domp->propname, *propnamedata.strings);
			PPMD(D_CREATEDB, ("%s: %s has property name: %s\n",
			    str, domp->name, domp->propname))
		}
		ppm_prop_free(cdata);


		/* get "domain_xy-devices" property */
		bzero(&devdata, sizeof (devdata));
		plen = strlen(domp->name) + strlen(PPM_DEV_PROP_SUFFIX) + 1;
		devdata.name = kmem_zalloc(plen, KM_SLEEP);
		(void) sprintf(devdata.name, "%s%s",
		    domp->name, PPM_DEV_PROP_SUFFIX);

		cdata[0] = &devdata;
		cdata[1] = NULL;
		if (err = ppm_get_confdata(cdata, dip)) {
			PPMD(D_CREATEDB, ("%s: Can't read property %s!\n",
			    str, devdata.name))
			return (ppm_attach_err(cdata, err));
		}

		for (dev_namep = devdata.strings; *dev_namep; dev_namep++) {
			if (!ppm_parse_pattern(&db, *dev_namep))
				return (ppm_attach_err(cdata, err));
			db->next = domp->conflist;
			domp->conflist = db;
			PPMD(D_CREATEDB, ("%s: %s add pattern: %s \n",
			    str, devdata.name, db->name))
		}
		PPMD(D_CREATEDB, ("\n"))
		ppm_prop_free(cdata);


		/* get "domain_xy-control" property */
		bzero(&dcdata, sizeof (dcdata));
		plen = strlen(domp->name) + strlen(PPM_CTRL_PROP_SUFFIX) + 1;
		dcdata.name = kmem_zalloc(plen, KM_SLEEP);
		(void) sprintf(dcdata.name, "%s%s",
		    domp->name, PPM_CTRL_PROP_SUFFIX);

		cdata[0] = &dcdata;
		cdata[1] = NULL;
		if (ppm_get_confdata(cdata, dip) == DDI_PROP_SUCCESS) {
			for (dc_namep = dcdata.strings; *dc_namep;
			    dc_namep++) {
				dc = kmem_zalloc(sizeof (*dc), KM_SLEEP);
				dc->next = domp->dc;
				domp->dc = dc;
				err = ppm_parse_dc(dc_namep, domp->dc);
				if (err != DDI_SUCCESS)
					return (ppm_attach_err(cdata, err));
			}
		}
		ppm_prop_free(cdata);
#ifdef	DEBUG
		dc = domp->dc;
		while (dc) {
			ppm_print_dc(dc);
			dc = dc->next;
		}
#endif
	}

	return (DDI_SUCCESS);
}


/*
 * scan conf devices within each domain for a matching device name
 */
ppm_domain_t *
ppm_lookup_dev(dev_info_t *dip)
{
	char path[MAXNAMELEN];
	ppm_domain_t *domp;
	ppm_db_t *dbp;
#ifdef	__x86
	char *devtype = NULL;
#endif	/* __x86 */

	PPM_GET_PATHNAME(dip, path);
	for (domp = ppm_domain_p; domp; domp = domp->next) {
		if (PPM_DOMAIN_UP(domp)) {
			for (dbp = domp->conflist; dbp; dbp = dbp->next) {
				/*
				 * allow claiming root without knowing
				 * its full name
				 */
				if (dip == ddi_root_node() &&
				    strcmp(dbp->name, "/") == 0)
					return (domp);

#ifdef	__x86
				/*
				 * Special rule to catch all CPU devices on x86.
				 */
				if (domp->model == PPMD_CPU &&
				    strcmp(dbp->name, "/") == 0 &&
				    ddi_prop_lookup_string(DDI_DEV_T_ANY, dip,
				    DDI_PROP_DONTPASS, "device_type",
				    &devtype) == DDI_SUCCESS) {
					if (strcmp(devtype, "cpu") == 0) {
						ddi_prop_free(devtype);
						return (domp);
					} else {
						ddi_prop_free(devtype);
					}
				}
#endif	/* __x86 */

				if (ppm_match_devs(path, dbp) == 0)
					return (domp);
			}
		}
	}

	return (NULL);
}


/*
 * check ppm.conf file domain device pathname syntax, if correct,
 * create device match pattern.
 * return 1 for good, -1 for bad.
 */
ppm_db_t *
ppm_parse_pattern(struct ppm_db **dbpp, char *dev_path)
{
	char path[MAXNAMELEN];
	int	wccnt, i;
	int	wcpos[2];
	int	pos;
	char	*cp;
	ppm_db_t *dbp;

	(void) strcpy(path, dev_path);
	if ((wccnt = ppm_count_char(path, '*')) > 2)
		return (NULL);

	for (i = 0, cp = path, pos = 0; i < wccnt; i++, cp++, pos++) {
		for (; *cp; cp++, pos++)
			if (*cp == '*')
				break;
		wcpos[i] = pos;
		PPMD(D_CREATEDB, ("    wildcard #%d, pos %d\n",
		    (i + 1), wcpos[i]))
	}

#ifdef	DEBUG
	/* first '*', if exists, don't go beyond the string */
	if (wccnt > 0)
		ASSERT(wcpos[0] < strlen(path));

	/* second '*', if exists, better be the last character */
	if (wccnt == 2)
		ASSERT(wcpos[1] == (strlen(path) - 1));
#endif

	/*
	 * first '*', if followed by any char, must be immediately
	 * followed by '@' and the rest better be bound by
	 * ['0-9', 'a-f', A-F'] until ended '0' or second '*''0'.
	 */
	if ((wccnt > 0) && (wcpos[0] < (strlen(path) - 1))) {
		cp = path + wcpos[0] + 1;
		if (*cp != '@')
			return (NULL);

		if (!(((*(++cp) > '0') && (*cp < '9')) ||
		    ((*cp > 'a') && (*cp < 'f')) ||
		    ((*cp > 'A') && (*cp < 'F'))))
			return (NULL);
	}

	dbp = kmem_zalloc(sizeof (struct ppm_db), KM_SLEEP);
	dbp->name = kmem_zalloc((strlen(path) + 1), KM_SLEEP);
	(void) strcpy(dbp->name, path);
	dbp->wccnt = wccnt;
	dbp->wcpos[0] = (wccnt > 0) ? wcpos[0] : -1;
	dbp->wcpos[1] = (wccnt == 2) ? wcpos[1] : -1;

	return (*dbpp = dbp);
}


/*
 * match given device "path" to domain device pathname
 * pattern dbp->name that contains one or two '*' character(s).
 * Matching policy:
 *   1). If one wildcard terminates match pattern, need exact match
 *       up to (but exclude) the wildcard;
 *   2). If one wildcard does not terminate match pattern, it is to
 *       match driver name (terminates with '@') and must be followed
 *       by exact match of rest of pattern;
 *   3). If two wildcards, first is to match driver name as in 2),
 *       second is to match fcnid (terminates with '/' or '\0') and
 *       must the last char of pattern.
 *
 * return  0  if match, and
 *        non 0  if mismatch
 */
int
ppm_match_devs(char *dev_path, ppm_db_t *dbp)
{
	char path[MAXNAMELEN];
	char *cp;	/* points into "path", real device pathname */
	char *np;	/* points into "dbp->name", the pattern */
	int  len;

	if (dbp->wccnt == 0)
		return (strcmp(dev_path, dbp->name));

	(void) strcpy(path, dev_path);

	/* match upto the first '*' regardless */
	if (strncmp(path, dbp->name, dbp->wcpos[0]) != 0)
		return (-1);


	/* "<exact match>*"	*/
	if (dbp->name[dbp->wcpos[0] + 1] == 0) {
		cp = path + dbp->wcpos[0];
		while (*cp && (*cp++ != '/'))
			;
		return ((*cp == 0) ? 0 : -1);
	}


	/* locate '@'	*/
	cp = path + dbp->wcpos[0] + 1;
	while (*cp && *cp != '@')
		cp++;

	np = dbp->name + dbp->wcpos[0] + 1;

	/* if one wildcard, match the rest in the pattern */
	if (dbp->wccnt == 1)
		return ((strcmp(cp, np) == 0) ? 0 : (-1));


	/* must have exact match after first wildcard up to second */
	ASSERT(dbp->wccnt == 2);
	len = dbp->wcpos[1] - dbp->wcpos[0] - 1;
	if (strncmp(cp, np, len) != 0)
		return (-1);

	/* second wildcard match terminates with '/' or '\0' */
	/* but only termination with '\0' is a successful match */
	cp += len;
	while (*cp && (*cp != '/'))
		cp++;
	return ((*cp == 0) ? 0 : -1);
}


/*
 * By claiming a device, ppm gets involved in its power change
 * process: handles additional issues prior and/or post its
 * power(9e) call.
 *
 * If 'dip' is a PCI device, this is the time to ask its parent
 * what PCI bus speed it is running.
 *
 * returns 1 (claimed), 0 (not claimed)
 */
int
ppm_claim_dev(dev_info_t *dip)
{
	ppm_domain_t	*domp;
	dev_info_t	*pdip;
	uint_t		pciclk;
	int		claimed = -1;

	domp = ppm_lookup_dev(dip);
	if (!domp)
		claimed = 0;

	if (domp && PPMD_IS_PCI(domp->model) &&
	    ! (domp->dflags & (PPMD_PCI33MHZ | PPMD_PCI66MHZ))) {
		pdip = ddi_get_parent(dip);
		ASSERT(pdip);
		pciclk = ddi_prop_get_int(DDI_DEV_T_ANY, pdip,
		    DDI_PROP_DONTPASS, "clock-frequency", -1);

		switch (pciclk) {
		case 33000000:
			domp->dflags |= PPMD_PCI33MHZ;
			claimed = 1;
			break;
		case 66000000:
			domp->dflags |= PPMD_PCI66MHZ;
			claimed = 1;
			break;
		default:
			claimed = 0;
			break;
		}
	}

	if (domp && (claimed == -1))
		claimed = 1;

#ifdef DEBUG
	if (claimed) {
		char path[MAXNAMELEN];
		PPMD(D_CLAIMDEV, ("ppm_claim_dev: %s into domain %s\n",
		    ddi_pathname(dip, path), domp->name))
	}

#endif

	return (claimed);
}

/*
 * add a device to the list of domain's owned devices (if it is not already
 * on the list).
 */
ppm_owned_t *
ppm_add_owned(dev_info_t *dip, ppm_domain_t *domp)
{
	char path[MAXNAMELEN];
	ppm_owned_t *owned, *new_owned;

	ASSERT(MUTEX_HELD(&domp->lock));
	PPM_GET_PATHNAME(dip, path);
	for (owned = domp->owned; owned; owned = owned->next)
		if (strcmp(path, owned->path) == 0)
			return (owned);

	new_owned = kmem_zalloc(sizeof (*new_owned), KM_SLEEP);
	new_owned->path = kmem_zalloc(strlen(path) + 1, KM_SLEEP);
	(void) strcpy(new_owned->path, path);
	new_owned->next = domp->owned;
	domp->owned = new_owned;

	return (domp->owned);
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
	ppm_owned_t *owned;

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
		ppm_dev_init(new);
		new->next = domp->devlist;
		domp->devlist = new;
		PPMD(D_ADDDEV,
		    ("ppm_add_dev: %s to domain %s: ppm_dev(0x%p)\n",
		    new->path, domp->name, (void *)new))
	}

	ASSERT(new != NULL);
	/*
	 * devi_pm_ppm_private should be set only after all
	 * ppm_dev s related to all components have been
	 * initialized and domain's pwr_cnt is incremented
	 * for each of them.
	 */
	PPM_SET_PRIVATE(dip, new);

	/* remember this device forever */
	owned = ppm_add_owned(dip, domp);

	/*
	 * Initializing flag is set for devices which have gone through
	 * PPM_PMR_INIT_CHILD ctlop.  By this point, these devices have
	 * been added to ppm structures and could participate in pm
	 * decision making, so clear the initializing flag.
	 */
	if (owned->initializing) {
		owned->initializing = 0;
		PPMD(D_ADDDEV, ("ppm_add_dev: cleared initializing flag "
		    "for %s@%s\n", PM_NAME(dip),
		    (PM_ADDR(dip) == NULL) ? "" : PM_ADDR(dip)))
	}

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

		PPMD(D_REMDEV, ("ppm_rem_dev: path \"%s\", ppm_dev 0x%p\n",
		    pdp->path, (void *)pdp))

		PPM_SET_PRIVATE(dip, NULL);
		*devpp = pdp->next;
		ppm_dev_fini(pdp);
		kmem_free(pdp->path, strlen(pdp->path) + 1);
		kmem_free(pdp, sizeof (*pdp));
	}
	mutex_exit(&domp->lock);
}

/*
 * prepare kernel ioctl calls:
 */
void
ppm_init_cb(dev_info_t *dip)
{
	char		*str = "ppm_init_cb";
	ppm_domain_t	*domp;
	ppm_dc_t	*dc;

	for (domp = ppm_domain_p; domp != NULL; domp = domp->next) {
		for (dc = domp->dc; dc; dc = dc->next) {
			/*
			 * Warning: This code is rather confusing.
			 *
			 * It intends to ensure that ppm_init_lyr() is only
			 * called ONCE for a device that may be associated
			 * with more than one domain control.
			 * So, what it does is first to check to see if
			 * there is a handle, and then if not it goes on
			 * to call the init_lyr() routine.
			 *
			 * The non-obvious thing is that the ppm_init_lyr()
			 * routine, in addition to opening the device
			 * associated with the dc (domain control) in
			 * question, has the side-effect of creating the
			 * handle for that dc as well.
			 */
			if (ppm_lookup_hndl(domp->model, dc) != NULL)
				continue;

			if (ppm_init_lyr(dc, dip) != DDI_SUCCESS) {
				domp->dflags |= PPMD_OFFLINE;
				cmn_err(CE_WARN, "%s: ppm domain %s will "
				    "be offline.", str, domp->name);
				break;
			}
		}
	}
}


/*
 *  ppm_init_lyr - initializing layered ioctl
 * Return:
 *     DDI_SUCCESS  - succeeded
 *     DDI_FAILURE  - failed
 *
 */
int
ppm_init_lyr(ppm_dc_t	*dc, dev_info_t *dip)
{
	char			*str = "ppm_init_lyr";
	int			err = 0;
	ldi_ident_t		li;

	ASSERT(dc && dc->path);

	if (err = ldi_ident_from_dip(dip, &li)) {
		cmn_err(CE_WARN, "%s: get ldi identifier "
		    "failed (err=%d)", str, err);
	}

	err = ldi_open_by_name(dc->path, FWRITE|FREAD, kcred, &(dc->lh), li);

	(void) ldi_ident_release(li);

	if (err != 0) {
		cmn_err(CE_WARN, "Failed to open device(%s), rv(%d)",
		    dc->path, err);
		return (err);
	}

	return (DDI_SUCCESS);
}

/*
 * lock, unlock, or trylock for one power mutex
 */
void
ppm_lock_one(ppm_dev_t *ppmd, power_req_t *reqp, int *iresp)
{
	switch (reqp->request_type) {
	case PMR_PPM_LOCK_POWER:
		pm_lock_power_single(ppmd->dip);
		break;

	case PMR_PPM_UNLOCK_POWER:
		pm_unlock_power_single(ppmd->dip);
		break;

	case PMR_PPM_TRY_LOCK_POWER:
		*iresp = pm_try_locking_power_single(ppmd->dip);
		break;
	}
}


/*
 * lock, unlock, or trylock for all power mutexes within a domain
 */
void
ppm_lock_all(ppm_domain_t *domp, power_req_t *reqp, int *iresp)
{
	/*
	 * To simplify the implementation we let all the devices
	 * in the domain be represented by a single device (dip).
	 * We use the first device in the domain's devlist.  This
	 * is safe because we return with the domain lock held
	 * which prevents the list from changing.
	 */
	if (reqp->request_type == PMR_PPM_LOCK_POWER) {
		if (!MUTEX_HELD(&domp->lock))
			mutex_enter(&domp->lock);
		domp->refcnt++;
		ASSERT(domp->devlist != NULL);
		pm_lock_power_single(domp->devlist->dip);
		/* domain lock remains held */
		return;
	} else if (reqp->request_type == PMR_PPM_UNLOCK_POWER) {
		ASSERT(MUTEX_HELD(&domp->lock));
		ASSERT(domp->devlist != NULL);
		pm_unlock_power_single(domp->devlist->dip);
		if (--domp->refcnt == 0)
			mutex_exit(&domp->lock);
		return;
	}

	ASSERT(reqp->request_type == PMR_PPM_TRY_LOCK_POWER);
	if (!MUTEX_HELD(&domp->lock))
		if (!mutex_tryenter(&domp->lock)) {
			*iresp = 0;
			return;
		}
	*iresp = pm_try_locking_power_single(domp->devlist->dip);
	if (*iresp)
		domp->refcnt++;
	else
		mutex_exit(&domp->lock);
}


/*
 * return FALSE: if any detached device during its previous life exported
 *   the "no-involuntary-power-cycles" property and detached with its
 *   power level not at its lowest, or there is a device in the process
 *   of being installed/attached; if a PCI domain has devices that have not
 *   exported a property that it can tolerate clock off while bus is not
 *   quiescent; if a 66mhz PCI domain has devices that do not support stopping
 *   clock at D3; either one would count as a power holder.
 * return TRUE: otherwise.
 */
boolean_t
ppm_none_else_holds_power(ppm_domain_t *domp)
{
	ppm_dev_t  *ppmd;
	ppm_owned_t *owned;
	int	i = 0;

	if (PPMD_IS_PCI(domp->model)) {
		for (ppmd = domp->devlist; ppmd; ppmd = ppmd->next) {
			if ((domp->model == PPMD_PCI_PROP) &&
			    !(ppmd->flags & PPMDEV_PCI_PROP_CLKPM))
				return (B_FALSE);
			if ((domp->dflags & PPMD_PCI66MHZ) &&
			    !(ppmd->flags & PPMDEV_PCI66_D2))
				return (B_FALSE);
		}
	}

	for (owned = domp->owned; owned; owned = owned->next)
		if (pm_noinvol_detached(owned->path) || owned->initializing)
			i++;
	return (i == 0);
}


/*
 * return the number of char 'c' occurrences in string s
 */
int
ppm_count_char(char *s, char c)
{
	int	i = 0;
	char	*cp = s;

	while (*cp) {
		if (*cp == c)
			i++;
		cp++;
	}

	return (i);
}


/*
 * extract and convert a substring from input string "ss" in form of
 * "name=value" into an hex or decimal integer
 */
#define	X_BASE	16
#define	D_BASE	10
int
ppm_stoi(char *ss, uint_t *val)
{
	char *cp;
	int  hex_ = 0, base = D_BASE;
	int  digit;

	if ((cp = strchr(ss, '=')) == NULL) {
		*val = UINT_MAX;
		return (-1);
	}

	cp++;
	if ((*cp == '0') && (*++cp == 'x')) {
		hex_++;
		cp++;
		base = X_BASE;
	}

	for (digit = 0; *cp; cp++) {
		if (hex_ && ((*cp >= 'A') && (*cp <= 'F')))
			digit = (digit * base) + ((*cp - 'A') + D_BASE);
		else if (hex_ && ((*cp >= 'a') && (*cp <= 'f')))
			digit = (digit * base) + ((*cp - 'a') + D_BASE);
		else
			digit = (digit * base) + (*cp - '0');
	}

	return (*val = digit);
}

/*
 * ppm_convert - convert a #define symbol to its integer value,
 * only the #defines for ppm_dc.cmd and ppm_dc.method fields in
 * ppmvar.h file are recognized.
 */
struct ppm_confdefs {
	char	*sym;
	int	val;
} ppm_confdefs_table[] = {
	"ENTER_S3", PPMDC_ENTER_S3,
	"EXIT_S3", PPMDC_EXIT_S3,
	"CPU_NEXT", PPMDC_CPU_NEXT,
	"PRE_CHNG", PPMDC_PRE_CHNG,
	"CPU_GO", PPMDC_CPU_GO,
	"POST_CHNG", PPMDC_POST_CHNG,
	"FET_ON", PPMDC_FET_ON,
	"FET_OFF", PPMDC_FET_OFF,
	"CLK_OFF", PPMDC_CLK_OFF,
	"CLK_ON", PPMDC_CLK_ON,
	"LED_ON", PPMDC_LED_ON,
	"LED_OFF", PPMDC_LED_OFF,
	"KIO", PPMDC_KIO,
	"VCORE", PPMDC_VCORE,
#ifdef sun4u
	"I2CKIO", PPMDC_I2CKIO,
#endif
	"CPUSPEEDKIO", PPMDC_CPUSPEEDKIO,
	"PRE_PWR_OFF", PPMDC_PRE_PWR_OFF,
	"PRE_PWR_ON", PPMDC_PRE_PWR_ON,
	"POST_PWR_ON", PPMDC_POST_PWR_ON,
	"PWR_OFF", PPMDC_PWR_OFF,
	"PWR_ON", PPMDC_PWR_ON,
	"RESET_OFF", PPMDC_RESET_OFF,
	"RESET_ON", PPMDC_RESET_ON,
	NULL
};


/*
 * convert a #define'd symbol to its integer value where
 * input "symbol" is expected to be in form of "SYMBOL=value"
 */
int
ppm_convert(char *symbol, uint_t *val)
{
	char *s;
	struct ppm_confdefs *pcfp;

	*val = UINT_MAX;
	if ((s = strchr(symbol, '=')) == NULL) {
		cmn_err(CE_WARN, "ppm_convert: token \"%s\" syntax error in "
		    "ppm.conf file", symbol);
		return (-1);
	}
	s++;

	for (pcfp = ppm_confdefs_table; (pcfp->sym != NULL); pcfp++) {
		if (strcmp(s, pcfp->sym) == 0)
			return (*val = pcfp->val);
	}

	cmn_err(CE_WARN, "ppm_convert: Unrecognizable token \"%s\" "
	    "in ppm.conf file", symbol);
	return (-1);
}


/*
 * parse a domain control property string into data structure struct ppm_dc
 */
int
ppm_parse_dc(char **dc_namep, ppm_dc_t *dc)
{
	char	*str = "ppm_parse_dc";
	char	*line;
	char	*f, *b;
	char    **dclist;	/* list of ppm_dc_t fields */
	int	count;		/* the # of '=' indicates the # of items */
	size_t	len;		/* length of line being parsed */
	boolean_t done;
	int	i;
	int	err;

	len = strlen(*dc_namep);
	line = kmem_alloc(len + 1, KM_SLEEP);
	(void) strcpy(line, *dc_namep);

	count = ppm_count_char(line, '=');
	ASSERT((count - ppm_count_char(line, ' ')) == 1);

	dclist = (char **)
	    kmem_zalloc((sizeof (char *) * (count + 1)), KM_SLEEP);
	for (i = 0, f = b = line, done = B_FALSE; !done; i++, f = ++b) {
		while (*b != ' ' && *b != 0)
			b++;
		if (*b == 0)
			done = B_TRUE;
		else
			*b = 0;
		dclist[i] = f;
	}

	for (i = 0; i < count; i++) {
		if (strstr(dclist[i], "cmd=")) {
			err = ppm_convert(dclist[i], &dc->cmd);
			if (err == -1)
				return (err);
			continue;
		}
		if ((f = strstr(dclist[i], "path=")) != NULL) {
			f += strlen("path=");
			dc->path = kmem_zalloc((strlen(f) + 1), KM_SLEEP);
			(void) strcpy(dc->path, f);
			continue;
		}
		if (strstr(dclist[i], "method=")) {
			err = ppm_convert(dclist[i], &dc->method);
			if (err == -1)
				return (err);
			continue;
		}
		if (strstr(dclist[i], "iowr=")) {
			(void) ppm_stoi(dclist[i], &dc->m_un.kio.iowr);
			continue;
		}
		if (strstr(dclist[i], "iord=")) {
			(void) ppm_stoi(dclist[i], &dc->m_un.kio.iord);
			continue;
		}
		if (strstr(dclist[i], "val=")) {
			(void) ppm_stoi(dclist[i], &dc->m_un.kio.val);
			continue;
		}
		if (strstr(dclist[i], "speeds=")) {
			ASSERT(dc->method == PPMDC_CPUSPEEDKIO);
			(void) ppm_stoi(dclist[i], &dc->m_un.cpu.speeds);
			continue;
		}
#ifdef sun4u
		if (strstr(dclist[i], "mask=")) {
			(void) ppm_stoi(dclist[i], &dc->m_un.i2c.mask);
			continue;
		}
#endif
		/* This must be before the if statement for delay */
		if (strstr(dclist[i], "post_delay=")) {
#ifdef sun4u
			ASSERT(dc->method == PPMDC_KIO ||
			    dc->method == PPMDC_I2CKIO);
#else
			ASSERT(dc->method == PPMDC_KIO);
#endif
			/*
			 * all delays are uint_t type instead of clock_t.
			 * If the delay is too long, it might get truncated.
			 * But, we don't expect delay to be too long.
			 */
			switch (dc->method) {
			case PPMDC_KIO:
				(void) ppm_stoi(dclist[i],
				    &dc->m_un.kio.post_delay);
				break;

#ifdef sun4u
			case PPMDC_I2CKIO:
				(void) ppm_stoi(dclist[i],
				    &dc->m_un.i2c.post_delay);
				break;
#endif

			default:
				break;
			}
			continue;
		}
		if (strstr(dclist[i], "delay=")) {
#ifdef sun4u
			ASSERT(dc->method == PPMDC_VCORE ||
			    dc->method == PPMDC_KIO ||
			    dc->method == PPMDC_I2CKIO);
#else
			ASSERT(dc->method == PPMDC_VCORE ||
			    dc->method == PPMDC_KIO);
#endif

			/*
			 * all delays are uint_t type instead of clock_t.
			 * If the delay is too long, it might get truncated.
			 * But, we don't expect delay to be too long.
			 */

			switch (dc->method) {
			case PPMDC_KIO:
				(void) ppm_stoi(dclist[i], &dc->m_un.kio.delay);
				break;

#ifdef sun4u
			case PPMDC_I2CKIO:
				(void) ppm_stoi(dclist[i], &dc->m_un.i2c.delay);
				break;
#endif

			case PPMDC_VCORE:
				(void) ppm_stoi(dclist[i], &dc->m_un.cpu.delay);
				break;

			default:
				break;
			}
			continue;
		}

		/* we encounted unrecognized field, flag error */
		cmn_err(CE_WARN, "%s: Unrecognized token \"%s\" in ppm.conf "
		    "file!", str, dclist[i]);
		return (-1);
	}

	kmem_free(dclist, sizeof (char *) * (count + 1));
	kmem_free(line, len + 1);

	return (DDI_SUCCESS);
}


/*
 * search for domain control handle for a claimed device coupled with a
 * domain control command.  NULL device may indicate LED domain.
 */
ppm_dc_t *
ppm_lookup_dc(ppm_domain_t *domp, int cmd)
{
#ifdef	DEBUG
	char *str = "ppm_lookup_dc";
#endif
	ppm_dc_t	*dc;

	/*
	 *  For convenience, we accept 'domp' as NULL for searching
	 *  LED domain control operation.
	 */
	if ((cmd == PPMDC_LED_OFF) || (cmd == PPMDC_LED_ON)) {
		for (domp = ppm_domain_p; domp; domp = domp->next)
			if (domp->model == PPMD_LED)
				break;
		if (!domp || !domp->dc || !domp->dc->lh || !domp->dc->next) {
			PPMD(D_LED, ("\tinsufficient led domain control "
			    "information.\n"))
			return (NULL);
		}
		if (cmd == domp->dc->cmd)
			return (domp->dc);
		else
			return (domp->dc->next);
	}


	/*
	 * for the rest of ppm domains, lookup ppm_dc starting from domp
	 */
	ASSERT(domp != NULL);
	switch (cmd) {
	case PPMDC_CPU_NEXT:
	case PPMDC_PRE_CHNG:
	case PPMDC_CPU_GO:
	case PPMDC_POST_CHNG:
	case PPMDC_FET_OFF:
	case PPMDC_FET_ON:
	case PPMDC_CLK_OFF:
	case PPMDC_CLK_ON:
	case PPMDC_PRE_PWR_OFF:
	case PPMDC_PRE_PWR_ON:
	case PPMDC_POST_PWR_ON:
	case PPMDC_PWR_OFF:
	case PPMDC_PWR_ON:
	case PPMDC_RESET_OFF:
	case PPMDC_RESET_ON:
	case PPMDC_ENTER_S3:
	case PPMDC_EXIT_S3:
		break;
	default:
		PPMD(D_PPMDC, ("%s: cmd(%d) unrecognized\n", str, cmd))
		return (NULL);
	}

	for (dc = domp->dc; dc; dc = dc->next) {
		if (dc->cmd == cmd) {
			return (dc);
		}
	}

	return (NULL);
}

#include <sys/esunddi.h>

ppm_domain_t *
ppm_get_domain_by_dev(const char *p)
{
	dev_info_t *dip;
	ppm_domain_t	*domp;
	ppm_dev_t	*pdev;
	boolean_t	found = B_FALSE;

	if ((dip = e_ddi_hold_devi_by_path((char *)p, 0)) == NULL)
		return (NULL);

	for (domp = ppm_domain_p; domp; domp = domp->next) {
		for (pdev = domp->devlist; pdev; pdev = pdev->next) {
			if (pdev->dip == dip) {
				found = B_TRUE;
				break;
			}
		}
		if (found)
			break;
	}
	ddi_release_devi(dip);
	return (domp);
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
		FLINTSTR(D_CTLOPS2, PMR_PPM_INIT_CHILD),
		FLINTSTR(D_CTLOPS2, PMR_PPM_UNINIT_CHILD),
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
		FLINTSTR(D_LOCKS, PMR_PPM_POWER_LOCK_OWNER),
		FLINTSTR(D_CTLOPS1 | D_CTLOPS2, PMR_PPM_ENTER_SX),
		FLINTSTR(D_CTLOPS1 | D_CTLOPS2, PMR_UNKNOWN),
	};

	for (ccp = cmds; ccp->ctlop != PMR_UNKNOWN; ccp++)
		if (ctlop == ccp->ctlop)
			break;

	if (ccp->flags & mask)
		return (ccp->str);
	return (NULL);
}

void
ppm_print_dc(ppm_dc_t *dc)
{
	ppm_dc_t	*d = dc;

	PPMD(D_PPMDC, ("\nAdds ppm_dc: path(%s),\n     cmd(%x), "
	    "method(%x), ", d->path, d->cmd, d->method))
	if (d->method == PPMDC_KIO) {
		PPMD(D_PPMDC, ("kio.iowr(%x), kio.val(0x%X)",
		    d->m_un.kio.iowr, d->m_un.kio.val))
#ifdef sun4u
	} else if (d->method == PPMDC_I2CKIO) {
		PPMD(D_PPMDC, ("i2c.iowr(%x), i2c.val(0x%X), "
		    "i2c.mask(0x%X)", d->m_un.i2c.iowr,
		    d->m_un.i2c.val,  d->m_un.i2c.mask))
#endif
	} else if (d->method == PPMDC_VCORE) {
		PPMD(D_PPMDC, ("cpu: .iord(%x), .iowr(%x), .val(0x%X), "
		    ".delay(0x%x)",
		    d->m_un.cpu.iord, d->m_un.cpu.iowr, d->m_un.cpu.val,
		    d->m_un.cpu.delay))
	} else if (d->method == PPMDC_CPUSPEEDKIO) {
		PPMD(D_PPMDC, ("cpu.iowr(%x), cpu.speeds(0x%X)",
		    d->m_un.cpu.iowr, d->m_un.cpu.speeds))
	}
	PPMD(D_PPMDC, ("\n"))
}
#endif	/* DEBUG */
