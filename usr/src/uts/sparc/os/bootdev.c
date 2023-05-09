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
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/systm.h>
#include <sys/pathname.h>
#include <sys/modctl.h>
#include <sys/sunndi.h>
#include <sys/sunmdi.h>
#include <sys/mdi_impldefs.h>
#include <sys/promif.h>

struct parinfo {
	dev_info_t *dip;
	dev_info_t *pdip;
};

/*
 * internal functions
 */
static int resolve_devfs_name(char *, char *);
static dev_info_t *find_alternate_node(dev_info_t *, major_t);
static dev_info_t *get_parent(dev_info_t *, struct parinfo *);
static int i_devi_to_promname(dev_info_t *, char *, dev_info_t **alt_dipp);

/* internal global data */
static struct modlmisc modlmisc = {
	&mod_miscops, "bootdev misc module 1.22"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

int
_init()
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * convert a prom device path to an equivalent path in /devices
 * Does not deal with aliases.  Does deal with pathnames which
 * are not fully qualified.  This routine is generalized
 * to work across several flavors of OBP
 */
int
i_promname_to_devname(char *prom_name, char *ret_buf)
{
	if (prom_name == NULL || ret_buf == NULL ||
	    (strlen(prom_name) >= MAXPATHLEN)) {
		return (EINVAL);
	}
	if (i_ddi_prompath_to_devfspath(prom_name, ret_buf) != DDI_SUCCESS)
		return (EINVAL);

	return (0);
}

/*
 * The function is to get prom name according non-client dip node.
 * And the function will set the alternate node of dip to alt_dip
 * if it is exist which must be PROM node.
 */
static int
i_devi_to_promname(dev_info_t *dip, char *prom_path, dev_info_t **alt_dipp)
{
	dev_info_t *pdip, *cdip, *idip;
	char *unit_address, *nodename;
	major_t major;
	int depth, old_depth = 0;
	struct parinfo *parinfo = NULL;
	struct parinfo *info;
	int ret = 0;

	if (MDI_CLIENT(dip))
		return (EINVAL);

	if (ddi_pathname_obp(dip, prom_path) != NULL) {
		return (0);
	}
	/*
	 * ddi_pathname_obp return NULL, but the obp path still could
	 * be different with the devfs path name, so need use a parents
	 * stack to compose the path name string layer by layer.
	 */

	/* find the closest ancestor which is a prom node */
	pdip = dip;
	parinfo = kmem_alloc(OBP_STACKDEPTH * sizeof (*parinfo),
	    KM_SLEEP);
	for (depth = 0; ndi_dev_is_prom_node(pdip) == 0; depth++) {
		if (depth == OBP_STACKDEPTH) {
			ret = EINVAL;
			/* must not have been an obp node */
			goto out;
		}
		pdip = get_parent(pdip, &parinfo[depth]);
	}
	old_depth = depth;
	ASSERT(pdip);	/* at least root is prom node */
	if (pdip)
		(void) ddi_pathname(pdip, prom_path);

	ndi_hold_devi(pdip);

	for (depth = old_depth; depth > 0; depth--) {
		info = &parinfo[depth - 1];
		idip = info->dip;
		nodename = ddi_node_name(idip);
		unit_address = ddi_get_name_addr(idip);

		if (pdip) {
			major = ddi_driver_major(idip);
			cdip = find_alternate_node(pdip, major);
			ndi_rele_devi(pdip);
			if (cdip) {
				nodename = ddi_node_name(cdip);
			}
		}

		/*
		 * node name + unitaddr to the prom_path
		 */
		(void) strcat(prom_path, "/");
		(void) strcat(prom_path, nodename);
		if (unit_address && (*unit_address)) {
			(void) strcat(prom_path, "@");
			(void) strcat(prom_path, unit_address);
		}
		pdip = cdip;
	}

	if (pdip) {
		ndi_rele_devi(pdip); /* hold from find_alternate_node */
	}
	/*
	 * Now pdip is the alternate node which is same hierarchy as dip
	 * if it exists.
	 */
	*alt_dipp = pdip;
out:
	if (parinfo) {
		/* release holds from get_parent() */
		for (depth = old_depth; depth > 0; depth--) {
			info = &parinfo[depth - 1];
			if (info && info->pdip)
				ndi_rele_devi(info->pdip);
		}
		kmem_free(parinfo, OBP_STACKDEPTH * sizeof (*parinfo));
	}
	return (ret);
}

/*
 * translate a devfs pathname to one that will be acceptable
 * by the prom.  In most cases, there is no translation needed.
 * For systems supporting generically named devices, the prom
 * may support nodes such as 'disk' that do not have any unit
 * address information (i.e. target,lun info).  If this is the
 * case, the ddi framework will reject the node as invalid and
 * populate the devinfo tree with nodes froms the .conf file
 * (e.g. sd).  In this case, the names that show up in /devices
 * are sd - since the prom only knows about 'disk' nodes, this
 * routine detects this situation and does the conversion
 * There are also cases such as pluto where the disk node in the
 * prom is named "SUNW,ssd" but in /devices the name is "ssd".
 *
 * If MPxIO is enabled, the translation involves following
 * pathinfo nodes to the "best" parent.
 *
 * return a 0 on success with the new device string in ret_buf.
 * Otherwise return the appropriate error code as we may be called
 * from the openprom driver.
 */
int
i_devname_to_promname(char *dev_name, char *ret_buf, size_t len)
{
	dev_info_t *dip, *pdip, *cdip, *alt_dip = NULL;
	mdi_pathinfo_t *pip = NULL;
	char *dev_path, *prom_path;
	char *unit_address, *minorname, *nodename;
	major_t major;
	char *rptr, *optr, *offline;
	size_t olen, rlen;
	int ret = 0;

	/* do some sanity checks */
	if ((dev_name == NULL) || (ret_buf == NULL) ||
	    (strlen(dev_name) > MAXPATHLEN)) {
		return (EINVAL);
	}

	/*
	 * Convert to a /devices name. Fail the translation if
	 * the name doesn't exist.
	 */
	dev_path = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	if (resolve_devfs_name(dev_name, dev_path) != 0 ||
	    strncmp(dev_path, "/devices/", 9) != 0) {
		kmem_free(dev_path, MAXPATHLEN);
		return (EINVAL);
	}
	dev_name = dev_path + sizeof ("/devices") - 1;

	bzero(ret_buf, len);

	if (prom_finddevice(dev_name) != OBP_BADNODE) {
		/* we are done */
		(void) snprintf(ret_buf, len, "%s", dev_name);
		kmem_free(dev_path, MAXPATHLEN);
		return (0);
	}

	/*
	 * if we get here, then some portion of the device path is
	 * not understood by the prom.  We need to look for alternate
	 * names (e.g. replace ssd by disk) and mpxio enabled devices.
	 */
	dip = e_ddi_hold_devi_by_path(dev_name, 0);
	if (dip == NULL) {
		cmn_err(CE_NOTE, "cannot find dip for %s", dev_name);
		kmem_free(dev_path, MAXPATHLEN);
		return (EINVAL);
	}

	prom_path = kmem_zalloc(MAXPATHLEN, KM_SLEEP);
	rlen = len;
	rptr = ret_buf;

	if (!MDI_CLIENT(dip)) {
		ret = i_devi_to_promname(dip, prom_path, &alt_dip);
		if (ret == 0) {
			minorname = strrchr(dev_name, ':');
			if (minorname && (minorname[1] != '\0')) {
				(void) strcat(prom_path, minorname);
			}
			(void) snprintf(rptr, rlen, "%s", prom_path);
		}
	} else {
		/*
		 * if get to here, means dip is a vhci client
		 */
		offline = kmem_zalloc(len, KM_SLEEP); /* offline paths */
		olen = len;
		optr = offline;
		/*
		 * The following code assumes that the phci client is at leaf
		 * level.
		 */
		ndi_devi_enter(dip);
		while ((pip = mdi_get_next_phci_path(dip, pip)) != NULL) {
			/*
			 * walk all paths associated to the client node
			 */
			bzero(prom_path, MAXPATHLEN);

			/*
			 * replace with mdi_hold_path() when mpxio goes into
			 * genunix
			 */
			MDI_PI_LOCK(pip);
			MDI_PI_HOLD(pip);
			MDI_PI_UNLOCK(pip);

			if (mdi_pi_pathname_obp(pip, prom_path) != NULL) {
				/*
				 * The path has different obp path
				 */
				goto minor_pathinfo;
			}

			pdip = mdi_pi_get_phci(pip);
			ndi_hold_devi(pdip);

			/*
			 * Get obp path name of the phci node firstly.
			 * NOTE: if the alternate node of pdip exists,
			 * the third argument of the i_devi_to_promname()
			 * would be set to the alternate node.
			 */
			(void) i_devi_to_promname(pdip, prom_path, &alt_dip);
			if (alt_dip != NULL) {
				ndi_rele_devi(pdip);
				pdip = alt_dip;
				ndi_hold_devi(pdip);
			}

			nodename = ddi_node_name(dip);
			unit_address = MDI_PI(pip)->pi_addr;

			major = ddi_driver_major(dip);
			cdip = find_alternate_node(pdip, major);

			if (cdip) {
				nodename = ddi_node_name(cdip);
			}
			/*
			 * node name + unitaddr to the prom_path
			 */
			(void) strcat(prom_path, "/");
			(void) strcat(prom_path, nodename);
			if (unit_address && (*unit_address)) {
				(void) strcat(prom_path, "@");
				(void) strcat(prom_path, unit_address);
			}
			if (cdip) {
				/* hold from find_alternate_node */
				ndi_rele_devi(cdip);
			}
			ndi_rele_devi(pdip);
minor_pathinfo:
			minorname = strrchr(dev_name, ':');
			if (minorname && (minorname[1] != '\0')) {
				(void) strcat(prom_path, minorname);
			}

			if (MDI_PI_IS_ONLINE(pip)) {
				(void) snprintf(rptr, rlen, "%s", prom_path);
				rlen -= strlen(rptr) + 1;
				rptr += strlen(rptr) + 1;
				if (rlen <= 0) /* drop paths we can't store */
					break;
			} else {	/* path is offline */
				(void) snprintf(optr, olen, "%s", prom_path);
				olen -= strlen(optr) + 1;
				if (olen > 0) /* drop paths we can't store */
					optr += strlen(optr) + 1;
			}
			MDI_PI_LOCK(pip);
			MDI_PI_RELE(pip);
			if (MDI_PI(pip)->pi_ref_cnt == 0)
				cv_broadcast(&MDI_PI(pip)->pi_ref_cv);
			MDI_PI_UNLOCK(pip);
		}
		ndi_devi_exit(dip);
		ret = 0;
		if (rlen > 0) {
			/* now add as much of offline to ret_buf as possible */
			bcopy(offline, rptr, rlen);
		}
		kmem_free(offline, len);
	}
	/* release hold from e_ddi_hold_devi_by_path() */
	ndi_rele_devi(dip);
	ret_buf[len - 1] = '\0';
	ret_buf[len - 2] = '\0';
	kmem_free(dev_path, MAXPATHLEN);
	kmem_free(prom_path, MAXPATHLEN);

	return (ret);
}

/*
 * check for a possible substitute node.  This routine searches the
 * children of parent_dip, looking for a node that:
 *	1. is a prom node
 *	2. binds to the same major number
 *	3. there is no need to verify that the unit-address information
 *		match since it is likely that the substitute node
 *		will have none (e.g. disk) - this would be the reason the
 *		framework rejected it in the first place.
 *
 * assumes parent_dip is held
 */
static dev_info_t *
find_alternate_node(dev_info_t *parent_dip, major_t major)
{
	dev_info_t *child_dip;

	/* lock down parent to keep children from being removed */
	ndi_devi_enter(parent_dip);
	for (child_dip = ddi_get_child(parent_dip); child_dip != NULL;
	    child_dip = ddi_get_next_sibling(child_dip)) {

		/* look for obp node with matching major */
		if ((ndi_dev_is_prom_node(child_dip) != 0) &&
		    (ddi_driver_major(child_dip) == major)) {
			ndi_hold_devi(child_dip);
			break;
		}
	}
	ndi_devi_exit(parent_dip);
	return (child_dip);
}

/*
 * given an absolute pathname, convert it, if possible, to a devfs
 * name.  Examples:
 * /dev/rsd3a to /pci@1f,4000/glm@3/sd@0,0:a
 * /dev/dsk/c0t0d0s0 to /pci@1f,4000/glm@3/sd@0,0:a
 * /devices/pci@1f,4000/glm@3/sd@0,0:a to /pci@1f,4000/glm@3/sd@0,0:a
 * /pci@1f,4000/glm@3/sd@0,0:a unchanged
 *
 * This routine deals with symbolic links, physical pathname with and
 * without /devices stripped. Returns 0 on success or -1 on failure.
 */
static int
resolve_devfs_name(char *name, char *buffer)
{
	int error;
	char *fullname = NULL;
	struct pathname pn, rpn;

	/* if not a /dev or /device name, prepend /devices */
	if (strncmp(name, "/dev/", 5) != 0 &&
	    strncmp(name, "/devices/", 9) != 0) {
		fullname = kmem_alloc(MAXPATHLEN, KM_SLEEP);
		(void) snprintf(fullname, MAXPATHLEN, "/devices%s", name);
		name = fullname;
	}

	if (pn_get(name, UIO_SYSSPACE, &pn) != 0) {
		if (fullname)
			kmem_free(fullname, MAXPATHLEN);
		return (-1);
	}

	pn_alloc(&rpn);
	error = lookuppn(&pn, &rpn, FOLLOW, NULL, NULL);
	if (error == 0)
		bcopy(rpn.pn_path, buffer, rpn.pn_pathlen);

	pn_free(&pn);
	pn_free(&rpn);
	if (fullname)
		kmem_free(fullname, MAXPATHLEN);

	return (error);
}

/*
 * If bootstring contains a device path, we need to convert to a format
 * the prom will understand.  To do so, we convert the existing path to
 * a prom-compatible path and return the value of new_path.  If the
 * caller specifies new_path as NULL, we allocate an appropriately
 * sized new_path on behalf of the caller.  If the caller invokes this
 * function with new_path = NULL, they must do so from a context in
 * which it is safe to perform a sleeping memory allocation.
 */
char *
i_convert_boot_device_name(char *cur_path, char *new_path, size_t *len)
{
	char *ptr;
	int rval;

	ASSERT(cur_path != NULL && len != NULL);
	ASSERT(new_path == NULL || *len >= MAXPATHLEN);

	if (new_path == NULL) {
		*len = MAXPATHLEN + MAXNAMELEN;
		new_path = kmem_alloc(*len, KM_SLEEP);
	}

	if ((ptr = strchr(cur_path, ' ')) != NULL)
		*ptr = '\0';

	rval = i_devname_to_promname(cur_path, new_path, *len);

	if (ptr != NULL)
		*ptr = ' ';

	if (rval == 0) {
		if (ptr != NULL) {
			(void) snprintf(new_path + strlen(new_path),
			    *len - strlen(new_path), "%s", ptr);
		}
	} else {		/* the conversion failed */
		(void) snprintf(new_path, *len, "%s", cur_path);
	}

	return (new_path);
}

/*
 * Get the parent dip.
 */
static dev_info_t *
get_parent(dev_info_t *dip, struct parinfo *info)
{
	dev_info_t *pdip;

	pdip = ddi_get_parent(dip);
	ndi_hold_devi(pdip);
	info->dip = dip;
	info->pdip = pdip;
	return (pdip);
}
