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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Ported from 4.1.1_PSRA: "@(#)openprom.c 1.19 91/02/19 SMI";
 *
 * Porting notes:
 *
 * OPROMU2P unsupported after SunOS 4.x.
 *
 * Only one of these devices per system is allowed.
 */

/*
 * Openprom eeprom options/devinfo driver.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/openpromio.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/autoconf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/promif.h>
#include <sys/sysmacros.h>	/* offsetof */
#include <sys/nvpair.h>
#include <sys/zone.h>
#include <sys/consplat.h>
#include <sys/bootconf.h>
#include <sys/systm.h>
#include <sys/bootprops.h>

#define	MAX_OPENS	32	/* Up to this many simultaneous opens */

#define	IOC_IDLE	0	/* snapshot ioctl states */
#define	IOC_SNAP	1	/* snapshot in progress */
#define	IOC_DONE	2	/* snapshot done, but not copied out */
#define	IOC_COPY	3	/* copyout in progress */

/*
 * XXX	Make this dynamic.. or (better still) make the interface stateless
 */
static struct oprom_state {
	pnode_t	current_id;	/* node we're fetching props from */
	int16_t	already_open;	/* if true, this instance is 'active' */
	int16_t	ioc_state;	/* snapshot ioctl state */
	char	*snapshot;	/* snapshot of all prom nodes */
	size_t	size;		/* size of snapshot */
	prom_generation_cookie_t tree_gen;
} oprom_state[MAX_OPENS];

static kmutex_t oprom_lock;	/* serialize instance assignment */

static int opromopen(dev_t *, int, int, cred_t *);
static int opromioctl(dev_t, int, intptr_t, int, cred_t *, int *);
static int opromclose(dev_t, int, int, cred_t *);

static int opinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int opattach(dev_info_t *, ddi_attach_cmd_t cmd);
static int opdetach(dev_info_t *, ddi_detach_cmd_t cmd);

/* help functions */
static int oprom_checknodeid(pnode_t, pnode_t);
static int oprom_copyinstr(intptr_t, char *, size_t, size_t);
static int oprom_copynode(pnode_t, uint_t, char **, size_t *);
static int oprom_snapshot(struct oprom_state *, intptr_t);
static int oprom_copyout(struct oprom_state *, intptr_t);
static int oprom_setstate(struct oprom_state *, int16_t);

static struct cb_ops openeepr_cb_ops = {
	opromopen,		/* open */
	opromclose,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	opromioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* streamtab  */
	D_NEW | D_MP		/* Driver compatibility flag */
};

static struct dev_ops openeepr_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	opinfo,			/* info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	opattach,		/* attach */
	opdetach,		/* detach */
	nodev,			/* reset */
	&openeepr_cb_ops,	/* driver operations */
	NULL,			/* bus operations */
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,
	"OPENPROM/NVRAM Driver",
	&openeepr_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int	error;

	mutex_init(&oprom_lock, NULL, MUTEX_DRIVER, NULL);

	error = mod_install(&modlinkage);
	if (error != 0) {
		mutex_destroy(&oprom_lock);
		return (error);
	}

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int	error;

	error = mod_remove(&modlinkage);
	if (error != 0)
		return (error);

	mutex_destroy(&oprom_lock);
	return (0);
}

static dev_info_t *opdip;
static pnode_t options_nodeid;

/*ARGSUSED*/
static int
opinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error = DDI_FAILURE;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)opdip;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		/* All dev_t's map to the same, single instance */
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		break;
	}

	return (error);
}

static int
opattach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {

	case DDI_ATTACH:
		if (prom_is_openprom()) {
			options_nodeid = prom_optionsnode();
		} else {
			options_nodeid = OBP_BADNODE;
		}

		opdip = dip;

		if (ddi_create_minor_node(dip, "openprom", S_IFCHR,
		    0, DDI_PSEUDO, NULL) == DDI_FAILURE) {
			return (DDI_FAILURE);
		}

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static int
opdetach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ddi_remove_minor_node(dip, NULL);
	opdip = NULL;

	return (DDI_SUCCESS);
}

/*
 * Allow multiple opens by tweaking the dev_t such that it looks like each
 * open is getting a different minor device.  Each minor gets a separate
 * entry in the oprom_state[] table.
 */
/*ARGSUSED*/
static int
opromopen(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	int m;
	struct oprom_state *st = oprom_state;

	if (getminor(*devp) != 0)
		return (ENXIO);

	mutex_enter(&oprom_lock);
	for (m = 0; m < MAX_OPENS; m++)
		if (st->already_open)
			st++;
		else {
			st->already_open = 1;
			/*
			 * It's ours.
			 */
			st->current_id = (pnode_t)0;
			ASSERT(st->snapshot == NULL && st->size == 0);
			ASSERT(st->ioc_state == IOC_IDLE);
			break;
		}
	mutex_exit(&oprom_lock);

	if (m == MAX_OPENS)  {
		/*
		 * "Thank you for calling, but all our lines are
		 * busy at the moment.."
		 *
		 * We could get sophisticated here, and go into a
		 * sleep-retry loop .. but hey, I just can't see
		 * that many processes sitting in this driver.
		 *
		 * (And if it does become possible, then we should
		 * change the interface so that the 'state' is held
		 * external to the driver)
		 */
		return (EAGAIN);
	}

	*devp = makedevice(getmajor(*devp), (minor_t)m);

	return (0);
}

/*ARGSUSED*/
static int
opromclose(dev_t dev, int flag, int otype, cred_t *cred_p)
{
	struct oprom_state *st;

	st = &oprom_state[getminor(dev)];
	ASSERT(getminor(dev) < MAX_OPENS && st->already_open != 0);
	if (st->snapshot) {
		kmem_free(st->snapshot, st->size);
		st->snapshot = NULL;
		st->size = 0;
		st->ioc_state = IOC_IDLE;
	}
	mutex_enter(&oprom_lock);
	st->already_open = 0;
	mutex_exit(&oprom_lock);

	return (0);
}

#ifdef __sparc
static int
get_bootpath_prop(char *bootpath)
{
	if (root_is_ramdisk) {
		if (BOP_GETPROP(bootops, "bootarchive", bootpath) == -1)
			return (-1);
		(void) strlcat(bootpath, ":a", BO_MAXOBJNAME);
	} else {
		if ((BOP_GETPROP(bootops, "bootpath", bootpath) == -1) ||
		    strlen(bootpath) == 0) {
			if (BOP_GETPROP(bootops,
			    "boot-path", bootpath) == -1)
				return (-1);
		}
		if (memcmp(bootpath, BP_ISCSI_DISK,
		    strlen(BP_ISCSI_DISK)) == 0) {
			get_iscsi_bootpath_vhci(bootpath);
		}
	}
	return (0);
}
#endif

struct opromioctl_args {
	struct oprom_state *st;
	int cmd;
	intptr_t arg;
	int mode;
};

/*ARGSUSED*/
static int
opromioctl_cb(void *avp, int has_changed)
{
	struct opromioctl_args *argp = avp;
	int cmd;
	intptr_t arg;
	int mode;
	struct oprom_state *st;
	struct openpromio *opp;
	int valsize;
	char *valbuf;
	int error = 0;
	uint_t userbufsize;
	pnode_t node_id;
	char propname[OBP_MAXPROPNAME];

	st = argp->st;
	cmd = argp->cmd;
	arg = argp->arg;
	mode = argp->mode;

	if (has_changed) {
		/*
		 * The prom tree has changed since we last used current_id,
		 * so we need to check it.
		 */
		if ((st->current_id != OBP_NONODE) &&
		    (st->current_id != OBP_BADNODE)) {
			if (oprom_checknodeid(st->current_id, OBP_NONODE) == 0)
				st->current_id = OBP_BADNODE;
		}
	}

	/*
	 * Check permissions
	 * and weed out unsupported commands on x86 platform
	 */
	switch (cmd) {
#if !defined(__i386) && !defined(__amd64)
	case OPROMLISTKEYSLEN:
		valsize = prom_asr_list_keys_len();
		opp = (struct openpromio *)kmem_zalloc(
		    sizeof (uint_t) + 1, KM_SLEEP);
		opp->oprom_size = valsize;
		if (copyout(opp, (void *)arg, (sizeof (uint_t))) != 0)
			error = EFAULT;
		kmem_free(opp, sizeof (uint_t) + 1);
		break;
	case OPROMLISTKEYS:
		valsize = prom_asr_list_keys_len();
		if (copyin((void *)arg, &userbufsize, sizeof (uint_t)) != 0)
			return (EFAULT);
		if (valsize > userbufsize)
			return (EINVAL);
		valbuf = (char *)kmem_zalloc(valsize + 1, KM_SLEEP);
		if (prom_asr_list_keys((caddr_t)valbuf) == -1) {
			kmem_free(valbuf, valsize + 1);
			return (EFAULT);
		}
		opp = (struct openpromio *)kmem_zalloc(
		    valsize + sizeof (uint_t) + 1, KM_SLEEP);
		opp->oprom_size = valsize;
		bcopy(valbuf, opp->oprom_array, valsize);
		if (copyout(opp, (void *)arg, (valsize + sizeof (uint_t))) != 0)
			error = EFAULT;
		kmem_free(valbuf, valsize + 1);
		kmem_free(opp, valsize + sizeof (uint_t) + 1);
		break;
	case OPROMEXPORT:
		valsize = prom_asr_export_len();
		if (copyin((void *)arg, &userbufsize, sizeof (uint_t)) != 0)
			return (EFAULT);
		if (valsize > userbufsize)
			return (EINVAL);
		valbuf = (char *)kmem_zalloc(valsize + 1, KM_SLEEP);
		if (prom_asr_export((caddr_t)valbuf) == -1) {
			kmem_free(valbuf, valsize + 1);
			return (EFAULT);
		}
		opp = (struct openpromio *)kmem_zalloc(
		    valsize + sizeof (uint_t) + 1, KM_SLEEP);
		opp->oprom_size = valsize;
		bcopy(valbuf, opp->oprom_array, valsize);
		if (copyout(opp, (void *)arg, (valsize + sizeof (uint_t))) != 0)
			error = EFAULT;
		kmem_free(valbuf, valsize + 1);
		kmem_free(opp, valsize + sizeof (uint_t) + 1);
		break;
	case OPROMEXPORTLEN:
		valsize = prom_asr_export_len();
		opp = (struct openpromio *)kmem_zalloc(
		    sizeof (uint_t) + 1, KM_SLEEP);
		opp->oprom_size = valsize;
		if (copyout(opp, (void *)arg, (sizeof (uint_t))) != 0)
			error = EFAULT;
		kmem_free(opp, sizeof (uint_t) + 1);
		break;
#endif
	case OPROMGETOPT:
	case OPROMNXTOPT:
		if ((mode & FREAD) == 0) {
			return (EPERM);
		}
		node_id = options_nodeid;
		break;

	case OPROMSETOPT:
	case OPROMSETOPT2:
#if !defined(__i386) && !defined(__amd64)
		if (mode & FWRITE) {
			node_id = options_nodeid;
			break;
		}
#endif /* !__i386 && !__amd64 */
		return (EPERM);

	case OPROMNEXT:
	case OPROMCHILD:
	case OPROMGETPROP:
	case OPROMGETPROPLEN:
	case OPROMNXTPROP:
	case OPROMSETNODEID:
		if ((mode & FREAD) == 0) {
			return (EPERM);
		}
		node_id = st->current_id;
		break;
	case OPROMCOPYOUT:
		if (st->snapshot == NULL)
			return (EINVAL);
		/*FALLTHROUGH*/
	case OPROMSNAPSHOT:
	case OPROMGETCONS:
	case OPROMGETBOOTARGS:
	case OPROMGETBOOTPATH:
	case OPROMGETVERSION:
	case OPROMPATH2DRV:
	case OPROMPROM2DEVNAME:
#if !defined(__i386) && !defined(__amd64)
	case OPROMGETFBNAME:
	case OPROMDEV2PROMNAME:
	case OPROMREADY64:
#endif	/* !__i386 && !__amd64 */
		if ((mode & FREAD) == 0) {
			return (EPERM);
		}
		break;

	default:
		return (EINVAL);
	}

	/*
	 * Deal with SNAPSHOT and COPYOUT ioctls first
	 */
	switch (cmd) {
	case OPROMCOPYOUT:
		return (oprom_copyout(st, arg));

	case OPROMSNAPSHOT:
		return (oprom_snapshot(st, arg));
	}

	/*
	 * Copy in user argument length and allocation memory
	 *
	 * NB do not copyin the entire buffer we may not need
	 *	to. userbufsize can be as big as 32 K.
	 */
	if (copyin((void *)arg, &userbufsize, sizeof (uint_t)) != 0)
		return (EFAULT);

	if (userbufsize == 0 || userbufsize > OPROMMAXPARAM)
		return (EINVAL);

	opp = (struct openpromio *)kmem_zalloc(
	    userbufsize + sizeof (uint_t) + 1, KM_SLEEP);

	/*
	 * Execute command
	 */
	switch (cmd) {

	case OPROMGETOPT:
	case OPROMGETPROP:
	case OPROMGETPROPLEN:

		if ((prom_is_openprom() == 0) ||
		    (node_id == OBP_NONODE) || (node_id == OBP_BADNODE)) {
			error = EINVAL;
			break;
		}

		/*
		 * The argument, a NULL terminated string, is a prop name.
		 */
		if ((error = oprom_copyinstr(arg, opp->oprom_array,
		    (size_t)userbufsize, OBP_MAXPROPNAME)) != 0) {
			break;
		}
		(void) strcpy(propname, opp->oprom_array);
		valsize = prom_getproplen(node_id, propname);

		/*
		 * 4010173: 'name' is a property, but not an option.
		 */
		if ((cmd == OPROMGETOPT) && (strcmp("name", propname) == 0))
			valsize = -1;

		if (cmd == OPROMGETPROPLEN)  {
			int proplen = valsize;

			if (userbufsize < sizeof (int)) {
				error = EINVAL;
				break;
			}
			opp->oprom_size = valsize = sizeof (int);
			bcopy(&proplen, opp->oprom_array, valsize);
		} else if (valsize > 0 && valsize <= userbufsize) {
			bzero(opp->oprom_array, valsize + 1);
			(void) prom_getprop(node_id, propname,
			    opp->oprom_array);
			opp->oprom_size = valsize;
			if (valsize < userbufsize)
				++valsize;	/* Forces NULL termination */
						/* If space permits */
		} else {
			/*
			 * XXX: There is no error code if the buf is too small.
			 * which is consistent with the current behavior.
			 *
			 * NB: This clause also handles the non-error
			 * zero length (boolean) property value case.
			 */
			opp->oprom_size = 0;
			(void) strcpy(opp->oprom_array, "");
			valsize = 1;
		}
		if (copyout(opp, (void *)arg, (valsize + sizeof (uint_t))) != 0)
			error = EFAULT;
		break;

	case OPROMNXTOPT:
	case OPROMNXTPROP:
		if ((prom_is_openprom() == 0) ||
		    (node_id == OBP_NONODE) || (node_id == OBP_BADNODE)) {
			error = EINVAL;
			break;
		}

		/*
		 * The argument, a NULL terminated string, is a prop name.
		 */
		if ((error = oprom_copyinstr(arg, opp->oprom_array,
		    (size_t)userbufsize, OBP_MAXPROPNAME)) != 0) {
			break;
		}
		valbuf = (char *)prom_nextprop(node_id, opp->oprom_array,
		    propname);
		valsize = strlen(valbuf);

		/*
		 * 4010173: 'name' is a property, but it's not an option.
		 */
		if ((cmd == OPROMNXTOPT) && valsize &&
		    (strcmp(valbuf, "name") == 0)) {
			valbuf = (char *)prom_nextprop(node_id, "name",
			    propname);
			valsize = strlen(valbuf);
		}

		if (valsize == 0) {
			opp->oprom_size = 0;
		} else if (++valsize <= userbufsize) {
			opp->oprom_size = valsize;
			bzero((caddr_t)opp->oprom_array, (size_t)valsize);
			bcopy((caddr_t)valbuf, (caddr_t)opp->oprom_array,
			    (size_t)valsize);
		}

		if (copyout(opp, (void *)arg, valsize + sizeof (uint_t)) != 0)
			error = EFAULT;
		break;

	case OPROMNEXT:
	case OPROMCHILD:
	case OPROMSETNODEID:

		if (prom_is_openprom() == 0 ||
		    userbufsize < sizeof (pnode_t)) {
			error = EINVAL;
			break;
		}

		/*
		 * The argument is a phandle. (aka pnode_t)
		 */
		if (copyin(((caddr_t)arg + sizeof (uint_t)),
		    opp->oprom_array, sizeof (pnode_t)) != 0) {
			error = EFAULT;
			break;
		}

		/*
		 * If pnode_t from userland is garbage, we
		 * could confuse the PROM.
		 */
		node_id = *(pnode_t *)opp->oprom_array;
		if (oprom_checknodeid(node_id, st->current_id) == 0) {
			cmn_err(CE_NOTE, "!nodeid 0x%x not found",
			    (int)node_id);
			error = EINVAL;
			break;
		}

		if (cmd == OPROMNEXT)
			st->current_id = prom_nextnode(node_id);
		else if (cmd == OPROMCHILD)
			st->current_id = prom_childnode(node_id);
		else {
			/* OPROMSETNODEID */
			st->current_id = node_id;
			break;
		}

		opp->oprom_size = sizeof (pnode_t);
		*(pnode_t *)opp->oprom_array = st->current_id;

		if (copyout(opp, (void *)arg,
		    sizeof (pnode_t) + sizeof (uint_t)) != 0)
			error = EFAULT;
		break;

	case OPROMGETCONS:
		/*
		 * Is openboot supported on this machine?
		 * This ioctl used to return the console device,
		 * information; this is now done via modctl()
		 * in libdevinfo.
		 */
		opp->oprom_size = sizeof (char);

		opp->oprom_array[0] |= prom_is_openprom() ?
		    OPROMCONS_OPENPROM : 0;

		/*
		 * The rest of the info is needed by Install to
		 * decide if graphics should be started.
		 */
		if ((getzoneid() == GLOBAL_ZONEID) &&
		    plat_stdin_is_keyboard()) {
			opp->oprom_array[0] |= OPROMCONS_STDIN_IS_KBD;
		}

		if ((getzoneid() == GLOBAL_ZONEID) &&
		    plat_stdout_is_framebuffer()) {
			opp->oprom_array[0] |= OPROMCONS_STDOUT_IS_FB;
		}

		if (copyout(opp, (void *)arg,
		    sizeof (char) + sizeof (uint_t)) != 0)
			error = EFAULT;
		break;

	case OPROMGETBOOTARGS: {
		extern char kern_bootargs[];

		valsize = strlen(kern_bootargs) + 1;
		if (valsize > userbufsize) {
			error = EINVAL;
			break;
		}
		(void) strcpy(opp->oprom_array, kern_bootargs);
		opp->oprom_size = valsize - 1;

		if (copyout(opp, (void *)arg, valsize + sizeof (uint_t)) != 0)
			error = EFAULT;
		break;
	}

	case OPROMGETBOOTPATH: {
#if defined(__sparc) && defined(_OBP)

		char bpath[OBP_MAXPATHLEN];
		if (get_bootpath_prop(bpath) != 0) {
			error = EINVAL;
			break;
		}
		valsize = strlen(bpath) + 1;
		if (valsize > userbufsize) {
			error = EINVAL;
			break;
		}
		(void) strcpy(opp->oprom_array, bpath);

#elif defined(__i386) || defined(__amd64)

		extern char saved_cmdline[];
		valsize = strlen(saved_cmdline) + 1;
		if (valsize > userbufsize) {
			error = EINVAL;
			break;
		}
		(void) strcpy(opp->oprom_array, saved_cmdline);
#endif
		opp->oprom_size = valsize - 1;
		if (copyout(opp, (void *)arg, valsize + sizeof (uint_t)) != 0)
			error = EFAULT;
		break;
	}

	/*
	 * convert a prom device path to an equivalent devfs path
	 */
	case OPROMPROM2DEVNAME: {
		char *dev_name;

		/*
		 * The input argument, a pathname, is a NULL terminated string.
		 */
		if ((error = oprom_copyinstr(arg, opp->oprom_array,
		    (size_t)userbufsize, MAXPATHLEN)) != 0) {
			break;
		}

		dev_name = kmem_alloc(MAXPATHLEN, KM_SLEEP);

		error = i_promname_to_devname(opp->oprom_array, dev_name);
		if (error != 0) {
			kmem_free(dev_name, MAXPATHLEN);
			break;
		}
		valsize = opp->oprom_size = strlen(dev_name);
		if (++valsize > userbufsize) {
			kmem_free(dev_name, MAXPATHLEN);
			error = EINVAL;
			break;
		}
		(void) strcpy(opp->oprom_array, dev_name);
		if (copyout(opp, (void *)arg, sizeof (uint_t) + valsize) != 0)
			error = EFAULT;

		kmem_free(dev_name, MAXPATHLEN);
		break;
	}

	/*
	 * Convert a prom device path name to a driver name
	 */
	case OPROMPATH2DRV: {
		char *drv_name;
		major_t maj;

		/*
		 * The input argument, a pathname, is a NULL terminated string.
		 */
		if ((error = oprom_copyinstr(arg, opp->oprom_array,
		    (size_t)userbufsize, MAXPATHLEN)) != 0) {
			break;
		}

		/*
		 * convert path to a driver binding name
		 */
		maj = path_to_major((char *)opp->oprom_array);
		if (maj == DDI_MAJOR_T_NONE) {
			error = EINVAL;
			break;
		}

		/*
		 * resolve any aliases
		 */
		if ((drv_name = ddi_major_to_name(maj)) == NULL) {
			error = EINVAL;
			break;
		}

		(void) strcpy(opp->oprom_array, drv_name);
		opp->oprom_size = strlen(drv_name);
		if (copyout(opp, (void *)arg,
		    sizeof (uint_t) + opp->oprom_size + 1) != 0)
			error = EFAULT;
		break;
	}

	case OPROMGETVERSION:
		/*
		 * Get a string representing the running version of the
		 * prom. How to create such a string is platform dependent,
		 * so we just defer to a promif function. If no such
		 * association exists, the promif implementation
		 * may copy the string "unknown" into the given buffer,
		 * and return its length (incl. NULL terminator).
		 *
		 * We expect prom_version_name to return the actual
		 * length of the string, but copy at most userbufsize
		 * bytes into the given buffer, including NULL termination.
		 */

		valsize = prom_version_name(opp->oprom_array, userbufsize);
		if (valsize < 0) {
			error = EINVAL;
			break;
		}

		/*
		 * copyout only the part of the user buffer we need to.
		 */
		if (copyout(opp, (void *)arg,
		    (size_t)(min((uint_t)valsize, userbufsize) +
		    sizeof (uint_t))) != 0)
			error = EFAULT;
		break;

#if !defined(__i386) && !defined(__amd64)
	case OPROMGETFBNAME:
		/*
		 * Return stdoutpath, if it's a frame buffer.
		 * Yes, we are comparing a possibly longer string against
		 * the size we're really going to copy, but so what?
		 */
		if ((getzoneid() == GLOBAL_ZONEID) &&
		    (prom_stdout_is_framebuffer() != 0) &&
		    (userbufsize > strlen(prom_stdoutpath()))) {
			prom_strip_options(prom_stdoutpath(),
			    opp->oprom_array);	/* strip options and copy */
			valsize = opp->oprom_size = strlen(opp->oprom_array);
			if (copyout(opp, (void *)arg,
			    valsize + 1 + sizeof (uint_t)) != 0)
				error = EFAULT;
		} else
			error = EINVAL;
		break;

	/*
	 * Convert a logical or physical device path to prom device path
	 */
	case OPROMDEV2PROMNAME: {
		char *prom_name;

		/*
		 * The input argument, a pathname, is a NULL terminated string.
		 */
		if ((error = oprom_copyinstr(arg, opp->oprom_array,
		    (size_t)userbufsize, MAXPATHLEN)) != 0) {
			break;
		}

		prom_name = kmem_alloc(userbufsize, KM_SLEEP);

		/*
		 * convert the devfs path to an equivalent prom path
		 */
		error = i_devname_to_promname(opp->oprom_array, prom_name,
		    userbufsize);

		if (error != 0) {
			kmem_free(prom_name, userbufsize);
			break;
		}

		for (valsize = 0; valsize < userbufsize; valsize++) {
			opp->oprom_array[valsize] = prom_name[valsize];

			if ((valsize > 0) && (prom_name[valsize] == '\0') &&
			    (prom_name[valsize-1] == '\0')) {
				break;
			}
		}
		opp->oprom_size = valsize;

		kmem_free(prom_name, userbufsize);
		if (copyout(opp, (void *)arg, sizeof (uint_t) + valsize) != 0)
			error = EFAULT;

		break;
	}

	case OPROMSETOPT:
	case OPROMSETOPT2: {
		int namebuflen;
		int valbuflen;

		if ((prom_is_openprom() == 0) ||
		    (node_id == OBP_NONODE) || (node_id == OBP_BADNODE)) {
			error = EINVAL;
			break;
		}

		/*
		 * The arguments are a property name and a value.
		 * Copy in the entire user buffer.
		 */
		if (copyin(((caddr_t)arg + sizeof (uint_t)),
		    opp->oprom_array, userbufsize) != 0) {
			error = EFAULT;
			break;
		}

		/*
		 * The property name is the first string, value second
		 */
		namebuflen = strlen(opp->oprom_array);
		valbuf = opp->oprom_array + namebuflen + 1;
		valbuflen = strlen(valbuf);

		if (cmd == OPROMSETOPT) {
			valsize = valbuflen + 1;  /* +1 for the '\0' */
		} else {
			if ((namebuflen + 1 + valbuflen + 1) > userbufsize) {
				error = EINVAL;
				break;
			}
			valsize = (opp->oprom_array + userbufsize) - valbuf;
		}

		/*
		 * 4010173: 'name' is not an option, but it is a property.
		 */
		if (strcmp(opp->oprom_array, "name") == 0)
			error = EINVAL;
		else if (prom_setprop(node_id, opp->oprom_array,
		    valbuf, valsize) < 0)
			error = EINVAL;

		break;
	}

	case OPROMREADY64: {
		struct openprom_opr64 *opr =
		    (struct openprom_opr64 *)opp->oprom_array;
		int i;
		pnode_t id;

		if (userbufsize < sizeof (*opr)) {
			error = EINVAL;
			break;
		}

		valsize = userbufsize -
		    offsetof(struct openprom_opr64, message);

		i = prom_version_check(opr->message, valsize, &id);
		opr->return_code = i;
		opr->nodeid = (int)id;

		valsize = offsetof(struct openprom_opr64, message);
		valsize += strlen(opr->message) + 1;

		/*
		 * copyout only the part of the user buffer we need to.
		 */
		if (copyout(opp, (void *)arg,
		    (size_t)(min((uint_t)valsize, userbufsize) +
		    sizeof (uint_t))) != 0)
			error = EFAULT;
		break;

	}	/* case OPROMREADY64 */
#endif	/* !__i386 && !__amd64 */
	}	/* switch (cmd)	*/

	kmem_free(opp, userbufsize + sizeof (uint_t) + 1);
	return (error);
}

/*ARGSUSED*/
static int
opromioctl(dev_t dev, int cmd, intptr_t arg, int mode,
    cred_t *credp, int *rvalp)
{
	struct oprom_state *st;
	struct opromioctl_args arg_block;

	if (getminor(dev) >= MAX_OPENS)
		return (ENXIO);

	st = &oprom_state[getminor(dev)];
	ASSERT(st->already_open);
	arg_block.st = st;
	arg_block.cmd = cmd;
	arg_block.arg = arg;
	arg_block.mode = mode;
	return (prom_tree_access(opromioctl_cb, &arg_block, &st->tree_gen));
}

/*
 * Copyin string and verify the actual string length is less than maxsize
 * specified by the caller.
 *
 * Currently, maxsize is either OBP_MAXPROPNAME for property names
 * or MAXPATHLEN for device path names. userbufsize is specified
 * by the userland caller.
 */
static int
oprom_copyinstr(intptr_t arg, char *buf, size_t bufsize, size_t maxsize)
{
	int error;
	size_t actual_len;

	if ((error = copyinstr(((caddr_t)arg + sizeof (uint_t)),
	    buf, bufsize, &actual_len)) != 0) {
		return (error);
	}
	if ((actual_len == 0) || (actual_len > maxsize)) {
		return (EINVAL);
	}

	return (0);
}

/*
 * Check pnode_t passed in from userland
 */
static int
oprom_checknodeid(pnode_t node_id, pnode_t current_id)
{
	int depth;
	pnode_t id[OBP_STACKDEPTH];

	/*
	 * optimized path
	 */
	if (node_id == 0) {
		return (1);
	}
	if (node_id == OBP_BADNODE) {
		return (0);
	}
	if ((current_id != OBP_BADNODE) && ((node_id == current_id) ||
	    (node_id == prom_nextnode(current_id)) ||
	    (node_id == prom_childnode(current_id)))) {
		return (1);
	}

	/*
	 * long path: walk from root till we find node_id
	 */
	depth = 1;
	id[0] = prom_nextnode((pnode_t)0);

	while (depth) {
		if (id[depth - 1] == node_id)
			return (1);	/* node_id found */

		if (id[depth] = prom_childnode(id[depth - 1])) {
			depth++;
			continue;
		}

		while (depth &&
		    ((id[depth - 1] = prom_nextnode(id[depth - 1])) == 0))
			depth--;
	}
	return (0);	/* node_id not found */
}

static int
oprom_copytree(struct oprom_state *st, uint_t flag)
{
	ASSERT(st->snapshot == NULL && st->size == 0);
	return (oprom_copynode(
	    prom_nextnode(0), flag, &st->snapshot, &st->size));
}

static int
oprom_snapshot(struct oprom_state *st, intptr_t arg)
{
	uint_t flag;

	if (oprom_setstate(st, IOC_SNAP) == -1)
		return (EBUSY);

	/* copyin flag and create snapshot */
	if ((copyin((void *)arg, &flag, sizeof (uint_t)) != 0) ||
	    (oprom_copytree(st, flag) != 0)) {
		(void) oprom_setstate(st, IOC_IDLE);
		return (EFAULT);
	}


	/* copyout the size of the snapshot */
	flag = (uint_t)st->size;
	if (copyout(&flag, (void *)arg, sizeof (uint_t)) != 0) {
		kmem_free(st->snapshot, st->size);
		st->snapshot = NULL;
		st->size = 0;
		(void) oprom_setstate(st, IOC_IDLE);
		return (EFAULT);
	}

	(void) oprom_setstate(st, IOC_DONE);
	return (0);
}

static int
oprom_copyout(struct oprom_state *st, intptr_t arg)
{
	int error = 0;
	uint_t size;

	if (oprom_setstate(st, IOC_COPY) == -1)
		return (EBUSY);

	/* copyin size and copyout snapshot */
	if (copyin((void *)arg, &size, sizeof (uint_t)) != 0)
		error = EFAULT;
	else if (size < st->size)
		error = EINVAL;
	else if (copyout(st->snapshot, (void *)arg, st->size) != 0)
		error = EFAULT;

	if (error) {
		/*
		 * on error keep the snapshot until a successful
		 * copyout or when the driver is closed.
		 */
		(void) oprom_setstate(st, IOC_DONE);
		return (error);
	}

	kmem_free(st->snapshot, st->size);
	st->snapshot = NULL;
	st->size = 0;
	(void) oprom_setstate(st, IOC_IDLE);
	return (0);
}

/*
 * Copy all properties of nodeid into a single packed nvlist
 */
static int
oprom_copyprop(pnode_t nodeid, uint_t flag, nvlist_t *nvl)
{
	int proplen;
	char *propname, *propval, *buf1, *buf2;

	ASSERT(nvl != NULL);

	/*
	 * non verbose mode, get the "name" property only
	 */
	if (flag == 0) {
		proplen = prom_getproplen(nodeid, "name");
		if (proplen <= 0) {
			cmn_err(CE_WARN,
			    "failed to get the name of openprom node 0x%x",
			    nodeid);
			(void) nvlist_add_string(nvl, "name", "");
			return (0);
		}
		propval = kmem_zalloc(proplen + 1, KM_SLEEP);
		(void) prom_getprop(nodeid, "name", propval);
		(void) nvlist_add_string(nvl, "name", propval);
		kmem_free(propval, proplen + 1);
		return (0);
	}

	/*
	 * Ask for first property by passing a NULL string
	 */
	buf1 = kmem_alloc(OBP_MAXPROPNAME, KM_SLEEP);
	buf2 = kmem_zalloc(OBP_MAXPROPNAME, KM_SLEEP);
	buf1[0] = '\0';
	while (propname = (char *)prom_nextprop(nodeid, buf1, buf2)) {
		if (strlen(propname) == 0)
			break;		/* end of prop list */
		(void) strcpy(buf1, propname);

		proplen = prom_getproplen(nodeid, propname);
		if (proplen == 0) {
			/* boolean property */
			(void) nvlist_add_boolean(nvl, propname);
			continue;
		}
		/* add 1 for null termination in case of a string */
		propval = kmem_zalloc(proplen + 1, KM_SLEEP);
		(void) prom_getprop(nodeid, propname, propval);
		(void) nvlist_add_byte_array(nvl, propname,
		    (uchar_t *)propval, proplen + 1);
		kmem_free(propval, proplen + 1);
		bzero(buf2, OBP_MAXPROPNAME);
	}

	kmem_free(buf1, OBP_MAXPROPNAME);
	kmem_free(buf2, OBP_MAXPROPNAME);

	return (0);
}

/*
 * Copy all children and descendents into a a packed nvlist
 */
static int
oprom_copychild(pnode_t nodeid, uint_t flag, char **buf, size_t *size)
{
	nvlist_t *nvl;
	pnode_t child = prom_childnode(nodeid);

	if (child == 0)
		return (0);

	(void) nvlist_alloc(&nvl, 0, KM_SLEEP);
	while (child != 0) {
		char *nodebuf = NULL;
		size_t nodesize = 0;
		if (oprom_copynode(child, flag, &nodebuf, &nodesize)) {
			nvlist_free(nvl);
			cmn_err(CE_WARN, "failed to copy nodeid 0x%x", child);
			return (-1);
		}
		(void) nvlist_add_byte_array(nvl, "node",
		    (uchar_t *)nodebuf, nodesize);
		kmem_free(nodebuf, nodesize);
		child = prom_nextnode(child);
	}

	(void) nvlist_pack(nvl, buf, size, NV_ENCODE_NATIVE, KM_SLEEP);
	nvlist_free(nvl);
	return (0);
}

/*
 * Copy a node into a packed nvlist
 */
static int
oprom_copynode(pnode_t nodeid, uint_t flag, char **buf, size_t *size)
{
	int error = 0;
	nvlist_t *nvl;
	char *childlist = NULL;
	size_t childsize = 0;

	(void) nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP);
	ASSERT(nvl != NULL);

	/* @nodeid -- @ is not a legal char in a 1275 property name */
	(void) nvlist_add_int32(nvl, "@nodeid", (int32_t)nodeid);

	/* properties */
	if (error = oprom_copyprop(nodeid, flag, nvl))
		goto fail;

	/* children */
	error = oprom_copychild(nodeid, flag, &childlist, &childsize);
	if (error != 0)
		goto fail;
	if (childlist != NULL) {
		(void) nvlist_add_byte_array(nvl, "@child",
		    (uchar_t *)childlist, (uint_t)childsize);
		kmem_free(childlist, childsize);
	}

	/* pack into contiguous buffer */
	error = nvlist_pack(nvl, buf, size, NV_ENCODE_NATIVE, KM_SLEEP);

fail:
	nvlist_free(nvl);
	return (error);
}

/*
 * The driver is stateful across OPROMSNAPSHOT and OPROMCOPYOUT.
 * This function encapsulates the state machine:
 *
 *	-> IOC_IDLE -> IOC_SNAP -> IOC_DONE -> IOC_COPY ->
 *	|		SNAPSHOT		COPYOUT	 |
 *	--------------------------------------------------
 *
 * Returns 0 on success and -1 on failure
 */
static int
oprom_setstate(struct oprom_state *st, int16_t new_state)
{
	int ret = 0;

	mutex_enter(&oprom_lock);
	switch (new_state) {
	case IOC_IDLE:
	case IOC_DONE:
		break;
	case IOC_SNAP:
		if (st->ioc_state != IOC_IDLE)
			ret = -1;
		break;
	case IOC_COPY:
		if (st->ioc_state != IOC_DONE)
			ret = -1;
		break;
	default:
		ret = -1;
	}

	if (ret == 0)
		st->ioc_state = new_state;
	else
		cmn_err(CE_NOTE, "incorrect state transition from %d to %d",
		    st->ioc_state, new_state);
	mutex_exit(&oprom_lock);
	return (ret);
}
