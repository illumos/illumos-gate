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

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/cred.h>
#include <sys/policy.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/systeminfo.h>

#include <sys/fm/protocol.h>
#include <sys/devfm.h>

extern int fm_get_paddr(nvlist_t *, uint64_t *);
#if defined(__x86)
extern int fm_ioctl_physcpu_info(int, nvlist_t *, nvlist_t **);
extern int fm_ioctl_cpu_retire(int, nvlist_t *, nvlist_t **);
extern int fm_ioctl_gentopo_legacy(int, nvlist_t *, nvlist_t **);
#endif /* __x86 */

static int fm_ioctl_versions(int, nvlist_t *, nvlist_t **);
static int fm_ioctl_page_retire(int, nvlist_t *, nvlist_t **);

/*
 * The driver's capabilities are strictly versioned, allowing userland patching
 * without a reboot.  The userland should start with a FM_VERSIONS ioctl to
 * query the versions of the kernel interfaces, then it's all userland's
 * responsibility to prepare arguments etc to match the current kenrel.
 * The version of FM_VERSIONS itself is FM_DRV_VERSION.
 */
typedef struct fm_version {
	char		*interface;	/* interface name */
	uint32_t	version;	/* interface version */
} fm_vers_t;

typedef struct fm_subroutine {
	int		cmd;		/* ioctl cmd */
	boolean_t	priv;		/* require privilege */
	char		*version;	/* version name */
	int		(*func)(int, nvlist_t *, nvlist_t **);	/* handler */
} fm_subr_t;

static const fm_vers_t fm_versions[] = {
	{ FM_VERSIONS_VERSION, FM_DRV_VERSION },
	{ FM_PAGE_OP_VERSION, 1 },
	{ FM_CPU_OP_VERSION, 1 },
	{ FM_CPU_INFO_VERSION, 1 },
	{ FM_TOPO_LEGACY_VERSION, 1 },
	{ NULL, 0 }
};

static const fm_subr_t fm_subrs[] = {
	{ FM_IOC_VERSIONS, B_FALSE, FM_VERSIONS_VERSION, fm_ioctl_versions },
	{ FM_IOC_PAGE_RETIRE, B_TRUE, FM_PAGE_OP_VERSION,
	    fm_ioctl_page_retire },
	{ FM_IOC_PAGE_STATUS, B_FALSE, FM_PAGE_OP_VERSION,
	    fm_ioctl_page_retire },
	{ FM_IOC_PAGE_UNRETIRE, B_TRUE, FM_PAGE_OP_VERSION,
	    fm_ioctl_page_retire },
#if defined(__x86)
	{ FM_IOC_PHYSCPU_INFO, B_FALSE, FM_CPU_INFO_VERSION,
	    fm_ioctl_physcpu_info },
	{ FM_IOC_CPU_RETIRE, B_TRUE, FM_CPU_OP_VERSION,
	    fm_ioctl_cpu_retire },
	{ FM_IOC_CPU_STATUS, B_FALSE, FM_CPU_OP_VERSION,
	    fm_ioctl_cpu_retire },
	{ FM_IOC_CPU_UNRETIRE, B_TRUE, FM_CPU_OP_VERSION,
	    fm_ioctl_cpu_retire },
	{ FM_IOC_GENTOPO_LEGACY, B_FALSE, FM_TOPO_LEGACY_VERSION,
	    fm_ioctl_gentopo_legacy },
#endif	/* __x86 */
	{ -1, B_FALSE, NULL, NULL },
};

static dev_info_t *fm_dip;
static boolean_t is_i86xpv;
static nvlist_t *fm_vers_nvl;

static int
fm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		if (ddi_create_minor_node(dip, ddi_get_name(dip), S_IFCHR,
		    ddi_get_instance(dip), DDI_PSEUDO, 0) != DDI_SUCCESS) {
			ddi_remove_minor_node(dip, NULL);
			return (DDI_FAILURE);
		}
		fm_dip = dip;
		is_i86xpv = (strcmp(platform, "i86xpv") == 0);
		break;
	case DDI_RESUME:
		break;
	default:
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

static int
fm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int ret = DDI_SUCCESS;

	switch (cmd) {
	case DDI_DETACH:
		ddi_remove_minor_node(dip, NULL);
		fm_dip = NULL;
		break;
	default:
		ret = DDI_FAILURE;
	}
	return (ret);
}

/*ARGSUSED*/
static int
fm_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = fm_dip;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = NULL;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/*ARGSUSED1*/
static int
fm_open(dev_t *devp, int flag, int typ, struct cred *cred)
{
	if (typ != OTYP_CHR)
		return (EINVAL);
	if (getminor(*devp) != 0)
		return (ENXIO);

	return (0);
}

/*ARGSUSED*/
static int
fm_ioctl_versions(int cmd, nvlist_t *invl, nvlist_t **onvlp)
{
	nvlist_t *nvl;
	int err;

	if ((err = nvlist_dup(fm_vers_nvl, &nvl, KM_SLEEP)) == 0)
		*onvlp = nvl;

	return (err);
}

/*
 * Given a mem-scheme FMRI for a page, execute the given page retire
 * command on it.
 */
/*ARGSUSED*/
static int
fm_ioctl_page_retire(int cmd, nvlist_t *invl, nvlist_t **onvlp)
{
	uint64_t pa;
	nvlist_t *fmri;
	int err;

	if (is_i86xpv)
		return (ENOTSUP);

	if ((err = nvlist_lookup_nvlist(invl, FM_PAGE_RETIRE_FMRI, &fmri))
	    != 0)
		return (err);

	if ((err = fm_get_paddr(fmri, &pa)) != 0)
		return (err);

	switch (cmd) {
	case FM_IOC_PAGE_STATUS:
		return (page_retire_check(pa, NULL));

	case FM_IOC_PAGE_RETIRE:
		return (page_retire(pa, PR_FMA));

	case FM_IOC_PAGE_UNRETIRE:
		return (page_unretire(pa));
	}

	return (ENOTTY);
}

/*ARGSUSED*/
static int
fm_ioctl(dev_t dev, int cmd, intptr_t data, int flag, cred_t *cred, int *rvalp)
{
	char *buf;
	int err;
	uint_t model;
	const fm_subr_t *subr;
	uint32_t vers;
	fm_ioc_data_t fid;
	nvlist_t *invl = NULL, *onvl = NULL;
#ifdef _MULTI_DATAMODEL
	fm_ioc_data32_t fid32;
#endif

	if (getminor(dev) != 0)
		return (ENXIO);

	for (subr = fm_subrs; subr->cmd != cmd; subr++)
		if (subr->cmd == -1)
			return (ENOTTY);

	if (subr->priv && (flag & FWRITE) == 0 &&
	    secpolicy_sys_config(CRED(), 0) != 0)
		return (EPERM);

	model = ddi_model_convert_from(flag & FMODELS);

	switch (model) {
#ifdef _MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		if (ddi_copyin((void *)data, &fid32,
		    sizeof (fm_ioc_data32_t), flag) != 0)
			return (EFAULT);
		fid.fid_version = fid32.fid_version;
		fid.fid_insz = fid32.fid_insz;
		fid.fid_inbuf = (caddr_t)(uintptr_t)fid32.fid_inbuf;
		fid.fid_outsz = fid32.fid_outsz;
		fid.fid_outbuf = (caddr_t)(uintptr_t)fid32.fid_outbuf;
		break;
#endif /* _MULTI_DATAMODEL */
	case DDI_MODEL_NONE:
	default:
		if (ddi_copyin((void *)data, &fid, sizeof (fm_ioc_data_t),
		    flag) != 0)
			return (EFAULT);
	}

	if (nvlist_lookup_uint32(fm_vers_nvl, subr->version, &vers) != 0 ||
	    fid.fid_version != vers)
		return (ENOTSUP);

	if (fid.fid_insz > FM_IOC_MAXBUFSZ)
		return (ENAMETOOLONG);
	if (fid.fid_outsz > FM_IOC_OUT_MAXBUFSZ)
		return (EINVAL);

	/*
	 * Copy in and unpack the input nvlist.
	 */
	if (fid.fid_insz != 0 && fid.fid_inbuf != (caddr_t)0) {
		buf = kmem_alloc(fid.fid_insz, KM_SLEEP);
		if (ddi_copyin(fid.fid_inbuf, buf, fid.fid_insz, flag) != 0) {
			kmem_free(buf, fid.fid_insz);
			return (EFAULT);
		}
		err = nvlist_unpack(buf, fid.fid_insz, &invl, KM_SLEEP);
		kmem_free(buf, fid.fid_insz);
		if (err != 0)
			return (err);
	}

	err = subr->func(cmd, invl, &onvl);

	nvlist_free(invl);

	if (err != 0) {
		nvlist_free(onvl);
		return (err);
	}

	/*
	 * If the output nvlist contains any data, pack it and copyout.
	 */
	if (onvl != NULL) {
		size_t sz;

		if ((err = nvlist_size(onvl, &sz, NV_ENCODE_NATIVE)) != 0) {
			nvlist_free(onvl);
			return (err);
		}
		if (sz > fid.fid_outsz) {
			nvlist_free(onvl);
			return (ENAMETOOLONG);
		}

		buf = kmem_alloc(sz, KM_SLEEP);
		if ((err = nvlist_pack(onvl, &buf, &sz, NV_ENCODE_NATIVE,
		    KM_SLEEP)) != 0) {
			kmem_free(buf, sz);
			nvlist_free(onvl);
			return (err);
		}
		nvlist_free(onvl);
		if (ddi_copyout(buf, fid.fid_outbuf, sz, flag) != 0) {
			kmem_free(buf, sz);
			return (EFAULT);
		}
		kmem_free(buf, sz);
		fid.fid_outsz = sz;

		switch (model) {
#ifdef _MULTI_DATAMODEL
		case DDI_MODEL_ILP32:
			fid32.fid_outsz = (size32_t)fid.fid_outsz;
			if (ddi_copyout(&fid32, (void *)data,
			    sizeof (fm_ioc_data32_t), flag) != 0)
				return (EFAULT);
			break;
#endif /* _MULTI_DATAMODEL */
		case DDI_MODEL_NONE:
		default:
			if (ddi_copyout(&fid, (void *)data,
			    sizeof (fm_ioc_data_t), flag) != 0)
				return (EFAULT);
		}
	}

	return (err);
}

static struct cb_ops fm_cb_ops = {
	fm_open,		/* open */
	nulldev,		/* close */
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	fm_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* streamtab  */
	D_NEW | D_MP | D_64BIT | D_U64BIT
};

static struct dev_ops fm_ops = {
	DEVO_REV,		/* devo_rev, */
	0,			/* refcnt  */
	fm_info,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	fm_attach,		/* attach */
	fm_detach,		/* detach */
	nodev,			/* reset */
	&fm_cb_ops,		/* driver operations */
	(struct bus_ops *)0	/* bus operations */
};

static struct modldrv modldrv = {
	&mod_driverops, "fault management driver", &fm_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1, &modldrv, NULL
};

int
_init(void)
{
	const fm_vers_t *p;
	int ret;


	if ((ret = mod_install(&modlinkage)) == 0) {
		(void) nvlist_alloc(&fm_vers_nvl, NV_UNIQUE_NAME, KM_SLEEP);
		for (p = fm_versions; p->interface != NULL; p++)
			(void) nvlist_add_uint32(fm_vers_nvl, p->interface,
			    p->version);
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&modlinkage)) == 0) {
		nvlist_free(fm_vers_nvl);
	}

	return (ret);
}
