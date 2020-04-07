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
 * The ioctl interface for administrative commands.
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/ksynch.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/model.h>
#include <sys/sysmacros.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/sched_impl.h>
#include <sys/crypto/ioctladmin.h>
#include <c2/audit.h>
#include <sys/disp.h>

/*
 * DDI entry points.
 */
static int cryptoadm_attach(dev_info_t *, ddi_attach_cmd_t);
static int cryptoadm_detach(dev_info_t *, ddi_detach_cmd_t);
static int cryptoadm_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int cryptoadm_open(dev_t *, int, int, cred_t *);
static int cryptoadm_close(dev_t, int, int, cred_t *);
static int cryptoadm_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

extern void audit_cryptoadm(int, char *, crypto_mech_name_t *, uint_t,
    uint_t, uint32_t, int);

/*
 * Module linkage.
 */
static struct cb_ops cbops = {
	cryptoadm_open,		/* cb_open */
	cryptoadm_close,	/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	cryptoadm_ioctl,	/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_streamtab */
	D_MP,			/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev,			/* cb_awrite */
};

static struct dev_ops devops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	cryptoadm_getinfo,	/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	cryptoadm_attach,	/* devo_attach */
	cryptoadm_detach,	/* devo_detach */
	nodev,			/* devo_reset */
	&cbops,			/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,		/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,					/* drv_modops */
	"Cryptographic Administrative Interface",	/* drv_linkinfo */
	&devops,
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* ml_rev */
	&modldrv,		/* ml_linkage */
	NULL
};

static dev_info_t	*cryptoadm_dip = NULL;

/*
 * DDI entry points.
 */
int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
cryptoadm_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)cryptoadm_dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
cryptoadm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}
	if (ddi_get_instance(dip) != 0) {
		/* we only allow instance 0 to attach */
		return (DDI_FAILURE);
	}

	/* create the minor node */
	if (ddi_create_minor_node(dip, "cryptoadm", S_IFCHR, 0,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "cryptoadm: failed creating minor node");
		ddi_remove_minor_node(dip, NULL);
		return (DDI_FAILURE);
	}

	cryptoadm_dip = dip;

	return (DDI_SUCCESS);
}

static int
cryptoadm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	cryptoadm_dip = NULL;
	ddi_remove_minor_node(dip, NULL);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
cryptoadm_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	if (otyp != OTYP_CHR || cryptoadm_dip == NULL)
		return (ENXIO);

	/* exclusive opens are not supported */
	if (flag & FEXCL)
		return (ENOTSUP);

	*devp = makedevice(getmajor(*devp), 0);

	kcf_sched_start();

	return (0);
}

/* ARGSUSED */
static int
cryptoadm_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	return (0);
}

/*
 * Returns TRUE if array of size MAXNAMELEN contains a '\0'
 * termination character, otherwise, it returns FALSE.
 */
static boolean_t
null_terminated(char *array)
{
	int i;

	for (i = 0; i < MAXNAMELEN; i++)
		if (array[i] == '\0')
			return (B_TRUE);

	return (B_FALSE);
}

/*
 * This ioctl returns an array of hardware providers.  Each entry
 * contains a device name, device instance, and number of
 * supported mechanisms.
 */
/* ARGSUSED */
static int
get_dev_list(dev_t dev, caddr_t arg, int mode, int *rval)
{
	crypto_get_dev_list_t dev_list;
	crypto_dev_list_entry_t *entries;
	size_t copyout_size;
	uint_t count;
	ulong_t offset;

	if (copyin(arg, &dev_list, sizeof (dev_list)) != 0)
		return (EFAULT);

	/* get the list from the core module */
	if (crypto_get_dev_list(&count, &entries) != 0) {
		dev_list.dl_return_value = CRYPTO_FAILED;
		if (copyout(&dev_list, arg, sizeof (dev_list)) != 0) {
			return (EFAULT);
		}
		return (0);
	}

	/* check if buffer is too small */
	if (count > dev_list.dl_dev_count) {
		dev_list.dl_dev_count = count;
		dev_list.dl_return_value = CRYPTO_BUFFER_TOO_SMALL;
		crypto_free_dev_list(entries, count);
		if (copyout(&dev_list, arg, sizeof (dev_list)) != 0) {
			return (EFAULT);
		}
		return (0);
	}

	dev_list.dl_dev_count = count;
	dev_list.dl_return_value = CRYPTO_SUCCESS;

	copyout_size = count * sizeof (crypto_dev_list_entry_t);

	/* copyout the first stuff */
	if (copyout(&dev_list, arg, sizeof (dev_list)) != 0) {
		crypto_free_dev_list(entries, count);
		return (EFAULT);
	}

	/* copyout entries */
	offset = offsetof(crypto_get_dev_list_t, dl_devs);
	if (count > 0 && copyout(entries, arg + offset, copyout_size) != 0) {
		crypto_free_dev_list(entries, count);
		return (EFAULT);
	}
	crypto_free_dev_list(entries, count);
	return (0);
}

/*
 * This ioctl returns a buffer containing the null terminated names
 * of software providers.
 */
/* ARGSUSED */
static int
get_soft_list(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_get_soft_list, soft_list);
	char *names;
	size_t len;
	uint_t count;

	STRUCT_INIT(soft_list, mode);

	if (copyin(arg, STRUCT_BUF(soft_list), STRUCT_SIZE(soft_list)) != 0)
		return (EFAULT);

	/* get the list from the core module */
	if (crypto_get_soft_list(&count, &names, &len) != 0) {
		STRUCT_FSET(soft_list, sl_return_value, CRYPTO_FAILED);
		if (copyout(STRUCT_BUF(soft_list), arg,
		    STRUCT_SIZE(soft_list)) != 0) {
			return (EFAULT);
		}
		return (0);
	}

	/* check if buffer is too small */
	if (len > STRUCT_FGET(soft_list, sl_soft_len)) {
		STRUCT_FSET(soft_list, sl_soft_count, count);
		STRUCT_FSET(soft_list, sl_soft_len, len);
		STRUCT_FSET(soft_list, sl_return_value,
		    CRYPTO_BUFFER_TOO_SMALL);
		kmem_free(names, len);
		if (copyout(STRUCT_BUF(soft_list), arg,
		    STRUCT_SIZE(soft_list)) != 0) {
			return (EFAULT);
		}
		return (0);
	}

	STRUCT_FSET(soft_list, sl_soft_count, count);
	STRUCT_FSET(soft_list, sl_soft_len, len);
	STRUCT_FSET(soft_list, sl_return_value, CRYPTO_SUCCESS);

	if (count > 0 && copyout(names,
	    STRUCT_FGETP(soft_list, sl_soft_names), len) != 0) {
		kmem_free(names, len);
		return (EFAULT);
	}
	kmem_free(names, len);

	if (copyout(STRUCT_BUF(soft_list), arg, STRUCT_SIZE(soft_list)) != 0) {
		return (EFAULT);
	}

	return (0);
}

/*
 * This ioctl returns an array of mechanisms supported by the
 * specified device.
 */
/* ARGSUSED */
static int
get_dev_info(dev_t dev, caddr_t arg, int mode, int *rval)
{
	crypto_get_dev_info_t dev_info;
	crypto_mech_name_t *entries;
	size_t copyout_size;
	uint_t count;
	ulong_t offset;
	char *dev_name;
	int rv;

	if (copyin(arg, &dev_info, sizeof (dev_info)) != 0)
		return (EFAULT);

	dev_name = dev_info.di_dev_name;
	/* make sure the device name is null terminated */
	if (!null_terminated(dev_name)) {
		dev_info.di_return_value = CRYPTO_ARGUMENTS_BAD;
		if (copyout(&dev_info, arg, sizeof (dev_info)) != 0) {
			return (EFAULT);
		}
		return (0);
	}

	/* get mechanism names from the core module */
	if ((rv = crypto_get_dev_info(dev_name, dev_info.di_dev_instance,
	    &count, &entries)) != CRYPTO_SUCCESS) {
		dev_info.di_return_value = rv;
		if (copyout(&dev_info, arg, sizeof (dev_info)) != 0) {
			return (EFAULT);
		}
		return (0);
	}

	/* check if buffer is too small */
	if (count > dev_info.di_count) {
		dev_info.di_count = count;
		dev_info.di_return_value = CRYPTO_BUFFER_TOO_SMALL;
		crypto_free_mech_list(entries, count);
		if (copyout(&dev_info, arg, sizeof (dev_info)) != 0) {
			return (EFAULT);
		}
		return (0);
	}

	dev_info.di_count = count;
	dev_info.di_return_value = CRYPTO_SUCCESS;

	copyout_size = count * sizeof (crypto_mech_name_t);

	/* copyout the first stuff */
	if (copyout(&dev_info, arg, sizeof (dev_info)) != 0) {
		crypto_free_mech_list(entries, count);
		return (EFAULT);
	}

	/* copyout entries */
	offset = offsetof(crypto_get_dev_info_t, di_list);
	if (copyout(entries, arg + offset, copyout_size) != 0) {
		crypto_free_mech_list(entries, count);
		return (EFAULT);
	}
	crypto_free_mech_list(entries, count);
	return (0);
}

/*
 * This ioctl returns an array of mechanisms supported by the
 * specified cryptographic module.
 */
/* ARGSUSED */
static int
get_soft_info(dev_t dev, caddr_t arg, int mode, int *rval)
{
	crypto_get_soft_info_t soft_info;
	crypto_mech_name_t *entries;
	size_t copyout_size;
	uint_t count;
	ulong_t offset;
	char *name;

	if (copyin(arg, &soft_info, sizeof (soft_info)) != 0)
		return (EFAULT);

	name = soft_info.si_name;
	/* make sure the provider name is null terminated */
	if (!null_terminated(name)) {
		soft_info.si_return_value = CRYPTO_ARGUMENTS_BAD;
		if (copyout(&soft_info, arg, sizeof (soft_info)) != 0) {
			return (EFAULT);
		}
		return (0);
	}

	/* get mechanism names from the core module */
	if (crypto_get_soft_info(name, &count, &entries) != 0) {
		soft_info.si_return_value = CRYPTO_FAILED;
		if (copyout(&soft_info, arg, sizeof (soft_info)) != 0) {
			return (EFAULT);
		}
		return (0);
	}

	/* check if buffer is too small */
	if (count > soft_info.si_count) {
		soft_info.si_count = count;
		soft_info.si_return_value = CRYPTO_BUFFER_TOO_SMALL;
		crypto_free_mech_list(entries, count);
		if (copyout(&soft_info, arg, sizeof (soft_info)) != 0) {
			return (EFAULT);
		}
		return (0);
	}

	soft_info.si_count = count;
	soft_info.si_return_value = CRYPTO_SUCCESS;
	copyout_size = count * sizeof (crypto_mech_name_t);

	/* copyout the first stuff */
	if (copyout(&soft_info, arg, sizeof (soft_info)) != 0) {
		crypto_free_mech_list(entries, count);
		return (EFAULT);
	}

	/* copyout entries */
	offset = offsetof(crypto_get_soft_info_t, si_list);
	if (copyout(entries, arg + offset, copyout_size) != 0) {
		crypto_free_mech_list(entries, count);
		return (EFAULT);
	}
	crypto_free_mech_list(entries, count);
	return (0);
}

/*
 * This ioctl disables mechanisms supported by the specified device.
 */
/* ARGSUSED */
static int
load_dev_disabled(dev_t dev, caddr_t arg, int mode, int *rval)
{
	crypto_load_dev_disabled_t dev_disabled;
	crypto_mech_name_t *entries;
	size_t size;
	ulong_t offset;
	uint_t count;
	uint_t instance;
	char *dev_name;
	uint32_t rv;
	int error = 0;

	entries = NULL;
	count = 0;
	instance = 0;
	rv = CRYPTO_SUCCESS;
	if (copyin(arg, &dev_disabled, sizeof (dev_disabled)) != 0) {
		error =  EFAULT;
		goto out2;
	}

	dev_name = dev_disabled.dd_dev_name;
	/* make sure the device name is null terminated */
	if (!null_terminated(dev_name)) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto out;
	}

	count = dev_disabled.dd_count;
	instance = dev_disabled.dd_dev_instance;
	if (count == 0) {
		/* remove the entry */
		if (crypto_load_dev_disabled(dev_name, instance, 0, NULL) != 0)
			rv = CRYPTO_FAILED;
		else
			rv = CRYPTO_SUCCESS;
		goto out;
	}

	if (count > KCF_MAXMECHS) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto out;
	}

	size = count * sizeof (crypto_mech_name_t);
	entries = kmem_alloc(size, KM_SLEEP);

	offset = offsetof(crypto_load_dev_disabled_t, dd_list);
	if (copyin(arg + offset, entries, size) != 0) {
		kmem_free(entries, size);
		error = EFAULT;
		goto out2;
	}

	/* 'entries' consumed (but not freed) by crypto_load_dev_disabled() */
	if (crypto_load_dev_disabled(dev_name, instance, count, entries) != 0) {
		kmem_free(entries, size);
		rv = CRYPTO_FAILED;
		goto out;
	}
	rv = CRYPTO_SUCCESS;
out:
	dev_disabled.dd_return_value = rv;

	if (copyout(&dev_disabled, arg, sizeof (dev_disabled)) != 0) {
		error = EFAULT;
	}
out2:
	if (AU_AUDITING())
		audit_cryptoadm(CRYPTO_LOAD_DEV_DISABLED, dev_name, entries,
		    count, instance, rv, error);
	return (error);
}

/*
 * This ioctl disables mechanisms supported by the specified
 * cryptographic module.
 */
/* ARGSUSED */
static int
load_soft_disabled(dev_t dev, caddr_t arg, int mode, int *rval)
{
	crypto_load_soft_disabled_t soft_disabled;
	crypto_mech_name_t *entries;
	size_t size;
	uint_t count;
	ulong_t offset;
	char *name;
	uint32_t rv;
	int error = 0;

	entries = NULL;
	count = 0;
	rv = CRYPTO_SUCCESS;
	if (copyin(arg, &soft_disabled, sizeof (soft_disabled)) != 0) {
		error = EFAULT;
		goto out2;
	}

	name = soft_disabled.sd_name;
	/* make sure the name is null terminated */
	if (!null_terminated(name)) {
		soft_disabled.sd_return_value = CRYPTO_ARGUMENTS_BAD;
		if (copyout(&soft_disabled, arg, sizeof (soft_disabled)) != 0) {
			return (EFAULT);
		}
		return (0);
	}

	count = soft_disabled.sd_count;
	if (count == 0) {
		/* remove the entry */
		if (crypto_load_soft_disabled(name, 0, NULL) != 0) {
			rv = CRYPTO_FAILED;
		} else {
			rv = CRYPTO_SUCCESS;
		}
		goto out;
	}

	if (count > KCF_MAXMECHS) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto out;
	}

	size = count * sizeof (crypto_mech_name_t);
	entries = kmem_alloc(size, KM_SLEEP);

	offset = offsetof(crypto_load_soft_disabled_t, sd_list);
	if (copyin(arg + offset, entries, size) != 0) {
		kmem_free(entries, size);
		error = EFAULT;
		goto out2;
	}

	/* 'entries' is consumed by crypto_load_soft_disabled() */
	if (crypto_load_soft_disabled(name, count, entries) != 0) {
		kmem_free(entries, size);
		rv = CRYPTO_FAILED;
		goto out;
	}
	rv = CRYPTO_SUCCESS;
out:
	soft_disabled.sd_return_value = rv;

	if (copyout(&soft_disabled, arg, sizeof (soft_disabled)) != 0) {
		error = EFAULT;
	}
out2:
	if (AU_AUDITING())
		audit_cryptoadm(CRYPTO_LOAD_SOFT_DISABLED, name, entries,
		    count, 0, rv, error);
	return (error);
}

/*
 * This ioctl loads the supported mechanisms of the specfied cryptographic
 * module.  This is so, at boot time, all software providers do not
 * have to be opened in order to cause them to register their
 * supported mechanisms.
 */
/* ARGSUSED */
static int
load_soft_config(dev_t dev, caddr_t arg, int mode, int *rval)
{
	crypto_load_soft_config_t soft_config;
	crypto_mech_name_t *entries;
	size_t size;
	uint_t count;
	ulong_t offset;
	char *name;
	uint32_t rv;
	int error = 0;

	entries = NULL;
	count = 0;
	rv = CRYPTO_SUCCESS;
	if (copyin(arg, &soft_config, sizeof (soft_config)) != 0) {
		error = EFAULT;
		goto out2;
	}

	name = soft_config.sc_name;
	/* make sure the name is null terminated */
	if (!null_terminated(name)) {
		soft_config.sc_return_value = CRYPTO_ARGUMENTS_BAD;
		if (copyout(&soft_config, arg, sizeof (soft_config)) != 0) {
			return (EFAULT);
		}
		return (0);
	}

	count = soft_config.sc_count;
	if (count == 0) {
		if (crypto_load_soft_config(name, 0, NULL) != 0) {
			rv = CRYPTO_FAILED;
		} else {
			rv = CRYPTO_SUCCESS;
		}
		goto out;
	}

	if (count > KCF_MAXMECHS) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto out;
	}

	size = count * sizeof (crypto_mech_name_t);
	entries = kmem_alloc(size, KM_SLEEP);

	offset = offsetof(crypto_load_soft_config_t, sc_list);
	if (copyin(arg + offset, entries, size) != 0) {
		kmem_free(entries, size);
		error = EFAULT;
		goto out2;
	}

	/*
	 * 'entries' is consumed (but not freed) by
	 * crypto_load_soft_config()
	 */
	if (crypto_load_soft_config(name, count, entries) != 0) {
		kmem_free(entries, size);
		rv = CRYPTO_FAILED;
		goto out;
	}
	rv = CRYPTO_SUCCESS;
out:
	soft_config.sc_return_value = rv;

	if (copyout(&soft_config, arg, sizeof (soft_config)) != 0) {
		error = EFAULT;
	}
out2:
	if (AU_AUDITING())
		audit_cryptoadm(CRYPTO_LOAD_SOFT_CONFIG, name, entries, count,
		    0, rv, error);
	return (error);
}

/*
 * This ioctl unloads the specfied cryptographic module and removes
 * its table of supported mechanisms.
 */
/* ARGSUSED */
static int
unload_soft_module(dev_t dev, caddr_t arg, int mode, int *rval)
{
	crypto_unload_soft_module_t unload_soft_module;
	char *name;
	uint32_t rv;
	int error = 0;

	rv = CRYPTO_SUCCESS;
	if (copyin(arg, &unload_soft_module,
	    sizeof (unload_soft_module)) != 0) {
		error = EFAULT;
		goto out2;
	}

	name = unload_soft_module.sm_name;
	/* make sure the name is null terminated */
	if (!null_terminated(name)) {
		unload_soft_module.sm_return_value = CRYPTO_ARGUMENTS_BAD;
		if (copyout(&unload_soft_module, arg,
		    sizeof (unload_soft_module)) != 0) {
			return (EFAULT);
		}
		return (0);
	}

	rv = crypto_unload_soft_module(name);
out:
	unload_soft_module.sm_return_value = rv;

	if (copyout(&unload_soft_module, arg,
	    sizeof (unload_soft_module)) != 0) {
		error = EFAULT;
	}
out2:
	if (AU_AUDITING())
		audit_cryptoadm(CRYPTO_UNLOAD_SOFT_MODULE, name, NULL, 0, 0,
		    rv, error);

	return (error);
}

static int
cryptoadm_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *c,
    int *rval)
{
	int error;
#define	ARG	((caddr_t)arg)

	switch (cmd) {
	case CRYPTO_LOAD_DEV_DISABLED:
	case CRYPTO_LOAD_SOFT_DISABLED:
	case CRYPTO_LOAD_SOFT_CONFIG:
	case CRYPTO_UNLOAD_SOFT_MODULE:
	case CRYPTO_LOAD_DOOR:
	case CRYPTO_FIPS140_SET:
		if ((error = drv_priv(c)) != 0)
			return (error);
	default:
		break;
	}

	switch (cmd) {
	case CRYPTO_GET_DEV_LIST:
		return (get_dev_list(dev, ARG, mode, rval));

	case CRYPTO_GET_DEV_INFO:
		return (get_dev_info(dev, ARG, mode, rval));

	case CRYPTO_GET_SOFT_LIST:
		return (get_soft_list(dev, ARG, mode, rval));

	case CRYPTO_GET_SOFT_INFO:
		return (get_soft_info(dev, ARG, mode, rval));

	case CRYPTO_LOAD_DEV_DISABLED:
		return (load_dev_disabled(dev, ARG, mode, rval));

	case CRYPTO_LOAD_SOFT_DISABLED:
		return (load_soft_disabled(dev, ARG, mode, rval));

	case CRYPTO_LOAD_SOFT_CONFIG:
		return (load_soft_config(dev, ARG, mode, rval));

	case CRYPTO_UNLOAD_SOFT_MODULE:
		return (unload_soft_module(dev, ARG, mode, rval));
	}

	return (EINVAL);
}
