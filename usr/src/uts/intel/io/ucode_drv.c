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
 *
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/policy.h>
#include <sys/processor.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/auxv.h>
#include <sys/ucode.h>
#include <sys/systeminfo.h>
#include <sys/x86_archext.h>

static dev_info_t *ucode_devi;
static uint32_t ucode_max_combined_size;
static kmutex_t ucode_update_lock;

static int
ucode_getinfo(dev_info_t *devi, ddi_info_cmd_t cmd, void *arg, void **result)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
	case DDI_INFO_DEVT2INSTANCE:
		break;
	default:
		return (DDI_FAILURE);
	}

	switch (getminor((dev_t)arg)) {
	case UCODE_MINOR:
		break;
	default:
		return (DDI_FAILURE);
	}

	if (cmd == DDI_INFO_DEVT2INSTANCE)
		*result = 0;
	else
		*result = ucode_devi;
	return (DDI_SUCCESS);
}

static int
ucode_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	ASSERT(cmd != DDI_RESUME);

	switch (cmd) {
	case DDI_RESUME:
		return (DDI_SUCCESS);

	case DDI_ATTACH:
		ucode_devi = devi;
		ucode_max_combined_size = UCODE_MAX_COMBINED_SIZE;

		if (ddi_create_minor_node(devi, UCODE_NODE_NAME, S_IFCHR,
		    UCODE_MINOR, DDI_PSEUDO, 0) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "%s: Unable to create minor node",
			    UCODE_NODE_NAME);
			return (DDI_FAILURE);
		}
		ddi_report_dev(devi);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static int
ucode_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	/*
	 * The power management and DR framework should never invoke this
	 * driver with DDI_SUSPEND because the ucode pseudo device does not
	 * have a reg property or hardware binding.  However, we will return
	 * DDI_SUCCESS so that in the unlikely event that it does get
	 * called, the system will still suspend and resume.
	 */
	ASSERT(cmd != DDI_SUSPEND);

	switch (cmd) {
	case DDI_SUSPEND:
		return (DDI_SUCCESS);

	case DDI_DETACH:
		ddi_remove_minor_node(devi, NULL);
		ucode_devi = NULL;
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

static int
ucode_open(dev_t *dev, int flag, int otyp, cred_t *cr)
{
	return (getminor(*dev) == UCODE_MINOR ? 0 : ENXIO);
}

static int
ucode_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cr, int *rval)
{
	switch (cmd) {
	case UCODE_GET_VERSION: {
		int size;
		uint32_t *revp, *rev_array;
		size_t bufsz = NCPU * sizeof (*revp);
		ucode_errno_t rc = EM_OK;

		STRUCT_DECL(ucode_get_rev_struct, h);
		STRUCT_INIT(h, mode);
		if (ddi_copyin((void *)arg,
		    STRUCT_BUF(h), STRUCT_SIZE(h), mode))
			return (EFAULT);

		if ((size = STRUCT_FGET(h, ugv_size)) > NCPU || size < 0)
			return (EINVAL);

		if (size == 0)
			return (0);

		if ((rev_array = STRUCT_FGETP(h, ugv_rev)) == NULL)
			return (EINVAL);

		size *= sizeof (uint32_t);

		/* Can't rely on caller for kernel's buffer size. */
		revp = kmem_zalloc(bufsz, KM_SLEEP);
		if (ddi_copyin((void *)rev_array, revp, size, mode) != 0) {
			kmem_free(revp, bufsz);
			return (EINVAL);
		}

		rc = ucode_get_rev(revp);

		STRUCT_FSET(h, ugv_errno, rc);

		if (ddi_copyout(revp, (void *)rev_array, size, mode) != 0) {
			kmem_free(revp, bufsz);
			return (EFAULT);
		}

		kmem_free(revp, bufsz);

		if (ddi_copyout(STRUCT_BUF(h), (void *)arg,
		    STRUCT_SIZE(h), mode))
			return (EFAULT);

		return (0);
	}

	case UCODE_UPDATE: {
		int size;
		uint8_t *ucodep, *uw_ucode;
		ucode_errno_t rc = EM_OK;

		/*
		 * Requires all privilege.
		 */
		if (cr && secpolicy_ucode_update(cr))
			return (EPERM);

		STRUCT_DECL(ucode_write_struct, h);

		STRUCT_INIT(h, mode);
		if (ddi_copyin((void *)arg, STRUCT_BUF(h), STRUCT_SIZE(h),
		    mode))
			return (EFAULT);

		/*
		 * We allow the size of the combined microcode file to be up to
		 * ucode_max_combined_size.  It is initialized to
		 * UCODE_MAX_COMBINED_SIZE, and can be patched if necessary.
		 */
		size = STRUCT_FGET(h, uw_size);
		if (size > ucode_max_combined_size || size == 0)
			return (EINVAL);

		if ((uw_ucode = STRUCT_FGETP(h, uw_ucode)) == NULL)
			return (EINVAL);

		ucodep = kmem_zalloc(size, KM_SLEEP);
		if (ddi_copyin((void *)uw_ucode, ucodep, size, mode) != 0) {
			kmem_free(ucodep, size);
			return (EFAULT);
		}

		if ((rc = ucode_validate(ucodep, size)) != EM_OK) {
			kmem_free(ucodep, size);
			STRUCT_FSET(h, uw_errno, rc);
			if (ddi_copyout(STRUCT_BUF(h), (void *)arg,
			    STRUCT_SIZE(h), mode))
				return (EFAULT);
			return (0);
		}

		mutex_enter(&ucode_update_lock);
		rc = ucode_update(ucodep, size);
		mutex_exit(&ucode_update_lock);

		kmem_free(ucodep, size);

		STRUCT_FSET(h, uw_errno, rc);
		if (ddi_copyout(STRUCT_BUF(h), (void *)arg,
		    STRUCT_SIZE(h), mode))
			return (EFAULT);

		/*
		 * Even if rc is not EM_OK, it is a successful operation
		 * from ioctl()'s perspective.  We return the detailed error
		 * code via the ucode_write_struct data structure.
		 */
		return (0);
	}


	default:
		return (ENOTTY);
	}
}

static struct cb_ops ucode_cb_ops = {
	ucode_open,
	nulldev,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	ucode_ioctl,
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,
	NULL,
	D_64BIT | D_NEW | D_MP
};

static struct dev_ops ucode_dv_ops = {
	DEVO_REV,
	0,
	ucode_getinfo,
	nulldev,		/* identify */
	nulldev,		/* probe */
	ucode_attach,
	ucode_detach,
	nodev,			/* reset */
	&ucode_cb_ops,
	(struct bus_ops *)0,
	NULL,			/* power */
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"ucode driver",
	&ucode_dv_ops
};

static struct modlinkage modl = {
	MODREV_1,
	&modldrv
};

int
_init(void)
{
	int rc;

	if ((rc = mod_install(&modl)) != 0)
		return (rc);

	mutex_init(&ucode_update_lock, NULL, MUTEX_DRIVER, NULL);

	return (0);
}

int
_fini(void)
{
	int rc;

	if ((rc = mod_remove(&modl)) != 0)
		return (rc);

	mutex_destroy(&ucode_update_lock);

	return (0);
}

int
_info(struct modinfo *modinfo)
{
	return (mod_info(&modl, modinfo));
}
