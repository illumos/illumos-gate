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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copyright 2019 Joyent, Inc.
 */


#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/processor.h>
#include <sys/cpuvar.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/policy.h>

#include <sys/auxv.h>
#include <sys/cpuid_drv.h>
#include <sys/systeminfo.h>

#if defined(__x86)
#include <sys/x86_archext.h>
#endif

static dev_info_t *cpuid_devi;

/*ARGSUSED*/
static int
cpuid_getinfo(dev_info_t *devi, ddi_info_cmd_t cmd, void *arg, void **result)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
	case DDI_INFO_DEVT2INSTANCE:
		break;
	default:
		return (DDI_FAILURE);
	}

	switch (getminor((dev_t)arg)) {
	case CPUID_SELF_CPUID_MINOR:
		break;
	default:
		return (DDI_FAILURE);
	}

	if (cmd == DDI_INFO_DEVT2INSTANCE)
		*result = 0;
	else
		*result = cpuid_devi;
	return (DDI_SUCCESS);
}

static int
cpuid_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);
	cpuid_devi = devi;

	return (ddi_create_minor_node(devi, CPUID_DRIVER_SELF_NODE, S_IFCHR,
	    CPUID_SELF_CPUID_MINOR, DDI_PSEUDO, 0));
}

static int
cpuid_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);
	ddi_remove_minor_node(devi, NULL);
	cpuid_devi = NULL;
	return (DDI_SUCCESS);
}

/*ARGSUSED1*/
static int
cpuid_open(dev_t *dev, int flag, int otyp, cred_t *cr)
{
	return (getminor(*dev) == CPUID_SELF_CPUID_MINOR ? 0 : ENXIO);
}

#if defined(_HAVE_CPUID_INSN)

/*ARGSUSED*/
static int
cpuid_read(dev_t dev, uio_t *uio, cred_t *cr)
{
	struct cpuid_regs crs;
	int error = 0;

	if (!is_x86_feature(x86_featureset, X86FSET_CPUID))
		return (ENXIO);

	if (uio->uio_resid & (sizeof (crs) - 1))
		return (EINVAL);

	while (uio->uio_resid > 0) {
		u_offset_t uoff;

		if ((uoff = (u_offset_t)uio->uio_loffset) > UINT_MAX) {
			error = EINVAL;
			break;
		}

		crs.cp_eax = (uint32_t)uoff;
		crs.cp_ebx = crs.cp_ecx = crs.cp_edx = 0;
		(void) cpuid_insn(NULL, &crs);

		if ((error = uiomove(&crs, sizeof (crs), UIO_READ, uio)) != 0)
			break;
		uio->uio_loffset = uoff + 1;
	}

	return (error);
}

#else

#define	cpuid_read	nodev

#endif	/* _HAVE_CPUID_INSN */

/*ARGSUSED*/
static int
cpuid_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cr, int *rval)
{
	char areq[16];
	void *ustr;

	switch (cmd) {
	case CPUID_GET_HWCAP: {
		STRUCT_DECL(cpuid_get_hwcap, h);

		STRUCT_INIT(h, mode);
		if (ddi_copyin((void *)arg,
		    STRUCT_BUF(h), STRUCT_SIZE(h), mode))
			return (EFAULT);
		if ((ustr = STRUCT_FGETP(h, cgh_archname)) != NULL &&
		    copyinstr(ustr, areq, sizeof (areq), NULL) != 0)
			return (EFAULT);
		areq[sizeof (areq) - 1] = '\0';

		if (strcmp(areq, architecture) == 0) {
			STRUCT_FSET(h, cgh_hwcap[0], auxv_hwcap);
			STRUCT_FSET(h, cgh_hwcap[1], auxv_hwcap_2);
#if defined(_SYSCALL32_IMPL)
		} else if (strcmp(areq, architecture_32) == 0) {
			STRUCT_FSET(h, cgh_hwcap[0], auxv_hwcap32);
			STRUCT_FSET(h, cgh_hwcap[1], auxv_hwcap32_2);
#endif
		} else {
			STRUCT_FSET(h, cgh_hwcap[0], 0);
			STRUCT_FSET(h, cgh_hwcap[1], 0);
		}
		if (ddi_copyout(STRUCT_BUF(h),
		    (void *)arg, STRUCT_SIZE(h), mode))
			return (EFAULT);
		return (0);
	}

#ifdef __x86
	case CPUID_RDMSR: {
		struct cpuid_rdmsr crm = { 0, };
		label_t label;

		if (secpolicy_sys_config(cr, B_FALSE) != 0)
			return (EPERM);

		if (ddi_copyin((void *)arg, &crm, sizeof (crm), mode))
			return (EFAULT);

		kpreempt_disable();

		if (on_fault(&label)) {
			kpreempt_enable();
			return (ENOENT);
		}

		crm.cr_msr_val = rdmsr(crm.cr_msr_nr);

		no_fault();
		kpreempt_enable();

		if (ddi_copyout(&crm, (void *)arg, sizeof (crm), mode))
			return (EFAULT);
		return (0);
	}
#endif

	default:
		return (ENOTTY);
	}
}

static struct cb_ops cpuid_cb_ops = {
	cpuid_open,
	nulldev,	/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	cpuid_read,
	nodev,		/* write */
	cpuid_ioctl,
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* poll */
	ddi_prop_op,
	NULL,
	D_64BIT | D_NEW | D_MP
};

static struct dev_ops cpuid_dv_ops = {
	DEVO_REV,
	0,
	cpuid_getinfo,
	nulldev,	/* identify */
	nulldev,	/* probe */
	cpuid_attach,
	cpuid_detach,
	nodev,		/* reset */
	&cpuid_cb_ops,
	(struct bus_ops *)0,
	NULL,
	ddi_quiesce_not_needed,		/* quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"cpuid driver",
	&cpuid_dv_ops
};

static struct modlinkage modl = {
	MODREV_1,
	&modldrv
};

int
_init(void)
{
	return (mod_install(&modl));
}

int
_fini(void)
{
	return (mod_remove(&modl));
}

int
_info(struct modinfo *modinfo)
{
	return (mod_info(&modl, modinfo));
}
