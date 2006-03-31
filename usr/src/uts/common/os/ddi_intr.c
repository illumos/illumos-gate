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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/note.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/avintr.h>
#include <sys/autoconf.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>	/* include prototypes */
#include <sys/atomic.h>

/*
 * New DDI interrupt framework
 */

/*
 * MSI/X allocation limit.
 * This limit will change with Resource Management support.
 */
uint_t		ddi_msix_alloc_limit = 2;

/*
 * ddi_intr_get_supported_types:
 *	Return, as a bit mask, the hardware interrupt types supported by
 *	both the device and by the host in the integer pointed
 *	to be the 'typesp' argument.
 */
int
ddi_intr_get_supported_types(dev_info_t *dip, int *typesp)
{
	int			ret;
	ddi_intr_handle_impl_t	hdl;

	if (dip == NULL)
		return (DDI_EINVAL);

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_get_supported_types: dip %p\n",
	    (void *)dip));

	if (*typesp = i_ddi_intr_get_supported_types(dip))
		return (DDI_SUCCESS);

	bzero(&hdl, sizeof (ddi_intr_handle_impl_t));
	hdl.ih_dip = dip;

	ret = i_ddi_intr_ops(dip, dip, DDI_INTROP_SUPPORTED_TYPES, &hdl,
	    (void *)typesp);

	if (ret != DDI_SUCCESS)
		return (DDI_INTR_NOTFOUND);

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_get_supported_types: types %x\n",
	    *typesp));

	return (ret);
}


/*
 * ddi_intr_get_nintrs:
 * 	Return as an integer in the integer pointed to by the argument
 * 	*nintrsp*, the number of interrupts the device supports for the
 *	given interrupt type.
 */
int
ddi_intr_get_nintrs(dev_info_t *dip, int type, int *nintrsp)
{
	int			ret;
	ddi_intr_handle_impl_t	hdl;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_get_nintrs: dip %p, type: %d\n",
	    (void *)dip, type));

	if ((dip == NULL) || (type & ~(DDI_INTR_SUP_TYPES))) {
		*nintrsp = 0;
		return (DDI_EINVAL);
	}

	if (!(i_ddi_intr_get_supported_types(dip) & type)) {
		*nintrsp = 0;
		return (DDI_EINVAL);
	}

	if (*nintrsp = i_ddi_intr_get_supported_nintrs(dip, type))
		return (DDI_SUCCESS);

	bzero(&hdl, sizeof (ddi_intr_handle_impl_t));
	hdl.ih_dip = dip;
	hdl.ih_type = type;

	ret = i_ddi_intr_ops(dip, dip, DDI_INTROP_NINTRS, &hdl,
	    (void *)nintrsp);

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_get_nintrs:: nintrs %x\n",
	    *nintrsp));

	return (ret);
}


/*
 * ddi_intr_get_navail:
 *	Bus nexus driver will return availble interrupt count value for
 *	a given interrupt type.
 *
 * 	Return as an integer in the integer pointed to by the argument
 * 	*navailp*, the number of interrupts currently available for the
 *	given interrupt type.
 */
int
ddi_intr_get_navail(dev_info_t *dip, int type, int *navailp)
{
	int			ret;
	ddi_intr_handle_impl_t	hdl;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_get_navail: dip %p, type: %d\n",
	    (void *)dip, type));

	if ((dip == NULL) || (type & ~(DDI_INTR_SUP_TYPES))) {
		*navailp = 0;
		return (DDI_EINVAL);
	}

	if (!(i_ddi_intr_get_supported_types(dip) & type)) {
		*navailp = 0;
		return (DDI_EINVAL);
	}

	/*
	 * In future, this interface implementation will change
	 * with Resource Management support.
	 */
	bzero(&hdl, sizeof (ddi_intr_handle_impl_t));
	hdl.ih_dip = dip;
	hdl.ih_type = type;

	ret = i_ddi_intr_ops(dip, dip, DDI_INTROP_NAVAIL, &hdl,
	    (void *)navailp);

	return (ret == DDI_SUCCESS ? DDI_SUCCESS : DDI_INTR_NOTFOUND);
}


/*
 * Interrupt allocate/free functions
 */
int
ddi_intr_alloc(dev_info_t *dip, ddi_intr_handle_t *h_array, int type, int inum,
    int count, int *actualp, int behavior)
{
	ddi_intr_handle_impl_t	*hdlp, tmp_hdl;
	int			i, ret, cap = 0, intr_type, nintrs = 0;
	uint_t			pri;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_alloc: name %s dip 0x%p "
	    "type %x inum %x count %x behavior %x\n", ddi_driver_name(dip),
	    (void *)dip, type, inum, count, behavior));

	/* Validate parameters */
	if (dip == NULL || h_array == NULL || count < 1) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_intr_alloc: Invalid args\n"));
		return (DDI_EINVAL);
	}

	/* Validate interrupt type */
	if (!(i_ddi_intr_get_supported_types(dip) & type)) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_intr_alloc: type %x not "
		    "supported\n", type));
		return (DDI_EINVAL);
	}

	/* First, get how many interrupts the device supports */
	if (!(nintrs = i_ddi_intr_get_supported_nintrs(dip, type))) {
		if (ddi_intr_get_nintrs(dip, type, &nintrs) != DDI_SUCCESS) {
			DDI_INTR_APIDBG((CE_CONT, "ddi_intr_alloc: no "
			    "interrupts found of type %d\n", type));
			return (DDI_INTR_NOTFOUND);
		}
	}

	/* Is this function invoked with more interrupt than device supports? */
	if (count > nintrs) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_intr_alloc: no of interrupts "
		    "requested %d is more than supported %d\n", count, nintrs));
		return (DDI_EINVAL);
	}

	/*
	 * Check if requested interrupt type is not same as interrupt
	 * type is in use if any.
	 */
	if (((intr_type = i_ddi_intr_get_current_type(dip)) != 0) &&
	    (intr_type != type)) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_intr_alloc: Requested "
		    "interrupt type %x is different from interrupt type %x"
		    "already in use\n", type, intr_type));

		return (DDI_EINVAL);
	}

	/*
	 * Check if requested interrupt type is in use and requested number
	 * of interrupts and number of interrupts already in use exceeds the
	 * number of interrupts supported by this device.
	 */
	if (intr_type) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_intr_alloc: type %x "
		    "is already being used\n", type));

		if ((count + i_ddi_intr_get_current_nintrs(dip)) > nintrs) {
			DDI_INTR_APIDBG((CE_CONT, "ddi_intr_alloc: count %d "
			    "+ intrs in use %d exceeds supported %d intrs\n",
			    count, i_ddi_intr_get_current_nintrs(dip), nintrs));
			return (DDI_EINVAL);
		}
	}

	/*
	 * For MSI, ensure that the requested interrupt count is a power of 2
	 */
	if (type == DDI_INTR_TYPE_MSI && !ISP2(count)) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_intr_alloc: "
		    "MSI count %d is not a power of two\n", count));
		return (DDI_EINVAL);
	}

	/*
	 * Limit max MSI/X allocation to ddi_msix_alloc_limit.
	 * This limit will change with Resource Management support.
	 */
	if (DDI_INTR_IS_MSI_OR_MSIX(type) && (count > ddi_msix_alloc_limit)) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_intr_alloc: Requested MSI/Xs %d"
		    "Max MSI/Xs limit %d\n", count, ddi_msix_alloc_limit));

		if (behavior == DDI_INTR_ALLOC_STRICT) {
			DDI_INTR_APIDBG((CE_CONT, "ddi_intr_alloc: "
			    "DDI_INTR_ALLOC_STRICT flag is passed, "
			    "return failure\n"));

			return (DDI_EAGAIN);
		}

		count = ddi_msix_alloc_limit;
	}

	/* Now allocate required number of interrupts */
	bzero(&tmp_hdl, sizeof (ddi_intr_handle_impl_t));
	tmp_hdl.ih_type = type;
	tmp_hdl.ih_inum = inum;
	tmp_hdl.ih_scratch1 = count;
	tmp_hdl.ih_scratch2 = (void *)(uintptr_t)behavior;
	tmp_hdl.ih_dip = dip;

	i_ddi_intr_devi_init(dip);

	if (i_ddi_intr_ops(dip, dip, DDI_INTROP_ALLOC,
	    &tmp_hdl, (void *)actualp) != DDI_SUCCESS) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_intr_alloc: allocation "
		    "failed\n"));
		i_ddi_intr_devi_fini(dip);
		return (*actualp ? DDI_EAGAIN : DDI_INTR_NOTFOUND);
	}

	if ((ret = i_ddi_intr_ops(dip, dip, DDI_INTROP_GETPRI,
	    &tmp_hdl, (void *)&pri)) != DDI_SUCCESS) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_intr_alloc: get priority "
		    "failed\n"));
		goto fail;
	}

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_alloc: getting capability\n"));

	if ((ret = i_ddi_intr_ops(dip, dip, DDI_INTROP_GETCAP,
	    &tmp_hdl, (void *)&cap)) != DDI_SUCCESS) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_intr_alloc: get capability "
		    "failed\n"));
		goto fail;
	}

	/*
	 * Save current interrupt type, supported and current intr count.
	 */
	i_ddi_intr_set_current_type(dip, type);
	i_ddi_intr_set_supported_nintrs(dip, nintrs);
	i_ddi_intr_set_current_nintrs(dip,
	    i_ddi_intr_get_current_nintrs(dip) + *actualp);

	/* Now, go and handle each "handle" */
	for (i = 0; i < *actualp; i++) {
		hdlp = (ddi_intr_handle_impl_t *)kmem_zalloc(
		    (sizeof (ddi_intr_handle_impl_t)), KM_SLEEP);
		rw_init(&hdlp->ih_rwlock, NULL, RW_DRIVER, NULL);
		h_array[i] = (struct __ddi_intr_handle *)hdlp;
		hdlp->ih_type = type;
		hdlp->ih_pri = pri;
		hdlp->ih_cap = cap;
		hdlp->ih_ver = DDI_INTR_VERSION;
		hdlp->ih_state = DDI_IHDL_STATE_ALLOC;
		hdlp->ih_dip = dip;
		hdlp->ih_inum = inum + i;
		i_ddi_alloc_intr_phdl(hdlp);
		if (type & DDI_INTR_TYPE_FIXED)
			i_ddi_set_intr_handle(dip, hdlp->ih_inum, &h_array[i]);

		DDI_INTR_APIDBG((CE_CONT, "ddi_intr_alloc: hdlp = 0x%p\n",
		    (void *)h_array[i]));
	}

	return (DDI_SUCCESS);

fail:
	(void) i_ddi_intr_ops(tmp_hdl.ih_dip, tmp_hdl.ih_dip,
	    DDI_INTROP_FREE, &tmp_hdl, NULL);
	i_ddi_intr_devi_fini(dip);

	return (ret);
}


int
ddi_intr_free(ddi_intr_handle_t h)
{
	ddi_intr_handle_impl_t	*hdlp = (ddi_intr_handle_impl_t *)h;
	int			ret;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_free: hdlp = %p\n", (void *)hdlp));

	if (hdlp == NULL)
		return (DDI_EINVAL);

	rw_enter(&hdlp->ih_rwlock, RW_WRITER);
	if (((hdlp->ih_flags & DDI_INTR_MSIX_DUP) &&
	    (hdlp->ih_state != DDI_IHDL_STATE_ADDED)) ||
	    ((hdlp->ih_state != DDI_IHDL_STATE_ALLOC) &&
	    (!(hdlp->ih_flags & DDI_INTR_MSIX_DUP)))) {
		rw_exit(&hdlp->ih_rwlock);
		return (DDI_EINVAL);
	}

	ret = i_ddi_intr_ops(hdlp->ih_dip, hdlp->ih_dip,
	    DDI_INTROP_FREE, hdlp, NULL);

	rw_exit(&hdlp->ih_rwlock);
	if (ret == DDI_SUCCESS) {
		/* This would be the dup vector */
		if (hdlp->ih_flags & DDI_INTR_MSIX_DUP)
			atomic_dec_32(&hdlp->ih_main->ih_dup_cnt);
		else {
			i_ddi_intr_set_current_nintrs(hdlp->ih_dip,
			    i_ddi_intr_get_current_nintrs(hdlp->ih_dip) - 1);

			if (i_ddi_intr_get_current_nintrs(hdlp->ih_dip) == 0) {
				i_ddi_intr_devi_fini(hdlp->ih_dip);
			} else {
				if (hdlp->ih_type & DDI_INTR_TYPE_FIXED)
					i_ddi_set_intr_handle(hdlp->ih_dip,
					    hdlp->ih_inum, NULL);
			}

			i_ddi_free_intr_phdl(hdlp);
		}
		rw_destroy(&hdlp->ih_rwlock);
		kmem_free(hdlp, sizeof (ddi_intr_handle_impl_t));
	}

	return (ret);
}

/*
 * Interrupt get/set capacity functions
 *
 * The logic used to figure this out is shown here:
 *
 *			Device level		Platform level	    Intr source
 * 1. Fixed interrupts
 * (non-PCI)
 * o Flags supported	N/A			Maskable/Pending/    rootnex
 *						No Block Enable
 * o navail					1
 *
 * 2. PCI Fixed interrupts
 * o Flags supported	pending/Maskable	Maskable/pending/    pci
 *						No Block enable
 * o navail		N/A			1
 *
 * 3. PCI MSI
 * o Flags supported	Maskable/Pending	Maskable/Pending    pci
 *			Block Enable		(if drvr doesn't)   Block Enable
 * o navail		N/A			#vectors - #used    N/A
 *
 * 4. PCI MSI-X
 * o Flags supported	Maskable/Pending	Maskable/Pending    pci
 *			Block Enable				    Block Enable
 * o navail		N/A			#vectors - #used    N/A
 *
 * where:
 *	#vectors	- Total numbers of vectors available
 *	#used		- Total numbers of vectors currently being used
 *
 * For devices complying to PCI2.3 or greater, see bit10 of Command Register
 * 0 - enables assertion of INTx
 * 1 - disables assertion of INTx
 *
 * For non MSI/X interrupts; if the IRQ is shared then all ddi_intr_set_*()
 * operations return failure.
 */
int
ddi_intr_get_cap(ddi_intr_handle_t h, int *flagsp)
{
	ddi_intr_handle_impl_t	*hdlp = (ddi_intr_handle_impl_t *)h;
	int			ret;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_get_cap: hdlp = %p\n",
	    (void *)hdlp));

	*flagsp = 0;
	if (hdlp == NULL)
		return (DDI_EINVAL);

	rw_enter(&hdlp->ih_rwlock, RW_READER);

	if (hdlp->ih_cap) {
		*flagsp = hdlp->ih_cap & ~DDI_INTR_FLAG_MSI64;
		rw_exit(&hdlp->ih_rwlock);
		return (DDI_SUCCESS);
	}

	ret = i_ddi_intr_ops(hdlp->ih_dip, hdlp->ih_dip,
	    DDI_INTROP_GETCAP, hdlp, (void *)flagsp);

	if (ret == DDI_SUCCESS) {
		hdlp->ih_cap = *flagsp;

		/* Mask out MSI/X 64-bit support to the consumer */
		*flagsp &= ~DDI_INTR_FLAG_MSI64;
	}

	rw_exit(&hdlp->ih_rwlock);
	return (ret);
}

int
ddi_intr_set_cap(ddi_intr_handle_t h, int flags)
{
	ddi_intr_handle_impl_t	*hdlp = (ddi_intr_handle_impl_t *)h;
	int			ret;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_set_cap: hdlp = %p", (void *)hdlp));

	if (hdlp == NULL)
		return (DDI_EINVAL);

	rw_enter(&hdlp->ih_rwlock, RW_WRITER);
	if (hdlp->ih_state != DDI_IHDL_STATE_ALLOC) {
		rw_exit(&hdlp->ih_rwlock);
		return (DDI_EINVAL);
	}

	/* Only DDI_INTR_FLAG_LEVEL or DDI_INTR_FLAG_EDGE are allowed */
	if (!(flags & (DDI_INTR_FLAG_EDGE | DDI_INTR_FLAG_LEVEL))) {
		DDI_INTR_APIDBG((CE_CONT, "%s%d: only LEVEL or EDGE capability "
		    "can be set\n", ddi_driver_name(hdlp->ih_dip),
		    ddi_get_instance(hdlp->ih_dip)));
		rw_exit(&hdlp->ih_rwlock);
		return (DDI_EINVAL);
	}

	/* Both level/edge flags must be currently supported */
	if (!(hdlp->ih_cap & (DDI_INTR_FLAG_EDGE | DDI_INTR_FLAG_LEVEL))) {
		DDI_INTR_APIDBG((CE_CONT, "%s%d: Both LEVEL and EDGE capability"
		    " must be supported\n", ddi_driver_name(hdlp->ih_dip),
		    ddi_get_instance(hdlp->ih_dip)));
		rw_exit(&hdlp->ih_rwlock);
		return (DDI_ENOTSUP);
	}

	ret = i_ddi_intr_ops(hdlp->ih_dip, hdlp->ih_dip,
	    DDI_INTROP_SETCAP, hdlp, &flags);

	rw_exit(&hdlp->ih_rwlock);
	return (ret);
}

/*
 * Priority related functions
 */

/*
 * ddi_intr_get_hilevel_pri:
 *	Returns the minimum priority level for a
 *	high-level interrupt on a platform.
 */
uint_t
ddi_intr_get_hilevel_pri(void)
{
	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_get_hilevel_pri:\n"));
	return (LOCK_LEVEL + 1);
}

int
ddi_intr_get_pri(ddi_intr_handle_t h, uint_t *prip)
{
	ddi_intr_handle_impl_t	*hdlp = (ddi_intr_handle_impl_t *)h;
	int			ret;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_get_pri: hdlp = %p\n",
	    (void *)hdlp));

	*prip = 0;
	if (hdlp == NULL)
		return (DDI_EINVAL);

	rw_enter(&hdlp->ih_rwlock, RW_READER);
	/* Already initialized, just return that */
	if (hdlp->ih_pri) {
		*prip = hdlp->ih_pri;
		rw_exit(&hdlp->ih_rwlock);
		return (DDI_SUCCESS);
	}

	ret = i_ddi_intr_ops(hdlp->ih_dip, hdlp->ih_dip,
	    DDI_INTROP_GETPRI, hdlp, (void *)prip);

	if (ret == DDI_SUCCESS)
		hdlp->ih_pri = *prip;

	rw_exit(&hdlp->ih_rwlock);
	return (ret);
}

int
ddi_intr_set_pri(ddi_intr_handle_t h, uint_t pri)
{
	ddi_intr_handle_impl_t	*hdlp = (ddi_intr_handle_impl_t *)h;
	int			ret;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_set_pri: hdlp = %p", (void *)hdlp));

	if (hdlp == NULL)
		return (DDI_EINVAL);

	/* Validate priority argument */
	if (pri < DDI_INTR_PRI_MIN || pri > DDI_INTR_PRI_MAX) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_intr_set_pri: invalid priority "
		    "specified  = %x\n", pri));
		return (DDI_EINVAL);
	}

	rw_enter(&hdlp->ih_rwlock, RW_WRITER);
	if (hdlp->ih_state != DDI_IHDL_STATE_ALLOC) {
		rw_exit(&hdlp->ih_rwlock);
		return (DDI_EINVAL);
	}

	/* If the passed priority is same as existing priority; do nothing */
	if (pri == hdlp->ih_pri) {
		rw_exit(&hdlp->ih_rwlock);
		return (DDI_SUCCESS);
	}

	ret = i_ddi_intr_ops(hdlp->ih_dip, hdlp->ih_dip,
	    DDI_INTROP_SETPRI, hdlp, &pri);

	if (ret == DDI_SUCCESS)
		hdlp->ih_pri = pri;

	rw_exit(&hdlp->ih_rwlock);
	return (ret);
}

/*
 * Interrupt add/duplicate/remove handlers
 */
int
ddi_intr_add_handler(ddi_intr_handle_t h, ddi_intr_handler_t inthandler,
    void *arg1, void *arg2)
{
	ddi_intr_handle_impl_t	*hdlp = (ddi_intr_handle_impl_t *)h;
	int			ret;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_add_handler: hdlp = 0x%p\n",
	    (void *)hdlp));

	if ((hdlp == NULL) || (inthandler == NULL))
		return (DDI_EINVAL);

	rw_enter(&hdlp->ih_rwlock, RW_WRITER);
	if (hdlp->ih_state != DDI_IHDL_STATE_ALLOC) {
		rw_exit(&hdlp->ih_rwlock);
		return (DDI_EINVAL);
	}

	hdlp->ih_cb_func = inthandler;
	hdlp->ih_cb_arg1 = arg1;
	hdlp->ih_cb_arg2 = arg2;

	ret = i_ddi_intr_ops(hdlp->ih_dip, hdlp->ih_dip,
	    DDI_INTROP_ADDISR, hdlp, NULL);

	if (ret != DDI_SUCCESS) {
		hdlp->ih_cb_func = NULL;
		hdlp->ih_cb_arg1 = NULL;
		hdlp->ih_cb_arg2 = NULL;
	} else
		hdlp->ih_state = DDI_IHDL_STATE_ADDED;

	rw_exit(&hdlp->ih_rwlock);
	return (ret);
}

int
ddi_intr_dup_handler(ddi_intr_handle_t org, int dup_inum,
    ddi_intr_handle_t *dup)
{
	ddi_intr_handle_impl_t	*hdlp = (ddi_intr_handle_impl_t *)org;
	ddi_intr_handle_impl_t	*dup_hdlp;
	int			ret;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_dup_handler: hdlp = 0x%p\n",
	    (void *)hdlp));

	/* Do some input argument checking ("dup" handle is not allocated) */
	if ((hdlp == NULL) || (*dup != NULL))
		return (DDI_EINVAL);

	rw_enter(&hdlp->ih_rwlock, RW_READER);

	/* Do some input argument checking */
	if ((hdlp->ih_state == DDI_IHDL_STATE_ALLOC) ||	/* intr handle alloc? */
	    (hdlp->ih_type != DDI_INTR_TYPE_MSIX) ||	/* only MSI-X allowed */
	    (hdlp->ih_flags & DDI_INTR_MSIX_DUP)) {	/* only dup original */
		rw_exit(&hdlp->ih_rwlock);
		return (DDI_EINVAL);
	}

	hdlp->ih_scratch1 = dup_inum;
	ret = i_ddi_intr_ops(hdlp->ih_dip, hdlp->ih_dip,
	    DDI_INTROP_DUPVEC, hdlp, NULL);

	if (ret == DDI_SUCCESS) {
		dup_hdlp = (ddi_intr_handle_impl_t *)
		    kmem_alloc(sizeof (ddi_intr_handle_impl_t), KM_SLEEP);

		atomic_add_32(&hdlp->ih_dup_cnt, 1);

		*dup = (ddi_intr_handle_t)dup_hdlp;
		bcopy(hdlp, dup_hdlp, sizeof (ddi_intr_handle_impl_t));

		/* These fields are unique to each dupped msi-x vector */
		rw_init(&dup_hdlp->ih_rwlock, NULL, RW_DRIVER, NULL);
		dup_hdlp->ih_state = DDI_IHDL_STATE_ADDED;
		dup_hdlp->ih_inum = dup_inum;
		dup_hdlp->ih_flags |= DDI_INTR_MSIX_DUP;
		dup_hdlp->ih_dup_cnt = 0;

		/* Point back to original vector */
		dup_hdlp->ih_main = hdlp;
	}

	rw_exit(&hdlp->ih_rwlock);
	return (ret);
}

int
ddi_intr_remove_handler(ddi_intr_handle_t h)
{
	ddi_intr_handle_impl_t	*hdlp = (ddi_intr_handle_impl_t *)h;
	int			ret = DDI_SUCCESS;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_remove_handler: hdlp = %p\n",
	    (void *)hdlp));

	if (hdlp == NULL)
		return (DDI_EINVAL);

	rw_enter(&hdlp->ih_rwlock, RW_WRITER);

	if (hdlp->ih_state != DDI_IHDL_STATE_ADDED) {
		ret = DDI_EINVAL;
		goto done;
	} else if (hdlp->ih_flags & DDI_INTR_MSIX_DUP)
		goto done;

	ASSERT(hdlp->ih_dup_cnt == 0);
	if (hdlp->ih_dup_cnt > 0) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_intr_remove_handler: MSI-X "
		    "dup_cnt %d is not 0\n", hdlp->ih_dup_cnt));
		ret = DDI_FAILURE;
		goto done;
	}

	ret = i_ddi_intr_ops(hdlp->ih_dip, hdlp->ih_dip,
	    DDI_INTROP_REMISR, hdlp, NULL);

	if (ret == DDI_SUCCESS) {
		hdlp->ih_state = DDI_IHDL_STATE_ALLOC;
		hdlp->ih_cb_func = NULL;
		hdlp->ih_cb_arg1 = NULL;
		hdlp->ih_cb_arg2 = NULL;
	}

done:
	rw_exit(&hdlp->ih_rwlock);
	return (ret);
}

/*
 * Interrupt enable/disable/block_enable/block_disable handlers
 */
int
ddi_intr_enable(ddi_intr_handle_t h)
{
	ddi_intr_handle_impl_t	*hdlp = (ddi_intr_handle_impl_t *)h;
	int			ret;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_enable: hdlp = %p\n",
	    (void *)hdlp));

	if (hdlp == NULL)
		return (DDI_EINVAL);

	rw_enter(&hdlp->ih_rwlock, RW_WRITER);
	if ((hdlp->ih_state != DDI_IHDL_STATE_ADDED) ||
	    ((hdlp->ih_type == DDI_INTR_TYPE_MSI) &&
	    (hdlp->ih_cap & DDI_INTR_FLAG_BLOCK))) {
		rw_exit(&hdlp->ih_rwlock);
		return (DDI_EINVAL);
	}

	I_DDI_VERIFY_MSIX_HANDLE(hdlp);

	ret = i_ddi_intr_ops(hdlp->ih_dip, hdlp->ih_dip,
	    DDI_INTROP_ENABLE, hdlp, NULL);

	if (ret == DDI_SUCCESS)
		hdlp->ih_state = DDI_IHDL_STATE_ENABLE;

	rw_exit(&hdlp->ih_rwlock);
	return (ret);
}

int
ddi_intr_disable(ddi_intr_handle_t h)
{
	ddi_intr_handle_impl_t	*hdlp = (ddi_intr_handle_impl_t *)h;
	int			ret;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_disable: hdlp = %p\n",
	    (void *)hdlp));

	if (hdlp == NULL)
		return (DDI_EINVAL);

	rw_enter(&hdlp->ih_rwlock, RW_WRITER);
	if ((hdlp->ih_state != DDI_IHDL_STATE_ENABLE) ||
	    ((hdlp->ih_type == DDI_INTR_TYPE_MSI) &&
	    (hdlp->ih_cap & DDI_INTR_FLAG_BLOCK))) {
		rw_exit(&hdlp->ih_rwlock);
		return (DDI_EINVAL);
	}

	I_DDI_VERIFY_MSIX_HANDLE(hdlp);

	ret = i_ddi_intr_ops(hdlp->ih_dip, hdlp->ih_dip,
	    DDI_INTROP_DISABLE, hdlp, NULL);

	if (ret == DDI_SUCCESS)
		hdlp->ih_state = DDI_IHDL_STATE_ADDED;

	rw_exit(&hdlp->ih_rwlock);
	return (ret);
}

int
ddi_intr_block_enable(ddi_intr_handle_t *h_array, int count)
{
	ddi_intr_handle_impl_t	*hdlp;
	int			i, ret;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_block_enable: h_array = %p\n",
	    (void *)h_array));

	if (h_array == NULL)
		return (DDI_EINVAL);

	for (i = 0; i < count; i++) {
		hdlp = (ddi_intr_handle_impl_t *)h_array[i];
		rw_enter(&hdlp->ih_rwlock, RW_READER);

		if (hdlp->ih_state != DDI_IHDL_STATE_ADDED ||
		    hdlp->ih_type != DDI_INTR_TYPE_MSI ||
		    !(hdlp->ih_cap & DDI_INTR_FLAG_BLOCK)) {
			rw_exit(&hdlp->ih_rwlock);
			return (DDI_EINVAL);
		}
		rw_exit(&hdlp->ih_rwlock);
	}

	hdlp = (ddi_intr_handle_impl_t *)h_array[0];
	rw_enter(&hdlp->ih_rwlock, RW_WRITER);
	hdlp->ih_scratch1 = count;
	hdlp->ih_scratch2 = (void *)h_array;

	ret = i_ddi_intr_ops(hdlp->ih_dip, hdlp->ih_dip,
	    DDI_INTROP_BLOCKENABLE, hdlp, NULL);

	rw_exit(&hdlp->ih_rwlock);

	if (ret == DDI_SUCCESS) {
		for (i = 0; i < count; i++) {
			hdlp = (ddi_intr_handle_impl_t *)h_array[i];
			rw_enter(&hdlp->ih_rwlock, RW_WRITER);
			hdlp->ih_state = DDI_IHDL_STATE_ENABLE;
			rw_exit(&hdlp->ih_rwlock);
		}
	}

	return (ret);
}

int
ddi_intr_block_disable(ddi_intr_handle_t *h_array, int count)
{
	ddi_intr_handle_impl_t	*hdlp;
	int			i, ret;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_block_disable: h_array = %p\n",
	    (void *)h_array));

	if (h_array == NULL)
		return (DDI_EINVAL);

	for (i = 0; i < count; i++) {
		hdlp = (ddi_intr_handle_impl_t *)h_array[i];
		rw_enter(&hdlp->ih_rwlock, RW_READER);
		if (hdlp->ih_state != DDI_IHDL_STATE_ENABLE ||
		    hdlp->ih_type != DDI_INTR_TYPE_MSI ||
		    !(hdlp->ih_cap & DDI_INTR_FLAG_BLOCK)) {
			rw_exit(&hdlp->ih_rwlock);
			return (DDI_EINVAL);
		}
		rw_exit(&hdlp->ih_rwlock);
	}

	hdlp = (ddi_intr_handle_impl_t *)h_array[0];
	rw_enter(&hdlp->ih_rwlock, RW_WRITER);
	hdlp->ih_scratch1 = count;
	hdlp->ih_scratch2 = (void *)h_array;

	ret = i_ddi_intr_ops(hdlp->ih_dip, hdlp->ih_dip,
	    DDI_INTROP_BLOCKDISABLE, hdlp, NULL);

	rw_exit(&hdlp->ih_rwlock);

	if (ret == DDI_SUCCESS) {
		for (i = 0; i < count; i++) {
			hdlp = (ddi_intr_handle_impl_t *)h_array[i];
			rw_enter(&hdlp->ih_rwlock, RW_WRITER);
			hdlp->ih_state = DDI_IHDL_STATE_ADDED;
			rw_exit(&hdlp->ih_rwlock);
		}
	}

	return (ret);
}

/*
 * Interrupt set/clr mask handlers
 */
int
ddi_intr_set_mask(ddi_intr_handle_t h)
{
	ddi_intr_handle_impl_t	*hdlp = (ddi_intr_handle_impl_t *)h;
	int			ret;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_set_mask: hdlp = %p\n",
	    (void *)hdlp));

	if (hdlp == NULL)
		return (DDI_EINVAL);

	rw_enter(&hdlp->ih_rwlock, RW_WRITER);
	if ((hdlp->ih_state != DDI_IHDL_STATE_ENABLE) ||
	    (!(hdlp->ih_cap & DDI_INTR_FLAG_MASKABLE))) {
		rw_exit(&hdlp->ih_rwlock);
		return (DDI_EINVAL);
	}

	ret =  i_ddi_intr_ops(hdlp->ih_dip, hdlp->ih_dip,
	    DDI_INTROP_SETMASK, hdlp, NULL);

	rw_exit(&hdlp->ih_rwlock);
	return (ret);
}

int
ddi_intr_clr_mask(ddi_intr_handle_t h)
{
	ddi_intr_handle_impl_t	*hdlp = (ddi_intr_handle_impl_t *)h;
	int			ret;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_clr_mask: hdlp = %p\n",
	    (void *)hdlp));

	if (hdlp == NULL)
		return (DDI_EINVAL);

	rw_enter(&hdlp->ih_rwlock, RW_WRITER);
	if ((hdlp->ih_state != DDI_IHDL_STATE_ENABLE) ||
	    (!(hdlp->ih_cap & DDI_INTR_FLAG_MASKABLE))) {
		rw_exit(&hdlp->ih_rwlock);
		return (DDI_EINVAL);
	}

	ret = i_ddi_intr_ops(hdlp->ih_dip, hdlp->ih_dip,
	    DDI_INTROP_CLRMASK, hdlp, NULL);

	rw_exit(&hdlp->ih_rwlock);
	return (ret);
}

/*
 * Interrupt get_pending handler
 */
int
ddi_intr_get_pending(ddi_intr_handle_t h, int *pendingp)
{
	ddi_intr_handle_impl_t	*hdlp = (ddi_intr_handle_impl_t *)h;
	int			ret;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_get_pending: hdlp = %p\n",
	    (void *)hdlp));

	if (hdlp == NULL)
		return (DDI_EINVAL);

	rw_enter(&hdlp->ih_rwlock, RW_READER);
	if (!(hdlp->ih_cap & DDI_INTR_FLAG_PENDING)) {
		rw_exit(&hdlp->ih_rwlock);
		return (DDI_EINVAL);
	}

	ret = i_ddi_intr_ops(hdlp->ih_dip, hdlp->ih_dip,
	    DDI_INTROP_GETPENDING, hdlp, (void *)pendingp);

	rw_exit(&hdlp->ih_rwlock);
	return (ret);
}

/*
 * Soft interrupt handlers
 */
/*
 * Add a soft interrupt and register its handler
 */
/* ARGSUSED */
int
ddi_intr_add_softint(dev_info_t *dip, ddi_softint_handle_t *h_p, int soft_pri,
    ddi_intr_handler_t handler, void *arg1)
{
	ddi_softint_hdl_impl_t	*hdlp;
	int			ret;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_add_softint: dip = %p, "
	    "softpri = 0x%x\n", (void *)dip, soft_pri));

	if ((dip == NULL) || (h_p == NULL) || (handler == NULL)) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_intr_add_softint: "
		    "invalid arguments"));

		return (DDI_EINVAL);
	}

	/* Validate input arguments */
	if (soft_pri < DDI_INTR_SOFTPRI_MIN ||
	    soft_pri > DDI_INTR_SOFTPRI_MAX) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_intr_add_softint: invalid "
		    "soft_pri input given  = %x\n", soft_pri));
		return (DDI_EINVAL);
	}

	hdlp = (ddi_softint_hdl_impl_t *)kmem_zalloc(
	    sizeof (ddi_softint_hdl_impl_t), KM_SLEEP);

	/* fill up internally */
	rw_init(&hdlp->ih_rwlock, NULL, RW_DRIVER, NULL);
	rw_enter(&hdlp->ih_rwlock, RW_WRITER);
	hdlp->ih_pri = soft_pri;
	hdlp->ih_dip = dip;
	hdlp->ih_cb_func = handler;
	hdlp->ih_cb_arg1 = arg1;
	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_add_softint: hdlp = %p\n",
	    (void *)hdlp));

	/* do the platform specific calls */
	if ((ret = i_ddi_add_softint(hdlp)) != DDI_SUCCESS) {
		rw_exit(&hdlp->ih_rwlock);
		rw_destroy(&hdlp->ih_rwlock);
		kmem_free(hdlp, sizeof (ddi_softint_hdl_impl_t));
		return (ret);
	}

	*h_p = (ddi_softint_handle_t)hdlp;
	rw_exit(&hdlp->ih_rwlock);
	return (ret);
}

/*
 * Remove the soft interrupt
 */
int
ddi_intr_remove_softint(ddi_softint_handle_t h)
{
	ddi_softint_hdl_impl_t	*hdlp = (ddi_softint_hdl_impl_t *)h;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_remove_softint: hdlp = %p\n",
	    (void *)hdlp));

	if (hdlp == NULL)
		return (DDI_EINVAL);

	rw_enter(&hdlp->ih_rwlock, RW_WRITER);
	i_ddi_remove_softint(hdlp);
	rw_exit(&hdlp->ih_rwlock);
	rw_destroy(&hdlp->ih_rwlock);

	/* kmem_free the hdl impl_t structure allocated earlier */
	kmem_free(hdlp, sizeof (ddi_softint_hdl_impl_t));
	return (DDI_SUCCESS);
}

/*
 * Trigger a soft interrupt
 */
int
ddi_intr_trigger_softint(ddi_softint_handle_t h, void *arg2)
{
	ddi_softint_hdl_impl_t	*hdlp = (ddi_softint_hdl_impl_t *)h;
	int			ret;

	if (hdlp == NULL)
		return (DDI_EINVAL);

	if ((ret = i_ddi_trigger_softint(hdlp, arg2)) != DDI_SUCCESS) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_intr_trigger_softint: failed, "
		    " ret 0%x\n", ret));

		return (ret);
	}

	hdlp->ih_cb_arg2 = arg2;
	return (DDI_SUCCESS);
}

/*
 * Get the soft interrupt priority
 */
int
ddi_intr_get_softint_pri(ddi_softint_handle_t h, uint_t *soft_prip)
{
	ddi_softint_hdl_impl_t	*hdlp = (ddi_softint_hdl_impl_t *)h;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_get_softint_pri: h = %p\n",
	    (void *)h));

	if (hdlp == NULL)
		return (DDI_EINVAL);

	rw_enter(&hdlp->ih_rwlock, RW_READER);
	*soft_prip = hdlp->ih_pri;
	rw_exit(&hdlp->ih_rwlock);
	return (DDI_SUCCESS);
}

/*
 * Set the soft interrupt priority
 */
int
ddi_intr_set_softint_pri(ddi_softint_handle_t h, uint_t soft_pri)
{
	ddi_softint_hdl_impl_t	*hdlp = (ddi_softint_hdl_impl_t *)h;
	int			ret;
	uint_t			orig_soft_pri;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_set_softint_pri: h = %p\n",
	    (void *)h));

	if (hdlp == NULL)
		return (DDI_EINVAL);

	/* Validate priority argument */
	if (soft_pri < DDI_INTR_SOFTPRI_MIN ||
	    soft_pri > DDI_INTR_SOFTPRI_MAX) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_intr_set_softint_pri: invalid "
		    "soft_pri input given  = %x\n", soft_pri));
		return (DDI_EINVAL);
	}

	rw_enter(&hdlp->ih_rwlock, RW_WRITER);
	orig_soft_pri = hdlp->ih_pri;
	hdlp->ih_pri = soft_pri;

	if ((ret = i_ddi_set_softint_pri(hdlp, orig_soft_pri)) != DDI_SUCCESS) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_intr_set_softint_pri: failed, "
		    " ret 0%x\n", ret));
		hdlp->ih_pri = orig_soft_pri;
	}

	rw_exit(&hdlp->ih_rwlock);
	return (ret);
}

/*
 * Old DDI interrupt framework
 *
 * The following DDI interrupt interfaces are obsolete.
 * Use the above new DDI interrupt interfaces instead.
 */

int
ddi_intr_hilevel(dev_info_t *dip, uint_t inumber)
{
	ddi_intr_handle_t	hdl, *existing_hdlp;
	int			actual, ret;
	uint_t			high_pri, pri;

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_hilevel: name=%s%d dip=0x%p "
	    "inum=0x%x\n", ddi_driver_name(dip), ddi_get_instance(dip),
	    (void *)dip, inumber));

	/*
	 * The device driver may have already registed with the
	 * framework. If so, first try to get the existing interrupt handle
	 * for that given inumber and use that handle.
	 */
	existing_hdlp = i_ddi_get_intr_handle(dip, inumber);
	if (existing_hdlp) {
		hdl = existing_hdlp[0];	/* Use existing handle */
	} else {
		if ((ret = ddi_intr_alloc(dip, &hdl, DDI_INTR_TYPE_FIXED,
		    inumber, 1, &actual,
		    DDI_INTR_ALLOC_NORMAL)) != DDI_SUCCESS) {
			DDI_INTR_APIDBG((CE_CONT, "ddi_intr_hilevel: "
			    "ddi_intr_alloc failed, ret 0x%x\n", ret));
			return (0);
		}
	}

	if ((ret = ddi_intr_get_pri(hdl, &pri)) != DDI_SUCCESS) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_intr_hilevel: "
		    "ddi_intr_get_pri failed, ret 0x%x\n", ret));
		(void) ddi_intr_free(hdl);
		return (0);
	}

	high_pri = ddi_intr_get_hilevel_pri();

	DDI_INTR_APIDBG((CE_CONT, "ddi_intr_hilevel: pri = %x, "
	    "high_pri = %x\n", pri, high_pri));

	/* Free the handle allocated here only if no existing handle exists */
	if (existing_hdlp == NULL)
		(void) ddi_intr_free(hdl);

	return (pri >= high_pri);
}

int
ddi_dev_nintrs(dev_info_t *dip, int *result)
{
	DDI_INTR_APIDBG((CE_CONT, "ddi_dev_nintrs: name=%s%d dip=0x%p\n",
	    ddi_driver_name(dip), ddi_get_instance(dip), (void *)dip));

	if (ddi_intr_get_nintrs(dip, DDI_INTR_TYPE_FIXED,
	    result) != DDI_SUCCESS) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_dev_nintrs: "
		    "ddi_intr_get_nintrs failed\n"));
		*result = 0;
	}

	return (DDI_SUCCESS);
}

int
ddi_get_iblock_cookie(dev_info_t *dip, uint_t inumber,
    ddi_iblock_cookie_t *iblock_cookiep)
{
	ddi_intr_handle_t	hdl, *existing_hdlp;
	int			actual, ret;
	uint_t			pri;

	DDI_INTR_APIDBG((CE_CONT, "ddi_get_iblock_cookie: name=%s%d dip=0x%p "
	    "inum=0x%x\n", ddi_driver_name(dip), ddi_get_instance(dip),
	    (void *)dip, inumber));

	ASSERT(iblock_cookiep != NULL);

	/*
	 * The device driver may have already registed with the
	 * framework. If so, first try to get the existing interrupt handle
	 * for that given inumber and use that handle.
	 */
	existing_hdlp = i_ddi_get_intr_handle(dip, inumber);
	if (existing_hdlp) {
		hdl = existing_hdlp[0];	/* Use existing handle */
	} else {
		if ((ret = ddi_intr_alloc(dip, &hdl, DDI_INTR_TYPE_FIXED,
		    inumber, 1, &actual,
		    DDI_INTR_ALLOC_NORMAL)) != DDI_SUCCESS) {
			DDI_INTR_APIDBG((CE_CONT, "ddi_get_iblock_cookie: "
			    "ddi_intr_alloc failed, ret 0x%x\n", ret));
			return (DDI_INTR_NOTFOUND);
		}
	}

	if ((ret = ddi_intr_get_pri(hdl, &pri)) != DDI_SUCCESS) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_get_iblock_cookie: "
		    "ddi_intr_get_pri failed, ret 0x%x\n", ret));

		(void) ddi_intr_free(hdl);
		return (DDI_FAILURE);
	}

	*iblock_cookiep = (ddi_iblock_cookie_t)(uintptr_t)pri;
	/* Free the handle allocated here only if no existing handle exists */
	if (existing_hdlp == NULL)
		(void) ddi_intr_free(hdl);

	return (DDI_SUCCESS);
}

int
ddi_add_intr(dev_info_t *dip, uint_t inumber,
    ddi_iblock_cookie_t *iblock_cookiep,
    ddi_idevice_cookie_t *idevice_cookiep,
    uint_t (*int_handler)(caddr_t int_handler_arg),
    caddr_t int_handler_arg)
{
	ddi_intr_handle_t	*hdl_p;
	int			actual, ret;
	uint_t			pri;

	DDI_INTR_APIDBG((CE_CONT, "ddi_add_intr: name=%s%d dip=0x%p "
	    "inum=0x%x\n", ddi_driver_name(dip), ddi_get_instance(dip),
	    (void *)dip, inumber));

	hdl_p = kmem_zalloc(sizeof (ddi_intr_handle_t), KM_SLEEP);

	if ((ret = ddi_intr_alloc(dip, hdl_p, DDI_INTR_TYPE_FIXED,
	    inumber, 1, &actual, DDI_INTR_ALLOC_NORMAL)) != DDI_SUCCESS) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_add_intr: "
		    "ddi_intr_alloc failed, ret 0x%x\n", ret));
		kmem_free(hdl_p, sizeof (ddi_intr_handle_t));
		return (DDI_INTR_NOTFOUND);
	}

	if ((ret = ddi_intr_get_pri(hdl_p[0], &pri)) != DDI_SUCCESS)  {
		DDI_INTR_APIDBG((CE_CONT, "ddi_add_intr: "
		    "ddi_intr_get_pri failed, ret 0x%x\n", ret));
		(void) ddi_intr_free(hdl_p[0]);
		kmem_free(hdl_p, sizeof (ddi_intr_handle_t));
		return (DDI_FAILURE);
	}

	if ((ret = ddi_intr_add_handler(hdl_p[0], (ddi_intr_handler_t *)
	    int_handler, int_handler_arg, NULL)) != DDI_SUCCESS) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_add_intr: "
		    "ddi_intr_add_handler failed, ret 0x%x\n", ret));
		(void) ddi_intr_free(hdl_p[0]);
		kmem_free(hdl_p, sizeof (ddi_intr_handle_t));
		return (DDI_FAILURE);
	}

	if ((ret = ddi_intr_enable(hdl_p[0])) != DDI_SUCCESS) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_add_intr: "
		    "ddi_intr_enable failed, ret 0x%x\n", ret));
		(void) ddi_intr_remove_handler(hdl_p[0]);
		(void) ddi_intr_free(hdl_p[0]);
		kmem_free(hdl_p, sizeof (ddi_intr_handle_t));
		return (DDI_FAILURE);
	}

	if (iblock_cookiep)
		*iblock_cookiep = (ddi_iblock_cookie_t)(uintptr_t)pri;

	if (idevice_cookiep) {
		idevice_cookiep->idev_vector = 0;
		idevice_cookiep->idev_priority = pri;
	}

	return (DDI_SUCCESS);
}

/* ARGSUSED */
int
ddi_add_fastintr(dev_info_t *dip, uint_t inumber,
    ddi_iblock_cookie_t *iblock_cookiep,
    ddi_idevice_cookie_t *idevice_cookiep,
    uint_t (*hi_int_handler)(void))
{
	DDI_INTR_APIDBG((CE_CONT, "ddi_add_fastintr: name=%s%d dip=0x%p "
	    "inum=0x%x: Not supported, return failure\n", ddi_driver_name(dip),
	    ddi_get_instance(dip), (void *)dip, inumber));

	return (DDI_FAILURE);
}

/* ARGSUSED */
void
ddi_remove_intr(dev_info_t *dip, uint_t inum, ddi_iblock_cookie_t iblock_cookie)
{
	ddi_intr_handle_t	*hdl_p;
	int			ret;

	DDI_INTR_APIDBG((CE_CONT, "ddi_remove_intr: name=%s%d dip=0x%p "
	    "inum=0x%x\n", ddi_driver_name(dip), ddi_get_instance(dip),
	    (void *)dip, inum));

	if ((hdl_p = i_ddi_get_intr_handle(dip, inum)) == NULL) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_remove_intr: no handle "
		    "found\n"));
		return;
	}

	if ((ret = ddi_intr_disable(hdl_p[0])) != DDI_SUCCESS) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_remove_intr: "
		    "ddi_intr_disable failed, ret 0x%x\n", ret));
		return;
	}

	if ((ret = ddi_intr_remove_handler(hdl_p[0])) != DDI_SUCCESS) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_remove_intr: "
		    "ddi_intr_remove_handler failed, ret 0x%x\n", ret));
		return;
	}

	if ((ret = ddi_intr_free(hdl_p[0])) != DDI_SUCCESS) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_remove_intr: "
		    "ddi_intr_free failed, ret 0x%x\n", ret));
		return;
	}

	kmem_free(hdl_p, sizeof (ddi_intr_handle_t));
}

/* ARGSUSED */
int
ddi_get_soft_iblock_cookie(dev_info_t *dip, int preference,
    ddi_iblock_cookie_t *iblock_cookiep)
{
	DDI_INTR_APIDBG((CE_CONT, "ddi_get_soft_iblock_cookie: name=%s%d "
	    "dip=0x%p pref=0x%x\n", ddi_driver_name(dip), ddi_get_instance(dip),
	    (void *)dip, preference));

	ASSERT(iblock_cookiep != NULL);

	if (preference == DDI_SOFTINT_FIXED)
		return (DDI_FAILURE);

	*iblock_cookiep = (ddi_iblock_cookie_t)((uintptr_t)
	    ((preference > DDI_SOFTINT_MED) ? DDI_SOFT_INTR_PRI_H :
	    DDI_SOFT_INTR_PRI_M));

	return (DDI_SUCCESS);
}

int
ddi_add_softintr(dev_info_t *dip, int preference, ddi_softintr_t *idp,
    ddi_iblock_cookie_t *iblock_cookiep,
    ddi_idevice_cookie_t *idevice_cookiep,
    uint_t (*int_handler)(caddr_t int_handler_arg),
    caddr_t int_handler_arg)
{
	ddi_softint_handle_t	*hdl_p;
	uint64_t		softpri;
	int			ret;

	DDI_INTR_APIDBG((CE_CONT, "ddi_add_softintr: name=%s%d dip=0x%p "
	    "pref=0x%x\n", ddi_driver_name(dip), ddi_get_instance(dip),
	    (void *)dip, preference));

	if ((idp == NULL) || ((preference == DDI_SOFTINT_FIXED) &&
	    (iblock_cookiep == NULL)))
		return (DDI_FAILURE);

	/* Translate the priority preference */
	if (preference == DDI_SOFTINT_FIXED) {
		softpri = (uint64_t)(uintptr_t)*iblock_cookiep;
		softpri = MIN(softpri, DDI_SOFT_INTR_PRI_H);
	} else {
		softpri = (uint64_t)((preference > DDI_SOFTINT_MED) ?
		    DDI_SOFT_INTR_PRI_H : DDI_SOFT_INTR_PRI_M);
	}

	DDI_INTR_APIDBG((CE_CONT, "ddi_add_softintr: preference 0x%x "
	    "softpri 0x%lx\n", preference, (long)softpri));

	hdl_p = kmem_zalloc(sizeof (ddi_softint_handle_t), KM_SLEEP);
	if ((ret = ddi_intr_add_softint(dip, hdl_p, softpri,
	    (ddi_intr_handler_t *)int_handler, int_handler_arg)) !=
	    DDI_SUCCESS) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_add_softintr: "
		    "ddi_intr_add_softint failed, ret 0x%x\n", ret));

		kmem_free(hdl_p, sizeof (ddi_softint_handle_t));
		return (DDI_FAILURE);
	}

	if (iblock_cookiep)
		*iblock_cookiep =  (ddi_iblock_cookie_t)(uintptr_t)softpri;

	if (idevice_cookiep) {
		idevice_cookiep->idev_vector = 0;
		idevice_cookiep->idev_priority = softpri;
	}

	*idp = (ddi_softintr_t)hdl_p;

	DDI_INTR_APIDBG((CE_CONT, "ddi_add_softintr: dip = 0x%p, "
	    "idp = 0x%p, ret = %x\n", (void *)dip, (void *)*idp, ret));

	return (DDI_SUCCESS);
}

void
ddi_remove_softintr(ddi_softintr_t id)
{
	ddi_softint_handle_t	*h_p = (ddi_softint_handle_t *)id;

	DDI_INTR_APIDBG((CE_CONT, "ddi_remove_softintr: id=0x%p\n",
	    (void *)id));

	if (h_p == NULL)
		return;

	DDI_INTR_APIDBG((CE_CONT, "ddi_remove_softintr: handle 0x%p\n",
	    (void *)h_p));

	(void) ddi_intr_remove_softint(*h_p);
	kmem_free(h_p, sizeof (ddi_softint_handle_t));
}

void
ddi_trigger_softintr(ddi_softintr_t id)
{
	ddi_softint_handle_t	*h_p = (ddi_softint_handle_t *)id;
	int			ret;

	if (h_p == NULL)
		return;

	if ((ret = ddi_intr_trigger_softint(*h_p, NULL)) != DDI_SUCCESS) {
		DDI_INTR_APIDBG((CE_CONT, "ddi_trigger_softintr: "
		    "ddi_intr_trigger_softint failed, hdlp 0x%p "
		    "ret 0x%x\n", (void *)h_p, ret));
	}
}
