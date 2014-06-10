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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/ddi_impldefs.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddifm.h>
#include <sys/fm/io/ddi.h>
#include <sys/fm/protocol.h>
#include <sys/ontrap.h>


/*
 * DDI DMA Engine functions for x86.
 * These functions are more naturally generic, but do not apply to SPARC.
 */

int
ddi_dmae_alloc(dev_info_t *dip, int chnl, int (*dmae_waitfp)(), caddr_t arg)
{
	return (ddi_dma_mctl(dip, dip, 0, DDI_DMA_E_ACQUIRE,
	    (off_t *)dmae_waitfp, (size_t *)arg,
	    (caddr_t *)(uintptr_t)chnl, 0));
}

int
ddi_dmae_release(dev_info_t *dip, int chnl)
{
	return (ddi_dma_mctl(dip, dip, 0, DDI_DMA_E_FREE, 0, 0,
	    (caddr_t *)(uintptr_t)chnl, 0));
}

int
ddi_dmae_getattr(dev_info_t *dip, ddi_dma_attr_t *attrp)
{
	return (ddi_dma_mctl(dip, dip, 0, DDI_DMA_E_GETATTR, 0, 0,
	    (caddr_t *)attrp, 0));
}

int
ddi_dmae_1stparty(dev_info_t *dip, int chnl)
{
	return (ddi_dma_mctl(dip, dip, 0, DDI_DMA_E_1STPTY, 0, 0,
	    (caddr_t *)(uintptr_t)chnl, 0));
}

int
ddi_dmae_prog(dev_info_t *dip, struct ddi_dmae_req *dmaereqp,
	ddi_dma_cookie_t *cookiep, int chnl)
{
	return (ddi_dma_mctl(dip, dip, 0, DDI_DMA_E_PROG, (off_t *)dmaereqp,
	    (size_t *)cookiep, (caddr_t *)(uintptr_t)chnl, 0));
}

int
ddi_dmae_swsetup(dev_info_t *dip, struct ddi_dmae_req *dmaereqp,
	ddi_dma_cookie_t *cookiep, int chnl)
{
	return (ddi_dma_mctl(dip, dip, 0, DDI_DMA_E_SWSETUP, (off_t *)dmaereqp,
	    (size_t *)cookiep, (caddr_t *)(uintptr_t)chnl, 0));
}

int
ddi_dmae_swstart(dev_info_t *dip, int chnl)
{
	return (ddi_dma_mctl(dip, dip, 0, DDI_DMA_E_SWSTART, 0, 0,
	    (caddr_t *)(uintptr_t)chnl, 0));
}

int
ddi_dmae_stop(dev_info_t *dip, int chnl)
{
	return (ddi_dma_mctl(dip, dip, 0, DDI_DMA_E_STOP, 0, 0,
	    (caddr_t *)(uintptr_t)chnl, 0));
}

int
ddi_dmae_enable(dev_info_t *dip, int chnl)
{
	return (ddi_dma_mctl(dip, dip, 0, DDI_DMA_E_ENABLE, 0, 0,
	    (caddr_t *)(uintptr_t)chnl, 0));
}

int
ddi_dmae_disable(dev_info_t *dip, int chnl)
{
	return (ddi_dma_mctl(dip, dip, 0, DDI_DMA_E_DISABLE, 0, 0,
	    (caddr_t *)(uintptr_t)chnl, 0));
}

int
ddi_dmae_getcnt(dev_info_t *dip, int chnl, int *countp)
{
	return (ddi_dma_mctl(dip, dip, 0, DDI_DMA_E_GETCNT, 0, (size_t *)countp,
	    (caddr_t *)(uintptr_t)chnl, 0));
}

/*
 * implementation specific access handle and routines:
 */

static uintptr_t impl_acc_hdl_id = 0;

/*
 * access handle allocator
 */
ddi_acc_hdl_t *
impl_acc_hdl_get(ddi_acc_handle_t hdl)
{
	/*
	 * recast to ddi_acc_hdl_t instead of
	 * casting to ddi_acc_impl_t and then return the ah_platform_private
	 *
	 * this optimization based on the ddi_acc_hdl_t is the
	 * first member of the ddi_acc_impl_t.
	 */
	return ((ddi_acc_hdl_t *)hdl);
}

ddi_acc_handle_t
impl_acc_hdl_alloc(int (*waitfp)(caddr_t), caddr_t arg)
{
	ddi_acc_impl_t *hp;
	on_trap_data_t *otp;
	int sleepflag;

	sleepflag = ((waitfp == (int (*)())KM_SLEEP) ? KM_SLEEP : KM_NOSLEEP);
	/*
	 * Allocate and initialize the data access handle and error status.
	 */
	if ((hp = kmem_zalloc(sizeof (ddi_acc_impl_t), sleepflag)) == NULL)
		goto fail;
	if ((hp->ahi_err = (ndi_err_t *)kmem_zalloc(
	    sizeof (ndi_err_t), sleepflag)) == NULL) {
		kmem_free(hp, sizeof (ddi_acc_impl_t));
		goto fail;
	}
	if ((otp = (on_trap_data_t *)kmem_zalloc(
	    sizeof (on_trap_data_t), sleepflag)) == NULL) {
		kmem_free(hp->ahi_err, sizeof (ndi_err_t));
		kmem_free(hp, sizeof (ddi_acc_impl_t));
		goto fail;
	}
	hp->ahi_err->err_ontrap = otp;
	hp->ahi_common.ah_platform_private = (void *)hp;

	return ((ddi_acc_handle_t)hp);
fail:
	if ((waitfp != (int (*)())KM_SLEEP) &&
	    (waitfp != (int (*)())KM_NOSLEEP))
		ddi_set_callback(waitfp, arg, &impl_acc_hdl_id);
	return (NULL);
}

void
impl_acc_hdl_free(ddi_acc_handle_t handle)
{
	ddi_acc_impl_t *hp;

	/*
	 * The supplied (ddi_acc_handle_t) is actually a (ddi_acc_impl_t *),
	 * because that's what we allocated in impl_acc_hdl_alloc() above.
	 */
	hp = (ddi_acc_impl_t *)handle;
	if (hp) {
		kmem_free(hp->ahi_err->err_ontrap, sizeof (on_trap_data_t));
		kmem_free(hp->ahi_err, sizeof (ndi_err_t));
		kmem_free(hp, sizeof (ddi_acc_impl_t));
		if (impl_acc_hdl_id)
			ddi_run_callback(&impl_acc_hdl_id);
	}
}

/*
 * Function used to check if a given access handle owns the failing address.
 * Called by ndi_fmc_error, when we detect a PIO error.
 */
/* ARGSUSED */
static int
impl_acc_check(dev_info_t *dip, const void *handle, const void *addr,
    const void *not_used)
{
	pfn_t pfn, fault_pfn;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get((ddi_acc_handle_t)handle);

	ASSERT(hp);

	if (addr != NULL) {
		pfn = hp->ah_pfn;
		fault_pfn = mmu_btop(*(uint64_t *)addr);
		if (fault_pfn >= pfn && fault_pfn < (pfn + hp->ah_pnum))
			return (DDI_FM_NONFATAL);
	}
	return (DDI_FM_UNKNOWN);
}

void
impl_acc_err_init(ddi_acc_hdl_t *handlep)
{
	int fmcap;
	ndi_err_t *errp;
	on_trap_data_t *otp;
	ddi_acc_impl_t *hp = (ddi_acc_impl_t *)handlep;

	fmcap = ddi_fm_capable(handlep->ah_dip);

	if (handlep->ah_acc.devacc_attr_version < DDI_DEVICE_ATTR_V1 ||
	    !DDI_FM_ACC_ERR_CAP(fmcap)) {
		handlep->ah_acc.devacc_attr_access = DDI_DEFAULT_ACC;
	} else if (handlep->ah_acc.devacc_attr_access == DDI_FLAGERR_ACC &&
	    hp->ahi_scan == NULL) {
		handlep->ah_acc.devacc_attr_access = DDI_DEFAULT_ACC;
	} else if (DDI_FM_ACC_ERR_CAP(fmcap)) {
		if (handlep->ah_acc.devacc_attr_access == DDI_DEFAULT_ACC) {
			if (handlep->ah_xfermodes)
				return;
			i_ddi_drv_ereport_post(handlep->ah_dip, DVR_EFMCAP,
			    NULL, DDI_NOSLEEP);
		} else {
			errp = hp->ahi_err;
			otp = (on_trap_data_t *)errp->err_ontrap;
			otp->ot_handle = (void *)(hp);
			otp->ot_prot = OT_DATA_ACCESS;
			errp->err_status = DDI_FM_OK;
			errp->err_expected = DDI_FM_ERR_UNEXPECTED;
			errp->err_cf = impl_acc_check;
		}
	}
}

/* ARGSUSED */
int
impl_dma_check(dev_info_t *dip, const void *handle, const void *pci_hdl,
    const void *not_used)
{
	return (DDI_FM_UNKNOWN);
}

void
impl_acc_hdl_init(ddi_acc_hdl_t *handlep)
{
	ddi_acc_impl_t *hp;
	int fmcap;
	int devacc_attr_access;

	if (!handlep)
		return;
	fmcap = ddi_fm_capable(handlep->ah_dip);
	if (handlep->ah_acc.devacc_attr_version < DDI_DEVICE_ATTR_V1 ||
	    !DDI_FM_ACC_ERR_CAP(fmcap))
		devacc_attr_access = DDI_DEFAULT_ACC;
	else
		devacc_attr_access = handlep->ah_acc.devacc_attr_access;

	hp = (ddi_acc_impl_t *)handlep->ah_platform_private;

	/*
	 * Can only do FLAGERR if scan callback is set up. This should
	 * also guarantee that the peekpoke_mutex and err_mutex are defined.
	 */
	if (devacc_attr_access == DDI_FLAGERR_ACC && hp->ahi_scan == NULL)
		devacc_attr_access = DDI_DEFAULT_ACC;

	switch (devacc_attr_access) {
	case DDI_CAUTIOUS_ACC:
		hp->ahi_get8 = i_ddi_caut_get8;
		hp->ahi_put8 = i_ddi_caut_put8;
		hp->ahi_rep_get8 = i_ddi_caut_rep_get8;
		hp->ahi_rep_put8 = i_ddi_caut_rep_put8;
		hp->ahi_get16 = i_ddi_caut_get16;
		hp->ahi_get32 = i_ddi_caut_get32;
		hp->ahi_put16 = i_ddi_caut_put16;
		hp->ahi_put32 = i_ddi_caut_put32;
		hp->ahi_rep_get16 = i_ddi_caut_rep_get16;
		hp->ahi_rep_get32 = i_ddi_caut_rep_get32;
		hp->ahi_rep_put16 = i_ddi_caut_rep_put16;
		hp->ahi_rep_put32 = i_ddi_caut_rep_put32;
		hp->ahi_get64 = i_ddi_caut_get64;
		hp->ahi_put64 = i_ddi_caut_put64;
		hp->ahi_rep_get64 = i_ddi_caut_rep_get64;
		hp->ahi_rep_put64 = i_ddi_caut_rep_put64;
		break;
	case DDI_FLAGERR_ACC:
		if (hp->ahi_acc_attr & DDI_ACCATTR_IO_SPACE) {
			hp->ahi_get8 = i_ddi_prot_io_get8;
			hp->ahi_put8 = i_ddi_prot_io_put8;
			hp->ahi_rep_get8 = i_ddi_prot_io_rep_get8;
			hp->ahi_rep_put8 = i_ddi_prot_io_rep_put8;

			/* temporary set these 64 functions to no-ops */
			hp->ahi_get64 = i_ddi_io_get64;
			hp->ahi_put64 = i_ddi_io_put64;
			hp->ahi_rep_get64 = i_ddi_io_rep_get64;
			hp->ahi_rep_put64 = i_ddi_io_rep_put64;

			/*
			 * check for BIG endian access
			 */
			if (handlep->ah_acc.devacc_attr_endian_flags ==
			    DDI_STRUCTURE_BE_ACC) {
				hp->ahi_get16 = i_ddi_prot_io_swap_get16;
				hp->ahi_get32 = i_ddi_prot_io_swap_get32;
				hp->ahi_put16 = i_ddi_prot_io_swap_put16;
				hp->ahi_put32 = i_ddi_prot_io_swap_put32;
				hp->ahi_rep_get16 =
				    i_ddi_prot_io_swap_rep_get16;
				hp->ahi_rep_get32 =
				    i_ddi_prot_io_swap_rep_get32;
				hp->ahi_rep_put16 =
				    i_ddi_prot_io_swap_rep_put16;
				hp->ahi_rep_put32 =
				    i_ddi_prot_io_swap_rep_put32;
			} else {
				hp->ahi_acc_attr |= DDI_ACCATTR_DIRECT;
				hp->ahi_get16 = i_ddi_prot_io_get16;
				hp->ahi_get32 = i_ddi_prot_io_get32;
				hp->ahi_put16 = i_ddi_prot_io_put16;
				hp->ahi_put32 = i_ddi_prot_io_put32;
				hp->ahi_rep_get16 = i_ddi_prot_io_rep_get16;
				hp->ahi_rep_get32 = i_ddi_prot_io_rep_get32;
				hp->ahi_rep_put16 = i_ddi_prot_io_rep_put16;
				hp->ahi_rep_put32 = i_ddi_prot_io_rep_put32;
			}

		} else if (hp->ahi_acc_attr & DDI_ACCATTR_CPU_VADDR) {

			hp->ahi_get8 = i_ddi_prot_vaddr_get8;
			hp->ahi_put8 = i_ddi_prot_vaddr_put8;
			hp->ahi_rep_get8 = i_ddi_prot_vaddr_rep_get8;
			hp->ahi_rep_put8 = i_ddi_prot_vaddr_rep_put8;

			/*
			 * check for BIG endian access
			 */
			if (handlep->ah_acc.devacc_attr_endian_flags ==
			    DDI_STRUCTURE_BE_ACC) {

				hp->ahi_get16 = i_ddi_prot_vaddr_swap_get16;
				hp->ahi_get32 = i_ddi_prot_vaddr_swap_get32;
				hp->ahi_get64 = i_ddi_prot_vaddr_swap_get64;
				hp->ahi_put16 = i_ddi_prot_vaddr_swap_put16;
				hp->ahi_put32 = i_ddi_prot_vaddr_swap_put32;
				hp->ahi_put64 = i_ddi_prot_vaddr_swap_put64;
				hp->ahi_rep_get16 =
				    i_ddi_prot_vaddr_swap_rep_get16;
				hp->ahi_rep_get32 =
				    i_ddi_prot_vaddr_swap_rep_get32;
				hp->ahi_rep_get64 =
				    i_ddi_prot_vaddr_swap_rep_get64;
				hp->ahi_rep_put16 =
				    i_ddi_prot_vaddr_swap_rep_put16;
				hp->ahi_rep_put32 =
				    i_ddi_prot_vaddr_swap_rep_put32;
				hp->ahi_rep_put64 =
				    i_ddi_prot_vaddr_swap_rep_put64;
			} else {
				hp->ahi_acc_attr |= DDI_ACCATTR_DIRECT;
				hp->ahi_get16 = i_ddi_prot_vaddr_get16;
				hp->ahi_get32 = i_ddi_prot_vaddr_get32;
				hp->ahi_get64 = i_ddi_prot_vaddr_get64;
				hp->ahi_put16 = i_ddi_prot_vaddr_put16;
				hp->ahi_put32 = i_ddi_prot_vaddr_put32;
				hp->ahi_put64 = i_ddi_prot_vaddr_put64;
				hp->ahi_rep_get16 = i_ddi_prot_vaddr_rep_get16;
				hp->ahi_rep_get32 = i_ddi_prot_vaddr_rep_get32;
				hp->ahi_rep_get64 = i_ddi_prot_vaddr_rep_get64;
				hp->ahi_rep_put16 = i_ddi_prot_vaddr_rep_put16;
				hp->ahi_rep_put32 = i_ddi_prot_vaddr_rep_put32;
				hp->ahi_rep_put64 = i_ddi_prot_vaddr_rep_put64;
			}
		}
		break;
	case DDI_DEFAULT_ACC:
		if (hp->ahi_acc_attr & DDI_ACCATTR_IO_SPACE) {
			hp->ahi_get8 = i_ddi_io_get8;
			hp->ahi_put8 = i_ddi_io_put8;
			hp->ahi_rep_get8 = i_ddi_io_rep_get8;
			hp->ahi_rep_put8 = i_ddi_io_rep_put8;

			/* temporary set these 64 functions to no-ops */
			hp->ahi_get64 = i_ddi_io_get64;
			hp->ahi_put64 = i_ddi_io_put64;
			hp->ahi_rep_get64 = i_ddi_io_rep_get64;
			hp->ahi_rep_put64 = i_ddi_io_rep_put64;

			/*
			 * check for BIG endian access
			 */
			if (handlep->ah_acc.devacc_attr_endian_flags ==
			    DDI_STRUCTURE_BE_ACC) {
				hp->ahi_get16 = i_ddi_io_swap_get16;
				hp->ahi_get32 = i_ddi_io_swap_get32;
				hp->ahi_put16 = i_ddi_io_swap_put16;
				hp->ahi_put32 = i_ddi_io_swap_put32;
				hp->ahi_rep_get16 = i_ddi_io_swap_rep_get16;
				hp->ahi_rep_get32 = i_ddi_io_swap_rep_get32;
				hp->ahi_rep_put16 = i_ddi_io_swap_rep_put16;
				hp->ahi_rep_put32 = i_ddi_io_swap_rep_put32;
			} else {
				hp->ahi_acc_attr |= DDI_ACCATTR_DIRECT;
				hp->ahi_get16 = i_ddi_io_get16;
				hp->ahi_get32 = i_ddi_io_get32;
				hp->ahi_put16 = i_ddi_io_put16;
				hp->ahi_put32 = i_ddi_io_put32;
				hp->ahi_rep_get16 = i_ddi_io_rep_get16;
				hp->ahi_rep_get32 = i_ddi_io_rep_get32;
				hp->ahi_rep_put16 = i_ddi_io_rep_put16;
				hp->ahi_rep_put32 = i_ddi_io_rep_put32;
			}

		} else if (hp->ahi_acc_attr & DDI_ACCATTR_CPU_VADDR) {

			hp->ahi_get8 = i_ddi_vaddr_get8;
			hp->ahi_put8 = i_ddi_vaddr_put8;
			hp->ahi_rep_get8 = i_ddi_vaddr_rep_get8;
			hp->ahi_rep_put8 = i_ddi_vaddr_rep_put8;

			/*
			 * check for BIG endian access
			 */
			if (handlep->ah_acc.devacc_attr_endian_flags ==
			    DDI_STRUCTURE_BE_ACC) {

				hp->ahi_get16 = i_ddi_vaddr_swap_get16;
				hp->ahi_get32 = i_ddi_vaddr_swap_get32;
				hp->ahi_get64 = i_ddi_vaddr_swap_get64;
				hp->ahi_put16 = i_ddi_vaddr_swap_put16;
				hp->ahi_put32 = i_ddi_vaddr_swap_put32;
				hp->ahi_put64 = i_ddi_vaddr_swap_put64;
				hp->ahi_rep_get16 = i_ddi_vaddr_swap_rep_get16;
				hp->ahi_rep_get32 = i_ddi_vaddr_swap_rep_get32;
				hp->ahi_rep_get64 = i_ddi_vaddr_swap_rep_get64;
				hp->ahi_rep_put16 = i_ddi_vaddr_swap_rep_put16;
				hp->ahi_rep_put32 = i_ddi_vaddr_swap_rep_put32;
				hp->ahi_rep_put64 = i_ddi_vaddr_swap_rep_put64;
			} else {
				hp->ahi_acc_attr |= DDI_ACCATTR_DIRECT;
				hp->ahi_get16 = i_ddi_vaddr_get16;
				hp->ahi_get32 = i_ddi_vaddr_get32;
				hp->ahi_get64 = i_ddi_vaddr_get64;
				hp->ahi_put16 = i_ddi_vaddr_put16;
				hp->ahi_put32 = i_ddi_vaddr_put32;
				hp->ahi_put64 = i_ddi_vaddr_put64;
				hp->ahi_rep_get16 = i_ddi_vaddr_rep_get16;
				hp->ahi_rep_get32 = i_ddi_vaddr_rep_get32;
				hp->ahi_rep_get64 = i_ddi_vaddr_rep_get64;
				hp->ahi_rep_put16 = i_ddi_vaddr_rep_put16;
				hp->ahi_rep_put32 = i_ddi_vaddr_rep_put32;
				hp->ahi_rep_put64 = i_ddi_vaddr_rep_put64;
			}
		}
		break;
	}
	hp->ahi_fault_check = i_ddi_acc_fault_check;
	hp->ahi_fault_notify = i_ddi_acc_fault_notify;
	hp->ahi_fault = 0;
	impl_acc_err_init(handlep);
}

/*
 * The followings are low-level routines for data access.
 *
 * All of these routines should be implemented in assembly. Those
 * that have been rewritten be found in ~ml/ddi_i86_asm.s
 */

/*ARGSUSED*/
uint16_t
i_ddi_vaddr_swap_get16(ddi_acc_impl_t *hdlp, uint16_t *addr)
{
	return (ddi_swap16(*addr));
}

/*ARGSUSED*/
uint16_t
i_ddi_io_swap_get16(ddi_acc_impl_t *hdlp, uint16_t *addr)
{
	return (ddi_swap16(inw((uintptr_t)addr)));
}

/*ARGSUSED*/
uint32_t
i_ddi_vaddr_swap_get32(ddi_acc_impl_t *hdlp, uint32_t *addr)
{
	return (ddi_swap32(*addr));
}

/*ARGSUSED*/
uint32_t
i_ddi_io_swap_get32(ddi_acc_impl_t *hdlp, uint32_t *addr)
{
	return (ddi_swap32(inl((uintptr_t)addr)));
}

/*ARGSUSED*/
uint64_t
i_ddi_vaddr_swap_get64(ddi_acc_impl_t *hdlp, uint64_t *addr)
{
	return (ddi_swap64(*addr));
}

/*ARGSUSED*/
void
i_ddi_vaddr_swap_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value)
{
	*addr = ddi_swap16(value);
}

/*ARGSUSED*/
void
i_ddi_io_swap_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value)
{
	outw((uintptr_t)addr, ddi_swap16(value));
}

/*ARGSUSED*/
void
i_ddi_vaddr_swap_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value)
{
	*addr = ddi_swap32(value);
}

/*ARGSUSED*/
void
i_ddi_io_swap_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value)
{
	outl((uintptr_t)addr, ddi_swap32(value));
}

/*ARGSUSED*/
void
i_ddi_vaddr_swap_put64(ddi_acc_impl_t *hdlp, uint64_t *addr, uint64_t value)
{
	*addr = ddi_swap64(value);
}

/*ARGSUSED*/
void
i_ddi_vaddr_rep_get8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	uint8_t	*h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*h++ = *d++;
	else
		for (; repcount; repcount--)
			*h++ = *d;
}

/*ARGSUSED*/
void
i_ddi_vaddr_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	uint16_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*h++ = *d++;
	else
		for (; repcount; repcount--)
			*h++ = *d;
}

/*ARGSUSED*/
void
i_ddi_vaddr_swap_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	uint16_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*h++ = ddi_swap16(*d++);
	else
		for (; repcount; repcount--)
			*h++ = ddi_swap16(*d);
}

/*ARGSUSED*/
void
i_ddi_io_swap_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	uint16_t *h;
	uintptr_t port;

	h = host_addr;
	port = (uintptr_t)dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--, port += 2)
			*h++ = ddi_swap16(inw(port));
	else
		for (; repcount; repcount--)
			*h++ = ddi_swap16(inw(port));
}

/*ARGSUSED*/
void
i_ddi_vaddr_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*h++ = *d++;
	else
		for (; repcount; repcount--)
			*h++ = *d;
}

/*ARGSUSED*/
void
i_ddi_vaddr_swap_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*h++ = ddi_swap32(*d++);
	else
		for (; repcount; repcount--)
			*h++ = ddi_swap32(*d);
}

/*ARGSUSED*/
void
i_ddi_io_swap_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *h;
	uintptr_t port;

	h = host_addr;
	port = (uintptr_t)dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--, port += 4)
			*h++ = ddi_swap32(inl(port));
	else
		for (; repcount; repcount--)
			*h++ = ddi_swap32(inl(port));
}

/*ARGSUSED*/
void
i_ddi_vaddr_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
	uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	uint64_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*h++ = *d++;
	else
		for (; repcount; repcount--)
			*h++ = *d;
}

/*ARGSUSED*/
void
i_ddi_vaddr_swap_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
	uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	uint64_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*h++ = ddi_swap64(*d++);
	else
		for (; repcount; repcount--)
			*h++ = ddi_swap64(*d);
}

/*ARGSUSED*/
void
i_ddi_vaddr_rep_put8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	uint8_t	*h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*d++ = *h++;
	else
		for (; repcount; repcount--)
			*d = *h++;
}

/*ARGSUSED*/
void
i_ddi_vaddr_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	uint16_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*d++ = *h++;
	else
		for (; repcount; repcount--)
			*d = *h++;
}

/*ARGSUSED*/
void
i_ddi_vaddr_swap_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	uint16_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*d++ = ddi_swap16(*h++);
	else
		for (; repcount; repcount--)
			*d = ddi_swap16(*h++);
}

/*ARGSUSED*/
void
i_ddi_io_swap_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	uint16_t *h;
	uintptr_t port;

	h = host_addr;
	port = (uintptr_t)dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--, port += 2)
			outw(port, ddi_swap16(*h++));
	else
		for (; repcount; repcount--)
			outw(port, ddi_swap16(*h++));
}

/*ARGSUSED*/
void
i_ddi_vaddr_rep_put32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*d++ = *h++;
	else
		for (; repcount; repcount--)
			*d = *h++;
}

/*ARGSUSED*/
void
i_ddi_vaddr_swap_rep_put32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*d++ = ddi_swap32(*h++);
	else
		for (; repcount; repcount--)
			*d = ddi_swap32(*h++);
}

/*ARGSUSED*/
void
i_ddi_io_swap_rep_put32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *h;
	uintptr_t port;

	h = host_addr;
	port = (uintptr_t)dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--, port += 4)
			outl(port, ddi_swap32(*h++));
	else
		for (; repcount; repcount--)
			outl(port, ddi_swap32(*h++));
}

/*ARGSUSED*/
void
i_ddi_vaddr_rep_put64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
	uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	uint64_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*d++ = *h++;
	else
		for (; repcount; repcount--)
			*d = *h++;
}

/*ARGSUSED*/
void
i_ddi_vaddr_swap_rep_put64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
	uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	uint64_t *h, *d;

	h = host_addr;
	d = dev_addr;

	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*d++ = ddi_swap64(*h++);
	else
		for (; repcount; repcount--)
			*d = ddi_swap64(*h++);
}

/*ARGSUSED*/
uint64_t
i_ddi_io_get64(ddi_acc_impl_t *hdlp, uint64_t *addr)
{
	panic("ddi_get64 from i/o space");
	/*NOTREACHED*/
	return (0);
}

/*ARGSUSED*/
void
i_ddi_io_put64(ddi_acc_impl_t *hdlp, uint64_t *host_addr, uint64_t value)
{
	panic("ddi_put64 to i/o space");
	/*NOTREACHED*/
}

void
do_scan(ddi_acc_impl_t *hdlp)
{
	ddi_fm_error_t de;
	ndi_err_t *errp = (ndi_err_t *)hdlp->ahi_err;

	bzero(&de, sizeof (ddi_fm_error_t));
	de.fme_version = DDI_FME_VERSION;
	de.fme_ena = fm_ena_generate(0, FM_ENA_FMT1);
	de.fme_flag = DDI_FM_ERR_UNEXPECTED;

	mutex_enter(hdlp->ahi_err_mutexp);
	hdlp->ahi_scan(hdlp->ahi_scan_dip, &de);
	if (de.fme_status != DDI_FM_OK) {
		errp->err_ena = de.fme_ena;
		errp->err_expected = de.fme_flag;
		errp->err_status = DDI_FM_NONFATAL;
	}
	mutex_exit(hdlp->ahi_err_mutexp);
}

/*ARGSUSED*/
uint8_t
i_ddi_prot_vaddr_get8(ddi_acc_impl_t *hdlp, uint8_t *addr)
{
	uint8_t val;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	val = *addr;
	if (val == 0xff)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);

	return (val);
}

/*ARGSUSED*/
uint16_t
i_ddi_prot_vaddr_get16(ddi_acc_impl_t *hdlp, uint16_t *addr)
{
	uint16_t val;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	val = *addr;
	if (val == 0xffff)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);

	return (val);
}

/*ARGSUSED*/
uint32_t
i_ddi_prot_vaddr_get32(ddi_acc_impl_t *hdlp, uint32_t *addr)
{
	uint32_t val;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	val = *addr;
	if (val == 0xffffffff)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);

	return (val);
}

/*ARGSUSED*/
uint64_t
i_ddi_prot_vaddr_get64(ddi_acc_impl_t *hdlp, uint64_t *addr)
{
	uint64_t val;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	val = *addr;
	if (val == 0xffffffffffffffff)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);

	return (val);
}

/*ARGSUSED*/
uint8_t
i_ddi_prot_io_get8(ddi_acc_impl_t *hdlp, uint8_t *addr)
{
	uint8_t val;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	val = inb((uintptr_t)addr);
	if (val == 0xff)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);

	return (val);
}

/*ARGSUSED*/
uint16_t
i_ddi_prot_io_get16(ddi_acc_impl_t *hdlp, uint16_t *addr)
{
	uint16_t val;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	val = inw((uintptr_t)addr);
	if (val == 0xffff)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);

	return (val);
}

/*ARGSUSED*/
uint32_t
i_ddi_prot_io_get32(ddi_acc_impl_t *hdlp, uint32_t *addr)
{
	uint32_t val;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	val = inl((uintptr_t)addr);
	if (val == 0xffffffff)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);

	return (val);
}

/*ARGSUSED*/
uint16_t
i_ddi_prot_vaddr_swap_get16(ddi_acc_impl_t *hdlp, uint16_t *addr)
{
	uint16_t val;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	val = ddi_swap16(*addr);
	if (val == 0xffff)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);

	return (val);
}

/*ARGSUSED*/
uint16_t
i_ddi_prot_io_swap_get16(ddi_acc_impl_t *hdlp, uint16_t *addr)
{
	uint16_t val;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	val = ddi_swap16(inw((uintptr_t)addr));
	if (val == 0xffff)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);

	return (val);
}

/*ARGSUSED*/
uint32_t
i_ddi_prot_vaddr_swap_get32(ddi_acc_impl_t *hdlp, uint32_t *addr)
{
	uint32_t val;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	val = ddi_swap32(*addr);
	if (val == 0xffffffff)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);

	return (val);
}

/*ARGSUSED*/
uint32_t
i_ddi_prot_io_swap_get32(ddi_acc_impl_t *hdlp, uint32_t *addr)
{
	uint32_t val;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	val = ddi_swap32(inl((uintptr_t)addr));
	if (val == 0xffffffff)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);

	return (val);
}

/*ARGSUSED*/
uint64_t
i_ddi_prot_vaddr_swap_get64(ddi_acc_impl_t *hdlp, uint64_t *addr)
{
	uint64_t val;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	val = ddi_swap64(*addr);
	if (val == 0xffffffffffffffff)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);

	return (val);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_put8(ddi_acc_impl_t *hdlp, uint8_t *addr, uint8_t value)
{
	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	*addr = value;
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_io_put8(ddi_acc_impl_t *hdlp, uint8_t *addr, uint8_t value)
{
	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	outb((uintptr_t)addr, value);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value)
{
	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	*addr = value;
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_io_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value)
{
	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	outw((uintptr_t)addr, value);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_put32(ddi_acc_impl_t *hdlp, uint32_t *addr,
    uint32_t value)
{
	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	*addr = value;
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_io_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value)
{
	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	outl((uintptr_t)addr, value);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_put64(ddi_acc_impl_t *hdlp, uint64_t *addr,
    uint64_t value)
{
	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	*addr = value;
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_swap_put16(ddi_acc_impl_t *hdlp, uint16_t *addr,
    uint16_t value)
{
	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	*addr = ddi_swap16(value);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_io_swap_put16(ddi_acc_impl_t *hdlp, uint16_t *addr, uint16_t value)
{
	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	outw((uintptr_t)addr, ddi_swap16(value));
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_swap_put32(ddi_acc_impl_t *hdlp, uint32_t *addr,
    uint32_t value)
{
	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	*addr = ddi_swap32(value);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_io_swap_put32(ddi_acc_impl_t *hdlp, uint32_t *addr, uint32_t value)
{
	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	outl((uintptr_t)addr, ddi_swap32(value));
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_swap_put64(ddi_acc_impl_t *hdlp, uint64_t *addr,
    uint64_t value)
{
	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	*addr = ddi_swap64(value);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_io_rep_get8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	int fail = 0;
	uint8_t	*h;
	uintptr_t port;

	h = host_addr;
	port = (uintptr_t)dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR) {
		for (; repcount; repcount--, port++)
			if ((*h++ = inb(port)) == 0xff)
				fail = 1;
	} else {
		for (; repcount; repcount--)
			if ((*h++ = inb(port)) == 0xff)
				fail = 1;
	}
	if (fail == 1)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_io_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	int fail = 0;
	uint16_t *h;
	uintptr_t port;

	h = host_addr;
	port = (uintptr_t)dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR) {
		for (; repcount; repcount--, port += 2)
			if ((*h++ = inw(port)) == 0xffff)
				fail = 1;
	} else {
		for (; repcount; repcount--)
			if ((*h++ = inw(port)) == 0xffff)
				fail = 1;
	}
	if (fail == 1)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_io_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	int fail = 0;
	uint32_t *h;
	uintptr_t port;

	h = host_addr;
	port = (uintptr_t)dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR) {
		for (; repcount; repcount--, port += 4)
			if ((*h++ = inl(port)) == 0xffffffff)
				fail = 1;
	} else {
		for (; repcount; repcount--)
			if ((*h++ = inl(port)) == 0xffffffff)
				fail = 1;
	}
	if (fail == 1)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_rep_get8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	int fail = 0;
	uint8_t	*h, *d;

	h = host_addr;
	d = dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR) {
		for (; repcount; repcount--)
			if ((*h++ = *d++) == 0xff)
				fail = 1;
	} else {
		for (; repcount; repcount--)
			if ((*h++ = *d) == 0xff)
				fail = 1;
	}
	if (fail == 1)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	int fail = 0;
	uint16_t *h, *d;

	h = host_addr;
	d = dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR) {
		for (; repcount; repcount--)
			if ((*h++ = *d++) == 0xffff)
				fail = 1;
	} else {
		for (; repcount; repcount--)
			if ((*h++ = *d) == 0xffff)
				fail = 1;
	}
	if (fail == 1)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_swap_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	int fail = 0;
	uint16_t *h, *d;

	h = host_addr;
	d = dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR) {
		for (; repcount; repcount--)
			if ((*h++ = ddi_swap16(*d++)) == 0xffff)
				fail = 1;
	} else {
		for (; repcount; repcount--)
			if ((*h++ = ddi_swap16(*d)) == 0xffff)
				fail = 1;
	}
	if (fail == 1)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_io_swap_rep_get16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	int fail = 0;
	uint16_t *h;
	uintptr_t port;

	h = host_addr;
	port = (uintptr_t)dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR) {
		for (; repcount; repcount--, port += 2)
			if ((*h++ = ddi_swap16(inw(port))) == 0xffff)
				fail = 1;
	} else {
		for (; repcount; repcount--)
			if ((*h++ = ddi_swap16(inw(port))) == 0xffff)
				fail = 1;
	}
	if (fail == 1)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	int fail = 0;
	uint32_t *h, *d;

	h = host_addr;
	d = dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR) {
		for (; repcount; repcount--)
			if ((*h++ = *d++) == 0xffffffff)
				fail = 1;
	} else {
		for (; repcount; repcount--)
			if ((*h++ = *d) == 0xffffffff)
				fail = 1;
	}
	if (fail == 1)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_swap_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	int fail = 0;
	uint32_t *h, *d;

	h = host_addr;
	d = dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR) {
		for (; repcount; repcount--)
			if ((*h++ = ddi_swap32(*d++)) == 0xffffffff)
				fail = 1;
	} else {
		for (; repcount; repcount--)
			if ((*h++ = ddi_swap32(*d)) == 0xffffffff)
				fail = 1;
	}
	if (fail == 1)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_io_swap_rep_get32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	int fail = 0;
	uint32_t *h;
	uintptr_t port;

	h = host_addr;
	port = (uintptr_t)dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR) {
		for (; repcount; repcount--, port += 4)
			if ((*h++ = ddi_swap32(inl(port))) == 0xffffffff)
				fail = 1;
	} else {
		for (; repcount; repcount--)
			if ((*h++ = ddi_swap32(inl(port))) == 0xffffffff)
				fail = 1;
	}
	if (fail == 1)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
	uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	int fail = 0;
	uint64_t *h, *d;

	h = host_addr;
	d = dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR) {
		for (; repcount; repcount--)
			if ((*h++ = *d++) == 0xffffffffffffffff)
				fail = 1;
	} else {
		for (; repcount; repcount--)
			if ((*h++ = *d) == 0xffffffffffffffff)
				fail = 1;
	}
	if (fail == 1)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_swap_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
	uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	int fail = 0;
	uint64_t *h, *d;

	h = host_addr;
	d = dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR) {
		for (; repcount; repcount--)
			if ((*h++ = ddi_swap64(*d++)) == 0xffffffffffffffff)
				fail = 1;
	} else {
		for (; repcount; repcount--)
			if ((*h++ = ddi_swap64(*d)) == 0xffffffffffffffff)
				fail = 1;
	}
	if (fail == 1)
		do_scan(hdlp);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_rep_put8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	uint8_t	*h, *d;

	h = host_addr;
	d = dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*d++ = *h++;
	else
		for (; repcount; repcount--)
			*d = *h++;
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_io_rep_put8(ddi_acc_impl_t *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	uint8_t	*h;
	uintptr_t port;

	h = host_addr;
	port = (uintptr_t)dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--, port++)
			outb(port, *h++);
	else
		for (; repcount; repcount--)
			outb(port, *h++);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	uint16_t *h, *d;

	h = host_addr;
	d = dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*d++ = *h++;
	else
		for (; repcount; repcount--)
			*d = *h++;
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_io_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	uint16_t *h;
	uintptr_t port;

	h = host_addr;
	port = (uintptr_t)dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--, port += 2)
			outw(port, *h++);
	else
		for (; repcount; repcount--)
			outw(port, *h++);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_swap_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	uint16_t *h, *d;

	h = host_addr;
	d = dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*d++ = ddi_swap16(*h++);
	else
		for (; repcount; repcount--)
			*d = ddi_swap16(*h++);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_io_swap_rep_put16(ddi_acc_impl_t *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	uint16_t *h;
	uintptr_t port;

	h = host_addr;
	port = (uintptr_t)dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--, port += 2)
			outw(port, ddi_swap16(*h++));
	else
		for (; repcount; repcount--)
			outw(port, ddi_swap16(*h++));
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_rep_put32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *h, *d;

	h = host_addr;
	d = dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*d++ = *h++;
	else
		for (; repcount; repcount--)
			*d = *h++;
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_io_rep_put32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *h;
	uintptr_t port;

	h = host_addr;
	port = (uintptr_t)dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--, port += 4)
			outl(port, *h++);
	else
		for (; repcount; repcount--)
			outl(port, *h++);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_swap_rep_put32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *h, *d;

	h = host_addr;
	d = dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*d++ = ddi_swap32(*h++);
	else
		for (; repcount; repcount--)
			*d = ddi_swap32(*h++);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_io_swap_rep_put32(ddi_acc_impl_t *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	uint32_t *h;
	uintptr_t port;

	h = host_addr;
	port = (uintptr_t)dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--, port += 4)
			outl(port, ddi_swap32(*h++));
	else
		for (; repcount; repcount--)
			outl(port, ddi_swap32(*h++));
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_rep_put64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
	uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	uint64_t *h, *d;

	h = host_addr;
	d = dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*d++ = *h++;
	else
		for (; repcount; repcount--)
			*d = *h++;
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

/*ARGSUSED*/
void
i_ddi_prot_vaddr_swap_rep_put64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
	uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	uint64_t *h, *d;

	h = host_addr;
	d = dev_addr;

	mutex_enter(hdlp->ahi_peekpoke_mutexp);
	if (flags == DDI_DEV_AUTOINCR)
		for (; repcount; repcount--)
			*d++ = ddi_swap64(*h++);
	else
		for (; repcount; repcount--)
			*d = ddi_swap64(*h++);
	mutex_exit(hdlp->ahi_peekpoke_mutexp);
}

void
ddi_io_rep_get8(ddi_acc_handle_t handle,
	uint8_t *host_addr, uint8_t *dev_addr, size_t repcount)
{
	(((ddi_acc_impl_t *)handle)->ahi_rep_get8)
	    ((ddi_acc_impl_t *)handle, host_addr, dev_addr,
	    repcount, DDI_DEV_NO_AUTOINCR);
}

void
ddi_io_rep_get16(ddi_acc_handle_t handle,
	uint16_t *host_addr, uint16_t *dev_addr, size_t repcount)
{
	(((ddi_acc_impl_t *)handle)->ahi_rep_get16)
	    ((ddi_acc_impl_t *)handle, host_addr, dev_addr,
	    repcount, DDI_DEV_NO_AUTOINCR);
}

void
ddi_io_rep_get32(ddi_acc_handle_t handle,
	uint32_t *host_addr, uint32_t *dev_addr, size_t repcount)
{
	(((ddi_acc_impl_t *)handle)->ahi_rep_get32)
	    ((ddi_acc_impl_t *)handle, host_addr, dev_addr,
	    repcount, DDI_DEV_NO_AUTOINCR);
}

/*ARGSUSED*/
void
i_ddi_io_rep_get64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
	uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	cmn_err(CE_PANIC, "ddi_rep_get64 from i/o space");
}

void
ddi_io_rep_put8(ddi_acc_handle_t handle,
	uint8_t *host_addr, uint8_t *dev_addr, size_t repcount)
{
	(((ddi_acc_impl_t *)handle)->ahi_rep_put8)
	    ((ddi_acc_impl_t *)handle, host_addr, dev_addr,
	    repcount, DDI_DEV_NO_AUTOINCR);
}

void
ddi_io_rep_put16(ddi_acc_handle_t handle,
	uint16_t *host_addr, uint16_t *dev_addr, size_t repcount)
{
	(((ddi_acc_impl_t *)handle)->ahi_rep_put16)
	    ((ddi_acc_impl_t *)handle, host_addr, dev_addr,
	    repcount, DDI_DEV_NO_AUTOINCR);
}

void
ddi_io_rep_put32(ddi_acc_handle_t handle,
	uint32_t *host_addr, uint32_t *dev_addr, size_t repcount)
{
	(((ddi_acc_impl_t *)handle)->ahi_rep_put32)
	    ((ddi_acc_impl_t *)handle, host_addr, dev_addr,
	    repcount, DDI_DEV_NO_AUTOINCR);
}

/*ARGSUSED*/
void
i_ddi_io_rep_put64(ddi_acc_impl_t *hdlp, uint64_t *host_addr,
	uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	cmn_err(CE_PANIC, "ddi_rep_put64 to i/o space");
}

/*
 * We need to separate the old interfaces from the new ones and leave them
 * in here for a while. Previous versions of the OS defined the new interfaces
 * to the old interfaces. This way we can fix things up so that we can
 * eventually remove these interfaces.
 * e.g. A 3rd party module/driver using ddi_io_rep_get8 and built against S10
 * or earlier will actually have a reference to ddi_io_rep_getb in the binary.
 */
#ifdef _ILP32
void
ddi_io_rep_getb(ddi_acc_handle_t handle,
	uint8_t *host_addr, uint8_t *dev_addr, size_t repcount)
{
	(((ddi_acc_impl_t *)handle)->ahi_rep_get8)
	    ((ddi_acc_impl_t *)handle, host_addr, dev_addr,
	    repcount, DDI_DEV_NO_AUTOINCR);
}

void
ddi_io_rep_getw(ddi_acc_handle_t handle,
	uint16_t *host_addr, uint16_t *dev_addr, size_t repcount)
{
	(((ddi_acc_impl_t *)handle)->ahi_rep_get16)
	    ((ddi_acc_impl_t *)handle, host_addr, dev_addr,
	    repcount, DDI_DEV_NO_AUTOINCR);
}

void
ddi_io_rep_getl(ddi_acc_handle_t handle,
	uint32_t *host_addr, uint32_t *dev_addr, size_t repcount)
{
	(((ddi_acc_impl_t *)handle)->ahi_rep_get32)
	    ((ddi_acc_impl_t *)handle, host_addr, dev_addr,
	    repcount, DDI_DEV_NO_AUTOINCR);
}

void
ddi_io_rep_putb(ddi_acc_handle_t handle,
	uint8_t *host_addr, uint8_t *dev_addr, size_t repcount)
{
	(((ddi_acc_impl_t *)handle)->ahi_rep_put8)
	    ((ddi_acc_impl_t *)handle, host_addr, dev_addr,
	    repcount, DDI_DEV_NO_AUTOINCR);
}

void
ddi_io_rep_putw(ddi_acc_handle_t handle,
	uint16_t *host_addr, uint16_t *dev_addr, size_t repcount)
{
	(((ddi_acc_impl_t *)handle)->ahi_rep_put16)
	    ((ddi_acc_impl_t *)handle, host_addr, dev_addr,
	    repcount, DDI_DEV_NO_AUTOINCR);
}

void
ddi_io_rep_putl(ddi_acc_handle_t handle,
	uint32_t *host_addr, uint32_t *dev_addr, size_t repcount)
{
	(((ddi_acc_impl_t *)handle)->ahi_rep_put32)
	    ((ddi_acc_impl_t *)handle, host_addr, dev_addr,
	    repcount, DDI_DEV_NO_AUTOINCR);
}
#endif /* _ILP32 */

/*
 * These next two functions could be translated into assembler someday
 */
int
ddi_check_acc_handle(ddi_acc_handle_t handle)
{
	ddi_acc_impl_t *hdlp = (ddi_acc_impl_t *)handle;
	return (((*hdlp->ahi_fault_check)(hdlp) == DDI_SUCCESS) ? DDI_SUCCESS :
	    DDI_FAILURE);
}

int
i_ddi_acc_fault_check(ddi_acc_impl_t *hdlp)
{
	/* Default version, just returns flag value */
	return (hdlp->ahi_fault);
}

/*ARGSUSED*/
void
i_ddi_acc_fault_notify(ddi_acc_impl_t *hdlp)
{
	/* Default version, does nothing for now */
}

void
i_ddi_acc_set_fault(ddi_acc_handle_t handle)
{
	ddi_acc_impl_t *hdlp = (ddi_acc_impl_t *)handle;

	if (!hdlp->ahi_fault) {
		hdlp->ahi_fault = 1;
		(*hdlp->ahi_fault_notify)(hdlp);
	}
}

void
i_ddi_acc_clr_fault(ddi_acc_handle_t handle)
{
	ddi_acc_impl_t *hdlp = (ddi_acc_impl_t *)handle;

	if (hdlp->ahi_fault) {
		hdlp->ahi_fault = 0;
		(*hdlp->ahi_fault_notify)(hdlp);
	}
}
