/*
 * Copyright (c) 2008-2016 Solarflare Communications Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing official
 * policies, either expressed or implied, of the FreeBSD Project.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/atomic.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/ethernet.h>
#include <sys/pci.h>
#include <sys/pcie.h>

#include "sfxge.h"

#include "efx.h"


/* Interrupt table DMA attributes */
static ddi_device_acc_attr_t sfxge_intr_devacc = {

	DDI_DEVICE_ATTR_V0,	/* devacc_attr_version */
	DDI_NEVERSWAP_ACC,	/* devacc_attr_endian_flags */
	DDI_STRICTORDER_ACC	/* devacc_attr_dataorder */
};

static ddi_dma_attr_t sfxge_intr_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version	*/
	0,			/* dma_attr_addr_lo	*/
	0xffffffffffffffffull,	/* dma_attr_addr_hi	*/
	0xffffffffffffffffull,	/* dma_attr_count_max	*/
	EFX_INTR_SIZE,		/* dma_attr_align	*/
	0xffffffff,		/* dma_attr_burstsizes	*/
	1,			/* dma_attr_minxfer	*/
	0xffffffffffffffffull,	/* dma_attr_maxxfer	*/
	0xffffffffffffffffull,	/* dma_attr_seg		*/
	1,			/* dma_attr_sgllen	*/
	1,			/* dma_attr_granular	*/
	0			/* dma_attr_flags	*/
};

static unsigned int
sfxge_intr_line(caddr_t arg1, caddr_t arg2)
{
	sfxge_t *sp = (void *)arg1;
	efx_nic_t *enp = sp->s_enp;
	sfxge_intr_t *sip = &(sp->s_intr);
	unsigned int index;
	boolean_t fatal;
	uint32_t qmask;
	int rc;

	_NOTE(ARGUNUSED(arg2))

	ASSERT3U(sip->si_type, ==, EFX_INTR_LINE);

	if (sip->si_state != SFXGE_INTR_STARTED &&
	    sip->si_state != SFXGE_INTR_TESTING) {
		rc = DDI_INTR_UNCLAIMED;
		goto done;
	}

	if (sip->si_state == SFXGE_INTR_TESTING) {
		sip->si_mask |= 1;	/* only one interrupt */
		rc = DDI_INTR_CLAIMED;
		goto done;
	}

	efx_intr_status_line(enp, &fatal, &qmask);

	if (fatal) {
		sfxge_intr_fatal(sp);

		rc = DDI_INTR_CLAIMED;
		goto done;
	}

	if (qmask != 0) {
		for (index = 0; index < EFX_INTR_NEVQS; index++) {
			if (qmask & (1 << index))
				(void) sfxge_ev_qpoll(sp, index);
		}

		sip->si_zero_count = 0;
		sfxge_gld_rx_push(sp);
		rc = DDI_INTR_CLAIMED;
		goto done;
	}

	/*
	 * bug15671/bug17203 workaround. Return CLAIMED for the first ISR=0
	 * interrupt, and poll all evqs for work. For subsequent ISR=0
	 * interrupts (the line must be shared in this case), just rearm the
	 * event queues to ensure we don't miss an interrupt.
	 */
	if (sip->si_zero_count++ == 0) {
		for (index = 0; index < EFX_INTR_NEVQS; index++) {
			if (sp->s_sep[index] != NULL)
				(void) sfxge_ev_qpoll(sp, index);
		}

		rc = DDI_INTR_CLAIMED;
	} else {
		for (index = 0; index < EFX_INTR_NEVQS; index++) {
			if (sp->s_sep[index] != NULL)
				(void) sfxge_ev_qprime(sp, index);
		}

		rc = DDI_INTR_UNCLAIMED;
	}

done:
	return (rc);
}

static unsigned int
sfxge_intr_message(caddr_t arg1, caddr_t arg2)
{
	sfxge_t *sp = (void *)arg1;
	efx_nic_t *enp = sp->s_enp;
	sfxge_intr_t *sip = &(sp->s_intr);
	unsigned int index = (unsigned int)(uintptr_t)arg2;
	boolean_t fatal;
	int rc;

	ASSERT3U(sip->si_type, ==, EFX_INTR_MESSAGE);

	if (sip->si_state != SFXGE_INTR_STARTED &&
	    sip->si_state != SFXGE_INTR_TESTING) {
		rc = DDI_INTR_UNCLAIMED;
		goto done;
	}

	if (sip->si_state == SFXGE_INTR_TESTING) {
		uint64_t mask;

		do {
			mask = sip->si_mask;
		} while (atomic_cas_64(&(sip->si_mask), mask,
		    mask | (1 << index)) != mask);

		rc = DDI_INTR_CLAIMED;
		goto done;
	}

	efx_intr_status_message(enp, index, &fatal);

	if (fatal) {
		sfxge_intr_fatal(sp);

		rc = DDI_INTR_CLAIMED;
		goto done;
	}

	(void) sfxge_ev_qpoll(sp, index);

	sfxge_gld_rx_push(sp);
	rc = DDI_INTR_CLAIMED;

done:
	return (rc);
}

static int
sfxge_intr_bus_enable(sfxge_t *sp)
{
	sfxge_intr_t *sip = &(sp->s_intr);
	ddi_intr_handler_t *handler;
	int add_index;
	int en_index;
	int err;
	int rc;

	/* Serialise all instances to avoid problems seen in bug31184. */
	mutex_enter(&sfxge_global_lock);

	switch (sip->si_type) {
	case EFX_INTR_MESSAGE:
		handler = sfxge_intr_message;
		break;

	case EFX_INTR_LINE:
		handler = sfxge_intr_line;
		break;

	default:
		dev_err(sp->s_dip, CE_WARN, SFXGE_CMN_ERR
		    "bus_enable: unknown intr type (si_type=%d nalloc=%d)",
		    sip->si_type, sip->si_nalloc);
		ASSERT(B_FALSE);
		rc = EINVAL;
		goto fail1;
	}

	/* Try to add the handlers */
	for (add_index = 0; add_index < sip->si_nalloc; add_index++) {
		unsigned int pri;

		/* This cannot fail unless given invalid inputs. */
		err = ddi_intr_get_pri(sip->si_table[add_index], &pri);
		ASSERT(err == DDI_SUCCESS);

		DTRACE_PROBE2(pri, unsigned int, add_index, unsigned int, pri);

		err = ddi_intr_add_handler(sip->si_table[add_index], handler,
		    (caddr_t)sp, (caddr_t)(uintptr_t)add_index);
		if (err != DDI_SUCCESS) {
			dev_err(sp->s_dip, CE_WARN, SFXGE_CMN_ERR
			    "bus_enable: ddi_intr_add_handler failed"
			    " err=%d (h=%p idx=%d nalloc=%d)",
			    err, (void *)sip->si_table[add_index], add_index,
			    sip->si_nalloc);

			rc = (err == DDI_EINVAL) ? EINVAL : EFAULT;
			goto fail2;
		}
	}

	/* Get interrupt capabilities */
	err = ddi_intr_get_cap(sip->si_table[0], &(sip->si_cap));
	if (err != DDI_SUCCESS) {
		dev_err(sp->s_dip, CE_WARN, SFXGE_CMN_ERR
		    "bus_enable: ddi_intr_get_cap failed"
		    " err=%d (h=%p idx=%d nalloc=%d)",
		    err, (void *)sip->si_table[0], 0, sip->si_nalloc);

		if (err == DDI_EINVAL)
			rc = EINVAL;
		else if (err == DDI_ENOTSUP)
			rc = ENOTSUP;
		else
			rc = EFAULT;

		goto fail3;
	}

	/* Enable interrupts at the bus  */
	if (sip->si_cap & DDI_INTR_FLAG_BLOCK) {
		en_index = 0; /* Silence gcc */
		err = ddi_intr_block_enable(sip->si_table, sip->si_nalloc);
		if (err != DDI_SUCCESS) {
			dev_err(sp->s_dip, CE_WARN, SFXGE_CMN_ERR
			    "bus_enable: ddi_intr_block_enable failed"
			    " err=%d (table=%p nalloc=%d)",
			    err, (void *)sip->si_table, sip->si_nalloc);

			rc = (err == DDI_EINVAL) ? EINVAL : EFAULT;
			goto fail4;
		}
	} else {
		for (en_index = 0; en_index < sip->si_nalloc; en_index++) {
			err = ddi_intr_enable(sip->si_table[en_index]);
			if (err != DDI_SUCCESS) {
				dev_err(sp->s_dip, CE_WARN, SFXGE_CMN_ERR
				    "bus_enable: ddi_intr_enable failed"
				    " err=%d (h=%p idx=%d nalloc=%d)",
				    err, (void *)sip->si_table[en_index],
				    en_index, sip->si_nalloc);

				rc = (err == DDI_EINVAL) ? EINVAL : EFAULT;
				goto fail4;
			}
		}
	}

	mutex_exit(&sfxge_global_lock);
	return (0);

fail4:
	DTRACE_PROBE(fail4);

	/* Disable the enabled handlers */
	if (!(sip->si_cap & DDI_INTR_FLAG_BLOCK)) {
		while (--en_index >= 0) {
			err = ddi_intr_disable(sip->si_table[en_index]);
			if (err != DDI_SUCCESS) {
				dev_err(sp->s_dip, CE_WARN, SFXGE_CMN_ERR
				    "bus_enable: ddi_intr_disable"
				    " failed err=%d (h=%p idx=%d nalloc=%d)",
				    err, (void *)sip->si_table[en_index],
				    en_index, sip->si_nalloc);
			}
		}
	}

fail3:
	DTRACE_PROBE(fail3);

	/* Remove all handlers */
	add_index = sip->si_nalloc;

fail2:
	DTRACE_PROBE(fail2);

	/* Remove remaining handlers */
	while (--add_index >= 0) {
		err = ddi_intr_remove_handler(sip->si_table[add_index]);
		if (err != DDI_SUCCESS) {
			dev_err(sp->s_dip, CE_WARN, SFXGE_CMN_ERR
			    "bus_enable: ddi_intr_remove_handler"
			    " failed err=%d (h=%p idx=%d nalloc=%d)",
			    err, (void *)sip->si_table[add_index], add_index,
			    sip->si_nalloc);
		}
	}

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	mutex_exit(&sfxge_global_lock);
	return (rc);
}

static void
sfxge_intr_bus_disable(sfxge_t *sp)
{
	sfxge_intr_t *sip = &(sp->s_intr);
	int index;
	int err;

	/* Serialise all instances to avoid problems seen in bug31184. */
	mutex_enter(&sfxge_global_lock);

	/* Disable interrupts at the bus */
	if (sip->si_cap & DDI_INTR_FLAG_BLOCK) {
		err = ddi_intr_block_disable(sip->si_table, sip->si_nalloc);
		if (err != DDI_SUCCESS) {
			dev_err(sp->s_dip, CE_WARN, SFXGE_CMN_ERR
			    "bus_disable: ddi_intr_block_disable"
			    " failed err=%d (table=%p nalloc=%d)",
			    err, (void *)sip->si_table, sip->si_nalloc);
		}
	} else {
		index = sip->si_nalloc;
		while (--index >= 0) {
			err = ddi_intr_disable(sip->si_table[index]);
			if (err != DDI_SUCCESS) {
				dev_err(sp->s_dip, CE_WARN, SFXGE_CMN_ERR
				    "bus_disable: ddi_intr_disable"
				    " failed err=%d (h=%p idx=%d nalloc=%d)",
				    err, (void *)sip->si_table[index], index,
				    sip->si_nalloc);
			}
		}
	}

	sip->si_cap = 0;

	/* Remove all handlers */
	index = sip->si_nalloc;
	while (--index >= 0) {
		err = ddi_intr_remove_handler(sip->si_table[index]);
		if (err != DDI_SUCCESS) {
			dev_err(sp->s_dip, CE_WARN, SFXGE_CMN_ERR
			    "bus_disable: ddi_intr_remove_handler"
			    " failed err=%d (h=%p idx=%d nalloc=%d)",
			    err, (void *)sip->si_table[index], index,
			    sip->si_nalloc);
		}
	}

	mutex_exit(&sfxge_global_lock);
}

static int
sfxge_intr_nic_enable(sfxge_t *sp)
{
	sfxge_intr_t *sip = &(sp->s_intr);
	efsys_mem_t *esmp = &(sip->si_mem);
	efx_nic_t *enp = sp->s_enp;
	unsigned int index;
	uint64_t mask;
	unsigned int count;
	int rc;

	/* Zero the memory */
	bzero(esmp->esm_base, EFX_INTR_SIZE);

	/* Enable interrupts at the NIC */
	if ((rc = efx_intr_init(enp, sip->si_type, esmp)) != 0)
		goto fail1;

	efx_intr_enable(enp);

	/* FIXME FIXME FIXME */
	if (sp->s_family == EFX_FAMILY_HUNTINGTON) {
		/* Disable interrupt test until supported on Huntington. */
		return (0);
	}
	/* FIXME FIXME FIXME */

	/* Test the interrupts */
	mask = 0;
	for (index = 0; index < sip->si_nalloc; index++) {
		mask |= (1 << index);

		rc = efx_intr_trigger(enp, index);
		ASSERT3U(rc, ==, 0);
	}

	/* Wait for the tests to complete */
	count = 0;
	do {
		DTRACE_PROBE1(wait, unsigned int, count);

		/* Spin for 1 ms */
		drv_usecwait(1000);

		/*
		 * Check to see that all the test interrupts have been
		 * processed.
		 */
		if ((mask & sip->si_mask) == mask)
			goto done;

	} while (++count < 20);

	rc = ETIMEDOUT;
	goto fail2;

done:
	return (0);

fail2:
	DTRACE_PROBE(fail2);

	dev_err(sp->s_dip, CE_WARN, SFXGE_CMN_ERR
	    "Interrupt test failed (mask=%"PRIx64" got=%"
	    PRIx64"). NIC is disabled",
	    mask, sip->si_mask);

	DTRACE_PROBE2(int_test_fail, uint64_t, mask, uint64_t, sip->si_mask);

	sip->si_mask = 0;

	/* Disable interrupts at the NIC */
	efx_intr_disable(enp);
	efx_intr_fini(enp);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static void
sfxge_intr_nic_disable(sfxge_t *sp)
{
	sfxge_intr_t *sip = &(sp->s_intr);
	efx_nic_t *enp = sp->s_enp;

	sip->si_mask = 0;

	/* Disable interrupts at the NIC */
	efx_intr_disable(enp);
	efx_intr_fini(enp);
}

static inline unsigned
pow2_le(unsigned long n)
{
	unsigned int order = 1;
	ASSERT3U(n, >, 0);
	while ((1ul << order) <= n) ++order;
	return (1ul << (order - 1));
}

int
sfxge_intr_init(sfxge_t *sp)
{
	dev_info_t *dip = sp->s_dip;
	sfxge_intr_t *sip = &(sp->s_intr);
	efsys_mem_t *esmp = &(sip->si_mem);
	sfxge_dma_buffer_attr_t dma_attr;
	int err;
	int rc;
	int types;
	int type;
	int index;
	unsigned int nalloc;
	int navail;

	SFXGE_OBJ_CHECK(sip, sfxge_intr_t);

	ASSERT3U(sip->si_state, ==, SFXGE_INTR_UNINITIALIZED);

#ifdef __sparc
	/* PSARC 2007/453 */
	(void) ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    "#msix-request", NULL, 0);
#endif

	/* Get the map of supported interrupt types */
	err = ddi_intr_get_supported_types(dip, &types);
	if (err != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, SFXGE_CMN_ERR
		    "intr_init: ddi_intr_get_supported_types failed err=%d",
		    err);

		if (err == DDI_EINVAL)
			rc = EINVAL;
		else if (err == DDI_INTR_NOTFOUND)
			rc = ENOENT;
		else
			rc = EFAULT;

		goto fail1;
	}

	/* Choose most favourable type */
	if (types & DDI_INTR_TYPE_MSIX) {
		DTRACE_PROBE(msix);

		type = DDI_INTR_TYPE_MSIX;
		sip->si_type = EFX_INTR_MESSAGE;
	} else {
		DTRACE_PROBE(fixed);

		ASSERT(types & DDI_INTR_TYPE_FIXED);

		type = DDI_INTR_TYPE_FIXED;
		sip->si_type = EFX_INTR_LINE;
	}

	/* Get the number of available interrupts */
	navail = 0;
	err = ddi_intr_get_navail(dip, type, &navail);
	if (err != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, SFXGE_CMN_ERR
		    "intr_init: ddi_intr_get_navail failed err=%d", err);

		if (err == DDI_EINVAL)
			rc = EINVAL;
		else if (err == DDI_INTR_NOTFOUND)
			rc = ENOENT;
		else
			rc = EFAULT;

		goto fail2;
	}

	/* Double-check */
	if (navail == 0) {
		rc = ENOENT;
		goto fail2;
	}

	/*
	 * Allow greater number of MSI-X interrupts than CPUs.
	 * This can be useful to prevent RX no desc drops; See task 32179.
	 * Limit non MSI-X interrupts to a single instance.
	 */
	if (type != DDI_INTR_TYPE_MSIX)
		navail = 1;
	else
		navail = min(navail, sfxge_rx_scale_prop_get(sp));

	DTRACE_PROBE1(navail, unsigned int, navail);

	/* Allocate a handle table */
	sip->si_table_size = navail * sizeof (ddi_intr_handle_t);
	sip->si_table = kmem_zalloc(sip->si_table_size, KM_SLEEP);

	/*
	 * Allocate interrupt handles.
	 * Serialise all device instances to avoid problems seen in bug31184.
	 */
	mutex_enter(&sfxge_global_lock);

	err = ddi_intr_alloc(dip, sip->si_table, type, 0,
	    navail, &(sip->si_nalloc), DDI_INTR_ALLOC_NORMAL);

	mutex_exit(&sfxge_global_lock);

	if (err != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, SFXGE_CMN_ERR
		    "intr_init: ddi_intr_alloc failed err=%d"
		    " (navail=%d nalloc=%d)",
		    err, navail, sip->si_nalloc);

		if (err == DDI_EINVAL)
			rc = EINVAL;
		else if (err == DDI_EAGAIN)
			rc = EAGAIN;
		else if (err == DDI_INTR_NOTFOUND)
			rc = ENOENT;
		else
			rc = EFAULT;

		goto fail3;
	}

	/* Double-check */
	if (sip->si_nalloc == 0) {
		rc = ENOENT;
		goto fail3;
	}

	/* Round down to a power of 2 */
	nalloc = pow2_le(sip->si_nalloc);

	/* Free off any excess handles */
	mutex_enter(&sfxge_global_lock);

	index = sip->si_nalloc;
	while (--index >= nalloc) {
		(void) ddi_intr_free(sip->si_table[index]);
		sip->si_table[index] = NULL;
	}

	mutex_exit(&sfxge_global_lock);

	sip->si_nalloc = nalloc;
	DTRACE_PROBE1(nalloc, unsigned int, sip->si_nalloc);

	dma_attr.sdba_dip	 = sp->s_dip;
	dma_attr.sdba_dattrp	 = &sfxge_intr_dma_attr;
	dma_attr.sdba_callback	 = DDI_DMA_SLEEP;
	dma_attr.sdba_length	 = EFX_INTR_SIZE;
	dma_attr.sdba_memflags	 = DDI_DMA_CONSISTENT;
	dma_attr.sdba_devaccp	 = &sfxge_intr_devacc;
	dma_attr.sdba_bindflags	 = DDI_DMA_RDWR | DDI_DMA_CONSISTENT;
	dma_attr.sdba_maxcookies = 1;
	dma_attr.sdba_zeroinit	 = B_TRUE;

	if ((rc = sfxge_dma_buffer_create(esmp, &dma_attr)) != 0)
		goto fail4;

	/* Store the highest priority for convenience */
	sip->si_intr_pri = 0;
	for (index = 0; index < sip->si_nalloc; index++) {
		uint_t pri;
		if ((rc = ddi_intr_get_pri(sip->si_table[index], &pri)) !=  0)
			goto fail5;
		if (pri > sip->si_intr_pri)
			sip->si_intr_pri = pri;
	}

	sip->si_state = SFXGE_INTR_INITIALIZED;
	return (0);

fail5:
	DTRACE_PROBE(fail5);

fail4:
	DTRACE_PROBE(fail4);

	/* Free interrupt handles */
	mutex_exit(&sfxge_global_lock);

	index = sip->si_nalloc;
	while (--index >= 0) {
		err = ddi_intr_free(sip->si_table[index]);
		if (err != DDI_SUCCESS) {
			dev_err(dip, CE_WARN, SFXGE_CMN_ERR
			    "intr_init: ddi_intr_free failed err=%d"
			    " (h=%p idx=%d nalloc=%d)",
			    err, (void *)sip->si_table[index], index,
			    sip->si_nalloc);
		}
		sip->si_table[index] = NULL;
	}
	sip->si_nalloc = 0;

	mutex_exit(&sfxge_global_lock);

fail3:
	DTRACE_PROBE(fail3);

	/* Free the handle table */
	kmem_free(sip->si_table, sip->si_table_size);
	sip->si_table = NULL;
	sip->si_table_size = 0;

fail2:
	DTRACE_PROBE(fail2);

	/* Clear the interrupt type */
	sip->si_type = EFX_INTR_INVALID;

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	SFXGE_OBJ_CHECK(sip, sfxge_intr_t);

	return (rc);
}

int
sfxge_intr_start(sfxge_t *sp)
{
	sfxge_intr_t *sip = &(sp->s_intr);
	int rc;

	ASSERT3U(sip->si_state, ==, SFXGE_INTR_INITIALIZED);

	/* Enable interrupts at the bus */
	if ((rc = sfxge_intr_bus_enable(sp)) != 0)
		goto fail1;

	sip->si_state = SFXGE_INTR_TESTING;

	/* Enable interrupts at the NIC */
	if ((rc = sfxge_intr_nic_enable(sp)) != 0)
		goto fail2;

	sip->si_state = SFXGE_INTR_STARTED;

	return (0);

fail2:
	DTRACE_PROBE(fail2);

	/* Disable interrupts at the bus */
	sfxge_intr_bus_disable(sp);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	sip->si_state = SFXGE_INTR_INITIALIZED;

	return (rc);
}

void
sfxge_intr_stop(sfxge_t *sp)
{
	sfxge_intr_t *sip = &(sp->s_intr);

	ASSERT3U(sip->si_state, ==, SFXGE_INTR_STARTED);

	sip->si_state = SFXGE_INTR_INITIALIZED;

	/* Disable interrupts at the NIC */
	sfxge_intr_nic_disable(sp);

	/* Disable interrupts at the bus */
	sfxge_intr_bus_disable(sp);
}

void
sfxge_intr_fini(sfxge_t *sp)
{
	sfxge_intr_t *sip = &(sp->s_intr);
	efsys_mem_t *esmp = &(sip->si_mem);
	int index;
	int err;

	ASSERT3U(sip->si_state, ==, SFXGE_INTR_INITIALIZED);

	sip->si_state = SFXGE_INTR_UNINITIALIZED;

	/* Tear down dma setup */
	sfxge_dma_buffer_destroy(esmp);


	/* Free interrupt handles */
	mutex_enter(&sfxge_global_lock);

	index = sip->si_nalloc;
	while (--index >= 0) {
		err = ddi_intr_free(sip->si_table[index]);
		if (err != DDI_SUCCESS) {
			dev_err(sp->s_dip, CE_WARN, SFXGE_CMN_ERR
			    "intr_fini: ddi_intr_free failed err=%d"
			    " (h=%p idx=%d nalloc=%d)",
			    err, (void *)sip->si_table[index],
			    index, sip->si_nalloc);
		}
		sip->si_table[index] = NULL;
	}
	sip->si_nalloc = 0;

	mutex_exit(&sfxge_global_lock);

	/* Free the handle table */
	kmem_free(sip->si_table, sip->si_table_size);
	sip->si_table = NULL;
	sip->si_table_size = 0;

	/* Clear the interrupt type */
	sip->si_type = EFX_INTR_INVALID;

	SFXGE_OBJ_CHECK(sip, sfxge_intr_t);
}
