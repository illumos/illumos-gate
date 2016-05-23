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
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include "sfxge.h"

#include "efx.h"

/* Monitor DMA attributes */
static ddi_device_acc_attr_t sfxge_mon_devacc = {

	DDI_DEVICE_ATTR_V0,	/* devacc_attr_version */
	DDI_NEVERSWAP_ACC,	/* devacc_attr_endian_flags */
	DDI_STRICTORDER_ACC	/* devacc_attr_dataorder */
};

static ddi_dma_attr_t sfxge_mon_dma_attr = {
	DMA_ATTR_V0,		/* dma_attr_version	*/
	0,			/* dma_attr_addr_lo	*/
	0xffffffffffffffffull,	/* dma_attr_addr_hi	*/
	0xffffffffffffffffull,	/* dma_attr_count_max	*/
	0x1000,			/* dma_attr_align	*/
	0xffffffff,		/* dma_attr_burstsizes	*/
	1,			/* dma_attr_minxfer	*/
	0xffffffffffffffffull,	/* dma_attr_maxxfer	*/
	0xffffffffffffffffull,	/* dma_attr_seg		*/
	1,			/* dma_attr_sgllen	*/
	1,			/* dma_attr_granular	*/
	0			/* dma_attr_flags	*/
};


static int
sfxge_mon_kstat_update(kstat_t *ksp, int rw)
{
	sfxge_t *sp = ksp->ks_private;
	sfxge_mon_t *smp = &(sp->s_mon);
	efsys_mem_t *esmp = &(smp->sm_mem);
	efx_nic_t *enp = sp->s_enp;
	kstat_named_t *knp;
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(sp->s_enp);
	int rc, sn;

	if (rw != KSTAT_READ) {
		rc = EACCES;
		goto fail1;
	}

	ASSERT(mutex_owned(&(smp->sm_lock)));

	if (smp->sm_state != SFXGE_MON_STARTED)
		goto done;

	if (smp->sm_polling) {
		rc = efx_mon_stats_update(enp, esmp, smp->sm_statbuf);
		if (rc != 0)
			goto fail2;
	}

	knp = smp->sm_stat;
	for (sn = 0; sn < EFX_MON_NSTATS; sn++) {
		if (encp->enc_mon_stat_mask[sn / EFX_MON_MASK_ELEMENT_SIZE] &
		    (1 << (sn % EFX_MON_MASK_ELEMENT_SIZE)))  {
			knp->value.ui64 = smp->sm_statbuf[sn].emsv_value;
			knp++;
		}
	}

	knp->value.ui32 = sp->s_num_restarts;
	knp++;
	knp->value.ui32 = sp->s_num_restarts_hw_err;
	knp++;
	knp->value.ui32 = smp->sm_polling;
	knp++;

done:
	return (0);

fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static int
sfxge_mon_kstat_init(sfxge_t *sp)
{
	sfxge_mon_t *smp = &(sp->s_mon);
	dev_info_t *dip = sp->s_dip;
	efx_nic_t *enp = sp->s_enp;
	kstat_t *ksp;
	kstat_named_t *knp;
	char name[MAXNAMELEN];
	unsigned int id;
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(sp->s_enp);
	int rc;
	int nstat;

	if ((smp->sm_statbuf = kmem_zalloc(sizeof (uint32_t) * EFX_MON_NSTATS,
	    KM_NOSLEEP)) == NULL) {
		rc = ENOMEM;
		goto fail1;
	}

	(void) snprintf(name, MAXNAMELEN - 1, "%s_%s", ddi_driver_name(dip),
	    efx_mon_name(enp));


	/* Create the set */
	for (id = 0, nstat = 0; id < EFX_MON_NSTATS; id++) {
		if (encp->enc_mon_stat_mask[id / EFX_MON_MASK_ELEMENT_SIZE] &
		    (1 << (id % EFX_MON_MASK_ELEMENT_SIZE)))  {
			nstat++;
		}
	}

	if ((ksp = kstat_create((char *)ddi_driver_name(dip),
	    ddi_get_instance(dip), name, "mon", KSTAT_TYPE_NAMED,
	    nstat+3, 0)) == NULL) {
		rc = ENOMEM;
		goto fail2;
	}

	smp->sm_ksp = ksp;

	ksp->ks_update = sfxge_mon_kstat_update;
	ksp->ks_private = sp;
	ksp->ks_lock = &(smp->sm_lock);

	/* Initialise the named stats */
	smp->sm_stat = knp = ksp->ks_data;
	for (id = 0; id < EFX_MON_NSTATS; id++) {
		if (encp->enc_mon_stat_mask[id / EFX_MON_MASK_ELEMENT_SIZE] &
		    (1 << (id % EFX_MON_MASK_ELEMENT_SIZE)))  {
			kstat_named_init(knp,
			    (char *)efx_mon_stat_name(enp, id),
			    KSTAT_DATA_UINT64);
			knp++;
		}
	}
	kstat_named_init(knp, "num_restarts", KSTAT_DATA_UINT32);
	knp++;
	kstat_named_init(knp, "num_restarts_hw_err", KSTAT_DATA_UINT32);
	knp++;
	kstat_named_init(knp, "mon_polling", KSTAT_DATA_UINT32);
	knp++;

	kstat_install(ksp);

	return (0);

fail2:
	DTRACE_PROBE(fail2);
	kmem_free(smp->sm_statbuf, sizeof (uint32_t) * EFX_MON_NSTATS);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static void
sfxge_mon_kstat_fini(sfxge_t *sp)
{
	sfxge_mon_t *smp = &(sp->s_mon);

	/* Destroy the set */
	kstat_delete(smp->sm_ksp);
	smp->sm_ksp = NULL;
	smp->sm_stat = NULL;

	kmem_free(smp->sm_statbuf, sizeof (uint32_t) * EFX_MON_NSTATS);
}

int
sfxge_mon_init(sfxge_t *sp)
{
	sfxge_mon_t *smp = &(sp->s_mon);
	efx_nic_t *enp = sp->s_enp;
	efsys_mem_t *esmp = &(smp->sm_mem);
	sfxge_dma_buffer_attr_t dma_attr;
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(enp);
	int rc;

	SFXGE_OBJ_CHECK(smp, sfxge_mon_t);

	ASSERT3U(smp->sm_state, ==, SFXGE_MON_UNINITIALIZED);

	smp->sm_sp = sp;

	mutex_init(&(smp->sm_lock), NULL, MUTEX_DRIVER, NULL);

	dma_attr.sdba_dip	 = sp->s_dip;
	dma_attr.sdba_dattrp	 = &sfxge_mon_dma_attr;
	dma_attr.sdba_callback	 = DDI_DMA_SLEEP;
	dma_attr.sdba_length	 = encp->enc_mon_stat_dma_buf_size;
	dma_attr.sdba_memflags	 = DDI_DMA_CONSISTENT;
	dma_attr.sdba_devaccp	 = &sfxge_mon_devacc;
	dma_attr.sdba_bindflags	 = DDI_DMA_READ | DDI_DMA_CONSISTENT;
	dma_attr.sdba_maxcookies = 1;
	dma_attr.sdba_zeroinit	 = B_TRUE;

	if ((rc = sfxge_dma_buffer_create(esmp, &dma_attr)) != 0)
		goto fail1;

	smp->sm_type = encp->enc_mon_type;

	DTRACE_PROBE1(mon, efx_mon_type_t, smp->sm_type);

	smp->sm_state = SFXGE_MON_INITIALIZED;

	/* Initialize the statistics */
	if ((rc = sfxge_mon_kstat_init(sp)) != 0)
		goto fail2;

	return (0);

fail2:
	DTRACE_PROBE(fail2);

	/* Tear down DMA setup */
	sfxge_dma_buffer_destroy(esmp);

fail1:
	DTRACE_PROBE1(fail1, int, rc);
	mutex_destroy(&(smp->sm_lock));

	smp->sm_sp = NULL;

	SFXGE_OBJ_CHECK(smp, sfxge_mac_t);

	return (rc);
}

int
sfxge_mon_start(sfxge_t *sp)
{
	sfxge_mon_t *smp = &(sp->s_mon);
	int rc;

	mutex_enter(&(smp->sm_lock));
	ASSERT3U(smp->sm_state, ==, SFXGE_MON_INITIALIZED);

	/* Initialize the MON module */
	if ((rc = efx_mon_init(sp->s_enp)) != 0)
		goto fail1;

	smp->sm_state = SFXGE_MON_STARTED;

	mutex_exit(&(smp->sm_lock));

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	mutex_exit(&(smp->sm_lock));

	return (rc);
}

void
sfxge_mon_stop(sfxge_t *sp)
{
	sfxge_mon_t *smp = &(sp->s_mon);

	mutex_enter(&(smp->sm_lock));

	ASSERT3U(smp->sm_state, ==, SFXGE_MON_STARTED);
	smp->sm_state = SFXGE_MON_INITIALIZED;

	/* Tear down the MON module */
	efx_mon_fini(sp->s_enp);

	mutex_exit(&(smp->sm_lock));
}

void
sfxge_mon_fini(sfxge_t *sp)
{
	sfxge_mon_t *smp = &(sp->s_mon);
	efsys_mem_t *esmp = &(smp->sm_mem);

	ASSERT3U(smp->sm_state, ==, SFXGE_MON_INITIALIZED);

	/* Tear down the statistics */
	sfxge_mon_kstat_fini(sp);

	smp->sm_state = SFXGE_MON_UNINITIALIZED;
	mutex_destroy(&(smp->sm_lock));

	smp->sm_sp = NULL;
	smp->sm_type = EFX_MON_INVALID;

	/* Tear down DMA setup */
	sfxge_dma_buffer_destroy(esmp);

	SFXGE_OBJ_CHECK(smp, sfxge_mon_t);
}
