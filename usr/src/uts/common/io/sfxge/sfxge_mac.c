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

/*
 * All efx_mac_*() must be after efx_port_init()
 * LOCKING STRATEGY: Aquire sm_lock and test sm_state==SFXGE_MAC_STARTED
 * to serialise against sfxge_restart()
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include "sfxge.h"
#include "efx.h"

#define	SFXGE_MAC_POLL_PERIOD_MS 1000

static void sfxge_mac_link_update_locked(sfxge_t *sp, efx_link_mode_t mode);


/* MAC DMA attributes */
static ddi_device_acc_attr_t sfxge_mac_devacc = {

	DDI_DEVICE_ATTR_V0,	/* devacc_attr_version */
	DDI_NEVERSWAP_ACC,	/* devacc_attr_endian_flags */
	DDI_STRICTORDER_ACC	/* devacc_attr_dataorder */
};

static ddi_dma_attr_t sfxge_mac_dma_attr = {
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


static void
_sfxge_mac_stat_update(sfxge_mac_t *smp, int tries, int delay_usec)
{
	sfxge_t *sp = smp->sm_sp;
	efsys_mem_t *esmp = &(smp->sm_mem);
	int i;

	ASSERT(mutex_owned(&(smp->sm_lock)));
	ASSERT3U(smp->sm_state, !=, SFXGE_MAC_UNINITIALIZED);

	/* if no stats pending then they are already freshly updated */
	if (smp->sm_mac_stats_timer_reqd && !smp->sm_mac_stats_pend)
		return;

	for (i = 0; i < tries; i++) {
		/* Try to update the cached counters */
		if (efx_mac_stats_update(sp->s_enp, esmp, smp->sm_stat,
		    NULL) != EAGAIN)
			goto done;

		drv_usecwait(delay_usec);
	}

	DTRACE_PROBE(mac_stat_timeout);
	dev_err(sp->s_dip, CE_NOTE, SFXGE_CMN_ERR "MAC stats timeout");
	return;

done:
	smp->sm_mac_stats_pend = B_FALSE;
	smp->sm_lbolt = ddi_get_lbolt();
}

static void
sfxge_mac_stat_update_quick(sfxge_mac_t *smp)
{
	/*
	 * Update the statistics from the most recent DMA. This might race
	 * with an inflight dma, so retry once. Otherwise get mac stat
	 * values from the last mac_poll() or MC periodic stats.
	 */
	_sfxge_mac_stat_update(smp, 2, 50);
}

static void
sfxge_mac_stat_update_wait(sfxge_mac_t *smp)
{
	/* Wait a max of 20 * 500us = 10ms */
	_sfxge_mac_stat_update(smp, 20, 500);
}

static int
sfxge_mac_kstat_update(kstat_t *ksp, int rw)
{
	sfxge_mac_t *smp = ksp->ks_private;
	kstat_named_t *knp;
	int rc;
	unsigned int val;
	sfxge_rx_coalesce_mode_t rxmode;

	if (rw != KSTAT_READ) {
		rc = EACCES;
		goto fail1;
	}

	ASSERT(mutex_owned(&(smp->sm_lock)));

	if (smp->sm_state != SFXGE_MAC_STARTED)
		goto done;

	sfxge_mac_stat_update_quick(smp);

	knp = smp->sm_stat;
	knp += EFX_MAC_NSTATS;

	knp->value.ui64 = (smp->sm_link_up) ? 1 : 0;
	knp++;

	knp->value.ui64 = smp->sm_link_speed;
	knp++;

	knp->value.ui64 = smp->sm_link_duplex;
	knp++;

	knp->value.ui64 = (smp->sm_fcntl & EFX_FCNTL_GENERATE) ? 1 : 0;
	knp++;

	knp->value.ui64 = (smp->sm_fcntl & EFX_FCNTL_RESPOND) ? 1 : 0;
	knp++;

	sfxge_ev_moderation_get(smp->sm_sp, &val);
	knp->value.ui64 = val;
	knp++;

	sfxge_rx_coalesce_mode_get(smp->sm_sp, &rxmode);
	knp->value.ui64 = (uint64_t)rxmode;
	knp++;

	if (sfxge_rx_scale_count_get(smp->sm_sp, &val) != 0)
		val = 0;
	knp->value.ui64 = val;
	knp++;

done:
	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static int
sfxge_mac_kstat_init(sfxge_t *sp)
{
	sfxge_mac_t *smp = &(sp->s_mac);
	dev_info_t *dip = sp->s_dip;
	char name[MAXNAMELEN];
	kstat_t *ksp;
	kstat_named_t *knp;
	unsigned int id;
	int rc;

	/* Create the set */
	(void) snprintf(name, MAXNAMELEN - 1, "%s_mac", ddi_driver_name(dip));

	if ((ksp = kstat_create((char *)ddi_driver_name(dip),
	    ddi_get_instance(dip), name, "mac", KSTAT_TYPE_NAMED,
	    EFX_MAC_NSTATS + 8, 0)) == NULL) {
		rc = ENOMEM;
		goto fail1;
	}

	smp->sm_ksp = ksp;

	ksp->ks_update = sfxge_mac_kstat_update;
	ksp->ks_private = smp;
	ksp->ks_lock = &(smp->sm_lock);

	/* Initialise the named stats */
	smp->sm_stat = knp = ksp->ks_data;
	for (id = 0; id < EFX_MAC_NSTATS; id++) {
		kstat_named_init(knp, (char *)efx_mac_stat_name(sp->s_enp, id),
		    KSTAT_DATA_UINT64);
		knp++;
	}

	kstat_named_init(knp++, "link_up", KSTAT_DATA_UINT64);
	kstat_named_init(knp++, "link_speed", KSTAT_DATA_UINT64);
	kstat_named_init(knp++, "link_duplex", KSTAT_DATA_UINT64);
	kstat_named_init(knp++, "fcntl_generate", KSTAT_DATA_UINT64);
	kstat_named_init(knp++, "fcntl_respond", KSTAT_DATA_UINT64);
	kstat_named_init(knp++, "intr_moderation", KSTAT_DATA_UINT64);
	kstat_named_init(knp++, "rx_coalesce_mode", KSTAT_DATA_UINT64);
	kstat_named_init(knp++, "rx_scale_count", KSTAT_DATA_UINT64);

	kstat_install(ksp);

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static void
sfxge_mac_kstat_fini(sfxge_t *sp)
{
	sfxge_mac_t *smp = &(sp->s_mac);

	/* Destroy the set */
	kstat_delete(smp->sm_ksp);
	smp->sm_ksp = NULL;
	smp->sm_stat = NULL;
}

void
sfxge_mac_stat_get(sfxge_t *sp, unsigned int id, uint64_t *valp)
{
	sfxge_mac_t *smp = &(sp->s_mac);

	/* Make sure the cached counter values are recent */
	mutex_enter(&(smp->sm_lock));

	if (smp->sm_state != SFXGE_MAC_STARTED)
		goto done;

	sfxge_mac_stat_update_quick(smp);

	*valp = smp->sm_stat[id].value.ui64;

done:
	mutex_exit(&(smp->sm_lock));
}

static void
sfxge_mac_poll(void *arg)
{
	sfxge_t *sp = arg;
	efx_nic_t *enp = sp->s_enp;
	sfxge_mac_t *smp = &(sp->s_mac);
	efsys_mem_t *esmp = &(smp->sm_mem);
	efx_link_mode_t mode;
	clock_t timeout;

	mutex_enter(&(smp->sm_lock));
	while (smp->sm_state == SFXGE_MAC_STARTED) {

		/* clears smp->sm_mac_stats_pend if appropriate */
		if (smp->sm_mac_stats_pend)
			sfxge_mac_stat_update_wait(smp);

		/* This may sleep waiting for MCDI completion */
		mode = EFX_LINK_UNKNOWN;
		if (efx_port_poll(enp, &mode) == 0)
			sfxge_mac_link_update_locked(sp, mode);

		if ((smp->sm_link_poll_reqd == B_FALSE) &&
		    (smp->sm_mac_stats_timer_reqd == B_FALSE))
			goto done;

		/* Zero the memory */
		bzero(esmp->esm_base, EFX_MAC_STATS_SIZE);

		/* Trigger upload the MAC statistics counters */
		if (smp->sm_link_up &&
		    efx_mac_stats_upload(sp->s_enp, esmp) == 0)
			smp->sm_mac_stats_pend = B_TRUE;

		/* Wait for timeout or end of polling */
		timeout = ddi_get_lbolt() + drv_usectohz(1000 *
		    SFXGE_MAC_POLL_PERIOD_MS);
		while (smp->sm_state == SFXGE_MAC_STARTED) {
			if (cv_timedwait(&(smp->sm_link_poll_kv),
			    &(smp->sm_lock), timeout) < 0) {
				/* Timeout - poll if polling still enabled */
				break;
			}
		}
	}
done:
	mutex_exit(&(smp->sm_lock));

}

static void
sfxge_mac_poll_start(sfxge_t *sp)
{
	sfxge_mac_t *smp = &(sp->s_mac);

	ASSERT(mutex_owned(&(smp->sm_lock)));
	ASSERT3U(smp->sm_state, ==, SFXGE_MAC_STARTED);

	/* Schedule a poll */
	(void) ddi_taskq_dispatch(smp->sm_tqp, sfxge_mac_poll, sp, DDI_SLEEP);
}

static void
sfxge_mac_poll_stop(sfxge_t *sp)
{
	sfxge_mac_t *smp = &(sp->s_mac);

	ASSERT(mutex_owned(&(smp->sm_lock)));
	ASSERT3U(smp->sm_state, ==, SFXGE_MAC_INITIALIZED);

	cv_broadcast(&(smp->sm_link_poll_kv));

	/* Wait for link polling to cease */
	mutex_exit(&(smp->sm_lock));
	ddi_taskq_wait(smp->sm_tqp);
	mutex_enter(&(smp->sm_lock));

	/* Collect the final statistics. */
	sfxge_mac_stat_update_wait(smp);
}

int
sfxge_mac_init(sfxge_t *sp)
{
	sfxge_mac_t *smp = &(sp->s_mac);
	efsys_mem_t *esmp = &(smp->sm_mem);
	dev_info_t *dip = sp->s_dip;
	sfxge_dma_buffer_attr_t dma_attr;
	const efx_nic_cfg_t *encp;
	unsigned char *bytes;
	unsigned int n;
	int err, rc;

	SFXGE_OBJ_CHECK(smp, sfxge_mac_t);

	ASSERT3U(smp->sm_state, ==, SFXGE_MAC_UNINITIALIZED);

	smp->sm_sp = sp;
	encp = efx_nic_cfg_get(sp->s_enp);
	smp->sm_link_poll_reqd = (~encp->enc_features &
	    EFX_FEATURE_LINK_EVENTS);
	smp->sm_mac_stats_timer_reqd = (~encp->enc_features &
	    EFX_FEATURE_PERIODIC_MAC_STATS);

	mutex_init(&(smp->sm_lock), NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(sp->s_intr.si_intr_pri));
	cv_init(&(smp->sm_link_poll_kv), NULL, CV_DRIVER, NULL);

	/* Create link poll taskq */
	smp->sm_tqp = ddi_taskq_create(dip, "mac_tq", 1, TASKQ_DEFAULTPRI, 0);
	if (smp->sm_tqp == NULL) {
		rc = ENOMEM;
		goto fail1;
	}

	if ((rc = sfxge_phy_init(sp)) != 0)
		goto fail2;

	dma_attr.sdba_dip	 = dip;
	dma_attr.sdba_dattrp	 = &sfxge_mac_dma_attr;
	dma_attr.sdba_callback	 = DDI_DMA_SLEEP;
	dma_attr.sdba_length	 = EFX_MAC_STATS_SIZE;
	dma_attr.sdba_memflags	 = DDI_DMA_CONSISTENT;
	dma_attr.sdba_devaccp	 = &sfxge_mac_devacc;
	dma_attr.sdba_bindflags	 = DDI_DMA_READ | DDI_DMA_CONSISTENT;
	dma_attr.sdba_maxcookies = 1;
	dma_attr.sdba_zeroinit	 = B_TRUE;

	if ((rc = sfxge_dma_buffer_create(esmp, &dma_attr)) != 0)
		goto fail3;

	/* Set the initial flow control values */
	smp->sm_fcntl = EFX_FCNTL_RESPOND | EFX_FCNTL_GENERATE;

	/*
	 * Determine the 'burnt-in' MAC address:
	 *
	 * A: if the "mac-address" property is set on our device node use that.
	 * B: otherwise, use the value from NVRAM.
	 */

	/* A: property  */
	err = ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "mac-address", &bytes, &n);
	switch (err) {
	case DDI_PROP_SUCCESS:
		if (n == ETHERADDRL) {
			bcopy(bytes, smp->sm_bia, ETHERADDRL);
			goto done;
		}

		ddi_prop_free(bytes);
		break;

	default:
		break;
	}

	/* B: NVRAM */
	bcopy(encp->enc_mac_addr, smp->sm_bia, ETHERADDRL);

done:
	/* Initialize the statistics */
	if ((rc = sfxge_mac_kstat_init(sp)) != 0)
		goto fail4;

	if ((rc = sfxge_phy_kstat_init(sp)) != 0)
		goto fail5;

	smp->sm_state = SFXGE_MAC_INITIALIZED;

	return (0);

fail5:
	DTRACE_PROBE(fail5);

	sfxge_mac_kstat_fini(sp);
fail4:
	DTRACE_PROBE(fail4);

	/* Tear down DMA setup */
	sfxge_dma_buffer_destroy(esmp);
fail3:
	DTRACE_PROBE(fail3);

	sfxge_phy_fini(sp);
fail2:
	DTRACE_PROBE(fail2);

	/* Destroy the link poll taskq */
	ddi_taskq_destroy(smp->sm_tqp);
	smp->sm_tqp = NULL;

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	cv_destroy(&(smp->sm_link_poll_kv));

	mutex_destroy(&(smp->sm_lock));

	smp->sm_sp = NULL;

	return (rc);
}

static int
sfxge_mac_filter_apply(sfxge_t *sp)
{
	efx_nic_t *enp = sp->s_enp;
	sfxge_mac_t *smp = &(sp->s_mac);
	int rc;

	ASSERT(mutex_owned(&(smp->sm_lock)));

	if (smp->sm_state == SFXGE_MAC_STARTED) {
		boolean_t all_unicst;
		boolean_t mulcst;
		boolean_t all_mulcst;
		boolean_t brdcst;

		all_unicst = (smp->sm_promisc == SFXGE_PROMISC_ALL_PHYS);
		mulcst = (smp->sm_mcast_count > 0);
		all_mulcst = (smp->sm_promisc >= SFXGE_PROMISC_ALL_MULTI);
		brdcst = B_TRUE;

		if ((rc = efx_mac_filter_set(enp, all_unicst, mulcst,
		    all_mulcst, brdcst)) != 0) {
			goto fail1;
		}
		if ((rc = efx_mac_multicast_list_set(enp,
		    smp->sm_mcast_addr, smp->sm_mcast_count)) != 0)
			goto fail2;
	}

	return (0);

fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

int
sfxge_mac_start(sfxge_t *sp, boolean_t restart)
{
	sfxge_mac_t *smp = &(sp->s_mac);
	efsys_mem_t *esmp = &(smp->sm_mem);
	efx_nic_t *enp = sp->s_enp;
	size_t pdu;
	int rc;

	mutex_enter(&(smp->sm_lock));

	ASSERT3U(smp->sm_state, ==, SFXGE_MAC_INITIALIZED);

	if ((rc = efx_port_init(enp)) != 0)
		goto fail1;

	/*
	 * Set up the advertised capabilities that may have been asked for
	 * before the call to efx_port_init().
	 */
	if ((rc = sfxge_phy_cap_apply(sp, !restart)) != 0)
		goto fail2;

	/* Set the SDU */
	pdu = EFX_MAC_PDU(sp->s_mtu);
	if ((rc = efx_mac_pdu_set(enp, pdu)) != 0)
		goto fail3;

	if ((rc = efx_mac_fcntl_set(enp, smp->sm_fcntl, B_TRUE)) != 0)
		goto fail4;

	/* Set the unicast address */
	if ((rc = efx_mac_addr_set(enp, (smp->sm_laa_valid) ?
	    smp->sm_laa : smp->sm_bia)) != 0)
		goto fail5;

	if ((rc = sfxge_mac_filter_apply(sp)) != 0)
		goto fail6;

	if (!smp->sm_mac_stats_timer_reqd) {
		if ((rc = efx_mac_stats_periodic(enp, esmp,
		    SFXGE_MAC_POLL_PERIOD_MS, B_FALSE)) != 0)
			goto fail7;
	}

	if ((rc = efx_mac_drain(enp, B_FALSE)) != 0)
		goto fail8;

	smp->sm_state = SFXGE_MAC_STARTED;

	/*
	 * Start link state polling. For hardware that reports link change
	 * events we still poll once to update the initial link state.
	 */
	sfxge_mac_poll_start(sp);

	mutex_exit(&(smp->sm_lock));
	return (0);

fail8:
	DTRACE_PROBE(fail8);
	(void) efx_mac_stats_periodic(enp, esmp, 0, B_FALSE);
fail7:
	DTRACE_PROBE(fail7);
fail6:
	DTRACE_PROBE(fail6);
fail5:
	DTRACE_PROBE(fail5);
fail4:
	DTRACE_PROBE(fail4);
fail3:
	DTRACE_PROBE(fail3);
fail2:
	DTRACE_PROBE(fail2);
	efx_port_fini(enp);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	mutex_exit(&(smp->sm_lock));

	return (rc);
}


static void
sfxge_mac_link_update_locked(sfxge_t *sp, efx_link_mode_t mode)
{
	sfxge_mac_t *smp = &(sp->s_mac);
	const char *change, *duplex;
	char info[sizeof (": now 10000Mbps FULL duplex")];

	ASSERT(mutex_owned(&(smp->sm_lock)));
	if (smp->sm_state != SFXGE_MAC_STARTED)
		return;

	if (smp->sm_link_mode == mode)
		return;

	smp->sm_link_mode = mode;
	smp->sm_link_up = B_TRUE;

	switch (smp->sm_link_mode) {
	case EFX_LINK_UNKNOWN:
	case EFX_LINK_DOWN:
		smp->sm_link_speed = 0;
		smp->sm_link_duplex = SFXGE_LINK_DUPLEX_UNKNOWN;
		smp->sm_link_up = B_FALSE;
		break;

	case EFX_LINK_10HDX:
	case EFX_LINK_10FDX:
		smp->sm_link_speed = 10;
		smp->sm_link_duplex = (smp->sm_link_mode == EFX_LINK_10HDX) ?
		    SFXGE_LINK_DUPLEX_HALF : SFXGE_LINK_DUPLEX_FULL;
		break;

	case EFX_LINK_100HDX:
	case EFX_LINK_100FDX:
		smp->sm_link_speed = 100;
		smp->sm_link_duplex = (smp->sm_link_mode == EFX_LINK_100HDX) ?
		    SFXGE_LINK_DUPLEX_HALF : SFXGE_LINK_DUPLEX_FULL;
		break;

	case EFX_LINK_1000HDX:
	case EFX_LINK_1000FDX:
		smp->sm_link_speed = 1000;
		smp->sm_link_duplex = (smp->sm_link_mode == EFX_LINK_1000HDX) ?
		    SFXGE_LINK_DUPLEX_HALF : SFXGE_LINK_DUPLEX_FULL;
		break;

	case EFX_LINK_10000FDX:
		smp->sm_link_speed = 10000;
		smp->sm_link_duplex = SFXGE_LINK_DUPLEX_FULL;
		break;

	case EFX_LINK_40000FDX:
		smp->sm_link_speed = 40000;
		smp->sm_link_duplex = SFXGE_LINK_DUPLEX_FULL;
		break;

	default:
		ASSERT(B_FALSE);
		break;
	}

	duplex = (smp->sm_link_duplex == SFXGE_LINK_DUPLEX_FULL) ?
	    "full" : "half";
	change = (smp->sm_link_up) ? "UP" : "DOWN";
	(void) snprintf(info, sizeof (info), ": now %dMbps %s duplex",
	    smp->sm_link_speed, duplex);

	dev_err(sp->s_dip, CE_NOTE, SFXGE_CMN_ERR "Link %s%s",
	    change, smp->sm_link_up ? info : "");

	/* Push link state update to the OS */
	sfxge_gld_link_update(sp);
}

void
sfxge_mac_link_update(sfxge_t *sp, efx_link_mode_t mode)
{
	sfxge_mac_t *smp = &(sp->s_mac);

	mutex_enter(&(smp->sm_lock));
	sfxge_mac_link_update_locked(sp, mode);
	mutex_exit(&(smp->sm_lock));
}

void
sfxge_mac_link_check(sfxge_t *sp, boolean_t *upp)
{
	sfxge_mac_t *smp = &(sp->s_mac);

	mutex_enter(&(smp->sm_lock));
	*upp = smp->sm_link_up;
	mutex_exit(&(smp->sm_lock));
}

void
sfxge_mac_link_speed_get(sfxge_t *sp, unsigned int *speedp)
{
	sfxge_mac_t *smp = &(sp->s_mac);

	mutex_enter(&(smp->sm_lock));
	*speedp = smp->sm_link_speed;
	mutex_exit(&(smp->sm_lock));
}

void
sfxge_mac_link_duplex_get(sfxge_t *sp, sfxge_link_duplex_t *duplexp)
{
	sfxge_mac_t *smp = &(sp->s_mac);

	mutex_enter(&(smp->sm_lock));
	*duplexp = smp->sm_link_duplex;
	mutex_exit(&(smp->sm_lock));
}

void
sfxge_mac_fcntl_get(sfxge_t *sp, unsigned int *fcntlp)
{
	sfxge_mac_t *smp = &(sp->s_mac);

	mutex_enter(&(smp->sm_lock));
	*fcntlp = smp->sm_fcntl;
	mutex_exit(&(smp->sm_lock));
}

int
sfxge_mac_fcntl_set(sfxge_t *sp, unsigned int fcntl)
{
	sfxge_mac_t *smp = &(sp->s_mac);
	int rc;

	mutex_enter(&(smp->sm_lock));

	if (smp->sm_fcntl == fcntl)
		goto done;

	smp->sm_fcntl = fcntl;

	if (smp->sm_state != SFXGE_MAC_STARTED)
		goto done;

	if ((rc = efx_mac_fcntl_set(sp->s_enp, smp->sm_fcntl, B_TRUE)) != 0)
		goto fail1;

done:
	mutex_exit(&(smp->sm_lock));

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	mutex_exit(&(smp->sm_lock));

	return (rc);
}

int
sfxge_mac_unicst_get(sfxge_t *sp, sfxge_unicst_type_t type, uint8_t *addr)
{
	sfxge_mac_t *smp = &(sp->s_mac);
	int rc;

	if (type >= SFXGE_UNICST_NTYPES) {
		rc = EINVAL;
		goto fail1;
	}

	mutex_enter(&(smp->sm_lock));

	if (smp->sm_state != SFXGE_MAC_INITIALIZED &&
	    smp->sm_state != SFXGE_MAC_STARTED) {
		rc = EFAULT;
		goto fail2;
	}

	switch (type) {
	case SFXGE_UNICST_BIA:
		bcopy(smp->sm_bia, addr, ETHERADDRL);
		break;

	case SFXGE_UNICST_LAA:
		if (!(smp->sm_laa_valid)) {
			rc = ENOENT;
			goto fail3;
		}

		bcopy(smp->sm_laa, addr, ETHERADDRL);
		break;

	default:
		ASSERT(B_FALSE);
		break;
	}

	mutex_exit(&(smp->sm_lock));

	return (0);


fail3:
	DTRACE_PROBE(fail3);
fail2:
	DTRACE_PROBE(fail2);

	mutex_exit(&(smp->sm_lock));

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

int
sfxge_mac_unicst_set(sfxge_t *sp, uint8_t *addr)
{
	sfxge_mac_t *smp = &(sp->s_mac);
	efx_nic_t *enp = sp->s_enp;
	boolean_t old_mac_valid;
	uint8_t old_mac[ETHERADDRL];
	int rc;

	mutex_enter(&(smp->sm_lock));

	old_mac_valid = smp->sm_laa_valid;
	if (old_mac_valid)
		bcopy(smp->sm_laa, old_mac, ETHERADDRL);

	bcopy(addr, smp->sm_laa, ETHERADDRL);
	smp->sm_laa_valid = B_TRUE;

	if (smp->sm_state != SFXGE_MAC_STARTED)
		goto done;

	if (efx_nic_cfg_get(enp)->enc_allow_set_mac_with_installed_filters) {
		if ((rc = efx_mac_addr_set(enp, smp->sm_laa)) != 0) {
			dev_err(sp->s_dip, CE_NOTE, SFXGE_CMN_ERR
			    "unable to set unicast MAC filter");
			goto fail1;
		}
	} else {
		/* Older EF10 firmware requires a device start */
		mutex_exit(&smp->sm_lock);
		sfxge_stop(sp);
		if ((rc = sfxge_start(sp, B_TRUE)) != 0) {
			dev_err(sp->s_dip, CE_NOTE, SFXGE_CMN_ERR
			    "unable to restart with a new MAC");
			mutex_enter(&(smp->sm_lock));
			goto fail1;
		}
		mutex_enter(&smp->sm_lock);
	}

	if ((rc = efx_mac_addr_set(enp, smp->sm_laa)) != 0)
		goto fail1;

done:
	mutex_exit(&(smp->sm_lock));

	return (0);

fail1:
	if (old_mac_valid)
		bcopy(old_mac, smp->sm_laa, ETHERADDRL);
	else
		smp->sm_laa_valid = B_FALSE;

	DTRACE_PROBE1(fail1, int, rc);

	mutex_exit(&(smp->sm_lock));

	return (rc);
}

int
sfxge_mac_promisc_set(sfxge_t *sp, sfxge_promisc_type_t promisc)
{
	sfxge_mac_t *smp = &(sp->s_mac);
	int rc;

	mutex_enter(&(smp->sm_lock));

	if (smp->sm_promisc == promisc)
		goto done;

	smp->sm_promisc = promisc;

	if ((rc = sfxge_mac_filter_apply(sp)) != 0)
		goto fail1;

done:
	mutex_exit(&(smp->sm_lock));
	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);
	mutex_exit(&(smp->sm_lock));

	return (rc);
}

int
sfxge_mac_multicst_add(sfxge_t *sp, const uint8_t *addr)
{
	sfxge_mac_t *smp = &(sp->s_mac);
	int i;
	int rc;

	mutex_enter(&(smp->sm_lock));

	if ((addr[0] & 0x1) == 0) {
		rc = EINVAL;
		goto fail1;
	}

	/* Check if the address is already in the list */
	i = 0;
	while (i < smp->sm_mcast_count) {
		if (bcmp(smp->sm_mcast_addr + (i * ETHERADDRL),
		    addr, ETHERADDRL) == 0)
			goto done;
		else
			i++;
	}

	if (smp->sm_mcast_count >= EFX_MAC_MULTICAST_LIST_MAX) {
		rc = ENOENT;
		goto fail1;
	}

	/* Add to the list */
	bcopy(addr, smp->sm_mcast_addr + (smp->sm_mcast_count++ * ETHERADDRL),
	    ETHERADDRL);

	if ((rc = sfxge_mac_filter_apply(sp)) != 0)
		goto fail2;

done:
	mutex_exit(&(smp->sm_lock));
	return (0);

fail2:
	DTRACE_PROBE(fail2);
	smp->sm_mcast_count--;
fail1:
	DTRACE_PROBE1(fail1, int, rc);
	mutex_exit(&(smp->sm_lock));

	return (rc);
}

int
sfxge_mac_multicst_remove(sfxge_t *sp, const uint8_t *addr)
{
	sfxge_mac_t *smp = &(sp->s_mac);
	int i;
	int rc;

	mutex_enter(&(smp->sm_lock));

	i = 0;
	while (i < smp->sm_mcast_count) {
		if (bcmp(smp->sm_mcast_addr + (i * ETHERADDRL),
		    addr, ETHERADDRL) == 0) {
			(void) memmove(smp->sm_mcast_addr + (i * ETHERADDRL),
			    smp->sm_mcast_addr + ((i + 1) * ETHERADDRL),
			    (smp->sm_mcast_count - (i + 1)) * ETHERADDRL);
			smp->sm_mcast_count--;
		} else
			i++;
	}

	if ((rc = sfxge_mac_filter_apply(sp)) != 0)
		goto fail1;

	mutex_exit(&(smp->sm_lock));
	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);
	mutex_exit(&(smp->sm_lock));

	return (rc);
}

void
sfxge_mac_stop(sfxge_t *sp)
{
	sfxge_mac_t *smp = &(sp->s_mac);
	efx_nic_t *enp = sp->s_enp;
	efsys_mem_t *esmp = &(smp->sm_mem);

	mutex_enter(&(smp->sm_lock));

	ASSERT3U(smp->sm_state, ==, SFXGE_MAC_STARTED);
	ASSERT3P(smp->sm_sp, ==, sp);
	smp->sm_state = SFXGE_MAC_INITIALIZED;

	/* If stopping in response to an MC reboot this may fail */
	if (!smp->sm_mac_stats_timer_reqd)
		(void) efx_mac_stats_periodic(enp, esmp, 0, B_FALSE);

	sfxge_mac_poll_stop(sp);

	smp->sm_lbolt = 0;

	smp->sm_link_up = B_FALSE;
	smp->sm_link_speed = 0;
	smp->sm_link_duplex = SFXGE_LINK_DUPLEX_UNKNOWN;

	/* This may call MCDI */
	(void) efx_mac_drain(enp, B_TRUE);

	smp->sm_link_mode = EFX_LINK_UNKNOWN;

	efx_port_fini(enp);

	mutex_exit(&(smp->sm_lock));
}

void
sfxge_mac_fini(sfxge_t *sp)
{
	sfxge_mac_t *smp = &(sp->s_mac);
	efsys_mem_t *esmp = &(smp->sm_mem);

	ASSERT3U(smp->sm_state, ==, SFXGE_MAC_INITIALIZED);
	ASSERT3P(smp->sm_sp, ==, sp);

	/* Tear down the statistics */
	sfxge_phy_kstat_fini(sp);
	sfxge_mac_kstat_fini(sp);

	smp->sm_state = SFXGE_MAC_UNINITIALIZED;
	smp->sm_link_mode = EFX_LINK_UNKNOWN;
	smp->sm_promisc = SFXGE_PROMISC_OFF;

	bzero(smp->sm_mcast_addr, sizeof (smp->sm_mcast_addr));
	smp->sm_mcast_count = 0;

	bzero(smp->sm_laa, ETHERADDRL);
	smp->sm_laa_valid = B_FALSE;

	bzero(smp->sm_bia, ETHERADDRL);

	smp->sm_fcntl = 0;

	/* Finish with PHY DMA memory */
	sfxge_phy_fini(sp);

	/* Teardown the DMA */
	sfxge_dma_buffer_destroy(esmp);

	/* Destroy the link poll taskq */
	ddi_taskq_destroy(smp->sm_tqp);
	smp->sm_tqp = NULL;

	mutex_destroy(&(smp->sm_lock));

	smp->sm_sp = NULL;
}
