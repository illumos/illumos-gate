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
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/ethernet.h>
#include <sys/pci.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/processor.h>
#include <sys/cpuvar.h>
#include <sys/pghw.h>

#include "sfxge.h"
#include "sfxge_version.h"
#include "efsys.h"
#include "efx.h"

#ifdef	DEBUG
boolean_t sfxge_aask = B_FALSE;
#endif

/* Receive queue TRIM default polling interval (in microseconds) */
#define	SFXGE_RX_QPOLL_USEC	(5000000)

/* Broadcast address */
uint8_t	sfxge_brdcst[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/*
 * By default modinfo will display lines truncated to 80 characters and so just
 * show 32 characters of our sfxge_ident string.
 */
const char sfxge_ident[] = "Solarflare 10Gb/40Gb Ethernet";
const char sfxge_version[] = SFXGE_VERSION_STRING;

static void
sfxge_cfg_build(sfxge_t *sp)
{
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(sp->s_enp);
	(void) snprintf(sp->s_cfg_kstat.buf.sck_mac, 64,
	    "%02X:%02X:%02X:%02X:%02X:%02X",
	    encp->enc_mac_addr[0], encp->enc_mac_addr[1],
	    encp->enc_mac_addr[2], encp->enc_mac_addr[3],
	    encp->enc_mac_addr[4], encp->enc_mac_addr[5]);
}

static int
sfxge_create(dev_info_t *dip, sfxge_t **spp)
{
	sfxge_t *sp;
	efx_nic_t *enp;
	unsigned int rxq_size;
	int rxq_poll_usec;
	int rc;

	/* Allocate the object */
	sp = kmem_zalloc(sizeof (*sp), KM_SLEEP);
	sp->s_dip = dip;
	ddi_set_driver_private(dip, sp);

	mutex_init(&(sp->s_state_lock), NULL, MUTEX_DRIVER, NULL);
	sp->s_state = SFXGE_UNINITIALIZED;

	/* Get property values */
	sp->s_mtu = ddi_prop_get_int(DDI_DEV_T_ANY, sp->s_dip,
	    DDI_PROP_DONTPASS, "mtu", ETHERMTU);

	sp->s_action_on_hw_err = ddi_prop_get_int(DDI_DEV_T_ANY, sp->s_dip,
	    DDI_PROP_DONTPASS, "action_on_hw_err", SFXGE_RECOVER);

	rxq_size = ddi_prop_get_int(DDI_DEV_T_ANY, sp->s_dip,
	    DDI_PROP_DONTPASS, "rxq_size", SFXGE_DEFAULT_RXQ_SIZE);
	if (!(ISP2(rxq_size)))
		rxq_size = SFXGE_DEFAULT_RXQ_SIZE;
	rxq_size = min(rxq_size, EFX_RXQ_MAXNDESCS);
	sp->s_rxq_size = (uint16_t)max(rxq_size, EFX_RXQ_MINNDESCS);

	/* Configure polling interval for queue refill/trim */
	rxq_poll_usec = ddi_prop_get_int(DDI_DEV_T_ANY, sp->s_dip,
	    DDI_PROP_DONTPASS, "rxq_poll_usec", SFXGE_RX_QPOLL_USEC);
	if (rxq_poll_usec <= 0)
		rxq_poll_usec = SFXGE_RX_QPOLL_USEC;
	sp->s_rxq_poll_usec = rxq_poll_usec;

#if EFSYS_OPT_MCDI_LOGGING
	sp->s_mcdi_logging = ddi_prop_get_int(DDI_DEV_T_ANY, sp->s_dip,
	    DDI_PROP_DONTPASS, "mcdi_logging", 0);
#endif

	/* Create a taskq */
	sp->s_tqp = ddi_taskq_create(dip, "tq", 1, TASKQ_DEFAULTPRI, 0);
	if (sp->s_tqp == NULL) {
		rc = ENOMEM;
		goto fail2;
	}

	/* Check and initialize PCI configuration space */
	if ((rc = sfxge_pci_init(sp)) != 0)
		goto fail3;

	/* Map the device registers */
	if ((rc = sfxge_bar_init(sp)) != 0)
		goto fail4;

	/* Create the NIC object */
	mutex_init(&(sp->s_nic_lock), NULL, MUTEX_DRIVER, NULL);

	if ((rc = efx_nic_create(sp->s_family, (efsys_identifier_t *)sp,
	    &(sp->s_bar), &(sp->s_nic_lock), &enp)) != 0)
		goto fail5;

	sp->s_enp = enp;

	/* Initialize MCDI to talk to the Microcontroller */
	if ((rc = sfxge_mcdi_init(sp)) != 0)
		goto fail6;

	/* Probe the NIC and build the configuration data area */
	if ((rc = efx_nic_probe(enp)) != 0)
		goto fail7;

	switch (sp->s_family) {
	case EFX_FAMILY_HUNTINGTON:
		sfxge_pcie_check_link(sp, 8, 3); /* PCI 8x Gen3 */
		break;

	case EFX_FAMILY_SIENA:
		sfxge_pcie_check_link(sp, 8, 2); /* PCI 8x Gen2 */
		break;

	default:
		break;
	}

	if ((rc = efx_nvram_init(enp)) != 0)
		goto fail8;

	if ((rc = efx_vpd_init(enp)) != 0)
		goto fail9;

	if ((rc = efx_nic_reset(enp)) != 0)
		goto fail10;

	sfxge_sram_init(sp);

	if ((rc = sfxge_intr_init(sp)) != 0)
		goto fail11;

	if ((rc = sfxge_ev_init(sp)) != 0)
		goto fail12;

	if ((rc = sfxge_mac_init(sp)) != 0)
		goto fail13;

	if ((rc = sfxge_rx_init(sp)) != 0)
		goto fail14;

	if ((rc = sfxge_tx_init(sp)) != 0)
		goto fail15;

	if ((rc = sfxge_mon_init(sp)) != 0)
		goto fail16;

	mutex_init(&(sp->s_tx_flush_lock), NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(sp->s_intr.si_intr_pri));
	cv_init(&(sp->s_tx_flush_kv), NULL, CV_DRIVER, NULL);

	sp->s_state = SFXGE_INITIALIZED;

	*spp = sp;
	return (0);

fail16:
	DTRACE_PROBE(fail15);
	sfxge_tx_fini(sp);

fail15:
	DTRACE_PROBE(fail14);
	sfxge_rx_fini(sp);

fail14:
	DTRACE_PROBE(fail14);
	sfxge_mac_fini(sp);

fail13:
	DTRACE_PROBE(fail13);
	sfxge_ev_fini(sp);

fail12:
	DTRACE_PROBE(fail12);
	sfxge_intr_fini(sp);

fail11:
	DTRACE_PROBE(fail11);
	sfxge_sram_fini(sp);
	(void) efx_nic_reset(sp->s_enp);

fail10:
	DTRACE_PROBE(fail10);
	efx_vpd_fini(enp);

fail9:
	DTRACE_PROBE(fail9);
	efx_nvram_fini(enp);

fail8:
	DTRACE_PROBE(fail8);
	efx_nic_unprobe(enp);

fail7:
	DTRACE_PROBE(fail7);
	sfxge_mcdi_fini(sp);

fail6:
	DTRACE_PROBE(fail6);
	sp->s_enp = NULL;
	efx_nic_destroy(enp);

fail5:
	DTRACE_PROBE(fail5);
	mutex_destroy(&(sp->s_nic_lock));
	sfxge_bar_fini(sp);

fail4:
	DTRACE_PROBE(fail4);
	sfxge_pci_fini(sp);

fail3:
	DTRACE_PROBE(fail3);
	ddi_taskq_destroy(sp->s_tqp);
	sp->s_tqp = NULL;

fail2:
	DTRACE_PROBE(fail2);

	/* Clear property values */
	sp->s_mtu = 0;

	mutex_destroy(&(sp->s_state_lock));

	/* Free the soft state */
	sp->s_dip = NULL;

	SFXGE_OBJ_CHECK(sp, sfxge_t);
	kmem_free(sp, sizeof (*sp));

	return (rc);
}


static int
sfxge_start_locked(sfxge_t *sp, boolean_t restart)
{
	int rc;

	ASSERT(mutex_owned(&(sp->s_state_lock)));

	if (sp->s_state == SFXGE_STARTED)
		goto done;

	if (sp->s_state != SFXGE_REGISTERED) {
		rc = EINVAL;
		goto fail1;
	}
	sp->s_state = SFXGE_STARTING;

	/* Start a new epoch (allow fresh MCDI requests to succeed) */
	efx_mcdi_new_epoch(sp->s_enp);

	if ((rc = efx_nic_reset(sp->s_enp)) != 0)
		goto fail2;

	if ((rc = efx_nic_init(sp->s_enp)) != 0)
		goto fail3;

	if ((rc = efx_filter_init(sp->s_enp)) != 0)
		goto fail4;

	if ((rc = sfxge_sram_start(sp)) != 0)
		goto fail5;

	if ((rc = sfxge_intr_start(sp)) != 0)
		goto fail6;

	if ((rc = sfxge_ev_start(sp)) != 0)
		goto fail7;

	if ((rc = sfxge_mac_start(sp, restart)) != 0)
		goto fail8;

	if ((rc = sfxge_rx_start(sp)) != 0)
		goto fail9;

	if ((rc = sfxge_tx_start(sp)) != 0)
		goto fail10;

	if ((rc = sfxge_mon_start(sp)) != 0)
		goto fail11;

	ASSERT3U(sp->s_state, ==, SFXGE_STARTING);
	sp->s_state = SFXGE_STARTED;

	/* Notify any change of MTU */
	sfxge_gld_mtu_update(sp);

done:
	return (0);

fail11:
	DTRACE_PROBE(fail11);
	sfxge_tx_stop(sp);

fail10:
	DTRACE_PROBE(fail10);
	sfxge_rx_stop(sp);

fail9:
	DTRACE_PROBE(fail9);
	sfxge_mac_stop(sp);

fail8:
	DTRACE_PROBE(fail8);
	sfxge_ev_stop(sp);

fail7:
	DTRACE_PROBE(fail7);
	sfxge_intr_stop(sp);

fail6:
	DTRACE_PROBE(fail6);
	sfxge_sram_stop(sp);

fail5:
	DTRACE_PROBE(fail5);
	efx_filter_fini(sp->s_enp);

fail4:
	DTRACE_PROBE(fail4);
	efx_nic_fini(sp->s_enp);

fail3:
	DTRACE_PROBE(fail3);
	(void) efx_nic_reset(sp->s_enp);

fail2:
	DTRACE_PROBE(fail2);

	ASSERT3U(sp->s_state, ==, SFXGE_STARTING);
	sp->s_state = SFXGE_REGISTERED;

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}


int
sfxge_start(sfxge_t *sp, boolean_t restart)
{
	int rc;

	mutex_enter(&(sp->s_state_lock));
	rc = sfxge_start_locked(sp, restart);
	mutex_exit(&(sp->s_state_lock));
	return (rc);
}


static void
sfxge_stop_locked(sfxge_t *sp)
{
	ASSERT(mutex_owned(&(sp->s_state_lock)));

	if (sp->s_state != SFXGE_STARTED) {
		return;
	}
	sp->s_state = SFXGE_STOPPING;

	sfxge_mon_stop(sp);
	sfxge_tx_stop(sp);
	sfxge_rx_stop(sp);
	sfxge_mac_stop(sp);

	/* Stop event processing - must be after rx_stop see sfxge_rx_qpoll() */
	sfxge_ev_stop(sp);
	sfxge_intr_stop(sp); /* cope with late flush/soft events until here */
	sfxge_sram_stop(sp);

	efx_filter_fini(sp->s_enp);

	efx_nic_fini(sp->s_enp);
	(void) efx_nic_reset(sp->s_enp);

	ASSERT3U(sp->s_state, ==, SFXGE_STOPPING);
	sp->s_state = SFXGE_REGISTERED;
}

void
sfxge_stop(sfxge_t *sp)
{
	mutex_enter(&(sp->s_state_lock));
	sfxge_stop_locked(sp);
	mutex_exit(&(sp->s_state_lock));
}

static void
_sfxge_restart(void *arg)
{
	sfxge_t *sp = arg;
	int rc;

	/* logging on entry is in sfxge_restart_dispatch */
	mutex_enter(&(sp->s_state_lock));

	DTRACE_PROBE(_sfxge_restart);
	if (sp->s_state != SFXGE_STARTED)
		goto done;

	/* inform the OS that the link is down - may trigger IPMP failover */
	if (sp->s_hw_err && sp->s_action_on_hw_err != SFXGE_INVISIBLE) {
		sp->s_mac.sm_link_mode = EFX_LINK_DOWN;
		sfxge_gld_link_update(sp);
	}

	/* Stop processing */
	sfxge_stop_locked(sp);

	if (sp->s_hw_err && sp->s_action_on_hw_err == SFXGE_LEAVE_DEAD) {
		dev_err(sp->s_dip, CE_WARN, SFXGE_CMN_ERR
		    "NIC error - interface is"
		    " being left permanently DOWN per driver config");

		(void) atomic_swap_32(&(sp->s_nested_restarts), 0);
		mutex_exit(&(sp->s_state_lock));
		return;
	} else
		sp->s_hw_err = SFXGE_HW_OK;

	/* Start processing */
	if ((rc = sfxge_start_locked(sp, B_TRUE)) != 0)
		goto fail1;

done:
	(void) atomic_swap_32(&(sp->s_nested_restarts), 0);
	mutex_exit(&(sp->s_state_lock));
	dev_err(sp->s_dip, CE_WARN, SFXGE_CMN_ERR "NIC restart complete");
	return;

fail1:
	DTRACE_PROBE1(fail1, int, rc);
	dev_err(sp->s_dip, CE_WARN,
	    SFXGE_CMN_ERR "FATAL ERROR: NIC restart failed rc=%d", rc);

	(void) atomic_swap_32(&(sp->s_nested_restarts), 0);
	mutex_exit(&(sp->s_state_lock));
}

int
sfxge_restart_dispatch(sfxge_t *sp, uint_t cflags, sfxge_hw_err_t hw_err,
    const char *reason, uint32_t errval)
{
	if (hw_err == SFXGE_HW_OK)
		sp->s_num_restarts++;
	else {
		sp->s_hw_err = hw_err;
		sp->s_num_restarts_hw_err++;
	}

	if (atomic_inc_32_nv(&(sp->s_nested_restarts)) > 1) {
		/* A restart is currently in progress */
		return (0);
	}

	DTRACE_PROBE2(sfxge_restart_dispatch, sfxge_hw_err_t, hw_err, char *,
	    reason);

	dev_err(sp->s_dip, CE_WARN, SFXGE_CMN_ERR "NIC restart due to %s:%d",
	    reason, errval);

	/* If cflags == DDI_SLEEP then guaranteed to succeed */
	return (ddi_taskq_dispatch(sp->s_tqp, _sfxge_restart, sp, cflags));
}


static int
sfxge_can_destroy(sfxge_t *sp)
{
	int index;

	/*
	 * In SFC bug 19834 it was noted that a mblk passed up to STREAMS
	 * could be reused for transmit and sit in the sfxge_tx_packet_cache.
	 * This call to empty the TX deferred packet list may result in
	 * rx_loaned reducing.
	 */
	index = EFX_ARRAY_SIZE(sp->s_stp);
	while (--index >= 0) {
		sfxge_txq_t *stp = sp->s_stp[index];

		if (stp != NULL)
			sfxge_tx_qdpl_flush(stp);
	}

	/* Need to wait for desballoc free_func callback */
	return (sfxge_rx_loaned(sp));
}


static int
sfxge_destroy(sfxge_t *sp)
{
	ddi_taskq_t *tqp;
	efx_nic_t *enp;
	int rc;

	ASSERT3U(sp->s_state, ==, SFXGE_INITIALIZED);
	enp = sp->s_enp;

	if (sfxge_can_destroy(sp) != 0) {
		rc = EBUSY;
		goto fail1;
	}

	sp->s_state = SFXGE_UNINITIALIZED;

	cv_destroy(&(sp->s_tx_flush_kv));
	mutex_destroy(&(sp->s_tx_flush_lock));

	sfxge_mon_fini(sp);
	sfxge_tx_fini(sp);
	sfxge_rx_fini(sp);
	sfxge_mac_fini(sp);
	sfxge_ev_fini(sp);
	sfxge_intr_fini(sp);
	sfxge_sram_fini(sp);
	(void) efx_nic_reset(enp);

	efx_vpd_fini(enp);
	efx_nvram_fini(enp);
	efx_nic_unprobe(enp);
	sfxge_mcdi_fini(sp);

	/* Destroy the NIC object */
	sp->s_enp = NULL;
	efx_nic_destroy(enp);

	mutex_destroy(&(sp->s_nic_lock));

	/* Unmap the device registers */
	sfxge_bar_fini(sp);

	/* Tear down PCI configuration space */
	sfxge_pci_fini(sp);

	/* Destroy the taskq */
	tqp = sp->s_tqp;
	sp->s_tqp = NULL;
	ddi_taskq_destroy(tqp);

	mutex_destroy(&(sp->s_state_lock));

	/* Clear property values */
	sp->s_mtu = 0;

	/* Free the soft state */
	sp->s_dip = NULL;

	SFXGE_OBJ_CHECK(sp, sfxge_t);
	kmem_free(sp, sizeof (*sp));

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

void
sfxge_ioctl(sfxge_t *sp, queue_t *wq, mblk_t *mp)
{
	struct iocblk *iocp;
	int rc, taskq_wait = 0;
	size_t ioclen = 0;

	/*
	 * single concurrent IOCTL
	 * serialized from sfxge_create, _destroy, _(re)start, _stop
	 */
	mutex_enter(&(sp->s_state_lock));

	/*LINTED*/
	iocp = (struct iocblk *)mp->b_rptr;

	switch (iocp->ioc_cmd) {
	case SFXGE_NVRAM_IOC:
		ioclen = sizeof (sfxge_nvram_ioc_t);
		break;
	case SFXGE_MCDI_IOC:
		ioclen = sizeof (sfxge_mcdi_ioc_t);
		break;
	case SFXGE_MCDI2_IOC:
		ioclen = sizeof (sfxge_mcdi2_ioc_t);
		break;
	case SFXGE_VPD_IOC:
		ioclen = sizeof (sfxge_vpd_ioc_t);
		break;
	case SFXGE_NIC_RESET_IOC:
		break;
	default:
		rc = ENOTSUP;
		goto fail1;
	}

	if (iocp->ioc_count != ioclen) {
		rc = EINVAL;
		goto fail2;
	}

	/* if in multiple fragments pull it up to one linear buffer */
	if ((rc = miocpullup(mp, ioclen)) != 0) {
		goto fail3;
	}

	switch (iocp->ioc_cmd) {
	case SFXGE_NVRAM_IOC: {
		sfxge_nvram_ioc_t *snip =
		    (sfxge_nvram_ioc_t *)mp->b_cont->b_rptr;

		if ((rc = sfxge_nvram_ioctl(sp, snip)) != 0)
			goto fail4;

		break;
	}
	case SFXGE_MCDI_IOC: {
		sfxge_mcdi_ioc_t *smip = (sfxge_mcdi_ioc_t *)mp->b_cont->b_rptr;

		if ((rc = sfxge_mcdi_ioctl(sp, smip)) != 0)
			goto fail4;
		taskq_wait = 1;

		break;
	}
	case SFXGE_MCDI2_IOC: {
		sfxge_mcdi2_ioc_t *smip =
		    (sfxge_mcdi2_ioc_t *)mp->b_cont->b_rptr;

		if ((rc = sfxge_mcdi2_ioctl(sp, smip)) != 0)
			goto fail4;
		taskq_wait = 1;

		break;
	}
	case SFXGE_NIC_RESET_IOC: {
		DTRACE_PROBE(nic_reset_ioc);

		/* sp->s_state_lock held */
		(void) sfxge_restart_dispatch(sp, DDI_SLEEP, SFXGE_HW_OK,
		    "NIC_RESET_IOC", 0);
		taskq_wait = 1;

		break;
	}
	case SFXGE_VPD_IOC: {
		sfxge_vpd_ioc_t *svip = (sfxge_vpd_ioc_t *)mp->b_cont->b_rptr;

		if ((rc = sfxge_vpd_ioctl(sp, svip)) != 0)
			goto fail4;

		break;
	}
	default:
		ASSERT(0);
	}

	mutex_exit(&(sp->s_state_lock));

	if (taskq_wait) {
		/*
		 * Wait for any tasks that may be accessing GLD functions
		 * This may end up waiting for multiple nic_resets
		 * as it needs to be outside of s_state_lock for sfxge_restart()
		 */
		ddi_taskq_wait(sp->s_tqp);
	}

	/* The entire structure is the acknowledgement */
	miocack(wq, mp, iocp->ioc_count, 0);

	return;

fail4:
	DTRACE_PROBE(fail4);
fail3:
	DTRACE_PROBE(fail3);
fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	mutex_exit(&(sp->s_state_lock));

	/* no data returned */
	miocnak(wq, mp, 0, rc);
}

static int
sfxge_register(sfxge_t *sp)
{
	int rc;

	ASSERT3U(sp->s_state, ==, SFXGE_INITIALIZED);

	if ((rc = sfxge_gld_register(sp)) != 0)
		goto fail1;

	sp->s_state = SFXGE_REGISTERED;

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static int
sfxge_unregister(sfxge_t *sp)
{
	int rc;

	ASSERT3U(sp->s_state, ==, SFXGE_REGISTERED);

	/* Wait for any tasks that may be accessing GLD functions */
	ddi_taskq_wait(sp->s_tqp);

	if ((rc = sfxge_gld_unregister(sp)) != 0)
		goto fail1;

	sp->s_state = SFXGE_INITIALIZED;

	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static void
_sfxge_vpd_kstat_init(sfxge_t *sp, caddr_t vpd, size_t size, efx_vpd_tag_t tag,
    const char *keyword, sfxge_vpd_type_t type)
{
	static const char unknown[] = "?";
	efx_nic_t *enp = sp->s_enp;
	sfxge_vpd_kstat_t *svkp = &(sp->s_vpd_kstat);
	kstat_named_t *knp;
	efx_vpd_value_t *evvp;

	evvp = svkp->svk_vv + type;
	evvp->evv_tag = tag;
	evvp->evv_keyword = EFX_VPD_KEYWORD(keyword[0], keyword[1]);

	if (efx_vpd_get(enp, vpd, size, evvp) != 0) {
		evvp->evv_length = strlen(unknown) + 1;
		bcopy(unknown, evvp->evv_value, evvp->evv_length);
	}

	knp = &(svkp->svk_stat[type]);

	kstat_named_init(knp, (char *)keyword, KSTAT_DATA_STRING);
	kstat_named_setstr(knp, (char *)evvp->evv_value);
	svkp->svk_ksp->ks_data_size += sizeof (*evvp);
}

static int
sfxge_vpd_kstat_init(sfxge_t *sp)
{
	efx_nic_t *enp = sp->s_enp;
	sfxge_vpd_kstat_t *svkp = &(sp->s_vpd_kstat);
	dev_info_t *dip = sp->s_dip;
	char name[MAXNAMELEN];
	kstat_t *ksp;
	caddr_t vpd;
	size_t size;
	int rc;

	SFXGE_OBJ_CHECK(svkp, sfxge_vpd_kstat_t);
	(void) snprintf(name, MAXNAMELEN - 1, "%s_vpd", ddi_driver_name(dip));

	/* Get a copy of the VPD space */
	if ((rc = efx_vpd_size(enp, &size)) != 0)
		goto fail1;

	if ((vpd = kmem_zalloc(size, KM_NOSLEEP)) == NULL) {
		rc = ENOMEM;
		goto fail2;
	}

	if ((svkp->svk_vv = kmem_zalloc(sizeof (efx_vpd_value_t) *
	    SFXGE_VPD_MAX, KM_NOSLEEP)) == NULL) {
		rc = ENOMEM;
		goto fail3;
	}

	if ((rc = efx_vpd_read(enp, vpd, size)) != 0)
		goto fail4;

	if ((ksp = kstat_create((char *)ddi_driver_name(dip),
	    ddi_get_instance(dip), name, "vpd", KSTAT_TYPE_NAMED, SFXGE_VPD_MAX,
	    KSTAT_FLAG_VIRTUAL)) == NULL) {
		rc = ENOMEM;
		goto fail5;
	}
	svkp->svk_ksp = ksp;
	ksp->ks_data = &(svkp->svk_stat);

	_sfxge_vpd_kstat_init(sp, vpd, size, EFX_VPD_ID, "ID", SFXGE_VPD_ID);
	_sfxge_vpd_kstat_init(sp, vpd, size, EFX_VPD_RO, "PN", SFXGE_VPD_PN);
	_sfxge_vpd_kstat_init(sp, vpd, size, EFX_VPD_RO, "SN", SFXGE_VPD_SN);
	_sfxge_vpd_kstat_init(sp, vpd, size, EFX_VPD_RO, "EC", SFXGE_VPD_EC);
	_sfxge_vpd_kstat_init(sp, vpd, size, EFX_VPD_RO, "MN", SFXGE_VPD_MN);
	_sfxge_vpd_kstat_init(sp, vpd, size, EFX_VPD_RO, "VD", SFXGE_VPD_VD);
	_sfxge_vpd_kstat_init(sp, vpd, size, EFX_VPD_RO, "VE", SFXGE_VPD_VE);

	kstat_install(ksp);
	kmem_free(vpd, size);

	return (0);

fail5:
	DTRACE_PROBE(fail5);
fail4:
	DTRACE_PROBE(fail4);
	kmem_free(svkp->svk_vv, sizeof (efx_vpd_value_t) * SFXGE_VPD_MAX);
fail3:
	DTRACE_PROBE(fail3);
	kmem_free(vpd, size);
fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);
	SFXGE_OBJ_CHECK(svkp, sfxge_vpd_kstat_t);

	return (rc);
}

static void
sfxge_vpd_kstat_fini(sfxge_t *sp)
{
	sfxge_vpd_kstat_t *svkp = &(sp->s_vpd_kstat);

	/* NOTE: VPD support is optional, so kstats might not be registered */
	if (svkp->svk_ksp != NULL) {

		kstat_delete(svkp->svk_ksp);

		kmem_free(svkp->svk_vv,
		    sizeof (efx_vpd_value_t) * SFXGE_VPD_MAX);

		bzero(svkp->svk_stat,
		    sizeof (kstat_named_t) * SFXGE_VPD_MAX);

		svkp->svk_ksp = NULL;
	}

	SFXGE_OBJ_CHECK(svkp, sfxge_vpd_kstat_t);
}

static int
sfxge_cfg_kstat_init(sfxge_t *sp)
{
	dev_info_t *dip = sp->s_dip;
	char name[MAXNAMELEN];
	kstat_t *ksp;
	sfxge_cfg_kstat_t *sckp;
	int rc;

	sfxge_cfg_build(sp);

	/* Create the set */
	(void) snprintf(name, MAXNAMELEN - 1, "%s_cfg", ddi_driver_name(dip));

	if ((ksp = kstat_create((char *)ddi_driver_name(dip),
	    ddi_get_instance(dip), name, "cfg", KSTAT_TYPE_NAMED,
	    sizeof (sckp->kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL)) == NULL) {
		rc = ENOMEM;
		goto fail1;
	}

	sp->s_cfg_ksp = ksp;

	ksp->ks_data = sckp = &(sp->s_cfg_kstat);

	kstat_named_init(&(sckp->kstat.sck_mac), "mac", KSTAT_DATA_STRING);
	kstat_named_setstr(&(sckp->kstat.sck_mac), sckp->buf.sck_mac);
	ksp->ks_data_size += sizeof (sckp->buf.sck_mac);

	kstat_named_init(&(sckp->kstat.sck_version), "version",
	    KSTAT_DATA_STRING);
	kstat_named_setstr(&(sckp->kstat.sck_version), sfxge_version);
	ksp->ks_data_size += sizeof (sfxge_version);

	kstat_install(ksp);
	return (0);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}

static void
sfxge_cfg_kstat_fini(sfxge_t *sp)
{
	if (sp->s_cfg_ksp == NULL)
		return;

	kstat_delete(sp->s_cfg_ksp);
	sp->s_cfg_ksp = NULL;

	bzero(&(sp->s_cfg_kstat), sizeof (sfxge_cfg_kstat_t));
}

static int
sfxge_resume(sfxge_t *sp)
{
	int rc;

	/* Start processing */
	if ((rc = sfxge_start(sp, B_FALSE)) != 0)
		goto fail1;

	return (DDI_SUCCESS);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (DDI_FAILURE);
}

static int
sfxge_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	sfxge_t *sp;
	int rc;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
		if ((sp = ddi_get_driver_private(dip)) == NULL)
			return (DDI_FAILURE);
		return (sfxge_resume(sp));

	default:
		return (DDI_FAILURE);
	}

	/* Create the soft state */
	if ((rc = sfxge_create(dip, &sp)) != 0)
		goto fail1;

	/* Create the configuration kstats */
	if ((rc = sfxge_cfg_kstat_init(sp)) != 0)
		goto fail2;

	/* Create the VPD kstats */
	if ((rc = sfxge_vpd_kstat_init(sp)) != 0) {
		if (rc != ENOTSUP)
			goto fail3;
	}

	/* Register the interface */
	if ((rc = sfxge_register(sp)) != 0)
		goto fail4;

	/* Announce ourselves in the system log */
	ddi_report_dev(dip);

	return (DDI_SUCCESS);

fail4:
	DTRACE_PROBE(fail4);

	/* Destroy the VPD kstats */
	sfxge_vpd_kstat_fini(sp);

fail3:
	DTRACE_PROBE(fail3);

	/* Destroy the configuration kstats */
	sfxge_cfg_kstat_fini(sp);

fail2:
	DTRACE_PROBE(fail2);

	/* Destroy the soft state */
	(void) sfxge_destroy(sp);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (DDI_FAILURE);
}

static int
sfxge_suspend(sfxge_t *sp)
{
	/* Stop processing */
	sfxge_stop(sp);

	return (DDI_SUCCESS);
}

static int
sfxge_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	sfxge_t *sp = ddi_get_driver_private(dip);
	int rc;

	switch (cmd) {
	case DDI_DETACH:
		if (sp == NULL)
			return (DDI_FAILURE);
		break;

	case DDI_SUSPEND:
		if (sp == NULL)
			return (DDI_FAILURE);
		return (sfxge_suspend(sp));

	default:
		return (DDI_FAILURE);
	}

	ASSERT(sp != NULL);

	/* Wait for any pending restarts to complete */
	ddi_taskq_wait(sp->s_tqp);

	/*
	 * IOCTLs from utilites can cause GLD mc_start() (SFXGE_STARTED state)
	 * And mc_stop() may not occur until detach time and race. SFC bug 19855
	 * Holding the lock seems to be enough - the log message is not seen
	 */
	mutex_enter(&(sp->s_state_lock));
	if (sp->s_state == SFXGE_STARTED) {
		dev_err(dip, CE_WARN, SFXGE_CMN_ERR
		    "STREAMS detach when STARTED");
		sfxge_stop_locked(sp);
		ASSERT3U(sp->s_state, ==, SFXGE_REGISTERED);
	}
	mutex_exit(&(sp->s_state_lock));

	ASSERT(sp->s_state == SFXGE_REGISTERED ||
	    sp->s_state == SFXGE_INITIALIZED);

	if (sp->s_state != SFXGE_REGISTERED)
		goto destroy;

	/* Unregister the interface */
	if ((rc = sfxge_unregister(sp)) != 0)
		goto fail1;

destroy:
	/* Destroy the VPD kstats */
	sfxge_vpd_kstat_fini(sp);

	/* Destroy the configuration kstats */
	sfxge_cfg_kstat_fini(sp);

	/*
	 * Destroy the soft state - this might fail until rx_loaned packets that
	 * have been passed up the STREAMS stack are returned
	 */
	if ((rc = sfxge_destroy(sp)) != 0)
		goto fail2;

	return (DDI_SUCCESS);

fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (DDI_FAILURE);
}

/*
 * modlinkage
 */

DDI_DEFINE_STREAM_OPS(sfxge_dev_ops, nulldev, nulldev, sfxge_attach,
    sfxge_detach, nulldev, NULL, D_MP, NULL, NULL);

static struct modldrv		sfxge_modldrv = {
	&mod_driverops,
	(char *)sfxge_ident,
	&sfxge_dev_ops,
};

static struct modlinkage	sfxge_modlinkage = {
	MODREV_1,
	{ &sfxge_modldrv, NULL }
};

kmutex_t	sfxge_global_lock;
unsigned int	*sfxge_cpu;

int
_init(void)
{
	int rc;

	mutex_init(&sfxge_global_lock, NULL, MUTEX_DRIVER, NULL);

	/* Create tables for CPU, core, cache and chip counts */
	sfxge_cpu = kmem_zalloc(sizeof (unsigned int) * NCPU, KM_SLEEP);

	mac_init_ops(&sfxge_dev_ops, SFXGE_DRIVER_NAME);

	if ((rc = mod_install(&sfxge_modlinkage)) != 0)
		goto fail1;

	return (0);

fail1:
	DTRACE_PROBE(fail2);

	mac_fini_ops(&sfxge_dev_ops);

	kmem_free(sfxge_cpu, sizeof (unsigned int) * NCPU);
	mutex_destroy(&sfxge_global_lock);

	return (rc);
}

int
_fini(void)
{
	int rc;

	if ((rc = mod_remove(&sfxge_modlinkage)) != 0)
		return (rc);

	mac_fini_ops(&sfxge_dev_ops);

	/* Destroy tables */
	kmem_free(sfxge_cpu, sizeof (unsigned int) * NCPU);

	mutex_destroy(&sfxge_global_lock);

	return (0);
}

int
_info(struct modinfo *mip)
{
	return (mod_info(&sfxge_modlinkage, mip));
}
