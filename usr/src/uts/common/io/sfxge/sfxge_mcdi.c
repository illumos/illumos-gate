/*
 * Copyright (c) 2009-2016 Solarflare Communications Inc.
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
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/pci.h>

#include "sfxge.h"
#include "efsys.h"
#include "efx.h"
#include "efx_mcdi.h"
#include "efx_regs_mcdi.h"

/* MAC DMA attributes */
static ddi_device_acc_attr_t sfxge_mcdi_devacc = {

	DDI_DEVICE_ATTR_V0,	/* devacc_attr_version */
	DDI_NEVERSWAP_ACC,	/* devacc_attr_endian_flags */
	DDI_STRICTORDER_ACC	/* devacc_attr_dataorder */
};

static ddi_dma_attr_t sfxge_mcdi_dma_attr = {
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

/*
 * Notes on MCDI operation:
 * ------------------------
 * MCDI requests can be made in arbitrary thread context, and as a synchronous
 * API must therefore block until the response is available from the MC, or
 * a watchdog timeout occurs.
 *
 * This interacts badly with the limited number of worker threads (2 per CPU)
 * used by the Solaris callout subsystem to invoke timeout handlers. If both
 * worker threads are blocked (e.g. waiting for a condvar or mutex) then timeout
 * processing is deadlocked on that CPU, causing system failure.
 *
 * For this reason the driver does not use event based MCDI completion, as this
 * leads to numerous paths involving timeouts and reentrant GLDv3 entrypoints
 * that result in a deadlocked system.
 */
#define	SFXGE_MCDI_POLL_INTERVAL	10		/* 10us in 1us units */
#define	SFXGE_MCDI_WATCHDOG_INTERVAL	10000000	/* 10s in 1us units */


/* Acquire exclusive access to MCDI for the duration of a request */
static void
sfxge_mcdi_acquire(sfxge_mcdi_t *smp)
{
	mutex_enter(&(smp->sm_lock));
	ASSERT3U(smp->sm_state, !=, SFXGE_MCDI_UNINITIALIZED);

	while (smp->sm_state != SFXGE_MCDI_INITIALIZED) {
		(void) cv_wait(&(smp->sm_kv), &(smp->sm_lock));
	}
	smp->sm_state = SFXGE_MCDI_BUSY;

	mutex_exit(&(smp->sm_lock));
}


/* Release ownership of MCDI on request completion */
static void
sfxge_mcdi_release(sfxge_mcdi_t *smp)
{
	mutex_enter(&(smp->sm_lock));
	ASSERT((smp->sm_state == SFXGE_MCDI_BUSY) ||
	    (smp->sm_state == SFXGE_MCDI_COMPLETED));

	smp->sm_state = SFXGE_MCDI_INITIALIZED;
	cv_broadcast(&(smp->sm_kv));

	mutex_exit(&(smp->sm_lock));
}


static void
sfxge_mcdi_timeout(sfxge_t *sp)
{
	dev_info_t *dip = sp->s_dip;

	dev_err(dip, CE_WARN, SFXGE_CMN_ERR "MC_TIMEOUT");

	DTRACE_PROBE(mcdi_timeout);
	(void) sfxge_restart_dispatch(sp, DDI_SLEEP, SFXGE_HW_ERR,
	    "MCDI timeout", 0);
}


static void
sfxge_mcdi_poll(sfxge_t *sp)
{
	efx_nic_t *enp = sp->s_enp;
	clock_t timeout;
	boolean_t aborted;

	/* Poll until request completes or timeout */
	timeout = ddi_get_lbolt() + drv_usectohz(SFXGE_MCDI_WATCHDOG_INTERVAL);
	while (efx_mcdi_request_poll(enp) == B_FALSE) {

		/* No response received yet */
		if (ddi_get_lbolt() > timeout) {
			/* Timeout expired */
			goto fail;
		}

		/* Short delay to avoid excessive PCIe traffic */
		drv_usecwait(SFXGE_MCDI_POLL_INTERVAL);
	}

	/* Request completed (or polling failed) */
	return;

fail:
	/* Timeout before request completion */
	DTRACE_PROBE(fail);
	aborted = efx_mcdi_request_abort(enp);
	ASSERT(aborted);
	sfxge_mcdi_timeout(sp);
}


static void
sfxge_mcdi_execute(void *arg, efx_mcdi_req_t *emrp)
{
	sfxge_t *sp = (sfxge_t *)arg;
	sfxge_mcdi_t *smp = &(sp->s_mcdi);

	sfxge_mcdi_acquire(smp);

	/* Issue request and poll for completion */
	efx_mcdi_request_start(sp->s_enp, emrp, B_FALSE);
	sfxge_mcdi_poll(sp);

	sfxge_mcdi_release(smp);
}


static void
sfxge_mcdi_ev_cpl(void *arg)
{
	sfxge_t *sp = (sfxge_t *)arg;
	sfxge_mcdi_t *smp = &(sp->s_mcdi);

	mutex_enter(&(smp->sm_lock));
	ASSERT(smp->sm_state == SFXGE_MCDI_BUSY);
	smp->sm_state = SFXGE_MCDI_COMPLETED;
	cv_broadcast(&(smp->sm_kv));
	mutex_exit(&(smp->sm_lock));
}


static void
sfxge_mcdi_exception(void *arg, efx_mcdi_exception_t eme)
{
	sfxge_t *sp = (sfxge_t *)arg;
	const char *reason;

	if (eme == EFX_MCDI_EXCEPTION_MC_REBOOT)
		reason = "MC_REBOOT";
	else if (eme == EFX_MCDI_EXCEPTION_MC_BADASSERT)
		reason = "MC_BADASSERT";
	else
		reason = "MC_UNKNOWN";

	DTRACE_PROBE(mcdi_exception);
	/* sfxge_evq_t->se_lock held */
	(void) sfxge_restart_dispatch(sp, DDI_SLEEP, SFXGE_HW_ERR, reason, 0);
}

#if EFSYS_OPT_MCDI_LOGGING
#define	SFXGE_MCDI_LOG_BUF_SIZE	128

static size_t
sfxge_mcdi_do_log(char *buffer, void *data, size_t data_size,
    size_t pfxsize, size_t position)
{
	uint32_t *words = data;
	size_t i;

	for (i = 0; i < data_size; i += sizeof (*words)) {
		if (position + 2 * sizeof (*words) + 1 >=
		    SFXGE_MCDI_LOG_BUF_SIZE) {
			buffer[position] = '\0';
			cmn_err(CE_NOTE, "%s \\", buffer);
			position = pfxsize;
		}
		snprintf(buffer + position, SFXGE_MCDI_LOG_BUF_SIZE - position,
		    " %08x", *words);
		words++;
		position += 2 * sizeof (uint32_t) + 1;
	}
	return (position);
}


static void
sfxge_mcdi_logger(void *arg, efx_log_msg_t type,
    void *header, size_t header_size, void *data, size_t data_size)
{
	sfxge_t *sp = (sfxge_t *)arg;
	char buffer[SFXGE_MCDI_LOG_BUF_SIZE];
	size_t pfxsize;
	size_t start;

	if (!sp->s_mcdi_logging)
		return;

	pfxsize = snprintf(buffer, sizeof (buffer),
	    "sfc %04x:%02x:%02x.%02x %s%d MCDI RPC %s:",
	    0,
	    PCI_REG_BUS_G(sp->s_bus_addr),
	    PCI_REG_DEV_G(sp->s_bus_addr),
	    PCI_REG_FUNC_G(sp->s_bus_addr),
	    ddi_driver_name(sp->s_dip),
	    ddi_get_instance(sp->s_dip),
	    type == EFX_LOG_MCDI_REQUEST ? "REQ" :
	    type == EFX_LOG_MCDI_RESPONSE ? "RESP" : "???");
	start = sfxge_mcdi_do_log(buffer, header, header_size,
	    pfxsize, pfxsize);
	start = sfxge_mcdi_do_log(buffer, data, data_size, pfxsize, start);
	if (start != pfxsize) {
		buffer[start] = '\0';
		cmn_err(CE_NOTE, "%s", buffer);
	}
}
#endif /* EFSYS_OPT_MCDI_LOGGING */

int
sfxge_mcdi_init(sfxge_t *sp)
{
	efx_nic_t *enp = sp->s_enp;
	sfxge_mcdi_t *smp = &(sp->s_mcdi);
	efsys_mem_t *esmp = &(smp->sm_mem);
	efx_mcdi_transport_t *emtp = &(smp->sm_emt);
	sfxge_dma_buffer_attr_t dma_attr;
	int msg_buf_size;
	int rc;

	ASSERT3U(smp->sm_state, ==, SFXGE_MCDI_UNINITIALIZED);

	msg_buf_size = sizeof (uint32_t) + MCDI_CTL_SDU_LEN_MAX_V2;

	/* Allocate host DMA buffer for MCDI commands */
	dma_attr.sdba_dip	 = sp->s_dip;
	dma_attr.sdba_dattrp	 = &sfxge_mcdi_dma_attr;
	dma_attr.sdba_callback	 = DDI_DMA_SLEEP;
	dma_attr.sdba_length	 = msg_buf_size;
	dma_attr.sdba_memflags	 = DDI_DMA_CONSISTENT;
	dma_attr.sdba_devaccp	 = &sfxge_mcdi_devacc;
	dma_attr.sdba_bindflags	 = DDI_DMA_RDWR | DDI_DMA_CONSISTENT;
	dma_attr.sdba_maxcookies = 1;
	dma_attr.sdba_zeroinit	 = B_TRUE;

	if ((rc = sfxge_dma_buffer_create(esmp, &dma_attr)) != 0)
		goto fail1;

	mutex_init(&(smp->sm_lock), NULL, MUTEX_DRIVER, NULL);

	smp->sm_state = SFXGE_MCDI_INITIALIZED;

	emtp->emt_context   = sp;
	emtp->emt_dma_mem   = esmp;
	emtp->emt_execute   = sfxge_mcdi_execute;
	emtp->emt_ev_cpl    = sfxge_mcdi_ev_cpl;
	emtp->emt_exception = sfxge_mcdi_exception;
#if EFSYS_OPT_MCDI_LOGGING
	emtp->emt_logger    = sfxge_mcdi_logger;
#endif

	cv_init(&(smp->sm_kv), NULL, CV_DRIVER, NULL);

	if ((rc = efx_mcdi_init(enp, emtp)) != 0)
		goto fail2;

	return (0);

fail2:
	DTRACE_PROBE(fail2);

	cv_destroy(&(smp->sm_kv));
	mutex_destroy(&(smp->sm_lock));

	sfxge_dma_buffer_destroy(esmp);

	smp->sm_state = SFXGE_MCDI_UNINITIALIZED;
	smp->sm_sp = NULL;
	SFXGE_OBJ_CHECK(smp, sfxge_mcdi_t);

fail1:
	DTRACE_PROBE1(fail1, int, rc);

	return (rc);
}


void
sfxge_mcdi_fini(sfxge_t *sp)
{
	efx_nic_t *enp = sp->s_enp;
	sfxge_mcdi_t *smp = &(sp->s_mcdi);
	efsys_mem_t *esmp = &(smp->sm_mem);
	efx_mcdi_transport_t *emtp;

	mutex_enter(&(smp->sm_lock));
	ASSERT3U(smp->sm_state, ==, SFXGE_MCDI_INITIALIZED);

	efx_mcdi_fini(enp);
	emtp = &(smp->sm_emt);
	bzero(emtp, sizeof (*emtp));

	smp->sm_sp = NULL;

	cv_destroy(&(smp->sm_kv));
	mutex_exit(&(smp->sm_lock));

	sfxge_dma_buffer_destroy(esmp);

	mutex_destroy(&(smp->sm_lock));

	smp->sm_state = SFXGE_MCDI_UNINITIALIZED;
	SFXGE_OBJ_CHECK(smp, sfxge_mcdi_t);
}


int
sfxge_mcdi_ioctl(sfxge_t *sp, sfxge_mcdi_ioc_t *smip)
{
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(sp->s_enp);
	sfxge_mcdi_t *smp = &(sp->s_mcdi);
	efx_mcdi_req_t emr;
	uint8_t *out;
	int rc;

	if (smp->sm_state == SFXGE_MCDI_UNINITIALIZED) {
		rc = ENODEV;
		goto fail1;
	}

	if (!(encp->enc_features & EFX_FEATURE_MCDI)) {
		rc = ENOTSUP;
		goto fail2;
	}

	out = kmem_zalloc(sizeof (smip->smi_payload), KM_NOSLEEP);
	if (out == NULL) {
		rc = ENOMEM;
		goto fail3;
	}

	emr.emr_cmd = smip->smi_cmd;
	emr.emr_in_buf = smip->smi_payload;
	emr.emr_in_length = smip->smi_len;

	emr.emr_out_buf = out;
	emr.emr_out_length = sizeof (smip->smi_payload);

	sfxge_mcdi_execute(sp, &emr);

	smip->smi_rc = (uint8_t)emr.emr_rc;
	smip->smi_cmd = (uint8_t)emr.emr_cmd;
	smip->smi_len = (uint8_t)emr.emr_out_length_used;
	bcopy(out, smip->smi_payload, smip->smi_len);

	/*
	 * Helpfully trigger a device reset in response to an MCDI_CMD_REBOOT
	 * Both ports will see ->emt_exception callbacks on the next MCDI poll
	 */
	if (smip->smi_cmd == MC_CMD_REBOOT) {

		DTRACE_PROBE(mcdi_ioctl_mc_reboot);
		/* sfxge_t->s_state_lock held */
		(void) sfxge_restart_dispatch(sp, DDI_SLEEP, SFXGE_HW_OK,
		    "MC_REBOOT triggering restart", 0);
	}

	kmem_free(out, sizeof (smip->smi_payload));

	return (0);

fail3:
	DTRACE_PROBE(fail3);
fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);
	return (rc);
}

int
sfxge_mcdi2_ioctl(sfxge_t *sp, sfxge_mcdi2_ioc_t *smip)
{
	const efx_nic_cfg_t *encp = efx_nic_cfg_get(sp->s_enp);
	sfxge_mcdi_t *smp = &(sp->s_mcdi);
	efx_mcdi_req_t emr;
	uint8_t *out;
	int rc;

	if (smp->sm_state == SFXGE_MCDI_UNINITIALIZED) {
		rc = ENODEV;
		goto fail1;
	}

	if (!(encp->enc_features & EFX_FEATURE_MCDI)) {
		rc = ENOTSUP;
		goto fail2;
	}

	out = kmem_zalloc(sizeof (smip->smi_payload), KM_NOSLEEP);
	if (out == NULL) {
		rc = ENOMEM;
		goto fail3;
	}

	emr.emr_cmd = smip->smi_cmd;
	emr.emr_in_buf = smip->smi_payload;
	emr.emr_in_length = smip->smi_len;

	emr.emr_out_buf = out;
	emr.emr_out_length = sizeof (smip->smi_payload);

	sfxge_mcdi_execute(sp, &emr);

	smip->smi_rc = emr.emr_rc;
	smip->smi_cmd = emr.emr_cmd;
	smip->smi_len = (uint32_t)emr.emr_out_length_used;
	bcopy(out, smip->smi_payload, smip->smi_len);

	/*
	 * Helpfully trigger a device reset in response to an MCDI_CMD_REBOOT
	 * Both ports will see ->emt_exception callbacks on the next MCDI poll
	 */
	if (smip->smi_cmd == MC_CMD_REBOOT) {

		DTRACE_PROBE(mcdi_ioctl_mc_reboot);
		/* sfxge_t->s_state_lock held */
		(void) sfxge_restart_dispatch(sp, DDI_SLEEP, SFXGE_HW_OK,
		    "MC_REBOOT triggering restart", 0);
	}

	kmem_free(out, sizeof (smip->smi_payload));

	return (0);

fail3:
	DTRACE_PROBE(fail3);
fail2:
	DTRACE_PROBE(fail2);
fail1:
	DTRACE_PROBE1(fail1, int, rc);
	return (rc);
}
