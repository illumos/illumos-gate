/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2011 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#include <emlxs.h>

/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_PKT_C);

#if (EMLXS_MODREV >= EMLXS_MODREV3)
typedef struct
{
	ddi_dma_cookie_t pkt_cmd_cookie;
	ddi_dma_cookie_t pkt_resp_cookie;
	ddi_dma_cookie_t pkt_data_cookie;

} emlxs_pkt_cookie_t;
#endif /* >= EMLXS_MODREV3 */


/* ARGSUSED */
static void
emlxs_pkt_thread(emlxs_hba_t *hba, void *arg1, void *arg2)
{
	emlxs_port_t *port;
	fc_packet_t *pkt = (fc_packet_t *)arg1;
	int32_t rval;
	emlxs_buf_t *sbp;

	sbp = PKT2PRIV(pkt);
	port = sbp->port;

	/* Send the pkt now */
	rval = emlxs_pkt_send(pkt, 1);

	if (rval != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_trans_msg,
		    "Deferred pkt_send failed: status=%x pkt=%p", rval,
		    pkt);

		if (pkt->pkt_comp) {
			emlxs_set_pkt_state(sbp, IOSTAT_LOCAL_REJECT, 0, 1);

			((CHANNEL *)sbp->channel)->ulpCmplCmd++;
			(*pkt->pkt_comp) (pkt);
		} else {
			emlxs_pkt_free(pkt);
		}
	}

	return;

} /* emlxs_pkt_thread() */


extern int32_t
emlxs_pkt_send(fc_packet_t *pkt, uint32_t now)
{
	emlxs_port_t *port = (emlxs_port_t *)pkt->pkt_ulp_private;
	emlxs_hba_t *hba = HBA;
	int32_t rval;

	if (now) {
		rval = emlxs_fca_transport((opaque_t)port, pkt);
	} else {
		/* Spawn a thread to send the pkt */
		emlxs_thread_spawn(hba, emlxs_pkt_thread, (char *)pkt, NULL);

		rval = FC_SUCCESS;
	}

	return (rval);

} /* emlxs_pkt_send() */


extern void
emlxs_pkt_free(fc_packet_t *pkt)
{
	emlxs_port_t *port = (emlxs_port_t *)pkt->pkt_ulp_private;

	(void) emlxs_fca_pkt_uninit((opaque_t)port, pkt);

	if (pkt->pkt_datalen) {
		(void) ddi_dma_unbind_handle(pkt->pkt_data_dma);
		(void) ddi_dma_mem_free(&pkt->pkt_data_acc);
		(void) ddi_dma_free_handle(&pkt->pkt_data_dma);
	}

	if (pkt->pkt_rsplen) {
		(void) ddi_dma_unbind_handle(pkt->pkt_resp_dma);
		(void) ddi_dma_mem_free(&pkt->pkt_resp_acc);
		(void) ddi_dma_free_handle(&pkt->pkt_resp_dma);
	}

	if (pkt->pkt_cmdlen) {
		(void) ddi_dma_unbind_handle(pkt->pkt_cmd_dma);
		(void) ddi_dma_mem_free(&pkt->pkt_cmd_acc);
		(void) ddi_dma_free_handle(&pkt->pkt_cmd_dma);
	}
#if (EMLXS_MODREV >= EMLXS_MODREV3)
	kmem_free(pkt, (sizeof (fc_packet_t) + sizeof (emlxs_buf_t) +
	    sizeof (emlxs_pkt_cookie_t)));
#else
	kmem_free(pkt, (sizeof (fc_packet_t) + sizeof (emlxs_buf_t)));
#endif /* >= EMLXS_MODREV3 */

	return;

} /* emlxs_pkt_free() */


/* Default pkt callback routine */
extern void
emlxs_pkt_callback(fc_packet_t *pkt)
{
	emlxs_pkt_free(pkt);

	return;

} /* emlxs_pkt_callback() */



extern fc_packet_t *
emlxs_pkt_alloc(emlxs_port_t *port, uint32_t cmdlen, uint32_t rsplen,
    uint32_t datalen, int32_t sleep)
{
	emlxs_hba_t *hba = HBA;
	fc_packet_t *pkt;
	int32_t(*cb) (caddr_t);
	unsigned long real_len;
	uint32_t pkt_size;
	emlxs_buf_t *sbp;

#if (EMLXS_MODREV >= EMLXS_MODREV3)
	emlxs_pkt_cookie_t *pkt_cookie;

	pkt_size =
	    sizeof (fc_packet_t) + sizeof (emlxs_buf_t) +
	    sizeof (emlxs_pkt_cookie_t);
#else
	uint32_t num_cookie;

	pkt_size = sizeof (fc_packet_t) + sizeof (emlxs_buf_t);
#endif /* >= EMLXS_MODREV3 */


	/* Allocate some space */
	if (!(pkt = (fc_packet_t *)kmem_alloc(pkt_size, sleep))) {
		return (NULL);
	}

	bzero(pkt, pkt_size);

	cb = (sleep == KM_SLEEP) ? DDI_DMA_SLEEP : DDI_DMA_DONTWAIT;

	pkt->pkt_ulp_private = (opaque_t)port;
	pkt->pkt_fca_private =
	    (opaque_t)((uintptr_t)pkt + sizeof (fc_packet_t));
	pkt->pkt_comp = emlxs_pkt_callback;
	pkt->pkt_tran_flags = (FC_TRAN_CLASS3 | FC_TRAN_INTR);
	pkt->pkt_cmdlen = cmdlen;
	pkt->pkt_rsplen = rsplen;
	pkt->pkt_datalen = datalen;

#if (EMLXS_MODREV >= EMLXS_MODREV3)
	pkt_cookie =
	    (emlxs_pkt_cookie_t *)((uintptr_t)pkt + sizeof (fc_packet_t) +
	    sizeof (emlxs_buf_t));
	pkt->pkt_cmd_cookie = &pkt_cookie->pkt_cmd_cookie;
	pkt->pkt_resp_cookie = &pkt_cookie->pkt_resp_cookie;
	pkt->pkt_data_cookie = &pkt_cookie->pkt_data_cookie;
#endif /* >= EMLXS_MODREV3 */

	if (cmdlen) {
		/* Allocate the cmd buf */
		if (ddi_dma_alloc_handle(hba->dip, &hba->dma_attr_1sg, cb,
		    NULL, &pkt->pkt_cmd_dma) != DDI_SUCCESS) {
			cmdlen = 0;
			rsplen = 0;
			datalen = 0;
			goto failed;
		}

		if (ddi_dma_mem_alloc(pkt->pkt_cmd_dma, cmdlen,
		    &emlxs_data_acc_attr, DDI_DMA_CONSISTENT, cb, NULL,
		    (caddr_t *)&pkt->pkt_cmd, &real_len,
		    &pkt->pkt_cmd_acc) != DDI_SUCCESS) {
			(void) ddi_dma_free_handle(&pkt->pkt_cmd_dma);

			cmdlen = 0;
			rsplen = 0;
			datalen = 0;
			goto failed;
		}

		if (real_len < cmdlen) {
			(void) ddi_dma_mem_free(&pkt->pkt_cmd_acc);
			(void) ddi_dma_free_handle(&pkt->pkt_cmd_dma);

			cmdlen = 0;
			rsplen = 0;
			datalen = 0;
			goto failed;
		}
#if (EMLXS_MODREV >= EMLXS_MODREV3)
		if (ddi_dma_addr_bind_handle(pkt->pkt_cmd_dma, NULL,
		    pkt->pkt_cmd, real_len,
		    DDI_DMA_WRITE | DDI_DMA_CONSISTENT, cb, NULL,
		    pkt->pkt_cmd_cookie,
		    &pkt->pkt_cmd_cookie_cnt) != DDI_DMA_MAPPED)
#else
		if (ddi_dma_addr_bind_handle(pkt->pkt_cmd_dma, NULL,
		    pkt->pkt_cmd, real_len,
		    DDI_DMA_WRITE | DDI_DMA_CONSISTENT, cb, NULL,
		    &pkt->pkt_cmd_cookie, &num_cookie) != DDI_DMA_MAPPED)
#endif /* >= EMLXS_MODREV3 */
		{
			(void) ddi_dma_mem_free(&pkt->pkt_cmd_acc);
			(void) ddi_dma_free_handle(&pkt->pkt_cmd_dma);

			cmdlen = 0;
			rsplen = 0;
			datalen = 0;
			goto failed;
		}
#if (EMLXS_MODREV >= EMLXS_MODREV3)
		if (pkt->pkt_cmd_cookie_cnt != 1)
#else
		if (num_cookie != 1)
#endif /* >= EMLXS_MODREV3 */
		{
			rsplen = 0;
			datalen = 0;
			goto failed;
		}

		bzero(pkt->pkt_cmd, cmdlen);

	}

	if (rsplen) {
		/* Allocate the rsp buf */
		if (ddi_dma_alloc_handle(hba->dip, &hba->dma_attr_1sg, cb,
		    NULL, &pkt->pkt_resp_dma) != DDI_SUCCESS) {
			rsplen = 0;
			datalen = 0;
			goto failed;

		}

		if (ddi_dma_mem_alloc(pkt->pkt_resp_dma, rsplen,
		    &emlxs_data_acc_attr, DDI_DMA_CONSISTENT, cb, NULL,
		    (caddr_t *)&pkt->pkt_resp, &real_len,
		    &pkt->pkt_resp_acc) != DDI_SUCCESS) {
			(void) ddi_dma_free_handle(&pkt->pkt_resp_dma);

			rsplen = 0;
			datalen = 0;
			goto failed;
		}

		if (real_len < rsplen) {
			(void) ddi_dma_mem_free(&pkt->pkt_resp_acc);
			(void) ddi_dma_free_handle(&pkt->pkt_resp_dma);

			rsplen = 0;
			datalen = 0;
			goto failed;
		}
#if (EMLXS_MODREV >= EMLXS_MODREV3)
		if (ddi_dma_addr_bind_handle(pkt->pkt_resp_dma, NULL,
		    pkt->pkt_resp, real_len,
		    DDI_DMA_READ | DDI_DMA_CONSISTENT, cb, NULL,
		    pkt->pkt_resp_cookie,
		    &pkt->pkt_resp_cookie_cnt) != DDI_DMA_MAPPED)
#else
		if (ddi_dma_addr_bind_handle(pkt->pkt_resp_dma, NULL,
		    pkt->pkt_resp, real_len,
		    DDI_DMA_READ | DDI_DMA_CONSISTENT, cb, NULL,
		    &pkt->pkt_resp_cookie, &num_cookie) != DDI_DMA_MAPPED)
#endif /* >= EMLXS_MODREV3 */
		{
			(void) ddi_dma_mem_free(&pkt->pkt_resp_acc);
			(void) ddi_dma_free_handle(&pkt->pkt_resp_dma);

			rsplen = 0;
			datalen = 0;
			goto failed;
		}
#if (EMLXS_MODREV >= EMLXS_MODREV3)
		if (pkt->pkt_resp_cookie_cnt != 1)
#else
		if (num_cookie != 1)
#endif /* >= EMLXS_MODREV3 */
		{
			datalen = 0;
			goto failed;
		}

		bzero(pkt->pkt_resp, rsplen);

	}

	/* Allocate the data buf */
	if (datalen) {
		/* Allocate the rsp buf */
		if (ddi_dma_alloc_handle(hba->dip, &hba->dma_attr_1sg, cb,
		    NULL, &pkt->pkt_data_dma) != DDI_SUCCESS) {
			datalen = 0;
			goto failed;
		}

		if (ddi_dma_mem_alloc(pkt->pkt_data_dma, datalen,
		    &emlxs_data_acc_attr, DDI_DMA_CONSISTENT, cb, NULL,
		    (caddr_t *)&pkt->pkt_data, &real_len,
		    &pkt->pkt_data_acc) != DDI_SUCCESS) {
			(void) ddi_dma_free_handle(&pkt->pkt_data_dma);

			datalen = 0;
			goto failed;
		}

		if (real_len < datalen) {
			(void) ddi_dma_mem_free(&pkt->pkt_data_acc);
			(void) ddi_dma_free_handle(&pkt->pkt_data_dma);

			datalen = 0;
			goto failed;
		}
#if (EMLXS_MODREV >= EMLXS_MODREV3)
		if (ddi_dma_addr_bind_handle(pkt->pkt_data_dma, NULL,
		    pkt->pkt_data, real_len,
		    DDI_DMA_READ | DDI_DMA_WRITE | DDI_DMA_CONSISTENT, cb,
		    NULL, pkt->pkt_data_cookie,
		    &pkt->pkt_data_cookie_cnt) != DDI_DMA_MAPPED)
#else
		if (ddi_dma_addr_bind_handle(pkt->pkt_data_dma, NULL,
		    pkt->pkt_data, real_len,
		    DDI_DMA_READ | DDI_DMA_WRITE | DDI_DMA_CONSISTENT, cb,
		    NULL, &pkt->pkt_data_cookie,
		    &num_cookie) != DDI_DMA_MAPPED)
#endif /* >= EMLXS_MODREV3 */
		{
			(void) ddi_dma_mem_free(&pkt->pkt_data_acc);
			(void) ddi_dma_free_handle(&pkt->pkt_data_dma);

			datalen = 0;
			goto failed;
		}
#if (EMLXS_MODREV >= EMLXS_MODREV3)
		if (pkt->pkt_data_cookie_cnt != 1)
#else
		if (num_cookie != 1)
#endif /* >= EMLXS_MODREV3 */
		{
			goto failed;
		}

		bzero(pkt->pkt_data, datalen);
	}

	sbp = PKT2PRIV(pkt);
	bzero((void *)sbp, sizeof (emlxs_buf_t));

	mutex_init(&sbp->mtx, NULL, MUTEX_DRIVER, DDI_INTR_PRI(hba->intr_arg));
	sbp->pkt_flags = PACKET_VALID | PACKET_ULP_OWNED | PACKET_ALLOCATED;
	sbp->port = port;
	sbp->pkt = pkt;
	sbp->iocbq.sbp = sbp;

	return (pkt);

failed:

	if (datalen) {
		(void) ddi_dma_unbind_handle(pkt->pkt_data_dma);
		(void) ddi_dma_mem_free(&pkt->pkt_data_acc);
		(void) ddi_dma_free_handle(&pkt->pkt_data_dma);
	}

	if (rsplen) {
		(void) ddi_dma_unbind_handle(pkt->pkt_resp_dma);
		(void) ddi_dma_mem_free(&pkt->pkt_resp_acc);
		(void) ddi_dma_free_handle(&pkt->pkt_resp_dma);
	}

	if (cmdlen) {
		(void) ddi_dma_unbind_handle(pkt->pkt_cmd_dma);
		(void) ddi_dma_mem_free(&pkt->pkt_cmd_acc);
		(void) ddi_dma_free_handle(&pkt->pkt_cmd_dma);
	}

	if (pkt) {
		kmem_free(pkt, pkt_size);
	}

	return (NULL);

} /* emlxs_pkt_alloc() */
