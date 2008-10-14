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
 * Copyright 2008 Emulex.  All rights reserved.
 * Use is subject to License terms.
 */


#include "emlxs.h"

EMLXS_MSG_DEF(EMLXS_MEM_C);


#ifdef SLI3_SUPPORT
static uint32_t emlxs_hbq_alloc(emlxs_hba_t *hba, uint32_t hbq_id);
static void emlxs_hbq_free_all(emlxs_hba_t *hba, uint32_t hbq_id);
#endif	/* SLI3_SUPPORT */

/*
 *   emlxs_mem_alloc_buffer
 *
 *   This routine will allocate iocb/data buffer
 *   space and setup the buffers for all rings on
 *   the specified board to use. The data buffers
 *   can be posted to the ring with the
 *   fc_post_buffer routine.  The iocb buffers
 *   are used to make a temp copy of the response
 *   ring iocbs. Returns 0 if not enough memory,
 *   Returns 1 if successful.
 */


extern int32_t
emlxs_mem_alloc_buffer(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg;
	MBUF_INFO *buf_info;
	uint8_t *bp;
	uint8_t *oldbp;
	MEMSEG *mp;
	MATCHMAP *matp;
	NODELIST *ndlp;
	IOCBQ *iocbq;
	MAILBOXQ *mbox;
	MBUF_INFO bufinfo;
	int32_t i;
	RING *fcp_rp;
	RING *ip_rp;
	RING *els_rp;
	RING *ct_rp;
#ifdef EMLXS_SPARC
	int32_t j;
	ULP_BDE64 *v_bpl;
	ULP_BDE64 *p_bpl;
#endif	/* EMLXS_SPARC */
	uint32_t total_iotags;

	buf_info = &bufinfo;
	cfg = &CFG;

	mutex_enter(&EMLXS_MEMGET_LOCK);

	/*
	 * Allocate and Initialize MEM_NLP (0)
	 */
	mp = &hba->memseg[MEM_NLP];
	mp->fc_memsize = sizeof (NODELIST);
	mp->fc_numblks = (int16_t)hba->max_nodes + 2;
	mp->fc_total_memsize = mp->fc_memsize * mp->fc_numblks;
	mp->fc_memstart_virt = kmem_zalloc(mp->fc_total_memsize, KM_NOSLEEP);
	mp->fc_memget_cnt = mp->fc_numblks;
	mp->fc_memput_cnt = 0;
	mp->fc_memstart_phys = 0;
	mp->fc_memflag = 0;
	mp->fc_lowmem = 0;
	mp->fc_mem_dma_handle = 0;
	mp->fc_mem_dat_handle = 0;
	mp->fc_memget_ptr = 0;
	mp->fc_memget_end = 0;
	mp->fc_memput_ptr = 0;
	mp->fc_memput_end = 0;

	if (mp->fc_memstart_virt == NULL) {
		mutex_exit(&EMLXS_MEMGET_LOCK);

		(void) emlxs_mem_free_buffer(hba);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
		    "NLP memory pool.");

		return (0);
	}
	bzero(mp->fc_memstart_virt, mp->fc_memsize);
	ndlp = (NODELIST *) mp->fc_memstart_virt;

	/*
	 * Link buffer into beginning of list. The first pointer in each
	 * buffer is a forward pointer to the next buffer.
	 */
	for (i = 0; i < mp->fc_numblks; i++, ndlp++) {
		ndlp->flag |= NODE_POOL_ALLOCATED;

		oldbp = mp->fc_memget_ptr;
		bp = (uint8_t *)ndlp;
		if (oldbp == NULL) {
			mp->fc_memget_end = bp;
		}
		mp->fc_memget_ptr = bp;
		*((uint8_t **)bp) = oldbp;
	}


	/*
	 * Allocate and Initialize MEM_IOCB (1)
	 */
	mp = &hba->memseg[MEM_IOCB];
	mp->fc_memsize = sizeof (IOCBQ);
	mp->fc_numblks = (uint16_t)cfg[CFG_NUM_IOCBS].current;
	mp->fc_total_memsize = mp->fc_memsize * mp->fc_numblks;
	mp->fc_memstart_virt = kmem_zalloc(mp->fc_total_memsize, KM_NOSLEEP);
	mp->fc_lowmem = (mp->fc_numblks >> 4);
	mp->fc_memget_cnt = mp->fc_numblks;
	mp->fc_memput_cnt = 0;
	mp->fc_memflag = 0;
	mp->fc_memstart_phys = 0;
	mp->fc_mem_dma_handle = 0;
	mp->fc_mem_dat_handle = 0;
	mp->fc_memget_ptr = 0;
	mp->fc_memget_end = 0;
	mp->fc_memput_ptr = 0;
	mp->fc_memput_end = 0;

	if (mp->fc_memstart_virt == NULL) {
		mutex_exit(&EMLXS_MEMGET_LOCK);

		(void) emlxs_mem_free_buffer(hba);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
		    "IOCB memory pool.");

		return (0);
	}
	bzero(mp->fc_memstart_virt, mp->fc_memsize);
	iocbq = (IOCBQ *) mp->fc_memstart_virt;

	/*
	 * Link buffer into beginning of list. The first pointer in each
	 * buffer is a forward pointer to the next buffer.
	 */
	for (i = 0; i < mp->fc_numblks; i++, iocbq++) {
		iocbq->flag |= IOCB_POOL_ALLOCATED;

		oldbp = mp->fc_memget_ptr;
		bp = (uint8_t *)iocbq;
		if (oldbp == NULL) {
			mp->fc_memget_end = bp;
		}
		mp->fc_memget_ptr = bp;
		*((uint8_t **)bp) = oldbp;
	}

	/*
	 * Allocate and Initialize MEM_MBOX (2)
	 */
	mp = &hba->memseg[MEM_MBOX];
	mp->fc_memsize = sizeof (MAILBOXQ);
	mp->fc_numblks = (int16_t)hba->max_nodes + 32;
	mp->fc_total_memsize = mp->fc_memsize * mp->fc_numblks;
	mp->fc_memstart_virt = kmem_zalloc(mp->fc_total_memsize, KM_NOSLEEP);
	mp->fc_lowmem = (mp->fc_numblks >> 3);
	mp->fc_memget_cnt = mp->fc_numblks;
	mp->fc_memput_cnt = 0;
	mp->fc_memflag = 0;
	mp->fc_memstart_phys = 0;
	mp->fc_mem_dma_handle = 0;
	mp->fc_mem_dat_handle = 0;
	mp->fc_memget_ptr = 0;
	mp->fc_memget_end = 0;
	mp->fc_memput_ptr = 0;
	mp->fc_memput_end = 0;

	if (mp->fc_memstart_virt == NULL) {
		mutex_exit(&EMLXS_MEMGET_LOCK);

		(void) emlxs_mem_free_buffer(hba);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
		    "MBOX memory pool.");

		return (0);
	}
	bzero(mp->fc_memstart_virt, mp->fc_memsize);
	mbox = (MAILBOXQ *) mp->fc_memstart_virt;

	/*
	 * Link buffer into beginning of list. The first pointer in each
	 * buffer is a forward pointer to the next buffer.
	 */
	for (i = 0; i < mp->fc_numblks; i++, mbox++) {
		mbox->flag |= MBQ_POOL_ALLOCATED;

		oldbp = mp->fc_memget_ptr;
		bp = (uint8_t *)mbox;
		if (oldbp == NULL) {
			mp->fc_memget_end = bp;
		}
		mp->fc_memget_ptr = bp;
		*((uint8_t **)bp) = oldbp;
	}

	/*
	 * Initialize fc_table
	 */
	fcp_rp = &hba->ring[FC_FCP_RING];
	ip_rp = &hba->ring[FC_IP_RING];
	els_rp = &hba->ring[FC_ELS_RING];
	ct_rp = &hba->ring[FC_CT_RING];

	fcp_rp->max_iotag = cfg[CFG_NUM_IOTAGS].current;
	ip_rp->max_iotag = hba->max_nodes;
	els_rp->max_iotag = hba->max_nodes;
	ct_rp->max_iotag = hba->max_nodes;

	/* Allocate the fc_table */
	total_iotags = fcp_rp->max_iotag + ip_rp->max_iotag +
	    els_rp->max_iotag + ct_rp->max_iotag;

	bzero(buf_info, sizeof (MBUF_INFO));
	buf_info->size = total_iotags * sizeof (emlxs_buf_t *);
	buf_info->align = sizeof (void *);

	(void) emlxs_mem_alloc(hba, buf_info);
	if (buf_info->virt == NULL) {
		mutex_exit(&EMLXS_MEMGET_LOCK);

		(void) emlxs_mem_free_buffer(hba);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
		    "fc_table buffer.");

		return (0);
	}
	hba->iotag_table = buf_info->virt;
	fcp_rp->fc_table = &hba->iotag_table[0];
	ip_rp->fc_table = &hba->iotag_table[fcp_rp->max_iotag];
	els_rp->fc_table = &hba->iotag_table[fcp_rp->max_iotag +
	    ip_rp->max_iotag];
	ct_rp->fc_table = &hba->iotag_table[fcp_rp->max_iotag +
	    ip_rp->max_iotag + els_rp->max_iotag];

#ifdef EMLXS_SPARC
	/*
	 * Allocate and Initialize FCP MEM_BPL's. This is for increased
	 * performance on sparc
	 */

	bzero(buf_info, sizeof (MBUF_INFO));
	buf_info->size = fcp_rp->max_iotag * sizeof (MATCHMAP);
	buf_info->align = sizeof (void *);

	(void) emlxs_mem_alloc(hba, buf_info);
	if (buf_info->virt == NULL) {
		mutex_exit(&EMLXS_MEMGET_LOCK);

		(void) emlxs_mem_free_buffer(hba);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
		    "FCP BPL table buffer.");

		return (0);
	}
	hba->fcp_bpl_table = buf_info->virt;
	bzero(hba->fcp_bpl_table, buf_info->size);

	bzero(buf_info, sizeof (MBUF_INFO));
	buf_info->size = (fcp_rp->max_iotag * (3 * sizeof (ULP_BDE64)));
	buf_info->flags = FC_MBUF_DMA;
	buf_info->align = 32;

	(void) emlxs_mem_alloc(hba, buf_info);
	if (buf_info->virt == NULL) {
		mutex_exit(&EMLXS_MEMGET_LOCK);

		(void) emlxs_mem_free_buffer(hba);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
		    "FCP BPL DMA buffers.");

		return (0);
	}
	bzero(buf_info->virt, buf_info->size);

	hba->fcp_bpl_mp.size = buf_info->size;
	hba->fcp_bpl_mp.virt = buf_info->virt;
	hba->fcp_bpl_mp.phys = buf_info->phys;
	hba->fcp_bpl_mp.data_handle = buf_info->data_handle;
	hba->fcp_bpl_mp.dma_handle = buf_info->dma_handle;
	hba->fcp_bpl_mp.tag = NULL;

	v_bpl = (ULP_BDE64 *) hba->fcp_bpl_mp.virt;
	p_bpl = (ULP_BDE64 *) hba->fcp_bpl_mp.phys;
	for (i = 0, j = 0; i < fcp_rp->max_iotag; i++, j += 3) {
		matp = &hba->fcp_bpl_table[i];

		matp->fc_mptr = NULL;
		matp->size = (3 * sizeof (ULP_BDE64));
		matp->virt = (uint8_t *)& v_bpl[j];
		matp->phys = (uint64_t)& p_bpl[j];
		matp->dma_handle = NULL;
		matp->data_handle = NULL;
		matp->tag = MEM_BPL;
		matp->flag |= MAP_TABLE_ALLOCATED;
	}

#endif	/* EMLXS_SPARC */

	/*
	 * Allocate and Initialize MEM_BPL (3)
	 */

	mp = &hba->memseg[MEM_BPL];
	mp->fc_memsize = hba->mem_bpl_size;	/* Set during attach */
	mp->fc_numblks = (uint16_t)cfg[CFG_NUM_IOCBS].current;
	mp->fc_memflag = FC_MEM_DMA;
	mp->fc_lowmem = (mp->fc_numblks >> 4);
	mp->fc_memstart_virt = 0;
	mp->fc_memstart_phys = 0;
	mp->fc_mem_dma_handle = 0;
	mp->fc_mem_dat_handle = 0;
	mp->fc_memget_ptr = 0;
	mp->fc_memget_end = 0;
	mp->fc_memput_ptr = 0;
	mp->fc_memput_end = 0;
	mp->fc_total_memsize = 0;
	mp->fc_memget_cnt = mp->fc_numblks;
	mp->fc_memput_cnt = 0;

	/* Allocate buffer pools for above buffer structures */
	for (i = 0; i < mp->fc_numblks; i++) {
		/*
		 * If this is a DMA buffer we need alignment on a page so we
		 * don't want to worry about buffers spanning page boundries
		 * when mapping memory for the adapter.
		 */
		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = sizeof (MATCHMAP);
		buf_info->align = sizeof (void *);

		(void) emlxs_mem_alloc(hba, buf_info);
		if (buf_info->virt == NULL) {
			mutex_exit(&EMLXS_MEMGET_LOCK);

			(void) emlxs_mem_free_buffer(hba);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "BPL segment buffer.");

			return (0);
		}
		matp = (MATCHMAP *) buf_info->virt;
		bzero(matp, sizeof (MATCHMAP));

		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = mp->fc_memsize;
		buf_info->flags = FC_MBUF_DMA;
		buf_info->align = 32;

		(void) emlxs_mem_alloc(hba, buf_info);
		if (buf_info->virt == NULL) {
			mutex_exit(&EMLXS_MEMGET_LOCK);

			(void) emlxs_mem_free_buffer(hba);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "BPL DMA buffer.");

			return (0);
		}
		bp = (uint8_t *)buf_info->virt;
		bzero(bp, mp->fc_memsize);

		/*
		 * Link buffer into beginning of list. The first pointer in
		 * each buffer is a forward pointer to the next buffer.
		 */
		oldbp = mp->fc_memget_ptr;

		if (oldbp == 0) {
			mp->fc_memget_end = (uint8_t *)matp;
		}
		mp->fc_memget_ptr = (uint8_t *)matp;
		matp->fc_mptr = oldbp;
		matp->virt = buf_info->virt;
		matp->phys = buf_info->phys;
		matp->size = buf_info->size;
		matp->dma_handle = buf_info->dma_handle;
		matp->data_handle = buf_info->data_handle;
		matp->tag = MEM_BPL;
		matp->flag |= MAP_POOL_ALLOCATED;
	}


	/*
	 * These represent the unsolicited ELS buffers we preallocate.
	 */

	mp = &hba->memseg[MEM_BUF];
	mp->fc_memsize = MEM_BUF_SIZE;
	mp->fc_numblks = MEM_ELSBUF_COUNT + MEM_BUF_COUNT;
	mp->fc_memflag = FC_MEM_DMA;
	mp->fc_lowmem = 3;
	mp->fc_memstart_virt = 0;
	mp->fc_memstart_phys = 0;
	mp->fc_mem_dma_handle = 0;
	mp->fc_mem_dat_handle = 0;
	mp->fc_memget_ptr = 0;
	mp->fc_memget_end = 0;
	mp->fc_memput_ptr = 0;
	mp->fc_memput_end = 0;
	mp->fc_total_memsize = 0;
	mp->fc_memget_cnt = mp->fc_numblks;
	mp->fc_memput_cnt = 0;

	/* Allocate buffer pools for above buffer structures */
	for (i = 0; i < mp->fc_numblks; i++) {
		/*
		 * If this is a DMA buffer we need alignment on a page so we
		 * don't want to worry about buffers spanning page boundries
		 * when mapping memory for the adapter.
		 */
		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = sizeof (MATCHMAP);
		buf_info->align = sizeof (void *);

		(void) emlxs_mem_alloc(hba, buf_info);
		if (buf_info->virt == NULL) {
			mutex_exit(&EMLXS_MEMGET_LOCK);

			(void) emlxs_mem_free_buffer(hba);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "MEM_BUF Segment buffer.");

			return (0);
		}
		matp = (MATCHMAP *) buf_info->virt;
		bzero(matp, sizeof (MATCHMAP));

		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = mp->fc_memsize;
		buf_info->flags = FC_MBUF_DMA;
		buf_info->align = 32;

		(void) emlxs_mem_alloc(hba, buf_info);
		if (buf_info->virt == NULL) {
			mutex_exit(&EMLXS_MEMGET_LOCK);

			(void) emlxs_mem_free_buffer(hba);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "MEM_BUF DMA buffer.");

			return (0);
		}
		bp = (uint8_t *)buf_info->virt;
		bzero(bp, mp->fc_memsize);

		/*
		 * Link buffer into beginning of list. The first pointer in
		 * each buffer is a forward pointer to the next buffer.
		 */
		oldbp = mp->fc_memget_ptr;

		if (oldbp == 0) {
			mp->fc_memget_end = (uint8_t *)matp;
		}
		mp->fc_memget_ptr = (uint8_t *)matp;
		matp->fc_mptr = oldbp;
		matp->virt = buf_info->virt;
		matp->phys = buf_info->phys;
		matp->size = buf_info->size;
		matp->dma_handle = buf_info->dma_handle;
		matp->data_handle = buf_info->data_handle;
		matp->tag = MEM_BUF;
		matp->flag |= MAP_POOL_ALLOCATED;
	}


	/*
	 * These represent the unsolicited IP buffers we preallocate.
	 */

	mp = &hba->memseg[MEM_IPBUF];
	mp->fc_memsize = MEM_IPBUF_SIZE;
	mp->fc_numblks = MEM_IPBUF_COUNT;
	mp->fc_memflag = FC_MEM_DMA;
	mp->fc_lowmem = 3;
	mp->fc_memstart_virt = 0;
	mp->fc_memstart_phys = 0;
	mp->fc_mem_dma_handle = 0;
	mp->fc_mem_dat_handle = 0;
	mp->fc_memget_ptr = 0;
	mp->fc_memget_end = 0;
	mp->fc_memput_ptr = 0;
	mp->fc_memput_end = 0;
	mp->fc_total_memsize = 0;
	mp->fc_memget_cnt = mp->fc_numblks;
	mp->fc_memput_cnt = 0;

	/* Allocate buffer pools for above buffer structures */
	for (i = 0; i < mp->fc_numblks; i++) {
		/*
		 * If this is a DMA buffer we need alignment on a page so we
		 * don't want to worry about buffers spanning page boundries
		 * when mapping memory for the adapter.
		 */
		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = sizeof (MATCHMAP);
		buf_info->align = sizeof (void *);

		(void) emlxs_mem_alloc(hba, buf_info);
		if (buf_info->virt == NULL) {
			mutex_exit(&EMLXS_MEMGET_LOCK);

			(void) emlxs_mem_free_buffer(hba);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "IP_BUF Segment buffer.");

			return (0);
		}
		matp = (MATCHMAP *) buf_info->virt;
		bzero(matp, sizeof (MATCHMAP));

		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = mp->fc_memsize;
		buf_info->flags = FC_MBUF_DMA;
		buf_info->align = 32;

		(void) emlxs_mem_alloc(hba, buf_info);
		if (buf_info->virt == NULL) {
			mutex_exit(&EMLXS_MEMGET_LOCK);

			(void) emlxs_mem_free_buffer(hba);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "IP_BUF DMA buffer.");

			return (0);
		}
		bp = (uint8_t *)buf_info->virt;
		bzero(bp, mp->fc_memsize);

		/*
		 * Link buffer into beginning of list. The first pointer in
		 * each buffer is a forward pointer to the next buffer.
		 */
		oldbp = mp->fc_memget_ptr;

		if (oldbp == 0) {
			mp->fc_memget_end = (uint8_t *)matp;
		}
		mp->fc_memget_ptr = (uint8_t *)matp;
		matp->fc_mptr = oldbp;
		matp->virt = buf_info->virt;
		matp->phys = buf_info->phys;
		matp->size = buf_info->size;
		matp->dma_handle = buf_info->dma_handle;
		matp->data_handle = buf_info->data_handle;
		matp->tag = MEM_IPBUF;
		matp->flag |= MAP_POOL_ALLOCATED;
	}

	/*
	 * These represent the unsolicited CT buffers we preallocate.
	 */
	mp = &hba->memseg[MEM_CTBUF];
	mp->fc_memsize = MEM_CTBUF_SIZE;
	mp->fc_numblks = MEM_CTBUF_COUNT;
	mp->fc_memflag = FC_MEM_DMA;
	mp->fc_lowmem = 0;
	mp->fc_memstart_virt = 0;
	mp->fc_memstart_phys = 0;
	mp->fc_mem_dma_handle = 0;
	mp->fc_mem_dat_handle = 0;
	mp->fc_memget_ptr = 0;
	mp->fc_memget_end = 0;
	mp->fc_memput_ptr = 0;
	mp->fc_memput_end = 0;
	mp->fc_total_memsize = 0;
	mp->fc_memget_cnt = mp->fc_numblks;
	mp->fc_memput_cnt = 0;

	/* Allocate buffer pools for above buffer structures */
	for (i = 0; i < mp->fc_numblks; i++) {
		/*
		 * If this is a DMA buffer we need alignment on a page so we
		 * don't want to worry about buffers spanning page boundries
		 * when mapping memory for the adapter.
		 */
		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = sizeof (MATCHMAP);
		buf_info->align = sizeof (void *);

		(void) emlxs_mem_alloc(hba, buf_info);
		if (buf_info->virt == NULL) {
			mutex_exit(&EMLXS_MEMGET_LOCK);

			(void) emlxs_mem_free_buffer(hba);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "CT_BUF Segment buffer.");

			return (0);
		}
		matp = (MATCHMAP *) buf_info->virt;
		bzero(matp, sizeof (MATCHMAP));

		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = mp->fc_memsize;
		buf_info->flags = FC_MBUF_DMA;
		buf_info->align = 32;

		(void) emlxs_mem_alloc(hba, buf_info);
		if (buf_info->virt == NULL) {
			mutex_exit(&EMLXS_MEMGET_LOCK);

			(void) emlxs_mem_free_buffer(hba);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "CT_BUF DMA buffer.");

			return (0);
		}
		bp = (uint8_t *)buf_info->virt;
		bzero(bp, mp->fc_memsize);

		/*
		 * Link buffer into beginning of list. The first pointer in
		 * each buffer is a forward pointer to the next buffer.
		 */
		oldbp = mp->fc_memget_ptr;

		if (oldbp == 0) {
			mp->fc_memget_end = (uint8_t *)matp;
		}
		mp->fc_memget_ptr = (uint8_t *)matp;
		matp->fc_mptr = oldbp;
		matp->virt = buf_info->virt;
		matp->phys = buf_info->phys;
		matp->size = buf_info->size;
		matp->dma_handle = buf_info->dma_handle;
		matp->data_handle = buf_info->data_handle;
		matp->tag = MEM_CTBUF;
		matp->flag |= MAP_POOL_ALLOCATED;
	}

#ifdef SFCT_SUPPORT

	/*
	 * These represent the unsolicited FCT buffers we preallocate.
	 */
	mp = &hba->memseg[MEM_FCTBUF];
	mp->fc_memsize = MEM_FCTBUF_SIZE;
	mp->fc_numblks = (hba->tgt_mode) ? MEM_FCTBUF_COUNT : 0;
	mp->fc_memflag = FC_MEM_DMA;
	mp->fc_lowmem = 0;
	mp->fc_memstart_virt = 0;
	mp->fc_memstart_phys = 0;
	mp->fc_mem_dma_handle = 0;
	mp->fc_mem_dat_handle = 0;
	mp->fc_memget_ptr = 0;
	mp->fc_memget_end = 0;
	mp->fc_memput_ptr = 0;
	mp->fc_memput_end = 0;
	mp->fc_total_memsize = 0;
	mp->fc_memget_cnt = mp->fc_numblks;
	mp->fc_memput_cnt = 0;

	/* Allocate buffer pools for above buffer structures */
	for (i = 0; i < mp->fc_numblks; i++) {
		/*
		 * If this is a DMA buffer we need alignment on a page so we
		 * don't want to worry about buffers spanning page boundries
		 * when mapping memory for the adapter.
		 */
		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = sizeof (MATCHMAP);
		buf_info->align = sizeof (void *);

		(void) emlxs_mem_alloc(hba, buf_info);
		if (buf_info->virt == NULL) {
			mutex_exit(&EMLXS_MEMGET_LOCK);

			(void) emlxs_mem_free_buffer(hba);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "FCT_BUF Segment buffer.");

			return (0);
		}
		matp = (MATCHMAP *) buf_info->virt;
		bzero(matp, sizeof (MATCHMAP));

		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = mp->fc_memsize;
		buf_info->flags = FC_MBUF_DMA;
		buf_info->align = 32;

		(void) emlxs_mem_alloc(hba, buf_info);
		if (buf_info->virt == NULL) {
			mutex_exit(&EMLXS_MEMGET_LOCK);

			(void) emlxs_mem_free_buffer(hba);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "FCT_BUF DMA buffer.");

			return (0);
		}
		bp = (uint8_t *)buf_info->virt;
		bzero(bp, mp->fc_memsize);

		/*
		 * Link buffer into beginning of list. The first pointer in
		 * each buffer is a forward pointer to the next buffer.
		 */
		oldbp = mp->fc_memget_ptr;

		if (oldbp == 0) {
			mp->fc_memget_end = (uint8_t *)matp;
		}
		mp->fc_memget_ptr = (uint8_t *)matp;
		matp->fc_mptr = oldbp;
		matp->virt = buf_info->virt;
		matp->phys = buf_info->phys;
		matp->size = buf_info->size;
		matp->dma_handle = buf_info->dma_handle;
		matp->data_handle = buf_info->data_handle;
		matp->tag = MEM_FCTBUF;
		matp->flag |= MAP_POOL_ALLOCATED;
	}
#endif	/* SFCT_SUPPORT */

	for (i = 0; i < FC_MAX_SEG; i++) {
		char *seg;

		switch (i) {
		case MEM_NLP:
			seg = "MEM_NLP";
			break;
		case MEM_IOCB:
			seg = "MEM_IOCB";
			break;
		case MEM_MBOX:
			seg = "MEM_MBOX";
			break;
		case MEM_BPL:
			seg = "MEM_BPL";
			break;
		case MEM_BUF:
			seg = "MEM_BUF";
			break;
		case MEM_IPBUF:
			seg = "MEM_IPBUF";
			break;
		case MEM_CTBUF:
			seg = "MEM_CTBUF";
			break;
#ifdef SFCT_SUPPORT
		case MEM_FCTBUF:
			seg = "MEM_FCTBUF";
			break;
#endif	/* SFCT_SUPPORT */
		default:
			break;
		}

		mp = &hba->memseg[i];

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_msg,
		    "Segment: %s mp=%p size=%x count=%d flags=%x base=%p",
		    seg, mp, mp->fc_memsize, mp->fc_numblks, mp->fc_memflag,
		    mp->fc_memget_ptr);
	}

	mutex_exit(&EMLXS_MEMGET_LOCK);

	return (1);

} /* emlxs_mem_alloc_buffer() */



/*
 *   emlxs_mem_free_buffer
 *
 *   This routine will free iocb/data buffer space
 *   and TGTM resource.
 */
extern int
emlxs_mem_free_buffer(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_port_t *vport;
	int32_t j;
	uint8_t *bp;
	MEMSEG *mp;
	MATCHMAP *mm;
	RING *rp;
	IOCBQ *iocbq;
	IOCB *iocb;
	MAILBOXQ *mbox, *mbsave;
	MBUF_INFO *buf_info;
	MBUF_INFO bufinfo;
	emlxs_buf_t *sbp;
	fc_unsol_buf_t *ubp;
	RING *fcp_rp;
	RING *ip_rp;
	RING *els_rp;
	RING *ct_rp;
	uint32_t total_iotags;
	emlxs_ub_priv_t *ub_priv;

	buf_info = &bufinfo;

	/* Check for deferred pkt completion */
	if (hba->mbox_sbp) {
		sbp = (emlxs_buf_t *)hba->mbox_sbp;
		hba->mbox_sbp = 0;

		emlxs_pkt_complete(sbp, -1, 0, 1);
	}
	/* Check for deferred ub completion */
	if (hba->mbox_ubp) {
		ubp = (fc_unsol_buf_t *)hba->mbox_ubp;
		ub_priv = (emlxs_ub_priv_t *)ubp->ub_fca_private;
		port = ub_priv->port;
		hba->mbox_ubp = 0;

		emlxs_ub_callback(port, ubp);
	}
	/* Check for deferred iocb tx */
	if (hba->mbox_iocbq) {	/* iocb */
		iocbq = (IOCBQ *) hba->mbox_iocbq;
		hba->mbox_iocbq = 0;
		iocb = &iocbq->iocb;

		/* Set the error status of the iocb */
		iocb->ulpStatus = IOSTAT_LOCAL_REJECT;
		iocb->un.grsp.perr.statLocalError = IOERR_ABORT_REQUESTED;

		switch (iocb->ulpCommand) {
		case CMD_FCP_ICMND_CR:
		case CMD_FCP_ICMND_CX:
		case CMD_FCP_IREAD_CR:
		case CMD_FCP_IREAD_CX:
		case CMD_FCP_IWRITE_CR:
		case CMD_FCP_IWRITE_CX:
		case CMD_FCP_ICMND64_CR:
		case CMD_FCP_ICMND64_CX:
		case CMD_FCP_IREAD64_CR:
		case CMD_FCP_IREAD64_CX:
		case CMD_FCP_IWRITE64_CR:
		case CMD_FCP_IWRITE64_CX:
			rp = &hba->ring[FC_FCP_RING];
			emlxs_handle_fcp_event(hba, rp, iocbq);
			break;

		case CMD_ELS_REQUEST_CR:
		case CMD_ELS_REQUEST_CX:
		case CMD_XMIT_ELS_RSP_CX:
		case CMD_ELS_REQUEST64_CR:	/* This is the only one used */
						/*   currently for deferred */
						/*   iocb tx */
		case CMD_ELS_REQUEST64_CX:
		case CMD_XMIT_ELS_RSP64_CX:
			rp = &hba->ring[FC_ELS_RING];
			(void) emlxs_els_handle_event(hba, rp, iocbq);
			break;

		case CMD_GEN_REQUEST64_CR:
		case CMD_GEN_REQUEST64_CX:
			rp = &hba->ring[FC_CT_RING];
			(void) emlxs_ct_handle_event(hba, rp, iocbq);
			break;

		default:
			rp = (RING *) iocbq->ring;

			if (rp) {
				if (rp->ringno == FC_ELS_RING) {
					(void) emlxs_mem_put(hba, MEM_ELSBUF,
					    (uint8_t *)iocbq->bp);
				} else if (rp->ringno == FC_CT_RING) {
					(void) emlxs_mem_put(hba, MEM_CTBUF,
					    (uint8_t *)iocbq->bp);
				} else if (rp->ringno == FC_IP_RING) {
					(void) emlxs_mem_put(hba, MEM_IPBUF,
					    (uint8_t *)iocbq->bp);
				}
#ifdef SFCT_SUPPORT
				else if (rp->ringno == FC_FCT_RING) {
					(void) emlxs_mem_put(hba, MEM_FCTBUF,
					    (uint8_t *)iocbq->bp);
				}
#endif	/* SFCT_SUPPORT */

			} else if (iocbq->bp) {
				(void) emlxs_mem_put(hba, MEM_BUF,
				    (uint8_t *)iocbq->bp);
			}
			if (!iocbq->sbp) {
				(void) emlxs_mem_put(hba, MEM_IOCB,
				    (uint8_t *)iocbq);
			}
		}
	}
	/* free the mapped address match area for each ring */
	for (j = 0; j < hba->ring_count; j++) {
		rp = &hba->ring[j];

		/* Flush the ring */
		(void) emlxs_tx_ring_flush(hba, rp, 0);

		while (rp->fc_mpoff) {
			uint64_t addr;

			addr = 0;
			mm = (MATCHMAP *) (rp->fc_mpoff);

			if ((j == FC_ELS_RING) ||
			    (j == FC_CT_RING) ||
#ifdef SFCT_SUPPORT
			    (j == FC_FCT_RING) ||
#endif	/* SFCT_SUPPORT */
			    (j == FC_IP_RING)) {
				addr = mm->phys;
			}
			if ((mm = emlxs_mem_get_vaddr(hba, rp, addr))) {
				if (j == FC_ELS_RING) {
					(void) emlxs_mem_put(hba, MEM_ELSBUF,
					    (uint8_t *)mm);
				} else if (j == FC_CT_RING) {
					(void) emlxs_mem_put(hba, MEM_CTBUF,
					    (uint8_t *)mm);
				} else if (j == FC_IP_RING) {
					(void) emlxs_mem_put(hba, MEM_IPBUF,
					    (uint8_t *)mm);
				}
#ifdef SFCT_SUPPORT
				else if (j == FC_FCT_RING) {
					(void) emlxs_mem_put(hba, MEM_FCTBUF,
					    (uint8_t *)mm);
				}
#endif	/* SFCT_SUPPORT */

			}
		}
	}

#ifdef SLI3_SUPPORT
	if (hba->flag & FC_HBQ_ENABLED) {
		emlxs_hbq_free_all(hba, EMLXS_ELS_HBQ_ID);
		emlxs_hbq_free_all(hba, EMLXS_IP_HBQ_ID);
		emlxs_hbq_free_all(hba, EMLXS_CT_HBQ_ID);
#ifdef SFCT_SUPPORT
		if (hba->tgt_mode) {
			emlxs_hbq_free_all(hba, EMLXS_FCT_HBQ_ID);
		}
#endif	/* SFCT_SUPPORT */

	}
#endif	/* SLI3_SUPPORT */

	/* Free everything on mbox queue */
	mbox = (MAILBOXQ *) (hba->mbox_queue.q_first);
	while (mbox) {
		mbsave = mbox;
		mbox = (MAILBOXQ *) mbox->next;
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mbsave);
	}
	hba->mbox_queue.q_first = NULL;
	hba->mbox_queue.q_last = NULL;
	hba->mbox_queue.q_cnt = 0;
	hba->mbox_queue_flag = 0;

	/* Free the nodes */
	for (j = 0; j < MAX_VPORTS; j++) {
		vport = &VPORT(j);
		if (vport->node_count) {
			emlxs_node_destroy_all(vport);
		}
	}

	/* Free memory associated with all buffers on get buffer pool */
	if (hba->iotag_table) {
		fcp_rp = &hba->ring[FC_FCP_RING];
		ip_rp = &hba->ring[FC_IP_RING];
		els_rp = &hba->ring[FC_ELS_RING];
		ct_rp = &hba->ring[FC_CT_RING];

		total_iotags = fcp_rp->max_iotag + ip_rp->max_iotag +
		    els_rp->max_iotag + ct_rp->max_iotag;

		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = total_iotags * sizeof (emlxs_buf_t *);
		buf_info->virt = hba->iotag_table;
		emlxs_mem_free(hba, buf_info);

		hba->iotag_table = 0;
	}
#ifdef EMLXS_SPARC
	if (hba->fcp_bpl_table) {
		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = fcp_rp->max_iotag * sizeof (MATCHMAP);
		buf_info->virt = hba->fcp_bpl_table;
		emlxs_mem_free(hba, buf_info);

		hba->fcp_bpl_table = 0;
	}
	if (hba->fcp_bpl_mp.virt) {
		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = hba->fcp_bpl_mp.size;
		buf_info->virt = hba->fcp_bpl_mp.virt;
		buf_info->phys = hba->fcp_bpl_mp.phys;
		buf_info->dma_handle = hba->fcp_bpl_mp.dma_handle;
		buf_info->data_handle = hba->fcp_bpl_mp.data_handle;
		buf_info->flags = FC_MBUF_DMA;
		emlxs_mem_free(hba, buf_info);

		bzero(&hba->fcp_bpl_mp, sizeof (MATCHMAP));
	}
#endif	/* EMLXS_SPARC */

	/* Free the memory segments */
	for (j = 0; j < FC_MAX_SEG; j++) {
		mp = &hba->memseg[j];

		/* MEM_NLP, MEM_IOCB, MEM_MBOX */
		if (j < MEM_BPL) {
			if (mp->fc_memstart_virt) {
				kmem_free(mp->fc_memstart_virt,
				    mp->fc_total_memsize);
				bzero((char *)mp, sizeof (MEMSEG));
			}
			continue;
		}
		/*
		 * MEM_BPL, MEM_BUF, MEM_ELSBUF, MEM_IPBUF, MEM_CTBUF,
		 * MEM_FCTBUF
		 */

		/* Free memory associated with all buffers on get buffer pool */
		mutex_enter(&EMLXS_MEMGET_LOCK);
		while ((bp = mp->fc_memget_ptr) != NULL) {
			mp->fc_memget_ptr = *((uint8_t **)bp);
			mm = (MATCHMAP *) bp;

			bzero(buf_info, sizeof (MBUF_INFO));
			buf_info->size = mm->size;
			buf_info->virt = mm->virt;
			buf_info->phys = mm->phys;
			buf_info->dma_handle = mm->dma_handle;
			buf_info->data_handle = mm->data_handle;
			buf_info->flags = FC_MBUF_DMA;
			emlxs_mem_free(hba, buf_info);

			bzero(buf_info, sizeof (MBUF_INFO));
			buf_info->size = sizeof (MATCHMAP);
			buf_info->virt = (uint32_t *)mm;
			emlxs_mem_free(hba, buf_info);
		}
		mutex_exit(&EMLXS_MEMGET_LOCK);

		/* Free memory associated with all buffers on put buffer pool */
		mutex_enter(&EMLXS_MEMPUT_LOCK);
		while ((bp = mp->fc_memput_ptr) != NULL) {
			mp->fc_memput_ptr = *((uint8_t **)bp);
			mm = (MATCHMAP *) bp;

			bzero(buf_info, sizeof (MBUF_INFO));
			buf_info->size = mm->size;
			buf_info->virt = mm->virt;
			buf_info->phys = mm->phys;
			buf_info->dma_handle = mm->dma_handle;
			buf_info->data_handle = mm->data_handle;
			buf_info->flags = FC_MBUF_DMA;
			emlxs_mem_free(hba, buf_info);

			bzero(buf_info, sizeof (MBUF_INFO));
			buf_info->size = sizeof (MATCHMAP);
			buf_info->virt = (uint32_t *)mm;
			emlxs_mem_free(hba, buf_info);
		}
		mutex_exit(&EMLXS_MEMPUT_LOCK);
		bzero((char *)mp, sizeof (MEMSEG));
	}

	return (0);

} /* emlxs_mem_free_buffer() */


extern uint8_t *
emlxs_mem_buf_alloc(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint8_t *bp = NULL;
	MATCHMAP *matp = NULL;
	MBUF_INFO *buf_info;
	MBUF_INFO bufinfo;

	buf_info = &bufinfo;

	bzero(buf_info, sizeof (MBUF_INFO));
	buf_info->size = sizeof (MATCHMAP);
	buf_info->align = sizeof (void *);

	(void) emlxs_mem_alloc(hba, buf_info);
	if (buf_info->virt == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
		    "MEM_BUF_ALLOC buffer.");

		return (0);
	}
	matp = (MATCHMAP *) buf_info->virt;
	bzero(matp, sizeof (MATCHMAP));

	bzero(buf_info, sizeof (MBUF_INFO));
	buf_info->size = MEM_BUF_SIZE;
	buf_info->flags = FC_MBUF_DMA;
	buf_info->align = 32;

	(void) emlxs_mem_alloc(hba, buf_info);
	if (buf_info->virt == NULL) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
		    "MEM_BUF_ALLOC DMA buffer.");

		return (0);
	}
	bp = (uint8_t *)buf_info->virt;
	bzero(bp, MEM_BUF_SIZE);

	matp->fc_mptr = NULL;
	matp->virt = buf_info->virt;
	matp->phys = buf_info->phys;
	matp->size = buf_info->size;
	matp->dma_handle = buf_info->dma_handle;
	matp->data_handle = buf_info->data_handle;
	matp->tag = MEM_BUF;
	matp->flag |= MAP_BUF_ALLOCATED;

	return ((uint8_t *)matp);

} /* emlxs_mem_buf_alloc() */


extern uint8_t *
emlxs_mem_buf_free(emlxs_hba_t *hba, uint8_t *bp)
{
	MATCHMAP *matp;
	MBUF_INFO bufinfo;
	MBUF_INFO *buf_info;

	buf_info = &bufinfo;

	matp = (MATCHMAP *) bp;

	if (!(matp->flag & MAP_BUF_ALLOCATED)) {
		return (NULL);
	}

	bzero(buf_info, sizeof (MBUF_INFO));
	buf_info->size = matp->size;
	buf_info->virt = matp->virt;
	buf_info->phys = matp->phys;
	buf_info->dma_handle = matp->dma_handle;
	buf_info->data_handle = matp->data_handle;
	buf_info->flags = FC_MBUF_DMA;
	emlxs_mem_free(hba, buf_info);

	bzero(buf_info, sizeof (MBUF_INFO));
	buf_info->size = sizeof (MATCHMAP);
	buf_info->virt = (uint32_t *)matp;
	emlxs_mem_free(hba, buf_info);

	return (bp);

} /* emlxs_mem_buf_free() */



/*
 *   emlxs_mem_get
 *
 *   This routine will get a free memory buffer.
 *   seg identifies which buffer pool to use.
 *   Returns the free buffer ptr or 0 for no buf
 */
extern uint8_t *
emlxs_mem_get(emlxs_hba_t *hba, uint32_t arg)
{
	emlxs_port_t *port = &PPORT;
	MEMSEG *mp;
	uint8_t *bp = NULL;
	uint32_t seg = arg & MEM_SEG_MASK;
	MAILBOXQ *mbq;
	MATCHMAP *matp;
	IOCBQ *iocbq;
	NODELIST *node;
	uint8_t *base;
	uint8_t *end;

	/* range check on seg argument */
	if (seg >= FC_MAX_SEG) {
		return (NULL);
	}
	mp = &hba->memseg[seg];

	/* Check if memory segment destroyed! */
	if (mp->fc_memsize == 0) {
		return (NULL);
	}
	mutex_enter(&EMLXS_MEMGET_LOCK);

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_msg, "mem_get[%d]:
	 * memget=%p,%d  memput=%p,%d", seg, mp->fc_memget_ptr,
	 * mp->fc_memget_cnt, mp->fc_memput_ptr, mp->fc_memput_cnt);
	 */

top:

	if (mp->fc_memget_ptr) {
		bp = mp->fc_memget_ptr;

		/*
		 * Checking (seg == MEM_MBOX || seg == MEM_IOCB || seg ==
		 * MEM_NLP)
		 */
		/* Verify buffer is in this memory region */
		if (mp->fc_memstart_virt && mp->fc_total_memsize) {
			base = mp->fc_memstart_virt;
			end = mp->fc_memstart_virt + mp->fc_total_memsize;
			if (bp < base || bp >= end) {
				/* Invalidate the the get list */
				mp->fc_memget_ptr = NULL;
				mp->fc_memget_end = NULL;
				mp->fc_memget_cnt = 0;

				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_error_msg,
				    "Corruption detected: seg=%x bp=%p "
				    "base=%p end=%p.", seg, bp, base, end);

				emlxs_ffstate_change(hba, FC_ERROR);

				mutex_exit(&EMLXS_MEMGET_LOCK);

				(void) thread_create(NULL, 0,
				    emlxs_shutdown_thread,
				    (char *)hba, 0, &p0, TS_RUN,
				    v.v_maxsyspri - 2);

				return (NULL);
			}
		}
		/*
		 * If a memory block exists, take it off freelist and return
		 * it to the user.
		 */
		if (mp->fc_memget_end == bp) {
			mp->fc_memget_ptr = NULL;
			mp->fc_memget_end = NULL;
			mp->fc_memget_cnt = 0;

		} else {
			/*
			 * Pointer to the next free buffer
			 */
			mp->fc_memget_ptr = *((uint8_t **)bp);
			mp->fc_memget_cnt--;
		}

		switch (seg) {
		case MEM_MBOX:
			bzero(bp, sizeof (MAILBOXQ));

			mbq = (MAILBOXQ *) bp;
			mbq->flag |= MBQ_POOL_ALLOCATED;
			break;

		case MEM_IOCB:
			bzero(bp, sizeof (IOCBQ));

			iocbq = (IOCBQ *) bp;
			iocbq->flag |= IOCB_POOL_ALLOCATED;
			break;

		case MEM_NLP:
			bzero(bp, sizeof (NODELIST));

			node = (NODELIST *) bp;
			node->flag |= NODE_POOL_ALLOCATED;
			break;

		case MEM_BPL:
		case MEM_BUF:	/* MEM_ELSBUF */
		case MEM_IPBUF:
		case MEM_CTBUF:
#ifdef SFCT_SUPPORT
		case MEM_FCTBUF:
#endif	/* SFCT_SUPPORT */
		default:
			matp = (MATCHMAP *) bp;
			matp->fc_mptr = NULL;
			matp->flag |= MAP_POOL_ALLOCATED;
			break;
		}
	} else {
		mutex_enter(&EMLXS_MEMPUT_LOCK);
		if (mp->fc_memput_ptr) {
			/*
			 * Move buffer from memput to memget
			 */
			mp->fc_memget_ptr = mp->fc_memput_ptr;
			mp->fc_memget_end = mp->fc_memput_end;
			mp->fc_memget_cnt = mp->fc_memput_cnt;
			mp->fc_memput_ptr = NULL;
			mp->fc_memput_end = NULL;
			mp->fc_memput_cnt = 0;
			mutex_exit(&EMLXS_MEMPUT_LOCK);

			goto top;
		}
		mutex_exit(&EMLXS_MEMPUT_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_alloc_failed_msg,
		    "Pool empty: seg=%x lowmem=%x free=%x",
		    seg, mp->fc_lowmem, mp->fc_memget_cnt);

		/* HBASTATS.memAllocErr++; */
	}

	/*
	 * bp2 = mp->fc_memget_ptr;
	 *
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_msg, "mem_get[%d]-:
	 * memget=%p,%d  memput=%p,%d >%x", seg, mp->fc_memget_ptr,
	 * mp->fc_memget_cnt, mp->fc_memput_ptr, mp->fc_memput_cnt, ((bp2)?
	 * *((uint8_t **) bp2):0));
	 */

	mutex_exit(&EMLXS_MEMGET_LOCK);

	return (bp);

} /* emlxs_mem_get() */



extern uint8_t *
emlxs_mem_put(emlxs_hba_t *hba, uint32_t seg, uint8_t *bp)
{
	emlxs_port_t *port = &PPORT;
	MEMSEG *mp;
	uint8_t *oldbp;
	MATCHMAP *matp;
	IOCBQ *iocbq;
	MAILBOXQ *mbq;
	NODELIST *node;
	uint8_t *base;
	uint8_t *end;

	if (!bp) {
		return (NULL);
	}
	/* Check on seg argument */
	if (seg >= FC_MAX_SEG) {
		return (NULL);
	}
	mp = &hba->memseg[seg];

	switch (seg) {
	case MEM_MBOX:
		mbq = (MAILBOXQ *) bp;

		if (!(mbq->flag & MBQ_POOL_ALLOCATED)) {
			return (bp);
		}
		break;

	case MEM_IOCB:
		iocbq = (IOCBQ *) bp;

		/* Check to make sure the IOCB is pool allocated */
		if (!(iocbq->flag & IOCB_POOL_ALLOCATED)) {
			return (bp);
		}
		/*
		 * Any IOCBQ with a packet attached did not come from our
		 * pool
		 */
		if (iocbq->sbp) {
			return (bp);
		}
		break;

	case MEM_NLP:
		node = (NODELIST *) bp;

		/* Check to make sure the NODE is pool allocated */
		if (!(node->flag & NODE_POOL_ALLOCATED)) {
			return (bp);
		}
		break;

	case MEM_BPL:
	case MEM_BUF:	/* MEM_ELSBUF */
	case MEM_IPBUF:
	case MEM_CTBUF:
#ifdef SFCT_SUPPORT
	case MEM_FCTBUF:
#endif	/* SFCT_SUPPORT */
	default:
		matp = (MATCHMAP *) bp;

		if (matp->flag & MAP_BUF_ALLOCATED) {
			return (emlxs_mem_buf_free(hba, bp));
		}
		if (matp->flag & MAP_TABLE_ALLOCATED) {
			return (bp);
		}
		/* Check to make sure the MATCHMAP is pool allocated */
		if (!(matp->flag & MAP_POOL_ALLOCATED)) {
			return (bp);
		}
		break;
	}

	/* Free the pool object */
	mutex_enter(&EMLXS_MEMPUT_LOCK);

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_msg, "mem_put[%d]:
	 * memget=%p,%d  memput=%p,%d", seg, mp->fc_memget_ptr,
	 * mp->fc_memget_cnt, mp->fc_memput_ptr, mp->fc_memput_cnt);
	 */

	/* Check if memory segment destroyed! */
	if (mp->fc_memsize == 0) {
		mutex_exit(&EMLXS_MEMPUT_LOCK);
		return (NULL);
	}
	/* Check if buffer was just freed */
	if (mp->fc_memput_ptr == bp) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_error_msg,
		    "Freeing Free object: seg=%x bp=%p", seg, bp);

		mutex_exit(&EMLXS_MEMPUT_LOCK);
		return (NULL);
	}
	/* Validate the buffer */

	/*
	 * Checking (seg == MEM_BUF) || (seg == MEM_BPL) || (seg ==
	 * MEM_CTBUF) || (seg == MEM_IPBUF) || (seg == MEM_FCTBUF)
	 */
	if (mp->fc_memflag & FC_MEM_DMA) {
		if (matp->tag != seg) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_error_msg,
			    "Corruption detected: seg=%x tag=%x bp=%p",
			    seg, matp->tag, bp);

			emlxs_ffstate_change(hba, FC_ERROR);

			mutex_exit(&EMLXS_MEMPUT_LOCK);

			(void) thread_create(NULL, 0, emlxs_shutdown_thread,
			    (char *)hba, 0, &p0, TS_RUN, v.v_maxsyspri - 2);

			return (NULL);
		}
	}
	/* Checking (seg == MEM_MBOX || seg == MEM_IOCB || seg == MEM_NLP) */
	else if (mp->fc_memstart_virt && mp->fc_total_memsize) {
		base = mp->fc_memstart_virt;
		end = mp->fc_memstart_virt + mp->fc_total_memsize;
		if (bp < base || bp >= end) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_error_msg,
			    "Corruption detected: seg=%x bp=%p base=%p end=%p",
			    seg, bp, base, end);

			emlxs_ffstate_change(hba, FC_ERROR);

			mutex_exit(&EMLXS_MEMPUT_LOCK);

			(void) thread_create(NULL, 0, emlxs_shutdown_thread,
			    (char *)hba, 0, &p0, TS_RUN, v.v_maxsyspri - 2);

			return (NULL);
		}
	}
	/* Release to the first place of the freelist */
	oldbp = mp->fc_memput_ptr;
	mp->fc_memput_ptr = bp;
	*((uint8_t **)bp) = oldbp;

	if (oldbp == NULL) {
		mp->fc_memput_end = bp;
		mp->fc_memput_cnt = 1;
	} else {
		mp->fc_memput_cnt++;
	}

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_msg, "mem_put[%d]-:
	 * memget=%p,%d  memput=%p,%d", seg, mp->fc_memget_ptr,
	 * mp->fc_memget_cnt, mp->fc_memput_ptr, mp->fc_memput_cnt);
	 */

	mutex_exit(&EMLXS_MEMPUT_LOCK);

	return (bp);

} /* emlxs_mem_put() */



/*
 * Look up the virtual address given a mapped address
 */
extern MATCHMAP *
emlxs_mem_get_vaddr(emlxs_hba_t *hba, RING *rp, uint64_t mapbp)
{
	emlxs_port_t *port = &PPORT;
	MATCHMAP *prev;
	MATCHMAP *mp;

	switch (rp->ringno) {
	case FC_ELS_RING:
		mp = (MATCHMAP *) rp->fc_mpoff;
		prev = 0;

		while (mp) {
			if (mp->phys == mapbp) {
				if (prev == 0) {
					rp->fc_mpoff = mp->fc_mptr;
				} else {
					prev->fc_mptr = mp->fc_mptr;
				}

				if (rp->fc_mpon == (uint8_t *)mp) {
					rp->fc_mpon = (uint8_t *)prev;
				}
				mp->fc_mptr = 0;

				emlxs_mpdata_sync(mp->dma_handle, 0, mp->size,
				    DDI_DMA_SYNC_FORKERNEL);

				HBASTATS.ElsUbPosted--;

				return (mp);
			}
			prev = mp;
			mp = (MATCHMAP *) mp->fc_mptr;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_error_msg,
		    "ELS Buffer not mapped: bp=%lx ringno=%x mpoff=%p mpon=%p",
		    mapbp, rp->ringno, rp->fc_mpoff, rp->fc_mpon);

		break;

	case FC_CT_RING:
		mp = (MATCHMAP *) rp->fc_mpoff;
		prev = 0;

		while (mp) {
			if (mp->phys == mapbp) {
				if (prev == 0) {
					rp->fc_mpoff = mp->fc_mptr;
				} else {
					prev->fc_mptr = mp->fc_mptr;
				}

				if (rp->fc_mpon == (uint8_t *)mp) {
					rp->fc_mpon = (uint8_t *)prev;
				}
				mp->fc_mptr = 0;

				emlxs_mpdata_sync(mp->dma_handle, 0, mp->size,
				    DDI_DMA_SYNC_FORKERNEL);

				HBASTATS.CtUbPosted--;

				return (mp);
			}
			prev = mp;
			mp = (MATCHMAP *) mp->fc_mptr;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_error_msg,
		    "CT Buffer not mapped: bp=%lx ringno=%x mpoff=%p mpon=%p",
		    mapbp, rp->ringno, rp->fc_mpoff, rp->fc_mpon);

		break;

	case FC_IP_RING:
		mp = (MATCHMAP *) rp->fc_mpoff;
		prev = 0;

		while (mp) {
			if (mp->phys == mapbp) {
				if (prev == 0) {
					rp->fc_mpoff = mp->fc_mptr;
				} else {
					prev->fc_mptr = mp->fc_mptr;
				}

				if (rp->fc_mpon == (uint8_t *)mp) {
					rp->fc_mpon = (uint8_t *)prev;
				}
				mp->fc_mptr = 0;

				emlxs_mpdata_sync(mp->dma_handle, 0, mp->size,
				    DDI_DMA_SYNC_FORKERNEL);

				HBASTATS.IpUbPosted--;

				return (mp);
			}
			prev = mp;
			mp = (MATCHMAP *) mp->fc_mptr;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_error_msg,
		    "IP Buffer not mapped: bp=%lx ringno=%x mpoff=%p mpon=%p",
		    mapbp, rp->ringno, rp->fc_mpoff, rp->fc_mpon);

		break;

#ifdef SFCT_SUPPORT
	case FC_FCT_RING:
		mp = (MATCHMAP *) rp->fc_mpoff;
		prev = 0;

		while (mp) {
			if (mp->phys == mapbp) {
				if (prev == 0) {
					rp->fc_mpoff = mp->fc_mptr;
				} else {
					prev->fc_mptr = mp->fc_mptr;
				}

				if (rp->fc_mpon == (uint8_t *)mp) {
					rp->fc_mpon = (uint8_t *)prev;
				}
				mp->fc_mptr = 0;

				emlxs_mpdata_sync(mp->dma_handle, 0, mp->size,
				    DDI_DMA_SYNC_FORKERNEL);

				HBASTATS.FctUbPosted--;

				return (mp);
			}
			prev = mp;
			mp = (MATCHMAP *) mp->fc_mptr;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_error_msg,
		    "FCT Buffer not mapped: bp=%lx ringno=%x mpoff=%p mpon=%p",
		    mapbp, rp->ringno, rp->fc_mpoff, rp->fc_mpon);

		break;
#endif	/* SFCT_SUPPORT */
	}

	return (0);

} /* emlxs_mem_get_vaddr() */


/*
 * Given a virtual address, bp, generate the physical mapped address and place
 * it where addr points to. Save the address pair for lookup later.
 */
extern void
emlxs_mem_map_vaddr(emlxs_hba_t *hba, RING *rp, MATCHMAP *mp, uint32_t *haddr,
    uint32_t *laddr)
{
	switch (rp->ringno) {
	case FC_ELS_RING:
		/*
		 * Update slot fc_mpon points to then bump it fc_mpoff is
		 * pointer head of the list. fc_mpon  is pointer tail of the
		 * list.
		 */
		mp->fc_mptr = 0;
		if (rp->fc_mpoff == 0) {
			rp->fc_mpoff = (uint8_t *)mp;
			rp->fc_mpon = (uint8_t *)mp;
		} else {
			((MATCHMAP *) (rp->fc_mpon))->fc_mptr = (uint8_t *)mp;
			rp->fc_mpon = (uint8_t *)mp;
		}

		if (hba->flag & FC_SLIM2_MODE) {
			/* return mapped address */
			*haddr = (uint32_t)putPaddrHigh(mp->phys);
			*laddr = (uint32_t)putPaddrLow(mp->phys);
		} else {
			/* return mapped address */
			*laddr = (uint32_t)putPaddrLow(mp->phys);
		}

		HBASTATS.ElsUbPosted++;

		break;

	case FC_CT_RING:
		/*
		 * Update slot fc_mpon points to then bump it fc_mpoff is
		 * pointer head of the list. fc_mpon  is pointer tail of the
		 * list.
		 */
		mp->fc_mptr = 0;
		if (rp->fc_mpoff == 0) {
			rp->fc_mpoff = (uint8_t *)mp;
			rp->fc_mpon = (uint8_t *)mp;
		} else {
			((MATCHMAP *) (rp->fc_mpon))->fc_mptr = (uint8_t *)mp;
			rp->fc_mpon = (uint8_t *)mp;
		}

		if (hba->flag & FC_SLIM2_MODE) {
			/* return mapped address */
			*haddr = (uint32_t)putPaddrHigh(mp->phys);
			*laddr = (uint32_t)putPaddrLow(mp->phys);
		} else {
			/* return mapped address */
			*laddr = (uint32_t)putPaddrLow(mp->phys);
		}

		HBASTATS.CtUbPosted++;

		break;


	case FC_IP_RING:
		/*
		 * Update slot fc_mpon points to then bump it fc_mpoff is
		 * pointer head of the list. fc_mpon  is pointer tail of the
		 * list.
		 */
		mp->fc_mptr = 0;
		if (rp->fc_mpoff == 0) {
			rp->fc_mpoff = (uint8_t *)mp;
			rp->fc_mpon = (uint8_t *)mp;
		} else {
			((MATCHMAP *) (rp->fc_mpon))->fc_mptr = (uint8_t *)mp;
			rp->fc_mpon = (uint8_t *)mp;
		}

		if (hba->flag & FC_SLIM2_MODE) {
			/* return mapped address */
			*haddr = (uint32_t)putPaddrHigh(mp->phys);
			*laddr = (uint32_t)putPaddrLow(mp->phys);
		} else {
			/* return mapped address */
			*laddr = (uint32_t)putPaddrLow(mp->phys);
		}

		HBASTATS.IpUbPosted++;
		break;


#ifdef SFCT_SUPPORT
	case FC_FCT_RING:
		/*
		 * Update slot fc_mpon points to then bump it fc_mpoff is
		 * pointer head of the list. fc_mpon  is pointer tail of the
		 * list.
		 */
		mp->fc_mptr = 0;
		if (rp->fc_mpoff == 0) {
			rp->fc_mpoff = (uint8_t *)mp;
			rp->fc_mpon = (uint8_t *)mp;
		} else {
			((MATCHMAP *) (rp->fc_mpon))->fc_mptr = (uint8_t *)mp;
			rp->fc_mpon = (uint8_t *)mp;
		}

		if (hba->flag & FC_SLIM2_MODE) {
			/* return mapped address */
			*haddr = (uint32_t)putPaddrHigh(mp->phys);
			*laddr = (uint32_t)putPaddrLow(mp->phys);
		} else {
			/* return mapped address */
			*laddr = (uint32_t)putPaddrLow(mp->phys);
		}

		HBASTATS.FctUbPosted++;
		break;
#endif	/* SFCT_SUPPORT */
	}
} /* emlxs_mem_map_vaddr() */


#ifdef SLI3_SUPPORT

static uint32_t
emlxs_hbq_alloc(emlxs_hba_t *hba, uint32_t hbq_id)
{
	emlxs_port_t *port = &PPORT;
	HBQ_INIT_t *hbq;
	MBUF_INFO *buf_info;
	MBUF_INFO bufinfo;

	hbq = &hba->hbq_table[hbq_id];

	if (hbq->HBQ_host_buf.virt == 0) {
		buf_info = &bufinfo;

		/* Get the system's page size in a DDI-compliant way. */
		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = hbq->HBQ_numEntries * sizeof (HBQE_t);
		buf_info->flags = FC_MBUF_DMA;
		buf_info->align = 4096;

		(void) emlxs_mem_alloc(hba, buf_info);

		if (buf_info->virt == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_msg,
			    "Unable to alloc HBQ.");
			return (ENOMEM);
		}
		hbq->HBQ_host_buf.virt = (void *) buf_info->virt;
		hbq->HBQ_host_buf.phys = buf_info->phys;
		hbq->HBQ_host_buf.data_handle = buf_info->data_handle;
		hbq->HBQ_host_buf.dma_handle = buf_info->dma_handle;
		hbq->HBQ_host_buf.size = buf_info->size;
		hbq->HBQ_host_buf.tag = hbq_id;

		bzero((char *)hbq->HBQ_host_buf.virt, buf_info->size);
	}
	return (0);

} /* emlxs_hbq_alloc() */


extern uint32_t
emlxs_hbq_setup(emlxs_hba_t *hba, uint32_t hbq_id)
{
	emlxs_port_t *port = &PPORT;
	HBQ_INIT_t *hbq;
	MATCHMAP *mp;
	HBQE_t *hbqE;
	MAILBOX *mb;
	void *ioa2;
	uint32_t j;
	uint32_t count;
	uint32_t size;
	uint32_t ringno;
	uint32_t seg;

	switch (hbq_id) {
	case EMLXS_ELS_HBQ_ID:
		count = MEM_ELSBUF_COUNT;
		size = MEM_ELSBUF_SIZE;
		ringno = FC_ELS_RING;
		seg = MEM_ELSBUF;
		HBASTATS.ElsUbPosted = count;
		break;

	case EMLXS_IP_HBQ_ID:
		count = MEM_IPBUF_COUNT;
		size = MEM_IPBUF_SIZE;
		ringno = FC_IP_RING;
		seg = MEM_IPBUF;
		HBASTATS.IpUbPosted = count;
		break;

	case EMLXS_CT_HBQ_ID:
		count = MEM_CTBUF_COUNT;
		size = MEM_CTBUF_SIZE;
		ringno = FC_CT_RING;
		seg = MEM_CTBUF;
		HBASTATS.CtUbPosted = count;
		break;

#ifdef SFCT_SUPPORT
	case EMLXS_FCT_HBQ_ID:
		count = MEM_FCTBUF_COUNT;
		size = MEM_FCTBUF_SIZE;
		ringno = FC_FCT_RING;
		seg = MEM_FCTBUF;
		HBASTATS.FctUbPosted = count;
		break;
#endif	/* SFCT_SUPPORT */

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_msg,
		    "emlxs_hbq_setup: Invalid HBQ id. (%x)", hbq_id);
		return (1);
	}

	/* Configure HBQ */
	hbq = &hba->hbq_table[hbq_id];
	hbq->HBQ_numEntries = count;

	/* Get a Mailbox buffer to setup mailbox commands for CONFIG_HBQ */
	if ((mb = (MAILBOX *) emlxs_mem_get(hba, (MEM_MBOX | MEM_PRI))) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_msg,
		    "emlxs_hbq_setup: Unable to get mailbox.");
		return (1);
	}
	/* Allocate HBQ Host buffer and Initialize the HBQEs */
	if (emlxs_hbq_alloc(hba, hbq_id)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_msg,
		    "emlxs_hbq_setup: Unable to allocate HBQ.");
		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		return (1);
	}
	hbq->HBQ_recvNotify = 1;
	hbq->HBQ_num_mask = 0;	/* Bind to ring */
	hbq->HBQ_profile = 0;	/* Selection profile 0=all, 7=logentry */
	hbq->HBQ_ringMask = 1 << ringno;	/* b0100 * ringno - Binds */
						/*   HBA to a ring e.g. */
	/* Ring0=b0001, Ring1=b0010, Ring2=b0100 */
	hbq->HBQ_headerLen = 0;	/* 0 if not profile 4 or 5 */
	hbq->HBQ_logEntry = 0;	/* Set to 1 if this HBQ will be used for */
	hbq->HBQ_id = hbq_id;
	hbq->HBQ_PutIdx_next = 0;
	hbq->HBQ_PutIdx = hbq->HBQ_numEntries - 1;
	hbq->HBQ_GetIdx = 0;
	hbq->HBQ_PostBufCnt = hbq->HBQ_numEntries;
	bzero(hbq->HBQ_PostBufs, sizeof (hbq->HBQ_PostBufs));

	/* Fill in POST BUFFERs in HBQE */
	hbqE = (HBQE_t *)hbq->HBQ_host_buf.virt;
	for (j = 0; j < hbq->HBQ_numEntries; j++, hbqE++) {
		/* Allocate buffer to post */
		if ((mp = (MATCHMAP *) emlxs_mem_get(hba, (seg | MEM_PRI))) ==
		    0) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_msg,
			    "emlxs_hbq_setup: Unable to allocate HBQ buffer. "
			    "cnt=%d", j);
			emlxs_hbq_free_all(hba, hbq_id);
			return (1);
		}
		hbq->HBQ_PostBufs[j] = mp;

		hbqE->unt.ext.HBQ_tag = hbq_id;
		hbqE->unt.ext.HBQE_tag = j;
		hbqE->bde.tus.f.bdeSize = size;
		hbqE->bde.tus.f.bdeFlags = 0;
		hbqE->unt.w = PCIMEM_LONG(hbqE->unt.w);
		hbqE->bde.tus.w = PCIMEM_LONG(hbqE->bde.tus.w);
		hbqE->bde.addrLow =
		    PCIMEM_LONG((uint32_t)putPaddrLow(mp->phys));
		hbqE->bde.addrHigh =
		    PCIMEM_LONG((uint32_t)putPaddrHigh(mp->phys));
	}

	/* Issue CONFIG_HBQ */
	emlxs_mb_config_hbq(hba, mb, hbq_id);
	if (emlxs_mb_issue_cmd(hba, mb, MBX_WAIT, 0) != MBX_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_debug_msg,
		    "emlxs_hbq_setup: Unable to config HBQ. cmd=%x status=%x",
		    mb->mbxCommand, mb->mbxStatus);

		(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		emlxs_hbq_free_all(hba, hbq_id);
		return (1);
	}
	/* Setup HBQ Get/Put indexes */
	ioa2 = (void *) ((char *)hba->slim_addr + (hba->hgp_hbq_offset +
	    (hbq_id * sizeof (uint32_t))));
	WRITE_SLIM_ADDR(hba, (volatile uint32_t *) ioa2, hbq->HBQ_PutIdx);

	hba->hbq_count++;

	(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);

	return (0);

} /* emlxs_hbq_setup */


static void
emlxs_hbq_free_all(emlxs_hba_t *hba, uint32_t hbq_id)
{
	HBQ_INIT_t *hbq;
	MBUF_INFO *buf_info;
	MBUF_INFO bufinfo;
	uint32_t seg;
	uint32_t j;

	switch (hbq_id) {
	case EMLXS_ELS_HBQ_ID:
		seg = MEM_ELSBUF;
		HBASTATS.ElsUbPosted = 0;
		break;

	case EMLXS_IP_HBQ_ID:
		seg = MEM_IPBUF;
		HBASTATS.IpUbPosted = 0;
		break;

	case EMLXS_CT_HBQ_ID:
		seg = MEM_CTBUF;
		HBASTATS.CtUbPosted = 0;
		break;

#ifdef SFCT_SUPPORT
	case EMLXS_FCT_HBQ_ID:
		seg = MEM_FCTBUF;
		HBASTATS.FctUbPosted = 0;
		break;
#endif	/* SFCT_SUPPORT */

	default:
		return;
	}


	hbq = &hba->hbq_table[hbq_id];

	if (hbq->HBQ_host_buf.virt != 0) {
		for (j = 0; j < hbq->HBQ_PostBufCnt; j++) {
			(void) emlxs_mem_put(hba, seg,
			    (uint8_t *)hbq->HBQ_PostBufs[j]);
			hbq->HBQ_PostBufs[j] = NULL;
		}
		hbq->HBQ_PostBufCnt = 0;

		buf_info = &bufinfo;
		bzero(buf_info, sizeof (MBUF_INFO));

		buf_info->size = hbq->HBQ_host_buf.size;
		buf_info->virt = hbq->HBQ_host_buf.virt;
		buf_info->phys = hbq->HBQ_host_buf.phys;
		buf_info->dma_handle = hbq->HBQ_host_buf.dma_handle;
		buf_info->data_handle = hbq->HBQ_host_buf.data_handle;
		buf_info->flags = FC_MBUF_DMA;

		emlxs_mem_free(hba, buf_info);

		hbq->HBQ_host_buf.virt = NULL;
	}
	return;

} /* emlxs_hbq_free_all() */


extern void
emlxs_update_HBQ_index(emlxs_hba_t *hba, uint32_t hbq_id)
{
	void *ioa2;
	uint32_t status;
	uint32_t HBQ_PortGetIdx;
	HBQ_INIT_t *hbq;

	switch (hbq_id) {
	case EMLXS_ELS_HBQ_ID:
		HBASTATS.ElsUbPosted++;
		break;

	case EMLXS_IP_HBQ_ID:
		HBASTATS.IpUbPosted++;
		break;

	case EMLXS_CT_HBQ_ID:
		HBASTATS.CtUbPosted++;
		break;

#ifdef SFCT_SUPPORT
	case EMLXS_FCT_HBQ_ID:
		HBASTATS.FctUbPosted++;
		break;
#endif	/* SFCT_SUPPORT */

	default:
		return;
	}

	hbq = &hba->hbq_table[hbq_id];

	hbq->HBQ_PutIdx = (hbq->HBQ_PutIdx + 1 >= hbq->HBQ_numEntries) ? 0 :
	    hbq->HBQ_PutIdx + 1;

	if (hbq->HBQ_PutIdx == hbq->HBQ_GetIdx) {
		HBQ_PortGetIdx = PCIMEM_LONG(((SLIM2 *) hba->slim2.virt)->
		    mbx.us.s2.HBQ_PortGetIdx[hbq_id]);

		hbq->HBQ_GetIdx = HBQ_PortGetIdx;

		if (hbq->HBQ_PutIdx == hbq->HBQ_GetIdx) {
			return;
		}
	}
	ioa2 = (void *) ((char *)hba->slim_addr + (hba->hgp_hbq_offset +
	    (hbq_id * sizeof (uint32_t))));
	status = hbq->HBQ_PutIdx;
	WRITE_SLIM_ADDR(hba, (volatile uint32_t *) ioa2, status);

	return;

} /* emlxs_update_HBQ_index() */

#endif	/* SLI3_SUPPORT */
