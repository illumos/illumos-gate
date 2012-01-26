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
 * Copyright 2010 Emulex.  All rights reserved.
 * Use is subject to license terms.
 */


#include <emlxs.h>

EMLXS_MSG_DEF(EMLXS_MEM_C);


extern int32_t
emlxs_mem_alloc_buffer(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg;
	MBUF_INFO *buf_info;
	MEMSEG *seg;
	MBUF_INFO bufinfo;
	int32_t i;
	int32_t cnt;
#ifdef EMLXS_SPARC
	MATCHMAP *mp;
	MATCHMAP **fcp_bpl_table;
#endif	/* EMLXS_SPARC */

	buf_info = &bufinfo;
	cfg = &CFG;

	bzero(hba->memseg, sizeof (hba->memseg));

	/*
	 * Initialize fc_table
	 */
	cnt = cfg[CFG_NUM_IOTAGS].current;
	if (cnt) {
		hba->max_iotag = (uint16_t)cnt;
	}
	/* ioatg 0 is not used, iotags 1 thru max_iotag-1 are used */

	/* Allocate the fc_table */
	bzero(buf_info, sizeof (MBUF_INFO));
	buf_info->size = (hba->max_iotag * sizeof (emlxs_buf_t *));

	(void) emlxs_mem_alloc(hba, buf_info);
	if (buf_info->virt == NULL) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
		    "fc_table buffer.");

		goto failed;
	}
	hba->fc_table = buf_info->virt;
	bzero(hba->fc_table, buf_info->size);

#ifdef EMLXS_SPARC
	if (!(hba->model_info.sli_mask & EMLXS_SLI4_MASK)) {
	/*
	 * Allocate and Initialize FCP MEM_BPL table
	 * This is for increased performance on sparc
	 */
	bzero(buf_info, sizeof (MBUF_INFO));
	buf_info->size = hba->max_iotag * sizeof (MATCHMAP *);

	(void) emlxs_mem_alloc(hba, buf_info);
	if (buf_info->virt == NULL) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
		    "FCP BPL table buffer.");

		goto failed;
	}
	hba->sli.sli3.fcp_bpl_table = buf_info->virt;
	bzero(hba->sli.sli3.fcp_bpl_table, buf_info->size);

	/* Allocate a pool of BPLs for the FCP MEM_BPL table */
	seg = &hba->sli.sli3.fcp_bpl_seg;
	bzero(seg, sizeof (MEMSEG));
	(void) strcpy(seg->fc_label, "FCP BPL Pool");
	seg->fc_memtag	= MEM_BPL;
	seg->fc_memsize	= (3 * sizeof (ULP_BDE64));
	seg->fc_numblks	= hba->max_iotag;
	seg->fc_reserved = 0;
	seg->fc_memflag	= FC_MBUF_DMA | FC_MBUF_SNGLSG;
	seg->fc_memalign = 32;

	if (emlxs_mem_pool_alloc(hba, seg) == NULL) {
		goto failed;
	}

	/* Initialize the FCP MEM_BPL table */
	fcp_bpl_table = (MATCHMAP**)hba->sli.sli3.fcp_bpl_table;
	mp = (MATCHMAP*)seg->fc_memget_ptr;
	for (i = 0; i < seg->fc_numblks; i++) {
		mp->flag |= MAP_TABLE_ALLOCATED;
		*fcp_bpl_table = mp;

		mp = (MATCHMAP *)mp->fc_mptr;
		fcp_bpl_table++;
	}
	}
#endif /* EMLXS_SPARC */

	/* Prepare the memory pools */
	for (i = 0; i < FC_MAX_SEG; i++) {
		seg = &hba->memseg[i];

		switch (i) {
		case MEM_NLP:
			(void) strcpy(seg->fc_label, "Node Pool");
			seg->fc_memtag	= MEM_NLP;
			seg->fc_memsize	= sizeof (NODELIST);
			seg->fc_numblks	= (int16_t)hba->max_nodes + 2;
			seg->fc_reserved = 0;
			seg->fc_memflag	= 0;
			break;

		case MEM_IOCB:
			(void) strcpy(seg->fc_label, "IOCB Pool");
			seg->fc_memtag	= MEM_IOCB;
			seg->fc_memsize	= sizeof (IOCBQ);
			seg->fc_numblks	= (uint16_t)cfg[CFG_NUM_IOCBS].current;
			seg->fc_reserved = 0;
			seg->fc_memflag	= 0;
			break;

		case MEM_MBOX:
			(void) strcpy(seg->fc_label, "MBOX Pool");
			seg->fc_memtag	= MEM_MBOX;
			seg->fc_memsize	= sizeof (MAILBOXQ);
			seg->fc_numblks	= (int16_t)hba->max_nodes + 32;
			seg->fc_reserved = 0;
			seg->fc_memflag	= 0;
			break;

		case MEM_BPL:
			if (hba->model_info.sli_mask & EMLXS_SLI4_MASK) {
				continue;
			}
			(void) strcpy(seg->fc_label, "BPL Pool");
			seg->fc_memtag	= MEM_BPL;
			seg->fc_memsize	= hba->sli.sli3.mem_bpl_size;
			seg->fc_numblks	= (int16_t)hba->max_iotag + 2;
			seg->fc_reserved = 0;
			seg->fc_memflag	= FC_MBUF_DMA | FC_MBUF_SNGLSG;
			seg->fc_memalign = 32;
			break;

		case MEM_BUF:
			/* These are the unsolicited ELS buffers. */
			(void) strcpy(seg->fc_label, "BUF Pool");
			seg->fc_memtag	= MEM_BUF;
			seg->fc_memsize	= MEM_BUF_SIZE;
			seg->fc_numblks	= MEM_ELSBUF_COUNT + MEM_BUF_COUNT;
			seg->fc_reserved = 0;
			seg->fc_memflag	= FC_MBUF_DMA | FC_MBUF_SNGLSG;
			seg->fc_memalign = 32;
			break;

		case MEM_IPBUF:
			/* These are the unsolicited IP buffers. */
			if (cfg[CFG_NETWORK_ON].current == 0) {
				continue;
			}

			(void) strcpy(seg->fc_label, "IPBUF Pool");
			seg->fc_memtag	= MEM_IPBUF;
			seg->fc_memsize	= MEM_IPBUF_SIZE;
			seg->fc_numblks	= MEM_IPBUF_COUNT;
			seg->fc_reserved = 0;
			seg->fc_memflag	= FC_MBUF_DMA | FC_MBUF_SNGLSG;
			seg->fc_memalign = 32;
			break;

		case MEM_CTBUF:
			/* These are the unsolicited CT buffers. */
			(void) strcpy(seg->fc_label, "CTBUF Pool");
			seg->fc_memtag	= MEM_CTBUF;
			seg->fc_memsize	= MEM_CTBUF_SIZE;
			seg->fc_numblks	= MEM_CTBUF_COUNT;
			seg->fc_reserved = 0;
			seg->fc_memflag	= FC_MBUF_DMA | FC_MBUF_SNGLSG;
			seg->fc_memalign = 32;
			break;

		case MEM_FCTBUF:
#ifdef SFCT_SUPPORT
			/* These are the unsolicited FCT buffers. */
			if (hba->tgt_mode == 0) {
				continue;
			}

			(void) strcpy(seg->fc_label, "FCTBUF Pool");
			seg->fc_memtag	= MEM_FCTBUF;
			seg->fc_memsize	= MEM_FCTBUF_SIZE;
			seg->fc_numblks	= MEM_FCTBUF_COUNT;
			seg->fc_reserved = 0;
			seg->fc_memflag	= FC_MBUF_DMA | FC_MBUF_SNGLSG;
			seg->fc_memalign = 32;
#endif /* SFCT_SUPPORT */
			break;

		default:
			continue;
		}

		if (seg->fc_memsize == 0) {
			continue;
		}

		if (emlxs_mem_pool_alloc(hba, seg) == NULL) {
			goto failed;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_msg,
		    "%s: seg=%p size=%x count=%d flags=%x base=%p",
		    seg->fc_label, seg, seg->fc_memsize, seg->fc_numblks,
		    seg->fc_memflag, seg->fc_memget_ptr);
	}

	return (1);

failed:

	(void) emlxs_mem_free_buffer(hba);
	return (0);

} /* emlxs_mem_alloc_buffer() */


/*
 * emlxs_mem_free_buffer
 *
 * This routine will free iocb/data buffer space
 * and TGTM resource.
 */
extern int
emlxs_mem_free_buffer(emlxs_hba_t *hba)
{
	emlxs_port_t *vport;
	int32_t j;
	MATCHMAP *mp;
	CHANNEL *cp;
	RING *rp;
	MBUF_INFO *buf_info;
	MBUF_INFO bufinfo;

	buf_info = &bufinfo;

	for (j = 0; j < hba->chan_count; j++) {
		cp = &hba->chan[j];

		/* Flush the ring */
		(void) emlxs_tx_channel_flush(hba, cp, 0);
	}

	if (!(hba->model_info.sli_mask & EMLXS_SLI4_MASK)) {
		/* free the mapped address match area for each ring */
		for (j = 0; j < MAX_RINGS; j++) {
			rp = &hba->sli.sli3.ring[j];

			while (rp->fc_mpoff) {
				uint64_t addr;

				addr = 0;
				mp = (MATCHMAP *)(rp->fc_mpoff);

				if ((j == hba->channel_els) ||
				    (j == hba->channel_ct) ||
#ifdef SFCT_SUPPORT
				    (j == hba->CHANNEL_FCT) ||
#endif /* SFCT_SUPPORT */
				    (j == hba->channel_ip)) {
					addr = mp->phys;
				}

				if ((mp = emlxs_mem_get_vaddr(hba, rp, addr))) {
					if (j == hba->channel_els) {
						emlxs_mem_put(hba,
						    MEM_ELSBUF, (void *)mp);
					} else if (j == hba->channel_ct) {
						emlxs_mem_put(hba,
						    MEM_CTBUF, (void *)mp);
					} else if (j == hba->channel_ip) {
						emlxs_mem_put(hba,
						    MEM_IPBUF, (void *)mp);
					}
#ifdef SFCT_SUPPORT
					else if (j == hba->CHANNEL_FCT) {
						emlxs_mem_put(hba,
						    MEM_FCTBUF, (void *)mp);
					}
#endif /* SFCT_SUPPORT */

				}
			}
		}
	}

	if (hba->flag & FC_HBQ_ENABLED) {
		emlxs_hbq_free_all(hba, EMLXS_ELS_HBQ_ID);
		emlxs_hbq_free_all(hba, EMLXS_IP_HBQ_ID);
		emlxs_hbq_free_all(hba, EMLXS_CT_HBQ_ID);

		if (hba->tgt_mode) {
			emlxs_hbq_free_all(hba, EMLXS_FCT_HBQ_ID);
		}
	}

	/* Free the nodes */
	for (j = 0; j < MAX_VPORTS; j++) {
		vport = &VPORT(j);
		if (vport->node_count) {
			emlxs_node_destroy_all(vport);
		}
	}

	/* Make sure the mailbox queue is empty */
	emlxs_mb_flush(hba);

	/* Free memory associated with all buffers on get buffer pool */
	if (hba->fc_table) {
		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = hba->max_iotag * sizeof (emlxs_buf_t *);
		buf_info->virt = hba->fc_table;
		emlxs_mem_free(hba, buf_info);
		hba->fc_table = NULL;
	}

#ifdef EMLXS_SPARC
	if (hba->sli.sli3.fcp_bpl_table) {
		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = hba->max_iotag * sizeof (MATCHMAP *);
		buf_info->virt = hba->sli.sli3.fcp_bpl_table;
		emlxs_mem_free(hba, buf_info);
		hba->sli.sli3.fcp_bpl_table = NULL;
	}

	if (hba->sli.sli3.fcp_bpl_seg.fc_memsize) {
		emlxs_mem_pool_free(hba, &hba->sli.sli3.fcp_bpl_seg);
		bzero(&hba->sli.sli3.fcp_bpl_seg, sizeof (MEMSEG));
	}
#endif /* EMLXS_SPARC */

	/* Free the memory segments */
	for (j = 0; j < FC_MAX_SEG; j++) {
		emlxs_mem_pool_free(hba, &hba->memseg[j]);
	}

	return (0);

} /* emlxs_mem_free_buffer() */


extern MEMSEG *
emlxs_mem_pool_alloc(emlxs_hba_t *hba, MEMSEG *seg)
{
	emlxs_port_t *port = &PPORT;
	uint8_t *bp = NULL;
	MATCHMAP *mp = NULL;
	MBUF_INFO *buf_info;
	MBUF_INFO local_buf_info;
	uint32_t i;

	buf_info = &local_buf_info;

	mutex_enter(&EMLXS_MEMGET_LOCK);
	mutex_enter(&EMLXS_MEMPUT_LOCK);

	/* Calculate total memory size */
	seg->fc_total_memsize = (seg->fc_memsize * seg->fc_numblks);

	if (seg->fc_total_memsize == 0) {
		mutex_exit(&EMLXS_MEMPUT_LOCK);
		mutex_exit(&EMLXS_MEMGET_LOCK);
		return (NULL);
	}

	if (!(seg->fc_memflag & FC_MBUF_DMA)) {
		goto vmem_pool;
	}

/* dma_pool */

	for (i = 0; i < seg->fc_numblks; i++) {
		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = sizeof (MATCHMAP);
		buf_info->align = sizeof (void *);

		(void) emlxs_mem_alloc(hba, buf_info);
		if (buf_info->virt == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "%s desc[%d]. size=%d", seg->fc_label, i,
			    buf_info->size);

			goto failed;
		}

		mp = (MATCHMAP *)buf_info->virt;
		bzero(mp, sizeof (MATCHMAP));

		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size  = seg->fc_memsize;
		buf_info->flags = seg->fc_memflag;
		buf_info->align = seg->fc_memalign;

		(void) emlxs_mem_alloc(hba, buf_info);
		if (buf_info->virt == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "%s buffer[%d]. size=%d", seg->fc_label, i,
			    buf_info->size);

			/* Free the mp object */
			bzero(buf_info, sizeof (MBUF_INFO));
			buf_info->size = sizeof (MATCHMAP);
			buf_info->virt = (void *)mp;
			emlxs_mem_free(hba, buf_info);

			goto failed;
		}
		bp = (uint8_t *)buf_info->virt;
		bzero(bp, seg->fc_memsize);

		mp->virt = buf_info->virt;
		mp->phys = buf_info->phys;
		mp->size = buf_info->size;
		mp->dma_handle = buf_info->dma_handle;
		mp->data_handle = buf_info->data_handle;
		mp->tag = seg->fc_memtag;
		mp->segment = seg;
		mp->flag |= MAP_POOL_ALLOCATED;

		/* Add the buffer desc to the tail of the pool freelist */
		if (seg->fc_memget_end == NULL) {
			seg->fc_memget_ptr = (uint8_t *)mp;
			seg->fc_memget_cnt = 1;
		} else {
			*((uint8_t **)(seg->fc_memget_end)) = (uint8_t *)mp;
			seg->fc_memget_cnt++;
		}
		seg->fc_memget_end = (uint8_t *)mp;
	}

	mutex_exit(&EMLXS_MEMPUT_LOCK);
	mutex_exit(&EMLXS_MEMGET_LOCK);
	return (seg);

vmem_pool:

	mutex_exit(&EMLXS_MEMPUT_LOCK);
	mutex_exit(&EMLXS_MEMGET_LOCK);

	seg->fc_memstart_virt = kmem_zalloc(seg->fc_total_memsize, KM_SLEEP);

	mutex_enter(&EMLXS_MEMGET_LOCK);
	mutex_enter(&EMLXS_MEMPUT_LOCK);

	if (seg->fc_memstart_virt == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
		    "%s base. size=%d", seg->fc_label,
		    seg->fc_total_memsize);

		goto failed;
	}

	bp = (uint8_t *)seg->fc_memstart_virt;
	for (i = 0; i < seg->fc_numblks; i++) {

		/* Add the buffer to the tail of the pool freelist */
		if (seg->fc_memget_end == NULL) {
			seg->fc_memget_ptr = (uint8_t *)bp;
			seg->fc_memget_cnt = 1;
		} else {
			*((uint8_t **)(seg->fc_memget_end)) = (uint8_t *)bp;
			seg->fc_memget_cnt++;
		}
		seg->fc_memget_end = (uint8_t *)bp;

		bp += seg->fc_memsize;
	}

	mutex_exit(&EMLXS_MEMPUT_LOCK);
	mutex_exit(&EMLXS_MEMGET_LOCK);
	return (seg);

failed:

	mutex_exit(&EMLXS_MEMPUT_LOCK);
	mutex_exit(&EMLXS_MEMGET_LOCK);
	emlxs_mem_pool_free(hba, seg);
	return (NULL);

} /* emlxs_mem_pool_alloc() */


extern void
emlxs_mem_pool_free(emlxs_hba_t *hba, MEMSEG *seg)
{
	emlxs_port_t *port = &PPORT;
	uint8_t *bp = NULL;
	MATCHMAP *mp = NULL;
	MBUF_INFO *buf_info;
	MBUF_INFO local_buf_info;
	MEMSEG segment;
	uint32_t free;

	/* Save a local copy of the segment and */
	/* destroy the original outside of locks */
	mutex_enter(&EMLXS_MEMGET_LOCK);
	mutex_enter(&EMLXS_MEMPUT_LOCK);

	free = seg->fc_memget_cnt + seg->fc_memput_cnt;
	if (free < seg->fc_numblks) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_detail_msg,
		    "emlxs_mem_pool_free: %s not full. (%d < %d)",
		    seg->fc_label, free, seg->fc_numblks);
	}

	bcopy(seg, &segment, sizeof (MEMSEG));
	bzero((char *)seg, sizeof (MEMSEG));
	seg = &segment;

	mutex_exit(&EMLXS_MEMPUT_LOCK);
	mutex_exit(&EMLXS_MEMGET_LOCK);

	/* Now free the memory  */

	if (!(seg->fc_memflag & FC_MBUF_DMA)) {
		if (seg->fc_memstart_virt) {
			kmem_free(seg->fc_memstart_virt, seg->fc_total_memsize);
		}

		return;
	}

	buf_info = &local_buf_info;

	/* Free memory associated with all buffers on get buffer pool */
	while ((bp = seg->fc_memget_ptr) != NULL) {
		seg->fc_memget_ptr = *((uint8_t **)bp);
		mp = (MATCHMAP *)bp;

		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = mp->size;
		buf_info->virt = mp->virt;
		buf_info->phys = mp->phys;
		buf_info->dma_handle = mp->dma_handle;
		buf_info->data_handle = mp->data_handle;
		buf_info->flags = seg->fc_memflag;
		emlxs_mem_free(hba, buf_info);

		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = sizeof (MATCHMAP);
		buf_info->virt = (void *)mp;
		emlxs_mem_free(hba, buf_info);
	}

	/* Free memory associated with all buffers on put buffer pool */
	while ((bp = seg->fc_memput_ptr) != NULL) {
		seg->fc_memput_ptr = *((uint8_t **)bp);
		mp = (MATCHMAP *)bp;

		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = mp->size;
		buf_info->virt = mp->virt;
		buf_info->phys = mp->phys;
		buf_info->dma_handle = mp->dma_handle;
		buf_info->data_handle = mp->data_handle;
		buf_info->flags = seg->fc_memflag;
		emlxs_mem_free(hba, buf_info);

		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = sizeof (MATCHMAP);
		buf_info->virt = (void *)mp;
		emlxs_mem_free(hba, buf_info);
	}

	return;

} /* emlxs_mem_pool_free() */


extern void *
emlxs_mem_pool_get(emlxs_hba_t *hba, MEMSEG *seg, uint32_t priority)
{
	emlxs_port_t	*port = &PPORT;
	void		*bp = NULL;
	MATCHMAP	*mp;
	uint32_t	free;

	mutex_enter(&EMLXS_MEMGET_LOCK);

	/* Check if memory segment destroyed! */
	if (seg->fc_total_memsize == 0) {
		mutex_exit(&EMLXS_MEMGET_LOCK);
		return (NULL);
	}

	/* Check priority and reserved status */
	if ((priority == 0) && seg->fc_reserved) {
		free = seg->fc_memget_cnt + seg->fc_memput_cnt;
		if (free <= seg->fc_reserved) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_alloc_failed_msg,
			    "%s low. (%d <= %d)", seg->fc_label,
			    free, seg->fc_reserved);

			mutex_exit(&EMLXS_MEMGET_LOCK);
			return (NULL);
		}
	}

top:

	if (seg->fc_memget_ptr) {

		bp = seg->fc_memget_ptr;

		/* Remove buffer from freelist */
		if (seg->fc_memget_end == bp) {
			seg->fc_memget_ptr = NULL;
			seg->fc_memget_end = NULL;
			seg->fc_memget_cnt = 0;

		} else {
			seg->fc_memget_ptr = *((uint8_t **)bp);
			seg->fc_memget_cnt--;
		}

		if (!(seg->fc_memflag & FC_MBUF_DMA)) {
			bzero(bp, seg->fc_memsize);
		} else {
			mp = (MATCHMAP *)bp;
			mp->fc_mptr = NULL;
			mp->flag |= MAP_POOL_ALLOCATED;
		}

	} else {
		mutex_enter(&EMLXS_MEMPUT_LOCK);
		if (seg->fc_memput_ptr) {
			/*
			 * Move list from memput to memget
			 */
			seg->fc_memget_ptr = seg->fc_memput_ptr;
			seg->fc_memget_end = seg->fc_memput_end;
			seg->fc_memget_cnt = seg->fc_memput_cnt;
			seg->fc_memput_ptr = NULL;
			seg->fc_memput_end = NULL;
			seg->fc_memput_cnt = 0;
			mutex_exit(&EMLXS_MEMPUT_LOCK);

			goto top;
		}
		mutex_exit(&EMLXS_MEMPUT_LOCK);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_alloc_failed_msg,
		    "%s empty.", seg->fc_label);
	}

	mutex_exit(&EMLXS_MEMGET_LOCK);

	return (bp);

} /* emlxs_mem_pool_get() */


extern void
emlxs_mem_pool_put(emlxs_hba_t *hba, MEMSEG *seg, void *bp)
{
	emlxs_port_t	*port = &PPORT;
	MATCHMAP	*mp;
	void		*base;
	void		*end;

	/* Free the pool object */
	mutex_enter(&EMLXS_MEMPUT_LOCK);

	/* Check if memory segment destroyed! */
	if (seg->fc_total_memsize == 0) {
		mutex_exit(&EMLXS_MEMPUT_LOCK);
		return;
	}

	/* Check if buffer was just freed */
	if (seg->fc_memput_ptr == bp) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_error_msg,
		    "%s: Freeing free object: bp=%p", seg->fc_label, bp);

		mutex_exit(&EMLXS_MEMPUT_LOCK);
		return;
	}

	/* Validate the buffer belongs to this pool */
	if (seg->fc_memflag & FC_MBUF_DMA) {
		mp = (MATCHMAP *)bp;

		if (!(mp->flag & MAP_POOL_ALLOCATED) ||
		    (mp->segment != seg)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_error_msg,
			    "emlxs_mem_pool_put: %s invalid: mp=%p " \
			    "tag=0x%x flag=%x", seg->fc_label,
			    mp, mp->tag, mp->flag);

			EMLXS_STATE_CHANGE(hba, FC_ERROR);

			mutex_exit(&EMLXS_MEMPUT_LOCK);

			emlxs_thread_spawn(hba, emlxs_shutdown_thread,
			    NULL, NULL);

			return;
		}

	} else { /* Vmem_pool */
		base = seg->fc_memstart_virt;
		end = (void *)((uint8_t *)seg->fc_memstart_virt +
		    seg->fc_total_memsize);

		if (bp < base || bp >= end) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_error_msg,
			    "emlxs_mem_pool_put: %s Invalid: bp=%p base=%p " \
			    "end=%p", seg->fc_label,
			    bp, base, end);

			EMLXS_STATE_CHANGE(hba, FC_ERROR);

			mutex_exit(&EMLXS_MEMPUT_LOCK);

			emlxs_thread_spawn(hba, emlxs_shutdown_thread,
			    NULL, NULL);

			return;
		}
	}

	/* Release buffer to the end of the freelist */
	if (seg->fc_memput_end == NULL) {
		seg->fc_memput_ptr = bp;
		seg->fc_memput_cnt = 1;
	} else {
		*((void **)(seg->fc_memput_end)) = bp;
		seg->fc_memput_cnt++;
	}
	seg->fc_memput_end = bp;
	*((void **)(bp)) = NULL;

	mutex_exit(&EMLXS_MEMPUT_LOCK);

	return;

} /* emlxs_mem_pool_put() */


extern MATCHMAP *
emlxs_mem_buf_alloc(emlxs_hba_t *hba, uint32_t size)
{
	emlxs_port_t *port = &PPORT;
	uint8_t *bp = NULL;
	MATCHMAP *mp = NULL;
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

		return (NULL);
	}

	mp = (MATCHMAP *)buf_info->virt;
	bzero(mp, sizeof (MATCHMAP));

	bzero(buf_info, sizeof (MBUF_INFO));
	buf_info->size = size;
	buf_info->flags = FC_MBUF_DMA | FC_MBUF_SNGLSG | FC_MBUF_DMA32;
	buf_info->align = 32;

	(void) emlxs_mem_alloc(hba, buf_info);
	if (buf_info->virt == NULL) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
		    "MEM_BUF_ALLOC DMA buffer.");

		/* Free the mp object */
		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = sizeof (MATCHMAP);
		buf_info->virt = (void *)mp;
		emlxs_mem_free(hba, buf_info);

		return (0);
	}
	bp = (uint8_t *)buf_info->virt;
	bzero(bp, MEM_BUF_SIZE);

	mp->virt = buf_info->virt;
	mp->phys = buf_info->phys;
	mp->size = buf_info->size;
	mp->dma_handle = buf_info->dma_handle;
	mp->data_handle = buf_info->data_handle;
	mp->tag = MEM_BUF;
	mp->flag |= MAP_BUF_ALLOCATED;

	return (mp);

} /* emlxs_mem_buf_alloc() */


extern void
emlxs_mem_buf_free(emlxs_hba_t *hba, MATCHMAP *mp)
{
	MBUF_INFO bufinfo;
	MBUF_INFO *buf_info;

	buf_info = &bufinfo;

	if (!(mp->flag & MAP_BUF_ALLOCATED)) {
		return;
	}

	bzero(buf_info, sizeof (MBUF_INFO));
	buf_info->size = mp->size;
	buf_info->virt = mp->virt;
	buf_info->phys = mp->phys;
	buf_info->dma_handle = mp->dma_handle;
	buf_info->data_handle = mp->data_handle;
	buf_info->flags = FC_MBUF_DMA;
	emlxs_mem_free(hba, buf_info);

	bzero(buf_info, sizeof (MBUF_INFO));
	buf_info->size = sizeof (MATCHMAP);
	buf_info->virt = (void *)mp;
	emlxs_mem_free(hba, buf_info);

	return;

} /* emlxs_mem_buf_free() */


extern void *
emlxs_mem_get(emlxs_hba_t *hba, uint32_t seg_id, uint32_t priority)
{
	emlxs_port_t	*port = &PPORT;
	void		*bp;
	MAILBOXQ	*mbq;
	IOCBQ		*iocbq;
	NODELIST	*node;
	MEMSEG		*seg;

	if (seg_id >= FC_MAX_SEG) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_error_msg,
		    "emlxs_mem_get: Invalid segment id = %d",
		    seg_id);

		return (NULL);
	}
	seg = &hba->memseg[seg_id];

	/* Alloc a buffer from the pool */
	bp = emlxs_mem_pool_get(hba, seg, priority);

	if (bp) {
		switch (seg_id) {
		case MEM_MBOX:
			mbq = (MAILBOXQ *)bp;
			mbq->flag |= MBQ_POOL_ALLOCATED;
			break;

		case MEM_IOCB:
			iocbq = (IOCBQ *)bp;
			iocbq->flag |= IOCB_POOL_ALLOCATED;
			break;

		case MEM_NLP:
			node = (NODELIST *)bp;
			node->flag |= NODE_POOL_ALLOCATED;
			break;
		}
	}

	return (bp);

} /* emlxs_mem_get() */


extern void
emlxs_mem_put(emlxs_hba_t *hba, uint32_t seg_id, void *bp)
{
	emlxs_port_t	*port = &PPORT;
	MAILBOXQ	*mbq;
	IOCBQ		*iocbq;
	NODELIST	*node;
	MEMSEG		*seg;
	MATCHMAP	*mp;

	if (seg_id >= FC_MAX_SEG) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_error_msg,
		    "emlxs_mem_put: Invalid segment id = %d: bp=%p",
		    seg_id, bp);

		return;
	}
	seg = &hba->memseg[seg_id];

	/* Verify buffer */
	switch (seg_id) {
	case MEM_MBOX:
		mbq = (MAILBOXQ *)bp;

		if (!(mbq->flag & MBQ_POOL_ALLOCATED)) {
			return;
		}
		break;

	case MEM_IOCB:
		iocbq = (IOCBQ *)bp;

		if (!(iocbq->flag & IOCB_POOL_ALLOCATED)) {
			return;
		}

		/* Any IOCBQ with a packet attached did not come */
		/* from our pool */
		if (iocbq->sbp) {
			return;
		}
		break;

	case MEM_NLP:
		node = (NODELIST *)bp;

		if (!(node->flag & NODE_POOL_ALLOCATED)) {
			return;
		}
		break;

	default:
		mp = (MATCHMAP *)bp;

		if (mp->flag & MAP_BUF_ALLOCATED) {
			emlxs_mem_buf_free(hba, mp);
			return;
		}

		if (mp->flag & MAP_TABLE_ALLOCATED) {
			return;
		}

		if (!(mp->flag & MAP_POOL_ALLOCATED)) {
			return;
		}
		break;
	}

	/* Free a buffer to the pool */
	emlxs_mem_pool_put(hba, seg, bp);

	return;

} /* emlxs_mem_put() */


/*
 * Look up the virtual address given a mapped address
 */
/* SLI3 */
extern MATCHMAP *
emlxs_mem_get_vaddr(emlxs_hba_t *hba, RING *rp, uint64_t mapbp)
{
	emlxs_port_t *port = &PPORT;
	MATCHMAP *prev;
	MATCHMAP *mp;

	if (rp->ringno == hba->channel_els) {
		mp = (MATCHMAP *)rp->fc_mpoff;
		prev = 0;

		while (mp) {
			if (mp->phys == mapbp) {
				if (prev == 0) {
					rp->fc_mpoff = mp->fc_mptr;
				} else {
					prev->fc_mptr = mp->fc_mptr;
				}

				if (rp->fc_mpon == mp) {
					rp->fc_mpon = (void *)prev;
				}

				mp->fc_mptr = NULL;

				EMLXS_MPDATA_SYNC(mp->dma_handle, 0, mp->size,
				    DDI_DMA_SYNC_FORKERNEL);

				HBASTATS.ElsUbPosted--;

				return (mp);
			}

			prev = mp;
			mp = (MATCHMAP *)mp->fc_mptr;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_error_msg,
		    "ELS Buffer not mapped: bp=%lx ringno=%x mpoff=%p mpon=%p",
		    mapbp, rp->ringno, rp->fc_mpoff, rp->fc_mpon);

	} else if (rp->ringno == hba->channel_ct) {

		mp = (MATCHMAP *)rp->fc_mpoff;
		prev = 0;

		while (mp) {
			if (mp->phys == mapbp) {
				if (prev == 0) {
					rp->fc_mpoff = mp->fc_mptr;
				} else {
					prev->fc_mptr = mp->fc_mptr;
				}

				if (rp->fc_mpon == mp) {
					rp->fc_mpon = (void *)prev;
				}

				mp->fc_mptr = NULL;

				EMLXS_MPDATA_SYNC(mp->dma_handle, 0, mp->size,
				    DDI_DMA_SYNC_FORKERNEL);

				HBASTATS.CtUbPosted--;

				return (mp);
			}

			prev = mp;
			mp = (MATCHMAP *)mp->fc_mptr;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_error_msg,
		    "CT Buffer not mapped: bp=%lx ringno=%x mpoff=%p mpon=%p",
		    mapbp, rp->ringno, rp->fc_mpoff, rp->fc_mpon);

	} else if (rp->ringno == hba->channel_ip) {

		mp = (MATCHMAP *)rp->fc_mpoff;
		prev = 0;

		while (mp) {
			if (mp->phys == mapbp) {
				if (prev == 0) {
					rp->fc_mpoff = mp->fc_mptr;
				} else {
					prev->fc_mptr = mp->fc_mptr;
				}

				if (rp->fc_mpon == mp) {
					rp->fc_mpon = (void *)prev;
				}

				mp->fc_mptr = NULL;

				EMLXS_MPDATA_SYNC(mp->dma_handle, 0, mp->size,
				    DDI_DMA_SYNC_FORKERNEL);

				HBASTATS.IpUbPosted--;

				return (mp);
			}

			prev = mp;
			mp = (MATCHMAP *)mp->fc_mptr;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_error_msg,
		    "IP Buffer not mapped: bp=%lx ringno=%x mpoff=%p mpon=%p",
		    mapbp, rp->ringno, rp->fc_mpoff, rp->fc_mpon);

#ifdef SFCT_SUPPORT
	} else if (rp->ringno == hba->CHANNEL_FCT) {
		mp = (MATCHMAP *)rp->fc_mpoff;
		prev = 0;

		while (mp) {
			if (mp->phys == mapbp) {
				if (prev == 0) {
					rp->fc_mpoff = mp->fc_mptr;
				} else {
					prev->fc_mptr = mp->fc_mptr;
				}

				if (rp->fc_mpon == mp) {
					rp->fc_mpon = (void *)prev;
				}

				mp->fc_mptr = NULL;

				EMLXS_MPDATA_SYNC(mp->dma_handle, 0, mp->size,
				    DDI_DMA_SYNC_FORKERNEL);

				HBASTATS.FctUbPosted--;

				return (mp);
			}

			prev = mp;
			mp = (MATCHMAP *)mp->fc_mptr;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_error_msg,
		    "FCT Buffer not mapped: bp=%lx ringno=%x mpoff=%p mpon=%p",
		    mapbp, rp->ringno, rp->fc_mpoff, rp->fc_mpon);

#endif /* SFCT_SUPPORT */
	}

	return (0);

} /* emlxs_mem_get_vaddr() */


/*
 * Given a virtual address bp, generate the physical mapped address and
 * place it where addr points to. Save the address pair for lookup later.
 */
/* SLI3 */
extern void
emlxs_mem_map_vaddr(emlxs_hba_t *hba, RING *rp, MATCHMAP *mp,
    uint32_t *haddr, uint32_t *laddr)
{
	if (rp->ringno == hba->channel_els) {
		/*
		 * Update slot fc_mpon points to then bump it
		 * fc_mpoff is pointer head of the list.
		 * fc_mpon is pointer tail of the list.
		 */
		mp->fc_mptr = NULL;
		if (rp->fc_mpoff == 0) {
			rp->fc_mpoff = (void *)mp;
			rp->fc_mpon = (void *)mp;
		} else {
			((MATCHMAP *)(rp->fc_mpon))->fc_mptr =
			    (void *)mp;
			rp->fc_mpon = (void *)mp;
		}

		if (hba->flag & FC_SLIM2_MODE) {

			/* return mapped address */
			*haddr = PADDR_HI(mp->phys);
			/* return mapped address */
			*laddr = PADDR_LO(mp->phys);
		} else {
			/* return mapped address */
			*laddr = PADDR_LO(mp->phys);
		}

		HBASTATS.ElsUbPosted++;

	} else if (rp->ringno == hba->channel_ct) {
		/*
		 * Update slot fc_mpon points to then bump it
		 * fc_mpoff is pointer head of the list.
		 * fc_mpon is pointer tail of the list.
		 */
		mp->fc_mptr = NULL;
		if (rp->fc_mpoff == 0) {
			rp->fc_mpoff = (void *)mp;
			rp->fc_mpon = (void *)mp;
		} else {
			((MATCHMAP *)(rp->fc_mpon))->fc_mptr =
			    (void *)mp;
			rp->fc_mpon = (void *)mp;
		}

		if (hba->flag & FC_SLIM2_MODE) {
			/* return mapped address */
			*haddr = PADDR_HI(mp->phys);
			/* return mapped address */
			*laddr = PADDR_LO(mp->phys);
		} else {
			/* return mapped address */
			*laddr = PADDR_LO(mp->phys);
		}

		HBASTATS.CtUbPosted++;


	} else if (rp->ringno == hba->channel_ip) {
		/*
		 * Update slot fc_mpon points to then bump it
		 * fc_mpoff is pointer head of the list.
		 * fc_mpon is pointer tail of the list.
		 */
		mp->fc_mptr = NULL;
		if (rp->fc_mpoff == 0) {
			rp->fc_mpoff = (void *)mp;
			rp->fc_mpon = (void *)mp;
		} else {
			((MATCHMAP *)(rp->fc_mpon))->fc_mptr =
			    (void *)mp;
			rp->fc_mpon = (void *)mp;
		}

		if (hba->flag & FC_SLIM2_MODE) {
			/* return mapped address */
			*haddr = PADDR_HI(mp->phys);
			*laddr = PADDR_LO(mp->phys);
		} else {
			*laddr = PADDR_LO(mp->phys);
		}

		HBASTATS.IpUbPosted++;


#ifdef SFCT_SUPPORT
	} else if (rp->ringno == hba->CHANNEL_FCT) {
		/*
		 * Update slot fc_mpon points to then bump it
		 * fc_mpoff is pointer head of the list.
		 * fc_mpon is pointer tail of the list.
		 */
		mp->fc_mptr = NULL;
		if (rp->fc_mpoff == 0) {
			rp->fc_mpoff = (void *)mp;
			rp->fc_mpon = (void *)mp;
		} else {
			((MATCHMAP *)(rp->fc_mpon))->fc_mptr =
			    (void *)mp;
			rp->fc_mpon = (void *)mp;
		}

		if (hba->flag & FC_SLIM2_MODE) {
			/* return mapped address */
			*haddr = PADDR_HI(mp->phys);
			/* return mapped address */
			*laddr = PADDR_LO(mp->phys);
		} else {
			/* return mapped address */
			*laddr = PADDR_LO(mp->phys);
		}

		HBASTATS.FctUbPosted++;

#endif /* SFCT_SUPPORT */
	}
} /* emlxs_mem_map_vaddr() */


/* SLI3 */
uint32_t
emlxs_hbq_alloc(emlxs_hba_t *hba, uint32_t hbq_id)
{
	emlxs_port_t *port = &PPORT;
	HBQ_INIT_t *hbq;
	MBUF_INFO *buf_info;
	MBUF_INFO bufinfo;

	hbq = &hba->sli.sli3.hbq_table[hbq_id];

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

		hbq->HBQ_host_buf.virt = buf_info->virt;
		hbq->HBQ_host_buf.phys = buf_info->phys;
		hbq->HBQ_host_buf.data_handle = buf_info->data_handle;
		hbq->HBQ_host_buf.dma_handle = buf_info->dma_handle;
		hbq->HBQ_host_buf.size = buf_info->size;
		hbq->HBQ_host_buf.tag = hbq_id;

		bzero((char *)hbq->HBQ_host_buf.virt, buf_info->size);
	}

	return (0);

} /* emlxs_hbq_alloc() */
