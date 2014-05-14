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

/* #define EMLXS_POOL_DEBUG */

EMLXS_MSG_DEF(EMLXS_MEM_C);


static uint32_t emlxs_mem_pool_alloc(emlxs_hba_t *hba, MEMSEG *seg,
			uint32_t count);
static void emlxs_mem_pool_free(emlxs_hba_t *hba, MEMSEG *seg, uint32_t count);


extern int32_t
emlxs_mem_alloc_buffer(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg;
	MBUF_INFO *buf_info;
	MEMSEG *seg;
	MBUF_INFO bufinfo;
	int32_t i;
	MATCHMAP *mp;
	MATCHMAP **bpl_table;

	buf_info = &bufinfo;
	cfg = &CFG;

	bzero(hba->memseg, sizeof (hba->memseg));

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

	/* Prepare the memory pools */
	for (i = 0; i < FC_MAX_SEG; i++) {
		seg = &hba->memseg[i];

		switch (i) {
		case MEM_NLP:
			(void) strlcpy(seg->fc_label, "Node Pool",
			    sizeof (seg->fc_label));
			seg->fc_memtag	= MEM_NLP;
			seg->fc_memsize	= sizeof (NODELIST);
			seg->fc_hi_water = hba->max_nodes + 2;
			seg->fc_lo_water = 2;
			seg->fc_step = 1;
			break;

		case MEM_IOCB:
			(void) strlcpy(seg->fc_label, "IOCB Pool",
			    sizeof (seg->fc_label));
			seg->fc_memtag	= MEM_IOCB;
			seg->fc_memsize	= sizeof (IOCBQ);
			seg->fc_hi_water = cfg[CFG_NUM_IOCBS].current;
			seg->fc_lo_water = cfg[CFG_NUM_IOCBS].low;
			seg->fc_step = cfg[CFG_NUM_IOCBS].low;
			break;

		case MEM_MBOX:
			(void) strlcpy(seg->fc_label, "MBOX Pool",
			    sizeof (seg->fc_label));
			seg->fc_memtag	= MEM_MBOX;
			seg->fc_memsize	= sizeof (MAILBOXQ);
			seg->fc_hi_water = hba->max_nodes + 32;
			seg->fc_lo_water = 32;
			seg->fc_step = 1;
			break;

		case MEM_BPL:
			if (hba->model_info.sli_mask & EMLXS_SLI4_MASK) {
				continue;
			}
			(void) strlcpy(seg->fc_label, "BPL Pool",
			    sizeof (seg->fc_label));
			seg->fc_memtag	= MEM_BPL;
			seg->fc_memsize	= hba->sli.sli3.mem_bpl_size;
			seg->fc_memflag	= FC_MBUF_DMA | FC_MBUF_SNGLSG;
			seg->fc_memalign = 32;
			seg->fc_hi_water = hba->max_iotag;
			seg->fc_lo_water = cfg[CFG_NUM_IOCBS].low;
			seg->fc_step = cfg[CFG_NUM_IOCBS].low;
			break;

		case MEM_BUF:
			/* These are the unsolicited ELS buffers. */
			(void) strlcpy(seg->fc_label, "BUF Pool",
			    sizeof (seg->fc_label));
			seg->fc_memtag	= MEM_BUF;
			seg->fc_memsize	= MEM_BUF_SIZE;
			seg->fc_memflag	= FC_MBUF_DMA | FC_MBUF_SNGLSG;
			seg->fc_memalign = 32;
			seg->fc_hi_water = MEM_ELSBUF_COUNT + MEM_BUF_COUNT;
			seg->fc_lo_water = MEM_ELSBUF_COUNT;
			seg->fc_step = 1;
			break;

		case MEM_IPBUF:
			/* These are the unsolicited IP buffers. */
			if (cfg[CFG_NETWORK_ON].current == 0) {
				continue;
			}

			(void) strlcpy(seg->fc_label, "IPBUF Pool",
			    sizeof (seg->fc_label));
			seg->fc_memtag	= MEM_IPBUF;
			seg->fc_memsize	= MEM_IPBUF_SIZE;
			seg->fc_memflag	= FC_MBUF_DMA | FC_MBUF_SNGLSG;
			seg->fc_memalign = 32;
			seg->fc_hi_water = MEM_IPBUF_COUNT;
			seg->fc_lo_water = 0;
			seg->fc_step = 4;
			break;

		case MEM_CTBUF:
			/* These are the unsolicited CT buffers. */
			(void) strlcpy(seg->fc_label, "CTBUF Pool",
			    sizeof (seg->fc_label));
			seg->fc_memtag	= MEM_CTBUF;
			seg->fc_memsize	= MEM_CTBUF_SIZE;
			seg->fc_memflag	= FC_MBUF_DMA | FC_MBUF_SNGLSG;
			seg->fc_memalign = 32;
			seg->fc_hi_water = MEM_CTBUF_COUNT;
			seg->fc_lo_water = MEM_CTBUF_COUNT;
			seg->fc_step = 1;
			break;

#ifdef SFCT_SUPPORT
		case MEM_FCTBUF:
			/* These are the unsolicited FCT buffers. */
			if (!(port->flag & EMLXS_TGT_ENABLED)) {
				continue;
			}

			(void) strlcpy(seg->fc_label, "FCTBUF Pool",
			    sizeof (seg->fc_label));
			seg->fc_memtag	= MEM_FCTBUF;
			seg->fc_memsize	= MEM_FCTBUF_SIZE;
			seg->fc_memflag	= FC_MBUF_DMA | FC_MBUF_SNGLSG;
			seg->fc_memalign = 32;
			seg->fc_hi_water = MEM_FCTBUF_COUNT;
			seg->fc_lo_water = 0;
			seg->fc_step = 8;
			break;
#endif /* SFCT_SUPPORT */

		default:
			continue;
		}

		if (seg->fc_memsize == 0) {
			continue;
		}

		(void) emlxs_mem_pool_create(hba, seg);

		if (seg->fc_numblks < seg->fc_lo_water) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "%s: count=%d size=%d flags=%x lo=%d hi=%d",
			    seg->fc_label, seg->fc_numblks,
			    seg->fc_memsize, seg->fc_memflag, seg->fc_lo_water,
			    seg->fc_hi_water);

			goto failed;
		}
	}

	hba->sli.sli3.bpl_table = NULL;
	seg = &hba->memseg[MEM_BPL];

	/* If SLI3 and MEM_BPL pool is static */
	if (!(hba->model_info.sli_mask & EMLXS_SLI4_MASK) &&
	    !(seg->fc_memflag & FC_MEMSEG_DYNAMIC)) {
		/*
		 * Allocate and Initialize bpl_table
		 * This is for increased performance.
		 */
		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = hba->max_iotag * sizeof (MATCHMAP *);

		(void) emlxs_mem_alloc(hba, buf_info);
		if (buf_info->virt == NULL) {

			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_mem_alloc_failed_msg,
			    "BPL table buffer.");

			goto failed;
		}
		hba->sli.sli3.bpl_table = buf_info->virt;

		bpl_table = (MATCHMAP**)hba->sli.sli3.bpl_table;
		for (i = 0; i < hba->max_iotag; i++) {
			mp = (MATCHMAP *) emlxs_mem_get(hba, MEM_BPL);
			mp->flag |= MAP_TABLE_ALLOCATED;
			bpl_table[i] = mp;
		}
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
	emlxs_port_t *port = &PPORT;
	emlxs_port_t *vport;
	int32_t j;
	MATCHMAP *mp;
	CHANNEL *cp;
	RING *rp;
	MBUF_INFO *buf_info;
	MBUF_INFO bufinfo;
	MATCHMAP **bpl_table;

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

		if (port->flag & EMLXS_TGT_ENABLED) {
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

	if (hba->fc_table) {
		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = hba->max_iotag * sizeof (emlxs_buf_t *);
		buf_info->virt = hba->fc_table;
		emlxs_mem_free(hba, buf_info);
		hba->fc_table = NULL;
	}

	if (hba->sli.sli3.bpl_table) {
		/* Return MEM_BPLs to their pool */
		bpl_table = (MATCHMAP**)hba->sli.sli3.bpl_table;
		for (j = 0; j < hba->max_iotag; j++) {
			mp = bpl_table[j];
			mp->flag &= ~MAP_TABLE_ALLOCATED;
			emlxs_mem_put(hba, MEM_BPL, (void*)mp);
		}

		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = hba->max_iotag * sizeof (MATCHMAP *);
		buf_info->virt = hba->sli.sli3.bpl_table;
		emlxs_mem_free(hba, buf_info);
		hba->sli.sli3.bpl_table = NULL;
	}

	/* Free the memory segments */
	for (j = 0; j < FC_MAX_SEG; j++) {
		emlxs_mem_pool_destroy(hba, &hba->memseg[j]);
	}

	return (0);

} /* emlxs_mem_free_buffer() */


/* Must hold EMLXS_MEMGET_LOCK when calling */
static uint32_t
emlxs_mem_pool_alloc(emlxs_hba_t *hba, MEMSEG *seg, uint32_t count)
{
	emlxs_port_t *port = &PPORT;
	uint8_t *bp = NULL;
	MATCHMAP *mp = NULL;
	MBUF_INFO *buf_info;
	MBUF_INFO local_buf_info;
	uint32_t i;
	uint32_t fc_numblks;

	if (seg->fc_memsize == 0) {
		return (0);
	}

	if (seg->fc_numblks >= seg->fc_hi_water) {
		return (0);
	}

	if (count == 0) {
		return (0);
	}

	if (count > (seg->fc_hi_water - seg->fc_numblks)) {
		count = (seg->fc_hi_water - seg->fc_numblks);
	}

	buf_info = &local_buf_info;
	fc_numblks = seg->fc_numblks;

	/* Check for initial allocation */
	if (!(seg->fc_memflag & FC_MEMSEG_PUT_ENABLED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_detail_msg,
		    "%s alloc:%d n=%d s=%d f=%x l=%d,%d,%d "
		    "f=%d:%d",
		    seg->fc_label, count, seg->fc_numblks,
		    seg->fc_memsize, seg->fc_memflag, seg->fc_lo_water,
		    seg->fc_hi_water, seg->fc_step, seg->fc_memget_cnt,
		    seg->fc_low);
	}

	if (!(seg->fc_memflag & FC_MBUF_DMA)) {
		goto vmem_pool;
	}

/* dma_pool */

	for (i = 0; i < count; i++) {
		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = sizeof (MATCHMAP);
		buf_info->align = sizeof (void *);

		(void) emlxs_mem_alloc(hba, buf_info);
		if (buf_info->virt == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "%s: count=%d size=%d",
			    seg->fc_label, seg->fc_numblks, seg->fc_memsize);

			goto done;
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
			    "%s: count=%d size=%d",
			    seg->fc_label, seg->fc_numblks, seg->fc_memsize);

			/* Free the mp object */
			bzero(buf_info, sizeof (MBUF_INFO));
			buf_info->size = sizeof (MATCHMAP);
			buf_info->virt = (void *)mp;
			emlxs_mem_free(hba, buf_info);

			goto done;
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

#ifdef SFCT_SUPPORT
		if (mp->tag >= MEM_FCTSEG) {
			if (emlxs_fct_stmf_alloc(hba, mp)) {
				/* Free the DMA memory itself */
				emlxs_mem_free(hba, buf_info);

				/* Free the mp object */
				bzero(buf_info, sizeof (MBUF_INFO));
				buf_info->size = sizeof (MATCHMAP);
				buf_info->virt = (void *)mp;
				emlxs_mem_free(hba, buf_info);

				goto done;
			}
		}
#endif /* SFCT_SUPPORT */

		/* Add the buffer desc to the tail of the pool freelist */
		if (seg->fc_memget_end == NULL) {
			seg->fc_memget_ptr = (uint8_t *)mp;
			seg->fc_memget_cnt = 1;
		} else {
			*((uint8_t **)(seg->fc_memget_end)) = (uint8_t *)mp;
			seg->fc_memget_cnt++;
		}
		seg->fc_memget_end = (uint8_t *)mp;

		seg->fc_numblks++;
		seg->fc_total_memsize += (seg->fc_memsize + sizeof (MATCHMAP));
	}

	goto done;

vmem_pool:

	for (i = 0; i < count; i++) {
		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size  = seg->fc_memsize;

		(void) emlxs_mem_alloc(hba, buf_info);
		if (buf_info->virt == NULL) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_mem_alloc_failed_msg,
			    "%s: count=%d size=%d",
			    seg->fc_label, seg->fc_numblks, seg->fc_memsize);

			goto done;
		}
		bp = (uint8_t *)buf_info->virt;

		/* Add the buffer to the tail of the pool freelist */
		if (seg->fc_memget_end == NULL) {
			seg->fc_memget_ptr = (uint8_t *)bp;
			seg->fc_memget_cnt = 1;
		} else {
			*((uint8_t **)(seg->fc_memget_end)) = (uint8_t *)bp;
			seg->fc_memget_cnt++;
		}
		seg->fc_memget_end = (uint8_t *)bp;

		seg->fc_numblks++;
		seg->fc_total_memsize += seg->fc_memsize;
	}

done:

	return ((seg->fc_numblks - fc_numblks));

} /* emlxs_mem_pool_alloc() */


/* Must hold EMLXS_MEMGET_LOCK & EMLXS_MEMPUT_LOCK when calling */
static void
emlxs_mem_pool_free(emlxs_hba_t *hba, MEMSEG *seg, uint32_t count)
{
	emlxs_port_t *port = &PPORT;
	uint8_t *bp = NULL;
	MATCHMAP *mp = NULL;
	MBUF_INFO *buf_info;
	MBUF_INFO local_buf_info;

	if ((seg->fc_memsize == 0) ||
	    (seg->fc_numblks == 0) ||
	    (count == 0)) {
		return;
	}

	/* Check max count */
	if (count > seg->fc_numblks) {
		count = seg->fc_numblks;
	}

	/* Move memput list to memget list */
	if (seg->fc_memput_ptr) {
		if (seg->fc_memget_end == NULL) {
			seg->fc_memget_ptr = seg->fc_memput_ptr;
		} else {
			*((uint8_t **)(seg->fc_memget_end)) =\
			    seg->fc_memput_ptr;
		}
		seg->fc_memget_end = seg->fc_memput_end;
		seg->fc_memget_cnt += seg->fc_memput_cnt;

		seg->fc_memput_ptr = NULL;
		seg->fc_memput_end = NULL;
		seg->fc_memput_cnt = 0;
	}

	buf_info = &local_buf_info;

	/* Check for final deallocation */
	if (!(seg->fc_memflag & FC_MEMSEG_GET_ENABLED)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_detail_msg,
		    "%s free:%d n=%d s=%d f=%x l=%d,%d,%d "
		    "f=%d:%d",
		    seg->fc_label, count, seg->fc_numblks,
		    seg->fc_memsize, seg->fc_memflag, seg->fc_lo_water,
		    seg->fc_hi_water, seg->fc_step, seg->fc_memget_cnt,
		    seg->fc_low);
	}

	if (!(seg->fc_memflag & FC_MBUF_DMA)) {
		goto vmem_pool;
	}

dma_pool:

	/* Free memory associated with all buffers on get buffer pool */
	while (count && ((bp = seg->fc_memget_ptr) != NULL)) {
		/* Remove buffer from list */
		if (seg->fc_memget_end == bp) {
			seg->fc_memget_ptr = NULL;
			seg->fc_memget_end = NULL;
			seg->fc_memget_cnt = 0;

		} else {
			seg->fc_memget_ptr = *((uint8_t **)bp);
			seg->fc_memget_cnt--;
		}
		mp = (MATCHMAP *)bp;

#ifdef SFCT_SUPPORT
		if (mp->tag >= MEM_FCTSEG) {
			emlxs_fct_stmf_free(hba, mp);
		}
#endif /* SFCT_SUPPORT */

		/* Free the DMA memory itself */
		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = mp->size;
		buf_info->virt = mp->virt;
		buf_info->phys = mp->phys;
		buf_info->dma_handle = mp->dma_handle;
		buf_info->data_handle = mp->data_handle;
		buf_info->flags = seg->fc_memflag;
		emlxs_mem_free(hba, buf_info);

		/* Free the handle */
		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = sizeof (MATCHMAP);
		buf_info->virt = (void *)mp;
		emlxs_mem_free(hba, buf_info);

		seg->fc_numblks--;
		seg->fc_total_memsize -= (seg->fc_memsize + sizeof (MATCHMAP));

		count--;
	}

	return;

vmem_pool:

	/* Free memory associated with all buffers on get buffer pool */
	while (count && ((bp = seg->fc_memget_ptr) != NULL)) {
		/* Remove buffer from list */
		if (seg->fc_memget_end == bp) {
			seg->fc_memget_ptr = NULL;
			seg->fc_memget_end = NULL;
			seg->fc_memget_cnt = 0;

		} else {
			seg->fc_memget_ptr = *((uint8_t **)bp);
			seg->fc_memget_cnt--;
		}

		/* Free the Virtual memory itself */
		bzero(buf_info, sizeof (MBUF_INFO));
		buf_info->size = seg->fc_memsize;
		buf_info->virt = bp;
		emlxs_mem_free(hba, buf_info);

		seg->fc_numblks--;
		seg->fc_total_memsize -= seg->fc_memsize;

		count--;
	}

	return;

} /* emlxs_mem_pool_free() */


extern uint32_t
emlxs_mem_pool_create(emlxs_hba_t *hba, MEMSEG *seg)
{
	emlxs_config_t *cfg = &CFG;

	mutex_enter(&EMLXS_MEMGET_LOCK);
	mutex_enter(&EMLXS_MEMPUT_LOCK);

	if (seg->fc_memsize == 0) {
		mutex_exit(&EMLXS_MEMPUT_LOCK);
		mutex_exit(&EMLXS_MEMGET_LOCK);

		return (0);
	}

	/* Sanity check hi > lo */
	if (seg->fc_lo_water > seg->fc_hi_water) {
		seg->fc_hi_water = seg->fc_lo_water;
	}

	/* If dynamic pools are disabled, then force pool to max level */
	if (cfg[CFG_MEM_DYNAMIC].current == 0) {
		seg->fc_lo_water = seg->fc_hi_water;
	}

	/* If pool is dynamic, then fc_step must be >0 */
	/* Otherwise, fc_step must be 0 */
	if (seg->fc_lo_water != seg->fc_hi_water) {
		seg->fc_memflag |= FC_MEMSEG_DYNAMIC;

		if (seg->fc_step == 0) {
			seg->fc_step = 1;
		}
	} else {
		seg->fc_step = 0;
	}

	seg->fc_numblks = 0;
	seg->fc_total_memsize = 0;
	seg->fc_low = 0;

	(void) emlxs_mem_pool_alloc(hba, seg,  seg->fc_lo_water);

	seg->fc_memflag |= (FC_MEMSEG_PUT_ENABLED|FC_MEMSEG_GET_ENABLED);

	mutex_exit(&EMLXS_MEMPUT_LOCK);
	mutex_exit(&EMLXS_MEMGET_LOCK);

	return (seg->fc_numblks);

} /* emlxs_mem_pool_create() */


extern void
emlxs_mem_pool_destroy(emlxs_hba_t *hba, MEMSEG *seg)
{
	emlxs_port_t *port = &PPORT;

	mutex_enter(&EMLXS_MEMGET_LOCK);
	mutex_enter(&EMLXS_MEMPUT_LOCK);

	if (seg->fc_memsize == 0) {
		mutex_exit(&EMLXS_MEMPUT_LOCK);
		mutex_exit(&EMLXS_MEMGET_LOCK);
		return;
	}

	/* Leave FC_MEMSEG_PUT_ENABLED set for now */
	seg->fc_memflag &= ~FC_MEMSEG_GET_ENABLED;

	/* Try to free all objects */
	emlxs_mem_pool_free(hba, seg, seg->fc_numblks);

	if (seg->fc_numblks) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_detail_msg,
		    "mem_pool_destroy: %s leak detected: "
		    "%d objects still allocated.",
		    seg->fc_label, seg->fc_numblks);
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_detail_msg,
		    "mem_pool_destroy: %s destroyed.",
		    seg->fc_label);

		/* Clear all */
		bzero(seg, sizeof (MEMSEG));
	}

	mutex_exit(&EMLXS_MEMPUT_LOCK);
	mutex_exit(&EMLXS_MEMGET_LOCK);

	return;

} /* emlxs_mem_pool_destroy() */


extern void
emlxs_mem_pool_clean(emlxs_hba_t *hba, MEMSEG *seg)
{
	emlxs_port_t *port = &PPORT;
	uint32_t clean_count;
	uint32_t free_count;
	uint32_t free_pad;

	mutex_enter(&EMLXS_MEMGET_LOCK);
	mutex_enter(&EMLXS_MEMPUT_LOCK);

	if (!(seg->fc_memflag & FC_MEMSEG_DYNAMIC)) {
		mutex_exit(&EMLXS_MEMPUT_LOCK);
		mutex_exit(&EMLXS_MEMGET_LOCK);
		return;
	}

	if (!(seg->fc_memflag & FC_MEMSEG_GET_ENABLED)) {
		goto done;
	}

#ifdef EMLXS_POOL_DEBUG
	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_detail_msg,
	    "%s clean: n=%d s=%d f=%x l=%d,%d,%d "
	    "f=%d:%d",
	    seg->fc_label, seg->fc_numblks,
	    seg->fc_memsize, seg->fc_memflag, seg->fc_lo_water,
	    seg->fc_hi_water, seg->fc_step, seg->fc_memget_cnt,
	    seg->fc_low);
#endif /* EMLXS_POOL_DEBUG */

	/* Calculatge current free count */
	free_count = (seg->fc_memget_cnt + seg->fc_memput_cnt);

	/* Reset fc_low value to current free count */
	clean_count = seg->fc_low;
	seg->fc_low = free_count;

	/* Return if pool is already at lo water mark */
	if (seg->fc_numblks <= seg->fc_lo_water) {
		goto done;
	}

	/* Return if there is nothing to clean */
	if ((free_count == 0) ||
	    (clean_count <= 1)) {
		goto done;
	}

	/* Calculate a 3 percent free pad count (1 being minimum) */
	if (seg->fc_numblks > 66) {
		free_pad = ((seg->fc_numblks * 3)/100);
	} else {
		free_pad = 1;
	}

	/* Return if fc_low is below pool free pad */
	if (clean_count <= free_pad) {
		goto done;
	}

	clean_count -= free_pad;

	/* clean_count can't exceed minimum pool levels */
	if (clean_count > (seg->fc_numblks - seg->fc_lo_water)) {
		clean_count = (seg->fc_numblks - seg->fc_lo_water);
	}

	emlxs_mem_pool_free(hba, seg, clean_count);

done:
	if (seg->fc_last != seg->fc_numblks) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_detail_msg,
		    "%s update: n=%d->%d s=%d f=%x l=%d,%d,%d "
		    "f=%d:%d",
		    seg->fc_label, seg->fc_last, seg->fc_numblks,
		    seg->fc_memsize, seg->fc_memflag, seg->fc_lo_water,
		    seg->fc_hi_water, seg->fc_step, seg->fc_memget_cnt,
		    seg->fc_low);

		seg->fc_last = seg->fc_numblks;
	}

	mutex_exit(&EMLXS_MEMPUT_LOCK);
	mutex_exit(&EMLXS_MEMGET_LOCK);
	return;

} /* emlxs_mem_pool_clean() */


extern void *
emlxs_mem_pool_get(emlxs_hba_t *hba, MEMSEG *seg)
{
	emlxs_port_t	*port = &PPORT;
	void		*bp = NULL;
	MATCHMAP	*mp;
	uint32_t	free_count;

	mutex_enter(&EMLXS_MEMGET_LOCK);

	/* Check if memory pool is GET enabled */
	if (!(seg->fc_memflag & FC_MEMSEG_GET_ENABLED)) {
		mutex_exit(&EMLXS_MEMGET_LOCK);
		return (NULL);
	}

	/* If no entries on memget list, then check memput list */
	if (!seg->fc_memget_ptr) {
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
		}
		mutex_exit(&EMLXS_MEMPUT_LOCK);
	}

	/* If no entries on memget list, then pool is empty */
	/* Try to allocate more if pool is dynamic */
	if (!seg->fc_memget_ptr &&
	    (seg->fc_memflag & FC_MEMSEG_DYNAMIC)) {
		(void) emlxs_mem_pool_alloc(hba, seg,  seg->fc_step);
		seg->fc_low = 0;
	}

	/* If no entries on memget list, then pool is empty */
	if (!seg->fc_memget_ptr) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_alloc_failed_msg,
		    "%s empty.", seg->fc_label);

		mutex_exit(&EMLXS_MEMGET_LOCK);
		return (NULL);
	}

	/* Remove an entry from the get list */
	bp = seg->fc_memget_ptr;

	if (seg->fc_memget_end == bp) {
		seg->fc_memget_ptr = NULL;
		seg->fc_memget_end = NULL;
		seg->fc_memget_cnt = 0;

	} else {
		seg->fc_memget_ptr = *((uint8_t **)bp);
		seg->fc_memget_cnt--;
	}

	/* Initialize buffer */
	if (!(seg->fc_memflag & FC_MBUF_DMA)) {
		bzero(bp, seg->fc_memsize);
	} else {
		mp = (MATCHMAP *)bp;
		mp->fc_mptr = NULL;
		mp->flag |= MAP_POOL_ALLOCATED;
	}

	/* Set fc_low if pool is dynamic */
	if (seg->fc_memflag & FC_MEMSEG_DYNAMIC) {
		free_count = (seg->fc_memget_cnt + seg->fc_memput_cnt);
		if (free_count < seg->fc_low) {
			seg->fc_low = free_count;
		}
	}

	mutex_exit(&EMLXS_MEMGET_LOCK);

	return (bp);

} /* emlxs_mem_pool_get() */


extern void
emlxs_mem_pool_put(emlxs_hba_t *hba, MEMSEG *seg, void *bp)
{
	emlxs_port_t	*port = &PPORT;
	MATCHMAP	*mp;

	/* Free the pool object */
	mutex_enter(&EMLXS_MEMPUT_LOCK);

	/* Check if memory pool is PUT enabled */
	if (!(seg->fc_memflag & FC_MEMSEG_PUT_ENABLED)) {
		mutex_exit(&EMLXS_MEMPUT_LOCK);
		return;
	}

	/* Check if buffer was just freed */
	if ((seg->fc_memput_end == bp) || (seg->fc_memget_end == bp)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_error_msg,
		    "%s: Freeing free object: bp=%p", seg->fc_label, bp);

		mutex_exit(&EMLXS_MEMPUT_LOCK);
		return;
	}

	/* Validate DMA buffer */
	if (seg->fc_memflag & FC_MBUF_DMA) {
		mp = (MATCHMAP *)bp;

		if (!(mp->flag & MAP_POOL_ALLOCATED) ||
		    (mp->segment != seg)) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_error_msg,
			    "mem_pool_put: %s invalid: mp=%p " \
			    "tag=0x%x flag=%x", seg->fc_label,
			    mp, mp->tag, mp->flag);

			EMLXS_STATE_CHANGE(hba, FC_ERROR);

			mutex_exit(&EMLXS_MEMPUT_LOCK);

			emlxs_thread_spawn(hba, emlxs_shutdown_thread,
			    NULL, NULL);

			return;
		}
	}

	/* Release buffer to the end of the memput list */
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

	/* This is for late PUT's after an initial */
	/* emlxs_mem_pool_destroy call */
	if ((seg->fc_memflag & FC_MEMSEG_PUT_ENABLED) &&
	    !(seg->fc_memflag & FC_MEMSEG_GET_ENABLED)) {
		emlxs_mem_pool_destroy(hba, seg);
	}

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
	bzero(bp, buf_info->size);

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
emlxs_mem_get(emlxs_hba_t *hba, uint32_t seg_id)
{
	emlxs_port_t	*port = &PPORT;
	void		*bp;
	MAILBOXQ	*mbq;
	IOCBQ		*iocbq;
	NODELIST	*node;
	MEMSEG		*seg;

	if (seg_id >= FC_MAX_SEG) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pool_error_msg,
		    "mem_get: Invalid segment id = %d",
		    seg_id);

		return (NULL);
	}
	seg = &hba->memseg[seg_id];

	/* Alloc a buffer from the pool */
	bp = emlxs_mem_pool_get(hba, seg);

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
		    "mem_put: Invalid segment id = %d: bp=%p",
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
