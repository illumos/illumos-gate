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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/note.h>

/*
 * Generic SCSI Host Bus Adapter interface implementation
 */

#include <sys/dada/dada.h>

extern int dcd_options;

static kmutex_t	dcd_hba_mutex;

kmutex_t	dcd_log_mutex;

struct dcd_hba_inst {
	dev_info_t	*inst_dip;
	dcd_hba_tran_t	*inst_hba_tran;
	struct dcd_hba_inst	*inst_next;
	struct	dcd_hba_inst	*inst_prev;
};

static struct dcd_hba_inst	*dcd_hba_list	= NULL;
static struct dcd_hba_inst	*dcd_hba_list_tail = NULL;


_NOTE(READ_ONLY_DATA(dev_ops))

kmutex_t	dcd_flag_nointr_mutex;
kcondvar_t	dcd_flag_nointr_cv;


/*
 * Called from _init when loading the dcd module.
 */
void
dcd_initialize_hba_interface()
{
	mutex_init(&dcd_hba_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&dcd_flag_nointr_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&dcd_flag_nointr_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&dcd_log_mutex, NULL, MUTEX_DRIVER, NULL);
}

/*
 * Called from fini() when unloading the dcd module.
 */

void
dcd_uninitialize_hba_interface()
{
	mutex_destroy(&dcd_hba_mutex);
	cv_destroy(&dcd_flag_nointr_cv);
	mutex_destroy(&dcd_flag_nointr_mutex);
	mutex_destroy(&dcd_log_mutex);
}


/*
 * Called by an HBA from _init()
 */
/* ARGSUSED */
int
dcd_hba_init(struct modlinkage *modlp)
{

	return (0);
}



#ifdef NOTNEEDED
/* ARGSUSED */
int
dcd_hba_attach(dev_info_t *dip,
	ddi_dma_lim_t	*hba_lim,
	dcd_hba_tran_t	*hba_tran,
	int		flags,
	void		*hba_options)
{

	ddi_dma_attr_t		hba_dma_attr;

	bzero(&hba_dma_attr, sizeof (ddi_dma_attr_t));

	hba_dma_attr.dma_attr_burstsizes = hba_lim->dlim_burstsizes;
	hba_dma_attr.dma_attr_minxfer = hba_lim->dlim_minxfer;

	return (dcd_hba_attach_setup(dip, &hba_dma_attr, hba_tran, flags));
}
#endif


int
dcd_hba_attach(
	dev_info_t	*dip,
	ddi_dma_attr_t	*hba_dma_attr,
	dcd_hba_tran_t	*hba_tran,
	int		flags)
{

	struct dcd_hba_inst	*elem;
	int			value;
	int			len;
	char			*prop_name;
	char			*errmsg =
	    "dcd_hba_attach: cannott create property '%s' for %s%d\n";

	/*
	 * Link this instance into the list
	 */
	elem = kmem_alloc(sizeof (struct dcd_hba_inst), KM_SLEEP);

	elem->inst_dip = dip;
	elem->inst_hba_tran = hba_tran;

	mutex_enter(&dcd_hba_mutex);
	elem->inst_next = NULL;
	elem->inst_prev = dcd_hba_list_tail;

	if (dcd_hba_list == NULL) {
		dcd_hba_list = elem;
	}
	if (dcd_hba_list_tail) {
		dcd_hba_list_tail->inst_next = elem;
	}
	dcd_hba_list_tail = elem;
	mutex_exit(&dcd_hba_mutex);


	/*
	 * Save all the improtant HBA information that must be accessed
	 * later.
	 */

	hba_tran->tran_hba_dip = dip;
	hba_tran->tran_hba_flags = flags;

	/*
	 * Note: We only need dma_attr_minxfer and dma_attr_burstsize
	 * from the DMA atrributes
	 */

	hba_tran->tran_min_xfer = hba_dma_attr->dma_attr_minxfer;
	hba_tran->tran_min_burst_size =
	    (1<<(ddi_ffs(hba_dma_attr->dma_attr_burstsizes)-1));
	hba_tran->tran_max_burst_size =
	    (1<<(ddi_fls(hba_dma_attr->dma_attr_burstsizes)-1));



	prop_name = "dcd_options";
	len = 0;
	if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN, 0, prop_name,
	    NULL, &len) == DDI_PROP_NOT_FOUND) {
		value = dcd_options;
		if (ddi_prop_update_int(DDI_MAJOR_T_UNKNOWN, dip,
		    prop_name, value) != DDI_PROP_SUCCESS) {
			cmn_err(CE_CONT, errmsg, prop_name,
			    ddi_get_name(dip), ddi_get_instance(dip));
		}
	}


	/*
	 * XXX : This needs to be removed when code cleanup
	 * ddi_set_driver_private(dip, (caddr_t)hba_tran);
	 */
#ifdef DEBUG1
	printf("Called Set driver private with dip %x, tran %x\n",
	    dip, hba_tran);
#endif

	return (DDI_SUCCESS);
}


/*
 * called by an HBA to detach an instance of the driver
 */

int
dcd_hba_detach(dev_info_t *dip)
{

	dcd_hba_tran_t	*hba;
	struct dcd_hba_inst 	*elem;

	hba = ddi_get_driver_private(dip);
	ddi_set_driver_private(dip, NULL);
	ASSERT(hba != NULL);

	hba->tran_hba_dip = (dev_info_t *)NULL;
	hba->tran_hba_flags = 0;
	hba->tran_min_burst_size = (uchar_t)0;
	hba->tran_max_burst_size = (uchar_t)0;


	/*
	 * Remove HBA instance from dcd_hba_list
	 */

	mutex_enter(&dcd_hba_mutex);

	for (elem = dcd_hba_list; elem != (struct dcd_hba_inst *)NULL;
	    elem = elem->inst_next) {
		if (elem->inst_dip == dip)
			break;
	}

	if (elem == (struct dcd_hba_inst *)NULL) {
		cmn_err(CE_NOTE, "dcd_hba_attach: Unknown HBA instance\n");
		mutex_exit(&dcd_hba_mutex);
	}

	if (elem == dcd_hba_list) {
		dcd_hba_list = elem->inst_next;
		dcd_hba_list->inst_prev = (struct dcd_hba_inst *)NULL;
	} else if (elem == dcd_hba_list_tail) {
		dcd_hba_list_tail = elem->inst_prev;
		dcd_hba_list_tail->inst_next = (struct dcd_hba_inst *)NULL;
	} else {
		elem->inst_prev->inst_next = elem->inst_next;
		elem->inst_next->inst_prev = elem->inst_prev;
	}
	mutex_exit(&dcd_hba_mutex);

	kmem_free(elem, sizeof (struct dcd_hba_inst));

	return (DDI_SUCCESS);
}

void
dcd_hba_fini()
{

}

/* ARGSUSED */
dcd_hba_tran_t *
dcd_hba_tran_alloc(
	dev_info_t	*dip,
	int		flags)
{

	return (kmem_zalloc(sizeof (dcd_hba_tran_t),
	    (flags & DCD_HBA_CANSLEEP) ? KM_SLEEP: KM_NOSLEEP));
}


void
dcd_hba_tran_free(dcd_hba_tran_t	*hba_tran)
{

	kmem_free(hba_tran, sizeof (dcd_hba_tran_t));
}


/*
 * XXX: Do we really need the following routines.
 */

/*
 * private wrapper for dcd_pkt's allocated via scsi_hba_pkt_alloc
 */

struct dcd_pkt_wrapper {
	struct dcd_pkt	dcd_pkt;
	int		pkt_wrapper_len;
};

_NOTE(SCHEME_PROTECTS_DATA("unique per thread", dcd_pkt_wrapper))

/*
 * Round up all allocations so that we can gurentee
 * long-long alignment. This is the same alignment
 * provided by kmem_alloc().
 */

#define	ROUNDUP(x)	(((x) + 0x07) & ~0x07)

/*
 * Called by an HBA to allocate a dcd_pkt
 */

/* ARGSUSED */
struct dcd_pkt *
dcd_hba_pkt_alloc(
	struct dcd_address	*ap,
	int			cmdlen,
	int			statuslen,
	int			tgtlen,
	int			hbalen,
	int			(*callback)(caddr_t arg),
	caddr_t			arg)
{

	struct dcd_pkt	*pkt;
	struct dcd_pkt_wrapper	*hba_pkt;
	caddr_t		p;
	int		pktlen;


	/*
	 * Sanity check
	 */
	if (callback != SLEEP_FUNC && callback != NULL_FUNC) {
		cmn_err(CE_PANIC, " dcd_hba_pkt_alloc: callback must be"
		    " either SLEEP or NULL\n");
	}


	/*
	 * Round up so everything gets allocated on long-word boundaries.
	 */

	cmdlen = ROUNDUP(cmdlen);
	tgtlen = ROUNDUP(tgtlen);
	hbalen = ROUNDUP(hbalen);
	statuslen = ROUNDUP(statuslen);
	pktlen = sizeof (struct dcd_pkt_wrapper) +
	    cmdlen + tgtlen +hbalen + statuslen;

	hba_pkt = kmem_zalloc(pktlen,
	    (callback = SLEEP_FUNC) ? KM_SLEEP: KM_NOSLEEP);

	if (hba_pkt == NULL) {
		ASSERT(callback == NULL_FUNC);
		return (NULL);
	}

	/*
	 * Set up or private info on this pkt
	 */
	hba_pkt->pkt_wrapper_len = pktlen;
	pkt = &hba_pkt->dcd_pkt;
	p = (caddr_t)(hba_pkt + 1);

	/*
	 * set up pointers to private data areas, cdb and status.
	 */
	if (hbalen > 0) {
		pkt->pkt_ha_private = (ataopaque_t)p;
		p += hbalen;
	}

	if (tgtlen > 0) {
		pkt->pkt_private = (ataopaque_t)p;
		p += tgtlen;
	}

	if (statuslen > 0) {
		pkt->pkt_scbp = (uchar_t *)p;
		p += statuslen;
	}

	if (cmdlen > 0) {
		pkt->pkt_cdbp = (void *)p;
	}

	/*
	 * Initialize the pkt's dcd_address
	 */
	pkt->pkt_address = *ap;
#ifdef DEBUG1
	printf("da_target %x, da_lun %x, a_hba_tran %x\n",
	    pkt->pkt_address.da_target, pkt->pkt_address.da_lun,
	    pkt->pkt_address.a_hba_tran);
	printf("From address : da_target %x, da_lun %x, a_hba_tran %x\n",
	    ap->da_target, ap->da_lun, ap->a_hba_tran);
	printf("Pkt %x\n", pkt);

#endif
	return (pkt);
}


/* ARGSUSED */
void
dcd_hba_pkt_free(
	struct dcd_address *ap,
	struct dcd_pkt	   *pkt)
{

	kmem_free((struct dcd_pkt_wrapper *)pkt,
	    ((struct dcd_pkt_wrapper *)pkt)->pkt_wrapper_len);
}


/*
 * Called by an HBA to map strings to capability indices
 */

int
dcd_hba_lookup_capstr(char		*capstr)
{

	/*
	 * Capability strings, masking the '-' vs '_'.
	 */
	static struct cap_strings {
		char *cap_string;
		int   cap_index;
	} cap_string[] = {
		{ "dma-max",		DCD_CAP_DMA_MAX		},
		{ "dma_max",		DCD_CAP_DMA_MAX		},
		{ "ultraata",		DCD_CAP_ULTRA_ATA	},
		{ "busmaster",		DCD_CAP_BUS_MASTER	},
		{ "overlap",		DCD_CAP_OVERLAP		},
		{ "parity",		DCD_CAP_PARITY		},
		{ "sector-size",	DCD_CAP_SECTOR_SIZE	},
		{ "total-sectors",	DCD_CAP_TOTAL_SECTORS	},
		{ "geometry",		DCD_CAP_GEOMETRY	},
		{ "block-mode",		DCD_CAP_BLOCKMODE	},
		{ "block-factor",	DCD_CAP_BLOCKFACTOR	},
		{ "dma-support",		DCD_CAP_DMA_SUPPORT	},
		{ "pio-support", 	DCD_CAP_PIO_SUPPORT	},
		{ "lba-addressing",	DCD_CAP_LBA_ADDRESSING  },
		{ NULL, 0					}
	};
	struct cap_strings *cp;

	for (cp = cap_string; cp->cap_string != NULL; cp++) {
		if (strcmp(cp->cap_string, capstr) == 0) {
			return (cp->cap_index);
		}
	}

	return (-1);
}
