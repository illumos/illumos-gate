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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/note.h>

/*
 * Generic SCSI Host Bus Adapter interface implementation
 */
#include <sys/scsi/scsi.h>
#include <sys/file.h>
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/ddi.h>
#include <sys/epm.h>

extern struct scsi_pkt *scsi_init_cache_pkt(struct scsi_address *,
		    struct scsi_pkt *, struct buf *, int, int, int, int,
		    int (*)(caddr_t), caddr_t);
extern void scsi_free_cache_pkt(struct scsi_address *,
		    struct scsi_pkt *);
extern void scsi_cache_dmafree(struct scsi_address *,
		    struct scsi_pkt *);
extern void scsi_sync_cache_pkt(struct scsi_address *,
		    struct scsi_pkt *);

/*
 * Round up all allocations so that we can guarantee
 * long-long alignment.  This is the same alignment
 * provided by kmem_alloc().
 */
#define	ROUNDUP(x)	(((x) + 0x07) & ~0x07)

/* Magic number to track correct allocations in wrappers */
#define	PKT_WRAPPER_MAGIC	0xa110ced	/* alloced correctly */

static kmutex_t	scsi_hba_mutex;

kmutex_t scsi_log_mutex;


struct scsi_hba_inst {
	dev_info_t		*inst_dip;
	scsi_hba_tran_t		*inst_hba_tran;
	struct scsi_hba_inst	*inst_next;
	struct scsi_hba_inst	*inst_prev;
};

static struct scsi_hba_inst	*scsi_hba_list		= NULL;
static struct scsi_hba_inst	*scsi_hba_list_tail	= NULL;


kmutex_t	scsi_flag_nointr_mutex;
kcondvar_t	scsi_flag_nointr_cv;

/*
 * Prototypes for static functions
 */
static int	scsi_hba_bus_ctl(
			dev_info_t		*dip,
			dev_info_t		*rdip,
			ddi_ctl_enum_t		op,
			void			*arg,
			void			*result);

static int	scsi_hba_map_fault(
			dev_info_t		*dip,
			dev_info_t		*rdip,
			struct hat		*hat,
			struct seg		*seg,
			caddr_t			addr,
			struct devpage		*dp,
			pfn_t			pfn,
			uint_t			prot,
			uint_t			lock);

static int	scsi_hba_get_eventcookie(
			dev_info_t		*dip,
			dev_info_t		*rdip,
			char			*name,
			ddi_eventcookie_t	*eventp);

static int	scsi_hba_add_eventcall(
			dev_info_t		*dip,
			dev_info_t		*rdip,
			ddi_eventcookie_t	event,
			void			(*callback)(
					dev_info_t *dip,
					ddi_eventcookie_t event,
					void *arg,
					void *bus_impldata),
			void			*arg,
			ddi_callback_id_t	*cb_id);

static int	scsi_hba_remove_eventcall(
			dev_info_t *devi,
			ddi_callback_id_t id);

static int	scsi_hba_post_event(
			dev_info_t		*dip,
			dev_info_t		*rdip,
			ddi_eventcookie_t	event,
			void			*bus_impldata);

static int	scsi_hba_info(
			dev_info_t		*dip,
			ddi_info_cmd_t		infocmd,
			void			*arg,
			void			**result);

static int scsi_hba_bus_config(dev_info_t *parent, uint_t flag,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp);
static int scsi_hba_bus_unconfig(dev_info_t *parent, uint_t flag,
    ddi_bus_config_op_t op, void *arg);
static int scsi_hba_fm_init_child(dev_info_t *self, dev_info_t *child,
    int cap, ddi_iblock_cookie_t *ibc);
static int scsi_hba_bus_power(dev_info_t *parent, void *impl_arg,
    pm_bus_power_op_t op, void *arg, void *result);

/*
 * Busops vector for SCSI HBA's.
 */
static struct bus_ops scsi_hba_busops = {
	BUSO_REV,
	nullbusmap,			/* bus_map */
	NULL,				/* bus_get_intrspec */
	NULL,				/* bus_add_intrspec */
	NULL,				/* bus_remove_intrspec */
	scsi_hba_map_fault,		/* bus_map_fault */
	ddi_dma_map,			/* bus_dma_map */
	ddi_dma_allochdl,		/* bus_dma_allochdl */
	ddi_dma_freehdl,		/* bus_dma_freehdl */
	ddi_dma_bindhdl,		/* bus_dma_bindhdl */
	ddi_dma_unbindhdl,		/* bus_unbindhdl */
	ddi_dma_flush,			/* bus_dma_flush */
	ddi_dma_win,			/* bus_dma_win */
	ddi_dma_mctl,			/* bus_dma_ctl */
	scsi_hba_bus_ctl,		/* bus_ctl */
	ddi_bus_prop_op,		/* bus_prop_op */
	scsi_hba_get_eventcookie,	/* bus_get_eventcookie */
	scsi_hba_add_eventcall,		/* bus_add_eventcall */
	scsi_hba_remove_eventcall,	/* bus_remove_eventcall */
	scsi_hba_post_event,		/* bus_post_event */
	NULL,				/* bus_intr_ctl */
	scsi_hba_bus_config,		/* bus_config */
	scsi_hba_bus_unconfig,		/* bus_unconfig */
	scsi_hba_fm_init_child,		/* bus_fm_init */
	NULL,				/* bus_fm_fini */
	NULL,				/* bus_fm_access_enter */
	NULL,				/* bus_fm_access_exit */
	scsi_hba_bus_power		/* bus_power */
};


static struct cb_ops scsi_hba_cbops = {
	scsi_hba_open,
	scsi_hba_close,
	nodev,			/* strategy */
	nodev,			/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	scsi_hba_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* prop_op */
	NULL,			/* stream */
	D_NEW|D_MP|D_HOTPLUG,	/* cb_flag */
	CB_REV,			/* rev */
	nodev,			/* int (*cb_aread)() */
	nodev			/* int (*cb_awrite)() */
};


/*
 * Called from _init() when loading scsi module
 */
void
scsi_initialize_hba_interface()
{
	mutex_init(&scsi_hba_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&scsi_flag_nointr_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&scsi_flag_nointr_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&scsi_log_mutex, NULL, MUTEX_DRIVER, NULL);
}

#ifdef	NO_SCSI_FINI_YET
/*
 * Called from _fini() when unloading scsi module
 */
void
scsi_uninitialize_hba_interface()
{
	mutex_destroy(&scsi_hba_mutex);
	cv_destroy(&scsi_flag_nointr_cv);
	mutex_destroy(&scsi_flag_nointr_mutex);
	mutex_destroy(&scsi_log_mutex);
}
#endif	/* NO_SCSI_FINI_YET */

int
scsi_hba_pkt_constructor(void *buf, void *arg, int kmflag)
{
	struct scsi_pkt_cache_wrapper *pktw;
	struct scsi_pkt		*pkt;
	scsi_hba_tran_t		*tran = (scsi_hba_tran_t *)arg;
	int			pkt_len;
	char			*ptr;

	/*
	 * allocate a chunk of memory for the following:
	 * scsi_pkt
	 * pcw_* fields
	 * pkt_ha_private
	 * pkt_cdbp, if needed
	 * (pkt_private always null)
	 * pkt_scbp, if needed
	 */
	pkt_len = tran->tran_hba_len + sizeof (struct scsi_pkt_cache_wrapper);
	if (tran->tran_hba_flags & SCSI_HBA_TRAN_CDB)
		pkt_len += DEFAULT_CDBLEN;
	if (tran->tran_hba_flags & SCSI_HBA_TRAN_SCB)
		pkt_len += DEFAULT_SCBLEN;
	bzero(buf, pkt_len);

	ptr = buf;
	pktw = buf;
	ptr += sizeof (struct scsi_pkt_cache_wrapper);
	pkt = &(pktw->pcw_pkt);
	pkt->pkt_ha_private = (opaque_t)ptr;

	pktw->pcw_magic = PKT_WRAPPER_MAGIC;	/* alloced correctly */
	/*
	 * keep track of the granularity at the time this handle was
	 * allocated
	 */
	pktw->pcw_granular = tran->tran_dma_attr.dma_attr_granular;

	if (ddi_dma_alloc_handle(tran->tran_hba_dip,
	    &tran->tran_dma_attr,
	    kmflag == KM_SLEEP ? SLEEP_FUNC: NULL_FUNC, NULL,
	    &pkt->pkt_handle) != DDI_SUCCESS) {

		return (-1);
	}
	ptr += tran->tran_hba_len;
	if (tran->tran_hba_flags & SCSI_HBA_TRAN_CDB) {
		pkt->pkt_cdbp = (opaque_t)ptr;
		ptr += DEFAULT_CDBLEN;
	}
	pkt->pkt_private = NULL;
	if (tran->tran_hba_flags & SCSI_HBA_TRAN_SCB)
		pkt->pkt_scbp = (opaque_t)ptr;
	if (tran->tran_pkt_constructor)
		return ((*tran->tran_pkt_constructor)(pkt, arg, kmflag));
	else
		return (0);
}

#define	P_TO_TRAN(pkt)	((pkt)->pkt_address.a_hba_tran)

void
scsi_hba_pkt_destructor(void *buf, void *arg)
{
	struct scsi_pkt_cache_wrapper *pktw = buf;
	struct scsi_pkt *pkt	= &(pktw->pcw_pkt);
	scsi_hba_tran_t		*tran = (scsi_hba_tran_t *)arg;

	ASSERT(pktw->pcw_magic == PKT_WRAPPER_MAGIC);
	ASSERT((pktw->pcw_flags & PCW_BOUND) == 0);
	if (tran->tran_pkt_destructor)
		(*tran->tran_pkt_destructor)(pkt, arg);

	/* make sure nobody messed with our pointers */
	ASSERT(pkt->pkt_ha_private == (opaque_t)((char *)pkt +
	    sizeof (struct scsi_pkt_cache_wrapper)));
	ASSERT(((tran->tran_hba_flags & SCSI_HBA_TRAN_SCB) == 0) ||
	    (pkt->pkt_scbp == (opaque_t)((char *)pkt +
	    tran->tran_hba_len +
	    (((tran->tran_hba_flags & SCSI_HBA_TRAN_CDB) == 0) ?
	    0 : DEFAULT_CDBLEN) +
	    DEFAULT_PRIVLEN + sizeof (struct scsi_pkt_cache_wrapper))));
	ASSERT(((tran->tran_hba_flags & SCSI_HBA_TRAN_CDB) == 0) ||
	    (pkt->pkt_cdbp == (opaque_t)((char *)pkt +
	    tran->tran_hba_len +
	    sizeof (struct scsi_pkt_cache_wrapper))));
	ASSERT(pkt->pkt_handle);
	ddi_dma_free_handle(&pkt->pkt_handle);
	pkt->pkt_handle = NULL;
	pkt->pkt_numcookies = 0;
	pktw->pcw_total_xfer = 0;
	pktw->pcw_totalwin = 0;
	pktw->pcw_curwin = 0;
}

/*
 * Called by an HBA from _init()
 */
int
scsi_hba_init(struct modlinkage *modlp)
{
	struct dev_ops *hba_dev_ops;

	/*
	 * Get the devops structure of the hba,
	 * and put our busops vector in its place.
	 */
	hba_dev_ops = ((struct modldrv *)(modlp->ml_linkage[0]))->drv_dev_ops;
	ASSERT(hba_dev_ops->devo_bus_ops == NULL);
	hba_dev_ops->devo_bus_ops = &scsi_hba_busops;

	/*
	 * Provide getinfo and hotplugging ioctl if driver
	 * does not provide them already
	 */
	if (hba_dev_ops->devo_cb_ops == NULL) {
		hba_dev_ops->devo_cb_ops = &scsi_hba_cbops;
	}
	if (hba_dev_ops->devo_cb_ops->cb_open == scsi_hba_open) {
		ASSERT(hba_dev_ops->devo_cb_ops->cb_close == scsi_hba_close);
		hba_dev_ops->devo_getinfo = scsi_hba_info;
	}

	return (0);
}


/*
 * Implement this older interface in terms of the new.
 * This is hardly in the critical path, so avoiding
 * unnecessary code duplication is more important.
 */
/*ARGSUSED*/
int
scsi_hba_attach(
	dev_info_t		*dip,
	ddi_dma_lim_t		*hba_lim,
	scsi_hba_tran_t		*hba_tran,
	int			flags,
	void			*hba_options)
{
	ddi_dma_attr_t		hba_dma_attr;

	bzero(&hba_dma_attr, sizeof (ddi_dma_attr_t));

	hba_dma_attr.dma_attr_burstsizes = hba_lim->dlim_burstsizes;
	hba_dma_attr.dma_attr_minxfer = hba_lim->dlim_minxfer;

	return (scsi_hba_attach_setup(dip, &hba_dma_attr, hba_tran, flags));
}


/*
 * Called by an HBA to attach an instance of the driver
 */
int
scsi_hba_attach_setup(
	dev_info_t		*dip,
	ddi_dma_attr_t		*hba_dma_attr,
	scsi_hba_tran_t		*hba_tran,
	int			flags)
{
	struct dev_ops		*hba_dev_ops;
	struct scsi_hba_inst	*elem;
	int			value;
	int			len;
	char			*prop_name;
	const char		*prop_value;
	int			capable;
	static char		*errmsg =
	    "scsi_hba_attach: cannot create property '%s' for %s%d\n";
	static const char	*interconnect[] = INTERCONNECT_TYPE_ASCII;

	/*
	 * Link this instance into the scsi_hba_list
	 */
	elem = kmem_alloc(sizeof (struct scsi_hba_inst), KM_SLEEP);

	mutex_enter(&scsi_hba_mutex);

	elem->inst_dip = dip;
	elem->inst_hba_tran = hba_tran;

	elem->inst_next = NULL;
	elem->inst_prev = scsi_hba_list_tail;
	if (scsi_hba_list == NULL) {
		scsi_hba_list = elem;
	}
	if (scsi_hba_list_tail) {
		scsi_hba_list_tail->inst_next = elem;
	}
	scsi_hba_list_tail = elem;
	mutex_exit(&scsi_hba_mutex);

	/*
	 * Save all the important HBA information that must be accessed
	 * later by scsi_hba_bus_ctl(), and scsi_hba_map().
	 */
	hba_tran->tran_hba_dip = dip;
	hba_tran->tran_hba_flags &= SCSI_HBA_TRAN_ALLOC;
	hba_tran->tran_hba_flags |= (flags & ~SCSI_HBA_TRAN_ALLOC);

	/*
	 * Note: we only need dma_attr_minxfer and dma_attr_burstsizes
	 * from the DMA attributes.  scsi_hba_attach(9f) only
	 * guarantees that these two fields are initialized properly.
	 * If this changes, be sure to revisit the implementation
	 * of scsi_hba_attach(9F).
	 */
	(void) memcpy(&hba_tran->tran_dma_attr, hba_dma_attr,
	    sizeof (ddi_dma_attr_t));

	/* create kmem_cache, if needed */
	if (hba_tran->tran_setup_pkt) {
		char tmp[96];
		int hbalen;
		int cmdlen = 0;
		int statuslen = 0;

		ASSERT(hba_tran->tran_init_pkt == NULL);
		ASSERT(hba_tran->tran_destroy_pkt == NULL);

		hba_tran->tran_init_pkt = scsi_init_cache_pkt;
		hba_tran->tran_destroy_pkt = scsi_free_cache_pkt;
		hba_tran->tran_sync_pkt = scsi_sync_cache_pkt;
		hba_tran->tran_dmafree = scsi_cache_dmafree;

		hbalen = ROUNDUP(hba_tran->tran_hba_len);
		if (flags & SCSI_HBA_TRAN_CDB)
			cmdlen = ROUNDUP(DEFAULT_CDBLEN);
		if (flags & SCSI_HBA_TRAN_SCB)
			statuslen = ROUNDUP(DEFAULT_SCBLEN);

		(void) snprintf(tmp, sizeof (tmp), "pkt_cache_%s_%d",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		hba_tran->tran_pkt_cache_ptr = kmem_cache_create(tmp,
		    sizeof (struct scsi_pkt_cache_wrapper) +
		    hbalen + cmdlen + statuslen, 8,
		    scsi_hba_pkt_constructor, scsi_hba_pkt_destructor,
		    NULL, hba_tran, NULL, 0);
	}

	/*
	 * Attach scsi configuration property parameters
	 * to this instance of the hba.
	 */
	prop_name = "scsi-reset-delay";
	len = 0;
	if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN, 0, prop_name,
	    NULL, &len) == DDI_PROP_NOT_FOUND) {
		value = scsi_reset_delay;
		if (ddi_prop_update_int(DDI_MAJOR_T_UNKNOWN, dip,
		    prop_name, value) != DDI_PROP_SUCCESS) {
			cmn_err(CE_CONT, errmsg, prop_name,
			    ddi_driver_name(dip), ddi_get_instance(dip));
		}
	}

	prop_name = "scsi-tag-age-limit";
	len = 0;
	if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN, 0, prop_name,
	    NULL, &len) == DDI_PROP_NOT_FOUND) {
		value = scsi_tag_age_limit;
		if (ddi_prop_update_int(DDI_MAJOR_T_UNKNOWN, dip,
		    prop_name, value) != DDI_PROP_SUCCESS) {
			cmn_err(CE_CONT, errmsg, prop_name,
			    ddi_driver_name(dip), ddi_get_instance(dip));
		}
	}

	prop_name = "scsi-watchdog-tick";
	len = 0;
	if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN, 0, prop_name,
	    NULL, &len) == DDI_PROP_NOT_FOUND) {
		value = scsi_watchdog_tick;
		if (ddi_prop_update_int(DDI_MAJOR_T_UNKNOWN, dip,
		    prop_name, value) != DDI_PROP_SUCCESS) {
			cmn_err(CE_CONT, errmsg, prop_name,
			    ddi_driver_name(dip), ddi_get_instance(dip));
		}
	}

	prop_name = "scsi-options";
	len = 0;
	if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN, 0, prop_name,
	    NULL, &len) == DDI_PROP_NOT_FOUND) {
		value = scsi_options;
		if (ddi_prop_update_int(DDI_MAJOR_T_UNKNOWN, dip,
		    prop_name, value) != DDI_PROP_SUCCESS) {
			cmn_err(CE_CONT, errmsg, prop_name,
			    ddi_driver_name(dip), ddi_get_instance(dip));
		}
	}

	prop_name = "scsi-selection-timeout";
	len = 0;
	if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN, 0, prop_name,
	    NULL, &len) == DDI_PROP_NOT_FOUND) {
		value = scsi_selection_timeout;
		if (ddi_prop_update_int(DDI_MAJOR_T_UNKNOWN, dip,
		    prop_name, value) != DDI_PROP_SUCCESS) {
			cmn_err(CE_CONT, errmsg, prop_name,
			    ddi_driver_name(dip), ddi_get_instance(dip));
		}
	}
	if ((hba_tran->tran_hba_flags & SCSI_HBA_TRAN_ALLOC) &&
	    (hba_tran->tran_interconnect_type > 0) &&
	    (hba_tran->tran_interconnect_type < INTERCONNECT_MAX)) {
		prop_name = "initiator-interconnect-type";
		len = 0;
		if (ddi_prop_op(DDI_DEV_T_ANY, dip, PROP_LEN, 0, prop_name,
		    NULL, &len) == DDI_PROP_NOT_FOUND) {
			value = hba_tran->tran_interconnect_type;
			prop_value = interconnect[value];
			if (ddi_prop_update_string(DDI_MAJOR_T_UNKNOWN, dip,
			    prop_name, (char *)prop_value)
			    != DDI_PROP_SUCCESS) {
				cmn_err(CE_CONT, errmsg, prop_name,
				    ddi_driver_name(dip),
				    ddi_get_instance(dip));
			}
		}
	}

	ddi_set_driver_private(dip, hba_tran);

	/*
	 * Create devctl minor node unless driver supplied its own
	 * open/close entry points
	 */
	hba_dev_ops = ddi_get_driver(dip);
	ASSERT(hba_dev_ops != NULL);
	if (hba_dev_ops->devo_cb_ops->cb_open == scsi_hba_open) {
		/*
		 * Make sure that instance number doesn't overflow
		 * when forming minor numbers.
		 */
		ASSERT(ddi_get_instance(dip) <=
		    (L_MAXMIN >> INST_MINOR_SHIFT));

		if ((ddi_create_minor_node(dip, "devctl", S_IFCHR,
		    INST2DEVCTL(ddi_get_instance(dip)),
		    DDI_NT_SCSI_NEXUS, 0) != DDI_SUCCESS) ||
		    (ddi_create_minor_node(dip, "scsi", S_IFCHR,
		    INST2SCSI(ddi_get_instance(dip)),
		    DDI_NT_SCSI_ATTACHMENT_POINT, 0) != DDI_SUCCESS)) {
			ddi_remove_minor_node(dip, "devctl");
			ddi_remove_minor_node(dip, "scsi");
			cmn_err(CE_WARN, "scsi_hba_attach: "
			    "cannot create devctl/scsi minor nodes");
		}
	}

	/*
	 * NOTE: SCSA maintains an 'fm-capable' domain, in tran_fm_capable,
	 * that is not dependent (limited by) the capabilities of its parents.
	 * For example a dip in a branch that is not DDI_FM_EREPORT_CAPABLE
	 * may report as capable, via tran_fm_capable, to its scsi_device
	 * children.
	 *
	 * Get 'fm-capable' property from driver.conf, if present. If not
	 * present, default to the scsi_fm_capable global (which has
	 * DDI_FM_EREPORT_CAPABLE set by default).
	 */
	if (hba_tran->tran_fm_capable == DDI_FM_NOT_CAPABLE)
		hba_tran->tran_fm_capable = ddi_getprop(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP | DDI_PROP_NOTPROM,
		    "fm-capable", scsi_fm_capable);

	/*
	 * If an HBA is *not* doing its own fma support by calling
	 * ddi_fm_init() prior to scsi_hba_attach_setup(), we provide a
	 * minimal common SCSA implementation so that scsi_device children
	 * can generate ereports via scsi_fm_ereport_post().  We use
	 * ddi_fm_capable() to detect an HBA calling ddi_fm_init() prior to
	 * scsi_hba_attach_setup().
	 */
	if (hba_tran->tran_fm_capable &&
	    (ddi_fm_capable(dip) == DDI_FM_NOT_CAPABLE)) {
		/*
		 * We are capable of something, pass our capabilities up
		 * the tree, but use a local variable so our parent can't
		 * limit our capabilities (we don't want our parent to
		 * clear DDI_FM_EREPORT_CAPABLE).
		 *
		 * NOTE: iblock cookies are not important because scsi
		 * HBAs always interrupt below LOCK_LEVEL.
		 */
		capable = hba_tran->tran_fm_capable;
		ddi_fm_init(dip, &capable, NULL);

		/*
		 * Set SCSI_HBA_TRAN_FMSCSA bit to mark us as usiung the
		 * common minimal SCSA fm implementation -  we called
		 * ddi_fm_init(), so we are responsible for calling
		 * ddi_fm_fini() in scsi_hba_detach().
		 */
		hba_tran->tran_hba_flags |= SCSI_HBA_TRAN_FMSCSA;
	}

	return (DDI_SUCCESS);
}

/*
 * Called by an HBA to detach an instance of the driver
 */
int
scsi_hba_detach(dev_info_t *dip)
{
	struct dev_ops		*hba_dev_ops;
	scsi_hba_tran_t		*hba;
	struct scsi_hba_inst	*elem;


	hba = ddi_get_driver_private(dip);
	ddi_set_driver_private(dip, NULL);
	ASSERT(hba != NULL);
	ASSERT(hba->tran_open_flag == 0);

	/*
	 * If we are taking care of mininal default fma implementation,
	 * call ddi_fm_fini(9F).
	 */
	if (hba->tran_hba_flags & SCSI_HBA_TRAN_FMSCSA) {
		ddi_fm_fini(dip);
	}

	hba_dev_ops = ddi_get_driver(dip);
	ASSERT(hba_dev_ops != NULL);
	if (hba_dev_ops->devo_cb_ops->cb_open == scsi_hba_open) {
		ddi_remove_minor_node(dip, "devctl");
		ddi_remove_minor_node(dip, "scsi");
	}

	/*
	 * XXX - scsi_transport.h states that these data fields should not be
	 *	 referenced by the HBA. However, to be consistent with
	 *	 scsi_hba_attach(), they are being reset.
	 */
	hba->tran_hba_dip = (dev_info_t *)NULL;
	hba->tran_hba_flags = 0;
	(void) memset(&hba->tran_dma_attr, 0, sizeof (ddi_dma_attr_t));

	if (hba->tran_pkt_cache_ptr != NULL) {
		kmem_cache_destroy(hba->tran_pkt_cache_ptr);
		hba->tran_pkt_cache_ptr = NULL;
	}
	/*
	 * Remove HBA instance from scsi_hba_list
	 */
	mutex_enter(&scsi_hba_mutex);
	for (elem = scsi_hba_list; elem != (struct scsi_hba_inst *)NULL;
	    elem = elem->inst_next) {
		if (elem->inst_dip == dip)
			break;
	}

	if (elem == (struct scsi_hba_inst *)NULL) {
		cmn_err(CE_CONT, "scsi_hba_attach: unknown HBA instance\n");
		mutex_exit(&scsi_hba_mutex);
		return (DDI_FAILURE);
	}
	if (elem == scsi_hba_list) {
		scsi_hba_list = elem->inst_next;
		if (scsi_hba_list) {
			scsi_hba_list->inst_prev = (struct scsi_hba_inst *)NULL;
		}
		if (elem == scsi_hba_list_tail) {
			scsi_hba_list_tail = NULL;
		}
	} else if (elem == scsi_hba_list_tail) {
		scsi_hba_list_tail = elem->inst_prev;
		if (scsi_hba_list_tail) {
			scsi_hba_list_tail->inst_next =
			    (struct scsi_hba_inst *)NULL;
		}
	} else {
		elem->inst_prev->inst_next = elem->inst_next;
		elem->inst_next->inst_prev = elem->inst_prev;
	}
	mutex_exit(&scsi_hba_mutex);

	kmem_free(elem, sizeof (struct scsi_hba_inst));

	return (DDI_SUCCESS);
}

/*
 * Called by an HBA from _fini()
 */
void
scsi_hba_fini(struct modlinkage *modlp)
{
	struct dev_ops *hba_dev_ops;

	/*
	 * Get the devops structure of this module
	 * and clear bus_ops vector.
	 */
	hba_dev_ops = ((struct modldrv *)(modlp->ml_linkage[0]))->drv_dev_ops;

	if (hba_dev_ops->devo_cb_ops == &scsi_hba_cbops) {
		hba_dev_ops->devo_cb_ops = NULL;
	}

	if (hba_dev_ops->devo_getinfo == scsi_hba_info) {
		hba_dev_ops->devo_getinfo = NULL;
	}

	hba_dev_ops->devo_bus_ops = (struct bus_ops *)NULL;
}

static int
smp_ctlops_reportdev(dev_info_t	*dip, dev_info_t *rdip)
{
	scsi_hba_tran_t		*hba;
	char			*smp_wwn;

	hba = ddi_get_driver_private(dip);
	ASSERT(hba != NULL);

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, rdip,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP | DDI_PROP_NOTPROM,
	    SMP_WWN, &smp_wwn) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	cmn_err(CE_CONT,
	    "?%s%d at %s%d: wwn %s\n",
	    ddi_driver_name(rdip), ddi_get_instance(rdip),
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    smp_wwn);

	ddi_prop_free(smp_wwn);
	return (DDI_SUCCESS);
}


static int
smp_ctlops_initchild(dev_info_t	*dip, dev_info_t *rdip)
{
	struct smp_device	*smp;
	char			name[SCSI_MAXNAMELEN];
	scsi_hba_tran_t		*hba;
	dev_info_t		*ndip;
	char			*smp_wwn;
	uint64_t		wwn;

	hba = ddi_get_driver_private(dip);

	if (hba == NULL)
		return (DDI_FAILURE);

	smp = kmem_zalloc(sizeof (struct smp_device), KM_SLEEP);

	/*
	 * Clone transport structure if requested, so
	 * the HBA can maintain target-specific info, if
	 * necessary.
	 */
	if (hba->tran_hba_flags & SCSI_HBA_TRAN_CLONE) {
		scsi_hba_tran_t	*clone =
		    kmem_alloc(sizeof (scsi_hba_tran_t), KM_SLEEP);

		bcopy(hba, clone, sizeof (scsi_hba_tran_t));
		hba = clone;
	}

	smp->dip = rdip;
	smp->smp_addr.a_hba_tran = hba;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, rdip,
	    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP | DDI_PROP_NOTPROM,
	    SMP_WWN, &smp_wwn) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (ddi_devid_str_to_wwn(smp_wwn, &wwn)) {
		goto failure;
	}

	bcopy(&wwn, smp->smp_addr.a_wwn, SAS_WWN_BYTE_SIZE);

	bzero(name, sizeof (SCSI_MAXNAMELEN));

	(void) sprintf(name, "w%s", smp_wwn);

	/*
	 * Prevent duplicate nodes.
	 */
	ndip = ndi_devi_find(dip, ddi_node_name(rdip), name);

	if (ndip && (ndip != rdip)) {
		goto failure;
	}

	ddi_set_name_addr(rdip, name);

	ddi_set_driver_private(rdip, smp);

	ddi_prop_free(smp_wwn);

	return (DDI_SUCCESS);

failure:
	kmem_free(smp, sizeof (struct smp_device));
	if (hba->tran_hba_flags & SCSI_HBA_TRAN_CLONE) {
		kmem_free(hba, sizeof (scsi_hba_tran_t));
	}
	ddi_prop_free(smp_wwn);
	return (DDI_FAILURE);
}

static int
smp_ctlops_uninitchild(dev_info_t *dip, dev_info_t *rdip)
{
	struct smp_device	*smp;
	scsi_hba_tran_t		*hba;

	hba = ddi_get_driver_private(dip);
	ASSERT(hba != NULL);

	smp = ddi_get_driver_private(rdip);
	ASSERT(smp != NULL);

	if (hba->tran_hba_flags & SCSI_HBA_TRAN_CLONE) {
		hba = smp->smp_addr.a_hba_tran;
		kmem_free(hba, sizeof (scsi_hba_tran_t));
	}
	kmem_free(smp, sizeof (*smp));

	ddi_set_driver_private(rdip, NULL);
	ddi_set_name_addr(rdip, NULL);

	return (DDI_SUCCESS);
}

/*
 * Generic bus_ctl operations for SCSI HBA's,
 * hiding the busctl interface from the HBA.
 */
/*ARGSUSED*/
static int
scsi_hba_bus_ctl(
	dev_info_t		*dip,
	dev_info_t		*rdip,
	ddi_ctl_enum_t		op,
	void			*arg,
	void			*result)
{
	switch (op) {
	case DDI_CTLOPS_REPORTDEV:
	{
		struct scsi_device	*devp;
		scsi_hba_tran_t		*hba;

		hba = ddi_get_driver_private(dip);
		ASSERT(hba != NULL);

		if (ddi_prop_exists(DDI_DEV_T_ANY, rdip,
		    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP | DDI_PROP_NOTPROM,
		    SMP_PROP)) {
			return (smp_ctlops_reportdev(dip, rdip));
		}

		devp = ddi_get_driver_private(rdip);

		if ((hba->tran_get_bus_addr == NULL) ||
		    (hba->tran_get_name == NULL)) {
			cmn_err(CE_CONT, "?%s%d at %s%d: target %x lun %x\n",
			    ddi_driver_name(rdip), ddi_get_instance(rdip),
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    devp->sd_address.a_target, devp->sd_address.a_lun);
		} else {
			char name[SCSI_MAXNAMELEN];
			char bus_addr[SCSI_MAXNAMELEN];

			if ((*hba->tran_get_name)(devp, name,
			    SCSI_MAXNAMELEN) != 1) {
				return (DDI_FAILURE);
			}
			if ((*hba->tran_get_bus_addr)(devp, bus_addr,
			    SCSI_MAXNAMELEN) != 1) {
				return (DDI_FAILURE);
			}
			cmn_err(CE_CONT,
			    "?%s%d at %s%d: name %s, bus address %s\n",
			    ddi_driver_name(rdip), ddi_get_instance(rdip),
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    name, bus_addr);
		}
		return (DDI_SUCCESS);
	}

	case DDI_CTLOPS_IOMIN:
	{
		int		val;
		scsi_hba_tran_t	*hba;
		ddi_dma_attr_t	*attr;

		hba = ddi_get_driver_private(dip);
		ASSERT(hba != NULL);
		attr = &hba->tran_dma_attr;

		val = *((int *)result);
		val = maxbit(val, attr->dma_attr_minxfer);
		/*
		 * The 'arg' value of nonzero indicates 'streaming'
		 * mode.  If in streaming mode, pick the largest
		 * of our burstsizes available and say that that
		 * is our minimum value (modulo what minxfer is).
		 */
		*((int *)result) = maxbit(val, ((intptr_t)arg ?
		    (1<<ddi_ffs(attr->dma_attr_burstsizes)-1) :
		    (1<<(ddi_fls(attr->dma_attr_burstsizes)-1))));

		return (ddi_ctlops(dip, rdip, op, arg, result));
	}

	case DDI_CTLOPS_INITCHILD:
	{
		dev_info_t		*child_dip = (dev_info_t *)arg;
		struct scsi_device	*sd;
		char			name[SCSI_MAXNAMELEN];
		scsi_hba_tran_t		*hba;
		dev_info_t		*ndip;

		if (ddi_prop_exists(DDI_DEV_T_ANY, child_dip,
		    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP | DDI_PROP_NOTPROM,
		    SMP_PROP)) {
			return (smp_ctlops_initchild(dip, child_dip));
		}

		hba = ddi_get_driver_private(dip);

		/*
		 * For a driver like fp with multiple upper-layer-protocols
		 * it is possible for scsi_hba_init in _init to plumb SCSA
		 * and have the load of fcp (which does scsi_hba_attach_setup)
		 * to fail.  In this case we may get here with a NULL hba.
		 */
		if (hba == NULL)
			return (DDI_FAILURE);

		sd = kmem_zalloc(sizeof (struct scsi_device), KM_SLEEP);

		/*
		 * Clone transport structure if requested, so
		 * the HBA can maintain target-specific info, if
		 * necessary. At least all SCSI-3 HBAs will do this.
		 */
		if (hba->tran_hba_flags & SCSI_HBA_TRAN_CLONE) {
			scsi_hba_tran_t	*clone =
			    kmem_alloc(sizeof (scsi_hba_tran_t), KM_SLEEP);

			bcopy(hba, clone, sizeof (scsi_hba_tran_t));
			hba = clone;
			hba->tran_sd = sd;
		} else {
			ASSERT(hba->tran_sd == NULL);
		}

		sd->sd_dev = child_dip;
		sd->sd_address.a_hba_tran = hba;

		/*
		 * Make sure that HBA either supports both or none
		 * of tran_get_name/tran_get_addr
		 */
		if ((hba->tran_get_name != NULL) ||
		    (hba->tran_get_bus_addr != NULL)) {
			if ((hba->tran_get_name == NULL) ||
			    (hba->tran_get_bus_addr == NULL)) {
				cmn_err(CE_CONT,
				    "%s%d: should support both or none of "
				    "tran_get_name and tran_get_bus_addr\n",
				    ddi_driver_name(dip),
				    ddi_get_instance(dip));
				goto failure;
			}
		}

		/*
		 * In case HBA doesn't support tran_get_name/tran_get_bus_addr
		 * (e.g. most pre-SCSI-3 HBAs), we have to continue
		 * to provide old semantics. In case a HBA driver does
		 * support it, a_target and a_lun fields of scsi_address
		 * are not defined and will be 0 except for parallel bus.
		 */
		{
			int	t_len;
			int	targ = 0;
			int	lun = 0;

			t_len = sizeof (targ);
			if (ddi_prop_op(DDI_DEV_T_ANY, child_dip,
			    PROP_LEN_AND_VAL_BUF, DDI_PROP_DONTPASS |
			    DDI_PROP_CANSLEEP, "target", (caddr_t)&targ,
			    &t_len) != DDI_SUCCESS) {
				if (hba->tran_get_name == NULL) {
					kmem_free(sd,
					    sizeof (struct scsi_device));
					if (hba->tran_hba_flags &
					    SCSI_HBA_TRAN_CLONE) {
						kmem_free(hba,
						    sizeof (scsi_hba_tran_t));
					}
					return (DDI_NOT_WELL_FORMED);
				}
			}

			t_len = sizeof (lun);
			(void) ddi_prop_op(DDI_DEV_T_ANY, child_dip,
			    PROP_LEN_AND_VAL_BUF, DDI_PROP_DONTPASS |
			    DDI_PROP_CANSLEEP, "lun", (caddr_t)&lun,
			    &t_len);

			/*
			 * If the HBA does not implement tran_get_name then it
			 * doesn't have any hope of supporting a LUN >= 256.
			 */
			if (lun >= 256 && hba->tran_get_name == NULL) {
				goto failure;
			}

			/*
			 * This is also to make sure that if someone plugs in
			 * a SCSI-2 disks to a SCSI-3 parallel bus HBA,
			 * his SCSI-2 target driver still continue to work.
			 */
			sd->sd_address.a_target = (ushort_t)targ;
			sd->sd_address.a_lun = (uchar_t)lun;
		}

		/*
		 * In case HBA support tran_get_name (e.g. all SCSI-3 HBAs),
		 * give it a chance to tell us the name.
		 * If it doesn't support this entry point, a name will be
		 * fabricated
		 */
		if (scsi_get_name(sd, name, SCSI_MAXNAMELEN) != 1) {
			goto failure;
		}

		/*
		 * Prevent duplicate nodes.
		 */
		ndip = ndi_devi_find(dip, ddi_node_name(child_dip), name);

		if (ndip && (ndip != child_dip)) {
			goto failure;
		}

		ddi_set_name_addr(child_dip, name);

		/*
		 * This is a grotty hack that allows direct-access
		 * (non-scsi) drivers using this interface to
		 * put its own vector in the 'a_hba_tran' field.
		 * When the drivers are fixed, remove this hack.
		 */
		sd->sd_reserved = hba;

		/*
		 * call hba's target init entry point if it exists
		 */
		if (hba->tran_tgt_init != NULL) {
			if ((*hba->tran_tgt_init)
			    (dip, child_dip, hba, sd) != DDI_SUCCESS) {
				ddi_set_name_addr(child_dip, NULL);
				goto failure;
			}

			/*
			 * Another grotty hack to undo initialization
			 * some hba's think they have authority to
			 * perform.
			 *
			 * XXX - Pending dadk_probe() semantics
			 *	 change.  (Re: 1171432)
			 */
			if (hba->tran_tgt_probe != NULL)
				sd->sd_inq = NULL;
		}

		mutex_init(&sd->sd_mutex, NULL, MUTEX_DRIVER, NULL);

		ddi_set_driver_private(child_dip, sd);

		return (DDI_SUCCESS);

failure:
		kmem_free(sd, sizeof (struct scsi_device));
		if (hba->tran_hba_flags & SCSI_HBA_TRAN_CLONE) {
			kmem_free(hba, sizeof (scsi_hba_tran_t));
		}
		return (DDI_FAILURE);
	}

	case DDI_CTLOPS_UNINITCHILD:
	{
		struct scsi_device	*sd;
		dev_info_t		*child_dip = (dev_info_t *)arg;
		scsi_hba_tran_t		*hba;

		if (ddi_prop_exists(DDI_DEV_T_ANY, child_dip,
		    DDI_PROP_DONTPASS | DDI_PROP_CANSLEEP | DDI_PROP_NOTPROM,
		    SMP_PROP)) {
			return (smp_ctlops_uninitchild(dip, child_dip));
		}

		hba = ddi_get_driver_private(dip);
		ASSERT(hba != NULL);

		sd = ddi_get_driver_private(child_dip);
		ASSERT(sd != NULL);

		if (hba->tran_hba_flags & SCSI_HBA_TRAN_CLONE) {
			/*
			 * This is a grotty hack, continued.  This
			 * should be:
			 *	hba = sd->sd_address.a_hba_tran;
			 */
			hba = sd->sd_reserved;
			ASSERT(hba->tran_hba_flags & SCSI_HBA_TRAN_CLONE);
			ASSERT(hba->tran_sd == sd);
		} else {
			ASSERT(hba->tran_sd == NULL);
		}

		scsi_unprobe(sd);
		if (hba->tran_tgt_free != NULL) {
			(*hba->tran_tgt_free) (dip, child_dip, hba, sd);
		}
		mutex_destroy(&sd->sd_mutex);
		if (hba->tran_hba_flags & SCSI_HBA_TRAN_CLONE) {
			kmem_free(hba, sizeof (scsi_hba_tran_t));
		}
		kmem_free(sd, sizeof (*sd));

		ddi_set_driver_private(child_dip, NULL);
		ddi_set_name_addr(child_dip, NULL);

		return (DDI_SUCCESS);
	}
	case DDI_CTLOPS_SIDDEV:
		return (ndi_dev_is_persistent_node(rdip) ?
		    DDI_SUCCESS : DDI_FAILURE);

	/* XXX these should be handled */
	case DDI_CTLOPS_POWER:
	case DDI_CTLOPS_ATTACH:
	case DDI_CTLOPS_DETACH:

		return (DDI_SUCCESS);

	/*
	 * These ops correspond to functions that "shouldn't" be called
	 * by a SCSI target driver.  So we whine when we're called.
	 */
	case DDI_CTLOPS_DMAPMAPC:
	case DDI_CTLOPS_REPORTINT:
	case DDI_CTLOPS_REGSIZE:
	case DDI_CTLOPS_NREGS:
	case DDI_CTLOPS_SLAVEONLY:
	case DDI_CTLOPS_AFFINITY:
	case DDI_CTLOPS_POKE:
	case DDI_CTLOPS_PEEK:
		cmn_err(CE_CONT, "%s%d: invalid op (%d) from %s%d\n",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    op, ddi_driver_name(rdip), ddi_get_instance(rdip));
		return (DDI_FAILURE);

	/*
	 * Everything else (e.g. PTOB/BTOP/BTOPR requests) we pass up
	 */
	default:
		return (ddi_ctlops(dip, rdip, op, arg, result));
	}
}


/*
 * Called by an HBA to allocate a scsi_hba_tran structure
 */
/*ARGSUSED*/
scsi_hba_tran_t *
scsi_hba_tran_alloc(
	dev_info_t		*dip,
	int			flags)
{
	scsi_hba_tran_t		*hba_tran;

	hba_tran = kmem_zalloc(sizeof (scsi_hba_tran_t),
	    (flags & SCSI_HBA_CANSLEEP) ? KM_SLEEP : KM_NOSLEEP);

	hba_tran->tran_interconnect_type = INTERCONNECT_PARALLEL;
	hba_tran->tran_hba_flags |= SCSI_HBA_TRAN_ALLOC;

	return (hba_tran);
}

int
scsi_tran_ext_alloc(
	scsi_hba_tran_t		*hba_tran,
	size_t			length,
	int			flags)
{
	void	*hba_tran_ext;
	int	ret = DDI_FAILURE;

	hba_tran_ext = kmem_zalloc(length, (flags & SCSI_HBA_CANSLEEP)
	    ? KM_SLEEP : KM_NOSLEEP);
	if (hba_tran_ext != NULL) {
		hba_tran->tran_extension = hba_tran_ext;
		ret = DDI_SUCCESS;
	}
	return (ret);
}

void
scsi_tran_ext_free(
	scsi_hba_tran_t		*hba_tran,
	size_t			length)
{
	if (hba_tran->tran_extension != NULL) {
		kmem_free(hba_tran->tran_extension, length);
		hba_tran->tran_extension = NULL;
	}
}

/*
 * Called by an HBA to free a scsi_hba_tran structure
 */
void
scsi_hba_tran_free(
	scsi_hba_tran_t		*hba_tran)
{
	kmem_free(hba_tran, sizeof (scsi_hba_tran_t));
}

/*
 * Private wrapper for scsi_pkt's allocated via scsi_hba_pkt_alloc()
 */
struct scsi_pkt_wrapper {
	struct scsi_pkt		scsi_pkt;
	int			pkt_wrapper_magic;
	int			pkt_wrapper_len;
};

#if !defined(lint)
_NOTE(SCHEME_PROTECTS_DATA("unique per thread", scsi_pkt_wrapper))
_NOTE(SCHEME_PROTECTS_DATA("Unshared Data", dev_ops))
#endif

/*
 * Called by an HBA to allocate a scsi_pkt
 */
/*ARGSUSED*/
struct scsi_pkt *
scsi_hba_pkt_alloc(
	dev_info_t		*dip,
	struct scsi_address	*ap,
	int			cmdlen,
	int			statuslen,
	int			tgtlen,
	int			hbalen,
	int			(*callback)(caddr_t arg),
	caddr_t			arg)
{
	struct scsi_pkt		*pkt;
	struct scsi_pkt_wrapper	*hba_pkt;
	caddr_t			p;
	int			acmdlen, astatuslen, atgtlen, ahbalen;
	int			pktlen;

	/*
	 * Sanity check
	 */
	if (callback != SLEEP_FUNC && callback != NULL_FUNC) {
		cmn_err(CE_PANIC, "scsi_hba_pkt_alloc: callback must be"
		    " either SLEEP or NULL\n");
	}

	/*
	 * Round up so everything gets allocated on long-word boundaries
	 */
	acmdlen = ROUNDUP(cmdlen);
	astatuslen = ROUNDUP(statuslen);
	atgtlen = ROUNDUP(tgtlen);
	ahbalen = ROUNDUP(hbalen);
	pktlen = sizeof (struct scsi_pkt_wrapper) +
	    acmdlen + astatuslen + atgtlen + ahbalen;

	hba_pkt = kmem_zalloc(pktlen,
	    (callback == SLEEP_FUNC) ? KM_SLEEP : KM_NOSLEEP);
	if (hba_pkt == NULL) {
		ASSERT(callback == NULL_FUNC);
		return (NULL);
	}

	/*
	 * Set up our private info on this pkt
	 */
	hba_pkt->pkt_wrapper_len = pktlen;
	hba_pkt->pkt_wrapper_magic = PKT_WRAPPER_MAGIC;	/* alloced correctly */
	pkt = &hba_pkt->scsi_pkt;

	/*
	 * Set up pointers to private data areas, cdb, and status.
	 */
	p = (caddr_t)(hba_pkt + 1);
	if (hbalen > 0) {
		pkt->pkt_ha_private = (opaque_t)p;
		p += ahbalen;
	}
	if (tgtlen > 0) {
		pkt->pkt_private = (opaque_t)p;
		p += atgtlen;
	}
	if (statuslen > 0) {
		pkt->pkt_scbp = (uchar_t *)p;
		p += astatuslen;
	}
	if (cmdlen > 0) {
		pkt->pkt_cdbp = (uchar_t *)p;
	}

	/*
	 * Initialize the pkt's scsi_address
	 */
	pkt->pkt_address = *ap;

	/*
	 * NB: It may not be safe for drivers, esp target drivers, to depend
	 * on the following fields being set until all the scsi_pkt
	 * allocation violations discussed in scsi_pkt.h are all resolved.
	 */
	pkt->pkt_cdblen = cmdlen;
	pkt->pkt_tgtlen = tgtlen;
	pkt->pkt_scblen = statuslen;

	return (pkt);
}

/*
 * Called by an HBA to free a scsi_pkt
 */
/*ARGSUSED*/
void
scsi_hba_pkt_free(
	struct scsi_address	*ap,
	struct scsi_pkt		*pkt)
{
	kmem_free(pkt, ((struct scsi_pkt_wrapper *)pkt)->pkt_wrapper_len);
}

/*
 * Return 1 if the scsi_pkt used a proper allocator.
 *
 * The DDI does not allow a driver to allocate it's own scsi_pkt(9S), a
 * driver should not have *any* compiled in dependencies on "sizeof (struct
 * scsi_pkt)". While this has been the case for many years, a number of
 * drivers have still not been fixed. This function can be used to detect
 * improperly allocated scsi_pkt structures, and produce messages identifying
 * drivers that need to be fixed.
 *
 * While drivers in violation are being fixed, this function can also
 * be used by the framework to detect packets that violated allocation
 * rules.
 *
 * NB: It is possible, but very unlikely, for this code to return a false
 * positive (finding correct magic, but for wrong reasons).  Careful
 * consideration is needed for callers using this interface to condition
 * access to newer scsi_pkt fields (those after pkt_reason).
 *
 * NB: As an aid to minimizing the amount of work involved in 'fixing' legacy
 * drivers that violate scsi_*(9S) allocation rules, private
 * scsi_pkt_size()/scsi_size_clean() functions are available (see their
 * implementation for details).
 *
 * *** Non-legacy use of scsi_pkt_size() is discouraged. ***
 *
 * NB: When supporting broken HBA drivers is not longer a concern, this
 * code should be removed.
 */
int
scsi_pkt_allocated_correctly(struct scsi_pkt *pkt)
{
	struct scsi_pkt_wrapper	*hba_pkt = (struct scsi_pkt_wrapper *)pkt;
	int	magic;
	major_t	major;
#ifdef	DEBUG
	int	*pspwm, *pspcwm;

	/*
	 * We are getting scsi packets from two 'correct' wrapper schemes,
	 * make sure we are looking at the same place in both to detect
	 * proper allocation.
	 */
	pspwm = &((struct scsi_pkt_wrapper *)0)->pkt_wrapper_magic;
	pspcwm = &((struct scsi_pkt_cache_wrapper *)0)->pcw_magic;
	ASSERT(pspwm == pspcwm);
#endif	/* DEBUG */


	/*
	 * Check to see if driver is scsi_size_clean(), assume it
	 * is using the scsi_pkt_size() interface everywhere it needs to
	 * if the driver indicates it is scsi_size_clean().
	 */
	major = ddi_driver_major(P_TO_TRAN(pkt)->tran_hba_dip);
	if (devnamesp[major].dn_flags & DN_SCSI_SIZE_CLEAN)
		return (1);		/* ok */

	/*
	 * Special case crossing a page boundary. If the scsi_pkt was not
	 * allocated correctly, then accross a page boundary we have a
	 * fault hazzard.
	 */
	if ((((uintptr_t)(&hba_pkt->scsi_pkt)) & MMU_PAGEMASK) ==
	    (((uintptr_t)(&hba_pkt->pkt_wrapper_magic)) & MMU_PAGEMASK)) {
		/* fastpath, no cross-page hazzard */
		magic = hba_pkt->pkt_wrapper_magic;
	} else {
		/* add protection for cross-page hazzard */
		if (ddi_peek32((dev_info_t *)NULL,
		    &hba_pkt->pkt_wrapper_magic, &magic) == DDI_FAILURE) {
			return (0);	/* violation */
		}
	}

	/* properly allocated packet always has correct magic */
	return ((magic == PKT_WRAPPER_MAGIC) ? 1 : 0);
}

/*
 * Private interfaces to simplify conversion of legacy drivers so they don't
 * depend on scsi_*(9S) size. Instead of using these private interface, HBA
 * drivers should use DDI sanctioned allocation methods:
 *
 *	scsi_pkt	Use scsi_hba_pkt_alloc(9F), or implement
 *			tran_setup_pkt(9E).
 *
 *	scsi_device	You are doing something strange/special, a scsi_device
 *			structure should only be allocated by scsi_hba.c
 *			initchild code or scsi_vhci.c code.
 *
 *	scsi_hba_tran	Use scsi_hba_tran_alloc(9F).
 */
size_t
scsi_pkt_size()
{
	return (sizeof (struct scsi_pkt));
}

size_t
scsi_hba_tran_size()
{
	return (sizeof (scsi_hba_tran_t));
}

size_t
scsi_device_size()
{
	return (sizeof (struct scsi_device));
}

/*
 * Legacy compliance to scsi_pkt(9S) allocation rules through use of
 * scsi_pkt_size() is detected by the 'scsi-size-clean' driver.conf property
 * or an HBA driver calling to scsi_size_clean() from attach(9E).  A driver
 * developer should only indicate that a legacy driver is clean after using
 * SCSI_SIZE_CLEAN_VERIFY to ensure compliance (see scsi_pkt.h).
 */
void
scsi_size_clean(dev_info_t *dip)
{
	major_t		major;
	struct devnames	*dnp;

	ASSERT(dip);
	major = ddi_driver_major(dip);
	ASSERT(major < devcnt);
	if (major >= devcnt) {
		cmn_err(CE_WARN, "scsi_pkt_size: bogus major: %d", major);
		return;
	}

	/* Set DN_SCSI_SIZE_CLEAN flag in dn_flags. */
	dnp = &devnamesp[major];
	if ((dnp->dn_flags & DN_SCSI_SIZE_CLEAN) == 0) {
		LOCK_DEV_OPS(&dnp->dn_lock);
		dnp->dn_flags |= DN_SCSI_SIZE_CLEAN;
		UNLOCK_DEV_OPS(&dnp->dn_lock);
	}
}


/*
 * Called by an HBA to map strings to capability indices
 */
int
scsi_hba_lookup_capstr(
	char			*capstr)
{
	/*
	 * Capability strings, masking the the '-' vs. '_' misery
	 */
	static struct cap_strings {
		char	*cap_string;
		int	cap_index;
	} cap_strings[] = {
		{ "dma_max",		SCSI_CAP_DMA_MAX		},
		{ "dma-max",		SCSI_CAP_DMA_MAX		},
		{ "msg_out",		SCSI_CAP_MSG_OUT		},
		{ "msg-out",		SCSI_CAP_MSG_OUT		},
		{ "disconnect",		SCSI_CAP_DISCONNECT		},
		{ "synchronous",	SCSI_CAP_SYNCHRONOUS		},
		{ "wide_xfer",		SCSI_CAP_WIDE_XFER		},
		{ "wide-xfer",		SCSI_CAP_WIDE_XFER		},
		{ "parity",		SCSI_CAP_PARITY			},
		{ "initiator-id",	SCSI_CAP_INITIATOR_ID		},
		{ "untagged-qing",	SCSI_CAP_UNTAGGED_QING		},
		{ "tagged-qing",	SCSI_CAP_TAGGED_QING		},
		{ "auto-rqsense",	SCSI_CAP_ARQ			},
		{ "linked-cmds",	SCSI_CAP_LINKED_CMDS		},
		{ "sector-size",	SCSI_CAP_SECTOR_SIZE		},
		{ "total-sectors",	SCSI_CAP_TOTAL_SECTORS		},
		{ "geometry",		SCSI_CAP_GEOMETRY		},
		{ "reset-notification",	SCSI_CAP_RESET_NOTIFICATION	},
		{ "qfull-retries",	SCSI_CAP_QFULL_RETRIES		},
		{ "qfull-retry-interval", SCSI_CAP_QFULL_RETRY_INTERVAL	},
		{ "scsi-version",	SCSI_CAP_SCSI_VERSION		},
		{ "interconnect-type",	SCSI_CAP_INTERCONNECT_TYPE	},
		{ "lun-reset",		SCSI_CAP_LUN_RESET		},
		{ "max-cdb-length",	SCSI_CAP_CDB_LEN		},
		{ "dma-max-arch",	SCSI_CAP_DMA_MAX_ARCH		},
		{ NULL,			0				}
	};
	struct cap_strings	*cp;

	for (cp = cap_strings; cp->cap_string != NULL; cp++) {
		if (strcmp(cp->cap_string, capstr) == 0) {
			return (cp->cap_index);
		}
	}

	return (-1);
}


/*
 * Called by an HBA to determine if the system is in 'panic' state.
 */
int
scsi_hba_in_panic()
{
	return (panicstr != NULL);
}



/*
 * If a SCSI target driver attempts to mmap memory,
 * the buck stops here.
 */
/*ARGSUSED*/
static int
scsi_hba_map_fault(
	dev_info_t		*dip,
	dev_info_t		*rdip,
	struct hat		*hat,
	struct seg		*seg,
	caddr_t			addr,
	struct devpage		*dp,
	pfn_t			pfn,
	uint_t			prot,
	uint_t			lock)
{
	return (DDI_FAILURE);
}


static int
scsi_hba_get_eventcookie(
	dev_info_t		*dip,
	dev_info_t		*rdip,
	char			*name,
	ddi_eventcookie_t	*eventp)
{
	scsi_hba_tran_t		*hba;

	hba = ddi_get_driver_private(dip);
	if (hba->tran_get_eventcookie && ((*hba->tran_get_eventcookie)(dip,
	    rdip, name, eventp) == DDI_SUCCESS)) {
		return (DDI_SUCCESS);
	}

	return (ndi_busop_get_eventcookie(dip, rdip, name, eventp));
}


static int
scsi_hba_add_eventcall(
	dev_info_t		*dip,
	dev_info_t		*rdip,
	ddi_eventcookie_t	event,
	void			(*callback)(
					dev_info_t *dip,
					ddi_eventcookie_t event,
					void *arg,
					void *bus_impldata),
	void			*arg,
	ddi_callback_id_t	*cb_id)
{
	scsi_hba_tran_t		*hba;

	hba = ddi_get_driver_private(dip);
	if (hba->tran_add_eventcall && ((*hba->tran_add_eventcall)(dip, rdip,
	    event, callback, arg, cb_id) == DDI_SUCCESS)) {
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}


static int
scsi_hba_remove_eventcall(dev_info_t *devi, ddi_callback_id_t cb_id)
{
	scsi_hba_tran_t		*hba;
	ASSERT(cb_id);

	hba = ddi_get_driver_private(devi);
	if (hba->tran_remove_eventcall && ((*hba->tran_remove_eventcall)(
	    devi, cb_id) == DDI_SUCCESS)) {
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}


static int
scsi_hba_post_event(
	dev_info_t		*dip,
	dev_info_t		*rdip,
	ddi_eventcookie_t	event,
	void			*bus_impldata)
{
	scsi_hba_tran_t		*hba;

	hba = ddi_get_driver_private(dip);
	if (hba->tran_post_event && ((*hba->tran_post_event)(dip,
	    rdip, event, bus_impldata) == DDI_SUCCESS)) {
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

/*
 * The attach/detach of individual instances is controlled by the DDI
 * framework, hence, DDI_DEVT2DEVINFO doesn't make much sense (because
 * it ask drivers to hold individual dips in memory.
 */
static dev_info_t *
devt_to_devinfo(dev_t dev)
{
	dev_info_t *dip;
	struct devnames *dnp;
	major_t major = getmajor(dev);
	int instance = MINOR2INST(getminor(dev));

	if (major >= devcnt) {
		return (NULL);
	}

	dnp = &devnamesp[major];
	LOCK_DEV_OPS(&(dnp->dn_lock));
	dip = dnp->dn_head;
	while (dip && (ddi_get_instance(dip) != instance)) {
		dip = ddi_get_next(dip);
	}
	UNLOCK_DEV_OPS(&(dnp->dn_lock));

	return (dip);
}

/*
 * Default getinfo(9e) for scsi_hba
 */
/* ARGSUSED */
static int
scsi_hba_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	int error = DDI_SUCCESS;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)devt_to_devinfo((dev_t)arg);
		if (*result == NULL) {
			error = DDI_FAILURE;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(intptr_t)(MINOR2INST(getminor((dev_t)arg)));
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/*
 * Default open and close routine for scsi_hba
 */

/* ARGSUSED */
int
scsi_hba_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	int rv = 0;
	dev_info_t *dip;
	scsi_hba_tran_t *hba;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	dip = devt_to_devinfo(*devp);
	if (dip == NULL)
		return (ENXIO);

	if ((hba = ddi_get_driver_private(dip)) == NULL)
		return (ENXIO);

	/*
	 * tran_open_flag bit field:
	 *	0:	closed
	 *	1:	shared open by minor at bit position
	 *	1 at 31st bit:	exclusive open
	 */
	mutex_enter(&(hba->tran_open_lock));
	if (flags & FEXCL) {
		if (hba->tran_open_flag != 0) {
			rv = EBUSY;		/* already open */
		} else {
			hba->tran_open_flag = TRAN_OPEN_EXCL;
		}
	} else {
		if (hba->tran_open_flag == TRAN_OPEN_EXCL) {
			rv = EBUSY;		/* already excl. open */
		} else {
			int minor = getminor(*devp) & TRAN_MINOR_MASK;
			hba->tran_open_flag |= (1 << minor);
			/*
			 * Ensure that the last framework reserved minor
			 * is unused. Otherwise, the exclusive open
			 * mechanism may break.
			 */
			ASSERT(minor != 31);
		}
	}
	mutex_exit(&(hba->tran_open_lock));

	return (rv);
}

/* ARGSUSED */
int
scsi_hba_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	dev_info_t *dip;
	scsi_hba_tran_t *hba;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	dip = devt_to_devinfo(dev);
	if (dip == NULL)
		return (ENXIO);

	if ((hba = ddi_get_driver_private(dip)) == NULL)
		return (ENXIO);

	mutex_enter(&(hba->tran_open_lock));
	if (hba->tran_open_flag == TRAN_OPEN_EXCL) {
		hba->tran_open_flag = 0;
	} else {
		int minor = getminor(dev) & TRAN_MINOR_MASK;
		hba->tran_open_flag &= ~(1 << minor);
	}
	mutex_exit(&(hba->tran_open_lock));
	return (0);
}

/*
 * standard ioctl commands for SCSI hotplugging
 */

/* ARGSUSED */
int
scsi_hba_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
	int *rvalp)
{
	dev_info_t *self;
	dev_info_t *child;
	struct scsi_device *sd;
	scsi_hba_tran_t *hba;
	struct devctl_iocdata *dcp;
	uint_t bus_state;
	int rv = 0;
	int circ;

	self = devt_to_devinfo(dev);
	if (self == NULL)
		return (ENXIO);

	if ((hba = ddi_get_driver_private(self)) == NULL)
		return (ENXIO);

	/*
	 * For these ioctls, the general implementation suffices
	 */
	switch (cmd) {
	case DEVCTL_DEVICE_GETSTATE:
	case DEVCTL_DEVICE_ONLINE:
	case DEVCTL_DEVICE_OFFLINE:
	case DEVCTL_DEVICE_REMOVE:
	case DEVCTL_BUS_GETSTATE:
		return (ndi_devctl_ioctl(self, cmd, arg, mode, 0));
	}

	switch (cmd) {

	case DEVCTL_DEVICE_RESET:
		if (hba->tran_reset == NULL) {
			rv = ENOTSUP;
			break;
		}
		/*
		 * read devctl ioctl data
		 */
		if (ndi_dc_allochdl((void *)arg, &dcp) != NDI_SUCCESS)
			return (EFAULT);
		if (ndi_dc_getname(dcp) == NULL ||
		    ndi_dc_getaddr(dcp) == NULL) {
			ndi_dc_freehdl(dcp);
			return (EINVAL);
		}

		ndi_devi_enter(self, &circ);

		child = ndi_devi_find(self,
		    ndi_dc_getname(dcp), ndi_dc_getaddr(dcp));
		if (child == NULL) {
			ndi_devi_exit(self, circ);
			ndi_dc_freehdl(dcp);
			return (ENXIO);
		}

		ndi_hold_devi(child);
		ndi_devi_exit(self, circ);

		/*
		 * See DDI_CTLOPS_INITCHILD above
		 */
		sd = ddi_get_driver_private(child);
		if ((sd == NULL) || hba->tran_reset(
		    &sd->sd_address, RESET_TARGET) == 0) {
			rv = EIO;
		}

		ndi_devi_enter(self, &circ);
		ndi_rele_devi(child);
		ndi_devi_exit(self, circ);

		ndi_dc_freehdl(dcp);

		break;


	case DEVCTL_BUS_QUIESCE:
		if ((ndi_get_bus_state(self, &bus_state) == NDI_SUCCESS) &&
		    (bus_state == BUS_QUIESCED)) {
			rv = EALREADY;
			break;
		}

		if (hba->tran_quiesce == NULL) {
			rv = ENOTSUP;
		} else if ((*hba->tran_quiesce)(self) != 0) {
			rv = EIO;
		} else {
			(void) ndi_set_bus_state(self, BUS_QUIESCED);
		}
		break;

	case DEVCTL_BUS_UNQUIESCE:
		if ((ndi_get_bus_state(self, &bus_state) == NDI_SUCCESS) &&
		    (bus_state == BUS_ACTIVE)) {
			rv = EALREADY;
			break;
		}

		if (hba->tran_unquiesce == NULL) {
			rv = ENOTSUP;
		} else if ((*hba->tran_unquiesce)(self) != 0) {
			rv = EIO;
		} else {
			(void) ndi_set_bus_state(self, BUS_ACTIVE);
		}
		break;

	case DEVCTL_BUS_RESET:
		/*
		 * Use tran_bus_reset
		 */
		if (hba->tran_bus_reset == NULL) {
			rv = ENOTSUP;
		} else if ((*hba->tran_bus_reset)(self, RESET_BUS) == 0) {
			rv = EIO;
		}
		break;

	case DEVCTL_BUS_RESETALL:
		if (hba->tran_reset == NULL) {
			rv = ENOTSUP;
			break;
		}
		/*
		 * Find a child's scsi_address and invoke tran_reset
		 *
		 * XXX If no child exists, one may to able to fake a child.
		 *	This will be a enhancement for the future.
		 *	For now, we fall back to BUS_RESET.
		 */
		ndi_devi_enter(self, &circ);
		child = ddi_get_child(self);
		sd = NULL;
		while (child) {
			if ((sd = ddi_get_driver_private(child)) != NULL)
				break;

			child = ddi_get_next_sibling(child);
		}

		if (sd != NULL) {
			ndi_hold_devi(child);
			ndi_devi_exit(self, circ);
			if ((*hba->tran_reset)
			    (&sd->sd_address, RESET_ALL) == 0) {
				rv = EIO;
			}
			ndi_devi_enter(self, &circ);
			ndi_rele_devi(child);
			ndi_devi_exit(self, circ);
		} else {
			ndi_devi_exit(self, circ);
			if ((hba->tran_bus_reset == NULL) ||
			    ((*hba->tran_bus_reset)(self, RESET_BUS) == 0)) {
				rv = EIO;
			}
		}
		break;

	case DEVCTL_BUS_CONFIGURE:
		if (ndi_devi_config(self, NDI_DEVFS_CLEAN|
		    NDI_DEVI_PERSIST|NDI_CONFIG_REPROBE) != NDI_SUCCESS) {
			rv = EIO;
		}
		break;

	case DEVCTL_BUS_UNCONFIGURE:
		if (ndi_devi_unconfig(self,
		    NDI_DEVI_REMOVE|NDI_DEVFS_CLEAN) != NDI_SUCCESS) {
			rv = EBUSY;
		}
		break;

	default:
		rv = ENOTTY;
	} /* end of outer switch */

	return (rv);
}

static int
scsi_hba_bus_config(dev_info_t *parent, uint_t flag, ddi_bus_config_op_t op,
    void *arg, dev_info_t **childp)
{
	scsi_hba_tran_t *hba;

	hba = ddi_get_driver_private(parent);
	if (hba && hba->tran_bus_config) {
		return (hba->tran_bus_config(parent, flag, op, arg, childp));
	}

	/*
	 * Force reprobe for BUS_CONFIG_ONE or when manually reconfiguring
	 * via devfsadm(1m) to emulate deferred attach.
	 * Reprobe only discovers driver.conf enumerated nodes, more
	 * dynamic implementations probably require their own bus_config.
	 */
	if ((op == BUS_CONFIG_ONE) || (flag & NDI_DRV_CONF_REPROBE))
		flag |= NDI_CONFIG_REPROBE;

	return (ndi_busop_bus_config(parent, flag, op, arg, childp, 0));
}

static int
scsi_hba_bus_unconfig(dev_info_t *parent, uint_t flag, ddi_bus_config_op_t op,
    void *arg)
{
	scsi_hba_tran_t *hba;

	hba = ddi_get_driver_private(parent);
	if (hba && hba->tran_bus_unconfig) {
		return (hba->tran_bus_unconfig(parent, flag, op, arg));
	}
	return (ndi_busop_bus_unconfig(parent, flag, op, arg));
}

/*
 * Convert scsi ascii string data to NULL terminated (semi) legal IEEE 1275
 * "compatible" (name) property form.
 *
 * For ASCII INQUIRY data, a one-way conversion algorithm is needed to take
 * SCSI_ASCII (20h - 7Eh) to a 1275-like compatible form. The 1275 spec allows
 * letters, digits, one ",", and ". _ + -", all limited by a maximum 31
 * character length. Since ", ." are used as separators in the compatible
 * string itself, they are converted to "_". All SCSI_ASCII characters that
 * are illegal in 1275, as well as any illegal SCSI_ASCII characters
 * encountered, are converted to "_". To reduce length, trailing blanks are
 * trimmed from SCSI_ASCII fields prior to conversion.
 *
 * Example: SCSI_ASCII "ST32550W SUN2.1G" -> "ST32550W_SUN2_1G"
 *
 * NOTE: the 1275 string form is always less than or equal to the scsi form.
 */
static char *
string_scsi_to_1275(char *s_1275, char *s_scsi, int len)
{
	(void) strncpy(s_1275, s_scsi, len);
	s_1275[len--] = '\0';

	while (len >= 0) {
		if (s_1275[len] == ' ')
			s_1275[len--] = '\0';	/* trim trailing " " */
		else
			break;
	}

	while (len >= 0) {
		if (((s_1275[len] >= 'a') && (s_1275[len] <= 'z')) ||
		    ((s_1275[len] >= 'A') && (s_1275[len] <= 'Z')) ||
		    ((s_1275[len] >= '0') && (s_1275[len] <= '9')) ||
		    (s_1275[len] == '_') ||
		    (s_1275[len] == '+') ||
		    (s_1275[len] == '-'))
			len--;			/* legal 1275  */
		else
			s_1275[len--] = '_';	/* illegal SCSI_ASCII | 1275 */
	}

	return (s_1275);
}

/*
 * Given the inquiry data, binding_set, and dtype_node for a scsi device,
 * return the nodename and compatible property for the device. The "compatible"
 * concept comes from IEEE-1275.  The compatible information is returned is in
 * the correct form for direct use defining the "compatible" string array
 * property.  Internally, "compatible" is also used to determine the nodename
 * to return.
 *
 * This function is provided as a separate entry point for use by drivers that
 * currently issue their own non-SCSA inquiry command and perform their own
 * node creation based their own private compiled in tables.  Converting these
 * drivers to use this interface provides a quick easy way of obtaining
 * consistency as well as the flexibility associated with the 1275 techniques.
 *
 * The dtype_node is passed as a separate argument (instead of having the
 * implementation use inq_dtype).  It indicates that information about
 * a secondary function embedded service should be produced.
 *
 * Callers must always use scsi_hba_nodename_compatible_free, even if
 * *nodenamep is null, to free the nodename and compatible information
 * when done.
 *
 * If a nodename can't be determined then **compatiblep will point to a
 * diagnostic string containing all the compatible forms.
 *
 * NOTE: some compatible strings may violate the 31 character restriction
 * imposed by IEEE-1275.  This is not a problem because Solaris does not care
 * about this 31 character limit.
 *
 *  The following compatible forms, in high to low precedence
 *  order, are defined for SCSI target device nodes.
 *
 *  scsiclass,DDEEFFF.vVVVVVVVV.pPPPPPPPPPPPPPPPP.rRRRR	(1 *1&2)
 *  scsiclass,DDEE.vVVVVVVVV.pPPPPPPPPPPPPPPPP.rRRRR	(2 *1)
 *  scsiclass,DDFFF.vVVVVVVVV.pPPPPPPPPPPPPPPPP.rRRRR	(3 *2)
 *  scsiclass,DD.vVVVVVVVV.pPPPPPPPPPPPPPPPP.rRRRR	(4)
 *  scsiclass,DDEEFFF.vVVVVVVVV.pPPPPPPPPPPPPPPPP	(5 *1&2)
 *  scsiclass,DDEE.vVVVVVVVV.pPPPPPPPPPPPPPPPP		(6 *1)
 *  scsiclass,DDFFF.vVVVVVVVV.pPPPPPPPPPPPPPPPP		(7 *2)
 *  scsiclass,DD.vVVVVVVVV.pPPPPPPPPPPPPPPPP		(8)
 *  scsa,DD.bBBBBBBBB					(8.5 *3)
 *  scsiclass,DDEEFFF					(9 *1&2)
 *  scsiclass,DDEE					(10 *1)
 *  scsiclass,DDFFF					(11 *2)
 *  scsiclass,DD					(12)
 *  scsiclass						(13)
 *
 *	  *1 only produced on a secondary function node
 *	  *2 only produced on a node with flags
 *	  *3 only produces when binding-set legacy support is needed
 *
 *	where:
 *
 *	v                       is the letter 'v'. Denotest the
 *				beginning of VVVVVVVV.
 *
 *	VVVVVVVV                Translated scsi_vendor.
 *
 *	p                       is the letter 'p'. Denotes the
 *				beginning of PPPPPPPPPPPPPPPP.
 *
 *	PPPPPPPPPPPPPPPP	Translated scsi_product.
 *
 *	r                       is the letter 'r'. Denotes the
 *				beginning of RRRR.
 *
 *	RRRR                    Translated scsi_revision.
 *
 *	DD                      is a two digit ASCII hexadecimal
 *				number.  The value of the two digits is
 *				based one the SCSI "Peripheral device
 *				type" command set associated with the
 *				node.  On a primary node this is the
 *				scsi_dtype of the primary command set,
 *				on a secondary node this is the
 *				scsi_dtype associated with the embedded
 *				function command set.
 *
 *	EE                      Same encoding used for DD. This form is
 *				only generated on secondary function
 *				nodes. The DD function is embedded in
 *				an EE device.
 *
 *	FFF                     Concatenation, in alphabetical order,
 *				of the flag characters below. The
 *				following flag characters are defined:
 *
 *				R       Removable media: Used when
 *					scsi_rmb is set.
 *
 *				Forms using FFF are only be generated
 *				if there are applicable flag
 *				characters.
 *
 *	b                       is the letter 'b'. Denotes the
 *				beginning of BBBBBBBB.
 *
 *	BBBBBBBB                Binding-set. Operating System Specific:
 *				scsi-binding-set property of HBA.
 */
#define	NCOMPAT		(1 + (8 + 1 + 5) + 1)
#define	COMPAT_LONGEST	(strlen( \
	"scsiclass,DDEEFFF.vVVVVVVVV.pPPPPPPPPPPPPPPPP.rRRRR" + 1))
void
scsi_hba_nodename_compatible_get(struct scsi_inquiry *inq, char *binding_set,
    int dtype_node, char *compat0,
    char **nodenamep, char ***compatiblep, int *ncompatiblep)
{
	char	vid[sizeof (inq->inq_vid) + 1 ];
	char	pid[sizeof (inq->inq_pid) + 1];
	char	rev[sizeof (inq->inq_revision) + 1];
	char	f[sizeof ("ER")];
	int	dtype_device;
	int	ncompat;		/* number of compatible */
	char	**compatp;		/* compatible ptrs */
	int	i;
	char	*nname;			/* nodename */
	char	*dname;			/* driver name */
	char	**csp;
	char	*p;
	int	tlen;
	int	len;
	major_t	major;

	/*
	 * Nodename_aliases: This table was originally designed to be
	 * implemented via a new nodename_aliases file - a peer to the
	 * driver_aliases that selects a nodename based on compatible
	 * forms in much the same say driver_aliases is used to select
	 * driver bindings from compatible forms.  Each compatible form
	 * is an 'alias'.  Until a more general need for a
	 * nodename_aliases file exists, which may never occur, the
	 * scsi mappings are described here via a compiled in table.
	 *
	 * This table contains nodename mappings for self-identifying
	 * scsi devices enumerated by the Solaris kernel.  For a given
	 * device, the highest precedence "compatible" form with a
	 * mapping is used to select the nodename for the device. This
	 * will typically be a generic nodename, however in some legacy
	 * compatibility cases a driver nodename mapping may be selected.
	 *
	 * Because of possible breakage associated with switching SCSI
	 * target devices from driver nodenames to generic nodenames,
	 * we are currently unable to support generic nodenames for all
	 * SCSI devices (binding-sets).  Although /devices paths are
	 * defined as unstable, avoiding possible breakage is
	 * important.  Some of the newer SCSI transports (USB) already
	 * use generic nodenames.  All new SCSI transports and target
	 * devices should use generic nodenames. At times this decision
	 * may be architecture dependent (sparc .vs. intel) based on when
	 * a transport was supported on a particular architecture.
	 *
	 * We provide a base set of generic nodename mappings based on
	 * scsiclass dtype and higher-precedence driver nodename
	 * mappings based on scsa "binding-set" to cover legacy
	 * issues.  The binding-set is typically associated with
	 * "scsi-binding-set" property value of the HBA.  The legacy
	 * mappings are provided independent of whether the driver they
	 * refer to is installed.  This allows a correctly named node
	 * be created at discovery time, and binding to occur when/if
	 * an add_drv of the legacy driver occurs.
	 *
	 * We also have mappings for legacy SUN hardware that
	 * misidentifies itself (enclosure services which identify
	 * themselves as processors).  All future hardware should use
	 * the correct dtype.
	 *
	 * As SCSI HBAs are modified to use the SCSA interfaces for
	 * self-identifying SCSI target devices (PSARC/2004/116)  the
	 * nodename_aliases table (PSARC/2004/420) should be augmented
	 * with legacy mappings in order to maintain compatibility with
	 * existing /devices paths, especially for devices that house
	 * an OS.  Failure to do this may cause upgrade problems.
	 * Additions for new target devices or transports should not
	 * add scsa binding-set compatible mappings.
	 */
	static struct nodename_aliases {
		char	*na_nodename;		/* nodename */
		char	*na_alias;		/* compatible form match */
	} na[] = {
	/* # mapping to generic nodenames based on scsi dtype */
		{"disk",		"scsiclass,00"},
		{"tape",		"scsiclass,01"},
		{"printer",		"scsiclass,02"},
		{"processor",		"scsiclass,03"},
		{"worm",		"scsiclass,04"},
		{"cdrom",		"scsiclass,05"},
		{"scanner",		"scsiclass,06"},
		{"optical-disk",	"scsiclass,07"},
		{"medium-changer",	"scsiclass,08"},
		{"obsolete",		"scsiclass,09"},
		{"prepress-a",		"scsiclass,0a"},
		{"prepress-b",		"scsiclass,0b"},
		{"array-controller",	"scsiclass,0c"},
		{"enclosure",		"scsiclass,0d"},
		{"disk",		"scsiclass,0e"},
		{"card-reader",		"scsiclass,0f"},
		{"bridge",		"scsiclass,10"},
		{"object-store",	"scsiclass,11"},
		{"reserved",		"scsiclass,12"},
		{"reserved",		"scsiclass,13"},
		{"reserved",		"scsiclass,14"},
		{"reserved",		"scsiclass,15"},
		{"reserved",		"scsiclass,16"},
		{"reserved",		"scsiclass,17"},
		{"reserved",		"scsiclass,18"},
		{"reserved",		"scsiclass,19"},
		{"reserved",		"scsiclass,1a"},
		{"reserved",		"scsiclass,1b"},
		{"reserved",		"scsiclass,1c"},
		{"reserved",		"scsiclass,1d"},
		{"well-known-lun",	"scsiclass,1e"},
		{"unknown",		"scsiclass,1f"},

#ifdef	sparc
	/* # legacy mapping to driver nodenames for fcp binding-set */
		{"ssd",			"scsa,00.bfcp"},
		{"st",			"scsa,01.bfcp"},
		{"sgen",		"scsa,08.bfcp"},
		{"ses",			"scsa,0d.bfcp"},

	/* # legacy mapping to driver nodenames for vhci binding-set */
		{"ssd",			"scsa,00.bvhci"},
		{"st",			"scsa,01.bvhci"},
		{"sgen",		"scsa,08.bvhci"},
		{"ses",			"scsa,0d.bvhci"},
#else	/* sparc */
	/* # for x86 fcp and vhci use generic nodenames */
#endif	/* sparc */

#ifdef	notdef
	/*
	 * The following binding-set specific mappings are not being
	 * delivered at this time, but are listed here as an examples of
	 * the type of mappings needed.
	 */

	/* # legacy mapping to driver nodenames for spi binding-set */
		{"sd",			"scsa,00.bspi"},
		{"sd",			"scsa,05.bspi"},
		{"sd",			"scsa,07.bspi"},
		{"st",			"scsa,01.bspi"},
		{"ses",			"scsa,0d.bspi"},

	/* #				SUN misidentified spi hardware */
		{"ses",			"scsiclass,03.vSUN.pD2"},
		{"ses",			"scsiclass,03.vSYMBIOS.pD1000"},

	/* # legacy mapping to driver nodenames for atapi binding-set */
		{"sd",			"scsa,00.batapi"},
		{"sd",			"scsa,05.batapi"},
		{"sd",			"scsa,07.batapi"},
		{"st",			"scsa,01.batapi"},
		{"unknown",		"scsa,0d.batapi"},

	/* # legacy mapping to generic nodenames for usb binding-set */
		{"disk",		"scsa,05.busb"},
		{"disk",		"scsa,07.busb"},
		{"changer",		"scsa,08.busb"},
		{"comm",		"scsa,09.busb"},
		{"array_ctlr",		"scsa,0c.busb"},
		{"esi",			"scsa,0d.busb"},
#endif	/* notdef */

	/*
	 * mapping nodenames for mpt based on scsi dtype
	 * for being compatible with the original node names
	 * under mpt controller
	 */
		{"sd",			"scsa,00.bmpt"},
		{"sd",			"scsa,05.bmpt"},
		{"sd",			"scsa,07.bmpt"},
		{"st",			"scsa,01.bmpt"},
		{"ses",			"scsa,0d.bmpt"},
		{"sgen",		"scsa,08.bmpt"},
		{NULL,		NULL}
	};
	struct nodename_aliases *nap;

	ASSERT(nodenamep && compatiblep && ncompatiblep &&
	    (binding_set == NULL || (strlen(binding_set) <= 8)));
	if ((nodenamep == NULL) || (compatiblep == NULL) ||
	    (ncompatiblep == NULL))
		return;

	/*
	 * In order to reduce runtime we allocate one block of memory that
	 * contains both the NULL terminated array of pointers to compatible
	 * forms and the individual compatible strings.  This block is
	 * somewhat larger than needed, but is short lived - it only exists
	 * until the caller can transfer the information into the "compatible"
	 * string array property and call scsi_hba_nodename_compatible_free.
	 */
	tlen = NCOMPAT * COMPAT_LONGEST;
	compatp = kmem_alloc((NCOMPAT * sizeof (char *)) + tlen, KM_SLEEP);

	/* convert inquiry data from SCSI ASCII to 1275 string */
	(void) string_scsi_to_1275(vid, inq->inq_vid,
	    sizeof (inq->inq_vid));
	(void) string_scsi_to_1275(pid, inq->inq_pid,
	    sizeof (inq->inq_pid));
	(void) string_scsi_to_1275(rev, inq->inq_revision,
	    sizeof (inq->inq_revision));
	ASSERT((strlen(vid) <= sizeof (inq->inq_vid)) &&
	    (strlen(pid) <= sizeof (inq->inq_pid)) &&
	    (strlen(rev) <= sizeof (inq->inq_revision)));

	/*
	 * Form flags alphabetically:
	 * R - removable:
	 *	Set when inq_rmb is set and for well known scsi dtypes.  For a
	 *	bus where the entire device is removable (like USB), we expect
	 *	the HBA to intercept the inquiry data and set inq_rmb.
	 *	Since OBP does not distinguish removable media in its generic
	 *	name selection we avoid setting the 'R' flag if the root is not
	 *	yet mounted.
	 */
	dtype_device = inq->inq_dtype & DTYPE_MASK;
	i = 0;
	if (rootvp && (inq->inq_rmb ||
	    (dtype_device == DTYPE_WORM) ||
	    (dtype_device == DTYPE_RODIRECT) ||
	    (dtype_device == DTYPE_OPTICAL)))
		f[i++] = 'R';
	f[i] = '\0';

	/*
	 * Construct all applicable compatible forms. See comment at the
	 * head of the function for a description of the compatible forms.
	 */
	csp = compatp;
	p = (char *)(compatp + NCOMPAT);


	/* ( 0) driver (optional, not documented in scsi(4)) */
	if (compat0) {
		*csp++ = p;
		(void) snprintf(p, tlen, "%s", compat0);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* ( 1) scsiclass,DDEEF.vV.pP.rR */
	if ((dtype_device != dtype_node) && *f && *vid && *pid && *rev) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x%02x%s.v%s.p%s.r%s",
		    dtype_node, dtype_device, f, vid, pid, rev);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* ( 2) scsiclass,DDEE.vV.pP.rR */
	if ((dtype_device != dtype_node) && *vid && *pid && *rev) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x%02x.v%s.p%s.r%s",
		    dtype_node, dtype_device, vid, pid, rev);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* ( 3) scsiclass,DDF.vV.pP.rR */
	if (*f && *vid && *pid && *rev) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x%s.v%s.p%s.r%s",
		    dtype_node, f, vid, pid, rev);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* ( 4) scsiclass,DD.vV.pP.rR */
	if (*vid && *pid && rev) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x.v%s.p%s.r%s",
		    dtype_node, vid, pid, rev);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* ( 5) scsiclass,DDEEF.vV.pP */
	if ((dtype_device != dtype_node) && *f && *vid && *pid) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x%02x%s.v%s.p%s",
		    dtype_node, dtype_device, f, vid, pid);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* ( 6) scsiclass,DDEE.vV.pP */
	if ((dtype_device != dtype_node) && *vid && *pid) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x%02x.v%s.p%s",
		    dtype_node, dtype_device, vid, pid);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* ( 7) scsiclass,DDF.vV.pP */
	if (*f && *vid && *pid) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x%s.v%s.p%s",
		    dtype_node, f, vid, pid);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* ( 8) scsiclass,DD.vV.pP */
	if (*vid && *pid) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x.v%s.p%s",
		    dtype_node, vid, pid);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* (8.5) scsa,DD.bB (not documented in scsi(4)) */
	if (binding_set) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsa,%02x.b%s",
		    dtype_node, binding_set);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* ( 9) scsiclass,DDEEF */
	if ((dtype_device != dtype_node) && *f) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x%02x%s",
		    dtype_node, dtype_device, f);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* (10) scsiclass,DDEEF */
	if (dtype_device != dtype_node) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x%02x",
		    dtype_node, dtype_device);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* (11) scsiclass,DDF */
	if (*f) {
		*csp++ = p;
		(void) snprintf(p, tlen, "scsiclass,%02x%s",
		    dtype_node, f);
		len = strlen(p) + 1;
		p += len;
		tlen -= len;
	}

	/* (12) scsiclass,DD */
	*csp++ = p;
	(void) snprintf(p, tlen, "scsiclass,%02x", dtype_node);
	len = strlen(p) + 1;
	p += len;
	tlen -= len;

	/* (13) scsiclass */
	*csp++ = p;
	(void) snprintf(p, tlen, "scsiclass");
	len = strlen(p) + 1;
	p += len;
	tlen -= len;
	ASSERT(tlen >= 0);

	*csp = NULL;			/* NULL terminate array of pointers */
	ncompat = csp - compatp;

	/*
	 * When determining a nodename, a nodename_aliases specified
	 * mapping has precedence over using a driver_aliases specified
	 * driver binding as a nodename.
	 *
	 * See if any of the compatible forms have a nodename_aliases
	 * specified nodename.  These mappings are described by
	 * nodename_aliases entries like:
	 *
	 *	disk		"scsiclass,00"
	 *	enclosure	"scsiclass,03.vSYMBIOS.pD1000"
	 *	ssd		"scsa,00.bfcp"
	 *
	 * All nodename_aliases mappings should idealy be to generic
	 * names, however a higher precedence legacy mapping to a
	 * driver name may exist.  The highest precedence mapping
	 * provides the nodename, so legacy driver nodename mappings
	 * (if they exist) take precedence over generic nodename
	 * mappings.
	 */
	for (nname = NULL, csp = compatp; (nname == NULL) && *csp; csp++) {
		for (nap = na; nap->na_nodename; nap++) {
			if (strcmp(*csp, nap->na_alias) == 0) {
				nname = nap->na_nodename;
				break;
			}
		}
	}

	/*
	 * If no nodename_aliases mapping exists then use the
	 * driver_aliases specified driver binding as a nodename.
	 * Determine the driver based on compatible (which may
	 * have the passed in compat0 as the first item). The
	 * driver_aliases file has entries like
	 *
	 *	sd	"scsiclass,00"
	 *
	 * that map compatible forms to specific drivers.  These
	 * entries are established by add_drv. We use the most specific
	 * driver binding as the nodename. This matches the eventual
	 * ddi_driver_compatible_major() binding that will be
	 * established by bind_node()
	 */
	if (nname == NULL) {
		for (dname = NULL, csp = compatp; *csp; csp++) {
			major = ddi_name_to_major(*csp);
			if ((major == (major_t)-1) ||
			    (devnamesp[major].dn_flags & DN_DRIVER_REMOVED))
				continue;
			if (dname = ddi_major_to_name(major))
				break;
		}
		nname = dname;
	}

	/* return results */
	if (nname) {
		*nodenamep = kmem_alloc(strlen(nname) + 1, KM_SLEEP);
		(void) strcpy(*nodenamep, nname);
	} else {
		*nodenamep = NULL;

		/*
		 * If no nodename could be determined return a special
		 * 'compatible' to be used for a diagnostic message. This
		 * compatible contains all compatible forms concatenated
		 * into a single string pointed to by the first element.
		 */
		if (nname == NULL) {
			for (csp = compatp; *(csp + 1); csp++)
				*((*csp) + strlen(*csp)) = ' ';
			*(compatp + 1) = NULL;
			ncompat = 1;
		}

	}
	*compatiblep = compatp;
	*ncompatiblep = ncompat;
}

/* Free allocations associated with scsi_hba_nodename_compatible_get use. */
void
scsi_hba_nodename_compatible_free(char *nodename, char **compatible)
{
	if (nodename)
		kmem_free(nodename, strlen(nodename) + 1);

	if (compatible)
		kmem_free(compatible, (NCOMPAT * sizeof (char *)) +
		    (NCOMPAT * COMPAT_LONGEST));
}

/*ARGSUSED*/
static int
scsi_hba_fm_init_child(dev_info_t *self, dev_info_t *child, int cap,
    ddi_iblock_cookie_t *ibc)
{
	scsi_hba_tran_t	*hba = ddi_get_driver_private(self);

	return (hba ? hba->tran_fm_capable : scsi_fm_capable);
}

static int
scsi_hba_bus_power(dev_info_t *parent, void *impl_arg, pm_bus_power_op_t op,
    void *arg, void *result)
{
	scsi_hba_tran_t *hba;

	hba = ddi_get_driver_private(parent);
	if (hba && hba->tran_bus_power) {
		return (hba->tran_bus_power(parent, impl_arg, op, arg, result));
	}

	return (pm_busop_bus_power(parent, impl_arg, op, arg, result));
}
