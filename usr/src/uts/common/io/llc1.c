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


/*
 * llc1 - an LLC Class 1 MUX compatible with SunConnect LLC2 uses DLPI
 * interface.  Its primary use is to support RPL for network boot but can be
 * used by other protocols.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/mkdev.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/devops.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/strsun.h>
#include <sys/stat.h>
#include <netinet/in.h> /* for byteorder macros on machines that define them */
#include <sys/llc1.h>
#include <sys/kstat.h>
#include <sys/debug.h>

/*
 * function prototypes, etc.
 */
static int llc1_open(queue_t *q, dev_t *dev, int flag, int sflag,
	cred_t *cred);
static int llc1_close(queue_t *q, int flag, cred_t *cred);
static int llc1_uwput(queue_t *q, mblk_t *mp);
static int llc1_uwsrv(queue_t *q);
static int llc1_lrsrv(queue_t *q);
static int llc1_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int llc1_detach(dev_info_t *dev, ddi_detach_cmd_t cmd);
static int llc1_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd);

static mblk_t *llc1_form_udata(llc1_t *lld, llc_mac_info_t *macinfo,
	mblk_t *mp);
static mblk_t *llc1_xid_reply(llc_mac_info_t *macinfo, mblk_t *mp, int sap);
static mblk_t *llc1_xid_ind_con(llc1_t *lld, llc_mac_info_t *macinfo,
	mblk_t *mp);
static mblk_t *llc1_test_reply(llc_mac_info_t *macinfo, mblk_t *mp, int sap);
static mblk_t *llc1_test_ind_con(llc1_t *lld, llc_mac_info_t *macinfo,
	mblk_t *mp);

static void llc1_ioctl(queue_t *q, mblk_t *mp);
static void llc1_recv(llc_mac_info_t *macinfo, mblk_t *mp);
static void llc1_req_raw(llc_mac_info_t *macinfo);
static void llc1_find_waiting(llc_mac_info_t *macinfo, mblk_t *mp, long prim);

static minor_t llc1_findminor(llc1dev_t *device);
static void llc1_send_disable_multi(llc_mac_info_t *, llc_mcast_t *);

static void llc1insque(void *elem, void *pred);
static void llc1remque(void *arg);
static void llc1error();
static int llc1_subs_unbind(void);
static void llc1_init_kstat(llc_mac_info_t *macinfo);
static void llc1_uninit_kstat(llc_mac_info_t *macinfo);
static int llc1_update_kstat(kstat_t *ksp, int rw);
static int llc1_broadcast(struct ether_addr *addr, llc_mac_info_t *macinfo);
static int llc1_unbind(queue_t *q, mblk_t *mp);
static int llc1_subs_bind(queue_t *q, mblk_t *mp);
static int llc1_unitdata(queue_t *q, mblk_t *mp);
static int llc1_inforeq(queue_t *q, mblk_t *mp);
static int llc1attach(queue_t *q, mblk_t *mp);
static void llc1_send_bindreq(llc_mac_info_t *macinfo);
static int llc1_req_info(queue_t *q);
static int llc1_cmds(queue_t *q, mblk_t *mp);
static int llc1_setppa(struct ll_snioc *snioc);
static int llc1_getppa(llc_mac_info_t *macinfo, struct ll_snioc *snioc);
static int llc1_bind(queue_t *q, mblk_t *mp);
static int llc1unattach(queue_t *q, mblk_t *mp);
static int llc1_enable_multi(queue_t *q, mblk_t *mp);
static int llc1_disable_multi(queue_t *q, mblk_t *mp);
static int llc1_xid_req_res(queue_t *q, mblk_t *mp, int req_or_res);
static int llc1_test_req_res(queue_t *q, mblk_t *mp, int req_or_res);
static int llc1_local(struct ether_addr *addr, llc_mac_info_t *macinfo);
static int llc1_snap_match(llc1_t *lld, struct snaphdr *snap);

/*
 * the standard streams glue for defining the type of streams entity and the
 * operational parameters.
 */

static struct module_info llc1_minfo = {
	LLC1IDNUM,
	"llc1",
	0,
	LLC1_DEFMAX,
	LLC1_HIWATER,		/* high water mark */
	LLC1_LOWATER,		/* low water mark */
};

static struct qinit llc1_rint = {
	NULL,
	NULL,
	llc1_open,
	llc1_close,
	NULL,
	&llc1_minfo,
	NULL
};

static struct qinit llc1_wint = {
	llc1_uwput,
	llc1_uwsrv,
	NULL,
	NULL,
	NULL,
	&llc1_minfo,
	NULL
};

static struct qinit llc1_muxrint = {
	putq,
	llc1_lrsrv,
	NULL,
	NULL,
	NULL,
	&llc1_minfo,
	NULL
};

static struct qinit llc1_muxwint = {
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	&llc1_minfo,
	NULL
};

struct streamtab llc1_info = {
	&llc1_rint,
	&llc1_wint,
	&llc1_muxrint,
	&llc1_muxwint
};

/*
 * loadable module/driver wrapper this allows llc1 to be unloaded later
 */

#if !defined(BUILD_STATIC)
#include <sys/modctl.h>

/* define the "ops" structure for a STREAMS driver */
DDI_DEFINE_STREAM_OPS(llc1_ops, nulldev, nulldev, llc1_attach,
    llc1_detach, nodev, llc1_getinfo, D_MP | D_MTPERMOD, &llc1_info,
    ddi_quiesce_not_supported);

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"LLC Class 1 Driver",
	&llc1_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

#endif

#ifdef LLC1_DEBUG
extern int llc1_debug = 0x0;

#endif

/*
 * Allocate and zero-out "number" structures each of type "structure" in
 * kernel memory.
 */
#define	GETSTRUCT(structure, number)   \
	(kmem_zalloc(sizeof (structure) * (number), KM_NOSLEEP))
#define	GETBUF(structure, size) \
	(kmem_zalloc(size, KM_NOSLEEP))

static struct llc1device llc1_device_list;

/*
 * llc1_attach - init time attach support When the hardware specific attach
 * is called, it must call this procedure with the device class structure
 */

static int
llc1_attach(dev_info_t *devinfo, ddi_attach_cmd_t cmd)
{
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	/*
	 * there isn't any hardware but we do need to initialize things
	 */
	if (!(llc1_device_list.llc1_status & LLC1_ATTACHED)) {
		llc1_device_list.llc1_status |= LLC1_ATTACHED;
		rw_init(&llc1_device_list.llc1_rwlock, NULL, RW_DRIVER, NULL);

		/* make sure minor device lists are initialized */
		llc1_device_list.llc1_str_next =
		    llc1_device_list.llc1_str_prev =
		    (llc1_t *)&llc1_device_list.llc1_str_next;

		/* make sure device list is initialized */
		llc1_device_list.llc1_mac_next =
		    llc1_device_list.llc1_mac_prev =
		    (llc_mac_info_t *)&llc1_device_list.llc1_mac_next;
	}

	/*
	 * now do all the DDI stuff necessary
	 */

	ddi_set_driver_private(devinfo, &llc1_device_list);

	/*
	 * create the file system device node
	 */
	if (ddi_create_minor_node(devinfo, "llc1", S_IFCHR,
	    0, DDI_PSEUDO, CLONE_DEV) == DDI_FAILURE) {
		llc1error(devinfo, "ddi_create_minor_node failed");
		ddi_remove_minor_node(devinfo, NULL);
		return (DDI_FAILURE);
	}
	llc1_device_list.llc1_multisize = ddi_getprop(DDI_DEV_T_NONE,
	    devinfo, 0, "multisize", 0);
	if (llc1_device_list.llc1_multisize == 0)
		llc1_device_list.llc1_multisize = LLC1_MAX_MULTICAST;

	ddi_report_dev(devinfo);
	return (DDI_SUCCESS);
}

/*
 * llc1_detach standard kernel interface routine
 */

static int
llc1_detach(dev_info_t *dev, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}
	if (llc1_device_list.llc1_ndevice > 0)
		return (DDI_FAILURE);
	/* remove all mutex and locks */
	rw_destroy(&llc1_device_list.llc1_rwlock);
	llc1_device_list.llc1_status = 0;	/* no longer attached */
	ddi_remove_minor_node(dev, NULL);
	return (DDI_SUCCESS);
}

/*
 * llc1_devinfo(dev, cmd, arg, result) standard kernel devinfo lookup
 * function
 */
/*ARGSUSED2*/
static int
llc1_getinfo(dev_info_t *dev, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int error;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (dev == NULL) {
			error = DDI_FAILURE;
		} else {
			*result = (void *)dev;
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/*
 * llc1_open()
 * LLC1 open routine, called when device is opened by the user
 */

/*ARGSUSED2*/
static int
llc1_open(queue_t *q, dev_t *dev, int flag, int sflag, cred_t *cred)
{
	llc1_t *llc1;
	minor_t	minordev;
	int	status = 0;

	ASSERT(q);

	/*
	 * Stream already open, sucess.
	 */
	if (q->q_ptr)
		return (0);
	/*
	 * Serialize access through open/close this will serialize across all
	 * llc1 devices, but open and close are not frequent so should not
	 * induce much, if any delay.
	 */
	rw_enter(&llc1_device_list.llc1_rwlock, RW_WRITER);

	if (sflag == CLONEOPEN) {
		/* need to find a minor dev */
		minordev = llc1_findminor(&llc1_device_list);
		if (minordev == 0) {
			rw_exit(&llc1_device_list.llc1_rwlock);
			return (ENXIO);
		}
		*dev = makedevice(getmajor(*dev), minordev);
	} else {
		minordev = getminor (*dev);
		if ((minordev > MAXMIN32) || (minordev == 0)) {
			rw_exit(&llc1_device_list.llc1_rwlock);
			return (ENXIO);
		}
	}

	/*
	 * get a per-stream structure and link things together so we
	 * can easily find them later.
	 */

	llc1 = kmem_zalloc(sizeof (llc1_t), KM_SLEEP);
	llc1->llc_qptr = q;
	WR(q)->q_ptr = q->q_ptr = (caddr_t)llc1;
	/*
	 * fill in the structure and state info
	 */
	llc1->llc_state = DL_UNATTACHED;
	llc1->llc_style = DL_STYLE2;
	llc1->llc_minor = minordev;

	mutex_init(&llc1->llc_lock, NULL, MUTEX_DRIVER, NULL);
	llc1insque(llc1, llc1_device_list.llc1_str_prev);
	rw_exit(&llc1_device_list.llc1_rwlock);
	qprocson(q);		/* start the queues running */
	return (status);
}

/*
 * llc1_close(q)
 * normal stream close call checks current status and cleans up
 * data structures that were dynamically allocated
 */
/*ARGSUSED1*/
static int
llc1_close(queue_t *q, int flag, cred_t *cred)
{
	llc1_t *llc1;

	ASSERT(q);
	ASSERT(q->q_ptr);

	qprocsoff(q);
	llc1 = (llc1_t *)q->q_ptr;
	rw_enter(&llc1_device_list.llc1_rwlock, RW_WRITER);
	/* completely disassociate the stream from the device */
	q->q_ptr = WR(q)->q_ptr = NULL;

	(void) llc1remque(llc1); /* remove from active list */
	rw_exit(&llc1_device_list.llc1_rwlock);

	mutex_enter(&llc1->llc_lock);
	if (llc1->llc_state == DL_IDLE || llc1->llc_state == DL_UNBOUND) {
		llc1->llc_state = DL_UNBOUND;	/* force the issue */
	}

	if (llc1->llc_mcast != NULL) {
		int	i;

		for (i = 0; i < llc1_device_list.llc1_multisize; i++) {
			llc_mcast_t *mcast;

			if ((mcast = llc1->llc_mcast[i]) != NULL) {
				/*
				 * disable from stream and possibly
				 * lower stream
				 */
				if (llc1->llc_mac_info &&
				    llc1->llc_mac_info->llcp_flags &
				    LLC1_AVAILABLE)
					llc1_send_disable_multi(
					    llc1->llc_mac_info,
					    mcast);
				llc1->llc_mcast[i] = NULL;
			}
		}
		kmem_free(llc1->llc_mcast,
		    sizeof (llc_mcast_t *) * llc1->llc_multicnt);
		llc1->llc_mcast = NULL;
	}
	llc1->llc_state = DL_UNATTACHED;

	mutex_exit(&llc1->llc_lock);

	mutex_destroy(&llc1->llc_lock);

	kmem_free(llc1, sizeof (llc1_t));

	return (0);
}

/*
 * llc1_uwput()
 * general llc stream write put routine. Receives ioctl's from
 * user level and data from upper modules and processes them immediately.
 * M_PROTO/M_PCPROTO are queued for later processing by the service
 * procedure.
 */

static int
llc1_uwput(queue_t *q, mblk_t *mp)
{
	llc1_t *ld = (llc1_t *)(q->q_ptr);

#ifdef LLC1_DEBUG
	if (llc1_debug & LLCTRACE)
		printf("llc1_wput(%x %x): type %d\n", q, mp, DB_TYPE(mp));
#endif
	switch (DB_TYPE(mp)) {

	case M_IOCTL:		/* no waiting in ioctl's */
		(void) llc1_ioctl(q, mp);
		break;

	case M_FLUSH:		/* canonical flush handling */
		if (*mp->b_rptr & FLUSHW)
			flushq(q, 0);

		if (*mp->b_rptr & FLUSHR) {
			flushq(RD(q), 0);
			*mp->b_rptr &= ~FLUSHW;
			qreply(q, mp);
		} else
			freemsg(mp);
		break;

		/* for now, we will always queue */
	case M_PROTO:
	case M_PCPROTO:
		(void) putq(q, mp);
		break;

	case M_DATA:
		/* fast data / raw support */
		if ((ld->llc_flags & (LLC_RAW | LLC_FAST)) == 0 ||
		    ld->llc_state != DL_IDLE) {
			(void) merror(q, mp, EPROTO);
			break;
		}
		/* need to do further checking */
		(void) putq(q, mp);
		break;

	default:
#ifdef LLC1_DEBUG
		if (llc1_debug & LLCERRS)
			printf("llc1: Unexpected packet type from queue: %d\n",
			    mp->b_datap->db_type);
#endif
		freemsg(mp);
	}
	return (0);
}

/*
 * llc1_lrsrv()
 * called when data is put into the service queue from below.
 * Determines additional processing that might be needed and sends the data
 * upstream in the form of a Data Indication packet.
 */
static int
llc1_lrsrv(queue_t *q)
{
	mblk_t *mp;
	union DL_primitives *prim;
	llc_mac_info_t *macinfo = (llc_mac_info_t *)q->q_ptr;
	struct iocblk *iocp;

#ifdef LLC1_DEBUG
	if (llc1_debug & LLCTRACE)
		printf("llc1_rsrv(%x)\n", q);
	if (llc1_debug & LLCRECV) {
		printf("llc1_lrsrv: q=%x macinfo=%x", q, macinfo);
		if (macinfo == NULL) {
			printf("NULL macinfo");
			panic("null macinfo in lrsrv");
			/*NOTREACHED*/
		}
		printf("\n");
	}
#endif

	/*
	 * determine where message goes, then call the proper handler
	 */

	while ((mp = getq(q)) != NULL) {
		switch (DB_TYPE(mp)) {
		case M_PROTO:
		case M_PCPROTO:
			prim = (union DL_primitives *)mp->b_rptr;
			/* only some primitives ever get passed through */
			switch (prim->dl_primitive) {
			case DL_INFO_ACK:
				if (macinfo->llcp_flags & LLC1_LINKED) {
					/*
					 * we are in the midst of completing
					 * the I_LINK/I_PLINK and needed this
					 * info
					 */
					macinfo->llcp_flags &= ~LLC1_LINKED;
					macinfo->llcp_flags |= LLC1_AVAILABLE;
					macinfo->llcp_maxpkt =
					    prim->info_ack.dl_max_sdu;
					macinfo->llcp_minpkt =
					    prim->info_ack.dl_min_sdu;
					macinfo->llcp_type =
					    prim->info_ack.dl_mac_type;
					if (macinfo->llcp_type == DL_ETHER) {
						macinfo->llcp_type = DL_CSMACD;
						/*
						 * size of max header
						 * (including SNAP)
						 */
						macinfo->llcp_maxpkt -= 8;
					}
					macinfo->llcp_addrlen =
					    prim->info_ack.dl_addr_length -
					    ABS(prim->info_ack.dl_sap_length);

					bcopy(mp->b_rptr +
					    prim->info_ack.dl_addr_offset,
					    macinfo->llcp_macaddr,
					    macinfo->llcp_addrlen);
					bcopy(mp->b_rptr +
					    prim->info_ack.
					    dl_brdcst_addr_offset,
					    macinfo->llcp_broadcast,
					    prim->info_ack.
					    dl_brdcst_addr_length);

					if (prim->info_ack.dl_current_state ==
					    DL_UNBOUND)
						llc1_send_bindreq(macinfo);
					freemsg(mp);
					/*
					 * need to put the lower stream into
					 * DLRAW mode.  Currently only DL_ETHER
					 * or DL_CSMACD
					 */
					switch (macinfo->llcp_type) {
					case DL_ETHER:
					case DL_CSMACD:
						/*
						 * raw mode is optimal so ask
						 * for it * we might not get
						 * it but that's OK
						 */
						llc1_req_raw(macinfo);
						break;
					default:
						/*
						 * don't want raw mode so don't
						 * ask for it
						 */
						break;
					}
				} else {
					if (prim->info_ack.dl_current_state ==
					    DL_IDLE)
					/* address was wrong before */
					bcopy(mp->b_rptr +
					    prim->info_ack.dl_addr_offset,
					    macinfo->llcp_macaddr,
					    macinfo->llcp_addrlen);
					freemsg(mp);
				}
				break;
			case DL_BIND_ACK:
				/*
				 * if we had to bind, the macaddr is wrong
				 * so get it again
				 */
				freemsg(mp);
				(void) llc1_req_info(q);
				break;
			case DL_UNITDATA_IND:
				/* when not using raw mode we get these */
				(void) llc1_recv(macinfo, mp);
				break;
			case DL_ERROR_ACK:
				/* binding is a special case */
				if (prim->error_ack.dl_error_primitive ==
				    DL_BIND_REQ) {
					freemsg(mp);
					if (macinfo->llcp_flags & LLC1_BINDING)
						llc1_send_bindreq(macinfo);
				} else
					llc1_find_waiting(macinfo, mp,
					    prim->error_ack.dl_error_primitive);
				break;
			case DL_PHYS_ADDR_ACK:
				llc1_find_waiting(macinfo, mp,
				    DL_PHYS_ADDR_REQ);
				break;
			case DL_OK_ACK:
				if (prim->ok_ack.dl_correct_primitive ==
				    DL_BIND_REQ)
					macinfo->llcp_flags &= ~LLC1_BINDING;
				/* FALLTHROUGH */
			default:
				freemsg(mp);
			}
			break;

		case M_IOCACK:
			/* probably our DLIOCRAW completing */
			iocp = (struct iocblk *)mp->b_rptr;
			if ((macinfo->llcp_flags & LLC1_RAW_WAIT) &&
			    macinfo->llcp_iocid == iocp->ioc_id) {
				macinfo->llcp_flags &= ~LLC1_RAW_WAIT;
				/* we can use this form */
				macinfo->llcp_flags |= LLC1_USING_RAW;
				freemsg(mp);
				break;
			}
			/* need to find the correct queue */
			freemsg(mp);
			break;
		case M_IOCNAK:
			iocp = (struct iocblk *)mp->b_rptr;
			if ((macinfo->llcp_flags & LLC1_RAW_WAIT) &&
			    macinfo->llcp_iocid == iocp->ioc_id) {
				macinfo->llcp_flags &= ~LLC1_RAW_WAIT;
				freemsg(mp);
				break;
			}
			/* need to find the correct queue */
			freemsg(mp);
			break;
		case M_DATA:
			llc1_recv(macinfo, mp);
			break;
		}
	}
	return (0);
}

/*
 * llc1_uwsrv - Incoming messages are processed according to the DLPI
 * protocol specification
 */

static int
llc1_uwsrv(queue_t *q)
{
	mblk_t *mp;
	llc1_t *lld = (llc1_t *)q->q_ptr;
	union DL_primitives *prim;
	int	err;

#ifdef LLC1_DEBUG
	if (llc1_debug & LLCTRACE)
		printf("llc1_wsrv(%x)\n", q);
#endif


	while ((mp = getq(q)) != NULL) {
		switch (mp->b_datap->db_type) {
		case M_PROTO:	/* Will be an DLPI message of some type */
		case M_PCPROTO:
			if ((err = llc1_cmds(q, mp)) != LLCE_OK) {
				prim = (union DL_primitives *)mp->b_rptr;
				if (err == LLCE_NOBUFFER || err == DL_SYSERR) {
					/* quit while we're ahead */
					lld->llc_stats->llcs_nobuffer++;
#ifdef LLC1_DEBUG
					if (llc1_debug & LLCERRS)
						printf(
"llc1_cmds: nonfatal err=%d\n",
						    err);
#endif
					(void) putbq(q, mp);
					return (0);

				} else {
					dlerrorack(q, mp,
					    prim->dl_primitive,
					    err, 0);
				}
			}
			break;
		case M_DATA:
			/*
			 * retry of a previously processed
			 * UNITDATA_REQ or is a RAW message from
			 * above
			 */

			mutex_enter(&lld->llc_lock);
			putnext(lld->llc_mac_info->llcp_queue, mp);
			mutex_exit(&lld->llc_lock);
			freemsg(mp);	/* free on success */
			break;

			/* This should never happen */
		default:
#ifdef LLC1_DEBUG
			if (llc1_debug & LLCERRS)
				printf("llc1_wsrv: type(%x) not supported\n",
				    mp->b_datap->db_type);
#endif
			freemsg(mp);	/* unknown types are discarded */
			break;
		}
	}
	return (0);
}

/*
 * llc1_multicast used to determine if the address is a multicast address for
 * this user.
 */
int
llc1_multicast(struct ether_addr *addr, llc1_t *lld)
{
	int i;

	if (lld->llc_mcast)
		for (i = 0; i < lld->llc_multicnt; i++)
			if (lld->llc_mcast[i] &&
			    lld->llc_mcast[i]->llcm_refcnt &&
			    bcmp(lld->llc_mcast[i]->llcm_addr,
			    addr->ether_addr_octet, ETHERADDRL) == 0)
				return (1);
	return (0);
}

/*
 * llc1_ioctl handles all ioctl requests passed downstream. This routine is
 * passed a pointer to the message block with the ioctl request in it, and a
 * pointer to the queue so it can respond to the ioctl request with an ack.
 */

int	llc1_doreqinfo;

static void
llc1_ioctl(queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp;
	llc1_t *lld;
	struct linkblk *link;
	llc_mac_info_t *macinfo;
	mblk_t *tmp;
	int error;

#ifdef LLC1_DEBUG
	if (llc1_debug & LLCTRACE)
		printf("llc1_ioctl(%x %x)\n", q, mp);
#endif
	lld = (llc1_t *)q->q_ptr;
	iocp = (struct iocblk *)mp->b_rptr;
	switch (iocp->ioc_cmd) {
		/* XXX need to lock the data structures */
	case I_PLINK:
	case I_LINK:
		link = (struct linkblk *)mp->b_cont->b_rptr;
		tmp = allocb(sizeof (llc_mac_info_t), BPRI_MED);
		if (tmp == NULL) {
			(void) miocnak(q, mp, 0, ENOSR);
			return;
		}
		bzero(tmp->b_rptr, sizeof (llc_mac_info_t));
		macinfo = (llc_mac_info_t *)tmp->b_rptr;
		macinfo->llcp_mb = tmp;
		macinfo->llcp_next = macinfo->llcp_prev = macinfo;
		macinfo->llcp_queue = link->l_qbot;
		macinfo->llcp_lindex = link->l_index;
		/* tentative */
		macinfo->llcp_ppa = --llc1_device_list.llc1_nextppa;
		llc1_device_list.llc1_ndevice++;
		macinfo->llcp_flags |= LLC1_LINKED | LLC1_DEF_PPA;
		macinfo->llcp_lqtop = q;
		macinfo->llcp_data = NULL;

		/* need to do an info_req before an info_req or attach */

		rw_enter(&llc1_device_list.llc1_rwlock, RW_WRITER);
		llc1insque(macinfo, llc1_device_list.llc1_mac_prev);
		macinfo->llcp_queue->q_ptr = RD(macinfo->llcp_queue)->q_ptr =
		    (caddr_t)macinfo;
		llc1_init_kstat(macinfo);
		rw_exit(&llc1_device_list.llc1_rwlock);

		/* initiate getting the info */
		(void) llc1_req_info(macinfo->llcp_queue);

		miocack(q, mp, 0, 0);
		return;

	case I_PUNLINK:
	case I_UNLINK:
		link = (struct linkblk *)mp->b_cont->b_rptr;
		rw_enter(&llc1_device_list.llc1_rwlock, RW_WRITER);
		for (macinfo = llc1_device_list.llc1_mac_next;
		    macinfo != NULL &&
		    macinfo !=
		    (llc_mac_info_t *)&llc1_device_list.llc1_mac_next;
		    macinfo = macinfo->llcp_next) {
			if (macinfo->llcp_lindex == link->l_index &&
			    macinfo->llcp_queue == link->l_qbot) {
				/* found it */

				ASSERT(macinfo->llcp_next);

			    /* remove from device list */
				llc1_device_list.llc1_ndevice--;
				llc1remque(macinfo);

			    /* remove any mcast structs */
				if (macinfo->llcp_mcast != NULL) {
				kmem_free(macinfo->llcp_mcast,
				    sizeof (llc_mcast_t) *
				    llc1_device_list.llc1_multisize);
				macinfo->llcp_mcast = NULL;
				}

			    /* remove any kstat counters */
				if (macinfo->llcp_kstatp != NULL)
				llc1_uninit_kstat(macinfo);
				if (macinfo->llcp_mb != NULL)
				freeb(macinfo->llcp_mb);

				lld->llc_mac_info = NULL;

				miocack(q, mp, 0, 0);

			    /* finish any necessary setup */
				if (llc1_device_list.llc1_ndevice == 0)
				llc1_device_list.llc1_nextppa = 0;

				rw_exit(&llc1_device_list.llc1_rwlock);
				return;
			}
		}
		rw_exit(&llc1_device_list.llc1_rwlock);
		/*
		 * what should really be done here -- force errors on all
		 * streams?
		 */
		miocnak(q, mp, 0, EINVAL);
		return;

	case L_SETPPA:
		error = miocpullup(mp, sizeof (struct ll_snioc));
		if (error != 0) {
			miocnak(q, mp, 0, error);
			return;
		}

		if (llc1_setppa((struct ll_snioc *)mp->b_cont->b_rptr) >= 0) {
			miocack(q, mp, 0, 0);
			return;
		}
		miocnak(q, mp, 0, EINVAL);
		return;

	case L_GETPPA:
		if (mp->b_cont == NULL) {
			mp->b_cont = allocb(sizeof (struct ll_snioc), BPRI_MED);
			if (mp->b_cont == NULL) {
				miocnak(q, mp, 0, ENOSR);
				return;
			}
			mp->b_cont->b_wptr =
			    mp->b_cont->b_rptr + sizeof (struct ll_snioc);
		} else {
			error = miocpullup(mp, sizeof (struct ll_snioc));
			if (error != 0) {
				miocnak(q, mp, 0, error);
				return;
			}
		}

		lld = (llc1_t *)q->q_ptr;
		if (llc1_getppa(lld->llc_mac_info,
		    (struct ll_snioc *)mp->b_cont->b_rptr) >= 0)
			miocack(q, mp, 0, 0);
		else
			miocnak(q, mp, 0, EINVAL);
		return;
	default:
		miocnak(q, mp, 0, EINVAL);
	}
}

/*
 * llc1_setppa(snioc) this function sets the real PPA number for a previously
 * I_LINKED stream. Be careful to select the macinfo struct associated
 * with our llc struct, to avoid erroneous references.
 */

static int
llc1_setppa(struct ll_snioc *snioc)
{
	llc_mac_info_t *macinfo;

	for (macinfo = llc1_device_list.llc1_mac_next;
	    macinfo != (llc_mac_info_t *)&llc1_device_list.llc1_mac_next;
	    macinfo = macinfo->llcp_next)
		if (macinfo->llcp_lindex == snioc->lli_index &&
		    (macinfo->llcp_flags & LLC1_DEF_PPA)) {
			macinfo->llcp_flags &= ~LLC1_DEF_PPA;
			macinfo->llcp_ppa = snioc->lli_ppa;
			return (0);
		}
	return (-1);
}

/*
 * llc1_getppa(macinfo, snioc) returns the PPA for this stream
 */
static int
llc1_getppa(llc_mac_info_t *macinfo, struct ll_snioc *snioc)
{
	if (macinfo == NULL)
		return (-1);
	snioc->lli_ppa = macinfo->llcp_ppa;
	snioc->lli_index = macinfo->llcp_lindex;
	return (0);
}

/*
 * llc1_cmds - process the DL commands as defined in dlpi.h
 */
static int
llc1_cmds(queue_t *q, mblk_t *mp)
{
	union DL_primitives *dlp;
	llc1_t *llc = (llc1_t *)q->q_ptr;
	int	result = 0;
	llc_mac_info_t *macinfo = llc->llc_mac_info;

	dlp = (union DL_primitives *)mp->b_rptr;
#ifdef LLC1_DEBUG
	if (llc1_debug & LLCTRACE)
		printf("llc1_cmds(%x, %x):dlp=%x, dlp->dl_primitive=%d\n",
		    q, mp, dlp, dlp->dl_primitive);
#endif
	mutex_enter(&llc->llc_lock);
	rw_enter(&llc1_device_list.llc1_rwlock, RW_READER);

	switch (dlp->dl_primitive) {
	case DL_BIND_REQ:
		result = llc1_bind(q, mp);
		break;

	case DL_UNBIND_REQ:
		result = llc1_unbind(q, mp);
		break;

	case DL_SUBS_BIND_REQ:
		result = llc1_subs_bind(q, mp);
		break;

	case DL_SUBS_UNBIND_REQ:
		result = llc1_subs_unbind();
		break;

	case DL_UNITDATA_REQ:
		result = llc1_unitdata(q, mp);
		break;

	case DL_INFO_REQ:
		result = llc1_inforeq(q, mp);
		break;

	case DL_ATTACH_REQ:
		result = llc1attach(q, mp);
		break;

	case DL_DETACH_REQ:
		result = llc1unattach(q, mp);
		break;

	case DL_ENABMULTI_REQ:
		result = llc1_enable_multi(q, mp);
		break;

	case DL_DISABMULTI_REQ:
		result = llc1_disable_multi(q, mp);
		break;

	case DL_XID_REQ:
		result = llc1_xid_req_res(q, mp, 0);
		break;

	case DL_XID_RES:
		result = llc1_xid_req_res(q, mp, 1);
		break;

	case DL_TEST_REQ:
		result = llc1_test_req_res(q, mp, 0);
		break;

	case DL_TEST_RES:
		result = llc1_test_req_res(q, mp, 1);
		break;

	case DL_SET_PHYS_ADDR_REQ:
		result = DL_NOTSUPPORTED;
		break;

	case DL_PHYS_ADDR_REQ:
		if (llc->llc_state != DL_UNATTACHED && macinfo) {
			llc->llc_waiting_for = dlp->dl_primitive;
			putnext(WR(macinfo->llcp_queue), mp);
			result = LLCE_OK;
		} else {
			result = DL_OUTSTATE;
		}
		break;

	case DL_PROMISCON_REQ:
	case DL_PROMISCOFF_REQ:
		result = DL_NOTSUPPORTED;
		break;

	default:
#ifdef LLC1_DEBUG
		if (llc1_debug & LLCERRS)
			printf("llc1_cmds: Received unknown primitive: %d\n",
			    dlp->dl_primitive);
#endif
		result = DL_BADPRIM;
		break;
	}
	rw_exit(&llc1_device_list.llc1_rwlock);
	mutex_exit(&llc->llc_lock);
	return (result);
}

/*
 * llc1_bind - determine if a SAP is already allocated and whether it is
 * legal to do the bind at this time
 */
static int
llc1_bind(queue_t *q, mblk_t *mp)
{
	int	sap;
	dl_bind_req_t *dlp;
	llc1_t *lld = (llc1_t *)q->q_ptr;

	ASSERT(lld);

#ifdef LLC1_DEBUG
	if (llc1_debug & LLCTRACE)
		printf("llc1_bind(%x %x)\n", q, mp);
#endif

	dlp = (dl_bind_req_t *)mp->b_rptr;
	sap = dlp->dl_sap;

#ifdef LLC1_DEBUG
	if (llc1_debug & LLCPROT)
		printf("llc1_bind: lsap=%x\n", sap);
#endif

	if (lld->llc_mac_info == NULL)
		return (DL_OUTSTATE);

	if (lld->llc_qptr && lld->llc_state != DL_UNBOUND) {
#ifdef LLC1_DEBUG
		if (llc1_debug & LLCERRS)
			printf("llc1_bind: stream bound/not attached (%d)\n",
			    lld->llc_state);
#endif
		return (DL_OUTSTATE);
	}

	if (dlp->dl_service_mode != DL_CLDLS || dlp->dl_max_conind != 0) {
		return (DL_UNSUPPORTED);
	}
	/*
	 * prohibit group saps.	An exception is the broadcast sap which is,
	 * unfortunately, used by SUNSelect to indicate Novell Netware in
	 * 802.3 mode.	Really should use a very non-802.2 SAP like 0xFFFF
	 * or -2.
	 */

	if (sap == 0 || (sap <= 0xFF && (sap & 1 && sap != 0xFF)) ||
	    sap > 0xFFFF) {
		return (DL_BADSAP);
	}
	lld->llc_state = DL_BIND_PENDING;

	/* if we fall through, then the SAP is legal */
	if (sap == 0xFF) {
		if (lld->llc_mac_info->llcp_type == DL_CSMACD)
			sap = LLC_NOVELL_SAP;
		else
			return (DL_BADSAP);
	}
	lld->llc_sap = sap;

	if (sap > 0xFF) {
		ushort_t snapsap = htons(sap);
		/* this is SNAP, so set things up */
		lld->llc_snap[3] = ((uchar_t *)&snapsap)[0];
		lld->llc_snap[4] = ((uchar_t *)&snapsap)[1];
		/* mark as SNAP but allow OID to be added later */
		lld->llc_flags |= LLC_SNAP;
		lld->llc_sap = LLC_SNAP_SAP;
	}

#ifdef LLC1_DEBUG
	if (llc1_debug & LLCPROT)
		printf("llc1_bind: ok - type = %d\n", lld->llc_type);
#endif

	if (dlp->dl_xidtest_flg & DL_AUTO_XID)
		lld->llc_flags |= LLC1_AUTO_XID;
	if (dlp->dl_xidtest_flg & DL_AUTO_TEST)
		lld->llc_flags |= LLC1_AUTO_TEST;

	/* ACK the BIND, if possible */

	dlbindack(q, mp, sap, lld->llc_mac_info->llcp_macaddr, 6, 0, 0);

	lld->llc_state = DL_IDLE;	/* bound and ready */

	return (LLCE_OK);
}

/*
 * llc1_unbind - perform an unbind of an LSAP or ether type on the stream.
 * The stream is still open and can be re-bound.
 */
static int
llc1_unbind(queue_t *q, mblk_t *mp)
{
	llc1_t *lld;

#ifdef LLC1_DEBUG
	if (llc1_debug & LLCTRACE)
		printf("llc1_unbind(%x %x)\n", q, mp);
#endif
	lld = (llc1_t *)q->q_ptr;

	if (lld->llc_mac_info == NULL)
		return (DL_OUTSTATE);

	if (lld->llc_state != DL_IDLE) {
#ifdef LLC1_DEBUG
		if (llc1_debug & LLCERRS)
			printf("llc1_unbind: wrong state (%d)\n",
			    lld->llc_state);
#endif
		return (DL_OUTSTATE);
	}
	lld->llc_state = DL_UNBIND_PENDING;
	lld->llc_flags &= ~(LLC_SNAP|LLC_SNAP_OID); /* just in case */
	dlokack(q, mp, DL_UNBIND_REQ);
	lld->llc_state = DL_UNBOUND;
	return (LLCE_OK);
}

/*
 * llc1_inforeq - generate the response to an info request
 */
static int
llc1_inforeq(queue_t *q, mblk_t *mp)
{
	llc1_t *lld;
	mblk_t *nmp;
	dl_info_ack_t *dlp;
	int	bufsize;

#ifdef LLC1_DEBUG
	if (llc1_debug & LLCTRACE)
		printf("llc1_inforeq(%x %x)\n", q, mp);
#endif
	lld = (llc1_t *)q->q_ptr;
	ASSERT(lld);
	if (lld->llc_mac_info == NULL)
		bufsize = sizeof (dl_info_ack_t) + ETHERADDRL;
	else
		bufsize = sizeof (dl_info_ack_t) +
		    2 * lld->llc_mac_info->llcp_addrlen + 2;

	nmp = mexchange(q, mp, bufsize, M_PCPROTO, DL_INFO_ACK);

	if (nmp) {
		nmp->b_wptr = nmp->b_rptr + sizeof (dl_info_ack_t);
		dlp = (dl_info_ack_t *)nmp->b_rptr;
		bzero(dlp, DL_INFO_ACK_SIZE);
		dlp->dl_primitive = DL_INFO_ACK;
		if (lld->llc_mac_info)
			dlp->dl_max_sdu = lld->llc_mac_info->llcp_maxpkt;
		dlp->dl_min_sdu = 0;
		dlp->dl_mac_type = lld->llc_type;
		dlp->dl_service_mode = DL_CLDLS;
		dlp->dl_current_state = lld->llc_state;
		dlp->dl_provider_style =
		    (lld->llc_style == 0) ? lld->llc_style : DL_STYLE2;

		/* now append physical address */
		if (lld->llc_mac_info) {
			dlp->dl_addr_length = lld->llc_mac_info->llcp_addrlen;
			dlp->dl_addr_offset = DL_INFO_ACK_SIZE;
			nmp->b_wptr += dlp->dl_addr_length + 1;
			bcopy(lld->llc_mac_info->llcp_macaddr,
			    ((caddr_t)dlp) + dlp->dl_addr_offset,
			    lld->llc_mac_info->llcp_addrlen);
			if (lld->llc_state == DL_IDLE) {
				dlp->dl_sap_length = -1; /* 1 byte on end */
				*(((caddr_t)dlp) + dlp->dl_addr_offset +
				    dlp->dl_addr_length) = lld->llc_sap;
				dlp->dl_addr_length += 1;
			}
			/* and the broadcast address */
			dlp->dl_brdcst_addr_length =
			    lld->llc_mac_info->llcp_addrlen;
			dlp->dl_brdcst_addr_offset =
			    dlp->dl_addr_offset + dlp->dl_addr_length;
			nmp->b_wptr += dlp->dl_brdcst_addr_length;
			bcopy(lld->llc_mac_info->llcp_broadcast,
			    ((caddr_t)dlp) + dlp->dl_brdcst_addr_offset,
			    lld->llc_mac_info->llcp_addrlen);
		} else {
			dlp->dl_addr_length = 0; /* not attached yet */
			dlp->dl_addr_offset = 0;
			dlp->dl_sap_length = 0; /* 1 bytes on end */
		}
		dlp->dl_version = DL_VERSION_2;
		qreply(q, nmp);
	}
	return (LLCE_OK);
}

/*
 * llc1_unitdata
 * send a datagram.  Destination address/lsap is in M_PROTO
 * message (first mblock), data is in remainder of message.
 *
 * NOTE: We are reusing the DL_unitdata_req mblock; if llc header gets any
 * bigger, recheck to make sure it still fits!	We assume that we have a
 * 64-byte dblock for this, since a DL_unitdata_req is 20 bytes and the next
 * larger dblock size is 64.
 */
static int
llc1_unitdata(queue_t *q, mblk_t *mp)
{
	llc1_t *lld = (llc1_t *)q->q_ptr;
	dl_unitdata_req_t *dlp = (dl_unitdata_req_t *)mp->b_rptr;
	struct ether_header *hdr;
	struct llcaddr *llcp;
	mblk_t *nmp;
	long	msglen;
	struct llchdr *llchdr;
	llc_mac_info_t *macinfo;
	int xmt_type = 0;

#ifdef LLC1_DEBUG
	if (llc1_debug & LLCTRACE)
		printf("llc1_unitdata(%x %x)\n", q, mp);
#endif

	if ((macinfo = lld->llc_mac_info) == NULL)
		return (DL_OUTSTATE);

	if (lld->llc_state != DL_IDLE) {
#ifdef LLC1_DEBUG
		if (llc1_debug & LLCERRS)
			printf("llc1_unitdata: wrong state (%d)\n",
			    lld->llc_state);
#endif
		return (DL_OUTSTATE);
	}

	/* need the destination address in all cases */
	llcp = (struct llcaddr *)((caddr_t)dlp + dlp->dl_dest_addr_offset);

	if (macinfo->llcp_flags & LLC1_USING_RAW) {
		/*
		 * make a valid header for transmission
		 */

	    /* need a buffer big enough for the headers */
		nmp = allocb(macinfo->llcp_addrlen * 2 + 2 + 8, BPRI_MED);
		hdr = (struct ether_header *)nmp->b_rptr;
		msglen = msgdsize(mp);

	    /* fill in type dependent fields */
		switch (lld->llc_type) {
		case DL_CSMACD: /* 802.3 CSMA/CD */
		nmp->b_wptr = nmp->b_rptr + LLC1_CSMACD_HDR_SIZE;
		llchdr = (struct llchdr *)nmp->b_wptr;
		bcopy(llcp->llca_addr,
		    hdr->ether_dhost.ether_addr_octet,
		    ETHERADDRL);
		bcopy(macinfo->llcp_macaddr,
		    hdr->ether_shost.ether_addr_octet,
		    ETHERADDRL);

		if (lld->llc_sap != LLC_NOVELL_SAP) {
			/* set length with llc header size */
			hdr->ether_type = ntohs(msglen +
			    sizeof (struct llchdr));

			/* need an LLC header, otherwise is Novell */
			/* bound sap is always source */
			llchdr->llc_ssap = lld->llc_sap;

			/* destination sap */
			llchdr->llc_dsap = llcp->llca_sap;

			/* always Unnumbered Information */
			llchdr->llc_ctl = LLC_UI;

			nmp->b_wptr += sizeof (struct llchdr);

			if (lld->llc_flags & LLC_SNAP) {
				bcopy(lld->llc_snap, nmp->b_wptr, 5);
				llchdr->llc_dsap = LLC_SNAP_SAP;
				nmp->b_wptr += 5;
			}
		} else {
			/* set length without llc header size */
			hdr->ether_type = ntohs(msglen);

			/* we don't do anything else for Netware */
		}

		if (ismulticast(hdr->ether_dhost.ether_addr_octet)) {
			if (bcmp(hdr->ether_dhost.ether_addr_octet,
			    macinfo->llcp_broadcast, ETHERADDRL) == 0)
				xmt_type = 2;
			else
				xmt_type = 1;
		}

		break;

		default:		/* either RAW or unknown, send as is */
		break;
		}
		DB_TYPE(nmp) = M_DATA; /* ether/llc header is data */
		nmp->b_cont = mp->b_cont;	/* use the data given */
		freeb(mp);
		mp = nmp;
	} else {
	    /* need to format a DL_UNITDATA_REQ with LLC1 header inserted */
		nmp = allocb(sizeof (struct llchdr)+sizeof (struct snaphdr),
		    BPRI_MED);
		if (nmp == NULL)
		return (DL_UNDELIVERABLE);
		llchdr = (struct llchdr *)(nmp->b_rptr);
		nmp->b_wptr += sizeof (struct llchdr);
		llchdr->llc_dsap = llcp->llca_sap;
		llchdr->llc_ssap = lld->llc_sap;
		llchdr->llc_ctl = LLC_UI;

		/*
		 * if we are using SNAP, insert the header here
		 */
		if (lld->llc_flags & LLC_SNAP) {
			bcopy(lld->llc_snap, nmp->b_wptr, 5);
			nmp->b_wptr += 5;
		}
		nmp->b_cont = mp->b_cont;
		mp->b_cont = nmp;
		nmp = mp;
		if (ismulticast(llcp->llca_addr)) {
			if (bcmp(llcp->llca_addr,
			    macinfo->llcp_broadcast, ETHERADDRL) == 0)
				xmt_type = 2;
			else
				xmt_type = 1;
		}
	}
	if (canput(macinfo->llcp_queue)) {
		lld->llc_stats->llcs_bytexmt += msgdsize(mp);
		lld->llc_stats->llcs_pktxmt++;
		switch (xmt_type) {
		case 1:
			macinfo->llcp_stats.llcs_multixmt++;
			break;
		case 2:
			macinfo->llcp_stats.llcs_brdcstxmt++;
			break;
		}

		putnext(macinfo->llcp_queue, mp);
		return (LLCE_OK);	/* this is almost correct, the result */
	} else {
		lld->llc_stats->llcs_nobuffer++;
	}
	if (nmp != NULL)
		freemsg(nmp);	/* free on failure */
	return (LLCE_OK);
}

/*
 * llc1_recv(macinfo, mp)
 * called with an ethernet packet in a mblock; must decide
 * whether packet is for us and which streams to queue it to. This routine is
 * called with locally originated packets for loopback.
 */
static void
llc1_recv(llc_mac_info_t *macinfo, mblk_t *mp)
{
	struct ether_addr *addr;
	llc1_t *lld;
	mblk_t *nmp, *udmp;
	int	i, nmcast = 0, statcnt_normal = 0, statcnt_brdcst = 0;
	int valid, msgsap;
	struct llchdr *llchdr;

#ifdef LLC1_DEBUG
	if (llc1_debug & LLCTRACE)
		printf("llc1_recv(%x, %x)\n", mp, macinfo);
#endif

	if (DB_TYPE(mp) == M_PROTO) {
		dl_unitdata_ind_t *udata;

		/* check to see if really LLC1 XXX */
		/* also need to make sure to keep address info */
		nmp = mp;
		udata = (dl_unitdata_ind_t *)(nmp->b_rptr);
		addr = (struct ether_addr *)(nmp->b_rptr +
		    udata->dl_dest_addr_offset);
		llchdr = (struct llchdr *)(nmp->b_cont->b_rptr);
		if (macinfo->llcp_type == DL_CSMACD) {
			i = ((struct llcsaddr *)addr)->llca_ssap;
			if (i < 60) {
				valid = adjmsg(mp->b_cont, i - msgdsize(mp));
			}
		}
	} else {
		struct ether_header *hdr;

		/* Note that raw mode currently assumes Ethernet */
		nmp = NULL;
		hdr = (struct ether_header *)mp->b_rptr;
		addr = &hdr->ether_dhost;
		llchdr = (struct llchdr *)(mp->b_rptr +
		    sizeof (struct ether_header));
		i = (ushort_t)ntohs(hdr->ether_type);
		if (i < 60) {
			(void) adjmsg(mp, i + sizeof (struct ether_header) -
			    msgdsize(mp));
		}
	}
	udmp = NULL;

	msgsap = llchdr->llc_dsap;

#ifdef LLC1_DEBUG
	if (llc1_debug & LLCRECV) {
		printf("llc1_recv: machdr=<%s>\n", ether_sprintf(addr));
	}
#endif

	if (llc1_broadcast(addr, macinfo)) {
		valid = 2;	/* 2 means valid but multicast */
		statcnt_brdcst = 1;
	} else {
		valid = llc1_local(addr, macinfo);
		statcnt_normal = msgdsize(mp);
	}

	/*
	 * Note that the NULL SAP is a special case.  It is associated with
	 * the MAC layer and not the LLC layer so should be handled
	 * independently of any STREAM.
	 */
	if (msgsap == LLC_NULL_SAP) {
		/* only XID and TEST ever processed, UI is dropped */
		if ((llchdr->llc_ctl & ~LLC_P) == LLC_XID)
			mp = llc1_xid_reply(macinfo, mp, 0);
		else if ((llchdr->llc_ctl & ~LLC_P) == LLC_TEST)
			mp = llc1_test_reply(macinfo, mp, 0);
	} else
		for (lld = llc1_device_list.llc1_str_next;
		    lld != (llc1_t *)&llc1_device_list.llc1_str_next;
		    lld = lld->llc_next) {

			/*
			 * is this a potentially usable SAP on the
			 * right MAC layer?
			 */
			if (lld->llc_qptr == NULL ||
			    lld->llc_state != DL_IDLE ||
			    lld->llc_mac_info != macinfo) {
				continue;
			}
#ifdef LLC1_DEBUG
			if (llc1_debug & LLCRECV)
				printf(
"llc1_recv: type=%d, sap=%x, pkt-dsap=%x\n",
				    lld->llc_type, lld->llc_sap,
				    msgsap);
#endif
			if (!valid && ismulticast(addr->ether_addr_octet) &&
			    lld->llc_multicnt > 0 &&
			    llc1_multicast(addr, lld)) {
				valid |= 4;
			} else if (lld->llc_flags & LLC_PROM)
				/* promiscuous mode */
				valid = 1;

			if ((lld->llc_flags & LLC_PROM) ||
				/* promiscuous streams */
			    (valid &&
			    (lld->llc_sap == msgsap ||
			    msgsap == LLC_GLOBAL_SAP))) {
				/* sap matches */
				if (msgsap == LLC_SNAP_SAP &&
				    (lld->llc_flags & (LLC_SNAP|LLC_PROM)) ==
				    LLC_SNAP) {
					if (!llc1_snap_match(lld,
					    (struct snaphdr *)(llchdr+1)))
						continue;
				}
				if (!canputnext(RD(lld->llc_qptr))) {
#ifdef LLC1_DEBUG
					if (llc1_debug & LLCRECV)
						printf(
"llc1_recv: canput failed\n");
#endif
					lld->llc_stats->llcs_blocked++;
					continue;
				}
				/* check for Novell special handling */
				if (msgsap == LLC_GLOBAL_SAP &&
				    lld->llc_sap == LLC_NOVELL_SAP &&
				    llchdr->llc_ssap == LLC_GLOBAL_SAP) {

					/* A Novell packet */
					nmp = llc1_form_udata(lld, macinfo, mp);
					continue;
				}
				switch (llchdr->llc_ctl) {
				case LLC_UI:
					/*
					 * this is an Unnumbered Information
					 * packet so form a DL_UNITDATA_IND and
					 * send to user
					 */
					nmp = llc1_form_udata(lld, macinfo, mp);
					break;

				case LLC_XID:
				case LLC_XID | LLC_P:
					/*
					 * this is either an XID request or
					 * response. We either handle directly
					 * (if user hasn't requested to handle
					 * itself) or send to user. We also
					 * must check if a response if user
					 * handled so that we can send correct
					 * message form
					 */
					if (lld->llc_flags & LLC1_AUTO_XID) {
						nmp = llc1_xid_reply(macinfo,
						    mp, lld->llc_sap);
					} else {
						/*
						 * hand to the user for
						 * handling. if this is a
						 * "request", generate a
						 * DL_XID_IND.	If it is a
						 * "response" to one of our
						 * requests, generate a
						 * DL_XID_CON.
						 */
						nmp = llc1_xid_ind_con(lld,
						    macinfo, mp);
					}
					macinfo->llcp_stats.llcs_xidrcv++;
					break;

				case LLC_TEST:
				case LLC_TEST | LLC_P:
					/*
					 * this is either a TEST request or
					 * response.  We either handle
					 * directly (if user hasn't
					 * requested to handle itself)
					 * or send to user.  We also
					 * must check if a response if
					 * user handled so that we can
					 * send correct message form
					 */
					if (lld->llc_flags & LLC1_AUTO_TEST) {
						nmp = llc1_test_reply(macinfo,
						    mp, lld->llc_sap);
					} else {
						/*
						 * hand to the user for
						 * handling. if this is
						 * a "request",
						 * generate a
						 * DL_TEST_IND. If it
						 * is a "response" to
						 * one of our requests,
						 * generate a
						 * DL_TEST_CON.
						 */
						nmp = llc1_test_ind_con(lld,
						    macinfo, mp);
					}
					macinfo->llcp_stats.llcs_testrcv++;
					break;
				default:
					nmp = mp;
					break;
				}
				mp = nmp;
			}
		}
	if (mp != NULL)
		freemsg(mp);
	if (udmp != NULL)
		freeb(udmp);
	if (nmcast > 0)
		macinfo->llcp_stats.llcs_multircv++;
	if (statcnt_brdcst) {
		macinfo->llcp_stats.llcs_brdcstrcv++;
	}
	if (statcnt_normal) {
		macinfo->llcp_stats.llcs_bytercv += statcnt_normal;
		macinfo->llcp_stats.llcs_pktrcv++;
	}
}

/*
 * llc1_local - check to see if the message is addressed to this system by
 * comparing with the board's address.
 */
static int
llc1_local(struct ether_addr *addr, llc_mac_info_t *macinfo)
{
	return (bcmp(addr->ether_addr_octet, macinfo->llcp_macaddr,
	    macinfo->llcp_addrlen) == 0);
}

/*
 * llc1_broadcast - check to see if a broadcast address is the destination of
 * this received packet
 */
static int
llc1_broadcast(struct ether_addr *addr, llc_mac_info_t *macinfo)
{
	return (bcmp(addr->ether_addr_octet, macinfo->llcp_broadcast,
	    macinfo->llcp_addrlen) == 0);
}

/*
 * llc1attach(q, mp) DLPI DL_ATTACH_REQ this attaches the stream to a PPA
 */
static int
llc1attach(queue_t *q, mblk_t *mp)
{
	dl_attach_req_t *at;
	llc_mac_info_t *mac;
	llc1_t *llc = (llc1_t *)q->q_ptr;

	at = (dl_attach_req_t *)mp->b_rptr;

	if (llc->llc_state != DL_UNATTACHED) {
		return (DL_OUTSTATE);
	}
	llc->llc_state = DL_ATTACH_PENDING;

	if (rw_tryupgrade(&llc1_device_list.llc1_rwlock) == 0) {
		/*
		 * someone else has a lock held.  To avoid deadlock,
		 * release the READER lock and block on a WRITER
		 * lock.  This will let things continue safely.
		 */
		rw_exit(&llc1_device_list.llc1_rwlock);
		rw_enter(&llc1_device_list.llc1_rwlock, RW_WRITER);
	}

	for (mac = llc1_device_list.llc1_mac_next;
	    mac != (llc_mac_info_t *)(&llc1_device_list.llc1_mac_next);
	    mac = mac->llcp_next) {
		ASSERT(mac);
		if (mac->llcp_ppa == at->dl_ppa && mac->llcp_lqtop == q) {
			/*
			 * We may have found the correct PPA
			 * check to see if linking has finished.
			 * Use explicit flag checks for incorrect
			 * state, and use negative values for "tenative"
			 * llcp_ppas, to avoid erroneous attaches.
			 */
			if (mac->llcp_flags &
			    (LLC1_LINKED|LLC1_DEF_PPA)) {
				return (DL_INITFAILED);
			} else if (!(mac->llcp_flags & LLC1_AVAILABLE)) {
				return (DL_BADPPA);
			}

			/* this links us to the PPA */
			mac->llcp_nstreams++;
			llc->llc_mac_info = mac;

			llc->llc_state = DL_UNBOUND; /* now ready for action */
			llc->llc_stats = &mac->llcp_stats;
			dlokack(q, mp, DL_ATTACH_REQ);

			return (LLCE_OK);
		}
	}
	llc->llc_state = DL_UNATTACHED;
	return (DL_BADPPA);
}

/*
 * llc1unattach(q, mp) DLPI DL_DETACH_REQ detaches the mac layer from the
 * stream
 */
static int
llc1unattach(queue_t *q, mblk_t *mp)
{
	llc1_t *llc = (llc1_t *)q->q_ptr;
	int	state;
	int	i;

	state = llc->llc_state;
	if (state != DL_UNBOUND)
		return (DL_OUTSTATE);

	/* can now detach from the PPA */
	llc->llc_state = DL_DETACH_PENDING;

	if (rw_tryupgrade(&llc1_device_list.llc1_rwlock) == 0) {
		/*
		 * someone else has a lock held.  To avoid deadlock,
		 * release the READER lock and block on a WRITER
		 * lock.  This will let things continue safely.
		 */
		rw_exit(&llc1_device_list.llc1_rwlock);
		rw_enter(&llc1_device_list.llc1_rwlock, RW_WRITER);
	}

	if (llc->llc_mcast) {
		for (i = 0; i < llc1_device_list.llc1_multisize; i++) {
			llc_mcast_t *mcast;

			if ((mcast = llc->llc_mcast[i]) != NULL) {
				/* disable from stream and possibly lower */
				llc1_send_disable_multi(llc->llc_mac_info,
				    mcast);
				llc->llc_mcast[i] = NULL;
			}
		}
		kmem_free(llc->llc_mcast,
		    sizeof (llc_mcast_t *) * llc->llc_multicnt);
		llc->llc_mcast = NULL;
	}
	if (llc->llc_mac_info)
		llc->llc_mac_info->llcp_nstreams--;
	llc->llc_sap = 0;
	llc->llc_state = DL_UNATTACHED;
	if (mp) {
		dlokack(q, mp, DL_DETACH_REQ);
	}
	return (LLCE_OK);
}

/*
 * llc1_enable_multi enables multicast address on the stream if the mac layer
 * isn't enabled for this address, enable at that level as well.
 */
static int
llc1_enable_multi(queue_t *q, mblk_t *mp)
{
	llc1_t *llc;
	llc_mac_info_t *macinfo;
	struct ether_addr *maddr;
	dl_enabmulti_req_t *multi;
	llc_mcast_t *mcast;
	int	status = DL_BADADDR;
	int	i;

#if defined(LLC1_DEBUG)
	if (llc1_debug & LLCPROT) {
		printf("llc1_enable_multi(%x, %x)\n", q, mp);
	}
#endif

	llc = (llc1_t *)q->q_ptr;

	if (llc->llc_state == DL_UNATTACHED)
		return (DL_OUTSTATE);

	macinfo = llc->llc_mac_info;
	multi = (dl_enabmulti_req_t *)mp->b_rptr;
	maddr = (struct ether_addr *)(mp->b_rptr + multi->dl_addr_offset);

	/*
	 * check to see if this multicast address is valid if it is, then
	 * check to see if it is already in the per stream table and the per
	 * device table if it is already in the per stream table, if it isn't
	 * in the per device, add it.  If it is, just set a pointer.  If it
	 * isn't, allocate what's necessary.
	 */

	if (MBLKL(mp) >= sizeof (dl_enabmulti_req_t) &&
	    MBLKIN(mp, multi->dl_addr_offset, multi->dl_addr_length) &&
	    multi->dl_addr_length == macinfo->llcp_addrlen &&
	    ismulticast(maddr->ether_addr_octet)) {
		/* request appears to be valid */
		/* does this address appear in current table? */
		if (llc->llc_mcast == NULL) {
			/* no mcast addresses -- allocate table */
			llc->llc_mcast =
			    GETSTRUCT(llc_mcast_t *,
			    llc1_device_list.llc1_multisize);
			if (llc->llc_mcast == NULL)
				return (DL_SYSERR);
			llc->llc_multicnt = llc1_device_list.llc1_multisize;
		} else {
			for (i = 0; i < llc1_device_list.llc1_multisize; i++) {
				if (llc->llc_mcast[i] &&
				    bcmp(llc->llc_mcast[i]->llcm_addr,
				    maddr->ether_addr_octet, ETHERADDRL)) {
					/* this is a match -- just succeed */
					dlokack(q, mp, DL_ENABMULTI_REQ);
					return (LLCE_OK);
				}
			}
		}
		/*
		 * there wasn't one so check to see if the mac layer has one
		 */
		if (macinfo->llcp_mcast == NULL) {
			macinfo->llcp_mcast =
			    GETSTRUCT(llc_mcast_t,
			    llc1_device_list.llc1_multisize);
			if (macinfo->llcp_mcast == NULL)
				return (DL_SYSERR);
		}
		for (mcast = NULL, i = 0;
		    i < llc1_device_list.llc1_multisize; i++) {
			if (macinfo->llcp_mcast[i].llcm_refcnt &&
			    bcmp(macinfo->llcp_mcast[i].llcm_addr,
			    maddr->ether_addr_octet, ETHERADDRL) == 0) {
				mcast = &macinfo->llcp_mcast[i];
				break;
			}
		}
		if (mcast == NULL) {
			mblk_t *nmp;

			nmp = dupmsg(mp);
			if (nmp) {
				nmp->b_cont = NULL;
				DB_TYPE(nmp) = M_PROTO;
				putnext(WR(macinfo->llcp_queue), nmp);
			}
			/* find an empty slot to fill in */
			for (mcast = macinfo->llcp_mcast, i = 0;
			    i < llc1_device_list.llc1_multisize; i++, mcast++) {
				if (mcast->llcm_refcnt == 0) {
					bcopy(maddr->ether_addr_octet,
					    mcast->llcm_addr, ETHERADDRL);
					break;
				}
			}
		}
		if (mcast != NULL) {
			for (i = 0; i < llc1_device_list.llc1_multisize; i++) {
				if (llc->llc_mcast[i] == NULL) {
					llc->llc_mcast[i] = mcast;
					mcast->llcm_refcnt++;
					dlokack(q, mp, DL_ENABMULTI_REQ);
					return (LLCE_OK);
				}
			}
		}
		status = DL_TOOMANY;
	}
	return (status);
}

/*
 * llc1_disable_multi disable the multicast address on the stream if last
 * reference for the mac layer, disable there as well
 */
static int
llc1_disable_multi(queue_t *q, mblk_t *mp)
{
	llc1_t *llc;
	llc_mac_info_t *macinfo;
	struct ether_addr *maddr;
	dl_enabmulti_req_t *multi;
	int	status = DL_BADADDR, i;
	llc_mcast_t *mcast;

#if defined(LLC1_DEBUG)
	if (llc1_debug & LLCPROT) {
		printf("llc1_enable_multi(%x, %x)\n", q, mp);
	}
#endif

	llc = (llc1_t *)q->q_ptr;

	if (llc->llc_state == DL_UNATTACHED)
		return (DL_OUTSTATE);

	macinfo = llc->llc_mac_info;
	multi = (dl_enabmulti_req_t *)mp->b_rptr;
	maddr = (struct ether_addr *)(multi + 1);

	if (MBLKL(mp) >= sizeof (dl_enabmulti_req_t) &&
	    MBLKIN(mp, multi->dl_addr_offset, multi->dl_addr_length)) {
		/* request appears to be valid */
		/* does this address appear in current table? */
		if (llc->llc_mcast != NULL) {
			for (i = 0; i < llc->llc_multicnt; i++)
				if (((mcast = llc->llc_mcast[i]) != NULL) &&
				    mcast->llcm_refcnt &&
				    bcmp(mcast->llcm_addr,
				    maddr->ether_addr_octet, ETHERADDRL) == 0) {
					llc1_send_disable_multi(macinfo,
					    mcast);
					llc->llc_mcast[i] = NULL;
					dlokack(q, mp, DL_DISABMULTI_REQ);
					return (LLCE_OK);
				}
			status = DL_NOTENAB;
		}
	}
	return (status);
}

/*
 * llc1_send_disable_multi(llc, macinfo, mcast) this function is used to
 * disable a multicast address if the reference count goes to zero. The
 * disable request will then be forwarded to the lower stream.
 */
static void
llc1_send_disable_multi(llc_mac_info_t *macinfo, llc_mcast_t *mcast)
{
	mblk_t *mp;
	dl_disabmulti_req_t *dis;

	if (mcast == NULL) {
		return;
	}
	if (macinfo == NULL || macinfo->llcp_queue == NULL) {
		return;
	}
	if (--mcast->llcm_refcnt > 0)
		return;

	mp = allocb(sizeof (dl_disabmulti_req_t) + ETHERADDRL, BPRI_MED);
	if (mp) {
		dis = (dl_disabmulti_req_t *)mp->b_rptr;
		mp->b_wptr =
		    mp->b_rptr + sizeof (dl_disabmulti_req_t) + ETHERADDRL;
		dis->dl_primitive = DL_DISABMULTI_REQ;
		dis->dl_addr_offset = sizeof (dl_disabmulti_req_t);
		dis->dl_addr_length = ETHERADDRL;
		bcopy(mcast->llcm_addr,
		    (mp->b_rptr + sizeof (dl_disabmulti_req_t)), ETHERADDRL);
		DB_TYPE(mp) = M_PROTO;
		putnext(WR(macinfo->llcp_queue), mp);
	}
}

/*
 * llc1_findminor(device) searches the per device class list of STREAMS for
 * the first minor number not used.  Note that we currently don't allocate
 * minor 0.
 */

static minor_t
llc1_findminor(llc1dev_t *device)
{
	llc1_t *next;
	minor_t	minor;

	ASSERT(device != NULL);
	for (minor = 1; minor <= MAXMIN32; minor++) {
		for (next = device->llc1_str_next;
		    next != NULL && next != (llc1_t *)&device->llc1_str_next;
		    next = next->llc_next) {
			if (minor == next->llc_minor)
				goto nextminor;
		}
		return (minor);
nextminor:
		/* don't need to do anything */
		;
	}
	/*NOTREACHED*/
	return (0);
}

/*
 * llc1_req_info(q) simply construct a DL_INFO_REQ to be sent to the lower
 * stream this is used to populate the macinfo structure.
 */
static int
llc1_req_info(queue_t *q)
{
	dl_info_req_t *info;
	mblk_t *mp;

	mp = allocb(DL_INFO_REQ_SIZE, BPRI_MED);
	if (mp == NULL)
		return (-1);
	DB_TYPE(mp) = M_PCPROTO;
	info = (dl_info_req_t *)mp->b_rptr;
	mp->b_wptr = mp->b_rptr + DL_INFO_REQ_SIZE;
	info->dl_primitive = DL_INFO_REQ;
	putnext(q, mp);
	return (0);
}

/*
 * llc1_req_raw(macinfo) request that the lower stream enter DLIOCRAW mode
 */
static void
llc1_req_raw(llc_mac_info_t *macinfo)
{
	mblk_t *mp;

	mp = mkiocb(DLIOCRAW);
	if (mp == NULL)
		return;

	macinfo->llcp_iocid = ((struct iocblk *)mp->b_rptr)->ioc_id;

	putnext(macinfo->llcp_queue, mp);
	macinfo->llcp_flags |= LLC1_RAW_WAIT;
}

/*
 * llc1_send_bindreq
 * if lower stream isn't bound, bind it to something appropriate
 */
static void
llc1_send_bindreq(llc_mac_info_t *macinfo)
{
	mblk_t *mp;
	dl_bind_req_t *bind;

	if (macinfo->llcp_sap >= 0xFF) {
		/* have to quite sometime if the world is failing */
		macinfo->llcp_sap &= ~(LLC1_BINDING|LLC1_AVAILABLE);
		return;
	}

	mp = allocb(sizeof (dl_bind_req_t), BPRI_MED);
	if (mp == NULL)
		return;

	bind = (dl_bind_req_t *)mp->b_rptr;
	mp->b_wptr = mp->b_rptr + sizeof (dl_bind_req_t);

	bind->dl_primitive = DL_BIND_REQ;
	bind->dl_sap = macinfo->llcp_sap += 2; /* starts at 2, inc by 2  */
	macinfo->llcp_flags |= LLC1_BINDING;
	bind->dl_max_conind = 0;
	bind->dl_service_mode = DL_CLDLS;
	bind->dl_conn_mgmt = 0;
	bind->dl_xidtest_flg = 0;
	putnext(macinfo->llcp_queue, mp);
}

/*
 * llc1_form_udata(lld, macinfo, mp) format a DL_UNITDATA_IND message to be
 * sent to the user
 */
static mblk_t *
llc1_form_udata(llc1_t *lld, llc_mac_info_t *macinfo, mblk_t *mp)
{
	mblk_t *udmp, *nmp;
	dl_unitdata_ind_t *udata;
	struct ether_header *hdr;
	struct llchdr *llchdr;
	struct snaphdr *snap;

	if (macinfo->llcp_flags & LLC1_USING_RAW) {
		hdr = (struct ether_header *)mp->b_rptr;
		llchdr = (struct llchdr *)(hdr + 1);

	    /* allocate the DL_UNITDATA_IND M_PROTO header */
		udmp = allocb(sizeof (dl_unitdata_ind_t) +
		    2 * (macinfo->llcp_addrlen + 5), BPRI_MED);
		if (udmp == NULL) {
		/* might as well discard since we can't go further */
		freemsg(mp);
		return (NULL);
		}
		udata = (dl_unitdata_ind_t *)udmp->b_rptr;
		udmp->b_wptr += sizeof (dl_unitdata_ind_t);

		nmp = dupmsg(mp);	/* make a copy for future streams */
		if (lld->llc_sap != LLC_NOVELL_SAP)
			mp->b_rptr += sizeof (struct ether_header) +
			    sizeof (struct llchdr);
		else
			mp->b_rptr += sizeof (struct ether_header);

		if (lld->llc_flags & LLC_SNAP) {
			mp->b_rptr += sizeof (struct snaphdr);
			snap = (struct snaphdr *)(llchdr + 1);
		}

		/*
		 * now setup the DL_UNITDATA_IND header
		 */
		DB_TYPE(udmp) = M_PROTO;
		udata->dl_primitive = DL_UNITDATA_IND;
		udata->dl_dest_addr_offset = sizeof (dl_unitdata_ind_t);
		bcopy(hdr->ether_dhost.ether_addr_octet,
		    LLCADDR(udata, udata->dl_dest_addr_offset)->llca_addr,
		    macinfo->llcp_addrlen);

		if (lld->llc_flags & LLC_SNAP) {
			udata->dl_dest_addr_length = macinfo->llcp_addrlen + 2;
			LLCSADDR(udata, udata->dl_dest_addr_offset)->llca_ssap =
			    ntohs(*(ushort_t *)snap->snap_type);
		} else {
			udata->dl_dest_addr_length = macinfo->llcp_addrlen + 1;
			LLCADDR(udata, udata->dl_dest_addr_offset)->llca_sap =
			    llchdr->llc_dsap;
		}
		udmp->b_wptr += udata->dl_dest_addr_length;
		udata->dl_src_addr_offset = udata->dl_dest_addr_length +
		    udata->dl_dest_addr_offset;
		bcopy(hdr->ether_shost.ether_addr_octet,
		    LLCADDR(udata, udata->dl_src_addr_offset)->llca_addr,
		    macinfo->llcp_addrlen);
		if (lld->llc_flags & LLC_SNAP) {
			udata->dl_src_addr_length = macinfo->llcp_addrlen + 2;
			LLCSADDR(udata, udata->dl_src_addr_offset)->llca_ssap =
			    ntohs(*(ushort_t *)snap->snap_type);
		} else {
			udata->dl_src_addr_length = macinfo->llcp_addrlen + 1;
			LLCADDR(udata, udata->dl_src_addr_offset)->llca_sap =
			    llchdr->llc_ssap;
		}
		udata->dl_group_address = hdr->ether_dhost.ether_addr_octet[0] &
		    0x1;
		udmp->b_wptr += udata->dl_src_addr_length;
		udmp->b_cont = mp;
	} else {
		dl_unitdata_ind_t *ud2;
		if (mp->b_cont == NULL) {
		return (mp);	/* we can't do anything */
		}
	    /* if we end up here, we only want to patch the existing M_PROTO */
		nmp = dupmsg(mp);	/* make a copy for future streams */
		udata = (dl_unitdata_ind_t *)(mp->b_rptr);
		udmp = allocb(MBLKL(mp) + 4, BPRI_MED);
		bcopy(mp->b_rptr, udmp->b_rptr, sizeof (dl_unitdata_ind_t));
		ud2 = (dl_unitdata_ind_t *)(udmp->b_rptr);
		udmp->b_wptr += sizeof (dl_unitdata_ind_t);
		bcopy((caddr_t)mp->b_rptr + udata->dl_dest_addr_offset,
		    udmp->b_wptr, macinfo->llcp_addrlen);
		ud2->dl_dest_addr_offset = sizeof (dl_unitdata_ind_t);
		ud2->dl_dest_addr_length = macinfo->llcp_addrlen + 1;
		udmp->b_wptr += ud2->dl_dest_addr_length;
		bcopy((caddr_t)udmp->b_rptr + udata->dl_src_addr_offset,
		    udmp->b_wptr, macinfo->llcp_addrlen);
		ud2->dl_src_addr_length = ud2->dl_dest_addr_length;
		udmp->b_wptr += ud2->dl_src_addr_length;
		udmp->b_cont = mp->b_cont;
		if (lld->llc_sap != LLC_NOVELL_SAP)
			mp->b_cont->b_rptr += sizeof (struct llchdr);
		freeb(mp);

		DB_TYPE(udmp) = M_PROTO;
		udata = (dl_unitdata_ind_t *)(mp->b_rptr);
		llchdr = (struct llchdr *)(mp->b_cont->b_rptr);
		LLCADDR(udata, udata->dl_dest_addr_offset)->llca_sap =
		    llchdr->llc_dsap;
		LLCADDR(udata, udata->dl_src_addr_offset)->llca_sap =
		    llchdr->llc_ssap;
	}
#ifdef LLC1_DEBUG
		if (llc1_debug & LLCRECV)
		printf("llc1_recv: queued message to %x (%d)\n",
		    lld->llc_qptr, lld->llc_minor);
#endif
	/* enqueue for the service routine to process */
	putnext(RD(lld->llc_qptr), udmp);
	mp = nmp;
	return (mp);
}

/*
 * llc1_xid_reply(macinfo, mp) automatic reply to an XID command
 */
static mblk_t *
llc1_xid_reply(llc_mac_info_t *macinfo, mblk_t *mp, int sap)
{
	mblk_t *nmp, *rmp;
	struct ether_header *hdr, *msgether;
	struct llchdr *llchdr;
	struct llchdr *msgllc;
	struct llchdr_xid *xid;

	if (DB_TYPE(mp) == M_DATA) {
		hdr = (struct ether_header *)mp->b_rptr;
		llchdr = (struct llchdr *)(hdr + 1);
	} else {
		if (mp->b_cont == NULL)
			return (mp);
		llchdr = (struct llchdr *)(mp->b_cont->b_rptr);
	}

	/* we only want to respond to commands to avoid response loops */
	if (llchdr->llc_ssap & LLC_RESPONSE)
		return (mp);

	nmp = allocb(msgdsize(mp) + LLC_XID_INFO_SIZE, BPRI_MED);
	if (nmp == NULL) {
		return (mp);
	}

	/*
	 * now construct the XID reply frame
	 */
	if (DB_TYPE(mp) == M_DATA) {
		msgether = (struct ether_header *)nmp->b_rptr;
		nmp->b_wptr += sizeof (struct ether_header);
		bcopy(hdr->ether_shost.ether_addr_octet,
		    msgether->ether_dhost.ether_addr_octet,
		    macinfo->llcp_addrlen);
		bcopy(macinfo->llcp_macaddr,
		    msgether->ether_shost.ether_addr_octet,
		    macinfo->llcp_addrlen);
		msgether->ether_type = htons(sizeof (struct llchdr_xid) +
		    sizeof (struct llchdr));
		rmp = nmp;
	} else {
		dl_unitdata_req_t *ud;
		dl_unitdata_ind_t *rud;
		rud = (dl_unitdata_ind_t *)mp->b_rptr;

		rmp = allocb(sizeof (dl_unitdata_req_t) +
		    macinfo->llcp_addrlen + 5, BPRI_MED);
		if (rmp == NULL)
			return (mp);

		DB_TYPE(rmp) = M_PROTO;
		bzero(rmp->b_rptr, sizeof (dl_unitdata_req_t));
		ud = (dl_unitdata_req_t *)rmp->b_rptr;
		ud->dl_primitive = DL_UNITDATA_REQ;
		ud->dl_dest_addr_offset = sizeof (dl_unitdata_req_t);
		ud->dl_dest_addr_length = macinfo->llcp_addrlen + 1;

		rmp->b_wptr += sizeof (dl_unitdata_req_t);
		bcopy(LLCADDR(mp->b_rptr, rud->dl_src_addr_offset),
		    LLCADDR(rmp->b_rptr, ud->dl_dest_addr_offset),
		    macinfo->llcp_addrlen);
		LLCADDR(rmp->b_rptr, ud->dl_dest_addr_offset)->llca_sap =
		    LLCADDR(mp->b_rptr, rud->dl_src_addr_offset)->llca_sap;
		rmp->b_wptr += sizeof (struct llcaddr);
		rmp->b_cont = nmp;
	}

	msgllc = (struct llchdr *)nmp->b_wptr;
	xid = (struct llchdr_xid *)(msgllc + 1);
	nmp->b_wptr += sizeof (struct llchdr);

	msgllc->llc_dsap = llchdr->llc_ssap;

	/* mark it a response */
	msgllc->llc_ssap = sap | LLC_RESPONSE;

	msgllc->llc_ctl = llchdr->llc_ctl;
	xid->llcx_format = LLC_XID_FMTID;
	xid->llcx_class = LLC_XID_TYPE_1;
	xid->llcx_window = 0;	/* we don't have connections yet */

	nmp->b_wptr += sizeof (struct llchdr_xid);
	macinfo->llcp_stats.llcs_xidxmt++;
	putnext(WR(macinfo->llcp_queue), rmp);
	return (mp);
}

/*
 * llc1_xid_ind_con(lld, macinfo, mp) form a DL_XID_IND or DL_XID_CON message
 * to send to the user since it was requested that the user process these
 * messages
 */
static mblk_t *
llc1_xid_ind_con(llc1_t *lld, llc_mac_info_t *macinfo, mblk_t *mp)
{
	mblk_t *nmp;
	dl_xid_ind_t *xid;
	struct ether_header *hdr;
	struct llchdr *llchdr;
	int raw;

	nmp = allocb(sizeof (dl_xid_ind_t) + 2 * (macinfo->llcp_addrlen + 1),
	    BPRI_MED);
	if (nmp == NULL)
		return (mp);

	if ((raw = (DB_TYPE(mp) == M_DATA)) != 0) {
		hdr = (struct ether_header *)mp->b_rptr;
		llchdr = (struct llchdr *)(hdr + 1);
	} else {
		if (mp->b_rptr == NULL)
			return (mp);
		llchdr = (struct llchdr *)mp->b_cont->b_rptr;
	}

	xid = (dl_xid_ind_t *)nmp->b_rptr;
	xid->dl_flag = (llchdr->llc_ctl & LLC_P) ? DL_POLL_FINAL : 0;
	xid->dl_dest_addr_offset = sizeof (dl_xid_ind_t);
	xid->dl_dest_addr_length = macinfo->llcp_addrlen + 1;

	if (raw) {
		bcopy(hdr->ether_dhost.ether_addr_octet,
		    (nmp->b_rptr + xid->dl_dest_addr_offset),
		    xid->dl_dest_addr_length);
	} else {
		dl_unitdata_ind_t *ind;
		ind = (dl_unitdata_ind_t *)mp->b_rptr;
		bcopy(LLCADDR(ind, ind->dl_dest_addr_offset),
		    (nmp->b_rptr + xid->dl_dest_addr_offset),
		    xid->dl_dest_addr_length);
	}

	LLCADDR(xid, xid->dl_dest_addr_offset)->llca_sap =
	    llchdr->llc_dsap;

	xid->dl_src_addr_offset =
	    xid->dl_dest_addr_offset + xid->dl_dest_addr_length;
	xid->dl_src_addr_length = xid->dl_dest_addr_length;

	if (raw) {
		bcopy(hdr->ether_shost.ether_addr_octet,
		    (nmp->b_rptr + xid->dl_src_addr_offset),
		    xid->dl_src_addr_length);
	} else {
		dl_unitdata_ind_t *ind;
		ind = (dl_unitdata_ind_t *)mp->b_rptr;
		bcopy(LLCADDR(mp->b_rptr, ind->dl_src_addr_offset),
		    (nmp->b_rptr + xid->dl_src_addr_offset),
		    ind->dl_src_addr_length);
	}
	LLCADDR(nmp->b_rptr, xid->dl_src_addr_offset)->llca_sap =
	    llchdr->llc_ssap & ~LLC_RESPONSE;

	nmp->b_wptr = nmp->b_rptr + sizeof (dl_xid_ind_t) +
	    2 * xid->dl_dest_addr_length;

	if (!(llchdr->llc_ssap & LLC_RESPONSE)) {
		xid->dl_primitive = DL_XID_IND;
	} else {
		xid->dl_primitive = DL_XID_CON;
	}

	DB_TYPE(nmp) = M_PROTO;
	if (raw) {
		if (MBLKL(mp) >
		    (sizeof (struct ether_header) + sizeof (struct llchdr))) {
			nmp->b_cont = dupmsg(mp);
			if (nmp->b_cont) {
				nmp->b_cont->b_rptr +=
					sizeof (struct ether_header) +
					sizeof (struct llchdr);
			}
		}
	} else if (mp->b_cont != NULL && MBLKL(mp->b_cont) >
						sizeof (struct llchdr)) {
		nmp->b_cont = dupmsg(mp->b_cont);
		(void) adjmsg(nmp->b_cont, sizeof (struct llchdr));
	}
	putnext(RD(lld->llc_qptr), nmp);
	return (mp);
}

/*
 * llc1_xid_req_res(q, mp, req_or_res) the user wants to send an XID message
 * or response construct a proper message and put on the net
 */
static int
llc1_xid_req_res(queue_t *q, mblk_t *mp, int req_or_res)
{
	dl_xid_req_t *xid = (dl_xid_req_t *)mp->b_rptr;
	llc1_t *llc = (llc1_t *)q->q_ptr;
	llc_mac_info_t *macinfo;
	mblk_t *nmp, *rmp;
	struct ether_header *hdr;
	struct llchdr *llchdr;

	if (llc == NULL || llc->llc_state == DL_UNATTACHED)
		return (DL_OUTSTATE);

	if (llc->llc_sap == LLC_NOVELL_SAP)
		return (DL_NOTSUPPORTED);

	if (llc->llc_flags & DL_AUTO_XID)
		return (DL_XIDAUTO);

	macinfo = llc->llc_mac_info;
	if (MBLKL(mp) < sizeof (dl_xid_req_t) ||
	    !MBLKIN(mp, xid->dl_dest_addr_offset, xid->dl_dest_addr_length)) {
		return (DL_BADPRIM);
	}

	nmp = allocb(sizeof (struct ether_header) + sizeof (struct llchdr) +
	    sizeof (struct llchdr_xid), BPRI_MED);

	if (nmp == NULL)
		return (LLCE_NOBUFFER);

	if (macinfo->llcp_flags & LLC1_USING_RAW) {
		hdr = (struct ether_header *)nmp->b_rptr;
		bcopy(LLCADDR(xid, xid->dl_dest_addr_offset)->llca_addr,
		    hdr->ether_dhost.ether_addr_octet, ETHERADDRL);
		bcopy(macinfo->llcp_macaddr,
		    hdr->ether_shost.ether_addr_octet, ETHERADDRL);
		hdr->ether_type = htons(sizeof (struct llchdr) + msgdsize(mp));
		nmp->b_wptr = nmp->b_rptr +
		    sizeof (struct ether_header) + sizeof (struct llchdr);
		llchdr = (struct llchdr *)(hdr + 1);
		rmp = nmp;
	} else {
		dl_unitdata_req_t *ud;
		rmp = allocb(sizeof (dl_unitdata_req_t) +
		    (macinfo->llcp_addrlen + 2), BPRI_MED);
		if (rmp == NULL) {
			freemsg(nmp);
			return (LLCE_NOBUFFER);
		}
		ud = (dl_unitdata_req_t *)rmp->b_rptr;
		DB_TYPE(rmp) = M_PROTO;
		ud->dl_primitive = DL_UNITDATA_REQ;
		ud->dl_dest_addr_offset = sizeof (dl_unitdata_req_t);
		ud->dl_dest_addr_length = xid->dl_dest_addr_length;
		rmp->b_wptr += sizeof (dl_unitdata_req_t);
		bcopy(LLCADDR(xid, xid->dl_dest_addr_offset)->llca_addr,
		    LLCADDR(ud, ud->dl_dest_addr_offset),
		    xid->dl_dest_addr_length);
		LLCSADDR(ud, ud->dl_dest_addr_offset)->llca_ssap =
		    msgdsize(mp);
		rmp->b_wptr += xid->dl_dest_addr_length;
		rmp->b_cont = nmp;
		llchdr = (struct llchdr *)nmp->b_rptr;
		nmp->b_wptr += sizeof (struct llchdr);
	}

	llchdr->llc_dsap = LLCADDR(xid, xid->dl_dest_addr_offset)->llca_sap;
	llchdr->llc_ssap = llc->llc_sap | (req_or_res ? LLC_RESPONSE : 0);
	llchdr->llc_ctl =
	    LLC_XID | ((xid->dl_flag & DL_POLL_FINAL) ? LLC_P : 0);

	nmp->b_cont = mp->b_cont;
	mp->b_cont = NULL;
	freeb(mp);
	macinfo->llcp_stats.llcs_xidxmt++;
	putnext(WR(macinfo->llcp_queue), rmp);
	return (LLCE_OK);
}

/*
 * llc1_test_reply(macinfo, mp)
 * automatic reply to a TEST message
 */
static mblk_t *
llc1_test_reply(llc_mac_info_t *macinfo, mblk_t *mp, int sap)
{
	mblk_t *nmp;
	struct ether_header *hdr, *msgether;
	struct llchdr *llchdr;
	struct llchdr *msgllc;
	int poll_final;

	if (DB_TYPE(mp) == M_PROTO) {
		if (mp->b_cont == NULL)
			return (mp);
		llchdr = (struct llchdr *)mp->b_cont->b_rptr;
		hdr = NULL;
	} else {
		hdr = (struct ether_header *)mp->b_rptr;
		llchdr = (struct llchdr *)(hdr + 1);
	}

	/* we only want to respond to commands to avoid response loops */
	if (llchdr->llc_ssap & LLC_RESPONSE)
		return (mp);

	nmp = copymsg(mp);	/* so info field is duplicated */
	if (nmp == NULL) {
		nmp = mp;
		mp = NULL;
	}
	/*
	 * now construct the TEST reply frame
	 */


	poll_final = llchdr->llc_ctl & LLC_P;

	if (DB_TYPE(nmp) == M_PROTO) {
		dl_unitdata_req_t *udr = (dl_unitdata_req_t *)nmp->b_rptr;
		dl_unitdata_ind_t *udi = (dl_unitdata_ind_t *)nmp->b_rptr;

		/* make into a request */
		udr->dl_primitive = DL_UNITDATA_REQ;
		udr->dl_dest_addr_offset = udi->dl_src_addr_offset;
		udr->dl_dest_addr_length = udi->dl_src_addr_length;
		udr->dl_priority.dl_min = udr->dl_priority.dl_max = 0;
		msgllc = (struct llchdr *)nmp->b_cont->b_rptr;
	} else {
		msgether = (struct ether_header *)nmp->b_rptr;
		bcopy(hdr->ether_shost.ether_addr_octet,
		    msgether->ether_dhost.ether_addr_octet,
		    macinfo->llcp_addrlen);
		bcopy(macinfo->llcp_macaddr,
		    msgether->ether_shost.ether_addr_octet,
		    macinfo->llcp_addrlen);
		msgllc = (struct llchdr *)(msgether+1);
	}

	msgllc->llc_dsap = llchdr->llc_ssap;

	/* mark it as a response */
	msgllc->llc_ssap = sap |  LLC_RESPONSE;
	msgllc->llc_ctl = LLC_TEST | poll_final;

	macinfo->llcp_stats.llcs_testxmt++;
	putnext(WR(macinfo->llcp_queue), nmp);
	return (mp);
}

/*
 * llc1_test_ind_con(lld, macinfo, mp) form a DL_TEST_IND or DL_TEST_CON
 * message to send to the user since it was requested that the user process
 * these messages
 */
static mblk_t *
llc1_test_ind_con(llc1_t *lld, llc_mac_info_t *macinfo, mblk_t *mp)
{
	mblk_t *nmp;
	dl_test_ind_t *test;
	struct ether_header *hdr;
	struct llchdr *llchdr;
	int raw;

	nmp = allocb(sizeof (dl_test_ind_t) + 2 * (ETHERADDRL + 1), BPRI_MED);
	if (nmp == NULL)
		return (NULL);

	if ((raw = (DB_TYPE(mp) == M_DATA)) != 0) {
		hdr = (struct ether_header *)mp->b_rptr;
		llchdr = (struct llchdr *)(hdr + 1);
	} else {
		if (mp->b_rptr == NULL)
			return (mp);
		llchdr = (struct llchdr *)mp->b_cont->b_rptr;
	}

	test = (dl_test_ind_t *)nmp->b_rptr;
	test->dl_flag = (llchdr->llc_ctl & LLC_P) ? DL_POLL_FINAL : 0;
	test->dl_dest_addr_offset = sizeof (dl_test_ind_t);
	test->dl_dest_addr_length = macinfo->llcp_addrlen + 1;

	if (raw) {
		bcopy(hdr->ether_dhost.ether_addr_octet,
		    LLCADDR(nmp->b_rptr, test->dl_dest_addr_offset)->llca_addr,
		    test->dl_dest_addr_length);
	} else {
		dl_unitdata_ind_t *ind;
		ind = (dl_unitdata_ind_t *)mp->b_rptr;
		bcopy(LLCADDR(ind, ind->dl_dest_addr_offset),
		    (nmp->b_rptr + test->dl_dest_addr_offset),
		    test->dl_dest_addr_length);
	}

	LLCADDR(test, test->dl_dest_addr_offset)->llca_sap =
	    llchdr->llc_dsap;

	test->dl_src_addr_offset = test->dl_dest_addr_offset +
	    test->dl_dest_addr_length;
	test->dl_src_addr_length = test->dl_dest_addr_length;

	if (raw) {
		bcopy(hdr->ether_shost.ether_addr_octet,
		    LLCADDR(nmp->b_rptr, test->dl_src_addr_offset)->llca_addr,
		    test->dl_src_addr_length);
	} else {
		dl_unitdata_ind_t *ind;
		ind = (dl_unitdata_ind_t *)mp->b_rptr;
		bcopy(LLCADDR(mp->b_rptr, ind->dl_src_addr_offset),
		    (nmp->b_rptr + test->dl_src_addr_offset),
		    ind->dl_src_addr_length);
	}
	LLCADDR(nmp->b_rptr, test->dl_src_addr_offset)->llca_sap =
	    llchdr->llc_ssap & ~LLC_RESPONSE;

	nmp->b_wptr = nmp->b_rptr + sizeof (dl_test_ind_t) +
	    2 * test->dl_dest_addr_length;

	if (!(llchdr->llc_ssap & LLC_RESPONSE)) {
		test->dl_primitive = DL_TEST_IND;
	} else {
		test->dl_primitive = DL_TEST_CON;
	}

	DB_TYPE(nmp) = M_PROTO;
	if (raw) {
		if (MBLKL(mp) >
		    (sizeof (struct ether_header) + sizeof (struct llchdr))) {
			nmp->b_cont = dupmsg(mp);
			if (nmp->b_cont) {
				nmp->b_cont->b_rptr +=
					sizeof (struct ether_header) +
					sizeof (struct llchdr);
			}
		}
	} else if (mp->b_cont != NULL && MBLKL(mp->b_cont) >
					sizeof (struct llchdr)) {
		nmp->b_cont = dupmsg(mp->b_cont);
		(void) adjmsg(nmp->b_cont, sizeof (struct llchdr));
	}
	putnext(RD(lld->llc_qptr), nmp);
	return (mp);
}

/*
 * llc1_test_req_res(q, mp, req_or_res) the user wants to send a TEST
 * message or response construct a proper message and put on the net
 */
static int
llc1_test_req_res(queue_t *q, mblk_t *mp, int req_or_res)
{
	dl_test_req_t *test = (dl_test_req_t *)mp->b_rptr;
	llc1_t *llc = (llc1_t *)q->q_ptr;
	llc_mac_info_t *macinfo;
	mblk_t *nmp, *rmp;
	struct ether_header *hdr;
	struct llchdr *llchdr;

	if (llc == NULL || llc->llc_state == DL_UNATTACHED)
		return (DL_OUTSTATE);

	if (llc->llc_sap == LLC_NOVELL_SAP)
		return (DL_NOTSUPPORTED);

	if (llc->llc_flags & DL_AUTO_TEST)
		return (DL_TESTAUTO);

	macinfo = llc->llc_mac_info;
	if (MBLKL(mp) < sizeof (dl_test_req_t) ||
	    !MBLKIN(mp, test->dl_dest_addr_offset,
	    test->dl_dest_addr_length)) {
		return (DL_BADPRIM);
	}

	nmp = allocb(sizeof (struct ether_header) + sizeof (struct llchdr),
	    BPRI_MED);

	if (nmp == NULL)
		return (LLCE_NOBUFFER);

	if (macinfo->llcp_flags & LLC1_USING_RAW) {
		hdr = (struct ether_header *)nmp->b_rptr;
		bcopy(LLCADDR(test, test->dl_dest_addr_offset)->llca_addr,
		    hdr->ether_dhost.ether_addr_octet, ETHERADDRL);
		bcopy(macinfo->llcp_macaddr,
		    hdr->ether_shost.ether_addr_octet, ETHERADDRL);
		hdr->ether_type = htons(sizeof (struct llchdr) + msgdsize(mp));
		nmp->b_wptr = nmp->b_rptr +
		    sizeof (struct ether_header) + sizeof (struct llchdr);
		llchdr = (struct llchdr *)(hdr + 1);
		rmp = nmp;
	} else {
		dl_unitdata_req_t *ud;

		rmp = allocb(sizeof (dl_unitdata_req_t) +
		    (macinfo->llcp_addrlen + 2), BPRI_MED);
		if (rmp == NULL) {
			freemsg(nmp);
			return (LLCE_NOBUFFER);

		}
		ud = (dl_unitdata_req_t *)rmp->b_rptr;
		DB_TYPE(rmp) = M_PROTO;
		ud->dl_primitive = DL_UNITDATA_REQ;
		ud->dl_dest_addr_offset = sizeof (dl_unitdata_req_t);
		ud->dl_dest_addr_length = test->dl_dest_addr_length;
		rmp->b_wptr += sizeof (dl_unitdata_req_t);
		bcopy(LLCADDR(test, test->dl_dest_addr_offset)->llca_addr,
		    LLCADDR(ud, ud->dl_dest_addr_offset),
		    test->dl_dest_addr_length);
		LLCSADDR(ud, ud->dl_dest_addr_offset)->llca_ssap =
		    msgdsize(mp);
		rmp->b_wptr += test->dl_dest_addr_length;
		rmp->b_cont = nmp;
		llchdr = (struct llchdr *)nmp->b_rptr;
		nmp->b_wptr += sizeof (struct llchdr);
	}

	llchdr->llc_dsap = LLCADDR(test, test->dl_dest_addr_offset)->llca_sap;
	llchdr->llc_ssap = llc->llc_sap | (req_or_res ? LLC_RESPONSE : 0);
	llchdr->llc_ctl =
	    LLC_TEST | ((test->dl_flag & DL_POLL_FINAL) ? LLC_P : 0);

	nmp->b_cont = mp->b_cont;
	mp->b_cont = NULL;
	freeb(mp);
	macinfo->llcp_stats.llcs_testxmt++;
	putnext(WR(macinfo->llcp_queue), rmp);
	return (LLCE_OK);
}

/*
 * llc1_find_waiting(macinfo, mp, prim) look for a stream waiting for a
 * response to a message identified by prim and send it to the user.
 */
static void
llc1_find_waiting(llc_mac_info_t *macinfo, mblk_t *mp, long prim)
{
	llc1_t *llc;

	for (llc = llc1_device_list.llc1_str_next;
	    llc != (llc1_t *)&llc1_device_list.llc1_str_next;
	    llc = llc->llc_next)
		if (llc->llc_mac_info == macinfo &&
		    prim == llc->llc_waiting_for) {
			putnext(RD(llc->llc_qptr), mp);
			llc->llc_waiting_for = -1;
			return;
		}
	freemsg(mp);
}

static void
llc1insque(void *elem, void *pred)
{
	struct qelem *pelem = elem;
	struct qelem *ppred = pred;
	struct qelem *pnext = ppred->q_forw;

	pelem->q_forw = pnext;
	pelem->q_back = ppred;
	ppred->q_forw = pelem;
	pnext->q_back = pelem;
}

static void
llc1remque(void *arg)
{
	struct qelem *pelem = arg;
	struct qelem *elem = arg;

	ASSERT(pelem->q_forw != NULL);
	pelem->q_forw->q_back = pelem->q_back;
	pelem->q_back->q_forw = pelem->q_forw;
	elem->q_back = elem->q_forw = NULL;
}

/* VARARGS */
static void
llc1error(dev_info_t *dip, char *fmt, char *a1, char *a2, char *a3,
    char *a4, char *a5, char *a6)
{
	static long last;
	static char *lastfmt;
	time_t now;

	/*
	 * Don't print same error message too often.
	 */
	now = gethrestime_sec();
	if ((last == (now & ~1)) && (lastfmt == fmt))
		return;
	last = now & ~1;
	lastfmt = fmt;

	cmn_err(CE_CONT, "%s%d:  ",
	    ddi_get_name(dip), ddi_get_instance(dip));
	cmn_err(CE_CONT, fmt, a1, a2, a3, a4, a5, a6);
	cmn_err(CE_CONT, "\n");
}

/*ARGSUSED1*/
static int
llc1_update_kstat(kstat_t *ksp, int rw)
{
	llc_mac_info_t *macinfo;
	kstat_named_t *kstat;
	struct llc_stats *stats;

	if (ksp == NULL)
		return (0);

	kstat = (kstat_named_t *)(ksp->ks_data);
	macinfo = (llc_mac_info_t *)(ksp->ks_private);
	stats = &macinfo->llcp_stats;

	kstat[LLCS_NOBUFFER].value.ul = stats->llcs_nobuffer;
	kstat[LLCS_MULTIXMT].value.ul = stats->llcs_multixmt;
	kstat[LLCS_MULTIRCV].value.ul = stats->llcs_multircv;
	kstat[LLCS_BRDCSTXMT].value.ul = stats->llcs_brdcstxmt;
	kstat[LLCS_BRDCSTRCV].value.ul = stats->llcs_brdcstrcv;
	kstat[LLCS_BLOCKED].value.ul = stats->llcs_blocked;
	kstat[LLCS_PKTXMT].value.ul = stats->llcs_pktxmt;
	kstat[LLCS_PKTRCV].value.ul = stats->llcs_pktrcv;
	kstat[LLCS_BYTEXMT].value.ul = stats->llcs_bytexmt;
	kstat[LLCS_BYTERCV].value.ul = stats->llcs_bytercv;
	kstat[LLCS_XIDXMT].value.ul = stats->llcs_xidxmt;
	kstat[LLCS_XIDRCV].value.ul = stats->llcs_xidrcv;
	kstat[LLCS_TESTXMT].value.ul = stats->llcs_testxmt;
	kstat[LLCS_TESTRCV].value.ul = stats->llcs_testrcv;
	kstat[LLCS_IERRORS].value.ul = stats->llcs_ierrors;
	kstat[LLCS_OERRORS].value.ul = stats->llcs_oerrors;
	return (0);
}

static void
llc1_init_kstat(llc_mac_info_t *macinfo)
{
	kstat_named_t *ksp;

	/*
	 * Note that the temporary macinfo->llcp_ppa number is negative.
	 */
	macinfo->llcp_kstatp = kstat_create("llc", (-macinfo->llcp_ppa - 1),
	    NULL, "net", KSTAT_TYPE_NAMED,
	    sizeof (struct llc_stats) / sizeof (long), 0);
	if (macinfo->llcp_kstatp == NULL)
		return;

	macinfo->llcp_kstatp->ks_update = llc1_update_kstat;
	macinfo->llcp_kstatp->ks_private = (void *)macinfo;

	ksp = (kstat_named_t *)(macinfo->llcp_kstatp->ks_data);

	kstat_named_init(&ksp[LLCS_NOBUFFER], "nobuffer", KSTAT_DATA_ULONG);
	kstat_named_init(&ksp[LLCS_MULTIXMT], "multixmt", KSTAT_DATA_ULONG);
	kstat_named_init(&ksp[LLCS_MULTIRCV], "multircv", KSTAT_DATA_ULONG);
	kstat_named_init(&ksp[LLCS_BRDCSTXMT], "brdcstxmt", KSTAT_DATA_ULONG);
	kstat_named_init(&ksp[LLCS_BRDCSTRCV], "brdcstrcv", KSTAT_DATA_ULONG);
	kstat_named_init(&ksp[LLCS_BLOCKED], "blocked", KSTAT_DATA_ULONG);
	kstat_named_init(&ksp[LLCS_PKTXMT], "pktxmt", KSTAT_DATA_ULONG);
	kstat_named_init(&ksp[LLCS_PKTRCV], "pktrcv", KSTAT_DATA_ULONG);
	kstat_named_init(&ksp[LLCS_BYTEXMT], "bytexmt", KSTAT_DATA_ULONG);
	kstat_named_init(&ksp[LLCS_BYTERCV], "bytercv", KSTAT_DATA_ULONG);
	kstat_named_init(&ksp[LLCS_XIDXMT], "xidxmt", KSTAT_DATA_ULONG);
	kstat_named_init(&ksp[LLCS_XIDRCV], "xidrcv", KSTAT_DATA_ULONG);
	kstat_named_init(&ksp[LLCS_TESTXMT], "testxmt", KSTAT_DATA_ULONG);
	kstat_named_init(&ksp[LLCS_TESTRCV], "testrcv", KSTAT_DATA_ULONG);
	kstat_named_init(&ksp[LLCS_IERRORS], "ierrors", KSTAT_DATA_ULONG);
	kstat_named_init(&ksp[LLCS_OERRORS], "oerrors", KSTAT_DATA_ULONG);
	kstat_install(macinfo->llcp_kstatp);
}

static void
llc1_uninit_kstat(llc_mac_info_t *macinfo)
{
	if (macinfo->llcp_kstatp) {
		kstat_delete(macinfo->llcp_kstatp);
		macinfo->llcp_kstatp = NULL;
	}
}

/*
 * llc1_subs_bind(q, mp)
 *	implements the DL_SUBS_BIND_REQ primitive
 *	this only works for a STREAM bound to LLC_SNAP_SAP
 *	or one bound to the automatic SNAP mode.
 *	If bound to LLC_SNAP_SAP, the subs bind can be:
 *	- 2 octets treated as a native byte order short (ethertype)
 *	- 3 octets treated as a network order byte string (OID part)
 *	- 5 octets treated as a network order byte string (full SNAP header)
 *	If bound to an automatic SNAP mode sap, then only the 3 octet
 *	form is allowed
 */
static int
llc1_subs_bind(queue_t *q, mblk_t *mp)
{
	llc1_t *lld = (llc1_t *)q->q_ptr;
	dl_subs_bind_req_t *subs = (dl_subs_bind_req_t *)mp->b_rptr;
	ushort_t subssap;
	uchar_t *sapstr;
	int result;


#if defined(LLC1_DEBUG)
	if (llc1_debug & (LLCTRACE|LLCPROT)) {
			printf("llc1_subs_bind (%x, %x)\n", q, mp);
	}
#endif

	if (lld == NULL || lld->llc_state != DL_IDLE) {
		result = DL_OUTSTATE;
	} else if (lld->llc_sap != LLC_SNAP_SAP ||
	    subs->dl_subs_bind_class != DL_HIERARCHICAL_BIND) {
		/* we only want to support this for SNAP at present */
		result = DL_UNSUPPORTED;
	} else {

		lld->llc_state = DL_SUBS_BIND_PND;

		sapstr = (uchar_t *)(mp->b_rptr + subs->dl_subs_sap_offset);

		result = LLCE_OK;
		switch (subs->dl_subs_sap_length) {
		case 2:		/* just the ethertype part */
			if (lld->llc_flags & LLC_SNAP) {
				result = DL_BADADDR;
				break;
			}
			((uchar_t *)&subssap)[0] = sapstr[0];
			((uchar_t *)&subssap)[1] = sapstr[1];
			subssap = htons(subssap);
			lld->llc_snap[3] = ((uchar_t *)&subssap)[0];
			lld->llc_snap[4] = ((uchar_t *)&subssap)[1];
			lld->llc_flags |= LLC_SNAP;
			break;

		case 3:		/* just the OID part */
			if ((lld->llc_flags & (LLC_SNAP|LLC_SNAP_OID)) ==
			    (LLC_SNAP|LLC_SNAP_OID)) {
				result = DL_BADADDR;
				break;
			}
			bcopy(sapstr, lld->llc_snap, 3);
			lld->llc_flags |= LLC_SNAP_OID;
			break;

		case 5:		/* full SNAP header */
			if (lld->llc_flags & (LLC_SNAP|LLC_SNAP_OID)) {
				result = DL_BADADDR;
				break;
			}
			bcopy(sapstr, lld->llc_snap, 5);
			lld->llc_flags |= LLC_SNAP|LLC_SNAP_OID;
			break;
		}
		/* if successful, acknowledge and enter the proper state */
		if (result == LLCE_OK) {
			mblk_t *nmp = mp;
			dl_subs_bind_ack_t *ack;

			if (DB_REF(mp) != 1 ||
			    MBLKL(mp) < (sizeof (dl_subs_bind_ack_t) + 5)) {
				freemsg(mp);
				nmp = allocb(sizeof (dl_subs_bind_ack_t) + 5,
				    BPRI_MED);
			}
			ack = (dl_subs_bind_ack_t *)nmp->b_rptr;
			nmp->b_wptr = nmp->b_rptr +
			    sizeof (dl_subs_bind_ack_t) + 5;
			ack->dl_primitive = DL_SUBS_BIND_ACK;
			ack->dl_subs_sap_offset = sizeof (dl_subs_bind_ack_t);
			ack->dl_subs_sap_length = 5;
			bcopy(lld->llc_snap,
			    (caddr_t)nmp->b_rptr + ack->dl_subs_sap_offset + 5,
			    5);
			DB_TYPE(nmp) = M_PCPROTO;
			qreply(q, nmp);

		}
		lld->llc_state = DL_IDLE;
	}
	return (result);
}

/*
 *
 */
static int
llc1_subs_unbind(void)
{
	return (DL_UNSUPPORTED);
}

char *
snapdmp(uchar_t *bstr)
{
	static char buff[32];

	(void) sprintf(buff, "%x.%x.%x.%x.%x",
	    bstr[0],
	    bstr[1],
	    bstr[2],
	    bstr[3],
	    bstr[4]);
	return (buff);
}

static int
llc1_snap_match(llc1_t *lld, struct snaphdr *snap)
{
	return (bcmp(snap->snap_oid, lld->llc_snap, 5) == 0);
}
