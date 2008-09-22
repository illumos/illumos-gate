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
 * pem - PCMCIA Event Manager
 *
 * gives user level access to PCMCIA event notification and
 * allows managing devices
 */

#if defined(DEBUG)
#define	PEM_DEBUG
#endif

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/devops.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/kstat.h>
#include <sys/debug.h>
#include <sys/callb.h>

#include <sys/autoconf.h>

#include <sys/pctypes.h>
#include <pcmcia/sys/cs_types.h>
#include <sys/pcmcia.h>
#include <sys/sservice.h>
#include <pcmcia/sys/cis.h>
#include <pcmcia/sys/cis_handlers.h>
#include <pcmcia/sys/cs.h>
#include <pcmcia/sys/cs_priv.h>
#include <pcmcia/sys/cs_stubs.h>

#include <sys/spl.h>

#include <sys/pem.h>

#ifdef PEM_DEBUG
int	pem_debug = 0;
#endif

int pem_softint_pend = 0;
int pem_softint_posted = 0;

char _depends_on[] = "misc/pcmcia";

static int (*cardservices)();
static int (*Socket_Services)(int, ...);
uint32_t pem_minors;		/* minors are bit mask */

/*
 * function prototypes, etc.
 */
int _init(void);
int _fini(void);
int _info(struct modinfo *modinfop);

static	int pem_open(queue_t *, dev_t *, int, int, cred_t *);
static	int pem_close(queue_t *, int, cred_t *);
static	int pem_wput(queue_t *, mblk_t *);
static	int pem_wsrv(queue_t *q);
static	int pem_rsrv(queue_t *q);
static  int pem_attach(dev_info_t *, ddi_attach_cmd_t);
static  int pem_detach(dev_info_t *, ddi_detach_cmd_t);
static	int pem_devinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static 	int pem_event_handler(int, int, int, void *);
static  uint32_t pem_soft_intr(caddr_t);
static int pem_ioctl(queue_t *, mblk_t *);
static int pem_cmds(queue_t *q, mblk_t *mp);
static void pem_error(queue_t *q, mblk_t *, int, int, int);
static int pem_init_req(queue_t *, mblk_t *, em_init_req_t *);
static int pem_info_req(queue_t *, mblk_t *, em_info_req_t *);
static int pem_modify_event_req(queue_t *, mblk_t *,
					em_modify_event_mask_req_t *);
static int pem_adapter_info(queue_t *, mblk_t *);
static int pem_socket_info(queue_t *, mblk_t *);
static int pem_get_socket(queue_t *, mblk_t *);
static int pem_ident_socket(queue_t *, mblk_t *);
static void pem_event_dispatch(int, int, int, void *);
extern dev_info_t *pcmcia_get_devinfo(int);
extern int pcmcia_get_minors(dev_info_t *, struct pcm_make_dev **);
static void pem_flushqueue(queue_t *);

kmutex_t pem_global_lock;
kmutex_t pem_intr_lock;
kcondvar_t pem_condvar;


ddi_softintr_t pem_intr_id;
ddi_iblock_cookie_t pem_iblock;
ddi_idevice_cookie_t pem_dcookie;

client_handle_t pem_cs_handle;

static struct pem_inst {
	pem_t *pi_pem;
	queue_t *pi_queue;
} *pem_instances;

struct pem_event pem_events[PEM_MAX_EVENTS];

/*
 * Allocate and zero-out "number" structures each of type "structure" in
 * kernel memory.
 */
#define	GETSTRUCT(structure, number)   \
	((structure *) kmem_zalloc(\
		(uint32_t)(sizeof (structure) * (number)), KM_NOSLEEP))

/* STREAMS setup glue */
static struct module_info pem_minfo = {
	PEM_IDNUM,
	PEM_NAME,
	PEM_MIN,
	PEM_MAX,
	PEM_HIWATER,
	PEM_LOWATER
};

static struct qinit pem_rint = {
	NULL,
	pem_rsrv,
	pem_open,
	pem_close,
	NULL,
	&pem_minfo
};

static struct qinit pem_wint = {
	pem_wput,
	pem_wsrv,
	NULL,
	NULL,
	NULL,
	&pem_minfo
};

static struct streamtab pem_info = {
	&pem_rint,
	&pem_wint,
	NULL,
	NULL
};

DDI_DEFINE_STREAM_OPS(pem_ops, nulldev, nulldev, pem_attach, pem_detach,
			nodev, pem_devinfo, D_NEW | D_MP, &pem_info,
			ddi_quiesce_not_supported);
/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_driverops;

static struct modldrv modlmisc = {
	&mod_driverops,		/* Type of module - a utility provider */
	"PCMCIA Event Manager",
	&pem_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *) &modlmisc, NULL
};



int
_init(void)
{
	int e;

	if ((e = ddi_soft_state_init((void **)&pem_instances,
	    sizeof (struct pem_inst), 1)) != 0)
		return (e);

	mutex_init(&pem_global_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&pem_condvar, NULL, CV_DRIVER, NULL);

	e = mod_install(&modlinkage);

	if (e != 0) {
		mutex_destroy(&pem_global_lock);
		cv_destroy(&pem_condvar);
		ddi_soft_state_fini((void **)&pem_instances);
	}

	return (e);
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&modlinkage)) == 0) {
		mutex_destroy(&pem_global_lock);
		cv_destroy(&pem_condvar);
		ddi_soft_state_fini((void **)&pem_instances);
	}
	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


static int
pem_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	uchar_t events[EM_EVENT_SIZE];
	int i;

	switch (cmd) {
	case DDI_ATTACH:
		for (i = 0; i < EM_EVENT_SIZE; i++)
			events[i] = (uchar_t)~0;
		i = pcmcia_set_em_handler(pem_event_handler,
		    (caddr_t)events,
		    sizeof (events),
		    0x1234,
		    (void **)&cardservices,
		    (void **)&Socket_Services);
		if (i != 0) {
#if defined(PEM_DEBUG)
			if (pem_debug)
				cmn_err(CE_CONT, "pem: no event handler\n");
#endif
			return (DDI_FAILURE);
		}

		(void) ddi_create_minor_node(dip, "pem", S_IFCHR, 0,
		    "pcmcia:event", 0);

		(void) ddi_add_softintr(dip, DDI_SOFTINT_MED, &pem_intr_id,
		    &pem_iblock,
		    0,
		    pem_soft_intr, (caddr_t)dip);

		mutex_init(&pem_intr_lock, NULL, MUTEX_DRIVER,
		    (void *)(uintptr_t)__ipltospl(SPL7));
		break;

	case DDI_RESUME:
		/*
		 * we need to tell the daemon to start all over again
		 * since the world state may have changed.
		 */
		break;

	default:
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
pem_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	clock_t tm;

#ifdef PEM_DEBUG
	if (pem_debug & PEMTRACE)
		cmn_err(CE_CONT, "pem_detach cmd=%d pem_minors=%d"
		    " pem_softint_posted=%d\n",
		    cmd, pem_minors, pem_softint_posted);
#endif

	switch (cmd) {
	case DDI_DETACH:
		if (pem_minors != 0)
			return (DDI_FAILURE);
		mutex_enter(&pem_intr_lock);
		(void) pcmcia_set_em_handler(NULL, NULL, 0, 0x1234, NULL, NULL);

		while (pem_softint_posted > 0) {
			/*
			 * delay for 1 second to allow outstanding soft
			 * interrupts to be processed before removing the
			 * soft interrupt handler.
			 */
			tm = ddi_get_lbolt();
			(void) cv_timedwait(&pem_condvar, &pem_intr_lock,
			    tm + drv_usectohz(100000));
		}

		ddi_remove_softintr(pem_intr_id);
		pem_intr_id = 0;
		mutex_exit(&pem_intr_lock);
		mutex_destroy(&pem_intr_lock);
		break;
	case DDI_SUSPEND:
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
pem_devinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int error = DDI_SUCCESS;
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = 0;
		break;
	default:
		error = DDI_FAILURE;
		break;
	}
	return (error);
}

/*
 * PEM service routines
 */

/*
 * pem_open(q, dev, flag, sflag, cred)
 * generic open routine.  Hardware open will call this. The
 * hardware open passes in the pemevice structure (one per device class) as
 * well as all of the normal open parameters.
 */
/* ARGSUSED */
static int
pem_open(queue_t *q, dev_t *dev, int flag, int sflag, cred_t *cred)
{
	pem_t  *pem;
	mblk_t *mp;
	struct pem_inst *inst;
	minor_t minordev;

	ASSERT(q);

	ASSERT(q->q_ptr == NULL);	/* Clone device gives us a fresh Q */

	mutex_enter(&pem_global_lock);
	/* find minor device number */
	minordev = ddi_ffs(~pem_minors);
	if (minordev == 0) {
		mutex_exit(&pem_global_lock);
		return (ENXIO);
	}

	if (ddi_soft_state_zalloc(pem_instances, minordev - 1) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "pem: cannot allocate state");
		mutex_exit(&pem_global_lock);
		return (ENXIO);
	}
	inst = (struct pem_inst *)ddi_get_soft_state(pem_instances,
	    minordev - 1);

	if (inst == NULL) {
		mutex_exit(&pem_global_lock);
		return (ENXIO);
	}

	pem_minors |= 1 << (minordev - 1);
	*dev = makedevice(getmajor(*dev), minordev);
	minordev--;

	if (pem_cs_handle == 0 && cardservices != NULL) {
		client_reg_t reg;
#if defined(PEM_DEBUG)
		int result;
#endif

		reg.dip = NULL;
		reg.Attributes = INFO_SOCKET_SERVICES;
		reg.EventMask = 0;
		reg.event_handler = NULL;
		reg.Version = CS_VERSION;
#if defined(PEM_DEBUG)
		result = cardservices(RegisterClient, &pem_cs_handle, &reg);
		if (pem_debug && result != CS_SUCCESS)
			cmn_err(CE_CONT, "pem: couldn't register for CS\n");
#else
		(void) cardservices(RegisterClient, &pem_cs_handle, &reg);
#endif

	}

	mutex_exit(&pem_global_lock);

	/*
	 * get a per-stream structure and link things together so we
	 * can easily find them later.
	 */
	mp = allocb(sizeof (pem_t), BPRI_MED);
	if (mp == NULL) {
		return (ENOSR);
	}

	pem = (pem_t *)mp->b_rptr;
	ASSERT(pem != NULL);
	bzero((caddr_t)mp->b_rptr, sizeof (pem_t));
	pem->pem_mb = mp;
	pem->pem_qptr = WR(q);
	pem->pem_id = 0x1234;
	WR(q)->q_ptr = q->q_ptr = (caddr_t)pem;
	pem->pem_minor = minordev;

	inst->pi_pem = pem;
	inst->pi_queue = WR(q);

	qprocson(q);		/* start the queues running */
	qenable(WR(q));
	return (0);
}

/*
 * pem_close(q) normal stream close call checks current status and cleans up
 * data structures that were dynamically allocated
 */
/* ARGSUSED */
static int
pem_close(queue_t *q, int flag, cred_t *cred)
{
	pem_t	*pem = (pem_t *)q->q_ptr;
	struct pem_inst *inst;
	int minor;

	ASSERT(q);
	ASSERT(pem);

	qprocsoff(q);

	mutex_enter(&pem_global_lock);
	/* disassociate the stream from the device */
	q->q_ptr = WR(q)->q_ptr = NULL;

	if (pem != NULL && pem_instances != NULL) {
		inst = (struct pem_inst *)ddi_get_soft_state(pem_instances,
		    pem->pem_minor);
		if (inst != NULL) {

			minor = pem->pem_minor;
			pem_minors &= ~(1 << minor);

			freeb(pem->pem_mb);
			inst->pi_pem = NULL;
			inst->pi_queue = NULL;
			ddi_soft_state_free(pem_instances, minor);
		}
	}

	mutex_exit(&pem_global_lock);

	return (0);
}

/*
 * pem_wput(q, mp)
 * general pem stream write put routine. Receives ioctl's from
 * user level and data from upper modules and processes them immediately.
 * M_PROTO/M_PCPROTO are queued for later processing by the service
 * procedure.
 */

static int
pem_wput(q, mp)
	queue_t *q;		/* queue pointer */
	mblk_t *mp;		/* message pointer */
{
	int err = 0;
#ifdef PEM_DEBUG
	if (pem_debug & PEMTRACE)
		cmn_err(CE_CONT, "pem_wput(%p %p): type %x\n",
			(void *)q, (void *)mp, DB_TYPE(mp));
#endif

	switch (DB_TYPE(mp)) {
	case M_IOCTL:		/* no waiting in ioctl's */
		err = pem_ioctl(q, mp);
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

	case M_PROTO:
	case M_PCPROTO:
		/* for now, we will always queue  proto messages */
		(void) putq(q, mp);
		break;

	case M_DATA:
		/* force a fatal error */
		merror(q, mp, EIO);
		break;
	default:
#ifdef PEM_DEBUG
		if (pem_debug & PEMERRS)
			cmn_err(CE_CONT,
				"pem: Unexpected packet type from queue: %x\n",
				DB_TYPE(mp));
#endif
		freemsg(mp);
		break;
	}
	return (err);
}

/*
 * pem_wsrv - Incoming messages are processed according to the DLPI protocol
 * specification
 */
static int
pem_wsrv(q)
	queue_t *q;		/* queue pointer */
{
	mblk_t *mp;
	int	err = 0;

#ifdef PEM_DEBUG
	if (pem_debug & PEMTRACE)
		cmn_err(CE_CONT, "pem_wsrv(%p)\n", (void *)q);
#endif


	while ((mp = getq(q)) != NULL) {
		switch (DB_TYPE(mp)) {
		case M_IOCTL:
			/* case where we couldn't do it in the put procedure */
			err = pem_ioctl(q, mp);
			break;
		case M_PROTO:	/* Will be an PM message of some type */
		case M_PCPROTO:
			if ((err = pem_cmds(q, mp)) != PEME_OK) {
				pem_error(q, mp, err, 0, 0);
			}
			break;
		case M_DATA:
			freemsg(mp);
			(void) putctl1(RD(q), M_ERROR, EIO);
			break;

			/* This should never happen */
		default:
#ifdef PEM_DEBUG
			if (pem_debug & PEMERRS)
				cmn_err(CE_CONT,
					"pem_wsrv: db_type(%x) not supported\n",
					mp->b_datap->db_type);
#endif
			freemsg(mp);	/* unknown types are discarded */
			break;
		}
	}
	return (err);
}

/*
 * pem_rsrv(q)
 *	simple read service procedure
 *	purpose is to avoid the time it takes for packets
 *	to move through IP so we can get them off the board
 *	as fast as possible due to limited PC resources.
 */
static int
pem_rsrv(queue_t *q)
{
	mblk_t *mp;
	while ((mp = getq(q)) != NULL) {
		putnext(q, mp);
	}
	return (0);
}

/*
 * pem_ioctl(q, mp)
 * handles all ioctl requests passed downstream. This routine is
 * passed a pointer to the message block with the ioctl request in it, and a
 * pointer to the queue so it can respond to the ioctl request with an ack.
 */
static int
pem_ioctl(queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp;

#ifdef PEM_DEBUG
	if (pem_debug & PEMTRACE)
		cmn_err(CE_CONT, "pem_ioctl(%p %p)\n", (void *)q, (void *)mp);
#endif
	iocp = (struct iocblk *)mp->b_rptr;
	switch (iocp->ioc_cmd) {
	default:
		miocnak(q, mp, 0, EINVAL);
		break;
	}
	return (0);
}

/*
 * pem_cmds(q, mp)
 *	process the PM commands as defined in em.h
 *	note that the primitives return status which is passed back
 *	to the service procedure.
 */
static int
pem_cmds(q, mp)
	queue_t *q;		/* queue pointer */
	mblk_t *mp;		/* message pointer */
{
	int result = EINVAL;
	union em_primitives *prim = (union em_primitives *)mp->b_rptr;

#ifdef PEM_DEBUG
	if (pem_debug & PEMTRACE)
		cmn_err(CE_CONT,
			"pem_cmds(%p, %p):pem=(N/A), prim->em_primitive=%d\n",
			(void *)q, (void *)mp, (int)prim->em_primitive);
#endif

	switch (prim->em_primitive) {
	case EM_INIT_REQ:
		result = pem_init_req(q, mp, &prim->init_req);
		break;
	case EM_INFO_REQ:
		result = pem_info_req(q, mp, &prim->info_req);
		break;
	case EM_MODIFY_EVENT_MASK_REQ:
		result = pem_modify_event_req(q, mp,
						&prim->modify_event_mask_req);
		break;

	case EM_ADAPTER_INFO_REQ:
		result = pem_adapter_info(q, mp);
		break;
	case EM_SOCKET_INFO_REQ:
		result = pem_socket_info(q, mp);
		break;
	case EM_GET_SOCKET_REQ:
		result = pem_get_socket(q, mp);
		break;
	case EM_IDENT_SOCKET_REQ:
		result = pem_ident_socket(q, mp);
		break;
	default:
#ifdef PEM_DEBUG
		if (pem_debug & PEMERRS)
			cmn_err(CE_CONT,
				"pem_cmds: unknown M_PROTO message: %d\n",
				(int)prim->em_primitive);
#endif
		result = EM_BADPRIM;
	}
	return (result);
}

/*
 * pem_info_req - generate the response to an info request
 */
/* ARGSUSED */
static int
pem_info_req(queue_t *q, mblk_t *mp, em_info_req_t *inforeq)
{
	pem_t  *pem;
	int bufsize;
	em_info_ack_t *infoack;

#ifdef PEM_DEBUG
	if (pem_debug & PEMTRACE)
		cmn_err(CE_CONT, "pem_inforeq(%p %p)\n", (void *)q, (void *)mp);
#endif
	pem = (pem_t *)q->q_ptr;
	ASSERT(pem);

	bufsize = sizeof (em_info_ack_t) + EM_EVENT_SIZE * 2;
	mp = mexchange(q, mp, bufsize, M_PCPROTO, EM_INFO_ACK);
	if (mp) {
		infoack = (em_info_ack_t *)mp->b_rptr;
		bzero((caddr_t)infoack, bufsize);
		infoack->em_state = pem->pem_state;
		infoack->em_version = EM_CURRENT_VERSION;
		if (pem->pem_flags & PEMF_EVENTS) {
			infoack->em_event_mask_length = EM_EVENT_SIZE;
			infoack->em_event_mask_offset = sizeof (em_info_ack_t);
			bcopy((caddr_t)pem->pem_event_mask,
			    (caddr_t)mp->b_rptr +
			    infoack->em_event_mask_offset, EM_EVENT_SIZE);
		}
		if (pem->pem_flags & PEMF_CLASSES) {
			infoack->em_event_class_length = EM_CLASS_SIZE;
			infoack->em_event_class_offset =
			    sizeof (em_info_ack_t) +
			    infoack->em_event_mask_length;
			bcopy((caddr_t)pem->pem_event_class,
			    (caddr_t)mp->b_rptr +
			    infoack->em_event_class_offset, EM_CLASS_SIZE);
		}
		qreply(q, mp);
	}

	return (PEME_OK);
}

/*
 * pem_init_req - initialize the open stream to receive events, etc.
 */

static int
pem_init_req(queue_t *q, mblk_t *mp, em_init_req_t *initreq)
{
	uchar_t *event, *class;
	pem_t *pem = (pem_t *)q->q_ptr;

	if (pem == NULL) {
		cmn_err(CE_CONT, "pem_init_req: no pem\n");
		return (PEME_UNAVAILABLE);
	}
	pem_flushqueue(q);

	if (initreq->em_event_mask_offset != 0)
		event = ((uchar_t *)initreq) + initreq->em_event_mask_offset;
	else
		event = NULL;
	if (initreq->em_event_class_offset != 0)
		class = ((uchar_t *)initreq) + initreq->em_event_class_offset;
	else
		class = NULL;

	if (event != NULL && initreq->em_event_mask_length <= EM_EVENT_SIZE) {
		bcopy((caddr_t)event, (caddr_t)pem->pem_event_mask,
		    initreq->em_event_mask_length);
		pem->pem_flags |= PEMF_EVENTS;
	}
	if (class != NULL && initreq->em_event_mask_length <= EM_CLASS_SIZE) {
		bcopy((caddr_t)class, (caddr_t)pem->pem_event_class,
		    initreq->em_event_class_length);
		pem->pem_flags |= PEMF_CLASSES;
	}
#if	defined(PEM_DEBUG)
	if (pem_debug) {
		cmn_err(CE_CONT, "pem_init_req:\n");
		cmn_err(CE_CONT, "\tevent mask = %x (len=%d)\n",
		    (int)(*(uint32_t *)event),
		    (int)initreq->em_event_mask_length);
	}
#endif
	pem->pem_flags |= PEMF_INIT;
	pem->pem_state = EM_INIT;

	mp = mexchange(q, mp, sizeof (em_init_ack_t), M_PCPROTO, EM_INIT_ACK);
	if (mp != NULL)
		qreply(q, mp);

	return (PEME_OK);
}

int
pem_get_first_tuple(queue_t *q, mblk_t *mp, em_get_first_tuple_req_t *treq)
{
	tuple_t tuple;
	cisinfo_t cisinfo;
	int result, len;
	cisparse_t parse;

	if (pem_cs_handle == 0) {
		return (PEME_UNAVAILABLE);
	}
	if (cardservices(ValidateCIS, pem_cs_handle, &cisinfo) != SUCCESS) {
		return (PEME_NO_CIS);
	}

	tuple.DesiredTuple = treq->em_desired_tuple;
	tuple.Socket = treq->em_socket;

	if ((result = cardservices(GetFirstTuple, pem_cs_handle, &tuple)) !=
	    SUCCESS) {
		pem_error(q, mp, EM_GET_FIRST_TUPLE_REQ, PEME_NO_TUPLE,
		    result);
		return (PEME_OK);
	}

	/* now have a tuple so lets construct a proper response */

	len = tuple.TupleDataLen; /* start assuming length of raw data */
	len += sizeof (em_get_next_tuple_ack_t);
	mp = mexchange(q, mp, len, M_PROTO, EM_GET_FIRST_TUPLE_ACK);
	if (mp == NULL)
		return (PEME_OK);

	result = cardservices(ParseTuple, pem_cs_handle, &tuple, &parse, NULL);
	if (result == CS_SUCCESS) {
		mp->b_cont = allocb(sizeof (cisinfo_t), BPRI_MED);
		if (mp->b_cont)
			mp->b_cont->b_wptr += sizeof (cisinfo_t);
	}
	qreply(q, mp);
	return (0);
}

/*
 * pem_flushqueue(q)
 *	used by DLPI primitives that require flushing the queues.
 *	essentially, this is DL_UNBIND_REQ.
 */
static void
pem_flushqueue(queue_t *q)
{
	/* flush all data in both queues */
	flushq(q, FLUSHDATA);
	flushq(WR(q), FLUSHDATA);
	/* flush all the queues upstream */
	(void) putctl1(q, M_FLUSH, FLUSHRW);
}

static int
pem_claim(struct pem_event *pe)
{
	int result = 0;
	mutex_enter(&pem_intr_lock);
	if (pe->pe_owner == PE_OWN_FREE) {
		result++;
		pe->pe_owner++;
	}
	mutex_exit(&pem_intr_lock);
	return (result);
}

static void
pem_event_ind(queue_t *q, uint32_t event, uint32_t socket, void *arg)
{
	mblk_t *mp;
	int len;
	em_event_ind_t *ind;

	len = sizeof (em_event_ind_t);
	switch (event) {
	case PCE_DEV_IDENT:
		len += strlen((char *)arg) + 1;
		break;
	case PCE_INIT_DEV:
		len += sizeof (struct pcm_make_dev);
		break;
	}

	mp = allocb(len + sizeof (struct pem_event), BPRI_MED);
	if (mp == NULL)
		return;
	mp->b_cont = NULL;
	DB_TYPE(mp) = M_PROTO;
	ind = (em_event_ind_t *)(mp->b_rptr);
	mp->b_wptr += len;

	ind->em_primitive = EM_EVENT_IND;
	ind->em_logical_socket = socket;
	ind->em_event = event;
	switch (event) {
		struct pcm_make_dev *devp;
	case PCE_DEV_IDENT:
		ind->em_event_info_offset = sizeof (em_event_ind_t);
		ind->em_event_info_length = strlen((char *)arg) + 1;
		(void) strncpy((char *)mp->b_rptr + sizeof (em_event_ind_t),
		    (char *)arg, PEMMAXINFO - 1);
		break;
	case PCE_INIT_DEV:
		ind->em_event_info_offset = sizeof (em_event_ind_t);
		ind->em_event_info_length = sizeof (struct pcm_make_dev);
		devp = (struct pcm_make_dev *)arg;
		bcopy((caddr_t)devp,
		    (caddr_t)(mp->b_rptr + sizeof (em_event_ind_t)),
		    PEMMAXINFO);
		break;
	}
	(void) putq(q, mp);
}

/* ARGSUSED */
uint32_t
pem_soft_intr(caddr_t arg)
{
	int i;
	struct pem_event *pe;
	int serviced = 0;

	do {
		mutex_enter(&pem_intr_lock);
		pem_softint_pend = 0;
		mutex_exit(&pem_intr_lock);

		for (i = 0, pe = pem_events; i < PEM_MAX_EVENTS; i++, pe++) {
			if (pe->pe_owner == PE_OWN_HANDLER) {
				/* have an event */
				pem_event_dispatch(pe->pe_id, pe->pe_event,
				    pe->pe_socket,
				    pe->pe_info);
				mutex_enter(&pem_intr_lock);
				pe->pe_owner = PE_OWN_FREE;
				serviced = 1;
				pem_softint_posted--;
				mutex_exit(&pem_intr_lock);
			}
		}
	} while (pem_softint_pend);

	if (serviced)
		return (DDI_INTR_CLAIMED);
	return (DDI_INTR_UNCLAIMED);
}

static void
pem_event_dispatch(int id, int event, int socket, void *arg)
{
	uint32_t minors;
	int i;
	struct pem_inst *inst;
	pem_t *pem;
	queue_t *q;

#if	defined(PEM_DEBUG)
	if (pem_debug)
		cmn_err(CE_CONT, "pem_event_dispatch(%x, %x, %x, %p)\n",
		    id, event, socket, (void *)arg);
#endif
	if (pem_instances == NULL)
		return;
	mutex_enter(&pem_global_lock);
	for (i = 0, minors = pem_minors;
	    minors != 0 && i < 4; minors >>= 1, i++) {
		if (minors & 1) {
			inst = ddi_get_soft_state(pem_instances, i);
			if (inst == NULL) {
				continue;
			}
			pem = inst->pi_pem;
			if (pem == NULL)
				continue;
#if	defined(PEM_DEBUG)
			if (pem_debug)
				cmn_err(CE_CONT,
				    "\tflags=%x, id=%x, wanted=%d\n",
				    (int)pem->pem_flags,
				    (int)pem->pem_id,
				    PR_GET(pem->pem_event_mask, event));
#endif
			if (pem->pem_flags & PEMF_EVENTS &&
			    pem->pem_id == id &&
			    PR_GET(pem->pem_event_mask, event)) {
				q = pem->pem_qptr;
				pem_event_ind(RD(q), event, socket, arg);
			}
		}
	}
	mutex_exit(&pem_global_lock);
}

static int
pem_event_handler(int id, int event, int socket, void *arg)
{
	int i;
	struct pem_event *pe;
	int didevents = 0;

#if	defined(PEM_DEBUG)
	if (pem_debug)
		cmn_err(CE_CONT, "pem_event_handler(%x, %x, %x, %p)\n",
		    id, event, socket, (void *)arg);
#endif
	for (i = 0, pe = pem_events; i < PEM_MAX_EVENTS; i++, pe++) {
		if (pem_claim(pe)) {
			pe->pe_event = event;
			pe->pe_socket = socket;
			pe->pe_id = id;
			pe->pe_owner ++; /* give to soft int */
			switch (event) {
				struct pcm_make_dev *devp;
			case PCE_DEV_IDENT:
				if (arg != NULL)
					(void) strncpy((char *)pe->pe_info,
					    (char *)arg,
					    MODMAXNAMELEN);
				break;
			case PCE_INIT_DEV:
				devp = (struct pcm_make_dev *)arg;
				if (arg != NULL)
					bcopy((caddr_t)devp,
					    (caddr_t)pe->pe_info,
					    PEMMAXINFO);
			}
			didevents = 1;
			break;
		}
	}
	mutex_enter(&pem_intr_lock);
	if (didevents && pem_intr_id != 0) {
		pem_softint_pend = 1;
		pem_softint_posted++;
		mutex_exit(&pem_intr_lock);
		ddi_trigger_softintr(pem_intr_id);
	} else
		mutex_exit(&pem_intr_lock);
	return (0);
}

/* ARGSUSED */
static void
pem_error(queue_t *q, mblk_t *mp, int primitive, int error, int suberr)
{}

/* ARGSUSED */
static int
pem_modify_event_req(queue_t *q, mblk_t *mp, em_modify_event_mask_req_t *req)
{
	return (0);
}

static int
pem_adapter_info(queue_t *q, mblk_t *mp)
{
	inquire_adapter_t adapt;

	if (Socket_Services(SS_InquireAdapter, &adapt) == SUCCESS) {
		int bufsize;

		bufsize = sizeof (em_adapter_info_ack_t);
		bufsize += adapt.NumPower * sizeof (struct power_entry);

		mp = mexchange(q, mp, bufsize, M_PCPROTO, EM_ADAPTER_INFO_ACK);
		if (mp != NULL) {
			em_adapter_info_ack_t *ack;
			ack = (em_adapter_info_ack_t *)(mp->b_rptr);
			mp->b_wptr = mp->b_rptr + bufsize;
			ack->em_num_sockets = adapt.NumSockets;
			ack->em_num_windows = adapt.NumWindows;
			ack->em_num_power = adapt.NumPower;
			if (adapt.NumPower > 0) {
				ack->em_power_offset =
				    sizeof (em_adapter_info_ack_t);
				ack->em_power_length = adapt.NumPower *
				    sizeof (struct power_entry);
				bcopy((caddr_t)adapt.power_entry,
				    (caddr_t)mp->b_rptr +
				    ack->em_power_offset,
				    ack->em_power_length);
			}
			(void) putq(RD(q), mp);
		}
	}
	return (PEME_OK);
}

static int
pem_socket_info(queue_t *q, mblk_t *mp)
{
	inquire_socket_t socket;
	em_socket_info_ack_t *ack;
	em_socket_info_req_t *req;

	req = (em_socket_info_req_t *)(mp->b_rptr);
	socket.socket = req->em_socket;
	if (Socket_Services(SS_InquireSocket, &socket) == SUCCESS) {
		mp = mexchange(q, mp, sizeof (em_socket_info_ack_t),
		    M_PCPROTO, EM_SOCKET_INFO_ACK);
		if (mp != NULL) {
			ack = (em_socket_info_ack_t *)(mp->b_rptr);
			mp->b_wptr = mp->b_rptr +
			    sizeof (em_socket_info_ack_t);
			bzero(mp->b_rptr, sizeof (em_socket_info_ack_t));
			ack->em_status_int_caps = socket.SCIntCaps;
			ack->em_status_report_caps = socket.SCRptCaps;
			ack->em_control_indicator_caps = socket.CtlIndCaps;
			ack->em_socket_caps = socket.SocketCaps;
			(void) putq(RD(q), mp);
		}
	}
	return (PEME_OK);
}

static int
pem_get_socket(queue_t *q, mblk_t *mp)
{
	get_socket_t socket;
	em_get_socket_ack_t *ack;
	em_get_socket_req_t *req;

	req = (em_get_socket_req_t *)(mp->b_rptr);
	socket.socket = req->em_socket;

	if (Socket_Services(SS_GetSocket, &socket) == SUCCESS) {
		mp = mexchange(q, mp, sizeof (em_get_socket_ack_t),
		    M_PCPROTO, EM_GET_SOCKET_ACK);
		mp->b_wptr = mp->b_rptr + sizeof (em_get_socket_ack_t);
		ack = (em_get_socket_ack_t *)(mp->b_rptr);
		ack->em_socket = socket.socket;
		ack->em_vcc_level = socket.VccLevel;
		ack->em_vpp1_level = socket.Vpp1Level;
		ack->em_vpp2_level = socket.Vpp2Level;
		ack->em_state = socket.state;
		ack->em_control_ind = socket.CtlInd;
		ack->em_ireq_routing = socket.IRQRouting;
		ack->em_iftype = socket.IFType;
	}
	return (PEME_OK);
}

/*
 * pem_ident_socket()
 *	This primitive triggers artificial events for the
 *	socket. It basically recreates those events that
 *	have occurred on the socket up to this point in time
 */
static int
pem_ident_socket(queue_t *q, mblk_t *mp)
{
	dev_info_t *dip;
	em_ident_socket_req_t *ident = (em_ident_socket_req_t *)mp->b_rptr;
	int num_minors, i;
	struct pcm_make_dev *minors;

	dip = (dev_info_t *)pcmcia_get_devinfo(ident->em_socket);
	if (dip == NULL)
		return (PEME_NO_INFO);

	/* OK, have at least a name available */

	pem_event_ind(RD(q), PCE_DEV_IDENT, ident->em_socket,
	    (void *)ddi_get_name(dip));

	num_minors = pcmcia_get_minors(dip, &minors);

	for (i = 0; i < num_minors; i++) {
		pem_event_ind(RD(q), PCE_INIT_DEV, ident->em_socket,
		    (void *)(minors + i));
	}
	if (num_minors > 0)
		kmem_free(minors, num_minors * sizeof (struct pcm_make_dev));
	return (PEME_OK);
}
