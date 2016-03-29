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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 *
 * USB generic serial driver (GSD)
 *
 */
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/termio.h>
#include <sys/termiox.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/strtty.h>
#include <sys/policy.h>
#include <sys/consdev.h>

#include <sys/usb/usba.h>
#include <sys/usb/clients/usbser/usbser_var.h>
#include <sys/usb/clients/usbser/usbser_dsdi.h>
#include <sys/usb/clients/usbser/usbser_rseq.h>
#include <sys/usb/usba/genconsole.h>

/* autoconfiguration subroutines */
static int	usbser_rseq_do_cb(rseq_t *, int, uintptr_t);
static int	usbser_free_soft_state(usbser_state_t *);
static int	usbser_init_soft_state(usbser_state_t *);
static int	usbser_fini_soft_state(usbser_state_t *);
static int	usbser_attach_dev(usbser_state_t *);
static void	usbser_detach_dev(usbser_state_t *);
static int	usbser_attach_ports(usbser_state_t *);
static int	usbser_create_port_minor_nodes(usbser_state_t *, int);
static void	usbser_detach_ports(usbser_state_t *);
static int	usbser_create_taskq(usbser_state_t *);
static void	usbser_destroy_taskq(usbser_state_t *);
static void	usbser_set_dev_state_init(usbser_state_t *);

/* hotplugging and power management */
static int	usbser_disconnect_cb(dev_info_t *);
static int	usbser_reconnect_cb(dev_info_t *);
static void	usbser_disconnect_ports(usbser_state_t *);
static int	usbser_cpr_suspend(dev_info_t *);
static int	usbser_suspend_ports(usbser_state_t *);
static void	usbser_cpr_resume(dev_info_t *);
static int	usbser_restore_device_state(usbser_state_t *);
static void	usbser_restore_ports_state(usbser_state_t *);

/* STREAMS subroutines */
static int	usbser_open_setup(queue_t *, usbser_port_t *, int, int,
		cred_t *);
static int	usbser_open_init(usbser_port_t *, int);
static void	usbser_check_port_props(usbser_port_t *);
static void	usbser_open_fini(usbser_port_t *);
static int	usbser_open_line_setup(usbser_port_t *, int, int);
static int	usbser_open_carrier_check(usbser_port_t *, int, int);
static void	usbser_open_queues_init(usbser_port_t *, queue_t *);
static void	usbser_open_queues_fini(usbser_port_t *);
static void	usbser_close_drain(usbser_port_t *);
static void	usbser_close_cancel_break(usbser_port_t *);
static void	usbser_close_hangup(usbser_port_t *);
static void	usbser_close_cleanup(usbser_port_t *);

/* threads */
static void	usbser_thr_dispatch(usbser_thread_t *);
static void	usbser_thr_cancel(usbser_thread_t *);
static void	usbser_thr_wake(usbser_thread_t *);
static void	usbser_wq_thread(void *);
static void	usbser_rq_thread(void *);

/* DSD callbacks */
static void	usbser_tx_cb(caddr_t);
static void	usbser_rx_cb(caddr_t);
static void	usbser_rx_massage_data(usbser_port_t *, mblk_t *);
static void	usbser_rx_massage_mbreak(usbser_port_t *, mblk_t *);
static void	usbser_rx_cb_put(usbser_port_t *, queue_t *, queue_t *,
		mblk_t *);
static void	usbser_status_cb(caddr_t);
static void	usbser_status_proc_cb(usbser_port_t *);

/* serial support */
static void	usbser_wmsg(usbser_port_t *);
static int	usbser_data(usbser_port_t *, mblk_t *);
static int	usbser_ioctl(usbser_port_t *, mblk_t *);
static void	usbser_iocdata(usbser_port_t *, mblk_t *);
static void	usbser_stop(usbser_port_t *, mblk_t *);
static void	usbser_start(usbser_port_t *, mblk_t *);
static void	usbser_stopi(usbser_port_t *, mblk_t *);
static void	usbser_starti(usbser_port_t *, mblk_t *);
static void	usbser_flush(usbser_port_t *, mblk_t *);
static void	usbser_break(usbser_port_t *, mblk_t *);
static void	usbser_delay(usbser_port_t *, mblk_t *);
static void	usbser_restart(void *);
static int	usbser_port_program(usbser_port_t *);
static void	usbser_inbound_flow_ctl(usbser_port_t *);

/* misc */
static int	usbser_dev_is_online(usbser_state_t *);
static void	usbser_serialize_port_act(usbser_port_t *, int);
static void	usbser_release_port_act(usbser_port_t *, int);
#ifdef DEBUG
static char	*usbser_msgtype2str(int);
static char	*usbser_ioctl2str(int);
#endif

/* USBA events */
usb_event_t usbser_usb_events = {
	usbser_disconnect_cb,	/* disconnect */
	usbser_reconnect_cb,	/* reconnect */
	NULL,			/* pre-suspend */
	NULL,			/* pre-resume */
};

/* debug support */
uint_t	 usbser_errlevel = USB_LOG_L4;
uint_t	 usbser_errmask = DPRINT_MASK_ALL;
uint_t	 usbser_instance_debug = (uint_t)-1;

/* usb serial console */
static struct usbser_state *usbser_list;
static kmutex_t usbser_lock;
static int usbser_console_abort;
static usb_console_info_t console_input, console_output;
static uchar_t *console_input_buf;
static uchar_t *console_input_start, *console_input_end;

_NOTE(SCHEME_PROTECTS_DATA("unshared", usbser_console_abort))
_NOTE(SCHEME_PROTECTS_DATA("unshared", console_input))
_NOTE(SCHEME_PROTECTS_DATA("unshared", console_output))
_NOTE(SCHEME_PROTECTS_DATA("unshared", console_input_start))
_NOTE(SCHEME_PROTECTS_DATA("unshared", console_input_end))

static void usbser_putchar(cons_polledio_arg_t, uchar_t);
static int usbser_getchar(cons_polledio_arg_t);
static boolean_t usbser_ischar(cons_polledio_arg_t);
static void usbser_polledio_enter(cons_polledio_arg_t);
static void usbser_polledio_exit(cons_polledio_arg_t);
static int usbser_polledio_init(usbser_port_t *);
static void usbser_polledio_fini(usbser_port_t *);

static struct cons_polledio usbser_polledio = {
	CONSPOLLEDIO_V1,
	NULL,	/* to be set later */
	usbser_putchar,
	usbser_getchar,
	usbser_ischar,
	usbser_polledio_enter,
	usbser_polledio_exit
};

/* various statistics. TODO: replace with kstats */
static int usbser_st_tx_data_loss = 0;
static int usbser_st_rx_data_loss = 0;
static int usbser_st_put_stopi = 0;
static int usbser_st_mstop = 0;
static int usbser_st_mstart = 0;
static int usbser_st_mstopi = 0;
static int usbser_st_mstarti = 0;
static int usbser_st_rsrv = 0;
_NOTE(SCHEME_PROTECTS_DATA("monotonic stats", usbser_st_{
	tx_data_loss rx_data_loss put_stopi mstop mstart mstopi mstarti rsrv}))
_NOTE(SCHEME_PROTECTS_DATA("unshared", usb_bulk_req_t))
_NOTE(SCHEME_PROTECTS_DATA("unshared", usb_intr_req_t))

/* taskq parameter */
extern pri_t minclsyspri;

/*
 * tell warlock not to worry about STREAMS structures
 */
_NOTE(SCHEME_PROTECTS_DATA("unique per call", iocblk datab msgb queue copyreq))

/*
 * modload support
 */
extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops,	/* Type of module */
	"USB generic serial module"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};


#define	RSEQ(f1, f2) RSEQE(f1, usbser_rseq_do_cb, f2, NULL)


/*
 * loadable module entry points
 * ----------------------------
 */

int
_init(void)
{
	int err;

	mutex_init(&usbser_lock, NULL, MUTEX_DRIVER, (void *)NULL);

	if ((err = mod_install(&modlinkage)) != 0)
		mutex_destroy(&usbser_lock);

	return (err);
}


int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) != 0)
		return (err);

	mutex_destroy(&usbser_lock);

	return (0);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * soft state size
 */
int
usbser_soft_state_size()
{
	return (sizeof (usbser_state_t));
}


/*
 * autoconfiguration entry points
 * ------------------------------
 */

/*ARGSUSED*/
int
usbser_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result, void *statep)
{
	int		instance;
	int		ret = DDI_FAILURE;
	usbser_state_t	*usbserp;

	instance = USBSER_MINOR2INST(getminor((dev_t)arg));

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = NULL;
		usbserp = ddi_get_soft_state(statep, instance);
		if (usbserp != NULL) {
			*result = usbserp->us_dip;
			if (*result != NULL) {
				ret = DDI_SUCCESS;
			}
		}

		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)(uintptr_t)instance;
		ret = DDI_SUCCESS;

		break;
	default:
		break;
	}

	return (ret);
}

/*
 * device attach
 */
static rseq_t rseq_att[] = {
	RSEQ(NULL,			usbser_free_soft_state),
	RSEQ(usbser_init_soft_state,	usbser_fini_soft_state),
	RSEQ(usbser_attach_dev,		usbser_detach_dev),
	RSEQ(usbser_attach_ports,	usbser_detach_ports),
	RSEQ(usbser_create_taskq,	usbser_destroy_taskq),
	RSEQ(NULL,			usbser_set_dev_state_init)
};

static void
usbser_insert(struct usbser_state *usp)
{
	struct usbser_state *tmp;

	mutex_enter(&usbser_lock);
	tmp = usbser_list;
	if (tmp == NULL)
		usbser_list = usp;
	else {
		while (tmp->us_next)
			tmp = tmp->us_next;
		tmp->us_next = usp;
	}
	mutex_exit(&usbser_lock);
}

static void
usbser_remove(struct usbser_state *usp)
{
	struct usbser_state *tmp, *prev = NULL;

	mutex_enter(&usbser_lock);
	tmp = usbser_list;
	while (tmp != usp) {
		prev = tmp;
		tmp = tmp->us_next;
	}
	ASSERT(tmp == usp);	/* must exist, else attach/detach wrong */
	if (prev)
		prev->us_next = usp->us_next;
	else
		usbser_list = usp->us_next;
	usp->us_next = NULL;
	mutex_exit(&usbser_lock);
}

/*
 * Return the first serial device, with dip held. This is called
 * from the console subsystem to place console on usb serial device.
 */
dev_info_t *
usbser_first_device(void)
{
	dev_info_t *dip = NULL;

	mutex_enter(&usbser_lock);
	if (usbser_list) {
		dip = usbser_list->us_dip;
		ndi_hold_devi(dip);
	}
	mutex_exit(&usbser_lock);

	return (dip);
}

int
usbser_attach(dev_info_t *dip, ddi_attach_cmd_t cmd,
		void *statep, ds_ops_t *ds_ops)
{
	int		instance;
	usbser_state_t	*usp;

	instance = ddi_get_instance(dip);

	switch (cmd) {
	case DDI_ATTACH:

		break;
	case DDI_RESUME:
		usbser_cpr_resume(dip);

		return (DDI_SUCCESS);
	default:

		return (DDI_FAILURE);
	}

	/* allocate and get soft state */
	if (ddi_soft_state_zalloc(statep, instance) != DDI_SUCCESS) {

		return (DDI_FAILURE);
	}
	if ((usp = ddi_get_soft_state(statep, instance)) == NULL) {
		ddi_soft_state_free(statep, instance);

		return (DDI_FAILURE);
	}

	usp->us_statep = statep;
	usp->us_dip = dip;
	usp->us_instance = instance;
	usp->us_ds_ops = ds_ops;

	if (rseq_do(rseq_att, NELEM(rseq_att), (uintptr_t)usp, 0) == RSEQ_OK) {
		ddi_report_dev(dip);
		usbser_insert(usp);

		return (DDI_SUCCESS);
	} else {

		return (DDI_FAILURE);
	}
}

/*
 * device detach
 */
int
usbser_detach(dev_info_t *dip, ddi_detach_cmd_t cmd, void *statep)
{
	int		instance = ddi_get_instance(dip);
	usbser_state_t	*usp;
	int		rval;

	usp = ddi_get_soft_state(statep, instance);

	switch (cmd) {
	case DDI_DETACH:
		USB_DPRINTF_L4(DPRINT_DETACH, usp->us_lh, "usbser_detach");
		usbser_remove(usp);
		(void) rseq_undo(rseq_att, NELEM(rseq_att), (uintptr_t)usp, 0);
		USB_DPRINTF_L4(DPRINT_DETACH, NULL,
		    "usbser_detach.%d: end", instance);

		return (DDI_SUCCESS);
	case DDI_SUSPEND:
		rval = usbser_cpr_suspend(dip);

		return ((rval == USB_SUCCESS)? DDI_SUCCESS : DDI_FAILURE);
	default:

		return (DDI_FAILURE);
	}
}

/*
 * STREAMS entry points
 * --------------------
 *
 *
 * port open
 */
/*ARGSUSED*/
int
usbser_open(queue_t *rq, dev_t *dev, int flag, int sflag, cred_t *cr,
		void *statep)
{
	usbser_state_t	*usp;
	usbser_port_t	*pp;
	int		minor = getminor(*dev);
	int		instance;
	uint_t		port_num;
	int		rval;

	instance = USBSER_MINOR2INST(minor);
	if (instance < 0) {

		return (ENXIO);
	}

	usp = ddi_get_soft_state(statep, instance);
	if (usp == NULL) {

		return (ENXIO);
	}

	/* don't allow to open disconnected device */
	mutex_enter(&usp->us_mutex);
	if (usp->us_dev_state == USB_DEV_DISCONNECTED) {
		mutex_exit(&usp->us_mutex);

		return (ENXIO);
	}
	mutex_exit(&usp->us_mutex);

	/* get port soft state */
	port_num = USBSER_MINOR2PORT(minor);
	if (port_num >= usp->us_port_cnt) {

		return (ENXIO);
	}
	pp = &usp->us_ports[port_num];

	/* set up everything for open */
	rval = usbser_open_setup(rq, pp, minor, flag, cr);

	USB_DPRINTF_L4(DPRINT_OPEN, pp->port_lh, "usbser_open: rval=%d", rval);

	return (rval);
}


/*
 * port close
 *
 * some things driver should do when the last app closes the line:
 *
 *	drain data;
 *	cancel break/delay;
 *	hangup line (if necessary);
 *	DSD close;
 *	cleanup soft state;
 */
/*ARGSUSED*/
int
usbser_close(queue_t *rq, int flag, cred_t *cr)
{
	usbser_port_t	*pp = (usbser_port_t *)rq->q_ptr;
	int		online;

	if (pp == NULL) {

		return (ENXIO);
	}

	online = usbser_dev_is_online(pp->port_usp);

	/*
	 * in the closing state new activities will not be initiated
	 */
	mutex_enter(&pp->port_mutex);
	pp->port_state = USBSER_PORT_CLOSING;

	if (online) {
		/* drain the data */
		usbser_close_drain(pp);
	}

	/* stop break/delay */
	usbser_close_cancel_break(pp);

	if (online) {
		/* hangup line */
		usbser_close_hangup(pp);
	}

	/*
	 * close DSD, cleanup state and transition to 'closed' state
	 */
	usbser_close_cleanup(pp);
	mutex_exit(&pp->port_mutex);

	USB_DPRINTF_L4(DPRINT_CLOSE, pp->port_lh, "usbser_close: end");

	return (0);
}


/*
 * read side service routine: send as much as possible messages upstream
 * and if there is still place on the queue, enable receive (if not already)
 */
int
usbser_rsrv(queue_t *q)
{
	usbser_port_t	*pp = (usbser_port_t *)q->q_ptr;
	mblk_t		*mp;

	usbser_st_rsrv++;
	USB_DPRINTF_L4(DPRINT_RQ, pp->port_lh, "usbser_rsrv");

	while (canputnext(q) && (mp = getq(q))) {
		putnext(q, mp);
	}

	if (canputnext(q)) {
		mutex_enter(&pp->port_mutex);
		ASSERT(pp->port_state != USBSER_PORT_CLOSED);

		if (USBSER_PORT_ACCESS_OK(pp)) {
			usbser_thr_wake(&pp->port_rq_thread);
		}
		mutex_exit(&pp->port_mutex);
	}

	return (0);
}


/*
 * wput: put message on the queue and wake wq thread
 */
int
usbser_wput(queue_t *q, mblk_t *mp)
{
	usbser_port_t	*pp = (usbser_port_t *)q->q_ptr;

	USB_DPRINTF_L4(DPRINT_WQ, pp->port_lh, "usbser_wput");

	mutex_enter(&pp->port_mutex);
	ASSERT(pp->port_state != USBSER_PORT_CLOSED);

	/* ignore new messages if port is already closing */
	if (pp->port_state == USBSER_PORT_CLOSING) {
		freemsg(mp);
	} else if (putq(q, mp)) {
		/*
		 * this counter represents amount of tx data on the wq.
		 * each time the data is passed to DSD for transmission,
		 * the counter is decremented accordingly
		 */
		pp->port_wq_data_cnt += msgdsize(mp);
	} else {
		usbser_st_tx_data_loss++;
	}
	mutex_exit(&pp->port_mutex);

	return (0);
}


/*
 * we need wsrv() routine to take advantage of STREAMS flow control:
 * without it the framework will consider we are always able to process msgs
 */
int
usbser_wsrv(queue_t *q)
{
	usbser_port_t	*pp = (usbser_port_t *)q->q_ptr;

	USB_DPRINTF_L4(DPRINT_WQ, pp->port_lh, "usbser_wsrv");

	mutex_enter(&pp->port_mutex);
	ASSERT(pp->port_state != USBSER_PORT_CLOSED);

	if (USBSER_PORT_ACCESS_OK(pp)) {
		usbser_thr_wake(&pp->port_wq_thread);
	}
	mutex_exit(&pp->port_mutex);

	return (0);
}


/*
 * power entry point
 */
int
usbser_power(dev_info_t *dip, int comp, int level)
{
	void		*statep;
	usbser_state_t	*usp;
	int		new_state;
	int		rval;

	statep = ddi_get_driver_private(dip);
	usp = ddi_get_soft_state(statep, ddi_get_instance(dip));

	USB_DPRINTF_L3(DPRINT_EVENTS, usp->us_lh,
	    "usbser_power: dip=0x%p, comp=%d, level=%d",
	    (void *)dip, comp, level);

	mutex_enter(&usp->us_mutex);
	new_state = usp->us_dev_state;
	mutex_exit(&usp->us_mutex);

	/* let DSD do the job */
	rval = USBSER_DS_USB_POWER(usp, comp, level, &new_state);

	/* stay in sync with DSD */
	mutex_enter(&usp->us_mutex);
	usp->us_dev_state = new_state;
	mutex_exit(&usp->us_mutex);

	return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}


/*
 *
 * configuration entry point subroutines
 * -------------------------------------
 *
 * rseq callback
 */
static int
usbser_rseq_do_cb(rseq_t *rseq, int num, uintptr_t arg)
{
	usbser_state_t *usp = (usbser_state_t *)arg;
	int	rval = rseq[num].r_do.s_rval;
	char	*name = rseq[num].r_do.s_name;

	if (rval != DDI_SUCCESS) {
		USB_DPRINTF_L2(DPRINT_ATTACH, usp->us_lh,
		    "do %s failed (%d)", name, rval);

		return (RSEQ_UNDO);
	} else {

		return (RSEQ_OK);
	}
}


/*
 * free soft state
 */
static int
usbser_free_soft_state(usbser_state_t *usp)
{
	ddi_soft_state_free(usp->us_statep, usp->us_instance);

	return (USB_SUCCESS);
}

/*
 * init instance soft state
 */
static int
usbser_init_soft_state(usbser_state_t *usp)
{
	usp->us_lh = usb_alloc_log_hdl(usp->us_dip, "usbs[*].",
	    &usbser_errlevel, &usbser_errmask, &usbser_instance_debug,
	    0);
	mutex_init(&usp->us_mutex, NULL, MUTEX_DRIVER, (void *)NULL);

	/* save state pointer for use in event callbacks */
	ddi_set_driver_private(usp->us_dip, usp->us_statep);

	usp->us_dev_state = USBSER_DEV_INIT;

	return (DDI_SUCCESS);
}

/*
 * fini instance soft state
 */
static int
usbser_fini_soft_state(usbser_state_t *usp)
{
	usb_free_log_hdl(usp->us_lh);
	mutex_destroy(&usp->us_mutex);
	ddi_set_driver_private(usp->us_dip, NULL);

	return (DDI_SUCCESS);
}

/*
 * attach entire device
 */
static int
usbser_attach_dev(usbser_state_t *usp)
{
	ds_attach_info_t ai;
	int		rval;

	usp->us_dev_state = USB_DEV_ONLINE;

	ai.ai_dip = usp->us_dip;
	ai.ai_usb_events = &usbser_usb_events;
	ai.ai_hdl = &usp->us_ds_hdl;
	ai.ai_port_cnt = &usp->us_port_cnt;

	rval = USBSER_DS_ATTACH(usp, &ai);

	if ((rval != USB_SUCCESS) || (usp->us_ds_hdl == NULL) ||
	    (usp->us_port_cnt == 0)) {
		USB_DPRINTF_L4(DPRINT_ATTACH, usp->us_lh, "usbser_attach_dev: "
		    "failed %d %p %d", rval, usp->us_ds_hdl, usp->us_port_cnt);

		return (DDI_FAILURE);
	}

	USB_DPRINTF_L4(DPRINT_ATTACH, usp->us_lh,
	    "usbser_attach_dev: port_cnt = %d", usp->us_port_cnt);

	return (DDI_SUCCESS);
}


/*
 * detach entire device
 */
static void
usbser_detach_dev(usbser_state_t *usp)
{
	USBSER_DS_DETACH(usp);
}


/*
 * attach each individual port
 */
static int
usbser_attach_ports(usbser_state_t *usp)
{
	int		i;
	usbser_port_t	*pp;
	ds_cb_t		ds_cb;

	/*
	 * allocate port array
	 */
	usp->us_ports = kmem_zalloc(usp->us_port_cnt *
	    sizeof (usbser_port_t), KM_SLEEP);

	/* callback handlers */
	ds_cb.cb_tx = usbser_tx_cb;
	ds_cb.cb_rx = usbser_rx_cb;
	ds_cb.cb_status = usbser_status_cb;

	/*
	 * initialize each port
	 */
	for (i = 0; i < usp->us_port_cnt; i++) {
		pp = &usp->us_ports[i];

		/*
		 * initialize data
		 */
		pp->port_num = i;
		pp->port_usp = usp;
		pp->port_ds_ops = usp->us_ds_ops;
		pp->port_ds_hdl = usp->us_ds_hdl;

		/* allocate log handle */
		(void) sprintf(pp->port_lh_name, "usbs[%d].", i);
		pp->port_lh = usb_alloc_log_hdl(usp->us_dip,
		    pp->port_lh_name, &usbser_errlevel, &usbser_errmask,
		    &usbser_instance_debug, 0);

		mutex_init(&pp->port_mutex, NULL, MUTEX_DRIVER, (void *)NULL);
		cv_init(&pp->port_state_cv, NULL, CV_DEFAULT, NULL);
		cv_init(&pp->port_act_cv, NULL, CV_DEFAULT, NULL);
		cv_init(&pp->port_car_cv, NULL, CV_DEFAULT, NULL);

		/*
		 * init threads
		 */
		pp->port_wq_thread.thr_port = pp;
		pp->port_wq_thread.thr_func = usbser_wq_thread;
		pp->port_wq_thread.thr_arg = (void *)&pp->port_wq_thread;
		cv_init(&pp->port_wq_thread.thr_cv, NULL, CV_DEFAULT, NULL);

		pp->port_rq_thread.thr_port = pp;
		pp->port_rq_thread.thr_func = usbser_rq_thread;
		pp->port_rq_thread.thr_arg = (void *)&pp->port_rq_thread;
		cv_init(&pp->port_rq_thread.thr_cv, NULL, CV_DEFAULT, NULL);

		/*
		 * register callbacks
		 */
		ds_cb.cb_arg = (caddr_t)pp;
		USBSER_DS_REGISTER_CB(usp, i, &ds_cb);

		pp->port_state = USBSER_PORT_CLOSED;

		if (usbser_create_port_minor_nodes(usp, i) != USB_SUCCESS) {
			usbser_detach_ports(usp);

			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}


/*
 * create a pair of minor nodes for the port
 */
static int
usbser_create_port_minor_nodes(usbser_state_t *usp, int port_num)
{
	int	instance = usp->us_instance;
	minor_t	minor;
	char	name[16];

	/*
	 * tty node
	 */
	(void) sprintf(name, "%d", port_num);
	minor = USBSER_MAKEMINOR(instance, port_num, 0);

	if (ddi_create_minor_node(usp->us_dip, name,
	    S_IFCHR, minor, DDI_NT_SERIAL, NULL) != DDI_SUCCESS) {

		return (USB_FAILURE);
	}

	/*
	 * dial-out node
	 */
	(void) sprintf(name, "%d,cu", port_num);
	minor = USBSER_MAKEMINOR(instance, port_num, OUTLINE);

	if (ddi_create_minor_node(usp->us_dip, name,
	    S_IFCHR, minor, DDI_NT_SERIAL_DO, NULL) != DDI_SUCCESS) {

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/*
 * detach each port individually
 */
static void
usbser_detach_ports(usbser_state_t *usp)
{
	int		i;
	int		sz;
	usbser_port_t	*pp;

	/*
	 * remove all minor nodes
	 */
	ddi_remove_minor_node(usp->us_dip, NULL);

	for (i = 0; i < usp->us_port_cnt; i++) {
		pp = &usp->us_ports[i];

		if (pp->port_state != USBSER_PORT_CLOSED) {
			ASSERT(pp->port_state == USBSER_PORT_NOT_INIT);

			continue;
		}

		USBSER_DS_UNREGISTER_CB(usp, i);

		mutex_destroy(&pp->port_mutex);
		cv_destroy(&pp->port_state_cv);
		cv_destroy(&pp->port_act_cv);
		cv_destroy(&pp->port_car_cv);

		cv_destroy(&pp->port_wq_thread.thr_cv);
		cv_destroy(&pp->port_rq_thread.thr_cv);

		usb_free_log_hdl(pp->port_lh);
	}

	/*
	 * free memory
	 */
	sz = usp->us_port_cnt * sizeof (usbser_port_t);
	kmem_free(usp->us_ports, sz);
	usp->us_ports = NULL;
}


/*
 * create a taskq with two threads per port (read and write sides)
 */
static int
usbser_create_taskq(usbser_state_t *usp)
{
	int	nthr = usp->us_port_cnt * 2;

	usp->us_taskq = ddi_taskq_create(usp->us_dip, "usbser_taskq",
	    nthr, TASKQ_DEFAULTPRI, 0);

	return ((usp->us_taskq == NULL) ? DDI_FAILURE : DDI_SUCCESS);
}


static void
usbser_destroy_taskq(usbser_state_t *usp)
{
	ddi_taskq_destroy(usp->us_taskq);
}


static void
usbser_set_dev_state_init(usbser_state_t *usp)
{
	mutex_enter(&usp->us_mutex);
	usp->us_dev_state = USBSER_DEV_INIT;
	mutex_exit(&usp->us_mutex);
}

/*
 * hotplugging and power management
 * ---------------------------------
 *
 * disconnect event callback
 */
/*ARGSUSED*/
static int
usbser_disconnect_cb(dev_info_t *dip)
{
	void		*statep;
	usbser_state_t	*usp;

	statep = ddi_get_driver_private(dip);
	usp = ddi_get_soft_state(statep, ddi_get_instance(dip));

	USB_DPRINTF_L3(DPRINT_EVENTS, usp->us_lh,
	    "usbser_disconnect_cb: dip=%p", (void *)dip);

	mutex_enter(&usp->us_mutex);
	switch (usp->us_dev_state) {
	case USB_DEV_ONLINE:
	case USB_DEV_PWRED_DOWN:
		/* prevent further activity */
		usp->us_dev_state = USB_DEV_DISCONNECTED;
		mutex_exit(&usp->us_mutex);

		/* see if any of the ports are open and do necessary handling */
		usbser_disconnect_ports(usp);

		/* call DSD to do any necessary work */
		if (USBSER_DS_DISCONNECT(usp) != USB_DEV_DISCONNECTED) {
			USB_DPRINTF_L2(DPRINT_EVENTS, usp->us_lh,
			    "usbser_disconnect_cb: ds_disconnect failed");
		}

		break;
	case USB_DEV_SUSPENDED:
		/* we remain suspended */
	default:
		mutex_exit(&usp->us_mutex);

		break;
	}

	return (USB_SUCCESS);
}


/*
 * reconnect event callback
 */
/*ARGSUSED*/
static int
usbser_reconnect_cb(dev_info_t *dip)
{
	void		*statep;
	usbser_state_t	*usp;

	statep = ddi_get_driver_private(dip);
	usp = ddi_get_soft_state(statep, ddi_get_instance(dip));

	USB_DPRINTF_L3(DPRINT_EVENTS, usp->us_lh,
	    "usbser_reconnect_cb: dip=%p", (void *)dip);

	(void) usbser_restore_device_state(usp);

	return (USB_SUCCESS);
}


/*
 * if any of the ports is open during disconnect,
 * send M_HANGUP message upstream and log a warning
 */
static void
usbser_disconnect_ports(usbser_state_t *usp)
{
	usbser_port_t	*pp;
	queue_t		*rq;
	int		complain = 0;
	int		hangup = 0;
	timeout_id_t	delay_id = 0;
	int		i;

	if (usp->us_ports == NULL) {
		return;
	}

	for (i = 0; i < usp->us_port_cnt; i++) {
		pp = &usp->us_ports[i];

		mutex_enter(&pp->port_mutex);
		if (pp->port_state == USBSER_PORT_OPEN ||
		    USBSER_IS_OPENING(pp) ||
		    pp->port_state == USBSER_PORT_CLOSING) {
			complain = 1;
		}

		if (pp->port_state == USBSER_PORT_OPEN) {
			rq = pp->port_ttycommon.t_readq;

			/*
			 * hangup the stream; will send actual
			 * M_HANGUP message after releasing mutex
			 */
			pp->port_flags |= USBSER_FL_HUNGUP;
			hangup = 1;

			/*
			 * cancel all activities
			 */
			usbser_release_port_act(pp, USBSER_ACT_ALL);

			delay_id = pp->port_delay_id;
			pp->port_delay_id = 0;

			/* mark disconnected */
			pp->port_state = USBSER_PORT_DISCONNECTED;
			cv_broadcast(&pp->port_state_cv);
		}
		mutex_exit(&pp->port_mutex);

		if (hangup) {
			(void) putnextctl(rq, M_HANGUP);
			hangup = 0;
		}

		/*
		 * we couldn't untimeout while holding the mutex - do it now
		 */
		if (delay_id) {
			(void) untimeout(delay_id);
			delay_id = 0;
		}
	}

	/*
	 * complain about disconnecting device while open
	 */
	if (complain) {
		USB_DPRINTF_L0(DPRINT_EVENTS, usp->us_lh, "device was "
		    "disconnected while open. Data may have been lost");
	}
}


/*
 * do CPR suspend
 *
 * We use a trivial CPR strategy - fail if any of the device's ports are open.
 * The problem with more sophisticated strategies is that each open port uses
 * two threads that sit in the loop until the port is closed, while CPR has to
 * stop all kernel threads to succeed. Stopping port threads is a rather
 * intrusive and delicate procedure; I leave it as an RFE for now.
 *
 */
static int
usbser_cpr_suspend(dev_info_t *dip)
{
	void		*statep;
	usbser_state_t	*usp;
	int		new_state;
	int		rval;

	statep = ddi_get_driver_private(dip);
	usp = ddi_get_soft_state(statep, ddi_get_instance(dip));

	USB_DPRINTF_L4(DPRINT_EVENTS, usp->us_lh, "usbser_cpr_suspend");

	/* suspend each port first */
	if (usbser_suspend_ports(usp) != USB_SUCCESS) {
		USB_DPRINTF_L3(DPRINT_EVENTS, usp->us_lh,
		    "usbser_cpr_suspend: GSD failure");

		return (USB_FAILURE);
	}

	new_state = USBSER_DS_SUSPEND(usp);	/* let DSD do its part */

	mutex_enter(&usp->us_mutex);
	if (new_state == USB_DEV_SUSPENDED) {
		rval = USB_SUCCESS;
	} else {
		ASSERT(new_state == USB_DEV_ONLINE);
		rval = USB_FAILURE;
	}
	usp->us_dev_state = new_state;
	mutex_exit(&usp->us_mutex);

	return (rval);
}


static int
usbser_suspend_ports(usbser_state_t *usp)
{
	usbser_port_t	*pp;
	int		i;

	for (i = 0; i < usp->us_port_cnt; i++) {
		pp = &usp->us_ports[i];

		mutex_enter(&pp->port_mutex);
		if (pp->port_state != USBSER_PORT_CLOSED) {
			mutex_exit(&pp->port_mutex);

			return (USB_FAILURE);
		}
		mutex_exit(&pp->port_mutex);
	}

	return (USB_SUCCESS);
}


/*
 * do CPR resume
 *
 * DSD will return USB_DEV_ONLINE in case of success
 */
static void
usbser_cpr_resume(dev_info_t *dip)
{
	void		*statep;
	usbser_state_t	*usp;

	statep = ddi_get_driver_private(dip);
	usp = ddi_get_soft_state(statep, ddi_get_instance(dip));

	USB_DPRINTF_L3(DPRINT_EVENTS, usp->us_lh, "usbser_cpr_resume");

	(void) usbser_restore_device_state(usp);
}


/*
 * restore device state after CPR resume or reconnect
 */
static int
usbser_restore_device_state(usbser_state_t *usp)
{
	int	new_state, current_state;

	/* needed as power up state of dev is "unknown" to system */
	(void) pm_busy_component(usp->us_dip, 0);
	(void) pm_raise_power(usp->us_dip, 0, USB_DEV_OS_FULL_PWR);

	mutex_enter(&usp->us_mutex);
	current_state = usp->us_dev_state;
	mutex_exit(&usp->us_mutex);

	ASSERT((current_state == USB_DEV_DISCONNECTED) ||
	    (current_state == USB_DEV_SUSPENDED));

	/*
	 * call DSD to perform device-specific work
	 */
	if (current_state == USB_DEV_DISCONNECTED) {
		new_state = USBSER_DS_RECONNECT(usp);
	} else {
		new_state = USBSER_DS_RESUME(usp);
	}

	mutex_enter(&usp->us_mutex);
	usp->us_dev_state = new_state;
	mutex_exit(&usp->us_mutex);

	if (new_state == USB_DEV_ONLINE) {
		/*
		 * restore ports state
		 */
		usbser_restore_ports_state(usp);
	}

	(void) pm_idle_component(usp->us_dip, 0);

	return (USB_SUCCESS);
}


/*
 * restore ports state after device reconnect/resume
 */
static void
usbser_restore_ports_state(usbser_state_t *usp)
{
	usbser_port_t	*pp;
	queue_t		*rq;
	int		i;

	for (i = 0; i < usp->us_port_cnt; i++) {
		pp = &usp->us_ports[i];

		mutex_enter(&pp->port_mutex);
		/*
		 * only care about ports that are open
		 */
		if ((pp->port_state != USBSER_PORT_SUSPENDED) &&
		    (pp->port_state != USBSER_PORT_DISCONNECTED)) {
			mutex_exit(&pp->port_mutex);

			continue;
		}

		pp->port_state = USBSER_PORT_OPEN;

		/*
		 * if the stream was hung up during disconnect, restore it
		 */
		if (pp->port_flags & USBSER_FL_HUNGUP) {
			pp->port_flags &= ~USBSER_FL_HUNGUP;
			rq = pp->port_ttycommon.t_readq;

			mutex_exit(&pp->port_mutex);
			(void) putnextctl(rq, M_UNHANGUP);
			mutex_enter(&pp->port_mutex);
		}

		/*
		 * restore serial parameters
		 */
		(void) usbser_port_program(pp);

		/*
		 * wake anything that might be sleeping
		 */
		cv_broadcast(&pp->port_state_cv);
		cv_broadcast(&pp->port_act_cv);
		usbser_thr_wake(&pp->port_wq_thread);
		usbser_thr_wake(&pp->port_rq_thread);
		mutex_exit(&pp->port_mutex);
	}
}


/*
 * STREAMS subroutines
 * -------------------
 *
 *
 * port open state machine
 *
 * here's a list of things that the driver has to do while open;
 * because device can be opened any number of times,
 * initial open has additional responsibilities:
 *
 *	if (initial_open) {
 *		initialize soft state;	\
 *		DSD open;		- see usbser_open_init()
 *		dispatch threads;	/
 *	}
 *	raise DTR;
 *	wait for carrier (if necessary);
 *
 * we should also take into consideration that two threads can try to open
 * the same physical port simultaneously (/dev/term/N and /dev/cua/N).
 *
 * return values:
 *	0	- success;
 *	>0	- fail with this error code;
 */
static int
usbser_open_setup(queue_t *rq, usbser_port_t *pp, int minor, int flag,
		cred_t *cr)
{
	int	rval = USBSER_CONTINUE;

	mutex_enter(&pp->port_mutex);
	/*
	 * refer to port state diagram in the header file
	 */
loop:
	switch (pp->port_state) {
	case USBSER_PORT_CLOSED:
		/*
		 * initial open
		 */
		rval = usbser_open_init(pp, minor);

		break;
	case USBSER_PORT_OPENING_TTY:
		/*
		 * dial-out thread can overtake the port
		 * if tty open thread is sleeping waiting for carrier
		 */
		if ((minor & OUTLINE) && (pp->port_flags & USBSER_FL_WOPEN)) {
			pp->port_state = USBSER_PORT_OPENING_OUT;

			USB_DPRINTF_L3(DPRINT_OPEN, pp->port_lh,
			    "usbser_open_state: overtake");
		}

		/* FALLTHRU */
	case USBSER_PORT_OPENING_OUT:
		/*
		 * if no other open in progress, setup the line
		 */
		if (USBSER_NO_OTHER_OPEN(pp, minor)) {
			rval = usbser_open_line_setup(pp, minor, flag);

			break;
		}

		/* FALLTHRU */
	case USBSER_PORT_CLOSING:
		/*
		 * wait until close active phase ends
		 */
		if (cv_wait_sig(&pp->port_state_cv, &pp->port_mutex) == 0) {
			rval = EINTR;
		}

		break;
	case USBSER_PORT_OPEN:
		if ((pp->port_ttycommon.t_flags & TS_XCLUDE) &&
		    secpolicy_excl_open(cr) != 0) {
			/*
			 * exclusive use
			 */
			rval = EBUSY;
		} else if (USBSER_OPEN_IN_OTHER_MODE(pp, minor)) {
			/*
			 * tty and dial-out modes are mutually exclusive
			 */
			rval = EBUSY;
		} else {
			/*
			 * port is being re-open in the same mode
			 */
			rval = usbser_open_line_setup(pp, minor, flag);
		}

		break;
	default:
		rval = ENXIO;

		break;
	}

	if (rval == USBSER_CONTINUE) {

		goto loop;
	}

	/*
	 * initial open requires additional handling
	 */
	if (USBSER_IS_OPENING(pp)) {
		if (rval == USBSER_COMPLETE) {
			if (pp->port_state == USBSER_PORT_OPENING_OUT) {
				pp->port_flags |= USBSER_FL_OUT;
			}
			pp->port_state = USBSER_PORT_OPEN;
			cv_broadcast(&pp->port_state_cv);

			usbser_open_queues_init(pp, rq);
		} else {
			usbser_open_fini(pp);
		}
	}
	mutex_exit(&pp->port_mutex);

	return (rval);
}


/*
 * initialize the port when opened for the first time
 */
static int
usbser_open_init(usbser_port_t *pp, int minor)
{
	usbser_state_t	*usp = pp->port_usp;
	tty_common_t	*tp = &pp->port_ttycommon;
	int		rval = ENXIO;

	ASSERT(pp->port_state == USBSER_PORT_CLOSED);

	/*
	 * init state
	 */
	pp->port_act = 0;
	pp->port_flags &= USBSER_FL_PRESERVE;
	pp->port_flowc = '\0';
	pp->port_wq_data_cnt = 0;

	if (minor & OUTLINE) {
		pp->port_state = USBSER_PORT_OPENING_OUT;
	} else {
		pp->port_state = USBSER_PORT_OPENING_TTY;
	}

	/*
	 * init termios settings
	 */
	tp->t_iflag = 0;
	tp->t_iocpending = NULL;
	tp->t_size.ws_row = tp->t_size.ws_col = 0;
	tp->t_size.ws_xpixel = tp->t_size.ws_ypixel = 0;
	tp->t_startc = CSTART;
	tp->t_stopc = CSTOP;

	usbser_check_port_props(pp);

	/*
	 * dispatch wq and rq threads:
	 * although queues are not enabled at this point,
	 * we will need wq to run status processing callback
	 */
	usbser_thr_dispatch(&pp->port_wq_thread);
	usbser_thr_dispatch(&pp->port_rq_thread);

	/*
	 * open DSD port
	 */
	mutex_exit(&pp->port_mutex);
	rval = USBSER_DS_OPEN_PORT(usp, pp->port_num);
	mutex_enter(&pp->port_mutex);

	if (rval != USB_SUCCESS) {

		return (ENXIO);
	}
	pp->port_flags |= USBSER_FL_DSD_OPEN;

	/*
	 * program port with default parameters
	 */
	if ((rval = usbser_port_program(pp)) != 0) {

		return (ENXIO);
	}

	return (USBSER_CONTINUE);
}


/*
 * create a pair of minor nodes for the port
 */
static void
usbser_check_port_props(usbser_port_t *pp)
{
	dev_info_t	*dip = pp->port_usp->us_dip;
	tty_common_t	*tp = &pp->port_ttycommon;
	struct termios	*termiosp;
	uint_t		len;
	char		name[20];

	/*
	 * take default modes from "ttymodes" property if it exists
	 */
	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, ddi_root_node(), 0,
	    "ttymodes", (uchar_t **)&termiosp, &len) == DDI_PROP_SUCCESS) {

		if (len == sizeof (struct termios)) {
			tp->t_cflag = termiosp->c_cflag;

			if (termiosp->c_iflag & (IXON | IXANY)) {
				tp->t_iflag =
				    termiosp->c_iflag & (IXON | IXANY);
				tp->t_startc = termiosp->c_cc[VSTART];
				tp->t_stopc = termiosp->c_cc[VSTOP];
			}
		}
		ddi_prop_free(termiosp);
	}

	/*
	 * look for "ignore-cd" or "port-N-ignore-cd" property
	 */
	(void) sprintf(name, "port-%d-ignore-cd", pp->port_num);
	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "ignore-cd", 0) ||
	    ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, name, 0)) {
		pp->port_flags |= USBSER_FL_IGNORE_CD;
	} else {
		pp->port_flags &= ~USBSER_FL_IGNORE_CD;
	}
}


/*
 * undo what was done in usbser_open_init()
 */
static void
usbser_open_fini(usbser_port_t *pp)
{
	uint_t		port_num = pp->port_num;
	usbser_state_t	*usp = pp->port_usp;

	/*
	 * close DSD if it is open
	 */
	if (pp->port_flags & USBSER_FL_DSD_OPEN) {
		mutex_exit(&pp->port_mutex);
		if (USBSER_DS_CLOSE_PORT(usp, port_num) != USB_SUCCESS) {
			USB_DPRINTF_L2(DPRINT_CLOSE, pp->port_lh,
			    "usbser_open_fini: CLOSE_PORT fail");
		}
		mutex_enter(&pp->port_mutex);
	}

	/*
	 * cancel threads
	 */
	usbser_thr_cancel(&pp->port_wq_thread);
	usbser_thr_cancel(&pp->port_rq_thread);

	/*
	 * unpdate soft state
	 */
	pp->port_state = USBSER_PORT_CLOSED;
	cv_broadcast(&pp->port_state_cv);
	cv_broadcast(&pp->port_car_cv);
}


/*
 * setup serial line
 */
static int
usbser_open_line_setup(usbser_port_t *pp, int minor, int flag)
{
	int	rval;

	mutex_exit(&pp->port_mutex);
	/*
	 * prevent opening a disconnected device
	 */
	if (!usbser_dev_is_online(pp->port_usp)) {
		mutex_enter(&pp->port_mutex);

		return (ENXIO);
	}

	/* raise DTR on every open */
	(void) USBSER_DS_SET_MODEM_CTL(pp, TIOCM_DTR, TIOCM_DTR);

	mutex_enter(&pp->port_mutex);
	/*
	 * check carrier
	 */
	rval = usbser_open_carrier_check(pp, minor, flag);

	return (rval);
}


/*
 * check carrier and wait if needed
 */
static int
usbser_open_carrier_check(usbser_port_t *pp, int minor, int flag)
{
	tty_common_t	*tp = &pp->port_ttycommon;
	int		val = 0;
	int		rval;

	if (pp->port_flags & USBSER_FL_IGNORE_CD) {
		tp->t_flags |= TS_SOFTCAR;
	}

	/*
	 * check carrier
	 */
	if (tp->t_flags & TS_SOFTCAR) {
		pp->port_flags |= USBSER_FL_CARR_ON;
	} else if (USBSER_DS_GET_MODEM_CTL(pp, TIOCM_CD, &val) != USB_SUCCESS) {

		return (ENXIO);
	} else if (val & TIOCM_CD) {
		pp->port_flags |= USBSER_FL_CARR_ON;
	} else {
		pp->port_flags &= ~USBSER_FL_CARR_ON;
	}

	/*
	 * don't block if 1) not allowed to, 2) this is a local device,
	 * 3) opening in dial-out mode, or 4) carrier is already on
	 */
	if ((flag & (FNDELAY | FNONBLOCK)) || (tp->t_cflag & CLOCAL) ||
	    (minor & OUTLINE) || (pp->port_flags & USBSER_FL_CARR_ON)) {

		return (USBSER_COMPLETE);
	}

	/*
	 * block until carrier up (only in tty mode)
	 */
	USB_DPRINTF_L4(DPRINT_OPEN, pp->port_lh,
	    "usbser_open_carrier_check: waiting for carrier...");

	pp->port_flags |= USBSER_FL_WOPEN;

	rval = cv_wait_sig(&pp->port_car_cv, &pp->port_mutex);

	pp->port_flags &= ~USBSER_FL_WOPEN;

	if (rval == 0) {
		/*
		 * interrupted with a signal
		 */
		return (EINTR);
	} else {
		/*
		 * try again
		 */
		return (USBSER_CONTINUE);
	}
}


/*
 * during open, setup queues and message processing
 */
static void
usbser_open_queues_init(usbser_port_t *pp, queue_t *rq)
{
	pp->port_ttycommon.t_readq = rq;
	pp->port_ttycommon.t_writeq = WR(rq);
	rq->q_ptr = WR(rq)->q_ptr = (caddr_t)pp;

	qprocson(rq);
}


/*
 * clean up queues and message processing
 */
static void
usbser_open_queues_fini(usbser_port_t *pp)
{
	queue_t	*rq = pp->port_ttycommon.t_readq;

	mutex_exit(&pp->port_mutex);
	/*
	 * clean up queues
	 */
	qprocsoff(rq);

	/*
	 * free unused messages
	 */
	flushq(rq, FLUSHALL);
	flushq(WR(rq), FLUSHALL);

	rq->q_ptr = WR(rq)->q_ptr = NULL;
	ttycommon_close(&pp->port_ttycommon);
	mutex_enter(&pp->port_mutex);
}


/*
 * during close, wait until pending data is gone or the signal is sent
 */
static void
usbser_close_drain(usbser_port_t *pp)
{
	int	need_drain;
	clock_t	until;
	int	rval = USB_SUCCESS;

	/*
	 * port_wq_data_cnt indicates amount of data on the write queue,
	 * which becomes zero when all data is submitted to DSD. But usbser
	 * stays busy until it gets tx callback from DSD, signalling that
	 * data has been sent over USB. To be continued in the next comment...
	 */
	until = ddi_get_lbolt() +
	    drv_usectohz(USBSER_WQ_DRAIN_TIMEOUT * 1000000);

	while ((pp->port_wq_data_cnt > 0) && USBSER_PORT_IS_BUSY(pp)) {
		if ((rval = cv_timedwait_sig(&pp->port_act_cv, &pp->port_mutex,
		    until)) <= 0) {

			break;
		}
	}

	/* don't drain if timed out or received a signal */
	need_drain = (pp->port_wq_data_cnt == 0) || !USBSER_PORT_IS_BUSY(pp) ||
	    (rval != USB_SUCCESS);

	mutex_exit(&pp->port_mutex);
	/*
	 * Once the data reaches USB serial box, it may still be stored in its
	 * internal output buffer (FIFO). We call DSD drain to ensure that all
	 * the data is transmitted transmitted over the serial line.
	 */
	if (need_drain) {
		rval = USBSER_DS_FIFO_DRAIN(pp, USBSER_TX_FIFO_DRAIN_TIMEOUT);
		if (rval != USB_SUCCESS) {
			(void) USBSER_DS_FIFO_FLUSH(pp, DS_TX);
		}
	} else {
		(void) USBSER_DS_FIFO_FLUSH(pp, DS_TX);
	}
	mutex_enter(&pp->port_mutex);
}


/*
 * during close, cancel break/delay
 */
static void
usbser_close_cancel_break(usbser_port_t *pp)
{
	timeout_id_t	delay_id;

	if (pp->port_act & USBSER_ACT_BREAK) {
		delay_id = pp->port_delay_id;
		pp->port_delay_id = 0;

		mutex_exit(&pp->port_mutex);
		(void) untimeout(delay_id);
		(void) USBSER_DS_BREAK_CTL(pp, DS_OFF);
		mutex_enter(&pp->port_mutex);

		pp->port_act &= ~USBSER_ACT_BREAK;
	}
}


/*
 * during close, drop RTS/DTR if necessary
 */
static void
usbser_close_hangup(usbser_port_t *pp)
{
	/*
	 * drop DTR and RTS if HUPCL is set
	 */
	if (pp->port_ttycommon.t_cflag & HUPCL) {
		mutex_exit(&pp->port_mutex);
		(void) USBSER_DS_SET_MODEM_CTL(pp, TIOCM_RTS | TIOCM_DTR, 0);
		mutex_enter(&pp->port_mutex);
	}
}


/*
 * state cleanup during close
 */
static void
usbser_close_cleanup(usbser_port_t *pp)
{
	usbser_open_queues_fini(pp);

	usbser_open_fini(pp);
}


/*
 *
 * thread management
 * -----------------
 *
 *
 * dispatch a thread
 */
static void
usbser_thr_dispatch(usbser_thread_t *thr)
{
	usbser_port_t	*pp = thr->thr_port;
	usbser_state_t	*usp = pp->port_usp;
	int		rval;

	ASSERT(mutex_owned(&pp->port_mutex));
	ASSERT((thr->thr_flags & USBSER_THR_RUNNING) == 0);

	thr->thr_flags = USBSER_THR_RUNNING;

	rval = ddi_taskq_dispatch(usp->us_taskq, thr->thr_func, thr->thr_arg,
	    DDI_SLEEP);
	ASSERT(rval == DDI_SUCCESS);
}


/*
 * cancel a thread
 */
static void
usbser_thr_cancel(usbser_thread_t *thr)
{
	usbser_port_t	*pp = thr->thr_port;

	ASSERT(mutex_owned(&pp->port_mutex));

	thr->thr_flags &= ~USBSER_THR_RUNNING;
	cv_signal(&thr->thr_cv);

	/* wait until the thread actually exits */
	do {
		cv_wait(&thr->thr_cv, &pp->port_mutex);

	} while ((thr->thr_flags & USBSER_THR_EXITED) == 0);
}


/*
 * wake thread
 */
static void
usbser_thr_wake(usbser_thread_t *thr)
{
	ASSERT(mutex_owned(&thr->thr_port->port_mutex));

	thr->thr_flags |= USBSER_THR_WAKE;
	cv_signal(&thr->thr_cv);
}


/*
 * thread handling write queue requests
 */
static void
usbser_wq_thread(void *arg)
{
	usbser_thread_t	*thr = (usbser_thread_t *)arg;
	usbser_port_t	*pp = thr->thr_port;

	USB_DPRINTF_L4(DPRINT_WQ, pp->port_lh, "usbser_wq_thread: enter");

	mutex_enter(&pp->port_mutex);
	while (thr->thr_flags & USBSER_THR_RUNNING) {
		/*
		 * when woken, see what we should do
		 */
		if (thr->thr_flags & USBSER_THR_WAKE) {
			thr->thr_flags &= ~USBSER_THR_WAKE;

			/*
			 * status callback pending?
			 */
			if (pp->port_flags & USBSER_FL_STATUS_CB) {
				usbser_status_proc_cb(pp);
			}

			usbser_wmsg(pp);
		} else {
			/*
			 * sleep until woken up to do some work, e.g:
			 * - new message arrives;
			 * - data transmit completes;
			 * - status callback pending;
			 * - wq thread is cancelled;
			 */
			cv_wait(&thr->thr_cv, &pp->port_mutex);
			USB_DPRINTF_L4(DPRINT_WQ, pp->port_lh,
			    "usbser_wq_thread: wakeup");
		}
	}
	thr->thr_flags |= USBSER_THR_EXITED;
	cv_signal(&thr->thr_cv);
	USB_DPRINTF_L4(DPRINT_WQ, pp->port_lh, "usbser_wq_thread: exit");
	mutex_exit(&pp->port_mutex);
}


/*
 * thread handling read queue requests
 */
static void
usbser_rq_thread(void *arg)
{
	usbser_thread_t	*thr = (usbser_thread_t *)arg;
	usbser_port_t	*pp = thr->thr_port;

	USB_DPRINTF_L4(DPRINT_WQ, pp->port_lh, "usbser_rq_thread: enter");

	mutex_enter(&pp->port_mutex);
	while (thr->thr_flags & USBSER_THR_RUNNING) {
		/*
		 * read service routine will wake us when
		 * more space is available on the read queue
		 */
		if (thr->thr_flags & USBSER_THR_WAKE) {
			thr->thr_flags &= ~USBSER_THR_WAKE;

			/*
			 * don't process messages until queue is enabled
			 */
			if (!pp->port_ttycommon.t_readq) {

				continue;
			}

			/*
			 * check whether we need to resume receive
			 */
			if (pp->port_flags & USBSER_FL_RX_STOPPED) {
				pp->port_flowc = pp->port_ttycommon.t_startc;
				usbser_inbound_flow_ctl(pp);
			}

			/*
			 * grab more data if available
			 */
			mutex_exit(&pp->port_mutex);
			usbser_rx_cb((caddr_t)pp);
			mutex_enter(&pp->port_mutex);
		} else {
			cv_wait(&thr->thr_cv, &pp->port_mutex);
			USB_DPRINTF_L4(DPRINT_WQ, pp->port_lh,
			    "usbser_rq_thread: wakeup");
		}
	}
	thr->thr_flags |= USBSER_THR_EXITED;
	cv_signal(&thr->thr_cv);
	USB_DPRINTF_L4(DPRINT_RQ, pp->port_lh, "usbser_rq_thread: exit");
	mutex_exit(&pp->port_mutex);
}


/*
 * DSD callbacks
 * -------------
 *
 * Note: to avoid deadlocks with DSD, these callbacks
 * should not call DSD functions that can block.
 *
 *
 * transmit callback
 *
 * invoked by DSD when the last byte of data is transmitted over USB
 */
static void
usbser_tx_cb(caddr_t arg)
{
	usbser_port_t	*pp = (usbser_port_t *)arg;
	int		online;

	online = usbser_dev_is_online(pp->port_usp);

	mutex_enter(&pp->port_mutex);
	USB_DPRINTF_L4(DPRINT_TX_CB, pp->port_lh,
	    "usbser_tx_cb: act=%x curthread=%p", pp->port_act,
	    (void *)curthread);

	usbser_release_port_act(pp, USBSER_ACT_TX);

	/*
	 * as long as port access is ok and the port is not busy on
	 * TX, break, ctrl or delay, the wq_thread should be waken
	 * to do further process for next message
	 */
	if (online && USBSER_PORT_ACCESS_OK(pp) &&
	    !USBSER_PORT_IS_BUSY_NON_RX(pp)) {
		/*
		 * wake wq thread for further data/ioctl processing
		 */
		usbser_thr_wake(&pp->port_wq_thread);
	}
	mutex_exit(&pp->port_mutex);
}


/*
 * receive callback
 *
 * invoked by DSD when there is more data for us to pick
 */
static void
usbser_rx_cb(caddr_t arg)
{
	usbser_port_t	*pp = (usbser_port_t *)arg;
	queue_t		*rq, *wq;
	mblk_t		*mp;		/* current mblk */
	mblk_t		*data, *data_tail; /* M_DATA mblk list and its tail */
	mblk_t		*emp;		/* error (M_BREAK) mblk */

	USB_DPRINTF_L4(DPRINT_RX_CB, pp->port_lh, "usbser_rx_cb");

	if (!usbser_dev_is_online(pp->port_usp)) {

		return;
	}

	/* get data from DSD */
	if ((mp = USBSER_DS_RX(pp)) == NULL) {

		return;
	}

	mutex_enter(&pp->port_mutex);
	if ((!USBSER_PORT_ACCESS_OK(pp)) ||
	    ((pp->port_ttycommon.t_cflag & CREAD) == 0)) {
		freemsg(mp);
		mutex_exit(&pp->port_mutex);
		USB_DPRINTF_L3(DPRINT_RX_CB, pp->port_lh,
		    "usbser_rx_cb: access not ok or receiver disabled");

		return;
	}

	usbser_serialize_port_act(pp, USBSER_ACT_RX);

	rq = pp->port_ttycommon.t_readq;
	wq = pp->port_ttycommon.t_writeq;
	mutex_exit(&pp->port_mutex);

	/*
	 * DSD data is a b_cont-linked list of M_DATA and M_BREAK blocks.
	 * M_DATA is correctly received data.
	 * M_BREAK is a character with either framing or parity error.
	 *
	 * this loop runs through the list of mblks. when it meets an M_BREAK,
	 * it sends all leading M_DATA's in one shot, then sends M_BREAK.
	 * in the trivial case when list contains only M_DATA's, the loop
	 * does nothing but set data variable.
	 */
	data = data_tail = NULL;
	while (mp) {
		/*
		 * skip data until we meet M_BREAK or end of list
		 */
		if (DB_TYPE(mp) == M_DATA) {
			if (data == NULL) {
				data = mp;
			}
			data_tail = mp;
			mp = mp->b_cont;

			continue;
		}

		/* detach data list from mp */
		if (data_tail) {
			data_tail->b_cont = NULL;
		}
		/* detach emp from the list */
		emp = mp;
		mp = mp->b_cont;
		emp->b_cont = NULL;

		/* DSD shouldn't send anything but M_DATA or M_BREAK */
		if ((DB_TYPE(emp) != M_BREAK) || (MBLKL(emp) != 2)) {
			freemsg(emp);
			USB_DPRINTF_L2(DPRINT_RX_CB, pp->port_lh,
			    "usbser_rx_cb: bad message");

			continue;
		}

		/*
		 * first tweak and send M_DATA's
		 */
		if (data) {
			usbser_rx_massage_data(pp, data);
			usbser_rx_cb_put(pp, rq, wq, data);
			data = data_tail = NULL;
		}

		/*
		 * now tweak and send M_BREAK
		 */
		mutex_enter(&pp->port_mutex);
		usbser_rx_massage_mbreak(pp, emp);
		mutex_exit(&pp->port_mutex);
		usbser_rx_cb_put(pp, rq, wq, emp);
	}

	/* send the rest of the data, if any */
	if (data) {
		usbser_rx_massage_data(pp, data);
		usbser_rx_cb_put(pp, rq, wq, data);
	}

	mutex_enter(&pp->port_mutex);
	usbser_release_port_act(pp, USBSER_ACT_RX);
	mutex_exit(&pp->port_mutex);
}

/*
 * the joys of termio -- this is to accomodate Unix98 assertion:
 *
 *   If PARENB is supported and is set, when PARMRK is set, and CSIZE is
 *   set to CS8, and IGNPAR is clear, and ISTRIP is clear, a valid
 *   character of '\377' is read as '\377', '\377'.
 *
 *   Posix Ref: Assertion 7.1.2.2-16(C)
 *
 * this requires the driver to scan every incoming valid character
 */
static void
usbser_rx_massage_data(usbser_port_t *pp, mblk_t *mp)
{
	tty_common_t	*tp = &pp->port_ttycommon;
	uchar_t		*p;
	mblk_t		*newmp;
	int		tailsz;

	/* avoid scanning if possible */
	mutex_enter(&pp->port_mutex);
	if (!((tp->t_cflag & PARENB) && (tp->t_iflag & PARMRK) &&
	    ((tp->t_cflag & CSIZE) == CS8) &&
	    ((tp->t_iflag & (IGNPAR|ISTRIP)) == 0))) {
		mutex_exit(&pp->port_mutex);

		return;
	}
	mutex_exit(&pp->port_mutex);

	while (mp) {
		for (p = mp->b_rptr; p < mp->b_wptr; ) {
			if (*p++ != 0377) {

				continue;
			}
			USB_DPRINTF_L4(DPRINT_RX_CB, pp->port_lh,
			    "usbser_rx_massage_data: mp=%p off=%ld(%ld)",
			    (void *)mp, _PTRDIFF(p,  mp->b_rptr) - 1,
			    (long)MBLKL(mp));

			/*
			 * insert another 0377 after this one. all data after
			 * the original 0377 have to be copied to the new mblk
			 */
			tailsz = _PTRDIFF(mp->b_wptr, p);
			if ((newmp = allocb(tailsz + 1, BPRI_HI)) == NULL) {
				USB_DPRINTF_L2(DPRINT_RX_CB, pp->port_lh,
				    "usbser_rx_massage_data: allocb failed");

				continue;
			}

			/* fill in the new mblk */
			*newmp->b_wptr++ = 0377;
			if (tailsz > 0) {
				bcopy(p, newmp->b_wptr, tailsz);
				newmp->b_wptr += tailsz;
			}
			/* shrink the original mblk */
			mp->b_wptr = p;

			newmp->b_cont = mp->b_cont;
			mp->b_cont = newmp;
			p = newmp->b_rptr + 1;
			mp = newmp;
		}
		mp = mp->b_cont;
	}
}

/*
 * more joys of termio
 */
static void
usbser_rx_massage_mbreak(usbser_port_t *pp, mblk_t *mp)
{
	tty_common_t	*tp = &pp->port_ttycommon;
	uchar_t		err, c;

	err = *mp->b_rptr;
	c = *(mp->b_rptr + 1);

	if ((err & (DS_FRAMING_ERR | DS_BREAK_ERR)) && (c == 0)) {
		/* break */
		mp->b_rptr += 2;
	} else if (!(tp->t_iflag & INPCK) && (err & (DS_PARITY_ERR))) {
		/* Posix Ref: Assertion 7.1.2.2-20(C) */
		mp->b_rptr++;
		DB_TYPE(mp) = M_DATA;
	} else {
		/* for ldterm to handle */
		mp->b_rptr++;
	}

	USB_DPRINTF_L4(DPRINT_RX_CB, pp->port_lh,
	    "usbser_rx_massage_mbreak: type=%x len=%ld [0]=0%o",
	    DB_TYPE(mp), (long)MBLKL(mp), (MBLKL(mp) > 0) ? *mp->b_rptr : 45);
}


/*
 * in rx callback, try to send an mblk upstream
 */
static void
usbser_rx_cb_put(usbser_port_t *pp, queue_t *rq, queue_t *wq, mblk_t *mp)
{
	if (canputnext(rq)) {
		putnext(rq, mp);
	} else if (canput(rq) && putq(rq, mp)) {
		/*
		 * full queue indicates the need for inbound flow control
		 */
		(void) putctl(wq, M_STOPI);
		usbser_st_put_stopi++;

		USB_DPRINTF_L3(DPRINT_RX_CB, pp->port_lh,
		    "usbser_rx_cb: cannot putnext, flow ctl");
	} else {
		freemsg(mp);
		usbser_st_rx_data_loss++;
		(void) putctl(wq, M_STOPI);
		usbser_st_put_stopi++;

		USB_DPRINTF_L1(DPRINT_RX_CB, pp->port_lh,
		    "input overrun");
	}
}


/*
 * modem status change callback
 *
 * each time external status lines are changed, DSD calls this routine
 */
static void
usbser_status_cb(caddr_t arg)
{
	usbser_port_t	*pp = (usbser_port_t *)arg;

	USB_DPRINTF_L4(DPRINT_STATUS_CB, pp->port_lh, "usbser_status_cb");

	if (!usbser_dev_is_online(pp->port_usp)) {

		return;
	}

	/*
	 * actual processing will be done in usbser_status_proc_cb()
	 * running in wq thread
	 */
	mutex_enter(&pp->port_mutex);
	if (USBSER_PORT_ACCESS_OK(pp) || USBSER_IS_OPENING(pp)) {
		pp->port_flags |= USBSER_FL_STATUS_CB;
		usbser_thr_wake(&pp->port_wq_thread);
	}
	mutex_exit(&pp->port_mutex);
}


/*
 * modem status change
 */
static void
usbser_status_proc_cb(usbser_port_t *pp)
{
	tty_common_t	*tp = &pp->port_ttycommon;
	queue_t		*rq, *wq;
	int		status;
	int		drop_dtr = 0;
	int		rq_msg = 0, wq_msg = 0;

	USB_DPRINTF_L4(DPRINT_STATUS_CB, pp->port_lh, "usbser_status_proc_cb");

	pp->port_flags &= ~USBSER_FL_STATUS_CB;

	mutex_exit(&pp->port_mutex);
	if (!usbser_dev_is_online(pp->port_usp)) {
		mutex_enter(&pp->port_mutex);

		return;
	}

	/* get modem status */
	if (USBSER_DS_GET_MODEM_CTL(pp, -1, &status) != USB_SUCCESS) {
		mutex_enter(&pp->port_mutex);

		return;
	}

	mutex_enter(&pp->port_mutex);
	usbser_serialize_port_act(pp, USBSER_ACT_CTL);

	rq = pp->port_ttycommon.t_readq;
	wq = pp->port_ttycommon.t_writeq;

	/*
	 * outbound flow control
	 */
	if (tp->t_cflag & CRTSCTS) {
		if (!(status & TIOCM_CTS)) {
			/*
			 * CTS dropped, stop xmit
			 */
			if (!(pp->port_flags & USBSER_FL_TX_STOPPED)) {
				wq_msg = M_STOP;
			}
		} else if (pp->port_flags & USBSER_FL_TX_STOPPED) {
			/*
			 * CTS raised, resume xmit
			 */
			wq_msg = M_START;
		}
	}

	/*
	 * check carrier
	 */
	if ((status & TIOCM_CD) || (tp->t_flags & TS_SOFTCAR)) {
		/*
		 * carrier present
		 */
		if ((pp->port_flags & USBSER_FL_CARR_ON) == 0) {
			pp->port_flags |= USBSER_FL_CARR_ON;

			rq_msg = M_UNHANGUP;
			/*
			 * wake open
			 */
			if (pp->port_flags & USBSER_FL_WOPEN) {
				cv_broadcast(&pp->port_car_cv);
			}

			USB_DPRINTF_L4(DPRINT_STATUS_CB, pp->port_lh,
			    "usbser_status_cb: carr on");
		}
	} else if (pp->port_flags & USBSER_FL_CARR_ON) {
		pp->port_flags &= ~USBSER_FL_CARR_ON;
		/*
		 * carrier went away: if not local line, drop DTR
		 */
		if (!(tp->t_cflag & CLOCAL)) {
			drop_dtr = 1;
			rq_msg = M_HANGUP;
		}
		if ((pp->port_flags & USBSER_FL_TX_STOPPED) && (wq_msg == 0)) {
			wq_msg = M_START;
		}

		USB_DPRINTF_L4(DPRINT_STATUS_CB, pp->port_lh,
		    "usbser_status_cb: carr off");
	}
	mutex_exit(&pp->port_mutex);

	USB_DPRINTF_L4(DPRINT_STATUS_CB, pp->port_lh,
	    "usbser_status_cb: rq_msg=%d wq_msg=%d", rq_msg, wq_msg);

	/*
	 * commit postponed actions now
	 * do so only if port is fully open (queues are enabled)
	 */
	if (rq) {
		if (rq_msg) {
			(void) putnextctl(rq, rq_msg);
		}
		if (drop_dtr) {
			(void) USBSER_DS_SET_MODEM_CTL(pp, TIOCM_DTR, 0);
		}
		if (wq_msg) {
			(void) putctl(wq, wq_msg);
		}
	}

	mutex_enter(&pp->port_mutex);
	usbser_release_port_act(pp, USBSER_ACT_CTL);
}


/*
 * serial support
 * --------------
 *
 *
 * this routine is run by wq thread every time it's woken,
 * i.e. when the queue contains messages to process
 */
static void
usbser_wmsg(usbser_port_t *pp)
{
	queue_t		*q = pp->port_ttycommon.t_writeq;
	mblk_t		*mp;
	int		msgtype;

	ASSERT(mutex_owned(&pp->port_mutex));

	if (q == NULL) {
		USB_DPRINTF_L3(DPRINT_WQ, pp->port_lh, "usbser_wmsg: q=NULL");

		return;
	}
	USB_DPRINTF_L4(DPRINT_WQ, pp->port_lh, "usbser_wmsg: q=%p act=%x 0x%x",
	    (void *)q, pp->port_act, q->q_first ? DB_TYPE(q->q_first) : 0xff);

	while ((mp = getq(q)) != NULL) {
		msgtype = DB_TYPE(mp);
		USB_DPRINTF_L4(DPRINT_WQ, pp->port_lh, "usbser_wmsg: "
		    "type=%s (0x%x)", usbser_msgtype2str(msgtype), msgtype);

		switch (msgtype) {
		/*
		 * high-priority messages
		 */
		case M_STOP:
			usbser_stop(pp, mp);

			break;
		case M_START:
			usbser_start(pp, mp);

			break;
		case M_STOPI:
			usbser_stopi(pp, mp);

			break;
		case M_STARTI:
			usbser_starti(pp, mp);

			break;
		case M_IOCDATA:
			usbser_iocdata(pp, mp);

			break;
		case M_FLUSH:
			usbser_flush(pp, mp);

			break;
		/*
		 * normal-priority messages
		 */
		case M_BREAK:
			usbser_break(pp, mp);

			break;
		case M_DELAY:
			usbser_delay(pp, mp);

			break;
		case M_DATA:
			if (usbser_data(pp, mp) != USB_SUCCESS) {
				(void) putbq(q, mp);

				return;
			}

			break;
		case M_IOCTL:
			if (usbser_ioctl(pp, mp) != USB_SUCCESS) {
				(void) putbq(q, mp);

				return;
			}

			break;
		default:
			freemsg(mp);

			break;
		}
	}
}


/*
 * process M_DATA message
 */
static int
usbser_data(usbser_port_t *pp, mblk_t *mp)
{
	/* put off until current transfer ends or delay is over */
	if ((pp->port_act & USBSER_ACT_TX) ||
	    (pp->port_act & USBSER_ACT_DELAY)) {

		return (USB_FAILURE);
	}
	if (MBLKL(mp) <= 0) {
		freemsg(mp);

		return (USB_SUCCESS);
	}

	pp->port_act |= USBSER_ACT_TX;
	pp->port_wq_data_cnt -= msgdsize(mp);

	mutex_exit(&pp->port_mutex);
	/* DSD is required to accept data block in any case */
	(void) USBSER_DS_TX(pp, mp);
	mutex_enter(&pp->port_mutex);

	return (USB_SUCCESS);
}


/*
 * process an M_IOCTL message
 */
static int
usbser_ioctl(usbser_port_t *pp, mblk_t *mp)
{
	tty_common_t	*tp = &pp->port_ttycommon;
	queue_t		*q = tp->t_writeq;
	struct iocblk	*iocp;
	int		cmd;
	mblk_t		*datamp;
	int		error = 0, rval = USB_SUCCESS;
	int		val;

	ASSERT(mutex_owned(&pp->port_mutex));
	ASSERT(DB_TYPE(mp) == M_IOCTL);

	iocp = (struct iocblk *)mp->b_rptr;
	cmd = iocp->ioc_cmd;

	USB_DPRINTF_L4(DPRINT_IOCTL, pp->port_lh, "usbser_ioctl: "
	    "mp=%p %s (0x%x)", (void *)mp, usbser_ioctl2str(cmd), cmd);

	if (tp->t_iocpending != NULL) {
		/*
		 * We were holding an ioctl response pending the
		 * availability of an mblk to hold data to be passed up;
		 * another ioctl came through, which means that ioctl
		 * must have timed out or been aborted.
		 */
		freemsg(tp->t_iocpending);
		tp->t_iocpending = NULL;
	}

	switch (cmd) {
	case TIOCMGET:
	case TIOCMBIC:
	case TIOCMBIS:
	case TIOCMSET:
	case CONSOPENPOLLEDIO:
	case CONSCLOSEPOLLEDIO:
	case CONSSETABORTENABLE:
	case CONSGETABORTENABLE:
		/*
		 * For the above ioctls do not call ttycommon_ioctl() because
		 * this function frees up the message block (mp->b_cont) that
		 * contains the address of the user variable where we need to
		 * pass back the bit array.
		 */
		error = -1;
		usbser_serialize_port_act(pp, USBSER_ACT_CTL);
		mutex_exit(&pp->port_mutex);
		break;

	case TCSBRK:
		/* serialize breaks */
		if (pp->port_act & USBSER_ACT_BREAK)
			return (USB_FAILURE);
		/*FALLTHRU*/
	default:
		usbser_serialize_port_act(pp, USBSER_ACT_CTL);
		mutex_exit(&pp->port_mutex);
		(void) ttycommon_ioctl(tp, q, mp, &error);
		break;
	}

	if (error == 0) {
		/*
		 * ttycommon_ioctl() did most of the work
		 * we just use the data it set up
		 */
		switch (cmd) {
		case TCSETSF:
		case TCSETSW:
		case TCSETA:
		case TCSETAW:
		case TCSETAF:
			(void) USBSER_DS_FIFO_DRAIN(pp, DS_TX);
			/*FALLTHRU*/

		case TCSETS:
			mutex_enter(&pp->port_mutex);
			error = usbser_port_program(pp);
			mutex_exit(&pp->port_mutex);
			break;
		}
		goto end;

	} else if (error > 0) {
		USB_DPRINTF_L3(DPRINT_IOCTL, pp->port_lh, "usbser_ioctl: "
		    "ttycommon_ioctl returned %d", error);
		goto end;
	}

	/*
	 * error < 0: ttycommon_ioctl() didn't do anything, we process it here
	 */
	error = 0;
	switch (cmd) {
	case TCSBRK:
		if ((error = miocpullup(mp, sizeof (int))) != 0)
			break;

		/* drain output */
		(void) USBSER_DS_FIFO_DRAIN(pp, USBSER_TX_FIFO_DRAIN_TIMEOUT);

		/*
		 * if required, set break
		 */
		if (*(int *)mp->b_cont->b_rptr == 0) {
			if (USBSER_DS_BREAK_CTL(pp, DS_ON) != USB_SUCCESS) {
				error = EIO;
				break;
			}

			mutex_enter(&pp->port_mutex);
			pp->port_act |= USBSER_ACT_BREAK;
			pp->port_delay_id = timeout(usbser_restart, pp,
			    drv_usectohz(250000));
			mutex_exit(&pp->port_mutex);
		}
		mioc2ack(mp, NULL, 0, 0);
		break;

	case TIOCSBRK:	/* set break */
		if (USBSER_DS_BREAK_CTL(pp, DS_ON) != USB_SUCCESS)
			error = EIO;
		else
			mioc2ack(mp, NULL, 0, 0);
		break;

	case TIOCCBRK:	/* clear break */
		if (USBSER_DS_BREAK_CTL(pp, DS_OFF) != USB_SUCCESS)
			error = EIO;
		else
			mioc2ack(mp, NULL, 0, 0);
		break;

	case TIOCMSET:	/* set all modem bits */
	case TIOCMBIS:	/* bis modem bits */
	case TIOCMBIC:	/* bic modem bits */
		if (iocp->ioc_count == TRANSPARENT) {
			mcopyin(mp, NULL, sizeof (int), NULL);
			break;
		}
		if ((error = miocpullup(mp, sizeof (int))) != 0)
			break;

		val = *(int *)mp->b_cont->b_rptr;
		if (cmd == TIOCMSET) {
			rval = USBSER_DS_SET_MODEM_CTL(pp, -1, val);
		} else if (cmd == TIOCMBIS) {
			rval = USBSER_DS_SET_MODEM_CTL(pp, val, -1);
		} else if (cmd == TIOCMBIC) {
			rval = USBSER_DS_SET_MODEM_CTL(pp, val, 0);
		}
		if (rval == USB_SUCCESS)
			mioc2ack(mp, NULL, 0, 0);
		else
			error = EIO;
		break;

	case TIOCSILOOP:
		if (USBSER_DS_LOOPBACK_SUPPORTED(pp)) {
			if (USBSER_DS_LOOPBACK(pp, DS_ON) == USB_SUCCESS)
				mioc2ack(mp, NULL, 0, 0);
			else
				error = EIO;
		} else {
			error = EINVAL;
		}
		break;

	case TIOCCILOOP:
		if (USBSER_DS_LOOPBACK_SUPPORTED(pp)) {
			if (USBSER_DS_LOOPBACK(pp, DS_OFF) == USB_SUCCESS)
				mioc2ack(mp, NULL, 0, 0);
			else
				error = EIO;
		} else {
			error = EINVAL;
		}
		break;

	case TIOCMGET:	/* get all modem bits */
		if ((datamp = allocb(sizeof (int), BPRI_MED)) == NULL) {
			error = EAGAIN;
			break;
		}
		rval = USBSER_DS_GET_MODEM_CTL(pp, -1, (int *)datamp->b_rptr);
		if (rval != USB_SUCCESS) {
			error = EIO;
			break;
		}
		if (iocp->ioc_count == TRANSPARENT)
			mcopyout(mp, NULL, sizeof (int), NULL, datamp);
		else
			mioc2ack(mp, datamp, sizeof (int), 0);
		break;

	case CONSOPENPOLLEDIO:
		error = usbser_polledio_init(pp);
		if (error != 0)
			break;

		error = miocpullup(mp, sizeof (struct cons_polledio *));
		if (error != 0)
			break;

		*(struct cons_polledio **)mp->b_cont->b_rptr = &usbser_polledio;

		mp->b_datap->db_type = M_IOCACK;
		break;

	case CONSCLOSEPOLLEDIO:
		usbser_polledio_fini(pp);
		mp->b_datap->db_type = M_IOCACK;
		iocp->ioc_error = 0;
		iocp->ioc_rval = 0;
		break;

	case CONSSETABORTENABLE:
		error = secpolicy_console(iocp->ioc_cr);
		if (error != 0)
			break;

		if (iocp->ioc_count != TRANSPARENT) {
			error = EINVAL;
			break;
		}

		/*
		 * To do: implement console abort support
		 * This involves adding a console flag to usbser
		 * state structure. If flag is set, parse input stream
		 * for abort sequence (see asy for example).
		 *
		 * For now, run mdb -K to get kmdb prompt.
		 */
		if (*(intptr_t *)mp->b_cont->b_rptr)
			usbser_console_abort = 1;
		else
			usbser_console_abort = 0;

		mp->b_datap->db_type = M_IOCACK;
		iocp->ioc_error = 0;
		iocp->ioc_rval = 0;
		break;

	case CONSGETABORTENABLE:
		/*CONSTANTCONDITION*/
		ASSERT(sizeof (boolean_t) <= sizeof (boolean_t *));
		/*
		 * Store the return value right in the payload
		 * we were passed.  Crude.
		 */
		mcopyout(mp, NULL, sizeof (boolean_t), NULL, NULL);
		*(boolean_t *)mp->b_cont->b_rptr = (usbser_console_abort != 0);
		break;

	default:
		error = EINVAL;
		break;
	}
end:
	if (error != 0)
		miocnak(q, mp, 0, error);
	else
		qreply(q, mp);

	mutex_enter(&pp->port_mutex);
	usbser_release_port_act(pp, USBSER_ACT_CTL);

	return (USB_SUCCESS);
}


/*
 * process M_IOCDATA message
 */
static void
usbser_iocdata(usbser_port_t *pp, mblk_t *mp)
{
	tty_common_t	*tp = &pp->port_ttycommon;
	queue_t		*q = tp->t_writeq;
	struct copyresp	*csp;
	int		cmd;
	int		val;
	int		rval = USB_FAILURE;

	ASSERT(mutex_owned(&pp->port_mutex));

	csp = (struct copyresp *)mp->b_rptr;
	cmd = csp->cp_cmd;

	if (csp->cp_rval != 0) {
		freemsg(mp);
		return;
	}

	switch (cmd) {
	case TIOCMSET:	/* set all modem bits */
	case TIOCMBIS:	/* bis modem bits */
	case TIOCMBIC:	/* bic modem bits */
		if ((mp->b_cont == NULL) ||
		    (MBLKL(mp->b_cont) < sizeof (int))) {
			miocnak(q, mp, 0, EINVAL);
			break;
		}
		val = *(int *)mp->b_cont->b_rptr;

		usbser_serialize_port_act(pp, USBSER_ACT_CTL);
		mutex_exit(&pp->port_mutex);

		if (cmd == TIOCMSET) {
			rval = USBSER_DS_SET_MODEM_CTL(pp, -1, val);
		} else if (cmd == TIOCMBIS) {
			rval = USBSER_DS_SET_MODEM_CTL(pp, val, -1);
		} else if (cmd == TIOCMBIC) {
			rval = USBSER_DS_SET_MODEM_CTL(pp, val, 0);
		}

		if (mp->b_cont) {
			freemsg(mp->b_cont);
			mp->b_cont = NULL;
		}

		if (rval == USB_SUCCESS)
			miocack(q, mp, 0, 0);
		else
			miocnak(q, mp, 0, EIO);

		mutex_enter(&pp->port_mutex);
		usbser_release_port_act(pp, USBSER_ACT_CTL);
		break;

	case TIOCMGET:	/* get all modem bits */
		mutex_exit(&pp->port_mutex);
		miocack(q, mp, 0, 0);
		mutex_enter(&pp->port_mutex);
		break;

	default:
		mutex_exit(&pp->port_mutex);
		miocnak(q, mp, 0, EINVAL);
		mutex_enter(&pp->port_mutex);
		break;
	}
}


/*
 * handle M_START[I]/M_STOP[I] messages
 */
static void
usbser_stop(usbser_port_t *pp, mblk_t *mp)
{
	usbser_st_mstop++;
	if (!(pp->port_flags & USBSER_FL_TX_STOPPED)) {
		usbser_serialize_port_act(pp, USBSER_ACT_CTL);
		pp->port_flags |= USBSER_FL_TX_STOPPED;

		mutex_exit(&pp->port_mutex);
		USBSER_DS_STOP(pp, DS_TX);
		mutex_enter(&pp->port_mutex);

		usbser_release_port_act(pp, USBSER_ACT_TX);
		usbser_release_port_act(pp, USBSER_ACT_CTL);
	}
	freemsg(mp);
}


static void
usbser_start(usbser_port_t *pp, mblk_t *mp)
{
	usbser_st_mstart++;
	if (pp->port_flags & USBSER_FL_TX_STOPPED) {
		usbser_serialize_port_act(pp, USBSER_ACT_CTL);
		pp->port_flags &= ~USBSER_FL_TX_STOPPED;

		mutex_exit(&pp->port_mutex);
		USBSER_DS_START(pp, DS_TX);
		mutex_enter(&pp->port_mutex);
		usbser_release_port_act(pp, USBSER_ACT_CTL);
	}
	freemsg(mp);
}


static void
usbser_stopi(usbser_port_t *pp, mblk_t *mp)
{
	usbser_st_mstopi++;
	usbser_serialize_port_act(pp, USBSER_ACT_CTL);
	pp->port_flowc = pp->port_ttycommon.t_stopc;
	usbser_inbound_flow_ctl(pp);
	usbser_release_port_act(pp, USBSER_ACT_CTL);
	freemsg(mp);
}

static void
usbser_starti(usbser_port_t *pp, mblk_t *mp)
{
	usbser_st_mstarti++;
	usbser_serialize_port_act(pp, USBSER_ACT_CTL);
	pp->port_flowc = pp->port_ttycommon.t_startc;
	usbser_inbound_flow_ctl(pp);
	usbser_release_port_act(pp, USBSER_ACT_CTL);
	freemsg(mp);
}

/*
 * process M_FLUSH message
 */
static void
usbser_flush(usbser_port_t *pp, mblk_t *mp)
{
	queue_t	*q = pp->port_ttycommon.t_writeq;

	if (*mp->b_rptr & FLUSHW) {
		mutex_exit(&pp->port_mutex);
		(void) USBSER_DS_FIFO_FLUSH(pp, DS_TX);	/* flush FIFO buffers */
		flushq(q, FLUSHDATA);			/* flush write queue */
		mutex_enter(&pp->port_mutex);

		usbser_release_port_act(pp, USBSER_ACT_TX);

		*mp->b_rptr &= ~FLUSHW;
	}
	if (*mp->b_rptr & FLUSHR) {
		/*
		 * flush FIFO buffers
		 */
		mutex_exit(&pp->port_mutex);
		(void) USBSER_DS_FIFO_FLUSH(pp, DS_RX);
		flushq(RD(q), FLUSHDATA);
		qreply(q, mp);
		mutex_enter(&pp->port_mutex);
	} else {
		freemsg(mp);
	}
}

/*
 * process M_BREAK message
 */
static void
usbser_break(usbser_port_t *pp, mblk_t *mp)
{
	int	rval;

	/*
	 * set the break and arrange for usbser_restart() to be called in 1/4 s
	 */
	mutex_exit(&pp->port_mutex);
	rval = USBSER_DS_BREAK_CTL(pp, DS_ON);
	mutex_enter(&pp->port_mutex);

	if (rval == USB_SUCCESS) {
		pp->port_act |= USBSER_ACT_BREAK;
		pp->port_delay_id = timeout(usbser_restart, pp,
		    drv_usectohz(250000));
	}
	freemsg(mp);
}


/*
 * process M_DELAY message
 */
static void
usbser_delay(usbser_port_t *pp, mblk_t *mp)
{
	/*
	 * arrange for usbser_restart() to be called when the delay expires
	 */
	pp->port_act |= USBSER_ACT_DELAY;
	pp->port_delay_id = timeout(usbser_restart, pp,
	    (clock_t)(*(uchar_t *)mp->b_rptr + 6));
	freemsg(mp);
}


/*
 * restart output on a line after a delay or break timer expired
 */
static void
usbser_restart(void *arg)
{
	usbser_port_t	*pp = (usbser_port_t *)arg;

	USB_DPRINTF_L4(DPRINT_WQ, pp->port_lh, "usbser_restart");

	mutex_enter(&pp->port_mutex);
	/* if cancelled, return immediately */
	if (pp->port_delay_id == 0) {
		mutex_exit(&pp->port_mutex);

		return;
	}
	pp->port_delay_id = 0;

	/* clear break if necessary */
	if (pp->port_act & USBSER_ACT_BREAK) {
		mutex_exit(&pp->port_mutex);
		(void) USBSER_DS_BREAK_CTL(pp, DS_OFF);
		mutex_enter(&pp->port_mutex);
	}

	usbser_release_port_act(pp, USBSER_ACT_BREAK | USBSER_ACT_DELAY);

	/* wake wq thread to resume message processing */
	usbser_thr_wake(&pp->port_wq_thread);
	mutex_exit(&pp->port_mutex);
}


/*
 * program port hardware with the chosen parameters
 * most of the operation is based on the values of 'c_iflag' and 'c_cflag'
 */
static int
usbser_port_program(usbser_port_t *pp)
{
	tty_common_t		*tp = &pp->port_ttycommon;
	int			baudrate;
	int			c_flag;
	ds_port_param_entry_t	pe[6];
	ds_port_params_t	params;
	int			flow_ctl, ctl_val;
	int			err = 0;

	baudrate = tp->t_cflag & CBAUD;
	if (tp->t_cflag & CBAUDEXT) {
		baudrate += 16;
	}

	/*
	 * set input speed same as output, as split speed not supported
	 */
	if (tp->t_cflag & (CIBAUD|CIBAUDEXT)) {
		tp->t_cflag &= ~(CIBAUD);
		if (baudrate > CBAUD) {
			tp->t_cflag |= CIBAUDEXT;
			tp->t_cflag |=
			    (((baudrate - CBAUD - 1) << IBSHIFT) & CIBAUD);
		} else {
			tp->t_cflag &= ~CIBAUDEXT;
			tp->t_cflag |= ((baudrate << IBSHIFT) & CIBAUD);
		}
	}

	c_flag = tp->t_cflag;

	/*
	 * flow control
	 */
	flow_ctl = tp->t_iflag & (IXON | IXANY | IXOFF);
	if (c_flag & CRTSCTS) {
		flow_ctl |= CTSXON;
	}
	if (c_flag & CRTSXOFF) {
		flow_ctl |= RTSXOFF;
	}

	/*
	 * fill in port parameters we need to set:
	 *
	 * baud rate
	 */
	pe[0].param = DS_PARAM_BAUD;
	pe[0].val.ui = baudrate;

	/* stop bits */
	pe[1].param = DS_PARAM_STOPB;
	pe[1].val.ui = c_flag & CSTOPB;

	/* parity */
	pe[2].param = DS_PARAM_PARITY;
	pe[2].val.ui = c_flag & (PARENB | PARODD);

	/* char size */
	pe[3].param = DS_PARAM_CHARSZ;
	pe[3].val.ui = c_flag & CSIZE;

	/* start & stop chars */
	pe[4].param = DS_PARAM_XON_XOFF;
	pe[4].val.uc[0] = tp->t_startc;
	pe[4].val.uc[1] = tp->t_stopc;

	/* flow control */
	pe[5].param = DS_PARAM_FLOW_CTL;
	pe[5].val.ui = flow_ctl;

	params.tp_entries = &pe[0];
	params.tp_cnt = 6;

	/* control signals */
	ctl_val = TIOCM_DTR | TIOCM_RTS;
	if (baudrate == 0) {
		ctl_val &= ~TIOCM_DTR;	/* zero baudrate means drop DTR */
	}
	if (pp->port_flags & USBSER_FL_RX_STOPPED) {
		ctl_val &= ~TIOCM_RTS;
	}

	/* submit */
	mutex_exit(&pp->port_mutex);
	err = USBSER_DS_SET_PORT_PARAMS(pp, &params);
	if (err != USB_SUCCESS) {
		mutex_enter(&pp->port_mutex);

		return (EINVAL);
	}

	err = USBSER_DS_SET_MODEM_CTL(pp, TIOCM_DTR | TIOCM_RTS, ctl_val);
	mutex_enter(&pp->port_mutex);

	return ((err == USB_SUCCESS) ? 0 : EIO);
}


/*
 * check if any inbound flow control action needed
 */
static void
usbser_inbound_flow_ctl(usbser_port_t *pp)
{
	tcflag_t	need_hw;
	int		rts;
	char		c = pp->port_flowc;
	mblk_t		*mp = NULL;

	USB_DPRINTF_L4(DPRINT_WQ, pp->port_lh,
	    "usbser_inbound_flow_ctl: c=%x cflag=%x port_flags=%x",
	    c, pp->port_ttycommon.t_cflag, pp->port_flags);

	if (c == '\0') {

		return;
	}
	pp->port_flowc = '\0';

	/*
	 * if inbound hardware flow control enabled, we need to frob RTS
	 */
	need_hw = (pp->port_ttycommon.t_cflag & CRTSXOFF);
	if (c == pp->port_ttycommon.t_startc) {
		rts = TIOCM_RTS;
		pp->port_flags &= ~USBSER_FL_RX_STOPPED;
	} else {
		rts = 0;
		pp->port_flags |= USBSER_FL_RX_STOPPED;
	}

	/*
	 * if character flow control active, transmit a start or stop char,
	 */
	if (pp->port_ttycommon.t_iflag & IXOFF) {
		if ((mp = allocb(1, BPRI_LO)) == NULL) {
			USB_DPRINTF_L2(DPRINT_WQ, pp->port_lh,
			    "usbser_inbound_flow_ctl: allocb failed");
		} else {
			*mp->b_wptr++ = c;
			pp->port_flags |= USBSER_ACT_TX;
		}
	}

	mutex_exit(&pp->port_mutex);
	if (need_hw) {
		(void) USBSER_DS_SET_MODEM_CTL(pp, TIOCM_RTS, rts);
	}
	if (mp) {
		(void) USBSER_DS_TX(pp, mp);
	}
	mutex_enter(&pp->port_mutex);
}


/*
 * misc
 * ----
 *
 *
 * returns != 0 if device is online, 0 otherwise
 */
static int
usbser_dev_is_online(usbser_state_t *usp)
{
	int	rval;

	mutex_enter(&usp->us_mutex);
	rval = (usp->us_dev_state == USB_DEV_ONLINE);
	mutex_exit(&usp->us_mutex);

	return (rval);
}

/*
 * serialize port activities defined by 'act' mask
 */
static void
usbser_serialize_port_act(usbser_port_t *pp, int act)
{
	while (pp->port_act & act)
		cv_wait(&pp->port_act_cv, &pp->port_mutex);
	pp->port_act |= act;
}


/*
 * indicate that port activity is finished
 */
static void
usbser_release_port_act(usbser_port_t *pp, int act)
{
	pp->port_act &= ~act;
	cv_broadcast(&pp->port_act_cv);
}

#ifdef DEBUG
/*
 * message type to string and back conversion.
 *
 * pardon breaks on the same line, but as long as cstyle doesn't
 * complain, I'd like to keep this form for trivial cases like this.
 * associative arrays in the kernel, anyone?
 */
static char *
usbser_msgtype2str(int type)
{
	char	*str;

	switch (type) {
	case M_STOP:	str = "M_STOP";		break;
	case M_START:	str = "M_START";	break;
	case M_STOPI:	str = "M_STOPI";	break;
	case M_STARTI:	str = "M_STARTI";	break;
	case M_DATA:	str = "M_DATA";		break;
	case M_DELAY:	str = "M_DELAY";	break;
	case M_BREAK:	str = "M_BREAK";	break;
	case M_IOCTL:	str = "M_IOCTL";	break;
	case M_IOCDATA:	str = "M_IOCDATA";	break;
	case M_FLUSH:	str = "M_FLUSH";	break;
	case M_CTL:	str = "M_CTL";		break;
	case M_READ:	str = "M_READ";		break;
	default:	str = "unknown";	break;
	}

	return (str);
}

static char *
usbser_ioctl2str(int ioctl)
{
	char	*str;

	switch (ioctl) {
	case TCGETA:	str = "TCGETA";		break;
	case TCSETA:	str = "TCSETA";		break;
	case TCSETAF:	str = "TCSETAF";	break;
	case TCSETAW:	str = "TCSETAW";	break;
	case TCSBRK:	str = "TCSBRK";		break;
	case TCXONC:	str = "TCXONC";		break;
	case TCFLSH:	str = "TCFLSH";		break;
	case TCGETS:	str = "TCGETS";		break;
	case TCSETS:	str = "TCSETS";		break;
	case TCSETSF:	str = "TCSETSF";	break;
	case TCSETSW:	str = "TCSETSW";	break;
	case TIOCSBRK:	str = "TIOCSBRK";	break;
	case TIOCCBRK:	str = "TIOCCBRK";	break;
	case TIOCMSET:	str = "TIOCMSET";	break;
	case TIOCMBIS:	str = "TIOCMBIS";	break;
	case TIOCMBIC:	str = "TIOCMBIC";	break;
	case TIOCMGET:	str = "TIOCMGET";	break;
	case TIOCSILOOP: str = "TIOCSILOOP";	break;
	case TIOCCILOOP: str = "TIOCCILOOP";	break;
	case TCGETX:	str = "TCGETX";		break;
	case TCSETX:	str = "TCGETX";		break;
	case TCSETXW:	str = "TCGETX";		break;
	case TCSETXF:	str = "TCGETX";		break;
	default:	str = "unknown";	break;
	}

	return (str);
}
#endif
/*
 * Polled IO support
 */

/* called once	by consconfig() when polledio is opened */
static int
usbser_polledio_init(usbser_port_t *pp)
{
	int err;
	usb_pipe_handle_t hdl;
	ds_ops_t *ds_ops = pp->port_ds_ops;

	/* only one serial line console supported */
	if (console_input != NULL)
		return (USB_FAILURE);

	/* check if underlying driver supports polled io */
	if (ds_ops->ds_version < DS_OPS_VERSION_V1 ||
	    ds_ops->ds_out_pipe == NULL || ds_ops->ds_in_pipe == NULL)
		return (USB_FAILURE);

	/* init polled input pipe */
	hdl = ds_ops->ds_in_pipe(pp->port_ds_hdl, pp->port_num);
	err = usb_console_input_init(pp->port_usp->us_dip, hdl,
	    &console_input_buf, &console_input);
	if (err)
		return (USB_FAILURE);

	/* init polled output pipe */
	hdl = ds_ops->ds_out_pipe(pp->port_ds_hdl, pp->port_num);
	err = usb_console_output_init(pp->port_usp->us_dip, hdl,
	    &console_output);
	if (err) {
		(void) usb_console_input_fini(console_input);
		console_input = NULL;
		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}

/* called once	by consconfig() when polledio is closed */
/*ARGSUSED*/
static void usbser_polledio_fini(usbser_port_t *pp)
{
	/* Since we can't move the console, there is nothing to do. */
}

/*ARGSUSED*/
static void
usbser_polledio_enter(cons_polledio_arg_t arg)
{
	(void) usb_console_input_enter(console_input);
	(void) usb_console_output_enter(console_output);
}

/*ARGSUSED*/
static void
usbser_polledio_exit(cons_polledio_arg_t arg)
{
	(void) usb_console_output_exit(console_output);
	(void) usb_console_input_exit(console_input);
}

/*ARGSUSED*/
static void
usbser_putchar(cons_polledio_arg_t arg, uchar_t c)
{
	static uchar_t cr[2] = {'\r', '\n'};
	uint_t nout;

	if (c == '\n')
		(void) usb_console_write(console_output, cr, 2, &nout);
	else
		(void) usb_console_write(console_output, &c, 1, &nout);
}

/*ARGSUSED*/
static int
usbser_getchar(cons_polledio_arg_t arg)
{
	while (!usbser_ischar(arg))
		;

	return (*console_input_start++);
}

/*ARGSUSED*/
static boolean_t
usbser_ischar(cons_polledio_arg_t arg)
{
	uint_t num_bytes;

	if (console_input_start < console_input_end)
		return (B_TRUE);

	if (usb_console_read(console_input, &num_bytes) != USB_SUCCESS)
		return (B_FALSE);

	console_input_start = console_input_buf;
	console_input_end = console_input_buf + num_bytes;

	return (num_bytes != 0);
}
