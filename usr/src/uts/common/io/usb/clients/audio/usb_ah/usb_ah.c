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
 * USB audio hid streams module - processes hid data
 * from HID driver and converts to a format that usb_ac
 * understands. The stack looks like this :
 *	hid --> usb_ah --> usb_ac --> audio framework
 * usb_ac just acts as a passthrough layer for the converted data.
 *
 * During open, usb_ah gets the parser handle from hid and gets the
 * hardware information passed as report descriptor. Then it finds out
 * the relevant usages and stores the bitmap and other information in
 * internal data structure. When a button is pressed to. say,
 * increase/decrease the volume, a report is generated and hid sends
 * that data up through the streams. usb_ah, upon getting this
 * information and with the prior knowledge about the bitmap for each
 * button, calculates the value and sends up to usb_ac.  usb_ac in
 * turn sends a command down to speaker to increase the volume of the
 * speaker that is managed by usb_ac.
 */
#include <sys/usb/usba.h>
#include <sys/usb/clients/hid/hid.h>
#include <sys/usb/clients/hidparser/hidparser.h>
#include <sys/stropts.h>
#include <sys/strsun.h>


#include <sys/usb/clients/audio/usb_audio.h>
#include <sys/usb/clients/audio/usb_mixer.h>
#include <sys/usb/clients/audio/usb_ah/usb_ah.h>

/* debugging information */
uint_t			usb_ah_errmask = (uint_t)PRINT_MASK_ALL;
uint_t			usb_ah_errlevel = USB_LOG_L4;
static usb_log_handle_t	usb_ah_log_handle;

/*
 * Internal Function Prototypes
 */
static void	usb_ah_mctl_receive(queue_t *, mblk_t *);
static mblk_t	*usb_ah_cp_mblk(mblk_t *);
static void	usb_ah_timeout(void *);
static void	usb_ah_repeat_send(usb_ah_state_t *, usb_ah_button_descr_t *,
			struct iocblk, char *, int);
static void	usb_ah_cancel_timeout(usb_ah_state_t *);
static void	usb_ah_check_usage_send_data(usb_ah_state_t *, mblk_t *);
static int	usb_ah_get_cooked_rd(usb_ah_state_t *);
static mblk_t	*usb_ah_mk_mctl(struct iocblk, void *, size_t);

/* stream qinit functions defined here */
static int	usb_ah_open(queue_t *, dev_t *, int, int, cred_t *);
static int	usb_ah_close(queue_t *, int, cred_t *);
static int	usb_ah_rput(queue_t *, mblk_t *);
static int	usb_ah_wput(queue_t *, mblk_t *);

/*
 * Global Variables
 */
int usb_ah_rpt_tick;

static struct streamtab usb_ah_info;
static struct fmodsw fsw = {
	"usb_ah",
	&usb_ah_info,
	D_NEW | D_MP | D_MTPERMOD
};

/*
 * Module linkage information for the kernel.
 */
extern struct mod_ops mod_strmodops;

static struct modlstrmod modlstrmod = {
	&mod_strmodops,
	"USB audio hid streams",
	&fsw
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modlstrmod,
	NULL
};

/*
 * Warlock is not aware of the automatic locking mechanisms for
 * streams modules.
 * Since warlock is not aware of the streams perimeters, these notes
 * have been added.
 */
_NOTE(SCHEME_PROTECTS_DATA("unique per call", iocblk))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", datab))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", msgb))
_NOTE(SCHEME_PROTECTS_DATA("unique per call", queue))

/*
 * Module qinit functions
 */
static struct module_info usb_ah_minfo = {
	0,		/* module id number */
	"usb_ah",	/* module name */
	0,		/* min packet size accepted */
	INFPSZ,		/* max packet size accepted */
	2048,		/* hi-water mark */
	128		/* lo-water mark */
	};

/* read side for key data and ioctl replies */
static struct qinit usb_ah_rinit = {
	usb_ah_rput,
	NULL,		/* service not used */
	usb_ah_open,
	usb_ah_close,
	NULL,
	&usb_ah_minfo
	};

/* write side -- just pass everything down */
static struct qinit usb_ah_winit = {
	usb_ah_wput,
	NULL,
	usb_ah_open,
	usb_ah_close,
	NULL,
	&usb_ah_minfo
	};

static struct streamtab usb_ah_info = {
	&usb_ah_rinit,
	&usb_ah_winit,
	NULL,		/* for muxes */
	NULL,		/* for muxes */
};


int
_init()
{
	int rval = mod_install(&modlinkage);

	if (rval == 0) {
		usb_ah_rpt_tick = drv_usectohz(USB_AH_TIMEOUT);
		usb_ah_log_handle = usb_alloc_log_hdl(NULL, "usb_ah",
		    &usb_ah_errlevel, &usb_ah_errmask, NULL, 0);
	}

	return (rval);
}


int
_fini()
{
	int rval = mod_remove(&modlinkage);

	if (rval == 0) {
		usb_free_log_hdl(usb_ah_log_handle);
	}

	return (rval);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}


/*
 * usb_ah_open :
 *	Open a usb audio hid device
 */
/* ARGSUSED */
static int
usb_ah_open(queue_t *q, dev_t *devp, int oflag, int sflag, cred_t *crp)
{
	usb_ah_state_t	*usb_ahd;
	hidparser_packet_info_t hpack;
	struct iocblk	mctlmsg;
	mblk_t		*mctl_ptr;

	if (q->q_ptr) {
		USB_DPRINTF_L3(PRINT_MASK_OPEN, usb_ah_log_handle,
		    "usb_ah_open already opened");

		return (0); /* already opened */
	}

	if (sflag != MODOPEN) {
		/* Only module open supported */
		return (EINVAL);
	}

	usb_ahd = kmem_zalloc(sizeof (usb_ah_state_t), KM_SLEEP);

	USB_DPRINTF_L3(PRINT_MASK_OPEN, usb_ah_log_handle,
	    "usb_ah_state= 0x%p", (void *)usb_ahd);

	mutex_init(&usb_ahd->usb_ah_mutex, NULL, MUTEX_DRIVER, NULL);

	/*
	 * Set up private data.
	 */
	usb_ahd->usb_ah_readq = q;
	usb_ahd->usb_ah_writeq = WR(q);

	/*
	 * Set up queue pointers, so that the "put" procedure will accept
	 * the reply to the "ioctl" message we send down.
	 */
	q->q_ptr = (caddr_t)usb_ahd;
	WR(q)->q_ptr = (caddr_t)usb_ahd;

	qprocson(q);

	/* request hid report descriptor from HID */
	mctlmsg.ioc_cmd = HID_GET_PARSER_HANDLE;
	mctlmsg.ioc_count = 0;
	mctl_ptr = usba_mk_mctl(mctlmsg, NULL, 0);
	if (mctl_ptr == NULL) {
		/* failure to allocate M_CTL message */
		qprocsoff(q);
		mutex_destroy(&usb_ahd->usb_ah_mutex);
		kmem_free(usb_ahd, sizeof (*usb_ahd));

		return (ENOMEM);
	}

	putnext(usb_ahd->usb_ah_writeq, mctl_ptr);

	/*
	 * Now that signal has been sent, wait for report descriptor.
	 * Cleanup  if user signals in the mean time
	 */
	usb_ahd->usb_ah_flags |= USB_AH_QWAIT;
	while (usb_ahd->usb_ah_flags & USB_AH_QWAIT) {

		if (qwait_sig(q) == 0) {
			usb_ahd->usb_ah_flags = 0;
			qprocsoff(q);
			mutex_destroy(&usb_ahd->usb_ah_mutex);
			kmem_free(usb_ahd, sizeof (*usb_ahd));

			return (EINTR);
		}
	}

	if (usb_ahd->usb_ah_report_descr != NULL) {
		hidparser_find_max_packet_size_from_report_descriptor(
		    usb_ahd->usb_ah_report_descr, &hpack);

		/* round up to the nearest byte */
		usb_ahd->usb_ah_packet_size = (hpack.max_packet_size + 7) / 8;

		if (hpack.report_id == HID_REPORT_ID_UNDEFINED) {
			usb_ahd->usb_ah_uses_report_ids = 0;
			usb_ahd->usb_ah_report_id = HID_REPORT_ID_UNDEFINED;
		} else {
			usb_ahd->usb_ah_uses_report_ids = 1;
			usb_ahd->usb_ah_report_id = hpack.report_id;
			/* add more more byte for report id */
			usb_ahd->usb_ah_packet_size++;
		}

		if (usb_ah_get_cooked_rd(usb_ahd) != USB_SUCCESS) {
			qprocsoff(q);
			mutex_destroy(&usb_ahd->usb_ah_mutex);
			kmem_free(usb_ahd, sizeof (*usb_ahd));

			return (EIO);
		}
	} else {
		USB_DPRINTF_L2(PRINT_MASK_OPEN, usb_ah_log_handle,
		    "usb_ah: Invalid Report Descriptor Tree.");

		qprocsoff(q);
		mutex_destroy(&usb_ahd->usb_ah_mutex);
		kmem_free(usb_ahd, sizeof (*usb_ahd));

		return (EIO);
	}

	usb_ahd->usb_ah_flags |= USB_AH_OPEN;

	return (0);
}


/*
 * usb_ah_close :
 *	Close a audio hid device
 */
/* ARGSUSED1 */
static int
usb_ah_close(queue_t *q, int flag, cred_t *crp)
{
	usb_ah_state_t *usb_ahd = (usb_ah_state_t *)q->q_ptr;

	mutex_enter(&usb_ahd->usb_ah_mutex);

	/*
	 * Since we're about to destroy our private data, turn off
	 * our open flag first, so we don't accept any more input
	 * and try to use that data.
	 */
	usb_ahd->usb_ah_flags = 0;
	usb_ah_cancel_timeout(usb_ahd);

	flushq(q, FLUSHALL);
	flushq(WR(q), FLUSHALL);

	mutex_exit(&usb_ahd->usb_ah_mutex);

	qprocsoff(q);
	q->q_ptr = NULL;
	WR(q)->q_ptr = NULL;

	mutex_destroy(&usb_ahd->usb_ah_mutex);
	kmem_free(usb_ahd, sizeof (usb_ah_state_t));

	return (0);
}

static int
usb_ah_wput(queue_t *q, mblk_t *mp)
{
	putnext(q, mp);
	return (0);
}

/*
 * usb_ah_rput :
 *	Put procedure for input from driver end of stream (read queue).
 */
static int
usb_ah_rput(queue_t *q, mblk_t *mp)
{
	usb_ah_state_t		*usb_ahd;

	usb_ahd = (usb_ah_state_t *)q->q_ptr;

	if (usb_ahd == 0) {
		freemsg(mp);	/* nobody's listening */

		return (0);
	}

	switch (mp->b_datap->db_type) {

	case M_DATA:
		if (!(usb_ahd->usb_ah_flags & USB_AH_OPEN)) {
			freemsg(mp);	/* not ready to listen */

		} else if (MBLKL(mp) == usb_ahd->usb_ah_packet_size) {

			/*
			 * Process this report if the device doesn't have
			 * multiple reports, or this is the one we support
			 */
			if ((usb_ahd->usb_ah_report_id ==
			    HID_REPORT_ID_UNDEFINED) ||
			    (usb_ahd->usb_ah_report_id == (int)*mp->b_rptr)) {
				/* we now have a complete packet */
				usb_ah_check_usage_send_data(usb_ahd, mp);
			} else {
				USB_DPRINTF_L2(PRINT_MASK_ALL,
				    usb_ah_log_handle,
				    "usb_ah_rput: skipping report with "
				    "id= %d", *mp->b_rptr);

				/* skip the reports we don't support */
				freemsg(mp);
			}
		} else {
			/* filter out spurious packets */
			freemsg(mp);
		}

		break;

	case M_CTL:
		usb_ah_mctl_receive(q, mp);
		break;

	case M_FLUSH:
	case M_IOCACK:
	case M_IOCNAK:
		putnext(q, mp);
		break;

	default:
		putnext(q, mp);
		break;
	}

	return (0);
}


/*
 * usb_ah_mctl_receive :
 *	Handle M_CTL messages from hid. If we don't understand
 *	the command, send it up.
 */
static void
usb_ah_mctl_receive(queue_t *q, mblk_t *mp)
{
	usb_ah_state_t *usb_ahd = (usb_ah_state_t *)q->q_ptr;
	struct iocblk *iocp;
	caddr_t  data;

	iocp = (struct iocblk *)mp->b_rptr;
	if (mp->b_cont != NULL)
		data = (caddr_t)mp->b_cont->b_rptr;

	switch (iocp->ioc_cmd) {
	case HID_GET_PARSER_HANDLE:
		USB_DPRINTF_L3(PRINT_MASK_ALL, usb_ah_log_handle,
		    "usb_ah_mctl_receive HID_GET_PARSER_HANDL mctl");
		if ((data != NULL) &&
		    (iocp->ioc_count == sizeof (hidparser_handle_t)) &&
		    (MBLKL(mp->b_cont) == iocp->ioc_count)) {
			usb_ahd->usb_ah_report_descr =
			    *(hidparser_handle_t *)data;
		} else {
			usb_ahd->usb_ah_report_descr = NULL;
		}
		freemsg(mp);
		usb_ahd->usb_ah_flags &= ~USB_AH_QWAIT;

		break;
	case HID_DISCONNECT_EVENT :
	case HID_POWER_OFF:
		USB_DPRINTF_L3(PRINT_MASK_ALL, usb_ah_log_handle,
		    "usb_ah_mctl_receive HID_DISCONNECT_EVENT/HID_POWER_OFF");

		/* Cancel any auto repeat keys */
		usb_ah_cancel_timeout(usb_ahd);

		freemsg(mp);

		break;
	case HID_CONNECT_EVENT:
	case HID_FULL_POWER:
		USB_DPRINTF_L3(PRINT_MASK_ALL, usb_ah_log_handle,
		    "usb_ah_mctl_receive HID_CONNECT_EVENT/HID_FULL_POWER");
		freemsg(mp);

		break;
	default:
		putnext(q, mp);
	}
}


/*
 * usb_ah_repeat_send
 *	This function sends a M_CTL message to usb_ac repeatedly
 */
static void
usb_ah_repeat_send(usb_ah_state_t *usb_ahd, usb_ah_button_descr_t *bd,
    struct iocblk mctlmsg, char *buf, int len)
{
	mblk_t	*dup_mp;

	bd->mblk = usb_ah_mk_mctl(mctlmsg, buf, len);

	if (bd->mblk != NULL) {
		dup_mp = usb_ah_cp_mblk(bd->mblk);

		if (dup_mp != NULL) {
			mutex_exit(&usb_ahd->usb_ah_mutex);
			putnext(usb_ahd->usb_ah_readq, dup_mp);
			mutex_enter(&usb_ahd->usb_ah_mutex);
		}

		usb_ahd->usb_ah_cur_bd = bd;
		usb_ahd->usb_ah_tid = qtimeout(usb_ahd->usb_ah_readq,
		    usb_ah_timeout, bd, usb_ah_rpt_tick);
	}
}


/*
 * usb_ah_timeout:
 *	Timeout routine to handle autorepeat of buttons
 */
static void
usb_ah_timeout(void *addr)
{
	usb_ah_button_descr_t *bd;
	usb_ah_state_t	*usb_ahd;
	mblk_t		*dup_mp;

	bd = (usb_ah_button_descr_t *)addr;
	usb_ahd = (usb_ah_state_t *)bd->uahp;

	mutex_enter(&usb_ahd->usb_ah_mutex);

	/*
	 * If a release event still hasn't reached, tid will be non-zero
	 * Send another press event up
	 */
	if (usb_ahd->usb_ah_tid) {
		dup_mp = usb_ah_cp_mblk(bd->mblk);
		if (dup_mp != NULL) {
			mutex_exit(&usb_ahd->usb_ah_mutex);
			putnext(usb_ahd->usb_ah_readq, dup_mp);
			mutex_enter(&usb_ahd->usb_ah_mutex);
		}
		if (bd->mblk != NULL) {
			usb_ahd->usb_ah_cur_bd = bd;
			usb_ahd->usb_ah_tid = qtimeout(usb_ahd->usb_ah_readq,
			    usb_ah_timeout, bd, usb_ah_rpt_tick);
		}
	}
	mutex_exit(&usb_ahd->usb_ah_mutex);
}


/*
 * usb_ah_cancel_timeout:
 *	Cancels the timeout for autorepeat sequence
 */
static void
usb_ah_cancel_timeout(usb_ah_state_t *usb_ahd)
{
	queue_t	*rq = usb_ahd->usb_ah_readq;

	if (usb_ahd->usb_ah_tid) {
		(void) quntimeout(rq, usb_ahd->usb_ah_tid);
		usb_ahd->usb_ah_tid = 0;
		usb_ahd->usb_ah_cur_bd->pressed = 0;
		freemsg(usb_ahd->usb_ah_cur_bd->mblk);
		usb_ahd->usb_ah_cur_bd = NULL;
	}
}


/*
 * usb_ah_cp_mblk
 *	Create an identical 2-mblk as the one passed through argument
 */
static mblk_t *
usb_ah_cp_mblk(mblk_t *mp)
{
	mblk_t *bp1, *bp2;
	int len;
	struct iocblk	*iocp;

	if ((bp1 = allocb((int)sizeof (struct iocblk), BPRI_HI)) == NULL) {
		USB_DPRINTF_L4(PRINT_MASK_ALL, usb_ah_log_handle,
		    "usb_ah_cp_mblk: 1st allocb failed");

		return (NULL);
	}

	iocp = (struct iocblk *)mp->b_rptr;
	bcopy(iocp, (struct iocblk *)bp1->b_datap->db_base,
	    sizeof (struct iocblk));

	bp1->b_datap->db_type = M_PROTO;
	bp1->b_wptr += sizeof (struct iocblk);

	ASSERT(mp->b_cont != NULL);
	len = MBLKL(mp->b_cont);

	if (mp->b_cont->b_datap->db_base) {
		if ((bp2 = allocb(len, BPRI_HI)) == NULL) {
			USB_DPRINTF_L4(PRINT_MASK_ALL, usb_ah_log_handle,
			    "usb_ah_cp_mblk: 2nd allocb failed");
			freemsg(bp1);

			return (NULL);
		}
		bp1->b_cont = bp2;
		bcopy(mp->b_cont->b_datap->db_base, bp2->b_datap->db_base, len);
		bp2->b_wptr += len;
	}

	return (bp1);
}


/*
 * usb_ah_get_cooked_rd:
 *	Cook the report descriptor by making hidparser calls and
 *	put them in a library
 */
static int
usb_ah_get_cooked_rd(usb_ah_state_t *usb_ahd)
{
	uint_t		location;
	uint_t		offset, i;
	usb_ah_button_descr_t	*bd;
	hidparser_usage_info_t	*ud;
	usb_ah_rpt_t	*rpt;
	hidparser_rpt_t	*hid_rpt;

	rpt = &(usb_ahd->usb_ah_report[USB_AH_INPUT_RPT]);
	hid_rpt = &(usb_ahd->usb_ah_report[USB_AH_INPUT_RPT].hid_rpt);

	if (hidparser_get_usage_list_in_order(
	    usb_ahd->usb_ah_report_descr,
	    usb_ahd->usb_ah_report_id,
	    HIDPARSER_ITEM_INPUT,
	    hid_rpt) == HIDPARSER_FAILURE) {
		USB_DPRINTF_L3(PRINT_MASK_OPEN,
		    usb_ah_log_handle, "getting usage list in order failed");

		return (USB_FAILURE);
	}

	USB_DPRINTF_L4(PRINT_MASK_OPEN, usb_ah_log_handle,
	    "usb_ah_open:no. of usages=%d", hid_rpt->no_of_usages);

	location = offset = 0;
	for (i = 0; i < hid_rpt->no_of_usages; i++) {
		USB_DPRINTF_L4(PRINT_MASK_OPEN,
		    usb_ah_log_handle, "collection=0x%x, usage=0x%x/0x%x",
		    hid_rpt->usage_descr[i].collection_usage,
		    hid_rpt->usage_descr[i].usage_page,
		    hid_rpt->usage_descr[i].usage_id);
		ud = &(hid_rpt->usage_descr[i]);
		bd = &(rpt->button_descr[i]);

		/* Initialize the variables */
		hid_rpt->main_item_value = 0;

		/* get input items for each usages */
		(void) hidparser_get_main_item_data_descr(
		    usb_ahd->usb_ah_report_descr,
		    usb_ahd->usb_ah_report_id,
		    HIDPARSER_ITEM_INPUT,
		    hid_rpt->usage_descr[i].usage_page,
		    hid_rpt->usage_descr[i].usage_id,
		    &hid_rpt->main_item_value);

		bd->location = location;
		bd->offset = offset;
		bd->no_of_bits = ud->rptsz;

		USB_DPRINTF_L4(PRINT_MASK_ALL, usb_ah_log_handle,
		    "byte location %d, bit offset %d", bd->location,
		    bd->offset);
		offset += ud->rptsz;
		while (offset >= 8) {
			location++;
			offset -= 8;
		}

	}

	return (USB_SUCCESS);
}


/*
 * usb_ah_check_usage_send_data:
 *	Check if a button is pressed, if so, send the appropriate
 *	message	up
 */
static void
usb_ah_check_usage_send_data(usb_ah_state_t *usb_ahd, mblk_t *mp)
{
	int			i, mask;
	char			val;
	hidparser_rpt_t		*hid_rpt;
	usb_ah_button_descr_t	*bd;
	usb_ah_rpt_t		*rpt;
	uchar_t			*ptr;
	struct iocblk		mctlmsg;
	mblk_t			*mctl_ptr;

	mutex_enter(&usb_ahd->usb_ah_mutex);
	rpt = &(usb_ahd->usb_ah_report[USB_AH_INPUT_RPT]);
	hid_rpt = &(usb_ahd->usb_ah_report[USB_AH_INPUT_RPT].hid_rpt);

	for (i = 0; i < hid_rpt->no_of_usages; i++) {

		bd = &(rpt->button_descr[i]);
		bd->uahp = (void *)usb_ahd;

		USB_DPRINTF_L4(PRINT_MASK_ALL,
		    usb_ah_log_handle, "usb_ah_check_usage_send_data:"
		    "uses_report_id=%d, location=%d, offset=%d, "
		    "no_of_bits=%d", usb_ahd->usb_ah_uses_report_ids,
		    bd->location, bd->offset, bd->no_of_bits);

		ptr = mp->b_rptr + bd->location;

		/* XXX workaround */
		if (ptr > mp->b_wptr) {
			USB_DPRINTF_L2(PRINT_MASK_ALL,
			    usb_ah_log_handle, "usb_ah_check_usage_send_data:"
			    "bad report: location=%d", bd->location);

			continue;
		}

		ASSERT(ptr <= mp->b_wptr);

		mask = ((1 << bd->no_of_bits) - 1);
		val = (char)((*ptr >> bd->offset) & mask);

		USB_DPRINTF_L4(PRINT_MASK_ALL,
		    usb_ah_log_handle, "usb_ah_check_usage_send_data:"
		    "usage=0x%x, "
		    "mask=0x%x, val=0x%x", hid_rpt->usage_descr[i].usage_id,
		    mask, val);

		if (hid_rpt->usage_descr[i].collection_usage !=
		    HID_CONSUMER_CONTROL) {
			/*
			 * skip item in unknown collections, for now.
			 * this includes the volume and mute controls
			 * in the microphone collection on plantronics
			 * dsp-300 device with 3.xx firmware.
			 */
			continue;
		}

		switch (hid_rpt->usage_descr[i].usage_id) {
		case HID_CONSUMER_VOL:	/* LC */
			if (val != 0) {
				if (hid_rpt->main_item_value &
				    HID_MAIN_ITEM_RELATIVE) {
					/* Relative volume */
					mctlmsg.ioc_cmd = USB_AUDIO_VOL_CHANGE;
					mctlmsg.ioc_count = sizeof (uint_t);
					mctl_ptr = usb_ah_mk_mctl(mctlmsg,
					    &val, mctlmsg.ioc_count);
					if (mctl_ptr != NULL) {
						mutex_exit(&usb_ahd->
						    usb_ah_mutex);
						putnext(usb_ahd->usb_ah_readq,
						    mctl_ptr);
						mutex_enter(&usb_ahd->
						    usb_ah_mutex);
					}
				} else {
					USB_DPRINTF_L2(PRINT_MASK_ALL,
					    usb_ah_log_handle, "usb_ah_rput:"
					    "Absolute volume change "
					    "not supported");
				}
			}

			break;
		case HID_CONSUMER_VOL_DECR: /* RTC */
			if (val != 0) {
				val = -val;
			}
			/* FALLTHRU */
		case HID_CONSUMER_VOL_INCR:  /* RTC */
			if (val != 0) {

				/*
				 * If another autorepeating button has been
				 * pressed, cancel that one first
				 */
				usb_ah_cancel_timeout(usb_ahd);
				mctlmsg.ioc_cmd = USB_AUDIO_VOL_CHANGE;
				mctlmsg.ioc_count = sizeof (uint_t);
				bd->pressed = 1;
				usb_ah_repeat_send(usb_ahd, bd,
				    mctlmsg, (char *)&val, mctlmsg.ioc_count);
			} else {
				/* Do not steal other's release event */
				if (bd->pressed) {
					usb_ah_cancel_timeout(usb_ahd);
				}
			}

			break;
		case HID_CONSUMER_MUTE:	/* OOC */
			if (val) {
				mctlmsg.ioc_cmd = USB_AUDIO_MUTE;
				mctlmsg.ioc_count = sizeof (uint_t);
				mctl_ptr = usb_ah_mk_mctl(mctlmsg,
				    &val, mctlmsg.ioc_count);
				if (mctl_ptr != NULL) {
					mutex_exit(&usb_ahd->usb_ah_mutex);
					putnext(usb_ahd->usb_ah_readq,
					    mctl_ptr);
					mutex_enter(&usb_ahd->usb_ah_mutex);
				}

			}

			break;
		case HID_CONSUMER_BASS:
		case HID_CONSUMER_TREBLE:
		default:

			break;
		}
	}
	mutex_exit(&usb_ahd->usb_ah_mutex);
	freemsg(mp);
}


/*
 * since usb_ac now uses LDI to access HID streams, we must change the msg
 * type from M_CTL to M_PROTO since the streamhead will not pass M_CTLs up
 */
static mblk_t *
usb_ah_mk_mctl(struct iocblk mctlmsg, void *buf, size_t len)
{
	mblk_t *mp;

	mp = usba_mk_mctl(mctlmsg, buf, len);
	if (mp == NULL)
		return (NULL);

	mp->b_datap->db_type = M_PROTO;
	return (mp);
}
