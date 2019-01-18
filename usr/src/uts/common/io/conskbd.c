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
 * Console kbd multiplexor driver for Sun.
 * The console "zs" port is linked under us, with the "kbd" module pushed
 * on top of it.
 * Minor device 0 is what programs normally use.
 * Minor device 1 is used to feed predigested keystrokes to the "workstation
 * console" driver, which it is linked beneath.
 *
 *
 *     This module can support multiple keyboards to be used simultaneously.
 * and enable users to use at a time multiple keyboards connected to the
 * same system. All the keyboards are linked under conskbd, and act as a
 * keyboard with replicated keys.
 *
 *     The DIN keyboards of SUN, for exmple , type 3/4/5,  are supported via
 * a two-level architecure. The lower one is one of serialport drivers, such
 * as zs, se, and the upper is  "kb" STREAMS module. Currenly, the serialport
 * drivers don't support polled I/O interfaces, we couldn't group the keyboard
 * of this kind under conskbd. So we do as the follows:
 *
 *         A new ioctl CONSSETKBDTYPE interface between conskbd and lower
 *     keyboard drivers is added. When conskbd receives I_LINK or I_PLINK
 *     ioctl, it will send a CONSSETKBDTYPE ioctl to the driver which is
 *     requesting to be linked under conskbd. If the lower driver does't
 *     recognize this ioctl, the virtual keyboard will be disabled so that
 *     only one keyboard instance could be linked under conskbd.
 */
#define	KEYMAP_SIZE_VARIABLE

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/kbio.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/consdev.h>
#include <sys/note.h>
#include <sys/kmem.h>
#include <sys/kstat.h>
#include <sys/policy.h>
#include <sys/kbd.h>
#include <sys/kbtrans.h>
#include <sys/promif.h>
#include <sys/vuid_event.h>
#include <sys/conskbd.h>
#include <sys/beep.h>

extern struct keyboard *kbtrans_usbkb_maptab_init(void);
extern void kbtrans_usbkb_maptab_fini(struct keyboard **);
extern int ddi_create_internal_pathname(dev_info_t *, char *, int, minor_t);

/*
 * Module linkage routines for the kernel
 */
static int conskbd_attach(dev_info_t *, ddi_attach_cmd_t);
static int conskbd_detach(dev_info_t *, ddi_detach_cmd_t);
static int conskbd_info(dev_info_t *, ddi_info_cmd_t, void *, void **);

/*
 * STREAMS queue processing procedures
 */
static int	conskbduwsrv(queue_t *);
static int	conskbdlwserv(queue_t *);
static int	conskbdlrput(queue_t *, mblk_t *);
static int	conskbdclose(queue_t *, int, cred_t *);
static int	conskbdopen(queue_t *, dev_t *, int, int, cred_t *);


/* STREAMS driver id and limit value struct */
static struct module_info conskbdm_info = {
	0,		/* mi_idnum */
	"conskbd",	/* mi_idname */
	0,		/* mi_minpsz */
	1024,		/* mi_maxpsz */
	2048,		/* mi_hiwat */
	128		/* mi_lowat */
};

/*
 * STREAMS queue processing procedure structures
 */
/* upper read queue processing procedure structures */
static struct qinit conskbdurinit = {
	NULL,			/* qi_putp */
	(int (*)())NULL,	/* qi_srvp */
	conskbdopen,		/* qi_qopen */
	conskbdclose,		/* qi_qclose */
	(int (*)())NULL,	/* qi_qadmin */
	&conskbdm_info,		/* qi_minfo */
	NULL			/* qi_mstat */
};

/* upper write queue processing procedures structuresi */
static struct qinit conskbduwinit = {
	putq,		/* qi_putp */
	conskbduwsrv,	/* qi_srvp */
	conskbdopen,			/* qi_qopen */
	conskbdclose,			/* qi_qclose */
	(int (*)())NULL,		/* qi_qadmin */
	&conskbdm_info,			/* qi_minfo */
	NULL				/* qi_mstat */
};

/* lower read queue processing procedures structures */
static struct qinit conskbdlrinit = {
	conskbdlrput,	/* qi_putp */
	(int (*)())NULL,		/* qi_srvp */
	(int (*)())NULL,		/* qi_qopen */
	(int (*)())NULL,		/* qi_qclose */
	(int (*)())NULL,		/* qi_qadmin */
	&conskbdm_info,			/* qi_minfo */
	NULL				/* qi_mstat */
};

/* lower write processing procedures structures */
static struct qinit conskbdlwinit = {
	putq,				/* qi_putp */
	conskbdlwserv,	/* qi_srvp */
	(int (*)())NULL,		/* qi_qopen */
	(int (*)())NULL,		/* qi_qclose */
	(int (*)())NULL,		/* qi_qadmin */
	&conskbdm_info,			/* qi_minfo */
	NULL				/* qi_mstat */
};

/* STREAMS entity declaration structure */
static struct streamtab conskbd_str_info = {
	&conskbdurinit,		/* st_rdinit */
	&conskbduwinit,		/* st_wrinit */
	&conskbdlrinit,		/* st_muxrinit */
	&conskbdlwinit,		/* st_muxwinit */
};


/* Entry points structure */
static struct cb_ops cb_conskbd_ops = {
	nulldev,		/* cb_open */
	nulldev,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	nodev,			/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	&conskbd_str_info,	/* cb_stream */
	D_MP | D_MTOUTPERIM | D_MTOCEXCL	/* cb_flag */
};


/*
 * Device operations structure
 */
static struct dev_ops conskbd_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	conskbd_info,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	conskbd_attach,		/* devo_attach */
	conskbd_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&(cb_conskbd_ops),	/* devo_cb_ops */
	(struct bus_ops *)NULL,	/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,		/* quiesce */
};

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops, /* Type of module.  This one is a pseudo driver */
	"conskbd multiplexer driver",
	&conskbd_ops,	/* driver ops */
};

/*
 * Module linkage structure
 */
static struct modlinkage modlinkage = {
	MODREV_1,	/* ml_rev */
	&modldrv,	/* ml_linkage */
	NULL		/* NULL terminates the list */
};

/*
 * Debug printing
 */
#ifndef DPRINTF
#ifdef DEBUG
void	conskbd_dprintf(const char *fmt, ...);
#define	DPRINTF(l, m, args) \
	(((l) >= conskbd_errlevel) && ((m) & conskbd_errmask) ?	\
		conskbd_dprintf args :				\
		(void) 0)

/*
 * Severity levels for printing
 */
#define	PRINT_L0	0	/* print every message */
#define	PRINT_L1	1	/* debug */
#define	PRINT_L2	2	/* quiet */

/*
 * Masks
 */
#define	PRINT_MASK_ALL		0xFFFFFFFFU
uint_t	conskbd_errmask = PRINT_MASK_ALL;
uint_t	conskbd_errlevel = PRINT_L2;

#else
#define	DPRINTF(l, m, args)	/* NOTHING */
#endif
#endif

/*
 * Module global data are protected by outer perimeter. Modifying
 * these global data is executed in outer perimeter exclusively.
 * Except in conskbdopen() and conskbdclose(), which are entered
 * exclusively (Refer to D_MTOCEXCL flag), all changes for the
 * global variables are protected by qwriter().
 */
static	queue_t	*conskbd_regqueue; /* regular keyboard queue above us */
static	queue_t	*conskbd_consqueue; /* console queue above us */


static dev_info_t *conskbd_dip;		/* private copy of devinfo pointer */
static long	conskbd_idle_stamp;	/* seconds tstamp of latest keystroke */
static struct keyboard *conskbd_keyindex;

/*
 * Normally, kstats of type KSTAT_TYPE_NAMED have multiple elements.  In
 * this case we use this type for a single element because the ioctl code
 * for it knows how to handle mixed kernel/user data models.  Also, it
 * will be easier to add new statistics later.
 */
static struct {
	kstat_named_t idle_sec;		/* seconds since last keystroke */
} conskbd_kstat = {
	{ "idle_sec", KSTAT_DATA_LONG, }
};

/*
 * Local routines prototypes
 */
static int conskbd_kstat_update(kstat_t *, int);

static void conskbd_ioctl(queue_t *, mblk_t *);
static void conskbd_ioc_plink(queue_t *, mblk_t *);
static void conskbd_ioc_punlink(queue_t *, mblk_t *);
static void conskbd_legacy_kbd_ioctl(queue_t *, mblk_t *);
static void conskbd_virtual_kbd_ioctl(queue_t *, mblk_t *);
static mblk_t *conskbd_alloc_firm_event(ushort_t, int);

static conskbd_pending_msg_t *conskbd_mux_find_msg(mblk_t *);
static void conskbd_mux_enqueue_msg(conskbd_pending_msg_t *);
static void conskbd_mux_dequeue_msg(conskbd_pending_msg_t *);
static void conskbd_link_lowque_virt(queue_t *, mblk_t *);
static void conskbd_link_lowque_legacy(queue_t *, mblk_t *);

static void conskbd_handle_downstream_msg(queue_t *, mblk_t *);
static void conskbd_kioctype_complete(conskbd_lower_queue_t *, mblk_t *);
static void conskbd_kioctrans_complete(conskbd_lower_queue_t *, mblk_t *);
static void conskbd_kioclayout_complete(conskbd_lower_queue_t *, mblk_t *);
static void conskbd_kiocsled_complete(conskbd_lower_queue_t *, mblk_t *);
static void conskbd_mux_upstream_msg(conskbd_lower_queue_t *, mblk_t *);
static void conskbd_legacy_upstream_msg(conskbd_lower_queue_t *, mblk_t *);
static void conskbd_lqs_ack_complete(conskbd_lower_queue_t *, mblk_t *);

static void conskbd_polledio_enter(cons_polledio_arg_t);
static void conskbd_polledio_exit(cons_polledio_arg_t);
static int  conskbd_polledio_ischar(cons_polledio_arg_t);
static int  conskbd_polledio_getchar(cons_polledio_arg_t);
static void conskbd_polledio_setled(struct kbtrans_hardware *, int);

static void conskbd_streams_setled(struct kbtrans_hardware *, int);
static boolean_t conskbd_override_kbtrans(queue_t *, mblk_t *);
static boolean_t
conskbd_polled_keycheck(struct kbtrans_hardware *,
    kbtrans_key_t *, enum keystate *);

/*
 * Callbacks needed by kbtrans
 */
static struct kbtrans_callbacks conskbd_callbacks = {
	conskbd_streams_setled,
	conskbd_polledio_setled,
	conskbd_polled_keycheck,
};

/*
 * Single private "global" lock for the few rare conditions
 * we want single-threaded.
 */
static	kmutex_t	conskbd_msgq_lock;
static	conskbd_pending_msg_t	*conskbd_msg_queue;

/*
 * The software state structure of virtual keyboard.
 * Currently, only one virtual keyboard is supported.
 */
static conskbd_state_t	conskbd = { 0 };

/* This variable backs up the layout state for non-self-ID keyboards */
static int kbd_layout_bak = 0;

/*
 * _init()
 *
 * Description:
 *      Driver initialization, called when driver is first loaded.
 *      This is how access is initially given to all the static structures.
 *
 * Arguments:
 *      None
 *
 * Returns:
 *      ddi_soft_state_init() status, see ddi_soft_state_init(9f), or
 *      mod_install() status, see mod_install(9f)
 */
int
_init(void)
{
	int	error;

	error = mod_install(&modlinkage);
	if (error != 0) {
		return (error);
	}

	conskbd_keyindex = kbtrans_usbkb_maptab_init();

	mutex_init(&conskbd_msgq_lock, NULL, MUTEX_DRIVER, NULL);

	return (error);

}	/* _init() */

/*
 * _fini()
 *
 * Description:
 *      Module de-initialization, called when the driver is to be unloaded.
 *
 * Arguments:
 *      None
 *
 * Returns:
 *      mod_remove() status, see mod_remove(9f)
 */
int
_fini(void)
{
	int	error;

	error = mod_remove(&modlinkage);
	if (error != 0)
		return (error);
	mutex_destroy(&conskbd_msgq_lock);
	kbtrans_usbkb_maptab_fini(&conskbd_keyindex);

	return (0);

}	/* _fini() */

/*
 * _info()
 *
 * Description:
 *      Module information, returns information about the driver.
 *
 * Arguments:
 *      modinfo         *modinfop       Pointer to the opaque modinfo structure
 *
 * Returns:
 *      mod_info() status, see mod_info(9f)
 */
int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));

}	/* _info() */


/*
 * conskbd_attach()
 *
 * Description:
 *	This routine creates two device nodes. One is the "kbd" node, which
 * is used by user application programs(such as Xserver).The other is the
 * "conskbd" node, which is an internal node. consconfig_dacf module will
 * open this internal node, and link the conskbd under the wc (workstaion
 * console).
 *
 * Arguments:
 *      dev_info_t      *dip    Pointer to the device's dev_info struct
 *      ddi_attach_cmd_t cmd    Attach command
 *
 * Returns:
 *      DDI_SUCCESS             The driver was initialized properly
 *      DDI_FAILURE             The driver couldn't be initialized properly
 */
/*ARGSUSED*/
static int
conskbd_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	kstat_t	*ksp;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	default:
		return (DDI_FAILURE);

	}
	if ((ddi_create_minor_node(devi, "kbd", S_IFCHR,
	    0, DDI_PSEUDO, 0) == DDI_FAILURE) ||
	    (ddi_create_internal_pathname(devi, "conskbd", S_IFCHR,
	    1) == DDI_FAILURE)) {
		ddi_remove_minor_node(devi, NULL);
		return (DDI_FAILURE);
	}
	conskbd_dip = devi;

	ksp = kstat_create("conskbd", 0, "activity", "misc", KSTAT_TYPE_NAMED,
	    sizeof (conskbd_kstat) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (ksp) {
		ksp->ks_data = (void *) &conskbd_kstat;
		ksp->ks_update = conskbd_kstat_update;
		kstat_install(ksp);
		conskbd_idle_stamp = gethrestime_sec();	/* initial value */
	}

	conskbd.conskbd_layout = -1;	/* invalid layout */
	conskbd.conskbd_led_state = -1;
	conskbd.conskbd_bypassed = B_FALSE;

	return (DDI_SUCCESS);

}	/* conskbd_attach() */

/*
 * conskbd_detach()
 *
 * Description:
 *      Detach an instance of the conskbd driver. In fact, the driver can not
 * be detached.
 *
 * Arguments:
 *      dev_info_t              *dip    Pointer to the device's dev_info struct
 *      ddi_detach_cmd_t        cmd     Detach command
 *
 * Returns:
 *      DDI_SUCCESS     The driver was detached
 *      DDI_FAILURE     The driver couldn't be detached
 */
/*ARGSUSED*/
static int
conskbd_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	return (DDI_FAILURE);

}	/* conskbd_detach() */

/* ARGSUSED */
static int
conskbd_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
    void **result)
{
	register int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (conskbd_dip == NULL) {
			error = DDI_FAILURE;
		} else {
			*result = (void *) conskbd_dip;
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

}	/* conskbd_info() */

/*ARGSUSED*/
static int
conskbdopen(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *crp)
{
	dev_t	unit;
	int	err;

	unit = getminor(*devp);

	if (unit == 0) {
		/*
		 * Opening "/dev/kbd".
		 */
		conskbd_regqueue = q;
		qprocson(q);
		return (0);
	} else if (unit != 1) {
		/* we don't do that under Bozo's Big Tent */
		return (ENODEV);
	}

	/*
	 * Check if already initialized
	 */
	if (conskbd_consqueue != NULL)
		return (0);

	/*
	 * Opening the device to be linked under the console.
	 */
	conskbd_consqueue = q;

	if (secpolicy_console(crp) != 0)
		return (EPERM);

	/*
	 * initialize kbtrans module for conskbd
	 */
	err = kbtrans_streams_init(q, sflag, (struct kbtrans_hardware *)
	    &conskbd, &conskbd_callbacks, &conskbd.conskbd_kbtrans, 0, 0);
	if (err != 0)
		return (err);
	kbtrans_streams_set_keyboard(conskbd.conskbd_kbtrans, KB_USB,
	    conskbd_keyindex);

	conskbd.conskbd_polledio.cons_polledio_version = CONSPOLLEDIO_V1;
	conskbd.conskbd_polledio.cons_polledio_argument =
	    (cons_polledio_arg_t)&conskbd;
	conskbd.conskbd_polledio.cons_polledio_putchar = NULL;
	conskbd.conskbd_polledio.cons_polledio_getchar =
	    (int (*)(cons_polledio_arg_t)) conskbd_polledio_getchar;
	conskbd.conskbd_polledio.cons_polledio_ischar =
	    (boolean_t (*)(cons_polledio_arg_t))conskbd_polledio_ischar;
	conskbd.conskbd_polledio.cons_polledio_enter = conskbd_polledio_enter;
	conskbd.conskbd_polledio.cons_polledio_exit = conskbd_polledio_exit;
	qprocson(q);

	return (0);

}	/* conskbdopen() */


/*ARGSUSED*/
static int
conskbdclose(queue_t *q, int flag, cred_t *crp)
{
	if (q == conskbd_regqueue) {

		conskbd_pending_msg_t	*pmsg, *prev, *next;
		mblk_t		*mp;

		/* switch the input stream back to conskbd_consqueue */
		conskbd.conskbd_directio = B_FALSE;

		kbtrans_streams_untimeout(conskbd.conskbd_kbtrans);
		kbtrans_streams_set_queue(conskbd.conskbd_kbtrans,
		    conskbd_consqueue);
		qprocsoff(q);
		conskbd_regqueue = NULL;

		/*
		 * If there are any pending ioctls which conskbd hasn't
		 * responded to yet, remove them from conskbd_msg_queue.
		 * Otherwise, we might send the response to a nonexistent
		 * closed queue. Refer to: conskbd_mux_upstream_msg().
		 */
		for (prev = NULL, pmsg = conskbd_msg_queue; pmsg != NULL;
		    pmsg = next) {
			next = pmsg->kpm_next;
			if (pmsg->kpm_upper_queue == WR(q)) {
				if (prev == NULL)
					conskbd_msg_queue = next;
				else
					prev->kpm_next = next;

				while (pmsg->kpm_resp_list != NULL) {
					mp = pmsg->kpm_resp_list;
					pmsg->kpm_resp_list = mp->b_next;
					mp->b_next = mp->b_prev = NULL;
					freemsg(mp);
				}
				mutex_destroy(&pmsg->kpm_lock);
				kmem_free(pmsg, sizeof (*pmsg));
			} else {
				prev = pmsg;
			}
		}
	} else if (q == conskbd_consqueue) {
		/*
		 * Well, this is probably a mistake, but we will permit you
		 * to close the path to the console if you really insist.
		 */
		qprocsoff(q);
		conskbd_consqueue = NULL;
	}

	return (0);

}	/* conskbdclose() */

/*
 * Service procedure for upper write queue.
 *	To make sure the order of messages, we don't process any
 * message in qi_putq() routine of upper write queue, instead the
 * qi_putq() routine, which is a standard putq() routine, puts all
 * messages into a queue, and lets the following service procedure
 * deal with all messages.
 *	This routine is invoked when ioctl commands are send down
 * by a consumer of the keyboard device, eg, when the keyboard
 * consumer tries to determine the keyboard layout type, or sets
 * the led states.
 */
static int
conskbduwsrv(queue_t *q)
{
	mblk_t	*mp;
	queue_t	*oldq;
	enum kbtrans_message_response ret;
	struct copyresp *csp;
	struct freq_request *frqp;
	int error;

	while ((mp = getq(q)) != NULL) {

		/*
		 * if the virtual keyboard is supported
		 */
		if (conskbd.conskbd_bypassed == B_FALSE) {

			if (conskbd_override_kbtrans(q, mp) == B_TRUE)
				continue;
			/*
			 * The conskbd driver is a psaudo driver. It has two
			 * devcice nodes, one is used by kernel, and the other
			 * is used by end-users. There are two STREAMS queues
			 * corresponding to the two device nodes, console queue
			 * and regular queue.
			 * In conskbd_override_kbtrans() routine, when receives
			 * KIOCSDIRECT ioctl, we need change the direction of
			 * keyboard input messages, and direct the input stream
			 * from keyboard into right queue. It causes this queue
			 * to be switched between regular queue and console
			 * queue. And here, in this routine, the in-parameter
			 * "q" can be any one of the two. Moreover, this module
			 * is executed in multithreaded environment, even if the
			 * q is switched to regular queue, it is possible that
			 * the in-parameter is still the console queue, and we
			 * need to return response to right queue.
			 * The response is sent to upstream by the kbtrans
			 * module. so we need to save the old queue, and wait
			 * kbtrans to proces message and to send response out,
			 * and then switch back to old queue.
			 */
			oldq = kbtrans_streams_get_queue(
			    conskbd.conskbd_kbtrans);
			kbtrans_streams_set_queue(
			    conskbd.conskbd_kbtrans, RD(q));
			ret = kbtrans_streams_message(
			    conskbd.conskbd_kbtrans, mp);
			kbtrans_streams_set_queue(
			    conskbd.conskbd_kbtrans, oldq);

			switch (ret) {
				case KBTRANS_MESSAGE_HANDLED:
					continue;
				case KBTRANS_MESSAGE_NOT_HANDLED:
					break;
			}
		}

		switch (mp->b_datap->db_type) {

		case M_IOCTL:
			conskbd_ioctl(q, mp);
			break;

		case M_FLUSH:
			if (*mp->b_rptr & FLUSHW) {
				flushq(q, FLUSHDATA);
			}
			/*
			 * here, if flush read queue, some key-up messages
			 * may be lost so that upper module or applications
			 * treat corresponding keys as being held down for
			 * ever.
			 */
			freemsg(mp);
			break;

		case M_DATA:
			/*
			 * virtual keyboard doesn't support this interface.
			 * only when it is disabled, we pass the message
			 * down to lower queue.
			 */
			if ((conskbd.conskbd_bypassed) &&
			    (conskbd.conskbd_lqueue_nums > 0)) {
				if (putq(conskbd.conskbd_lqueue_list->
				    lqs_queue, mp) != 1)
					freemsg(mp);
			} else {
				freemsg(mp);
			}
			break;

		case M_IOCDATA:
			/*
			 * Only deal with copyresp to KIOCSETFREQ
			 * transparent ioctl now
			 */
			csp = (struct copyresp *)mp->b_rptr;
			if (csp->cp_rval) {
				miocnak(q, mp, 0, EINVAL);
				break;
			}

			error = 0;
			switch (csp->cp_cmd) {
			case KIOCSETFREQ:
				frqp = (struct freq_request *)mp->
				    b_cont->b_rptr;

				switch (frqp->type) {
				case CONSOLE_BEEP:
					error = beeper_freq(BEEP_CONSOLE,
					    (int)frqp->freq);
						break;

				case KBD_BEEP:
					error = beeper_freq(BEEP_TYPE4,
					    (int)frqp->freq);
						break;

				default:
					error = 1;
				} /* frqp->type */

				break;

			default:
				error = 1;
			} /* csp->cp_cmd */

			if (error == 0)
				miocack(q, mp, 0, 0);
			else
				miocnak(q, mp, 0, EINVAL);

			break;

		default:
			/*
			 * Pass an error message up.
			 */
			mp->b_datap->db_type = M_ERROR;
			if (mp->b_cont) {
				freemsg(mp->b_cont);
				mp->b_cont = NULL;
			}
			mp->b_rptr = mp->b_datap->db_base;
			mp->b_wptr = mp->b_rptr + sizeof (char);
			*mp->b_rptr = EINVAL;
			qreply(q, mp);
		}
	}	/* end of while */

	return (0);
}	/* conskbduwsrv() */

static void
conskbd_ioctl(queue_t *q, mblk_t *mp)
{
	struct	iocblk			*iocp;
	int	error = 0;

	iocp = (struct iocblk *)mp->b_rptr;

	switch (iocp->ioc_cmd) {

	case I_LINK:
	case I_PLINK:
		if (conskbd.conskbd_bypassed == B_TRUE) {
		/*
		 * A legacy keyboard can NOT be connected to conskbd together
		 * with other keyboards. So when a legacy keyboard is already
		 * linked under conkbd, we just reject all others.
		 */
			miocnak(q, mp, 0, EAGAIN);
			break;
		}
		qwriter(q, mp, conskbd_ioc_plink, PERIM_OUTER);
		break;

	case I_UNLINK:
	case I_PUNLINK:
		qwriter(q, mp, conskbd_ioc_punlink, PERIM_OUTER);
		break;

	case KIOCSKABORTEN:
		/*
		 * Check if privileged
		 */
		if ((error = secpolicy_sys_config(iocp->ioc_cr, B_FALSE))) {
			miocnak(q, mp, 0, error);
			return;
		}

		error = miocpullup(mp, sizeof (int));
		if (error != 0) {
			miocnak(q, mp, 0, error);
			return;
		}

		abort_enable = *(int *)mp->b_cont->b_rptr;
		miocack(q, mp, 0, 0);
		break;

	case KIOCSETFREQ:
		if (iocp->ioc_count != TRANSPARENT) {
			/*
			 * We don't support non-transparent ioctls,
			 * i.e. I_STR ioctls
			 */
			miocnak(q, mp, 0, EINVAL);
		} else {
			/* Transparent ioctl */
			mcopyin(mp, NULL, sizeof (struct freq_request), NULL);
			qreply(q, mp);
		}
		break;

	default:
		if (conskbd.conskbd_bypassed == B_TRUE) {
			conskbd_legacy_kbd_ioctl(q, mp);
		} else {
			conskbd_virtual_kbd_ioctl(q, mp);
		}
	}

}	/* conskbd_ioctl() */


static void
conskbd_virtual_kbd_ioctl(queue_t *q, mblk_t *mp)
{
	struct iocblk		*iocp;
	mblk_t			*datap;
	int			cmd;
	int			error = 0;

	iocp = (struct iocblk *)mp->b_rptr;

	switch (iocp->ioc_cmd) {
	case KIOCLAYOUT:
		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			miocnak(q, mp, 0, ENOMEM);
			break;
		}

		if (conskbd.conskbd_layout == -1)
			*(int *)datap->b_wptr = KBTRANS_USBKB_DEFAULT_LAYOUT;
		else
			*(int *)datap->b_wptr = conskbd.conskbd_layout;

		datap->b_wptr += sizeof (int);
		if (mp->b_cont)
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		miocack(q, mp, sizeof (int), 0);
		break;

	case KIOCSLAYOUT:
		if (iocp->ioc_count != TRANSPARENT) {
			miocnak(q, mp, 0, EINVAL);
			break;
		}
		kbd_layout_bak = conskbd.conskbd_layout;
		conskbd.conskbd_layout = *(intptr_t *)(mp->b_cont->b_rptr);
		if (conskbd.conskbd_layout != kbd_layout_bak) {

			/* notify the upper of the change event */
			if ((datap = conskbd_alloc_firm_event(
			    KEYBOARD_LAYOUT_CHANGE,
			    conskbd.conskbd_layout)) != NULL) {
				if (conskbd.conskbd_directio) {
					putnext(conskbd_regqueue, datap);
				} else {
					freemsg(datap);
				}
			}
		}
		miocack(q, mp, 0, 0);
		break;

	case CONSOPENPOLLEDIO:
		error = miocpullup(mp, sizeof (struct cons_polledio *));
		if (error != 0) {
			miocnak(q, mp, 0, error);
			break;
		}
		if (conskbd.conskbd_lqueue_list == NULL) {
			miocnak(q, mp, 0, EINVAL);
			break;
		}
		conskbd_handle_downstream_msg(q, mp);
		break;

	case CONSCLOSEPOLLEDIO:
		if (conskbd.conskbd_lqueue_list == NULL) {
			miocnak(q, mp, 0, EINVAL);
			break;
		}
		conskbd_handle_downstream_msg(q, mp);
		break;

	case CONSSETABORTENABLE:
		/*
		 * To enable combined STOP-A(or F1-A) to trap into kmdb,
		 * the lower physical keyboard drivers are always told not
		 * to parse abort sequence(refer to consconfig_dacf module).
		 * Instead, lower drivers always send all keydown & keyup
		 * messages up to conskbd, so that when key STOP(or F1) is
		 * pressed on one keyboard and key A is pressed on another
		 * keyboard, the system could trap into kmdb.
		 *
		 * When we by kbtrans_streams_message() invoked kbtrans to
		 * handle ioctls in conskbduwsrv() routine, kbtrans module
		 * already handle the message though it returned to us a
		 * KBTRANS_MESSAGE_NOT_HANDLED. For virtual keyboard, no
		 * special initialization or un-initialization is needed.
		 * So we just return ACK to upper module.
		 */
		miocack(q, mp, 0, 0);
		break;

	case KIOCCMD:
	case KIOCMKTONE:
		if (conskbd.conskbd_lqueue_list == NULL ||
		    mp->b_cont == NULL) {
			miocnak(q, mp, 0, EINVAL);
			break;
		}
		cmd = *(int *)mp->b_cont->b_rptr;
		if (cmd == KBD_CMD_GETLAYOUT) {
			freemsg(mp->b_cont);
			datap = allocb(sizeof (int), BPRI_HI);
			if (datap == NULL) {
				miocnak(q, mp, 0, ENOMEM);
				return;
			}
			if (conskbd.conskbd_layout == -1)
				*(int *)datap->b_wptr =
				    KBTRANS_USBKB_DEFAULT_LAYOUT;
			else
				*(int *)datap->b_wptr = conskbd.conskbd_layout;

			mp->b_cont = datap;
			miocack(q, mp, sizeof (int), 0);
			return;
		}
		conskbd_handle_downstream_msg(q, mp);
		break;

	default:
		miocnak(q, mp, 0, EINVAL);
		break;
	}

}	/* conskbd_virtual_kbd_ioctl() */

static void
conskbd_legacy_kbd_ioctl(queue_t *q, mblk_t *mp)
{
	conskbd_lower_queue_t	*lq;
	struct	iocblk		*iocp;
	int	error = 0;

	iocp = (struct iocblk *)mp->b_rptr;

	ASSERT(conskbd.conskbd_lqueue_nums == 1);
	switch (iocp->ioc_cmd) {

	case KIOCGDIRECT: {
		mblk_t *datap;

		if ((datap = allocb(sizeof (int), BPRI_MED)) == NULL) {
			miocnak(q, mp, 0, ENOMEM);
			break;
		}

		*(int *)datap->b_wptr = conskbd.conskbd_directio;
		datap->b_wptr += sizeof (int);
		if (mp->b_cont != NULL) {
			freemsg(mp->b_cont);
			mp->b_cont = NULL;
		}
		mp->b_cont = datap;
		miocack(q, mp, sizeof (int), 0);
		break;
	}

	case KIOCSDIRECT:
		error = miocpullup(mp, sizeof (int));
		if (error != 0) {
			miocnak(q, mp, 0, error);
			break;
		}
		conskbd.conskbd_directio = *(int *)mp->b_cont->b_rptr;

		/*
		 * Pass this through, if there's something to pass
		 * it through to, so the system keyboard can reset
		 * itself.
		 */
		if (conskbd.conskbd_lqueue_nums > 0) {
			lq = conskbd.conskbd_lqueue_list;
			ASSERT(lq && lq->lqs_next == NULL);
			if (putq(lq->lqs_queue, mp) != 1) {
				miocnak(q, mp, 0, ENOMEM);
				return;
			}
			break;
		}

		miocack(q, mp, 0, 0);
		break;

	default:
		/*
		 * Pass this through, if there's something to pass it
		 * through to; otherwise, reject it.
		 */
		if (conskbd.conskbd_lqueue_nums > 0) {
			lq = conskbd.conskbd_lqueue_list;
			ASSERT(lq && lq->lqs_next == NULL);
			if (putq(lq->lqs_queue, mp) != 1) {
				miocnak(q, mp, 0, ENOMEM);
				return;
			}
			break;
		}

		/* nobody below us; reject it */
		miocnak(q, mp, 0, EINVAL);
		break;
	}

}	/* conskbd_legacy_kbd_ioctl() */


/*
 * Service procedure for lower write queue.
 * Puts things on the queue below us, if it lets us.
 */
static int
conskbdlwserv(queue_t *q)
{
	register mblk_t *mp;

	while (canput(q->q_next) && (mp = getq(q)) != NULL)
		putnext(q, mp);

	return (0);
}	/* conskbdlwserv() */

/*
 * Put procedure for lower read queue.
 * Pass everything up to minor device 0 if "directio" set, otherwise to minor
 * device 1.
 */
static int
conskbdlrput(queue_t *q, mblk_t *mp)
{
	conskbd_lower_queue_t	*lqs;
	struct iocblk	*iocp;
	Firm_event	*fe;

	DPRINTF(PRINT_L1, PRINT_MASK_ALL, ("conskbdlrput\n"));

	switch (mp->b_datap->db_type) {

	case M_FLUSH:
		if (*mp->b_rptr == FLUSHR) {
			flushq(q, FLUSHDATA);	/* XXX doesn't flush M_DELAY */
			*mp->b_rptr &= ~FLUSHR;	/* it has been flushed */
		}
		if (*mp->b_rptr == FLUSHW) {
			flushq(WR(q), FLUSHDATA);
			qreply(q, mp);	/* give the read queues a crack at it */
		} else
			freemsg(mp);
		break;

	case M_DATA:
		if (conskbd.conskbd_bypassed == B_FALSE) {

			fe = (Firm_event *)mp->b_rptr;

			/*
			 * This is a workaround.
			 *
			 * According to HID specification, there are the
			 * following keycode mapping between PS2 and USB,
			 *
			 *	PS2 AT-101 keycode(29)  --->    USB(49)
			 *	PS2 AT-102 keycode(42)  --->    USB(50)
			 *
			 * However, the two keys, AT-101(29) and AT-102(42),
			 * have the same scancode,0x2B, in PS2 scancode SET1
			 * which we are using. The Kb8042 driver always
			 * recognizes the two keys as PS2(29) so that we could
			 * not know which is being pressed or released when we
			 * receive scancode 0x2B. Fortunately, the two keys can
			 * not co-exist in a specific layout. In other words,
			 * in the table of keycode-to-symbol mapping, either
			 * entry 49 or 50 is a hole. So, if we're processing a
			 * keycode 49, we look at the entry for 49.  If it's
			 * HOLE, remap the key to 50; If we're processing a 50,
			 * look at the entry for 50.  If it's HOLE, we remap
			 * the key to 49.
			 */
			if (fe->id == 49 || fe->id == 50) {
				if (conskbd_keyindex->k_normal[50] == HOLE)
					fe->id = 49;
				else
					fe->id = 50;
			}

			/*
			 * Remember key state of each key of lower physical
			 * keyboard. When a keyboard is umplumbed from conskbd,
			 * we will check all key states. By then,  we will fake
			 * a KEY_RELEASED message for each key in KEY_PRESSED
			 * state. Otherwise, upper module will treat these keys
			 * as held-down for ever.
			 */
			iocp = (struct iocblk *)mp->b_rptr;
			lqs = (conskbd_lower_queue_t *)q->q_ptr;
			if (fe->value)
				lqs->lqs_key_state[fe->id] = KEY_PRESSED;
			else
				lqs->lqs_key_state[fe->id] = KEY_RELEASED;

			kbtrans_streams_key(conskbd.conskbd_kbtrans,
			    fe->id, fe->value ? KEY_PRESSED : KEY_RELEASED);
			freemsg(mp);
		} else {
			if (conskbd.conskbd_directio)
				putnext(conskbd_regqueue, mp);
			else if (conskbd_consqueue != NULL)
				putnext(conskbd_consqueue, mp);
			else
				freemsg(mp);
		}
		conskbd_idle_stamp = gethrestime_sec();
		break;

	case M_IOCACK:
	case M_IOCNAK:
		iocp = (struct iocblk *)mp->b_rptr;
		lqs = (conskbd_lower_queue_t *)q->q_ptr;

		DPRINTF(PRINT_L1, PRINT_MASK_ALL, ("conskbdlrput: "
		    "ACK/NAK - cmd 0x%x\n", iocp->ioc_cmd));

		conskbd_lqs_ack_complete(lqs, mp);
		break;

	case M_ERROR:
	case M_HANGUP:
	default:
		freemsg(mp);	/* anything useful here? */
		break;
	}

	return (0);
}	/* conskbdlrput() */


/* ARGSUSED */
static int
conskbd_kstat_update(kstat_t *ksp, int rw)
{
	if (rw == KSTAT_WRITE)
		return (EACCES);

	conskbd_kstat.idle_sec.value.l = gethrestime_sec() - conskbd_idle_stamp;

	return (0);

}	/* conskbd_kstat_update() */

/*
 * STREAMS architecuture provides guarantee that the ID of each
 * message, iocblk.ioc_id, in a stream is unique. The following
 * routine performes the task: When receive request from upstream,
 * it saves the request in a global link list, clones the request,
 * and then sends a copy of the request to each of lower queues
 * which are plumbed into conskbd. And then, when receives responses
 * from lower queues in conskbdlrput() routine, we can know the
 * request matching received responses by searching the global linked
 * list to find the request which has the same message ID of the
 * response. Then, when all lower queues response this request, we
 * give a response to upstreams based the following policy:
 * If any one of lower queues acks our reuqest, then we return ack
 * to upstreams; only if all lower queues nak our request, we return
 * nak to upstreams. If all responses are nak, the error number of
 * the first response is sent to upstream.
 */
static void
conskbd_handle_downstream_msg(queue_t *q, mblk_t *mp)
{
	conskbd_pending_msg_t	*msg;
	conskbd_lower_queue_t	*lqs;
	struct iocblk	*iocp;
	mblk_t		*clonemp;
	int		retry;

	if (conskbd.conskbd_lqueue_nums == 0) {
		miocnak(q, mp, 0, EINVAL);
		return;
	}

	msg = (conskbd_pending_msg_t *)
	    kmem_zalloc(sizeof (conskbd_pending_msg_t), KM_SLEEP);
	mutex_init(&msg->kpm_lock, NULL, MUTEX_DRIVER, NULL);
	lqs = conskbd.conskbd_lqueue_list;
	iocp = (struct iocblk *)mp->b_rptr;

	ASSERT(iocp->ioc_cmd == CONSOPENPOLLEDIO ||
	    iocp->ioc_cmd == CONSCLOSEPOLLEDIO ||
	    iocp->ioc_cmd == KIOCCMD ||
	    iocp->ioc_cmd == KIOCMKTONE);

	msg->kpm_upper_queue = q;
	msg->kpm_req_msg = mp;
	msg->kpm_req_id = iocp->ioc_id;
	msg->kpm_req_cmd = iocp->ioc_cmd;
	msg->kpm_req_nums = conskbd.conskbd_lqueue_nums;
	conskbd_mux_enqueue_msg(msg);

	for (retry = 0, lqs = conskbd.conskbd_lqueue_list; lqs; ) {

		/*
		 * if a lower physical keyboard is not in polled I/O
		 * mode, we couldn't send CONSCLOSEPOLLEDIO to it,
		 * otherwise, system will panic.
		 */
		if (iocp->ioc_cmd == CONSCLOSEPOLLEDIO &&
		    lqs->lqs_polledio == NULL) {
			lqs = lqs->lqs_next;
			msg->kpm_req_nums --;
			retry = 0;
			continue;
		}

		clonemp = copymsg(mp);
		if (clonemp != NULL) {
			if (putq(lqs->lqs_queue, clonemp) == 1) {
				lqs = lqs->lqs_next;
				retry = 0;
				continue;
			}

			/*
			 * failed to invoke putq(), retry.
			 */
			freemsg(clonemp);
		}

		/*
		 * During testing it was observed that occasionally
		 * copymsg() would fail during boot. The reason for
		 * these failures is unknown. Since we really want
		 * to successfully plumb up all the attached keyboards
		 * during boot we do a best effort here by retrying
		 * the copymsg() call in the hopes that it will
		 * succeeded upon subsequent invocations.
		 *
		 * If all the calls to copymsg() fails, it will cause
		 * the corresponding keyboard to be unavailable, or
		 * or behave weirdly,
		 *
		 * 1) for CONSOPENPOLLEDIO
		 *	if copymsg()fails, the corresponding keyboard
		 *	is not available in polled I/O mode once
		 *	entering kmdb;
		 * 2) for CONSCLOSEPOLLEDIO
		 *	if copymsg() fails, the corresponding keyboard
		 *	is not available in normal mode once returning
		 *	from kmdb;
		 * 3) for KIOCCMD
		 *	3.1) for KBD_CMD_NOBELL
		 *		there's no beep in USB and PS2 keyboard,
		 *		this ioctl actually disables the beep on
		 *		system mainboard. Note that all the cloned
		 *		messages sent down to lower queues do the
		 *		same job for system mainboard. Therefore,
		 *		even if we fail to send this ioctl to most
		 *		of lower queues, the beep still would be
		 *		disabled. So, no trouble exists here.
		 *	3.2) for others
		 *		nothing;
		 *
		 * However, all cases could be resume next time when the
		 * same request comes again.
		 */
		if (retry ++ >= 5) {
			dev_t	devt;
			char	path[MAXPATHLEN + 1];

			devt = lqs->lqs_queue->q_stream->sd_vnode->v_rdev;
			switch (iocp->ioc_cmd) {
			case CONSOPENPOLLEDIO:
				if (ddi_dev_pathname(devt, S_IFCHR,
				    path) == DDI_SUCCESS)
					cmn_err(CE_WARN, "conskbd: "
					    "keyboard is not available"
					    " for system debugging: %s",
					    path);
				break;

			case CONSCLOSEPOLLEDIO:
				if (ddi_dev_pathname(devt, S_IFCHR,
				    path) == DDI_SUCCESS)
					cmn_err(CE_WARN, "conskbd: "
					    "keyboard is not available:"
					    " %s", path);
				break;

			default:
				break;
			}
			msg->kpm_req_nums --;
			lqs = lqs->lqs_next;
			retry = 0;
		}
	}

	if (msg->kpm_req_nums == 0) {
		conskbd_mux_dequeue_msg(msg);
		kmem_free(msg, sizeof (*msg));
		miocnak(q, mp, 0, ENOMEM);
	}

}	/* conskbd_handle_downstream_msg() */


static void
conskbd_ioc_plink(queue_t *q, mblk_t *mp)
{
	mblk_t		*req;
	queue_t		*lowque;
	struct linkblk		*linkp;
	conskbd_lower_queue_t	*lqs;

	lqs = kmem_zalloc(sizeof (*lqs), KM_SLEEP);
	ASSERT(lqs->lqs_state == LQS_UNINITIALIZED);

	linkp = (struct linkblk *)mp->b_cont->b_rptr;
	lowque = linkp->l_qbot;

	lqs->lqs_queue = lowque;
	lqs->lqs_pending_plink = mp;
	lqs->lqs_pending_queue = q;

	req = mkiocb(CONSSETKBDTYPE);
	if (req == NULL) {
		miocnak(q, mp, 0, ENOMEM);
		kmem_free(lqs, sizeof (*lqs));
		return;
	}

	req->b_cont = allocb(sizeof (int), BPRI_MED);
	if (req->b_cont == NULL) {
		freemsg(req);
		miocnak(q, mp, 0, ENOMEM);
		kmem_free(lqs, sizeof (*lqs));
		return;
	}

	lowque->q_ptr = lqs;
	OTHERQ(lowque)->q_ptr = lqs;
	*(int *)req->b_cont->b_wptr = KB_USB;
	req->b_cont->b_wptr += sizeof (int);

	lqs->lqs_state = LQS_KIOCTYPE_ACK_PENDING;

	if (putq(lowque, req) != 1) {
		freemsg(req);
		miocnak(lqs->lqs_pending_queue,
		    lqs->lqs_pending_plink, 0, ENOMEM);
		lowque->q_ptr = NULL;
		OTHERQ(lowque)->q_ptr = NULL;
		kmem_free(lqs, sizeof (*lqs));
	}

}	/* conskbd_ioc_plink() */


static void
conskbd_ioc_punlink(queue_t *q, mblk_t *mp)
{
	int			index;
	struct linkblk		*linkp;
	conskbd_lower_queue_t	*lqs;
	conskbd_lower_queue_t	*prev;

	linkp = (struct linkblk *)mp->b_cont->b_rptr;
	prev = conskbd.conskbd_lqueue_list;
	for (lqs = prev; lqs; lqs = lqs->lqs_next) {
		if (lqs->lqs_queue == linkp->l_qbot) {
			if (prev == lqs)
				conskbd.conskbd_lqueue_list =
				    lqs->lqs_next;
			else
				prev->lqs_next = lqs->lqs_next;

			lqs->lqs_queue->q_ptr =  NULL;
			OTHERQ(lqs->lqs_queue)->q_ptr = NULL;
			conskbd.conskbd_lqueue_nums --;
			if (conskbd.conskbd_lqueue_nums == 0) {
				kbd_layout_bak = conskbd.conskbd_layout;
				conskbd.conskbd_layout = -1;
			}

			for (index = 0; index < KBTRANS_KEYNUMS_MAX; index ++) {
				if (lqs->lqs_key_state[index] == KEY_PRESSED)
					kbtrans_streams_key(
					    conskbd.conskbd_kbtrans,
					    index,
					    KEY_RELEASED);
			}

			kmem_free(lqs, sizeof (*lqs));
			miocack(q, mp, 0, 0);
			return;
		}
		prev = lqs;
	}
	miocnak(q, mp, 0, EINVAL);

}	/* conskbd_ioc_punlink() */

/*
 * Every physical keyboard has a corresponding STREAMS queue. We call this
 * queue lower queue. Every lower queue has a state, refer to conskbd.h file
 * about "enum conskbd_lqs_state".
 * The following routine is used to handle response messages from lower queue.
 * When receiving ack/nak message from lower queue(s), the routine determines
 * the passage for it according to the current state of this lower queue.
 */
static void
conskbd_lqs_ack_complete(conskbd_lower_queue_t *lqs, mblk_t *mp)
{
	switch (lqs->lqs_state) {

	/* S6: working in virtual keyboard mode, multi-keyboards are usable */
	case LQS_INITIALIZED:
		conskbd_mux_upstream_msg(lqs, mp);
		break;

	/* S5: working in legacy mode, only one keyboard is usable */
	case LQS_INITIALIZED_LEGACY:
		conskbd_legacy_upstream_msg(lqs, mp);
		break;

	/* S4: wait lower queue to acknowledge KIOCSLED/KIOCGLED  message */
	case LQS_KIOCSLED_ACK_PENDING:
		conskbd_kiocsled_complete(lqs, mp);
		break;

	/* S3: wait lower queue to acknowledge KIOCLAYOUT  message */
	case LQS_KIOCLAYOUT_ACK_PENDING:
		conskbd_kioclayout_complete(lqs, mp);
		break;

	/* S2: wait lower queue to acknowledge KIOCTRANS  message */
	case LQS_KIOCTRANS_ACK_PENDING:
		conskbd_kioctrans_complete(lqs, mp);
		break;

	/* S1: wait lower queue to acknowledge KIOCTYPE  message */
	case LQS_KIOCTYPE_ACK_PENDING:
		conskbd_kioctype_complete(lqs, mp);
		break;

	/* if reaching here, there must be a error */
	default:
		freemsg(mp);
		cmn_err(CE_WARN, "conskbd: lqs_ack_complete() state error");
		break;
	}

}	/* conskbd_lqs_ack_complete() */


static void
conskbd_kioctype_complete(conskbd_lower_queue_t *lqs, mblk_t *mp)
{
	struct iocblk	*iocp;
	mblk_t		*req;
	queue_t		*lowerque;
	int		err = ENOMEM;

	ASSERT(lqs->lqs_pending_plink);
	ASSERT(lqs->lqs_state == LQS_KIOCTYPE_ACK_PENDING);

	lowerque = lqs->lqs_queue;

	switch (mp->b_datap->db_type) {
	case M_IOCACK:
		req = mkiocb(KIOCTRANS);
		if (req == NULL) {
			goto err_exit;
		}

		req->b_cont = allocb(sizeof (int), BPRI_MED);
		if (req->b_cont == NULL) {
			freemsg(req);
			goto err_exit;
		}

		/* Set the translate mode to TR_UNTRANS_EVENT */
		*(int *)req->b_cont->b_wptr = TR_UNTRANS_EVENT;
		req->b_cont->b_wptr += sizeof (int);

		/* Ready to handle the response to KIOCTRANS */
		lqs->lqs_state = LQS_KIOCTRANS_ACK_PENDING;

		if (putq(lowerque, req) != 1) {
			freemsg(req);
			goto err_exit;
		}
		freemsg(mp);
		return;

	case M_IOCNAK:
		/*
		 * The lower keyboard driver can't mimic USB keyboard,
		 * that's say, the physical keyboard is an old one, such
		 * as TYPE 3/4/5 one. In this case, the virtual keyboard
		 * is disabled, and the data from lower keyboard driver
		 * will bypass the conskbd module.
		 */

		/*
		 * if there is any other keyborad already linked under the
		 * conskbd, we reject the current one.
		 */
		if (conskbd.conskbd_lqueue_nums > 0) {
			iocp = (struct iocblk *)mp->b_rptr;
			err = iocp->ioc_error;
			goto err_exit;
		}

		/*
		 * link this keyboard under conskbd.
		 */
		qwriter(lowerque, mp, conskbd_link_lowque_legacy, PERIM_OUTER);
		return;
	}

err_exit:
	miocnak(lqs->lqs_pending_queue, lqs->lqs_pending_plink, 0, err);
	lowerque->q_ptr = NULL;
	OTHERQ(lowerque)->q_ptr = NULL;
	kmem_free(lqs, sizeof (*lqs));
	freemsg(mp);

}	/* conskbd_kioctype_complete() */

static void
conskbd_kioctrans_complete(conskbd_lower_queue_t *lqs, mblk_t *mp)
{
	struct iocblk	*iocp;
	mblk_t		*req;
	queue_t		*lowerque;
	int		err = ENOMEM;

	ASSERT(lqs->lqs_pending_plink != NULL);
	ASSERT(lqs->lqs_state == LQS_KIOCTRANS_ACK_PENDING);

	lowerque = lqs->lqs_queue;

	switch (mp->b_datap->db_type) {
	case M_IOCACK:
		req = mkiocb(KIOCLAYOUT);
		if (req == NULL) {
			goto err_exit;
		}

		req->b_cont = allocb(sizeof (int), BPRI_MED);
		if (req->b_cont == NULL) {
			freemsg(req);
			goto err_exit;
		}

		/* waiting for response to KIOCLAYOUT */
		lqs->lqs_state = LQS_KIOCLAYOUT_ACK_PENDING;
		if (putq(lqs->lqs_queue, req) != 1) {
			freemsg(req);
			goto err_exit;
		}
		freemsg(mp);
		return;

	case M_IOCNAK:
		iocp = (struct iocblk *)mp->b_rptr;
		err = iocp->ioc_error;
		goto err_exit;
	}

err_exit:
	miocnak(lqs->lqs_pending_queue, lqs->lqs_pending_plink, 0, err);
	lowerque->q_ptr = NULL;
	OTHERQ(lowerque)->q_ptr = NULL;
	kmem_free(lqs, sizeof (*lqs));
	freemsg(mp);

}	/* conskbd_kioctrans_complete() */

/*
 * Allocate a firm event
 */
static mblk_t *
conskbd_alloc_firm_event(ushort_t id, int value)
{
	mblk_t	*mb;
	Firm_event *fe;

	if ((mb = allocb(sizeof (Firm_event), BPRI_HI)) != NULL) {
		fe = (Firm_event *)mb->b_wptr;
		fe->id = id;
		fe->pair_type = FE_PAIR_NONE;
		fe->pair = '\0';
		fe->value = value;
		mb->b_wptr += sizeof (Firm_event);
	}

	return (mb);
}

static void
conskbd_kioclayout_complete(conskbd_lower_queue_t *lqs, mblk_t *mp)
{
	mblk_t		*req;
	int		layout;
	boolean_t	fail;

	ASSERT(lqs->lqs_pending_plink != NULL);
	ASSERT(lqs->lqs_state == LQS_KIOCLAYOUT_ACK_PENDING);

	switch (mp->b_datap->db_type) {
	case M_IOCACK:
		if (miocpullup(mp, sizeof (int)) == 0) {
			layout = *(int *)mp->b_cont->b_rptr;
			/*
			 * We just accept the layout of the first keyboard
			 * requesting to be linked under conskbd. If current
			 * keyboard is the first one, and if we get right
			 * layout from it, we set conskbd's layout
			 */
			if (layout != -1 && conskbd.conskbd_layout == -1) {
				if (layout == 0) {
					conskbd.conskbd_layout = kbd_layout_bak;
				} else {
					conskbd.conskbd_layout = layout;
					if (layout == kbd_layout_bak) {
						break;
					}
					if ((req = conskbd_alloc_firm_event(
					    KEYBOARD_LAYOUT_CHANGE,
					    layout)) != NULL) {
						if (conskbd.conskbd_directio) {
							putnext(
							    conskbd_regqueue,
							    req);
						} else if (conskbd_consqueue
						    != NULL) {
							putnext(
							    conskbd_consqueue,
							    req);
						} else {
							freemsg(req);
						}
					}
				}
			}
		}
		break;


	/* if fail, leave conskbd's layout as it is */
	case M_IOCNAK:
		break;
	}

	fail = B_TRUE;

	if (conskbd.conskbd_led_state == -1)
		req = mkiocb(KIOCGLED);
	else
		req = mkiocb(KIOCSLED);

	if (req) {
		req->b_cont = allocb(sizeof (uchar_t), BPRI_MED);
		if (req->b_cont) {
			if (conskbd.conskbd_led_state != -1) {
				*(uchar_t *)req->b_cont->b_wptr =
				    conskbd.conskbd_led_state;
				req->b_cont->b_wptr += sizeof (uchar_t);
			}

			/* waiting for response to KIOCSLED */
			lqs->lqs_state = LQS_KIOCSLED_ACK_PENDING;
			if (putq(lqs->lqs_queue, req) == 1) {
				fail = B_FALSE;
			} else {
				freemsg(req);
			}

		} else {
			freemsg(req);
		}
	}

	if (fail) {
		/*
		 * If fail to allocate KIOCSLED/KIOCGLED message or put
		 * the message into lower queue, we immediately link
		 * current keyboard under conskbd. Thus, even if fails
		 * to set/get LED, this keyboard could be available.
		 */
		qwriter(lqs->lqs_queue,
		    mp, conskbd_link_lowque_virt, PERIM_OUTER);
	} else {
		freemsg(mp);
	}

}	/* conskbd_kioclayout_complete() */


static void
conskbd_kiocsled_complete(conskbd_lower_queue_t *lqs, mblk_t *mp)
{
	int	led_state;

	ASSERT(lqs->lqs_pending_plink != NULL);
	ASSERT(lqs->lqs_state == LQS_KIOCSLED_ACK_PENDING);

	if (conskbd.conskbd_led_state == -1) {
		switch (mp->b_datap->db_type) {
		case M_IOCACK:
			if (miocpullup(mp, sizeof (uchar_t)) == 0) {
				led_state = *(uchar_t *)mp->b_cont->b_rptr;
				conskbd.conskbd_led_state = led_state;
				kbtrans_streams_setled(conskbd.conskbd_kbtrans,
				    led_state);
			}
			break;

		/* if fail, leave conskbd's led_state as it is */
		case M_IOCNAK:
			break;
		}
	}

	/*
	 * Basically, failure of setting/getting LED is not a fatal
	 * error, so we will plumb the lower queue into conskbd whether
	 * setting/getting LED succeeds or fails.
	 */
	qwriter(lqs->lqs_queue, mp, conskbd_link_lowque_virt, PERIM_OUTER);

}	/* conskbd_kiocsled_complete() */


static void
conskbd_mux_upstream_msg(conskbd_lower_queue_t *lqs, mblk_t *mp)
{
	conskbd_pending_msg_t	*msg;
	struct iocblk		*iocp;
	int			error;
	dev_t			devt;
	char			path[MAXPATHLEN + 1];

	ASSERT(lqs->lqs_state == LQS_INITIALIZED);
	msg = conskbd_mux_find_msg(mp);

	if (!msg) {
		/*
		 * Here we discard the response if:
		 *
		 *   1. It's an KIOCSLED request; see conskbd_streams_setled().
		 *   2. The application has already closed the upper stream;
		 *		see conskbdclose()
		 */
		freemsg(mp);
		return;
	}

	/*
	 * We use the b_next field of mblk_t structure to link all
	 * response coming from lower queues into a linkage list,
	 * and make use of the b_prev field to save a pointer to
	 * the lower queue from which the current response message
	 * comes.
	 */
	ASSERT(mp->b_next == NULL && mp->b_prev == NULL);
	mutex_enter(&msg->kpm_lock);
	mp->b_next = msg->kpm_resp_list;
	mp->b_prev = (mblk_t *)lqs;
	msg->kpm_resp_list = mp;
	msg->kpm_resp_nums ++;

	if (msg->kpm_resp_nums < msg->kpm_req_nums) {
		mutex_exit(&msg->kpm_lock);
		return;
	}

	ASSERT(msg->kpm_resp_nums == msg->kpm_req_nums);
	ASSERT(mp == msg->kpm_resp_list);

	mutex_exit(&msg->kpm_lock);

	conskbd_mux_dequeue_msg(msg);


	/*
	 * Here, we have the policy that, if any one lower queue ACK
	 * our reuqest, then we return ACK to upstreams; only if all
	 * lower queues NAK our request, we return NAK to upstreams.
	 * if all responses are nak, the errno of the  first response
	 * is sent to upstreams
	 */
	ASSERT(mp->b_rptr);
	error = ((struct iocblk *)mp->b_rptr)->ioc_error;

	switch (msg->kpm_req_cmd) {
	case CONSOPENPOLLEDIO:
		/*
		 * Here, we can safely ignore the NAK message. If any one lower
		 * queue returns NAK, the pointer to the corresponding polledio
		 * structure will remain null, that's say lqs->lqs_polledio =
		 * null. When we need to invoke polled I/O interface, we will
		 * check if the pointer is null.
		 */
		for (mp = msg->kpm_resp_list; mp; ) {
			cons_polledio_t		*polledio;

			msg->kpm_resp_list = mp->b_next;
			lqs = (conskbd_lower_queue_t *)mp->b_prev;
			devt = lqs->lqs_queue->q_stream->sd_vnode->v_rdev;
			if (mp->b_datap->db_type == M_IOCACK) {
				polledio = *(struct cons_polledio **)
				    mp->b_cont->b_rptr;
				if (polledio->cons_polledio_version ==
				    CONSPOLLEDIO_V1) {
					lqs->lqs_polledio = polledio;
					error = 0;
				} else {
					/*
					 * USB and PS2 keyboard drivers should
					 * use the same cons_polledio structure
					 * as conskbd.
					 */
					if (ddi_dev_pathname(devt, S_IFCHR,
					    path) == DDI_SUCCESS) {
						cmn_err(CE_WARN, "keyboard "
						    "driver does not support "
						    "system debugging: %s",
						    path);
					}
					error = EINVAL;
				}
			} else {
				if (ddi_dev_pathname(devt, S_IFCHR, path) ==
				    DDI_SUCCESS) {
					cmn_err(CE_WARN, "conskbd: keyboard is"
					    " not available for system"
					    " debugging:  %s", path);
				}
			}
			mp->b_next = NULL;
			mp->b_prev = NULL;
			freemsg(mp);
			mp = msg->kpm_resp_list;
		}

		mp = msg->kpm_req_msg;
		if (error == 0) {
			*(struct cons_polledio **)mp->b_cont->b_rptr =
			    &conskbd.conskbd_polledio;
		}
		break;

	case CONSCLOSEPOLLEDIO:
		for (mp = msg->kpm_resp_list; mp; ) {
			msg->kpm_resp_list = mp->b_next;
			lqs = (conskbd_lower_queue_t *)mp->b_prev;
			if (mp->b_datap->db_type == M_IOCACK) {
				lqs->lqs_polledio = NULL;
				error = 0;
			} else {
				devt =
				    lqs->lqs_queue->q_stream->sd_vnode->v_rdev;

				if (ddi_dev_pathname(devt, S_IFCHR, path) ==
				    DDI_SUCCESS) {
					cmn_err(CE_WARN, "conskbd: keyboard is"
					    " not available: %s", path);
				}
			}

			mp->b_next = NULL;
			mp->b_prev = NULL;
			freemsg(mp);
			mp = msg->kpm_resp_list;
		}
		break;

	case KIOCCMD:
	case KIOCMKTONE:
		for (mp = msg->kpm_resp_list; mp; ) {
			msg->kpm_resp_list = mp->b_next;

			if (mp->b_datap->db_type == M_IOCACK)
				error = 0;
			mp->b_next = NULL;
			mp->b_prev = NULL;
			freemsg(mp);
			mp = msg->kpm_resp_list;
		}
		break;

	default:  /* it is impossible to reach here */
		cmn_err(CE_WARN, "conskbd: unexpected ioctl reply");
	}

	mp = msg->kpm_req_msg;
	if (error == 0) {
		mp->b_datap->db_type = M_IOCACK;
	} else {
		mp->b_datap->db_type = M_IOCNAK;
	}
	iocp = (struct iocblk *)mp->b_rptr;
	iocp->ioc_error = error;
	qreply(msg->kpm_upper_queue, mp);
	mutex_destroy(&msg->kpm_lock);
	kmem_free(msg, sizeof (*msg));

}	/* conskbd_mux_upstream_msg() */

static void
conskbd_link_lowque_legacy(queue_t *lowque, mblk_t *mp)
{
	conskbd_lower_queue_t *lqs;

	freemsg(mp);

	/*
	 * Bypass the virutal keyboard for old hardware,
	 * Now, only current legacy keyboard can be linked
	 * under conskbd
	 */
	conskbd.conskbd_bypassed = B_TRUE;

	/*
	 * Link the lower queue under conskbd
	 */
	lqs = (conskbd_lower_queue_t *)lowque->q_ptr;
	lqs->lqs_state = LQS_INITIALIZED_LEGACY;
	lqs->lqs_next = conskbd.conskbd_lqueue_list;
	conskbd.conskbd_lqueue_list = lqs;
	conskbd.conskbd_lqueue_nums++;

	mioc2ack(lqs->lqs_pending_plink, NULL, 0, 0);
	qreply(lqs->lqs_pending_queue, lqs->lqs_pending_plink);

}	/* conskbd_link_lowque_legacy() */

static void
conskbd_link_lowque_virt(queue_t *lowque, mblk_t *mp)
{
	int		index;
	conskbd_lower_queue_t *lqs;

	freemsg(mp);

	lqs = (conskbd_lower_queue_t *)lowque->q_ptr;

	ASSERT(lqs->lqs_queue == lowque);
	ASSERT(lqs->lqs_pending_plink != NULL);

	/*
	 * Now, link the lower queue under conskbd
	 */
	for (index = 0; index < KBTRANS_KEYNUMS_MAX; index ++) {
		lqs->lqs_key_state[index] = KEY_RELEASED;
	}
	lqs->lqs_next = conskbd.conskbd_lqueue_list;
	lqs->lqs_state = LQS_INITIALIZED;
	conskbd.conskbd_lqueue_nums++;
	conskbd.conskbd_lqueue_list = lqs;
	mioc2ack(lqs->lqs_pending_plink, NULL, 0, 0);
	qreply(lqs->lqs_pending_queue, lqs->lqs_pending_plink);

}	/* conskbd_link_lowque_virt() */

/*ARGSUSED*/
static void
conskbd_legacy_upstream_msg(conskbd_lower_queue_t *lqs, mblk_t *mp)
{
	struct iocblk	*iocp;

	ASSERT(lqs && lqs->lqs_state == LQS_INITIALIZED_LEGACY);

	/*
	 * We assume that all of the ioctls are headed to the
	 * conskbd_regqueue if it is open.  We are intercepting a few ioctls
	 * that we know belong to conskbd_consqueue, and sending them there.
	 * Any other, new ioctls that have to be routed to conskbd_consqueue
	 * should be added to this list.
	 */
	iocp = (struct iocblk *)mp->b_rptr;

	if ((iocp->ioc_cmd == CONSOPENPOLLEDIO) ||
	    (iocp->ioc_cmd == CONSCLOSEPOLLEDIO)) {

		DPRINTF(PRINT_L1, PRINT_MASK_ALL,
		    ("conskbd_legacy_upstream_msg: "
		    "CONSOPEN/CLOSEPOLLEDIO ACK/NAK\n"));
		putnext(conskbd_consqueue, mp);

	} else if (conskbd_regqueue != NULL) {
		DPRINTF(PRINT_L1, PRINT_MASK_ALL,
		    ("conskbd_legacy_upstream_msg: conskbd_regqueue != NULL"));

		putnext(conskbd_regqueue, mp);

	} else if (conskbd_consqueue != NULL) {
		DPRINTF(PRINT_L1, PRINT_MASK_ALL,
		    ("conskbd_legacy_upstream_msg: conskbd_consqueue != NULL"));
		putnext(conskbd_consqueue, mp);
	} else {
		/* if reached here, it must be a error */
		cmn_err(CE_WARN,
		    "kb:  no destination for IOCACK/IOCNAK!");
		freemsg(mp);
	}

}	/* conskbd_legacy_upstream_msg() */

/*
 * This routine is a callback routine for kbtrans module to set LED.
 * Kbtrans will invoke it in two cases:
 *
 * 1) application initiated request
 *	A KIOCSLED ioctl is sent by an application. The ioctl will be
 *	be prcoessed by queue service procedure conskbduwsrv(), which
 *	in turn calls kbtrans to process the ioctl. Then kbtrans invokes
 *	conskbd_streams_setled() to set LED, after that,  kbtrans will
 *	return an ACK message to upper module.
 *
 * 2) Kbtrans initiated the request
 *	When conskbd works in TR_ASCII translation mode, if anyone of
 *	CapsLock, NumberLock and Compose keys is pressed, kbtrans need
 *	to set LED. In this case, there is no ioctl from upper module.
 *	There is no requirement to send response to somebody.
 *
 * In first case, kbtrans will send response to upper module; and in the
 * second, we don't need to send response. So conskbd_streams_setled()
 * has no return value.
 */
static void
conskbd_streams_setled(struct kbtrans_hardware *hw, int led_state)
{
	conskbd_state_t  *conskbdp = (conskbd_state_t *)hw;
	conskbd_lower_queue_t *lqs;
	mblk_t		*req;

	ASSERT(&conskbd == conskbdp);

	if (led_state == -1)
		return;

	conskbdp->conskbd_led_state = led_state;

	/*
	 * Basically, failing to set LED is not a fatal error, we just skip
	 * it if this happens.
	 */
	for (lqs = conskbdp->conskbd_lqueue_list; lqs; lqs = lqs->lqs_next) {
		req = mkiocb(KIOCSLED);

		if (!req) {
			continue;
		}

		req->b_cont = allocb(sizeof (uchar_t), BPRI_MED);
		if (!req->b_cont) {
			freemsg(req);
			continue;
		}
		*(uchar_t *)req->b_cont->b_wptr = led_state;
		req->b_cont->b_wptr += sizeof (uchar_t);
		if (putq(lqs->lqs_queue, req) != 1)
			freemsg(req);
	}

}	/* conskbd_streams_setled() */

static void
conskbd_polledio_setled(struct kbtrans_hardware *hw, int led_state)
{
	conskbd_state_t  *conskbdp = (conskbd_state_t *)hw;
	struct cons_polledio		*cb;
	conskbd_lower_queue_t	*lqs;

	for (lqs = conskbdp->conskbd_lqueue_list; lqs; lqs = lqs->lqs_next) {
		cb = lqs->lqs_polledio;
		if ((cb != NULL) && (cb->cons_polledio_setled != NULL)) {
			cb->cons_polledio_setled(cb->cons_polledio_argument,
			    led_state);
		}
	}

}	/* conskbd_polledio_setled() */

static boolean_t
conskbd_polled_keycheck(struct kbtrans_hardware *hw,
    kbtrans_key_t *keycode, enum keystate *state)
{
	conskbd_state_t  *conskbdp = (conskbd_state_t *)hw;
	struct cons_polledio	*cb;
	conskbd_lower_queue_t	*lqs;
	boolean_t	ret = B_FALSE;

	for (ret = B_FALSE, lqs = conskbdp->conskbd_lqueue_list; lqs != NULL;
	    lqs = lqs->lqs_next) {
		cb = lqs->lqs_polledio;
		if ((cb != NULL) &&
		    (cb->cons_polledio_keycheck != NULL)) {
			ret = cb->cons_polledio_keycheck(
			    cb->cons_polledio_argument, keycode, state);
		}

		/* Get a char from lower queue(hardware) ? */
		if (ret == B_TRUE) {

			/* A legacy keyboard ? */
			if (conskbd.conskbd_bypassed == B_TRUE)
				break;

			/*
			 * This is the PS2 scancode 0x2B -> USB(49) /
			 * USB(50) keycode mapping workaround, for
			 * polled mode.
			 *
			 * There are two possible USB keycode mappings
			 * for PS2 scancode 0x2B and this workaround
			 * makes sure that we use the USB keycode that
			 * does not end up being mapped to a HOLE key
			 * using the current keyboard translation
			 * tables.
			 *
			 * See conskbdlrput() for a detailed
			 * explanation of the problem.
			 */
			if (*keycode == 49 || *keycode == 50) {
				if (conskbd_keyindex->k_normal[50] == HOLE)
					*keycode = 49;
				else
					*keycode = 50;
			}

			break;
		}
	}

	return (ret);

}	/* conskbd_polled_keycheck() */

static boolean_t
conskbd_override_kbtrans(queue_t *q, mblk_t *mp)
{
	struct iocblk		*iocp;
	int		directio;
	int		error;

	if (mp->b_datap->db_type != M_IOCTL)
		return (B_FALSE);

	iocp = (struct iocblk *)mp->b_rptr;

	switch (iocp->ioc_cmd) {
	case KIOCGDIRECT: {
		/*
		 * Don't let the kbtrans-based code see this; it will
		 * respond incorrectly.
		 */
		register mblk_t *datap;

		if ((datap = allocb((int)sizeof (int), BPRI_MED)) == NULL) {
			miocnak(q, mp, 0, ENOMEM);
			return (B_TRUE);
		}

		*(int *)datap->b_wptr = conskbd.conskbd_directio;
		datap->b_wptr += sizeof (int);
		if (mp->b_cont) {
			freemsg(mp->b_cont);
			mp->b_cont = NULL;
		}
		mp->b_cont = datap;
		miocack(q, mp, sizeof (int), 0);
		return (B_TRUE);
	}

	case KIOCSDIRECT:
		/*
		 * Peek at this, set our variables, and then let the kbtrans
		 * based code see it and respond to it.
		 */
		error = miocpullup(mp, sizeof (int));
		if (error != 0) {
			return (B_FALSE);
		}

		directio = *(int *)mp->b_cont->b_rptr;
		if (directio != 0 && directio != 1) {
			miocnak(q, mp, 0, EINVAL);
			return (B_TRUE);
		}
		conskbd.conskbd_directio = directio;

		if (conskbd.conskbd_directio) {
			kbtrans_streams_set_queue(
			    conskbd.conskbd_kbtrans, conskbd_regqueue);
		} else {
			kbtrans_streams_set_queue(
			    conskbd.conskbd_kbtrans, conskbd_consqueue);
		}

		/*
		 * Let the kbtrans-based code see this and respond to it.
		 */
		return (B_FALSE);

	default:
		return (B_FALSE);
	}

}	/* conskbd_override_kbtrans() */


static void
conskbd_polledio_enter(cons_polledio_arg_t arg)
{
	conskbd_state_t		*conskbdp;
	struct cons_polledio		*cb;
	conskbd_lower_queue_t	*lqs;

	conskbdp = (conskbd_state_t *)arg;
	for (lqs = conskbdp->conskbd_lqueue_list; lqs; lqs = lqs->lqs_next) {
		cb = lqs->lqs_polledio;
		if ((cb != NULL) && (cb->cons_polledio_enter != NULL)) {
			cb->cons_polledio_enter(cb->cons_polledio_argument);
		}
	}

}	/* conskbd_polledio_enter() */

static void
conskbd_polledio_exit(cons_polledio_arg_t arg)
{
	conskbd_state_t		*conskbdp;
	struct cons_polledio		*cb;
	conskbd_lower_queue_t	*lqs;

	conskbdp = (conskbd_state_t *)arg;
	for (lqs = conskbdp->conskbd_lqueue_list; lqs; lqs = lqs->lqs_next) {
		cb = lqs->lqs_polledio;
		if ((cb != NULL) && (cb->cons_polledio_exit != NULL)) {
			cb->cons_polledio_exit(cb->cons_polledio_argument);
		}
	}

}	/* conskbd_polledio_exit() */

static int
conskbd_polledio_getchar(cons_polledio_arg_t arg)
{
	conskbd_state_t  *conskbdp;

	conskbdp = (conskbd_state_t *)arg;

	return (kbtrans_getchar(conskbdp->conskbd_kbtrans));

}	/* conskbd_polledio_getchar() */

static int
conskbd_polledio_ischar(cons_polledio_arg_t arg)
{
	conskbd_state_t  *conskbdp;

	conskbdp = (conskbd_state_t *)arg;

	return (kbtrans_ischar(conskbdp->conskbd_kbtrans));

}	/* conskbd_polledio_ischar() */


static void
conskbd_mux_enqueue_msg(conskbd_pending_msg_t *msg)
{
	mutex_enter(&conskbd_msgq_lock);
	msg->kpm_next = conskbd_msg_queue;
	conskbd_msg_queue = msg;
	mutex_exit(&conskbd_msgq_lock);

}	/* conskbd_mux_enqueue_msg() */

/*
 * the messages in conskbd_msg_queue we just enqueue
 */
static conskbd_pending_msg_t *
conskbd_mux_find_msg(mblk_t *mp)
{
	conskbd_pending_msg_t	*msg;
	struct iocblk		*iocp;
	uint_t	id;

	mutex_enter(&conskbd_msgq_lock);
	msg = conskbd_msg_queue;

	iocp = (struct iocblk *)mp->b_rptr;
	ASSERT(iocp);
	id = iocp->ioc_id;
	while (msg && msg->kpm_req_id != id) {
		msg = msg->kpm_next;
	}
	mutex_exit(&conskbd_msgq_lock);

	return (msg);

}	/* conskbd_mux_find_msg() */


static void
conskbd_mux_dequeue_msg(conskbd_pending_msg_t *msg)
{
	conskbd_pending_msg_t *prev;
	conskbd_pending_msg_t *p;

	mutex_enter(&conskbd_msgq_lock);
	prev = conskbd_msg_queue;

	for (p = prev; p && p != msg; p = p->kpm_next)
		prev = p;

	ASSERT(p && p == msg);

	if (prev == p) {
		conskbd_msg_queue = msg->kpm_next;
	} else {
		prev->kpm_next = p->kpm_next;
	}
	p->kpm_next = NULL;
	mutex_exit(&conskbd_msgq_lock);

}	/* conskbd_mux_dequeue_msg() */

#ifdef DEBUG
/*ARGSUSED*/
void
conskbd_dprintf(const char *fmt, ...)
{
	char buf[256];
	va_list ap;

	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);

	cmn_err(CE_CONT, "conskbd: %s", buf);

}	/* conskbd_dprintf() */
#endif
