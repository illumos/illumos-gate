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
/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#define	KEYMAP_SIZE_VARIABLE

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/inline.h>
#include <sys/termio.h>
#include <sys/stropts.h>
#include <sys/termios.h>
#include <sys/stream.h>
#include <sys/strtty.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/note.h>
#include "sys/consdev.h"
#include <sys/kbd.h>
#include <sys/kbtrans.h>
#include "kb8042.h"

#include <sys/i8042.h>

#include "sys/kbio.h"		/* for KIOCSLAYOUT */
#include "sys/stat.h"
#include "sys/reboot.h"
#include <sys/promif.h>
#include <sys/beep.h>
#include <sys/inttypes.h>
#include <sys/policy.h>

/*
 * For any keyboard, there is a unique code describing the position
 * of the key on a keyboard. We refer to the code as "station number".
 * The following table is used to map the station numbers from ps2
 * AT/XT keyboards to that of a USB one.
 *
 * A mapping was added for entry K8042_STOP, to map to USB key code 120 (which
 * maps to the STOP key) when in KB_USB mode, and maps to a HOLE entry
 * when in KB_PC mode.  Note that this does not need to be made conditional
 * on the architecture for which this module is complied because there are no
 * keys that map to K8042_STOP on non-SPARC platforms.
 */
static kbtrans_key_t keytab_pc2usb[KBTRANS_KEYNUMS_MAX] = {
/*  0 */	0,	53,	30,	31,	32,	33,	34,	35,
/*  8 */	36,	37,	38,	39,	45,	46,	137,	42,
/* 16 */	43,	20,	26,	8,	21,	23,	28,	24,
/* 24 */	12,	18,	19,	47,	48,	49,	57,	4,
/* 32 */	22,	7,	9,	10,	11,	13,	14,	15,
/* 40 */	51,	52,	50,	40,	225,	100,	29,	27,
/* 48 */	6,	25,	5,	17,	16,	54,	55,	56,
/* 56 */	135,	229,	224,	227,	226,	44,	230,	231,
/* 64 */	228,	101,	0,	0,	0,	0,	0,	0,
/* 72 */	0,	0,	0,	73,	76,	0,	0,	80,
/* 80 */	74,	77,	0,	82,	81,	75,	78,	0,
/* 88 */	0,	79,	83,	95,	92,	89,	0,	84,
/* 96 */	96,	93,	90,	98,	85,	97,	94,	91,
/* 104 */	99,	86,	87,	133,	88,	0,	41,	0,
/* 112 */	58,	59,	60,	61,	62,	63,	64,	65,
/* 120 */	66,	67,	68,	69,	70,	71,	72,	0,
/* 128 */	0,	0,	0,	139,	138,	136,	0,	0,
/* 136 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 144 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 152 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 160 */	120,	0,	0,	0,	0,	0,	0,	0,
/* 168 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 176 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 184 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 192 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 200 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 208 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 216 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 224 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 232 */	0,	128,	129,	127,	0,	0,	0,	0,
/* 240 */	0,	0,	0,	0,	0,	0,	0,	0,
/* 248 */	0,	0,	0,	0
};

#ifdef __sparc
#define	USECS_PER_WAIT 100
#define	MAX_WAIT_USECS 100000 /* in usecs = 100 ms */
#define	MIN_DELAY_USECS USECS_PER_WAIT

boolean_t kb8042_warn_unknown_scanset = B_TRUE;
int kb8042_default_scanset = 2;

#endif

#define	MAX_KB8042_WAIT_MAX_MS	500		/* 500ms total */
#define	MAX_KB8042_RETRIES	5

enum state_return { STATE_NORMAL, STATE_INTERNAL };

static void kb8042_init(struct kb8042 *kb8042, boolean_t from_resume);
static uint_t kb8042_intr(caddr_t arg);
static void kb8042_wait_poweron(struct kb8042 *kb8042);
static void kb8042_send_to_keyboard(struct kb8042 *, int, boolean_t);
static int kb8042_xlate_leds(int);
static void kb8042_setled(struct kb8042 *, int led_state, boolean_t polled);
static void kb8042_streams_setled(struct kbtrans_hardware *hw, int led_state);
static void kb8042_polled_setled(struct kbtrans_hardware *hw, int led_state);
static boolean_t kb8042_polled_keycheck(
			struct kbtrans_hardware *hw, int *key,
			enum keystate *state);
static void kb8042_get_initial_leds(struct kb8042 *, int *, int *);
static boolean_t kb8042_autorepeat_detect(struct kb8042 *kb8042, int key_pos,
			enum keystate state);
static void kb8042_type4_cmd(struct kb8042 *kb8042, int cmd);
static void kb8042_ioctlmsg(struct kb8042 *kb8042, queue_t *, mblk_t *);
static void kb8042_iocdatamsg(queue_t *, mblk_t *);
static void kb8042_process_key(struct kb8042 *, kbtrans_key_t, enum keystate);
static int kb8042_polled_ischar(cons_polledio_arg_t arg);
static int kb8042_polled_getchar(cons_polledio_arg_t arg);
static void kb8042_cleanup(struct kb8042 *kb8042);
static void kb8042_received_byte(struct kb8042 *, int);

static struct kbtrans_callbacks kb8042_callbacks = {
	kb8042_streams_setled,
	kb8042_polled_setled,
	kb8042_polled_keycheck,
};

extern struct keyboard keyindex_pc;

#define	DRIVER_NAME(dip) ddi_driver_name(dip)

static	char	module_name[] = "kb8042";

static int kb8042_open(queue_t *qp, dev_t *devp, int flag, int sflag,
			cred_t *credp);
static int kb8042_close(queue_t *qp, int flag, cred_t *credp);
static int kb8042_rsrv(queue_t *);
static int kb8042_wsrv(queue_t *);

struct module_info kb8042_sinfo = {
	.mi_idnum = 42,			/* Module ID */
	.mi_idname = module_name,	/* Module name */
	.mi_minpsz = 0,			/* Minimum packet size */
	.mi_maxpsz = 32,		/* Maximum packet size */
	.mi_hiwat = 256,		/* High water mark */
	.mi_lowat = 128			/* Low water mark */
};

static struct qinit kb8042_rinit = {
	.qi_putp = NULL,
	.qi_srvp = kb8042_rsrv,
	.qi_qopen = kb8042_open,
	.qi_qclose = kb8042_close,
	.qi_qadmin = NULL,
	.qi_minfo = &kb8042_sinfo,
	.qi_mstat = NULL,
	.qi_rwp = NULL,
	.qi_infop = NULL,
	.qi_struiot = 0
};

static struct qinit kb8042_winit = {
	.qi_putp = putq,
	.qi_srvp = kb8042_wsrv,
	.qi_qopen = kb8042_open,
	.qi_qclose = kb8042_close,
	.qi_qadmin = NULL,
	.qi_minfo = &kb8042_sinfo,
	.qi_mstat = NULL,
	.qi_rwp = NULL,
	.qi_infop = NULL,
	.qi_struiot = 0
};

struct streamtab kb8042_str_info = {
	.st_rdinit = &kb8042_rinit,
	.st_wrinit = &kb8042_winit,
	.st_muxrinit = NULL,
	.st_muxwinit = NULL
};

struct kb8042	Kdws = {0};
static dev_info_t *kb8042_dip = NULL;

static int kb8042_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg,
		void **result);
static int kb8042_attach(dev_info_t *, ddi_attach_cmd_t);
static int kb8042_detach(dev_info_t *, ddi_detach_cmd_t);

static struct cb_ops cb_kb8042_ops = {
	.cb_open = nulldev,
	.cb_close = nulldev,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = nodev,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = nochpoll,
	.cb_prop_op = ddi_prop_op,
	.cb_str = &kb8042_str_info,
	.cb_flag = D_MP,
	.cb_rev = CB_REV,
	.cb_aread = nodev,
	.cb_awrite = nodev
};

struct dev_ops kb8042_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = kb8042_getinfo,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = kb8042_attach,
	.devo_detach = kb8042_detach,
	.devo_reset = nodev,
	.devo_cb_ops = &cb_kb8042_ops,
	.devo_bus_ops = NULL,
	.devo_power = NULL,
	.devo_quiesce = ddi_quiesce_not_needed
};


/*
 * This is the loadable module wrapper.
 */
#include <sys/modctl.h>

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	.drv_modops = &mod_driverops,	/* Type of module. */
	.drv_linkinfo = "PS/2 keyboard driver",
	.drv_dev_ops = &kb8042_ops,	/* driver ops */
};

static struct modlinkage modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &modldrv, NULL }
};

int
_init(void)
{
	int	rv;

	rv = mod_install(&modlinkage);
	return (rv);
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

#ifdef __sparc
static boolean_t
kb8042_is_input_avail(struct kb8042 *kb8042, int timeout_usec, boolean_t polled)
{
	int i;
	int port = (polled == B_TRUE) ? I8042_POLL_INPUT_AVAIL :
	    I8042_INT_INPUT_AVAIL;
	int reps = timeout_usec / USECS_PER_WAIT;

	for (i = 0; i < reps; i++) {
		if (ddi_get8(kb8042->handle, kb8042->addr + port) != 0)
			return (B_TRUE);

		if (i < (reps - 1))
			drv_usecwait(USECS_PER_WAIT);
	}
	return (B_FALSE);
}

static void
kb8042_clear_input_buffer(struct kb8042 *kb8042, boolean_t polled)
{
	int port = (polled == B_TRUE) ? I8042_POLL_INPUT_DATA :
	    I8042_INT_INPUT_DATA;

	while (kb8042_is_input_avail(kb8042, MIN_DELAY_USECS, polled)) {
		(void) ddi_get8(kb8042->handle, kb8042->addr + port);
	}
}

/*
 * kb8042_send_and_expect does all its I/O via polling interfaces
 */
static boolean_t
kb8042_send_and_expect(struct kb8042 *kb8042, uint8_t send, uint8_t expect,
    int timeout, int *error, uint8_t *got)
{
	uint8_t datab;
	int err;
	boolean_t rval;

	ddi_put8(kb8042->handle,
	    kb8042->addr + I8042_POLL_OUTPUT_DATA, send);

	if (kb8042_is_input_avail(kb8042, timeout, B_TRUE)) {
		err = 0;
		datab = ddi_get8(kb8042->handle,
		    kb8042->addr + I8042_POLL_INPUT_DATA);
		rval = ((datab == expect) ? B_TRUE : B_FALSE);
	} else {
		err = EAGAIN;
		rval = B_FALSE;
	}

	if (error != NULL)
		*error = err;
	if (got != NULL)
		*got = datab;
	return (rval);
}

static const char *
kb8042_error_string(int errcode)
{
	switch (errcode) {
	case EAGAIN:
		return ("Timed out");
	default:
		return ("Unknown error");
	}
}

/*
 * kb8042_read_scanset works properly because it is called before ddi_add_intr
 * (if it is called after ddi_add_intr, i8042_intr would call kb8042_intr
 * instead of just storing the data that comes in from the keyboard, which
 * would prevent the code here from getting it.)
 */
static int
kb8042_read_scanset(struct kb8042 *kb8042)
{
	int scanset = -1;
	int err;
	uint8_t got;

	kb8042_clear_input_buffer(kb8042, B_TRUE);

	/*
	 * Send a "change scan code set" command to the keyboard.
	 * It should respond with an ACK.
	 */
	if (kb8042_send_and_expect(kb8042, KB_SET_SCAN, KB_ACK, MAX_WAIT_USECS,
	    &err, &got) != B_TRUE) {
		goto fail_read_scanset;
	}

	/*
	 * Send a 0.  The keyboard should ACK the 0, then it should send the
	 * scan code set in use.
	 */
	if (kb8042_send_and_expect(kb8042, 0, KB_ACK, MAX_WAIT_USECS, &err,
	    &got) != B_TRUE) {
		goto fail_read_scanset;
	}

	/*
	 * The next input byte from the keyboard should be the scan code
	 * set in use, though some keyboards like to send a few more acks
	 * just for fun, so blow past those to get the keyboard scan code.
	 */
	while (kb8042_is_input_avail(kb8042, MAX_WAIT_USECS, B_TRUE) &&
	    (scanset = ddi_get8(kb8042->handle,
	    kb8042->addr + I8042_POLL_INPUT_DATA)) == KB_ACK)
		;

#ifdef DEBUG
	cmn_err(CE_NOTE, "!Scan code set from keyboard is `%d'.",
	    scanset);
#endif

	return (scanset);

fail_read_scanset:
#ifdef DEBUG
	if (err == 0)
		cmn_err(CE_NOTE, "Could not read current scan set from "
		    "keyboard: %s. (Expected 0x%x, but got 0x%x).",
		    kb8042_error_string(err), KB_ACK, got);
	else
		cmn_err(CE_NOTE, "Could not read current scan set from "
		    "keyboard: %s.", kb8042_error_string(err));
#endif
	return (-1);
}
#endif

static int
kb8042_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int	rc;
	int	scanset;
	int	leds;

	struct kb8042	*kb8042 = &Kdws;
	static ddi_device_acc_attr_t attr = {
		DDI_DEVICE_ATTR_V0,
		DDI_NEVERSWAP_ACC,
		DDI_STRICTORDER_ACC,
	};

	switch (cmd) {
	case DDI_RESUME:
		leds = kb8042->leds.commanded;
		kb8042->w_init = 0;
		kb8042_init(kb8042, B_TRUE);
		kb8042_setled(kb8042, leds, B_FALSE);
		mutex_enter(&kb8042->w_hw_mutex);
		kb8042->suspended = B_FALSE;
		if (kb8042->w_qp != NULL) {
			enableok(WR(kb8042->w_qp));
			qenable(WR(kb8042->w_qp));
		}
		cv_broadcast(&kb8042->suspend_cv);
		mutex_exit(&kb8042->w_hw_mutex);
		return (DDI_SUCCESS);

	case DDI_ATTACH:
		if (kb8042_dip != NULL)
			return (DDI_FAILURE);
		/* The rest of the function is for attach */
		break;

	default:
		return (DDI_FAILURE);
	}

	kb8042->debugger.mod1 = 58;	/* Left Ctrl */
	kb8042->debugger.mod2 = 60;	/* Left Alt */
	kb8042->debugger.trigger = 33;	/* D */
	kb8042->debugger.mod1_down = B_FALSE;
	kb8042->debugger.mod2_down = B_FALSE;
	kb8042->debugger.enabled = B_FALSE;

	kb8042_dip = devi;
	kb8042->init_state = KB8042_UNINITIALIZED;

	kb8042->polled_synthetic_release_pending = B_FALSE;

	if (ddi_create_minor_node(devi, module_name, S_IFCHR, 0,
	    DDI_NT_KEYBOARD, 0) == DDI_FAILURE) {
		goto failure;
	}

	kb8042->init_state |= KB8042_MINOR_NODE_CREATED;

	rc = ddi_regs_map_setup(devi, 0, (caddr_t *)&kb8042->addr,
	    (offset_t)0, (offset_t)0, &attr, &kb8042->handle);
	if (rc != DDI_SUCCESS) {
#ifdef DEBUG
		cmn_err(CE_WARN, "kb8042_attach:  can't map registers");
#endif
		goto failure;
	}

	kb8042->init_state |= KB8042_REGS_MAPPED;

	if (ddi_get_iblock_cookie(devi, 0, &kb8042->w_iblock) !=
	    DDI_SUCCESS) {
		cmn_err(CE_WARN, "kb8042_attach:  Can't get iblock cookie");
		goto failure;
	}

	mutex_init(&kb8042->w_hw_mutex, NULL, MUTEX_DRIVER, kb8042->w_iblock);
	cv_init(&kb8042->ops_cv, NULL, CV_DRIVER, NULL);
	cv_init(&kb8042->suspend_cv, NULL, CV_DRIVER, NULL);
	cv_init(&kb8042->cmd_cv, NULL, CV_DRIVER, NULL);
	kb8042->init_state |= KB8042_HW_MUTEX_INITTED;

	kb8042_init(kb8042, B_FALSE);

#ifdef __sparc
	/* Detect the scan code set currently in use */
	scanset = kb8042_read_scanset(kb8042);

	if (scanset < 0 && kb8042_warn_unknown_scanset) {

		cmn_err(CE_WARN, "Cannot determine keyboard scan code set ");
		cmn_err(CE_CONT, "(is the keyboard plugged in?). ");
		cmn_err(CE_CONT, "Defaulting to scan code set %d.  If the "
		    "keyboard does not ", kb8042_default_scanset);
		cmn_err(CE_CONT, "work properly, add "
		    "`set kb8042:kb8042_default_scanset=%d' to /etc/system ",
		    (kb8042_default_scanset == 1) ? 2 : 1);
		cmn_err(CE_CONT, "(via network or with a USB keyboard) and "
		    "restart the system.  If you ");
		cmn_err(CE_CONT, "do not want to see this message in the "
		    "future, add ");
		cmn_err(CE_CONT, "`set kb8042:kb8042_warn_unknown_scanset=0' "
		    "to /etc/system.\n");

		/* Use the default scan code set. */
		scanset = kb8042_default_scanset;
	}
#else
	/* x86 systems use scan code set 1 -- no detection required */
	scanset = 1;
#endif
	if (KeyboardConvertScan_init(kb8042, scanset) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "Cannot initialize keyboard scan converter: "
		    "Unknown scan code set `%d'.", scanset);
		/* Scan code set is not supported */
		goto failure;
	}

	/*
	 * Turn on interrupts...
	 */
	if (ddi_add_intr(devi, 0,
	    &kb8042->w_iblock, (ddi_idevice_cookie_t *)NULL,
	    kb8042_intr, (caddr_t)kb8042) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "kb8042_attach: cannot add interrupt");
		goto failure;
	}

	kb8042->init_state |= KB8042_INTR_ADDED;

	ddi_report_dev(devi);

#ifdef DEBUG
	cmn_err(CE_CONT, "?%s instance #%d READY\n",
	    DRIVER_NAME(devi), ddi_get_instance(devi));
#endif

	return (DDI_SUCCESS);

failure:
	kb8042_cleanup(kb8042);
	return (DDI_FAILURE);
}

static int
kb8042_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct kb8042 *kb8042 = &Kdws;

	switch (cmd) {
	case DDI_SUSPEND:
		mutex_enter(&kb8042->w_hw_mutex);
		ASSERT(kb8042->ops >= 0);
		while (kb8042->ops > 0)
			cv_wait(&kb8042->ops_cv, &kb8042->w_hw_mutex);
		kb8042->suspended = B_TRUE;
		mutex_exit(&kb8042->w_hw_mutex);
		return (DDI_SUCCESS);

	case DDI_DETACH:
		/* If someone has a stream open, fail to detach */
		if (kb8042->w_qp != NULL)
			return (DDI_FAILURE);

		ASSERT(kb8042_dip == dip);

		kb8042_cleanup(kb8042);

		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
kb8042_getinfo(
    dev_info_t *dip,
    ddi_info_cmd_t infocmd,
    void *arg,
    void **result)
{
	register int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (kb8042_dip == NULL) {
			error = DDI_FAILURE;
		} else {
			*result = (void *) kb8042_dip;
			error = DDI_SUCCESS;
		}
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
		break;
	}
	return (error);
}

static void
kb8042_cleanup(struct kb8042 *kb8042)
{
	ASSERT(kb8042_dip != NULL);

	if (kb8042->init_state & KB8042_INTR_ADDED)
		ddi_remove_intr(kb8042_dip, 0, kb8042->w_iblock);

	if (kb8042->init_state & KB8042_HW_MUTEX_INITTED) {
		cv_destroy(&kb8042->cmd_cv);
		cv_destroy(&kb8042->suspend_cv);
		cv_destroy(&kb8042->ops_cv);
		mutex_destroy(&kb8042->w_hw_mutex);
	}

	if (kb8042->init_state & KB8042_REGS_MAPPED)
		ddi_regs_map_free(&kb8042->handle);

	if (kb8042->init_state & KB8042_MINOR_NODE_CREATED)
		ddi_remove_minor_node(kb8042_dip, NULL);

	kb8042->init_state = KB8042_UNINITIALIZED;
	kb8042_dip = NULL;
}

static void
kb8042_init(struct kb8042 *kb8042, boolean_t from_resume)
{
	if (kb8042->w_init)
		return;

	if (!from_resume) {
		kb8042->w_kblayout = 0;	/* Default to US */
		kb8042->w_qp = (queue_t *)NULL;
		kb8042->simulated_kbd_type = KB_PC;
		kb8042->leds.commanded = -1;	/* Unknown initial state */
		kb8042->leds.desired = -1;	/* Unknown initial state */
	}

	kb8042_wait_poweron(kb8042);

	kb8042->kb_old_key_pos = 0;

	/*
	 * Explicitly grab and release the 8042 lock outside of
	 * kb8042_send_to_keyboard, because this is the only situation
	 * where a polling interface is used with locking required.
	 */
	(void) ddi_get8(kb8042->handle, kb8042->addr + I8042_LOCK);
	/* Set up the command state machine and start it running. */
	kb8042_send_to_keyboard(kb8042, KB_ENABLE, B_TRUE);
	(void) ddi_get8(kb8042->handle, kb8042->addr + I8042_UNLOCK);

	kb8042->w_init++;

	(void) drv_setparm(SYSRINT, 1);	/* reset keyboard interrupts */
}

/*ARGSUSED2*/
static int
kb8042_open(queue_t *qp, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	struct kb8042	*kb8042;
	int err = 0;
	int initial_leds;
	int initial_led_mask;

	kb8042 = &Kdws;

	mutex_enter(&kb8042->w_hw_mutex);
	if (qp->q_ptr) {
		kb8042->w_dev = *devp;
		mutex_exit(&kb8042->w_hw_mutex);
		return (0);
	}

	if (secpolicy_console(credp) != 0) {
		mutex_exit(&kb8042->w_hw_mutex);
		return (EPERM);
	}

	while (kb8042->suspended) {
		if (cv_wait_sig(&kb8042->suspend_cv, &kb8042->w_hw_mutex) ==
		    0) {
			mutex_exit(&kb8042->w_hw_mutex);
			return (EINTR);
		}
	}

	kb8042->w_dev = *devp;
	qp->q_ptr = (caddr_t)kb8042;
	WR(qp)->q_ptr = qp->q_ptr;
	if (!kb8042->w_qp)
		kb8042->w_qp = qp;

	ASSERT(kb8042->ops >= 0);
	kb8042->ops++;
	mutex_exit(&kb8042->w_hw_mutex);

	kb8042_get_initial_leds(kb8042, &initial_leds, &initial_led_mask);
	err = kbtrans_streams_init(qp, sflag,
	    (struct kbtrans_hardware *)kb8042, &kb8042_callbacks,
	    &kb8042->hw_kbtrans,
	    initial_leds, initial_led_mask);
	if (err != 0)
		goto out;

	kbtrans_streams_set_keyboard(kb8042->hw_kbtrans, KB_PC, &keyindex_pc);

	kb8042->polledio.cons_polledio_version = CONSPOLLEDIO_V1;
	kb8042->polledio.cons_polledio_argument =
	    (cons_polledio_arg_t)kb8042;
	kb8042->polledio.cons_polledio_putchar = NULL;
	kb8042->polledio.cons_polledio_getchar =
	    (int (*)(cons_polledio_arg_t))kb8042_polled_getchar;
	kb8042->polledio.cons_polledio_ischar =
	    (boolean_t (*)(cons_polledio_arg_t))kb8042_polled_ischar;
	kb8042->polledio.cons_polledio_enter = NULL;
	kb8042->polledio.cons_polledio_exit = NULL;
	kb8042->polledio.cons_polledio_setled =
	    (void (*)(cons_polledio_arg_t, int))kb8042_polled_setled;
	kb8042->polledio.cons_polledio_keycheck =
	    (boolean_t (*)(cons_polledio_arg_t, int *,
	    enum keystate *))kb8042_polled_keycheck;

	qprocson(qp);

	kbtrans_streams_enable(kb8042->hw_kbtrans);

out:
	mutex_enter(&kb8042->w_hw_mutex);
	ASSERT(kb8042->ops > 0);
	kb8042->ops--;
	if (kb8042->ops == 0)
		cv_broadcast(&kb8042->ops_cv);
	mutex_exit(&kb8042->w_hw_mutex);

	return (err);
}

/*ARGSUSED1*/
static int
kb8042_close(queue_t *qp, int flag, cred_t *credp)
{
	struct kb8042	*kb8042;

	/* If a beep is in progress, stop that */
	(void) beeper_off();

	kb8042 = (struct kb8042 *)qp->q_ptr;

	mutex_enter(&kb8042->w_hw_mutex);
	while (kb8042->suspended) {
		if (cv_wait_sig(&kb8042->suspend_cv, &kb8042->w_hw_mutex) ==
		    0) {
			mutex_exit(&kb8042->w_hw_mutex);
			return (EINTR);
		}
	}

	ASSERT(kb8042->ops >= 0);
	kb8042->ops++;
	mutex_exit(&kb8042->w_hw_mutex);

	(void) kbtrans_streams_fini(kb8042->hw_kbtrans);

	kb8042->w_qp = (queue_t *)NULL;
	qprocsoff(qp);

	mutex_enter(&kb8042->w_hw_mutex);
	ASSERT(kb8042->ops > 0);
	kb8042->ops--;
	if (kb8042->ops == 0)
		cv_broadcast(&kb8042->ops_cv);
	mutex_exit(&kb8042->w_hw_mutex);

	return (0);
}

static int
kb8042_rsrv(queue_t *qp)
{
	mblk_t *mp;
	struct kb8042 *kb8042;

	while ((mp = getq(qp)) != NULL) {
		if (mp->b_datap->db_type == M_DATA) {
			kb8042 = (struct kb8042 *)qp->q_ptr;
			kb8042_received_byte(kb8042, *mp->b_rptr);
		}
		freemsg(mp);
	}
	return (0);
}

static int
kb8042_wsrv(queue_t *qp)
{
	struct kb8042 *kb8042;

	mblk_t	*mp;
	boolean_t suspended;

	kb8042 = (struct kb8042 *)qp->q_ptr;

	mutex_enter(&kb8042->w_hw_mutex);
	suspended = kb8042->suspended;
	ASSERT(kb8042->ops >= 0);
	if (!suspended)
		kb8042->ops++;
	mutex_exit(&kb8042->w_hw_mutex);

#ifdef NO_KB_DEBUG
	while (!suspended && (mp = getq(qp)) != NULL) {
#else
	/*
	 * Not taking keyboard input while suspending can make debugging
	 * difficult.  However, we still do the ops counting so that we
	 * don't suspend at a bad time.
	 */
	while ((mp = getq(qp))) {
#endif
		switch (kbtrans_streams_message(kb8042->hw_kbtrans, mp)) {
		case KBTRANS_MESSAGE_HANDLED:
			continue;
		case KBTRANS_MESSAGE_NOT_HANDLED:
			break;
		}
		switch (mp->b_datap->db_type) {
		case M_IOCTL:
			kb8042_ioctlmsg(kb8042, qp, mp);
			continue;
		case M_IOCDATA:
			kb8042_iocdatamsg(qp, mp);
			continue;
		case M_DELAY:
		case M_STARTI:
		case M_STOPI:
		case M_READ:	/* ignore, no buffered data */
			freemsg(mp);
			continue;
		case M_FLUSH:
			*mp->b_rptr &= ~FLUSHW;
			if (*mp->b_rptr & FLUSHR)
				qreply(qp, mp);
			else
				freemsg(mp);
			continue;
		default:
			cmn_err(CE_NOTE, "kb8042_wsrv: bad msg %x",
			    mp->b_datap->db_type);
			freemsg(mp);
			continue;
		}
	}

	mutex_enter(&kb8042->w_hw_mutex);
	if (!suspended) {
		ASSERT(kb8042->ops > 0);
		kb8042->ops--;
		if (kb8042->ops == 0)
			cv_broadcast(&kb8042->ops_cv);
	}
	mutex_exit(&kb8042->w_hw_mutex);

	return (0);
}

static void
kb8042_ioctlmsg(struct kb8042 *kb8042, queue_t *qp, mblk_t *mp)
{
	struct iocblk	*iocp;
	mblk_t		*datap;
	int		error;
	int		tmp;
	int		cycles;
	int		frequency;
	int		msecs;

	iocp = (struct iocblk *)mp->b_rptr;

	switch (iocp->ioc_cmd) {

	case CONSOPENPOLLEDIO:
		error = miocpullup(mp, sizeof (struct cons_polledio *));
		if (error != 0) {
			miocnak(qp, mp, 0, error);
			return;
		}

		/*
		 * We are given an appropriate-sized data block,
		 * and return a pointer to our structure in it.
		 */
		*(struct cons_polledio **)mp->b_cont->b_rptr =
		    &kb8042->polledio;
		mp->b_datap->db_type = M_IOCACK;
		iocp->ioc_error = 0;
		qreply(qp, mp);
		break;

	case CONSCLOSEPOLLEDIO:
		miocack(qp, mp, 0, 0);
		break;

	case CONSSETABORTENABLE:
		if (iocp->ioc_count != TRANSPARENT) {
			miocnak(qp, mp, 0, EINVAL);
			return;
		}

		kb8042->debugger.enabled = *(intptr_t *)mp->b_cont->b_rptr;
		miocack(qp, mp, 0, 0);
		break;

	/*
	 * Valid only in TR_UNTRANS_MODE mode.
	 */
	case CONSSETKBDTYPE:
		error = miocpullup(mp, sizeof (int));
		if (error != 0) {
			miocnak(qp, mp, 0, error);
			return;
		}
		tmp =  *(int *)mp->b_cont->b_rptr;
		if (tmp != KB_PC && tmp != KB_USB) {
			miocnak(qp, mp, 0, EINVAL);
			break;
		}
		kb8042->simulated_kbd_type = tmp;
		miocack(qp, mp, 0, 0);
		break;

	case KIOCLAYOUT:
		if (kb8042->w_kblayout == -1) {
			miocnak(qp, mp, 0, EINVAL);
			return;
		}

		if ((datap = allocb(sizeof (int), BPRI_HI)) == NULL) {
			miocnak(qp, mp, 0, ENOMEM);
			return;
		}

		if (kb8042->simulated_kbd_type == KB_USB)
			*(int *)datap->b_wptr = KBTRANS_USBKB_DEFAULT_LAYOUT;
		else
			*(int *)datap->b_wptr = kb8042->w_kblayout;

		datap->b_wptr += sizeof (int);
		if (mp->b_cont)
			freemsg(mp->b_cont);
		mp->b_cont = datap;
		iocp->ioc_count = sizeof (int);
		mp->b_datap->db_type = M_IOCACK;
		iocp->ioc_error = 0;
		qreply(qp, mp);
		break;

	case KIOCSLAYOUT:
		if (iocp->ioc_count != TRANSPARENT) {
			miocnak(qp, mp, 0, EINVAL);
			return;
		}

		kb8042->w_kblayout = *(intptr_t *)mp->b_cont->b_rptr;
		miocack(qp, mp, 0, 0);
		break;

	case KIOCCMD:
		error = miocpullup(mp, sizeof (int));
		if (error != 0) {
			miocnak(qp, mp, 0, error);
			return;
		}

		kb8042_type4_cmd(kb8042, *(int *)mp->b_cont->b_rptr);
		miocack(qp, mp, 0, 0);
		break;

	case KIOCMKTONE:
		if (iocp->ioc_count != TRANSPARENT) {
			miocnak(qp, mp, 0, EINVAL);
			return;
		}

		tmp = (int)(*(intptr_t *)mp->b_cont->b_rptr);
		cycles = tmp & 0xffff;
		msecs = (tmp >> 16) & 0xffff;

		if (cycles == 0)
			frequency = UINT16_MAX;
		else if (cycles == UINT16_MAX)
			frequency = 0;
		else {
			frequency = (PIT_HZ + cycles / 2) / cycles;
			if (frequency > UINT16_MAX)
				frequency = UINT16_MAX;
		}

		error = beep_mktone(frequency, msecs);
		if (error != 0)
			miocnak(qp, mp, 0, error);
		else
			miocack(qp, mp, 0, 0);
		break;

	default:
#ifdef DEBUG1
		cmn_err(CE_NOTE, "!kb8042_ioctlmsg %x", iocp->ioc_cmd);
#endif
		miocnak(qp, mp, 0, EINVAL);
		return;
	}
}

/*
 * Process a byte received from the keyboard
 */
static void
kb8042_received_byte(
	struct kb8042	*kb8042,
	int		scancode)	/* raw scan code */
{
	boolean_t	legit;		/* is this a legit key pos'n? */
	int		key_pos = -1;
	enum keystate	state;
	boolean_t	synthetic_release_needed;

	if (!kb8042->w_init)	/* can't do anything anyway */
		return;

	legit = KeyboardConvertScan(kb8042, scancode, &key_pos, &state,
	    &synthetic_release_needed);

	if (legit == 0) {
		/* Eaten by translation */
		return;
	}

	/*
	 * Don't know if we want this permanently, but it seems interesting
	 * for the moment.
	 */
	if (key_pos == kb8042->debugger.mod1) {
		kb8042->debugger.mod1_down = (state == KEY_PRESSED);
	}
	if (key_pos == kb8042->debugger.mod2) {
		kb8042->debugger.mod2_down = (state == KEY_PRESSED);
	}
	if (kb8042->debugger.enabled &&
	    key_pos == kb8042->debugger.trigger &&
	    kb8042->debugger.mod1_down &&
	    kb8042->debugger.mod2_down) {
		/*
		 * Require new presses of the modifiers.
		 */
		kb8042->debugger.mod1_down = B_FALSE;
		kb8042->debugger.mod2_down = B_FALSE;
		abort_sequence_enter(NULL);
		return;
	}

	/*
	 * If there's no queue above us - as can happen if we've been
	 * attached but not opened - drop the keystroke.
	 * Note that we do this here instead of above so that
	 * Ctrl-Alt-D still works.
	 */
	if (kb8042->w_qp == NULL) {
		return;
	}

	/*
	 * This is to filter out auto repeat since it can't be
	 * turned off at the hardware.  (Yeah, yeah, PS/2 keyboards
	 * can.  Don't know whether they've taken over the world.
	 * Don't think so.)
	 */
	if (kb8042_autorepeat_detect(kb8042, key_pos, state)) {
		return;
	}


	kb8042_process_key(kb8042, key_pos, state);

	/*
	 * This is a total hack.  For some stupid reason, the two additional
	 * keys on Korean keyboards (Hangul and Hangul/Hanja) report press
	 * only.  We synthesize a release immediately.
	 */
	if (synthetic_release_needed) {
		(void) kb8042_autorepeat_detect(kb8042, key_pos, KEY_RELEASED);
		kb8042_process_key(kb8042, key_pos, state);
	}
}


static void
kb8042_process_key(struct kb8042 *kb8042, kbtrans_key_t key_pos,
    enum keystate state)
{
	kbtrans_key_t key;

	ASSERT(key_pos >= 0 && key_pos <= 255);
	if (kb8042->simulated_kbd_type == KB_PC) {
		kbtrans_streams_key(kb8042->hw_kbtrans, key_pos, state);
	} else if (kb8042->simulated_kbd_type == KB_USB) {
		key = keytab_pc2usb[key_pos];
		if (key != 0) {
			kbtrans_streams_key(kb8042->hw_kbtrans, key, state);
		}
	}
}

/*
 * Called from interrupt handler when keyboard interrupt occurs.
 */
static uint_t
kb8042_intr(caddr_t arg)
{
	uchar_t scancode;	/* raw scan code */
	int rc;
	struct kb8042 *kb8042 = (struct kb8042 *)arg;

	rc = DDI_INTR_UNCLAIMED;

	if (kb8042->init_state == KB8042_UNINITIALIZED)
		return (DDI_INTR_UNCLAIMED);

	/* don't care if drv_setparm succeeds */
	(void) drv_setparm(SYSRINT, 1);

	while (ddi_get8(kb8042->handle, kb8042->addr + I8042_INT_INPUT_AVAIL)
	    != 0) {
		mblk_t *mp;

		rc = DDI_INTR_CLAIMED;

		scancode = ddi_get8(kb8042->handle,
		    kb8042->addr + I8042_INT_INPUT_DATA);

		/*
		 * Intercept ACK and RESEND and signal the condition that
		 * kb8042_send_and_wait is waiting for.
		 */
		switch (scancode) {
		case KB_ACK:
			mutex_enter(&kb8042->w_hw_mutex);
			kb8042->acked = 1;
			cv_signal(&kb8042->cmd_cv);
			mutex_exit(&kb8042->w_hw_mutex);
			return (rc);
		case KB_RESEND:
			mutex_enter(&kb8042->w_hw_mutex);
			kb8042->need_retry = 1;
			cv_signal(&kb8042->cmd_cv);
			mutex_exit(&kb8042->w_hw_mutex);
			return (rc);
		default:
			break;
		}

		if ((mp = allocb(sizeof (scancode), BPRI_HI)) == NULL)
			return (rc);
		*mp->b_wptr++ = scancode;
		if (putq(RD(kb8042->w_qp), mp) == 0)
			freemsg(mp);
	}

	return (rc);
}

static void
kb8042_iocdatamsg(queue_t *qp, mblk_t *mp)
{
	struct copyresp	*csp;

	csp = (struct copyresp *)mp->b_rptr;
	if (csp->cp_rval) {
		freemsg(mp);
		return;
	}

	switch (csp->cp_cmd) {
	default:
		miocack(qp, mp, 0, 0);
		break;
	}
}

static boolean_t
kb8042_polled_keycheck(
    struct kbtrans_hardware *hw,
    int *key,
    enum keystate *state)
{
	struct kb8042 *kb8042 = (struct kb8042 *)hw;
	int	scancode;
	boolean_t	legit;
	boolean_t	synthetic_release_needed;

	if (kb8042->polled_synthetic_release_pending) {
		*key = kb8042->polled_synthetic_release_key;
		*state = KEY_RELEASED;
		kb8042->polled_synthetic_release_pending = B_FALSE;
		(void) kb8042_autorepeat_detect(kb8042, *key, *state);
		return (B_TRUE);
	}

	for (;;) {
		if (ddi_get8(kb8042->handle,
		    kb8042->addr + I8042_POLL_INPUT_AVAIL) == 0) {
			return (B_FALSE);
		}

		scancode = ddi_get8(kb8042->handle,
		    kb8042->addr + I8042_POLL_INPUT_DATA);

		legit = KeyboardConvertScan(kb8042, scancode, key, state,
		    &synthetic_release_needed);
		if (!legit) {
			continue;
		}
		/*
		 * For the moment at least, we rely on hardware autorepeat
		 * for polled I/O autorepeat.  However, for coordination
		 * with the interrupt-driven code, maintain the last key
		 * pressed.
		 */
		(void) kb8042_autorepeat_detect(kb8042, *key, *state);

		/*
		 * This is a total hack to support two additional keys
		 * on Korean keyboards.  They report only on press, and
		 * so we synthesize a release.  Most likely this will
		 * never be important to polled  I/O, but if I do it
		 * "right" the first time it _won't_ be an issue.
		 */
		if (synthetic_release_needed) {
			kb8042->polled_synthetic_release_pending = B_TRUE;
			kb8042->polled_synthetic_release_key = *key;
		}

		if (kb8042->simulated_kbd_type == KB_USB) {
			*key = keytab_pc2usb[*key];
		}
		return (B_TRUE);
	}
}

static void
kb8042_setled(struct kb8042 *kb8042, int led_state, boolean_t polled)
{
	kb8042->leds.desired = led_state;

	if (!polled)
		mutex_enter(&kb8042->w_hw_mutex);

	if (kb8042->leds.desired != kb8042->leds.commanded) {
		kb8042_send_to_keyboard(kb8042, KB_SET_LED, polled);
	}

	if (!polled)
		mutex_exit(&kb8042->w_hw_mutex);
}

static void
kb8042_polled_setled(struct kbtrans_hardware *hw, int led_state)
{
	struct kb8042 *kb8042 = (struct kb8042 *)hw;
	kb8042_setled(kb8042, led_state, B_TRUE);
}

static void
kb8042_streams_setled(struct kbtrans_hardware *hw, int led_state)
{
	struct kb8042 *kb8042 = (struct kb8042 *)hw;
	kb8042_setled(kb8042, led_state, B_FALSE);
}


static int
kb8042_send_and_wait(struct kb8042 *kb8042, uint8_t u8, boolean_t polled)
{
	uint8_t *outp = kb8042->addr +
	    (polled ? I8042_POLL_OUTPUT_DATA : I8042_INT_OUTPUT_DATA);
	uint8_t *inavp = kb8042->addr +
	    (polled ? I8042_POLL_INPUT_AVAIL : I8042_INT_INPUT_AVAIL);
	uint8_t *inp = kb8042->addr +
	    (polled ? I8042_POLL_INPUT_DATA : I8042_INT_INPUT_DATA);
	uint8_t b;
	int ms_waited;
	int timedout;
	int expire;
	int retries = 0;

	do {
		kb8042->acked = 0;
		kb8042->need_retry = 0;
		ms_waited = 0;		/* Zero it whether polled or not */
		timedout = 0;

		ddi_put8(kb8042->handle, outp, u8);

		while (!kb8042->acked && !kb8042->need_retry && !timedout) {

			if (polled) {
				if (ddi_get8(kb8042->handle, inavp)) {
					b = ddi_get8(kb8042->handle, inp);
					switch (b) {
					case KB_ACK:
						kb8042->acked = 1;
						break;
					case KB_RESEND:
						kb8042->need_retry = 1;
						break;
					default:
						/*
						 * drop it: We should never
						 * get scancodes while
						 * we're in the middle of a
						 * command anyway.
						 */
#ifdef DEBUG
						cmn_err(CE_WARN, "!Unexpected "
						    " byte 0x%x", b);
#endif
						break;
					}
				}

				/*
				 * Wait 1ms if an ACK wasn't received yet
				 */
				if (!kb8042->acked) {
					drv_usecwait(1000);
					ms_waited++;
					if (ms_waited >= MAX_KB8042_WAIT_MAX_MS)
						timedout = B_TRUE;
				}
			} else {
				/* Interrupt-driven */
				expire = ddi_get_lbolt() +
				    drv_usectohz(MAX_KB8042_WAIT_MAX_MS * 1000);

				/*
				 * If cv_timedwait returned -1 and we neither
				 * received an ACK nor a RETRY response, then
				 * we timed out.
				 */
				if (cv_timedwait(&kb8042->cmd_cv,
				    &kb8042->w_hw_mutex, expire) == -1 &&
				    !kb8042->acked && !kb8042->need_retry) {
					timedout = B_TRUE;
				}
			}

		}
	} while ((kb8042->need_retry || timedout) &&
	    ++retries < MAX_KB8042_RETRIES);

	return (kb8042->acked);
}

/*
 * kb8042_send_to_keyboard should be called with w_hw_mutex held if
 * polled is FALSE.
 */
static void
kb8042_send_to_keyboard(struct kb8042 *kb8042, int byte, boolean_t polled)
{

	/*
	 * KB_SET_LED and KB_ENABLE are special commands which require blocking
	 * other 8042 consumers while executing.
	 *
	 * Other commands/data are sent using the single put8 I/O access
	 * function.
	 */
	if (byte == KB_SET_LED) {

		if (!polled) {
			(void) ddi_get8(kb8042->handle, kb8042->addr +
			    I8042_LOCK);
		}

		if (kb8042_send_and_wait(kb8042, KB_SET_LED, polled)) {
			/*
			 * Ignore return value, as there's nothing we can
			 * do about it if the SET LED command fails.
			 */
			(void) kb8042_send_and_wait(kb8042,
			    kb8042_xlate_leds(kb8042->leds.desired), polled);
		}

		if (!polled) {
			(void) ddi_get8(kb8042->handle, kb8042->addr +
			    I8042_UNLOCK);
		}
		kb8042->leds.commanded = kb8042->leds.desired;

	} else if (byte == KB_ENABLE) {

		if (!polled) {
			(void) ddi_get8(kb8042->handle, kb8042->addr +
			    I8042_LOCK);
		}

		(void) kb8042_send_and_wait(kb8042, KB_ENABLE, polled);

		if (!polled) {
			(void) ddi_get8(kb8042->handle, kb8042->addr +
			    I8042_UNLOCK);
		}

	} else {
		/* All other commands use the "normal" virtual output port */
		if (polled) {
			ddi_put8(kb8042->handle,
			    kb8042->addr + I8042_POLL_OUTPUT_DATA, byte);
		} else {
			ddi_put8(kb8042->handle,
			    kb8042->addr + I8042_INT_OUTPUT_DATA, byte);
		}
	}
}

/*
 * Wait until the keyboard is fully up, maybe.
 * We may be the first person to talk to the keyboard, in which case
 * it's patiently waiting to say "AA" to us to tell us it's up.
 * In theory it sends the AA in 300ms < n < 9s, but it's a pretty
 * good bet that we've already spent that long getting to that point,
 * so we'll only wait long enough for the communications electronics to
 * run.
 */
static void
kb8042_wait_poweron(struct kb8042 *kb8042)
{
	int cnt;
	int ready;

	/* wait for up to 250 ms for a response */
	for (cnt = 0; cnt < 250; cnt++) {
		ready = ddi_get8(kb8042->handle,
		    kb8042->addr + I8042_INT_INPUT_AVAIL);
		if (ready != 0)
			break;
		drv_usecwait(1000);
	}

	/*
	 * If there's something pending, read and discard it.  If not,
	 * assume things are OK anyway - maybe somebody else ate it
	 * already.  (On a PC, the BIOS almost certainly did.)
	 */
	if (ready != 0) {
		(void) ddi_get8(kb8042->handle,
		    kb8042->addr + I8042_INT_INPUT_DATA);
	}
}

static int
kb8042_xlate_leds(int led)
{
	int res;

	res = 0;

	if (led & LED_NUM_LOCK)
		res |= LED_NUM;
	if (led & LED_SCROLL_LOCK)
		res |= LED_SCR;
	if (led & LED_CAPS_LOCK)
		res |= LED_CAP;

	return (res);
}

/*ARGSUSED*/
static void
kb8042_get_initial_leds(
    struct kb8042 *kb8042,
    int *initial_leds,
    int *initial_led_mask)
{
#if defined(__i386) || defined(__amd64)
	extern caddr_t	p0_va;
	uint8_t		bios_kb_flag;

	bios_kb_flag = p0_va[BIOS_KB_FLAG];

	*initial_led_mask = LED_CAPS_LOCK | LED_NUM_LOCK | LED_SCROLL_LOCK;
	*initial_leds = 0;
	if (bios_kb_flag & BIOS_CAPS_STATE)
		*initial_leds |= LED_CAPS_LOCK;
	if (bios_kb_flag & BIOS_NUM_STATE)
		*initial_leds |= LED_NUM_LOCK;
	if (bios_kb_flag & BIOS_SCROLL_STATE)
		*initial_leds |= LED_SCROLL_LOCK;
#else
	*initial_leds = 0;
	*initial_led_mask = 0;
#endif
}

static boolean_t
kb8042_autorepeat_detect(
    struct kb8042 *kb8042,
    int key_pos,
    enum keystate state)
{
	if (state == KEY_RELEASED) {
		if (kb8042->kb_old_key_pos == key_pos)
			kb8042->kb_old_key_pos = 0;
	} else {
		if (kb8042->kb_old_key_pos == key_pos) {
			return (B_TRUE);
		}
		kb8042->kb_old_key_pos = key_pos;
	}
	return (B_FALSE);
}

/* ARGSUSED */
static void
kb8042_type4_cmd(struct kb8042 *kb8042, int cmd)
{
	switch (cmd) {
	case KBD_CMD_BELL:
		(void) beeper_on(BEEP_TYPE4);
		break;
	case KBD_CMD_NOBELL:
		(void) beeper_off();
		break;
	}
}


/*
 * This is a pass-thru routine to get a character at poll time.
 */
static int
kb8042_polled_getchar(cons_polledio_arg_t arg)
{
	struct kb8042	*kb8042;

	kb8042 = (struct kb8042 *)arg;

	return (kbtrans_getchar(kb8042->hw_kbtrans));
}

/*
 * This is a pass-thru routine to get a character at poll time.
 */
static int
kb8042_polled_ischar(cons_polledio_arg_t arg)
{
	struct kb8042	*kb8042;

	kb8042 = (struct kb8042 *)arg;

	return (kbtrans_ischar(kb8042->hw_kbtrans));
}
