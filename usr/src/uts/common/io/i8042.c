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
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/inline.h>
#include <sys/conf.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/i8042.h>
#include <sys/kmem.h>
#include <sys/promif.h>	/* for prom_printf */
#include <sys/note.h>

/*
 * Note: For x86, this driver is used to create keyboard/mouse nodes when
 * booting with ACPI enumeration turned off (acpi-enum=off).
 */

/*
 * Unfortunately, soft interrupts are implemented poorly.  Each additional
 * soft interrupt user impacts the performance of all existing soft interrupt
 * users.  This is not the case on SPARC, however.
 */
#ifdef __sparc
#define	USE_SOFT_INTRS
#else
#undef	USE_SOFT_INTRS
#endif

/*
 * The command bytes are different for x86 and for SPARC because on x86,
 * all modern 8042s can properly translate scan code set 2 codes to
 * scan code set 1.  On SPARC systems that have 8042s (e.g. Tadpole laptops),
 * setting the "translation" bit in the command byte has no effect.
 * This is potentially dangerous if, in the future, new SPARC systems uses 8042s
 * that implement the scan code translation when the translation bit is set.
 *
 * On SPARC, kb8042 will attempt to detect which scan code set the keyboard
 * is using.  In order for that code to work, the real scan code set must be the
 * set that is returned by the keyboard (and not a different set that is
 * translated by the 8042). (e.g. If the translation bit were enabled here,
 * and the keyboard returned scan code set 2 when kb8042 queried it, kb8042
 * would not be able to know with certainty that the scan codes it will receive
 * are set 2 scancodes, or set 1 translations made by the 8042).
 */

/*
 * 8042 Command Byte Layout:
 *
 * 0x80:  0   = Reserved, must be zero.
 * 0x40:  1   = Translate to XT codes. (0=No translation)
 * 0x20:  1   = Disable aux (mouse) port. (0=Enable port)
 * 0x10:  1   = Disable main (keyboard) port. (0=Enable port)
 * 0x08:  0   = Reserved, must be zero.
 * 0x04:  1   = System flag, 1 means passed self-test.
 *		Caution:  setting this bit to zero causes some
 *		systems (HP Kayak XA) to fail to reboot without
 *		a hard reset.
 * 0x02:  0   = Disable aux port interrupts. (1=Enable aux port interrupts)
 * 0x01:  0   = Disable main port interrupts. (1=Enable main port interrupts)
 *
 */
#if defined(__sparc)
#define	I8042_CMD_DISABLE_ALL	0x34
#define	I8042_CMD_ENABLE_ALL	0x07
#elif defined(__x86)
#define	I8042_CMD_DISABLE_ALL	0x74
#define	I8042_CMD_ENABLE_ALL	0x47
#endif

#define	BUFSIZ	64

/*
 * Child nodes, used to determine which to create at bus_config time
 */
#define	I8042_KEYBOARD 2
#define	I8042_MOUSE 1

enum i8042_ports {
	MAIN_PORT = 0,
	AUX_PORT
};

#define	NUM_PORTS	2

/*
 * Only register at most MAX_INTERRUPTS interrupt handlers,
 * regardless of the number of interrupts in the prom node.
 * This is important, as registering for all interrupts on
 * some systems (e.g. Tadpole laptops) results in a flood
 * of spurious interrupts (for Tadpole, the first 2 interrupts
 * are for the keyboard and mouse, respectively, and the
 * third is for a proprietary device that is also accessed
 * via the same I/O addresses.)
 */
#define	MAX_INTERRUPTS	2

/*
 * One of these for each port - main (keyboard) and aux (mouse).
 */
struct i8042_port {
	boolean_t		initialized;
	dev_info_t		*dip;
	int			inumber;
	enum i8042_ports	which;		/* main or aux port */
#if defined(USE_SOFT_INTRS)
	ddi_softint_handle_t	soft_hdl;
	boolean_t		soft_intr_enabled;
#else
	kmutex_t		intr_mutex;
#endif
	uint_t			(*intr_func)(caddr_t arg1, caddr_t arg2);
	caddr_t			intr_arg1;
	caddr_t			intr_arg2;
	struct i8042		*i8042_global;
	/*
	 * wptr is next byte to write
	 */
	int			wptr;
	/*
	 * rptr is next byte to read, == wptr means empty
	 * NB:  At full, one byte is unused.
	 */
	int			rptr;
	int			overruns;
	unsigned char		buf[BUFSIZ];
	/*
	 * has_glock is 1 if this child has the [put8] exclusive-access lock.
	 */
	volatile boolean_t	has_glock;
};

/*
 * Describes entire 8042 device.
 */
struct i8042 {
	dev_info_t		*dip;
	struct i8042_port	i8042_ports[NUM_PORTS];
	kmutex_t		i8042_mutex;
	kmutex_t		i8042_out_mutex;
	boolean_t		initialized;
	ddi_acc_handle_t	io_handle;
	uint8_t			*io_addr;
	int			nintrs;
	ddi_iblock_cookie_t	*iblock_cookies;
	uint_t			init_state;
/* Initialization states: */
#define	I8042_INIT_BASIC		0x00000001
#define	I8042_INIT_REGS_MAPPED		0x00000002
#define	I8042_INIT_MUTEXES		0x00000004
#define	I8042_INIT_INTRS_ENABLED	0x00000010
	uint_t			intrs_added;
#ifdef __sparc
	timeout_id_t		timeout_id;
#endif
	/*
	 * glock is 1 if any child has the [put8] exclusive-access lock
	 * glock_cv is associated with the condition `glock == 0'
	 */
	volatile int		glock;
	/*
	 * Callers awaiting exclusive access in i8042_put8 sleep on glock_cv
	 * and are signaled when another child relinquishes exclusive access.
	 */
	kcondvar_t		glock_cv;
};

/*
 * i8042 hardware register definitions
 */

/*
 * These are I/O registers, relative to the device's base (normally 0x60).
 */
#define	I8042_DATA	0x00	/* read/write data here */
#define	I8042_STAT	0x04	/* read status here */
#define	I8042_CMD	0x04	/* write commands here */

/*
 * These are bits in I8042_STAT.
 */
#define	I8042_STAT_OUTBF	0x01	/* Output (to host) buffer full */
#define	I8042_STAT_INBF		0x02	/* Input (from host) buffer full */
#define	I8042_STAT_AUXBF	0x20	/* Output buffer data is from aux */

/*
 * These are commands to the i8042 itself (as distinct from the devices
 * attached to it).
 */
#define	I8042_CMD_RCB		0x20	/* Read command byte (we don't use) */
#define	I8042_CMD_WCB		0x60	/* Write command byte */
#define	I8042_CMD_WRITE_AUX	0xD4	/* Send next data byte to aux port */

/*
 * Maximum number of times to loop while clearing pending data from the
 * keyboard controller.
 */
#define	MAX_JUNK_ITERATIONS	1000

/*
 * Maximum time to wait for the keyboard to become ready to accept data
 * (maximum time = MAX_WAIT_ITERATIONS * USECS_PER_WAIT (default is 250ms))
 */
#define	MAX_WAIT_ITERATIONS	25000
#define	USECS_PER_WAIT		10


#ifdef __sparc

#define	PLATFORM_MATCH(s) (strncmp(ddi_get_name(ddi_root_node()), \
	(s), strlen(s)) == 0)

/*
 * On some older SPARC platforms that have problems with the
 * interrupt line attached to the PS/2 keyboard/mouse, it
 * may be necessary to change the operating mode of the nexus
 * to a polling-based (instead of interrupt-based) method.
 * this variable is present to enable a worst-case workaround so
 * owners of these systems can still retain a working keyboard.
 *
 * The `i8042_polled_mode' variable can be used to force polled
 * mode for platforms that have this issue, but for which
 * automatic relief is not implemented.
 *
 * In the off chance that one of the platforms is misidentified
 * as requiried polling mode, `i8042_force_interrupt_mode' can
 * be set to force the nexus to use interrupts.
 */
#define	I8042_MIN_POLL_INTERVAL 1000	/* usecs */
int i8042_poll_interval = 8000;		/* usecs */
int i8042_fast_poll_interval;		/* usecs */
int i8042_slow_poll_interval;		/* usecs */

boolean_t i8042_polled_mode = B_FALSE;
boolean_t i8042_force_interrupt_mode = B_FALSE;
#endif /* __sparc */

int max_wait_iterations = MAX_WAIT_ITERATIONS;

#ifdef DEBUG
int i8042_debug = 0;
#endif

/*
 * function prototypes for bus ops routines:
 */
static int i8042_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t offset, off_t len, caddr_t *addrp);
static int i8042_ctlops(dev_info_t *dip, dev_info_t *rdip,
	ddi_ctl_enum_t op, void *arg, void *result);

/*
 * function prototypes for dev ops routines:
 */
static int i8042_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int i8042_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static	int i8042_intr_ops(dev_info_t *dip, dev_info_t *rdip,
	ddi_intr_op_t intr_op, ddi_intr_handle_impl_t *hdlp, void *result);
static int i8042_bus_config(dev_info_t *, uint_t, ddi_bus_config_op_t,
    void *, dev_info_t **);
static int i8042_bus_unconfig(dev_info_t *, uint_t,
    ddi_bus_config_op_t, void *);
#ifdef __sparc
static int i8042_build_interrupts_property(dev_info_t *dip);
static boolean_t i8042_is_polling_platform(void);
#endif

/*
 * bus ops and dev ops structures:
 */
static struct bus_ops i8042_bus_ops = {
	BUSO_REV,
	i8042_map,
	NULL,
	NULL,
	NULL,
	NULL,		/* ddi_map_fault */
	NULL,		/* ddi_dma_map */
	NULL,		/* ddi_dma_allochdl */
	NULL,		/* ddi_dma_freehdl */
	NULL,		/* ddi_dma_bindhdl */
	NULL,		/* ddi_dma_unbindhdl */
	NULL,		/* ddi_dma_flush */
	NULL,		/* ddi_dma_win */
	NULL,		/* ddi_dma_mctl */
	i8042_ctlops,
	ddi_bus_prop_op,
	NULL,			/* (*bus_get_eventcookie)();	*/
	NULL,			/* (*bus_add_eventcall)();	*/
	NULL,			/* (*bus_remove_eventcall)();	*/
	NULL,			/* (*bus_post_event)();		*/
	NULL,			/* bus_intr_ctl */
	i8042_bus_config,	/* bus_config */
	i8042_bus_unconfig,	/* bus_unconfig */
	NULL,			/* bus_fm_init */
	NULL,			/* bus_fm_fini */
	NULL,			/* bus_fm_access_enter */
	NULL,			/* bus_fm_access_exit */
	NULL,			/* bus_power */
	i8042_intr_ops		/* bus_intr_op */
};

static struct dev_ops i8042_ops = {
	DEVO_REV,
	0,
	ddi_no_info,
	nulldev,
	0,
	i8042_attach,
	i8042_detach,
	nodev,
	(struct cb_ops *)0,
	&i8042_bus_ops,
	NULL,
	ddi_quiesce_not_needed,
};


/*
 * module definitions:
 */
#include <sys/modctl.h>
extern struct mod_ops mod_driverops;

static struct modldrv modldrv = {
	&mod_driverops,		/* Type of module.  This one is a driver */
	"i8042 nexus driver",	/* Name of module. */
	&i8042_ops,		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modldrv, NULL
};

int
_init(void)
{
	int e;

	/*
	 * Install the module.
	 */
	e = mod_install(&modlinkage);
	return (e);
}

int
_fini(void)
{
	int e;

	/*
	 * Remove the module.
	 */
	e = mod_remove(&modlinkage);
	if (e != 0)
		return (e);

	return (e);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

#define	DRIVER_NAME(dip)	ddi_driver_name(dip)

static void i8042_timeout(void *arg);
static unsigned int i8042_intr(caddr_t arg);
static void i8042_write_command_byte(struct i8042 *, unsigned char);
static uint8_t i8042_get8(ddi_acc_impl_t *handlep, uint8_t *addr);
static void i8042_put8(ddi_acc_impl_t *handlep, uint8_t *addr,
    uint8_t value);
static void i8042_send(struct i8042 *global, int reg, unsigned char cmd);
static uint8_t i8042_get8(ddi_acc_impl_t *handlep, uint8_t *addr);

unsigned int i8042_unclaimed_interrupts = 0;

static void
i8042_discard_junk_data(struct i8042 *global)
{
	/* Discard any junk data that may have been left around */
	for (;;) {
		unsigned char		stat;

		stat = ddi_get8(global->io_handle,
		    global->io_addr + I8042_STAT);
		if (! (stat & I8042_STAT_OUTBF))
			break;
		(void) ddi_get8(global->io_handle,
		    global->io_addr + I8042_DATA);

	}
}

static int
i8042_cleanup(struct i8042 *global)
{
	int which_port, i;
	struct i8042_port *port;

	ASSERT(global != NULL);

	if (global->initialized == B_TRUE) {
		/*
		 * If any children still have regs mapped or interrupts
		 * registered, return immediate failure (and do nothing).
		 */
		mutex_enter(&global->i8042_mutex);

		for (which_port = 0; which_port < NUM_PORTS; which_port++) {
			port = &global->i8042_ports[which_port];

			if (port->initialized == B_TRUE) {
				mutex_exit(&global->i8042_mutex);
				return (DDI_FAILURE);
			}
#if defined(USE_SOFT_INTRS)
			if (port->soft_hdl != 0) {
				mutex_exit(&global->i8042_mutex);
				return (DDI_FAILURE);
			}
#else
			mutex_enter(&port->intr_mutex);
			if (port->intr_func != NULL) {
				mutex_exit(&port->intr_mutex);
				mutex_exit(&global->i8042_mutex);
				return (DDI_FAILURE);
			}
			mutex_exit(&port->intr_mutex);
#endif
		}
		global->initialized = B_FALSE;

		mutex_exit(&global->i8042_mutex);
	}

#ifdef __sparc
	/* If there may be an outstanding timeout, cancel it */
	if (global->timeout_id != 0) {
		(void) untimeout(global->timeout_id);
	}
#endif

	/* Stop the controller from generating interrupts */
	if (global->init_state & I8042_INIT_INTRS_ENABLED)
		i8042_write_command_byte(global, I8042_CMD_DISABLE_ALL);

	if (global->intrs_added) {
		/*
		 * Remove the interrupts in the reverse order in
		 * which they were added
		 */
		for (i = global->nintrs - 1; i >= 0; i--) {
			if (global->intrs_added & (1 << i))
				ddi_remove_intr(global->dip, i,
				    global->iblock_cookies[i]);
		}
	}


	if (global->init_state & I8042_INIT_MUTEXES) {
		for (which_port = 0; which_port < NUM_PORTS; which_port++) {
#ifndef USE_SOFT_INTRS
			port = &global->i8042_ports[which_port];
			mutex_destroy(&port->intr_mutex);
#endif
		}
		cv_destroy(&global->glock_cv);
		mutex_destroy(&global->i8042_out_mutex);
		mutex_destroy(&global->i8042_mutex);
	}

	if (global->init_state & I8042_INIT_REGS_MAPPED)
		ddi_regs_map_free(&global->io_handle);

	if (global->init_state & I8042_INIT_BASIC) {
		ddi_set_driver_private(global->dip, (caddr_t)NULL);
		if (global->nintrs > 0) {
			kmem_free(global->iblock_cookies, global->nintrs *
			    sizeof (ddi_iblock_cookie_t));
		}
		kmem_free(global, sizeof (struct i8042));
	}

	return (DDI_SUCCESS);
}

#define	OBF_WAIT_COUNT 1000	/* in granules of 10uS */

/*
 * Wait for the 8042 to fill the 'output' (from 8042 to host)
 * buffer.  If 8042 fails to fill the output buffer within an
 * allowed time, return 1 (which means there is no data available),
 * otherwise return 0
 */
static int
i8042_wait_obf(struct i8042 *global)
{
	int timer = 0;

	while (!(ddi_get8(global->io_handle, global->io_addr + I8042_STAT) &
	    I8042_STAT_OUTBF)) {
		if (++timer > OBF_WAIT_COUNT)
			return (1);
		drv_usecwait(10);
	}
	return (0);
}


/*
 * Drain all queued bytes from the 8042.
 * Return 0 for no error, <> 0 if there was an error.
 */
static int
i8042_purge_outbuf(struct i8042 *global)
{
	int	i;

	for (i = 0; i < MAX_JUNK_ITERATIONS; i++) {
		if (i8042_wait_obf(global))
			break;
		(void) ddi_get8(global->io_handle,
		    global->io_addr + I8042_DATA);
	}

	/*
	 * If we hit the maximum number of iterations, then there
	 * was a serious problem (e.g. our hardware may not be
	 * present or working properly).
	 */
	return (i == MAX_JUNK_ITERATIONS);
}

static int
i8042_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct i8042_port	*port;
	enum i8042_ports	which_port;
	int			i;
#if !defined(USE_SOFT_INTRS)
	ddi_iblock_cookie_t	cookie;
#endif
	static ddi_device_acc_attr_t attr = {
		DDI_DEVICE_ATTR_V0,
		DDI_NEVERSWAP_ACC,
		DDI_STRICTORDER_ACC,
	};
	struct i8042 *global;
#ifdef __sparc
	int			interval;
#endif

	switch (cmd) {
	case DDI_RESUME:
		global = (struct i8042 *)ddi_get_driver_private(dip);
		i8042_discard_junk_data(global);
		i8042_write_command_byte(global, I8042_CMD_ENABLE_ALL);
		return (DDI_SUCCESS);

	case DDI_ATTACH:
		/* Handled in the main function block */
		break;

	default:
		return (DDI_FAILURE);
	}

	/*
	 * DDI_ATTACH processing
	 */

	global = (struct i8042 *)kmem_zalloc(sizeof (struct i8042), KM_SLEEP);
	ddi_set_driver_private(dip, (caddr_t)global);
	global->dip = dip;
	global->initialized = B_FALSE;

	global->init_state |= I8042_INIT_BASIC;

	if (ddi_regs_map_setup(dip, 0, (caddr_t *)&global->io_addr,
	    (offset_t)0, (offset_t)0, &attr, &global->io_handle)
	    != DDI_SUCCESS)
		goto fail;

	global->init_state |= I8042_INIT_REGS_MAPPED;

	/*
	 * Get the number of interrupts for this nexus
	 */
	if (ddi_dev_nintrs(dip, &global->nintrs) == DDI_FAILURE)
		goto fail;

#ifdef __sparc
	if ((i8042_polled_mode || i8042_is_polling_platform()) &&
	    !i8042_force_interrupt_mode) {
		/*
		 * If we're on a platform that has known
		 * interrupt issues with the keyboard/mouse,
		 * use polled mode.
		 */
		i8042_polled_mode = B_TRUE;
		global->nintrs = 0;
	} else if (global->nintrs == 0) {
		/*
		 * If there are no interrupts on the i8042 node,
		 * we may be on a brain-dead platform that only
		 * has interrupts properties on i8042's children
		 * (e.g. some UltraII-based boards)
		 * In this case, scan first-level children, and
		 * build a list of interrupts that each child uses,
		 * then create an `interrupts' property on the nexus node
		 * that contains the interrupts used by all children
		 */
		if (i8042_build_interrupts_property(dip) == DDI_FAILURE ||
		    ddi_dev_nintrs(dip, &global->nintrs) == DDI_FAILURE ||
		    global->nintrs == 0) {
			cmn_err(CE_WARN, "i8042#%d: No interrupts defined!",
			    ddi_get_instance(global->dip));
			goto fail;
		}
	}
#else
	if (global->nintrs == 0) {
		cmn_err(CE_WARN, "i8042#%d: No interrupts defined!",
		    ddi_get_instance(global->dip));
		goto fail;
	}
#endif

	if (global->nintrs > MAX_INTERRUPTS)
		global->nintrs = MAX_INTERRUPTS;

	if (global->nintrs > 0) {
		global->iblock_cookies = kmem_zalloc(global->nintrs *
		    sizeof (ddi_iblock_cookie_t), KM_NOSLEEP);

		for (i = 0; i < global->nintrs; i++) {
			if (ddi_get_iblock_cookie(dip, i,
			    &global->iblock_cookies[i]) != DDI_SUCCESS)
				goto fail;
		}
	} else
		global->iblock_cookies = NULL;

	mutex_init(&global->i8042_mutex, NULL, MUTEX_DRIVER,
	    (global->nintrs > 0) ? global->iblock_cookies[0] : NULL);

	mutex_init(&global->i8042_out_mutex, NULL, MUTEX_DRIVER, NULL);

	cv_init(&global->glock_cv, NULL, CV_DRIVER, NULL);

	for (which_port = 0; which_port < NUM_PORTS; ++which_port) {
		port = &global->i8042_ports[which_port];
		port->initialized = B_FALSE;
		port->i8042_global = global;
		port->which = which_port;
#if defined(USE_SOFT_INTRS)
		port->soft_hdl = 0;
#else

		/*
		 * Assume that the interrupt block cookie for port <n>
		 * is iblock_cookies[<n>] (a 1:1 mapping).  If there are not
		 * enough interrupts to cover the number of ports, use
		 * the cookie from interrupt 0.
		 */
		if (global->nintrs > 0) {
			cookie = global->iblock_cookies[
			    (which_port < global->nintrs) ? which_port : 0];

			mutex_init(&port->intr_mutex, NULL, MUTEX_DRIVER,
			    cookie);

		} else {
			mutex_init(&port->intr_mutex, NULL, MUTEX_DRIVER, NULL);
		}

#endif
	}

	global->init_state |= I8042_INIT_MUTEXES;

	/*
	 * Disable input and interrupts from both the main and aux ports.
	 *
	 * It is difficult if not impossible to read the command byte in
	 * a completely clean way.  Reading the command byte may cause
	 * an interrupt, and there is no way to suppress interrupts without
	 * writing the command byte.  On a PC we might rely on the fact
	 * that IRQ 1 is disabled and guaranteed not shared, but on
	 * other platforms the interrupt line might be shared and so
	 * causing an interrupt could be bad.
	 *
	 * Since we can't read the command byte and update it, we
	 * just set it to static values.
	 */
	i8042_write_command_byte(global, I8042_CMD_DISABLE_ALL);

	global->init_state &= ~I8042_INIT_INTRS_ENABLED;

	/* Discard any junk data that may have been left around */
	if (i8042_purge_outbuf(global) != 0)
		goto fail;


	/*
	 * Assume the number of interrupts is less that the number of
	 * bits in the variable used to keep track of which interrupt
	 * was added.
	 */
	ASSERT(global->nintrs <= (sizeof (global->intrs_added) * NBBY));

	for (i = 0; i < global->nintrs; i++) {
		/*
		 * The 8042 handles all interrupts, because all
		 * device access goes through the same I/O addresses.
		 */
		if (ddi_add_intr(dip, i,
		    (ddi_iblock_cookie_t *)NULL,
		    (ddi_idevice_cookie_t *)NULL,
		    i8042_intr, (caddr_t)global) != DDI_SUCCESS)
			goto fail;

		global->intrs_added |= (1 << i);
	}

	global->initialized = B_TRUE;

	/*
	 * Enable the main and aux data ports and interrupts
	 */
	i8042_write_command_byte(global, I8042_CMD_ENABLE_ALL);
	global->init_state |= I8042_INIT_INTRS_ENABLED;

#ifdef __sparc
	if (i8042_polled_mode) {
		/*
		 * Do not allow anyone to set the polling interval
		 * to an interval more frequent than I8042_MIN_POLL_INTERVAL --
		 * it could hose the system.
		 */
		interval = i8042_poll_interval;
		if (interval < I8042_MIN_POLL_INTERVAL)
			interval = I8042_MIN_POLL_INTERVAL;
		i8042_fast_poll_interval = interval;
		i8042_slow_poll_interval = interval << 3;

		global->timeout_id = timeout(i8042_timeout, global,
		    drv_usectohz(i8042_slow_poll_interval));
	}
#endif

	return (DDI_SUCCESS);

fail:
	/* cleanup will succeed because no children have attached yet */
	(void) i8042_cleanup(global);
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
i8042_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct i8042 *global = (struct i8042 *)ddi_get_driver_private(dip);

	ASSERT(global != NULL);

	switch (cmd) {
	case DDI_SUSPEND:
		/*
		 * Do not disable the keyboard controller for x86 suspend, as
		 * the keyboard can be used to bring the system out of
		 * suspend.
		 */
#ifdef __sparc
		/* Disable interrupts and controller devices before suspend */
		i8042_write_command_byte(global, I8042_CMD_DISABLE_ALL);
#endif
		return (DDI_SUCCESS);

	case DDI_DETACH:
		/* DETACH can only succeed if cleanup succeeds */
		return (i8042_cleanup(global));

	default:
		return (DDI_FAILURE);
	}
}

/*
 * The primary interface to us from our children is via virtual registers.
 * This is the entry point that allows our children to "map" these
 * virtual registers.
 */
static int
i8042_map(
	dev_info_t *dip,
	dev_info_t *rdip,
	ddi_map_req_t *mp,
	off_t offset,
	off_t len,
	caddr_t *addrp)
{
	struct i8042_port	*port;
	struct i8042		*global;
	enum i8042_ports	which_port;
	int			*iprop;
	unsigned int		iprop_len;
	int			rnumber;
	ddi_acc_hdl_t		*handle;
	ddi_acc_impl_t		*ap;

	global = ddi_get_driver_private(dip);

	switch (mp->map_type) {
	case DDI_MT_REGSPEC:
		which_port = *(int *)mp->map_obj.rp;
		break;

	case DDI_MT_RNUMBER:
		rnumber = mp->map_obj.rnumber;
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, rdip,
		    DDI_PROP_DONTPASS, "reg", &iprop, &iprop_len) !=
		    DDI_SUCCESS) {
#if defined(DEBUG)
			cmn_err(CE_WARN, "%s #%d:  Missing 'reg' on %s@%s",
			    DRIVER_NAME(dip), ddi_get_instance(dip),
			    ddi_node_name(rdip), ddi_get_name_addr(rdip));
#endif
			return (DDI_FAILURE);
		}
#if defined(DEBUG)
		if (iprop_len != 1) {
			cmn_err(CE_WARN, "%s #%d:  Malformed 'reg' on %s@%s",
			    DRIVER_NAME(dip), ddi_get_instance(dip),
			    ddi_node_name(rdip), ddi_get_name_addr(rdip));
			return (DDI_FAILURE);
		}
		if (rnumber < 0 || rnumber >= iprop_len) {
			cmn_err(CE_WARN, "%s #%d:  bad map request for %s@%s",
			    DRIVER_NAME(dip), ddi_get_instance(dip),
			    ddi_node_name(rdip), ddi_get_name_addr(rdip));
			return (DDI_FAILURE);
		}
#endif
		which_port = iprop[rnumber];
		ddi_prop_free((void *)iprop);
#if defined(DEBUG)
		if (which_port != MAIN_PORT && which_port != AUX_PORT) {
			cmn_err(CE_WARN,
			    "%s #%d:  bad 'reg' value %d on %s@%s",
			    DRIVER_NAME(dip), ddi_get_instance(dip),
			    which_port,
			    ddi_node_name(rdip), ddi_get_name_addr(rdip));
			return (DDI_FAILURE);
		}
#endif
		break;

	default:
#if defined(DEBUG)
		cmn_err(CE_WARN, "%s #%d:  unknown map type %d for %s@%s",
		    DRIVER_NAME(dip), ddi_get_instance(dip),
		    mp->map_type,
		    ddi_node_name(rdip), ddi_get_name_addr(rdip));
#endif
		return (DDI_FAILURE);
	}

#if defined(DEBUG)
	if (offset != 0 || len != 0) {
		cmn_err(CE_WARN,
		    "%s #%d:  partial mapping attempt for %s@%s ignored",
		    DRIVER_NAME(dip), ddi_get_instance(dip),
		    ddi_node_name(rdip), ddi_get_name_addr(rdip));
	}
#endif

	port = &global->i8042_ports[which_port];

	switch (mp->map_op) {
	case DDI_MO_MAP_LOCKED:
#if defined(USE_SOFT_INTRS)
		port->soft_intr_enabled = B_FALSE;
#else
		port->intr_func = NULL;
#endif
		port->wptr = 0;
		port->rptr = 0;
		port->dip = dip;
		port->inumber = 0;
		port->has_glock = B_FALSE;
		port->initialized = B_TRUE;

		handle = mp->map_handlep;
		handle->ah_bus_private = port;
		handle->ah_addr = 0;
		ap = (ddi_acc_impl_t *)handle->ah_platform_private;
		/*
		 * Support get8, put8 and _rep_put8
		 */
		ap->ahi_put8 = i8042_put8;
		ap->ahi_get8 = i8042_get8;
		ap->ahi_put16 = NULL;
		ap->ahi_get16 = NULL;
		ap->ahi_put32 = NULL;
		ap->ahi_get32 = NULL;
		ap->ahi_put64 = NULL;
		ap->ahi_get64 = NULL;
		ap->ahi_rep_put8 = NULL;
		ap->ahi_rep_get8 = NULL;
		ap->ahi_rep_put16 = NULL;
		ap->ahi_rep_get16 = NULL;
		ap->ahi_rep_put32 = NULL;
		ap->ahi_rep_get32 = NULL;
		ap->ahi_rep_put64 = NULL;
		ap->ahi_rep_get64 = NULL;
		*addrp = 0;
		return (DDI_SUCCESS);

	case DDI_MO_UNMAP:
		port->initialized = B_FALSE;
		return (DDI_SUCCESS);

	default:
		cmn_err(CE_WARN, "%s:  map operation %d not supported",
		    DRIVER_NAME(dip), mp->map_op);
		return (DDI_FAILURE);
	}
}

#ifdef __sparc
static void
i8042_timeout(void *arg)
{
	struct i8042 *i8042_p = (struct i8042 *)arg;
	int interval;

	/*
	 * Allow the polling speed to be changed on the fly --
	 * catch it here and update the intervals used.
	 */
	if (i8042_fast_poll_interval != i8042_poll_interval) {
		interval = i8042_poll_interval;
		if (interval < I8042_MIN_POLL_INTERVAL)
			interval = I8042_MIN_POLL_INTERVAL;
		i8042_fast_poll_interval = interval;
		i8042_slow_poll_interval = interval << 3;
	}

	/*
	 * If the ISR returned true, start polling at a faster rate to
	 * increate responsiveness.  Once the keyboard or mouse go idle,
	 * the ISR will return UNCLAIMED, and we'll go back to the slower
	 * polling rate.  This gives some positive hysteresis (but not
	 * negative, since we go back to the slower polling interval after
	 * only one UNCLAIMED).  This has shown to be responsive enough,
	 * even for fast typers.
	 */
	interval = (i8042_intr((caddr_t)i8042_p) == DDI_INTR_CLAIMED) ?
	    i8042_fast_poll_interval : i8042_slow_poll_interval;

	if (i8042_polled_mode)
		i8042_p->timeout_id = timeout(i8042_timeout, arg,
		    drv_usectohz(interval));
	else
		i8042_p->timeout_id = 0;
}
#endif

/*
 * i8042 hardware interrupt routine.  Called for both main and aux port
 * interrupts.
 */
static unsigned int
i8042_intr(caddr_t arg)
{
	struct i8042		*global = (struct i8042 *)arg;
	enum i8042_ports	which_port;
	unsigned char		stat;
	unsigned char		byte;
	int			new_wptr;
	struct i8042_port	*port;

	mutex_enter(&global->i8042_mutex);

	stat = ddi_get8(global->io_handle, global->io_addr + I8042_STAT);

	if (! (stat & I8042_STAT_OUTBF)) {
		++i8042_unclaimed_interrupts;
		mutex_exit(&global->i8042_mutex);
		return (DDI_INTR_UNCLAIMED);
	}

	byte = ddi_get8(global->io_handle, global->io_addr + I8042_DATA);

	which_port = (stat & I8042_STAT_AUXBF) ? AUX_PORT : MAIN_PORT;

	port = &global->i8042_ports[which_port];

	if (! port->initialized) {
		mutex_exit(&global->i8042_mutex);
		return (DDI_INTR_CLAIMED);
	}

	new_wptr = (port->wptr + 1) % BUFSIZ;
	if (new_wptr == port->rptr) {
		port->overruns++;
#if defined(DEBUG)
		if (port->overruns % 50 == 1) {
			cmn_err(CE_WARN, "i8042/%d: %d overruns\n",
			    which_port, port->overruns);
		}
#endif

		mutex_exit(&global->i8042_mutex);
		return (DDI_INTR_CLAIMED);
	}

	port->buf[port->wptr] = byte;
	port->wptr = new_wptr;

#if defined(USE_SOFT_INTRS)
	if (port->soft_intr_enabled)
		(void) ddi_intr_trigger_softint(port->soft_hdl,
		    port->intr_arg2);
#endif

	mutex_exit(&global->i8042_mutex);

#if	!defined(USE_SOFT_INTRS)
	mutex_enter(&port->intr_mutex);
	if (port->intr_func != NULL)
		port->intr_func(port->intr_arg1, NULL);
	mutex_exit(&port->intr_mutex);
#endif

	return (DDI_INTR_CLAIMED);
}

static void
i8042_write_command_byte(struct i8042 *global, unsigned char cb)
{
	mutex_enter(&global->i8042_out_mutex);
	i8042_send(global, I8042_CMD, I8042_CMD_WCB);
	i8042_send(global, I8042_DATA, cb);
	mutex_exit(&global->i8042_out_mutex);
}

/*
 * Send a byte to either the i8042 command or data register, depending on
 * the argument.
 */
static void
i8042_send(struct i8042 *global, int reg, unsigned char val)
{
	uint8_t stat;
	int tries = 0;

	/*
	 * First, wait for the i8042 to be ready to accept data.
	 */
	/*CONSTANTCONDITION*/
	while (1) {
		stat = ddi_get8(global->io_handle,
		    global->io_addr + I8042_STAT);

		if ((stat & I8042_STAT_INBF) == 0) {
			ddi_put8(global->io_handle, global->io_addr+reg, val);
			break;
		}

		/* Don't wait unless we're going to check again */
		if (++tries >= max_wait_iterations)
			break;
		else
			drv_usecwait(USECS_PER_WAIT);
	}

#ifdef DEBUG
	if (tries >= MAX_WAIT_ITERATIONS)
		cmn_err(CE_WARN, "i8042_send: timeout!");
#endif
}

/*
 * Here's the interface to the virtual registers on the device.
 *
 * Normal interrupt-driven I/O:
 *
 * I8042_INT_INPUT_AVAIL	(r/o)
 *	Interrupt mode input bytes available?  Zero = No.
 * I8042_INT_INPUT_DATA		(r/o)
 *	Fetch interrupt mode input byte.
 * I8042_INT_OUTPUT_DATA	(w/o)
 *	Interrupt mode output byte.
 *
 * Polled I/O, used by (e.g.) kmdb, when normal system services are
 * unavailable:
 *
 * I8042_POLL_INPUT_AVAIL	(r/o)
 *	Polled mode input bytes available?  Zero = No.
 * I8042_POLL_INPUT_DATA	(r/o)
 *	Polled mode input byte.
 * I8042_POLL_OUTPUT_DATA	(w/o)
 *	Polled mode output byte.
 *
 * Note that in polled mode we cannot use cmn_err; only prom_printf is safe.
 */
static uint8_t
i8042_get8(ddi_acc_impl_t *handlep, uint8_t *addr)
{
	struct i8042_port *port;
	struct i8042 *global;
	uint8_t	ret;
	ddi_acc_hdl_t	*h;
	uint8_t stat;

	h = (ddi_acc_hdl_t *)handlep;

	port = (struct i8042_port *)h->ah_bus_private;
	global = port->i8042_global;

	switch ((uintptr_t)addr) {
	case I8042_LOCK:
		ASSERT(port->has_glock != B_TRUE);	/* No reentrancy */
		mutex_enter(&global->i8042_out_mutex);
		/*
		 * Block other children requesting exclusive access here until
		 * the child possessing it relinquishes the lock.
		 */
		while (global->glock) {
			cv_wait(&global->glock_cv, &global->i8042_out_mutex);
		}
		port->has_glock = B_TRUE;
		global->glock = 1;
		mutex_exit(&global->i8042_out_mutex);
		ret = 0;
		break;

	case I8042_UNLOCK:
		mutex_enter(&global->i8042_out_mutex);
		ASSERT(global->glock != 0);
		ASSERT(port->has_glock == B_TRUE);
		port->has_glock = B_FALSE;
		global->glock = 0;
		/*
		 * Signal anyone waiting for exclusive access that it is now
		 * available.
		 */
		cv_signal(&global->glock_cv);
		mutex_exit(&global->i8042_out_mutex);
		ret = 0;
		break;

	case I8042_INT_INPUT_AVAIL:
		mutex_enter(&global->i8042_mutex);
		ret = port->rptr != port->wptr;
		mutex_exit(&global->i8042_mutex);
		return (ret);

	case I8042_INT_INPUT_DATA:
		mutex_enter(&global->i8042_mutex);

		if (port->rptr != port->wptr) {
			ret = port->buf[port->rptr];
			port->rptr = (port->rptr + 1) % BUFSIZ;
		} else {
#if defined(DEBUG)
			cmn_err(CE_WARN,
			    "i8042:  Tried to read from empty buffer");
#endif
			ret = 0;
		}


		mutex_exit(&global->i8042_mutex);

		break;

#if defined(DEBUG)
	case I8042_INT_OUTPUT_DATA:
	case I8042_POLL_OUTPUT_DATA:
		cmn_err(CE_WARN, "i8042:  read of write-only register 0x%p",
		    (void *)addr);
		ret = 0;
		break;
#endif

	case I8042_POLL_INPUT_AVAIL:
		if (port->rptr != port->wptr)
			return (B_TRUE);
		for (;;) {
			stat = ddi_get8(global->io_handle,
			    global->io_addr + I8042_STAT);
			if ((stat & I8042_STAT_OUTBF) == 0)
				return (B_FALSE);
			switch (port->which) {
			case MAIN_PORT:
				if ((stat & I8042_STAT_AUXBF) == 0)
					return (B_TRUE);
				break;
			case AUX_PORT:
				if ((stat & I8042_STAT_AUXBF) != 0)
					return (B_TRUE);
				break;
			default:
				cmn_err(CE_WARN, "data from unknown port: %d",
				    port->which);
			}
			/*
			 * Data for wrong port pending; discard it.
			 */
			(void) ddi_get8(global->io_handle,
			    global->io_addr + I8042_DATA);
		}

		/* NOTREACHED */

	case I8042_POLL_INPUT_DATA:
		if (port->rptr != port->wptr) {
			ret = port->buf[port->rptr];
			port->rptr = (port->rptr + 1) % BUFSIZ;
			return (ret);
		}

		stat = ddi_get8(global->io_handle,
		    global->io_addr + I8042_STAT);
		if ((stat & I8042_STAT_OUTBF) == 0) {
#if defined(DEBUG)
			prom_printf("I8042_POLL_INPUT_DATA:  no data!\n");
#endif
			return (0);
		}
		ret = ddi_get8(global->io_handle,
		    global->io_addr + I8042_DATA);
		switch (port->which) {
		case MAIN_PORT:
			if ((stat & I8042_STAT_AUXBF) == 0)
				return (ret);
			break;
		case AUX_PORT:
			if ((stat & I8042_STAT_AUXBF) != 0)
				return (ret);
			break;
		}
#if defined(DEBUG)
		prom_printf("I8042_POLL_INPUT_DATA:  data for wrong port!\n");
#endif
		return (0);

	default:
#if defined(DEBUG)
		cmn_err(CE_WARN, "i8042:  read of undefined register 0x%p",
		    (void *)addr);
#endif
		ret = 0;
		break;
	}
	return (ret);
}

static void
i8042_put8(ddi_acc_impl_t *handlep, uint8_t *addr, uint8_t value)
{
	struct i8042		*global;
	struct i8042_port	*port;
	ddi_acc_hdl_t		*h;

	h = (ddi_acc_hdl_t *)handlep;
	port = (struct i8042_port *)h->ah_bus_private;
	global = port->i8042_global;

	switch ((uintptr_t)addr) {
	case I8042_INT_OUTPUT_DATA:
	case I8042_POLL_OUTPUT_DATA:

		if ((uintptr_t)addr == I8042_INT_OUTPUT_DATA) {
			mutex_enter(&global->i8042_out_mutex);

			/*
			 * If no child has exclusive access, then proceed with
			 * the put8 below.  If a child (not the one making the
			 * call) has exclusive access, wait for it to be
			 * relinquished.  The use of i8042_out_mutex prevents
			 * children seeking exclusive access from getting it
			 * while a child is writing to the 8042.
			 */
			while (global->glock && !port->has_glock) {
				cv_wait(&global->glock_cv,
				    &global->i8042_out_mutex);
			}
		}

		if (port->which == AUX_PORT)
			i8042_send(global, I8042_CMD, I8042_CMD_WRITE_AUX);

		i8042_send(global, I8042_DATA, value);

		if ((uintptr_t)addr == I8042_INT_OUTPUT_DATA)
			mutex_exit(&global->i8042_out_mutex);

		break;

#if defined(DEBUG)
	case I8042_INT_INPUT_AVAIL:
	case I8042_INT_INPUT_DATA:
	case I8042_POLL_INPUT_AVAIL:
	case I8042_POLL_INPUT_DATA:
		cmn_err(CE_WARN, "i8042:  write of read-only register 0x%p",
		    (void *)addr);
		break;

	default:
		cmn_err(CE_WARN, "i8042:  read of undefined register 0x%p",
		    (void *)addr);
		break;
#endif
	}
}


/* ARGSUSED */
static int
i8042_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	struct i8042_port *port;
#if defined(USE_SOFT_INTRS)
	struct i8042	*global;
	int		ret;
#endif

	switch (intr_op) {
	case DDI_INTROP_SUPPORTED_TYPES:
		*(int *)result = DDI_INTR_TYPE_FIXED;
		break;
	case DDI_INTROP_GETCAP:
		if (i_ddi_intr_ops(dip, rdip, intr_op, hdlp, result)
		    == DDI_FAILURE)
			*(int *)result = 0;
		break;
	case DDI_INTROP_NINTRS:
	case DDI_INTROP_NAVAIL:
		*(int *)result = 1;
		break;
	case DDI_INTROP_ALLOC:
		*(int *)result = hdlp->ih_scratch1;
		break;
	case DDI_INTROP_FREE:
		break;
	case DDI_INTROP_GETPRI:
		/* Hard coding it for x86 */
		*(int *)result = 5;
		break;
	case DDI_INTROP_ADDISR:
		port = ddi_get_parent_data(rdip);

#if defined(USE_SOFT_INTRS)
		global = port->i8042_global;
		ret = ddi_intr_add_softint(rdip, &port->soft_hdl,
		    I8042_SOFTINT_PRI, hdlp->ih_cb_func, hdlp->ih_cb_arg1);

		if (ret != DDI_SUCCESS) {
#if defined(DEBUG)
			cmn_err(CE_WARN, "%s #%d:  "
			    "Cannot add soft interrupt for %s #%d, ret=%d.",
			    DRIVER_NAME(dip), ddi_get_instance(dip),
			    DRIVER_NAME(rdip), ddi_get_instance(rdip), ret);
#endif	/* defined(DEBUG) */
			return (ret);
		}

#else	/* defined(USE_SOFT_INTRS) */
		mutex_enter(&port->intr_mutex);
		port->intr_func = hdlp->ih_cb_func;
		port->intr_arg1 = hdlp->ih_cb_arg1;
		port->intr_arg2 = hdlp->ih_cb_arg2;
		mutex_exit(&port->intr_mutex);
#endif	/* defined(USE_SOFT_INTRS) */
		break;
	case DDI_INTROP_REMISR:
		port = ddi_get_parent_data(rdip);

#if defined(USE_SOFT_INTRS)
		global = port->i8042_global;
		mutex_enter(&global->i8042_mutex);
		port->soft_hdl = 0;
		mutex_exit(&global->i8042_mutex);
#else	/* defined(USE_SOFT_INTRS) */
		mutex_enter(&port->intr_mutex);
		port->intr_func = NULL;
		mutex_exit(&port->intr_mutex);
#endif	/* defined(USE_SOFT_INTRS) */
		break;
	case DDI_INTROP_ENABLE:
		port = ddi_get_parent_data(rdip);
#if defined(USE_SOFT_INTRS)
		global = port->i8042_global;
		mutex_enter(&global->i8042_mutex);
		port->soft_intr_enabled = B_TRUE;
		if (port->wptr != port->rptr)
			(void) ddi_intr_trigger_softint(port->soft_hdl,
			    port->intr_arg2);
		mutex_exit(&global->i8042_mutex);
#else	/* defined(USE_SOFT_INTRS) */
		mutex_enter(&port->intr_mutex);
		if (port->wptr != port->rptr)
			port->intr_func(port->intr_arg1, port->intr_arg2);
		mutex_exit(&port->intr_mutex);
#endif	/* defined(USE_SOFT_INTRS) */
		break;
	case DDI_INTROP_DISABLE:
#if defined(USE_SOFT_INTRS)
		port = ddi_get_parent_data(rdip);
		global = port->i8042_global;
		mutex_enter(&global->i8042_mutex);
		port->soft_intr_enabled = B_FALSE;
		(void) ddi_intr_remove_softint(port->soft_hdl);
		mutex_exit(&global->i8042_mutex);
#endif	/* defined(USE_SOFT_INTRS) */
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
i8042_ctlops(dev_info_t *dip, dev_info_t *rdip,
    ddi_ctl_enum_t op, void *arg, void *result)
{
	int	*iprop;
	unsigned int	iprop_len;
	int	which_port;
	char	name[16];
	struct i8042	*global;
	dev_info_t	*child;

	global = ddi_get_driver_private(dip);

	switch (op) {
	case DDI_CTLOPS_INITCHILD:
		child = (dev_info_t *)arg;
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child,
		    DDI_PROP_DONTPASS, "reg", &iprop, &iprop_len) !=
		    DDI_SUCCESS) {
#if defined(DEBUG)
			cmn_err(CE_WARN, "%s #%d:  Missing 'reg' on %s@???",
			    DRIVER_NAME(dip), ddi_get_instance(dip),
			    ddi_node_name(child));
#endif
			return (DDI_FAILURE);
		}
		which_port = iprop[0];
		ddi_prop_free((void *)iprop);

		(void) sprintf(name, "%d", which_port);
		ddi_set_name_addr(child, name);
		ddi_set_parent_data(child,
		    (caddr_t)&global->i8042_ports[which_port]);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_UNINITCHILD:
		child = (dev_info_t *)arg;
		ddi_set_name_addr(child, NULL);
		ddi_set_parent_data(child, NULL);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REPORTDEV:
		cmn_err(CE_CONT, "?8042 device:  %s@%s, %s # %d\n",
		    ddi_node_name(rdip), ddi_get_name_addr(rdip),
		    DRIVER_NAME(rdip), ddi_get_instance(rdip));
		return (DDI_SUCCESS);

	default:
		return (ddi_ctlops(dip, rdip, op, arg, result));
	}
	/* NOTREACHED */
}

#if defined(__x86)
static dev_info_t *
i8042_devi_findchild_by_node_name(dev_info_t *pdip, char *nodename)
{
	dev_info_t *child;

	ASSERT(DEVI_BUSY_OWNED(pdip));

	if (nodename == NULL) {
		return ((dev_info_t *)NULL);
	}

	for (child = ddi_get_child(pdip); child != NULL;
	    child = ddi_get_next_sibling(child)) {

		if (strcmp(ddi_node_name(child), nodename) == 0)
			break;
	}
	return (child);
}

static void
alloc_kb_mouse(dev_info_t *i8042_dip, int nodes_needed)
{
	dev_info_t *xdip;
	int acpi_off = 0;
	char *acpi_prop;

	/*
	 * If ACPI enumeration is not disabled and has taken place, return
	 * early and do nothing.
	 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "acpi-enum", &acpi_prop) == DDI_PROP_SUCCESS) {
		if (strcmp("off", acpi_prop) == 0) {
			acpi_off = 1;
		}
		ddi_prop_free(acpi_prop);
	}
	if (acpi_off == 0) {
		return;
	}

	if (nodes_needed & I8042_MOUSE) {
		/* mouse */
		ndi_devi_alloc_sleep(i8042_dip, "mouse",
		    (pnode_t)DEVI_SID_NODEID, &xdip);
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, xdip,
		    "reg", 1);
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, xdip,
		    "interrupts", 2);
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, xdip,
		    "compatible", "pnpPNP,f03");
		/*
		 * The device_type property does not matter on SPARC.  Retain it
		 * on x86 for compatibility with the previous pseudo-prom.
		 */
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, xdip,
		    "device_type", "mouse");
		(void) ndi_devi_bind_driver(xdip, 0);
	}

	if (nodes_needed & I8042_KEYBOARD) {
		/* keyboard */
		ndi_devi_alloc_sleep(i8042_dip, "keyboard",
		    (pnode_t)DEVI_SID_NODEID, &xdip);
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, xdip,
		    "reg", 0);
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, xdip,
		    "interrupts", 1);
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, xdip,
		    "compatible", "pnpPNP,303");
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, xdip,
		    "device_type", "keyboard");
		(void) ndi_devi_bind_driver(xdip, 0);
	}
}
#endif

static int
i8042_bus_config(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg, dev_info_t **childp)
{
#if defined(__x86)
	int nodes_needed = 0;

	/*
	 * On x86 systems, if ACPI is disabled, the only way the
	 * keyboard and mouse can be enumerated is by creating them
	 * manually.  The following code searches for the existence of
	 * the keyboard and mouse nodes and creates them if they are not
	 * found.
	 */
	ndi_devi_enter(parent);
	if (i8042_devi_findchild_by_node_name(parent, "keyboard") == NULL)
		nodes_needed |= I8042_KEYBOARD;
	if (i8042_devi_findchild_by_node_name(parent, "mouse") == NULL)
		nodes_needed |= I8042_MOUSE;

	/* If the mouse and keyboard nodes do not already exist, create them */
	if (nodes_needed)
		alloc_kb_mouse(parent, nodes_needed);
	ndi_devi_exit(parent);
#endif
	return (ndi_busop_bus_config(parent, flags, op, arg, childp, 0));
}

static int
i8042_bus_unconfig(dev_info_t *parent, uint_t flags,
    ddi_bus_config_op_t op, void *arg)
{
	/*
	 * The NDI_UNCONFIG flag allows the reference count on this nexus to be
	 * decremented when children's drivers are unloaded, enabling the nexus
	 * itself to be unloaded.
	 */
	return (ndi_busop_bus_unconfig(parent, flags | NDI_UNCONFIG, op, arg));
}

#ifdef __sparc
static int
i8042_build_interrupts_property(dev_info_t *dip)
{
	dev_info_t *child = ddi_get_child(dip);
	uint_t nintr;
	int *intrs = NULL;
	int interrupts[MAX_INTERRUPTS];
	int i = 0;

	/* Walk the children of this node, scanning for interrupts properties */
	while (child != NULL && i < MAX_INTERRUPTS) {

		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child,
		    DDI_PROP_DONTPASS, "interrupts", &intrs, &nintr)
		    == DDI_PROP_SUCCESS && intrs != NULL) {

			while (nintr > 0 && i < MAX_INTERRUPTS) {
				interrupts[i++] = intrs[--nintr];
			}
			ddi_prop_free(intrs);
		}

		child = ddi_get_next_sibling(child);
	}

	if (ddi_prop_update_int_array(DDI_DEV_T_NONE, dip, "interrupts",
	    interrupts, i) != DDI_PROP_SUCCESS) {

		return (DDI_FAILURE);
	}

	/*
	 * Oh, the humanity. On the platforms on which we need to
	 * synthesize an interrupts property, we ALSO need to update the
	 * device_type property, and set it to "serial" in order for the
	 * correct interrupt PIL to be chosen by the framework.
	 */
	if (ddi_prop_update_string(DDI_DEV_T_NONE, dip, "device_type", "serial")
	    != DDI_PROP_SUCCESS) {

		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static boolean_t
i8042_is_polling_platform(void)
{
	/*
	 * Returns true if this platform is one of the platforms
	 * that has interrupt issues with the PS/2 keyboard/mouse.
	 */
	if (PLATFORM_MATCH("SUNW,UltraAX-"))
		return (B_TRUE);
	else
		return (B_FALSE);
}
#endif
