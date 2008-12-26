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
 *
 * The "rmc_comm" driver provides access to the RMC so that its clients need
 * not be concerned with the details of the access mechanism, which in this
 * case is implemented via a packet-based protocol over a serial link via a
 * 16550 compatible serial port.
 */


/*
 *  Header files
 */
#include <sys/conf.h>
#include <sys/membar.h>
#include <sys/modctl.h>
#include <sys/strlog.h>
#include <sys/types.h>
#include <sys/sunddi.h>
#include <sys/ddi.h>
#include <sys/rmc_comm_dp_boot.h>
#include <sys/rmc_comm_dp.h>
#include <sys/rmc_comm_drvintf.h>
#include <sys/rmc_comm.h>
#include <sys/cpu_sgnblk_defs.h>

/*
 * Local definitions
 */
#define	MYNAME			"rmc_comm"
#define	NOMAJOR			(~(major_t)0)
#define	DUMMY_VALUE		(~(int8_t)0)

/*
 * Local data
 */
static void *rmc_comm_statep;
static major_t rmc_comm_major = NOMAJOR;
static kmutex_t rmc_comm_attach_lock;
static ddi_device_acc_attr_t rmc_comm_dev_acc_attr[1] =
{
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};
static int watchdog_was_active;
extern int watchdog_activated;
extern int watchdog_enable;

/*
 * prototypes
 */

extern void dp_reset(struct rmc_comm_state *, uint8_t, boolean_t, boolean_t);
static void sio_put_reg(struct rmc_comm_state *, uint_t, uint8_t);
static uint8_t sio_get_reg(struct rmc_comm_state *, uint_t);
static void sio_check_fault_status(struct rmc_comm_state *);
static boolean_t sio_data_ready(struct rmc_comm_state *);
static void rmc_comm_set_irq(struct rmc_comm_state *, boolean_t);
static uint_t rmc_comm_hi_intr(caddr_t);
static uint_t rmc_comm_softint(caddr_t);
static void rmc_comm_cyclic(void *);
static void rmc_comm_hw_reset(struct rmc_comm_state *);
static void rmc_comm_offline(struct rmc_comm_state *);
static int rmc_comm_online(struct rmc_comm_state *, dev_info_t *);
static void rmc_comm_unattach(struct rmc_comm_state *, dev_info_t *, int,
    boolean_t, boolean_t, boolean_t);
static int rmc_comm_attach(dev_info_t *, ddi_attach_cmd_t);
static int rmc_comm_detach(dev_info_t *, ddi_detach_cmd_t);

/*
 * for client leaf drivers to register their desire for rmc_comm
 * to stay attached
 */
int
rmc_comm_register()
{
	struct rmc_comm_state *rcs;

	mutex_enter(&rmc_comm_attach_lock);
	rcs = ddi_get_soft_state(rmc_comm_statep, 0);
	if ((rcs == NULL) || (!rcs->is_attached)) {
		mutex_exit(&rmc_comm_attach_lock);
		return (DDI_FAILURE);
	}
	rcs->n_registrations++;
	mutex_exit(&rmc_comm_attach_lock);
	return (DDI_SUCCESS);
}

void
rmc_comm_unregister()
{
	struct rmc_comm_state *rcs;

	mutex_enter(&rmc_comm_attach_lock);
	rcs = ddi_get_soft_state(rmc_comm_statep, 0);
	ASSERT(rcs != NULL);
	ASSERT(rcs->n_registrations != 0);
	rcs->n_registrations--;
	mutex_exit(&rmc_comm_attach_lock);
}

/*
 * to get the soft state structure of a specific instance
 */
struct rmc_comm_state *
rmc_comm_getstate(dev_info_t *dip, int instance, const char *caller)
{
	struct rmc_comm_state *rcs = NULL;
	dev_info_t *sdip = NULL;
	major_t dmaj = NOMAJOR;

	if (dip != NULL) {
		/*
		 * Use the instance number from the <dip>; also,
		 * check that it really corresponds to this driver
		 */
		instance = ddi_get_instance(dip);
		dmaj = ddi_driver_major(dip);
		if (rmc_comm_major == NOMAJOR && dmaj != NOMAJOR)
			rmc_comm_major = dmaj;
		else if (dmaj != rmc_comm_major) {
			cmn_err(CE_WARN,
			    "%s: major number mismatch (%d vs. %d) in %s(),"
			    "probably due to child misconfiguration",
			    MYNAME, rmc_comm_major, dmaj, caller);
			instance = -1;
		}
	}
	if (instance >= 0)
		rcs = ddi_get_soft_state(rmc_comm_statep, instance);
	if (rcs != NULL) {
		sdip = rcs->dip;
		if (dip == NULL && sdip == NULL)
			rcs = NULL;
		else if (dip != NULL && sdip != NULL && sdip != dip) {
			cmn_err(CE_WARN,
			    "%s: devinfo mismatch (%p vs. %p) in %s(), "
			    "probably due to child misconfiguration", MYNAME,
			    (void *)dip, (void *)sdip, caller);
			rcs = NULL;
		}
	}

	return (rcs);
}


/*
 * Lowest-level serial I/O chip register read/write
 */
static void
sio_put_reg(struct rmc_comm_state *rcs, uint_t reg, uint8_t val)
{
	DPRINTF(rcs, DSER, (CE_CONT, "REG[%d]<-$%02x", reg, val));

	if (rcs->sd_state.sio_handle != NULL && !rcs->sd_state.sio_fault) {
		/*
		 * The chip is mapped as "I/O" (e.g. with the side-effect
		 * bit on SPARC), therefore accesses are required to be
		 * in-order, with no value cacheing.  However, there can
		 * still be write-behind buffering, so it is not guaranteed
		 * that a write actually reaches the chip in a given time.
		 *
		 * To force the access right through to the chip, we follow
		 * the write with another write (to the SCRATCH register)
		 * and a read (of the value just written to the SCRATCH
		 * register).  The SCRATCH register is specifically provided
		 * for temporary data and has no effect on the SIO's own
		 * operation, making it ideal as a synchronising mechanism.
		 *
		 * If we didn't do this, it would be possible that the new
		 * value wouldn't reach the chip (and have the *intended*
		 * side-effects, such as disabling interrupts), for such a
		 * long time that the processor could execute a *lot* of
		 * instructions - including exiting the interrupt service
		 * routine and re-enabling interrupts.  This effect was
		 * observed to lead to spurious (unclaimed) interrupts in
		 * some circumstances.
		 *
		 * This will no longer be needed once "synchronous" access
		 * handles are available (see PSARC/2000/269 and 2000/531).
		 */
		ddi_put8(rcs->sd_state.sio_handle,
		    rcs->sd_state.sio_regs + reg, val);
		ddi_put8(rcs->sd_state.sio_handle,
		    rcs->sd_state.sio_regs + SIO_SCR, val);
		membar_sync();
		(void) ddi_get8(rcs->sd_state.sio_handle,
		    rcs->sd_state.sio_regs + SIO_SCR);
	}
}

static uint8_t
sio_get_reg(struct rmc_comm_state *rcs, uint_t reg)
{
	uint8_t val;

	if (rcs->sd_state.sio_handle && !rcs->sd_state.sio_fault)
		val = ddi_get8(rcs->sd_state.sio_handle,
		    rcs->sd_state.sio_regs + reg);
	else
		val = DUMMY_VALUE;
	DPRINTF(rcs, DSER, (CE_CONT, "$%02x<-REG[%d]", val, reg));
	return (val);
}

static void
sio_check_fault_status(struct rmc_comm_state *rcs)
{
	rcs->sd_state.sio_fault =
	    ddi_check_acc_handle(rcs->sd_state.sio_handle) != DDI_SUCCESS;
}

boolean_t
rmc_comm_faulty(struct rmc_comm_state *rcs)
{
	if (!rcs->sd_state.sio_fault)
		sio_check_fault_status(rcs);
	return (rcs->sd_state.sio_fault);
}

/*
 * Check for data ready.
 */
static boolean_t
sio_data_ready(struct rmc_comm_state *rcs)
{
	uint8_t status;

	/*
	 * Data is available if the RXDA bit in the LSR is nonzero
	 * (if reading it didn't incur a fault).
	 */
	status = sio_get_reg(rcs, SIO_LSR);
	return ((status & SIO_LSR_RXDA) != 0 && !rmc_comm_faulty(rcs));
}

/*
 * Enable/disable interrupts
 */
static void
rmc_comm_set_irq(struct rmc_comm_state *rcs, boolean_t newstate)
{
	uint8_t val;

	val = newstate ? SIO_IER_RXHDL_IE : 0;
	sio_put_reg(rcs, SIO_IER, SIO_IER_STD | val);
	rcs->sd_state.hw_int_enabled = newstate;
}

/*
 * High-level interrupt handler:
 *	Checks whether initialisation is complete (to avoid a race
 *	with mutex_init()), and whether chip interrupts are enabled.
 *	If not, the interrupt's not for us, so just return UNCLAIMED.
 *	Otherwise, disable the interrupt, trigger a softint, and return
 *	CLAIMED.  The softint handler will then do all the real work.
 *
 *	NOTE: the chip interrupt capability is only re-enabled once the
 *	receive code has run, but that can be called from a poll loop
 *	or cyclic callback as well as from the softint.  So it's *not*
 *	guaranteed that there really is a chip interrupt pending here,
 *	'cos the work may already have been done and the reason for the
 *	interrupt gone away before we get here.
 *
 *	OTOH, if we come through here twice without the receive code
 *	having run in between, that's definitely wrong.  In such an
 *	event, we would notice that chip interrupts haven't yet been
 *	re-enabled and return UNCLAIMED, allowing the system's jabber
 *	protect code (if any) to do its job.
 */
static uint_t
rmc_comm_hi_intr(caddr_t arg)
{
	struct rmc_comm_state *rcs = (void *)arg;
	uint_t claim;

	claim = DDI_INTR_UNCLAIMED;
	if (rcs->sd_state.cycid != NULL) {
		/*
		 * Handle the case where this interrupt fires during
		 * panic processing.  If that occurs, then a thread
		 * in rmc_comm might have been idled while holding
		 * hw_mutex.  If so, that thread will never make
		 * progress, and so we do not want to unconditionally
		 * grab hw_mutex.
		 */
		if (ddi_in_panic() != 0) {
			if (mutex_tryenter(rcs->sd_state.hw_mutex) == 0) {
				return (claim);
			}
		} else {
			mutex_enter(rcs->sd_state.hw_mutex);
		}
		if (rcs->sd_state.hw_int_enabled) {
			rmc_comm_set_irq(rcs, B_FALSE);
			ddi_trigger_softintr(rcs->sd_state.softid);
			claim = DDI_INTR_CLAIMED;
		}
		mutex_exit(rcs->sd_state.hw_mutex);
	}
	return (claim);
}

/*
 * Packet receive handler
 *
 * This routine should be called from the low-level softint, or the
 * cyclic callback, or rmc_comm_cmd() (for polled operation), with the
 * low-level mutex already held.
 */
void
rmc_comm_serdev_receive(struct rmc_comm_state *rcs)
{
	uint8_t data;

	DPRINTF(rcs, DSER, (CE_CONT, "serdev_receive: soft int handler\n"));

	/*
	 * Check for access faults before starting the receive
	 * loop (we don't want to cause bus errors or suchlike
	 * unpleasantness in the event that the SIO has died).
	 */
	if (!rmc_comm_faulty(rcs)) {

		char *rx_buf = rcs->sd_state.serdev_rx_buf;
		uint16_t rx_buflen = 0;

		/*
		 * Read bytes from the FIFO until they're all gone
		 * or our buffer overflows (which must be an error)
		 */

		/*
		 * At the moment, the receive buffer is overwritten any
		 * time data is received from the serial device.
		 * This should not pose problems (probably!) as the data
		 * protocol is half-duplex
		 * Otherwise, a circular buffer must be implemented!
		 */
		mutex_enter(rcs->sd_state.hw_mutex);
		while (sio_data_ready(rcs)) {
			data = sio_get_reg(rcs, SIO_RXD);
			rx_buf[rx_buflen++] = data;
			if (rx_buflen >= SIO_MAX_RXBUF_SIZE)
				break;
		}
		rcs->sd_state.serdev_rx_count = rx_buflen;

		DATASCOPE(rcs, 'R', rx_buf, rx_buflen)

		rmc_comm_set_irq(rcs, B_TRUE);
		mutex_exit(rcs->sd_state.hw_mutex);

		/*
		 * call up the data protocol receive handler
		 */
		rmc_comm_dp_drecv(rcs, (uint8_t *)rx_buf, rx_buflen);
	}
}

/*
 * Low-level softint handler
 *
 * This routine should be triggered whenever there's a byte to be read
 */
static uint_t
rmc_comm_softint(caddr_t arg)
{
	struct rmc_comm_state *rcs = (void *)arg;

	mutex_enter(rcs->dp_state.dp_mutex);
	rmc_comm_serdev_receive(rcs);
	mutex_exit(rcs->dp_state.dp_mutex);
	return (DDI_INTR_CLAIMED);
}

/*
 * Cyclic handler: just calls the receive routine, in case interrupts
 * are not being delivered and in order to handle command timeout
 */
static void
rmc_comm_cyclic(void *arg)
{
	struct rmc_comm_state *rcs = (void *)arg;

	mutex_enter(rcs->dp_state.dp_mutex);
	rmc_comm_serdev_receive(rcs);
	mutex_exit(rcs->dp_state.dp_mutex);
}

/*
 * Serial protocol
 *
 * This routine builds a command and sets it in progress.
 */
void
rmc_comm_serdev_send(struct rmc_comm_state *rcs, char *buf, int buflen)
{
	uint8_t *p;
	uint8_t status;

	/*
	 * Check and update the SIO h/w fault status before accessing
	 * the chip registers.  If there's a (new or previous) fault,
	 * we'll run through the protocol but won't really touch the
	 * hardware and all commands will timeout.  If a previously
	 * discovered fault has now gone away (!), then we can (try to)
	 * proceed with the new command (probably a probe).
	 */
	sio_check_fault_status(rcs);

	/*
	 * Send the command now by stuffing the packet into the Tx FIFO.
	 */
	DATASCOPE(rcs, 'S', buf, buflen)

	mutex_enter(rcs->sd_state.hw_mutex);
	p = (uint8_t *)buf;
	while (p < (uint8_t *)&buf[buflen]) {

		/*
		 * before writing to the TX holding register, we make sure that
		 * it is empty. In this case, there will be no chance to
		 * overflow the serial device FIFO (but, on the other hand,
		 * it may introduce some latency)
		 */
		status = sio_get_reg(rcs, SIO_LSR);
		while ((status & SIO_LSR_XHRE) == 0) {
			drv_usecwait(100);
			status = sio_get_reg(rcs, SIO_LSR);
		}
		sio_put_reg(rcs, SIO_TXD, *p++);
	}
	mutex_exit(rcs->sd_state.hw_mutex);
}

/*
 * wait for the tx fifo to drain - used for urgent nowait requests
 */
void
rmc_comm_serdev_drain(struct rmc_comm_state *rcs)
{
	uint8_t status;

	mutex_enter(rcs->sd_state.hw_mutex);
	status = sio_get_reg(rcs, SIO_LSR);
	while ((status & SIO_LSR_XHRE) == 0) {
		drv_usecwait(100);
		status = sio_get_reg(rcs, SIO_LSR);
	}
	mutex_exit(rcs->sd_state.hw_mutex);
}

/*
 * Hardware setup - put the SIO chip in the required operational
 * state,  with all our favourite parameters programmed correctly.
 * This routine leaves all SIO interrupts disabled.
 */

static void
rmc_comm_hw_reset(struct rmc_comm_state *rcs)
{
	uint16_t divisor;

	/*
	 * Disable interrupts, soft reset Tx and Rx circuitry,
	 * reselect standard modes (bits/char, parity, etc).
	 */
	rmc_comm_set_irq(rcs, B_FALSE);
	sio_put_reg(rcs, SIO_FCR, SIO_FCR_RXSR | SIO_FCR_TXSR);
	sio_put_reg(rcs, SIO_LCR, SIO_LCR_STD);

	/*
	 * Select the proper baud rate; if the value is invalid
	 * (presumably 0, i.e. not specified, but also if the
	 * "baud" property is set to some silly value), we assume
	 * the default.
	 */
	if (rcs->baud < SIO_BAUD_MIN || rcs->baud > SIO_BAUD_MAX) {
		divisor = SIO_BAUD_TO_DIVISOR(SIO_BAUD_DEFAULT) *
		    rcs->baud_divisor_factor;
	} else {
		divisor = SIO_BAUD_TO_DIVISOR(rcs->baud) *
		    rcs->baud_divisor_factor;
	}

	/*
	 * According to the datasheet, it is forbidden for the divisor
	 * register to be zero.  So when loading the register in two
	 * steps, we have to make sure that the temporary value formed
	 * between loads is nonzero.  However, we can't rely on either
	 * half already having a nonzero value, as the datasheet also
	 * says that these registers are indeterminate after a reset!
	 * So, we explicitly set the low byte to a non-zero value first;
	 * then we can safely load the high byte, and then the correct
	 * value for the low byte, without the result ever being zero.
	 */
	sio_put_reg(rcs, SIO_BSR, SIO_BSR_BANK1);
	sio_put_reg(rcs, SIO_LBGDL, 0xff);
	sio_put_reg(rcs, SIO_LBGDH, divisor >> 8);
	sio_put_reg(rcs, SIO_LBGDL, divisor & 0xff);
	sio_put_reg(rcs, SIO_BSR, SIO_BSR_BANK0);

	/*
	 * Program the remaining device registers as required
	 */
	sio_put_reg(rcs, SIO_MCR, SIO_MCR_STD);
	sio_put_reg(rcs, SIO_FCR, SIO_FCR_STD);
}

/*
 * Higher-level setup & teardown
 */
static void
rmc_comm_offline(struct rmc_comm_state *rcs)
{
	if (rcs->sd_state.sio_handle != NULL)
		ddi_regs_map_free(&rcs->sd_state.sio_handle);
	rcs->sd_state.sio_handle = NULL;
	rcs->sd_state.sio_regs = NULL;
}

static int
rmc_comm_online(struct rmc_comm_state *rcs, dev_info_t *dip)
{
	ddi_acc_handle_t h;
	caddr_t p;
	int nregs;
	int err;

	if (ddi_dev_nregs(dip, &nregs) != DDI_SUCCESS)
		nregs = 0;
	switch (nregs) {
	default:
	case 1:
		/*
		 *  regset 0 represents the SIO operating registers
		 */
		err = ddi_regs_map_setup(dip, 0, &p, 0, 0,
		    rmc_comm_dev_acc_attr, &h);
		if (err != DDI_SUCCESS)
			return (EIO);
		rcs->sd_state.sio_handle = h;
		rcs->sd_state.sio_regs = (void *)p;
		break;
	case 0:
		/*
		 *  If no registers are defined, succeed vacuously;
		 *  commands will be accepted, but we fake the accesses.
		 */
		break;
	}

	/*
	 * Now that the registers are mapped, we can initialise the SIO h/w
	 */
	rmc_comm_hw_reset(rcs);
	return (0);
}


/*
 * Initialization of the serial device (data structure, mutex, cv, hardware
 * and so on). It is called from the attach routine.
 */

int
rmc_comm_serdev_init(struct rmc_comm_state *rcs, dev_info_t *dip)
{
	int err = DDI_SUCCESS;

	rcs->sd_state.cycid = NULL;

	/*
	 *  Online the hardware ...
	 */
	err = rmc_comm_online(rcs, dip);
	if (err != 0)
		return (-1);

	/*
	 * call ddi_get_soft_iblock_cookie() to retrieve the
	 * the interrupt block cookie so that the mutexes are initialized
	 * before adding the interrupt (to avoid a potential race condition).
	 */

	err = ddi_get_soft_iblock_cookie(dip, DDI_SOFTINT_LOW,
	    &rcs->dp_state.dp_iblk);
	if (err != DDI_SUCCESS)
		return (-1);

	err = ddi_get_iblock_cookie(dip, 0, &rcs->sd_state.hw_iblk);
	if (err != DDI_SUCCESS)
		return (-1);

	/*
	 * initialize mutex here before adding hw/sw interrupt handlers
	 */
	mutex_init(rcs->dp_state.dp_mutex, NULL, MUTEX_DRIVER,
	    rcs->dp_state.dp_iblk);

	mutex_init(rcs->sd_state.hw_mutex, NULL, MUTEX_DRIVER,
	    rcs->sd_state.hw_iblk);

	/*
	 * Install soft and hard interrupt handler(s)
	 *
	 * the soft intr. handler will need the data protocol lock (dp_mutex)
	 * So, data protocol mutex and iblock cookie are created/initialized
	 * here
	 */

	err = ddi_add_softintr(dip, DDI_SOFTINT_LOW, &rcs->sd_state.softid,
	    &rcs->dp_state.dp_iblk, NULL, rmc_comm_softint, (caddr_t)rcs);
	if (err != DDI_SUCCESS) {
		mutex_destroy(rcs->dp_state.dp_mutex);
		mutex_destroy(rcs->sd_state.hw_mutex);
		return (-1);
	}

	/*
	 * hardware interrupt
	 */

	if (rcs->sd_state.sio_handle != NULL) {
		err = ddi_add_intr(dip, 0, &rcs->sd_state.hw_iblk, NULL,
		    rmc_comm_hi_intr, (caddr_t)rcs);

		/*
		 * did we successfully install the h/w interrupt handler?
		 */
		if (err != DDI_SUCCESS) {
			ddi_remove_softintr(rcs->sd_state.softid);
			mutex_destroy(rcs->dp_state.dp_mutex);
			mutex_destroy(rcs->sd_state.hw_mutex);
			return (-1);
		}
	}

	/*
	 * Start periodical callbacks
	 */
	rcs->sd_state.cycid = ddi_periodic_add(rmc_comm_cyclic, rcs,
	    5 * RMC_COMM_ONE_SEC, DDI_IPL_1);
	return (0);
}

/*
 * Termination of the serial device (data structure, mutex, cv, hardware
 * and so on). It is called from the detach routine.
 */

void
rmc_comm_serdev_fini(struct rmc_comm_state *rcs, dev_info_t *dip)
{
	rmc_comm_hw_reset(rcs);

	if (rcs->sd_state.cycid != NULL) {
		ddi_periodic_delete(rcs->sd_state.cycid);
		rcs->sd_state.cycid = NULL;

		if (rcs->sd_state.sio_handle != NULL)
			ddi_remove_intr(dip, 0, rcs->sd_state.hw_iblk);

		ddi_remove_softintr(rcs->sd_state.softid);

		mutex_destroy(rcs->sd_state.hw_mutex);

		mutex_destroy(rcs->dp_state.dp_mutex);
	}
	rmc_comm_offline(rcs);
}

/*
 * device driver entry routines (init/fini, attach/detach, ...)
 */

/*
 *  Clean up on detach or failure of attach
 */
static void
rmc_comm_unattach(struct rmc_comm_state *rcs, dev_info_t *dip, int instance,
    boolean_t drvi_init, boolean_t dp_init, boolean_t sd_init)
{
	if (rcs != NULL) {
		/*
		 * disable interrupts now
		 */
		rmc_comm_set_irq(rcs, B_FALSE);

		/*
		 * driver interface termination (if it has been initialized)
		 */
		if (drvi_init)
			rmc_comm_drvintf_fini(rcs);

		/*
		 * data protocol termination (if it has been initialized)
		 */
		if (dp_init)
			rmc_comm_dp_fini(rcs);

		/*
		 * serial device termination (if it has been initialized)
		 */
		if (sd_init)
			rmc_comm_serdev_fini(rcs, dip);

		ddi_set_driver_private(dip, NULL);
	}
	ddi_soft_state_free(rmc_comm_statep, instance);
}

/*
 *  Autoconfiguration routines
 */

static int
rmc_comm_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct rmc_comm_state *rcs = NULL;
	sig_state_t *current_sgn_p;
	int instance;

	/*
	 * only allow one instance
	 */
	instance = ddi_get_instance(dip);
	if (instance != 0)
		return (DDI_FAILURE);

	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_RESUME:
		if ((rcs = rmc_comm_getstate(dip, instance,
		    "rmc_comm_attach")) == NULL)
			return (DDI_FAILURE);	/* this "can't happen" */

		rmc_comm_hw_reset(rcs);
		rmc_comm_set_irq(rcs, B_TRUE);
		rcs->dip = dip;

		mutex_enter(&tod_lock);
		if (watchdog_enable && tod_ops.tod_set_watchdog_timer != NULL &&
		    watchdog_was_active) {
			(void) tod_ops.tod_set_watchdog_timer(0);
		}
		mutex_exit(&tod_lock);

		mutex_enter(rcs->dp_state.dp_mutex);
		dp_reset(rcs, INITIAL_SEQID, 1, 1);
		mutex_exit(rcs->dp_state.dp_mutex);

		current_sgn_p = (sig_state_t *)modgetsymvalue(
		    "current_sgn", 0);
		if ((current_sgn_p != NULL) &&
		    (current_sgn_p->state_t.sig != 0)) {
			CPU_SIGNATURE(current_sgn_p->state_t.sig,
			    current_sgn_p->state_t.state,
			    current_sgn_p->state_t.sub_state, -1);
		}
		return (DDI_SUCCESS);

	case DDI_ATTACH:
		break;
	}

	/*
	 *  Allocate the soft-state structure
	 */
	if (ddi_soft_state_zalloc(rmc_comm_statep, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);
	if ((rcs = rmc_comm_getstate(dip, instance, "rmc_comm_attach")) ==
	    NULL) {
		rmc_comm_unattach(rcs, dip, instance, 0, 0, 0);
		return (DDI_FAILURE);
	}
	ddi_set_driver_private(dip, rcs);

	rcs->dip = NULL;

	/*
	 *  Set various options from .conf properties
	 */
	rcs->baud = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "baud-rate", 0);
	rcs->debug = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "debug", 0);

	/*
	 * the baud divisor factor tells us how to scale the result of
	 * the SIO_BAUD_TO_DIVISOR macro for platforms which do not
	 * use the standard 24MHz uart clock
	 */
	rcs->baud_divisor_factor = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "baud-divisor-factor", SIO_BAUD_DIVISOR_MIN);

	/*
	 * try to be reasonable if the scale factor contains a silly value
	 */
	if ((rcs->baud_divisor_factor < SIO_BAUD_DIVISOR_MIN) ||
	    (rcs->baud_divisor_factor > SIO_BAUD_DIVISOR_MAX))
		rcs->baud_divisor_factor = SIO_BAUD_DIVISOR_MIN;

	/*
	 * initialize serial device
	 */
	if (rmc_comm_serdev_init(rcs, dip) != 0) {
		rmc_comm_unattach(rcs, dip, instance, 0, 0, 0);
		return (DDI_FAILURE);
	}

	/*
	 * initialize data protocol
	 */
	rmc_comm_dp_init(rcs);

	/*
	 * initialize driver interface
	 */
	if (rmc_comm_drvintf_init(rcs) != 0) {
		rmc_comm_unattach(rcs, dip, instance, 0, 1, 1);
		return (DDI_FAILURE);
	}

	/*
	 *  Initialise devinfo-related fields
	 */
	rcs->majornum = ddi_driver_major(dip);
	rcs->instance = instance;
	rcs->dip = dip;

	/*
	 * enable interrupts now
	 */
	rmc_comm_set_irq(rcs, B_TRUE);

	/*
	 *  All done, report success
	 */
	ddi_report_dev(dip);
	mutex_enter(&rmc_comm_attach_lock);
	rcs->is_attached = B_TRUE;
	mutex_exit(&rmc_comm_attach_lock);
	return (DDI_SUCCESS);
}

static int
rmc_comm_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct rmc_comm_state *rcs;
	int instance;

	instance = ddi_get_instance(dip);
	if ((rcs = rmc_comm_getstate(dip, instance, "rmc_comm_detach")) == NULL)
		return (DDI_FAILURE);	/* this "can't happen" */

	switch (cmd) {
	case DDI_SUSPEND:
		mutex_enter(&tod_lock);
		if (watchdog_enable && watchdog_activated &&
		    tod_ops.tod_clear_watchdog_timer != NULL) {
			watchdog_was_active = 1;
			(void) tod_ops.tod_clear_watchdog_timer();
		} else {
			watchdog_was_active = 0;
		}
		mutex_exit(&tod_lock);

		rcs->dip = NULL;
		rmc_comm_hw_reset(rcs);

		return (DDI_SUCCESS);

	case DDI_DETACH:
		/*
		 * reject detach if any client(s) still registered
		 */
		mutex_enter(&rmc_comm_attach_lock);
		if (rcs->n_registrations != 0) {
			mutex_exit(&rmc_comm_attach_lock);
			return (DDI_FAILURE);
		}
		/*
		 * Committed to complete the detach;
		 * mark as no longer attached, to prevent new clients
		 * registering (as part of a coincident attach)
		 */
		rcs->is_attached = B_FALSE;
		mutex_exit(&rmc_comm_attach_lock);
		rmc_comm_unattach(rcs, dip, instance, 1, 1, 1);
		return (DDI_SUCCESS);

	default:
		return (DDI_FAILURE);
	}
}

/*ARGSUSED*/
static int
rmc_comm_reset(dev_info_t *dip, ddi_reset_cmd_t cmd)
{
	struct rmc_comm_state *rcs;

	if ((rcs = rmc_comm_getstate(dip, -1, "rmc_comm_reset")) == NULL)
		return (DDI_FAILURE);
	rmc_comm_hw_reset(rcs);
	return (DDI_SUCCESS);
}

/*
 * System interface structures
 */
static struct dev_ops rmc_comm_dev_ops =
{
	DEVO_REV,
	0,				/* refcount		*/
	nodev,				/* getinfo		*/
	nulldev,			/* identify		*/
	nulldev,			/* probe		*/
	rmc_comm_attach,		/* attach		*/
	rmc_comm_detach,		/* detach		*/
	rmc_comm_reset,			/* reset		*/
	(struct cb_ops *)NULL,		/* driver operations	*/
	(struct bus_ops *)NULL,		/* bus operations	*/
	nulldev,			/* power()		*/
	ddi_quiesce_not_supported,	/* devo_quiesce */
};

static struct modldrv modldrv =
{
	&mod_driverops,
	"rmc_comm driver",
	&rmc_comm_dev_ops
};

static struct modlinkage modlinkage =
{
	MODREV_1,
	{
		&modldrv,
		NULL
	}
};

/*
 *  Dynamic loader interface code
 */
int
_init(void)
{
	int err;

	mutex_init(&rmc_comm_attach_lock, NULL, MUTEX_DRIVER, NULL);
	err = ddi_soft_state_init(&rmc_comm_statep,
	    sizeof (struct rmc_comm_state), 0);
	if (err == DDI_SUCCESS)
		if ((err = mod_install(&modlinkage)) != 0) {
			ddi_soft_state_fini(&rmc_comm_statep);
		}
	if (err != DDI_SUCCESS)
		mutex_destroy(&rmc_comm_attach_lock);
	return (err);
}

int
_info(struct modinfo *mip)
{
	return (mod_info(&modlinkage, mip));
}

int
_fini(void)
{
	int err;

	if ((err = mod_remove(&modlinkage)) == 0) {
		ddi_soft_state_fini(&rmc_comm_statep);
		rmc_comm_major = NOMAJOR;
		mutex_destroy(&rmc_comm_attach_lock);
	}
	return (err);
}
