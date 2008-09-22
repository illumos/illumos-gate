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
 * The "lombus" driver provides access to the LOMlite2 virtual registers,
 * so that its clients (children) need not be concerned with the details
 * of the access mechanism, which in this case is implemented via a
 * packet-based protocol over a serial link connected to one of the serial
 * ports of the SuperIO (SIO) chip.
 *
 * On the other hand, this driver doesn't generally know what the virtual
 * registers signify - only the clients need this information.
 */


/*
 *  Header files
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/intr.h>
#include <sys/kmem.h>
#include <sys/membar.h>
#include <sys/modctl.h>
#include <sys/note.h>
#include <sys/open.h>
#include <sys/poll.h>
#include <sys/spl.h>
#include <sys/stat.h>
#include <sys/strlog.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>

#include <sys/lombus.h>


#if	defined(NDI_ACC_HDL_V2)

/*
 * Compiling for Solaris 9+ with access handle enhancements
 */
#define	HANDLE_TYPE		ndi_acc_handle_t
#define	HANDLE_ADDR(hdlp)	(hdlp->ah_addr)
#define	HANDLE_FAULT(hdlp)	(hdlp->ah_fault)
#define	HANDLE_MAPLEN(hdlp)	(hdlp->ah_len)
#define	HANDLE_PRIVATE(hdlp)	(hdlp->ah_bus_private)

#else

/*
 * Compatibility definitions for backport to Solaris 8
 */
#define	HANDLE_TYPE		ddi_acc_impl_t
#define	HANDLE_ADDR(hdlp)	(hdlp->ahi_common.ah_addr)
#define	HANDLE_FAULT(hdlp)	(hdlp->ahi_fault)
#define	HANDLE_MAPLEN(hdlp)	(hdlp->ahi_common.ah_len)
#define	HANDLE_PRIVATE(hdlp)	(hdlp->ahi_common.ah_bus_private)

#define	ddi_driver_major(dip)	ddi_name_to_major(ddi_binding_name(dip))

#endif	/* NDI_ACC_HDL_V2 */


/*
 * Local definitions
 */
#define	MYNAME			"lombus"
#define	NOMAJOR			(~(major_t)0)
#define	DUMMY_VALUE		(~(int8_t)0)

#define	LOMBUS_INST_TO_MINOR(i)	(i)
#define	LOMBUS_MINOR_TO_INST(m)	(m)

#define	LOMBUS_DUMMY_ADDRESS	((caddr_t)0x0CADD1ED)
#define	ADDR_TO_OFFSET(a, hdlp)	((caddr_t)(a) - HANDLE_ADDR(hdlp))
#define	ADDR_TO_VREG(a)		((caddr_t)(a) - LOMBUS_DUMMY_ADDRESS)
#define	VREG_TO_ADDR(v)		(LOMBUS_DUMMY_ADDRESS + (v))


/*
 * The following definitions are taken from the datasheet
 * for the National Semiconductor PC87317 (SuperIO) chip.
 *
 * This chip implements UART functionality as logical device 6.
 * It provides all sorts of wierd modes and extensions, but we
 * have chosen to use only the 16550-compatible features
 * ("non-extended mode").
 *
 * Hardware: serial chip register numbers
 */
#define	SIO_RXD			0	/* read		*/
#define	SIO_TXD			0	/* write	*/
#define	SIO_IER			1
#define	SIO_EIR			2	/* read		*/
#define	SIO_FCR			2	/* write	*/
#define	SIO_LCR			3
#define	SIO_BSR			3	/* wierd	*/
#define	SIO_MCR			4
#define	SIO_LSR			5
#define	SIO_MSR			6
#define	SIO_SCR			7

#define	SIO_LBGDL		0	/* bank 1	*/
#define	SIO_LBGDH		1	/* bank 1	*/

/*
 * Hardware: serial chip register bits
 */
#define	SIO_IER_RXHDL_IE	0x01
#define	SIO_IER_STD		0x00

#define	SIO_EIR_IPF		0x01
#define	SIO_EIR_IPR0		0x02
#define	SIO_EIR_IPR1		0x04
#define	SIO_EIR_RXFT		0x08
#define	SIO_EIR_FEN0		0x40
#define	SIO_EIR_FEN1		0x80

#define	SIO_FCR_FIFO_EN		0x01
#define	SIO_FCR_RXSR		0x02
#define	SIO_FCR_TXSR		0x04
#define	SIO_FCR_RXFTH0		0x40
#define	SIO_FCR_RXFTH1		0x80
#define	SIO_FCR_STD		(SIO_FCR_RXFTH0|SIO_FCR_FIFO_EN)

#define	SIO_LCR_WLS0		0x01
#define	SIO_LCR_WLS1		0x02
#define	SIO_LCR_STB		0x04
#define	SIO_LCR_PEN		0x08
#define	SIO_LCR_EPS		0x10
#define	SIO_LCR_STKP		0x20
#define	SIO_LCR_SBRK		0x40
#define	SIO_LCR_BKSE		0x80
#define	SIO_LCR_8BIT		(SIO_LCR_WLS0|SIO_LCR_WLS1)
#define	SIO_LCR_EPAR		(SIO_LCR_PEN|SIO_LCR_EPS)
#define	SIO_LCR_STD		(SIO_LCR_8BIT|SIO_LCR_EPAR)

#define	SIO_BSR_BANK0		(SIO_LCR_STD)
#define	SIO_BSR_BANK1		(SIO_LCR_BKSE|SIO_LCR_STD)

#define	SIO_MCR_DTR		0x01
#define	SIO_MCR_RTS		0x02
#define	SIO_MCR_ISEN		0x08
#define	SIO_MCR_STD		(SIO_MCR_ISEN)

#define	SIO_LSR_RXDA		0x01
#define	SIO_LSR_OE		0x02
#define	SIO_LSR_PE		0x04
#define	SIO_LSR_FE		0x08
#define	SIO_LSR_BRKE		0x10
#define	SIO_LSR_TXRDY		0x20
#define	SIO_LSR_TXEMP		0x40
#define	SIO_LSR_ER_INF		0x80

#define	SIO_MSR_DCTS		0x01
#define	SIO_MSR_DDSR		0x02
#define	SIO_MSR_TERI		0x04
#define	SIO_MSR_DDCD		0x08
#define	SIO_MSR_CTS		0x10
#define	SIO_MSR_DSR		0x20
#define	SIO_MSR_RI		0x40
#define	SIO_MSR_DCD		0x80

/*
 * Min/max/default baud rates, and a macro to convert from a baud
 * rate to the number (divisor) to put in the baud rate registers
 */
#define	SIO_BAUD_MIN		50
#define	SIO_BAUD_MAX		115200
#define	SIO_BAUD_DEFAULT	38400
#define	SIO_BAUD_TO_DIVISOR(b)	(115200 / (b))


/*
 * Packet format ...
 */
#define	LOMBUS_MASK		0xc0	/* Byte-type bits		*/
#define	LOMBUS_PARAM		0x00	/* Parameter byte: 0b0xxxxxxx	*/
#define	LOMBUS_LAST		0x80	/* Last byte of packet		*/
#define	LOMBUS_CMD		0x80	/* Command byte:   0b10###XWV	*/
#define	LOMBUS_STATUS		0xc0	/* Status  byte:   0b11###AEV	*/

#define	LOMBUS_SEQ		0x38	/* Sequence number bits		*/
#define	LOMBUS_SEQ_LSB		0x08	/* Sequence number LSB		*/
#define	LOMBUS_CMD_XADDR	0x04	/* Extended (2-byte) addressing	*/
#define	LOMBUS_CMD_WRITE	0x02	/* Write command		*/
#define	LOMBUS_CMD_WMSB		0x01	/* Set MSB on Write		*/
#define	LOMBUS_CMD_READ		0x01	/* Read command			*/
#define	LOMBUS_CMD_NOP		0x00	/* NOP command			*/

#define	LOMBUS_STATUS_ASYNC	0x04	/* Asynchronous event pending	*/
#define	LOMBUS_STATUS_ERR	0x02	/* Error in command processing	*/
#define	LOMBUS_STATUS_MSB	0x01	/* MSB of Value read		*/

#define	LOMBUS_VREG_LO(x)	((x) & ((1 << 7) - 1))
#define	LOMBUS_VREG_HI(x)	((x) >> 7)

#define	LOMBUS_BUFSIZE		8


/*
 * Time periods, in nanoseconds
 *
 * Note that LOMBUS_ONE_SEC and some other time
 * periods are defined in <sys/lombus.h>
 */
#define	LOMBUS_CMD_POLL		(LOMBUS_ONE_SEC/20)
#define	LOMBUS_CTS_POLL		(LOMBUS_ONE_SEC/20)
#define	LOMBUS_CTS_TIMEOUT	(LOMBUS_ONE_SEC*2)


/*
 * Local datatypes
 */
enum lombus_cmdstate {
	LOMBUS_CMDSTATE_IDLE,
	LOMBUS_CMDSTATE_BUSY,
	LOMBUS_CMDSTATE_WAITING,
	LOMBUS_CMDSTATE_READY,
	LOMBUS_CMDSTATE_ERROR
};


/*
 * This driver's soft-state structure
 */

struct lombus_state {
	/*
	 * Configuration data, set during attach
	 */
	dev_info_t *dip;
	major_t majornum;
	int instance;

	ddi_acc_handle_t sio_handle;
	uint8_t *sio_regs;
	ddi_softintr_t softid;
	ddi_periodic_t cycid; /* periodical callback */

	/*
	 * Parameters derived from .conf properties
	 */
	boolean_t allow_echo;
	int baud;
	uint32_t debug;
	boolean_t fake_cts;

	/*
	 * Hardware mutex (initialised using <hw_iblk>),
	 * used to prevent retriggering the softint while
	 * it's still fetching data out of the chip FIFO.
	 */
	kmutex_t hw_mutex[1];
	ddi_iblock_cookie_t hw_iblk;

	/*
	 * Data protected by the hardware mutex: the watchdog-patting
	 * protocol data (since the dog can be patted from a high-level
	 * cyclic), and the interrupt-enabled flag.
	 */
	hrtime_t hw_last_pat;
	boolean_t hw_int_enabled;

	/*
	 * Flag to indicate that we've incurred a hardware fault on
	 * accesses to the SIO; once this is set, we fake all further
	 * accesses in order not to provoke additional bus errors.
	 */
	boolean_t sio_fault;

	/*
	 * Serial protocol state data, protected by lo_mutex
	 * (which is initialised using <lo_iblk>)
	 */
	kmutex_t lo_mutex[1];
	ddi_iblock_cookie_t lo_iblk;
	kcondvar_t lo_cv[1];

	volatile enum lombus_cmdstate cmdstate;
	clock_t deadline;
	uint8_t cmdbuf[LOMBUS_BUFSIZE];
	uint8_t reply[LOMBUS_BUFSIZE];
	uint8_t async;
	uint8_t index;
	uint8_t result;
	uint8_t sequence;
	uint32_t error;
};

/*
 * The auxiliary structure attached to each child
 * (the child's parent-private-data points to this).
 */
struct lombus_child_info {
	lombus_regspec_t *rsp;
	int nregs;
};


/*
 * Local data
 */

static void *lombus_statep;

static major_t lombus_major = NOMAJOR;

static ddi_device_acc_attr_t lombus_dev_acc_attr[1] =
{
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};


/*
 *  General utility routines ...
 */

static void
lombus_trace(struct lombus_state *ssp, char code, const char *caller,
	const char *fmt, ...)
{
	char buf[256];
	char *p;
	va_list va;

	if (ssp->debug & (1 << (code-'@'))) {
		p = buf;
		snprintf(p, sizeof (buf) - (p - buf),
		    "%s/%s: ", MYNAME, caller);
		p += strlen(p);

		va_start(va, fmt);
		vsnprintf(p, sizeof (buf) - (p - buf), fmt, va);
		va_end(va);

		buf[sizeof (buf) - 1] = '\0';
		strlog(ssp->majornum, ssp->instance, code, SL_TRACE, buf);
	}
}

static struct lombus_state *
lombus_getstate(dev_info_t *dip, int instance, const char *caller)
{
	struct lombus_state *ssp = NULL;
	dev_info_t *sdip = NULL;
	major_t dmaj = NOMAJOR;

	if (dip != NULL) {
		/*
		 * Use the instance number from the <dip>; also,
		 * check that it really corresponds to this driver
		 */
		instance = ddi_get_instance(dip);
		dmaj = ddi_driver_major(dip);
		if (lombus_major == NOMAJOR && dmaj != NOMAJOR)
			lombus_major = dmaj;
		else if (dmaj != lombus_major) {
			cmn_err(CE_WARN,
			    "%s: major number mismatch (%d vs. %d) in %s(),"
			    "probably due to child misconfiguration",
			    MYNAME, lombus_major, dmaj, caller);
			instance = -1;
		}
	}

	if (instance >= 0)
		ssp = ddi_get_soft_state(lombus_statep, instance);
	if (ssp != NULL) {
		sdip = ssp->dip;
		if (dip == NULL && sdip == NULL)
			ssp = NULL;
		else if (dip != NULL && sdip != NULL && sdip != dip) {
			cmn_err(CE_WARN,
			    "%s: devinfo mismatch (%p vs. %p) in %s(), "
			    "probably due to child misconfiguration",
			    MYNAME, (void *)dip, (void *)sdip, caller);
			ssp = NULL;
		}
	}

	return (ssp);
}

/*
 * Lowest-level serial I/O chip register read/write
 */

static void
sio_put_reg(struct lombus_state *ssp, uint_t reg, uint8_t val)
{
	lombus_trace(ssp, 'P', "sio_put_reg", "REG[%d] <- $%02x", reg, val);

	if (ssp->sio_handle != NULL && !ssp->sio_fault) {
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
		ddi_put8(ssp->sio_handle, ssp->sio_regs + reg, val);
		ddi_put8(ssp->sio_handle, ssp->sio_regs + SIO_SCR, val);
		membar_sync();
		(void) ddi_get8(ssp->sio_handle, ssp->sio_regs + SIO_SCR);
	}
}

static uint8_t
sio_get_reg(struct lombus_state *ssp, uint_t reg)
{
	uint8_t val;

	if (ssp->sio_handle && !ssp->sio_fault)
		val = ddi_get8(ssp->sio_handle, ssp->sio_regs + reg);
	else
		val = DUMMY_VALUE;

	lombus_trace(ssp, 'G', "sio_get_reg", "$%02x <- REG[%d]", val, reg);

	return (val);
}

static void
sio_check_fault_status(struct lombus_state *ssp)
{
	ssp->sio_fault = ddi_check_acc_handle(ssp->sio_handle) != DDI_SUCCESS;
}

static boolean_t
sio_faulty(struct lombus_state *ssp)
{
	if (!ssp->sio_fault)
		sio_check_fault_status(ssp);
	return (ssp->sio_fault);
}


/*
 * Check for data ready.
 */
static boolean_t
sio_data_ready(struct lombus_state *ssp)
{
	uint8_t status;

	/*
	 * Data is available if the RXDA bit in the LSR is nonzero
	 * (if reading it didn't incur a fault).
	 */
	status = sio_get_reg(ssp, SIO_LSR);
	return ((status & SIO_LSR_RXDA) != 0 && !sio_faulty(ssp));
}

/*
 * Check for LOM ready
 */
static boolean_t
sio_lom_ready(struct lombus_state *ssp)
{
	uint8_t status;
	boolean_t rslt;

	/*
	 * The LOM is ready if the CTS bit in the MSR is 1, meaning
	 * that the /CTS signal is being asserted (driven LOW) -
	 * unless we incurred a fault in trying to read the MSR!
	 *
	 * For debugging, we force the result to TRUE if the FAKE flag is set
	 */
	status = sio_get_reg(ssp, SIO_MSR);
	rslt = (status & SIO_MSR_CTS) != 0 && !sio_faulty(ssp);

	lombus_trace(ssp, 'R', "sio_lom_ready", "S $%02x R %d F %d",
	    status, rslt, ssp->fake_cts);

	return (rslt || ssp->fake_cts);
}

#if	0
/*
 * Check for interrupt pending
 */
static boolean_t
sio_irq_pending(struct lombus_state *ssp)
{
	uint8_t status;
	boolean_t rslt;

	/*
	 * An interrupt is pending if the IPF bit in the EIR is 0,
	 * assuming we didn't incur a fault in trying to ready it.
	 *
	 * Note: we expect that every time we read this register
	 * (which is only done from the interrupt service routine),
	 * we will see $11001100 (RX FIFO timeout interrupt pending).
	 */
	status = sio_get_reg(ssp, SIO_EIR);

	rslt = (status & SIO_EIR_IPF) == 0 && !sio_faulty(ssp);
	lombus_trace(ssp, 'I', "sio_irq_pending", "S $%02x R %d",
	    status, rslt);

	/*
	 * To investigate whether we're getting any abnormal interrupts
	 * this code checks that the status value is as expected, and that
	 * chip-level interrupts are supposed to be enabled at this time.
	 * This will cause a PANIC (on a driver compiled with DEBUG) if
	 * all is not as expected ...
	 */
	ASSERT(status == 0xCC);
	ASSERT(ssp->hw_int_enabled);

	return (rslt);
}
#endif	/* 0 */

/*
 * Enable/disable interrupts
 */
static void
lombus_set_irq(struct lombus_state *ssp, boolean_t newstate)
{
	uint8_t val;

	val = newstate ? SIO_IER_RXHDL_IE : 0;
	sio_put_reg(ssp, SIO_IER, SIO_IER_STD | val);
	ssp->hw_int_enabled = newstate;
}

/*
 * Assert/deassert RTS
 */
static void
lombus_toggle_rts(struct lombus_state *ssp)
{
	uint8_t val;

	val = sio_get_reg(ssp, SIO_MCR);
	val &= SIO_MCR_RTS;
	val ^= SIO_MCR_RTS;
	val |= SIO_MCR_STD;
	sio_put_reg(ssp, SIO_MCR, val);
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
lombus_hi_intr(caddr_t arg)
{
	struct lombus_state *ssp = (void *)arg;
	uint_t claim;

	claim = DDI_INTR_UNCLAIMED;
	if (ssp->cycid != NULL) {
		mutex_enter(ssp->hw_mutex);
		if (ssp->hw_int_enabled) {
			lombus_set_irq(ssp, B_FALSE);
			ddi_trigger_softintr(ssp->softid);
			claim = DDI_INTR_CLAIMED;
		}
		mutex_exit(ssp->hw_mutex);
	}

	return (claim);
}

/*
 * Packet receive handler
 *
 * This routine should be called from the low-level softint, or the
 * cyclic callback, or lombus_cmd() (for polled operation), with the
 * low-level mutex already held.
 */
static void
lombus_receive(struct lombus_state *ssp)
{
	boolean_t ready = B_FALSE;
	uint8_t data = 0;
	uint8_t rcvd = 0;
	uint8_t tmp;

	lombus_trace(ssp, 'S', "lombus_receive",
	    "state %d; error $%x",
	    ssp->cmdstate, ssp->error);

	/*
	 * Check for access faults before starting the receive
	 * loop (we don't want to cause bus errors or suchlike
	 * unpleasantness in the event that the SIO has died).
	 */
	if (!sio_faulty(ssp)) {
		/*
		 * Read bytes from the FIFO until they're all gone,
		 * or we find the 'END OF PACKET' set on one, or
		 * our buffer overflows (which must be an error)
		 */
		mutex_enter(ssp->hw_mutex);
		while (sio_data_ready(ssp)) {
			data = sio_get_reg(ssp, SIO_RXD);
			ssp->reply[rcvd = ssp->index] = data;
			if (++rcvd >= LOMBUS_BUFSIZE)
				break;
			ssp->index = rcvd;
			if (data & LOMBUS_LAST)
				break;
		}
		lombus_set_irq(ssp, B_TRUE);
		mutex_exit(ssp->hw_mutex);
	}

	lombus_trace(ssp, 'S', "lombus_receive",
	    "rcvd %d: $%02x $%02x $%02x $%02x $%02x $%02x $%02x $%02x",
	    rcvd,
	    ssp->reply[0], ssp->reply[1],
	    ssp->reply[2], ssp->reply[3],
	    ssp->reply[4], ssp->reply[5],
	    ssp->reply[6], ssp->reply[7]);

	if (ssp->cmdstate != LOMBUS_CMDSTATE_WAITING) {
		/*
		 * We're not expecting any data in this state, so if
		 * we DID receive any data, we just throw it away by
		 * resetting the buffer index to 0.
		 */
		ssp->index = 0;
	} else if (rcvd == 0) {
		/*
		 * No bytes received this time through (though there
		 * might be a partial packet sitting in the buffer).
		 * If it seems the LOM is taking too long to respond,
		 * we'll assume it's died and return an error.
		 */
		if (ddi_get_lbolt() > ssp->deadline) {
			ssp->cmdstate = LOMBUS_CMDSTATE_ERROR;
			ssp->error = LOMBUS_ERR_TIMEOUT;
			ready = B_TRUE;
		}
	} else if (rcvd >= LOMBUS_BUFSIZE) {
		/*
		 * Buffer overflow; discard the data & treat as an error
		 * (even if the last byte read did claim to terminate a
		 * packet, it can't be a valid one 'cos it's too long!)
		 */
		ssp->index = 0;
		ssp->cmdstate = LOMBUS_CMDSTATE_ERROR;
		ssp->error = LOMBUS_ERR_OFLOW;
		ready = B_TRUE;
	} else if ((data & LOMBUS_LAST) == 0) {
		/*
		 * Packet not yet complete; leave the partial packet in
		 * the buffer for later ...
		 */
		_NOTE(EMPTY)
		;
	} else if ((data & LOMBUS_MASK) != LOMBUS_STATUS) {
		/*
		 * Invalid "status" byte - maybe an echo of the command?
		 *
		 * As a debugging feature, we allow for this, assuming
		 * that if the LOM has echoed the command byte, it has
		 * also echoed all the parameter bytes before starting
		 * command processing.  So, we dump out the buffer and
		 * then clear it, so we can go back to looking for the
		 * real reply.
		 *
		 * Otherwise, we just drop the data & flag an error.
		 */
		if (ssp->allow_echo) {
			lombus_trace(ssp, 'E', "lombus_receive",
			    "echo $%02x $%02x $%02x $%02x "
			    "$%02x $%02x $%02x $%02x",
			    ssp->reply[0], ssp->reply[1],
			    ssp->reply[2], ssp->reply[3],
			    ssp->reply[4], ssp->reply[5],
			    ssp->reply[6], ssp->reply[7]);
			ssp->index = 0;
		} else {
			ssp->cmdstate = LOMBUS_CMDSTATE_ERROR;
			ssp->error = LOMBUS_ERR_BADSTATUS;
			ready = B_TRUE;
		}
	} else if ((data & LOMBUS_SEQ) != ssp->sequence) {
		/*
		 * Wrong sequence number!  Flag this as an error
		 */
		ssp->cmdstate = LOMBUS_CMDSTATE_ERROR;
		ssp->error = LOMBUS_ERR_SEQUENCE;
		ready = B_TRUE;
	} else {
		/*
		 * Finally, we know that's it's a valid reply to our
		 * last command.  Update the ASYNC status, derive the
		 * reply parameter (if any), and check the ERROR bit
		 * to find out what the parameter means.
		 *
		 * Note that not all the values read/assigned here
		 * are meaningful, but it doesn't matter; the waiting
		 * thread will know which one(s) it should check.
		 */
		ssp->async = (data & LOMBUS_STATUS_ASYNC) ? 1 : 0;
		tmp = ((data & LOMBUS_STATUS_MSB) ? 0x80 : 0) | ssp->reply[0];
		if (data & LOMBUS_STATUS_ERR) {
			ssp->cmdstate = LOMBUS_CMDSTATE_ERROR;
			ssp->error = tmp;
		} else {
			ssp->cmdstate = LOMBUS_CMDSTATE_READY;
			ssp->result = tmp;
		}
		ready = B_TRUE;
	}

	lombus_trace(ssp, 'T', "lombus_receive",
	    "rcvd %d; last $%02x; state %d; error $%x; ready %d",
	    rcvd, data, ssp->cmdstate, ssp->error, ready);

	if (ready)
		cv_broadcast(ssp->lo_cv);
}

/*
 * Low-level softint handler
 *
 * This routine should be triggered whenever there's a byte to be read
 */
static uint_t
lombus_softint(caddr_t arg)
{
	struct lombus_state *ssp = (void *)arg;

	mutex_enter(ssp->lo_mutex);
	lombus_receive(ssp);
	mutex_exit(ssp->lo_mutex);

	return (DDI_INTR_CLAIMED);
}

/*
 * Cyclic handler: just calls the receive routine, in case interrupts
 * are not being delivered and in order to handle command timeout
 */
static void
lombus_cyclic(void *arg)
{
	struct lombus_state *ssp = (void *)arg;

	mutex_enter(ssp->lo_mutex);
	lombus_receive(ssp);
	mutex_exit(ssp->lo_mutex);
}


/*
 * Serial protocol
 *
 * This routine builds a command and sets it in progress.
 */
static uint8_t
lombus_cmd(HANDLE_TYPE *hdlp, ptrdiff_t vreg, uint_t val, uint_t cmd)
{
	struct lombus_state *ssp;
	clock_t start;
	clock_t tick;
	uint8_t *p;

	/*
	 * First of all, wait for the interface to be available.
	 *
	 * NOTE: we blow through all the mutex/cv/state checking and
	 * preempt any command in progress if the system is panicking!
	 */
	ssp = HANDLE_PRIVATE(hdlp);
	mutex_enter(ssp->lo_mutex);
	while (ssp->cmdstate != LOMBUS_CMDSTATE_IDLE && !panicstr)
		cv_wait(ssp->lo_cv, ssp->lo_mutex);

	ssp->cmdstate = LOMBUS_CMDSTATE_BUSY;
	ssp->sequence = (ssp->sequence + LOMBUS_SEQ_LSB) & LOMBUS_SEQ;

	/*
	 * We have exclusive ownership, so assemble the command (backwards):
	 *
	 * [byte 0]	Command:	modified by XADDR and/or WMSB bits
	 * [Optional] Parameter: 	Value to write (low 7 bits)
	 * [Optional] Parameter: 	Register number (high 7 bits)
	 * [Optional] Parameter: 	Register number (low 7 bits)
	 */
	p = &ssp->cmdbuf[0];
	*p++ = LOMBUS_CMD | ssp->sequence | cmd;
	switch (cmd) {
	case LOMBUS_CMD_WRITE:
		*p++ = val & 0x7f;
		if (val >= 0x80)
			ssp->cmdbuf[0] |= LOMBUS_CMD_WMSB;
		/*FALLTHRU*/
	case LOMBUS_CMD_READ:
		if (LOMBUS_VREG_HI(vreg) != 0) {
			*p++ = LOMBUS_VREG_HI(vreg);
			ssp->cmdbuf[0] |= LOMBUS_CMD_XADDR;
		}
		*p++ = LOMBUS_VREG_LO(vreg);
		/*FALLTHRU*/
	case LOMBUS_CMD_NOP:
		break;
	}

	/*
	 * Check and update the SIO h/w fault status before accessing
	 * the chip registers.  If there's a (new or previous) fault,
	 * we'll run through the protocol but won't really touch the
	 * hardware and all commands will timeout.  If a previously
	 * discovered fault has now gone away (!), then we can (try to)
	 * proceed with the new command (probably a probe).
	 */
	sio_check_fault_status(ssp);

	/*
	 * Wait up to LOMBUS_CTS_TIMEOUT (2 seconds) for the LOM to tell
	 * us that it's ready for the next command.  If it doesn't, though,
	 * we'll send it anyway, on the basis that the CTS signal might be
	 * open- or short-circuited (or the LOM firmware forgot to set it,
	 * or the LOM just got reset, or whatever ...)
	 */
	start = ddi_get_lbolt();
	ssp->deadline = start + drv_usectohz(LOMBUS_CTS_TIMEOUT/1000);
	while (!sio_lom_ready(ssp)) {
		if ((tick = ddi_get_lbolt()) > ssp->deadline)
			break;
		tick += drv_usectohz(LOMBUS_CTS_POLL/1000);
		cv_timedwait(ssp->lo_cv, ssp->lo_mutex, tick);
	}

	/*
	 * Either the LOM is ready, or we timed out waiting for CTS.
	 * In either case, we're going to send the command now by
	 * stuffing the packet into the Tx FIFO, reversing it as we go.
	 * We call lombus_receive() first to ensure there isn't any
	 * garbage left in the Rx FIFO from an earlier command that
	 * timed out (or was pre-empted by a PANIC!).  This also makes
	 * sure that SIO interrupts are enabled so we'll see the reply
	 * more quickly (the poll loop below will still work even if
	 * interrupts aren't enabled, but it will take longer).
	 */
	lombus_receive(ssp);
	mutex_enter(ssp->hw_mutex);
	while (p > ssp->cmdbuf)
		sio_put_reg(ssp, SIO_TXD, *--p);
	mutex_exit(ssp->hw_mutex);

	/*
	 * Prepare for the reply (to be processed by the interrupt/cyclic
	 * handler and/or polling loop below), then wait for a response
	 * or timeout.
	 */
	start = ddi_get_lbolt();
	ssp->deadline = start + drv_usectohz(LOMBUS_CMD_TIMEOUT/1000);
	ssp->error = 0;
	ssp->index = 0;
	ssp->result = DUMMY_VALUE;
	ssp->cmdstate = LOMBUS_CMDSTATE_WAITING;
	while (ssp->cmdstate == LOMBUS_CMDSTATE_WAITING) {
		tick = ddi_get_lbolt() + drv_usectohz(LOMBUS_CMD_POLL/1000);
		if (cv_timedwait(ssp->lo_cv, ssp->lo_mutex, tick) == -1)
			lombus_receive(ssp);
	}

	/*
	 * The return value may not be meaningful but retrieve it anyway
	 */
	val = ssp->result;
	if (sio_faulty(ssp)) {
		val = DUMMY_VALUE;
		HANDLE_FAULT(hdlp) = LOMBUS_ERR_SIOHW;
	} else if (ssp->cmdstate != LOMBUS_CMDSTATE_READY) {
		/*
		 * Some problem here ... transfer the error code from
		 * the per-instance state to the per-handle fault flag.
		 * The error code shouldn't be zero!
		 */
		if (ssp->error != 0)
			HANDLE_FAULT(hdlp) = ssp->error;
		else
			HANDLE_FAULT(hdlp) = LOMBUS_ERR_BADERRCODE;
	}

	/*
	 * All done now!
	 */
	ssp->index = 0;
	ssp->cmdstate = LOMBUS_CMDSTATE_IDLE;
	cv_broadcast(ssp->lo_cv);
	mutex_exit(ssp->lo_mutex);

	return (val);
}


/*
 * Space 0 - LOM virtual register access
 * Only 8-bit accesses are supported.
 */
static uint8_t
lombus_vreg_get8(HANDLE_TYPE *hdlp, uint8_t *addr)
{
	ptrdiff_t offset;

	/*
	 * Check the offset that the caller has added to the base address
	 * against the length of the mapping originally requested.
	 */
	offset = ADDR_TO_OFFSET(addr, hdlp);
	if (offset < 0 || offset >= HANDLE_MAPLEN(hdlp)) {
		/*
		 * Invalid access - flag a fault and return a dummy value
		 */
		HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_NUM;
		return (DUMMY_VALUE);
	}

	/*
	 * Derive the virtual register number and run the command
	 */
	return (lombus_cmd(hdlp, ADDR_TO_VREG(addr), 0, LOMBUS_CMD_READ));
}

static void
lombus_vreg_put8(HANDLE_TYPE *hdlp, uint8_t *addr, uint8_t val)
{
	ptrdiff_t offset;

	/*
	 * Check the offset that the caller has added to the base address
	 * against the length of the mapping originally requested.
	 */
	offset = ADDR_TO_OFFSET(addr, hdlp);
	if (offset < 0 || offset >= HANDLE_MAPLEN(hdlp)) {
		/*
		 * Invalid access - flag a fault and return
		 */
		HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_NUM;
		return;
	}

	/*
	 * Derive the virtual register number and run the command
	 */
	(void) lombus_cmd(hdlp, ADDR_TO_VREG(addr), val, LOMBUS_CMD_WRITE);
}

static void
lombus_vreg_rep_get8(HANDLE_TYPE *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	size_t inc;

	inc = (flags & DDI_DEV_AUTOINCR) ? 1 : 0;
	for (; repcount--; dev_addr += inc)
		*host_addr++ = lombus_vreg_get8(hdlp, dev_addr);
}

static void
lombus_vreg_rep_put8(HANDLE_TYPE *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	size_t inc;

	inc = (flags & DDI_DEV_AUTOINCR) ? 1 : 0;
	for (; repcount--; dev_addr += inc)
		lombus_vreg_put8(hdlp, dev_addr, *host_addr++);
}


/*
 * Space 1 - LOM watchdog pat register access
 * Only 8-bit accesses are supported.
 *
 * Reads have no effect and return 0.
 *
 * Writes pat the dog by toggling the RTS line iff enough time has
 * elapsed since last time we toggled it.
 *
 * Multi-byte reads (using ddi_rep_get8(9F)) are a fairly inefficient
 * way of zeroing the destination area ;-) and still won't pat the dog.
 *
 * Multi-byte writes (using ddi_rep_put8(9F)) will almost certainly
 * only count as a single pat, no matter how many bytes the caller
 * says to write, as the inter-pat time is VERY long compared with
 * the time it will take to read the memory source area.
 */

static uint8_t
lombus_pat_get8(HANDLE_TYPE *hdlp, uint8_t *addr)
{
	ptrdiff_t offset;

	/*
	 * Check the offset that the caller has added to the base address
	 * against the length of the mapping originally requested.
	 */
	offset = ADDR_TO_OFFSET(addr, hdlp);
	if (offset < 0 || offset >= HANDLE_MAPLEN(hdlp)) {
		/*
		 * Invalid access - flag a fault and return a dummy value
		 */
		HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_NUM;
		return (DUMMY_VALUE);
	}

	return (0);
}

static void
lombus_pat_put8(HANDLE_TYPE *hdlp, uint8_t *addr, uint8_t val)
{
	struct lombus_state *ssp;
	ptrdiff_t offset;
	hrtime_t now;

	_NOTE(ARGUNUSED(val))

	/*
	 * Check the offset that the caller has added to the base address
	 * against the length of the mapping originally requested.
	 */
	offset = ADDR_TO_OFFSET(addr, hdlp);
	if (offset < 0 || offset >= HANDLE_MAPLEN(hdlp)) {
		/*
		 * Invalid access - flag a fault and return
		 */
		HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_NUM;
		return;
	}

	ssp = HANDLE_PRIVATE(hdlp);
	mutex_enter(ssp->hw_mutex);
	now = gethrtime();
	if ((now - ssp->hw_last_pat) >= LOMBUS_MIN_PAT) {
		lombus_toggle_rts(ssp);
		ssp->hw_last_pat = now;
	}
	mutex_exit(ssp->hw_mutex);
}

static void
lombus_pat_rep_get8(HANDLE_TYPE *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	size_t inc;

	inc = (flags & DDI_DEV_AUTOINCR) ? 1 : 0;
	for (; repcount--; dev_addr += inc)
		*host_addr++ = lombus_pat_get8(hdlp, dev_addr);
}

static void
lombus_pat_rep_put8(HANDLE_TYPE *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	size_t inc;

	inc = (flags & DDI_DEV_AUTOINCR) ? 1 : 0;
	for (; repcount--; dev_addr += inc)
		lombus_pat_put8(hdlp, dev_addr, *host_addr++);
}


/*
 * Space 2 - LOM async event flag register access
 * Only 16-bit accesses are supported.
 */
static uint16_t
lombus_event_get16(HANDLE_TYPE *hdlp, uint16_t *addr)
{
	struct lombus_state *ssp;
	ptrdiff_t offset;

	/*
	 * Check the offset that the caller has added to the base address
	 * against the length of the mapping orignally requested.
	 */
	offset = ADDR_TO_OFFSET(addr, hdlp);
	if (offset < 0 || (offset%2) != 0 || offset >= HANDLE_MAPLEN(hdlp)) {
		/*
		 * Invalid access - flag a fault and return a dummy value
		 */
		HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_NUM;
		return (DUMMY_VALUE);
	}

	/*
	 * Return the value of the asynchronous-event-pending flag
	 * as passed back by the LOM at the end of the last command.
	 */
	ssp = HANDLE_PRIVATE(hdlp);
	return (ssp->async);
}

static void
lombus_event_put16(HANDLE_TYPE *hdlp, uint16_t *addr, uint16_t val)
{
	ptrdiff_t offset;

	_NOTE(ARGUNUSED(val))

	/*
	 * Check the offset that the caller has added to the base address
	 * against the length of the mapping originally requested.
	 */
	offset = ADDR_TO_OFFSET(addr, hdlp);
	if (offset < 0 || (offset%2) != 0 || offset >= HANDLE_MAPLEN(hdlp)) {
		/*
		 * Invalid access - flag a fault and return
		 */
		HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_NUM;
		return;
	}

	/*
	 * The user can't overwrite the asynchronous-event-pending flag!
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_RO;
}

static void
lombus_event_rep_get16(HANDLE_TYPE *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	size_t inc;

	inc = (flags & DDI_DEV_AUTOINCR) ? 1 : 0;
	for (; repcount--; dev_addr += inc)
		*host_addr++ = lombus_event_get16(hdlp, dev_addr);
}

static void
lombus_event_rep_put16(HANDLE_TYPE *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	size_t inc;

	inc = (flags & DDI_DEV_AUTOINCR) ? 1 : 0;
	for (; repcount--; dev_addr += inc)
		lombus_event_put16(hdlp, dev_addr, *host_addr++);
}


/*
 * All spaces - access handle fault information
 * Only 32-bit accesses are supported.
 */
static uint32_t
lombus_meta_get32(HANDLE_TYPE *hdlp, uint32_t *addr)
{
	struct lombus_state *ssp;
	ptrdiff_t offset;

	/*
	 * Derive the offset that the caller has added to the base
	 * address originally returned, and use it to determine
	 * which meta-register is to be accessed ...
	 */
	offset = ADDR_TO_OFFSET(addr, hdlp);
	switch (offset) {
	case LOMBUS_FAULT_REG:
		/*
		 * This meta-register provides a code for the most
		 * recent virtual register access fault, if any.
		 */
		return (HANDLE_FAULT(hdlp));

	case LOMBUS_PROBE_REG:
		/*
		 * Reading this meta-register clears any existing fault
		 * (at the virtual, not the hardware access layer), then
		 * runs a NOP command and returns the fault code from that.
		 */
		HANDLE_FAULT(hdlp) = 0;
		lombus_cmd(hdlp, 0, 0, LOMBUS_CMD_NOP);
		return (HANDLE_FAULT(hdlp));

	case LOMBUS_ASYNC_REG:
		/*
		 * Obsolescent - but still supported for backwards
		 * compatibility.  This is an alias for the newer
		 * LOMBUS_EVENT_REG, but doesn't require a separate
		 * "reg" entry and ddi_regs_map_setup() call.
		 *
		 * It returns the value of the asynchronous-event-pending
		 * flag as passed back by the LOM at the end of the last
		 * completed command.
		 */
		ssp = HANDLE_PRIVATE(hdlp);
		return (ssp->async);

	default:
		/*
		 * Invalid access - flag a fault and return a dummy value
		 */
		HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
		return (DUMMY_VALUE);
	}
}

static void
lombus_meta_put32(HANDLE_TYPE *hdlp, uint32_t *addr, uint32_t val)
{
	ptrdiff_t offset;

	/*
	 * Derive the offset that the caller has added to the base
	 * address originally returned, and use it to determine
	 * which meta-register is to be accessed ...
	 */
	offset = ADDR_TO_OFFSET(addr, hdlp);
	switch (offset) {
	case LOMBUS_FAULT_REG:
		/*
		 * This meta-register contains a code for the most
		 * recent virtual register access fault, if any.
		 * It can be cleared simply by writing 0 to it.
		 */
		HANDLE_FAULT(hdlp) = val;
		return;

	case LOMBUS_PROBE_REG:
		/*
		 * Writing this meta-register clears any existing fault
		 * (at the virtual, not the hardware acess layer), then
		 * runs a NOP command.  The caller can check the fault
		 * code later if required.
		 */
		HANDLE_FAULT(hdlp) = 0;
		lombus_cmd(hdlp, 0, 0, LOMBUS_CMD_NOP);
		return;

	default:
		/*
		 * Invalid access - flag a fault
		 */
		HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
		return;
	}
}

static void
lombus_meta_rep_get32(HANDLE_TYPE *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	size_t inc;

	inc = (flags & DDI_DEV_AUTOINCR) ? 1 : 0;
	for (; repcount--; dev_addr += inc)
		*host_addr++ = lombus_meta_get32(hdlp, dev_addr);
}

static void
lombus_meta_rep_put32(HANDLE_TYPE *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	size_t inc;

	inc = (flags & DDI_DEV_AUTOINCR) ? 1 : 0;
	for (; repcount--; dev_addr += inc)
		lombus_meta_put32(hdlp, dev_addr, *host_addr++);
}


/*
 * Finally, some dummy functions for all unsupported access
 * space/size/mode combinations ...
 */
static uint8_t
lombus_no_get8(HANDLE_TYPE *hdlp, uint8_t *addr)
{
	_NOTE(ARGUNUSED(addr))

	/*
	 * Invalid access - flag a fault and return a dummy value
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
	return (DUMMY_VALUE);
}

static void
lombus_no_put8(HANDLE_TYPE *hdlp, uint8_t *addr, uint8_t val)
{
	_NOTE(ARGUNUSED(addr, val))

	/*
	 * Invalid access - flag a fault
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
}

static void
lombus_no_rep_get8(HANDLE_TYPE *hdlp, uint8_t *host_addr,
		uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	_NOTE(ARGUNUSED(host_addr, dev_addr, repcount, flags))

	/*
	 * Invalid access - flag a fault
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
}

static void
lombus_no_rep_put8(HANDLE_TYPE *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	_NOTE(ARGUNUSED(host_addr, dev_addr, repcount, flags))

	/*
	 * Invalid access - flag a fault
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
}

static uint16_t
lombus_no_get16(HANDLE_TYPE *hdlp, uint16_t *addr)
{
	_NOTE(ARGUNUSED(addr))

	/*
	 * Invalid access - flag a fault and return a dummy value
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
	return (DUMMY_VALUE);
}

static void
lombus_no_put16(HANDLE_TYPE *hdlp, uint16_t *addr, uint16_t val)
{
	_NOTE(ARGUNUSED(addr, val))

	/*
	 * Invalid access - flag a fault
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
}

static void
lombus_no_rep_get16(HANDLE_TYPE *hdlp, uint16_t *host_addr,
		uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	_NOTE(ARGUNUSED(host_addr, dev_addr, repcount, flags))

	/*
	 * Invalid access - flag a fault
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
}

static void
lombus_no_rep_put16(HANDLE_TYPE *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	_NOTE(ARGUNUSED(host_addr, dev_addr, repcount, flags))

	/*
	 * Invalid access - flag a fault
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
}

static uint64_t
lombus_no_get64(HANDLE_TYPE *hdlp, uint64_t *addr)
{
	_NOTE(ARGUNUSED(addr))

	/*
	 * Invalid access - flag a fault and return a dummy value
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
	return (DUMMY_VALUE);
}

static void
lombus_no_put64(HANDLE_TYPE *hdlp, uint64_t *addr, uint64_t val)
{
	_NOTE(ARGUNUSED(addr, val))

	/*
	 * Invalid access - flag a fault
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
}

static void
lombus_no_rep_get64(HANDLE_TYPE *hdlp, uint64_t *host_addr,
	uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	_NOTE(ARGUNUSED(host_addr, dev_addr, repcount, flags))

	/*
	 * Invalid access - flag a fault
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
}

static void
lombus_no_rep_put64(HANDLE_TYPE *hdlp, uint64_t *host_addr,
	uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	_NOTE(ARGUNUSED(host_addr, dev_addr, repcount, flags))

	/*
	 * Invalid access - flag a fault
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
}

static int
lombus_acc_fault_check(HANDLE_TYPE *hdlp)
{
	return (HANDLE_FAULT(hdlp) != 0);
}


/*
 * Hardware setup - put the SIO chip in the required operational
 * state,  with all our favourite parameters programmed correctly.
 * This routine leaves all SIO interrupts disabled.
 */

static void
lombus_hw_reset(struct lombus_state *ssp)
{
	uint16_t divisor;

	/*
	 * Disable interrupts, soft reset Tx and Rx circuitry,
	 * reselect standard modes (bits/char, parity, etc).
	 */
	lombus_set_irq(ssp, B_FALSE);
	sio_put_reg(ssp, SIO_FCR, SIO_FCR_RXSR | SIO_FCR_TXSR);
	sio_put_reg(ssp, SIO_LCR, SIO_LCR_STD);

	/*
	 * Select the proper baud rate; if the value is invalid
	 * (presumably 0, i.e. not specified, but also if the
	 * "baud" property is set to some silly value), we assume
	 * the default.
	 */
	if (ssp->baud < SIO_BAUD_MIN || ssp->baud > SIO_BAUD_MAX)
		divisor = SIO_BAUD_TO_DIVISOR(SIO_BAUD_DEFAULT);
	else
		divisor = SIO_BAUD_TO_DIVISOR(ssp->baud);

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
	sio_put_reg(ssp, SIO_BSR, SIO_BSR_BANK1);
	sio_put_reg(ssp, SIO_LBGDL, 0xff);
	sio_put_reg(ssp, SIO_LBGDH, divisor >> 8);
	sio_put_reg(ssp, SIO_LBGDL, divisor & 0xff);
	sio_put_reg(ssp, SIO_BSR, SIO_BSR_BANK0);

	/*
	 * Program the remaining device registers as required
	 */
	sio_put_reg(ssp, SIO_MCR, SIO_MCR_STD);
	sio_put_reg(ssp, SIO_FCR, SIO_FCR_STD);
}


/*
 * Higher-level setup & teardown
 */

static void
lombus_offline(struct lombus_state *ssp)
{
	if (ssp->sio_handle != NULL)
		ddi_regs_map_free(&ssp->sio_handle);
	ssp->sio_handle = NULL;
	ssp->sio_regs = NULL;
}

static int
lombus_online(struct lombus_state *ssp)
{
	ddi_acc_handle_t h;
	caddr_t p;
	int nregs;
	int err;

	if (ddi_dev_nregs(ssp->dip, &nregs) != DDI_SUCCESS)
		nregs = 0;

	switch (nregs) {
	default:
	case 1:
		/*
		 *  regset 0 represents the SIO operating registers
		 */
		err = ddi_regs_map_setup(ssp->dip, 0, &p, 0, 0,
		    lombus_dev_acc_attr, &h);
		lombus_trace(ssp, 'O', "online",
		    "regmap 0 status %d addr $%p", err, p);
		if (err != DDI_SUCCESS)
			return (EIO);

		ssp->sio_handle = h;
		ssp->sio_regs = (void *)p;
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
	lombus_hw_reset(ssp);
	return (0);
}


/*
 *  Nexus routines
 */

#if	defined(NDI_ACC_HDL_V2)

static const ndi_acc_fns_t lombus_vreg_acc_fns = {
	NDI_ACC_FNS_CURRENT,
	NDI_ACC_FNS_V1,

	lombus_vreg_get8,
	lombus_vreg_put8,
	lombus_vreg_rep_get8,
	lombus_vreg_rep_put8,

	lombus_no_get16,
	lombus_no_put16,
	lombus_no_rep_get16,
	lombus_no_rep_put16,

	lombus_meta_get32,
	lombus_meta_put32,
	lombus_meta_rep_get32,
	lombus_meta_rep_put32,

	lombus_no_get64,
	lombus_no_put64,
	lombus_no_rep_get64,
	lombus_no_rep_put64,

	lombus_acc_fault_check
};

static const ndi_acc_fns_t lombus_pat_acc_fns = {
	NDI_ACC_FNS_CURRENT,
	NDI_ACC_FNS_V1,

	lombus_pat_get8,
	lombus_pat_put8,
	lombus_pat_rep_get8,
	lombus_pat_rep_put8,

	lombus_no_get16,
	lombus_no_put16,
	lombus_no_rep_get16,
	lombus_no_rep_put16,

	lombus_meta_get32,
	lombus_meta_put32,
	lombus_meta_rep_get32,
	lombus_meta_rep_put32,

	lombus_no_get64,
	lombus_no_put64,
	lombus_no_rep_get64,
	lombus_no_rep_put64,

	lombus_acc_fault_check
};

static const ndi_acc_fns_t lombus_event_acc_fns = {
	NDI_ACC_FNS_CURRENT,
	NDI_ACC_FNS_V1,

	lombus_no_get8,
	lombus_no_put8,
	lombus_no_rep_get8,
	lombus_no_rep_put8,

	lombus_event_get16,
	lombus_event_put16,
	lombus_event_rep_get16,
	lombus_event_rep_put16,

	lombus_meta_get32,
	lombus_meta_put32,
	lombus_meta_rep_get32,
	lombus_meta_rep_put32,

	lombus_no_get64,
	lombus_no_put64,
	lombus_no_rep_get64,
	lombus_no_rep_put64,

	lombus_acc_fault_check
};

static int
lombus_map_handle(struct lombus_state *ssp, ddi_map_op_t op,
	int space, caddr_t vaddr, off_t len,
	ndi_acc_handle_t *hdlp, caddr_t *addrp)
{
	switch (op) {
	default:
		return (DDI_ME_UNIMPLEMENTED);

	case DDI_MO_MAP_LOCKED:
		switch (space) {
		default:
			return (DDI_ME_REGSPEC_RANGE);

		case LOMBUS_VREG_SPACE:
			ndi_set_acc_fns(hdlp, &lombus_vreg_acc_fns);
			break;

		case LOMBUS_PAT_SPACE:
			ndi_set_acc_fns(hdlp, &lombus_pat_acc_fns);
			break;

		case LOMBUS_EVENT_SPACE:
			ndi_set_acc_fns(hdlp, &lombus_event_acc_fns);
			break;
		}
		hdlp->ah_addr = *addrp = vaddr;
		hdlp->ah_len = len;
		hdlp->ah_bus_private = ssp;
		return (DDI_SUCCESS);

	case DDI_MO_UNMAP:
		*addrp = NULL;
		hdlp->ah_bus_private = NULL;
		return (DDI_SUCCESS);
	}
}

#else

static int
lombus_map_handle(struct lombus_state *ssp, ddi_map_op_t op,
	int space, caddr_t vaddr, off_t len,
	ddi_acc_hdl_t *hdlp, caddr_t *addrp)
{
	ddi_acc_impl_t *aip = hdlp->ah_platform_private;

	switch (op) {
	default:
		return (DDI_ME_UNIMPLEMENTED);

	case DDI_MO_MAP_LOCKED:
		switch (space) {
		default:
			return (DDI_ME_REGSPEC_RANGE);

		case LOMBUS_VREG_SPACE:
			aip->ahi_get8 = lombus_vreg_get8;
			aip->ahi_put8 = lombus_vreg_put8;
			aip->ahi_rep_get8 = lombus_vreg_rep_get8;
			aip->ahi_rep_put8 = lombus_vreg_rep_put8;

			aip->ahi_get16 = lombus_no_get16;
			aip->ahi_put16 = lombus_no_put16;
			aip->ahi_rep_get16 = lombus_no_rep_get16;
			aip->ahi_rep_put16 = lombus_no_rep_put16;

			aip->ahi_get32 = lombus_meta_get32;
			aip->ahi_put32 = lombus_meta_put32;
			aip->ahi_rep_get32 = lombus_meta_rep_get32;
			aip->ahi_rep_put32 = lombus_meta_rep_put32;

			aip->ahi_get64 = lombus_no_get64;
			aip->ahi_put64 = lombus_no_put64;
			aip->ahi_rep_get64 = lombus_no_rep_get64;
			aip->ahi_rep_put64 = lombus_no_rep_put64;

			aip->ahi_fault_check = lombus_acc_fault_check;
			break;

		case LOMBUS_PAT_SPACE:
			aip->ahi_get8 = lombus_pat_get8;
			aip->ahi_put8 = lombus_pat_put8;
			aip->ahi_rep_get8 = lombus_pat_rep_get8;
			aip->ahi_rep_put8 = lombus_pat_rep_put8;

			aip->ahi_get16 = lombus_no_get16;
			aip->ahi_put16 = lombus_no_put16;
			aip->ahi_rep_get16 = lombus_no_rep_get16;
			aip->ahi_rep_put16 = lombus_no_rep_put16;

			aip->ahi_get32 = lombus_meta_get32;
			aip->ahi_put32 = lombus_meta_put32;
			aip->ahi_rep_get32 = lombus_meta_rep_get32;
			aip->ahi_rep_put32 = lombus_meta_rep_put32;

			aip->ahi_get64 = lombus_no_get64;
			aip->ahi_put64 = lombus_no_put64;
			aip->ahi_rep_get64 = lombus_no_rep_get64;
			aip->ahi_rep_put64 = lombus_no_rep_put64;

			aip->ahi_fault_check = lombus_acc_fault_check;
			break;

		case LOMBUS_EVENT_SPACE:
			aip->ahi_get8 = lombus_no_get8;
			aip->ahi_put8 = lombus_no_put8;
			aip->ahi_rep_get8 = lombus_no_rep_get8;
			aip->ahi_rep_put8 = lombus_no_rep_put8;

			aip->ahi_get16 = lombus_event_get16;
			aip->ahi_put16 = lombus_event_put16;
			aip->ahi_rep_get16 = lombus_event_rep_get16;
			aip->ahi_rep_put16 = lombus_event_rep_put16;

			aip->ahi_get32 = lombus_meta_get32;
			aip->ahi_put32 = lombus_meta_put32;
			aip->ahi_rep_get32 = lombus_meta_rep_get32;
			aip->ahi_rep_put32 = lombus_meta_rep_put32;

			aip->ahi_get64 = lombus_no_get64;
			aip->ahi_put64 = lombus_no_put64;
			aip->ahi_rep_get64 = lombus_no_rep_get64;
			aip->ahi_rep_put64 = lombus_no_rep_put64;

			aip->ahi_fault_check = lombus_acc_fault_check;
			break;
		}
		hdlp->ah_addr = *addrp = vaddr;
		hdlp->ah_len = len;
		hdlp->ah_bus_private = ssp;
		return (DDI_SUCCESS);

	case DDI_MO_UNMAP:
		*addrp = NULL;
		hdlp->ah_bus_private = NULL;
		return (DDI_SUCCESS);
	}
}

#endif	/* NDI_ACC_HDL_V2 */

static int
lombus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t off, off_t len, caddr_t *addrp)
{
	struct lombus_child_info *lcip;
	struct lombus_state *ssp;
	lombus_regspec_t *rsp;

	if ((ssp = lombus_getstate(dip, -1, "lombus_map")) == NULL)
		return (DDI_FAILURE);	/* this "can't happen" */

	/*
	 * Validate mapping request ...
	 */

	if (mp->map_flags != DDI_MF_KERNEL_MAPPING)
		return (DDI_ME_UNSUPPORTED);
	if (mp->map_handlep == NULL)
		return (DDI_ME_UNSUPPORTED);
	if (mp->map_type != DDI_MT_RNUMBER)
		return (DDI_ME_UNIMPLEMENTED);
	if ((lcip = ddi_get_parent_data(rdip)) == NULL)
		return (DDI_ME_INVAL);
	if ((rsp = lcip->rsp) == NULL)
		return (DDI_ME_INVAL);
	if (mp->map_obj.rnumber >= lcip->nregs)
		return (DDI_ME_RNUMBER_RANGE);
	rsp += mp->map_obj.rnumber;
	if (off < 0 || off >= rsp->lombus_size)
		return (DDI_ME_INVAL);
	if (len == 0)
		len = rsp->lombus_size-off;
	if (len < 0)
		return (DDI_ME_INVAL);
	if (off+len < 0 || off+len > rsp->lombus_size)
		return (DDI_ME_INVAL);

	return (lombus_map_handle(ssp, mp->map_op,
	    rsp->lombus_space, VREG_TO_ADDR(rsp->lombus_base+off), len,
	    mp->map_handlep, addrp));
}

static int
lombus_ctlops(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t op,
	void *arg, void *result)
{
	struct lombus_child_info *lcip;
	struct lombus_state *ssp;
	lombus_regspec_t *rsp;
	dev_info_t *cdip;
	char addr[32];
	uint_t nregs;
	uint_t rnum;
	int *regs;
	int limit;
	int err;
	int i;

	if ((ssp = lombus_getstate(dip, -1, "lombus_ctlops")) == NULL)
		return (DDI_FAILURE);	/* this "can't happen" */

	switch (op) {
	default:
		break;

	case DDI_CTLOPS_INITCHILD:
		/*
		 * First, look up and validate the "reg" property.
		 *
		 * It must be a non-empty integer array containing a set
		 * of triples.  Once we've verified that, we can treat it
		 * as an array of type lombus_regspec_t[], which defines
		 * the meaning of the elements of each triple:
		 * +  the first element of each triple must be a valid space
		 * +  the second and third elements (base, size) of each
		 *	triple must define a valid subrange of that space
		 * If it passes all the tests, we save it away for future
		 * reference in the child's parent-private-data field.
		 */
		cdip = arg;
		err = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, cdip,
		    DDI_PROP_DONTPASS, "reg", &regs, &nregs);
		lombus_trace(ssp, 'C', "initchild",
		    "prop status %d size %d", err, nregs);
		if (err != DDI_PROP_SUCCESS)
			return (DDI_FAILURE);

		err = (nregs <= 0 || (nregs % LOMBUS_REGSPEC_SIZE) != 0);
		nregs /= LOMBUS_REGSPEC_SIZE;
		rsp = (lombus_regspec_t *)regs;
		for (i = 0; i < nregs && !err; ++i) {
			switch (rsp[i].lombus_space) {
			default:
				limit = 0;
				err = 1;
				break;

			case LOMBUS_VREG_SPACE:
				limit = LOMBUS_MAX_REG+1;
				break;

			case LOMBUS_PAT_SPACE:
				limit = LOMBUS_PAT_REG+1;
				break;

			case LOMBUS_EVENT_SPACE:
				limit = LOMBUS_EVENT_REG+1;
				break;
			}

			err |= (rsp[i].lombus_base < 0);
			err |= (rsp[i].lombus_base >= limit);

			if (rsp[i].lombus_size == 0)
				rsp[i].lombus_size = limit-rsp[i].lombus_base;
			err |= (rsp[i].lombus_size < 0);

			err |= (rsp[i].lombus_base+rsp[i].lombus_size < 0);
			err |= (rsp[i].lombus_base+rsp[i].lombus_size > limit);
		}

		if (err) {
			ddi_prop_free(regs);
			return (DDI_FAILURE);
		}

		lcip = kmem_zalloc(sizeof (*lcip), KM_SLEEP);
		lcip->nregs = nregs;
		lcip->rsp = rsp;
		ddi_set_parent_data(cdip, lcip);

		(void) snprintf(addr, sizeof (addr),
		    "%x,%x", rsp[0].lombus_space, rsp[0].lombus_base);
		ddi_set_name_addr(cdip, addr);

		return (DDI_SUCCESS);

	case DDI_CTLOPS_UNINITCHILD:
		cdip = arg;
		ddi_set_name_addr(cdip, NULL);
		lcip = ddi_get_parent_data(cdip);
		ddi_set_parent_data(cdip, NULL);
		ddi_prop_free(lcip->rsp);
		kmem_free(lcip, sizeof (*lcip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_REPORTDEV:
		if (rdip == NULL)
			return (DDI_FAILURE);

		cmn_err(CE_CONT, "?LOM device: %s@%s, %s#%d\n",
		    ddi_node_name(rdip), ddi_get_name_addr(rdip),
		    ddi_driver_name(dip), ddi_get_instance(dip));

		return (DDI_SUCCESS);

	case DDI_CTLOPS_REGSIZE:
		if ((lcip = ddi_get_parent_data(rdip)) == NULL)
			return (DDI_FAILURE);
		if ((rnum = *(uint_t *)arg) >= lcip->nregs)
			return (DDI_FAILURE);
		*(off_t *)result = lcip->rsp[rnum].lombus_size;
		return (DDI_SUCCESS);

	case DDI_CTLOPS_NREGS:
		if ((lcip = ddi_get_parent_data(rdip)) == NULL)
			return (DDI_FAILURE);
		*(int *)result = lcip->nregs;
		return (DDI_SUCCESS);
	}

	return (ddi_ctlops(dip, rdip, op, arg, result));
}


/*
 *  Clean up on detach or failure of attach
 */
static int
lombus_unattach(struct lombus_state *ssp, int instance)
{
	if (ssp != NULL) {
		lombus_hw_reset(ssp);
		if (ssp->cycid != NULL) {
			ddi_periodic_delete(ssp->cycid);
			ssp->cycid = NULL;
			if (ssp->sio_handle != NULL)
				ddi_remove_intr(ssp->dip, 0, ssp->hw_iblk);
			ddi_remove_softintr(ssp->softid);
			cv_destroy(ssp->lo_cv);
			mutex_destroy(ssp->lo_mutex);
			mutex_destroy(ssp->hw_mutex);
		}
		lombus_offline(ssp);
		ddi_set_driver_private(ssp->dip, NULL);
	}

	ddi_soft_state_free(lombus_statep, instance);
	return (DDI_FAILURE);
}

/*
 *  Autoconfiguration routines
 */

static int
lombus_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct lombus_state *ssp = NULL;
	int instance;
	int err;

	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_ATTACH:
		break;
	}

	/*
	 *  Allocate the soft-state structure
	 */
	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(lombus_statep, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);
	if ((ssp = lombus_getstate(dip, instance, "lombus_attach")) == NULL)
		return (lombus_unattach(ssp, instance));
	ddi_set_driver_private(dip, ssp);

	/*
	 *  Initialise devinfo-related fields
	 */
	ssp->dip = dip;
	ssp->majornum = ddi_driver_major(dip);
	ssp->instance = instance;

	/*
	 *  Set various options from .conf properties
	 */
	ssp->allow_echo = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "allow-lom-echo", 0) != 0;
	ssp->baud = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "baud-rate", 0);
	ssp->debug = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "debug", 0);
	ssp->fake_cts = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "fake-cts", 0) != 0;

	/*
	 * Initialise current state & time
	 */
	ssp->cmdstate = LOMBUS_CMDSTATE_IDLE;
	ssp->hw_last_pat = gethrtime();
	ssp->cycid = NULL;

	/*
	 *  Online the hardware ...
	 */
	err = lombus_online(ssp);
	if (err != 0)
		return (lombus_unattach(ssp, instance));

	/*
	 * Install soft and hard interrupt handler(s)
	 * Initialise mutexes and cv
	 * Start cyclic callbacks
	 * Enable interrupts
	 */
	err = ddi_add_softintr(dip, DDI_SOFTINT_LOW, &ssp->softid,
	    &ssp->lo_iblk, NULL, lombus_softint, (caddr_t)ssp);
	if (err != DDI_SUCCESS)
		return (lombus_unattach(ssp, instance));

	if (ssp->sio_handle != NULL)
		err = ddi_add_intr(dip, 0, &ssp->hw_iblk, NULL,
		    lombus_hi_intr, (caddr_t)ssp);

	mutex_init(ssp->hw_mutex, NULL, MUTEX_DRIVER, ssp->hw_iblk);
	mutex_init(ssp->lo_mutex, NULL, MUTEX_DRIVER, ssp->lo_iblk);
	cv_init(ssp->lo_cv, NULL, CV_DRIVER, NULL);

	/*
	 * Register a periodical handler.
	 */
	ssp->cycid = ddi_periodic_add(lombus_cyclic, ssp, LOMBUS_ONE_SEC,
	    DDI_IPL_1);

	/*
	 * Final check before enabling h/w interrupts - did
	 * we successfully install the h/w interrupt handler?
	 */
	if (err != DDI_SUCCESS)
		return (lombus_unattach(ssp, instance));

	lombus_set_irq(ssp, B_TRUE);

	/*
	 *  All done, report success
	 */
	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}


static int
lombus_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct lombus_state *ssp;
	int instance;

	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_DETACH:
		break;
	}

	instance = ddi_get_instance(dip);
	if ((ssp = lombus_getstate(dip, instance, "lombus_detach")) == NULL)
		return (DDI_FAILURE);	/* this "can't happen" */

	(void) lombus_unattach(ssp, instance);
	return (DDI_SUCCESS);
}

static int
lombus_reset(dev_info_t *dip, ddi_reset_cmd_t cmd)
{
	struct lombus_state *ssp;

	_NOTE(ARGUNUSED(cmd))

	if ((ssp = lombus_getstate(dip, -1, "lombus_reset")) == NULL)
		return (DDI_FAILURE);

	lombus_hw_reset(ssp);
	return (DDI_SUCCESS);
}


/*
 * System interface structures
 */

static struct cb_ops lombus_cb_ops =
{
	nodev,			/* b/c open	*/
	nodev,			/* b/c close	*/
	nodev,			/* b   strategy	*/
	nodev,			/* b   print	*/
	nodev,			/* b   dump 	*/
	nodev,			/* c   read	*/
	nodev,			/* c   write	*/
	nodev,			/* c   ioctl	*/
	nodev,			/* c   devmap	*/
	nodev,			/* c   mmap	*/
	nodev,			/* c   segmap	*/
	nochpoll,		/* c   poll	*/
	ddi_prop_op,		/* b/c prop_op	*/
	NULL,			/* c   streamtab */
	D_MP | D_NEW		/* b/c flags	*/
};

static struct bus_ops lombus_bus_ops =
{
	BUSO_REV,			/* revision		*/
	lombus_map,			/* bus_map		*/
	0,				/* get_intrspec		*/
	0,				/* add_intrspec		*/
	0,				/* remove_intrspec	*/
	i_ddi_map_fault,		/* map_fault		*/
	ddi_no_dma_map,			/* dma_map		*/
	ddi_no_dma_allochdl,		/* allocate DMA handle	*/
	ddi_no_dma_freehdl,		/* free DMA handle	*/
	ddi_no_dma_bindhdl,		/* bind DMA handle	*/
	ddi_no_dma_unbindhdl,		/* unbind DMA handle	*/
	ddi_no_dma_flush,		/* flush DMA		*/
	ddi_no_dma_win,			/* move DMA window	*/
	ddi_no_dma_mctl,		/* generic DMA control	*/
	lombus_ctlops,			/* generic control	*/
	ddi_bus_prop_op,		/* prop_op		*/
	ndi_busop_get_eventcookie,	/* get_eventcookie	*/
	ndi_busop_add_eventcall,	/* add_eventcall	*/
	ndi_busop_remove_eventcall,	/* remove_eventcall	*/
	ndi_post_event,			/* post_event		*/
	0,				/* interrupt control	*/
	0,				/* bus_config		*/
	0,				/* bus_unconfig		*/
	0,				/* bus_fm_init		*/
	0,				/* bus_fm_fini		*/
	0,				/* bus_fm_access_enter	*/
	0,				/* bus_fm_access_exit	*/
	0,				/* bus_power		*/
	i_ddi_intr_ops			/* bus_intr_op		*/
};

static struct dev_ops lombus_dev_ops =
{
	DEVO_REV,
	0,				/* refcount		*/
	ddi_no_info,			/* getinfo		*/
	nulldev,			/* identify		*/
	nulldev,			/* probe		*/
	lombus_attach,			/* attach		*/
	lombus_detach,			/* detach		*/
	lombus_reset,			/* reset		*/
	&lombus_cb_ops,			/* driver operations	*/
	&lombus_bus_ops,		/* bus operations	*/
	NULL,				/* power		*/
	ddi_quiesce_not_supported,	/* devo_quiesce		*/
};

static struct modldrv modldrv =
{
	&mod_driverops,
	"lombus driver",
	&lombus_dev_ops
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

	err = ddi_soft_state_init(&lombus_statep,
	    sizeof (struct lombus_state), 0);
	if (err == DDI_SUCCESS)
		if ((err = mod_install(&modlinkage)) != 0) {
			ddi_soft_state_fini(&lombus_statep);
		}

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
		ddi_soft_state_fini(&lombus_statep);
		lombus_major = NOMAJOR;
	}

	return (err);
}
