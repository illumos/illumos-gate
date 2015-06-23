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
 *
 * The "bscbus" driver provides access to the LOMlite2 virtual registers,
 * so that its clients (children) need not be concerned with the details
 * of the access mechanism, which in this case is implemented via a
 * packet-based protocol over a Xbus (similar to ebus) parallel link to the
 * H8 host interface registers.
 *
 * On the other hand, this driver doesn't generally know what the virtual
 * registers signify - only the clients need this information.
 */


#include <sys/note.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/file.h>

#if defined(__sparc)
#include <sys/intr.h>
#include <sys/membar.h>
#endif

#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/note.h>
#include <sys/open.h>
#include <sys/poll.h>
#include <sys/spl.h>
#include <sys/stat.h>
#include <sys/strlog.h>
#include <sys/atomic.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>

#include <sys/bscbus.h>

#if	defined(NDI_ACC_HDL_V2)

/*
 * Compiling for Solaris 10+ with access handle enhancements
 */
#define	HANDLE_TYPE		ndi_acc_handle_t
#define	HANDLE_ADDR(hdlp)	(hdlp->ah_addr)
#define	HANDLE_FAULT(hdlp)	(hdlp->ah_fault)
#define	HANDLE_MAPLEN(hdlp)	(hdlp->ah_len)
#define	HANDLE_PRIVATE(hdlp)	(hdlp->ah_bus_private)

#else

/*
 * Compatibility definitions for backport to Solaris 8/9
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
#define	MYNAME			"bscbus"
#define	NOMAJOR			(~(major_t)0)
#define	DUMMY_VALUE		(~(int8_t)0)

#define	BSCBUS_INST_TO_MINOR(i)	(i)
#define	BSCBUS_MINOR_TO_INST(m)	(m)

#define	BSCBUS_MAX_CHANNELS	(4)

#define	BSCBUS_DUMMY_ADDRESS	((caddr_t)0x0CADD1ED)
#define	ADDR_TO_OFFSET(a, hdlp)	((caddr_t)(a) - HANDLE_ADDR(hdlp))
#define	ADDR_TO_VREG(a)		((caddr_t)(a) - BSCBUS_DUMMY_ADDRESS)
#define	VREG_TO_ADDR(v)		(BSCBUS_DUMMY_ADDRESS + (v))

#ifdef DEBUG
#define	BSCBUS_LOGSTATUS
#endif /* DEBUG */

#ifdef BSCBUS_LOGSTATUS
/*
 * BSC command logging routines.
 * Record the data passing to and from the BSC
 */

typedef enum {
	BSC_CMD_BUSY = 1,		/* bsc reports busy	*/
	BSC_CMD_CLEARING = 2,		/* clearing bsc busy	*/
	BSC_CMD_CLEARED = 3,		/* cleared bsc busy	*/
	BSC_CMD_SENDING = 4,		/* sending next byte	*/
	BSC_CMD_SENT = 5,		/* sending last byte	*/
	BSC_CMD_PENDING = 6,		/* got sent byte ack	*/
	BSC_CMD_REPLY = 7,		/* got reply byte	*/
	BSC_CMD_COMPLETE = 8,		/* command complete	*/
	BSC_CMD_ERROR_SEQ = 9,		/* error status		*/
	BSC_CMD_ERROR_STATUS = 10,	/* error status		*/
	BSC_CMD_ERROR_OFLOW = 11,	/* error status		*/
	BSC_CMD_ERROR_TOUT = 12,	/* error status		*/

	BSC_CMD_PROCESS = 13,		/* async intr		*/
	BSC_CMD_V1INTR = 14,		/* v1 intr		*/
	BSC_CMD_V1INTRUNCL = 15,	/* v1 intr unclaim	*/
	BSC_CMD_DOGPAT = 17		/* watchdog pat		*/
} bsc_cmd_stamp_t;

typedef struct {
	hrtime_t	bcl_now;
	int		bcl_seq;
	bsc_cmd_stamp_t	bcl_cat;
	uint8_t		bcl_chno;
	uint8_t		bcl_cmdstate;
	uint8_t		bcl_status;
	uint8_t		bcl_data;
} bsc_cmd_log_t;

uint32_t	bscbus_cmd_log_size = 1024;

uint32_t	bscbus_cmd_log_flags = 0xffffffff;

#endif /* BSCBUS_LOGSTATUS */

/*
 * The following definitions are taken from the Hardware Manual for
 * the Hitachi H8S/2148 in conjunction with the hardware specification
 * for the Stiletto blade.
 *
 * Each instance of the host interface has 3 registers on the H8:
 * IDRn  - Input Data Register	- write-only for Solaris.
 *				  writes to this can be done via two
 *				  addresses - control and data.
 *				  The H8 can determine which address was
 *				  written by examining the C/D bit in
 *				  the status register.
 * ODRn  - Output Data Register - read-only for Solaris.
 *				  A read has the side effect of acknowledging
 *				  interrupts.
 * STRn  - Status Register	- read-only for Solaris.
 *
 *
 *
 * In terms of host access to this the Input and Output data registers are
 * mapped at the same address.
 */
#define	H8_IDRD	0
#define	H8_IDRC	1
#define	H8_ODR	0
#define	H8_STR	1

#define	H8_STR_OBF		0x01	/* data available in ODR */
#define	H8_STR_IBF		0x02	/* data for H8 in IDR */
#define	H8_STR_IDRC		0x08	/* last write to IDR was to IDRC */
					/* 0=data, 1=command */
#define	H8_STR_BUSY		0x04	/* H8 busy processing command */
#define	H8_STR_TOKENPROTOCOL	0x80	/* token-passing protocol */

/*
 * Packet format ...
 */
#define	BSCBUS_MASK		0xc0	/* Byte-type bits		*/
#define	BSCBUS_PARAM		0x00	/* Parameter byte: 0b0xxxxxxx	*/
#define	BSCBUS_LAST		0x80	/* Last byte of packet		*/
#define	BSCBUS_CMD		0x80	/* Command byte:   0b10###XWV	*/
#define	BSCBUS_STATUS		0xc0	/* Status  byte:   0b11###AEV	*/

#define	BSCBUS_SEQ		0x38	/* Sequence number bits		*/
#define	BSCBUS_SEQ_LSB		0x08	/* Sequence number LSB		*/
#define	BSCBUS_CMD_XADDR	0x04	/* Extended (2-byte) addressing	*/
#define	BSCBUS_CMD_WRITE	0x02	/* Write command		*/
#define	BSCBUS_CMD_WMSB		0x01	/* Set MSB on Write		*/
#define	BSCBUS_CMD_READ		0x01	/* Read command			*/
#define	BSCBUS_CMD_NOP		0x00	/* NOP command			*/

#define	BSCBUS_STATUS_ASYNC	0x04	/* Asynchronous event pending	*/
#define	BSCBUS_STATUS_ERR	0x02	/* Error in command processing	*/
#define	BSCBUS_STATUS_MSB	0x01	/* MSB of Value read		*/

#define	BSCBUS_VREG_LO(x)	((x) & ((1 << 7) - 1))
#define	BSCBUS_VREG_HI(x)	((x) >> 7)

#define	BSCBUS_BUFSIZE		8

#define	BSCBUS_CHANNEL_TO_OFFSET(chno)	((chno) * 2)	/* Register offset */

/*
 * Time periods, in nanoseconds
 *
 * Note that LOMBUS_ONE_SEC and some other time
 * periods are defined in <sys/lombus.h>
 */
#define	BSCBUS_CMD_POLL			(LOMBUS_ONE_SEC)
#define	BSCBUS_CMD_POLLNOINTS		(LOMBUS_ONE_SEC/20)
#define	BSCBUS_HWRESET_POLL		(LOMBUS_ONE_SEC/20)
#define	BSCBUS_HWRESET_TIMEOUT		(LOMBUS_ONE_SEC*2)

#define	BSCBUS_DOG_PAT_POLL_LIMIT	(1000)
#define	BSCBUS_DOG_PAT_POLL		(1)
#define	BSCBUS_PAT_RETRY_LIMIT	5

/*
 * Local datatypes
 */
enum bscbus_cmdstate {
	BSCBUS_CMDSTATE_IDLE,		/* No transaction in progress */
	BSCBUS_CMDSTATE_BUSY,		/* Setting up command */
	BSCBUS_CMDSTATE_CLEARING,	/* Clearing firmware busy status */
	BSCBUS_CMDSTATE_SENDING,	/* Waiting to send data to f/w */
	BSCBUS_CMDSTATE_PENDING,	/* Waiting for ack from f/w */
	BSCBUS_CMDSTATE_WAITING,	/* Waiting for status from f/w */
	BSCBUS_CMDSTATE_READY,		/* Status received/command done */
	BSCBUS_CMDSTATE_ERROR		/* Command failed with error */
};

struct bscbus_channel_state {
	/* Changes to these are protected by the instance ch_mutex mutex */
	struct bscbus_state	*ssp;
	uint8_t			*ch_regs;
	ddi_acc_handle_t	ch_handle;  /* per channel access handle */
	unsigned int		chno;
	unsigned int		map_count; /* Number of mappings to channel */
	boolean_t		map_dog;   /* channel is mapped for watchdog */

	/*
	 * Flag to indicate that we've incurred a hardware fault on
	 * accesses to the H8; once this is set, we fake all further
	 * accesses in order not to provoke additional bus errors.
	 */
	boolean_t		xio_fault;

	/*
	 * Data protected by the dog_mutex: the watchdog-patting
	 * protocol data (since the dog can be patted from a high-level
	 * cyclic), and the interrupt-enabled flag.
	 */
	kmutex_t		dog_mutex[1];
	unsigned int		pat_retry_count;
	unsigned int		pat_fail_count;

	/*
	 * Serial protocol state data, protected by lo_mutex
	 * (which is initialised using <lo_iblk>)
	 */
	kmutex_t		lo_mutex[1];
	ddi_iblock_cookie_t	lo_iblk;
	kcondvar_t		lo_cv[1];
	int			unclaimed_count;

	volatile enum bscbus_cmdstate cmdstate;
	clock_t			deadline;
	clock_t			poll_hz;
	boolean_t		interrupt_failed;
	uint8_t 		cmdbuf[BSCBUS_BUFSIZE];
	uint8_t			*cmdp;	/* Points to last tx'd in cmdbuf */
	uint8_t			reply[BSCBUS_BUFSIZE];
	uint8_t			async;
	uint8_t			index;
	uint8_t			result;
	uint8_t			sequence;
	uint32_t		error;
};

#define	BSCBUS_TX_PENDING(csp)		((csp)->cmdp > (csp)->cmdbuf)

/*
 * This driver's soft-state structure
 */

struct bscbus_state {
	/*
	 * Configuration data, set during attach
	 */
	dev_info_t		*dip;
	major_t			majornum;
	int			instance;

	ddi_acc_handle_t	h8_handle;
	uint8_t			*h8_regs;

	/*
	 * Parameters derived from .conf properties
	 */
	uint32_t		debug;

	/*
	 * Flag to indicate that we are using per channel
	 * mapping of the register sets and interrupts.
	 * reg set 0 is chan 0
	 * reg set 1 is chan 1 ...
	 *
	 * Interrupts are specified in that order but later
	 * channels may not have interrupts.
	 */
	boolean_t		per_channel_regs;

	/*
	 * channel state data, protected by ch_mutex
	 * channel claim/release requests are protected by this mutex.
	 */
	kmutex_t		ch_mutex[1];
	struct bscbus_channel_state	channel[BSCBUS_MAX_CHANNELS];

#ifdef BSCBUS_LOGSTATUS
	/*
	 * Command logging buffer for recording transactions with the
	 * BSC. This is useful for debugging failed transactions and other
	 * such funnies.
	 */
	bsc_cmd_log_t		*cmd_log;
	uint32_t		cmd_log_idx;
	uint32_t		cmd_log_size;
	uint32_t		cmd_log_flags;
#endif /* BSCBUS_LOGSTATUS */
};

/*
 * The auxiliary structure attached to each child
 * (the child's parent-private-data points to this).
 */
struct bscbus_child_info {
	lombus_regspec_t *rsp;
	int nregs;
};

#ifdef BSCBUS_LOGSTATUS
void bscbus_cmd_log(struct bscbus_channel_state *, bsc_cmd_stamp_t,
    uint8_t, uint8_t);
#else /* BSCBUS_LOGSTATUS */
#define	bscbus_cmd_log(state, stamp, status, data)
#endif /* BSCBUS_LOGSTATUS */


/*
 * Local data
 */

static void *bscbus_statep;

static major_t bscbus_major = NOMAJOR;

static ddi_device_acc_attr_t bscbus_dev_acc_attr[1] = {
	DDI_DEVICE_ATTR_V0,
	DDI_STRUCTURE_LE_ACC,
	DDI_STRICTORDER_ACC
};


/*
 *  General utility routines ...
 */

#ifdef DEBUG
static void
bscbus_trace(struct bscbus_channel_state *csp, char code, const char *caller,
	const char *fmt, ...)
{
	char buf[256];
	char *p;
	va_list va;

	if (csp->ssp->debug & (1 << (code-'@'))) {
		p = buf;
		(void) snprintf(p, sizeof (buf) - (p - buf),
		    "%s/%s: ", MYNAME, caller);
		p += strlen(p);

		va_start(va, fmt);
		(void) vsnprintf(p, sizeof (buf) - (p - buf), fmt, va);
		va_end(va);

		buf[sizeof (buf) - 1] = '\0';
		(void) strlog(csp->ssp->majornum, csp->ssp->instance,
		    code, SL_TRACE, buf);
	}
}
#else /* DEBUG */
#define	bscbus_trace
#endif /* DEBUG */

static struct bscbus_state *
bscbus_getstate(dev_info_t *dip, int instance, const char *caller)
{
	struct bscbus_state *ssp = NULL;
	dev_info_t *sdip = NULL;
	major_t dmaj = NOMAJOR;

	if (dip != NULL) {
		/*
		 * Use the instance number from the <dip>; also,
		 * check that it really corresponds to this driver
		 */
		instance = ddi_get_instance(dip);
		dmaj = ddi_driver_major(dip);
		if (bscbus_major == NOMAJOR && dmaj != NOMAJOR)
			bscbus_major = dmaj;
		else if (dmaj != bscbus_major) {
			cmn_err(CE_WARN,
			    "%s: major number mismatch (%d vs. %d) in %s(),"
			    "probably due to child misconfiguration",
			    MYNAME, bscbus_major, dmaj, caller);
			instance = -1;
		}
	}

	if (instance >= 0)
		ssp = ddi_get_soft_state(bscbus_statep, instance);
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
 * Lowest-level I/O register read/write
 */

static void
bscbus_put_reg(struct bscbus_channel_state *csp, uint_t reg, uint8_t val)
{
	if (csp->ch_handle != NULL && !csp->xio_fault) {
		ddi_put8(csp->ch_handle,
		    csp->ch_regs + reg, val);
	}
}

static uint8_t
bscbus_get_reg(struct bscbus_channel_state *csp, uint_t reg)
{
	uint8_t val;

	if (csp->ch_handle != NULL && !csp->xio_fault)
		val = ddi_get8(csp->ch_handle,
		    csp->ch_regs + reg);
	else
		val = DUMMY_VALUE;

	return (val);
}

static void
bscbus_check_fault_status(struct bscbus_channel_state *csp)
{
	csp->xio_fault =
	    ddi_check_acc_handle(csp->ch_handle) != DDI_SUCCESS;
}

static boolean_t
bscbus_faulty(struct bscbus_channel_state *csp)
{
	if (!csp->xio_fault)
		bscbus_check_fault_status(csp);
	return (csp->xio_fault);
}

/*
 * Write data into h8 registers
 */
static void
bscbus_pat_dog(struct bscbus_channel_state *csp, uint8_t val)
{
	uint8_t status;
	uint32_t doglimit = BSCBUS_DOG_PAT_POLL_LIMIT;

	bscbus_trace(csp, 'W', "bscbus_pat_dog:", "");

	bscbus_cmd_log(csp, BSC_CMD_DOGPAT, 0, val);
	status = bscbus_get_reg(csp, H8_STR);
	while (status & H8_STR_IBF) {
		if (csp->pat_retry_count > BSCBUS_PAT_RETRY_LIMIT) {
			/*
			 * Previous attempts to contact BSC have failed.
			 * Do not bother waiting for it to eat previous
			 * data.
			 * Pat anyway just in case the BSC is really alive
			 * and the IBF bit is lying.
			 */
			bscbus_put_reg(csp, H8_IDRC, val);
			bscbus_trace(csp, 'W', "bscbus_pat_dog:",
			    "retry count exceeded");
			return;
		}
		if (--doglimit == 0) {
			/* The BSC is not responding - give up */
			csp->pat_fail_count++;
			csp->pat_retry_count++;
			/* Pat anyway just in case the BSC is really alive */
			bscbus_put_reg(csp, H8_IDRC, val);
			bscbus_trace(csp, 'W', "bscbus_pat_dog:",
			    "poll limit exceeded");
			return;
		}
		drv_usecwait(BSCBUS_DOG_PAT_POLL);
		status = bscbus_get_reg(csp, H8_STR);
	}
	bscbus_put_reg(csp, H8_IDRC, val);
	csp->pat_retry_count = 0;
}

/*
 * State diagrams for how bscbus_process works.
 *	BSCBUS_CMDSTATE_IDLE		No transaction in progress
 *	BSCBUS_CMDSTATE_BUSY		Setting up command
 *	BSCBUS_CMDSTATE_CLEARING	Clearing firmware busy status
 *	BSCBUS_CMDSTATE_SENDING		Waiting to send data to f/w
 *	BSCBUS_CMDSTATE_PENDING		Waiting for ack from f/w
 *	BSCBUS_CMDSTATE_WAITING		Waiting for status from f/w
 *	BSCBUS_CMDSTATE_READY		Status received/command done
 *	BSCBUS_CMDSTATE_ERROR		Command failed with error
 *
 *	+----------+
 *	|	   |
 *	| IDLE/BUSY|
 *	|   (0/1)  |  abnormal
 *	+----------+  state
 *	    |	  \   detected
 *	    |	   \------>------+  +----<---+
 *	bsc |			 |  |	     |
 *	is  |			 V  V	     |
 *     ready|		     +----------+    |
 *	    |		     |		|    ^
 *	    |		     | CLEARING |    |
 *	    |		     |	 (2)	|    |
 *	    |		     +----------+    |
 *	    |		 cleared /  | \	     | more to clear
 *	    |			/   |  \-->--+
 *	    |  +-------<-------/    V
 *	    |  |		    |
 *	    V  V		    |timeout
 *	+----------+ timeout	    |
 *	|	   |------>---------+--------+
 *	| SENDING  |			     |
 *	|   (3)	   |------<-------+	     |
 *	+----------+		  |	     V
 *	sent|	 \ send		  ^ack	     |
 *	last|	  \ next	  |received  |
 *	    |	   \	     +----------+    |
 *	    |	    \	     |		|    |
 *	    |	     \------>| PENDING	|-->-+
 *	    |		     |	 (4)	|    |
 *	    |		     +----------+    |timeout
 *	    |	 +---<----+		     |
 *	    |	 |	  |		     |
 *	    V	 V	  |		     |
 *	+----------+	  |		     |
 *	|	   |	  |		     |
 *	| WAITING  |	  ^		     |
 *	|   (5)	   |	  |		     |
 *	+----------+	  |		     |
 *	    |  | |more	  |		     |
 *	    |  V |required|		     |
 *	done|  | +--->----+		     |
 *	    |  +--->--------------+  +---<---+
 *	    |	error/timeout	  |  |
 *	    V			  V  V
 *	+----------+	      +----------+
 *	|	   |	      |		 |
 *	| READY	   |	      |	 ERROR	 |
 *	|   (7)	   |	      |	  (6)	 |
 *	+----------+	      +----------+
 *	    |			  |
 *	    V			  V
 *	    |			  |
 *	    +------>---+---<------+
 *		       |
 *		       |
 *		     Back to
 *		      Idle
 */

static void
bscbus_process_sending(struct bscbus_channel_state *csp, uint8_t status)
{
	/*
	 * When we get here we actually expect H8_STR_IBF to
	 * be clear but we check just in case of problems.
	 */
	ASSERT(BSCBUS_TX_PENDING(csp));
	if (!(status & H8_STR_IBF)) {
		bscbus_put_reg(csp, H8_IDRD, *--csp->cmdp);
		bscbus_trace(csp, 'P', "bscbus_process_sending",
		    "state %d; val $%x",
		    csp->cmdstate, *csp->cmdp);
		if (!BSCBUS_TX_PENDING(csp)) {
			bscbus_cmd_log(csp, BSC_CMD_SENT,
			    status, *csp->cmdp);
			/* No more pending - move to waiting state */
			bscbus_trace(csp, 'P', "bscbus_process_sending",
			    "moving to waiting");
			csp->cmdstate = BSCBUS_CMDSTATE_WAITING;
			/* Extend deadline because time has moved on */
			csp->deadline = ddi_get_lbolt() +
			    drv_usectohz(LOMBUS_CMD_TIMEOUT/1000);
		} else {
			/* Wait for ack of this byte */
			bscbus_cmd_log(csp, BSC_CMD_SENDING,
			    status, *csp->cmdp);
			csp->cmdstate = BSCBUS_CMDSTATE_PENDING;
			bscbus_trace(csp, 'P', "bscbus_process_sending",
			    "moving to pending");
		}
	}
}

static void
bscbus_process_clearing(struct bscbus_channel_state *csp,
    uint8_t status, uint8_t data)
{
	/*
	 * We only enter this state if H8_STR_BUSY was set when
	 * we started the transaction. We just ignore all received
	 * data until we see OBF set AND BUSY cleared.
	 * It is not good enough to see BUSY clear on its own
	 */
	if ((status & H8_STR_OBF) && !(status & H8_STR_BUSY)) {
		bscbus_cmd_log(csp, BSC_CMD_CLEARED, status, data);
		csp->cmdstate = BSCBUS_CMDSTATE_SENDING;
		/* Throw away any data received up until now */
		bscbus_trace(csp, 'P', "bscbus_process_clearing",
		    "busy cleared");
		/*
		 * Send the next byte immediately.
		 * At this stage we should clear the OBF flag because that
		 * data has been used. IBF is still valid so do not clear that.
		 */
		status &= ~(H8_STR_OBF);
		bscbus_process_sending(csp, status);
	} else {
		if (status & H8_STR_OBF) {
			bscbus_cmd_log(csp, BSC_CMD_CLEARING, status, data);
		}
	}
}

static void
bscbus_process_pending(struct bscbus_channel_state *csp, uint8_t status)
{
	/* We are waiting for an acknowledgement of a byte */
	if (status & H8_STR_OBF) {
		bscbus_cmd_log(csp, BSC_CMD_PENDING,
		    status, *csp->cmdp);
		bscbus_trace(csp, 'P', "bscbus_process_pending",
		    "moving to sending");
		csp->cmdstate = BSCBUS_CMDSTATE_SENDING;
		/*
		 * Send the next byte immediately.
		 * At this stage we should clear the OBF flag because that
		 * data has been used. IBF is still valid so do not clear that.
		 */
		status &= ~(H8_STR_OBF);
		bscbus_process_sending(csp, status);
	}
}

static boolean_t
bscbus_process_waiting(struct bscbus_channel_state *csp,
    uint8_t status, uint8_t data)
{
	uint8_t rcvd = 0;
	boolean_t ready = B_FALSE;
	uint8_t tmp;

	if (status & H8_STR_OBF) {
		csp->reply[rcvd = csp->index] = data;
		if (++rcvd < BSCBUS_BUFSIZE)
			csp->index = rcvd;

		bscbus_trace(csp, 'D', "bscbus_process_waiting",
		    "rcvd %d: $%02x $%02x $%02x $%02x $%02x $%02x $%02x $%02x",
		    rcvd,
		    csp->reply[0], csp->reply[1],
		    csp->reply[2], csp->reply[3],
		    csp->reply[4], csp->reply[5],
		    csp->reply[6], csp->reply[7]);
	}

	if (rcvd == 0) {
		/*
		 * No bytes received this time through (though there
		 * might be a partial packet sitting in the buffer).
		 */
		/* EMPTY */
		;
	} else if (rcvd >= BSCBUS_BUFSIZE) {
		/*
		 * Buffer overflow; discard the data & treat as an error
		 * (even if the last byte read did claim to terminate a
		 * packet, it can't be a valid one 'cos it's too long!)
		 */
		bscbus_cmd_log(csp, BSC_CMD_ERROR_OFLOW, status, data);
		csp->index = 0;
		csp->cmdstate = BSCBUS_CMDSTATE_ERROR;
		csp->error = LOMBUS_ERR_OFLOW;
		ready = B_TRUE;
	} else if ((data & BSCBUS_LAST) == 0) {
		/*
		 * Packet not yet complete; leave the partial packet in
		 * the buffer for later ...
		 */
		bscbus_cmd_log(csp, BSC_CMD_REPLY, status, data);
	} else if ((data & BSCBUS_MASK) != BSCBUS_STATUS) {
		/* Invalid "status" byte - maybe an echo of the command? */
		bscbus_cmd_log(csp, BSC_CMD_ERROR_STATUS, status, data);

		csp->cmdstate = BSCBUS_CMDSTATE_ERROR;
		csp->error = LOMBUS_ERR_BADSTATUS;
		ready = B_TRUE;
	} else if ((data & BSCBUS_SEQ) != csp->sequence) {
		/* Wrong sequence number!  Flag this as an error */
		bscbus_cmd_log(csp, BSC_CMD_ERROR_SEQ, status, data);

		csp->cmdstate = BSCBUS_CMDSTATE_ERROR;
		csp->error = LOMBUS_ERR_SEQUENCE;
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
		bscbus_cmd_log(csp, BSC_CMD_COMPLETE, status, data);
		csp->async = (data & BSCBUS_STATUS_ASYNC) ? 1 : 0;

		tmp = ((data & BSCBUS_STATUS_MSB) ? 0x80 : 0) | csp->reply[0];
		if (data & BSCBUS_STATUS_ERR) {
			csp->cmdstate = BSCBUS_CMDSTATE_ERROR;
			csp->error = tmp;
		} else {
			csp->cmdstate = BSCBUS_CMDSTATE_READY;
			csp->result = tmp;
		}
		ready = B_TRUE;
	}
	return (ready);
}

/*
 * Packet receive handler
 *
 * This routine should be called from the low-level softint,
 * or bscbus_cmd() (for polled operation), with the
 * low-level mutex already held.
 */
static void
bscbus_process(struct bscbus_channel_state *csp,
    uint8_t status, uint8_t data)
{
	boolean_t ready = B_FALSE;

	ASSERT(mutex_owned(csp->lo_mutex));

	if ((status & H8_STR_OBF) || (status & H8_STR_IBF)) {
		bscbus_trace(csp, 'D', "bscbus_process",
		    "state %d; error $%x",
		    csp->cmdstate, csp->error);
	}

	switch (csp->cmdstate) {
	case BSCBUS_CMDSTATE_CLEARING:
		bscbus_process_clearing(csp, status, data);
		break;
	case BSCBUS_CMDSTATE_SENDING:
		bscbus_process_sending(csp, status);
		break;
	case BSCBUS_CMDSTATE_PENDING:
		bscbus_process_pending(csp, status);
		break;
	case BSCBUS_CMDSTATE_WAITING:
		ready = bscbus_process_waiting(csp, status, data);
		break;
	default:
		/* Nothing to do */
		break;
	}

	/*
	 * Check for timeouts - but only if the command has not yet
	 * completed (ready is true when command completes in this
	 * call to bscbus_process OR cmdstate is READY or ERROR if
	 * this is a spurious call to bscbus_process i.e. a spurious
	 * interrupt)
	 */
	if (!ready &&
	    ((ddi_get_lbolt() - csp->deadline) > 0) &&
	    csp->cmdstate != BSCBUS_CMDSTATE_READY &&
	    csp->cmdstate != BSCBUS_CMDSTATE_ERROR) {
		bscbus_trace(csp, 'P', "bscbus_process",
		    "timeout previous state %d; error $%x",
		    csp->cmdstate, csp->error);
		bscbus_cmd_log(csp, BSC_CMD_ERROR_TOUT, status, data);
		if (csp->cmdstate == BSCBUS_CMDSTATE_CLEARING) {
			/* Move onto sending because busy might be stuck */
			csp->cmdstate = BSCBUS_CMDSTATE_SENDING;
			/* Extend timeout relative to original start time */
			csp->deadline += drv_usectohz(LOMBUS_CMD_TIMEOUT/1000);
		} else if (csp->cmdstate != BSCBUS_CMDSTATE_IDLE) {
			csp->cmdstate = BSCBUS_CMDSTATE_ERROR;
			csp->error = LOMBUS_ERR_TIMEOUT;
		}
		ready = B_TRUE;
	}

	if ((status & H8_STR_OBF) || (status & H8_STR_IBF) || ready) {
		bscbus_trace(csp, 'D', "bscbus_process",
		    "last $%02x; state %d; error $%x; ready %d",
		    data, csp->cmdstate, csp->error, ready);
	}
	if (ready)
		cv_broadcast(csp->lo_cv);
}

static uint_t
bscbus_hwintr(caddr_t arg)
{
	struct bscbus_channel_state *csp = (void *)arg;

	uint8_t status;
	uint8_t data = 0xb0 /* Dummy value */;

	mutex_enter(csp->lo_mutex);
	/*
	 * Read the registers to ensure that the interrupt is cleared.
	 * Status must be read first because reading data changes the
	 * status.
	 * We always read the data because that clears the interrupt down.
	 * This is horrible hardware semantics but we have to do it!
	 */
	status = bscbus_get_reg(csp, H8_STR);
	data = bscbus_get_reg(csp, H8_ODR);
	if (!(status & H8_STR_OBF)) {
		bscbus_cmd_log(csp, BSC_CMD_V1INTRUNCL, status, data);
		csp->unclaimed_count++;
	} else {
		bscbus_cmd_log(csp, BSC_CMD_V1INTR, status, data);
	}
	if (status & H8_STR_TOKENPROTOCOL) {
		bscbus_process(csp, status, data);
		if (csp->interrupt_failed) {
			bscbus_trace(csp, 'I', "bscbus_hwintr:",
			    "interrupt fault cleared channel %d", csp->chno);
			csp->interrupt_failed = B_FALSE;
			csp->poll_hz = drv_usectohz(BSCBUS_CMD_POLL / 1000);
		}
	}

	mutex_exit(csp->lo_mutex);
	return (DDI_INTR_CLAIMED);
}

void
bscbus_poll(struct bscbus_channel_state *csp)
{
	/*
	 * This routine is only called if we timeout in userland
	 * waiting for an interrupt. This generally means that we have
	 * lost interrupt capabilities or that something has gone
	 * wrong.  In this case we are allowed to access the hardware
	 * and read the data register if necessary.
	 * If interrupts return then recovery actions should mend us!
	 */
	uint8_t status;
	uint8_t data = 0xfa; /* Dummy value */

	ASSERT(mutex_owned(csp->lo_mutex));

	/* Should look for data to receive */
	status = bscbus_get_reg(csp, H8_STR);
	if (status & H8_STR_OBF) {
		/* There is data available */
		data = bscbus_get_reg(csp, H8_ODR);
		bscbus_cmd_log(csp, BSC_CMD_PROCESS, status, data);
	}
	bscbus_process(csp, status, data);
}

/*
 * Serial protocol
 *
 * This routine builds a command and sets it in progress.
 */
static uint8_t
bscbus_cmd(HANDLE_TYPE *hdlp, ptrdiff_t vreg, uint_t val, uint_t cmd)
{
	struct bscbus_channel_state *csp;
	clock_t start;
	uint8_t status;

	/*
	 * First of all, wait for the interface to be available.
	 *
	 * NOTE: we blow through all the mutex/cv/state checking and
	 * preempt any command in progress if the system is panicking!
	 */
	csp = HANDLE_PRIVATE(hdlp);
	mutex_enter(csp->lo_mutex);
	while (csp->cmdstate != BSCBUS_CMDSTATE_IDLE && !ddi_in_panic())
		cv_wait(csp->lo_cv, csp->lo_mutex);

	csp->cmdstate = BSCBUS_CMDSTATE_BUSY;
	csp->sequence = (csp->sequence + BSCBUS_SEQ_LSB) & BSCBUS_SEQ;

	/*
	 * We have exclusive ownership, so assemble the command (backwards):
	 *
	 * [byte 0]	Command:	modified by XADDR and/or WMSB bits
	 * [Optional] Parameter: 	Value to write (low 7 bits)
	 * [Optional] Parameter: 	Register number (high 7 bits)
	 * [Optional] Parameter: 	Register number (low 7 bits)
	 */
	csp->cmdp = &csp->cmdbuf[0];
	*csp->cmdp++ = BSCBUS_CMD | csp->sequence | cmd;
	switch (cmd) {
	case BSCBUS_CMD_WRITE:
		*csp->cmdp++ = val & 0x7f;
		if (val >= 0x80)
			csp->cmdbuf[0] |= BSCBUS_CMD_WMSB;
		/*FALLTHRU*/
	case BSCBUS_CMD_READ:
		if (BSCBUS_VREG_HI(vreg) != 0) {
			*csp->cmdp++ = BSCBUS_VREG_HI(vreg);
			csp->cmdbuf[0] |= BSCBUS_CMD_XADDR;
		}
		*csp->cmdp++ = BSCBUS_VREG_LO(vreg);
		/*FALLTHRU*/
	case BSCBUS_CMD_NOP:
		break;
	}

	/*
	 * Check and update the H8 h/w fault status before accessing
	 * the chip registers.  If there's a (new or previous) fault,
	 * we'll run through the protocol but won't really touch the
	 * hardware and all commands will timeout.  If a previously
	 * discovered fault has now gone away (!), then we can (try to)
	 * proceed with the new command (probably a probe).
	 */
	bscbus_check_fault_status(csp);

	/*
	 * Prepare for the command (to be processed by the interrupt
	 * handler and/or polling loop below), and wait for a response
	 * or timeout.
	 */
	start = ddi_get_lbolt();
	csp->deadline = start + drv_usectohz(LOMBUS_CMD_TIMEOUT/1000);
	csp->error = 0;
	csp->index = 0;
	csp->result = DUMMY_VALUE;

	status = bscbus_get_reg(csp, H8_STR);
	if (status & H8_STR_BUSY) {
		bscbus_cmd_log(csp, BSC_CMD_BUSY, status, 0xfd);
		/*
		 * Must ensure that the busy state has cleared before
		 * sending the command
		 */
		csp->cmdstate = BSCBUS_CMDSTATE_CLEARING;
		bscbus_trace(csp, 'P', "bscbus_cmd",
		    "h8 reporting status (%x) busy - clearing", status);
	} else {
		/* It is clear to send the command immediately */
		csp->cmdstate = BSCBUS_CMDSTATE_SENDING;
		bscbus_trace(csp, 'P', "bscbus_cmd",
		    "sending first byte of command, status %x", status);
		bscbus_poll(csp);
	}

	csp->poll_hz = drv_usectohz(
	    (csp->interrupt_failed ?
	    BSCBUS_CMD_POLLNOINTS : BSCBUS_CMD_POLL) / 1000);

	while ((csp->cmdstate != BSCBUS_CMDSTATE_READY) &&
	    (csp->cmdstate != BSCBUS_CMDSTATE_ERROR)) {
		ASSERT(csp->cmdstate != BSCBUS_CMDSTATE_IDLE);

		if ((cv_reltimedwait(csp->lo_cv, csp->lo_mutex,
		    csp->poll_hz, TR_CLOCK_TICK) == -1) &&
		    csp->cmdstate != BSCBUS_CMDSTATE_READY &&
		    csp->cmdstate != BSCBUS_CMDSTATE_ERROR) {
			if (!csp->interrupt_failed) {
				bscbus_trace(csp, 'I', "bscbus_cmd:",
				    "interrupt_failed channel %d", csp->chno);
				csp->interrupt_failed = B_TRUE;
				csp->poll_hz = drv_usectohz(
				    BSCBUS_CMD_POLLNOINTS / 1000);
			}
			bscbus_poll(csp);
		}
	}

	/*
	 * The return value may not be meaningful but retrieve it anyway
	 */
	val = csp->result;
	if (bscbus_faulty(csp)) {
		val = DUMMY_VALUE;
		HANDLE_FAULT(hdlp) = LOMBUS_ERR_SIOHW;
	} else if (csp->cmdstate != BSCBUS_CMDSTATE_READY) {
		/*
		 * Some problem here ... transfer the error code from
		 * the per-instance state to the per-handle fault flag.
		 * The error code shouldn't be zero!
		 */
		if (csp->error != 0)
			HANDLE_FAULT(hdlp) = csp->error;
		else
			HANDLE_FAULT(hdlp) = LOMBUS_ERR_BADERRCODE;
	}

	/*
	 * All done now!
	 */
	csp->index = 0;
	csp->cmdstate = BSCBUS_CMDSTATE_IDLE;
	cv_broadcast(csp->lo_cv);
	mutex_exit(csp->lo_mutex);

	return (val);
}

/*
 * Space 0 - LOM virtual register access
 * Only 8-bit accesses are supported.
 */
static uint8_t
bscbus_vreg_get8(HANDLE_TYPE *hdlp, uint8_t *addr)
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
	return (bscbus_cmd(hdlp, ADDR_TO_VREG(addr), 0, BSCBUS_CMD_READ));
}

static void
bscbus_vreg_put8(HANDLE_TYPE *hdlp, uint8_t *addr, uint8_t val)
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
	(void) bscbus_cmd(hdlp, ADDR_TO_VREG(addr), val, BSCBUS_CMD_WRITE);
}

static void
bscbus_vreg_rep_get8(HANDLE_TYPE *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	size_t inc;

	inc = (flags & DDI_DEV_AUTOINCR) ? 1 : 0;
	for (; repcount--; dev_addr += inc)
		*host_addr++ = bscbus_vreg_get8(hdlp, dev_addr);
}

static void
bscbus_vreg_rep_put8(HANDLE_TYPE *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	size_t inc;

	inc = (flags & DDI_DEV_AUTOINCR) ? 1 : 0;
	for (; repcount--; dev_addr += inc)
		bscbus_vreg_put8(hdlp, dev_addr, *host_addr++);
}


/*
 * Space 1 - LOM watchdog pat register access
 * Only 8-bit accesses are supported.
 *
 * Reads have no effect and return 0.
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
bscbus_pat_get8(HANDLE_TYPE *hdlp, uint8_t *addr)
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
bscbus_pat_put8(HANDLE_TYPE *hdlp, uint8_t *addr, uint8_t val)
{
	struct bscbus_channel_state *csp;
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

	csp = HANDLE_PRIVATE(hdlp);
	mutex_enter(csp->dog_mutex);
	bscbus_pat_dog(csp, val);
	mutex_exit(csp->dog_mutex);
}

static void
bscbus_pat_rep_get8(HANDLE_TYPE *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	size_t inc;

	inc = (flags & DDI_DEV_AUTOINCR) ? 1 : 0;
	for (; repcount--; dev_addr += inc)
		*host_addr++ = bscbus_pat_get8(hdlp, dev_addr);
}

static void
bscbus_pat_rep_put8(HANDLE_TYPE *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	size_t inc;

	inc = (flags & DDI_DEV_AUTOINCR) ? 1 : 0;
	for (; repcount--; dev_addr += inc)
		bscbus_pat_put8(hdlp, dev_addr, *host_addr++);
}


/*
 * Space 2 - LOM async event flag register access
 * Only 16-bit accesses are supported.
 */
static uint16_t
bscbus_event_get16(HANDLE_TYPE *hdlp, uint16_t *addr)
{
	struct bscbus_channel_state *csp;
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
	csp = HANDLE_PRIVATE(hdlp);
	return (csp->async);
}

static void
bscbus_event_put16(HANDLE_TYPE *hdlp, uint16_t *addr, uint16_t val)
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
bscbus_event_rep_get16(HANDLE_TYPE *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	size_t inc;

	inc = (flags & DDI_DEV_AUTOINCR) ? 1 : 0;
	for (; repcount--; dev_addr += inc)
		*host_addr++ = bscbus_event_get16(hdlp, dev_addr);
}

static void
bscbus_event_rep_put16(HANDLE_TYPE *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	size_t inc;

	inc = (flags & DDI_DEV_AUTOINCR) ? 1 : 0;
	for (; repcount--; dev_addr += inc)
		bscbus_event_put16(hdlp, dev_addr, *host_addr++);
}


/*
 * All spaces - access handle fault information
 * Only 32-bit accesses are supported.
 */
static uint32_t
bscbus_meta_get32(HANDLE_TYPE *hdlp, uint32_t *addr)
{
	struct bscbus_channel_state *csp;
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
		(void) bscbus_cmd(hdlp, 0, 0, BSCBUS_CMD_NOP);
		return (HANDLE_FAULT(hdlp));

	case LOMBUS_ASYNC_REG:
		/*
		 * Obsolescent - but still supported for backwards
		 * compatibility.  This is an alias for the newer
		 * LOMBUS_EVENT_REG, but doesn't require a separate
		 * "reg" entry and ddi_regs_map_setup() call.
		 *
		 * It returns the value of the asynchronous-event-pending
		 * flag as passed back by the BSC at the end of the last
		 * completed command.
		 */
		csp = HANDLE_PRIVATE(hdlp);
		return (csp->async);

	default:
		/*
		 * Invalid access - flag a fault and return a dummy value
		 */
		HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
		return (DUMMY_VALUE);
	}
}

static void
bscbus_meta_put32(HANDLE_TYPE *hdlp, uint32_t *addr, uint32_t val)
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
		(void) bscbus_cmd(hdlp, 0, 0, BSCBUS_CMD_NOP);
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
bscbus_meta_rep_get32(HANDLE_TYPE *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	size_t inc;

	inc = (flags & DDI_DEV_AUTOINCR) ? 1 : 0;
	for (; repcount--; dev_addr += inc)
		*host_addr++ = bscbus_meta_get32(hdlp, dev_addr);
}

static void
bscbus_meta_rep_put32(HANDLE_TYPE *hdlp, uint32_t *host_addr,
	uint32_t *dev_addr, size_t repcount, uint_t flags)
{
	size_t inc;

	inc = (flags & DDI_DEV_AUTOINCR) ? 1 : 0;
	for (; repcount--; dev_addr += inc)
		bscbus_meta_put32(hdlp, dev_addr, *host_addr++);
}


/*
 * Finally, some dummy functions for all unsupported access
 * space/size/mode combinations ...
 */
static uint8_t
bscbus_no_get8(HANDLE_TYPE *hdlp, uint8_t *addr)
{
	_NOTE(ARGUNUSED(addr))

	/*
	 * Invalid access - flag a fault and return a dummy value
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
	return (DUMMY_VALUE);
}

static void
bscbus_no_put8(HANDLE_TYPE *hdlp, uint8_t *addr, uint8_t val)
{
	_NOTE(ARGUNUSED(addr, val))

	/*
	 * Invalid access - flag a fault
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
}

static void
bscbus_no_rep_get8(HANDLE_TYPE *hdlp, uint8_t *host_addr,
		uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	_NOTE(ARGUNUSED(host_addr, dev_addr, repcount, flags))

	/*
	 * Invalid access - flag a fault
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
}

static void
bscbus_no_rep_put8(HANDLE_TYPE *hdlp, uint8_t *host_addr,
	uint8_t *dev_addr, size_t repcount, uint_t flags)
{
	_NOTE(ARGUNUSED(host_addr, dev_addr, repcount, flags))

	/*
	 * Invalid access - flag a fault
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
}

static uint16_t
bscbus_no_get16(HANDLE_TYPE *hdlp, uint16_t *addr)
{
	_NOTE(ARGUNUSED(addr))

	/*
	 * Invalid access - flag a fault and return a dummy value
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
	return (DUMMY_VALUE);
}

static void
bscbus_no_put16(HANDLE_TYPE *hdlp, uint16_t *addr, uint16_t val)
{
	_NOTE(ARGUNUSED(addr, val))

	/*
	 * Invalid access - flag a fault
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
}

static void
bscbus_no_rep_get16(HANDLE_TYPE *hdlp, uint16_t *host_addr,
		uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	_NOTE(ARGUNUSED(host_addr, dev_addr, repcount, flags))

	/*
	 * Invalid access - flag a fault
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
}

static void
bscbus_no_rep_put16(HANDLE_TYPE *hdlp, uint16_t *host_addr,
	uint16_t *dev_addr, size_t repcount, uint_t flags)
{
	_NOTE(ARGUNUSED(host_addr, dev_addr, repcount, flags))

	/*
	 * Invalid access - flag a fault
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
}

static uint64_t
bscbus_no_get64(HANDLE_TYPE *hdlp, uint64_t *addr)
{
	_NOTE(ARGUNUSED(addr))

	/*
	 * Invalid access - flag a fault and return a dummy value
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
	return (DUMMY_VALUE);
}

static void
bscbus_no_put64(HANDLE_TYPE *hdlp, uint64_t *addr, uint64_t val)
{
	_NOTE(ARGUNUSED(addr, val))

	/*
	 * Invalid access - flag a fault
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
}

static void
bscbus_no_rep_get64(HANDLE_TYPE *hdlp, uint64_t *host_addr,
	uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	_NOTE(ARGUNUSED(host_addr, dev_addr, repcount, flags))

	/*
	 * Invalid access - flag a fault
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
}

static void
bscbus_no_rep_put64(HANDLE_TYPE *hdlp, uint64_t *host_addr,
	uint64_t *dev_addr, size_t repcount, uint_t flags)
{
	_NOTE(ARGUNUSED(host_addr, dev_addr, repcount, flags))

	/*
	 * Invalid access - flag a fault
	 */
	HANDLE_FAULT(hdlp) = LOMBUS_ERR_REG_SIZE;
}

static int
bscbus_acc_fault_check(HANDLE_TYPE *hdlp)
{
	return (HANDLE_FAULT(hdlp) != 0);
}

/*
 * Hardware setup - ensure that there are no pending transactions and
 * hence no pending interrupts. We do this be ensuring that the BSC is
 * not reporting a busy condition and that it does not have any data
 * pending in its output buffer.
 * This is important because if we have pending interrupts at attach
 * time Solaris will hang due to bugs in ddi_get_iblock_cookie.
 */
static void
bscbus_hw_reset(struct bscbus_channel_state *csp)
{
	int64_t timeout;
	uint8_t status;

	if (csp->map_count == 0) {
		/* No-one using this instance - no need to reset hardware */
		return;
	}

	bscbus_trace(csp, 'R', "bscbus_hw_reset",
	    "resetting channel %d", csp->chno);

	status = bscbus_get_reg(csp, H8_STR);
	if (status & H8_STR_BUSY) {
		/*
		 * Give the h8 time to complete a reply.
		 * In practice we should never worry about this
		 * because whenever we get here it will have been
		 * long enough for the h8 to complete a reply
		 */
		bscbus_cmd_log(csp, BSC_CMD_BUSY, status, 0);
		bscbus_trace(csp, 'R', "bscbus_hw_reset",
		    "h8 reporting status (%x) busy - waiting", status);
		if (ddi_in_panic()) {
			drv_usecwait(BSCBUS_HWRESET_POLL/1000);
		} else {
			delay(drv_usectohz(BSCBUS_HWRESET_POLL/1000));
		}
	}
	/* Reply should be completed by now. Try to clear busy status */
	status = bscbus_get_reg(csp, H8_STR);
	if (status & (H8_STR_BUSY | H8_STR_OBF)) {
		bscbus_trace(csp, 'R', "bscbus_hw_reset",
		    "clearing busy status for channel %d", csp->chno);

		for (timeout = BSCBUS_HWRESET_TIMEOUT;
		    (timeout > 0);
		    timeout -= BSCBUS_HWRESET_POLL) {
			if (status & H8_STR_OBF) {
				(void) bscbus_get_reg(csp, H8_ODR);
				if (!(status & H8_STR_BUSY)) {
					/* We are done */
					break;
				}
			}
			if (ddi_in_panic()) {
				drv_usecwait(BSCBUS_HWRESET_POLL/1000);
			} else {
				delay(drv_usectohz(BSCBUS_HWRESET_POLL/1000));
			}
			status = bscbus_get_reg(csp, H8_STR);
		}
		if (timeout <= 0) {
			cmn_err(CE_WARN, "bscbus_hw_reset: timed out "
			    "clearing busy status");
		}
	}
	/*
	 * We read ODR just in case there is a pending interrupt with
	 * no data. This is potentially dangerous because we could get
	 * out of sync due to race conditions BUT at this point the
	 * channel should be idle so it is safe.
	 */
	(void) bscbus_get_reg(csp, H8_ODR);
}

/*
 * Higher-level setup & teardown
 */

static void
bscbus_offline(struct bscbus_state *ssp)
{
	if (ssp->h8_handle != NULL)
		ddi_regs_map_free(&ssp->h8_handle);
	ssp->h8_handle = NULL;
	ssp->h8_regs = NULL;
}

static int
bscbus_online(struct bscbus_state *ssp)
{
	ddi_acc_handle_t h;
	caddr_t p;
	int nregs;
	int err;

	ssp->h8_handle = NULL;
	ssp->h8_regs = (void *)NULL;
	ssp->per_channel_regs = B_FALSE;

	if (ddi_dev_nregs(ssp->dip, &nregs) != DDI_SUCCESS)
		nregs = 0;

	switch (nregs) {
	case 1:
		/*
		 *  regset 0 represents the H8 interface registers
		 */
		err = ddi_regs_map_setup(ssp->dip, 0, &p, 0, 0,
		    bscbus_dev_acc_attr, &h);
		if (err != DDI_SUCCESS)
			return (EIO);

		ssp->h8_handle = h;
		ssp->h8_regs = (void *)p;
		break;

	case 0:
		/*
		 *  If no registers are defined, succeed vacuously;
		 *  commands will be accepted, but we fake the accesses.
		 */
		break;

	default:
		/*
		 * Remember that we are using the new register scheme.
		 * reg set 0 is chan 0
		 * reg set 1 is chan 1 ...
		 * Interrupts are specified in that order but later
		 * channels may not have interrupts.
		 * We map the regs later on a per channel basis.
		 */
		ssp->per_channel_regs = B_TRUE;
		break;
	}
	return (0);
}

static int
bscbus_claim_channel(struct bscbus_channel_state *csp, boolean_t map_dog)
{
	int err;

	mutex_enter(csp->ssp->ch_mutex);
	csp->map_count++;
	bscbus_trace(csp, 'C', "bscbus_claim_channel",
	    "claim channel for channel %d, count %d",
	    csp->chno, csp->map_count);

	if (csp->map_count == 1) {
		/* No-one is using this channel - initialise it */
		bscbus_trace(csp, 'C', "bscbus_claim_channel",
		    "initialise channel %d, count %d",
		    csp->chno, csp->map_count);

		mutex_init(csp->dog_mutex, NULL, MUTEX_DRIVER,
		    (void *)(uintptr_t)__ipltospl(SPL7 - 1));
		csp->map_dog = map_dog;
		csp->interrupt_failed = B_FALSE;
		csp->cmdstate = BSCBUS_CMDSTATE_IDLE;
		csp->pat_retry_count = 0;
		csp->pat_fail_count = 0;

		/* Map appropriate register set for this channel */
		if (csp->ssp->per_channel_regs == B_TRUE) {
			ddi_acc_handle_t h;
			caddr_t p;

			err = ddi_regs_map_setup(csp->ssp->dip, csp->chno,
			    &p, 0, 0, bscbus_dev_acc_attr, &h);

			if (err != DDI_SUCCESS) {
				goto failed1;
			}

			csp->ch_handle = h;
			csp->ch_regs = (void *)p;

			bscbus_trace(csp, 'C', "bscbus_claim_channel",
			    "mapped chno=%d ch_handle=%d ch_regs=%p",
			    csp->chno, h, p);
		} else {
			/*
			 * if using the old reg property scheme use the
			 * common mapping.
			 */
			csp->ch_handle = csp->ssp->h8_handle;
			csp->ch_regs =
			    csp->ssp->h8_regs +
			    BSCBUS_CHANNEL_TO_OFFSET(csp->chno);
		}

		/* Ensure no interrupts pending prior to getting iblk cookie */
		bscbus_hw_reset(csp);

		if (csp->map_dog == 1) {
			/*
			 * we don't want lo_mutex to be initialised
			 * with an iblock cookie if we are the wdog,
			 * because we don't use interrupts.
			 */
			mutex_init(csp->lo_mutex, NULL,
			    MUTEX_DRIVER, NULL);
			cv_init(csp->lo_cv, NULL,
			    CV_DRIVER, NULL);
			csp->unclaimed_count = 0;
		} else {
			int ninterrupts;

			/*
			 * check that there is an interrupt for this
			 * this channel. If we fail to setup interrupts we
			 * must unmap the registers and fail.
			 */
			err = ddi_dev_nintrs(csp->ssp->dip, &ninterrupts);

			if (err != DDI_SUCCESS) {
				ninterrupts = 0;
			}

			if (ninterrupts <= csp->chno) {
				cmn_err(CE_WARN,
				    "no interrupt available for "
				    "bscbus channel %d", csp->chno);
				goto failed2;
			}

			if (ddi_intr_hilevel(csp->ssp->dip, csp->chno) != 0) {
				cmn_err(CE_WARN,
				    "bscbus interrupts are high "
				    "level - channel not usable.");
				goto failed2;
			} else {
				err = ddi_get_iblock_cookie(csp->ssp->dip,
				    csp->chno, &csp->lo_iblk);
				if (err != DDI_SUCCESS) {
					goto failed2;
				}

				mutex_init(csp->lo_mutex, NULL,
				    MUTEX_DRIVER, csp->lo_iblk);
				cv_init(csp->lo_cv, NULL,
				    CV_DRIVER, NULL);
				csp->unclaimed_count = 0;

				err = ddi_add_intr(csp->ssp->dip, csp->chno,
				    &csp->lo_iblk, NULL,
				    bscbus_hwintr, (caddr_t)csp);
				if (err != DDI_SUCCESS) {
					cv_destroy(csp->lo_cv);
					mutex_destroy(csp->lo_mutex);
					goto failed2;
				}
			}
		}
		/*
		 * The channel is now live and may
		 * receive interrupts
		 */
	} else if (csp->map_dog != map_dog) {
		bscbus_trace(csp, 'C', "bscbus_claim_channel",
		    "request conflicts with previous mapping. old %x, new %x.",
		    csp->map_dog, map_dog);
		goto failed1;
	}
	mutex_exit(csp->ssp->ch_mutex);
	return (1);

failed2:
	/* unmap regs for failed channel */
	if (csp->ssp->per_channel_regs == B_TRUE) {
		ddi_regs_map_free(&csp->ch_handle);
	}
	csp->ch_handle = NULL;
	csp->ch_regs = (void *)NULL;
failed1:
	csp->map_count--;
	mutex_exit(csp->ssp->ch_mutex);
	return (0);
}

static void
bscbus_release_channel(struct bscbus_channel_state *csp)
{
	mutex_enter(csp->ssp->ch_mutex);
	if (csp->map_count == 1) {
		/* No-one is now using this channel - shutdown channel */
		bscbus_trace(csp, 'C', "bscbus_release_channel",
		    "shutdown channel %d, count %d",
		    csp->chno, csp->map_count);

		if (csp->map_dog == 0) {
			ASSERT(!ddi_intr_hilevel(csp->ssp->dip, csp->chno));
			ddi_remove_intr(csp->ssp->dip, csp->chno, csp->lo_iblk);
		}
		cv_destroy(csp->lo_cv);
		mutex_destroy(csp->lo_mutex);
		mutex_destroy(csp->dog_mutex);
		bscbus_hw_reset(csp);

		/* unmap registers if using the new register scheme */
		if (csp->ssp->per_channel_regs == B_TRUE) {
			ddi_regs_map_free(&csp->ch_handle);
		}
		csp->ch_handle = NULL;
		csp->ch_regs = (void *)NULL;
	}
	csp->map_count--;
	bscbus_trace(csp, 'C', "bscbus_release_channel",
	    "release channel %d, count %d",
	    csp->chno, csp->map_count);
	mutex_exit(csp->ssp->ch_mutex);
}


/*
 *  Nexus routines
 */

#if	defined(NDI_ACC_HDL_V2)

static const ndi_acc_fns_t bscbus_vreg_acc_fns = {
	NDI_ACC_FNS_CURRENT,
	NDI_ACC_FNS_V1,

	bscbus_vreg_get8,
	bscbus_vreg_put8,
	bscbus_vreg_rep_get8,
	bscbus_vreg_rep_put8,

	bscbus_no_get16,
	bscbus_no_put16,
	bscbus_no_rep_get16,
	bscbus_no_rep_put16,

	bscbus_meta_get32,
	bscbus_meta_put32,
	bscbus_meta_rep_get32,
	bscbus_meta_rep_put32,

	bscbus_no_get64,
	bscbus_no_put64,
	bscbus_no_rep_get64,
	bscbus_no_rep_put64,

	bscbus_acc_fault_check
};

static const ndi_acc_fns_t bscbus_pat_acc_fns = {
	NDI_ACC_FNS_CURRENT,
	NDI_ACC_FNS_V1,

	bscbus_pat_get8,
	bscbus_pat_put8,
	bscbus_pat_rep_get8,
	bscbus_pat_rep_put8,

	bscbus_no_get16,
	bscbus_no_put16,
	bscbus_no_rep_get16,
	bscbus_no_rep_put16,

	bscbus_meta_get32,
	bscbus_meta_put32,
	bscbus_meta_rep_get32,
	bscbus_meta_rep_put32,

	bscbus_no_get64,
	bscbus_no_put64,
	bscbus_no_rep_get64,
	bscbus_no_rep_put64,

	bscbus_acc_fault_check
};

static const ndi_acc_fns_t bscbus_event_acc_fns = {
	NDI_ACC_FNS_CURRENT,
	NDI_ACC_FNS_V1,

	bscbus_no_get8,
	bscbus_no_put8,
	bscbus_no_rep_get8,
	bscbus_no_rep_put8,

	bscbus_event_get16,
	bscbus_event_put16,
	bscbus_event_rep_get16,
	bscbus_event_rep_put16,

	bscbus_meta_get32,
	bscbus_meta_put32,
	bscbus_meta_rep_get32,
	bscbus_meta_rep_put32,

	bscbus_no_get64,
	bscbus_no_put64,
	bscbus_no_rep_get64,
	bscbus_no_rep_put64,

	bscbus_acc_fault_check
};

static int
bscbus_map_handle(struct bscbus_channel_state *csp, ddi_map_op_t op,
	int space, caddr_t vaddr, off_t len,
	ndi_acc_handle_t *hdlp, caddr_t *addrp)
{
	switch (op) {
	default:
		return (DDI_ME_UNIMPLEMENTED);

	case DDI_MO_MAP_LOCKED:
		if (bscbus_claim_channel(csp,
		    (space == LOMBUS_PAT_SPACE)) == 0) {
			return (DDI_ME_GENERIC);
		}

		switch (space) {
		default:
			return (DDI_ME_REGSPEC_RANGE);

		case LOMBUS_VREG_SPACE:
			ndi_set_acc_fns(hdlp, &bscbus_vreg_acc_fns);
			break;

		case LOMBUS_PAT_SPACE:
			ndi_set_acc_fns(hdlp, &bscbus_pat_acc_fns);
			break;

		case LOMBUS_EVENT_SPACE:
			ndi_set_acc_fns(hdlp, &bscbus_event_acc_fns);
			break;
		}
		hdlp->ah_addr = *addrp = vaddr;
		hdlp->ah_len = len;
		hdlp->ah_bus_private = csp;
		return (DDI_SUCCESS);

	case DDI_MO_UNMAP:
		*addrp = NULL;
		hdlp->ah_bus_private = NULL;
		bscbus_release_channel(csp);
		return (DDI_SUCCESS);
	}
}

#else

static int
bscbus_map_handle(struct bscbus_channel_state *csp, ddi_map_op_t op,
	int space, caddr_t vaddr, off_t len,
	ddi_acc_hdl_t *hdlp, caddr_t *addrp)
{
	ddi_acc_impl_t *aip = hdlp->ah_platform_private;

	switch (op) {
	default:
		return (DDI_ME_UNIMPLEMENTED);

	case DDI_MO_MAP_LOCKED:
		if (bscbus_claim_channel(csp,
		    (space == LOMBUS_PAT_SPACE)) == 0) {
			return (DDI_ME_GENERIC);
		}

		switch (space) {
		default:
			return (DDI_ME_REGSPEC_RANGE);

		case LOMBUS_VREG_SPACE:
			aip->ahi_get8 = bscbus_vreg_get8;
			aip->ahi_put8 = bscbus_vreg_put8;
			aip->ahi_rep_get8 = bscbus_vreg_rep_get8;
			aip->ahi_rep_put8 = bscbus_vreg_rep_put8;

			aip->ahi_get16 = bscbus_no_get16;
			aip->ahi_put16 = bscbus_no_put16;
			aip->ahi_rep_get16 = bscbus_no_rep_get16;
			aip->ahi_rep_put16 = bscbus_no_rep_put16;

			aip->ahi_get32 = bscbus_meta_get32;
			aip->ahi_put32 = bscbus_meta_put32;
			aip->ahi_rep_get32 = bscbus_meta_rep_get32;
			aip->ahi_rep_put32 = bscbus_meta_rep_put32;

			aip->ahi_get64 = bscbus_no_get64;
			aip->ahi_put64 = bscbus_no_put64;
			aip->ahi_rep_get64 = bscbus_no_rep_get64;
			aip->ahi_rep_put64 = bscbus_no_rep_put64;

			aip->ahi_fault_check = bscbus_acc_fault_check;
			break;

		case LOMBUS_PAT_SPACE:
			aip->ahi_get8 = bscbus_pat_get8;
			aip->ahi_put8 = bscbus_pat_put8;
			aip->ahi_rep_get8 = bscbus_pat_rep_get8;
			aip->ahi_rep_put8 = bscbus_pat_rep_put8;

			aip->ahi_get16 = bscbus_no_get16;
			aip->ahi_put16 = bscbus_no_put16;
			aip->ahi_rep_get16 = bscbus_no_rep_get16;
			aip->ahi_rep_put16 = bscbus_no_rep_put16;

			aip->ahi_get32 = bscbus_meta_get32;
			aip->ahi_put32 = bscbus_meta_put32;
			aip->ahi_rep_get32 = bscbus_meta_rep_get32;
			aip->ahi_rep_put32 = bscbus_meta_rep_put32;

			aip->ahi_get64 = bscbus_no_get64;
			aip->ahi_put64 = bscbus_no_put64;
			aip->ahi_rep_get64 = bscbus_no_rep_get64;
			aip->ahi_rep_put64 = bscbus_no_rep_put64;

			aip->ahi_fault_check = bscbus_acc_fault_check;
			break;

		case LOMBUS_EVENT_SPACE:
			aip->ahi_get8 = bscbus_no_get8;
			aip->ahi_put8 = bscbus_no_put8;
			aip->ahi_rep_get8 = bscbus_no_rep_get8;
			aip->ahi_rep_put8 = bscbus_no_rep_put8;

			aip->ahi_get16 = bscbus_event_get16;
			aip->ahi_put16 = bscbus_event_put16;
			aip->ahi_rep_get16 = bscbus_event_rep_get16;
			aip->ahi_rep_put16 = bscbus_event_rep_put16;

			aip->ahi_get32 = bscbus_meta_get32;
			aip->ahi_put32 = bscbus_meta_put32;
			aip->ahi_rep_get32 = bscbus_meta_rep_get32;
			aip->ahi_rep_put32 = bscbus_meta_rep_put32;

			aip->ahi_get64 = bscbus_no_get64;
			aip->ahi_put64 = bscbus_no_put64;
			aip->ahi_rep_get64 = bscbus_no_rep_get64;
			aip->ahi_rep_put64 = bscbus_no_rep_put64;

			aip->ahi_fault_check = bscbus_acc_fault_check;
			break;
		}
		hdlp->ah_addr = *addrp = vaddr;
		hdlp->ah_len = len;
		hdlp->ah_bus_private = csp;
		return (DDI_SUCCESS);

	case DDI_MO_UNMAP:
		*addrp = NULL;
		hdlp->ah_bus_private = NULL;
		bscbus_release_channel(csp);
		return (DDI_SUCCESS);
	}
}

#endif	/* NDI_ACC_HDL_V2 */

static int
bscbus_map(dev_info_t *dip, dev_info_t *rdip, ddi_map_req_t *mp,
	off_t off, off_t len, caddr_t *addrp)
{
	struct bscbus_child_info *lcip;
	struct bscbus_state *ssp;
	lombus_regspec_t *rsp;

	if ((ssp = bscbus_getstate(dip, -1, "bscbus_map")) == NULL)
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

	return (bscbus_map_handle(
	    &ssp->channel[LOMBUS_SPACE_TO_CHANNEL(rsp->lombus_space)],
	    mp->map_op, LOMBUS_SPACE_TO_REGSET(rsp->lombus_space),
	    VREG_TO_ADDR(rsp->lombus_base+off), len, mp->map_handlep, addrp));
}


static int
bscbus_ctlops(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t op,
	void *arg, void *result)
{
	struct bscbus_child_info *lcip;
	lombus_regspec_t *rsp;
	dev_info_t *cdip;
	char addr[32];
	uint_t nregs;
	uint_t rnum;
	int *regs;
	int limit;
	int err;
	int i;

	if (bscbus_getstate(dip, -1, "bscbus_ctlops") == NULL)
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
		if (err != DDI_PROP_SUCCESS)
			return (DDI_FAILURE);

		err = (nregs <= 0 || (nregs % LOMBUS_REGSPEC_SIZE) != 0);
		nregs /= LOMBUS_REGSPEC_SIZE;
		rsp = (lombus_regspec_t *)regs;
		for (i = 0; i < nregs && !err; ++i) {
			switch (LOMBUS_SPACE_TO_REGSET(rsp[i].lombus_space)) {
			default:
				limit = 0;
				err = 1;
				cmn_err(CE_WARN,
				    "child(%p): unknown reg space %d",
				    (void *)cdip, rsp[i].lombus_space);
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

		cmn_err(CE_CONT, "?BSC device: %s@%s, %s#%d\n",
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
 * This nexus does not support passing interrupts to leaf drivers, so
 * all the intrspec-related operations just fail as cleanly as possible.
 */

/*ARGSUSED*/
static int
bscbus_intr_op(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
#if defined(__sparc)
	return (i_ddi_intr_ops(dip, rdip, op, hdlp, result));
#else
	_NOTE(ARGUNUSED(dip, rdip, op, hdlp, result))
	return (DDI_FAILURE);
#endif
}

/*
 *  Clean up on detach or failure of attach
 */
static int
bscbus_unattach(struct bscbus_state *ssp, int instance)
{
	int chno;

	if (ssp != NULL) {
		for (chno = 0; chno < BSCBUS_MAX_CHANNELS; chno++) {
			ASSERT(ssp->channel[chno].map_count == 0);
		}
		bscbus_offline(ssp);
		ddi_set_driver_private(ssp->dip, NULL);
		mutex_destroy(ssp->ch_mutex);
	}
#ifdef BSCBUS_LOGSTATUS
	if (ssp->cmd_log_size != 0) {
		kmem_free(ssp->cmd_log,
		    ssp->cmd_log_size * sizeof (bsc_cmd_log_t));
	}
#endif /* BSCBUS_LOGSTATUS */


	ddi_soft_state_free(bscbus_statep, instance);
	return (DDI_FAILURE);
}

/*
 *  Autoconfiguration routines
 */

static int
bscbus_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	struct bscbus_state *ssp = NULL;
	int chno;
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
	if (ddi_soft_state_zalloc(bscbus_statep, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);
	if ((ssp = bscbus_getstate(dip, instance, "bscbus_attach")) == NULL)
		return (bscbus_unattach(ssp, instance));
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
	ssp->debug = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "debug", 0);

	mutex_init(ssp->ch_mutex, NULL, MUTEX_DRIVER, NULL);

#ifdef BSCBUS_LOGSTATUS
	ssp->cmd_log_size = bscbus_cmd_log_size;
	if (ssp->cmd_log_size != 0) {
		ssp->cmd_log_idx = 0;
		ssp->cmd_log = kmem_zalloc(ssp->cmd_log_size *
		    sizeof (bsc_cmd_log_t), KM_SLEEP);
	}
#endif /* BSCBUS_LOGSTATUS */

	/*
	 *  Online the hardware ...
	 */
	err = bscbus_online(ssp);
	if (err != 0)
		return (bscbus_unattach(ssp, instance));

	for (chno = 0; chno < BSCBUS_MAX_CHANNELS; chno++) {
		struct bscbus_channel_state *csp = &ssp->channel[chno];

		/*
		 * Initialise state
		 * The hardware/interrupts are setup at map time to
		 * avoid claiming hardware that OBP is using
		 */
		csp->ssp = ssp;
		csp->chno = chno;
		csp->map_count = 0;
		csp->map_dog = B_FALSE;
	}

	/*
	 *  All done, report success
	 */
	ddi_report_dev(dip);
	return (DDI_SUCCESS);
}

static int
bscbus_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	struct bscbus_state *ssp;
	int instance;

	switch (cmd) {
	default:
		return (DDI_FAILURE);

	case DDI_DETACH:
		break;
	}

	instance = ddi_get_instance(dip);
	if ((ssp = bscbus_getstate(dip, instance, "bscbus_detach")) == NULL)
		return (DDI_FAILURE);	/* this "can't happen" */

	(void) bscbus_unattach(ssp, instance);
	return (DDI_SUCCESS);
}

static int
bscbus_reset(dev_info_t *dip, ddi_reset_cmd_t cmd)
{
	struct bscbus_state *ssp;
	int chno;

	_NOTE(ARGUNUSED(cmd))

	if ((ssp = bscbus_getstate(dip, -1, "bscbus_reset")) == NULL)
		return (DDI_FAILURE);

	for (chno = 0; chno < BSCBUS_MAX_CHANNELS; chno++) {
		bscbus_hw_reset(&ssp->channel[chno]);
	}
	return (DDI_SUCCESS);
}


/*
 * System interface structures
 */

static struct cb_ops bscbus_cb_ops =
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

static struct bus_ops bscbus_bus_ops =
{
	BUSO_REV,			/* revision		*/
	bscbus_map,			/* bus_map		*/
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
	bscbus_ctlops,			/* generic control	*/
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
	bscbus_intr_op			/* bus_intr_op		*/
};

static struct dev_ops bscbus_dev_ops =
{
	DEVO_REV,
	0,				/* refcount		*/
	ddi_no_info,			/* getinfo		*/
	nulldev,			/* identify		*/
	nulldev,			/* probe		*/
	bscbus_attach,			/* attach		*/
	bscbus_detach,			/* detach		*/
	bscbus_reset,			/* reset		*/
	&bscbus_cb_ops,			/* driver operations	*/
	&bscbus_bus_ops,		/* bus operations	*/
	NULL,				/* power		*/
	ddi_quiesce_not_needed,			/* quiesce		*/
};

static struct modldrv modldrv =
{
	&mod_driverops,
	"bscbus driver",
	&bscbus_dev_ops
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

	err = ddi_soft_state_init(&bscbus_statep,
	    sizeof (struct bscbus_state), 0);
	if (err == DDI_SUCCESS)
		if ((err = mod_install(&modlinkage)) != DDI_SUCCESS) {
			ddi_soft_state_fini(&bscbus_statep);
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

	if ((err = mod_remove(&modlinkage)) == DDI_SUCCESS) {
		ddi_soft_state_fini(&bscbus_statep);
		bscbus_major = NOMAJOR;
	}

	return (err);
}

#ifdef BSCBUS_LOGSTATUS
void bscbus_cmd_log(struct bscbus_channel_state *csp, bsc_cmd_stamp_t cat,
    uint8_t status, uint8_t data)
{
	int idx;
	bsc_cmd_log_t *logp;
	struct bscbus_state *ssp;

	if ((csp) == NULL)
		return;
	if ((ssp = (csp)->ssp) == NULL)
		return;
	if (ssp->cmd_log_size == 0)
		return;
	if ((bscbus_cmd_log_flags & (1 << cat)) == 0)
		return;
	idx = atomic_inc_32_nv(&ssp->cmd_log_idx);
	logp = &ssp->cmd_log[idx % ssp->cmd_log_size];
	logp->bcl_seq = idx;
	logp->bcl_cat = cat;
	logp->bcl_now = gethrtime();
	logp->bcl_chno = csp->chno;
	logp->bcl_cmdstate = csp->cmdstate;
	logp->bcl_status = status;
	logp->bcl_data = data;
}
#endif /* BSCBUS_LOGSTATUS */
