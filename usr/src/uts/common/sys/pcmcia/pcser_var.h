/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1999,2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PCSER_VAR_H
#define	_PCSER_VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	PCSER_DEBUG_LOWMASK	0x0000000ff
#define	PCSER_DEBUG_DEFAULT	0x000000100
#define	PCSER_DEBUG_POLL	0x000000200
#define	PCSER_DEBUG_XMIT	0x000000400
#define	PCSER_DEBUG_RCV		0x000000800
#define	PCSER_DEBUG_MODEM	0x000001000
#define	PCSER_DEBUG_RCVEX	0x000002000
#define	PCSER_DEBUG_CIS		0x000004000
#define	PCSER_DEBUG_CIS_SCFT	0x000008000	/* sorted cftable */
#define	PCSER_DEBUG_CIS_UCFT	0x000010000	/* unsorted cftable */
#define	PCSER_DEBUG_RTSCTS	0x000020000
#define	PCSER_DEBUG_DRAINSILO	0x000040000
#define	PCSER_DEBUG_PARAM	0x000080000
#define	PCSER_DEBUG_READY	0x000100000
#define	PCSER_DEBUG_MANUSPEC	0x000200000
#define	PCSER_DEBUG_READY_DELAY	0x000400000
#define	PCSER_DEBUG_CISVARS	0x000800000
#define	PCSER_DEBUG_SOFTINT	0x001000000

/* #define	DEBUG_PCSERIOCTL */

/*
 * Values for CS_EVENT_CLIENT_INFO event handler
 */
#define	PCSER_CLIENT_DESCRIPTION	"PCMCIA serial/modem card driver"
#define	PCSER_VENDOR_DESCRIPTION	CS_SUN_VENDOR_DESCRIPTION
#define	PCSER_REV_LEVEL			0x100
#define	PCSER_REV_DAY			31
#define	PCSER_REV_MONTH			3
#define	PCSER_REV_YEAR			16
#define	PCSER_REV_DATE			CS_CLIENT_INFO_MAKE_DATE(	\
						PCSER_REV_DAY,		\
						PCSER_REV_MONTH,	\
						PCSER_REV_YEAR)

/*
 * Private data structures for PCMCIA async serial communications cards
 *	and modems using the 8250-type UART.
 *
 * various device things
 */
#define	PCSER_NAME			"pcser"	/* driver name */
#define	PCSER_SOCKET(dev)		(getminor(dev) & 0x3f)
#define	PCSER_OUTLINE(dev)		(getminor(dev) & 0x80)
#define	PCSER_CONTROL_LINE(dev)		(getminor(dev) & 0x40)
#define	N_PCSER			2	/* hint to ddi_soft_state_init() */
#define	USE_CCSR(L)			(L->cis_vars.present & \
						CONFIG_STATUS_REG_PRESENT)
#define	MAX_TX_BUF_SIZE			64

#define	PCSER_HIMUTEX_ENTER(pcser)	{mutex_enter(&(pcser)->event_hilock);\
					mutex_enter((pcser)->pcser_mutex); }
#define	PCSER_HIMUTEX_EXIT(pcser)	{mutex_exit((pcser)->pcser_mutex);   \
					mutex_exit(&(pcser)->event_hilock); }

#ifdef	CBAUDEXT
#define	PCSER_DUALHW_FLOW		"pcser_use_dualflow"
#endif
#ifndef	CBAUDEXT
#define	PCSER_HIGHSPEED_PROP		"pcser_use_hispeed"
#endif

/*
 * These macros return device minor numbers given a socket number.
 */
#define	PCSER_DINODE(skt)	(skt & 0x3f)		/* dial-in */
#define	PCSER_DONODE(skt)	((skt & 0x3f) | 0x80)	/* dial-out */
#define	PCSER_CTLNODE(skt)	((skt & 0x3f) | 0x40)	/* control */

/*
 * The driver uses a two-level interrupt scheme; the hardware interrupts
 *	at a high level, and the driver schedules a softint on a lower
 *	level to deal with the STREAMS processing.
 */
#define	PCSER_SOFT_PREF	DDI_SOFTINT_MED	/* soft interrupt level */

/*
 * some general sizing and enumeration constants
 * the silo sizes are the same for both the cd180 and the ppc, and are
 *	located in pcserio.h as PCSER_SILOSIZE
 * the TXBUF sizes determine how many characters pcser_start() will try to
 *	stuff into the soft tx buffers in the line struct.  you should leave
 *	PCSER_TXBUFSIZE at 8 since the interrupt handler for the cd180 doesn't
 *	know what to do if it gets larger.
 * PPC_TXBUFSIZE is made a little larger since the ppc interrupt handler
 *	is smart enough to take data from the soft tx buffer if there is any
 *	both PCSER_TXBUFSIZE and PPC_TXBUFSIZE must be <= to LINE_TXBUFSIZE
 */
/* when to disable RTS if we're using CTS/RTS flow control */
#define	PCSER_HIWATER		960
/* when to enable RTS if we're using CTS/RTS flow control */
#define	PCSER_LOWWATER		300
/* default STREAMS buffer size in pcser_drainsilo() */
#define	PCSER_DRAIN_BSIZE	16

/*
 * If CRTSXOFF is not defined, then we're probably being built on
 *	a pre-2.5 kernel, so alias CRTSXOFF to CRTSCTS. This will
 *	cause the driver to treat CRTSCTS as a bidirectional flow
 *	control enable bit rather than a unidirectional flow control
 *	enable bit as it is in 2.5 and above.
 */
#ifndef	CRTSXOFF
#define	CRTSXOFF	CRTSCTS
#endif

/*
 * The number of unidentified IRQ's that we allow before we
 *	shut down the card.
 */
#define	PCSER_UNID_IRQ_MAX	10	/* max unknown IRQs */

/*
 * The number of different possible line speeds (not all of which
 *	may be supported)
 */
#define	PCSER_MAX_SPEEDS	23	/* max baud rates we support */

/*
 * timeout and timing parameters
 *
 * serial lines
 *	NQFRETRY and QFRETRYTIME are used in pcser_drainsilo()
 */
#define	MS2HZ(time)		drv_usectohz(time * 1000)
/* CSTYLED */
#define	PCSER_TIMEOUT		(MS2HZ(15000))	/* ctrl lines in close */
/* CSTYLED */
#define	PCSER_IGNORE_CD_TIMEOUT	3000		/* ignore CD in mS */
/* CSTYLED */
#define	NQFRETRY		26		/* put tries to receive q */
/* CSTYLED */
#define	QFRETRYTIME		(MS2HZ(  100))	/* queue retry */
/* CSTYLED */
#define	BREAK1_TIMEOUT		(MS2HZ(   90))	/*  90mS pre-BREAK */
/* CSTYLED */
#define	BREAK2_TIMEOUT		(MS2HZ(  350))	/* 350mS BREAK */
/* CSTYLED */
#define	DRAIN_TIMEOUT		(MS2HZ(   10))	/*  10mS DRAIN */
/* CSTYLED */
#define	PCSER_READY_TIMEOUT	(MS2HZ( 6000))	/* card ready */
/* CSTYLED */
#define	PCSER_READYWAIT_TIMEOUT	(MS2HZ(20000))	/* wait for ready in attach */
/* CSTYLED */
#define	PCSER_DTR_DROP_DELAY	(MS2HZ(  200))	/* delay around DTR drop */

/*
 * The next two items are used in pcser_card_insertion() to handle
 *	cards that require a delay after resetting and after
 *	configuring the card.
 *
 * PCSER_INSERT_READY_TMO1 - time to wait between checking READY before
 *	doing a RequestConfiguration
 * PCSER_INSERT_READY_TMO2 - time to wait between checking READY after
 *	doing a RequestConfiguration
 */
/* CSTYLED */
#define	PCSER_INSERT_READY_TMO1	(MS2HZ(20))	/* ready wait in card_insert */
#define	PCSER_INSERT_READY_TMO2	(MS2HZ(200))	/* ready wait in card_insert */
#define	PCSER_INSERT_READY_CNT	5		/* max times to try */

/*
 * UNTIMEOUT() macro to make sure we're not trying untimeout a bogus timeout
 */
#define	UNTIMEOUT(utt) {		\
	if (utt) {			\
	    (void) untimeout(utt);	\
	    utt = 0;			\
	}				\
}

/*
 * XXX card present macro
 */
#define	CARD_PRESENT(pm)	((pm)->card_state & PCSER_CARD_INSERTED)

#define	CARD_INSERT_CHECK(pm)		\
	((pm)->card_state & (PCSER_CARD_INSERTED | PCSER_READY_ERR))

/*
 * user-level audio control - note that we overload the TIOCMBIS and
 *	TIOCMBIC ioctls by using the TIOCM_SR bit to control
 *	the audio signal from the modem to the system speaker XXX
 */
#define	TIOCM_AUDIO	TIOCM_SR
#define	AUDIO_GET(L)	(((L->saved_state) & PCSER_AUDIO_ON)?1:0)

/*
 * for modem_init()
 */
#define	MODEM_SET_AUDIO_ON	1	/* enable card audio */
#define	MODEM_SET_AUDIO_OFF	2	/* disable card audio */
#define	MODEM_FIFO_FLUSH	3	/* flush Tx and Rx FIFOs */

/*
 * UART defines
 */

/*
 * IIR - interrupt identification register
 */
#define	IIR_MASK	0x007	/* the only bits of interest */
#define	MODEM_CHANGE	0x000
#define	XMIT_DATA	0x002
#define	RCV_DATA	0x004
#define	RCV_EXP		0x006
#define	IIR_PENDING	0x001	/* note: 0 == pending!! */

/*
 * IER - interrupt enable register
 */
#define	RX_DATA_E	0x001	/* receive data */
#define	TX_READY_E	0x002	/* transmitter empty */
#define	TX_EMPTY_E	0x002	/* transmitter empty */
#define	RX_EXCEPTION_E	0x004	/* receive exception (line status) */
#define	MODEM_CHANGE_E	0x008	/* modem lines changed state */

/*
 * LSR - line status register
 */
#define	RX_DATA_AVAIL	0x001	/* char available */
#define	RX_OVERRUN	0x002	/* overrun error */
#define	RX_PARITY	0x004	/* parity error */
#define	RX_FRAMING	0x008	/* framing error */
#define	RX_BREAK	0x010	/* BREAK detected */
#define	TX_THR_EMPTY	0x020	/* THR empty */
#define	TX_SHIFT_EMPTY	0x040	/* Tx shift register empty */

/*
 * MCR - modem control register
 */
#define	DTR_ON_MCR	0x001
#define	RTS_ON_MCR	0x002
#define	OUT1_ON_MCR	0x004
#define	OUT2_ON_MCR	0x008
#define	LOOP_ON_MCR	0x010

/*
 * MSR - modem status register
 */
#define	CTS_CHANGE	0x001
#define	DSR_CHANGE	0x002
#define	RI_CHANGE	0x004
#define	CD_CHANGE	0x008
#define	CTS_ON_MSR	0x010
#define	DSR_ON_MSR	0x020
#define	RI_ON_MSR	0x040
#define	CD_ON_MSR	0x080

/*
 * LCR - line control register
 */
#define	CHAR_5		0x00
#define	CHAR_6		0x01
#define	CHAR_7		0x02
#define	CHAR_8		0x03

#define	STOP_1		0x00
#define	STOP_15		0x04
#define	STOP_2		0x04

#define	USE_P		0x08
#define	ODD_P		0x00
#define	EVEN_P		0x10

#define	MARK_P		0x00
#define	SPACE_P		0x20

#define	IGNORE_P	0x000	/* XXX ?? */

#define	SET_BREAK	0x040
#define	DLAB		0x080

/*
 * DTR latch values
 */
#define	DTR_OFF_SHADOW	0x000	/* drop DTR */
#define	DTR_ON_SHADOW	0x001	/* assert DTR */

/*
 * macros to get/set the shadow state of the line's DTR pin
 */
#define	DTR_GET(L)	(((L->dtr_shadow)&DTR_ON_SHADOW)?1:0)
#define	DTR_SET(L, S)	(L->dtr_shadow = S)

/*
 * define driver defaults for all the serial lines; these can be manipulated
 * via the PCSER_SDEFAULTS/PCSER_GDEFAULTS ioctl()'s; see "pcserio.h"
 */
/* assert DTR on open, use zs DTR semantics on close */
#define	SDFLAGS		DTR_ASSERT
#define	CFLAGS		(CS8|CREAD|HUPCL)	/* UNIX line flags in t_cflag */
#define	RX_BAUD		B9600	/* default receiver baud rate */
#define	TX_BAUD		B9600	/* default transmitter baud rate */

/*
 * all the bytes we get from the modem get put into a soft silo before being
 *	handed off to STREAMS; the following macros handle the RTS line if
 *	we're using CTS/RTS flow control:
 * CHECK_RTS_OFF(line) should be called by the Rx interrupt handler for
 *	each character put into the soft silo; if the soft silo nears
 *	full, RTS will be deasserted
 * CHECK_RTS_ON(line) should be called by the soft interrupt soft silo
 *	drain code; once the soft silo level has gone below the low
 *	water mark, RTS will be asserted
 * FLUSHSILO(line) is used to flush the silo in case there's an error
 * PUTSILO(line,char) puts a character into the soft silo and calls
 *	CHECK_RTS_OFF(line) to see if RTS should be deasserted
 */
#ifdef	USE_MACRO_RTSCTS
#define	CHECK_RTS_OFF(line) {					\
	if (line->pcser_ttycommon.t_cflag & CRTSXOFF) {		\
	    if (line->pcser_sscnt > line->pcser_hiwater)	\
		OUTB(&line->regs->mcr,				\
		    (INB(&line->regs->mcr) & ~RTS_ON_MCR));	\
	}							\
}
#define	CHECK_RTS_ON(line) {					\
	if (line->pcser_ttycommon.t_cflag & CRTSXOFF) {		\
	    if (line->pcser_sscnt < line->pcser_lowwater)	\
		OUTB(&line->regs->mcr,				\
		    (INB(&line->regs->mcr) | RTS_ON_MCR));	\
	}							\
}
#endif	/* USE_MACRO_RTSCTS */

#ifdef	PX_IFLUSH_DEBUG

#define	FLUSHSILO(zline) { \
	cmn_err(CE_CONT, "pcser_FLUSHSILO: socket %d flushing soft silo\n", \
						(int)zline->pcser->sn); \
	zline->pcser_source = zline->pcser_sink = zline->pcser_ssilo; \
	zline->pcser_sscnt = 0; \
}

#else

#define	FLUSHSILO(line) { \
	line->pcser_source = line->pcser_sink = line->pcser_ssilo; \
	line->pcser_sscnt = 0; \
}

#endif	/* PX_IFLUSH_DEBUG */

#define	PUTSILO(zline, c) { \
	if (zline->pcser_sscnt < PCSER_SILOSIZE) { \
	    zline->pcser_sscnt++;\
	    if (zline->pcser_source == &zline->pcser_ssilo[PCSER_SILOSIZE]) \
		zline->pcser_source = zline->pcser_ssilo;\
	    *zline->pcser_source++ = c; \
	    CHECK_RTS_OFF(zline); \
	} else { \
	    FLUSHSILO(zline); \
	    CHECK_RTS_ON(zline);	\
	    cmn_err(CE_CONT, "pcser: socket %d soft silo overflow\n", \
						(int)zline->pcser->sn); \
	} \
}

/*
 * pcser_cftable_t and pcser_cftable_params_t structures are used
 *	to store values from the CISTPL_CFTABLE_ENTRY tuples.
 */
typedef struct pcser_cftable_params_t {
	uchar_t		config_index;
	uint32_t	addr_lines;	/* IO addr lines decoded */
	uint32_t	length;		/* length of IO range */
	uint32_t	pin;		/* PRR bits valid mask */
	unsigned	modem_vcc;
	unsigned	modem_vpp1;
	unsigned	modem_vpp2;
	uint32_t	modem_base;	/* base of UART registers */
} pcser_cftable_params_t;

typedef struct pcser_cftable_t {
	uint32_t		desireability;	/* desireability factor */
	pcser_cftable_params_t	p;		/* parameters */
	struct pcser_cftable_t	*prev;
	struct pcser_cftable_t	*next;
} pcser_cftable_t;

/*
 * pcser_cis_vars_t structure used to save interesting information
 *	gleaned from the CIS.
 * The configuration registers present flags are defined in the Card
 *	Services header files.
 */
typedef struct pcser_cis_vars_t {
	uint32_t	flags;		/* general capability flags */
	uint32_t	present;	/* config register present flags */
	char		prod_strings[CISTPL_VERS_1_MAX_PROD_STRINGS]
					    [CIS_MAX_TUPLE_DATA_LEN];
	uint32_t	major_revision;	/* card major revision level */
	uint32_t	minor_revision;	/* card minor revision level */
	uint32_t	manufacturer_id;	/* manufacturer ID */
	uint32_t	card_id;	/* card ID */
	uint32_t	config_base;	/* base offset of config registers */
	/* resource configuration */
	uchar_t		config_index;
	uint32_t	addr_lines;	/* IO addr lines decoded */
	uint32_t	length;		/* length of IO range */
	uint32_t	pin;		/* PRR bits valid mask */
	unsigned	modem_vcc;
	unsigned	modem_vpp1;
	unsigned	modem_vpp2;
	uint32_t	modem_base;	/* base of UART registers */
	/* UART features */
	uint32_t	txbufsize;	/* Tx FIFO buffer size */
	uint32_t	rxbufsize;	/* Rx FIFO buffer size */
	uchar_t		fifo_enable;	/* Tx/Rx FIFO enable code */
	uchar_t		fifo_disable;	/* Tx/Rx FIFO disable code */
	uchar_t		auto_rts;	/* Auto RTS enable code */
	uchar_t		auto_cts;	/* Auto CTS enable code */
	uint32_t	ready_delay_1;	/* READY delay before config in mS */
	uint32_t	ready_delay_2;	/* READY delay after config in mS */
	pcser_cftable_t	cftable;	/* active CFTABLE_ENTRY values */
} pcser_cis_vars_t;

/*
 * Flgas for pcser_cis_vars_t.flags field
 */
#define	PCSER_FIFO_ENABLE	0x00000001	/* fifo_enable code OK */
#define	PCSER_FIFO_DISABLE	0x00000002	/* fifo_disable code OK */
#define	PCSER_AUTO_RTS		0x00000004	/* auto_rts enable code OK */
#define	PCSER_AUTO_CTS		0x00000008	/* auto_cts enable code OK */

/*
 * Per line structure
 * there is one of these for each serial line plus one more for
 * the ppc.
 */
typedef struct pcser_line_t {
	/* stuff common to both the cd180 and the ppc */
	unsigned		state;		/* various state flags */
	unsigned		flags;		/* default mode flags */
	unsigned		saved_state;	/* saved over open/close */
	acc_handle_t		handle;		/* modem registers handle */
	pcser_cis_vars_t	cis_vars;
	timeout_id_t		pcser_timeout_id;	/* timeout id */
	timeout_id_t		pcser_draintimeout_id;	/* timeout id */
	timeout_id_t		ignore_cd_timeout_id;	/* timeout id */
	timeout_id_t		restart_timeout_id;	/* timeout id */
	int			pcser_ignore_cd_time;	/* ignore CD in mS */
	struct pcser_unit_t	*pcser;
	kcondvar_t		cvp;
	kmutex_t		line_mutex;
	uchar_t			dtr_shadow;	/* shadow of DTR latch */
	uchar_t			pcser_flowc;	/* flow control character */
	int			pcser_max_txbufsize;	/* soft Tx buf size */
	int			pcser_txbufsize;	/* soft Tx buf size */
	int			pcser_rxfifo_size;	/* size of Rx FIFO */
	uchar_t			*pcser_txbuf;	/* soft tx buffer */
	int			pcser_txcount;	/* num chars in pcser_txbuf */
	int			pcser_silosize;	/* size of rx silo */
	int			pcser_sscnt;	/* silo count */
	uchar_t			*pcser_source;	/* silo source */
	uchar_t			*pcser_sink;	/* silo sink */
	uchar_t			pcser_ssilo[PCSER_SILOSIZE];	/* soft silo */
	int			pcser_qfcnt;	/* queue full retry count */
	bufcall_id_t		pcser_wbufcid;	/* write-side bufcall id */
	/* stuff that affects  the reception of data */
	int			drain_size;	/* buf size pcser_drainsilo */
	int			pcser_hiwater;	/* high water mark CHECK_RTS */
	int			pcser_lowwater;	/* low water mark CHECK_RTS */
	int			rx_fifo_thld;	/* cd-180 RxFIFO threshold */
	struct	pcser_stats_t	pcser_stats;	/* support PCSER_GSTATS ioctl */
	tty_common_t		pcser_ttycommon;	/* common tty stuff */
} pcser_line_t;

/*
 * flags in pcser_line_t.state field
 */
#define	PCSER_WOPEN		0x00000001	/* wait for open to complete */
#define	PCSER_ISOPEN		0x00000002	/* open is complete */
#define	PCSER_OUT		0x00000004	/* line used for dialout */
#define	PCSER_CARR_ON		0x00000008	/* CD on last time we looked */
#define	PCSER_RTSOFF_MESSAGE	0x00000010
#define	PCSER_STOPPED		0x00000020	/* output is stopped */
#define	PCSER_DELAY		0x00000040	/* waiting for delay */
#define	PCSER_BREAK		0x00000080	/* waiting for break */
#define	PCSER_BUSY		0x00000100	/* waiting for transmission */
#define	PCSER_FLUSH		0x00000200	/* flushing Tx output */
#define	PCSER_OPEN_READY	0x00000400	/* ready for IRQs in open */
#define	PCSER_WCLOSE		0x00000800	/* wakeup from close in open */
#define	PCSER_XWAIT		0x00001000	/* waiting for xmtr to drain */
#define	PCSER_IXOFF		0x00002000	/* using s/w Rx flow control */
#define	PCSER_CANWAIT		0x00004000	/* pcser_drainsilo waiting */
#define	PCSER_CONTROL		0x00008000	/* control line */
#define	PCSER_SBREAK		0x00010000	/* start BREAK */
#define	PCSER_EBREAK		0x00020000	/* end BREAK */
#define	PCSER_ISROOT		0x00040000	/* line was root at open */
#define	PCSER_CTSWAIT		0x00080000	/* wait for CTS for next Tx */
/* flags used with pcser_softint() */
#define	PCSER_TXWORK		0x00100000	/* Tx work to do */
#define	PCSER_RXWORK		0x00200000	/* Rx work to do */
#define	PCSER_CVBROADCAST	0x00400000	/* need a cv_broadcast */
#define	PCSER_UNTIMEOUT		0x00800000	/* need an untimeout */
#define	PCSER_MHANGUP		0x01000000	/* send M_HANGUP message */
#define	PCSER_MUNHANGUP		0x02000000	/* send M_UNHANGUP message */
#define	PCSER_MBREAK		0x04000000	/* send M_BREAK message */
#define	PCSER_IGNORE_CD		0x08000000	/* ignore CD transitions */
#define	PCSER_FIRST_OPEN	0x10000000	/* first open since config */
#define	PCSER_INDRAIN		0x20000000	/* in pcser_drainsilo */
#define	PCSER_RTSON_MESSAGE	0x40000000
#define	PCSER_DRAIN		0x80000000	/* pcser_start flushing */

/*
 * flags in pcser_line_t.saved_state field
 */
#define	PCSER_AUDIO_ON		0x00000001	/* audio enabled */

/*
 * flags in pcser_line_t.flags field are in pcser_io.h
 */

/*
 * private flags for pcser_xmit and pcser_modem
 */
#define	PCSER_CALL		0x00000001	/* OK to call routine */
#define	PCSER_DONTCALL		0x00000002	/* don't call routine */

/*
 * Per board (controller) structure
 */
typedef struct pcser_unit_t {
	client_handle_t		client_handle;	/* client handle for socket */
	uint32_t		sn;		/* socket number */
	int			instance;	/* instance number */
	uint32_t		card_state;
	kmutex_t		*pcser_mutex;	/* protects UART registers */
	kmutex_t		irq_mutex;
	kmutex_t		noirq_mutex;
	kmutex_t		event_hilock;	/* protects hi-level events */
	timeout_id_t		ready_timeout_id;
	timeout_id_t		readywait_timeout_id;
	int			unid_irq;	/* unknown IRQ count */
	ddi_iblock_cookie_t	soft_blk_cookie;	/* soft int cookie */
	ddi_softintr_t		softint_id;
	unsigned		flags;
	struct pcser_line_t	line;
	struct pcser_line_t	control_line;
	dev_info_t		*dip;		/* Device dev_info_t */
	kcondvar_t		readywait_cv;
} pcser_unit_t;

/*
 * flags in pcser_unit_t.flags field
 */
#define	PCSER_DIDLOCKS		0x00000001	/* cv/mutex_init in attach */
#define	PCSER_REGCLIENT		0x00000002	/* RegisterClient is OK */
#define	PCSER_REQSOCKMASK	0x00000004	/* RequestSocketMask is OK */
#define	PCSER_SOFTINTROK	0x00000008	/* added to interrupt chain */
#define	PCSER_ATTACHOK		0x00000010	/* pcser_attach is OK */
#define	PCSER_REQUESTIO		0x00000020	/* did RequestIO */
#define	PCSER_REQUESTIRQ	0x00000040	/* did RequestIRQ */
#define	PCSER_REQUESTCONFIG	0x00000080	/* did RequestConfiguration */
#define	PCSER_MAKEDEVICENODE	0x00000100	/* did MakeDeviceNode */
#ifdef	CBAUDEXT
#define	PCSER_USE_DUALFLOW	0x40000000	/* alias CRTSCTS and CRTSXOF */
#endif
#ifndef	CBAUDEXT
#define	PCSER_USE_HIGHSPEED	0x80000000	/* use high baud rates */
#endif

/*
 * flags in pcser_unit_t.card_state field
 */
#define	PCSER_CARD_INSERTED	0x00000001	/* card is here */
#define	PCSER_WAIT_FOR_READY	0x00000002	/* waiting for card ready */
#define	PCSER_CARD_IS_READY	0x00000004	/* card is ready */
#define	PCSER_READY_WAIT	0x00000008	/* waiting for READY */
#define	PCSER_READY_ERR		0x00000010	/* failure to become ready */

/*
 * the state struct for transparent ioctl()s
 */
struct pcser_state_t {
	int	state;
	caddr_t	addr;
};

/*
 * state for transparent ioctl()'s used in pcser_state_t
 */
#define	PCSER_COPYIN	1
#define	PCSER_COPYOUT	2

#ifdef	__cplusplus
}
#endif

#endif	/* _PCSER_VAR_H */
