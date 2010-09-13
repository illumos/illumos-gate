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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_RMC_COMM_H
#define	_SYS_RMC_COMM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
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

#define	SIO_FCR_FIFO_EN		0x01
#define	SIO_FCR_RXSR		0x02
#define	SIO_FCR_TXSR		0x04
#define	SIO_FCR_RXFTH0		0x40
#define	SIO_FCR_STD		(SIO_FCR_RXFTH0|SIO_FCR_FIFO_EN)

#define	SIO_LCR_WLS0		0x01
#define	SIO_LCR_WLS1		0x02
#define	SIO_LCR_PEN		0x08
#define	SIO_LCR_EPS		0x10
#define	SIO_LCR_BKSE		0x80
#define	SIO_LCR_8BIT		(SIO_LCR_WLS0|SIO_LCR_WLS1)
#define	SIO_LCR_STD		(SIO_LCR_8BIT)
#define	SIO_BSR_BANK0		(SIO_LCR_STD)
#define	SIO_BSR_BANK1		(SIO_LCR_BKSE|SIO_LCR_STD)

#define	SIO_MCR_ISEN		0x08
#define	SIO_MCR_STD		(SIO_MCR_ISEN)

/* Line Status Register */
#define	SIO_LSR_RXDA		0x01	/* data ready */
#define	SIO_LSR_OVRRUN		0x02	/* overrun error */
#define	SIO_LSR_PARERR		0x04	/* parity error */
#define	SIO_LSR_FRMERR		0x08	/* framing error */
#define	SIO_LSR_BRKDET		0x10	/* a break has arrived */
#define	SIO_LSR_XHRE		0x20	/* tx hold reg is now empty */
#define	SIO_LSR_XSRE		0x40	/* tx shift reg is now empty */
#define	SIO_LSR_RFBE		0x80	/* rx FIFO Buffer error */

/*
 * Min/max/default baud rates, and a macro to convert from a baud
 * rate to the number (divisor) to put in the baud rate registers
 */
#define	SIO_BAUD_MIN		50
#define	SIO_BAUD_MAX		115200
#define	SIO_BAUD_DEFAULT	115200
#define	SIO_BAUD_TO_DIVISOR(b)	(115200 / (b))
#define	SIO_BAUD_DIVISOR_MIN	1
#define	SIO_BAUD_DIVISOR_MAX	64

/*
 * serial rx buffer size: set to maximum message size + 'bits'
 * (protocol overhead)
 */

#define	SIO_MAX_RXBUF_SIZE	(DP_MAX_MSGLEN + 128)

/*
 * protocol status struct
 */

typedef struct rmc_comm_serdev_state {

	ddi_acc_handle_t sio_handle;
	uint8_t *sio_regs;
	ddi_softintr_t softid;
	ddi_periodic_t cycid; /* periodical callback */

	/*
	 * Hardware mutex (initialised using <hw_iblk>),
	 * used to prevent retriggering the softint while
	 * it's still fetching data out of the chip FIFO.
	 */
	kmutex_t hw_mutex[1];
	ddi_iblock_cookie_t hw_iblk;
	boolean_t hw_int_enabled;

	/*
	 * Flag to indicate that we've incurred a hardware fault on
	 * accesses to the SIO; once this is set, we fake all further
	 * accesses in order not to provoke additional bus errors.
	 */
	boolean_t sio_fault;

	/*
	 * serial device receive buffer
	 */
	char serdev_rx_buf[SIO_MAX_RXBUF_SIZE];
	uint16_t serdev_rx_count;

} rmc_comm_serdev_state_t;

/*
 * This driver's soft-state structure
 */
struct rmc_comm_state {
	/*
	 * Configuration data, set during attach
	 */
	dev_info_t *dip;
	major_t majornum;
	int instance;
	int n_registrations;
	boolean_t is_attached;

	/*
	 * Parameters derived from .conf properties
	 */
	int baud;
	uint32_t debug;
	int baud_divisor_factor;

	/*
	 * serial device status...
	 */
	rmc_comm_serdev_state_t sd_state;

	/*
	 * protocol status struct
	 */
	rmc_comm_dp_state_t dp_state;

	/*
	 * driver interface status struct
	 */
	rmc_comm_drvintf_state_t drvi_state;
};


/*
 * Time periods, in nanoseconds
 */
#define	RMC_COMM_ONE_SEC	1000000000LL

/*
 * debugging
 */

#define	DSER	0x01	/* serial device */
#define	DPRO	0x02	/* protocol */
#define	DAPI	0x04	/* API */
#define	DPKT	0x08	/* packet handling routine */
#define	DGEN	0x10	/* generic */
#define	DDSC	0x20	/* datascope */
#define	DMEM	0x40	/* memory alloc/release */

#ifdef  DEBUG
#define	DPRINTF(rcs, d, ARGLIST)	{ if (rcs->debug & d) cmn_err ARGLIST; }
#define	DATASCOPE(rcs, c, b, l)	{ int i, j; char s[80]; \
				s[0] = (c); \
				s[1] = '\0'; \
				for (i = 1; i < (l)+1; i++) { \
					j = strlen(s); \
					(void) sprintf(s+j, "%02x ", \
						(uchar_t)b[i-1]); \
					if (i%24 == 0) { \
						DPRINTF(rcs, DDSC, \
							(CE_CONT, "%s\n", s)); \
						s[0] = (c); \
						s[1] = '\0'; \
					} \
				} \
				if (i%24 != 0) \
					DPRINTF(rcs, DDSC, \
							(CE_CONT, "%s\n", s)); \
				}
#else
#define	DPRINTF(rcs, d, ARGLIST)
#define	DATASCOPE(rcs, c, b, l)
#endif  /* DEBUG */


/*
 * function prototypes
 */

int rmc_comm_serdev_init(struct rmc_comm_state *, dev_info_t *);
void rmc_comm_serdev_fini(struct rmc_comm_state *, dev_info_t *);
void rmc_comm_serdev_receive(struct rmc_comm_state *);
void rmc_comm_serdev_send(struct rmc_comm_state *, char *, int);
void rmc_comm_serdev_drain(struct rmc_comm_state *);
struct rmc_comm_state *rmc_comm_getstate(dev_info_t *, int, const char *);
int rmc_comm_register(void);
void rmc_comm_unregister(void);

void rmc_comm_dp_init(struct rmc_comm_state *);
void rmc_comm_dp_fini(struct rmc_comm_state *);
void rmc_comm_dp_drecv(struct rmc_comm_state *, uint8_t *, int);
void rmc_comm_dp_mrecv(struct rmc_comm_state *, uint8_t *);
int rmc_comm_dp_msend(struct rmc_comm_state *, dp_message_t *);
void rmc_comm_bp_msend(struct rmc_comm_state *, bp_msg_t *);
void rmc_comm_bp_srecsend(struct rmc_comm_state *, char *, int);
int rmc_comm_dp_ctlsend(struct rmc_comm_state *, uint8_t);
void rmc_comm_dp_mcleanup(struct rmc_comm_state *);

int rmc_comm_drvintf_init(struct rmc_comm_state *);
void rmc_comm_drvintf_fini(struct rmc_comm_state *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RMC_COMM_H */
