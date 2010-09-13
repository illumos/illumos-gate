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
 * Copyright (c) 1990,1991,1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SYS_BPP_IO_H
#define	_SYS_BPP_IO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	I/O header file for the bidirectional parallel port
 *	driver (bpp) for the Zebra SBus card.
 */

#include <sys/ioccom.h>

#ifdef __cplusplus
extern "C" {
#endif

/*	#defines (not struct elements) below */

/*
 * Minor device number encoding (should not be here):
 */
#define	BPP_UNIT(dev)	getminor(*dev)

/*
 * ioctl defines for cmd argument
 */
	/* set contents of transfer parms structure	*/
#define	BPPIOC_SETPARMS		_IOW('b', 1, struct bpp_transfer_parms)
	/* read contents of transfer parms structure	*/
#define	BPPIOC_GETPARMS		_IOR('b', 2, struct bpp_transfer_parms)
	/* set contents of output pins structure	*/
#define	BPPIOC_SETOUTPINS	_IOW('b', 3, struct bpp_pins)
	/* read contents of output pins structure	*/
#define	BPPIOC_GETOUTPINS	_IOR('b', 4, struct bpp_pins)
	/* read contents of snapshot error status structure	*/
#define	BPPIOC_GETERR		_IOR('b', 5, struct bpp_error_status)
	/* pretend to attempt a data transfer	*/
#define	BPPIOC_TESTIO		_IO('b', 6)
/* ioctl values 7-12 are test-only and are reserved */


/*	Structure definitions and locals #defines below */

#define	MAX_TIMEOUT	1800000		/* maximum read/write timeout	*/
					/* 30 minutes			*/
/*
 * #defines and enum variables, and general comments for the
 * bpp_transfer_parms structure.
 */

/* Values for read_handshake and write_handshake fields */
enum	handshake_t {
	BPP_NO_HS = 1,		/* no handshake pins */
	BPP_ACK_HS = 2,		/* handshake controlled by ACK line */
	BPP_BUSY_HS = 3,	/* handshake controlled by BSY line */
	BPP_ACK_BUSY_HS = 4,	/* handshake controlled by ACK and BSY lines */
				/* read_handshake only! */
	BPP_XSCAN_HS = 5,	/* xerox scanner mode, read_handshake only! */
	BPP_HSCAN_HS = 6,	/* HP scanjet scanner mode */
				/* read_handshake only! */
	BPP_CLEAR_MEM = 7,	/* write 0's to memory, read_handshake only! */
	BPP_SET_MEM = 8,	/* write 1's to memory, read_handshake only! */
	/* The following handshakes are RESERVED. Do not use. */
	BPP_VPRINT_HS = 9,	/* valid only in read/write mode */
	BPP_VPLOT_HS = 10	/* valid only in read/write mode */
};

/*
 * The read_setup_time field indicates
 * dstrb- to bsy+ in BPP_HS_NOHS or BPP_HS_ACKHS
 * dstrb- to ack+ in BPP_HS_ACKHS or BPP_HS_ACKBUSYHS
 * ack- to dstrb+ in BPP_HS_XSCANHS
 *
 * The read_strobe_width field indicates
 * ack+ to ack- in BPP_HS_ACKHS or BPP_HS_ACKBUSYHS
 * dstrb+ to dstrb- in BPP_HS_XSCANHS
 */

/* Values allowed for write_handshake field */
/*
 * these are duplicates of the definitions above
 *	BPP_HS_NOHS
 *	BPP_HS_ACKHS
 *	BPP_HS_BUSYHS
 */

/*
 * The write_setup_time field indicates
 * data valid to dstrb+ in all handshakes
 *
 * The write_strobe_width field indicates
 * dstrb+ to dstrb- in non-reserved handshakes
 * minimum dstrb+ to dstrb- in BPP_HS_VPRINTHS or BPP_HS_VPLOTHS
 */


/*
 * This structure is used to configure the hardware handshake and
 * timing modes.
 */
struct bpp_transfer_parms {
	enum	handshake_t
		read_handshake;		/* parallel port read handshake mode */
	int	read_setup_time;	/* DSS register - in nanoseconds */
	int	read_strobe_width;	/* DSW register - in nanoseconds */
	int	read_timeout;		/* wait this many microseconds */
					/* before aborting a transfer */
	enum	handshake_t
		write_handshake;	/* parallel port write handshake mode */
	int	write_setup_time;	/* DSS register - in nanoseconds */
	int	write_strobe_width;	/* DSW register - in nanoseconds */
	int	write_timeout;		/* wait this many microseconds */
					/* before aborting a transfer */
};

struct bpp_pins {
	uchar_t	output_reg_pins;	/* pins in P_OR register */
	uchar_t	input_reg_pins;		/* pins in P_IR register */
};


/*
 * #defines and general comments for
 * the bpp_pins structure.
 */
/* Values for output_reg_pins field */
#define	BPP_SLCTIN_PIN		0x01	/* Select in pin		*/
#define	BPP_AFX_PIN		0x02	/* Auto feed pin		*/
#define	BPP_INIT_PIN		0x04	/* Initialize pin		*/
#define	BPP_V1_PIN		0x08	/* reserved pin 1		*/
#define	BPP_V2_PIN		0x10	/* reserved pin 2		*/
#define	BPP_V3_PIN		0x20	/* reserved pin 3		*/

#define	BPP_ALL_OUT_PINS	(BPP_SLCTIN_PIN | BPP_AFX_PIN | BPP_INIT_PIN |\
				BPP_V1_PIN | BPP_V2_PIN | BPP_V3_PIN)

/* Values for input_reg_pins field */
#define	BPP_ERR_PIN		0x01	/* Error pin			*/
#define	BPP_SLCT_PIN		0x02	/* Select pin			*/
#define	BPP_PE_PIN		0x04	/* Paper empty pin		*/

#define	BPP_ALL_IN_PINS		(BPP_ERR_PIN | BPP_SLCT_PIN | BPP_PE_PIN)

struct	bpp_error_status {
	char	timeout_occurred;	/* 1 if a timeout occurred	*/
	char	bus_error;		/* 1 if an SBus bus error	*/
	uchar_t	pin_status;		/* status of pins which could */
					/* cause an error */
};

/*
 * #defines for the bpp_error_status structure
 */
/* Values for pin_status field */
#define	BPP_ERR_ERR		0x01	/* Error pin active		*/
#define	BPP_SLCT_ERR		0x02	/* Select pin active		*/
#define	BPP_PE_ERR		0x04	/* Paper empty pin active	*/
#define	BPP_SLCTIN_ERR		0x10	/* Select in pin active		*/
#define	BPP_BUSY_ERR		0x40	/* Busy pin active		*/

#ifdef __cplusplus
}
#endif

#endif /* !_SYS_BPP_IO_H */
