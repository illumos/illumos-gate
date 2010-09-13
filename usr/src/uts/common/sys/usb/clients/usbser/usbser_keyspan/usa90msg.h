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
 */

#ifndef _SYS_USB_USBSER_KEYSPAN_USA90MSG_H
#define	_SYS_USB_USBSER_KEYSPAN_USA90MSG_H


#ifdef	__cplusplus
extern "C" {
#endif

typedef struct keyspan_usa19hs_port_ctrl_msg keyspan_usa19hs_port_ctrl_msg_t;
typedef struct keyspan_usa19hs_port_status_msg
    keyspan_usa19hs_port_status_msg_t;

/*
 * usa90msg.h
 *
 * Copyright (c) 1998-2003 InnoSys Incorporated.  All Rights Reserved
 *
 * Keyspan USB Async Firmware to run on xxxxx
 *
 *
 * Revisions:
 *
 * 2003feb14		add setTxMode/txMode  and cancelRxXoff to portControl
 *
 */

struct keyspan_usa19hs_port_ctrl_msg {
	/*
	 * there are three types of "commands" sent in the control message:
	 *
	 * configuration changes which must be requested by setting
	 * the corresponding "set" flag (and should only be requested
	 * when necessary, to reduce overhead on the device):
	 */

	uint8_t setClocking;	/* host requests baud rate be set */
	uint8_t baudLo;		/* host does baud divisor calculation */
	uint8_t baudHi;		/* host does baud divisor calculation */

	uint8_t setLcr;		/* host requests lcr be set */
	uint8_t lcr;		/* use PARITY, STOPBITS, DATABITS below */

	uint8_t setRxMode;	/* set receive mode */
	uint8_t rxMode;		/* RXMODE_DMA or RXMODE_BYHAND */

	uint8_t setTxMode;	/* set transmit mode */
	uint8_t txMode;		/* TXMODE_DMA or TXMODE_BYHAND */

	/* host requests tx flow control be set */
	uint8_t setTxFlowControl;
	uint8_t txFlowControl;	/* use TX_FLOW... bits below */

	/* host requests rx flow control be set */
	uint8_t setRxFlowControl;
	uint8_t rxFlowControl;	/* use RX_FLOW... bits below */
	uint8_t sendXoff;	/* host requests XOFF transmitted immediately */
	uint8_t sendXon;	/* host requests XON char transmitted */
	uint8_t xonChar;	/* specified in current character format */
	uint8_t xoffChar;	/* specified in current character format */

	uint8_t sendChar;	/* host requests char transmitted immediately */
	uint8_t txChar;		/* character to send */

	uint8_t setRts;		/* host requests RTS output be set */
	uint8_t rts;		/* 1=on, 0=off */
	uint8_t setDtr;		/* host requests DTR output be set */
	uint8_t dtr;		/* 1=on, 0=off */

	/*
	 * configuration data which is simply used as is
	 * and must be specified correctly in every host message.
	 */

	/* forward when this number of chars available */
	uint8_t rxForwardingLength;
	uint8_t rxForwardingTimeout;	/* (1-31 in ms) */
	uint8_t txAckSetting;	/* 0=don't ack, 1=normal, 2-255 TBD... */
	/*
	 * Firmware states which cause actions if they change
	 * and must be specified correctly in every host message.
	 */

	uint8_t portEnabled;	/* 0=disabled, 1=enabled */
	uint8_t txFlush;	/* 0=normal, 1=toss outbound data */
	uint8_t txBreak;	/* 0=break off, 1=break on */
	uint8_t loopbackMode;	/* 0=no loopback, 1=loopback enabled */

	/*
	 * commands which are flags only; these are processed in order
	 * (so that, e.g., if rxFlush and rxForward flags are set, the
	 * port will have no data to forward); any non-zero value
	 * is respected
	 */

	uint8_t rxFlush;	/* toss inbound data */

	/* forward all inbound data, NOW (as if fwdLen==1) */
	uint8_t rxForward;
	uint8_t cancelRxXoff;	/* cancel any receive XOFF state (_txXoff) */
	uint8_t returnStatus;	/* return current status NOW */
};

/* defines for bits in lcr */
#define		USA_DATABITS_5		0x00
#define		USA_DATABITS_6		0x01
#define		USA_DATABITS_7		0x02
#define		USA_DATABITS_8		0x03
#define		STOPBITS_5678_1		0x00 /* 1 stop bit for all byte sizes */
#define		STOPBITS_5_1p5		0x04 /* 1.5 stop bits for 5-bit byte */
#define		STOPBITS_678_2		0x04 /* 2 stop bits for 6-8 bit byte */
#define		USA_PARITY_NONE		0x00
#define		USA_PARITY_ODD		0x08
#define		USA_PARITY_EVEN		0x18
#define		PARITY_MARK_1		0x28 /* force parity MARK */
#define		PARITY_SPACE_0		0x38 /* force parity SPACE */

#define		TXFLOW_CTS			0x04
#define		TXFLOW_DSR			0x08
#define		TXFLOW_XOFF			0x01
#define		TXFLOW_XOFF_ANY		0x02
#define		TXFLOW_XOFF_BITS	(TXFLOW_XOFF | TXFLOW_XOFF_ANY)

#define		RXFLOW_XOFF			0x10
#define		RXFLOW_RTS			0x20
#define		RXFLOW_DTR			0x40
#define		RXFLOW_DSR_SENSITIVITY	0x80

#define		RXMODE_BYHAND		0x00
#define		RXMODE_DMA			0x02

#define		TXMODE_BYHAND		0x00
#define		TXMODE_DMA			0x02

/* all things called "StatusMessage" are sent on the status endpoint */

struct keyspan_usa19hs_port_status_msg {
	uint8_t msr;		/* reports the actual MSR register */
	uint8_t cts;		/* reports CTS pin */
	uint8_t dcd;		/* reports DCD pin */
	uint8_t dsr;		/* reports DSR pin */
	uint8_t ri;		/* reports RI pin */
	uint8_t _txXoff;	/* port is in XOFF state (we received XOFF) */
	uint8_t rxBreak;	/* reports break state */

	/* count of overrun errors (since last reported) */
	uint8_t rxOverrun;

	/* count of parity errors (since last reported) */
	uint8_t rxParity;

	/* count of frame errors (since last reported) */
	uint8_t rxFrame;
	uint8_t portState;	/* PORTSTATE_xxx bits (useful for debugging) */
	uint8_t messageAck;	/* message acknowledgement */
	uint8_t charAck;	/* character acknowledgement */

	/* (value = returnStatus) a control message has been processed */
	uint8_t controlResponse;
};

/* bits in RX data message when STAT byte is included */

#define	RXERROR_OVERRUN		0x02
#define	RXERROR_PARITY		0x04
#define	RXERROR_FRAMING		0x08
#define	RXERROR_BREAK		0x10

#define	PORTSTATE_ENABLED	0x80
#define	PORTSTATE_TXFLUSH	0x01
#define	PORTSTATE_TXBREAK	0x02
#define	PORTSTATE_LOOPBACK	0x04

/* MSR bits */

/* CTS has changed since last report */
#define	USA_MSR_dCTS			0x01
#define	USA_MSR_dDSR			0x02
#define	USA_MSR_dRI			0x04
#define	USA_MSR_dDCD			0x08

#define	USA_MSR_CTS			0x10	/* current state of CTS */
#define	USA_MSR_DSR			0x20
#define	USA_USA_MSR_RI			0x40
#define	MSR_DCD				0x80

/* ie: the maximum length of an endpoint buffer */
#define		MAX_DATA_LEN			64

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_USBSER_KEYSPAN_USA90MSG_H */
