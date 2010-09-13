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


#ifndef _SYS_USB_USBSER_KEYSPAN_USA49MSG_H
#define	_SYS_USB_USBSER_KEYSPAN_USA49MSG_H

typedef struct keyspan_usa49_port_ctrl_msg keyspan_usa49_port_ctrl_msg_t;
typedef struct keyspan_usa49_port_status_msg keyspan_usa49_port_status_msg_t;

/*
 * usa49msg.h
 *
 * Copyright (C) 1998-2000 InnoSys Incorporated.  All Rights Reserved
 *
 * Keyspan USB Async Message Formats for the USA49W
 *
 *
 * Buffer formats for RX/TX data messages are not defined by
 * a structure, but are described here:
 *
 * USB OUT (host -> USAxx, transmit) messages contain a
 * REQUEST_ACK indicator (set to 0xff to request an ACK at the
 * completion of transmit; 0x00 otherwise), followed by data:
 *
 *	RQSTACK DAT DAT DAT ...
 *
 * with a total data length of 63.
 *
 * USB IN (USAxx -> host, receive) messages begin with a status
 * byte in which the 0x80 bit is either:
 *
 * (a)	0x80 bit clear
 *		indicates that the bytes following it are all data
 *		bytes:
 *
 *			STAT DATA DATA DATA DATA DATA ...
 *
 *		for a total of up to 63 DATA bytes,
 *
 * or:
 *
 *	(b)	0x80 bit set
 *		indiates that the bytes following alternate data and
 *		status bytes:
 *
 *			STAT DATA STAT DATA STAT DATA STAT DATA ...
 *
 *		for a total of up to 32 DATA bytes.
 *
 * The valid bits in the STAT bytes are:
 *
 *	OVERRUN	0x02
 *	PARITY	0x04
 *	FRAMING	0x08
 *	BREAK	0x10
 *
 * Notes:
 *
 * (1) The OVERRUN bit can appear in either (a) or (b) format
 *	messages, but the but the PARITY/FRAMING/BREAK bits
 *	only appear in (b) format messages.
 * (2) For the host to determine the exact point at which the
 *	overrun occurred (to identify the point in the data
 *	stream at which the data was lost), it needs to count
 *	128 characters, starting at the first character of the
 *	message in which OVERRUN was reported; the lost character(s)
 *	would have been received between the 128th and 129th
 *	characters.
 * (3)	An RX data message in which the first byte has 0x80 clear
 *	serves as a "break off" indicator.
 * (4)	a control message specifying disablePort will be answered
 *	with a status message, but no further status will be sent
 *	until a control messages with enablePort is sent
 *
 */

/*
 * Host->device messages sent on the global control endpoint:
 *
 * portNumber	message
 * ----------	--------------------
 * 0,1,2,3	portControlMessage
 * 0x80		globalControlMessage
 */

struct keyspan_usa49_port_ctrl_msg {
	/*
	 * 0.	0/1/2/3 	port control message follows
	 * 0x80 set	non-port control message follows
	 */
	uint8_t portNumber;

	/*
	 * there are three types of "commands" sent in the control message:
	 *
	 * 1. configuration changes which must be requested by setting
	 * the corresponding "set" flag (and should only be requested
	 * when necessary, to reduce overhead on the USA26):
	 */
	uint8_t setClocking;	/* host requests baud rate be set */
	uint8_t baudLo;		/* host does baud divisor calculation */

	/* baudHi is only used for first port (gives lower rates) */
	uint8_t baudHi;
	uint8_t prescaler;	/* specified as N/8; values 8-ff are valid */
	/* must be set any time internal baud rate is set; */
	uint8_t txClocking;	/* 0=internal, 1=external/DSR */
	uint8_t rxClocking;	/* 0=internal, 1=external/DSR */

	uint8_t setLcr;		/* host requests lcr be set */
	uint8_t lcr;		/* use PARITY, STOPBITS, DATABITS below */

	uint8_t setFlowControl;	/* host requests flow control be set */
	uint8_t ctsFlowControl;	/* 1=use CTS flow control, 0=don't */
	uint8_t xonFlowControl;	/* 1=use XON/XOFF flow control, 0=don't */
	uint8_t xonChar;	/* specified in current character format */
	uint8_t xoffChar;	/* specified in current character format */

	uint8_t setRts;		/* host requests RTS output be set */
	uint8_t rts;		/* 1=active, 0=inactive */

	uint8_t setDtr;		/* host requests DTR output be set */
	uint8_t dtr;		/* 1=on, 0=off */

	/*
	 * 3. configuration data which is simply used as is (no overhead,
	 * but must be specified correctly in every host message).
	 */

	/* forward when this number of chars available */
	uint8_t forwardingLength;
	uint8_t dsrFlowControl;	/* 1=use DSR flow control, 0=don't */

	/* 0=not allowed, 1=normal, 2-255 deliver ACK faster */
	uint8_t txAckThreshold;
	uint8_t loopbackMode;	/* 0=no loopback, 1=loopback enabled */

	/*
	 * 4.	commands which are flags only; these are processed in order
	 * (so that, e.g., if both _txOn and _txOff flags are set, the
	 * port ends in a TX_OFF state); any non-zero value is respected
	 */

	/* enable transmitting (and continue if there's data) */
	uint8_t _txOn;
	uint8_t _txOff;		/* stop transmitting */
	uint8_t txFlush;	/* toss outbound data */
	uint8_t txBreak;	/* turn on break (cleared by _txOn) */
	uint8_t rxOn;		/* turn on receiver */
	uint8_t rxOff;		/* turn off receiver */
	uint8_t rxFlush;	/* toss inbound data */

	/* forward all inbound data, NOW (as if fwdLen==1) */
	uint8_t rxForward;

	/* return current status (even if it hasn't changed) */
	uint8_t returnStatus;
	uint8_t resetDataToggle;	/* reset data toggle state to DATA0 */

	/* start servicing port (move data, check status) */
	uint8_t enablePort;

	/* stop servicing port (does implicit tx/rx flush/off) */
	uint8_t disablePort;

};

/* defines for bits in lcr */
#define	USA_DATABITS_5		0x00
#define	USA_DATABITS_6		0x01
#define	USA_DATABITS_7		0x02
#define	USA_DATABITS_8		0x03
#define	STOPBITS_5678_1		0x00	/* 1 stop bit for all byte sizes */
#define	STOPBITS_5_1p5		0x04	/* 1.5 stop bits for 5-bit byte */
#define	STOPBITS_678_2		0x04	/* 2 stop bits for 6/7/8-bit byte */
#define	USA_PARITY_NONE		0x00
#define	USA_PARITY_ODD		0x08
#define	USA_PARITY_EVEN		0x18
#define	PARITY_1			0x28
#define	PARITY_0			0x38

/*
 * during normal operation, status messages are returned
 * to the host whenever the board detects changes.  In some
 * circumstances (e.g. Windows), status messages from the
 * device cause problems; to shut them off, the host issues
 * a control message with the disableStatusMessages flags
 * set (to any non-zero value).  The device will respond to
 * this message, and then suppress further status messages;
 * it will resume sending status messages any time the host
 * sends any control message (either global or port-specific).
 */

struct keyspan_usa49_globalControlMessage {
	uint8_t portNumber;	/* 0x80 */

	/* 1/2=number of status responses requested */
	uint8_t sendGlobalStatus;
	uint8_t resetStatusToggle;	/* 1=reset global status toggle */
	uint8_t resetStatusCount;	/* a cycling value */
	uint8_t remoteWakeupEnable;	/* 0x10=P1, 0x20=P2, 0x40=P3, 0x80=P4 */
	uint8_t disableStatusMessages;	/* 1=send no status until host talks */
};

/*
 * Device->host messages send on the global status endpoint
 *
 * portNumber			message
 * ----------			--------------------
 * 0x00,0x01,0x02,0x03		portStatusMessage
 * 0x80				globalStatusMessage
 * 0x81				globalDebugMessage
 */

struct keyspan_usa49_port_status_msg {	/* one for each port */
	uint8_t portNumber;	/* 0,1,2,3 */
	uint8_t cts;		/* reports CTS pin */
	uint8_t dcd;		/* reports DCD pin */
	uint8_t dsr;		/* reports DSR pin */
	uint8_t ri;		/* reports RI pin */
	uint8_t _txOff;		/* transmit has been disabled (by host) */

	/* transmit is in XOFF state (either host or RX XOFF) */
	uint8_t _txXoff;
	uint8_t rxEnabled;	/* as configured by rxOn/rxOff 1=on, 0=off */

	/* 1=a control message has been processed */
	uint8_t controlResponse;
	uint8_t txAck;		/* ACK (data TX complete) */
	uint8_t rs232valid;	/* RS-232 signal valid */
};

/* bits in RX data message when STAT byte is included */
#define	RXERROR_OVERRUN	0x02
#define	RXERROR_PARITY	0x04
#define	RXERROR_FRAMING	0x08
#define	RXERROR_BREAK	0x10

struct keyspan_usa49_globalStatusMessage {
	uint8_t portNumber;	/* 0x80=globalStatusMessage */
	uint8_t sendGlobalStatus;	/* from request, decremented */
	uint8_t resetStatusCount;	/* as in request */
};

struct keyspan_usa49_globalDebugMessage {
	uint8_t portNumber;	/* 0x81=globalDebugMessage */
	uint8_t n;		/* typically a count/status byte */
	uint8_t b;		/* typically a data byte */
};

/* ie: the maximum length of an EZUSB endpoint buffer */
#define	MAX_DATA_LEN			64

/* update status approx. 60 times a second (16.6666 ms) */
#define	STATUS_UPDATE_INTERVAL	16

/* status rationing tuning value (each port gets checked each n ms) */
#define	STATUS_RATION	10

#endif /* _SYS_USB_USBSER_KEYSPAN_USA49MSG_H */
