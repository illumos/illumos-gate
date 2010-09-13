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

#ifndef _SYS_USB_UGEN_H
#define	_SYS_USB_UGEN_H


#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Header  file  for  applications  written to  USB  Generic Driver (UGEN).
 * This  provides different  status  values written  to the application by
 * UGEN.
 */

/*
 * UGEN  provides a mechanism  to  retrieve  USB bus  specific information
 * through endpoint status minor nodes (See ugen(7D) for more information).
 * Whenever an error occurs on any endpoint, the application can retrieve
 * the last command status (int). Possible values are give below
 */
#define	USB_LC_STAT_NOERROR		0x00	/* No error		  */
#define	USB_LC_STAT_CRC			0x01	/* CRC timeout detected   */
#define	USB_LC_STAT_BITSTUFFING		0x02	/* Bit-stuffing violation */
#define	USB_LC_STAT_DATA_TOGGLE_MM	0x03	/* Data toggle mismatch	  */
#define	USB_LC_STAT_STALL		0x04	/* Endpoint stalled	  */
#define	USB_LC_STAT_DEV_NOT_RESP	0x05	/* Device not responding  */
#define	USB_LC_STAT_PID_CHECKFAILURE	0x06	/* PID Check failure	  */
#define	USB_LC_STAT_UNEXP_PID		0x07	/* Unexpected PID	  */
#define	USB_LC_STAT_DATA_OVERRUN	0x08	/* Data size exceeded	  */
#define	USB_LC_STAT_DATA_UNDERRUN	0x09	/* Less data received	  */
#define	USB_LC_STAT_BUFFER_OVERRUN	0x0a	/* Buffer size exceeded	  */
#define	USB_LC_STAT_BUFFER_UNDERRUN	0x0b	/* Buffer under run	  */
#define	USB_LC_STAT_TIMEOUT		0x0c	/* Command timed out	  */
#define	USB_LC_STAT_NOT_ACCESSED	0x0d	/* Not accessed by h/w	  */
#define	USB_LC_STAT_UNSPECIFIED_ERR	0x0e	/* Unspecified error	  */
#define	USB_LC_STAT_NO_BANDWIDTH	0x41	/* No bandwidth		  */
#define	USB_LC_STAT_HW_ERR		0x42	/* Hardware error	  */
#define	USB_LC_STAT_SUSPENDED		0x43	/* Device suspended/resumed */
#define	USB_LC_STAT_DISCONNECTED	0x44	/* Device disconnected	  */
#define	USB_LC_STAT_INTR_BUF_FULL	0x45	/* Interrupt buf was full */
#define	USB_LC_STAT_INVALID_REQ		0x46	/* request was invalid	  */
#define	USB_LC_STAT_INTERRUPTED		0x47	/* request was interrupted  */
#define	USB_LC_STAT_NO_RESOURCES	0x48	/* no resources for req	  */
#define	USB_LC_STAT_INTR_POLLING_FAILED	0x49	/* failed to restart poll  */
#define	USB_LC_STAT_ISOC_POLLING_FAILED	0x50	/* failed to restart iso poll */
#define	USB_LC_STAT_ISOC_UNINITIALIZED	0x51	/* isoc_info not inited yet */
#define	USB_LC_STAT_ISOC_PKT_ERROR	0x52	/* All pkts in last req fail */

/*
 * Endpoint control
 */
#define	USB_EP_INTR_ONE_XFER		0x01	/* when this bit is set	*/
						/* ugen will poll an intr */
						/* endpoint only once	*/

/*
 * Possible Device status (int) values
 * Application can poll(2) and read(2) device status on device status minor
 * nodes (See ugen(7D) for more details).
 */
#define	USB_DEV_STAT_ONLINE		0x1	/* Device is online	  */
#define	USB_DEV_STAT_DISCONNECTED	0x2	/* Device is disconnected */
#define	USB_DEV_STAT_RESUMED		0x4	/* Device resumed	  */
#define	USB_DEV_STAT_UNAVAILABLE	0x5	/* Device unavailable	  */

/*
 * Structure for holding isoc data packets information. Application and ugen
 * driver use these structures to exchange isoc packet information.
 */
typedef struct ugen_isoc_pkt_descr {
	/*
	 * Set by the application, for all isochronous requests, to the
	 * number of bytes to transfer in a packet.
	 */
	ushort_t	dsc_isoc_pkt_len;

	/*
	 * Set by ugen to actual number of bytes sent/received in a packet.
	 */
	ushort_t	dsc_isoc_pkt_actual_len;

	/*
	 * Per packet status set by ugen driver both for the isochronous IN
	 * and OUT requests.
	 */
	int	dsc_isoc_pkt_status;
} ugen_isoc_pkt_descr_t;

typedef struct ugen_isoc_req_head {
	int	req_isoc_pkts_count; /* pkt count of the isoc request */
	ugen_isoc_pkt_descr_t req_isoc_pkt_descrs[1]; /* pkt descriptors */
} ugen_isoc_req_head_t;


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_USB_UGEN_H */
