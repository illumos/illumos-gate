/*
 * Copyright (c) 2006 IronPort Systems Inc. <ambrisko@ironport.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/dev/ipmi/ipmivars.h,v 1.3 2008/08/28 02:13:53 jhb Exp $
 */

/*
 * Copyright 2012, Joyent, Inc.  All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _IPMIVARS_H_
#define	_IPMIVARS_H_

#include <sys/types.h>
#include <sys/queue.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct ipmi_device;
struct ipmi_request;

typedef enum {
	IRS_ALLOCATED,
	IRS_QUEUED,
	IRS_PROCESSED,
	IRS_COMPLETED,
	IRS_CANCELED
} ir_status_t;

struct ipmi_request {
	TAILQ_ENTRY(ipmi_request) ir_link;
	struct ipmi_device *ir_owner;	/* Driver uses NULL. */
	uchar_t		*ir_request;	/* Request is data to send to BMC. */
	size_t		ir_requestlen;
	uchar_t		*ir_reply;	/* Reply is data read from BMC. */
	size_t		ir_replybuflen;	/* Length of ir_reply[] buffer. */
	int		ir_replylen;	/* Length of reply from BMC. */
	int		ir_error;
	long		ir_msgid;
	uint8_t		ir_addr;
	uint8_t		ir_command;
	uint8_t		ir_compcode;
	int		ir_sz;		/* size of request */

	kcondvar_t	ir_cv;
	ir_status_t	ir_status;
};

#define	MAX_RES				3
#define	KCS_DATA			0
#define	KCS_CTL_STS			1
#define	SMIC_DATA			0
#define	SMIC_CTL_STS			1
#define	SMIC_FLAGS			2

#define	IPMI_BUSY	0x1
#define	IPMI_CLOSING	0x2

/* Per file descriptor data. */
typedef struct ipmi_device {
	TAILQ_HEAD(, ipmi_request) ipmi_completed_requests;
	pollhead_t		*ipmi_pollhead;
	int			ipmi_requests;
	uchar_t			ipmi_address;	/* IPMB address. */
	uchar_t			ipmi_lun;
	dev_t			ipmi_dev;
	list_node_t		ipmi_node;	/* list link for open devs */
	int			ipmi_status;
	kcondvar_t		ipmi_cv;
} ipmi_device_t;

struct ipmi_softc {
	int			ipmi_io_rid;
	int			ipmi_io_type;
	uint64_t		ipmi_io_address;
	int			ipmi_io_mode;
	int			ipmi_io_spacing;
	int			ipmi_io_irq;
	void			*ipmi_irq;
	int			ipmi_detaching;
	TAILQ_HEAD(, ipmi_request) ipmi_pending_requests;
	kmutex_t		ipmi_lock;
	kcondvar_t		ipmi_request_added;
	taskq_t			*ipmi_kthread;
	int			(*ipmi_startup)(struct ipmi_softc *);
	int			(*ipmi_enqueue_request)(struct ipmi_softc *,
				    struct ipmi_request *);
};

#define	KCS_MODE		0x01
#define	SMIC_MODE		0x02
#define	BT_MODE			0x03
#define	SSIF_MODE		0x04

/* KCS status flags */
#define	KCS_STATUS_OBF			0x01 /* Data Out ready from BMC */
#define	KCS_STATUS_IBF			0x02 /* Data In from System */
#define	KCS_STATUS_SMS_ATN		0x04 /* Ready in RX queue */
#define	KCS_STATUS_C_D			0x08 /* Command/Data register write */
#define	KCS_STATUS_OEM1			0x10
#define	KCS_STATUS_OEM2			0x20
#define	KCS_STATUS_S0			0x40
#define	KCS_STATUS_S1			0x80
#define	KCS_STATUS_STATE(x)		((x)>>6)
#define	KCS_STATUS_STATE_IDLE		0x0
#define	KCS_STATUS_STATE_READ		0x1
#define	KCS_STATUS_STATE_WRITE		0x2
#define	KCS_STATUS_STATE_ERROR		0x3
#define	KCS_IFACE_STATUS_OK		0x00
#define	KCS_IFACE_STATUS_ABORT		0x01
#define	KCS_IFACE_STATUS_ILLEGAL	0x02
#define	KCS_IFACE_STATUS_LENGTH_ERR	0x06
#define	KCS_IFACE_STATUS_UNKNOWN_ERR	0xff

/* KCS control codes */
#define	KCS_CONTROL_GET_STATUS_ABORT	0x60
#define	KCS_CONTROL_WRITE_START		0x61
#define	KCS_CONTROL_WRITE_END		0x62
#define	KCS_DATA_IN_READ		0x68

/* SMIC status flags */
#define	SMIC_STATUS_BUSY		0x01 /* System set and BMC clears it */
#define	SMIC_STATUS_SMS_ATN		0x04 /* BMC has a message */
#define	SMIC_STATUS_EVT_ATN		0x08 /* Event has been RX */
#define	SMIC_STATUS_SMI			0x10 /* asserted SMI */
#define	SMIC_STATUS_TX_RDY		0x40 /* Ready to accept WRITE */
#define	SMIC_STATUS_RX_RDY		0x80 /* Ready to read */
#define	SMIC_STATUS_RESERVED		0x22

/* SMIC control codes */
#define	SMIC_CC_SMS_GET_STATUS		0x40
#define	SMIC_CC_SMS_WR_START		0x41
#define	SMIC_CC_SMS_WR_NEXT		0x42
#define	SMIC_CC_SMS_WR_END		0x43
#define	SMIC_CC_SMS_RD_START		0x44
#define	SMIC_CC_SMS_RD_NEXT		0x45
#define	SMIC_CC_SMS_RD_END		0x46

/* SMIC status codes */
#define	SMIC_SC_SMS_RDY			0xc0
#define	SMIC_SC_SMS_WR_START		0xc1
#define	SMIC_SC_SMS_WR_NEXT		0xc2
#define	SMIC_SC_SMS_WR_END		0xc3
#define	SMIC_SC_SMS_RD_START		0xc4
#define	SMIC_SC_SMS_RD_NEXT		0xc5
#define	SMIC_SC_SMS_RD_END		0xc6

#define	IPMI_ADDR(netfn, lun)		((netfn) << 2 | (lun))
#define	IPMI_REPLY_ADDR(addr)		((addr) + 0x4)

#define	IPMI_LOCK(sc)			mutex_enter(&(sc)->ipmi_lock)
#define	IPMI_UNLOCK(sc)			mutex_exit(&(sc)->ipmi_lock)
#define	IPMI_LOCK_ASSERT(sc)		ASSERT(MUTEX_HELD(&(sc)->ipmi_lock))

#define	ipmi_alloc_driver_request(addr, cmd, reqlen, replylen)		\
	ipmi_alloc_request(NULL, 0, (addr), (cmd), (reqlen), (replylen))

#define	INB(sc, x)							\
	inb((sc)->ipmi_io_address + ((sc)->ipmi_io_spacing * (x)))
#define	OUTB(sc, x, value)						\
	outb((sc)->ipmi_io_address + ((sc)->ipmi_io_spacing * (x)), value)

#define	MAX_TIMEOUT (3 * hz)

/* Manage requests. */
void	ipmi_complete_request(struct ipmi_softc *, struct ipmi_request *);
struct ipmi_request *ipmi_dequeue_request(struct ipmi_softc *);
int	ipmi_polled_enqueue_request(struct ipmi_softc *, struct ipmi_request *);
struct ipmi_request *ipmi_alloc_request(struct ipmi_device *, long msgid,
	    uint8_t, uint8_t, size_t, size_t);
void	ipmi_free_request(struct ipmi_request *);

/* Interface attach routines. */
boolean_t ipmi_startup(struct ipmi_softc *sc);
int	ipmi_kcs_attach(struct ipmi_softc *);

/* Interface detach cleanup */
void	ipmi_shutdown(struct ipmi_softc *sc);

#ifdef	__cplusplus
}
#endif

#endif	/* _IPMIVARS_H_ */
