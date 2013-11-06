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
 */

/* $FreeBSD: src/sys/dev/ipmi/ipmi.c,v 1.16 2011/11/07 15:43:11 ed Exp $ */

/*
 * Copyright 2012, Joyent, Inc.  All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/devops.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/smbios.h>
#include <sys/smbios_impl.h>
#include <sys/ipmi.h>
#include "ipmivars.h"

/*
 * Request management.
 */

/* Allocate a new request with request and reply buffers. */
struct ipmi_request *
ipmi_alloc_request(struct ipmi_device *dev, long msgid, uint8_t addr,
    uint8_t command, size_t requestlen, size_t replylen)
{
	struct ipmi_request *req;

	req = kmem_zalloc(sizeof (struct ipmi_request) + requestlen + replylen,
	    KM_SLEEP);
	req->ir_sz = sizeof (struct ipmi_request) + requestlen + replylen;
	req->ir_owner = dev;
	req->ir_msgid = msgid;
	req->ir_addr = addr;
	req->ir_command = command;
	if (requestlen) {
		req->ir_request = (uchar_t *)&req[1];
		req->ir_requestlen = requestlen;
	}
	if (replylen) {
		req->ir_reply = (uchar_t *)&req[1] + requestlen;
		req->ir_replybuflen = replylen;
	}

	cv_init(&req->ir_cv, NULL, CV_DEFAULT, NULL);
	req->ir_status = IRS_ALLOCATED;

	return (req);
}

/* Free a request no longer in use. */
void
ipmi_free_request(struct ipmi_request *req)
{
	if (req == NULL)
		return;

	cv_destroy(&req->ir_cv);

	kmem_free(req, req->ir_sz);
}

/* Store a processed request on the appropriate completion queue. */
/*ARGSUSED*/
void
ipmi_complete_request(struct ipmi_softc *sc, struct ipmi_request *req)
{
	struct ipmi_device *dev;

	IPMI_LOCK_ASSERT(sc);

	if (req->ir_status == IRS_CANCELED) {
		ASSERT(req->ir_owner == NULL);
		ipmi_free_request(req);
		return;
	}

	req->ir_status = IRS_COMPLETED;

	/*
	 * Anonymous requests (from inside the driver) always have a
	 * waiter that we awaken.
	 */
	if (req->ir_owner == NULL) {
		cv_signal(&req->ir_cv);
	} else {
		dev = req->ir_owner;
		TAILQ_INSERT_TAIL(&dev->ipmi_completed_requests, req, ir_link);
		pollwakeup(dev->ipmi_pollhead, POLLIN | POLLRDNORM);

		dev->ipmi_status &= ~IPMI_BUSY;
		if (dev->ipmi_status & IPMI_CLOSING)
			cv_signal(&dev->ipmi_cv);
	}
}

/*
 * Enqueue an internal driver request and wait until it is completed.
 */
static int
ipmi_submit_driver_request(struct ipmi_softc *sc, struct ipmi_request **preq,
    int timo)
{
	int error;
	struct ipmi_request *req = *preq;

	ASSERT(req->ir_owner == NULL);

	IPMI_LOCK(sc);
	error = sc->ipmi_enqueue_request(sc, req);

	if (error != 0) {
		IPMI_UNLOCK(sc);
		return (error);
	}

	while (req->ir_status != IRS_COMPLETED && error >= 0)
		if (timo == 0)
			cv_wait(&req->ir_cv, &sc->ipmi_lock);
		else
			error = cv_timedwait(&req->ir_cv, &sc->ipmi_lock,
			    ddi_get_lbolt() + timo);

	switch (req->ir_status) {
		case IRS_QUEUED:
			TAILQ_REMOVE(&sc->ipmi_pending_requests, req, ir_link);
			req->ir_status = IRS_CANCELED;
			error = EWOULDBLOCK;
			break;
		case IRS_PROCESSED:
			req->ir_status = IRS_CANCELED;
			error = EWOULDBLOCK;
			*preq = NULL;
			break;
		case IRS_COMPLETED:
			error = req->ir_error;
			break;
		default:
			panic("IPMI: Invalid request status");
			break;
	}
	IPMI_UNLOCK(sc);

	return (error);
}

/*
 * Helper routine for polled system interfaces that use
 * ipmi_polled_enqueue_request() to queue requests.  This request
 * waits until there is a pending request and then returns the first
 * request.  If the driver is shutting down, it returns NULL.
 */
struct ipmi_request *
ipmi_dequeue_request(struct ipmi_softc *sc)
{
	struct ipmi_request *req;

	IPMI_LOCK_ASSERT(sc);

	while (!sc->ipmi_detaching && TAILQ_EMPTY(&sc->ipmi_pending_requests))
		cv_wait(&sc->ipmi_request_added, &sc->ipmi_lock);
	if (sc->ipmi_detaching)
		return (NULL);

	req = TAILQ_FIRST(&sc->ipmi_pending_requests);
	TAILQ_REMOVE(&sc->ipmi_pending_requests, req, ir_link);
	req->ir_status = IRS_PROCESSED;

	if (req->ir_owner != NULL)
		req->ir_owner->ipmi_status |= IPMI_BUSY;

	return (req);
}

int
ipmi_polled_enqueue_request(struct ipmi_softc *sc, struct ipmi_request *req)
{

	IPMI_LOCK_ASSERT(sc);

	TAILQ_INSERT_TAIL(&sc->ipmi_pending_requests, req, ir_link);
	req->ir_status = IRS_QUEUED;
	cv_signal(&sc->ipmi_request_added);
	return (0);
}

void
ipmi_shutdown(struct ipmi_softc *sc)
{
	taskq_destroy(sc->ipmi_kthread);

	cv_destroy(&sc->ipmi_request_added);
	mutex_destroy(&sc->ipmi_lock);
}

boolean_t
ipmi_startup(struct ipmi_softc *sc)
{
	struct ipmi_request *req;
	int error, i;

	/* Initialize interface-independent state. */
	mutex_init(&sc->ipmi_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sc->ipmi_request_added, NULL, CV_DEFAULT, NULL);
	TAILQ_INIT(&sc->ipmi_pending_requests);

	/* Initialize interface-dependent state. */
	error = sc->ipmi_startup(sc);
	if (error) {
		cmn_err(CE_WARN, "Failed to initialize interface: %d", error);
		return (B_FALSE);
	}

	/* Send a GET_DEVICE_ID request. */
	req = ipmi_alloc_driver_request(IPMI_ADDR(IPMI_APP_REQUEST, 0),
	    IPMI_GET_DEVICE_ID, 0, 15);

	error = ipmi_submit_driver_request(sc, &req, MAX_TIMEOUT);
	if (error == EWOULDBLOCK) {
		cmn_err(CE_WARN, "Timed out waiting for GET_DEVICE_ID");
		ipmi_free_request(req);
		return (B_FALSE);
	} else if (error) {
		cmn_err(CE_WARN, "Failed GET_DEVICE_ID: %d", error);
		ipmi_free_request(req);
		return (B_FALSE);
	} else if (req->ir_compcode != 0) {
		cmn_err(CE_WARN,
		    "Bad completion code for GET_DEVICE_ID: %d",
		    req->ir_compcode);
		ipmi_free_request(req);
		return (B_FALSE);
	} else if (req->ir_replylen < 5) {
		cmn_err(CE_WARN, "Short reply for GET_DEVICE_ID: %d",
		    req->ir_replylen);
		ipmi_free_request(req);
		return (B_FALSE);
	}

	cmn_err(CE_CONT, "!device rev. %d, firmware rev. %d.%d%d, "
	    "version %d.%d",
	    req->ir_reply[1] & 0x0f, req->ir_reply[2] & 0x7f,
	    req->ir_reply[3] >> 4, req->ir_reply[3] & 0x0f,
	    req->ir_reply[4] & 0x0f, req->ir_reply[4] >> 4);

	ipmi_free_request(req);

	req = ipmi_alloc_driver_request(IPMI_ADDR(IPMI_APP_REQUEST, 0),
	    IPMI_CLEAR_FLAGS, 1, 0);

	if ((error = ipmi_submit_driver_request(sc, &req, 0)) != 0) {
		cmn_err(CE_WARN, "Failed to clear IPMI flags: %d\n", error);
		ipmi_free_request(req);
		return (B_FALSE);
	}

	/* Magic numbers */
	if (req->ir_compcode == 0xc0) {
		cmn_err(CE_NOTE, "!Clear flags is busy");
	}
	if (req->ir_compcode == 0xc1) {
		cmn_err(CE_NOTE, "!Clear flags illegal");
	}
	ipmi_free_request(req);

	for (i = 0; i < 8; i++) {
		req = ipmi_alloc_driver_request(IPMI_ADDR(IPMI_APP_REQUEST, 0),
		    IPMI_GET_CHANNEL_INFO, 1, 0);
		req->ir_request[0] = (uchar_t)i;

		if (ipmi_submit_driver_request(sc, &req, 0) != 0) {
			ipmi_free_request(req);
			break;
		}

		if (req->ir_compcode != 0) {
			ipmi_free_request(req);
			break;
		}
		ipmi_free_request(req);
	}
	cmn_err(CE_CONT, "!number of channels %d", i);

	/* probe for watchdog */
	req = ipmi_alloc_driver_request(IPMI_ADDR(IPMI_APP_REQUEST, 0),
	    IPMI_GET_WDOG, 0, 0);

	if ((error = ipmi_submit_driver_request(sc, &req, 0)) != 0) {
		cmn_err(CE_WARN, "Failed to check IPMI watchdog: %d\n", error);
		ipmi_free_request(req);
		return (B_FALSE);
	}

	if (req->ir_compcode == 0x00) {
		cmn_err(CE_CONT, "!watchdog supported");

		/*
		 * Here is where we could register a watchdog event handler.
		 * See ipmi_wd_event() in the FreeBSD code.
		 */
	}
	ipmi_free_request(req);

	return (B_TRUE);
}
