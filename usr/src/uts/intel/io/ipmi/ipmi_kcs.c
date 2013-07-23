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

/* $FreeBSD: src/sys/dev/ipmi/ipmi_kcs.c,v 1.3 2008/08/28 02:11:04 jhb */

/*
 * Copyright 2012, Joyent, Inc.  All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/param.h>
#include <sys/disp.h>
#include <sys/systm.h>
#include <sys/condvar.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/ipmi.h>
#include "ipmivars.h"

static void	kcs_clear_obf(struct ipmi_softc *, int);
static void	kcs_error(struct ipmi_softc *);
static int	kcs_wait_for_ibf(struct ipmi_softc *, int);
static int	kcs_wait_for_obf(struct ipmi_softc *, int);

#define	RETRY_USECS	100
static clock_t timeout_usecs;

static int
kcs_wait_for_ibf(struct ipmi_softc *sc, int state)
{
	int status;
	clock_t i;

	status = INB(sc, KCS_CTL_STS);
	if (state == 0) {
		/* WAIT FOR IBF = 0 */
		for (i = 0; i < timeout_usecs && status & KCS_STATUS_IBF;
		    i += RETRY_USECS) {
			drv_usecwait(RETRY_USECS);
			status = INB(sc, KCS_CTL_STS);
		}
	} else {
		/* WAIT FOR IBF = 1 */
		for (i = 0; i < timeout_usecs && !(status & KCS_STATUS_IBF);
		    i += RETRY_USECS) {
			drv_usecwait(RETRY_USECS);
			status = INB(sc, KCS_CTL_STS);
		}
	}
	return (status);
}

static int
kcs_wait_for_obf(struct ipmi_softc *sc, int state)
{
	int status;
	clock_t i;

	status = INB(sc, KCS_CTL_STS);
	if (state == 0) {
		/* WAIT FOR OBF = 0 */
		for (i = 0; i < timeout_usecs && status & KCS_STATUS_OBF;
		    i += RETRY_USECS) {
			drv_usecwait(RETRY_USECS);
			status = INB(sc, KCS_CTL_STS);
		}
	} else {
		/* WAIT FOR OBF = 1 */
		for (i = 0; i < timeout_usecs && !(status & KCS_STATUS_OBF);
		    i += RETRY_USECS) {
			drv_usecwait(RETRY_USECS);
			status = INB(sc, KCS_CTL_STS);
		}
	}
	return (status);
}

static void
kcs_clear_obf(struct ipmi_softc *sc, int status)
{
	/* Clear OBF */
	if (status & KCS_STATUS_OBF) {
		(void) INB(sc, KCS_DATA);
	}
}

static void
kcs_error(struct ipmi_softc *sc)
{
	int retry, status;
	uchar_t data;

	for (retry = 0; retry < 2; retry++) {

		/* Wait for IBF = 0 */
		status = kcs_wait_for_ibf(sc, 0);

		/* ABORT */
		OUTB(sc, KCS_CTL_STS, KCS_CONTROL_GET_STATUS_ABORT);

		/* Wait for IBF = 0 */
		status = kcs_wait_for_ibf(sc, 0);

		/* Clear OBF */
		kcs_clear_obf(sc, status);

		if (status & KCS_STATUS_OBF) {
			data = INB(sc, KCS_DATA);
			if (data != 0)
				cmn_err(CE_WARN,
				    "KCS Error Data %02x", data);
		}

		/* 0x00 to DATA_IN */
		OUTB(sc, KCS_DATA, 0x00);

		/* Wait for IBF = 0 */
		status = kcs_wait_for_ibf(sc, 0);

		if (KCS_STATUS_STATE(status) == KCS_STATUS_STATE_READ) {

			/* Wait for OBF = 1 */
			status = kcs_wait_for_obf(sc, 1);

			/* Read error status */
			data = INB(sc, KCS_DATA);
			if (data != 0)
				cmn_err(CE_WARN, "KCS error: %02x", data);

			/* Write READ into Data_in */
			OUTB(sc, KCS_DATA, KCS_DATA_IN_READ);

			/* Wait for IBF = 0 */
			status = kcs_wait_for_ibf(sc, 0);
		}

		/* IDLE STATE */
		if (KCS_STATUS_STATE(status) == KCS_STATUS_STATE_IDLE) {
			/* Wait for OBF = 1 */
			status = kcs_wait_for_obf(sc, 1);

			/* Clear OBF */
			kcs_clear_obf(sc, status);
			return;
		}
	}
	cmn_err(CE_WARN, "KCS: Error retry exhausted");
}

/*
 * Start to write a request.  Waits for IBF to clear and then sends the
 * WR_START command.
 */
static int
kcs_start_write(struct ipmi_softc *sc)
{
	int retry, status;

	for (retry = 0; retry < 10; retry++) {
		/* Wait for IBF = 0 */
		status = kcs_wait_for_ibf(sc, 0);

		/* Clear OBF */
		kcs_clear_obf(sc, status);

		/* Write start to command */
		OUTB(sc, KCS_CTL_STS, KCS_CONTROL_WRITE_START);

		/* Wait for IBF = 0 */
		status = kcs_wait_for_ibf(sc, 0);
		if (KCS_STATUS_STATE(status) == KCS_STATUS_STATE_WRITE)
			break;
		delay(1000000);
	}

	if (KCS_STATUS_STATE(status) != KCS_STATUS_STATE_WRITE)
		/* error state */
		return (0);

	/* Clear OBF */
	kcs_clear_obf(sc, status);

	return (1);
}

/*
 * Write a byte of the request message, excluding the last byte of the
 * message which requires special handling.
 */
static int
kcs_write_byte(struct ipmi_softc *sc, uchar_t data)
{
	int status;

	/* Data to Data */
	OUTB(sc, KCS_DATA, data);

	/* Wait for IBF = 0 */
	status = kcs_wait_for_ibf(sc, 0);

	if (KCS_STATUS_STATE(status) != KCS_STATUS_STATE_WRITE)
		return (0);

	/* Clear OBF */
	kcs_clear_obf(sc, status);
	return (1);
}

/*
 * Write the last byte of a request message.
 */
static int
kcs_write_last_byte(struct ipmi_softc *sc, uchar_t data)
{
	int status;

	/* Write end to command */
	OUTB(sc, KCS_CTL_STS, KCS_CONTROL_WRITE_END);

	/* Wait for IBF = 0 */
	status = kcs_wait_for_ibf(sc, 0);

	if (KCS_STATUS_STATE(status) != KCS_STATUS_STATE_WRITE)
		/* error state */
		return (0);

	/* Clear OBF */
	kcs_clear_obf(sc, status);

	/* Send data byte to DATA. */
	OUTB(sc, KCS_DATA, data);
	return (1);
}

/*
 * Read one byte of the reply message.
 */
static int
kcs_read_byte(struct ipmi_softc *sc, uchar_t *data)
{
	int status;

	/* Wait for IBF = 0 */
	status = kcs_wait_for_ibf(sc, 0);

	/* Read State */
	if (KCS_STATUS_STATE(status) == KCS_STATUS_STATE_READ) {

		/* Wait for OBF = 1 */
		status = kcs_wait_for_obf(sc, 1);

		/* Read Data_out */
		*data = INB(sc, KCS_DATA);

		/* Write READ into Data_in */
		OUTB(sc, KCS_DATA, KCS_DATA_IN_READ);
		return (1);
	}

	/* Idle State */
	if (KCS_STATUS_STATE(status) == KCS_STATUS_STATE_IDLE) {

		/* Wait for OBF = 1 */
		status = kcs_wait_for_obf(sc, 1);

		/* Read Dummy */
		(void) INB(sc, KCS_DATA);
		return (2);
	}

	/* Error State */
	return (0);
}

/*
 * Send a request message and collect the reply.  Returns true if we
 * succeed.
 */
static int
kcs_polled_request(struct ipmi_softc *sc, struct ipmi_request *req)
{
	uchar_t *cp, data;
	int i, state;

	/* Send the request. */
	if (!kcs_start_write(sc)) {
		cmn_err(CE_WARN, "KCS: Failed to start write");
		goto fail;
	}
#ifdef KCS_DEBUG
	cmn_err(CE_NOTE, "KCS: WRITE_START... ok");
#endif

	if (!kcs_write_byte(sc, req->ir_addr)) {
		cmn_err(CE_WARN, "KCS: Failed to write address");
		goto fail;
	}
#ifdef KCS_DEBUG
	cmn_err(CE_NOTE, "KCS: Wrote address: %02x", req->ir_addr);
#endif

	if (req->ir_requestlen == 0) {
		if (!kcs_write_last_byte(sc, req->ir_command)) {
			cmn_err(CE_WARN,
			    "KCS: Failed to write command");
			goto fail;
		}
#ifdef KCS_DEBUG
		cmn_err(CE_NOTE, "KCS: Wrote command: %02x",
		    req->ir_command);
#endif
	} else {
		if (!kcs_write_byte(sc, req->ir_command)) {
			cmn_err(CE_WARN,
			    "KCS: Failed to write command");
			goto fail;
		}
#ifdef KCS_DEBUG
		cmn_err(CE_NOTE, "KCS: Wrote command: %02x",
		    req->ir_command);
#endif

		cp = req->ir_request;
		for (i = 0; i < req->ir_requestlen - 1; i++) {
			if (!kcs_write_byte(sc, *cp++)) {
				cmn_err(CE_WARN,
				    "KCS: Failed to write data byte %d",
				    i + 1);
				goto fail;
			}
#ifdef KCS_DEBUG
			cmn_err(CE_NOTE, "KCS: Wrote data: %02x",
			    cp[-1]);
#endif
		}

		if (!kcs_write_last_byte(sc, *cp)) {
			cmn_err(CE_WARN,
			    "KCS: Failed to write last dta byte");
			goto fail;
		}
#ifdef KCS_DEBUG
		cmn_err(CE_NOTE, "KCS: Wrote last data: %02x",
		    *cp);
#endif
	}

	/* Read the reply.  First, read the NetFn/LUN. */
	if (kcs_read_byte(sc, &data) != 1) {
		cmn_err(CE_WARN, "KCS: Failed to read address");
		goto fail;
	}
#ifdef KCS_DEBUG
	cmn_err(CE_NOTE, "KCS: Read address: %02x", data);
#endif
	if (data != IPMI_REPLY_ADDR(req->ir_addr)) {
		cmn_err(CE_WARN, "KCS: Reply address mismatch");
		goto fail;
	}

	/* Next we read the command. */
	if (kcs_read_byte(sc, &data) != 1) {
		cmn_err(CE_WARN, "KCS: Failed to read command");
		goto fail;
	}
#ifdef KCS_DEBUG
	cmn_err(CE_NOTE, "KCS: Read command: %02x", data);
#endif
	if (data != req->ir_command) {
		cmn_err(CE_WARN, "KCS: Command mismatch");
		goto fail;
	}

	/* Next we read the completion code. */
	if (kcs_read_byte(sc, &req->ir_compcode) != 1) {
		cmn_err(CE_WARN, "KCS: Failed to read completion code");
		goto fail;
	}
#ifdef KCS_DEBUG
	cmn_err(CE_NOTE, "KCS: Read completion code: %02x",
	    req->ir_compcode);
#endif

	/* Finally, read the reply from the BMC. */
	i = 0;
	for (;;) {
		state = kcs_read_byte(sc, &data);
		if (state == 0) {
			cmn_err(CE_WARN,
			    "KCS: Read failed on byte %d", i + 1);
			goto fail;
		}
		if (state == 2)
			break;
		if (i < req->ir_replybuflen) {
			req->ir_reply[i] = data;
#ifdef KCS_DEBUG
			cmn_err(CE_NOTE, "KCS: Read data %02x",
			    data);
		} else {
			cmn_err(CE_WARN,
			    "KCS: Read short %02x byte %d", data, i + 1);
#endif
		}
		i++;
	}
	req->ir_replylen = i;
#ifdef KCS_DEBUG
	cmn_err(CE_NOTE, "KCS: READ finished (%d bytes)", i);
	if (req->ir_replybuflen < i)
#else
	if (req->ir_replybuflen < i && req->ir_replybuflen != 0)
#endif
		cmn_err(CE_WARN, "KCS: Read short: %d buffer, %d actual",
		    (int)(req->ir_replybuflen), i);
	return (1);
fail:
	kcs_error(sc);
	return (0);
}

static void
kcs_loop(void *arg)
{
	struct ipmi_softc *sc = arg;
	struct ipmi_request *req;
	int i, ok;

	IPMI_LOCK(sc);
	while ((req = ipmi_dequeue_request(sc)) != NULL) {
		IPMI_UNLOCK(sc);
		ok = 0;
		for (i = 0; i < 3 && !ok; i++)
			ok = kcs_polled_request(sc, req);
		if (ok)
			req->ir_error = 0;
		else
			req->ir_error = EIO;
		IPMI_LOCK(sc);
		ipmi_complete_request(sc, req);
	}
	IPMI_UNLOCK(sc);
}

static int
kcs_startup(struct ipmi_softc *sc)
{
	sc->ipmi_kthread = taskq_create_proc("ipmi_kcs", 1, minclsyspri, 1, 1,
	    curzone->zone_zsched, TASKQ_PREPOPULATE);

	if (taskq_dispatch(sc->ipmi_kthread, kcs_loop, (void *) sc,
	    TQ_SLEEP) == NULL) {
		taskq_destroy(sc->ipmi_kthread);
		return (1);
	}

	return (0);
}

int
ipmi_kcs_attach(struct ipmi_softc *sc)
{
	int status;

	/* Setup function pointers. */
	sc->ipmi_startup = kcs_startup;
	sc->ipmi_enqueue_request = ipmi_polled_enqueue_request;

	/* See if we can talk to the controller. */
	status = INB(sc, KCS_CTL_STS);
	if (status == 0xff) {
		cmn_err(CE_CONT, "!KCS couldn't find it");
		return (ENXIO);
	}

	timeout_usecs = drv_hztousec(MAX_TIMEOUT);

#ifdef KCS_DEBUG
	cmn_err(CE_NOTE, "KCS: initial state: %02x", status);
#endif
	if (status & KCS_STATUS_OBF ||
	    KCS_STATUS_STATE(status) != KCS_STATUS_STATE_IDLE)
		kcs_error(sc);

	return (0);
}
