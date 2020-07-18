/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2014 Tycho Nightingale <tycho.nightingale@pluribusnetworks.com>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND
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
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2020 Oxide Computer Company
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>

#include <machine/vmm.h>

#include "vatpic.h"
#include "vatpit.h"
#include "vpmtmr.h"
#include "vrtc.h"
#include "vmm_ioport.h"

#define	MAX_IOPORTS		1280

static ioport_handler_func_t ioport_handler[MAX_IOPORTS] = {
	[TIMER_MODE] = vatpit_handler,
	[TIMER_CNTR0] = vatpit_handler,
	[TIMER_CNTR1] = vatpit_handler,
	[TIMER_CNTR2] = vatpit_handler,
	[NMISC_PORT] = vatpit_nmisc_handler,
	[IO_ICU1] = vatpic_master_handler,
	[IO_ICU1 + ICU_IMR_OFFSET] = vatpic_master_handler,
	[IO_ICU2] = vatpic_slave_handler,
	[IO_ICU2 + ICU_IMR_OFFSET] = vatpic_slave_handler,
	[IO_ELCR1] = vatpic_elc_handler,
	[IO_ELCR2] = vatpic_elc_handler,
	[IO_PMTMR] = vpmtmr_handler,
	[IO_RTC] = vrtc_addr_handler,
	[IO_RTC + 1] = vrtc_data_handler,
};

int
vm_inout_access(struct vm *vm, int vcpuid, bool in, uint16_t port,
    uint8_t bytes, uint32_t *val)
{
	ioport_handler_func_t handler;
	int error;

	handler = NULL;
	if (port < MAX_IOPORTS) {
		handler = ioport_handler[port];
	}

	if (handler != NULL) {
		error = (*handler)(vm, vcpuid, in, port, bytes, val);
	} else {
		/* Look for hooks, if a standard handler is not present */
		error = vm_ioport_handle_hook(vm, vcpuid, in, port, bytes, val);
	}

	return (error);
}
