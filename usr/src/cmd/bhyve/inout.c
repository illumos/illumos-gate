/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
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

#include <sys/param.h>
#include <sys/linker_set.h>
#include <sys/_iovec.h>
#include <sys/mman.h>

#include <x86/psl.h>
#include <x86/segments.h>

#include <machine/vmm.h>
#include <vmmapi.h>

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "bhyverun.h"
#include "config.h"
#include "inout.h"

SET_DECLARE(inout_port_set, struct inout_port);

#define	MAX_IOPORTS	(1 << 16)

#define	VERIFY_IOPORT(port, size) \
	assert((port) >= 0 && (size) > 0 && ((port) + (size)) <= MAX_IOPORTS)

struct inout_handler {
	const char	*name;
	int		flags;
	inout_func_t	handler;
	void		*arg;
};

static struct inout_handler inout_handlers[MAX_IOPORTS];

static int
default_inout(struct vmctx *ctx __unused, int in,
    int port __unused, int bytes, uint32_t *eax, void *arg __unused)
{
	if (in) {
		switch (bytes) {
		case 4:
			*eax = 0xffffffff;
			break;
		case 2:
			*eax = 0xffff;
			break;
		case 1:
			*eax = 0xff;
			break;
		}
	}

	return (0);
}

static void
register_default_iohandler(int start, int size)
{
	struct inout_port iop;

	VERIFY_IOPORT(start, size);

	bzero(&iop, sizeof(iop));
	iop.name = "default";
	iop.port = start;
	iop.size = size;
	iop.flags = IOPORT_F_INOUT | IOPORT_F_DEFAULT;
	iop.handler = default_inout;

	register_inout(&iop);
}

int
emulate_inout(struct vmctx *ctx, struct vcpu *vcpu, struct vm_inout *inout)
{
	struct inout_handler handler;
	inout_func_t hfunc;
	void *harg;
	int error;
	uint8_t bytes;
	bool in;

	bytes = inout->bytes;
	in = (inout->flags & INOUT_IN) != 0;

	assert(bytes == 1 || bytes == 2 || bytes == 4);

	handler = inout_handlers[inout->port];
	hfunc = handler.handler;
	harg = handler.arg;

	if (hfunc == default_inout &&
	    get_config_bool_default("x86.strictio", false))
		return (-1);

	if (in) {
		if (!(handler.flags & IOPORT_F_IN))
			return (-1);
	} else {
		if (!(handler.flags & IOPORT_F_OUT))
			return (-1);
	}

	error = hfunc(ctx, in, inout->port, bytes, &inout->eax, harg);
	return (error);
}

void
init_inout(void)
{
	struct inout_port **iopp, *iop;

	/*
	 * Set up the default handler for all ports
	 */
	register_default_iohandler(0, MAX_IOPORTS);

	/*
	 * Overwrite with specified handlers
	 */
	SET_FOREACH(iopp, inout_port_set) {
		iop = *iopp;
		assert(iop->port < MAX_IOPORTS);
		inout_handlers[iop->port].name = iop->name;
		inout_handlers[iop->port].flags = iop->flags;
		inout_handlers[iop->port].handler = iop->handler;
		inout_handlers[iop->port].arg = NULL;
	}
}

int
register_inout(struct inout_port *iop)
{
	int i;

	VERIFY_IOPORT(iop->port, iop->size);

	/*
	 * Verify that the new registration is not overwriting an already
	 * allocated i/o range.
	 */
	if ((iop->flags & IOPORT_F_DEFAULT) == 0) {
		for (i = iop->port; i < iop->port + iop->size; i++) {
			if ((inout_handlers[i].flags & IOPORT_F_DEFAULT) == 0)
				return (-1);
		}
	}

	for (i = iop->port; i < iop->port + iop->size; i++) {
		inout_handlers[i].name = iop->name;
		inout_handlers[i].flags = iop->flags;
		inout_handlers[i].handler = iop->handler;
		inout_handlers[i].arg = iop->arg;
	}

	return (0);
}

int
unregister_inout(struct inout_port *iop)
{

	VERIFY_IOPORT(iop->port, iop->size);
	assert(inout_handlers[iop->port].name == iop->name);

	register_default_iohandler(iop->port, iop->size);

	return (0);
}
