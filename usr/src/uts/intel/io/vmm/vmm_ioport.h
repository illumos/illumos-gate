/*-
 * SPDX-License-Identifier: BSD-2-Clause
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
 */
/* This file is dual-licensed; see usr/src/contrib/bhyve/LICENSE */

/*
 * Copyright 2020 Oxide Computer Company
 */

#ifndef	_VMM_IOPORT_H_
#define	_VMM_IOPORT_H_

#include <sys/vmm_kernel.h>

struct ioport_entry {
	ioport_handler_t	iope_func;
	void			*iope_arg;
	uint16_t		iope_port;
	uint16_t		iope_flags;
	uint32_t		iope_pad;
};
typedef struct ioport_entry ioport_entry_t;

struct ioport_config {
	struct ioport_entry	*iop_entries;
	uint_t			iop_count;
};

#define	IOPF_DEFAULT	0
#define	IOPF_FIXED	(1 << 0)	/* system device fixed in position */
#define	IOPF_DRV_HOOK	(1 << 1)	/* external driver hook */

void vm_inout_init(struct vm *vm, struct ioport_config *ports);
void vm_inout_cleanup(struct vm *vm, struct ioport_config *ports);

int vm_inout_attach(struct ioport_config *ports, uint16_t port, uint16_t flags,
    ioport_handler_t func, void *arg);
int vm_inout_detach(struct ioport_config *ports, uint16_t port, bool drv_hook,
    ioport_handler_t *old_func, void **old_arg);

int vm_inout_access(struct ioport_config *ports, bool in, uint16_t port,
    uint8_t bytes, uint32_t *val);

/*
 * Arbitrary cookie for io port hook:
 * - top 48 bits: func address + arg
 * - lower 16 bits: port
 */
#define	IOP_GEN_COOKIE(func, arg, port)					\
	((uintptr_t)((((uintptr_t)(func) + (uintptr_t)(arg)) << 16)	\
	    | (uint16_t)(port)))
#define	IOP_PORT_FROM_COOKIE(cookie)	(uint16_t)(cookie)

#endif	/* _VMM_IOPORT_H_ */
