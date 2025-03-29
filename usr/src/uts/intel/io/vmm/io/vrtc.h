/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2014 Neel Natu (neel@freebsd.org)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
 * Copyright 2018 Joyent, Inc.
 * Copyright 2023 Oxide Computer Company
 */

#ifndef _VRTC_H_
#define	_VRTC_H_

#include <isa/isareg.h>

struct vrtc;

struct vrtc *vrtc_init(struct vm *vm);
void vrtc_cleanup(struct vrtc *vrtc);
void vrtc_reset(struct vrtc *vrtc);

void vrtc_get_time(struct vm *vm, timespec_t *);
int vrtc_set_time(struct vm *vm, const timespec_t *);
int vrtc_nvram_write(struct vm *vm, int offset, uint8_t value);
int vrtc_nvram_read(struct vm *vm, int offset, uint8_t *retval);

int vrtc_addr_handler(void *arg, bool in, uint16_t port, uint8_t bytes,
    uint32_t *val);
int vrtc_data_handler(void *arg, bool in, uint16_t port, uint8_t bytes,
    uint32_t *val);

void vrtc_localize_resources(struct vrtc *);
void vrtc_pause(struct vrtc *);
void vrtc_resume(struct vrtc *);

#endif
