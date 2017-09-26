/*-
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
 *
 * $FreeBSD: head/usr.sbin/bhyve/bhyverun.h 277310 2015-01-18 03:08:30Z neel $
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
 * Copyright 2015 Pluribus Networks Inc.
 */

#ifndef	_FBSDRUN_H_
#define	_FBSDRUN_H_

#ifndef CTASSERT		/* Allow lint to override */
#define	CTASSERT(x)		_CTASSERT(x, __LINE__)
#define	_CTASSERT(x, y)		__CTASSERT(x, y)
#define	__CTASSERT(x, y)	typedef char __assert ## y[(x) ? 1 : -1]
#endif

#define	VMEXIT_CONTINUE		(0)
#define	VMEXIT_ABORT		(-1)

struct vmctx;
extern int guest_ncpus;
extern char *guest_uuid_str;
extern char *vmname;
#ifndef	__FreeBSD__
extern int bcons_wait;
extern int bcons_connected;
extern pthread_mutex_t bcons_wait_lock;
extern pthread_cond_t bcons_wait_done;
#endif

void *paddr_guest2host(struct vmctx *ctx, uintptr_t addr, size_t len);

void fbsdrun_set_capabilities(struct vmctx *ctx, int cpu);
void fbsdrun_addcpu(struct vmctx *ctx, int fromcpu, int newcpu, uint64_t rip);
int  fbsdrun_muxed(void);
int  fbsdrun_vmexit_on_hlt(void);
int  fbsdrun_vmexit_on_pause(void);
int  fbsdrun_disable_x2apic(void);
int  fbsdrun_virtio_msix(void);
#endif
