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

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/systm.h>

#include <machine/vmm.h>

#include "vatpic.h"
#include "vatpit.h"
#include "vrtc.h"
#include "vmm_ioport.h"

/* Arbitrary limit on entries per VM */
static uint_t ioport_entry_limit = 64;

static void
vm_inout_def(ioport_entry_t *entries, uint_t i, uint16_t port,
    ioport_handler_t func, void *arg, uint16_t flags)
{
	ioport_entry_t *ent = &entries[i];

	if (i != 0) {
		const ioport_entry_t *prev = &entries[i - 1];
		/* ensure that entries are inserted in sorted order */
		VERIFY(prev->iope_port < port);
	}
	ent->iope_func = func;
	ent->iope_arg = arg;
	ent->iope_port = port;
	ent->iope_flags = flags;
}

void
vm_inout_init(struct vm *vm, struct ioport_config *cfg)
{
	struct vatpit *pit = vm_atpit(vm);
	struct vatpic *pic = vm_atpic(vm);
	struct vrtc *rtc = vm_rtc(vm);
	const uint_t ndefault = 13;
	const uint16_t flag = IOPF_FIXED;
	ioport_entry_t *ents;
	uint_t i = 0;

	VERIFY0(cfg->iop_entries);
	VERIFY0(cfg->iop_count);

	ents = kmem_zalloc(ndefault * sizeof (ioport_entry_t), KM_SLEEP);

	/* PIC (master): 0x20-0x21 */
	vm_inout_def(ents, i++, IO_ICU1, vatpic_master_handler, pic, flag);
	vm_inout_def(ents, i++, IO_ICU1 + ICU_IMR_OFFSET, vatpic_master_handler,
	    pic, flag);

	/* PIT: 0x40-0x43 and 0x61 (ps2 tie-in) */
	vm_inout_def(ents, i++, TIMER_CNTR0, vatpit_handler, pit, flag);
	vm_inout_def(ents, i++, TIMER_CNTR1, vatpit_handler, pit, flag);
	vm_inout_def(ents, i++, TIMER_CNTR2, vatpit_handler, pit, flag);
	vm_inout_def(ents, i++, TIMER_MODE, vatpit_handler, pit, flag);
	vm_inout_def(ents, i++, NMISC_PORT, vatpit_nmisc_handler, pit, flag);

	/* RTC: 0x70-0x71 */
	vm_inout_def(ents, i++, IO_RTC, vrtc_addr_handler, rtc, flag);
	vm_inout_def(ents, i++, IO_RTC + 1, vrtc_data_handler, rtc, flag);

	/* PIC (slave): 0xa0-0xa1 */
	vm_inout_def(ents, i++, IO_ICU2, vatpic_slave_handler, pic, flag);
	vm_inout_def(ents, i++, IO_ICU2 + ICU_IMR_OFFSET, vatpic_slave_handler,
	    pic, flag);

	/* PIC (ELCR): 0x4d0-0x4d1 */
	vm_inout_def(ents, i++, IO_ELCR1, vatpic_elc_handler, pic, flag);
	vm_inout_def(ents, i++, IO_ELCR2, vatpic_elc_handler, pic, flag);

	VERIFY3U(i, ==, ndefault);
	cfg->iop_entries = ents;
	cfg->iop_count = ndefault;
}

void
vm_inout_cleanup(struct vm *vm, struct ioport_config *cfg)
{
	VERIFY(cfg->iop_entries);
	VERIFY(cfg->iop_count);

	kmem_free(cfg->iop_entries,
	    sizeof (ioport_entry_t) * cfg->iop_count);
	cfg->iop_entries = NULL;
	cfg->iop_count = 0;
}

static void
vm_inout_remove_at(uint_t idx, uint_t old_count, ioport_entry_t *old_ents,
    ioport_entry_t *new_ents)
{
	uint_t new_count = old_count - 1;

	VERIFY(old_count != 0);
	VERIFY(idx < old_count);

	/* copy entries preceeding to-be-removed index */
	if (idx > 0) {
		bcopy(old_ents, new_ents, sizeof (ioport_entry_t) * idx);
	}
	/* copy entries following to-be-removed index */
	if (idx < new_count) {
		bcopy(&old_ents[idx + 1], &new_ents[idx],
		    sizeof (ioport_entry_t) * (new_count - idx));
	}
}

static void
vm_inout_insert_space_at(uint_t idx, uint_t old_count, ioport_entry_t *old_ents,
    ioport_entry_t *new_ents)
{
	uint_t new_count = old_count + 1;

	VERIFY(idx < new_count);

	/* copy entries preceeding index where space is to be added */
	if (idx > 0) {
		bcopy(old_ents, new_ents, sizeof (ioport_entry_t) * idx);
	}
	/* copy entries to follow added space */
	if (idx < new_count) {
		bcopy(&old_ents[idx], &new_ents[idx + 1],
		    sizeof (ioport_entry_t) * (old_count - idx));
	}
}

int
vm_inout_attach(struct ioport_config *cfg, uint16_t port, uint16_t flags,
    ioport_handler_t func, void *arg)
{
	uint_t i, old_count, insert_idx;
	ioport_entry_t *old_ents;

	if (cfg->iop_count >= ioport_entry_limit) {
		return (ENOSPC);
	}

	old_count = cfg->iop_count;
	old_ents = cfg->iop_entries;
	for (insert_idx = i = 0; i < old_count; i++) {
		const ioport_entry_t *compare = &old_ents[i];
		if (compare->iope_port == port) {
			return (EEXIST);
		} else if (compare->iope_port < port) {
			insert_idx = i + 1;
		}
	}


	ioport_entry_t *new_ents;
	uint_t new_count = old_count + 1;
	new_ents = kmem_alloc(new_count * sizeof (ioport_entry_t), KM_SLEEP);
	vm_inout_insert_space_at(insert_idx, old_count, old_ents, new_ents);

	new_ents[insert_idx].iope_func = func;
	new_ents[insert_idx].iope_arg = arg;
	new_ents[insert_idx].iope_port = port;
	new_ents[insert_idx].iope_flags = flags;
	new_ents[insert_idx].iope_pad = 0;

	cfg->iop_entries = new_ents;
	cfg->iop_count = new_count;
	kmem_free(old_ents, old_count * sizeof (ioport_entry_t));

	return (0);
}

int
vm_inout_detach(struct ioport_config *cfg, uint16_t port, bool drv_hook,
    ioport_handler_t *old_func, void **old_arg)
{
	uint_t i, old_count, remove_idx;
	ioport_entry_t *old_ents;

	old_count = cfg->iop_count;
	old_ents = cfg->iop_entries;
	VERIFY(old_count > 1);
	for (i = 0; i < old_count; i++) {
		const ioport_entry_t *compare = &old_ents[i];
		if (compare->iope_port != port) {
			continue;
		}
		/* fixed ports are not allowed to be detached at runtime */
		if ((compare->iope_flags & IOPF_FIXED) != 0) {
			return (EPERM);
		}

		/*
		 * Driver-attached and bhyve-internal ioport hooks can only be
		 * removed by the respective party which attached them.
		 */
		if (drv_hook && (compare->iope_flags & IOPF_DRV_HOOK) == 0) {
			return (EPERM);
		} else if (!drv_hook &&
		    (compare->iope_flags & IOPF_DRV_HOOK) != 0) {
			return (EPERM);
		}
		break;
	}
	if (i == old_count) {
		return (ENOENT);
	}
	remove_idx = i;

	if (old_func != NULL) {
		*old_func = cfg->iop_entries[remove_idx].iope_func;
	}
	if (old_arg != NULL) {
		*old_arg = cfg->iop_entries[remove_idx].iope_arg;
	}

	ioport_entry_t *new_ents;
	uint_t new_count = old_count - 1;
	new_ents = kmem_alloc(new_count * sizeof (ioport_entry_t), KM_SLEEP);
	vm_inout_remove_at(remove_idx, old_count, old_ents, new_ents);

	cfg->iop_entries = new_ents;
	cfg->iop_count = new_count;
	kmem_free(old_ents, old_count * sizeof (ioport_entry_t));

	return (0);
}

static ioport_entry_t *
vm_inout_find(const struct ioport_config *cfg, uint16_t port)
{
	const uint_t count = cfg->iop_count;
	ioport_entry_t *entries = cfg->iop_entries;

	for (uint_t i = 0; i < count; i++) {
		if (entries[i].iope_port == port) {
			return (&entries[i]);
		}
	}
	return (NULL);
}

int
vm_inout_access(struct ioport_config *cfg, bool in, uint16_t port,
    uint8_t bytes, uint32_t *val)
{
	const ioport_entry_t *ent;
	int err;

	ent = vm_inout_find(cfg, port);
	if (ent == NULL) {
		err = ESRCH;
	} else {
		err = ent->iope_func(ent->iope_arg, in, port, bytes, val);
	}

	return (err);
}
