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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <npi.h>
#include <sys/nxge/nxge_impl.h>

nxge_os_mutex_t npidebuglock;
int npi_debug_init = 0;
uint64_t npi_debug_level = 0;

extern void npi_trace_dump(rtrace_t *, int);

void
npi_debug_msg(npi_handle_function_t function, uint64_t level, char *fmt, ...)
{
	char msg_buffer[1024];
	char prefix_buffer[32];
	int cmn_level = CE_CONT;
	va_list ap;

	if ((level & npi_debug_level) ||
	    (level & NPI_REG_CTL) ||
	    (level & NPI_ERR_CTL)) {

		if (npi_debug_init == 0) {
			MUTEX_INIT(&npidebuglock, NULL, MUTEX_DRIVER, NULL);
			npi_debug_init = 1;
		}

		MUTEX_ENTER(&npidebuglock);

		if (level & NPI_ERR_CTL) {
			cmn_level = CE_WARN;
		}

		va_start(ap, fmt);
		(void) vsprintf(msg_buffer, fmt, ap);
		va_end(ap);

		(void) sprintf(prefix_buffer, "%s%d(%d):", "npi",
		    function.instance, function.function);

		MUTEX_EXIT(&npidebuglock);
		cmn_err(cmn_level, "!%s %s\n", prefix_buffer, msg_buffer);
	}
}

void
npi_rtrace_buf_init(rtrace_t *rt)
{
	int i;

	rt->next_idx = 0;
	rt->last_idx = MAX_RTRACE_ENTRIES - 1;
	rt->wrapped = B_FALSE;
	for (i = 0; i < MAX_RTRACE_ENTRIES; i++) {
		rt->buf[i].ctl_addr = TRACE_CTL_INVALID;
		rt->buf[i].val_l32 = 0;
		rt->buf[i].val_h32 = 0;
	}
}

void
npi_rtrace_update(npi_handle_t handle, boolean_t wr, rtrace_t *rt,
    uint32_t addr, uint64_t val)
{
	int idx;
	idx = rt->next_idx;
	if (wr == B_TRUE)
		rt->buf[idx].ctl_addr = (addr & TRACE_ADDR_MASK)
		    | TRACE_CTL_WR;
	else
		rt->buf[idx].ctl_addr = (addr & TRACE_ADDR_MASK);
	rt->buf[idx].ctl_addr |= (((handle.function.function
	    << TRACE_FUNC_SHIFT) & TRACE_FUNC_MASK) |
	    ((handle.function.instance
	    << TRACE_INST_SHIFT) & TRACE_INST_MASK));
	rt->buf[idx].val_l32 = val & 0xFFFFFFFF;
	rt->buf[idx].val_h32 = (val >> 32) & 0xFFFFFFFF;
	rt->next_idx++;
	if (rt->next_idx > rt->last_idx) {
		rt->next_idx = 0;
		rt->wrapped = B_TRUE;
	}
}

void
npi_trace_update(npi_handle_t handle, boolean_t wr, rtrace_t *rt,
    const char *name, uint32_t addr, uint64_t val)
{
	int idx;
	idx = rt->next_idx;
	if (wr == B_TRUE)
		rt->buf[idx].ctl_addr = (addr & TRACE_ADDR_MASK)
		    | TRACE_CTL_WR;
	else
		rt->buf[idx].ctl_addr = (addr & TRACE_ADDR_MASK);
	/*
	 * Control Address field format
	 *
	 * Bit  0 - 23: Address
	 * Bit 24 - 25: Function Number
	 * Bit 26 - 29: Instance Number
	 * Bit 30: Read/Write Direction bit
	 * Bit 31: Invalid bit
	 */
	rt->buf[idx].ctl_addr |= (((handle.function.function
	    << TRACE_FUNC_SHIFT) & TRACE_FUNC_MASK) |
	    ((handle.function.instance
	    << TRACE_INST_SHIFT) & TRACE_INST_MASK));
	rt->buf[idx].val_l32 = val & 0xFFFFFFFF;
	rt->buf[idx].val_h32 = (val >> 32) & 0xFFFFFFFF;
	(void) strncpy(rt->buf[idx].name, name, 15);
	rt->next_idx++;
	if (rt->next_idx > rt->last_idx) {
		rt->next_idx = 0;
		rt->wrapped = B_TRUE;
	}
}

#if defined(NPI_DEBUG)
void
npi_trace_dump(
	rtrace_t *rt,
	int count)
{
	rt_buf_t *trace;
	int cursor, i;

	if (count == 0 || count > MAX_RTRACE_ENTRIES)
		count = 32;

	/*
	 * Starting with the last recorded entry,
	 * dump the <count> most recent records.
	 */
	cursor = rt->next_idx;
	cursor = (cursor == 0) ? rt->last_idx : cursor - 1;

	for (i = 0; i < count; i++) {
		trace = &rt->buf[cursor];
		if (trace->ctl_addr == 0)
			break;
		cmn_err(CE_NOTE, "%16s @ 0x%08x: 0x%08x.%08x: %c",
		    trace->name, trace->ctl_addr,
		    trace->val_h32, trace->val_l32,
		    trace->ctl_addr & TRACE_CTL_WR ? 'W' : 'R');
		cursor = (cursor == 0) ? rt->last_idx : cursor - 1;
	}
}
#endif
