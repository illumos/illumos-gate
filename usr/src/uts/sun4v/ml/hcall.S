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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Hypervisor calls
 */

#include <sys/asm_linkage.h>
#include <sys/machasi.h>
#include <sys/machparam.h>
#include <sys/hypervisor_api.h>

	/*
	 * int hv_mach_exit(uint64_t exit_code)
	 */
	ENTRY(hv_mach_exit)
	mov	HV_MACH_EXIT, %o5
	ta	FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_mach_exit)

	/*
	 * uint64_t hv_mach_sir(void)
	 */
	ENTRY(hv_mach_sir)
	mov	HV_MACH_SIR, %o5
	ta	FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_mach_sir)

	/*
	 * hv_cpu_start(uint64_t cpuid, uint64_t pc, ui64_t rtba,
	 *     uint64_t arg)
	 */
	ENTRY(hv_cpu_start)
	mov	HV_CPU_START, %o5
	ta	FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_cpu_start)

	/*
	 * hv_cpu_stop(uint64_t cpuid)
	 */
	ENTRY(hv_cpu_stop)
	mov	HV_CPU_STOP, %o5
	ta	FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_cpu_stop)

	/*
	 * hv_cpu_set_rtba(uint64_t *rtba)
	 */
	ENTRY(hv_cpu_set_rtba)
	mov	%o0, %o2
	ldx	[%o2], %o0
	mov	HV_CPU_SET_RTBA, %o5
	ta	FAST_TRAP
	stx	%o1, [%o2]
	retl
	  nop
	SET_SIZE(hv_cpu_set_rtba)

	/*
	 * int64_t hv_cnputchar(uint8_t ch)
	 */
	ENTRY(hv_cnputchar)
	mov	CONS_PUTCHAR, %o5
	ta	FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_cnputchar)

	/*
	 * int64_t hv_cngetchar(uint8_t *ch)
	 */
	ENTRY(hv_cngetchar)
	mov	%o0, %o2
	mov	CONS_GETCHAR, %o5
	ta	FAST_TRAP
	brnz,a	%o0, 1f		! failure, just return error
	  nop

	cmp	%o1, H_BREAK
	be	1f
	mov	%o1, %o0

	cmp	%o1, H_HUP
	be	1f
	mov	%o1, %o0

	stb	%o1, [%o2]	! success, save character and return 0
	mov	0, %o0
1:
	retl
	  nop
	SET_SIZE(hv_cngetchar)

	ENTRY(hv_tod_get)
	mov	%o0, %o4
	mov	TOD_GET, %o5
	ta	FAST_TRAP
	retl
	  stx	%o1, [%o4]
	SET_SIZE(hv_tod_get)

	ENTRY(hv_tod_set)
	mov	TOD_SET, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_tod_set)

	/*
	 * Map permanent address
	 * arg0 vaddr (%o0)
	 * arg1 context (%o1)
	 * arg2 tte (%o2)
	 * arg3 flags (%o3)  0x1=d 0x2=i
	 */
	ENTRY(hv_mmu_map_perm_addr)
	mov	MAP_PERM_ADDR, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_mmu_map_perm_addr)

	/*
	 * hv_mmu_fault_area_conf(void *raddr)
	 */
	ENTRY(hv_mmu_fault_area_conf)
	mov	%o0, %o2
	ldx	[%o2], %o0
	mov	MMU_SET_INFOPTR, %o5
	ta	FAST_TRAP
	stx	%o1, [%o2]
	retl
	  nop
	SET_SIZE(hv_mmu_fault_area_conf)

	/*
	 * Unmap permanent address
	 * arg0 vaddr (%o0)
	 * arg1 context (%o1)
	 * arg2 flags (%o2)  0x1=d 0x2=i
	 */
	ENTRY(hv_mmu_unmap_perm_addr)
	mov	UNMAP_PERM_ADDR, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_mmu_unmap_perm_addr)

	/*
	 * Set TSB for context 0
	 * arg0 ntsb_descriptor (%o0)
	 * arg1 desc_ra (%o1)
	 */
	ENTRY(hv_set_ctx0)
	mov	MMU_TSB_CTX0, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_set_ctx0)

	/*
	 * Set TSB for context non0
	 * arg0 ntsb_descriptor (%o0)
	 * arg1 desc_ra (%o1)
	 */
	ENTRY(hv_set_ctxnon0)
	mov	MMU_TSB_CTXNON0, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_set_ctxnon0)

#ifdef SET_MMU_STATS
	/*
	 * Returns old stat area on success
	 */
	ENTRY(hv_mmu_set_stat_area)
	mov	MMU_STAT_AREA, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_mmu_set_stat_area)
#endif /* SET_MMU_STATS */

	/*
	 * CPU Q Configure
	 * arg0 queue (%o0)
	 * arg1 Base address RA (%o1)
	 * arg2 Size (%o2)
	 */
	ENTRY(hv_cpu_qconf)
	mov	HV_CPU_QCONF, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_cpu_qconf)

	/*
	 * arg0 - devhandle
	 * arg1 - devino
	 *
	 * ret0 - status
	 * ret1 - sysino
	 */
	ENTRY(hvio_intr_devino_to_sysino)
	mov	HVIO_INTR_DEVINO2SYSINO, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stx	%o1, [%o2]
1:	retl
	nop
	SET_SIZE(hvio_intr_devino_to_sysino)

	/*
	 * arg0 - sysino
	 *
	 * ret0 - status
	 * ret1 - intr_valid_state
	 */
	ENTRY(hvio_intr_getvalid)
	mov	%o1, %o2
	mov	HVIO_INTR_GETVALID, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stuw	%o1, [%o2]
1:	retl
	nop
	SET_SIZE(hvio_intr_getvalid)

	/*
	 * arg0 - sysino
	 * arg1 - intr_valid_state
	 *
	 * ret0 - status
	 */
	ENTRY(hvio_intr_setvalid)
	mov	HVIO_INTR_SETVALID, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hvio_intr_setvalid)

	/*
	 * arg0 - sysino
	 *
	 * ret0 - status
	 * ret1 - intr_state
	 */
	ENTRY(hvio_intr_getstate)
	mov	%o1, %o2
	mov	HVIO_INTR_GETSTATE, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stuw	%o1, [%o2]
1:	retl
	nop
	SET_SIZE(hvio_intr_getstate)

	/*
	 * arg0 - sysino
	 * arg1 - intr_state
	 *
	 * ret0 - status
	 */
	ENTRY(hvio_intr_setstate)
	mov	HVIO_INTR_SETSTATE, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hvio_intr_setstate)

	/*
	 * arg0 - sysino
	 *
	 * ret0 - status
	 * ret1 - cpu_id
	 */
	ENTRY(hvio_intr_gettarget)
	mov	%o1, %o2
	mov	HVIO_INTR_GETTARGET, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stuw	%o1, [%o2]
1:	retl
	nop
	SET_SIZE(hvio_intr_gettarget)

	/*
	 * arg0 - sysino
	 * arg1 - cpu_id
	 *
	 * ret0 - status
	 */
	ENTRY(hvio_intr_settarget)
	mov	HVIO_INTR_SETTARGET, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hvio_intr_settarget)

	/*
	 * hv_cpu_yield(void)
	 */
	ENTRY(hv_cpu_yield)
	mov	HV_CPU_YIELD, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_cpu_yield)

	/*
	 * int hv_cpu_state(uint64_t cpuid, uint64_t *cpu_state);
	 */
	ENTRY(hv_cpu_state)
	mov	%o1, %o4			! save datap
	mov	HV_CPU_STATE, %o5
	ta	FAST_TRAP
	brz,a	%o0, 1f
	stx	%o1, [%o4]
1:
	retl
	nop
	SET_SIZE(hv_cpu_state)

	/*
	 * HV state dump zone Configure
	 * arg0 real adrs of dump buffer (%o0)
	 * arg1 size of dump buffer (%o1)
	 * ret0 status (%o0)
	 * ret1 size of buffer on success and min size on EINVAL (%o1)
	 * hv_dump_buf_update(uint64_t paddr, uint64_t size, uint64_t *ret_size)
	 */
	ENTRY(hv_dump_buf_update)
	mov	DUMP_BUF_UPDATE, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%o2]
	SET_SIZE(hv_dump_buf_update)

	/*
	 * arg0 - timeout value (%o0)
	 *
	 * ret0 - status (%o0)
	 * ret1 - time_remaining (%o1)
	 * hv_mach_set_watchdog(uint64_t timeout, uint64_t *time_remaining)
	 */
	ENTRY(hv_mach_set_watchdog)
	mov	%o1, %o2
	mov	MACH_SET_WATCHDOG, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%o2]
	SET_SIZE(hv_mach_set_watchdog)

	/*
	 * For memory scrub
	 * int hv_mem_scrub(uint64_t real_addr, uint64_t length,
	 * 	uint64_t *scrubbed_len);
	 * Retun %o0 -- status
	 *       %o1 -- bytes scrubbed
	 */
	ENTRY(hv_mem_scrub)
	mov	%o2, %o4
	mov	HV_MEM_SCRUB, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%o4]
	SET_SIZE(hv_mem_scrub)

	/*
	 * Flush ecache
	 * int hv_mem_sync(uint64_t real_addr, uint64_t length,
	 * 	uint64_t *flushed_len);
	 * Retun %o0 -- status
	 *       %o1 -- bytes flushed
	 */
	ENTRY(hv_mem_sync)
	mov	%o2, %o4
	mov	HV_MEM_SYNC, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%o4]
	SET_SIZE(hv_mem_sync)

	/*
	 * uint64_t hv_tm_enable(uint64_t enable)
	 */
	ENTRY(hv_tm_enable)
	mov	HV_TM_ENABLE, %o5
	ta	FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_tm_enable)

	/*
	 * TTRACE_BUF_CONF Configure
	 * arg0 RA base of buffer (%o0)
	 * arg1 buf size in no. of entries (%o1)
	 * ret0 status (%o0)
	 * ret1 minimum size in no. of entries on failure,
	 * actual size in no. of entries on success (%o1)
	 */
	ENTRY(hv_ttrace_buf_conf)
	mov	TTRACE_BUF_CONF, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%o2]
	SET_SIZE(hv_ttrace_buf_conf)

	 /*
	 * TTRACE_BUF_INFO
	 * ret0 status (%o0)
	 * ret1 RA base of buffer (%o1)
	 * ret2 size in no. of entries (%o2)
	 */
	ENTRY(hv_ttrace_buf_info)
	mov	%o0, %o3
	mov	%o1, %o4
	mov	TTRACE_BUF_INFO, %o5
	ta	FAST_TRAP
	stx	%o1, [%o3]
	retl
	stx	%o2, [%o4]
	SET_SIZE(hv_ttrace_buf_info)

	/*
	 * TTRACE_ENABLE
	 * arg0 enable/ disable (%o0)
	 * ret0 status (%o0)
	 * ret1 previous enable state (%o1)
	 */
	ENTRY(hv_ttrace_enable)
	mov	%o1, %o2
	mov	TTRACE_ENABLE, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%o2]
	SET_SIZE(hv_ttrace_enable)

	/*
	 * TTRACE_FREEZE
	 * arg0 enable/ freeze (%o0)
	 * ret0 status (%o0)
	 * ret1 previous freeze state (%o1)
	 */
	ENTRY(hv_ttrace_freeze)
	mov	%o1, %o2
	mov	TTRACE_FREEZE, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%o2]
	SET_SIZE(hv_ttrace_freeze)

	/*
	 * MACH_DESC
	 * arg0 buffer real address
	 * arg1 pointer to uint64_t for size of buffer
	 * ret0 status
	 * ret1 return required size of buffer / returned data size
	 */
	ENTRY(hv_mach_desc)
	mov     %o1, %o4                ! save datap
	ldx     [%o1], %o1
	mov     HV_MACH_DESC, %o5
	ta      FAST_TRAP
	retl
	stx   %o1, [%o4]
	SET_SIZE(hv_mach_desc)

	/*
	 * hv_ra2pa(uint64_t ra)
	 *
	 * MACH_DESC
	 * arg0 Real address to convert
	 * ret0 Returned physical address or -1 on error
	 */
	ENTRY(hv_ra2pa)
	mov	HV_RA2PA, %o5
	ta	FAST_TRAP
	cmp	%o0, 0
	move	%xcc, %o1, %o0
	movne	%xcc, -1, %o0
	retl
	nop
	SET_SIZE(hv_ra2pa)

	/*
	 * hv_hpriv(void *func, uint64_t arg1, uint64_t arg2, uint64_t arg3)
	 *
	 * MACH_DESC
	 * arg0 OS function to call
	 * arg1 First arg to OS function
	 * arg2 Second arg to OS function
	 * arg3 Third arg to OS function
	 * ret0 Returned value from function
	 */

	ENTRY(hv_hpriv)
	mov	HV_HPRIV, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_hpriv)

	/*
         * hv_ldc_tx_qconf(uint64_t channel, uint64_t ra_base,
	 *	uint64_t nentries);
	 */
	ENTRY(hv_ldc_tx_qconf)
	mov     LDC_TX_QCONF, %o5
	ta      FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_ldc_tx_qconf)


	/*
         * hv_ldc_tx_qinfo(uint64_t channel, uint64_t *ra_base,
	 *	uint64_t *nentries);
	 */
	ENTRY(hv_ldc_tx_qinfo)
	mov	%o1, %g1
	mov	%o2, %g2
	mov     LDC_TX_QINFO, %o5
	ta      FAST_TRAP
	stx     %o1, [%g1]
	retl
	  stx   %o2, [%g2]
	SET_SIZE(hv_ldc_tx_qinfo)


	/*
	 * hv_ldc_tx_get_state(uint64_t channel,
	 *	uint64_t *headp, uint64_t *tailp, uint64_t *state);
	 */
	ENTRY(hv_ldc_tx_get_state)
	mov     LDC_TX_GET_STATE, %o5
	mov     %o1, %g1
	mov     %o2, %g2
	mov     %o3, %g3
	ta      FAST_TRAP
	stx     %o1, [%g1]
	stx     %o2, [%g2]
	retl
	  stx   %o3, [%g3]
	SET_SIZE(hv_ldc_tx_get_state)


	/*
	 * hv_ldc_tx_set_qtail(uint64_t channel, uint64_t tail)
	 */
	ENTRY(hv_ldc_tx_set_qtail)
	mov     LDC_TX_SET_QTAIL, %o5
	ta      FAST_TRAP
	retl
	SET_SIZE(hv_ldc_tx_set_qtail)


	/*
         * hv_ldc_rx_qconf(uint64_t channel, uint64_t ra_base,
	 *	uint64_t nentries);
	 */
	ENTRY(hv_ldc_rx_qconf)
	mov     LDC_RX_QCONF, %o5
	ta      FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_ldc_rx_qconf)


	/*
         * hv_ldc_rx_qinfo(uint64_t channel, uint64_t *ra_base,
	 *	uint64_t *nentries);
	 */
	ENTRY(hv_ldc_rx_qinfo)
	mov	%o1, %g1
	mov	%o2, %g2
	mov     LDC_RX_QINFO, %o5
	ta      FAST_TRAP
	stx     %o1, [%g1]
	retl
	  stx   %o2, [%g2]
	SET_SIZE(hv_ldc_rx_qinfo)


	/*
	 * hv_ldc_rx_get_state(uint64_t channel,
	 *	uint64_t *headp, uint64_t *tailp, uint64_t *state);
	 */
	ENTRY(hv_ldc_rx_get_state)
	mov     LDC_RX_GET_STATE, %o5
	mov     %o1, %g1
	mov     %o2, %g2
	mov     %o3, %g3
	ta      FAST_TRAP
	stx     %o1, [%g1]
	stx     %o2, [%g2]
	retl
	  stx   %o3, [%g3]
	SET_SIZE(hv_ldc_rx_get_state)


	/*
	 * hv_ldc_rx_set_qhead(uint64_t channel, uint64_t head)
	 */
	ENTRY(hv_ldc_rx_set_qhead)
	mov     LDC_RX_SET_QHEAD, %o5
	ta      FAST_TRAP
	retl
	SET_SIZE(hv_ldc_rx_set_qhead)

	/*
	 * hv_ldc_set_map_table(uint64_t channel, uint64_t tbl_ra,
	 *		uint64_t tbl_entries)
	 */
	ENTRY(hv_ldc_set_map_table)
	mov     LDC_SET_MAP_TABLE, %o5
	ta      FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_ldc_set_map_table)


	/*
	 * hv_ldc_get_map_table(uint64_t channel, uint64_t *tbl_ra,
	 *		uint64_t *tbl_entries)
	 */
	ENTRY(hv_ldc_get_map_table)
	mov	%o1, %g1
	mov	%o2, %g2
	mov     LDC_GET_MAP_TABLE, %o5
	ta      FAST_TRAP
	stx     %o1, [%g1]
	retl
	  stx     %o2, [%g2]
	SET_SIZE(hv_ldc_get_map_table)


	/*
	 * hv_ldc_copy(uint64_t channel, uint64_t request, uint64_t cookie,
	 *		uint64_t raddr, uint64_t length, uint64_t *lengthp);
	 */
	ENTRY(hv_ldc_copy)
	mov     %o5, %g1
	mov     LDC_COPY, %o5
	ta      FAST_TRAP
	retl
	  stx   %o1, [%g1]
	SET_SIZE(hv_ldc_copy)


	/*
	 * hv_ldc_mapin(uint64_t channel, uint64_t cookie, uint64_t *raddr,
	 *		uint64_t *perm)
	 */
	ENTRY(hv_ldc_mapin)
	mov	%o2, %g1
	mov	%o3, %g2
	mov     LDC_MAPIN, %o5
	ta      FAST_TRAP
	stx     %o1, [%g1]
	retl
	  stx     %o2, [%g2]
	SET_SIZE(hv_ldc_mapin)


	/*
	 * hv_ldc_unmap(uint64_t raddr)
	 */
	ENTRY(hv_ldc_unmap)
	mov     LDC_UNMAP, %o5
	ta      FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_ldc_unmap)


	/*
	 * hv_ldc_revoke(uint64_t channel, uint64_t cookie,
	 *		 uint64_t revoke_cookie
	 */
	ENTRY(hv_ldc_revoke)
	mov     LDC_REVOKE, %o5
	ta      FAST_TRAP
	retl
	  nop
	SET_SIZE(hv_ldc_revoke)

	/*
	 * hv_ldc_mapin_size_max(uint64_t tbl_type, uint64_t *sz)
	 */
	ENTRY(hv_ldc_mapin_size_max)
	mov	%o1, %g1
	mov     LDC_MAPIN_SIZE_MAX, %o5
	ta      FAST_TRAP
	retl
	  stx     %o1, [%g1]
	SET_SIZE(hv_ldc_mapin_size_max)

	/*
	 * hvldc_intr_getcookie(uint64_t dev_hdl, uint32_t devino,
	 *			uint64_t *cookie);
	 */
	ENTRY(hvldc_intr_getcookie)
	mov	%o2, %g1
	mov     VINTR_GET_COOKIE, %o5
	ta      FAST_TRAP
	retl
	  stx   %o1, [%g1]
	SET_SIZE(hvldc_intr_getcookie)

	/*
	 * hvldc_intr_setcookie(uint64_t dev_hdl, uint32_t devino,
	 *			uint64_t cookie);
	 */
	ENTRY(hvldc_intr_setcookie)
	mov     VINTR_SET_COOKIE, %o5
	ta      FAST_TRAP
	retl
	  nop
	SET_SIZE(hvldc_intr_setcookie)


	/*
	 * hvldc_intr_getvalid(uint64_t dev_hdl, uint32_t devino,
	 *			int *intr_valid_state);
	 */
	ENTRY(hvldc_intr_getvalid)
	mov	%o2, %g1
	mov     VINTR_GET_VALID, %o5
	ta      FAST_TRAP
	retl
	  stuw   %o1, [%g1]
	SET_SIZE(hvldc_intr_getvalid)

	/*
	 * hvldc_intr_setvalid(uint64_t dev_hdl, uint32_t devino,
	 *			int intr_valid_state);
	 */
	ENTRY(hvldc_intr_setvalid)
	mov     VINTR_SET_VALID, %o5
	ta      FAST_TRAP
	retl
	  nop
	SET_SIZE(hvldc_intr_setvalid)

	/*
	 * hvldc_intr_getstate(uint64_t dev_hdl, uint32_t devino,
	 *			int *intr_state);
	 */
	ENTRY(hvldc_intr_getstate)
	mov	%o2, %g1
	mov     VINTR_GET_STATE, %o5
	ta      FAST_TRAP
	retl
	  stuw   %o1, [%g1]
	SET_SIZE(hvldc_intr_getstate)

	/*
	 * hvldc_intr_setstate(uint64_t dev_hdl, uint32_t devino,
	 *			int intr_state);
	 */
	ENTRY(hvldc_intr_setstate)
	mov     VINTR_SET_STATE, %o5
	ta      FAST_TRAP
	retl
	  nop
	SET_SIZE(hvldc_intr_setstate)

	/*
	 * hvldc_intr_gettarget(uint64_t dev_hdl, uint32_t devino,
	 *			uint32_t *cpuid);
	 */
	ENTRY(hvldc_intr_gettarget)
	mov	%o2, %g1
	mov     VINTR_GET_TARGET, %o5
	ta      FAST_TRAP
	retl
	  stuw   %o1, [%g1]
	SET_SIZE(hvldc_intr_gettarget)

	/*
	 * hvldc_intr_settarget(uint64_t dev_hdl, uint32_t devino,
	 *			uint32_t cpuid);
	 */
	ENTRY(hvldc_intr_settarget)
	mov     VINTR_SET_TARGET, %o5
	ta      FAST_TRAP
	retl
	  nop
	SET_SIZE(hvldc_intr_settarget)

	/*
	 * hv_api_get_version(uint64_t api_group, uint64_t *majorp,
	 *			uint64_t *minorp)
	 *
	 * API_GET_VERSION
	 * arg0 API group
	 * ret0 status
	 * ret1 major number
	 * ret2 minor number
	 */
	ENTRY(hv_api_get_version)
	mov	%o1, %o3
	mov	%o2, %o4
	mov	API_GET_VERSION, %o5
	ta	CORE_TRAP
	stx	%o1, [%o3]
	retl
	  stx	%o2, [%o4]
	SET_SIZE(hv_api_get_version)

	/*
	 * hv_api_set_version(uint64_t api_group, uint64_t major,
	 *			uint64_t minor, uint64_t *supported_minor)
	 *
	 * API_SET_VERSION
	 * arg0 API group
	 * arg1 major number
	 * arg2 requested minor number
	 * ret0 status
	 * ret1 actual minor number
	 */
	ENTRY(hv_api_set_version)
	mov	%o3, %o4
	mov	API_SET_VERSION, %o5
	ta	CORE_TRAP
	retl
	  stx	%o1, [%o4]
	SET_SIZE(hv_api_set_version)

	/*
	 * %o0 - buffer real address
	 * %o1 - buffer size
	 * %o2 - &characters written
	 * returns
	 * 	status
	 */
	ENTRY(hv_cnwrite)
	mov	CONS_WRITE, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%o2]
	SET_SIZE(hv_cnwrite)

	/*
	 * %o0 character buffer ra
	 * %o1 buffer size
	 * %o2 pointer to returned size
	 * return values:
	 * 0 success
	 * hv_errno failure
	 */
	ENTRY(hv_cnread)
	mov	CONS_READ, %o5
	ta	FAST_TRAP
	brnz,a	%o0, 1f		! failure, just return error
	nop

	cmp	%o1, H_BREAK
	be	1f
	mov	%o1, %o0

	cmp	%o1, H_HUP
	be	1f
	mov	%o1, %o0

	stx	%o1, [%o2]	! success, save count and return 0
	mov	0, %o0
1:
	retl
	nop
	SET_SIZE(hv_cnread)

	/*
	 * SOFT_STATE_SET
	 * arg0 state (%o0)
	 * arg1 string (%o1)
	 * ret0 status (%o0)
	 */
	ENTRY(hv_soft_state_set)
	mov	SOFT_STATE_SET, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_soft_state_set)

	/*
	 * SOFT_STATE_GET
	 * arg0 string buffer (%o0)
	 * ret0 status (%o0)
	 * ret1 current state (%o1)
	 */
	ENTRY(hv_soft_state_get)
	mov	%o1, %o2
	mov	SOFT_STATE_GET, %o5
	ta	FAST_TRAP
	retl
	stx	%o1, [%o2]
	SET_SIZE(hv_soft_state_get)

	ENTRY(hv_guest_suspend)
	mov	GUEST_SUSPEND, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_guest_suspend)

	ENTRY(hv_tick_set_npt)
	mov	TICK_SET_NPT, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_tick_set_npt)

	ENTRY(hv_stick_set_npt)
	mov	STICK_SET_NPT, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_stick_set_npt)

	/*
	 * REBOOT_DATA_SET
	 * arg0 buffer real address
	 * arg1 buffer length
	 * ret0 status
	 */
	ENTRY(hv_reboot_data_set)
	mov	HV_REBOOT_DATA_SET, %o5
	ta	FAST_TRAP
	retl
	nop
	SET_SIZE(hv_reboot_data_set)

