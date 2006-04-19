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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Hypervisor calls
 */

#include <sys/asm_linkage.h>
#include <sys/machasi.h>
#include <sys/machparam.h>
#include <sys/hypervisor_api.h>

#if defined(lint) || defined(__lint)

/*ARGSUSED*/
int64_t
hv_cnputchar(uint8_t ch)
{ return (0); }

/*ARGSUSED*/
int64_t
hv_cngetchar(uint8_t *ch)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_tod_get(uint64_t *seconds)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_tod_set(uint64_t seconds)
{ return (0);}

/*ARGSUSED*/
uint64_t
hv_mmu_map_perm_addr(void *vaddr, int ctx, uint64_t tte, int flags)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_mmu_unmap_perm_addr(void *vaddr, int ctx, int flags)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_set_ctx0(uint64_t ntsb_descriptor, uint64_t desc_ra)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_set_ctxnon0(uint64_t ntsb_descriptor, uint64_t desc_ra)
{ return (0); }

#ifdef SET_MMU_STATS
/*ARGSUSED*/
uint64_t
hv_mmu_set_stat_area(uint64_t rstatarea, uint64_t size)
{ return (0); }
#endif /* SET_MMU_STATS */

/*ARGSUSED*/
uint64_t
hv_cpu_qconf(int queue, uint64_t paddr, int size)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_intr_devino_to_sysino(uint64_t dev_hdl, uint32_t devino, uint64_t *sysino)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_intr_getvalid(uint64_t sysino, int *intr_valid_state)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_intr_setvalid(uint64_t sysino, int intr_valid_state)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_intr_getstate(uint64_t sysino, int *intr_state)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_intr_setstate(uint64_t sysino, int intr_state)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_intr_gettarget(uint64_t sysino, uint32_t *cpuid)
{ return (0); }

/*ARGSUSED*/
uint64_t
hvio_intr_settarget(uint64_t sysino, uint32_t cpuid)
{ return (0); }

uint64_t
hv_cpu_yield(void)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_cpu_state(uint64_t cpuid, uint64_t *cpu_state)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_dump_buf_update(uint64_t paddr, uint64_t size, uint64_t *minsize)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_mem_scrub(uint64_t real_addr, uint64_t length, uint64_t *scrubbed_len)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_mem_sync(uint64_t real_addr, uint64_t length, uint64_t *flushed_len)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_ttrace_buf_conf(uint64_t paddr, uint64_t size, uint64_t *size1)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_ttrace_buf_info(uint64_t *paddr, uint64_t *size)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_ttrace_enable(uint64_t enable, uint64_t *prev_enable)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_ttrace_freeze(uint64_t freeze, uint64_t *prev_freeze)
{ return (0); }

/*ARGSUSED*/
uint64_t
hv_mach_desc(uint64_t buffer_ra, uint64_t *buffer_sizep)
{ return (0); }
	
/*ARGSUSED*/	
uint64_t
hv_ra2pa(uint64_t ra)
{ return (0); }

/*ARGSUSED*/	
uint64_t
hv_hpriv(void *func, uint64_t arg1, uint64_t arg2, uint64_t arg3)
{ return (0); }

#else	/* lint || __lint */

	/*
	 * %o0 - character
	 */
	ENTRY(hv_cnputchar)
	mov	CONS_WRITE, %o5
	ta	FAST_TRAP
	tst	%o0
	retl
	movnz	%xcc, -1, %o0
	SET_SIZE(hv_cnputchar)

	/*
	 * %o0 pointer to character buffer
	 * return values:
	 * 0 success
	 * hv_errno failure
	 */
	ENTRY(hv_cngetchar)
	mov	%o0, %o2
	mov	CONS_READ, %o5
	ta	FAST_TRAP
	brnz,a	%o0, 1f		! failure, just return error
	mov	1, %o0

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
	mov	CPU_QCONF, %o5
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

#endif	/* lint || __lint */
