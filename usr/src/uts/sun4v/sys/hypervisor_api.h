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

#ifndef _SYS_HYPERVISOR_API_H
#define	_SYS_HYPERVISOR_API_H

/*
 * sun4v Hypervisor API
 *
 * Reference: api.pdf Revision 0.12 dated May 12, 2004.
 *	      io-api.txt version 1.11 dated 10/19/2004
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Trap types
 */
#define	FAST_TRAP		0x80	/* Function # in %o5 */
#define	CPU_TICK_NPT		0x81
#define	CPU_STICK_NPT		0x82
#define	MMU_MAP_ADDR		0x83
#define	MMU_UNMAP_ADDR		0x84
#define	MMU_MAP_TTE		0x86

#define	CORE_TRAP		0xff

/*
 * Error returns in %o0.
 * (Additional result is returned in %o1.)
 */
#define	H_EOK			0	/* Successful return */
#define	H_ENOCPU		1	/* Invalid CPU id */
#define	H_ENORADDR		2	/* Invalid real address */
#define	H_ENOINTR		3	/* Invalid interrupt id */
#define	H_EBADPGSZ		4	/* Invalid pagesize encoding */
#define	H_EBADTSB		5	/* Invalid TSB description */
#define	H_EINVAL		6	/* Invalid argument */
#define	H_EBADTRAP		7	/* Invalid function number */
#define	H_EBADALIGN		8	/* Invalid address alignment */
#define	H_EWOULDBLOCK		9	/* Cannot complete operation */
					/* without blocking */
#define	H_ENOACCESS		10	/* No access to resource */
#define	H_EIO			11	/* I/O error */
#define	H_ECPUERROR		12	/* CPU is in error state */
#define	H_ENOTSUPPORTED		13	/* Function not supported */
#define	H_ENOMAP		14	/* Mapping is not valid, */
					/* no translation exists */
#define	H_EBUSY			17	/* Resource busy */
#define	H_ETOOMANY		15	/* Hard resource limit exceeded */
#define	H_ECHANNEL		16	/* Illegal LDC channel */

#define	H_BREAK			-1	/* Console Break */
#define	H_HUP			-2	/* Console Break */

/*
 * Mondo CPU ID argument processing.
 */
#define	HV_SEND_MONDO_ENTRYDONE	0xffff

/*
 * Function numbers for FAST_TRAP.
 */
#define	HV_MACH_EXIT		0x00
#define	HV_MACH_DESC		0x01
#define	HV_MACH_SIR		0x02
#define	MACH_SET_WATCHDOG	0x05

#define	HV_CPU_START		0x10
#define	HV_CPU_STOP		0x11
#define	HV_CPU_YIELD		0x12
#define	HV_CPU_QCONF		0x14
#define	HV_CPU_STATE		0x17
#define	HV_CPU_SET_RTBA		0x18

#define	MMU_TSB_CTX0		0x20
#define	MMU_TSB_CTXNON0		0x21
#define	MMU_DEMAP_PAGE		0x22
#define	MMU_DEMAP_CTX		0x23
#define	MMU_DEMAP_ALL		0x24
#define	MAP_PERM_ADDR		0x25
#define	MMU_SET_INFOPTR		0x26
#define	MMU_ENABLE		0x27
#define	UNMAP_PERM_ADDR		0x28

#define	HV_MEM_SCRUB		0x31
#define	HV_MEM_SYNC		0x32
#define	HV_MEM_IFLUSH		0x33
#define	HV_MEM_IFLUSH_ALL	0x34

#define	HV_INTR_SEND		0x42

#define	TOD_GET			0x50
#define	TOD_SET			0x51

#define	CONS_GETCHAR		0x60
#define	CONS_PUTCHAR		0x61
#define	CONS_READ		0x62
#define	CONS_WRITE		0x63

#define	SOFT_STATE_SET		0x70
#define	SOFT_STATE_GET		0x71

#define	TTRACE_BUF_CONF		0x90
#define	TTRACE_BUF_INFO		0x91
#define	TTRACE_ENABLE		0x92
#define	TTRACE_FREEZE		0x93
#define	DUMP_BUF_UPDATE		0x94

#define	HVIO_INTR_DEVINO2SYSINO	0xa0
#define	HVIO_INTR_GETVALID	0xa1
#define	HVIO_INTR_SETVALID	0xa2
#define	HVIO_INTR_GETSTATE	0xa3
#define	HVIO_INTR_SETSTATE	0xa4
#define	HVIO_INTR_GETTARGET	0xa5
#define	HVIO_INTR_SETTARGET	0xa6

#define	VINTR_GET_COOKIE	0xa7
#define	VINTR_SET_COOKIE	0xa8
#define	VINTR_GET_VALID		0xa9
#define	VINTR_SET_VALID		0xaa
#define	VINTR_GET_STATE		0xab
#define	VINTR_SET_STATE		0xac
#define	VINTR_GET_TARGET	0xad
#define	VINTR_SET_TARGET	0xae

#define	LDC_TX_QCONF		0xe0
#define	LDC_TX_QINFO		0xe1
#define	LDC_TX_GET_STATE	0xe2
#define	LDC_TX_SET_QTAIL	0xe3
#define	LDC_RX_QCONF		0xe4
#define	LDC_RX_QINFO		0xe5
#define	LDC_RX_GET_STATE	0xe6
#define	LDC_RX_SET_QHEAD	0xe7

#define	LDC_SET_MAP_TABLE	0xea
#define	LDC_GET_MAP_TABLE	0xeb
#define	LDC_COPY		0xec
#define	LDC_MAPIN		0xed
#define	LDC_UNMAP		0xee
#define	LDC_REVOKE		0xef

#ifdef SET_MMU_STATS
#define	MMU_STAT_AREA		0xfc
#endif /* SET_MMU_STATS */

#define	HV_TM_ENABLE		0x180

#define	HV_RA2PA		0x200
#define	HV_HPRIV		0x201

/*
 * Function numbers for CORE_TRAP.
 */
#define	API_SET_VERSION		0x00
#define	API_PUT_CHAR		0x01
#define	API_EXIT		0x02
#define	API_GET_VERSION		0x03


/*
 * Definitions for MACH_SOFT_STATE routines
 */

#define	SIS_NORMAL		0x01
#define	SIS_TRANSITION		0x02

/*
 * Bits for MMU functions flags argument:
 *	arg3 of MMU_MAP_ADDR
 *	arg3 of MMU_DEMAP_CTX
 *	arg2 of MMU_DEMAP_ALL
 */
#define	MAP_DTLB		0x1
#define	MAP_ITLB		0x2


/*
 * Interrupt state manipulation definitions.
 */

#define	HV_INTR_IDLE_STATE	0
#define	HV_INTR_RECEIVED_STATE	1
#define	HV_INTR_DELIVERED_STATE	2

#define	HV_INTR_NOTVALID	0
#define	HV_INTR_VALID		1

#ifndef _ASM

/*
 * TSB description structure for MMU_TSB_CTX0 and MMU_TSB_CTXNON0.
 */
typedef struct hv_tsb_info {
	uint16_t	hvtsb_idxpgsz;	/* page size used to index TSB */
	uint16_t	hvtsb_assoc;	/* TSB associativity */
	uint32_t	hvtsb_ntte;	/* TSB size (#TTE entries) */
	uint32_t	hvtsb_ctx_index; /* context reg index */
	uint32_t	hvtsb_pgszs;	/* sizes in use */
	uint64_t	hvtsb_pa;	/* real address of TSB base */
	uint64_t	hvtsb_rsvd;	/* reserved */
} hv_tsb_info_t;

#define	HVTSB_SHARE_INDEX	((uint32_t)-1)

#ifdef SET_MMU_STATS
#ifndef TTE4V_NPGSZ
#define	TTE4V_NPGSZ	8
#endif /* TTE4V_NPGSZ */
/*
 * MMU statistics structure for MMU_STAT_AREA
 */
struct mmu_stat_one {
	uint64_t	hit_ctx0[TTE4V_NPGSZ];
	uint64_t	hit_ctxn0[TTE4V_NPGSZ];
	uint64_t	tsb_miss;
	uint64_t	tlb_miss;	/* miss, no TSB set */
	uint64_t	map_ctx0[TTE4V_NPGSZ];
	uint64_t	map_ctxn0[TTE4V_NPGSZ];
};

struct mmu_stat {
	struct mmu_stat_one	immu_stat;
	struct mmu_stat_one	dmmu_stat;
	uint64_t		set_ctx0;
	uint64_t		set_ctxn0;
};
#endif /* SET_MMU_STATS */

#endif /* ! _ASM */

/*
 * CPU States
 */
#define	CPU_STATE_INVALID	0x0
#define	CPU_STATE_STOPPED	0x1	/* cpu not started */
#define	CPU_STATE_RUNNING	0x2	/* cpu running guest code */
#define	CPU_STATE_ERROR		0x3	/* cpu is in the error state */
#define	CPU_STATE_LAST_PUBLIC	CPU_STATE_ERROR	/* last valid state */

/*
 * MMU fault status area
 */

#define	MMFSA_TYPE_	0x00	/* fault type */
#define	MMFSA_ADDR_	0x08	/* fault address */
#define	MMFSA_CTX_	0x10	/* fault context */

#define	MMFSA_I_	0x00		/* start of fields for I */
#define	MMFSA_I_TYPE	(MMFSA_I_ + MMFSA_TYPE_) /* instruction fault type */
#define	MMFSA_I_ADDR	(MMFSA_I_ + MMFSA_ADDR_) /* instruction fault address */
#define	MMFSA_I_CTX	(MMFSA_I_ + MMFSA_CTX_)	/* instruction fault context */

#define	MMFSA_D_	0x40		/* start of fields for D */
#define	MMFSA_D_TYPE	(MMFSA_D_ + MMFSA_TYPE_) /* data fault type */
#define	MMFSA_D_ADDR	(MMFSA_D_ + MMFSA_ADDR_) /* data fault address */
#define	MMFSA_D_CTX	(MMFSA_D_ + MMFSA_CTX_)	/* data fault context */

#define	MMFSA_F_FMISS	1	/* fast miss */
#define	MMFSA_F_FPROT	2	/* fast protection */
#define	MMFSA_F_MISS	3	/* mmu miss */
#define	MMFSA_F_INVRA	4	/* invalid RA */
#define	MMFSA_F_PRIV	5	/* privilege violation */
#define	MMFSA_F_PROT	6	/* protection violation */
#define	MMFSA_F_NFO	7	/* NFO access */
#define	MMFSA_F_SOPG	8	/* so page */
#define	MMFSA_F_INVVA	9	/* invalid VA */
#define	MMFSA_F_INVASI	10	/* invalid ASI */
#define	MMFSA_F_NCATM	11	/* non-cacheable atomic */
#define	MMFSA_F_PRVACT	12	/* privileged action */
#define	MMFSA_F_WPT	13	/* watchpoint hit */
#define	MMFSA_F_UNALIGN	14	/* unaligned access */
#define	MMFSA_F_INVPGSZ	15	/* invalid page size */

#define	MMFSA_SIZE	0x80	/* in bytes, 64 byte aligned */

/*
 * MMU fault status - MMFSA_IFS and MMFSA_DFS
 */
#define	MMFS_FV		0x00000001
#define	MMFS_OW		0x00000002
#define	MMFS_W		0x00000004
#define	MMFS_PR		0x00000008
#define	MMFS_CT		0x00000030
#define	MMFS_E		0x00000040
#define	MMFS_FT		0x00003f80
#define	MMFS_ME		0x00004000
#define	MMFS_TM		0x00008000
#define	MMFS_ASI	0x00ff0000
#define	MMFS_NF		0x01000000

/*
 * DMA sync parameter definitions
 */
#define	HVIO_DMA_SYNC_DIR_TO_DEV		0x01
#define	HVIO_DMA_SYNC_DIR_FROM_DEV		0x02
#define	HVIO_DMA_SYNC_DIR_NO_ICACHE_FLUSH	0x04

/*
 * LDC Channel States
 */
#define	LDC_CHANNEL_DOWN	0x0
#define	LDC_CHANNEL_UP		0x1
#define	LDC_CHANNEL_RESET	0x2

#ifndef _ASM

extern uint64_t hv_mmu_map_perm_addr(void *, int, uint64_t, int);
extern uint64_t	hv_mmu_unmap_perm_addr(void *, int, int);
extern uint64_t hv_mach_exit(uint64_t exit_code);
extern uint64_t hv_mach_sir(void);

extern uint64_t hv_cpu_start(uint64_t cpuid, uint64_t pc, uint64_t rtba,
    uint64_t arg);
extern uint64_t hv_cpu_stop(uint64_t cpuid);
extern uint64_t hv_cpu_set_rtba(uint64_t *rtba);

extern uint64_t	hv_set_ctx0(uint64_t, uint64_t);
extern uint64_t	hv_set_ctxnon0(uint64_t, uint64_t);
extern uint64_t hv_mmu_fault_area_conf(void *raddr);
#ifdef SET_MMU_STATS
extern uint64_t hv_mmu_set_stat_area(uint64_t, uint64_t);
#endif /* SET_MMU_STATS */

extern uint64_t hv_cpu_qconf(int queue, uint64_t paddr, int size);
extern uint64_t hv_cpu_yield(void);
extern uint64_t hv_cpu_state(uint64_t cpuid, uint64_t *cpu_state);
extern uint64_t hv_mem_scrub(uint64_t real_addr, uint64_t length,
    uint64_t *scrubbed_len);
extern uint64_t hv_mem_sync(uint64_t real_addr, uint64_t length,
    uint64_t *flushed_len);
extern uint64_t hv_mem_iflush(uint64_t real_addr, uint64_t length,
    uint64_t *flushed_len);
extern uint64_t hv_mem_iflush_all(void);
extern uint64_t hv_tm_enable(uint64_t enable);

extern uint64_t hv_service_recv(uint64_t s_id, uint64_t buf_pa,
    uint64_t size, uint64_t *recv_bytes);
extern uint64_t hv_service_send(uint64_t s_id, uint64_t buf_pa,
    uint64_t size, uint64_t *send_bytes);
extern uint64_t hv_service_getstatus(uint64_t s_id, uint64_t *vreg);
extern uint64_t hv_service_setstatus(uint64_t s_id, uint64_t bits);
extern uint64_t hv_service_clrstatus(uint64_t s_id, uint64_t bits);
extern uint64_t hv_mach_desc(uint64_t buffer_ra, uint64_t *buffer_sizep);

extern uint64_t hv_ttrace_buf_info(uint64_t *, uint64_t *);
extern uint64_t hv_ttrace_buf_conf(uint64_t, uint64_t, uint64_t *);
extern uint64_t hv_ttrace_enable(uint64_t, uint64_t *);
extern uint64_t hv_ttrace_freeze(uint64_t, uint64_t *);
extern uint64_t hv_dump_buf_update(uint64_t, uint64_t, uint64_t *);
extern uint64_t hv_mach_set_watchdog(uint64_t, uint64_t *);

extern int64_t hv_cnputchar(uint8_t);
extern int64_t hv_cngetchar(uint8_t *);
extern int64_t hv_cnwrite(uint64_t, uint64_t, uint64_t *);
extern int64_t hv_cnread(uint64_t, uint64_t, int64_t *);

extern uint64_t hv_tod_get(uint64_t *seconds);
extern uint64_t hv_tod_set(uint64_t);

extern uint64_t hvio_intr_devino_to_sysino(uint64_t dev_hdl, uint32_t devino,
    uint64_t *sysino);
extern uint64_t hvio_intr_getvalid(uint64_t sysino,
	int *intr_valid_state);
extern uint64_t hvio_intr_setvalid(uint64_t sysino,
	int intr_valid_state);
extern uint64_t hvio_intr_getstate(uint64_t sysino,
	int *intr_state);
extern uint64_t hvio_intr_setstate(uint64_t sysino, int intr_state);
extern uint64_t hvio_intr_gettarget(uint64_t sysino, uint32_t *cpuid);
extern uint64_t hvio_intr_settarget(uint64_t sysino, uint32_t cpuid);
extern uint64_t hv_soft_state_set(uint64_t state, uint64_t string_ra);
extern uint64_t hv_soft_state_get(uint64_t string_ra, uint64_t *state);

extern uint64_t hv_ldc_tx_qconf(uint64_t channel, uint64_t ra_base,
    uint64_t nentries);
extern uint64_t hv_ldc_tx_qinfo(uint64_t channel, uint64_t *ra_base,
    uint64_t *nentries);
extern uint64_t hv_ldc_tx_get_state(uint64_t channel, uint64_t *headp,
    uint64_t *tailp, uint64_t *state);
extern uint64_t hv_ldc_tx_set_qtail(uint64_t channel, uint64_t tail);
extern uint64_t hv_ldc_rx_qconf(uint64_t channel, uint64_t ra_base,
    uint64_t nentries);
extern uint64_t hv_ldc_rx_qinfo(uint64_t channel, uint64_t *ra_base,
    uint64_t *nentries);
extern uint64_t hv_ldc_rx_get_state(uint64_t channel, uint64_t *headp,
    uint64_t *tailp, uint64_t *state);
extern uint64_t hv_ldc_rx_set_qhead(uint64_t channel, uint64_t head);

extern uint64_t hv_ldc_set_map_table(uint64_t channel, uint64_t tbl_ra,
    uint64_t tbl_entries);
extern uint64_t hv_ldc_get_map_table(uint64_t channel, uint64_t *tbl_ra,
    uint64_t *tbl_entries);
extern uint64_t hv_ldc_copy(uint64_t channel, uint64_t request,
    uint64_t cookie, uint64_t raddr, uint64_t length, uint64_t *lengthp);
extern uint64_t hv_ldc_mapin(uint64_t channel, uint64_t cookie,
    uint64_t *raddr, uint64_t *perm);
extern uint64_t hv_ldc_unmap(uint64_t raddr);
extern uint64_t hv_ldc_revoke(uint64_t channel, uint64_t cookie,
    uint64_t revoke_cookie);
extern uint64_t hv_api_get_version(uint64_t api_group, uint64_t *majorp,
    uint64_t *minorp);
extern uint64_t hv_api_set_version(uint64_t api_group, uint64_t major,
    uint64_t minor, uint64_t *supported_minor);

extern uint64_t hvldc_intr_getcookie(uint64_t dev_hdl, uint32_t devino,
    uint64_t *cookie);
extern uint64_t hvldc_intr_setcookie(uint64_t dev_hdl, uint32_t devino,
    uint64_t cookie);
extern uint64_t hvldc_intr_getvalid(uint64_t dev_hdl, uint32_t devino,
    int *intr_valid_state);
extern uint64_t hvldc_intr_setvalid(uint64_t dev_hdl, uint32_t devino,
    int intr_valid_state);
extern uint64_t hvldc_intr_getstate(uint64_t dev_hdl, uint32_t devino,
    int *intr_state);
extern uint64_t hvldc_intr_setstate(uint64_t dev_hdl, uint32_t devino,
    int intr_state);
extern uint64_t hvldc_intr_gettarget(uint64_t dev_hdl, uint32_t devino,
    uint32_t *cpuid);
extern uint64_t hvldc_intr_settarget(uint64_t dev_hdl, uint32_t devino,
    uint32_t cpuid);

#endif /* ! _ASM */


#ifdef __cplusplus
}
#endif

#endif /* _SYS_HYPERVISOR_API_H */
