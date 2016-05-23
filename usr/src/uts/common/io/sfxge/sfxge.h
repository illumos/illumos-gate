/*
 * Copyright (c) 2008-2016 Solarflare Communications Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing official
 * policies, either expressed or implied, of the FreeBSD Project.
 */

#ifndef	_SYS_SFXGE_H
#define	_SYS_SFXGE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stream.h>
#include <sys/ethernet.h>
#include <sys/cpuvar.h>

#include <sys/mac.h>
#include <sys/mac_ether.h>
#include <sys/mac_provider.h>

#include "sfxge_ioc.h"
#include "sfxge_debug.h"

#include "efx.h"
#include "efx_regs.h"

#ifdef	_KERNEL

#define	SFXGE_DRIVER_NAME "sfxge"

#define	SFXGE_CPU_CACHE_SIZE	64

typedef struct sfxge_s	sfxge_t;

typedef enum sfxge_intr_state_e {
	SFXGE_INTR_UNINITIALIZED = 0,
	SFXGE_INTR_INITIALIZED,
	SFXGE_INTR_TESTING,
	SFXGE_INTR_STARTED
} sfxge_intr_state_t;

typedef struct sfxge_intr_s {
	ddi_intr_handle_t	*si_table;
	int			si_table_size;
	int			si_nalloc;
	int			si_type;
	int			si_cap;
	efsys_mem_t		si_mem;
	uint64_t		si_mask;
	sfxge_intr_state_t	si_state;
	uint32_t		si_zero_count;
	int			si_intr_pri;
} sfxge_intr_t;

typedef enum sfxge_promisc_type_e {
	SFXGE_PROMISC_OFF = 0,
	SFXGE_PROMISC_ALL_MULTI,
	SFXGE_PROMISC_ALL_PHYS
} sfxge_promisc_type_t;

typedef enum sfxge_link_duplex_e {
	SFXGE_LINK_DUPLEX_UNKNOWN = 0,
	SFXGE_LINK_DUPLEX_HALF,
	SFXGE_LINK_DUPLEX_FULL
} sfxge_link_duplex_t;

typedef enum sfxge_unicst_type_e {
	SFXGE_UNICST_BIA = 0,
	SFXGE_UNICST_LAA,
	SFXGE_UNICST_NTYPES
} sfxge_unicst_type_t;

typedef struct sfxge_phy_s {
		kstat_t			*sp_ksp;
		kstat_named_t		*sp_stat;
		uint32_t		*sp_statbuf;
		efsys_mem_t		sp_mem;
} sfxge_phy_t;

typedef enum sfxge_mac_state_e {
	SFXGE_MAC_UNINITIALIZED = 0,
	SFXGE_MAC_INITIALIZED,
	SFXGE_MAC_STARTED
} sfxge_mac_state_t;

typedef struct sfxge_mac_s {
	sfxge_t			*sm_sp;
	efsys_mem_t		sm_mem;
	kstat_t			*sm_ksp;
	kstat_named_t		*sm_stat;
	uint8_t			sm_bia[ETHERADDRL];
	uint8_t			sm_laa[ETHERADDRL];
	boolean_t		sm_laa_valid;
	unsigned int		sm_fcntl;
	sfxge_promisc_type_t	sm_promisc;
	uint8_t			sm_mcast_addr[EFX_MAC_MULTICAST_LIST_MAX *
	    ETHERADDRL]; /* List of multicast addresses to filter on */
	int			sm_mcast_count;
	clock_t			sm_lbolt;
	kmutex_t		sm_lock;
	efx_link_mode_t		sm_link_mode;
	unsigned int		sm_link_speed;
	sfxge_link_duplex_t	sm_link_duplex;
	boolean_t		sm_link_up;
	boolean_t		sm_link_poll_reqd;
	kcondvar_t		sm_link_poll_kv;
	boolean_t		sm_mac_stats_timer_reqd;
	boolean_t		sm_mac_stats_pend;
	ddi_taskq_t		*sm_tqp;
	sfxge_mac_state_t	sm_state;
	sfxge_phy_t		sm_phy;
	uint32_t		sm_phy_cap_to_set;
	uint32_t		sm_phy_cap_to_unset;
} sfxge_mac_t;

typedef enum sfxge_mon_state_e {
	SFXGE_MON_UNINITIALIZED = 0,
	SFXGE_MON_INITIALIZED,
	SFXGE_MON_STARTED
} sfxge_mon_state_t;

typedef struct sfxge_mon_s {
	sfxge_t			*sm_sp;
	efx_mon_type_t		sm_type;
	unsigned int		sm_devid;
	kstat_t			*sm_ksp;
	kstat_named_t		*sm_stat;
	efx_mon_stat_value_t	*sm_statbuf;
	kmutex_t		sm_lock;
	sfxge_mon_state_t	sm_state;
	efsys_mem_t		sm_mem;
	int			sm_polling;
} sfxge_mon_t;

typedef enum sfxge_sram_state_e {
	SFXGE_SRAM_UNINITIALIZED = 0,
	SFXGE_SRAM_INITIALIZED,
	SFXGE_SRAM_STARTED
} sfxge_sram_state_t;

typedef struct sfxge_sram_s {
	sfxge_t			*ss_sp;
	kmutex_t		ss_lock;
	struct map		*ss_buf_tbl_map;
	unsigned int		ss_count;
	sfxge_sram_state_t	ss_state;
} sfxge_sram_t;

typedef enum sfxge_mcdi_state_e {
	SFXGE_MCDI_UNINITIALIZED = 0,
	SFXGE_MCDI_INITIALIZED,
	SFXGE_MCDI_BUSY,
	SFXGE_MCDI_COMPLETED
} sfxge_mcdi_state_t;

typedef struct sfxge_mcdi_s {
	sfxge_t			*sm_sp;
	kmutex_t		sm_lock;
	sfxge_mcdi_state_t	sm_state;
	efx_mcdi_transport_t	sm_emt;
	efsys_mem_t		sm_mem;
	kcondvar_t		sm_kv;		/* MCDI poll complete */
} sfxge_mcdi_t;

#define	SFXGE_NEVS			4096
#define	SFXGE_RX_NDESCS			1024
#define	SFXGE_TX_NDESCS			1024
#define	SFXGE_TX_NLABELS		EFX_EV_TX_NLABELS

#define	SFXGE_DEFAULT_RXQ_SIZE		1024
#define	SFXGE_DEFAULT_MODERATION	30

typedef enum sfxge_evq_state_e {
	SFXGE_EVQ_UNINITIALIZED = 0,
	SFXGE_EVQ_INITIALIZED,
	SFXGE_EVQ_STARTING,
	SFXGE_EVQ_STARTED
} sfxge_evq_state_t;

#define	SFXGE_EV_BATCH	(SFXGE_NEVS / 4)

typedef struct sfxge_txq_s	sfxge_txq_t;

typedef struct sfxge_evq_s {
	union {
		struct {
			sfxge_t			*__se_sp;
			unsigned int		__se_index;
			efsys_mem_t		__se_mem;
			unsigned int		__se_id;
			kstat_t			*__se_ksp;
			kstat_named_t		*__se_stat;
			efx_ev_callbacks_t	__se_eec;
			sfxge_evq_state_t	__se_state;
			boolean_t		__se_exception;
		} __se_s1;
		uint8_t __se_pad[SFXGE_CPU_CACHE_SIZE * 4];
	} __se_u1;
	union {
		struct {
			kmutex_t		__se_lock;
			kcondvar_t		__se_init_kv;
			efx_evq_t		*__se_eep;
			unsigned int		__se_count;
			unsigned int		__se_rx;
			unsigned int		__se_tx;
			sfxge_txq_t		*__se_stp;
			sfxge_txq_t		**__se_stpp;
			processorid_t		__se_cpu_id;
			uint16_t		__se_ev_batch;
		} __se_s2;
		uint8_t	__se_pad[SFXGE_CPU_CACHE_SIZE];
	} __se_u2;
	union {
		struct {
			sfxge_txq_t	*__se_label_stp[SFXGE_TX_NLABELS];
		} __se_s3;
		uint8_t	__se_pad[SFXGE_CPU_CACHE_SIZE * 4];
	} __se_u3;
} sfxge_evq_t;

#define	se_sp		__se_u1.__se_s1.__se_sp
#define	se_index	__se_u1.__se_s1.__se_index
#define	se_mem		__se_u1.__se_s1.__se_mem
#define	se_id		__se_u1.__se_s1.__se_id
#define	se_ksp		__se_u1.__se_s1.__se_ksp
#define	se_stat		__se_u1.__se_s1.__se_stat
#define	se_eec		__se_u1.__se_s1.__se_eec
#define	se_state	__se_u1.__se_s1.__se_state
#define	se_exception	__se_u1.__se_s1.__se_exception

#define	se_lock		__se_u2.__se_s2.__se_lock
#define	se_init_kv	__se_u2.__se_s2.__se_init_kv
#define	se_eep		__se_u2.__se_s2.__se_eep
#define	se_count	__se_u2.__se_s2.__se_count
#define	se_rx		__se_u2.__se_s2.__se_rx
#define	se_tx		__se_u2.__se_s2.__se_tx
#define	se_stp		__se_u2.__se_s2.__se_stp
#define	se_stpp		__se_u2.__se_s2.__se_stpp
#define	se_cpu_id	__se_u2.__se_s2.__se_cpu_id
#define	se_ev_batch	__se_u2.__se_s2.__se_ev_batch

#define	se_label_stp	__se_u3.__se_s3.__se_label_stp


#define	SFXGE_MAGIC_RESERVED	0x8000

#define	SFXGE_MAGIC_DMAQ_LABEL_WIDTH  5
#define	SFXGE_MAGIC_DMAQ_LABEL_MASK   ((1 << SFXGE_MAGIC_DMAQ_LABEL_WIDTH) - 1)

#define	SFXGE_MAGIC_RX_QFLUSH_DONE					\
	(SFXGE_MAGIC_RESERVED | (1 << SFXGE_MAGIC_DMAQ_LABEL_WIDTH))

#define	SFXGE_MAGIC_RX_QFLUSH_FAILED					\
	(SFXGE_MAGIC_RESERVED | (2 << SFXGE_MAGIC_DMAQ_LABEL_WIDTH))

#define	SFXGE_MAGIC_RX_QFPP_TRIM					\
	(SFXGE_MAGIC_RESERVED | (3 << SFXGE_MAGIC_DMAQ_LABEL_WIDTH))

#define	SFXGE_MAGIC_TX_QFLUSH_DONE					\
	(SFXGE_MAGIC_RESERVED | (4 << SFXGE_MAGIC_DMAQ_LABEL_WIDTH))

typedef struct sfxge_rxq_s		sfxge_rxq_t;

#define	SFXGE_ETHERTYPE_LOOPBACK	0x9000	/* Xerox loopback */

typedef struct sfxge_rx_packet_s	sfxge_rx_packet_t;

struct sfxge_rx_packet_s {
	union {
		struct {
			frtn_t			__srp_free;
			uint16_t		__srp_flags;
			uint16_t		__srp_size;
			mblk_t			*__srp_mp;
			struct ether_header	*__srp_etherhp;
			struct ip		*__srp_iphp;
			struct tcphdr		*__srp_thp;
			size_t			__srp_off;
		} __srp_s1;
		uint8_t	__srp_pad[SFXGE_CPU_CACHE_SIZE];
	} __srp_u1;
	union {
		struct {
			sfxge_rxq_t		*__srp_srp;
			ddi_dma_handle_t	__srp_dma_handle;
			ddi_acc_handle_t	__srp_acc_handle;
			unsigned char		*__srp_base;
			size_t			__srp_mblksize;
			uint64_t		__srp_addr;
			boolean_t		__srp_recycle;
			caddr_t			__srp_putp;
		} __srp_s2;
		uint8_t	__srp_pad[SFXGE_CPU_CACHE_SIZE * 2];
	} __srp_u2;
};

#define	srp_free	__srp_u1.__srp_s1.__srp_free
#define	srp_flags	__srp_u1.__srp_s1.__srp_flags
#define	srp_size	__srp_u1.__srp_s1.__srp_size
#define	srp_mp		__srp_u1.__srp_s1.__srp_mp
#define	srp_etherhp	__srp_u1.__srp_s1.__srp_etherhp
#define	srp_iphp	__srp_u1.__srp_s1.__srp_iphp
#define	srp_thp		__srp_u1.__srp_s1.__srp_thp
#define	srp_off		__srp_u1.__srp_s1.__srp_off

#define	srp_srp		__srp_u2.__srp_s2.__srp_srp
#define	srp_dma_handle	__srp_u2.__srp_s2.__srp_dma_handle
#define	srp_acc_handle	__srp_u2.__srp_s2.__srp_acc_handle
#define	srp_base	__srp_u2.__srp_s2.__srp_base
#define	srp_mblksize	__srp_u2.__srp_s2.__srp_mblksize
#define	srp_addr	__srp_u2.__srp_s2.__srp_addr
#define	srp_recycle	__srp_u2.__srp_s2.__srp_recycle
#define	srp_putp	__srp_u2.__srp_s2.__srp_putp

#define	SFXGE_RX_FPP_NSLOTS	8
#define	SFXGE_RX_FPP_MASK	(SFXGE_RX_FPP_NSLOTS - 1)

/* Free packet pool putlist (dynamically allocated) */
typedef struct sfxge_rx_fpp_putlist_s {
	kmutex_t		srfpl_lock;
	unsigned int		srfpl_count;
	mblk_t			*srfpl_putp;
	mblk_t			**srfpl_putpp;
} sfxge_rx_fpp_putlist_t;

/* Free packet pool */
typedef struct sfxge_rx_fpp_s {
	caddr_t		srfpp_putp;
	unsigned int	srfpp_loaned;
	mblk_t		*srfpp_get;
	unsigned int	srfpp_count;
	unsigned int	srfpp_min;
	/* Low water mark: Don't trim to below this */
	unsigned int    srfpp_lowat;
} sfxge_rx_fpp_t;

typedef struct sfxge_rx_flow_s	sfxge_rx_flow_t;

struct sfxge_rx_flow_s {
	uint32_t		srf_tag;
	/* in-order segment count */
	unsigned int		srf_count;
	uint16_t		srf_tci;
	uint32_t		srf_saddr;
	uint32_t		srf_daddr;
	uint16_t		srf_sport;
	uint16_t		srf_dport;
	/* sequence number */
	uint32_t		srf_seq;
	clock_t			srf_lbolt;
	mblk_t			*srf_mp;
	mblk_t			**srf_mpp;
	struct ether_header	*srf_etherhp;
	struct ip		*srf_iphp;
	struct tcphdr		*srf_first_thp;
	struct tcphdr		*srf_last_thp;
	size_t			srf_len;
	sfxge_rx_flow_t		*srf_next;
};

#define	SFXGE_MAX_FLOW		1024
#define	SFXGE_SLOW_START	20

typedef enum sfxge_flush_state_e {
	SFXGE_FLUSH_INACTIVE = 0,
	SFXGE_FLUSH_DONE,
	SFXGE_FLUSH_PENDING,
	SFXGE_FLUSH_FAILED
} sfxge_flush_state_t;

typedef enum sfxge_rxq_state_e {
	SFXGE_RXQ_UNINITIALIZED = 0,
	SFXGE_RXQ_INITIALIZED,
	SFXGE_RXQ_STARTED
} sfxge_rxq_state_t;


#define	SFXGE_RX_BATCH	128
#define	SFXGE_RX_NSTATS	8 /* note that *esballoc share one kstat */

struct sfxge_rxq_s {
	union {
		struct {
			sfxge_t				*__sr_sp;
			unsigned int			__sr_index;
			efsys_mem_t			__sr_mem;
			unsigned int			__sr_id;
			unsigned int			__sr_lowat;
			unsigned int			__sr_hiwat;
			volatile timeout_id_t		__sr_tid;
			sfxge_rxq_state_t		__sr_state;
		} __sr_s1;
		uint8_t	__sr_pad[SFXGE_CPU_CACHE_SIZE * 2];
	} __sr_u1;
	union {
		struct {
			sfxge_rx_packet_t		**__sr_srpp;
			unsigned int			__sr_added;
			unsigned int			__sr_pushed;
			unsigned int			__sr_pending;
			unsigned int			__sr_completed;
			unsigned int			__sr_loopback;
			mblk_t   			*__sr_mp;
			mblk_t   			**__sr_mpp;
			sfxge_rx_flow_t			*__sr_flow;
			sfxge_rx_flow_t			*__sr_srfp;
			sfxge_rx_flow_t			**__sr_srfpp;
			clock_t				__sr_rto;
		} __sr_s2;
		uint8_t	__sr_pad[SFXGE_CPU_CACHE_SIZE * 2];
	} __sr_u2;
	union {
		struct {
			sfxge_rx_fpp_t			__sr_fpp;
			efx_rxq_t			*__sr_erp;
			volatile sfxge_flush_state_t	__sr_flush;
			kcondvar_t			__sr_flush_kv;
			kstat_t				*__sr_ksp;
		} __sr_s3;
		uint8_t	__sr_pad[SFXGE_CPU_CACHE_SIZE];
	} __sr_u3;
	struct {
		/* NB must match SFXGE_RX_NSTATS */
		uint32_t    srk_rx_pkt_mem_limit;
		uint32_t    srk_kcache_alloc_nomem;
		uint32_t    srk_dma_alloc_nomem;
		uint32_t    srk_dma_alloc_fail;
		uint32_t    srk_dma_bind_nomem;
		uint32_t    srk_dma_bind_fail;
		uint32_t    srk_desballoc_fail;
		uint32_t    srk_rxq_empty_discard;
	} sr_kstat;
};

#define	sr_sp		__sr_u1.__sr_s1.__sr_sp
#define	sr_index	__sr_u1.__sr_s1.__sr_index
#define	sr_mem		__sr_u1.__sr_s1.__sr_mem
#define	sr_id		__sr_u1.__sr_s1.__sr_id
#define	sr_mrh		__sr_u1.__sr_s1.__sr_mrh
#define	sr_lowat	__sr_u1.__sr_s1.__sr_lowat
#define	sr_hiwat	__sr_u1.__sr_s1.__sr_hiwat
#define	sr_tid		__sr_u1.__sr_s1.__sr_tid
#define	sr_state	__sr_u1.__sr_s1.__sr_state

#define	sr_srpp		__sr_u2.__sr_s2.__sr_srpp
#define	sr_added	__sr_u2.__sr_s2.__sr_added
#define	sr_pushed	__sr_u2.__sr_s2.__sr_pushed
#define	sr_pending	__sr_u2.__sr_s2.__sr_pending
#define	sr_completed	__sr_u2.__sr_s2.__sr_completed
#define	sr_loopback	__sr_u2.__sr_s2.__sr_loopback
#define	sr_mp		__sr_u2.__sr_s2.__sr_mp
#define	sr_mpp		__sr_u2.__sr_s2.__sr_mpp
#define	sr_flow		__sr_u2.__sr_s2.__sr_flow
#define	sr_srfp		__sr_u2.__sr_s2.__sr_srfp
#define	sr_srfpp	__sr_u2.__sr_s2.__sr_srfpp
#define	sr_rto		__sr_u2.__sr_s2.__sr_rto

#define	sr_fpp		__sr_u3.__sr_s3.__sr_fpp
#define	sr_erp		__sr_u3.__sr_s3.__sr_erp
#define	sr_flush	__sr_u3.__sr_s3.__sr_flush
#define	sr_flush_kv	__sr_u3.__sr_s3.__sr_flush_kv
#define	sr_ksp		__sr_u3.__sr_s3.__sr_ksp

typedef struct sfxge_tx_packet_s	sfxge_tx_packet_t;

/* Packet type from parsing transmit packet */
typedef enum sfxge_packet_type_e {
	SFXGE_PACKET_TYPE_UNKNOWN = 0,
	SFXGE_PACKET_TYPE_IPV4_TCP,
	SFXGE_PACKET_TYPE_IPV4_UDP,
	SFXGE_PACKET_TYPE_IPV4_SCTP,
	SFXGE_PACKET_TYPE_IPV4_OTHER,
	SFXGE_PACKET_NTYPES
} sfxge_packet_type_t;

struct sfxge_tx_packet_s {
	sfxge_tx_packet_t	*stp_next;
	mblk_t			*stp_mp;
	struct ether_header	*stp_etherhp;
	struct ip 		*stp_iphp;
	struct tcphdr		*stp_thp;
	size_t			stp_off;
	size_t			stp_size;
	size_t			stp_mss;
	uint32_t		stp_dpl_put_len;
};

#define	SFXGE_TX_FPP_MAX	64

typedef struct sfxge_tx_fpp_s {
	sfxge_tx_packet_t	*stf_stpp;
	unsigned int		stf_count;
} sfxge_tx_fpp_t;

typedef struct sfxge_tx_mapping_s	sfxge_tx_mapping_t;

#define	SFXGE_TX_MAPPING_NADDR	(((1 << 16) >> 12) + 2)

struct sfxge_tx_mapping_s {
	sfxge_tx_mapping_t	*stm_next;
	sfxge_t			*stm_sp;
	mblk_t			*stm_mp;
	ddi_dma_handle_t	stm_dma_handle;
	caddr_t			stm_base;
	size_t			stm_size;
	size_t			stm_off;
	uint64_t		stm_addr[SFXGE_TX_MAPPING_NADDR];
};

typedef struct sfxge_tx_fmp_s {
	sfxge_tx_mapping_t	*stf_stmp;
	unsigned int		stf_count;
} sfxge_tx_fmp_t;

typedef struct sfxge_tx_buffer_s	sfxge_tx_buffer_t;

struct sfxge_tx_buffer_s {
	sfxge_tx_buffer_t	*stb_next;
	size_t			stb_off;
	efsys_mem_t		stb_esm;
};

#define	SFXGE_TX_BUFFER_SIZE	0x400
#define	SFXGE_TX_HEADER_SIZE	0x100
#define	SFXGE_TX_COPY_THRESHOLD	0x200

typedef struct sfxge_tx_fbp_s {
	sfxge_tx_buffer_t	*stf_stbp;
	unsigned int		stf_count;
} sfxge_tx_fbp_t;

typedef struct sfxge_tx_dpl_s {
	uintptr_t		std_put;
	sfxge_tx_packet_t	*std_get;
	sfxge_tx_packet_t	**std_getp;
	unsigned int		std_count; /* only get list count */
	unsigned int		get_pkt_limit;
	unsigned int		put_pkt_limit;
	unsigned int		get_full_count;
	unsigned int		put_full_count;
} sfxge_tx_dpl_t;

typedef enum sfxge_txq_state_e {
	SFXGE_TXQ_UNINITIALIZED = 0,
	SFXGE_TXQ_INITIALIZED,
	SFXGE_TXQ_STARTED,
	SFXGE_TXQ_FLUSH_PENDING,
	SFXGE_TXQ_FLUSH_DONE,
	SFXGE_TXQ_FLUSH_FAILED
} sfxge_txq_state_t;

typedef enum sfxge_txq_type_e {
	SFXGE_TXQ_NON_CKSUM = 0,
	SFXGE_TXQ_IP_CKSUM,
	SFXGE_TXQ_IP_TCP_UDP_CKSUM,
	SFXGE_TXQ_NTYPES
} sfxge_txq_type_t;

#define	SFXGE_TXQ_UNBLOCK_LEVEL1	(EFX_TXQ_LIMIT(SFXGE_TX_NDESCS) / 4)
#define	SFXGE_TXQ_UNBLOCK_LEVEL2	0
#define	SFXGE_TXQ_NOT_BLOCKED		-1

#define	SFXGE_TX_BATCH	64

struct sfxge_txq_s {
	union {
		struct {
			sfxge_t				*__st_sp;
			unsigned int			__st_index;
			unsigned int			__st_label;
			sfxge_txq_type_t		__st_type;
			unsigned int			__st_evq;
			efsys_mem_t			__st_mem;
			unsigned int			__st_id;
			kstat_t				*__st_ksp;
			kstat_named_t			*__st_stat;
			sfxge_txq_state_t		__st_state;
		} __st_s1;
		uint8_t	__st_pad[SFXGE_CPU_CACHE_SIZE * 2];
	} __st_u1;
	union {
		struct {
			sfxge_tx_dpl_t			__st_dpl;
		} __st_s2;
		uint8_t	__st_pad[SFXGE_CPU_CACHE_SIZE];
	} __st_u2;
	union {
		struct {
			kmutex_t			__st_lock;
			/* mapping pool - sfxge_tx_mapping_t */
			sfxge_tx_fmp_t			__st_fmp;
			/* buffer pool - sfxge_tx_buffer_t */
			sfxge_tx_fbp_t			__st_fbp;
			/* packet pool - sfxge_tx_packet_t */
			sfxge_tx_fpp_t			__st_fpp;
			efx_buffer_t			*__st_eb;
			unsigned int			__st_n;
			efx_txq_t			*__st_etp;
			sfxge_tx_mapping_t		**__st_stmp;
			sfxge_tx_buffer_t		**__st_stbp;
			mblk_t				**__st_mp;
			unsigned int			__st_added;
			unsigned int			__st_reaped;
			int				__st_unblock;
		} __st_s3;
		uint8_t	__st_pad[SFXGE_CPU_CACHE_SIZE * 3];
	} __st_u3;
	union {
		struct {
			sfxge_txq_t			*__st_next;
			unsigned int			__st_pending;
			unsigned int			__st_completed;

		} __st_s4;
		uint8_t	__st_pad[SFXGE_CPU_CACHE_SIZE];
	} __st_u4;
};

#define	st_sp		__st_u1.__st_s1.__st_sp
#define	st_index	__st_u1.__st_s1.__st_index
#define	st_label	__st_u1.__st_s1.__st_label
#define	st_type		__st_u1.__st_s1.__st_type
#define	st_evq		__st_u1.__st_s1.__st_evq
#define	st_mem		__st_u1.__st_s1.__st_mem
#define	st_id		__st_u1.__st_s1.__st_id
#define	st_ksp		__st_u1.__st_s1.__st_ksp
#define	st_stat		__st_u1.__st_s1.__st_stat
#define	st_state	__st_u1.__st_s1.__st_state

#define	st_dpl		__st_u2.__st_s2.__st_dpl

#define	st_lock		__st_u3.__st_s3.__st_lock
#define	st_fmp		__st_u3.__st_s3.__st_fmp
#define	st_fbp		__st_u3.__st_s3.__st_fbp
#define	st_fpp		__st_u3.__st_s3.__st_fpp
#define	st_eb		__st_u3.__st_s3.__st_eb
#define	st_n		__st_u3.__st_s3.__st_n
#define	st_etp		__st_u3.__st_s3.__st_etp
#define	st_stmp		__st_u3.__st_s3.__st_stmp
#define	st_stbp		__st_u3.__st_s3.__st_stbp
#define	st_mp		__st_u3.__st_s3.__st_mp
#define	st_added	__st_u3.__st_s3.__st_added
#define	st_reaped	__st_u3.__st_s3.__st_reaped
#define	st_unblock	__st_u3.__st_s3.__st_unblock

#define	st_next		__st_u4.__st_s4.__st_next
#define	st_pending	__st_u4.__st_s4.__st_pending
#define	st_completed	__st_u4.__st_s4.__st_completed

typedef enum sfxge_rx_scale_state_e {
	SFXGE_RX_SCALE_UNINITIALIZED = 0,
	SFXGE_RX_SCALE_INITIALIZED,
	SFXGE_RX_SCALE_STARTED
} sfxge_rx_scale_state_t;

#define	SFXGE_RX_SCALE_MAX	EFX_RSS_TBL_SIZE

typedef struct sfxge_rx_scale_s {
	kmutex_t		srs_lock;
	unsigned int		*srs_cpu;
	unsigned int		srs_tbl[SFXGE_RX_SCALE_MAX];
	unsigned int		srs_count;
	kstat_t			*srs_ksp;
	sfxge_rx_scale_state_t	srs_state;
} sfxge_rx_scale_t;


typedef enum sfxge_rx_coalesce_mode_e {
	SFXGE_RX_COALESCE_OFF = 0,
	SFXGE_RX_COALESCE_DISALLOW_PUSH = 1,
	SFXGE_RX_COALESCE_ALLOW_PUSH = 2
} sfxge_rx_coalesce_mode_t;

typedef enum sfxge_vpd_type_e {
	SFXGE_VPD_ID = 0,
	SFXGE_VPD_PN = 1,
	SFXGE_VPD_SN = 2,
	SFXGE_VPD_EC = 3,
	SFXGE_VPD_MN = 4,
	SFXGE_VPD_VD = 5,
	SFXGE_VPD_VE = 6,
	SFXGE_VPD_MAX = 7,
} sfxge_vpd_type_t;

typedef struct sfxge_vpd_kstat_s {
	kstat_t		*svk_ksp;
	kstat_named_t	svk_stat[SFXGE_VPD_MAX];
	efx_vpd_value_t	*svk_vv;
} sfxge_vpd_kstat_t;

typedef struct sfxge_cfg_kstat_s {
	struct {
		kstat_named_t	sck_mac;
		kstat_named_t	sck_version;
	} kstat;
	struct {
		char		sck_mac[64 + 1];
	} buf;
} sfxge_cfg_kstat_t;

typedef enum sfxge_state_e {
	SFXGE_UNINITIALIZED = 0,
	SFXGE_INITIALIZED,
	SFXGE_REGISTERED,
	SFXGE_STARTING,
	SFXGE_STARTED,
	SFXGE_STOPPING
} sfxge_state_t;

typedef enum sfxge_hw_err_e {
	SFXGE_HW_OK = 0,
	SFXGE_HW_ERR,
} sfxge_hw_err_t;

typedef enum sfxge_action_on_hw_err_e {
	SFXGE_RECOVER = 0,
	SFXGE_INVISIBLE = 1,
	SFXGE_LEAVE_DEAD = 2,
} sfxge_action_on_hw_err_t;

typedef char *sfxge_mac_priv_prop_t;

#define	SFXGE_TOEPLITZ_KEY_LEN 40

struct sfxge_s {
	kmutex_t			s_state_lock;
	sfxge_state_t			s_state;
	dev_info_t			*s_dip;
	ddi_taskq_t			*s_tqp;
	ddi_acc_handle_t		s_pci_handle;
	uint16_t			s_pci_venid;
	uint16_t			s_pci_devid;
#if EFSYS_OPT_MCDI_LOGGING
	unsigned int			s_bus_addr;
#endif
	efx_family_t			s_family;
	unsigned int			s_pcie_nlanes;
	unsigned int 			s_pcie_linkspeed;
	kmutex_t			s_nic_lock;
	efsys_bar_t			s_bar;
	sfxge_intr_t			s_intr;
	sfxge_mac_t			s_mac;
	sfxge_mon_t			s_mon;
	sfxge_sram_t			s_sram;
	sfxge_mcdi_t			s_mcdi;
	kmem_cache_t			*s_eq0c; /* eventQ 0 */
	kmem_cache_t			*s_eqXc; /* all other eventQs */
	sfxge_evq_t			*s_sep[SFXGE_RX_SCALE_MAX];
	unsigned int			s_ev_moderation;
	kmem_cache_t			*s_rqc;
	sfxge_rxq_t			*s_srp[SFXGE_RX_SCALE_MAX];
	sfxge_rx_scale_t		s_rx_scale;
	size_t				s_rx_prefix_size;
	size_t				s_rx_buffer_size;
	size_t				s_rx_buffer_align;
	sfxge_rx_coalesce_mode_t	s_rx_coalesce_mode;
	int64_t				s_rx_pkt_mem_max;
	volatile uint64_t		s_rx_pkt_mem_alloc;
	kmem_cache_t			*s_rpc;
	kmem_cache_t			*s_tqc;
	unsigned int			s_tx_scale_base[SFXGE_TXQ_NTYPES];
	unsigned int			s_tx_scale_max[SFXGE_TXQ_NTYPES];
	int 				s_tx_qcount;
	sfxge_txq_t			*s_stp[SFXGE_RX_SCALE_MAX *
	    SFXGE_TXQ_NTYPES]; /* Sparse array */
	kmem_cache_t			*s_tpc;
	int				s_tx_flush_pending;
	kmutex_t			s_tx_flush_lock;
	kcondvar_t			s_tx_flush_kv;
	kmem_cache_t			*s_tbc;
	kmem_cache_t			*s_tmc;
	efx_nic_t			*s_enp;
	sfxge_vpd_kstat_t		s_vpd_kstat;
	sfxge_cfg_kstat_t		s_cfg_kstat;
	kstat_t				*s_cfg_ksp;
	size_t				s_mtu;
	int				s_rxq_poll_usec;
	mac_callbacks_t			s_mc;
	mac_handle_t			s_mh;
	sfxge_mac_priv_prop_t		*s_mac_priv_props;
	int				s_mac_priv_props_alloc;
	volatile uint32_t		s_nested_restarts;
	uint32_t			s_num_restarts;
	uint32_t			s_num_restarts_hw_err;
	sfxge_hw_err_t			s_hw_err;
	sfxge_action_on_hw_err_t	s_action_on_hw_err;
	uint16_t			s_rxq_size;
	uint16_t			s_evq0_size;
	uint16_t			s_evqX_size;
#if EFSYS_OPT_MCDI_LOGGING
	int				s_mcdi_logging;
#endif
	const uint32_t			*s_toeplitz_cache;
};

typedef struct sfxge_dma_buffer_attr_s {
	dev_info_t		*sdba_dip;
	ddi_dma_attr_t		*sdba_dattrp;
	int			(*sdba_callback) (caddr_t);
	size_t			sdba_length;
	uint_t			sdba_memflags;
	ddi_device_acc_attr_t	*sdba_devaccp;
	uint_t			sdba_bindflags;
	int			sdba_maxcookies;
	boolean_t		sdba_zeroinit;
} sfxge_dma_buffer_attr_t;

extern const char		sfxge_ident[];
extern uint8_t			sfxge_brdcst[];

extern kmutex_t			sfxge_global_lock;

extern unsigned int		*sfxge_cpu;

extern int			sfxge_start(sfxge_t *, boolean_t);
extern void			sfxge_stop(sfxge_t *);
extern void			sfxge_ioctl(sfxge_t *, queue_t *, mblk_t *);
extern int			sfxge_restart_dispatch(sfxge_t *, uint_t,
    sfxge_hw_err_t, const char *, uint32_t);

extern void			sfxge_gld_link_update(sfxge_t *);
extern void			sfxge_gld_mtu_update(sfxge_t *);
extern void			sfxge_gld_rx_post(sfxge_t *, unsigned int,
    mblk_t *);
extern void			sfxge_gld_rx_push(sfxge_t *);
extern int			sfxge_gld_register(sfxge_t *);
extern int			sfxge_gld_unregister(sfxge_t *);

extern int			sfxge_dma_buffer_create(efsys_mem_t *,
    const sfxge_dma_buffer_attr_t *);
extern void			sfxge_dma_buffer_destroy(efsys_mem_t *);

extern int			sfxge_intr_init(sfxge_t *);
extern int			sfxge_intr_start(sfxge_t *);
extern void			sfxge_intr_stop(sfxge_t *);
extern void			sfxge_intr_fini(sfxge_t *);
extern void			sfxge_intr_fatal(sfxge_t *);

extern int			sfxge_ev_init(sfxge_t *);
extern int			sfxge_ev_start(sfxge_t *);
extern void			sfxge_ev_moderation_get(sfxge_t *,
    unsigned int *);
extern int			sfxge_ev_moderation_set(sfxge_t *,
    unsigned int);
extern int			sfxge_ev_qmoderate(sfxge_t *, unsigned int,
    unsigned int);
extern int			sfxge_ev_qpoll(sfxge_t *, unsigned int);
extern int			sfxge_ev_qprime(sfxge_t *, unsigned int);
extern void			sfxge_ev_stop(sfxge_t *);
extern void			sfxge_ev_fini(sfxge_t *);
extern int			sfxge_ev_txlabel_alloc(sfxge_t *sp,
    unsigned int evq, sfxge_txq_t *stp, unsigned int *labelp);
extern int			sfxge_ev_txlabel_free(sfxge_t *sp,
    unsigned int evq, sfxge_txq_t *stp, unsigned int label);

extern int			sfxge_mon_init(sfxge_t *);
extern int			sfxge_mon_start(sfxge_t *);
extern void			sfxge_mon_stop(sfxge_t *);
extern void			sfxge_mon_fini(sfxge_t *);

extern int			sfxge_mac_init(sfxge_t *);
extern int			sfxge_mac_start(sfxge_t *, boolean_t);
extern void			sfxge_mac_stat_get(sfxge_t *, unsigned int,
    uint64_t *);
extern void			sfxge_mac_link_check(sfxge_t *, boolean_t *);
extern void			sfxge_mac_link_speed_get(sfxge_t *,
    unsigned int *);
extern void			sfxge_mac_link_duplex_get(sfxge_t *,
    sfxge_link_duplex_t *);
extern void			sfxge_mac_fcntl_get(sfxge_t *, unsigned int *);
extern int			sfxge_mac_fcntl_set(sfxge_t *, unsigned int);
extern int			sfxge_mac_unicst_get(sfxge_t *,
    sfxge_unicst_type_t, uint8_t *);
extern int			sfxge_mac_unicst_set(sfxge_t *,
    uint8_t *);
extern int			sfxge_mac_promisc_set(sfxge_t *,
    sfxge_promisc_type_t);
extern int			sfxge_mac_multicst_add(sfxge_t *,
    uint8_t const *addr);
extern int			sfxge_mac_multicst_remove(sfxge_t *,
    uint8_t const *addr);
extern void			sfxge_mac_stop(sfxge_t *);
extern void			sfxge_mac_fini(sfxge_t *);
extern void			sfxge_mac_link_update(sfxge_t *sp,
    efx_link_mode_t mode);

extern int			sfxge_mcdi_init(sfxge_t *sp);
extern void			sfxge_mcdi_fini(sfxge_t *sp);
extern int			sfxge_mcdi_ioctl(sfxge_t *sp,
    sfxge_mcdi_ioc_t *smip);
extern int			sfxge_mcdi2_ioctl(sfxge_t *sp,
    sfxge_mcdi2_ioc_t *smip);

extern int			sfxge_phy_init(sfxge_t *);
extern void			sfxge_phy_link_mode_get(sfxge_t *,
    efx_link_mode_t *);
extern void			sfxge_phy_fini(sfxge_t *);
extern int			sfxge_phy_kstat_init(sfxge_t *sp);
extern void			sfxge_phy_kstat_fini(sfxge_t *sp);
extern uint8_t			sfxge_phy_lp_cap_test(sfxge_t *sp,
    uint32_t field);
extern int			sfxge_phy_cap_apply(sfxge_t *sp,
    boolean_t use_default);
extern uint8_t			sfxge_phy_cap_test(sfxge_t *sp, uint32_t flags,
    uint32_t field, boolean_t *mutablep);
extern int			sfxge_phy_cap_set(sfxge_t *sp, uint32_t field,
    int set);

extern int			sfxge_rx_init(sfxge_t *);
extern int			sfxge_rx_start(sfxge_t *);
extern void			sfxge_rx_coalesce_mode_get(sfxge_t *,
    sfxge_rx_coalesce_mode_t *);
extern int			sfxge_rx_coalesce_mode_set(sfxge_t *,
    sfxge_rx_coalesce_mode_t);
extern unsigned int		sfxge_rx_scale_prop_get(sfxge_t *);
extern void			sfxge_rx_scale_update(void *);
extern int			sfxge_rx_scale_count_get(sfxge_t *,
    unsigned int *);
extern int			sfxge_rx_scale_count_set(sfxge_t *,
    unsigned int);
extern void			sfxge_rx_qcomplete(sfxge_rxq_t *, boolean_t);
extern void			sfxge_rx_qflush_done(sfxge_rxq_t *);
extern void			sfxge_rx_qflush_failed(sfxge_rxq_t *);
extern void			sfxge_rx_qfpp_trim(sfxge_rxq_t *);
extern void			sfxge_rx_stop(sfxge_t *);
extern unsigned int 		sfxge_rx_loaned(sfxge_t *);
extern void			sfxge_rx_fini(sfxge_t *);

extern int			sfxge_tx_init(sfxge_t *);
extern int			sfxge_tx_start(sfxge_t *);
extern int			sfxge_tx_packet_add(sfxge_t *, mblk_t *);
extern void			sfxge_tx_qcomplete(sfxge_txq_t *);
extern void			sfxge_tx_qflush_done(sfxge_txq_t *);
extern void			sfxge_tx_stop(sfxge_t *);
extern void			sfxge_tx_fini(sfxge_t *);
extern void			sfxge_tx_qdpl_flush(sfxge_txq_t *stp);

extern void			sfxge_sram_init(sfxge_t *);
extern int			sfxge_sram_buf_tbl_alloc(sfxge_t *, size_t,
    uint32_t *);
extern int			sfxge_sram_start(sfxge_t *);
extern int			sfxge_sram_buf_tbl_set(sfxge_t *, uint32_t,
    efsys_mem_t *, size_t);
extern void			sfxge_sram_buf_tbl_clear(sfxge_t *, uint32_t,
    size_t);
extern void			sfxge_sram_stop(sfxge_t *);
extern void			sfxge_sram_buf_tbl_free(sfxge_t *, uint32_t,
    size_t);
extern void			sfxge_sram_fini(sfxge_t *);

extern sfxge_packet_type_t	sfxge_pkthdr_parse(mblk_t *,
    struct ether_header **, struct ip **, struct tcphdr **, size_t *, size_t *,
    uint16_t *, uint16_t *);

extern int sfxge_toeplitz_hash_init(sfxge_t *);
extern void sfxge_toeplitz_hash_fini(sfxge_t *);
extern uint32_t sfxge_toeplitz_hash(sfxge_t *, unsigned int,
    uint8_t *, uint16_t, uint8_t *, uint16_t);

/*
 * 4-tuple hash for TCP/IPv4 used for LRO, TSO and TX queue selection.
 * To compute the same hash value as Siena/Huntington hardware, the inputs
 * must be in big endian (network) byte order.
 */
#define	SFXGE_TCP_HASH(_sp, _raddr, _rport, _laddr, _lport, _hash)	\
	do { \
		(_hash) = sfxge_toeplitz_hash(_sp, \
					sizeof (struct in_addr), \
					(uint8_t *)(_raddr), \
					(_rport), \
					(uint8_t *)(_laddr), \
					(_lport)); \
		_NOTE(CONSTANTCONDITION) \
	} while (B_FALSE)

/*
 * 4-tuple hash for non-TCP IPv4 packets, used for TX queue selection.
 * For UDP or SCTP packets, calculate a 4-tuple hash using port numbers.
 * For other IPv4 non-TCP packets, use zero for the port numbers.
 */
#define	SFXGE_IP_HASH(_sp, _raddr, _rport, _laddr, _lport, _hash)	\
	SFXGE_TCP_HASH((_sp), (_raddr), (_rport), (_laddr), (_lport), (_hash))


extern int		sfxge_nvram_ioctl(sfxge_t *, sfxge_nvram_ioc_t *);

extern int		sfxge_pci_init(sfxge_t *);
extern void		sfxge_pcie_check_link(sfxge_t *, unsigned int,
    unsigned int);
extern void		sfxge_pci_fini(sfxge_t *);

extern int		sfxge_bar_init(sfxge_t *);
extern void		sfxge_bar_fini(sfxge_t *);

extern int		sfxge_vpd_ioctl(sfxge_t *, sfxge_vpd_ioc_t *);


#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SFXGE_H */
