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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file is part of the Chelsio T1 Ethernet driver.
 *
 * Copyright (C) 2003-2005 Chelsio Communications.  All rights reserved.
 */

#ifndef _CHELSIO_CH_H
#define	_CHELSIO_CH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/debug.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Definitions for module_info
 */

#define	CHIDNUM		(666)		/* module ID number */
#define	CHNAME		"chxge"		/* module name */
#define	CHMINPSZ	(0)		/* min packet size */
#define	CHMAXPSZ	ETHERMTU	/* max packet size */
#define	CHHIWAT		(32 * 1024)	/* hi-water mark */
#define	CHLOWAT		(1)		/* lo-water mark */

#define	CH_NO_HWCKSUM	0x1	/* hardware should no add checksum */
#define	CH_NO_CPL	0x2	/* no cpl header with data */
#define	CH_OFFLOAD	0x4	/* do TCP/IP offload processing */
#define	CH_ARP		0x8	/* dummy arp packet (don't free) */
#define	CH_TCP_MF	0x10	/* Indicator of Fragmented TCP */
#define	CH_UDP_MF	0x20	/* Indicator of Fragmented UDP */
#define	CH_UDP		0x40	/* Indicator of regular TCP */

#define	SZ_INUSE	64	/* # of in use counters */

/*
 * PCI registers
 */
#define	BAR0 1
#define	BAR1 2
#define	BAR2 3
#define	BAR3 4

#ifdef CONFIG_CHELSIO_T1_OFFLOAD
/*
 * TOE pre-mapped buffer structure
 */
typedef struct tbuf {
	struct tbuf	*tb_next;	/* next entry in free list */
	caddr_t		tb_base;	/* base of buffer */
	uint64_t	tb_pa;		/* physical address of buffer */
	ulong_t		tb_dh;		/* dma handle */
	ulong_t		tb_ah;		/* dma address handle */
	void		*tb_sa;		/* address of card ctrl struct */
	uint32_t	tb_debug;	/* initally 0 */
	uint32_t	tb_len;		/* length of data */
} tbuf_t;
#endif	/* CONFIG_CHELSIO_T1_OFFLOAD */

/*
 * header structures to hold pre-mapped (DMA) kernel memory buffers.
 */
typedef struct ch_esb {
	struct ch_esb   *cs_next;	/* next entry in list */
	struct ch_esb   *cs_owner;	/* list of buffers owned by ch_t */
	void		*cs_sa;		/* card structure to get ch ptr */
	ulong_t		cs_dh;		/* dma handle */
	ulong_t		cs_ah;		/* dma address handle */
	caddr_t		cs_buf;		/* vaddr of buffer */
	uint64_t	cs_pa;		/* paddr of buffer */
	uint32_t	cs_index;	/* index of buffer_in_use count */
	uint32_t	cs_flag;	/* if set, commit suicide */
#ifdef FRAGMENT				/* we assume no fragments */
	ddi_dma_cookie_t cs_cookie[MAXFS];
	uint_t		cs_ncookie;
#endif
	frtn_t		cs_frtn;	/* for esballoc */
} ch_esb_t;

/*
 * structure for linked list of multicast addresses that have been
 * assigned to the card.
 */
typedef struct ch_mc {
	struct ch_mc *cmc_next;
	uint8_t cmc_mca[6];
} ch_mc_t;

/*
 * structure for linked list of pre-allocated dma handles for command Q
 */
typedef struct free_dh {
	struct free_dh *dhe_next;
	ulong_t dhe_dh;
} free_dh_t;

/*
 * instance configuration
 */
typedef struct ch_cfg {
	uint32_t cksum_enabled: 1;
	uint32_t burstsize_set: 1;
	uint32_t burstsize: 2;
	uint32_t transaction_cnt_set: 1;
	uint32_t transaction_cnt: 3;
	uint32_t relaxed_ordering: 1;
	uint32_t enable_dvma: 1;
} ch_cfg_t;

/*
 * Per-card state information
 */
typedef struct ch {
	dev_info_t	*ch_dip;	/* device dev info */
	gld_mac_info_t	*ch_macp;	/* gld mac structure */

	ch_cfg_t	ch_config;	/* instance configuration */
	uint_t		ch_flags;	/* state flags */
	uint_t		ch_state;	/* card state */
	uint_t		ch_blked;	/* card is blked on output */
	kmutex_t	ch_lock;	/* lock for ch structure */

	caddr_t		ch_pci;		/* PCI configuration vaddr */
	ddi_acc_handle_t ch_hpci;	/* PCI configuration access handle */
	off_t		ch_pcisz;	/* size of PCI configuration space */

	caddr_t		ch_bar0;	/* PCI BAR0 vaddr */
	ddi_acc_handle_t ch_hbar0;	/* PCI BAR0 access handle */
	off_t		ch_bar0sz;	/* size of BAR0 space */

	ddi_iblock_cookie_t ch_icookp; /* hardware interrupt cookie ptr */
	kmutex_t	ch_intr;	/* lock for interrupts */

	uint32_t	ch_maximum_mtu;	/* maximum mtu for adapter */

	uint32_t	ch_sm_buf_sz;	/* size of sm esballoc bufs */
	uint32_t	ch_sm_buf_aln;	/* alignment of sm esballoc bufs */
	ch_esb_t	*ch_small_esb_free; /* free list sm esballoc bufs */
	ch_esb_t	*ch_small_owner; /* list small bufs owned by ch_t */
	kmutex_t	ch_small_esbl;	/* lock for ch_small_esb list */
	uint_t		ch_sm_index;	/* small buffer in use count index */

	uint32_t	ch_bg_buf_sz;	/* size of bg esballoc bufs */
	uint32_t	ch_bg_buf_aln;	/* alignment of bg esballoc bufs */
	ch_esb_t	*ch_big_esb_free; /* free list of esballoc entries */
	ch_esb_t	*ch_big_owner;	/* list big bufs owned by ch_t */
	kmutex_t	ch_big_esbl;	/* lock for ch_esb list */
	uint_t		ch_big_index;	/* big buffer in use count index */

	kmutex_t	ch_mc_lck;	/* lock of mulitcast list */
	ch_mc_t		*ch_mc;		/* list of multicast entries */
	uint32_t	ch_mc_cnt;	/* cnt of multicast entries */

	/* XXX see how we can use cmdQ_ce list and get rid of lock */
	kmutex_t	ch_dh_lck;	/* lock for ch_dh list */
	free_dh_t	*ch_dh;		/* list of free dma headers for v2p */

#if defined(__sparc)
	/* XXX see how we can use cmdQ_ce list and get rid of lock */
	free_dh_t	*ch_vdh;	/* list of free dvma headers for v2p */
#endif

	uint32_t	ch_ip;		/* ip address from first arp */

	uint32_t	ch_mtu;		/* size of device MTU (1500 default) */

	/* XXX config_data needs cleanup */
	pe_config_data_t config_data;	/* card configuration vector */

	struct pe_port_t port[4];	/* from freebsd/oschtoe.h driver */
	pesge		*sge;
	struct pemc3	*mc3;
	struct pemc4	*mc4;
	struct pemc5	*mc5;
	struct petp	*tp;
	struct pecspi	*cspi;
	struct peespi	*espi;
	struct peulp	*ulp;
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	uint32_t	open_device_map;
#endif
	struct adapter_params params;
	uint16_t	vendor_id;
	uint16_t	device_id;
	uint16_t	device_subid;
	uint16_t	chip_revision;
	uint16_t	chip_version;
	uint32_t	is_asic;
	uint32_t	config;
	uint32_t	ch_unit;
	uint8_t		init_counter;
	char		*ch_name;
	/* statistics per card */
	uint32_t	isr_intr;	/* # interrupts */
	uint32_t	oerr;		/* send error (no mem) */
	uint32_t	norcvbuf;
#ifdef CONFIG_CHELSIO_T1_OFFLOAD
	int		ch_refcnt;
	void		*ch_toeinst;
	void		(*toe_rcv)(void *, mblk_t *);
	void		(*toe_free)(void *, tbuf_t *);
	int		(*toe_tunnel)(void *, mblk_t *);
	kcondvar_t	*ch_tx_overflow_cv;
	kmutex_t	*ch_tx_overflow_mutex;
#endif
	uint32_t	slow_intr_mask;
#ifdef HOST_PAUSE
	uint32_t	txxg_cfg1;	/* Place holder for MAC cfg reg1. */
	int		pause_on;
	hrtime_t	pause_time;
#endif
	kmutex_t	mac_lock;	/* lock for MAC structure */
} ch_t;

/* ch_flags */
#define	PEIDLE		0x00	/* chip is uninitialized */
#define	PERUNNING	0x01	/* chip is initialized */
#define	PEPROMISC	0x04	/* promiscuous mode enabled */
#define	PEALLMULTI	0x08	/* all multicast enabled */
#define	PESUSPENDED	0x20	/* suspended interface */
#define	PENORES		0x40	/* ran out of xmit resources */
#define	PESTOP		0x80	/* gldm_stop done */
#define	PEINITDONE	0x100	/* initialization done */
#define	TSO_CAPABLE	0x200	/* TSO able */

#ifdef CONFIG_CHELSIO_T1_OFFLOAD
/* open_device_map flag */
#define	TOEDEV_DEVMAP_BIT 0x1
#endif

/*
 * DMA mapping defines
 */
#define	DMA_STREAM 1	/* use DDI_DMA_STREAMING for DMA xfers */
#define	DMA_4KALN  2	/* align memory to 4K page boundry */
#define	DMA_OUT    4	/* this is a write buffer */
#define	DMA_SMALN  8	/* aligned at small buffer boundry */
#define	DMA_BGALN  16	/* aligned at big buffer boundry */

/*
 * Number of multicast addresses per stream
 */
#define	CHMAXMC   64
#define	CHMCALLOC (CHMAXMC * sizeof (struct ether_addr))

/* ----- Solaris memory - PCI - DMA mapping functions ------ */

void *ch_alloc_dma_mem(ch_t *, int, int, int, uint64_t *, ulong_t *, ulong_t *);
void ch_free_dma_mem(ulong_t, ulong_t);
void ch_unbind_dma_handle(ch_t *, free_dh_t *);

void ch_send_up(ch_t *, mblk_t *, uint32_t, int);

void ch_gld_ok(ch_t *);

uint32_t t1_read_reg_4(ch_t *obj, uint32_t reg_val);
void t1_write_reg_4(ch_t *obj, uint32_t reg_val, uint32_t write_val);
uint32_t t1_os_pci_read_config_2(ch_t *obj, uint32_t reg, uint16_t *val);
uint32_t t1_os_pci_read_config_4(ch_t *obj, uint32_t reg, uint32_t *val);
int t1_os_pci_write_config_2(ch_t *obj, uint32_t reg, uint16_t val);
int t1_os_pci_write_config_4(ch_t *obj, uint32_t reg, uint32_t val);
uint32_t le32_to_cpu(uint32_t data);

void *t1_os_malloc_wait_zero(size_t len);
void t1_os_free(void *adr, size_t len);
int t1_num_of_ports(ch_t *obj);
int pe_os_mem_copy(ch_t *obj, void *dst, void *src, size_t len);
void *pe_os_malloc_contig_wait_zero(ch_t *, size_t, uint64_t *,
    ulong_t *, ulong_t *, uint32_t);
void pe_set_mac(ch_t *sa, unsigned char *ac_enaddr);
unsigned char *pe_get_mac(ch_t *sa);
void pe_set_promiscuous(ch_t *sa, int flag);
int pe_get_stats(ch_t *sa, uint64_t *speed, uint32_t *intrcnt,
    uint32_t *norcvbuf, uint32_t *oerrors, uint32_t *ierrors,
    uint32_t *underrun, uint32_t *overrun, uint32_t *framing,
    uint32_t *crc, uint32_t *carrier, uint32_t *collisions,
    uint32_t *xcollisions, uint32_t *late, uint32_t *defer,
    uint32_t *xerrs, uint32_t *rerrs, uint32_t *toolong, uint32_t *runt,
    ulong_t *multixmt, ulong_t *multircv, ulong_t *brdcstxmt,
    ulong_t *brdcstrcv);
int pe_attach(ch_t *);
void pe_detach(ch_t *);
void pe_init(void *);
uint_t pe_intr(ch_t *);

#ifdef CONFIG_CHELSIO_T1_OFFLOAD
#define	toe_running(a) (a->open_device_map & TOEDEV_DEVMAP_BIT)
#endif

int pe_start(ch_t *sa, mblk_t *mb, uint32_t flg);
void pe_stop(ch_t *sa);
void pe_ioctl(ch_t *, queue_t *, mblk_t *);
int pe_set_mc(ch_t *, uint8_t *, int);

int tpi_read(ch_t *obj, u32 addr, u32 *value);

void CH_ALERT(const char *fmt, ...);
void CH_WARN(const char *fmt, ...);
void CH_ERR(const char *fmt, ...);
void t1_fatal_err(ch_t *chp);

#define	memset(s, c, n) bzero(s, n)

extern int enable_checksum_offload;

void pe_dma_handle_init(ch_t *, int);
free_dh_t *ch_get_dma_handle(ch_t *);

void pe_free_fake_arp(void *);

void pe_mark_freelists(ch_t *chp);

#if defined(__sparc)
free_dh_t *ch_get_dvma_handle(ch_t *);
void ch_unbind_dvma_handle(ch_t *, free_dh_t *);
#endif

#define	AMD_VENDOR_ID	0x1022
#define	AMD_BRIDGE	0x7450
#define	AMD_BRIDGE_REV	0x12

#ifdef __cplusplus
}
#endif

#endif	/* _CHELSIO_CH_H */
