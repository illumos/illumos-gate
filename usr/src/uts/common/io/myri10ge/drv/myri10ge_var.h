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
 * Copyright 2007-2009 Myricom, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef MYRI10GE_VAR_H
#define	MYRI10GE_VAR_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/atomic.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/debug.h>
#include <sys/dlpi.h>
#include <sys/ethernet.h>
#include <sys/mac_provider.h>
#define	MAC_CAPAB_POLL 0
#define	MC_RESOURCES 0
#include <sys/mac_ether.h>
#ifndef MYRICOM_PRIV
#include <sys/vlan.h>
#endif
#include <sys/pci.h>
#include <sys/pcie.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsubr.h>  	/* for hw cksum stuff */
#include <sys/pattr.h>		/* for hw cksum stuff */
#include <netinet/in.h>		/* for hw cksum stuff */
#include <netinet/ip.h>		/* for hw cksum stuff */
#include <netinet/ip6.h>	/* for hw cksum stuff */
#include <netinet/tcp.h>	/* for hw cksum stuff */
#include <netinet/udp.h>	/* for hw cksum stuff */
#include <sys/strsun.h>
#include <inet/common.h>
#include <inet/mi.h>
#include <inet/nd.h>
#include <sys/zmod.h>
#include <sys/cpuvar.h>
#include <sys/proc.h>
#include <sys/callb.h>

#include "myri10ge_mcp.h"
#include "myri10ge_version.h"

#define	MYRI10GE_FW_OFFSET 1024*1024
#define	MYRI10GE_EEPROM_STRINGS_SIZE 256
#define	MYRI10GE_HIGHPART_TO_U32(X) \
(sizeof (X) == 8) ? ((uint32_t)((uint64_t)(X) >> 32)) : (0)
#define	MYRI10GE_LOWPART_TO_U32(X) ((uint32_t)(X))

#define	MYRI10GE_DDI_REG_SET_32_BIT_MEMORY_SPACE 2
#define	MYRI10GE_DDI_REG_SET_64_BIT_MEMORY_SPACE 3

/*
 * Max descriptors a TSO send can use; worst case is every descriptor
 * crosses a 2KB boundary, as do the headers
 */

#define	MYRI10GE_MAX_SEND_DESC_TSO (2 + (65536 / 2048) * 2)

#ifdef MYRICOM_PRIV
#define	VLAN_TAGSZ 4
#endif

#if defined DDI_INTR_IS_MSI_OR_MSIX
#define	MYRI10GE_USE_MSI 1
#else
#define	MYRI10GE_USE_MSI 0
#endif


struct myri10ge_dma_stuff {
	ddi_dma_handle_t handle;
	ddi_acc_handle_t acc_handle;
	uint32_t low;
	uint32_t high;
};

typedef struct myri10ge_mblkq {
	struct myri10ge_priv *mgp;
	kmutex_t lock;
	mblk_t *head;
	mblk_t *tail;
	unsigned long cnt;
} myri10ge_mblkq_t;

typedef struct {
	mcp_slot_t *entry;
	struct myri10ge_dma_stuff dma;
	int cnt;
	int idx;
} myri10ge_rx_done_t;


typedef struct
{
	uint32_t data0;
	uint32_t data1;
	uint32_t data2;
} myri10ge_cmd_t;

struct myri10ge_pci_saved_state {
	uint32_t base[16];
	uint32_t msi_addr_low;
	uint32_t msi_addr_high;
	uint16_t msi_data_32;
	uint16_t msi_data_64;
	uint16_t msi_ctrl;
};

struct myri10ge_jpool_entry;

struct myri10ge_jpool_entry {
	struct myri10ge_jpool_entry *next;
	ddi_dma_handle_t dma_handle;
	ddi_acc_handle_t acc_handle;
	caddr_t buf;
	struct myri10ge_slice_state *ss;
	mcp_dma_addr_t dma;  /* Kept in network byte order */
	frtn_t free_func;
};

#define	MYRI10GE_CPU_CACHE_SZ	64
struct myri10ge_per_cpu_jpool {
	struct myri10ge_jpool_entry *head;
	uint8_t _pad[MYRI10GE_CPU_CACHE_SZ - sizeof (void *)];
};

#define	MYRI10GE_MAX_CPUS	64
#define	MYRI10GE_MAX_CPU_MASK	(64 - 1)

struct myri10ge_jpool_stuff {
	struct myri10ge_jpool_entry *head;
	struct myri10ge_per_cpu_jpool cpu[MYRI10GE_MAX_CPUS];
	kmutex_t mtx;
	int num_alloc;
	int low_water;
};

struct myri10ge_tx_ring_stats
{
	uint64_t multixmt;
	uint64_t brdcstxmt;
	uint64_t opackets;
	uint64_t obytes;
};

struct myri10ge_rx_ring_stats
{
	uint64_t multircv;
	uint64_t brdcstrcv;
	uint64_t ipackets;
	uint64_t ibytes;
};

struct myri10ge_tx_ring_entry_stats
{
	uint32_t  obytes;
	uint16_t  opackets;
	uint8_t	  brdcstxmt;
	uint8_t	  multixmt;
};

struct myri10ge_tx_pkt_stats {
	union {
		uint64_t all;
		struct myri10ge_tx_ring_entry_stats s;
	} un;
};

#define	ostat stat.un.s

struct myri10ge_tx_dma_handle {
	struct myri10ge_tx_dma_handle *next;
	ddi_dma_handle_t h;
};

struct myri10ge_tx_dma_handle_head {
	struct myri10ge_tx_dma_handle *head;
	struct myri10ge_tx_dma_handle *tail;
};

struct myri10ge_rx_buffer_state {
	caddr_t ptr;
	struct myri10ge_jpool_entry *j;
};

struct myri10ge_tx_buffer_state {
	mblk_t *m;
	struct myri10ge_tx_dma_handle *handle;
	struct myri10ge_tx_pkt_stats stat;
};

struct myri10ge_nic_stat {
	struct kstat_named dma_force_physical;
	struct kstat_named dma_read_bw_MBs;
	struct kstat_named dma_write_bw_MBs;
	struct kstat_named dma_read_write_bw_MBs;
	struct kstat_named lanes;
	struct kstat_named dropped_bad_crc32;
	struct kstat_named dropped_bad_phy;
	struct kstat_named dropped_link_error_or_filtered;
	struct kstat_named dropped_link_overflow;
	struct kstat_named dropped_multicast_filtered;
	struct kstat_named dropped_no_big_buffer;
	struct kstat_named dropped_no_small_buffer;
	struct kstat_named dropped_overrun;
	struct kstat_named dropped_pause;
	struct kstat_named dropped_runt;
	struct kstat_named dropped_unicast_filtered;
	struct kstat_named link_changes;
	struct kstat_named link_up;
};

struct myri10ge_slice_stat {
	struct kstat_named lro_bad_csum;
	struct kstat_named lro_flushed;
	struct kstat_named lro_queued;
	struct kstat_named rx_big;
	struct kstat_named rx_bigbuf_firmware;
	struct kstat_named rx_bigbuf_pool;
	struct kstat_named rx_bigbuf_smalls;
	struct kstat_named rx_copy;
	struct kstat_named rx_small;
	struct kstat_named rx_big_nobuf;
	struct kstat_named rx_small_nobuf;
	struct kstat_named tx_activate;
	struct kstat_named tx_done;
	struct kstat_named tx_handles_alloced;
	struct kstat_named tx_req;
	struct kstat_named xmit_err;
	struct kstat_named xmit_lowbuf;
	struct kstat_named xmit_lsobadflags;
	struct kstat_named xmit_pullup;
	struct kstat_named xmit_pullup_first;
	struct kstat_named xmit_sched;
	struct kstat_named xmit_stall;
	struct kstat_named xmit_stall_early;
	struct kstat_named xmit_stall_late;
	struct kstat_named xmit_zero_len;
};

struct myri10ge_info {
	struct kstat_named driver_version;
	struct kstat_named firmware_version;
	struct kstat_named firmware_name;
	struct kstat_named interrupt_type;
	struct kstat_named product_code;
	struct kstat_named serial_number;
};


#define	MYRI10GE_NIC_STAT_INC(field)					\
(((struct myri10ge_nic_stat *)mgp->ksp_stat->ks_data)->field.value.ul)++
#define	MYRI10GE_SLICE_STAT_INC(field)					\
(((struct myri10ge_slice_stat *)ss->ksp_stat->ks_data)->field.value.ul)++
#define	MYRI10GE_SLICE_STAT_ADD(field, val)				\
(((struct myri10ge_slice_stat *)ss->ksp_stat->ks_data)->field.value.ul) += val
#define	MYRI10GE_SLICE_STAT_DEC(field)					\
(((struct myri10ge_slice_stat *)ss->ksp_stat->ks_data)->field.value.ul)--
#define	MYRI10GE_ATOMIC_SLICE_STAT_INC(field) 				\
atomic_inc_ulong(&(((struct myri10ge_slice_stat *)			\
	ss->ksp_stat->ks_data)->field.value.ul))
#define	MYRI10GE_ATOMIC_SLICE_STAT_DEC(field) 				\
atomic_dec_ulong(&(((struct myri10ge_slice_stat *)			\
	ss->ksp_stat->ks_data)->field.value.ul))
#define	MYRI10GE_SLICE_STAT(field)					\
(((struct myri10ge_slice_stat *)ss->ksp_stat->ks_data)->field.value.ul)


struct myri10ge_tx_copybuf
{
	caddr_t va;
	int len;
	struct myri10ge_dma_stuff dma;
};

typedef struct
{
	mcp_kreq_ether_recv_t *lanai;	/* lanai ptr for recv ring */
	mcp_kreq_ether_recv_t *shadow;	/* host shadow of recv ring */
	struct myri10ge_rx_buffer_state *info;
	int cnt;
	int alloc_fail;
	int mask;			/* number of rx slots -1 */
	boolean_t polling;
} myri10ge_rx_ring_t;

typedef struct
{
	mcp_kreq_ether_send_t *lanai;	/* lanai ptr for sendq	*/
	char *go;			/* doorbell to poll sendq */
	char *stop;			/* doorbell to !poll sendq */
	struct myri10ge_tx_buffer_state *info;
	struct myri10ge_tx_copybuf *cp;
	int req;			/* transmits submitted	*/
	int mask;			/* number of transmit slots -1 */
	int done;			/* transmits completed	*/
	int pkt_done;			/* packets completed */
	int active;
	uint32_t stall;
	uint32_t stall_early;
	uint32_t stall_late;
	int sched;
	kmutex_t lock;
	struct myri10ge_tx_ring_stats stats;
	int watchdog_req;
	int watchdog_done;
	unsigned long activate;
	kmutex_t handle_lock;
	struct myri10ge_tx_dma_handle  *free_tx_handles;
	mac_ring_handle_t rh;
} myri10ge_tx_ring_t;

struct lro_entry;

struct lro_entry
{
	struct lro_entry *next;
	mblk_t		*m_head;
	mblk_t		*m_tail;
	int		timestamp;
	struct ip	*ip;
	uint32_t	tsval;
	uint32_t	tsecr;
	uint32_t	source_ip;
	uint32_t	dest_ip;
	uint32_t	next_seq;
	uint32_t	ack_seq;
	uint32_t	len;
	uint32_t	data_csum;
	uint16_t	window;
	uint16_t	source_port;
	uint16_t	dest_port;
	uint16_t	append_cnt;
	uint16_t	mss;
	uint8_t		flags;
};

struct myri10ge_mblk_list
{
	mblk_t *head;
	mblk_t **tail;
	int cnt;
};

struct myri10ge_priv;

struct myri10ge_slice_state {
	struct myri10ge_priv *mgp;
	myri10ge_tx_ring_t tx;	/* transmit ring 	*/
	myri10ge_rx_ring_t rx_small;
	myri10ge_rx_ring_t rx_big;
	myri10ge_rx_done_t rx_done;
	struct myri10ge_jpool_stuff jpool;
	struct myri10ge_rx_ring_stats rx_stats;
	volatile uint32_t *irq_claim;
	mcp_irq_data_t *fw_stats;
	struct lro_entry *lro_active;
	struct lro_entry *lro_free;
	struct myri10ge_dma_stuff fw_stats_dma;
	int jbufs_for_smalls;
	struct myri10ge_jpool_entry *small_jpool;
	int j_rx_cnt;
	mac_resource_handle_t mrh;
	kstat_t *ksp_stat;
	mac_ring_handle_t rx_rh;
	kmutex_t rx_lock;
	kmutex_t poll_lock;
	uint64_t rx_gen_num;
	boolean_t rx_polling;
	int rx_token;
	int watchdog_rx_copy;
};

struct myri10ge_priv {
	struct myri10ge_slice_state *ss;
	int max_intr_slots;
	int num_slices;
	dev_info_t *dip;
	mac_handle_t mh;
	ddi_acc_handle_t io_handle;
	int tx_boundary;
	int watchdog_rx_pause;
	kstat_t *ksp_stat;
	kstat_t *ksp_info;
	int running;			/* running? 		*/
	int csum_flag;			/* rx_csums? 		*/
	uint8_t	mac_addr[6];		/* eeprom mac address */
	volatile uint8_t *sram;
	int sram_size;
	unsigned long  board_span;
	unsigned long iomem_base;
	volatile uint32_t *irq_deassert;
	char *mac_addr_string;
	mcp_cmd_response_t *cmd;
	struct myri10ge_dma_stuff cmd_dma;
	int msi_enabled;
	int link_state;
	int rdma_tags_available;
	int intr_coal_delay;
	volatile uint32_t *intr_coal_delay_ptr;
	kmutex_t cmd_lock;
	kmutex_t intrlock;
	int down_cnt;
	int watchdog_resets;
	unsigned char *eth_z8e;
	unsigned int eth_z8e_length;
	ddi_iblock_cookie_t icookie;
	ddi_intr_handle_t *htable;
	int intr_size;
	int intr_cnt;
	int intr_cap;
	unsigned int intr_pri;
	int ddi_intr_type;
	int pause;
	timeout_id_t timer_id;
	clock_t timer_ticks;
	int vso;
	uint32_t mcp_index;
	char fw_version[128];
	char name[32];
	char *fw_name;
	char *intr_type;
	char eeprom_strings[MYRI10GE_EEPROM_STRINGS_SIZE];
	char *sn_str;
	char *pc_str;
	uint32_t read_dma;
	uint32_t write_dma;
	uint32_t read_write_dma;
	uint32_t pcie_link_width;
	int max_read_request_4k;
	caddr_t nd_head;
	struct myri10ge_priv *next;
	uint_t refcnt;
	int reg_set;
	int features;
	struct myri10ge_pci_saved_state pci_saved_state;
	uint32_t *toeplitz_hash_table;
	uint32_t rss_key[8];
	ddi_acc_handle_t cfg_hdl;
	int macaddr_cnt;
};

/* features bitmask */
#define	MYRI10GE_TSO 1

#if defined(__GNUC__)
#define	likely(x)	__builtin_expect((x), 1)
#define	unlikely(x)	__builtin_expect((x), 0)
#else
#define	likely(x)	(x)
#define	unlikely(x)	(x)
#endif /* defined(__GNUC__) */

#define	mb membar_producer

struct myri10ge_priv *myri10ge_get_instance(uint_t unit);
void myri10ge_put_instance(struct myri10ge_priv *);
int myri10ge_send_cmd(struct myri10ge_priv *mgp, uint32_t cmd,
    myri10ge_cmd_t *data);
caddr_t myri10ge_dma_alloc(dev_info_t *dip, size_t len,
    ddi_dma_attr_t *attr, ddi_device_acc_attr_t  *accattr,
    uint_t alloc_flags, int bind_flags, struct myri10ge_dma_stuff *dma,
    int warn, int (*waitfp)(caddr_t));
void myri10ge_dma_free(struct myri10ge_dma_stuff *dma);

void myri10ge_lro_flush(struct myri10ge_slice_state *ss,
    struct lro_entry *lro, struct myri10ge_mblk_list *mbl);
int myri10ge_lro_rx(struct myri10ge_slice_state *ss, mblk_t *m_head,
    uint32_t csum, struct myri10ge_mblk_list *mbl);
void myri10ge_mbl_append(struct myri10ge_slice_state *ss,
    struct myri10ge_mblk_list *mbl, mblk_t *mp);
uint16_t myri10ge_csum_generic(uint16_t *raw, int len);
extern int myri10ge_lro_max_aggr;
extern int myri10ge_mtu;

#ifndef ETHERNET_HEADER_SIZE
#define	ETHERNET_HEADER_SIZE 14
#endif

#define	MYRI10GE_TOEPLITZ_HASH	(MXGEFW_RSS_HASH_TYPE_TCP_IPV4|\
	    MXGEFW_RSS_HASH_TYPE_IPV4)
#define	MYRI10GE_POLL_NULL INT_MAX

/*
 *  This file uses MyriGE driver indentation.
 *
 * Local Variables:
 * c-file-style:"sun"
 * tab-width:8
 * End:
 */

#ifdef	__cplusplus
}
#endif

#endif /* MYRI10GE_VAR_H */
