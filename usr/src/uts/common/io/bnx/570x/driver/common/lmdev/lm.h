/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _LM_H
#define _LM_H

#include "lm_defs.h"
#include "listq.h"



/*******************************************************************************
 * Constants.
 ******************************************************************************/

#define BAD_DEFAULT_VALUE                   0xffffffff

#define ETHERNET_ADDRESS_SIZE               6
#define ETHERNET_PACKET_HEADER_SIZE         14
#define MIN_ETHERNET_PACKET_SIZE            60
#define MAX_ETHERNET_PACKET_SIZE            1514
#define MAX_ETHERNET_PACKET_BUFFER_SIZE     1536    /* A nice even number. */
#define MIN_JMBO_ETHERNET_PACKET_SIZE       2014
#define MAX_JMBO_ETHERNET_PACKET_SIZE       9014



/*******************************************************************************
 * Forward definition.
 ******************************************************************************/

/* Main device structure. */
/* typedef struct _lm_device_t lm_device_t; */
struct _lm_device_t;

/* Packet descriptor for sending/receiving packets. */
/* typedef struct _lm_packet_t lm_packet_t; */
struct _lm_packet_t;



/*******************************************************************************
 * Mutlicast address table.
 ******************************************************************************/

#ifndef LM_MAX_MC_TABLE_SIZE
#define LM_MAX_MC_TABLE_SIZE                64
#endif

typedef struct _lm_mc_entry_t
{
    u8_t mc_addr[ETHERNET_ADDRESS_SIZE];
    u16_t ref_cnt;
} lm_mc_entry_t;

typedef struct _lm_mc_table_t
{
    u32_t entry_cnt;
    lm_mc_entry_t addr_arr[LM_MAX_MC_TABLE_SIZE];
} lm_mc_table_t;



/*******************************************************************************
 * Network wake-up frame.
 ******************************************************************************/

#ifndef LM_NWUF_PATTERN_SIZE
#define LM_NWUF_PATTERN_SIZE                    128
#endif
#define LM_NWUF_PATTERN_MASK_SIZE               (LM_NWUF_PATTERN_SIZE/8)

/* Wake-up frame pattern. */
typedef struct _lm_nwuf_pattern_t
{
    u32_t size;         /* Mask size. */
    u8_t mask[LM_NWUF_PATTERN_MASK_SIZE];
    u8_t pattern[LM_NWUF_PATTERN_SIZE];
} lm_nwuf_t;


#ifndef LM_MAX_NWUF_CNT
#define LM_MAX_NWUF_CNT                         7
#endif

#ifndef LM_MAX_NWUF_CNT_5709
#define LM_MAX_NWUF_CNT_5709                    8
#endif

typedef struct _lm_nwuf_list_t
{
    lm_nwuf_t nwuf_arr[LM_MAX_NWUF_CNT_5709];
    u32_t cnt;
} lm_nwuf_list_t;



/*******************************************************************************
 * Interrupts.
 ******************************************************************************/

#define LM_NO_EVENT_ACTIVE                          0x00000000

#define LM_TX0_EVENT_BIT                            0

#define LM_TX0_EVENT_ACTIVE                         (1UL<<0)
#define LM_TX1_EVENT_ACTIVE                         (1UL<<1)
#define LM_TX2_EVENT_ACTIVE                         (1UL<<2)
#define LM_TX3_EVENT_ACTIVE                         (1UL<<3)
#define LM_TX4_EVENT_ACTIVE                         (1UL<<4)
#define LM_TX5_EVENT_ACTIVE                         (1UL<<5)
#define LM_TX6_EVENT_ACTIVE                         (1UL<<6)
#define LM_TX7_EVENT_ACTIVE                         (1UL<<7)
#define LM_TX8_EVENT_ACTIVE                         (1UL<<8)
#define LM_TX9_EVENT_ACTIVE                         (1UL<<9)
#define LM_TX10_EVENT_ACTIVE                        (1UL<<10)
#define LM_TX11_EVENT_ACTIVE                        (1UL<<11)

#define LM_TX_EVENT_MASK                            0xfffUL

#define LM_RX0_EVENT_BIT                            16

#define LM_RX0_EVENT_ACTIVE                         (1UL<<16)
#define LM_RX1_EVENT_ACTIVE                         (1UL<<17)
#define LM_RX2_EVENT_ACTIVE                         (1UL<<18)
#define LM_RX3_EVENT_ACTIVE                         (1UL<<19)
#define LM_RX4_EVENT_ACTIVE                         (1UL<<20)
#define LM_RX5_EVENT_ACTIVE                         (1UL<<21)
#define LM_RX6_EVENT_ACTIVE                         (1UL<<22)
#define LM_RX7_EVENT_ACTIVE                         (1UL<<23)
#define LM_RX8_EVENT_ACTIVE                         (1UL<<24)
#define LM_RX9_EVENT_ACTIVE                         (1UL<<25)
#define LM_RX10_EVENT_ACTIVE                        (1UL<<26)
#define LM_RX11_EVENT_ACTIVE                        (1UL<<27)

#define LM_RX_EVENT_MASK                            0xfff0000UL

#define LM_PHY_CONFIG_CHANGED                       (1UL<<13)
#define LM_KWQ_EVENT_ACTIVE                         (1UL<<14)
#define LM_KCQ_EVENT_ACTIVE                         (1UL<<15)
#define LM_PHY_EVENT_ACTIVE                         (1UL<<30)
#define LM_KNOCK_KNOCK_EVENT                        (1UL<<31)

typedef u32_t lm_interrupt_status_t;



/*******************************************************************************
 * Function prototypes.
 ******************************************************************************/

/* Description:
 *    1.  Retrieves the adapter information, such as IRQ, BAR, chip 
 *        IDs, MAC address, etc. 
 *    2.  Maps the BAR to system address space so hardware registers are 
 *        accessible. 
 *    3.  Initializes the default parameters in 'pdev'. 
 *    4.  Reads user configurations. 
 *    5.  Resets the transceiver.
 * This routine calls the following mm routines: 
 *    mm_map_io_base, mm_get_user_config. */
lm_status_t
lm_get_dev_info(
    struct _lm_device_t *pdev);

/* Description:
 *    This routine is called during driver initialization.  It is responsible 
 *    for allocating memory resources needed by the driver.  Packet
 *    descriptors are allocated here and put into various queues.  OS
 *    independent initialization of packets descriptors are done here and 
 *    finished up in mm_init_packet_desc.
 * This routine calls the following mm routines: 
 *    mm_alloc_mem, mm_alloc_phys_mem, and mm_init_packet_desc. */
lm_status_t
lm_init_resc(
    struct _lm_device_t *pdev);

/* Description:
 *    This routine is responsible for stopping the hardware from running, 
 *    cleaning up various request queues, aborting transmit requests, and 
 *    reclaiming all the receive buffers.
 * This routine calls the following mm routines:
 *    mm_indicate_tx, mm_free_rx_buf. */
void
lm_abort(
    struct _lm_device_t *pdev,
    u32_t abort_op,
    u32_t idx);
#define ABORT_OP_RX_CHAIN               1
#define ABORT_OP_TX_CHAIN               2

void
lm_recv_abort(
    struct _lm_device_t *pdev,
    u32_t idx);

void
lm_send_abort(
    struct _lm_device_t *pdev,
    u32_t idx);

/* Description:
 *    This routine is called to initialize the first stage of reset which
 *    only initializes all the device configurations; however states machines
 *    if any, are not enabled yet. */
lm_status_t
lm_reset_setup(
    struct _lm_device_t *pdev,
    u32_t reset_reason);

/* Description:
 *    This routine finishes up the final stage of reset.  Various state
 *    machines are enabled here.  Upon exit, interrupt will not yet enabled
 *    and receive buffers are not queued.  However, the chip is initialized 
 *    and is ready to send and receive packets.
 *    receive buffers are not queued. */
lm_status_t
lm_reset_run(
    struct _lm_device_t *pdev);

/* Description:
 *    The main function of this routine is to reset and initialize the
 *    hardware.  Upon exit, interrupt generation is not enable; however,
 *    the hardware is ready to accept transmit requests and receive receive
 *    packets.  'lm_abort' must be called prior to calling 'lm_reset'. 
 *    This routine is a wrapper for lm_reset_setup and lm_reset_run. */
lm_status_t
lm_reset(
    struct _lm_device_t *pdev,
    u32_t reset_reason);

/* Description:
 *    The main responsibility of this routine is to gracefully restore the 
 *    chip to its initial power-on state. */
void
lm_chip_reset(
    struct _lm_device_t *pdev,
    lm_reason_t reason);

/* Description:
 *    This routine post the indicate buffer or receive buffers in the
 *    free buffer pool.  If 'packet' is null, all buffers in the free poll
 *    will be posted; otherwise, only the 'packet' will be posted. */
#if defined(LM_NON_LEGACY_MODE_SUPPORT)
u32_t
lm_post_buffers(
    struct _lm_device_t *pdev,
    u32_t chain_idx,
    struct _lm_packet_t *packet,
    lm_frag_list_t *frags);   
#else
u32_t
lm_post_buffers(
    struct _lm_device_t *pdev,
    u32_t chain_idx,
    struct _lm_packet_t *packet);
#endif
/* Description:
 *    This routine sends the given packet.  Resources required to send this
 *    must have already been reserved.  The upper moduel is resposible for
 *    any necessary queueing. */
lm_status_t
lm_send_packet(
    struct _lm_device_t *pdev,
    u32_t chain_idx,
    struct _lm_packet_t *packet,
    lm_frag_list_t *frags);

/* Description: 
 *    This routine is called to get all pending interrupts. */
lm_interrupt_status_t
lm_get_interrupt_status(
    struct _lm_device_t *pdev);

/* Description: 
 *    This routine is called to service receive interrupts.
 * This routine calls the following mm routines:
 *    mm_indicate_rx */
void
lm_service_rx_int(
    struct _lm_device_t *pdev,
    u32_t chain_idx);

u32_t
lm_get_packets_rcvd(
    struct _lm_device_t *pdev,
    u32_t qidx,
    u32_t con_idx,
    s_list_t *rcvd_list);


/* Description:
 *    This routine is called to service transmit complete interrupts.
 * This routine calls the following mm routines:
 *    mm_indicate_tx, mm_complete_tx. */
void
lm_service_tx_int(
    struct _lm_device_t *pdev,
    u32_t chain_idx);

u32_t
lm_get_packets_sent(
    struct _lm_device_t *pdev,
    u32_t qidx,
    u32_t con_idx,
    s_list_t *sent_list);


/* Description:
 *    This routine is called to service PHY interrupt. 
 * This routine calls the following mm routines:
 *    mm_indicate_link */
void
lm_service_phy_int(
    struct _lm_device_t *pdev,
    u32_t force_service_int);

/* Description: 
 *    This routine is called to mask out interrupt from the hardware. */
void
lm_disable_int(
    struct _lm_device_t *pdev);

/* Description:
 *    This routine is called to enable interrupt generation. */
void
lm_enable_int(
    struct _lm_device_t *pdev);

/* Description:
 *    This routine is called to set the receive filter. */
lm_status_t
lm_set_rx_mask(
    struct _lm_device_t *pdev,
    u32_t user_idx,
    lm_rx_mask_t rx_mask);

/* Description:
 *    This routine is called to add a multicast address to the multicast 
 *    address table.  Multicast filtering is enabled independently via 
 *    lm_set_rx_mask call. */
lm_status_t
lm_add_mc(
    struct _lm_device_t *pdev,
    u8_t *mc_addr);

/* Description:
 *    This routine is called to remove a multicast address from the multicast
 *    address table.  Multicast filtering is enabled independently via
 *    lm_set_rx_mask call. */
lm_status_t
lm_del_mc(
    struct _lm_device_t *pdev,
    u8_t *mc_addr);

/* Description:
 *    This routine is called to remove all multicast addresses from the
 *    multicast address table.  Multicast filtering is enabled independently
 *    via lm_set_rx_mask call. */
void
lm_clear_mc(
    struct _lm_device_t *pdev);

/* Description: 
 *    This routine is called to set the current MAC address.  The 'addr_idx' 
 *    allows the caller to set multiple MAC addresses if the hardware is 
 *    capable of filtering multiple unicast addresses. */
lm_status_t
lm_set_mac_addr(
    struct _lm_device_t *pdev,
    u32_t addr_idx,   /* zero based address index. */
    u8_t *mac_addr);

/* Description:
 *    This routine is called to retrieve statistics.  */
lm_status_t
lm_get_stats(
    struct _lm_device_t *pdev,
    lm_stats_t stats_type,
    u64_t *stats_cnt);

/* Description:
 *    This routine is called to add a wake-up pattern to the main list that
 *    contains all the wake-up frame. */
lm_status_t
lm_add_nwuf(
    struct _lm_device_t *pdev,
    u32_t byte_pattern_size,
    u32_t byte_mask_size,
    u8_t *byte_mask,
    u8_t *byte_pattern);

/* Description: 
 *    This routine is called to remove the wake-up pattern from the main list
 *    that contains all the wake-up frame. */
lm_status_t
lm_del_nwuf(
    struct _lm_device_t *pdev,
    u32_t byte_mask_size,
    u8_t *byte_mask,
    u8_t *byte_pattern);

/* Description:
 *    Delete all the NWUF entries. */
void
lm_clear_nwuf(
    struct _lm_device_t *pdev);


/* Description:
 *    This routine is called to set up the device power state. */
void
lm_set_power_state(
    struct _lm_device_t *pdev,
    lm_power_state_t power_state,
    lm_wake_up_mode_t wake_up_mode,     /* Valid when power_state is D3. */
    u8_t set_pci_pm);

/* Description:
 *    This routine is called to initialize the PHY based one 'media_type'
 *    setting.  'wait_for_link_timeout' specifies how long to poll for
 *    link before returning. */
lm_status_t
lm_init_phy(
    struct _lm_device_t *pdev,
    lm_medium_t req_medium,
    lm_flow_control_t flow_control,
    u32_t selective_autoneg,
    u32_t wire_speed,
    u32_t wait_for_link_timeout);

u8_t lm_is_mmio_ok(struct _lm_device_t *pdev);

#if INCLUDE_OFLD_SUPPORT
void
lm_get_ooo_pkts_rcvd(
    struct _lm_device_t *pdev,
    struct _lm_rx_chain_t *rxq,
    u32_t con_idx,
    s_list_t *rx_done_list);
#endif

/*******************************************************************************
 * OS dependent functions called by the 'lm' routines.
 ******************************************************************************/

/* Busy delay for the specified microseconds. */
void
mm_wait(
    struct _lm_device_t *pdev,
    u32_t delay_us);

/* This routine is called to read a PCI configuration register.  The register
 * must be 32-bit aligned. */
lm_status_t
mm_read_pci(
    struct _lm_device_t *pdev,
    u32_t pci_reg,
    u32_t *reg_value);

/* This routine is called to write a PCI configuration register.  The 
 * register must be 32-bit aligned. */
lm_status_t
mm_write_pci(
    struct _lm_device_t *pdev,
    u32_t pci_reg,
    u32_t reg_value);

/* This routine is called to map the base address of the device registers
 * to system address space so that registers are accessible.  The base
 * address will be unmapped when the driver unloads. */
void *
mm_map_io_base(
    struct _lm_device_t *pdev,
    lm_address_t base_addr,
    u32_t size);

/* This routine is called to read driver configuration.  It is called from
 * lm_get_dev_info. */
lm_status_t
mm_get_user_config(
    struct _lm_device_t *pdev);

/* This routine returns the size of a packet descriptor. */
u32_t
mm_desc_size(
    struct _lm_device_t *pdev,
    u32_t desc_type);
#define DESC_TYPE_L2TX_PACKET           0
#define DESC_TYPE_L2RX_PACKET           1

/* This routine is responsible for allocating system memory and keeping track
 * of it.  The memory will be freed later when the driver unloads.  This
 * routine is called during driver initialization. */
void *
mm_alloc_mem(
    struct _lm_device_t *pdev,
    u32_t mem_size,
    void *resc_list);

/* This routine is responsible for physical memory and keeping track
 * of it.  The memory will be freed later when the driver unloads. */
void *
mm_alloc_phys_mem(
    struct _lm_device_t *pdev,
    u32_t mem_size,
    lm_address_t *phys_mem,
    u8_t mem_type,
    void *resc_list);
#define PHYS_MEM_TYPE_UNSPECIFIED       0
#define PHYS_MEM_TYPE_NONCACHED         1


/* This routine flushes a memory block from caches of all processors. */
//#if defined(_X86_) || defined(_AMD64_)
#define mm_flush_cache(_pdev, _mem_virt, _mem_phy, _mem_size, _flush_type)
//#else
//void
//mm_flush_cache(
//    struct _lm_device_t *pdev,
//    u8_t *mem_virt,
//    lm_address_t mem_phy,
//    u32_t mem_size,
//    u8_t flush_type);
//#define FLUSH_CACHE_BEFORE_DMA_READ     0
//#define FLUSH_CACHE_AFTER_DMA_WRITE     1
//#endif


/* This routine is called to indicate completion of a transmit request. 
 * If 'packet' is not NULL, all the packets in the completion queue will be
 * indicated.  Otherwise, only 'packet' will be indicated. */
void
mm_indicate_tx(
    struct _lm_device_t *pdev,
    u32_t chain_idx,
    struct _lm_packet_t *packet_arr[],
    u32_t num_packets);

/* This routine is called to indicate received packets.  If 'packet' is not
 * NULL, all the packets in the received queue will be indicated.  Otherwise,
 * only 'packet' will be indicated. */
#if defined(LM_NON_LEGACY_MODE_SUPPORT)
void
mm_indicate_rx(
    struct _lm_device_t *pdev,
    u32_t chain_idx,
    struct _lm_packet_t *packet_arr[],
    u32_t num_packets,
    u8_t ind_as_resc);
#else
void
mm_indicate_rx(
    struct _lm_device_t *pdev,
    u32_t chain_idx,
    struct _lm_packet_t *packet_arr[],
    u32_t num_packets);
#endif

#if INCLUDE_OFLD_SUPPORT
void
mm_return_ooo_pkts(
    struct _lm_device_t *pdev,
    u32_t       qidx,
    s_list_t    *rcvd_list,
    u32_t       l2pkt_type
    );
#endif

/* lm_service_phy_int calls this routine to indicate the current link. */
void
mm_indicate_link(
    struct _lm_device_t *pdev,
    lm_status_t link,
    lm_medium_t medium);

/* indirect register access lock. */
void
mm_acquire_ind_reg_lock(
    struct _lm_device_t *pdev);

void
mm_release_ind_reg_lock(
    struct _lm_device_t *pdev);

void
mm_comp_l2_filter_chng_req(
    struct _lm_device_t *pdev,
    lm_status_t lm_status,
    u32_t       q_grp_id);

void
mm_q_grp_abort_rx_request(
    struct _lm_device_t *pdev,
    u32_t       qidx);


#endif /* _LM_H */

