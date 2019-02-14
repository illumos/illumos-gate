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

#ifndef _LM5706_H
#define _LM5706_H


#include "bcmtype.h"
#include "debug.h"
#include "5706_reg.h"
#include "l2_defs.h"
#include "l5_defs.h"
#ifndef EXCLUDE_KQE_SUPPORT
#include "l4_kqe.h"
#endif
#ifndef L2_ONLY
#include "status_code.h"
#endif
#include "shmem.h"
#include "lm_desc.h"
#include "listq.h"
#include "lm.h"
#include "mm.h"
#ifndef L2_ONLY
#include "toe_ctx.h"
#endif
#ifdef UEFI
#include "5706_efi.h"
#endif
#ifdef SOLARIS
#include <sys/ddi.h>
#include <sys/sunddi.h>
#endif

#ifdef LINUX /*lediag*/
#include "../../mpd_driver_hybrid/pal2.h"
#endif

typedef struct fw_version
{
    u8_t    name[11];
    u8_t    namez;
    u32_t   version;
} fw_version_t;

#ifndef PRIVATE_HSI_HEADER
#include "rxp_hsi.h"
#include "com_hsi.h"
#include "cp_hsi.h"
#include "txp_hsi.h"
#include "tpat_hsi.h"
#else
#include "hsi.h"
#endif

/*******************************************************************************
 * Constants.
 ******************************************************************************/

#define MAX_TX_CHAIN                12
#define MAX_RX_CHAIN                12
#define FIRST_RSS_RXQ               4

#ifndef NUM_RX_CHAIN
#define NUM_RX_CHAIN                1
#endif

#ifndef NUM_TX_CHAIN
#define NUM_TX_CHAIN                1
#endif

#if NUM_TX_CHAIN > MAX_TX_CHAIN
#error Exceeded maximum number of tx chains.
#endif

#if NUM_RX_CHAIN > MAX_RX_CHAIN
#error Exceeded maximum number of rx chains.
#endif

/* Number of bits must be 10 to 25. */
#ifndef LM_PAGE_BITS
#define LM_PAGE_BITS                            12  /* 4K page. */
#endif

#define LM_PAGE_SIZE                            (1 << LM_PAGE_BITS)
#define LM_PAGE_MASK                            (LM_PAGE_SIZE - 1)


#ifndef CACHE_LINE_SIZE_MASK
#define CACHE_LINE_SIZE_MASK        0x3f
#endif


/* Number of packets per indication in calls to mm_indicate_rx/tx. */
#ifndef MAX_PACKETS_PER_INDICATION
#define MAX_PACKETS_PER_INDICATION  50
#endif


#ifndef MAX_FRAG_CNT
#define MAX_FRAG_CNT                33
#endif

/* The maximum is actually 0xffff which can be described by a BD. */
#define MAX_FRAGMENT_SIZE           0xf000


/* Context size. */
#define CTX_SHIFT                   7
#define CTX_SIZE                    (1 << CTX_SHIFT)
#define CTX_MASK                    (CTX_SIZE - 1)
#define GET_CID_ADDR(_cid)          ((_cid) << CTX_SHIFT)
#define GET_CID(_cid_addr)          ((_cid_addr) >> CTX_SHIFT)

#define PHY_CTX_SHIFT               6
#define PHY_CTX_SIZE                (1 << PHY_CTX_SHIFT)
#define PHY_CTX_MASK                (PHY_CTX_SIZE - 1)
#define GET_PCID_ADDR(_pcid)        ((_pcid) << PHY_CTX_SHIFT)
#define GET_PCID(_pcid_addr)        ((_pcid_addr) >> PHY_CTX_SHIFT)

#define MB_KERNEL_CTX_SHIFT         8
#define MB_KERNEL_CTX_SIZE          (1 << MB_KERNEL_CTX_SHIFT)
#define MB_KERNEL_CTX_MASK          (MB_KERNEL_CTX_SIZE - 1)
/* #define MB_GET_CID_ADDR(_cid)       (0x10000 + ((_cid) << MB_KERNEL_CTX_SHIFT)) */
#define MB_GET_CID_ADDR(_p, _c)     lm_mb_get_cid_addr(_p, _c)

#define MAX_CID_CNT                 0x4000
#define MAX_CID_ADDR                (GET_CID_ADDR(MAX_CID_CNT))
#define INVALID_CID_ADDR            0xffffffff


/* The size of the GRC window that appears in 32k-64k. */
#define GRC_WINDOW_BASE             0x8000
#define GRC_WINDOW_SIZE             0x8000


/* L2 rx frame header size. */
#define L2RX_FRAME_HDR_LEN          (sizeof(l2_fhdr_t)+2)


/* The number of bd's per page including the last bd which is used as
 * a pointer to the next bd page. */
#define BD_PER_PAGE                 (LM_PAGE_SIZE/sizeof(tx_bd_t))

/* The number of useable bd's per page.  This number does not include
 * the last bd at the end of the page. */
#define MAX_BD_PER_PAGE             ((u32_t) (BD_PER_PAGE-1))


/* Buffer size of the statistics block. */
#define CHIP_STATS_BUFFER_SIZE      ((sizeof(statistics_block_t) + \
                                        CACHE_LINE_SIZE_MASK) & \
                                        ~CACHE_LINE_SIZE_MASK)

/* Buffer size of the status block. */
#define STATUS_BLOCK_BUFFER_SIZE    ((sizeof(status_blk_combined_t) + \
                                        CACHE_LINE_SIZE_MASK) & \
                                        ~CACHE_LINE_SIZE_MASK)


#define RSS_INDIRECTION_TABLE_SIZE  0x80    /* Maximum indirection table. */
#define RSS_HASH_KEY_SIZE           0x40    /* Maximum key size. */
#ifndef RSS_LOOKUP_TABLE_WA
#define RSS_LOOKUP_TABLE_WA         (4*12*256)  /* 0 to disable workaround. */
#endif


/* Quick context assigments. */
#define L2RX_CID_BASE               0       /* 0-15 */
#define L2TX_CID_BASE               16      /* 16-23 */
#define KWQ_CID                     24
#define KCQ_CID                     25
#define HCOPY_CID                   26      /* 26-27 */
#define GEN_CHAIN_CID               29

/* Xinan definitions. */
#define L2TX_TSS_CID_BASE           32      /* 32-43 */

/* MSIX definitions. */
#define IRQ_MODE_UNKNOWN            0
#define IRQ_MODE_LINE_BASED         1
#define IRQ_MODE_SIMD               2
#define IRQ_MODE_MSI_BASED          3
#define IRQ_MODE_MSIX_BASED         4
#define MAX_MSIX_HW_VEC             9
#define PCI_GRC_WINDOW2_BASE        0xc000
#define PCI_GRC_WINDOW3_BASE        0xe000
#define MSIX_TABLE_ADDR             0x318000
#define MSIX_PBA_ADDR               0x31c000

/*******************************************************************************
 * Macros.
 ******************************************************************************/

/* These macros have been moved to bcmtype.h. */
#if 0
/* Signed subtraction macros with no sign extending.  */
#define S64_SUB(_a, _b)     ((s64_t) ((s64_t) (_a) - (s64_t) (_b)))
#define u64_SUB(_a, _b)     ((u64_t) ((s64_t) (_a) - (s64_t) (_b)))
#define S32_SUB(_a, _b)     ((s32_t) ((s32_t) (_a) - (s32_t) (_b)))
#define uS32_SUB(_a, _b)    ((u32_t) ((s32_t) (_a) - (s32_t) (_b)))
#define S16_SUB(_a, _b)     ((s16_t) ((s16_t) (_a) - (s16_t) (_b)))
#define u16_SUB(_a, _b)     ((u16_t) ((s16_t) (_a) - (s16_t) (_b)))
#define PTR_SUB(_a, _b)     ((u8_t *) (_a) - (u8_t *) (_b))
#endif

#ifndef OFFSETOF
#define OFFSETOF(_s, _m)    ((u32_t) PTR_SUB(&((_s *) 0)->_m, (u8_t *) 0))
#endif
#define WORD_ALIGNED_OFFSETOF(_s, _m)       (OFFSETOF(_s, _m) & ~0x03)


/* STATIC void
 * get_attn_chng_bits(
 *     lm_device_t *pdev,
 *     u32_t *asserted_attns,
 *     u32_t *deasserted_attns); */
#define GET_ATTN_CHNG_BITS(_pdev, _asserted_attns_ptr, _deasserted_attns_ptr) \
    {                                                                         \
        u32_t attn_chng;                                                      \
        u32_t attn_bits;                                                      \
        u32_t attn_ack;                                                       \
                                                                              \
        attn_bits = (_pdev)->vars.status_virt->deflt.status_attn_bits;        \
        attn_ack = (_pdev)->vars.status_virt->deflt.status_attn_bits_ack;     \
                                                                              \
        attn_chng = attn_bits ^ attn_ack;                                     \
                                                                              \
        *(_asserted_attns_ptr) = attn_bits & attn_chng;                       \
        *(_deasserted_attns_ptr) = ~attn_bits & attn_chng;                    \
    }



/*******************************************************************************
 * Statistics.
 ******************************************************************************/

typedef struct _lm_tx_statistics_t
{
    lm_u64_t ipv4_lso_frames;
    lm_u64_t ipv6_lso_frames;
    lm_u64_t ip_cso_frames;      
    lm_u64_t ipv4_tcp_udp_cso_frames; 
    lm_u64_t ipv6_tcp_udp_cso_frames; 
    u32_t aborted;
    u32_t no_bd;
    u32_t no_desc;
    u32_t no_coalesce_buf;
    u32_t no_map_reg;
} lm_tx_stats_t;


typedef struct _lm_rx_statistics_t
{
    u32_t aborted;
    u32_t err;
    u32_t crc;
    u32_t phy_err;
    u32_t alignment;
    u32_t short_packet;
    u32_t giant_packet;
} lm_rx_stats_t;



/*******************************************************************************
 * Packet descriptor.
 ******************************************************************************/
#if defined(LM_NON_LEGACY_MODE_SUPPORT)
typedef struct _lm_packet_t
{
    /* Must be the first entry in this structure. */
    s_list_entry_t link;

    lm_status_t status;

    union _lm_pkt_info_t
    {
        struct _tx_pkt_info_t
        {
            lm_pkt_tx_info_t *tx_pkt_info;
            u16_t next_bd_idx;
            u16_t bd_used;
            u8_t span_pages;
            u8_t  pad;
            u16_t pad1;
            u32_t size;
            #if DBG
            tx_bd_t *dbg_start_bd;
            u16_t dbg_start_bd_idx;
            u16_t dbg_frag_cnt;
            #endif
        } tx;

        struct _rx_pkt_info_t
        {
            lm_pkt_rx_info_t *rx_pkt_info;
            u16_t next_bd_idx;
            u16_t pad;
            u32_t hash_value;           /* RSS hash value. */
            #if DBG
            rx_bd_t *dbg_bd;
            rx_bd_t *dbg_bd1; /* when vmq header split is enabled */
            #endif
        } rx;
    } u1;
} lm_packet_t;
#else
typedef struct _lm_packet_t
{
    /* Must be the first entry in this structure. */
    s_list_entry_t link;

    lm_status_t status;
    u32_t size;

    union _lm_pkt_info_t
    {
        struct _lm_tx_pkt_info_t
        {
            lm_tx_flag_t flags;

            u16_t vlan_tag;
            u16_t next_bd_idx;
            u16_t bd_used;
            u8_t span_pages;
            u8_t _pad;

            u16_t lso_mss;
            u16_t _pad2;

            u16_t lso_ip_hdr_len;
            u16_t lso_tcp_hdr_len;

            #if DBG
            tx_bd_t *dbg_start_bd;
            u16_t dbg_start_bd_idx;
            u16_t dbg_frag_cnt;
            #endif
        } tx;

        struct _lm_rx_pkt_info_t
        {
            lm_rx_flag_t flags;

            u16_t vlan_tag;
            u16_t ip_cksum;
            u16_t tcp_or_udp_cksum;
            u16_t next_bd_idx;

            u8_t *mem_virt;
            lm_address_t mem_phy;
            u32_t buf_size;

            u32_t hash_value;           /* RSS hash value. */

            #if DBG
            rx_bd_t *dbg_bd;
            #endif
        } rx;
    } u1;
} lm_packet_t;
#endif

DECLARE_FRAG_LIST_BUFFER_TYPE(lm_packet_frag_list_t, MAX_FRAG_CNT);



/*******************************************************************************
 * Configurable parameters for the hardware dependent module.
 ******************************************************************************/

typedef struct _lm_params_t
{
    /* This value is used by the upper module to inform the protocol
     * of the maximum transmit/receive packet size.  Packet size
     * ranges from 1514-9014 bytes.  This value does not include CRC32 and
     * VLAN tag. */
    u32_t mtu;
    /* Current node address.  The MAC address is initially set to the
     * hardware address.  This entry can be modified to allow the driver
     * to override the default MAC address.  The new MAC address takes
     * effect after a driver reset. */
    u8_t mac_addr[8];

    u32_t l2_rx_desc_cnt[MAX_RX_CHAIN];
    u32_t l2_tx_bd_page_cnt[MAX_TX_CHAIN];
    u32_t l2_rx_bd_page_cnt[MAX_RX_CHAIN];

    u32_t l4_tx_bd_page_cnt;
    u32_t limit_l4_tx_bd_cnt;
    u32_t l4_rx_bd_page_cnt;
    u32_t limit_l4_rx_bd_cnt;

    #ifndef EXCLUDE_KQE_SUPPORT
    u32_t kwq_page_cnt;
    u32_t kcq_page_cnt;
    u32_t kcq_history_size;
    u32_t con_kcqe_history_size;
    u32_t con_kwqe_history_size;
    #endif

    u32_t gen_bd_page_cnt;
    u32_t max_gen_buf_cnt;
    u32_t gen_buf_per_alloc;

    /* This parameter controls whether the buffered data (generic buffers)
     * should be copied to a staging buffer for indication. */
    u32_t copy_buffered_data;

    /* All the L2 receive buffers start at a cache line size aligned
     * address.  This value determines the location of the L2 frame header
     * from the beginning of the receive buffer.  The value must be a
     * multiple of 4. */
    u32_t rcv_buffer_offset;

    /* Enable a separate receive queue for receiving packets with
     * TCP SYN bit set. */
    u32_t enable_syn_rcvq;

    /* Buffer of hcopy descriptor to allocate for a connection.  When
     * this value is 0, hcopy is disabled. */
    u32_t hcopy_desc_cnt;

    /* Number of pages used for the hcopy bd chain. */
    u32_t hcopy_bd_page_cnt;

    /* This parameter is only valid when enable_hcopy is enabled.
     * When enable_hcopy is enabled, a given connection will not
     * be able to process subsequent kcqe's after the copy_gen kcqe
     * until the hcopy request (for the copy_gen) has completed.
     * The subsequent kcqe's will be copied to a per-connection kcq
     * buffer.  The parameter controls the size of this buffer. */
    u32_t buffered_kcqe_cnt;

    /* Size of the deferred kcqe queue. */
    u32_t deferred_kcqe_cnt;

    /* Various test/debug modes.  Any validation failure will cause the
     * driver to write to misc.swap_diag0 with the corresponding flag.
     * The intention is to trigger the bus analyzer. */
    u32_t test_mode;
    #define TEST_MODE_DISABLED                  0x00
    #define TEST_MODE_OBSOLETE_0                0x01    /* was TEST_MODE_IKOS */
    #define TEST_MODE_OBSOLETE_1                0x02    /* was TEST_MODE_FPGA */
    #define TEST_MODE_VERIFY_RX_CRC             0x10
    #define TEST_MODE_RX_BD_TAGGING             0x20
    #define TEST_MODE_TX_BD_TAGGING             0x40
    #define TEST_MODE_LOG_REG_ACCESS            0x80
    #define TEST_MODE_SAVE_DUMMY_DMA_DATA       0x0100
    #define TEST_MODE_INIT_GEN_BUF_DATA         0x0200
    #define TEST_MODE_DRIVER_PULSE_ALWAYS_ALIVE 0x0400
    #define TEST_MODE_IGNORE_SHMEM_SIGNATURE    0x0800
    #define TEST_MODE_XDIAG_ISCSI               0x1000

    lm_offload_t ofld_cap;
    lm_wake_up_mode_t wol_cap;
    lm_flow_control_t flow_ctrl_cap;
    lm_medium_t req_medium;

    u32_t selective_autoneg;
    #define SELECTIVE_AUTONEG_OFF                   0
    #define SELECTIVE_AUTONEG_SINGLE_SPEED          1
    #define SELECTIVE_AUTONEG_ENABLE_SLOWER_SPEEDS  2

    u32_t wire_speed;                           /* Not valid on SERDES. */
    u32_t phy_addr;                             /* PHY address. */

    /* Ways for the MAC to determine a link change. */
    u32_t phy_int_mode;
    #define PHY_INT_MODE_AUTO                   0
    #define PHY_INT_MODE_MI_INTERRUPT           1
    #define PHY_INT_MODE_LINK_READY             2
    #define PHY_INT_MODE_AUTO_POLLING           3

    /* Ways for the driver to get the link change event. */
    u32_t link_chng_mode;
    #define LINK_CHNG_MODE_AUTO                 0
    #define LINK_CHNG_MODE_USE_STATUS_REG       1
    #define LINK_CHNG_MODE_USE_STATUS_BLOCK     2

    /* Coalescing paramers. */
    u32_t hc_timer_mode;
    #define HC_COLLECT_MODE                     0x0000
    #define HC_RX_TIMER_MODE                    0x0001
    #define HC_TX_TIMER_MODE                    0x0002
    #define HC_COM_TIMER_MODE                   0x0004
    #define HC_CMD_TIMER_MODE                   0x0008
    #define HC_TIMER_MODE                       0x000f

    u32_t ind_comp_limit;
    u32_t tx_quick_cons_trip;
    u32_t tx_quick_cons_trip_int;
    u32_t rx_quick_cons_trip;
    u32_t rx_quick_cons_trip_int;
    u32_t comp_prod_trip;
    u32_t comp_prod_trip_int;
    u32_t tx_ticks;
    u32_t tx_ticks_int;
    u32_t com_ticks;
    u32_t com_ticks_int;
    u32_t cmd_ticks;
    u32_t cmd_ticks_int;
    u32_t rx_ticks;
    u32_t rx_ticks_int;
    u32_t stats_ticks;

    /* Xinan per-processor HC configuration. */
    u32_t psb_tx_cons_trip;
    u32_t psb_tx_ticks;
    u32_t psb_rx_cons_trip;
    u32_t psb_rx_ticks;
    u32_t psb_comp_prod_trip;
    u32_t psb_com_ticks;
    u32_t psb_cmd_ticks;
    u32_t psb_period_ticks;

    u32_t enable_fir;
    u32_t num_rchans;
    u32_t num_wchans;
    u32_t one_tdma;
    u32_t ping_pong_dma;
    u32_t serdes_pre_emphasis;
    u32_t tmr_reload_value1;

    u32_t keep_vlan_tag;

    u32_t enable_remote_phy;
    u32_t rphy_req_medium;
    u32_t rphy_flow_ctrl_cap;
    u32_t rphy_selective_autoneg;
    u32_t rphy_wire_speed;

    u32_t bin_mq_mode;
    u32_t validate_l4_data;

    /* disable PCIe non-FATAL error reporting */
    u32_t disable_pcie_nfr;

    // setting for L2 flow control 0 for disable 1 for enable: 
    u32_t fw_flow_control;
    // This parameter dictates how long to wait before dropping L2 packet
    // due to insufficient posted buffers
    // 0 mean no waiting before dropping, 0xFFFF means maximum wait
    u32_t fw_flow_control_wait;
    // 8 lsb represents watermark for flow control, 0 is disable
    u32_t fw_flow_control_watermarks;

    u32_t ena_large_grc_timeout;

    /* 0 causes the driver to report the current flow control configuration.
     * 1 causes the driver to report the flow control autoneg result. */
    u32_t flow_control_reporting_mode;
} lm_params_t;



/*******************************************************************************
 * Device NVM info -- The native strapping does not support the new parts, the
 *                    software needs to reconfigure for them.
 ******************************************************************************/

typedef struct _flash_spec_t
{
    u32_t buffered;
    u32_t shift_bits;
    u32_t page_size;
    u32_t addr_mask;
    u32_t total_size;
} flash_spec_t;


/*******************************************************************************
 * Device info.
 ******************************************************************************/

typedef struct _lm_hardware_info_t
{
    /* PCI info. */
    u16_t vid;
    u16_t did;
    u16_t ssid;
    u16_t svid;

    u8_t irq;
    u8_t int_pin;
    u8_t latency_timer;
    u8_t cache_line_size;
    u8_t rev_id;
    u8_t _pad[3];

    u8_t mac_id;            /* 5709 function 0 or 1. */
    u8_t bin_size;          /* 5709 bin size in term of context pages. */
    u16_t first_l4_l5_bin;  /* 5709 first bin. */

    lm_address_t mem_base;
    u32_t bar_size;

    /* Device info. */
    u32_t phy_id;               /* (phy_reg2 << 16) | phy_reg3 */
    u8_t mac_addr[8];           /* Hardware MAC address. */
    u8_t iscsi_mac_addr[8];     /* Hardware MAC address for iSCSI. */

    u32_t shmem_base;           /* Firmware share memory base addr. */

    u32_t chip_id;      /* chip num:16-31, rev:12-15, metal:4-11, bond_id:0-3 */
    #define CHIP_NUM(_p)                (((_p)->hw_info.chip_id) & 0xffff0000)
    #define CHIP_NUM_5706               0x57060000
    #define CHIP_NUM_5708               0x57080000
    #define CHIP_NUM_5709               0x57090000
    #define CHIP_NUM_57728              0x00000000

    #define CHIP_REV(_p)                (((_p)->hw_info.chip_id) & 0x0000f000)
    #define CHIP_REV_Ax                 0x00000000
    #define CHIP_REV_Bx                 0x00001000
    #define CHIP_REV_Cx                 0x00002000
    #define CHIP_REV_FPGA               0x0000f000
    #define CHIP_REV_IKOS               0x0000e000

    #define CHIP_METAL(_p)              (((_p)->hw_info.chip_id) & 0x00000ff0)
    #define CHIP_BONDING(_p)            (((_p)->hw_info.chip_id) & 0x0000000f)

    #define CHIP_ID(_p)                 (((_p)->hw_info.chip_id) & 0xfffffff0)
    #define CHIP_ID_5706_A0             0x57060000
    #define CHIP_ID_5706_A1             0x57060010
    #define CHIP_ID_5706_FPGA           0x5706f000
    #define CHIP_ID_5706_IKOS           0x5706e000
    #define CHIP_ID_5708_A0             0x57080000
    #define CHIP_ID_5708_B0             0x57081000
    #define CHIP_ID_5708_B1             0x57081010
    #define CHIP_ID_5708_FPGA           0x5708f000
    #define CHIP_ID_5708_IKOS           0x5708e000
    #define CHIP_ID_5709_A0             0x57090000
    #define CHIP_ID_5709_A1             0x57090010
    #define CHIP_ID_5709_B0             0x57091000
    #define CHIP_ID_5709_B1             0x57091010
    #define CHIP_ID_5709_B2             0x57091020
    #define CHIP_ID_5709_FPGA           0x5709f000
    #define CHIP_ID_5709_IKOS           0x5709e000

    #define CHIP_BOND_ID(_p)            (((_p)->hw_info.chip_id) & 0xf)

    /* A serdes chip will have the first bit of the bond id set. */
    #define CHIP_BOND_ID_SERDES_BIT     0x01

    /* HW config from nvram. */
    u32_t nvm_hw_config;

    u32_t max_toe_conn;
    u32_t max_iscsi_conn;
    u32_t max_iscsi_pending_tasks;

    /* Bus info. */
    u8_t bus_mode;
    #define BUS_MODE_PCI                0
    #define BUS_MODE_PCIX               1
    #define BUS_MODE_PCIE               2

    u8_t bus_width;
    #define BUS_WIDTH_32_BIT            32
    #define BUS_WIDTH_64_BIT            64

    u16_t bus_speed;
    #define BUS_SPEED_33_MHZ            33
    #define BUS_SPEED_50_MHZ            50
    #define BUS_SPEED_66_MHZ            66
    #define BUS_SPEED_100_MHZ           100
    #define BUS_SPEED_133_MHZ           133

    /* EPB info.  Only valid for 5708. */
    u8_t pcie_bus_num;

    u8_t pcie_max_width;
    u8_t pcie_width;
    #define PCIE_WIDTH_1                1
    #define PCIE_WIDTH_2                2
    #define PCIE_WIDTH_4                4
    #define PCIE_WIDTH_8                8
    #define PCIE_WIDTH_16               16
    #define PCIE_WIDTH_32               32

    u8_t _unused_;

    u16_t pcie_max_speed;
    u16_t pcie_speed;
    #define PCIE_SPEED_2_5_G            25
    #define PCIE_SPEED_5_G              50

    /* Flash info. */
    flash_spec_t flash_spec;
} lm_hardware_info_t;



/*******************************************************************************
 * Device state variables.
 ******************************************************************************/

typedef struct _phy_mem_block_t
{
    lm_address_t start_phy;
    u8_t *start;
    u32_t size;
} phy_mem_block_t;


typedef struct _lm_variables_t
{
#ifdef SOLARIS
	ddi_acc_handle_t dmaRegAccHandle;
#endif
    volatile reg_space_t *regview;

    volatile status_blk_combined_t *status_virt;
    lm_address_t status_phy;

    lm_status_t link_status;
    lm_medium_t medium;
    lm_flow_control_t flow_control;

    /* remote phy status. */
    u8_t rphy_status;
    #define RPHY_STATUS_ACTIVE          0x01
    #define RPHY_STATUS_MODULE_PRESENT  0x02

    u8_t enable_cu_rate_limiter;

    u16_t bcm5706s_tx_drv_cur;

    volatile statistics_block_t *stats_virt;
    lm_address_t stats_phy;

    u16_t fw_wr_seq;
    u8_t fw_timed_out;

    /* Serdes autonegotiation fallback.  For a serdes medium,
     * if we cannot get link via autonegotiation, we'll force
     * the speed to get link. */
    u8_t serdes_fallback_select;
    u8_t serdes_fallback_status;
    #define SERDES_FALLBACK_NONE            0
    #define SERDES_FALLBACK_1G              1
    #define SERDES_FALLBACK_2_5G            2

    /* This flag is set if the cable is attached when there
     * is no link.  The upper module could check this flag to
     * determine if there is a need to wait for link. */
    u8_t cable_is_attached;

    /* Write sequence for driver pulse. */
    u16_t drv_pulse_wr_seq;

    /* 5708 pre-emphasis. */
    u32_t serdes_pre_emphasis;

    u32_t interrupt_mode;
    
    u32_t cu_mbuf_cnt; /*5709 only */

    u32_t hw_filter_ctx_offset;
    /* 5709 backing store context memory. */
    #ifndef MAX_CTX
    #define MAX_CTX                         (16 * 1024)
    #endif
    #define ONE_CTX_SIZE                    0x80
    #define NUM_CTX_MBLKS                   16
    #define CTX_MBLK_SIZE                   (128 * 1024)
    phy_mem_block_t ctx_mem[NUM_CTX_MBLKS];
} lm_variables_t;



/*******************************************************************************
 * Transmit info.
 ******************************************************************************/

typedef struct _lm_tx_chain_t
{
    u32_t idx;
    #define TX_CHAIN_IDX0                       0
    #define TX_CHAIN_IDX1                       1
    #define TX_CHAIN_IDX2                       2
    #define TX_CHAIN_IDX3                       3
    #define TX_CHAIN_IDX4                       4
    #define TX_CHAIN_IDX5                       5
    #define TX_CHAIN_IDX6                       6
    #define TX_CHAIN_IDX7                       7
    #define TX_CHAIN_IDX8                       8
    #define TX_CHAIN_IDX9                       9
    #define TX_CHAIN_IDX10                      10
    #define TX_CHAIN_IDX11                      11

    u8_t  cpu_num;
    u8_t  cpu_num_valid;
    u16_t reserve2;
    /* This is a contiguous memory block of params.l2_tx_bd_page_cnt pages
     * used for L2 tx_bd chain.  The BD chain is arranged as a circular
     * chain where the last BD entry of a page points to the next page,
     * and the last BD entry of the last page points to the first. */
    tx_bd_t *bd_chain_virt;
    lm_address_t bd_chain_phy;

    u32_t cid_addr;
    u16_t prod_idx;
    u16_t con_idx;
    tx_bd_t *prod_bd;
    u32_t prod_bseq;
    volatile u16_t *hw_con_idx_ptr;
    u16_t bd_left;

    s_list_t active_descq;
} lm_tx_chain_t;


typedef struct _lm_tx_info_t
{
    lm_tx_chain_t chain[MAX_TX_CHAIN];

    u32_t num_txq;
    u32_t cu_idx;

    lm_tx_stats_t stats;
} lm_tx_info_t;



/*******************************************************************************
 * Receive info.
 ******************************************************************************/

typedef struct _lm_rx_chain_t
{
    u32_t idx;
    #define RX_CHAIN_IDX0                       0
    #define RX_CHAIN_IDX1                       1
    #define RX_CHAIN_IDX2                       2
    #define RX_CHAIN_IDX3                       3
    #define RX_CHAIN_IDX4                       4
    #define RX_CHAIN_IDX5                       5
    #define RX_CHAIN_IDX6                       6
    #define RX_CHAIN_IDX7                       7
    #define RX_CHAIN_IDX8                       8
    #define RX_CHAIN_IDX9                       9
    #define RX_CHAIN_IDX10                      10
    #define RX_CHAIN_IDX11                      11
    #define RX_CHAIN_IDX12                      12
    #define RX_CHAIN_IDX13                      13
    #define RX_CHAIN_IDX14                      14
    #define RX_CHAIN_IDX15                      15

    u8_t  cpu_num;  /* place holder for cpu affinity(msix) */
    u8_t  cpu_num_valid;
    u16_t max_pkt_len;
    /* This is a contiguous memory block of params.l2_rx_bd_page_cnt pages
     * used for rx completion.  The BD chain is arranged as a circular
     * chain where the last BD entry of a page points to the next page,
     * and the last BD entry of the last page points to the first. */
    rx_bd_t *bd_chain_virt;
    lm_address_t bd_chain_phy;

    u32_t cid_addr;
    u16_t prod_idx;
    u16_t con_idx;
    u16_t hw_con_idx;
    u16_t _pad;

    rx_bd_t *prod_bd;
    u32_t prod_bseq;
    volatile u16_t *hw_con_idx_ptr;
    u16_t bd_left;

    u32_t vmq_lookahead_size;
    s_list_t free_descq; /* legacy mode variable */
    s_list_t active_descq;
} lm_rx_chain_t;


typedef struct _lm_rx_info_t
{
    lm_rx_chain_t chain[MAX_RX_CHAIN];

    u32_t num_rxq;

    #define RX_FILTER_USER_IDX0         0
    #define RX_FILTER_USER_IDX1         1
    #define RX_FILTER_USER_IDX2         2
    #define RX_FILTER_USER_IDX3         3
    #define MAX_RX_FILTER_USER_CNT      4
    lm_rx_mask_t mask[MAX_RX_FILTER_USER_CNT];

    lm_rx_stats_t stats;

    #ifndef EXCLUDE_RSS_SUPPORT
    u32_t rss_tbl_size;
    u8_t *rss_ind_table_virt;
    lm_address_t rss_ind_table_phy;
    #endif
} lm_rx_info_t;



#ifndef EXCLUDE_KQE_SUPPORT
/*******************************************************************************
 * Kernel work and completion queue info.
 ******************************************************************************/

typedef struct _lm_kq_info_t
{
    u32_t kwq_cid_addr;
    u32_t kcq_cid_addr;

    kwqe_t *kwq_virt;
    kwqe_t *kwq_prod_qe;
    kwqe_t *kwq_con_qe;
    kwqe_t *kwq_last_qe;
    u16_t kwq_prod_idx;
    u16_t kwq_con_idx;
    u32_t kwqe_left;

    kcqe_t *kcq_virt;
    kcqe_t *kcq_con_qe;
    kcqe_t *kcq_last_qe;
    u16_t kcq_con_idx;
    u16_t history_kcq_con_idx;
    kcqe_t *history_kcq_con_qe;

    void *kwq_pgtbl_virt;
    lm_address_t kwq_pgtbl_phy;
    lm_address_t kwq_phy;

    void *kcq_pgtbl_virt;
    lm_address_t kcq_pgtbl_phy;
    lm_address_t kcq_phy;

    /* Statistics. */
    u32_t no_kwq_bd_left;
} lm_kq_info_t;
#endif /* EXCLUDE_KQE_SUPPORT */



/*******************************************************************************
 * Include the l4 offload header file.
 ******************************************************************************/

#if INCLUDE_OFLD_SUPPORT
#include "lm_ofld.h"
#else
/* This structure is only used as a placed holder and it is not referenced. */
typedef struct _lm_offload_info_t
{
    void *unused;
} lm_offload_info_t;
#endif



/*******************************************************************************
 * Main device block.
 ******************************************************************************/

typedef enum
{
    OS_TYPE_UNKNOWN = 0,
    OS_TYPE_W2K     = 1,
    OS_TYPE_WXP     = 2,
    OS_TYPE_W2K3    = 3,
    OS_TYPE_VISTA   = 4,
    OS_TYPE_W2K8    = 5,
    OS_TYPE_WIN7    = 6,
    OS_TYPE_WIN8    = 7,
} lm_os_type_t;


typedef struct _lm_device_t
{
    d_list_entry_t link;        /* Link for the device list. */

    u32_t ver_num;              /* major:8 minor:8 rel:8 fix:8 */
    u8_t ver_str[32];           /* null terminated version string. */

    lm_os_type_t os_type;

    lm_variables_t vars;
    lm_tx_info_t tx_info;
    lm_rx_info_t rx_info;
    #ifndef EXCLUDE_KQE_SUPPORT
    lm_kq_info_t kq_info;
    #endif
    lm_offload_info_t ofld;
    lm_hardware_info_t hw_info;
    lm_params_t params;
    lm_mc_table_t mc_table;
    lm_nwuf_list_t nwuf_list;

    #ifdef UEFI
    EFI_PCI_IO_PROTOCOL *PciIoFuncs;
    #endif

    /* Statistics. */
    u32_t chip_reset_cnt;
    u32_t fw_timed_out_cnt;
} lm_device_t;



/*******************************************************************************
 * Functions exported between file modules.
 ******************************************************************************/

lm_status_t
lm_mwrite(
    lm_device_t *pdev,
    u32_t phy_addr,
    u32_t phy_reg,
    u32_t val);

lm_status_t
lm_mread(
    lm_device_t *pdev,
    u32_t phy_addr,
    u32_t phy_reg,
    u32_t *ret_val);

u32_t
lm_nvram_query(
    lm_device_t *pdev,
    u8_t reset_flash_block,
    u8_t no_hw_mod);

void
lm_nvram_init(
    lm_device_t *pdev,
    u8_t reset_flash_block);

lm_status_t
lm_nvram_read(
    lm_device_t *pdev,
    u32_t offset,
    u32_t *ret_buf,
    u32_t buf_size);        /* Must be a multiple of 4. */

lm_status_t
lm_nvram_write(
    lm_device_t *pdev,
    u32_t offset,
    u32_t *data_buf,
    u32_t buf_size);        /* Must be a multiple of 4. */

void
lm_init_cpus(
    lm_device_t *pdev,
    u32_t cpu_mask);
#define CPU_RV2P_1          0x00000001
#define CPU_RV2P_2          0x00000002
#define CPU_RXP             0x00000004
#define CPU_TXP             0x00000008
#define CPU_TPAT            0x00000010
#define CPU_COM             0x00000020
#define CPU_CP              0x00000040
#define CPU_ALL             0xffffffff

void
lm_reg_rd_ind(
    lm_device_t *pdev,
    u32_t offset,
    u32_t *ret);

void
lm_reg_wr_ind(
    lm_device_t *pdev,
    u32_t offset,
    u32_t val);

void
lm_ctx_wr(
    lm_device_t *pdev,
    u32_t cid_addr,
    u32_t offset,
    u32_t val);

u32_t
lm_ctx_rd(
    lm_device_t *pdev,
    u32_t cid_addr,
    u32_t offset);

void
lm_setup_bd_chain_ring(
    u8_t *mem_virt,
    lm_address_t mem_phy,
    u32_t page_cnt);

lm_status_t
lm_init_remote_phy(
    lm_device_t *pdev,
    lm_link_settings_t *local_link,
    lm_link_settings_t *rphy_link);

lm_status_t
lm_init_mac_link(
    lm_device_t *pdev);

#ifndef EXCLUDE_KQE_SUPPORT
u32_t
lm_submit_kernel_wqes(
    lm_device_t *pdev,
    kwqe_t *wqes[],
    u32_t num_wqes);

u32_t
lm_get_kernel_cqes(
    lm_device_t *pdev,
    kcqe_t *cqe_ptr[],
    u32_t ptr_cnt);

u8_t
lm_ack_kernel_cqes(
    lm_device_t *pdev,
    u32_t num_cqes);

void
lm_ack_completed_wqes(
    lm_device_t *pdev);
#endif /* EXCLUDE_KQE_SUPPORT */

u8_t
fw_reset_sync(
    lm_device_t *pdev,
    lm_reason_t reason,
    u32_t msg_data,
    u32_t fw_ack_timeout_us);   /* timeout in microseconds. */

void
lm_reg_rd_blk(
    lm_device_t *pdev,
    u32_t reg_offset,
    u32_t *buf_ptr,
    u32_t u32t_cnt);

void
lm_reg_rd_blk_ind(
    lm_device_t *pdev,
    u32_t reg_offset,
    u32_t *buf_ptr,
    u32_t u32t_cnt);

void
lm_reg_wr_blk(
    lm_device_t *pdev,
    u32_t reg_offset,
    u32_t *data_ptr,
    u32_t u32t_cnt);

void
lm_reg_wr_blk_ind(
    lm_device_t *pdev,
    u32_t reg_offset,
    u32_t *data_ptr,
    u32_t u32t_cnt);

lm_status_t
lm_submit_fw_cmd(
    lm_device_t *pdev,
    u32_t drv_msg);

lm_status_t
lm_last_fw_cmd_status(
    lm_device_t *pdev);

#ifndef EXCLUDE_RSS_SUPPORT

#if defined(LM_NON_LEGACY_MODE_SUPPORT)
lm_status_t
lm_enable_rss(
    lm_device_t *pdev,
    lm_rss_hash_t hash_type,
    PROCESSOR_NUMBER *indirection_table,
    u32_t table_size,
    u8_t *hash_key,
    u32_t key_size,
    u8_t *cpu_tbl,
    u8_t *rss_qidx_tbl);
#else
lm_status_t
lm_enable_rss(
    lm_device_t *pdev,
    lm_rss_hash_t hash_type,
    u8_t *indirection_table,
    u32_t table_size,
    u8_t *hash_key,
    u32_t key_size);
#endif

lm_status_t
lm_disable_rss(
    lm_device_t *pdev);
#endif /* EXCLUDE_RSS_SUPPORT */

lm_medium_t
lm_get_medium(
    lm_device_t *pdev);

u32_t
lm_mb_get_cid_addr(
    lm_device_t *pdev,
    u32_t cid);

u32_t
lm_mb_get_bypass_addr(
    lm_device_t *pdev,
    u32_t cid);

void
lm_set_pcie_nfe_report(
    lm_device_t *pdev);

void 
lm_clear_coalescing_ticks(
    lm_device_t *pdev);

void
lm_post_rx_bd(
    lm_device_t *pdev,
    lm_rx_chain_t *rxq
    );

void 
lm_create_q_group(
    lm_device_t *pdev,
    u32_t q_group_id,
    u32_t lookahead_sz 
    );

lm_status_t 
lm_destroy_q_group(
    lm_device_t *pdev,
    u32_t q_group_id,
    u32_t num_queues
    );

void 
lm_update_defq_filter_ctx(
    lm_device_t *pdev,
    u8_t valid
    );

lm_status_t 
lm_chng_q_group_filter(
    lm_device_t *pdev,
    u32_t q_group_id,
    u8_t  *dest_mac,
    u16_t *vlan_ptr,
    u32_t filter_id
    );

#ifndef EXCLUDE_KQE_SUPPORT
u32_t
lm_service_l2_kcqes(
    struct _lm_device_t *pdev,
    kcqe_t *cqe_ptr[],
    u32_t num_cqes);
#endif

/*******************************************************************************
 * Register access macros.
 ******************************************************************************/

#if DBG && LOG_REG_ACCESS

#define LOG_REG_RD(_pdev, _offset, _val) \
    if((_pdev)->params.test_mode & TEST_MODE_LOG_REG_ACCESS) \
    { \
        DbgMessage2(_pdev, INFORM, "rd 0x%04x = 0x%08x\n", _offset, _val); \
    }

#define LOG_REG_WR(_pdev, _offset, _val) \
    if((_pdev)->params.test_mode & TEST_MODE_LOG_REG_ACCESS) \
    { \
        DbgMessage2(_pdev, INFORM, "wr 0x%04x 0x%08x\n", _offset, _val); \
    }

#define LOG_MBQ_WR32(_pdev, _cid, _offset, _val) \
    if((_pdev)->params.test_mode & TEST_MODE_LOG_REG_ACCESS) \
    { \
        DbgMessage3(_pdev, INFORM, "mbq_wr32 (0x%04x,0x%02x) = 0x%08x\n", \
            _cid, _offset, _val); \
    }

#define LOG_MBQ_WR32(_pdev, _cid, _offset, _val) \
    if((_pdev)->params.test_mode & TEST_MODE_LOG_REG_ACCESS) \
    { \
        DbgMessage3(_pdev, INFORM, "mbq_wr32 (0x%04x,0x%02x) = 0x%08x\n", \
            _cid, _offset, _val); \
    }

#define LOG_MBQ_WR16(_pdev, _cid, _offset, _val) \
    if((_pdev)->params.test_mode & TEST_MODE_LOG_REG_ACCESS) \
    { \
        DbgMessage3(_pdev, INFORM, "mbq_wr16 (0x%04x,0x%02x) = 0x%04x\n", \
            _cid, _offset, _val); \
    }

#define LOG_MBQ_WR8(_pdev, _cid, _offset, _val) \
    if((_pdev)->params.test_mode & TEST_MODE_LOG_REG_ACCESS) \
    { \
        DbgMessage3(_pdev, INFORM, "mbq_wr8 (0x%04x,0x%02x) = 0x%02x\n", \
            _cid, _offset, _val); \
    }

#else
#define LOG_REG_RD(_pdev, _offset, _val)
#define LOG_REG_WR(_pdev, _offset, _val)
#define LOG_MBQ_WR32(_pdev, _cid, _offset, _val)
#define LOG_MBQ_WR16(_pdev, _cid, _offset, _val)
#define LOG_MBQ_WR8(_pdev, _cid, _offset, _val)
#endif

/* Indirect register access. */
#define REG_RD_IND(_pdev, _offset, _ret)    lm_reg_rd_ind(_pdev, _offset, _ret)
#define REG_WR_IND(_pdev, _offset, _val)    lm_reg_wr_ind(_pdev, _offset, _val)

#ifdef CONFIG_PPC64

/* Register access via register name. */
#define REG_RD(_pdev, _name, _ret) \
    mm_read_barrier(); \
    *(_ret) = pal_readl(&((_pdev)->vars.regview->_name)); \
    LOG_REG_RD( \
        _pdev, \
        OFFSETOF(reg_space_t, _name), \
        (_pdev)->vars.regview->_name)

#define REG_WR(_pdev, _name, _val) \
    LOG_REG_WR(_pdev, OFFSETOF(reg_space_t, _name), _val); \
    pal_writel((_val), &((_pdev)->vars.regview->_name)); \
    mm_write_barrier()


/* Register access via register offset. */
#define REG_RD_OFFSET(_pdev, _offset, _ret) \
    mm_read_barrier(); \
    *(_ret) = pal_readl((volatile u32_t *) ((u8_t *) (_pdev)->vars.regview + (_offset))); \
    LOG_REG_RD( \
        _pdev, \
        _offset, \
        *((volatile u32_t *) ((u8_t *) (_pdev)->vars.regview + (_offset))))

#define REG_WR_OFFSET(_pdev, _offset, _val) \
    LOG_REG_WR(_pdev, _offset, _val); \
    pal_writel((_val), (volatile u32_t *) ((u8_t *) (_pdev)->vars.regview + (_offset))); \
    mm_write_barrier()


/* Context write via mailbox queue. */
#define MBQ_WR32(_pdev, _cid, _offset, _val) \
    LOG_MBQ_WR32(_pdev, _cid, _offset, _val); \
    pal_writel((_val), (volatile u32_t *) ((u8_t *) (_pdev)->vars.regview + \
                    MB_GET_CID_ADDR(_pdev, _cid) + (_offset))); \
    mm_write_barrier(); \
    if(CHIP_REV(_pdev) == CHIP_REV_IKOS) \
    { \
        mm_wait(_pdev, 1); \
    }

#define MBQ_WR16(_pdev, _cid, _offset, _val) \
    LOG_MBQ_WR16(_pdev, _cid, _offset, _val); \
    pal_writew((_val), (volatile u16_t *) ((u8_t *) (_pdev)->vars.regview + \
                    MB_GET_CID_ADDR(_pdev, _cid) + (_offset))); \
    mm_write_barrier(); \
    if(CHIP_REV(_pdev) == CHIP_REV_IKOS) \
    { \
        mm_wait(_pdev, 1); \
    }

#define MBQ_WR8(_pdev, _cid, _offset, _val) \
    LOG_MBQ_WR8(_pdev, _cid, _offset, _val); \
    pal_writeb((_val), (volatile u8_t *) ((u8_t *) (_pdev)->vars.regview + \
                    MB_GET_CID_ADDR(_pdev, _cid) + (_offset))); \
    mm_write_barrier(); \
    if(CHIP_REV(_pdev) == CHIP_REV_IKOS) \
    { \
        mm_wait(_pdev, 1); \
    }

#else /* CONFIG_PPC64 */

#ifdef SOLARIS

/* Register access via register name. */
#define REG_RD(_pdev, _name, _ret)                             \
    mm_read_barrier();                                         \
    if ((OFFSETOF(reg_space_t, _name) % 4) == 0)               \
    {                                                          \
        *(_ret) =                                              \
            ddi_get32((_pdev)->vars.dmaRegAccHandle,           \
                      (u32_t *)&(_pdev)->vars.regview->_name); \
    }                                                          \
    else                                                       \
    {                                                          \
        *(_ret) =                                              \
            ddi_get16((_pdev)->vars.dmaRegAccHandle,           \
                      (u16_t *)&(_pdev)->vars.regview->_name); \
    }                                                          \
    LOG_REG_RD(_pdev, OFFSETOF(reg_space_t, _name), *(_ret))

#define REG_WR(_pdev, _name, _val)                         \
    LOG_REG_WR(_pdev, OFFSETOF(reg_space_t, _name), _val); \
    if ((OFFSETOF(reg_space_t, _name) % 4) == 0)           \
    {                                                      \
        ddi_put32((_pdev)->vars.dmaRegAccHandle,           \
                  (u32_t *)&(_pdev)->vars.regview->_name,  \
                  (_val));                                 \
    }                                                      \
    else                                                   \
    {                                                      \
        ddi_put16((_pdev)->vars.dmaRegAccHandle,           \
                  (u16_t *)&(_pdev)->vars.regview->_name,  \
                  (u16_t)(_val));                          \
    }                                                      \
    mm_write_barrier()

/* Register access via register offset. */
#define REG_RD_OFFSET(_pdev, _offset, _ret)                                    \
    mm_read_barrier();                                                         \
    *(_ret) = ddi_get32((_pdev)->vars.dmaRegAccHandle,                         \
                        (u32_t *)((u8_t *)(_pdev)->vars.regview + (_offset))); \
    LOG_REG_RD(_pdev, _offset, *(_ret))

#define REG_WR_OFFSET(_pdev, _offset, _val)                         \
    LOG_REG_WR(_pdev, _offset, _val);                               \
    ddi_put32((_pdev)->vars.dmaRegAccHandle,                        \
              (u32_t *)((u8_t *)(_pdev)->vars.regview + (_offset)), \
              (_val));                                              \
    mm_write_barrier()

/* Context write via mailbox queue. */
#define MBQ_WR32(_pdev, _cid, _offset, _val)                       \
    LOG_MBQ_WR32(_pdev, _cid, _offset, _val);                      \
    ddi_put32((_pdev)->vars.dmaRegAccHandle,                       \
              (u32_t *)((u8_t *)(_pdev)->vars.regview +            \
                        MB_GET_CID_ADDR(_pdev, _cid) + (_offset)), \
              (_val));                                             \
    mm_write_barrier();                                            \
    if(CHIP_REV(_pdev) == CHIP_REV_IKOS)                           \
    {                                                              \
        mm_wait(_pdev, 1);                                         \
    }

#define MBQ_WR16(_pdev, _cid, _offset, _val)                       \
    LOG_MBQ_WR16(_pdev, _cid, _offset, _val);                      \
    ddi_put16((_pdev)->vars.dmaRegAccHandle,                       \
              (u16_t *)((u8_t *)(_pdev)->vars.regview +            \
                        MB_GET_CID_ADDR(_pdev, _cid) + (_offset)), \
              (u16_t)(_val));                                      \
    mm_write_barrier();                                            \
    if(CHIP_REV(_pdev) == CHIP_REV_IKOS)                           \
    {                                                              \
        mm_wait(_pdev, 1);                                         \
    }

#define MBQ_WR8(_pdev, _cid, _offset, _val)                      \
    LOG_MBQ_WR8(_pdev, _cid, _offset, _val);                     \
    ddi_put8((_pdev)->vars.dmaRegAccHandle,                      \
             (u8_t *)((u8_t *)(_pdev)->vars.regview +            \
                      MB_GET_CID_ADDR(_pdev, _cid) + (_offset)), \
             (u8_t)(_val));                                      \
    mm_write_barrier();                                          \
    if(CHIP_REV(_pdev) == CHIP_REV_IKOS)                         \
    {                                                            \
        mm_wait(_pdev, 1);                                       \
    }

#elif !defined(UEFI)

/* Register access via register name. */
#define REG_RD(_pdev, _name, _ret) \
    mm_read_barrier(); \
    *(_ret) = ((_pdev)->vars.regview->_name); \
    LOG_REG_RD( \
        _pdev, \
        OFFSETOF(reg_space_t, _name), \
        (_pdev)->vars.regview->_name)

#define REG_WR(_pdev, _name, _val) \
    LOG_REG_WR(_pdev, OFFSETOF(reg_space_t, _name), _val); \
    (_pdev)->vars.regview->_name = (_val); \
    mm_write_barrier()


/* Register access via register offset. */
#define REG_RD_OFFSET(_pdev, _offset, _ret) \
    mm_read_barrier(); \
    *(_ret) = *((volatile u32_t *) ((u8_t *) (_pdev)->vars.regview+(_offset)));\
    LOG_REG_RD( \
        _pdev, \
        _offset, \
        *((volatile u32_t *) ((u8_t *) (_pdev)->vars.regview + (_offset))))

#define REG_WR_OFFSET(_pdev, _offset, _val) \
    LOG_REG_WR(_pdev, _offset, _val); \
    *((volatile u32_t *) ((u8_t *) (_pdev)->vars.regview+(_offset)))=(_val); \
    mm_write_barrier()


/* Context write via mailbox queue. */
#define MBQ_WR32(_pdev, _cid, _offset, _val) \
    LOG_MBQ_WR32(_pdev, _cid, _offset, _val); \
    *((volatile u32_t *) (((u8_t *) (_pdev)->vars.regview) + \
        MB_GET_CID_ADDR(_pdev, _cid) + (_offset))) = (_val); \
    mm_write_barrier(); \
    if(CHIP_REV(_pdev) == CHIP_REV_IKOS) \
    { \
        mm_wait(_pdev, 1); \
    }

#define MBQ_WR16(_pdev, _cid, _offset, _val) \
    LOG_MBQ_WR16(_pdev, _cid, _offset, _val); \
    *((volatile u16_t *) (((u8_t *) (_pdev)->vars.regview) + \
        MB_GET_CID_ADDR(_pdev, _cid) + (_offset))) = (u16_t) (_val); \
    mm_write_barrier(); \
    if(CHIP_REV(_pdev) == CHIP_REV_IKOS) \
    { \
        mm_wait(_pdev, 1); \
    }

#define MBQ_WR8(_pdev, _cid, _offset, _val) \
    LOG_MBQ_WR8(_pdev, _cid, _offset, _val); \
    *((volatile u8_t *) (((u8_t *) (_pdev)->vars.regview) + \
        MB_GET_CID_ADDR(_pdev, _cid) + (_offset))) = (u8_t) (_val); \
    mm_write_barrier(); \
    if(CHIP_REV(_pdev) == CHIP_REV_IKOS) \
    { \
        mm_wait(_pdev, 1); \
    }

#else   //UEFI

/* Register access via register name. */
#define REG_RD(_pdev, _name, _ret) \
    if ((OFFSETOF(reg_space_t, _name) % 4) == 0) \
    { \
        (_pdev)->PciIoFuncs->Mem.Read( \
                (_pdev)->PciIoFuncs, \
                EfiPciIoWidthUint32, \
                0, \
                (UINT64)(OFFSETOF(reg_space_t, _name)), \
                1, \
                _ret); \
    } \
    else \
    { \
        (_pdev)->PciIoFuncs->Mem.Read( \
                (_pdev)->PciIoFuncs, \
                EfiPciIoWidthUint16, \
                0, \
                (UINT64)(OFFSETOF(reg_space_t, _name)), \
                1, \
                _ret); \
    }

#define REG_WR(_pdev, _name, _val) \
    if ((OFFSETOF(reg_space_t, _name) % 4) == 0) \
    { \
        { \
            u32_t w_val; \
            w_val = _val; \
            (_pdev)->PciIoFuncs->Mem.Write( \
                    (_pdev)->PciIoFuncs, \
                    EfiPciIoWidthUint32, \
                    0, \
                    (UINT64)(OFFSETOF(reg_space_t, _name)), \
                    1, \
                    &w_val); \
        } \
    } \
    else \
    { \
        { \
            u16_t w_val; \
            w_val = (u16_t)_val; \
            (_pdev)->PciIoFuncs->Mem.Write( \
                    (_pdev)->PciIoFuncs, \
                    EfiPciIoWidthUint16, \
                    0, \
                    (UINT64)(OFFSETOF(reg_space_t, _name)), \
                    1, \
                    &w_val); \
        } \
    }


/* Register access via register offset. */
#define REG_RD_OFFSET(_pdev, _offset, _ret) \
    (_pdev)->PciIoFuncs->Mem.Read( \
            (_pdev)->PciIoFuncs, \
            EfiPciIoWidthUint32, \
            0, \
            (UINT64)(_offset), \
            1, \
            _ret)

#define REG_WR_OFFSET(_pdev, _offset, _val) \
    { \
        u32_t w_val; \
        w_val = _val; \
        (_pdev)->PciIoFuncs->Mem.Write( \
                (_pdev)->PciIoFuncs, \
                EfiPciIoWidthUint32, \
                0, \
                (UINT64)(_offset), \
                1, \
                &w_val); \
    }


/* Context write via mailbox queue. */
#define MBQ_WR32(_pdev, _cid, _offset, _val) \
    { \
        u32_t w_val; \
        w_val = _val; \
        (_pdev)->PciIoFuncs->Mem.Write( \
                (_pdev)->PciIoFuncs, \
                EfiPciIoWidthUint32, \
                0, \
                (UINT64)(MB_GET_CID_ADDR(_pdev, _cid) + (_offset)), \
                1, \
                &w_val); \
        if(CHIP_REV(_pdev) == CHIP_REV_IKOS) \
        { \
            mm_wait(_pdev, 1); \
        } \
    }

#define MBQ_WR16(_pdev, _cid, _offset, _val) \
    { \
        u16_t w_val; \
        w_val = _val; \
        (_pdev)->PciIoFuncs->Mem.Write( \
                (_pdev)->PciIoFuncs, \
                EfiPciIoWidthUint16, \
                0, \
                (UINT64)(MB_GET_CID_ADDR(_pdev, _cid) + (_offset)), \
                1, \
                &w_val); \
        if(CHIP_REV(_pdev) == CHIP_REV_IKOS) \
        { \
            mm_wait(_pdev, 1); \
        } \
    }

#define MBQ_WR8(_pdev, _cid, _offset, _val) \
    { \
        u8_t w_val; \
        w_val = _val; \
        (_pdev)->PciIoFuncs->Mem.Write( \
                (_pdev)->PciIoFuncs, \
                EfiPciIoWidthUint8, \
                0, \
                (UINT64)(MB_GET_CID_ADDR(_pdev, _cid) + (_offset)), \
                1, \
                &w_val); \
        if(CHIP_REV(_pdev) == CHIP_REV_IKOS) \
        { \
            mm_wait(_pdev, 1); \
        } \
    }

#endif  //!UEFI

#endif /* CONFIG_PPC64 */

/* Indirect context access.  Unlike the MBQ_WR, these macros will not
 * trigger a chip event. */
#define CTX_WR(_pdev, _cid_addr, _offset, _val) \
    lm_ctx_wr(_pdev, _cid_addr, _offset, _val)

#define CTX_RD(_pdev, _cid_addr, _offset) \
    lm_ctx_rd(_pdev, _cid_addr, _offset)


/* Away to trigger the bus analyzer. */
#define TRIGGER(_pdev, _val)        REG_WR(_pdev, misc.misc_id, _val)



#endif /* _LM5706_H */

