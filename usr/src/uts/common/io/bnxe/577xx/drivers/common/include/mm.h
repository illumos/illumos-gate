
/*****************************************************************************
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
 *
 * Copyright 2014 QLogic Corporation
 * The contents of this file are subject to the terms of the
 * QLogic End User License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://www.qlogic.com/Resources/Documents/DriverDownloadHelp/
 * QLogic_End_User_Software_License.txt
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 *****************************************************************************/

#ifndef _MM_H
#define _MM_H

#include <sys/va_list.h>

/* 
   This define is relevant for MS compilers.
   So the main purpose here is to comply with older MS compilers
   as well as non-MS compilers   
*/
#ifndef FORCEINLINE
#if defined(_MSC_VER) && (_MSC_VER >= 1200) /* Windows */
#define FORCEINLINE __forceinline
#else
#define FORCEINLINE __inline
#endif /* _MSC_VER */
#endif /* !FORCEINLINE */

/* common lpme callback used by multiple platforms */
typedef void lm_generic_workitem_function(struct _lm_device_t *pdev);
lm_status_t mm_register_lpme(struct _lm_device_t *_pdev, 
                             lm_generic_workitem_function *func,
                             const u8_t b_fw_access,
                             const u8_t b_queue_for_fw);

/* mm_i2c for special elink query */
lm_status_t mm_i2c_update(struct _lm_device_t *pdev);

/* query system time - for time stamps */
u64_t       mm_query_system_time(void);

#if defined(UEFI)
#include "mm_uefi.h"
#elif defined(DOS)
#include "mm_dos.h"
#elif defined(__LINUX) || defined (USER_LINUX)
#include "mm_linux.h"
#elif defined(__SunOS)
#include "mm_solaris.h"
#elif defined(__USER_MODE_DEBUG) 
#include "mm_user_mode_debug.h"
#elif defined(_VBD_) || defined(_VBD_CMD_)
#include "mm_vbd.h"
#elif defined (NDISMONO) // VBD
#include "mm_ndismono.h"
#endif

unsigned int mm_crc32(unsigned char *address, unsigned int size, unsigned int crc);

#define mm_read_barrier()  mm_read_barrier_imp()
#define mm_write_barrier() mm_write_barrier_imp()
#define mm_barrier()       mm_barrier_imp()

#define mm_atomic_set(/* u32_t* */_p, /* u32_t */_v) mm_atomic_set_imp(_p, _v)

#define mm_atomic_dec(/* u32_t* */_p) mm_atomic_dec_imp(_p)
#define mm_atomic_inc(/* u32_t* */_p) mm_atomic_inc_imp(_p)

#define mm_atomic_add(/* u32_t* */_p, /* u32_t */_v) mm_atomic_add_imp(_p, _v)

#define mm_atomic_sub(/* u32_t* */_p, /* u32_t */_v) mm_atomic_sub_imp(_p, _v)

#define mm_atomic_and(/* u32_t* */_p, /* u32_t */_v) mm_atomic_and_imp(_p, _v)
#define mm_atomic_long_and(/* unsigned long* */_p, /* unsigned long */_v) \
    mm_atomic_long_and_imp(_p, _v)

#define mm_atomic_or(/* u32_t* */_p, /* u32_t */_v)  mm_atomic_or_imp(_p, _v)
#define mm_atomic_long_or(/* unsigned long* */_p, /* unsigned long */_v) \
    mm_atomic_long_or_imp(_p, _v)

#define mm_atomic_read(/* u32_t* */_p) mm_atomic_read_imp(_p)
#define mm_atomic_long_read(/* unsigned long* */_p)  \
    mm_atomic_long_read_imp(_p)

#define mm_atomic_cmpxchg(/* u32_t* */_p, /* u32_t */_old_val, /* u32_t */_new_val) \
    mm_atomic_cmpxchg_imp(_p, _old_val, _new_val)

#define MM_WRITE_DOORBELL(/* struct _lm_device_t* */PDEV, /* u32_t */BAR, /* u32_t */CID, /* u32_t */VAL) \
    MM_WRITE_DOORBELL_IMP(PDEV, BAR, CID, VAL)

#define MM_REGISTER_LPME(/* struct _lm_device_t* */_pdev, /* lm_generic_workitem_function */_func, /* u8_t */_b_fw_access, /* u8_t */_b_queue_for_fw) \
    MM_REGISTER_LPME_IMP(_pdev, _func, _b_fw_access, _b_queue_for_fw)

#define MM_ACQUIRE_SPQ_LOCK(/* struct _lm_device_t* */pdev)     MM_ACQUIRE_SPQ_LOCK_IMP(pdev)
#define MM_RELEASE_SPQ_LOCK(/* struct _lm_device_t* */pdev)     MM_RELEASE_SPQ_LOCK_IMP(pdev)
#define MM_ACQUIRE_SPQ_LOCK_DPC(/* struct _lm_device_t* */pdev) MM_ACQUIRE_SPQ_LOCK_DPC(pdev)
#define MM_RELEASE_SPQ_LOCK_DPC(/* struct _lm_device_t* */pdev) MM_RELEASE_SPQ_LOCK_DPC(pdev)

#define MM_ACQUIRE_CID_LOCK(/* struct _lm_device_t* */pdev) MM_ACQUIRE_CID_LOCK_IMP(pdev)
#define MM_RELEASE_CID_LOCK(/* struct _lm_device_t* */pdev) MM_RELEASE_CID_LOCK_IMP(pdev)

#define MM_ACQUIRE_REQUEST_LOCK(/* struct _lm_device_t* */pdev) MM_ACQUIRE_REQUEST_LOCK_IMP(pdev)
#define MM_RELEASE_REQUEST_LOCK(/* struct _lm_device_t* */pdev) MM_RELEASE_REQUEST_LOCK_IMP(pdev)

#define MM_ACQUIRE_REQUEST_LOCK_DPC(/* struct _lm_device_t* */pdev) MM_ACQUIRE_REQUEST_LOCK_DPC_IMP(pdev)
#define MM_RELEASE_REQUEST_LOCK_DPC(/* struct _lm_device_t* */pdev) MM_RELEASE_REQUEST_LOCK_DPC_IMP(pdev)

#define MM_ACQUIRE_PHY_LOCK(/* struct _lm_device_t* */pdev)     MM_ACQUIRE_PHY_LOCK_IMP(pdev)
#define MM_RELEASE_PHY_LOCK(/* struct _lm_device_t* */pdev)     MM_RELEASE_PHY_LOCK_IMP(pdev)
#define MM_ACQUIRE_PHY_LOCK_DPC(/* struct _lm_device_t* */pdev) MM_ACQUIRE_PHY_LOCK_DPC_IMP(pdev)
#define MM_RELEASE_PHY_LOCK_DPC(/* struct _lm_device_t* */pdev) MM_RELEASE_PHY_LOCK_DPC_IMP(pdev)

#define MM_ACQUIRE_MCP_LOCK(/* struct _lm_device_t* */pdev) MM_ACQUIRE_MCP_LOCK_IMP(pdev)
#define MM_RELEASE_MCP_LOCK(/* struct _lm_device_t* */pdev) MM_RELEASE_MCP_LOCK_IMP(pdev)

#define MM_ACQUIRE_ISLES_CONTROL_LOCK(/* struct _lm_device_t* */pdev)     MM_ACQUIRE_ISLES_CONTROL_LOCK_IMP(pdev)
#define MM_RELEASE_ISLES_CONTROL_LOCK(/* struct _lm_device_t* */pdev)     MM_RELEASE_ISLES_CONTROL_LOCK_IMP(pdev)
#define MM_ACQUIRE_ISLES_CONTROL_LOCK_DPC(/* struct _lm_device_t* */pdev) MM_ACQUIRE_ISLES_CONTROL_LOCK_DPC_IMP(pdev)
#define MM_RELEASE_ISLES_CONTROL_LOCK_DPC(/* struct _lm_device_t* */pdev) MM_RELEASE_ISLES_CONTROL_LOCK_DPC_IMP(pdev)

#define MM_ACQUIRE_RAMROD_COMP_LOCK(/* struct _lm_device_t* */pdev) MM_ACQUIRE_RAMROD_COMP_LOCK_IMP(pdev)
#define MM_RELEASE_RAMROD_COMP_LOCK(/* struct _lm_device_t* */pdev) MM_RELEASE_RAMROD_COMP_LOCK_IMP(pdev)

#define MM_ACQUIRE_IND_REG_LOCK(/* struct _lm_device_t* */pdev) MM_ACQUIRE_IND_REG_LOCK_IMP(pdev)
#define MM_RELEASE_IND_REG_LOCK(/* struct _lm_device_t* */pdev) MM_RELEASE_IND_REG_LOCK_IMP(pdev)

#define MM_ACQUIRE_LOADER_LOCK() MM_ACQUIRE_LOADER_LOCK_IMP()
#define MM_RELEASE_LOADER_LOCK() MM_RELEASE_LOADER_LOCK_IMP()

#define MM_ACQUIRE_SP_REQ_MGR_LOCK(/* struct _lm_device_t* */pdev) MM_ACQUIRE_SP_REQ_MGR_LOCK_IMP(pdev)
#define MM_RELEASE_SP_REQ_MGR_LOCK(/* struct _lm_device_t* */pdev) MM_RELEASE_SP_REQ_MGR_LOCK_IMP(pdev)

#define MM_ACQUIRE_SB_LOCK(/* struct _lm_device_t* */pdev, /* u8_t */sb_idx) MM_ACQUIRE_SB_LOCK_IMP(pdev, sb_idx)
#define MM_RELEASE_SB_LOCK(/* struct _lm_device_t* */pdev, /* u8_t */sb_idx) MM_RELEASE_SB_LOCK_IMP(pdev, sb_idx)

void mm_init_lock(struct _lm_device_t *_pdev, mm_spin_lock_t *spinlock);

#ifdef _VBD_
#if defined(NTDDI_WIN8)
__drv_maxIRQL(DISPATCH_LEVEL)
__drv_at(lock->irql, __drv_savesIRQL)
__drv_setsIRQL(DISPATCH_LEVEL)
#endif
#endif
lm_status_t mm_acquire_lock( mm_spin_lock_t *spinlock);

#ifdef _VBD_
#if defined(NTDDI_WIN8)
_IRQL_requires_(DISPATCH_LEVEL)
__drv_at(lock->irql, __drv_restoresIRQL )
#endif
#endif
lm_status_t mm_release_lock( mm_spin_lock_t *spinlock);

#define MM_ACQUIRE_ETH_CON_LOCK(/* struct _lm_device_t* */pdev) MM_ACQUIRE_ETH_CON_LOCK_IMP(pdev)
#define MM_RELEASE_ETH_CON_LOCK(/* struct _lm_device_t* */pdev) MM_RELEASE_ETH_CON_LOCK_IMP(pdev)

#ifdef VF_INVOLVED

#define MM_ACQUIRE_PF_LOCK(/* struct _lm_device_t* */pdev) MM_ACQUIRE_PF_LOCK_IMP(pdev)
#define MM_RELEASE_PF_LOCK(/* struct _lm_device_t* */pdev) MM_RELEASE_PF_LOCK_IMP(pdev)

#define MM_ACQUIRE_VFS_STATS_LOCK(/* struct _lm_device_t* */pdev)     MM_ACQUIRE_VFS_STATS_LOCK_IMP(pdev)
#define MM_RELEASE_VFS_STATS_LOCK(/* struct _lm_device_t* */pdev)     MM_RELEASE_VFS_STATS_LOCK_IMP(pdev)
#define MM_ACQUIRE_VFS_STATS_LOCK_DPC(/* struct _lm_device_t* */pdev) MM_ACQUIRE_VFS_STATS_LOCK_DPC_IMP(pdev)
#define MM_RELEASE_VFS_STATS_LOCK_DPC(/* struct _lm_device_t* */pdev) MM_RELEASE_VFS_STATS_LOCK_DPC_IMP(pdev)

#endif /* VF_INVOLVED */


#define mm_er_initiate_recovery(/* struct _lm_device_t* */pdev) \
    mm_er_initiate_recovery_imp(pdev)

#define MM_REGISTER_DPC(/* struct _lm_device_t* */_pdev, /* lm_generic_dpc_func */_func) \
    mm_register_dpc_imp(_pdev, _func)

#define MM_EMPTY_RAMROD_RECEIVED(/* struct _lm_device_t* */pdev, /* lm_cli_idx_t */lm_cli_idx) \
    mm_empty_ramrod_received_imp(pdev, lm_cli_idx)

#define mm_dbus_start_if_enable(/* struct _lm_device_t* */pdev) \
    mm_dbus_start_if_enabled_imp(pdev)
#define mm_dbus_stop_if_started(/* struct _lm_device_t* */pdev) \
    mm_dbus_stop_if_started_imp(pdev)


/* Busy delay for the specified microseconds. */
void mm_wait(struct _lm_device_t *pdev,
             u32_t delay_us);

/* Read a PCI configuration register (must be 32-bit aligned) */
lm_status_t mm_read_pci(struct _lm_device_t *pdev,
                        u32_t pci_reg,
                        u32_t *reg_value);

/* Write a PCI configuration register (must be 32-bit aligned) */
lm_status_t mm_write_pci(struct _lm_device_t *pdev,
                         u32_t pci_reg,
                         u32_t reg_value);

/*
 * Map the base address of the device registers to system address space so
 * that registers are accessible. The base address will be unmapped when the
 * driver unloads.
 */
void * mm_map_io_base(struct _lm_device_t *pdev,
                      lm_address_t base_addr,
                      u32_t size,
                      u8_t bar);

/* Read driver configuration.  It is called from lm_get_dev_info. */
lm_status_t mm_get_user_config(struct _lm_device_t *pdev);

/* Get the size of a packet descriptor. */
u32_t mm_desc_size(struct _lm_device_t *pdev,
                   u32_t desc_type);
#define DESC_TYPE_L2TX_PACKET 0
#define DESC_TYPE_L2RX_PACKET 1


/* XXX
mm_map_io_space(struct _lm_device_t * pLM,
                lm_address_t  physAddr,
                u8_t          bar,
                u32_t         offset,
                u32_t         size,
                void *        pHandle);
*/
#ifdef __SunOS
void *
mm_map_io_space_solaris(struct _lm_device_t *      pLM,
                        lm_address_t       physAddr,
                        u8_t               bar,
                        u32_t              offset,
                        u32_t              size,
                        ddi_acc_handle_t * pRegAccHandle);
#else
void *
mm_map_io_space(struct _lm_device_t *pdev,
                lm_address_t phys_addr,
                u32_t size);
#endif

void mm_unmap_io_space(struct _lm_device_t *pdev,
                       void *virt_addr,
                       u32_t size);


void * mm_alloc_mem_imp(struct _lm_device_t *pdev,
                        u32_t mem_size,
                        const char* sz_file,
                        const unsigned long line,
                        u8_t cli_idx);
#define mm_alloc_mem(_pdev, _mem_size, cli_idx) \
    mm_alloc_mem_imp((_pdev), (_mem_size), __FILE_STRIPPED__, __LINE__, (cli_idx));


void * mm_alloc_phys_mem_imp(struct _lm_device_t* pdev,
                             u32_t mem_size,
                             lm_address_t* phys_mem,
                             u8_t mem_type,
                             const char* sz_file,
                             const unsigned long line,
                             u8_t cli_idx);
#define mm_alloc_phys_mem(_pdev, _mem_size, _phys_mem, _mem_type, cli_idx) \
    mm_alloc_phys_mem_imp((_pdev), (_mem_size), (_phys_mem), (_mem_type), __FILE_STRIPPED__, __LINE__, (cli_idx));


void * mm_rt_alloc_mem_imp(struct _lm_device_t* pdev,
                           u32_t mem_size,
                           const char* sz_file,
                           const unsigned long line,
                           u8_t cli_idx);
#define mm_rt_alloc_mem(_pdev, _mem_size, cli_idx) \
    mm_rt_alloc_mem_imp((_pdev), (_mem_size), __FILE_STRIPPED__, __LINE__, (cli_idx));


void * mm_alloc_phys_mem_align_imp(struct _lm_device_t* pdev,
                                   u32_t mem_size,
                                   lm_address_t* phys_mem,
                                   u32_t alignment,
                                   u8_t mem_type,
                                   const char* sz_file,
                                   const unsigned long line,
                                   u8_t cli_idx ) ;

#define mm_alloc_phys_mem_align(_pdev, _mem_size, _phys_mem, _alignment, _mem_type, cli_idx) \
    mm_alloc_phys_mem_align_imp((_pdev), (_mem_size), (_phys_mem), (_alignment), (_mem_type), __FILE_STRIPPED__, __LINE__, (cli_idx));


void * mm_rt_alloc_phys_mem_imp(struct _lm_device_t* pdev,
                                u32_t mem_size,
                                lm_address_t* phys_mem,
                                u8_t mem_type,
                                const char* sz_file,
                                const unsigned long line,
                                u8_t cli_idx);

#define mm_rt_alloc_phys_mem(_pdev, _mem_size, _phys_mem, _flush_type, cli_idx) \
    mm_rt_alloc_phys_mem_imp((_pdev), (_mem_size), (_phys_mem), (_flush_type), __FILE_STRIPPED__, __LINE__, (cli_idx));


#define PHYS_MEM_TYPE_UNSPECIFIED 0
#define PHYS_MEM_TYPE_NONCACHED   1


void mm_rt_free_mem(struct _lm_device_t *pdev,
                    void *mem_virt,
                    u32_t mem_size,
                    u8_t cli_idx);

void mm_rt_free_phys_mem(struct _lm_device_t *pdev,
                         u32_t mem_size,
                         void *virt_mem,
                         lm_address_t phys_mem,
                         u8_t cli_idx);


void mm_memset(void *buf, u8_t val, u32_t mem_size);
#define mm_mem_zero(buf, mem_size) mm_memset((buf), 0, (mem_size))

void mm_memcpy(void *destenation, const void *source, u32_t mem_size);

u8_t mm_memcmp(void *buf1, void *buf2, u32_t count);


/* Returns current high-definition time. */
u64_t mm_get_current_time(struct _lm_device_t *pdev);


/*
 * This routine is called to indicate completion of a transmit request.
 * If 'packet' is not NULL, all the packets in the completion queue will
 * be indicated.  Otherwise, only 'packet' will be indicated.
 */
void mm_indicate_tx(struct _lm_device_t *pdev,
                    u32_t chain_idx,
                    s_list_t *packet_list);


/**
 * @brief
 *      a function that enables lm to indicate rx packets
 *      directly. In regular rx indication flow, the call is
 *      made from UM -> Um request the rx packets and then
 *      indicates them. This function, at time of writing, was
 *      used just for aborting packets but may be used for any
 *      kind of indication. 
 * 
 * @param pdev 
 * @param chain_idx 
 * @param packet_list 
 * @param ind_status   - SUCCESS / ABORTED
 */
void mm_indicate_rx(struct _lm_device_t *pdev,
                    u32_t                chain_idx,
                    s_list_t            *packet_list,
                    lm_status_t          ind_status);

/* Indicate the current phy link status. */
void mm_indicate_link(struct _lm_device_t *pdev,
                      lm_status_t link,
                      lm_medium_t medium);

/* Indicate a critical HW error that requires to completely
   stop all access to the device */
void mm_indicate_hw_failure(struct _lm_device_t *pdev);

/* Call the lm_task_cb_t callback function after the specified delay. */
typedef void(*lm_task_cb_t)(struct _lm_device_t *pdev, void *param);
lm_status_t mm_schedule_task(struct _lm_device_t *pdev,
                             u32_t delay_ms,
                             lm_task_cb_t task,
                             void *param);


/* XXX needs description... */
void mm_set_done(struct _lm_device_t *pdev,
                 u32_t cid,
                 void *cookie);


struct sq_pending_command;

void mm_return_sq_pending_command(struct _lm_device_t * pdev,
                                  struct sq_pending_command * pending);

struct sq_pending_command * mm_get_sq_pending_command(struct _lm_device_t * pdev);


u32_t mm_copy_packet_buf(struct _lm_device_t *pdev,
                         struct _lm_packet_t *lmpkt, /* packet to copy from */
                         u8_t *mem_buf,              /* buffer to copy to */
                         u32_t size);                /* number of bytes to copy */


lm_status_t mm_event_log_generic_arg_fwd(struct _lm_device_t* pdev,
                                         const lm_log_id_t lm_log_id,
                                         va_list ap);

lm_status_t mm_event_log_generic(struct _lm_device_t* pdev,
                                 const lm_log_id_t lm_log_id,
                                 ...);

void mm_print_bdf(int, void*);


/* common alloc and zero memory routine used for all platforms */
static __inline void * mm_rt_zalloc_mem(struct _lm_device_t * pdev, u32_t size)
{
    void * ptr;

    ptr = mm_rt_alloc_mem(pdev, size, 0);

    if (ptr)
    {
        mm_mem_zero(ptr, size);
    }

    return ptr;
}


u32_t mm_build_ver_string(struct _lm_device_t * pdev);


#ifdef VF_INVOLVED

#ifndef VF_TO_PF_STANDARD_BLOCK_ID
#define VF_TO_PF_STANDARD_BLOCK_ID 0x100
#endif

struct _lm_vf_pf_message_t;
struct _lm_vf_info_t;
struct _lm_sriov_info_t;

void mm_vf_pf_arm_trigger(struct _lm_device_t *pdev,
                          struct _lm_vf_pf_message_t *mess);

lm_status_t mm_vf_pf_write_block_to_sw_channel(struct _lm_device_t *pdev,
                                               u32_t block_id,
                                               void *buffer,
                                               u32_t length);

lm_status_t mm_vf_pf_read_block_from_sw_channel(struct _lm_device_t *pdev,
                                                u32_t block_id,
                                                void *buffer,
                                                u32_t *length);

lm_status_t mm_vf_pf_sw_ch_process_standard_request(struct _lm_device_t *pdev,
                                                    u16_t relative_vf_id,
                                                    void *virt_buffer,
                                                    u32_t length);

lm_status_t mm_vf_pf_sw_ch_retrieve_standard_response(struct _lm_device_t *pdev,
                                                      u16_t relative_vf_id,
                                                      void *virt_buffer,
                                                      u32_t length);

lm_status_t mm_vf_pf_hw_ch_process_standard_request(struct _lm_device_t *pdev,
                                                    u8_t vf_id,
                                                    lm_address_t *vf_pf_message);

lm_status_t mm_vf_pf_upload_standard_request(struct _lm_device_t *pdev,
                                             u8_t vf_id,
                                             lm_address_t *vf_pf_message);

lm_status_t mm_vf_en(struct _lm_device_t* pdev,
                     u16_t vfs_num);

void mm_vf_dis(struct _lm_device_t* pdev);

u16_t mm_get_extended_caps(struct _lm_device_t *pdev,
                           u16_t capabilityID);

lm_status_t mm_get_sriov_info(struct _lm_device_t *pdev,
                              struct _lm_sriov_info_t *info);

lm_status_t mm_pf_get_queues_number(struct _lm_device_t *pdev,
                                    struct _lm_vf_info_t *vf_info,
                                    u8_t *num_rxqs,
                                    u8_t *num_txqs);

lm_status_t mm_pf_get_filters_number(struct _lm_device_t *pdev,
                                     struct _lm_vf_info_t *vf_info, 
                                     u8_t *num_mac_filters,
                                     u8_t *num_vlan_filters,
                                     u8_t *num_mc_filters);

lm_status_t mm_pf_get_macs(struct _lm_device_t *pdev,
                           struct _lm_vf_info_t *vf_info,
                           u8_t *permanent_mac_addr,
                           u8_t *current_mac_addr);

void mm_report_malicious_vf(struct _lm_device_t *pdev, struct _lm_vf_info_t *vf_info);

#endif /* ifdef VF_INVOLVED */


#ifdef BIG_ENDIAN
// LE
#define mm_le16_to_cpu(val) mm_le16_to_cpu_imp(val)
#define mm_cpu_to_le16(val) mm_cpu_to_le16_imp(val)
#define mm_le32_to_cpu(val) mm_le32_to_cpu_imp(val)
#define mm_cpu_to_le32(val) mm_cpu_to_le32_imp(val)
// BE
#define mm_be32_to_cpu(val) mm_be32_to_cpu_imp(val)
#define mm_cpu_to_be32(val) mm_cpu_to_be32_imp(val)
#define mm_be16_to_cpu(val) mm_be16_to_cpu_imp(val)
#define mm_cpu_to_be16(val) mm_cpu_to_be16_imp(val)
#else /* LITTLE_ENDIAN */
// LE
#define mm_le16_to_cpu(val) mm_le16_to_cpu_imp(val)
#define mm_cpu_to_le16(val) mm_cpu_to_le16_imp(val)
#define mm_le32_to_cpu(val) mm_le32_to_cpu_imp(val)
#define mm_cpu_to_le32(val) mm_cpu_to_le32_imp(val)
// BE
#define mm_be32_to_cpu(val) mm_be32_to_cpu_imp(val)
#define mm_cpu_to_be32(val) mm_cpu_to_be32_imp(val)
#define mm_be16_to_cpu(val) mm_be16_to_cpu_imp(val)
#define mm_cpu_to_be16(val) mm_cpu_to_be16_imp(val)
#endif /* ifdef BIG_ENDIAN */


#define mm_get_bar_offset(/* struct _lm_device_t* */pdev, /* u8_t */bar_num, /* lm_address_t* */bar_addr) \
    mm_get_bar_offset_imp(pdev, bar_num, bar_addr)

#define mm_get_bar_size(/* struct _lm_device_t* */pdev, /* u8_t */bar_num, /* u32_t* */val_p) \
    mm_get_bar_size_imp(pdev, bar_num, val_p)


#endif /* _MM_H */

