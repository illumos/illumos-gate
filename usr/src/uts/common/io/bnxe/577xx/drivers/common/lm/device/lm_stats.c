/*******************************************************************************
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
 *
 * Module Description:
 *
 *
 * History:
 *    02/05/07 Alon Elhanani    Inception.
 ******************************************************************************/


#include "lm5710.h"
#include "license.h"
#include "mcp_shmem.h"
#include "command.h"
#include "debug.h"

// does HW statistics is active
// only if we are PMF && collect_enabled is on!
#define LM_STATS_IS_HW_ACTIVE(_pdev) ( _pdev->vars.stats.stats_collect.stats_hw.b_collect_enabled && \
                                       IS_PMF(_pdev) )

// do _cmd statement only if in SF mode
// we use this macro since in MF mode we don't maintain non-mandatory statistics so to prevent inconsistently - we don't use them at all
#define LM_STATS_DO_IF_SF(_pdev,_cmd) if( !_pdev->hw_info.mf_info.multi_vnics_mode ){ _cmd; } ;

#define LM_STATS_64_TO_HI_LO( _x_64_, _hi_lo ) ( _hi_lo##_hi = (u32_t)U64_HI( _x_64_ ) ); ( _hi_lo##_lo = (u32_t)U64_LO( _x_64_ ) );
#define LM_STATS_HI_LO_TO_64( _hi_lo, _x_64_ ) ( _x_64_ = (((u64_t)(_hi_lo##_hi) << 32) | (_hi_lo##_lo)) )

/**
 * driver stats are stored as 64bits where the lower bits store
 * the value and the upper bits store the wraparound count.
 * different stat fields are stored with different data sizes
 * and the following macros help in storing values in the
 * "overflow count" part of a 64bit value and seperating it from
 * the actual data.
  */
#define DATA_MASK(_bits) (((u64_t)-1)>>(64-_bits))
#define STATS_DATA(_bits,_val) ( (_val) & DATA_MASK(_bits) )
#define WRAPAROUND_COUNT_MASK(_bits) ( ~ DATA_MASK(_bits) )
#define HAS_WRAPPED_AROUND(_bits,_old,_new) ((STATS_DATA(_bits,_old) ) > (STATS_DATA(_bits,_new) ))
#define INC_WRAPAROUND_COUNT(_bits,_val) (_val + ( 1ull << _bits ) )

/**lm_update_wraparound_if_needed
 * This function checks the old and new values, and returns a
 * either the new data with the old wraparound count, or (if a
 * wraparound has occured) the new data with an incremented
 * wraparound count.
 *
 * val_current can be given in either little-endian or
 * big-endian byte ordering. the values returned are always in
 * host byte order.
 *
 * @param data_bits the number of data bits in the values
 * @param val_current the newly collected value. the byte
 *                    ordering is detemined by
 *                    @param b_swap_bytes
 * @param val_prev the the previously saved value in host byte
 *                 order
 * @param b_swap_bytes TRUE if val_current is byte-swapped (i.e
 *                     given as little-endian on a big-endian
 *                     machine), FALSE otherwise.
 *
 * @return u64_t the new data with an appropriate wraparound
 *         count.
 */

static u64_t lm_update_wraparound_if_needed(u8_t data_bits, u64_t val_current, u64_t val_prev, u8_t b_swap_bytes)
{
    if(b_swap_bytes)
    {
        /*We assume that only 32bit stats will ever need to be byte-swapped. this is because
          all HW data is byte-swapped by DMAE as needed, and the 64bit FW stats are swapped
          by the REGPAIR macros.*/
        DbgBreakIf(data_bits != 32);
        val_current=mm_le32_to_cpu(val_current);
    }
    if (HAS_WRAPPED_AROUND(data_bits,val_prev,val_current))
    {
        val_prev=INC_WRAPAROUND_COUNT(data_bits,val_prev);
    }
    return ((val_prev & WRAPAROUND_COUNT_MASK(data_bits)) |
            (val_current & DATA_MASK(data_bits))); /*take the overflow count we calculated, and the data from the new value*/
}

/**
 * The following macros handle the wraparound-count for FW
 * stats. Note that in the 32bit case (i.e any stats that are
 * not REGPAIRs), the bytes have to swapped if the host byte
 * order is not little-endian.
 */
#define LM_SIGN_EXTEND_VALUE_32( val_current_32, val_prev_64 ) \
    val_prev_64 = lm_update_wraparound_if_needed( 32, val_current_32, val_prev_64, CHANGE_ENDIANITY )
#define LM_SIGN_EXTEND_VALUE_36( val_current_36, val_prev_64 ) \
    val_prev_64 = lm_update_wraparound_if_needed( 36, val_current_36, val_prev_64, FALSE)
#define LM_SIGN_EXTEND_VALUE_42( val_current_42, val_prev_64 ) \
    val_prev_64 = lm_update_wraparound_if_needed( 42, val_current_42, val_prev_64, FALSE )



/* function checks if there is a pending completion for statistics and a pending dpc to handle the completion:
 * for cases where VBD gets a bit starved - we don't want to assert if chip isn't stuck and we have a pending completion
 */
u8_t is_pending_stats_completion(struct _lm_device_t * pdev);

lm_status_t lm_stats_hw_collect( struct _lm_device_t *pdev );

#ifdef _VBD_CMD_
extern volatile u32_t* g_everest_sim_flags_ptr;
#define EVEREST_SIM_STATS       0x02
#endif


/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_get_stats( lm_device_t* pdev,
              lm_stats_t   stats_type,
              u64_t*       stats_cnt
#ifdef VF_INVOLVED
              ,lm_vf_info_t * vf_info
#endif
              )
{
    lm_status_t lm_status    = LM_STATUS_SUCCESS;
    lm_u64_t*   stats        = (lm_u64_t *)stats_cnt;
    const u32_t i            = LM_CLI_IDX_NDIS;
   lm_stats_fw_t* stats_fw  = NULL;

#ifdef VF_INVOLVED
   if (vf_info != NULL) {
           stats_fw = (lm_stats_fw_t*)vf_info->vf_stats.mirror_stats_fw;
           vf_info->vf_stats.vf_exracted_stats_cnt++;
   } else
#endif
   {
           stats_fw = &pdev->vars.stats.stats_mirror.stats_fw;
   }

    switch(stats_type)
    {
        case LM_STATS_FRAMES_XMITTED_OK:
            stats->as_u64 = stats_fw->eth_xstorm_common.client_statistics[i].total_sent_pkts ;
            // ioc IfHCOutPkts
            break;
        case LM_STATS_FRAMES_RECEIVED_OK:
            stats->as_u64 = stats_fw->eth_tstorm_common.client_statistics[i].rcv_broadcast_pkts +
                            stats_fw->eth_tstorm_common.client_statistics[i].rcv_multicast_pkts +
                            stats_fw->eth_tstorm_common.client_statistics[i].rcv_unicast_pkts ;
            stats->as_u64-= stats_fw->eth_ustorm_common.client_statistics[i].ucast_no_buff_pkts ;
            stats->as_u64-= stats_fw->eth_ustorm_common.client_statistics[i].mcast_no_buff_pkts ;
            stats->as_u64-= stats_fw->eth_ustorm_common.client_statistics[i].bcast_no_buff_pkts ;
            // ioc IfHCInPkts
            break;
        case LM_STATS_ERRORED_RECEIVE_CNT:
#ifdef VF_INVOLVED
                   DbgBreakIf(vf_info);
#endif
#define LM_STATS_ERROR_DISCARD_SUM( _pdev, _i )  _pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[_i].checksum_discard + \
                                                 _pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[_i].packets_too_big_discard + \
                                                 _pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.port_statistics.mac_discard + \
                                                 LM_STATS_HW_GET_MACS_U64(_pdev, stats_rx.rx_stat_dot3statsframestoolong )
            stats->as_u64 = LM_STATS_ERROR_DISCARD_SUM( pdev, i ) ;
           break;
        case LM_STATS_RCV_CRC_ERROR:
            // Spec. 9
#ifdef VF_INVOLVED
                   DbgBreakIf(vf_info);
#endif
            stats->as_u64 = LM_STATS_HW_GET_MACS_U64(pdev, stats_rx.rx_stat_dot3statsfcserrors) ;
            // ioc Dot3StatsFCSErrors
            break;
        case LM_STATS_ALIGNMENT_ERROR:
            // Spec. 10
#ifdef VF_INVOLVED
                   DbgBreakIf(vf_info);
#endif
            if( !IS_PMF(pdev))
            {
                stats->as_u64 = 0 ;
            }
            else
            {
                stats->as_u64 =  LM_STATS_HW_GET_MACS_U64(pdev, stats_rx.rx_stat_dot3statsalignmenterrors) ;
            }
            // ioc Dot3StatsAlignmentErrors
            break;
        case LM_STATS_SINGLE_COLLISION_FRAMES:
            // Spec. 18
#ifdef VF_INVOLVED
                   DbgBreakIf(vf_info);
#endif
            if( !IS_PMF(pdev) )
            {
                stats->as_u64 = 0 ;
            }
            else
            {
                stats->as_u64 =  LM_STATS_HW_GET_MACS_U64(pdev, stats_tx.tx_stat_dot3statssinglecollisionframes ) ;
            }
            // ioc Dot3StatsSingleCollisionFrames
            break;
        case LM_STATS_MULTIPLE_COLLISION_FRAMES:
            // Spec. 19
#ifdef VF_INVOLVED
                   DbgBreakIf(vf_info);
#endif
            if( !IS_PMF(pdev) )
            {
                stats->as_u64 = 0 ;
            }
            else
            {
                stats->as_u64 =  LM_STATS_HW_GET_MACS_U64(pdev, stats_tx.tx_stat_dot3statsmultiplecollisionframes ) ;
            }
            // ioc Dot3StatsMultipleCollisionFrame
            break;
        case LM_STATS_FRAMES_DEFERRED:
            // Spec. 40 (not in mini port)
#ifdef VF_INVOLVED
                   DbgBreakIf(vf_info);
#endif
            stats->as_u64 =  LM_STATS_HW_GET_MACS_U64(pdev, stats_tx.tx_stat_dot3statsdeferredtransmissions ) ;
            // ioc Dot3StatsDeferredTransmissions
            break;
        case LM_STATS_MAX_COLLISIONS:
            // Spec. 21
#ifdef VF_INVOLVED
                   DbgBreakIf(vf_info);
#endif
            stats->as_u64 = LM_STATS_HW_GET_MACS_U64(pdev, stats_tx.tx_stat_dot3statsexcessivecollisions ) ;
            // ioc Dot3StatsExcessiveCollisions
            break;
        case LM_STATS_UNICAST_FRAMES_XMIT:
            // Spec. 6
            stats->as_u64 = stats_fw->eth_xstorm_common.client_statistics[i].unicast_pkts_sent ;
            break;
        case LM_STATS_MULTICAST_FRAMES_XMIT:
            // Spec. 7
            stats->as_u64 = stats_fw->eth_xstorm_common.client_statistics[i].multicast_pkts_sent ;
            break;
        case LM_STATS_BROADCAST_FRAMES_XMIT:
            stats->as_u64 = stats_fw->eth_xstorm_common.client_statistics[i].broadcast_pkts_sent ;
            break;
        case LM_STATS_UNICAST_FRAMES_RCV:
            stats->as_u64 = stats_fw->eth_tstorm_common.client_statistics[i].rcv_unicast_pkts ;
            break;
        case LM_STATS_MULTICAST_FRAMES_RCV:
            stats->as_u64 = stats_fw->eth_tstorm_common.client_statistics[i].rcv_multicast_pkts ;
            break;
        case LM_STATS_BROADCAST_FRAMES_RCV:
            stats->as_u64 = stats_fw->eth_tstorm_common.client_statistics[i].rcv_broadcast_pkts ;
            break;
        case LM_STATS_ERRORED_TRANSMIT_CNT:
#ifdef VF_INVOLVED
                   DbgBreakIf(vf_info);
#endif
            if( !IS_PMF(pdev) )
            {
                stats->as_u64 = 0 ;
            }
            else
            {
                stats->as_u64 =  LM_STATS_HW_GET_MACS_U64(pdev, stats_tx.tx_stat_dot3statsinternalmactransmiterrors ) ;
            }
            break;
        case LM_STATS_RCV_OVERRUN:
#ifdef VF_INVOLVED
                   DbgBreakIf(vf_info);
#endif
            stats->as_u64 =  pdev->vars.stats.stats_mirror.stats_hw.nig.brb_discard ;
            stats->as_u64+=  pdev->vars.stats.stats_mirror.stats_hw.nig.brb_truncate ;
            stats->as_u64+=  pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.port_statistics.xxoverflow_discard ;
            break;
        case LM_STATS_XMIT_UNDERRUN:
            //These counters are always zero
#ifdef VF_INVOLVED
                   DbgBreakIf(vf_info);
#endif
            stats->as_u64 = 0;
            break;
        case LM_STATS_RCV_NO_BUFFER_DROP:
            stats->as_u64 = stats_fw->eth_tstorm_common.client_statistics[i].no_buff_discard ;
            stats->as_u64+= stats_fw->eth_ustorm_common.client_statistics[i].ucast_no_buff_pkts ;
            stats->as_u64+= stats_fw->eth_ustorm_common.client_statistics[i].mcast_no_buff_pkts ;
            stats->as_u64+= stats_fw->eth_ustorm_common.client_statistics[i].bcast_no_buff_pkts ;
            // ioc IfInMBUFDiscards
            break;
        case LM_STATS_BYTES_RCV:
            stats->as_u64 = stats_fw->eth_tstorm_common.client_statistics[i].rcv_broadcast_bytes +
                            stats_fw->eth_tstorm_common.client_statistics[i].rcv_multicast_bytes +
                            stats_fw->eth_tstorm_common.client_statistics[i].rcv_unicast_bytes ;
            //  ioc IfHCInOctets
            break;
        case LM_STATS_BYTES_XMIT:
            stats->as_u64 = stats_fw->eth_xstorm_common.client_statistics[i].total_sent_bytes ;
            // ioc IfHCOutOctets
            break;
        case LM_STATS_IF_IN_DISCARDS:
#ifdef VF_INVOLVED
               if (vf_info != NULL)
               {
                       stats->as_u64 = 0;
               }
               else
#endif
               {
                   stats->as_u64 = LM_STATS_ERROR_DISCARD_SUM( pdev, i ) ;                            // LM_STATS_ERRORED_RECEIVE_CNT
               }
                stats->as_u64+= stats_fw->eth_tstorm_common.client_statistics[i].no_buff_discard ;    // LM_STATS_RCV_NO_BUFFER_DROP
                stats->as_u64+= stats_fw->eth_ustorm_common.client_statistics[i].ucast_no_buff_pkts ; // LM_STATS_RCV_NO_BUFFER_DROP
                stats->as_u64+= stats_fw->eth_ustorm_common.client_statistics[i].mcast_no_buff_pkts ; // LM_STATS_RCV_NO_BUFFER_DROP
                stats->as_u64+= stats_fw->eth_ustorm_common.client_statistics[i].bcast_no_buff_pkts ; // LM_STATS_RCV_NO_BUFFER_DROP
#ifdef VF_INVOLVED
                if (vf_info == NULL)
#endif
                {
                    stats->as_u64+= pdev->vars.stats.stats_mirror.stats_hw.nig.brb_discard ;   // LM_STATS_RCV_OVERRUN
                    stats->as_u64+= pdev->vars.stats.stats_mirror.stats_hw.nig.brb_truncate ;  // LM_STATS_RCV_OVERRUN
                }
                stats->as_u64+= stats_fw->eth_tstorm_common.port_statistics.xxoverflow_discard ; // LM_STATS_RCV_OVERRUN
            break;
        case LM_STATS_MULTICAST_BYTES_RCV:
            stats->as_u64 = stats_fw->eth_tstorm_common.client_statistics[i].rcv_multicast_bytes ;
            break;
        case LM_STATS_DIRECTED_BYTES_RCV:
            stats->as_u64 = stats_fw->eth_tstorm_common.client_statistics[i].rcv_unicast_bytes ;
            break;
        case LM_STATS_BROADCAST_BYTES_RCV:
            stats->as_u64 = stats_fw->eth_tstorm_common.client_statistics[i].rcv_broadcast_bytes ;
            break;
        case LM_STATS_DIRECTED_BYTES_XMIT:
            stats->as_u64 = stats_fw->eth_xstorm_common.client_statistics[i].unicast_bytes_sent ;
            break;
        case LM_STATS_MULTICAST_BYTES_XMIT:
            stats->as_u64 = stats_fw->eth_xstorm_common.client_statistics[i].multicast_bytes_sent ;
            break;
        case LM_STATS_BROADCAST_BYTES_XMIT:
            stats->as_u64 = stats_fw->eth_xstorm_common.client_statistics[i].broadcast_bytes_sent ;
            break;
/*
        case LM_STATS_IF_IN_ERRORS:
        case LM_STATS_IF_OUT_ERRORS:
            stats->as_u32.low = 0;
            stats->as_u32.high = 0;
            break;
*/
        default:
           stats->as_u64 = 0 ;
            lm_status = LM_STATUS_INVALID_PARAMETER;
            break;
    }
    //DbgMessage(pdev, WARN, "lm_get_stats: stats_type=0x%X val=%d\n", stats_type, stats->as_u64);
    return lm_status;
} /* lm_get_stats */
/*******************************************************************************
 * Description:
 *  Zero the mirror statistics (probably after miniport was down in windows, 'driver unload' on ediag)
 *
 * Return:
 ******************************************************************************/
void lm_stats_reset( struct _lm_device_t* pdev)
{
    DbgMessage(pdev, INFORM, "Zero 'mirror' statistics...\n");
    mm_mem_zero( &pdev->vars.stats.stats_mirror, sizeof(pdev->vars.stats.stats_mirror) ) ;
}

/*
 * lm_edebug_if_is_stats_disabled returns TRUE if statistics gathering is
 * disabled according to edebug-driver interface implemented through SHMEM2
 * field named edebug_driver_if. Otherwise, return FALSE.
*/
static u32_t
lm_edebug_if_is_stats_disabled(struct _lm_device_t * pdev)
{
    u32_t shmem2_size;
    u32_t offset = OFFSETOF(shmem2_region_t, edebug_driver_if[1]);
    u32_t val;

    if (pdev->hw_info.shmem_base2 != 0)
    {
        LM_SHMEM2_READ(pdev, OFFSETOF(shmem2_region_t, size), &shmem2_size);

        if (shmem2_size > offset)
        {
            LM_SHMEM2_READ(pdev, offset, &val);


            if (val == EDEBUG_DRIVER_IF_OP_CODE_DISABLE_STAT)
            {
                return TRUE;
            }
        }
    }

    return FALSE;
}


static lm_status_t lm_stats_fw_post_request(lm_device_t *pdev)
{
    lm_status_t             lm_status = LM_STATUS_SUCCESS;
    lm_stats_fw_collect_t * stats_fw  = &pdev->vars.stats.stats_collect.stats_fw;

    stats_fw->fw_stats_req->hdr.drv_stats_counter = mm_cpu_to_le16(stats_fw->drv_counter);

    // zero no completion counter
    stats_fw->timer_wakeup_no_completion_current = 0 ;

    stats_fw->b_completion_done = FALSE ;
    if (IS_VFDEV(pdev))
    {
        return LM_STATUS_SUCCESS;
    }
    stats_fw->b_ramrod_completed = FALSE ;

#ifdef VF_INVOLVED
#ifndef __LINUX
    if (IS_CHANNEL_VIRT_MODE_MASTER_PFDEV(pdev))
    {
        lm_stats_prep_vf_fw_stats_req(pdev);
    }
#endif
#endif

    /* send FW stats ramrod */
    lm_status = lm_sq_post_entry(pdev,&(stats_fw->stats_sp_list_command),CMD_PRIORITY_HIGH);

    DbgBreakIf( LM_STATUS_SUCCESS != lm_status ) ;

    if (lm_status == LM_STATUS_SUCCESS)
    {
        // increamant ramrod counter (for debugging)
        ++stats_fw->stats_ramrod_cnt ;
    }

    return lm_status;

}
// main stats function called from timer
void lm_stats_on_timer( struct _lm_device_t * pdev )
{
    lm_status_t                         lm_status   = LM_STATUS_SUCCESS ;
    u32_t                               val         = 0 ;

    if CHK_NULL( pdev )
    {
        DbgBreakIf(!pdev) ;
        return;
    }

    ++pdev->vars.stats.stats_collect.timer_wakeup ;

#ifdef _VBD_CMD_
    val = GET_FLAGS(*g_everest_sim_flags_ptr, EVEREST_SIM_STATS);
    pdev->vars.stats.stats_collect.stats_fw.b_collect_enabled = val && pdev->vars.stats.stats_collect.stats_fw.b_collect_enabled;
#endif
    /* disable statistics if FW SP trace is involved */
    if (pdev->params.record_sp)
    {
        ++pdev->vars.stats.stats_collect.sp_record_disabled;
        return;
    }
    /* if stats gathering is disabled according to edebug-driver i/f - return */
    if(lm_edebug_if_is_stats_disabled(pdev))
    {
        ++pdev->vars.stats.stats_collect.shmem_disabled;
        return;
    }

    if( pdev->vars.stats.stats_collect.stats_fw.b_collect_enabled )
    {
        // verify that previous ramrod cb is finished
        if( lm_stats_fw_complete( pdev ) == LM_STATUS_BUSY)
        {
            // using a variable to have event log since the message is too long
            val = ++pdev->vars.stats.stats_collect.stats_fw.timer_wakeup_no_completion_current ;

            // update timer_wakeup_no_completion_max
            if( pdev->vars.stats.stats_collect.stats_fw.timer_wakeup_no_completion_max < val )
            {
                pdev->vars.stats.stats_collect.stats_fw.timer_wakeup_no_completion_max = val ;
            }
            /* We give up in two case:
             * 1. We got here #NO_COMPLETION times without having a stats-completion pending to be handled
             * 2. There is a completion pending to be handled - but it still hasn't been handled in #COMP_NOT_HANDLED times
             *    we got here. #COMP_NOT_HANDLED > #NO_COMPLETION*/
            if ((!is_pending_stats_completion(pdev) && (val >= MAX_STATS_TIMER_WAKEUP_NO_COMPLETION)) ||
                (val >= MAX_STATS_TIMER_WAKEUP_COMP_NOT_HANDLED))
            {
                if(GET_FLAGS(pdev->params.debug_cap_flags,DEBUG_CAP_FLAGS_STATS_FW))
                {
                    LM_TRIGGER_PCIE(pdev);
                }
                /* shutdown bug - BSOD only if shutdown is not in progress */
                if (!lm_reset_is_inprogress(pdev))
                {
                    /* BSOD */
                    if(GET_FLAGS(pdev->params.debug_cap_flags,DEBUG_CAP_FLAGS_STATS_FW))
                    {
                        DbgBreakIfAll( val >= MAX_STATS_TIMER_WAKEUP_NO_COMPLETION ) ;
                    }
                }
            }

            /* check interrupt mode on 57710A0 boards */
            lm_57710A0_dbg_intr(pdev);

            // this is total wake up no completion - for debuging
            ++pdev->vars.stats.stats_collect.stats_fw.timer_wakeup_no_completion_total ;
        }
        else
        {
            lm_status = lm_stats_fw_post_request(pdev);
            DbgBreakIf(lm_status != LM_STATUS_SUCCESS);
        }
    } // fw collect enabled

    if( LM_STATS_IS_HW_ACTIVE(pdev) )
    {
        // if link is not up - we can simply pass this call (optimization)
        if( pdev->vars.stats.stats_collect.stats_hw.b_is_link_up )
        {
            MM_ACQUIRE_PHY_LOCK_DPC(pdev);

            // we can call dmae only if link is up, and we must check it with lock
            if( pdev->vars.stats.stats_collect.stats_hw.b_is_link_up )
            {
                lm_status = lm_stats_hw_collect( pdev );

                DbgBreakIf( LM_STATUS_SUCCESS != lm_status ) ;

                // assign values for relevant mac type which is up - inside the lock due to consistecy reasons
                lm_stats_hw_assign( pdev ) ;
            }

            // assign to statistics to MCP
            lm_stats_mgmt_assign( pdev ) ;

            MM_RELEASE_PHY_LOCK_DPC(pdev);
        } // link is up
    } // LM_STATS_IS_HW_ACTIVE
    else if( pdev->vars.stats.stats_collect.stats_hw.b_collect_enabled &&
             pdev->vars.stats.stats_collect.stats_hw.b_is_link_up ) // when there is no link - no use writing to mgmt
    {
        MM_ACQUIRE_PHY_LOCK_DPC(pdev);
        lm_stats_mgmt_assign( pdev ) ;
        MM_RELEASE_PHY_LOCK_DPC(pdev);
    }
}

u8_t is_pending_stats_completion(struct _lm_device_t * pdev)
{
    volatile struct hc_sp_status_block * sp_sb=NULL;
    u32_t val=0;

    /* read interrupt mask from IGU - check that default-status-block bit is off... */
    if (INTR_BLK_TYPE(pdev)==INTR_BLK_HC){
        val = REG_RD(pdev,  HC_REG_INT_MASK + 4*PORT_ID(pdev) );
    } // TODO add IGU complement


    sp_sb = lm_get_default_status_block(pdev);

    /* check bit 0 is masked (value 0) and that cstorm in default-status-block has increased. */
    if(!GET_FLAGS(val, 1) && lm_is_eq_completion(pdev))
    {
        return TRUE;
    }
    return FALSE; /* no pending completion */
}

/**lm_stats_get_dmae_operation
 * The statistics module uses two pre-allocated DMAE operations
 * instead of allocating and releasing a DMAE operation on every
 * statistics collection. There is an operation for EMAC
 * statistics, and an operation for BMAC or MSTAT statistics
 * (since EMAC requires 3 SGEs and BMAC/MSTAT require 2).
 * This function returns the appropriate DMAE operation based on
 * current MAC setting.
 *
 *
 * @param pdev the device to use.
 *
 * @return lm_dmae_operation_t* the DMAE operation to use for
 *         collection HW statistics from the current MAC.
 */
static lm_dmae_operation_t*
lm_stats_get_dmae_operation(lm_device_t* pdev)
{
    if (HAS_MSTAT(pdev) || (pdev->vars.mac_type == MAC_TYPE_BMAC))
    {
        return (lm_dmae_operation_t*)pdev->vars.stats.stats_collect.stats_hw.non_emac_dmae_operation;
    }
    else if(pdev->vars.mac_type == MAC_TYPE_EMAC)
    {
        return (lm_dmae_operation_t*)pdev->vars.stats.stats_collect.stats_hw.emac_dmae_operation;
    }
    else
    {
        DbgBreakIf((pdev->vars.mac_type != MAC_TYPE_EMAC) && (pdev->vars.mac_type != MAC_TYPE_BMAC));
        return NULL;
    }

}

/*
 *Function Name:lm_stats_dmae
 *
 *Parameters:
 *
 *Description:
 *  collect stats from hw using dmae
 *Returns:
 *
 */
lm_status_t lm_stats_dmae( lm_device_t *pdev )
{
    lm_status_t             lm_status   = LM_STATUS_SUCCESS ;
    lm_dmae_context_t*      context     = lm_dmae_get(pdev, LM_DMAE_STATS)->context;
    lm_dmae_operation_t*    operation   = lm_stats_get_dmae_operation(pdev);

    DbgBreakIf( FALSE == LM_STATS_IS_HW_ACTIVE( pdev ) ) ;

    if (NULL == operation)
    {
        DbgBreakIf( NULL == operation );
        return LM_STATUS_FAILURE;
    }

    lm_status = lm_dmae_context_execute(pdev,context,operation);

    if (LM_STATUS_ABORTED == lm_status)
    {
        //if the DMAE operation was interrupted by lm_reset_is_inprogress, it's OK and we can treat it as success.
        lm_status = LM_STATUS_SUCCESS;
    }

    return lm_status ;
}

/*
 *Function Name:lm_stats_clear_emac_stats
 *
 *Parameters:
 *
 *Description:
 *  resets all emac statistics counter registers
 *Returns:
 *
 */
lm_status_t lm_stats_clear_emac_stats( lm_device_t *pdev )
{
    u32_t i              = 0 ;
    u32_t j              = 0 ;
    u32_t count_limit[3] = { EMAC_REG_EMAC_RX_STAT_AC_COUNT,
                             1,
                             EMAC_REG_EMAC_TX_STAT_AC_COUNT } ;
    u32_t reg_start  [3] = { EMAC_REG_EMAC_RX_STAT_AC,
                             EMAC_REG_EMAC_RX_STAT_AC_28,
                             EMAC_REG_EMAC_TX_STAT_AC } ;
    u32_t emac_base      = 0 ;
    u32_t dummy          = 0 ;

    ASSERT_STATIC( ARRSIZE(reg_start) == ARRSIZE(count_limit) );

    if CHK_NULL( pdev )
    {
        return LM_STATUS_INVALID_PARAMETER ;
    }

    emac_base = ( 0 == PORT_ID(pdev) ) ? GRCBASE_EMAC0 : GRCBASE_EMAC1 ;

    for( i = 0; i< ARRSIZE(reg_start) ; i++ )
    {
        for( j = 0 ; j < count_limit[i]; j++ )
        {
            dummy = REG_RD( pdev, emac_base + reg_start[i]+(j*sizeof(u32_t))) ; /*Clear stats registers by reading from from ReadClear RX/RXerr/TX STAT banks*/
        }
    }
    return LM_STATUS_SUCCESS ;
}

/*
 *Function Name:lm_stats_on_update_state
 *
 *Parameters:
 *
 *Description:
 *  This function should be called on one of two occasions:
 *  - When link is down
 *  - When PMF is going down (meaning - changed to another PMF)
 *  Function must be called under PHY LOCK
 *  1. in case no link - do nothing
 *  2. make last query to hw stats for current link
 *  3. assign to mirror host structures
 *  4. assign to MCP (managment)
 *  5. saves the copy in mirror
 *Returns:
 *
 */
lm_status_t lm_stats_on_update_state(lm_device_t * pdev )
{
    lm_status_t lm_status = LM_STATUS_SUCCESS ;

    if CHK_NULL( pdev )
    {
        DbgBreakIf( !pdev ) ;
        return LM_STATUS_INVALID_PARAMETER ;
    }

    if( MAC_TYPE_NONE == pdev->vars.mac_type )
    {
        DbgMessage(pdev, WARNstat, "lm_stats_on_link_update: linking down when already linked down\n" );
        return LM_STATUS_LINK_DOWN ;
    }

    if ( LM_STATS_IS_HW_ACTIVE(pdev) )
    {
        // call statistics for the last time before link down
        lm_status = lm_stats_dmae( pdev ) ;

        if( LM_STATUS_SUCCESS != lm_status )
        {
            DbgBreakIf( LM_STATUS_SUCCESS != lm_status ) ;
        }

        // assign last values before link down
        lm_stats_hw_assign( pdev ) ;
    }

    // assign to statistics to mgmt
    lm_stats_mgmt_assign( pdev ) ;

    return lm_status;
}
// NOTE: this function must be called under PHY LOCK!
// - 1. Lock with stats timer/dmae, whcih means - no timer request on air when function running
// - 2. Last update of stats from emac/bmac (TBD - do it with reset addresses)
// - 3. keep latest stats in a copy
// - 4. if emac - reset all stats registers!
// - 5. if up - change b_link_down_is_on flag to FALSE
lm_status_t lm_stats_on_link_update( lm_device_t *pdev, const u8_t b_is_link_up )
{
    lm_status_t lm_status = LM_STATUS_SUCCESS ;

    if CHK_NULL( pdev )
    {
        DbgBreakIf( !pdev ) ;
        return LM_STATUS_INVALID_PARAMETER ;
    }

    if( FALSE == b_is_link_up ) // link down
    {
        pdev->vars.stats.stats_collect.stats_hw.b_is_link_up = FALSE ;

        if ( FALSE == LM_STATS_IS_HW_ACTIVE(pdev) )
        {
            return LM_STATUS_SUCCESS;
        }

        // get stats for the last time, assign to managment and save copy to mirror
        lm_status = lm_stats_on_update_state(pdev);

        if( LM_STATUS_SUCCESS != lm_status )
        {
            return lm_status ;
        }

        switch( pdev->vars.mac_type )
        {
        case MAC_TYPE_EMAC:
            lm_stats_clear_emac_stats( pdev ) ; // resest emac stats fields
            break;

        case MAC_TYPE_BMAC: // nothing to do - bigmac resets itself anyway
            break;

        case MAC_TYPE_UMAC: // nothing to do - mstat resets anyway
        case MAC_TYPE_XMAC:
            DbgBreakIf(!CHIP_IS_E3(pdev));
            break;

        default:
        case MAC_TYPE_NONE:
            DbgBreakMsg( "mac_type not acceptable\n" ) ;
            return LM_STATUS_INVALID_PARAMETER ;
        }

        // Set current to 0
        mm_mem_zero( &pdev->vars.stats.stats_mirror.stats_hw.macs[STATS_MACS_IDX_CURRENT],
                     sizeof(pdev->vars.stats.stats_mirror.stats_hw.macs[STATS_MACS_IDX_CURRENT]) ) ;
    }
    else
    {
        pdev->vars.stats.stats_collect.stats_hw.b_is_link_up = TRUE ;
    }

    return lm_status ;
}

/**lm_stats_alloc_hw_query
 * Allocate buffers for the MAC and NIG stats. If the chip has
 * an EMAC block, memory will be allocated for it's stats.
 * otherwise only the non-EMAC and NIG buffers will be
 * allocated. The non-EMAC buffer will be of the proper size for
 * BMAC1/BMAC2/MSTAT, as needed.
 *
 * @param pdev the pdev to initialize
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success,
 *         LM_STATUS_FAILURE on failure.
 */
static lm_status_t lm_stats_alloc_hw_query(lm_device_t *pdev)
{
    lm_stats_hw_collect_t*  stats_hw                = &(pdev->vars.stats.stats_collect.stats_hw);
    u32_t                   alloc_size              = 0 ;
    u32_t                   mac_stats_alloc_size    = 0;
    lm_address_t            phys_addr               = {{0}};

    if(!HAS_MSTAT(pdev)) //MSTAT replaces EMAC/BMAC1/BMAC2 stats.
    {
        DbgMessage(NULL, INFORM, "lm_stats_alloc_hw_query: device has no MSTAT block.\n");
        // Allocate continuous memory for statistics buffers to be read from hardware. This can probably be changed to
        // allocate max(emac, bmac) instead of emac+bmac, but need to make sure there are no races in the transition from
        // 1G link to 10G link or vice-versa
        mac_stats_alloc_size = sizeof(struct _stats_emac_query_t) + sizeof( union _stats_bmac_query_t);
        alloc_size =  mac_stats_alloc_size + sizeof( struct _stats_nig_query_t ) ;
        stats_hw->u.s.addr_emac_stats_query = mm_alloc_phys_mem(pdev, alloc_size, &phys_addr ,PHYS_MEM_TYPE_NONCACHED, LM_RESOURCE_COMMON );

        stats_hw->mac_stats_phys_addr = phys_addr;
        LM_INC64(&phys_addr, sizeof(struct _stats_emac_query_t));
        stats_hw->bmac_stats_phys_addr = phys_addr;
        LM_INC64(&phys_addr, sizeof( union _stats_bmac_query_t));
        stats_hw->nig_stats_phys_addr= phys_addr;

        DbgMessage(NULL, INFORM, "lm_stats_alloc_hw_query: allocated a block of size %d at %x\n", alloc_size, stats_hw->u.s.addr_emac_stats_query);
        if CHK_NULL( stats_hw->u.s.addr_emac_stats_query )
        {
            DbgBreakIf(!stats_hw->u.s.addr_emac_stats_query );
            return LM_STATUS_FAILURE ;
        }

        stats_hw->u.s.addr_bmac1_stats_query = (struct _stats_bmac1_query_t*)((u8_t*)stats_hw->u.s.addr_emac_stats_query + sizeof(struct _stats_emac_query_t)) ;
        stats_hw->u.s.addr_bmac2_stats_query = (struct _stats_bmac2_query_t*)((u8_t*)stats_hw->u.s.addr_emac_stats_query + sizeof(struct _stats_emac_query_t)) ;
        stats_hw->addr_nig_stats_query   = (struct _stats_nig_query_t*)((u8_t*)stats_hw->u.s.addr_bmac1_stats_query + sizeof(union _stats_bmac_query_t)) ;
        DbgMessage(NULL, INFORM, "lm_stats_alloc_hw_query: addr_bmac1_stats_query = %x, addr_bmac2_stats_query=%x, addr_nig_stats_query=%x\n", stats_hw->u.s.addr_bmac1_stats_query, stats_hw->u.s.addr_bmac2_stats_query, stats_hw->addr_nig_stats_query);
    }
    else
    {
        DbgMessage(NULL, INFORM, "lm_stats_alloc_hw_query: device has an MSTAT block.\n");

        mac_stats_alloc_size = sizeof(struct _stats_mstat_query_t);
        alloc_size = mac_stats_alloc_size + sizeof( struct _stats_nig_query_t );

        stats_hw->u.addr_mstat_stats_query = mm_alloc_phys_mem(pdev, alloc_size, &phys_addr ,PHYS_MEM_TYPE_NONCACHED, LM_RESOURCE_COMMON );

        stats_hw->mac_stats_phys_addr = phys_addr;
        LM_INC64(&phys_addr, mac_stats_alloc_size);
        stats_hw->nig_stats_phys_addr = phys_addr;

        DbgMessage(NULL, INFORM, "lm_stats_alloc_hw_query: allocated a block of size %d at %x\n", alloc_size, stats_hw->u.addr_mstat_stats_query);
        if CHK_NULL( stats_hw->u.addr_mstat_stats_query )
        {
            DbgBreakIf(!stats_hw->u.addr_mstat_stats_query );
            return LM_STATUS_FAILURE ;
        }

        stats_hw->addr_nig_stats_query   = (struct _stats_nig_query_t*)((u8_t*)stats_hw->u.addr_mstat_stats_query + sizeof(struct _stats_mstat_query_t)) ;
        DbgMessage(NULL, INFORM, "lm_stats_alloc_hw_query: stats_hw->addr_nig_stats_query=%x\n", stats_hw->addr_nig_stats_query);
    }

    return LM_STATUS_SUCCESS;
}

lm_status_t lm_stats_alloc_fw_resc (struct _lm_device_t *pdev)
{
    lm_stats_fw_collect_t * stats_fw        = &pdev->vars.stats.stats_collect.stats_fw;
    u32_t                   num_groups      = 0;
    u32_t                   alloc_size      = 0;
    u8_t                    num_queue_stats = 1;

    /* Total number of FW statistics requests =
     * 1 for port stats + 1 for PF stats + 1 for queue stats + 1 for FCoE stats + 1 for toe stats */
    #define NUM_FW_STATS_REQS 5
    stats_fw->fw_static_stats_num = stats_fw->fw_stats_num = NUM_FW_STATS_REQS;

#ifndef __LINUX
    if (IS_CHANNEL_VIRT_MODE_MASTER_PFDEV(pdev)) {
        stats_fw->fw_stats_num += pdev->hw_info.sriov_info.total_vfs * 2;
    }
#endif

    /* Request is built from stats_query_header and an array of
     * stats_query_cmd_group each of which contains
     * STATS_QUERY_CMD_COUNT rules. The real number or requests is
     * configured in the stats_query_header.
     */
    num_groups = (stats_fw->fw_stats_num) / STATS_QUERY_CMD_COUNT +
        (((stats_fw->fw_stats_num) % STATS_QUERY_CMD_COUNT) ? 1 : 0);

#ifndef __LINUX
    if (IS_CHANNEL_VIRT_MODE_MASTER_PFDEV(pdev)) {
        DbgMessage(pdev, WARN, "%d stats groups to support %d VFs\n",num_groups, pdev->hw_info.sriov_info.total_vfs);
    }
#endif
    stats_fw->fw_stats_req_sz = sizeof(struct stats_query_header) +
            num_groups * sizeof(struct stats_query_cmd_group);

    /* Data for statistics requests + stats_conter
     *
     * stats_counter holds per-STORM counters that are incremented
     * when STORM has finished with the current request.
     */
    stats_fw->fw_stats_data_sz = sizeof(struct per_port_stats) +
                             sizeof(struct per_pf_stats) +
                             sizeof(struct per_queue_stats) * num_queue_stats +
                             sizeof(struct toe_stats_query) +
                             sizeof(struct fcoe_statistics_params) +
                             sizeof(struct stats_counter);

    alloc_size = stats_fw->fw_stats_data_sz + stats_fw->fw_stats_req_sz;
    stats_fw->fw_stats = mm_alloc_phys_mem(pdev, alloc_size, &stats_fw->fw_stats_mapping ,PHYS_MEM_TYPE_NONCACHED, LM_RESOURCE_COMMON );
    if (!stats_fw->fw_stats)
    {
        return LM_STATUS_RESOURCE;
    }
    /* Set shortcuts */
    stats_fw->fw_stats_req = (lm_stats_fw_stats_req_t *)stats_fw->fw_stats;
    stats_fw->fw_stats_req_mapping = stats_fw->fw_stats_mapping;

    stats_fw->fw_stats_data = (lm_stats_fw_stats_data_t *)
        ((u8*)stats_fw->fw_stats + stats_fw->fw_stats_req_sz);

    stats_fw->fw_stats_data_mapping = stats_fw->fw_stats_mapping;
    LM_INC64(&stats_fw->fw_stats_data_mapping, stats_fw->fw_stats_req_sz);

    return LM_STATUS_SUCCESS;
}

/*
 *Function Name: lm_stats_alloc_drv_info_to_mfw_resc
 *
 *Parameters:
 *
 *Description:
 *  Allocates physical memory to be used for OCBB statisics query by MFW needed for E3+ only
 *Returns:
 *
 */
static lm_status_t lm_stats_alloc_drv_info_to_mfw_resc(lm_device_t *pdev)
{
    lm_stats_drv_info_to_mfw_t*        drv_info_to_mfw = &(pdev->vars.stats.stats_collect.drv_info_to_mfw );
    u32_t                              alloc_size      = 0 ;
    lm_address_t                       phys_addr       = {{0}};
    lm_status_t                        lm_status       = LM_STATUS_SUCCESS;

    if( CHIP_IS_E3(pdev) )
    {
        alloc_size                                 = max( ( sizeof( *drv_info_to_mfw->addr.eth_stats   ) ),
                                                          ( sizeof( *drv_info_to_mfw->addr.iscsi_stats ) ) ) ;
        alloc_size                                 = max( ( sizeof( *drv_info_to_mfw->addr.fcoe_stats  ) ), alloc_size ) ;

        // since it is a union it doesn't matter
        drv_info_to_mfw->addr.eth_stats            = mm_alloc_phys_mem(pdev, alloc_size, &phys_addr ,PHYS_MEM_TYPE_NONCACHED, LM_RESOURCE_COMMON );

        if( !drv_info_to_mfw->addr.eth_stats )
        {
            lm_status = LM_STATUS_RESOURCE;
        }

        drv_info_to_mfw->drv_info_to_mfw_phys_addr = phys_addr;
    }

    return lm_status;
}

// allocate memory both for hw and fw statistics
lm_status_t lm_stats_alloc_resc( struct _lm_device_t* pdev )
{
    u8_t                    loader_channel_idx      = (u8_t)(-1) ;
    u8_t                    executer_channel_idx    = (u8_t)(-1) ;
    lm_status_t             lm_status               = LM_STATUS_SUCCESS;
    lm_dmae_context_info_t *stats_dmae_context_info = lm_dmae_get(pdev, LM_DMAE_STATS);

    if CHK_NULL(pdev )
    {
        DbgBreakIf(!pdev) ;
        return LM_STATUS_INVALID_PARAMETER ;
    }

    lm_status = lm_stats_alloc_fw_resc(pdev);

    if( lm_status != LM_STATUS_SUCCESS )
    {
        // stats is not such a big deal if not working but since we
        // only allocate here buffer, it doesn't matter since next alloc will also fail...
        return lm_status;
    }


    lm_status = lm_stats_alloc_drv_info_to_mfw_resc(pdev);

    if( lm_status != LM_STATUS_SUCCESS )
    {
        // OCBB is not such a big deal if not working but since we
        // only allocate here buffer, it doesn't matter since next alloc will also fail...
        return lm_status;
    }

    lm_status = lm_stats_alloc_hw_query(pdev);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }


    switch (PORT_ID(pdev))
    {
    case 0:
        {
            loader_channel_idx = DMAE_STATS_PORT_0_CMD_IDX_0;
            executer_channel_idx = DMAE_STATS_PORT_0_CMD_IDX_1;
        }
        break;
    case 1:
        {
            loader_channel_idx = DMAE_STATS_PORT_1_CMD_IDX_0;
            executer_channel_idx = DMAE_STATS_PORT_1_CMD_IDX_1;
        }
        break;
    default:
        {
            DbgMessage(NULL, FATAL, "Invalid Port ID %d\n", PORT_ID(pdev));
            DbgBreak();
            return LM_STATUS_INVALID_PARAMETER;
        }
        break;
    }

    //create the locking policy for the stats DMAE context
    lm_status = lm_dmae_locking_policy_create(pdev, LM_PROTECTED_RESOURCE_DMAE_STATS, LM_DMAE_LOCKING_POLICY_TYPE_PER_PF, &stats_dmae_context_info->locking_policy);
    if(lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    //create the stats DMAE context
    stats_dmae_context_info->context = lm_dmae_context_create_sgl( pdev,
                                                                   loader_channel_idx,
                                                                   executer_channel_idx,
                                                                   &stats_dmae_context_info->locking_policy,
                                                                   CHANGE_ENDIANITY);
    if (CHK_NULL(stats_dmae_context_info->context))
    {
        DbgBreak();
        return LM_STATUS_FAILURE;
    }

    //create the non-EMAC DMAE operation
    pdev->vars.stats.stats_collect.stats_hw.non_emac_dmae_operation = lm_dmae_operation_create_sgl(pdev, TRUE, stats_dmae_context_info->context);

    //create the EMAC DMAE operation if needed
    if (!HAS_MSTAT(pdev))
    {
        pdev->vars.stats.stats_collect.stats_hw.emac_dmae_operation = lm_dmae_operation_create_sgl(pdev, TRUE, stats_dmae_context_info->context);
    }
    else
    {
        pdev->vars.stats.stats_collect.stats_hw.emac_dmae_operation = NULL;
    }

    return LM_STATUS_SUCCESS ;
}

/**lm_stats_hw_setup_nig
 * Add the DMAE command for reading NIG stats to the non-EMAC
 * DMAE context.
 *
 * @param pdev the device to initialize
 * @param dmae_operation the operation to setup for reading NIG
 *                       statistics
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *         failure value on failure.
 */
static lm_status_t lm_stats_hw_setup_nig(lm_device_t* pdev, lm_dmae_operation_t* dmae_operation)
{
    lm_status_t     lm_status    = LM_STATUS_FAILURE;

    lm_dmae_address_t source = lm_dmae_address((0==PORT_ID(pdev))?NIG_REG_STAT0_BRB_DISCARD : NIG_REG_STAT1_BRB_DISCARD,
                                               LM_DMAE_ADDRESS_GRC);
    lm_dmae_address_t dest = lm_dmae_address(pdev->vars.stats.stats_collect.stats_hw.nig_stats_phys_addr.as_u64,
                                             LM_DMAE_ADDRESS_HOST_PHYS);

    lm_status = lm_dmae_operation_add_sge(pdev, dmae_operation, source, dest, sizeof(struct _stats_nig_query_t ) / sizeof(u32_t));

    return lm_status;
}

/**
 * This struct is used to describe a DMAE SGE. It is used by the
 * lm_status_setup_xxx and lm_stats_set_dmae_operation_sges
 * functions.
 *
 */
struct lm_stats_sge_descr_t{
    u32_t source_offset;
    u64_t dest_paddr;
    u16_t length; // in DWORDS
};


/**lm_stats_set_dmae_operation_sges
 * Set the SGEs of a DMAE operation according to the supplied
 * SGE descriptor array. If the DMAE operation had any SGEs
 * defined before, this function removes them.
 *
 * @param pdev the device to use
 * @param operation the operation to modify
 * @param sge_descr the array of SGE descriptors
 * @param num_sges the number of SGE descriptors
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *         failure value on failure.
 */
static lm_status_t lm_stats_set_dmae_operation_sges(lm_device_t* pdev, lm_dmae_operation_t* operation, struct lm_stats_sge_descr_t* sge_descr, u8_t num_sges)
{
    u8_t sge_idx = 0;
    lm_dmae_address_t sge_source = {{0}};
    lm_dmae_address_t sge_dest = {{0}};
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    //after returning from D3 there may be some SGEs set up here.
    lm_dmae_operation_clear_all_sges(operation);

    for (sge_idx = 0; sge_idx < num_sges; ++sge_idx)
    {
        sge_source = lm_dmae_address(sge_descr[sge_idx].source_offset, LM_DMAE_ADDRESS_GRC);
        sge_dest = lm_dmae_address(sge_descr[sge_idx].dest_paddr, LM_DMAE_ADDRESS_HOST_PHYS);

        lm_status = lm_dmae_operation_add_sge(pdev, operation, sge_source, sge_dest, sge_descr[sge_idx].length);
        if (LM_STATUS_SUCCESS != lm_status)
        {
            DbgBreak();
            return lm_status;
        }
    }

    return lm_status;
}

/**lm_stats_hw_setup_emac
 * setup the DMAE SGL for the EMAC stats DMAE context
 *
 * @param pdev the device to initialize
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *         value on failure.
 */
static lm_status_t lm_stats_hw_setup_emac(  lm_device_t* pdev)
{
    const u64_t base_paddr = pdev->vars.stats.stats_collect.stats_hw.mac_stats_phys_addr.as_u64;

    const u16_t sge1_len = sizeof(pdev->vars.stats.stats_collect.stats_hw.u.s.addr_emac_stats_query->stats_rx );
    const u16_t sge2_len = sizeof(pdev->vars.stats.stats_collect.stats_hw.u.s.addr_emac_stats_query->stats_rx_err );
    const u32_t emac_base = (PORT_ID(pdev)==0) ? GRCBASE_EMAC0 : GRCBASE_EMAC1;

    lm_status_t lm_status = LM_STATUS_FAILURE;

    lm_dmae_operation_t* operation = pdev->vars.stats.stats_collect.stats_hw.emac_dmae_operation;

    struct lm_stats_sge_descr_t sges[3] = {{0}}; //we can't use an initializer because DOS compiler requires that all initializers be constant.

    sges[0].source_offset = emac_base + EMAC_REG_EMAC_RX_STAT_IFHCINOCTETS;
    sges[0].dest_paddr = base_paddr;
    sges[0].length = EMAC_REG_EMAC_RX_STAT_AC_COUNT;

    sges[1].source_offset = emac_base + EMAC_REG_EMAC_RX_STAT_FALSECARRIERERRORS;
    sges[1].dest_paddr = base_paddr + sge1_len;
    sges[1].length = 1;

    sges[2].source_offset = emac_base + EMAC_REG_EMAC_TX_STAT_IFHCOUTOCTETS;
    sges[2].dest_paddr = base_paddr + sge1_len + sge2_len;
    sges[2].length = EMAC_REG_EMAC_TX_STAT_AC_COUNT;

    lm_status = lm_stats_set_dmae_operation_sges(pdev, operation, sges, ARRSIZE(sges));
    if (LM_STATUS_SUCCESS != lm_status)
    {
        DbgBreakMsg("Failed to initialize EMAC stats DMAE operation.\n");
        return lm_status;
    }

    lm_status = lm_stats_hw_setup_nig(pdev, operation);
    if (LM_STATUS_SUCCESS != lm_status)
    {
        DbgBreakMsg("Failed to initialize NIG stats DMAE operation.\n");
        return lm_status;
    }

    return lm_status;
}

/**lm_stats_hw_setup_non_emac
 * Setup the DMAE SGL for the non-EMAC stats DMAE context. This
 * function assumes that the MAC statistics themselves can be
 * read with 2 DMAE transactions.
 *
 *
 * @param pdev the device to initialize
 * @param paddr_base the base physical address where the
 *                   statistics data will be copied.
 * @param grc_base the base GRC address of the required stats
 *                 block (e.g NIG_REG_INGRESS_BMAC0_MEM or
 *                 GRCBASE_MSTAT0)
 * @param block1_start offset of the first register in the first
 *                     transaction.
 * @param block1_size size (in bytes) of the first DMAE
 *                    transaction.
 * @param block2_start offset of the first register in the
 *                     second transaction.
 * @param block2_size size (in bytes) of the second DMAE
 *                    transaction.
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *         value on failure.
 */
static lm_status_t lm_stats_hw_setup_non_emac(  lm_device_t* pdev,
                                                u64_t paddr_base,
                                                u32_t grc_base,
                                                u32_t block1_start, u16_t block1_size,
                                                u32_t block2_start, u16_t block2_size)
{
    lm_status_t lm_status = LM_STATUS_FAILURE;

    lm_dmae_operation_t* operation = (lm_dmae_operation_t*)pdev->vars.stats.stats_collect.stats_hw.non_emac_dmae_operation;

    struct lm_stats_sge_descr_t sges[2] = {{0}};

    sges[0].source_offset = grc_base+block1_start;
    sges[0].dest_paddr = paddr_base;
    sges[0].length = block1_size / sizeof(u32_t);

    sges[1].source_offset = grc_base+block2_start;
    sges[1].dest_paddr = paddr_base + block1_size;
    sges[1].length = block2_size / sizeof(u32_t);

    lm_status = lm_stats_set_dmae_operation_sges(pdev, operation, sges, ARRSIZE(sges));
    if (LM_STATUS_SUCCESS != lm_status)
    {
        DbgBreakMsg("Failed to initialize non-EMAC stats DMAE operation.\n");
        return lm_status;
    }

    lm_status = lm_stats_hw_setup_nig(pdev, operation);
    if (LM_STATUS_SUCCESS != lm_status)
    {
        DbgBreakMsg("Failed to initialize NIG stats DMAE operation.\n");
        return lm_status;
    }

    return lm_status;
}

/**lm_stats_hw_setup_bmac
 * Setup the BMAC1/BMAC2 stats DMAE transactions.
 * @see lm_stats_hw_setup_non_emac for more details.
 *
 * @param pdev the device to initialize.
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *         value on failure.
 */
static lm_status_t lm_stats_hw_setup_bmac(lm_device_t* pdev)
{
    const u32_t     port         = PORT_ID(pdev) ;
    u32_t           bmac_base    = 0 ; // bmac: GRCBASE_NIG, bmac_base + reg name
                                       // nig :GRCBASE_NIG, reg name (NIG_XXX)
    u32_t           bmac_tx_start_reg, bmac_rx_start_reg;
    u16_t           bmac_tx_stat_size, bmac_rx_stat_size;
    lm_status_t     lm_status = LM_STATUS_FAILURE;

    DbgBreakIf(HAS_MSTAT(pdev));

    switch( port )
    {
    case 0:
        bmac_base = NIG_REG_INGRESS_BMAC0_MEM ;
        break;

    case 1:
        bmac_base = NIG_REG_INGRESS_BMAC1_MEM;

        if (!CHIP_IS_E1x(pdev))
        {
            DbgMessage(pdev, INFORMi, "BMAC stats should never be collected on port 1 of E2!\n");
            bmac_base = NIG_REG_INGRESS_BMAC0_MEM;
        }
        break;

    default:
        DbgBreakIf( port > 1 ) ;
        break;

    }

    if (CHIP_IS_E1x(pdev))
    {
        bmac_tx_start_reg = BIGMAC_REGISTER_TX_STAT_GTPKT;
        bmac_rx_start_reg = BIGMAC_REGISTER_RX_STAT_GR64;
        bmac_tx_stat_size = sizeof(pdev->vars.stats.stats_collect.stats_hw.u.s.addr_bmac1_stats_query->stats_tx);
        bmac_rx_stat_size = sizeof(pdev->vars.stats.stats_collect.stats_hw.u.s.addr_bmac1_stats_query->stats_rx);
    }
    else
    {
        bmac_tx_start_reg = BIGMAC2_REGISTER_TX_STAT_GTPOK;
        bmac_rx_start_reg = BIGMAC2_REGISTER_RX_STAT_GR64;
        bmac_tx_stat_size = sizeof(pdev->vars.stats.stats_collect.stats_hw.u.s.addr_bmac2_stats_query->stats_tx);
        bmac_rx_stat_size = sizeof(pdev->vars.stats.stats_collect.stats_hw.u.s.addr_bmac2_stats_query->stats_rx);
    }

    lm_status = lm_stats_hw_setup_non_emac(pdev,
                                           pdev->vars.stats.stats_collect.stats_hw.bmac_stats_phys_addr.as_u64,
                                           bmac_base,
                                           bmac_tx_start_reg,
                                           bmac_tx_stat_size,
                                           bmac_rx_start_reg,
                                           bmac_rx_stat_size);

    return lm_status;
}

/**lm_stats_hw_setup_mstat
 * Setup the MSTAT stats DMAE transactions.
 * @see lm_stats_hw_setup_non_emac for more details.
 *
 * @param pdev the device to initialize.
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *         value on failure.
 */
static lm_status_t lm_stats_hw_setup_mstat(lm_device_t* pdev)
{
    const u32_t     port         = PORT_ID(pdev) ;
    u32_t           mstat_base   = 0;
    u32_t           mstat_tx_start, mstat_rx_start;
    u16_t           mstat_tx_size, mstat_rx_size;
    lm_status_t     lm_status    = LM_STATUS_FAILURE;
    lm_stats_hw_collect_t* stats_hw = &pdev->vars.stats.stats_collect.stats_hw;

    DbgBreakIf(!HAS_MSTAT(pdev));

    mstat_tx_start = MSTAT_REG_TX_STAT_GTXPOK_LO;
    mstat_tx_size = sizeof(stats_hw->u.addr_mstat_stats_query->stats_tx);

    mstat_rx_start = MSTAT_REG_RX_STAT_GR64_LO;
    mstat_rx_size = sizeof(stats_hw->u.addr_mstat_stats_query->stats_rx);

    DbgMessage(pdev, INFORM, "lm_stats_hw_setup_mstat: mstat_tx_start=%x, mstat_tx_size=%x, mstat_rx_start=%x, mstat_rx_size=%x\n",mstat_tx_start,mstat_tx_size,mstat_rx_start, mstat_rx_size);

    switch(port)
    {
    case 0:
        mstat_base = GRCBASE_MSTAT0;
        break;
    case 1:
        mstat_base = GRCBASE_MSTAT1;
        break;
    default:
        DbgBreakIf( port > 1 ) ;
        break;
    }

    lm_status = lm_stats_hw_setup_non_emac(pdev,
                                           pdev->vars.stats.stats_collect.stats_hw.mac_stats_phys_addr.as_u64,
                                           mstat_base,
                                           mstat_tx_start,
                                           mstat_tx_size,
                                           mstat_rx_start,
                                           mstat_rx_size);

    return lm_status;
}

/* Description:
*    setups resources regarding hw stats (init fields)
*    set offsets serials of hw reads, either from EMAC & BIGMAC or from MSTAT block
*/
lm_status_t lm_stats_hw_setup(struct _lm_device_t *pdev)
{
    lm_status_t lm_status           = LM_STATUS_SUCCESS ;
    /* enable hw collect with mstat only if it's not fpga and not a 4-domain emulation compile... */
    u8_t        b_enable_collect    = HAS_MSTAT(pdev)? ((CHIP_REV_IS_EMUL(pdev) && (CHIP_BONDING(pdev) == 0)) || CHIP_REV_IS_ASIC(pdev)) : TRUE;

    if(HAS_MSTAT(pdev))
    {
        lm_status = lm_stats_hw_setup_mstat(pdev);
        if(lm_status != LM_STATUS_SUCCESS)
        {
            DbgMessage(NULL, FATAL, "Failed to initialize MSTAT statistics\n");
            return lm_status;
        }
    }
    else
    {
        lm_status = lm_stats_hw_setup_emac(pdev);
        if(lm_status != LM_STATUS_SUCCESS)
        {
            DbgMessage(NULL, FATAL, "Failed to initialize EMAC statistics\n");
            return lm_status;
        }
        lm_status = lm_stats_hw_setup_bmac(pdev);
        if(lm_status != LM_STATUS_SUCCESS)
        {
            DbgMessage(NULL, FATAL, "Failed to initialize BMAC statistics\n");
            return lm_status;
        }
    }

    pdev->vars.stats.stats_collect.stats_hw.b_is_link_up = FALSE;

    pdev->vars.stats.stats_collect.stats_hw.b_collect_enabled = b_enable_collect ; // HW stats are not supported on E3 FPGA.

    return lm_status ;
} /* lm_stats_hw_setup */

/**
 * This function will prepare the statistics ramrod data the way
 * we will only have to increment the statistics counter and
 * send the ramrod each time we have to.
 *
 * @param pdev
 */
static void lm_stats_prep_fw_stats_req(lm_device_t *pdev)
{
    lm_stats_fw_collect_t     *stats_fw        = &pdev->vars.stats.stats_collect.stats_fw;
    struct stats_query_header *stats_hdr       = &stats_fw->fw_stats_req->hdr;
    lm_address_t              cur_data_offset  = {{0}};
    struct stats_query_entry  *cur_query_entry = NULL;

    stats_hdr->cmd_num           = stats_fw->fw_stats_num;
    stats_hdr->drv_stats_counter = 0;

    /* storm_counters struct contains the counters of completed
     * statistics requests per storm which are incremented by FW
     * each time it completes hadning a statistics ramrod. We will
     * check these counters in the timer handler and discard a
     * (statistics) ramrod completion.
     */
    cur_data_offset = stats_fw->fw_stats_data_mapping;
    LM_INC64(&cur_data_offset, OFFSETOF(lm_stats_fw_stats_data_t, storm_counters));

    stats_hdr->stats_counters_addrs.hi = mm_cpu_to_le32(cur_data_offset.as_u32.high);
    stats_hdr->stats_counters_addrs.lo = mm_cpu_to_le32(cur_data_offset.as_u32.low);

    /* prepare to the first stats ramrod (will be completed with
     * the counters equal to zero) - init counters to somethig different.
     */
    mm_memset(&stats_fw->fw_stats_data->storm_counters, 0xff, sizeof(stats_fw->fw_stats_data->storm_counters) );

    /**** Port FW statistics data ****/
    cur_data_offset = stats_fw->fw_stats_data_mapping;
    LM_INC64(&cur_data_offset, OFFSETOF(lm_stats_fw_stats_data_t, port));

    cur_query_entry = &stats_fw->fw_stats_req->query[LM_STATS_PORT_QUERY_IDX];

    cur_query_entry->kind       = STATS_TYPE_PORT;
    /* For port query index is a DONT CARE */
    cur_query_entry->index      = PORT_ID(pdev);
    cur_query_entry->funcID     = mm_cpu_to_le16(FUNC_ID(pdev));;
    cur_query_entry->address.hi = mm_cpu_to_le32(cur_data_offset.as_u32.high);
    cur_query_entry->address.lo = mm_cpu_to_le32(cur_data_offset.as_u32.low);

    /**** PF FW statistics data ****/
    cur_data_offset = stats_fw->fw_stats_data_mapping;
    LM_INC64(&cur_data_offset, OFFSETOF(lm_stats_fw_stats_data_t, pf));

    cur_query_entry = &stats_fw->fw_stats_req->query[LM_STATS_PF_QUERY_IDX];

    cur_query_entry->kind       = STATS_TYPE_PF;
    /* For PF query index is a DONT CARE */
    cur_query_entry->index      = PORT_ID(pdev);
    cur_query_entry->funcID     = mm_cpu_to_le16(FUNC_ID(pdev));
    cur_query_entry->address.hi = mm_cpu_to_le32(cur_data_offset.as_u32.high);
    cur_query_entry->address.lo = mm_cpu_to_le32(cur_data_offset.as_u32.low);

    /**** Toe query  ****/
    cur_data_offset = stats_fw->fw_stats_data_mapping;
    LM_INC64(&cur_data_offset, OFFSETOF(lm_stats_fw_stats_data_t, toe));

    ASSERT_STATIC(LM_STATS_TOE_IDX<ARRSIZE(stats_fw->fw_stats_req->query));
    cur_query_entry = &stats_fw->fw_stats_req->query[LM_STATS_TOE_IDX];

    cur_query_entry->kind       = STATS_TYPE_TOE;
    cur_query_entry->index      = LM_STATS_CNT_ID(pdev);
    cur_query_entry->funcID     = mm_cpu_to_le16(FUNC_ID(pdev));
    cur_query_entry->address.hi = mm_cpu_to_le32(cur_data_offset.as_u32.high);
    cur_query_entry->address.lo = mm_cpu_to_le32(cur_data_offset.as_u32.low);

    if ( !CHIP_IS_E1x(pdev) )
    {
        // FW will assert if we send this kind for chip < E2
        /**** FCoE query  ****/
        cur_data_offset = stats_fw->fw_stats_data_mapping;
        LM_INC64(&cur_data_offset, OFFSETOF(lm_stats_fw_stats_data_t, fcoe));

        ASSERT_STATIC(LM_STATS_FCOE_IDX<ARRSIZE(stats_fw->fw_stats_req->query));
        cur_query_entry = &stats_fw->fw_stats_req->query[LM_STATS_FCOE_IDX];
        cur_query_entry->kind       = STATS_TYPE_FCOE;
        cur_query_entry->index      = LM_STATS_CNT_ID(pdev);
        cur_query_entry->funcID     = mm_cpu_to_le16(FUNC_ID(pdev));
        cur_query_entry->address.hi = mm_cpu_to_le32(cur_data_offset.as_u32.high);
        cur_query_entry->address.lo = mm_cpu_to_le32(cur_data_offset.as_u32.low);
    }
    else
    {
        // if no FCoE, we need to decrease command count by one
        --stats_hdr->cmd_num;
    }

    /**** Clients' queries ****/
    cur_data_offset = stats_fw->fw_stats_data_mapping;
    LM_INC64(&cur_data_offset, OFFSETOF(lm_stats_fw_stats_data_t, queue_stats));

    ASSERT_STATIC(LM_STATS_FIRST_QUEUE_QUERY_IDX < ARRSIZE(stats_fw->fw_stats_req->query));
    cur_query_entry = &stats_fw->fw_stats_req->query[LM_STATS_FIRST_QUEUE_QUERY_IDX];

    cur_query_entry->kind       = STATS_TYPE_QUEUE;
    cur_query_entry->index      = LM_STATS_CNT_ID(pdev);
    cur_query_entry->funcID     = mm_cpu_to_le16(FUNC_ID(pdev));
    cur_query_entry->address.hi = mm_cpu_to_le32(cur_data_offset.as_u32.high);
    cur_query_entry->address.lo = mm_cpu_to_le32(cur_data_offset.as_u32.low);
    /* TODO : VF! more stats? */
}

#ifdef VF_INVOLVED
void lm_stats_prep_vf_fw_stats_req(lm_device_t *pdev)
{
    lm_stats_fw_collect_t      *stats_fw = &pdev->vars.stats.stats_collect.stats_fw;
    struct stats_query_header  *stats_hdr = &stats_fw->fw_stats_req->hdr;
    struct stats_query_entry   *cur_query_entry;
    u8_t                        vf_idx = 0;
    u8_t                        cmd_cnt = 0;
    lm_vf_info_t               *vf_info;

    cur_query_entry = &stats_fw->fw_stats_req->query[LM_STATS_FIRST_VF_QUEUE_QUERY_IDX];

    MM_ACQUIRE_VFS_STATS_LOCK_DPC(pdev);
    for (vf_idx = 0; vf_idx < pdev->vfs_set.number_of_enabled_vfs; vf_idx++) {
        vf_info = &pdev->vfs_set.vfs_array[vf_idx];
        if (vf_info->vf_stats.vf_stats_state == VF_STATS_REQ_SUBMITTED) {
            u8_t process_it = FALSE;
            if (vf_info->vf_stats.vf_stats_flag & VF_STATS_COLLECT_FW_STATS_FOR_PF) {
                cur_query_entry->kind = STATS_TYPE_QUEUE;
                cur_query_entry->index = LM_FW_VF_STATS_CNT_ID(vf_info);
                cur_query_entry->funcID = mm_cpu_to_le16(FUNC_ID(pdev));
                cur_query_entry->address.hi = mm_cpu_to_le32(vf_info->vf_stats.pf_fw_stats_phys_data.as_u32.high);
                cur_query_entry->address.lo = mm_cpu_to_le32(vf_info->vf_stats.pf_fw_stats_phys_data.as_u32.low);
                process_it = TRUE;
                cur_query_entry++;
                cmd_cnt++;
            }
            if (vf_info->vf_stats.vf_stats_flag & VF_STATS_COLLECT_FW_STATS_FOR_VF) {
                cur_query_entry->kind = STATS_TYPE_QUEUE;
                cur_query_entry->index = LM_FW_VF_STATS_CNT_ID(vf_info);
                cur_query_entry->funcID = mm_cpu_to_le16(8 + vf_info->abs_vf_id);
                cur_query_entry->address.hi = mm_cpu_to_le32(vf_info->vf_stats.vf_fw_stats_phys_data.as_u32.high);
                cur_query_entry->address.lo = mm_cpu_to_le32(vf_info->vf_stats.vf_fw_stats_phys_data.as_u32.low);
                process_it = TRUE;
                cur_query_entry++;
                cmd_cnt++;
            }
            if (process_it) {
                vf_info->vf_stats.vf_stats_state = VF_STATS_REQ_IN_PROCESSING;
                vf_info->vf_stats.vf_stats_cnt++;
            }
        }
    }
    stats_hdr->cmd_num = stats_fw->fw_static_stats_num + cmd_cnt;
    MM_RELEASE_VFS_STATS_LOCK_DPC(pdev);

}
#endif

/* Description:
*    setups fw statistics parameters
*/
void lm_stats_fw_setup(struct _lm_device_t *pdev)
{
    lm_stats_fw_collect_t * stats_fw = &pdev->vars.stats.stats_collect.stats_fw;
    stats_fw->b_completion_done      = TRUE ; // reset flag to initial value
    stats_fw->b_ramrod_completed     = TRUE ;
    stats_fw->drv_counter            = 0 ;
    stats_fw->b_collect_enabled      = pdev->params.fw_stats_init_value ; // change to TRUE in order to enable fw stats

    pdev->vars.stats.stats_collect.b_last_called  = TRUE ;

    /* Prepare the constatnt slow-path command (For stats we don't allocate a new one each time) */
    lm_sq_post_fill_entry(pdev,
                          &(stats_fw->stats_sp_list_command),
                          0 /* cid: Don't care */,
                          RAMROD_CMD_ID_COMMON_STAT_QUERY,
                          NONE_CONNECTION_TYPE,
                          stats_fw->fw_stats_req_mapping.as_u64,
                          FALSE /* don't release sp mem*/);

    /* Prepare the FW stats ramrod request structure (can do this just once) */
    lm_stats_prep_fw_stats_req(pdev);
}
/*
 *------------------------------------------------------------------------
 * lm_stats_fw_check_update_done -
 *
 * check done flags and update flags
 *
 *------------------------------------------------------------------------
 */
void lm_stats_fw_check_update_done( struct _lm_device_t *pdev, OUT u32_t* ptr_stats_flags_done )
{
    if CHK_NULL( ptr_stats_flags_done )
    {
        DbgBreakIf(!ptr_stats_flags_done) ;
        return;
    }

    if (IS_VFDEV(pdev)) {
        SET_FLAGS(*ptr_stats_flags_done,LM_STATS_FLAGS_ALL);
        return;
    }
    // For each storm still wasn't done, we check and if done - set, so next time
    // we won't need to check again

    // eth xstorm
    if( 0 == GET_FLAGS(*ptr_stats_flags_done, LM_STATS_FLAG_XSTORM ) )
    {
        if( LM_STATS_VERIFY_COUNTER( pdev, fw_stats_data->storm_counters.xstats_counter ) )
        {
            SET_FLAGS(*ptr_stats_flags_done,LM_STATS_FLAG_XSTORM ) ;
        }
    }

    // eth tstorm
    if( 0 == GET_FLAGS(*ptr_stats_flags_done, LM_STATS_FLAG_TSTORM ) )
    {
        if( LM_STATS_VERIFY_COUNTER( pdev, fw_stats_data->storm_counters.tstats_counter ) )
        {
            SET_FLAGS(*ptr_stats_flags_done,LM_STATS_FLAG_TSTORM ) ;
        }
    }

    // eth ustorm
    if( 0 == GET_FLAGS(*ptr_stats_flags_done, LM_STATS_FLAG_USTORM ) )
    {
        if( LM_STATS_VERIFY_COUNTER( pdev, fw_stats_data->storm_counters.ustats_counter ) )
        {
            SET_FLAGS(*ptr_stats_flags_done,LM_STATS_FLAG_USTORM ) ;
        }
    }

    // eth cstorm
    if( 0 == GET_FLAGS(*ptr_stats_flags_done, LM_STATS_FLAG_CSTORM ) )
    {
        if( LM_STATS_VERIFY_COUNTER( pdev, fw_stats_data->storm_counters.cstats_counter ) )
        {
            SET_FLAGS(*ptr_stats_flags_done,LM_STATS_FLAG_CSTORM ) ;
        }
    }

}

/**
 * @Desription: Checks if FW completed last statistic update, if
 *            it did it assigns the statistics
 *
 * @param pdev
 *
 * @return lm_status_t LM_STATUS_SUCCESS if FW has completed
 *         LM_STATUS_BUSY if it hasn't yet completed
 */
lm_status_t lm_stats_fw_complete( struct _lm_device_t *pdev  )
{
    u32_t stats_flags_done      = 0 ; // bit wise for storms done flags are on
    u32_t stats_flags_assigned  = 0 ; // bit wise for already assigned values from storms
    lm_status_t lm_status             = LM_STATUS_SUCCESS;

    if CHK_NULL( pdev )
    {
        DbgBreakIf( !pdev ) ;
        return LM_STATUS_INVALID_PARAMETER;
    }

    /* First check if the ramrod has completed, if it hasn't don't bother checking
     * dma completion  yet, we need both of them to complete before sending another
     * ramrod. */
    if (IS_PFDEV(pdev) && (FALSE == pdev->vars.stats.stats_collect.stats_fw.b_ramrod_completed))
    {
        lm_status = LM_STATUS_BUSY;
    }
    else if (FALSE == pdev->vars.stats.stats_collect.stats_fw.b_completion_done)
    {

        // check done flags and update the falg if there was a change
        lm_stats_fw_check_update_done( pdev, &stats_flags_done ) ;

        // Check if we can assign any of the storms
        if ( LM_STATS_DO_ASSIGN_ANY( stats_flags_done, stats_flags_assigned) )
        {
            // assign stats that are ready
            lm_stats_fw_assign( pdev, stats_flags_done, &stats_flags_assigned ) ;
#ifdef VF_INVOLVED
#ifndef __LINUX
            if (IS_CHANNEL_VIRT_MODE_MASTER_PFDEV(pdev)) {
                u32_t vf_stats_flags_assigned  = 0;
                MM_ACQUIRE_VFS_STATS_LOCK_DPC(pdev);
                lm_pf_stats_vf_fw_assign( pdev, stats_flags_done, &vf_stats_flags_assigned);
                MM_RELEASE_VFS_STATS_LOCK_DPC(pdev);
            }
#endif
#endif
        }

        // did all storms were assigned
        if ERR_IF( LM_STATS_FLAGS_ALL != stats_flags_assigned  )
        {
            lm_status = LM_STATUS_BUSY;
        }
        else
        {
#ifdef VF_INVOLVED
#ifndef __LINUX
            if (IS_CHANNEL_VIRT_MODE_MASTER_PFDEV(pdev)) {
                u8_t            vf_idx;
                lm_vf_info_t   *vf_info;
                MM_ACQUIRE_VFS_STATS_LOCK_DPC(pdev);
                for (vf_idx = 0; vf_idx < pdev->vfs_set.number_of_enabled_vfs; vf_idx++) {
                    vf_info = &pdev->vfs_set.vfs_array[vf_idx];
                    if (vf_info->vf_stats.vf_stats_state == VF_STATS_REQ_IN_PROCESSING) {
                        if (vf_info->vf_stats.stop_collect_stats || vf_info->was_flred) {
                            vf_info->vf_stats.vf_stats_state = VF_STATS_REQ_READY;
                        } else {
                            vf_info->vf_stats.vf_stats_state = VF_STATS_REQ_SUBMITTED;
                        }
                    }
                }
                MM_RELEASE_VFS_STATS_LOCK_DPC(pdev);
            }
#endif
#endif
            ++pdev->vars.stats.stats_collect.stats_fw.drv_counter ;

            // barrier (for IA64) is to assure that the counter will be incremented BEFORE
            // the complation_done flag is set to TRUE.
            // in order to assure correct drv_counter sent to fw in lm_stats_on_timer (CQ48772)

            if (IS_PFDEV(pdev))
            {
                mm_write_barrier();
            }
            // now we can notify timer that cb is done!
            pdev->vars.stats.stats_collect.stats_fw.b_completion_done = TRUE ;
            lm_status = LM_STATUS_SUCCESS;
        }
    }
    return lm_status;
}

void
lm_stats_fw_assign_fcoe_xstorm(IN const struct fcoe_statistics_params* collect,
                               OUT lm_fcoe_stats_t* mirror)
{
    //Tx
    LM_SIGN_EXTEND_VALUE_32(collect->tx_stat.fcoe_tx_byte_cnt, mirror->fcoe_tx_byte_cnt);
    LM_SIGN_EXTEND_VALUE_32(collect->tx_stat.fcoe_tx_pkt_cnt, mirror->fcoe_tx_pkt_cnt);
    LM_SIGN_EXTEND_VALUE_32(collect->tx_stat.fcp_tx_pkt_cnt, mirror->fcp_tx_pkt_cnt);
}


void
lm_stats_fw_assign_fcoe_tstorm(IN const struct fcoe_statistics_params* collect,
                               OUT lm_fcoe_stats_t* mirror)
{
    //Section 0
    LM_SIGN_EXTEND_VALUE_32(collect->rx_stat0.fcoe_rx_byte_cnt, mirror->fcoe_rx_byte_cnt);
    LM_SIGN_EXTEND_VALUE_32(collect->rx_stat0.fcoe_rx_pkt_cnt, mirror->fcoe_rx_pkt_cnt);

    //Section 1
    LM_SIGN_EXTEND_VALUE_32(collect->rx_stat1.fcoe_rx_drop_pkt_cnt, mirror->fcoe_rx_drop_pkt_cnt_tstorm);
    LM_SIGN_EXTEND_VALUE_32(collect->rx_stat1.fcoe_ver_cnt, mirror->fcoe_ver_cnt);
}

void
lm_stats_fw_assign_fcoe_ustorm(IN const struct fcoe_statistics_params* collect,
                               OUT lm_fcoe_stats_t* mirror)
{
    //Section 2
    LM_SIGN_EXTEND_VALUE_32(collect->rx_stat2.drop_seq_cnt, mirror->drop_seq_cnt);
    LM_SIGN_EXTEND_VALUE_32(collect->rx_stat2.eofa_del_cnt, mirror->eofa_del_cnt);
    LM_SIGN_EXTEND_VALUE_32(collect->rx_stat2.fc_crc_cnt, mirror->fc_crc_cnt);
    LM_SIGN_EXTEND_VALUE_32(collect->rx_stat2.fcoe_rx_drop_pkt_cnt, mirror->fcoe_rx_drop_pkt_cnt_ustorm);
    LM_SIGN_EXTEND_VALUE_32(collect->rx_stat2.fcp_rx_pkt_cnt, mirror->fcp_rx_pkt_cnt);
    LM_SIGN_EXTEND_VALUE_32(collect->rx_stat2.miss_frame_cnt, mirror->miss_frame_cnt);
    LM_SIGN_EXTEND_VALUE_32(collect->rx_stat2.seq_timeout_cnt, mirror->seq_timeout_cnt);
}

/*
 *------------------------------------------------------------------------
 * lm_stats_fw_assign -
 *
 * assign values from fw shared memory to the lm structs
 *
 *------------------------------------------------------------------------
 */
void lm_stats_fw_assign( struct _lm_device_t *pdev, u32_t stats_flags_done, u32_t* ptr_stats_flags_assigned )
{
    const u8_t cli_id       = LM_CLI_IDX_NDIS ;
    int        arr_cnt      = 0 ;
    u8_t       i            = 0 ;

    if CHK_NULL( ptr_stats_flags_assigned )
    {
        DbgBreakIf(!ptr_stats_flags_assigned) ;
        return;
    }

// assign reg_pair fw collected into fw mirror
#define LM_STATS_FW_ASSIGN_TOE_REGPAIR(field_name) \
        REGPAIR_TO_U64(pdev->vars.stats.stats_mirror.stats_fw.toe_##field_name, \
        pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->toe.field_name ) ;

// assign u32 fw collected into fw mirror + do sign extension
#define LM_STATS_FW_ASSIGN_TOE_U32(field_name) \
        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->toe.field_name, \
        pdev->vars.stats.stats_mirror.stats_fw.toe_##field_name ) ;


    // eth xstorm
    if( LM_STATS_DO_ASSIGN( stats_flags_done, *ptr_stats_flags_assigned, LM_STATS_FLAG_XSTORM ) )
    {
        // regpairs
        REGPAIR_TO_U64(pdev->vars.stats.stats_mirror.stats_fw.eth_xstorm_common.client_statistics[cli_id].unicast_bytes_sent,
                       pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.xstorm_queue_statistics.ucast_bytes_sent);
        // regpairs
        REGPAIR_TO_U64(pdev->vars.stats.stats_mirror.stats_fw.eth_xstorm_common.client_statistics[cli_id].multicast_bytes_sent,
                       pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.xstorm_queue_statistics.mcast_bytes_sent);

        // regpairs
        REGPAIR_TO_U64(pdev->vars.stats.stats_mirror.stats_fw.eth_xstorm_common.client_statistics[cli_id].broadcast_bytes_sent,
                       pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.xstorm_queue_statistics.bcast_bytes_sent);

        pdev->vars.stats.stats_mirror.stats_fw.eth_xstorm_common.client_statistics[cli_id].total_sent_bytes =
            pdev->vars.stats.stats_mirror.stats_fw.eth_xstorm_common.client_statistics[cli_id].unicast_bytes_sent +
            pdev->vars.stats.stats_mirror.stats_fw.eth_xstorm_common.client_statistics[cli_id].multicast_bytes_sent +
            pdev->vars.stats.stats_mirror.stats_fw.eth_xstorm_common.client_statistics[cli_id].broadcast_bytes_sent;

        // non regpairs
        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.xstorm_queue_statistics.ucast_pkts_sent,
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_xstorm_common.client_statistics[cli_id].unicast_pkts_sent );

        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.xstorm_queue_statistics.mcast_pkts_sent,
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_xstorm_common.client_statistics[cli_id].multicast_pkts_sent );

        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.xstorm_queue_statistics.bcast_pkts_sent,
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_xstorm_common.client_statistics[cli_id].broadcast_pkts_sent );

        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.xstorm_queue_statistics.error_drop_pkts,
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_xstorm_common.client_statistics[cli_id].error_drop_pkts );

        pdev->vars.stats.stats_mirror.stats_fw.eth_xstorm_common.client_statistics[cli_id].total_sent_pkts =
            pdev->vars.stats.stats_mirror.stats_fw.eth_xstorm_common.client_statistics[cli_id].unicast_pkts_sent+
            pdev->vars.stats.stats_mirror.stats_fw.eth_xstorm_common.client_statistics[cli_id].multicast_pkts_sent +
            pdev->vars.stats.stats_mirror.stats_fw.eth_xstorm_common.client_statistics[cli_id].broadcast_pkts_sent;



        /* TOE Stats for Xstorm */
        arr_cnt = ARRSIZE(pdev->vars.stats.stats_mirror.stats_fw.toe_xstorm_toe.statistics) ;
        for ( i = 0; i < arr_cnt; i++)
        {
            LM_STATS_FW_ASSIGN_TOE_U32(xstorm_toe.statistics[i].tcp_out_segments) ;
            LM_STATS_FW_ASSIGN_TOE_U32(xstorm_toe.statistics[i].tcp_retransmitted_segments) ;
            LM_STATS_FW_ASSIGN_TOE_REGPAIR(xstorm_toe.statistics[i].ip_out_octets ) ;
            LM_STATS_FW_ASSIGN_TOE_U32(xstorm_toe.statistics[i].ip_out_requests) ;
        }

        if( !CHIP_IS_E1x(pdev) )
        {
            lm_stats_fw_assign_fcoe_xstorm(&pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->fcoe,
                                           &pdev->vars.stats.stats_mirror.stats_fw.fcoe);
        }

        SET_FLAGS( *ptr_stats_flags_assigned, LM_STATS_FLAG_XSTORM ) ;
    }

    // eth tstorm
    if( LM_STATS_DO_ASSIGN( stats_flags_done, *ptr_stats_flags_assigned, LM_STATS_FLAG_TSTORM ) )
    {
        // regpairs
        REGPAIR_TO_U64(pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[cli_id].rcv_unicast_bytes,
                       pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.tstorm_queue_statistics.rcv_ucast_bytes );

        REGPAIR_TO_U64(pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[cli_id].rcv_broadcast_bytes,
                       pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.tstorm_queue_statistics.rcv_bcast_bytes );

        REGPAIR_TO_U64(pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[cli_id].rcv_multicast_bytes,
                       pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.tstorm_queue_statistics.rcv_mcast_bytes );

        // FIXME REGPAIR_TO_U64(pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[cli_id].rcv_error_bytes,
        //               pdev->vars.stats.stats_collect.stats_fw.addr_eth_stats_query->tstorm_common.client_statistics[cnt_id].rcv_error_bytes );

        // eth tstorm - non regpairs
        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.tstorm_queue_statistics.checksum_discard,
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[cli_id].checksum_discard );

        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.tstorm_queue_statistics.pkts_too_big_discard,
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[cli_id].packets_too_big_discard );

        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.tstorm_queue_statistics.rcv_ucast_pkts,
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[cli_id].rcv_unicast_pkts );

        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.tstorm_queue_statistics.rcv_bcast_pkts,
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[cli_id].rcv_broadcast_pkts );

        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.tstorm_queue_statistics.rcv_mcast_pkts,
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[cli_id].rcv_multicast_pkts );

        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.tstorm_queue_statistics.no_buff_discard,
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[cli_id].no_buff_discard );

        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.tstorm_queue_statistics.ttl0_discard,
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[cli_id].ttl0_discard );



        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->port.tstorm_port_statistics.mf_tag_discard,
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[cli_id].ttl0_discard );


        /* Port Statistics */
        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->port.tstorm_port_statistics.mac_filter_discard, \
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.port_statistics.mac_filter_discard ) ;
        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->port.tstorm_port_statistics.brb_truncate_discard, \
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.port_statistics.brb_truncate_discard ) ;
        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->port.tstorm_port_statistics.mac_discard, \
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.port_statistics.mac_discard ) ;

        // toe tstorm
        arr_cnt = ARRSIZE(pdev->vars.stats.stats_mirror.stats_fw.toe_tstorm_toe.statistics) ;
        for ( i = 0; i < arr_cnt; i++)
        {
            LM_STATS_FW_ASSIGN_TOE_U32(tstorm_toe.statistics[i].ip_in_receives) ;
            LM_STATS_FW_ASSIGN_TOE_U32(tstorm_toe.statistics[i].ip_in_delivers) ;
            LM_STATS_FW_ASSIGN_TOE_REGPAIR(tstorm_toe.statistics[i].ip_in_octets) ;
            LM_STATS_FW_ASSIGN_TOE_U32(tstorm_toe.statistics[i].tcp_in_errors) ;
            LM_STATS_FW_ASSIGN_TOE_U32(tstorm_toe.statistics[i].ip_in_header_errors) ;
            LM_STATS_FW_ASSIGN_TOE_U32(tstorm_toe.statistics[i].ip_in_discards) ;
            LM_STATS_FW_ASSIGN_TOE_U32(tstorm_toe.statistics[i].ip_in_truncated_packets) ;
        }

        if( !CHIP_IS_E1x(pdev) )
        {
            lm_stats_fw_assign_fcoe_tstorm(&pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->fcoe,
                                           &pdev->vars.stats.stats_mirror.stats_fw.fcoe);
        }

        SET_FLAGS( *ptr_stats_flags_assigned, LM_STATS_FLAG_TSTORM ) ;
    }

    // eth ustorm
    if( LM_STATS_DO_ASSIGN( stats_flags_done, *ptr_stats_flags_assigned, LM_STATS_FLAG_USTORM ) )
    {
        // regpairs
        REGPAIR_TO_U64(pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[cli_id].ucast_no_buff_bytes,
                       pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.ustorm_queue_statistics.ucast_no_buff_bytes );

        REGPAIR_TO_U64(pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[cli_id].mcast_no_buff_bytes,
                       pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.ustorm_queue_statistics.mcast_no_buff_bytes );

        REGPAIR_TO_U64(pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[cli_id].bcast_no_buff_bytes,
                       pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.ustorm_queue_statistics.bcast_no_buff_bytes );

        REGPAIR_TO_U64(pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[cli_id].coalesced_bytes,
                       pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.ustorm_queue_statistics.coalesced_bytes );

        // non regpairs
        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.ustorm_queue_statistics.ucast_no_buff_pkts,
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[cli_id].ucast_no_buff_pkts );

        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.ustorm_queue_statistics.mcast_no_buff_pkts,
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[cli_id].mcast_no_buff_pkts );

        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.ustorm_queue_statistics.bcast_no_buff_pkts,
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[cli_id].bcast_no_buff_pkts );

        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.ustorm_queue_statistics.coalesced_pkts,
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[cli_id].coalesced_pkts );

        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.ustorm_queue_statistics.coalesced_events,
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[cli_id].coalesced_events );

        LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.ustorm_queue_statistics.coalesced_aborts,
                                 pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[cli_id].coalesced_aborts );

        if( !CHIP_IS_E1x(pdev) )
        {
            lm_stats_fw_assign_fcoe_ustorm(&pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->fcoe,
                                           &pdev->vars.stats.stats_mirror.stats_fw.fcoe);
        }

        SET_FLAGS( *ptr_stats_flags_assigned, LM_STATS_FLAG_USTORM ) ;
    }

    if( LM_STATS_DO_ASSIGN( stats_flags_done, *ptr_stats_flags_assigned, LM_STATS_FLAG_CSTORM ) )
    {
        // toe cstorm

        LM_STATS_FW_ASSIGN_TOE_U32(cstorm_toe.no_tx_cqes) ;
        SET_FLAGS( *ptr_stats_flags_assigned, LM_STATS_FLAG_CSTORM ) ;

    }
}

#ifdef VF_INVOLVED
void lm_pf_stats_vf_fw_assign(struct _lm_device_t *pdev, u32_t stats_flags_done, u32_t* ptr_stats_flags_assigned)
{
    lm_stats_fw_t          *mirror_stats_fw;
    struct per_queue_stats *queue_stats;
    const u8_t              cli_id = LM_CLI_IDX_NDIS ;
    u8_t                    vf_idx;

    if CHK_NULL( ptr_stats_flags_assigned )
    {
        DbgBreakIf(!ptr_stats_flags_assigned) ;
        return;
    }

    // eth xstorm
    if( LM_STATS_DO_ASSIGN( stats_flags_done, *ptr_stats_flags_assigned, LM_STATS_FLAG_XSTORM ) )
    {
        for (vf_idx = 0; vf_idx < pdev->vfs_set.number_of_enabled_vfs; vf_idx++) {
            mirror_stats_fw = pdev->vfs_set.vfs_array[vf_idx].vf_stats.mirror_stats_fw;
            queue_stats = pdev->vfs_set.vfs_array[vf_idx].vf_stats.pf_fw_stats_virt_data;
            // regpairs
            REGPAIR_TO_U64(mirror_stats_fw->eth_xstorm_common.client_statistics[cli_id].unicast_bytes_sent,
                           queue_stats->xstorm_queue_statistics.ucast_bytes_sent);
            // regpairs
            REGPAIR_TO_U64(mirror_stats_fw->eth_xstorm_common.client_statistics[cli_id].multicast_bytes_sent,
                           queue_stats->xstorm_queue_statistics.mcast_bytes_sent);

            // regpairs
            REGPAIR_TO_U64(mirror_stats_fw->eth_xstorm_common.client_statistics[cli_id].broadcast_bytes_sent,
                           queue_stats->xstorm_queue_statistics.bcast_bytes_sent);

            mirror_stats_fw->eth_xstorm_common.client_statistics[cli_id].total_sent_bytes =
                mirror_stats_fw->eth_xstorm_common.client_statistics[cli_id].unicast_bytes_sent +
                mirror_stats_fw->eth_xstorm_common.client_statistics[cli_id].multicast_bytes_sent +
                mirror_stats_fw->eth_xstorm_common.client_statistics[cli_id].broadcast_bytes_sent;

            // non regpairs
            LM_SIGN_EXTEND_VALUE_32( queue_stats->xstorm_queue_statistics.ucast_pkts_sent,
                                     mirror_stats_fw->eth_xstorm_common.client_statistics[cli_id].unicast_pkts_sent );

            LM_SIGN_EXTEND_VALUE_32( queue_stats->xstorm_queue_statistics.mcast_pkts_sent,
                                     mirror_stats_fw->eth_xstorm_common.client_statistics[cli_id].multicast_pkts_sent );

            LM_SIGN_EXTEND_VALUE_32( queue_stats->xstorm_queue_statistics.bcast_pkts_sent,
                                     mirror_stats_fw->eth_xstorm_common.client_statistics[cli_id].broadcast_pkts_sent );

            mirror_stats_fw->eth_xstorm_common.client_statistics[cli_id].total_sent_pkts =
                mirror_stats_fw->eth_xstorm_common.client_statistics[cli_id].unicast_pkts_sent+
                mirror_stats_fw->eth_xstorm_common.client_statistics[cli_id].multicast_pkts_sent +
                mirror_stats_fw->eth_xstorm_common.client_statistics[cli_id].broadcast_pkts_sent;


        }
        SET_FLAGS( *ptr_stats_flags_assigned, LM_STATS_FLAG_XSTORM ) ;
    }

    // eth tstorm
    if( LM_STATS_DO_ASSIGN( stats_flags_done, *ptr_stats_flags_assigned, LM_STATS_FLAG_TSTORM ) )
    {
        for (vf_idx = 0; vf_idx < pdev->vfs_set.number_of_enabled_vfs; vf_idx++) {
            mirror_stats_fw = pdev->vfs_set.vfs_array[vf_idx].vf_stats.mirror_stats_fw;
            queue_stats = pdev->vfs_set.vfs_array[vf_idx].vf_stats.pf_fw_stats_virt_data;
            // regpairs
            REGPAIR_TO_U64(mirror_stats_fw->eth_tstorm_common.client_statistics[cli_id].rcv_unicast_bytes,
                           queue_stats->tstorm_queue_statistics.rcv_ucast_bytes );

            REGPAIR_TO_U64(mirror_stats_fw->eth_tstorm_common.client_statistics[cli_id].rcv_broadcast_bytes,
                           queue_stats->tstorm_queue_statistics.rcv_bcast_bytes );

            REGPAIR_TO_U64(mirror_stats_fw->eth_tstorm_common.client_statistics[cli_id].rcv_multicast_bytes,
                           queue_stats->tstorm_queue_statistics.rcv_mcast_bytes );

            // FIXME REGPAIR_TO_U64(pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[cli_id].rcv_error_bytes,
            //               pdev->vars.stats.stats_collect.stats_fw.addr_eth_stats_query->tstorm_common.client_statistics[cnt_id].rcv_error_bytes );

            // eth tstorm - non regpairs
            LM_SIGN_EXTEND_VALUE_32( queue_stats->tstorm_queue_statistics.checksum_discard,
                                     mirror_stats_fw->eth_tstorm_common.client_statistics[cli_id].checksum_discard );
            LM_SIGN_EXTEND_VALUE_32( queue_stats->tstorm_queue_statistics.pkts_too_big_discard,
                                     mirror_stats_fw->eth_tstorm_common.client_statistics[cli_id].packets_too_big_discard );

            LM_SIGN_EXTEND_VALUE_32( queue_stats->tstorm_queue_statistics.rcv_ucast_pkts,
                                     mirror_stats_fw->eth_tstorm_common.client_statistics[cli_id].rcv_unicast_pkts );

            LM_SIGN_EXTEND_VALUE_32( queue_stats->tstorm_queue_statistics.rcv_bcast_pkts,
                                     mirror_stats_fw->eth_tstorm_common.client_statistics[cli_id].rcv_broadcast_pkts );

            LM_SIGN_EXTEND_VALUE_32( queue_stats->tstorm_queue_statistics.rcv_mcast_pkts,
                                     mirror_stats_fw->eth_tstorm_common.client_statistics[cli_id].rcv_multicast_pkts );
            LM_SIGN_EXTEND_VALUE_32( queue_stats->tstorm_queue_statistics.no_buff_discard,
                                     mirror_stats_fw->eth_tstorm_common.client_statistics[cli_id].no_buff_discard );
            LM_SIGN_EXTEND_VALUE_32( queue_stats->tstorm_queue_statistics.ttl0_discard,
                                     mirror_stats_fw->eth_tstorm_common.client_statistics[cli_id].ttl0_discard );

        }
        SET_FLAGS( *ptr_stats_flags_assigned, LM_STATS_FLAG_TSTORM ) ;
    }

    // eth ustorm
    if( LM_STATS_DO_ASSIGN( stats_flags_done, *ptr_stats_flags_assigned, LM_STATS_FLAG_USTORM ) )
    {
        for (vf_idx = 0; vf_idx < pdev->vfs_set.number_of_enabled_vfs; vf_idx++) {
            mirror_stats_fw = pdev->vfs_set.vfs_array[vf_idx].vf_stats.mirror_stats_fw;
            queue_stats = pdev->vfs_set.vfs_array[vf_idx].vf_stats.pf_fw_stats_virt_data;
            // regpairs
            REGPAIR_TO_U64(mirror_stats_fw->eth_ustorm_common.client_statistics[cli_id].ucast_no_buff_bytes,
                           queue_stats->ustorm_queue_statistics.ucast_no_buff_bytes );

            REGPAIR_TO_U64(mirror_stats_fw->eth_ustorm_common.client_statistics[cli_id].mcast_no_buff_bytes,
                           queue_stats->ustorm_queue_statistics.mcast_no_buff_bytes );

            REGPAIR_TO_U64(mirror_stats_fw->eth_ustorm_common.client_statistics[cli_id].bcast_no_buff_bytes,
                           queue_stats->ustorm_queue_statistics.bcast_no_buff_bytes );

            REGPAIR_TO_U64(pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[cli_id].coalesced_bytes,
                           pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.ustorm_queue_statistics.coalesced_bytes );

            // non regpairs
            LM_SIGN_EXTEND_VALUE_32( queue_stats->ustorm_queue_statistics.ucast_no_buff_pkts,
                                     mirror_stats_fw->eth_ustorm_common.client_statistics[cli_id].ucast_no_buff_pkts );

            LM_SIGN_EXTEND_VALUE_32( queue_stats->ustorm_queue_statistics.mcast_no_buff_pkts,
                                     mirror_stats_fw->eth_ustorm_common.client_statistics[cli_id].mcast_no_buff_pkts );

            LM_SIGN_EXTEND_VALUE_32( queue_stats->ustorm_queue_statistics.bcast_no_buff_pkts,
                                     mirror_stats_fw->eth_ustorm_common.client_statistics[cli_id].bcast_no_buff_pkts );

            LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.ustorm_queue_statistics.coalesced_pkts,
                                     pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[cli_id].coalesced_pkts );

            LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.ustorm_queue_statistics.coalesced_events,
                                     pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[cli_id].coalesced_events );

            LM_SIGN_EXTEND_VALUE_32( pdev->vars.stats.stats_collect.stats_fw.fw_stats_data->queue_stats.ustorm_queue_statistics.coalesced_aborts,
                                     pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[cli_id].coalesced_aborts );
        }
        SET_FLAGS( *ptr_stats_flags_assigned, LM_STATS_FLAG_USTORM ) ;
    }

    if( LM_STATS_DO_ASSIGN( stats_flags_done, *ptr_stats_flags_assigned, LM_STATS_FLAG_CSTORM ) )
    {
        SET_FLAGS( *ptr_stats_flags_assigned, LM_STATS_FLAG_CSTORM ) ;
    }

}
#endif

/**lm_stats_hw_macs_assign
 *
 * THIS FUNCTION MUST BE CALLED INSIDE PHY LOCK
 *
 * The mirrored statistics store 2 copies of the MAC stats:
 * CURRENT and TOTAL. the reason for this is that each PF has
 * it's own MAC and when a PMF change occures,  the new PMF
 * would start with all MAC stats equal to 0. in this case
 * CURRENT would be zeroed on the next collection, but TOTAL
 * would still have the old stats.
 * because of this, TOTAL is updated according to the difference
 * between the old value and the new value.
 *
 * the following function updates a field in the CURRENT block
 * and returns the value to be added to the TOTAL block
 *
 * @param bits the number of data bits in the field
 * @param field_collect_val the value collected from the HW
 * @param field_mirror_val a pointer to the relevant field in
 *                         the CURRENT block
 *
 * @return the difference between the new value and the old
 *         value - this should be added to the relevant field in
 *         the TOTAL block.
 *
 * @see stats_macs_idx_t , lm_stats_hw_t
 */
static u64_t lm_stats_hw_macs_assign(IN lm_device_t* pdev,
                                     IN u8_t bits,
                                     IN u64_t field_collect_val,
                                     IN OUT u64_t *field_mirror_val)
{
    /*MSTAT has no wraparound logic, and it's stat values are zeroed on each read.
      This means that what we read is the difference in the stats since the last read,
      so we should just update the counters and exit.
      EMAC and BMAC stats have wraparound logic and are not zeroed on read, so we handle
      the wraparound if needed and return the difference between the old value and the
      new value.*/
    if(HAS_MSTAT(pdev))
    {
        *field_mirror_val += field_collect_val;
        return field_collect_val;
    }
    else
    {
        u64_t prev = *field_mirror_val;
        *field_mirror_val = lm_update_wraparound_if_needed(bits, field_collect_val, *field_mirror_val,FALSE/*no need to swap bytes on HW stats*/) ;
        return *field_mirror_val - prev;
    }
}

#define LM_STATS_HW_MAC_ASSIGN(field_collect, field_mirror, field_width)\
    if (mac_query->field_collect != 0) { DbgMessage(pdev, INFORM, "assigning %s[=%x] to %s, width %d.\n", #field_collect, mac_query->field_collect, #field_mirror, field_width ); } \
    macs[STATS_MACS_IDX_TOTAL].field_mirror += lm_stats_hw_macs_assign( pdev, \
                                                                        field_width, \
                                                 mac_query->field_collect, \
                                                 &(macs[STATS_MACS_IDX_CURRENT].field_mirror) ) ;

#define LM_STATS_HW_MAC_ASSIGN_U32( field_collect, field_mirror ) LM_STATS_HW_MAC_ASSIGN(field_collect, field_mirror, 32)

#define LM_STATS_HW_MAC_ASSIGN_U36( field_collect, field_mirror ) LM_STATS_HW_MAC_ASSIGN(field_collect, field_mirror, 36)

#define LM_STATS_HW_MAC_ASSIGN_U42( field_collect, field_mirror ) LM_STATS_HW_MAC_ASSIGN(field_collect, field_mirror, 42)


// assign a block (emac/bmac) uXX hw collected into hw mirror + do sign extension (width is XX)
#define LM_STATS_HW_NIG_ASSIGN_UXX(bits, block_name,field_collect,field_mirror) \
                                   LM_SIGN_EXTEND_VALUE_##bits( pdev->vars.stats.stats_collect.stats_hw.addr_##block_name##_stats_query->field_collect, \
                                   pdev->vars.stats.stats_mirror.stats_hw.nig.field_mirror ) ;

#define LM_STATS_HW_NIG_ASSIGN_U32(block_name,field_collect,field_mirror) LM_STATS_HW_NIG_ASSIGN_UXX(32, block_name,field_collect,field_mirror)


/* The code below is duplicated for bmac1, bmac2 and mstat, the structure mac_query differs between them and therefore
 * needs to be done this way (to avoid duplicating the code) */
#define LM_STATS_NON_EMAC_ASSIGN_CODE(_field_width) \
{\
    /* Maps bmac_query into macs sturct */ \
    /* Spec .1-5 (N/A) */ \
    /* Spec .6 */ \
    if (!IS_MULTI_VNIC(pdev)) { \
        LM_STATS_HW_MAC_ASSIGN( stats_tx.tx_gtgca, stats_tx.tx_stat_ifhcoutucastpkts_bmac_bca, _field_width); \
        LM_STATS_HW_MAC_ASSIGN( stats_tx.tx_gtgca, stats_tx.tx_stat_ifhcoutbroadcastpkts, _field_width); \
        LM_STATS_HW_MAC_ASSIGN( stats_tx.tx_gtpkt, stats_tx.tx_stat_ifhcoutucastpkts_bmac_pkt , _field_width); \
        LM_STATS_HW_MAC_ASSIGN( stats_tx.tx_gtmca, stats_tx.tx_stat_ifhcoutucastpkts_bmac_mca , _field_width); \
        /* Spec .7 */ \
        LM_STATS_HW_MAC_ASSIGN( stats_tx.tx_gtmca, stats_tx.tx_stat_ifhcoutmulticastpkts , _field_width); \
        /* Spec .8  */ \
    } \
    /* Spec .9 */ \
    LM_STATS_HW_MAC_ASSIGN( stats_rx.rx_grfcs, stats_rx.rx_stat_dot3statsfcserrors, _field_width); \
    /* Spec .10-11 (N/A) */ \
    /* Spec .12 */ \
    /* Spec .13 */ \
    LM_STATS_HW_MAC_ASSIGN( stats_rx.rx_grovr, stats_rx.rx_stat_dot3statsframestoolong, _field_width); \
    /* Spec .14 (N/A) */ \
    /* Spec .15 */ \
    LM_STATS_HW_MAC_ASSIGN( stats_rx.rx_grxpf, stats_rx.rx_stat_xoffpauseframesreceived, _field_width); \
    /* Spec .17 */ \
    LM_STATS_HW_MAC_ASSIGN( stats_tx.tx_gtxpf, stats_tx.tx_stat_outxoffsent, _field_width); \
    /* Spec .18-21 (N/A) */ \
    /* Spec .22 */ \
    LM_STATS_HW_MAC_ASSIGN( stats_rx.rx_grxpf, stats_rx.rx_stat_maccontrolframesreceived_bmac_xpf, _field_width); \
    LM_STATS_HW_MAC_ASSIGN( stats_rx.rx_grxcf, stats_rx.rx_stat_maccontrolframesreceived_bmac_xcf, _field_width); \
    /* Spec .23-29 (N/A) */ \
    /* Spec. 30 */ \
    LM_STATS_HW_MAC_ASSIGN( stats_tx.tx_gt64, stats_tx.tx_stat_etherstatspkts64octets, _field_width); \
    /* Spec. 31 */ \
    LM_STATS_HW_MAC_ASSIGN( stats_tx.tx_gt127, stats_tx.tx_stat_etherstatspkts65octetsto127octets, _field_width); \
    /* Spec. 32 */ \
    LM_STATS_HW_MAC_ASSIGN( stats_tx.tx_gt255, stats_tx.tx_stat_etherstatspkts128octetsto255octets, _field_width); \
    /* Spec. 33 */ \
    LM_STATS_HW_MAC_ASSIGN( stats_tx.tx_gt511, stats_tx.tx_stat_etherstatspkts256octetsto511octets, _field_width); \
    /* Spec. 34 */ \
    LM_STATS_HW_MAC_ASSIGN( stats_tx.tx_gt1023, stats_tx.tx_stat_etherstatspkts512octetsto1023octets, _field_width); \
    /* Spec. 35                                                   */ \
    LM_STATS_HW_MAC_ASSIGN( stats_tx.tx_gt1518, stats_tx.tx_stat_etherstatspkts1024octetsto1522octet, _field_width); \
    /* Spec. 36 */ \
    LM_STATS_HW_MAC_ASSIGN( stats_tx.tx_gt2047,  stats_tx.tx_stat_etherstatspktsover1522octets_bmac_2047, _field_width); \
    LM_STATS_HW_MAC_ASSIGN( stats_tx.tx_gt4095,  stats_tx.tx_stat_etherstatspktsover1522octets_bmac_4095, _field_width); \
    LM_STATS_HW_MAC_ASSIGN( stats_tx.tx_gt9216,  stats_tx.tx_stat_etherstatspktsover1522octets_bmac_9216, _field_width); \
    LM_STATS_HW_MAC_ASSIGN( stats_tx.tx_gt16383, stats_tx.tx_stat_etherstatspktsover1522octets_bmac_16383, _field_width);\
    /* Spec. 38 */ \
    /* Spec. 39 */ \
    /* Spec. 40 (N/A) */ \
    /* Spec. 41 */ \
    LM_STATS_HW_MAC_ASSIGN( stats_tx.tx_gterr, stats_tx.tx_stat_dot3statsinternalmactransmiterrors, _field_width); \
    /* Spec. 42 (N/A) */ \
    /* Spec. 43 */ \
    LM_STATS_HW_MAC_ASSIGN( stats_tx.tx_gtxpf, stats_tx.tx_stat_flowcontroldone, _field_width); \
    /* Spec. 44 */ \
    LM_STATS_HW_MAC_ASSIGN( stats_rx.rx_grxpf, stats_rx.rx_stat_xoffstateentered, _field_width); \
    /* Spec. 45 */ \
    /* Spec. 46 (N/A) */ \
    /* Spec. 47 */ \
    LM_STATS_HW_MAC_ASSIGN( stats_tx.tx_gtufl, stats_tx.tx_stat_ifhcoutdiscards, _field_width); \
}

//Assign the registers that do not exist in MSTAT or have a different size and therefore can't
//be a part of LM_STATS_NON_EMAC_ASSIGN_CODE
#define LM_STATS_BMAC_ASSIGN_CODE \
{ \
    LM_STATS_HW_MAC_ASSIGN_U42( stats_rx.rx_grund, stats_rx.rx_stat_etherstatsundersizepkts ) ; \
    LM_STATS_HW_MAC_ASSIGN_U36( stats_rx.rx_grjbr, stats_rx.rx_stat_etherstatsjabbers ) ; \
    LM_STATS_HW_MAC_ASSIGN_U42( stats_rx.rx_grfrg, stats_rx.rx_stat_etherstatsfragments ) ; \
    LM_STATS_HW_MAC_ASSIGN_U42( stats_rx.rx_grerb, stats_rx.rx_stat_ifhcinbadoctets ); \
}

/* The code below is duplicated for bmac2 and mstat, the structure mac_query differs between them and therefore
 * needs to be done this way (to avoid duplicating the code) */
#define LM_STATS_BMAC2_MSTAT_ASSIGN_CODE(_field_width) \
{\
    LM_STATS_HW_MAC_ASSIGN( stats_tx.tx_gtxpp, stats_tx.tx_stat_pfcPacketCounter, _field_width); \
    /* Rx PFC Packet Counter*/ \
    LM_STATS_HW_MAC_ASSIGN( stats_rx.rx_grxpp, stats_rx.rx_stat_pfcPacketCounter, _field_width); \
}
//Assign the registers that do not exist in BMAC1/BMAC2 or have a different size and therefore
//can't be a part of LM_STATS_NON_EMAC_ASSIGN_CODE.
//Also, some fields are read from EMAC stats on devices that have an EMAC block but must be read
//from MSTAT on devices that don't have one.
#define LM_STATS_MSTAT_ASSIGN_CODE \
{ \
    LM_STATS_HW_MAC_ASSIGN( stats_rx.rx_grund, stats_rx.rx_stat_etherstatsundersizepkts, 39) ; \
    LM_STATS_HW_MAC_ASSIGN( stats_rx.rx_grfrg, stats_rx.rx_stat_etherstatsfragments, 39) ; \
    LM_STATS_HW_MAC_ASSIGN( stats_rx.rx_grerb, stats_rx.rx_stat_ifhcinbadoctets, 45); \
    if (!IS_MULTI_VNIC(pdev)) {\
        LM_STATS_HW_MAC_ASSIGN(stats_rx.rx_grbyt, stats_rx.rx_stat_ifhcinoctets, 45);\
        LM_STATS_HW_MAC_ASSIGN(stats_rx.rx_gruca, stats_rx.rx_stat_ifhcinucastpkts, 39)\
        LM_STATS_HW_MAC_ASSIGN(stats_rx.rx_grmca, stats_rx.rx_stat_ifhcinmulticastpkts, 39);\
        LM_STATS_HW_MAC_ASSIGN(stats_rx.rx_grbca, stats_rx.rx_stat_ifhcinbroadcastpkts, 39);\
        LM_STATS_HW_MAC_ASSIGN(stats_rx.rx_gr64, stats_rx.rx_stat_etherstatspkts64octets, 39);\
        LM_STATS_HW_MAC_ASSIGN(stats_rx.rx_gr127, stats_rx.rx_stat_etherstatspkts65octetsto127octets, 39);\
        LM_STATS_HW_MAC_ASSIGN(stats_rx.rx_gr255, stats_rx.rx_stat_etherstatspkts128octetsto255octets, 39);\
        LM_STATS_HW_MAC_ASSIGN(stats_rx.rx_gr511, stats_rx.rx_stat_etherstatspkts256octetsto511octets, 39);\
        LM_STATS_HW_MAC_ASSIGN(stats_rx.rx_gr1023, stats_rx.rx_stat_etherstatspkts512octetsto1023octets, 39);\
        LM_STATS_HW_MAC_ASSIGN(stats_rx.rx_gr1518, stats_rx.rx_stat_etherstatspkts1024octetsto1522octets, 39);\
        LM_STATS_HW_MAC_ASSIGN(stats_rx.rx_gr2047, stats_rx.rx_stat_etherstatspktsover1522octets, 39);\
    }\
}

/**lm_stats_hw_emac_assign
 * Copy the stats data from the BMAC1 stats values to the
 * generic struct used by the driver. This function must be
 * called after lm_stats_hw_collect that copies the data from
 * the hardware registers to the host's memory.
 *
 *
 * @param pdev the device to use.
 */
void lm_stats_hw_bmac1_assign( struct _lm_device_t *pdev)
{
    /* Macros required for macros used in this code */
    stats_macs_t *macs = &pdev->vars.stats.stats_mirror.stats_hw.macs[STATS_MACS_IDX_CURRENT];
    volatile struct _stats_bmac1_query_t *mac_query = pdev->vars.stats.stats_collect.stats_hw.u.s.addr_bmac1_stats_query;

    LM_STATS_NON_EMAC_ASSIGN_CODE(36)
    LM_STATS_BMAC_ASSIGN_CODE
}

/**lm_stats_hw_emac_assign
 * Copy the stats data from the BMAC2 stats values to the
 * generic struct used by the driver. This function must be
 * called after lm_stats_hw_collect that copies the data from
 * the hardware registers to the host's memory.
 *
 *
 * @param pdev the device to use.
 */
void lm_stats_hw_bmac2_assign( struct _lm_device_t *pdev)
{
    stats_macs_t *macs = &pdev->vars.stats.stats_mirror.stats_hw.macs[STATS_MACS_IDX_CURRENT];
    volatile struct _stats_bmac2_query_t *mac_query = pdev->vars.stats.stats_collect.stats_hw.u.s.addr_bmac2_stats_query;
    const u8_t bmac2_field_width = 36;

    DbgBreakIf(mac_query == NULL);

    LM_STATS_NON_EMAC_ASSIGN_CODE(bmac2_field_width)
    LM_STATS_BMAC2_MSTAT_ASSIGN_CODE(bmac2_field_width)
    LM_STATS_BMAC_ASSIGN_CODE
}

/**lm_stats_hw_emac_assign
 * Copy the stats data from the MSTAT stats values to the
 * generic struct used by the driver. This function must be
 * called after lm_stats_hw_collect that copies the data from
 * the hardware registers to the host's memory.
 *
 *
 * @param pdev the device to use.
 */
void lm_stats_hw_mstat_assign( lm_device_t* pdev)
{
    stats_macs_t *macs = &pdev->vars.stats.stats_mirror.stats_hw.macs[STATS_MACS_IDX_CURRENT];
    volatile struct _stats_mstat_query_t *mac_query = pdev->vars.stats.stats_collect.stats_hw.u.addr_mstat_stats_query;
    const u8_t mstat_field_width = 39;
    DbgBreakIf(mac_query == NULL);

    DbgMessage(pdev, INFORM, "lm_stats_hw_mstat_assign: mac_query=%x\n", mac_query);

    LM_STATS_NON_EMAC_ASSIGN_CODE(mstat_field_width)
    LM_STATS_BMAC2_MSTAT_ASSIGN_CODE(mstat_field_width)
    LM_STATS_MSTAT_ASSIGN_CODE
}

/**lm_stats_hw_emac_assign
 * Copy the stats data from the EMAC stats values to the generic
 * struct used by the driver. This function must be called after
 * lm_stats_hw_collect that copies the data from the hardware
 * registers to the host's memory.
 *
 *
 * @param pdev the device to use.
 */
void lm_stats_hw_emac_assign( struct _lm_device_t *pdev)
{
    stats_macs_t *macs = &pdev->vars.stats.stats_mirror.stats_hw.macs[STATS_MACS_IDX_CURRENT];
    volatile struct _stats_emac_query_t *mac_query = pdev->vars.stats.stats_collect.stats_hw.u.s.addr_emac_stats_query;

    DbgBreakIf(mac_query == NULL);

    LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_ifhcinbadoctets, stats_rx.rx_stat_ifhcinbadoctets ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_etherstatsfragments, stats_rx.rx_stat_etherstatsfragments ) ;

    if (!IS_MULTI_VNIC(pdev)) {
        LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_ifhcinoctets, stats_rx.rx_stat_ifhcinoctets );
        LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_ifhcinucastpkts, stats_rx.rx_stat_ifhcinucastpkts )
        LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_ifhcinmulticastpkts, stats_rx.rx_stat_ifhcinmulticastpkts );
        LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_ifhcinbroadcastpkts, stats_rx.rx_stat_ifhcinbroadcastpkts );
        LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_etherstatspkts64octets, stats_rx.rx_stat_etherstatspkts64octets );
        LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_etherstatspkts65octetsto127octets, stats_rx.rx_stat_etherstatspkts65octetsto127octets );
        LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_etherstatspkts128octetsto255octets, stats_rx.rx_stat_etherstatspkts128octetsto255octets );
        LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_etherstatspkts256octetsto511octets, stats_rx.rx_stat_etherstatspkts256octetsto511octets );
        LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_etherstatspkts512octetsto1023octets, stats_rx.rx_stat_etherstatspkts512octetsto1023octets);
        LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_etherstatspkts1024octetsto1522octets, stats_rx.rx_stat_etherstatspkts1024octetsto1522octets);
        LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_etherstatspktsover1522octets, stats_rx.rx_stat_etherstatspktsover1522octets);
        LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_ifhcoutoctets, stats_tx.tx_stat_ifhcoutoctets);
        LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_ifhcoutucastpkts, stats_tx.tx_stat_ifhcoutucastpkts);
        LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_ifhcoutmulticastpkts, stats_tx.tx_stat_ifhcoutmulticastpkts);
        LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_ifhcoutbroadcastpkts, stats_tx.tx_stat_ifhcoutbroadcastpkts);
    }

    LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_dot3statsfcserrors, stats_rx.rx_stat_dot3statsfcserrors ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_dot3statsalignmenterrors, stats_rx.rx_stat_dot3statsalignmenterrors ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_dot3statscarriersenseerrors, stats_rx.rx_stat_dot3statscarriersenseerrors ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_xonpauseframesreceived, stats_rx.rx_stat_xonpauseframesreceived ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_xoffpauseframesreceived, stats_rx.rx_stat_xoffpauseframesreceived ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_maccontrolframesreceived, stats_rx.rx_stat_maccontrolframesreceived ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_xoffstateentered, stats_rx.rx_stat_xoffstateentered ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_dot3statsframestoolong, stats_rx.rx_stat_dot3statsframestoolong ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_etherstatsjabbers, stats_rx.rx_stat_etherstatsjabbers ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_rx.rx_stat_etherstatsundersizepkts, stats_rx.rx_stat_etherstatsundersizepkts ) ;


    LM_STATS_HW_MAC_ASSIGN_U32(stats_rx_err.rx_stat_falsecarriererrors, stats_rx_err.rx_stat_falsecarriererrors ) ;



    LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_ifhcoutbadoctets, stats_tx.tx_stat_ifhcoutbadoctets ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_etherstatscollisions, stats_tx.tx_stat_etherstatscollisions ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_outxonsent, stats_tx.tx_stat_outxonsent ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_outxoffsent, stats_tx.tx_stat_outxoffsent ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_flowcontroldone, stats_tx.tx_stat_flowcontroldone ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_dot3statssinglecollisionframes, stats_tx.tx_stat_dot3statssinglecollisionframes ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_dot3statsmultiplecollisionframes, stats_tx.tx_stat_dot3statsmultiplecollisionframes ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_dot3statsdeferredtransmissions, stats_tx.tx_stat_dot3statsdeferredtransmissions ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_dot3statsexcessivecollisions, stats_tx.tx_stat_dot3statsexcessivecollisions ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_dot3statslatecollisions, stats_tx.tx_stat_dot3statslatecollisions ) ;


    LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_etherstatspkts64octets, stats_tx.tx_stat_etherstatspkts64octets ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_etherstatspkts65octetsto127octets, stats_tx.tx_stat_etherstatspkts65octetsto127octets ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_etherstatspkts128octetsto255octets, stats_tx.tx_stat_etherstatspkts128octetsto255octets ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_etherstatspkts256octetsto511octets, stats_tx.tx_stat_etherstatspkts256octetsto511octets ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_etherstatspkts512octetsto1023octets, stats_tx.tx_stat_etherstatspkts512octetsto1023octets ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_etherstatspkts1024octetsto1522octet, stats_tx.tx_stat_etherstatspkts1024octetsto1522octet ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_etherstatspktsover1522octets, stats_tx.tx_stat_etherstatspktsover1522octets ) ;
    LM_STATS_HW_MAC_ASSIGN_U32(stats_tx.tx_stat_dot3statsinternalmactransmiterrors, stats_tx.tx_stat_dot3statsinternalmactransmiterrors ) ;
}

void lm_stats_hw_assign( struct _lm_device_t *pdev )
{
    if(HAS_MSTAT(pdev))
    {
        DbgMessage(pdev, INFORM, "lm_stats_hw_assign: device has MSTAT block.\n");
        lm_stats_hw_mstat_assign(pdev);
    }
    else if (CHIP_IS_E2(pdev) && (pdev->vars.mac_type == MAC_TYPE_BMAC))
    {
        lm_stats_hw_bmac2_assign(pdev);
    }
    else if (pdev->vars.mac_type == MAC_TYPE_BMAC)
    {
        lm_stats_hw_bmac1_assign(pdev);
    }
    else if(pdev->vars.mac_type == MAC_TYPE_EMAC)
    {
        lm_stats_hw_emac_assign(pdev);
    }
    else
    {
        DbgBreakIf((pdev->vars.mac_type != MAC_TYPE_EMAC) && (pdev->vars.mac_type == MAC_TYPE_BMAC) && !HAS_MSTAT(pdev) );
    }

    //nig
    {
       LM_STATS_HW_NIG_ASSIGN_U32(nig, brb_discard,       brb_discard       ) ;
       if (!IS_MULTI_VNIC(pdev))
       {
           LM_STATS_HW_NIG_ASSIGN_U32(nig, brb_packet,        brb_packet        );
           LM_STATS_HW_NIG_ASSIGN_U32(nig, brb_truncate,      brb_truncate      );
           LM_STATS_HW_NIG_ASSIGN_U32(nig, flow_ctrl_discard, flow_ctrl_discard );
           LM_STATS_HW_NIG_ASSIGN_U32(nig, flow_ctrl_octets,  flow_ctrl_octets  );
           LM_STATS_HW_NIG_ASSIGN_U32(nig, flow_ctrl_packet,  flow_ctrl_packet  );
           LM_STATS_HW_NIG_ASSIGN_U32(nig, mng_discard,       mng_discard       );
           LM_STATS_HW_NIG_ASSIGN_U32(nig, mng_octet_inp,     mng_octet_inp     );
           LM_STATS_HW_NIG_ASSIGN_U32(nig, mng_octet_out,     mng_octet_out     );
           LM_STATS_HW_NIG_ASSIGN_U32(nig, mng_packet_inp,    mng_packet_inp    );
           LM_STATS_HW_NIG_ASSIGN_U32(nig, mng_packet_out,    mng_packet_out    );
           LM_STATS_HW_NIG_ASSIGN_U32(nig, pbf_octets,        pbf_octets        );
           LM_STATS_HW_NIG_ASSIGN_U32(nig, pbf_packet,        pbf_packet        );
           LM_STATS_HW_NIG_ASSIGN_U32(nig, safc_inp,          safc_inp          );
       }
       if(HAS_MSTAT(pdev))//E3 has no NIG-ex registers, so we use values from MSTAT instead.
       {
           //Note: this must occur after the other HW stats have been assigned.
           stats_macs_t* assigned_hw_stats = &pdev->vars.stats.stats_mirror.stats_hw.macs[STATS_MACS_IDX_TOTAL];
           struct _stats_nig_ex_t* nig_ex_stats = &pdev->vars.stats.stats_collect.stats_hw.nig_ex_stats_query;
           /*NIG pkt0 counts packets with sizes 1024-1522 bytes. MSTAT has an equivalent register.*/
           nig_ex_stats->egress_mac_pkt0 = assigned_hw_stats->stats_tx.tx_stat_etherstatspkts1024octetsto1522octet;
           /*NIG pkt1 counts packets of size 1523 and up. We sum the required MSTAT values to get the right result.
             Note that the field names are somewhat misleading, since they don't count sizes 1522-XXXX but [1522-2047],[2048-4095],[4096-9216],[9217-14383]
             (see MSTAT low level design document).
             */
           nig_ex_stats->egress_mac_pkt1 =  assigned_hw_stats->stats_tx.tx_stat_etherstatspktsover1522octets_bmac_2047+
                                            assigned_hw_stats->stats_tx.tx_stat_etherstatspktsover1522octets_bmac_4095+
                                            assigned_hw_stats->stats_tx.tx_stat_etherstatspktsover1522octets_bmac_9216+
                                            assigned_hw_stats->stats_tx.tx_stat_etherstatspktsover1522octets_bmac_16383;
       }
       else
       {
           LM_SIGN_EXTEND_VALUE_36( pdev->vars.stats.stats_collect.stats_hw.nig_ex_stats_query.egress_mac_pkt0, pdev->vars.stats.stats_mirror.stats_hw.nig_ex.egress_mac_pkt0 ) ;
           LM_SIGN_EXTEND_VALUE_36( pdev->vars.stats.stats_collect.stats_hw.nig_ex_stats_query.egress_mac_pkt1, pdev->vars.stats.stats_mirror.stats_hw.nig_ex.egress_mac_pkt1 ) ;
       }
    }
}

/*
 *Function Name: lm_drv_info_to_mfw_assign_eth
 *
 *Parameters:
 *
 *Description:
 *  assign drv_info eth stats from different places in the pdev to "mirror" (vars.stats.stats_mirror.stats_drv.drv_info_to_mfw.eth_stats)
 *Returns:
 *
 */
static void lm_drv_info_to_mfw_assign_eth( struct _lm_device_t *pdev )
{
    const u8_t              client_id  = LM_CLI_CID(pdev, LM_CLI_IDX_NDIS );
    eth_stats_info_t*       stats_eth  = &pdev->vars.stats.stats_mirror.stats_drv.drv_info_to_mfw.eth_stats;
    lm_client_con_params_t* cli_params = NULL;

    if( client_id >= ARRSIZE(pdev->params.l2_cli_con_params) )
    {
        DbgBreakIf( client_id >= ARRSIZE(pdev->params.l2_cli_con_params) );
        return;
    }

#define DRV_INFO_TO_MFW_NOT_SUPPORTED 0

    cli_params = &pdev->params.l2_cli_con_params[client_id];

    ASSERT_STATIC( sizeof(stats_eth->version) <= sizeof(pdev->ver_str) );

    ASSERT_STATIC( sizeof(stats_eth->mac_local) <= sizeof( pdev->params.mac_addr ) );

    mm_memcpy( stats_eth->version, pdev->ver_str, sizeof(stats_eth->version) );

    /* Locally Admin Addr.   BigEndian EIU48. Actual size is 6 bytes */
    /* Additional Programmed MAC Addr 1. 2*/

    // stats_eth->mac_local, mac_add1, mac_add2 - NO NEED to update here since they are already updated in lm_eq_handle_classification_eqe

    /* MTU Size. Note   : Negotiated MTU */
    stats_eth->mtu_size             = cli_params->mtu;

    /* LSO MaxOffloadSize. */
    stats_eth->lso_max_size         = DRV_INFO_TO_MFW_NOT_SUPPORTED; // we should acquire this from NDIS?

    /* LSO MinSegmentCount. */
    stats_eth->lso_min_seg_cnt      = DRV_INFO_TO_MFW_NOT_SUPPORTED; // we should acquire this from NDIS?

    /* Num Offloaded Connections TCP_IPv4. */
    stats_eth->ipv4_ofld_cnt        = pdev->vars.stats.stats_mirror.stats_drv.drv_toe.ipv[STATS_IP_4_IDX].currently_established;

    /* Num Offloaded Connections TCP_IPv6. */
    stats_eth->ipv6_ofld_cnt        = pdev->vars.stats.stats_mirror.stats_drv.drv_toe.ipv[STATS_IP_6_IDX].currently_established;

    /* Promiscuous Mode. non-zero true */
    stats_eth->promiscuous_mode = ( 0 != GET_FLAGS( pdev->client_info[client_id].last_set_rx_mask, LM_RX_MASK_PROMISCUOUS_MODE ) );

     /* TX Descriptors Queue Size */
    stats_eth->txq_size             = cli_params->num_tx_desc;

    /* RX Descriptors Queue Size */
    stats_eth->rxq_size             = cli_params->num_rx_desc;//= pdev->params.l2_rx_desc_cnt[LM_CLI_IDX_NDIS];

    /* TX Descriptor Queue Avg Depth. % Avg Queue Depth since last poll */
    stats_eth->txq_avg_depth        = DRV_INFO_TO_MFW_NOT_SUPPORTED;

    /* RX Descriptors Queue Avg Depth. % Avg Queue Depth since last poll */
    stats_eth->rxq_avg_depth        = DRV_INFO_TO_MFW_NOT_SUPPORTED;

    /* IOV_Offload. 0=none; 1=MultiQueue, 2=VEB 3= VEPA*/
    stats_eth->iov_offload          = DRV_INFO_TO_MFW_NOT_SUPPORTED;

    /* Num VF assigned to this PF. */
    stats_eth->vf_cnt               = 0; // Once Win8 (T7.4) should be changed!

    /* Number of NetQueue/VMQ Config'd. */
    stats_eth->netq_cnt             = mm_get_vmq_cnt(pdev);    

    /* Feature_Flags. */
    stats_eth->feature_flags        = mm_get_feature_flags(pdev);
} /* lm_drv_info_to_mfw_assign_eth */


/*
 *Function Name: lm_stats_drv_info_to_mfw_assign
 *
 *Parameters:
 *
 *Description:
 *  Upon the opcode assign relevant stats from "mirror" to physical memory in "collect"
 *  then, MFW will read this data.
 *Returns:
 *
 */
lm_status_t lm_stats_drv_info_to_mfw_assign( struct _lm_device_t *pdev, const enum drv_info_opcode drv_info_op )
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    void*        dest     = (void*)pdev->vars.stats.stats_collect.drv_info_to_mfw.addr.eth_stats; // this is a union so doesn't matter if etc/iscsi/fcoe
    void*        src      = NULL;
    u32_t        size     = 0;

    if CHK_NULL(dest)
    {
        // dest might be NULL if we got here in chip id < E3
        DbgBreakIf(!dest);
        return LM_STATUS_FAILURE;
    }

    switch(drv_info_op)
    {
    case ETH_STATS_OPCODE:
        // We gather eth stats from already known data
        lm_drv_info_to_mfw_assign_eth(pdev);

        src  = &pdev->vars.stats.stats_mirror.stats_drv.drv_info_to_mfw.eth_stats;
        size = sizeof(pdev->vars.stats.stats_mirror.stats_drv.drv_info_to_mfw.eth_stats);
        break;

    case ISCSI_STATS_OPCODE:
        // storage data is set by miniport
        src  = &pdev->vars.stats.stats_mirror.stats_drv.drv_info_to_mfw.iscsi_stats;
        size = sizeof(pdev->vars.stats.stats_mirror.stats_drv.drv_info_to_mfw.iscsi_stats);
        break;

    case FCOE_STATS_OPCODE:
        // storage data is set by miniport
        src  = &pdev->vars.stats.stats_mirror.stats_drv.drv_info_to_mfw.fcoe_stats;
        size = sizeof(pdev->vars.stats.stats_mirror.stats_drv.drv_info_to_mfw.fcoe_stats);
        break;

    default:
        lm_status = LM_STATUS_INVALID_PARAMETER;
        break;
    }

    if( LM_STATUS_SUCCESS == lm_status)
    {
        // Zero buffer
        mm_mem_zero( dest, size );

        // Copy relevant field
        mm_memcpy( dest, src, size );
    }

    return lm_status;
} /* lm_stats_drv_info_to_mfw_assign */

// resets mirror fw statistics
void lm_stats_fw_reset( struct _lm_device_t* pdev)
{
     if CHK_NULL( pdev )
     {
         DbgBreakIf(!pdev) ;
     }
     mm_memset( &pdev->vars.stats.stats_mirror.stats_fw, 0, sizeof(pdev->vars.stats.stats_mirror.stats_fw) ) ;
}

void lm_stats_get_dcb_stats( lm_device_t* pdev, lm_dcbx_stat *stats )
{
    stats->pfc_frames_sent      = (LM_STATS_HW_GET_MACS_U64( pdev, stats_tx.tx_stat_pfcPacketCounter ) );
    stats->pfc_frames_received  = (LM_STATS_HW_GET_MACS_U64( pdev, stats_rx.rx_stat_pfcPacketCounter ) );
}
void lm_stats_get_driver_stats( struct _lm_device_t* pdev, b10_driver_statistics_t *stats )
{
    stats->ver_num            = DRIVER_STATISTISTCS_VER_NUM;
    stats->tx_lso_frames      = pdev->vars.stats.stats_mirror.stats_drv.drv_eth.tx_lso_frames ;
    stats->tx_aborted         = pdev->vars.stats.stats_mirror.stats_drv.drv_eth.tx_aborted ;
    stats->tx_no_bd           = 0 ;
    stats->tx_no_desc         = 0 ;
    stats->tx_no_coalesce_buf = pdev->vars.stats.stats_mirror.stats_drv.drv_eth.tx_no_coalesce_buf ;
    stats->tx_no_map_reg      = 0 ;
    stats->rx_aborted         = pdev->vars.stats.stats_mirror.stats_drv.drv_eth.rx_aborted ;
    stats->rx_err             = 0 ;
    stats->rx_crc             = 0 ;
    stats->rx_phy_err         = 0 ;
    stats->rx_alignment       = 0;
    stats->rx_short_packet    = 0 ;
    stats->rx_giant_packet    = 0 ;
}

void lm_stats_get_l2_driver_stats( struct _lm_device_t* pdev, b10_l2_driver_statistics_t *stats )
{
    stats->ver_num            = L2_DRIVER_STATISTISTCS_VER_NUM;
    stats->RxIPv4FragCount    = pdev->vars.stats.stats_mirror.stats_drv.drv_eth.rx_ipv4_frag_count ;
    stats->RxIpCsErrorCount   = pdev->vars.stats.stats_mirror.stats_drv.drv_eth.rx_ip_cs_error_count ;
    stats->RxTcpCsErrorCount  = pdev->vars.stats.stats_mirror.stats_drv.drv_eth.rx_tcp_cs_error_count ;
    stats->RxLlcSnapCount     = pdev->vars.stats.stats_mirror.stats_drv.drv_eth.rx_llc_snap_count ;
    stats->RxPhyErrorCount    = pdev->vars.stats.stats_mirror.stats_drv.drv_eth.rx_phy_error_count ;
    stats->RxIpv6ExtCount     = pdev->vars.stats.stats_mirror.stats_drv.drv_eth.rx_ipv6_ext_count ;
    stats->TxNoL2Bd           = pdev->vars.stats.stats_mirror.stats_drv.drv_eth.tx_no_l2_bd ;
    stats->TxNoSqWqe          = pdev->vars.stats.stats_mirror.stats_drv.drv_eth.tx_no_sq_wqe ;
    stats->TxL2AssemblyBufUse = pdev->vars.stats.stats_mirror.stats_drv.drv_eth.tx_l2_assembly_buf_use ;
}
void lm_stats_get_l4_driver_stats( struct _lm_device_t* pdev, b10_l4_driver_statistics_t *stats )
{
    u8_t idx = 0 ;

    stats->ver_num                    = L4_DRIVER_STATISTISTCS_VER_NUM;

    idx = STATS_IP_4_IDX ;
    stats->CurrentlyIpv4Established   = pdev->vars.stats.stats_mirror.stats_drv.drv_toe.ipv[idx].currently_established ;
    stats->OutIpv4Resets              = pdev->vars.stats.stats_mirror.stats_drv.drv_toe.ipv[idx].out_resets ;
    stats->OutIpv4Fin                 = pdev->vars.stats.stats_mirror.stats_drv.drv_toe.ipv[idx].out_fin ;
    stats->InIpv4Reset                = pdev->vars.stats.stats_mirror.stats_drv.drv_toe.ipv[idx].in_reset ;
    stats->InIpv4Fin                  = pdev->vars.stats.stats_mirror.stats_drv.drv_toe.ipv[idx].in_fin ;

    idx = STATS_IP_6_IDX ;
    stats->CurrentlyIpv6Established   = pdev->vars.stats.stats_mirror.stats_drv.drv_toe.ipv[idx].currently_established ;
    stats->OutIpv6Resets              = pdev->vars.stats.stats_mirror.stats_drv.drv_toe.ipv[idx].out_resets ;
    stats->OutIpv6Fin                 = pdev->vars.stats.stats_mirror.stats_drv.drv_toe.ipv[idx].out_fin ;
    stats->InIpv6Reset                = pdev->vars.stats.stats_mirror.stats_drv.drv_toe.ipv[idx].in_reset ;
    stats->InIpv6Fin                  = pdev->vars.stats.stats_mirror.stats_drv.drv_toe.ipv[idx].in_fin ;

    stats->RxIndicateReturnPendingCnt = pdev->vars.stats.stats_mirror.stats_drv.drv_toe.rx_indicate_return_pending_cnt ;
    stats->RxIndicateReturnDoneCnt    = pdev->vars.stats.stats_mirror.stats_drv.drv_toe.rx_indicate_return_done_cnt ;
    stats->RxActiveGenBufCnt          = pdev->vars.stats.stats_mirror.stats_drv.drv_toe.rx_active_gen_buf_cnt ;
    stats->TxNoL4Bd                   = pdev->vars.stats.stats_mirror.stats_drv.drv_toe.tx_no_l4_bd ;
    stats->TxL4AssemblyBufUse         = pdev->vars.stats.stats_mirror.stats_drv.drv_toe.tx_l4_assembly_buf_use ;
}

void lm_stats_get_l2_chip_stats( struct _lm_device_t* pdev, void *buf, u8_t version)
{
    u32_t idx = LM_CLI_IDX_NDIS ;
    b10_l2_chip_statistics_t *stats = buf;

    stats->ver_num                                = version ;

    // TODO - change IOCTL structure to be per client

    stats->IfHCInOctets                           = pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[idx].rcv_broadcast_bytes +
                                                    pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[idx].rcv_multicast_bytes +
                                                    pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[idx].rcv_unicast_bytes ;
    stats->IfHCInBadOctets                        = (LM_STATS_HW_GET_MACS_U64( pdev, stats_rx.rx_stat_ifhcinbadoctets ) );
    stats->IfHCOutOctets                          = pdev->vars.stats.stats_mirror.stats_fw.eth_xstorm_common.client_statistics[idx].total_sent_bytes ;
    stats->IfHCOutBadOctets                       = (LM_STATS_HW_GET_MACS_U64( pdev, stats_tx.tx_stat_ifhcoutbadoctets ) );
    stats->IfHCInUcastPkts                        = (pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[idx].rcv_unicast_pkts ) ;
    stats->IfHCInMulticastPkts                    = (pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[idx].rcv_multicast_pkts ) ;
    stats->IfHCInBroadcastPkts                    = (pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[idx].rcv_broadcast_pkts ) ;
    stats->IfHCInUcastOctets                      = (pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[idx].rcv_unicast_bytes ) ;
    stats->IfHCInMulticastOctets                  = (pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[idx].rcv_multicast_bytes ) ;
    stats->IfHCInBroadcastOctets                  = (pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[idx].rcv_broadcast_bytes ) ;

    stats->IfHCOutUcastOctets                     = (pdev->vars.stats.stats_mirror.stats_fw.eth_xstorm_common.client_statistics[idx].unicast_bytes_sent ) ;
    stats->IfHCOutMulticastOctets                 = (pdev->vars.stats.stats_mirror.stats_fw.eth_xstorm_common.client_statistics[idx].multicast_bytes_sent ) ;
    stats->IfHCOutBroadcastOctets                 = (pdev->vars.stats.stats_mirror.stats_fw.eth_xstorm_common.client_statistics[idx].broadcast_bytes_sent ) ;
    stats->IfHCOutPkts                            = (pdev->vars.stats.stats_mirror.stats_fw.eth_xstorm_common.client_statistics[idx].total_sent_pkts ) ;


    lm_get_stats( pdev,  LM_STATS_UNICAST_FRAMES_XMIT, &stats->IfHCOutUcastPkts
#ifdef VF_INVOLVED
                  ,NULL
#endif
    ) ;
    lm_get_stats( pdev,  LM_STATS_MULTICAST_FRAMES_XMIT, &stats->IfHCOutMulticastPkts
#ifdef VF_INVOLVED
                  ,NULL
#endif
    ) ;
    lm_get_stats( pdev,  LM_STATS_BROADCAST_FRAMES_XMIT, &stats->IfHCOutBroadcastPkts
#ifdef VF_INVOLVED
                  ,NULL
#endif
     ) ;

    stats->IfHCInPkts                             = pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[idx].rcv_broadcast_pkts +
                                                    pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[idx].rcv_multicast_pkts +
                                                    pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[idx].rcv_unicast_pkts ;

    stats->IfHCOutDiscards                        = (LM_STATS_HW_GET_MACS_U64( pdev, stats_tx.tx_stat_ifhcoutdiscards ) );
    stats->IfHCInFalseCarrierErrors               = (LM_STATS_HW_GET_MACS_U64( pdev, stats_rx_err.rx_stat_falsecarriererrors ) );

    stats->Dot3StatsInternalMacTransmitErrors     = (LM_STATS_HW_GET_MACS_U64( pdev, stats_tx.tx_stat_dot3statsinternalmactransmiterrors )) ;
    stats->Dot3StatsCarrierSenseErrors            = (LM_STATS_HW_GET_MACS_U64( pdev, stats_rx.rx_stat_dot3statscarriersenseerrors )) ;
    stats->Dot3StatsFCSErrors                     = (LM_STATS_HW_GET_MACS_U64( pdev, stats_rx.rx_stat_dot3statsfcserrors )) ;
    stats->Dot3StatsAlignmentErrors               = (LM_STATS_HW_GET_MACS_U64( pdev, stats_rx.rx_stat_dot3statsalignmenterrors )) ;
    stats->Dot3StatsSingleCollisionFrames         = (LM_STATS_HW_GET_MACS_U64( pdev, stats_tx.tx_stat_dot3statssinglecollisionframes )) ;
    stats->Dot3StatsMultipleCollisionFrames       = (LM_STATS_HW_GET_MACS_U64( pdev, stats_tx.tx_stat_dot3statsmultiplecollisionframes )) ;
    stats->Dot3StatsDeferredTransmissions         = (LM_STATS_HW_GET_MACS_U64( pdev, stats_tx.tx_stat_dot3statsdeferredtransmissions )) ;
    stats->Dot3StatsExcessiveCollisions           = (LM_STATS_HW_GET_MACS_U64( pdev, stats_tx.tx_stat_dot3statsexcessivecollisions )) ;
    stats->Dot3StatsLateCollisions                = (LM_STATS_HW_GET_MACS_U64( pdev, stats_tx.tx_stat_dot3statslatecollisions )) ;
    stats->EtherStatsCollisions                   = (LM_STATS_HW_GET_MACS_U64( pdev, stats_tx.tx_stat_etherstatscollisions )) ;
    stats->EtherStatsFragments                    = (LM_STATS_HW_GET_MACS_U64( pdev, stats_rx.rx_stat_etherstatsfragments )) ;
    stats->EtherStatsJabbers                      = (LM_STATS_HW_GET_MACS_U64( pdev, stats_rx.rx_stat_etherstatsjabbers )) ;


    stats->EtherStatsUndersizePkts                = (LM_STATS_HW_GET_MACS_U64( pdev, stats_rx.rx_stat_etherstatsundersizepkts )) ;
    stats->EtherStatsOverrsizePkts                = (LM_STATS_HW_GET_MACS_U64( pdev, stats_rx.rx_stat_dot3statsframestoolong )) ;

    stats->EtherStatsPktsTx64Octets               = (LM_STATS_HW_GET_MACS_U64( pdev, stats_tx.tx_stat_etherstatspkts64octets )) ;
    stats->EtherStatsPktsTx65Octetsto127Octets    = (LM_STATS_HW_GET_MACS_U64( pdev, stats_tx.tx_stat_etherstatspkts65octetsto127octets )) ;
    stats->EtherStatsPktsTx128Octetsto255Octets   = (LM_STATS_HW_GET_MACS_U64( pdev, stats_tx.tx_stat_etherstatspkts128octetsto255octets )) ;
    stats->EtherStatsPktsTx256Octetsto511Octets   = (LM_STATS_HW_GET_MACS_U64( pdev, stats_tx.tx_stat_etherstatspkts256octetsto511octets )) ;
    stats->EtherStatsPktsTx512Octetsto1023Octets  = (LM_STATS_HW_GET_MACS_U64( pdev, stats_tx.tx_stat_etherstatspkts512octetsto1023octets)) ;
    stats->EtherStatsPktsTx1024Octetsto1522Octets = (pdev->vars.stats.stats_mirror.stats_hw.nig_ex.egress_mac_pkt0) ;
    stats->EtherStatsPktsTxOver1522Octets         = (pdev->vars.stats.stats_mirror.stats_hw.nig_ex.egress_mac_pkt1) ;

    stats->XonPauseFramesReceived                 = (LM_STATS_HW_GET_MACS_U64( pdev, stats_rx.rx_stat_xonpauseframesreceived )) ;
    stats->XoffPauseFramesReceived                = (LM_STATS_HW_GET_MACS_U64( pdev, stats_rx.rx_stat_xoffpauseframesreceived )) ;
    stats->OutXonSent                             = (LM_STATS_HW_GET_MACS_U64( pdev, stats_tx.tx_stat_outxonsent )) ;

    stats->OutXoffSent                            = (LM_STATS_HW_GET_MACS_U64( pdev, stats_tx.tx_stat_outxoffsent )) ;

    stats->FlowControlDone                        = (LM_STATS_HW_GET_MACS_U64( pdev, stats_tx.tx_stat_flowcontroldone )) ;

    stats->MacControlFramesReceived               = (LM_STATS_HW_GET_MACS_U64( pdev, stats_rx.rx_stat_maccontrolframesreceived )) ;
    stats->MacControlFramesReceived              += (LM_STATS_HW_GET_MACS_U64( pdev, stats_rx.rx_stat_maccontrolframesreceived_bmac_xcf )) ;

    stats->XoffStateEntered                       = (LM_STATS_HW_GET_MACS_U64( pdev, stats_rx.rx_stat_xoffstateentered )) ;
    lm_get_stats( pdev, LM_STATS_ERRORED_RECEIVE_CNT, &stats->IfInErrors
#ifdef VF_INVOLVED
                  ,NULL
#endif
    ) ;
    // TBD - IfInErrorsOctets - naming and support
    stats->IfInErrorsOctets                       = 0;

    stats->IfInNoBrbBuffer                        = (pdev->vars.stats.stats_mirror.stats_hw.nig.brb_discard) ;
    stats->IfInFramesL2FilterDiscards             = (pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.port_statistics.mac_filter_discard) ;
    stats->IfInTTL0Discards                       = (pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[idx].ttl0_discard) ;
    stats->IfInxxOverflowDiscards                 = (pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.port_statistics.xxoverflow_discard) ;

    stats->IfInMBUFDiscards                       = (pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[idx].no_buff_discard );
    stats->IfInMBUFDiscards                      += (pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[idx].ucast_no_buff_pkts );
    stats->IfInMBUFDiscards                      += (pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[idx].mcast_no_buff_pkts );
    stats->IfInMBUFDiscards                      += (pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[idx].bcast_no_buff_pkts );

    stats->Nig_brb_packet                         = (pdev->vars.stats.stats_mirror.stats_hw.nig.brb_packet) ;
    stats->Nig_brb_truncate                       = (pdev->vars.stats.stats_mirror.stats_hw.nig.brb_truncate) ;
    stats->Nig_flow_ctrl_discard                  = (pdev->vars.stats.stats_mirror.stats_hw.nig.flow_ctrl_discard) ;
    stats->Nig_flow_ctrl_octets                   = (pdev->vars.stats.stats_mirror.stats_hw.nig.flow_ctrl_octets) ;
    stats->Nig_flow_ctrl_packet                   = (pdev->vars.stats.stats_mirror.stats_hw.nig.flow_ctrl_packet) ;
    stats->Nig_mng_discard                        = (pdev->vars.stats.stats_mirror.stats_hw.nig.mng_discard) ;
    stats->Nig_mng_octet_inp                      = (pdev->vars.stats.stats_mirror.stats_hw.nig.mng_octet_inp) ;
    stats->Nig_mng_octet_out                      = (pdev->vars.stats.stats_mirror.stats_hw.nig.mng_octet_out) ;
    stats->Nig_mng_packet_inp                     = (pdev->vars.stats.stats_mirror.stats_hw.nig.mng_packet_inp) ;
    stats->Nig_mng_packet_out                     = (pdev->vars.stats.stats_mirror.stats_hw.nig.mng_packet_out) ;
    stats->Nig_pbf_octets                         = (pdev->vars.stats.stats_mirror.stats_hw.nig.pbf_octets) ;
    stats->Nig_pbf_packet                         = (pdev->vars.stats.stats_mirror.stats_hw.nig.pbf_packet) ;
    stats->Nig_safc_inp                           = (pdev->vars.stats.stats_mirror.stats_hw.nig.safc_inp) ;

    if (version > L2_CHIP_STATISTICS_VER_NUM_1)
    {
        /* v2 statistics */

        b10_l2_chip_statistics_v2_t *stats_v2 = buf;

        stats_v2->v2.Tx_lpi_count                 = pdev->vars.stats.stats_mirror.stats_hw.misc.tx_lpi_count;
    }

    if (version > L2_CHIP_STATISTICS_VER_NUM_2)
    {
        b10_l2_chip_statistics_v3_t *stats_v3 = buf;
        stats_v3->v3.coalesced_pkts = pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[idx].coalesced_pkts;
        stats_v3->v3.coalesced_bytes = pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[idx].coalesced_bytes;
        stats_v3->v3.coalesced_events = pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[idx].coalesced_events;
        stats_v3->v3.coalesced_aborts = pdev->vars.stats.stats_mirror.stats_fw.eth_ustorm_common.client_statistics[idx].coalesced_aborts;
    }
}

void lm_stats_get_l4_chip_stats( struct _lm_device_t* pdev, b10_l4_chip_statistics_t *stats )
{
    u8_t idx = 0 ;

    stats->ver_num                     = L4_CHIP_STATISTISTCS_VER_NUM ;

    stats->NoTxCqes                    = pdev->vars.stats.stats_mirror.stats_fw.toe_cstorm_toe.no_tx_cqes ;

    // IP4
    idx = STATS_IP_4_IDX ;

    stats->InTCP4Segments              = pdev->vars.stats.stats_mirror.stats_fw.toe_tstorm_toe.statistics[idx].ip_in_receives ;
    stats->OutTCP4Segments             = pdev->vars.stats.stats_mirror.stats_fw.toe_xstorm_toe.statistics[idx].tcp_out_segments ;
    stats->RetransmittedTCP4Segments   = pdev->vars.stats.stats_mirror.stats_fw.toe_xstorm_toe.statistics[idx].tcp_retransmitted_segments ;
    stats->InTCP4Errors                = pdev->vars.stats.stats_mirror.stats_fw.toe_tstorm_toe.statistics[idx].tcp_in_errors ;
    stats->InIP4Receives               = pdev->vars.stats.stats_mirror.stats_fw.toe_tstorm_toe.statistics[idx].ip_in_receives ;
    stats->InIP4HeaderErrors           = pdev->vars.stats.stats_mirror.stats_fw.toe_tstorm_toe.statistics[idx].ip_in_header_errors ;
    stats->InIP4Discards               = pdev->vars.stats.stats_mirror.stats_fw.toe_tstorm_toe.statistics[idx].ip_in_discards ;
    stats->InIP4Delivers               = pdev->vars.stats.stats_mirror.stats_fw.toe_tstorm_toe.statistics[idx].ip_in_delivers ;
    stats->InIP4Octets                 = pdev->vars.stats.stats_mirror.stats_fw.toe_tstorm_toe.statistics[idx].ip_in_octets ;
    stats->OutIP4Octets                = pdev->vars.stats.stats_mirror.stats_fw.toe_xstorm_toe.statistics[idx].ip_out_octets ;
    stats->InIP4TruncatedPackets       = pdev->vars.stats.stats_mirror.stats_fw.toe_tstorm_toe.statistics[idx].ip_in_truncated_packets ;

    // IP6
    idx = STATS_IP_6_IDX ;

    stats->InTCP6Segments              = pdev->vars.stats.stats_mirror.stats_fw.toe_tstorm_toe.statistics[idx].ip_in_receives ;
    stats->OutTCP6Segments             = pdev->vars.stats.stats_mirror.stats_fw.toe_xstorm_toe.statistics[idx].tcp_out_segments ;
    stats->RetransmittedTCP6Segments   = pdev->vars.stats.stats_mirror.stats_fw.toe_xstorm_toe.statistics[idx].tcp_retransmitted_segments ;
    stats->InTCP6Errors                = pdev->vars.stats.stats_mirror.stats_fw.toe_tstorm_toe.statistics[idx].tcp_in_errors ;
    stats->InIP6Receives               = pdev->vars.stats.stats_mirror.stats_fw.toe_tstorm_toe.statistics[idx].ip_in_receives ;
    stats->InIP6HeaderErrors           = pdev->vars.stats.stats_mirror.stats_fw.toe_tstorm_toe.statistics[idx].ip_in_header_errors ;
    stats->InIP6Discards               = pdev->vars.stats.stats_mirror.stats_fw.toe_tstorm_toe.statistics[idx].ip_in_discards ;
    stats->InIP6Delivers               = pdev->vars.stats.stats_mirror.stats_fw.toe_tstorm_toe.statistics[idx].ip_in_delivers ;
    stats->InIP6Octets                 = pdev->vars.stats.stats_mirror.stats_fw.toe_tstorm_toe.statistics[idx].ip_in_octets ;
    stats->OutIP6Octets                = pdev->vars.stats.stats_mirror.stats_fw.toe_xstorm_toe.statistics[idx].ip_out_octets ;
    stats->InIP6TruncatedPackets       = pdev->vars.stats.stats_mirror.stats_fw.toe_tstorm_toe.statistics[idx].ip_in_truncated_packets ;
}

void lm_stats_hw_config_stats( struct _lm_device_t* pdev, u8_t b_enabled )
{
    DbgMessage(pdev, WARNstat, "lm_stats_hw_config_stats: b_collect_enabled %s-->%s\n",
                pdev->vars.stats.stats_collect.stats_hw.b_collect_enabled ? "TRUE":"FALSE",
                b_enabled ? "TRUE":"FALSE" );

    if (IS_PFDEV(pdev)) {
    pdev->vars.stats.stats_collect.stats_hw.b_collect_enabled = b_enabled ;
    }
}

void lm_stats_fw_config_stats( struct _lm_device_t* pdev, u8_t b_enabled )
{
    DbgMessage(pdev, VERBOSEstat, "lm_stats_fw_config_stats: b_collect_enabled %s-->%s\n",
            pdev->vars.stats.stats_collect.stats_fw.b_collect_enabled ? "TRUE":"FALSE",
            b_enabled ? "TRUE":"FALSE" );
    if (IS_PFDEV(pdev) || IS_CHANNEL_VFDEV(pdev)) {
        pdev->vars.stats.stats_collect.stats_fw.b_collect_enabled = b_enabled ;
    }
}

/*
 *------------------------------------------------------------------------
 * lm_stats_mgmt_assign_func
 *
 * assign values from different 'mirror' structures into host_func_stats_t structure
 * that will be sent later to mgmt
 * NOTE: function must be called under PHY_LOCK (since it uses REG_WR_DMAE interface)
 *------------------------------------------------------------------------
 */
STATIC void lm_stats_mgmt_assign_func( IN struct _lm_device_t* pdev )
{
    u64_t              val           = 0 ;
    u64_t              val_base      = 0 ;
    lm_status_t        lm_status     = LM_STATUS_SUCCESS ;
    lm_stats_t         stats_type    = 0 ;
    host_func_stats_t* mcp_func      = NULL ;
    host_func_stats_t* mcp_func_base = NULL ;

    if CHK_NULL(pdev)
    {
        return;
    }

    if ( GET_FLAGS(pdev->params.test_mode, TEST_MODE_NO_MCP ) )
    {
        return;
    }

    mcp_func      = &pdev->vars.stats.stats_mirror.stats_mcp_func ;
    mcp_func_base = &pdev->vars.stats.stats_mirror.stats_mcp_func_base ;

    stats_type = LM_STATS_BYTES_RCV ;
    lm_status = lm_get_stats( pdev, stats_type, &val
#ifdef VF_INVOLVED
                  ,NULL
#endif
    ) ;
    if ERR_IF( LM_STATUS_SUCCESS != lm_status )
    {
        DbgMessage(pdev, WARNstat, "lm_stats_mcp_assign: lm_get_stats type=0x%X failed. lm_status=0x%X", stats_type, lm_status ) ;
    }
    else
    {
        // calculate 'total' rcv (total+discards)
        val += (pdev->vars.stats.stats_mirror.stats_fw.eth_tstorm_common.client_statistics[LM_CLI_IDX_NDIS].rcv_error_bytes) ;

        val+= LM_STATS_HI_LO_TO_64(mcp_func_base->total_bytes_received, val_base);
        mcp_func->total_bytes_received_hi                = (u32_t)U64_HI( val ) ;
        mcp_func->total_bytes_received_lo                = (u32_t)U64_LO( val ) ;
    }

    stats_type = LM_STATS_BYTES_XMIT ;
    lm_status  = lm_get_stats( pdev, stats_type, &val
#ifdef VF_INVOLVED
                  ,NULL
#endif
    ) ;
    if ERR_IF( LM_STATUS_SUCCESS != lm_status )
    {
        DbgMessage(pdev, WARNstat, "lm_stats_mcp_assign: lm_get_stats type=0x%X failed. lm_status=0x%X", stats_type, lm_status ) ;
    }
    else
    {
        val+= LM_STATS_HI_LO_TO_64(mcp_func_base->total_bytes_transmitted, val_base);
        mcp_func->total_bytes_transmitted_hi             = (u32_t)U64_HI( val ) ;
        mcp_func->total_bytes_transmitted_lo             = (u32_t)U64_LO( val ) ;
    }

    stats_type = LM_STATS_UNICAST_FRAMES_RCV ;
    lm_status  = lm_get_stats( pdev, stats_type, &val
#ifdef VF_INVOLVED
                  ,NULL
#endif
    ) ;
    if ERR_IF( LM_STATUS_SUCCESS != lm_status )
    {
        DbgMessage(pdev, WARNstat, "lm_stats_mcp_assign: lm_get_stats type=0x%X failed. lm_status=0x%X", stats_type, lm_status ) ;
    }
    else
    {
        val+= LM_STATS_HI_LO_TO_64(mcp_func_base->total_unicast_packets_received, val_base);
        mcp_func->total_unicast_packets_received_hi      = (u32_t)U64_HI( val ) ;
        mcp_func->total_unicast_packets_received_lo      = (u32_t)U64_LO( val ) ;
    }

    stats_type = LM_STATS_MULTICAST_FRAMES_RCV ;
    lm_status  = lm_get_stats( pdev, stats_type, &val
#ifdef VF_INVOLVED
                  ,NULL
#endif
    ) ;
    if ERR_IF( LM_STATUS_SUCCESS != lm_status )
    {
        DbgMessage(pdev, WARNstat, "lm_stats_mcp_assign: lm_get_stats type=0x%X failed. lm_status=0x%X", stats_type, lm_status ) ;
    }
    else
    {
        val+= LM_STATS_HI_LO_TO_64(mcp_func_base->total_multicast_packets_received, val_base);
        mcp_func->total_multicast_packets_received_hi    = (u32_t)U64_HI( val ) ;
        mcp_func->total_multicast_packets_received_lo    = (u32_t)U64_LO( val ) ;
    }

    stats_type = LM_STATS_BROADCAST_FRAMES_RCV ;
    lm_status = lm_get_stats( pdev, stats_type, &val
#ifdef VF_INVOLVED
                  ,NULL
#endif
    ) ;
    if ERR_IF( LM_STATUS_SUCCESS != lm_status )
    {
        DbgMessage(pdev, WARNstat, "lm_stats_mcp_assign: lm_get_stats type=0x%X failed. lm_status=0x%X", stats_type, lm_status ) ;
    }
    else
    {
        val+= LM_STATS_HI_LO_TO_64(mcp_func_base->total_broadcast_packets_received, val_base);
        mcp_func->total_broadcast_packets_received_hi    = (u32_t)U64_HI( val ) ;
        mcp_func->total_broadcast_packets_received_lo    = (u32_t)U64_LO( val ) ;
    }

    stats_type = LM_STATS_UNICAST_FRAMES_XMIT ;
    lm_status  = lm_get_stats( pdev, stats_type, &val
#ifdef VF_INVOLVED
                  ,NULL
#endif
    ) ;
    if ERR_IF( LM_STATUS_SUCCESS != lm_status )
    {
        DbgMessage(pdev, WARNstat, "lm_stats_mcp_assign: lm_get_stats type=0x%X failed. lm_status=0x%X", stats_type, lm_status ) ;
    }
    else
    {
        val+= LM_STATS_HI_LO_TO_64(mcp_func_base->total_unicast_packets_transmitted, val_base);
        mcp_func->total_unicast_packets_transmitted_hi   = (u32_t)U64_HI( val ) ;
        mcp_func->total_unicast_packets_transmitted_lo   = (u32_t)U64_LO( val ) ;
    }

    stats_type = LM_STATS_MULTICAST_FRAMES_XMIT ;
    lm_status  = lm_get_stats( pdev, stats_type, &val
#ifdef VF_INVOLVED
                  ,NULL
#endif
    ) ;
    if ERR_IF( LM_STATUS_SUCCESS != lm_status )
    {
        DbgMessage(pdev, WARNstat, "lm_stats_mcp_assign: lm_get_stats type=0x%X failed. lm_status=0x%X", stats_type, lm_status ) ;
    }
    else
    {
        val+= LM_STATS_HI_LO_TO_64(mcp_func_base->total_multicast_packets_transmitted, val_base);
        mcp_func->total_multicast_packets_transmitted_hi = (u32_t)U64_HI( val ) ;
        mcp_func->total_multicast_packets_transmitted_lo = (u32_t)U64_LO( val ) ;
    }

    stats_type = LM_STATS_BROADCAST_FRAMES_XMIT ;
    lm_status  = lm_get_stats( pdev, stats_type, &val
#ifdef VF_INVOLVED
                  ,NULL
#endif
    ) ;
    if ERR_IF( LM_STATUS_SUCCESS != lm_status )
    {
        DbgMessage(pdev, WARNstat, "lm_stats_mcp_assign: lm_get_stats type=0x%X failed. lm_status=0x%X", stats_type, lm_status ) ;
    }
    else
    {
        val+= LM_STATS_HI_LO_TO_64(mcp_func_base->total_broadcast_packets_transmitted, val_base);
        mcp_func->total_broadcast_packets_transmitted_hi = (u32_t)U64_HI( val ) ;
        mcp_func->total_broadcast_packets_transmitted_lo = (u32_t)U64_LO( val ) ;
    }

    // Calculate the size to be written through DMAE
    val = sizeof(pdev->vars.stats.stats_mirror.stats_mcp_func) ;
    val = val/sizeof(u32_t) ;
    mcp_func->host_func_stats_end = ++mcp_func->host_func_stats_start ;

    // This code section must be under phy lock!
    REG_WR_DMAE_LEN(pdev,
                    pdev->vars.fw_func_stats_ptr,
                    mcp_func,
                    (u16_t)val ) ;

} // lm_stats_mgmt_assign

/*
 *------------------------------------------------------------------------
 * lm_stats_mgmt_read_base -
 *
 * read values from mgmt structures into host_func_stats_t base structure
 * this is as a basic value that will be added when function report statistics
 * NOTE: function must be called under PHY_LOCK (since it uses REG_RD_DMAE interface)
 *------------------------------------------------------------------------
 */
static void lm_stats_mgmt_read_func_base( IN struct _lm_device_t* pdev )
{
    u64_t              val           = 0 ;
    host_func_stats_t* mcp_func_base = NULL ;

    if CHK_NULL(pdev)
    {
        return;
    }

    if( 0 == pdev->vars.fw_func_stats_ptr )
    {
        return;
    }

    if (GET_FLAGS(pdev->params.test_mode, TEST_MODE_NO_MCP ))
    {
        return;
    }

    mcp_func_base = &pdev->vars.stats.stats_mirror.stats_mcp_func_base ;

    val = sizeof(pdev->vars.stats.stats_mirror.stats_mcp_func_base) ;
    val = val/sizeof(u32_t) ;

    // This code section must be under phy lock!
    REG_RD_DMAE_LEN(pdev,
                    pdev->vars.fw_func_stats_ptr,
                    mcp_func_base,
                    (u16_t)val ) ;

} // lm_stats_mgmt_read_base


/*
 *------------------------------------------------------------------------
 * lm_stats_mgmt_clear_all_func -
 *
 * clear mgmt statistics for all function
 * should be called on init port part. first function should clear all other functions mail box
 * NOTE: function must be called under PHY_LOCK (since it uses REG_WR_DMAE interface)
 *------------------------------------------------------------------------
 */
static void lm_stats_mgmt_clear_all_func( IN struct _lm_device_t* pdev )
{
    u64_t              val               = 0 ;
    u8_t               func              = 0;
    u32_t              fw_func_stats_ptr = 0;

    // use current pdev stats_mcp_func for all function - (zeroed buffer)
    val = sizeof(pdev->vars.stats.stats_mirror.stats_mcp_func);
    mm_mem_zero(&pdev->vars.stats.stats_mirror.stats_mcp_func, (u32_t)val );

    val = val/sizeof(u32_t) ;

    LM_FOREACH_FUNC_MAILBOX_IN_PORT(pdev,func)
    {
        lm_setup_read_mgmt_stats_ptr(pdev, func, NULL, &fw_func_stats_ptr );

        if( 0 != fw_func_stats_ptr )
        {

            // This code section must be under phy lock!
            // writes zero
            REG_WR_DMAE_LEN(pdev,
                            fw_func_stats_ptr,
                            &pdev->vars.stats.stats_mirror.stats_mcp_func,
                            (u16_t)val ) ;
        }
        if(CHIP_IS_E1(pdev) || (!CHIP_IS_E1x(pdev) && (CHIP_PORT_MODE(pdev) == LM_CHIP_PORT_MODE_4)))
        {
            // only one iteration functionand one  for E1 !
            break;
        }
    }
} // lm_stats_mgmt_clear_all_func

/*
 *Function Name:lm_stats_port_to_from
 *
 *Parameters:
 *  b_is_to - determine is it operation to/from MCP
 *  b_is_to TRUE  - to MCP
 *  b_is_to FLASE - from MCP
 *Description:
 *  Helper function in order to set stats to/from mcp to driver host when swithcing PMF's
 *
 *Returns:
 *
 */
void lm_stats_port_to_from( IN OUT struct _lm_device_t* pdev, u8_t b_is_to )
{
    host_port_stats_t* mcp_port        = NULL ;
    lm_stats_hw_t*    stats_hw         = NULL ;
    stats_macs_idx_t  stats_macs_idx   = STATS_MACS_IDX_MAX ;
    u8_t              i                = 0 ;

    mcp_port = &pdev->vars.stats.stats_mirror.stats_mcp_port ;
    stats_hw = &pdev->vars.stats.stats_mirror.stats_hw ;

    ASSERT_STATIC( STATS_MACS_IDX_MAX == MAC_STX_IDX_MAX );
    ASSERT_STATIC( STATS_MACS_IDX_CURRENT < STATS_MACS_IDX_TOTAL );


    // B/EMAC is up:
    //   OLD PMF:
    //   copy all EMAC 'reset' to 'total'
    //
    //   NEW PMF:
    //   copy all EMAC 'total' to 'reset'
    //
    // NONE is up:
    //   copy only 'reset' to 'total'

    switch( pdev->vars.mac_type )
    {
    case MAC_TYPE_EMAC:
    case MAC_TYPE_BMAC:
    case MAC_TYPE_UMAC:
    case MAC_TYPE_XMAC:
        stats_macs_idx  = STATS_MACS_IDX_CURRENT ;
        break;

    case MAC_TYPE_NONE:
        stats_macs_idx  = STATS_MACS_IDX_TOTAL ;
        break;

    default:
        DbgBreakMsg( "mac_type not acceptable" ) ;
        return;
    }

#define LM_STATS_PMF_TO_FROM( _mcp_field, _hw_field, _b_is_to ) \
                             if( _b_is_to )\
                             {             \
                                LM_STATS_64_TO_HI_LO( stats_hw->macs[i]._hw_field, mcp_port->mac_stx[i]._mcp_field );\
                             }             \
                             else          \
                             {             \
                                 LM_STATS_HI_LO_TO_64( mcp_port->mac_stx[i]._mcp_field, stats_hw->macs[i]._hw_field ) ;\
                             }


    for( i = stats_macs_idx; i < STATS_MACS_IDX_MAX; i++ )
    {
       LM_STATS_PMF_TO_FROM( rx_stat_dot3statsfcserrors,                   stats_rx.rx_stat_dot3statsfcserrors,                   b_is_to ) ;
       LM_STATS_PMF_TO_FROM( rx_stat_dot3statsalignmenterrors,             stats_rx.rx_stat_dot3statsalignmenterrors,             b_is_to ) ; // BMAC 0
       LM_STATS_PMF_TO_FROM( rx_stat_dot3statscarriersenseerrors,          stats_rx.rx_stat_dot3statscarriersenseerrors,          b_is_to ) ; // BMAC 0
       LM_STATS_PMF_TO_FROM( rx_stat_etherstatsundersizepkts,              stats_rx.rx_stat_etherstatsundersizepkts,              b_is_to ) ;

       // Exception - don't migrate this parameter (mandatory NDIS parameter)
       //LM_STATS_PMF_TO_FROM( rx_stat_dot3statsframestoolong,               stats_rx.rx_stat_dot3statsframestoolong,             b_is_to ) ;

       LM_STATS_PMF_TO_FROM( rx_stat_xonpauseframesreceived,               stats_rx.rx_stat_xonpauseframesreceived,               b_is_to ) ; // BMAC 0
       LM_STATS_PMF_TO_FROM( rx_stat_xoffpauseframesreceived,              stats_rx.rx_stat_xoffpauseframesreceived,              b_is_to ) ;
       LM_STATS_PMF_TO_FROM( tx_stat_outxonsent,                           stats_tx.tx_stat_outxonsent,                           b_is_to ) ; // BMAC 0
       LM_STATS_PMF_TO_FROM( tx_stat_outxoffsent,                          stats_tx.tx_stat_outxoffsent,                          b_is_to ) ;
       LM_STATS_PMF_TO_FROM( tx_stat_dot3statssinglecollisionframes,       stats_tx.tx_stat_dot3statssinglecollisionframes,       b_is_to ) ; // BMAC 0
       LM_STATS_PMF_TO_FROM( tx_stat_dot3statsmultiplecollisionframes,     stats_tx.tx_stat_dot3statsmultiplecollisionframes,     b_is_to ) ; // BMAC 0
       LM_STATS_PMF_TO_FROM( tx_stat_dot3statslatecollisions,              stats_tx.tx_stat_dot3statslatecollisions,              b_is_to ) ; // BMAC 0
       LM_STATS_PMF_TO_FROM( tx_stat_dot3statsexcessivecollisions,         stats_tx.tx_stat_dot3statsexcessivecollisions,         b_is_to ) ; // BMAC 0
       LM_STATS_PMF_TO_FROM( rx_stat_maccontrolframesreceived,             stats_rx.rx_stat_maccontrolframesreceived,             b_is_to ) ;

       LM_STATS_PMF_TO_FROM( rx_stat_mac_xpf,                             stats_rx.rx_stat_maccontrolframesreceived_bmac_xpf,    b_is_to ) ; // EMAC 0 BMAC only
       LM_STATS_PMF_TO_FROM( rx_stat_mac_xcf,                             stats_rx.rx_stat_maccontrolframesreceived_bmac_xcf,    b_is_to ) ; // EMAC 0 BMAC only

       LM_STATS_PMF_TO_FROM( tx_stat_etherstatspkts64octets,               stats_tx.tx_stat_etherstatspkts64octets,               b_is_to ) ;
       LM_STATS_PMF_TO_FROM( tx_stat_etherstatspkts65octetsto127octets,    stats_tx.tx_stat_etherstatspkts65octetsto127octets,    b_is_to ) ;
       LM_STATS_PMF_TO_FROM( tx_stat_etherstatspkts128octetsto255octets,   stats_tx.tx_stat_etherstatspkts128octetsto255octets,   b_is_to ) ;
       LM_STATS_PMF_TO_FROM( tx_stat_etherstatspkts256octetsto511octets,   stats_tx.tx_stat_etherstatspkts256octetsto511octets,   b_is_to ) ;
       LM_STATS_PMF_TO_FROM( tx_stat_etherstatspkts512octetsto1023octets,  stats_tx.tx_stat_etherstatspkts512octetsto1023octets,  b_is_to ) ;
       LM_STATS_PMF_TO_FROM( tx_stat_etherstatspkts1024octetsto1522octets, stats_tx.tx_stat_etherstatspkts1024octetsto1522octet,  b_is_to ) ;
       LM_STATS_PMF_TO_FROM( tx_stat_etherstatspktsover1522octets,         stats_tx.tx_stat_etherstatspktsover1522octets,         b_is_to ) ;


       LM_STATS_PMF_TO_FROM( tx_stat_mac_2047,                            stats_tx.tx_stat_etherstatspktsover1522octets_bmac_2047, b_is_to ) ; // EMAC 0 BMAC only
       LM_STATS_PMF_TO_FROM( tx_stat_mac_4095,                            stats_tx.tx_stat_etherstatspktsover1522octets_bmac_4095, b_is_to ) ; // EMAC 0 BMAC only
       LM_STATS_PMF_TO_FROM( tx_stat_mac_9216,                            stats_tx.tx_stat_etherstatspktsover1522octets_bmac_9216, b_is_to ) ; // EMAC 0 BMAC only
       LM_STATS_PMF_TO_FROM( tx_stat_mac_16383,                           stats_tx.tx_stat_etherstatspktsover1522octets_bmac_16383, b_is_to ) ; // EMAC 0 BMAC only

       LM_STATS_PMF_TO_FROM( rx_stat_etherstatsfragments,                  stats_rx.rx_stat_etherstatsfragments,                  b_is_to ) ;
       LM_STATS_PMF_TO_FROM( rx_stat_etherstatsjabbers,                    stats_rx.rx_stat_etherstatsjabbers,                    b_is_to ) ;
       LM_STATS_PMF_TO_FROM( tx_stat_dot3statsdeferredtransmissions,       stats_tx.tx_stat_dot3statsdeferredtransmissions,       b_is_to ) ; // BMAC 0
       LM_STATS_PMF_TO_FROM( tx_stat_dot3statsinternalmactransmiterrors,   stats_tx.tx_stat_dot3statsinternalmactransmiterrors,   b_is_to ) ;
       LM_STATS_PMF_TO_FROM( tx_stat_etherstatscollisions,                 stats_tx.tx_stat_etherstatscollisions,                 b_is_to ) ; // BMAC 0
       LM_STATS_PMF_TO_FROM( tx_stat_flowcontroldone,                      stats_tx.tx_stat_flowcontroldone,                      b_is_to ) ;
       LM_STATS_PMF_TO_FROM( rx_stat_xoffstateentered,                     stats_rx.rx_stat_xoffstateentered,                     b_is_to ) ;
       LM_STATS_PMF_TO_FROM( rx_stat_ifhcinbadoctets,                      stats_rx.rx_stat_ifhcinbadoctets,                      b_is_to ) ;
       LM_STATS_PMF_TO_FROM( tx_stat_ifhcoutbadoctets,                     stats_tx.tx_stat_ifhcoutbadoctets,                     b_is_to ) ; // BMAC 0
       LM_STATS_PMF_TO_FROM( tx_stat_mac_ufl,                              stats_tx.tx_stat_ifhcoutdiscards,                      b_is_to ) ; // EMAC 0
       LM_STATS_PMF_TO_FROM( rx_stat_dot3statscarriersenseerrors,          stats_rx.rx_stat_dot3statscarriersenseerrors,          b_is_to ) ; // BMAC 0
    }

    // NIG, MSTAT and EEE
    if( b_is_to)
    {
        LM_STATS_64_TO_HI_LO( stats_hw->nig.brb_discard, mcp_port->brb_drop ) ;

        LM_STATS_64_TO_HI_LO( stats_hw->macs->stats_tx.tx_stat_pfcPacketCounter, mcp_port->pfc_frames_tx );
        LM_STATS_64_TO_HI_LO( stats_hw->macs->stats_rx.rx_stat_pfcPacketCounter, mcp_port->pfc_frames_rx );

        LM_STATS_64_TO_HI_LO( stats_hw->misc.tx_lpi_count, mcp_port->eee_lpi_count);
    }
    else
    {
        LM_STATS_HI_LO_TO_64( mcp_port->brb_drop, stats_hw->nig.brb_discard ) ;

        LM_STATS_HI_LO_TO_64( mcp_port->pfc_frames_tx, stats_hw->macs->stats_tx.tx_stat_pfcPacketCounter );
        LM_STATS_HI_LO_TO_64( mcp_port->pfc_frames_rx, stats_hw->macs->stats_rx.rx_stat_pfcPacketCounter );

        LM_STATS_HI_LO_TO_64( mcp_port->eee_lpi_count, stats_hw->misc.tx_lpi_count);
    }

}

/*
 * \brief Calculate MCP status port size
 *
 * Calculate the size to be written.
 *
 * This logic is required as b10_l2_chip_statistics_t may increase in size
 * (due to driver change), while MCP area reserved does not follow suit
 * (as is the case, for example, when the driver and MFW do not version-
 * match).
 *
 * This logic calculates the size available based on MFW version, and an
 * additional shmem item added to specifically report size available, thus
 * making future changes to statistics MCP size proof.
 *
 */

STATIC u16_t lm_stats_port_size(IN struct _lm_device_t *pdev)
{
    const u32_t      bc_rev_major               = LM_GET_BC_REV_MAJOR(pdev);
    const u8_t       b_bc_pfc_support           = bc_rev_major >= REQ_BC_VER_4_PFC_STATS_SUPPORTED;
    size_t           sizeof_port_stats          = 0;
    u32_t            sizeof_port_satas_shmem    = 0;

    if (LM_SHMEM2_HAS(pdev,sizeof_port_stats))
    {
        LM_SHMEM2_READ(pdev,OFFSETOF(struct shmem2_region, sizeof_port_stats), &sizeof_port_satas_shmem);

        sizeof_port_stats = min((size_t)sizeof_port_satas_shmem, sizeof(pdev->vars.stats.stats_mirror.stats_mcp_port));
    }
    else
    {
        if (b_bc_pfc_support)
        {
            // "pfc_frames_rx_lo" is the last member of host_port_stats_t for that MFW version.

            sizeof_port_stats = OFFSETOF(host_port_stats_t, pfc_frames_rx_lo) +
                sizeof(pdev->vars.stats.stats_mirror.stats_mcp_port.pfc_frames_rx_lo);
        }
        else
        {
            // "not_used" is the last member of host_port_stats_t for that MFW version.

            sizeof_port_stats = OFFSETOF(host_port_stats_t, not_used ) +
                sizeof(pdev->vars.stats.stats_mirror.stats_mcp_port.not_used);
        }
    }

    sizeof_port_stats /= sizeof(u32_t) ;

    /*
     * we are returning only 16 bits of the size calculated. Check (CHK version only) if the size
     * is too big to be held in 16 bits, which either indicate an error wrt size, or DMAE
     * about to be provided with a task too big.
     */

    DbgBreakIf( sizeof_port_stats >= 1u<<(sizeof(u16_t)*8) );

    return (u16_t)sizeof_port_stats;
}

/*
 *Function Name:lm_stats_port_zero
 *
 *Parameters:
 *
 *Description:
 *  This function should be called by first function on port (PMF) - zeros MCP scatrch pad
 *Returns:
 *
 */
lm_status_t lm_stats_port_zero( IN struct _lm_device_t* pdev )
{
    u16_t            size             = 0 ;
    lm_status_t      lm_status        = LM_STATUS_SUCCESS ;

    if( 0 == pdev->vars.fw_port_stats_ptr )
    {
        /* This could happen and therefore is not considered an error */
        return LM_STATUS_SUCCESS;
    }

    // Calculate the size to be written through DMAE
    size = lm_stats_port_size(pdev);

    // This code section must be under phy lock!
    REG_WR_DMAE_LEN_ZERO(pdev,
                         pdev->vars.fw_port_stats_ptr,
                         size ) ;

    return lm_status ;
}

/*
 *Function Name:lm_stats_port_save
 *
 *Parameters:
 *
 *Description:
 *  This function should be called before PMF is unloaded in order to preserve statitiscs for the next PMF
 *  ASSUMPTION: function must be called under PHY_LOCK (since it uses REG_WR_DMAE interface)
 *  ASSUMPTION: link can not change at this point and until PMF is down
 *Returns:
 *
 */
lm_status_t lm_stats_port_save( IN struct _lm_device_t* pdev )
{
    u16_t              size             = 0 ;
    lm_status_t        lm_status        = LM_STATUS_SUCCESS ;
    host_port_stats_t* mcp_port         = NULL ;

    if( 0 == pdev->vars.fw_port_stats_ptr )
    {
        /* This could happen and therefore is not considered an error */
        return LM_STATUS_SUCCESS;
    }

    lm_stats_port_to_from( pdev, TRUE ) ;

    // Calculate the size to be written through DMAE
    size = lm_stats_port_size(pdev);

    mcp_port = &pdev->vars.stats.stats_mirror.stats_mcp_port ;
    mcp_port->not_used = ++mcp_port->host_port_stats_counter ;

    // This code section must be under phy lock!
    REG_WR_DMAE_LEN(pdev,
                    pdev->vars.fw_port_stats_ptr,
                    mcp_port,
                    size ) ;

    return lm_status ;
}

/*
 *Function Name:lm_stats_port_load
 *
 *Parameters:
 *
 *Description:
 *  This function should be called before a new PMF is loaded in order to restore statitiscs from the previous PMF
 *  vars.is_pmf should be set to TRUE only after this function completed!
 *  ASSUMPTION: function must be called under PHY_LOCK (since it uses REG_RD_DMAE interface)
 *  ASSUMPTION: link can not change at this point and until PMF is up
 *Returns:
 *
 */
lm_status_t lm_stats_port_load( IN struct _lm_device_t* pdev )
{
    u16_t              size             = 0 ;
    lm_status_t        lm_status        = LM_STATUS_SUCCESS ;
    host_port_stats_t* mcp_port         = NULL ;

    if( 0 == pdev->vars.fw_port_stats_ptr )
    {
        /* This could happen and therefore is not considered an error */
        return LM_STATUS_SUCCESS;
    }

    // Calculate the size to be written through DMAE
    size = lm_stats_port_size(pdev);

    mcp_port = &pdev->vars.stats.stats_mirror.stats_mcp_port ;
    mcp_port->not_used = ++mcp_port->host_port_stats_counter ;

    // This code section must be under phy lock!
    REG_RD_DMAE_LEN(pdev,
                    pdev->vars.fw_port_stats_ptr,
                    mcp_port,
                    size ) ;

    lm_stats_port_to_from( pdev, FALSE ) ;

    return lm_status ;
}

/*
 *------------------------------------------------------------------------
 * lm_stats_mgmt_assign
 *
 * write values from mgmt structures into func and port  base structure
 * NOTE: function must be called under PHY_LOCK (since it uses REG_RD_DMAE interface)
 *------------------------------------------------------------------------
 */
void lm_stats_mgmt_assign( IN struct _lm_device_t* pdev )
{
    if CHK_NULL(pdev)
    {
        return;
    }

    if ( GET_FLAGS(pdev->params.test_mode, TEST_MODE_NO_MCP ) )
    {
        return;
    }

    if( pdev->vars.fw_func_stats_ptr )
    {
        lm_stats_mgmt_assign_func(pdev);
    }
    if( pdev->vars.fw_port_stats_ptr )
    {
        // only PMF should assign port statistics
        if( IS_PMF(pdev) )
        {
            lm_stats_port_save(pdev);
        }
    }
}

/*
 *Function Name:lm_stats_on_pmf_update
 *
 *Parameters:
 *  b_on:
 *  TRUE  - the device is beocming now a PMF
 *  FALSE - the device is now going down and transfering PMF to another device
 *Description:
 *  the function should be called under PHY LOCK.
 *  TRUE when a device becoming a PMF and before the link status changed from last state when previous PMF was down after call for mcp driver load
 *  FALSE when a device going down and after the link status saved and can not be changed (interrupts are disabled) before call for mcp driver unload
 *Returns:
 *
 */
lm_status_t lm_stats_on_pmf_update( struct _lm_device_t* pdev, IN u8_t b_on )
{
    lm_status_t lm_status  = LM_STATUS_SUCCESS ;

    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    if( b_on )
    {
        lm_status = lm_stats_port_load( pdev );
    }
    else
    {
        lm_status = lm_stats_on_update_state(pdev);

        // check for success, but link down is a valid situation!
        DbgBreakIf( ( LM_STATUS_SUCCESS != lm_status ) && ( LM_STATUS_LINK_DOWN != lm_status ) );

        // we need to save port stats only if link is down
        // if link is up, it was already made on call to lm_stats_on_update_state.
        if( LM_STATUS_LINK_DOWN == lm_status )
        {
            lm_status = lm_stats_port_save( pdev );
        }
    }
    return lm_status ;
}
/*
 *Function Name:lm_stats_on_pmf_init
 *
 *Parameters:
 *
 *Description:
 *  call this function under PHY LOCK when FIRST ever PMF is on
 *Returns:
 *
 */
lm_status_t lm_stats_on_pmf_init( struct _lm_device_t* pdev )
{
    lm_status_t lm_status  = LM_STATUS_SUCCESS ;
    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    lm_status = lm_stats_port_zero( pdev ) ;

    return lm_status ;

}

lm_status_t lm_stats_hw_collect( struct _lm_device_t* pdev )
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u8_t port             = PORT_ID(pdev);
    const u32_t pkt0      = port ? NIG_REG_STAT1_EGRESS_MAC_PKT0  : NIG_REG_STAT0_EGRESS_MAC_PKT0  ;
    const u32_t pkt1      = port ? NIG_REG_STAT1_EGRESS_MAC_PKT1  : NIG_REG_STAT0_EGRESS_MAC_PKT1  ;
    const u32_t eee       = port ? MISC_REG_CPMU_LP_SM_ENT_CNT_P1 : MISC_REG_CPMU_LP_SM_ENT_CNT_P0 ;

    // call the dmae commands sequance
    lm_status = lm_stats_dmae( pdev ) ;
    if( LM_STATUS_SUCCESS != lm_status )
    {
        return lm_status;
    }

    // read two more NIG registers in the regular way - on E3 these do not exist!!!
    if (!CHIP_IS_E3(pdev))
    {
        REG_RD_DMAE( pdev,  pkt0, &pdev->vars.stats.stats_collect.stats_hw.nig_ex_stats_query.egress_mac_pkt0 );
        REG_RD_DMAE( pdev,  pkt1, &pdev->vars.stats.stats_collect.stats_hw.nig_ex_stats_query.egress_mac_pkt1 );
    }

    // EEE is only supported in E3 chip
    if (CHIP_IS_E3(pdev))
    {
        pdev->vars.stats.stats_collect.stats_hw.misc_stats_query.tx_lpi_count = REG_RD(pdev, eee);
    }

    return lm_status ;
}

/*
 *Function Name:lm_stats_init_port_part
 *
 *Parameters:
 *
 *Description:
 *  call this function under PHY LOCK on port init
 *Returns:
 *
 */
void lm_stats_init_port_part( struct _lm_device_t* pdev )
{
    lm_stats_mgmt_clear_all_func(pdev);
}

/*
 *Function Name:lm_stats_init_port_part
 *
 *Parameters:
 *
 *Description:
 *  call this function under PHY LOCK on function init
 *Returns:
 *
 */
void lm_stats_init_func_part( struct _lm_device_t* pdev )
{
    if (IS_PMF(pdev) && IS_MULTI_VNIC(pdev))
    {
        lm_stats_on_pmf_init(pdev);
    }
    lm_stats_mgmt_read_func_base(pdev);
}
