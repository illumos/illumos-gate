#ifndef _LM_VF_H
#define _LM_VF_H

#include "lm_vf_common.h"

/* VF_INFO*/
#define MAX_VF_ETH_CONS             ((1 << (LM_VF_MAX_RVFID_SIZE + LM_VF_CID_WND_SIZE + 1)) - MAX_ETH_CONS)    /*128 - MAX_ETH_CONS for single connection*/

#define MAX_NUM_OF_SB_BLOCKS    16
#define SB_ARRAY_SIZE           ((MAX_NUM_OF_SB_BLOCKS - 1)/ELEM_OF_RES_ARRAY_SIZE_IN_BITS + 1)

#define MAX_NUM_OF_CLIENTS      24
#define CLIENTS_ARRAY_SIZE      ((MAX_NUM_OF_CLIENTS - 1)/ELEM_OF_RES_ARRAY_SIZE_IN_BITS + 1)

#define MAX_NUM_OF_STATS        18
#define STATS_ARRAY_SIZE        ((MAX_NUM_OF_STATS - 1)/ELEM_OF_RES_ARRAY_SIZE_IN_BITS + 1)

#define MAX_NUM_OF_CAM_OFFSETS  40
#define CAM_OFFSETS_ARRAY_SIZE  ((MAX_NUM_OF_CAM_OFFSETS - 1)/ELEM_OF_RES_ARRAY_SIZE_IN_BITS + 1)

#define MAX_NUM_OF_VFS          64
#define FLRED_VFS_ARRAY_SIZE    ((MAX_NUM_OF_VFS - 1)/ELEM_OF_RES_ARRAY_SIZE_IN_BITS + 1)
/**
typedef struct _vf_info_t {
    struct _lm_device_t *   ppfdev;

    u8_t            num_fw_sbs;
    u8_t            stats_id;

    u8_t            base_fw_client_id;
    u8_t            base_fw_sb_id;
    u8_t            base_cam_offset;

} vf_info_t;
*/
typedef struct _pf_resources_set_t {
    u32_t   free_sbs[SB_ARRAY_SIZE];
    u32_t   free_clients[CLIENTS_ARRAY_SIZE];
    u32_t   free_stats[CLIENTS_ARRAY_SIZE];
    u32_t   free_cam_offsets[CAM_OFFSETS_ARRAY_SIZE];
    u32_t   flred_vfs[FLRED_VFS_ARRAY_SIZE];
} pf_resources_set_t;
#endif
/* */
