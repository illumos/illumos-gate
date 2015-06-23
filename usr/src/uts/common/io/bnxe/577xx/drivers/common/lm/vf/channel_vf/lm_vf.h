#ifndef _LM_VF_H
#define _LM_VF_H

#include "vfpf_if.h"
#ifndef aligned_u64
#define aligned_u64 __declspec( align( 8 ) ) u64
#endif
#include "hw_channel.h"
#include "lm_vf_common.h"

/* VF_INFO*/
#define MAX_NUM_OF_SB_BLOCKS    136
#define SB_ARRAY_SIZE           ((MAX_NUM_OF_SB_BLOCKS - 1)/ELEM_OF_RES_ARRAY_SIZE_IN_BITS + 1)

#define MAX_NUM_OF_FW_CLIENTS      152
#define FW_CLIENTS_ARRAY_SIZE      ((MAX_NUM_OF_FW_CLIENTS - 1)/ELEM_OF_RES_ARRAY_SIZE_IN_BITS + 1)

#define MAX_NUM_OF_SW_CLIENTS      304
#define SW_CLIENTS_ARRAY_SIZE      ((MAX_NUM_OF_SW_CLIENTS - 1)/ELEM_OF_RES_ARRAY_SIZE_IN_BITS + 1)


typedef struct _pf_resources_set_t {
    u32_t   free_sbs[SB_ARRAY_SIZE];
    u32_t   free_fw_clients[FW_CLIENTS_ARRAY_SIZE];
    u32_t   free_sw_clients[SW_CLIENTS_ARRAY_SIZE];
} pf_resources_set_t;

//#define MM_ACQUIRE_PF_LOCK(pdev)
//#define MM_RELEASE_PF_LOCK(pdev)
#define MAX_VF_ETH_CONS             0

#define LM_SW_CID_TO_SW_QID(_pdev, _cid) (_cid)
#define LM_SW_QID_TO_SW_CID(_pdev, _qid) (_qid)

#endif
/* */
