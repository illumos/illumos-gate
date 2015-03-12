#ifndef MCP_SHMEM_H
#define MCP_SHMEM_H

#include "dev_info.h"
#ifdef BMAPI
#include "eve_inc\shmem.h"
#else
#include "shmem.h"
#endif

typedef struct shared_hw_cfg shared_hw_cfg_t;
typedef struct port_hw_cfg port_hw_cfg_t;
typedef struct shared_feat_cfg shared_feat_cfg_t;
typedef struct port_feat_cfg port_feat_cfg_t;
typedef struct mgmtfw_state mgmtfw_state_t;
typedef struct drv_port_mb drv_port_mb_t;
typedef struct drv_func_mb drv_func_mb_t;
typedef struct shared_mf_cfg shared_mf_cfg_t;
typedef struct port_mf_cfg port_mf_cfg_t;
typedef struct func_mf_cfg func_mf_cfg_t;
typedef struct mf_cfg mf_cfg_t;
typedef struct shmem_region shmem_region_t;
typedef struct shmem2_region shmem2_region_t;
typedef struct lldp_params lldp_params_t;
typedef struct lldp_admin_mib lldp_admin_mib_t;
typedef struct lldp_local_mib lldp_local_mib_t;
typedef struct lldp_local_mib_ext lldp_local_mib_ext_t;
typedef struct lldp_remote_mib lldp_remote_mib_t;
typedef struct lldp_dcbx_stat lldp_dcbx_stat_t;
typedef struct dcbx_features dcbx_features_t;
typedef struct dcbx_ets_feature dcbx_ets_feature_t;
typedef struct dcbx_pfc_feature dcbx_pfc_feature_t;
typedef struct dcbx_app_priority_feature dcbx_app_priority_feature_t;
typedef struct dcbx_app_priority_entry dcbx_app_priority_entry_t;

#endif /* MCP_SHMEM_H */

