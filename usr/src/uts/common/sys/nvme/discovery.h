/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _SYS_NVME_DISCOVERY_H
#define	_SYS_NVME_DISCOVERY_H

/*
 * This defines common types that are used for discovering features of NVMe
 * devices. The primary way for users to consume these types is through the
 * libnvme discovery APIs.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	NVME_LOG_ID_MANDATORY,
	NVME_LOG_ID_OPTIONAL,
	NVME_LOG_ID_VENDOR_SPECIFIC
} nvme_log_disc_kind_t;

/*
 * Different logs cover different aspects of a device. These are listed below
 * referring to the NVMe controller, the NVM subsystem itself, and then
 * particular namespaces. NVMe 2.x adds the notion of a domain. From a
 * specification perspective, the NVM subsystem is instead sometimes referred to
 * as a domain. A controller can only access a single domain so while the 2.x
 * specifications suggest the scope is slightly different for the NVM subsystem
 * below, they're basically the same for our purposes.
 */
typedef enum {
	NVME_LOG_SCOPE_CTRL	= 1 << 0,
	NVME_LOG_SCOPE_NVM	= 1 << 1,
	NVME_LOG_SCOPE_NS	= 1 << 2
} nvme_log_disc_scope_t;

typedef enum {
	/*
	 * This indicates that the implementation information is based on
	 * knowledge from a base spec.
	 */
	NVME_LOG_DISC_S_SPEC	= 1 << 0,
	/*
	 * This indicates that the knowledge is from the identify controller
	 * data structure.
	 */
	NVME_LOG_DISC_S_ID_CTRL	= 1 << 1,
	/*
	 * This indicates that we have used our internal information database
	 * about devices from a vendor's datasheets to determine that something
	 * is supported.
	 */
	NVME_LOG_DISC_S_DB	= 1 << 2,
	/*
	 * This indicates that we have used a command (whether vendor-specific
	 * or the NVMe 2.x Supported Log Pages) to get additional information
	 * about this.
	 */
	NVME_LOG_DISC_S_CMD	= 1 << 3
} nvme_log_disc_source_t;

typedef enum {
	/*
	 * These next three flags indicate that the log page requires additional
	 * information for it to complete successfully. These are specifically
	 * the log specific parameter or a log specific indicator (e.g. an
	 * endurance group, NVM set, domain, etc.). RAE was introduced in NVMe
	 * 1.3 and applied to logs that already existed. It will not be possible
	 * to set RAE on a log request that operates on a controller prior to
	 * NVMe 1.3.
	 */
	NVME_LOG_DISC_F_NEED_LSP	= 1 << 0,
	NVME_LOG_DISC_F_NEED_LSI	= 1 << 1,
	NVME_LOG_DISC_F_NEED_RAE	= 1 << 2,
	/*
	 * Log pages whose only scope is a namespace are required to specify a
	 * namespace. Otherwise, when the scope includes a controller or NVM
	 * subsystem then it is assumed that the default is to target the
	 * controller (e.g.  the health log page).
	 */
	NVME_LOG_DISC_F_NEED_NSID	= 1 << 3
} nvme_log_disc_fields_t;


typedef enum {
	NVME_FEAT_SCOPE_CTRL	= 1 << 0,
	NVME_FEAT_SCOPE_NS	= 1 << 1
} nvme_feat_scope_t;

typedef enum {
	/*
	 * Indicates that this feature requires an argument to select some part
	 * of the feature in cdw11.
	 */
	NVME_GET_FEAT_F_CDW11	= 1 << 0,
	/*
	 * Indicates that this feature will output data to a specific buffer and
	 * therefore a data argument is required for this feature.
	 */
	NVME_GET_FEAT_F_DATA	= 1 << 1,
	/*
	 * Indicates that this feature requires a namespace ID to be specified
	 * when getting this feature. In general, while one can usually set a
	 * feature to target the broadcast namespace, the same is not true of
	 * getting a feature.
	 */
	NVME_GET_FEAT_F_NSID	= 1 << 2,
} nvme_get_feat_fields_t;

typedef enum {
	/*
	 * These indicate that the feature requires fields set in the various
	 * control words to set the feature.
	 */
	NVME_SET_FEAT_F_CDW11	= 1 << 0,
	NVME_SET_FEAT_F_CDW12	= 1 << 1,
	NVME_SET_FEAT_F_CDW13	= 1 << 2,
	NVME_SET_FEAT_F_CDW14	= 1 << 3,
	NVME_SET_FEAT_F_CDW15	= 1 << 4,
	/*
	 * Indicates that there is a data payload component to this feature that
	 * must be set.
	 */
	NVME_SET_FEAT_F_DATA	= 1 << 5,
	/*
	 * Indicates that this feature requires a namespace ID. Broadcast IDs
	 * are more often allowed than with getting a feature, but it still
	 * depends.
	 */
	NVME_SET_FEAT_F_NSID	= 1 << 6
} nvme_set_feat_fields_t;

typedef enum {
	/*
	 * Indicates that getting the feature outputs data in cdw0 for
	 * consumption. This is the most common form of data output for getting
	 * features. Setting features usually doesn't output data in cdw0;
	 * however, a few are defined to.
	 */
	NVME_FEAT_OUTPUT_CDW0	= 1 << 0,
	/*
	 * Indicates that data is output in the data buffer that was passed in.
	 * This is only ever used for get features.
	 */
	NVME_FEAT_OUTPUT_DATA	= 1 << 1
} nvme_feat_output_t;

typedef enum {
	/*
	 * Indicates that when getting or setting this feature that requires a
	 * namespace ID, the broadcast namespace is allowed.
	 */
	NVME_FEAT_F_GET_BCAST_NSID	= 1 << 0,
	NVME_FEAT_F_SET_BCAST_NSID	= 1 << 1
} nvme_feat_flags_t;

typedef enum {
	NVME_FEAT_MANDATORY	= 0,
	NVME_FEAT_OPTIONAL,
	NVME_FEAT_VENDOR_SPECIFIC
} nvme_feat_kind_t;

/*
 * This enumeration indicates whether or not a given feature is specific to a
 * command set, and if so what one. The default is that most features are
 * present for all command sets, which uses the NVME_FEAT_CSI_NONE value.
 * Otherwise, it uses a bit-field to indicate what it is present in.
 */
typedef enum {
	NVME_FEAT_CSI_NONE	= 0,
	NVME_FEAT_CSI_NVM	= 1 << 0,
} nvme_feat_csi_t;

/*
 * Prior to NVMe 2.x, there was no standard way to determine if a given log page
 * was actually implemented or not. While several features had bits in the
 * identify controller namespace, some (e.g. LBA Range Type) are optional,
 * command-set specific, and have no such way of knowing if they're supported
 * short of saying so. If we cannot determine this from the controller's
 * version, type, and identify controller information, then we will indicate
 * that we don't know. When we have full support for leveraging the NVMe 2.x
 * Feature Identifiers Supported and Effects log pages and someone is
 * interrogating an NVMe 2.x controller, then ideally one should not see
 * unknown.
 */
typedef enum {
	NVME_FEAT_IMPL_UNKNOWN = 0,
	NVME_FEAT_IMPL_UNSUPPORTED,
	NVME_FEAT_IMPL_SUPPORTED
} nvme_feat_impl_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_DISCOVERY_H */
