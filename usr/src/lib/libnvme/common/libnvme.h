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

#ifndef _LIBNVME_H
#define	_LIBNVME_H

/*
 * This contains an evolving set of interfaces for more programmatically
 * interfacing with NVMe devices. For more information on why the library looks
 * this way, please see lib/libnvme/common/libnvme.c.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#include <libdevinfo.h>
#include <sys/nvme/discovery.h>

/*
 * Right now everything relies on seeing various pieces that are in sys/nvme.h,
 * unfortunately. This includes things like the identify, log page, and
 * structure data structures, various constants, and other things that have
 * accumulated. This must all be rejiggered prior to making this a committed
 * interface as we're leaking through many things that software needs.
 * Directionally splitting this out into headers that relate to the spec as
 * <sys/nvme/identify.h>, etc. would be useful and would address several of the
 * places that we're passing in raw uint32_t's for items that come from the spec
 * and could be a little more specific to help out consumers.
 */
#include <sys/nvme.h>

/*
 * General error classes that may be returned when operating on non-information
 * snapshots.
 */
typedef enum {
	NVME_ERR_OK	 = 0,
	/*
	 * Indicates that a command failed due to a controller-specific error.
	 * The controller's SCT/SC are valid in the corresponding objects error
	 * data.
	 */
	NVME_ERR_CONTROLLER,
	/*
	 * Indicates that there was a memory allocation error. The system error
	 * contains the specific errno.
	 */
	NVME_ERR_NO_MEM,
	/*
	 * Indicates that an operation could not complete because the kernel did
	 * not have DMA resources available for us.
	 */
	NVME_ERR_NO_DMA_MEM,
	/*
	 * Indicates that an error occurred while trying to use the devinfo
	 * library.
	 */
	NVME_ERR_LIBDEVINFO,
	/*
	 * Indicates that an internal error condition occurred.
	 */
	NVME_ERR_INTERNAL,
	/*
	 * Indicates that the function was given an invalid pointer argument.
	 */
	NVME_ERR_BAD_PTR,
	/*
	 * Indicates that an unknown flag argument was given to us.
	 */
	NVME_ERR_BAD_FLAG,
	/*
	 * Indicates that the devinfo node we were given doesn't correspond to
	 * an NVMe controller.
	 */
	NVME_ERR_BAD_DEVI,
	/*
	 * Indicates that while we found a devinfo property successfully,
	 * something about it does not match our expectations. This could be the
	 * type, number of values, range, etc.
	 */
	NVME_ERR_BAD_DEVI_PROP,
	/*
	 * Indicates that we were given an illegal instance (i.e. a negative
	 * instance).
	 */
	NVME_ERR_ILLEGAL_INSTANCE,
	/*
	 * Indicates that a means of identifying a controller (name, instance,
	 * etc.) does not match any known NVMe device.
	 */
	NVME_ERR_BAD_CONTROLLER,
	/*
	 * Indicates that a request could not proceed due to missing privileges.
	 */
	NVME_ERR_PRIVS,
	/*
	 * Indicates a failure to open a device file.
	 */
	NVME_ERR_OPEN_DEV,
	/*
	 * Indicates that the given restore data is not valid.
	 */
	NVME_ERR_BAD_RESTORE,
	/*
	 * Indicates that a namespace (name, ID, etc.) passed in is not valid on
	 * the controller. This may be because it's outside the valid range or
	 * there was an attempt to use the broadcast namespace when it's not
	 * supported.
	 */
	NVME_ERR_NS_RANGE,
	/*
	 * Indicates that a namespace ID is not usable in this context. For
	 * example, attempting to specify a namespace to an identify or log page
	 * that does not support them.
	 */
	NVME_ERR_NS_UNUSE,
	/*
	 * Indicates that the value for a get log page field is invalid. This
	 * may happened due to alignment, just being too large, or something
	 * else.
	 */
	NVME_ERR_LOG_CSI_RANGE,
	NVME_ERR_LOG_LID_RANGE,
	NVME_ERR_LOG_LSP_RANGE,
	NVME_ERR_LOG_LSI_RANGE,
	NVME_ERR_LOG_RAE_RANGE,
	NVME_ERR_LOG_SIZE_RANGE,
	NVME_ERR_LOG_OFFSET_RANGE,
	/*
	 * Indicates that the log field value given is not supported because the
	 * controller is not of a sufficient version or does not indicate that
	 * it is supported in the LPA field.
	 */
	NVME_ERR_LOG_CSI_UNSUP,
	NVME_ERR_LOG_LSP_UNSUP,
	NVME_ERR_LOG_LSI_UNSUP,
	NVME_ERR_LOG_RAE_UNSUP,
	NVME_ERR_LOG_OFFSET_UNSUP,
	/*
	 * Indicates that the log field value is unusable. The specifics of our
	 * request indicate that this cannot be set.
	 */
	NVME_ERR_LOG_LSP_UNUSE,
	NVME_ERR_LOG_LSI_UNUSE,
	NVME_ERR_LOG_RAE_UNUSE,
	/*
	 * Indicates that the log page's scope requires operating on something
	 * that isn't what was requested. This would happen if manually
	 * constructing a log page that operates on the controller, but passed a
	 * namespace (e.g. the firmware log page).
	 */
	NVME_ERR_LOG_SCOPE_MISMATCH,
	/*
	 * Indicates that a log request can't be executed because required
	 * fields have not been set.
	 */
	NVME_ERR_LOG_REQ_MISSING_FIELDS,
	/*
	 * Indicates that the named log is unknown to the library.
	 */
	NVME_ERR_LOG_NAME_UNKNOWN,
	/*
	 * Indicates that the named log is not supported by the device.
	 */
	NVME_ERR_LOG_UNSUP_BY_DEV,
	/*
	 * Indicates that the IDENTIFY command requested is unknown.
	 */
	NVME_ERR_IDENTIFY_UNKNOWN,
	/*
	 * Indicates that the requested identify command is not supported by the
	 * device.
	 */
	NVME_ERR_IDENTIFY_UNSUP_BY_DEV,
	/*
	 * Indicates that the identify command parameter is outside of the valid
	 * range for the field.
	 */
	NVME_ERR_IDENTIFY_CTRLID_RANGE,
	NVME_ERR_IDENTIFY_OUTPUT_RANGE,
	/*
	 * Indicates that the parameter given is not supported because the
	 * controller is not of a sufficient version or does not indicate that
	 * it is supported.
	 */
	NVME_ERR_IDENTIFY_CTRLID_UNSUP,
	/*
	 * Indicates that the parameter given is not supported in the context of
	 * a given identify command. Namespaces are handled with the
	 * cross-command error code.
	 */
	NVME_ERR_IDENTIFY_CTRLID_UNUSE,
	/*
	 * Indicates that an identify request can't be executed because required
	 * fields have not been set.
	 */
	NVME_ERR_IDENTIFY_REQ_MISSING_FIELDS,
	/*
	 * Indicates that the controller doesn't support the NVMe standard
	 * vendor unique command.
	 */
	NVME_ERR_VUC_UNSUP_BY_DEV,
	/*
	 * Indicates that the vendor unique command parameter is outside of the
	 * valid range for the field.
	 */
	NVME_ERR_VUC_TIMEOUT_RANGE,
	NVME_ERR_VUC_OPCODE_RANGE,
	NVME_ERR_VUC_IMPACT_RANGE,
	NVME_ERR_VUC_NDT_RANGE,
	/*
	 * Indicates that a vendor unique command already has an input or output
	 * buffer set and is being asked to set a separate one.
	 */
	NVME_ERR_VUC_CANNOT_RW,
	/*
	 * Indicates that the vendor unique request does not have valid
	 * execution context. This may be because the command was never executed
	 * or the exec failed in a way such that the controller never exercised
	 * the command.
	 */
	NVME_ERR_VUC_NO_RESULTS,
	/*
	 * Indicates that the named vendor unique command is not known to the
	 * library.
	 */
	NVME_ERR_VUC_UNKNOWN,
	/*
	 * Indicates that a vendor unique command can't be executed because
	 * required fields have not been set.
	 */
	NVME_ERR_VUC_REQ_MISSING_FIELDS,
	/*
	 * Indicates that the vendor-specific library operation could not
	 * proceed because it is not supported by the given device.
	 */
	NVME_ERR_VU_FUNC_UNSUP_BY_DEV,
	/*
	 * WDC e6 dump specific invalid values
	 */
	NVME_ERR_WDC_E6_OFFSET_RANGE,
	/*
	 * Indicates that the controller does not support firmware related
	 * operations.
	 */
	NVME_ERR_FW_UNSUP_BY_DEV,
	/*
	 * Indicates that the constraints of the device and what the kernel can
	 * do make the firmware upgrade non-tenable.
	 */
	NVME_ERR_KERN_FW_IMPOS,
	/*
	 * Indicates that a firmware download parameter is invalid.
	 */
	NVME_ERR_FW_LOAD_LEN_RANGE,
	NVME_ERR_FW_LOAD_OFFSET_RANGE,
	/*
	 * Indicates that the firmware commit command parameter is outside of
	 * the valid range for the field.
	 */
	NVME_ERR_FW_COMMIT_SLOT_RANGE,
	NVME_ERR_FW_COMMIT_ACTION_RANGE,
	/*
	 * Indicates that a firmware commit command can't be executed because
	 * required fields have not been set.
	 */
	NVME_ERR_FW_COMMIT_REQ_MISSING_FIELDS,
	/*
	 * Indicates that the firmware commit could not occur because the
	 * requested slot is read-only.
	 */
	NVME_ERR_FW_SLOT_RO,
	/*
	 * Indicates that the controller does not support NVM format operations.
	 */
	NVME_ERR_FORMAT_UNSUP_BY_DEV,
	/*
	 * Indicates that the controller does not support cryptographic secure
	 * erase.
	 */
	NVME_ERR_CRYPTO_SE_UNSUP_BY_DEV,
	/*
	 * Indicates that the NVM format command cannot be executed because it
	 * would target a specific namespace; however, the device does not allow
	 * a secure erase or a format to target an individual namespace.
	 */
	NVME_ERR_NS_FORMAT_UNSUP_BY_DEV,
	/*
	 * Indicates that the kernel does not support formatting with the
	 * specified LBA format, generally due to something like the use of
	 * metadata in the namespace.
	 */
	NVME_ERR_KERN_FORMAT_UNSUP,
	/*
	 * Indicates that the NVM format command parameter is outside of
	 * the valid range for the field.
	 */
	NVME_ERR_FORMAT_LBAF_RANGE,
	NVME_ERR_FORMAT_SES_RANGE,
	/*
	 * Indicates that the parameter and/or its value is not supported for a
	 * NVM format command.
	 */
	NVME_ERR_FORMAT_PARAM_UNSUP,
	/*
	 * Indicates that a NVM format command can't be executed because
	 * required fields have not been set.
	 */
	NVME_ERR_FORMAT_REQ_MISSING_FIELDS,
	/*
	 * Indicates that the WDC e6 log dump request could not be executed due
	 * to fields not being set.
	 */
	NVME_ERR_WDC_E6_REQ_MISSING_FIELDS,
	/*
	 * Indicates that the named feature is unknown to the library.
	 */
	NVME_ERR_FEAT_NAME_UNKNOWN,
	/*
	 * Indicates that the named feature is not supported by the device.
	 */
	NVME_ERR_FEAT_UNSUP_BY_DEV,
	/*
	 * Indicates that the feature parameter is outside of the valid range
	 * for the field.
	 */
	NVME_ERR_FEAT_FID_RANGE,
	NVME_ERR_FEAT_SEL_RANGE,
	NVME_ERR_FEAT_CDW11_RANGE,
	NVME_ERR_FEAT_DATA_RANGE,
	/*
	 * Indicates that the feature parameter given is not supported because
	 * the controller is not of a sufficient version.
	 */
	NVME_ERR_FEAT_SEL_UNSUP,
	/*
	 * Indicates that the get feature parameter given is not supported for
	 * the given feature. For example, passing in a cdw11 argument that is
	 * not needed.
	 */
	NVME_ERR_FEAT_CDW11_UNUSE,
	NVME_ERR_FEAT_DATA_UNUSE,
	/*
	 * Indicates that a feature request does not have valid output data.
	 * This may be because the command was never executed or it did not
	 * execute successfully.
	 */
	NVME_ERR_FEAT_NO_RESULTS,
	/*
	 * Indicates that a get features request can't be executed because
	 * required fields have not been set.
	 */
	NVME_ERR_GET_FEAT_REQ_MISSING_FIELDS,
	/*
	 * These indicate that the operation could not be executed because they
	 * require holding either a controller or namespace write lock and one
	 * is not held by the corresponding controller handle.
	 */
	NVME_ERR_NEED_CTRL_WRLOCK,
	NVME_ERR_NEED_NS_WRLOCK,
	/*
	 * These indicate that the operation could not be executed because the
	 * controller or namespace respectively currently have an exclusive
	 * write lock (or an equivalent future form) that blocks execution from
	 * others.
	 */
	NVME_ERR_CTRL_LOCKED,
	NVME_ERR_NS_LOCKED,
	/*
	 * Indicates that a fatal locking operation occurred that will terminate
	 * the process. This includes cases such as recursive enters on the same
	 * lock, attempting to unlock a lock that isn't owned, etc.
	 */
	NVME_ERR_LOCK_PROG,
	/*
	 * Indicates that a lock order violation was attempted. This includes
	 * things like taking the controller lock while holding the namespace
	 * lock, attempting to take a second namespace lock, holding a
	 * controller write lock and trying to get a namespace lock, etc.
	 */
	NVME_ERR_LOCK_ORDER,
	/*
	 * Indicates that a signal was encountered while attempting to take a
	 * lock.
	 */
	NVME_ERR_LOCK_WAIT_INTR,
	/*
	 * Indicates that attempting to take the lock failed because the thread
	 * would be required to block, but it asked not to.
	 */
	NVME_ERR_LOCK_WOULD_BLOCK,
	/*
	 * These indicate that the respective attach and detach operations
	 * failed to complete due to an error in the underlying kernel
	 * subsystems. For detach this might happen because of a disk being
	 * open, busy in a zpool, or something else. For attach, it may suggest
	 * and NDI or other issue.
	 */
	NVME_ERR_DETACH_KERN,
	NVME_ERR_ATTACH_KERN,
	/*
	 * Indicates that the kernel driver does not support some property of
	 * the requested namespace.
	 */
	NVME_ERR_ATTACH_UNSUP_KERN,
	/*
	 * Indicates that the operation cannot proceed because a namespace is
	 * attached to blkdev and it must be detached to proceed.
	 */
	NVME_ERR_NS_BLKDEV_ATTACH,
	/*
	 * Indicates that non-DMA kernel memory was not available for this
	 * request.
	 */
	NVME_ERR_NO_KERN_MEM,
	/*
	 * These two codes represent internal device conditions that indicate
	 * the device is unusable or that it was physically removed (usually due
	 * to hotplug).
	 */
	NVME_ERR_CTRL_DEAD,
	NVME_ERR_CTRL_GONE
} nvme_err_t;

/*
 * Errors used for the various information errors. This is shared between both
 * controller and namespace information structures.
 */
typedef enum {
	NVME_INFO_ERR_OK,
	/*
	 * Indicates that the item is not supported because this is the wrong
	 * controller transport. For example, asking about a PCI ID for
	 * something that is not PCI-based.
	 */
	NVME_INFO_ERR_TRANSPORT,
	/*
	 * Indicates that the item is not supported because the device version
	 * is too old to get this.
	 */
	NVME_INFO_ERR_VERSION,
	/*
	 * Indicates that we could not get certain information because the
	 * device does not support a given capability.
	 */
	NVME_INFO_ERR_MISSING_CAP,
	/*
	 * Indicates that the specified format value is unknown.
	 */
	NVME_INFO_ERR_BAD_LBA_FMT,
	/*
	 * These errors only occur during attempts to persist information and
	 * indicate challenges allocating memory or otherwise challenges with
	 * libnvpair.
	 */
	NVME_INFO_ERR_PERSIST_NVL,
	/*
	 * The first indicates that the index is invalid or if it is technically
	 * within the valid LBA format range, but there is no data size. The
	 * second indicates that we can't actually fully represent the data
	 * here. This happens because say the LBA size can't be represented by a
	 * uint64_t.
	 */
	NVME_INFO_ERR_BAD_FMT,
	NVME_INFO_ERR_BAD_FMT_DATA,
	/*
	 * Indicates that the information cannot be returned because the
	 * namespace's state does not allow us to answer this question. This may
	 * be because it's inactive as below or because blkdev is not attached.
	 */
	NVME_INFO_ERR_NS_INACTIVE,
	NVME_INFO_ERR_NS_NO_BLKDEV
} nvme_info_err_t;

typedef struct nvme nvme_t;
typedef struct nvme_ctrl nvme_ctrl_t;
typedef struct nvme_ctrl_iter nvme_ctrl_iter_t;
typedef struct nvme_ctrl_disc nvme_ctrl_disc_t;
typedef struct nvme_ctrl_info nvme_ctrl_info_t;
typedef struct nvme_ns nvme_ns_t;
typedef struct nvme_ns_iter nvme_ns_iter_t;
typedef struct nvme_ns_disc nvme_ns_disc_t;
typedef struct nvme_ns_info nvme_ns_info_t;
typedef struct nvme_nvm_lba_fmt nvme_nvm_lba_fmt_t;
typedef struct nvme_log_iter nvme_log_iter_t;
typedef struct nvme_log_disc nvme_log_disc_t;
typedef struct nvme_log_req nvme_log_req_t;
typedef struct nvme_id_req nvme_id_req_t;
typedef struct nvme_vuc_iter nvme_vuc_iter_t;
typedef struct nvme_vuc_disc nvme_vuc_disc_t;
typedef struct nvme_vuc_req nvme_vuc_req_t;
typedef struct nvme_fw_commit_req nvme_fw_commit_req_t;
typedef struct nvme_format_req nvme_format_req_t;
typedef struct nvme_feat_disc nvme_feat_disc_t;
typedef struct nvme_feat_iter nvme_feat_iter_t;
typedef struct nvme_get_feat_req nvme_get_feat_req_t;

/*
 * Vendor-specific forwards.
 */
typedef struct nvme_wdc_e6_req nvme_wdc_e6_req_t;

extern nvme_t *nvme_init(void);
extern void nvme_fini(nvme_t *);

/*
 * Error information. Operations that take an nvme_t, always set error
 * information on the nvme_t. Operations that operate on a controller or are
 * related to a request object or iterator that starts from the controller
 * set error information on the nvme_ctrl_t.
 */
extern nvme_err_t nvme_err(nvme_t *);
extern int32_t nvme_syserr(nvme_t *);
extern const char *nvme_errmsg(nvme_t *);
extern size_t nvme_errlen(nvme_t *);
extern const char *nvme_errtostr(nvme_t *, nvme_err_t);

extern nvme_err_t nvme_ctrl_err(nvme_ctrl_t *);
extern int32_t nvme_ctrl_syserr(nvme_ctrl_t *);
extern const char *nvme_ctrl_errmsg(nvme_ctrl_t *);
extern size_t nvme_ctrl_errlen(nvme_ctrl_t *);
extern void nvme_ctrl_deverr(nvme_ctrl_t *, uint32_t *, uint32_t *);
extern const char *nvme_ctrl_errtostr(nvme_ctrl_t *, nvme_err_t);

/*
 * Translations for NVMe spec error constants. These end up taking the
 * nvme_ctrl_t so that way they can potentially translate vendor-specific errors
 * if they are defined. A NULL controller is allowed, which will skip all such
 * processing altogether. Both functions will always a return a string so there
 * is no need to check for NULL (though it may just be a variant of "unknown
 * ...").
 *
 * If NULL is passed for the controller in nvme_sctostr(), we will assume that
 * the controller's type is a traditional PCI I/O controller and not a fabric
 * based controller, which further changes the way that command-specific status
 * codes are interpreted. Due to the lack of support in the system for
 * different controller types, this function will always assume a PCI I/O
 * controller currently.
 */
extern const char *nvme_scttostr(nvme_ctrl_t *, uint32_t);
extern const char *nvme_sctostr(nvme_ctrl_t *, nvme_csi_t, uint32_t, uint32_t);

typedef enum nvme_iter {
	NVME_ITER_VALID,
	NVME_ITER_DONE,
	NVME_ITER_ERROR
} nvme_iter_t;

/*
 * NVMe Controller discovery.
 */
extern di_node_t nvme_ctrl_disc_devi(const nvme_ctrl_disc_t *);
extern di_minor_t nvme_ctrl_disc_minor(const nvme_ctrl_disc_t *);

extern bool nvme_ctrl_discover_init(nvme_t *, nvme_ctrl_iter_t **);
extern nvme_iter_t nvme_ctrl_discover_step(nvme_ctrl_iter_t *,
    const nvme_ctrl_disc_t **);
extern void nvme_ctrl_discover_fini(nvme_ctrl_iter_t *);

typedef bool (*nvme_ctrl_disc_f)(nvme_t *, const nvme_ctrl_disc_t *, void *);
extern bool nvme_ctrl_discover(nvme_t *, nvme_ctrl_disc_f, void *);

extern bool nvme_ctrl_init(nvme_t *, di_node_t, nvme_ctrl_t **);
extern bool nvme_ctrl_init_by_instance(nvme_t *, int32_t, nvme_ctrl_t **);
extern bool nvme_ctrl_devi(nvme_ctrl_t *, di_node_t *);
extern void nvme_ctrl_fini(nvme_ctrl_t *);

/*
 * Get information about a controller. This information about a controller is
 * separate from the lifetime of the controller itself. This is done to
 * facilitate the ability of saving and using this information on another
 * system and make the management a bit easier. Errors appear on this object and
 * not the nmve_t.
 */
extern bool nvme_ctrl_info_snap(nvme_ctrl_t *, nvme_ctrl_info_t **);
extern bool nvme_ctrl_info_restore(nvme_t *, nvlist_t *, nvme_ctrl_info_t **);
extern bool nvme_ctrl_info_persist(nvme_ctrl_info_t *, nvlist_t **);
extern void nvme_ctrl_info_free(nvme_ctrl_info_t *);

extern nvme_info_err_t nvme_ctrl_info_err(nvme_ctrl_info_t *);
extern int32_t nvme_ctrl_info_syserr(nvme_ctrl_info_t *);
extern const char *nvme_ctrl_info_errmsg(nvme_ctrl_info_t *);
extern size_t nvme_ctrl_info_errlen(nvme_ctrl_info_t *);
extern const char *nvme_ctrl_info_errtostr(nvme_ctrl_info_t *, nvme_info_err_t);

/*
 * Information about an NVMe controller. This information is a combination of
 * the identify data structure which can be retrieved directly by folks who
 * would prefer to use it. Common fields that are used in something like nvmeadm
 * or other utilities who would rather not need to know about the specifics of
 * the data structure or have to think about the version can use that instead.
 *
 * NVMe 2.x has kept the identify controller data structure backwards
 * compatible. If a future version were to invalidate that, then this could
 * possibly return NULL.
 */
extern uint16_t nvme_ctrl_info_vendor(nvme_ctrl_info_t *);
extern const nvme_identify_ctrl_t *nvme_ctrl_info_identify(nvme_ctrl_info_t *);
extern const nvme_version_t *nvme_ctrl_info_version(nvme_ctrl_info_t *);
extern const char *nvme_ctrl_info_model(nvme_ctrl_info_t *);
extern const char *nvme_ctrl_info_serial(nvme_ctrl_info_t *);
extern uint32_t nvme_ctrl_info_fwgran(nvme_ctrl_info_t *);
extern const char *nvme_ctrl_info_fwrev(nvme_ctrl_info_t *);
extern uint32_t nvme_ctrl_info_nns(nvme_ctrl_info_t *);

typedef enum {
	NVME_CTRL_TRANSPORT_PCI,
	NVME_CTRL_TRANSPORT_TCP,
	NVME_CTRL_TRANSPORT_RDMA,
} nvme_ctrl_transport_t;

typedef enum {
	NVME_CTRL_TYPE_UNKNOWN,
	NVME_CTRL_TYPE_IO,
	NVME_CTRL_TYPE_ADMIN,
	NVME_CTRL_TYPE_DISCOVERY,
} nvme_ctrl_type_t;

/*
 * Controller types were explicitly added in the NVMe 1.4 specification. Prior
 * to that all controllers were required to support issuing I/O, hence we return
 * them as NVME_CTRL_TYPE_IO, even though this isn't quite by the spec. In 1.4
 * this was added to the identify controller information. The 'UNKNOWN' type is
 * for cases where we don't recognize the value based upon the standard.
 */
extern nvme_ctrl_type_t nvme_ctrl_info_type(nvme_ctrl_info_t *);
extern nvme_ctrl_transport_t nvme_ctrl_info_transport(nvme_ctrl_info_t *);

/*
 * The following pieces of information are specific to PCI NVMe controllers and
 * are not from the common identify controller data structure. As such they are
 * fallible. The first group come from configuration space while the others are
 * information that comes from the actual controller capability registers.
 */
extern bool nvme_ctrl_info_pci_vid(nvme_ctrl_info_t *, uint16_t *);
extern bool nvme_ctrl_info_pci_did(nvme_ctrl_info_t *, uint16_t *);
extern bool nvme_ctrl_info_pci_rev(nvme_ctrl_info_t *, uint8_t *);
extern bool nvme_ctrl_info_pci_subvid(nvme_ctrl_info_t *, uint16_t *);
extern bool nvme_ctrl_info_pci_subsys(nvme_ctrl_info_t *, uint16_t *);

extern bool nvme_ctrl_info_pci_mps_min(nvme_ctrl_info_t *, uint32_t *);
extern bool nvme_ctrl_info_pci_mps_max(nvme_ctrl_info_t *, uint32_t *);

extern bool nvme_ctrl_info_pci_nintrs(nvme_ctrl_info_t *, uint32_t *);

/*
 * These three items are only present if the device supports Namespace
 * Management.
 */
extern bool nvme_ctrl_info_cap(nvme_ctrl_info_t *, nvme_uint128_t *);
extern bool nvme_ctrl_info_unalloc_cap(nvme_ctrl_info_t *, nvme_uint128_t *);
extern bool nvme_ctrl_info_common_ns(nvme_ctrl_info_t *,
    const nvme_identify_nsid_t **);

/*
 * The following information is specific to the NVM command set for controllers.
 */
extern uint32_t nvme_ctrl_info_nformats(nvme_ctrl_info_t *);
extern bool nvme_ctrl_info_format(nvme_ctrl_info_t *, uint32_t,
    const nvme_nvm_lba_fmt_t **);
extern uint32_t nvme_nvm_lba_fmt_id(const nvme_nvm_lba_fmt_t *);
extern uint32_t nvme_nvm_lba_fmt_meta_size(const nvme_nvm_lba_fmt_t *);
extern uint64_t nvme_nvm_lba_fmt_data_size(const nvme_nvm_lba_fmt_t *);
extern uint32_t nvme_nvm_lba_fmt_rel_perf(const nvme_nvm_lba_fmt_t *);

/*
 * Identify Operations
 *
 * The basic controller and namespace identify operations are a part of the
 * controller and namespace snapshot facilities. These functions are designed to
 * help enumerate and iterate lists of active and inactive namespaces,
 * controllers, and related. The initial interface is a basic form that allows
 * folks to create a request based on one that the library knows about as the
 * kernel doesn't allow unknown requests.
 *
 * Eventually, when the kernel allows for arbitrary identify commands to be
 * issued we can add an nvme_id_req_init() and the ability to set the CSI and
 * CNS.
 */
extern bool nvme_id_req_init_by_cns(nvme_ctrl_t *, nvme_csi_t, uint32_t,
    nvme_id_req_t **);
extern void nvme_id_req_fini(nvme_id_req_t *);

extern bool nvme_id_req_set_nsid(nvme_id_req_t *, uint32_t);
extern bool nvme_id_req_set_ctrlid(nvme_id_req_t *, uint32_t);
extern bool nvme_id_req_set_output(nvme_id_req_t *, void *, size_t);
extern bool nvme_id_req_clear_output(nvme_id_req_t *);
extern bool nvme_id_req_exec(nvme_id_req_t *);

/*
 * NVMe Namespace Discovery
 *
 * Namespaces come in various states. While the controller has a list of
 * namespace IDs. The following enumeration describes namespace information with
 * increasing specificity.
 */
typedef enum {
	/*
	 * This returns all namespaces that are present on the device. This
	 * includes ones that may be ignored by the kernel or more.
	 */
	NVME_NS_DISC_F_ALL = 0,
	/*
	 * Only return namespaces that the controller considers to be allocated.
	 */
	NVME_NS_DISC_F_ALLOCATED,
	/*
	 * Only return namespaces that are active. If the controller does not
	 * support namespace management then all namespaces are considered
	 * active.
	 */
	NVME_NS_DISC_F_ACTIVE,
	/*
	 * The kernel has a notion of a namespace is ignored or not. In general,
	 * this is a subset of active namespaces that can actually be supported.
	 * They may or may not have a blkdev instance attached.
	 */
	NVME_NS_DISC_F_NOT_IGNORED,
	/*
	 * Only return namespaces that have blkdev actively attached. In other
	 * words these are disks that the OS can use.
	 */
	NVME_NS_DISC_F_BLKDEV
} nvme_ns_disc_level_t;

typedef enum nvme_ns_disc_flags {
	NVME_NS_DISC_F_EUI64_VALID	= 1 << 0,
	NVME_NS_DISC_F_NGUID_VALID	= 1 << 1
} nvme_ns_disc_flags_t;

extern uint32_t nvme_ns_disc_nsid(const nvme_ns_disc_t *);
extern nvme_ns_disc_level_t nvme_ns_disc_level(const nvme_ns_disc_t *);
extern nvme_ns_disc_flags_t nvme_ns_disc_flags(const nvme_ns_disc_t *);
extern const uint8_t *nvme_ns_disc_eui64(const nvme_ns_disc_t *);
extern const uint8_t *nvme_ns_disc_nguid(const nvme_ns_disc_t *);

extern bool nvme_ns_discover_init(nvme_ctrl_t *, nvme_ns_disc_level_t,
    nvme_ns_iter_t **);
extern nvme_iter_t nvme_ns_discover_step(nvme_ns_iter_t *,
    const nvme_ns_disc_t **);
extern void nvme_ns_discover_fini(nvme_ns_iter_t *);

typedef bool (*nvme_ns_disc_f)(nvme_ctrl_t *, const nvme_ns_disc_t *, void *);
extern bool nvme_ns_discover(nvme_ctrl_t *, nvme_ns_disc_level_t,
    nvme_ns_disc_f, void *);

extern bool nvme_ns_init(nvme_ctrl_t *, uint32_t, nvme_ns_t **);
extern bool nvme_ns_init_by_name(nvme_ctrl_t *, const char *, nvme_ns_t **);
extern void nvme_ns_fini(nvme_ns_t *);

/*
 * This is a convenience routine for opening up an NVMe controller and/or
 * namespace. Many utilities refer to things as <controller>/<namespace>. As
 * such, this will parse that apart. If no namespace is specified, it will be
 * left as NULL. If the specified controller or namespace cannot be found, then
 * the function will fail.
 *
 * Currently the only supported controller name is nvmeX, though we should
 * support GUIDs at some point. The namespace id, EUI64, and NGUID are all
 * supported for the namespace.
 */
extern bool nvme_ctrl_ns_init(nvme_t *, const char *, nvme_ctrl_t **,
    nvme_ns_t **);

/*
 * NVMe Namespace Information.
 *
 * Namespace information is broken into a few groups. There is basic information
 * about the LBA formats and capacities (which are provided in block sizes).
 * There is information about the IDs. Note the NGUID/EUI64 are fallible
 * because they are optional.
 */
extern bool nvme_ns_info_snap(nvme_ns_t *, nvme_ns_info_t **);
extern bool nvme_ctrl_ns_info_snap(nvme_ctrl_t *, uint32_t, nvme_ns_info_t **);
extern void nvme_ns_info_free(nvme_ns_info_t *);

extern nvme_info_err_t nvme_ns_info_err(nvme_ns_info_t *);
extern int32_t nvme_ns_info_syserr(nvme_ns_info_t *);
extern const char *nvme_ns_info_errmsg(nvme_ns_info_t *);
extern size_t nvme_ns_info_errlen(nvme_ns_info_t *);
extern const char *nvme_ns_info_errtostr(nvme_ns_info_t *, nvme_info_err_t);

extern uint32_t nvme_ns_info_nsid(nvme_ns_info_t *);
extern nvme_ns_disc_level_t nvme_ns_info_level(nvme_ns_info_t *);
extern const nvme_identify_nsid_t *nvme_ns_info_identify(nvme_ns_info_t *);

extern bool nvme_ns_info_nguid(nvme_ns_info_t *, uint8_t [16]);
extern bool nvme_ns_info_eui64(nvme_ns_info_t *, uint8_t [8]);

extern bool nvme_ns_info_size(nvme_ns_info_t *, uint64_t *);
extern bool nvme_ns_info_cap(nvme_ns_info_t *, uint64_t *);
extern bool nvme_ns_info_use(nvme_ns_info_t *, uint64_t *);

extern bool nvme_ns_info_curformat(nvme_ns_info_t *,
    const nvme_nvm_lba_fmt_t **);
extern bool nvme_ns_info_nformats(nvme_ns_info_t *, uint32_t *);
extern bool nvme_ns_info_format(nvme_ns_info_t *, uint32_t,
    const nvme_nvm_lba_fmt_t **);

extern bool nvme_ns_info_bd_addr(nvme_ns_info_t *, const char **);

/*
 * Controller and Namespace Locking
 *
 * A given controller can be active by several different parallel consumers.
 */
extern bool nvme_ctrl_lock(nvme_ctrl_t *, nvme_lock_level_t, nvme_lock_flags_t);
extern void nvme_ctrl_unlock(nvme_ctrl_t *);
extern bool nvme_ns_lock(nvme_ns_t *, nvme_lock_level_t, nvme_lock_flags_t);
extern void nvme_ns_unlock(nvme_ns_t *);

/*
 * Namespace Attach and Detach
 *
 * These operations are used to attach and detach a blkdev device from a given
 * namespace.
 */
extern bool nvme_ns_bd_attach(nvme_ns_t *);
extern bool nvme_ns_bd_detach(nvme_ns_t *);

/*
 * NVMe Log Page Discovery
 *
 * NVMe Log Pages provide some complications around discovery. There are
 * standard log pages, which are either mandatory or optional. There are also
 * vendor-specific log pages that we may know about. While NVMe 2.0 introduced a
 * way to list all of the supported log pages a device implements, that is not
 * true for most devices. Pre 2.x devices sometimes have a vendor-specific way
 * to list all the available logs. The NVMe 2.0 based mechanism also does not
 * provide a means of getting additional information such as required fields, so
 * we'll end up always needing the additional information this interface
 * provides.
 *
 * The log page discovery functions here allow a caller to just ask for all the
 * known IDs that exist for something. The discovery callback will fire once for
 * each log page that may be implemented. Log pages we know that aren't
 * implemented are never called back for.
 */
extern const char *nvme_log_disc_name(const nvme_log_disc_t *);
extern const char *nvme_log_disc_desc(const nvme_log_disc_t *);
extern nvme_csi_t nvme_log_disc_csi(const nvme_log_disc_t *);
extern uint32_t nvme_log_disc_lid(const nvme_log_disc_t *);
extern nvme_log_disc_kind_t nvme_log_disc_kind(const nvme_log_disc_t *);
extern nvme_log_disc_source_t nvme_log_disc_sources(const nvme_log_disc_t *);
extern nvme_log_disc_fields_t nvme_log_disc_fields(const nvme_log_disc_t *);
extern nvme_log_disc_scope_t nvme_log_disc_scopes(const nvme_log_disc_t *);
extern bool nvme_log_disc_impl(const nvme_log_disc_t *);

typedef enum {
	/*
	 * This indicates that the size of a log page is unknown. Instead, we
	 * will return a size that is reasonable enough to hopefully cover most
	 * things.
	 */
	NVME_LOG_SIZE_K_UNKNOWN	= 0,
	/*
	 * This indicates that there is a known fixed size for the log page and
	 * we have indicated what that is.
	 */
	NVME_LOG_SIZE_K_FIXED,
	/*
	 * This indicates that the total log size is variable; however, it can
	 * be determined by reading the specified following number of bytes.
	 * Once that number of bytes has been read, that can be passed to the
	 * nvme_log_disc_cal_size() function, which will attempt to determine
	 * the actual number of bytes based on the returned data.
	 */
	NVME_LOG_SIZE_K_VAR
} nvme_log_size_kind_t;
extern nvme_log_size_kind_t nvme_log_disc_size(const nvme_log_disc_t *,
    uint64_t *);
extern bool nvme_log_disc_calc_size(const nvme_log_disc_t *, uint64_t *,
    const void *, size_t);

/*
 * Duplicate and free log discovery information. The free function should only
 * be used when it is explicitly duplicated or obtained through something like
 * nvme_log_req_init_by_name(). It must not be used on the constant data
 * provided as part of the nvme_log_discover family of functions.
 */
extern bool nvme_log_disc_dup(nvme_ctrl_t *, const nvme_log_disc_t *,
    nvme_log_disc_t **);
extern void nvme_log_disc_free(nvme_log_disc_t *);

extern bool nvme_log_discover_init(nvme_ctrl_t *, nvme_log_disc_scope_t,
    uint32_t, nvme_log_iter_t **);
extern nvme_iter_t nvme_log_discover_step(nvme_log_iter_t *,
    const nvme_log_disc_t **);
extern void nvme_log_discover_fini(nvme_log_iter_t *);

typedef bool (*nvme_log_disc_f)(nvme_ctrl_t *, const nvme_log_disc_t *,
    void *);
extern bool nvme_log_discover(nvme_ctrl_t *, nvme_log_disc_scope_t,
    uint32_t, nvme_log_disc_f, void *);

/*
 * One does not simply request a log page. There are a lot of parameters that
 * are used to get a log page and these have been evolving over time. For
 * example, the size has changed between 1.2 and 1.3, NVMe 1.0 never had UUIDs,
 * LSP, LSIs, there are optional features around supporting offsets, etc.
 *
 * To deal with the fact that this keeps changing and an attempt to create a
 * stable ABI, we instead have an opaque structure that allows various fields to
 * be set and changed. To speed this up, this can be bootstrapped from the
 * discovery information directly or indirectly by the log page short name.
 *
 * Once all of the appropriate fields are set on a log page request then it can
 * be executed. A given request may be executed multiple times.
 *
 * When creating a raw log request, it will be up to the caller to fill in and
 * set up the log ID (lid) and the output information. It is assumed that by
 * default a log request should specify the NVM CSI. When using
 * nvme_log_req_init_by_disc(), the log ID and command set will be filled in
 * automatically. The discovery flags will indicate what other fields are still
 * required.
 */
extern bool nvme_log_req_init(nvme_ctrl_t *, nvme_log_req_t **);
extern bool nvme_log_req_init_by_disc(nvme_ctrl_t *, const nvme_log_disc_t *,
    nvme_log_req_t **);
extern bool nvme_log_req_init_by_name(nvme_ctrl_t *, const char *,
    uint32_t, nvme_log_disc_t **, nvme_log_req_t **);
extern void nvme_log_req_fini(nvme_log_req_t *);

extern bool nvme_log_req_set_lid(nvme_log_req_t *, uint32_t);
extern bool nvme_log_req_set_lsp(nvme_log_req_t *, uint32_t);
extern bool nvme_log_req_set_lsi(nvme_log_req_t *, uint32_t);
extern bool nvme_log_req_set_uuid(nvme_log_req_t *, uint32_t);
extern bool nvme_log_req_set_nsid(nvme_log_req_t *, uint32_t);
extern bool nvme_log_req_set_output(nvme_log_req_t *, void *, size_t);
extern bool nvme_log_req_clear_output(nvme_log_req_t *);
extern bool nvme_log_req_set_offset(nvme_log_req_t *, uint64_t);
extern bool nvme_log_req_set_rae(nvme_log_req_t *, bool);
extern bool nvme_log_req_set_csi(nvme_log_req_t *, nvme_csi_t);
extern bool nvme_log_req_exec(nvme_log_req_t *);

/*
 * Feature Discovery and Management
 *
 * Features are parts of the NVMe specification that can both be retrieved and
 * set. Features are often either a uint32_t or a larger data payload. In
 * addition, there are additional modifiers that are required to select
 * information about features. For example, when getting or setting a
 * temperature threshold feature, a temperature sensor ID is required. Much like
 * with log pages this has changed and added new arguments to getting and
 * setting a feature at the command level and the individual features have grown
 * support for more configuration as well.
 *
 * We currently provide information in discovery to determine what is required
 * to get a feature as well as the ability to fast path that. Currently we
 * provide the raw feature getting API that works at the low level. There is no
 * higher level API for specific features. This works okay for an nvmeadm(8)
 * style implementation, but we should consider adding more here based on
 * feedback from consumers.
 *
 * Currently the kernel does not support setting features, which is why there is
 * not a set feature API exposed through here. When it is, there will be an
 * analogues set feature API to the get feature API that allows for one to
 * build this up generically.
 */
extern const char *nvme_feat_disc_short(const nvme_feat_disc_t *);
extern const char *nvme_feat_disc_spec(const nvme_feat_disc_t *);
extern uint32_t nvme_feat_disc_fid(const nvme_feat_disc_t *);
extern nvme_feat_scope_t nvme_feat_disc_scope(const nvme_feat_disc_t *);
extern nvme_feat_kind_t nvme_feat_disc_kind(const nvme_feat_disc_t *);
extern nvme_feat_csi_t nvme_feat_disc_csi(const nvme_feat_disc_t *);
extern nvme_feat_flags_t nvme_feat_disc_flags(const nvme_feat_disc_t *);
extern nvme_get_feat_fields_t nvme_feat_disc_fields_get(
    const nvme_feat_disc_t *);
extern nvme_set_feat_fields_t nvme_feat_disc_fields_set(
    const nvme_feat_disc_t *);
extern nvme_feat_output_t nvme_feat_disc_output_get(const nvme_feat_disc_t *);
extern nvme_feat_output_t nvme_feat_disc_output_set(const nvme_feat_disc_t *);
extern uint64_t nvme_feat_disc_data_size(const nvme_feat_disc_t *);
extern nvme_feat_impl_t nvme_feat_disc_impl(const nvme_feat_disc_t *);

extern bool nvme_feat_discover_init(nvme_ctrl_t *, nvme_feat_scope_t, uint32_t,
    nvme_feat_iter_t **);
extern nvme_iter_t nvme_feat_discover_step(nvme_feat_iter_t *,
    const nvme_feat_disc_t **);
extern void nvme_feat_discover_fini(nvme_feat_iter_t *);

extern bool nvme_feat_disc_dup(nvme_ctrl_t *, const nvme_feat_disc_t *,
    nvme_feat_disc_t **);
extern void nvme_feat_disc_free(nvme_feat_disc_t *);

typedef bool (*nvme_feat_disc_f)(nvme_ctrl_t *, const nvme_feat_disc_t *,
    void *);
extern bool nvme_feat_discover(nvme_ctrl_t *, nvme_feat_scope_t, uint32_t,
    nvme_feat_disc_f, void *);

/*
 * Get Feature Request
 *
 * The get feature request allows one to build up a get feature command. It is
 * recommended to initiate a request based on discovery information or a
 * feature's name. That will allow the system to perform better validation, know
 * what fields are required or not, and pre-set parameters like the feature id
 * (fid). By default, a get features request will always ask for the current
 * value. Unless you want a saved or default value (and the controller is new
 * enough), then there is no need to set the selector. The only required field
 * when not using discovery information is the fid.
 */
extern bool nvme_get_feat_req_init(nvme_ctrl_t *, nvme_get_feat_req_t **);
extern bool nvme_get_feat_req_init_by_disc(nvme_ctrl_t *,
    const nvme_feat_disc_t *, nvme_get_feat_req_t **);
extern bool nvme_get_feat_req_init_by_name(nvme_ctrl_t *, const char *,
    uint32_t, nvme_feat_disc_t **, nvme_get_feat_req_t **);
extern void nvme_get_feat_req_fini(nvme_get_feat_req_t *);

extern bool nvme_get_feat_req_set_fid(nvme_get_feat_req_t *, uint32_t);
extern bool nvme_get_feat_req_set_sel(nvme_get_feat_req_t *, uint32_t);
extern bool nvme_get_feat_req_set_nsid(nvme_get_feat_req_t *, uint32_t);
extern bool nvme_get_feat_req_set_cdw11(nvme_get_feat_req_t *, uint32_t);
extern bool nvme_get_feat_req_set_output(nvme_get_feat_req_t *, void *, size_t);
extern bool nvme_get_feat_req_clear_output(nvme_get_feat_req_t *);
extern bool nvme_get_feat_req_exec(nvme_get_feat_req_t *);
extern bool nvme_get_feat_req_get_cdw0(nvme_get_feat_req_t *, uint32_t *);

/*
 * NVMe Vendor Unique Command Discovery and Execution
 *
 * There is a standard form of vendor unique commands which are indicated in the
 * identify controller datasheet. The first set of pieces here allows one to
 * discover which vendor-specific commands are supported by a device that are
 * known to the library. These generally have their own implementation
 * function; however, that isn't really linked to from the discovery function.
 * Tied into this is also asking if a given controller supports a given command
 * and getting information about it.
 *
 * The second set of functions here is all around allocating a vendor unique
 * command then executing it. Currently only admin commands are supported
 * through this interface.
 */
extern bool nvme_vuc_discover_init(nvme_ctrl_t *, uint32_t,
    nvme_vuc_iter_t **);
extern nvme_iter_t nvme_vuc_discover_step(nvme_vuc_iter_t *,
    const nvme_vuc_disc_t **);
extern void nvme_vuc_discover_fini(nvme_vuc_iter_t *);

typedef bool (*nvme_vuc_disc_f)(nvme_ctrl_t *, const nvme_vuc_disc_t *, void *);
extern bool nvme_vuc_discover(nvme_ctrl_t *, uint32_t, nvme_vuc_disc_f, void *);

extern bool nvme_vuc_discover_by_name(nvme_ctrl_t *, const char *, uint32_t,
    nvme_vuc_disc_t **);
extern bool nvme_vuc_disc_dup(nvme_ctrl_t *, const nvme_vuc_disc_t *,
    nvme_vuc_disc_t **);
extern void nvme_vuc_disc_free(nvme_vuc_disc_t *);

extern const char *nvme_vuc_disc_name(const nvme_vuc_disc_t *);
extern const char *nvme_vuc_disc_desc(const nvme_vuc_disc_t *);
extern uint32_t nvme_vuc_disc_opcode(const nvme_vuc_disc_t *);

typedef enum {
	/*
	 * Indicates that when this command is run, one should assume that all
	 * data is potentially erased.
	 */
	NVME_VUC_DISC_IMPACT_DATA	= 1 << 0,
	/*
	 * Indicates that when this command is run, one should assume that the
	 * list of namespaces and their attributes will change.
	 */
	NVME_VUC_DISC_IMPACT_NS		= 1 << 1
} nvme_vuc_disc_impact_t;
extern nvme_vuc_disc_impact_t nvme_vuc_disc_impact(const nvme_vuc_disc_t *);

typedef enum {
	NVME_VUC_DISC_IO_NONE	= 0,
	/*
	 * Indicates that this command needs additional data provided as input
	 * to the command.
	 */
	NVME_VUC_DISC_IO_INPUT	= 1 << 0,
	/*
	 * Indicates that this command writes output back to the host from the
	 * controller and a data buffer is required.
	 */
	NVME_VUC_DISC_IO_OUTPUT	= 1 << 1
} nvme_vuc_disc_io_t;
extern nvme_vuc_disc_io_t nvme_vuc_disc_dt(const nvme_vuc_disc_t *);

typedef enum {
	/*
	 * Indicates that the library has no opinion on whether a lock should be
	 * taken or not.
	 */
	NVME_VUC_DISC_LOCK_NONE	= 0,
	/*
	 * Indicates that a controller or namespace level read lock is
	 * recommended for this operation.
	 */
	NVME_VUC_DISC_LOCK_READ,
	/*
	 * Indicates that a controller or namespace level write lock is
	 * recommended for this operation.
	 */
	NVME_VUC_DISC_LOCK_WRITE
} nvme_vuc_disc_lock_t;
extern nvme_vuc_disc_lock_t nvme_vuc_disc_lock(const nvme_vuc_disc_t *);

extern bool nvme_vuc_req_init(nvme_ctrl_t *, nvme_vuc_req_t **);
extern void nvme_vuc_req_fini(nvme_vuc_req_t *);

extern bool nvme_vuc_req_set_opcode(nvme_vuc_req_t *, uint32_t);
extern bool nvme_vuc_req_set_nsid(nvme_vuc_req_t *, uint32_t);
extern bool nvme_vuc_req_set_timeout(nvme_vuc_req_t *, uint32_t);
extern bool nvme_vuc_req_set_cdw12(nvme_vuc_req_t *, uint32_t);
extern bool nvme_vuc_req_set_cdw13(nvme_vuc_req_t *, uint32_t);
extern bool nvme_vuc_req_set_cdw14(nvme_vuc_req_t *, uint32_t);
extern bool nvme_vuc_req_set_cdw15(nvme_vuc_req_t *, uint32_t);
extern bool nvme_vuc_req_set_impact(nvme_vuc_req_t *, nvme_vuc_disc_impact_t);
extern bool nvme_vuc_req_set_input(nvme_vuc_req_t *, const void *, size_t);
extern bool nvme_vuc_req_set_output(nvme_vuc_req_t *, void *, size_t);
extern bool nvme_vuc_req_clear_output(nvme_vuc_req_t *);

/*
 * Execute a request. After a request is executed, the status information
 * becomes available. A call to exec will invalidate any prior results. If the
 * request does not make it to the controller for some reason or some other
 * error occurs, then getting the results will fail. If the controller fails the
 * command, that will set the NVME_ERR_CONTROLLER error and the corresponding
 * SCT/SC values can be retrieved from the controller's error information for
 * inspection.
 */
extern bool nvme_vuc_req_exec(nvme_vuc_req_t *);
extern bool nvme_vuc_req_get_cdw0(nvme_vuc_req_t *, uint32_t *);

/*
 * Firmware Download and Commit (Activation)
 *
 * NVMe devices have a buffer that is used to receive a firmware download. This
 * can then be committed into a firmware slot or a boot slot through the commit
 * action. The commit action may also change which firmware slot is activated on
 * the next boot at the same time as installing an image or a commit can be used
 * to just change the active image. The optional bootloader features will have a
 * similar shape as to the firmware commit routines, but ultimately be different
 * ones to make it more obvious what is being done.
 *
 * The firmware download command has to date not really changed through the NVMe
 * 1.x and 2.0 standards, which is why it is not broken into a request and
 * execution format like others at this time.
 *
 * Firmware must be loaded with a particular granularity and if blocks do not
 * conform to that, nvme_fw_load() will return an error.
 */
extern bool nvme_fw_load(nvme_ctrl_t *, const void *, size_t, uint64_t);

extern bool nvme_fw_commit_req_init(nvme_ctrl_t *, nvme_fw_commit_req_t **);
extern void nvme_fw_commit_req_fini(nvme_fw_commit_req_t *);
extern bool nvme_fw_commit_req_set_slot(nvme_fw_commit_req_t *, uint32_t);
extern bool nvme_fw_commit_req_set_action(nvme_fw_commit_req_t *, uint32_t);
extern bool nvme_fw_commit_req_exec(nvme_fw_commit_req_t *);

/*
 * Format NVM
 *
 * This is used to erase and reformat either all namespaces or a specific one.
 * We currently do not support setting metadata or protection information for
 * namespaces in the kernel which is why this is not present in the library.
 */
extern bool nvme_format_req_init(nvme_ctrl_t *, nvme_format_req_t **);
extern void nvme_format_req_fini(nvme_format_req_t *);
extern bool nvme_format_req_set_lbaf(nvme_format_req_t *, uint32_t);
extern bool nvme_format_req_set_ses(nvme_format_req_t *, uint32_t);
extern bool nvme_format_req_set_nsid(nvme_format_req_t *, uint32_t);
extern bool nvme_format_req_exec(nvme_format_req_t *);

/*
 * Vendor-specific interfaces.
 */

/*
 * WDC resizing functions. These are interfaces supported in the SN840, SN650,
 * SN655, etc. These end up allowing one to adjust the overprovisioning ratio,
 * though this ends up reformatting the device and all namespaces in the
 * process. The values passed and returned are in GB (not GiB).
 */
extern bool nvme_wdc_resize_set(nvme_ctrl_t *, uint32_t);
extern bool nvme_wdc_resize_get(nvme_ctrl_t *, uint32_t *);

/*
 * WDC e6 diagnostic log. The e6 log is a WDC-specific diagnostic log which
 * contains information about the device itself.
 */
extern bool nvme_wdc_e6_req_init(nvme_ctrl_t *, nvme_wdc_e6_req_t **);
extern void nvme_wdc_e6_req_fini(nvme_wdc_e6_req_t *);
extern bool nvme_wdc_e6_req_set_offset(nvme_wdc_e6_req_t *, uint64_t);
extern bool nvme_wdc_e6_req_set_output(nvme_wdc_e6_req_t *, void *,
    size_t);
extern bool nvme_wdc_e6_req_clear_output(nvme_wdc_e6_req_t *);
extern bool nvme_wdc_e6_req_exec(nvme_wdc_e6_req_t *);

/*
 * WDC assert injection and removal.
 */
extern bool nvme_wdc_assert_clear(nvme_ctrl_t *);
extern bool nvme_wdc_assert_inject(nvme_ctrl_t *);

#ifdef __cplusplus
}
#endif

#endif /* _LIBNVME_H */
