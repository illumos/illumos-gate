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
 * Copyright 2016 Nexenta Systems, Inc.
 * Copyright 2020 Joyent, Inc.
 * Copyright 2019 Western Digital Corporation
 * Copyright 2025 Oxide Computer Company
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef _SYS_NVME_H
#define	_SYS_NVME_H

#include <sys/types.h>
#include <sys/debug.h>
#include <sys/stddef.h>

#ifdef _KERNEL
#include <sys/types32.h>
#else
#include <sys/uuid.h>
#include <stdint.h>
#endif

/*
 * Declarations used for communication between nvme(4D) and libnvme.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * NVMe ioctl definitions
 */

#define	NVME_IOC			(('N' << 24) | ('V' << 16) | ('M' << 8))
#define	NVME_IOC_CTRL_INFO		(NVME_IOC | 0)
#define	NVME_IOC_IDENTIFY		(NVME_IOC | 1)
#define	NVME_IOC_GET_LOGPAGE		(NVME_IOC | 2)
#define	NVME_IOC_GET_FEATURE		(NVME_IOC | 3)
#define	NVME_IOC_FORMAT			(NVME_IOC | 4)
#define	NVME_IOC_BD_DETACH		(NVME_IOC | 5)
#define	NVME_IOC_BD_ATTACH		(NVME_IOC | 6)
#define	NVME_IOC_FIRMWARE_DOWNLOAD	(NVME_IOC | 7)
#define	NVME_IOC_FIRMWARE_COMMIT	(NVME_IOC | 8)
#define	NVME_IOC_PASSTHRU		(NVME_IOC | 9)
#define	NVME_IOC_NS_INFO		(NVME_IOC | 10)
#define	NVME_IOC_LOCK			(NVME_IOC | 11)
#define	NVME_IOC_UNLOCK			(NVME_IOC | 12)
#define	NVME_IOC_CTRL_ATTACH		(NVME_IOC | 13)
#define	NVME_IOC_CTRL_DETACH		(NVME_IOC | 14)
#define	NVME_IOC_NS_CREATE		(NVME_IOC | 15)
#define	NVME_IOC_NS_DELETE		(NVME_IOC | 16)
#define	NVME_IOC_MAX			NVME_IOC_NS_DELETE

#define	IS_NVME_IOC(x)			((x) > NVME_IOC && (x) <= NVME_IOC_MAX)
#define	NVME_IOC_CMD(x)			((x) & 0xff)

/*
 * This represents the set of all possible errors that can be returned from an
 * ioctl. Our general rule of thumb is that we only will use an errno value to
 * indicate that certain processing failed: a lack of privileges, bad minor, or
 * failure to copy in and out the initial ioctl structure. However, if we get
 * far enough that there is any other failure (including a failure to copy in
 * and out nested data such as the identify command payload) then we will issue
 * an error here. Put differently, our basic promise is that there should be a
 * single straightforward meaning for any errno returned and instead all the
 * nuance is here. Our goal is that no one should guess what of two dozen things
 * an EINVAL might have referred to.
 *
 * When we are dealing with field parameters, there are three general classes of
 * errors that we define that are common across all request structures:
 *
 *   <REQ>_<FIELD>_RANGE	RANGE class errors indicate that the value
 *				passed in is outside the range that the device
 *				supports. The range may vary based on the
 *				specification. This is used both for issues like
 *				bad alignment in a value (e.g. not 4-byte
 *				aligned) or a value that is larger than the
 *				maximum possible size. Because the namespace ID
 *				is shared in every request in the controller and
 *				is part of our standard ioctl handling, we use a
 *				single set of errors for that.
 *
 *   <REQ>_<FIELD>_UNSUP	This indicates that the controller cannot
 *				support any value in the given field. This is
 *				either because the field was introduced in an
 *				NVMe specification later than the controller
 *				supports or because there is an explicit feature
 *				bit that indicates whether or not this field is
 *				valid. Entries here may or may not have a
 *				namespace unsupported entry due to the fact that
 *				this is command specific.
 *
 *  <REQ>_<FIELD>_UNUSE		This class is perhaps the weirdest. This
 *				represents a case where a given field cannot be
 *				set because it is not used based on the
 *				specifics of the request. For example, if you're
 *				getting the health log page, you may not set the
 *				LSP or LSI for that log page, even if you have
 *				an NVMe 1.4 controller that supports both fields
 *				because they have no meaning. A similar example
 *				would be setting a controller ID when it has no
 *				meaning in a particular identify request.
 *
 * While every field will have a RANGE class error, some fields will not have an
 * UNSUP or UNUSE class error depending on the specifics. A field that has
 * always been present since NVMe 1.0 and is always valid, such as say the log
 * page ID field for a get log page request or the length of a firmware download
 * request, currently are always valid. It is possible that future revisions to
 * the specification or our logic may change this.
 */
typedef enum {
	/*
	 * Indicates that the command actually completed successfully.
	 */
	NVME_IOCTL_E_OK	= 0,
	/*
	 * Indicates that the controller failed the command and the controller
	 * specific (SC/SCT) are available. For all other errors, those fields
	 * are reserved.
	 */
	NVME_IOCTL_E_CTRL_ERROR,
	/*
	 * Indicates that the controller is considered "dead" by the system and
	 * therefore is unusable. Separately, the controller may have been
	 * removed from the system due to hotplug or related. In that case, the
	 * gone variant is used to distinguish this.
	 */
	NVME_IOCTL_E_CTRL_DEAD,
	NVME_IOCTL_E_CTRL_GONE,
	/*
	 * Indicates that a bad namespace was requested. This would generally
	 * happen when referring to a namespace that is outside of controller's
	 * range.
	 */
	NVME_IOCTL_E_NS_RANGE,
	/*
	 * Indicates that a namespace is not usable in this context.
	 */
	NVME_IOCTL_E_NS_UNUSE,
	/*
	 * Indicates that the requested namespace could not be used because we
	 * are operating on a namespace minor and asked to operate on a
	 * different namespace.
	 */
	NVME_IOCTL_E_MINOR_WRONG_NS,
	/*
	 * Indicates that the requested ioctl can only operate on the controller
	 * minor and we were on a namespace minor. This is not used for when a
	 * namespace is incorrectly requested otherwise.
	 */
	NVME_IOCTL_E_NOT_CTRL,
	/*
	 * Indicates that we were asked to operate on the broadcast namespace
	 * either because it was specified or that was how the request was
	 * transformed and the broadcast namespace is not supported for this
	 * operation.
	 */
	NVME_IOCTL_E_NO_BCAST_NS,
	/*
	 * Indicates that the operation failed because the operation requires a
	 * controller or namespace write lock and the caller did not have it.
	 */
	NVME_IOCTL_E_NEED_CTRL_WRLOCK,
	NVME_IOCTL_E_NEED_NS_WRLOCK,
	/*
	 * Indicates that the operation could not proceed because someone else
	 * has exclusive access currently to the controller or namespace and
	 * therefore this request (which does not require exclusive access)
	 * could not proceed.
	 */
	NVME_IOCTL_E_CTRL_LOCKED,
	NVME_IOCTL_E_NS_LOCKED,
	/*
	 * Indicates that a standard log page was requested that the kernel
	 * doesn't know about.
	 */
	NVME_IOCTL_E_UNKNOWN_LOG_PAGE,
	/*
	 * Indicates that the controller does not support the requested log
	 * page; however, the kernel knows about it.
	 */
	NVME_IOCTL_E_UNSUP_LOG_PAGE,
	/*
	 * Indicates that the log page's scope requires operating on something
	 * that isn't what was requested. For example, trying to request the
	 * firmware information page on a namespace.
	 */
	NVME_IOCTL_E_BAD_LOG_SCOPE,
	/*
	 * Log page fields with bad values.
	 */
	NVME_IOCTL_E_LOG_CSI_RANGE,
	NVME_IOCTL_E_LOG_LID_RANGE,
	NVME_IOCTL_E_LOG_LSP_RANGE,
	NVME_IOCTL_E_LOG_LSI_RANGE,
	NVME_IOCTL_E_LOG_RAE_RANGE,
	NVME_IOCTL_E_LOG_SIZE_RANGE,
	NVME_IOCTL_E_LOG_OFFSET_RANGE,
	/*
	 * Log page fields that may not be supported.
	 */
	NVME_IOCTL_E_LOG_CSI_UNSUP,
	NVME_IOCTL_E_LOG_LSP_UNSUP,
	NVME_IOCTL_E_LOG_LSI_UNSUP,
	NVME_IOCTL_E_LOG_RAE_UNSUP,
	NVME_IOCTL_E_LOG_OFFSET_UNSUP,
	/*
	 * Log page fields that may not be usable, depending on context.
	 */
	NVME_IOCTL_E_LOG_LSP_UNUSE,
	NVME_IOCTL_E_LOG_LSI_UNUSE,
	NVME_IOCTL_E_LOG_RAE_UNUSE,
	/*
	 * Indicates that no DMA memory was available for a request.
	 */
	NVME_IOCTL_E_NO_DMA_MEM,
	/*
	 * Indicates that there was no kernel memory avilable for the request.
	 */
	NVME_IOCTL_E_NO_KERN_MEM,
	/*
	 * Indicates that an error occurred while trying to fill out the DMA PRP
	 */
	NVME_IOCTL_E_BAD_PRP,
	/*
	 * Indicates that a pointer to user data to read from or write to was
	 * not valid and generated a fault. Specifically this is for items that
	 * an ioctl structure points to.
	 */
	NVME_IOCTL_E_BAD_USER_DATA,
	/*
	 * Indicates that the kernel does not know about the requested identify
	 * command.
	 */
	NVME_IOCTL_E_UNKNOWN_IDENTIFY,
	/*
	 * Indicates that the controller does not support the requested identify
	 * command.
	 */
	NVME_IOCTL_E_UNSUP_IDENTIFY,
	/*
	 * The following errors indicate either a bad value for a given identify
	 * argument. This would happen because the value is outside the
	 * supported range. There is no CNS or below as those are the
	 * higher-level errors right above this.
	 */
	NVME_IOCTL_E_IDENTIFY_CTRLID_RANGE,
	/*
	 * Next, we have the unsupported and unusable pieces. The nsid was
	 * supported starting in NVMe 1.0, therefore it is never unsupported.
	 * However, the controller ID both requires controller support and is
	 * not usable in several requests.
	 */
	NVME_IOCTL_E_IDENTIFY_CTRLID_UNSUP,
	NVME_IOCTL_E_IDENTIFY_CTRLID_UNUSE,
	/*
	 * Indicates that the controller does not support the NVMe spec's
	 * general vendor unique command format.
	 */
	NVME_IOCTL_E_CTRL_VUC_UNSUP,
	/*
	 * The following indicate bad values for given NVMe vendor unique
	 * command fields. All of the cdw1[2-5] fields are not part of this
	 * because there is nothing that we can validate.
	 */
	NVME_IOCTL_E_VUC_TIMEOUT_RANGE,
	NVME_IOCTL_E_VUC_OPCODE_RANGE,
	NVME_IOCTL_E_VUC_FLAGS_RANGE,
	NVME_IOCTL_E_VUC_IMPACT_RANGE,
	NVME_IOCTL_E_VUC_NDT_RANGE,
	/*
	 * These indicate that the VUC data and that the corresponding pair of
	 * fields do not agree with each other.
	 */
	NVME_IOCTL_E_INCONSIST_VUC_FLAGS_NDT,
	NVME_IOCTL_E_INCONSIST_VUC_BUF_NDT,
	/*
	 * Indicates that the operation in question did not succeed because
	 * blkdev failed to detach. Most often this happens because the device
	 * node is busy. Reasons the device node could be busy include that the
	 * device is in a zpool, a file system is mounted, a process has the
	 * block device open, etc.
	 */
	NVME_IOCTL_E_BLKDEV_DETACH,
	/*
	 * Indicates that the operation in question failed because we were
	 * unable to create and online a new blkdev child.
	 */
	NVME_IOCTL_E_BLKDEV_ATTACH,
	/*
	 * Indicates that the namespace requested for an attach is not supported
	 * by the system. This would happen due to properties of the namespace
	 * itself (e.g. utilizing metadata sectors).
	 */
	NVME_IOCTL_E_UNSUP_ATTACH_NS,
	/*
	 * Indicates that the format operation is not supported by the
	 * controller at all.
	 */
	NVME_IOCTL_E_CTRL_FORMAT_UNSUP,
	/*
	 * Indicates that the controller does not support the ability to perform
	 * a cryptographic secure erase.
	 */
	NVME_IOCTL_E_CTRL_CRYPTO_SE_UNSUP,
	/*
	 * Indicates that a format operation is targeting a namespace, but
	 * cannot be performed because it does not support formatting an
	 * individual namespace or performing a secure-erase of an individual
	 * namespace respectively.
	 */
	NVME_IOCTL_E_CTRL_NS_FORMAT_UNSUP,
	NVME_IOCTL_E_CTRL_NS_SE_UNSUP,
	/*
	 * The following indicate bad values for a format NVM request.
	 */
	NVME_IOCTL_E_FORMAT_LBAF_RANGE,
	NVME_IOCTL_E_FORMAT_SES_RANGE,
	/*
	 * Indicates that the requested LBA format is not supported due to its
	 * use of metadata.
	 */
	NVME_IOCTL_E_UNSUP_LBAF_META,
	/*
	 * Indicates that the firmware commands are not supported by the
	 * controller at all.
	 */
	NVME_IOCTL_E_CTRL_FW_UNSUP,
	/*
	 * Indicates that the controller has reported a firmware update
	 * granularity that exceeds the calculated / driver supported maximum
	 * DMA transfer size. As such we cannot perform this operation.
	 */
	NVME_IOCTL_E_FW_LOAD_IMPOS_GRAN,
	/*
	 * The following indicate bad values for a firmware load's length and
	 * offset.
	 */
	NVME_IOCTL_E_FW_LOAD_LEN_RANGE,
	NVME_IOCTL_E_FW_LOAD_OFFSET_RANGE,
	/*
	 * The following indicate bad values for a firmware commit's slot and
	 * action.
	 */
	NVME_IOCTL_E_FW_COMMIT_SLOT_RANGE,
	NVME_IOCTL_E_FW_COMMIT_ACTION_RANGE,
	/*
	 * Indicates that an explicit attempt was made to download an image into
	 * a read-only slot. Note, some instances of this cannot be caught prior
	 * to issuing a command to the controller (commit action 0b11 as it can
	 * be used whether there is or isn't a staged image) and will result in
	 * a controller error.
	 */
	NVME_IOCTL_E_RO_FW_SLOT,
	/*
	 * Indicates that the kernel doesn't know about the NVMe feature in
	 * question and therefore cannot proceed.
	 */
	NVME_IOCTL_E_UNKNOWN_FEATURE,
	/*
	 * Indicates that while the system knows about the feature in question,
	 * it is not supported by the controller.
	 */
	NVME_IOCTL_E_UNSUP_FEATURE,
	/*
	 * The following errors indicate a bad value for a given get feature
	 * field. This would happen because the value is outside the supported
	 * range.
	 */
	NVME_IOCTL_E_GET_FEAT_SEL_RANGE,
	NVME_IOCTL_E_GET_FEAT_CDW11_RANGE,
	NVME_IOCTL_E_GET_FEAT_DATA_RANGE,
	/*
	 * This set of errors indicate that the field is not supported. This can
	 * happen because a given get feature command doesn't support setting
	 * this value, the field isn't supported in this revision of the
	 * controller, or similar issues.
	 */
	NVME_IOCTL_E_GET_FEAT_SEL_UNSUP,
	/*
	 * Fields that may be circumstantially unusable.
	 */
	NVME_IOCTL_E_GET_FEAT_CDW11_UNUSE,
	NVME_IOCTL_E_GET_FEAT_DATA_UNUSE,
	/*
	 * The following errors indicate a bad lock type.
	 */
	NVME_IOCTL_E_BAD_LOCK_ENTITY,
	NVME_IOCTL_E_BAD_LOCK_LEVEL,
	NVME_IOCTL_E_BAD_LOCK_FLAGS,
	/*
	 * Indicates that a namespace open cannot lock or unlock a controller.
	 */
	NVME_IOCTL_E_NS_CANNOT_LOCK_CTRL,
	NVME_IOCTL_E_NS_CANNOT_UNLOCK_CTRL,
	/*
	 * Indicates that this lock is already held by the caller.
	 */
	NVME_IOCTL_E_LOCK_ALREADY_HELD,
	/*
	 * Indicates that we cannot take the controller lock, because the
	 * caller already has an active namespace lock.
	 */
	NVME_IOCTL_E_LOCK_NO_CTRL_WITH_NS,
	/*
	 * Indicates that we cannot take a namespace lock because a controller
	 * write lock already exists.
	 */
	NVME_IOCTL_LOCK_NO_NS_WITH_CTRL_WRLOCK,
	/*
	 * Indicates that we cannot take a namespace lock because we already
	 * have one.
	 */
	NVME_IOCTL_E_LOCK_NO_2ND_NS,
	/*
	 * Indicate that a blocking wait for a lock was interrupted due to a
	 * signal.
	 */
	NVME_IOCTL_E_LOCK_WAIT_SIGNAL,
	/*
	 * Indicates that the lock could not be acquired because it was already
	 * held and we were asked not to block on the lock.
	 */
	NVME_IOCTL_E_LOCK_WOULD_BLOCK,
	/*
	 * Indicates that the lock operation could not proceed because the minor
	 * is already blocking on another lock operation.
	 */
	NVME_IOCTL_E_LOCK_PENDING,
	/*
	 * Indicates that the requested lock could not be unlocked because it is
	 * not held. The minor may not hold the lock or it may be blocking for
	 * acquisition.
	 */
	NVME_IOCTL_E_LOCK_NOT_HELD,
	/*
	 * Indicates that the requested lock could not be unlocked because the
	 * namespace requested is not the namespace that is currently locked.
	 */
	NVME_IOCTL_E_LOCK_WRONG_NS,
	/*
	 * Indicates that the request could not proceed because a namespace is
	 * attached to blkdev. This would block a format operation, a vendor
	 * unique command that indicated that it would impact all namespaces,
	 * etc.
	 */
	NVME_IOCTL_E_NS_BLKDEV_ATTACH,
	/*
	 * Indicates that the blkdev address somehow would have overflowed our
	 * internal buffer.
	 */
	NVME_IOCTL_E_BD_ADDR_OVER,
	/*
	 * Indicates that Namespace Management commands are not supported by the
	 * controller at all.
	 */
	NVME_IOCTL_E_CTRL_NS_MGMT_UNSUP,
	/*
	 * Indicates that the request could not proceed because the namespace is
	 * currently attached to a controller.
	 */
	NVME_IOCTL_E_NS_CTRL_ATTACHED,
	NVME_IOCTL_E_NS_CTRL_NOT_ATTACHED,
	/*
	 * This indicates that the namespace ID is valid; however, there is no
	 * namespace actually allocated for this ID. For example, when trying to
	 * attach or detach a controller to an unallocated namespace.
	 *
	 * When a namespace ID is invalid, the kernel will generally instead
	 * return NVME_IOCTL_E_NS_RANGE.
	 */
	NVME_IOCTL_E_NS_NO_NS,
	/*
	 * Namespace Create fields with bad values
	 */
	NVME_IOCTL_E_NS_CREATE_NSZE_RANGE,
	NVME_IOCTL_E_NS_CREATE_NCAP_RANGE,
	NVME_IOCTL_E_NS_CREATE_CSI_RANGE,
	NVME_IOCTL_E_NS_CREATE_FLBAS_RANGE,
	NVME_IOCTL_E_NS_CREATE_NMIC_RANGE,
	/*
	 * Namespace Create fields with unsupported versions. Currently this can
	 * only apply to the CSI. Note, there aren't unusable errors yet;
	 * however, that'll change when we support other CSI types.
	 */
	NVME_IOCTL_E_NS_CREATE_CSI_UNSUP,
	/*
	 * We may have a valid CSI, but not support it at our end. This error
	 * indicates that. Similarly, the device may not support thin
	 * provisioning.
	 */
	NVME_IOCTL_E_DRV_CSI_UNSUP,
	NVME_IOCTL_E_CTRL_THIN_PROV_UNSUP
} nvme_ioctl_errno_t;

/*
 * This structure is embedded as the first item of every ioctl. It is also used
 * directly for the following ioctls:
 *
 *  - blkdev attach (NVME_IOC_ATTACH)
 *  - blkdev detach (NVME_IOC_DETACH)
 *  - controller attach (NVME_IOC_CTRL_ATTACH)
 *  - controller detach (NVME_IOC_CTRL_DETACH)
 *  - namespace delete (NVME_IOC_NS_DELETE)
 */
typedef struct {
	/*
	 * This allows one to specify the namespace ID that the ioctl may
	 * target, if it supports it. This field may be left to zero to indicate
	 * that the current open device (whether the controller or a namespace)
	 * should be targeted. If a namespace is open, a value other than 0 or
	 * the current namespace's ID is invalid.
	 */
	uint32_t nioc_nsid;
	/*
	 * These next three values represent a possible error that may have
	 * occurred. On every ioctl nioc_drv_err is set to a value from the
	 * nvme_ioctl_errno_t enumeration. Anything other than NVME_IOCTL_E_OK
	 * indicates a failure of some kind. Some error values will put
	 * supplemental information in sct and sc. For example,
	 * NVME_IOCTL_E_CTRL_ERROR uses that as a way to return the raw error
	 * values from the controller for someone to inspect. Others may use
	 * this for their own well-defined supplemental information.
	 */
	uint32_t nioc_drv_err;
	uint32_t nioc_ctrl_sct;
	uint32_t nioc_ctrl_sc;
} nvme_ioctl_common_t;

/*
 * NVMe Identify Command (NVME_IOC_IDENTIFY).
 */
typedef struct {
	nvme_ioctl_common_t nid_common;
	uint32_t nid_cns;
	uint32_t nid_ctrlid;
	uintptr_t nid_data;
} nvme_ioctl_identify_t;

/*
 * The following constants describe the maximum values that may be used in
 * various identify requests.
 */
#define	NVME_IDENTIFY_MAX_CTRLID	0xffff
#define	NVME_IDENTIFY_MAX_NSID		0xffffffff
#define	NVME_IDENTIFY_MAX_CNS_1v2	0xff
#define	NVME_IDENTIFY_MAX_CNS_1v1	0x3
#define	NVME_IDENTIFY_MAX_CNS		0x1

/*
 * Get a specific feature (NVME_IOC_GET_FEATURE).
 */
typedef struct {
	nvme_ioctl_common_t nigf_common;
	uint32_t nigf_fid;
	uint32_t nigf_sel;
	uint32_t nigf_cdw11;
	uintptr_t nigf_data;
	uint64_t nigf_len;
	uint32_t nigf_cdw0;
} nvme_ioctl_get_feature_t;

/*
 * Feature maximums.
 */
#define	NVME_FEAT_MAX_FID	0xff
#define	NVME_FEAT_MAX_SEL	0x3

/*
 * Get a specific log page (NVME_IOC_GET_LOGPAGE). By default, unused fields
 * should be left at zero. The input data length is specified by nigl_len, in
 * bytes. The NVMe specification does not provide a way for a controller to
 * write less bytes than requested for a log page. It is undefined behavior if a
 * log page read requests more data than is supported. If this is successful,
 * nigl_len bytes will be copied out.
 */
typedef struct {
	nvme_ioctl_common_t nigl_common;
	uint32_t nigl_csi;
	uint32_t nigl_lid;
	uint32_t nigl_lsp;
	uint32_t nigl_lsi;
	uint32_t nigl_rae;
	uint64_t nigl_len;
	uint64_t nigl_offset;
	uintptr_t nigl_data;
} nvme_ioctl_get_logpage_t;

/*
 * The following constants describe the maximum values for fields that used in
 * the log page request. Note, some of these change with the version. These
 * values are inclusive. The default max is the lowest common value. Larger
 * values are included here. While these values are what the command set
 * maximums are, the device driver may support smaller minimums (e.g. for size).
 */
#define	NVME_LOG_MAX_LID	0xff
#define	NVME_LOG_MAX_LSP	0x0f
#define	NVME_LOG_MAX_LSP_2v0	0x7f
#define	NVME_LOG_MAX_LSI	0xffff
#define	NVME_LOG_MAX_UUID	0x7f
#define	NVME_LOG_MAX_CSI	0xff
#define	NVME_LOG_MAX_RAE	0x1
#define	NVME_LOG_MAX_OFFSET	UINT64_MAX

/*
 * These maximum size values are inclusive like the others. The fields are 12
 * and 32-bits wide respectively, but are zero based. That is accounted for by
 * the shifts below.
 */
#define	NVME_LOG_MAX_SIZE	((1ULL << 12ULL) * 4ULL)
#define	NVME_LOG_MAX_SIZE_1v2	((1ULL << 32ULL) * 4ULL)

/*
 * Inject a vendor-specific admin command (NVME_IOC_PASSTHRU).
 */
typedef struct {
	nvme_ioctl_common_t npc_common;	/* NSID and status */
	uint32_t npc_opcode;	/* Command opcode. */
	uint32_t npc_timeout;	/* Command timeout, in seconds. */
	uint32_t npc_flags;	/* Flags for the command. */
	uint32_t npc_impact;	/* Impact information */
	uint32_t npc_cdw0;	/* Command-specific result DWord 0 */
	uint32_t npc_cdw12;	/* Command-specific DWord 12 */
	uint32_t npc_cdw13;	/* Command-specific DWord 13 */
	uint32_t npc_cdw14;	/* Command-specific DWord 14 */
	uint32_t npc_cdw15;	/* Command-specific DWord 15 */
	uint64_t npc_buflen;	/* Size of npc_buf. */
	uintptr_t npc_buf;	/* I/O source or destination */
} nvme_ioctl_passthru_t;

/*
 * Constants for the passthru admin commands. Because the timeout is a kernel
 * property, we don't include that here.
 */
#define	NVME_PASSTHRU_MIN_ADMIN_OPC	0xc0
#define	NVME_PASSTHRU_MAX_ADMIN_OPC	0xff

/* Flags for NVMe passthru commands. */
#define	NVME_PASSTHRU_READ	0x1 /* Read from device */
#define	NVME_PASSTHRU_WRITE	0x2 /* Write to device */

/*
 * Impact information for NVMe passthru commands. The current impact flags are
 * defined as follows:
 *
 * NVME_IMPACT_NS	This implies that one or all of the namespaces may be
 *			changed. This command will rescan all namespace after
 *			this occurs and update our state as a result. However,
 *			this requires that all such namespaces not be attached
 *			to blkdev to continue.
 */
#define	NVME_IMPACT_NS		0x01


/*
 * Firmware download (NVME_IOC_FIRMWARE_DOWNLOAD).
 */
typedef struct {
	nvme_ioctl_common_t fwl_common;
	uintptr_t fwl_buf;
	uint64_t fwl_len;
	uint64_t fwl_off;
} nvme_ioctl_fw_load_t;

/*
 * Firmware commit (NVME_IOC_FIRMWARE_COMMIT). This was previously called
 * firmware activate in earlier specification revisions.
 */
typedef struct {
	nvme_ioctl_common_t fwc_common;
	uint32_t fwc_slot;
	uint32_t fwc_action;
} nvme_ioctl_fw_commit_t;

/*
 * Format NVM command (NVME_IOC_FORMAT)
 */
typedef struct {
	nvme_ioctl_common_t nif_common;
	uint32_t nif_lbaf;
	uint32_t nif_ses;
} nvme_ioctl_format_t;

typedef enum {
	NVME_LOCK_E_CTRL = 1,
	NVME_LOCK_E_NS
} nvme_lock_ent_t;

typedef enum {
	NVME_LOCK_L_READ	= 1,
	NVME_LOCK_L_WRITE
} nvme_lock_level_t;

typedef enum {
	NVME_LOCK_F_DONT_BLOCK	= 1 << 0
} nvme_lock_flags_t;

/*
 * Lock structure (NVME_IOC_LOCK).
 */
typedef struct {
	nvme_ioctl_common_t nil_common;
	nvme_lock_ent_t nil_ent;
	nvme_lock_level_t nil_level;
	nvme_lock_flags_t nil_flags;
} nvme_ioctl_lock_t;

/*
 * Unlock structure (NVME_IOC_UNLOCK).
 */
typedef struct {
	nvme_ioctl_common_t niu_common;
	nvme_lock_ent_t niu_ent;
} nvme_ioctl_unlock_t;

/*
 * Namespace Management related structures and constants. Note, namespace
 * controller attach, controller detach, and namespace delete all use the common
 * ioctl structure at this time.
 */
#define	NVME_NS_ATTACH_CTRL_ATTACH	0
#define	NVME_NS_ATTACH_CTRL_DETACH	1

/*
 * Constants related to fields here. These represent the specifications maximum
 * size, even though there are additional constraints placed on it by the driver
 * (e.g. we only allow creating a namespace with the NVM CSI).
 */
#define	NVME_NS_MGMT_MAX_CSI	0xff
#define	NVME_NS_MGMT_MAX_FLBAS	0xf
#define	NVME_NS_MGMT_NMIC_MASK	0x1

/*
 * Logical values for namespace multipath I/O and sharing capabilities (NMIC).
 */
typedef enum {
	/*
	 * Indicates that no NVMe namespace sharing is permitted between
	 * controllers.
	 */
	NVME_NS_NMIC_T_NONE	= 0,
	/*
	 * Indicates that namespace sharing is allowed between controllers. This
	 * is equivalent to the SHRNS bit being set.
	 */
	NVME_NS_NMIC_T_SHARED,
	/*
	 * Indicates that this is a dispersed namespace. A dispersed namespace
	 * implies a shared namespace and indicates that DISNS and SHRNS are
	 * both set.
	 */
	NVME_NS_NMIC_T_DISPERSED
} nvme_ns_nmic_t;

/*
 * Namespace create structure (NVME_IOC_NS_CREATE).
 */
typedef struct {
	nvme_ioctl_common_t nnc_common;
	uint64_t nnc_nsze;
	uint64_t nnc_ncap;
	uint32_t nnc_csi;
	uint32_t nnc_flbas;
	uint32_t nnc_nmic;
	uint32_t nnc_nsid;
} nvme_ioctl_ns_create_t;

/*
 * 32-bit ioctl structures. These must be packed to be 4 bytes to get the proper
 * ILP32 sizing.
 */
#if defined(_KERNEL) && defined(_SYSCALL32)
#pragma pack(4)
typedef struct {
	nvme_ioctl_common_t nid_common;
	uint32_t nid_cns;
	uint32_t nid_ctrlid;
	uintptr32_t nid_data;
} nvme_ioctl_identify32_t;

typedef struct {
	nvme_ioctl_common_t nigf_common;
	uint32_t nigf_fid;
	uint32_t nigf_sel;
	uint32_t nigf_cdw11;
	uintptr32_t nigf_data;
	uint64_t nigf_len;
	uint32_t nigf_cdw0;
} nvme_ioctl_get_feature32_t;

typedef struct {
	nvme_ioctl_common_t nigl_common;
	uint32_t nigl_csi;
	uint32_t nigl_lid;
	uint32_t nigl_lsp;
	uint32_t nigl_lsi;
	uint32_t nigl_rae;
	uint64_t nigl_len;
	uint64_t nigl_offset;
	uintptr32_t nigl_data;
} nvme_ioctl_get_logpage32_t;

typedef struct {
	nvme_ioctl_common_t npc_common;	/* NSID and status */
	uint32_t npc_opcode;	/* Command opcode. */
	uint32_t npc_timeout;	/* Command timeout, in seconds. */
	uint32_t npc_flags;	/* Flags for the command. */
	uint32_t npc_impact;	/* Impact information */
	uint32_t npc_cdw0;	/* Command-specific result DWord 0 */
	uint32_t npc_cdw12;	/* Command-specific DWord 12 */
	uint32_t npc_cdw13;	/* Command-specific DWord 13 */
	uint32_t npc_cdw14;	/* Command-specific DWord 14 */
	uint32_t npc_cdw15;	/* Command-specific DWord 15 */
	uint64_t npc_buflen;	/* Size of npc_buf. */
	uintptr32_t npc_buf;	/* I/O source or destination */
} nvme_ioctl_passthru32_t;

typedef struct {
	nvme_ioctl_common_t fwl_common;
	uintptr32_t fwl_buf;
	uint64_t fwl_len;
	uint64_t fwl_off;
} nvme_ioctl_fw_load32_t;
#pragma pack()	/* pack(4) */
#endif	/* _KERNEL && _SYSCALL32 */

/*
 * NVMe capabilities. This is a set of fields that come from the controller's
 * PCIe register space.
 */
typedef struct {
	uint32_t cap_mpsmax;		/* Memory Page Size Maximum */
	uint32_t cap_mpsmin;		/* Memory Page Size Minimum */
} nvme_capabilities_t;

/*
 * NVMe version
 */
typedef struct {
	uint16_t v_minor;
	uint16_t v_major;
} nvme_version_t;

#define	NVME_VERSION_ATLEAST(v, maj, min) \
	(((v)->v_major) > (maj) || \
	((v)->v_major == (maj) && (v)->v_minor >= (min)))

#define	NVME_VERSION_HIGHER(v, maj, min) \
	(((v)->v_major) > (maj) || \
	((v)->v_major == (maj) && (v)->v_minor > (min)))

/*
 * NVMe Namespace related constants. The maximum NSID is determined by the
 * identify controller data structure.
 */
#define	NVME_NSID_MIN	1
#define	NVME_NSID_BCAST	0xffffffff

#pragma pack(1)

typedef struct {
	uint64_t lo;
	uint64_t hi;
} nvme_uint128_t;

/*
 * NVMe Identify data structures
 */

#define	NVME_IDENTIFY_BUFSIZE	4096	/* buffer size for Identify */

/* NVMe Identify parameters (cdw10) */
#define	NVME_IDENTIFY_NSID		0x0	/* Identify Namespace */
#define	NVME_IDENTIFY_CTRL		0x1	/* Identify Controller */
#define	NVME_IDENTIFY_NSID_LIST		0x2	/* List Active Namespaces */
#define	NVME_IDENTIFY_NSID_DESC		0x3	/* Namespace ID Descriptors */

#define	NVME_IDENTIFY_NSID_ALLOC_LIST	0x10	/* List Allocated NSID */
#define	NVME_IDENTIFY_NSID_ALLOC	0x11	/* Identify Allocated NSID */
#define	NVME_IDENTIFY_NSID_CTRL_LIST	0x12	/* List Controllers on NSID */
#define	NVME_IDENTIFY_CTRL_LIST		0x13	/* Controller List */
#define	NVME_IDENTIFY_PRIMARY_CAPS	0x14	/* Primary Controller Caps */


/* NVMe Queue Entry Size bitfield */
typedef struct {
	uint8_t qes_min:4;		/* minimum entry size */
	uint8_t qes_max:4;		/* maximum entry size */
} nvme_idctl_qes_t;

/* NVMe Power State Descriptor */
typedef struct {
	uint16_t psd_mp;		/* Maximum Power */
	uint8_t psd_rsvd1;
	uint8_t psd_mps:1;		/* Max Power Scale (1.1) */
	uint8_t psd_nops:1;		/* Non-Operational State (1.1) */
	uint8_t psd_rsvd2:6;
	uint32_t psd_enlat;		/* Entry Latency */
	uint32_t psd_exlat;		/* Exit Latency */
	uint8_t psd_rrt:5;		/* Relative Read Throughput */
	uint8_t psd_rsvd3:3;
	uint8_t psd_rrl:5;		/* Relative Read Latency */
	uint8_t psd_rsvd4:3;
	uint8_t psd_rwt:5;		/* Relative Write Throughput */
	uint8_t	psd_rsvd5:3;
	uint8_t psd_rwl:5;		/* Relative Write Latency */
	uint8_t psd_rsvd6:3;
	uint16_t psd_idlp;		/* Idle Power (1.2) */
	uint8_t psd_rsvd7:6;
	uint8_t psd_ips:2;		/* Idle Power Scale (1.2) */
	uint8_t psd_rsvd8;
	uint16_t psd_actp;		/* Active Power (1.2) */
	uint8_t psd_apw:3;		/* Active Power Workload (1.2) */
	uint8_t psd_rsvd9:3;
	uint8_t psd_aps:2;		/* Active Power Scale */
	uint8_t psd_rsvd10[9];
} nvme_idctl_psd_t;

#define	NVME_SERIAL_SZ	20
#define	NVME_MODEL_SZ	40
#define	NVME_FWVER_SZ	8

/* NVMe Identify Controller Data Structure */
typedef struct {
	/* Controller Capabilities & Features */
	uint16_t id_vid;		/* PCI vendor ID */
	uint16_t id_ssvid;		/* PCI subsystem vendor ID */
	char id_serial[NVME_SERIAL_SZ];	/* Serial Number */
	char id_model[NVME_MODEL_SZ];	/* Model Number */
	char id_fwrev[NVME_FWVER_SZ];	/* Firmware Revision */
	uint8_t id_rab;			/* Recommended Arbitration Burst */
	uint8_t id_oui[3];		/* vendor IEEE OUI */
	struct {			/* Multi-Interface Capabilities */
		uint8_t m_multi_pci:1;	/* HW has multiple PCIe interfaces */
		uint8_t m_multi_ctrl:1; /* HW has multiple controllers (1.1) */
		uint8_t m_sr_iov:1;	/* Controller is SR-IOV virt fn (1.1) */
		uint8_t m_anar_sup:1;	/* ANA Reporting Supported (1.4) */
		uint8_t m_rsvd:4;
	} id_mic;
	uint8_t	id_mdts;		/* Maximum Data Transfer Size */
	uint16_t id_cntlid;		/* Unique Controller Identifier (1.1) */
	/* Added in NVMe 1.2 */
	uint32_t id_ver;		/* Version (1.2) */
	uint32_t id_rtd3r;		/* RTD3 Resume Latency (1.2) */
	uint32_t id_rtd3e;		/* RTD3 Entry Latency (1.2) */
	struct {
		uint32_t oaes_rsvd0:8;
		uint32_t oaes_nsan:1;	/* Namespace Attribute Notices (1.2) */
		uint32_t oaes_fwact:1;	/* Firmware Activation Notices (1.2) */
		uint32_t oaes_rsvd10:1;
		uint32_t oaes_ansacn:1;	/* Asymmetric NS Access Change (1.4) */
		uint32_t oaes_plat:1;	/* Predictable Lat Event Agg. (1.4) */
		uint32_t oaes_lbasi:1;	/* LBA Status Information (1.4) */
		uint32_t oaes_egeal:1;	/* Endurance Group Event Agg. (1.4) */
		uint32_t oaes_nnss:1;	/* Normal NVM Subsys Shutdown (2.0) */
		uint32_t oaes_tthr:1;	/* Temp. Tresh. Hysteresis Rec (2.1) */
		uint32_t oaes_rgcns:1;	/* Reach Group Change Notice (2.1) */
		uint32_t oaes_rsvd18:1;
		uint32_t oaes_ansan:1;	/* Allocated Namespace Attr. (2.1) */
		uint32_t oaes_rsvd20:7;
		uint32_t oaes_zdcn:1;	/* Zone Descriptor Change (2.0) */
		uint32_t oaes_rsvd28:3;
		uint32_t oaes_dlpcn:1;	/* Disc Log Page Change (2.0) */
	} id_oaes;
	struct {
		uint32_t ctrat_hid:1;	/* 128-bit Host Identifier (1.2)  */
		uint32_t ctrat_nops:1;	/* Non-Operational Power State (1.3) */
		uint32_t ctrat_nvmset:1; /* NVMe Sets (1.4) */
		uint32_t ctrat_rrl:1;	/* Read Recovery Levels (1.4) */
		uint32_t ctrat_engrp:1; /* Endurance Groups (1.4) */
		uint32_t ctrat_plm:1;	/* Predictable Latency Mode (1.4) */
		uint32_t ctrat_tbkas:1;	/* Traffic Based Keep Alive (1.4) */
		uint32_t ctrat_nsg:1;	/* Namespace Granularity (1.4) */
		uint32_t ctrat_sqass:1;	/* SQ Associations (1.4) */
		uint32_t ctrat_uuid:1;	/* UUID List (1.4) */
		uint32_t ctrat_mds:1;	/* Multi-Domain Subsys (2.0) */
		uint32_t ctrat_fcm:1;	/* Fixed Cap Management (2.0) */
		uint32_t ctrat_vcm:1;	/* Variable Cap Management (2.0) */
		uint32_t ctrat_deg:1;	/* Delete Endurance Group (2.0) */
		uint32_t ctrat_dnvms:1;	/* Delete NVM Set (2.0) */
		uint32_t ctrat_elbas:1;	/* Ext. LBA Formats (2.0) */
		uint32_t ctrat_mem:1;	/* MDTS and Size exclude Meta (2.1) */
		uint32_t ctrat_hmbr:1;	/* HMB Restrictions (2.1) */
		uint32_t ctrat_rhii:1;	/* Reservations and Host ID (2.1) */
		uint32_t ctrat_fdps:1;	/* Flexible Data Placement (2.1) */
		uint32_t ctrat_rsvd20:12;
	} id_ctratt;
	uint16_t id_rrls;		/* Read Recovery Levels (1.4) */
	struct {
		uint8_t bpcap_rpmbbpwps:2;	/* RPMB Prot Write (2.1) */
		uint8_t bpcap_sfbpwps:1;	/* Set Feat RPMB (2.1) */
		uint8_t bpcap_rsvd3:5;
	} id_bpcap;
	uint8_t id_rsvd_103;
	uint32_t id_nssl;		/* NVM Subsystem Shutdown Lat. (2.1) */
	uint8_t id_rsvd_108[2];
	struct {
		uint8_t plsi_plsepf:1;	/* PLS Emergency Power Fail (2.1) */
		uint8_t plsi_plsfq:1;	/* PLS Force Quiesce (2.1) */
		uint8_t plsi_rvsd:6;
	} id_plsi;
	uint8_t id_cntrltype;		/* Controller Type (1.4) */
	uint8_t id_frguid[16];		/* FRU GUID (1.3) */
	uint16_t id_crdt1;		/* Command Retry Delay Time 1 (1.4) */
	uint16_t id_crdt2;		/* Command Retry Delay Time 2 (1.4) */
	uint16_t id_crdt3;		/* Command Retry Delay Time 3 (1.4) */
	struct {
		uint8_t crcap_rrsup:1;	/* Reachability Reporting (2.1) */
		uint8_t crcap_rgidc:1;	/* Group ID Changeable (2.1) */
		uint8_t crcap_rsvd2:6;
	} id_crcap;
	uint8_t id_rsvd2_cc[240 - 135];
	uint8_t id_rsvd_nvmemi[253 - 240];
	/* NVMe-MI region */
	struct {			/* NVMe Subsystem Report */
		uint8_t nvmsr_nvmesd:1;	/* NVMe Storage Device */
		uint8_t nvmsr_nvmee:1;	/* NVMe Enclosure */
		uint8_t nvmsr_rsvd:6;
	} id_nvmsr;
	struct {			/* VPD Write Cycle Information */
		uint8_t vwci_crem:7;	/* Write Cycles Remaining */
		uint8_t vwci_valid:1;	/* Write Cycles Remaining Valid */
	} id_vpdwc;
	struct {			/* Management Endpoint Capabilities */
		uint8_t mec_smbusme:1;	/* SMBus Port Management Endpoint */
		uint8_t mec_pcieme:1;	/* PCIe Port Management Endpoint */
		uint8_t mec_rsvd:6;
	} id_mec;

	/* Admin Command Set Attributes */
	struct {			/* Optional Admin Command Support */
		uint16_t oa_security:1;	/* Security Send & Receive */
		uint16_t oa_format:1;	/* Format NVM */
		uint16_t oa_firmware:1;	/* Firmware Activate & Download */
		uint16_t oa_nsmgmt:1;	/* Namespace Management (1.2) */
		uint16_t oa_selftest:1;	/* Self Test (1.3) */
		uint16_t oa_direct:1;	/* Directives (1.3) */
		uint16_t oa_nvmemi:1;	/* MI-Send/Recv (1.3) */
		uint16_t oa_virtmgmt:1;	/* Virtualization Management (1.3) */
		uint16_t oa_doorbell:1;	/* Doorbell Buffer Config (1.3) */
		uint16_t oa_lbastat:1;	/* LBA Status (1.4) */
		uint16_t oa_clfs:1;	/* Command and Feat Lockdown (2.0) */
		uint16_t oa_hmlms:1;	/* Host Managed Live Migration (2.0) */
		uint16_t oa_rsvd12:4;
	} id_oacs;
	uint8_t	id_acl;			/* Abort Command Limit */
	uint8_t id_aerl;		/* Asynchronous Event Request Limit */
	struct {			/* Firmware Updates */
		uint8_t fw_readonly:1;	/* Slot 1 is Read-Only */
		uint8_t	fw_nslot:3;	/* number of firmware slots */
		uint8_t fw_norst:1;	/* Activate w/o reset (1.2) */
		uint8_t fw_smud:1;	/* Support Multiple Update Det. (2.0) */
		uint8_t fw_rsvd6:2;
	} id_frmw;
	struct {			/* Log Page Attributes */
		uint8_t lp_smart:1;	/* SMART/Health information per NS */
		uint8_t lp_cmdeff:1;	/* Command Effects (1.2) */
		uint8_t lp_extsup:1;	/* Extended Get Log Page (1.2) */
		uint8_t lp_telemetry:1;	/* Telemetry Log Pages (1.3) */
		uint8_t lp_persist:1;	/* Persistent Log Page (1.4) */
		uint8_t lp_mlps:1;	/* Misc. Log Page (2.0) */
		uint8_t lp_da4s:1;	/* Data Area 4 Support (2.0) */
		uint8_t lp_rsvd7:1;
	} id_lpa;
	uint8_t id_elpe;		/* Error Log Page Entries */
	uint8_t	id_npss;		/* Number of Power States */
	struct {			/* Admin Vendor Specific Command Conf */
		uint8_t av_spec:1;	/* use format from spec */
		uint8_t av_rsvd:7;
	} id_avscc;
	struct {			/* Autonomous Power State Trans (1.1) */
		uint8_t ap_sup:1;	/* APST supported (1.1) */
		uint8_t ap_rsvd:7;
	} id_apsta;
	uint16_t ap_wctemp;		/* Warning Composite Temp. (1.2) */
	uint16_t ap_cctemp;		/* Critical Composite Temp. (1.2) */
	uint16_t ap_mtfa;		/* Maximum Firmware Activation (1.2) */
	uint32_t ap_hmpre;		/* Host Memory Buf Pref Size (1.2) */
	uint32_t ap_hmmin;		/* Host Memory Buf Min Size (1.2) */
	nvme_uint128_t ap_tnvmcap;	/* Total NVM Capacity in Bytes (1.2) */
	nvme_uint128_t ap_unvmcap;	/* Unallocated NVM Capacity (1.2) */
	struct {			/* Replay Protected Mem. Block (1.2) */
		uint32_t rpmbs_units:3;	/* Number of targets */
		uint32_t rpmbs_auth:3;	/* Auth method */
		uint32_t rpmbs_rsvd:10;
		uint32_t rpmbs_tot:8;	/* Total size in 128KB */
		uint32_t rpmbs_acc:8;	/* Access size in 512B */
	} ap_rpmbs;
	/* Added in NVMe 1.3 */
	uint16_t ap_edstt;		/* Ext. Device Self-test time (1.3) */
	struct {			/* Device Self-test Options */
		uint8_t dsto_sub:1;	/* Subsystem level self-test (1.3) */
		uint8_t dsto_hirs:1;	/* Host-Initiated Refresh (2.1) */
		uint8_t dsto_rsvd:6;
	} ap_dsto;
	uint8_t ap_fwug;		/* Firmware Update Granularity (1.3) */
	uint16_t ap_kas;		/* Keep Alive Support (1.2) */
	struct {			/* Host Thermal Management (1.3) */
		uint16_t hctma_hctm:1;	/* Host Controlled (1.3) */
		uint16_t hctma_rsvd:15;
	} ap_hctma;
	uint16_t ap_mntmt;		/* Minimum Thermal Temperature (1.3) */
	uint16_t ap_mxtmt;		/* Maximum Thermal Temperature (1.3) */
	struct {			/* Sanitize Caps */
		uint32_t san_ces:1;	/* Crypto Erase Support (1.3) */
		uint32_t san_bes:1;	/* Block Erase Support (1.3) */
		uint32_t san_ows:1;	/* Overwite Support (1.3) */
		uint32_t san_vers:1;	/* Verification Support (2.1) */
		uint32_t san_rsvd:25;
		uint32_t san_ndi:1;	/* No-deallocate Inhibited (1.4) */
		uint32_t san_nodmmas:2;	/* No-Deallocate Modifies Media (1.4) */
	} ap_sanitize;
	uint32_t ap_hmminds;		/* Host Mem Buf Min Desc Entry (1.4) */
	uint16_t ap_hmmaxd;		/* How Mem Max Desc Entries (1.4) */
	uint16_t ap_nsetidmax;		/* Max NVMe set identifier (1.4) */
	uint16_t ap_engidmax;		/* Max Endurance Group ID (1.4) */
	uint8_t ap_anatt;		/* ANA Transition Time (1.4) */
	struct {			/* Asymmetric Namespace Access Caps */
		uint8_t anacap_opt:1;	/* Optimized State (1.4) */
		uint8_t anacap_unopt:1;	/* Un-optimized State (1.4) */
		uint8_t anacap_inacc:1;	/* Inaccessible State (1.4) */
		uint8_t anacap_ploss:1;	/* Persistent Loss (1.4) */
		uint8_t anacap_chg:1;	/* Change State (1.4 ) */
		uint8_t anacap_rsvd:1;
		uint8_t anacap_grpns:1;	/* ID Changes with NS Attach (1.4) */
		uint8_t anacap_grpid:1;	/* Supports Group ID (1.4) */
	} ap_anacap;
	uint32_t ap_anagrpmax;		/* ANA Group ID Max (1.4) */
	uint32_t ap_nanagrpid;		/* Number of ANA Group IDs (1.4) */
	uint32_t ap_pels;		/* Persistent Event Log Size (1.4) */
	uint16_t ap_did;		/* Domain ID (2.0) */
	struct {
		uint8_t kpioc_kpios:1;	/* Key Per I/O Sup (2.1) */
		uint8_t kpioc_kpisc:1;	/* Key Per I/O Scope (2.1) */
		uint8_t kpioc_rsvd:6;
	} ap_kpioc;
	uint8_t ap_rsvd359;
	uint16_t ap_mptfawr;		/* Max FW Act Time w/o Reset (2.1) */
	uint8_t ap_rsvd362[368-362];
	nvme_uint128_t ap_megcap;	/* Max Endurance Group Cap (2.1) */
	struct {
		uint8_t tmpthha_tmpthmh:3;	/* Temp Tresh Max Hyst (2.1) */
		uint8_t tmpthha_rsvd3:5;
	} ap_tmpthha;
	uint8_t ap_rsvd385;
	uint16_t ap_cqt;		/* Command Quiesce Time (2.1) */
	uint8_t ap_rsvd_ac[512 - 388];

	/* NVM Command Set Attributes */
	nvme_idctl_qes_t id_sqes;	/* Submission Queue Entry Size */
	nvme_idctl_qes_t id_cqes;	/* Completion Queue Entry Size */
	uint16_t id_maxcmd;		/* Max Outstanding Commands (1.3) */
	uint32_t id_nn;			/* Number of Namespaces */
	struct {			/* Optional NVM Command Support */
		uint16_t on_compare:1;	/* Compare */
		uint16_t on_wr_unc:1;	/* Write Uncorrectable */
		uint16_t on_dset_mgmt:1; /* Dataset Management */
		uint16_t on_wr_zero:1;	/* Write Zeroes (1.1) */
		uint16_t on_save:1;	/* Save/Select in Get/Set Feat (1.1) */
		uint16_t on_reserve:1;	/* Reservations (1.1) */
		uint16_t on_ts:1;	/* Timestamp (1.3) */
		uint16_t on_verify:1;	/* Verify (1.4) */
		uint16_t on_nvmcpys:1;	/* Copy (2.0) */
		uint16_t on_nvmcsa:1;	/* NVM Copy Single Atomicity (2.1) */
		uint16_t on_nvmafc:1;	/* NVM All Fast Copy (2.1) */
		uint16_t on_maxwzd:1;	/* Max Write Zeroes w/ Dealloc (2.1) */
		uint16_t on_nszs:1;	/* Namespace zeros (2.1) */
		uint16_t on_rsvd13:3;
	} id_oncs;
	struct {			/* Fused Operation Support */
		uint16_t f_cmp_wr:1;	/* Compare and Write */
		uint16_t f_rsvd:15;
	} id_fuses;
	struct {			/* Format NVM Attributes */
		uint8_t fn_format:1;	/* Format applies to all NS */
		uint8_t fn_sec_erase:1;	/* Secure Erase applies to all NS */
		uint8_t fn_crypt_erase:1; /* Cryptographic Erase supported */
		uint8_t fn_rsvd:5;
	} id_fna;
	struct {			/* Volatile Write Cache */
		uint8_t vwc_present:1;	/* Volatile Write Cache present */
		uint8_t vwc_nsflush:2;	/* Flush with NS ffffffff (1.4) */
		uint8_t rsvd:5;
	} id_vwc;
	uint16_t id_awun;		/* Atomic Write Unit Normal */
	uint16_t id_awupf;		/* Atomic Write Unit Power Fail */
	struct {			/* NVM Vendor Specific Command Conf */
		uint8_t nv_spec:1;	/* use format from spec */
		uint8_t nv_rsvd:7;
	} id_nvscc;
	struct {			/* Namespace Write Protection Caps */
		uint8_t nwpc_base:1;	/* Base support (1.4) */
		uint8_t nwpc_wpupc:1;	/* Write prot until power cycle (1.4) */
		uint8_t nwpc_permwp:1;	/* Permanent write prot (1.4) */
		uint8_t nwpc_rsvd:5;
	} id_nwpc;
	uint16_t id_acwu;		/* Atomic Compare & Write Unit (1.1) */
	struct {
		uint16_t cdfs_cdf0s:1;	/* Copy Desc Format 0 (2.0) */
		uint16_t cdfs_cdf1s:1;	/* Copy Desc Format 1 (2.0) */
		uint16_t cdfs_cdf2s:1;	/* Copy Desc Format 2 (2.1) */
		uint16_t cdfs_cdf3s:1;	/* Copy Desc Format 3 (2.1) */
		uint16_t cdfs_cdf4s:1;	/* Copy Desc Format 4 (2.1) */
		uint16_t cdfs_rsvd5:11;
	} id_cdfs;
	struct {			/* SGL Support (1.1) */
		uint16_t sgl_sup:2;	/* SGL Supported in NVM cmds (1.3) */
		uint16_t sgl_keyed:1;	/* Keyed SGL Support (1.2) */
		uint16_t sgl_rsvd3:5;
		uint16_t sgl_sdt:8;	/* SGL Desc Threshold (2.0) */
		uint16_t sgl_bucket:1;	/* SGL Bit Bucket supported (1.1) */
		uint16_t sgl_balign:1;	/* SGL Byte Aligned (1.2) */
		uint16_t sgl_sglgtd:1;	/* SGL Length Longer than Data (1.2) */
		uint16_t sgl_mptr:1;	/* SGL MPTR w/ SGL (1.2) */
		uint16_t sgl_offset:1;	/* SGL Address is offset (1.2) */
		uint16_t sgl_tport:1;	/* Transport SGL Data Block (1.4) */
		uint16_t sgl_rsvd22:10;
	} id_sgls;
	uint32_t id_mnan;		/* Maximum Num of Allowed NSes (1.4) */
	nvme_uint128_t id_maxdna;	/* Maximum Domain NS Attach (2.0) */
	uint32_t id_maxcna;		/* Maximum I/O Ctrl NS Attach (2.0) */
	uint32_t id_oaqd;		/* Optimal Agg. Queue Depth (2.1) */
	uint8_t id_rhiri;		/* Host-Init Refresh Ival (2.1) */
	uint8_t id_hirt;		/* Host-Init refresh time (2.1) */
	uint16_t id_cmmrtd;		/* Ctrl. Max Mem Track Desc (2.1) */
	uint16_t id_nmmrtd;		/* NVM Max Mem Track Desc (2.1) */
	uint8_t id_minmrtg;		/* Min Mem Range Track Gran (2.1) */
	uint8_t id_maxmrtg;		/* Max Mem Range Track Gran (2.1) */
	struct {
		uint8_t trattr_thmcs:1;	/* Track Host Memory Changes (2.1) */
		uint8_t trattr_tudcs:1;	/* Track User Data Changes (2.1) */
		uint8_t trattr_mrtll:1;	/* Memory Range Tracking Lim (2.1) */
		uint8_t trattr_rsvd3:5;
	} id_trattr;
	uint8_t id_rsvd577;
	uint16_t id_mcudmq;		/* Max Ctrl User Mig Queues (2.1) */
	uint16_t id_mnsudmq;		/* Max NVM Sys Mig Queues (2.1) */
	uint16_t id_mcmr;		/* Max CDQ Memory Ranges (2.1) */
	uint16_t id_nmcmr;		/* NVM Sub Max CDQ Mem Ranges (2.1) */
	uint16_t id_mcdqpc;		/* Max Ctrl Data Queue PRP (2.1) */
	uint8_t id_rsvd_nc_4[768 - 588];

	/* I/O Command Set Attributes */
	uint8_t id_subnqn[1024 - 768];	/* Subsystem Qualified Name (1.2.1+) */
	uint8_t id_rsvd_ioc[1792 - 1024];
	uint8_t id_nvmof[2048 - 1792];	/* NVMe over Fabrics */

	/* Power State Descriptors */
	nvme_idctl_psd_t id_psd[32];

	/* Vendor Specific */
	uint8_t id_vs[1024];
} nvme_identify_ctrl_t;

/*
 * NVMe Controller Types
 */
#define	NVME_CNTRLTYPE_RSVD	0
#define	NVME_CNTRLTYPE_IO	1
#define	NVME_CNTRLTYPE_DISC	2
#define	NVME_CNTRLTYPE_ADMIN	3

/*
 * RPMBS Authentication Types
 */
#define	NVME_RPMBS_AUTH_HMAC_SHA256	0

/*
 * NODMMAS Values
 */
#define	NVME_NODMMAS_UNDEF	0x00
#define	NVME_NODMMAS_NOMOD	0x01
#define	NVME_NODMMAS_DOMOD	0x02

/*
 * VWC NSID flushes
 */
#define	NVME_VWCNS_UNKNOWN	0x00
#define	NVME_VWCNS_UNSUP	0x02
#define	NVME_VWCNS_SUP		0x03

/*
 * SGL Support Values
 */
#define	NVME_SGL_UNSUP		0x00
#define	NVME_SGL_SUP_UNALIGN	0x01
#define	NVME_SGL_SUP_ALIGN	0x02

/* NVMe Identify Namespace LBA Format */
typedef struct {
	uint16_t lbaf_ms;		/* Metadata Size */
	uint8_t lbaf_lbads;		/* LBA Data Size */
	uint8_t lbaf_rp:2;		/* Relative Performance */
	uint8_t lbaf_rsvd1:6;
} nvme_idns_lbaf_t;

#define	NVME_MAX_LBAF	16

/* NVMe Identify Namespace Data Structure */
typedef struct {
	uint64_t id_nsize;		/* Namespace Size */
	uint64_t id_ncap;		/* Namespace Capacity */
	uint64_t id_nuse;		/* Namespace Utilization */
	struct {			/* Namespace Features */
		uint8_t f_thin:1;	/* Thin Provisioning */
		uint8_t f_nsabp:1;	/* Namespace atomics (1.2) */
		uint8_t f_dae:1;	/* Deallocated errors supported (1.2) */
		uint8_t f_uidreuse:1;	/* GUID reuse impossible (1.3) */
		uint8_t f_optperf:2;	/* Namespace I/O opt (1.4, N1.1) */
		uint8_t f_mam:1;	/* Multiple Atomicity (N1.1) */
		uint8_t f_optrperf:1;	/* Optional Read Perf (N1.1) */
	} id_nsfeat;
	uint8_t id_nlbaf;		/* Number of LBA formats */
	struct {			/* Formatted LBA size */
		uint8_t lba_format:4;	/* LBA format */
		uint8_t lba_extlba:1;	/* extended LBA (includes metadata) */
		uint8_t lba_fidxu:2;	/* Format Index Upper (N1.0) */
		uint8_t lba_rsvd:1;
	} id_flbas;
	struct {			/* Metadata Capabilities */
		uint8_t mc_extlba:1;	/* extended LBA transfers */
		uint8_t mc_separate:1;	/* separate metadata transfers */
		uint8_t mc_rsvd:6;
	} id_mc;
	struct {			/* Data Protection Capabilities */
		uint8_t dp_type1:1;	/* Protection Information Type 1 */
		uint8_t dp_type2:1;	/* Protection Information Type 2 */
		uint8_t dp_type3:1;	/* Protection Information Type 3 */
		uint8_t dp_first:1;	/* first 8 bytes of metadata */
		uint8_t dp_last:1;	/* last 8 bytes of metadata */
		uint8_t dp_rsvd:3;
	} id_dpc;
	struct {			/* Data Protection Settings */
		uint8_t dp_pinfo:3;	/* Protection Information enabled */
		uint8_t dp_first:1;	/* first 8 bytes of metadata */
		uint8_t dp_rsvd:4;
	} id_dps;
	struct {			/* NS Multi-Path/Sharing Cap (1.1) */
		uint8_t nm_shared:1;	/* NS is shared (1.1) */
		uint8_t nm_disperse:1;	/* NS is dispersed (2.1) */
		uint8_t nm_rsvd:6;
	} id_nmic;
	struct {			/* Reservation Capabilities (1.1) */
		uint8_t rc_persist:1;	/* Persist Through Power Loss (1.1) */
		uint8_t rc_wr_excl:1;	/* Write Exclusive (1.1) */
		uint8_t rc_excl:1;	/* Exclusive Access (1.1) */
		uint8_t rc_wr_excl_r:1;	/* Wr Excl - Registrants Only (1.1) */
		uint8_t rc_excl_r:1;	/* Excl Acc - Registrants Only (1.1) */
		uint8_t rc_wr_excl_a:1;	/* Wr Excl - All Registrants (1.1) */
		uint8_t rc_excl_a:1;	/* Excl Acc - All Registrants (1.1) */
		uint8_t rc_ign_ekey:1;	/* Ignore Existing Key (1.3) */
	} id_rescap;
	struct {			/* Format Progress Indicator (1.2) */
		uint8_t fpi_remp:7;	/* Percent NVM Format Remaining (1.2) */
		uint8_t fpi_sup:1;	/* Supported (1.2) */
	} id_fpi;
	struct {
		uint8_t dlfeat_drb:3;	/* Deallocation Read Behavior (1.3) */
		uint8_t dlfeat_wzds:1;	/* Write Zeroes Deallocation (1.3) */
		uint8_t dlfeat_gds:1;	/* Guard Deallocation Status (1.3) */
		uint8_t dlfeat_rsvd5:3;
	} id_dlfeat;
	uint16_t id_nawun;		/* Atomic Write Unit Normal (1.2) */
	uint16_t id_nawupf;		/* Atomic Write Unit Power Fail (1.2) */
	uint16_t id_nacwu;		/* Atomic Compare & Write Unit (1.2) */
	uint16_t id_nabsn;		/* Atomic Boundary Size Normal (1.2) */
	uint16_t id_nbao;		/* Atomic Boundary Offset (1.2) */
	uint16_t id_nabspf;		/* Atomic Boundary Size Fail (1.2) */
	uint16_t id_noiob;		/* Optimal I/O Boundary (1.3) */
	nvme_uint128_t id_nvmcap;	/* NVM Capacity */
	uint16_t id_npwg;		/* NS Pref. Write Gran. (1.4) */
	uint16_t id_npwa;		/* NS Pref. Write Align. (1.4) */
	uint16_t id_npdg;		/* NS Pref. Deallocate Gran. (1.4) */
	uint16_t id_npda;		/* NS Pref. Deallocate Align. (1.4) */
	uint16_t id_nows;		/* NS. Optimal Write Size (1.4) */
	uint16_t id_mssrl;		/* Max Single Source Range (N1.0) */
	uint32_t id_mcl;		/* Max Copy Length (N1.0) */
	uint8_t id_msrc;		/* Max Source Range (N1.0) */
	struct {
		uint8_t kpios_kpioens:1;	/* Key Per I/O En (N1.1) */
		uint8_t kpios_kpiosns:1;	/* Key Per I/O Sup (N1.1) */
		uint8_t kpios_rsvd2:6;
	} id_kpios;
	uint8_t id_nulbaf;		/* Unique Attr. LBA Formats (N1.1) */
	uint8_t id_rsvd83;
	uint32_t id_kpiodaag;		/* Key Per I/O Access Gran (N1.1) */
	uint8_t id_rsvd1[92 - 88];
	uint32_t id_anagrpid;		/* ANA Group Identifier (1.4) */
	uint8_t id_rsvd2[99 - 96];
	struct {
		uint8_t nsa_wprot:1;	/* Write Protected (1.4) */
		uint8_t nsa_rsvd:7;
	} id_nsattr;
	uint16_t id_nvmsetid;		/* NVM Set Identifier (1.4) */
	uint16_t id_endgid;		/* Endurance Group Identifier (1.4) */
	uint8_t id_nguid[16];		/* Namespace GUID (1.2) */
	uint8_t id_eui64[8];		/* IEEE Extended Unique Id (1.1) */
	nvme_idns_lbaf_t id_lbaf[NVME_MAX_LBAF];	/* LBA Formats */
	/*
	 * This region contains additional LBAF and should be updated as part of
	 * enabling support for additional LBA formats in the stack.
	 */
	uint8_t id_rsvd3[384 - 192];

	uint8_t id_vs[4096 - 384];	/* Vendor Specific */
} nvme_identify_nsid_t;

/* NVMe Identify Namespace ID List */
typedef struct {
					/* Ordered list of Namespace IDs */
	uint32_t nl_nsid[NVME_IDENTIFY_BUFSIZE / sizeof (uint32_t)];
} nvme_identify_nsid_list_t;

/* NVME Identify Controller ID List */
typedef struct {
	uint16_t	cl_nid;		/* Number of controller entries */
					/* unique controller identifiers */
	uint16_t	cl_ctlid[NVME_IDENTIFY_BUFSIZE / sizeof (uint16_t) - 1];
} nvme_identify_ctrl_list_t;

/* NVMe Identify Namespace Descriptor */
typedef struct {
	uint8_t nd_nidt;		/* Namespace Identifier Type */
	uint8_t nd_nidl;		/* Namespace Identifier Length */
	uint8_t nd_resv[2];
	uint8_t nd_nid[];		/* Namespace Identifier */
} nvme_identify_nsid_desc_t;

#define	NVME_NSID_DESC_EUI64	1
#define	NVME_NSID_DESC_NGUID	2
#define	NVME_NSID_DESC_NUUID	3
#define	NVME_NSID_DESC_MIN	NVME_NSID_DESC_EUI64
#define	NVME_NSID_DESC_MAX	NVME_NSID_DESC_NUUID

#define	NVME_NSID_DESC_LEN_EUI64	8
#define	NVME_NSID_DESC_LEN_NGUID	16
#define	NVME_NSID_DESC_LEN_NUUID	UUID_LEN

/* NVMe Identify Primary Controller Capabilities */
typedef struct {
	uint16_t	nipc_cntlid;	/* Controller ID */
	uint16_t	nipc_portid;	/* Port Identifier */
	uint8_t		nipc_crt;	/* Controller Resource Types */
	uint8_t		nipc_rsvd0[32 - 5];
	uint32_t	nipc_vqfrt;	/* VQ Resources Flexible Total */
	uint32_t	nipc_vqrfa;	/* VQ Resources Flexible Assigned */
	uint16_t	nipc_vqrfap;	/* VQ Resources to Primary */
	uint16_t	nipc_vqprt;	/* VQ Resources Private Total */
	uint16_t	nipc_vqfrsm;	/* VQ Resources Secondary Max */
	uint16_t	nipc_vqgran;	/* VQ Flexible Resource Gran */
	uint8_t		nipc_rvsd1[64 - 48];
	uint32_t	nipc_vifrt;	/* VI Flexible total */
	uint32_t	nipc_virfa;	/* VI Flexible Assigned */
	uint16_t	nipc_virfap;	/* VI Flexible Allocated to Primary */
	uint16_t	nipc_viprt;	/* VI Resources Private Total */
	uint16_t	nipc_vifrsm;	/* VI Resources Secondary Max */
	uint16_t	nipc_vigran;	/* VI Flexible Granularity */
	uint8_t		nipc_rsvd2[4096 - 80];
} nvme_identify_primary_caps_t;

/*
 * NVMe completion queue entry status field
 */
typedef struct {
	uint16_t sf_p:1;		/* Phase Tag */
	uint16_t sf_sc:8;		/* Status Code */
	uint16_t sf_sct:3;		/* Status Code Type */
	uint16_t sf_rsvd2:2;
	uint16_t sf_m:1;		/* More */
	uint16_t sf_dnr:1;		/* Do Not Retry */
} nvme_cqe_sf_t;


/*
 * NVMe Get Log Page
 */
#define	NVME_LOGPAGE_SUP	0x00	/* Supported Logs (2.0) */
#define	NVME_LOGPAGE_ERROR	0x01	/* Error Information */
#define	NVME_LOGPAGE_HEALTH	0x02	/* SMART/Health Information */
#define	NVME_LOGPAGE_FWSLOT	0x03	/* Firmware Slot Information */
#define	NVME_LOGPAGE_NSCHANGE	0x04	/* Changed namespace (1.2) */
#define	NVME_LOGPAGE_CMDSUP	0x05	/* Cmds. Supported and Effects (1.3) */
#define	NVME_LOGPAGE_SELFTEST	0x06	/* Device self-test (1.3) */
#define	NVME_LOGPAGE_TELMHOST	0x07	/* Telemetry Host-Initiated */
#define	NVME_LOGPAGE_TELMCTRL	0x08	/* Telemetry Controller-Initiated */
#define	NVME_LOGPAGE_ENDGRP	0x09	/* Endurance Group Information (1.4) */
#define	NVME_LOGPAGE_PLATSET	0x0a	/* Predictable Lat. per NVM Set (1.4) */
#define	NVME_LOGPAGE_PLATAGG	0x0b	/* Predictable Lat. Event Agg (1.4) */
#define	NVME_LOGPAGE_ASYMNS	0x0c	/* Asymmetric Namespace Access (1.4) */
#define	NVME_LOGPAGE_PEV	0x0d	/* Persistent Event Log (1.4) */
#define	NVME_LOGPAGE_LBASTS	0x0e	/* LBA Status Information (1.4) */
#define	NVME_LOGPAGE_ENDAGG	0x0f	/* Endurance Group Event Agg. (1.4) */

#define	NVME_LOGPAGE_VEND_MIN	0xc0
#define	NVME_LOGPAGE_VEND_MAX	0xff

/*
 * Supported Log Pages (2.0). There is one entry of an nvme_logsup_t that then
 * exists on a per-log basis.
 */

/*
 * The NVMe Log Identifier specific parameter field. Currently there is only one
 * defined field for the persistent event log (pel).
 */
typedef union {
	uint16_t nsl_lidsp;		/* Raw Value */
	struct {			/* Persistent Event Log */
		uint16_t nsl_ec512:1;
		uint16_t nsl_pel_rsvd0p1:15;
	} nsl_pel;
} nvme_suplog_lidsp_t;

typedef struct {
	uint16_t ns_lsupp:1;
	uint16_t ns_ios:1;
	uint16_t ns_rsvd0p2:14;
	nvme_suplog_lidsp_t ns_lidsp;
} nvme_suplog_t;

CTASSERT(sizeof (nvme_suplog_lidsp_t) == 2);
CTASSERT(sizeof (nvme_suplog_t) == 4);

typedef struct {
	nvme_suplog_t	nl_logs[256];
} nvme_suplog_log_t;

CTASSERT(sizeof (nvme_suplog_log_t) == 1024);

/*
 * SMART / Health information
 */
typedef struct {
	uint64_t el_count;		/* Error Count */
	uint16_t el_sqid;		/* Submission Queue ID */
	uint16_t el_cid;		/* Command ID */
	nvme_cqe_sf_t el_sf;		/* Status Field */
	uint8_t	el_byte;		/* Parameter Error Location byte */
	uint8_t	el_bit:3;		/* Parameter Error Location bit */
	uint8_t el_rsvd1:5;
	uint64_t el_lba;		/* Logical Block Address */
	uint32_t el_nsid;		/* Namespace ID */
	uint8_t	el_vendor;		/* Vendor Specific Information avail */
	uint8_t el_rsvd2[64 - 29];
} nvme_error_log_entry_t;

typedef struct {
	struct {			/* Critical Warning */
		uint8_t cw_avail:1;	/* available space too low */
		uint8_t cw_temp:1;	/* temperature too high */
		uint8_t cw_reliab:1;	/* degraded reliability */
		uint8_t cw_readonly:1;	/* media is read-only */
		uint8_t cw_volatile:1;	/* volatile memory backup failed */
		uint8_t cw_rsvd:3;
	} hl_crit_warn;
	uint16_t hl_temp;		/* Temperature */
	uint8_t hl_avail_spare;		/* Available Spare */
	uint8_t hl_avail_spare_thr;	/* Available Spare Threshold */
	uint8_t hl_used;		/* Percentage Used */
	uint8_t hl_rsvd1[32 - 6];
	nvme_uint128_t hl_data_read;	/* Data Units Read */
	nvme_uint128_t hl_data_write;	/* Data Units Written */
	nvme_uint128_t hl_host_read;	/* Host Read Commands */
	nvme_uint128_t hl_host_write;	/* Host Write Commands */
	nvme_uint128_t hl_ctrl_busy;	/* Controller Busy Time */
	nvme_uint128_t hl_power_cycles;	/* Power Cycles */
	nvme_uint128_t hl_power_on_hours; /* Power On Hours */
	nvme_uint128_t hl_unsafe_shutdn; /* Unsafe Shutdowns */
	nvme_uint128_t hl_media_errors;	/* Media Errors */
	nvme_uint128_t hl_errors_logged; /* Number of errors logged */
	/* Added in NVMe 1.2 */
	uint32_t hl_warn_temp_time;	/* Warning Composite Temp Time */
	uint32_t hl_crit_temp_time;	/* Critical Composite Temp Time */
	uint16_t hl_temp_sensor_1;	/* Temperature Sensor 1 */
	uint16_t hl_temp_sensor_2;	/* Temperature Sensor 2 */
	uint16_t hl_temp_sensor_3;	/* Temperature Sensor 3 */
	uint16_t hl_temp_sensor_4;	/* Temperature Sensor 4 */
	uint16_t hl_temp_sensor_5;	/* Temperature Sensor 5 */
	uint16_t hl_temp_sensor_6;	/* Temperature Sensor 6 */
	uint16_t hl_temp_sensor_7;	/* Temperature Sensor 7 */
	uint16_t hl_temp_sensor_8;	/* Temperature Sensor 8 */
	/* Added in NVMe 1.3 */
	uint32_t hl_tmtemp_1_tc;	/* Thermal Mgmt Temp 1 Transition # */
	uint32_t hl_tmtemp_2_tc;	/* Thermal Mgmt Temp 1 Transition # */
	uint32_t hl_tmtemp_1_time;	/* Time in Thermal Mgmt Temp 1 */
	uint32_t hl_tmtemp_2_time;	/* Time in Thermal Mgmt Temp 2 */
	uint8_t hl_rsvd2[512 - 232];
} nvme_health_log_t;

/*
 * The NVMe spec allows for up to seven firmware slots.
 */
#define	NVME_MAX_FWSLOTS	7

typedef struct {
	/* Active Firmware Slot */
	uint8_t fw_afi:3;
	uint8_t fw_rsvd1:1;
	/* Next Active Firmware Slot */
	uint8_t fw_next:3;
	uint8_t fw_rsvd2:1;
	uint8_t fw_rsvd3[7];
	/* Firmware Revision / Slot */
	char fw_frs[NVME_MAX_FWSLOTS][NVME_FWVER_SZ];
	uint8_t fw_rsvd4[512 - 64];
} nvme_fwslot_log_t;

/*
 * The NVMe spec specifies that the changed namespace list contains up to
 * 1024 entries.
 */
#define	NVME_NSCHANGE_LIST_SIZE	1024

typedef struct {
	uint32_t	nscl_ns[NVME_NSCHANGE_LIST_SIZE];
} nvme_nschange_list_t;

/*
 * Commands Supported and Effects log page and information structure. This was
 * an optional log page added in NVMe 1.2.
 */
typedef struct {
	uint8_t cmd_csupp:1;	/* Command supported */
	uint8_t cmd_lbcc:1;	/* Logical block content change */
	uint8_t cmd_ncc:1;	/* Namespace capability change */
	uint8_t cmd_nic:1;	/* Namespace inventory change */
	uint8_t cmd_ccc:1;	/* Controller capability change */
	uint8_t cmd_rsvd0p5:3;
	uint8_t cmd_rsvd1;
	uint16_t cmd_cse:3;	/* Command submission and execution */
	uint16_t cmd_uuid:1;	/* UUID select supported, 1.4 */
	uint16_t cmd_csp:12;	/* Command Scope, 2.0 */
} nvme_cmdeff_t;

CTASSERT(sizeof (nvme_cmdeff_t) == 4);

typedef enum {
	NVME_CMDEFF_CSP_NS		= 1 << 0,
	NVME_CMDEFF_CSP_CTRL		= 1 << 1,
	NVME_CMDEFF_CSP_SET		= 1 << 2,
	NVME_CMDEFF_CSP_ENDURANCE	= 1 << 3,
	NVME_CMDEFF_CSP_DOMAIN		= 1 << 4,
	NVME_CMDEFF_CSP_NVM		= 1 << 5
} nvme_cmdeff_csp_t;

typedef enum {
	NVME_CMDEFF_CSE_NONE	= 0,
	NVME_CMDEFF_CSE_NS,
	NVME_CMDEFF_CSE_CTRL
} nvme_cmdeff_cse_t;

typedef struct {
	nvme_cmdeff_t	cme_admin[256];
	nvme_cmdeff_t	cme_io[256];
	uint8_t		cme_rsvd2048[2048];
} nvme_cmdeff_log_t;

CTASSERT(sizeof (nvme_cmdeff_log_t) == 4096);
CTASSERT(offsetof(nvme_cmdeff_log_t, cme_rsvd2048) == 2048);

/*
 * Persistent Event Log Header. This log was added in NVMe 1.4. It begins with a
 * 512 byte header which is defined below. It uses the log specific parameter to
 * determine how to access it. Internally the drive contains the notion of a
 * context that must be released and accessed.
 */
typedef struct {
	uint8_t		pel_lid;	/* Log Identifier */
	uint8_t		pel_rsvd1[3];
	uint32_t	pel_tnev;	/* Total Number of Events */
	uint64_t	pel_tll;	/* Total Log Length */
	uint8_t		pel_lrev;	/* Log Revision */
	uint8_t		pel_rsvd17[1];
	uint16_t	pel_lhl;	/* Log Header Length */
	uint64_t	pel_tstmp;	/* Timestamp */
	nvme_uint128_t	pel_poh;	/* Power on Hours */
	uint64_t	pel_pwrcc;	/* Power Cycle Count */
	uint16_t	pel_vid;	/* PCI Vendor ID */
	uint16_t	pel_ssvid;	/* PCI Subsystem Vendor ID */
	uint8_t		pel_sn[NVME_SERIAL_SZ];	/* Serial Number */
	uint8_t		pel_mn[NVME_MODEL_SZ];	/* Model Number */
	uint8_t		pel_subnqn[372 - 116];	/* NVM Subsystem Qual. Name */
	uint16_t	pel_gnum;	/* Generation Number (2.0) */
	struct {			/* Reporting Context Info (2.0) */
		uint16_t pel_rcpid;	/* Port Identifier */
		uint16_t pel_rcpit:2;	/* Port Identifier Type */
		uint16_t pel_rce:1;	/* Reporting Context Exists */
		uint16_t pel_rsvd19:13;
	} pel_rci;
	uint8_t		pel_rsvd378[480 - 378];
	uint8_t		pel_seb[32];	/* Supported Events Bitmap */
	uint8_t		pel_data[];
} nvme_pev_log_t;

/*
 * This enum represents the bit index for various features in the supported
 * events bitmap.
 */
typedef enum {
	NVME_SEB_SHLSES	= 1,	/* SMART / Health Log */
	NVME_SEB_FCES = 2,	/* Firmware Commit */
	NVME_SEB_TCES = 3,	/* Timestamp Change */
	NVME_SEB_PRES = 4,	/* Power-on or Reset */
	NVME_SEB_NSHEES = 5,	/* NVM Subsystem Hardware Error */
	NVME_SEB_CNES = 6,	/* Change Namespace */
	NVME_SEB_FNSES = 7,	/* Format NVM Start */
	NVME_SEB_FNCES = 8,	/* Format NVM Completion */
	NVME_SEB_SSES = 9,	/* Sanitize Start */
	NVME_SEB_SCES = 10,	/* Sanitize Completion */
	NVME_SEB_SFES = 11,	/* Set Feature */
	NVME_SEB_TLCES = 12,	/* Telemetry Log Create */
	NVME_SEB_TEES = 13,	/* Thermal Excursion */
	NVME_SEB_SMVES = 14,	/* Sanitize Media Verification (2.1) */
	NVME_SEB_VSES = 222,	/* Vendor Specific */
	NVME_SEB_TCG = 223	/* TCG */
} nvme_pev_seb_t;

/*
 * Log specific fields for the persistent event log. These are required by the
 * log.
 */
typedef enum {
	/*
	 * Read the persistent event log, presumes that a context has already
	 * been established.
	 */
	NVME_PEV_LSP_READ	= 0,
	/*
	 * Establish a new context and then read a portion of the event log. Any
	 * prior existing context must already have been released.
	 */
	NVME_PEV_LSP_EST_CTX_READ,
	/*
	 * Releases the persistent event log context. It is legal for this
	 * context to already have been released.
	 */
	NVME_PEV_LSP_REL_CTX,
	/*
	 * This establishes a context and reads the fixed 512 bytes. The
	 * controller is supposed to ignore any offset and length fields and
	 * always read 512 bytes regardless. This is present starting in NVMe
	 * 2.0.
	 */
	NVME_PEV_LSP_EST_CTX_READ_512
} nvme_pev_log_lsp_t;

#ifndef __CHECKER__
CTASSERT(sizeof (nvme_pev_log_t) == 512);
CTASSERT(offsetof(nvme_pev_log_t, pel_gnum) == 372);
#endif

/*
 * NVMe Telemetry Header
 */
typedef struct {
	uint8_t ntl_lid;
	uint8_t ntl_rsvd1[4];
	uint8_t ntl_ieee[3];
	uint16_t ntl_thda1lb;
	uint16_t ntl_thda2lb;
	uint16_t ntl_thda3lb;
	uint8_t ntl_rsvd14[2];
	uint32_t ntl_thda4lb;
	uint8_t ntl_rsvd20[380 - 20];
	uint8_t ntl_ths;
	uint8_t ntl_thdgn;
	uint8_t ntl_tcda;
	uint8_t ntl_tcdgn;
	uint8_t ntl_rid[512 - 384];
	uint8_t ntl_data[];
} nvme_telemetry_log_t;

CTASSERT(sizeof (nvme_telemetry_log_t) == 512);

#define	NVME_TELMCTRL_LSP_CTHID	1

/*
 * NVMe Format NVM
 */
#define	NVME_FRMT_SES_NONE	0
#define	NVME_FRMT_SES_USER	1
#define	NVME_FRMT_SES_CRYPTO	2
#define	NVME_FRMT_MAX_SES	2

#define	NVME_FRMT_MAX_LBAF	15

typedef union {
	struct {
		uint32_t fm_lbaf:4;		/* LBA Format */
		uint32_t fm_ms:1;		/* Metadata Settings */
		uint32_t fm_pi:3;		/* Protection Information */
		uint32_t fm_pil:1;		/* Prot. Information Location */
		uint32_t fm_ses:3;		/* Secure Erase Settings */
		uint32_t fm_resvd:20;
	} b;
	uint32_t r;
} nvme_format_nvm_t;


/*
 * NVMe Get / Set Features
 */
#define	NVME_FEAT_ARBITRATION	0x01	/* Command Arbitration */
#define	NVME_FEAT_POWER_MGMT	0x02	/* Power Management */
#define	NVME_FEAT_LBA_RANGE	0x03	/* LBA Range Type */
#define	NVME_FEAT_TEMPERATURE	0x04	/* Temperature Threshold */
#define	NVME_FEAT_ERROR		0x05	/* Error Recovery */
#define	NVME_FEAT_WRITE_CACHE	0x06	/* Volatile Write Cache */
#define	NVME_FEAT_NQUEUES	0x07	/* Number of Queues */
#define	NVME_FEAT_INTR_COAL	0x08	/* Interrupt Coalescing */
#define	NVME_FEAT_INTR_VECT	0x09	/* Interrupt Vector Configuration */
#define	NVME_FEAT_WRITE_ATOM	0x0a	/* Write Atomicity */
#define	NVME_FEAT_ASYNC_EVENT	0x0b	/* Asynchronous Event Configuration */
#define	NVME_FEAT_AUTO_PST	0x0c	/* Autonomous Power State Transition */
					/* (1.1) */
#define	NVME_FEAT_HMB		0x0d	/* Host Memory Buffer (1.2) */
#define	NVME_FEAT_TIMESTAMP	0x0e	/* Timestamp (1.3) */
#define	NVME_FEAT_KEEP_ALIVE	0x0f	/* Keep Alive Timer (1.2) */
#define	NVME_FEAT_HCTM		0x10	/* Host Controlled Thermal Mgmt (1.3) */
#define	NVME_FEAT_NOPSC		0x11	/* Non-op Power State Cfg. (1.3) */
#define	NVME_FEAT_READ_REC	0x12	/* Read Recovery Level Cfg (1.4) */
#define	NVME_FEAT_PLM_CFG	0x13	/* Predictable Lat. Mode Cfg. (1.4) */
#define	NVME_FEAT_PLM_WIN	0x14	/* ^ Window (1.4) */
#define	NVME_FEAT_LBA_STS_ATTR	0x15	/* LBA Status Info Attr (1.4) */
#define	NVME_FEAT_HOST_BEHAVE	0x16	/* Host Behavior (1.4) */
#define	NVME_FEAT_SAN_CFG	0x17	/* Sanitize Config (1.4) */
#define	NVME_FEAT_EGRP_EVENT	0x18	/* Endurance Group Event Config (1.4) */
#define	NVME_FEAT_IO_CMD_SET	0x19	/* I/O Command Set Profile (2.0) */
#define	NVME_FEAT_IO_CMD_SET	0x19	/* I/O Command Set Profile (2.0) */
#define	NVME_FEAT_SPINUP	0x1a	/* Spinup Control (2.0) */
#define	NVME_FEAT_PLS		0x1b	/* Power Loss Signaling (2.1) */
#define	NVME_FEAT_FDP		0x1d	/* Flexible Device Placement (2.1) */
#define	NVME_FEAT_FDP_EVENTS	0x1e	/* ^ Events (2.1) */
#define	NVME_FEAT_NS_LABEL	0x1f	/* Namespace Admin Label (2.1) */
#define	NVME_FEAT_CTRL_DQ	0x21	/* Controller Data Queue (2.1) */
#define	NVME_FEAT_ENH_CTRL_META	0x7d	/* Enhanced Controller Metadata (2.0) */
#define	NVME_FEAT_CTRL_META	0x7e	/* Controller Metadata (2.0) */
#define	NVME_FEAT_NS_META	0x7f	/* Namespace Metadata (2.0) */

#define	NVME_FEAT_PROGRESS	0x80	/* Software Progress Marker */

/*
 * This enumeration represents the capabilities in the Get Features select / Set
 * Features save options. This was introduced in NVMe 1.1 and the values below
 * match the specification. An optional feature in the identify controller data
 * structure is set to indicate that this is supported (id_oncs.on_save).
 */
typedef enum {
	NVME_FEATURE_SEL_CURRENT	= 0,
	NVME_FEATURE_SEL_DEFAULT,
	NVME_FEATURE_SEL_SAVED,
	NVME_FEATURE_SEL_SUPPORTED
} nvme_feature_sel_t;

typedef union {
	struct {
		uint32_t gt_fid:8;	/* Feature ID */
		uint32_t gt_sel:3;	/* Select */
		uint32_t gt_rsvd:21;
	} b;
	uint32_t r;
} nvme_get_features_dw10_t;

/* Arbitration Feature */
typedef union {
	struct {
		uint8_t arb_ab:3;	/* Arbitration Burst */
		uint8_t arb_rsvd:5;
		uint8_t arb_lpw;	/* Low Priority Weight */
		uint8_t arb_mpw;	/* Medium Priority Weight */
		uint8_t arb_hpw;	/* High Priority Weight */
	} b;
	uint32_t r;
} nvme_arbitration_t;

/* Power Management Feature */
typedef union {
	struct {
		uint32_t pm_ps:5;	/* Power State */
		uint32_t pm_wh:3;	/* Workload Hint (1.2) */
		uint32_t pm_rsvd:24;
	} b;
	uint32_t r;
} nvme_power_mgmt_t;

/* LBA Range Type Feature */
typedef union {
	struct {
		uint32_t lr_num:6;	/* Number of LBA ranges */
		uint32_t lr_rsvd:26;
	} b;
	uint32_t r;
} nvme_lba_range_type_t;

typedef struct {
	uint8_t lr_type;		/* Type */
	struct {			/* Attributes */
		uint8_t lr_write:1;	/* may be overwritten */
		uint8_t lr_hidden:1;	/* hidden from OS/EFI/BIOS */
		uint8_t lr_rsvd1:6;
	} lr_attr;
	uint8_t lr_rsvd2[14];
	uint64_t lr_slba;		/* Starting LBA */
	uint64_t lr_nlb;		/* Number of Logical Blocks */
	uint8_t lr_guid[16];		/* Unique Identifier */
	uint8_t lr_rsvd3[16];
} nvme_lba_range_t;

#define	NVME_LBA_RANGE_BUFSIZE	4096

/* Temperature Threshold Feature */
typedef union {
	struct {
		uint16_t tt_tmpth;	/* Temperature Threshold */
		uint16_t tt_tmpsel:4;	/* Temperature Select */
		uint16_t tt_thsel:2;	/* Temperature Type */
		uint16_t tt_tmpthh:3;	/* Threshold Hysteresis (2.1) */
		uint16_t tt_resv:7;
	} b;
	uint32_t r;
} nvme_temp_threshold_t;

#define	NVME_TEMP_THRESH_MAX_SENSOR	8
#define	NVME_TEMP_THRESH_ALL	0xf
#define	NVME_TEMP_THRESH_OVER	0x00
#define	NVME_TEMP_THRESH_UNDER	0x01

/* Error Recovery Feature */
typedef union {
	struct {
		uint16_t er_tler;	/* Time-Limited Error Recovery */
		uint16_t er_dulbe:1;	/* Deallocated or Unwritten (1.2) */
		uint16_t er_rsvd:15;
	} b;
	uint32_t r;
} nvme_error_recovery_t;

/* Volatile Write Cache Feature */
typedef union {
	struct {
		uint32_t wc_wce:1;	/* Volatile Write Cache Enable */
		uint32_t wc_rsvd:31;
	} b;
	uint32_t r;
} nvme_write_cache_t;

/* Number of Queues Feature */
typedef union {
	struct {
		uint16_t nq_nsq;	/* Number of Submission Queues */
		uint16_t nq_ncq;	/* Number of Completion Queues */
	} b;
	uint32_t r;
} nvme_nqueues_t;

/* Interrupt Coalescing Feature */
typedef union {
	struct {
		uint8_t ic_thr;		/* Aggregation Threshold */
		uint8_t ic_time;	/* Aggregation Time */
		uint16_t ic_rsvd;
	} b;
	uint32_t r;
} nvme_intr_coal_t;

/* Interrupt Configuration Features */
typedef union {
	struct {
		uint16_t iv_iv;		/* Interrupt Vector */
		uint16_t iv_cd:1;	/* Coalescing Disable */
		uint16_t iv_rsvd:15;
	} b;
	uint32_t r;
} nvme_intr_vect_t;

/* Write Atomicity Feature */
typedef union {
	struct {
		uint32_t wa_dn:1;	/* Disable Normal */
		uint32_t wa_rsvd:31;
	} b;
	uint32_t r;
} nvme_write_atomicity_t;

/* Asynchronous Event Configuration Feature */
typedef union {
	struct {
		uint32_t aec_avail:1;	/* Available space too low */
		uint32_t aec_temp:1;	/* Temperature too high */
		uint32_t aec_reliab:1;	/* Degraded reliability */
		uint32_t aec_readonly:1;	/* Media is read-only */
		uint32_t aec_volatile:1;	/* Volatile mem backup failed */
		uint32_t aec_pmrro:1;	/* Persist Memory Read Only (X.X) */
		uint32_t aec_rsvd1:2;
		uint32_t aec_nsan:1;	/* Namespace attribute notices (1.2) */
		uint32_t aec_fwact:1;	/* Firmware activation notices (1.2) */
		uint32_t aec_telln:1;	/* Telemetry log notices (1.3) */
		uint32_t aec_ansacn:1;	/* Asymm. NS access change (1.4) */
		uint32_t aec_plat:1;	/* Predictable latency ev. agg. (1.4) */
		uint32_t aec_lbasi:1;	/* LBA status information (1.4) */
		uint32_t aec_egeal:1;	/* Endurance group ev. agg. (1.4) */
		uint32_t aec_nnsshdn:1;	/* Normal NVM Subsys Shutdown (2.0) */
		uint32_t aec_tthry:1;	/* Temp Thres Hysteresis (2.1) */
		uint32_t aec_rassn:1;	/* Reachability Association (2.1) */
		uint32_t aec_rgpr0:1;	/* Reachability Group (2.1) */
		uint32_t aec_ansan:1;	/* Allocated Namespace Attr. (2.1) */
		uint32_t aec_rsvd20:7;
		uint32_t aec_zdcn:1;	/* Zone Descriptor Changed (2.0) */
		/* Fabrics Specific */
		uint32_t aec_pmdrlpcn:1;	/* Pull Model Change (2.1) */
		uint32_t aec_adlpcn:1;	/* AVE Discovery Change (2.1) */
		uint32_t aec_hdlpcn:1;	/* Host Discovery Change (2.1) */
		uint32_t aec_dlpcn:1;	/* Discovery Change (2.0) */
	} b;
	uint32_t r;
} nvme_async_event_conf_t;

/* Autonomous Power State Transition Feature (1.1) */
typedef union {
	struct {
		uint32_t apst_apste:1;	/* APST enabled */
		uint32_t apst_rsvd:31;
	} b;
	uint32_t r;
} nvme_auto_power_state_trans_t;

typedef struct {
	uint32_t apst_rsvd1:3;
	uint32_t apst_itps:5;	/* Idle Transition Power State */
	uint32_t apst_itpt:24;	/* Idle Time Prior to Transition */
	uint32_t apst_rsvd2;
} nvme_auto_power_state_t;

#define	NVME_AUTO_PST_BUFSIZE	256

/* Host Behavior */
typedef struct {
	uint8_t nhb_acre;	/* Advanced Command Retry (1.4) */
	uint8_t nhb_etdas;	/* Telemetry Area 4 (2.0) */
	uint8_t nhb_lbafee;	/* Extended LBA Formats (2.0) */
	uint8_t nhb_hdisns;	/* Dispersed Namespaces (2.1) */
	uint16_t nhb_cdfe;	/* Copy Descriptor (2.1) */
	uint8_t nhb_rsvd[512 - 6];
} nvme_host_behavior_t;

CTASSERT(sizeof (nvme_host_behavior_t) == 512);

/* Software Progress Marker Feature */
typedef union {
	struct {
		uint8_t spm_pbslc;	/* Pre-Boot Software Load Count */
		uint8_t spm_rsvd[3];
	} b;
	uint32_t r;
} nvme_software_progress_marker_t;

/*
 * Firmware Commit - Command Dword 10
 */
#define	NVME_FWC_SAVE		0x0	/* Save image only */
#define	NVME_FWC_SAVE_ACTIVATE	0x1	/* Save and activate at next reset */
#define	NVME_FWC_ACTIVATE	0x2	/* Activate slot at next reset */
#define	NVME_FWC_ACTIVATE_IMMED	0x3	/* Activate slot immediately */

/*
 * Firmware slot number is only 3 bits, and zero is not allowed.
 * Valid range is 1 to 7.
 */
#define	NVME_FW_SLOT_MIN	1U	/* lowest allowable slot number ... */
#define	NVME_FW_SLOT_MAX	7U	/* ... and highest */

/*
 * Some constants to make verification of DWORD variables and arguments easier.
 * A DWORD is 4 bytes.
 */
#define	NVME_DWORD_SHIFT	2
#define	NVME_DWORD_SIZE		(1 << NVME_DWORD_SHIFT)
#define	NVME_DWORD_MASK		(NVME_DWORD_SIZE - 1)

/*
 * The maximum offset a firmware image segment can be loaded at is the number
 * of DWORDS in a 32 bit field. The maximum length of such a segment is the
 * same. Expressed in bytes it is:
 */
#define	NVME_FW_OFFSETB_MAX	((u_longlong_t)UINT32_MAX << NVME_DWORD_SHIFT)
#define	NVME_FW_LENB_MAX	NVME_FW_OFFSETB_MAX

typedef union {
	struct {
		uint32_t fc_slot:3;	/* Firmware slot */
		uint32_t fc_action:3;	/* Commit action */
		uint32_t fc_rsvd:26;
	} b;
	uint32_t r;
} nvme_firmware_commit_dw10_t;

#pragma pack() /* pack(1) */

/* NVMe completion status code type */
#define	NVME_CQE_SCT_GENERIC	0	/* Generic Command Status */
#define	NVME_CQE_SCT_SPECIFIC	1	/* Command Specific Status */
#define	NVME_CQE_SCT_INTEGRITY	2	/* Media and Data Integrity Errors */
#define	NVME_CQE_SCT_PATH	3	/* Path Related Status (1.4) */
#define	NVME_CQE_SCT_VENDOR	7	/* Vendor Specific */

/*
 * Status code ranges
 */
#define	NVME_CQE_SC_GEN_MIN		0x00
#define	NVME_CQE_SC_GEN_MAX		0x7f
#define	NVME_CQE_SC_CSI_MIN		0x80
#define	NVME_CQE_SC_CSI_MAX		0xbf
#define	NVME_CQE_SC_VEND_MIN		0xc0
#define	NVME_CQE_SC_VEND_MAX		0xff

/* NVMe completion status code (generic) */
#define	NVME_CQE_SC_GEN_SUCCESS		0x0	/* Successful Completion */
#define	NVME_CQE_SC_GEN_INV_OPC		0x1	/* Invalid Command Opcode */
#define	NVME_CQE_SC_GEN_INV_FLD		0x2	/* Invalid Field in Command */
#define	NVME_CQE_SC_GEN_ID_CNFL		0x3	/* Command ID Conflict */
#define	NVME_CQE_SC_GEN_DATA_XFR_ERR	0x4	/* Data Transfer Error */
#define	NVME_CQE_SC_GEN_ABORT_PWRLOSS	0x5	/* Cmds Aborted / Pwr Loss */
#define	NVME_CQE_SC_GEN_INTERNAL_ERR	0x6	/* Internal Error */
#define	NVME_CQE_SC_GEN_ABORT_REQUEST	0x7	/* Command Abort Requested */
#define	NVME_CQE_SC_GEN_ABORT_SQ_DEL	0x8	/* Cmd Aborted / SQ deletion */
#define	NVME_CQE_SC_GEN_ABORT_FUSE_FAIL	0x9	/* Cmd Aborted / Failed Fused */
#define	NVME_CQE_SC_GEN_ABORT_FUSE_MISS	0xa	/* Cmd Aborted / Missing Fusd */
#define	NVME_CQE_SC_GEN_INV_NS		0xb	/* Inval Namespace or Format */
#define	NVME_CQE_SC_GEN_CMD_SEQ_ERR	0xc	/* Command Sequence Error */
#define	NVME_CQE_SC_GEN_INV_SGL_LAST	0xd	/* Inval SGL Last Seg Desc */
#define	NVME_CQE_SC_GEN_INV_SGL_NUM	0xe	/* Inval Number of SGL Desc */
#define	NVME_CQE_SC_GEN_INV_DSGL_LEN	0xf	/* Data SGL Length Invalid */
#define	NVME_CQE_SC_GEN_INV_MSGL_LEN	0x10	/* Metadata SGL Length Inval */
#define	NVME_CQE_SC_GEN_INV_SGL_DESC	0x11	/* SGL Descriptor Type Inval */
/* Added in NVMe 1.2 */
#define	NVME_CQE_SC_GEN_INV_USE_CMB	0x12	/* Inval use of Ctrl Mem Buf */
#define	NVME_CQE_SC_GEN_INV_PRP_OFF	0x13	/* PRP Offset Invalid */
#define	NVME_CQE_SC_GEN_AWU_EXCEEDED	0x14	/* Atomic Write Unit Exceeded */
#define	NVME_CQE_SC_GEN_OP_DENIED	0x15	/* Operation Denied */
#define	NVME_CQE_SC_GEN_INV_SGL_OFF	0x16	/* SGL Offset Invalid */
#define	NVME_CQE_SC_GEN_INV_SGL_ST	0x17	/* SGL Sub type Invalid */
#define	NVME_CQE_SC_GEN_INCON_HOSTID	0x18	/* Host ID Inconsistent fmt */
#define	NVME_CQE_SC_GEN_KA_EXP		0x19	/* Keep Alive Timer Expired */
#define	NVME_CQE_SC_GEN_INV_KA_TO	0x1a	/* Keep Alive Timeout Invalid */
/* Added in NVMe 1.3 */
#define	NVME_CQE_SC_GEN_ABORT_PREEMPT	0x1b	/* Cmd aborted due to preempt */
#define	NVME_CQE_SC_GEN_SANITIZE_FAIL	0x1c	/* Sanitize Failed */
#define	NVME_CQE_SC_GEN_SANITIZING	0x1d	/* Sanitize in Progress */
#define	NVME_CQE_SC_GEN_INV_SGL_GRAN	0x1e	/* SGL Data Block Gran. Inval */
#define	NVME_CQE_SC_GEN_NO_CMD_Q_CMD	0x1f	/* Command not sup for CMB Q */
/* Added in NVMe 1.4 */
#define	NVME_CQE_SC_GEN_NS_RDONLY	0x20	/* Namespace is write prot. */
#define	NVME_CQE_SC_GEN_CMD_INTR	0x21	/* Command Interrupted */
#define	NVME_CQE_SC_GEN_TRANSIENT	0x22	/* Transient Transport Error */
/* Added in NVMe 2.0 */
#define	NVME_CQE_SC_GEN_CMD_LOCK	0x23	/* Command/Feature Lockdown */
#define	NVME_CQE_SC_ADM_MEDIA_NR	0x24	/* Admin Cmd Media Not Ready */

/* NVMe completion status code (generic NVM commands) */
#define	NVME_CQE_SC_GEN_NVM_LBA_RANGE	0x80	/* LBA Out Of Range */
#define	NVME_CQE_SC_GEN_NVM_CAP_EXC	0x81	/* Capacity Exceeded */
#define	NVME_CQE_SC_GEN_NVM_NS_NOTRDY	0x82	/* Namespace Not Ready */
#define	NVME_CQE_SC_GEN_NVM_RSV_CNFLCT	0x83	/* Reservation Conflict */
#define	NVME_CQE_SC_GEN_NVM_FORMATTING	0x84	/* Format in progress (1.2) */
/* Added in NVMe 2.0 */
#define	NVME_CQE_SC_GEN_KEY_INV_VAL	0x85	/* Invalid value size */
#define	NVME_CQE_SC_GEN_KEY_INV_KEY	0x86	/* Invalid key size */
#define	NVME_CQE_SC_GEN_KEY_ENOENT	0x87	/* KV Key Does Not Exist */
#define	NVME_CQE_SC_GEN_KEY_UNRECOV	0x88	/* Unrecovered Error */
#define	NVME_CQE_SC_GEN_KEY_EXISTS	0x89	/* Key already exists */

/* NVMe completion status code (command specific) */
#define	NVME_CQE_SC_SPC_INV_CQ		0x0	/* Completion Queue Invalid */
#define	NVME_CQE_SC_SPC_INV_QID		0x1	/* Invalid Queue Identifier */
#define	NVME_CQE_SC_SPC_MAX_QSZ_EXC	0x2	/* Max Queue Size Exceeded */
#define	NVME_CQE_SC_SPC_ABRT_CMD_EXC	0x3	/* Abort Cmd Limit Exceeded */
#define	NVME_CQE_SC_SPC_ASYNC_EVREQ_EXC	0x5	/* Async Event Request Limit */
#define	NVME_CQE_SC_SPC_INV_FW_SLOT	0x6	/* Invalid Firmware Slot */
#define	NVME_CQE_SC_SPC_INV_FW_IMG	0x7	/* Invalid Firmware Image */
#define	NVME_CQE_SC_SPC_INV_INT_VECT	0x8	/* Invalid Interrupt Vector */
#define	NVME_CQE_SC_SPC_INV_LOG_PAGE	0x9	/* Invalid Log Page */
#define	NVME_CQE_SC_SPC_INV_FORMAT	0xa	/* Invalid Format */
#define	NVME_CQE_SC_SPC_FW_RESET	0xb	/* FW Application Reset Reqd */
#define	NVME_CQE_SC_SPC_INV_Q_DEL	0xc	/* Invalid Queue Deletion */
#define	NVME_CQE_SC_SPC_FEAT_SAVE	0xd	/* Feature Id Not Saveable */
#define	NVME_CQE_SC_SPC_FEAT_CHG	0xe	/* Feature Not Changeable */
#define	NVME_CQE_SC_SPC_FEAT_NS_SPEC	0xf	/* Feature Not Namespace Spec */
/* Added in NVMe 1.2 */
#define	NVME_CQE_SC_SPC_FW_NSSR		0x10	/* FW Application NSSR Reqd */
#define	NVME_CQE_SC_SPC_FW_NEXT_RESET	0x11	/* FW Application Next Reqd */
#define	NVME_CQE_SC_SPC_FW_MTFA		0x12	/* FW Application Exceed MTFA */
#define	NVME_CQE_SC_SPC_FW_PROHIBITED	0x13	/* FW Application Prohibited */
#define	NVME_CQE_SC_SPC_FW_OVERLAP	0x14	/* Overlapping FW ranges */
#define	NVME_CQE_SC_SPC_NS_INSUF_CAP	0x15	/* NS Insufficient Capacity */
#define	NVME_CQE_SC_SPC_NS_NO_ID	0x16	/* NS ID Unavailable */
/* 0x17 is reserved */
#define	NVME_CQE_SC_SPC_NS_ATTACHED	0x18	/* NS Already Attached */
#define	NVME_CQE_SC_SPC_NS_PRIV		0x19	/* NS is private */
#define	NVME_CQE_SC_SPC_NS_NOT_ATTACH	0x1a	/* NS Not Attached */
#define	NVME_CQE_SC_SPC_THIN_ENOTSUP	0x1b	/* Thin Provisioning ENOTSUP */
#define	NVME_CQE_SC_SPC_INV_CTRL_LIST	0x1c	/* Controller list invalid */
/* Added in NVMe 1.3 */
#define	NVME_CQE_SC_SPC_SELF_TESTING	0x1d	/* Self-test in progress */
#define	NVME_CQE_SC_SPC_NO_BP_WRITE	0x1e	/* No Boot Partition Write */
#define	NVME_CQE_SC_SPC_INV_CTRL_ID	0x1f	/* Invalid Controller Id */
#define	NVME_CQE_SC_SPC_INV_SEC_CTRL	0x20	/* Invalid Sec. Ctrl state */
#define	NVME_CQE_SC_SPC_INV_CTRL_NRSRC	0x21	/* Inv. # Ctrl Resources */
#define	NVME_CQE_SC_SPC_INV_RSRC_ID	0x22	/* Inv. Resource ID */
/* Added in NVMe 1.4 */
#define	NVME_CQE_SC_SPC_NO_SAN_PMR	0x23	/* Sanitize prohib. w/ pmem */
#define	NVME_CQE_SC_SPC_INV_ANA_GID	0x24	/* Invalid ANA group ID */
#define	NVME_CQE_SC_SPC_ANA_ATTACH	0x25	/* ANA Attach Failed */
/* Added in NVMe 2.0 */
#define	NVME_CQE_SC_SPC_INSUF_CAP	0x26	/* Insufficient Capacity */
#define	NVME_CQE_SC_SPC_NS_ATTACH_LIM	0x27	/* NS Attach Limit Exceeded */
#define	NVME_CQE_SC_SPC_LOCKDOWN_UNSUP	0x28	/* Prohib Cmd Exec Not Sup */
#define	NVME_CQE_SC_SPC_UNSUP_IO_CMD	0x29	/* I/O Command set not sup */
#define	NVME_CQE_SC_SPC_DIS_IO_CMD	0x2a	/* I/O Command set not enab */
#define	NVME_CQE_SC_SPC_INV_CMD_COMBO	0x2b	/* I/O command set combo rej */
#define	NVME_CQE_SC_SPC_INV_IO_CMD	0x2c	/* Invalid I/O command set */
#define	NVME_CQE_SC_SPC_UNAVAIL_ID	0x2d	/* Unavailable ID */


/* NVMe completion status code (I/O command specific) */
#define	NVME_CQE_SC_SPC_NVM_CNFL_ATTR	0x80	/* Conflicting Attributes */
#define	NVME_CQE_SC_SPC_NVM_INV_PROT	0x81	/* Invalid Protection */
#define	NVME_CQE_SC_SPC_NVM_READONLY	0x82	/* Write to Read Only Range */
/* Added in 2.0 */
#define	NVME_CQE_SC_SPC_IO_LIMIT	0x83	/* Cmd Size Limit Exceeded */
/* 0x84 to 0xb7 are reserved */
#define	NVME_CQE_SC_SPC_ZONE_BDRY_ERR	0xb8	/* Zoned Boundary Error */
#define	NVME_CQE_SC_SPC_ZONE_FULL	0xb9	/* Zone is Full */
#define	NVME_CQE_SC_SPC_ZONE_RDONLY	0xba	/* Zone is Read Only */
#define	NVME_CQE_SC_SPC_ZONE_OFFLINE	0xbb	/* Zone is Offline */
#define	NVME_CQE_SC_SPC_ZONE_INV_WRITE	0xbc	/* Zone Invalid Write */
#define	NVME_CQE_SC_SPC_ZONE_ACT	0xbd	/* Too May Active Zones */
#define	NVME_CQE_SC_SPC_ZONE_OPEN	0xbe	/* Too May Open Zones */
#define	NVME_CQE_SC_SPC_INV_ZONE_TRANS	0xbf	/* Invalid Zone State Trans */

/* NVMe completion status code (data / metadata integrity) */
#define	NVME_CQE_SC_INT_NVM_WRITE	0x80	/* Write Fault */
#define	NVME_CQE_SC_INT_NVM_READ	0x81	/* Unrecovered Read Error */
#define	NVME_CQE_SC_INT_NVM_GUARD	0x82	/* Guard Check Error */
#define	NVME_CQE_SC_INT_NVM_APPL_TAG	0x83	/* Application Tag Check Err */
#define	NVME_CQE_SC_INT_NVM_REF_TAG	0x84	/* Reference Tag Check Err */
#define	NVME_CQE_SC_INT_NVM_COMPARE	0x85	/* Compare Failure */
#define	NVME_CQE_SC_INT_NVM_ACCESS	0x86	/* Access Denied */
/* Added in 1.2 */
#define	NVME_CQE_SC_INT_NVM_DEALLOC	0x87	/* Dealloc Log Block */
/* Added in 2.0 */
#define	NVME_CQE_SC_INT_NVM_TAG		0x88	/* End-to-End Storage Tag Err */

/* NVMe completion status code (path related) */
/* Added in NVMe 1.4 */
#define	NVME_CQE_SC_PATH_INT_ERR	0x00	/* Internal Path Error */
#define	NVME_CQE_SC_PATH_AA_PLOSS	0x01	/* Asym Access Pers Loss */
#define	NVME_CQE_SC_PATH_AA_INACC	0x02	/* Asym Access Inaccessible */
#define	NVME_CQE_SC_PATH_AA_TRANS	0x03	/* Asym Access Transition */
#define	NVME_CQE_SC_PATH_CTRL_ERR	0x60	/* Controller Path Error */
#define	NVME_CQE_SC_PATH_HOST_ERR	0x70	/* Host Path Error */
#define	NVME_CQE_SC_PATH_HOST_ABRT	0x71	/* Cmd aborted by host */

/*
 * Controller information (NVME_IOC_CTRL_INFO). This is a consolidation of misc.
 * information that we want to know about a controller.
 */
typedef struct {
	nvme_ioctl_common_t nci_common;
	nvme_identify_ctrl_t nci_ctrl_id;
	nvme_identify_nsid_t nci_common_ns;
	nvme_version_t nci_vers;
	nvme_capabilities_t nci_caps;
	uint32_t nci_nintrs;
} nvme_ioctl_ctrl_info_t;

/*
 * NVME namespace states.
 *
 * The values are defined entirely by the driver. Some states correspond to
 * namespace states described by the NVMe specification r1.3 section 6.1, others
 * are specific to the implementation of this driver. These are present in the
 * nvme_ns_kinfo_t that is used with the NVME_IOC_NS_INFO ioctl. Devices that
 * support Namespace Management have the ability to transition through these
 * states directly. Devices without it may be able to have namespaces in these
 * states depending on the version.
 *
 * The states are as follows:
 * - UNALLOCATED: The namespace ID exists, but has no corresponding NVM
 *   allocation as per the NVMe spec. It leaves this state with an NVMe
 *   Namespace Management NS create command: NVME_IOC_NS_CREATE.
 *
 * - ALLOCATED: The namespace exists in the controller as per the NVMe spec. It
 *   becomes ACTIVE (or IGNORED) by performing a controller attach comand:
 *   NVME_IOC_CTRL_ATTACH. It becomes unallocated by performing an NVMe
 *   Namespace Management NS delete command: NVME_IOC_NS_DELETE.
 *
 * - ACTIVE: The namespace exists and is attached to this controller as per the
 *   NVMe spec. From the hardware's perspective the namespace is usable.
 *
 *   Not all namespaces are supported by the kernel. For example, a namespace
 *   may use features that the NVMe device driver does not support such as
 *   end-to-end data protection features or a different command set.
 *
 *   When a namespace enters the active state, we will immediately evaluate
 *   whether or not we can support a block device (via blkdev(4D)) on this
 *   namespace. If we can, then we will immediately advance to the NOT_IGNORED
 *   state. Otherwise, to transition to the NOT_IGNORED state, the namespace
 *   must be formatted with the FORMAT NVM command with supported settings. The
 *   namespace can transition back to the ALLOCATED state by performing a
 *   NVME_IOC_CTRL_DETACH ioctl.
 *
 * - NOT_IGNORED: The namespace is active from the controller perspective and is
 *   formatted with settings that would support blkdev(4D) being attached;
 *   however, there is no blkdev(4D) instance currently attached. A device
 *   transitions from the NOT_IGNORED to the ATTACHED state by actively
 *   attaching a blkdev(4D) instance to the namespace through the
 *   NVME_IOC_BD_ATTACH ioctl. A namespace can transition back to the ACTIVE
 *   state by issuing a FORMAT NVM command with unsupported settings. It can
 *   also go to the ALLOCATED state by performing the NVME_IOC_CTRL_DETACH
 *   ioctl.
 *
 * - ATTACHED: the driver has attached a blkdev(4D) instance to this namespace
 *   and it is usable as a block device. Certain operations such as a FORMAT NVM
 *   or similar are rejected during this state. The device can go back to ACTIVE
 *   with the NVME_IOC_BD_DETACH ioctl.
 */
typedef enum {
	NVME_NS_STATE_UNALLOCATED = 0,
	NVME_NS_STATE_ALLOCATED,
	NVME_NS_STATE_ACTIVE,
	NVME_NS_STATE_NOT_IGNORED,
	NVME_NS_STATE_ATTACHED
} nvme_ns_state_t;

#define	NVME_NS_NSTATES	5

/*
 * This is the maximum length of the NVMe namespace's blkdev address. This is
 * only valid in the structure with the NVME_NS_STATE_ATTACHED flag is set.
 * Otherwise the entry will be all zeros. This is useful when you need to
 * determine what the corresponding blkdev instance in libdevinfo for the
 * device.
 */
#define	NVME_BLKDEV_NAMELEN	128

/*
 * Namespace Information (NVME_IOC_NS_INFO).
 */
typedef struct {
	nvme_ioctl_common_t nni_common;
	nvme_ns_state_t	nni_state;
	char nni_addr[NVME_BLKDEV_NAMELEN];
	nvme_identify_nsid_t nni_id;
} nvme_ioctl_ns_info_t;

/*
 * NVMe Command Set Identifiers. This was added in NVMe 2.0, but in all the
 * places it was required to be specified, the default value of 0 indicates the
 * traditional NVM command set.
 */
typedef enum {
	NVME_CSI_NVM	= 0,
	NVME_CSI_KV,
	NVME_CSI_ZNS
} nvme_csi_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_NVME_H */
