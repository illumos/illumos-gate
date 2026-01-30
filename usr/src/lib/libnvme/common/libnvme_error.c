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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * libnvme error manipulation and translation. This maintains the error objects
 * that we have on handles and provides translations between the kernel's errors
 * and those that we might generate ourselves. Information errors are instead
 * contained in the corresponding files that own controller and namespace
 * information libnvme_ctrl_info.c and libnvme_ns_info.c respectively.
 */

#include <string.h>
#include <stdarg.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <upanic.h>

#include "libnvme_impl.h"

/*
 * The following sets of functions provide translations of error types. Note,
 * the kernel headers need to be updated for newer NVMe specs at which point
 * these should be updated.
 */
const char *
nvme_scttostr(nvme_ctrl_t *ctrl __unused, uint32_t sc)
{
	switch (sc) {
	case NVME_CQE_SCT_GENERIC:
		return ("generic command status");
	case NVME_CQE_SCT_SPECIFIC:
		return ("command specific status");
	case NVME_CQE_SCT_INTEGRITY:
		return ("media and data integrity errors");
	case NVME_CQE_SCT_VENDOR:
		return ("vendor specific");
	default:
		return ("unknown status type");
	}
}

static const char *
nvme_sctostr_gen_gen(uint32_t sct)
{
	switch (sct) {
	case NVME_CQE_SC_GEN_SUCCESS:
		return ("successful completion");
	case NVME_CQE_SC_GEN_INV_OPC:
		return ("invalid command opcode");
	case NVME_CQE_SC_GEN_INV_FLD:
		return ("invalid field in command");
	case NVME_CQE_SC_GEN_ID_CNFL:
		return ("command id conflict");
	case NVME_CQE_SC_GEN_DATA_XFR_ERR:
		return ("data transfer error");
	case NVME_CQE_SC_GEN_ABORT_PWRLOSS:
		return ("commands aborted due to power loss notification");
	case NVME_CQE_SC_GEN_INTERNAL_ERR:
		return ("internal error");
	case NVME_CQE_SC_GEN_ABORT_REQUEST:
		return ("command abort requested");
	case NVME_CQE_SC_GEN_ABORT_SQ_DEL:
		return ("command aborted due to sq deletion");
	case NVME_CQE_SC_GEN_ABORT_FUSE_FAIL:
		return ("command aborted due to failed fused command");
	case NVME_CQE_SC_GEN_ABORT_FUSE_MISS:
		return ("command aborted due to missing fused command");
	case NVME_CQE_SC_GEN_INV_NS:
		return ("invalid namespace or format");
	case NVME_CQE_SC_GEN_CMD_SEQ_ERR:
		return ("command sequence error");
	case NVME_CQE_SC_GEN_INV_SGL_LAST:
		return ("invalid sgl last segment descriptor");
	case NVME_CQE_SC_GEN_INV_SGL_NUM:
		return ("invalid number of sgl descriptors");
	case NVME_CQE_SC_GEN_INV_DSGL_LEN:
		return ("data sgl length invalid");
	case NVME_CQE_SC_GEN_INV_MSGL_LEN:
		return ("metadata sgl length invalid");
	case NVME_CQE_SC_GEN_INV_SGL_DESC:
		return ("sgl descriptor type invalid");
	case NVME_CQE_SC_GEN_INV_USE_CMB:
		return ("invalid use of controller memory buffer");
	case NVME_CQE_SC_GEN_INV_PRP_OFF:
		return ("prp offset invalid");
	case NVME_CQE_SC_GEN_AWU_EXCEEDED:
		return ("atomic write unit exceeded");
	case NVME_CQE_SC_GEN_OP_DENIED:
		return ("operation denied");
	case NVME_CQE_SC_GEN_INV_SGL_OFF:
		return ("sgl offset invalid");
	case NVME_CQE_SC_GEN_INV_SGL_ST:
		return ("sgl sub type invalid");
	case NVME_CQE_SC_GEN_INCON_HOSTID:
		return ("host identifier inconsistent format");
	case NVME_CQE_SC_GEN_KA_EXP:
		return ("keep alive timer expired");
	case NVME_CQE_SC_GEN_INV_KA_TO:
		return ("keep alive timeout invalid");
	case NVME_CQE_SC_GEN_ABORT_PREEMPT:
		return ("command aborted due to preempt and abort");
	case NVME_CQE_SC_GEN_SANITIZE_FAIL:
		return ("sanitize failed");
	case NVME_CQE_SC_GEN_SANITIZING:
		return ("sanitize in progress");
	case NVME_CQE_SC_GEN_INV_SGL_GRAN:
		return ("sgl data block granularity invalid");
	case NVME_CQE_SC_GEN_NO_CMD_Q_CMD:
		return ("command not supported for queue in cmb");
	case NVME_CQE_SC_GEN_NS_RDONLY:
		return ("namespace is write protected");
	case NVME_CQE_SC_GEN_CMD_INTR:
		return ("command interrupted");
	case NVME_CQE_SC_GEN_TRANSIENT:
		return ("transient transport error");
	case NVME_CQE_SC_GEN_CMD_LOCK:
		return ("command prohibited by command and feature lockdown");
	case NVME_CQE_SC_ADM_MEDIA_NR:
		return ("admin command media not ready");
	default:
		return ("unknown status code");
	}
}

static const char *
nvme_sctostr_gen_csi(nvme_csi_t csi, uint32_t sct)
{
	/*
	 * These errors are allowed for all command sets.
	 */
	switch (sct) {
	case NVME_CQE_SC_GEN_NVM_CAP_EXC:
		return ("capacity exceeded");
	case NVME_CQE_SC_GEN_NVM_NS_NOTRDY:
		return ("namespace not ready");
	case NVME_CQE_SC_GEN_NVM_RSV_CNFLCT:
		return ("reservation conflict");
	default:
		break;
	}

	switch (csi) {
	case NVME_CSI_NVM:
	case NVME_CSI_ZNS:
		switch (sct) {
		case NVME_CQE_SC_GEN_NVM_LBA_RANGE:
			return ("lba out of range");
		case NVME_CQE_SC_GEN_NVM_FORMATTING:
			return ("format in progress");
		default:
			break;
		}
		break;
	case NVME_CSI_KV:
		switch (sct) {
		case NVME_CQE_SC_GEN_KEY_INV_VAL:
			return ("invalid value size");
		case NVME_CQE_SC_GEN_KEY_INV_KEY:
			return ("invalid key size");
		case NVME_CQE_SC_GEN_KEY_ENOENT:
			return ("kv key does not exist");
		case NVME_CQE_SC_GEN_KEY_UNRECOV:
			return ("unrecovered error");
		case NVME_CQE_SC_GEN_KEY_EXISTS:
			return ("key exists");
		default:
			break;
		}
		break;
	default:
		break;
	}

	return ("unknown command set specific general status code");
}

static const char *
nvme_sctostr_cmd_gen(uint32_t sct)
{
	switch (sct) {
	case NVME_CQE_SC_SPC_INV_CQ	:
		return ("completion queue invalid");
	case NVME_CQE_SC_SPC_INV_QID	:
		return ("invalid queue identifier");
	case NVME_CQE_SC_SPC_MAX_QSZ_EXC:
		return ("max queue size exceeded");
	case NVME_CQE_SC_SPC_ABRT_CMD_EXC:
		return ("abort command limit exceeded");
	case NVME_CQE_SC_SPC_ASYNC_EVREQ_EXC:
		return ("asynchronous event request limit");
	case NVME_CQE_SC_SPC_INV_FW_SLOT:
		return ("invalid firmware slot");
	case NVME_CQE_SC_SPC_INV_FW_IMG:
		return ("invalid firmware image");
	case NVME_CQE_SC_SPC_INV_INT_VECT:
		return ("invalid interrupt vector");
	case NVME_CQE_SC_SPC_INV_LOG_PAGE:
		return ("invalid log page");
	case NVME_CQE_SC_SPC_INV_FORMAT:
		return ("invalid format");
	case NVME_CQE_SC_SPC_FW_RESET:
		return ("firmware activation requires conventional reset");
	case NVME_CQE_SC_SPC_INV_Q_DEL:
		return ("invalid queue deletion");
	case NVME_CQE_SC_SPC_FEAT_SAVE:
		return ("feature identifier not saveable");
	case NVME_CQE_SC_SPC_FEAT_CHG:
		return ("feature not changeable");
	case NVME_CQE_SC_SPC_FEAT_NS_SPEC:
		return ("feature not namespace spec");
	case NVME_CQE_SC_SPC_FW_NSSR	:
		return ("firmware activation requires nvm subsystem reset");
	case NVME_CQE_SC_SPC_FW_NEXT_RESET:
		return ("firmware activation requires controller level reset");
	case NVME_CQE_SC_SPC_FW_MTFA	:
		return ("firmware activation requires maximum time violation");
	case NVME_CQE_SC_SPC_FW_PROHIBITED:
		return ("firmware activation prohibited");
	case NVME_CQE_SC_SPC_FW_OVERLAP:
		return ("overlapping range");
	case NVME_CQE_SC_SPC_NS_INSUF_CAP:
		return ("namespace insufficient capacity");
	case NVME_CQE_SC_SPC_NS_NO_ID:
		return ("namespace identifier unavailable");
	case NVME_CQE_SC_SPC_NS_ATTACHED:
		return ("namespace already attached");
	case NVME_CQE_SC_SPC_NS_PRIV:
		return ("namespace is private");
	case NVME_CQE_SC_SPC_NS_NOT_ATTACH:
		return ("namespace is not attached");
	case NVME_CQE_SC_SPC_THIN_ENOTSUP:
		return ("thin provisioning not supported");
	case NVME_CQE_SC_SPC_INV_CTRL_LIST:
		return ("controller list invalid");
	case NVME_CQE_SC_SPC_SELF_TESTING:
		return ("device self-test in progress");
	case NVME_CQE_SC_SPC_NO_BP_WRITE:
		return ("boot partition write protected");
	case NVME_CQE_SC_SPC_INV_CTRL_ID:
		return ("invalid controller identifier");
	case NVME_CQE_SC_SPC_INV_SEC_CTRL:
		return ("invalid secondary controller state");
	case NVME_CQE_SC_SPC_INV_CTRL_NRSRC:
		return ("invalid number of controller resources");
	case NVME_CQE_SC_SPC_INV_RSRC_ID:
		return ("Invalid resource identifier");
	case NVME_CQE_SC_SPC_NO_SAN_PMR:
		return ("sanitize prohibited while persistent memory region "
		    "is enabled");
	case NVME_CQE_SC_SPC_INV_ANA_GID:
		return ("ana group identifier invalid");
	case NVME_CQE_SC_SPC_ANA_ATTACH:
		return ("ana attach failed");
	case NVME_CQE_SC_SPC_INSUF_CAP:
		return ("insufficient capacity");
	case NVME_CQE_SC_SPC_NS_ATTACH_LIM:
		return ("namespace attachment limit exceeded");
	case NVME_CQE_SC_SPC_LOCKDOWN_UNSUP:
		return ("prohibition of command execution not supported");
	case NVME_CQE_SC_SPC_UNSUP_IO_CMD:
		return ("I/O command set not supported");
	case NVME_CQE_SC_SPC_DIS_IO_CMD:
		return ("I/O command set not enabled");
	case NVME_CQE_SC_SPC_INV_CMD_COMBO:
		return ("I/O command set combination rejected");
	case NVME_CQE_SC_SPC_INV_IO_CMD:
		return ("Invalid I/O command set");
	case NVME_CQE_SC_SPC_UNAVAIL_ID:
		return ("identifier unavailable");
	default:
		return ("unknown generic command status code");
	}
}

/*
 * The NVMe 2.0c spec that introduces many of the zoned related errors has
 * footnotes to suggest some of these are command set specific, but does not
 * mark any of them. For the moment we basically assume that they're valid
 * everywhere due to the fact that they don't overlap.
 */
static const char *
nvme_sctostr_cmd_csi(nvme_csi_t csi, uint32_t sct)
{
	switch (sct) {
	case NVME_CQE_SC_SPC_NVM_CNFL_ATTR:
		return ("conflicting attributes");
	case NVME_CQE_SC_SPC_NVM_INV_PROT:
		return ("invalid protection");
	case NVME_CQE_SC_SPC_NVM_READONLY:
		return ("write to read only range");
	case NVME_CQE_SC_SPC_ZONE_BDRY_ERR:
		return ("zoned boundary error");
	case NVME_CQE_SC_SPC_ZONE_FULL:
		return ("zone is full");
	case NVME_CQE_SC_SPC_ZONE_RDONLY:
		return ("zone is read only");
	case NVME_CQE_SC_SPC_ZONE_OFFLINE:
		return ("zone is offline");
	case NVME_CQE_SC_SPC_ZONE_INV_WRITE:
		return ("zone invalid write");
	case NVME_CQE_SC_SPC_ZONE_ACT:
		return ("too many active zones");
	case NVME_CQE_SC_SPC_ZONE_OPEN:
		return ("too many open zones");
	case NVME_CQE_SC_SPC_INV_ZONE_TRANS:
		return ("invalid zone state transition");
	default:
		return ("unknown command specific, I/O command set specific "
		    "status code");
	}
}

static const char *
nvme_sctostr_media(nvme_csi_t csi, uint32_t sct)
{
	if (sct >= NVME_CQE_SC_VEND_MIN) {
		return ("vendor specific media and data integrity status code");
	}

	/*
	 * Unlike NVMe 1.x, NVMe 2.x declares the following command set
	 * independent.
	 */
	switch (sct) {
	case NVME_CQE_SC_INT_NVM_WRITE:
		return ("write fault");
	case NVME_CQE_SC_INT_NVM_READ:
		return ("unrecovered read error");
	case NVME_CQE_SC_INT_NVM_GUARD:
		return ("guard check error");
	case NVME_CQE_SC_INT_NVM_APPL_TAG:
		return ("application tag check err");
	case NVME_CQE_SC_INT_NVM_REF_TAG:
		return ("reference tag check err");
	case NVME_CQE_SC_INT_NVM_ACCESS:
		return ("access denied");
	case NVME_CQE_SC_INT_NVM_TAG:
		return ("end-to-end storage tag check error");
	default:
		break;
	}

	/*
	 * The only command-set specific values are currently defined for the
	 * NVM command set.
	 */
	if (csi != NVME_CSI_NVM) {
		return ("unknown media and data integrity status code");
	}

	switch (sct) {
	case NVME_CQE_SC_INT_NVM_COMPARE:
		return ("compare failure");
	case NVME_CQE_SC_INT_NVM_DEALLOC:
		return ("deallocated or unwritten logical block");
	default:
		return ("unknown media and data integrity status code");
	}
}

static const char *
nvme_sctostr_path(uint32_t sct)
{
	switch (sct) {
	case NVME_CQE_SC_PATH_INT_ERR:
		return ("internal path error");
	case NVME_CQE_SC_PATH_AA_PLOSS:
		return ("asymmetric access persistent loss");
	case NVME_CQE_SC_PATH_AA_INACC:
		return ("asymmetric access inaccessible");
	case NVME_CQE_SC_PATH_AA_TRANS:
		return ("asymmetric access transition");
	case NVME_CQE_SC_PATH_CTRL_ERR:
		return ("controller pathing error");
	case NVME_CQE_SC_PATH_HOST_ERR:
		return ("host pathing error");
	case NVME_CQE_SC_PATH_HOST_ABRT:
		return ("command aborted by host");
	default:
		return ("unknown path related status code");
	}
}

const char *
nvme_sctostr(nvme_ctrl_t *ctrl __unused, nvme_csi_t csi, uint32_t sct,
    uint32_t sc)
{
	switch (sct) {
	case NVME_CQE_SCT_GENERIC:
		if (sc <= NVME_CQE_SC_GEN_MAX) {
			return (nvme_sctostr_gen_gen(sc));
		} else if (sc <= NVME_CQE_SC_CSI_MAX) {
			return (nvme_sctostr_gen_csi(csi, sc));
		} else {
			return ("generic vendor specific status code");
		}
	case NVME_CQE_SCT_SPECIFIC:
		if (sc <= NVME_CQE_SC_GEN_MAX) {
			return (nvme_sctostr_cmd_gen(sc));
		} else if (sc <= NVME_CQE_SC_CSI_MAX) {
			return (nvme_sctostr_cmd_csi(csi, sc));
		} else {
			return ("command specific vendor specific status code");
		}
	case NVME_CQE_SCT_INTEGRITY:
		return (nvme_sctostr_media(csi, sc));
	case NVME_CQE_SCT_PATH:
		return (nvme_sctostr_path(sc));
	case NVME_CQE_SCT_VENDOR:
		return ("vendor specific");
	default:
		return ("unknown status code");
	}
}

nvme_err_t
nvme_err(nvme_t *nvme)
{
	return (nvme->nh_err.ne_err);
}

int32_t
nvme_syserr(nvme_t *nvme)
{
	return (nvme->nh_err.ne_syserr);
}

const char *
nvme_errmsg(nvme_t *nvme)
{
	return (nvme->nh_err.ne_errmsg);
}

size_t
nvme_errlen(nvme_t *nvme)
{
	return (nvme->nh_err.ne_errlen);
}

const char *
nvme_errtostr(nvme_t *nvme, nvme_err_t err)
{
	switch (err) {
	case NVME_ERR_OK:
		return ("NVME_ERR_OK");
	case NVME_ERR_CONTROLLER:
		return ("NVME_ERR_CONTROLLER");
	case NVME_ERR_NO_MEM:
		return ("NVME_ERR_NO_MEM");
	case NVME_ERR_NO_DMA_MEM:
		return ("NVME_ERR_NO_DMA_MEM");
	case NVME_ERR_LIBDEVINFO:
		return ("NVME_ERR_LIBDEVINFO");
	case NVME_ERR_INTERNAL:
		return ("NVME_ERR_INTERNAL");
	case NVME_ERR_BAD_PTR:
		return ("NVME_ERR_BAD_PTR");
	case NVME_ERR_BAD_FLAG:
		return ("NVME_ERR_BAD_FLAG");
	case NVME_ERR_BAD_DEVI:
		return ("NVME_ERR_BAD_DEVI");
	case NVME_ERR_BAD_DEVI_PROP:
		return ("NVME_ERR_BAD_DEVI_PROP");
	case NVME_ERR_ILLEGAL_INSTANCE:
		return ("NVME_ERR_ILLEGAL_INSTANCE");
	case NVME_ERR_BAD_CONTROLLER:
		return ("NVME_ERR_BAD_CONTROLLER");
	case NVME_ERR_PRIVS:
		return ("NVME_ERR_PRIVS");
	case NVME_ERR_OPEN_DEV:
		return ("NVME_ERR_OPEN_DEV");
	case NVME_ERR_BAD_RESTORE:
		return ("NVME_ERR_BAD_RESTORE");
	case NVME_ERR_NS_RANGE:
		return ("NVME_ERR_NS_RANGE");
	case NVME_ERR_NS_UNUSE:
		return ("NVME_ERR_NS_UNUSE");
	case NVME_ERR_LOG_CSI_RANGE:
		return ("NVME_ERR_LOG_CSI_RANGE");
	case NVME_ERR_LOG_LID_RANGE:
		return ("NVME_ERR_LOG_LID_RANGE");
	case NVME_ERR_LOG_LSP_RANGE:
		return ("NVME_ERR_LOG_LSP_RANGE");
	case NVME_ERR_LOG_LSI_RANGE:
		return ("NVME_ERR_LOG_LSI_RANGE");
	case NVME_ERR_LOG_RAE_RANGE:
		return ("NVME_ERR_LOG_RAE_RANGE");
	case NVME_ERR_LOG_SIZE_RANGE:
		return ("NVME_ERR_LOG_SIZE_RANGE");
	case NVME_ERR_LOG_OFFSET_RANGE:
		return ("NVME_ERR_LOG_OFFSET_RANGE");
	case NVME_ERR_LOG_CSI_UNSUP:
		return ("NVME_ERR_LOG_CSI_UNSUP");
	case NVME_ERR_LOG_LSP_UNSUP:
		return ("NVME_ERR_LOG_LSP_UNSUP");
	case NVME_ERR_LOG_LSI_UNSUP:
		return ("NVME_ERR_LOG_LSI_UNSUP");
	case NVME_ERR_LOG_RAE_UNSUP:
		return ("NVME_ERR_LOG_RAE_UNSUP");
	case NVME_ERR_LOG_OFFSET_UNSUP:
		return ("NVME_ERR_LOG_OFFSET_UNSUP");
	case NVME_ERR_LOG_LSP_UNUSE:
		return ("NVME_ERR_LOG_LSP_UNUSE");
	case NVME_ERR_LOG_LSI_UNUSE:
		return ("NVME_ERR_LOG_LSI_UNUSE");
	case NVME_ERR_LOG_RAE_UNUSE:
		return ("NVME_ERR_LOG_RAE_UNUSE");
	case NVME_ERR_LOG_SCOPE_MISMATCH:
		return ("NVME_ERR_LOG_SCOPE_MISMATCH");
	case NVME_ERR_LOG_REQ_MISSING_FIELDS:
		return ("NVME_ERR_LOG_REQ_MISSING_FIELDS");
	case NVME_ERR_LOG_NAME_UNKNOWN:
		return ("NVME_ERR_LOG_NAME_UNKNOWN");
	case NVME_ERR_LOG_UNSUP_BY_DEV:
		return ("NVME_ERR_LOG_UNSUP_BY_DEV");
	case NVME_ERR_IDENTIFY_UNKNOWN:
		return ("NVME_ERR_IDENTIFY_UNKNOWN");
	case NVME_ERR_IDENTIFY_UNSUP_BY_DEV:
		return ("NVME_ERR_IDENTIFY_UNSUP_BY_DEV");
	case NVME_ERR_IDENTIFY_CTRLID_RANGE:
		return ("NVME_ERR_IDENTIFY_CTRLID_RANGE");
	case NVME_ERR_IDENTIFY_OUTPUT_RANGE:
		return ("NVME_ERR_IDENTIFY_OUTPUT_RANGE");
	case NVME_ERR_IDENTIFY_CTRLID_UNSUP:
		return ("NVME_ERR_IDENTIFY_CTRLID_UNSUP");
	case NVME_ERR_IDENTIFY_CTRLID_UNUSE:
		return ("NVME_ERR_IDENTIFY_CTRLID_UNUSE");
	case NVME_ERR_IDENTIFY_REQ_MISSING_FIELDS:
		return ("NVME_ERR_IDENTIFY_REQ_MISSING_FIELDS");
	case NVME_ERR_VUC_UNSUP_BY_DEV:
		return ("NVME_ERR_VUC_UNSUP_BY_DEV");
	case NVME_ERR_VUC_TIMEOUT_RANGE:
		return ("NVME_ERR_VUC_TIMEOUT_RANGE");
	case NVME_ERR_VUC_OPCODE_RANGE:
		return ("NVME_ERR_VUC_OPCODE_RANGE");
	case NVME_ERR_VUC_IMPACT_RANGE:
		return ("NVME_ERR_VUC_IMPACT_RANGE");
	case NVME_ERR_VUC_NDT_RANGE:
		return ("NVME_ERR_VUC_NDT_RANGE");
	case NVME_ERR_VUC_CANNOT_RW:
		return ("NVME_ERR_VUC_CANNOT_RW");
	case NVME_ERR_VUC_NO_RESULTS:
		return ("NVME_ERR_VUC_NO_RESULTS");
	case NVME_ERR_VUC_UNKNOWN:
		return ("NVME_ERR_VUC_UNKNOWN");
	case NVME_ERR_VUC_REQ_MISSING_FIELDS:
		return ("NVME_ERR_VUC_REQ_MISSING_FIELDS");
	case NVME_ERR_VU_FUNC_UNSUP_BY_DEV:
		return ("NVME_ERR_VU_FUNC_UNSUP_BY_DEV");
	case NVME_ERR_WDC_E6_OFFSET_RANGE:
		return ("NVME_ERR_WDC_E6_OFFSET_RANGE");
	case NVME_ERR_FW_UNSUP_BY_DEV:
		return ("NVME_ERR_FW_UNSUP_BY_DEV");
	case NVME_ERR_KERN_FW_IMPOS:
		return ("NVME_ERR_KERN_FW_IMPOS");
	case NVME_ERR_FW_LOAD_LEN_RANGE:
		return ("NVME_ERR_FW_LOAD_LEN_RANGE");
	case NVME_ERR_FW_LOAD_OFFSET_RANGE:
		return ("NVME_ERR_FW_LOAD_OFFSET_RANGE");
	case NVME_ERR_FW_COMMIT_SLOT_RANGE:
		return ("NVME_ERR_FW_COMMIT_SLOT_RANGE");
	case NVME_ERR_FW_COMMIT_ACTION_RANGE:
		return ("NVME_ERR_FW_COMMIT_ACTION_RANGE");
	case NVME_ERR_FW_COMMIT_REQ_MISSING_FIELDS:
		return ("NVME_ERR_FW_COMMIT_REQ_MISSING_FIELDS");
	case NVME_ERR_FW_SLOT_RO:
		return ("NVME_ERR_FW_SLOT_RO");
	case NVME_ERR_FORMAT_UNSUP_BY_DEV:
		return ("NVME_ERR_FORMAT_UNSUP_BY_DEV");
	case NVME_ERR_CRYPTO_SE_UNSUP_BY_DEV:
		return ("NVME_ERR_CRYPTO_SE_UNSUP_BY_DEV");
	case NVME_ERR_NS_FORMAT_UNSUP_BY_DEV:
		return ("NVME_ERR_NS_FORMAT_UNSUP_BY_DEV");
	case NVME_ERR_KERN_FORMAT_UNSUP:
		return ("NVME_ERR_KERN_FORMAT_UNSUP");
	case NVME_ERR_FORMAT_LBAF_RANGE:
		return ("NVME_ERR_FORMAT_LBAF_RANGE");
	case NVME_ERR_FORMAT_SES_RANGE:
		return ("NVME_ERR_FORMAT_SES_RANGE");
	case NVME_ERR_FORMAT_PARAM_UNSUP:
		return ("NVME_ERR_FORMAT_PARAM_UNSUP");
	case NVME_ERR_FORMAT_REQ_MISSING_FIELDS:
		return ("NVME_ERR_FORMAT_REQ_MISSING_FIELDS");
	case NVME_ERR_WDC_E6_REQ_MISSING_FIELDS:
		return ("NVME_ERR_WDC_E6_REQ_MISSING_FIELDS");
	case NVME_ERR_FEAT_NAME_UNKNOWN:
		return ("NVME_ERR_FEAT_NAME_UNKNOWN");
	case NVME_ERR_FEAT_UNSUP_BY_DEV:
		return ("NVME_ERR_FEAT_UNSUP_BY_DEV");
	case NVME_ERR_FEAT_FID_RANGE:
		return ("NVME_ERR_FEAT_FID_RANGE");
	case NVME_ERR_FEAT_SEL_RANGE:
		return ("NVME_ERR_FEAT_SEL_RANGE");
	case NVME_ERR_FEAT_CDW11_RANGE:
		return ("NVME_ERR_FEAT_CDW11_RANGE");
	case NVME_ERR_FEAT_DATA_RANGE:
		return ("NVME_ERR_FEAT_DATA_RANGE");
	case NVME_ERR_FEAT_SEL_UNSUP:
		return ("NVME_ERR_FEAT_SEL_UNSUP");
	case NVME_ERR_FEAT_CDW11_UNUSE:
		return ("NVME_ERR_FEAT_CDW11_UNUSE");
	case NVME_ERR_FEAT_DATA_UNUSE:
		return ("NVME_ERR_FEAT_DATA_UNUSE");
	case NVME_ERR_FEAT_NO_RESULTS:
		return ("NVME_ERR_FEAT_NO_RESULTS");
	case NVME_ERR_GET_FEAT_REQ_MISSING_FIELDS:
		return ("NVME_ERR_GET_FEAT_REQ_MISSING_FIELDS");
	case NVME_ERR_NEED_CTRL_WRLOCK:
		return ("NVME_ERR_NEED_CTRL_WRLOCK");
	case NVME_ERR_NEED_NS_WRLOCK:
		return ("NVME_ERR_NEED_NS_WRLOCK");
	case NVME_ERR_CTRL_LOCKED:
		return ("NVME_ERR_CTRL_LOCKED");
	case NVME_ERR_NS_LOCKED:
		return ("NVME_ERR_NS_LOCKED");
	case NVME_ERR_LOCK_PROG:
		return ("NVME_ERR_LOCK_PROG");
	case NVME_ERR_LOCK_ORDER:
		return ("NVME_ERR_LOCK_ORDER");
	case NVME_ERR_LOCK_WAIT_INTR:
		return ("NVME_ERR_LOCK_WAIT_INTR");
	case NVME_ERR_LOCK_WOULD_BLOCK:
		return ("NVME_ERR_LOCK_WOULD_BLOCK");
	case NVME_ERR_DETACH_KERN:
		return ("NVME_ERR_DETACH_KERN");
	case NVME_ERR_ATTACH_KERN:
		return ("NVME_ERR_ATTACH_KERN");
	case NVME_ERR_ATTACH_UNSUP_KERN:
		return ("NVME_ERR_ATTACH_UNSUP_KERN");
	case NVME_ERR_NS_BLKDEV_ATTACH:
		return ("NVME_ERR_NS_BLKDEV_ATTACH");
	case NVME_ERR_NO_KERN_MEM:
		return ("NVME_ERR_NO_KERN_MEM");
	case NVME_ERR_CTRL_DEAD:
		return ("NVME_ERR_CTRL_DEAD");
	case NVME_ERR_CTRL_GONE:
		return ("NVME_ERR_CTRL_GONE");
	case NVME_ERR_NS_MGMT_UNSUP_BY_DEV:
		return ("NVME_ERR_NS_MGMT_UNSUP_BY_DEV");
	case NVME_ERR_THIN_PROV_UNSUP_BY_DEV:
		return ("NVME_ERR_THIN_PROV_UNSUP_BY_DEV");
	case NVME_ERR_NS_ATTACH_REQ_MISSING_FIELDS:
		return ("NVME_ERR_NS_ATTACH_REQ_MISSING_FIELDS");
	case NVME_ERR_NS_CREATE_REQ_MISSING_FIELDS:
		return ("NVME_ERR_NS_CREATE_REQ_MISSING_FIELDS");
	case NVME_ERR_NS_DELETE_REQ_MISSING_FIELDS:
		return ("NVME_ERR_NS_DELETE_REQ_MISSING_FIELDS");
	case NVME_ERR_NS_CREATE_BAD_CSI:
		return ("NVME_ERR_NS_CREATE_BAD_CSI");
	case NVME_ERR_NS_ATTACH_BAD_SEL:
		return ("NVME_ERR_NS_ATTACH_BAD_SEL");
	case NVME_ERR_NS_CREATE_NO_RESULTS:
		return ("NVME_ERR_NS_CREATE_NO_RESULTS");
	case NVME_ERR_NS_CREATE_NCAP_RANGE:
		return ("NVME_ERR_NS_CREATE_NCAP_RANGE");
	case NVME_ERR_NS_CREATE_NSZE_RANGE:
		return ("NVME_ERR_NS_CREATE_NSZE_RANGE");
	case NVME_ERR_NS_CREATE_NMIC_RANGE:
		return ("NVME_ERR_NS_CREATE_NMIC_RANGE");
	case NVME_ERR_NS_CREATE_FLBAS_RANGE:
		return ("NVME_ERR_NS_CREATE_FLBAS_RANGE");
	case NVME_ERR_NS_CTRL_ATTACHED:
		return ("NVME_ERR_NS_CTRL_ATTACHED");
	case NVME_ERR_NS_CTRL_NOT_ATTACHED:
		return ("NVME_ERR_NS_CTRL_NOT_ATTACHED");
	case NVME_ERR_NS_UNALLOC:
		return ("NVME_ERR_NS_UNALLOC");
	case NVME_ERR_PCIE_LANE_RANGE:
		return ("NVME_ERR_PCIE_LANE_RANGE");
	case NVME_ERR_PCIE_EYE_BUF_RANGE:
		return ("NVME_ERR_PCIE_EYE_BUF_RANGE");
	default:
		return ("unknown error");
	}
}

nvme_err_t
nvme_ctrl_err(nvme_ctrl_t *ctrl)
{
	return (ctrl->nc_err.ne_err);
}

int32_t
nvme_ctrl_syserr(nvme_ctrl_t *ctrl)
{
	return (ctrl->nc_err.ne_syserr);
}

const char *
nvme_ctrl_errmsg(nvme_ctrl_t *ctrl)
{
	return (ctrl->nc_err.ne_errmsg);
}

size_t
nvme_ctrl_errlen(nvme_ctrl_t *ctrl)
{
	return (ctrl->nc_err.ne_errlen);
}

void
nvme_ctrl_deverr(nvme_ctrl_t *ctrl, uint32_t *sct, uint32_t *sc)
{
	if (sct != NULL) {
		*sct = ctrl->nc_err.ne_ctrl_sct;
	}

	if (sc != NULL) {
		*sc = ctrl->nc_err.ne_ctrl_sc;
	}
}

const char *
nvme_ctrl_errtostr(nvme_ctrl_t *ctrl, nvme_err_t err)
{
	return (nvme_errtostr(ctrl->nc_nvme, err));
}

static void
nvme_error_common(nvme_err_data_t *ep, nvme_err_t err, int32_t sys,
    const char *fmt, va_list ap)
{
	int ret;

	ep->ne_err = err;
	ep->ne_syserr = sys;
	ep->ne_ctrl_sct = 0;
	ep->ne_ctrl_sc = 0;
	ret = vsnprintf(ep->ne_errmsg,
	    sizeof (ep->ne_errmsg), fmt, ap);
	if (ret >= sizeof (ep->ne_errmsg)) {
		ep->ne_errlen = sizeof (ep->ne_errmsg) - 1;
	} else if (ret <= 0) {
		ep->ne_errlen = 0;
		ep->ne_errmsg[0] = '\0';
	} else {
		ep->ne_errlen = (size_t)ret;
	}
}

bool
nvme_error(nvme_t *nvme, nvme_err_t err, int32_t sys, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	nvme_error_common(&nvme->nh_err, err, sys, fmt, ap);
	va_end(ap);

	return (false);
}

bool
nvme_ctrl_error(nvme_ctrl_t *ctrl, nvme_err_t err, int32_t sys,
    const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	nvme_error_common(&ctrl->nc_err, err, sys, fmt, ap);
	va_end(ap);

	return (false);
}

static bool
nvme_success_common(nvme_err_data_t *err)
{
	err->ne_err = NVME_ERR_OK;
	err->ne_syserr = 0;
	err->ne_ctrl_sct = 0;
	err->ne_ctrl_sc = 0;
	err->ne_errmsg[0] = '\0';
	err->ne_errlen = 0;

	return (true);
}

bool
nvme_success(nvme_t *nvme)
{
	return (nvme_success_common(&nvme->nh_err));
}

bool
nvme_ctrl_success(nvme_ctrl_t *ctrl)
{
	return (nvme_success_common(&ctrl->nc_err));
}

void
nvme_err_save(const nvme_t *nvme, nvme_err_data_t *out)
{
	*out = nvme->nh_err;
}

void
nvme_err_set(nvme_t *nvme, const nvme_err_data_t *err)
{
	nvme->nh_err = *err;
}

void
nvme_ctrl_err_save(const nvme_ctrl_t *ctrl, nvme_err_data_t *out)
{
	*out = ctrl->nc_err;
}

void
nvme_ctrl_err_set(nvme_ctrl_t *ctrl, const nvme_err_data_t *err)
{
	ctrl->nc_err = *err;
}

/*
 * This table deals with mapping a kernel error to a library error and provides
 * a short description of what it is. Note, we do not expect all kernel errors
 * to occur and we may want to revisit which of these end up indicating a
 * programmer error that we caused somehow.
 */
typedef struct {
	nvme_ioctl_errno_t kl_kern;
	nvme_err_t kl_lib;
	const char *kl_desc;
} nvme_ktolmap_t;

/*
 * Please keep this table ordered based on the nvme_ioctl_error_t enumeration
 * order. This is not required for correctness, but helps when scanning for
 * missing entries. Please document why certain entries are skipped.
 */
static const nvme_ktolmap_t nvme_ktolmap[] = {
	/*
	 * NVME_IOCTL_E_OK and NVME_IOCTL_E_CTRL_ERROR should already have been
	 * dealt with and shouldn't be included here.
	 */
	{ NVME_IOCTL_E_CTRL_DEAD, NVME_ERR_CTRL_DEAD, "the controller is no "
	    "longer usable by the system" },
	{ NVME_IOCTL_E_CTRL_GONE, NVME_ERR_CTRL_GONE, "the controller has been "
	    "physically removed from the system" },
	{ NVME_IOCTL_E_NS_RANGE, NVME_ERR_NS_RANGE, "invalid namespace "
	    "requested" },
	{ NVME_IOCTL_E_NS_UNUSE, NVME_ERR_NS_UNUSE, "a namespace ID may not be "
	    "specified in this context" },
	/*
	 * We have purposefully skipped NVME_IOCTL_E_MINOR_WRONG_NS and
	 * NVME_IOCTL_E_NOT_CTRL as the library should not ever use the
	 * namespace minor.
	 */
	{ NVME_IOCTL_E_NO_BCAST_NS, NVME_ERR_NS_RANGE, "the broadcast "
	    "namespace may not be used in this context" },
	{ NVME_IOCTL_E_NEED_CTRL_WRLOCK, NVME_ERR_NEED_CTRL_WRLOCK, "operation "
	    "requires a controller write lock, but it is not owned" },
	{ NVME_IOCTL_E_NEED_NS_WRLOCK, NVME_ERR_NEED_NS_WRLOCK, "operation "
	    "requires a namespace write lock, but it is not owned" },
	{ NVME_IOCTL_E_CTRL_LOCKED, NVME_ERR_CTRL_LOCKED, "controller locked" },
	{ NVME_IOCTL_E_NS_LOCKED, NVME_ERR_NS_LOCKED, "namespace locked" },
	/*
	 * We have purposefully skipped NVME_IOCTL_E_UNKNOWN_LOG_PAGE as in
	 * theory the library and kernel should be in sync with the set of known
	 * log pages. If it is out of sync due to someone distributing the two
	 * weirdly or a bad build, we'd rather that end up as an internal error
	 * rather than a first class error for users.
	 */
	{ NVME_IOCTL_E_UNSUP_LOG_PAGE, NVME_ERR_LOG_UNSUP_BY_DEV, "controller "
	    "does not support the specified log page" },
	{ NVME_IOCTL_E_BAD_LOG_SCOPE, NVME_ERR_LOG_SCOPE_MISMATCH, "log page "
	    "does not work with the requested scope" },
	{ NVME_IOCTL_E_LOG_CSI_RANGE, NVME_ERR_LOG_CSI_RANGE, "invalid command "
	    "set interface value" },
	{ NVME_IOCTL_E_LOG_LID_RANGE, NVME_ERR_LOG_LID_RANGE, "invalid log "
	    "identifier value" },
	{ NVME_IOCTL_E_LOG_LSP_RANGE, NVME_ERR_LOG_LSP_RANGE, "invalid log "
	    "specific parameter value" },
	{ NVME_IOCTL_E_LOG_LSI_RANGE, NVME_ERR_LOG_LSI_RANGE, "invalid log "
	    "specific identifier value" },
	{ NVME_IOCTL_E_LOG_RAE_RANGE, NVME_ERR_LOG_SIZE_RANGE, "invalid retain "
	    "asynchronous event value" },
	{ NVME_IOCTL_E_LOG_SIZE_RANGE, NVME_ERR_LOG_SIZE_RANGE, "invalid log "
	    "length value" },
	{ NVME_IOCTL_E_LOG_OFFSET_RANGE, NVME_ERR_LOG_OFFSET_RANGE, "invalid "
	    "log offset value" },
	{ NVME_IOCTL_E_LOG_CSI_UNSUP, NVME_ERR_LOG_CSI_UNSUP,
	    "the controller does not support specifying the csi" },
	{ NVME_IOCTL_E_LOG_LSP_UNSUP, NVME_ERR_LOG_LSP_UNSUP,
	    "the controller does not support specifying the lsp" },
	{ NVME_IOCTL_E_LOG_LSI_UNSUP, NVME_ERR_LOG_LSI_UNSUP,
	    "or controller do not support specifying the lsi" },
	{ NVME_IOCTL_E_LOG_RAE_UNSUP, NVME_ERR_LOG_RAE_UNSUP,
	    "the controller does not support retaining an asynchronous event" },
	{ NVME_IOCTL_E_LOG_OFFSET_UNSUP, NVME_ERR_LOG_OFFSET_UNSUP,
	    "the controller do not support specifying a a read offset" },
	{ NVME_IOCTL_E_LOG_LSP_UNUSE, NVME_ERR_LOG_LSP_UNUSE, "the log page "
	    "does not allow the lsp to be used" },
	{ NVME_IOCTL_E_LOG_LSI_UNUSE, NVME_ERR_LOG_LSI_UNUSE, "the log page "
	    "does not allow the lsi to be used" },
	{ NVME_IOCTL_E_LOG_RAE_UNUSE, NVME_ERR_LOG_RAE_UNUSE,  "the log page "
	    "does not allow rae to be set" },
	{ NVME_IOCTL_E_NO_DMA_MEM, NVME_ERR_NO_DMA_MEM, "the kernel failed to "
	    "allocate sufficient DMA resources" },
	{ NVME_IOCTL_E_NO_KERN_MEM, NVME_ERR_NO_KERN_MEM, "the kernel failed "
	    "to allocate sufficient memory for this operation" },
	{ NVME_IOCTL_E_BAD_PRP, NVME_ERR_INTERNAL, "a driver error occurred "
	    "while filling out the command's DMA resources" },
	{ NVME_IOCTL_E_BAD_USER_DATA, NVME_ERR_BAD_PTR, "the kernel "
	    "detected an invalid user buffer while trying to read/write the "
	    "passed in data buffer" },
	{ NVME_IOCTL_E_UNKNOWN_IDENTIFY, NVME_ERR_IDENTIFY_UNKNOWN, "unknown "
	    "identify command requested" },
	{ NVME_IOCTL_E_UNSUP_IDENTIFY, NVME_ERR_IDENTIFY_UNSUP_BY_DEV,
	    "controller does not support the requested identify command" },
	{ NVME_IOCTL_E_IDENTIFY_CTRLID_RANGE, NVME_ERR_IDENTIFY_CTRLID_RANGE,
	    "invalid controller id value" },
	{ NVME_IOCTL_E_IDENTIFY_CTRLID_UNSUP, NVME_ERR_IDENTIFY_CTRLID_UNSUP,
	    "the controller does not support specifying the controller ID" },
	{ NVME_IOCTL_E_IDENTIFY_CTRLID_UNUSE, NVME_ERR_IDENTIFY_CTRLID_UNUSE,
	    "this specific identify request does not allow setting the "
	    "controller id" },
	{ NVME_IOCTL_E_CTRL_VUC_UNSUP, NVME_ERR_VUC_UNSUP_BY_DEV,
	    "the controller does not support standard NVMe vendor unique "
	    "commands" },
	/*
	 * The following indicate bad values for given NVMe vendor unique
	 * command fields. Note, we do not include an entry for
	 * NVME_IOCTL_E_VUC_FLAGS_RANGE because these flags are entirely owned
	 * by the library.
	 */
	{ NVME_IOCTL_E_VUC_TIMEOUT_RANGE, NVME_ERR_VUC_TIMEOUT_RANGE, "invalid "
	    "command timeout value" },
	{ NVME_IOCTL_E_VUC_OPCODE_RANGE, NVME_ERR_VUC_OPCODE_RANGE, "invalid "
	    "vendor unique opcode specified" },
	{ NVME_IOCTL_E_VUC_IMPACT_RANGE, NVME_ERR_VUC_IMPACT_RANGE, "invalid "
	    "vendor unique impact specified" },
	{ NVME_IOCTL_E_VUC_NDT_RANGE, NVME_ERR_VUC_NDT_RANGE, "invalid "
	    "data transfer size specified" },
	/*
	 * We skip NVME_IOCTL_E_INCONSIST_VUC_FLAGS_NDT and
	 * NVME_IOCTL_E_INCONSIST_VUC_BUF_NDT because these are solely under the
	 * library control and would indicate a programming error at our end.
	 * The user shouldn't be able to cause this.
	 */
	{ NVME_IOCTL_E_BLKDEV_DETACH, NVME_ERR_DETACH_KERN, "the kernel failed "
	    "to detach the requested namespace" },
	{ NVME_IOCTL_E_BLKDEV_ATTACH, NVME_ERR_ATTACH_KERN, "the kernel failed "
	    "to attach the requested namespace" },
	{ NVME_IOCTL_E_UNSUP_ATTACH_NS, NVME_ERR_ATTACH_UNSUP_KERN,
	    "the namespace is not supported by the kernel" },
	{ NVME_IOCTL_E_CTRL_FORMAT_UNSUP, NVME_ERR_FORMAT_UNSUP_BY_DEV, "the "
	    "controller does not support formatting namespaces" },
	{ NVME_IOCTL_E_CTRL_CRYPTO_SE_UNSUP, NVME_ERR_CRYPTO_SE_UNSUP_BY_DEV,
	    "the controller does not support cryptographic secure erase" },
	{ NVME_IOCTL_E_CTRL_NS_FORMAT_UNSUP, NVME_ERR_NS_FORMAT_UNSUP_BY_DEV,
	    "the controller cannot format a single namespace" },
	{ NVME_IOCTL_E_CTRL_NS_SE_UNSUP, NVME_ERR_NS_FORMAT_UNSUP_BY_DEV,
	    "the controller cannot secure erase a single namespace" },
	{ NVME_IOCTL_E_FORMAT_LBAF_RANGE, NVME_ERR_FORMAT_LBAF_RANGE,
	    "invalid LBA format value" },
	{ NVME_IOCTL_E_FORMAT_SES_RANGE, NVME_ERR_FORMAT_SES_RANGE,
	    "invalid secure erase settings value" },
	{ NVME_IOCTL_E_UNSUP_LBAF_META, NVME_ERR_KERN_FORMAT_UNSUP, "cannot "
	    "format due to the use of unsupported metadata sectors" },
	{ NVME_IOCTL_E_CTRL_FW_UNSUP, NVME_ERR_FW_UNSUP_BY_DEV, "the "
	    "controller does not support firmware commands" },
	{ NVME_IOCTL_E_FW_LOAD_IMPOS_GRAN, NVME_ERR_KERN_FW_IMPOS, "controller "
	    "reported firmware upgrade granularity does not work with the "
	    "calculated maximum DMA transfer size" },
	{ NVME_IOCTL_E_FW_LOAD_LEN_RANGE, NVME_ERR_FW_LOAD_LEN_RANGE,
	    "invalid firmware load length value" },
	{ NVME_IOCTL_E_FW_LOAD_OFFSET_RANGE, NVME_ERR_FW_LOAD_OFFSET_RANGE,
	    "invalid firmware load offset value" },
	{ NVME_IOCTL_E_FW_COMMIT_SLOT_RANGE, NVME_ERR_FW_COMMIT_SLOT_RANGE,
	    "invalid firmware commit slot value" },
	{ NVME_IOCTL_E_FW_COMMIT_ACTION_RANGE, NVME_ERR_FW_COMMIT_ACTION_RANGE,
	    "invalid firmware commit action value" },
	{ NVME_IOCTL_E_RO_FW_SLOT, NVME_ERR_FW_SLOT_RO, "cannot write to read-"
	    "only slot" },
	/*
	 * We have purposefully skipped NVME_IOCTL_E_UNKNOWN_FEATURE for the
	 * same reasons we did with NVME_IOCTL_E_UNKNOWN_LOG above.
	 */
	{ NVME_IOCTL_E_UNSUP_FEATURE, NVME_ERR_FEAT_UNSUP_BY_DEV, "the "
	    "controller does not supported the requested feature" },
	{ NVME_IOCTL_E_GET_FEAT_SEL_RANGE, NVME_ERR_FEAT_SEL_RANGE, "invalid "
	    "feature selector value" },
	{ NVME_IOCTL_E_GET_FEAT_CDW11_RANGE, NVME_ERR_FEAT_CDW11_RANGE,
	    "invalid feature-specific cdw11 value" },
	{ NVME_IOCTL_E_GET_FEAT_DATA_RANGE, NVME_ERR_FEAT_DATA_RANGE, "invalid "
	    "feature data, likely a size mismatch" },
	{ NVME_IOCTL_E_GET_FEAT_SEL_UNSUP, NVME_ERR_FEAT_SEL_UNSUP, "the "
	    "controller does not support specifying a feature selector" },
	{ NVME_IOCTL_E_GET_FEAT_CDW11_UNUSE, NVME_ERR_FEAT_CDW11_UNUSE,
	    "the feature does not support specifying a cdw11 argument" },
	{ NVME_IOCTL_E_GET_FEAT_DATA_UNUSE, NVME_ERR_FEAT_DATA_UNUSE,
	    "the feature does not support specifying a data buffer" },
	/*
	 * We skip the NVME_IOCTL_E_BAD_LOCK_ENTITY,
	 * NVME_IOCTL_E_BAD_LOCK_LEVEL, and NVME_IOCTL_E_BAD_LOCK_FLAGS
	 * arguments as these are all generally passed by the library and not
	 * really under direct user control. Therefore if there is a problem,
	 * that should be an internal error.
	 *
	 * Similarly we skip NVME_IOCTL_E_NS_CANNOT_LOCK_CTRL and
	 * NVME_IOCTL_E_NS_CANNOT_UNLOCK_CTRL because the library does not
	 * utilize namespace minors and these can only apply to those.
	 */
	{ NVME_IOCTL_E_LOCK_ALREADY_HELD, NVME_ERR_LOCK_PROG, "fatal "
	    "programmer error: recursive lock attempt" },
	{ NVME_IOCTL_E_LOCK_NO_CTRL_WITH_NS, NVME_ERR_LOCK_ORDER,
	    "control locks cannot be acquired while holding a namespace lock" },
	{ NVME_IOCTL_LOCK_NO_NS_WITH_CTRL_WRLOCK, NVME_ERR_LOCK_ORDER,
	    "no namespace locks may be acquired while holding a controller "
	    "write lock" },
	{ NVME_IOCTL_E_LOCK_NO_2ND_NS, NVME_ERR_LOCK_ORDER, "only a single "
	    "namespace lock can be held at any time" },
	{ NVME_IOCTL_E_LOCK_WAIT_SIGNAL, NVME_ERR_LOCK_WAIT_INTR, "signal "
	    "received while blocking" },
	{ NVME_IOCTL_E_LOCK_WOULD_BLOCK, NVME_ERR_LOCK_WOULD_BLOCK, "lock not "
	    "available and no blocking allowed" },
	{ NVME_IOCTL_E_LOCK_PENDING, NVME_ERR_LOCK_ORDER, "a handle may only "
	    "block on one lock at a time" },
	{ NVME_IOCTL_E_LOCK_NOT_HELD, NVME_ERR_LOCK_PROG, "fatal "
	    "programmer error: asked to unlock lock that was not held" },
	/*
	 * This error is almost a can't happen due to the library construction
	 * and should result in the above error, but if this does happen, we
	 * treat this as a fatal lock error regardless.
	 */
	{ NVME_IOCTL_E_LOCK_WRONG_NS, NVME_ERR_LOCK_PROG, "fatal "
	    "programmer error: asked to unlock namespace lock that was not "
	    "held" },
	{ NVME_IOCTL_E_NS_BLKDEV_ATTACH, NVME_ERR_NS_BLKDEV_ATTACH, "cannot "
	    "execute request while blkdev is attached to the namespace" },
	/*
	 * We purposefully skip NVME_IOCTL_E_BD_ADDR_OVER right now because
	 * there is nothing that a user can do about this. This is a
	 * libnvme/kernel interface issue.
	 */
	{ NVME_IOCTL_E_CTRL_NS_MGMT_UNSUP, NVME_ERR_NS_MGMT_UNSUP_BY_DEV,
	    "controller does not support namespace management" },
	{ NVME_IOCTL_E_NS_CTRL_ATTACHED, NVME_ERR_NS_CTRL_ATTACHED,
	    "cannot execute request against an attached namespace" },
	{ NVME_IOCTL_E_NS_CTRL_NOT_ATTACHED, NVME_ERR_NS_CTRL_NOT_ATTACHED,
	    "cannot execute request against an unattached namespace" },
	{ NVME_IOCTL_E_NS_NO_NS, NVME_ERR_NS_UNALLOC, "cannot execute request "
	    "against an unallocated namespace" },
	{ NVME_IOCTL_E_NS_CREATE_NSZE_RANGE, NVME_ERR_NS_CREATE_NSZE_RANGE,
	    "invalid namespace create size specified" },
	{ NVME_IOCTL_E_NS_CREATE_NCAP_RANGE, NVME_ERR_NS_CREATE_NCAP_RANGE,
	    "invalid namespace create capacity specified" },
	/*
	 * Right now the library only has a single error for an invalid CSI on
	 * namespace create regardless of the reason.
	 */
	{ NVME_IOCTL_E_NS_CREATE_CSI_RANGE, NVME_ERR_NS_CREATE_BAD_CSI,
	    "invalid namespace create command set identifier specified" },
	{ NVME_IOCTL_E_NS_CREATE_FLBAS_RANGE, NVME_ERR_NS_CREATE_FLBAS_RANGE,
	    "invalid namespace create LBA format specified" },
	{ NVME_IOCTL_E_NS_CREATE_NMIC_RANGE, NVME_ERR_NS_CREATE_NMIC_RANGE,
	    "invalid namespace multi-path and sharing capability specified" },
	{ NVME_IOCTL_E_NS_CREATE_CSI_UNSUP, NVME_ERR_NS_CREATE_BAD_CSI, "the "
	    "controller does not support specifying a CSI when creating "
	    "namespaces" },
	{ NVME_IOCTL_E_DRV_CSI_UNSUP, NVME_ERR_NS_CREATE_BAD_CSI, "the nvme "
	    "driver does not supporting CSIs with that value" },
	{ NVME_IOCTL_E_CTRL_THIN_PROV_UNSUP, NVME_ERR_THIN_PROV_UNSUP_BY_DEV,
	    "controller does not support thin provisioning of namespaces" },
};

/*
 * Translate a kernel ioctl error into the library's error. We handle the
 * controller error separately. Otherwise, everything else is done based upon
 * our translation table.
 */
bool
nvme_ioctl_error(nvme_ctrl_t *ctrl, const nvme_ioctl_common_t *ioc,
    const char *desc)
{
	int ret;
	nvme_err_data_t *err = &ctrl->nc_err;
	VERIFY3U(ioc->nioc_drv_err, !=, NVME_IOCTL_E_OK);

	err->ne_syserr = 0;
	err->ne_ctrl_sct = 0;
	err->ne_ctrl_sc = 0;

	if (ioc->nioc_drv_err == NVME_IOCTL_E_CTRL_ERROR) {
		const char *sct, *sc;
		err->ne_err = NVME_ERR_CONTROLLER;
		err->ne_ctrl_sct = ioc->nioc_ctrl_sct;
		err->ne_ctrl_sc = ioc->nioc_ctrl_sc;
		sct = nvme_scttostr(ctrl, ioc->nioc_ctrl_sct);
		sc = nvme_sctostr(ctrl, NVME_CSI_NVM, ioc->nioc_ctrl_sct,
		    ioc->nioc_ctrl_sc);
		ret = snprintf(err->ne_errmsg, sizeof (err->ne_errmsg),
		    "failed to execute %s command: received controller error "
		    "sct/sc %s/%s (0x%x/0x%x)", desc, sct, sc,
		    ioc->nioc_ctrl_sct, ioc->nioc_ctrl_sc);
	} else {
		const nvme_ktolmap_t *map = NULL;
		for (size_t i = 0; i < ARRAY_SIZE(nvme_ktolmap); i++) {
			if (nvme_ktolmap[i].kl_kern == ioc->nioc_drv_err) {
				map = &nvme_ktolmap[i];
				break;
			}
		}

		if (map != NULL) {
			err->ne_err = map->kl_lib;
			ret = snprintf(err->ne_errmsg, sizeof (err->ne_errmsg),
			    "failed to execute %s command: %s", desc,
			    map->kl_desc);
		} else {
			err->ne_err = NVME_ERR_INTERNAL;
			ret = snprintf(err->ne_errmsg, sizeof (err->ne_errmsg),
			    "failed to execute %s command: failed to map "
			    "kernel error 0x%x to a known cause", desc,
			    ioc->nioc_drv_err);
		}
	}

	if (ret >= sizeof (err->ne_errmsg)) {
		err->ne_errlen = sizeof (err->ne_errmsg) - 1;
	} else if (ret <= 0) {
		err->ne_errlen = 0;
		err->ne_errmsg[0] = '\0';
	} else {
		err->ne_errlen = (size_t)ret;
	}

	return (false);
}

/*
 * Evaluate the set of ioctl errors that we see and translate and/or abort a few
 * of the expected values. Most things will end up being translated into a
 * generic internal error as we expect a rather tight error set at this point.
 *
 * We choose to panic on EFAULT because we are responsible for all such EFAULT
 * errors. These are structure that are coming from the library. This is not
 * something that the user could have passed us (their buffers will trigger
 * an explicit nvme_ioctl_errno_t). Therefore, something has gone very wrong
 * with our stack or we just corrupted some memory.
 *
 * The same is true with EBADF. In this case, that'd happen either because our
 * controller fd was bandit'd away by someone or somehow we lost FREAD or FWRITE
 * on the fd. That should not be possible assuming everyone is acting in good
 * faith, so we treat this as a sign that something quite bad has happened and
 * we shouldn't continue.
 */
bool
nvme_ioctl_syserror(nvme_ctrl_t *ctrl, int err, const char *desc)
{
	switch (err) {
	case EFAULT:
	case EBADF: {
		const char *base = "fatal libnvme internal programming error: "
		    "failed to issue ioctl";
		char msg[1024];
		int ret;
		const char *up;
		size_t ulen;

		ret = snprintf(msg, sizeof (msg), "%s %s: %s (controller %p)",
		    base, desc, strerror(err), ctrl);
		if (ret >= sizeof (msg)) {
			ulen = sizeof (msg);
			up = msg;
		} else if (ret <= 0) {
			up = base;
			ulen = strlen(base) + 1;
		} else {
			ulen = (size_t)ret;
			up = msg;
		}

		upanic(up, ulen);
	}
	case EPERM:
		return (nvme_ctrl_error(ctrl, NVME_ERR_PRIVS, err,
		    "failed to issue %s ioctl due to missing privileges",
		    desc));
	default:
		return (nvme_ctrl_error(ctrl, NVME_ERR_INTERNAL, err,
		    "failed to issue %s ioctl due to unexpected system "
		    "error: %s", desc, strerror(err)));
	}
}

/*
 * Generate the standard warning about which fields are unused.
 */
bool
nvme_field_miss_err(nvme_ctrl_t *ctrl, const nvme_field_info_t *fields,
    size_t nfields, nvme_err_t err, const char *desc, uint32_t val)
{
	char buf[512];
	bool comma = false;

	VERIFY3U(val, !=, 0);
	buf[0] = '\0';
	for (size_t i = 0; i < nfields; i++) {
		if ((val & (1 << i)) == 0) {
			continue;
		}

		if (comma) {
			(void) strlcat(buf, ",", sizeof (buf));
		}
		(void) strlcat(buf, fields[i].nlfi_spec, sizeof (buf));
		comma = true;
	}

	return (nvme_ctrl_error(ctrl, err, 0, "cannot execute %s request due "
	    "to missing fields: %s", desc, buf));
}

bool
nvme_field_check_one(nvme_ctrl_t *ctrl, uint64_t val, const char *req,
    const nvme_field_check_t *check, uint32_t allow)
{
	const nvme_field_info_t *field = &check->chk_fields[check->chk_index];
	nvme_valid_ctrl_data_t data;
	nvme_field_error_t err;
	char msg[256];

	if (allow != 0 && (allow & (1 << check->chk_index)) == 0) {
		VERIFY3U(check->chk_field_unuse, !=, 0);
		return (nvme_ctrl_error(ctrl, check->chk_field_unuse, 0,
		    "field %s (%s) cannot be set in this %s request",
		    field->nlfi_human, field->nlfi_spec, req));
	}

	data.vcd_vers = &ctrl->nc_vers;
	data.vcd_id = &ctrl->nc_info;

	err = nvme_field_validate(field, &data, val, msg, sizeof (msg));
	switch (err) {
	case NVME_FIELD_ERR_OK:
		break;
	case NVME_FIELD_ERR_UNSUP_VERSION:
	case NVME_FIELD_ERR_UNSUP_FIELD:
		VERIFY3U(check->chk_field_unsup, !=, 0);
		return (nvme_ctrl_error(ctrl, check->chk_field_unsup, 0, "%s",
		    msg));
	case NVME_FIELD_ERR_BAD_VALUE:
		VERIFY3U(check->chk_field_range, !=, 0);
		return (nvme_ctrl_error(ctrl, check->chk_field_range, 0, "%s",
		    msg));
	}

	return (true);
}
