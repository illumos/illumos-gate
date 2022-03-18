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
 * Copyright 2021 Oxide Computer Company
 * Copyright 2022 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * nvmeadm output formatting for ofmt based rendering
 */

#include <strings.h>

#include "nvmeadm.h"

typedef enum nvme_list_ofmt_field {
	NVME_LIST_MODEL,
	NVME_LIST_SERIAL,
	NVME_LIST_FWREV,
	NVME_LIST_VERSION,
	NVME_LIST_SIZE,
	NVME_LIST_CAPACITY,
	NVME_LIST_USED,
	NVME_LIST_INSTANCE,
	NVME_LIST_NAMESPACE,
	NVME_LIST_DISK,
	NVME_LIST_UNALLOC,
} nvme_list_ofmt_field_t;

static boolean_t
nvme_list_common_ofmt_cb(ofmt_arg_t *ofmt_arg, char *buf, uint_t buflen)
{
	const nvme_process_arg_t *npa = ofmt_arg->ofmt_cbarg;
	int nvmelen;
	size_t ret;

	switch (ofmt_arg->ofmt_id) {
	case NVME_LIST_MODEL:
		nvmelen = nvme_strlen(npa->npa_idctl->id_model,
		    sizeof (npa->npa_idctl->id_model));
		if (nvmelen <= 0 || nvmelen > buflen) {
			return (B_FALSE);
		}
		(void) memcpy(buf, npa->npa_idctl->id_model, nvmelen);
		buf[nvmelen] = '\0';
		ret = nvmelen;
		break;
	case NVME_LIST_SERIAL:
		nvmelen = nvme_strlen(npa->npa_idctl->id_serial,
		    sizeof (npa->npa_idctl->id_serial));
		if (nvmelen <= 0 || nvmelen >= buflen) {
			return (B_FALSE);
		}
		(void) memcpy(buf, npa->npa_idctl->id_serial, nvmelen);
		buf[nvmelen] = '\0';
		ret = nvmelen;
		break;
	case NVME_LIST_FWREV:
		nvmelen = nvme_strlen(npa->npa_idctl->id_fwrev,
		    sizeof (npa->npa_idctl->id_fwrev));
		if (nvmelen <= 0 || nvmelen >= buflen) {
			return (B_FALSE);
		}
		(void) memcpy(buf, npa->npa_idctl->id_fwrev, nvmelen);
		buf[nvmelen] = '\0';
		ret = nvmelen;
		break;
	case NVME_LIST_VERSION:
		ret = snprintf(buf, buflen, "%u.%u", npa->npa_version->v_major,
		    npa->npa_version->v_minor);
		break;
	case NVME_LIST_INSTANCE:
		ret = strlcat(buf, npa->npa_name, buflen);
		break;
	default:
		abort();
	}
	if (ret >= buflen) {
		return (B_FALSE);
	}
	return (B_TRUE);
}

static boolean_t
nvme_list_ctrl_ofmt_cb(ofmt_arg_t *ofmt_arg, char *buf, uint_t buflen)
{
	const nvme_process_arg_t *npa = ofmt_arg->ofmt_cbarg;
	size_t ret;

	switch (ofmt_arg->ofmt_id) {
	case NVME_LIST_CAPACITY:
		ret = nvme_snprint_uint128(buf, buflen,
		    npa->npa_idctl->ap_tnvmcap, 0, 0);
		break;
	case NVME_LIST_UNALLOC:
		ret = nvme_snprint_uint128(buf, buflen,
		    npa->npa_idctl->ap_unvmcap, 0, 0);
		break;
	default:
		abort();
	}

	if (ret >= buflen) {
		return (B_FALSE);
	}
	return (B_TRUE);
}

static boolean_t
nvme_list_nsid_ofmt_cb(ofmt_arg_t *ofmt_arg, char *buf, uint_t buflen)
{
	const nvme_process_arg_t *npa = ofmt_arg->ofmt_cbarg;
	nvme_idns_lbaf_t *lbaf;
	uint_t blksize;
	uint64_t val;
	size_t ret;

	lbaf = &npa->npa_idns->id_lbaf[npa->npa_idns->id_flbas.lba_format];
	blksize = 1 << lbaf->lbaf_lbads;

	switch (ofmt_arg->ofmt_id) {
	case NVME_LIST_NAMESPACE:
		ret = strlcat(buf, di_minor_name(npa->npa_minor), buflen);
		break;
	case NVME_LIST_DISK:
		if (npa->npa_dsk != NULL) {
			ret = strlcat(buf, npa->npa_dsk, buflen);
		} else {
			ret = strlcat(buf, "--", buflen);
		}
		break;
	case NVME_LIST_SIZE:
		val = npa->npa_idns->id_nsize * blksize;
		ret = snprintf(buf, buflen, "%" PRIu64, val);
		break;
	case NVME_LIST_CAPACITY:
		val = npa->npa_idns->id_ncap * blksize;
		ret = snprintf(buf, buflen, "%" PRIu64, val);
		break;
	case NVME_LIST_USED:
		val = npa->npa_idns->id_nuse * blksize;
		ret = snprintf(buf, buflen, "%" PRIu64, val);
		break;
	default:
		abort();
	}

	if (ret >= buflen) {
		return (B_FALSE);
	}
	return (B_TRUE);
}

const ofmt_field_t nvme_list_ctrl_ofmt[] = {
	{ "MODEL", 30, NVME_LIST_MODEL, nvme_list_common_ofmt_cb },
	{ "SERIAL", 30, NVME_LIST_SERIAL, nvme_list_common_ofmt_cb },
	{ "FWREV", 10, NVME_LIST_FWREV, nvme_list_common_ofmt_cb },
	{ "VERSION", 10, NVME_LIST_VERSION, nvme_list_common_ofmt_cb },
	{ "CAPACITY", 15, NVME_LIST_CAPACITY, nvme_list_ctrl_ofmt_cb },
	{ "INSTANCE", 10, NVME_LIST_INSTANCE, nvme_list_common_ofmt_cb },
	{ "UNALLOCATED", 15, NVME_LIST_UNALLOC, nvme_list_ctrl_ofmt_cb },
	{ NULL, 0, 0, NULL }
};

const ofmt_field_t nvme_list_nsid_ofmt[] = {
	{ "MODEL", 30, NVME_LIST_MODEL, nvme_list_common_ofmt_cb },
	{ "SERIAL", 30, NVME_LIST_SERIAL, nvme_list_common_ofmt_cb },
	{ "FWREV", 10, NVME_LIST_FWREV, nvme_list_common_ofmt_cb },
	{ "VERSION", 10, NVME_LIST_VERSION, nvme_list_common_ofmt_cb },
	{ "SIZE", 15, NVME_LIST_SIZE, nvme_list_nsid_ofmt_cb },
	{ "CAPACITY", 15, NVME_LIST_CAPACITY, nvme_list_nsid_ofmt_cb },
	{ "USED", 15, NVME_LIST_USED, nvme_list_nsid_ofmt_cb },
	{ "INSTANCE", 10, NVME_LIST_INSTANCE, nvme_list_common_ofmt_cb },
	{ "NAMESPACE", 10, NVME_LIST_NAMESPACE, nvme_list_nsid_ofmt_cb },
	{ "DISK", 15, NVME_LIST_DISK, nvme_list_nsid_ofmt_cb },
	{ NULL, 0, 0, NULL }
};
