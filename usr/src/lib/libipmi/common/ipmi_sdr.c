/*
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
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2018, Joyent, Inc.
 */


#include <libipmi.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <math.h>

#include "ipmi_impl.h"

/*
 * This macros are used by ipmi_sdr_conv_reading.  They were taken verbatim from
 * the source for ipmitool (v1.88)
 */
#define	tos32(val, bits)	((val & ((1<<((bits)-1)))) ? (-((val) & \
				(1<<((bits)-1))) | (val)) : (val))

#define	__TO_TOL(mtol)	(uint16_t)(BSWAP_16(mtol) & 0x3f)

#define	__TO_M(mtol)	(int16_t)(tos32((((BSWAP_16(mtol) & 0xff00) >> 8) | \
				((BSWAP_16(mtol) & 0xc0) << 2)), 10))

#define	__TO_B(bacc)	(int32_t)(tos32((((BSWAP_32(bacc) & \
				0xff000000) >> 24) | \
				((BSWAP_32(bacc) & 0xc00000) >> 14)), 10))

#define	__TO_ACC(bacc)	(uint32_t)(((BSWAP_32(bacc) & 0x3f0000) >> 16) | \
				((BSWAP_32(bacc) & 0xf000) >> 6))

#define	__TO_ACC_EXP(bacc)	(uint32_t)((BSWAP_32(bacc) & 0xc00) >> 10)
#define	__TO_R_EXP(bacc)	(int32_t)(tos32(((BSWAP_32(bacc) & 0xf0) >> 4),\
				4))
#define	__TO_B_EXP(bacc)	(int32_t)(tos32((BSWAP_32(bacc) & 0xf), 4))

#define	SDR_SENSOR_L_LINEAR	0x00
#define	SDR_SENSOR_L_LN		0x01
#define	SDR_SENSOR_L_LOG10	0x02
#define	SDR_SENSOR_L_LOG2	0x03
#define	SDR_SENSOR_L_E		0x04
#define	SDR_SENSOR_L_EXP10	0x05
#define	SDR_SENSOR_L_EXP2	0x06
#define	SDR_SENSOR_L_1_X	0x07
#define	SDR_SENSOR_L_SQR	0x08
#define	SDR_SENSOR_L_CUBE	0x09
#define	SDR_SENSOR_L_SQRT	0x0a
#define	SDR_SENSOR_L_CUBERT	0x0b
#define	SDR_SENSOR_L_NONLINEAR	0x70

/*
 * Analog sensor reading data formats
 *
 * See Section 43.1
 */
#define	IPMI_DATA_FMT_UNSIGNED	0
#define	IPMI_DATA_FMT_ONESCOMP	1
#define	IPMI_DATA_FMT_TWOSCOMP	2

#define	IPMI_SDR_HDR_SZ		offsetof(ipmi_sdr_t, is_record)

typedef struct ipmi_sdr_cache_ent {
	char				*isc_name;
	uint8_t				isc_entity_id;
	uint8_t				isc_entity_inst;
	struct ipmi_sdr			*isc_sdr;
	ipmi_hash_link_t		isc_link;
} ipmi_sdr_cache_ent_t;

typedef struct ipmi_cmd_get_sdr {
	uint16_t	ic_gs_resid;
	uint16_t	ic_gs_recid;
	uint8_t		ic_gs_offset;
	uint8_t		ic_gs_len;
} ipmi_cmd_get_sdr_t;

typedef struct ipmi_rsp_get_sdr {
	uint16_t	ir_gs_next;
	uint8_t		ir_gs_record[1];
} ipmi_rsp_get_sdr_t;

/*
 * "Get SDR Repostiory Info" command.
 */
ipmi_sdr_info_t *
ipmi_sdr_get_info(ipmi_handle_t *ihp)
{
	ipmi_cmd_t cmd, *rsp;
	ipmi_sdr_info_t *sip;
	uint16_t tmp16;
	uint32_t tmp32;

	cmd.ic_netfn = IPMI_NETFN_STORAGE;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_GET_SDR_INFO;
	cmd.ic_dlen = 0;
	cmd.ic_data = NULL;

	if ((rsp = ipmi_send(ihp, &cmd)) == NULL)
		return (NULL);

	sip = rsp->ic_data;

	tmp16 = LE_IN16(&sip->isi_record_count);
	(void) memcpy(&sip->isi_record_count, &tmp16, sizeof (tmp16));

	tmp16 = LE_IN16(&sip->isi_free_space);
	(void) memcpy(&sip->isi_free_space, &tmp16, sizeof (tmp16));

	tmp32 = LE_IN32(&sip->isi_add_ts);
	(void) memcpy(&sip->isi_add_ts, &tmp32, sizeof (tmp32));

	tmp32 = LE_IN32(&sip->isi_erase_ts);
	(void) memcpy(&sip->isi_erase_ts, &tmp32, sizeof (tmp32));

	return (sip);
}

/*
 * Issue the "Reserve SDR Repository" command.
 */
static int
ipmi_sdr_reserve_repository(ipmi_handle_t *ihp)
{
	ipmi_cmd_t cmd, *rsp;

	cmd.ic_netfn = IPMI_NETFN_STORAGE;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_RESERVE_SDR_REPOSITORY;
	cmd.ic_dlen = 0;
	cmd.ic_data = NULL;

	if ((rsp = ipmi_send(ihp, &cmd)) == NULL)
		return (-1);

	ihp->ih_reservation = *((uint16_t *)rsp->ic_data);
	return (0);
}

/*
 * Returns B_TRUE if the repository has changed since the cached copy was last
 * referenced.
 */
boolean_t
ipmi_sdr_changed(ipmi_handle_t *ihp)
{
	ipmi_sdr_info_t *sip;

	if ((sip = ipmi_sdr_get_info(ihp)) == NULL)
		return (B_TRUE);

	return (sip->isi_add_ts > ihp->ih_sdr_ts ||
	    sip->isi_erase_ts > ihp->ih_sdr_ts ||
	    ipmi_hash_first(ihp->ih_sdr_cache) == NULL);
}

/*
 * Refresh the cache of sensor data records.
 */
int
ipmi_sdr_refresh(ipmi_handle_t *ihp)
{
	uint16_t id;
	ipmi_sdr_t *sdr;
	ipmi_sdr_cache_ent_t *ent;
	size_t namelen;
	uint8_t type, e_id = 0, e_inst = 0;
	char *name;
	ipmi_sdr_info_t *sip;
	uint32_t isi_add_ts, isi_erase_ts;

	if ((sip = ipmi_sdr_get_info(ihp)) == NULL)
		return (-1);

	(void) memcpy(&isi_add_ts, &sip->isi_add_ts, sizeof (uint32_t));
	(void) memcpy(&isi_erase_ts, &sip->isi_erase_ts, sizeof (uint32_t));
	if (isi_add_ts <= ihp->ih_sdr_ts &&
	    isi_erase_ts <= ihp->ih_sdr_ts &&
	    ipmi_hash_first(ihp->ih_sdr_cache) != NULL)
		return (0);

	ipmi_sdr_clear(ihp);
	ipmi_entity_clear(ihp);
	ihp->ih_sdr_ts = MAX(isi_add_ts, isi_erase_ts);

	/*
	 * Iterate over all existing SDRs and add them to the cache.
	 */
	id = IPMI_SDR_FIRST;
	while (id != IPMI_SDR_LAST) {
		if ((sdr = ipmi_sdr_get(ihp, id, &id)) == NULL)
			goto error;

		/*
		 * Extract the name from the record-specific data.
		 */
		switch (sdr->is_type) {
		case IPMI_SDR_TYPE_GENERIC_LOCATOR:
			{
				ipmi_sdr_generic_locator_t *glp =
				    (ipmi_sdr_generic_locator_t *)
				    sdr->is_record;
				namelen = glp->is_gl_idlen;
				type = glp->is_gl_idtype;
				name = glp->is_gl_idstring;
				e_id = glp->is_gl_entity;
				e_inst = glp->is_gl_instance;
				break;
			}

		case IPMI_SDR_TYPE_FRU_LOCATOR:
			{
				ipmi_sdr_fru_locator_t *flp =
				    (ipmi_sdr_fru_locator_t *)
				    sdr->is_record;
				namelen = flp->is_fl_idlen;
				name = flp->is_fl_idstring;
				type = flp->is_fl_idtype;
				e_id = flp->is_fl_entity;
				e_inst = flp->is_fl_instance;
				break;
			}

		case IPMI_SDR_TYPE_COMPACT_SENSOR:
			{
				ipmi_sdr_compact_sensor_t *csp =
				    (ipmi_sdr_compact_sensor_t *)
				    sdr->is_record;
				uint16_t tmp;

				namelen = csp->is_cs_idlen;
				type = csp->is_cs_idtype;
				name = csp->is_cs_idstring;
				e_id = csp->is_cs_entity_id;
				e_inst = csp->is_cs_entity_instance;

				tmp = LE_IN16(&csp->is_cs_assert_mask);
				(void) memcpy(&csp->is_cs_assert_mask, &tmp,
				    sizeof (tmp));

				tmp = LE_IN16(&csp->is_cs_deassert_mask);
				(void) memcpy(&csp->is_cs_deassert_mask, &tmp,
				    sizeof (tmp));

				tmp = LE_IN16(&csp->is_cs_reading_mask);
				(void) memcpy(&csp->is_cs_reading_mask, &tmp,
				    sizeof (tmp));
				break;
			}

		case IPMI_SDR_TYPE_FULL_SENSOR:
			{
				ipmi_sdr_full_sensor_t *fsp =
				    (ipmi_sdr_full_sensor_t *)
				    sdr->is_record;
				uint16_t tmp;

				namelen = fsp->is_fs_idlen;
				type = fsp->is_fs_idtype;
				name = fsp->is_fs_idstring;
				e_id = fsp->is_fs_entity_id;
				e_inst = fsp->is_fs_entity_instance;

				tmp = LE_IN16(&fsp->is_fs_assert_mask);
				(void) memcpy(&fsp->is_fs_assert_mask, &tmp,
				    sizeof (tmp));

				tmp = LE_IN16(&fsp->is_fs_deassert_mask);
				(void) memcpy(&fsp->is_fs_deassert_mask, &tmp,
				    sizeof (tmp));

				tmp = LE_IN16(&fsp->is_fs_reading_mask);
				(void) memcpy(&fsp->is_fs_reading_mask, &tmp,
				    sizeof (tmp));
				break;
			}

		case IPMI_SDR_TYPE_EVENT_ONLY:
			{
				ipmi_sdr_event_only_t *esp =
				    (ipmi_sdr_event_only_t *)
				    sdr->is_record;
				namelen = esp->is_eo_idlen;
				type = esp->is_eo_idtype;
				name = esp->is_eo_idstring;
				e_id = esp->is_eo_entity_id;
				e_inst = esp->is_eo_entity_instance;
				break;
			}

		case IPMI_SDR_TYPE_MANAGEMENT_LOCATOR:
			{
				ipmi_sdr_management_locator_t *msp =
				    (ipmi_sdr_management_locator_t *)
				    sdr->is_record;
				namelen = msp->is_ml_idlen;
				type = msp->is_ml_idtype;
				name = msp->is_ml_idstring;
				e_id = msp->is_ml_entity_id;
				e_inst = msp->is_ml_entity_instance;
				break;
			}

		case IPMI_SDR_TYPE_MANAGEMENT_CONFIRMATION:
			{
				ipmi_sdr_management_confirmation_t *mcp =
				    (ipmi_sdr_management_confirmation_t *)
				    sdr->is_record;
				uint16_t tmp;

				name = NULL;
				tmp = LE_IN16(&mcp->is_mc_product);
				(void) memcpy(&mcp->is_mc_product, &tmp,
				    sizeof (tmp));
				break;
			}

		default:
			name = NULL;
		}

		if ((ent = ipmi_zalloc(ihp,
		    sizeof (ipmi_sdr_cache_ent_t))) == NULL) {
			free(sdr);
			goto error;
		}

		ent->isc_sdr = sdr;
		ent->isc_entity_id = e_id;
		ent->isc_entity_inst = e_inst;

		if (name != NULL) {
			if ((ent->isc_name = ipmi_alloc(ihp, namelen + 1)) ==
			    NULL) {
				ipmi_free(ihp, ent->isc_sdr);
				ipmi_free(ihp, ent);
				goto error;
			}

			ipmi_decode_string(type, namelen, name, ent->isc_name);
		}

		/*
		 * This should never happen.  It means that the SP has returned
		 * a SDR record twice, with the same name and ID.  This has
		 * been observed on service processors that don't correctly
		 * return SDR_LAST during iteration, so assume we've looped in
		 * the SDR and return gracefully.
		 */
		if (ipmi_hash_lookup(ihp->ih_sdr_cache, ent) != NULL) {
			ipmi_free(ihp, ent->isc_sdr);
			ipmi_free(ihp, ent->isc_name);
			ipmi_free(ihp, ent);
			break;
		}

		ipmi_hash_insert(ihp->ih_sdr_cache, ent);
	}

	return (0);

error:
	ipmi_sdr_clear(ihp);
	ipmi_entity_clear(ihp);
	return (-1);
}

/*
 * Hash routines.  We allow lookup by name, but since not all entries have
 * names, we fall back to the entry pointer, which is guaranteed to be unique.
 * The end result is that entities without names cannot be looked up, but will
 * show up during iteration.
 */
static const void *
ipmi_sdr_hash_convert(const void *p)
{
	return (p);
}

static ulong_t
ipmi_sdr_hash_compute(const void *p)
{
	const ipmi_sdr_cache_ent_t *ep = p;

	if (ep->isc_name)
		return (ipmi_hash_strhash(ep->isc_name));
	else
		return (ipmi_hash_ptrhash(ep));
}

static int
ipmi_sdr_hash_compare(const void *a, const void *b)
{
	const ipmi_sdr_cache_ent_t *ap = a;
	const ipmi_sdr_cache_ent_t *bp = b;

	if (ap->isc_name == NULL || bp->isc_name == NULL)
		return (-1);

	if (strcmp(ap->isc_name, bp->isc_name) != 0)
		return (-1);

	/*
	 * When looking up only by name we return the first matching name. For
	 * a more precise match, callers can optionally specify an IPMI entity
	 * ID and instance that must also match.
	 */
	if (ap->isc_entity_id != IPMI_ET_UNSPECIFIED &&
	    bp->isc_entity_id != IPMI_ET_UNSPECIFIED) {
		if (ap->isc_entity_id != bp->isc_entity_id ||
		    ap->isc_entity_inst != bp->isc_entity_inst)
			return (-1);
	}
	return (0);
}

int
ipmi_sdr_init(ipmi_handle_t *ihp)
{
	if ((ihp->ih_sdr_cache = ipmi_hash_create(ihp,
	    offsetof(ipmi_sdr_cache_ent_t, isc_link),
	    ipmi_sdr_hash_convert, ipmi_sdr_hash_compute,
	    ipmi_sdr_hash_compare)) == NULL)
		return (-1);

	return (0);
}

void
ipmi_sdr_clear(ipmi_handle_t *ihp)
{
	ipmi_sdr_cache_ent_t *ent;

	while ((ent = ipmi_hash_first(ihp->ih_sdr_cache)) != NULL) {
		ipmi_hash_remove(ihp->ih_sdr_cache, ent);
		ipmi_free(ihp, ent->isc_sdr);
		ipmi_free(ihp, ent->isc_name);
		ipmi_free(ihp, ent);
	}
}

void
ipmi_sdr_fini(ipmi_handle_t *ihp)
{
	if (ihp->ih_sdr_cache != NULL) {
		ipmi_sdr_clear(ihp);
		ipmi_hash_destroy(ihp->ih_sdr_cache);
	}
}

ipmi_sdr_t *
ipmi_sdr_get(ipmi_handle_t *ihp, uint16_t id, uint16_t *next)
{
	uint8_t offset = IPMI_SDR_HDR_SZ, count = 0, chunksz = 16, sdr_sz;
	ipmi_cmd_t cmd, *rsp;
	ipmi_cmd_get_sdr_t req;
	ipmi_sdr_t *sdr;
	int i = 0;
	char *buf;

	req.ic_gs_resid = ihp->ih_reservation;
	req.ic_gs_recid = id;

	cmd.ic_netfn = IPMI_NETFN_STORAGE;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_GET_SDR;
	cmd.ic_dlen = sizeof (req);
	cmd.ic_data = &req;

	/*
	 * The size of the SDR is contained in the 5th byte of the SDR header,
	 * so we'll read the first 5 bytes to get the size, so we know how big
	 * to make the buffer.
	 */
	req.ic_gs_offset = 0;
	req.ic_gs_len = IPMI_SDR_HDR_SZ;
	for (i = 0; i < ihp->ih_retries; i++) {
		if ((rsp = ipmi_send(ihp, &cmd)) != NULL)
			break;

		if (ipmi_errno(ihp) != EIPMI_INVALID_RESERVATION)
			return (NULL);

		if (ipmi_sdr_reserve_repository(ihp) != 0)
			return (NULL);
		req.ic_gs_resid = ihp->ih_reservation;
	}
	if (rsp == NULL)
		return (NULL);

	sdr = (ipmi_sdr_t *)((ipmi_rsp_get_sdr_t *)rsp->ic_data)->ir_gs_record;
	sdr_sz = sdr->is_length;

	if ((buf = ipmi_zalloc(ihp, sdr_sz + IPMI_SDR_HDR_SZ)) == NULL) {
		(void) ipmi_set_error(ihp, EIPMI_NOMEM, NULL);
		return (NULL);
	}
	(void) memcpy(buf, (void *)sdr, IPMI_SDR_HDR_SZ);

	/*
	 * Some SDRs can be bigger than the buffer sizes for a given bmc
	 * interface.  Therefore we break up the process of reading in an entire
	 * SDR into multiple smaller reads.
	 */
	while (count < sdr_sz) {
		req.ic_gs_offset = offset;
		if (chunksz > (sdr_sz - count))
			chunksz = sdr_sz - count;
		req.ic_gs_len = chunksz;
		rsp = ipmi_send(ihp, &cmd);

		if (rsp != NULL) {
			count += chunksz;
			sdr = (ipmi_sdr_t *)
			    ((ipmi_rsp_get_sdr_t *)rsp->ic_data)->ir_gs_record;
			(void) memcpy(buf+offset, (void *)sdr, chunksz);
			offset += chunksz;
			i = 0;
		} else if (ipmi_errno(ihp) == EIPMI_INVALID_RESERVATION) {
			if (i >= ihp->ih_retries ||
			    ipmi_sdr_reserve_repository(ihp) != 0) {
				free(buf);
				return (NULL);
			}
			req.ic_gs_resid = ihp->ih_reservation;
			i++;
		} else {
			free(buf);
			return (NULL);
		}
	}
	*next = ((ipmi_rsp_get_sdr_t *)rsp->ic_data)->ir_gs_next;

	return ((ipmi_sdr_t *)buf);
}

int
ipmi_sdr_iter(ipmi_handle_t *ihp, int (*func)(ipmi_handle_t *,
    const char *, ipmi_sdr_t *, void *), void *data)
{
	ipmi_sdr_cache_ent_t *ent;
	int ret;

	if (ipmi_hash_first(ihp->ih_sdr_cache) == NULL &&
	    ipmi_sdr_refresh(ihp) != 0)
		return (-1);

	for (ent = ipmi_hash_first(ihp->ih_sdr_cache); ent != NULL;
	    ent = ipmi_hash_next(ihp->ih_sdr_cache, ent)) {
		if ((ret = func(ihp, ent->isc_name, ent->isc_sdr, data)) != 0)
			return (ret);
	}

	return (0);
}

ipmi_sdr_t *
ipmi_sdr_lookup(ipmi_handle_t *ihp, const char *idstr)
{
	return (ipmi_sdr_lookup_precise(ihp, idstr, IPMI_ET_UNSPECIFIED, 0));
}

ipmi_sdr_t *
ipmi_sdr_lookup_precise(ipmi_handle_t *ihp, const char *idstr, uint8_t e_id,
    uint8_t e_inst)
{
	ipmi_sdr_cache_ent_t *ent, search;

	if (ipmi_hash_first(ihp->ih_sdr_cache) == NULL &&
	    ipmi_sdr_refresh(ihp) != 0)
		return (NULL);

	search.isc_name = (char *)idstr;
	search.isc_sdr = NULL;
	search.isc_entity_id = e_id;
	search.isc_entity_inst = e_inst;
	if ((ent = ipmi_hash_lookup(ihp->ih_sdr_cache, &search)) == NULL) {
		(void) ipmi_set_error(ihp, EIPMI_NOT_PRESENT, NULL);
		return (NULL);
	}

	return (ent->isc_sdr);
}

static void *
ipmi_sdr_lookup_common(ipmi_handle_t *ihp, const char *idstr,
    uint8_t type)
{
	ipmi_sdr_t *sdrp;

	if ((sdrp = ipmi_sdr_lookup(ihp, idstr)) == NULL)
		return (NULL);

	if (sdrp->is_type != type) {
		(void) ipmi_set_error(ihp, EIPMI_NOT_PRESENT, NULL);
		return (NULL);
	}

	return (sdrp->is_record);
}

ipmi_sdr_fru_locator_t *
ipmi_sdr_lookup_fru(ipmi_handle_t *ihp, const char *idstr)
{
	return (ipmi_sdr_lookup_common(ihp, idstr,
	    IPMI_SDR_TYPE_FRU_LOCATOR));
}

ipmi_sdr_generic_locator_t *
ipmi_sdr_lookup_generic(ipmi_handle_t *ihp, const char *idstr)
{
	return (ipmi_sdr_lookup_common(ihp, idstr,
	    IPMI_SDR_TYPE_GENERIC_LOCATOR));
}

ipmi_sdr_compact_sensor_t *
ipmi_sdr_lookup_compact_sensor(ipmi_handle_t *ihp, const char *idstr)
{
	return (ipmi_sdr_lookup_common(ihp, idstr,
	    IPMI_SDR_TYPE_COMPACT_SENSOR));
}

ipmi_sdr_full_sensor_t *
ipmi_sdr_lookup_full_sensor(ipmi_handle_t *ihp, const char *idstr)
{
	return (ipmi_sdr_lookup_common(ihp, idstr,
	    IPMI_SDR_TYPE_FULL_SENSOR));
}

/*
 * Mostly taken from ipmitool source v1.88
 *
 * This function converts the raw sensor reading returned by
 * ipmi_get_sensor_reading to a unit-based value of type double.
 */
int
ipmi_sdr_conv_reading(ipmi_sdr_full_sensor_t *sensor, uint8_t val,
    double *result)
{
	int m, b, k1, k2;

	m = __TO_M(sensor->is_fs_mtol);
	b = __TO_B(sensor->is_fs_bacc);
	k1 = __TO_B_EXP(sensor->is_fs_bacc);
	k2 = __TO_R_EXP(sensor->is_fs_bacc);

	switch (sensor->is_fs_analog_fmt) {
	case IPMI_DATA_FMT_UNSIGNED:
		*result = (double)(((m * val) +
		    (b * pow(10, k1))) * pow(10, k2));
		break;
	case IPMI_DATA_FMT_ONESCOMP:
		if (val & 0x80)
			val++;
		/* FALLTHRU */
	case IPMI_DATA_FMT_TWOSCOMP:
		*result = (double)(((m * (int8_t)val) +
		    (b * pow(10, k1))) * pow(10, k2));
		break;
	default:
		/* This sensor does not return a numeric reading */
		return (-1);
	}

	switch (sensor->is_fs_sensor_linear_type) {
	case SDR_SENSOR_L_LN:
		*result = log(*result);
		break;
	case SDR_SENSOR_L_LOG10:
		*result = log10(*result);
		break;
	case SDR_SENSOR_L_LOG2:
		*result = (double)(log(*result) / log(2.0));
		break;
	case SDR_SENSOR_L_E:
		*result = exp(*result);
		break;
	case SDR_SENSOR_L_EXP10:
		*result = pow(10.0, *result);
		break;
	case SDR_SENSOR_L_EXP2:
		*result = pow(2.0, *result);
		break;
	case SDR_SENSOR_L_1_X:
		*result = pow(*result, -1.0);	/* 1/x w/o exception */
		break;
	case SDR_SENSOR_L_SQR:
		*result = pow(*result, 2.0);
		break;
	case SDR_SENSOR_L_CUBE:
		*result = pow(*result, 3.0);
		break;
	case SDR_SENSOR_L_SQRT:
		*result = sqrt(*result);
		break;
	case SDR_SENSOR_L_CUBERT:
		*result = cbrt(*result);
		break;
	case SDR_SENSOR_L_LINEAR:
	default:
		break;
	}
	return (0);
}
