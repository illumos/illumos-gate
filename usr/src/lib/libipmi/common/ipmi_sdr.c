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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libipmi.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

#include "ipmi_impl.h"

typedef struct ipmi_sdr_cache_ent {
	char				*isc_name;
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

	cmd.ic_netfn = IPMI_NETFN_STORAGE;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_GET_SDR_INFO;
	cmd.ic_dlen = 0;
	cmd.ic_data = NULL;

	if ((rsp = ipmi_send(ihp, &cmd)) == NULL)
		return (NULL);

	sip = rsp->ic_data;

	sip->isi_record_count = LE_IN16(&sip->isi_record_count);
	sip->isi_free_space = LE_IN16(&sip->isi_free_space);
	sip->isi_add_ts = LE_IN32(&sip->isi_add_ts);
	sip->isi_erase_ts = LE_IN32(&sip->isi_erase_ts);

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
	size_t namelen, len;
	uint8_t type;
	char *name;
	ipmi_sdr_info_t *sip;

	if ((sip = ipmi_sdr_get_info(ihp)) == NULL)
		return (-1);

	if (sip->isi_add_ts <= ihp->ih_sdr_ts &&
	    sip->isi_erase_ts <= ihp->ih_sdr_ts &&
	    ipmi_hash_first(ihp->ih_sdr_cache) != NULL)
		return (0);

	ipmi_sdr_clear(ihp);
	ipmi_entity_clear(ihp);
	ihp->ih_sdr_ts = MAX(sip->isi_add_ts, sip->isi_erase_ts);

	/*
	 * Iterate over all existing SDRs and add them to the cache.
	 */
	id = IPMI_SDR_FIRST;
	while (id != IPMI_SDR_LAST) {
		if ((sdr = ipmi_sdr_get(ihp, id, &id)) == NULL)
			return (-1);

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
				break;
			}

		case IPMI_SDR_TYPE_COMPACT_SENSOR:
			{
				ipmi_sdr_compact_sensor_t *csp =
				    (ipmi_sdr_compact_sensor_t *)
				    sdr->is_record;
				namelen = csp->is_cs_idlen;
				type = csp->is_cs_idtype;
				name = csp->is_cs_idstring;

				csp->is_cs_assert_mask =
				    LE_IN16(&csp->is_cs_assert_mask);
				csp->is_cs_deassert_mask =
				    LE_IN16(&csp->is_cs_deassert_mask);
				csp->is_cs_reading_mask =
				    LE_IN16(&csp->is_cs_reading_mask);
				break;
			}

		case IPMI_SDR_TYPE_FULL_SENSOR:
			{
				ipmi_sdr_full_sensor_t *csp =
				    (ipmi_sdr_full_sensor_t *)
				    sdr->is_record;
				namelen = csp->is_fs_idlen;
				type = csp->is_fs_idtype;
				name = csp->is_fs_idstring;

				csp->is_fs_assert_mask =
				    LE_IN16(&csp->is_fs_assert_mask);
				csp->is_fs_deassert_mask =
				    LE_IN16(&csp->is_fs_deassert_mask);
				csp->is_fs_reading_mask =
				    LE_IN16(&csp->is_fs_reading_mask);
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
				break;
			}

		case IPMI_SDR_TYPE_MANAGEMENT_CONFIRMATION:
			{
				ipmi_sdr_management_confirmation_t *mcp =
				    (ipmi_sdr_management_confirmation_t *)
				    sdr->is_record;
				name = NULL;
				mcp->is_mc_product =
				    LE_IN16(&mcp->is_mc_product);
				break;
			}

		default:
			name = NULL;
		}

		if ((ent = ipmi_zalloc(ihp,
		    sizeof (ipmi_sdr_cache_ent_t))) == NULL)
			return (-1);

		len = sdr->is_length + offsetof(ipmi_sdr_t, is_record);
		if ((ent->isc_sdr = ipmi_alloc(ihp, len)) == NULL) {
			ipmi_free(ihp, ent);
			return (-1);
		}
		bcopy(sdr, ent->isc_sdr, len);

		if (name != NULL) {
			if ((ent->isc_name = ipmi_alloc(ihp, namelen + 1)) ==
			    NULL) {
				ipmi_free(ihp, ent->isc_sdr);
				ipmi_free(ihp, ent);
				return (-1);
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
	 * While it is strange for a service processor to report multiple
	 * entries with the same name, we allow it by treating the (name, id)
	 * as the unique identifier.  When looking up by name, the SDR pointer
	 * is NULL, and we return the first matching name.
	 */
	if (ap->isc_sdr == NULL || bp->isc_sdr == NULL)
		return (0);

	if (ap->isc_sdr->is_id == bp->isc_sdr->is_id)
		return (0);
	else
		return (-1);
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
	ipmi_cmd_t cmd, *rsp;
	ipmi_cmd_get_sdr_t req;
	ipmi_rsp_get_sdr_t *sdr;
	int i;

	req.ic_gs_resid = ihp->ih_reservation;
	req.ic_gs_recid = id;
	req.ic_gs_offset = 0;
	req.ic_gs_len = 0xFF;

	cmd.ic_netfn = IPMI_NETFN_STORAGE;
	cmd.ic_lun = 0;
	cmd.ic_cmd = IPMI_CMD_GET_SDR;
	cmd.ic_dlen = sizeof (req);
	cmd.ic_data = &req;

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

	if (rsp->ic_dlen < sizeof (uint16_t) + sizeof (ipmi_sdr_t)) {
		(void) ipmi_set_error(ihp, EIPMI_BAD_RESPONSE_LENGTH, NULL);
		return (NULL);
	}

	sdr = rsp->ic_data;
	*next = sdr->ir_gs_next;

	return ((ipmi_sdr_t *)sdr->ir_gs_record);
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
	ipmi_sdr_cache_ent_t *ent, search;

	if (ipmi_hash_first(ihp->ih_sdr_cache) == NULL &&
	    ipmi_sdr_refresh(ihp) != 0)
		return (NULL);

	search.isc_name = (char *)idstr;
	search.isc_sdr = NULL;
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
