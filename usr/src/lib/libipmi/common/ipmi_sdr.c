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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libipmi.h>
#include <stddef.h>
#include <string.h>

#include "ipmi_impl.h"

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
 * Refresh the cache of sensor data records.
 */
static int
ipmi_sdr_refresh(ipmi_handle_t *ihp)
{
	size_t len;
	uint16_t id;
	ipmi_sdr_t *sdr;
	ipmi_sdr_cache_ent_t *ent;
	ipmi_sdr_generic_locator_t *gen_src, *gen_dst;
	ipmi_sdr_fru_locator_t *fru_src, *fru_dst;

	ipmi_sdr_clear(ihp);

	/*
	 * Iterate over all existing SDRs and add them to the cache.
	 */
	id = IPMI_SDR_FIRST;
	while (id != IPMI_SDR_LAST) {
		if ((sdr = ipmi_sdr_get(ihp, id, &id)) == NULL)
			return (-1);

		/*
		 * We currently only understand FRU and generic device records.
		 */
		if (sdr->is_type != IPMI_SDR_TYPE_GENERIC_LOCATOR &&
		    sdr->is_type != IPMI_SDR_TYPE_FRU_LOCATOR)
			continue;

		/*
		 * Create a copy of the SDR-specific data.
		 */
		gen_dst = NULL;
		fru_dst = NULL;
		switch (sdr->is_type) {
		case IPMI_SDR_TYPE_GENERIC_LOCATOR:
			gen_src = (ipmi_sdr_generic_locator_t *)sdr->is_record;
			len = offsetof(ipmi_sdr_generic_locator_t,
			    is_gl_idstring) + gen_src->is_gl_idlen + 1;
			if ((gen_dst = ipmi_alloc(ihp, len)) == NULL)
				return (-1);
			(void) memcpy(gen_dst, gen_src, len - 1);
			((char *)gen_dst)[len - 1] = '\0';
			break;

		case IPMI_SDR_TYPE_FRU_LOCATOR:
			fru_src = (ipmi_sdr_fru_locator_t *)sdr->is_record;
			len = offsetof(ipmi_sdr_fru_locator_t,
			    is_fl_idstring) + fru_src->is_fl_idlen + 1;
			if ((fru_dst = ipmi_alloc(ihp, len)) == NULL)
				return (-1);
			(void) memcpy(fru_dst, fru_src, len - 1);
			((char *)fru_dst)[len - 1] = '\0';
			break;
		}

		if ((ent = ipmi_alloc(ihp,
		    sizeof (ipmi_sdr_cache_ent_t))) == NULL) {
			ipmi_free(ihp, gen_dst);
			ipmi_free(ihp, fru_dst);
			return (-1);
		}

		ent->isc_generic = gen_dst;
		ent->isc_fru = fru_dst;
		ent->isc_next = ihp->ih_sdr_cache;
		ent->isc_type = sdr->is_type;
		ihp->ih_sdr_cache = ent;
	}

	return (0);
}

void
ipmi_sdr_clear(ipmi_handle_t *ihp)
{
	ipmi_sdr_cache_ent_t *ent, *next;

	while ((ent = ihp->ih_sdr_cache) != NULL) {
		next = ent->isc_next;
		ipmi_free(ihp, ent->isc_generic);
		ipmi_free(ihp, ent->isc_fru);
		ipmi_free(ihp, ent);
		ihp->ih_sdr_cache = next;
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
		if ((rsp = ipmi_send(ihp, &cmd)) == NULL) {
			if (ipmi_errno(ihp) != EIPMI_INVALID_RESERVATION)
				return (NULL);

			if (ipmi_sdr_reserve_repository(ihp) != 0)
				return (NULL);
			req.ic_gs_resid = ihp->ih_reservation;
		}
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

ipmi_sdr_fru_locator_t *
ipmi_sdr_lookup_fru(ipmi_handle_t *ihp, const char *idstr)
{
	ipmi_sdr_cache_ent_t *ent;

	if (ihp->ih_sdr_cache == NULL &&
	    ipmi_sdr_refresh(ihp) != 0)
		return (NULL);

	for (ent = ihp->ih_sdr_cache; ent != NULL; ent = ent->isc_next) {
		if (ent->isc_type != IPMI_SDR_TYPE_FRU_LOCATOR)
			continue;

		if (strcmp(ent->isc_fru->is_fl_idstring, idstr) == 0)
			return (ent->isc_fru);
	}

	(void) ipmi_set_error(ihp, EIPMI_NOT_PRESENT, NULL);
	return (NULL);
}

ipmi_sdr_generic_locator_t *
ipmi_sdr_lookup_generic(ipmi_handle_t *ihp, const char *idstr)
{
	ipmi_sdr_cache_ent_t *ent;

	if (ihp->ih_sdr_cache == NULL &&
	    ipmi_sdr_refresh(ihp) != 0)
		return (NULL);

	for (ent = ihp->ih_sdr_cache; ent != NULL; ent = ent->isc_next) {
		if (ent->isc_type != IPMI_SDR_TYPE_GENERIC_LOCATOR)
			continue;

		if (strcmp(ent->isc_generic->is_gl_idstring, idstr) == 0)
			return (ent->isc_generic);
	}

	(void) ipmi_set_error(ihp, EIPMI_NOT_PRESENT, NULL);
	return (NULL);
}
