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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright 2019 Joyent, Inc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <libnvpair.h>
#include <sys/types.h>
#include <libipmi.h>
#include <fm/topo_mod.h>
#include <ctype.h>
#include "chip.h"

#define	BUFSZ	128
#define	JEDEC_TBL_SZ	5

/*
 * The following table maps DIMM manufacturer names to a JEDEC ID as sourced
 * from JEDEC publication JEP106W.  This is (obviously) a sparse table which
 * only contains entries for manufacturers whose DIMM's have been qualified
 * for use on Sun platforms.
 */
static const char *jedec_tbl[JEDEC_TBL_SZ][2] =
{
	{ "HYUNDAI ELECTRONICS", "00AD" },
	{ "INFINEON", "00C1" },
	{ "MICRON TECHNOLOGY", "002C" },
	{ "QIMONDA", "7F51" },
	{ "SAMSUNG", "00CE" },
};

static int
ipmi_serial_lookup(topo_mod_t *mod, char *ipmi_tag, char *buf)
{
	char *fru_data;
	int i, found_id = 0, serial_len;
	ipmi_handle_t *hdl;
	ipmi_sdr_fru_locator_t *fru_loc;
	ipmi_fru_prod_info_t prod_info;

	topo_mod_dprintf(mod, "ipmi_serial_lookup() called\n");
	if ((hdl = topo_mod_ipmi_hold(mod)) == NULL) {
		topo_mod_dprintf(mod, "Failed to get IPMI handle\n");
		return (topo_mod_seterrno(mod, EMOD_UNKNOWN));
	}

	topo_mod_dprintf(mod, "Looking up FRU data for %s ...\n", ipmi_tag);
	if ((fru_loc = ipmi_sdr_lookup_fru(hdl, (const char *)ipmi_tag))
	    == NULL) {
		topo_mod_dprintf(mod, "Failed to lookup %s (%s)\n", ipmi_tag,
		    ipmi_errmsg(hdl));
		topo_mod_ipmi_rele(mod);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}


	topo_mod_dprintf(mod, "Reading FRU data ...\n");
	if (ipmi_fru_read(hdl, fru_loc, &fru_data) < 0) {
		topo_mod_dprintf(mod, "Failed to read FRU data (%s)\n",
		    ipmi_errmsg(hdl));
		topo_mod_ipmi_rele(mod);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	topo_mod_dprintf(mod, "Parsing product info area ...\n");
	if (ipmi_fru_parse_product(hdl, fru_data, &prod_info) < 0) {
		topo_mod_dprintf(mod, "Failed to read FRU product info (%s)\n",
		    ipmi_errmsg(hdl));
		free(fru_data);
		topo_mod_ipmi_rele(mod);
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}
	free(fru_data);
	topo_mod_ipmi_rele(mod);

	topo_mod_dprintf(mod, "FRU Product Serial: %s\n",
	    prod_info.ifpi_product_serial);
	topo_mod_dprintf(mod, "Manufacturer Name: \"%s\"\n",
	    prod_info.ifpi_manuf_name);

	serial_len = strnlen(prod_info.ifpi_product_serial, FRU_INFO_MAXLEN);

	/*
	 * Newer ILOM software that has the fix for CR 6607996 will have
	 * an 18-character serial number that has been synthesized using
	 * the recipe from the Sun SPD JEDEC DIMM specification.  If we
	 * find an 18-character then we'll simply use it, as-is, and
	 * return.
	 */
	if (serial_len == 18) {
		(void) memcpy(buf, prod_info.ifpi_product_serial, 18);
		*(buf+18) = '\0';
		return (0);
	}
	/*
	 * Older ILOM software that DOESN'T have the fix for CR 6607996 will
	 * only provide the 8 character manufacturer serial number.
	 *
	 * However, if for some reason the product info area doesn't have the
	 * serial information or if the serial isn't 8 characters (we may
	 * encounter SP's that don't populate the serial field or are buggy and
	 * populate it with garbage), then we'll stop right now and just set the
	 * buf to an empty string.
	 */
	if (serial_len != 8) {
		*buf = '\0';
		return (0);
	}

	/*
	 * What follows is a very crude adaptation of the recipe from the
	 * Sun SPD JEDEC DIMM specification for synthesizing globally unique
	 * serial numbers from the 8 character manufacturer serial number.
	 *
	 * The Sun serial number takes the following form:
	 *
	 * jjjjllyywwssssssss
	 *
	 * The components are:
	 *
	 * yyyy: JEDEC ID in hex (2 byte manufacture ID, 2 byte continuation
	 *	code).
	 *
	 * ll:   The memory module's manufacturing location.
	 *
	 * yyww: The module's manufacturing date (2-digit year/2-digit week)
	 *
	 * ssssssss: The 8 character maufacturer serial number
	 */
	/*
	 * First we need to normalize the manufacturer name we pulled out of
	 * the FRU product info area.  Our normalization algorithm is fairly
	 * simple:
	 *   - convert all alpha chars to uppercase
	 *   - convert non-alphanumeric characters to a single space
	 *
	 * We use the normalized name to lookup the JEDEC ID from a static
	 * table.  If the FRU area didn't have a manufacturer name or if the ID
	 * lookup fails we'll set jjjj to 0000.
	 */
	for (i = 0; prod_info.ifpi_manuf_name[i]; i++) {
		prod_info.ifpi_manuf_name[i] =
		    toupper(prod_info.ifpi_manuf_name[i]);
		if (!isalpha(prod_info.ifpi_manuf_name[i]) &&
		    !isdigit(prod_info.ifpi_manuf_name[i]))
			prod_info.ifpi_manuf_name[i] = (char)0x20;
	}
	topo_mod_dprintf(mod, "Normalized Manufacturer Name \"%s\"\n",
	    prod_info.ifpi_manuf_name);

	for (i = 0; i < JEDEC_TBL_SZ; i++)
		if (strcmp(prod_info.ifpi_manuf_name, jedec_tbl[i][0]) == 0) {
			found_id = 1;
			break;
		}

	if (found_id)
		(void) memcpy(buf, jedec_tbl[i][1], 4);
	else
		(void) memcpy(buf, (char *)("0000"), 4);

	/*
	 * The manufacturing location and date is not available via IPMI on
	 * Sun platforms, so we simply set these six digits to zeros.
	 */
	(void) memcpy((buf+4), (char *)("000000"), 6);

	/*
	 * Finally, we just copy the 8 character product serial straight over
	 * and then NULL terminate the string.
	 */
	(void) memcpy((buf+10), prod_info.ifpi_product_serial, 8);
	*(buf+18) = '\0';

	return (0);
}

/* ARGSUSED */
int
get_dimm_serial(topo_mod_t *mod, tnode_t *node, topo_version_t vers,
    nvlist_t *in, nvlist_t **out)
{
	char **entity_refs, fru_serial[FRU_INFO_MAXLEN];
	int err, rv = 0, i;
	uint_t nelems;
	boolean_t found_serial = B_FALSE;

	if (topo_prop_get_string_array(node, TOPO_PGROUP_IPMI, "entity_ref",
	    &entity_refs, &nelems, &err) != 0) {
		topo_mod_dprintf(mod, "%s: Failed to lookup entity_ref property"
		    " (%s)", __func__, topo_strerror(err));
		return (topo_mod_seterrno(mod, EMOD_NVL_INVAL));
	}

	for (i = 0; i < nelems; i++) {
		if (ipmi_serial_lookup(mod, entity_refs[i], fru_serial) == 0) {
			found_serial = B_TRUE;
			break;
		} else
			topo_mod_dprintf(mod, "Failed to lookup serial for "
			    "%s\n", entity_refs[i]);
	}
	if (! found_serial)
		(void) strcpy(fru_serial, "");

	if (store_prop_val(mod, fru_serial, "serial", out) != 0) {
		topo_mod_dprintf(mod, "Failed to set serial\n");
		/* topo errno already set */
		rv = -1;
	}
	topo_mod_strfreev(mod, entity_refs, nelems);

	return (rv);
}
