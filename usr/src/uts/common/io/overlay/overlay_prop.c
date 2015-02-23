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
 * Copyright 2015, Joyent, Inc.
 */

/*
 * Routines for manipulating property information structures.
 *
 * For more information, see the big theory statement in
 * uts/common/io/overlay/overlay.c
 */

#include <sys/overlay_impl.h>

void
overlay_prop_init(overlay_prop_handle_t phdl)
{
	overlay_ioc_propinfo_t *infop = (overlay_ioc_propinfo_t *)phdl;
	mac_propval_range_t *rangep = (mac_propval_range_t *)infop->oipi_poss;

	infop->oipi_posssize = sizeof (mac_propval_range_t);
	bzero(rangep, sizeof (mac_propval_range_t));
}

void
overlay_prop_set_name(overlay_prop_handle_t phdl, const char *name)
{
	overlay_ioc_propinfo_t *infop = (overlay_ioc_propinfo_t *)phdl;
	(void) strlcpy(infop->oipi_name, name, OVERLAY_PROP_NAMELEN);
}

void
overlay_prop_set_prot(overlay_prop_handle_t phdl, overlay_prop_prot_t prot)
{
	overlay_ioc_propinfo_t *infop = (overlay_ioc_propinfo_t *)phdl;
	infop->oipi_prot = prot;
}

void
overlay_prop_set_type(overlay_prop_handle_t phdl, overlay_prop_type_t type)
{
	overlay_ioc_propinfo_t *infop = (overlay_ioc_propinfo_t *)phdl;
	infop->oipi_type = type;
}

int
overlay_prop_set_default(overlay_prop_handle_t phdl, void *def, ssize_t len)
{
	overlay_ioc_propinfo_t *infop = (overlay_ioc_propinfo_t *)phdl;

	if (len > OVERLAY_PROP_SIZEMAX)
		return (E2BIG);

	if (len < 0)
		return (EOVERFLOW);

	bcopy(def, infop->oipi_default, len);
	infop->oipi_defsize = (uint32_t)len;

	return (0);
}

void
overlay_prop_set_nodefault(overlay_prop_handle_t phdl)
{
	overlay_ioc_propinfo_t *infop = (overlay_ioc_propinfo_t *)phdl;
	infop->oipi_default[0] = '\0';
	infop->oipi_defsize = 0;
}

void
overlay_prop_set_range_uint32(overlay_prop_handle_t phdl, uint32_t min,
    uint32_t max)
{
	overlay_ioc_propinfo_t *infop = (overlay_ioc_propinfo_t *)phdl;
	mac_propval_range_t *rangep = (mac_propval_range_t *)infop->oipi_poss;

	if (rangep->mpr_count != 0 && rangep->mpr_type != MAC_PROPVAL_UINT32)
		return;

	if (infop->oipi_posssize + sizeof (mac_propval_uint32_range_t) >
	    sizeof (infop->oipi_poss))
		return;

	infop->oipi_posssize += sizeof (mac_propval_uint32_range_t);
	rangep->mpr_count++;
	rangep->mpr_type = MAC_PROPVAL_UINT32;
	rangep->u.mpr_uint32[rangep->mpr_count-1].mpur_min = min;
	rangep->u.mpr_uint32[rangep->mpr_count-1].mpur_max = max;
}

void
overlay_prop_set_range_str(overlay_prop_handle_t phdl, const char *str)
{
	size_t len = strlen(str) + 1; /* Account for a null terminator */
	overlay_ioc_propinfo_t *infop = (overlay_ioc_propinfo_t *)phdl;
	mac_propval_range_t *rangep = (mac_propval_range_t *)infop->oipi_poss;
	mac_propval_str_range_t *pstr = &rangep->u.mpr_str;

	if (rangep->mpr_count != 0 && rangep->mpr_type != MAC_PROPVAL_STR)
		return;

	if (infop->oipi_posssize + len > sizeof (infop->oipi_poss))
		return;

	rangep->mpr_count++;
	rangep->mpr_type = MAC_PROPVAL_STR;
	strlcpy((char *)&pstr->mpur_data[pstr->mpur_nextbyte], str,
	    sizeof (infop->oipi_poss) - infop->oipi_posssize);
	pstr->mpur_nextbyte += len;
	infop->oipi_posssize += len;
}
