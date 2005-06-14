/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <picl.h>
#include <picldefs.h>
#include "fru_access_impl.h"

#define	SNOWBIRD		"SUNW,Netra-CP2300"

/*
 * check if the code is running on correct chassis or not.
 * return :
 *		0	- if we are on Snowbird
 *		-1	- if we are on wrong system
 *			  if there is any error
 */
int
fruaccess_platmod_check_chassis()
{
	picl_nodehdl_t chassish;
	char chassis_type[PICL_PROPNAMELEN_MAX];

	if (ptree_get_node_by_path(PICL_FRUTREE_CHASSIS,
		&chassish) != PICL_SUCCESS) {
		return (-1);
	}

	if (ptree_get_propval_by_name(chassish, PICL_PROP_CHASSIS_TYPE,
		chassis_type, sizeof (chassis_type)) != PICL_SUCCESS) {
		return (-1);
	}

	if (strcmp(chassis_type, SNOWBIRD) == 0) {
		return (0);
	} else {
		return (-1);
	}
}

/*
 * intialize the format structure, fill in src and dest addresses
 */
picl_errno_t
fruaccess_platmod_init_format(uint8_t slot_no, format_t *fru_format)
{
	/* initialize src and dest addresses */
	fru_format->src = IPMB_ADDR(slot_no);
	fru_format->dest = fru_format->src;
	return (PICL_SUCCESS);
}

/*
 * do all valid checks for fru
 * return :	0 if we can probe for fru
 *		-1 if probing is not required
 */
int
fruaccess_platmod_check_fru(picl_nodehdl_t parenth)
{
	int retval;
	char type[PICL_PROPSIZE_MAX];
	picl_nodehdl_t chassish, loc_parenth;

	retval = ptree_get_propval_by_name(parenth, PICL_PROP_SLOT_TYPE,
		(void *)type, PICL_PROPSIZE_MAX);
	if (retval != PICL_SUCCESS) {
		return (-1);
	}

	/* check only for pci and cpci slots */
	if ((strcmp(type, PICL_SLOT_CPCI) != 0) &&
		(strcmp(type, PICL_SLOT_PCI) != 0)) {
		return (-1);
	}

	/* check if location is direct parent of chassis or not */
	if (ptree_get_node_by_path(PICL_FRUTREE_CHASSIS,
		&chassish) != PICL_SUCCESS) {
		return (-1);
	}

	retval = ptree_get_propval_by_name(parenth, PICL_PROP_PARENT,
		(void *)&loc_parenth, sizeof (loc_parenth));
	if (retval != PICL_SUCCESS) {
		return (-1);
	}

	if (chassish != loc_parenth) {
		return (-1);
	}
	return (0);
}
