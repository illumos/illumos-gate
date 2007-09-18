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

/*
 * This utility constitutes a private interface - it will be removed
 * in a future release of Solaris.  Neither users nor other software
 * components can depend on the actions or existence of the utility.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/ethernet.h>
#include <libdlvnic.h>

/*ARGSUSED*/
static dladm_status_t
v_print(void *arg, dladm_vnic_attr_sys_t *attr)
{
	if (attr->va_mac_len != ETHERADDRL)
		return (DLADM_STATUS_OK);

	(void) printf("%d\t%s\t%s\n", attr->va_vnic_id, attr->va_dev_name,
	    ether_ntoa((struct ether_addr *)(attr->va_mac_addr)));

	return (DLADM_STATUS_OK);
}

static int
v_list(void)
{
	dladm_status_t status;

	status = dladm_vnic_walk_sys(v_print, NULL);

	if (status != DLADM_STATUS_OK)
		return (-1);

	return (0);
}

static dladm_status_t
v_find(void *arg, dladm_vnic_attr_sys_t *attr)
{
	dladm_vnic_attr_sys_t *specp = arg;

	if (strncmp(attr->va_dev_name, specp->va_dev_name,
	    strlen(attr->va_dev_name)) != 0)
		return (DLADM_STATUS_OK);

	if (attr->va_mac_len != specp->va_mac_len)
		return (DLADM_STATUS_OK);

	if (memcmp(attr->va_mac_addr, specp->va_mac_addr,
	    attr->va_mac_len) != 0)
		return (DLADM_STATUS_OK);

	specp->va_vnic_id = attr->va_vnic_id;

	return (DLADM_STATUS_EXIST);
}

static int
v_add(char *dev, char *addr)
{
	struct ether_addr *ea;
	dladm_vnic_attr_sys_t spec;
	uint_t vid;

	ea = ether_aton(addr);
	if (ea == NULL) {
		(void) fprintf(stderr, "Invalid ethernet address: %s\n",
		    addr);
		return (-1);
	}

	/*
	 * If a VNIC already exists over the specified device
	 * with this MAC address, use it.
	 */
	(void) strncpy(spec.va_dev_name, dev, sizeof (spec.va_dev_name) - 1);
	spec.va_mac_len = ETHERADDRL;
	(void) memcpy(spec.va_mac_addr, (uchar_t *)ea->ether_addr_octet,
	    spec.va_mac_len);

	if (dladm_vnic_walk_sys(v_find, &spec) == DLADM_STATUS_OK) {
		dladm_status_t status;

		/*
		 * None found, so create.
		 */
		status = dladm_vnic_create(0, dev, VNIC_MAC_ADDR_TYPE_FIXED,
		    (uchar_t *)ea->ether_addr_octet, ETHERADDRL,
		    &vid, DLADM_VNIC_OPT_TEMP | DLADM_VNIC_OPT_AUTOID);
		if (status != DLADM_STATUS_OK) {
			char buf[DLADM_STRSIZE];

			(void) fprintf(stderr, "dladm_vnic_create: %s\n",
			    dladm_status2str(status, buf));
			return (-1);
		}
	} else {
		vid = spec.va_vnic_id;
	}

	(void) printf("%d\n", vid);

	return (0);
}

static int
v_remove(char *vdev)
{
	uint_t vid;
	dladm_status_t status;

	vid = atoi(vdev);

	status = dladm_vnic_delete(vid, DLADM_VNIC_OPT_TEMP);

	if (status != DLADM_STATUS_OK) {
		char buf[DLADM_STRSIZE];

		(void) fprintf(stderr, "dladm_vnic_delete: %s\n",
		    dladm_status2str(status, buf));
		return (-1);
	}

	return (0);
}

int
main(int argc, char *argv[])
{
	switch (argc) {
	case 1:
		/* List operation. */
		return (v_list());
		/* NOTREACHED */
	case 2:
		/* Remove operation. */
		return (v_remove(argv[1]));
		/* NOTREACHED */
	case 3:
		/* Add operation. */
		return (v_add(argv[1], argv[2]));
		/* NOTREACHED */
	default:
		(void) fprintf(stderr, "Incorrect number of arguments - "
		    "must have 0, 1 or 2.\n");
		return (-1);
		/* NOTREACHED */
	}

	/* NOTREACHED */
}
