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

/*
 * This utility constitutes a private interface - it will be removed
 * in a future release of Solaris.  Neither users nor other software
 * components can depend on the actions or existence of the utility.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ethernet.h>
#include <libdllink.h>
#include <libdlvnic.h>
#include <libdlpi.h>

typedef struct vnic_attr {
	dladm_vnic_attr_sys_t attr;
	char *name;
} vnic_attr_t;

/*ARGSUSED*/
static int
v_print(datalink_id_t vnic_id, void *arg)
{
	dladm_vnic_attr_sys_t attr;
	char vnic[MAXLINKNAMELEN];
	char link[MAXLINKNAMELEN];

	if (dladm_vnic_info(vnic_id, &attr, DLADM_OPT_ACTIVE) !=
	    DLADM_STATUS_OK) {
		return (DLADM_WALK_CONTINUE);
	}

	if (attr.va_mac_len != ETHERADDRL)
		return (DLADM_WALK_CONTINUE);

	if (dladm_datalink_id2info(vnic_id, NULL, NULL, NULL, vnic,
	    sizeof (vnic)) != DLADM_STATUS_OK) {
		return (DLADM_WALK_CONTINUE);
	}

	if (dladm_datalink_id2info(attr.va_link_id, NULL, NULL, NULL, link,
	    sizeof (link)) != DLADM_STATUS_OK) {
		return (DLADM_WALK_CONTINUE);
	}

	(void) printf("%s\t%s\t%s\n", vnic, link,
	    ether_ntoa((struct ether_addr *)(attr.va_mac_addr)));

	return (DLADM_WALK_CONTINUE);
}

static void
v_list(void)
{
	(void) dladm_walk_datalink_id(v_print, NULL, DATALINK_CLASS_VNIC,
	    DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
}

static int
v_find(datalink_id_t vnic_id, void *arg)
{
	vnic_attr_t *vattr = arg;
	dladm_vnic_attr_sys_t *specp = &vattr->attr;
	dladm_vnic_attr_sys_t attr;
	char linkname[MAXLINKNAMELEN];

	if (dladm_vnic_info(vnic_id, &attr, DLADM_OPT_ACTIVE) !=
	    DLADM_STATUS_OK) {
		return (DLADM_WALK_CONTINUE);
	}

	if (attr.va_link_id != specp->va_link_id)
		return (DLADM_WALK_CONTINUE);

	if (attr.va_mac_len != specp->va_mac_len)
		return (DLADM_WALK_CONTINUE);

	if (memcmp(attr.va_mac_addr, specp->va_mac_addr,
	    attr.va_mac_len) != 0) {
		return (DLADM_WALK_CONTINUE);
	}

	if (vattr->name != NULL) {
		/* Names must match. */
		if (dladm_datalink_id2info(vnic_id, NULL, NULL, NULL, linkname,
		    sizeof (linkname)) != DLADM_STATUS_OK) {
			return (DLADM_WALK_CONTINUE);
		}

		if (strcmp(vattr->name, linkname) != 0)
			return (DLADM_WALK_CONTINUE);
	}

	specp->va_vnic_id = attr.va_vnic_id;

	return (DLADM_WALK_TERMINATE);
}

#define	ETHERTYPE_LOOPBACK	(0x9000)	/* loopback packet */

/*
 * Broadcasst a loopback ethernet packet via "link"
 */
static int
v_broadcast(char *link)
{
	int rval;
	dlpi_handle_t dh;
	dlpi_info_t dlinfo;
	struct ether_header eh;

	if ((rval = dlpi_open(link, &dh, DLPI_RAW)) != DLPI_SUCCESS) {
		(void) fprintf(stderr,
		    "dlpi_open failed, link name: %s, err=%d\n", link, rval);
		return (-1);
	}

	if ((rval = dlpi_bind(dh, DLPI_ANY_SAP, NULL)) != DLPI_SUCCESS) {
		(void) fprintf(stderr, "dlpi_bind failed, err=%d\n", rval);
		dlpi_close(dh);
		return (-1);
	}

	if ((rval = dlpi_info(dh, &dlinfo, 0)) != DLPI_SUCCESS) {
		(void) fprintf(stderr, "dlpi_info failed, err=%d\n", rval);
		dlpi_close(dh);
		return (-1);
	}

	if (dlinfo.di_bcastaddrlen == 0) {
		(void) fprintf(stderr,
		    "no broadcast address for link: %s\n", link);
		dlpi_close(dh);
		return (-1);
	}

	(void) memcpy(&eh.ether_dhost, dlinfo.di_bcastaddr, ETHERADDRL);
	(void) memcpy(&eh.ether_shost, dlinfo.di_physaddr, ETHERADDRL);
	eh.ether_type = htons(ETHERTYPE_LOOPBACK);

	rval = dlpi_send(dh, NULL, 0, &eh, sizeof (struct ether_header), NULL);
	if (rval != DLPI_SUCCESS) {
		(void) fprintf(stderr, "dlpi_send failed, err=%d\n", rval);
		dlpi_close(dh);
		return (-1);
	}

	dlpi_close(dh);
	return (0);
}

/*
 * Print out the link name of the VNIC.
 */
static int
v_add(char *link, char *addr, char *name)
{
	struct ether_addr *ea;
	vnic_attr_t vattr;
	datalink_id_t vnic_id, linkid;
	char vnic[MAXLINKNAMELEN];
	dladm_status_t status;
	char buf[DLADM_STRSIZE];
	boolean_t created = B_FALSE;

	ea = ether_aton(addr);
	if (ea == NULL) {
		(void) fprintf(stderr, "Invalid ethernet address: %s\n", addr);
		return (-1);
	}

	if (dladm_name2info(link, &linkid, NULL, NULL, NULL) !=
	    DLADM_STATUS_OK) {
		(void) fprintf(stderr, "Invalid link name: %s\n", link);
		return (-1);
	}

	/*
	 * If a VNIC already exists over the specified link
	 * with this MAC address and name, use it.
	 */
	vattr.attr.va_vnic_id = DATALINK_INVALID_LINKID;
	vattr.attr.va_link_id = linkid;
	vattr.attr.va_mac_len = ETHERADDRL;
	(void) memcpy(vattr.attr.va_mac_addr, (uchar_t *)ea->ether_addr_octet,
	    vattr.attr.va_mac_len);
	vattr.name = name;

	(void) dladm_walk_datalink_id(v_find, &vattr, DATALINK_CLASS_VNIC,
	    DATALINK_ANY_MEDIATYPE, DLADM_OPT_ACTIVE);
	if (vattr.attr.va_vnic_id == DATALINK_INVALID_LINKID) {
		/*
		 * None found, so create.
		 */
		status = dladm_vnic_create(name, linkid,
		    VNIC_MAC_ADDR_TYPE_FIXED, (uchar_t *)ea->ether_addr_octet,
		    ETHERADDRL, &vnic_id, DLADM_OPT_ACTIVE);
		if (status != DLADM_STATUS_OK) {
			(void) fprintf(stderr, "dladm_vnic_create: %s\n",
			    dladm_status2str(status, buf));
			return (-1);
		}
		created = B_TRUE;
	} else {
		vnic_id = vattr.attr.va_vnic_id;
	}

	if ((status = dladm_datalink_id2info(vnic_id, NULL, NULL, NULL, vnic,
	    sizeof (vnic))) != DLADM_STATUS_OK) {
		(void) fprintf(stderr, "dladm_datalink_id2info: %s\n",
		    dladm_status2str(status, buf));
		if (vattr.attr.va_vnic_id == DATALINK_INVALID_LINKID)
			(void) dladm_vnic_delete(vnic_id, DLADM_OPT_ACTIVE);
		return (-1);
	}

	/*
	 * Before we hand this newly created vnic over to caller, we want to
	 * broadcast its MAC address to make sure that the <MAC,port> mapping
	 * in the switch is correct.
	 */
	if (created)
		(void) v_broadcast(vnic);

	(void) printf("%s\n", vnic);

	return (0);
}

/*
 * v_remove() takes VNIC link name as the argument.
 */
static int
v_remove(char *vnic)
{
	datalink_id_t vnic_id;
	dladm_status_t status;
	char buf[DLADM_STRSIZE];

	if ((status = dladm_name2info(vnic, &vnic_id, NULL, NULL, NULL)) !=
	    DLADM_STATUS_OK) {
		(void) fprintf(stderr, "dladm_name2info: %s\n",
		    dladm_status2str(status, buf));
		return (-1);
	}

	status = dladm_vnic_delete(vnic_id, DLADM_OPT_ACTIVE);

	if (status != DLADM_STATUS_OK) {
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
		v_list();
		return (0);
		/* NOTREACHED */
	case 2:
		/* Remove operation. */
		return (v_remove(argv[1]));
		/* NOTREACHED */
	case 3:
	case 4:
		/* Add operation. */
		return (v_add(argv[1], argv[2], (argc == 3 ? NULL : argv[3])));
		/* NOTREACHED */
	default:
		(void) fprintf(stderr, "Incorrect number of arguments - "
		    "must have 0, 1, 2 or 3.\n");
		return (-1);
		/* NOTREACHED */
	}

	/* NOTREACHED */
}
