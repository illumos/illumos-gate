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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <libintl.h>
#include <net/if_types.h>
#include <net/if_dl.h>
#include <libdladm_impl.h>
#include <libdllink.h>
#include <libdlvnic.h>

/*
 * VNIC administration library.
 */

#define	VNIC_DEV	"/devices/pseudo/vnic@0:" VNIC_CTL_NODE_NAME

/* Limits on buffer size for VNIC_IOC_INFO request */
#define	MIN_INFO_SIZE (4*1024)
#define	MAX_INFO_SIZE (128*1024)

/* configuration database entry */
typedef struct dladm_vnic_attr_db {
	datalink_id_t	vt_vnic_id;
	datalink_id_t	vt_link_id;
	vnic_mac_addr_type_t vt_mac_addr_type;
	uint_t		vt_mac_len;
	uchar_t		vt_mac_addr[MAXMACADDRLEN];
} dladm_vnic_attr_db_t;

typedef struct dladm_vnic_modify_attr {
	vnic_mac_addr_type_t	vm_mac_addr_type;
	int			vm_mac_len;
	uchar_t			vm_mac_addr[MAXMACADDRLEN];
} dladm_vnic_modify_attr_t;

/*
 * Send a create command to the VNIC driver.
 */
static dladm_status_t
i_dladm_vnic_create_sys(int fd, dladm_vnic_attr_db_t *attr)
{
	int rc;
	vnic_ioc_create_t ioc;

	ioc.vc_vnic_id = attr->vt_vnic_id;
	ioc.vc_link_id = attr->vt_link_id;
	ioc.vc_mac_addr_type = attr->vt_mac_addr_type;
	ioc.vc_mac_len = attr->vt_mac_len;
	bcopy(attr->vt_mac_addr, ioc.vc_mac_addr, attr->vt_mac_len);

	rc = i_dladm_ioctl(fd, VNIC_IOC_CREATE, &ioc, sizeof (ioc));

	if (rc < 0)
		return (dladm_errno2status(errno));

	return (DLADM_STATUS_OK);
}

/*
 * Send a modify command to the VNIC driver.
 */
static dladm_status_t
i_dladm_vnic_modify_sys(datalink_id_t vnic_id, uint32_t modify_mask,
    dladm_vnic_modify_attr_t *attr)
{
	int rc;
	int fd;
	vnic_ioc_modify_t ioc;

	ioc.vm_vnic_id = vnic_id;

	ioc.vm_modify_mask = 0;
	if (modify_mask & DLADM_VNIC_MODIFY_ADDR)
		ioc.vm_modify_mask |= VNIC_IOC_MODIFY_ADDR;

	ioc.vm_mac_addr_type = attr->vm_mac_addr_type;
	ioc.vm_mac_len = attr->vm_mac_len;
	bcopy(attr->vm_mac_addr, ioc.vm_mac_addr, MAXMACADDRLEN);

	if ((fd = open(VNIC_DEV, O_RDWR)) < 0)
		return (dladm_errno2status(errno));

	rc = i_dladm_ioctl(fd, VNIC_IOC_MODIFY, &ioc, sizeof (ioc));

	(void) close(fd);

	if (rc < 0)
		return (dladm_errno2status(errno));

	return (DLADM_STATUS_OK);
}

/*
 * Get the configuration information of the given VNIC.
 */
dladm_status_t
dladm_vnic_info(datalink_id_t vnic_id, dladm_vnic_attr_sys_t *attrp,
    uint32_t flags)
{
	vnic_ioc_info_t *ioc;
	vnic_ioc_info_vnic_t *vnic;
	int rc, bufsize, fd;
	dladm_status_t status = DLADM_STATUS_OK;

	/* for now, only temporary creations are supported */
	if (flags & DLADM_OPT_PERSIST)
		return (dladm_errno2status(ENOTSUP));

	if ((fd = open(VNIC_DEV, O_RDWR)) == -1)
		return (dladm_errno2status(errno));

	bufsize = sizeof (vnic_ioc_info_t) + sizeof (vnic_ioc_info_vnic_t);
	ioc = (vnic_ioc_info_t *)calloc(1, bufsize);
	if (ioc == NULL) {
		(void) close(fd);
		return (dladm_errno2status(ENOMEM));
	}

	ioc->vi_vnic_id = vnic_id;
	rc = i_dladm_ioctl(fd, VNIC_IOC_INFO, ioc, bufsize);
	if (rc != 0) {
		status = dladm_errno2status(errno);
		goto bail;
	}

	vnic = (vnic_ioc_info_vnic_t *)(ioc + 1);

	attrp->va_vnic_id = vnic->vn_vnic_id;
	attrp->va_link_id = vnic->vn_link_id;
	attrp->va_mac_addr_type = vnic->vn_mac_addr_type;
	bcopy(vnic->vn_mac_addr, attrp->va_mac_addr, ETHERADDRL);
	attrp->va_mac_len = vnic->vn_mac_len;

bail:
	free(ioc);
	(void) close(fd);
	return (status);
}

/*
 * Remove a VNIC from the kernel.
 */
static dladm_status_t
i_dladm_vnic_delete_sys(int fd, dladm_vnic_attr_sys_t *attr)
{
	vnic_ioc_delete_t ioc;
	int rc;

	ioc.vd_vnic_id = attr->va_vnic_id;

	rc = i_dladm_ioctl(fd, VNIC_IOC_DELETE, &ioc, sizeof (ioc));

	if (rc < 0)
		return (dladm_errno2status(errno));

	return (DLADM_STATUS_OK);
}

/*
 * Convert between MAC address types and their string representations.
 */

typedef struct dladm_vnic_addr_type_s {
	char *va_str;
	vnic_mac_addr_type_t va_type;
} dladm_vnic_addr_type_t;

static dladm_vnic_addr_type_t addr_types[] = {
	{"fixed", VNIC_MAC_ADDR_TYPE_FIXED},
};

#define	NADDR_TYPES (sizeof (addr_types) / sizeof (dladm_vnic_addr_type_t))

/*
 * Return DLADM_STATUS_OK if a matching type was found,
 * DLADM_STATUS_BADARG otherwise
 */
dladm_status_t
dladm_vnic_str2macaddrtype(const char *str, vnic_mac_addr_type_t *val)
{
	int i;
	dladm_vnic_addr_type_t *type;

	for (i = 0; i < NADDR_TYPES; i++) {
		type = &addr_types[i];
		if (strncmp(str, type->va_str, strlen(type->va_str)) == 0) {
			*val = type->va_type;
			return (DLADM_STATUS_OK);
		}
	}

	return (DLADM_STATUS_BADARG);
}

/*
 * Create a new VNIC. Update the configuration file and bring it up.
 */
dladm_status_t
dladm_vnic_create(const char *vnic, datalink_id_t linkid,
    vnic_mac_addr_type_t mac_addr_type, uchar_t *mac_addr, int mac_len,
    datalink_id_t *vnic_id_out, uint32_t flags)
{
	dladm_vnic_attr_db_t attr;
	int i, fd;
	datalink_id_t vnic_id;
	datalink_class_t class;
	uint32_t media;
	char *name = (char *)vnic;
	dladm_status_t status;

	/*
	 * Sanity test arguments.
	 */
	if (flags & DLADM_OPT_PERSIST)
		return (dladm_errno2status(ENOTSUP));

	if (mac_len > MAXMACADDRLEN)
		return (DLADM_STATUS_INVALIDMACADDRLEN);

	for (i = 0; i < NADDR_TYPES; i++) {
		if (mac_addr_type == addr_types[i].va_type)
			break;
	}
	if (i == NADDR_TYPES)
		return (DLADM_STATUS_INVALIDMACADDRTYPE);

	if ((status = dladm_datalink_id2info(linkid, NULL, &class, &media,
	    NULL, 0)) != DLADM_STATUS_OK) {
		return (status);
	}

	if (class == DATALINK_CLASS_VNIC)
		return (DLADM_STATUS_BADARG);

	if (vnic == NULL) {
		flags |= DLADM_OPT_PREFIX;
		name = "vnic";
	}

	if ((status = dladm_create_datalink_id(name, DATALINK_CLASS_VNIC,
	    media, flags, &vnic_id)) != DLADM_STATUS_OK) {
		return (status);
	}

	bzero(&attr, sizeof (attr));
	attr.vt_vnic_id = vnic_id;
	attr.vt_link_id = linkid;
	attr.vt_mac_addr_type = mac_addr_type;
	attr.vt_mac_len = mac_len;
	bcopy(mac_addr, attr.vt_mac_addr, mac_len);

	if ((fd = open(VNIC_DEV, O_RDWR)) < 0) {
		status = dladm_errno2status(errno);
		goto done;
	}

	status = i_dladm_vnic_create_sys(fd, &attr);
	(void) close(fd);

done:
	if (status != DLADM_STATUS_OK) {
		(void) dladm_destroy_datalink_id(vnic_id,
		    flags & ~DLADM_OPT_PREFIX);
	} else {
		*vnic_id_out = vnic_id;
	}

	return (status);
}

/*
 * Modify the properties of a VNIC.
 */
dladm_status_t
dladm_vnic_modify(datalink_id_t vnic_id, uint32_t modify_mask,
    vnic_mac_addr_type_t mac_addr_type, uint_t mac_len, uchar_t *mac_addr,
    uint32_t flags)
{
	dladm_vnic_modify_attr_t new_attr;

	/* for now, only temporary creations are supported */
	if (flags & DLADM_OPT_PERSIST)
		return (dladm_errno2status(ENOTSUP));

	bzero(&new_attr, sizeof (new_attr));

	if (modify_mask & DLADM_VNIC_MODIFY_ADDR) {
		new_attr.vm_mac_addr_type = mac_addr_type;
		new_attr.vm_mac_len = mac_len;
		bcopy(mac_addr, new_attr.vm_mac_addr, MAXMACADDRLEN);
	}

	/* update the properties of the existing VNIC */
	return (i_dladm_vnic_modify_sys(vnic_id, modify_mask, &new_attr));
}

/*
 * Delete a VNIC.
 */
dladm_status_t
dladm_vnic_delete(datalink_id_t vnic_id, uint32_t flags)
{
	dladm_status_t status;
	dladm_vnic_attr_sys_t sys_attr;
	int fd;

	/* for now, only temporary deletes are supported */
	if (flags & DLADM_OPT_PERSIST)
		return (dladm_errno2status(ENOTSUP));

	if ((fd = open(VNIC_DEV, O_RDWR)) < 0)
		return (dladm_errno2status(errno));

	sys_attr.va_vnic_id = vnic_id;
	status = i_dladm_vnic_delete_sys(fd, &sys_attr);
	(void) close(fd);

	if (status != DLADM_STATUS_OK)
		return (status);

	(void) dladm_destroy_datalink_id(vnic_id, flags);
	return (status);
}
