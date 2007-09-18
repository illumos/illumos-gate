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
#include <libdlvnic.h>

/*
 * VNIC administration library.
 */

#define	VNIC_DEV	"/devices/pseudo/vnic@0:" VNIC_CTL_NODE_NAME

/*
 * Because by default the id is used as the DLPI device PPA and default
 * VLAN PPA's are calculated as ((1000 * vid) + PPA), the largest id
 * can't be > 999. We reserve the last 100 VNIC ids for automatic
 * VNIC id assignment.
 */
#define	DLADM_VNIC_MIN_VNIC_ID		1	/* total range */
#define	DLADM_VNIC_MAX_VNIC_ID		999
#define	DLADM_VNIC_MIN_VNIC_SPEC_ID	1	/* specified by user */
#define	DLADM_VNIC_MAX_VNIC_SPEC_ID	899
#define	DLADM_VNIC_MIN_VNIC_AUTO_ID	900	/* picked automatically */
#define	DLADM_VNIC_MAX_VNIC_AUTO_ID	999

#define	DLADM_VNIC_NUM_VNIC_AUTO_ID	(DLADM_VNIC_MAX_VNIC_AUTO_ID - \
    DLADM_VNIC_MIN_VNIC_AUTO_ID + 1)

/* Limits on buffer size for VNIC_IOC_INFO request */
#define	MIN_INFO_SIZE (4*1024)
#define	MAX_INFO_SIZE (128*1024)

/* configuration database entry */
typedef struct dladm_vnic_attr_db {
	uint_t		vt_vnic_id;
	char		vt_dev_name[MAXNAMELEN];
	vnic_mac_addr_type_t vt_mac_addr_type;
	uint_t		vt_mac_len;
	uchar_t		vt_mac_addr[MAXMACADDRLEN];
} dladm_vnic_attr_db_t;

typedef struct dladm_vnic_up {
	uint_t		vu_vnic_id;
	boolean_t	vu_found;
	int		vu_fd;
} dladm_vnic_up_t;

typedef struct dladm_vnic_down {
	uint32_t	vd_vnic_id;
	boolean_t	vd_found;
} dladm_vnic_down_t;

typedef struct dladm_vnic_modify {
	uint32_t	vm_vnic_id;
	boolean_t	vm_found;
} dladm_vnic_modify_t;

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
	bcopy(attr->vt_dev_name, ioc.vc_dev_name, MAXNAMELEN);
	ioc.vc_mac_addr_type = attr->vt_mac_addr_type;
	ioc.vc_mac_len = attr->vt_mac_len;
	bcopy(attr->vt_mac_addr, ioc.vc_mac_addr, attr->vt_mac_len);

	rc = i_dladm_ioctl(fd, VNIC_IOC_CREATE, &ioc, sizeof (ioc));

	if (rc < 0)
		return (dladm_errno2status(errno));

	return (DLADM_STATUS_OK);
}

/*
 * Invoked to bring up a VNIC.
 */
static dladm_status_t
i_dladm_vnic_up(void *arg, dladm_vnic_attr_db_t *attr)
{
	dladm_vnic_up_t *up = (dladm_vnic_up_t *)arg;
	dladm_status_t status;

	if (up->vu_vnic_id != 0 && up->vu_vnic_id != attr->vt_vnic_id)
		return (DLADM_STATUS_OK);

	up->vu_found = B_TRUE;

	status = i_dladm_vnic_create_sys(up->vu_fd, attr);
	if ((status != DLADM_STATUS_OK) && (up->vu_vnic_id != 0))
		return (status);

	return (DLADM_STATUS_OK);
}

/*
 * Send a modify command to the VNIC driver.
 */
static dladm_status_t
i_dladm_vnic_modify_sys(uint_t vnic_id, uint32_t modify_mask,
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
 * Walk through the vnics defined on the system and for each vnic <vnic>,
 * invoke <fn>(<arg>, <vnic>);
 */
dladm_status_t
dladm_vnic_walk_sys(dladm_status_t (*fn)(void *, dladm_vnic_attr_sys_t *),
    void *arg)
{
	vnic_ioc_info_t *ioc;
	vnic_ioc_info_vnic_t *vnic;
	dladm_vnic_attr_sys_t attr;
	int rc, i, bufsize, fd;
	char *where;
	dladm_status_t status = DLADM_STATUS_OK;

	if ((fd = open(VNIC_DEV, O_RDWR)) == -1)
		return (dladm_errno2status(errno));

	bufsize = MIN_INFO_SIZE;
	ioc = (vnic_ioc_info_t *)calloc(1, bufsize);
	if (ioc == NULL) {
		(void) close(fd);
		return (dladm_errno2status(ENOMEM));
	}

tryagain:

	rc = i_dladm_ioctl(fd, VNIC_IOC_INFO, ioc, bufsize);

	if (rc != 0) {
		if (errno == ENOSPC) {
			bufsize *= 2;
			if (bufsize <= MAX_INFO_SIZE) {
				ioc = (vnic_ioc_info_t *)realloc(ioc, bufsize);
				if (ioc != NULL) {
					bzero(ioc, bufsize);
					goto tryagain;
				}
			}
		}
		status = dladm_errno2status(errno);
		goto bail;
	}

	/*
	 * Go through each vnic returned by the vnic driver
	 */
	where = (char *)(ioc + 1);

	for (i = 0; i < ioc->vi_nvnics; i++) {
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		vnic = (vnic_ioc_info_vnic_t *)where;

		attr.va_vnic_id = vnic->vn_vnic_id;
		bcopy(vnic->vn_dev_name, attr.va_dev_name,
		    MAXNAMELEN);
		attr.va_mac_addr_type = vnic->vn_mac_addr_type;
		bcopy(vnic->vn_mac_addr, attr.va_mac_addr, ETHERADDRL);
		attr.va_mac_len = vnic->vn_mac_len;
		where = (char *)(vnic + 1);

		status = fn(arg, &attr);
		if (status != DLADM_STATUS_OK)
			goto bail;
	}

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
 * Invoked to bring down a VNIC.
 */
static dladm_status_t
i_dladm_vnic_down(void *arg, dladm_vnic_attr_sys_t *attr)
{
	dladm_vnic_down_t *down = (dladm_vnic_down_t *)arg;
	int fd;
	dladm_status_t status;

	if (down->vd_vnic_id != 0 && down->vd_vnic_id != attr->va_vnic_id)
		return (DLADM_STATUS_OK);

	down->vd_found = B_TRUE;

	if ((fd = open(VNIC_DEV, O_RDWR)) < 0)
		return (dladm_errno2status(errno));

	status = i_dladm_vnic_delete_sys(fd, attr);
	if ((status != DLADM_STATUS_OK) && (down->vd_vnic_id != 0)) {
		(void) close(fd);
		return (status);
	}

	(void) close(fd);
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

/* returns B_TRUE if a matching type was found, B_FALSE otherwise */
boolean_t
dladm_vnic_mac_addr_str_to_type(const char *str, vnic_mac_addr_type_t *val)
{
	int i;
	dladm_vnic_addr_type_t *type;

	for (i = 0; i < NADDR_TYPES; i++) {
		type = &addr_types[i];
		if (strncmp(str, type->va_str, strlen(type->va_str)) == 0) {
			*val = type->va_type;
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * Select a VNIC id automatically.
 */

typedef struct dladm_vnic_auto_state_s {
	uint_t		as_nslots;
	uint_t		*as_slots;
} dladm_vnic_auto_state_t;

static dladm_status_t
i_dladm_vnic_create_auto_walker(void *arg, dladm_vnic_attr_sys_t *attr)
{
	dladm_vnic_auto_state_t *state = arg;

	if (attr->va_vnic_id < DLADM_VNIC_MIN_VNIC_AUTO_ID ||
	    attr->va_vnic_id > DLADM_VNIC_MAX_VNIC_AUTO_ID)
		return (DLADM_STATUS_OK);

	state->as_slots[state->as_nslots++] = attr->va_vnic_id;

	return (DLADM_STATUS_OK);
}

static int
i_dladm_vnic_compare(const void *p1, const void *p2)
{
	uint_t i = *((uint_t *)p1);
	uint_t j = *((uint_t *)p2);

	if (i > j)
		return (1);
	if (i < j)
		return (-1);
	return (0);
}

/*ARGSUSED*/
static dladm_status_t
i_dladm_vnic_get_auto_id(dladm_vnic_attr_db_t *attr, uint32_t *vnic_id_out)
{
	dladm_vnic_auto_state_t state;
	uint_t vnic_ids[DLADM_VNIC_NUM_VNIC_AUTO_ID];
	int i;
	uint_t last_id, vnic_id;
	dladm_status_t status;

	/*
	 * Build a sorted array containing the existing VNIC ids in the range
	 * allocated for automatic allocation.
	 */
	state.as_nslots = 0;
	state.as_slots = vnic_ids;

	status = dladm_vnic_walk_sys(i_dladm_vnic_create_auto_walker, &state);
	if (status != DLADM_STATUS_OK)
		return (status);

	qsort(vnic_ids, state.as_nslots, sizeof (uint_t),
	    i_dladm_vnic_compare);

	/*
	 * Find a gap in the sequence of existing VNIC ids.
	 */
	last_id = DLADM_VNIC_MIN_VNIC_AUTO_ID - 1;
	vnic_id = 0;
	for (i = 0; i < state.as_nslots; i++) {
		if (vnic_ids[i] > (last_id + 1)) {
			vnic_id = last_id + 1;
			break;
		}
		last_id = vnic_ids[i];
	}

	if (vnic_id == 0) {
		/*
		 * Did not find a gap between existing entries, see if we
		 * can add one.
		 */
		if (last_id + 1 > DLADM_VNIC_MAX_VNIC_AUTO_ID)
			return (DLADM_STATUS_AUTOIDNOAVAILABLEID);

		/* still have room for one more VNIC */
		vnic_id = last_id + 1;
	}

	*vnic_id_out = vnic_id;

	return (DLADM_STATUS_OK);
}

/*
 * Create a new VNIC. Update the configuration file and bring it up.
 */
dladm_status_t
dladm_vnic_create(uint_t vnic_id, char *dev_name,
    vnic_mac_addr_type_t mac_addr_type, uchar_t *mac_addr, int mac_len,
    uint_t *vnic_id_out, uint32_t flags)
{
	dladm_vnic_attr_db_t attr;
	int i;
	boolean_t tempop = ((flags & DLADM_VNIC_OPT_TEMP) != 0);
	boolean_t autoid = ((flags & DLADM_VNIC_OPT_AUTOID) != 0);
	dladm_vnic_up_t up;
	dladm_status_t status;

	/*
	 * Sanity test arguments.
	 */
	if (autoid && !tempop)
		return (DLADM_STATUS_AUTOIDNOTEMP);

	if (!autoid && ((vnic_id < DLADM_VNIC_MIN_VNIC_SPEC_ID) ||
	    (vnic_id > DLADM_VNIC_MAX_VNIC_SPEC_ID)))
		return (DLADM_STATUS_INVALIDID);

	if (mac_len > MAXMACADDRLEN)
		return (DLADM_STATUS_INVALIDMACADDRLEN);

	for (i = 0; i < NADDR_TYPES; i++) {
		if (mac_addr_type == addr_types[i].va_type)
			break;
	}
	if (i == NADDR_TYPES)
		return (DLADM_STATUS_INVALIDMACADDRTYPE);

	/* for now, only temporary creations are supported */
	if (!tempop)
		return (dladm_errno2status(ENOTSUP));

auto_again:
	if (autoid) {
		/*
		 * Find an unused VNIC id.
		 */
		status = i_dladm_vnic_get_auto_id(&attr, vnic_id_out);
		if (status != DLADM_STATUS_OK)
			return (status);
		vnic_id = *vnic_id_out;
	}

	bzero(&attr, sizeof (attr));
	attr.vt_vnic_id = vnic_id;
	(void) strncpy(attr.vt_dev_name, dev_name,
	    sizeof (attr.vt_dev_name) - 1);
	attr.vt_mac_addr_type = mac_addr_type;
	attr.vt_mac_len = mac_len;
	bcopy(mac_addr, attr.vt_mac_addr, mac_len);

	up.vu_vnic_id = vnic_id;
	up.vu_found = B_FALSE;
	up.vu_fd = open(VNIC_DEV, O_RDWR);
	if (up.vu_fd < 0)
		return (dladm_errno2status(errno));

	status = i_dladm_vnic_up((void *)&up, &attr);
	(void) close(up.vu_fd);

	if ((status == DLADM_STATUS_EXIST) && autoid)
		goto auto_again;

	return (status);
}

/*
 * Modify the properties of a VNIC.
 */
dladm_status_t
dladm_vnic_modify(uint_t vnic_id, uint32_t modify_mask,
    vnic_mac_addr_type_t mac_addr_type, uint_t mac_len, uchar_t *mac_addr,
    uint32_t flags)
{
	dladm_vnic_modify_attr_t new_attr;
	boolean_t tempop = ((flags & DLADM_VNIC_OPT_TEMP) != 0);

	if ((vnic_id < DLADM_VNIC_MIN_VNIC_ID) ||
	    (vnic_id > DLADM_VNIC_MAX_VNIC_ID))
		return (DLADM_STATUS_INVALIDID);

	/* for now, only temporary creations are supported */
	if (!tempop)
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
dladm_vnic_delete(uint_t vnic_id, uint32_t flags)
{
	boolean_t tempop = ((flags & DLADM_VNIC_OPT_TEMP) != 0);
	dladm_vnic_down_t down;
	dladm_vnic_attr_sys_t sys_attr;

	if ((vnic_id < DLADM_VNIC_MIN_VNIC_ID) ||
	    (vnic_id > DLADM_VNIC_MAX_VNIC_ID))
		return (DLADM_STATUS_INVALIDID);

	/* for now, only temporary deletes are supported */
	if (!tempop)
		return (dladm_errno2status(ENOTSUP));

	down.vd_vnic_id = vnic_id;
	down.vd_found = B_FALSE;
	sys_attr.va_vnic_id = vnic_id;
	return (i_dladm_vnic_down((void *)&down, &sys_attr));
}
