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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <libdevinfo.h>
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
#include <sys/dld.h>
#include <sys/ib/ib_types.h>
#include <sys/ibpart.h>
#include <libdllink.h>
#include <libdladm.h>
#include <libdlib.h>
#include <libdladm_impl.h>

/*
 * IP over IB administration API; see PSARC/2010/085
 */

/*
 * Function prototypes
 */
dladm_status_t dladm_part_create(dladm_handle_t, datalink_id_t, ib_pkey_t,
    uint32_t, char *, datalink_id_t *, dladm_arg_list_t *);
static dladm_status_t	i_dladm_part_create(dladm_handle_t,
    dladm_part_attr_t *);
static dladm_status_t	dladm_part_persist_conf(dladm_handle_t, const char *,
    dladm_part_attr_t *);
static dladm_status_t i_dladm_part_delete(dladm_handle_t, datalink_id_t);
dladm_status_t	dladm_part_delete(dladm_handle_t, datalink_id_t, int);
static int	i_dladm_part_up(dladm_handle_t, datalink_id_t, void *);
dladm_status_t	dladm_part_up(dladm_handle_t, datalink_id_t, uint32_t);

/*
 * Convert a error status returned by the IP over IB kernel driver to a
 * valid dladm status.
 */
static dladm_status_t
dladm_ib_ioctl_err2status(int err)
{
	switch (err) {
	case 0:
		return (DLADM_STATUS_OK);
	case IBD_INVALID_PORT_INST:
		return (DLADM_STATUS_INVALID_PORT_INSTANCE);
	case IBD_PORT_IS_DOWN:
		return (DLADM_STATUS_PORT_IS_DOWN);
	case IBD_PKEY_NOT_PRESENT:
		return (DLADM_STATUS_PKEY_NOT_PRESENT);
	case IBD_PARTITION_EXISTS:
		return (DLADM_STATUS_PARTITION_EXISTS);
	case IBD_INVALID_PKEY:
		return (DLADM_STATUS_INVALID_PKEY);
	case IBD_NO_HW_RESOURCE:
		return (DLADM_STATUS_NO_IB_HW_RESOURCE);
	case IBD_INVALID_PKEY_TBL_SIZE:
		return (DLADM_STATUS_INVALID_PKEY_TBL_SIZE);
	default:
		return (DLADM_STATUS_FAILED);
	}
}

static dladm_status_t
i_dladm_ib_ioctl(dladm_handle_t handle, int ioccmd, ibd_ioctl_t *iocp)
{
	if (ioctl(dladm_dld_fd(handle), ioccmd, iocp) == 0)
		return (DLADM_STATUS_OK);

	if (iocp->ioc_status == 0)
		return (dladm_errno2status(errno));

	return (dladm_ib_ioctl_err2status(iocp->ioc_status));
}

/*
 * Get the active configuration information for the partition given by
 * the 'linkid'.
 */
static dladm_status_t
i_dladm_part_info_active(dladm_handle_t handle, datalink_id_t linkid,
    dladm_part_attr_t *attrp)
{
	ibpart_ioctl_t ioc;
	dladm_status_t status = DLADM_STATUS_OK;

	bzero(&ioc, sizeof (ioc));
	bzero(attrp, sizeof (*attrp));
	/*
	 * The ioc_linkid here will contain the data link id of the IB partition
	 * object.
	 */
	ioc.ibdioc.ioc_linkid = linkid;
	ioc.ibdioc.ioc_info_cmd = IBD_INFO_CMD_IBPART;

	status = i_dladm_ib_ioctl(handle, IBD_INFO_IBPART, (ibd_ioctl_t *)&ioc);
	if (status != DLADM_STATUS_OK)
		goto bail;

	/*
	 * On return from the ioctl ioc_linkid field contains the IB port's
	 * linkid.
	 */
	attrp->dia_physlinkid = ioc.ibdioc.ioc_linkid;
	attrp->dia_partlinkid = ioc.ioc_partid;
	attrp->dia_pkey = ioc.ioc_pkey;
	attrp->dia_portnum = ioc.ibdioc.ioc_portnum;
	attrp->dia_hca_guid = ioc.ibdioc.ioc_hcaguid;
	attrp->dia_port_guid = ioc.ibdioc.ioc_portguid;
	attrp->dia_instance = ioc.ibdioc.ioc_port_inst;

	/*
	 * If the IP over IB driver reports that this partition was created
	 * forcibly, then set the force create flag.
	 */
	if (ioc.ioc_force_create)
		attrp->dia_flags |= DLADM_PART_FORCE_CREATE;

bail:
	return (status);
}

/*
 * Get the configuration information about the IB partition 'linkid' from the
 * persistent configuration.
 */
static dladm_status_t
i_dladm_part_info_persist(dladm_handle_t handle, datalink_id_t linkid,
    dladm_part_attr_t *attrp)
{
	dladm_conf_t conf;
	dladm_status_t status;
	char linkover[MAXLINKNAMELEN];
	datalink_class_t class;
	boolean_t force = B_FALSE;

	conf.ds_readonly = B_FALSE;
	conf.ds_confid = DLADM_INVALID_CONF;

	/* Get the IB partition's datalink ID */
	if ((status = dladm_datalink_id2info(handle, linkid, NULL, &class,
	    NULL, NULL, 0)) != DLADM_STATUS_OK)
		goto done;

	bzero(attrp, sizeof (*attrp));
	attrp->dia_partlinkid = linkid;
	if ((status = dladm_getsnap_conf(handle, linkid, &conf)) !=
	    DLADM_STATUS_OK)
		return (status);

	/*
	 * Get the name of the IB Phys link over which IB partition was
	 * created.
	 */
	status = dladm_get_conf_field(handle, conf, FLINKOVER, linkover,
	    sizeof (linkover));
	if (status != DLADM_STATUS_OK) {
		attrp->dia_physlinkid = DATALINK_INVALID_LINKID;
		goto done;
	} else {
		/* Get the IB Phys link's datalink ID */
		if ((status = dladm_name2info(handle, linkover,
		    &attrp->dia_physlinkid, NULL, NULL, NULL)) !=
		    DLADM_STATUS_OK)
			goto done;
	}

	/* Get the IB partition's P_Key */
	status = dladm_get_conf_field(handle, conf, FPORTPKEY,
	    &attrp->dia_pkey, sizeof (uint64_t));
	if (status != DLADM_STATUS_OK)
		goto done;

	if (class != DATALINK_CLASS_PART) {
		status = DLADM_STATUS_BADARG;
		goto done;
	}

	/*
	 * If the FFORCE field is set in the persistent configuration database
	 * set the force create flag in the partition attributes.
	 */
	status = dladm_get_conf_field(handle, conf, FFORCE, &force,
	    sizeof (boolean_t));
	if (status != DLADM_STATUS_OK) {
		if (status != DLADM_STATUS_NOTFOUND)
			goto done;
	} else if (force == B_TRUE) {
		attrp->dia_flags |= DLADM_PART_FORCE_CREATE;
	}

	status = DLADM_STATUS_OK;
done:
	dladm_destroy_conf(handle, conf);
	return (status);
}

/*
 * Get the configuration information for the IB partition given by the datalink
 * ID 'linkid'. Based on the 'flags' field the information is either from the
 * active system (DLADM_OPT_ACTIVE) or from the persistent configuration
 * database.
 */
dladm_status_t
dladm_part_info(dladm_handle_t handle, datalink_id_t linkid,
    dladm_part_attr_t *attrp, uint32_t flags)
{
	if (flags == DLADM_OPT_ACTIVE)
		return (i_dladm_part_info_active(handle, linkid, attrp));
	else if (flags == DLADM_OPT_PERSIST)
		return (i_dladm_part_info_persist(handle, linkid, attrp));
	else
		return (DLADM_STATUS_BADARG);
}

/*
 * Get the configuration information for the IB Phys link given by the datalink
 * ID 'linkid'.
 */
dladm_status_t
dladm_ib_info(dladm_handle_t handle, datalink_id_t linkid,
    dladm_ib_attr_t *attrp, uint32_t flags __unused)
{
	uint_t instance;
	ibport_ioctl_t ioc;
	dladm_phys_attr_t	dpa;
	dladm_status_t status = DLADM_STATUS_OK;

	/*
	 * We need to get the device name of the IB Phys link to get the
	 * correct instance number of the IP over IB driver instance.
	 */
	if (dladm_phys_info(handle, linkid, &dpa, DLADM_OPT_ACTIVE)
	    != DLADM_STATUS_OK)
		return (DLADM_STATUS_BADARG);

	/*
	 * Get the instance number of the IP over IB driver instance which
	 * represents this IB Phys link.
	 */
	if (dladm_parselink(dpa.dp_dev, NULL, &instance) != DLADM_STATUS_OK)
		return (DLADM_STATUS_FAILED);

	bzero(&ioc, sizeof (ioc));
	/*
	 * The ioc_linkid here will contain IB port linkid here. We make the
	 * first ioctl call to get the P_Key table size for this HCA port.
	 */
	ioc.ibdioc.ioc_linkid = linkid;
	ioc.ibdioc.ioc_info_cmd = IBD_INFO_CMD_PKEYTBLSZ;
	ioc.ioc_pkey_tbl_sz = 0;
	ioc.ibdioc.ioc_port_inst = instance;

	status = i_dladm_ib_ioctl(handle, IBD_INFO_IBPART, (ibd_ioctl_t *)&ioc);
	if (status != DLADM_STATUS_OK)
		return (status);

	/*
	 * Now allocate the memory for the P_Key table based on the table size
	 * return by the ioctl.
	 */
	ioc.ioc_pkeys = calloc(sizeof (ib_pkey_t), ioc.ioc_pkey_tbl_sz);
	if (ioc.ioc_pkeys == NULL) {
		status = dladm_errno2status(errno);
		goto bail;
	}

	/*
	 * Call the ioctl again to get the P_Key table and other IB Phys link
	 * attributes.
	 */
	ioc.ibdioc.ioc_linkid = linkid;
	ioc.ibdioc.ioc_port_inst = instance;
	ioc.ibdioc.ioc_info_cmd = IBD_INFO_CMD_IBPORT;

	status = i_dladm_ib_ioctl(handle, IBD_INFO_IBPART, (ibd_ioctl_t *)&ioc);
	if (status != DLADM_STATUS_OK)
		goto bail;

	attrp->dia_physlinkid = ioc.ibdioc.ioc_linkid;
	attrp->dia_portnum = ioc.ibdioc.ioc_portnum;
	attrp->dia_port_pkey_tbl_sz = ioc.ioc_pkey_tbl_sz;
	attrp->dia_port_pkeys = ioc.ioc_pkeys;
	attrp->dia_hca_guid = ioc.ibdioc.ioc_hcaguid;
	attrp->dia_port_guid = ioc.ibdioc.ioc_portguid;
	attrp->dia_instance = ioc.ibdioc.ioc_port_inst;
	return (status);
bail:
	free(ioc.ioc_pkeys);
	return (status);
}

/*
 * Free the memory allocated for the IB HCA port's P_Key table by
 * dladm_ib_info library call.
 */
void
dladm_free_ib_info(dladm_ib_attr_t *attr)
{
	if (attr && attr->dia_port_pkeys)
		free(attr->dia_port_pkeys);
}

/*
 * Call into the IP over IB driver to create a partition object.
 */
static dladm_status_t
i_dladm_part_create(dladm_handle_t handle, dladm_part_attr_t *pattr)
{
	ibpart_ioctl_t	ioc;

	bzero(&ioc, sizeof (ioc));

	/* IB Physical datalink ID */
	ioc.ibdioc.ioc_linkid		= pattr->dia_physlinkid;
	/* IB Partition datalink ID */
	ioc.ioc_partid			= pattr->dia_partlinkid;
	ioc.ioc_pkey			= pattr->dia_pkey;
	ioc.ibdioc.ioc_port_inst	= pattr->dia_instance;
	ioc.ioc_force_create		= ((pattr->dia_flags & DLADM_OPT_FORCE)
	    != 0);

	return (i_dladm_ib_ioctl(handle, IBD_CREATE_IBPART, &ioc.ibdioc));
}

/*
 * Create an entry in the dladm persistent configuration database for the
 * partition specified by pattr.
 */
dladm_status_t
dladm_part_persist_conf(dladm_handle_t handle, const char *pname,
    dladm_part_attr_t *pattr)
{

	dladm_conf_t	conf;
	dladm_status_t	status;
	char		linkover[MAXLINKNAMELEN];
	uint64_t	u64;

	status = dladm_create_conf(handle, pname, pattr->dia_partlinkid,
	    DATALINK_CLASS_PART, DL_IB, &conf);
	if (status != DLADM_STATUS_OK)
		return (status);

	/*
	 * Get the name of the IB Phys link over which this partition was
	 * created.
	 */
	status = dladm_datalink_id2info(handle, pattr->dia_physlinkid,
	    NULL, NULL, NULL, linkover, sizeof (linkover));
	if (status != DLADM_STATUS_OK)
		return (status);

	/* Store IB Phys link name (linkover) */
	status = dladm_set_conf_field(handle, conf, FLINKOVER, DLADM_TYPE_STR,
	    linkover);
	if (status != DLADM_STATUS_OK)
		return (status);

	u64 = pattr->dia_pkey;

	/* Store the IB Partitions P_Key */
	status = dladm_set_conf_field(handle, conf, FPORTPKEY,
	    DLADM_TYPE_UINT64, &u64);
	if (status != DLADM_STATUS_OK)
		return (status);

	if (pattr->dia_flags & DLADM_OPT_FORCE) {
		boolean_t force = B_TRUE;
		/* Store the force create flag. */
		status = dladm_set_conf_field(handle, conf, FFORCE,
		    DLADM_TYPE_BOOLEAN, &force);
		if (status != DLADM_STATUS_OK)
			goto done;
	}

	status = dladm_write_conf(handle, conf);
	if (status != DLADM_STATUS_OK)
		return (status);

	dladm_destroy_conf(handle, conf);
done:
	return (status);
}

/*
 * Create a new IB Partition datalink of name 'pname' over the IB Physical link
 * given in 'physlinkid' with the P_key 'pkey' and return the datalink ID in
 * 'partlinkid'. If the 'force' option is set in the 'flags' argument, the
 * partition will be created even if the P_Key 'pkey' does not exist or if the
 * HCA port represented by the IB Phys link is down. If the 'temporary' flag is
 * set, then the configuration information is not added to the persistent
 * database.
 */
dladm_status_t
dladm_part_create(dladm_handle_t handle, datalink_id_t physlinkid,
    ib_pkey_t pkey, uint32_t flags, char *pname, datalink_id_t *partlinkid,
    dladm_arg_list_t *proplist)
{
	uint_t			i;
	dladm_status_t		status;
	uint_t			media;
	boolean_t		part_created = B_FALSE;
	boolean_t		conf_set = B_FALSE;
	dladm_phys_attr_t	dpa;
	dladm_part_attr_t	pattr;

	pattr.dia_pkey = pkey;
	pattr.dia_physlinkid = physlinkid; /* IB Phys link's datalink id */
	pattr.dia_flags = flags;

	flags &= ~DLADM_OPT_FORCE;

	/*
	 * Check whether the PKEY is valid. If not, return immediately
	 * Only full members are allowed as per the IPoIB specification
	 */
	if (pattr.dia_pkey <= IB_PKEY_INVALID_FULL)
		return (DLADM_STATUS_INVALID_PKEY);

	/*
	 * Get the media type of the Phys link datalink ID provided and
	 * make sure that it is Infiniband media DL_IB)
	 */
	if ((status = dladm_datalink_id2info(handle, pattr.dia_physlinkid, NULL,
	    NULL, &media, NULL, 0)) != DLADM_STATUS_OK)
		return (status);

	if (media != DL_IB)
		return (dladm_errno2status(ENOTSUP));

	/*
	 * Get the instance number of the IP over IB driver instance which the
	 * IB Phys link 'physlinkid' over which we will be creating our IB
	 * partition.
	 */
	if ((status = dladm_phys_info(handle, pattr.dia_physlinkid, &dpa,
	    DLADM_OPT_ACTIVE)) != DLADM_STATUS_OK)
		return (status);

	if (dladm_parselink(dpa.dp_dev, NULL, (uint_t *)&pattr.dia_instance) !=
	    DLADM_STATUS_OK)
		return (DLADM_STATUS_FAILED);


	if ((status = dladm_create_datalink_id(handle, pname,
	    DATALINK_CLASS_PART, DL_IB, flags, &pattr.dia_partlinkid)) !=
	    DLADM_STATUS_OK)
		return (status);

	/*
	 * Create the IB partition object.
	 */
	status = i_dladm_part_create(handle, &pattr);
	if (status != DLADM_STATUS_OK)
		goto done;

	part_created = B_TRUE;

	/*
	 * If the persist flag is set then write this partition information
	 * to the persistent configuration.
	 */
	if (pattr.dia_flags & DLADM_OPT_PERSIST) {
		status = dladm_part_persist_conf(handle, pname, &pattr);
		if (status != DLADM_STATUS_OK)
			goto done;
		conf_set = B_TRUE;
	}

	/*
	 * If the name-value pair list of properties were provided set those
	 * properties over the datalink.
	 */
	if (proplist != NULL) {
		for (i = 0; i < proplist->al_count; i++) {
			dladm_arg_info_t *aip = &proplist->al_info[i];

			status = dladm_set_linkprop(handle,
			    pattr.dia_partlinkid, aip->ai_name, aip->ai_val,
			    aip->ai_count, pattr.dia_flags);
			if (status != DLADM_STATUS_OK)
				break;
		}
	}
done:
	if (status != DLADM_STATUS_OK) {
		if (conf_set)
			(void) dladm_remove_conf(handle, pattr.dia_partlinkid);
		if (part_created)
			(void) i_dladm_part_delete(handle,
			    pattr.dia_partlinkid);
		(void) dladm_destroy_datalink_id(handle, pattr.dia_partlinkid,
		    flags);
	}

	if (partlinkid != NULL)
		*partlinkid = pattr.dia_partlinkid;

	return (status);
}

/*
 * Call into the IP over IB driver to delete the IB partition and free up all
 * the resources allocated for it.
 */
static dladm_status_t
i_dladm_part_delete(dladm_handle_t handle, datalink_id_t partid)
{
	ibpart_ioctl_t ioc;

	bzero(&ioc, sizeof (ioc));
	ioc.ioc_partid = partid;
	return (i_dladm_ib_ioctl(handle, IBD_DELETE_IBPART, &ioc.ibdioc));
}

/*
 * Delete an IB partition if 'flags' contains the active flag. Update the
 * persistent configuration if 'flags' contains the persist flag.
 */
dladm_status_t
dladm_part_delete(dladm_handle_t handle, datalink_id_t partid, int flags)
{
	dladm_status_t	status = DLADM_STATUS_OK;
	datalink_class_t class;

	if (flags == 0)
		return (DLADM_STATUS_BADARG);

	/*
	 * Make sure that the datalinkid provided is an IB partition class
	 * datalink ID.
	 */
	if ((dladm_datalink_id2info(handle, partid, NULL, &class, NULL, NULL, 0)
	    != DLADM_STATUS_OK))
		return (DLADM_STATUS_BADARG);

	if (class != DATALINK_CLASS_PART)
		return (DLADM_STATUS_BADARG);

	if ((flags & DLADM_OPT_ACTIVE) != 0) {
		status = i_dladm_part_delete(handle, partid);
		if (status == DLADM_STATUS_OK) {
			(void) dladm_set_linkprop(handle, partid, NULL, NULL, 0,
			    DLADM_OPT_ACTIVE);
			(void) dladm_destroy_datalink_id(handle, partid,
			    DLADM_OPT_ACTIVE);
		} else if (status != DLADM_STATUS_NOTFOUND ||
		    !(flags & DLADM_OPT_PERSIST)) {
			return (status);
		}
	}

	if ((flags & DLADM_OPT_PERSIST) != 0) {
		dladm_status_t db_status;
		db_status = dladm_remove_conf(handle, partid);

		/*
		 * A partition could have been temporarily deleted in which
		 * case the delete of the active partition above would have
		 * failed. In that case, we update the status to be returned
		 * to that of the status returned for deleting the persistent
		 * database entry.
		 */
		if (status == DLADM_STATUS_NOTFOUND)
			status = db_status;

		(void) dladm_destroy_datalink_id(handle, partid,
		    DLADM_OPT_PERSIST);
	}

	return (status);
}

/*
 * Call into the IP over IB driver to create the active instances of one or all
 * IB partitions present in the persistent configuration.
 */
static int
i_dladm_part_up(dladm_handle_t handle, datalink_id_t plinkid,
    void *arg __unused)
{
	dladm_conf_t	conf;
	datalink_id_t	linkid;
	ib_pkey_t	pkey;
	uint64_t	u64;
	char linkover[MAXLINKNAMELEN];
	dladm_status_t	status;
	dladm_phys_attr_t dpa;
	dladm_part_attr_t pattr;

	/*
	 * plinkid is the IB partition datalink's ID. Get an handle to the
	 * persistent configuration entry for this datalink ID. If this datalink
	 * ID is not present in the persistent configuration return.
	 */
	if ((status = dladm_getsnap_conf(handle, plinkid, &conf)) !=
	    DLADM_STATUS_OK)
		return (status);

	/*
	 * Get the name of the IB Phys link over which this partition was
	 * created.
	 */
	status = dladm_get_conf_field(handle, conf, FLINKOVER, linkover,
	    sizeof (linkover));
	if (status != DLADM_STATUS_OK)
		goto done;

	if ((status = dladm_name2info(handle, linkover, &linkid, NULL, NULL,
	    NULL)) != DLADM_STATUS_OK)
		goto done;

	/*
	 * Get the phys attribute of the IB Phys link to get the device name
	 * associated with the phys link. We need this to get the IP over IB
	 * driver instance number.
	 */
	if (dladm_phys_info(handle, linkid, &dpa, DLADM_OPT_ACTIVE)
	    != DLADM_STATUS_OK)
		goto done;

	/* Get the IB partition's P_key */
	status = dladm_get_conf_field(handle, conf, FPORTPKEY, &u64,
	    sizeof (u64));
	if (status != DLADM_STATUS_OK)
		goto done;

	pkey = (ib_pkey_t)u64;

	/*
	 * We always set the force flag during dladm_part_up because we want
	 * the partition creation to succeed even if the IB HCA port over which
	 * the partition is being created is still down. Since dladm_part_up
	 * is usually invoked during early boot sequence, it is possible under
	 * some IB subnet configurations for dladm_up_part to be called before
	 * the IB link negotiation is completed and port state is set to active
	 * and P_Key table is updated.
	 */
	pattr.dia_flags = DLADM_OPT_FORCE | DLADM_OPT_ACTIVE |
	    DLADM_OPT_PERSIST;
	/* IB Phys link's datalink ID. */
	pattr.dia_physlinkid = linkid;
	/* IB Partition's datalink ID. */
	pattr.dia_partlinkid = plinkid;
	pattr.dia_pkey = pkey;
	if (dladm_parselink(dpa.dp_dev, NULL, (uint_t *)&pattr.dia_instance) !=
	    DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);

	/* Create the active IB Partition object. */
	if (i_dladm_part_create(handle, &pattr) == DLADM_STATUS_OK &&
	    dladm_up_datalink_id(handle, plinkid) != DLADM_STATUS_OK)
		(void) i_dladm_part_delete(handle, linkid);

done:
	dladm_destroy_conf(handle, conf);
	return (DLADM_WALK_CONTINUE);
}

/*
 * Bring up one or all IB partition(s) present in the persistent configuration
 * database. If we need to bring up one IB Partition, its datalink ID is
 * provided in 'linkid'.
 */
dladm_status_t
dladm_part_up(dladm_handle_t handle, datalink_id_t linkid,
    uint32_t flags __unused)
{
	dladm_status_t status = DLADM_STATUS_OK;

	if (linkid == DATALINK_ALL_LINKID) {
		(void) dladm_walk_datalink_id(i_dladm_part_up, handle,
		    &status, DATALINK_CLASS_PART, DATALINK_ANY_MEDIATYPE,
		    DLADM_OPT_PERSIST);
		return (DLADM_STATUS_OK);
	} else {
		(void) i_dladm_part_up(handle, linkid, &status);
		return (status);
	}
}
