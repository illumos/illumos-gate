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

/*
 * Sun4v Platform specific functions.
 *
 * 	called when :
 *      machine_type ==  erie
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <kstat.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <libintl.h>
#include <note.h>
#include <sys/systeminfo.h>
#include <sys/openpromio.h>
#include <sys/sysmacros.h>
#include <picl.h>
#include "picldefs.h"
#include <pdevinfo.h>
#include <display.h>
#include <display_sun4v.h>
#include <libprtdiag.h>
#include "erie.h"

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif



/*
 * Add all io picl nodes under pci in io list
 */
/* ARGSUSED */
int
erie_pci_callback(picl_nodehdl_t pcih, void *args)
{
	int		err = PICL_SUCCESS;
	picl_nodehdl_t	nodeh;
	char		path[MAXSTRLEN];
	char		parent_path[MAXSTRLEN];
	char		piclclass[PICL_CLASSNAMELEN_MAX];
	char		name[MAXSTRLEN];
	char		model[MAXSTRLEN];
	char		nac[MAXSTRLEN];
	char		bus_type[MAXSTRLEN];
	int		slot = NO_SLOT;

	/* Get the parent node's path - used to determine bus type of child */
	err = picl_get_propval_by_name(pcih, PICL_PROP_DEVFS_PATH, parent_path,
	    sizeof (parent_path));
	if (err != PICL_SUCCESS) {
		return (err);
	}

	/* Walk through this node's children */
	err = picl_get_propval_by_name(pcih, PICL_PROP_CHILD, &nodeh,
	    sizeof (picl_nodehdl_t));
	while (err == PICL_SUCCESS) {

		/* Get child's class */
		if ((err = erie_get_class(nodeh, piclclass,
		    sizeof (piclclass))) != PICL_SUCCESS)
			return (err);

		/* If this node is a pci bus or bridge, get node's sibling */
		if ((strcmp(piclclass, "pci") == 0 ||
		    (strcmp(piclclass, "pciex") == 0))) {
			err = picl_get_propval_by_name(nodeh, PICL_PROP_PEER,
			    &nodeh, sizeof (picl_nodehdl_t));
			continue;
		}

		/*
		 * In order to get certain values, it's necessary
		 * to search the picl tree. If there's a problem
		 * with these searches, we'll return the err
		 */
		if ((err = erie_get_path(nodeh, path, sizeof (path)))
		    != PICL_SUCCESS)
			return (err);
		if ((err = erie_get_name(nodeh, name, sizeof (name)))
		    != PICL_SUCCESS)
			return (err);
		if ((err = erie_get_model(nodeh, model, sizeof (model)))
		    != PICL_SUCCESS)
			return (err);
		erie_get_bus_type(parent_path, bus_type);
		slot = erie_get_slot_number(path);
		erie_get_nac(bus_type, path, slot, name, nac, sizeof (nac));


		/* Print out the data */

		/* Print NAC */
		log_printf("%-11s", nac);

		/* Print IO Type */
		log_printf("%-6s", bus_type);

		/* Print Slot # */
		if (slot != NO_SLOT) {
			log_printf("%5d", slot);
			log_printf("%46s", path);
		} else {
			log_printf("%5s", MOTHERBOARD);
			log_printf("%46s", path);
		}

		/* Printf Node Name */
		if (strlen(name) > 25)
			log_printf("%25.24s+", name);
		else
			log_printf("%26s", name);
		/* Print Card Model */
		if (strlen(model) > 10)
			log_printf("%10.9s+", model);
		else
			log_printf("%11s", model);
		log_printf("\n");

		/* Grab the next child under parent node and do it again */
		err = picl_get_propval_by_name(nodeh, PICL_PROP_PEER, &nodeh,
		    sizeof (picl_nodehdl_t));
	}
	return (PICL_WALK_CONTINUE);
}


/*
 * ----------------------------------------------------------------------------
 */

/*
 * Add all IO ASIC revisions to list
 */
/* ARGSUSED */
int
erie_hw_rev_callback(picl_nodehdl_t pcih, void *args)
{
	int		err = PICL_SUCCESS;
	char		path[MAXSTRLEN] = "";
	char		nac[MAXSTRLEN];
	char		*compatible;
	int32_t		revision;

	/* Get path of this device */
	err = picl_get_propval_by_name(pcih, PICL_PROP_DEVFS_PATH, path,
	    sizeof (path));
	if (err != PICL_SUCCESS) {
		return (err);
	}
	/*
	 * If it's a network dev, then print network info.
	 * Else if it's not a network dev,  check for FIRE ASIC
	 * Else return PICL_WALK_CONTINUE
	 */
	if ((strcmp(path, ERIE_NETWORK_0) == 0) ||
	    (strcmp(path, ERIE_NETWORK_1) == 0)) {
		(void) snprintf(nac, sizeof (nac), "%s/%s%d", MOTHERBOARD,
		    OPHIR, 0);
		revision = erie_get_int_propval(pcih, OBP_PROP_REVISION_ID,
		    &err);
	} else if ((strcmp(path, ERIE_NETWORK_2) == 0) ||
	    (strcmp(path, ERIE_NETWORK_3) == 0)) {
		(void) snprintf(nac, sizeof (nac), "%s/%s%d", MOTHERBOARD,
		    OPHIR, 1);
		revision = erie_get_int_propval(pcih, OBP_PROP_REVISION_ID,
		    &err);
	} else if ((strcmp(path, ERIE_LSI_PATH) == 0)) {
		(void) snprintf(nac, sizeof (nac), "%s/%s", MOTHERBOARD,
		    SAS_SATA_HBA);
		revision = erie_get_int_propval(pcih, OBP_PROP_REVISION_ID,
		    &err);
	} else if ((strcmp(path, FIRE0) == 0) || (strcmp(path, FIRE1) == 0)) {
		(void) snprintf(nac, sizeof (nac), "%s/%s", MOTHERBOARD,
		    IOBRIDGE);
		revision = erie_get_int_propval(pcih, OBP_PROP_REVISION_ID,
		    &err);
	} else if ((strcmp(path, PCIE_PCIX) == 0) ||
	    (strcmp(path, PCIE_PCIE) == 0)) {
		(void) snprintf(nac, sizeof (nac), "%s/%s", MOTHERBOARD,
		    PCI_BRIDGE);
		revision = erie_get_int_propval(pcih, OBP_PROP_REVISION_ID,
		    &err);
	} else {
		return (PICL_WALK_CONTINUE);
	}

	/* Get first compatible value from picl compatible list */
	err = erie_get_first_compatible_value(pcih, &compatible);
	if (err != PICL_SUCCESS) {
		return (err);
	}

	/* Print nacation */
	log_printf("%-20s", nac);

	/* Print Device Path */
	log_printf("%41s", path);

	/* Print Compatible # */
	log_printf("%31s", compatible);
	free(compatible);

	/* Print Revision */
	log_printf("%6d", revision);
	log_printf("\n");

	return (PICL_WALK_CONTINUE);
}

/*
 * ----------------------------------------------------------------------------
 */

/*
 * Local functions
 */


/*
 * This function returns the first picl compatible value
 */
int
erie_get_first_compatible_value(picl_nodehdl_t nodeh, char **outbuf)
{
	int		err;
	picl_prophdl_t	proph;
	picl_propinfo_t	pinfo;
	picl_prophdl_t	tblh;
	picl_prophdl_t	rowproph;
	char		*pval;

	err = picl_get_propinfo_by_name(nodeh, OBP_PROP_COMPATIBLE,
	    &pinfo, &proph);
	if (err != PICL_SUCCESS)
	    return (err);

	if (pinfo.type == PICL_PTYPE_CHARSTRING) {
		pval = malloc(pinfo.size);
		if (pval == NULL)
			return (PICL_FAILURE);
		err = picl_get_propval(proph, pval, pinfo.size);
		if (err != PICL_SUCCESS) {
			free(pval);
			return (err);
		}
		*outbuf = pval;
		return (PICL_SUCCESS);
	}

	if (pinfo.type != PICL_PTYPE_TABLE)
		return (PICL_FAILURE);

	/* get first string from table */
	err = picl_get_propval(proph, &tblh, pinfo.size);
	if (err != PICL_SUCCESS)
		return (err);

	err = picl_get_next_by_row(tblh, &rowproph);
	if (err != PICL_SUCCESS)
		return (err);

	err = picl_get_propinfo(rowproph, &pinfo);
	if (err != PICL_SUCCESS)
	    return (err);

	pval = malloc(pinfo.size);
	if (pval == NULL)
		return (PICL_FAILURE);

	err = picl_get_propval(rowproph, pval, pinfo.size);
	if (err != PICL_SUCCESS) {
		free(pval);
		return (err);
	}

	*outbuf = pval;
	return (PICL_SUCCESS);
}

/*
 * This function returns the revision of
 * a device.
 */
int64_t
erie_get_int_propval(picl_nodehdl_t modh, char *prop_name, int *ret)
{
	int		err;
	picl_prophdl_t	proph;
	picl_propinfo_t	pinfo;
	int8_t		int8v;
	int16_t		int16v;
	int32_t		int32v;
	int64_t		int64v;

	err = picl_get_propinfo_by_name(modh, prop_name, &pinfo, &proph);
	if (err != PICL_SUCCESS) {
		*ret = err;
		return (0);
	}

	/*
	 * If it is not an int, uint or byte array prop, return failure
	 */
	if ((pinfo.type != PICL_PTYPE_INT) &&
		(pinfo.type != PICL_PTYPE_UNSIGNED_INT) &&
		(pinfo.type != PICL_PTYPE_BYTEARRAY)) {
		*ret = PICL_FAILURE;
		return (0);
	}

	switch (pinfo.size) {
	case sizeof (int8_t):
		err = picl_get_propval(proph, &int8v, sizeof (int8v));
		*ret = err;
		return (int8v);
	case sizeof (int16_t):
		err = picl_get_propval(proph, &int16v, sizeof (int16v));
		*ret = err;
		return (int16v);
	case sizeof (int32_t):
		err = picl_get_propval(proph, &int32v, sizeof (int32v));
		*ret = err;
		return (int32v);
	case sizeof (int64_t):
		err = picl_get_propval(proph, &int64v, sizeof (int64v));
		*ret = err;
		return (int64v);
	default:	/* not supported size */
		*ret = PICL_FAILURE;
		return (0);
	}
}

/*
 * This function fills in the bus type for an IO device.
 * If a device hangs off /pci@7c0/pci@0/pci@8, it's on
 * the pci-x bus. Otherwise, it's on a pci-e bus.
 *
 */
void
erie_get_bus_type(char path[], char bus_type[])
{
	if (strncmp(path, PCIX_BUS, ERIE_PCIX_COMP) == 0) {
		(void) strcpy(bus_type, "PCIX");
	} else {
		(void) strcpy(bus_type, "PCIE");
	}
}

/*
 * Thie function indicates whether a device is in a pci-e slot
 * or if it's on the motherboard. There's only one pci-e slot
 * on erie, everything else is on the motherboard.
 *
 */
int
erie_get_slot_number(char path[])
{
	if (strncmp(path, FIRE0, ERIE_PCIE_COMP) == 0)
		return (0);
	return (NO_SLOT);
}

/*
 * This function takes a path to one of the on-board
 * network devices and returns the instance# of that
 * device.
 *
 */
int
erie_get_network_instance(char path[])
{

	if (strncmp(path, ERIE_NETWORK_1, strlen(ERIE_NETWORK_1)) == 0) {
		return (1);
	} else if (strncmp(path, ERIE_NETWORK_3, strlen(ERIE_NETWORK_3)) == 0) {
		return (3);
	} else if (strncmp(path, ERIE_NETWORK_0, strlen(ERIE_NETWORK_0)) == 0) {
		return (0);
	} else if (strncmp(path, ERIE_NETWORK_2, strlen(ERIE_NETWORK_2)) == 0) {
		return (2);
	} else {
		return (-1);
	}
}

/*
 * This function gets the path of a node and
 * the error code from the picl API
 *
 */
int
erie_get_path(picl_nodehdl_t nodeh, char path[], int size)
{
	int  err;

	/* hardware path of this node */
	err = picl_get_propval_by_name(nodeh, PICL_PROP_DEVFS_PATH,
	    path, size);
	return (err);
}

/*
 * This function returns assings the string passed in
 * the value of the picl node's name
 *
 */
int
erie_get_name(picl_nodehdl_t nodeh, char name[], int size)
{
	int  err;
	char *compatible;
	char binding_name[MAXSTRLEN];
	char lname[MAXSTRLEN];

	/* Get this node's name */
	err = picl_get_propval_by_name(nodeh, PICL_PROP_NAME, &lname, size);
	if (err == PICL_PROPNOTFOUND) {
		(void) strcpy(lname, "");
		err = PICL_SUCCESS;
	}

	/*
	 * If binding_name is found,
	 * name will be <nodename>-<binding_name>
	 */
	err = picl_get_propval_by_name(nodeh, PICL_PROP_BINDING_NAME,
	    &binding_name, sizeof (binding_name));
	if (err == PICL_SUCCESS) {
		if (strcmp(lname, binding_name) != 0) {
			(void) strlcat(lname, "-", MAXSTRLEN);
			(void) strlcat(lname, binding_name, MAXSTRLEN);
		}
	/*
	 * if compatible prop is not found, name will be
	 * <nodename>-<compatible>
	 */
	} else if (err == PICL_PROPNOTFOUND) {
		err = erie_get_first_compatible_value(nodeh, &compatible);
		if (err == PICL_SUCCESS) {
			(void) strlcat(lname, "-", MAXSTRLEN);
			(void) strlcat(lname, compatible, MAXSTRLEN);
		}
		err = PICL_SUCCESS;
	} else {
		return (err);
	}

	/* The name was created fine, copy it to name var */
	(void) strcpy(name, lname);
	return (err);
}

/*
 * This functions assigns the string passed in the
 * the value of the picl node's NAC name.
 */
void
erie_get_nac(char bus_type[], char path[], int slot,  char name[], char nac[],
    int size)
{
	int instance;

	/* Figure out NAC name and instance, if onboard network node */
	if (strncmp(name, NETWORK, NET_COMP_NUM) == 0) {
		instance = erie_get_network_instance(path);
		(void) snprintf(nac, size, "%s/%s%d", MOTHERBOARD,
		    "NET", instance);
	} else if (slot != NO_SLOT) {
		(void) snprintf(nac, size, "%s/%s%d", MOTHERBOARD, bus_type,
		    slot);
	} else {
		(void) snprintf(nac, size, "%s/%s", MOTHERBOARD, bus_type);
	}
}

/*
 * This function copies the node's model into model string
 *
 */
int
erie_get_model(picl_nodehdl_t nodeh, char model[], int size)
{
	int err;
	char tmp_model[MAXSTRLEN];

	/* Get the model of this node */
	err = picl_get_propval_by_name(nodeh, OBP_PROP_MODEL,
	    &tmp_model, size);
	if (err == PICL_PROPNOTFOUND) {
		(void) strcpy(model, "");
		err = PICL_SUCCESS;
	} else {
		(void) strcpy(model, tmp_model);
	}
	return (err);
}

/*
 * This function copies the node's class into class string
 *
 */
int
erie_get_class(picl_nodehdl_t nodeh, char piclclass[], int size)
{
	int err;
	err = picl_get_propval_by_name(nodeh, PICL_PROP_CLASSNAME,
	    piclclass, size);
	return (err);
}
