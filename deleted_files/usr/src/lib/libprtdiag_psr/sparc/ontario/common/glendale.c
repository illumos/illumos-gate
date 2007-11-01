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
 *      machine_type ==  Glendale
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
#include "glendale_common.h"
#include "glendale.h"

/* prototypes for local functions */
static void glendale_get_bus_type(char *path, struct io_card *card);
static void glendale_get_slot_number(char *path, struct io_card *card);
static int glendale_get_network_instance(char *path);
static int glendale_get_usb_instance(char *path);
static int glendale_get_io_instance(char *path, char *type);
static int glendale_get_first_compatible_value(picl_nodehdl_t nodeh,
    char **outbuf);
static int64_t glendale_get_int_propval(picl_nodehdl_t modh, char *prop_name,
    int *ret);

/* ARGSUSED */
int
glendale_pci_callback(picl_nodehdl_t pcih, void *args)
{
	int		err = PICL_SUCCESS;
	picl_nodehdl_t	nodeh;
	char		path[MAXSTRLEN];
	char		parent_path[MAXSTRLEN];
	char		piclclass[PICL_CLASSNAMELEN_MAX];
	char		name[MAXSTRLEN];
	char		model[MAXSTRLEN];
	char		*compatible;
	char		binding_name[MAXSTRLEN];
	struct io_card	pci_card;
	int32_t		instance;
	char		pn_type;

	err = picl_get_propval_by_name(pcih, PICL_PROP_DEVFS_PATH, parent_path,
	    sizeof (parent_path));
	if (err != PICL_SUCCESS)
		return (err);

	/* Walk through the children */

	err = picl_get_propval_by_name(pcih, PICL_PROP_CHILD, &nodeh,
	    sizeof (picl_nodehdl_t));

	while (err == PICL_SUCCESS) {
		err = picl_get_propval_by_name(nodeh, PICL_PROP_CLASSNAME,
		    piclclass, sizeof (piclclass));
		if (err !=  PICL_SUCCESS)
			return (err);

		if (strcmp(piclclass, PICL_CLASS_PCIEX) == 0) {
			err = picl_get_propval_by_name(nodeh, PICL_PROP_PEER,
			    &nodeh, sizeof (picl_nodehdl_t));
			continue;
		}

		if (strcmp(piclclass, PICL_CLASS_PCI) == 0) {
			err = picl_get_propval_by_name(nodeh, PICL_PROP_CHILD,
			    &nodeh, sizeof (picl_nodehdl_t));
			continue;
		}

		err = picl_get_propval_by_name(nodeh, PICL_PROP_DEVFS_PATH,
		    path, sizeof (path));
		if (err != PICL_SUCCESS)
			return (err);

		(void) strlcpy(pci_card.notes, path, sizeof (pci_card.notes));

		glendale_get_bus_type(path, &pci_card);

		/* NIU may need parent path */
		glendale_get_slot_number(path, &pci_card);

		err = picl_get_propval_by_name(nodeh, PICL_PROP_NAME, &name,
		    sizeof (name));
		if (err == PICL_PROPNOTFOUND)
			(void) strlcpy(name, "", sizeof (name));
		else if (err != PICL_SUCCESS)
			return (err);

		/* Figure NAC name */
		if ((strcmp(name, NETWORK) == 0) &&
		    (strcmp(pci_card.slot_str, MOTHERBOARD) == 0)) {
			instance = glendale_get_network_instance(path);
			(void) snprintf(pci_card.status,
			    sizeof (pci_card.status), "%s/%s%d",
			    MOTHERBOARD, "NET", instance);

		} else if ((strcmp(name, LSI_SAS) == 0) &&
		    (strcmp(pci_card.slot_str, MOTHERBOARD) == 0)) {
			(void) snprintf(pci_card.status,
			    sizeof (pci_card.status), "%s/%s/%s",
			    MOTHERBOARD, GLENDALE_REM, GLENDALE_SCSI_TAG);

		} else if ((strcmp(name, DISPLAY) == 0) &&
		    (strcmp(pci_card.slot_str, MOTHERBOARD) == 0)) {
			(void) snprintf(pci_card.status,
			    sizeof (pci_card.status), "%s/%s",
			    MOTHERBOARD, GLENDALE_DISPLAY);

		} else {
			if (pci_card.slot != -1) {
				(void) snprintf(pci_card.status,
				    sizeof (pci_card.status), "%s/%s%d",
				    MOTHERBOARD, pci_card.bus_type,
				    pci_card.slot);
			} else {
				(void) snprintf(pci_card.status,
				    sizeof (pci_card.status), "%s/%s",
				    MOTHERBOARD, pci_card.bus_type);
			}
		}

		/* Special case for USB */
		if (strncmp(name, USB, strlen(USB)) == 0) {
			instance = glendale_get_usb_instance(path);
			if (instance != -1)
				(void) snprintf(pci_card.status,
				    sizeof (pci_card.status), "%s/%s%d",
				    MOTHERBOARD, "USB", instance);
		}

		/* PCIEM/NEM case is handled here */
		if ((instance = glendale_get_io_instance(path, &pn_type))
		    != -1) {
			if (pn_type == GLENDALE_PCIEM_TYPE)
				(void) snprintf(pci_card.status,
				    sizeof (pci_card.status), "%s/%s%d",
				    MOTHERBOARD, "PCI-EM", instance);
			else if (pn_type == GLENDALE_NEM_TYPE)
				(void) snprintf(pci_card.status,
				    sizeof (pci_card.status), "%s/%s%d",
				    MOTHERBOARD, "NEM", instance);
		}
		/*
		 * Get the name of this card. If binding_name is found,
		 * name will be <nodename>-<binding_name>
		 */

		err = picl_get_propval_by_name(nodeh, PICL_PROP_BINDING_NAME,
		    &binding_name, sizeof (binding_name));
		if (err == PICL_PROPNOTFOUND) {
			/*
			 * if compatible prop is found, name will be
			 * <nodename>-<compatible>
			 */
			err = glendale_get_first_compatible_value(nodeh,
			    &compatible);
			if (err == PICL_SUCCESS) {
				(void) strlcat(name, "-", MAXSTRLEN);
				(void) strlcat(name, compatible, MAXSTRLEN);
				free(compatible);
			} else if (err != PICL_PROPNOTFOUND)
				return (err);
		} else if (err != PICL_SUCCESS)
			return (err);
		else if (strcmp(name, binding_name) != 0) {
			(void) strlcat(name, "-", MAXSTRLEN);
			(void) strlcat(name, binding_name, MAXSTRLEN);
		}

		(void) strlcpy(pci_card.name, name, sizeof (pci_card.name));

		/* Get the model of this card */

		err = picl_get_propval_by_name(nodeh, OBP_PROP_MODEL,
		    &model, sizeof (model));
		if (err == PICL_PROPNOTFOUND)
			(void) strlcpy(model, "", sizeof (model));
		else if (err != PICL_SUCCESS)
			return (err);
		(void) strlcpy(pci_card.model, model, sizeof (pci_card.model));

		/* Print NAC name */
		log_printf("%-11s", pci_card.status);
		/* Print IO Type */
		log_printf("%6s", pci_card.bus_type);
		/* Print Slot # */
		log_printf("%5s", pci_card.slot_str);
		/* Print Parent Path */
		log_printf("%46.45s", pci_card.notes);
		/* Printf Card Name */
		if (strlen(pci_card.name) > 24)
			log_printf("%25.24s+", pci_card.name);
		else
			log_printf("%26s", pci_card.name);
		/* Print Card Model */
		if (strlen(pci_card.model) > 10)
			log_printf("%10.9s+", pci_card.model);
		else
			log_printf("%10s", pci_card.model);
		log_printf("\n");

		err = picl_get_propval_by_name(nodeh, PICL_PROP_PEER, &nodeh,
		    sizeof (picl_nodehdl_t));

	}

	return (PICL_WALK_CONTINUE);
}

/* ARGSUSED */
int
glendale_hw_rev_callback(picl_nodehdl_t pcih, void *args)
{
	int		err = PICL_SUCCESS;
	char		path[MAXSTRLEN];
	char		device_path[MAXSTRLEN];
	char		NAC[MAXSTRLEN];
	char		*compatible;
	int32_t		revision;
	int		device_found = 0;
	char		name[MAXSTRLEN];
	picl_nodehdl_t	nodeh;

	err = picl_get_propval_by_name(pcih, PICL_PROP_DEVFS_PATH, path,
	    sizeof (path));
	if (err != PICL_SUCCESS)
		return (err);

	/* usb is special as a child of PCIE2PCI bridge */
	if (strcmp(path, GLENDALE_PCIE2PCI) == 0) {
		err = picl_get_propval_by_name(pcih, PICL_PROP_CHILD, &nodeh,
		    sizeof (picl_nodehdl_t));
		if (err != PICL_SUCCESS)
			return (err);
		err = picl_get_propval_by_name(nodeh, PICL_PROP_NAME, &name,
		    sizeof (name));
		if (err != PICL_SUCCESS)
			return (err);
		if (strcmp(name, USB) == 0) {
			err = glendale_hw_rev_callback(nodeh, &nodeh);
			if (err != PICL_SUCCESS)
				return (err);
		}
	}

	if ((strcmp(path, GLENDALE_NETWORK_0_PATH) == 0)) {
		device_found = 1;
		(void) snprintf(NAC, sizeof (NAC), "%s/%s%d", MOTHERBOARD,
		    OPHIR, 0);
		revision = glendale_get_int_propval(pcih, OBP_PROP_REVISION_ID,
		    &err);
	}

	if ((strcmp(path, GLENDALE_USB0_PATH) == 0) ||
	    (strcmp(path, GLENDALE_USB1_PATH) == 0) ||
	    (strcmp(path, GLENDALE_USB2_PATH) == 0) ||
	    (strcmp(path, GLENDALE_USB3_PATH) == 0) ||
	    (strcmp(path, GLENDALE_USB4_PATH) == 0) ||
	    (strcmp(path, GLENDALE_USB5_PATH) == 0) ||
	    (strcmp(path, GLENDALE_USB6_PATH) == 0)) {
		device_found = 1;
		(void) snprintf(NAC, sizeof (NAC), "%s/%s%d", MOTHERBOARD,
		    USB_TAG, 0);
		revision = glendale_get_int_propval(pcih, OBP_PROP_REVISION_ID,
		    &err);
	}

	if ((strcmp(path, HBA_PATH) == 0)) {
		device_found = 1;
		(void) snprintf(NAC, sizeof (NAC), "%s/%s", MOTHERBOARD,
		    "IO-BRIDGE");
		revision = glendale_get_int_propval(pcih, OBP_PROP_VERSION_NUM,
		    &err);
	}

	if (strcmp(path, SWITCH_PATH) == 0) {
		device_found = 1;
		(void) snprintf(NAC, sizeof (NAC), "%s/%s", MOTHERBOARD,
		    SWITCH);
		revision = glendale_get_int_propval(pcih, OBP_PROP_REVISION_ID,
		    &err);
	}

	if (strcmp(path, GLENDALE_LSI_PATH) == 0) {
		device_found = 1;
		(void) snprintf(NAC, sizeof (NAC), "%s/%s/%s", MOTHERBOARD,
		    GLENDALE_REM, GLENDALE_SAS_HBA);
		revision = glendale_get_int_propval(pcih, OBP_PROP_REVISION_ID,
		    &err);
	}

	if (strcmp(path, GLENDALE_DISPLAY_PATH) == 0) {
		device_found = 1;
		(void) snprintf(NAC, sizeof (NAC), "%s/%s", MOTHERBOARD,
		    GLENDALE_DISPLAY);
		revision = glendale_get_int_propval(pcih, OBP_PROP_REVISION_ID,
		    &err);
	}

	if (strcmp(path, GLENDALE_PCIE2PCI) == 0) {
		device_found = 1;
		(void) snprintf(NAC, sizeof (NAC), "%s/%s", MOTHERBOARD,
		    PCI_BRIDGE);
		revision = glendale_get_int_propval(pcih, OBP_PROP_REVISION_ID,
		    &err);
	}

	if (device_found == 1) {

		(void) strlcpy(device_path, path, sizeof (device_path));
		err = glendale_get_first_compatible_value(pcih, &compatible);

		if (err != PICL_SUCCESS)
			return (err);

		/* Print NAC name */
		log_printf("%-20s", NAC);
		/* Print Device Path */
		if (strlen(device_path) > 38)
			log_printf("%38.37s+", device_path);
		else
			log_printf("%39s", device_path);
		/* Print Compatible # */
		log_printf("%31s", compatible);
		free(compatible);
		/* Print Revision */
		log_printf("%6d", revision);
		log_printf("\n");
	}

	return (PICL_WALK_CONTINUE);
}

static void
glendale_get_bus_type(char *path, struct io_card *card)
{
	if (strncmp(path, GLENDALE_PCIE_PCIEM0,
	    strlen(GLENDALE_PCIE_PCIEM0)) == 0) {
		(void) strlcpy(card->bus_type, "PCIE", sizeof (card->bus_type));
	} else if (strncmp(path, GLENDALE_PCIE_PCIEM1,
	    strlen(GLENDALE_PCIE_PCIEM1)) == 0) {
		(void) strlcpy(card->bus_type, "PCIE", sizeof (card->bus_type));
	} else if (strncmp(path, GLENDALE_PCIE_NEM0, strlen(GLENDALE_PCIE_NEM0))
	    == 0) {
		(void) strlcpy(card->bus_type, "PCIE", sizeof (card->bus_type));
	} else if (strncmp(path, GLENDALE_PCIE_NEM1, strlen(GLENDALE_PCIE_NEM1))
	    == 0) {
		(void) strlcpy(card->bus_type, "PCIE", sizeof (card->bus_type));
	} else if (strncmp(path, SWITCH_PATH, strlen(SWITCH_PATH)) == 0) {
		(void) strlcpy(card->bus_type, "PCIE", sizeof (card->bus_type));
	} else if (strncmp(path, GLENDALE_NIU, strlen(GLENDALE_NIU)) == 0) {
		(void) strlcpy(card->bus_type, "NIU", sizeof (card->bus_type));
	} else {
		(void) strlcpy(card->bus_type, "NONE", sizeof (card->bus_type));
	}
}

static void
glendale_get_slot_number(char *path, struct io_card *card)
{
	if (strncmp(path, GLENDALE_N2_XAUI0, strlen(GLENDALE_N2_XAUI0)) == 0) {
		(void) strlcpy(card->slot_str, "0", sizeof (card->slot_str));
		card->slot = 0;
	} else if (strncmp(path, GLENDALE_N2_XAUI1, strlen(GLENDALE_N2_XAUI1))
	    == 0) {
		(void) strlcpy(card->slot_str, "1", sizeof (card->slot_str));
		card->slot = 1;
	} else if (strncmp(path, GLENDALE_PCIE_PCIEM0,
	    strlen(GLENDALE_PCIE_PCIEM0)) == 0) {
		(void) strlcpy(card->slot_str, "0", sizeof (card->slot_str));
		card->slot = 0;
	} else if (strncmp(path, GLENDALE_PCIE_NEM0, strlen(GLENDALE_PCIE_NEM0))
	    == 0) {
		(void) strlcpy(card->slot_str, "0", sizeof (card->slot_str));
		card->slot = 0;
	} else if (strncmp(path, GLENDALE_PCIE_PCIEM1,
	    strlen(GLENDALE_PCIE_PCIEM1)) == 0) {
		(void) strlcpy(card->slot_str, "1", sizeof (card->slot_str));
		card->slot = 1;
	} else if (strncmp(path, GLENDALE_PCIE_NEM1, strlen(GLENDALE_PCIE_NEM1))
	    == 0) {
		(void) strlcpy(card->slot_str, "1", sizeof (card->slot_str));
		card->slot = 1;
	} else {
		(void) strlcpy(card->slot_str, MOTHERBOARD,
		    sizeof (card->slot_str));
		card->slot = -1;
	}
}

static int
glendale_get_network_instance(char *path)
{
	if (strncmp(path, GLENDALE_NETWORK_1_PATH,
	    strlen(GLENDALE_NETWORK_1_PATH)) == 0)
		return (1);
	else if (strncmp(path, GLENDALE_NETWORK_0_PATH,
	    strlen(GLENDALE_NETWORK_0_PATH)) == 0)
		return (0);
	else if (strncmp(path, GLENDALE_N2_XAUI1,
	    strlen(GLENDALE_N2_XAUI1)) == 0)
		return (1);
	else if (strncmp(path, GLENDALE_N2_XAUI0,
	    strlen(GLENDALE_N2_XAUI0)) == 0)
		return (0);
	else
		return (-1);
}

static int
glendale_get_usb_instance(char *path)
{
	if (strncmp(path, GLENDALE_USB6_PATH,
	    strlen(GLENDALE_USB6_PATH)) == 0)
		return (6);
	else if (strncmp(path, GLENDALE_USB5_PATH,
	    strlen(GLENDALE_USB5_PATH)) == 0)
		return (5);
	else if (strncmp(path, GLENDALE_USB4_PATH,
	    strlen(GLENDALE_USB4_PATH)) == 0)
		return (4);
	else if (strncmp(path, GLENDALE_USB3_PATH,
	    strlen(GLENDALE_USB3_PATH)) == 0)
		return (3);
	else if (strncmp(path, GLENDALE_USB2_PATH,
	    strlen(GLENDALE_USB2_PATH)) == 0)
		return (2);
	else if (strncmp(path, GLENDALE_USB1_PATH,
	    strlen(GLENDALE_USB1_PATH)) == 0)
		return (1);
	else if (strncmp(path, GLENDALE_USB0_PATH,
	    strlen(GLENDALE_USB0_PATH)) == 0)
		return (0);
	else
		return (-1);
}

static int
glendale_get_io_instance(char *path, char *type)
{
	if (strncmp(path, GLENDALE_PCIE_PCIEM1,
	    strlen(GLENDALE_PCIE_PCIEM1)) == 0) {
		*type = GLENDALE_PCIEM_TYPE;
		return (1);
	} else if (strncmp(path, GLENDALE_PCIE_PCIEM0,
	    strlen(GLENDALE_PCIE_PCIEM0)) == 0) {
		*type = GLENDALE_PCIEM_TYPE;
		return (0);
	} else if (strncmp(path, GLENDALE_PCIE_NEM1, strlen(GLENDALE_PCIE_NEM1))
	    == 0) {
		*type = GLENDALE_NEM_TYPE;
		return (1);
	} else if (strncmp(path, GLENDALE_PCIE_NEM0, strlen(GLENDALE_PCIE_NEM0))
	    == 0) {
		*type = GLENDALE_NEM_TYPE;
		return (0);
	} else
		return (-1);
}
/*
 * return the first compatible value
 */
static int
glendale_get_first_compatible_value(picl_nodehdl_t nodeh, char **outbuf)
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

static int64_t
glendale_get_int_propval(picl_nodehdl_t modh, char *prop_name, int *ret)
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
	    (pinfo.type != PICL_PTYPE_UNSIGNED_INT)) {
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
