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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2020 Peter Tribble.
 */

#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <kvm.h>
#include <varargs.h>
#include <time.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/openpromio.h>
#include <libintl.h>
#include <syslog.h>
#include <sys/dkio.h>
#include <sys/systeminfo.h>
#include <picldefs.h>
#include <math.h>
#include <errno.h>
#include "pdevinfo.h"
#include "display.h"
#include "display_sun4v.h"
#include "libprtdiag.h"

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

#define	MOTHERBOARD			"MB"
#define	NETWORK				"network"
#define	SUN4V_MACHINE			"sun4v"
#define	PARENT_NAMES			10

/*
 * Additional OBP properties
 */
#define	OBP_PROP_COMPATIBLE		"compatible"
#define	OBP_PROP_MODEL			"model"
#define	OBP_PROP_SLOT_NAMES		"slot-names"
#define	OBP_PROP_VERSION		"version"

#define	PICL_NODE_PHYSICAL_PLATFORM	"physical-platform"
#define	PICL_NODE_CHASSIS		"chassis"
#define	MEMORY_SIZE_FIELD		11
#define	INVALID_THRESHOLD		1000000

/*
 * Additional picl classes
 */
#ifndef	PICL_CLASS_SUN4V
#define	PICL_CLASS_SUN4V		"sun4v"
#endif

#ifndef	PICL_PROP_NAC
#define	PICL_PROP_NAC			"nac"
#endif

extern int sys_clk;
extern picl_errno_t sun4v_get_node_by_name(picl_nodehdl_t, char *,
	picl_nodehdl_t *);

static picl_nodehdl_t rooth = 0, phyplatformh = 0;
static picl_nodehdl_t chassish = 0;
static int class_node_found;
static int syserrlog;
static int all_status_ok;

/* local functions */
static int sun4v_get_first_compatible_value(picl_nodehdl_t, char **);
static void sun4v_display_memory_conf(picl_nodehdl_t);
static int sun4v_disp_env_status();
static void sun4v_env_print_fan_sensors();
static void sun4v_env_print_fan_indicators();
static void sun4v_env_print_temp_sensors();
static void sun4v_env_print_temp_indicators();
static void sun4v_env_print_current_sensors();
static void sun4v_env_print_current_indicators();
static void sun4v_env_print_voltage_sensors();
static void sun4v_env_print_voltage_indicators();
static void sun4v_env_print_LEDs();
static void sun4v_print_fru_status();
static int is_fru_absent(picl_nodehdl_t);
static void sun4v_print_fw_rev();
static void sun4v_print_chassis_serial_no();
static int openprom_callback(picl_nodehdl_t openpromh, void *arg);
static void sun4v_print_openprom_rev();

int
sun4v_display(Sys_tree *tree, Prom_node *root, int log,
	picl_nodehdl_t plafh)
{
	void *value;		/* used for opaque PROM data */
	struct mem_total memory_total;	/* Total memory in system */
	char machine[MAXSTRLEN];
	int	exit_code = 0;

	if (sysinfo(SI_MACHINE, machine, sizeof (machine)) == -1)
		return (1);
	if (strncmp(machine, SUN4V_MACHINE, strlen(SUN4V_MACHINE)) != 0)
		return (1);

	sys_clk = -1;  /* System clock freq. (in MHz) */

	/*
	 * Now display the machine's configuration. We do this if we
	 * are not logging.
	 */
	if (!logging) {
		struct utsname uts_buf;

		/*
		 * Display system banner
		 */
		(void) uname(&uts_buf);

		log_printf(dgettext(TEXT_DOMAIN, "System Configuration:  "
		    "Oracle Corporation  %s %s\n"), uts_buf.machine,
		    get_prop_val(find_prop(root, "banner-name")), 0);

		/* display system clock frequency */
		value = get_prop_val(find_prop(root, "clock-frequency"));
		if (value != NULL) {
			sys_clk = ((*((int *)value)) + 500000) / 1000000;
			log_printf(dgettext(TEXT_DOMAIN, "System clock "
			    "frequency: %d MHz\n"), sys_clk, 0);
		}

		/* Display the Memory Size */
		display_memorysize(tree, NULL, &memory_total);

		/* Display the CPU devices */
		sun4v_display_cpu_devices(plafh);

		/* Display the Memory configuration */
		class_node_found = 0;
		sun4v_display_memory_conf(plafh);

		/* Display all the IO cards. */
		(void) sun4v_display_pci(plafh);
		sun4v_display_diaginfo((log || (logging)), root, plafh);

		if (picl_get_root(&rooth) != PICL_SUCCESS)
			return (1);

		/*
		 * The physical-platform node may be missing on systems with
		 * older firmware so don't consider that an error.
		 */
		if (sun4v_get_node_by_name(rooth, PICL_NODE_PHYSICAL_PLATFORM,
		    &phyplatformh) != PICL_SUCCESS)
			return (0);

		if (picl_find_node(phyplatformh, PICL_PROP_CLASSNAME,
		    PICL_PTYPE_CHARSTRING, (void *)PICL_CLASS_CHASSIS,
		    strlen(PICL_CLASS_CHASSIS), &chassish) != PICL_SUCCESS)
			return (1);

		syserrlog = log;
		exit_code = sun4v_disp_env_status();
	}
	return (exit_code);
}

/*
 * The binding-name property encodes the bus type.
 */
static void
get_bus_type(picl_nodehdl_t nodeh, struct io_card *card)
{
	char val[PICL_PROPNAMELEN_MAX], *p, *q;

	card->bus_type[0] = '\0';

	if (picl_get_propval_by_name(nodeh, PICL_PROP_BINDING_NAME, val,
	    sizeof (val)) == PICL_SUCCESS) {
		if (strstr(val, PICL_CLASS_PCIEX))
			(void) strlcpy(card->bus_type, "PCIE",
			    sizeof (card->bus_type));
		else if (strstr(val, PICL_CLASS_PCI))
			(void) strlcpy(card->bus_type, "PCIX",
			    sizeof (card->bus_type));
		else {
			/*
			 * Not perfect: process the binding-name until
			 * we encounter something that we don't think would
			 * be part of a bus type.  This may get confused a bit
			 * if a device or vendor id is encoded right after
			 * the bus class since there's no delimiter.  If the
			 * id number begins with a hex digit [abcdef] then
			 * this will become part of the bus type string
			 * reported by prtdiag.  This is all an effort to
			 * print something potentially useful for bus types
			 * other than PCI/PCIe.
			 *
			 * We do this because this code will get called for
			 * non-PCI class devices like the xaui (class sun4v.)
			 */
			if (strstr(val, "SUNW,") != NULL)
				p = strchr(val, ',') + 1;
			else
				p = val;
			q = p;
			while (*p != '\0') {
				if (isdigit((char)*p) || ispunct((char)*p)) {
					*p = '\0';
					break;
				}
				*p = (char)_toupper((int)*p);
				++p;
			}
			(void) strlcpy(card->bus_type, q,
			    sizeof (card->bus_type));
		}
	}
}

/*
 * Fetch the Label property for this device.  If none is found then
 * search all the siblings with the same device ID for a
 * Label and return that Label.  The plug-in can only match the canonical
 * path from the PRI with a specific devfs path.  So we take care of
 * devices with multiple functions here.  A leaf device downstream of
 * a bridge should fall out of here with PICL_PROPNOTFOUND, and the
 * caller can walk back up the tree in search of the slot's Label.
 */
static picl_errno_t
get_slot_label(picl_nodehdl_t nodeh, struct io_card *card)
{
	char val[PICL_PROPNAMELEN_MAX];
	picl_errno_t err;
	picl_nodehdl_t pnodeh;
	uint32_t devid, sib_devid;
	int32_t instance;

	/*
	 * If there's a Label at this node then return it - we're
	 * done.
	 */
	err = picl_get_propval_by_name(nodeh, PICL_PROP_LABEL, val,
	    sizeof (val));
	if (err == PICL_SUCCESS) {
		(void) strlcpy(card->slot_str, val, sizeof (card->slot_str));
		return (err);
	} else if (err != PICL_PROPNOTFOUND)
		return (err);

	/*
	 * At this point we're starting to extrapolate what the Label
	 * should be since there is none at this specific node.
	 * Note that until the value of "err" is overwritten in the
	 * loop below, its value should be PICL_PROPNOTFOUND.
	 */

	/*
	 * The device must be attached, and we can figure that out if
	 * the instance number is present and is not equal to -1.
	 * This will prevent is from returning a Label for a sibling
	 * node when the node passed in would have a unique Label if the
	 * device were attached.  But if the device is downstream of a
	 * node with a Label then pci_callback() will still find that
	 * and use it.
	 */
	if (picl_get_propval_by_name(nodeh, PICL_PROP_INSTANCE, &instance,
	    sizeof (instance)) != PICL_SUCCESS)
		return (err);
	if (instance == -1)
		return (err);

	/*
	 * Narrow the search to just the one device ID.
	 */
	if (picl_get_propval_by_name(nodeh, PICL_PROP_DEVICE_ID, &devid,
	    sizeof (devid)) != PICL_SUCCESS)
		return (err);

	/*
	 * Go find the first child of the parent so we can search
	 * all of the siblings.
	 */
	if (picl_get_propval_by_name(nodeh, PICL_PROP_PARENT, &pnodeh,
	    sizeof (pnodeh)) != PICL_SUCCESS)
		return (err);
	if (picl_get_propval_by_name(pnodeh, PICL_PROP_CHILD, &pnodeh,
	    sizeof (pnodeh)) != PICL_SUCCESS)
		return (err);

	/*
	 * If the child's device ID matches, then fetch the Label and
	 * return it.  The first child/device ID should have a Label
	 * associated with it.
	 */
	do {
		if (picl_get_propval_by_name(pnodeh, PICL_PROP_DEVICE_ID,
		    &sib_devid, sizeof (sib_devid)) == PICL_SUCCESS) {
			if (sib_devid == devid) {
				if ((err = picl_get_propval_by_name(pnodeh,
				    PICL_PROP_LABEL, val, sizeof (val))) ==
				    PICL_SUCCESS) {
					(void) strlcpy(card->slot_str, val,
					    sizeof (card->slot_str));
					break;
				}
			}
		}
	} while (picl_get_propval_by_name(pnodeh, PICL_PROP_PEER, &pnodeh,
	    sizeof (pnodeh)) == PICL_SUCCESS);

	return (err);
}

static void
get_slot_number(picl_nodehdl_t nodeh, struct io_card *card)
{
	picl_errno_t err;
	picl_prophdl_t proph;
	picl_propinfo_t pinfo;
	picl_nodehdl_t pnodeh;
	uint8_t *pval;
	uint32_t dev_mask;
	char uaddr[MAXSTRLEN];
	int i;

	err = PICL_SUCCESS;
	while (err == PICL_SUCCESS) {
		if (picl_get_propval_by_name(nodeh, PICL_PROP_PARENT, &pnodeh,
		    sizeof (pnodeh)) != PICL_SUCCESS) {
			(void) strlcpy(card->slot_str, MOTHERBOARD,
			    sizeof (card->slot_str));
			card->slot = -1;
			return;
		}
		if (picl_get_propinfo_by_name(pnodeh, OBP_PROP_SLOT_NAMES,
		    &pinfo, &proph) == PICL_SUCCESS) {
			break;
		}
		nodeh = pnodeh;
	}
	if (picl_get_propval_by_name(nodeh, PICL_PROP_UNIT_ADDRESS, uaddr,
	    sizeof (uaddr)) != PICL_SUCCESS) {
		(void) strlcpy(card->slot_str, MOTHERBOARD,
		    sizeof (card->slot_str));
		card->slot = -1;
		return;
	}
	pval = (uint8_t *)malloc(pinfo.size);
	if (!pval) {
		(void) strlcpy(card->slot_str, MOTHERBOARD,
		    sizeof (card->slot_str));
		card->slot = -1;
		return;
	}
	if (picl_get_propval(proph, pval, pinfo.size) != PICL_SUCCESS) {
		(void) strlcpy(card->slot_str, MOTHERBOARD,
		    sizeof (card->slot_str));
		card->slot = -1;
		free(pval);
		return;
	}

	dev_mask = 0;
	for (i = 0; i < sizeof (dev_mask); i++)
		dev_mask |= (*(pval+i) << 8*(sizeof (dev_mask)-1-i));
	for (i = 0; i < sizeof (uaddr) && uaddr[i] != '\0'; i++) {
		if (uaddr[i] == ',') {
			uaddr[i] = '\0';
			break;
		}
	}
	card->slot = atol(uaddr);
	if (((1 << card->slot) & dev_mask) == 0) {
		(void) strlcpy(card->slot_str, MOTHERBOARD,
		    sizeof (card->slot_str));
		card->slot = -1;
	} else {
		char *p = (char *)(pval+sizeof (dev_mask));
		int shift = sizeof (uint32_t)*8-1-card->slot;
		uint32_t x = (dev_mask << shift) >> shift;
		int count = 0;	/* count # of 1's in x */
		int i = 0;
		while (x != 0) {
			count++;
			x &= x-1;
		}
		while (count > 1) {
			while (p[i++] != '\0')
				;
			count--;
		}
		(void) strlcpy(card->slot_str, (char *)(p+i),
		    sizeof (card->slot_str));
	}
	free(pval);
}

/*
 * add all io devices under pci in io list
 */
/* ARGSUSED */
static int
sun4v_pci_callback(picl_nodehdl_t pcih, void *args)
{
	char path[PICL_PROPNAMELEN_MAX];
	char class[PICL_CLASSNAMELEN_MAX];
	char name[PICL_PROPNAMELEN_MAX];
	char model[PICL_PROPNAMELEN_MAX];
	char binding_name[PICL_PROPNAMELEN_MAX];
	char val[PICL_PROPNAMELEN_MAX];
	char *compatible;
	picl_errno_t err;
	picl_nodehdl_t nodeh, pnodeh;
	struct io_card pci_card;

	/* Walk through the children */

	err = picl_get_propval_by_name(pcih, PICL_PROP_CHILD, &nodeh,
	    sizeof (picl_nodehdl_t));

	while (err == PICL_SUCCESS) {
		err = picl_get_propval_by_name(nodeh, PICL_PROP_CLASSNAME,
		    class, sizeof (class));
		if (err !=  PICL_SUCCESS)
			return (err);

		if (args) {
			char *val = args;
			if (strcmp(class, val) == 0) {
				err = picl_get_propval_by_name(nodeh,
				    PICL_PROP_PEER, &nodeh,
				    sizeof (picl_nodehdl_t));
				continue;
			} else if (strcmp(val, PICL_CLASS_PCIEX) == 0 &&
			    strcmp(class, PICL_CLASS_PCI) == 0) {
				err = picl_get_propval_by_name(nodeh,
				    PICL_PROP_PEER, &nodeh,
				    sizeof (picl_nodehdl_t));
				continue;
			} else if (strcmp(val, PICL_CLASS_PCI) == 0 &&
			    strcmp(class, PICL_CLASS_PCIEX) == 0) {
				err = picl_get_propval_by_name(nodeh,
				    PICL_PROP_PEER, &nodeh,
				    sizeof (picl_nodehdl_t));
				continue;
			}
		}

		err = picl_get_propval_by_name(nodeh, PICL_PROP_DEVFS_PATH,
		    path, sizeof (path));
		if (err != PICL_SUCCESS)
			return (err);

		(void) strlcpy(pci_card.notes, path, sizeof (pci_card.notes));

		pnodeh = nodeh;
		err = get_slot_label(nodeh, &pci_card);

		/*
		 * No Label at this node, maybe we're looking at a device
		 * downstream of a bridge.  Walk back up and find a Label and
		 * record that node in "pnodeh".
		 */
		while (err != PICL_SUCCESS) {
			if (err != PICL_PROPNOTFOUND)
				break;
			else if (picl_get_propval_by_name(pnodeh,
			    PICL_PROP_PARENT, &pnodeh, sizeof (pnodeh)) ==
			    PICL_SUCCESS)
				err = get_slot_label(pnodeh, &pci_card);
			else
				break;
		}

		/*
		 * Can't find a Label for this device in the PCI heirarchy.
		 * Try to synthesize a slot name from atoms.  This depends
		 * on the OBP slot_names property being implemented, and this
		 * so far doesn't seem to be on sun4v.  But just in case that
		 * is resurrected, the code is here.
		 */
		if (err != PICL_SUCCESS) {
			pnodeh = nodeh;
			get_slot_number(nodeh, &pci_card);
		}

		/*
		 * Passing in pnodeh instead of nodeh will cause prtdiag
		 * to display the type of IO slot for the leaf node.  For
		 * built-in devices and a lot of IO cards these will be
		 * the same thing.  But for IO cards with bridge chips or
		 * for things like expansion chassis, prtdiag will report
		 * the bus type of the IO slot and not the leaf, which
		 * could be different things.
		 */
		get_bus_type(pnodeh, &pci_card);

		err = picl_get_propval_by_name(nodeh, PICL_PROP_NAME, name,
		    sizeof (name));
		if (err == PICL_PROPNOTFOUND)
			(void) strlcpy(name, "", sizeof (name));
		else if (err != PICL_SUCCESS)
			return (err);

		err = picl_get_propval_by_name(nodeh, PICL_PROP_STATUS, val,
		    sizeof (val));
		if (err == PICL_PROPNOTFOUND)
			(void) strlcpy(val, "", sizeof (val));
		else if (err != PICL_SUCCESS)
			return (err);

		(void) snprintf(pci_card.status, sizeof (pci_card.status),
		    "%s", pci_card.slot_str);

		/*
		 * Get the name of this card. If binding_name is found,
		 * name will be <nodename>-<binding_name>.
		 */
		err = picl_get_propval_by_name(nodeh, PICL_PROP_BINDING_NAME,
		    binding_name, sizeof (binding_name));
		if (err == PICL_SUCCESS) {
			if (strcmp(name, binding_name) != 0) {
				(void) strlcat(name, "-", sizeof (name));
				(void) strlcat(name, binding_name,
				    sizeof (name));
			}
		} else if (err == PICL_PROPNOTFOUND) {
			/*
			 * if compatible prop is not found, name will be
			 * <nodename>-<compatible>
			 */
			err = sun4v_get_first_compatible_value(nodeh,
			    &compatible);
			if (err == PICL_SUCCESS) {
				(void) strlcat(name, "-", sizeof (name));
				(void) strlcat(name, compatible,
				    sizeof (name));
				free(compatible);
			}
		} else
			return (err);

		(void) strlcpy(pci_card.name, name, sizeof (pci_card.name));

		/* Get the model of this card */

		err = picl_get_propval_by_name(nodeh, OBP_PROP_MODEL,
		    model, sizeof (model));
		if (err == PICL_PROPNOTFOUND)
			(void) strlcpy(model, "", sizeof (model));
		else if (err != PICL_SUCCESS)
			return (err);
		(void) strlcpy(pci_card.model, model, sizeof (pci_card.model));

		/* Print NAC name */
		log_printf("%-18s", pci_card.status);
		/* Print IO Type */
		log_printf("%-6s", pci_card.bus_type);
		/* Printf Card Name */
		log_printf("%-34s", pci_card.name);
		/* Print Card Model */
		log_printf("%-8s", pci_card.model);
		log_printf("\n");
		/* Print Status */
		log_printf("%-18s", val);
		/* Print IO Type */
		log_printf("%-6s", "");
		/* Print Parent Path */
		log_printf("%-44s", pci_card.notes);
		log_printf("\n");

		err = picl_get_propval_by_name(nodeh, PICL_PROP_PEER, &nodeh,
		    sizeof (picl_nodehdl_t));
	}
	return (PICL_WALK_CONTINUE);
}

/*
 * display_pci
 * Display all the PCI IO cards on this board.
 */
void
sun4v_display_pci(picl_nodehdl_t plafh)
{
	char *fmt = "%-17s %-5s %-33s %-8s";
	/* Have we printed the column headings? */
	static int banner = FALSE;

	if (banner == FALSE) {
		log_printf("\n");
		log_printf("================================");
		log_printf(" IO Devices ");
		log_printf("================================");
		log_printf("\n");
		log_printf(fmt, "Slot +", "Bus", "Name +", "Model", 0);
		log_printf("\n");
		log_printf(fmt, "Status", "Type", "Path", "", 0);
		log_printf("\n");
		log_printf("---------------------------------"
		    "-------------------------------------------\n");
		banner = TRUE;
	}

	(void) picl_walk_tree_by_class(plafh, PICL_CLASS_PCIEX,
	    PICL_CLASS_PCIEX, sun4v_pci_callback);
	(void) picl_walk_tree_by_class(plafh, PICL_CLASS_PCI,
	    PICL_CLASS_PCI, sun4v_pci_callback);
	(void) picl_walk_tree_by_class(plafh, PICL_CLASS_SUN4V,
	    PICL_CLASS_SUN4V, sun4v_pci_callback);
}

/*
 * return the first compatible value
 */
static int
sun4v_get_first_compatible_value(picl_nodehdl_t nodeh, char **outbuf)
{
	picl_errno_t err;
	picl_prophdl_t proph;
	picl_propinfo_t pinfo;
	picl_prophdl_t tblh;
	picl_prophdl_t rowproph;
	char *pval;

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
 * print size of a memory segment
 */
static void
print_memory_segment_size(uint64_t size)
{
	uint64_t kbyte = 1024;
	uint64_t mbyte = kbyte * kbyte;
	uint64_t gbyte = kbyte * mbyte;
	uint64_t tbyte = kbyte * gbyte;
	char buf[MEMORY_SIZE_FIELD];

	if (size >= tbyte) {
		if (size % tbyte == 0)
			(void) snprintf(buf, sizeof (buf), "%d TB",
			    (int)(size / tbyte));
		else
			(void) snprintf(buf, sizeof (buf), "%.2f TB",
			    (float)size / tbyte);
	} else if (size >= gbyte) {
		if (size % gbyte == 0)
			(void) snprintf(buf, sizeof (buf), "%d GB",
			    (int)(size / gbyte));
		else
			(void) snprintf(buf, sizeof (buf), "%.2f GB",
			    (float)size / gbyte);
	} else if (size >= mbyte) {
		if (size % mbyte == 0)
			(void) snprintf(buf, sizeof (buf), "%d MB",
			    (int)(size / mbyte));
		else
			(void) snprintf(buf, sizeof (buf), "%.2f MB",
			    (float)size / mbyte);
	} else {
		if (size % kbyte == 0)
			(void) snprintf(buf, sizeof (buf), "%d KB",
			    (int)(size / kbyte));
		else
			(void) snprintf(buf, sizeof (buf), "%.2f KB",
			    (float)size / kbyte);
	}
	log_printf("%-9s", buf);
}

/*
 * Enumerate banks and dimms within a memory segment.  We're handed
 * the first bank within the segment - we assume there are dimms
 * (memory-module) nodes underneath.
 */
static void
print_memory_segment_contain(picl_nodehdl_t bank_nodeh)
{
	char val[PICL_PROPNAMELEN_MAX];
	picl_nodehdl_t module_nodeh;
	int flag = 0;
	uint64_t size;

	do {
		if (picl_get_propval_by_name(bank_nodeh, PICL_PROP_CHILD,
		    &module_nodeh, sizeof (picl_nodehdl_t)) != PICL_SUCCESS)
			continue;
		if (picl_get_propval_by_name(bank_nodeh, PICL_PROP_SIZE,
		    &size, sizeof (size)) == PICL_SUCCESS) {
			if (!flag) {
				print_memory_segment_size(size);
			} else {
				log_printf("                "
				    "                    ");
				print_memory_segment_size(size);
				flag = 0;
			}
		}
		do {
			if (picl_get_propval_by_name(module_nodeh,
			    PICL_PROP_NAC, val, sizeof (val)) !=
			    PICL_SUCCESS)
				continue;
			else {
				if (!flag) {
					log_printf("%s\n", val);
					flag = 1;
				} else {
					log_printf("%s%s\n",
					    "                       "
					    "                      ",
					    val);
				}
			}
		} while (picl_get_propval_by_name(module_nodeh, PICL_PROP_PEER,
		    &module_nodeh, sizeof (picl_nodehdl_t)) ==
		    PICL_SUCCESS);
	} while (picl_get_propval_by_name(bank_nodeh, PICL_PROP_PEER,
	    &bank_nodeh, sizeof (picl_nodehdl_t)) == PICL_SUCCESS);
}

/*
 * Search node where _class=="memory-segment"
 * print "Base Address", "Size", etc
 */
/*ARGSUSED*/
static int
sun4v_memory_conf_callback(picl_nodehdl_t nodeh, void *args)
{
	uint64_t base;
	uint64_t size;
	uint64_t ifactor;
	picl_errno_t err = PICL_SUCCESS;

	if (class_node_found == 0) {
		class_node_found = 1;
		return (PICL_WALK_TERMINATE);
	}
	while (err == PICL_SUCCESS) {
		err = picl_get_propval_by_name(nodeh, PICL_PROP_BASEADDRESS,
		    &base, sizeof (base));
		if (err !=  PICL_SUCCESS)
			break;
		err = picl_get_propval_by_name(nodeh, PICL_PROP_SIZE,
		    &size, sizeof (size));
		if (err !=  PICL_SUCCESS)
			break;
		err = picl_get_propval_by_name(nodeh,
		    PICL_PROP_INTERLEAVE_FACTOR, &ifactor,
		    sizeof (ifactor));
		if (err !=  PICL_SUCCESS)
			break;
		log_printf("0x%-13llx", base);
		print_memory_segment_size(size);
		log_printf("%-12lld", ifactor);
		err = picl_get_propval_by_name(nodeh, PICL_PROP_CHILD,
		    &nodeh, sizeof (nodeh));
		if (err ==  PICL_SUCCESS)
			print_memory_segment_contain(nodeh);
		log_printf("\n");
		err = picl_get_propval_by_name(nodeh, PICL_PROP_PEER, &nodeh,
		    sizeof (picl_nodehdl_t));
	}

	return (PICL_WALK_CONTINUE);
}

/*ARGSUSED*/
void
sun4v_display_memory_conf(picl_nodehdl_t plafh)
{
	char *fmt = "%-14s %-8s %-11s %-8s %-s";
	(void) picl_walk_tree_by_class(plafh, PICL_CLASS_MEMORY_SEGMENT,
	    NULL, sun4v_memory_conf_callback);
	if (class_node_found == 0)
		return;
	log_printf("\n");
	log_printf("=======================");
	log_printf(" Physical Memory Configuration ");
	log_printf("========================");
	log_printf("\n");
	log_printf("Segment Table:\n");
	log_printf(
	    "--------------------------------------------------------------\n");
	log_printf(fmt, "Base", "Segment", "Interleave", "Bank", "Contains", 0);
	log_printf("\n");
	log_printf(fmt, "Address", "Size", "Factor", "Size", "Modules", 0);
	log_printf("\n");
	log_printf(
	    "--------------------------------------------------------------\n");
	(void) picl_walk_tree_by_class(plafh, PICL_CLASS_MEMORY_SEGMENT,
	    NULL, sun4v_memory_conf_callback);
}

void
sun4v_display_cpu_devices(picl_nodehdl_t plafh)
{
	char *fmt = "%-6s %-9s %-22s %-6s";

	/*
	 * Display the table header for CPUs . Then display the CPU
	 * frequency, cache size, and processor revision of all cpus.
	 */
	log_printf(dgettext(TEXT_DOMAIN,
	    "\n"
	    "================================"
	    " Virtual CPUs "
	    "================================"
	    "\n"
	    "\n"));
	log_printf("\n");
	log_printf(fmt, "CPU ID", "Frequency", "Implementation",
	    "Status", 0);
	log_printf("\n");
	log_printf(fmt, "------", "---------",
	    "----------------------", "-------", 0);
	log_printf("\n");

	(void) picl_walk_tree_by_class(plafh, PICL_CLASS_CPU, PICL_CLASS_CPU,
	    sun4v_display_cpus);
}

/*
 * Display the CPUs present on this board.
 */
/*ARGSUSED*/
int
sun4v_display_cpus(picl_nodehdl_t cpuh, void* args)
{
	int status;
	picl_prophdl_t proph;
	picl_prophdl_t tblh;
	picl_prophdl_t rowproph;
	picl_propinfo_t propinfo;
	int *int_value;
	int cpuid;
	char *comp_value;
	char *no_prop_value = "   ";
	char freq_str[MAXSTRLEN];
	char state[MAXSTRLEN];

	/*
	 * Get cpuid property and print it and the NAC name
	 */
	status = picl_get_propinfo_by_name(cpuh, OBP_PROP_CPUID, &propinfo,
	    &proph);
	if (status == PICL_SUCCESS) {
		status = picl_get_propval(proph, &cpuid, sizeof (cpuid));
		if (status != PICL_SUCCESS) {
			log_printf("%-7s", no_prop_value);
		} else {
			log_printf("%-7d", cpuid);
		}
	} else {
		log_printf("%-7s", no_prop_value);
	}

clock_freq:
	status = picl_get_propinfo_by_name(cpuh, "clock-frequency", &propinfo,
	    &proph);
	if (status == PICL_SUCCESS) {
		int_value = malloc(propinfo.size);
		if (int_value == NULL) {
			log_printf("%-10s", no_prop_value);
			goto compatible;
		}
		status = picl_get_propval(proph, int_value, propinfo.size);
		if (status != PICL_SUCCESS) {
			log_printf("%-10s", no_prop_value);
		} else {
			/* Running frequency */
			(void) snprintf(freq_str, sizeof (freq_str), "%d MHz",
			    CLK_FREQ_TO_MHZ(*int_value));
			log_printf("%-10s", freq_str);
		}
		free(int_value);
	} else
		log_printf("%-10s", no_prop_value);

compatible:
	status = picl_get_propinfo_by_name(cpuh, "compatible", &propinfo,
	    &proph);
	if (status == PICL_SUCCESS) {
		if (propinfo.type == PICL_PTYPE_CHARSTRING) {
			/*
			 * Compatible Property only has 1 value
			 */
			comp_value = malloc(propinfo.size);
			if (comp_value == NULL) {
				log_printf("%-23s", no_prop_value, 0);
				goto state;
			}
			status = picl_get_propval(proph, comp_value,
			    propinfo.size);
			if (status != PICL_SUCCESS)
				log_printf("%-23s", no_prop_value, 0);
			else
				log_printf("%-23s", comp_value, 0);
			free(comp_value);
		} else if (propinfo.type == PICL_PTYPE_TABLE) {
			/*
			 * Compatible Property has multiple values
			 */
			status = picl_get_propval(proph, &tblh, propinfo.size);
			if (status != PICL_SUCCESS) {
				log_printf("%-23s", no_prop_value, 0);
				goto state;
			}
			status = picl_get_next_by_row(tblh, &rowproph);
			if (status != PICL_SUCCESS) {
				log_printf("%-23s", no_prop_value, 0);
				goto state;
			}

			status = picl_get_propinfo(rowproph, &propinfo);
			if (status != PICL_SUCCESS) {
				log_printf("%-23s", no_prop_value, 0);
				goto state;
			}

			comp_value = malloc(propinfo.size);
			if (comp_value == NULL) {
				log_printf("%-23s", no_prop_value, 0);
				goto state;
			}
			status = picl_get_propval(rowproph, comp_value,
			    propinfo.size);
			if (status != PICL_SUCCESS)
				log_printf("%-23s", no_prop_value, 0);
			else
				log_printf("%-23s", comp_value, 0);
			free(comp_value);
		}
	} else
		log_printf("%-23s", no_prop_value, 0);

state:
	status = picl_get_propinfo_by_name(cpuh, PICL_PROP_STATE,
	    &propinfo, &proph);
	if (status == PICL_SUCCESS) {
		status = picl_get_propval(proph, state, sizeof (state));
		if (status != PICL_SUCCESS) {
			log_printf("%-9s", no_prop_value);
		} else {
			log_printf("%-9s", state);
		}
	} else
		log_printf("%-9s", no_prop_value);

done:
	log_printf("\n");
	return (PICL_WALK_CONTINUE);
}

void
sun4v_display_diaginfo(int flag, Prom_node *root, picl_nodehdl_t plafh)
{
#ifdef	lint
	flag = flag;
	root = root;
	plafh = plafh;
#endif
	/*
	 * This function is intentionally empty
	 */
}

void
display_boardnum(int num)
{
	log_printf("%2d   ", num, 0);
}

static int
sun4v_disp_env_status()
{
	int	exit_code = 0;

	if (phyplatformh == 0)
		return (0);
	log_printf("\n");
	log_printf("============================");
	log_printf(" Environmental Status ");
	log_printf("============================");
	log_printf("\n");

	class_node_found = 0;
	all_status_ok = 1;
	sun4v_env_print_fan_sensors();
	exit_code |= (!all_status_ok);

	class_node_found = 0;
	all_status_ok = 1;
	sun4v_env_print_fan_indicators();
	exit_code |= (!all_status_ok);

	class_node_found = 0;
	all_status_ok = 1;
	sun4v_env_print_temp_sensors();
	exit_code |= (!all_status_ok);

	class_node_found = 0;
	all_status_ok = 1;
	sun4v_env_print_temp_indicators();
	exit_code |= (!all_status_ok);

	class_node_found = 0;
	all_status_ok = 1;
	sun4v_env_print_current_sensors();
	exit_code |= (!all_status_ok);

	class_node_found = 0;
	all_status_ok = 1;
	sun4v_env_print_current_indicators();
	exit_code |= (!all_status_ok);

	class_node_found = 0;
	all_status_ok = 1;
	sun4v_env_print_voltage_sensors();
	exit_code |= (!all_status_ok);

	class_node_found = 0;
	all_status_ok = 1;
	sun4v_env_print_voltage_indicators();
	exit_code |= (!all_status_ok);

	class_node_found = 0;
	all_status_ok = 1;
	sun4v_env_print_LEDs();
	exit_code |= (!all_status_ok);

	class_node_found = 0;
	all_status_ok = 1;
	sun4v_print_fru_status();
	exit_code |= (!all_status_ok);

	class_node_found = 0;
	sun4v_print_fw_rev();

	class_node_found = 0;
	sun4v_print_openprom_rev();

	sun4v_print_chassis_serial_no();

	return (exit_code);
}

/*ARGSUSED*/
static int
sun4v_env_print_sensor_callback(picl_nodehdl_t nodeh, void *args)
{
	char val[PICL_PROPNAMELEN_MAX];
	picl_nodehdl_t parenth;
	char *names[PARENT_NAMES];
	char *base_units[PICL_PROPNAMELEN_MAX];
	char *loc;
	int i;
	char *prop;
	picl_errno_t err;
	int32_t lo_warning, lo_shutdown, lo_poweroff;
	int32_t hi_warning, hi_shutdown, hi_poweroff;
	int32_t current_val;
	int32_t exponent;
	double display_val;
	typedef enum {SENSOR_OK, SENSOR_WARN, SENSOR_FAILED,
	    SENSOR_DISABLED, SENSOR_UNKNOWN} sensor_status_t;
	sensor_status_t sensor_status = SENSOR_OK;

	if (class_node_found == 0) {
		class_node_found = 1;
		return (PICL_WALK_TERMINATE);
	}

	prop = (char *)args;
	if (!prop) {
		sensor_status = SENSOR_UNKNOWN;
		all_status_ok = 0;
	} else {
		err = picl_get_propval_by_name(nodeh,
		    PICL_PROP_OPERATIONAL_STATUS, val,
		    sizeof (val));
		if (err == PICL_SUCCESS) {
			if (strcmp(val, "disabled") == 0) {
				sensor_status = SENSOR_DISABLED;
			}
		}
	}

	if (sensor_status != SENSOR_DISABLED &&
	    sensor_status != SENSOR_UNKNOWN) {
		if (picl_get_propval_by_name(nodeh, prop, &current_val,
		    sizeof (current_val)) != PICL_SUCCESS) {
			sensor_status = SENSOR_UNKNOWN;
		} else {
			if (picl_get_propval_by_name(nodeh,
			    PICL_PROP_LOW_WARNING,
			    &lo_warning, sizeof (lo_warning)) != PICL_SUCCESS)
				lo_warning = INVALID_THRESHOLD;
			if (picl_get_propval_by_name(nodeh,
			    PICL_PROP_LOW_SHUTDOWN,
			    &lo_shutdown, sizeof (lo_shutdown)) != PICL_SUCCESS)
				lo_shutdown = INVALID_THRESHOLD;
			if (picl_get_propval_by_name(nodeh,
			    PICL_PROP_LOW_POWER_OFF,
			    &lo_poweroff, sizeof (lo_poweroff)) != PICL_SUCCESS)
				lo_poweroff = INVALID_THRESHOLD;
			if (picl_get_propval_by_name(nodeh,
			    PICL_PROP_HIGH_WARNING,
			    &hi_warning, sizeof (hi_warning)) != PICL_SUCCESS)
				hi_warning = INVALID_THRESHOLD;
			if (picl_get_propval_by_name(nodeh,
			    PICL_PROP_HIGH_SHUTDOWN,
			    &hi_shutdown, sizeof (hi_shutdown)) != PICL_SUCCESS)
				hi_shutdown = INVALID_THRESHOLD;
			if (picl_get_propval_by_name(nodeh,
			    PICL_PROP_HIGH_POWER_OFF,
			    &hi_poweroff, sizeof (hi_poweroff)) != PICL_SUCCESS)
				hi_poweroff = INVALID_THRESHOLD;

			if ((lo_poweroff != INVALID_THRESHOLD &&
			    current_val <= lo_poweroff) ||
			    (hi_poweroff != INVALID_THRESHOLD &&
			    current_val >= hi_poweroff)) {
				sensor_status = SENSOR_FAILED;
			} else if ((lo_shutdown != INVALID_THRESHOLD &&
			    current_val <= lo_shutdown) ||
			    (hi_shutdown != INVALID_THRESHOLD &&
			    current_val >= hi_shutdown)) {
				sensor_status = SENSOR_FAILED;
			} else if ((lo_warning != INVALID_THRESHOLD &&
			    current_val <= lo_warning) ||
			    (hi_warning != INVALID_THRESHOLD &&
			    current_val >= hi_warning)) {
				sensor_status = SENSOR_WARN;
			} else {
				sensor_status = SENSOR_OK;
			}
		}
	}

	if (syserrlog == 0) {
		if (sensor_status != SENSOR_OK && all_status_ok == 1) {
			all_status_ok = 0;
			return (PICL_WALK_TERMINATE);
		}
		if (sensor_status == SENSOR_OK) {
			return (PICL_WALK_CONTINUE);
		}
	} else {
		if (sensor_status != SENSOR_OK && all_status_ok == 1) {
			all_status_ok = 0;
		}
	}

	/*
	 * If we're here then prtdiag was invoked with "-v" or we have
	 * a sensor that is beyond a threshold, so give them a book to
	 * read instead of the Cliff Notes.
	 */
	err = picl_get_propval_by_name(nodeh, PICL_PROP_PARENT, &parenth,
	    sizeof (parenth));
	if (err != PICL_SUCCESS) {
		log_printf("\n");
		return (PICL_WALK_CONTINUE);
	}

	/* gather up the path name for the sensor */
	if ((loc = (char *)malloc(PICL_PROPNAMELEN_MAX*PARENT_NAMES)) != NULL) {
		for (i = 0; i < PARENT_NAMES; i++) {
			if ((names[i] = (char *)malloc(PICL_PROPNAMELEN_MAX)) ==
			    NULL) {
				while (--i > -1)
					free(names[i]);
				free(loc);
				loc = NULL;
			}
		}
	}
	i = 0;
	if (loc != 0) {
		while (err == PICL_SUCCESS) {
			if (parenth == phyplatformh)
				break;
			err = picl_get_propval_by_name(parenth, PICL_PROP_NAME,
			    names[i++], PICL_PROPNAMELEN_MAX);
			if (err != PICL_SUCCESS) {
				i--;
				break;
			}
			if (i == PARENT_NAMES)
				break;
			err = picl_get_propval_by_name(parenth,
			    PICL_PROP_PARENT, &parenth, sizeof (parenth));
		}
		loc[0] = '\0';
		if (--i > -1) {
			(void) strlcat(loc, names[i],
			    PICL_PROPNAMELEN_MAX * PARENT_NAMES);
		}
		while (--i > -1) {
			(void) strlcat(loc, "/", PICL_PROPNAMELEN_MAX *
			    PARENT_NAMES);
			(void) strlcat(loc, names[i],
			    PICL_PROPNAMELEN_MAX * PARENT_NAMES);
		}
		log_printf("%-35s", loc);
		for (i = 0; i < PARENT_NAMES; i++)
			free(names[i]);
		free(loc);
	} else {
		log_printf("%-35s", " ");
	}
	err = picl_get_propval_by_name(nodeh, PICL_PROP_LABEL, val,
	    sizeof (val));
	if (err == PICL_SUCCESS)
		log_printf("%-19s", val);

	/*
	 * Get the exponent if present, and do a little math so that
	 * if we need to we can print a normalized value for the
	 * sensor reading.
	 */
	if (picl_get_propval_by_name(nodeh, PICL_PROP_EXPONENT,
	    &exponent, sizeof (exponent)) != PICL_SUCCESS)
		exponent = 0;
	if (exponent == 0)
		display_val = (double)current_val;
	else {
		display_val = (double)current_val *
		    pow((double)10, (double)exponent);

		/*
		 * Sometimes ILOM will scale a sensor reading but
		 * there will be nothing to the right of the decimal
		 * once that value is normalized.  Setting the
		 * exponent to zero will prevent the printf below
		 * from printing extraneous zeros.  Otherwise a
		 * negative exponent is used to set the precision
		 * for the printf.
		 */
		if ((int)display_val == display_val || exponent > 0)
			exponent = 0;
	}

	err = picl_get_propval_by_name(nodeh, PICL_PROP_BASE_UNITS,
	    base_units, sizeof (base_units));
	if (err != PICL_SUCCESS)
		base_units[0] = '\0';

	switch (sensor_status) {
	case SENSOR_FAILED:
		log_printf("%-s", "failed (");
		log_printf("%-.*f", abs(exponent), display_val);
		log_printf("%-s %s", base_units, ")");
		break;
	case SENSOR_WARN:
		log_printf("%-s", "warning (");
		log_printf("%-.*f", abs(exponent), display_val);
		log_printf("%-s %s", base_units, ")");
		break;
	case SENSOR_DISABLED:
		log_printf("%-s", "disabled");
		break;
	case SENSOR_OK:
		log_printf("%-s", "ok");
		break;
	default:
		log_printf("%-s", "unknown");
		break;
	}

	log_printf("\n");
	return (PICL_WALK_CONTINUE);
}

/*ARGSUSED*/
static int
sun4v_env_print_indicator_callback(picl_nodehdl_t nodeh, void *args)
{
	char current_val[PICL_PROPNAMELEN_MAX];
	char expected_val[PICL_PROPNAMELEN_MAX];
	char label[PICL_PROPNAMELEN_MAX];
	picl_nodehdl_t parenth;
	char *names[PARENT_NAMES];
	char *loc;
	int i = 0;
	char *prop = (char *)args;
	picl_errno_t err = PICL_SUCCESS;
	typedef enum {SENSOR_OK, SENSOR_WARN, SENSOR_FAILED,
	    SENSOR_DISABLED, SENSOR_UNKNOWN} sensor_status_t;
	sensor_status_t sensor_status = SENSOR_OK;

	if (class_node_found == 0) {
		class_node_found = 1;
		return (PICL_WALK_TERMINATE);
	}

	prop = (char *)args;
	if (!prop) {
		sensor_status = SENSOR_UNKNOWN;
		all_status_ok = 0;
	} else {
		err = picl_get_propval_by_name(nodeh,
		    PICL_PROP_OPERATIONAL_STATUS, current_val,
		    sizeof (current_val));
		if (err == PICL_SUCCESS) {
			if (strcmp(current_val, "disabled") == 0) {
				sensor_status = SENSOR_DISABLED;
			}
		}
	}

	if (sensor_status != SENSOR_DISABLED &&
	    sensor_status != SENSOR_UNKNOWN) {
		if (picl_get_propval_by_name(nodeh, prop, &current_val,
		    sizeof (current_val)) != PICL_SUCCESS) {
			(void) strlcpy(current_val, "unknown",
			    sizeof (current_val));
			sensor_status = SENSOR_UNKNOWN;
		} else {
			if (picl_get_propval_by_name(nodeh, PICL_PROP_EXPECTED,
			    &expected_val, sizeof (expected_val)) ==
			    PICL_SUCCESS) {
				if (strncmp(current_val, expected_val,
				    sizeof (current_val)) == 0) {
					sensor_status = SENSOR_OK;
				} else {
					sensor_status = SENSOR_FAILED;
				}
			}
		}
	}

	if (syserrlog == 0) {
		if (sensor_status != SENSOR_OK && all_status_ok == 1) {
			all_status_ok = 0;
			return (PICL_WALK_TERMINATE);
		}
		if (sensor_status == SENSOR_OK) {
			return (PICL_WALK_CONTINUE);
		}
	} else {
		if (sensor_status != SENSOR_OK && all_status_ok == 1) {
			all_status_ok = 0;
		}
	}

	/*
	 * If we're here then prtdiag was invoked with "-v" or we have
	 * a sensor that is beyond a threshold, so give them a book to
	 * read instead of the Cliff Notes.
	 */
	err = picl_get_propval_by_name(nodeh, PICL_PROP_PARENT, &parenth,
	    sizeof (parenth));
	if (err != PICL_SUCCESS) {
		log_printf("\n");
		return (PICL_WALK_CONTINUE);
	}
	if ((loc = (char *)malloc(PICL_PROPNAMELEN_MAX*PARENT_NAMES)) != NULL) {
		for (i = 0; i < PARENT_NAMES; i++) {
			if ((names[i] = (char *)malloc(PICL_PROPNAMELEN_MAX)) ==
			    NULL) {
				while (--i > -1)
					free(names[i]);
				free(loc);
				loc = NULL;
			}
		}
	}
	i = 0;
	if (loc) {
		while (err == PICL_SUCCESS) {
			if (parenth == phyplatformh)
				break;
			err = picl_get_propval_by_name(parenth, PICL_PROP_NAME,
			    names[i++], PICL_PROPNAMELEN_MAX);
			if (err != PICL_SUCCESS) {
				i--;
				break;
			}
			if (i == PARENT_NAMES)
				break;
			err = picl_get_propval_by_name(parenth,
			    PICL_PROP_PARENT, &parenth, sizeof (parenth));
		}
		loc[0] = '\0';
		if (--i > -1) {
			(void) strlcat(loc, names[i],
			    PICL_PROPNAMELEN_MAX * PARENT_NAMES);
		}
		while (--i > -1) {
			(void) strlcat(loc, "/", PICL_PROPNAMELEN_MAX *
			    PARENT_NAMES);
			(void) strlcat(loc, names[i],
			    PICL_PROPNAMELEN_MAX * PARENT_NAMES);
		}
		log_printf("%-35s", loc);
		for (i = 0; i < PARENT_NAMES; i++)
			free(names[i]);
		free(loc);
	} else {
		log_printf("%-35s", "");
	}

	err = picl_get_propval_by_name(nodeh, PICL_PROP_LABEL, label,
	    sizeof (label));
	if (err != PICL_SUCCESS)
		(void) strlcpy(label, "", sizeof (label));
	log_printf("%-19s", label);

	log_printf("%-8s", current_val);

	log_printf("\n");
	return (PICL_WALK_CONTINUE);
}

static void
sun4v_env_print_fan_sensors()
{
	char *fmt = "%-34s %-18s %-10s\n";
	/*
	 * If there isn't any fan sensor node, return now.
	 */
	(void) picl_walk_tree_by_class(phyplatformh,
	    PICL_CLASS_RPM_SENSOR, (void *)PICL_PROP_SPEED,
	    sun4v_env_print_sensor_callback);
	if (!class_node_found)
		return;
	log_printf("Fan sensors:\n");
	if (syserrlog == 0) {
		(void) picl_walk_tree_by_class(phyplatformh,
		    PICL_CLASS_RPM_SENSOR,
		    PICL_PROP_SPEED, sun4v_env_print_sensor_callback);
		if (all_status_ok) {
			log_printf("All fan sensors are OK.\n");
			return;
		}
	}
	log_printf("-------------------------------------------------"
	    "---------------\n");
	log_printf(fmt, "Location", "Sensor", "Status", 0);
	log_printf("-------------------------------------------------"
	    "---------------\n");
	(void) picl_walk_tree_by_class(phyplatformh, PICL_CLASS_RPM_SENSOR,
	    PICL_PROP_SPEED, sun4v_env_print_sensor_callback);
}

static void
sun4v_env_print_fan_indicators()
{
	char *fmt = "%-34s %-18s %-10s\n";
	(void) picl_walk_tree_by_class(phyplatformh,
	    PICL_CLASS_RPM_INDICATOR, (void *)PICL_PROP_CONDITION,
	    sun4v_env_print_indicator_callback);
	if (!class_node_found)
		return;
	log_printf("\nFan indicators:\n");
	if (syserrlog == 0) {
		(void) picl_walk_tree_by_class(phyplatformh,
		    PICL_CLASS_RPM_INDICATOR,
		    (void *)PICL_PROP_CONDITION,
		    sun4v_env_print_indicator_callback);
		if (all_status_ok) {
			log_printf("All fan indicators are OK.\n");
			return;
		}
	}
	log_printf("-------------------------------------------------"
	    "---------------\n");
	log_printf(fmt, "Location", "Sensor", "Condition", 0);
	log_printf("-------------------------------------------------"
	    "---------------\n");
	(void) picl_walk_tree_by_class(phyplatformh, PICL_CLASS_RPM_INDICATOR,
	    (void *)PICL_PROP_CONDITION, sun4v_env_print_indicator_callback);
}

static void
sun4v_env_print_temp_sensors()
{
	char *fmt = "%-34s %-18s %-10s\n";
	(void) picl_walk_tree_by_class(phyplatformh,
	    PICL_CLASS_TEMPERATURE_SENSOR,
	    (void *)PICL_PROP_TEMPERATURE,
	    sun4v_env_print_sensor_callback);
	if (!class_node_found)
		return;

	log_printf("\nTemperature sensors:\n");
	if (syserrlog == 0) {
		(void) picl_walk_tree_by_class(phyplatformh,
		    PICL_CLASS_TEMPERATURE_SENSOR,
		    PICL_PROP_TEMPERATURE, sun4v_env_print_sensor_callback);
		if (all_status_ok) {
			log_printf("All temperature sensors are OK.\n");
			return;
		}
	}
	log_printf("-------------------------------------------------"
	    "---------------\n");
	log_printf(fmt, "Location", "Sensor", "Status", 0);
	log_printf("-------------------------------------------------"
	    "---------------\n");
	(void) picl_walk_tree_by_class(phyplatformh,
	    PICL_CLASS_TEMPERATURE_SENSOR,
	    (void *)PICL_PROP_TEMPERATURE, sun4v_env_print_sensor_callback);
}

static void
sun4v_env_print_temp_indicators()
{
	char *fmt = "%-34s %-18s %-8s\n";
	(void) picl_walk_tree_by_class(phyplatformh,
	    PICL_CLASS_TEMPERATURE_INDICATOR, (void *)PICL_PROP_CONDITION,
	    sun4v_env_print_indicator_callback);
	if (!class_node_found)
		return;
	log_printf("\nTemperature indicators:\n");
	if (syserrlog == 0) {
		(void) picl_walk_tree_by_class(phyplatformh,
		    PICL_CLASS_TEMPERATURE_INDICATOR,
		    (void *)PICL_PROP_CONDITION,
		    sun4v_env_print_indicator_callback);
		if (all_status_ok) {
			log_printf("All temperature indicators are OK.\n");
			return;
		}
	}
	log_printf("-------------------------------------------------"
	    "---------------\n");
	log_printf(fmt, "Location", "Indicator", "Condition", 0);
	log_printf("-------------------------------------------------"
	    "---------------\n");
	(void) picl_walk_tree_by_class(phyplatformh,
	    PICL_CLASS_TEMPERATURE_INDICATOR,
	    (void *)PICL_PROP_CONDITION,
	    sun4v_env_print_indicator_callback);
}

static void
sun4v_env_print_current_sensors()
{
	char *fmt = "%-34s %-18s %-10s\n";
	(void) picl_walk_tree_by_class(phyplatformh, PICL_CLASS_CURRENT_SENSOR,
	    (void *)PICL_PROP_CURRENT, sun4v_env_print_sensor_callback);
	if (!class_node_found)
		return;
	log_printf("\nCurrent sensors:\n");
	if (syserrlog == 0) {
		(void) picl_walk_tree_by_class(phyplatformh,
		    PICL_CLASS_CURRENT_SENSOR,
		    PICL_PROP_CURRENT, sun4v_env_print_sensor_callback);
		if (all_status_ok) {
			log_printf("All current sensors are OK.\n");
			return;
		}
	}
	log_printf("-------------------------------------------------"
	    "---------------\n");
	log_printf(fmt, "Location", "Sensor", "Status", 0);
	log_printf("-------------------------------------------------"
	    "---------------\n");
	(void) picl_walk_tree_by_class(phyplatformh,
	    PICL_CLASS_CURRENT_SENSOR, (void *)PICL_PROP_CURRENT,
	    sun4v_env_print_sensor_callback);
}

static void
sun4v_env_print_current_indicators()
{
	char *fmt = "%-34s %-18s %-8s\n";
	(void) picl_walk_tree_by_class(phyplatformh,
	    PICL_CLASS_CURRENT_INDICATOR,
	    (void *)PICL_PROP_CONDITION,
	    sun4v_env_print_indicator_callback);
	if (!class_node_found)
		return;
	log_printf("\nCurrent indicators:\n");
	if (syserrlog == 0) {
		(void) picl_walk_tree_by_class(phyplatformh,
		    PICL_CLASS_CURRENT_INDICATOR, (void *)PICL_PROP_CONDITION,
		    sun4v_env_print_indicator_callback);
		if (all_status_ok) {
			log_printf("All current indicators are OK.\n");
			return;
		}
	}
	log_printf("-------------------------------------------------"
	    "---------------\n");
	log_printf(fmt, "Location", "Indicator", "Condition", 0);
	log_printf("-------------------------------------------------"
	    "---------------\n");
	(void) picl_walk_tree_by_class(phyplatformh,
	    PICL_CLASS_CURRENT_INDICATOR,
	    (void *)PICL_PROP_CONDITION,
	    sun4v_env_print_indicator_callback);
}

static void
sun4v_env_print_voltage_sensors()
{
	char *fmt = "%-34s %-18s %-10s\n";
	(void) picl_walk_tree_by_class(phyplatformh,
	    PICL_CLASS_VOLTAGE_SENSOR,
	    PICL_PROP_VOLTAGE,
	    sun4v_env_print_sensor_callback);
	if (!class_node_found)
		return;
	log_printf("\nVoltage sensors:\n");
	if (syserrlog == 0) {
		(void) picl_walk_tree_by_class(phyplatformh,
		    PICL_CLASS_VOLTAGE_SENSOR,
		    PICL_PROP_VOLTAGE, sun4v_env_print_sensor_callback);
		if (all_status_ok) {
			log_printf("All voltage sensors are OK.\n");
			return;
		}
	}
	log_printf("-------------------------------------------------"
	    "---------------\n");
	log_printf(fmt, "Location", "Sensor", "Status", 0);
	log_printf("-------------------------------------------------"
	    "---------------\n");
	(void) picl_walk_tree_by_class(phyplatformh,
	    PICL_CLASS_VOLTAGE_SENSOR,
	    (void *)PICL_PROP_VOLTAGE,
	    sun4v_env_print_sensor_callback);
}

static void
sun4v_env_print_voltage_indicators()
{
	char *fmt = "%-34s %-18s %-8s\n";
	(void) picl_walk_tree_by_class(phyplatformh,
	    PICL_CLASS_VOLTAGE_INDICATOR,
	    (void *)PICL_PROP_CONDITION,
	    sun4v_env_print_indicator_callback);
	if (!class_node_found)
		return;
	log_printf("\nVoltage indicators:\n");
	if (syserrlog == 0) {
		(void) picl_walk_tree_by_class(phyplatformh,
		    PICL_CLASS_VOLTAGE_INDICATOR, (void *)PICL_PROP_CONDITION,
		    sun4v_env_print_indicator_callback);
		if (all_status_ok) {
			log_printf("All voltage indicators are OK.\n");
			return;
		}
	}
	log_printf("-------------------------------------------------"
	    "---------------\n");
	log_printf(fmt, "Location", "Indicator", "Condition", 0);
	log_printf("-------------------------------------------------"
	    "---------------\n");
	(void) picl_walk_tree_by_class(phyplatformh,
	    PICL_CLASS_VOLTAGE_INDICATOR,
	    (void *)PICL_PROP_CONDITION,
	    sun4v_env_print_indicator_callback);
}

static void
sun4v_env_print_LEDs()
{
	char *fmt = "%-34s %-18s %-8s\n";
	if (syserrlog == 0)
		return;
	(void) picl_walk_tree_by_class(phyplatformh, PICL_CLASS_LED,
	    (void *)PICL_PROP_STATE, sun4v_env_print_indicator_callback);
	if (!class_node_found)
		return;
	log_printf("\nLEDs:\n");
	log_printf("-------------------------------------------------"
	    "---------------\n");
	log_printf(fmt, "Location", "LED", "State", 0);
	log_printf("-------------------------------------------------"
	    "---------------\n");
	(void) picl_walk_tree_by_class(phyplatformh, PICL_CLASS_LED,
	    (void *)PICL_PROP_STATE, sun4v_env_print_indicator_callback);
}

/*ARGSUSED*/
static int
sun4v_print_fru_status_callback(picl_nodehdl_t nodeh, void *args)
{
	char label[PICL_PROPNAMELEN_MAX];
	char status[PICL_PROPNAMELEN_MAX];
	picl_errno_t err;
	picl_prophdl_t proph;
	picl_nodehdl_t parenth;
	char *names[PARENT_NAMES];
	char *loc;
	int i;

	if (!class_node_found) {
		class_node_found = 1;
		return (PICL_WALK_TERMINATE);
	}
	err = picl_get_prop_by_name(nodeh, PICL_PROP_IS_FRU, &proph);
	if (err != PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);
	err = picl_get_propval_by_name(nodeh, PICL_PROP_LABEL, label,
	    sizeof (label));
	if (err != PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);
	err = picl_get_propval_by_name(nodeh, PICL_PROP_OPERATIONAL_STATUS,
	    status, sizeof (status));
	if (err != PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);
	if (syserrlog == 0) {
		if (strcmp(status, "disabled") == 0) {
			if (all_status_ok) {
				all_status_ok = 0;
				return (PICL_WALK_TERMINATE);
			}
		} else
			return (PICL_WALK_CONTINUE);
	} else {
		if (all_status_ok && (strcmp(status, "disabled") == 0)) {
			all_status_ok = 0;
		}
	}

	if (is_fru_absent(nodeh))
		strcpy(status, "Not present");

	err = picl_get_propval_by_name(nodeh, PICL_PROP_PARENT, &parenth,
	    sizeof (parenth));
	if (err != PICL_SUCCESS) {
		log_printf("\n");
		return (PICL_WALK_CONTINUE);
	}
	if ((loc = (char *)malloc(PICL_PROPNAMELEN_MAX*PARENT_NAMES)) == NULL)
		return (PICL_WALK_TERMINATE);
	for (i = 0; i < PARENT_NAMES; i++)
		if ((names[i] = (char *)malloc(PICL_PROPNAMELEN_MAX)) == NULL) {
			while (--i > -1)
				free(names[i]);
			free(loc);
			return (PICL_WALK_TERMINATE);
		}
	i = 0;
	while (err == PICL_SUCCESS) {
		if (parenth == phyplatformh)
			break;
		err = picl_get_propval_by_name(parenth, PICL_PROP_NAME,
		    names[i++], PICL_PROPNAMELEN_MAX);
		if (err != PICL_SUCCESS) {
			i--;
			break;
		}
		if (i == PARENT_NAMES)
			break;
		err = picl_get_propval_by_name(parenth, PICL_PROP_PARENT,
		    &parenth, sizeof (parenth));
	}
	loc[0] = '\0';
	if (--i > -1) {
		(void) strlcat(loc, names[i],
		    PICL_PROPNAMELEN_MAX * PARENT_NAMES);
	}
	while (--i > -1) {
		(void) strlcat(loc, "/", PICL_PROPNAMELEN_MAX * PARENT_NAMES);
		(void) strlcat(loc, names[i],
		    PICL_PROPNAMELEN_MAX * PARENT_NAMES);
	}
	log_printf("%-35s", loc);
	for (i = 0; i < PARENT_NAMES; i++)
		free(names[i]);
	free(loc);
	log_printf("%-10s", label);
	log_printf("%-9s", status);
	log_printf("\n");
	return (PICL_WALK_CONTINUE);
}

static void
sun4v_print_fru_status()
{
	char *fmt = "%-34s %-9s %-8s\n";

	(void) picl_walk_tree_by_class(phyplatformh, NULL, NULL,
	    sun4v_print_fru_status_callback);
	if (!class_node_found)
		return;

	log_printf("\n");
	log_printf("============================");
	log_printf(" FRU Status ");
	log_printf("============================");
	log_printf("\n");

	if (syserrlog == 0) {
		(void) picl_walk_tree_by_class(phyplatformh,
		    NULL, NULL,
		    sun4v_print_fru_status_callback);
		if (all_status_ok) {
			log_printf("All FRUs are enabled.\n");
			return;
		}
	}
	log_printf(fmt, "Location", "Name", "Status", 0);
	log_printf("------------------------------------------------------\n");
	(void) picl_walk_tree_by_class(phyplatformh, NULL, NULL,
	    sun4v_print_fru_status_callback);
}

/*  Check the children of the FRU node for a presence indicator */
static int
is_fru_absent(picl_nodehdl_t fruh)
{
	char class [PICL_CLASSNAMELEN_MAX];
	char condition [PICL_PROPNAMELEN_MAX];
	picl_errno_t err;
	picl_nodehdl_t nodeh;

	err = picl_get_propval_by_name(fruh, PICL_PROP_CHILD, &nodeh,
	    sizeof (picl_nodehdl_t));
	while (err == PICL_SUCCESS) {
		err = picl_get_propval_by_name(nodeh,
		    PICL_PROP_CLASSNAME, class, sizeof (class));
		if (err == PICL_SUCCESS &&
		    strcmp(class, "presence-indicator") == 0) {
			err = picl_get_propval_by_name(nodeh,
			    PICL_PROP_CONDITION, condition,
			    sizeof (condition));
			if (err == PICL_SUCCESS) {
				if (strcmp(condition, "Absent") == 0) {
					return (1);
				} else	{
					return (0);
				}
			}
		}
		err = picl_get_propval_by_name(nodeh, PICL_PROP_PEER,
		    &nodeh, sizeof (picl_nodehdl_t));
	}
	return (0);
}

/*ARGSUSED*/
static int
sun4v_print_fw_rev_callback(picl_nodehdl_t nodeh, void *args)
{
	char rev[PICL_PROPNAMELEN_MAX];
	picl_errno_t err;

	if (!class_node_found) {
		class_node_found = 1;
		return (PICL_WALK_TERMINATE);
	}

	err = picl_get_propval_by_name(nodeh, PICL_PROP_FW_REVISION, rev,
	    sizeof (rev));
	if (err != PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);
	if (strlen(rev) == 0)
		return (PICL_WALK_CONTINUE);
	log_printf("%s", rev);
	log_printf("\n");
	return (PICL_WALK_CONTINUE);
}

static void
sun4v_print_fw_rev()
{
	if (syserrlog == 0)
		return;

	(void) picl_walk_tree_by_class(phyplatformh, NULL, NULL,
	    sun4v_print_fw_rev_callback);
	if (!class_node_found)
		return;

	log_printf("\n");
	log_printf("============================");
	log_printf(" FW Version ");
	log_printf("============================");
	log_printf("\n");
	log_printf("Version\n");
	log_printf("-------------------------------------------------"
	    "-----------\n");
	(void) picl_walk_tree_by_class(phyplatformh, NULL, NULL,
	    sun4v_print_fw_rev_callback);
}

static void
sun4v_print_openprom_rev()
{
	if (syserrlog == 0)
		return;

	(void) picl_walk_tree_by_class(rooth, "openprom", NULL,
	    openprom_callback);
	if (!class_node_found)
		return;

	log_printf("\n");
	log_printf("======================");
	log_printf(" System PROM revisions ");
	log_printf("=======================");
	log_printf("\n");
	log_printf("Version\n");
	log_printf("-------------------------------------------------"
	    "-----------\n");
	(void) picl_walk_tree_by_class(rooth, "openprom", NULL,
	    openprom_callback);
}

/*
 * display the OBP and POST prom revisions (if present)
 */
/* ARGSUSED */
static int
openprom_callback(picl_nodehdl_t openpromh, void *arg)
{
	picl_prophdl_t	proph;
	picl_prophdl_t	tblh;
	picl_prophdl_t	rowproph;
	picl_propinfo_t	pinfo;
	char		*prom_version = NULL;
	char		*obp_version = NULL;
	int		err;

	if (!class_node_found) {
		class_node_found = 1;
		return (PICL_WALK_TERMINATE);
	}

	err = picl_get_propinfo_by_name(openpromh, OBP_PROP_VERSION,
	    &pinfo, &proph);
	if (err == PICL_PROPNOTFOUND)
		return (PICL_WALK_TERMINATE);
	else if (err != PICL_SUCCESS)
		return (err);

	/*
	 * If it's a table prop, the first element is OBP revision
	 * The second one is POST revision.
	 * If it's a charstring prop, the value will be only OBP revision
	 */
	if (pinfo.type == PICL_PTYPE_CHARSTRING) {
		prom_version = (char *)alloca(pinfo.size);
		if (prom_version == NULL)
			return (PICL_FAILURE);
		err = picl_get_propval(proph, prom_version, pinfo.size);
		if (err != PICL_SUCCESS)
			return (err);
		log_printf("%s\n", prom_version);
	}

	if (pinfo.type != PICL_PTYPE_TABLE)	/* not supported type */
		return (PICL_WALK_TERMINATE);

	err = picl_get_propval(proph, &tblh, pinfo.size);
	if (err != PICL_SUCCESS)
		return (err);

	err = picl_get_next_by_row(tblh, &rowproph);
	if (err == PICL_SUCCESS) {
		/* get first row */
		err = picl_get_propinfo(rowproph, &pinfo);
		if (err != PICL_SUCCESS)
			return (err);

		prom_version = (char *)alloca(pinfo.size);
		if (prom_version == NULL)
			return (PICL_FAILURE);

		err = picl_get_propval(rowproph, prom_version, pinfo.size);
		if (err != PICL_SUCCESS)
			return (err);
		log_printf("%s\n", prom_version);

		/* get second row */
		err = picl_get_next_by_col(rowproph, &rowproph);
		if (err == PICL_SUCCESS) {
			err = picl_get_propinfo(rowproph, &pinfo);
			if (err != PICL_SUCCESS)
				return (err);

			obp_version = (char *)alloca(pinfo.size);
			if (obp_version == NULL)
				return (PICL_FAILURE);
			err = picl_get_propval(rowproph, obp_version,
			    pinfo.size);
			if (err != PICL_SUCCESS)
				return (err);
			log_printf("%s\n", obp_version);
		}
	}

	return (PICL_WALK_TERMINATE);
}

static void
sun4v_print_chassis_serial_no()
{
	char val[PICL_PROPNAMELEN_MAX];
	picl_errno_t err;
	if (syserrlog == 0 || chassish == 0)
		return;

	log_printf("\n");
	log_printf("Chassis Serial Number");
	log_printf("\n");
	log_printf("---------------------\n");
	err = picl_get_propval_by_name(chassish, PICL_PROP_SERIAL_NUMBER,
	    val, sizeof (val));
	if (err == PICL_SUCCESS)
		log_printf("%s", val);
	log_printf("\n");
}
