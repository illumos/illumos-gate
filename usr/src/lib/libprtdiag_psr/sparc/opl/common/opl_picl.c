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
 *
 * Opl platform specific PICL functions.
 *
 * 	called when :
 *	machine_type == MTYPE_OPL
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
#include <dlfcn.h>
#include <errno.h>
#include <sys/systeminfo.h>
#include <sys/openpromio.h>
#include <sys/sysmacros.h>
#include <picl.h>
#include "picldefs.h"
#include <pdevinfo.h>
#include <display.h>
#include <libprtdiag.h>
#include <alloca.h>
#include "opl_picl.h"
#include <sys/pci.h>
#include <sys/pci_tools.h>
#include <sys/types.h>

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

static picl_errno_t do_walk(picl_nodehdl_t rooth, const char *classname,
    void *c_args, picl_errno_t (*callback_fn)(picl_nodehdl_t hdl, void *args));
static int opl_get_node_by_name(picl_nodehdl_t rooth, char *name,
    picl_nodehdl_t *nodeh);
static picl_errno_t get_lane_width(char *device_path, int bus_no, int func_no,
    int dev_no, int *actual, int *maximum, uint32_t *speed_max,
    uint32_t *speed_at, int *type);
static int	opl_display_pci(int syserrlog, picl_nodehdl_t plafh);
static picl_errno_t opl_pci_callback(picl_nodehdl_t pcih, void *args);
static int opl_get_first_compatible_value(picl_nodehdl_t nodeh,
    char **outbuf);
static int picldiag_get_clock_freq(picl_nodehdl_t modh,
    uint32_t *freq);
static uint64_t picldiag_get_uint_propval(picl_nodehdl_t modh,
    char *prop_name, int *ret);
static uint32_t	read_long(int fd, int bus, int dev, int func,
    int offset, int *ret);
static uint8_t read_byte(int fd, int bus, int dev, int func, int offset,
    int *ret);
static uint16_t read_word(int fd, int bus, int dev, int func, int offset,
    int *ret);


/*
 * Collect I/O nodes information.
 */
/* ARGSUSED */
static picl_errno_t
opl_pci_callback(picl_nodehdl_t pcih, void *args)
{
	picl_errno_t	err = PICL_SUCCESS;
	picl_nodehdl_t	nodeh;
	picl_prophdl_t  proph;
	picl_propinfo_t pinfo;
	char		path[MAXSTRLEN];
	char		parent_path[MAXSTRLEN];
	static char	root_path[MAXSTRLEN];
	char		piclclass[PICL_CLASSNAMELEN_MAX];
	char		name[MAXSTRLEN];
	char		model[MAXSTRLEN];
	char		*compatible;
	char		binding_name[MAXSTRLEN];
	struct io_card	pci_card;
	char		status[6] = "N/A";
	int		portid = PROP_INVALID;
	int		*reg_val;
	int		board = PROP_INVALID;
	static int	saved_board = PROP_INVALID;
	static int	saved_portid = PROP_INVALID;
	int 		actual = PROP_INVALID, maximum = PROP_INVALID;
	int 		bus_type;
	int 		rev_id = PROP_INVALID, dev_id = PROP_INVALID;
	int		ven_id = PROP_INVALID;
	size_t		prop_size;

	(void) memset(&pci_card, 0, sizeof (pci_card));

	err = picl_get_propval_by_name(pcih, PICL_PROP_CLASSNAME,
	    piclclass, sizeof (piclclass));

	if (err !=  PICL_SUCCESS)
		/* Do not proceed to parse this branch */
		return (err);

	if (!IS_PCI(piclclass))
		/* Do not parse non-pci nodes */
		return (PICL_INVALIDARG);

	err = picl_get_propval_by_name(pcih, PICL_PROP_DEVFS_PATH, parent_path,
	    sizeof (parent_path));
	if (err != PICL_SUCCESS)
		/* Do not proceed to parse this branch */
		return (err);
	err = picl_get_propval_by_name(pcih, OBP_PROP_BOARD_NUM, &board,
	    sizeof (board));

	if (err == PICL_NORESPONSE)
		/* Do not proceed to parse this branch */
		return (err);
	else if (err != PICL_PROPNOTFOUND) {
		saved_board = board;
		/* Save board node's pathname */
		prop_size = sizeof (parent_path) + 1;
		if (prop_size > MAXSTRLEN)
			prop_size = MAXSTRLEN;
		(void) strlcpy(root_path, parent_path, prop_size);
	}

	err = picl_get_propval_by_name
	    (pcih, OBP_PROP_PORTID, &portid, sizeof (portid));

	if (err != PICL_PROPNOTFOUND)
		saved_portid = portid;

	/* Walk through the children */

	err = picl_get_propval_by_name(pcih, PICL_PROP_CHILD, &nodeh,
	    sizeof (picl_nodehdl_t));

	while (err == PICL_SUCCESS) {
		uint32_t	freq_max = 0, freq_at = 0;

		err = picl_get_propval_by_name(nodeh, PICL_PROP_CLASSNAME,
		    piclclass, sizeof (piclclass));
		if (err !=  PICL_SUCCESS)
			/* Do not proceed to parse this node */
			return (err);

		if (IS_EBUS(piclclass)) {
			err = picl_get_propval_by_name(nodeh, PICL_PROP_PEER,
			    &nodeh, sizeof (picl_nodehdl_t));
			continue;
		}

		err = picl_get_propval_by_name(nodeh, PICL_PROP_DEVFS_PATH,
		    path, sizeof (path));
		if (err != PICL_SUCCESS) {
			/* Do not proceed to parse this node */
			return (err);
		}

		prop_size = sizeof (path) + 1;
		if (prop_size > MAXSTRLEN)
			prop_size = MAXSTRLEN;
		(void) strlcpy(pci_card.notes, path, prop_size);

		pci_card.board = saved_board;
		pci_card.schizo_portid = saved_portid;

		/*
		 * Get bus#, dev# and func# for this card from 'reg' property.
		 */

		err = picl_get_propinfo_by_name
		    (nodeh, OBP_PROP_REG, &pinfo, &proph);
		if (err == PICL_SUCCESS) {
			/* All of the array of bytes of "reg" have to be read */
			reg_val = malloc(pinfo.size);
			if (reg_val == NULL)
				return (PICL_FAILURE);


			err = picl_get_propval_by_name
			    (nodeh, OBP_PROP_REG, reg_val, pinfo.size);

			if (err != PICL_SUCCESS) {
				free(reg_val);
				/* Do not proceed to parse this node */
				return (err);
			}

			if (reg_val[0] != 0) {
				pci_card.dev_no =
				    (((reg_val[0]) & PCI_DEV_MASK) >> 11);
				pci_card.func_no =
				    (((reg_val[0]) & PCI_FUNC_MASK) >> 8);
				pci_card.slot =
				    (((reg_val[0]) & PCI_BUS_MASK) >> 16);
			} else
				free(reg_val);
		}

		err = get_lane_width(root_path, pci_card.slot, pci_card.dev_no,
		    pci_card.func_no, &actual, &maximum, &freq_max, &freq_at,
		    &bus_type);

		if (err != PICL_SUCCESS) {
			/*
			 * get_lane_width will fail when run as non-root.
			 * Set bus_type to PCI_UNKN so that bus frequency,
			 * bus type and lane width will print as "--" or UNKN.
			 */
			bus_type = PCI_UNKN;
		}


		err = picl_get_propval_by_name
		    (nodeh, PICL_PROP_NAME, name, sizeof (name));
		if (err != PICL_SUCCESS)
			(void) strcpy(name, "");

		/*
		 * Get the name of this card. If binding_name is found,
		 * name will be <nodename>-<binding_name>
		 */

		err = picl_get_propval_by_name(nodeh, PICL_PROP_BINDING_NAME,
		    binding_name, sizeof (binding_name));
		if (err == PICL_PROPNOTFOUND) {
			/*
			 * if compatible prop is found, name will be
			 * <nodename>-<compatible>
			 */
			err = opl_get_first_compatible_value(nodeh,
			    &compatible);
			if (err == PICL_SUCCESS) {
				(void) strlcat(name, "-", MAXSTRLEN);
				(void) strlcat(name, compatible, MAXSTRLEN);
				free(compatible);
			}
		} else if (err != PICL_SUCCESS) {
			/* No binding-name or compatible */
			(void) strcpy(binding_name, "N/A");
		} else if (strcmp(name, binding_name) != 0) {
			(void) strlcat(name, "-", MAXSTRLEN);
			(void) strlcat(name, binding_name, MAXSTRLEN);
		}


		prop_size = sizeof (name) + 1;
		if (prop_size > MAXSTRLEN)
			prop_size =  MAXSTRLEN;
		(void) strlcpy(pci_card.name, name, prop_size);

		/* Get the status of the card */
		err = picl_get_propval_by_name
		    (nodeh, PICL_PROP_STATUS, status, sizeof (status));


		/* Get the model of this card */

		err = picl_get_propval_by_name
		    (nodeh, OBP_PROP_MODEL, model, sizeof (model));
		prop_size = sizeof (model) + 1;
		if (prop_size > MAXSTRLEN)
			prop_size =  MAXSTRLEN;
		if (err != PICL_SUCCESS)
			(void) strcpy(model, "N/A");
		(void) strlcpy(pci_card.model, model, prop_size);

		if (bus_type == PCI)
			(void) strlcpy(pci_card.bus_type,
			    "PCI", sizeof (pci_card.bus_type));
		else if (bus_type == PCIX)
			(void) strlcpy(pci_card.bus_type,
			    "PCIx", sizeof (pci_card.bus_type));
		else if (bus_type == PCIE)
			(void) strlcpy(pci_card.bus_type,
			    "PCIe", sizeof (pci_card.bus_type));
		else
			(void) strlcpy(pci_card.bus_type,
			    "UNKN", sizeof (pci_card.bus_type));

		/* Get revision id */
		err = picl_get_propval_by_name
		    (nodeh, OBP_PROP_REVISION_ID, &rev_id, sizeof (rev_id));

		/* Get device id */
		err = picl_get_propval_by_name
		    (nodeh, OBP_PROP_DEVICE_ID, &dev_id, sizeof (dev_id));

		/* Get vendor id */
		err = picl_get_propval_by_name
		    (nodeh, OBP_PROP_VENDOR_ID, &ven_id, sizeof (ven_id));

		/*
		 * prtdiag -v prints all devices
		 */

		/* Print board number */
		log_printf("%02d  ", pci_card.board);
		/* Print IO Type */
		log_printf("%-5.5s ", pci_card.bus_type);

		log_printf("%-3d  ", pci_card.schizo_portid);
		log_printf("%4x, %4x, %4x     ", rev_id, dev_id, ven_id);

		log_printf("%3d, %2d, %2d",
		    pci_card.slot, pci_card.dev_no, pci_card.func_no);

		/* Print status */
		log_printf("  %-5.5s ", status);

		/* Print Lane widths, Max/Sup Freq, Speed */
		if (bus_type == PCIE) {
			PRINT_FMT(actual, maximum);
		} else if (bus_type == PCIX) {
			PRINT_FREQ_FMT(freq_at, freq_max);
		} else if (bus_type == PCI) {
			err = picldiag_get_clock_freq(nodeh, &freq_at);
			PRINT_FREQ_FMT(freq_at, freq_max);
		} else
			log_printf(" -- , --   ");

		/* Print Card Name */
		log_printf("%-30.30s", pci_card.name);

		/* Print Card Model */
		log_printf(" %-20.20s", pci_card.model);

		log_printf("\n");

		log_printf("%4s%-100.100s", " ", pci_card.notes);
		log_printf("\n");
		log_printf("\n");


		err = picl_get_propval_by_name
		    (nodeh, PICL_PROP_PEER, &nodeh, sizeof (picl_nodehdl_t));

	}

	return (PICL_WALK_CONTINUE);
}

/*
 * opl_display_pci
 * Display all the PCI IO cards on this board.
 */
static int
opl_display_pci(int syserrlog, picl_nodehdl_t plafh)
{
	picl_errno_t err;
	char	*fmt = "%-3s %-5s %-4s %-20s %-11s %-5s %-11s %-30s %-20s";
	char 	*fmt2 = "%-16s";
	static int banner = FALSE; /* Have we printed the column headings? */

	if (banner == FALSE) {
		log_printf("\n", 0);
		log_printf("=========================", 0);
		log_printf(dgettext(TEXT_DOMAIN, " IO Devices "), 0);
		log_printf("=========================", 0);
		log_printf("\n", 0);
		log_printf("\n", 0);
		log_printf(fmt, "", "IO", "", "", "", "", "Lane/Frq",
		    "", "", 0);
		log_printf("\n", 0);

		log_printf(fmt, "LSB", "Type", "LPID", "  RvID,DvID,VnID",
		    "  BDF", "State", "Act,  Max", "Name", "Model", 0);

		log_printf("\n");

		log_printf(fmt,
		    "---", "-----", "----", "  ------------------",
		    "  ---------", "-----", "-----------",
		    "------------------------------",
		    "--------------------", 0);
		log_printf("\n");
		log_printf(fmt2, "    Logical Path");
		log_printf("\n");
		log_printf(fmt2, "    ------------");
		log_printf("\n");
		banner = TRUE;
	}

	err = do_walk(plafh, PICL_CLASS_PCI, PICL_CLASS_PCI, opl_pci_callback);
	return (err);
}


/*
 * return the first compatible value
 */
static int
opl_get_first_compatible_value(picl_nodehdl_t nodeh, char **outbuf)
{
	picl_errno_t	err;
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

int
do_piclinfo(int syserrlog)
{
	picl_nodehdl_t rooth;		/* root PICL node for IO display */
	picl_nodehdl_t plafh;		/* Platform PICL node for IO display */

	picl_errno_t err;

	err = picl_initialize();
	if (err != PICL_SUCCESS) {
		(void) log_printf("picl_initialize failed: %s\n",
		    picl_strerror(err));
		return (err);
	}


	err = picl_get_root(&rooth);
	if (err != PICL_SUCCESS) {
		(void) log_printf("Getting root node failed: %s\n",
		    picl_strerror(err));
		return (err);
	}

	err = opl_get_node_by_name(rooth, PICL_NODE_PLATFORM, &plafh);

	if (err != PICL_SUCCESS) {
		(void) log_printf("Getting nodes by name failed: %s\n",
		    picl_strerror(err));
		return (err);
	}

	err = opl_display_pci(syserrlog, plafh);

	(void) picl_shutdown();

	return (err);
}

/*
 * search children to get the node by the nodename
 */
static int
opl_get_node_by_name(picl_nodehdl_t rooth, char *name,
    picl_nodehdl_t *nodeh)
{
	picl_nodehdl_t	childh;
	int		err;
	char		*nodename;

	nodename = alloca(strlen(name) + 1);
	if (nodename == NULL)
		return (PICL_FAILURE);

	err = picl_get_propval_by_name(rooth, PICL_PROP_CHILD, &childh,
	    sizeof (picl_nodehdl_t));

	while (err == PICL_SUCCESS) {
		err = picl_get_propval_by_name(childh, PICL_PROP_NAME,
		    nodename, (strlen(name) + 1));
		if (err != PICL_SUCCESS) {
			err = picl_get_propval_by_name(childh, PICL_PROP_PEER,
			    &childh, sizeof (picl_nodehdl_t));
			continue;
		}

		if (strcmp(nodename, name) == 0) {
			*nodeh = childh;
			return (PICL_SUCCESS);
		}

		err = picl_get_propval_by_name(childh, PICL_PROP_PEER,
		    &childh, sizeof (picl_nodehdl_t));
	}

	return (err);
}

static int
open_root_complex(char *root_complex)
{
	char *path;
	static char device_str[] = {"/devices"};
	static char devctl_str[] = {":reg"};
	int fd;

	path = malloc(
	    strlen(root_complex) + sizeof (device_str) + sizeof (devctl_str));
	if (path == NULL)
		return (PICL_FAILURE);
	(void) strcpy(path, device_str);
	(void) strcat(path, root_complex);
	(void) strcat(path, devctl_str);

	if ((fd = open(path, O_RDWR)) == -1) {
		return (-1);
	}
	return (fd);
}

static uint32_t
read_long(int fd, int bus, int dev, int func, int offset, int *ret)
{
	int rval;
	pcitool_reg_t prg;

	prg.user_version = PCITOOL_VERSION;
	prg.barnum = 0;
	prg.acc_attr = PCITOOL_ACC_ATTR_SIZE_4 +
	    PCITOOL_ACC_ATTR_ENDN_LTL;
	prg.bus_no = bus;
	prg.dev_no = dev;
	prg.func_no = func;
	prg.offset = offset;
	rval = ioctl(fd, PCITOOL_DEVICE_GET_REG, &prg);
	if (rval != 0) {
		log_printf("DEV_GET failed %d %s\n", rval, strerror(errno));
		log_printf("%d.%d.%d offset 0x%x\n", bus, dev, func, offset);
	}
	*ret = rval;
	return ((uint32_t)prg.data);
}

static uint16_t
read_word(int fd, int bus, int dev, int func, int offset, int *ret)
{
	int rval;
	pcitool_reg_t prg;

	prg.user_version = PCITOOL_VERSION;
	prg.barnum = 0;
	prg.acc_attr = PCITOOL_ACC_ATTR_SIZE_2 +
	    PCITOOL_ACC_ATTR_ENDN_LTL;
	prg.bus_no = bus;
	prg.dev_no = dev;
	prg.func_no = func;
	prg.offset = offset;
	rval = ioctl(fd, PCITOOL_DEVICE_GET_REG, &prg);
	if (rval != 0) {
		log_printf("DEV_GET failed %d %s\n", rval, strerror(errno));
		log_printf("%d.%d.%d offset 0x%x\n", bus, dev, func, offset);
	}
	*ret = rval;
	return ((uint16_t)prg.data);
}

static uint8_t
read_byte(int fd, int bus, int dev, int func, int offset, int *ret)
{
	int rval;
	pcitool_reg_t prg;

	prg.user_version = PCITOOL_VERSION;
	prg.barnum = 0;
	prg.acc_attr = PCITOOL_ACC_ATTR_SIZE_1 +
	    PCITOOL_ACC_ATTR_ENDN_LTL;
	prg.bus_no = bus;
	prg.dev_no = dev;
	prg.func_no = func;
	prg.offset = offset;
	rval = ioctl(fd, PCITOOL_DEVICE_GET_REG, &prg);
	if (rval != 0) {
		log_printf("DEV_GET failed %d %s\n", rval, strerror(errno));
		log_printf("%d.%d.%d offset 0x%x\n", bus, dev, func, offset);
	}
	*ret = rval;
	return ((uint8_t)prg.data);
}


static picl_errno_t
get_lane_width
	(char *device_path, int bus, int dev, int func, int *actual,
	int *maximum, uint32_t *speed_max, uint32_t *speed_at, int *type)
{
	uint_t cap_ptr, cap_reg, link_status, link_cap, capid;
	int fd, ret;

	if (device_path == NULL)
		return (PICL_FAILURE);

	fd = open_root_complex(device_path);
	if (fd == -1)
		return (PICL_FAILURE);

	/*
	 * Link Capabilities and Link Status registers are in the
	 * PCI-E capabilities register.  They are at offset
	 * 0xc and 0x12 respectively. They are documented in section
	 * 7.8 of the PCI Express Base Specification. The address of
	 * that structure is not fixed, it's kind of a linked list.
	 * The Capabilities Pointer reg (8 bits) is always at 0x34.
	 * It contains a pointer to the first capabilities structure.
	 * For each capability structure, the first 8 bits is the capability
	 * ID. The next 8 bits is the pointer to the next structure.
	 * If the Next Cap register is zero, it's the end of the list.
	 * The capability ID for the PCI-E strucutre is 0x10.  The idea
	 * is to follow the links until you find a Cap ID of 0x10, then
	 * read the registers at 0xc and 0x12 from there.
	 * If there's no Cap ID 0x10, then it's not a PCI-E device.
	 */

	cap_ptr = read_byte(fd, bus, dev, func, PCI_CONF_CAP_PTR, &ret);
	if (ret != 0) {
		/* ioctl failure */
		close(fd);
		return (PICL_FAILURE);
	}
	cap_reg = read_word(fd, bus, dev, func, cap_ptr, &ret);
	if (ret != 0) {
		/* ioctl failure */
		close(fd);
		return (PICL_FAILURE);
	}
	capid = cap_reg & PCI_CAP_MASK;
	while (cap_ptr != 0) {

		if (capid == PCI_CAP_ID_PCI_E) {
			link_cap = read_long(fd, bus, dev, func, cap_ptr +
			    PCIE_LINKCAP, &ret);
			if (ret != 0) {
				close(fd);
				return (PICL_FAILURE);
			}
			link_status = read_word(fd, bus, dev, func,
			    cap_ptr + PCIE_LINKSTS, &ret);
			if (ret != 0) {
				close(fd);
				return (PICL_FAILURE);
			}
			*actual = ((link_status >> PCI_LINK_SHIFT) &
			    PCI_LINK_MASK);
			*maximum = ((link_cap >> PCI_LINK_SHIFT) &
			    PCI_LINK_MASK);
			*type = PCIE;
		}
		if (capid == PCI_CAP_ID_PCIX) {
			uint32_t pcix_status;
			uint8_t hdr_type;
			int max_speed = PCI_FREQ_66;

			hdr_type = read_byte
			    (fd, bus, dev, func, PCI_CONF_HEADER, &ret);
			if (ret != 0) {
				/* ioctl failure */
				close(fd);
				return (PICL_FAILURE);
			}
			if ((hdr_type & PCI_HEADER_TYPE_M) == PCI_HEADER_PPB) {
				/* This is a PCI-X bridge */
				uint16_t sec_status, mode;
				sec_status = read_word(fd, bus, dev, func,
				    cap_ptr + PCI_PCIX_SEC_STATUS, &ret);
				if (ret != 0) {
					/* ioctl failure */
					close(fd);
					return (PICL_FAILURE);
				}
				if (sec_status & PCI_SEC_133)
					max_speed = PCI_FREQ_133;
				if (sec_status & PCI_SEC_266)
					max_speed = PCI_FREQ_266;
				if (sec_status & PCI_SEC_533)
					max_speed = PCI_FREQ_533;
				*speed_max = max_speed;
				*type = PCIX;
				mode = (sec_status >> PCI_CLASS_BRIDGE) &
				    PCI_BRIDGE_MC;
				if (mode) {
					int speed;
					if (mode == PCI_MODE_66)
						speed = PCI_FREQ_66;
					else if (mode == PCI_MODE_100)
						speed = PCI_FREQ_100;
					else if (mode == PCI_MODE_133)
						speed = PCI_FREQ_133;
					*speed_at = speed;
				}

			} else {  /* Leaf device */
				pcix_status = read_long(fd, bus, dev, func,
				    cap_ptr + PCI_PCIX_STATUS, &ret);
				if (ret != 0) {
					/* ioctl failure */
					close(fd);
					return (PICL_FAILURE);
				}
				if (pcix_status &
				    (PCI_LEAF_ULONG << PCI_SHIFT_133))
					max_speed = PCI_FREQ_133;
				if (pcix_status &
				    (PCI_LEAF_ULONG << PCI_SHIFT_266))
					max_speed = PCI_FREQ_266;
				if (pcix_status &
				    (PCI_LEAF_ULONG << PCI_SHIFT_533))
					max_speed = PCI_FREQ_533;
				*speed_max = max_speed;
				*type = PCI;
			}
		}
		cap_ptr = (cap_reg >> PCI_REG_FUNC_SHIFT);
		cap_reg = read_word(fd, bus, dev, func, cap_ptr, &ret);
		if (ret != 0) {
			/* ioctl failure */
			close(fd);
			return (PICL_FAILURE);
		}
		capid = cap_reg & PCI_CAP_MASK;
	}

	if (close(fd) == -1) {
		return (PICL_FAILURE);
	}

	return (PICL_SUCCESS);
}

/*
 * get the clock frequency
 */
static int
picldiag_get_clock_freq(picl_nodehdl_t modh, uint32_t *freq)
{
	int		err;
	uint64_t	clk_freq;

	clk_freq = picldiag_get_uint_propval(modh, OBP_PROP_CLOCK_FREQ, &err);
	if (err != PICL_SUCCESS)
		return (err);

	*freq = ROUND_TO_MHZ(clk_freq);

	return (PICL_SUCCESS);
}

static uint64_t
picldiag_get_uint_propval(picl_nodehdl_t modh, char *prop_name, int *ret)
{
	int		err;
	picl_prophdl_t	proph;
	picl_propinfo_t pinfo;
	uint8_t		uint8v;
	uint16_t	uint16v;
	uint32_t	uint32v;
	uint64_t	uint64v;

	err = picl_get_propinfo_by_name(modh, prop_name, &pinfo, &proph);
	if (err != PICL_SUCCESS) {
		*ret = err;
		return (0);
	}

	/*
	 * If it is not an int or uint prop, return failure
	 */
	if ((pinfo.type != PICL_PTYPE_INT) &&
	    (pinfo.type != PICL_PTYPE_UNSIGNED_INT)) {
		*ret = PICL_FAILURE;
		return (0);
	}


	/* uint prop */

	switch (pinfo.size) {
	case sizeof (uint8_t):
		err = picl_get_propval(proph, &uint8v, sizeof (uint8v));
		*ret = err;
		return (uint8v);
	case sizeof (uint16_t):
		err = picl_get_propval(proph, &uint16v, sizeof (uint16v));
		*ret = err;
		return (uint16v);
	case sizeof (uint32_t):
		err = picl_get_propval(proph, &uint32v, sizeof (uint32v));
		*ret = err;
		return (uint32v);
	case sizeof (uint64_t):
		err = picl_get_propval(proph, &uint64v, sizeof (uint64v));
		*ret = err;
		return (uint64v);
	default:	/* not supported size */
		*ret = PICL_FAILURE;
		return (0);
	}
}

/*
 * recursively visit all nodes
 */
static picl_errno_t
do_walk(picl_nodehdl_t rooth, const char *classname,
    void *c_args, picl_errno_t (*callback_fn)(picl_nodehdl_t hdl, void *args))
{
	picl_errno_t	err;
	picl_nodehdl_t  chdh;
	char		classval[PICL_CLASSNAMELEN_MAX];

	err = picl_get_propval_by_name(rooth, PICL_PROP_CHILD, &chdh,
	    sizeof (chdh));
	while (err == PICL_SUCCESS) {
		err = picl_get_propval_by_name(chdh, PICL_PROP_NAME,
		    classval, sizeof (classval));
		if (err != PICL_SUCCESS)
			return (err);

		err = callback_fn(chdh, c_args);

		if ((err = do_walk(chdh, classname, c_args, callback_fn)) !=
		    PICL_WALK_CONTINUE)
			return (err);

		err = picl_get_propval_by_name(chdh, PICL_PROP_PEER, &chdh,
		    sizeof (chdh));
	}
	if (err == PICL_PROPNOTFOUND)   /* end of a branch */
		return (PICL_WALK_CONTINUE);
	return (err);
}

int
get_proc_mode(void)
{
	picl_nodehdl_t nodeh;
	picl_prophdl_t  proph;
	picl_errno_t err;

	err = picl_initialize();
	if (err != PICL_SUCCESS) {
		(void) log_printf("picl_initialize failed: %s\n",
		    picl_strerror(err));
		return (err);
	}

	err = picl_get_node_by_path("/platform",  &nodeh);
	if (err != PICL_SUCCESS) {
		(void) log_printf("Getting plat node failed: %s\n",
		    picl_strerror(err));
		return (err);
	}

	err = picl_get_prop_by_name(nodeh, "SPARC64-VII-mode",  &proph);
	if (err != PICL_SUCCESS) {
		/* Do not display error message */
		return (err);
	}

	(void) picl_shutdown();

	return (err);
}
