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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * PICL plug-in that creates device tree nodes for all platforms
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <assert.h>
#include <alloca.h>
#include <unistd.h>
#include <stropts.h>
#include <syslog.h>
#include <libdevinfo.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/time.h>
#include <fcntl.h>
#include <picl.h>
#include <picltree.h>
#include <sys/types.h>
#include <sys/processor.h>
#include <kstat.h>
#include <sys/sysinfo.h>
#include <dirent.h>
#include <libintl.h>
#include <pthread.h>
#include <libnvpair.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <sys/obpdefs.h>
#include <sys/openpromio.h>
#include "picldevtree.h"

/*
 * Plugin registration entry points
 */
static void	picldevtree_register(void);
static void	picldevtree_init(void);
static void	picldevtree_fini(void);

static void	picldevtree_evhandler(const char *ename, const void *earg,
		    size_t size, void *cookie);

#pragma	init(picldevtree_register)

/*
 * Log message texts
 */
#define	DEVINFO_PLUGIN_INIT_FAILED	gettext("SUNW_picldevtree failed!\n")
#define	PICL_EVENT_DROPPED	\
	gettext("SUNW_picldevtree '%s' event dropped.\n")

/*
 * Macro to get PCI device id (from IEEE 1275 spec)
 */
#define	PCI_DEVICE_ID(x)			(((x) >> 11) & 0x1f)
/*
 * Local variables
 */
static picld_plugin_reg_t  my_reg_info = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_CRITICAL,
	"SUNW_picldevtree",
	picldevtree_init,
	picldevtree_fini
};

/*
 * Debug enabling environment variable
 */
#define	SUNW_PICLDEVTREE_PLUGIN_DEBUG	"SUNW_PICLDEVTREE_PLUGIN_DEBUG"
static	int		picldevtree_debug = 0;

static	conf_entries_t 	*conf_name_class_map = NULL;
static	builtin_map_t	sun4u_map[] = {
	/* MAX_NAMEVAL_SIZE */
	{ "SUNW,bpp", PICL_CLASS_PARALLEL},
	{ "parallel", PICL_CLASS_PARALLEL},
	{ "floppy", PICL_CLASS_FLOPPY},
	{ "memory", PICL_CLASS_MEMORY},
	{ "ebus", PICL_CLASS_EBUS},
	{ "i2c", PICL_CLASS_I2C},
	{ "usb", PICL_CLASS_USB},
	{ "isa", PICL_CLASS_ISA},
	{ "dma", PICL_CLASS_DMA},
	{ "keyboard", PICL_CLASS_KEYBOARD},
	{ "mouse", PICL_CLASS_MOUSE},
	{ "fan-control", PICL_CLASS_FAN_CONTROL},
	{ "sc", PICL_CLASS_SYSTEM_CONTROLLER},
	{ "dimm", PICL_CLASS_SEEPROM},
	{ "dimm-fru", PICL_CLASS_SEEPROM},
	{ "cpu", PICL_CLASS_SEEPROM},
	{ "cpu-fru", PICL_CLASS_SEEPROM},
	{ "flashprom", PICL_CLASS_FLASHPROM},
	{ "temperature", PICL_CLASS_TEMPERATURE_DEVICE},
	{ "motherboard", PICL_CLASS_SEEPROM},
	{ "motherboard-fru", PICL_CLASS_SEEPROM},
	{ "motherboard-fru-prom", PICL_CLASS_SEEPROM},
	{ "pmu", PICL_CLASS_PMU},
	{ "sound", PICL_CLASS_SOUND},
	{ "firewire", PICL_CLASS_FIREWIRE},
	{ "i2c-at34c02", PICL_CLASS_SEEPROM},
	{ "hardware-monitor", PICL_CLASS_HARDWARE_MONITOR},
	{ "", ""}
};
static	builtin_map_t	i86pc_map[] = {
	/* MAX_NAMEVAL_SIZE */
	{ "cpus", PICL_CLASS_I86CPUS},
	{ "cpu", PICL_CLASS_CPU},
	{ "memory", PICL_CLASS_MEMORY},
	{ "asy", PICL_CLASS_SERIAL},
	{ "", ""}
};
static	pname_type_map_t	pname_type_map[] = {
	{ "reg", PICL_PTYPE_BYTEARRAY},
	{ "device_type", PICL_PTYPE_CHARSTRING},
	{ "ranges", PICL_PTYPE_BYTEARRAY},
	{ "status", PICL_PTYPE_CHARSTRING},
	{ "compatible", PICL_PTYPE_CHARSTRING},
	{ "interrupts", PICL_PTYPE_BYTEARRAY},
	{ "model", PICL_PTYPE_CHARSTRING},
	{ "address", PICL_PTYPE_BYTEARRAY},
	{ "vendor-id", PICL_PTYPE_UNSIGNED_INT},
	{ "device-id", PICL_PTYPE_UNSIGNED_INT},
	{ "revision-id", PICL_PTYPE_UNSIGNED_INT},
	{ "class-code", PICL_PTYPE_UNSIGNED_INT},
	{ "min-grant", PICL_PTYPE_UNSIGNED_INT},
	{ "max-latency", PICL_PTYPE_UNSIGNED_INT},
	{ "devsel-speed", PICL_PTYPE_UNSIGNED_INT},
	{ "subsystem-id", PICL_PTYPE_UNSIGNED_INT},
	{ "subsystem-vendor-id", PICL_PTYPE_UNSIGNED_INT},
	{ "assigned-addresses", PICL_PTYPE_BYTEARRAY},
	{ "configuration#", PICL_PTYPE_UNSIGNED_INT},
	{ "assigned-address", PICL_PTYPE_UNSIGNED_INT},
	{ "#address-cells", PICL_PTYPE_UNSIGNED_INT},
	{ "#size-cells", PICL_PTYPE_UNSIGNED_INT},
	{ "clock-frequency", PICL_PTYPE_UNSIGNED_INT},
	{ "scsi-initiator-id", PICL_PTYPE_UNSIGNED_INT},
	{ "differential", PICL_PTYPE_UNSIGNED_INT},
	{ "idprom", PICL_PTYPE_BYTEARRAY},
	{ "bus-range", PICL_PTYPE_BYTEARRAY},
	{ "alternate-reg", PICL_PTYPE_BYTEARRAY},
	{ "power-consumption", PICL_PTYPE_BYTEARRAY},
	{ "slot-names", PICL_PTYPE_BYTEARRAY},
	{ "burst-sizes", PICL_PTYPE_UNSIGNED_INT},
	{ "up-burst-sizes", PICL_PTYPE_UNSIGNED_INT},
	{ "slot-address-bits", PICL_PTYPE_UNSIGNED_INT},
	{ "eisa-slots", PICL_PTYPE_BYTEARRAY},
	{ "dma", PICL_PTYPE_BYTEARRAY},
	{ "slot-names-index", PICL_PTYPE_UNSIGNED_INT},
	{ "pnp-csn", PICL_PTYPE_UNSIGNED_INT},
	{ "pnp-data", PICL_PTYPE_BYTEARRAY},
	{ "description", PICL_PTYPE_CHARSTRING},
	{ "pnp-id", PICL_PTYPE_CHARSTRING},
	{ "max-frame-size", PICL_PTYPE_UNSIGNED_INT},
	{ "address-bits", PICL_PTYPE_UNSIGNED_INT},
	{ "local-mac-address", PICL_PTYPE_BYTEARRAY},
	{ "mac-address", PICL_PTYPE_BYTEARRAY},
	{ "character-set", PICL_PTYPE_CHARSTRING},
	{ "available", PICL_PTYPE_BYTEARRAY},
	{ "port-wwn", PICL_PTYPE_BYTEARRAY},
	{ "node-wwn", PICL_PTYPE_BYTEARRAY},
	{ "width", PICL_PTYPE_UNSIGNED_INT},
	{ "linebytes", PICL_PTYPE_UNSIGNED_INT},
	{ "height", PICL_PTYPE_UNSIGNED_INT},
	{ "banner-name", PICL_PTYPE_CHARSTRING},
	{ "reset-reason", PICL_PTYPE_CHARSTRING},
	{ "implementation#", PICL_PTYPE_UNSIGNED_INT},
	{ "version#", PICL_PTYPE_UNSIGNED_INT},
	{ "icache-size", PICL_PTYPE_UNSIGNED_INT},
	{ "icache-line-size", PICL_PTYPE_UNSIGNED_INT},
	{ "icache-associativity", PICL_PTYPE_UNSIGNED_INT},
	{ "l1-icache-size", PICL_PTYPE_UNSIGNED_INT},
	{ "l1-icache-line-size", PICL_PTYPE_UNSIGNED_INT},
	{ "l1-icache-associativity", PICL_PTYPE_UNSIGNED_INT},
	{ "#itlb-entries", PICL_PTYPE_UNSIGNED_INT},
	{ "dcache-size", PICL_PTYPE_UNSIGNED_INT},
	{ "dcache-line-size", PICL_PTYPE_UNSIGNED_INT},
	{ "dcache-associativity", PICL_PTYPE_UNSIGNED_INT},
	{ "l1-dcache-size", PICL_PTYPE_UNSIGNED_INT},
	{ "l1-dcache-line-size", PICL_PTYPE_UNSIGNED_INT},
	{ "l1-dcache-associativity", PICL_PTYPE_UNSIGNED_INT},
	{ "#dtlb-entries", PICL_PTYPE_UNSIGNED_INT},
	{ "ecache-size", PICL_PTYPE_UNSIGNED_INT},
	{ "ecache-line-size", PICL_PTYPE_UNSIGNED_INT},
	{ "ecache-associativity", PICL_PTYPE_UNSIGNED_INT},
	{ "l2-cache-size", PICL_PTYPE_UNSIGNED_INT},
	{ "l2-cache-line-size", PICL_PTYPE_UNSIGNED_INT},
	{ "l2-cache-associativity", PICL_PTYPE_UNSIGNED_INT},
	{ "l2-cache-sharing", PICL_PTYPE_BYTEARRAY},
	{ "mask#", PICL_PTYPE_UNSIGNED_INT},
	{ "manufacturer#", PICL_PTYPE_UNSIGNED_INT},
	{ "sparc-version", PICL_PTYPE_UNSIGNED_INT},
	{ "version", PICL_PTYPE_CHARSTRING},
	{ "cpu-model", PICL_PTYPE_UNSIGNED_INT},
	{ "memory-layout", PICL_PTYPE_BYTEARRAY},
	{ "#interrupt-cells", PICL_PTYPE_UNSIGNED_INT},
	{ "interrupt-map", PICL_PTYPE_BYTEARRAY},
	{ "interrupt-map-mask", PICL_PTYPE_BYTEARRAY}
};

#define	PNAME_MAP_SIZE	sizeof (pname_type_map) / sizeof (pname_type_map_t)

static	builtin_map_t	*builtin_map_ptr = NULL;
static	int		builtin_map_size = 0;
static	char		mach_name[SYS_NMLN];
static	di_prom_handle_t	ph = DI_PROM_HANDLE_NIL;
static	int		snapshot_stale;

/*
 * UnitAddress mapping table
 */
static	unitaddr_func_t	encode_default_unitaddr;
static	unitaddr_func_t	encode_optional_unitaddr;
static	unitaddr_func_t	encode_scsi_unitaddr;
static	unitaddr_func_t	encode_upa_unitaddr;
static	unitaddr_func_t	encode_gptwo_jbus_unitaddr;
static	unitaddr_func_t	encode_pci_unitaddr;

static	unitaddr_map_t unitaddr_map_table[] = {
	{PICL_CLASS_JBUS, encode_gptwo_jbus_unitaddr, 0},
	{PICL_CLASS_GPTWO, encode_gptwo_jbus_unitaddr, 0},
	{PICL_CLASS_PCI, encode_pci_unitaddr, 0},
	{PICL_CLASS_PCIEX, encode_pci_unitaddr, 0},
	{PICL_CLASS_UPA, encode_upa_unitaddr, 0},
	{PICL_CLASS_SCSI, encode_scsi_unitaddr, 0},
	{PICL_CLASS_SCSI2, encode_scsi_unitaddr, 0},
	{PICL_CLASS_EBUS, encode_default_unitaddr, 2},
	{PICL_CLASS_SBUS, encode_default_unitaddr, 2},
	{PICL_CLASS_I2C, encode_default_unitaddr, 2},
	{PICL_CLASS_USB, encode_default_unitaddr, 1},
	{PICL_CLASS_PMU, encode_optional_unitaddr, 2},
	{NULL, encode_default_unitaddr, 0}
};

static int add_unitaddr_prop_to_subtree(picl_nodehdl_t nodeh);
static int get_unitaddr(picl_nodehdl_t parh, picl_nodehdl_t nodeh,
	char *unitaddr, size_t ualen);
static void set_pci_pciex_deviceid(picl_nodehdl_t plafh);

/*
 * The mc event completion handler.
 * The arguments are event name buffer and a packed nvlist buffer
 * with the size specifying the size of unpacked nvlist. These
 * buffers are deallcoated here.
 *
 * Also, if a memory controller node is being removed then destroy the
 * PICL subtree associated with that memory controller.
 */
static void
mc_completion_handler(char *ename, void *earg, size_t size)
{
	picl_nodehdl_t	mch;
	nvlist_t	*unpack_nvl;

	if (strcmp(ename, PICLEVENT_MC_REMOVED) == 0 &&
	    nvlist_unpack(earg, size, &unpack_nvl, NULL) == 0) {
		mch = NULL;
		(void) nvlist_lookup_uint64(unpack_nvl,
		    PICLEVENTARG_NODEHANDLE, &mch);
		if (mch != NULL) {
			if (picldevtree_debug)
				syslog(LOG_INFO,
				    "picldevtree: destroying_node:%llx\n",
				    mch);
			(void) ptree_destroy_node(mch);
		}
		nvlist_free(unpack_nvl);
	}

	free(ename);
	free(earg);
}

/*
 * Functions to post memory controller change event
 */
static int
post_mc_event(char *ename, picl_nodehdl_t mch)
{
	nvlist_t	*nvl;
	size_t		nvl_size;
	char		*pack_buf;
	char		*ev_name;

	ev_name = strdup(ename);
	if (ev_name == NULL)
		return (-1);

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME_TYPE, NULL)) {
		free(ev_name);
		return (-1);
	}

	pack_buf = NULL;
	if (nvlist_add_uint64(nvl, PICLEVENTARG_NODEHANDLE, mch) ||
	    nvlist_pack(nvl, &pack_buf, &nvl_size, NV_ENCODE_NATIVE, NULL)) {
		free(ev_name);
		nvlist_free(nvl);
		return (-1);
	}

	if (picldevtree_debug)
		syslog(LOG_INFO,
		    "picldevtree: posting MC event ename:%s nodeh:%llx\n",
		    ev_name, mch);
	if (ptree_post_event(ev_name, pack_buf, nvl_size,
	    mc_completion_handler) != PICL_SUCCESS) {
		free(ev_name);
		nvlist_free(nvl);
		return (-1);
	}
	nvlist_free(nvl);
	return (0);
}

/*
 * Lookup a name in the name to class map tables
 */
static int
lookup_name_class_map(char *classbuf, const char *nm)
{
	conf_entries_t	*ptr;
	int		i;

	/*
	 * check name to class mapping in conf file
	 */
	ptr = conf_name_class_map;

	while (ptr != NULL) {
		if (strcmp(ptr->name, nm) == 0) {
			(void) strlcpy(classbuf, ptr->piclclass,
			    PICL_CLASSNAMELEN_MAX);
			return (0);
		}
		ptr = ptr->next;
	}

	/*
	 * check name to class mapping in builtin table
	 */
	if (builtin_map_ptr == NULL)
		return (-1);

	for (i = 0; i < builtin_map_size; ++i)
		if (strcmp(builtin_map_ptr[i].name, nm) == 0) {
			(void) strlcpy(classbuf, builtin_map_ptr[i].piclclass,
			    PICL_CLASSNAMELEN_MAX);
			return (0);
		}
	return (-1);
}

/*
 * Lookup a prop name in the pname to class map table
 */
static int
lookup_pname_type_map(const char *pname, picl_prop_type_t *type)
{
	int		i;

	for (i = 0; i < PNAME_MAP_SIZE; ++i)
		if (strcmp(pname_type_map[i].pname, pname) == 0) {
			*type = pname_type_map[i].type;
			return (0);
		}

	return (-1);
}

/*
 * Return the number of strings in the buffer
 */
static int
get_string_count(char *strdat, int length)
{
	int	count;
	char	*lastnull;
	char	*nullptr;

	count = 1;
	for (lastnull = &strdat[length - 1], nullptr = strchr(strdat, '\0');
	    nullptr != lastnull; nullptr = strchr(nullptr+1, '\0'))
		count++;

	return (count);
}

/*
 * Return 1 if the node has a "reg" property
 */
static int
has_reg_prop(di_node_t dn)
{
	int			*pdata;
	int			dret;

	dret = di_prop_lookup_ints(DDI_DEV_T_ANY, dn, OBP_REG, &pdata);
	if (dret > 0)
		return (1);

	if (!ph)
		return (0);
	dret = di_prom_prop_lookup_ints(ph, dn, OBP_REG, &pdata);
	return (dret < 0 ? 0 : 1);
}

/*
 * This function copies a PROM node's device_type property value into the
 * buffer given by outbuf. The buffer size is PICL_CLASSNAMELEN_MAX.
 *
 * We reclassify device_type 'fru-prom' to PICL class 'seeprom'
 * for FRUID support.
 */
static int
get_device_type(char *outbuf, di_node_t dn)
{
	char			*pdata;
	char			*pdatap;
	int			dret;
	int			i;

	dret = di_prop_lookup_strings(DDI_DEV_T_ANY, dn, OBP_DEVICETYPE,
	    &pdata);
	if (dret <= 0) {
		if (!ph)
			return (-1);

		dret = di_prom_prop_lookup_strings(ph, dn, OBP_DEVICETYPE,
		    &pdata);
		if (dret <= 0) {
			return (-1);
		}
	}

	if (dret != 1) {
		/*
		 * multiple strings
		 */
		pdatap = pdata;
		for (i = 0; i < (dret - 1); ++i) {
			pdatap += strlen(pdatap);
			*pdatap = '-';	/* replace '\0' with '-' */
			pdatap++;
		}
	}
	if (strcasecmp(pdata, "fru-prom") == 0) {
		/*
		 * Use PICL 'seeprom' class for fru-prom device types
		 */
		(void) strlcpy(outbuf, PICL_CLASS_SEEPROM,
		    PICL_CLASSNAMELEN_MAX);
	} else {
		(void) strlcpy(outbuf, pdata, PICL_CLASSNAMELEN_MAX);
	}
	return (0);
}

/*
 * Get the minor node name in the class buffer passed
 */
static int
get_minor_class(char *classbuf, di_node_t dn)
{
	di_minor_t	mi_node;
	char		*mi_nodetype;
	char		*mi_name;

	/* get minor node type */
	mi_node = di_minor_next(dn, DI_MINOR_NIL);
	if (mi_node == DI_MINOR_NIL)
		return (-1);

	mi_nodetype = di_minor_nodetype(mi_node);
	if (mi_nodetype == NULL) { /* no type info, return name */
		mi_name = di_minor_name(mi_node);
		if (mi_name == NULL)
			return (-1);
		(void) strlcpy(classbuf, mi_name, PICL_CLASSNAMELEN_MAX);
		return (0);
	}

#define	DDI_NODETYPE(x, y) (strncmp(x, y, (sizeof (y) - 1)) == 0)

	/*
	 * convert the string to the picl class for non-peudo nodes
	 */
	if (DDI_NODETYPE(mi_nodetype, DDI_PSEUDO))
		return (-1);
	else if (DDI_NODETYPE(mi_nodetype, DDI_NT_BLOCK_WWN))
		(void) strcpy(classbuf, PICL_CLASS_BLOCK);
	else if (DDI_NODETYPE(mi_nodetype, DDI_NT_BLOCK_CHAN))
		(void) strcpy(classbuf, PICL_CLASS_BLOCK);
	else if (DDI_NODETYPE(mi_nodetype, DDI_NT_CD))
		(void) strcpy(classbuf, PICL_CLASS_CDROM);
	else if (DDI_NODETYPE(mi_nodetype, DDI_NT_CD_CHAN))
		(void) strcpy(classbuf, PICL_CLASS_CDROM);
	else if (DDI_NODETYPE(mi_nodetype, DDI_NT_FD))
		(void) strcpy(classbuf, PICL_CLASS_FLOPPY);
	else if (DDI_NODETYPE(mi_nodetype, DDI_NT_BLOCK_FABRIC))
		(void) strcpy(classbuf, PICL_CLASS_FABRIC);
	else if (DDI_NODETYPE(mi_nodetype, DDI_NT_BLOCK_SAS))
		(void) strcpy(classbuf, PICL_CLASS_SAS);
	else if (DDI_NODETYPE(mi_nodetype, DDI_NT_BLOCK))
		(void) strcpy(classbuf, PICL_CLASS_BLOCK);
	else if (DDI_NODETYPE(mi_nodetype, DDI_NT_MOUSE))
		(void) strcpy(classbuf, PICL_CLASS_MOUSE);
	else if (DDI_NODETYPE(mi_nodetype, DDI_NT_KEYBOARD))
		(void) strcpy(classbuf, PICL_CLASS_KEYBOARD);
	else if (DDI_NODETYPE(mi_nodetype, DDI_NT_ATTACHMENT_POINT))
		(void) strcpy(classbuf, PICL_CLASS_ATTACHMENT_POINT);
	else if (DDI_NODETYPE(mi_nodetype, DDI_NT_TAPE))
		(void) strcpy(classbuf, PICL_CLASS_TAPE);
	else if (DDI_NODETYPE(mi_nodetype, DDI_NT_SCSI_ENCLOSURE))
		(void) strcpy(classbuf, PICL_CLASS_SCSI);
	else if (DDI_NODETYPE(mi_nodetype, DDI_NT_ENCLOSURE)) {
		char	*colon;

		if ((colon = strchr(mi_nodetype, ':')) == NULL)
			return (-1);
		++colon;
		(void) strcpy(classbuf, colon);
	} else {	/* unrecognized type, return name */
		mi_name = di_minor_name(mi_node);
		if (mi_name == NULL)
			return (-1);
		(void) strlcpy(classbuf, mi_name, PICL_CLASSNAMELEN_MAX);
	}
	return (0);
}

/*
 * Derive PICL class using the compatible property of the node
 * We use the map table to map compatible property value to
 * class.
 */
static int
get_compatible_class(char *outbuf, di_node_t dn)
{
	char			*pdata;
	char			*pdatap;
	int			dret;
	int			i;

	dret = di_prop_lookup_strings(DDI_DEV_T_ANY, dn, OBP_COMPATIBLE,
	    &pdata);
	if (dret <= 0) {
		if (!ph)
			return (-1);

		dret = di_prom_prop_lookup_strings(ph, dn, OBP_COMPATIBLE,
		    &pdata);
		if (dret <= 0) {
			return (-1);
		}
	}

	pdatap = pdata;
	for (i = 0; i < dret; ++i) {
		if (lookup_name_class_map(outbuf, pdatap) == 0)
			return (0);
		pdatap += strlen(pdatap);
		pdatap++;
	}
	return (-1);
}

/*
 * For a given device node find the PICL class to use. Returns NULL
 * for non device node
 */
static int
get_node_class(char *classbuf, di_node_t dn, const char *nodename)
{
	if (get_device_type(classbuf, dn) == 0) {
		if (di_nodeid(dn) == DI_PROM_NODEID) {
			/*
			 * discard place holder nodes
			 */
			if ((strcmp(classbuf, DEVICE_TYPE_BLOCK) == 0) ||
			    (strcmp(classbuf, DEVICE_TYPE_BYTE) == 0) ||
			    (strcmp(classbuf, DEVICE_TYPE_SES) == 0) ||
			    (strcmp(classbuf, DEVICE_TYPE_FP) == 0) ||
			    (strcmp(classbuf, DEVICE_TYPE_DISK) == 0))
				return (-1);

			return (0);
		}
		return (0);	/* return device_type value */
	}

	if (get_compatible_class(classbuf, dn) == 0) {
		return (0);	/* derive class using compatible prop */
	}

	if (lookup_name_class_map(classbuf, nodename) == 0)
		return (0);	/* derive class using name prop */

	if (has_reg_prop(dn)) { /* use default obp-device */
		(void) strcpy(classbuf, PICL_CLASS_OBP_DEVICE);
		return (0);
	}

	return (get_minor_class(classbuf, dn));
}

/*
 * Add a table property containing nrows with one column
 */
static int
add_string_list_prop(picl_nodehdl_t nodeh, char *name, char *strlist,
    unsigned int nrows)
{
	ptree_propinfo_t	propinfo;
	picl_prophdl_t		proph;
	picl_prophdl_t		tblh;
	int			err;
	unsigned int		i;
	unsigned int		j;
	picl_prophdl_t		*proprow;
	int			len;

#define	NCOLS_IN_STRING_TABLE	1

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_TABLE, PICL_READ, sizeof (picl_prophdl_t), name,
	    NULL, NULL);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_create_table(&tblh);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_create_and_add_prop(nodeh, &propinfo, &tblh, &proph);
	if (err != PICL_SUCCESS)
		return (err);

	proprow = alloca(sizeof (picl_prophdl_t) * nrows);
	if (proprow == NULL) {
		(void) ptree_destroy_prop(proph);
		return (PICL_FAILURE);
	}

	for (j = 0; j < nrows; ++j) {
		len = strlen(strlist) + 1;
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_CHARSTRING, PICL_READ, len, name,
		    NULL, NULL);
		if (err != PICL_SUCCESS)
			break;
		err = ptree_create_prop(&propinfo, strlist, &proprow[j]);
		if (err != PICL_SUCCESS)
			break;
		strlist += len;
		err = ptree_add_row_to_table(tblh, NCOLS_IN_STRING_TABLE,
		    &proprow[j]);
		if (err != PICL_SUCCESS)
			break;
	}

	if (err != PICL_SUCCESS) {
		for (i = 0; i < j; ++i)
			(void) ptree_destroy_prop(proprow[i]);
		(void) ptree_delete_prop(proph);
		(void) ptree_destroy_prop(proph);
		return (err);
	}

	return (PICL_SUCCESS);
}

/*
 * return 1 if this node has this property with the given value
 */
static int
compare_string_propval(picl_nodehdl_t nodeh, const char *pname,
    const char *pval)
{
	char			*pvalbuf;
	int			err;
	int			len;
	ptree_propinfo_t	pinfo;
	picl_prophdl_t		proph;

	err = ptree_get_prop_by_name(nodeh, pname, &proph);
	if (err != PICL_SUCCESS)	/* prop doesn't exist */
		return (0);

	err = ptree_get_propinfo(proph, &pinfo);
	if (pinfo.piclinfo.type != PICL_PTYPE_CHARSTRING)
		return (0);	/* not string prop */

	len = strlen(pval) + 1;

	pvalbuf = alloca(len);
	if (pvalbuf == NULL)
		return (0);

	err = ptree_get_propval(proph, pvalbuf, len);
	if ((err == PICL_SUCCESS) && (strcmp(pvalbuf, pval) == 0))
		return (1);	/* prop match */

	return (0);
}

/*
 * This function recursively searches the tree for a node that has
 * the specified string property name and value
 */
static int
find_node_by_string_prop(picl_nodehdl_t rooth, const char *pname,
    const char *pval, picl_nodehdl_t *nodeh)
{
	picl_nodehdl_t		childh;
	int			err;

	for (err = ptree_get_propval_by_name(rooth, PICL_PROP_CHILD, &childh,
	    sizeof (picl_nodehdl_t)); err != PICL_PROPNOTFOUND;
	    err = ptree_get_propval_by_name(childh, PICL_PROP_PEER, &childh,
	    sizeof (picl_nodehdl_t))) {
		if (err != PICL_SUCCESS)
			return (err);

		if (compare_string_propval(childh, pname, pval)) {
			*nodeh = childh;
			return (PICL_SUCCESS);
		}

		if (find_node_by_string_prop(childh, pname, pval, nodeh) ==
		    PICL_SUCCESS)
			return (PICL_SUCCESS);
	}

	return (PICL_FAILURE);
}

/*
 * check if this is a string prop
 * If the length is less than or equal to 4, assume it's not a string list.
 * If there is any non-ascii or non-print char, it's not a string prop
 * If \0 is in the first char or any two consecutive \0's exist,
 * it's a bytearray prop.
 * Return value: 0 means it's not a string prop, 1 means it's a string prop
 */
static int
is_string_propval(unsigned char *pdata, int len)
{
	int	i;
	int	lastindex;
	int	prevnull = -1;

	switch (len) {
	case 1:
		if (!isascii(pdata[0]) || !isprint(pdata[0]))
			return (0);
		return (1);
	case 2:
	case 3:
	case 4:
		lastindex = len;
		if (pdata[len-1] == '\0')
			lastindex = len - 1;

		for (i = 0; i < lastindex; i++)
			if (!isascii(pdata[i]) || !isprint(pdata[i]))
				return (0);

		return (1);

	default:
		if (len <= 0)
			return (0);
		for (i = 0; i < len; i++) {
			if (!isascii(pdata[i]) || !isprint(pdata[i])) {
				if (pdata[i] != '\0')
					return (0);
				/*
				 * if the null char is in the first char
				 * or two consecutive nulls' exist,
				 * it's a bytearray prop
				 */
				if ((i == 0) || ((i - prevnull) == 1))
					return (0);

				prevnull = i;
			}
		}
		break;
	}

	return (1);
}

/*
 * This function counts the number of strings in the value buffer pdata
 * and creates a property.
 * If there is only one string in the buffer, pdata, a charstring property
 * type is created and added.
 * If there are more than one string in the buffer, pdata, then a table
 * of charstrings is added.
 */
static int
process_charstring_data(picl_nodehdl_t nodeh, char *pname, unsigned char *pdata,
    int retval)
{
	int			err;
	int			strcount;
	char			*strdat;
	ptree_propinfo_t	propinfo;

	/*
	 * append the null char at the end of string when there is
	 * no null terminator
	 */
	if (pdata[retval - 1] != '\0') {
		strdat = alloca(retval + 1);
		(void) memcpy(strdat, pdata, retval);
		strdat[retval] = '\0';
		retval++;
	} else {
		strdat = alloca(retval);
		(void) memcpy(strdat, pdata, retval);
	}

	/*
	 * If it's a string list, create a table prop
	 */
	strcount = get_string_count(strdat, retval);
	if (strcount > 1) {
		err = add_string_list_prop(nodeh, pname,
		    strdat, strcount);
		if (err != PICL_SUCCESS)
			return (err);
	} else {
		err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_CHARSTRING, PICL_READ,
		    strlen(strdat) + 1, pname, NULL,
		    NULL);
		if (err != PICL_SUCCESS)
			return (err);
		(void) ptree_create_and_add_prop(nodeh, &propinfo,
		    strdat, NULL);
	}
	return (PICL_SUCCESS);
}

/*
 * Add the OBP properties as properties of the PICL node
 */
static int
add_openprom_props(picl_nodehdl_t nodeh, di_node_t di_node)
{
	di_prom_prop_t		promp;
	char			*pname;
	unsigned char		*pdata;
	int			retval;
	ptree_propinfo_t	propinfo;
	int			err;
	picl_prop_type_t	type;

	if (!ph)
		return (PICL_FAILURE);

	for (promp = di_prom_prop_next(ph, di_node, DI_PROM_PROP_NIL);
	    promp != DI_PROM_PROP_NIL;
	    promp = di_prom_prop_next(ph, di_node, promp)) {

		pname = di_prom_prop_name(promp);

		retval = di_prom_prop_data(promp, &pdata);
		if (retval < 0) {
			return (PICL_SUCCESS);
		}
		if (retval == 0) {
			err = ptree_init_propinfo(&propinfo,
			    PTREE_PROPINFO_VERSION, PICL_PTYPE_VOID,
			    PICL_READ, (size_t)0, pname, NULL, NULL);
			if (err != PICL_SUCCESS) {
				return (err);
			}
			(void) ptree_create_and_add_prop(nodeh, &propinfo, NULL,
			    NULL);
			continue;
		}

		/*
		 * Get the prop type from pname map table
		 */
		if (lookup_pname_type_map(pname, &type) == 0) {
			if (type == PICL_PTYPE_CHARSTRING) {
				err = process_charstring_data(nodeh, pname,
				    pdata, retval);
				if (err != PICL_SUCCESS) {
					return (err);
				}
				continue;
			}

			err = ptree_init_propinfo(&propinfo,
			    PTREE_PROPINFO_VERSION, type, PICL_READ,
			    retval, pname, NULL, NULL);
			if (err != PICL_SUCCESS) {
				return (err);
			}
			(void) ptree_create_and_add_prop(nodeh, &propinfo,
			    pdata, NULL);
		} else if (!is_string_propval(pdata, retval)) {
			switch (retval) {
			case sizeof (uint8_t):
				/*FALLTHROUGH*/
			case sizeof (uint16_t):
				/*FALLTHROUGH*/
			case sizeof (uint32_t):
				type = PICL_PTYPE_UNSIGNED_INT;
				break;
			default:
				type = PICL_PTYPE_BYTEARRAY;
				break;
			}
			err = ptree_init_propinfo(&propinfo,
			    PTREE_PROPINFO_VERSION, type, PICL_READ,
			    retval, pname, NULL, NULL);
			if (err != PICL_SUCCESS) {
				return (err);
			}
			(void) ptree_create_and_add_prop(nodeh, &propinfo,
			    pdata, NULL);
		} else {
			err = process_charstring_data(nodeh, pname, pdata,
			    retval);
			if (err != PICL_SUCCESS) {
				return (err);
			}
		}
	}

	return (PICL_SUCCESS);
}

static void
add_boolean_prop(picl_nodehdl_t nodeh, ptree_propinfo_t propinfo, char *di_val)
{
	(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_VOID, PICL_READ, (size_t)0, di_val, NULL, NULL);
	(void) ptree_create_and_add_prop(nodeh, &propinfo, NULL, NULL);
}

static void
add_uints_prop(picl_nodehdl_t nodeh, ptree_propinfo_t propinfo, char *di_val,
    int *idata, int len)
{
	if (len == 1)
		(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_UNSIGNED_INT, PICL_READ, sizeof (int), di_val,
		    NULL, NULL);
	else
		(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_BYTEARRAY, PICL_READ, len * sizeof (int), di_val,
		    NULL, NULL);

	(void) ptree_create_and_add_prop(nodeh, &propinfo, idata, NULL);
}

static void
add_strings_prop(picl_nodehdl_t nodeh, ptree_propinfo_t propinfo, char *di_val,
    char *sdata, int len)
{
	if (len == 1) {
		(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(sdata) + 1, di_val,
		    NULL, NULL);
		(void) ptree_create_and_add_prop(nodeh, &propinfo, sdata, NULL);
	} else {
		(void) add_string_list_prop(nodeh, di_val, sdata, len);
	}
}

static void
add_bytes_prop(picl_nodehdl_t nodeh, ptree_propinfo_t propinfo, char *di_val,
    unsigned char *bdata, int len)
{
	(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_BYTEARRAY, PICL_READ, len, di_val, NULL, NULL);
	(void) ptree_create_and_add_prop(nodeh, &propinfo, bdata, NULL);
}

static const char *
path_state_name(di_path_state_t st)
{
	switch (st) {
		case DI_PATH_STATE_ONLINE:
			return ("online");
		case DI_PATH_STATE_STANDBY:
			return ("standby");
		case DI_PATH_STATE_OFFLINE:
			return ("offline");
		case DI_PATH_STATE_FAULT:
			return ("faulted");
	}
	return ("unknown");
}

/*
 * This function is the volatile property handler for the multipath node
 * "State" property. It must locate the associated devinfo node in order to
 * determine the current state. Since the devinfo node can have multiple
 * paths the devfs_path is used to locate the correct path.
 */
static int
get_path_state_name(ptree_rarg_t *rarg, void *vbuf)
{
	int		err;
	picl_nodehdl_t	parh;
	char		devfs_path[PATH_MAX];
	di_node_t	di_node;
	di_node_t	di_root;
	di_path_t	pi = DI_PATH_NIL;
	picl_nodehdl_t	mpnode;

	(void) strlcpy(vbuf, "unknown", MAX_STATE_SIZE);

	mpnode = rarg->nodeh;

	/*
	 * The parent node represents the vHCI.
	 */
	err = ptree_get_propval_by_name(mpnode, PICL_PROP_PARENT, &parh,
	    sizeof (picl_nodehdl_t));
	if (err != PICL_SUCCESS) {
		return (PICL_SUCCESS);
	}

	/*
	 * The PICL_PROP_DEVFS_PATH property will be used to locate the
	 * devinfo node for the vHCI driver.
	 */
	err = ptree_get_propval_by_name(parh, PICL_PROP_DEVFS_PATH, devfs_path,
	    sizeof (devfs_path));
	if (err != PICL_SUCCESS) {
		return (PICL_SUCCESS);
	}
	/*
	 * Find the di_node for the vHCI driver. It will be used to scan
	 * the path information nodes.
	 */
	di_root = di_init("/", DINFOCACHE);
	if (di_root == DI_NODE_NIL) {
		return (PICL_SUCCESS);
	}
	di_node = di_lookup_node(di_root, devfs_path);
	if (di_node == DI_NODE_NIL) {
		di_fini(di_root);
		return (PICL_SUCCESS);
	}

	/*
	 * The devfs_path will be used below to match the
	 * proper path information node.
	 */
	err = ptree_get_propval_by_name(mpnode, PICL_PROP_DEVFS_PATH,
	    devfs_path, sizeof (devfs_path));
	if (err != PICL_SUCCESS) {
		di_fini(di_root);
		return (PICL_SUCCESS);
	}

	/*
	 * Scan the path information nodes looking for the matching devfs
	 * path. When found obtain the state information.
	 */
	while ((pi = di_path_next_phci(di_node, pi)) != DI_PATH_NIL) {
		char		*di_path;
		di_node_t	phci_node = di_path_phci_node(pi);

		if (phci_node == DI_PATH_NIL)
			continue;

		di_path = di_devfs_path(phci_node);
		if (di_path) {
			if (strcmp(di_path, devfs_path) != 0) {
				di_devfs_path_free(di_path);
				continue;
			}
			(void) strlcpy(vbuf, path_state_name(di_path_state(pi)),
			    MAX_STATE_SIZE);
			di_devfs_path_free(di_path);
			break;
		}
	}

	di_fini(di_root);
	return (PICL_SUCCESS);
}

static void
add_di_path_prop(picl_nodehdl_t nodeh, di_path_prop_t di_path_prop)
{
	int			di_ptype;
	char			*di_val;
	ptree_propinfo_t	propinfo;
	int			*idata;
	char			*sdata;
	unsigned char		*bdata;
	int			len;

	di_ptype = di_path_prop_type(di_path_prop);
	di_val = di_path_prop_name(di_path_prop);

	switch (di_ptype) {
	case DI_PROP_TYPE_BOOLEAN:
		add_boolean_prop(nodeh, propinfo, di_val);
		break;
	case DI_PROP_TYPE_INT:
	case DI_PROP_TYPE_INT64:
		len = di_path_prop_ints(di_path_prop, &idata);
		if (len < 0)
			/* Received error, so ignore prop */
			break;
		add_uints_prop(nodeh, propinfo, di_val, idata, len);
		break;
	case DI_PROP_TYPE_STRING:
		len = di_path_prop_strings(di_path_prop, &sdata);
		if (len <= 0)
			break;
		add_strings_prop(nodeh, propinfo, di_val, sdata, len);
		break;
	case DI_PROP_TYPE_BYTE:
		len = di_path_prop_bytes(di_path_prop, &bdata);
		if (len < 0)
			break;
		add_bytes_prop(nodeh, propinfo, di_val, bdata, len);
		break;
	case DI_PROP_TYPE_UNKNOWN:
		/*
		 * Unknown type, we'll try and guess what it should be.
		 */
		len = di_path_prop_strings(di_path_prop, &sdata);
		if ((len > 0) && (sdata[0] != 0)) {
			add_strings_prop(nodeh, propinfo, di_val, sdata,
			    len);
			break;
		}
		len = di_path_prop_ints(di_path_prop, &idata);
		if (len > 0) {
			add_uints_prop(nodeh, propinfo, di_val,
			    idata, len);
			break;
		}
		len = di_path_prop_bytes(di_path_prop, &bdata);
		if (len > 0)
			add_bytes_prop(nodeh, propinfo,
			    di_val, bdata, len);
		else if (len == 0)
			add_boolean_prop(nodeh, propinfo,
			    di_val);
		break;
	case DI_PROP_TYPE_UNDEF_IT:
		break;
	default:
		break;
	}
}

/*
 * Add nodes for path information (PSARC/1999/647, PSARC/2008/437)
 */
static void
construct_mpath_node(picl_nodehdl_t parh, di_node_t di_node)
{
	di_path_t 		pi = DI_PATH_NIL;

	while ((pi = di_path_next_phci(di_node, pi)) != DI_PATH_NIL) {
		di_node_t 		phci_node = di_path_phci_node(pi);
		di_path_prop_t 		di_path_prop;
		picl_nodehdl_t		nodeh;
		ptree_propinfo_t	propinfo;
		int			err;
		int			instance;
		char			*di_val;

		if (phci_node == DI_PATH_NIL)
			continue;

		err = ptree_create_and_add_node(parh, PICL_CLASS_MULTIPATH,
		    PICL_CLASS_MULTIPATH, &nodeh);
		if (err != PICL_SUCCESS)
			continue;

		instance = di_instance(phci_node);
		(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_INT, PICL_READ, sizeof (instance),
		    PICL_PROP_INSTANCE, NULL, NULL);
		(void) ptree_create_and_add_prop(nodeh, &propinfo, &instance,
		    NULL);

		di_val = di_devfs_path(phci_node);
		if (di_val) {
			(void) ptree_init_propinfo(&propinfo,
			    PTREE_PROPINFO_VERSION,
			    PICL_PTYPE_CHARSTRING, PICL_READ,
			    strlen(di_val) + 1, PICL_PROP_DEVFS_PATH,
			    NULL, NULL);
			(void) ptree_create_and_add_prop(nodeh,
			    &propinfo, di_val, NULL);
			di_devfs_path_free(di_val);
		}

		(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_CHARSTRING, (PICL_READ|PICL_VOLATILE),
		    MAX_STATE_SIZE, PICL_PROP_STATE, get_path_state_name, NULL);
		(void) ptree_create_and_add_prop(nodeh, &propinfo, NULL, NULL);

		for (di_path_prop = di_path_prop_next(pi, DI_PROP_NIL);
		    di_path_prop != DI_PROP_NIL;
		    di_path_prop = di_path_prop_next(pi, di_path_prop)) {
			add_di_path_prop(nodeh, di_path_prop);
		}
	}
}

/*
 * Add properties provided by libdevinfo
 */
static void
add_devinfo_props(picl_nodehdl_t nodeh, di_node_t di_node)
{
	int			instance;
	char			*di_val;
	di_prop_t		di_prop;
	int			di_ptype;
	ptree_propinfo_t	propinfo;
	char			*sdata;
	unsigned char		*bdata;
	int			*idata;
	int			len;

	instance = di_instance(di_node);
	(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_INT, PICL_READ, sizeof (instance), PICL_PROP_INSTANCE,
	    NULL, NULL);
	(void) ptree_create_and_add_prop(nodeh, &propinfo, &instance, NULL);

	di_val = di_bus_addr(di_node);
	if (di_val) {
		(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(di_val) + 1,
		    PICL_PROP_BUS_ADDR, NULL, NULL);
		(void) ptree_create_and_add_prop(nodeh, &propinfo, di_val,
		    NULL);
	}

	di_val = di_binding_name(di_node);
	if (di_val) {
		(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(di_val) + 1,
		    PICL_PROP_BINDING_NAME, NULL, NULL);
		(void) ptree_create_and_add_prop(nodeh, &propinfo, di_val,
		    NULL);
	}

	di_val = di_driver_name(di_node);
	if (di_val) {
		(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(di_val) + 1,
		    PICL_PROP_DRIVER_NAME, NULL, NULL);
		(void) ptree_create_and_add_prop(nodeh, &propinfo, di_val,
		    NULL);
	}

	di_val = di_devfs_path(di_node);
	if (di_val) {
		(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(di_val) + 1,
		    PICL_PROP_DEVFS_PATH, NULL, NULL);
		(void) ptree_create_and_add_prop(nodeh, &propinfo, di_val,
		    NULL);
		di_devfs_path_free(di_val);
	}

	for (di_prop = di_prop_next(di_node, DI_PROP_NIL);
	    di_prop != DI_PROP_NIL;
	    di_prop = di_prop_next(di_node, di_prop)) {

		di_val = di_prop_name(di_prop);
		di_ptype = di_prop_type(di_prop);

		switch (di_ptype) {
		case DI_PROP_TYPE_BOOLEAN:
			add_boolean_prop(nodeh, propinfo, di_val);
			break;
		case DI_PROP_TYPE_INT:
			len = di_prop_ints(di_prop, &idata);
			if (len < 0)
				/* Received error, so ignore prop */
				break;
			add_uints_prop(nodeh, propinfo, di_val, idata, len);
			break;
		case DI_PROP_TYPE_STRING:
			len = di_prop_strings(di_prop, &sdata);
			if (len < 0)
				break;
			add_strings_prop(nodeh, propinfo, di_val, sdata, len);
			break;
		case DI_PROP_TYPE_BYTE:
			len = di_prop_bytes(di_prop, &bdata);
			if (len < 0)
				break;
			add_bytes_prop(nodeh, propinfo, di_val, bdata, len);
			break;
		case DI_PROP_TYPE_UNKNOWN:
			/*
			 * Unknown type, we'll try and guess what it should be.
			 */
			len = di_prop_strings(di_prop, &sdata);
			if ((len > 0) && (sdata[0] != 0)) {
				add_strings_prop(nodeh, propinfo, di_val, sdata,
				    len);
				break;
			}
			len = di_prop_ints(di_prop, &idata);
			if (len > 0) {
				add_uints_prop(nodeh, propinfo, di_val,
				    idata, len);
				break;
			}
			len = di_prop_rawdata(di_prop, &bdata);
			if (len > 0)
				add_bytes_prop(nodeh, propinfo,
				    di_val, bdata, len);
			else if (len == 0)
				add_boolean_prop(nodeh, propinfo,
				    di_val);
			break;
		case DI_PROP_TYPE_UNDEF_IT:
			break;
		default:
			break;
		}
	}
}

/*
 * This function creates the /obp node in the PICL tree for OBP nodes
 * without a device type class.
 */
static int
construct_picl_openprom(picl_nodehdl_t rooth, picl_nodehdl_t *obph)
{
	picl_nodehdl_t	tmph;
	int		err;

	err = ptree_create_and_add_node(rooth, PICL_NODE_OBP,
	    PICL_CLASS_PICL, &tmph);

	if (err != PICL_SUCCESS)
		return (err);
	*obph = tmph;
	return (PICL_SUCCESS);
}

/*
 * This function creates the /platform node in the PICL tree and
 * its properties. It sets the "platform-name" property to the
 * platform name
 */
static int
construct_picl_platform(picl_nodehdl_t rooth, di_node_t di_root,
    picl_nodehdl_t *piclh)
{
	int			err;
	picl_nodehdl_t		plafh;
	char			*nodename;
	char			nodeclass[PICL_CLASSNAMELEN_MAX];
	ptree_propinfo_t	propinfo;
	picl_prophdl_t		proph;

	nodename = di_node_name(di_root);
	if (nodename == NULL)
		return (PICL_FAILURE);

	err = 0;
	if (di_nodeid(di_root) == DI_PROM_NODEID ||
	    di_nodeid(di_root) == DI_SID_NODEID)
		err = get_device_type(nodeclass, di_root);

	if (err < 0)
		(void) strcpy(nodeclass, PICL_CLASS_UPA);	/* default */

	err = ptree_create_and_add_node(rooth, PICL_NODE_PLATFORM,
	    nodeclass, &plafh);
	if (err != PICL_SUCCESS)
		return (err);

	(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(nodename) + 1,
	    PICL_PROP_PLATFORM_NAME, NULL, NULL);
	err = ptree_create_and_add_prop(plafh, &propinfo, nodename, &proph);
	if (err != PICL_SUCCESS)
		return (err);

	(void) add_devinfo_props(plafh, di_root);

	(void) add_openprom_props(plafh, di_root);

	*piclh = plafh;

	return (PICL_SUCCESS);
}

/*
 * This function creates a node in /obp tree for the libdevinfo handle.
 */
static int
construct_obp_node(picl_nodehdl_t parh, di_node_t dn, picl_nodehdl_t *chdh)
{
	int		err;
	char		*nodename;
	char		nodeclass[PICL_CLASSNAMELEN_MAX];
	picl_nodehdl_t	anodeh;

	nodename = di_node_name(dn);	/* PICL_PROP_NAME */
	if (nodename == NULL)
		return (PICL_FAILURE);

	if (strcmp(nodename, "pseudo") == 0)
		return (PICL_FAILURE);

	if ((di_nodeid(dn) == DI_PROM_NODEID) &&
	    (get_device_type(nodeclass, dn) == 0))
		return (PICL_FAILURE);

	err = ptree_create_and_add_node(parh, nodename, nodename, &anodeh);
	if (err != PICL_SUCCESS)
		return (err);

	add_devinfo_props(anodeh, dn);

	(void) add_openprom_props(anodeh, dn);

	*chdh = anodeh;

	return (PICL_SUCCESS);
}

/*
 * This function creates a PICL node in /platform tree for a device
 */
static int
construct_devtype_node(picl_nodehdl_t parh, char *nodename,
    char *nodeclass, di_node_t dn, picl_nodehdl_t *chdh)
{
	int			err;
	picl_nodehdl_t		anodeh;

	err = ptree_create_and_add_node(parh, nodename, nodeclass, &anodeh);
	if (err != PICL_SUCCESS)
		return (err);

	(void) add_devinfo_props(anodeh, dn);
	(void) add_openprom_props(anodeh, dn);
	construct_mpath_node(anodeh, dn);

	*chdh = anodeh;
	return (err);
}

/*
 * Create a subtree of "picl" class nodes in /obp for these nodes
 */
static int
construct_openprom_tree(picl_nodehdl_t nodeh, di_node_t  dinode)
{
	di_node_t	cnode;
	picl_nodehdl_t	chdh;
	int		err;

	err = construct_obp_node(nodeh, dinode, &chdh);
	if (err != PICL_SUCCESS)
		return (err);

	for (cnode = di_child_node(dinode); cnode != DI_NODE_NIL;
	    cnode = di_sibling_node(cnode))
		(void) construct_openprom_tree(chdh, cnode);

	return (PICL_SUCCESS);

}

/*
 * Process the libdevinfo device tree and create nodes in /platform or /obp
 * PICL tree.
 *
 * This routine traverses the immediate children of "dinode" device and
 * determines the node class for that child. If it finds a valid class
 * name, then it builds a PICL node under /platform subtree and calls itself
 * recursively to construct the subtree for that child node. Otherwise, if
 * the parent_class is NULL, then it constructs a node and subtree under /obp
 * subtree.
 *
 * Note that we skip the children nodes that don't have a valid class name
 * and the parent_class is non NULL to prevent creation of any placeholder
 * nodes (such as sd,...).
 */
static int
construct_devinfo_tree(picl_nodehdl_t plafh, picl_nodehdl_t obph,
    di_node_t dinode, char *parent_class)
{
	di_node_t	cnode;
	picl_nodehdl_t	chdh;
	char		nodeclass[PICL_CLASSNAMELEN_MAX];
	char		*nodename;
	int		err;

	err = PICL_SUCCESS;
	for (cnode = di_child_node(dinode); cnode != DI_NODE_NIL;
	    cnode = di_sibling_node(cnode)) {
		nodename = di_node_name(cnode);	/* PICL_PROP_NAME */
		if (nodename == NULL)
			continue;

		err = get_node_class(nodeclass, cnode, nodename);

		if (err == 0) {
			err = construct_devtype_node(plafh, nodename,
			    nodeclass, cnode, &chdh);
			if (err != PICL_SUCCESS)
				return (err);
			err = construct_devinfo_tree(chdh, obph, cnode,
			    nodeclass);
		} else if (parent_class == NULL)
			err = construct_openprom_tree(obph, cnode);
		else
			continue;
		/*
		 * if parent_class is non NULL, skip the children nodes
		 * that don't have a valid device class - eliminates
		 * placeholder nodes (sd,...) from being created.
		 */
	}

	return (err);

}

/*
 * This function is called from the event handler called from the daemon
 * on PICL events.
 *
 * This routine traverses the children of the "dinode" device and
 * creates a PICL node for each child not found in the PICL tree and
 * invokes itself recursively to create a subtree for the newly created
 * child node. It also checks if the node being created is a meory
 * controller. If so, it posts PICLEVENT_MC_ADDED PICL event to the PICL
 * framework.
 */
static int
update_subtree(picl_nodehdl_t nodeh, di_node_t dinode)
{
	di_node_t	cnode;
	picl_nodehdl_t	chdh;
	picl_nodehdl_t	nh;
	char		*nodename;
	char		nodeclass[PICL_CLASSNAMELEN_MAX];
	char		*path_buf;
	char		buf[MAX_UNIT_ADDRESS_LEN];
	char		unitaddr[MAX_UNIT_ADDRESS_LEN];
	char		path_w_ua[MAXPATHLEN];
	char		path_wo_ua[MAXPATHLEN];
	char		*strp;
	int		gotit;
	int		err;

	for (cnode = di_child_node(dinode); cnode != DI_NODE_NIL;
	    cnode = di_sibling_node(cnode)) {
		path_buf = di_devfs_path(cnode);
		if (path_buf == NULL)
			continue;

		nodename = di_node_name(cnode);
		if (nodename == NULL) {
			di_devfs_path_free(path_buf);
			continue;
		}

		err = get_node_class(nodeclass, cnode, nodename);

		if (err < 0) {
			di_devfs_path_free(path_buf);
			continue;
		}

		/*
		 * this is quite complicated - both path_buf and any nodes
		 * already in the picl tree may, or may not, have the
		 * @<unit_addr> at the end of their names. So we must
		 * take path_buf and work out what the device path would
		 * be both with and without the unit_address, then search
		 * the picl tree for both forms.
		 */
		if (((strp = strrchr(path_buf, '/')) != NULL) &&
		    strchr(strp, '@') == NULL) {
			/*
			 * This is an unattached node - so the path is not
			 * unique. Need to find out which node it is.
			 * Find the unit_address from the OBP or devinfo
			 * properties.
			 */
			err = ptree_create_node(nodename, nodeclass, &chdh);
			if (err != PICL_SUCCESS)
				return (err);

			(void) add_devinfo_props(chdh, cnode);
			(void) add_openprom_props(chdh, cnode);

			err = get_unitaddr(nodeh, chdh, unitaddr,
			    sizeof (unitaddr));
			if (err != PICL_SUCCESS)
				return (err);
			(void) ptree_destroy_node(chdh);
			(void) snprintf(path_w_ua, sizeof (path_w_ua), "%s@%s",
			    path_buf, unitaddr);
			(void) snprintf(path_wo_ua, sizeof (path_wo_ua), "%s",
			    path_buf);
		} else {
			/*
			 * this is an attached node - so the path is unique
			 */
			(void) snprintf(path_w_ua, sizeof (path_w_ua), "%s",
			    path_buf);
			(void) snprintf(path_wo_ua, sizeof (path_wo_ua), "%s",
			    path_buf);
			strp = strrchr(path_wo_ua, '@');
			*strp++ = '\0';
			(void) snprintf(unitaddr, sizeof (unitaddr), "%s",
			    strp);
		}
		/*
		 * first look for node with unit address in devfs_path
		 */
		if (ptree_find_node(nodeh, PICL_PROP_DEVFS_PATH,
		    PICL_PTYPE_CHARSTRING, path_w_ua, strlen(path_w_ua) + 1,
		    &nh) == PICL_SUCCESS) {
			/*
			 * node already there - there's nothing we need to do
			 */
			if (picldevtree_debug > 1)
				syslog(LOG_INFO,
				    "update_subtree: path:%s node exists\n",
				    path_buf);
			di_devfs_path_free(path_buf);
			continue;
		}
		/*
		 * now look for node without unit address in devfs_path.
		 * This might be just one out of several
		 * nodes - need to check all siblings
		 */
		err = ptree_get_propval_by_name(nodeh, PICL_PROP_CHILD,
		    &chdh, sizeof (chdh));
		if ((err != PICL_SUCCESS) && (err != PICL_PROPNOTFOUND))
			return (err);
		gotit = 0;
		while (err == PICL_SUCCESS) {
			err = ptree_get_propval_by_name(chdh,
			    PICL_PROP_DEVFS_PATH, buf, sizeof (buf));
			if (err != PICL_SUCCESS)
				return (err);
			if (strcmp(buf, path_wo_ua) == 0) {
				err = ptree_get_propval_by_name(chdh,
				    PICL_PROP_UNIT_ADDRESS, buf, sizeof (buf));
				if (err != PICL_SUCCESS)
					return (err);
				if (strcmp(buf, unitaddr) == 0) {
					gotit = 1;
					break;
				}
			}
			err = ptree_get_propval_by_name(chdh,
			    PICL_PROP_PEER, &chdh, sizeof (chdh));
			if (err != PICL_SUCCESS)
				break;
		}
		if (gotit) {
			/*
			 * node already there - there's nothing we need to do
			 */
			if (picldevtree_debug > 1)
				syslog(LOG_INFO,
				    "update_subtree: path:%s node exists\n",
				    path_buf);
			di_devfs_path_free(path_buf);
			continue;
		}

#define	IS_MC(x)	(strcmp(x, PICL_CLASS_MEMORY_CONTROLLER) == 0 ? 1 : 0)

		if (construct_devtype_node(nodeh, nodename, nodeclass, cnode,
		    &chdh) == PICL_SUCCESS) {
			if (picldevtree_debug)
				syslog(LOG_INFO,
				    "picldevtree: added node:%s path:%s\n",
				    nodename, path_buf);
			if (IS_MC(nodeclass)) {
				if (post_mc_event(PICLEVENT_MC_ADDED, chdh) !=
				    PICL_SUCCESS)
					syslog(LOG_WARNING, PICL_EVENT_DROPPED,
					    PICLEVENT_MC_ADDED);
			}

			di_devfs_path_free(path_buf);
			(void) update_subtree(chdh, cnode);
		}
	}

	return (PICL_SUCCESS);

}

/*
 * Check for a stale OBP node. EINVAL is returned from the openprom(7D) driver
 * if the nodeid stored in the snapshot is not valid.
 */
static int
check_stale_node(di_node_t node, void *arg)
{
	di_prom_prop_t	promp;

	errno = 0;
	promp = di_prom_prop_next(ph, node, DI_PROM_PROP_NIL);
	if (promp == DI_PROM_PROP_NIL && errno == EINVAL) {
		snapshot_stale = 1;
		return (DI_WALK_TERMINATE);
	}
	return (DI_WALK_CONTINUE);
}

/*
 * Walk the snapshot and check the OBP properties of each node.
 */
static int
is_snapshot_stale(di_node_t root)
{
	snapshot_stale = 0;
	di_walk_node(root, DI_WALK_CLDFIRST, NULL, check_stale_node);
	return (snapshot_stale);
}

/*
 * This function processes the data from libdevinfo and creates nodes
 * in the PICL tree.
 */
static int
libdevinfo_init(picl_nodehdl_t rooth)
{
	di_node_t	di_root;
	picl_nodehdl_t	plafh;
	picl_nodehdl_t	obph;
	int		err;

	/*
	 * Use DINFOCACHE so that we obtain all attributes for all
	 * device instances (without necessarily doing a load/attach
	 * of all drivers).  Once the (on-disk) cache file is built, it
	 * exists over a reboot and can be read into memory at a very
	 * low cost.
	 */
	if ((di_root = di_init("/", DINFOCACHE)) == DI_NODE_NIL)
		return (PICL_FAILURE);

	if ((ph = di_prom_init()) == NULL)
		return (PICL_FAILURE);

	/*
	 * Check if the snapshot cache contains stale OBP nodeid references.
	 * If it does release the snapshot and obtain a live snapshot from the
	 * kernel.
	 */
	if (is_snapshot_stale(di_root)) {
		syslog(LOG_INFO, "picld detected stale snapshot cache");
		di_fini(di_root);
		if ((di_root = di_init("/", DINFOCPYALL | DINFOFORCE)) ==
		    DI_NODE_NIL) {
			return (PICL_FAILURE);
		}
	}

	/*
	 * create platform PICL node using di_root node
	 */
	err = construct_picl_platform(rooth, di_root, &plafh);
	if (err != PICL_SUCCESS) {
		di_fini(di_root);
		return (PICL_FAILURE);
	}

	err = construct_picl_openprom(rooth, &obph);
	if (err != PICL_SUCCESS) {
		di_fini(di_root);
		return (PICL_FAILURE);
	}

	(void) construct_devinfo_tree(plafh, obph, di_root, NULL);
	if (ph) {
		di_prom_fini(ph);
		ph = NULL;
	}
	di_fini(di_root);
	return (err);
}

/*
 * This function returns the integer property value
 */
static int
get_int_propval_by_name(picl_nodehdl_t	nodeh, char *pname, int *ival)
{
	int	err;

	err = ptree_get_propval_by_name(nodeh, pname, ival,
	    sizeof (int));

	return (err);
}

/*
 * This function returns the port ID (or CPU ID in the case of CMP cores)
 * of the specific CPU node handle.  If upa_portid exists, return its value.
 * Otherwise, return portid/cpuid.
 */
static int
get_cpu_portid(picl_nodehdl_t modh, int *id)
{
	int	err;

	if (strcmp(mach_name, "sun4u") == 0 ||
	    strcmp(mach_name, "sun4v") == 0) {
		err = get_int_propval_by_name(modh, OBP_PROP_UPA_PORTID, id);
		if (err == PICL_SUCCESS)
			return (err);
		err = get_int_propval_by_name(modh, OBP_PROP_PORTID, id);
		if (err == PICL_SUCCESS)
			return (err);
		return (get_int_propval_by_name(modh, OBP_PROP_CPUID, id));
	}
	if (strcmp(mach_name, "i86pc") == 0)
		return (get_int_propval_by_name(modh, OBP_REG, id));

	return (PICL_FAILURE);
}

/*
 * This function is the volatile read access function of CPU state
 * property
 */
static int
get_pi_state(ptree_rarg_t *rarg, void *vbuf)
{
	int	id;
	int	err;

	err = get_int_propval_by_name(rarg->nodeh, PICL_PROP_ID, &id);
	if (err != PICL_SUCCESS)
		return (err);

	switch (p_online(id, P_STATUS)) {
	case P_ONLINE:
		(void) strlcpy(vbuf, PS_ONLINE, MAX_STATE_SIZE);
		break;
	case P_OFFLINE:
		(void) strlcpy(vbuf, PS_OFFLINE, MAX_STATE_SIZE);
		break;
	case P_NOINTR:
		(void) strlcpy(vbuf, PS_NOINTR, MAX_STATE_SIZE);
		break;
	case P_SPARE:
		(void) strlcpy(vbuf, PS_SPARE, MAX_STATE_SIZE);
		break;
	case P_FAULTED:
		(void) strlcpy(vbuf, PS_FAULTED, MAX_STATE_SIZE);
		break;
	case P_POWEROFF:
		(void) strlcpy(vbuf, PS_POWEROFF, MAX_STATE_SIZE);
		break;
	default:
		(void) strlcpy(vbuf, "unknown", MAX_STATE_SIZE);
		break;
	}
	return (PICL_SUCCESS);
}

/*
 * This function is the volatile read access function of CPU processor_type
 * property
 */
static int
get_processor_type(ptree_rarg_t *rarg, void *vbuf)
{
	processor_info_t	cpu_info;
	int	id;
	int	err;

	err = get_int_propval_by_name(rarg->nodeh, PICL_PROP_ID, &id);
	if (err != PICL_SUCCESS)
		return (err);

	if (processor_info(id, &cpu_info) >= 0) {
		(void) strlcpy(vbuf, cpu_info.pi_processor_type, PI_TYPELEN);
	}
	return (PICL_SUCCESS);
}

/*
 * This function is the volatile read access function of CPU fputypes
 * property
 */
static int
get_fputypes(ptree_rarg_t *rarg, void *vbuf)
{
	processor_info_t	cpu_info;
	int	id;
	int	err;

	err = get_int_propval_by_name(rarg->nodeh, PICL_PROP_ID, &id);
	if (err != PICL_SUCCESS)
		return (err);

	if (processor_info(id, &cpu_info) >= 0) {
		(void) strlcpy(vbuf, cpu_info.pi_fputypes, PI_FPUTYPE);
	}
	return (PICL_SUCCESS);
}

/*
 * This function is the volatile read access function of CPU StateBegin
 * property. To minimize overhead, use kstat_chain_update() to refresh
 * the kstat header info as opposed to invoking kstat_open() every time.
 */
static int
get_pi_state_begin(ptree_rarg_t *rarg, void *vbuf)
{
	int 			err;
	int			cpu_id;
	static kstat_ctl_t	*kc = NULL;
	static pthread_mutex_t	kc_mutex = PTHREAD_MUTEX_INITIALIZER;
	kstat_t			*kp;
	kstat_named_t		*kn;

	err = get_int_propval_by_name(rarg->nodeh, PICL_PROP_ID, &cpu_id);
	if (err != PICL_SUCCESS)
		return (err);

	(void) pthread_mutex_lock(&kc_mutex);
	if (kc == NULL)
		kc = kstat_open();
	else if (kstat_chain_update(kc) == -1) {
		(void) kstat_close(kc);
		kc = kstat_open();
	}

	if (kc == NULL) {
		(void) pthread_mutex_unlock(&kc_mutex);
		return (PICL_FAILURE);
	}

	/* Get the state_begin from kstat */
	if ((kp = kstat_lookup(kc, KSTAT_CPU_INFO, cpu_id, NULL)) == NULL ||
	    kp->ks_type != KSTAT_TYPE_NAMED || kstat_read(kc, kp, 0) < 0) {
		(void) pthread_mutex_unlock(&kc_mutex);
		return (PICL_FAILURE);
	}

	kn = kstat_data_lookup(kp, KSTAT_STATE_BEGIN);
	if (kn) {
		*(uint64_t *)vbuf = (uint64_t)kn->value.l;
		err = PICL_SUCCESS;
	} else
		err = PICL_FAILURE;

	(void) pthread_mutex_unlock(&kc_mutex);
	return (err);
}

/*
 * This function adds CPU information to the CPU nodes
 */
/* ARGSUSED */
static int
add_processor_info(picl_nodehdl_t cpuh, void *args)
{
	int 			err;
	int			cpu_id;
	ptree_propinfo_t	propinfo;
	ptree_propinfo_t	pinfo;

	err = get_cpu_portid(cpuh, &cpu_id);
	if (err != PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);

	/*
	 * Check to make sure that the CPU is still present, i.e. that it
	 * has not been DR'ed out of the system.
	 */
	if (p_online(cpu_id, P_STATUS) == -1) {
		if (picldevtree_debug)
			syslog(LOG_INFO,
			    "picldevtree: cpu %d (%llx) does not exist - "
			    "deleting node\n", cpu_id, cpuh);

		if (ptree_delete_node(cpuh) == PICL_SUCCESS)
			(void) ptree_destroy_node(cpuh);

		return (PICL_WALK_CONTINUE);
	}

	(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_INT, PICL_READ, sizeof (int), PICL_PROP_ID, NULL, NULL);
	err = ptree_create_and_add_prop(cpuh, &propinfo, &cpu_id, NULL);
	if (err != PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);

	(void) ptree_init_propinfo(&pinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_CHARSTRING, (PICL_READ|PICL_VOLATILE), MAX_STATE_SIZE,
	    PICL_PROP_STATE, get_pi_state, NULL);
	(void) ptree_create_and_add_prop(cpuh, &pinfo, NULL, NULL);

	(void) ptree_init_propinfo(&pinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_CHARSTRING, (PICL_READ|PICL_VOLATILE), PI_TYPELEN,
	    PICL_PROP_PROCESSOR_TYPE, get_processor_type, NULL);
	(void) ptree_create_and_add_prop(cpuh, &pinfo, NULL, NULL);

	(void) ptree_init_propinfo(&pinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_CHARSTRING, (PICL_READ|PICL_VOLATILE), PI_FPUTYPE,
	    PICL_PROP_FPUTYPE, get_fputypes, NULL);
	(void) ptree_create_and_add_prop(cpuh, &pinfo, NULL, NULL);

	(void) ptree_init_propinfo(&pinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_TIMESTAMP, PICL_READ|PICL_VOLATILE, sizeof (uint64_t),
	    PICL_PROP_STATE_BEGIN, get_pi_state_begin, NULL);
	(void) ptree_create_and_add_prop(cpuh, &pinfo, NULL, NULL);

	return (PICL_WALK_CONTINUE);
}

/*
 * This function sets up the "ID" property in every CPU nodes
 * and adds processor info
 */
static int
setup_cpus(picl_nodehdl_t plafh)
{
	int 			err;

	err = ptree_walk_tree_by_class(plafh, PICL_CLASS_CPU, NULL,
	    add_processor_info);

	return (err);
}

/*
 * This function format's the manufacture's information for FFB display
 * devices
 */
static void
fmt_manf_id(manuf_t manufid, int bufsz, char *outbuf)
{
	/*
	 * Format the manufacturer's info.  Note a small inconsistency we
	 * have to work around - Brooktree has it's part number in decimal,
	 * while Mitsubishi has it's part number in hex.
	 */
	switch (manufid.fld.manf) {
	case MANF_BROOKTREE:
		(void) snprintf(outbuf, bufsz, "%s %d, version %d",
		    "Brooktree", manufid.fld.partno, manufid.fld.version);
		break;

	case MANF_MITSUBISHI:
		(void) snprintf(outbuf, bufsz, "%s %x, version %d",
		    "Mitsubishi", manufid.fld.partno, manufid.fld.version);
		break;

	default:
		(void) snprintf(outbuf, bufsz,
		    "JED code %d, Part num 0x%x, version %d",
		    manufid.fld.manf, manufid.fld.partno, manufid.fld.version);
	}
}

/*
 * If it's an ffb device, open ffb devices and return PICL_SUCCESS
 */
static int
open_ffb_device(picl_nodehdl_t ffbh, int *fd)
{
	DIR 			*dirp;
	char 			devfs_path[PATH_MAX];
	char 			dev_path[PATH_MAX];
	char 			*devp;
	struct dirent 		*direntp;
	int			err;
	int			tmpfd;

	/* Get the devfs_path of the ffb devices */
	err = ptree_get_propval_by_name(ffbh, PICL_PROP_DEVFS_PATH, devfs_path,
	    sizeof (devfs_path));
	if (err != PICL_SUCCESS)
		return (err);

	/* Get the device node name */
	devp = strrchr(devfs_path, '/');
	if (devp == NULL)
		return (PICL_FAILURE);
	*devp = '\0';
	++devp;

	/*
	 * Check if device node name has the ffb string
	 * If not, assume it's not a ffb device.
	 */
	if (strstr(devp, FFB_NAME) == NULL)
		return (PICL_FAILURE);

	/*
	 * Get the parent path of the ffb device node.
	 */
	(void) snprintf(dev_path, sizeof (dev_path), "%s/%s", "/devices",
	    devfs_path);

	/*
	 * Since we don't know ffb's minor nodename,
	 * we need to search all the devices under its
	 * parent dir by comparing the node name
	 */
	if ((dirp = opendir(dev_path)) == NULL)
		return (PICL_FAILURE);

	while ((direntp = readdir(dirp)) != NULL) {
		if (strstr(direntp->d_name, devp) != NULL) {
			(void) strcat(dev_path, "/");
			(void) strcat(dev_path, direntp->d_name);
			tmpfd = open(dev_path, O_RDWR);
			if (tmpfd < 0)
				continue;
			*fd = tmpfd;
			(void) closedir(dirp);
			return (PICL_SUCCESS);
		}
	}

	(void) closedir(dirp);
	return (PICL_FAILURE);
}

/*
 * This function recursively searches the tree for ffb display devices
 * and add ffb config information
 */
static int
add_ffb_config_info(picl_nodehdl_t rooth)
{
	picl_nodehdl_t		nodeh;
	int			err;
	char 			piclclass[PICL_CLASSNAMELEN_MAX];
	char 			manfidbuf[FFB_MANUF_BUFSIZE];
	int 			fd;
	int			board_rev;
	ffb_sys_info_t		fsi;
	ptree_propinfo_t	pinfo;

	for (err = ptree_get_propval_by_name(rooth, PICL_PROP_CHILD, &nodeh,
	    sizeof (picl_nodehdl_t)); err != PICL_PROPNOTFOUND;
	    err = ptree_get_propval_by_name(nodeh, PICL_PROP_PEER,
	    &nodeh, sizeof (picl_nodehdl_t))) {

		if (err != PICL_SUCCESS)
			return (err);

		err = ptree_get_propval_by_name(nodeh, PICL_PROP_CLASSNAME,
		    piclclass, PICL_CLASSNAMELEN_MAX);

		if ((err == PICL_SUCCESS) &&
		    (strcmp(piclclass, PICL_CLASS_DISPLAY) == 0)) {

			err = open_ffb_device(nodeh, &fd);
			if ((err == PICL_SUCCESS) &&
			    (ioctl(fd, FFB_SYS_INFO, &fsi) >= 0)) {
				(void) ptree_init_propinfo(&pinfo,
				    PTREE_PROPINFO_VERSION,
				    PICL_PTYPE_UNSIGNED_INT, PICL_READ,
				    sizeof (int), PICL_PROP_FFB_BOARD_REV,
				    NULL, NULL);
				board_rev = fsi.ffb_strap_bits.fld.board_rev;
				(void) ptree_create_and_add_prop(nodeh, &pinfo,
				    &board_rev, NULL);

				fmt_manf_id(fsi.dac_version,
				    sizeof (manfidbuf), manfidbuf);
				(void) ptree_init_propinfo(&pinfo,
				    PTREE_PROPINFO_VERSION,
				    PICL_PTYPE_CHARSTRING, PICL_READ,
				    strlen(manfidbuf) + 1,
				    PICL_PROP_FFB_DAC_VER, NULL, NULL);
				(void) ptree_create_and_add_prop(nodeh, &pinfo,
				    manfidbuf, NULL);

				fmt_manf_id(fsi.fbram_version,
				    sizeof (manfidbuf), manfidbuf);
				(void) ptree_init_propinfo(&pinfo,
				    PTREE_PROPINFO_VERSION,
				    PICL_PTYPE_CHARSTRING, PICL_READ,
				    strlen(manfidbuf) + 1,
				    PICL_PROP_FFB_FBRAM_VER, NULL,
				    NULL);
				(void) ptree_create_and_add_prop(nodeh, &pinfo,
				    manfidbuf, NULL);
				(void) close(fd);
			}
		} else if (add_ffb_config_info(nodeh) != PICL_SUCCESS)
			return (PICL_FAILURE);
	}
	return (PICL_SUCCESS);
}

static conf_entries_t *
free_conf_entries(conf_entries_t *list)
{
	conf_entries_t	*el;
	conf_entries_t	*del;

	if (list == NULL)
		return (NULL);
	el = list;
	while (el != NULL) {
		del = el;
		el = el->next;
		free(del->name);
		free(del->piclclass);
		free(del);
	}
	return (el);
}

/*
 * Reading config order: platform, common
 */
static conf_entries_t *
read_conf_file(char *fname, conf_entries_t *list)
{
	FILE		*fp;
	char		lbuf[CONFFILE_LINELEN_MAX];
	char		*nametok;
	char		*classtok;
	conf_entries_t	*el;
	conf_entries_t	*ptr;

	if (fname == NULL)
		return (list);

	fp = fopen(fname, "r");

	if (fp == NULL)
		return (list);

	while (fgets(lbuf, CONFFILE_LINELEN_MAX, fp) != NULL) {
		if ((lbuf[0] == CONFFILE_COMMENT_CHAR) || (lbuf[0] == '\n'))
			continue;

		nametok = strtok(lbuf, " \t\n");
		if (nametok == NULL)
			continue;

		classtok = strtok(NULL, " \t\n");
		if (classtok == NULL)
			continue;

		el = malloc(sizeof (conf_entries_t));
		if (el == NULL)
			break;
		el->name = strdup(nametok);
		el->piclclass = strdup(classtok);
		if ((el->name == NULL) || (el->piclclass == NULL)) {
			free(el);
			return (list);
		}
		el->next = NULL;

		/*
		 * Add it to the end of list
		 */
		if (list == NULL)
			list = el;
		else {
			ptr = list;
			while (ptr->next != NULL)
				ptr = ptr->next;
			ptr->next = el;
		}

	}
	(void) fclose(fp);
	return (list);
}

/*
 * Process the devtree conf file and set up the conf_name_class_map list
 */
static void
process_devtree_conf_file(void)
{
	char	nmbuf[SYS_NMLN];
	char	pname[PATH_MAX];

	conf_name_class_map = NULL;

	if (sysinfo(SI_PLATFORM, nmbuf, sizeof (nmbuf)) != -1) {
		(void) snprintf(pname, PATH_MAX, PICLD_PLAT_PLUGIN_DIRF, nmbuf);
		(void) strlcat(pname, DEVTREE_CONFFILE_NAME, PATH_MAX);
		conf_name_class_map = read_conf_file(pname,
		    conf_name_class_map);
	}

	if (sysinfo(SI_MACHINE, nmbuf, sizeof (nmbuf)) != -1) {
		(void) snprintf(pname, PATH_MAX, PICLD_PLAT_PLUGIN_DIRF, nmbuf);
		(void) strlcat(pname, DEVTREE_CONFFILE_NAME, PATH_MAX);
		conf_name_class_map = read_conf_file(pname,
		    conf_name_class_map);
	}

	(void) snprintf(pname, PATH_MAX, "%s/%s", PICLD_COMMON_PLUGIN_DIR,
	    DEVTREE_CONFFILE_NAME);
	conf_name_class_map = read_conf_file(pname, conf_name_class_map);
}

static	asr_conf_entries_t	*conf_name_asr_map = NULL;

static void
free_asr_conf_entries(asr_conf_entries_t *list) {
	asr_conf_entries_t  *el;
	asr_conf_entries_t  *del;

	el = list;
	while (el != NULL) {
		del = el;
		el = el->next;
		if (del->name)
			free(del->name);
		if (del->address)
			free(del->address);
		if (del->status)
			free(del->status);
		if (del->piclclass)
			free(del->piclclass);
		if (del->props)
			free(del->props);
		free(del);
	}
}

/*
 * Reading config order: platform, common
 */
static asr_conf_entries_t *
read_asr_conf_file(char *fname, asr_conf_entries_t *list)
{
	FILE		*fp;
	char		lbuf[CONFFILE_LINELEN_MAX];
	char		*nametok;
	char		*classtok;
	char		*statustok;
	char		*addresstok;
	char		*propstok;
	asr_conf_entries_t	*el;
	asr_conf_entries_t	*ptr;

	if (fname == NULL)
		return (list);

	fp = fopen(fname, "r");
	if (fp == NULL)
		return (list);

	while (fgets(lbuf, CONFFILE_LINELEN_MAX, fp) != NULL) {
		if ((lbuf[0] == CONFFILE_COMMENT_CHAR) || (lbuf[0] == '\n'))
			continue;

		nametok = strtok(lbuf, " \t\n");
		if (nametok == NULL)
			continue;

		classtok = strtok(NULL, " \t\n");
		if (classtok == NULL)
			continue;

		statustok = strtok(NULL, " \t\n");
		if (statustok == NULL)
			continue;

		addresstok = strtok(NULL, " \t\n");
		if (addresstok == NULL)
			continue;

		/*
		 * props are optional
		 */
		propstok = strtok(NULL, " \t\n");

		el = malloc(sizeof (asr_conf_entries_t));
		if (el == NULL)
			break;
		el->name = strdup(nametok);
		el->piclclass = strdup(classtok);
		el->status = strdup(statustok);
		el->address = strdup(addresstok);
		if (propstok != NULL)
			el->props = strdup(propstok);
		else
			el->props = NULL;
		if ((el->name == NULL) || (el->piclclass == NULL) ||
		    (el->address == NULL) || (el->status == NULL)) {
			if (el->name)
				free(el->name);
			if (el->address)
				free(el->address);
			if (el->status)
				free(el->status);
			if (el->piclclass)
				free(el->piclclass);
			if (el->props)
				free(el->props);
			free(el);
			break;
		}
		el->next = NULL;

		/*
		 * Add it to the end of list
		 */
		if (list == NULL)
			list = el;
		else {
			ptr = list;
			while (ptr->next != NULL)
				ptr = ptr->next;
			ptr->next = el;
		}

	}
	(void) fclose(fp);
	return (list);
}

/*
 * Process the asr conf file
 */
static void
process_asrtree_conf_file(void)
{
	char	nmbuf[SYS_NMLN];
	char	pname[PATH_MAX];

	if (sysinfo(SI_PLATFORM, nmbuf, sizeof (nmbuf)) != -1) {
		(void) snprintf(pname, PATH_MAX, PICLD_PLAT_PLUGIN_DIRF, nmbuf);
		(void) strlcat(pname, ASRTREE_CONFFILE_NAME, PATH_MAX);
		conf_name_asr_map = read_asr_conf_file(pname,
		    conf_name_asr_map);
	}

	if (sysinfo(SI_MACHINE, nmbuf, sizeof (nmbuf)) != -1) {
		(void) snprintf(pname, PATH_MAX, PICLD_PLAT_PLUGIN_DIRF, nmbuf);
		(void) strlcat(pname, ASRTREE_CONFFILE_NAME, PATH_MAX);
		conf_name_asr_map = read_asr_conf_file(pname,
		    conf_name_asr_map);
	}

	(void) snprintf(pname, PATH_MAX, "%s/%s", PICLD_COMMON_PLUGIN_DIR,
	    ASRTREE_CONFFILE_NAME);
	conf_name_asr_map = read_asr_conf_file(pname, conf_name_asr_map);
}

/*
 * This function reads the export file list from ASR
 */
static int
get_asr_export_list(char **exportlist, int *exportlistlen)
{
	struct openpromio oppbuf;
	struct openpromio *opp = &oppbuf;
	int d;
	int listsize;

	d = open("/dev/openprom", O_RDWR);
	if (d < 0)
		return (0);

	if (ioctl(d, OPROMEXPORTLEN, opp) == -1) {
		(void) close(d);
		return (0);
	}
	listsize = opp->oprom_size;
	opp = (struct openpromio *)malloc(sizeof (struct openpromio) +
	    listsize);
	if (opp == NULL) {
		(void) close(d);
		return (0);
	}
	(void) memset(opp, '\0', sizeof (struct openpromio) + listsize);
	opp->oprom_size = listsize;
	if (ioctl(d, OPROMEXPORT, opp) == -1) {
		free(opp);
		(void) close(d);
		return (0);
	}
	*exportlist = malloc(listsize);
	if (*exportlist == NULL) {
		free(opp);
		(void) close(d);
		return (0);
	}
	(void) memcpy(*exportlist, opp->oprom_array, opp->oprom_size);
	free(opp);
	*exportlistlen = opp->oprom_size;
	(void) close(d);
	return (1);
}

/*
 * Parses properties string, fills in triplet structure with first
 * type, name, val triplet and returns pointer to next property.
 * Returns NULL if no valid triplet found
 * CAUTION: drops \0 characters over separator characters: if you
 * want to parse the string twice, you'll have to take a copy.
 */
static char *
parse_props_string(char *props, asr_prop_triplet_t *triplet)
{
	char	*prop_name;
	char	*prop_val;
	char	*prop_next;

	prop_name = strchr(props, '?');
	if (prop_name == NULL)
		return (NULL);
	*prop_name++ = '\0';
	prop_val = strchr(prop_name, '=');
	if (prop_val == NULL)
		return (NULL);
	*prop_val++ = '\0';
	triplet->proptype = props;
	triplet->propname = prop_name;
	triplet->propval = prop_val;
	prop_next = strchr(prop_val, ':');
	if (prop_next == NULL)
		return (prop_val - 1);
	*prop_next++ = '\0';
	return (prop_next);
}

static int
add_status_prop(picl_nodehdl_t chdh, char *status)
{
	ptree_propinfo_t	propinfo;
	picl_prophdl_t		proph;
	int			err;

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(status) + 1,
	    PICL_PROP_STATUS, NULL, NULL);
	if (err != PICL_SUCCESS)
		return (err);
	err = ptree_create_and_add_prop(chdh, &propinfo, status, &proph);
	return (err);
}

static void
create_asr_node(char *parent, char *child, char *unitaddr, char *class,
	char *status, char *props)
{
	char			ptreepath[PATH_MAX];
	char			nodename[PICL_PROPNAMELEN_MAX];
	char			ua[MAX_UNIT_ADDRESS_LEN];
	char			*props_copy = NULL;
	char			*next;
	char			*prop_string;
	boolean_t		found = B_FALSE;
	picl_nodehdl_t		nodeh;
	picl_nodehdl_t		chdh;
	asr_prop_triplet_t	triple;
	ptree_propinfo_t	propinfo;
	picl_prophdl_t		proph;
	int			val;
	int			err;

	(void) strlcpy(ptreepath, PLATFORM_PATH, PATH_MAX);
	(void) strlcat(ptreepath, parent, PATH_MAX);

	if (ptree_get_node_by_path(ptreepath, &nodeh) != PICL_SUCCESS)
		return;
	/*
	 * see if the required child node already exists
	 */
	for (err = ptree_get_propval_by_name(nodeh, PICL_PROP_CHILD, &chdh,
	    sizeof (picl_nodehdl_t)); err != PICL_PROPNOTFOUND;
	    err = ptree_get_propval_by_name(chdh, PICL_PROP_PEER, &chdh,
	    sizeof (picl_nodehdl_t))) {
		if (err != PICL_SUCCESS)
			break;
		err = ptree_get_propval_by_name(chdh, PICL_PROP_NAME,
		    (void *)nodename, PICL_PROPNAMELEN_MAX);
		if (err != PICL_SUCCESS)
			break;
		if (strcmp(nodename, child) != 0)
			continue;
		/*
		 * found a candidate child node
		 */
		if (unitaddr) {
			/*
			 * does it match the required unit address?
			 */
			err = ptree_get_propval_by_name(chdh,
			    PICL_PROP_UNIT_ADDRESS, ua, sizeof (ua));
			if (err == PICL_PROPNOTFOUND)
				continue;
			if (err != PICL_SUCCESS)
				break;
			if (strcmp(unitaddr, ua) != 0)
				continue;
		}
		if (props == NULL) {
			next = "";
		} else if (props_copy == NULL) {
			props_copy = strdup(props);
			if (props_copy == NULL)
				return;
			next = props_copy;
		}
		while ((next = parse_props_string(next, &triple)) != NULL) {
			err = ptree_get_prop_by_name(chdh, triple.propname,
			    &proph);
			if (err != PICL_SUCCESS)
				break;
			err = ptree_get_propinfo(proph, &propinfo);
			if (err != PICL_SUCCESS)
				break;
			err = PICL_FAILURE;
			switch (propinfo.piclinfo.type) {
			case PICL_PTYPE_INT:
			case PICL_PTYPE_UNSIGNED_INT:
				if (strcmp(triple.proptype, "I") != 0)
					break;
				err = ptree_get_propval(proph, (void  *)&val,
				    sizeof (val));
				if (err != PICL_SUCCESS)
					break;
				if (val != atoi(triple.propval))
					err = PICL_FAILURE;
				break;
			case PICL_PTYPE_CHARSTRING:
				if (strcmp(triple.proptype, "S") != 0)
					break;
				prop_string = malloc(propinfo.piclinfo.size);
				if (prop_string == NULL)
					break;
				err = ptree_get_propval(proph,
				    (void *)prop_string,
				    propinfo.piclinfo.size);
				if (err != PICL_SUCCESS) {
					free(prop_string);
					break;
				}
				if (strcmp(prop_string, triple.propval) != 0)
					err = PICL_FAILURE;
				free(prop_string);
				break;
			default:
				break;
			}
			if (err != PICL_SUCCESS) {
				break;
			}
		}
		if (next == NULL) {
			found = B_TRUE;
			break;
		}
	}
	if (props_copy)
		free(props_copy);
	if (found) {
		/*
		 * does the pre-existing node have a status property?
		 */
		err = ptree_get_propval_by_name(chdh, PICL_PROP_STATUS,
		    ua, sizeof (ua));
		if (err == PICL_PROPNOTFOUND)
			(void) add_status_prop(chdh, status);
		if (err != PICL_SUCCESS)
			return;
		if ((strcmp(ua, ASR_DISABLED) == 0) ||
		    (strcmp(ua, ASR_FAILED) == 0) ||
		    ((strcmp(status, ASR_DISABLED) != 0) &&
		    (strcmp(status, ASR_FAILED) != 0))) {
			return;
		}
		/*
		 * more urgent status now, so replace existing value
		 */
		err = ptree_get_prop_by_name(chdh, PICL_PROP_STATUS, &proph);
		if (err != PICL_SUCCESS)
			return;
		(void) ptree_delete_prop(proph);
		(void) ptree_destroy_prop(proph);
		err = add_status_prop(chdh, status);
		if (err != PICL_SUCCESS)
			return;
		return;
	}

	/*
	 * typical case, node needs adding together with a set of properties
	 */
	if (ptree_create_and_add_node(nodeh, child, class, &chdh) ==
	    PICL_SUCCESS) {
		(void) add_status_prop(chdh, status);
		if (unitaddr) {
			(void) ptree_init_propinfo(&propinfo,
			    PTREE_PROPINFO_VERSION, PICL_PTYPE_CHARSTRING,
			    PICL_READ, strlen(unitaddr) + 1,
			    PICL_PROP_UNIT_ADDRESS, NULL, NULL);
			(void) ptree_create_and_add_prop(chdh, &propinfo,
			    unitaddr, &proph);
			(void) strlcpy(ptreepath, parent, PATH_MAX);
			(void) strlcat(ptreepath, "/", PATH_MAX);
			(void) strlcat(ptreepath, child, PATH_MAX);
			(void) strlcat(ptreepath, "@", PATH_MAX);
			(void) strlcat(ptreepath, unitaddr, PATH_MAX);
			(void) ptree_init_propinfo(&propinfo,
			    PTREE_PROPINFO_VERSION, PICL_PTYPE_CHARSTRING,
			    PICL_READ, strlen(ptreepath) + 1,
			    PICL_PROP_DEVFS_PATH, NULL, NULL);
			(void) ptree_create_and_add_prop(chdh, &propinfo,
			    ptreepath, &proph);
		}
		next = props;
		while ((next = parse_props_string(next, &triple)) != NULL) {
			/*
			 * only handle int and string properties for
			 * simplicity
			 */
			if (strcmp(triple.proptype, "I") == 0) {
				(void) ptree_init_propinfo(&propinfo,
				    PTREE_PROPINFO_VERSION,
				    PICL_PTYPE_INT, PICL_READ,
				    sizeof (int), triple.propname, NULL, NULL);
				val = atoi(triple.propval);
				(void) ptree_create_and_add_prop(chdh,
				    &propinfo, &val, &proph);
			} else {
				(void) ptree_init_propinfo(&propinfo,
				    PTREE_PROPINFO_VERSION,
				    PICL_PTYPE_CHARSTRING, PICL_READ,
				    strlen(triple.propval) + 1,
				    triple.propname, NULL, NULL);
				(void) ptree_create_and_add_prop(chdh,
				    &propinfo, triple.propval, &proph);
			}
		}
	}
}

static void
add_asr_nodes()
{
	char			*asrexport;
	int			asrexportlen;
	asr_conf_entries_t	*c = NULL;
	int			i;
	char			*key;
	char			*child;
	char			*unitaddr;
	uint16_t		count;
	int			disabled;

	if (get_asr_export_list(&asrexport, &asrexportlen) == 0)
		return;
	process_asrtree_conf_file();
	if (conf_name_asr_map == NULL)
		return;
	i = 0;
	while (i < asrexportlen) {
		key = &asrexport[i];
		i += strlen(key) + 1;
		if (i >= asrexportlen)
			break;

		/*
		 * next byte tells us whether failed by diags or manually
		 * disabled
		 */
		disabled = asrexport[i];
		i++;
		if (i >= asrexportlen)
			break;

		/*
		 * only type 1 supported
		 */
		if (asrexport[i] != 1)
			break;
		i++;
		if (i >= asrexportlen)
			break;

		/*
		 * next two bytes give size of reason string
		 */
		count = (asrexport[i] << 8) | asrexport[i + 1];
		i += count + 2;
		if (i > asrexportlen)
			break;

		/*
		 * now look for key in conf file info
		 */
		c = conf_name_asr_map;
		while (c != NULL) {
			if (strcmp(key, c->name) == 0) {
				child = strrchr(c->address, '/');
				*child++ = '\0';
				unitaddr = strchr(child, '@');
				if (unitaddr)
					*unitaddr++ = '\0';
				if (strcmp(c->status, ASR_DISABLED) == 0) {
					create_asr_node(c->address, child,
					    unitaddr, c->piclclass, disabled ?
					    ASR_DISABLED : ASR_FAILED,
					    c->props);
				} else {
					create_asr_node(c->address, child,
					    unitaddr, c->piclclass, c->status,
					    c->props);
				}
			}
			c = c->next;
		}
	}

	free_asr_conf_entries(conf_name_asr_map);
	free(asrexport);
}

/*
 * This function adds information to the /platform node
 */
static int
add_platform_info(picl_nodehdl_t plafh)
{
	struct utsname		uts_info;
	int			err;
	ptree_propinfo_t	propinfo;
	picl_prophdl_t		proph;

	if (uname(&uts_info) < 0)
		return (PICL_FAILURE);

	(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(uts_info.sysname) + 1,
	    PICL_PROP_SYSNAME, NULL, NULL);
	err = ptree_create_and_add_prop(plafh, &propinfo, uts_info.sysname,
	    &proph);
	if (err != PICL_SUCCESS)
		return (err);

	(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(uts_info.nodename) + 1,
	    PICL_PROP_NODENAME, NULL, NULL);
	err = ptree_create_and_add_prop(plafh, &propinfo, uts_info.nodename,
	    &proph);
	if (err != PICL_SUCCESS)
		return (err);

	(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(uts_info.release) + 1,
	    PICL_PROP_RELEASE, NULL, NULL);
	err = ptree_create_and_add_prop(plafh, &propinfo, uts_info.release,
	    &proph);
	if (err != PICL_SUCCESS)
		return (err);

	(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(uts_info.version) + 1,
	    PICL_PROP_VERSION, NULL, NULL);
	err = ptree_create_and_add_prop(plafh, &propinfo, uts_info.version,
	    &proph);
	if (err != PICL_SUCCESS)
		return (err);

	(void) ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(uts_info.machine) + 1,
	    PICL_PROP_MACHINE, NULL, NULL);
	err = ptree_create_and_add_prop(plafh, &propinfo, uts_info.machine,
	    &proph);
	return (err);
}

/*
 * Get first 32-bit value from the reg property
 */
static int
get_first_reg_word(picl_nodehdl_t nodeh, uint32_t *regval)
{
	int			err;
	uint32_t		*regbuf;
	picl_prophdl_t  	regh;
	ptree_propinfo_t	pinfo;

	err = ptree_get_prop_by_name(nodeh, OBP_REG, &regh);
	if (err != PICL_SUCCESS) 	/* no reg property */
		return (err);
	err = ptree_get_propinfo(regh, &pinfo);
	if (err != PICL_SUCCESS)
		return (err);
	if (pinfo.piclinfo.size < sizeof (uint32_t)) /* too small */
		return (PICL_FAILURE);
	regbuf = alloca(pinfo.piclinfo.size);
	if (regbuf == NULL)
		return (PICL_FAILURE);
	err = ptree_get_propval(regh, regbuf, pinfo.piclinfo.size);
	if (err != PICL_SUCCESS)
		return (err);
	*regval = *regbuf;	/* get first 32-bit value */
	return (PICL_SUCCESS);
}

/*
 * Get device ID from the reg property
 */
static int
get_device_id(picl_nodehdl_t nodeh, uint32_t *dev_id)
{
	int			err;
	uint32_t		regval;

	err = get_first_reg_word(nodeh, &regval);
	if (err != PICL_SUCCESS)
		return (err);

	*dev_id = PCI_DEVICE_ID(regval);
	return (PICL_SUCCESS);
}

/*
 * add Slot property for children of SBUS node
 */
/* ARGSUSED */
static int
add_sbus_slots(picl_nodehdl_t pcih, void *args)
{
	picl_nodehdl_t		nodeh;
	uint32_t		slot;
	int			err;
	ptree_propinfo_t	pinfo;

	for (err = ptree_get_propval_by_name(pcih, PICL_PROP_CHILD, &nodeh,
	    sizeof (picl_nodehdl_t)); err != PICL_PROPNOTFOUND;
	    err = ptree_get_propval_by_name(nodeh, PICL_PROP_PEER, &nodeh,
	    sizeof (picl_nodehdl_t))) {
		if (err != PICL_SUCCESS)
			return (err);

		if (get_first_reg_word(nodeh, &slot) != 0)
			continue;
		(void) ptree_init_propinfo(&pinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_UNSIGNED_INT, PICL_READ, sizeof (uint32_t),
		    PICL_PROP_SLOT, NULL, NULL);
		(void) ptree_create_and_add_prop(nodeh, &pinfo, &slot, NULL);
	}

	return (PICL_WALK_CONTINUE);
}

/*
 * This function creates a Slot property for SBUS child nodes
 * which can be correlated with the slot they are plugged into
 * on the motherboard.
 */
static int
set_sbus_slot(picl_nodehdl_t plafh)
{
	int		err;

	err = ptree_walk_tree_by_class(plafh, PICL_CLASS_SBUS, NULL,
	    add_sbus_slots);

	return (err);
}

/*
 * add DeviceID property for children of PCI/PCIEX node
 */
/* ARGSUSED */
static int
add_pci_deviceids(picl_nodehdl_t pcih, void *args)
{
	picl_nodehdl_t		nodeh;
	uint32_t		dev_id;
	int			err;
	ptree_propinfo_t	pinfo;

	for (err = ptree_get_propval_by_name(pcih, PICL_PROP_CHILD, &nodeh,
	    sizeof (picl_nodehdl_t)); err != PICL_PROPNOTFOUND;
	    err = ptree_get_propval_by_name(nodeh, PICL_PROP_PEER, &nodeh,
	    sizeof (picl_nodehdl_t))) {
		if (err != PICL_SUCCESS)
			return (err);

		if (get_device_id(nodeh, &dev_id) != 0)
			continue;
		(void) ptree_init_propinfo(&pinfo, PTREE_PROPINFO_VERSION,
		    PICL_PTYPE_UNSIGNED_INT, PICL_READ, sizeof (uint32_t),
		    PICL_PROP_DEVICE_ID, NULL, NULL);
		(void) ptree_create_and_add_prop(nodeh, &pinfo, &dev_id, NULL);
	}

	return (PICL_WALK_CONTINUE);
}

/*
 * This function creates a DeviceID property for PCI/PCIEX child nodes
 * which can be correlated with the slot they are plugged into
 * on the motherboard.
 */
static void
set_pci_pciex_deviceid(picl_nodehdl_t plafh)
{
	(void) ptree_walk_tree_by_class(plafh, PICL_CLASS_PCI, NULL,
	    add_pci_deviceids);

	(void) ptree_walk_tree_by_class(plafh, PICL_CLASS_PCIEX, NULL,
	    add_pci_deviceids);
}

/*
 * Default UnitAddress encode function
 */
static int
encode_default_unitaddr(char *buf, int sz, uint32_t *regprop, uint_t addrcells)
{
	int	i, len;

	/*
	 * Encode UnitAddress as %a,%b,%c,...,%n
	 */
	if (addrcells < 1)
		return (-1);

	len = snprintf(buf, sz, "%x", *regprop);
	for (i = 1; i < addrcells && len < sz; i++)
		len += snprintf(&buf[len], sz-len, ",%x", regprop[i]);

	return ((len >= sz) ? -1 : 0);
}

/*
 * UnitAddress encode function where the last component is not printed
 * unless non-zero.
 */
static int
encode_optional_unitaddr(char *buf, int sz, uint32_t *regprop, uint_t addrcells)
{
	int	retval;

	/*
	 * Encode UnitAddress as %a,%b,%c,...,%n where the last component
	 * is printed only if non-zero.
	 */
	if (addrcells > 1 && regprop[addrcells-1] == 0)
		retval = encode_default_unitaddr(buf, sz, regprop, addrcells-1);
	else
		retval = encode_default_unitaddr(buf, sz, regprop, addrcells);

	return (retval);
}


/*
 * UnitAddress encode function for SCSI class of devices
 */
static int
encode_scsi_unitaddr(char *buf, int sz, uint32_t *regprop, uint_t addrcells)
{
	int	len, retval;

	/*
	 * #address-cells	Format
	 *	2		second component printed only if non-zero
	 *
	 *	4		regprop:   phys_hi phys_lo lun_hi lun_lo
	 *			UnitAddr:  w<phys_hi><phys_lo>,<lun_lo>
	 */

	if (addrcells == 2) {
		retval = encode_optional_unitaddr(buf, sz, regprop, addrcells);
	} else if (addrcells == 4) {
		len = snprintf(buf, sz, "w%08x%08x,%x", regprop[0], regprop[1],
		    regprop[3]);
		retval = (len >= sz) ? -1 : 0;
	} else
		retval = -1;

	return (retval);
}

/*
 * UnitAddress encode function for UPA devices
 */
static int
encode_upa_unitaddr(char *buf, int sz, uint32_t *regprop, uint_t addrcells)
{
	int	len;

	if (addrcells != 2)
		return (-1);

	len = snprintf(buf, sz, "%x,%x", (regprop[0]/2)&0x1f, regprop[1]);
	return ((len >= sz) ? -1 : 0);
}

/*
 * UnitAddress encode function for GPTWO, JBUS devices
 */
static int
encode_gptwo_jbus_unitaddr(char *buf, int sz, uint32_t *regprop,
    uint_t addrcells)
{
	uint32_t	hi, lo;
	int		len, id, off;

	if (addrcells != 2)
		return (-1);

	hi = regprop[0];
	lo = regprop[1];

	if (hi & 0x400) {
		id = ((hi & 0x1) << 9) | (lo >> 23);	/* agent id */
		off = lo & 0x7fffff;			/* config offset */
		len = snprintf(buf, sz, "%x,%x", id, off);
	} else {
		len = snprintf(buf, sz, "m%x,%x", hi, lo);
	}
	return ((len >= sz) ? -1 : 0);
}

/*
 * UnitAddress encode function for PCI devices
 */
static int
encode_pci_unitaddr(char *buf, int sz, uint32_t *regprop, uint_t addrcells)
{
	typedef struct {
		uint32_t	n:1,		/* relocatable */
				p:1,		/* prefetchable */
				t:1,		/* address region aliases */
				zero:3,		/* must be zero */
				ss:2,		/* address space type */
				bus:8,		/* bus number */
				dev:5,		/* device number */
				fn:3,		/* function number */
				reg:8;		/* register number */
		uint32_t	phys_hi;	/* high physical address */
		uint32_t	phys_lo;	/* low physical address */
	} pci_addrcell_t;

	pci_addrcell_t	*p;
	int		len;

	if (addrcells != 3)
		return (-1);

	p = (pci_addrcell_t *)regprop;
	switch (p->ss) {
	case 0:		/* Config */
		if (p->fn)
			len = snprintf(buf, sz, "%x,%x", p->dev, p->fn);
		else
			len = snprintf(buf, sz, "%x", p->dev);
		break;
	case 1:		/* IO */
		len = snprintf(buf, sz, "i%x,%x,%x,%x", p->dev, p->fn, p->reg,
		    p->phys_lo);
		break;
	case 2:		/* Mem32 */
		len = snprintf(buf, sz, "m%x,%x,%x,%x", p->dev, p->fn, p->reg,
		    p->phys_lo);
		break;
	case 3:		/* Mem64 */
		len = snprintf(buf, sz, "x%x,%x,%x,%x%08x", p->dev, p->fn,
		    p->reg, p->phys_hi, p->phys_lo);
		break;
	}
	return ((len >= sz) ? -1 : 0);
}

/*
 * Get #address-cells property value
 */
static uint_t
get_addrcells_prop(picl_nodehdl_t nodeh)
{
	int			len, err;
	uint32_t		addrcells;
	ptree_propinfo_t	pinfo;
	picl_prophdl_t		proph;

	/*
	 * Get #address-cells property.  If not present, use default value.
	 */
	err = ptree_get_prop_by_name(nodeh, OBP_PROP_ADDRESS_CELLS, &proph);
	if (err == PICL_SUCCESS)
		err = ptree_get_propinfo(proph, &pinfo);

	len = pinfo.piclinfo.size;
	if (err == PICL_SUCCESS && len >= sizeof (uint8_t) &&
	    len <= sizeof (addrcells)) {
		err = ptree_get_propval(proph, &addrcells, len);
		if (err == PICL_SUCCESS) {
			if (len == sizeof (uint8_t))
				addrcells = *(uint8_t *)&addrcells;
			else if (len == sizeof (uint16_t))
				addrcells = *(uint16_t *)&addrcells;
		} else
			addrcells = DEFAULT_ADDRESS_CELLS;
	} else
		addrcells = DEFAULT_ADDRESS_CELLS;

	return (addrcells);
}

/*
 * Get UnitAddress mapping entry for a node
 */
static unitaddr_map_t *
get_unitaddr_mapping(picl_nodehdl_t nodeh)
{
	int		err;
	unitaddr_map_t	*uamap;
	char		clname[PICL_CLASSNAMELEN_MAX];

	/*
	 * Get my classname and locate a function to translate "reg" prop
	 * into "UnitAddress" prop for my children.
	 */
	err = ptree_get_propval_by_name(nodeh, PICL_PROP_CLASSNAME, clname,
	    sizeof (clname));
	if (err != PICL_SUCCESS)
		(void) strcpy(clname, "");	/* NULL class name */

	for (uamap = &unitaddr_map_table[0]; uamap->class != NULL; uamap++)
		if (strcmp(clname, uamap->class) == 0)
			break;

	return (uamap);
}

/*
 * Add UnitAddress property to the specified node
 */
static int
add_unitaddr_prop(picl_nodehdl_t nodeh, unitaddr_map_t *uamap, uint_t addrcells)
{
	int			regproplen, err;
	uint32_t		*regbuf;
	picl_prophdl_t		regh;
	ptree_propinfo_t	pinfo;
	char			unitaddr[MAX_UNIT_ADDRESS_LEN];

	err = ptree_get_prop_by_name(nodeh, OBP_REG, &regh);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_get_propinfo(regh, &pinfo);
	if (err != PICL_SUCCESS)
		return (PICL_FAILURE);

	if (pinfo.piclinfo.size < (addrcells * sizeof (uint32_t)))
		return (PICL_FAILURE);

	regproplen = pinfo.piclinfo.size;
	regbuf = alloca(regproplen);
	if (regbuf == NULL)
		return (PICL_FAILURE);

	err = ptree_get_propval(regh, regbuf, regproplen);
	if (err != PICL_SUCCESS || uamap->func == NULL ||
	    (uamap->addrcellcnt && uamap->addrcellcnt != addrcells) ||
	    (uamap->func)(unitaddr, sizeof (unitaddr), regbuf,
	    addrcells) != 0) {
		return (PICL_FAILURE);
	}

	err = ptree_init_propinfo(&pinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(unitaddr)+1,
	    PICL_PROP_UNIT_ADDRESS, NULL, NULL);
	if (err == PICL_SUCCESS)
		err = ptree_create_and_add_prop(nodeh, &pinfo, unitaddr, NULL);

	return (err);
}

/*
 * work out UnitAddress property of the specified node
 */
static int
get_unitaddr(picl_nodehdl_t parh, picl_nodehdl_t nodeh, char *unitaddr,
    size_t ualen)
{
	int			regproplen, err;
	uint32_t		*regbuf;
	picl_prophdl_t		regh;
	ptree_propinfo_t	pinfo;
	unitaddr_map_t		*uamap;
	uint32_t		addrcells;

	addrcells = get_addrcells_prop(parh);
	uamap = get_unitaddr_mapping(parh);

	err = ptree_get_prop_by_name(nodeh, OBP_REG, &regh);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_get_propinfo(regh, &pinfo);
	if (err != PICL_SUCCESS)
		return (err);

	if (pinfo.piclinfo.size < (addrcells * sizeof (uint32_t)))
		return (PICL_FAILURE);

	regproplen = pinfo.piclinfo.size;
	regbuf = alloca(regproplen);
	if (regbuf == NULL)
		return (PICL_FAILURE);

	err = ptree_get_propval(regh, regbuf, regproplen);
	if (err != PICL_SUCCESS || uamap->func == NULL ||
	    (uamap->addrcellcnt && uamap->addrcellcnt != addrcells) ||
	    (uamap->func)(unitaddr, ualen, regbuf, addrcells) != 0) {
		return (PICL_FAILURE);
	}
	return (PICL_SUCCESS);
}

/*
 * Add UnitAddress property to all children of the specified node
 */
static int
add_unitaddr_prop_to_subtree(picl_nodehdl_t nodeh)
{
	int			err;
	picl_nodehdl_t		chdh;
	unitaddr_map_t		*uamap;
	uint32_t		addrcells;

	/*
	 * Get #address-cells and unit address mapping entry for my
	 * node's class
	 */
	addrcells = get_addrcells_prop(nodeh);
	uamap = get_unitaddr_mapping(nodeh);

	/*
	 * Add UnitAddress property to my children and their subtree
	 */
	err = ptree_get_propval_by_name(nodeh, PICL_PROP_CHILD, &chdh,
	    sizeof (picl_nodehdl_t));

	while (err == PICL_SUCCESS) {
		(void) add_unitaddr_prop(chdh, uamap, addrcells);
		(void) add_unitaddr_prop_to_subtree(chdh);

		err = ptree_get_propval_by_name(chdh, PICL_PROP_PEER, &chdh,
		    sizeof (picl_nodehdl_t));
	}

	return (PICL_SUCCESS);
}

static int
update_memory_size_prop(picl_nodehdl_t plafh)
{
	picl_nodehdl_t		memh;
	picl_prophdl_t		proph;
	ptree_propinfo_t	pinfo;
	int			err, nspecs, snum, pval;
	char			*regbuf;
	memspecs_t		*mspecs;
	uint64_t		memsize;

	/*
	 * check if the #size-cells of the platform node is 2
	 */
	err = ptree_get_propval_by_name(plafh, OBP_PROP_SIZE_CELLS, &pval,
	    sizeof (pval));

	if (err == PICL_PROPNOTFOUND)
		pval = SUPPORTED_NUM_CELL_SIZE;
	else if (err != PICL_SUCCESS)
		return (err);

	/*
	 * don't know how to handle other vals
	 */
	if (pval != SUPPORTED_NUM_CELL_SIZE)
		return (PICL_FAILURE);

	err = ptree_get_node_by_path(MEMORY_PATH, &memh);
	if (err != PICL_SUCCESS)
		return (err);

	/*
	 * Get the REG property to calculate the size of memory
	 */
	err = ptree_get_prop_by_name(memh, OBP_REG, &proph);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_get_propinfo(proph, &pinfo);
	if (err != PICL_SUCCESS)
		return (err);

	regbuf = alloca(pinfo.piclinfo.size);
	if (regbuf == NULL)
		return (PICL_FAILURE);

	err = ptree_get_propval(proph, regbuf, pinfo.piclinfo.size);
	if (err != PICL_SUCCESS)
		return (err);

	mspecs = (memspecs_t *)regbuf;
	nspecs = pinfo.piclinfo.size / sizeof (memspecs_t);

	memsize = 0;
	for (snum = 0; snum < nspecs; ++snum)
		memsize += mspecs[snum].size;

	err = ptree_get_prop_by_name(memh, PICL_PROP_SIZE, &proph);
	if (err == PICL_SUCCESS) {
		err = ptree_update_propval(proph, &memsize, sizeof (memsize));
		return (err);
	}

	/*
	 * Add the size property
	 */
	(void) ptree_init_propinfo(&pinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_UNSIGNED_INT, PICL_READ, sizeof (memsize),
	    PICL_PROP_SIZE, NULL, NULL);
	err = ptree_create_and_add_prop(memh, &pinfo, &memsize, NULL);
	return (err);
}

/*
 * This function is executed as part of .init when the plugin is
 * dlopen()ed
 */
static void
picldevtree_register(void)
{
	if (getenv(SUNW_PICLDEVTREE_PLUGIN_DEBUG))
		picldevtree_debug = 1;
	(void) picld_plugin_register(&my_reg_info);
}

/*
 * This function is the init entry point of the plugin.
 * It initializes the /platform tree based on libdevinfo
 */
static void
picldevtree_init(void)
{
	picl_nodehdl_t	rhdl;
	int		err;
	struct utsname	utsname;
	picl_nodehdl_t	plafh;

	if (uname(&utsname) < 0)
		return;

	(void) strcpy(mach_name, utsname.machine);

	if (strcmp(mach_name, "sun4u") == 0) {
		builtin_map_ptr = sun4u_map;
		builtin_map_size = sizeof (sun4u_map) / sizeof (builtin_map_t);
	} else if (strcmp(mach_name, "sun4v") == 0) {
		builtin_map_ptr = sun4u_map;
		builtin_map_size = sizeof (sun4u_map) / sizeof (builtin_map_t);
	} else if (strcmp(mach_name, "i86pc") == 0) {
		builtin_map_ptr = i86pc_map;
		builtin_map_size = sizeof (i86pc_map) / sizeof (builtin_map_t);
	} else {
		builtin_map_ptr = NULL;
		builtin_map_size = 0;
	}

	err = ptree_get_root(&rhdl);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, DEVINFO_PLUGIN_INIT_FAILED);
		return;
	}

	process_devtree_conf_file();

	if (libdevinfo_init(rhdl) != PICL_SUCCESS) {
		syslog(LOG_ERR, DEVINFO_PLUGIN_INIT_FAILED);
		return;
	}

	err = ptree_get_node_by_path(PLATFORM_PATH, &plafh);
	if (err != PICL_SUCCESS)
		return;

	(void) add_unitaddr_prop_to_subtree(plafh);

	add_asr_nodes();

	(void) update_memory_size_prop(plafh);

	(void) setup_cpus(plafh);

	(void) add_ffb_config_info(plafh);

	(void) add_platform_info(plafh);

	set_pci_pciex_deviceid(plafh);

	(void) set_sbus_slot(plafh);

	(void) ptree_register_handler(PICLEVENT_SYSEVENT_DEVICE_ADDED,
	    picldevtree_evhandler, NULL);
	(void) ptree_register_handler(PICLEVENT_SYSEVENT_DEVICE_REMOVED,
	    picldevtree_evhandler, NULL);
	(void) ptree_register_handler(PICLEVENT_CPU_STATE_CHANGE,
	    picldevtree_evhandler, NULL);
	(void) ptree_register_handler(PICLEVENT_DR_AP_STATE_CHANGE,
	    picldevtree_evhandler, NULL);
}

/*
 * This function is the fini entry point of the plugin
 */
static void
picldevtree_fini(void)
{
	/* First unregister the event handlers */
	(void) ptree_unregister_handler(PICLEVENT_SYSEVENT_DEVICE_ADDED,
	    picldevtree_evhandler, NULL);
	(void) ptree_unregister_handler(PICLEVENT_SYSEVENT_DEVICE_REMOVED,
	    picldevtree_evhandler, NULL);
	(void) ptree_unregister_handler(PICLEVENT_CPU_STATE_CHANGE,
	    picldevtree_evhandler, NULL);
	(void) ptree_unregister_handler(PICLEVENT_DR_AP_STATE_CHANGE,
	    picldevtree_evhandler, NULL);

	conf_name_class_map = free_conf_entries(conf_name_class_map);
}

/*
 * This function is the event handler of this plug-in.
 *
 * It processes the following events:
 *
 *	PICLEVENT_SYSEVENT_DEVICE_ADDED
 *	PICLEVENT_SYSEVENT_DEVICE_REMOVED
 *	PICLEVENT_CPU_STATE_CHANGE
 *	PICLEVENT_DR_AP_STATE_CHANGE
 */
/* ARGSUSED */
static void
picldevtree_evhandler(const char *ename, const void *earg, size_t size,
    void *cookie)
{
	char			*devfs_path;
	char			ptreepath[PATH_MAX];
	char			dipath[PATH_MAX];
	picl_nodehdl_t		plafh;
	picl_nodehdl_t		nodeh;
	nvlist_t		*nvlp;

	if ((earg == NULL) ||
	    (ptree_get_node_by_path(PLATFORM_PATH, &plafh) != PICL_SUCCESS))
		return;

	if (strcmp(ename, PICLEVENT_DR_AP_STATE_CHANGE) == 0) {
		(void) setup_cpus(plafh);
		if (picldevtree_debug > 1)
			syslog(LOG_INFO, "picldevtree: event handler done\n");
		return;
	}

	nvlp = NULL;
	if (nvlist_unpack((char *)earg, size, &nvlp, NULL) ||
	    nvlist_lookup_string(nvlp, PICLEVENTARG_DEVFS_PATH, &devfs_path) ||
	    strlen(devfs_path) > (PATH_MAX - sizeof (PLATFORM_PATH))) {
		syslog(LOG_INFO, PICL_EVENT_DROPPED, ename);
		nvlist_free(nvlp);
		return;
	}

	(void) strlcpy(ptreepath, PLATFORM_PATH, PATH_MAX);
	(void) strlcat(ptreepath, devfs_path, PATH_MAX);
	(void) strlcpy(dipath, devfs_path, PATH_MAX);
	nvlist_free(nvlp);

	if (picldevtree_debug)
		syslog(LOG_INFO, "picldevtree: event handler invoked ename:%s "
		    "ptreepath:%s\n", ename, ptreepath);

	if (strcmp(ename, PICLEVENT_CPU_STATE_CHANGE) == 0) {
		goto done;
	}
	if (strcmp(ename, PICLEVENT_SYSEVENT_DEVICE_ADDED) == 0) {
		di_node_t		devnode;
		char		*strp;
		picl_nodehdl_t	parh;
		char		nodeclass[PICL_CLASSNAMELEN_MAX];
		char		*nodename;
		int		err;

		/* If the node already exist, then nothing else to do here */
		if (ptree_get_node_by_path(ptreepath, &nodeh) == PICL_SUCCESS)
			return;

		/* Skip if unable to find parent PICL node handle */
		parh = plafh;
		if (((strp = strrchr(ptreepath, '/')) != NULL) &&
		    (strp != strchr(ptreepath, '/'))) {
			*strp = '\0';
			if (ptree_get_node_by_path(ptreepath, &parh) !=
			    PICL_SUCCESS)
				return;
		}

		/*
		 * If parent is the root node
		 */
		if (parh == plafh) {
			ph = di_prom_init();
			devnode = di_init(dipath, DINFOCPYALL);
			if (devnode == DI_NODE_NIL) {
				if (ph != NULL) {
					di_prom_fini(ph);
					ph = NULL;
				}
				return;
			}
			nodename = di_node_name(devnode);
			if (nodename == NULL) {
				di_fini(devnode);
				if (ph != NULL) {
					di_prom_fini(ph);
					ph = NULL;
				}
				return;
			}

			err = get_node_class(nodeclass, devnode, nodename);
			if (err < 0) {
				di_fini(devnode);
				if (ph != NULL) {
					di_prom_fini(ph);
					ph = NULL;
				}
				return;
			}
			err = construct_devtype_node(plafh, nodename,
			    nodeclass, devnode, &nodeh);
			if (err != PICL_SUCCESS) {
				di_fini(devnode);
				if (ph != NULL) {
					di_prom_fini(ph);
					ph = NULL;
				}
				return;
			}
			(void) update_subtree(nodeh, devnode);
			(void) add_unitaddr_prop_to_subtree(nodeh);
			if (ph != NULL) {
				di_prom_fini(ph);
				ph = NULL;
			}
			di_fini(devnode);
			goto done;
		}

		/* kludge ... try without bus-addr first */
		if ((strp = strrchr(dipath, '@')) != NULL) {
			char *p;

			p = strrchr(dipath, '/');
			if (p != NULL && strp > p) {
				*strp = '\0';
				devnode = di_init(dipath, DINFOCPYALL);
				if (devnode != DI_NODE_NIL)
					di_fini(devnode);
				*strp = '@';
			}
		}
		/* Get parent devnode */
		if ((strp = strrchr(dipath, '/')) != NULL)
			*++strp = '\0';
		devnode = di_init(dipath, DINFOCPYALL);
		if (devnode == DI_NODE_NIL)
			return;
		ph = di_prom_init();
		(void) update_subtree(parh, devnode);
		(void) add_unitaddr_prop_to_subtree(parh);
		if (ph) {
			di_prom_fini(ph);
			ph = NULL;
		}
		di_fini(devnode);
	} else if (strcmp(ename, PICLEVENT_SYSEVENT_DEVICE_REMOVED) == 0) {
		char			delclass[PICL_CLASSNAMELEN_MAX];
		char		*strp;

		/*
		 * if final element of path doesn't have a unit address
		 * then it is not uniquely identifiable - cannot remove
		 */
		if (((strp = strrchr(ptreepath, '/')) != NULL) &&
		    strchr(strp, '@') == NULL)
			return;

		/* skip if can't find the node */
		if (ptree_get_node_by_path(ptreepath, &nodeh) != PICL_SUCCESS)
			return;

		if (ptree_delete_node(nodeh) != PICL_SUCCESS)
			return;

		if (picldevtree_debug)
			syslog(LOG_INFO,
			    "picldevtree: deleted node nodeh:%llx\n", nodeh);
		if ((ptree_get_propval_by_name(nodeh,
		    PICL_PROP_CLASSNAME, delclass, PICL_CLASSNAMELEN_MAX) ==
		    PICL_SUCCESS) && IS_MC(delclass)) {
			if (post_mc_event(PICLEVENT_MC_REMOVED, nodeh) !=
			    PICL_SUCCESS)
				syslog(LOG_WARNING, PICL_EVENT_DROPPED,
				    PICLEVENT_MC_REMOVED);
		} else
			(void) ptree_destroy_node(nodeh);
	}
done:
	(void) setup_cpus(plafh);
	(void) add_ffb_config_info(plafh);
	set_pci_pciex_deviceid(plafh);
	(void) set_sbus_slot(plafh);
	if (picldevtree_debug > 1)
		syslog(LOG_INFO, "picldevtree: event handler done\n");
}
