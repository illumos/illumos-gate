/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>
#include <errno.h>
#include <libintl.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/openpromio.h>
#include <sys/ddi.h>
#include <syslog.h>
#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <locale.h>
#include <picl.h>
#include "pdevinfo.h"
#include "display.h"
#include "display_sun4u.h"
#include "picldefs.h"
#include "libprtdiag.h"

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

#define	EM_INIT_FAIL		dgettext(TEXT_DOMAIN,\
	"picl_initialize failed: %s\n")
#define	EM_GET_ROOT_FAIL	dgettext(TEXT_DOMAIN,\
	"Getting root node failed: %s\n")
#define	EM_PRTDIAG_FAIL		dgettext(TEXT_DOMAIN, "Prtdiag failed!\n")

#define	SIGN_ON_MSG	dgettext(TEXT_DOMAIN,\
	"System Configuration: Sun Microsystems ")
#define	SYSCLK_FREQ_MSG	dgettext(TEXT_DOMAIN,\
	"System clock frequency: %d MHZ\n")
#define	MEM_SIZE_MSG	dgettext(TEXT_DOMAIN, "Memory size: ")

#define	DEFAULT_BOARD_NUM	0
#define	DEFAULT_PORTID		0
#define	CLK_FREQ_66MHZ		66
#define	USB			-1
#define	HUB			-2

/* bus id */
#define	PCI_TYPE		1

/*
 * PICL classes
 */
#define	PICL_CLASS_OPTIONS		"options"

/*
 * Property names
 */

#define	OBP_PROP_REG			"reg"
#define	OBP_PROP_CLOCK_FREQ		"clock-frequency"
#define	OBP_PROP_BOARD_NUM		"board#"
#define	OBP_PROP_REVISION_ID		"revision-id"
#define	OBP_PROP_VERSION_NUM		"version#"
#define	OBP_PROP_BOARD_TYPE		"board_type"
#define	OBP_PROP_ECACHE_SIZE		"ecache-size"
#define	OBP_PROP_IMPLEMENTATION		"implementation#"
#define	OBP_PROP_MASK			"mask#"
#define	OBP_PROP_COMPATIBLE		"compatible"
#define	OBP_PROP_BANNER_NAME		"banner-name"
#define	OBP_PROP_MODEL			"model"
#define	OBP_PROP_66MHZ_CAPABLE		"66mhz-capable"
#define	OBP_PROP_FBC_REG_ID		"fbc_reg_id"
#define	OBP_PROP_VERSION		"version"

#define	PROP_POWERFAIL_TIME		"powerfail-time"
#define	PICL_PROP_LOW_WARNING_THRESHOLD	"LowWarningThreshold"

#define	DEFAULT_LINE_WIDTH		78
#define	HEADING_SYMBOL			"="

#define	SIZE_FIELD	11
#define	MAX_IWAYS			32

typedef struct bank_list {
	picl_nodehdl_t		nodeh;
	uint32_t		iway_count;
	uint32_t		iway[MAX_IWAYS];
	struct bank_list	*next;
} bank_list_t;

typedef struct {
	uint64_t	base;
	uint64_t	size;
	int		ifactor;
	int		bank_count;
} seg_info_t;

static struct io_card	*io_card_list = NULL; /* The head of the IO card list */
static bank_list_t	*mem_banks = NULL;
static	int		mem_xfersize;
static	int		no_xfer_size = 0;

static const char *io_device_table[] = {
	"block",
	"disk",
	"cdrom",
	"floppy",
	"tape",
	"network",
	"display",
	"serial",
	"parallel",
	"scsi",
	"scsi-2",
	"scsi-3",
	"ide",
	"fcal",
	"keyboard",
	"mouse",
	"dma"
};

#define	NIODEVICE	(sizeof (io_device_table) / sizeof (io_device_table[0]))

static const char *bus_table[] = {
	"ebus",
	"isa",
	"pmu"
};

#define	NBUS	(sizeof (bus_table) / sizeof (bus_table[0]))

/*
 * check if it is an IO deice
 *	return 1 if this is a io device; return 0 for else.
 */
static int
is_io_device(char *device_class)
{
	int i;

	for (i = 0; i < NIODEVICE; i++) {
	    if (strcmp(device_class, io_device_table[i]) == 0)
		return (1);
	}

	return (0);
}

/*
 * check if it is a bus
 *	return	1 if this is a bus; return 0 for else.
 */
static int
is_bus(char *device_class)
{
	int i;

	for (i = 0; i < NBUS; i++) {
	    if (strcmp(device_class, bus_table[i]) == 0)
		return (1);
	}

	return (0);
}

/*
 * search children to get the node by the nodename
 *	return node handler in picl_nodehdl_t *nodeh
 */
static int
picldiag_get_node_by_name(picl_nodehdl_t rooth, char *name,
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

/*
 * get the value by the property name of the string prop
 *	the value will be in outbuf
 * Caller must free the outbuf
 */
static int
picldiag_get_string_propval(picl_nodehdl_t modh, char *prop_name, char **outbuf)
{
	int		err;
	picl_prophdl_t	proph;
	picl_propinfo_t	pinfo;
	char		*prop_value;

	err = picl_get_propinfo_by_name(modh, prop_name, &pinfo, &proph);
	if (err != PICL_SUCCESS)
		return (err);

	/*
	 * If it is not a string prop, return NULL
	 */
	if (pinfo.type != PICL_PTYPE_CHARSTRING)
	    return (PICL_FAILURE);

	prop_value = malloc(pinfo.size);
	if (prop_value == NULL)
		return (PICL_FAILURE);

	err = picl_get_propval(proph, prop_value, pinfo.size);
	if (err != PICL_SUCCESS) {
		free(prop_value);
		return (err);
	}

	*outbuf = prop_value;
	return (PICL_SUCCESS);
}


/*
 * return the value as a signed integer
 */

static int64_t
picldiag_get_int_propval(picl_nodehdl_t modh, char *prop_name, int *ret)
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
 * return the value of the uint prop
 */
static uint64_t
picldiag_get_uint_propval(picl_nodehdl_t modh, char *prop_name, int *ret)
{
	int		err;
	picl_prophdl_t	proph;
	picl_propinfo_t	pinfo;
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
 * return the value of the float prop
 */
static float
picldiag_get_float_propval(picl_nodehdl_t modh, char *prop_name, int *ret)
{
	int		err;
	picl_prophdl_t	proph;
	picl_propinfo_t	pinfo;
	float		floatv;

	err = picl_get_propinfo_by_name(modh, prop_name, &pinfo, &proph);
	if (err != PICL_SUCCESS) {
		*ret = err;
		return ((float)0);
	}

	/*
	 * If it is not a float prop, return failure
	 */
	if (pinfo.type != PICL_PTYPE_FLOAT) {
		*ret = PICL_FAILURE;
		return ((float)0);
	}

	*ret = picl_get_propval(proph, &floatv, sizeof (floatv));
	return (floatv);
}

/*
 * get the clock frequency
 */
static int
picldiag_get_clock_freq(picl_nodehdl_t modh, uint32_t *freq)
{
#define	ROUND_TO_MHZ(x)	(((x) + 500000)/ 1000000)
	int		err;
	uint64_t	clk_freq;

	clk_freq = picldiag_get_uint_propval(modh, OBP_PROP_CLOCK_FREQ, &err);
	if (err != PICL_SUCCESS)
		return (err);

	*freq = ROUND_TO_MHZ(clk_freq);

	return (PICL_SUCCESS);
}

/*
 * get the clock frequency from parent
 */
static int
picldiag_get_clock_from_parent(picl_nodehdl_t nodeh, uint32_t *clk)
{
	picl_nodehdl_t	parenth;
	int		err;


	err = picl_get_propval_by_name(nodeh, PICL_PROP_PARENT,
	    &parenth, sizeof (parenth));

	while (err == PICL_SUCCESS) {
		err = picldiag_get_clock_freq(parenth, clk);
		if (err != PICL_PROPNOTFOUND)
			return (err);

		err = picl_get_propval_by_name(parenth, PICL_PROP_PARENT,
		    &parenth, sizeof (parenth));
	}

	return (err);
}

/*
 * get _fru_parent prop
 * If not found, then travese superiors (parent nodes) until
 * a _fru_parent property is found.
 * If not found, no fru parent
 */
static int
picldiag_get_fru_parent(picl_nodehdl_t nodeh, picl_nodehdl_t *fruparenth)
{
	picl_nodehdl_t	fruh;
	int		err;

	/* find fru parent */
	err = picl_get_propval_by_name(nodeh, PICL_REFPROP_FRU_PARENT,
	    &fruh, sizeof (fruh));

	if (err != PICL_SUCCESS)
		err = picl_get_propval_by_name(nodeh, PICL_REFPROP_LOC_PARENT,
		    &fruh, sizeof (fruh));

	while (err == PICL_PROPNOTFOUND) {
		err = picl_get_propval_by_name(nodeh, PICL_PROP_PARENT,
		    &nodeh, sizeof (nodeh));
		if (err != PICL_SUCCESS)
			return (err);

		err = picl_get_propval_by_name(nodeh, PICL_REFPROP_FRU_PARENT,
		    &fruh, sizeof (fruh));
		if (err != PICL_SUCCESS)
			err = picl_get_propval_by_name(nodeh,
			    PICL_REFPROP_LOC_PARENT, &fruh, sizeof (fruh));
	}

	if (err == PICL_SUCCESS)
		*fruparenth = fruh;

	return (err);
}

/*
 * get label
 *
 * To get the label, use the following algorithm:
 * Lookup "Label" property in the fru node itself. If no
 * Label found, then traverse superiors (parent nodes) until
 * a Label property is found.
 * if not found, then no label
 */
static int
picldiag_get_label(picl_nodehdl_t nodeh, char **label)
{
	int		err;

	err = picldiag_get_string_propval(nodeh, PICL_PROP_LABEL, label);

	while (err == PICL_PROPNOTFOUND) {
		err = picl_get_propval_by_name(nodeh, PICL_PROP_PARENT,
		    &nodeh, sizeof (nodeh));
		if (err != PICL_SUCCESS)
			return (err);

		err = picldiag_get_string_propval(nodeh, PICL_PROP_LABEL,
		    label);
	}

	return (err);
}

/*
 * get combined label
 *
 * like picldiag_get_label, except concatenates the labels of parent locations
 * eg SB0/P3 for processor P3 on system board SB0
 *
 * if caller specifies non-zero label length, label will be cut to specified
 * length.
 * negative length is left justified, non-negative length is right justified
 */
static int
picldiag_get_combined_label(picl_nodehdl_t nodeh, char **label, int lablen)
{
	int	err;
	char	*ptr;
	char	*ptr1 = NULL;
	char	*ptr2;
	int	len;

	err = picldiag_get_string_propval(nodeh, PICL_PROP_LABEL, &ptr1);
	if (err != PICL_PROPNOTFOUND && err != PICL_SUCCESS)
		return (err);

	for (;;) {
		err = picl_get_propval_by_name(nodeh, PICL_PROP_PARENT,
		    &nodeh, sizeof (nodeh));
		if (err == PICL_PROPNOTFOUND)
			break;
		if (err != PICL_SUCCESS)
			return (err);

		err = picldiag_get_string_propval(nodeh, PICL_PROP_LABEL, &ptr);
		if (err == PICL_SUCCESS) {
			if (ptr1 == NULL) {
				ptr1 = ptr;
			} else {
				ptr2 = malloc(strlen(ptr1) + strlen(ptr) + 2);
				if (ptr2 == NULL)
					return (PICL_FAILURE);
				(void) strlcpy(ptr2, ptr, strlen(ptr)-1);
				(void) strlcat(ptr2, "/", 1);
				(void) strlcat(ptr2, ptr1, strlen(ptr1)-1);
				(void) strlcat(ptr2, "\0", 1);

				(void) free(ptr);
				(void) free(ptr1);
				ptr1 = ptr2;
			}
		} else if (err != PICL_PROPNOTFOUND) {
			return (err);
		}
	}

	if (ptr1 == NULL)
		return (PICL_PROPNOTFOUND);

	len = strlen(ptr1);
	/* if no string truncation is desired or required */
	if ((lablen == 0) || (len <= abs(lablen))) {
		*label = ptr1;
		return (PICL_SUCCESS);
	}

	/* string truncation is required; alloc space for (lablen + \0) */
	ptr = malloc(abs(lablen) + 1);
	if (ptr == 0)
		return (PICL_FAILURE);
	if (lablen > 0) {
		/* right justification; label = "+<string>\0" */
		strlcpy(ptr, "+", 1);
		strlcat(ptr, ptr1 + len - lablen + 1, lablen + 1);
	} else {
		/* left justification; label = "<string>+\0" */
		strlcpy(ptr, ptr1, abs(lablen) - 1);
		strcat(ptr, "+");
	}

	*label = ptr;
	return (PICL_SUCCESS);
}

/*
 * return the first compatible value
 */
static int
picldiag_get_first_compatible_value(picl_nodehdl_t nodeh, char **outbuf)
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
 * print the header in the center
 */
static void
logprintf_header(char *header, size_t line_width)
{
	size_t	start_pos;
	size_t	i;

	log_printf("\n");
	start_pos = (line_width - strlen(header) - 2) / 2;

	for (i = 0; i < start_pos; i++)
		log_printf("%s", HEADING_SYMBOL);

	log_printf(" %s ", header);

	for (i = 0; i < start_pos; i++)
		log_printf("%s", HEADING_SYMBOL);

	log_printf("\n");
}

/*
 * print the size
 */
static void
logprintf_size(uint64_t size)
{

	uint64_t	kbyte = 1024;
	uint64_t	mbyte = 1024 * 1024;
	uint64_t	gbyte = 1024 * 1024 * 1024;
	uint64_t	residue;
	char		buf[SIZE_FIELD];

	if (size >= gbyte) {
		residue = size % gbyte;
		if (residue == 0)
			snprintf(buf, sizeof (buf), "%dGB",
			    (int)(size / gbyte));
		else
			snprintf(buf, sizeof (buf), "%.2fGB",
			    (float)size / gbyte);
	} else if (size >= mbyte) {
		residue = size % mbyte;
		if (residue == 0)
			snprintf(buf, sizeof (buf), "%dMB",
			    (int)(size / mbyte));
		else
			snprintf(buf, sizeof (buf), "%.2fMB",
			    (float)size / mbyte);
	} else {
		residue = size % kbyte;
		if (residue == 0)
			snprintf(buf, sizeof (buf), "%dKB",
			    (int)(size / kbyte));
		else
			snprintf(buf, sizeof (buf), "%.2fKB",
			    (float)size / kbyte);
	}

	log_printf("%-10s ", buf);
}

/*
 * display platform banner
 */
static int
display_platform_banner(picl_nodehdl_t plafh)
{
	char	*platform;
	char	*banner_name;
	int	err;

	/*
	 * get PICL_PROP_MACHINE and PICL_PROP_BANNER_NAME
	 */
	log_printf(SIGN_ON_MSG);
	err = picldiag_get_string_propval(plafh, PICL_PROP_MACHINE,
	    &platform);
	if (err != PICL_SUCCESS)
		return (err);
	log_printf(" %s", platform);
	free(platform);

	err = picldiag_get_string_propval(plafh, OBP_PROP_BANNER_NAME,
	    &banner_name);
	if (err != PICL_SUCCESS)
		return (err);
	log_printf(" %s", banner_name);
	free(banner_name);

	log_printf("\n");
	return (PICL_SUCCESS);
}

/*
 * display the clock frequency
 */
static int
display_system_clock(picl_nodehdl_t plafh)
{
	uint32_t	system_clk;
	int		err;

	err = picldiag_get_clock_freq(plafh, &system_clk);
	if (err != PICL_SUCCESS)
		return (err);

	log_printf(SYSCLK_FREQ_MSG, system_clk);

	return (PICL_SUCCESS);
}

/*
 * callback function to display the memory size
 */
/*ARGSUSED*/
static int
memory_callback(picl_nodehdl_t memh, void *args)
{
	uint64_t	mem_size;
	int		err;

	log_printf(MEM_SIZE_MSG);
	mem_size = picldiag_get_uint_propval(memh, PICL_PROP_SIZE, &err);
	if (err == PICL_SUCCESS)
		logprintf_size(mem_size);
	log_printf("\n");
	no_xfer_size = 0;
	mem_xfersize = picldiag_get_uint_propval(memh, PICL_PROP_TRANSFER_SIZE,
	    &err);
	if (err == PICL_PROPNOTFOUND)
		no_xfer_size = 1;
	return (PICL_WALK_TERMINATE);
}

/*
 * callback function to print cpu information
 */
/*ARGSUSED*/
static int
cpu_callback(picl_nodehdl_t nodeh, void *args)
{
	int		err;
	int		id;
	uint64_t 	uintval;
	uint32_t	freq;
	char		*impl_name;
	char		*status;
	picl_prophdl_t	parenth;
	char		*label;

	/*
	 * If no ID is found, return
	 */
	id = picldiag_get_uint_propval(nodeh, PICL_PROP_ID, &err);
	if (err == PICL_PROPNOTFOUND)
		return (PICL_WALK_CONTINUE);
	else if (err != PICL_SUCCESS)
		return (err);
	log_printf(" %2d  ", id);

	/*
	 * If no freq is found, return
	 */
	err = picldiag_get_clock_freq(nodeh, &freq);
	if (err == PICL_PROPNOTFOUND)
		return (PICL_WALK_CONTINUE);
	else if (err != PICL_SUCCESS)
		return (err);
	log_printf(dgettext(TEXT_DOMAIN, "%4d MHz  "), freq);

	/* Ecache size */
	uintval = picldiag_get_uint_propval(nodeh, OBP_PROP_ECACHE_SIZE, &err);
	if (err == PICL_PROPNOTFOUND)
		log_printf(" -          ");
	else if (err == PICL_SUCCESS)
		logprintf_size(uintval);
	else
		return (err);

	/* Implementation */
	impl_name = NULL;
	err = picldiag_get_string_propval(nodeh, PICL_PROP_NAME, &impl_name);
	if (err != PICL_SUCCESS)
		log_printf(dgettext(TEXT_DOMAIN, "  <unknown>           "));
	else
		log_printf(" %-22s ", impl_name);

	/* CPU Mask */
	uintval = picldiag_get_uint_propval(nodeh, OBP_PROP_MASK, &err);
	if (err == PICL_PROPNOTFOUND)
		log_printf("  -     ");
	else if (err == PICL_SUCCESS)
		log_printf("%2lld.%-2lld   ", (uintval >> 4) & 0xf,
		    uintval & 0xf);
	else
		return (err);

	/*
	 * Status - if the node has a status property then display that
	 * otherwise display the State property
	 */
	err = picldiag_get_string_propval(nodeh, PICL_PROP_STATUS, &status);
	if (err == PICL_SUCCESS) {
		log_printf("%-12s", status);
		free(status);
	} else if (err != PICL_PROPNOTFOUND && err !=
	    PICL_PROPVALUNAVAILABLE && err != PICL_ENDOFLIST) {
		return (err);
	} else {
		err = picldiag_get_string_propval(nodeh,
		    PICL_PROP_STATE, &status);
		if (err == PICL_SUCCESS) {
			log_printf("%-12s", status);
			free(status);
		} else if (err != PICL_PROPNOTFOUND && err !=
		    PICL_PROPVALUNAVAILABLE && err !=
		    PICL_ENDOFLIST) {
			return (err);
		} else {
			log_printf(dgettext(TEXT_DOMAIN, "unknown    "));
		}
	}

	/*
	 * Location: use label of fru parent
	 */
	err = picldiag_get_fru_parent(nodeh, &parenth);
	if (err == PICL_PROPNOTFOUND) {
		log_printf(" -      ");
	} else if (err == PICL_SUCCESS) {
		err = picldiag_get_combined_label(parenth, &label, 12);
		if (err == PICL_PROPNOTFOUND)
			log_printf(" -      ");
		else if (err == PICL_SUCCESS) {
			log_printf("%s", label);
			free(label);
		} else
			return (err);
	} else
		return (err);

	log_printf("\n");
	return (PICL_WALK_CONTINUE);
}

/*
 * display cpu information
 */
static int
display_cpu_info(picl_nodehdl_t plafh)
{
	int	err;

	/*
	 * Display the table header for CPUs . Then display the CPU
	 * frequency, cache size, and processor revision  on all the boards.
	 */
	logprintf_header(dgettext(TEXT_DOMAIN, "CPUs"), DEFAULT_LINE_WIDTH);
	log_printf(dgettext(TEXT_DOMAIN, "               E$          CPU"
		"                    CPU\n"));
	log_printf(dgettext(TEXT_DOMAIN,
	    "CPU  Freq      Size        Implementation"
		"         Mask    Status      Location\n"));
	log_printf("---  --------  ----------  ---------------------  "
		"-----   ------      --------\n");

	err = picl_walk_tree_by_class(plafh, PICL_CLASS_CPU, PICL_CLASS_CPU,
	    cpu_callback);
	return (err);
}

/*
 * Inserts an io_card structure into the list.
 */
static void
add_io_card(uint32_t board, uint32_t bus_id, uint32_t slot, char *label,
    uint32_t freq, char *name, char *model, char *status, char *devfs_path)
{
	struct io_card card;

	card.display = 1;
	card.board = board;
	switch (bus_id) {
	case PCI_TYPE:
		strlcpy(card.bus_type, PCI_NAME, MAXSTRLEN);
		break;
	default: /* won't reach here */
		strlcpy(card.bus_type, "", MAXSTRLEN);
		break;
	}
	if (label == NULL)
		card.slot = slot;
	else {
		card.slot = PCI_SLOT_IS_STRING;
		(void) strlcpy(card.slot_str, label, MAXSTRLEN);
	}
	card.freq = freq;
	card.status[0] = '\0';
	card.name[0] = '\0';
	card.model[0] = '\0';
	card.notes[0] = '\0';
	if (status != NULL)
		strlcpy(card.status, status, MAXSTRLEN);
	if (name != NULL)
		strlcpy(card.name, name, MAXSTRLEN);
	if (model != NULL)
		strlcpy(card.model, model, MAXSTRLEN);
	if (status != NULL)
		strlcpy(card.status, status, MAXSTRLEN);
	if (devfs_path != NULL)
		strlcpy(card.notes, devfs_path, MAXSTRLEN);

	io_card_list = insert_io_card(io_card_list, &card);
}

static void
append_to_bank_list(bank_list_t *newptr)
{
	bank_list_t	*ptr;

	if (mem_banks == NULL) {
		mem_banks = newptr;
		return;
	}
	ptr = mem_banks;
	while (ptr->next != NULL)
		ptr = ptr->next;

	ptr->next = newptr;
}

static void
free_bank_list(void)
{
	bank_list_t	*ptr;
	bank_list_t	*tmp;

	for (ptr = mem_banks; ptr != NULL; ptr = tmp) {
		tmp = ptr->next;
		free(ptr);
	}
	mem_banks = NULL;
}


/*
 * print label for memory module
 */
static int
logprintf_memory_module_label(picl_nodehdl_t moduleh)
{
	picl_nodehdl_t	fruparenth;
	int		err;
	char		*label;

	err = picldiag_get_fru_parent(moduleh, &fruparenth);
	if (err == PICL_PROPNOTFOUND) {
		log_printf("-");
		return (PICL_SUCCESS);
	} else if (err != PICL_SUCCESS)
		return (err);

	err = picldiag_get_combined_label(fruparenth, &label, 30);
	if (err == PICL_PROPNOTFOUND)
		log_printf("-");
	else if (err == PICL_SUCCESS) {
		log_printf("%-15s", label);
		free(label);
	} else
		return (err);

	return (PICL_SUCCESS);
}

/*
 * print the bank id and add the bank handle in the bank list
 * return the head of the bank list
 */
static int
membank_callback(picl_nodehdl_t bankh, void *args)
{
	int		err;
	int64_t		id;
	uint64_t	match;
	uint64_t	mask;
	int		i;
	bank_list_t	*newptr;
	seg_info_t	*segp = args;

	/*
	 * print the bank id in the segment table contains column
	 */
	id = picldiag_get_uint_propval(bankh, PICL_PROP_ID, &err);
	if (segp->bank_count > 0)
		log_printf(",");
	if (err == PICL_PROPNOTFOUND)
		log_printf("-");
	else if (err == PICL_SUCCESS)
		log_printf("%-lld", id);
	else
		return (err);
	segp->bank_count++;

	/*
	 * Save the bank information for later (print_bank_table)
	 */
	newptr = malloc(sizeof (*newptr));
	if (newptr == NULL)
		return (PICL_FAILURE);

	newptr->nodeh = bankh;
	newptr->iway_count = 0;
	newptr->next = NULL;
	append_to_bank_list(newptr);

	/*
	 * Compute the way numbers for the bank
	 */
	if (no_xfer_size)
		return (PICL_WALK_CONTINUE);

	match = picldiag_get_uint_propval(bankh, PICL_PROP_ADDRESSMATCH, &err);
	if (err == PICL_PROPNOTFOUND)
		return (PICL_WALK_CONTINUE);
	else if (err != PICL_SUCCESS)
		return (err);

	mask = picldiag_get_uint_propval(bankh, PICL_PROP_ADDRESSMASK, &err);
	if (err == PICL_PROPNOTFOUND)
		return (PICL_WALK_CONTINUE);
	else if (err != PICL_SUCCESS)
		return (err);

	i = 0;
	while ((i < segp->ifactor) && (newptr->iway_count < MAX_IWAYS)) {
		if (((segp->base + i * mem_xfersize) & mask) == match)
			newptr->iway[newptr->iway_count++] = i;
		++i;
	}
	return (PICL_WALK_CONTINUE);
}


/*
 * find the memory bank and add the bank handle in the bank list
 * return the head of the bank list
 */
static int
logprintf_bankinfo(picl_nodehdl_t segh, seg_info_t *segp)
{
	int		err;

	log_printf(dgettext(TEXT_DOMAIN, "BankIDs "));
	/*
	 * find memory-bank
	 */
	segp->bank_count = 0;
	err = picl_walk_tree_by_class(segh, PICL_CLASS_MEMORY_BANK, segp,
	    membank_callback);
	log_printf("\n");
	return (err);
}

/*
 * print the label of memory module or the memory module bank ids
 */
static int
logprintf_seg_contains_col(picl_nodehdl_t nodeh, seg_info_t *segp)
{
	picl_nodehdl_t	moduleh;
	int		err;

	/*
	 * find memory-module if referenced directly from the memory-segment
	 * (ie no memory banks)
	 */
	err = picl_get_propval_by_name(nodeh, PICL_REFPROP_MEMORY_MODULE,
	    &moduleh, sizeof (moduleh));
	if ((err != PICL_SUCCESS) && (err != PICL_PROPNOTFOUND))
		return (err);
	if (err == PICL_SUCCESS) {
		err = logprintf_memory_module_label(moduleh);
		log_printf("\n");
		return (err);
	}

	/*
	 * memory-module not referenced directly from the memory segment
	 * so list memory banks instead
	 */
	err = logprintf_bankinfo(nodeh, segp);
	return (err);
}

/*
 * find all memory modules under the given memory module group
 * and print its label
 */
static int
logprintf_memory_module_group_info(picl_nodehdl_t memgrph, uint64_t mcid)
{
	int		err;
	int64_t		id;
	boolean_t	got_status;
	picl_nodehdl_t	moduleh;
	char		piclclass[PICL_CLASSNAMELEN_MAX];
	picl_nodehdl_t	fruparenth;
	char		*status;

	id = picldiag_get_uint_propval(memgrph, PICL_PROP_ID, &err);
	if (err == PICL_PROPNOTFOUND)
		id = -1;
	else if (err != PICL_SUCCESS)
		return (err);

	err = picl_get_propval_by_name(memgrph, PICL_PROP_CHILD, &moduleh,
	    sizeof (picl_nodehdl_t));

	while (err == PICL_SUCCESS) {
		/* controller id */
		log_printf("%-8lld       ", mcid);

		/* group id */
		if (id == -1) {
			log_printf("-         ");
		} else {
			log_printf("%-8lld ", id);
		}

		err = picl_get_propval_by_name(moduleh, PICL_PROP_CLASSNAME,
		    piclclass, sizeof (piclclass));
		if (err != PICL_SUCCESS)
			return (err);

		if (strcmp(piclclass, PICL_CLASS_MEMORY_MODULE) == 0) {
			err = logprintf_memory_module_label(moduleh);
			if (err != PICL_SUCCESS)
				return (err);
		}

		got_status = B_FALSE;
		err = picldiag_get_fru_parent(moduleh, &fruparenth);
		if (err == PICL_SUCCESS) {
			err = picldiag_get_string_propval(fruparenth,
			    PICL_PROP_OPERATIONAL_STATUS, &status);
			if (err == PICL_SUCCESS) {
				got_status = B_TRUE;
			} else if (err != PICL_PROPNOTFOUND)
				return (err);
		} else if (err != PICL_PROPNOTFOUND)
			return (err);

		if (!got_status) {
			err = picldiag_get_string_propval(moduleh,
			    PICL_PROP_STATUS, &status);
			if (err == PICL_SUCCESS)
				got_status = B_TRUE;
			else if (err != PICL_PROPNOTFOUND)
				return (err);
		}
		if (got_status) {
			log_printf("%s", status);
			free(status);
		}
		err = picl_get_propval_by_name(moduleh, PICL_PROP_PEER,
		    &moduleh, sizeof (picl_nodehdl_t));

		log_printf("\n");
	}
	if (err == PICL_PROPNOTFOUND)
		return (PICL_SUCCESS);
	return (err);
}

/*
 * search children to find memory module group under memory-controller
 */
static int
find_memory_module_group(picl_nodehdl_t mch, int *print_header)
{
	picl_nodehdl_t	memgrph;
	uint64_t	mcid;
	int		err;
	char		piclclass[PICL_CLASSNAMELEN_MAX];

	mcid = picldiag_get_uint_propval(mch, OBP_PROP_PORTID, &err);
	if (err == PICL_PROPNOTFOUND)
		mcid = DEFAULT_PORTID;
	else if (err != PICL_SUCCESS)
		return (err);

	err = picl_get_propval_by_name(mch, PICL_PROP_CHILD,
	    &memgrph, sizeof (picl_nodehdl_t));
	while (err == PICL_SUCCESS) {
		err = picl_get_propval_by_name(memgrph,
		    PICL_PROP_CLASSNAME, piclclass, sizeof (piclclass));
		if (err != PICL_SUCCESS)
			return (err);

		if (strcmp(piclclass, PICL_CLASS_MEMORY_MODULE_GROUP) == 0) {
			if (*print_header == 1) {
				log_printf(
				    dgettext(TEXT_DOMAIN,
					"\nMemory Module Groups:\n"));
				log_printf("--------------------------");
				log_printf("------\n");
				log_printf(dgettext(TEXT_DOMAIN,
				    "ControllerID   GroupID  Labels\n"));
				log_printf("--------------------------");
				log_printf("------\n");
				*print_header = 0;
			}
			err = logprintf_memory_module_group_info(memgrph, mcid);
			if (err != PICL_SUCCESS)
				return (err);
		}

		err = picl_get_propval_by_name(memgrph, PICL_PROP_PEER,
		    &memgrph, sizeof (picl_nodehdl_t));
	}
	if (err == PICL_PROPNOTFOUND)
		return (PICL_SUCCESS);
	return (err);
}

/*
 * print memory module group table per memory-controller
 */
static int
print_memory_module_group_table(picl_nodehdl_t plafh)
{
	picl_nodehdl_t	mch;
	int		err;
	char		piclclass[PICL_CLASSNAMELEN_MAX];
	int		print_header;

	print_header = 1;

	/*
	 * find memory-controller
	 */
	err = picl_get_propval_by_name(plafh, PICL_PROP_CHILD, &mch,
	    sizeof (picl_nodehdl_t));
	while (err == PICL_SUCCESS) {
		err = picl_get_propval_by_name(mch, PICL_PROP_CLASSNAME,
		    piclclass, sizeof (piclclass));
		if (err != PICL_SUCCESS)
			return (err);

		if (strcmp(piclclass, PICL_CLASS_MEMORY_CONTROLLER) != 0) {
			err = print_memory_module_group_table(mch);
			if (err != PICL_SUCCESS)
				return (err);
			err = picl_get_propval_by_name(mch, PICL_PROP_PEER,
			    &mch, sizeof (picl_nodehdl_t));
			continue;
		}

		err = find_memory_module_group(mch, &print_header);
		if (err != PICL_SUCCESS)
			return (err);

		err = picl_get_propval_by_name(mch, PICL_PROP_PEER,
		    &mch, sizeof (picl_nodehdl_t));
	}
	if (err == PICL_PROPNOTFOUND)
		return (PICL_SUCCESS);

	return (err);
}

/*
 * print bank table
 */
static int
print_bank_table(void)
{
	bank_list_t	*ptr;
	picl_nodehdl_t	bankh;
	picl_nodehdl_t	memgrph;
	picl_nodehdl_t	mch;
	int		err;
	int32_t		i;
	uint64_t	size;
	int		id;

	log_printf(dgettext(TEXT_DOMAIN, "\nBank Table:\n"));
	log_printf("---------------------------------------");
	log_printf("--------------------\n");
	log_printf(dgettext(TEXT_DOMAIN, "           Physical Location\n"));
	log_printf(dgettext(TEXT_DOMAIN, "ID       ControllerID  GroupID   "));
	log_printf(dgettext(TEXT_DOMAIN, "Size       Interleave Way\n"));
	log_printf("---------------------------------------");
	log_printf("--------------------\n");

	for (ptr = mem_banks; ptr != NULL; ptr = ptr->next) {
		bankh = ptr->nodeh;
		id = picldiag_get_uint_propval(bankh, PICL_PROP_ID, &err);
		if (err != PICL_SUCCESS)
			log_printf("%-8s ", "-");
		else
			log_printf("%-8d ", id);

		/* find memory-module-group */
		err = picl_get_propval_by_name(bankh,
		    PICL_REFPROP_MEMORY_MODULE_GROUP, &memgrph,
		    sizeof (memgrph));
		if (err == PICL_PROPNOTFOUND) {
			log_printf("%-8s      ", "-");
			log_printf("%-8s  ", "-");
		} else if (err != PICL_SUCCESS)
			return (err);
		else {
			/*
			 * get controller id
			 */
			err = picl_get_propval_by_name(memgrph,
			    PICL_PROP_PARENT, &mch, sizeof (picl_nodehdl_t));
			if (err != PICL_SUCCESS)
				return (err);

			id = picldiag_get_uint_propval(mch, OBP_PROP_PORTID,
			    &err);
			if (err == PICL_PROPNOTFOUND)
				id = DEFAULT_PORTID; /* use default */
			else if (err != PICL_SUCCESS)
				return (err);

			log_printf("%-8d      ", id);

			/* get group id */
			id = picldiag_get_uint_propval(memgrph, PICL_PROP_ID,
			    &err);
			if (err == PICL_PROPNOTFOUND)
				log_printf("-          ");
			else if (err == PICL_SUCCESS)
				log_printf("%-8d  ", id);
			else
				return (err);
		}

		size = picldiag_get_uint_propval(bankh, PICL_PROP_SIZE, &err);
		if (err == PICL_PROPNOTFOUND)
			log_printf("-        	 ");
		else if (err == PICL_SUCCESS)
			logprintf_size(size);
		else
			return (err);

		log_printf("     ");
		for (i = 0; i < ptr->iway_count; i++) {
			if (i != 0)
				log_printf(",");
			log_printf("%d", ptr->iway[i]);
		}

		log_printf("\n");
	}
	return (PICL_SUCCESS);
}

/*
 * callback function to print segment, add the bank in the list and
 * return the bank list
 */
/* ARGSUSED */
static int
memseg_callback(picl_nodehdl_t segh, void *args)
{
	seg_info_t	seginfo;
	int		err;

	/* get base address */
	seginfo.base = picldiag_get_uint_propval(segh, PICL_PROP_BASEADDRESS,
	    &err);
	if (err == PICL_PROPNOTFOUND) {
		log_printf("-\n");
		return (PICL_WALK_CONTINUE);
	} else if (err == PICL_SUCCESS)
		log_printf("0x%-16llx ", seginfo.base);
	else
		return (err);

	/* get size */
	seginfo.size = picldiag_get_uint_propval(segh, PICL_PROP_SIZE, &err);
	if (err == PICL_PROPNOTFOUND) {
		log_printf("-\n");
		return (PICL_WALK_CONTINUE);
	} else if (err == PICL_SUCCESS)
		logprintf_size(seginfo.size);
	else
		return (err);

	/* get interleave factor */
	seginfo.ifactor = picldiag_get_uint_propval(segh,
	    PICL_PROP_INTERLEAVE_FACTOR, &err);

	if (err == PICL_PROPNOTFOUND) {
		log_printf("       -\n");
		return (PICL_WALK_CONTINUE);
	} else if (err == PICL_SUCCESS)
		log_printf("       %-2d          ", seginfo.ifactor);
	else
		return (err);

	seginfo.bank_count = 0;
	err = logprintf_seg_contains_col(segh, &seginfo);
	if (err != PICL_SUCCESS)
		return (err);
	return (PICL_WALK_CONTINUE);
}

/*
 * search children to find memory-segment and set up the bank list
 */
static int
find_segments(picl_nodehdl_t plafh)
{
	int		err;

	log_printf(dgettext(TEXT_DOMAIN, "Segment Table:\n"));
	log_printf("------------------------------");
	log_printf("-----------------------------------------\n");
	log_printf(dgettext(TEXT_DOMAIN, "Base Address       Size       "));
	log_printf(dgettext(TEXT_DOMAIN, "Interleave Factor  Contains\n"));
	log_printf("------------------------------");
	log_printf("-----------------------------------------\n");

	err = picl_walk_tree_by_class(plafh, PICL_CLASS_MEMORY_SEGMENT,
	    NULL, memseg_callback);
	return (err);
}

/*
 * display memory configuration
 */
static int
display_memory_config(picl_nodehdl_t plafh)
{
	int		err;

	logprintf_header(dgettext(TEXT_DOMAIN, "Memory Configuration"),
	    DEFAULT_LINE_WIDTH);

	mem_banks = NULL;
	err = find_segments(plafh);

	if ((err == PICL_SUCCESS) && (mem_banks != NULL))
		print_bank_table();

	free_bank_list();

	return (print_memory_module_group_table(plafh));
}

/*
 * print the hub device
 */
static int
logprintf_hub_devices(picl_nodehdl_t hubh)
{
	char		*name;
	int		portnum;
	char		*labelp;
	picl_nodehdl_t	parenth;
	int		err;

	err = picldiag_get_string_propval(hubh, PICL_PROP_NAME, &name);
	if (err != PICL_SUCCESS)
		return (err);
	log_printf("%-12.12s  ", name);
	free(name);

	err = picl_get_propval_by_name(hubh, PICL_REFPROP_LOC_PARENT, &parenth,
	    sizeof (picl_nodehdl_t));

	if (err == PICL_SUCCESS) {
		/* Read the Label */
		err = picldiag_get_label(parenth, &labelp);
		if (err == PICL_SUCCESS) {
			log_printf("%s\n", labelp);
			free(labelp);
			return (PICL_SUCCESS);
		} else if (err != PICL_PROPNOTFOUND) {
			log_printf("\n");
			return (err);
		}
	} else if (err != PICL_PROPNOTFOUND) {
		log_printf("\n");
		return (err);
	}

	/* No Label, try the reg */
	err = picl_get_propval_by_name(hubh, OBP_PROP_REG, &portnum,
	    sizeof (portnum));
	if (err == PICL_PROPNOTFOUND)
		log_printf("  -\n");
	else if (err != PICL_SUCCESS) {
		log_printf("\n");
		return (err);
	} else
		log_printf("%3d\n", portnum);

	return (PICL_SUCCESS);
}

/*
 * callback functions to display hub devices
 */
/* ARGSUSED */
static int
print_usb_devices(picl_nodehdl_t hubh, void *arg)
{
	picl_nodehdl_t	chdh;
	char		*rootname;
	int		type = *(int *)arg;
	int		hubnum;
	int		err;

	err = picl_get_propval_by_name(hubh, PICL_PROP_CHILD, &chdh,
	    sizeof (picl_nodehdl_t));

	/* print header */
	if (err == PICL_SUCCESS) {
		err = picldiag_get_string_propval(hubh, PICL_PROP_NAME,
		    &rootname);
		if (err != PICL_SUCCESS)
			return (err);

		if (type == USB) {
			log_printf("\n===============================");
			log_printf(dgettext(TEXT_DOMAIN,
			    " %s Devices "), rootname);
		} else {
			/* Get its hub number */
			err = picl_get_propval_by_name(hubh,
			    OBP_PROP_REG, &hubnum, sizeof (hubnum));
			if ((err != PICL_SUCCESS) &&
			    (err != PICL_PROPNOTFOUND)) {
				free(rootname);
				return (err);
			}

			log_printf("\n===============================");
			if (err == PICL_SUCCESS)
				log_printf(dgettext(TEXT_DOMAIN,
				    " %s#%d Devices "),
				    rootname, hubnum);
			else
				log_printf(dgettext(TEXT_DOMAIN,
				    " %s Devices "), rootname);
		}

		log_printf("===============================\n\n");
		log_printf(dgettext(TEXT_DOMAIN, "Name          Port#\n"));
		log_printf("------------  -----\n");
		free(rootname);

		do {
			logprintf_hub_devices(chdh);

			err = picl_get_propval_by_name(chdh, PICL_PROP_PEER,
			    &chdh, sizeof (picl_nodehdl_t));
		} while (err == PICL_SUCCESS);
	}


	if (err == PICL_PROPNOTFOUND)
		return (PICL_WALK_CONTINUE);
	return (err);
}

/*
 * callback functions to display usb devices
 */
/* ARGSUSED */
static int
usb_callback(picl_nodehdl_t usbh, void *args)
{
	int		err;
	int		type;

	type = USB;
	err = print_usb_devices(usbh, &type);
	if (err != PICL_WALK_CONTINUE)
		return (err);
	type = HUB;
	err = picl_walk_tree_by_class(usbh, NULL, &type, print_usb_devices);
	if (err == PICL_SUCCESS)
		err = PICL_WALK_CONTINUE;
	return (err);
}


/*
 * find usb devices and print its information
 */
static int
display_usb_devices(picl_nodehdl_t plafh)
{
	int err;

	/*
	 * get the usb node
	 */
	err = picl_walk_tree_by_class(plafh, PICL_CLASS_USB, NULL,
	    usb_callback);
	return (err);
}



/*
 * If nodeh is the io device, add it into the io list and return
 * If it is not an io device and it has the subtree, traverse the subtree
 * and add all leaf io devices
 */
static int
add_io_leaves(picl_nodehdl_t nodeh, char *parentname, uint32_t board,
    uint32_t bus_id, uint64_t slot, uint32_t freq, char *model, char *status)
{
	picl_nodehdl_t	childh;
	picl_prophdl_t	proph;
	picl_propinfo_t	pinfo;
	int		err;
	char		*nameval;
	char		piclclass[PICL_CLASSNAMELEN_MAX];
	char		nodename[MAXSTRLEN];
	char		name[MAXSTRLEN];
	char		*devfs_path;
	char		*compatible;
	picl_nodehdl_t	fruparenth;
	char		*label;
	char		binding_name[MAXSTRLEN];

	err = picl_get_propinfo_by_name(nodeh, PICL_PROP_NAME, &pinfo,
	    &proph);
	if (err != PICL_SUCCESS)
		return (err);

	nameval = alloca(pinfo.size);
	if (nameval == NULL)
		return (PICL_FAILURE);

	err = picl_get_propval(proph, nameval, pinfo.size);
	if (err != PICL_SUCCESS)
		return (err);

	(void) strlcpy(nodename, nameval, MAXSTRLEN);

	err = picl_get_propval_by_name(nodeh, PICL_PROP_CLASSNAME,
	    piclclass, sizeof (piclclass));
	if (err != PICL_SUCCESS)
		return (err);

	/* if binding_name is found, name will be <nodename>-<binding_name> */
	err = picl_get_propval_by_name(nodeh, PICL_PROP_BINDING_NAME,
	    binding_name, sizeof (binding_name));
	if (err == PICL_PROPNOTFOUND) {
		/*
		 * if compatible prop is found, name will be
		 * <nodename>-<compatible>
		 */
		err = picldiag_get_first_compatible_value(nodeh, &compatible);
		if (err == PICL_SUCCESS) {
			strlcat(nodename, "-", MAXSTRLEN);
			strlcat(nodename, compatible, MAXSTRLEN);
			free(compatible);
		} else if (err != PICL_PROPNOTFOUND) {
			return (err);
		}
	} else if (err != PICL_SUCCESS) {
		return (err);
	} else if (strcmp(nodename, binding_name) != 0) {
		if (strcmp(nodename, piclclass) == 0) {
			/*
			 * nodename same as binding name -
			 * no need to display twice
			 */
			strlcpy(nodename, binding_name, MAXSTRLEN);
		} else {
			strlcat(nodename, "-", MAXSTRLEN);
			strlcat(nodename, binding_name, MAXSTRLEN);
		}
	}

	/*
	 * If it is an immediate child under pci and not
	 * a bus node, add it to the io list.
	 * If it is a child under sub-bus and it is in an io
	 * device, add it to the io list.
	 */
	if (((parentname == NULL) && (!is_bus(piclclass))) ||
	    ((parentname != NULL) && (is_io_device(piclclass)))) {
		if (parentname == NULL)
			(void) snprintf(name, MAXSTRLEN, "%s", nodename);
		else
			(void) snprintf(name, MAXSTRLEN, "%s/%s", parentname,
			    nodename);

		/*
		 * append the class if its class is not a generic
		 * obp-device class
		 */
		if (strcmp(piclclass, PICL_CLASS_OBP_DEVICE))
			(void) snprintf(name, MAXSTRLEN, "%s (%s)", name,
			    piclclass);

		err = picldiag_get_fru_parent(nodeh, &fruparenth);
		if (err == PICL_PROPNOTFOUND) {
			label = NULL;
		} else if (err != PICL_SUCCESS) {
			return (err);
		} else {
			err = picldiag_get_combined_label(fruparenth, &label,
			    15);
			if (err == PICL_PROPNOTFOUND)
				label = NULL;
			else if (err != PICL_SUCCESS)
				return (err);
		}
		/* devfs-path */
		err =  picldiag_get_string_propval(nodeh, PICL_PROP_DEVFS_PATH,
		    &devfs_path);
		if (err == PICL_PROPNOTFOUND)
			devfs_path = NULL;
		else if (err != PICL_SUCCESS)
			return (err);

		add_io_card(board, bus_id, slot, label, freq, name,
		    model, status, devfs_path);
		if (label != NULL)
			free(label);
		if (devfs_path != NULL)
			free(devfs_path);
		return (PICL_SUCCESS);
	}

	/*
	 * If there is any child, Go through each child.
	 */

	err = picl_get_propval_by_name(nodeh, PICL_PROP_CHILD,
	    &childh, sizeof (picl_nodehdl_t));

	/* there is a child */
	while (err == PICL_SUCCESS) {
		if (parentname == NULL)
			(void) strlcpy(name, nodename, MAXSTRLEN);
		else
			(void) snprintf(name, MAXSTRLEN, "%s/%s", parentname,
			    nodename);

		err = add_io_leaves(childh, name, board, bus_id, slot, freq,
		    model, status);
		if (err != PICL_SUCCESS)
			return (err);
		/*
		 * get next child
		 */
		err = picl_get_propval_by_name(childh, PICL_PROP_PEER,
		    &childh, sizeof (picl_nodehdl_t));
	}

	if (err == PICL_PROPNOTFOUND)
		return (PICL_SUCCESS);
	return (err);
}


/*
 * add all io devices under pci in io list
 */
/* ARGSUSED */
static int
pci_callback(picl_nodehdl_t pcih, void *args)
{
	picl_nodehdl_t	nodeh;
	int		err;
	char		piclclass[PICL_CLASSNAMELEN_MAX];
	uint32_t	boardnum;
	uint32_t	bus_id;
	uint32_t	slot;
	uint32_t	freq;
	char		*model;
	char		*status;

	/* Fill in common infomation */
	bus_id = PCI_TYPE;

	/*
	 * Check if it has the freq, if not,
	 * If not, use its parent's freq
	 * if its parent's freq is not found, return
	 */
	err = picldiag_get_clock_freq(pcih, &freq);
	if (err == PICL_PROPNOTFOUND) {
		err = picldiag_get_clock_from_parent(pcih, &freq);
		if (err == PICL_PROPNOTFOUND)
			return (PICL_WALK_CONTINUE);
		else if (err != PICL_SUCCESS)
			return (err);
	} else if (err != PICL_SUCCESS)
		return (err);

	/*
	 * If no board# is found, set boardnum to 0
	 */
	boardnum = picldiag_get_uint_propval(pcih, OBP_PROP_BOARD_NUM, &err);
	if (err == PICL_PROPNOTFOUND)
		boardnum = DEFAULT_BOARD_NUM;
	else if (err != PICL_SUCCESS)
		return (err);

	/* Walk through the children */

	err = picl_get_propval_by_name(pcih, PICL_PROP_CHILD, &nodeh,
	    sizeof (picl_nodehdl_t));
	while (err == PICL_SUCCESS) {
		err = picl_get_propval_by_name(nodeh, PICL_PROP_CLASSNAME,
		    piclclass, sizeof (piclclass));
		if (err != PICL_SUCCESS)
			return (err);

		/*
		 * Skip PCI bridge and USB devices because they will be
		 * processed later
		 */
		if ((strcmp(piclclass, PICL_CLASS_PCI) == 0) ||
		    (strcmp(piclclass, PICL_CLASS_USB) == 0)) {
			err = picl_get_propval_by_name(nodeh, PICL_PROP_PEER,
			    &nodeh, sizeof (picl_nodehdl_t));
			continue;
		}

		/* Get the device id for pci card */
		slot = picldiag_get_uint_propval(nodeh,
		    PICL_PROP_DEVICE_ID, &err);
		if (err == PICL_PROPNOTFOUND) {
			err = picl_get_propval_by_name(nodeh, PICL_PROP_PEER,
			    &nodeh, sizeof (picl_nodehdl_t));
			continue;
		} else if (err != PICL_SUCCESS)
			return (err);

		/* Get the model of this card */
		err = picldiag_get_string_propval(nodeh, OBP_PROP_MODEL,
		    &model);
		if (err == PICL_PROPNOTFOUND)
			model = NULL;
		else if (err != PICL_SUCCESS)
			return (err);

		err = picldiag_get_string_propval(nodeh, PICL_PROP_STATUS,
		    &status);
		if (err == PICL_PROPNOTFOUND) {
			status = malloc(5);
			if (status == NULL)
				return (PICL_FAILURE);
			strlcpy(status, "okay", 5);
		} else if (err != PICL_SUCCESS)
			return (err);

		err = add_io_leaves(nodeh, NULL, boardnum, bus_id, slot,
		    freq, model, status);

		if (model != NULL)
			free(model);

		if (status != NULL)
			free(status);

		if (err != PICL_SUCCESS)
			return (err);

		err = picl_get_propval_by_name(nodeh, PICL_PROP_PEER, &nodeh,
		    sizeof (picl_nodehdl_t));

	}

	if (err == PICL_PROPNOTFOUND)
		return (PICL_WALK_CONTINUE);

	return (err);
}


/*
 * loop through all children and add io devices in io list
 */
static int
process_io_leaves(picl_nodehdl_t rooth)
{
	picl_nodehdl_t	nodeh;
	char		classval[PICL_CLASSNAMELEN_MAX];
	int		err;

	err = picl_get_propval_by_name(rooth, PICL_PROP_CHILD, &nodeh,
	    sizeof (picl_nodehdl_t));
	while (err == PICL_SUCCESS) {
		err = picl_get_propval_by_name(nodeh, PICL_PROP_CLASSNAME,
		    classval, sizeof (classval));
		if (err != PICL_SUCCESS)
			return (err);

		if (err != PICL_SUCCESS)
			return (err);

		err = picl_get_propval_by_name(nodeh, PICL_PROP_PEER, &nodeh,
		    sizeof (picl_nodehdl_t));
	}

	if (err == PICL_PROPNOTFOUND)
		return (PICL_SUCCESS);

	return (err);
}


/*
 * find all io devices and add them in the io list
 */
static int
gather_io_cards(picl_nodehdl_t plafh)
{
	int		err;

	/*
	 * look for io devices under the immediate children of platform
	 */
	err = process_io_leaves(plafh);

	if (err != PICL_SUCCESS)
		return (err);

	if (err != PICL_SUCCESS)
		return (err);
	err = picl_walk_tree_by_class(plafh, PICL_CLASS_PCI,
	    PICL_CLASS_PCI, pci_callback);
	if (err != PICL_SUCCESS)
		return (err);
	return (err);
}

static void
picldiag_display_io_cards(struct io_card *list)
{
	static int banner = 0; /* Have we printed the column headings? */
	struct io_card *p;

	if (list == NULL)
		return;

	if (banner == 0) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "Bus   Freq      Slot +  Name +\n"), 0);
		log_printf(dgettext(TEXT_DOMAIN, "Type  MHz       Status  "
			"Path                          "
			"Model"), 0);
		log_printf("\n", 0);
		log_printf("----  ----  ----------  "
			"----------------------------  "
			"--------------------", 0);
		log_printf("\n", 0);
		banner = 1;
	}

	for (p = list; p != NULL; p = p -> next) {
		log_printf("%-4s  ", p->bus_type, 0);
		log_printf("%3d   ", p->freq, 0);
		/*
		 * We check to see if it's an int or
		 * a char string to display for slot.
		 */
		if (p->slot == PCI_SLOT_IS_STRING)
			log_printf("%10s  ", p->slot_str, 0);
		else
			log_printf("%10d  ", p->slot, 0);

		log_printf("%-28.28s", p->name, 0);
		if (strlen(p->name) > 28)
			log_printf("+ ", 0);
		else
			log_printf("  ", 0);
		log_printf("%-19.19s", p->model, 0);
		if (strlen(p->model) > 19)
			log_printf("+", 0);
		log_printf("\n", 0);
		log_printf("            %10s  ", p->status, 0);
		if (strlen(p->notes) > 0)
			log_printf("%s", p->notes, 0);
		log_printf("\n\n", 0);
	}
}

/*
 * display all io devices
 */
static int
display_io_device_info(picl_nodehdl_t plafh)
{
	int	err;

	err = gather_io_cards(plafh);
	if (err != PICL_SUCCESS)
		return (err);

	logprintf_header(dgettext(TEXT_DOMAIN, "IO Devices"),
	    DEFAULT_LINE_WIDTH);

	picldiag_display_io_cards(io_card_list);

	free_io_cards(io_card_list);

	return (PICL_SUCCESS);
}

/*
 * print fan device information
 */
static int
logprintf_fan_info(picl_nodehdl_t fanh)
{
	int		err;
	char		*label;
	char		*unit;
	int64_t		speed;
	int64_t		min_speed;
	picl_nodehdl_t	fruph;

	err = picldiag_get_fru_parent(fanh, &fruph);
	if (err != PICL_SUCCESS)
		return (err);

	err = picldiag_get_combined_label(fruph, &label, 14);
	if (err != PICL_SUCCESS)
		return (err);

	log_printf("%-14s ", label);
	free(label);

	err = picldiag_get_label(fanh, &label);
	if (err == PICL_SUCCESS) {
		log_printf("%-14s  ", label);
		free(label);
	} else if (err == PICL_PROPNOTFOUND || err == PICL_PROPVALUNAVAILABLE) {
		log_printf("  -           ");
	} else
		return (err);

	speed = picldiag_get_uint_propval(fanh, PICL_PROP_FAN_SPEED, &err);
	if (err == PICL_SUCCESS) {
		min_speed = picldiag_get_uint_propval(fanh,
		    PICL_PROP_LOW_WARNING_THRESHOLD, &err);
		if (err != PICL_SUCCESS)
			min_speed = 0;
		if (speed < min_speed) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "failed (%lld"), speed);
			err = picldiag_get_string_propval(fanh,
			    PICL_PROP_FAN_SPEED_UNIT, &unit);
			if (err == PICL_SUCCESS) {
				log_printf("%s", unit);
				free(unit);
			}
			log_printf(")");
		} else {
			log_printf(dgettext(TEXT_DOMAIN, "okay"));
		}
	} else {
		err = picldiag_get_string_propval(fanh,
		    PICL_PROP_FAN_SPEED_UNIT, &unit);
		if (err == PICL_SUCCESS) {
			log_printf("%-12s ", unit);
			free(unit);
		}
	}

	log_printf("\n");
	return (PICL_SUCCESS);
}

static int
fan_callback(picl_nodehdl_t fanh, void *arg)
{
	int	*countp = arg;
	int		err;

	if (*countp == 0) {
		log_printf(dgettext(TEXT_DOMAIN, "Fan Status:\n"));
		log_printf("---------------------------------------\n");
		log_printf(dgettext(TEXT_DOMAIN,
		    "Location       Sensor          Status          \n"));
		log_printf("---------------------------------------\n");
	}
	*countp += 1;
	err = logprintf_fan_info(fanh);
	if (err == PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);
	return (err);
}

/*
 * callback function search children to find fan device and print its speed
 */
static int
display_fan_speed(picl_nodehdl_t plafh)
{
	int		err;
	int		print_header;

	print_header = 0;
	err = picl_walk_tree_by_class(plafh, PICL_CLASS_FAN,
	    &print_header, fan_callback);
	return (err);
}

/*
 * print temperature sensor information
 */
static int
logprintf_temp_info(picl_nodehdl_t temph)
{
	int		err;
	char		*label;
	int64_t		temperature;
	int64_t		threshold;
	picl_nodehdl_t	fruph;
	char		*status = "unknown";
	int		got_temp = 0;

	err = picldiag_get_fru_parent(temph, &fruph);
	if (err != PICL_SUCCESS)
		return (err);

	err = picldiag_get_combined_label(fruph, &label, 14);
	if (err != PICL_SUCCESS)
		return (err);

	log_printf("%-14s ", label);
	free(label);

	err = picldiag_get_label(temph, &label);
	if (err != PICL_SUCCESS)
		return (err);
	log_printf("%-14s ", label);
	free(label);

	temperature = picldiag_get_int_propval(temph, PICL_PROP_TEMPERATURE,
	    &err);
	if (err == PICL_SUCCESS) {
		got_temp = 1;
		status = "okay";
	} else if (err != PICL_PROPNOTFOUND && err != PICL_PROPVALUNAVAILABLE) {
		return (err);
	}

	threshold = picldiag_get_int_propval(temph, PICL_PROP_LOW_WARNING,
	    &err);
	if (err == PICL_SUCCESS) {
		if (got_temp && temperature < threshold)
			status = "warning";
	} else if (err != PICL_PROPNOTFOUND && err != PICL_PROPVALUNAVAILABLE) {
		return (err);
	}

	threshold = picldiag_get_int_propval(temph, PICL_PROP_LOW_SHUTDOWN,
	    &err);
	if (err == PICL_SUCCESS) {
		if (got_temp && temperature < threshold)
			status = "failed";
	} else if (err != PICL_PROPNOTFOUND && err != PICL_PROPVALUNAVAILABLE) {
		return (err);
	}

	threshold = picldiag_get_int_propval(temph, PICL_PROP_HIGH_WARNING,
	    &err);
	if (err == PICL_SUCCESS) {
		if (got_temp && temperature > threshold)
			status = "warning";
	} else if (err != PICL_PROPNOTFOUND && err != PICL_PROPVALUNAVAILABLE) {
		return (err);
	}

	threshold = picldiag_get_int_propval(temph, PICL_PROP_HIGH_SHUTDOWN,
	    &err);
	if (err == PICL_SUCCESS) {
		if (got_temp && temperature > threshold)
			status = "failed";
	} else if (err != PICL_PROPNOTFOUND && err != PICL_PROPVALUNAVAILABLE) {
		return (err);
	}

	err = picldiag_get_string_propval(temph, PICL_PROP_CONDITION, &status);
	if (err == PICL_SUCCESS) {
		log_printf("%s", status);
		free(status);
	} else if (err != PICL_PROPNOTFOUND && err != PICL_PROPVALUNAVAILABLE) {
		return (err);
	} else {
		log_printf("%s ", status);
		if (strcmp(status, "failed") == 0 ||
		    strcmp(status, "warning") == 0)
			log_printf("(%.2lldC)", temperature);
	}

	log_printf("\n");
	return (PICL_SUCCESS);
}

static int
temp_callback(picl_nodehdl_t temph, void *arg)
{
	int		err;
	int	*countp = arg;

	if (*countp == 0) {
		log_printf("\n");
		log_printf("---------------------------------------\n");
		log_printf(dgettext(TEXT_DOMAIN, "Temperature sensors:\n"));
		log_printf("------------------------------------\n");
		log_printf(dgettext(TEXT_DOMAIN,
		    "Location       Sensor         Status\n"));
		log_printf("------------------------------------\n");
	}
	*countp += 1;
	err = logprintf_temp_info(temph);
	if (err == PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);
	return (err);
}

/*
 * callback function search children to find temp sensors and print the temp
 */
/* ARGSUSED */
static int
display_temp(picl_nodehdl_t plafh)
{
	int		err;
	int		print_header;

	print_header = 0;
	err = picl_walk_tree_by_class(plafh, PICL_CLASS_TEMPERATURE_SENSOR,
	    &print_header, temp_callback);
	if (err != PICL_SUCCESS)
		return (err);
	err = picl_walk_tree_by_class(plafh, PICL_CLASS_TEMPERATURE_INDICATOR,
	    &print_header, temp_callback);
	return (err);
}

/*
 * print current sensor information
 */
static int
logprintf_current_info(picl_nodehdl_t currenth)
{
	int		err;
	char		*label;
	float		current;
	float		threshold;
	picl_nodehdl_t	fruph;
	char		*status = "unknown";
	int		got_current = 0;

	err = picldiag_get_fru_parent(currenth, &fruph);
	if (err != PICL_SUCCESS)
		return (err);

	err = picldiag_get_combined_label(fruph, &label, 10);
	if (err != PICL_SUCCESS)
		return (err);

	log_printf("%-10s ", label);
	free(label);

	err = picldiag_get_label(currenth, &label);
	if (err != PICL_SUCCESS)
		return (err);
	log_printf("%-10s  ", label);
	free(label);

	current = picldiag_get_float_propval(currenth, PICL_PROP_CURRENT, &err);
	if (err == PICL_SUCCESS) {
		status = "okay";
		got_current = 1;
	} else if (err != PICL_PROPNOTFOUND && err != PICL_PROPVALUNAVAILABLE) {
		return (err);
	}

	threshold = picldiag_get_float_propval(currenth, PICL_PROP_LOW_WARNING,
	    &err);
	if (err == PICL_SUCCESS) {
		if (got_current && current < threshold)
			status = "warning";
	} else if (err != PICL_PROPNOTFOUND && err != PICL_PROPVALUNAVAILABLE) {
		return (err);
	}

	threshold = picldiag_get_float_propval(currenth, PICL_PROP_LOW_SHUTDOWN,
	    &err);
	if (err == PICL_SUCCESS) {
		if (got_current && current < threshold)
			status = "failed";
	} else if (err != PICL_PROPNOTFOUND && err != PICL_PROPVALUNAVAILABLE) {
		return (err);
	}

	threshold = picldiag_get_float_propval(currenth, PICL_PROP_HIGH_WARNING,
	    &err);
	if (err == PICL_SUCCESS) {
		if (got_current && current > threshold)
			status = "warning";
	} else if (err != PICL_PROPNOTFOUND && err != PICL_PROPVALUNAVAILABLE) {
		return (err);
	}

	threshold = picldiag_get_float_propval(currenth,
	    PICL_PROP_HIGH_SHUTDOWN, &err);
	if (err == PICL_SUCCESS) {
		if (got_current && current > threshold)
			status = "failed";
	} else if (err != PICL_PROPNOTFOUND && err != PICL_PROPVALUNAVAILABLE) {
		return (err);
	}

	err = picldiag_get_string_propval(currenth,
	    PICL_PROP_CONDITION, &status);
	if (err == PICL_SUCCESS) {
		log_printf(" %s", status);
		free(status);
	} else if (err != PICL_PROPNOTFOUND && err != PICL_PROPVALUNAVAILABLE) {
		return (err);
	} else {
		log_printf("%s ", status);
		if (strcmp(status, "failed") == 0 ||
		    strcmp(status, "warning") == 0)
			log_printf("(%.2fA)", current);
	}

	log_printf("\n");
	return (PICL_SUCCESS);
}

static int
current_callback(picl_nodehdl_t currh, void *arg)
{
	int		err;
	int	*countp = arg;

	if (*countp == 0) {
		log_printf("------------------------------------\n");
		log_printf(dgettext(TEXT_DOMAIN, "Current sensors:\n"));
		log_printf("------------------------------\n");
		log_printf(dgettext(TEXT_DOMAIN,
		    "Location  Sensor        Status\n"));
		log_printf("------------------------------\n");
	}
	*countp += 1;
	err = logprintf_current_info(currh);
	if (err == PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);
	return (err);
}

/*
 * callback function search children to find curr sensors and print the curr
 */
/* ARGSUSED */
static int
display_current(picl_nodehdl_t plafh)
{
	int		err;
	int		print_header;

	print_header = 0;
	err = picl_walk_tree_by_class(plafh, PICL_CLASS_CURRENT_SENSOR,
	    &print_header, current_callback);
	if (err != PICL_SUCCESS)
		return (err);
	err = picl_walk_tree_by_class(plafh, PICL_CLASS_CURRENT_INDICATOR,
	    &print_header, current_callback);
	return (err);
}

/*
 * print voltage sensor information
 */
static int
logprintf_voltage_info(picl_nodehdl_t voltageh)
{
	int		err;
	char		*label;
	float		voltage;
	float		threshold;
	picl_nodehdl_t	fruph;
	char		*status = "unknown";
	int		got_voltage = 0;

	err = picldiag_get_fru_parent(voltageh, &fruph);
	if (err != PICL_SUCCESS)
		return (err);

	err = picldiag_get_combined_label(fruph, &label, 10);
	if (err != PICL_SUCCESS)
		return (err);

	log_printf("%-10s ", label);
	free(label);

	err = picldiag_get_label(voltageh, &label);
	if (err != PICL_SUCCESS)
		return (err);
	log_printf("%-12s  ", label);
	free(label);

	voltage = picldiag_get_float_propval(voltageh, PICL_PROP_VOLTAGE, &err);
	if (err == PICL_SUCCESS) {
		status = "okay";
		got_voltage = 1;
	} else if (err != PICL_PROPNOTFOUND && err != PICL_PROPVALUNAVAILABLE) {
		return (err);
	}

	threshold = picldiag_get_float_propval(voltageh, PICL_PROP_LOW_WARNING,
	    &err);
	if (err == PICL_SUCCESS) {
		if (got_voltage && voltage < threshold)
			status = "warning";
	} else if (err != PICL_PROPNOTFOUND && err != PICL_PROPVALUNAVAILABLE) {
		return (err);
	}

	threshold = picldiag_get_float_propval(voltageh, PICL_PROP_LOW_SHUTDOWN,
	    &err);
	if (err == PICL_SUCCESS) {
		if (got_voltage && voltage < threshold)
			status = "failed";
	} else if (err != PICL_PROPNOTFOUND && err != PICL_PROPVALUNAVAILABLE) {
		return (err);
	}

	threshold = picldiag_get_float_propval(voltageh, PICL_PROP_HIGH_WARNING,
	    &err);
	if (err == PICL_SUCCESS) {
		if (got_voltage && voltage > threshold)
			status = "warning";
	} else if (err != PICL_PROPNOTFOUND && err != PICL_PROPVALUNAVAILABLE) {
		return (err);
	}

	threshold = picldiag_get_float_propval(voltageh,
	    PICL_PROP_HIGH_SHUTDOWN, &err);
	if (err == PICL_SUCCESS) {
		if (got_voltage && voltage > threshold)
			status = "failed";
	} else if (err != PICL_PROPNOTFOUND && err != PICL_PROPVALUNAVAILABLE) {
		return (err);
	}

	err = picldiag_get_string_propval(voltageh,
	    PICL_PROP_CONDITION, &status);
	if (err == PICL_SUCCESS) {
		log_printf("%s", status);
		free(status);
	} else if (err != PICL_PROPNOTFOUND && err != PICL_PROPVALUNAVAILABLE) {
		return (err);
	} else {
		log_printf("%s ", status);
		if (strcmp(status, "warning") == 0 ||
		    strcmp(status, "failed") == 0)
			log_printf("(%.2fV)", voltage);
	}

	log_printf("\n");
	return (PICL_SUCCESS);
}

static int
voltage_callback(picl_nodehdl_t voltageh, void *arg)
{
	int	*countp = arg;
	int		err;

	if (*countp == 0) {
		log_printf("--------------------------------\n");
		log_printf(dgettext(TEXT_DOMAIN, "Voltage sensors:\n"));
		log_printf("-------------------------------\n");
		log_printf(dgettext(TEXT_DOMAIN,
		    "Location   Sensor        Status\n"));
		log_printf("-------------------------------\n");
	}
	*countp += 1;
	err = logprintf_voltage_info(voltageh);
	if (err == PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);
	return (err);
}

/*
 * callback function search children to find voltage sensors and print voltage
 */
/* ARGSUSED */
static int
display_voltage(picl_nodehdl_t plafh)
{
	int		err;
	int		print_header;

	print_header = 0;
	err = picl_walk_tree_by_class(plafh, PICL_CLASS_VOLTAGE_SENSOR,
	    &print_header, voltage_callback);
	if (err != PICL_SUCCESS)
		return (err);
	err = picl_walk_tree_by_class(plafh, PICL_CLASS_VOLTAGE_INDICATOR,
	    &print_header, voltage_callback);
	return (err);
}

/*
 * print led device information
 */
static int
logprintf_led_info(picl_nodehdl_t ledh)
{
	int		err;
	char		*label;
	char		*state;
	char		*color;
	picl_nodehdl_t  fruph;

	err = picldiag_get_fru_parent(ledh, &fruph);
	if (err != PICL_SUCCESS)
		return (err);

	err = picldiag_get_combined_label(fruph, &label, 10);
	if (err != PICL_SUCCESS) {
		log_printf("      -    ", label);
	} else {
		log_printf("%-10s ", label);
		free(label);
	}

	err = picldiag_get_label(ledh, &label);
	if (err != PICL_SUCCESS)
		return (err);
	log_printf("%-20s  ", label);
	free(label);

	err = picldiag_get_string_propval(ledh, PICL_PROP_STATE, &state);
	if (err == PICL_PROPNOTFOUND || err == PICL_PROPVALUNAVAILABLE) {
		log_printf("     -     ");
	} else if (err != PICL_SUCCESS) {
		return (err);
	} else {
		log_printf("%-10s  ", state);
		free(state);
	}

	err = picldiag_get_string_propval(ledh, PICL_PROP_COLOR, &color);
	if (err == PICL_PROPNOTFOUND || err == PICL_PROPVALUNAVAILABLE) {
		log_printf("\n");
	} else if (err != PICL_SUCCESS) {
		return (err);
	} else {
		log_printf("%-16s\n", color);
		free(color);
	}

	return (PICL_SUCCESS);
}

static int
led_callback(picl_nodehdl_t ledh, void *arg)
{
	int		*countp = arg;
	int		err;

	if (*countp == 0) {

		log_printf("--------------------------------------"
		    "------------\n");
		log_printf(dgettext(TEXT_DOMAIN, "Led State:\n"));
		log_printf("--------------------------------------"
		    "------------\n");
		log_printf(dgettext(TEXT_DOMAIN,
		    "Location   Led                   State"
		    "       Color\n"));
		log_printf("--------------------------------------"
		    "------------\n");
	}
	*countp += 1;
	err = logprintf_led_info(ledh);
	if (err == PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);
	return (err);
}

/*
 * callback function search children to find led devices and print status
 */
/* ARGSUSED */
static int
display_led_status(picl_nodehdl_t plafh)
{
	int		print_header;

	print_header = 0;
	picl_walk_tree_by_class(plafh, PICL_CLASS_LED,
	    &print_header, led_callback);
	return (PICL_SUCCESS);
}

/*
 * print keyswitch device information
 */
static int
logprintf_keyswitch_info(picl_nodehdl_t keyswitchh, picl_nodehdl_t fruph)
{
	int		err;
	char		*label;
	char		*state;

	err = picldiag_get_combined_label(fruph, &label, 10);
	if (err != PICL_SUCCESS) {
		log_printf("%-14s", "     -");
	} else {
		log_printf("%-14s ", label);
		free(label);
	}

	err = picldiag_get_label(keyswitchh, &label);
	if (err != PICL_SUCCESS)
		return (err);
	log_printf("%-11s ", label);
	free(label);

	err = picldiag_get_string_propval(keyswitchh, PICL_PROP_STATE, &state);
	if (err == PICL_PROPNOTFOUND || err == PICL_PROPVALUNAVAILABLE) {
		log_printf("     -\n");
	} else if (err != PICL_SUCCESS) {
		return (err);
	} else {
		log_printf("%s\n", state);
		free(state);
	}

	return (PICL_SUCCESS);
}

static int
keyswitch_callback(picl_nodehdl_t keyswitchh, void *arg)
{
	int		*countp = arg;
	int		err;
	picl_nodehdl_t	fruph;

	/*
	 * Tamale simulates a key-switch on ENxS. So the presence of a
	 * node of class keyswitch is not sufficient. If it has a fru parent
	 * or location parent, then believe it.
	 */
	err = picl_get_propval_by_name(keyswitchh, PICL_REFPROP_FRU_PARENT,
	    &fruph, sizeof (fruph));
	if (err == PICL_PROPNOTFOUND) {
		err = picl_get_propval_by_name(keyswitchh,
		    PICL_REFPROP_LOC_PARENT, &fruph, sizeof (fruph));
	}
	if (err == PICL_PROPNOTFOUND || err == PICL_PROPVALUNAVAILABLE)
		return (PICL_WALK_CONTINUE);
	if (err != PICL_SUCCESS)
		return (err);

	if (*countp == 0) {
		log_printf("-----------------------------------------\n");
		log_printf(dgettext(TEXT_DOMAIN, "Keyswitch:\n"));
		log_printf("-----------------------------------------\n");
		log_printf(dgettext(TEXT_DOMAIN,
		    "Location       Keyswitch   State\n"));
		log_printf("-----------------------------------------\n");
	}
	*countp += 1;
	err = logprintf_keyswitch_info(keyswitchh, fruph);
	if (err == PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);
	return (err);
}

/*
 * search children to find keyswitch device(s) and print status
 */
/* ARGSUSED */
static int
display_keyswitch(picl_nodehdl_t plafh)
{
	int		print_header = 0;

	picl_walk_tree_by_class(plafh, PICL_CLASS_KEYSWITCH,
	    &print_header, keyswitch_callback);
	return (PICL_SUCCESS);
}

/*
 * display environment status
 */
static int
display_envctrl_status(picl_nodehdl_t plafh)
{
	logprintf_header(dgettext(TEXT_DOMAIN, "Environmental Status"),
	    DEFAULT_LINE_WIDTH);

	display_fan_speed(plafh);
	display_temp(plafh);
	display_current(plafh);
	display_voltage(plafh);
	display_keyswitch(plafh);
	display_led_status(plafh);

	return (PICL_SUCCESS);
}

/*
 * print fru operational status
 */
static int
logprintf_fru_oper_status(picl_nodehdl_t fruh, int *countp)
{
	int		err;
	char		*label;
	char		*status;

	err = picldiag_get_combined_label(fruh, &label, 15);
	if (err != PICL_SUCCESS)
		return (PICL_WALK_CONTINUE);

	err = picldiag_get_string_propval(fruh,
	    PICL_PROP_OPERATIONAL_STATUS, &status);
	if (err == PICL_SUCCESS) {
		if (*countp == 0) {
			logprintf_header(dgettext(TEXT_DOMAIN,
			    "FRU Operational Status"),
			    DEFAULT_LINE_WIDTH);
			log_printf("-------------------------\n");
			log_printf(dgettext(TEXT_DOMAIN,
			    "Fru Operational Status:\n"));
			log_printf("-------------------------\n");
			log_printf(dgettext(TEXT_DOMAIN,
			    "Location        Status   \n"));
			log_printf("-------------------------\n");
		}
		*countp += 1;
		log_printf("%-15s ", label);
		free(label);
		log_printf("%s\n", status);
		free(status);
	} else if (err != PICL_PROPNOTFOUND && err != PICL_PROPVALUNAVAILABLE) {
		free(label);
		return (err);
	} else {
		free(label);
	}
	return (PICL_WALK_CONTINUE);
}

static int
fru_oper_status_callback(picl_nodehdl_t fruh, void *arg)
{
	int err;

	err = logprintf_fru_oper_status(fruh, (int *)arg);
	return (err);
}

/*
 * display fru operational status
 */
static int
display_fru_oper_status(picl_nodehdl_t frutreeh)
{
	int		print_header;

	print_header = 0;
	picl_walk_tree_by_class(frutreeh, PICL_CLASS_FRU,
	    &print_header, fru_oper_status_callback);
	return (PICL_SUCCESS);
}

/*
 * check if the node having the version prop
 * If yes, print its nodename and version
 */
/* ARGSUSED */
static int
asicrev_callback(picl_nodehdl_t nodeh, void *arg)
{
	uint32_t	version;
	char		*name;
	char		*model;
	char		*status;
	int		err;

	version = picldiag_get_uint_propval(nodeh, OBP_PROP_VERSION_NUM,
	    &err);
	if (err == PICL_PROPNOTFOUND)
		return (PICL_WALK_CONTINUE);
	else if (err != PICL_SUCCESS)
		return (err);

	/* devfs-path */
	err =  picldiag_get_string_propval(nodeh, PICL_PROP_DEVFS_PATH, &name);
	if (err == PICL_PROPNOTFOUND)
		name = NULL;
	else if (err != PICL_SUCCESS)
		return (err);

	/* model */
	err =  picldiag_get_string_propval(nodeh, PICL_PROP_BINDING_NAME,
	    &model);
	if (err == PICL_PROPNOTFOUND)
		model = NULL;
	else if (err != PICL_SUCCESS)
		return (err);

	/* status */
	err = picldiag_get_string_propval(nodeh, PICL_PROP_STATUS, &status);
	if (err == PICL_PROPNOTFOUND)
		status = NULL;
	else if (err != PICL_SUCCESS)
		return (err);

	/*
	 * Display the data
	 */

	/* name */
	if (name != NULL) {
		log_printf("%-22s ", name);
		free(name);
	} else
		log_printf("%-22s ", "unknown");
	/* model */
	if (model != NULL) {
		log_printf("%-15s  ", model);
		free(model);
	} else
		log_printf("%-15s  ", "unknown");
	/* status */
	if (status == NULL)
		log_printf("%-15s  ", "okay");
	else {
		log_printf("%-15s  ", status);
		free(status);
	}
	/* revision */
	log_printf("  %-4d\n",	version);

	return (PICL_WALK_CONTINUE);
}

/*
 * traverse the tree to display asic revision id for ebus
 */
/* ARGSUSED */
static int
ebus_callback(picl_nodehdl_t ebush, void *arg)
{
	uint32_t	id;
	char		*name;
	int		err;
	char		*model;
	char		*status;

	id = picldiag_get_uint_propval(ebush, OBP_PROP_REVISION_ID, &err);
	if (err == PICL_PROPNOTFOUND)
		return (PICL_WALK_CONTINUE);
	else if (err != PICL_SUCCESS)
		return (err);

	/* devfs-path */
	err =  picldiag_get_string_propval(ebush, PICL_PROP_DEVFS_PATH, &name);
	if (err == PICL_PROPNOTFOUND)
		name = NULL;
	else if (err != PICL_SUCCESS)
		return (err);

	/* model */
	err =  picldiag_get_string_propval(ebush, PICL_PROP_BINDING_NAME,
	    &model);
	if (err == PICL_PROPNOTFOUND)
		model = NULL;
	else if (err != PICL_SUCCESS)
		return (err);

	/* status */
	err = picldiag_get_string_propval(ebush, PICL_PROP_STATUS, &status);
	if (err == PICL_PROPNOTFOUND)
		status = NULL;
	else if (err != PICL_SUCCESS)
		return (err);

	/*
	 * Display the data
	 */

	/* name */
	if (name != NULL) {
		log_printf("%-22s ", name);
		free(name);
	} else
		log_printf("%-22s ", "unknown");
	/* model */
	if (model != NULL) {
		log_printf("%-15s  ", model);
		free(model);
	} else
		log_printf("%-15s  ", "unknown");
	/* status */
	if (status == NULL)
		log_printf("%-15s  ", "okay");
	else {
		log_printf("%-15s  ", status);
		free(status);
	}
	/* revision */
	log_printf("  %-4d\n",	id);

	return (PICL_WALK_CONTINUE);
}

/*
 * display asic revision id
 */
static int
display_hw_revisions(picl_nodehdl_t plafh)
{
	int	err;

	/* Print the header */
	logprintf_header(dgettext(TEXT_DOMAIN, "HW Revisions"),
	    DEFAULT_LINE_WIDTH);

	log_printf(dgettext(TEXT_DOMAIN, "ASIC Revisions:\n"));
	log_printf("-----------------------------");
	log_printf("--------------------------------------\n");
	log_printf(dgettext(TEXT_DOMAIN, "Path                   Device"));
	log_printf(dgettext(TEXT_DOMAIN,
	    "           Status             Revision\n"));
	log_printf("-----------------------------");
	log_printf("--------------------------------------\n");

	err = picl_walk_tree_by_class(plafh, NULL, NULL, asicrev_callback);
	if (err != PICL_SUCCESS)
		return (err);

	err = picl_walk_tree_by_class(plafh, PICL_CLASS_EBUS,
	    NULL, ebus_callback);
	if (err != PICL_SUCCESS)
		return (err);

	log_printf("\n");

	return (err);
}

/*
 * find the options node and its powerfail_time prop
 * If found, display the list of latest powerfail.
 */
/* ARGSUSED */
static int
options_callback(picl_nodehdl_t nodeh, void *arg)
{
	time_t		value;
	char		*failtime;
	int		err;

	err = picldiag_get_string_propval(nodeh, PROP_POWERFAIL_TIME,
	    &failtime);
	if (err == PICL_PROPNOTFOUND)
		return (PICL_WALK_TERMINATE);
	else if (err != PICL_SUCCESS)
		return (err);

	value = (time_t)atoi(failtime);
	free(failtime);
	if (value == 0)
		return (PICL_WALK_TERMINATE);

	log_printf(dgettext(TEXT_DOMAIN, "Most recent AC Power Failure:\n"));
	log_printf("=============================\n");
	log_printf("%s", ctime(&value));
	log_printf("\n");
	return (PICL_WALK_TERMINATE);
}

/*
 * display the OBP and POST prom revisions
 */
/* ARGSUSED */
static int
flashprom_callback(picl_nodehdl_t flashpromh, void *arg)
{
	picl_prophdl_t	proph;
	picl_prophdl_t	tblh;
	picl_prophdl_t	rowproph;
	picl_propinfo_t	pinfo;
	char		*prom_version = NULL;
	char		*obp_version = NULL;
	int		err;

	err = picl_get_propinfo_by_name(flashpromh, OBP_PROP_VERSION,
	    &pinfo, &proph);
	if (err == PICL_PROPNOTFOUND)
		return (PICL_WALK_TERMINATE);
	else if (err != PICL_SUCCESS)
		return (err);

	log_printf(dgettext(TEXT_DOMAIN, "System PROM revisions:\n"));
	log_printf("----------------------\n");

	/*
	 * If it's a table prop, the first element is OBP revision
	 * The second one is POST revision.
	 * If it's a charstring prop, the value will be only OBP revision
	 */
	if (pinfo.type == PICL_PTYPE_CHARSTRING) {
		prom_version = alloca(pinfo.size);
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

		prom_version = alloca(pinfo.size);
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

			obp_version = alloca(pinfo.size);
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

static int
display_system_info(int serrlog, int log_flag, picl_nodehdl_t rooth)
{
	int		err;
	picl_nodehdl_t plafh;
	picl_nodehdl_t frutreeh;

	err = picldiag_get_node_by_name(rooth, PICL_NODE_PLATFORM, &plafh);
	if (err != PICL_SUCCESS)
		return (err);

	if (!log_flag) {
		err = display_platform_banner(plafh);
		if (err != PICL_SUCCESS)
			return (err);

		err = display_system_clock(plafh);
		if (err != PICL_SUCCESS)
			return (err);

		err = picl_walk_tree_by_class(plafh, PICL_CLASS_MEMORY,
		    PICL_CLASS_MEMORY, memory_callback);
		if (err != PICL_SUCCESS)
			return (err);

		err = display_cpu_info(plafh);
		if (err != PICL_SUCCESS)
			return (err);

		err = display_io_device_info(plafh);
		if (err != PICL_SUCCESS)
			return (err);

		err = display_memory_config(plafh);
		if (err != PICL_SUCCESS)
			return (err);

		err = display_usb_devices(plafh);
		if (err != PICL_SUCCESS)
			return (err);
	}

	if (serrlog) {
		err = picl_walk_tree_by_class(rooth, PICL_CLASS_OPTIONS,
		    NULL, options_callback);
		if (err != PICL_SUCCESS)
			return (err);

		err = picldiag_get_node_by_name(rooth, PICL_NODE_FRUTREE,
		    &frutreeh);

		/* return ok if no frutree in picl on schumacher */
		if (err != PICL_SUCCESS)
			return	(PICL_SUCCESS);

		err = display_fru_oper_status(frutreeh);
		if (err != PICL_SUCCESS)
			return (err);

		err = display_hw_revisions(plafh);
		if (err != PICL_SUCCESS)
			return (err);

		err = picl_walk_tree_by_class(plafh, PICL_CLASS_FLASHPROM,
		    NULL, flashprom_callback);
		if (err != PICL_SUCCESS)
			return (err);
	}

	return (PICL_SUCCESS);
}

/* ARGSUSED */
int
do_prominfo(int serrlog, char *pgname, int log_flag, int prt_flag)
{
	int		err;
	char		*errstr;
	int		done;
	picl_nodehdl_t	rooth;

	err = picl_initialize();
	if (err != PICL_SUCCESS) {
		fprintf(stderr, EM_INIT_FAIL, picl_strerror(err));
		exit(1);
	}

	do {
		done = 1;
		err = picl_get_root(&rooth);
		if (err != PICL_SUCCESS) {
			fprintf(stderr, EM_GET_ROOT_FAIL, picl_strerror(err));
			exit(1);
		}

		err = display_system_info(serrlog, log_flag, rooth);

		if ((err == PICL_STALEHANDLE) || (err == PICL_INVALIDHANDLE))
			done = 0;
	} while (!done);

	if (err != PICL_SUCCESS) {
		errstr = picl_strerror(err);
		fprintf(stderr, EM_PRTDIAG_FAIL);
		fprintf(stderr, "%s\n", errstr? errstr : " ");
	}

	(void) picl_shutdown();

	return (0);
}
