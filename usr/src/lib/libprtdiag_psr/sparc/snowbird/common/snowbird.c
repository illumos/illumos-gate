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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * This program prints the diagnostics of Sanibel system. It
 * also prints other miscellaneous information about watchdog, temperature
 * of CPU sensor, firmware versions of SMC and, micro controller role
 * etc. The basic sources of output is PICL, and  SMC.
 */

/* includes */

#include <stdio.h>
#include <strings.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/param.h>
#include <picl.h>
#include <libintl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/systeminfo.h>
#include <sys/openpromio.h>
#include <fcntl.h>
#include <smc_if.h>
#include <stropts.h>
#include <alloca.h>
#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <unistd.h>
#include <kstat.h>
#include <sys/utsname.h>
#include <stddef.h>
#include <pdevinfo.h>
#include <display_sun4u.h>
#include <libprtdiag.h>
#include <smclib.h>
#include <smc_commands.h>
#include <picldefs.h>

/* #defines for the PICL library API usage and local static variables */
#define	PD_CPCI_SLOT_TYPE	"cpci"
#define	PD_PCI_SLOT_TYPE	"pci"
#define	PD_PRESENT		1
#define	PD_BLANK		" "
#define	PD_ENABLED		1
#define	PD_DISABLED		0
#define	SNOWBIRD		"SUNW,Netra-CP2300"
#define	CHASSIS_NODE_NAME	"chassis"

/* #defines for the SMC and IPMI commands */
#define	POLL_TIMEOUT				10000
#define	DEFAULT_SEQN				0xff

/* SMC driver */
#define	PD_SMC_DRV_PATH			"/dev/ctsmc"

/* Constants */
#define	OBP_PROP_BANNER_NAME		"banner-name"
#define	OBP_PROP_CLOCK_FREQ		"clock-frequency"



/* #defines for local usage */
#define	PD_SUCCESS	0
#define	PD_FAILURE	1
#define	PD_INTERNAL_FAILURE	2
#define	PD_ERROR	-1

/*	static global variables	*/
static int pd_print_option;
static uint8_t pd_smc_glbl_enabl_rsp[2];
static boolean_t pd_hdr_prt		= B_TRUE;
static int pd_smc_fd			= 0;


/* function declarations used in this program */
static uint32_t pd_check_for_snowbird();
static uint32_t pd_prt_snowbird_diag();
static uint32_t pd_check_cpu_health();
static uint32_t pd_check_tty_debug_mode();
static uint32_t pd_query_SMC_firmware_version();
static uint32_t pd_check_slots();
int32_t pd_prt_slot_info(picl_nodehdl_t, void *);
int do_prominfo(int syserrlog, char *pname, int log_flag, int prt_flag);
static uint32_t pd_query_watchdog_state();
int pd_check_wd_state(picl_nodehdl_t, void *);
static uint32_t pd_print_fruinfo_hdr();
static uint32_t pd_print_device_info(int);
static uint32_t pd_get_role_information();
static uint32_t pd_get_message_flags();
static uint32_t pd_get_reset_mode();
static uint32_t pd_get_sensor_reading();
static uint32_t pd_get_sensor_threshold();
static uint32_t pd_prt_cpci_condition(picl_nodehdl_t nodeh);
static uint32_t pd_check_location_parent(picl_nodehdl_t nodeh);
static uint64_t
picldiag_get_uint_propval(picl_nodehdl_t modh, char *prop_name, int *ret);
static int picldiag_get_clock_freq(picl_nodehdl_t modh, uint32_t *freq);
static int display_system_clock(picl_nodehdl_t plafh);

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

	log_printf(dgettext(TEXT_DOMAIN,
		"System clock frequency: %d MHZ\n"), system_clk);

	return (PICL_SUCCESS);
}


/*
 * get the value by the property name of the string prop
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
	log_printf(dgettext(TEXT_DOMAIN,
		"System Configuration: Sun Microsystems "), 0);
	err = picldiag_get_string_propval(plafh, PICL_PROP_MACHINE,
	    &platform);
	if (err != PICL_SUCCESS)
		return (err);
	log_printf(" %s", platform, 0);
	free(platform);

	err = picldiag_get_string_propval(plafh, OBP_PROP_BANNER_NAME,
	    &banner_name);
	if (err != PICL_SUCCESS)
		return (err);
	log_printf(" %s", banner_name, 0);
	free(banner_name);

	log_printf("\n", 0);
	return (PICL_SUCCESS);
}

/*
 * search children to get the node by the nodename
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
 * This routine is invoked when prtdiag starts execution. It prints
 * system configuration, memory size, initializes PICL and acts as
 * a driver routine for prtdiag output for Snowbird.
 */
/* ARGSUSED */
int
do_prominfo(int syserrlog, char *pname, int log_flag, int prt_flag)
{

	struct mem_total memory_total;	/*	total memory in system	*/
	struct grp_info grps;
	uint8_t status = PD_SUCCESS;
	picl_nodehdl_t rooth;
	picl_nodehdl_t plafh;
	struct system_kstat_data *kstats = NULL;
	Sys_tree *tree = NULL;

	sys_clk = -1;
	pd_print_option = syserrlog;

	if ((status = picl_initialize()) != PICL_SUCCESS) {
		log_printf("prtdiag: failed to initialize the PICL\n", 0);
		exit(1);
	}

	if ((status = picl_get_root(&rooth)) != PICL_SUCCESS) {
		log_printf("prtdiag: failed\n", 0);
		exit(1);
	}

	status = picldiag_get_node_by_name(rooth, PICL_NODE_PLATFORM, &plafh);
	if (status != PICL_SUCCESS)
		return (status);

	if (!log_flag) {

		status = display_platform_banner(plafh);
		if (status != PICL_SUCCESS)
			return (status);

		status = display_system_clock(plafh);
		if (status != PICL_SUCCESS)
			return (status);

		/* display the memory Size */
		display_memorysize(tree, kstats, &grps, &memory_total);
	}

	if ((pd_smc_fd = open(PD_SMC_DRV_PATH, O_RDWR)) == -1)
		return (PD_FAILURE);

	if ((status = pd_check_for_snowbird()) != PD_SUCCESS)
		return (status);

	if ((status = pd_prt_snowbird_diag()) != PD_SUCCESS)
		return (status);

	(void) close(pd_smc_fd);

	if (picl_shutdown() != PICL_SUCCESS)
		return (PD_INTERNAL_FAILURE);

	return (PD_SUCCESS);

}

/*
 * This routine prints out the platform name.
 */

static uint32_t
pd_check_for_snowbird()
{

	char si_platform[30];

	if (sysinfo(SI_PLATFORM, si_platform, sizeof (si_platform)) == -1) {
		return (PD_FAILURE);
	}
	/* is it a Snowbird? */
	if (strcmp(si_platform, SNOWBIRD) != 0)
		return (PD_FAILURE);

	log_printf("platform Type : %s\n", si_platform, 0);
	return (PD_SUCCESS);

}


/*
 * Driver routine for satellite specific output. This is also used by
 * host driver routine as all satellite information is printed by host.
 * It also prints some host specific information for formatting purposes
 */

static uint32_t
pd_prt_snowbird_diag()
{
	uint8_t status = PD_SUCCESS;
	if ((status = pd_check_cpu_health()) != PD_SUCCESS) {
		return (status);
	}
	if (pd_print_option) {

		log_printf(
			"\n %11s Other Miscellaneous Information \n",
			PD_BLANK, 0);
		log_printf(
			"%12s ------------------------------- \n",
			PD_BLANK, 0);

		if ((status = pd_get_role_information()) != PD_SUCCESS) {
			return (status);
		}

		if (pd_smc_glbl_enabl_rsp[1] & 0x10) {
			log_printf(
				"IPMI Response Notification\t\tEnabled\n", 0);
		} else {
			log_printf(
				"IPMI Response Notification\t\tDisabled\n", 0);
		}
		if ((status = pd_query_SMC_firmware_version()) != PD_SUCCESS) {
			return (status);
		}

		if ((status = pd_check_tty_debug_mode()) != PD_SUCCESS) {
			return (status);
		}

		if ((status = pd_get_reset_mode()) != PD_SUCCESS) {
			return (status);
		}

		if ((status = pd_get_message_flags()) != PD_SUCCESS) {
			return (status);
		}

		if ((status = pd_query_watchdog_state()) != PD_SUCCESS) {
			return (status);
		}

		if ((status = pd_get_sensor_reading()) != PD_SUCCESS) {
			return (status);
		}

		if ((status = pd_get_sensor_threshold()) != PD_SUCCESS) {
			return (status);
		}

	}
	return (status);

}

/*
 * This routine prints the mode in which SMC is running. It uses the
 * response from SMC global enables to determine the mode
 */
static uint32_t
pd_check_tty_debug_mode()
{

	if (pd_smc_glbl_enabl_rsp[1] & 0x20) {
		log_printf("SMC verbose mode\t\t\tON\n", 0);
	} else {
		log_printf("SMC verbose mode\t\t\tOFF\n", 0);
	}

	return (PD_SUCCESS);
}

/* This routine prints SMC f/w version */
static uint32_t
pd_query_SMC_firmware_version()
{

	sc_reqmsg_t req_pkt;
	sc_rspmsg_t rsp_pkt;
	uint8_t ver, rev, bldrev;


	smc_init_smc_msg(&req_pkt, SMC_QUERY_FIRMWARE_VERSION,
		DEFAULT_SEQN, 0);
	smc_send_msg(-1, &req_pkt, &rsp_pkt, POLL_TIMEOUT);
	ver = (rsp_pkt.data[0] & 0xf0) >> 4;
	rev = rsp_pkt.data[0] & 0x0f;
	bldrev = rsp_pkt.data[2] & 0x3f;

	log_printf("SMC f/w version is\t\t\t%d.%d.%d\n", ver, rev, bldrev, 0);

	return (PD_SUCCESS);

}

/*
 * This routine checks CPU's health by using SMC self test results command
 * It acts as driver routine for printing cPCI slot information
 */
static uint32_t
pd_check_cpu_health()
{

	sc_reqmsg_t req_pkt;
	sc_rspmsg_t rsp_pkt;
	uint8_t	dev_id = 0x1f;
#ifdef DEBUG
	uint8_t i2c_chk = 0x40;
#endif
	uint8_t mem_test = 0x20;

	smc_init_smc_msg(&req_pkt, SMC_GET_SMC_SELF_TEST_RESULT,
		DEFAULT_SEQN, 0);
	smc_send_msg(-1, &req_pkt, &rsp_pkt, POLL_TIMEOUT);

	dev_id = rsp_pkt.data[0] & dev_id;

#ifdef DEBUG
	if (rsp_pkt.data[0] & i2c_chk) {
		pd_print_device_info(dev_id);
	}
#endif
	if (rsp_pkt.data[0] & mem_test) {
		pd_print_device_info(dev_id);
	}
	return (pd_check_slots());

}

/*
 * This routine decodes error message for CPU failures and prints details
 * of the failure
 */
static uint32_t
pd_print_device_info(int dev_id)
{

	switch (dev_id) {
		case 1:
			log_printf("Mux Philip 9540\n", 0);
			break;
		case 2:
			log_printf("cpu temp max1617\n", 0);
			break;
		case 3:
			log_printf("pmc temp max 1617\n", 0);
			break;
		case 4:
			log_printf("MB HS temp max 1617\n", 0);
			break;
		case 5:
			log_printf("MB mem temp max1617\n", 0);
			break;
		case 6:
			log_printf("MB gpio Philip8574\n", 0);
			break;
		case 7:
			log_printf("MB Fru ID ID i2c eep\n", 0);
			break;
		case 8:
			log_printf("MB enet ID ID i2d eep\n", 0);
			break;
		case 9:
			log_printf("MB gpio Philip8574A\n", 0);
			break;
		case 10:
			log_printf("SDRAM mod1 temp max1617\n", 0);
			break;
		case 11:
			log_printf("SDRAM mod ID  ID i2c eep\n", 0);
			break;
		case 12:
			log_printf("SDRAM mod2 temp max1617\n", 0);
			break;
		case 13:
			log_printf("SDRAM mod ID  ID i2c eep\n", 0);
			break;
		case 14:
			log_printf("Power mod temp ds1721\n", 0);
			break;
		case 15:
			log_printf("Power mod gpio Philip 8574\n", 0);
			break;
		case 16:
			log_printf("Power mod ID eep ST M24C01\n", 0);
			break;
		case 17:
			log_printf("SMC ID i2c eep\n", 0);
			break;

		default:
			log_printf("device id unknown\n", 0);
			break;

	}

	return (PD_SUCCESS);

}

/*
 * This routine walks PICL tree by "Location" class and calls prt_slot_info
 * routine to print the slot information
 */

/*ARGSUSED*/
static uint32_t
pd_check_slots()
{

	picl_nodehdl_t nodeh;
	char *c_args = NULL;

	if (picl_get_root(&nodeh) != PICL_SUCCESS)
		return (PD_INTERNAL_FAILURE);


	if (picl_walk_tree_by_class(nodeh, PICL_CLASS_LOCATION,
		    (void *)c_args, pd_prt_slot_info) != PICL_SUCCESS) {
		return (PD_INTERNAL_FAILURE);
	}

	return (PD_SUCCESS);

}


/*ARGSUSED*/
int32_t

pd_prt_slot_info(picl_nodehdl_t nodeh, void *c_args)
{

	char *valbuf;
	char label_txt[30];
	int unit_no = -1, ctr = 0;
	picl_nodehdl_t childh;
	picl_propinfo_t propinfo;
	picl_prophdl_t proph;

	/* if not immediate child of "chassis" node, ignore it */
	if (pd_check_location_parent(nodeh) != PD_SUCCESS)
		return (PD_INTERNAL_FAILURE);


	/* get the label on the location */
	if (picl_get_prop_by_name(nodeh, PICL_PROP_LABEL,
		    &proph) != PICL_SUCCESS)
		return (PD_INTERNAL_FAILURE);

	if (picl_get_propinfo(proph, &propinfo) != PICL_SUCCESS)
		return (PD_INTERNAL_FAILURE);

	valbuf = (char *) malloc(sizeof (char) * (propinfo.size));
	if (valbuf == NULL)
		return (PD_INTERNAL_FAILURE);

	if (picl_get_propval(proph, (void *)valbuf, propinfo.size)
		    != PICL_SUCCESS) {
		free(valbuf);
		return (PD_INTERNAL_FAILURE);
	}

	while (valbuf[ctr] != ' ' && valbuf[ctr] != NULL) {
		label_txt[ctr] = valbuf[ctr];
		++ctr;
	}

	label_txt[ctr++] = '\0';

	if (valbuf[ctr] != NULL) {
		unit_no = atoi(valbuf+ctr);
	}

	free(valbuf);

	/* get the slot type for the location */
	if (picl_get_prop_by_name(nodeh, PICL_PROP_SLOT_TYPE,
		    &proph) != PICL_SUCCESS)
		return (PD_INTERNAL_FAILURE);

	if (picl_get_propinfo(proph, & propinfo) != PICL_SUCCESS)
		return (PD_INTERNAL_FAILURE);

	valbuf = (char *) malloc(sizeof (char) * (propinfo.size));
	if (valbuf == NULL)
		return (PD_INTERNAL_FAILURE);

	if (picl_get_propval(proph, (void *)valbuf,
		    propinfo.size) != PICL_SUCCESS) {
		free(valbuf);
		return (PD_INTERNAL_FAILURE);
	}

	if ((strcmp(valbuf, PD_CPCI_SLOT_TYPE) == 0) ||
	    (strcmp(valbuf, PD_PCI_SLOT_TYPE) == 0)) {
		(void) pd_print_fruinfo_hdr();
		log_printf("\n%s         ", label_txt, 0);

	/* For Snowbird no unit number is present on the label */
		unit_no = 1;
		log_printf(" %d       Yes      cPSB IO Slot\n", unit_no, 0);

		if (picl_get_propval_by_name(nodeh, PICL_PROP_CHILD,
			    &childh, sizeof (childh)) == PICL_SUCCESS) {
			pd_prt_cpci_condition(childh);
		}
		/* For Snowbird auto configuration is always enabled */
		log_printf("%29s Properties:\n", PD_BLANK, 0);
		log_printf("%31s auto-config = enabled\n", PD_BLANK, 0);
	}


	free(valbuf);
	return (PD_SUCCESS);

}



static uint32_t
pd_print_fruinfo_hdr()
{

	log_printf(
		"\n %19s FRU Information \n",
		PD_BLANK, 0);
	log_printf(
		"%11s ------------------------------------------------\n",
		PD_BLANK, 0);

	log_printf(dgettext(TEXT_DOMAIN,
		"FRU         FRU    FRU      Miscellaneous\n"), 0);
	log_printf(dgettext(TEXT_DOMAIN,
		"Type        Unit#  Present  Information\n"), 0);
	log_printf("----        -----  -------", 0);
	log_printf("  --------------------------------\n", 0);
	return (PD_SUCCESS);

}

static uint32_t
pd_check_location_parent(picl_nodehdl_t nodeh)
{

	picl_nodehdl_t parenth;
	char *prop_name;

	if (picl_get_propval_by_name(nodeh, PICL_PROP_PARENT,
		    &parenth, sizeof (parenth)) != PICL_SUCCESS) {
		return (PD_FAILURE);
	}

	prop_name = (char *) malloc(sizeof (char) * PICL_PROPNAMELEN_MAX);
	if (prop_name == NULL) {
		return (PD_FAILURE);
	}

	if (picl_get_propval_by_name(parenth, PICL_PROP_NAME, (void *)prop_name,
		    PICL_PROPNAMELEN_MAX) != PICL_SUCCESS) {
		free(prop_name);
		return (PD_FAILURE);
	}

	if (strcmp(prop_name, CHASSIS_NODE_NAME) == 0) {
		free(prop_name);
		return (PD_SUCCESS);
	} else {
		free(prop_name);
		return (PD_FAILURE);
	}

}


/*ARGSUSED*/
static uint32_t
pd_query_watchdog_state()
{

	picl_nodehdl_t nodehandle;
	char *c_args = NULL;

	if (picl_get_root(&nodehandle) != PICL_SUCCESS) {
		return (PD_INTERNAL_FAILURE);
	}

	if (picl_walk_tree_by_class(nodehandle, PICL_CLASS_WATCHDOG_TIMER,
		    (void *)c_args, pd_check_wd_state) != PICL_SUCCESS)
		return (PD_INTERNAL_FAILURE);

	return (PD_SUCCESS);

}

/*ARGSUSED*/
int
pd_check_wd_state(picl_nodehdl_t nodeh, void *c_args)
{

	char *prop_name, *valbuf;
	picl_propinfo_t propinfo;
	picl_prophdl_t proph;

	prop_name = (char *) malloc(sizeof (char) * PICL_PROPNAMELEN_MAX);
	if (prop_name == NULL) {
		return (PICL_WALK_TERMINATE);
	}

	if (picl_get_propval_by_name(nodeh, PICL_PROP_NAME,
		(void *)prop_name, PICL_PROPNAMELEN_MAX) != PICL_SUCCESS) {
		free(prop_name);
		return (PICL_WALK_TERMINATE);
	}

	if ((picl_get_prop_by_name(nodeh, PICL_PROP_STATE,
		&proph)) != PICL_SUCCESS) {
		free(prop_name);
		return (PICL_WALK_TERMINATE);
	}

	if ((picl_get_propinfo(proph, &propinfo)) != PICL_SUCCESS) {
		free(prop_name);
		return (PICL_WALK_TERMINATE);
	}

	valbuf = (char *) malloc(sizeof (char) * (propinfo.size));
	if (valbuf == NULL) {
		free(prop_name);
		return (PICL_WALK_TERMINATE);
	}

	if ((picl_get_propval(proph, (void *)valbuf,
		propinfo.size)) != PICL_SUCCESS) {
		free(valbuf);
		free(prop_name);
		return (PICL_WALK_TERMINATE);
	}

	if (pd_hdr_prt) {
		log_printf("\n       Watch Dog Status \n", 0);
		log_printf("       ---------------- \n", 0);
		log_printf("Node                      Status\n", 0);
		log_printf("----                      ------\n", 0);
		pd_hdr_prt = B_FALSE;
	}

	log_printf("%s           ", prop_name, 0);
	log_printf("%s\n", valbuf, 0);

	free(prop_name);
	free(valbuf);
	return (PICL_WALK_CONTINUE);

}


static uint32_t
pd_get_role_information()
{

	sc_reqmsg_t req_pkt;
	sc_rspmsg_t rsp_pkt;
	uint8_t usparc_role;

	smc_init_smc_msg(&req_pkt, SMC_GET_ROLE_INFO,
		DEFAULT_SEQN, 0);
	smc_send_msg(-1, &req_pkt, &rsp_pkt, POLL_TIMEOUT);
	usparc_role = rsp_pkt.data[1];

	log_printf(dgettext(TEXT_DOMAIN,
		"UltraSPARC Host Role\t\t\t"), 0);
	if (usparc_role & 0x80) {
		log_printf(
			dgettext(TEXT_DOMAIN,
			"System Board Computer (SBC)\n"), 0);
	}
	if (usparc_role & 0x40) {
		log_printf(dgettext(TEXT_DOMAIN,
			"Standby System Board Computer (Standby SBC)\n"), 0);
	}
	if (usparc_role & 0x20) {
		log_printf(dgettext(TEXT_DOMAIN,
		"Alternate System Board Computer (Alternate SBC)\n"), 0);
	}
	if (usparc_role & 0x10) {
		log_printf(dgettext(TEXT_DOMAIN,
			"Satellite Board Computer (SAT)\n"), 0);
	}
	return (PD_SUCCESS);

}


static uint32_t
pd_get_message_flags()
{

	sc_reqmsg_t req_pkt;
	sc_rspmsg_t rsp_pkt;

	smc_init_smc_msg(&req_pkt, SMC_GET_MESSAGE_FLAGS,
		DEFAULT_SEQN, 0);
	smc_send_msg(-1, &req_pkt, &rsp_pkt, POLL_TIMEOUT);

	if (rsp_pkt.data[0] & 0x01) {
		log_printf("Messages Available in queue Recieving\n", 0);
	} else {
		log_printf("No messages in queue for Recieving\n", 0);
	}

	return (PD_SUCCESS);


}



static uint32_t
pd_get_reset_mode()
{

	sc_reqmsg_t req_pkt;
	sc_rspmsg_t rsp_pkt;


	smc_init_smc_msg(&req_pkt, SMC_GET_CONFIG_BLOCK,
		DEFAULT_SEQN,  0);
	smc_send_msg(-1, &req_pkt, &rsp_pkt, POLL_TIMEOUT);

	log_printf("Reset Mode\t\t\t\t%x \n", rsp_pkt.data[2], 0);

	return (PD_SUCCESS);

}


static uint32_t
pd_get_sensor_reading()
{


	sc_reqmsg_t req_pkt;
	sc_rspmsg_t rsp_pkt;

	req_pkt.data[0] = 0x0e;

	smc_init_smc_msg(&req_pkt, SMC_SENSOR_READING_GET,
		DEFAULT_SEQN, 1);
	smc_send_msg(-1, &req_pkt, &rsp_pkt, POLL_TIMEOUT);
	log_printf("\nCPU Node Temperature Information\n", PD_BLANK, 0);
	log_printf("--------------------------------\n", PD_BLANK, 0);
	log_printf("Temperature Reading: %d\n\n", rsp_pkt.data[0], 0);

	return (PD_SUCCESS);

}


static uint32_t
pd_get_sensor_threshold()
{


	sc_reqmsg_t req_pkt;
	sc_rspmsg_t rsp_pkt;
	uint8_t thres_mask;
	req_pkt.data[0] = 0x0e;

	smc_init_smc_msg(&req_pkt, SMC_SENSOR_THRESHOLD_GET,
		DEFAULT_SEQN,  1);
	smc_send_msg(-1, &req_pkt, &rsp_pkt, POLL_TIMEOUT);
	log_printf("Critical Threshold Information\n", 0);
	log_printf("------------------------------\n", 0);

	thres_mask = rsp_pkt.data[0];

	if (thres_mask & 0x20) {
		log_printf("High Power-Off Threshold %9s", PD_BLANK, 0);
		if (rsp_pkt.data[6] & 0x80) {
			log_printf("-%d\n",
				(int)((uint8_t)~rsp_pkt.data[6] + 1), 0);
		} else {
			log_printf(" %d\n", rsp_pkt.data[6], 0);
		}
	}

	if (thres_mask & 0x10) {
		log_printf("High Shutdown Threshold %10s", PD_BLANK, 0);
		if (rsp_pkt.data[5] & 0x80) {
			log_printf("-%d\n",
				(int)((uint8_t)~rsp_pkt.data[5] + 1), 0);
		} else {
			log_printf(" %d\n", rsp_pkt.data[5], 0);
		}
	}


	if (thres_mask & 0x08) {
		log_printf("High Warning Threshold %11s", PD_BLANK, 0);
		if (rsp_pkt.data[4] & 0x80) {
			log_printf("-%d\n",
				(int)((uint8_t)~rsp_pkt.data[4] + 1), 0);
		} else {
			log_printf(" %d\n", rsp_pkt.data[4], 0);
		}
	}

	if (thres_mask & 0x04) {
		log_printf("Low Power Off Threshold %10s", PD_BLANK, 0);
		if (rsp_pkt.data[3] & 0x80) {
			log_printf("-%d\n",
				(int)((uint8_t)~rsp_pkt.data[3] + 1), 0);
		} else {
			log_printf(" %d\n", rsp_pkt.data[3], 0);
		}
	}

	if (thres_mask & 0x02) {
		log_printf("Low Shutdown Threshold %11s", PD_BLANK, 0);
		if (rsp_pkt.data[2] & 0x80) {
			log_printf("-%d\n",
				(int)((uint8_t)~rsp_pkt.data[2] + 1), 0);
		} else {
			log_printf(" %d\n", rsp_pkt.data[2], 0);
		}
	}

	if (thres_mask & 0x01) {
		log_printf("Low Warning Threshold %12s", PD_BLANK, 0);
		if (rsp_pkt.data[1] & 0x80) {
			log_printf("-%d\n",
				(int)((uint8_t)~rsp_pkt.data[1] + 1), 0);
		} else {
			log_printf(" %d\n", rsp_pkt.data[1], 0);
		}
	}

	return (PD_SUCCESS);

}



static uint32_t
pd_prt_cpci_condition(picl_nodehdl_t nodeh)
{

	picl_propinfo_t propinfo;
	picl_prophdl_t proph;
	char *valbuf;


	if (picl_get_prop_by_name(nodeh, PICL_PROP_CONDITION,
		    &proph) != PICL_SUCCESS) {
		return (PD_FAILURE);
	}

	if (picl_get_propinfo(proph, &propinfo) != PICL_SUCCESS) {
		return (PD_FAILURE);
	}

	valbuf = (char *) malloc(sizeof (char) * (propinfo.size));
	if (valbuf == NULL) {
		return (PD_FAILURE);
	}

	if (picl_get_propval(proph, (void *)valbuf,
		    propinfo.size) != PICL_SUCCESS) {
		free(valbuf);
		return (PD_FAILURE);
	}


	log_printf("%29s Condition : %s\n", PD_BLANK, valbuf, 0);

	free(valbuf);
	return (PD_SUCCESS);


}
