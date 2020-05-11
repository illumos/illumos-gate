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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * PICL plug-in that creates the FRU Hierarchy for the
 * SUNW,Sun-Fire-480R (Cherrystone) platform
 */

#include <stdio.h>
#include <string.h>
#include <libintl.h>
#include <libnvpair.h>
#include <syslog.h>
#include <picl.h>
#include <picltree.h>
#include <picldefs.h>

/*
 * Plugin registration entry points
 */
static void	picl_frutree_register(void);
static void	picl_frutree_init(void);
static void	picl_frutree_fini(void);
static void	picl_frutree_evhandler(const char *ename, const void *earg,
		    size_t size, void *cookie);

#pragma	init(picl_frutree_register)

/*
 * Log message texts
 */
#define	CREATE_FRUTREE_FAIL	gettext("Failed to create frutree node\n")
#define	CREATE_CHASSIS_FAIL	gettext("Failed to create chassis node\n")
#define	IOBRD_INIT_FAIL		gettext("do_ioboard_init() failed\n")
#define	RSCBRD_INIT_FAIL	gettext("do_rscboard_init() failed\n")
#define	FCAL_INIT_FAIL		gettext("do_fcal_init() failed\n")
#define	PS_INIT_FAIL		gettext("do_power_supplies_init() failed\n")
#define	SYSBOARD_INIT_FAIL	gettext("do_centerplane_init() failed\n")

/*
 * Viewpoints property field used by SunMC
 */
#define	CHASSIS_VIEWPOINTS	gettext("front top rear")

/*
 * Ref prop values
 */
#define	SEEPROM_SOURCE		"_seeprom_source"
#define	FRU_PARENT		"_fru_parent"

/*
 * List of all the FRU locations in the platform_frupath[] array, and
 * location_label[] array
 */
#define	PS0		0
#define	PS1		1
#define	RSC		2
#define	DISKBACKPLANE	3
#define	PDB		4
#define	CENTERPLANE	5
#define	IOBRD		6
#define	CPUMOD0		7
#define	CPUMOD1		8
#define	CPU0_DIMM0	9
#define	DIMMS_PER_MOD	8
#define	DIMMS_PER_SLOT	16

/*
 * Local variables
 */
static picld_plugin_reg_t  my_reg_info = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_NON_CRITICAL,
	"SUNW_Cherrystone_frutree",
	picl_frutree_init,
	picl_frutree_fini
};

/*
 * List of all the FRUs in the /platform tree with SEEPROMs
 */
static char *platform_frupath[] = {
	"/platform/pci@9,700000/ebus@1/i2c@1,30/fru@0,a2", /* PS 0 */
	"/platform/pci@9,700000/ebus@1/i2c@1,30/fru@0,a0", /* PS 1 */
	"/platform/pci@9,700000/ebus@1/i2c@1,30/fru@0,a6", /* RSC */
	"/platform/pci@9,700000/ebus@1/i2c@1,30/fru@0,a8", /* Disk Backplane */
	"/platform/pci@9,700000/ebus@1/i2c@1,30/fru@0,ae", /* PDB */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@4,a8", /* Centerplane */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@4,aa", /* IO */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@4,a0", /* CPU MOD 0 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@4,a2", /* CPU MOD 1 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@0,a0", /* CPU0 DIMM0 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@0,a2", /* CPU0 DIMM1 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@0,a4", /* CPU0 DIMM2 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@0,a6", /* CPU0 DIMM3 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@0,a8", /* CPU0 DIMM4 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@0,aa", /* CPU0 DIMM5 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@0,ac", /* CPU0 DIMM6 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@0,ae", /* CPU0 DIMM7 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@2,a0", /* CPU2 DIMM0 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@2,a2", /* CPU2 DIMM1 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@2,a4", /* CPU2 DIMM2 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@2,a6", /* CPU2 DIMM3 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@2,a8", /* CPU2 DIMM4 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@2,aa", /* CPU2 DIMM5 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@2,ac", /* CPU2 DIMM6 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@2,ae", /* CPU2 DIMM7 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@1,a0", /* CPU1 DIMM0 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@1,a2", /* CPU1 DIMM1 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@1,a4", /* CPU1 DIMM2 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@1,a6", /* CPU1 DIMM3 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@1,a8", /* CPU1 DIMM4 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@1,aa", /* CPU1 DIMM5 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@1,ac", /* CPU1 DIMM6 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@1,ae", /* CPU1 DIMM7 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@3,a0", /* CPU3 DIMM0 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@3,a2", /* CPU3 DIMM1 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@3,a4", /* CPU3 DIMM2 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@3,a6", /* CPU3 DIMM3 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@3,a8", /* CPU3 DIMM4 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@3,aa", /* CPU3 DIMM5 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@3,ac", /* CPU3 DIMM6 */
	"/platform/pci@9,700000/ebus@1/i2c@1,2e/fru@3,ae", /* CPU3 DIMM7 */
	NULL};

/*
 * List of Labels for FRU locations (uses the #define's from above)
 */
static char *location_label[] = {
	"0",			/* PS0 */
	"1",			/* PS1 */
	NULL,			/* RSC */
	NULL,			/* DISKBACKPLANE */
	NULL,			/* PDB */
	NULL,			/* CENTERPLANE */
	NULL,			/* IOBRD */
	"A",			/* CPUMOD0 */
	"B",			/* CPUMOD1 */
	"J2900",		/* CPU0 DIMM0 */
	"J3100",		/* CPU0 DIMM1 */
	"J2901",		/* CPU0 DIMM2 */
	"J3101",		/* CPU0 DIMM3 */
	"J3000",		/* CPU0 DIMM4 */
	"J3200",		/* CPU0 DIMM5 */
	"J3001",		/* CPU0 DIMM6 */
	"J3201",		/* CPU0 DIMM7 */
	"J7900",		/* CPU1 DIMM0 */
	"J8100",		/* CPU1 DIMM1 */
	"J7901",		/* CPU1 DIMM2 */
	"J8101",		/* CPU1 DIMM3 */
	"J8000",		/* CPU1 DIMM4 */
	"J8200",		/* CPU1 DIMM5 */
	"J8001",		/* CPU1 DIMM6 */
	"J8201",		/* CPU1 DIMM7 */
	"0",			/* CPU0 label */
	"1",			/* CPU1 label */
	NULL};

/*
 * List of all the FRU slots for power supplies (hotpluggable)
 */
static char *frutree_power_supply[] = {
	"/frutree/chassis/power-dist-board/power-supply-slot?Slot=0",
	"/frutree/chassis/power-dist-board/power-supply-slot?Slot=1",
	NULL};

/* PICL handle for the root node of the "frutree" */
static picl_nodehdl_t	frutreeh;

static int	do_ioboard_init(picl_nodehdl_t);
static int	do_rscboard_init(picl_nodehdl_t);
static int	do_fcal_init(picl_nodehdl_t);
static int	do_power_supplies_init(picl_nodehdl_t);
static int	do_centerplane_init(picl_nodehdl_t);
static int	do_cpu_module_init(picl_nodehdl_t, int);
static int	do_dimms_init(picl_nodehdl_t, int, int);

static int	add_ref_prop(picl_nodehdl_t, picl_nodehdl_t, char *);
static int	add_slot_prop(picl_nodehdl_t, int);
static int	add_label_prop(picl_nodehdl_t, char *);
static int	add_void_fda_prop(picl_nodehdl_t);
static int	add_viewpoints_prop(picl_nodehdl_t, char *);
static int	add_all_nodes();
static int	remove_all_nodes(picl_nodehdl_t);

static int	add_hotplug_fru_device(void);
static int	rem_hotplug_fru_device(void);
static int	is_added_device(char *, char *);
static int	is_removed_device(char *, char *);
static int	add_power_supply(int);
static int	remove_power_supply(int);

/*
 * This function is executed as part of .init when the plugin is
 * dlopen()ed
 */
static void
picl_frutree_register()
{
	(void) picld_plugin_register(&my_reg_info);
}

/*
 * This function is the init entry point of the plugin.
 * It initializes the /frutree tree
 */
static void
picl_frutree_init()
{
	int		err;

	err = add_all_nodes();
	if (err != PICL_SUCCESS) {
		(void) remove_all_nodes(frutreeh);
		return;
	}

	/* Register the event handler routine */
	(void) ptree_register_handler(PICLEVENT_SYSEVENT_DEVICE_ADDED,
	    picl_frutree_evhandler, NULL);
	(void) ptree_register_handler(PICLEVENT_SYSEVENT_DEVICE_REMOVED,
	    picl_frutree_evhandler, NULL);
}

/*
 * This function is the fini entry point of the plugin
 */
static void
picl_frutree_fini(void)
{
	/* Unregister the event handler routine */
	(void) ptree_unregister_handler(PICLEVENT_SYSEVENT_DEVICE_ADDED,
	    picl_frutree_evhandler, NULL);
	(void) ptree_unregister_handler(PICLEVENT_SYSEVENT_DEVICE_REMOVED,
	    picl_frutree_evhandler, NULL);

	(void) remove_all_nodes(frutreeh);
}

/*
 * This function is the event handler of this plug-in.
 *
 * It processes the following events:
 *
 *	PICLEVENT_SYSEVENT_DEVICE_ADDED
 *	PICLEVENT_SYSEVENT_DEVICE_REMOVED
 */
/* ARGSUSED */
static void
picl_frutree_evhandler(const char *ename, const void *earg, size_t size,
    void *cookie)
{
	if (strcmp(ename, PICLEVENT_SYSEVENT_DEVICE_ADDED) == 0) {
		/* Check for and add any hotplugged device(s) */
		(void) add_hotplug_fru_device();

	} else if (strcmp(ename, PICLEVENT_SYSEVENT_DEVICE_REMOVED) == 0) {
		/* Check for and remove any hotplugged device(s) */
		(void) rem_hotplug_fru_device();
	}
}

/* Initializes the FRU nodes for the IO board */
static int
do_ioboard_init(picl_nodehdl_t rooth)
{
	picl_nodehdl_t		iobrdh;
	picl_nodehdl_t		tmph;
	int			err;

	/* Create the node for the IO board (if it exists) */
	if (ptree_get_node_by_path(platform_frupath[IOBRD], &tmph) ==
	    PICL_SUCCESS) {
		err = ptree_create_node("io-board", "fru", &iobrdh);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_ref_prop(iobrdh, tmph, SEEPROM_SOURCE);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_void_fda_prop(iobrdh);
		if (err != PICL_SUCCESS)
			return (err);

		err = ptree_add_node(rooth, iobrdh);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_ref_prop(tmph, iobrdh, FRU_PARENT);
		if (err != PICL_SUCCESS)
			return (err);
	}
	return (PICL_SUCCESS);
}

/* Initializes the FRU node for the RSC card */
static int
do_rscboard_init(picl_nodehdl_t rooth)
{
	picl_nodehdl_t		rscbrdh;
	picl_nodehdl_t		tmph;
	int			err;

	/* Create the node for the RSC board (if it exists) */
	if (ptree_get_node_by_path(platform_frupath[RSC], &tmph) ==
	    PICL_SUCCESS) {
		err = ptree_create_node("rsc-board", "fru", &rscbrdh);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_ref_prop(rscbrdh, tmph, SEEPROM_SOURCE);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_void_fda_prop(rscbrdh);
		if (err != PICL_SUCCESS)
			return (err);

		err = ptree_add_node(rooth, rscbrdh);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_ref_prop(tmph, rscbrdh, FRU_PARENT);
		if (err != PICL_SUCCESS)
			return (err);
	}
	return (PICL_SUCCESS);
}

/* Initializes the FRU nodes for the FCAL backplaned */
static int
do_fcal_init(picl_nodehdl_t rooth)
{
	picl_nodehdl_t		fcalsloth;
	picl_nodehdl_t		fcalmodh;
	picl_nodehdl_t		tmph;
	int			err;

	/* Create the node for the FCAL backplane slot */
	err = ptree_create_node("fcal-backplane-slot",
	    "location", &fcalsloth);
	if (err != PICL_SUCCESS)
		return (err);

	err = add_slot_prop(fcalsloth, 0);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_add_node(rooth, fcalsloth);
	if (err != PICL_SUCCESS)
		return (err);

	/* If the FCAL backplane exists, create a node for it */
	if (ptree_get_node_by_path(platform_frupath[DISKBACKPLANE], &tmph) ==
	    PICL_SUCCESS) {
		err = ptree_create_node("fcal-backplane", "fru",
		    &fcalmodh);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_ref_prop(fcalmodh, tmph, SEEPROM_SOURCE);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_void_fda_prop(fcalmodh);
		if (err != PICL_SUCCESS)
			return (err);

		err = ptree_add_node(fcalsloth, fcalmodh);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_ref_prop(tmph, fcalmodh, FRU_PARENT);
		if (err != PICL_SUCCESS)
			return (err);
	}
	return (PICL_SUCCESS);
}

/* Initializes the FRU nodes for the PDB and the power supplies */
static int
do_power_supplies_init(picl_nodehdl_t rooth)
{
	picl_nodehdl_t		powerbrdh;
	picl_nodehdl_t		powersloth;
	picl_nodehdl_t		powermodh;
	picl_nodehdl_t		tmph;
	int			i, err, slotnum;

	/* Create the node for the PDB (if it exists) */
	if (ptree_get_node_by_path(platform_frupath[PDB], &tmph) ==
	    PICL_SUCCESS) {
		err = ptree_create_node("power-dist-board", "fru", &powerbrdh);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_ref_prop(powerbrdh, tmph, SEEPROM_SOURCE);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_void_fda_prop(powerbrdh);
		if (err != PICL_SUCCESS)
			return (err);

		err = ptree_add_node(rooth, powerbrdh);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_ref_prop(tmph, powerbrdh, FRU_PARENT);
		if (err != PICL_SUCCESS)
			return (err);

		for (i = PS0; i <= PS1; i++) {
			/* Create the node for the power supply slot */
			err = ptree_create_node("power-supply-slot",
			    "location", &powersloth);
			if (err != PICL_SUCCESS)
				return (err);

			slotnum = i - PS0;
			err = add_slot_prop(powersloth, slotnum);
			if (err != PICL_SUCCESS)
				return (err);

			err = add_label_prop(powersloth, location_label[i]);
			if (err != PICL_SUCCESS)
				return (err);

			err = ptree_add_node(powerbrdh, powersloth);
			if (err != PICL_SUCCESS)
				return (err);

			/* If the PS exists, create a node for it */
			if (ptree_get_node_by_path(platform_frupath[i],
			    &tmph) == PICL_SUCCESS) {
				err = ptree_create_node("power-supply",
				    "fru", &powermodh);
				if (err != PICL_SUCCESS)
					return (err);

				err = add_ref_prop(powermodh, tmph,
				    SEEPROM_SOURCE);
				if (err != PICL_SUCCESS)
					return (err);

				err = add_void_fda_prop(powermodh);
				if (err != PICL_SUCCESS)
					return (err);

				err = ptree_add_node(powersloth, powermodh);
				if (err != PICL_SUCCESS)
					return (err);

				err = add_ref_prop(tmph, powermodh, FRU_PARENT);
				if (err != PICL_SUCCESS)
					return (err);
			}
		}
	}
	return (PICL_SUCCESS);
}

/* Initializes the FRU nodes for the centerplane and CPU Memory modules */
static int
do_centerplane_init(picl_nodehdl_t rooth)
{
	picl_nodehdl_t		sysboardh;
	picl_nodehdl_t		cpumemsloth;
	picl_nodehdl_t		cpumemmodh;
	picl_nodehdl_t		tmph;
	int			i, err, slotnum;

	/* Create the node for the system board (if it exists) */
	if (ptree_get_node_by_path(platform_frupath[CENTERPLANE], &tmph) ==
	    PICL_SUCCESS) {
		err = ptree_create_node("centerplane", "fru",
		    &sysboardh);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_ref_prop(sysboardh, tmph, SEEPROM_SOURCE);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_void_fda_prop(sysboardh);
		if (err != PICL_SUCCESS)
			return (err);

		err = ptree_add_node(rooth, sysboardh);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_ref_prop(tmph, sysboardh, FRU_PARENT);
		if (err != PICL_SUCCESS)
			return (err);

		for (i = CPUMOD0; i <= CPUMOD1; i++) {
			/* Create the node for the CPU Memory slot */
			err = ptree_create_node("cpu-mem-slot", "location",
			    &cpumemsloth);
			if (err != PICL_SUCCESS)
				return (err);

			slotnum = i - CPUMOD0;
			err = add_slot_prop(cpumemsloth, slotnum);
			if (err != PICL_SUCCESS)
				return (err);

			err = add_label_prop(cpumemsloth, location_label[i]);
			if (err != PICL_SUCCESS)
				return (err);

			err = ptree_add_node(sysboardh, cpumemsloth);
			if (err != PICL_SUCCESS)
				return (err);

			/* If CPU Mem module exists, create a node for it */
			if (ptree_get_node_by_path(platform_frupath[i],
			    &tmph) == PICL_SUCCESS) {
				err = ptree_create_node("cpu-mem-module",
				    "fru", &cpumemmodh);
				if (err != PICL_SUCCESS)
					return (err);

				err = add_ref_prop(cpumemmodh, tmph,
				    SEEPROM_SOURCE);
				if (err != PICL_SUCCESS)
					return (err);

				err = add_void_fda_prop(cpumemmodh);
				if (err != PICL_SUCCESS)
					return (err);

				err = ptree_add_node(cpumemsloth, cpumemmodh);
				if (err != PICL_SUCCESS)
					return (err);

				err = add_ref_prop(tmph, cpumemmodh,
				    FRU_PARENT);
				if (err != PICL_SUCCESS)
					return (err);

				err = do_cpu_module_init(cpumemmodh, slotnum);
				if (err != PICL_SUCCESS)
					return (err);
			}
		}
	}
	return (PICL_SUCCESS);
}

/* Creates the FRU nodes for the CPU Module and associated DIMMs */
static int
do_cpu_module_init(picl_nodehdl_t rooth, int slot)
{
	picl_nodehdl_t		cpumodh;
	int			i, c, err;

	for (i = 0; i <= 1; i++) {
		err = ptree_create_node("cpu-module", "location",
		    &cpumodh);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_slot_prop(cpumodh, i);
		if (err != PICL_SUCCESS)
			return (err);

		c = CPU0_DIMM0 + DIMMS_PER_SLOT + i;

		err = add_label_prop(cpumodh, location_label[c]);
		if (err != PICL_SUCCESS)
			return (err);

		err = ptree_add_node(rooth, cpumodh);
		if (err != PICL_SUCCESS)
			return (err);

		/* Create the nodes for the memory (if they exist) */
		err = do_dimms_init(cpumodh, slot, i);
		if (err != PICL_SUCCESS)
			return (err);
	}
	return (PICL_SUCCESS);
}

/* Creates the FRU nodes for the DIMMs on a particular CPU Module */
static int
do_dimms_init(picl_nodehdl_t rooth, int slot, int module)
{
	picl_nodehdl_t		dimmsloth;
	picl_nodehdl_t		dimmmodh;
	picl_nodehdl_t		tmph;
	int			i, c, l, err;

	for (i = 0; i < DIMMS_PER_MOD; i++) {
		/* Create the node for the memory slot */
		err = ptree_create_node("dimm-slot", "location",
		    &dimmsloth);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_slot_prop(dimmsloth, i);
		if (err != PICL_SUCCESS)
			return (err);

		c = ((slot * DIMMS_PER_SLOT) +
		    (module * DIMMS_PER_MOD) + i) + CPU0_DIMM0;

		l = c - (DIMMS_PER_SLOT * slot);

		err = add_label_prop(dimmsloth, location_label[l]);
		if (err != PICL_SUCCESS)
			return (err);

		err = ptree_add_node(rooth, dimmsloth);
		if (err != PICL_SUCCESS)
			return (err);

		/* If the memory module exists, create a node for it */
		if (ptree_get_node_by_path(platform_frupath[c], &tmph) ==
		    PICL_SUCCESS) {
			err = ptree_create_node("dimm-module", "fru",
			    &dimmmodh);
			if (err != PICL_SUCCESS)
				return (err);

			err = add_ref_prop(dimmmodh, tmph, SEEPROM_SOURCE);
			if (err != PICL_SUCCESS)
				return (err);

			err = add_void_fda_prop(dimmmodh);
			if (err != PICL_SUCCESS)
				return (err);

			err = ptree_add_node(dimmsloth, dimmmodh);
			if (err != PICL_SUCCESS)
				return (err);

			err = add_ref_prop(tmph, dimmmodh, FRU_PARENT);
			if (err != PICL_SUCCESS)
				return (err);
		}
	}
	return (PICL_SUCCESS);
}

/* Creates a "reference" property between two PICL nodes */
static int
add_ref_prop(picl_nodehdl_t nodeh, picl_nodehdl_t tmph, char *str)
{
	picl_prophdl_t		proph;
	ptree_propinfo_t	propinfo;
	int			err;

	if (str == NULL)
		return (PICL_FAILURE);

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_REFERENCE, PICL_READ, sizeof (picl_nodehdl_t),
	    str, NULL, NULL);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_create_and_add_prop(nodeh, &propinfo, &tmph, &proph);
	if (err != PICL_SUCCESS)
		return (err);

	return (PICL_SUCCESS);
}

/* Creates a "slot" property for a given PICL node */
static int
add_slot_prop(picl_nodehdl_t nodeh, int slotnum)
{
	picl_prophdl_t		proph;
	ptree_propinfo_t	propinfo;
	int			err;

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_INT, PICL_READ, 4, "Slot", NULL, NULL);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_create_and_add_prop(nodeh, &propinfo, &slotnum, &proph);
	if (err != PICL_SUCCESS)
		return (err);

	return (PICL_SUCCESS);
}

/* Creates a "Label" property for a given PICL node */
static int
add_label_prop(picl_nodehdl_t nodeh, char *label)
{
	picl_prophdl_t		proph;
	ptree_propinfo_t	propinfo;
	int			err;

	if (label == NULL)
		return (PICL_FAILURE);

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(label)+1, "Label",
	    NULL, NULL);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_create_and_add_prop(nodeh, &propinfo, label, &proph);
	if (err != PICL_SUCCESS)
		return (err);

	return (PICL_SUCCESS);
}

/* Creates a "FRUDataAvailable" void property for the given PICL node */
static int
add_void_fda_prop(picl_nodehdl_t nodeh)
{
	picl_prophdl_t		proph;
	ptree_propinfo_t	propinfo;
	int			err;

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_VOID, PICL_READ, 0, "FRUDataAvailable", NULL, NULL);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_create_and_add_prop(nodeh, &propinfo, NULL, &proph);
	if (err != PICL_SUCCESS)
		return (err);

	return (PICL_SUCCESS);
}

/* Creates a "ViewPoints" property -- used for chassis */
static int
add_viewpoints_prop(picl_nodehdl_t nodeh, char *string)
{
	picl_prophdl_t		proph;
	ptree_propinfo_t	propinfo;
	int			err;

	if (string == NULL)
		return (PICL_FAILURE);

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_CHARSTRING, PICL_READ, strlen(string)+1, "ViewPoints",
	    NULL, NULL);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_create_and_add_prop(nodeh, &propinfo, string, &proph);
	if (err != PICL_SUCCESS)
		return (err);

	return (PICL_SUCCESS);
}

/* Creates and adds all of the frutree nodes */
static int
add_all_nodes()
{
	picl_nodehdl_t	rooth;
	picl_nodehdl_t	chassish;
	int		err;

	/* Get the root node of the PICL tree */
	err = ptree_get_root(&rooth);
	if (err != PICL_SUCCESS) {
		return (err);
	}

	/* Create and add the root node of the FRU subtree */
	err = ptree_create_and_add_node(rooth, "frutree", "picl", &frutreeh);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, CREATE_FRUTREE_FAIL);
		return (err);
	}

	/* Create and add the chassis node */
	err = ptree_create_and_add_node(frutreeh, "chassis", "fru", &chassish);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, CREATE_CHASSIS_FAIL);
		return (err);
	}

	/* Add ViewPoints prop to chassis node */
	err = add_viewpoints_prop(chassish, CHASSIS_VIEWPOINTS);
	if (err != PICL_SUCCESS)
		return (err);

	/* Initialize the FRU nodes for the IO board */
	err = do_ioboard_init(chassish);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, IOBRD_INIT_FAIL);
		return (err);
	}

	/* Initialize the FRU node for the RSC card */
	err = do_rscboard_init(chassish);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, RSCBRD_INIT_FAIL);
		return (err);
	}

	/* Initialize the FRU nodes for the DISK backplane */
	err = do_fcal_init(chassish);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, FCAL_INIT_FAIL);
		return (err);
	}

	/* Initialize the FRU nodes for the PDB and the power supplies */
	err = do_power_supplies_init(chassish);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PS_INIT_FAIL);
		return (err);
	}

	/* Initialize the FRU nodes for the CPU Memory modules */
	err = do_centerplane_init(chassish);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, SYSBOARD_INIT_FAIL);
		return (err);
	}

	return (PICL_SUCCESS);
}

/* Deletes and destroys all PICL nodes for which rooth is a ancestor */
static int
remove_all_nodes(picl_nodehdl_t rooth)
{
	picl_nodehdl_t		chdh;
	int			err, done = 0;

	while (!done) {
		err = ptree_get_propval_by_name(rooth, PICL_PROP_CHILD, &chdh,
		    sizeof (picl_nodehdl_t));
		if (err != PICL_PROPNOTFOUND) {
			(void) remove_all_nodes(chdh);
		} else {
			err = ptree_delete_node(rooth);
			if (err != PICL_SUCCESS) {
				return (err);
			} else {
				(void) ptree_destroy_node(rooth);
			}
			done = 1;
		}
	}
	return (PICL_SUCCESS);
}

/* Searches the list of hotpluggable FRUs, adds the appropriate node(s) */
static int
add_hotplug_fru_device()
{
	int		i, err, slotnum;

	/* Check for hotplugged power supplies */
	for (i = PS0; i <= PS1; i++) {
		/* Compare the /platform tree to the frutree */
		slotnum = i - PS0;
		err = is_added_device(platform_frupath[i],
		    frutree_power_supply[slotnum]);
		if (err != PICL_SUCCESS)
			continue;

		/* If they are different, then add a power supply */
		err = add_power_supply(slotnum);
		if (err != PICL_SUCCESS)
			continue;
	}
	return (PICL_SUCCESS);
}

/* Searches the list of hotpluggable FRUs, removes the appropriate node(s) */
static int
rem_hotplug_fru_device()
{
	int		i, err, slotnum;

	/* Check for hotplugged power supplies */
	for (i = PS0; i <= PS1; i++) {
		/* Compare the /platform tree to the frutree */
		slotnum = i - PS0;
		err = is_removed_device(platform_frupath[i],
		    frutree_power_supply[slotnum]);
		if (err != PICL_SUCCESS)
			continue;

		/* If they are different, then remove a power supply */
		err = remove_power_supply(slotnum);
		if (err != PICL_SUCCESS)
			continue;
	}
	return (PICL_SUCCESS);
}

/*
 * Compare the /platform tree to the /frutree to determine if a
 * new device has been added
 */
static int
is_added_device(char *plat, char *fru)
{
	int		err;
	picl_nodehdl_t	plath, frusloth, frumodh;

	/* Check for node in the /platform tree */
	err = ptree_get_node_by_path(plat, &plath);
	if (err != PICL_SUCCESS)
		return (err);

	/*
	 * The node is in /platform, so find the corresponding slot in
	 * the frutree
	 */
	err = ptree_get_node_by_path(fru, &frusloth);
	if (err != PICL_SUCCESS)
		return (err);

	/*
	 * If the slot in the frutree has a child, then return
	 * PICL_FAILURE.  This means that the /platform tree and
	 * the frutree are consistent and no action is necessary.
	 * Otherwise return PICL_SUCCESS to indicate that a node needs
	 * to be added to the frutree
	 */
	err = ptree_get_propval_by_name(frusloth, PICL_PROP_CHILD,
	    &frumodh, sizeof (picl_nodehdl_t));
	if (err == PICL_SUCCESS)
		return (PICL_FAILURE);

	return (PICL_SUCCESS);
}

/*
 * Compare the /platform tree to the /frutree to determine if a
 * device has been removed
 */
static int
is_removed_device(char *plat, char *fru)
{
	int		err;
	picl_nodehdl_t	plath, frusloth, frumodh;


	/* Check for node in /platform tree */
	err = ptree_get_node_by_path(plat, &plath);
	if (err == PICL_SUCCESS)
		return (PICL_FAILURE);

	/*
	 * The node is not in /platform, so find the corresponding slot in
	 * the frutree
	 */
	err = ptree_get_node_by_path(fru, &frusloth);
	if (err != PICL_SUCCESS)
		return (err);

	/*
	 * If the slot in the frutree does not have a child, then return
	 * PICL_FAILURE.  This means that the /platform tree and
	 * the frutree are consistent and no action is necessary.
	 * Otherwise return PICL_SUCCESS to indicate that the needs
	 * to be removed from the frutree
	 */
	err = ptree_get_propval_by_name(frusloth, PICL_PROP_CHILD,
	    &frumodh, sizeof (picl_nodehdl_t));
	if (err != PICL_SUCCESS)
		return (err);

	return (PICL_SUCCESS);
}

static int
remove_picl_node(picl_nodehdl_t nodeh)
{
	int err;
	err = ptree_delete_node(nodeh);
	if (err != PICL_SUCCESS)
		return (err);
	(void) ptree_destroy_node(nodeh);
	return (PICL_SUCCESS);
}

/* event completion handler for PICL_FRU_ADDED/PICL_FRU_REMOVED events */
static void
frudr_completion_handler(char *ename, void *earg, size_t size)
{
	picl_nodehdl_t	fruh;

	if (strcmp(ename, PICL_FRU_REMOVED) == 0) {
		/*
		 * now frudata has been notified that the node is to be
		 * removed, we can actually remove it
		 */
		fruh = 0;
		(void) nvlist_lookup_uint64(earg,
		    PICLEVENTARG_FRUHANDLE, &fruh);
		if (fruh != 0) {
			(void) remove_picl_node(fruh);
		}
	}
	nvlist_free(earg);
	free(earg);
	free(ename);
}

/*
 * Post the PICL_FRU_ADDED/PICL_FRU_REMOVED event
 */
static void
post_frudr_event(char *ename, picl_nodehdl_t parenth, picl_nodehdl_t fruh)
{
	nvlist_t	*nvl;
	char		*ev_name;

	ev_name = strdup(ename);
	if (ev_name == NULL)
		return;
	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME_TYPE, 0)) {
		free(ev_name);
		return;
	}
	if (parenth != 0L &&
	    nvlist_add_uint64(nvl, PICLEVENTARG_PARENTHANDLE, parenth)) {
		free(ev_name);
		nvlist_free(nvl);
		return;
	}
	if (fruh != 0L &&
	    nvlist_add_uint64(nvl, PICLEVENTARG_FRUHANDLE, fruh)) {
		free(ev_name);
		nvlist_free(nvl);
		return;
	}
	if (ptree_post_event(ev_name, nvl, sizeof (nvl),
	    frudr_completion_handler) != 0) {
		free(ev_name);
		nvlist_free(nvl);
	}
}

/* Hotplug routine used to add a new power supply */
static int
add_power_supply(int slotnum)
{
	picl_nodehdl_t		powersloth;
	picl_nodehdl_t		powermodh;
	picl_nodehdl_t		tmph;
	int			i, err;

	/* Find the node for the given power supply slot */
	if (ptree_get_node_by_path(frutree_power_supply[slotnum],
	    &powersloth) == PICL_SUCCESS) {

		i = slotnum + PS0;

		/* Make sure it's in /platform and create the frutree node */
		if (ptree_get_node_by_path(platform_frupath[i], &tmph) ==
		    PICL_SUCCESS) {
			err = ptree_create_node("power-supply", "fru",
			    &powermodh);
			if (err != PICL_SUCCESS)
				return (err);

			err = add_ref_prop(powermodh, tmph, SEEPROM_SOURCE);
			if (err != PICL_SUCCESS)
				return (err);

			err = add_void_fda_prop(powermodh);
			if (err != PICL_SUCCESS)
				return (err);

			err = ptree_add_node(powersloth, powermodh);
			if (err != PICL_SUCCESS)
				return (err);

			err = add_ref_prop(tmph, powermodh, FRU_PARENT);
			if (err != PICL_SUCCESS)
				return (err);

			/* Post picl-fru-added event */
			post_frudr_event(PICL_FRU_ADDED, 0, powermodh);
		}
	}
	return (PICL_SUCCESS);
}

/* Hotplug routine used to remove an existing power supply */
static int
remove_power_supply(int slotnum)
{
	picl_nodehdl_t		powersloth;
	picl_nodehdl_t		powermodh;
	int			err;

	/* Find the node for the given power supply slot */
	if (ptree_get_node_by_path(frutree_power_supply[slotnum],
	    &powersloth) == PICL_SUCCESS) {
		/* Make sure it's got a child, then delete it */
		err = ptree_get_propval_by_name(powersloth, PICL_PROP_CHILD,
		    &powermodh, sizeof (picl_nodehdl_t));
		if (err != PICL_SUCCESS) {
			return (err);
		}

		err = ptree_delete_node(powermodh);
		if (err != PICL_SUCCESS) {
			return (err);
		}
		(void) ptree_destroy_node(powermodh);
		/* Post picl-fru-removed event */
		post_frudr_event(PICL_FRU_REMOVED, 0, powermodh);
	}
	return (PICL_SUCCESS);
}
