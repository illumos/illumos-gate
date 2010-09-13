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
 * Copyright (c) 1999-2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * PICL plug-in that creates the FRU Hierarchy for the
 * SUNW,Sun-Fire-280R (Littleneck) platform
 */

#include <stdio.h>
#include <string.h>
#include <libintl.h>
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
#define	SYSBRD_INIT_FAIL	gettext("do_sysboard_init() failed\n")
#define	CPUS_INIT_FAIL		gettext("do_cpus_init() failed\n")
#define	DIMMS_INIT_FAIL		gettext("do_mem_init() failed\n")
#define	PS_INIT_FAIL		gettext("do_power_supplies_init() failed\n")
#define	FCAL_INIT_FAIL		gettext("do_fcal_init() failed\n")
#define	RSC_INIT_FAIL		gettext("do_rscboard_init() failed\n")

/*
 * ViewPoints property field used by SunMC
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
#define	CPU0	0
#define	CPU1	1
#define	DIMM0	2
#define	DIMM1	3
#define	DIMM2	4
#define	DIMM3	5
#define	DIMM4	6
#define	DIMM5	7
#define	DIMM6	8
#define	DIMM7	9
#define	PDB	10
#define	PS0	11
#define	PS1	12
#define	FCAL	13
#define	RSC	14
#define	SYSBRD	15

/*
 * Local variables
 */
static picld_plugin_reg_t  my_reg_info = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_NON_CRITICAL,
	"SUNW_Sun-Fire-280R_frutree",
	picl_frutree_init,
	picl_frutree_fini,
};

/*
 * List of all the FRUs in the /platform tree with SEEPROMs
 */
static char *platform_frupath[] = {
	"/platform/pci@8,700000/ebus@5/i2c@1,30/cpu-fru@0,a0",
	"/platform/pci@8,700000/ebus@5/i2c@1,30/cpu-fru@0,a2",
	"/platform/pci@8,700000/ebus@5/i2c@1,2e/dimm-fru@1,a0",
	"/platform/pci@8,700000/ebus@5/i2c@1,2e/dimm-fru@1,a2",
	"/platform/pci@8,700000/ebus@5/i2c@1,2e/dimm-fru@1,a4",
	"/platform/pci@8,700000/ebus@5/i2c@1,2e/dimm-fru@1,a6",
	"/platform/pci@8,700000/ebus@5/i2c@1,2e/dimm-fru@1,a8",
	"/platform/pci@8,700000/ebus@5/i2c@1,2e/dimm-fru@1,aa",
	"/platform/pci@8,700000/ebus@5/i2c@1,2e/dimm-fru@1,ac",
	"/platform/pci@8,700000/ebus@5/i2c@1,2e/dimm-fru@1,ae",
	"/platform/pci@8,700000/ebus@5/i2c@1,30/power-distribution-board@0,aa",
	"/platform/pci@8,700000/ebus@5/i2c@1,30/power-supply@0,ac",
	"/platform/pci@8,700000/ebus@5/i2c@1,30/power-supply@0,ae",
	"/platform/pci@8,700000/ebus@5/i2c@1,30/fcal-backplane@0,a4",
	"/platform/pci@8,700000/ebus@5/i2c@1,30/remote-system-console@0,a6",
	"/platform/pci@8,700000/ebus@5/i2c@1,30/motherboard-fru@0,a8",
	NULL};

/*
 * List of all the FRU slots in the frutree that can be hotplugged
 */
static char *frutree_power_supply[] = {
	"/frutree/chassis/power-dist-board/power-supply-slot?Slot=0",
	"/frutree/chassis/power-dist-board/power-supply-slot?Slot=1",
	NULL};

/*
 * List of Labels for FRU locations (uses the #define's from above)
 */
static char *location_label[] = {
	"0",
	"1",
	"J0100",
	"J0101",
	"J0202",
	"J0203",
	"J0304",
	"J0305",
	"J0406",
	"J0407",
	NULL,			/* power distribution board placeholder */
	"0",
	"1",
	NULL};

/* PICL handle for the root node of the "frutree" */
static picl_nodehdl_t	frutreeh;

static int	do_sysboard_init(picl_nodehdl_t, picl_nodehdl_t *);
static int	do_cpus_init(picl_nodehdl_t);
static int	do_mem_init(picl_nodehdl_t);
static int	do_power_supplies_init(picl_nodehdl_t);
static int	do_fcal_init(picl_nodehdl_t);
static int	do_rscboard_init(picl_nodehdl_t);

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
void
picl_frutree_register()
{
	(void) picld_plugin_register(&my_reg_info);
}

/*
 * This function is the init entry point of the plugin.
 * It initializes the /frutree tree
 */
void
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
void
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

/* Initialize the FRU node for the system board */
static int
do_sysboard_init(picl_nodehdl_t rooth, picl_nodehdl_t *childh)
{
	picl_nodehdl_t		tmph;
	int			err;

	/* Create the node for the system board */
	if (ptree_get_node_by_path(platform_frupath[SYSBRD], &tmph) ==
	    PICL_SUCCESS) {
		err = ptree_create_node("system-board", "fru", childh);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_ref_prop(*childh, tmph, SEEPROM_SOURCE);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_void_fda_prop(*childh);
		if (err != PICL_SUCCESS)
			return (err);

		err = ptree_add_node(rooth, *childh);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_ref_prop(tmph, *childh, FRU_PARENT);
		if (err != PICL_SUCCESS)
			return (err);

	}
	return (PICL_SUCCESS);
}

/* Initializes the FRU nodes for the CPU modules */
static int
do_cpus_init(picl_nodehdl_t rooth)
{
	picl_nodehdl_t		cpusloth;
	picl_nodehdl_t		cpumodh;
	picl_nodehdl_t		tmph;
	int			i, err;

	for (i = CPU0; i <= CPU1; i++) {
		/* Create the node for the CPU slot */
		err = ptree_create_node("cpu-slot", "location", &cpusloth);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_slot_prop(cpusloth, i);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_label_prop(cpusloth, location_label[i]);
		if (err != PICL_SUCCESS)
			return (err);

		err = ptree_add_node(rooth, cpusloth);
		if (err != PICL_SUCCESS)
			return (err);

		/* If the CPU module exists, create a node for it */
		if (ptree_get_node_by_path(platform_frupath[i], &tmph) ==
		    PICL_SUCCESS) {
			err = ptree_create_node("cpu-module", "fru", &cpumodh);
			if (err != PICL_SUCCESS)
				return (err);

			err = add_ref_prop(cpumodh, tmph, SEEPROM_SOURCE);
			if (err != PICL_SUCCESS)
				return (err);

			err = add_void_fda_prop(cpumodh);
			if (err != PICL_SUCCESS)
				return (err);

			err = ptree_add_node(cpusloth, cpumodh);
			if (err != PICL_SUCCESS)
				return (err);

			err = add_ref_prop(tmph, cpumodh, FRU_PARENT);
			if (err != PICL_SUCCESS)
				return (err);
		}
	}
	return (PICL_SUCCESS);
}

/* Initializes the FRU nodes for the memory modules */
static int
do_mem_init(picl_nodehdl_t rooth)
{
	picl_nodehdl_t		memsloth;
	picl_nodehdl_t		memmodh;
	picl_nodehdl_t		tmph;
	int			i, err, slotnum;

	for (i = DIMM0; i <= DIMM7; i++) {
		/* Create the node for the memory slot */
		err = ptree_create_node("mem-slot", "location", &memsloth);
		if (err != PICL_SUCCESS)
			return (err);

		slotnum = i - DIMM0;
		err = add_slot_prop(memsloth, slotnum);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_label_prop(memsloth, location_label[i]);
		if (err != PICL_SUCCESS)
			return (err);

		err = ptree_add_node(rooth, memsloth);
		if (err != PICL_SUCCESS)
			return (err);

		/* If the memory exists, create a node for it */
		if (ptree_get_node_by_path(platform_frupath[i], &tmph) ==
		    PICL_SUCCESS) {
			err = ptree_create_node("mem-module", "fru", &memmodh);
			if (err != PICL_SUCCESS)
				return (err);

			err = add_ref_prop(memmodh, tmph, SEEPROM_SOURCE);
			if (err != PICL_SUCCESS)
				return (err);

			err = add_void_fda_prop(memmodh);
			if (err != PICL_SUCCESS)
				return (err);

			err = ptree_add_node(memsloth, memmodh);
			if (err != PICL_SUCCESS)
				return (err);

			err = add_ref_prop(tmph, memmodh, FRU_PARENT);
			if (err != PICL_SUCCESS)
				return (err);
		}
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

/* Initializes the FRU nodes for the FCAL backplane */
static int
do_fcal_init(picl_nodehdl_t rooth)
{
	picl_nodehdl_t		fcalbrdh;
	picl_nodehdl_t		tmph;
	int			err;

	/* Create the node for the FCAL backplane (if it exists) */
	if (ptree_get_node_by_path(platform_frupath[FCAL], &tmph) ==
	    PICL_SUCCESS) {
		err = ptree_create_node("fcal-backplane", "fru", &fcalbrdh);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_ref_prop(fcalbrdh, tmph, SEEPROM_SOURCE);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_void_fda_prop(fcalbrdh);
		if (err != PICL_SUCCESS)
			return (err);

		err = ptree_add_node(rooth, fcalbrdh);
		if (err != PICL_SUCCESS)
			return (err);

		err = add_ref_prop(tmph, fcalbrdh, FRU_PARENT);
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

/* Creates a "Slot" property for a given PICL node */
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
	picl_nodehdl_t	sysboardh;
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

	/* Initialize the FRU node for the system board */
	err = do_sysboard_init(chassish, &sysboardh);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, SYSBRD_INIT_FAIL);
		return (err);
	}

	/* Initialize the FRU nodes for the CPU modules */
	err = do_cpus_init(sysboardh);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, CPUS_INIT_FAIL);
		return (err);
	}

	/* Initialize the FRU nodes for the memory modules */
	err = do_mem_init(sysboardh);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, DIMMS_INIT_FAIL);
		return (err);
	}

	/* Initialize the FRU nodes for the PDB and the power supplies */
	err = do_power_supplies_init(chassish);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, PS_INIT_FAIL);
		return (err);
	}

	/* Initialize the FRU nodes for the FCAL backplane */
	err = do_fcal_init(chassish);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, FCAL_INIT_FAIL);
		return (err);
	}

	/* Initialize the FRU node for the RSC card */
	err = do_rscboard_init(chassish);
	if (err != PICL_SUCCESS) {
		syslog(LOG_ERR, RSC_INIT_FAIL);
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

/*
 * Searches the list of hotpluggable FRUs for this platform and adds the
 * appropriate node(s) to the frutree
 */
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

/*
 * Searches the list of hotpluggable FRUs for this platform and removes the
 * appropriate node(s) from the frutree
 */
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
		return (PICL_FAILURE);

	return (PICL_SUCCESS);
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
		} else {
			(void) ptree_destroy_node(powermodh);
		}
	}
	return (PICL_SUCCESS);
}
