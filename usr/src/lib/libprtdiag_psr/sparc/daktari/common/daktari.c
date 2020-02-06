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
 * Copyright 2020 Peter Tribble.
 */

/*
 * Daktari Platform specific functions.
 *
 *	called when :
 *      machine_type ==  MTYPE_DAKTARI
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <kstat.h>
#include <string.h>
#include <assert.h>
#include <libintl.h>
#include <note.h>

#include <sys/openpromio.h>
#include <sys/sysmacros.h>
#include <sys/daktari.h>

#include <pdevinfo.h>
#include <display.h>
#include <pdevinfo_sun4u.h>
#include <display_sun4u.h>
#include <libprtdiag.h>

#include <picl.h>
#include "workfile.c"

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

#define	DAK_MAX_SLOTS_PER_IO_BD		9
#define	DAK_MAX_DISKS			12
#define	DAK_MAX_FSP_LEDS		2
#define	DAK_MAX_PS			3
#define	DAK_MAX_PS_VOLTAGE_SENSORS	4
#define	DAK_MAX_PS_FAULT_SENSORS	3
#define	DAK_MAX_FANS			10
#ifndef SCHIZO_COMPAT_PROP
#define	SCHIZO_COMPAT_PROP		"pci108e,8001"
#endif

#define	MULTIPLE_BITS_SET(x)		((x)&((x)-1))

extern	int	print_flag;

/*
 * these functions will overlay the symbol table of libprtdiag
 * at runtime (workgroup server systems only)
 */
void	display_cpu_devices(Sys_tree *tree);
void	display_cpus(Board_node *board);
void	display_pci(Board_node *board);
void	display_io_cards(struct io_card *list);
void	display_diaginfo(int flag, Prom_node *root, Sys_tree *tree,
				struct system_kstat_data *kstats);
void	display_ffb(Board_node *board, int table);
void	display_memoryconf(Sys_tree *tree);

/* local functions */
static	int disp_envc_status(void);
static	int dak_env_print_temps(picl_nodehdl_t);
static	int dak_env_print_keyswitch(picl_nodehdl_t);
static	int dak_env_print_FSP_LEDS(picl_nodehdl_t);
static	int dak_env_print_disk(picl_nodehdl_t);
static	int dak_env_print_fans(picl_nodehdl_t);
static	int dak_env_print_ps(picl_nodehdl_t);

static void dak_display_hw_revisions(Prom_node *root,
					Board_node *bnode);
static void display_schizo_revisions(Board_node *bdlist);


/*
 * Defining the error_check function in order to return the
 * appropriate error code.
 */
/*ARGSUSED0*/
int
error_check(Sys_tree *tree, struct system_kstat_data *kstats)
{
	int exit_code = 0;	/* init to all OK */
	/*
	 * silently check for any types of machine errors
	 */
	print_flag = 0;
	if (disp_fail_parts(tree)) {
		/* set exit_code to show failures */
		exit_code = 1;
	}
	print_flag = 1;

	return (exit_code);
}

/*
 * disp_fail_parts
 *
 * Display the failed parts in the system. This function looks for
 * the status property in all PROM nodes. On systems where
 * the PROM does not support passing diagnostic information
 * through the device tree, this routine will be silent.
 */
int
disp_fail_parts(Sys_tree *tree)
{
	int exit_code = 0;
	int system_failed = 0;
	Board_node *bnode = tree->bd_list;
	Prom_node *pnode;

	/* go through all of the boards looking for failed units. */
	while (bnode != NULL) {
		/* find failed chips */
		pnode = find_failed_node(bnode->nodes);
		if ((pnode != NULL) && !system_failed) {
			system_failed = 1;
			exit_code = 1;
			if (print_flag == 0) {
				return (exit_code);
			}
			log_printf("\n");
			log_printf(dgettext(TEXT_DOMAIN, "Failed Field "
			    "Replaceable Units (FRU) in System:\n"));
			log_printf("=========================="
			    "====================\n");
		}
		while (pnode != NULL) {
			void *value;
			char *name;		/* node name string */
			char *type;		/* node type string */
			char *board_type = NULL;

			value = get_prop_val(find_prop(pnode, "status"));
			name = get_node_name(pnode);

			/* sanity check of data retrieved from PROM */
			if ((value == NULL) || (name == NULL)) {
				pnode = next_failed_node(pnode);
				continue;
			}

			/* Find the board type of this board */
			if (bnode->board_type == CPU_BOARD) {
				board_type = "CPU";
			} else {
				board_type = "IO";
			}

			log_printf(dgettext(TEXT_DOMAIN, "%s unavailable "
			    "on %s Board #%d\n"), name, board_type,
			    bnode->board_num);

			log_printf(dgettext(TEXT_DOMAIN,
			    "\tPROM fault string: %s\n"), value);

			log_printf(dgettext(TEXT_DOMAIN,
			    "\tFailed Field Replaceable Unit is "));

			/*
			 * Determine whether FRU is CPU module, system
			 * board, or SBus card.
			 */
			if ((name != NULL) && (strstr(name, "sbus"))) {

				log_printf(dgettext(TEXT_DOMAIN,
				    "SBus Card %d\n"),
				    get_sbus_slot(pnode));

			} else if (((name = get_node_name(pnode->parent)) !=
			    NULL) && (strstr(name, "pci"))) {

				log_printf(dgettext(TEXT_DOMAIN,
				    "PCI Card %d"),
				    get_pci_device(pnode));

			} else if (((type = get_node_type(pnode)) != NULL) &&
			    (strstr(type, "cpu"))) {

				log_printf(dgettext(TEXT_DOMAIN, "UltraSPARC "
				    "module Board %d Module %d\n"), 0,
				    get_id(pnode));

			} else {
				log_printf(dgettext(TEXT_DOMAIN,
				    "%s board %d\n"), board_type,
				    bnode->board_num);
			}
			pnode = next_failed_node(pnode);
		}
		bnode = bnode->next;
	}

	if (!system_failed) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "No failures found in System\n"));
		log_printf("===========================\n\n");
	}

	if (system_failed)
		return (1);
	else
		return (0);
}

/*ARGSUSED*/
void
display_hp_fail_fault(Sys_tree *tree, struct system_kstat_data *kstats)
{
	/* Display failed units */
	(void) disp_fail_parts(tree);
}

void
display_memoryconf(Sys_tree *tree)
{
	Board_node	*bnode = tree->bd_list;

	log_printf(dgettext(TEXT_DOMAIN,
	    "========================= Memory Configuration"
	    " ===============================\n"
	    "\n           Logical  Logical"
	    "  Logical "
	    "\n      MC   Bank     Bank     Bank"
	    "         DIMM    Interleave  Interleaved"
	    "\n Brd  ID   num      size     "
	    "Status       Size    "
	    "Factor      with"
	    "\n----  ---  ----     ------   "
	    "-----------  ------  "
	    "----------  -----------"));

	while (bnode != NULL) {
		if (get_us3_mem_regs(bnode)) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "\nFailed to get memory information.\n"));
			return;
		}
		bnode = bnode->next;
	}

	/* Display what we have found */
	display_us3_banks();
}

void
display_cpu_devices(Sys_tree *tree)
{
	Board_node *bnode;

	/*
	 * Display the table header for CPUs . Then display the CPU
	 * frequency, cache size, and processor revision of all cpus.
	 */
	log_printf(dgettext(TEXT_DOMAIN,
	    "\n"
	    "========================="
	    " CPUs "
	    "==============================================="
	    "\n"
	    "\n"
	    "           Run   E$  CPU    CPU  \n"
	    "Brd  CPU   MHz   MB Impl.   Mask \n"
	    "--- ----- ---- ---- ------- ---- \n"));

	/* Now display all of the cpus on each board */
	bnode = tree->bd_list;
	if (bnode == NULL) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "CPU Board list was NULL\n"));
	}
	while (bnode != NULL) {
		display_cpus(bnode);
		bnode = bnode->next;
	}

	log_printf("\n");
}

/*
 * Display the CPUs present on this board.
 */
void
display_cpus(Board_node *board)
{
	Prom_node 	*cpu;
	uint_t freq;	 /* CPU clock frequency */
	int ecache_size; /* External cache size */
	int *l3_shares;
	int *mid;
	int *impl;
	int *mask;
	int *coreid;
	char fru_prev = 'X'; /* Valid frus are 'A','B','C','D' */
	int mid_prev;
	int ecache_size_prev = 0;
	char fru_name;

	/*
	 * display the CPUs' operating frequency, cache size, impl. field
	 * and mask revision.
	 */
	for (cpu = dev_find_type(board->nodes, "cpu"); cpu != NULL;
	    cpu = dev_next_type(cpu, "cpu")) {

		mid = (int *)get_prop_val(find_prop(cpu, "portid"));
		if (mid == NULL)
			mid = (int *)get_prop_val(find_prop(cpu, "cpuid"));
		freq = DAK_CLK_FREQ_TO_MHZ(get_cpu_freq(cpu));
		ecache_size = get_ecache_size(cpu);
		impl = (int *)get_prop_val(find_prop(cpu, "implementation#"));
		mask = (int *)get_prop_val(find_prop(cpu, "mask#"));
		l3_shares = (int *)get_prop_val(find_prop(cpu,
		    "l3-cache-sharing"));

		/* Do not display a failed CPU node */
		if ((impl == NULL) || (freq == 0) || (node_failed(cpu)))
			continue;

		/* Board number */
		fru_name = (char)('A' + DAK_GETSLOT(*mid));

		if (CPU_IMPL_IS_CMP(*impl)) {
			coreid = (int *)get_prop_val(find_prop(cpu, "reg"));
			if (coreid == NULL) {
				continue;
			}
			if ((fru_prev == 'X') ||
			    ((fru_prev != 'X') &&
			    (fru_name != fru_prev))) {
				fru_prev = fru_name;
				mid_prev = *mid;
				ecache_size_prev = ecache_size;
				continue;
			} else {
				/*
				 * Some CMP chips have a split E$,
				 * so the size for both cores is added
				 * together to get the total size for
				 * the chip.
				 *
				 * Still, other CMP chips have E$ (L3)
				 * which is logically shared, so the
				 * total size is equal to the core size.
				 */
				if ((l3_shares == NULL) ||
				    ((l3_shares != NULL) &&
				    MULTIPLE_BITS_SET(*l3_shares))) {
					ecache_size += ecache_size_prev;
				}
				ecache_size_prev = 0;
				fru_prev = 'X';
			}
		}

		log_printf("%2c", fru_name);

		/* CPU Module ID */
		if (CPU_IMPL_IS_CMP(*impl)) {
			log_printf("%3d,%3d", mid_prev, *mid, 0);
		} else
			log_printf("    %d  ", *mid);

		/* Running frequency */
		log_printf(" %4u ", freq);

		/* Ecache size */
		if (ecache_size == 0)
			log_printf(dgettext(TEXT_DOMAIN, "%3s  "),
			    "N/A");
		else
			log_printf("%4.1f ",
			    (float)ecache_size / (float)(1<<20));

		/* Implementation */
		if (impl == NULL) {
			log_printf(dgettext(TEXT_DOMAIN, "%s    "),
			"N/A");
		} else {
			if (IS_CHEETAH(*impl))
				log_printf("%7s", "US-III ", 0);
			else if (IS_CHEETAH_PLUS(*impl))
				log_printf("%7s", "US-III+", 0);
			else if (IS_JAGUAR(*impl))
				log_printf("%7s", "US-IV  ", 0);
			else if (IS_PANTHER(*impl))
				log_printf("%7s", "US-IV+ ", 0);
			else
				log_printf("%-7x", *impl, 0);
		}

		/* CPU Mask */
		if (mask == NULL) {
			log_printf(dgettext(TEXT_DOMAIN, " %3s   "),
			"N/A");
		} else {
			log_printf(dgettext(TEXT_DOMAIN, " %2d.%d"),
			    (*mask >> 4) & 0xf, *mask & 0xf);
		}

		log_printf("\n");
	}
}

/*
 * display_pci
 * Display all the PCI IO cards on this board.
 */
void
display_pci(Board_node *board)
{
	struct io_card	*card_list = NULL;
	struct io_card	card;
	void		*value;
	Prom_node	*pci;
	Prom_node	*card_node;
	char		*slot_name_arr[DAK_MAX_SLOTS_PER_IO_BD] = {NULL};
	int		i;
#ifdef DEBUG
	int		slot_name_bits;
#endif

	if (board == NULL)
		return;

	memset(&card, 0, sizeof (struct io_card));
	/* Initialize all the common information */
	card.display = TRUE;
	card.board = board->board_num;

	/*
	 * Search for each pci instance, then find/display all nodes under
	 * each instance node found.
	 */
	for (pci = dev_find_node_by_compat(board->nodes, SCHIZO_COMPAT_PROP);
	    pci != NULL;
	    pci = dev_next_node_by_compat(pci, SCHIZO_COMPAT_PROP)) {
		(void) snprintf(card.bus_type, MAXSTRLEN,
		    dgettext(TEXT_DOMAIN, "PCI"));
		/*
		 * Get slot-name properties from parent node and
		 * store them in an array.
		 */
		value = (char *)get_prop_val(
		    find_prop(pci, "slot-names"));

		if (value != NULL) {
#ifdef DEBUG
			/* save the 4 byte bitmask */
			slot_name_bits = *(int *)value;
#endif

			/* array starts after first int */
			slot_name_arr[0] = (char *)value + sizeof (int);
			for (i = 1; i < DAK_MAX_SLOTS_PER_IO_BD; i++) {
				slot_name_arr[i] = (char *)slot_name_arr[i - 1]
				    + strlen(slot_name_arr[i - 1]) +1;
			}
		}
		/*
		 * Search for Children of this node ie. Cards.
		 * Note: any of these cards can be a pci-bridge
		 *	that itself has children. If we find a
		 *	pci-bridge we need to handle it specially.
		 */
		card_node = pci->child;
		/* Generate the list of pci cards on pci instance: pci */
		fill_pci_card_list(pci, card_node, &card, &card_list,
		    slot_name_arr);
	} /* end-for */

	display_io_cards(card_list);
	free_io_cards(card_list);
	log_printf("\n");
}

/*
 * Print out all the io cards in the list.  Also print the column
 * headers if told to do so.
 */
void
display_io_cards(struct io_card *list)
{
	static int banner = 0; /* Have we printed the column headings? */
	struct io_card *p;

	if (list == NULL)
		return;

	if (banner == FALSE) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "                         Bus  Max\n"
		    "     IO   Port Bus       Freq Bus  Dev,"
		    "\n"
		    "Brd  Type  ID  Side Slot MHz  Freq "
		    "Func State Name                              "
		    "Model\n"
		/* ---------Brd  IO   Port Bus  Slot Bus  Max  Dev  Stat */
		    "---- ---- ---- ---- ---- ---- ---- ----"
		    " ----- "
		    "--------------------------------  "
		    "----------------------\n"));
		banner = TRUE;
	}

	for (p = list; p != NULL; p = p -> next) {
		log_printf(dgettext(TEXT_DOMAIN, "I/O  "));
		log_printf("%-4s  ", p->bus_type);
		log_printf("%-3d  ", p->schizo_portid);
		log_printf("%c    ", p->pci_bus);
		log_printf("%-1s    ", p->slot_str);
		log_printf("%-3d ", p->freq);
		switch (p->pci_bus) {
		case 'A':
			log_printf(dgettext(TEXT_DOMAIN, " 66  "));
			break;
		case 'B':
			log_printf(dgettext(TEXT_DOMAIN, " 33  "));
			break;
		default:
			log_printf(dgettext(TEXT_DOMAIN, "  -  "));
			break;
		}

		log_printf("%-1d,%-1d  ", p->dev_no, p->func_no);
		log_printf("%-5s ", p->status);
		log_printf("%-32.32s", p->name);
		if (strlen(p->name) > 32)
			log_printf(dgettext(TEXT_DOMAIN, "+ "));
		else
			log_printf(dgettext(TEXT_DOMAIN, "  "));
		log_printf("%-22.22s", p->model);
		if (strlen(p->model) > 22)
			log_printf(dgettext(TEXT_DOMAIN, "+"));

#ifdef DEBUG
		log_printf(dgettext(TEXT_DOMAIN, "%s  "), p->notes);
#endif
		log_printf("\n");
	}
}

/*
 * display_ffb
 *
 * There are no FFB's on a Daktari, however in the generic library,
 * the display_ffb() function is implemented so we have to define an
 * empty function here.
 */
/* ARGSUSED */
void
display_ffb(Board_node *board, int table)
{}


/*
 * ----------------------------------------------------------------------------
 */

/* ARGSUSED */
void
display_diaginfo(int flag, Prom_node *root, Sys_tree *tree,
	struct system_kstat_data *kstats)
{
	/* NOTE(ARGUNUSED(kstats)) */
	/*
	 * Now display the last powerfail time and the fatal hardware
	 * reset information. We do this under a couple of conditions.
	 * First if the user asks for it. The second is if the user
	 * told us to do logging, and we found a system failure.
	 */
	if (flag) {
		/*
		 * display time of latest powerfail. Not all systems
		 * have this capability. For those that do not, this
		 * is just a no-op.
		 */
		disp_powerfail(root);

		(void) disp_envc_status();

		/* platform_disp_prom_version(tree); */
		dak_display_hw_revisions(root, tree->bd_list);
	}
}

/*
 * local functions
 */

/*
 * disp_envc_status
 *
 * This routine displays the environmental status passed up from
 * device drivers via the envlibobj.so library.
 * This is a Daktari specific environmental information display routine.
 */
int
disp_envc_status()
{
	int err;
	char *system = "SYSTEM";
	picl_nodehdl_t system_node, root;

	err = picl_initialize();
	if (err != PICL_SUCCESS) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "picl_initialize failed\n"
		    "%s\nCannot display environmental status\n"),
		    picl_strerror(err));
		return (err);
	}
	err = picl_get_root(&root);
	err = find_child_device(root, system, &system_node);
	if (err != PICL_SUCCESS) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "picl_get_node_by_path for the SYSTEM node "
		    "failed\n"
		    "%s\nCannot display environmental status\n"),
		    picl_strerror(err));
		return (err);
	}

	log_printf(dgettext(TEXT_DOMAIN,
	    "\n"
	    "========================= "
	    "Environmental Status "
	    "========================="
	    "\n"
	    "\n"));

	dak_env_print_temps(system_node);
	dak_env_print_keyswitch(system_node);
	dak_env_print_FSP_LEDS(system_node);
	dak_env_print_disk(system_node);
	dak_env_print_fans(system_node);
	dak_env_print_ps(system_node);

	(void) picl_shutdown();
	return (0);
}

int
dak_env_print_ps(picl_nodehdl_t system_node)
{
	int		i, r, fail, err = 0;
	int		low_warn_flag = 0;
	int32_t		number;
	char		name[PICL_PROPNAMELEN_MAX];
	picl_nodehdl_t	*ps;
	picl_nodehdl_t	*ps_fail[DAK_MAX_PS_FAULT_SENSORS];
	picl_nodehdl_t	*ps_I_sensor[DAK_MAX_PS_VOLTAGE_SENSORS];
	int32_t		volts[DAK_MAX_PS_VOLTAGE_SENSORS];
	int32_t		lo_warn[DAK_MAX_PS_VOLTAGE_SENSORS];
	char		fault_state
	    [DAK_MAX_PS_FAULT_SENSORS][PICL_PROPNAMELEN_MAX];
	char		ps_state[PICL_PROPNAMELEN_MAX];
	/* Printing out the Power Supply Heading information */
	log_printf(dgettext(TEXT_DOMAIN,
	    "Power Supplies:\n"
	    "---------------\n"
	    "                                                    "
	    "Current Drain:\n"
	    "Supply     Status     Fan Fail  Temp Fail  CS Fail  "
	    "3.3V   5V   12V   48V\n"
	    "------  ------------  --------  ---------  "
	    "-------  ----   --   ---   ---\n"));

	err = fill_device_array_from_id(system_node, "PSVC_PS", &number,
	    &ps);
	if (err != PICL_SUCCESS) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "failed in fill_device_array_from_id for PS\n"
		    "%s\n"), picl_strerror(err));
		return (err);
	}
	/* Printing out the Power Supply Status information */
	for (i = 0; i < DAK_MAX_PS; i++) {
		/*
		 * Re initialize the fail variable so that if
		 * one power supply fails, they don't all do also.
		 */
		fail = 0;

		err = picl_get_propval_by_name(ps[i], PICL_PROP_NAME, name,
		    PICL_PROPNAMELEN_MAX);
		if (err != PICL_SUCCESS) {
			continue;
		}
		err = picl_get_propval_by_name(ps[i], "State", ps_state,
		    PICL_PROPNAMELEN_MAX);
		if (err != PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "Error getting ps[%d]'s state: %s"),
			    i, picl_strerror(err));
		}

		err = fill_device_array_from_id(ps[i], "PSVC_DEV_FAULT_SENSOR",
		    &number, &ps_fail[i]);

		if (err != PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "failed to get present PS fault sensors\n"
			    "%s\n"), picl_strerror(err));
			return (err);
		}

		err = fill_device_array_from_id(ps[i], "PSVC_PS_I_SENSOR",
		    &number, &ps_I_sensor[i]);

		if ((err != PICL_SUCCESS) && (err != PICL_INVALIDHANDLE)) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "failed to get present PS I sensors\n"
			    "%s\n"), picl_strerror(err));
		}

		log_printf("%s", name);

		/*
		 * If the AC cord is unplugged, then the power supply
		 * sensors will have unreliable values.  In this case,
		 * skip to the next power supply.
		 */
		if (strcmp(ps_state, "HOTPLUGGED") == 0) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "      UNPLUGGED\n"));
			continue;
		}

		for (r = 0; r < DAK_MAX_PS_FAULT_SENSORS; r++) {
			err = picl_get_propval_by_name(ps_fail[i][r], "State",
			    fault_state[r], PICL_PROPNAMELEN_MAX);
			if (err == PICL_SUCCESS) {
				fail =
				    strcmp(fault_state[r], "OFF")
				    + fail;
			} else {
				log_printf(dgettext(TEXT_DOMAIN,
				    "picl_get_propval_by_name for ps "
				    "fault state failed\n"
				    "%s\n"), picl_strerror(err));
				return (err);
			}
		}
		for (r = 0; r < DAK_MAX_PS_VOLTAGE_SENSORS; r++) {
			err = picl_get_propval_by_name(ps_I_sensor[i][r],
			    "AtoDSensorValue", &volts[r],
			    sizeof (int32_t));
			if (err != PICL_SUCCESS) {
				log_printf(dgettext(TEXT_DOMAIN,
				    "failed to get A to D sensor "
				    "value\n%s\n"), picl_strerror(err));
				return (err);
			}
			err = picl_get_propval_by_name(ps_I_sensor[i][r],
			    "LowWarningThreshold", &lo_warn[r],
			    sizeof (int32_t));
			if (err != PICL_SUCCESS) {
				log_printf(dgettext(TEXT_DOMAIN,
				    "failed to get low warning threshold "
				    "value\n%s\n"), picl_strerror(err));
				return (err);
			}
			if (volts[r] <= lo_warn[r])
				low_warn_flag++;
		}

		if (fail != 0 || low_warn_flag != 0) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "      FAIL      "));
		} else {
			log_printf(dgettext(TEXT_DOMAIN, "      GOOD      "));
		}

		if (fail != 0) {
			for (r = 0; r < DAK_MAX_PS_FAULT_SENSORS; r++) {
				log_printf(dgettext(TEXT_DOMAIN, "      %-4s"),
				    fault_state[r]);
			}
		} else {
			for (r = 0; r < DAK_MAX_PS_FAULT_SENSORS; r++) {
				log_printf(dgettext(TEXT_DOMAIN, "          "));
			}
		}
		for (r = 0; r < DAK_MAX_PS_VOLTAGE_SENSORS; r++) {
			log_printf(dgettext(TEXT_DOMAIN, "    %2d"), volts[r]);
		}
		log_printf("\n");
	}
	log_printf("\n");
	return (err);
}

int
dak_env_print_fans(picl_nodehdl_t system_node)
{
	int		i, err = 0;
	int32_t		number, fan_speed;
	picl_nodehdl_t	*fans;
	char		name[PICL_PROPNAMELEN_MAX];
	char		enabled[PICL_PROPNAMELEN_MAX];

	err = fill_device_array_from_id(system_node, "PSVC_FAN", &number,
	    &fans);
	if (err != PICL_SUCCESS) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "failed in fill_device_array_from_id "
		    "for FAN\n"
		    "%s\n"), picl_strerror(err));
		return (err);
	}

	log_printf("\n");
	log_printf(dgettext(TEXT_DOMAIN,
	    "=================================\n"));
	log_printf("\n");
	log_printf(dgettext(TEXT_DOMAIN, "Fan Bank :\n"));
	log_printf(dgettext(TEXT_DOMAIN, "----------\n"));
	log_printf("\n");
	log_printf(dgettext(TEXT_DOMAIN, "Bank                        Speed "
	    "        Status        Fan State\n"));
	log_printf(dgettext(TEXT_DOMAIN, "                           ( RPMS )"
	    "	\n"));
	log_printf(dgettext(TEXT_DOMAIN, "----                       --------"
	    "      ---------      ---------\n"));


	for (i = 0; i < DAK_MAX_FANS; i++) {
		char fan_state[PICL_PROPNAMELEN_MAX];
		fan_speed = 0;
		err = picl_get_propval_by_name(fans[i], PICL_PROP_NAME, name,
		    PICL_PROPNAMELEN_MAX);
		if (err == PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN, "%16-s"), name);
		} else {
			continue;
		}

		err = picl_get_propval_by_name(fans[i], "Fan-speed",
		    &fan_speed, sizeof (int32_t));
		if ((err != PICL_SUCCESS) && (err != PICL_INVALIDHANDLE)) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "failed in picl_get_propval_by_name for "
			    "fan speed\n"
			    "%s\n"), picl_strerror(err));
			return (err);
		}

		if ((strcmp(name, "CPU0_PRIM_FAN") != 0) &&
		    (strcmp(name, "CPU1_PRIM_FAN") != 0)) {
			err = picl_get_propval_by_name(fans[i], "Fan-switch",
			    enabled, PICL_PROPNAMELEN_MAX);
			if ((err != PICL_SUCCESS) &&
			    (err != PICL_INVALIDHANDLE)) {
				log_printf(dgettext(TEXT_DOMAIN,
				    "failed in picl_get_propval_by_name for"
				    " fan enabled/disabled\n"
				    "%s\n"), picl_strerror(err));
				return (err);
			}
			/*
			 * Display the fan's speed and whether or not
			 * it's enabled.
			 */
			if (strcmp(enabled, "ON") == 0) {
				log_printf(dgettext(TEXT_DOMAIN,
				    "\t     %4d        [ENABLED]"),
				    fan_speed);
			} else {
				log_printf(dgettext(TEXT_DOMAIN,
				    "\t        0        [DISABLED]"));
			}

		} else {
			/* Display the fan's speed */
			log_printf(dgettext(TEXT_DOMAIN, "\t     %4d"),
			    fan_speed);
			log_printf(dgettext(TEXT_DOMAIN,
			    "        [ENABLED]"));
		}

		err = picl_get_propval_by_name(fans[i], "State", fan_state,
		    PICL_PROPNAMELEN_MAX);
		if (err != PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "picl_get_propval_by_name failed: %s"),
			    picl_strerror(err));
			return (err);
		}
		log_printf(dgettext(TEXT_DOMAIN, "\t    %s\n"), fan_state);
	}
	log_printf("\n");
	log_printf(dgettext(TEXT_DOMAIN,
	    "=================================\n"));
	log_printf("\n");

	return (err);
}

int
dak_env_print_disk(picl_nodehdl_t system_node)
{
	int		i, err;
	int32_t		number;
	picl_nodehdl_t	*disks;
	picl_nodehdl_t	disk_slots[DAK_MAX_DISKS];
	picl_nodehdl_t	disk_fault_leds[DAK_MAX_DISKS];
	picl_nodehdl_t	disk_remove_leds[DAK_MAX_DISKS];
	char		led_state[PICL_PROPNAMELEN_MAX];
	char		name[PICL_PROPNAMELEN_MAX];

	err = fill_device_array_from_id(system_node, "PSVC_DISK", &number,
	    &disks);
	if (err != PICL_SUCCESS) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "failed in fill_device_array_from_id for "
		    "DISK\n"
		    "%s\n"), picl_strerror(err));
		return (err);
	}

	log_printf(dgettext(TEXT_DOMAIN,
	    "Disk Status:\n"
	    "	  Presence	Fault LED	Remove LED\n"));

	for (i = 0; i < DAK_MAX_DISKS; i++) {
		err = picl_get_propval_by_name(disks[i], PICL_PROP_NAME, name,
		    PICL_PROPNAMELEN_MAX);
		switch (err) {
		case PICL_SUCCESS:
			log_printf(dgettext(TEXT_DOMAIN, "DISK  %2d: [%7s]"),
			    i, "PRESENT");
			break;
		case PICL_INVALIDHANDLE:
			log_printf(dgettext(TEXT_DOMAIN, "DISK  %2d: [%7s]"),
			    i, "EMPTY");
			log_printf("\n");
			continue;
		default:
			log_printf(dgettext(TEXT_DOMAIN,
			    "Failed picl_get_propval_by_name for "
			    "disk %d with %s\n"), i, picl_strerror(err));
			return (err);
		}

		err = fill_device_from_id(disks[i], "PSVC_PARENT",
		    &(disk_slots[i]));
		switch (err) {
		case PICL_SUCCESS:
			break;
		case PICL_INVALIDHANDLE:
			continue;
		default:
			log_printf(dgettext(TEXT_DOMAIN,
			    "failed in fill_device_from_id for disk "
			    "slot\n"
			    "%s\n"), picl_strerror(err));
			return (err);
		}

		err = fill_device_from_id(disk_slots[i], "PSVC_SLOT_FAULT_LED",
		    &disk_fault_leds[i]);
		if (err != PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "failed in fill_device_from_id for disk slot "
			    "fault led\n"
			    "%s\n"), picl_strerror(err));
			return (err);
		}
		err = picl_get_propval_by_name(disk_fault_leds[i],
		    "State", led_state, PICL_PROPNAMELEN_MAX);
		if (err == PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN, "	   [%3s]"),
			    led_state);
		} else {
			log_printf(dgettext(TEXT_DOMAIN,
			    "picl_get_propval_by_name for fault led_state"
			    " failed\n"
			    "%s\n"), picl_strerror(err));
			return (err);
		}
		err = fill_device_from_id(disk_slots[i], "PSVC_SLOT_REMOVE_LED",
		    &disk_remove_leds[i]);
		if (err != PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "failed in fill_device_from_id for disk slot "
			    "remove led\n"
			    "%s\n"), picl_strerror(err));
			return (err);
		}

		err = picl_get_propval_by_name(disk_remove_leds[i],
		    "State", led_state, PICL_PROPNAMELEN_MAX);
		if (err == PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "	   [%3s]"), led_state);
		} else {
			log_printf(dgettext(TEXT_DOMAIN,
			    "picl_get_propval_by_name for remove"
			    " led_state failed\n"
			    "%s\n"), picl_strerror(err));
			return (err);
		}
		log_printf("\n");
	}
	return (err);
}

int
dak_env_print_FSP_LEDS(picl_nodehdl_t system_node)
{
	int		i, err = 0;
	int32_t		number;
	picl_nodehdl_t	*fsp_leds;
	char		led_state[PICL_PROPNAMELEN_MAX];

	err = fill_device_array_from_id(system_node, "PSVC_FSP_LED", &number,
	    &fsp_leds);
	if (err != PICL_SUCCESS) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "failed in fill_device_array_from_id for "
		    "FSP_LED\n"
		    "%s\n"), picl_strerror(err));
		return (err);
	}

	log_printf(dgettext(TEXT_DOMAIN,
	    "System LED Status:\n"
	    "                   GEN FAULT                REMOVE\n"));
	for (i = 0; i < DAK_MAX_FSP_LEDS; i++) {
		err = picl_get_propval_by_name(fsp_leds[i], "State",
		    led_state, PICL_PROPNAMELEN_MAX);
		if (err != PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "picl_get_propval_by_name for led_state"
			    " failed\n"
			    "%s\n"), picl_strerror(err));
			return (err);
		}

		log_printf(dgettext(TEXT_DOMAIN,
		    "                    [%3s]"), led_state);
	}
	log_printf("\n\n");
	log_printf(dgettext(TEXT_DOMAIN,
	    "                   DISK FAULT               "));
	log_printf(dgettext(TEXT_DOMAIN, "POWER FAULT\n"));
	for (i = 2; i < 4; i++) {
		err = picl_get_propval_by_name(fsp_leds[i], "State",
		    led_state, PICL_PROPNAMELEN_MAX);
		if (err != PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "picl_get_propval_by_name for led_state"
			    " failed\n"
			    "%s\n"), picl_strerror(err));
			return (err);
		}
		log_printf(dgettext(TEXT_DOMAIN, "                    [%3s]"),
		    led_state);
	}
	log_printf("\n\n");
	log_printf(dgettext(TEXT_DOMAIN,
	    "                   LEFT THERMAL FAULT       "
	    "RIGHT THERMAL FAULT\n"));
	for (i = 4; i < 6; i++) {
		err = picl_get_propval_by_name(fsp_leds[i], "State",
		    led_state, PICL_PROPNAMELEN_MAX);
		if (err != PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "picl_get_propval_by_name for led_state "
			    "failed\n"
			    "%s\n"), picl_strerror(err));
			return (err);
		}
		log_printf(dgettext(TEXT_DOMAIN, "                    [%3s]"),
		    led_state);
	}
	log_printf("\n\n");
	log_printf(dgettext(TEXT_DOMAIN,
	    "                   LEFT DOOR                "
	    "RIGHT DOOR\n"));
	for (i = 6; i < 8; i++) {
		err = picl_get_propval_by_name(fsp_leds[i], "State",
		    led_state, PICL_PROPNAMELEN_MAX);
		if (err != PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "picl_get_propval_by_name for led_state"
			    " failed\n"
			    "%s\n"), picl_strerror(err));
			return (err);
		}
		log_printf(dgettext(TEXT_DOMAIN, "                    [%3s]"),
		    led_state);
	}
	log_printf("\n\n");
	log_printf(dgettext(TEXT_DOMAIN,
	    "=================================\n"));
	log_printf("\n");

	return (err);
}

int
dak_env_print_keyswitch(picl_nodehdl_t system_node)
{
	int 		err = 0;
	picl_nodehdl_t *keyswitch;
	int32_t		number;
	char		ks_pos[PICL_PROPNAMELEN_MAX];

	err = fill_device_array_from_id(system_node, "PSVC_KEYSWITCH", &number,
	    &keyswitch);
	if (err != PICL_SUCCESS) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "failed in fill_device_array_from_id for "
		    "	PSVC_KEYSWITCH\n"
		    "%s\n"), picl_strerror(err));
		return (err);
	}

	err = picl_get_propval_by_name(keyswitch[0], "State", ks_pos,
	    PICL_PROPNAMELEN_MAX);
	if (err != PICL_SUCCESS) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "picl_get_propval_by_name for keyswitch state "
		    "failed\n"
		    "%s\n"), picl_strerror(err));
		return (err);
	}

	log_printf(dgettext(TEXT_DOMAIN,
	    "Front Status Panel:\n"
	    "-------------------\n"
	    "Keyswitch position: "
	    "%s\n"), ks_pos);
	log_printf("\n");

	return (err);
}

int
dak_env_print_temps(picl_nodehdl_t system_node)
{
	int		i;
	int		err;
	picl_nodehdl_t	*system_ts_nodes;
	int32_t		temp;
	int32_t		number;
	char		label[PICL_PROPNAMELEN_MAX];
	char		state[PICL_PROPNAMELEN_MAX];
	char		*p;

	err = fill_device_array_from_id(system_node, "PSVC_TS", &number,
	    &system_ts_nodes);
	if (err != PICL_SUCCESS) {
		return (err);
	}

	log_printf(dgettext(TEXT_DOMAIN,
	    "System Temperatures (Celsius):\n"
	    "-------------------------------\n"
	    "Device\t\tTemperature\tStatus\n"
	    "---------------------------------------\n"));

	for (i = 0; i < number; i++) {
		err = picl_get_propval_by_name(system_ts_nodes[i],
		    "State", state, sizeof (state));
		if (err != PICL_SUCCESS) {
			if (err == PICL_INVALIDHANDLE) {
				strcpy(state, "n/a");
			} else {
				log_printf("%s\n", picl_strerror(err));
				return (err);
			}
		}
		err = picl_get_propval_by_name(system_ts_nodes[i],
		    PICL_PROP_NAME, label, PICL_PROPNAMELEN_MAX);
		if (err != PICL_SUCCESS) {
			if (err == PICL_INVALIDHANDLE)
				/* This FRU isn't present. Skip it. */
				continue;
			log_printf("%s\n", picl_strerror(err));
			return (err);
		}

		/*
		 * The names in the tree are like "CPU0_DIE_TEMPERATURE_SENSOR".
		 * All we want to print is up to the first underscore.
		 */
		p = strchr(label, '_');
		if (p != NULL)
			*p = '\0';

		err = picl_get_propval_by_name(system_ts_nodes[i],
		    "Temperature", &temp, sizeof (temp));
		if (err != PICL_SUCCESS) {
			log_printf("%s\n", picl_strerror(err));
			return (err);
		}
		log_printf("%s\t\t%3d\t\t%s\n", label, temp, state);
	}

	log_printf(dgettext(TEXT_DOMAIN,
	    "\n=================================\n\n"));

	return (PICL_SUCCESS);
}

static void
dak_display_hw_revisions(Prom_node *root, Board_node *bdlist)
{
	Prom_node	*pnode;
	char		*value;

	log_printf(dgettext(TEXT_DOMAIN, "\n"
	    "========================= HW Revisions "
	    "=======================================\n\n"));

	log_printf(dgettext(TEXT_DOMAIN,
	    "System PROM revisions:\n"
	    "----------------------\n"));

	pnode = dev_find_node(root, "openprom");
	if (pnode != NULL) {
		value = (char *)get_prop_val(find_prop(pnode, "version"));
		log_printf(value);
	}

	log_printf(dgettext(TEXT_DOMAIN, "\n\n"
	    "IO ASIC revisions:\n"
	    "------------------\n"
	    "         Port\n"
	    "Model     ID  Status Version\n"
	    "-------- ---- ------ -------\n"));

	display_schizo_revisions(bdlist);
}

static void
display_schizo_revisions(Board_node *bdlist)
{
	Prom_node	*pnode;
	int		*int_val;
	int		portid;
	int		prev_portid = -1;
	char		*status_a = NULL;
	char		*status_b = NULL;
	int		revision;
#ifdef DEBUG
	uint32_t	a_notes, b_notes;
#endif
	int		pci_bus;
	Board_node	*bnode;
	bnode = bdlist;

	while (bnode != NULL) {
		/*
		 * search this board node for all Schizos
		 */
		for (pnode = dev_find_node_by_compat(bnode->nodes,
		    SCHIZO_COMPAT_PROP); pnode != NULL;
		    pnode = dev_next_node_by_compat(pnode,
		    SCHIZO_COMPAT_PROP)) {

			/*
			 * get the reg property to determine
			 * whether we are looking at side A or B
			 */
			int_val = (int *)get_prop_val
			    (find_prop(pnode, "reg"));
			if (int_val != NULL) {
				int_val ++; /* second integer in array */
				pci_bus = ((*int_val) & 0x7f0000);
			}

			/* get portid */
			int_val = (int *)get_prop_val
			    (find_prop(pnode, "portid"));
			if (int_val == NULL)
				continue;

			portid = *int_val;

			/*
			 * If this is a new portid and it is PCI bus B,
			 * we skip onto the PCI bus A.
			 */
			if ((portid != prev_portid) && (pci_bus == 0x700000)) {
				prev_portid = portid;
				/* status */
				status_b = (char *)get_prop_val
				    (find_prop(pnode, "status"));
#ifdef DEBUG
				b_notes = pci_bus;
#endif
				continue; /* skip to the next schizo */
			}

			/*
			 * This must be side A of the same Schizo.
			 * Gather all its props and display them.
			 */
#ifdef DEBUG
			a_notes = pci_bus;
#endif

			prev_portid = portid;

			int_val = (int *)get_prop_val
			    (find_prop(pnode, "version#"));
			if (int_val != NULL)
				revision = *int_val;
			else
				revision = -1;

			status_a = (char *)get_prop_val(find_prop
			    (pnode, "status"));

			log_printf(dgettext(TEXT_DOMAIN, "Schizo    "));

			log_printf(dgettext(TEXT_DOMAIN, "%-3d "), portid, 0);


			log_printf((status_a == NULL && status_b == NULL) ?
			    dgettext(TEXT_DOMAIN, "  ok  ") :
			    dgettext(TEXT_DOMAIN, " fail "));

			log_printf(dgettext(TEXT_DOMAIN, " %4d   "),
			    revision);
#ifdef DEBUG
			log_printf(" 0x%x 0x%x", a_notes, b_notes);
#endif
			log_printf("\n");
		}
		bnode = bnode->next;
	}
}
