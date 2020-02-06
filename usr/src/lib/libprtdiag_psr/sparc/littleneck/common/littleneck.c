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
 *
 * Littleneck Platform specific functions.
 *
 *	called when :
 *      machine_type ==  MTYPE_LITTLENECK
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
#include <syslog.h>

#include <sys/openpromio.h>
#include <sys/sysmacros.h>

#include <pdevinfo.h>
#include <display.h>
#include <pdevinfo_sun4u.h>
#include <display_sun4u.h>
#include <libprtdiag.h>

#include <picl.h>
#include "workfile.c"

#define	LNECK_MAX_PS		2
#define	LNECK_MAX_DISKS		2
#define	LNECK_MAX_FANS		1

#ifndef	SCHIZO_COMPAT_PROP
#define	SCHIZO_COMPAT_PROP	"pci108e,8001"
#endif

/* Count of failed PSU's found */
int ps_failure = 0;

/*
 * Ignore first entry into disp_envc_status()
 * from libprtdiag/common/display_sun4u.c
 */
int print_flag = 0;

/*
 * these functions will overlay the symbol table of libprtdiag
 * at runtime (workgroup server systems only)
 */
int	error_check(Sys_tree *tree, struct system_kstat_data *kstats);
void	display_cpu_devices(Sys_tree *tree);
void	display_pci(Board_node *board);
void	display_io_cards(struct io_card *list);
void	display_diaginfo(int flag, Prom_node *root, Sys_tree *tree,
				struct system_kstat_data *kstats);
void	display_ffb(Board_node *board, int table);
void	display_memoryconf(Sys_tree *tree);

/* local functions */
static	int disp_envc_status(void);
static	int lneck_env_print_temps(picl_nodehdl_t);
static	int lneck_env_print_keyswitch(picl_nodehdl_t);
static	int lneck_env_print_FSP_LEDS(picl_nodehdl_t);
static	int lneck_env_print_disk(picl_nodehdl_t);
static	int lneck_env_print_fans(picl_nodehdl_t);
static	int lneck_env_print_ps(picl_nodehdl_t);

static void lneck_display_hw_revisions(Prom_node *root,
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
	/* silently check for any types of machine errors */
	print_flag = 0;
	if (disp_fail_parts(tree) || disp_envc_status())
		/* set exit_code to show failures */
		exit_code = 1;

	print_flag = 1;

	return (exit_code);
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
	    "========================= CPUs "
	    "==============================================="
	    "\n"
	    "\n"
	    "          Run    E$    CPU     CPU  \n"
	    "Brd  CPU  MHz    MB   Impl.    Mask \n"
	    "---  ---  ----  ----  -------  ---- \n"));

	/* Now display all of the cpus on each board */
	bnode = tree->bd_list;
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
	char		cpu_name[] = "cpu";

	/*
	 * display the CPUs' operating frequency, cache size, impl. field
	 * and mask revision.
	 */

	for (cpu = dev_find_type(board->nodes, cpu_name); cpu != NULL;
	    cpu = dev_next_type(cpu, cpu_name)) {
		uint_t freq;	 /* CPU clock frequency */
		int ecache_size; /* External cache size */
		int *mid;
		int *impl;
		int *mask;

		mid = (int *)get_prop_val(find_prop(cpu, "portid"));
		freq = LNECK_CLK_FREQ_TO_MHZ(get_cpu_freq(cpu));
		ecache_size = get_ecache_size(cpu);
		impl = (int *)get_prop_val(find_prop(cpu, "implementation#"));
		mask = (int *)get_prop_val(find_prop(cpu, "mask#"));

		/* Do not display a failed CPU node */
		if ((freq != 0) && (node_failed(cpu) == 0)) {
			/* Board number */
			switch (*mid) {
			case 1:
				log_printf(dgettext(TEXT_DOMAIN,
				" B   "));
				break;
			case 0:
				log_printf(dgettext(TEXT_DOMAIN,
				" A   "));
				break;
			default:
				log_printf(dgettext(TEXT_DOMAIN, "X    "));
			}

			/* CPU MID */
			log_printf("%2d   ", *mid);

			/* Module number */

			/* Running frequency */
			log_printf("%4u  ", freq);

			/* Ecache size */
			if (ecache_size == 0)
				log_printf("N/A  ");
			else
				log_printf("%4.1f  ",
				    (float)ecache_size / (float)(1<<20));

			/* Implementation */
			if (impl == NULL) {
				log_printf(dgettext(TEXT_DOMAIN, "%6s  "),
				" N/A");
			} else {
				if (IS_CHEETAH(*impl))
					log_printf("%-7s ", "US-III", 0);
				else if (IS_CHEETAH_PLUS(*impl))
					log_printf("%-7s ", "US-III+", 0);
				else
					log_printf("%-7x ", *impl, 0);
			}

			/* CPU Mask */
			if (mask == NULL) {
				log_printf(dgettext(TEXT_DOMAIN, " N/A   "));
			} else {
				log_printf(dgettext(TEXT_DOMAIN, " %d.%d   "),
				    (*mask >> 4) & 0xf, *mask & 0xf);
			}

			log_printf("\n");
		}
	}
}

void
display_memoryconf(Sys_tree *tree)
{
	Board_node	*bnode = tree->bd_list;

	log_printf(dgettext(TEXT_DOMAIN,
	    "========================= Memory Configuration"
	    " ===============================\n"
	    "\n           Logical  Logical  Logical "
	    "\n      MC   Bank     Bank     Bank         DIMM    "
	    "Interleave  Interleaved"
	    "\n Brd  ID   num      size     Status       Size    "
	    "Factor      with"
	    "\n----  ---  ----     ------   -----------  ------  "
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

/*ARGSUSED2*/
void
display_diaginfo(int flag, Prom_node *root, Sys_tree *tree,
	struct system_kstat_data *kstats)
{
	/*
	 * Now display the last powerfail time and the fatal hardware
	 * reset information. We do this under a couple of conditions.
	 * First if the user asks for it. The second is iof the user
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

		/* Hardware revision function calls */
		lneck_display_hw_revisions(root, tree->bd_list);
		log_printf("\n");
	}
	return;

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

	char		*slot_name_arr[LNECK_MAX_SLOTS_PER_IO_BD] = {NULL};
	int		i;

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
			/* array starts after first int */
			slot_name_arr[0] = (char *)value + sizeof (int);
			for (i = 1; i < LNECK_MAX_SLOTS_PER_IO_BD; i++) {
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

	if (list == NULL) {
		return;
	}

	if (banner == FALSE) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "                         Bus  Max\n"
		    "     IO   Port Bus       Freq Bus  Dev,\n"
		    "Brd  Type  ID  Side Slot MHz  Freq Func State "
		    "Name                              "));
#ifdef DEBUG
		log_printf(dgettext(TEXT_DOMAIN,
		    "Model                   Notes\n"));
#else
		log_printf(dgettext(TEXT_DOMAIN, "Model\n"));
#endif
		/* ---------Node Brd  IO   Port Bus  Slot Bus  Max  Dev  Stat */
		log_printf(dgettext(TEXT_DOMAIN,
		    "---- ---- ---- ---- ---- ---- ---- ---- ----- "
		    "--------------------------------  "
#ifdef DEBUG
		    "----------------------  "
#endif
		    "----------------------\n"));
		banner = TRUE;
	}

	for (p = list; p != NULL; p = p -> next) {
		log_printf(dgettext(TEXT_DOMAIN, "I/O   "));
		log_printf(dgettext(TEXT_DOMAIN, "%-4s  "), p->bus_type);
		log_printf(dgettext(TEXT_DOMAIN, "%-3d  "),
		    p->schizo_portid);
		log_printf(dgettext(TEXT_DOMAIN, "%c    "), p->pci_bus);
		log_printf(dgettext(TEXT_DOMAIN, "%-1s    "), p->slot_str);
		log_printf(dgettext(TEXT_DOMAIN, "%-3d "), p->freq);
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

		log_printf(dgettext(TEXT_DOMAIN, "%-1d,%-1d  "),
		    p->dev_no, p->func_no);
		log_printf(dgettext(TEXT_DOMAIN, "%-5s "), p->status);
		log_printf(dgettext(TEXT_DOMAIN, "%-32.32s"), p->name);
		if (strlen(p->name) > 32)
			log_printf(dgettext(TEXT_DOMAIN, "+ "));
		else
			log_printf(dgettext(TEXT_DOMAIN, "  "));
		log_printf(dgettext(TEXT_DOMAIN, "%-22.22s"), p->model);
		if (strlen(p->model) > 22)
			log_printf(dgettext(TEXT_DOMAIN, "+"));
#ifdef DEBUG
		log_printf("%s  ", p->notes);
#endif
		log_printf("\n");
	}
}

/*
 * display_ffb
 *
 * There are no FFB's on a Littleneck, however in the generic library,
 * the display_ffb() function is implemented so we have to define an
 * empty function here.
 */
/*ARGSUSED0*/
void
display_ffb(Board_node *board, int table)
{}


/*
 * local functions
 */

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
		return (0);
	} else {
		return (1);
	}
}


/*
 * disp_envc_status
 *
 * This routine displays the environmental status passed up from
 * device drivers via the envlibobj.so library.
 * This is a Littleneck specific environmental information display routine.
 */
static int
disp_envc_status(void)
{
	int err;
	char *system = "SYSTEM";
	picl_nodehdl_t system_node, root;

	log_printf("\n");
	log_printf(dgettext(TEXT_DOMAIN, "========================="
	    " Environmental Status =========================\n\n"));

	err = picl_initialize();
	if (err != PICL_SUCCESS) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "Cannot print environmental information\n"
		    "picl_initialize failed\n"
		    "%s\n"), picl_strerror(err));
	}

	if (err == PICL_SUCCESS) {
		err = picl_get_root(&root);
		err = find_child_device(root, system, &system_node);
		if (err != PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "Cannot print environmental information\n"
			    "find_child_device for the SYSTEM node "
			    "failed\n"
			    "%s\n"), picl_strerror(err));
		}

		if ((err = lneck_env_print_temps(system_node)) !=
		    PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "Temperature Checking failed: %s\n"),
			    picl_strerror(err));
		}
		if ((err = lneck_env_print_keyswitch(system_node)) !=
		    PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "Keyswitch information checking failed: %s\n"),
			    picl_strerror(err));
		}
		if ((err = lneck_env_print_FSP_LEDS(system_node)) !=
		    PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "FSP LED information checking failed: %s\n"),
			    picl_strerror(err));
		}
		if ((err = lneck_env_print_disk(system_node)) !=
		    PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "Disk information checking failed: %s\n"),
			    picl_strerror(err));
		}
		if ((err = lneck_env_print_fans(system_node)) !=
		    PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "Fan information checking failed: %s\n"),
			    picl_strerror(err));
		}
		if ((err = lneck_env_print_ps(system_node)) !=
		    PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "Power Supply information checking failed: "
			    "%s\n"), picl_strerror(err));
		} else if (ps_failure != 0)
			err = PICL_FAILURE;
	}
	return (err);
}

int
lneck_env_print_ps(picl_nodehdl_t system_node)
{
	int		i, err = 0;
	int32_t		number;
	picl_nodehdl_t	*ps;
	picl_nodehdl_t	ps_fail[2], ps_type[2];
	char		name[PICL_PROPNAMELEN_MAX];
	boolean_t	type;
	char		fault_state[PICL_PROPNAMELEN_MAX];

	log_printf(dgettext(TEXT_DOMAIN,
	    "Power Supplies:\n"
	    "---------------\n"
	    "Supply     Status         PS Type\n"
	    "------     ------      ---------------\n"));
	err = fill_device_array_from_id(system_node, "PSVC_PS", &number,
	    &ps);
	if (err != PICL_SUCCESS) {
		return (err);
	}

	for (i = 0; i < LNECK_MAX_PS; i++) {
		err = picl_get_propval_by_name(ps[i], PICL_PROP_NAME, name,
		    PICL_PROPNAMELEN_MAX);
		if (err == PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN, "%6-s"), name);
		} else continue;

		err = picl_get_propval_by_name(ps[i], "FaultInformation",
		    fault_state, PICL_PROPNAMELEN_MAX);
		if (err == PICL_SUCCESS) {
			if ((strlen(fault_state) == 0) ||
			    (strcmp(fault_state, "NO_FAULT") == 0)) {
				strcpy(fault_state, "OK");
			} else
				/*
				 * Bump up count if fault_state	 !OK
				 */
				ps_failure++;

			log_printf(dgettext(TEXT_DOMAIN, "    [%-6s] "),
			    fault_state);
		} else {
			return (err);
		}

		err = fill_device_from_id(ps[i], "PSVC_DEV_FAULT_SENSOR",
		    &ps_fail[i]);
		if (err != PICL_SUCCESS) {
			return (err);
		}

		err = fill_device_from_id(ps[i], "PSVC_DEV_TYPE_SENSOR",
		    &ps_type[i]);
		if (err != PICL_SUCCESS) {
			return (err);
		}
		err = picl_get_propval_by_name(ps_type[i], "Gpio-value", &type,
		    sizeof (boolean_t));
		if (err == PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN, "    [%13s]"),
			    type == 0 ? "Quahog/Razor" : "Sun-Fire-280R");
			if (type == 0) {
				log_printf(dgettext(TEXT_DOMAIN,
				    "WARNING: PS is of the wrong type\n"));
			} else log_printf("\n");
		} else {
			return (err);
		}

	}

	log_printf(dgettext(TEXT_DOMAIN,
	    "\n"
	    "================================="
	    "\n"
	    "\n"));

	/*
	 * Do not display an error message just because PS1 is
	 * not present.
	 */
	if (err == PICL_INVALIDHANDLE) {
		err = PICL_SUCCESS;
	}

	return (err);
}

int
lneck_env_print_fans(picl_nodehdl_t system_node) {
	int		i, err = 0;
	int32_t		number;
	picl_nodehdl_t	*fans;
	picl_nodehdl_t	fan_fault[1];
	char		fault_state[PICL_PROPNAMELEN_MAX];
	char		name[PICL_PROPNAMELEN_MAX];

	err = fill_device_array_from_id(system_node, "PSVC_FAN", &number,
				&fans);
	if (err != PICL_SUCCESS) {
		return (err);
	}

	log_printf(dgettext(TEXT_DOMAIN,
		"\n"
		"=================================\n"
		"\n"
		"Fan Bank :\n"
		"----------\n"
		"\n"
		"Bank                        Status\n"
		"----                        -------\n"));

	for (i = 0; i < LNECK_MAX_FANS; i++) {
		err = picl_get_propval_by_name(fans[i], PICL_PROP_NAME, name,
				PICL_PROPNAMELEN_MAX);
		if (err == PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN, "%16-s"), name);
		} else continue;

		err = fill_device_from_id(fans[i], "PSVC_DEV_FAULT_SENSOR",
				&fan_fault[i]);
		if (err != PICL_SUCCESS) {
			return (err);
		}

		err = picl_get_propval_by_name(fans[i], "FaultInformation",
			&fault_state, PICL_PROPNAMELEN_MAX);

		if (err == PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN, "            [%3s]\n"),
				fault_state);
		} else {
		    return (err);
		}
	}
	log_printf(dgettext(TEXT_DOMAIN,
		"\n"
		"================================="
		"\n"
		"\n"));

	return (err);
}

int
lneck_env_print_disk(picl_nodehdl_t system_node) {
	int		i, err = 0;
	int32_t		number;
	picl_nodehdl_t	*disks;
	char		fault_state[PICL_PROPNAMELEN_MAX];
	char		name[PICL_PROPNAMELEN_MAX];

	err = fill_device_array_from_id(system_node, "PSVC_DISK", &number,
				&disks);
	if (err != PICL_SUCCESS) {
		return (err);
	}

	log_printf(dgettext(TEXT_DOMAIN,
		"Disk Status:\n"
		"          Presence      Fault Value\n"
		"          --------      -----------\n"));

	for (i = 0; i < LNECK_MAX_DISKS; i++) {
		err = picl_get_propval_by_name(disks[i], PICL_PROP_NAME, name,
				PICL_PROPNAMELEN_MAX);
		switch (err) {
		case PICL_SUCCESS:
			log_printf(dgettext(TEXT_DOMAIN,
				"DISK  %2d: [PRESENT]"), i);
			break;
		case PICL_INVALIDHANDLE:
			log_printf(dgettext(TEXT_DOMAIN,
				"DISK  %2d: [EMPTY  ]\n"), i);
			continue;
		default:
		    return (err);
		}
		err = picl_get_propval_by_name(disks[i], "FaultInformation",
			&fault_state, PICL_PROPNAMELEN_MAX);
		if (err == PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN, "     [%3s]"),
				fault_state);
		} else {
			if (err != PICL_INVALIDHANDLE)
				return (err);
		}
		log_printf("\n");
	}

	if (err == PICL_INVALIDHANDLE) {
		err = PICL_SUCCESS;
	}

	return (err);
}

int
lneck_env_print_FSP_LEDS(picl_nodehdl_t system_node) {
	int		err;
	int32_t		number;
	picl_nodehdl_t	*fsp_led;
	char		fault_state[PICL_PROPNAMELEN_MAX];

	err = fill_device_array_from_id(system_node, "PSVC_FSP_LED", &number,
				&fsp_led);
	if (err != PICL_SUCCESS) {
		return (err);
	}

	log_printf(dgettext(TEXT_DOMAIN,
		"System LED Status: POWER                   GEN FAULT\n"
		"                   [ ON]"));
	err = picl_get_propval_by_name(fsp_led[0], "State", &fault_state,
		PICL_PROPNAMELEN_MAX);
	if (err == PICL_SUCCESS) {
		log_printf("                    [%3s]", fault_state);
	} else {
		return (err);
	}

	log_printf(dgettext(TEXT_DOMAIN,
		"\n"
		"\n"
		"================================="
		"\n"
		"\n"));

	return (err);
}

int
lneck_env_print_keyswitch(picl_nodehdl_t system_node) {
	int		err = 0;
	picl_nodehdl_t	*keyswitch;
	int32_t		number;
	char		ks_pos[PICL_PROPNAMELEN_MAX];

	err = fill_device_array_from_id(system_node, "PSVC_KEYSWITCH", &number,
				&keyswitch);
	if (err != PICL_SUCCESS) {
		return (err);
	}
	err = picl_get_propval_by_name(keyswitch[0], "State", ks_pos,
		PICL_PROPNAMELEN_MAX);
	if (err != PICL_SUCCESS) {
		return (err);
	}

	log_printf(dgettext(TEXT_DOMAIN,
		"Front Status Panel:\n"
		"-------------------\n"
		"Keyswitch position: %s\n"), ks_pos);
	log_printf("\n");

	return (err);
}

int
lneck_env_print_temps(picl_nodehdl_t system_node) {
	int		i, err = 0;
	picl_nodehdl_t	*system_ts_nodes;
	int32_t		temp, number;

	err = fill_device_array_from_id(system_node, "PSVC_TS", &number,
				&system_ts_nodes);
	if (err != PICL_SUCCESS) {
		return (err);
	}


	log_printf(dgettext(TEXT_DOMAIN,
		"System Temperatures (Celsius):\n"
		"------------------------------\n"
		"cpu0   1 \n"
		"---------\n"));

	for (i = 0; i < 2; i++) {
		err = picl_get_propval_by_name(system_ts_nodes[i],
				"Temperature", &temp, sizeof (temp));
		if (err == PICL_SUCCESS) {
			log_printf(dgettext(TEXT_DOMAIN, "  %02d"), temp);
		} else {
			if (err == PICL_INVALIDHANDLE) {
				err = PICL_SUCCESS;
				log_printf(dgettext(TEXT_DOMAIN, "  xx"));
			} else {
				return (err);
			}
		}
	}

	log_printf("\n");
	log_printf("\n");
	log_printf(dgettext(TEXT_DOMAIN,
	"=================================\n"));
	log_printf("\n");

	return (err);
}

static void
lneck_display_hw_revisions(Prom_node *root, Board_node *bdlist)
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
	    "                     Port\n"
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
