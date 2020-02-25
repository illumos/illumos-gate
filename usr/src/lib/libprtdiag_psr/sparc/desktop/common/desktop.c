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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2020 Peter Tribble.
 *
 * Desktop Platform specific functions.
 *
 *	Called when:
 *	machine_type == MTYPE_DARWIN &&
 *	machine_type == MTYPE_DEFAULT
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <kvm.h>
#include <varargs.h>
#include <errno.h>
#include <time.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/systeminfo.h>
#include <sys/utsname.h>
#include <sys/openpromio.h>
#include <kstat.h>
#include <libintl.h>
#include <syslog.h>
#include <sys/dkio.h>
#include "pdevinfo.h"
#include "display.h"
#include "pdevinfo_sun4u.h"
#include "display_sun4u.h"
#include "libprtdiag.h"

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif


#define	PCI_BUS(x)		((x  >> 16) & 0xff)

/*
 * State variable to signify the type of machine we're currently
 * running on.  Since prtdiag has come to be the dumping ground
 * for lots of platform-specific routines, and machine architecture
 * alone is not enough to determine our course of action, we need
 * to enumerate the different machine types that we should worry
 * about.
 */
enum machine_type {
	MTYPE_DEFAULT = 0,  /* Desktop-class machine */
	MTYPE_DARWIN = 1
};

enum machine_type machine_type = MTYPE_DEFAULT;

extern	int	print_flag;

/*
 * these functions will overlay the symbol table of libprtdiag
 * at runtime (desktop systems only)
 */
int	error_check(Sys_tree *tree, struct system_kstat_data *kstats);
int	disp_fail_parts(Sys_tree *tree);
void	display_hp_fail_fault(Sys_tree *tree, struct system_kstat_data *kstats);
void	display_diaginfo(int flag, Prom_node *root, Sys_tree *tree,
		struct system_kstat_data *kstats);
void	display_pci(Board_node *bnode);
void	display_sbus(Board_node *);


/* local functions */
static	void dt_disp_asic_revs(Sys_tree *);
static	void display_sabre_pci(Board_node *);
static	void display_dev_node(Prom_node *np, int depth);
static	void get_machine_type(void);

int
error_check(Sys_tree *tree, struct system_kstat_data *kstats)
{
	int exit_code = 0;	/* init to all OK */

#ifdef lint
	kstats = kstats;
#endif

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
	int exit_code;
	int system_failed = 0;
	Board_node *bnode = tree->bd_list;
	Prom_node *pnode;

	exit_code = 0;

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
			log_printf("\n", 0);
			log_printf(dgettext(TEXT_DOMAIN, "Failed Field "
				"Replaceable Units (FRU) in System:\n"), 0);
			log_printf("=========================="
				"====================\n", 0);
		}

		while (pnode != NULL) {
			void *value;
			char *name;		/* node name string */
			char *type;		/* node type string */
			char *board_type = NULL;

			value = get_prop_val(find_prop(pnode, "status"));
			name = get_node_name(pnode);

			/* sanity check of data retreived from PROM */
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
					bnode->board_num, 0);

			log_printf(dgettext(TEXT_DOMAIN,
				"\tPROM fault string: %s\n"), value, 0);

			log_printf(dgettext(TEXT_DOMAIN,
				"\tFailed Field Replaceable Unit is "), 0);

			/*
			 * Determine whether FRU is CPU module, system
			 * board, or SBus card.
			 */
			if ((name != NULL) && (strstr(name, "sbus"))) {

				log_printf(dgettext(TEXT_DOMAIN,
					"SBus Card %d\n"),
					get_sbus_slot(pnode), 0);

			} else if (((name = get_node_name(pnode->parent)) !=
			    NULL) && (strstr(name, "pci"))) {

				log_printf(dgettext(TEXT_DOMAIN,
					"PCI Card %d"),
					get_pci_device(pnode), 0);

			} else if (((type = get_node_type(pnode)) != NULL) &&
			    (strstr(type, "cpu"))) {

				log_printf(dgettext(TEXT_DOMAIN, "UltraSPARC "
					"module Board %d Module %d\n"), 0,
						get_id(pnode));

			} else {
				log_printf(dgettext(TEXT_DOMAIN,
					"%s board %d\n"), board_type,
					bnode->board_num, 0);
			}
			pnode = next_failed_node(pnode);
		}
		bnode = bnode->next;
	}

	if (!system_failed) {
		log_printf("\n", 0);
		log_printf(dgettext(TEXT_DOMAIN,
			"No failures found in System\n"), 0);
		log_printf("===========================\n", 0);
	}

	if (system_failed)
		return (1);
	else
		return (0);
}


void
display_hp_fail_fault(Sys_tree *tree, struct system_kstat_data *kstats)
{

#ifdef lint
	kstats = kstats;
#endif
	/* Display failed units */
	(void) disp_fail_parts(tree);
}

void
display_diaginfo(int flag, Prom_node *root, Sys_tree *tree,
	struct system_kstat_data *kstats)
{

#ifdef	lint
	kstats = kstats;
#endif
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

		dt_disp_asic_revs(tree);

		platform_disp_prom_version(tree);
	}
	return;

}

void
display_pci(Board_node *bnode)
{
	Prom_node	*pci;

	/*
	 * We have different routines for walking/displaying PCI
	 * devices depending on whether the PCI device is a
	 * Psycho or a Sabre.
	 */
	pci = dev_find_node_by_type(bnode->nodes, "model", "SUNW,psycho");
	if (pci != NULL) {
		display_psycho_pci(bnode);
		return;
	}

	pci = dev_find_node_by_type(bnode->nodes, "model", "SUNW,sabre");
	if (pci != NULL) {
		display_sabre_pci(bnode);
		return;
	}
}

/*
 * local functions
 */

void
dt_disp_asic_revs(Sys_tree *tree)
{
	Board_node *bnode;
	Prom_node *pnode;
	char *name;
	int *version;

	/* Print the header */
	log_printf("\n", 0);
	log_printf("=========================", 0);
	log_printf(" HW Revisions ", 0);
	log_printf("=========================", 0);
	log_printf("\n", 0);
	log_printf("\n", 0);

	bnode = tree->bd_list;

	log_printf("ASIC Revisions:\n", 0);
	log_printf("---------------\n", 0);

	/* Find sysio and print rev */
	for (pnode = dev_find_node(bnode->nodes, "sbus"); pnode != NULL;
	    pnode = dev_next_node(pnode, "sbus")) {
		version = (int *)get_prop_val(find_prop(pnode, "version#"));
		name = get_prop_val(find_prop(pnode, "name"));

		if ((version != NULL) && (name != NULL)) {
			log_printf("SBus: %s Rev %d\n",
				name, *version, 0);
		}
	}

	/* Find Psycho and print rev */
	for (pnode = dev_find_node(bnode->nodes, "pci"); pnode != NULL;
	    pnode = dev_next_node(pnode, "pci")) {
		version = (int *)get_prop_val(find_prop(pnode, "version#"));
		name = get_prop_val(find_prop(pnode, "name"));

		if ((version != NULL) && (name != NULL))
			log_printf("PCI: %s Rev %d\n",
				name, *version, 0);
	}

	/* Find Cheerio and print rev */
	for (pnode = dev_find_node(bnode->nodes, "ebus"); pnode != NULL;
	    pnode = dev_next_node(pnode, "ebus")) {
		version = (int *)get_prop_val(find_prop(pnode, "revision-id"));
		name = get_prop_val(find_prop(pnode, "name"));

		if ((version != NULL) && (name != NULL))
			log_printf("Cheerio: %s Rev %d\n", name, *version, 0);
	}


	/* Find the FEPS and print rev */
	for (pnode = dev_find_node(bnode->nodes, "SUNW,hme"); pnode != NULL;
	    pnode = dev_next_node(pnode, "SUNW,hme")) {
		version = (int *)get_prop_val(find_prop(pnode,	"hm-rev"));
		name = get_prop_val(find_prop(pnode, "name"));

		if ((version != NULL) && (name != NULL)) {
			log_printf("FEPS: %s Rev ", name);
			if (*version == 0xa0) {
				log_printf("2.0\n", 0);
			} else if (*version == 0x20) {
				log_printf("2.1\n", 0);
			} else {
				log_printf("%x\n", *version, 0);
			}
		}
	}
	log_printf("\n", 0);

	display_ffb(bnode, 0);
}

/*
 * print the header and call display_dev_node() to walk the device
 * tree (darwin platform only).
 */
static void
display_sabre_pci(Board_node *board)
{
	if (board == NULL)
		return;

	log_printf("     Bus#  Freq\n", 0);
	log_printf("Brd  Type  MHz   Slot  "
		"Name                              Model", 0);
	log_printf("\n", 0);
	log_printf("---  ----  ----  ----  "
		"--------------------------------  ----------------------", 0);
	log_printf("\n", 0);
	display_dev_node(board->nodes, 0);
	log_printf("\n", 0);
}


/*
 * Recursively traverse the device tree and use tree depth as filter.
 * called by: display_sabre_pci()
 */
static void
display_dev_node(Prom_node *np, int depth)
{
	char *name, *model, *compat, *regval;
	unsigned int reghi;

	if (!np)
		return;
	if (depth > 2)
		return;

	name = get_prop_val(find_prop(np, "name"));
	model = get_prop_val(find_prop(np, "model"));
	compat = get_prop_val(find_prop(np, "compatible"));
	regval = get_prop_val(find_prop(np, "reg"));

	if (!regval)
		return;
	else
		reghi = *(int *)regval;

	if (!model)
		model = "";
	if (!name)
		name = "";

	if (depth == 2) {
		char buf[256];
		if (compat)
			(void) sprintf(buf, "%s-%s", name, compat);
		else
			(void) sprintf(buf, "%s", name);

		log_printf(" 0   PCI-%d  33   ", PCI_BUS(reghi), 0);
		log_printf("%3d   ", PCI_DEVICE(reghi), 0);
		log_printf("%-32.32s", buf, 0);
		log_printf(strlen(buf) > 32 ? "+ " : "  ", 0);
		log_printf("%-22.22s", model, 0);
		log_printf(strlen(model) > 22 ? "+" : "", 0);
		log_printf("\n", 0);

#ifdef DEBUG
		if (!compat)
			compat = "";
		printf("bus=%d slot=%d name=%s model=%s compat=%s\n",
			PCI_BUS(reghi), PCI_DEVICE(reghi), name, model, compat);
#endif
	}

	if ((!strstr(name, "ebus")) && (!strstr(name, "ide")))
		display_dev_node(np->child, depth+1);
	display_dev_node(np->sibling, depth);
}

/*
 * display_sbus
 * Display all the SBus IO cards on this board.
 */
void
display_sbus(Board_node *board)
{
	struct io_card card;
	struct io_card *card_list = NULL;
	int freq;
	int card_num;
	void *value;
	Prom_node *sbus;
	Prom_node *card_node;

	if (board == NULL)
		return;

	for (sbus = dev_find_node(board->nodes, SBUS_NAME); sbus != NULL;
	    sbus = dev_next_node(sbus, SBUS_NAME)) {

		/* Skip failed nodes for now */
		if (node_failed(sbus))
			continue;

		/* Calculate SBus frequency in MHz */
		value = get_prop_val(find_prop(sbus, "clock-frequency"));
		if (value != NULL)
			freq = ((*(int *)value) + 500000) / 1000000;
		else
			freq = -1;

		for (card_node = sbus->child; card_node != NULL;
		    card_node = card_node->sibling) {
			char *model;
			char *name;
			char *child_name;

			card_num = get_sbus_slot(card_node);
			if (card_num == -1)
				continue;

			/* Fill in card information */
			card.display = 1;
			card.freq = freq;
			card.board = board->board_num;
			(void) sprintf(card.bus_type, "SBus");
			card.slot = card_num;
			card.status[0] = '\0';

			/* Try and get card status */
			value = get_prop_val(find_prop(card_node, "status"));
			if (value != NULL)
				(void) strncpy(card.status, (char *)value,
					MAXSTRLEN);

			/* XXX - For now, don't display failed cards */
			if (strstr(card.status, "fail") != NULL)
				continue;

			/*
			 * sets the machine_type var if not already set
			 */
			get_machine_type();

			/*
			 * For desktops, the only high slot number that
			 * needs to be displayed is the # 14 slot.
			 */
			if (machine_type == MTYPE_DEFAULT &&
			    card_num >= MX_SBUS_SLOTS && card_num != 14) {
				continue;
			}

			/* Now gather all of the node names for that card */
			model = (char *)get_prop_val(find_prop(card_node,
				"model"));
			name = get_node_name(card_node);

			if (name == NULL)
				continue;

			card.name[0] = '\0';
			card.model[0] = '\0';

			/* Figure out how we want to display the name */
			child_name = get_node_name(card_node->child);
			if ((card_node->child != NULL) &&
			    (child_name != NULL)) {
				value = get_prop_val(find_prop(card_node->child,
					"device_type"));
				if (value != NULL)
					(void) sprintf(card.name, "%s/%s (%s)",
						name, child_name,
						(char *)value);
				else
					(void) sprintf(card.name, "%s/%s", name,
						child_name);
			} else {
				(void) strncpy(card.name, name, MAXSTRLEN);
			}

			if (model != NULL)
				(void) strncpy(card.model, model, MAXSTRLEN);

			card_list = insert_io_card(card_list, &card);
		}
	}

	/* We're all done gathering card info, now print it out */
	display_io_cards(card_list);
	free_io_cards(card_list);
}

static void
get_machine_type(void)
{
	char name[MAXSTRLEN];

	machine_type = MTYPE_DEFAULT;

	/* Figure out what kind of machine we're on */
	if (sysinfo(SI_PLATFORM, name, MAXSTRLEN) != -1) {
		if (strcmp(name, "SUNW,Ultra-5_10") == 0)
			machine_type = MTYPE_DARWIN;
	}
}
