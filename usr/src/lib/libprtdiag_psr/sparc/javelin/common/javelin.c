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
 *
 * Javelin Platform specific functions.
 *
 *	called when :
 *	machine_type ==  MTYPE_JAVELIN
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

extern	int	print_flag;

/*
 * these functions will overlay the symbol table of libprtdiag
 * at runtime (workgroup server systems only)
 */
int	error_check(Sys_tree *tree, struct system_kstat_data *kstats);
void	display_memoryconf(Sys_tree *tree, struct grp_info *grps);
int	disp_fail_parts(Sys_tree *tree);
void	display_hp_fail_fault(Sys_tree *tree, struct system_kstat_data *kstats);
void	display_diaginfo(int flag, Prom_node *root, Sys_tree *tree,
				struct system_kstat_data *kstats);
void	display_boardnum(int num);
void	display_pci(Board_node *);
void	display_io_cards(struct io_card *list);
void	display_ffb(Board_node *, int);
void	read_platform_kstats(Sys_tree *tree,
		struct system_kstat_data *sys_kstat,
		struct bd_kstat_data *bdp, struct envctrl_kstat_data *ep);

/* local functions */
static	int disp_envc_status(struct system_kstat_data *);
static	void tazjav_disp_asic_revs(Sys_tree *);
static	int tazmo_physical_slot(Prom_node *, Prom_node *, int, char *);
static	Prom_node *dev_next_node_sibling(Prom_node *root, char *name);


int
error_check(Sys_tree *tree, struct system_kstat_data *kstats)
{
	int exit_code = 0;	/* init to all OK */

#ifdef	lint
	kstats = kstats;
#endif
	/*
	 * silently check for any types of machine errors
	 */
	print_flag = 0;
	if (disp_fail_parts(tree) || disp_envc_status(kstats)) {
		/* set exit_code to show failures */
		exit_code = 1;
	}
	print_flag = 1;

	return (exit_code);
}

/* Search for and return the node's sibling */
static Prom_node *
dev_next_node_sibling(Prom_node *root, char *name)
{
	if (root == NULL)
		return (NULL);

	/* look at your siblings */
	if (dev_find_node(root->sibling, name) != NULL)
		return (root->sibling);

	return (NULL);  /* not found */
}

/*
 * This function displays memory configurations specific to Tazmo/Javelin.
 * The PROM device tree is read to obtain this information.
 * Some of the information obtained is memory interleave factor,
 * DIMM sizes, DIMM socket names.
 */
void
display_memoryconf(Sys_tree *tree, struct grp_info *grps)
{
	Board_node *bnode;
	Prom_node *memory;
	Prom_node *bank;
	Prom_node *dimm;
	uint_t *preg;
	uint_t interlv;
	unsigned long size = 0;
	int bank_count = 0;
	char *sock_name;
	char *status;
	Prop *status_prop;
	char interleave[8];
	int total_size = 0;
#ifdef lint
	grps = grps;
#endif

	log_printf("\n", 0);
	log_printf("=========================", 0);
	log_printf(dgettext(TEXT_DOMAIN, " Memory "), 0);
	log_printf("=========================", 0);
	log_printf("\n", 0);
	log_printf("\n", 0);
	bnode = tree->bd_list;
	memory = dev_find_node(bnode->nodes, "memory");
	preg = (uint_t *)(get_prop_val(find_prop(memory, "interleave")));
	if (preg) {
		interlv = preg[4];
		log_printf("Memory Interleave Factor = %d-way\n\n", interlv, 0);
	}
	log_printf("       Interlv.  Socket   Size\n", 0);
	log_printf("Bank    Group     Name    (MB)  Status\n", 0);
	log_printf("----    -----    ------   ----  ------\n", 0);

	dimm = bnode->nodes;
	for (bank = dev_find_node(bnode->nodes, "bank"); bank != NULL;
	    bank = dev_next_node(bank, "bank")) {
		int bank_size = 0;
		uint_t *reg_prop;

		preg = (uint_t *)(get_prop_val(
		    find_prop(bank, "bank-interleave")));

		reg_prop = (uint_t *)(get_prop_val(
		    find_prop(bank, "reg")));

		/*
		 * Skip empty banks
		 */
		if (((reg_prop[2]<<12) + (reg_prop[3]>>20)) == 0) {
			bank_count++;
			continue;
		}

		if (preg) {
			interlv = preg[2];
			(void) sprintf(interleave, " %d ", interlv);
			bank_size = (preg[0]<<12) + (preg[1]>>20);
		} else {
			(void) sprintf(interleave, "%s", "none");
			preg = (uint_t *)(get_prop_val(find_prop(bank, "reg")));
			if (preg) {
				bank_size = (preg[2]<<12) + (preg[3]>>20);
			}
		}
		for (dimm = dev_find_node(bank, "dimm"); dimm != NULL;
		    dimm = dev_next_node_sibling(dimm, "dimm")) {
			char dimm_status[16];

			sock_name = (char *)(get_prop_val(
			    find_prop(dimm, "socket-name")));
			preg = (uint_t *)(get_prop_val(find_prop(dimm, "reg")));
			size = (preg[2]<<12) + (preg[3]>>20);
			if ((status_prop = find_prop(dimm, "status")) == NULL) {
				(void) sprintf(dimm_status, "%s", "OK");
			} else {
				status = (char *)(get_prop_val(status_prop));
				(void) sprintf(dimm_status, "%s", status);
			}
			log_printf("%3d     %5s    %6s  %4d  %6s\n",
			    bank_count, interleave, sock_name,
			    size, dimm_status, 0);
		}
		total_size += bank_size;
		bank_count++;
	}
	log_printf("\n", 0);
}

/*
 * disp_fail_parts
 *
 * Display the failed parts in the system. This function looks for
 * the status property in all PROM nodes. On systems where
 * the PROM does not supports passing diagnostic information
 * thruogh the device tree, this routine will be silent.
 */
int
disp_fail_parts(Sys_tree *tree)
{
	int exit_code;
	int system_failed = 0;
	Board_node *bnode = tree->bd_list;
	Prom_node *pnode;
	char *fru;
	char *sock_name;
	char slot_str[MAXSTRLEN];

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

			value = get_prop_val(find_prop(pnode, "status"));
			name = get_node_name(pnode);

			/* sanity check of data retreived from PROM */
			if ((value == NULL) || (name == NULL)) {
				pnode = next_failed_node(pnode);
				continue;
			}


			log_printf(dgettext(TEXT_DOMAIN, "%s unavailable :\n"),
			    name, 0);

			log_printf(dgettext(TEXT_DOMAIN, "\tPROM fault "
			    "string: %s\n"), value, 0);

			log_printf(dgettext(TEXT_DOMAIN, "\tFailed Field "
			    "Replaceable Unit is "), 0);

			/*
			 * Determine whether FRU is CPU module, system
			 * board, or SBus card.
			 */
			if ((name != NULL) && (strstr(name, "sbus"))) {

				log_printf(dgettext(TEXT_DOMAIN, "SBus "
				    "Card %d\n"), get_sbus_slot(pnode), 0);

			} else if (((name = get_node_name(pnode)) !=
			    NULL) && (strstr(name, "pci"))) {

				log_printf(dgettext(TEXT_DOMAIN, "system "
				    "board\n"), 0);

			} else if (((name = get_node_name(pnode)) !=
			    NULL) && (strstr(name, "ffb"))) {

				log_printf(dgettext(TEXT_DOMAIN, "FFB "
				    "Card %d\n"), tazmo_physical_slot(
				    dev_find_node(bnode->nodes, "slot2dev"),
				    pnode, -1, slot_str), 0);

			} else if (((name = get_node_name(pnode->parent)) !=
			    NULL) && (strstr(name, "pci"))) {

				(void) tazmo_physical_slot(NULL,
				    pnode->parent,
				    get_pci_device(pnode),
				    slot_str);
				log_printf(dgettext(TEXT_DOMAIN, "PCI Card "
				    "in %s\n"), slot_str, 0);

			} else if (((type = get_node_type(pnode)) != NULL) &&
			    (strstr(type, "cpu"))) {

				log_printf(
				    dgettext(TEXT_DOMAIN, "UltraSPARC "
				    "module Module %d\n"),
				    get_id(pnode));

			} else if (((type = get_node_type(pnode)) != NULL) &&
			    (strstr(type, "memory-module"))) {

				fru = (char *)(get_prop_val(
				    find_prop(pnode, "fru")));
				sock_name = (char *)(get_prop_val(
				    find_prop(pnode, "socket-name")));
				log_printf(
				    dgettext(TEXT_DOMAIN, "%s in "
				    "socket %s\n"), fru,
				    sock_name, 0);
			}
			pnode = next_failed_node(pnode);
		}
		bnode = bnode->next;
	}

	if (!system_failed) {
		log_printf("\n", 0);
		log_printf(dgettext(TEXT_DOMAIN, "No failures found "
		    "in System\n"), 0);
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

		(void) disp_envc_status(kstats);

		tazjav_disp_asic_revs(tree);

		platform_disp_prom_version(tree);
	}
	return;

}

/* ARGSUSED */
void
display_boardnum(int num)
{
	log_printf("SYS   ", 0);
}



/*
 * display_pci
 * Display all the PCI IO cards on this board.
 */

/* ARGSUSED */
void
display_pci(Board_node *board)
{
	struct io_card *card_list = NULL;
	struct io_card card;
	void *value;
	Prom_node *pci;
	Prom_node *card_node;

	if (board == NULL)
		return;

	/* Initialize all the common information */
	card.display = 1;
	card.board = board->board_num;
	(void) sprintf(card.bus_type, "PCI");

	for (pci = dev_find_node(board->nodes, PCI_NAME); pci != NULL;
	    pci = dev_next_node(pci, PCI_NAME)) {
		char *name;
		Prom_node *prev_parent = NULL;
		int prev_device = -1;
		int pci_pci_bridge = 0;

		/*
		 * If we have reached a pci-to-pci bridge node,
		 * we are one level below the 'pci' nodes level
		 * in the device tree. To get back to that level,
		 * the search should continue with the sibling of
		 * the parent or else the remaining 'pci' cards
		 * will not show up in the output.
		 */
		if (find_prop(pci, "upa-portid") == NULL) {
			if ((pci->parent->sibling != NULL) &&
			    (strcmp(get_prop_val(
			    find_prop(pci->parent->sibling,
			    "name")), PCI_NAME) == 0))
				pci = pci->parent->sibling;
			else {
				pci = pci->parent->sibling;
				continue;
			}
		}

		/* Skip all failed nodes for now */
		if (node_failed(pci))
			continue;

		/* Fill in frequency */
		value = get_prop_val(find_prop(pci, "clock-frequency"));
		if (value == NULL)
			card.freq = -1;
		else
			card.freq = ((*(int *)value) + 500000) / 1000000;

		/* Walk through the PSYCHO children */
		card_node = pci->child;
		while (card_node != NULL) {
			Prop *compat = NULL;

			/* If it doesn't have a name, skip it */
			name = (char *)get_prop_val(
			    find_prop(card_node, "name"));
			if (name == NULL) {
				card_node = card_node->sibling;
				continue;
			}

			/*
			 * If this is a PCI bridge, then display its
			 * children.
			 */
			if (strcmp(name, "pci") == 0) {
				card_node = card_node->child;
				pci_pci_bridge = 1;
				continue;
			}

			/* Get the slot number for this card */
			if (pci_pci_bridge) {
				card.slot = tazmo_physical_slot(
				    dev_find_node(board->nodes, "slot2dev"),
				    pci,
				    get_pci_to_pci_device(card_node->parent),
				    card.slot_str);
			} else
				card.slot = tazmo_physical_slot(
				    dev_find_node(board->nodes, "slot2dev"),
				    pci,
				    get_pci_device(card_node),
				    card.slot_str);

			/*
			 * Check that duplicate devices are not reported
			 * on Tazmo.
			 */
			if ((card_node->parent == prev_parent) &&
			    (get_pci_device(card_node) == prev_device) &&
			    (pci_pci_bridge == 0))
				card.slot = -1;
			prev_parent = card_node->parent;
			prev_device = get_pci_device(card_node);


			if (card.slot == -1 || strstr(name, "ebus")) {
				card_node = card_node->sibling;
				continue;
			}

			/* XXX - Don't know how to get status for PCI cards */
			card.status[0] = '\0';

			/* Get the model of this card */
			value = get_prop_val(find_prop(card_node, "model"));
			if (value == NULL)
				card.model[0] = '\0';
			else
				(void) sprintf(card.model, "%s",
				    (char *)value);

			/*
			 * Check if further processing is necessary to display
			 * this card uniquely.
			 */
			distinguish_identical_io_cards(name, card_node, &card);


			/*
			 * If we haven't figured out the frequency yet,
			 * try and get it from the card.
			 */
			value = get_prop_val(find_prop(pci, "clock-frequency"));
			if (value != NULL && card.freq == -1)
				card.freq = ((*(int *)value) + 500000)
				    / 1000000;


			value = get_prop_val(find_prop(card_node,
			    "compatible"));

			/*
			 * On Tazmo, we would like to print out the last
			 * string of the "compatible" property if it exists.
			 * The IEEE 1275 spec. states that this last string
			 * will be the classcode name.
			 */
			if (value != NULL) {
				char *tval;
				int index;
				const int always = 1;

				tval = (char *)value;
				index = 0;
				compat = find_prop(card_node, "compatible");
				while (always) {
					if ((strlen(tval) + 1) ==
					    (compat->size - index))
						break;
					index += strlen(tval) + 1;
					tval += strlen(tval) + 1;
				}
				value = (void *)tval;
			}

			if (value != NULL)
				(void) sprintf(card.name, "%s-%s",
				    (char *)name, (char *)value);
			else
				(void) sprintf(card.name, "%s",
				    (char *)name);

			if (card.freq != -1)
				card_list = insert_io_card(card_list, &card);

			/*
			 * If we are done with the children of the pci bridge,
			 * we must continue with the remaining siblings of
			 * the pci-to-pci bridge.
			 */
			if ((card_node->sibling == NULL) && pci_pci_bridge) {
				card_node = card_node->parent->sibling;
				pci_pci_bridge = 0;
			} else
				card_node = card_node->sibling;
		}
	}

	display_io_cards(card_list);
	free_io_cards(card_list);
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

	if (banner == 0) {
		log_printf("     Bus   Freq\n", 0);
		log_printf("Brd  Type  MHz   Slot  "
		    "Name                              "
		    "Model", 0);
		log_printf("\n", 0);
		log_printf("---  ----  ----  ----  "
		    "--------------------------------  "
		    "----------------------", 0);
		log_printf("\n", 0);
		banner = 1;
	}

	for (p = list; p != NULL; p = p -> next) {
		log_printf("SYS   ", p->board, 0);
		log_printf("%-4s  ", p->bus_type, 0);
		log_printf("%3d   ", p->freq, 0);
		log_printf("%3d   ", p->slot, 0);
		log_printf("%-32.32s", p->name, 0);
		if (strlen(p->name) > 32)
			log_printf("+ ", 0);
		else
			log_printf("  ", 0);
		log_printf("%-22.22s", p->model, 0);
		if (strlen(p->model) > 22)
			log_printf("+", 0);
		log_printf("\n", 0);
	}
}

/*
 * display_ffb
 * Display all FFBs on this board.  It can either be in tabular format,
 * or a more verbose format.
 */
void
display_ffb(Board_node *board, int table)
{
	Prom_node *ffb;
	void *value;
	struct io_card *card_list = NULL;
	struct io_card card;

	if (board == NULL)
		return;

	/* Fill in common information */
	card.display = 1;
	card.board = board->board_num;
	(void) sprintf(card.bus_type, "UPA");
	card.freq = sys_clk;

	for (ffb = dev_find_node(board->nodes, FFB_NAME); ffb != NULL;
	    ffb = dev_next_node(ffb, FFB_NAME)) {
		if (table == 1) {
			/* Print out in table format */

			/* XXX - Get the slot number (hack) */
			card.slot = tazmo_physical_slot(
			    dev_find_node(board->nodes, "slot2dev"),
			    ffb,
			    -1,
			    card.slot_str);

			/* Find out if it's single or double buffered */
			(void) sprintf(card.name, "FFB");
			value = get_prop_val(find_prop(ffb, "board_type"));
			if (value != NULL)
				if ((*(int *)value) & FFB_B_BUFF)
					(void) sprintf(card.name,
					    "FFB, Double Buffered");
				else
					(void) sprintf(card.name,
					    "FFB, Single Buffered");

			/* Print model number */
			card.model[0] = '\0';
			value = get_prop_val(find_prop(ffb, "model"));
			if (value != NULL)
				(void) sprintf(card.model, "%s",
				    (char *)value);

			card_list = insert_io_card(card_list, &card);
		} else {
			/* print in long format */
			char device[MAXSTRLEN];
			int fd = -1;
			struct dirent *direntp;
			DIR *dirp;
			union strap_un strap;
			struct ffb_sys_info fsi;

			/* Find the device node using upa address */
			value = get_prop_val(find_prop(ffb, "upa-portid"));
			if (value == NULL)
				continue;

			(void) sprintf(device, "%s@%x", FFB_NAME,
			    *(int *)value);
			if ((dirp = opendir("/devices")) == NULL)
				continue;

			while ((direntp = readdir(dirp)) != NULL) {
				if (strstr(direntp->d_name, device) != NULL) {
					(void) sprintf(device, "/devices/%s",
					    direntp->d_name);
					fd = open(device, O_RDWR, 0666);
					break;
				}
			}
			(void) closedir(dirp);

			if (fd == -1)
				continue;

			if (ioctl(fd, FFB_SYS_INFO, &fsi) < 0)
				continue;

			log_printf("FFB Hardware Configuration:\n", 0);
			log_printf("-----------------------------------\n", 0);

			strap.ffb_strap_bits = fsi.ffb_strap_bits;
			log_printf("\tBoard rev: %d\n",
			    (int)strap.fld.board_rev, 0);
			log_printf("\tFBC version: "
			    "0x%x\n", fsi.fbc_version, 0);
			log_printf("\tDAC: %s\n",
			    fmt_manf_id(fsi.dac_version, device), 0);
			log_printf("\t3DRAM: %s\n",
			    fmt_manf_id(fsi.fbram_version, device), 0);
			log_printf("\n", 0);
		}
	}

	display_io_cards(card_list);
	free_io_cards(card_list);
}

/*
 * This module does the reading and interpreting of javelin system
 * kstats. These kstats are created by the environ drivers.
 */
void
read_platform_kstats(Sys_tree *tree, struct system_kstat_data *sys_kstat,
    struct bd_kstat_data *bdp, struct envctrl_kstat_data *ep)
{
	kstat_ctl_t		*kc;
	struct envctrltwo_kstat_data *ecp;
	kstat_t			*ksp;

	if ((kc = kstat_open()) == NULL) {
		return;
	}
#ifdef lint
	tree = tree;
	bdp = bdp;
	ep = ep;
#endif

	/* read the envctrltwo kstats */
	ecp = &sys_kstat->envc_data;

	/* Read the power supply kstats */
	ksp = kstat_lookup(kc, ENVCTRL_MODULE_NAME, INSTANCE_0,
	    ENVCTRL_KSTAT_PSNAME2);

	if (ksp != NULL && (kstat_read(kc, ksp, NULL) != -1)) {
		(void) memcpy(ecp->ps_kstats, ksp->ks_data,
		    ksp->ks_ndata * sizeof (envctrl_ps2_t));
	} else {
		sys_kstat->envctrltwo_kstat_ok = B_FALSE;
		return;
	}

	ecp->num_ps_kstats = ksp->ks_ndata;

	/* Read the fan status kstats */
	ksp = kstat_lookup(kc, ENVCTRL_MODULE_NAME, INSTANCE_0,
	    ENVCTRL_KSTAT_FANSTAT);

	if (ksp != NULL && (kstat_read(kc, ksp, NULL) != -1)) {
		(void) memcpy(ecp->fan_kstats, ksp->ks_data,
		    ksp->ks_ndata * sizeof (envctrl_fan_t));
	} else {
		sys_kstat->envctrltwo_kstat_ok = B_FALSE;
		return;
	}

	ecp->num_fan_kstats = ksp->ks_ndata;

	/* Read the enclosure kstats */
	ksp = kstat_lookup(kc, ENVCTRL_MODULE_NAME, INSTANCE_0,
	    ENVCTRL_KSTAT_ENCL);

	if (ksp != NULL && (kstat_read(kc, ksp, NULL) != -1)) {
		(void) memcpy(ecp->encl_kstats, ksp->ks_data,
		    ksp->ks_ndata * sizeof (envctrl_encl_t));
	} else {
		sys_kstat->envctrltwo_kstat_ok = B_FALSE;
		return;
	}

	ecp->num_encl_kstats = ksp->ks_ndata;

	/* Read the temperature kstats */
	ksp = kstat_lookup(kc, ENVCTRL_MODULE_NAME, INSTANCE_0,
	    ENVCTRL_KSTAT_TEMPERATURE);

	if (ksp != NULL && (kstat_read(kc, ksp, NULL) != -1)) {
		(void) memcpy(ecp->temp_kstats, ksp->ks_data,
		    ksp->ks_ndata * sizeof (envctrl_temp_t));
	} else {
		sys_kstat->envctrltwo_kstat_ok = B_FALSE;
		return;
	}

	ecp->num_temp_kstats = ksp->ks_ndata;

	/* Read the disk kstats */
	ksp = kstat_lookup(kc, ENVCTRL_MODULE_NAME, INSTANCE_0,
	    ENVCTRL_KSTAT_DISK);

	if (ksp != NULL && (kstat_read(kc, ksp, NULL) != -1)) {
		(void) memcpy(ecp->disk_kstats, ksp->ks_data,
		    ksp->ks_ndata * sizeof (envctrl_disk_t));
	} else {
		sys_kstat->envctrltwo_kstat_ok = B_FALSE;
		return;
	}

	ecp->num_disk_kstats = ksp->ks_ndata;

	sys_kstat->envctrltwo_kstat_ok = 1;
	return;

}

/*
 * Walk the PROM device tree and build the system tree and root tree.
 * Nodes that have a board number property are placed in the board
 * structures for easier processing later. Child nodes are placed
 * under their parents. ffb (Fusion Frame Buffer) nodes are handled
 * specially, because they do not contain board number properties.
 * This was requested from OBP, but was not granted. So this code
 * must parse the MID of the FFB to find the board#.
 */
Prom_node *
walk(Sys_tree *tree, Prom_node *root, int id)
{
	register int curnode;
	Prom_node *pnode;
	char *name;
	char *type;
	char *model;
	int board_node = 0;

	/* allocate a node for this level */
	if ((pnode = (Prom_node *) malloc(sizeof (struct prom_node))) ==
	    NULL) {
		perror("malloc");
		exit(2);	/* program errors cause exit 2 */
	}

	/* assign parent Prom_node */
	pnode->parent = root;
	pnode->sibling = NULL;
	pnode->child = NULL;

	/* read properties for this node */
	dump_node(pnode);

	/*
	 * Place a node in a 'board' if it has 'board'-ness. The definition
	 * is that all nodes that are children of root should have a
	 * board# property. But the PROM tree does not exactly follow
	 * this. This is where we start hacking. The name 'ffb' can
	 * change, so watch out for this.
	 *
	 * The UltraSPARC, sbus, pci and ffb nodes will exit in
	 * the desktops and will not have board# properties. These
	 * cases must be handled here.
	 *
	 * PCI to PCI bridges also have the name "pci", but with different
	 * model property values.  They should not be put under 'board'.
	 */
	name = get_node_name(pnode);
	type = get_node_type(pnode);
	model = (char *)get_prop_val(find_prop(pnode, "model"));
#ifdef DEBUG
	if (name != NULL)
		printf("name=%s ", name);
	if (type != NULL)
		printf("type=%s ", type);
	if (model != NULL)
		printf("model=%s", model);
	printf("\n");

	if (model == NULL)
		model = "";
#endif
	if (type == NULL)
		type = "";
	if (name != NULL) {
		if (has_board_num(pnode)) {
			add_node(tree, pnode);
			board_node = 1;
#ifdef DEBUG
			printf("ADDED BOARD name=%s type=%s model=%s\n",
			    name, type, model);
#endif
		} else if ((strcmp(name, FFB_NAME)  == 0)		||
		    (strcmp(type, "cpu") == 0)				||

		    ((strcmp(name, "pci") == 0) && (model != NULL) &&
		    (strcmp(model, "SUNW,psycho") == 0))		||

		    ((strcmp(name, "pci") == 0) && (model != NULL) &&
		    (strcmp(model, "SUNW,sabre") == 0))			||

		    (strcmp(name, "counter-timer") == 0)		||
		    (strcmp(name, "sbus") == 0)				||
		    (strcmp(name, "memory") == 0)			||
		    (strcmp(name, "mc") == 0)				||
		    (strcmp(name, "associations") == 0)) {
			add_node(tree, pnode);
			board_node = 1;
#ifdef DEBUG
			printf("ADDED BOARD name=%s type=%s model=%s\n",
			    name, type, model);
#endif
		}
#ifdef DEBUG
		else
			printf("node not added: name=%s type=%s\n", name, type);
#endif
	}

	if (curnode = child(id)) {
		pnode->child = walk(tree, pnode, curnode);
	}

	if (curnode = next(id)) {
		if (board_node) {
			return (walk(tree, root, curnode));
		} else {
			pnode->sibling = walk(tree, root, curnode);
		}
	}

	if (board_node) {
		return (NULL);
	} else {
		return (pnode);
	}
}

/*
 * local functions
 */

/*
 * disp_envc_status
 *
 * This routine displays the environmental status passed up from
 * device drivers via kstats. The kstat names are defined in
 * kernel header files included by this module.
 * This is a Javelin specific environmental information display routine.
 */
static int
disp_envc_status(struct system_kstat_data *sys_kstats)
{
	struct envctrltwo_kstat_data *ecp;
	envctrl_ps2_t ps_ks;
	envctrl_fan_t fans_ks;
	envctrl_encl_t encl_ks;
	envctrl_temp_t temp_ks;
	envctrl_disk_t disk_ks;
	char state[48];
	uchar_t val, fsp_value;
	uchar_t disk_pr, disk_fl;
	int i;
	int exit_code = 0;

	if (sys_kstats->envctrltwo_kstat_ok == 0) {
		log_printf("\n", 0);
		log_printf(dgettext(TEXT_DOMAIN, "Environmental information "
		    "is not available\n"), 0);
		log_printf(dgettext(TEXT_DOMAIN, "Environmental driver may "
		    "not be installed\n"), 0);
		log_printf("\n", 0);
		return (1);
	}

	ecp = &sys_kstats->envc_data;

	log_printf("\n", 0);
	log_printf("=========================", 0);
	log_printf(dgettext(TEXT_DOMAIN, " Environmental Status "), 0);
	log_printf("=========================", 0);
	log_printf("\n", 0);
	log_printf("\n", 0);

	log_printf("System Temperatures (Celsius):\n", 0);
	log_printf("------------------------------\n", 0);

	for (i = 0; i < ecp->num_temp_kstats; i++) {
		temp_ks = ecp->temp_kstats[i];
		log_printf("%10s    %d", temp_ks.label, temp_ks.value);
		if (temp_ks.value >= temp_ks.shutdown_threshold) {
			log_printf("    CRITICAL\n", 0);
			exit_code = 1;
		} else if (temp_ks.value >= temp_ks.warning_threshold) {
			log_printf("    WARNING\n", 0);
			exit_code = 1;
		} else if (temp_ks.value < temp_ks.min) {
			log_printf("    WARNING\n", 0);
			exit_code = 1;
		} else
			log_printf("\n", 0);
	}

	log_printf("\n", 0);
	log_printf("=================================\n", 0);
	log_printf("\n", 0);
	encl_ks = ecp->encl_kstats[0];
	val = encl_ks.value & ENVCTRL_UE250_FSP_KEYMASK;
	fsp_value = encl_ks.value;
	switch (val) {
	case ENVCTRL_UE250_FSP_KEYOFF:
		(void) sprintf(state, "%s", "Off");
		break;
	case ENVCTRL_UE250_FSP_KEYON:
		(void) sprintf(state, "%s", "On");
		break;
	case ENVCTRL_UE250_FSP_KEYDIAG:
		(void) sprintf(state, "%s", "Diagnostic");
		break;
	case ENVCTRL_UE250_FSP_KEYLOCKED:
		(void) sprintf(state, "%s", "Secure");
		break;
	default:
		(void) sprintf(state, "%s", "Broken!");
		exit_code = 1;
		break;
	}
	log_printf("Front Status Panel:\n", 0);
	log_printf("-------------------\n", 0);
	log_printf("Keyswitch position is in %s mode.\n", state);
	log_printf("\n", 0);
	val = fsp_value & (ENVCTRL_UE250_FSP_DISK_ERR |
	    ENVCTRL_UE250_FSP_PS_ERR | ENVCTRL_UE250_FSP_TEMP_ERR |
	    ENVCTRL_UE250_FSP_GEN_ERR | ENVCTRL_UE250_FSP_ACTIVE);
	log_printf("System LED Status:  DISK ERROR      POWER  \n", 0);
	log_printf("                      [%3s]         [ ON]      \n",
	    val & ENVCTRL_UE250_FSP_DISK_ERR ? "ON" : "OFF");
	log_printf("                POWER SUPPLY ERROR  ACTIVITY \n", 0);
	log_printf("                      [%3s]         [%3s]      \n",
	    val & ENVCTRL_UE250_FSP_PS_ERR ? "ON" : "OFF",
	    val & ENVCTRL_UE250_FSP_ACTIVE ? "ON" : "OFF");
	log_printf("                    GENERAL ERROR   THERMAL ERROR  \n", 0);
	log_printf("                      [%3s]         [%3s]      \n",
	    val & ENVCTRL_UE250_FSP_GEN_ERR ? "ON" : "OFF",
	    val & ENVCTRL_UE250_FSP_TEMP_ERR ? "ON" : "OFF");
	if (val & (ENVCTRL_UE250_FSP_DISK_ERR | ENVCTRL_UE250_FSP_PS_ERR |
	    ENVCTRL_UE250_FSP_GEN_ERR | ENVCTRL_UE250_FSP_TEMP_ERR)) {
		exit_code = 1;
	}

	log_printf("\n", 0);
	log_printf("=================================\n", 0);
	log_printf("\n", 0);
	disk_pr = disk_fl = 0;
	for (i = 0; i < ecp->num_disk_kstats; i++) {
		disk_ks = ecp->disk_kstats[i];
		if (disk_ks.slot == -1)
			continue;
		disk_pr |= 1 << disk_ks.slot;
		if (disk_ks.disk_ok == 0)
			disk_fl |= 1 << disk_ks.slot;
	}

	log_printf("Disk LED Status:	OK = GREEN	ERROR = YELLOW\n", 0);
	log_printf("		DISK  5: %7s	DISK  3: %7s	DISK  1: %7s\n",
	    disk_pr & ENVCTRL_DISK_5 ?
	    disk_fl & ENVCTRL_DISK_5 ? "[ERROR]" : "[OK]" : "[EMPTY]",
	    disk_pr & ENVCTRL_DISK_3 ?
	    disk_fl & ENVCTRL_DISK_3 ? "[ERROR]" : "[OK]" : "[EMPTY]",
	    disk_pr & ENVCTRL_DISK_1 ?
	    disk_fl & ENVCTRL_DISK_1 ? "[ERROR]" : "[OK]" : "[EMPTY]");
	log_printf("		DISK  4: %7s	DISK  2: %7s	DISK  0: %7s\n",
	    disk_pr & ENVCTRL_DISK_4 ?
	    disk_fl & ENVCTRL_DISK_4 ? "[ERROR]" : "[OK]" : "[EMPTY]",
	    disk_pr & ENVCTRL_DISK_2 ?
	    disk_fl & ENVCTRL_DISK_2 ? "[ERROR]" : "[OK]" : "[EMPTY]",
	    disk_pr & ENVCTRL_DISK_0 ?
	    disk_fl & ENVCTRL_DISK_0 ? "[ERROR]" : "[OK]" : "[EMPTY]");

	log_printf("\n", 0);
	log_printf("=================================\n", 0);
	log_printf("\n", 0);
	log_printf("Fan Bank :\n", 0);
	log_printf("----------\n", 0);
	log_printf("\n", 0);

	fans_ks = ecp->fan_kstats[0];
	log_printf("Bank      Speed     Status\n", 0);
	log_printf("         (0-255)	\n", 0);
	log_printf("----      -----     ------\n", 0);
	if (fans_ks.fans_ok == B_TRUE)
		log_printf(" SYS     %5d        OK\n", fans_ks.fanspeed);
	else if (fans_ks.fans_ok != B_TRUE) {
		log_printf(" SYS     %5d      FAILED\n", fans_ks.fanspeed);
		exit_code = 1;
	}

	log_printf("\n", 0);
	log_printf("=================================\n", 0);
	log_printf("\n", 0);
	log_printf("Power Supplies:\n", 0);
	log_printf("---------------\n", 0);
	log_printf("\n", 0);
	log_printf("Supply     Status\n", 0);
	log_printf("------     ------\n", 0);

	for (i = 0; i < ecp->num_ps_kstats; i++) {
		ps_ks = ecp->ps_kstats[i];
		if (ps_ks.ps_ok == B_TRUE)
			(void) sprintf(state, "%s", "  OK  ");
		else if (ps_ks.ps_ok != B_TRUE) {
			(void) sprintf(state, "%s", "FAILED: DC "
			    "Power Failure");
			exit_code = 1;
		}

		log_printf(" %2d        %s\n", ps_ks.slot, state);
	}

	return (exit_code);
}

void
tazjav_disp_asic_revs(Sys_tree *tree)
{
	Board_node *bnode;
	Prom_node *pnode;
	char *name;
	int *version;
	char *model;

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
			log_printf("SBus: %s Rev %d\n", name, *version, 0);
		}
	}

	/* Find Psycho and print rev */
	for (pnode = dev_find_node(bnode->nodes, "pci"); pnode != NULL;
	    pnode = dev_next_node(pnode, "pci")) {
		Prom_node *parsib = pnode->parent->sibling;

		if (find_prop(pnode, "upa-portid") == NULL) {
			if ((parsib != NULL) &&
			    (strcmp(get_prop_val(
			    find_prop(parsib, "name")),
			    PCI_NAME) == 0))
				pnode = parsib;
			else {
				pnode = parsib;
				continue;
			}
		}

		version = (int *)get_prop_val(find_prop(pnode, "version#"));
		name = get_prop_val(find_prop(pnode, "name"));

		if ((version != NULL) && (name != NULL))
			if (get_pci_bus(pnode) == 0)
				log_printf("STP2223BGA: Rev %d\n", *version, 0);
	}

	/* Find Cheerio and print rev */
	for (pnode = dev_find_node(bnode->nodes, "ebus"); pnode != NULL;
	    pnode = dev_next_node(pnode, "ebus")) {
		version = (int *)get_prop_val(find_prop(pnode, "revision-id"));
		name = get_prop_val(find_prop(pnode, "name"));

		if ((version != NULL) && (name != NULL))
			log_printf("STP2003QFP: Rev %d\n", *version, 0);
	}

	/* Find System Controller and print rev */
	for (pnode = dev_find_node(bnode->nodes, "sc"); pnode != NULL;
	    pnode = dev_next_node(pnode, "sc")) {
		version = (int *)get_prop_val(find_prop(pnode, "version#"));
		model = (char *)get_prop_val(find_prop(pnode, "model"));
		name = get_prop_val(find_prop(pnode, "name"));

		if ((version != NULL) && (name != NULL)) {
			if ((strcmp(model, "SUNW,sc-marvin") == 0))
				log_printf("STP2205BGA: Rev %d\n", *version, 0);
		}
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

	if (dev_find_node(bnode->nodes, FFB_NAME) != NULL) {
		display_ffb(bnode, 0);
	}
}


/*
 * Determine the physical PCI slot based on which Psycho is the parent
 * of the PCI card.
 */
static int
tazmo_physical_slot(Prom_node *slotd, Prom_node *parent, int device, char *str)
{
	int *upa_id = NULL;
	int *reg = NULL;
	int offset;
	char controller[MAXSTRLEN];
	char *name;
	Prop *prop;
	char *devpath_p;
	char slotx[16] = "";
	int *slot_names_mask;
	char *slot_names;
	int shift = 0;
	int slot;
	int slots, start_slot;

	/*
	 * If slotd != NULL, then we must return the physical PCI slot
	 * number based on the information in the slot2dev associations
	 * node. This routine is called from display_pci() with slotd
	 * != NULL. If so, we return without obtaining the slot name.
	 * If slotd == NULL, we look for the slot name through the
	 * slot-names property in the bus node.
	 */

	if (slotd != NULL) {
		(void) strcpy(str, "");
		if ((prop = find_prop(parent, "upa-portid")) != NULL)
			upa_id = (int *)(get_prop_val(prop));
		if ((prop = find_prop(parent, "reg")) != NULL)
			reg = (int *)(get_prop_val(prop));
		if ((prop = find_prop(parent, "name")) != NULL)
			name = (char *)(get_prop_val(prop));
		if ((upa_id == NULL) || (reg == NULL)) {
			return (-1);
		}
		offset = reg[1];
		if (strcmp(name, "pci") == 0) {
			(void) sprintf(controller, "/pci@%x,%x/*@%x,*",
			    *upa_id, offset, device);
			slots = 20;
		} else if (strcmp(name, "SUNW,ffb") == 0) {
			(void) sprintf(controller, "/*@%x,0", *upa_id);
			slots = 2;
		}

		/*
		 * Javelin and future projects will use 0 based
		 * numbering for slots.
		 */
		start_slot = 0;
		slots = slots - 1;
		for (slot = start_slot; slot <= slots; slot++) {
			if (strcmp(name, "pci") == 0)
				(void) sprintf(slotx, "pci-slot#%d", slot);
			else if (strcmp(name, "SUNW,ffb") == 0)
				(void) sprintf(slotx, "graphics#%d", slot);
			if ((prop = find_prop(slotd, slotx)) != NULL)
				if ((devpath_p = (char *)(get_prop_val
				    (prop))) != NULL)
					if (strcmp(devpath_p, controller) == 0)
						return (slot);
		}
		return (-1);
	}

	/*
	 * Get slot-names property from parent node.
	 * This property consists of a 32 bit mask indicating which
	 * devices are relevant to this bus node. Following are a
	 * number of strings depending on how many bits are set in the
	 * bit mask; the first string gives the label that is printed
	 * on the chassis for the smallest device number, and so on.
	 */

	prop = find_prop(parent, "slot-names");
	if (prop == NULL) {
		(void) strcpy(str, "");
		return (-1);
	}
	slot_names_mask = (int *)(get_prop_val(prop));
	slot_names = (char *)slot_names_mask;

	slot = 1;
	slot_names += 4;	/* Skip the 4 byte bitmask */

	while (shift < 32) {
		/*
		 * Shift through the bitmask looking to see if the
		 * bit corresponding to "device" is set. If so, copy
		 * the correcsponding string to the provided pointer.
		 */
		if (*slot_names_mask & slot) {
			if (shift == device) {
				(void) strcpy(str, slot_names);
				return (0);
			}
			slot_names += strlen(slot_names)+1;
		}
		shift++;
		slot = slot << 1;
	}
	return (-1);
}
