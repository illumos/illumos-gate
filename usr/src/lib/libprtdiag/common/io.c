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
 * Copyright (c) 1999-2001 by Sun Microsystems, Inc.
 * All rights reserved.
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
#include <sys/systeminfo.h>
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

Prom_node *
find_pci_bus(Prom_node *node, int id, int bus)
{
	Prom_node *pnode;

	/* find the first pci node */
	pnode = dev_find_node(node, "pci");

	while (pnode != NULL) {
		int tmp_id;
		int tmp_bus;

		tmp_id = get_id(pnode);
		tmp_bus = get_pci_bus(pnode);

		if ((tmp_id == id) &&
		    (tmp_bus == bus)) {
			break;
		}

		pnode = dev_next_node(pnode, "pci");
	}
	return (pnode);
}

/*
 * get_pci_bus
 *
 * Determines the PCI bus, either A (0) or B (1). If the function cannot
 * find the bus-ranges property, it returns -1.
 */
int
get_pci_bus(Prom_node *pnode)
{
	int *value;

	/* look up the bus-range property */
	if ((value = (int *)get_prop_val(find_prop(pnode, "bus-range"))) ==
	    NULL) {
		return (-1);
	}

	if (*value == 0) {
		return (1);	/* B bus has a bus-range value = 0 */
	} else {
		return (0);
	}
}



/*
 * Find the PCI device number of this PCI device. If no device number can
 * be determined, then return -1.
 */
int
get_pci_device(Prom_node *pnode)
{
	void *value;

	value = get_prop_val(find_prop(pnode, "assigned-addresses"));
	if (value != NULL) {
		return (PCI_DEVICE(*(int *)value));
	} else {
		return (-1);
	}
}

/*
 * Find the PCI device number of this PCI device. If no device number can
 * be determined, then return -1.
 */
int
get_pci_to_pci_device(Prom_node *pnode)
{
	void *value;

	value = get_prop_val(find_prop(pnode, "reg"));
	if (value != NULL) {
		return (PCI_DEVICE(*(int *)value));
	} else {
		return (-1);
	}
}

/*
 * free_io_cards
 * Frees the memory allocated for an io card list.
 */
void
free_io_cards(struct io_card *card_list)
{
	/* Free the list */
	if (card_list != NULL) {
		struct io_card *p, *q;

		for (p = card_list, q = NULL; p != NULL; p = q) {
			q = p->next;
			free(p);
		}
	}
}


/*
 * insert_io_card
 * Inserts an io_card structure into the list.  The list is maintained
 * in order based on board number and slot number.  Also, the storage
 * for the "card" argument is assumed to be handled by the caller,
 * so we won't touch it.
 */
struct io_card *
insert_io_card(struct io_card *list, struct io_card *card)
{
	struct io_card *newcard;
	struct io_card *p, *q;

	if (card == NULL)
		return (list);

	/* Copy the card to be added into new storage */
	newcard = (struct io_card *)malloc(sizeof (struct io_card));
	if (newcard == NULL) {
		perror("malloc");
		exit(2);
	}
	(void) memcpy(newcard, card, sizeof (struct io_card));
	newcard->next = NULL;

	if (list == NULL)
		return (newcard);

	/* Find the proper place in the list for the new card */
	for (p = list, q = NULL; p != NULL; q = p, p = p->next) {
		if (newcard->board < p->board)
			break;
		if ((newcard->board == p->board) && (newcard->slot < p->slot))
			break;
	}

	/* Insert the new card into the list */
	if (q == NULL) {
		newcard->next = p;
		return (newcard);
	} else {
		newcard->next = p;
		q->next = newcard;
		return (list);
	}
}


char *
fmt_manf_id(unsigned int encoded_id, char *outbuf)
{
	union manuf manuf;

	/*
	 * Format the manufacturer's info.  Note a small inconsistency we
	 * have to work around - Brooktree has it's part number in decimal,
	 * while Mitsubishi has it's part number in hex.
	 */
	manuf.encoded_id = encoded_id;
	switch (manuf.fld.manf) {
	case MANF_BROOKTREE:
		(void) sprintf(outbuf, "%s %d, version %d", "Brooktree",
		    manuf.fld.partno, manuf.fld.version);
		break;

	case MANF_MITSUBISHI:
		(void) sprintf(outbuf, "%s %x, version %d", "Mitsubishi",
		    manuf.fld.partno, manuf.fld.version);
		break;

	default:
		(void) sprintf(outbuf, "JED code %d, Part num 0x%x, version %d",
		    manuf.fld.manf, manuf.fld.partno, manuf.fld.version);
	}
	return (outbuf);
}


/*
 * Find the sbus slot number of this Sbus device. If no slot number can
 * be determined, then return -1.
 */
int
get_sbus_slot(Prom_node *pnode)
{
	void *value;

	if ((value = get_prop_val(find_prop(pnode, "reg"))) != NULL) {
		return (*(int *)value);
	} else {
		return (-1);
	}
}


/*
 * This routine is the generic link into displaying system IO
 * configuration. It displays the table header, then displays
 * all the SBus cards, then displays all fo the PCI IO cards.
 */
void
display_io_devices(Sys_tree *tree)
{
	Board_node *bnode;

	/*
	 * TRANSLATION_NOTE
	 * Following string is used as a table header.
	 * Please maintain the current alignment in
	 * translation.
	 */
	log_printf("\n", 0);
	log_printf("=========================", 0);
	log_printf(dgettext(TEXT_DOMAIN, " IO Cards "), 0);
	log_printf("=========================", 0);
	log_printf("\n", 0);
	log_printf("\n", 0);
	bnode = tree->bd_list;
	while (bnode != NULL) {
		display_sbus(bnode);
		display_pci(bnode);
		display_ffb(bnode, 1);
		bnode = bnode->next;
	}
}

void
display_pci(Board_node *bnode)
{
#ifdef  lint
	bnode = bnode;
#endif
	/*
	 * This function is intentionally empty
	 */
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
		log_printf("Brd  Type  MHz   Slot        "
		    "Name                          "
		    "Model", 0);
		log_printf("\n", 0);
		log_printf("---  ----  ----  ----------  "
		    "----------------------------  "
		    "--------------------", 0);
		log_printf("\n", 0);
		banner = 1;
	}

	for (p = list; p != NULL; p = p -> next) {
		log_printf("%2d   ", p->board, 0);
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
	}
}

/*
 * Display all FFBs on this board.  It can either be in tabular format,
 * or a more verbose format.
 */
void
display_ffb(Board_node *board, int table)
{
	Prom_node *fb;
	void *value;
	struct io_card *card_list = NULL;
	struct io_card card;
	char *type;
	char *label;

	if (board == NULL)
		return;

	/* Fill in common information */
	card.display = 1;
	card.board = board->board_num;
	(void) sprintf(card.bus_type, BUS_TYPE);
	card.freq = sys_clk;

	for (fb = dev_find_node_by_type(board->nodes, "device_type", "display");
	    fb != NULL;
	    fb = dev_next_node_by_type(fb, "device_type", "display")) {
		value = get_prop_val(find_prop(fb, "name"));
		if (value != NULL) {
			if ((strcmp(FFB_NAME, value)) == 0) {
				type = FFB_NAME;
				label = "FFB";
			} else if ((strcmp(AFB_NAME, value)) == 0) {
				type = AFB_NAME;
				label = "AFB";
			} else
				continue;
		} else
			continue;
		if (table == 1) {
			/* Print out in table format */

			/* XXX - Get the slot number (hack) */
			card.slot = get_id(fb);

			/* Find out if it's single or double buffered */
			(void) sprintf(card.name, "%s", label);
			value = get_prop_val(find_prop(fb, "board_type"));
			if (value != NULL)
				if ((*(int *)value) & FFB_B_BUFF)
					(void) sprintf(card.name,
					    "%s, Double Buffered", label);
				else
					(void) sprintf(card.name,
					    "%s, Single Buffered", label);

			/*
			 * Print model number only if board_type bit 2
			 * is not set and it is not SUNW,XXX-XXXX.
			 */
			card.model[0] = '\0';

			if (strcmp(type, AFB_NAME) == 0) {
				if (((*(int *)value) & 0x4) != 0x4) {
					value = get_prop_val(find_prop(fb,
					    "model"));
					if ((value != NULL) &&
					    (strcmp(value,
					    "SUNW,XXX-XXXX") != 0)) {
						(void) sprintf(card.model, "%s",
						    (char *)value);
					}
				}
			} else {
				value = get_prop_val(find_prop(fb, "model"));
				if (value != NULL)
					(void) sprintf(card.model, "%s",
					    (char *)value);
			}

			card_list = insert_io_card(card_list, &card);
		} else {
			/* print in long format */
			char device[MAXSTRLEN];
			int fd = -1;
			struct dirent *direntp;
			DIR *dirp;
			union strap_un strap;
			struct ffb_sys_info fsi;

			/* Find the device node using upa-portid/portid */
			value = get_prop_val(find_prop(fb, "upa-portid"));
			if (value == NULL)
				value = get_prop_val(find_prop(fb, "portid"));

			if (value == NULL)
				continue;

			(void) sprintf(device, "%s@%x", type,
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

			log_printf("%s Hardware Configuration:\n", label, 0);
			log_printf("-----------------------------------\n", 0);

			strap.ffb_strap_bits = fsi.ffb_strap_bits;
			log_printf("\tBoard rev: %d\n",
			    (int)strap.fld.board_rev, 0);
			log_printf("\tFBC version: 0x%x\n", fsi.fbc_version, 0);
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


/*
 * Get slot-names properties from parent node and
 * store them in an array.
 */
int
populate_slot_name_arr(Prom_node *pci, int *slot_name_bits,
    char **slot_name_arr, int num_slots)
{
	int	i, j, bit_mask;
	char	*value;

	value = (char *)get_prop_val(find_prop(pci, "slot-names"));
	D_PRINTF("\n populate_slot_name_arr: value = [0x%x]\n", value);

	if (value != NULL) {
		char	*strings_arr[MAX_SLOTS_PER_IO_BD];
		bit_mask = *slot_name_bits = *(int *)value;
		D_PRINTF("\nslot_names 1st integer = [0x%x]", *slot_name_bits);

		/* array starts after first int */
		strings_arr[0] = value + sizeof (int);

		/*
		 * break the array out into num_slots number of strings
		 */
		for (i = 1; i < num_slots; i++) {
			strings_arr[i] = (char *)strings_arr[i - 1]
			    + strlen(strings_arr[i - 1]) + 1;
		}

		/*
		 * process array of slot_names to remove blanks
		 */
		j = 0;
		for (i = 0; i < num_slots; i++) {
			if ((bit_mask >> i) & 0x1)
				slot_name_arr[i] = strings_arr[j++];
			else
				slot_name_arr[i] = "";

			D_PRINTF("\nslot_name_arr[%d] = [%s]", i,
			    slot_name_arr[i]);
		}
		return (0);
	} else {
		D_PRINTF("\n populate_slot_name_arr: - psycho with no "
		    "slot-names\n");
		return (0);
	}
}

int
get_card_frequency(Prom_node *pci)
{
	char	*value = get_prop_val(find_prop(pci, "clock-frequency"));

	if (value == NULL)
		return (-1);
	else
		return (int)(((*(int *)value) + 500000) / 1000000);

}

void
get_dev_func_num(Prom_node *card_node, int *dev_no, int *func_no)
{

	void	*value = get_prop_val(find_prop(card_node, "reg"));

	if (value != NULL) {
		int int_val = *(int *)value;
		*dev_no = PCI_REG_TO_DEV(int_val);
		*func_no = PCI_REG_TO_FUNC(int_val);
	} else {
		*dev_no = -1;
		*func_no = -1;
	}
}

void
get_pci_class_codes(Prom_node *card_node, int *class_code, int *subclass_code)
{
	int	class_code_reg = get_pci_class_code_reg(card_node);

	*class_code = CLASS_REG_TO_CLASS(class_code_reg);
	*subclass_code = CLASS_REG_TO_SUBCLASS(class_code_reg);
}

int
is_pci_bridge(Prom_node *card_node, char *name)
{
	int class_code, subclass_code;

	if (card_node == NULL)
		return (FALSE);

	get_pci_class_codes(card_node, &class_code, &subclass_code);

	if ((strncmp(name, "pci", 3) == 0) &&
	    (class_code == PCI_BRIDGE_CLASS) &&
	    (subclass_code == PCI_PCI_BRIDGE_SUBCLASS))
		return (TRUE);
	else
		return (FALSE);
}

int
is_pci_bridge_other(Prom_node *card_node, char *name)
{
	int class_code, subclass_code;

	if (card_node == NULL)
		return (FALSE);

	get_pci_class_codes(card_node, &class_code, &subclass_code);

	if ((strncmp(name, "pci", 3) == 0) &&
	    (class_code == PCI_BRIDGE_CLASS) &&
	    (subclass_code == PCI_SUBCLASS_OTHER))
		return (TRUE);
	else
		return (FALSE);
}
void
get_pci_card_model(Prom_node *card_node, char *model)
{
	char	*name = get_prop_val(find_prop(card_node, "name"));
	char	*value = get_prop_val(find_prop(card_node, "model"));
	int	pci_bridge = is_pci_bridge(card_node, name);

	if (value == NULL)
		model[0] = '\0';
	else
		(void) sprintf(model, "%s", value);

	if (pci_bridge) {
		if (strlen(model) == 0)
			(void) sprintf(model, "%s", "pci-bridge");
		else
			(void) sprintf(model, "%s/pci-bridge", model);
	}
}

void
create_io_card_name(Prom_node *card_node, char *name, char *card_name)
{
	char	*value = get_prop_val(find_prop(card_node, "compatible"));
	char	*child_name;
	char	buf[MAXSTRLEN];

	if (value != NULL) {
		(void) sprintf(buf, "%s-%s", name, value);
	} else
		(void) sprintf(buf, "%s", name);

	name = buf;

	child_name = (char *)get_node_name(card_node->child);

	if ((card_node->child != NULL) &&
	    (child_name != NULL)) {
		value = get_prop_val(find_prop(card_node->child,
		    "device_type"));
		if (value != NULL)
			(void) sprintf(card_name, "%s/%s (%s)",
			    name, child_name, value);
		else
			(void) sprintf(card_name, "%s/%s", name,
			    child_name);
	} else {
		(void) sprintf(card_name, "%s", name);
	}
}


/*
 * Desktop display_psycho_pci
 * Display all the psycho based PCI IO cards on this board.
 */

/* ARGSUSED */
void
display_psycho_pci(Board_node *board)
{
	struct io_card	*card_list = NULL;
	struct io_card	card;
	void		*value;

	Prom_node	*pci, *card_node, *pci_bridge_node = NULL;
	char		*name;
	int		slot_name_bits, pci_bridge_dev_no, class_code,
	    subclass_code, pci_pci_bridge;
	char		*slot_name_arr[MAX_SLOTS_PER_IO_BD];

	if (board == NULL)
		return;

	/* Initialize all the common information */
	card.display = 1;
	card.board = board->board_num;
	(void) sprintf(card.bus_type, "PCI");

	for (pci = dev_find_node_by_type(board->nodes, "model", "SUNW,psycho");
	    pci != NULL;
	    pci = dev_next_node_by_type(pci, "model", "SUNW,psycho")) {

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
			    "name")), PCI_NAME) == 0)) {
				pci = pci->parent->sibling;
			} else {
				pci = pci->parent->sibling;
				continue;
			}
		}

		D_PRINTF("\n\n------->Looking at device [%s][%d] - [%s]\n",
		    PCI_NAME, *((int *)get_prop_val(find_prop(
		    pci, "upa-portid"))),
		    get_prop_val(find_prop(pci, "model")));

		/* Skip all failed nodes for now */
		if (node_failed(pci))
			continue;

		/* Fill in frequency */
		card.freq = get_card_frequency(pci);

		/*
		 * Each PSYCHO device has a slot-names property that can be
		 * used to determine the slot-name string for each IO
		 * device under this node. We get this array now and use
		 * it later when looking at the children of this PSYCHO.
		 */
		if ((populate_slot_name_arr(pci, &slot_name_bits,
		    (char **)&slot_name_arr, MAX_SLOTS_PER_IO_BD)) != 0)
			goto next_card;

		/* Walk through the PSYCHO children */
		card_node = pci->child;
		while (card_node != NULL) {

			pci_pci_bridge = FALSE;

			/* If it doesn't have a name, skip it */
			name = (char *)get_prop_val(
			    find_prop(card_node, "name"));
			if (name == NULL)
				goto next_card;

			/* get dev# and func# for this card. */
			get_dev_func_num(card_node, &card.dev_no,
			    &card.func_no);

			/* get class/subclass code for this card. */
			get_pci_class_codes(card_node, &class_code,
			    &subclass_code);

			D_PRINTF("\nName [%s] - ", name);
			D_PRINTF("device no [%d] - ", card.dev_no);
			D_PRINTF("class_code [%d] subclass_code [%d] - ",
			    class_code, subclass_code);

			/*
			 * Weed out PCI Bridge, subclass 'other' and
			 * ebus nodes.
			 */
			if (((class_code == PCI_BRIDGE_CLASS) &&
			    (subclass_code == PCI_SUBCLASS_OTHER)) ||
			    (strstr(name, "ebus"))) {
				D_PRINTF("\nSkip ebus/class-other nodes [%s]",
				    name);
				goto next_card;
			}

			/*
			 * If this is a PCI bridge, then we store it's dev_no
			 * so that it's children can use it for getting at
			 * the slot_name.
			 */
			if (is_pci_bridge(card_node, name)) {
				pci_bridge_dev_no = card.dev_no;
				pci_bridge_node = card_node;
				pci_pci_bridge = TRUE;
				D_PRINTF("\nPCI Bridge detected\n");
			}

			/*
			 * If we are the child of a pci_bridge we use the
			 * dev# of the pci_bridge as an index to get
			 * the slot number. We know that we are a child of
			 * a pci-bridge if our parent is the same as the last
			 * pci_bridge node found above.
			 */
			if (card_node->parent == pci_bridge_node)
				card.dev_no = pci_bridge_dev_no;

			/* Get slot-names property from slot_names_arr. */
			get_slot_number_str(&card, (char **)slot_name_arr,
			    slot_name_bits);

			if (slot_name_bits) {
				D_PRINTF("\nIO Card [%s] dev_no [%d] SlotStr "
				    "[%s] slot [%s]", name, card.dev_no,
				    slot_name_arr[card.dev_no],
				    card.slot_str);
			}

			/* XXX - Don't know how to get status for PCI cards */
			card.status[0] = '\0';

			/* Get the model of this card */
			get_pci_card_model(card_node, (char *)&card.model);

			/*
			 * If we haven't figured out the frequency yet,
			 * try and get it from the card.
			 */
			value = get_prop_val(find_prop(pci, "clock-frequency"));
			if (value != NULL && card.freq == -1)
				card.freq = ((*(int *)value) + 500000)
				    / 1000000;


			/* Figure out how we want to display the name */
			create_io_card_name(card_node, name,
			    (char *)&card.name);

			if (card.freq != -1)
				card_list = insert_io_card(card_list, &card);

next_card:
			/*
			 * If we are done with the children of the pci bridge,
			 * we must continue with the remaining siblings of
			 * the pci-to-pci bridge - otherwise we move onto our
			 * own sibling.
			 */
			if (pci_pci_bridge) {
				if (card_node->child != NULL)
					card_node = card_node->child;
				else
					card_node = card_node->sibling;
			} else {
				if ((card_node->parent == pci_bridge_node) &&
				    (card_node->sibling == NULL))
					card_node = pci_bridge_node->sibling;
				else
					card_node = card_node->sibling;
			}
		} /* end-while */
	} /* end-for */

	D_PRINTF("\n\n");

	display_io_cards(card_list);
	free_io_cards(card_list);
}

void
get_slot_number_str(struct io_card *card, char **slot_name_arr,
    int slot_name_bits)
{
	if (card->dev_no != -1) {
		char	*slot;
		/*
		 * slot_name_bits is a mask of the plug-in slots so if our
		 * dev_no does not appear in this mask we must be an
		 * on_board device so set the slot to 'On-Board'
		 */
		if (slot_name_bits & (1 << card->dev_no)) {
			/* we are a plug-in card */
			slot = slot_name_arr[card->dev_no];
			if (strlen(slot) != 0) {
				(void) sprintf(card->slot_str, "%s",
				    slot);
			} else
				(void) sprintf(card->slot_str, "-");
		} else {
			/* this is an on-board dev. */
			(void) sprintf(card->slot_str, "On-Board");
		}

	} else {
		(void) sprintf(card->slot_str, "%c", '-');
	}

	/* Informs display_io_cards to print slot_str instead of slot */
	card->slot = PCI_SLOT_IS_STRING;
}


/*
 * The output of a number of I/O cards are identical so we need to
 * differentiate between them.
 *
 * This function is called by the platform specific code and it decides
 * if the card needs further processing.
 *
 * It can be extended in the future if card types other than QLC have
 * the same problems.
 */
void
distinguish_identical_io_cards(char *name, Prom_node *node,
    struct io_card *card)
{
	if ((name == NULL) || (node == NULL))
		return;

	if (strcmp(name, "SUNW,qlc") == 0)
		decode_qlc_card_model_prop(node, card);
}


/*
 * The name/model properties for a number of the QLC FCAL PCI cards are
 * identical (*), so we need to distinguish them using the subsystem-id
 * and modify the model string to be more informative.
 *
 * (*) Currently the problem cards are:
 *	Amber
 *	Crystal+
 */
void
decode_qlc_card_model_prop(Prom_node *card_node, struct io_card *card)
{
	void	*value = NULL;

	if (card_node == NULL)
		return;

	value = get_prop_val(find_prop(card_node, "subsystem-id"));
	if (value != NULL) {
		int	id = *(int *)value;

		switch (id) {
		case AMBER_SUBSYSTEM_ID:
			(void) snprintf(card->model, MAX_QLC_MODEL_LEN, "%s",
			    AMBER_CARD_NAME);
			break;

		case CRYSTAL_SUBSYSTEM_ID:
			(void) snprintf(card->model, MAX_QLC_MODEL_LEN, "%s",
			    CRYSTAL_CARD_NAME);
			break;

		default:
			/*
			 * If information has been saved into the model field
			 * before this function was called we will keep it as
			 * it probably will be more meaningful that the
			 * subsystem-id, otherwise we save the subsystem-id in
			 * the hope that it will distinguish the cards.
			 */
			if (strcmp(card->model, "") == 0) {
				(void) snprintf(card->model, MAX_QLC_MODEL_LEN,
				    "0x%x", id);
			}
			break;
		}
	}
}
