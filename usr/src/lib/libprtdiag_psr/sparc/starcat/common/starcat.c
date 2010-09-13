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
 *
 * Starcat Platform specific functions.
 *
 * 	called when :
 *	machine_type == MTYPE_STARCAT
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <kvm.h>
#include <varargs.h>
#include <time.h>
#include <dirent.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/openpromio.h>
#include <libintl.h>
#include <syslog.h>
#include <sys/dkio.h>
#include <pdevinfo.h>
#include <display.h>
#include <pdevinfo_sun4u.h>
#include <display_sun4u.h>
#include <libprtdiag.h>

#define	HZ_TO_MHZ(x)		(((x) + 500000) / 1000000)
#define	PORTID_TO_EXPANDER(p)	(((p) >> 5) & 0x1f)
#define	PORTID_TO_SLOT(p)	(((p) >> 3) & 0x1)
#define	PORTID_TO_INSTANCE(p)	((p) & 0x3)
#define	SCHIZO_COMPATIBLE	"pci108e,8001"
#define	XMITS_COMPATIBLE	"pci108e,8002"
#define	SC_BOARD_TYPE(id)	(PORTID_TO_SLOT(id) ? "IO" : "SB")

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SYS_TEST"
#endif	/* TEXT_DOMAIN */

#define	DEFAULT_MAX_FREQ	66	/* 66 MHz */
#define	PCIX_MAX_FREQ		90	/* 90 MHz */

/*
 * these functions will overlay the symbol table of libprtdiag
 * at runtime (Starcat systems only)
 */

int	do_prominfo(int syserrlog, char *pgname, int log_flag, int prt_flag);
void	*get_prop_val(Prop *prop);
Prop	*find_prop(Prom_node *pnode, char *name);
char	*get_node_name(Prom_node *pnode);
char	*get_node_type(Prom_node *pnode);
void	add_node(Sys_tree *, Prom_node *);
void	display_pci(Board_node *);
void	display_ffb(Board_node *, int);
void	display_io_cards(struct io_card *list);
void	display_cpu_devices(Sys_tree *tree);
void	display_cpus(Board_node *board);
void	display_memoryconf(Sys_tree *tree, struct grp_info *grps);
void	print_us3_memory_line(int portid, int bank_id, uint64_t bank_size,
	    char *bank_status, uint64_t dimm_size, uint32_t intlv, int seg_id);
void	display_diaginfo(int flag, Prom_node *root, Sys_tree *tree,
		struct system_kstat_data *kstats);

/* Local Functions */
static void	starcat_disp_hw_revisions(Prom_node *root);
static void display_io_max_bus_speed(struct io_card *p);
static void display_io_slot_info(struct io_card *p);

/* The bus max freq is determined based on board level in use */
int	board_bus_max_freq = DEFAULT_MAX_FREQ;	/* 66MHz default */

/*
 * display_pci
 * Display all the PCI IO cards on this board.
 */
void
display_pci(Board_node *board)
{
	struct io_card *card_list = NULL;
	struct io_card card;
	void *value;
	Prom_node *pci;
	Prom_node *card_node;
	Prom_node *pci_bridge_node = NULL;
	char	*slot_name_arr[MAX_SLOTS_PER_IO_BD] = {NULL};
	char	*slot_name = NULL;
	int	slot_name_bits;
	int	slot_name_offset = 0;
	char	*child_name;
	char	*name, *type;
	char	buf[MAXSTRLEN];
	int	*int_val;
	int	pci_bus;
	int	pci_bridge = 0;
	int	pci_bridge_dev_no;
	int	child_dev_no;
	int	i;
	int	portid;
	int	version, *pversion;

	if (board == NULL)
		return;

	/* Initialize all the common information */
	card.display = TRUE;
	card.board = board->board_num;
	card.node_id = board->node_id;

	/*
	 * Search for each schizo, then find/display all nodes under
	 * each schizo node found.  Since the model property "SUNW,schizo"
	 * is not supported on Starcat, we must match on the compatible
	 * property "pci108e,8001".
	 */
	for (pci = dev_find_node_by_compatible(board->nodes, SCHIZO_COMPATIBLE);
	    pci != NULL;
	    pci = dev_next_node_by_compatible(pci, SCHIZO_COMPATIBLE)) {

		/* set max freq for this board */
		board_bus_max_freq = DEFAULT_MAX_FREQ;
		/*
		 * Find out if this is a PCI or cPCI IO Board.
		 * If "enum-impl" property exists in pci node => cPCI.
		 */
		value = get_prop_val(find_prop(pci, "enum-impl"));
		if (value == NULL) {
			(void) sprintf(card.bus_type, "PCI");
		} else {
			(void) sprintf(card.bus_type, "cPCI");
		}

		if (strstr((char *)get_prop_val(
		    find_prop(pci, "compatible")), XMITS_COMPATIBLE)) {
			sprintf(card.notes, "%s", XMITS_COMPATIBLE);
			/*
			 * With XMITS 3.X and PCI-X mode, the bus speed
			 * can be higher than 66MHZ.
			 */
			value = (int *)get_prop_val
			    (find_prop(pci, "module-revision#"));
			if (value) {
				pversion = (int *)value;
				version = *pversion;
				if (version >= 4)
					board_bus_max_freq = PCIX_MAX_FREQ;
			}
		} else if (strstr((char *)get_prop_val(
		    find_prop(pci, "compatible")), SCHIZO_COMPATIBLE))
			sprintf(card.notes, "%s", SCHIZO_COMPATIBLE);
		else
			sprintf(card.notes, " ");

		/*
		 * Get slot-names property from parent node and
		 * store the individual slot names in an array.
		 * This is more general than Starcat requires, but
		 * it is correct, according to the slot-names property.
		 */
		value = (char *)get_prop_val(find_prop(pci, "slot-names"));
		if (value == NULL) {
			/*
			 * No slot_names property.  This could be an Xmits
			 * card, so check the child node for slot-names property
			 */
			value = (char *)get_prop_val(
			    find_prop(pci->child, "slot-names"));
		}

		if (value != NULL) {
			/* Get the 4 byte bitmask and pointer to first name */
			slot_name_bits = *(int *)value;
			if (slot_name_bits > 0)
				slot_name_offset = slot_name_bits - 1;
			slot_name = (char *)value + sizeof (int);

			for (i = 0; i < MAX_SLOTS_PER_IO_BD; i++) {
				if (! (slot_name_bits & (1 << i))) {
					slot_name_arr[i] = (char *)NULL;
					continue;
				}

				/*
				 * Save the name pointer into the array
				 * and advance it past the end of this
				 * slot name
				 */
				slot_name_arr[i] = slot_name;
				slot_name += strlen(slot_name) + 1;
			}
			slot_name = (char *)NULL;
		}

		/*
		 * Search for Children of this node ie. Cards.
		 * Note: any of these cards can be a pci-bridge
		 *	that itself has children. If we find a
		 *	pci-bridge we need to handle it specially.
		 */
		card_node = pci->child;
		while (card_node != NULL) {
			pci_bridge = 0;

			/* If it doesn't have a name, skip it */
			name = (char *)get_prop_val(
			    find_prop(card_node, "name"));
			if (name == NULL) {
				card_node = card_node->sibling;
				continue;
			}

			/*
			 * get dev# and func# for this card from the
			 * 'reg' property.
			 */
			int_val = (int *)get_prop_val(
			    find_prop(card_node, "reg"));
			if (int_val != NULL) {
				card.dev_no = (((*int_val) & 0xF800) >> 11);
				card.func_no = (((*int_val) & 0x700) >> 8);
			} else {
				card.dev_no = -1;
				card.func_no = -1;
			}

			/*
			 * If this is a pci-bridge, then store it's dev#
			 * as its children nodes need this to get their slot#.
			 * We set the pci_bridge flag so that we know we are
			 * looking at a pci-bridge node. This flag gets reset
			 * every time we enter this while loop.
			 */

			/*
			 * Check for a PCI-PCI Bridge for PCI and cPCI
			 * IO Boards using the name and type properties.
			 */
			type = (char *)get_prop_val(
			    find_prop(card_node, "device_type"));
			if ((type != NULL) &&
			    (strncmp(name, "pci", 3) == 0) &&
			    (strcmp(type, "pci") == 0)) {
				pci_bridge_dev_no = card.dev_no;
				pci_bridge_node = card_node;
				pci_bridge = TRUE;
			}

			/*
			 * Get slot-names property from slot_names_arr.
			 * If we are the child of a pci_bridge we use the
			 * dev# of the pci_bridge as an index to get
			 * the slot number. We know that we are a child of
			 * a pci-bridge if our parent is the same as the last
			 * pci_bridge node found above.
			 */
			if (card.dev_no != -1) {
				/*
				 * We compare this card's parent node with the
				 * pci_bridge_node to see if it's a child.
				 */
				if (card_node->parent == pci_bridge_node) {
					/* use dev_no of pci_bridge */
					child_dev_no = pci_bridge_dev_no - 1;
				} else {
					/* use card's own dev_no */
					child_dev_no = card.dev_no - 1;
				}

				if (child_dev_no < MAX_SLOTS_PER_IO_BD &&
				    child_dev_no >= 0 &&
				    slot_name_arr
				    [child_dev_no + slot_name_offset] != NULL) {

					slot_name = slot_name_arr[
					    child_dev_no + slot_name_offset];
				} else
					slot_name = (char *)NULL;

				if (slot_name != NULL && slot_name[0] != '\0') {
					(void) sprintf(card.slot_str, "%s",
					    slot_name);
				} else {
					(void) sprintf(card.slot_str, "-");
				}
			} else {
				(void) sprintf(card.slot_str, "%c", '-');
			}

			/*
			 * Get the portid of the schizo that this card
			 * lives under.
			 */
			portid = -1;
			value = get_prop_val(find_prop(pci, "portid"));
			if (value != NULL) {
				portid = *(int *)value;
			}
			card.schizo_portid = portid;

#ifdef	DEBUG
			(void) sprintf(card.notes, "%s portid [%d]"
			    " dev_no [%d] slot_name[%s] name_bits[%#x]",
			    card.notes, portid, card.dev_no,
			    ((slot_name != NULL) ? slot_name : "NULL"),
			    slot_name_bits);
#endif	/* DEBUG */

			/*
			 * Find out whether this is PCI bus A or B
			 * using the 'reg' property.
			 */
			int_val = (int *)get_prop_val
			    (find_prop(pci, "reg"));

			if (int_val != NULL) {
				int_val ++; /* skip over first integer */
				pci_bus = ((*int_val) & 0x7f0000);
				if (pci_bus == 0x600000)
					card.pci_bus = 'A';
				else if (pci_bus == 0x700000)
					card.pci_bus = 'B';
				else
					card.pci_bus = '-';
			} else {
				card.pci_bus = '-';
			}


			/*
			 * Check for failed status.
			 */
			if (node_failed(card_node))
				strcpy(card.status, "fail");
			else
				strcpy(card.status, "ok");

			/* Get the model of this card */
			value = get_prop_val(find_prop(card_node, "model"));
			if (value == NULL)
				card.model[0] = '\0';
			else {
				(void) sprintf(card.model, "%s", (char *)value);
				/*
				 * If we wish to exclude onboard devices
				 * (such as SBBC) then this is the place
				 * and here is how to do it:
				 *
				 * if (strcmp(card.model, "SUNW,sbbc") == 0) {
				 *	card_node = card_node->sibling;
				 *	continue;
				 * }
				 */
			}

			/*
			 * The card may have a "clock-frequency" but we
			 * are not interested in that. Instead we get the
			 * "clock-frequency" of the PCI Bus that the card
			 * resides on. PCI-A can operate at 33Mhz or 66Mhz
			 * depending on what card is plugged into the Bus.
			 * PCI-B always operates at 33Mhz.
			 *
			 */
			int_val = get_prop_val(find_prop(pci,
			    "clock-frequency"));
			if (int_val != NULL) {
				card.freq = HZ_TO_MHZ(*int_val);
			} else {
				card.freq = -1;
			}

			/*
			 * Figure out how we want to display the name
			 */
			value = get_prop_val(find_prop(card_node,
			    "compatible"));
			if (value != NULL) {
				/* use 'name'-'compatible' */
				(void) sprintf(buf, "%s-%s", name,
				    (char *)value);
			} else {
				/* just use 'name' */
				(void) sprintf(buf, "%s", name);
			}
			name = buf;

			/*
			 * If this node has children, add the device_type
			 * of the child to the name value of this card.
			 */
			child_name = (char *)get_node_name(card_node->child);
			if ((card_node->child != NULL) &&
			    (child_name != NULL)) {
				value = get_prop_val(find_prop(card_node->child,
				    "device_type"));
				if (value != NULL) {
					/* add device_type of child to name */
					(void) sprintf(card.name, "%s/%s (%s)",
					    name, child_name,
					    (char *)value);
				} else {
					/* just add child's name */
					(void) sprintf(card.name, "%s/%s",
					    name, child_name);
				}
			} else {
				/* childless, just the card's name */
				(void) sprintf(card.name, "%s", (char *)name);
			}

			/*
			 * If this is a pci-bridge, then add the word
			 * 'pci-bridge' to its model.
			 */
			if (pci_bridge) {
				if (card.model[0] == '\0')
					(void) sprintf(card.model,
					    "%s", "pci-bridge");
				else
					(void) strcat(card.model,
					    "/pci-bridge");
			}

			/* insert this card in the list to be displayed later */
			card_list = insert_io_card(card_list, &card);

			/*
			 * If we are dealing with a pci-bridge, we need to move
			 * down to the children of this bridge, if there are
			 * any, otherwise its siblings.
			 *
			 * If not a bridge, we are either dealing with a regular
			 * card (in which case we move onto the sibling of this
			 * card) or we are dealing with a child of a pci-bridge
			 * (in which case we move onto the child's siblings or
			 * if there are no more siblings for this child, we
			 * move onto the parent's siblings).  I hope you're
			 * getting all this, there will be an exam later.
			 */
			if (pci_bridge) {
				if (card_node->child != NULL)
					card_node = card_node->child;
				else
					card_node = card_node->sibling;
			} else {
				/*
				 * If our parent is a pci-bridge but there
				 * are no more of its children to process we
				 * move back up to our parent's sibling,
				 * otherwise we move onto our own sibling.
				 */
				if ((card_node->parent == pci_bridge_node) &&
				    (card_node->sibling == NULL))
					card_node =
					    pci_bridge_node->sibling;
				else
					card_node = card_node->sibling;
			}

		} /* end while (card_node ...) loop */

	} /* end for (pci ...) loop */

	display_io_cards(card_list);
	free_io_cards(card_list);
}

/*
 * display_ffb
 *
 * There are no FFB's on a Starcat, however in the generic library,
 * the display_ffb() function is implemented so we have to define an
 * empty function here.
 */
/*ARGSUSED0*/
void
display_ffb(Board_node *board, int table)
{
}

/*
 * add_node
 *
 * This function adds a board node to the board structure where that
 * that node's physical component lives.
 */
void
add_node(Sys_tree *root, Prom_node *pnode)
{
	int	portid = -1;
	int	nodeid = -1;
	void	*value;
	Board_node	*bnode;
	Prom_node	*p;
	char	*type;

	/* Get the board number of this board from the portid prop */
	if ((value = get_prop_val(find_prop(pnode, "portid"))) == NULL) {
		if (type = get_node_type(pnode))
			if (strcmp(type, "cpu") == 0)
				value = get_prop_val(find_prop(pnode->parent,
				    "portid"));
	}
	if (value != NULL) {
		portid = *(int *)value;
		nodeid = PORTID_TO_EXPANDER(portid);
	}

	/* find the board node with the same board number */
	if ((bnode = find_board(root, portid)) == NULL) {
		bnode = insert_board(root, portid);
		bnode->board_type = UNKNOWN_BOARD;
		bnode->node_id = nodeid;
	}

	/* now attach this prom node to the board list */
	/* Insert this node at the end of the list */
	pnode->sibling = NULL;
	if (bnode->nodes == NULL)
		bnode->nodes = pnode;
	else {
		p = bnode->nodes;
		while (p->sibling != NULL)
			p = p->sibling;
		p->sibling = pnode;
	}
}



/*
 * Print out all the io cards in the list.  Also print the column
 * headers if told to do so.
 */
void
display_io_cards(struct io_card *list)
{
	char	*hdrfmt = "%-10.10s  %-4.4s %-4.4s %-4.4s %-4.4s %-4.4s"
	    " %-4.4s %-5.5s %-32.32s  %-22.22s"
#ifdef	DEBUG
	    "  %-22.22s"
#endif	/* DEBUG */
	    "\n";

	static int banner = FALSE; /* Have we printed the column headings? */
	struct io_card *p;

	if (list == NULL)
		return;

	(void) textdomain(TEXT_DOMAIN);

	if (banner == FALSE) {
		log_printf(hdrfmt,
		    "", "", "", "",
		    gettext("Bus"),
		    gettext("Max"),
		    "", "", "", "",
#ifdef	DEBUG
		    "",
#endif	/* DEBUG */
		    0);

		log_printf(hdrfmt,
		    "",
		    gettext("IO"),
		    gettext("Port"),
		    gettext("Bus"),
		    gettext("Freq"),
		    gettext("Bus"),
		    gettext("Dev,"),
		    "", "", "",
#ifdef	DEBUG
		    "",
#endif	/* DEBUG */
		    0);

		log_printf(hdrfmt,
		    gettext("Slot ID"),
		    gettext("Type"),
		    gettext(" ID"),
		    gettext("Side"),
		    gettext("MHz"),
		    gettext("Freq"),
		    gettext("Func"),
		    gettext("State"),
		    gettext("Name"),
		    gettext("Model"),
#ifdef	DEBUG
		    gettext("Notes"),
#endif	/* DEBUG */
		    0);

		log_printf(hdrfmt,
		    "----------", "----", "----", "----", "----", "----",
		    "----", "-----", "--------------------------------",
		    "----------------------",
#ifdef	DEBUG
		    "----------------------",
#endif	/* DEBUG */
		    0);

		banner = TRUE;
	}

	for (p = list; p != NULL; p = p -> next) {

		display_io_slot_info(p);

		display_io_max_bus_speed(p);

		log_printf("\n", 0);
	}
}


static void
display_io_slot_info(struct io_card *p)
{
	/*
	 * Onboard devices are distinguished by Slot IDs that
	 * indicate only the I/O board.  Plug-in cards indicate
	 * their leaf and Schizo.
	 */

	if (p->slot_str[0] == '-') {
		log_printf("/%-2s%02d       ",
		    SC_BOARD_TYPE(p->board),
		    PORTID_TO_EXPANDER(p->board), 0);
	} else {
		char	c;
		if (strcmp(p->notes, XMITS_COMPATIBLE) == 0) {
			log_printf("/%-2s%02d/%s  ",
			    SC_BOARD_TYPE(p->board),
			    PORTID_TO_EXPANDER(p->board),
			    p->slot_str, 0);
		} else {
			if (p->pci_bus == 'A')
				c = '3';
			else if (p->pci_bus == 'B') {
				c = '5';
			} else
				c = '-';
			log_printf("/%-2s%02d/C%cV%1d  ",
			    SC_BOARD_TYPE(p->board),
			    PORTID_TO_EXPANDER(p->board), c,
			    PORTID_TO_INSTANCE(p->schizo_portid),
			    0);
		}
	}
	log_printf("%-4.4s ", gettext(p->bus_type), 0);
	log_printf("%3d  ", p->schizo_portid, 0);
	log_printf(" %c  ", p->pci_bus, 0);
	log_printf(" %3d  ", p->freq, 0);
}

#define	BUS_SPEED_PRINT(speed)	log_printf(" %d  ", speed, 0)

static void
display_io_max_bus_speed(struct io_card *p)
{
	int speed = board_bus_max_freq;

	switch (p->pci_bus) {
	case 'A':
		BUS_SPEED_PRINT(speed);
		break;
	case 'B':
		if (strcmp(p->notes, XMITS_COMPATIBLE) == 0) {
			if (PORTID_TO_INSTANCE(p->schizo_portid) == 0)
				BUS_SPEED_PRINT(33);
			else
				BUS_SPEED_PRINT(speed);
		} else
			BUS_SPEED_PRINT(33);
		break;
	default:
		log_printf("  -  ", 0);
		break;
	}

	log_printf("%-1d,%-1d  ", p->dev_no, p->func_no, 0);
	log_printf("%-5.5s ", gettext(p->status), 0);
	log_printf("%-32.32s%c ", p->name,
	    ((strlen(p->name) > 32) ? '+' : ' '), 0);
	log_printf("%-22.22s%c", p->model,
	    ((strlen(p->model) > 22) ? '+' : ' '), 0);
#ifdef	DEBUG
	log_printf(" %s", p->notes, 0);
#endif	/* DEBUG */
}

void
display_cpu_devices(Sys_tree *tree)
{
	Board_node *bnode;
	char	*hdrfmt = "%-8.8s  %-7.7s  %-4.4s  %-4.4s  %-7.7s  %-4.4s\n";

	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Display the table header for CPUs . Then display the CPU
	 * frequency, cache size, and processor revision of all cpus.
	 */
	log_printf("\n", 0);
	log_printf("=========================", 0);
	log_printf(gettext(" CPUs "), 0);
	log_printf("=========================", 0);
	log_printf("\n\n", 0);

	log_printf(hdrfmt,
	    "",
	    gettext("CPU "),
	    gettext("Run"),
	    gettext(" E$"),
	    gettext(" CPU"),
	    gettext("CPU"), 0);

	log_printf(hdrfmt,
	    gettext("Slot ID"),
	    gettext("ID "),
	    gettext("MHz"),
	    gettext(" MB"),
	    gettext("Impl."),
	    gettext("Mask"), 0);

	log_printf(hdrfmt,
	    "--------", "-------", "----", "----", "-------",  "----", 0);

	/* Now display all of the cpus on each board */
	bnode = tree->bd_list;
	while (bnode != NULL) {
		display_cpus(bnode);
		bnode = bnode->next;
	}

	log_printf("\n", 0);
}

/*
 * Display the CPUs present on this board.
 */
void
display_cpus(Board_node *board)
{
	Prom_node *cpu;
	uint_t freq;		/* CPU clock frequency */
	int ecache_size;	/* External cache size */
	int *impl;
	int *mask;
	int decoded_mask;
	int *cpuid;
	int *coreid;
	int cpuid_prev = -1;
	int ecache_size_prev = 0;

	(void) textdomain(TEXT_DOMAIN);
	/*
	 * display the CPUs' operating frequency, cache size, impl. field
	 * and mask revision.
	 */
	for (cpu = dev_find_type(board->nodes, "cpu"); cpu != NULL;
	    cpu = dev_next_type(cpu, "cpu")) {

		freq = HZ_TO_MHZ(get_cpu_freq(cpu));
		ecache_size = get_ecache_size(cpu);
		impl = (int *)get_prop_val(find_prop(cpu, "implementation#"));
		mask = (int *)get_prop_val(find_prop(cpu, "mask#"));
		cpuid = (int *)get_prop_val(find_prop(cpu, "cpuid"));
		if (cpuid == NULL)
			cpuid = &board->board_num;

		/* Do not display a failed CPU node */
		if ((freq == 0) || (impl == 0) || (node_failed(cpu)))
			continue;

		if (CPU_IMPL_IS_CMP(*impl)) {
			coreid = (int *)get_prop_val(find_prop(cpu,
			    "reg"));
			if (coreid == NULL) {
				continue;
			}

			/*
			 * The assumption is made that 2 cores will always be
			 * listed together in the device tree. If either core
			 * is "bad" then the FRU will not be listed.
			 */
			if (cpuid_prev == -1) {
				cpuid_prev = *cpuid;
				ecache_size_prev = ecache_size;
				continue;
			} else {
				/*
				 * Jaguar has a split E$, so the size for both
				 * cores must be added together to get the total
				 * size for the entire chip.
				 *
				 * Panther E$ (L3) is logically shared, so the
				 * total size is equal to the core size.
				 */
				if (IS_JAGUAR(*impl)) {
					ecache_size += ecache_size_prev;
				}

				ecache_size_prev = 0;
			}
		}

		/*
		 * Print out cpu data.
		 *
		 * Slot ID
		 */
		log_printf("/%-2s%02d/P%1d  ",
		    SC_BOARD_TYPE(*cpuid),
		    PORTID_TO_EXPANDER(*cpuid),
		    PORTID_TO_INSTANCE(*cpuid), 0);

		/* CPU ID */
		if (CPU_IMPL_IS_CMP(*impl)) {
			log_printf("%3d,%3d  ", cpuid_prev,
			    *cpuid, 0);
			cpuid_prev = -1;
		} else
			log_printf("%3d      ", *cpuid, 0);

		/* Running frequency */
		log_printf("%4u  ", freq, 0);

		/* Ecache size */
		if (ecache_size == 0)
			log_printf("%-4.4s  ", gettext("N/A"), 0);
		else
			log_printf("%4.1f  ",
			    (float)ecache_size / (float)(1<<20),
			    0);

		/* Implementation */
		switch (*impl) {
		case CHEETAH_IMPL:
			log_printf("%-7.7s  ",
			    gettext("US-III"), 0);
			break;
		case CHEETAH_PLUS_IMPL:
			log_printf("%-7.7s  ",
			    gettext("US-III+"), 0);
			break;
		case JAGUAR_IMPL:
			log_printf("%-7.7s  ",
			    gettext("US-IV"), 0);
			break;
		case PANTHER_IMPL:
			log_printf("%-7.7s  ",
			    gettext("US-IV+"), 0);
			break;
		default:
			log_printf("%-7x  ", *impl, 0);
			break;
		}

		/* CPU Mask */
		if (mask == NULL) {
			log_printf("%-4.4s", gettext("N/A"), 0);
		} else {
			if (IS_CHEETAH(*impl))
				decoded_mask = REMAP_CHEETAH_MASK(*mask);
			else
				decoded_mask = *mask;

			log_printf("%d.%d",
			    (decoded_mask >> 4) & 0xf,
			    decoded_mask & 0xf, 0);
		}

		log_printf("\n", 0);
	}
}


/*ARGSUSED1*/
void
display_memoryconf(Sys_tree *tree, struct grp_info *grps)
{
	Board_node	*bnode = tree->bd_list;
	char	*hdrfmt = "\n%-11.11s  %-4.4s  %-7.7s  %-7.7s  %-8.8s  %-6.6s"
	    "  %-10.10s  %-10.10s";

	(void) textdomain(TEXT_DOMAIN);

	log_printf("=========================", 0);
	log_printf(gettext(" Memory Configuration "), 0);
	log_printf("=========================", 0);
	log_printf("\n", 0);

	log_printf(hdrfmt,
	    "", "",
	    gettext("Logical"),
	    gettext("Logical"),
	    gettext("Logical"),
	    "", "", "", 0);

	log_printf(hdrfmt,
	    "",
	    gettext("Port"),
	    gettext("Bank"),
	    gettext("Bank"),
	    gettext("Bank"),
	    gettext(" DIMM"),
	    gettext("Interleave"),
	    gettext("Interleave"), 0);

	log_printf(hdrfmt,
	    gettext("Slot ID"),
	    gettext(" ID"),
	    gettext("Number"),
	    gettext("Size"),
	    gettext("Status"),
	    gettext(" Size"),
	    gettext("Factor"),
	    gettext("Segment"), 0);

	log_printf(hdrfmt,
	    "-----------", "----", "-------", "-------", "--------",
	    "------", "----------", "----------", 0);

	while (bnode != NULL) {
		if (get_us3_mem_regs(bnode)) {
			log_printf(
			    gettext(
			    "\nFailed to get memory information.\n"),
			    0);
			return;
		}
		bnode = bnode->next;
	}

	/* Display what we have found */
	display_us3_banks();
}


/*
 * This function provides Starcat's formatting of the memory config
 * information that get_us3_mem_regs() and display_us3_banks() code has
 * gathered. It overrides the generic print_us3_memory_line() code
 * which prints an error message.
 */
void
print_us3_memory_line(int portid, int bank_id, uint64_t bank_size,
	char *bank_status, uint64_t dimm_size, uint32_t intlv, int seg_id)
{
	(void) textdomain(TEXT_DOMAIN);

	/* Slot ID */
	log_printf("\n/%-2s%02d/P%1d/B%1d  ",
	    SC_BOARD_TYPE(portid), PORTID_TO_EXPANDER(portid),
	    PORTID_TO_INSTANCE(portid), (bank_id & 0x1), 0);

	/* Port ID */
	log_printf("%3d   ", portid, 0);

	/* Logical Bank Number */
	log_printf("   %1d     ", (bank_id & 0x3), 0);

	/* Logical Bank Size */
	log_printf("%4lldMB   ", bank_size, 0);

	/* Logical Bank Status */
	log_printf("%-8.8s  ", gettext(bank_status), 0);

	/* DIMM Size */
	log_printf("%4lldMB  ", dimm_size, 0);

	/* Interleave Factor */
	log_printf("  %2d-%-3.3s    ", intlv, gettext("way"), 0);

	/* Interleave Segment */
	log_printf("   %3d", seg_id, 0);
}

/*ARGSUSED2*/
void
display_diaginfo(int flag, Prom_node *root, Sys_tree *tree,
	struct system_kstat_data *kstats)
{
	if (flag) {
		/*
		 * display time of latest powerfail. Not all systems
		 * have this capability. For those that do not, this
		 * is just a no-op.
		 */
		disp_powerfail(root);

		(void) textdomain(TEXT_DOMAIN);

		/* Print the header */
		log_printf("\n", 0);
		log_printf("=========================", 0);
		log_printf(gettext(" Diagnostic Information "), 0);
		log_printf("=========================", 0);
		log_printf("\n\n", 0);
		log_printf(gettext("For diagnostic information,"), 0);
		log_printf("\n", 0);
		log_printf(gettext(
		    "see /var/opt/SUNWSMS/adm/[A-R]/messages on the SC."),
		    0);
		log_printf("\n", 0);

		/* Print the PROM revisions here */
		starcat_disp_hw_revisions(root);
	}
}

/*
 * local functions -  functions that are only needed inside this library
 */

static void
starcat_disp_hw_revisions(Prom_node *root)
{
	Prom_node	*pnode;
	char		*version;

	(void) textdomain(TEXT_DOMAIN);

	/* Print the header */
	log_printf("\n", 0);
	log_printf("=========================", 0);
	log_printf(gettext(" Hardware Revisions "), 0);
	log_printf("=========================", 0);
	log_printf("\n\n", 0);

	/* Display Prom revision header */
	log_printf(gettext("OpenBoot firmware revision:"), 0);
	log_printf("\n---------------------------\n", 0);

	/*
	 * Display OBP version info
	 */
	pnode = dev_find_node(root, "openprom");
	if (pnode != NULL) {
		version = (char *)get_prop_val(find_prop(pnode, "version"));
		log_printf("%s\n\n", version, 0);
	}
}

/*
 * We call do_devinfo() in order to use the libdevinfo device tree
 * instead of OBP's device tree.
 */
int
do_prominfo(int syserrlog, char *pgname, int log_flag, int prt_flag)
{

	return (do_devinfo(syserrlog, pgname, log_flag, prt_flag));

}

/*
 * return the property value for the Prop
 * passed in. (When using libdevinfo)
 */
void *
get_prop_val(Prop *prop)
{
	if (prop == NULL)
		return (NULL);

	return ((void *)(prop->value.val_ptr));
}

/*
 * Search a Prom node and retrieve the property with the correct
 * name. (When using libdevinfo)
 */
Prop *
find_prop(Prom_node *pnode, char *name)
{
	Prop *prop;

	if (pnode == NULL)
		return (NULL);

	for (prop = pnode->props; prop != NULL; prop = prop->next) {
		if (prop->name.val_ptr != NULL &&
		    strcmp((char *)(prop->name.val_ptr), name) == 0)
			break;
	}

	return (prop);
}

/*
 * This function searches through the properties of the node passed in
 * and returns a pointer to the value of the name property.
 * (When using libdevinfo)
 */
char *
get_node_name(Prom_node *pnode)
{
	Prop *prop;

	if (pnode == NULL) {
		return (NULL);
	}

	prop = pnode->props;
	while (prop != NULL) {
		if (strcmp("name", (char *)prop->name.val_ptr) == 0)
			return (prop->value.val_ptr);
		prop = prop->next;
	}
	return (NULL);
}

/*
 * This function searches through the properties of the node passed in
 * and returns a pointer to the value of the device_type property.
 * (When using libdevinfo)
 */
char *
get_node_type(Prom_node *pnode)
{
	Prop *prop;

	if (pnode == NULL) {
		return (NULL);
	}

	prop = pnode->props;
	while (prop != NULL) {
		if (strcmp("device_type", (char *)prop->name.val_ptr) == 0)
			return (prop->value.val_ptr);
		prop = prop->next;
	}
	return (NULL);
}
