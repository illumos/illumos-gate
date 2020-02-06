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
 * Serengeti Platform specific functions.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <kstat.h>
#include <string.h>
#include <assert.h>
#include <alloca.h>
#include <libintl.h>
#include <fcntl.h>
#include <varargs.h>

#include <sys/openpromio.h>
#include <sys/sysmacros.h>

#include <sys/serengeti.h>
#include <sys/sgfrutypes.h>

#include <pdevinfo.h>
#include <display.h>
#include <pdevinfo_sun4u.h>
#include <display_sun4u.h>
#include <libprtdiag.h>

#include <config_admin.h>

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

#define	SCHIZO_COMPATIBLE	"pci108e,8001"
#define	XMITS_COMPATIBLE	"pci108e,8002"

#define	ACTIVE		0
#define	INACTIVE	1
#define	DISPLAY_INFO	40

#define	EVNT2STR(e)	((e) == CFGA_STAT_NONE ? "none" : \
			    (e) == CFGA_STAT_EMPTY ? "empty" : \
			    (e) == CFGA_STAT_DISCONNECTED ? "disconnected" : \
			    (e) == CFGA_STAT_CONNECTED ? "connected" : \
			    (e) == CFGA_STAT_UNCONFIGURED ? "unconfigured" : \
			    (e) == CFGA_STAT_CONFIGURED ? "configured" : \
			    "unknown")

#define	COND2STR(c)	((c) == CFGA_COND_UNKNOWN ? "unknown" : \
			    (c) == CFGA_COND_OK ? "ok" : \
			    (c) == CFGA_COND_FAILING ? "failing" : \
			    (c) == CFGA_COND_FAILED ? "failed" : \
			    (c) == CFGA_COND_UNUSABLE ? "unusable" : \
			    "???")

#define	SG_CLK_FREQ_TO_MHZ(x)	(((x) + 500000) / 1000000)

#define	MAX_STATUS_LEN		8
#define	SG_FAIL			"fail"
#define	SG_DISABLED		"disabled"
#define	SG_DEGRADED		"degraded"
#define	SG_OK			"ok"

#define	SG_SCHIZO_FAILED	1
#define	SG_SCHIZO_GOOD		0

#define	DEFAULT_MAX_FREQ	66	/* 66 MHz */
#define	PCIX_MAX_FREQ		100	/* 100 MHz */

#define	CFG_CPU	"::cpu"

#define	CFG_SET_FRU_NAME_NODE(str, num) \
{ \
	char tmp_str[MAX_FRU_NAME_LEN]; \
	sprintf(tmp_str, "/N%d", num); \
	strncat(str, tmp_str, sizeof (tmp_str)); \
}

#define	CFG_SET_FRU_NAME_CPU_BOARD(str, num) \
{ \
	char tmp_str[MAX_FRU_NAME_LEN]; \
	sprintf(tmp_str, ".%s%d", SG_HPU_TYPE_CPU_BOARD_ID, num); \
	strncat(str, tmp_str, sizeof (tmp_str)); \
}

#define	CFG_SET_FRU_NAME_MODULE(str, num) \
{ \
	char tmp_str[MAX_FRU_NAME_LEN]; \
	sprintf(tmp_str, "%s%d", CFG_CPU, num); \
	strncat(str, tmp_str, sizeof (tmp_str)); \
}

extern	int	print_flag;

/*
 * these functions will overlay the symbol table of libprtdiag
 * at runtime (Serengeti systems only)
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
void	display_diaginfo(int flag, Prom_node *root, Sys_tree *tree,
		struct system_kstat_data *kstats);
void	display_hp_fail_fault(Sys_tree *tree, struct system_kstat_data *kstats);
void	get_failed_parts(void);
int	display_failed_parts(Sys_tree *tree);
void	display_memoryconf(Sys_tree *tree);
void	print_us3_memory_line(int portid, int bank_id, uint64_t bank_size,
	    char *bank_status, uint64_t dimm_size, uint32_t intlv, int seg_id);

/* Local Functions */
static void	serengeti_display_hw_revisions(Prom_node *root,
							Board_node *bnode);
static Board_node *serengeti_find_board(Sys_tree *root, int board, int nodeid);
static Board_node *serengeti_insert_board(Sys_tree *root, int board, int nid);
static int	display_schizo_revisions(Board_node *bdlist, int mode);
static void	display_sgsbbc_revisions(Board_node *bdlist);
static void	serengeti_display_board_info(int state);
static void	serengeti_display_board_info_header(int state);
static boolean_t cpu_node_configured(char *const node);
static void display_io_max_bus_speed(struct io_card *p);
static void display_io_slot_info(struct io_card *p);
static void get_slot_name(struct io_card *card, char *slot_name);

/* The bus max freq is determined based on board level in use */
int	board_bus_max_freq = DEFAULT_MAX_FREQ;	/* 66MHz default */

/*
 * Serengeti now uses both the devinfo tree and the OBP tree for it's
 * prtdiag. The devinfo tree is used for getting the HW config of the
 * system and the OBP device tree is used for listing the failed HW
 * in the system. This is because devinfo currently does not include
 * any PROM nodes with a status of 'fail' so we need to go to OBP to
 * get a list of failed HW. We use the tree flag to allow the same code
 * to walk both trees.
 *
 * We really need to look at having a single tree for all platforms!
 */
#define	DEVINFO_TREE	1
#define	OBP_TREE	2

static int	tree = DEVINFO_TREE;

#ifdef DEBUG
#define	D_PRINTFINDENT	printfindent
void
printfindent(int indent, char *fmt, ...)
{
	va_list ap;
	int i = 0;
	for (i = 0; i < indent; i ++)
		printf("\t");

	va_start(ap);
	(void) vprintf(fmt, ap);
	va_end(ap);
}
#else
#define	D_PRINTFINDENT
#endif

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
	Prom_node *pci_bridge_node;
	Prom_node *child_pci_bridge_node;
	char	*slot_name = NULL;	/* info in "slot-names" prop */
	char	*child_name;
	char	*name, *type;
	char	*pname, *ptype;
	char	buf[MAXSTRLEN];
	int	*int_val;
	int	pci_bus;
	int	pci_bridge = 0;
	int	pci_bridge_dev_no;
	char	*slot_name_arr[SG_MAX_SLOTS_PER_IO_BD] = {NULL};
	int	i;
	int	portid;
	int	level = 0;
	int	version, *pversion;
#ifdef DEBUG
	int	slot_name_bits;
#endif

	if (board == NULL)
		return;

	/* Initialize all the common information */
	card.display = TRUE;
	card.board = board->board_num;
	card.node_id = board->node_id;

	/*
	 * Search for each schizo and xmits, then find/display all nodes under
	 * each schizo and xmits node found.
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
		 * Get slot-name properties from parent node and
		 * store them in an array.
		 */
		value = (char *)get_prop_val(find_prop(pci, "slot-names"));
		if (value != NULL) {
#ifdef DEBUG
			/* save the 4 byte bitmask */
			slot_name_bits = *(int *)value;
#endif
			/* array starts after first int */
			slot_name_arr[0] = (char *)value + sizeof (int);

			D_PRINTFINDENT(0, "slot_name_arr[0] is [%s]\n",
			    slot_name_arr[0]);

			for (i = 1; i < SG_MAX_SLOTS_PER_IO_BD; i++) {
				slot_name_arr[i] = (char *)slot_name_arr[i - 1]
				    + strlen(slot_name_arr[i - 1]) +1;

			D_PRINTFINDENT(0, "slot_name_arr[%d] is [%s]\n", i,
			    slot_name_arr[i]);

			}
		}

		/*
		 * Search for Children of this node ie. Cards.
		 * Note: any of these cards can be a pci-bridge
		 *	that itself has children. If we find a
		 *	pci-bridge we need to handle it specially.
		 *
		 *	There can now be the condition of a pci-bridge
		 *	being the child of a pci-bridge which create a
		 *	two levels of pci-bridges.  This special condition
		 *	needs to be handled as well.  The variable level
		 *	is used to track the depth of the tree.  This
		 *	variable is then used to find instances of this case.
		 */
		level = 0;
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
			D_PRINTFINDENT(level, "NAME is %s\n", name);

			type = (char *)get_prop_val(
			    find_prop(card_node, "device_type"));

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
			 * as it's children nodes need this to get their slot#.
			 * We set the pci_bridge flag so that we know we are
			 * looking at a pci-bridge node. This flag gets reset
			 * every time we enter this while loop.
			 */

			/*
			 * Check for a PCI-PCI Bridge for PCI and cPCI
			 * IO Boards using the name and type properties.
			 *
			 * If level is greater then 0, then check the parent
			 * node to see if it was also a pci-bridge.  We do not
			 * this when level is 0 as this will see the schizo or
			 * xmits device as a pci-bridge node.  This will mess
			 * up the slot number of child nodes.
			 */
			if ((type != NULL) &&
			    (strncmp(name, "pci", 3) == 0) &&
			    (strcmp(type, "pci") == 0)) {
				if (level > 0) {
					pname = (char *)get_prop_val(
					    find_prop(card_node->parent,
					    "name"));
					ptype = (char *)get_prop_val(
					    find_prop(card_node->parent,
					    "device_type"));

					if ((ptype != NULL) &&
					    (pname != NULL) &&
					    (strncmp(pname, "pci", 3) == 0) &&
					    (strcmp(ptype, "pci") == 0)) {
						child_pci_bridge_node =
						    card_node;
					} else {
						pci_bridge_dev_no = card.dev_no;
						pci_bridge_node = card_node;
					}
				} else {
					pci_bridge_dev_no = card.dev_no;
					pci_bridge_node = card_node;
				}
				pci_bridge = TRUE;

				D_PRINTFINDENT(level,
				    "pci_bridge_dev_no is [%d]\n",
				    pci_bridge_dev_no);
			}

			/*
			 * Get slot-names property from slot_names_arr.
			 * If we are the child of a pci_bridge we use the
			 * dev# of the pci_bridge as an index to get
			 * the slot number. We know that we are a child of
			 * a pci-bridge if our parent is the same as the last
			 * pci_bridge node found above.
			 */
			if (type)
				D_PRINTFINDENT(level,
				    "*** name is [%s] - type is [%s]\n",
				    name, type);
			else
				D_PRINTFINDENT(level,
				    "*** name is [%s]\n", name);

			if (card.dev_no != -1) {
				/*
				 * We compare this cards parent node with the
				 * pci_bridge_node to see if it's a child.
				 */
				if (((level > 0) &&
				    (card_node->parent->parent ==
				    pci_bridge_node)) ||
				    (card_node->parent == pci_bridge_node)) {
					/* use dev_no of pci_bridge */
					D_PRINTFINDENT(level,
					    "   pci_bridge_dev_no is [%d]\n",
					    pci_bridge_dev_no);

					slot_name =
					    slot_name_arr[pci_bridge_dev_no -1];
				} else {
					/* use cards own dev_no */
					D_PRINTFINDENT(level,
					    "    card.dev_no is [%d]\n",
					    card.dev_no);

					slot_name =
					    slot_name_arr[card.dev_no - 1];
				}

				get_slot_name(&card, slot_name);

			} else {
				(void) sprintf(card.slot_str, "%c", '-');
			}

			/*
			 * Get the portid of the schizo and xmits that this card
			 * lives under.
			 */
			portid = -1;
			value = get_prop_val(find_prop(pci, "portid"));
			if (value != NULL) {
				portid = *(int *)value;
			}
			card.schizo_portid = portid;

#ifdef DEBUG
			(void) sprintf(card.notes, "%s portid [%d] dev_no[%d]"
			    " slot_name[%s] name_bits[%d]",
			    card.notes,
			    portid,
			    card.dev_no, slot_name,
			    slot_name_bits);
#endif

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
			if (node_status(card_node, SG_FAIL))
				strncpy(card.status, SG_FAIL,
				    sizeof (SG_FAIL));
			else if (node_status(card_node, SG_DISABLED))
				strncpy(card.status, SG_DISABLED,
				    sizeof (SG_DISABLED));
			else
				strncpy(card.status, SG_OK,
				    sizeof (SG_OK));

			/* Get the model of this card */
			value = get_prop_val(find_prop(card_node, "model"));
			if (value == NULL)
				card.model[0] = '\0';
			else {
				(void) sprintf(card.model, "%s",
				    (char *)value);
				/* Skip sgsbbc nodes, they are not cards */
				if (strcmp(card.model, "SUNW,sgsbbc") == 0) {
					card_node = card_node->sibling;
					continue;
				}
			}

			/*
			 * Check if further processing is necessary to display
			 * this card uniquely.
			 */
			distinguish_identical_io_cards(name, card_node, &card);

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
				card.freq = SG_CLK_FREQ_TO_MHZ(*int_val);
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
					/* just add childs name */
					(void) sprintf(card.name, "%s/%s", name,
					    child_name);
				}
			} else {
				(void) sprintf(card.name, "%s", (char *)name);
			}

			/*
			 * If this is a pci-bridge, then add the word
			 * 'pci-bridge' to it's model.
			 */
			if (pci_bridge) {
				if (strlen(card.model) == 0)
					(void) sprintf(card.model,
					    "%s", "pci-bridge");
				else
					(void) sprintf(card.model,
					    "%s/pci-bridge", card.model);
			}

			/* insert this card in the list to be displayed later */
			card_list = insert_io_card(card_list, &card);

			/*
			 * If we are dealing with a pci-bridge, we need to move
			 * down to the children of this bridge if there are any.
			 *
			 * If we are not, we are either dealing with a regular
			 * card (in which case we move onto the sibling of this
			 * card) or we are dealing with a child of a pci-bridge
			 * (in which case we move onto the child's siblings or
			 * if there are no more siblings for this child, we
			 * move onto the parents siblings).
			 *
			 * Once we reach the last child node of a pci-bridge,
			 * we need to back up the tree to the parents sibling
			 * node.  If our parent has no more siblings, we need
			 * to check our grand parent for siblings.
			 *
			 * If we have no more siblings, we simply point to
			 * to the child's sibling which moves us onto the next
			 * bus leaf.
			 *
			 * The variable level gets adjusted on some of the
			 * conditions as this is used to track level within
			 * the tree we have reached.
			 */
			if (pci_bridge) {
				if (card_node->child != NULL) {
					level++;
					card_node = card_node->child;
				} else
					card_node = card_node->sibling;
			} else {
				if ((card_node->parent == pci_bridge_node) &&
				    (card_node->sibling == NULL)) {
					card_node = pci_bridge_node->sibling;
					if (level > 0)
						level--;
				} else if ((card_node->parent ==
				    child_pci_bridge_node) &&
				    (card_node->parent->parent ==
				    pci_bridge_node)) {
					if ((child_pci_bridge_node->sibling) &&
					    (card_node->sibling == NULL)) {
						card_node =
						    child_pci_bridge_node-> \
						    sibling;
					if (level > 0)
						level--;
					} else if ((pci_bridge_node->sibling) &&
					    (card_node->sibling == NULL)) {
						card_node =
						    pci_bridge_node->sibling;
						if (level > 1)
							level = level - 2;
						else if (level > 0)
							level--;
					} else
						card_node = card_node->sibling;
				} else
					card_node = card_node->sibling;
			}
		} /* end-while */
	} /* end-for */

	display_io_cards(card_list);
	free_io_cards(card_list);
}

/*
 * display_ffb
 *
 * There are no FFB's on a Serengeti, however in the generic library,
 * the display_ffb() function is implemented so we have to define an
 * empty function here.
 */
/*ARGSUSED0*/
void
display_ffb(Board_node *board, int table)
{}

static void
serengeti_display_board_info_header(int state)
{
	char *fmt = "%-9s  %-11s  %-12s  %-12s  %-9s %-40s\n";

	log_printf("\n", 0);
	log_printf("=========================", 0);
	if (state == ACTIVE)
		log_printf(dgettext(TEXT_DOMAIN,
		    " Active Boards for Domain "), 0);
	else
		log_printf(dgettext(TEXT_DOMAIN,
		    " Available Boards/Slots for Domain "), 0);
	log_printf("===========================", 0);
	log_printf("\n", 0);
	log_printf("\n", 0);

	log_printf(fmt, "", "Board", "Receptacle", "Occupant", "", "", 0);

	log_printf(fmt, "FRU Name", "Type", "Status", "Status",
	    "Condition", "Info", 0);

	log_printf(fmt, "---------", "-----------", "-----------",
	    "------------", "---------",
	    "----------------------------------------", 0);
}

static void
serengeti_display_board_info(int state)
{
	int i, z, ret;
	int nlist = 0;
	int available_board_count = 0;
	struct cfga_list_data *board_cfg = NULL;
	char *err_string = NULL;
	char tmp_id[CFGA_LOG_EXT_LEN + 1];
	char tmp_info[DISPLAY_INFO + 1];
	const char listops[] = "class=sbd";
	struct cfga_list_data dat;
	cfga_flags_t flags = 0;

	ret = config_list_ext(0, NULL, &board_cfg, &nlist,
	    NULL, listops,
	    &err_string, flags);

	if (ret == CFGA_OK) {
		serengeti_display_board_info_header(state);
		for (i = 0; i < nlist; i++) {
			dat = board_cfg[i];

			if ((state != ACTIVE) &&
			    (dat.ap_o_state == CFGA_STAT_CONFIGURED))
				continue;
			else if ((state == ACTIVE) &&
			    (dat.ap_o_state != CFGA_STAT_CONFIGURED))
				continue;
			if (state == INACTIVE)
				available_board_count++;

			memcpy(tmp_id, dat.ap_log_id, CFGA_LOG_EXT_LEN);
			tmp_id[CFGA_LOG_EXT_LEN] = '\0';
			for (z = 0; z < strlen(tmp_id); z++) {
				if (tmp_id[z] == '.')
					tmp_id[z] = '/';
			}
			log_printf("/%-8s  ", tmp_id, 0);
			log_printf("%-11s  ", dat.ap_type, 0);

			log_printf("%-12s  ", EVNT2STR(dat.ap_r_state), 0);
			log_printf("%-12s  ", EVNT2STR(dat.ap_o_state), 0);
			log_printf("%-8s  ", COND2STR(dat.ap_cond), 0);

			memcpy(tmp_info, dat.ap_info, DISPLAY_INFO);
			tmp_info[DISPLAY_INFO - 1] = '\0';
			if (strlen(tmp_info) >= (DISPLAY_INFO - 1))
				tmp_info[DISPLAY_INFO - 2] = '+';
			log_printf("%-*s\n", (DISPLAY_INFO - 1), tmp_info, 0);
		}
		if ((state == INACTIVE) &&
		    (available_board_count == 0)) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "There are currently no "
			    "Boards/Slots available "
			    "to this Domain\n"), 0);
		}
	}
	if (board_cfg)
		free(board_cfg);
	if (err_string)
		free(err_string);
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
	int	board	= -1;
	int	portid	= -1;
	int	nodeid	= -1;

	void		*value	= NULL;
	Board_node	*bnode	= NULL;
	Prom_node	*p	= NULL;
	char		*type;

	/* Get the board number of this board from the portid prop */
	if ((value = get_prop_val(find_prop(pnode, "portid"))) == NULL) {
		if ((type = get_node_type(pnode)) && (strcmp(type, "cpu") == 0))
			value =
			    get_prop_val(find_prop(pnode->parent, "portid"));
	}
	if (value != NULL) {
		portid = *(int *)value;
	}

	nodeid	= SG_PORTID_TO_NODEID(portid);
	board	= SG_PORTID_TO_BOARD_NUM(portid);

	/* find the board node with the same board number */
	if ((bnode = serengeti_find_board(root, board, nodeid)) == NULL) {
		bnode = serengeti_insert_board(root, board, nodeid);
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
	char	*fmt = "%-10s  %-4s %-4s %-4s %-4s %-4s %-4s %-4s %-4s %-34s";

	static int banner = FALSE; /* Have we printed the column headings? */
	struct io_card *p;

	if (list == NULL)
		return;

	if (banner == FALSE) {
		log_printf(fmt, "", "", "", "", "", "Bus", "Max",
		    "", "", "", 0);
		log_printf("\n", 0);
		log_printf(fmt, "", "IO", "Port", "Bus", "", "Freq", "Bus",
		    "Dev,", "", "", 0);
		log_printf("\n", 0);
		log_printf(fmt, "FRU Name", "Type", " ID", "Side", "Slot",
		    "MHz", "Freq", "Func", "State", "Name", 0);
#ifdef DEBUG
		log_printf("Model                   Notes\n", 0);
#else
		log_printf("Model\n", 0);
#endif

		log_printf(fmt, "----------", "----", "----", "----", "----",
		    "----", "----", "----", "-----",
		    "--------------------------------", 0);
#ifdef DEBUG
		log_printf("----------------------  ", 0);
#endif
		log_printf("----------------------\n", 0);
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
	char	fru_name[MAX_FRU_NAME_LEN] = "";

	SG_SET_FRU_NAME_NODE(fru_name, p->node_id);
	SG_SET_FRU_NAME_IO_BOARD(fru_name, p->board);
	SG_SET_FRU_NAME_MODULE(fru_name, p->schizo_portid % 2);

	log_printf("%-8s  ", fru_name, 0);
	log_printf("%-4s  ", p->bus_type, 0);
	log_printf("%-3d  ", p->schizo_portid, 0);
	log_printf("%c    ", p->pci_bus, 0);
	log_printf("%-1s    ", p->slot_str, 0);
	log_printf("%-3d ", p->freq, 0);
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
			if ((strncmp(p->slot_str, "1", 1) == 0) ||
			    (strncmp(p->slot_str, "0", 1) == 0))
				BUS_SPEED_PRINT(33);
			else
				BUS_SPEED_PRINT(speed);
		} else
			BUS_SPEED_PRINT(33);
		break;
	default:
		log_printf("  -	 ", 0);
		break;
	}

	log_printf("%-1d,%-1d  ", p->dev_no, p->func_no, 0);
	log_printf("%-5s ", p->status, 0);

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

	/* printf formats */
	char	*fmt1 = "%-10s  %-7s  %-4s  %-4s  %-7s  %-4s\n";

	/*
	 * Display the table header for CPUs . Then display the CPU
	 * frequency, cache size, and processor revision of all cpus.
	 */
	log_printf("\n", 0);
	log_printf("=========================", 0);
	log_printf(" CPUs ", 0);
	log_printf("=========================", 0);
	log_printf("======================", 0);
	log_printf("\n", 0);
	log_printf("\n", 0);

	log_printf(fmt1, "", "CPU ", "Run", " E$", "CPU", "CPU", 0);

	log_printf(fmt1, "FRU Name", "ID ", "MHz", " MB",
	    "Impl.", "Mask", 0);

	log_printf(fmt1, "----------", "-------", "----", "----",
	    "-------",  "----", 0);

	/* Now display all of the cpus on each board */
	bnode = tree->bd_list;
	while (bnode != NULL) {
		display_cpus(bnode);
		bnode = bnode->next;
	}

	log_printf("\n", 0);
}

static boolean_t
cpu_node_configured(char *const node)
{
	int ret, i;
	int nlist = 0;
	boolean_t rv;
	char *err_string = NULL;
	char *const *ap_args = NULL;
	struct cfga_list_data *statlist = NULL;
	struct cfga_list_data dat;
	cfga_flags_t flags = CFGA_FLAG_LIST_ALL;

	if (node == NULL)
		return (FALSE);

	ap_args = &node;
	ret = config_list_ext(1, &node, &statlist, &nlist,
	    NULL, NULL, &err_string, flags);

	if (ret == CFGA_OK) {
		dat = statlist[0];

		if (dat.ap_o_state == CFGA_STAT_CONFIGURED)
			rv = TRUE;
		else
			rv = FALSE;
	} else {
		rv = FALSE;
	}
	if (statlist)
		free(statlist);
	if (err_string)
		free(err_string);
	return (rv);
}

/*
 * Display the CPUs present on this board.
 */
void
display_cpus(Board_node *board)
{
	Prom_node *cpu;
	uint_t freq;	 /* CPU clock frequency */
	int ecache_size; /* External cache size */
	int board_num = board->board_num;
	int *mid;
	int *impl;
	int *mask;
	int decoded_mask;
	int *coreid;
	int mid_prev = -1;
	int ecache_size_prev = 0;
	char fru_prev[MAX_FRU_NAME_LEN] = "";

	/*
	 * display the CPUs' operating frequency, cache size, impl. field
	 * and mask revision.
	 */
	for (cpu = dev_find_type(board->nodes, "cpu"); cpu != NULL;
	    cpu = dev_next_type(cpu, "cpu")) {
		char	fru_name[MAX_FRU_NAME_LEN] = "";
		char	cfg_fru_name[MAX_FRU_NAME_LEN] = "";

		mid = (int *)get_prop_val(find_prop(cpu, "portid"));
		if (mid == NULL)
			mid = (int *)get_prop_val(find_prop(cpu, "cpuid"));
		freq = SG_CLK_FREQ_TO_MHZ(get_cpu_freq(cpu));
		ecache_size = get_ecache_size(cpu);
		impl = (int *)get_prop_val(find_prop(cpu, "implementation#"));
		mask = (int *)get_prop_val(find_prop(cpu, "mask#"));

		/* Do not display a failed CPU node */
		if ((impl == NULL) || (freq == 0) || (node_failed(cpu)))
			continue;

		/* FRU Name */
		SG_SET_FRU_NAME_NODE(fru_name, board->node_id);

		SG_SET_FRU_NAME_CPU_BOARD(fru_name, board_num);
		SG_SET_FRU_NAME_MODULE(fru_name, *mid % 4);

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
			 *
			 * As display_cpus on Serengeti does actually process
			 * all cpu's per board a copy of the fru_name needs to
			 * be made as the following core may not be its
			 * sibling. If this is the case it is assumed that a
			 * sibling core has failed, so the fru should not be
			 * displayed.
			 *
			 * For the first instance of a core, fru_prev is
			 * expected to be empty.  The current values are then
			 * stored and the next board->nodes is processed. If
			 * this is a sibling core, the ecache size it tallied
			 * and the  previous value reset and processing
			 * continues.
			 *
			 * If the following core is not a sibling, the new
			 * values are stored and the next board->nodes is
			 * processed.
			 */
			if (strncmp(fru_prev, "", sizeof (fru_prev)) == 0) {
				strncpy(fru_prev, fru_name, sizeof (fru_name));
				mid_prev = *mid;
				ecache_size_prev = ecache_size;
				continue;
			} else {
				if (strncmp(fru_name, fru_prev,
				    sizeof (fru_prev)) == 0) {
					/*
					 * Jaguar has a split E$, so the size
					 * for both cores must be added together
					 * to get the total size for the entire
					 * chip.
					 *
					 * Panther E$ (L3) is logically shared,
					 * so the total size is equal to the
					 * core size.
					 */
					if (IS_JAGUAR(*impl)) {
						ecache_size += ecache_size_prev;
					}

					ecache_size_prev = 0;
					strncpy(fru_prev, "",
					    sizeof (fru_prev));
				} else {
					mid_prev = *mid;
					ecache_size_prev = ecache_size;
					strncpy(fru_prev, fru_name,
					    sizeof (fru_name));
					continue;
				}
			}
		}

		/*
		 * If cpu is not configured, do not display it
		 */
		CFG_SET_FRU_NAME_NODE(cfg_fru_name, board->node_id);
		CFG_SET_FRU_NAME_CPU_BOARD(cfg_fru_name, board_num);
		CFG_SET_FRU_NAME_MODULE(cfg_fru_name, *mid % 4);

		if (!(cpu_node_configured(cfg_fru_name))) {
			continue;
		}


		log_printf("%-10s  ", fru_name, 0);

		/* CPU MID */
		if (CPU_IMPL_IS_CMP(*impl)) {
			log_printf("%3d,%3d ", mid_prev, *mid, 0);
			mid_prev = -1;
		} else
			log_printf("%3d     ", *mid, 0);

		/* Running frequency */
		log_printf(" %4u  ", freq, 0);

		/* Ecache size */
		if (ecache_size == 0)
			log_printf("%3s  ", "N/A", 0);
		else
			log_printf("%4.1f  ",
			    (float)ecache_size / (float)(1<<20),
			    0);

		/* Implementation */
		if (impl == NULL) {
			log_printf("%6s  ", " N/A", 0);
		} else {
			switch (*impl) {
			case CHEETAH_IMPL:
				log_printf("%-7s ", "US-III", 0);
				break;
			case CHEETAH_PLUS_IMPL:
				log_printf("%-7s ", "US-III+", 0);
				break;
			case JAGUAR_IMPL:
				log_printf("%-7s ", "US-IV", 0);
				break;
			case PANTHER_IMPL:
				log_printf("%-7s ", "US-IV+", 0);
				break;
			default:
				log_printf("%-7x ", *impl, 0);
				break;
			}
		}

		/* CPU Mask */
		if (mask == NULL) {
			log_printf(" %3s   ", "N/A", 0);
		} else {
			if (IS_CHEETAH(*impl))
				decoded_mask = REMAP_CHEETAH_MASK(*mask);
			else
				decoded_mask = *mask;

			log_printf(" %d.%d   ",
			    (decoded_mask >> 4) & 0xf,
			    decoded_mask & 0xf, 0);
		}

		log_printf("\n", 0);
	}
}


/*ARGSUSED3*/
void
display_diaginfo(int flag, Prom_node *root, Sys_tree *tree,
    struct system_kstat_data *kstats)
{
	log_printf("\n", 0);
	log_printf("=========================", 0);
	log_printf(dgettext(TEXT_DOMAIN, " Hardware Failures "), 0);
	log_printf("==================================", 0);
	log_printf("\n", 0);

	/*
	 * Get a list of failed parts (ie. devices with a status of
	 * 'fail') from the OBP device tree and display them.
	 */
	get_failed_parts();

	/* return unless -v option specified */
	if (!flag) {
		log_printf("\n", 0);
		return;
	}

	/*
	 * display time of latest powerfail. Not all systems
	 * have this capability. For those that do not, this
	 * is just a no-op.
	 */
	disp_powerfail(root);

	/* Print the PROM revisions here */
	serengeti_display_hw_revisions(root, tree->bd_list);
}

/*
 * local functions -  functions that are only needed inside this library
 */

static void
serengeti_display_hw_revisions(Prom_node *root, Board_node *bdlist)
{
	Prom_node	*pnode;
	char		*value;

	/* Print the header */
	log_printf("\n", 0);
	log_printf("=========================", 0);
	log_printf(dgettext(TEXT_DOMAIN, " HW Revisions "), 0);
	log_printf("=======================================", 0);
	log_printf("\n", 0);
	log_printf("\n", 0);

	/* Display Prom revision header */
	log_printf("System PROM revisions:\n", 0);
	log_printf("----------------------\n", 0);

	/*
	 * Display OBP version info
	 */
	pnode = dev_find_node(root, "openprom");
	if (pnode != NULL) {
		value = (char *)get_prop_val(find_prop(pnode, "version"));
		log_printf("%s\n\n", value, 0);
	} else {
		log_printf("OBP ???\n\n", value, 0);
	}

	/*
	 * Display ASIC revisions
	 */
	log_printf("IO ASIC revisions:\n", 0);
	log_printf("------------------\n", 0);

	log_printf("                            Port\n", 0);
	log_printf("FRU Name    Model            ID    Status", 0);
#ifdef DEBUG
	log_printf("   Version  Notes\n", 0);
#else
	log_printf("   Version\n", 0);
#endif
	/* ---------FRU Name--Model-----------Port-Status */
	log_printf("----------- --------------- ---- ---------- "
#ifdef DEBUG
	    "-------  "
#endif
	    "-------\n", 0);
	/*
	 * Display SCHIZO version info
	 */
	display_schizo_revisions(bdlist, SG_SCHIZO_GOOD);

	/*
	 * Display sgsbbc version info
	 */
	display_sgsbbc_revisions(bdlist);
}

/*
 * This function displays Schizo and Xmits revision of boards
 */
static int
display_schizo_revisions(Board_node *bdlist, int mode)
{
	Prom_node	*pnode;
	int		*int_val;
	int		portid;
	int		prev_portid = -1;
	char		*model;
	char		*status_a, *status_b;
	char		status[MAX_STATUS_LEN];
	int		version;
	int		node_id;
#ifdef DEBUG
	uint32_t	a_notes, b_notes;
#endif
	int		pci_bus;
	/*
	 * rv is used when mode is set to SG_SCHIZO_FAILED.
	 * We need to signal if a failure is found so that
	 * the correct headers/footers can be printed.
	 *
	 * rv = 1 implies a failed/disavled schizo device
	 * rv = 0 implies all other cases
	 */
	int		rv = 0;
	Board_node	*bnode;
	void		*value;

	bnode = bdlist;
	while (bnode != NULL) {
		/*
		 * search this board node for all Schizos
		 */
		for (pnode = dev_find_node_by_compatible(bnode->nodes,
		    SCHIZO_COMPATIBLE); pnode != NULL;
		    pnode = dev_next_node_by_compatible(pnode,
		    SCHIZO_COMPATIBLE)) {

			char	fru_name[MAX_FRU_NAME_LEN] = "";

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
			 * we skip onto the PCI bus A. (PCI-A and PCI-B share
			 * the same portid)
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

			/* get the node-id */
			node_id =  SG_PORTID_TO_NODEID(portid);

			/* model */
			model = (char *)get_prop_val
			    (find_prop(pnode, "model"));

			/* version */
			value = (int *)get_prop_val
			    (find_prop(pnode, "module-revision#"));

			if (value)
				int_val = (int *)value;
			else
				int_val = (int *)get_prop_val
				    (find_prop(pnode, "version#"));
			if (int_val != NULL)
				version = *int_val;
			else
				version = -1;

			/* status */
			status_a = (char *)get_prop_val(find_prop
			    (pnode, "status"));

			/*
			 * Display the data
			 */
			/* FRU Name */
			SG_SET_FRU_NAME_NODE(fru_name, node_id);
			SG_SET_FRU_NAME_IO_BOARD(fru_name,
			    SG_IO_BD_PORTID_TO_BD_NUM(portid));
			SG_SET_FRU_NAME_MODULE(fru_name, portid % 2);

			if (mode == SG_SCHIZO_FAILED) {
				if ((status_a != (char *)NULL) &&
				    ((status_b != (char *)NULL))) {
					if ((strcmp
					    (status_a, SG_DISABLED) == 0) &&
					    (strcmp(status_b,
					    SG_DISABLED) == 0)) {
						log_printf("\tFRU Type : %s\n ",
						    model, 0);
						log_printf("\tLocation : %s\n",
						    fru_name, 0);
						log_printf
						    ("\tPROM status: %s\n\n",
						    SG_DISABLED, 0);
						rv = 1;
					}
				}
				continue;
			}
			/*
			 * This section of code is executed when displaying
			 * non-failed schizo devices.  If the mode is set to
			 * SG_SCHIZO_FAILED, then this section of code will
			 * not be executed
			 */
			if ((status_a == (char *)NULL) &&
			    ((status_b == (char *)NULL)))
				sprintf(status, " %s      ", SG_OK);
			else if ((status_a == (char *)NULL) &&
			    ((strcmp(status_b, SG_DISABLED) == 0)))
				sprintf(status, " %s", SG_DEGRADED);
			else if ((status_b == (char *)NULL) &&
			    ((strcmp(status_a, SG_DISABLED) == 0)))
				sprintf(status, " %s", SG_DEGRADED);
			else
				continue;

			log_printf("%-12s", fru_name, 0);

			/* model */

			if (model != NULL)
				log_printf("%-15s  ", model, 0);
			else
				log_printf("%-15s  ", "unknown", 0);
			/* portid */
			log_printf("%-3d ", portid, 0);

			/* status */
			log_printf("%s", status, 0);

			/* version */
			log_printf("     %-4d   ", version, 0);
#ifdef DEBUG
			log_printf("0x%x 0x%x", a_notes, b_notes, 0);
			log_printf(" %d", portid, 0);
#endif
			log_printf("\n", 0);
		}
		bnode = bnode->next;
	}
	return (rv);
}

static void
display_sgsbbc_revisions(Board_node *bdlist)
{

	Prom_node	*pnode;
	int		*int_val;
	int		portid;
	char		*model;
	char		*status;
	int		revision;
	int		node_id;
	Board_node	*bnode;

#ifdef DEBUG
	char	*slot_name;
	char	notes[30];
	char	*value;
#endif

	bnode = bdlist;
	while (bnode != NULL) {
		/*
		 * search this board node for all sgsbbc's
		 */
		for (pnode = dev_find_node_by_type(bnode->nodes, "model",
		    "SUNW,sgsbbc"); pnode != NULL;
		    pnode = dev_next_node_by_type(pnode, "model",
		    "SUNW,sgsbbc")) {

			char	fru_name[MAX_FRU_NAME_LEN] = "";

			/*
			 * We need to go to this node's parent to
			 * get a portid to tell us what board it is on
			 */
			int_val = (int *)get_prop_val
			    (find_prop(pnode->parent, "portid"));
			if (int_val == NULL)
				continue;

			portid = *int_val;
			/* get the node-id */
			node_id =  SG_PORTID_TO_NODEID(portid);

			/* model */
			model = (char *)get_prop_val
			    (find_prop(pnode, "model"));

			/* status */
			status = (char *)get_prop_val(find_prop
			    (pnode, "status"));

			/* revision */
			int_val = (int *)get_prop_val
			    (find_prop(pnode, "revision-id"));
			if (int_val != NULL)
				revision = *int_val;
			else
				revision = -1;

#ifdef DEBUG
			value = (char *)get_prop_val(
			    find_prop(pnode->parent, "slot-names"));
			if (value != NULL) {
				/* Skip the 4 byte bitmask */
				slot_name = (char *)value + sizeof (int);
			} else {
				strcpy(slot_name, "not_found");
			}
			(void) sprintf(notes, "[%s] portid [%d]", slot_name,
			    portid);
#endif
			/*
			 * Display the data
			 */
			/* FRU Name */
			SG_SET_FRU_NAME_NODE(fru_name, node_id);
			SG_SET_FRU_NAME_IO_BOARD(fru_name,
			    SG_IO_BD_PORTID_TO_BD_NUM(portid));
			SG_SET_FRU_NAME_MODULE(fru_name, portid % 2);
			log_printf("%-12s", fru_name, 0);

			/* model */
			if (model != NULL)
				log_printf("%-15s  ", model, 0);
			else
				log_printf("%-15s  ", "unknown", 0);
			/* portid */
			log_printf("%-3d ", portid, 0);
			/* status */
			if (status == (char *)NULL)
				log_printf(" ok      ", 0);
			else
				log_printf(" fail    ", 0);
			/* revision */
			log_printf("     %-4d   ", revision, 0);
#ifdef DEBUG
			log_printf("%s", notes, 0);
#endif
			log_printf("\n", 0);
		}
		bnode = bnode->next;
	}
}

/*ARGSUSED0*/
void
display_hp_fail_fault(Sys_tree *tree, struct system_kstat_data *kstats)
{
	serengeti_display_board_info(ACTIVE);
	serengeti_display_board_info(INACTIVE);
}

/*
 * display_failed_parts
 *
 * Display the failed parts in the system. This function looks for
 * the status property in all PROM nodes contained in the Sys_tree
 * passed in.
 */
int
display_failed_parts(Sys_tree *tree)
{
	int system_failed = 0;
	int bank_failed = 0;
	int schizo_failed = FALSE;
	int portid, nodeid, board;
	Board_node *bnode = tree->bd_list;
	Prom_node *pnode;
	int *coreid, *impl;
	print_flag = TRUE;

	/*
	 * go through all of the OBP nodes looking for
	 * failed units.
	 */
	while (bnode != NULL) {

		pnode = find_failed_node(bnode->nodes);
		if ((pnode != NULL) && !system_failed) {
			system_failed = TRUE;
			log_printf("\n", 0);
			log_printf(dgettext(TEXT_DOMAIN,
			    "Failed Field Replaceable Units (FRU) in "
			    "System:\n"), 0);
			log_printf("=========================="
			    "====================\n", 0);
		}

		while (pnode != NULL) {
			void *status;
			char *name, *type, *model;

			char	fru_name[MAX_FRU_NAME_LEN] = "";

			status = get_prop_val(find_prop(pnode, "status"));
			name = get_node_name(pnode);

			/* sanity check of data retreived from PROM */
			if ((status == NULL) || (name == NULL)) {
				pnode = next_failed_node(pnode);
				continue;
			}

			type = get_node_type(pnode);
			portid = get_id(pnode);
			model = (char *)get_prop_val
			    (find_prop(pnode, "model"));

			/*
			 * Determine whether FRU is CPU module, Mem Controller,
			 * PCI card, schizo,xmits or sgsbbc.
			 */
			if ((model != NULL) && strstr(model, "sgsbbc")) {
				/*
				 * sgsbbc / bootbus-controller
				 */
				portid = get_id(pnode->parent);
				nodeid = SG_PORTID_TO_NODEID(portid);
				board = SG_PORTID_TO_BOARD_NUM(portid);

				SG_SET_FRU_NAME_NODE(fru_name, nodeid);
				SG_SET_FRU_NAME_IO_BOARD(fru_name, board);
				SG_SET_FRU_NAME_MODULE(fru_name, portid % 2);

				log_printf("\tFailed Device : %s (%s)\n", model,
				    name, 0);
				log_printf("\tLocation : %s\n", fru_name, 0);

			} else if (strstr(name, "pci") && (portid == -1)) {
				/*
				 * PCI Bridge if name = pci and it doesn't
				 * have a portid.
				 */
				portid = get_id(pnode->parent);
				nodeid = SG_PORTID_TO_NODEID(portid);
				board = SG_PORTID_TO_BOARD_NUM(portid);

				SG_SET_FRU_NAME_NODE(fru_name, nodeid);
				SG_SET_FRU_NAME_IO_BOARD(fru_name, board);
				SG_SET_FRU_NAME_MODULE(fru_name, portid % 2);

				log_printf("\tFRU type : ", 0);
				log_printf("PCI Bridge Device\n", 0);
				log_printf("\tLocation : %s\n", fru_name, 0);

			} else if ((type != NULL) &&
			    (strstr(type, "cpu") ||
			    strstr(type, "memory-controller"))) {
				/*
				 * CPU or memory controller
				 */
				portid = get_id(pnode);
				/*
				 * For cpu nodes that belong to a CMP, the
				 * portid is stored in the parent "cmp" node.
				 */
				if (portid == -1)
					portid = get_id(pnode->parent);
				nodeid = SG_PORTID_TO_NODEID(portid);
				board = SG_PORTID_TO_BOARD_NUM(portid);

				SG_SET_FRU_NAME_NODE(fru_name, nodeid);
				SG_SET_FRU_NAME_CPU_BOARD(fru_name, board);
				SG_SET_FRU_NAME_MODULE(fru_name, portid % 4);

				log_printf("\tFRU type : ", 0);

				if (strstr(type, "memory-controller"))
					log_printf("Memory Controller on ", 0);

				log_printf("UltraSPARC module\n", 0);

				log_printf("\tLocation : %s\n", fru_name, 0);

			} else {
				/*
				 * It should only be a PCI card if we get to
				 * here but lets check to be sure.
				 */
				char *parents_model, *grandparents_model;
				Prom_node *parent_pnode;
				int pci_card_found = 0;

				if (pnode->parent != NULL)
					parent_pnode = pnode->parent;

				/*
				 * Is our parent a schizo or xmits
				 */
				parents_model = (char *)get_prop_val
				    (find_prop(pnode->parent, "model"));
				if ((parents_model != NULL) &&
				    (strstr(parents_model, "SUNW,schizo") ||
				    strstr(parents_model, "SUNW,xmits"))) {
					portid = get_id(pnode->parent);
					pci_card_found = TRUE;
				}

				/*
				 * Is our grandparent a schizo xmits
				 */
				grandparents_model = (char *)get_prop_val
				    (find_prop(parent_pnode->parent, "model"));
				if ((grandparents_model != NULL) &&
				    (strstr(grandparents_model,
				    "SUNW,schizo") ||
				    strstr(grandparents_model,
				    "SUNW,xmits"))) {
					portid = get_id(parent_pnode->parent);
					pci_card_found = TRUE;
				}

				if (pci_card_found) {
					nodeid = SG_PORTID_TO_NODEID(portid);
					board = SG_PORTID_TO_BOARD_NUM(portid);

					SG_SET_FRU_NAME_NODE(fru_name, nodeid);
					SG_SET_FRU_NAME_IO_BOARD(fru_name,
					    board);
					SG_SET_FRU_NAME_MODULE(fru_name,
					    portid % 2);

					log_printf("\tFRU type :", 0);
					log_printf(" PCI Card\n", 0);
					log_printf("\tLocation : %s\n",
					    fru_name, 0);
				}
			}
			log_printf("\tPROM status: %s\n\n", status, 0);

			pnode = next_failed_node(pnode);
		}
		bnode = bnode->next;

	}

	bank_failed = display_us3_failed_banks(system_failed);
	schizo_failed = display_schizo_revisions(tree->bd_list,
	    SG_SCHIZO_FAILED);
	if (system_failed || bank_failed || schizo_failed)
		return (1);
	else
		return (0);
}


/*
 * This routine displays the memory configuration for all boards in the
 * system.
 */
void
display_memoryconf(Sys_tree *tree)
{
	Board_node	*bnode = tree->bd_list;

	log_printf("========================= Memory Configuration"
	    " ===============================\n", 0);
	log_printf("\n                     Logical  Logical  Logical ", 0);
	log_printf("\n               Port  Bank     Bank     Bank         "
	    "DIMM    Interleave  Interleave", 0);
	log_printf("\nFRU Name        ID   Num      Size     Status       "
	    "Size    Factor      Segment", 0);
	log_printf("\n-------------  ----  ----     ------   -----------  "
	    "------  ----------  ----------", 0);

	while (bnode != NULL) {
		if (get_us3_mem_regs(bnode)) {
			log_printf(dgettext(TEXT_DOMAIN,
			    "\nFailed to get memory information.\n"), 0);
			return;
		}
		bnode = bnode->next;
	}

	/* Display what we have found */
	display_us3_banks();
}

/*
 * This function provides Serengeti's formatting of the memory config
 * information that get_us3_mem_regs() and display_us3_banks() code has
 * gathered. It overrides the generic print_us3_memory_line() code
 * which prints an error message.
 */
void
print_us3_memory_line(int portid, int bank_id, uint64_t bank_size,
    char *bank_status, uint64_t dimm_size, uint32_t intlv, int seg_id)
{
	int		nodeid, board, mcid;
	char		fru_name[MAX_FRU_NAME_LEN] = "";

	mcid		= SG_PORTID_TO_SAFARI_ID(portid);
	nodeid		= SG_PORTID_TO_NODEID(portid);
	board		= SG_PORTID_TO_BOARD_NUM(portid);

	SG_SET_FRU_NAME_NODE(fru_name, nodeid);
	SG_SET_FRU_NAME_CPU_BOARD(fru_name, board);
	SG_SET_FRU_NAME_MODULE(fru_name, mcid % 4);
	SG_SET_FRU_NAME_BANK(fru_name, (bank_id % 4) % 2);

	log_printf("\n%-13s   %2d   %2d      %4lldMB    %11-s  %4lldMB "
	    "   %2d-way       %d",
	    fru_name, mcid,
	    (bank_id % 4), bank_size, bank_status, dimm_size,
	    intlv, seg_id, 0);
}

void
print_us3_failed_memory_line(int portid, int bank_id, char *bank_status)
{
	int		nodeid, board, mcid;
	char		fru_name[MAX_FRU_NAME_LEN] = "";

	mcid		= SG_PORTID_TO_SAFARI_ID(portid);
	nodeid		= SG_PORTID_TO_NODEID(portid);
	board		= SG_PORTID_TO_BOARD_NUM(portid);

	SG_SET_FRU_NAME_NODE(fru_name, nodeid);
	SG_SET_FRU_NAME_CPU_BOARD(fru_name, board);
	SG_SET_FRU_NAME_MODULE(fru_name, mcid % 4);
	SG_SET_FRU_NAME_BANK(fru_name, (bank_id % 4) % 2);

	log_printf("\tFRU type : ", 0);
	log_printf("Physical Memory Bank\n", 0);
	log_printf("\tLocation : %s (Logical Bank %2d)\n",
	    fru_name, (bank_id %4), 0);
	log_printf("\tPROM status: %s\n\n", bank_status, 0);
}


/*
 * Find the requested board struct in the system device tree.
 *
 * This function overrides the functionality of the generic find_board()
 * function in libprtdiag, but since we need to pass another parameter,
 * we cannot simply overlay the symbol table.
 */
static Board_node *
serengeti_find_board(Sys_tree *root, int board, int nodeid)
{
	Board_node *bnode = root->bd_list;

	while ((bnode != NULL) &&
	    ((board != bnode->board_num) || (nodeid != bnode->node_id))) {
		bnode = bnode->next;
	}
	return (bnode);
}


/*
 * Add a board to the system list in order (sorted by NodeID then board#).
 * Initialize all pointer fields to NULL.
 */
static Board_node *
serengeti_insert_board(Sys_tree *root, int board, int nodeid)
{
	Board_node *bnode;
	Board_node *temp = root->bd_list;

	if ((bnode = (Board_node *) malloc(sizeof (Board_node))) == NULL) {
		perror("malloc");
		exit(1);
	}

	bnode->nodes = NULL;
	bnode->next = NULL;
	bnode->board_num = board;
	bnode->node_id = nodeid;
	bnode->board_type = UNKNOWN_BOARD;

	if (temp == NULL)
		root->bd_list = bnode;

	else if ((temp->board_num > board) && (temp->node_id >= nodeid)) {
		bnode->next = temp;
		root->bd_list = bnode;

	} else {
		while ((temp->next != NULL) &&
		    ((board > temp->next->board_num) ||
		    (nodeid > temp->node_id)))
			temp = temp->next;

		bnode->next = temp->next;
		temp->next = bnode;
	}
	root->board_cnt++;

	return (bnode);
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
 * return the property value for the Prop passed in depending on
 * which tree (OBP/DEVINFO) is being used.
 */
void *
get_prop_val(Prop *prop)
{
	if (prop == NULL)
		return (NULL);

	/* Check which tree is being used. */
	if (tree == DEVINFO_TREE)
		return ((void *)(prop->value.val_ptr));
	else {
		if (prop->value.opp.holds_array)
			return ((void *)(prop->value.opp.oprom_array));
		else
			return ((void *)(&prop->value.opp.oprom_node[0]));
	}
}

/*
 * Search a Prom node and retrieve the property with the correct
 * name depending on which tree (OBP/DEVINFO) is being used.
 */
Prop *
find_prop(Prom_node *pnode, char *name)
{
	Prop *prop;

	if (pnode  == NULL)
		return (NULL);

	if (pnode->props == NULL)
		return (NULL);

	prop = pnode->props;

	/* Check which tree is being used. */
	if (tree == DEVINFO_TREE) {
		while ((prop != NULL) &&
		    (strcmp((char *)(prop->name.val_ptr), name)))
			prop = prop->next;
	} else {
		while ((prop != NULL) && (strcmp((char *)
		    (prop->name.opp.oprom_array), name)))
			prop = prop->next;
	}
	return (prop);
}

/*
 * This function searches through the properties of the node passed in
 * and returns a pointer to the value of the name property
 * depending on which tree (OBP/DEVINFO) is being used.
 */
char *
get_node_name(Prom_node *pnode)
{
	Prop *prop;

	if (pnode == NULL)
		return (NULL);

	prop = pnode->props;
	while (prop != NULL) {
		/* Check which tree is being used. */
		if (tree == DEVINFO_TREE) {
			if (strcmp("name", (char *)prop->name.val_ptr) == 0)
				return ((char *)prop->value.val_ptr);
		} else {
			if (strcmp("name", prop->name.opp.oprom_array) == 0)
				return (prop->value.opp.oprom_array);
		}
		prop = prop->next;
	}
	return (NULL);
}

/*
 * This function searches through the properties of the node passed in
 * and returns a pointer to the value of the device_type property
 * depending on which tree (OBP/DEVINFO) is being used.
 */
char *
get_node_type(Prom_node *pnode)
{
	Prop *prop;

	if (pnode == NULL)
		return (NULL);

	prop = pnode->props;
	while (prop != NULL) {
		/* Check which tree is being used. */
		if (tree == DEVINFO_TREE) {
			if (strcmp("device_type", (char *)prop->name.val_ptr)
			    == 0)
				return ((char *)prop->value.val_ptr);
		} else {
			if (strcmp("device_type", prop->name.opp.oprom_array)
			    == 0)
				return (prop->value.opp.oprom_array);
		}
		prop = prop->next;
	}
	return (NULL);
}

/*
 * Take a snapshot of the OBP device tree and walk this snapshot
 * to find all failed HW (ie. devices with a status property of
 * 'fail'). Call display_failed_parts() to display the failed HW.
 */
void
get_failed_parts(void)
{
	int system_failed = 0;
	Sys_tree obp_sys_tree;		/* system information */

	/* set the the system tree fields */
	obp_sys_tree.sys_mem = NULL;
	obp_sys_tree.boards = NULL;
	obp_sys_tree.bd_list = NULL;
	obp_sys_tree.board_cnt = 0;

	if (promopen(O_RDONLY)) {
		(void) fprintf(stderr, "%s",
		    dgettext(TEXT_DOMAIN, "openprom device "
		    "open failed"));
		return;
	}

	if ((is_openprom() == 0) || (next(0) == 0)) {
		(void) fprintf(stderr, "%s",
		    dgettext(TEXT_DOMAIN, "openprom device "
		    "error encountered."));
		return;
	}

	tree = OBP_TREE;	/* Switch to the OBP tree */

	(void) walk(&obp_sys_tree, NULL, next(0));

	system_failed = display_failed_parts(&obp_sys_tree);

	if (!system_failed) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "No Hardware failures found in System\n"), 0);
	}
	promclose();
	tree = DEVINFO_TREE;	/* Switch back to the DEVINFO tree */
}

/*
 * get_slot_name figures out the slot no. for the card. In the case of
 * XMITS slots 2 & 3 and slots 6 & 7 are reversed in slot_name by OBP
 * so we need to cater for this to correctly identify the slot no.
 */
static void
get_slot_name(struct io_card *card, char *slot_name)
{
	char tmp_ptr[2];

	if (strlen(slot_name) != 0) {
		if (strcmp(card->notes, XMITS_COMPATIBLE) == 0) {
			(void) sprintf(tmp_ptr, "%c",
			    slot_name[strlen(slot_name) -1]);
			switch (tmp_ptr[0]) {
			case '2':
				(void) sprintf(card->slot_str, "%c", '3');
				break;
			case '3':
				(void) sprintf(card->slot_str, "%c", '2');
				break;
			case '6':
				(void) sprintf(card->slot_str, "%c", '7');
				break;
			case '7':
				(void) sprintf(card->slot_str, "%c", '6');
				break;
			default:
				(void) sprintf(card->slot_str, "%c",
				    slot_name[strlen(slot_name) -1]);
			}
		} else
			(void) sprintf(card->slot_str, "%c",
			    slot_name[strlen(slot_name) -1]);
	} else
		(void) sprintf(card->slot_str, "-");
}
