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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2020 Peter Tribble.
 *
 * Opl Platform specific functions.
 *
 *	called when :
 *	machine_type == MTYPE_OPL
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <varargs.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <sys/openpromio.h>
#include <libintl.h>
#include <syslog.h>
#include <sys/dkio.h>
#include <pdevinfo.h>
#include <libprtdiag.h>
#include <libdevinfo.h>
#include <kstat.h>

/*
 * Globals and externs
 */
#define	KBYTE	1024
#define	MBYTE	(KBYTE * KBYTE)
#define	HZ_TO_MHZ(x)	((((uint64_t)(x)) + 500000) / 1000000)
#define	SCF_SECURE_MODE_KSTAT_NAMED	"secure_mode"
#define	SCF_STAT_MODE_UNLOCK	0
#define	SCF_STAT_MODE_LOCK	1
#define	SCF_SYSTEM_KSTAT_NAME	"scf"
#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SYS_TEST"
#endif	/* TEXT_DOMAIN */

/*
 * Global functions and variables
 * these functions will overlay the symbol table of libprtdiag
 * at runtime (Opl systems only)
 */
struct  cs_status {
	int cs_number;
	int status;
	uint_t avail_hi;
	uint_t avail_lo;
	uint_t dimm_hi;
	uint_t dimm_lo;
	int dimms;
};

int	do_prominfo(int syserrlog, char *pgname, int log_flag, int prt_flag);
void	*get_prop_val(Prop *prop);
void	display_ffb(Board_node *, int);
void	display_sbus(Board_node *board);
void	display_cpu_devices(Sys_tree *tree);
void	display_cpus(Board_node *board);
void	display_memoryconf(Sys_tree *tree);
void	display_io_cards(struct io_card *list);
void	display_io_devices(Sys_tree *tree);
void	display_diaginfo(int flag, Prom_node *root, Sys_tree *tree,
    struct system_kstat_data *kstats);
Prop	*find_prop(Prom_node *pnode, char *name);
int	do_piclinfo(int);
int	get_proc_mode(void);

/* Local functions */
static	void opl_disp_environ(void);
static	void opl_disp_hw_revisions(Sys_tree *tree, Prom_node *root);
static	uint64_t print_opl_memory_line(int lsb, struct cs_status *cs_stat,
    int ngrps, int mirror_mode);
static	uint64_t get_opl_mem_regs(Board_node *bnode);
void 	add_node(Sys_tree *root, Prom_node *pnode);
static	int get_prop_size(Prop *prop);

static int v_flag = 0;

/*
 * Linked list of IO card info for display.
 * Using file scope for use in a recursive function.
 */
static struct io_card *card_list = NULL;

/*
 * Check prom node for a class-code. If it exists and it's not a bridge device
 * then add an io_card to card_list. Then recursively call this function for
 * its child and sibling nodes.
 */
static void
walk_tree_for_pci_devices(Prom_node *node, int board_number)
{
	struct io_card card;
	char	*str;
	void	*val;
	int	ccode;

	if (node == NULL) {
		return;
	}

	/* Look for a class-code property. Skip, if it's a bridge */
	ccode = -1;
	val = get_prop_val(find_prop(node, "class-code"));
	if (val != NULL) {
		ccode = *(int *)val;
	}
	if ((ccode != -1) && (ccode < 0x60000 || ccode > 0x6ffff)) {
		(void) memset(&card, 0, sizeof (card));
		card.board = board_number;

		str = (char *)get_prop_val(find_prop(node, "name"));
		(void) strlcpy(card.name, (str == NULL ? "N/A":str),
		    sizeof (card.name));

		str = (char *)get_prop_val(find_prop(node, "model"));
		(void) strlcpy(card.model, (str == NULL ? "N/A":str),
		    sizeof (card.model));

		/* insert card to the list */
		card_list = insert_io_card(card_list, &card);
	}
	/* Call this function for its child/sibling */
	walk_tree_for_pci_devices(node->child, board_number);
	walk_tree_for_pci_devices(node->sibling, board_number);
}

/*
 * For display of I/O devices for "prtdiag"
 */
void
display_io_devices(Sys_tree *tree)
{
	Board_node *bnode;

	if (v_flag) {
		/*
		 * OPL's PICL interface for display of PCI I/O devices
		 * for "prtdiag -v"
		 */
		(void) do_piclinfo(v_flag);
	} else {
		log_printf("\n", 0);
		log_printf("=========================", 0);
		log_printf(dgettext(TEXT_DOMAIN, " IO Cards "), 0);
		log_printf("=========================", 0);
		log_printf("\n", 0);
		log_printf("\n", 0);
		bnode = tree->bd_list;
		while (bnode != NULL) {
			walk_tree_for_pci_devices(bnode->nodes,
			    bnode->board_num);
			bnode = bnode->next;
		}
		display_io_cards(card_list);
		free_io_cards(card_list);
	}
}

/*
 * There are no FFB's on OPL.
 */
/*ARGSUSED*/
void
display_ffb(Board_node *board, int table)
{
}

/*
 * There are no Sbus's on OPL.
 */
/*ARGSUSED*/
void
display_sbus(Board_node *board)
{
}

/*
 * Details of I/O information. Print out all the io cards.
 */
void
display_io_cards(struct io_card *list)
{
	char	*hdrfmt = "%-6.6s %-14.14s %-12.12s\n";

	struct io_card *p;

	if (list == NULL)
		return;

	(void) textdomain(TEXT_DOMAIN);

	log_printf(hdrfmt, gettext("LSB"), gettext("Name"), gettext("Model"),
	    0);

	log_printf(hdrfmt, "---", "-----------------", "------------", 0);

	for (p = list; p != NULL; p = p->next) {

		/* Board number */
		log_printf(" %02d    ", p->board, 0);

		/* Card name */
		log_printf("%-15.15s", p->name, 0);

		/* Card model */
		log_printf("%-12.12s", p->model, 0);

		log_printf("\n", 0);
	}
	log_printf("\n", 0);
}

/*
 * Details of CPU information.
 */
void
display_cpu_devices(Sys_tree *tree)
{
	Board_node *bnode;
	char *hdrfmt =
	    "%-4.4s  %-4.4s  %-40.40s  %-5.5s  %-5.5s  %-5.5s %-4.4s\n";

	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Display the table header for CPUs . Then display the CPU
	 * frequency, cache size, and processor revision of all cpus.
	 */
	log_printf("\n", 0);
	log_printf("====================================", 0);
	log_printf(gettext(" CPUs "), 0);
	log_printf("====================================", 0);
	log_printf("\n\n", 0);

	log_printf(hdrfmt,
	    "",
	    gettext("CPU"),
	    gettext("              CPU                  "),
	    gettext("Run"),
	    gettext("L2$"),
	    gettext("CPU"),
	    gettext("CPU"), 0);

	log_printf(hdrfmt,
	    gettext("LSB"),
	    gettext("Chip"),
	    gettext("               ID                 "),
	    gettext("MHz"),
	    gettext(" MB"),
	    gettext("Impl."),
	    gettext("Mask"), 0);

	log_printf(hdrfmt,
	"---", "----", "----------------------------------------", "----",
	"---",  "-----", "----", 0);

	/* Now display all of the cpus on each board */
	for (bnode = tree->bd_list; bnode != NULL; bnode = bnode->next) {
		display_cpus(bnode);
	}

	log_printf("\n", 0);
}

/*
 * Display the CPUs present on this board.
 */
void
display_cpus(Board_node *board)
{
	int *impl, *mask, *cpuid, *portid, *l2cache_size;
	uint_t freq;		/* CPU clock frequency */
	Prom_node *pnode, *cpu;
	char *name;

	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Get the Cpus' properties for display
	 */
	for (pnode = board->nodes; pnode != NULL; pnode = pnode->sibling) {
		char cpu_str[MAXSTRLEN], fcpu_str[MAXSTRLEN] = {0};

		name = get_node_name(pnode);
		if ((name == NULL) || (strncmp(name, "cmp", 3) != 0)) {
			continue;
		}

		portid = (int *)get_prop_val(find_prop(pnode, "portid"));
		freq = (HZ_TO_MHZ(get_cpu_freq(pnode->child)));
		l2cache_size = (int *)get_prop_val(find_prop(pnode->child,
		    "l2-cache-size"));
		impl = (int *)get_prop_val(find_prop(pnode->child,
		    "implementation#"));
		mask = (int *)get_prop_val(find_prop(pnode->child, "mask#"));

		/* Lsb id */
		log_printf(" %02d   ", board->board_num, 0);

		if (portid != NULL)
			log_printf("%3d   ", (((*portid)>>3)&0x3), 0);

		/*
		 * OPL
		 * Specific parsing of the CMP/CORE/CPU chain.
		 * The internal cpu tree built by walk_di_tree()
		 * in common code can be illustrated by the diagram
		 * below:
		 *
		 * Olympus:
		 *
		 *   cmp->cpu->cpu->cpu->cpu->(next board nodes)
		 *   / \
		 * core core
		 *
		 * Jupiter:
		 *
		 * cmp->cpu->cpu->cpu->cpu->cpu->cpu->cpu->cpu->(board nodes)
		 *   |
		 *  _____________
		 * /   \    \    \
		 * core core core core
		 *
		 *
		 * where "/" or "\" are children
		 *    and "->" are siblings
		 *
		 */
		for (cpu = pnode->sibling; cpu != NULL; ) {
			Prom_node	*cpu_next = NULL;

			name = get_node_name(cpu);
			if ((name == NULL) || (strncmp(name, "cpu", 3) != 0)) {
				break;
			}

			/* Id assigned to Virtual processor core */
			cpuid = (int *)get_prop_val(find_prop(cpu, "cpuid"));
			cpu_next = cpu->sibling;

			if (cpu_next != NULL) {
				name = get_node_name(cpu_next);

				if ((name == NULL) ||
				    (strncmp(name, "cpu", 3) != 0)) {
					cpu_next = NULL;
				}
			}

			if (cpuid != NULL) {
				/* Used for printing in comma format */
				(void) sprintf(cpu_str, "%4d", *cpuid);
				(void) strlcat(fcpu_str, cpu_str, MAXSTRLEN);

				if (cpu_next != NULL) {
					(void) strlcat(fcpu_str, ",",
					    MAXSTRLEN);
				}
			} else {
				(void) sprintf(cpu_str, "%4s", "N/A");
				(void) strlcat(fcpu_str, cpu_str, MAXSTRLEN);

				if (cpu_next != NULL) {
					(void) strlcat(fcpu_str, ",",
					    MAXSTRLEN);
				}
			}
			cpu = cpu_next;
		}

		log_printf("%-40.40s", fcpu_str, 0);

		/* Running frequency */
		if (freq != 0)
			log_printf("  %4ld  ", freq, 0);
		else
			log_printf("  %4s  ", "N/A", 0);

		/* L2 cache size */
		if (l2cache_size == NULL)
			log_printf(" %3s    ", "N/A", 0);
		else {
			log_printf("%4.1f   ",
			    (float)(*l2cache_size) / (float)(1<<20), 0);
		}


		/* Implementation number of processor */
		if (impl != NULL)
			log_printf("  %4d  ", *impl, 0);
		else
			log_printf(" %4s     ", "N/A", 0);

		/* Mask Set version */
		/* Bits 31:24 of VER register is mask. */
		/* Mask value : Non MTP mode - 00-7f, MTP mode - 80-ff */
		if (mask == NULL)
			log_printf("%3s", "N/A", 0);
		else
			log_printf("%-3d", (*mask)&0xff, 0);

		log_printf("\n", 0);

	}
}

/*
 * Gather memory information: Details of memory information.
 */
static uint64_t
get_opl_mem_regs(Board_node *bnode)
{
	Prom_node	*pnode;
	struct		cs_status	*cs_stat;
	uint64_t	total_mem = 0;
	int		cs_size, ngrps;

	pnode = dev_find_node(bnode->nodes, "pseudo-mc");
	while (pnode != NULL) {

		cs_size = get_prop_size(find_prop(pnode, "cs-status"));

		if (cs_size > 0) {
			int	*mirror_mode = NULL;
			int	mode = 0;

			/* OBP returns lists of 7 ints */
			cs_stat = (struct cs_status *)get_prop_val
			    (find_prop(pnode, "cs-status"));

			mirror_mode = (int *)(get_prop_val
			    (find_prop(pnode, "mirror-mode")));

			if (mirror_mode != NULL)
				mode = (*mirror_mode);

			/*
			 * The units of cs_size will be either number of bytes
			 * or number of int array elements as this is derived
			 * from the libprtdiag Prop node size field which has
			 * inconsistent units.   Until this is addressed in
			 * libprtdiag, we need a heuristic to determine the
			 * number of CS groups.  Given that the maximum number
			 * of CS groups is 2, the maximum number of cs-status
			 * array elements will be 2*7=14.  Since this is smaller
			 * than the byte size of a single struct status, we use
			 * this to decide if we are dealing with bytes or array
			 * elements in determining the number of CS groups.
			 */
			if (cs_size < sizeof (struct cs_status)) {
				/* cs_size is number of total int [] elements */
				ngrps = cs_size / 7;
			} else {
				/* cs_size is total byte count */
				ngrps = cs_size/sizeof (struct cs_status);
			}

			if (cs_stat != NULL) {
				total_mem +=
				    print_opl_memory_line(bnode->board_num,
				    cs_stat, ngrps, mode);
			}
		}

		pnode = dev_next_node(pnode, "pseudo-mc");
	}
	return (total_mem);
}

/*
 * Display memory information.
 */
void
display_memoryconf(Sys_tree *tree)
{
	Board_node	*bnode = tree->bd_list;
	uint64_t	total_mem = 0, total_sys_mem = 0;
	char *hdrfmt =  "\n%-5.5s  %-6.6s  %-18.18s  %-10.10s"
	    " %-6.6s  %-5.5s %-7.7s %-10.10s";

	(void) textdomain(TEXT_DOMAIN);

	log_printf("============================", 0);
	log_printf(gettext(" Memory Configuration "), 0);
	log_printf("============================", 0);
	log_printf("\n", 0);

	log_printf(hdrfmt,
	    "",
	    gettext("Memory"),
	    gettext("Available"),
	    gettext("Memory"),
	    gettext("DIMM"),
	    gettext("# of"),
	    gettext("Mirror"),
	    gettext("Interleave"),
	    0);

	log_printf(hdrfmt,
	    gettext("LSB"),
	    gettext("Group"),
	    gettext("Size"),
	    gettext("Status"),
	    gettext("Size"),
	    gettext("DIMMs"),
	    gettext("Mode"),
	    gettext("Factor"), 0);

	log_printf(hdrfmt,
	    "---", "-------", "------------------", "-------", "------",
	    "-----", "-------", "----------",  0);

	log_printf("\n", 0);

	for (bnode = tree->bd_list; bnode != NULL; bnode = bnode->next) {
		total_mem += get_opl_mem_regs(bnode);
	}

	/*
	 * Sanity check to ensure that the total amount of system
	 * memory matches the total number of memory that
	 * we find here. Display error message if there is a mis-match.
	 */
	total_sys_mem = (((uint64_t)sysconf(_SC_PAGESIZE) * (uint64_t)sysconf
	    (_SC_PHYS_PAGES)) / MBYTE);

	if (total_mem != total_sys_mem) {
		log_printf(dgettext(TEXT_DOMAIN, "\nError:total available "
		    "size [%lldMB] does not match total system memory "
		    "[%lldMB]\n"), total_mem, total_sys_mem, 0);
	}

}

/*
 * This function provides Opl's formatting of the memory config
 * information that get_opl_mem_regs() has gathered.
 */
static uint64_t
print_opl_memory_line(int lsb, struct cs_status *cs_stat, int ngrps,
	int mirror_mode)
{
	int	i;
	uint64_t	total_board_mem = 0;
	int		i_factor = 2;   /* default to non-mirror mode */
	int		interleave;

	(void) textdomain(TEXT_DOMAIN);

	if (mirror_mode)
		i_factor *= 2;

	/*
	 * Interleave factor calculation:
	 * Obtain "mirror-mode" property from pseudo-mc.
	 * cs_stat[0].dimms/i_factor represents interleave factor per
	 * pseudo-mc node. Must use cs_stat[0].dimms since this will yield
	 * interleave factor even if some DIMMs are isolated, except for
	 * the case where the entire memory group has been deconfigured (eg. due
	 * to DIMM failure); in this case, we use the second memory group
	 * (i.e. cs_stat[1]).
	 *
	 * Mirror mode:
	 *   interleave factor = (# of DIMMs on cs_stat[0]/4)
	 *
	 * Non-mirror mode:
	 *   interleave factor = (# of DIMMs on cs_stat[0]/2)
	 */

	if (cs_stat[0].dimms == 0)
		interleave = cs_stat[1].dimms/i_factor;
	else
		interleave = cs_stat[0].dimms/i_factor;


	for (i = 0; i < ngrps; i++) {
		uint64_t	mem_size;

		mem_size = ((((uint64_t)cs_stat[i].avail_hi)<<32) +
		    cs_stat[i].avail_lo);

		if (mem_size == 0)
			continue;

		/* Lsb Id */
		log_printf(" %02d    ", lsb, 0);

		/* Memory Group Number */
		if ((cs_stat[i].cs_number) == 0)
			log_printf("%-6.6s", "A", 0);
		else
			log_printf("%-6.6s", "B", 0);

		/* Memory Group Size */
		log_printf("%8lldMB            ", mem_size/MBYTE, 0);

		total_board_mem += (mem_size/MBYTE);

		/* Memory Group Status */
		log_printf("%-11.11s",
		    cs_stat[i].status ? "partial": "okay", 0);

		/* DIMM Size */
		log_printf("%4lldMB   ",
		    ((((uint64_t)cs_stat[i].dimm_hi)<<32)
		    + cs_stat[i].dimm_lo)/MBYTE, 0);

		/* Number of DIMMs */
		log_printf("  %2d", cs_stat[i].dimms);

		/* Mirror Mode */
		if (mirror_mode) {
			log_printf("%-4.4s", " yes");
		} else
			log_printf("%-4.4s", " no ");

		/* Interleave Factor */
		if (interleave)
			log_printf("      %d-way\n", interleave);
		else
			log_printf("      None\n");
	}
	return (total_board_mem);
}

/*
 * Details of hardware revision and environmental status.
 */
/*ARGSUSED*/
void
display_diaginfo(int flag, Prom_node *root, Sys_tree *tree,
	struct system_kstat_data *kstats)
{
	/* Print the PROM revisions */
	opl_disp_hw_revisions(tree, root);
}

/*
 * Gather and display hardware revision and environmental status
 */
/*ARGSUSED*/
static void
opl_disp_hw_revisions(Sys_tree *tree, Prom_node *root)
{
	char		*version;
	Prom_node	*pnode;
	int		value;

	(void) textdomain(TEXT_DOMAIN);

	/* Print the header */
	log_printf("\n", 0);
	log_printf("====================", 0);
	log_printf(gettext(" Hardware Revisions "), 0);
	log_printf("====================", 0);
	log_printf("\n\n", 0);

	/* Display Prom revision header */
	log_printf(gettext("System PROM revisions:"), 0);
	log_printf("\n----------------------\n", 0);
	log_printf("\n", 0);

	/* Display OBP version info */
	pnode = dev_find_node(root, "openprom");
	if (pnode != NULL) {
		version = (char *)get_prop_val(find_prop(pnode, "version"));
		if (version != NULL)
			log_printf("%s\n\n", version, 0);
		else
			log_printf("%s\n\n", "N/A", 0);
	}

	/* Print the header */
	log_printf("\n", 0);
	log_printf("===================", 0);
	log_printf(gettext(" Environmental Status "), 0);
	log_printf("===================", 0);
	log_printf("\n\n", 0);

	opl_disp_environ();

	/*
	 * PICL interface needs to be used for system processor mode display.
	 * Check existence of OBP property "SPARC64-VII-mode".
	 * No display if property does not exist.
	 * If property exists then system is in (Jupiter) SPARC64-VII-mode.
	 */
	value = get_proc_mode();

	if (value == 0) {
		/* Print the header */
		log_printf("\n", 0);
		log_printf("===================", 0);
		log_printf(gettext(" System Processor Mode "), 0);
		log_printf("===================", 0);
		log_printf("\n\n", 0);

		/* Jupiter mode */
		log_printf("%s\n\n", "SPARC64-VII mode");
	}
}

/*
 * Gather environmental information
 */
static void
opl_disp_environ(void)
{
	kstat_ctl_t *kc;
	kstat_t *ksp;
	kstat_named_t   *k;

	if ((kc = kstat_open()) == NULL)
		return;

	if ((ksp = kstat_lookup
	    (kc, "scfd", 0, SCF_SYSTEM_KSTAT_NAME)) == NULL) {
		(void) kstat_close(kc);
		return;
	}

	if (kstat_read(kc, ksp, NULL) == -1) {
		(void) kstat_close(kc);
		return;
	}

	if ((k = (kstat_named_t *)kstat_data_lookup
	    (ksp, SCF_SECURE_MODE_KSTAT_NAMED)) == NULL) {
		(void) kstat_close(kc);
		return;
	}

	if (k->value.c[0] == SCF_STAT_MODE_LOCK)
		log_printf("Mode switch is in LOCK mode ", 0);
	else if (k->value.c[0] == SCF_STAT_MODE_UNLOCK)
		log_printf("Mode switch is in UNLOCK mode", 0);
	else
		log_printf("Mode switch is in UNKNOWN mode", 0);

	log_printf("\n", 0);

	(void) kstat_close(kc);
}


/*
 * Calls do_devinfo() in order to use the libdevinfo device tree
 * instead of OBP's device tree.
 */
int
do_prominfo(int syserrlog, char *pgname, int log_flag, int prt_flag)
{
	v_flag = syserrlog;
	return (do_devinfo(syserrlog, pgname, log_flag, prt_flag));
}

/*
 * Return the property value for the Prop
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
 * Return the property size for the Prop
 * passed in. (When using libdevinfo)
 */
static int
get_prop_size(Prop *prop)
{

	if ((prop != NULL) && (prop->size > 0))
		return (prop->size);
	else
		return (0);
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
 * This function adds a board node to the board structure where that
 * that node's physical component lives.
 */
void
add_node(Sys_tree *root, Prom_node *pnode)
{
	int board;
	Board_node *bnode;
	Prom_node *p;
	char *type;

	if ((board = get_board_num(pnode)) == -1) {
		type = get_node_type(pnode);
		if ((type != NULL) && (strcmp(type, "cpu") == 0))
			board = get_board_num((pnode->parent)->parent);
	}

	/* find the node with the same board number */
	if ((bnode = find_board(root, board)) == NULL) {
		bnode = insert_board(root, board);
		bnode->board_type = UNKNOWN_BOARD;
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
