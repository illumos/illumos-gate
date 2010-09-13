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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Sunfire Platform specific functions.
 *
 * 	called when :
 *	machine_type == MTYPE_SUNFIRE
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
#include <errno.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/openpromio.h>
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

/* Macros for manipulating UPA IDs and board numbers on Sunfire. */
#define	bd_to_upa(bd) ((bd) << 1)
#define	upa_to_bd(upa)  ((upa) >> 1)

#define	MAX_MSGS	64

extern	int	print_flag;

/*
 * these functions will overlay the symbol table of libprtdiag
 * at runtime (sunfire systems only)
 */
int	error_check(Sys_tree *tree, struct system_kstat_data *kstats);
void	display_memoryconf(Sys_tree *tree, struct grp_info *grps);
int	disp_fail_parts(Sys_tree *tree);
void	display_memorysize(Sys_tree *tree, struct system_kstat_data *kstats,
		struct grp_info *grps, struct mem_total *memory_total);
void	display_hp_fail_fault(Sys_tree *tree, struct system_kstat_data *kstats);
void	display_diaginfo(int flag, Prom_node *root, Sys_tree *tree,
		struct system_kstat_data *kstats);
void	display_mid(int mid);
void 	display_pci(Board_node *);
void 	display_ffb(Board_node *, int);
void	add_node(Sys_tree *, Prom_node *);
void	resolve_board_types(Sys_tree *);

/* local functions */
static	void build_mem_tables(Sys_tree *, struct system_kstat_data *,
		struct grp_info *);
static	void get_mem_total(struct mem_total *, struct grp_info *);
static	int disp_fault_list(Sys_tree *, struct system_kstat_data *);
static	int disp_err_log(struct system_kstat_data *);
static	int disp_env_status(struct system_kstat_data *);
static	int disp_keysw_and_leds(struct system_kstat_data *);
static	void sunfire_disp_prom_versions(Sys_tree *);
static	void erase_msgs(char **);
static	void display_msgs(char **msgs, int board);
static	void sunfire_disp_asic_revs(Sys_tree *, struct system_kstat_data *);
static	void display_hp_boards(struct system_kstat_data *);
static	int disp_parts(char **, u_longlong_t, int);
/*
 * Error analysis routines. These routines decode data from specified
 * error registers. They are meant to be used for decoding the fatal
 * hardware reset data passed to the kernel by sun4u POST.
 */
static int analyze_cpu(char **, int, u_longlong_t);
static int analyze_ac(char **, u_longlong_t);
static int analyze_dc(int, char **, u_longlong_t);

#define	RESERVED_STR	"Reserved"

#define	MAX_PARTS	5
#define	MAX_FRUS	5

#define	MAXSTRLEN	256

/* Define special bits */
#define	UPA_PORT_A	0x1
#define	UPA_PORT_B	0x2


/*
 * These defines comne from async.h, but it does not get exported from
 * uts/sun4u/sys, so they must be redefined.
 */
#define	P_AFSR_ISAP	0x0000000040000000ULL /* incoming addr. parity err */
#define	P_AFSR_ETP	0x0000000020000000ULL /* ecache tag parity */
#define	P_AFSR_ETS	0x00000000000F0000ULL /* cache tag parity syndrome */
#define	ETS_SHIFT	16

/* List of parts possible */
#define	RSVD_PART	1
#define	UPA_PART	2
#define	UPA_A_PART	3
#define	UPA_B_PART	4
#define	SOFTWARE_PART	5
#define	AC_PART		6
#define	AC_ANY_PART	7
#define	DTAG_PART	8
#define	DTAG_A_PART	9
#define	DTAG_B_PART	10
#define	FHC_PART	11
#define	BOARD_PART	12
#define	BOARD_ANY_PART	13
#define	BOARD_CONN_PART	14
#define	BACK_PIN_PART	15
#define	BACK_TERM_PART	16
#define	CPU_PART	17

/* List of possible parts */
static char *part_str[] = {
	"",			/* 0, a placeholder for indexing */
	"",			/* 1, reserved strings shouldn't be printed */
	"UPA devices",					/* 2 */
	"UPA Port A device",				/* 3 */
	"UPA Port B device",				/* 4 */
	"Software error",				/* 5 */
	"Address Controller",				/* 6 */
	"Undetermined Address Controller in system",	/* 7 */
	"Data Tags",					/* 8 */
	"Data Tags for UPA Port A",			/* 9 */
	"Data Tags for UPA Port B",			/* 10 */
	"Firehose Controller",				/* 11 */
	"This Board",					/* 12 */
	"Undetermined Board in system",			/* 13 */
	"Board Connector",				/* 14 */
	"Centerplane pins ",				/* 15 */
	"Centerplane terminators",			/* 16 */
	"CPU",						/* 17 */
};

/* Ecache parity error messages. Tells which bits are bad. */
static char *ecache_parity[] = {
	"Bits 7:0 ",
	"Bits 15:8 ",
	"Bits 21:16 ",
	"Bits 24:22 "
};


struct ac_error {
	char *error;
	int part[MAX_PARTS];
};

typedef struct ac_error ac_err;

/*
 * Hardware error register meanings, failed parts and FRUs. The
 * following strings are indexed for the bit positions of the
 * corresponding bits in the hardware. The code checks bit x of
 * the hardware error register and prints out string[x] if the bit
 * is turned on.
 *
 * This database of parts which are probably failed and which FRU's
 * to replace was based on knowledge of the Sunfire Programmers Spec.
 * and discussions with the hardware designers. The order of the part
 * lists and consequently the FRU lists are in the order of most
 * likely cause first.
 */
static ac_err ac_errors[] = {
	{							/* 0 */
		"UPA Port A Error",
		{ UPA_A_PART, 0, 0, 0, 0 },
	},
	{							/* 1 */
		"UPA Port B Error",
		{ UPA_B_PART, 0, 0, 0, 0 },
	},
	{							/* 2 */
		NULL,
		{ RSVD_PART, 0, 0, 0, 0 },
	},
	{							/* 3 */
		NULL,
		{ RSVD_PART, 0, 0, 0, 0 },
	},
	{							/* 4 */
		"UPA Interrupt to unmapped destination",
		{ BOARD_PART, 0, 0, 0, 0 },
	},
	{							/* 5 */
		"UPA Non-cacheable write to unmapped destination",
		{ BOARD_PART, 0, 0, 0, 0 },
	},
	{							/* 6 */
		"UPA Cacheable write to unmapped destination",
		{ BOARD_PART, 0, 0, 0, 0 },
	},
	{							/* 7 */
		"Illegal Write Received",
		{ BOARD_PART, 0, 0, 0, 0 },
	},
	{							/* 8 */
		"Local Writeback match with line in state S",
		{ AC_PART, DTAG_PART, 0, 0, 0 },
	},
	{							/* 9 */
		"Local Read match with valid line in Tags",
		{ AC_PART, DTAG_PART, 0, 0, 0 },
	},
	{							/* 10 */
		NULL,
		{ RSVD_PART, 0, 0, 0, 0 },
	},
	{							/* 11 */
		NULL,
		{ RSVD_PART, 0, 0, 0, 0 },
	},
	{							/* 12 */
		"Tag and Victim were valid during lookup",
		{ AC_PART, DTAG_PART, 0, 0, 0 },
	},
	{							/* 13 */
		"Local Writeback matches a victim in state S",
		{ AC_PART, CPU_PART, 0, 0, 0 },
	},
	{							/* 14 */
		"Local Read matches valid line in victim buffer",
		{ AC_PART, CPU_PART, 0, 0, 0 },
	},
	{							/* 15 */
		"Local Read victim bit set and victim is S state",
		{ AC_PART, CPU_PART, 0, 0, 0 },
	},
	{							/* 16 */
		"Local Read Victim bit set and Valid Victim Buffer",
		{ AC_PART, CPU_PART, 0, 0, 0 },
	},
	{							/* 17 */
		NULL,
		{ RSVD_PART, 0, 0, 0, 0 },
	},
	{							/* 18 */
		NULL,
		{ RSVD_PART, 0, 0, 0, 0 },
	},
	{							/* 19 */
		NULL,
		{ RSVD_PART, 0, 0, 0, 0 },
	},
	{							/* 20 */
		"UPA Transaction received in Sleep mode",
		{ AC_PART, 0, 0, 0, 0 },
	},
	{							/* 21 */
		"P_FERR error P_REPLY received from UPA Port",
		{ CPU_PART, AC_PART, 0, 0, 0 },
	},
	{							/* 22 */
		"Illegal P_REPLY received from UPA Port",
		{ CPU_PART, AC_PART, 0, 0, 0 },
	},
	{							/* 23 */
		NULL,
		{ RSVD_PART, 0, 0, 0, 0 },
	},
	{							/* 24 */
		"Timeout on a UPA Master Port",
		{ AC_ANY_PART, BOARD_ANY_PART, 0, 0, 0 },
	},
	{							/* 25 */
		NULL,
		{ RSVD_PART, 0, 0, 0, 0 },
	},
	{							/* 26 */
		NULL,
		{ RSVD_PART, 0, 0, 0, 0 },
	},
	{							/* 27 */
		NULL,
		{ RSVD_PART, 0, 0, 0, 0 },
	},
	{							/* 28 */
		"Coherent Transactions Queue Overflow Error",
		{ BACK_PIN_PART, BOARD_CONN_PART, AC_PART, AC_ANY_PART, 0 },
	},
	{							/* 29 */
		"Non-cacheable Request Queue Overflow Error",
		{ AC_PART, AC_ANY_PART, 0, 0, 0 },
	},
	{							/* 30 */
		"Non-cacheable Reply Queue Overflow Error",
		{ AC_PART, 0, 0, 0, 0 },
	},
	{							/* 31 */
		"PREQ Queue Overflow Error",
		{ CPU_PART, AC_PART, 0, 0, 0 },
	},
	{							/* 32 */
		"Foreign DID CAM Overflow Error",
		{ AC_PART, AC_ANY_PART, 0, 0, 0 },
	},
	{							/* 33 */
		"FT->UPA Queue Overflow Error",
		{ BACK_PIN_PART, BOARD_CONN_PART, AC_PART, AC_ANY_PART, 0 },
	},
	{							/* 34 */
		NULL,
		{ RSVD_PART, 0, 0, 0, 0 },
	},
	{							/* 35 */
		NULL,
		{ RSVD_PART, 0, 0, 0, 0 },
	},
	{							/* 36 */
		"UPA Port B Dtag Parity Error",
		{ DTAG_B_PART, AC_PART, 0, 0, 0 },
	},
	{							/* 37 */
		"UPA Port A Dtag Parity Error",
		{ DTAG_A_PART, AC_PART, 0, 0, 0 },
	},
	{							/* 38 */
		NULL,
		{ RSVD_PART, 0, 0, 0, 0 },
	},
	{							/* 39 */
		NULL,
		{ RSVD_PART, 0, 0, 0, 0 },
	},
	{							/* 40 */
		"UPA Bus Parity Error",
		{ UPA_PART, AC_PART, 0, 0, 0 },
	},
	{							/* 41 */
		"Data ID Line Mismatch",
		{ BACK_PIN_PART, BOARD_CONN_PART, AC_PART, 0, 0 },
	},
	{							/* 42 */
		"Arbitration Line Mismatch",
		{ BACK_PIN_PART, BOARD_CONN_PART, AC_PART, 0, 0 },
	},
	{							/* 43 */
		"Shared Line Parity Mismatch",
		{ BACK_PIN_PART, BOARD_CONN_PART, AC_PART, 0, 0 },
	},
	{							/* 44 */
		"FireTruck Control Line Parity Error",
		{ AC_PART, BACK_PIN_PART, 0, 0, 0 },
	},
	{							/* 45 */
		"FireTruck Address Bus Parity Error",
		{ AC_PART, BACK_PIN_PART, 0, 0, 0 },
	},
	{							/* 46 */
		"Internal RAM Parity Error",
		{ AC_PART, 0, 0, 0, 0 },
	},
	{							/* 47 */
		NULL,
		{ RSVD_PART, 0, 0, 0, 0 },
	},
	{							/* 48 */
		"Internal Hardware Error",
		{ AC_PART, 0, 0, 0, 0 },
	},
	{							/* 49 */
		"FHC Communications Error",
		{ FHC_PART, AC_PART, 0, 0, 0 },
	},
	/* Bits 50-63 are reserved in this implementation. */
};


#define	MAX_BITS (sizeof (ac_errors)/ sizeof (ac_err))

/*
 * There are only two error bits in the DC shadow chain that are
 * important. They indicate an overflow error and a parity error,
 * respectively. The other bits are not error bits and should not
 * be checked for.
 */
#define	DC_OVERFLOW	0x2
#define	DC_PARITY	0x4

static char dc_overflow_txt[] = "Board %d DC %d Overflow Error";
static char dc_parity_txt[] = "Board %d DC %d Parity Error";

/* defines for the sysio */
#define	UPA_APERR	0x4

int
error_check(Sys_tree *tree, struct system_kstat_data *kstats)
{
	int exit_code = 0;	/* init to all OK */

	/*
	 * silently check for any types of machine errors
	 */
	print_flag = 0;
	if (disp_fail_parts(tree) || disp_fault_list(tree, kstats) ||
		disp_err_log(kstats) || disp_env_status(kstats)) {
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
			log_printf(dgettext(TEXT_DOMAIN,
				"Failed Field Replaceable Units (FRU) "
				"in System:\n"), 0);
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

			log_printf(dgettext(TEXT_DOMAIN,
				"%s unavailable on %s Board #%d\n"),
				name, board_type, bnode->board_num, 0);

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

				log_printf(dgettext(TEXT_DOMAIN,
					"UltraSPARC module "
					"Board %d Module %d\n"),
						get_id(pnode) >> 1,
						get_id(pnode) & 0x1);

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
display_memorysize(Sys_tree *tree, struct system_kstat_data *kstats,
	struct grp_info *grps, struct mem_total *memory_total) {

	/* Build the memory group tables and interleave data */
	build_mem_tables(tree, kstats, grps);

	/* display total usable installed memory */
	get_mem_total(memory_total, grps);
	(void) log_printf(dgettext(TEXT_DOMAIN,
		"Memory size: %4dMb\n"), memory_total->dram, 0);

	/* We display the NVSIMM size totals separately. */
	if (memory_total->nvsimm != 0) {
		(void) log_printf(dgettext(TEXT_DOMAIN,
			"NVSIMM size: %4dMb\n"), memory_total->nvsimm);
	}
}

/*
 * This routine displays the memory configuration for all boards in the
 * system.
 */
void
display_memoryconf(Sys_tree *tree, struct grp_info *grps)
{
	int group;
	char *status_str[] = {  "Unknown", " Empty ", " Failed", " Active",
				" Spare " };
	char *cond_str[] = {    " Unknown  ", "    OK    ", " Failing  ",
				"  Failed  ", " Uninit.  " };

#ifdef lint
	tree = tree;
#endif
	/* Print the header for the memory section. */
	log_printf("\n", 0);
	log_printf("=========================", 0);
	log_printf(dgettext(TEXT_DOMAIN, " Memory "), 0);
	log_printf("=========================", 0);
	log_printf("\n", 0);
	log_printf("\n", 0);
	log_printf("                                              Intrlv.  "
		"Intrlv.\n", 0);
	log_printf("Brd   Bank   MB    Status   Condition  Speed   Factor  "
		" With\n", 0);
	log_printf("---  -----  ----  -------  ----------  -----  -------  "
		"-------\n", 0);

	/* Print the Memory groups information. */
	for (group = 0; group < MAX_GROUPS; group++) {
		struct grp *grp;

		grp = &grps->grp[group];

		/* If this board is not a CPU or MEM board, skip it. */
		if ((grp->type != MEM_BOARD) && (grp->type != CPU_BOARD)) {
			continue;
		}

		if (grp->valid) {
			log_printf("%2d   ", grp->board, 0);
			log_printf("  %1d    ", grp->group, 0);
			log_printf("%4d  ", grp->size, 0);
			log_printf("%7s  ", status_str[grp->status], 0);
			log_printf("%10s  ", cond_str[grp->condition], 0);
			log_printf("%3dns  ", grp->speed, 0);
			log_printf("%3d-way  ", grp->factor, 0);
			if (grp->factor > 1) {
				log_printf("%4c", grp->groupid, 0);
			}
			log_printf("\n", 0);
		}
	}

}


void
display_hp_fail_fault(Sys_tree *tree, struct system_kstat_data *kstats)
{
	/* Display Hot plugged, disabled and failed boards */
	(void) display_hp_boards(kstats);

	/* Display failed units */
	(void) disp_fail_parts(tree);

	/* Display fault info */
	(void) disp_fault_list(tree, kstats);
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

		/* Display system environmental conditions. */
		(void) disp_env_status(kstats);

		/* Display ASIC Chip revs for all boards. */
		sunfire_disp_asic_revs(tree, kstats);

		/* Print the PROM revisions here */
		sunfire_disp_prom_versions(tree);

		/*
		 * Display the latest system fatal hardware
		 * error data, if any. The system holds this
		 * data in SRAM, so it does not persist
		 * across power-on resets.
		 */
		(void) disp_err_log(kstats);
	}
}

void
display_mid(int mid)
{
	log_printf("  %2d     ", mid % 2, 0);
}

/*
 * display_pci
 * Call the generic psycho version of this function.
 */
void
display_pci(Board_node *board)
{
	display_psycho_pci(board);
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
			card.slot = get_id(ffb);

			/* Find out if it's single or double buffered */
			(void) sprintf(card.name, "FFB");
			value = get_prop_val(find_prop(ffb, "board_type"));
			if (value != NULL)
				if ((*(int *)value) & FFB_B_BUFF)
					(void) sprintf(card.name, "FFB, "
						"Double Buffered");
				else
					(void) sprintf(card.name, "FFB, "
						"Single Buffered");

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

			log_printf("Board %d FFB Hardware Configuration:\n",
				board->board_num, 0);
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
 * add_node
 *
 * This function adds a board node to the board structure where that
 * that node's physical component lives.
 */
void
add_node(Sys_tree *root, Prom_node *pnode)
{
	int board;
	Board_node *bnode;
	char *name = get_node_name(pnode);
	Prom_node *p;

	/* add this node to the Board list of the appropriate board */
	if ((board = get_board_num(pnode)) == -1) {
		void *value;

		/*
		 * if it is a server, pci nodes and ffb nodes never have
		 * board number properties and software can find the board
		 * number from the reg property. It is derived from the
		 * high word of the 'reg' property, which contains the
		 * mid.
		 */
		if ((name != NULL) &&
		    ((strcmp(name, FFB_NAME) == 0) ||
		    (strcmp(name, "pci") == 0) ||
		    (strcmp(name, "counter-timer") == 0))) {
			/* extract the board number from the 'reg' prop. */
			if ((value = get_prop_val(find_prop(pnode,
			    "reg"))) == NULL) {
				(void) printf("add_node() no reg property\n");
				exit(2);
			}
			board = (*(int *)value - 0x1c0) / 4;
		}
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

/*
 * Function resolve_board_types
 *
 * After the tree is walked and all the information is gathered, this
 * function is called to resolve the type of each board.
 */
void
resolve_board_types(Sys_tree *tree)
{
	Board_node *bnode;
	Prom_node *pnode;
	char *type;

	bnode = tree->bd_list;
	while (bnode != NULL) {
		bnode->board_type = UNKNOWN_BOARD;

		pnode = dev_find_node(bnode->nodes, "fhc");
		type = get_prop_val(find_prop(pnode, "board-type"));
		if (type == NULL) {
			bnode = bnode->next;
			continue;
		}

		if (strcmp(type, CPU_BD_NAME) == 0) {
			bnode->board_type = CPU_BOARD;
		} else if (strcmp(type, MEM_BD_NAME) == 0) {
			bnode->board_type = MEM_BOARD;
		} else if (strcmp(type, DISK_BD_NAME) == 0) {
			bnode->board_type = DISK_BOARD;
		} else if (strcmp(type, IO_SBUS_FFB_BD_NAME) == 0) {
			bnode->board_type = IO_SBUS_FFB_BOARD;
		} else if (strcmp(type, IO_2SBUS_BD_NAME) == 0) {
			bnode->board_type = IO_2SBUS_BOARD;
		} else if (strcmp(type, IO_PCI_BD_NAME) == 0) {
			bnode->board_type = IO_PCI_BOARD;
		} else if (strcmp(type, IO_2SBUS_SOCPLUS_BD_NAME) == 0) {
			bnode->board_type = IO_2SBUS_SOCPLUS_BOARD;
		} else if (strcmp(type, IO_SBUS_FFB_SOCPLUS_BD_NAME) == 0) {
			bnode->board_type = IO_SBUS_FFB_SOCPLUS_BOARD;
		}

		bnode = bnode->next;
	}

}

/*
 * local functions
 */

static void
sunfire_disp_prom_versions(Sys_tree *tree)
{
	Board_node *bnode;

	/* Display Prom revision header */
	log_printf("System Board PROM revisions:\n", 0);
	log_printf("----------------------------\n", 0);

	/* For each board, print the POST and OBP versions */
	for (bnode = tree->bd_list; bnode != NULL; bnode = bnode->next) {
		Prom_node *flashprom;   /* flashprom device node */

		/* find a flashprom node for this board */
		flashprom = dev_find_node(bnode->nodes, "flashprom");

		/* If no flashprom node found, continue */
		if (flashprom == NULL)
			continue;

		/* flashprom node found, display board# */
		log_printf("Board %2d: ", bnode->board_num, 0);

		disp_prom_version(flashprom);
	}
}


/*
 * functions that are only needed inside this library
 */

/*
 * build_mem_tables
 *
 * This routine builds the memory table which tells how much memory
 * is present in each SIMM group of each board, what the interleave
 * factors are, and the group ID of the interleave group.
 *
 * The algorithms used are:
 *	First fill in the sizes of groups.
 *	Next build lists of all groups with same physical base.
 *	From #of members in each list, interleave factor is
 *	determined.
 *	All members of a certain list get the same interleave
 *	group ID.
 */
static void
build_mem_tables(Sys_tree *tree,
		struct system_kstat_data *kstats,
		struct grp_info *grps)
{
	struct mem_inter inter_grps;	/* temp structure for interleaves */
	struct inter_grp *intrp;
	int group;
	int i;

	/* initialize the interleave lists */
	for (i = 0, intrp = &inter_grps.i_grp[0]; i < MAX_GROUPS; i++,
	    intrp++) {
		intrp->valid = 0;
		intrp->count = 0;
		intrp->groupid = '\0';
		intrp->base = 0;
	}

	for (group = 0; group < MAX_GROUPS; group++) {
		int found;
		int board;
		struct grp *grp;
		struct bd_kstat_data *bksp;
		uchar_t simm_reg;
		Board_node *bnode;

		board = group/2;
		bksp = &kstats->bd_ksp_list[board];
		grp = &grps->grp[group];
		grp->group = group % 2;

		/*
		 * Copy the board type field into the group record.
		 */
		if ((bnode = find_board(tree, board)) != NULL) {
			grp->type = bnode->board_type;
		} else {
			grp->type = UNKNOWN_BOARD;
			continue;
		}

		/* Make sure we have kstats for this board */
		if (bksp->ac_kstats_ok == 0) {
			/* Mark this group as invalid and move to next one */
			grp->valid = 0;
			continue;
		}

		/* Find the bank status property */
		if (bksp->ac_memstat_ok) {
			grp->status = bksp->mem_stat[grp->group].status;
			grp->condition = bksp->mem_stat[grp->group].condition;
		} else {
			grp->status = StUnknown;
			grp->condition = ConUnknown;
		}

		switch (grp->status) {
		case StBad:
		case StActive:
		case StSpare:
			break;
		default:
			grp->status = StUnknown;
			break;
		}

		switch (grp->condition) {
		case ConOK:
		case ConFailing:
		case ConFailed:
		case ConTest:
		case ConBad:
			break;
		default:
			grp->condition = ConUnknown;
			break;
		}

		/* base the group size off of the simmstat kstat. */
		if (bksp->simmstat_kstats_ok == 0) {
			grp->valid = 0;
			continue;
		}

		/* Is it bank 0 or bank 1 */
		if (grp->group == 0) {
			simm_reg = bksp->simm_status[0];
		} else {
			simm_reg = bksp->simm_status[1];
		}

		/* Now decode the size field. */
		switch (simm_reg & 0x1f) {
		case MEM_SIZE_64M:
			grp->size = 64;
			break;
		case MEM_SIZE_256M:
			grp->size = 256;
			break;
		case MEM_SIZE_1G:
			grp->size = 1024;
			break;
		case MEM_SIZE_2G:
			grp->size = 2048;
			break;
		default:
			grp->valid = 0;
			continue;
		}

		/* Decode the speed field */
		switch ((simm_reg & 0x60) >> 5) {
		case MEM_SPEED_50ns:
			grp->speed = 50;
			break;
		case MEM_SPEED_60ns:
			grp->speed = 60;
			break;
		case MEM_SPEED_70ns:
			grp->speed = 70;
			break;
		case MEM_SPEED_80ns:
			grp->speed = 80;
			break;
		}

		grp->valid = 1;
		grp->base = GRP_BASE(bksp->ac_memdecode[grp->group]);
		grp->board = board;
		if (grp->group == 0) {
			grp->factor = INTLV0(bksp->ac_memctl);
		} else {	/* assume it is group 1 */
			grp->factor = INTLV1(bksp->ac_memctl);
		}
		grp->groupid = '\0';	/* Not in a group yet */

		/*
		 * find the interleave list this group belongs on. If the
		 * interleave list corresponding to this base address is
		 * not found, then create a new one.
		 */

		i = 0;
		intrp = &inter_grps.i_grp[0];
		found = 0;
		while ((i < MAX_GROUPS) && !found && (intrp->valid != 0)) {
			if ((intrp->valid != 0) &&
			    (intrp->base == grp->base)) {
				grp->groupid = intrp->groupid;
				intrp->count++;
				found = 1;
			}
			i++;
			intrp++;
		}
		/*
		 * We did not find a matching base. So now i and intrp
		 * now point to the next interleave group in the list.
		 */
		if (!found) {
			intrp->count++;
			intrp->valid = 1;
			intrp->groupid = 'A' + (char)i;
			intrp->base = grp->base;
			grp->groupid = intrp->groupid;
		}
	}
}


static void
get_mem_total(struct mem_total *mem_total, struct grp_info *grps)
{
	struct grp *grp;
	int i;

	/* Start with total of zero */
	mem_total->dram = 0;
	mem_total->nvsimm = 0;

	/* For now we ignore NVSIMMs. We might want to fix this later. */
	for (i = 0, grp = &grps->grp[0]; i < MAX_GROUPS; i++, grp++) {
		if (grp->valid == 1 && grp->status == StActive) {
			mem_total->dram += grp->size;
		}
	}
}

static int
disp_fault_list(Sys_tree *tree, struct system_kstat_data *kstats)
{
	struct ft_list *ftp;
	int i;
	int result = 0;
	time_t t;

	if (!kstats->ft_kstat_ok) {
		return (result);
	}

	for (i = 0, ftp = kstats->ft_array; i < kstats->nfaults; i++, ftp++) {
		if (!result) {
			log_printf("\n", 0);
			log_printf("Detected System Faults\n", 0);
			log_printf("======================\n", 0);
		}
		result = 1;
		if (ftp->fclass == FT_BOARD) {
			log_printf("Board %d fault: %s\n", ftp->unit,
				ftp->msg, 0);

			/*
			 * If the fault on this board is PROM inherited, see
			 * if we can find some failed component information
			 * in the PROM device tree. The general solution
			 * would be to fix the fhc driver and have it put in
			 * more descriptive messages, but that's for another
			 * day.
			 */

			if (ftp->type == FT_PROM) {
				Board_node *bn;
				Prom_node *pn;
				char *str;

				bn = find_board(tree, ftp->unit);
				/*
				 * If any nodes under this board have a
				 * status containing "fail", print it out.
				 */
				pn = find_failed_node(bn->nodes);
				while (pn) {
					str = get_prop_val(find_prop(pn,
						"status"));
					if (str != NULL) {
						log_printf("Fault: %s\n", str,
							0);
					}

					pn = next_failed_node(pn);
				}
			}
		} else if ((ftp->type == FT_CORE_PS) || (ftp->type == FT_PPS)) {
			log_printf("Unit %d %s failure\n", ftp->unit,
				ftp->msg, 0);
		} else if ((ftp->type == FT_OVERTEMP) &&
		    (ftp->fclass == FT_SYSTEM)) {
			log_printf("Clock board %s\n", ftp->msg, 0);
		} else {
			log_printf("%s failure\n", ftp->msg, 0);
		}

		t = (time_t)ftp->create_time;
		log_printf("\tDetected %s",
			asctime(localtime(&t)), 0);
	}

	if (!result) {
		log_printf("\n", 0);
		log_printf("No System Faults found\n", 0);
		log_printf("======================\n", 0);
	}

	log_printf("\n", 0);

	return (result);
}


/*
 * disp_err_log
 *
 * Display the fatal hardware reset system error logs. These logs are
 * collected by POST and passed up through the kernel to userland.
 * They will not necessarily be present in all systems. Their form
 * might also be different in different systems.
 *
 * NOTE - We are comparing POST defined board types here. Do not confuse
 * them with kernel board types. The structure being analyzed in this
 * function is created by POST. All the defines for it are in reset_info.h,
 * which was ported from POST header files.
 */
static int
disp_err_log(struct system_kstat_data *kstats)
{
	int exit_code = 0;
	int i;
	struct reset_info *rst_info;
	struct board_info *bdp;
	char *err_msgs[MAX_MSGS]; /* holds all messages for a system board */
	int msg_idx;		/* current msg number */
	int count;		/* number added by last analyze call */
	char **msgs;

	/* start by initializing the err_msgs array to all NULLs */
	for (i = 0; i < MAX_MSGS; i++) {
		err_msgs[i] = NULL;
	}

	/* First check to see that the reset-info kstats are present. */
	if (kstats->reset_kstats_ok == 0) {
		return (exit_code);
	}

	rst_info = &kstats->reset_info;

	/* Everything is OK, so print out time/date stamp first */
	log_printf("\n", 0);
	log_printf(
		dgettext(TEXT_DOMAIN,
			"Analysis of most recent Fatal Hardware Watchdog:\n"),
			0);
	log_printf("======================================================\n",
		0);
	log_printf("Log Date: %s\n",
		get_time(&kstats->reset_info.tod_timestamp[0]), 0);

	/* initialize the vector and the message index. */
	msgs = err_msgs;
	msg_idx = 0;

	/* Loop Through all of the boards. */
	bdp = &rst_info->bd_reset_info[0];
	for (i = 0; i < MAX_BOARDS; i++, bdp++) {

		/* Is there data for this board? */
		if ((bdp->board_desc & BD_STATE_MASK) == BD_NOT_PRESENT) {
			continue;
		}

		/* If it is a CPU Board, look for CPU data. */
		if (BOARD_TYPE(bdp->board_desc) == CPU_TYPE) {
			/* analyze CPU 0 if present */
			if (bdp->board_desc & CPU0_OK) {
				count = analyze_cpu(msgs, 0,
					bdp->cpu[0].afsr);
				msgs += count;
				msg_idx += count;
			}

			/* analyze CPU1 if present. */
			if (bdp->board_desc & CPU1_OK) {
				count = analyze_cpu(msgs, 1,
					bdp->cpu[1].afsr);
				msgs += count;
				msg_idx += count;
			}
		}

		/* Always Analyze the AC and the DCs on a board. */
		count = analyze_ac(msgs, bdp->ac_error_status);
		msgs += count;
		msg_idx += count;

		count = analyze_dc(i, msgs, bdp->dc_shadow_chain);
		msgs += count;
		msg_idx += count;

		if (msg_idx != 0)
			display_msgs(err_msgs, i);

		erase_msgs(err_msgs);

		/* If any messages are logged, we have errors */
		if (msg_idx != 0) {
			exit_code = 1;
		}

		/* reset the vector and the message index */
		msg_idx = 0;
		msgs = &err_msgs[0];
	}

	return (exit_code);
}

static void
erase_msgs(char **msgs)
{
	int i;

	for (i = 0; (*msgs != NULL) && (i < MAX_MSGS); i++, msgs++) {
		free(*msgs);
		*msgs = NULL;
	}
}


static void
display_msgs(char **msgs, int board)
{
	int i;

	/* display the header for this board */
	print_header(board);

	for (i = 0; (*msgs != NULL) && (i < MAX_MSGS); i++, msgs++) {
		log_printf(*msgs, 0);
	}
}



/*
 * disp_keysw_and_leds
 *
 * This routine displays the position of the keyswitch and the front panel
 * system LEDs. The keyswitch can be in either normal, diagnostic, or
 * secure position. The three front panel LEDs are of importance because
 * the center LED indicates component failure on the system.
 */
static int
disp_keysw_and_leds(struct system_kstat_data *kstats)
{
	int board;
	int diag_mode = 0;
	int secure_mode = 0;
	int result = 0;

	/* Check the first valid board to determeine the diag bit */
	/* Find the first valid board */
	for (board = 0; board < MAX_BOARDS; board++) {
		if (kstats->bd_ksp_list[board].fhc_kstats_ok != 0) {
			/* If this was successful, break out of loop */
			if ((kstats->bd_ksp_list[board].fhc_bsr &
			    FHC_DIAG_MODE) == 0)
				diag_mode = 1;
			break;
		}
	}

	/*
	 * Check the register on the clock-board to determine the
	 * secure bit.
	 */
	if (kstats->sys_kstats_ok) {
		/* The secure bit is negative logic. */
		if (kstats->keysw_status == KEY_SECURE) {
			secure_mode = 1;
		}
	}

	/*
	 * The system cannot be in diag and secure mode. This is
	 * illegal.
	 */
	if (secure_mode && diag_mode) {
		result = 2;
		return (result);
	}

	/* Now print the keyswitch position. */
	log_printf("Keyswitch position is in ", 0);

	if (diag_mode) {
		log_printf("Diagnostic Mode\n");
	} else if (secure_mode) {
		log_printf("Secure Mode\n", 0);
	} else {
		log_printf("Normal Mode\n");
	}

	/* display the redundant power status */
	if (kstats->sys_kstats_ok) {
		log_printf("System Power Status: ", 0);

		switch (kstats->power_state) {
		case REDUNDANT:
			log_printf("Redundant\n", 0);
			break;

		case MINIMUM:
			log_printf("Minimum Available\n", 0);
			break;

		case BELOW_MINIMUM:
			log_printf("Insufficient Power Available\n", 0);
			break;

		default:
			log_printf("Unknown\n", 0);
			break;
		}
	}

	if (kstats->sys_kstats_ok) {
		/*
		 * If the center LED is on, then we return a non-zero
		 * result.
		 */
		log_printf("System LED Status:    GREEN     YELLOW     "
			"GREEN\n", 0);
		if ((kstats->sysctrl & SYS_LED_MID) != 0) {
			log_printf("WARNING                ", 0);
		} else {
			log_printf("Normal                 ", 0);
		}

		/*
		 * Left LED is negative logic, center and right LEDs
		 * are positive logic.
		 */
		if ((kstats->sysctrl & SYS_LED_LEFT) == 0) {
			log_printf("ON ", 0);
		} else {
			log_printf("OFF", 0);
		}

		log_printf("       ", 0);
		if ((kstats->sysctrl & SYS_LED_MID) != 0) {
			log_printf("ON ", 0);
		} else {
			log_printf("OFF", 0);
		}

		log_printf("       BLINKING", 0);
	}

	log_printf("\n", 0);
	return (result);
}

/*
 * disp_env_status
 *
 * This routine displays the environmental status passed up from
 * device drivers via kstats. The kstat names are defined in
 * kernel header files included by this module.
 */
static int
disp_env_status(struct system_kstat_data *kstats)
{
	struct bd_kstat_data *bksp;
	int exit_code = 0;
	int i;
	uchar_t curr_temp;
	int is4slot = 0;

	/*
	 * Define some message arrays to make life simpler.  These
	 * messages correspond to definitions in <sys/fhc.c> for
	 * temperature trend (enum temp_trend) and temperature state
	 * (enum temp_state).
	 */
	static char *temp_trend_msg[] = {	"unknown",
						"rapidly falling",
						"falling",
						"stable",
						"rising",
						"rapidly rising",
						"unknown (noisy)"
					};
	static char *temp_state_msg[] = {	"   OK    ",
						"WARNING  ",
						" DANGER  "
					};

	log_printf("\n", 0);
	log_printf("=========================", 0);
	log_printf(dgettext(TEXT_DOMAIN, " Environmental Status "), 0);
	log_printf("=========================", 0);
	log_printf("\n", 0);

	exit_code = disp_keysw_and_leds(kstats);

	if (!kstats->sys_kstats_ok) {
		log_printf(dgettext(TEXT_DOMAIN,
			"*** Error: Unavailable ***\n\n"));
		return (1);
	}

	/*
	 * for purposes within this routine,
	 * 5 slot behaves the same as a 4 slot
	 */
	if (SYS_TYPE(kstats->sysstat1) == SYS_4_SLOT)
		is4slot = 1;

	log_printf("\n", 0);
	log_printf("\nFans:\n", 0);
	log_printf("-----\n", 0);

	log_printf("Unit   Status\n", 0);
	log_printf("----   ------\n", 0);

	log_printf("%-4s    ", is4slot ? "Disk" : "Rack", 0);
	/* Check the status of the Rack Fans */
	if ((kstats->fan_status & SYS_RACK_FANFAIL) == 0) {
		log_printf("OK\n", 0);
	} else {
		log_printf("FAIL\n", 0);
		exit_code = 1;
	}

	if (!is4slot) {
		/*
		 * keyswitch and ac box are on 8 & 16 slot only
		 */
		/* Check the status of the Keyswitch Fan assembly. */
		log_printf("%-4s    ", "Key", 0);
		if ((kstats->fan_status & SYS_KEYSW_FAN_OK) != 0) {
			log_printf("OK\n", 0);
		} else {
			log_printf("FAIL\n", 0);
			exit_code = 1;
		}

		log_printf("%-4s    ", "AC", 0);
		if ((kstats->fan_status & SYS_AC_FAN_OK) != 0) {
			log_printf("OK\n", 0);
		} else {
			log_printf("FAIL\n", 0);
			exit_code = 1;
		}
	} else {
		/*
		 * peripheral fan is on 4 slot only
		 * XXX might want to indicate transient states too
		 */
		if (kstats->psstat_kstat_ok) {
			if (kstats->ps_shadow[SYS_P_FAN_INDEX] == PS_OK) {
				log_printf("PPS     OK\n", 0);
			} else if (kstats->ps_shadow[SYS_P_FAN_INDEX] ==
			    PS_FAIL) {
				log_printf("PPS     FAIL\n", 0);
				exit_code = 1;
			}
		}
	}

	log_printf("\n", 0);


	log_printf("System Temperatures (Celsius):\n", 0);
	log_printf("------------------------------\n", 0);
	log_printf("Brd   State   Current  Min  Max  Trend\n", 0);
	log_printf("---  -------  -------  ---  ---  -----\n", 0);

	for (i = 0, bksp = &kstats->bd_ksp_list[0]; i < MAX_BOARDS;
	    i++, bksp++) {

		/* Make sure we have kstats for this board first */
		if (!bksp->temp_kstat_ok) {
			continue;
		}
		log_printf("%2d   ", i, 0);

		/* Print the current state of the temperature */
		log_printf("%s", temp_state_msg[bksp->tempstat.state], 0);
		/* Set exit code for WARNING and DANGER */
		if (bksp->tempstat.state != 0)
			exit_code = 1;

		/* Print the current temperature */
		curr_temp = bksp->tempstat.l1[bksp->tempstat.index % L1_SZ];
		log_printf("   %2d    ", curr_temp, 0);

		/* Print the minimum recorded temperature */
		log_printf(" %2d  ", bksp->tempstat.min, 0);

		/* Print the maximum recorded temperature */
		log_printf(" %2d  ", bksp->tempstat.max, 0);

		/* Print the current trend in temperature (if available) */
		if (bksp->tempstat.version < 2)
		    log_printf("unknown\n", 0);
		else
		    log_printf("%s\n", temp_trend_msg[bksp->tempstat.trend], 0);
	}
	if (kstats->temp_kstat_ok) {
		log_printf("CLK  ", 0);

		/* Print the current state of the temperature */
		log_printf("%s", temp_state_msg[kstats->tempstat.state], 0);
		/* Set exit code for WARNING or DANGER */
		if (kstats->tempstat.state != 0)
			exit_code = 1;

		/* Print the current temperature */
		curr_temp = kstats->tempstat.l1[kstats->tempstat.index % L1_SZ];
		log_printf("   %2d    ", curr_temp, 0);

		/* Print the minimum recorded temperature */
		log_printf(" %2d  ", kstats->tempstat.min, 0);

		/* Print the maximum recorded temperature */
		log_printf(" %2d  ", kstats->tempstat.max, 0);

		/* Print the current trend in temperature (if available) */
		if (kstats->tempstat.version < 2)
			log_printf("unknown\n\n", 0);
		else
			log_printf("%s\n\n",
				temp_trend_msg[kstats->tempstat.trend], 0);
	} else {
		log_printf("\n");
	}

	log_printf("\n", 0);
	log_printf("Power Supplies:\n", 0);
	log_printf("---------------\n", 0);
	log_printf("Supply                        Status\n", 0);
	log_printf("---------                     ------\n", 0);
	if (kstats->psstat_kstat_ok) {
		for (i = 0; i < SYS_PS_COUNT; i++) {
			char *ps, *state;

			/* skip core power supplies that are not present */
			if (i <= SYS_PPS0_INDEX && kstats->ps_shadow[i] ==
			    PS_OUT)
				continue;

			/* Display the unit Number */
			switch (i) {
			case 0: ps = "0"; break;
			case 1: ps = "1"; break;
			case 2: ps = "2"; break;
			case 3: ps = "3"; break;
			case 4: ps = "4"; break;
			case 5: ps = "5"; break;
			case 6: ps = "6"; break;
			case 7: ps = is4slot ? "2nd PPS" : "7"; break;

			case SYS_PPS0_INDEX: ps = "PPS"; break;
			case SYS_CLK_33_INDEX: ps = "    System 3.3v"; break;
			case SYS_CLK_50_INDEX: ps = "    System 5.0v"; break;
			case SYS_V5_P_INDEX: ps = "    Peripheral 5.0v"; break;
			case SYS_V12_P_INDEX: ps = "    Peripheral 12v"; break;
			case SYS_V5_AUX_INDEX: ps = "    Auxiliary 5.0v"; break;
			case SYS_V5_P_PCH_INDEX: ps =
				"    Peripheral 5.0v precharge";
				break;
			case SYS_V12_P_PCH_INDEX: ps =
				"    Peripheral 12v precharge";
				break;
			case SYS_V3_PCH_INDEX: ps =
				"    System 3.3v precharge"; break;
			case SYS_V5_PCH_INDEX: ps =
				"    System 5.0v precharge"; break;

			/* skip the peripheral fan here */
			case SYS_P_FAN_INDEX:
				continue;
			}

			/* what is the state? */
			switch (kstats->ps_shadow[i]) {
			case PS_OK:
				state = "OK";
				break;

			case PS_FAIL:
				state = "FAIL";
				exit_code = 1;
				break;

			/* XXX is this an exit_code condition? */
			case PS_OUT:
				state = "PPS Out";
				exit_code = 1;
				break;

			case PS_UNKNOWN:
				state = "Unknown";
				break;

			default:
				state = "Illegal State";
				break;
			}

			log_printf("%-32s %s\n", ps, state, 0);
		}
	}

	/* Check status of the system AC Power Source */
	log_printf("%-32s ", "AC Power", 0);
	if ((kstats->sysstat2 & SYS_AC_FAIL) == 0) {
		log_printf("OK\n", 0);
	} else {
		log_printf("failed\n", 0);
		exit_code = 1;
	}
	log_printf("\n", 0);

	return (exit_code);
}


/*
 * Many of the ASICs present in fusion machines have implementation and
 * version numbers stored in the OBP device tree. These codes are displayed
 * in this routine in an effort to aid Engineering and Field service
 * in detecting old ASICs which may have bugs in them.
 */
static void
sunfire_disp_asic_revs(Sys_tree *tree, struct system_kstat_data *kstats)
{
	Board_node *bnode;
	Prom_node *pnode;
	int isplusbrd;
	char *board_str[] = {   "Uninitialized", "Unknown", "CPU",
				"Memory", "Dual-SBus", "UPA-SBus",
				"Dual-PCI", "Disk", "Clock",
				"Dual-SBus-SOC+", "UPA-SBus-SOC+"};

	/* Print the header */
	log_printf("\n", 0);
	log_printf("=========================", 0);
	log_printf(" HW Revisions ", 0);
	log_printf("=========================", 0);
	log_printf("\n", 0);
	log_printf("\n", 0);

	/* Else this is a Sunfire or campfire */
	log_printf("ASIC Revisions:\n", 0);
	log_printf("---------------\n", 0);

	/* Display Firetruck ASIC Revisions first */
	log_printf("Brd  FHC  AC  SBus0  SBus1  PCI0  PCI1  FEPS", 0);
	log_printf("  Board Type      Attributes", 0);
	log_printf("\n", 0);
	log_printf("---  ---  --  -----  -----  ----  ----  ----", 0);
	log_printf("  ----------      ----------", 0);
	log_printf("\n", 0);

	/*
	 * Display all of the FHC, AC, and chip revisions for the entire
	 * machine. The AC anf FHC chip revs are available  from the device
	 * tree that was read out of the PROM, but the DC chip revs will be
	 * read via a kstat. The interfaces for this are not completely
	 * available at this time.
	 */
	bnode = tree->bd_list;
	while (bnode != NULL) {
		int *version;
		int upa = bd_to_upa(bnode->board_num);

		/* Display the header with the board number */
		log_printf("%2d   ", bnode->board_num, 0);

		/* display the FHC version */
		if ((pnode = dev_find_node(bnode->nodes, "fhc")) == NULL) {
			log_printf("     ", 0);
		} else {
			if ((version = (int *)get_prop_val(find_prop(pnode,
			    "version#"))) == NULL) {
				log_printf("     ", 0);
			} else {
				log_printf(" %d   ", *version, 0);
			}
		}

		/* display the AC version */
		if ((pnode = dev_find_node(bnode->nodes, "ac")) == NULL) {
			log_printf("    ", 0);
		} else {
			if ((version = (int *)get_prop_val(find_prop(pnode,
			    "version#"))) == NULL) {
				log_printf("    ", 0);
			} else {
				log_printf(" %d  ", *version, 0);
			}
		}

		/* Find sysio 0 on board and print rev */
		if ((pnode = find_device(bnode, upa, "sbus")) == NULL) {
			log_printf("       ", 0);
		} else {
			if ((version = (int *)get_prop_val(find_prop(pnode,
			    "version#"))) == NULL) {
				log_printf("       ", 0);
			} else {
				log_printf("  %d    ", *version, 0);
			}
		}

		/* Find sysio 1 on board and print rev */
		if ((pnode = find_device(bnode, upa+1, "sbus")) == NULL) {
			log_printf("       ", 0);
		} else {
			if ((version = (int *)get_prop_val(find_prop(pnode,
			    "version#"))) == NULL) {
				log_printf("       ", 0);
			} else {
				log_printf("  %d    ", *version, 0);
			}
		}

		/* Find Psycho 0 on board and print rev */
		if ((pnode = find_device(bnode, upa, "pci")) == NULL) {
			log_printf("      ", 0);
		} else {
			if ((version = (int *)get_prop_val(find_prop(pnode,
			    "version#"))) == NULL) {
				log_printf("      ", 0);
			} else {
				log_printf(" %d    ", *version, 0);
			}
		}

		/* Find Psycho 1 on board and print rev */
		if ((pnode = find_device(bnode, upa+1, "pci")) == NULL) {
			log_printf("      ", 0);
		} else {
			if ((version = (int *)get_prop_val(find_prop(pnode,
			    "version#"))) == NULL) {
				log_printf("      ", 0);
			} else {
				log_printf(" %d    ", *version, 0);
			}
		}

		/* Find the FEPS on board and print rev */
		if ((pnode = dev_find_node(bnode->nodes, "SUNW,hme")) != NULL) {
			if ((version = (int *)get_prop_val(find_prop(pnode,
			    "hm-rev"))) != NULL) {
				if (*version == 0xa0) {
					log_printf(" 2.0  ", 0);
				} else if (*version == 0x20) {
					log_printf(" 2.1  ", 0);
				} else {
					log_printf(" %2x   ", *version, 0);
				}
			}
		} else
			log_printf("      ", 0);

		/* print out the board type */
		isplusbrd = ISPLUSBRD(kstats->bd_ksp_list
				[bnode->board_num].fhc_bsr);

		log_printf("%-16s", board_str[bnode->board_type], 0);
		if (isplusbrd)
			log_printf("100MHz Capable", 0);
		else
			log_printf("84MHz Capable", 0);

		log_printf("\n", 0);
		bnode = bnode->next;
	}
	log_printf("\n", 0);

	/* Now display the FFB board component revisions */
	for (bnode = tree->bd_list; bnode != NULL; bnode = bnode->next) {
		display_ffb(bnode, 0);
	}
}

static void
display_hp_boards(struct system_kstat_data *kstats)
{
	int i;
	int j;
	int hp_found = 0;
	struct hp_info *hp;
	char *state;

	for (i = 0, hp = &kstats->hp_info[0]; i < MAX_BOARDS; i++, hp++) {
		if (!hp->kstat_ok) {
			continue;
		}

		hp_found = 1;
	}

	/* return if there are no hotplug boards in the system. */
	if (!hp_found) {
		return;
	}

	if (hp_found != 0) {
		log_printf("\n", 0);
		log_printf("Detached Boards\n", 0);
		log_printf("===============\n", 0);
		log_printf("  Slot  State       Type           Info\n", 0);
		log_printf("  ----  ---------   ------         ----"
			"-------------------------------------\n", 0);
	}

	/* Display all detached boards */
	for (i = 0, hp = &kstats->hp_info[0]; i < MAX_BOARDS; i++, hp++) {
		struct cpu_info *cpu;

		if (hp->kstat_ok == 0) {
			continue;
		}


		switch (hp->bd_info.state) {
		case UNKNOWN_STATE:
			state = "unknown";
			break;

		case ACTIVE_STATE:
			state = "active";
			break;

		case LOWPOWER_STATE:
			state = "low-power";
			break;

		case HOTPLUG_STATE:
			state = "hot-plug";
			break;

		case DISABLED_STATE:
			state = "disabled";
			break;

		case FAILED_STATE:
			state = "failed";
			break;

		default:
			state = "unknown";
			break;
		}

		log_printf("   %2d   %9s   ", i, state, 0);

		switch (hp->bd_info.type) {
		case MEM_BOARD:
			log_printf("%-14s ", MEM_BD_NAME, 0);
			break;

		case CPU_BOARD:
			log_printf("%-14s ", CPU_BD_NAME, 0);

			/* Cannot display CPU info for disabled boards */
			if ((hp->bd_info.state == DISABLED_STATE) ||
			    (hp->bd_info.state == FAILED_STATE)) {
				break;
			}

			/* Display both CPUs if present */
			cpu = &hp->bd_info.bd.cpu[0];
			for (j = 0; j < 2; j++, cpu++) {
				log_printf("CPU %d: ", j, 0);
				/* Print the rated speed of the CPU. */
				if (cpu->cpu_speed > 1) {
					log_printf("%3d MHz", cpu->cpu_speed,
						0);
				} else {
					log_printf("no CPU       ", 0);
					continue;
				}

				/* Display the size of the cache */
				if (cpu->cache_size != 0) {
					log_printf(" %0.1fM ",
						(float)cpu->cache_size /
						(float)(1024*1024), 0);
				} else {
					log_printf("    ", 0);
				}
			}
			break;

		case IO_2SBUS_BOARD:
			log_printf("%-14s ", IO_2SBUS_BD_NAME, 0);
			break;

		case IO_2SBUS_SOCPLUS_BOARD:
			log_printf("%-14s ", IO_2SBUS_SOCPLUS_BD_NAME, 0);
			break;

		case IO_SBUS_FFB_BOARD:
			log_printf("%-14s ", IO_SBUS_FFB_BD_NAME, 0);
			switch (hp->bd_info.bd.io2.ffb_size) {
			case FFB_SINGLE:
				log_printf("Single buffered FFB", 0);
				break;

			case FFB_DOUBLE:
				log_printf("Double buffered FFB", 0);
				break;

			case FFB_NOT_FOUND:
				log_printf("No FFB installed", 0);
				break;

			default:
				log_printf("Illegal FFB size", 0);
				break;
			}
			break;

		case IO_SBUS_FFB_SOCPLUS_BOARD:
			log_printf("%-14s ", IO_SBUS_FFB_SOCPLUS_BD_NAME, 0);
			switch (hp->bd_info.bd.io2.ffb_size) {
			case FFB_SINGLE:
				log_printf("Single buffered FFB", 0);
				break;

			case FFB_DOUBLE:
				log_printf("Double buffered FFB", 0);
				break;

			case FFB_NOT_FOUND:
				log_printf("No FFB installed", 0);
				break;

			default:
				log_printf("Illegal FFB size", 0);
				break;
			}
			break;

		case IO_PCI_BOARD:
			log_printf("%-14s ", IO_PCI_BD_NAME, 0);
			break;

		case DISK_BOARD:
			log_printf("%-14s ", "disk", 0);
			for (j = 0; j < 2; j++) {
				log_printf("Disk %d:", j, 0);
				if (hp->bd_info.bd.dsk.disk_pres[j]) {
					log_printf(" Target: %2d   ",
						hp->bd_info.bd.dsk.disk_id[j],
						0);
				} else {
					log_printf(" no disk      ", 0);
				}
			}
			break;

		case UNKNOWN_BOARD:
		case UNINIT_BOARD:
		default:
			log_printf("UNKNOWN ", 0);
			break;
		}
		log_printf("\n");
	}
}

/*
 * Analysis functions:
 *
 * Most of the Fatal error data analyzed from error registers is not
 * very complicated. This is because the FRUs for errors detected by
 * most parts is either a CPU module, a FFB, or the system board
 * itself.
 * The analysis of the Address Controller errors is the most complicated.
 * These errors can be caused by other boards as well as the local board.
 */

/*
 * analyze_cpu
 *
 * Analyze the CPU MFSR passed in and determine what type of fatal
 * hardware errors occurred at the time of the crash. This function
 * returns a pointer to a string to the calling routine.
 */
static int
analyze_cpu(char **msgs, int cpu_id, u_longlong_t afsr)
{
	int count = 0;
	int i;
	int syndrome;
	char msgbuf[MAXSTRLEN];

	if (msgs == NULL) {
		return (count);
	}

	if (afsr & P_AFSR_ETP) {
		(void) sprintf(msgbuf, "CPU %d Ecache Tag Parity Error, ",
			cpu_id);

		/* extract syndrome for afsr */
		syndrome = (afsr & P_AFSR_ETS) >> ETS_SHIFT;

		/* now concat the parity syndrome msg */
		for (i = 0; i < 4; i++) {
			if ((0x1 << i)  & syndrome) {
				(void) strcat(msgbuf, ecache_parity[i]);
			}
		}
		(void) strcat(msgbuf, "\n");
		*msgs++ = strdup(msgbuf);
		count++;
	}

	if (afsr & P_AFSR_ISAP) {
		(void) sprintf(msgbuf,
			"CPU %d Incoming System Address Parity Error\n",
			cpu_id);
		*msgs++ = strdup(msgbuf);
		count++;
	}

	return (count);
}

/*
 * analyze_ac
 *
 * This function checks the AC error register passed in and checks
 * for any errors that occured during the fatal hardware reset.
 */
static int
analyze_ac(char **msgs, u_longlong_t ac_error)
{
	int i;
	int count = 0;
	char msgbuf[MAXSTRLEN];
	int tmp_cnt;

	if (msgs == NULL) {
		return (count);
	}

	for (i = 2; i < MAX_BITS; i++) {
		if ((((u_longlong_t)0x1 << i) & ac_error) != 0) {
			if (ac_errors[i].error != NULL) {
				(void) sprintf(msgbuf, "AC: %s\n",
					ac_errors[i].error);
				*msgs++ = strdup(msgbuf);
				count++;

				/* display the part that might cause this */
				tmp_cnt = disp_parts(msgs, ac_error, i);
				count += tmp_cnt;
				msgs += tmp_cnt;
			}
		}
	}

	return (count);
}

/*
 * analyze_dc
 *
 * This routine checks the DC shdow chain and tries to determine
 * what type of error might have caused the fatal hardware reset
 * error.
 */
static int
analyze_dc(int board, char **msgs, u_longlong_t dc_error)
{
	int i;
	int count = 0;
	char msgbuf[MAXSTRLEN];

	if (msgs == NULL) {
		return (count);
	}

	/*
	 * The DC scan data is contained in 8 bytes, one byte per
	 * DC. There are 8 DCs on a system board.
	 */

	for (i = 0; i < 8; i++) {
		if (dc_error & DC_OVERFLOW) {
			(void) sprintf(msgbuf, dc_overflow_txt, board, i);
			*msgs++ = strdup(msgbuf);
			count++;
		}

		if (dc_error & DC_PARITY) {
			(void) sprintf(msgbuf, dc_parity_txt, board, i);
			*msgs++ = strdup(msgbuf);
			count++;
		}
		dc_error = dc_error >> 8;	/* shift over to next byte */
	}

	return (count);
}

static int
disp_parts(char **msgs, u_longlong_t ac_error, int type)
{
	int count = 0;
	int part;
	char msgbuf[MAXSTRLEN];
	int i;

	if (msgs == NULL) {
		return (count);
	}

	(void) sprintf(msgbuf, "\tThe error could be caused by:\n");
	*msgs++ = strdup(msgbuf);
	count++;

	for (i = 0; (i < MAX_FRUS) && ac_errors[type].part[i]; i++) {
		part = ac_errors[type].part[i];

		if (part == UPA_PART) {
			if (ac_error & UPA_PORT_A) {
				part = UPA_A_PART;
			} else if (ac_error & UPA_PORT_B) {
				part = UPA_B_PART;
			}
		}

		if (part == DTAG_PART) {
			if (ac_error & UPA_PORT_A) {
				part = DTAG_A_PART;
			} else if (ac_error & UPA_PORT_B) {
				part = DTAG_B_PART;
			}
		}

		(void) sprintf(msgbuf, "\t\t%s\n", part_str[part]);

		*msgs++ = strdup(msgbuf);
		count++;
	}

	return (count);
}
