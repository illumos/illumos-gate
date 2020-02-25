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
 * Copyright (c) 2020 Peter Tribble.
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
#include <sys/sbd_ioctl.h>
#include <sys/sbdp_mem.h>
#include <sys/serengeti.h>
#include <sys/mc.h>
#include "pdevinfo.h"
#include "display.h"
#include "pdevinfo_sun4u.h"
#include "display_sun4u.h"
#include "libprtdiag.h"

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

#define	KBYTE	1024
#define	MBYTE	(KBYTE * KBYTE)

#define	MEM_UK_SIZE_MASK	0x3FF

/*
 * Global variables.
 */
static memory_bank_t	*bank_head;
static memory_bank_t	*bank_tail;
static memory_seg_t	*seg_head;

/*
 * Local functions.
 */
static void add_bank_node(uint64_t mc_decode, int portid, char *bank_status);
static void add_seg_node(void);
static memory_seg_t *match_seg(uint64_t);


/*
 * Used for US-I and US-II systems
 */
/*ARGSUSED0*/
void
display_memorysize(Sys_tree *tree, struct system_kstat_data *kstats,
	struct mem_total *memory_total)
{
	log_printf(dgettext(TEXT_DOMAIN, "Memory size: "), 0);

	if (sysconf(_SC_PAGESIZE) == -1 || sysconf(_SC_PHYS_PAGES) == -1)
		log_printf(dgettext(TEXT_DOMAIN, "unable to determine\n"), 0);
	else {
		uint64_t	mem_size;

		mem_size =
		    (uint64_t)sysconf(_SC_PAGESIZE) * \
			(uint64_t)sysconf(_SC_PHYS_PAGES);

		if (mem_size >= MBYTE)
			log_printf(dgettext(TEXT_DOMAIN, "%d Megabytes\n"),
				(int)((mem_size+MBYTE-1) / MBYTE), 0);
		else
			log_printf(dgettext(TEXT_DOMAIN, "%d Kilobytes\n"),
				(int)((mem_size+KBYTE-1) / KBYTE), 0);
	}
}

/*ARGSUSED0*/
void
display_memoryconf(Sys_tree *tree)
{
	/*
	 * This function is intentionally blank
	 */
}

/*
 * The following functions are for use by any US-III based systems.
 * All they need to do is to call get_us3_mem_regs()
 * and then display_us3_banks(). Each platform then needs to decide how
 * to format this data by over-riding the generic function
 * print_us3_memory_line().
 */
int
get_us3_mem_regs(Board_node *bnode)
{
	Prom_node	*pnode;
	int		portid;
	uint64_t	*ma_reg_arr;
	uint64_t	madr[NUM_MBANKS_PER_MC];
	void		*bank_status_array;
	char		*bank_status;
	int		i, status_offset;

	for (pnode = dev_find_node(bnode->nodes, "memory-controller");
		pnode != NULL;
		pnode = dev_next_node(pnode, "memory-controller")) {

		/* Get portid of this mc from libdevinfo. */
		portid = (*(int *)get_prop_val(find_prop(pnode, "portid")));

		/* read the logical_bank_ma_regs property for this mc node. */
		ma_reg_arr = (uint64_t *)get_prop_val(
				find_prop(pnode, MEM_CFG_PROP_NAME));

		/*
		 * There are situations where a memory-controller node
		 * will not have the logical_bank_ma_regs property and
		 * we need to allow for these cases. They include:
		 *	- Excalibur/Littleneck systems that only
		 *	  support memory on one of their CPUs.
		 *	- Systems that support DR where a cpu board
		 *	  can be unconfigured but still connected.
		 * It is up to the caller of this function to ensure
		 * that the bank_head and seg_head pointers are not
		 * NULL after processing all memory-controllers in the
		 * system. This would indicate a situation where no
		 * memory-controllers in the system have a logical_bank_ma_regs
		 * property which should never happen.
		 */
		if (ma_reg_arr == NULL)
			continue;

		/*
		 * The first NUM_MBANKS_PER_MC of uint64_t's in the
		 * logical_bank_ma_regs property are the madr values.
		 */
		for (i = 0; i < NUM_MBANKS_PER_MC; i++) {
			madr[i] = *ma_reg_arr++;
		}

		/*
		 * Get the bank_status property for this mem controller from
		 * OBP. This contains the bank-status for each logical bank.
		 */
		bank_status_array = (void *)get_prop_val(
				find_prop(pnode, "bank-status"));
		status_offset = 0;

		/*
		 * process each logical bank
		 */
		for (i = 0; i < NUM_MBANKS_PER_MC; i++) {
			/*
			 * Get the bank-status string for this bank
			 * from the bank_status_array we just retrieved
			 * from OBP. If the prop was not found, we
			 * malloc a bank_status and set it to "no_status".
			 */
			if (bank_status_array) {
				bank_status = ((char *)bank_status_array +
				    status_offset);

				/* Move offset to next bank_status string */
				status_offset += (strlen(bank_status) + 1);
			} else {
				bank_status = malloc(strlen("no_status"));
				strcpy(bank_status, "no_status");
			}

			/*
			 * create a bank_node for this bank
			 * and add it to the list.
			 */
			add_bank_node(madr[i], portid, bank_status);

			/*
			 * find the segment to which this bank
			 * belongs. If it doesn't already exist
			 * then create it. If it exists, add to it.
			 */
			add_seg_node();
		}
	}
	return (0);
}

static void
add_bank_node(uint64_t mc_decode, int portid, char *bank_status)
{
	static int	id = 0;
	memory_bank_t	*new, *bank;
	uint32_t	ifactor = MC_INTLV(mc_decode);
	uint64_t	seg_size;

	if ((new = malloc(sizeof (memory_bank_t))) == NULL) {
		perror("malloc");
		exit(1);
	}

	new->portid = portid;
	new->id = id++;
	new->valid = (mc_decode >> 63);
	new->uk = MC_UK(mc_decode);
	new->um = MC_UM(mc_decode);
	new->lk = MC_LK(mc_decode);
	new->lm = MC_LM(mc_decode);

	seg_size = ((((uint64_t)new->uk & MEM_UK_SIZE_MASK) + 1) << 26);
	new->bank_size = seg_size / ifactor;
	new->bank_status = bank_status;

	new->next = NULL;
	new->seg_next = NULL;

	/* Handle the first bank found */
	if (bank_head == NULL) {
		bank_head = new;
		bank_tail = new;
		return;
	}

	/* find last bank in list */
	bank = bank_head;
	while (bank->next)
		bank = bank->next;

	/* insert this bank into the list */
	bank->next = new;
	bank_tail = new;
}

void
display_us3_banks(void)
{
	uint64_t	base, bank_size;
	uint32_t	intlv;
	memory_bank_t	*bank, *tmp_bank;
	memory_seg_t	*seg;
	int		 mcid;
	uint64_t	dimm_size;
	uint64_t	total_bank_size = 0;
	uint64_t	total_sys_mem;
	static uint64_t	bank0_size, bank1_size, bank2_size, bank3_size;

	if ((bank_head == NULL) || (seg_head == NULL)) {
		log_printf("\nCannot find any memory bank/segment info.\n");
		return;
	}

	for (bank = bank_head; bank; bank = bank->next) {
		/*
		 * Interleave factor is determined from the
		 * lk bits in the Mem Addr Decode register.
		 *
		 * The Base Address of the memory segment in which this
		 * bank belongs is determined from the um abd uk bits
		 * of the Mem Addr Decode register.
		 *
		 * See section 9.1.5 of Cheetah Programmer's reference
		 * manual.
		 */
		intlv 		= ((bank->lk ^ 0xF) + 1);
		base 		= bank->um & ~(bank->uk);

		mcid 		= SG_PORTID_TO_SAFARI_ID(bank->portid);

		/* If bank is not valid, set size to zero incase it's garbage */
		if (bank->valid)
			bank_size = ((bank->bank_size) / MBYTE);
		else
			bank_size = 0;

		/*
		 * Keep track of all banks found so we can check later
		 * that this value matches the total memory in the
		 * system using the pagesize and number of pages.
		 */
		total_bank_size	+= bank_size;

		/* Find the matching segment for this bank. */
		seg = match_seg(base);

		/*
		 * Find the Dimm size by adding banks 0 + 2 and divide by 4
		 * and then adding banks 1 + 3 and divide by 4. We divide
		 * by 2 if one of the logical banks size is zero.
		 */
		switch ((bank->id) % 4) {
		case 0:
			/* have bank0_size, need bank2_size */
			bank0_size = bank_size;
			bank2_size = 0;

			tmp_bank = bank->next;
			while (tmp_bank) {
				if (tmp_bank->valid == 0) {
					tmp_bank = tmp_bank->next;
					continue;
				}
				/* Is next bank on the same mc ? */
				if (mcid != SG_PORTID_TO_SAFARI_ID(
				    tmp_bank->portid)) {
					break;
				}
				if ((tmp_bank->id) % 4 == 2) {
					bank2_size =
					    (tmp_bank->bank_size / MBYTE);
					break;
				}
				tmp_bank = tmp_bank->next;
			}
			if (bank2_size)
				dimm_size = (bank0_size + bank2_size) / 4;
			else
				dimm_size = bank0_size / 2;
			break;
		case 1:
			/* have bank1_size, need bank3_size */
			bank1_size = bank_size;
			bank3_size = 0;

			tmp_bank = bank->next;
			while (tmp_bank) {
				if (tmp_bank->valid == 0) {
					tmp_bank = tmp_bank->next;
					continue;
				}
				/* Is next bank on the same mc ? */
				if (mcid != SG_PORTID_TO_SAFARI_ID(
				    tmp_bank->portid)) {
					break;
				}
				if ((tmp_bank->id) % 4 == 3) {
					bank3_size =
					    (tmp_bank->bank_size / MBYTE);
					break;
				}
				tmp_bank = tmp_bank->next;
			}
			if (bank3_size)
				dimm_size = (bank1_size + bank3_size) / 4;
			else
				dimm_size = bank1_size / 2;
			break;
		case 2:
			/* have bank0_size and bank2_size */
			bank2_size = bank_size;
			if (bank0_size)
				dimm_size = (bank0_size + bank2_size) / 4;
			else
				dimm_size = bank2_size / 2;
			break;
		case 3:
			/* have bank1_size and bank3_size */
			bank3_size = bank_size;
			if (bank1_size)
				dimm_size = (bank1_size + bank3_size) / 4;
			else
				dimm_size = bank3_size / 4;
			break;
		}

		if (bank->valid == 0)
			continue;

		/*
		 * Call platform specific code for formatting memory
		 * information.
		 */
		print_us3_memory_line(bank->portid, bank->id, bank_size,
		    bank->bank_status, dimm_size, intlv, seg->id);
	}

	printf("\n");

	/*
	 * Sanity check to ensure that the total amount of system
	 * memory matches the total number of memory banks that
	 * we find here. Scream if there is a mis-match.
	 */
	total_sys_mem = (((uint64_t)sysconf(_SC_PAGESIZE) * \
		(uint64_t)sysconf(_SC_PHYS_PAGES)) / MBYTE);

	if (total_bank_size != total_sys_mem) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "\nError: total bank size [%lldMB] does not match total "
			"system memory [%lldMB]\n"), total_bank_size,
				total_sys_mem, 0);
	}

}

static void
add_seg_node(void)
{
	uint64_t	base;
	memory_seg_t	*new;
	static int	id = 0;
	memory_bank_t	*bank = bank_tail;

	if (bank->valid != 1)
		return;

	base = bank->um & ~(bank->uk);

	if ((new = match_seg(base)) == NULL) {
		/*
		 * This bank is part of a new segment, so create
		 * a struct for it and added to the list of segments
		 */
		if ((new = malloc(sizeof (memory_seg_t))) == NULL) {
			perror("malloc");
			exit(1);
		}
		new->id = id++;
		new->base = base;
		new->size = (((uint64_t)bank->uk +1) << 26);
		new->intlv = ((bank->lk ^ 0xF) + 1);

		/*
		 * add to the seg list
		 */
		new->next = seg_head;
		seg_head = new;
	}

	new->nbanks++;
	/*
	 * add bank into segs bank list.  Note we add at the head
	 */
	bank->seg_next = new->banks;
	new->banks = bank;
}

static memory_seg_t *
match_seg(uint64_t base)
{
	memory_seg_t	*cur_seg;

	for (cur_seg = seg_head; cur_seg; cur_seg = cur_seg->next) {
		if (cur_seg-> base == base)
			break;
	}
	return (cur_seg);
}

/*ARGSUSED0*/
void
print_us3_memory_line(int portid, int bank_id, uint64_t bank_size,
    char *bank_status, uint64_t dimm_size, uint32_t intlv, int seg_id)
{
	log_printf(dgettext(TEXT_DOMAIN,
	    "\n No print_us3_memory_line() function specified for"
	    " this platform\n"), 0);
}

int
display_us3_failed_banks(int system_failed)
{
	memory_bank_t	*bank;
	int		found_failed_bank = 0;

	if ((bank_head == NULL) || (seg_head == NULL)) {
		log_printf("\nCannot find any memory bank/segment info.\n");
		return (1);
	}

	for (bank = bank_head; bank; bank = bank->next) {
		/*
		 * check to see if the bank is invalid and also
		 * check if the bank_status is unpopulated.  Unpopulated
		 * means the bank is empty.
		 */

		if ((bank->valid == 0) &&
		    (strcmp(bank->bank_status, "unpopulated"))) {
			if (!system_failed && !found_failed_bank) {
				found_failed_bank = TRUE;
				log_printf("\n", 0);
				log_printf(dgettext(TEXT_DOMAIN,
				"Failed Field Replaceable Units (FRU) in "
				    "System:\n"), 0);
				log_printf("=========================="
				    "====================\n", 0);
			}
			/*
			 * Call platform specific code for formatting memory
			 * information.
			 */
			print_us3_failed_memory_line(bank->portid, bank->id,
			    bank->bank_status);
		}
	}
	if (found_failed_bank)
		return (1);
	else
		return (0);
}

/*ARGSUSED0*/
void
print_us3_failed_memory_line(int portid, int bank_id, char *bank_status)
{
	log_printf(dgettext(TEXT_DOMAIN,
	    "\n No print_us3_failed_memory_line() function specified for"
	    " this platform\n"), 0);
}
