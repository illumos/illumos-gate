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
 *
 * Cherrystone platform-specific functions
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

#include <picl.h>

#include <sys/cheetahregs.h>
#include <sys/cherrystone.h>
#include "workfile.c"

#define	SCHIZO_COMPAT_PROP	"pci108e,8001"

#define	MULTIPLE_BITS_SET(x)	((x)&((x)-1))

#define	MAX_PS		2
#define	MAX_PS_SENSORS	3
#define	MAX_DISKS	2
#define	MAX_FANS	5
#define	NUM_PCI_SLOTS	5

/*
 * these functions will overlay the symbol table of libprtdiag
 * at runtime (workgroup server systems only)
 */
void	display_cpu_devices(Sys_tree *tree);
void	display_pci(Board_node *board);
void	display_io_cards(struct io_card *list);
void	display_diaginfo(int flag, Prom_node *root, Sys_tree *tree,
				struct system_kstat_data *kstats);
void	display_ffb(Board_node *board, int table);
void	display_memoryconf(Sys_tree *tree);

/* local functions */
static void disp_envc_status(void);
static int print_temps(picl_nodehdl_t);
static int print_keyswitch(picl_nodehdl_t);
static int print_FSP_LEDS(picl_nodehdl_t);
static int print_disk(picl_nodehdl_t);
static int print_fans(picl_nodehdl_t);
static int print_ps(picl_nodehdl_t);

static void display_hw_revisions(Prom_node *root,
					Board_node *bnode);
static void display_schizo_revisions(Board_node *bdlist);


void
display_cpu_devices(Sys_tree *tree)
{
	Board_node *bnode;

	log_printf(dgettext(TEXT_DOMAIN,
	    "\n========================= CPUs "
	    "===============================================\n\n"
	    "          Run   E$  CPU     CPU  \n"
	    "Brd  CPU  MHz   MB  Impl.   Mask \n"
	    "--- ----- ---- ---- ------- ---- \n"));

	bnode = tree->bd_list;
	while (bnode != NULL) {
		display_cpus(bnode);
		bnode = bnode->next;
	}

	log_printf("\n");
}
void
display_cpus(Board_node *board)
{
	Prom_node 	*cpu;
	uint_t freq;
	int ecache_size;
	int *l3_shares;
	int *mid;
	int *impl;
	int *mask;
	int *coreid;
	char fru_prev = 'X'; /* Valid frus are 'A','B' */
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
		freq = HZ_TO_MHZ(get_cpu_freq(cpu));
		ecache_size = get_ecache_size(cpu);
		impl = (int *)get_prop_val(find_prop(cpu, "implementation#"));
		mask = (int *)get_prop_val(find_prop(cpu, "mask#"));
		l3_shares =
		    (int *)get_prop_val(find_prop(cpu, "l3-cache-sharing"));

		/* Do not display a failed CPU node */
		if ((impl == NULL) || (freq == 0) || (node_failed(cpu)))
			continue;

		fru_name = CHERRYSTONE_GETSLOT_LABEL(*mid);
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

		log_printf(" %c", fru_name);

		/* CPU Module ID */
		if (CPU_IMPL_IS_CMP(*impl)) {
			log_printf("%3d,%3d ", mid_prev, *mid, 0);
		} else
			log_printf("   %2d   ", *mid);

		/* Running frequency */
		log_printf("%4u", freq);

		if (ecache_size == 0)
			log_printf(" N/A  ");
		else
			log_printf(" %4.1f ",
			    (float)ecache_size / (float)(1<<20));
			/* Implementation */
		if (impl == NULL) {
			log_printf(dgettext(TEXT_DOMAIN, "  N/A   "));
		} else {
			if (IS_CHEETAH(*impl))
				log_printf(dgettext(TEXT_DOMAIN,
				    "US-III  "));
			else if (IS_CHEETAH_PLUS(*impl))
				log_printf(dgettext(TEXT_DOMAIN,
				    "US-III+ "));
			else if (IS_JAGUAR(*impl))
				log_printf(dgettext(TEXT_DOMAIN,
				    "US-IV   "));
			else if (IS_PANTHER(*impl))
				log_printf(dgettext(TEXT_DOMAIN,
				    "US-IV+  "));
			else
				log_printf("%-6x  ", *impl);
		}

		/* CPU Mask */
		if (mask == NULL) {
			log_printf(dgettext(TEXT_DOMAIN, " N/A\n"));
		} else {
			log_printf(dgettext(TEXT_DOMAIN, " %d.%d\n"),
			    (*mask >> 4) & 0xf, *mask & 0xf);
		}
	}
}

void
display_memoryconf(Sys_tree *tree)
{
	Board_node	*bnode = tree->bd_list;

	log_printf(dgettext(TEXT_DOMAIN,
	    "========================= Memory Configuration"
	    " ===============================\n\n"
	    "          Logical  Logical  Logical\n"
	    "     MC   Bank     Bank     Bank         DIMM    "
	    "Interleave  Interleaved\n"
	    "Brd  ID   num      size     Status       Size    "
	    "Factor      with\n"
	    "---  ---  ----     ------   -----------  ------  "
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

/*ARGSUSED3*/
void
display_diaginfo(int flag, Prom_node *root, Sys_tree *tree,
	struct system_kstat_data *kstats)
{
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

		disp_envc_status();

		display_hw_revisions(root, tree->bd_list);
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
	static int	banner = FALSE;

	char		*slot_name_arr[NUM_PCI_SLOTS];
	int		i;

	if (board == NULL)
		return;

	(void) memset(&card, 0, sizeof (struct io_card));
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
			for (i = 1; i < NUM_PCI_SLOTS; i++) {
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

	if (!banner && card_list != NULL) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "                    Bus  Max\n"
		    " IO  Port Bus       Freq Bus  Dev,\n"
		    "Type  ID  Side Slot MHz  Freq Func State "
		    "Name                              Model"
#ifdef DEBUG
		    "                   Notes"
#endif
		    "\n"
		    "---- ---- ---- ---- ---- ---- ---- ----- "
		    "--------------------------------  "
#ifdef DEBUG
		    "----------------------  "
#endif
		    "----------------------\n"));
		banner = TRUE;
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
	struct io_card *p;

	for (p = list; p != NULL; p = p -> next) {
		log_printf(dgettext(TEXT_DOMAIN,
		    "%-4s  %-3d  %c    %-1s    %-3d"),
		    p->bus_type, p->schizo_portid, p->pci_bus,
		    p->slot_str, p->freq);

		switch (p->pci_bus) {
		case 'A':
			log_printf(dgettext(TEXT_DOMAIN, "  66  "));
			break;
		case 'B':
			log_printf(dgettext(TEXT_DOMAIN, "  33  "));
			break;
		default:
			assert(0);
			break;
		}

		log_printf(dgettext(TEXT_DOMAIN,
		    "%-1d,%-1d  %-5s %-32.32s"),
		    p->dev_no, p->func_no, p->status, p->name);
		if (strlen(p->name) > 32)
			log_printf(dgettext(TEXT_DOMAIN, "+ "));
		else
			log_printf(dgettext(TEXT_DOMAIN, "  "));
		log_printf(dgettext(TEXT_DOMAIN, "%-22.22s"), p->model);
		if (strlen(p->model) > 22)
			log_printf(dgettext(TEXT_DOMAIN, "+"));
#ifdef DEBUG
		log_printf("%s", p->notes);
#endif
		log_printf("\n");
	}
}

/*ARGSUSED*/
void
display_ffb(Board_node *board, int table)
{
	/* NOP, since there are no FFB's on this platform. */
}


/*
 * local functions
 */


static void
disp_envc_status()
{
	int err;
	char *system = "SYSTEM";
	picl_nodehdl_t system_node, root;

	log_printf(dgettext(TEXT_DOMAIN,
	    "\n"
	    "=========================  Environmental Status "
	    "=========================\n\n"));

	err = picl_initialize();
	if (err != PICL_SUCCESS) {
		exit_code = PD_INTERNAL_FAILURE;
		goto err_out;
	}
	err = picl_get_root(&root);
	if (err != PICL_SUCCESS) {
		exit_code = PD_INTERNAL_FAILURE;
		goto err_out;
	}
	err = find_child_device(root, system, &system_node);
	if (err != PICL_SUCCESS) {
		exit_code = PD_INTERNAL_FAILURE;
		goto err_out;
	}

	err = print_temps(system_node);
	err |= print_keyswitch(system_node);
	err |= print_FSP_LEDS(system_node);
	err |= print_disk(system_node);
	err |= print_fans(system_node);
	err |= print_ps(system_node);

	if (err != PICL_SUCCESS)
		goto err_out;

	return;

err_out:
	log_printf(dgettext(TEXT_DOMAIN,
	    "\nEnvironmental reporting error: %s\n"),
	    picl_strerror(err));
}

static int
print_ps(picl_nodehdl_t system_node)
{
	int		i, j, err = 0;
	int32_t		number;
	picl_nodehdl_t	*ps;
	picl_nodehdl_t	*ps_fail_sensor;
	char		name[PICL_PROPNAMELEN_MAX];
	char		fault_state[PICL_PROPNAMELEN_MAX];

	log_printf(dgettext(TEXT_DOMAIN, "\n\n"
	    "Power Supplies:\n"
	    "---------------\n"
	    "\n"
	    "Supply     Status        Fault     Fan Fail   Temp Fail\n"
	    "------    ------------   --------  ---------  ---------\n"));

	err = fill_device_array_from_id(system_node, "PSVC_PS", &number, &ps);
	if (err != PICL_SUCCESS) {
		return (err);
	}

	for (i = 0; i < MAX_PS; i++) {
		err = picl_get_propval_by_name(ps[i], PICL_PROP_NAME, name,
		    PICL_PROPNAMELEN_MAX);
		if (err != PICL_SUCCESS)
			continue;

		log_printf(dgettext(TEXT_DOMAIN, "%6-s"), name);
		err = picl_get_propval_by_name(ps[i], "FaultInformation",
		    fault_state, PICL_PROPNAMELEN_MAX);
		if (err != PICL_SUCCESS) {
			free(ps);
			return (err);
		}
		log_printf(dgettext(TEXT_DOMAIN, "   [%-12s]"), fault_state);
		if (strcmp(fault_state, "NO AC POWER") == 0) {
			log_printf("\n");
			continue;
		}

		err = fill_device_array_from_id(ps[i], "PSVC_DEV_FAULT_SENSOR",
		    &number, &ps_fail_sensor);

		if (err != PICL_SUCCESS) {
			free(ps);
			return (err);
		}
		log_printf("   ");
		for (j = 0; j < MAX_PS_SENSORS; j++) {
			err = picl_get_propval_by_name(ps_fail_sensor[j],
			    "State", fault_state, PICL_PROPNAMELEN_MAX);
			if (err != PICL_SUCCESS) {
				if (err == PICL_FAILURE) {
					break;
				}
				free(ps);
				free(ps_fail_sensor);
				return (err);
			}
			log_printf(dgettext(TEXT_DOMAIN, "%-10s"), fault_state);
		}
		log_printf("\n");
		free(ps_fail_sensor);
	}

	log_printf(dgettext(TEXT_DOMAIN,
	    "\n=================================\n\n"));

	free(ps);
	return (PICL_SUCCESS);
}

static int
print_fans(picl_nodehdl_t system_node)
{
	int		i, err;
	int32_t		number;
	picl_nodehdl_t	*fans;
	picl_nodehdl_t	phdl;
	char		prop[PICL_PROPNAMELEN_MAX];
	char		parent[PICL_PROPNAMELEN_MAX];
	int32_t		rpm;

	err = fill_device_array_from_id(system_node, "PSVC_FAN", &number,
	    &fans);
	if (err != PICL_SUCCESS) {
		return (err);
	}

	log_printf(dgettext(TEXT_DOMAIN,
	    "\n=================================\n\n"
	    "Fan Status:\n"
	    "-----------\n\n"
	    "Fan Tray        Fan              RPM    Status\n"
	    "-----------     ----            -----   ----------\n"));

	for (i = 0; i < MAX_FANS; i++) {
		err = picl_get_propval_by_name(fans[i], PICL_PROP_NAME, prop,
		    PICL_PROPNAMELEN_MAX);
		if (err != PICL_SUCCESS)
			continue;

		err = fill_device_from_id(fans[i], "PSVC_PARENT", &phdl);
		if (err != PICL_SUCCESS)
			continue;
		err = picl_get_propval_by_name(phdl, PICL_PROP_NAME, parent,
		    PICL_PROPNAMELEN_MAX);
		if (err != PICL_SUCCESS)
			continue;

		log_printf(dgettext(TEXT_DOMAIN, "%-16s"), parent);


		log_printf(dgettext(TEXT_DOMAIN, "%-16s"), prop);

		err = picl_get_propval_by_name(fans[i], "Fan-speed",
		    &rpm, sizeof (rpm));
		if (err != PICL_SUCCESS) {
			free(fans);
			return (err);
		}
		log_printf(dgettext(TEXT_DOMAIN, "%5d "), rpm);

		err = picl_get_propval_by_name(fans[i], "FaultInformation",
		    prop, PICL_PROPNAMELEN_MAX);
		if (err != PICL_SUCCESS) {
			free(fans);
			return (err);
		}
		log_printf(dgettext(TEXT_DOMAIN, "  [%s]\n"), prop);
	}
	log_printf(dgettext(TEXT_DOMAIN,
	    "\n=================================\n\n"));
	free(fans);
	return (PICL_SUCCESS);
}

static int
print_disk(picl_nodehdl_t system_node)
{
	int		i, err;
	int32_t		number;
	picl_nodehdl_t	*disks;
	char		state[PICL_PROPNAMELEN_MAX];

	err = fill_device_array_from_id(system_node, "PSVC_DISK", &number,
	    &disks);
	if (err != PICL_SUCCESS) {
		return (err);
	}

	log_printf(dgettext(TEXT_DOMAIN,
	    "Disk Status:\n"
	    "------------\n"));
	for (i = 0; i < MAX_DISKS; i++) {
		err = picl_get_propval_by_name(disks[i], "FaultInformation",
		    state, PICL_PROPNAMELEN_MAX);

		switch (err) {
		case PICL_SUCCESS:
			log_printf(dgettext(TEXT_DOMAIN,
			    "DISK %d: [%3s]\n"), i, state);
			break;
		case PICL_INVALIDHANDLE:
			log_printf(dgettext(TEXT_DOMAIN,
			    "DISK %d: [ NOT PRESENT ]\n"), i);
			break;
		default:
			free(disks);
			return (err);
		}
	}
	free(disks);
	return (PICL_SUCCESS);
}

static int
print_FSP_LEDS(picl_nodehdl_t system_node)
{
	int		err;
	int32_t		number;
	picl_nodehdl_t	*fsp_led;
	char		fault_state[PICL_PROPNAMELEN_MAX];
	char		locate_state[PICL_PROPNAMELEN_MAX];

	err = fill_device_array_from_id(system_node, "PSVC_FSP_LED", &number,
	    &fsp_led);
	if (err != PICL_SUCCESS) {
		return (err);
	}

	assert(number == 2);
	err = picl_get_propval_by_name(fsp_led[0], "State", &fault_state,
	    PICL_PROPNAMELEN_MAX);
	if (err != PICL_SUCCESS) {
		free(fsp_led);
		return (err);
	}

	if (strcmp(fault_state, PSVC_LED_ON) == 0)
		exit_code = PD_SYSTEM_FAILURE;

	err = picl_get_propval_by_name(fsp_led[1], "State", &locate_state,
	    PICL_PROPNAMELEN_MAX);
	if (err != PICL_SUCCESS) {
		free(fsp_led);
		return (err);
	}

	log_printf(dgettext(TEXT_DOMAIN,
	    "System LED Status:\n\n"
	    "  LOCATOR   FAULT    POWER\n"
	    "  -------  -------  -------\n"
	    "   [%3s]    [%3s]    [ ON]"),
	    locate_state, fault_state);

	log_printf(dgettext(TEXT_DOMAIN,
	    "\n\n=================================\n\n"));
	free(fsp_led);
	return (err);
}

static int
print_keyswitch(picl_nodehdl_t system_node)
{
	int		err;
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
		free(keyswitch);
		return (err);
	}

	log_printf(dgettext(TEXT_DOMAIN,
	    "Front Status Panel:\n"
	    "-------------------\n"
	    "Keyswitch position: %s\n\n"), ks_pos);
	free(keyswitch);
	return (err);
}

static int
print_temps(picl_nodehdl_t system_node)
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
				(void) strcpy(state, "n/a");
			} else {
				free(system_ts_nodes);
				return (err);
			}
		}
		err = picl_get_propval_by_name(system_ts_nodes[i],
		    PICL_PROP_NAME, label, PICL_PROPNAMELEN_MAX);
		if (err != PICL_SUCCESS) {
			if (err == PICL_INVALIDHANDLE)
				/* This FRU isn't present. Skip it. */
				continue;
			free(system_ts_nodes);
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
			free(system_ts_nodes);
			return (err);
		}
		log_printf("%s\t\t%3d\t\t%s\n", label, temp, state);
	}

	log_printf(dgettext(TEXT_DOMAIN,
	    "\n=================================\n\n"));

	free(system_ts_nodes);
	return (PICL_SUCCESS);
}

static void
display_hw_revisions(Prom_node *root, Board_node *bdlist)
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
