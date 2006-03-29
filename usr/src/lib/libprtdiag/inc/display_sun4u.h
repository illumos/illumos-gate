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

#ifndef	_DISPLAY_SUN4U_H
#define	_DISPLAY_SUN4U_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <pdevinfo_sun4u.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Define the memory decode bits for easier reading.  These are from
 * the Sunfire Programmer's Manual.
 */
#define	MEM_SIZE_64M   0x4
#define	MEM_SIZE_256M  0xb
#define	MEM_SIZE_1G    0xf
#define	MEM_SIZE_2G    0x2

#define	MEM_SPEED_50ns 0x0
#define	MEM_SPEED_60ns 0x3
#define	MEM_SPEED_70ns 0x2
#define	MEM_SPEED_80ns 0x1

/*
 * If a QLC card is present in the system, the following values are needed
 * to decode what type of a QLC card it is.
 */
#define	AMBER_SUBSYSTEM_ID	0x4082
#define	CRYSTAL_SUBSYSTEM_ID	0x4083

#define	AMBER_CARD_NAME		"Amber"
#define	CRYSTAL_CARD_NAME	"Crystal+"

#define	MAX_QLC_MODEL_LEN	10

/*
 * Define strings in this structure as arrays instead of pointers so
 * that copying is easier.
 */
struct io_card {
	int  display;		    /* Should we display this card? */
	int  node_id;		    /* Node ID */
	int  board;		    /* Board number */
	char bus_type[MAXSTRLEN];   /* Type of bus this IO card is on */
	int  schizo_portid;	    /* portid of the Schizo for this card */
	char pci_bus;		    /* PCI bus A or B */
	int  slot;		    /* Slot number */
	char slot_str[MAXSTRLEN];   /* Slot description string */
	int  freq;		    /* Frequency (in MHz) */
	char status[MAXSTRLEN];	    /* Card status */
	char name[MAXSTRLEN];	    /* Card name */
	char model[MAXSTRLEN];	    /* Card model */
	int  dev_no;		    /* device number */
	int  func_no;		    /* function number */
	char notes[MAXSTRLEN];	    /* notes */
	struct io_card *next;
};

/* used to determine whether slot (int) or slot_str(char*) should be used */
#define	PCI_SLOT_IS_STRING	(-99)

int display(Sys_tree *, Prom_node *, struct system_kstat_data *, int);

#ifdef	__cplusplus
}
#endif

#endif	/* _DISPLAY_SUN4U_H */
