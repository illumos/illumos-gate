/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (C) 2013 Hewlett-Packard Development Company, L.P.
 */

#ifndef	_CPQARY3_BD_H
#define	_CPQARY3_BD_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file collects various info about each supported
 * controller that the driver needs to know in order to
 * properly support the board.  during device attach, the
 * driver can use cpqary3_bd_getbybid() to fetch the board
 * definition for the device to which it has attached.
 *
 * the source for the board definitions themselves is kept
 * in controllers, which is used to generate the c code to
 * define a static array of structs.  this array and its
 * search functions are defined in cpqary3_bd.c
 *
 * NOTE: if new fields are added or if the order of the
 * fields is altered, then the cpqary3_bd.c definitions
 * must be updated!
 */

struct cpqary3_bd {
	char		*bd_dispname;		/* display name */
	offset_t	bd_maplen;		/* register map length */
	uint16_t	bd_pci_subvenid;	/* PCI subvendor ID */
	uint16_t	bd_pci_subsysid;	/* PCI subsystem ID */
	uint32_t	bd_intrpendmask;	/* interrupt pending mask */
	uint32_t	bd_flags;		/* flags */
	uint32_t	bd_is_e200;
	uint32_t	bd_intrmask;
	uint32_t	bd_lockup_intrmask;
	uint32_t	bd_is_ssll;
};
typedef struct cpqary3_bd   cpqary3_bd_t;

/* bd_flags */
#define	SA_BD_SAS	0x00000001  /* board is a sas controller */


extern cpqary3_bd_t *cpqary3_bd_getbybid(uint32_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _CPQARY3_BD_H */
