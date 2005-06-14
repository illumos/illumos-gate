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
 * Copyright (c) 1996 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _CS_STUBS_H
#define	_CS_STUBS_H

#pragma ident	"%W%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Magic number for Card Services to use when registering it's entry
 *	point with the Card Services stubs module.
 */
#define	CS_STUBS_MAGIC	0x19960300

/*
 * Card Services function identifiers - these correspond to the PCMCIA
 *	standard function codes for CS with the exception of a few
 *	private and implementation-specific function identifiers.
 *
 * client services functions
 */
#define	GetCardServicesInfo		0x000b
#define	RegisterClient			0x0010
#define	DeregisterClient		0x0002
#define	GetStatus			0x000c
#define	ResetFunction			0x0011
#define	SetEventMask			0x0031
#define	GetEventMask			0x002e
/*
 * reource management functions
 */
#define	RequestIO			0x001f
#define	ReleaseIO			0x001b
#define	RequestIRQ			0x0020
#define	ReleaseIRQ			0x001c
#define	RequestWindow			0x0021
#define	ReleaseWindow			0x001d
#define	ModifyWindow			0x0017
#define	MapMemPage			0x0014
#define	RequestSocketMask		0x0022
#define	ReleaseSocketMask		0x002f
#define	RequestConfiguration		0x0030
#define	GetConfigurationInfo		0x0004
#define	ModifyConfiguration		0x0027
#define	ReleaseConfiguration		0x001e
#define	AccessConfigurationRegister	0x0036
/*
 * bulk memory service functions
 */
#define	OpenMemory			0x0018
#define	ReadMemory			0x0019
#define	WriteMemory			0x0024
#define	CopyMemory			0x0001
#define	RegisterEraseQueue		0x000f
#define	CheckEraseQueue			0x0026
#define	DeregisterEraseQueue		0x0025
#define	CloseMemory			0x0000
/*
 * client utility functions
 */
#define	GetFirstTuple			0x0007
#define	GetNextTuple			0x000a
#define	GetTupleData			0x000d
#define	GetFirstRegion			0x0006
#define	GetNextRegion			0x0009
#define	GetFirstPartition		0x0005
#define	GetNextPartition		0x0008
/*
 * advanced client services functions
 */
#define	ReturnSSEntry			0x0023
#define	MapLogSocket			0x0012
#define	MapPhySocket			0x0015
#define	MapLogWindow			0x0013
#define	MapPhyWindow			0x0016
#define	RegisterMTD			0x001a
#define	RegisterTimer			0x0028
#define	SetRegion			0x0029
#define	ValidateCIS			0x002b
#define	RequestExclusive		0x002c
#define	ReleaseExclusive		0x002d
#define	GetFirstClient			0x000e
#define	GetNextClient			0x002a
#define	GetClientInfo			0x0003
#define	AddSocketServices		0x0032
#define	ReplaceSocketServices		0x0033
#define	VendorSpecific			0x0034
#define	AdjustResourceInfo		0x0035
/*
 * private functions - clients should never call these; if they do,
 *	the system will esplode.
 */
#define	CISRegister			0x1000
#define	CISUnregister			0x1001
#define	InitCISWindow			0x1002
/*
 * Card Services functions specific to this implementation
 */
#define	ParseTuple		0x2000	/* parses contents of tuples */
#define	MakeDeviceNode		0x2001	/* makes device nodes in fs */
#define	ConvertSpeed		0x2002	/* converts device speeds */
#define	ConvertSize		0x2003	/* converts device sizes */
#define	Event2Text		0x2004	/* return string of event type */
#define	Error2Text		0x2005	/* function or ret code string */
#define	CS_DDI_Info		0x2006	/* set/get DDI info */
#define	CS_Sys_Ctl		0x2007  /* CS system control */
#define	RemoveDeviceNode	0x2008	/* removes device nodes in fs */
#define	GetPhysicalAdapterInfo	0x2009	/* returns physical adapter info */
#define	CSFuncListEnd		0x8000	/* end of CS function list */

/*
 * Structure used when Card Services registers it's entry point with
 *	the Card Services stubs module
 */
typedef struct cs_register_cardservices_t {
	uint32_t	function;
	uint32_t	magic;
	csfunction_t	*cardservices;
	csfunction_t	*socketservices;
} cs_register_cardservices_t;

/*
 * Functions for cs_register_cardservices_t
 */
#define	CS_ENTRY_REGISTER	0x0001
#define	CS_ENTRY_DEREGISTER	0x0002
#define	CS_ENTRY_INQUIRE	0x0003

/*
 * Function prototypes
 */
int32_t csx_register_cardservices(cs_register_cardservices_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _CS_STUBS_H */
