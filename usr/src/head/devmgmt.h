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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef	_DEVMGMT_H
#define	_DEVMGMT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.12	*/

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * devmgmt.h
 *
 * Contents:
 *    -	Device Management definitions,
 *    -	getvol() definitions
 */

/*
 * Device management definitions
 *	- Default pathnames (relative to installation point)
 *	- Environment variable namess
 *	- Standard field names in the device table
 *	- Flags
 *	- Miscellaneous definitions
 */


/*
 * Default pathnames (relative to the package installation
 * point) to the files used by Device Management:
 *
 *	DTAB_PATH	Device table
 *	DGRP_PATH	Device group table
 *	DVLK_PATH	Device reservation table
 */

#define	DTAB_PATH			"/etc/device.tab"
#define	DGRP_PATH			"/etc/dgroup.tab"
#define	DVLK_PATH			"/etc/devlkfile"


/*
 * Names of environment variables
 *
 *	OAM_DEVTAB	Name of variable that defines the pathname to
 *			the device-table file
 *	OAM_DGROUP	Name of variable that defines the pathname to
 *			the device-group table file
 *	OAM_DEVLKTAB	Name of variable that defines the pathname to
 *			the device-reservation table file
 */

#define	OAM_DEVTAB			"OAM_DEVTAB"
#define	OAM_DGROUP			"OAM_DGROUP"
#define	OAM_DEVLKTAB			"OAM_DEVLKTAB"


/*
 * Standard field names in the device table
 */

#define	DTAB_ALIAS			"alias"
#define	DTAB_CDEVICE			"cdevice"
#define	DTAB_BDEVICE			"bdevice"
#define	DTAB_PATHNAME			"pathname"


/*
 * Flags:
 *	For getdev() and getdgrp():
 *		DTAB_ANDCRITERIA	Devices must meet all criteria
 *					instead of any of the criteria
 *		DTAB_EXCLUDEFLAG	The list of devices or device groups
 *					is the list that is to be excluded,
 *					not those to select from.
 *		DTAB_LISTALL		List all device groups, even those that
 *					have no valid members (getdgrp() only).
 */

#define	DTAB_ANDCRITERIA		0x01
#define	DTAB_EXCLUDEFLAG		0x02
#define	DTAB_LISTALL			0x04


/*
 * Miscellaneous Definitions
 *
 *	DTAB_MXALIASLN	Maximum alias length
 */

#define	DTAB_MXALIASLN			14

/*
 * Device Management Structure definitions
 *	reservdev	Reserved device description
 */

/*
 * struct reservdev
 *
 *	Structure describes a reserved device.
 *
 *  Elements:
 *	char   *devname		Alias of the reserved device
 *	pid_t	key		Key used to reserve the device
 */

struct reservdev {
	char   *devname;
	pid_t	key;
};

/*
 * Device Management Functions:
 *
 *	devattr()	Returns a device's attribute
 *	devreserv()	Reserves a device
 *	devfree()	Frees a reserved device
 *	reservdev()	Return list of reserved devices
 *	getdev()	Get devices that match criteria
 *	getdgrp()	Get device-groups containing devices
 *			that match criteria
 *	listdev()	List attributes defined for a device
 *	listdgrp()	List members of a device-group
 */

	char			*devattr(char *, char *);
	int			devfree(int, char *);
	char			**devreserv(int, char ***);
	char			**getdev(char **, char **, int);
	char			**getdgrp(char **, char **, int);
	char			**listdev(char *);
	char			**listdgrp(char *);
	struct reservdev	**reservdev(void);

/*
 * getvol() definitions
 */

#define	DM_BATCH	0x0001
#define	DM_ELABEL	0x0002
#define	DM_FORMAT	0x0004
#define	DM_FORMFS	0x0008
#define	DM_WLABEL	0x0010
#define	DM_OLABEL	0x0020

	int			getvol(char *, char *, int, char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _DEVMGMT_H */
