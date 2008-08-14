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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef __LM_DISK_H
#define	__LM_DISK_H


#include <lm.h>
#include <lm_proto.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	SLOT_MIN 50		/* If no carts the min of space needed */
#define	PCL_LEN	10		/* Max length of a disk cartridge PCL */
#define	SLOT_CFG_SIZE 75	/* The number of bytes in one slot */
				/* definition of a config slot LMPL */
				/* command */
#define	MAX_CONFIG_CARTS 420	/* Max number of cartridges that can */
				/* be processed into one config slot */
				/* LMPL command */
#define	DRIVE_MIN 50		/* If no drives the min of space needed */
#define	DNAME_LEN 20
#define	DRIVE_CFG_SIZE 75	/* The number of bytes in one drive */
				/* definition of a config drive LMPL */
				/* command */
#define	MAX_CONFIG_DRIVES 400	/* Max number of drives that can */
				/* be processed into one config slot */
				/* LMPL command */

#define	CFG_SLOT "slot [\"%s\" \"panel 0\" \"group 0\" \
\"%s\" \"%s\" %s true] "

#define	DELE_SLOT "delslots [\"%s\"] "

/* The following command formats differ from those in the  IEEE */
/* spec in the drive name. The reason this was done is that when the */
/* LM is activated initally, it does not know what the logical */
/* names are for the drives in the library, it only knows a geometry */
/* from the acsls perspective. Thus during the inital activation config */
/* LM sends up the acsls geometry and MM matches this with the geoemetry */
/* attribute of a drive. This same scheme was carried over for the */
/* partial configs assocatied when mounts and unmounts are done, even though */
/* LM knows the logical name at that time. */

#define	TEXT_CART "\"%s\" "
#define	CFG_DRIVE "drive [\"\" \"%s\" \"panel 0\" \"%s\" %s %s] "

#define	CONFIG_MOUNT "config task [\"%d\"] scope [partial] \
slot [\"%s\" \"panel 0\" \"group 0\" \"none\" \"DISK\" false true] \
drive [\"\" \"%s\" \"panel 0\" \"%s\" true true]; "

#define	CONFIG_UNMOUNT "config task [\"%d\"] scope [partial] \
slot [\"%s\" \"panel 0\" \"group 0\" \"%s\" \"DISK\" true true] \
drive [\"\" \"%s\" \"panel 0\" \"none\" false true]; "

#define	CONFIG_SCAN "config task [\"%d\"] scope [partial] \
slot [\"%s\" \"panel %d\" \"group %d\" \"%s\" \"%s\" true true]; "

#define	CONFIG_CART_EVENT "config task [\"%d\"] scope [partial] \
slot [\"%s\" \"panel %d\" \"group %d\" \"%s\" \"%s\" true true]; "

#define	CONFIG_DRIVE_EVENT "config task [\"%d\"] scope [partial] \
drive [\"\" \"%d,%d,%d,%d\" \"panel %d\" \"%s\" %s %s]; "

#define	LM_SHOW_OCC "show task [\"%d\"] \
match [and(streq(LIBRARY.\"LibraryName\" \"%s\") \
streq(CARTRIDGE.\"CartridgePCL\" \"%s\"))] \
report[CARTRIDGE.\"CartridgeDriveOccupied\"] \
reportmode[value]; "

#define	LM_SHOW_CARTS "show task [\"%d\"] \
match [streq(LIBRARY.\"LibraryName\" \"%s\")] \
report[CARTRIDGE.\"CartridgePCL\" CARTRIDGE.\"CartridgeDriveOccupied\"] \
reportmode[value]; "

#define	LM_SHOW_CART_NUM "show task [\"%d\"] \
match [streq(LIBRARY.\"LibraryName\" \"%s\")] \
report[CARTRIDGE] \
reportmode[number]; "

#define	LM_SHOW_DRIVE "show task [\"%d\"] \
match [and(streq(LIBRARY.\"LibraryName\" \"%s\") \
streq(DRIVE.\"DriveName\" \"%s\"))] \
report[DRIVE.\"CartridgePCL\"] \
reportmode[value]; "

#define	LM_SHOW_DRIVES "show task [\"%d\"] \
match [streq(LIBRARY.\"LibraryName\" \"%s\")] \
report[DRIVE.\"DriveName\" DRIVE.\"CartridgePCL\"] \
reportmode[value]; "

#define	LM_SHOW_DRIVE_NUM "show task [\"%d\"] \
match [streq(LIBRARY.\"LibraryName\" \"%s\")] \
report[DRIVE] \
reportmode[number]; "

#define	DISK_CONFIG "config task [\"%d\"] scope [partial] \
bay [\"panel 0\" true] \
slotgroup [\"group 0\" \"panel 0\" none \"ordinary\"] \
slotgroup [\"group cap0\" \"panel 0\" both \"port\"]; "

#define	FREE_1 "freeslots [\"panel 0\" \"L180\" \"%d\"] \
freeslots [\"panel 1\" \"L180\" \"%d\"] \
freeslots [\"panel 2\" \"L180\" \"%d\"]"

int lm_library_config(char *, char *, char *);

#ifdef	__cplusplus
}
#endif

#endif /* __LM_DISK_H */
