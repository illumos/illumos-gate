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
 */

#ifndef	_SYS_SYSEVENT_PWRCTL_H
#define	_SYS_SYSEVENT_PWRCTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Event type schema for EC_PWRCTL:
 *	Event Class	- EC_PWRCTL
 *	Event Sub-Class	- ESC_PWRCTL_ADD |
 *                        ESC_PWRCTL_REMOVE |
 *                        ESC_PWRCTL_WARN |
 *                        ESC_PWRCTL_LOW |
 *                        ESC_PWRCTL_STATE_CHANGE |
 *			  ESC_PWRCTL_POWER_BUTTON |
 *			  ESC_PWRCTL_BRIGHTNESS_UP |
 *			  ESC_PWRCTL_BRIGHTNESS_DOWN
 *	Event Publisher	- SUNW:kern:[environmental monitor name]
 *	Attribute Name	- PWRCTL_VERSION
 *	Attribute Type	- SE_DATA_TYPE_UINT32
 *	Attribute Value	- [version of the schema]
 *	Attribute Name	- PWRCTL_DEV_HID
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value	- [Label identifying the ACPI hardware]
 *	Attribute Name	- PWRCTL_DEV_UID
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value	- [Both the _HID and _UID values can be of either type
 *	                   STRING or NUMBER in the ACPI tables. In order to
 *	                   provide a consistent data type in the external
 *	                   interface, these values are always returned as NULL
 *	                   terminated strings, regardless of the original data
 *	                   type in the source ACPI table.]
 *	Attribute Name	- PWRCTL_DEV_INDEX
 *	Attribute Type	- SE_DATA_TYPE_UINT32
 *	Attribute Value	- [Device index]
 *
 * ESC_PWRCTL_WARN, ESC_PWRCTL_LOW only field:
 *	Attribute Name	- PWRCTL_CHARGE_LEVEL
 *	Attribute Type  - SE_DATA_TYPE_UINT32
 *	Attribute Value	- [charge level]
 */

#define	PWRCTL_VERSION		"pwrctl_version" /* Version of the schema */
#define	PWRCTL_DEV_PHYS_PATH	"pwrctl_dev_phys_path" /* Physical Path */
#define	PWRCTL_DEV_HID		"pwrctl_dev_hid" /* ACPI device Hardware Id */
#define	PWRCTL_DEV_UID		"pwrctl_dev_uid" /* ACPI device Unique Id */
#define	PWRCTL_DEV_INDEX	"pwrctl_dev_index" /* Device index */
#define	PWRCTL_CHARGE_LEVEL	"pwrctl_charge_level" /* Event related state */
#define	PWRCTL_BRIGHTNESS_LEVEL	"pwrctl_brightness_level"

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SYSEVENT_PWRCTL_H */
