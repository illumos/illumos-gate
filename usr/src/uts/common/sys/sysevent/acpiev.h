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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SYSEVENT_ACPIEV_H
#define	_SYS_SYSEVENT_ACPIEV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Event type schema for EC_ACPIEV:
 *	Event Class	- EC_ACPIEV
 *	Event Sub-Class	- ESC_ACPIEV_ADD |
 *                        ESC_ACPIEV_REMOVE |
 *                        ESC_ACPIEV_WARN |
 *                        ESC_ACPIEV_LOW |
 *                        ESC_ACPIEV_STATE_CHANGE
 *	Event Publisher	- SUNW:kern:[environmental monitor name]
 *	Attribute Name	- ACPIEV_VERSION
 *	Attribute Type	- SE_DATA_TYPE_UINT32
 *	Attribute Value	- [version of the schema]
 *	Attribute Name	- ACPIEV_DEV_HID
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value	- [Label identifying the ACPI hardware]
 *	Attribute Name	- ACPIEV_DEV_UID
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value	- [Both the _HID and _UID values can be of either type
 *	                   STRING or NUMBER in the ACPI tables. In order to
 *	                   provide a consistent data type in the external
 *	                   interface, these values are always returned as NULL
 *	                   terminated strings, regardless of the original data
 *	                   type in the source ACPI table.]
 *	Attribute Name 	- ACPIEV_DEV_INDEX
 *	Attribute Type	- SE_DATA_TYPE_UINT32
 *	Attribute Value	- [Device index]
 *
 * ESC_ACPIEV_WARN, ESC_ACPIEV_LOW only field:
 *	Attribute Name	- ACPIEV_CHARGE_LEVEL
 *	Attribute Type  - SE_DATA_TYPE_UINT32
 *	Attribute Value	- [charge level]
 */

#define	ACPIEV_VERSION		"acpiev_version" /* Version of the schema */
#define	ACPIEV_DEV_PHYS_PATH	"acpiev_dev_phys_path" /* Physical Path */
#define	ACPIEV_DEV_HID		"acpiev_dev_hid" /* ACPI device Hardware Id */
#define	ACPIEV_DEV_UID		"acpiev_dev_uid" /* ACPI device Unique Id */
#define	ACPIEV_DEV_INDEX	"acpiev_dev_index" /* Device index */
#define	ACPIEV_CHARGE_LEVEL	"acpiev_charge_level" /* Event related state */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SYSEVENT_ACPIEV_H */
