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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NFS_KEYS_H
#define	_NFS_KEYS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * NOT DEFINED IN cimKeys.h
 */

#define	CS_CREATION_CLASS	"CSCreationClassName"
#define	CSNAME			"CSName"
#define	FS_CREATION_CLASS	"FSCreationClassName"
#define	FSNAME			"FSName"
#define	SAME_ELEMENT		"SameElement"
/*
 * We must define two SettingID keys.
 * SettingID is for Solaris_PersistentShare.SettingID (CIM_SystemSetting) and
 * SettingId is for Solaris_NFSShareSecurity.SettingId (CIM_Setting)
 */
#define	SETTING_ID		"SettingID"
#define	SETTING_ID_LOWCASE	"SettingId"
#define	SYS_ELEMENT		"SystemElement"

/*
 * Defined in cimKeys.h
 */

#define	SYS_CREATION_CLASS	"SystemCreationClassName"
#define	CREATION_CLASS		"CreationClassName"
#define	SYSTEM			"SystemName"
#define	DEVICEID		"DeviceID"
#define	NAME			"Name"
#define	SYSTEM_ELEMENT		"SystemElement"
#define	SAME_ELEMENT		"SameElement"
#define	ANTECEDENT		"Antecedent"
#define	DEPENDENT		"Dependent"
#define	GROUP			"GroupComponent"
#define	PART			"PartComponent"
#define	TAG			"Tag"
#define	MODE			"Mode"

#ifdef __cplusplus
}
#endif

#endif /* _NFS_KEYS_H */
