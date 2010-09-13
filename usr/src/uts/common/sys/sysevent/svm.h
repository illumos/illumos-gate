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
 * Copyright 2000-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_SYSEVENT_SVM_H
#define	_SYS_SYSEVENT_SVM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/sysevent.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * svm.h contains the publicly defined sysevent attribute names and values
 * for all SVM type sysevents.  Additions/removals/changes are subject to
 * PSARC approval.
 */

/*
 * svm sysevent version
 */
#define	SVM_VERSION0	0
#define	SVM_VERSION	SVM_VERSION0

/*
 * Event type EC_SVM_CONFIG/EC_SVM_STATE event schema
 *	Event Class 	- EC_SVM_CONFIG | EC_SVM_STATE
 *	Event Sub-Class - ESC_SVM_CREATE/ESC_SVM_DELETE/ESC_SVM_ADD/
 *			  ESC_SVM_REMOVE/ESC_SVM_REPLACE/ESC_SVM_GROW/
 *			  ESC_SVM_RENAME_SRC/ESC_SVM_RENAME_DST/
 *			  ESC_SVM_MEDIATOR_ADD/ESC_SVM_MEDIATOR_DELETE/
 *			  ESC_SVM_HOST_ADD/ESC_SVM_HOST_DELETE/
 *			  ESC_SVM_DRIVE_ADD/ESC_SVM_DRIVE_DELETE/
 *			  ESC_SVM_DETACH/ESC_SVM_DETACHING/ESC_SVM_ATTACH/
 *			  ESC_SVM_ATTACHING |
 *			  ESC_SVM_INIT_START/ESC_SVM_INIT_FAILED/
 *			  ESC_SVM_INIT_FATAL/ESC_SVM_INIT_SUCCESS/
 *			  ESC_SVM_IOERR/ESC_SVM_ERRED/ESC_SVM_LASTERRED/
 *			  ESC_SVM_OK/ESC_SVM_ENABLE/ESC_SVM_RESYNC_START/
 *			  ESC_SVM_RESYNC_FAILED/ESC_SVM_RESYNC_SUCCESS/
 *			  ESC_SVM_RESYNC_DONE/ESC_SVM_HOTSPARED/
 *			  ESC_SVM_HS_FREED/ESC_SVM_HS_CHANGED/
 *			  ESC_SVM_TAKEOVER/ESC_SVM_RELEASE/ESC_SVM_OPEN_FAIL/
 *			  ESC_SVM_OFFLINE/ESC_SVM_ONLINE/ESC_SVM_CHANGE/
 *			  ESC_SVM_EXCHANGE/ESC_SVM_REGEN_START/
 *			  ESC_SVM_REGEN_DONE/ESC_SVM_REGEN_FAILED/
 *	Attribute Name	- SVM_TAG
 *	Attribute Type	- SE_DATA_TYPE_UINT32
 *	Attribute Value	- [Device Tag]]
 *	Attribute Name	- SVM_SET_NO
 *	Attribute Type	- SE_DATA_TYPE_UINT32 - uint_t
 *	Attribute Value	- [Device Set Number]
 *	Attribute Name	- SVM_DEV_ID
 *	Attribute Type	- SE_DATA_TYPE_UINT32 - ulong_t
 *	Attribute Value	- [Device ID]
 *	Attribute Name	- SVM_DEV_NAME
 *	Attribute Type	- SE_DATA_TYPE_STRING
 *	Attribute Value	- [Device Name]
 */
#define	SVM_VERSION_NO	"svm_version"	/* event version number */
#define	SVM_TAG		"svm_tag"	/* device tag */
#define	SVM_SET_NO	"svm_set_no"	/* device set number */
#define	SVM_DEV_ID	"svm_dev_id"	/* device event occured on */
#define	SVM_DEV_NAME	"svm_dev_name"	/* device name */

/*
 * sys event originator
 */
#define	EP_SVM		"svm"

/*
 * Device TAG definitions
 */
#define	SVM_TAG_METADEVICE	 1
#define	SVM_TAG_MIRROR		 2
#define	SVM_TAG_STRIPE		 3
#define	SVM_TAG_RAID5		 4
#define	SVM_TAG_TRANS		 5
#define	SVM_TAG_REPLICA		 6
#define	SVM_TAG_HSP		 7
#define	SVM_TAG_HS		 8
#define	SVM_TAG_SET		 9
#define	SVM_TAG_DRIVE		10
#define	SVM_TAG_HOST		11
#define	SVM_TAG_MEDIATOR	12

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SYSEVENT_SVM_H */
