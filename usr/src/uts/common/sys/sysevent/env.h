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

#ifndef _SYS_SYSEVENT_ENV_H
#define	_SYS_SYSEVENT_ENV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Event type EC_ENV/ESC_ENV_TEMP schema
 *	Event Class	- EC_ENV
 *	Event Sub-Class	- ESC_ENV_TEMP
 *	Event Publisher	- SUNW:kern:[environmental monitor name]
 *	Attribute Name	- ENV_VERSION
 *	Attribute Type	- SE_DATA_TYPE_UINT32
 *	Attribute Value	- [version of the schema]
 *	Attribute Name	- ENV_FRU_ID
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value	- [Label identifying the FRU or SE_RESERVED_ATTR]
 *	Attribute Name	- ENV_FRU_RESOURCE_ID
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value	- [Label identifying the Resource within the FRU or
 *			  SE_RESERVED_ATTR]
 *	Attribute Name	- ENV_FRU_DEVICE
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value	- ENV_RESERVED_ATTR
 *	Attribute Name	- ENV_FRU_STATE
 *	Attribute Type  - SE_DATA_TYPE_INT32
 *	Attribute Value	- ENV_OK | ENV_WARNING | ENV_FAILED
 *	Attribute Name	- ENV_MSG
 *	Attribute Type	- SE_DATA_TYPE_STRING
 *	Attribute Value	- [message passed by environmental monitor]
 */

#define	ENV_VERSION	"env_version"		/* version of the schema */
#define	ENV_FRU_ID	"env_fru_id"		/* PICL FRU name */
#define	ENV_FRU_RESOURCE_ID	"env_fru_resource_id"	/* FRU resource name */
#define	ENV_FRU_DEVICE	"env_fru_device_path"	/* Device path of sensor */
#define	ENV_FRU_STATE	"env_fru_state"		/* State of FRU */
#define	ENV_MSG		"env_msg"		/* environmental montitor msg */
#define	ENV_RESERVED_ATTR	""		/* Reserved attribute */

/*
 * Event type EC_ENV/ESC_ENV_POWER schema
 *	Event Class	- EC_ENV
 *	Event Sub-Class	- ESC_ENV_POWER
 *	Event Publisher	- SUNW:kern:[environmental monitor name]
 *	Attribute Name	- ENV_VERSION
 *	Attribute Type	- SE_DATA_TYPE_UINT32
 *	Attribute Value	- [version of the schema]
 *	Attribute Name	- ENV_FRU_ID
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value	- [Label identifying the FRU or SE_RESERVED_ATTR]
 *	Attribute Name	- ENV_FRU_RESOURCE_ID
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value	- [Label identifying the Resource within the FRU or
 *			   SE_RESERVED_ATTR]
 *	Attribute Name	- ENV_FRU_DEVICE
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value	- ENV_RESERVED_ATTR
 *	Attribute Name	- ENV_FRU_STATE
 *	Attribute Type  - SE_DATA_TYPE_INT32
 *	Attribute Value	- ENV_OK | ENV_WARNING | ENV_FAILED
 *	Attribute Name	- ENV_MSG
 *	Attribute Type	- SE_DATA_TYPE_STRING
 *	Attribute Value	- [message passed by environmental monitor]
 *
 *
 *
 * Event type EC_ENV/ESC_ENV_FAN event schema
 *	Event Class	- EC_ENV
 *	Event Sub-Class	- ESC_ENV_FAN
 *	Event Publisher	- SUNW:kern:[environmental monitor name]
 *	Attribute Name	- ENV_VERSION
 *	Attribute Type	- SE_DATA_TYPE_UINT32
 *	Attribute Value	- [version of the schema]
 *	Attribute Name	- ENV_FRU_ID
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value	- [Label identifying the FRU or SE_RESERVED_ATTR]
 *	Attribute Name	- ENV_FRU_RESOURCE_ID
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value	- [Label identifying the Resource within the FRU or
 *			   SE_RESERVED_ATTR]
 *	Attribute Name	- ENV_FRU_DEVICE
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value	- ENV_RESERVED_ATTR
 *	Attribute Name	- ENV_FRU_STATE
 *	Attribute Type  - SE_DATA_TYPE_INT32
 *	Attribute Value	- ENV_OK | ENV_WARNING | ENV_FAILED
 *	Attribute Name	- ENV_MSG
 *	Attribute Type	- SE_DATA_TYPE_STRING
 *	Attribute Value	- [message passed by environmental monitor]
 */

#define	ENV_OK		1
#define	ENV_WARNING	2
#define	ENV_FAILED	3

/*
 * Event type EC_ENV/ESC_ENV_LED event schema
 *	Event Class	- EC_ENV
 *	Event Sub-Class	- ESC_ENV_LED
 *	Event Publisher	- SUNW:kern:[environmental monitor name]
 *	Attribute Name	- ENV_VERSION
 *	Attribute Type	- SE_DATA_TYPE_UINT32
 *	Attribute Value	- [version of the schema]
 *	Attribute Name	- ENV_FRU_ID
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value	- [Label identifying the FRU or SE_RESERVED_ATTR]
 *	Attribute Name	- ENV_FRU_RESOURCE_ID
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value	- [Label identifying the Resource within the FRU or
 *			   SE_RESERVED_ATTR]
 *	Attribute Name	- ENV_FRU_DEVICE
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value - ENV_RESERVED_ATTR
 *	Attribute Name  - ENV_LED_COLOR
 *	Attribute Type  - SE_DATA_TYPE_STRING
 *	Attribute Value	- ENV_RESERVED_ATTR
 *	Attribute Name	- ENV_FRU_STATE
 *	Attribute Type  - SE_DATA_TYPE_INT32
 *	Attribute Value	- ENV_LED_ON | ENV_LED_OFF | ENV_LED_BLINKING |
 *			  ENV_LED_FLASHING | ENV_LED_INACCESSIBLE |
 *			  ENV_LED_STANDBY | ENV_LED_NOT_PRESENT
 *	Attribute Name	- ENV_MSG
 *	Attribute Type	- SE_DATA_TYPE_STRING
 *	Attribute Value	- [message passed by environmental monitor]
 */

#define	ENV_LED_ON		1
#define	ENV_LED_OFF		2
#define	ENV_LED_BLINKING	3
#define	ENV_LED_FLASHING	4
#define	ENV_LED_INACCESSIBLE	5
#define	ENV_LED_STANDBY		6
#define	ENV_LED_NOT_PRESENT	7

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_SYSEVENT_ENV_H */
