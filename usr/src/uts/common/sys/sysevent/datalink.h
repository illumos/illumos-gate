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
 * Copyright 2015 Joyent, Inc.
 */

#ifndef _SYS_SYSEVENT_DATALINK_H
#define	_SYS_SYSEVENT_DATALINK_H

/*
 * Datalink System Event payloads
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Event schema for EC_DATALINK_LINK_STATE
 *
 *	Event Class	- EC_DATALINK
 *	Event Sub-Class	- EC_DATALINK_LINK_STATE
 *
 *	Attribute Name	- DATALINK_EV_LINK_NAME
 *	Attribute Type	- SE_DATA_TYPE_STRING
 *	Attribute Value	- [Name of the datalink]
 *
 *	Attribute Name	- DATALINK_EV_LINK_ID
 *	Attribute Type	- SE_DATA_TYPE_INT32
 *	Attribute Value	- [datalink_id_t for the device]
 *
 *	Attribute Name	- DATALINK_EV_ZONE_ID
 *	Attribute Type	- SE_DATA_TYPE_INT32
 *	Attribute Value	- [zoneid_t of the zone the datalink is in]
 */

#define	DATALINK_EV_LINK_NAME		"link"
#define	DATALINK_EV_LINK_ID		"linkid"
#define	DATALINK_EV_ZONE_ID		"zone"

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SYSEVENT_DATALINK_H */
