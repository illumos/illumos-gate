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
 * Copyright (c) 2017, Joyent, Inc.
 */

#ifndef _DLSEND_H
#define	_DLSEND_H

/*
 * A common header file for things that dlsend and dlrecv need.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * We need to pick an arbitrary Ethertype to squat on for the purposes of this
 * testing program. As such we use one with a recongizable string. If someone
 * comes along and uses this, then we should get off of it.
 */
#define	DLSEND_SAP	0xdeed
#define	DLSEND_MSG	"A Elbereth Gilthoniel"

typedef struct dlsend_msg {
	uint64_t	dm_count;
	char		dm_host[MAXHOSTNAMELEN];
	char		dm_mesg[32];
} dlsend_msg_t;

#ifdef __cplusplus
}
#endif

#endif /* _DLSEND_H */
