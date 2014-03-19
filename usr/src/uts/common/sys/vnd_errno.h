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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_VND_ERRNO_H
#define	_SYS_VND_ERRNO_H

/*
 * This header contains all of the available vnd errors.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum vnd_errno {
	VND_E_SUCCESS = 0,		/* no error */
	VND_E_NOMEM,			/* no memory */
	VND_E_NODATALINK,		/* no such datalink */
	VND_E_NOTETHER,			/* not DL_ETHER */
	VND_E_DLPIINVAL,		/* Unknown DLPI failures */
	VND_E_ATTACHFAIL,		/* DL_ATTACH_REQ failed */
	VND_E_BINDFAIL,			/* DL_BIND_REQ failed */
	VND_E_PROMISCFAIL,		/* DL_PROMISCON_REQ failed */
	VND_E_DIRECTFAIL,		/* DLD_CAPAB_DIRECT enable failed */
	VND_E_CAPACKINVAL,		/* bad dl_capability_ack_t */
	VND_E_SUBCAPINVAL,		/* bad dl_capability_sub_t */
	VND_E_DLDBADVERS,		/* bad dld version */
	VND_E_KSTATCREATE,		/* failed to create kstats */
	VND_E_NODEV,			/* no such vnd link */
	VND_E_NONETSTACK,		/* netstack doesn't exist */
	VND_E_ASSOCIATED,		/* device already associated */
	VND_E_ATTACHED,			/* device already attached */
	VND_E_LINKED,			/* device already linked */
	VND_E_BADNAME,			/* invalid name */
	VND_E_PERM,			/* can't touch this */
	VND_E_NOZONE,			/* no such zone */
	VND_E_STRINIT,		/* failed to initialize vnd stream module */
	VND_E_NOTATTACHED,		/* device not attached */
	VND_E_NOTLINKED,		/* device not linked */
	VND_E_LINKEXISTS,	/* another device has the same link name */
	VND_E_MINORNODE,		/* failed to create minor node */
	VND_E_BUFTOOBIG,		/* requested buffer size is too large */
	VND_E_BUFTOOSMALL,		/* requested buffer size is too small */
	VND_E_DLEXCL,			/* unable to get dlpi excl access */
	VND_E_DIRECTNOTSUP,
			/* DLD direct capability not suported over data link */
	VND_E_BADPROPSIZE,		/* invalid property size */
	VND_E_BADPROP,			/* invalid property */
	VND_E_PROPRDONLY,		/* property is read only */
	VND_E_SYS,			/* unexpected system error */
	VND_E_CAPABPASS,
			/* capabilities invalid, pass-through module detected */
	VND_E_UNKNOWN			/* unknown error */
} vnd_errno_t;

#ifdef __cplusplus
}
#endif

#endif /* _SYS_VND_ERRNO_H */
