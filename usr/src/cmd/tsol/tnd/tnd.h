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

#ifndef	_TND_H_
#define	_TND_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * TSOL Messages have the following header
 */

typedef struct {
	uchar_t tnd_version; /* protocol version number */
	uchar_t tnd_message; /* message type. */
	uchar_t tnd_error_code; /* Error return for a reply. */
} tsol_tnd_hdr_t;

/*
 * TND TSOL messages
 */

#define	TND_DEBUG_REQ	127
#define	TND_POLL_REQ	128
#define	TND_REPLY	129

/*
 * TND errors
 */

#define	TND_SUCCESS 1
#define	TND_FAIL_LOG	2
#define	TND_FAIL_DEBUG_LEVEL 4
#define	TND_NOT_SUPPORTED 8
#define	TND_DENIED	16

/* TND door files */
#define	TND_DOORFILE	"/etc/.tnd_door"
#define	TND_DOORFILE2	"/etc/.tnd_door2"

/*
 * tnd request messages have the following format
 */

struct tsol_tnd_msg {
	tsol_tnd_hdr_t ttm_hdr; /* message header */
	uint_t ttm_int; /* debug level or poll interval(in seconds) */
};

#define	TNDLOG "/var/tsol/tndlog"
#define	MAX_TND_DEBUG 2
#define	DEF_TND_DEBUG 1

#define	HNAMELEN 64

/*
 * polling default (seconds)
 */
#define	TND_DEF_POLL_TIME 1800 /* 30 minutes */

/* tnrhtp_c cache structure */
struct tnd_tnrhtp_c {
	tsol_tpent_t tp_ent;
	struct tnd_tnrhtp_c *tp_next;
};

/* tnrhdb_c cache structure */
typedef struct tnd_tnrhdb_c {
	tsol_rhent_t	rh_ent;
	int		visited;	/* Flag to handle deletions */
	struct tnd_tnrhdb_c	*rh_next;
} tnd_tnrhdb_t;

/* tnrhdb lookup table */
typedef struct tnrh_tlb {
	in_addr_t	addr;
	char		template_name[TNTNAMSIZ];
	int		reload;		/* flag to reload/delete */
	int		masklen_used;	/* Which mask did we use */
	tnd_tnrhdb_t	*src;		/* Which table entry is our source */
	struct tnrh_tlb	*next;		/* Next in the hash chain */
} tnrh_tlb_t;

/* tnrhdb IPv6 address lookup table */
typedef struct tnrh_tlb_ipv6 {
	in6_addr_t	addr;
	char		template_name[TNTNAMSIZ];
	int		reload;		/* flag to reload/delete */
	int		masklen_used;	/* Which mask did we use */
	tnd_tnrhdb_t	*src;		/* Which table entry is our source */
	struct tnrh_tlb_ipv6	*next;	/* Next in the hash chain */
} tnrh_tlb_ipv6_t;

/* Clients of tnd can use this structure */
typedef struct {
	struct tsol_rhent rh;
	union {
		in_addr_t _v4addr;
		in6_addr_t _v6addr;
	} _addr_un;
	sa_family_t af;
	int flag;	/* flag to reload/delete */
} tndclnt_arg_t;
#define	v4addr _addr_un._v4addr
#define	v6addr _addr_un._v6addr

#ifdef	__cplusplus
}
#endif

#endif	/* _TND_H_ */
