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

#ifndef	_INET_KSSL_KSSLAPI_H
#define	_INET_KSSL_KSSLAPI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The kernel SSL proxy interface
 */


#ifdef	__cplusplus
extern "C" {
#endif

#include	<sys/socket.h>
#include	<netinet/in.h>

/* return status for the kssl API functions */

typedef enum {
	KSSL_STS_OK,	/* No further processing required */
	KSSL_STS_ERR	/* bogus argument  ... */
} kssl_status_t;

/* Endpoint type */
typedef	enum {
	KSSL_NO_PROXY = 0,	/* Not configured for use with KSSL */
	KSSL_IS_PROXY,		/* Acts as a proxy for someone else */
	KSSL_HAS_PROXY		/* A proxy is handling its work */
} kssl_endpt_type_t;

/* Return codes/commands from kssl_handle_record */
typedef enum {
	KSSL_CMD_NOT_SUPPORTED,	/* Not supported */
	KSSL_CMD_SEND,		/* send this packet out on the wire */
	KSSL_CMD_DELIVER_PROXY,	/* deliver this packet to proxy listener */
	KSSL_CMD_DELIVER_SSL,	/* Deliver to the SSL listener */
	KSSL_CMD_NONE,		/* consider it consumed. (ACK it, ... */
	KSSL_CMD_QUEUED		/* Queued, a call back will finish it */
} kssl_cmd_t;

typedef enum {
	KSSL_EVENT_CLOSE	/* close this context */
} kssl_event_t;

/* Un opaque context of an SSL connection */
typedef void *kssl_ctx_t;

/* Un opaque handle for an SSL map entry */
typedef	void *kssl_ent_t;

#define	SSL3_HDR_LEN		5
#define	SSL3_WROFFSET		7	/* 5 hdr + 2 byte-alignment */
#define	SSL3_MAX_TAIL_LEN	36	/* 16 AES blocks +  20 SHA1 digest */
#define	SSL3_MAX_RECORD_LEN	16384 - 1 - SSL3_HDR_LEN - SSL3_MAX_TAIL_LEN


kssl_endpt_type_t kssl_check_proxy(mblk_t *, void *, kssl_ent_t *);

kssl_status_t kssl_init_context(kssl_ent_t, uint32_t, int, kssl_ctx_t *);

void kssl_hold_ent(kssl_ent_t);
void kssl_release_ent(kssl_ent_t, void *, kssl_endpt_type_t);
void *kssl_find_fallback(kssl_ent_t);

void kssl_hold_ctx(kssl_ctx_t);
void kssl_release_ctx(kssl_ctx_t);

typedef void (*kssl_callback_t)(void *arg, mblk_t *mp, kssl_cmd_t cmd);

kssl_cmd_t kssl_input(kssl_ctx_t, mblk_t *, mblk_t **, boolean_t *,
    kssl_callback_t cbfn, void *arg);

kssl_cmd_t kssl_handle_mblk(kssl_ctx_t, mblk_t **, mblk_t **);

mblk_t *kssl_build_record(kssl_ctx_t, mblk_t *);


#ifdef	__cplusplus
}
#endif

#endif	/* _INET_KSSL_KSSLAPI_H */
