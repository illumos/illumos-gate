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
 * PPPoE common utilities and data.
 *
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef PPPOE_COMMON_H
#define	PPPOE_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/sppptun.h>
#include <net/pppoe.h>
#include <netinet/if_ether.h>

#define	PKT_INPUT_LEN	PPPOE_MSGMAX
#define	PKT_OCTL_LEN	(sizeof (struct ppptun_control) + 1)
#define	PKT_OUTPUT_LEN	PPPOE_MSGMAX

/* Common buffers */
extern uint32_t pkt_input[];
extern uint32_t pkt_octl[];
extern uint32_t pkt_output[];

/* Name of PPPoE tunnel driver */
extern const char tunnam[];

/* Name of application (from argv[0]) */
extern char *myname;

/* Ethernet broadcast address */
extern const ether_addr_t ether_bcast;

/* General purpose utility functions. */
struct strbuf;
extern int strioctl(int fd, int cmd, void *ptr, int ilen, int olen);
extern const char *ehost(const ppptun_atype *pap);
extern const char *ehost2(const struct ether_addr *ea);
extern const char *ihost(uint32_t haddr);
extern int hexdecode(char chr);
extern const char *mystrerror(int err);
extern void myperror(const char *emsg);
extern int mygetmsg(int fd, struct strbuf *ctrl, struct strbuf *data,
    int *flags);

/* PPPoE-specific functions. */
extern poep_t *poe_mkheader(void *dptr, uint8_t codeval, int sessionid);
extern boolean_t poe_tagcheck(const poep_t *poep, int length,
    const uint8_t *tptr);
extern int poe_add_str(poep_t *poep, uint16_t ttype, const char *str);
extern int poe_add_long(poep_t *poep, uint16_t ttype, uint32_t val);
extern int poe_two_longs(poep_t *poep, uint16_t ttype, uint32_t val1,
    uint32_t val2);
extern int poe_tag_copy(poep_t *poep, const uint8_t *tagp);
extern const char *poe_tagname(uint16_t tagtype);
extern const char *poe_codename(uint8_t codetype);

/* These are here in case access wrappers are desired. */
#define	poe_version_type(p)	((p)->poep_version_type)
#define	poe_code(p)		((p)->poep_code)
#define	poe_session_id(p)	ntohs((p)->poep_session_id)
#define	poe_length(p)		ntohs((p)->poep_length)

#ifdef	__cplusplus
}
#endif

#endif /* PPPOE_COMMON_H */
