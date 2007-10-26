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

#ifndef	_IPMI_IMPL_H
#define	_IPMI_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct ipmi_sdr_generic_locator;
struct ipmi_sdr_fru_locator;

typedef struct ipmi_sdr_cache_ent {
	uint8_t				isc_type;
	struct ipmi_sdr_generic_locator	*isc_generic;
	struct ipmi_sdr_fru_locator	*isc_fru;
	struct ipmi_sdr_cache_ent	*isc_next;
} ipmi_sdr_cache_ent_t;

typedef struct ipmi_transport {
	void *		(*it_open)(struct ipmi_handle *);
	void		(*it_close)(void *);
	int 		(*it_send)(void *, struct ipmi_cmd *, struct ipmi_cmd *,
			    int *);
} ipmi_transport_t;

struct ipmi_handle {
	ipmi_transport_t	*ih_transport;
	void			*ih_tdata;
	ipmi_cmd_t		ih_response;
	int			ih_errno;
	uint16_t		ih_reservation;
	int			ih_retries;
	ipmi_sdr_cache_ent_t	*ih_sdr_cache;
	ipmi_deviceid_t		ih_deviceid;
	boolean_t		ih_deviceid_valid;
	char			ih_errmsg[1024];
	char			ih_errbuf[1024];
	ipmi_user_t		*ih_users;
};

/*
 * Error handling
 */
extern int ipmi_set_error(ipmi_handle_t *, int, const char *, ...);

/*
 * Memory allocation
 */
extern void *ipmi_alloc(ipmi_handle_t *, size_t);
extern void *ipmi_zalloc(ipmi_handle_t *, size_t);
extern void ipmi_free(ipmi_handle_t *, void *);
extern void *impi_realloc(ipmi_handle_t *, void *, size_t);
extern char *ipmi_strdup(ipmi_handle_t *, const char *);

/*
 * Supported transports
 */
extern ipmi_transport_t ipmi_transport_bmc;

/*
 * Miscellaneous routines
 */
extern void ipmi_sdr_clear(ipmi_handle_t *);
extern void ipmi_user_clear(ipmi_handle_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _IPMI_IMPL_H */
