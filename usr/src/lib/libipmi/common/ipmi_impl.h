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

#ifndef	_IPMI_IMPL_H
#define	_IPMI_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <libipmi.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct ipmi_list {
	struct ipmi_list *l_prev;
	struct ipmi_list *l_next;
} ipmi_list_t;

typedef struct ipmi_hash_link {
	ipmi_list_t  ihl_list;		/* next on list of all elements */
	struct ipmi_hash_link *ihl_next;	/* next on this bucket */
} ipmi_hash_link_t;

typedef struct ipmi_hash {
	ipmi_handle_t *ih_handle;	/* handle to library state */
	ipmi_hash_link_t **ih_buckets;	/* array of buckets */
	size_t ih_nbuckets;		/* number of buckets */
	size_t ih_nelements;		/* number of elements */
	ipmi_list_t ih_list;		/* list of all elements */
	size_t ih_linkoffs;		/* offset of ipmi_hash_link in elem */
	const void *(*ih_convert)(const void *); /* key conversion function */
	ulong_t (*ih_compute)(const void *); /* hash computing function */
	int (*ih_compare)(const void *, const void *); /* compare function */
} ipmi_hash_t;

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
	ipmi_hash_t		*ih_sdr_cache;
	uint32_t		ih_sdr_ts;
	ipmi_deviceid_t		*ih_deviceid;
	uint32_t		ih_deviceid_len;
	char			*ih_firmware_rev;
	char			ih_errmsg[1024];
	char			ih_errbuf[1024];
	ipmi_list_t		ih_users;
	ipmi_hash_t		*ih_entities;
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
 * Primitives for converting
 */
typedef struct ipmi_name_trans {
	int		int_value;
	const char	*int_name;
} ipmi_name_trans_t;

typedef struct ipmi_sensor_trans {
	uint8_t			ist_key;
	uint8_t			ist_value;
	ipmi_name_trans_t	ist_mask[1];
} ipmi_sensor_trans_t;

extern ipmi_name_trans_t ipmi_entity_table[];
extern ipmi_name_trans_t ipmi_sensor_type_table[];
extern ipmi_name_trans_t ipmi_reading_type_table[];
extern ipmi_name_trans_t ipmi_errno_table[];
extern ipmi_name_trans_t ipmi_threshold_state_table[];
extern ipmi_sensor_trans_t ipmi_reading_state_table[];
extern ipmi_sensor_trans_t ipmi_specific_state_table[];

/*
 * Miscellaneous routines
 */
extern int ipmi_sdr_init(ipmi_handle_t *);
extern void ipmi_sdr_clear(ipmi_handle_t *);
extern void ipmi_sdr_fini(ipmi_handle_t *);
extern void ipmi_user_clear(ipmi_handle_t *);
extern int ipmi_entity_init(ipmi_handle_t *);
extern void ipmi_entity_clear(ipmi_handle_t *);
extern void ipmi_entity_fini(ipmi_handle_t *);

extern int ipmi_convert_bcd(int);
extern void ipmi_decode_string(uint8_t type, uint8_t len, char *data,
    char *buf);
extern boolean_t ipmi_is_sun_ilom(ipmi_deviceid_t *);

/*
 * List routines
 */

#define	ipmi_list_prev(elem)	((void *)(((ipmi_list_t *)(elem))->l_prev))
#define	ipmi_list_next(elem)	((void *)(((ipmi_list_t *)(elem))->l_next))

extern void ipmi_list_append(ipmi_list_t *, void *);
extern void ipmi_list_prepend(ipmi_list_t *, void *);
extern void ipmi_list_insert_before(ipmi_list_t *, void *, void *);
extern void ipmi_list_insert_after(ipmi_list_t *, void *, void *);
extern void ipmi_list_delete(ipmi_list_t *, void *);

/*
 * Hash table routines
 */

extern ipmi_hash_t *ipmi_hash_create(ipmi_handle_t *, size_t,
    const void *(*convert)(const void *),
    ulong_t (*compute)(const void *),
    int (*compare)(const void *, const void *));

extern void ipmi_hash_destroy(ipmi_hash_t *);
extern void *ipmi_hash_lookup(ipmi_hash_t *, const void *);
extern void ipmi_hash_insert(ipmi_hash_t *, void *);
extern void ipmi_hash_remove(ipmi_hash_t *, void *);
extern size_t ipmi_hash_count(ipmi_hash_t *);

extern ulong_t ipmi_hash_strhash(const void *);
extern int ipmi_hash_strcmp(const void *, const void *);

extern ulong_t ipmi_hash_ptrhash(const void *);
extern int ipmi_hash_ptrcmp(const void *, const void *);

extern void *ipmi_hash_first(ipmi_hash_t *);
extern void *ipmi_hash_next(ipmi_hash_t *, void *);

#ifdef	__cplusplus
}
#endif

#endif	/* _IPMI_IMPL_H */
