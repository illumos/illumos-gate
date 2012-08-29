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
 * Copyright (c) 2012 Joyent, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBIPD_H
#define	_LIBIPD_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Bitmask values for ic_mask.
 */
#define	IPDM_CORRUPT	0x1000
#define	IPDM_DELAY	0x2000
#define	IPDM_DROP	0x4000

typedef enum ipd_errno {
	EIPD_NOERROR = 0,
	EIPD_NOMEM,
	EIPD_ZC_NOENT,
	EIPD_RANGE,
	EIPD_PERM,
	EIPD_FAULT,
	EIPD_INTERNAL,
	EIPD_UNKNOWN
} ipd_errno_t;

typedef struct ipd_config {
	uint32_t ic_mask;
	uint32_t ic_corrupt;
	uint32_t ic_drop;
	uint32_t ic_delay;
} ipd_config_t;

struct ipd_stat;
typedef struct ipd_stat *ipd_stathdl_t;

typedef void (*ipd_status_cb_f)(zoneid_t, const ipd_config_t *, void *);

extern __thread ipd_errno_t ipd_errno;
extern __thread char ipd_errmsg[];

extern const char *ipd_strerror(ipd_errno_t);
extern int ipd_open(const char *);
extern int ipd_close(int);
extern int ipd_status_read(int, ipd_stathdl_t *);
extern void ipd_status_foreach_zone(const ipd_stathdl_t,
    ipd_status_cb_f, void *);
extern int ipd_status_get_config(const ipd_stathdl_t,
    zoneid_t, ipd_config_t **);
extern void ipd_status_free(ipd_stathdl_t);
extern int ipd_ctl(int, zoneid_t, const ipd_config_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBIPD_H */
