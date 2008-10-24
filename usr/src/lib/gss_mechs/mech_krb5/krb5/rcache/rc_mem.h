/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_KRB5_RC_MEM_H
#define	_KRB5_RC_MEM_H


#include "rc-int.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * mech_krb5/krb5/rcache/rc_mem.h
 *
 * This file of the Kerberos V5 software is derived from public-domain code
 * contributed by Daniel J. Bernstein, <brnstnd@acf10.nyu.edu>.
 */

/*
 * Solaris Kerberos:
 * Declarations for the memory replay cache implementation.
 */

struct mem_data {
	char *name;
	krb5_deltat lifespan;
	int hsize;
	struct authlist **h;
};

struct global_rcache {
	k5_mutex_t lock;
	struct mem_data *data;
};

extern struct global_rcache grcache;

extern const krb5_rc_ops krb5_rc_mem_ops;

krb5_error_code KRB5_CALLCONV krb5_rc_mem_init
	(krb5_context, krb5_rcache, krb5_deltat);
krb5_error_code KRB5_CALLCONV krb5_rc_mem_recover
	(krb5_context, krb5_rcache);
krb5_error_code KRB5_CALLCONV krb5_rc_mem_recover_or_init
	(krb5_context, krb5_rcache, krb5_deltat);
krb5_error_code KRB5_CALLCONV krb5_rc_mem_destroy
	(krb5_context, krb5_rcache);
krb5_error_code KRB5_CALLCONV krb5_rc_mem_close
	(krb5_context, krb5_rcache);
krb5_error_code KRB5_CALLCONV krb5_rc_mem_store
	(krb5_context, krb5_rcache, krb5_donot_replay *);
krb5_error_code KRB5_CALLCONV krb5_rc_mem_expunge
	(krb5_context, krb5_rcache);
krb5_error_code KRB5_CALLCONV krb5_rc_mem_get_span
	(krb5_context, krb5_rcache, krb5_deltat *);
char *KRB5_CALLCONV krb5_rc_mem_get_name
	(krb5_context, krb5_rcache);
krb5_error_code KRB5_CALLCONV krb5_rc_mem_resolve
	(krb5_context, krb5_rcache, char *);
void krb5_rc_free_entry
	(krb5_context, krb5_donot_replay **);

#ifdef __cplusplus
}
#endif

#endif /* !_KRB5_RC_MEM_H */
