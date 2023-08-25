/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * lib/krb5/rcache/rc_file.h
 *
 * This file of the Kerberos V5 software is derived from public-domain code
 * contributed by Daniel J. Bernstein, <brnstnd@acf10.nyu.edu>.
 *
 */

/*
 * Declarations for the file replay cache implementation.
 */

#ifndef _KRB5_RC_FILE_H
#define	_KRB5_RC_FILE_H


/* Solaris Kerberos */

#include "rc_common.h"
#include "rc_io.h"
#include "rc-int.h"

#ifndef EXCESSREPS
#define	EXCESSREPS 30
#endif
/*
 * The rcache will be automatically expunged when the number of expired
 * krb5_donot_replays encountered incidentally in searching exceeds the number
 * of live krb5_donot_replays by EXCESSREPS. With the defaults here, a typical
 * cache might build up some 10K of expired krb5_donot_replays before an
 * automatic expunge, with the waste basically independent of the number of
 * stores per minute.

 * The rcache will also automatically be expunged when it encounters more
 * than EXCESSREPS expired entries when recovering a cache in
 * file_recover.
 */

struct file_data {
	char *name;
	krb5_deltat lifespan;
	int hsize;
	int numhits;
	int nummisses;
	struct authlist **h;
	struct authlist *a;
	krb5_rc_iostuff d;
	char recovering;
};

extern const krb5_rc_ops krb5_rc_file_ops;

krb5_error_code KRB5_CALLCONV krb5_rc_file_init
    	(krb5_context,
		   krb5_rcache,
		   krb5_deltat);
krb5_error_code KRB5_CALLCONV krb5_rc_file_recover
	(krb5_context,
		   krb5_rcache);
krb5_error_code KRB5_CALLCONV krb5_rc_file_recover_or_init
    	(krb5_context,
		   krb5_rcache,
		   krb5_deltat);
krb5_error_code KRB5_CALLCONV krb5_rc_file_destroy
	(krb5_context,
		   krb5_rcache);
krb5_error_code KRB5_CALLCONV krb5_rc_file_close
	(krb5_context,
		   krb5_rcache);
krb5_error_code KRB5_CALLCONV krb5_rc_file_store
	(krb5_context,
		   krb5_rcache,
		   krb5_donot_replay *);
krb5_error_code KRB5_CALLCONV krb5_rc_file_expunge
	(krb5_context,
		   krb5_rcache);
krb5_error_code KRB5_CALLCONV krb5_rc_file_get_span
	(krb5_context,
		   krb5_rcache,
		   krb5_deltat *);
char * KRB5_CALLCONV krb5_rc_file_get_name
	(krb5_context,
		   krb5_rcache);
krb5_error_code KRB5_CALLCONV krb5_rc_file_resolve
	(krb5_context,
		   krb5_rcache,
		   char *);
krb5_error_code krb5_rc_file_close_no_free
	(krb5_context,
		   krb5_rcache);
void krb5_rc_free_entry
	(krb5_context,
		   krb5_donot_replay **);
#endif

