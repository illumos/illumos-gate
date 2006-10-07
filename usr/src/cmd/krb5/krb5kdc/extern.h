/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__KRB5_KDC_EXTERN__
#define	__KRB5_KDC_EXTERN__

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <netinet/in.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Copyright 1990,2001 by the Massachusetts Institute of Technology.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * <<< Description >>>
 */

typedef struct __kdc_realm_data {
    /*
     * General Kerberos per-realm data.
     */
    char *		realm_name;	/* Realm name			    */
/* XXX the real context should go away once the db_context is done. 
 * The db_context is then associated with the realm keytab using 
 * krb5_ktkdb_resolv(). There should be nothing in the context which 
 * cannot span multiple realms -- proven */
    krb5_context	realm_context;	/* Context to be used for realm	    */
    krb5_keytab		realm_keytab; 	/* keytab to be used for this realm */
    char *		realm_profile;	/* Profile file for this realm	    */
    /*
     * Database per-realm data.
     */
    char *		realm_dbname;	/* Database name for realm	    */
    char *		realm_stash;	/* Stash file name for realm	    */
    char *		realm_mpname;	/* Master principal name for realm  */
    krb5_principal	realm_mprinc;	/* Master principal for realm	    */
    krb5_keyblock	realm_mkey;	/* Master key for this realm	    */
    /*
     * TGS per-realm data.
     */
    krb5_principal	realm_tgsprinc;	/* TGS principal for this realm	    */
    /*
     * Other per-realm data.
     */
    char		*realm_ports;	/* Per-realm KDC UDP port */
    char		*realm_tcp_ports; /* Per-realm KDC TCP port */
    /*
     * Per-realm parameters.
     */
    krb5_deltat		realm_maxlife;	/* Maximum ticket life for realm    */
    krb5_deltat		realm_maxrlife;	/* Maximum renewable life for realm */
    krb5_boolean	realm_reject_bad_transit; /* Accept unverifiable transited_realm ? */
} kdc_realm_t;

extern kdc_realm_t	**kdc_realmlist;
extern int		kdc_numrealms;
extern kdc_realm_t	*kdc_active_realm;

kdc_realm_t *find_realm_data (char *, krb5_ui_4);

/*
 * Replace previously used global variables with the active (e.g. request's)
 * realm data.  This allows us to support multiple realms with minimal logic
 * changes.
 */
#define	kdc_context			kdc_active_realm->realm_context
#define	max_life_for_realm		kdc_active_realm->realm_maxlife
#define	max_renewable_life_for_realm	kdc_active_realm->realm_maxrlife
#define	master_keyblock			kdc_active_realm->realm_mkey
#define	master_princ			kdc_active_realm->realm_mprinc
#define	tgs_server_struct		*(kdc_active_realm->realm_tgsprinc)
#define	tgs_server			kdc_active_realm->realm_tgsprinc
#define	dbm_db_name			kdc_active_realm->realm_dbname
#define	primary_port			kdc_active_realm->realm_pport
#define reject_bad_transit		kdc_active_realm->realm_reject_bad_transit

/* various externs for KDC */
extern krb5_data 	empty_string;	/* an empty string */
extern krb5_timestamp 	kdc_infinity;	/* greater than all other timestamps */
extern krb5_rcache	kdc_rcache;	/* replay cache */
extern krb5_keyblock	psr_key;	/* key for predicted sam response */

extern volatile int signal_requests_exit;
extern volatile int signal_requests_hup;

/* libbsm */ 
extern void audit_krb5kdc_as_req(struct in_addr *, in_port_t, in_port_t,
				char *, char *, int);
extern void audit_krb5kdc_tgs_req(struct in_addr *, in_port_t, in_port_t,
				char *, char *, int);
extern void audit_krb5kdc_tgs_req_2ndtktmm(struct in_addr *, in_port_t,
					in_port_t, char *, char *);
extern void audit_krb5kdc_tgs_req_alt_tgt(struct in_addr *, in_port_t,
					in_port_t, char *, char *, int);

#ifdef	__cplusplus
}
#endif

#endif /* !__KRB5_KDC_EXTERN__ */
