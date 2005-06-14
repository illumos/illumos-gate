/*
 * Copyright 1995-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *  Copyright (c) 1995 Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  ldap-int.h - defines & prototypes internal to the LDAP library
 */

#include <stdlib.h> 			/* rri */
#include <pthread.h>			/* rri */
#include <netinet/in.h>

#define LDAP_URL_PREFIX         "ldap://"
#define LDAP_URL_PREFIX_LEN     7
#define LDAP_URL_URLCOLON	"URL:"
#define LDAP_URL_URLCOLON_LEN	4

#ifdef LDAP_REFERRALS
#define LDAP_REF_STR		"Referral:\n"
#define LDAP_REF_STR_LEN	10
#define LDAP_LDAP_REF_STR	LDAP_URL_PREFIX
#define LDAP_LDAP_REF_STR_LEN	LDAP_URL_PREFIX_LEN
#ifdef LDAP_DNS
#define LDAP_DX_REF_STR		"dx://"
#define LDAP_DX_REF_STR_LEN	5
#endif /* LDAP_DNS */
#endif /* LDAP_REFERRALS */


/*
 * in cache.c
 */
#ifdef NEEDPROTOS
void add_request_to_cache( LDAP *ld, unsigned int msgtype,
        BerElement *request );
void add_result_to_cache( LDAP *ld, LDAPMessage *result );
int check_cache( LDAP *ld, unsigned int msgtype, BerElement *request );
#else /* NEEDPROTOS */
void add_request_to_cache();
void add_result_to_cache();
int check_cache();
#endif /* NEEDPROTOS */


#ifdef KERBEROS
/*
 * in kerberos.c
 */
#ifdef NEEDPROTOS
char *get_kerberosv4_credentials( LDAP *ld, char *who, char *service,
        int *len );
#else /* NEEDPROTOS */
char *get_kerberosv4_credentials();
#endif /* NEEDPROTOS */

#endif /* KERBEROS */

/*
 * in notif.c
 */
int ldap_insert_notif(LDAP *ld, LDAPMessage *notif);
int ldap_add_notif(LDAP *ld, LDAPMessage *notif);


/*
 * in open.c
 */
int ldap_thr_index(); /* rri */
#ifdef NEEDPROTOS
int open_default_ldap_connection(LDAP *ld);
int open_ldap_connection( LDAP *ld, Sockbuf *sb, char *host, int defport,
	char **krbinstancep, int async );
#else /* NEEDPROTOS */
int open_default_ldap_connection();
int open_ldap_connection();
#endif /* NEEDPROTOS */

/*
 * in options.c
 */

int ldap_get_option (LDAP *ld, int option, void *outvalue);

/*
 * in os-ip.c
 */
void close_ldap_connection( Sockbuf *sb ); /* rri */
#ifdef NEEDPROTOS
int connect_to_host(Sockbuf *sb, char *host, in_addr_t address, int port,
	int async, int bindTimeout);
void close_connection( Sockbuf *sb );
#else /* NEEDPROTOS */
int connect_to_host();
void close_connection();
#endif /* NEEDPROTOS */

#ifdef KERBEROS
#ifdef NEEDPROTOS
char *host_connected_to( Sockbuf *sb );
#else /* NEEDPROTOS */
char *host_connected_to();
#endif /* NEEDPROTOS */
#endif /* KERBEROS */

#ifdef LDAP_REFERRALS
#ifdef NEEDPROTOS
int do_ldap_select( LDAP *ld, struct timeval *timeout );
void *new_select_info( void );
void free_select_info( void *sip );
void mark_select_write( LDAP *ld, Sockbuf *sb );
void mark_select_read( LDAP *ld, Sockbuf *sb );
void mark_select_clear( LDAP *ld, Sockbuf *sb );
long is_read_ready( LDAP *ld, Sockbuf *sb );
long is_write_ready( LDAP *ld, Sockbuf *sb );
#else /* NEEDPROTOS */
int do_ldap_select();
void *new_select_info();
void free_select_info();
void mark_select_write();
void mark_select_read();
void mark_select_clear();
long is_read_ready();
long is_write_ready();
#endif /* NEEDPROTOS */
#endif /* LDAP_REFERRALS */

/*
 * in regex.c		(rri)	
 */
int re_exec( char *lp );

/*
 * in request.c
 */
#ifdef NEEDPROTOS
int send_initial_request( LDAP *ld, unsigned int msgtype,
	char *dn, BerElement *ber );
BerElement *alloc_ber_with_options( LDAP *ld );
void set_ber_options( LDAP *ld, BerElement *ber );
#else /* NEEDPROTOS */
int send_initial_request();
BerElement *alloc_ber_with_options();
void set_ber_options();
#endif /* NEEDPROTOS */

#if defined( LDAP_REFERRALS ) || defined( LDAP_DNS )
#ifdef NEEDPROTOS
int send_server_request( LDAP *ld, BerElement *ber, int msgid,
	LDAPRequest *parentreq, LDAPServer *srvlist, LDAPConn *lc,
	int bind );
LDAPConn *new_connection( LDAP *ld, LDAPServer **srvlistp, int use_ldsb,
	int connect, int bind );
LDAPRequest *find_request_by_msgid( LDAP *ld, int msgid );
void free_request( LDAP *ld, LDAPRequest *lr );
void free_connection( LDAP *ld, LDAPConn *lc, int force, int unbind );
void dump_connection( LDAP *ld, LDAPConn *lconns, int all );
void dump_requests_and_responses( LDAP *ld );
#else /* NEEDPROTOS */
int send_server_request();
LDAPConn *new_connection();
LDAPRequest *find_request_by_msgid();
void free_request();
void free_connection();
void dump_connection();
void dump_requests_and_responses();
#endif /* NEEDPROTOS */
#endif /* LDAP_REFERRALS || LDAP_DNS */

#ifdef LDAP_REFERRALS
#ifdef NEEDPROTOS
int chase_referrals( LDAP *ld, LDAPRequest *lr, char **refs, int *count, int samerequest );
char ** ldap_errormsg2referrals(char *errmsg);
char *ldap_referral2error_msg(char ** refs);
int append_referral( LDAP *ld, char **referralsp, char *s );
#else /* NEEDPROTOS */
int chase_referrals();
char ** ldap_errormsg2referrals();
char *ldap_referral2error_msg();
int append_referral();
#endif /* NEEDPROTOS */
#endif /* LDAP_REFERRALS */

void nsldapi_connection_lost_nolock( LDAP *ld, Sockbuf *sb );

/*
 * in search.c
 */
#ifdef NEEDPROTOS
BerElement *ldap_build_search_req( LDAP *ld, char *base, int scope,
	char *filter, char **attrs, int attrsonly,  LDAPControl ** serverctrls,
					   struct timeval *timeoutp, int sizelimit );
#else /* NEEDPROTOS */
BerElement *ldap_build_search_req();
#endif /* NEEDPROTOS */

static int put_extensible_filter( BerElement *ber, char *type, char *val );

/*
 * in unbind.c
 */
#ifdef NEEDPROTOS
int ldap_ld_free( LDAP *ld, int close );
int send_unbind( LDAP *ld, Sockbuf *sb );
#else /* NEEDPROTOS */
int ldap_ld_free();
int send_unbind();
#endif /* NEEDPROTOS */


#ifdef LDAP_DNS
/*
 * in getdxbyname.c
 */
#ifdef NEEDPROTOS
char **getdxbyname( char *domain );
#else /* NEEDPROTOS */
char **getdxbyname();
#endif /* NEEDPROTOS */
#endif /* LDAP_DNS */
	
/*
 * abandon.c 
 */
#ifdef NEEDPROTOS
BerElement * ldap_build_abandon_req( LDAP *ld, int msgid, LDAPControl ** serverctrls);
#else
BerElement * ldap_build_abandon_req();
#endif

/* add.c */
#ifdef NEEDPROTOS
BerElement * ldap_build_add_req(LDAP *ld, char *dn, LDAPMod **attrs, LDAPControl ** serverctrls);
#else
BerElement * ldap_build_add_req();
#endif

/*
 * compare.c 
 */
#ifdef NEEDPROTOS
BerElement * ldap_build_compare_req(LDAP *ld, char *dn, char *attr,	struct berval *bvalue, LDAPControl **serverctrls);
#else
BerElement * ldap_build_compare_req();
#endif

/*
 * delete.c 
 */
#ifdef NEEDPROTOS
BerElement * ldap_build_delete_req(LDAP *ld, char *dn, LDAPControl **serverctrls);
#else
BerElement * ldap_build_delete_req();
#endif

/*
 * extop.c 
 */
#ifdef NEEDPROTOS
BerElement * ldap_build_extended_operation_req(LDAP *ld, char *exoid, struct berval *exdata, LDAPControl ** serverctrls);
#else
BerElement * ldap_build_extended_operation_req();
#endif

/*
 * modify.c 
 */
#ifdef NEEDPROTOS
BerElement * ldap_build_modify_req(LDAP *ld, char *dn, LDAPMod ** mods, LDAPControl **serverctrls);
#else
BerElement * ldap_build_modify_req();
#endif

/*
 * rename.c 
 */
#ifdef NEEDPROTOS
BerElement * ldap_build_rename_req ( LDAP *ld, char *dn, char *newrdn, char *newparent, int deleteoldrdn, LDAPControl **serverctrls);
#else
BerElement * ldap_build_rename_req ();
#endif

/*
 * saslbind.c 
 */
#ifdef NEEDPROTOS
BerElement * ldap_build_sasl_bind_req( LDAP *ld, char *dn, char *mechanism, struct berval *creds, LDAPControl ** serverctrls);
#else
BerElement * ldap_build_sasl_bind_req();
#endif
/*
 * sbind.c 
 */
#ifdef NEEDPROTOS
BerElement * ldap_build_simple_bind_req(LDAP *ld, char *dn, char *passwd, LDAPControl **serverctrls);
#else
BerElement * ldap_build_simple_bind_req();
#endif

/*
 * utils.c
 */

#ifdef NEEDPROTOS
void free_strarray(char **sap);
#else
void free_strarray();
#endif

/* 
 * Controls.c 
 */
#ifdef NEEDPROTOS
LDAPControl * ldap_control_dup(LDAPControl *ctrl);
LDAPControl ** ldap_controls_dup(LDAPControl ** ctrls);
int ldap_controls_code (BerElement *ber, LDAPControl **ctrls);
LDAPControl ** ldap_controls_decode(BerElement *ber, int *errcode);
int ldap_build_control(char *oid, BerElement *ber, int freeber,
	char iscritical, LDAPControl **ctrlp);
#else
LDAPControl * ldap_control_dup();
LDAPControl ** ldap_controls_dup();
int ldap_controls_code ();
LDAPControl ** ldap_controls_decode();
int ldap_build_control();
#endif

/* 
 * ber/io.c 
 */
#ifdef NEEDPROTOS
int ber_flush(Sockbuf *sb, BerElement *ber, int freeit);
unsigned int ber_get_next(Sockbuf *sb, unsigned int *len, BerElement *ber);
#else
int ber_flush();
unsigned int ber_get_next();
#endif

