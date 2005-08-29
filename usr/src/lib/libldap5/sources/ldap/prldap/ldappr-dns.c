/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * The contents of this file are subject to the Netscape Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/NPL/
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * The Original Code is Mozilla Communicator client code, released
 * March 31, 1998.
 *
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation. Portions created by Netscape are
 * Copyright (C) 1998-1999 Netscape Communications Corporation. All
 * Rights Reserved.
 *
 * Contributor(s):
 */

/*
 * DNS callback functions for libldap that use the NSPR (Netscape
 * Portable Runtime) thread API.
 *
 */

#ifdef _SOLARIS_SDK
#include "solaris-int.h"
#include <libintl.h>
#include <syslog.h>
#include <nsswitch.h>
#include <synch.h>
#include <nss_dbdefs.h>
#include <netinet/in.h>
static char *host_service = NULL;
static DEFINE_NSS_DB_ROOT(db_root_hosts);
#endif

#include "ldappr-int.h"

static LDAPHostEnt *prldap_gethostbyname( const char *name,
	LDAPHostEnt *result, char *buffer, int buflen, int *statusp,
	void *extradata );
static LDAPHostEnt *prldap_gethostbyaddr( const char *addr, int length,
	int type, LDAPHostEnt *result, char *buffer, int buflen,
	int *statusp, void *extradata );
static int prldap_getpeername( LDAP *ld, struct sockaddr *addr,
	char *buffer, int buflen );
static LDAPHostEnt *prldap_convert_hostent( LDAPHostEnt *ldhp,
	PRHostEnt *prhp );

#ifdef _SOLARIS_SDK
static LDAPHostEnt *
prldap_gethostbyname1(const char *name, LDAPHostEnt *result,
	char *buffer, int buflen, int *statusp, void *extradata);
extern int
str2hostent(const char *instr, int lenstr, void *ent, char *buffer,
	int buflen);
#endif /* _SOLARIS_SDK */


/*
 * Install NSPR DNS functions into ld (if ld is NULL, they are installed
 * as the default functions for new LDAP * handles).
 *
 * Returns 0 if all goes well and -1 if not.
 */
int
prldap_install_dns_functions( LDAP *ld )
{
    struct ldap_dns_fns			dnsfns;

    memset( &dnsfns, '\0', sizeof(struct ldap_dns_fns) );
    dnsfns.lddnsfn_bufsize = PR_NETDB_BUF_SIZE;
    dnsfns.lddnsfn_gethostbyname = prldap_gethostbyname;
    dnsfns.lddnsfn_gethostbyaddr = prldap_gethostbyaddr;
	    dnsfns.lddnsfn_getpeername = prldap_getpeername;
	    if ( ldap_set_option( ld, LDAP_OPT_DNS_FN_PTRS, (void *)&dnsfns ) != 0 ) {
		return( -1 );
	    }

    return( 0 );
}


static LDAPHostEnt *
prldap_gethostbyname( const char *name, LDAPHostEnt *result,
	char *buffer, int buflen, int *statusp, void *extradata )
{
	PRHostEnt	prhent;

	if( !statusp || ( *statusp = (int)PR_GetIPNodeByName( name,
		PRLDAP_DEFAULT_ADDRESS_FAMILY, PR_AI_DEFAULT,
		buffer, buflen, &prhent )) == PR_FAILURE ) {
		return( NULL );
	}

	return( prldap_convert_hostent( result, &prhent ));
}


static LDAPHostEnt *
prldap_gethostbyaddr( const char *addr, int length, int type,
	LDAPHostEnt *result, char *buffer, int buflen, int *statusp,
	void *extradata )
{
    PRHostEnt	prhent;
    PRNetAddr	iaddr;

	if ( PR_SetNetAddr(PR_IpAddrNull, PRLDAP_DEFAULT_ADDRESS_FAMILY,
		0, &iaddr) == PR_FAILURE
 		|| PR_StringToNetAddr( addr, &iaddr ) == PR_FAILURE ) {
		return( NULL );
	}

    if( !statusp || (*statusp = PR_GetHostByAddr(&iaddr, buffer,
	     buflen, &prhent )) == PR_FAILURE ) {
	return( NULL );
    }
    return( prldap_convert_hostent( result, &prhent ));
}

static int
prldap_getpeername( LDAP *ld, struct sockaddr *addr, char *buffer, int buflen)
{
    PRLDAPIOSocketArg *sa;
    PRFileDesc	*fd;
    PRNetAddr	iaddr;
    int		ret;

    if (NULL != ld) {
	    ret = prldap_socket_arg_from_ld( ld, &sa );
	    if (ret != LDAP_SUCCESS) {
		return (-1);
	    }
	    ret = PR_GetPeerName(sa->prsock_prfd, &iaddr);
	    if( ret == PR_FAILURE ) {
		return( -1 );
	    }
	    *addr = *((struct sockaddr *)&iaddr.raw);
	    ret = PR_NetAddrToString(&iaddr, buffer, buflen);
	    if( ret == PR_FAILURE ) {
		return( -1 );
	    }
	    return (0);
    }
    return (-1);
}


/*
 * Function: prldap_convert_hostent()
 * Description: copy the fields of a PRHostEnt struct to an LDAPHostEnt
 * Returns: the LDAPHostEnt pointer passed in.
 */
static LDAPHostEnt *
prldap_convert_hostent( LDAPHostEnt *ldhp, PRHostEnt *prhp )
{
	ldhp->ldaphe_name = prhp->h_name;
	ldhp->ldaphe_aliases = prhp->h_aliases;
	ldhp->ldaphe_addrtype = prhp->h_addrtype;
	ldhp->ldaphe_length =  prhp->h_length;
	ldhp->ldaphe_addr_list =  prhp->h_addr_list;
	return( ldhp );
}

#ifdef _SOLARIS_SDK
/*
 * prldap_x_install_dns_skipdb attempts to prevent recursion in resolving
 * the hostname to an IP address when a host name is given to LDAP user.
 *
 * For example, libsldap cannot use LDAP to resolve the host name to an
 * address because of recursion. The caller is instructing libldap to skip
 * the specified name service when resolving addresses for the specified
 * ldap connection.
 *
 * Note:
 *      This only supports ipv4 addresses currently.
 *
 *      Since host_service applies to all connections, calling
 *      prldap_x_install_dns_skipdb with name services other than
 *      ldap or what uses ldap (for example nis+ might use ldap) to
 *      skip will lead to unpredictable results.
 *
 * Returns:
 *      0       if success and data base found
 *      -1      if failure
 */

int
prldap_x_install_dns_skipdb(LDAP *ld, const char *skip)
{
	enum __nsw_parse_err		pserr;
	struct __nsw_switchconfig       *conf;
	struct __nsw_lookup             *lkp;
	struct ldap_dns_fns             dns_fns;
	char                            *name_list = NULL;
	char                            *tmp;
	const char                      *name;
	int                             len;
	boolean_t                       got_skip = B_FALSE;

	/*
	 * db_root_hosts.lock mutex is used to ensure that the name list
	 * is not in use by the name service switch while we are updating
	 * the host_service
	 */

        (void) mutex_lock(&db_root_hosts.lock);
        conf = __nsw_getconfig("hosts", &pserr);
        if (conf == NULL) {
                (void) mutex_unlock(&db_root_hosts.lock);
                return (0);
        }

        /* check for skip and count other backends */
        for (lkp = conf->lookups; lkp != NULL; lkp = lkp->next) {
                name = lkp->service_name;
                if (strcmp(name, skip) == 0) {
                        got_skip = B_TRUE;
                        continue;
                }
                if (name_list == NULL)
                        name_list = strdup(name);
                else {
                        len = strlen(name_list);
                        tmp = realloc(name_list, len + strlen(name) + 2);
                        if (tmp == NULL) {
                                free(name_list);
                                name_list = NULL;
                        } else {
                                name_list = tmp;
                                name_list[len++] = ' ';
                                (void) strcpy(name_list+len, name);
                        }
                }
                if (name_list == NULL) {        /* alloc error */
                        (void) mutex_unlock(&db_root_hosts.lock);
                        __nsw_freeconfig(conf);
                        return (-1);
                }
        }
        __nsw_freeconfig(conf);
        if (!got_skip) {
		/*
		 * Since skip name service not used for hosts, we do not need
		 * to install our private address resolution function
		 */
                (void) mutex_unlock(&db_root_hosts.lock);
                if (name_list != NULL)
                        free(name_list);
                return (0);
        }
        if (host_service != NULL)
                free(host_service);
        host_service = name_list;
        (void) mutex_unlock(&db_root_hosts.lock);

        if (ldap_get_option(ld, LDAP_OPT_DNS_FN_PTRS, &dns_fns) != 0)
                return (-1);
        dns_fns.lddnsfn_bufsize = PR_NETDB_BUF_SIZE;
        dns_fns.lddnsfn_gethostbyname = prldap_gethostbyname1;
        if (ldap_set_option(ld, LDAP_OPT_DNS_FN_PTRS, &dns_fns) != 0)
                return (-1);
        return (0);
}

/*
 * prldap_initf_hosts is passed to and called by nss_search() as a
 * service routine.
 *
 * Returns:
 *      None
 */

static void
prldap_initf_hosts(nss_db_params_t *p)
{
        static char *no_service = "";

        p->name = NSS_DBNAM_HOSTS;
        p->flags |= NSS_USE_DEFAULT_CONFIG;
        p->default_config = host_service == NULL ? no_service : host_service;
}

/*
 * called by prldap_gethostbyname1()
 */
/*
 * prldap_switch_gethostbyname_r is called by prldap_gethostbyname1 as a
 * substitute for gethostbyname_r(). A method which prevents recursion. see
 * prldap_gethostbyname1() and prldap_x_install_dns_skipdb().
 *
 * Returns:
 *      PR_SUCCESS                    if success
 *      PR_FAILURE                    if failure
 */

static int
prldap_switch_gethostbyname_r(const char *name,
        struct hostent *result, char *buffer, int buflen,
        int *h_errnop)
{
        nss_XbyY_args_t arg;
        nss_status_t    res;
	struct hostent	*resp;

	/*
	 * Log the information indicating that we are trying to
	 * resolve the LDAP server name.
	 */
	syslog(LOG_INFO, "libldap: Resolving server name \"%s\"", name);

        NSS_XbyY_INIT(&arg, result, buffer, buflen, str2hostent);

        arg.key.name = name;
        arg.stayopen = 0;

        res = nss_search(&db_root_hosts, prldap_initf_hosts,
            NSS_DBOP_HOSTS_BYNAME, &arg);
        arg.status = res;
        *h_errnop = arg.h_errno;
	resp = (struct hostent *)NSS_XbyY_FINI(&arg);

	return (resp != NULL ? PR_SUCCESS : PR_FAILURE);
}

/*
 * prldap_gethostbyname1 is used to be a substitute gethostbyname_r for
 * libldap when it is unsafe to use the normal nameservice functions.
 *
 * Returns:
 *      pointer to LDAPHostEnt:         if success contains the address
 *      NULL pointer:                   if failure
 */

static LDAPHostEnt *
prldap_gethostbyname1(const char *name, LDAPHostEnt *result,
	char *buffer, int buflen, int *statusp, void *extradata)
{
        int         h_errno;
	LDAPHostEnt prhent;

	memset(&prhent, '\0', sizeof (prhent));
        if (!statusp || ( *statusp = prldap_switch_gethostbyname_r(name,
                        &prhent, buffer, buflen, &h_errno )) == PR_FAILURE) {
		/*
		 * If we got here, it means that we are not able to
		 * resolve the LDAP server name and so warn the system
		 * adminstrator accordingly.
		 */
		syslog(LOG_WARNING, "libldap: server name \"%s\" could not "
		"be resolved", name);
		return (NULL);
        }

        return (prldap_convert_hostent(result, &prhent));
}

#endif  /* _SOLARIS_SDK */
