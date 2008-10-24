/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * lib/kad5/kadm_host_srv_names.c
 */

#include <k5-int.h>
#include "admin.h"
#include <stdio.h>
#include <os-proto.h>


#define	KADM5_MASTER "admin_server"
#define	KADM5_KPASSWD "kpasswd_server"

/*
 * Find the admin server for the given realm. If the realm is null or
 * the empty string, find the admin server for the default realm.
 * Returns 0 on succsess (KADM5_OK). It is the callers responsibility to
 * free the storage allocated to the admin server, master.
 */
kadm5_ret_t
kadm5_get_master(krb5_context context, const char *realm, char **master)
{
	char *def_realm;
	char *delim;
#ifdef KRB5_DNS_LOOKUP
	struct sockaddr *addrs;
	int naddrs;
	unsigned short dns_portno;
	char dns_host[MAX_DNS_NAMELEN];
	krb5_data dns_realm;
	krb5_error_code dns_ret = 1;
#endif /* KRB5_DNS_LOOKUP */

	if (realm == 0 || *realm == '\0')
		krb5_get_default_realm(context, &def_realm);

	(void) profile_get_string(context->profile, "realms",
	    realm ? realm : def_realm,
	    KADM5_MASTER, 0, master);

	if ((*master != NULL) && ((delim = strchr(*master, ':')) != NULL))
		*delim = '\0';
#ifdef KRB5_DNS_LOOKUP
	if (*master == NULL) {
		/*
		 * Initialize realm info for (possible) DNS lookups.
		 */
		dns_realm.data = strdup(realm ? realm : def_realm);
		dns_realm.length = strlen(realm ? realm : def_realm);
		dns_realm.magic = 0;

		dns_ret = krb5_get_servername(context, &dns_realm,
		    "_kerberos-adm", "_udp",
		    dns_host, &dns_portno);
		if (dns_ret == 0)
			*master = strdup(dns_host);

		if (dns_realm.data)
			free(dns_realm.data);
	}
#endif /* KRB5_DNS_LOOKUP */
	return (*master ? KADM5_OK : KADM5_NO_SRV);
}

/*
 * Find the kpasswd server for the given realm. If the realm is null or
 * the empty string, find the admin server for the default realm.
 * Returns 0 on succsess (KADM5_OK). It is the callers responsibility to
 * free the storage allocated to the admin server, master.
 */
kadm5_ret_t
kadm5_get_kpasswd(krb5_context context, const char *realm, char **kpasswd)
{
	char *def_realm = NULL;
	char *delim;
#ifdef KRB5_DNS_LOOKUP
	struct sockaddr *addrs;
	int naddrs;
	unsigned short dns_portno;
	char dns_host[MAX_DNS_NAMELEN];
	krb5_data dns_realm;
	krb5_error_code dns_ret = 1, ret;
#endif /* KRB5_DNS_LOOKUP */

	if (realm == 0 || *realm == '\0') {
		ret = krb5_get_default_realm(context, &def_realm);
		if (ret != 0)
			return (ret);
	}

	(void) profile_get_string(context->profile, "realms",
	    realm ? realm : def_realm,
	    KADM5_KPASSWD, 0, kpasswd);

	if ((*kpasswd != NULL) && ((delim = strchr(*kpasswd, ':')) != NULL))
		*delim = '\0';
#ifdef KRB5_DNS_LOOKUP
	if (*kpasswd == NULL) {
		/*
		 * Initialize realm info for (possible) DNS lookups.
		 */
		dns_realm.data = strdup(realm ? realm : def_realm);
		if (dns_realm.data == NULL) {
			if (def_realm != NULL)
				free(def_realm);
			return (ENOMEM);
		}
		dns_realm.length = strlen(realm ? realm : def_realm);
		dns_realm.magic = 0;

		dns_ret = krb5_get_servername(context, &dns_realm,
		    "_kpasswd", "_tcp",
		    dns_host, &dns_portno);
		if (dns_ret == 0) {
			*kpasswd = strdup(dns_host);

			if (*kpasswd == NULL) {
				free(dns_realm.data);
				if (def_realm != NULL)
					free(def_realm);
				return (ENOMEM);
			}
		}

		free(dns_realm.data);
	}
#endif /* KRB5_DNS_LOOKUP */

	if (def_realm != NULL)
		free(def_realm);
	return (*kpasswd ? KADM5_OK : KADM5_NO_SRV);
}

/*
 * Get the host base service name for the admin principal. Returns
 * KADM5_OK on success. Caller must free the storage allocated for
 * host_service_name.
 */
kadm5_ret_t
kadm5_get_adm_host_srv_name(krb5_context context,
			    const char *realm, char **host_service_name)
{
	kadm5_ret_t ret;
	char *name;
	char *host;


	if (ret = kadm5_get_master(context, realm, &host))
		return (ret);

	name = malloc(strlen(KADM5_ADMIN_HOST_SERVICE)+ strlen(host) + 2);
	if (name == NULL) {
		free(host);
		return (ENOMEM);
	}
	sprintf(name, "%s@%s", KADM5_ADMIN_HOST_SERVICE, host);
	free(host);
	*host_service_name = name;

	return (KADM5_OK);
}

/*
 * Get the host base service name for the changepw principal. Returns
 * KADM5_OK on success. Caller must free the storage allocated for
 * host_service_name.
 */
kadm5_ret_t
kadm5_get_cpw_host_srv_name(krb5_context context,
			    const char *realm, char **host_service_name)
{
	kadm5_ret_t ret;
	char *name;
	char *host;

	/*
	 * First try to find the kpasswd server, after all we are about to
	 * try to change our password.  If this fails then try admin_server.
	 */
	if (ret = kadm5_get_kpasswd(context, realm, &host)) {
		if (ret = kadm5_get_master(context, realm, &host))
			return (ret);
	}

	name = malloc(strlen(KADM5_CHANGEPW_HOST_SERVICE) + strlen(host) + 2);
	if (name == NULL) {
		free(host);
		return (ENOMEM);
	}
	sprintf(name, "%s@%s", KADM5_CHANGEPW_HOST_SERVICE, host);
	free(host);
	*host_service_name = name;

	return (KADM5_OK);
}

/*
 * Get the host base service name for the kiprop principal. Returns
 * KADM5_OK on success. Caller must free the storage allocated
 * for host_service_name.
 */
kadm5_ret_t kadm5_get_kiprop_host_srv_name(krb5_context context,
				    const char *realm,
				    char **host_service_name) {
	kadm5_ret_t ret;
	char *name;
	char *host;


	if (ret = kadm5_get_master(context, realm, &host))
		return (ret);

	name = malloc(strlen(KADM5_KIPROP_HOST_SERVICE) + strlen(host) + 2);
	if (name == NULL) {
		free(host);
		return (ENOMEM);
	}
	sprintf(name, "%s@%s", KADM5_KIPROP_HOST_SERVICE, host);
	free(host);
	*host_service_name = name;

	return (KADM5_OK);
}

/*
 * Solaris Kerberos:
 * Try to determine if this is the master KDC for a given realm
 */
kadm5_ret_t kadm5_is_master(krb5_context context, const char *realm,
    krb5_boolean *is_master) {

	kadm5_ret_t ret;
	char *admin_host = NULL;
	krb5_address **master_addr = NULL;
	krb5_address **local_addr = NULL;

	if (is_master)
		*is_master = FALSE;
	else
		return (KADM5_FAILURE);

	/* Locate the master KDC */
	if (ret = kadm5_get_master(context, realm, &admin_host))
		return (ret);

	if (ret = krb5_os_hostaddr(context, admin_host, &master_addr)) {
		free(admin_host);
		return (ret);
	}

	/* Get the local addresses */
	if (ret = krb5_os_localaddr(context, &local_addr)) {
		krb5_free_addresses(context, master_addr);
		free(admin_host);
		return (ret);
	}

	/* Compare them */
	for (; *master_addr; master_addr++) {
		if (krb5_address_search(context, *master_addr, local_addr)) {
			*is_master = TRUE;
			break;
		}
	}

	krb5_free_addresses(context, local_addr);
	krb5_free_addresses(context, master_addr);
	free(admin_host);

	return (KADM5_OK);
}
