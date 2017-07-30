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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "iscsi.h"
#include "nvfile.h"
#include "persistent.h"
#include <sys/scsi/adapters/iscsi_if.h>
#include <netinet/in.h>

/*
 * MAX_KEY_SIZE needs to be the same size of the ISCSI_MAX_NAME_LEN
 * plus space for a ',' and a string form of tpgt (5 bytes).
 */
#define	MAX_KEY_SIZE	(ISCSI_MAX_NAME_LEN + 5)

/*
 * Name identifiers for the various types of data
 */
#define	DISCOVERY_METHOD_ID		"DiscMethod"
#define	NODE_NAME_ID			"NodeName"
#define	NODE_ALIAS_ID			"NodeAlias"
#define	STATIC_ADDR_ID			"StaticAddr"
#define	STATIC_ADDR2_ID			"StaticAddr2"
#define	DISCOVERY_ADDR_ID		"DiscAddr"
#define	ISNS_SERVER_ADDR_ID		"ISNSAddr"
#define	LOGIN_PARAMS_ID			"Login"
#define	CHAP_PARAMS_ID			"Chap"
#define	RADIUS_PARAMS_ID		"Radius"
#define	BIDIR_AUTH_PARAMS_ID		"BidirAuth"
#define	SESSION_PARAMS_ID		"Session"
#define	TUNABLE_PARAMS_ID		"Tunable"

/*
 *  Local Global Variables
 */
static kmutex_t		static_addr_data_lock;
static kmutex_t		disc_addr_data_lock;
static kmutex_t		isns_addr_data_lock;
static kmutex_t		param_data_lock;
static kmutex_t		chap_data_lock;
static kmutex_t		auth_data_lock;
static kmutex_t		tunable_data_lock;
/*
 *  Local Function Prototypes
 */
static boolean_t persistent_disc_meth_common(iSCSIDiscoveryMethod_t method,
		    boolean_t do_clear);
static void persistent_static_addr_upgrade_to_v2();

/*
 * This wrapper keeps old inet_ntop() behaviour and should be called when
 * IP addresses are used as keys into persistent storage.
 */
static void
iscsi_inet_ntop(int af, const void *addr, char *buf)
{
#define	UC(b)	(((int)b) & 0xff)
	if (af == AF_INET) {
		uchar_t *v4addr = (uchar_t *)addr;
		(void) snprintf(buf, INET6_ADDRSTRLEN, "%03d.%03d.%03d.%03d",
		    UC(v4addr[0]), UC(v4addr[1]), UC(v4addr[2]), UC(v4addr[3]));
	} else {
		(void) inet_ntop(af, addr, buf, INET6_ADDRSTRLEN);
	}
#undef	UC
}

/*
 * persistent_init_disc_addr_oids - Oid is stored with discovery address
 * however oids are not persisted and the discovery address oids need to
 * be regenerated during initialization.
 */
static void
persistent_init_disc_addr_oids()
{
	uint32_t addr_count = 0;
	void *void_p = NULL;
	entry_t	e;
	uint32_t i, curr_count;

	/*
	 * Using two loops here as as addresses are updated and readded we get
	 * into an infinite loop while doing persistent_disc_addr_next if we
	 * update the entry as we go.  The first loop will get the number of
	 * addresses that need to be updated and the second will update that
	 * many addresses.
	 */
	persistent_disc_addr_lock();
	while (persistent_disc_addr_next(&void_p, &e) == B_TRUE) {
		addr_count++;
	}
	persistent_disc_addr_unlock();

	for (i = 0; i < addr_count; i++) {
		curr_count = 0;

		void_p = NULL;
		persistent_disc_addr_lock();

		/* Use curr_count to skip previously updated addresses */
		while (persistent_disc_addr_next(&void_p, &e) ==
		    B_TRUE && i < curr_count) {
			curr_count++;
		}
		persistent_disc_addr_unlock();

		mutex_enter(&iscsi_oid_mutex);
		e.e_oid = iscsi_oid++;
		mutex_exit(&iscsi_oid_mutex);

		if (persistent_disc_addr_set(&e) == B_FALSE) {
			break;
		}
	}
}

/*
 * persistent_init_static_addr_oids - Oid is stored with static address
 * however oids are not persisted and the static address oids need to
 * be regenerated during initialization.
 */
static void
persistent_init_static_addr_oids()
{
	uint32_t addr_count = 0;
	void *void_p = NULL;
	entry_t	e;
	uint32_t i, curr_count;
	char	*target_name;

	/*
	 * Solaris 10 Update 1/2 initially had a database
	 * that didn't support the multiple static-config
	 * entries to the same target.  The below call
	 * will check if the database is still of that
	 * old structure and upgrade it.  It will leave
	 * the old records incase a down grade of the
	 * software is required.
	 */
	persistent_static_addr_upgrade_to_v2();

	/*
	 * Using two loops here as as addresses are updated and readded we get
	 * into an infinite loop while doing persistent_disc_addr_next if we
	 * update the entry as we go.  The first loop will get the number of
	 * addresses that need to be updated and the second will update that
	 * many addresses.
	 */
	target_name = kmem_alloc(MAX_KEY_SIZE, KM_SLEEP);
	persistent_static_addr_lock();
	while (persistent_static_addr_next(&void_p, target_name, &e) ==
	    B_TRUE) {
		addr_count++;
	}

	for (i = 0; i < addr_count; i++) {
		curr_count = 0;

		void_p = NULL;

		/* Use curr_count to skip previously updated addresses */
		while ((persistent_static_addr_next(
		    &void_p, target_name, &e) == B_TRUE) &&
		    (i < curr_count)) {
			curr_count++;
		}

		/* Skip the target whose address size length is 0 */
		if (e.e_insize == 0) {
			continue;
		}

		mutex_enter(&iscsi_oid_mutex);
		e.e_oid = iscsi_oid++;
		mutex_exit(&iscsi_oid_mutex);

		if (persistent_static_addr_set(target_name, &e) == B_FALSE) {
			break;
		}
	}
	persistent_static_addr_unlock();
	kmem_free(target_name, MAX_KEY_SIZE);
}

/*
 * persistent_static_addr_upgrade_to_v2 - checks to see if the
 * STATIC_ADDR2_ID exists in the persistent store tree.  If not
 * found then it converts the STATIC_ADDR_ID data into the
 * STATIC_ADDR2_ID format and saves the branch.
 */
static void
persistent_static_addr_upgrade_to_v2()
{
	entry_t	    e;
	char	    *target_name;
	char	    *c_end;
	void	    *void_p = NULL;

	/*
	 * Check is version 2 of STATIC_ADDR list exists.
	 */
	target_name = kmem_zalloc(MAX_KEY_SIZE, KM_SLEEP);
	persistent_static_addr_lock();
	if (nvf_list_check(STATIC_ADDR2_ID) == B_FALSE) {
		/*
		 * We need to upgrade any existing
		 * STATIC_ADDR data to version 2.  Loop
		 * thru all old entries and set new version
		 * values.
		 */
		while (nvf_data_next(STATIC_ADDR_ID, &void_p,
		    target_name, (void *)&e, sizeof (e)) == B_TRUE) {
			/* Convert STATIC_ADDR to STATIC_ADDR2 */
			c_end = strchr(target_name, ',');
			if (c_end == NULL) {
				continue;
			}
			*c_end = '\0';
			/* Skip the target whose address size length is 0 */
			if (e.e_insize == 0) {
				continue;
			}
			/* Add updated record */
			(void) persistent_static_addr_set(target_name, &e);
		}
	}
	persistent_static_addr_unlock();
	kmem_free(target_name, MAX_KEY_SIZE);
}

/*
 * persistent_init -- initialize use of the persistent store
 */
void
persistent_init()
{
	nvf_init();
	mutex_init(&static_addr_data_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&disc_addr_data_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&isns_addr_data_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&param_data_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&chap_data_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&auth_data_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&tunable_data_lock, NULL, MUTEX_DRIVER, NULL);
}

/*
 * persistent_load -- load the persistent store
 */
boolean_t
persistent_load()
{
	boolean_t	rval = B_FALSE;

	rval = nvf_load();
	if (rval == B_TRUE) {
		persistent_init_disc_addr_oids();
		persistent_init_static_addr_oids();
	}

	return (rval);
}

/*
 * persistent_fini --  finish using the persistent store
 */
void
persistent_fini(void)
{
	nvf_fini();

	mutex_destroy(&static_addr_data_lock);
	mutex_destroy(&disc_addr_data_lock);
	mutex_destroy(&param_data_lock);
	mutex_destroy(&chap_data_lock);
	mutex_destroy(&auth_data_lock);
	mutex_destroy(&tunable_data_lock);
}


/*
 * +--------------------------------------------------------------------+
 * | Discovery Method Interfaces                                        |
 * +--------------------------------------------------------------------+
 */

/*
 * persistent_disc_meth_set -- enable a specific discovery method
 */
boolean_t
persistent_disc_meth_set(iSCSIDiscoveryMethod_t method)
{
	return (persistent_disc_meth_common(method, B_FALSE));
}

/*
 * persistent_disc_meth_get -- return the status of all discovery methods as
 * found in the persistent store
 */
iSCSIDiscoveryMethod_t
persistent_disc_meth_get(void)
{
	boolean_t		rval;
	iSCSIDiscoveryMethod_t	methods;

	rval = nvf_node_value_get(DISCOVERY_METHOD_ID, (uint32_t *)&methods);
	if (rval == B_FALSE) {
		methods = iSCSIDiscoveryMethodUnknown;
	}

	return (methods);
}

/*
 * persistent_disc_meth_clear -- disable a specific discovery method
 */
boolean_t
persistent_disc_meth_clear(iSCSIDiscoveryMethod_t method)
{
	return (persistent_disc_meth_common(method, B_TRUE));
}



/*
 * persistent_disc_meth_common - common function used to set or clear the
 * status of a discovery method in the persistent store.
 */
static boolean_t
persistent_disc_meth_common(iSCSIDiscoveryMethod_t method, boolean_t do_clear)
{
	boolean_t		rval;
	iSCSIDiscoveryMethod_t	discovery_types = iSCSIDiscoveryMethodUnknown;

	(void) nvf_node_value_get(DISCOVERY_METHOD_ID,
	    (uint32_t *)&discovery_types);
	if (do_clear) {
		discovery_types &= ~method;
	} else {
		discovery_types |= method;
	}

	rval = nvf_node_value_set(DISCOVERY_METHOD_ID, discovery_types);

	return (rval);
}



/*
 * +--------------------------------------------------------------------+
 * | Node/Initiator Name Interfaces                                     |
 * +--------------------------------------------------------------------+
 */

/*
 * persistent_initiator_name_set -- sets the node's initiator name
 */
boolean_t
persistent_initiator_name_set(char *p)
{
	return (nvf_node_name_set(NODE_NAME_ID, p));
}

/*
 * persistent_initiator_name_get -- returns the node's initiator name
 */
boolean_t
persistent_initiator_name_get(char *p, int size)
{
	return (nvf_node_name_get(NODE_NAME_ID, p, size));
}


/*
 * +--------------------------------------------------------------------+
 * | Node/Initiator Alias Interfaces                                    |
 * +--------------------------------------------------------------------+
 */

/*
 * persistent_alias_name_set -- sets the node's initiator name alias
 */
boolean_t
persistent_alias_name_set(char *p)
{
	return (nvf_node_name_set(NODE_ALIAS_ID, p));
}

/*
 * persistent_initiator_name_get -- returns the node's initiator name alias
 */
boolean_t
persistent_alias_name_get(char *p, int size)
{
	return (nvf_node_name_get(NODE_ALIAS_ID, p, size));
}


/*
 * +--------------------------------------------------------------------+
 * | Static Target Address Interfaces                                   |
 * +--------------------------------------------------------------------+
 */

/*
 * persistent_static_addr_set -- store hostname, IP address, and port
 * information for a specific target.
 */
boolean_t
persistent_static_addr_set(char *target_name, entry_t *e)
{
	boolean_t	rval;
	char		*key;
	char		*ip_str;

	ASSERT(target_name != NULL);
	ASSERT(e != NULL);
	ASSERT(mutex_owned(&static_addr_data_lock));

	key = kmem_zalloc(MAX_KEY_SIZE, KM_SLEEP);
	ip_str = kmem_zalloc(INET6_ADDRSTRLEN, KM_SLEEP);
	if (e->e_insize == sizeof (struct in_addr))
		iscsi_inet_ntop(AF_INET, &e->e_u.u_in4, ip_str);
	else
		iscsi_inet_ntop(AF_INET6, &e->e_u.u_in6, ip_str);

	if (snprintf(key, MAX_KEY_SIZE - 1, "%s,%s:%d,%d",
	    target_name, ip_str, e->e_port, e->e_tpgt) >= MAX_KEY_SIZE) {
		kmem_free(key, MAX_KEY_SIZE);
		kmem_free(ip_str, INET6_ADDRSTRLEN);
		return (B_FALSE);
	}

	rval = nvf_data_set(STATIC_ADDR2_ID, key, (void *)e,
	    sizeof (entry_t));

	kmem_free(key, MAX_KEY_SIZE);
	kmem_free(ip_str, INET6_ADDRSTRLEN);
	return (rval);
}

/*
 * persistent_static_addr_next -- get the next target's hostname, IP address,
 * and port information.
 *
 * The first time this function is called, the argument (void **v)
 * should be a pointer to a value of NULL which causes this function to obtain
 * the first static target element.
 *
 * This function assumes the associated static address lock is held.
 *
 * Returns B_TRUE when data is valid. B_FALSE returned when data is
 * not available (end of configured targets has been reached).
 *
 */
boolean_t
persistent_static_addr_next(void **v, char *target_name, entry_t *e)
{
	boolean_t   rval;
	char	    *c_end, *key;

	ASSERT(v != NULL);
	ASSERT(target_name != NULL);
	ASSERT(e != NULL);
	ASSERT(mutex_owned(&static_addr_data_lock));

	key = kmem_zalloc(MAX_KEY_SIZE, KM_SLEEP);
	rval = nvf_data_next(STATIC_ADDR2_ID, v, key,
	    (void *)e, sizeof (*e));

	/* extract target_name */
	c_end = strchr(key, ',');
	if (c_end == NULL) {
		kmem_free(key, MAX_KEY_SIZE);
		return (B_FALSE);
	}
	*c_end = '\0';
	/* copy target name */
	(void) strcpy(target_name, key);

	kmem_free(key, MAX_KEY_SIZE);

	return (rval);
}

/*
 * persistent_static_addr_clear -- remove the next hostname, IP address, and
 * port information for a specific target from the configured static targets.
 */
boolean_t
persistent_static_addr_clear(uint32_t oid)
{
	boolean_t	rval = B_FALSE;
	void		*void_p = NULL;
	entry_t		e;
	char		*key;
	char		*target_name;
	char		*ip_str;

	/* Find the entry based on oid then record the name and tpgt */
	target_name = kmem_zalloc(MAX_KEY_SIZE, KM_SLEEP);
	persistent_static_addr_lock();
	while (persistent_static_addr_next(
	    &void_p, target_name, &e) == B_TRUE) {
		if (e.e_oid == oid) {
			break;
		}
	}

	/* If we found a match clear the entry */
	if (e.e_oid == oid) {
		ip_str = kmem_zalloc(INET6_ADDRSTRLEN, KM_SLEEP);
		key = kmem_zalloc(MAX_KEY_SIZE, KM_SLEEP);
		if (e.e_insize == sizeof (struct in_addr))
			iscsi_inet_ntop(AF_INET, &e.e_u.u_in4, ip_str);
		else
			iscsi_inet_ntop(AF_INET6, &e.e_u.u_in6, ip_str);

		if (snprintf(key, MAX_KEY_SIZE - 1, "%s,%s:%d,%d",
		    target_name, ip_str, e.e_port, e.e_tpgt) >= MAX_KEY_SIZE) {
			persistent_static_addr_unlock();
			kmem_free(key, MAX_KEY_SIZE);
			kmem_free(ip_str, INET6_ADDRSTRLEN);
			kmem_free(target_name, MAX_KEY_SIZE);
			return (B_FALSE);
		}

		rval = nvf_data_clear(STATIC_ADDR2_ID, key);
		kmem_free(key, MAX_KEY_SIZE);
		kmem_free(ip_str, INET6_ADDRSTRLEN);
	}
	persistent_static_addr_unlock();
	kmem_free(target_name, MAX_KEY_SIZE);

	return (rval);
}


/*
 * persistent_static_addr_lock -- lock access to static targets.  This
 * ensures static targets are unchanged while the lock is held.  The
 * lock should be grabbed while walking through the static targets.
 */
void
persistent_static_addr_lock(void)
{
	mutex_enter(&static_addr_data_lock);
}

/*
 * persistent_static_addr_unlock -- unlock access to the configured of static
 * targets.
 */
void
persistent_static_addr_unlock(void)
{
	mutex_exit(&static_addr_data_lock);
}


/*
 * +--------------------------------------------------------------------+
 * | ISNS Server Address Interfaces                                     |
 * +--------------------------------------------------------------------+
 */

/*
 * persistent_addr_set -- store entry address information
 */
boolean_t
persistent_isns_addr_set(entry_t *e)
{
	char		name[INET6_ADDRSTRLEN];
	boolean_t	rval;

	/*
	 * Create name from given discovery address - SendTargets discovery
	 * nodes do not have an associated node name. A name is manufactured
	 * from the IP address given.
	 */
	if (e->e_insize == sizeof (struct in_addr))
		iscsi_inet_ntop(AF_INET, &e->e_u.u_in4, name);
	else
		iscsi_inet_ntop(AF_INET6, &e->e_u.u_in6, name);

	mutex_enter(&isns_addr_data_lock);
	rval = nvf_data_set(ISNS_SERVER_ADDR_ID, name,
	    (void *)e, sizeof (entry_t));
	mutex_exit(&isns_addr_data_lock);

	return (rval);
}

/*
 * persistent_disc_addr_next -- get the next iSCSI discovery node's address
 * and port information.
 *
 * The first time this function is called, the argument (void **v)
 * should be a pointer to a value of NULL which causes this function to obtain
 * the first discovery address element.
 *
 * This function assumes the associated disccovery address lock is held.
 *
 * Returns B_TRUE when data is valid. B_FALSE returned when data is
 * not available (end of configured discovery addresses has been reached).
 *
 */
boolean_t
persistent_isns_addr_next(void **v, entry_t *e)
{
	char		name[INET6_ADDRSTRLEN];

	ASSERT(mutex_owned(&isns_addr_data_lock));

	return (nvf_data_next(ISNS_SERVER_ADDR_ID, v, name,
	    (void *)e, sizeof (*e)));
}

/*
 * persistent_disc_addr_clear -- remove IP address and port information from
 * the configured SendTargets discovery nodes.
 */
boolean_t
persistent_isns_addr_clear(entry_t *e)
{
	char		name[INET6_ADDRSTRLEN];
	boolean_t	rval;

	/*
	 * Create name from given discovery address - SendTargets discovery
	 * nodes do not have an associated node name. A name is manufactured
	 * from the IP address given.
	 */
	if (e->e_insize == sizeof (struct in_addr))
		iscsi_inet_ntop(AF_INET, &e->e_u.u_in4, name);
	else
		iscsi_inet_ntop(AF_INET6, &e->e_u.u_in6, name);

	mutex_enter(&static_addr_data_lock);
	rval = nvf_data_clear(ISNS_SERVER_ADDR_ID, name);
	mutex_exit(&static_addr_data_lock);

	return (rval);
}


/*
 * persistent_disc_addr_lock -- lock access to the SendTargets discovery
 * addresses.  This ensures discovery addresses are unchanged while the lock
 * is held.  The lock should be grabbed while walking through the discovery
 * addresses
 */
void
persistent_isns_addr_lock(void)
{
	mutex_enter(&isns_addr_data_lock);
}

/*
 * persistent_disc_addr_unlock -- unlock access to discovery addresses.
 */
void
persistent_isns_addr_unlock(void)
{
	mutex_exit(&isns_addr_data_lock);
}

/*
 * +--------------------------------------------------------------------+
 * | Discovery Address Interfaces                                       |
 * +--------------------------------------------------------------------+
 */

/*
 * persistent_disc_addr_set -- store IP address, and port information for
 * for an iSCSI discovery node that provides target information via a
 * SendTargets response.
 */
boolean_t
persistent_disc_addr_set(entry_t *e)
{
	char		name[INET6_ADDRSTRLEN];
	boolean_t	rval;

	/*
	 * Create name from given discovery address - SendTargets discovery
	 * nodes do not have an associated node name. A name is manufactured
	 * from the IP address given.
	 */
	if (e->e_insize == sizeof (struct in_addr))
		iscsi_inet_ntop(AF_INET, &e->e_u.u_in4, name);
	else
		iscsi_inet_ntop(AF_INET6, &e->e_u.u_in6, name);

	mutex_enter(&disc_addr_data_lock);
	rval = nvf_data_set(DISCOVERY_ADDR_ID, name,
	    (void *)e, sizeof (entry_t));
	mutex_exit(&disc_addr_data_lock);

	return (rval);
}

/*
 * persistent_disc_addr_next -- get the next iSCSI discovery node's address
 * and port information.
 *
 * The first time this function is called, the argument (void **v)
 * should be a pointer to a value of NULL which causes this function to obtain
 * the first discovery address element.
 *
 * This function assumes the associated disccovery address lock is held.
 *
 * Returns B_TRUE when data is valid. B_FALSE returned when data is
 * not available (end of configured discovery addresses has been reached).
 *
 */
boolean_t
persistent_disc_addr_next(void **v, entry_t *e)
{
	char		name[INET6_ADDRSTRLEN];

	ASSERT(mutex_owned(&disc_addr_data_lock));

	return (nvf_data_next(DISCOVERY_ADDR_ID, v, name,
	    (void *)e, sizeof (*e)));
}

/*
 * persistent_disc_addr_clear -- remove IP address and port information from
 * the configured SendTargets discovery nodes.
 */
boolean_t
persistent_disc_addr_clear(entry_t *e)
{
	char		name[INET6_ADDRSTRLEN];
	boolean_t	rval;

	/*
	 * Create name from given discovery address - SendTargets discovery
	 * nodes do not have an associated node name. A name is manufactured
	 * from the IP address given.
	 */
	if (e->e_insize == sizeof (struct in_addr))
		iscsi_inet_ntop(AF_INET, &e->e_u.u_in4, name);
	else
		iscsi_inet_ntop(AF_INET6, &e->e_u.u_in6, name);

	mutex_enter(&static_addr_data_lock);
	rval = nvf_data_clear(DISCOVERY_ADDR_ID, name);
	mutex_exit(&static_addr_data_lock);

	return (rval);
}


/*
 * persistent_disc_addr_lock -- lock access to the SendTargets discovery
 * addresses.  This ensures discovery addresses are unchanged while the lock
 * is held.  The lock should be grabbed while walking through the discovery
 * addresses
 */
void
persistent_disc_addr_lock(void)
{
	mutex_enter(&disc_addr_data_lock);
}

/*
 * persistent_disc_addr_unlock -- unlock access to discovery addresses.
 */
void
persistent_disc_addr_unlock(void)
{
	mutex_exit(&disc_addr_data_lock);
}


/*
 * +--------------------------------------------------------------------+
 * | Login Parameter Interfaces                                         |
 * +--------------------------------------------------------------------+
 */

/*
 * persistent_param_set -- store login parameters for a specific target
 */
boolean_t
persistent_param_set(char *node, persistent_param_t *param)
{
	boolean_t	rval;

	mutex_enter(&param_data_lock);
	rval = nvf_data_set(LOGIN_PARAMS_ID, node,
	    (void *)param, sizeof (persistent_param_t));
	mutex_exit(&param_data_lock);

	return (rval);
}

/*
 * persistent_param_get -- obtain login parameters for a specific target
 */
boolean_t
persistent_param_get(char *node, persistent_param_t *param)
{
	return (nvf_data_get(LOGIN_PARAMS_ID, node,
	    (void *)param, sizeof (*param)));
}

/*
 * persistent_param_next -- get the next target's login parameters.
 *
 * The first time this function is called, the argument (void **v)
 * should be a pointer to a value of NULL which causes this function to obtain
 * the first target's login parameters.
 *
 * This function assumes the associated login parameter lock is held.
 *
 * Returns B_TRUE when data in *param is valid. B_FALSE returned when no
 * more data is available (end of configured target login parameters).
 */
boolean_t
persistent_param_next(void **v, char *node, persistent_param_t *param)
{
	ASSERT(mutex_owned(&param_data_lock));

	return (nvf_data_next(LOGIN_PARAMS_ID, v, node,
	    (void *)param, sizeof (*param)));
}

/*
 * persistent_param_clear -- remove login parameters for a specific target
 */
boolean_t
persistent_param_clear(char *node)
{
	boolean_t	rval1, rval2, rval3;

	mutex_enter(&param_data_lock);
	rval1 = nvf_data_clear(LOGIN_PARAMS_ID, node);
	rval2 = nvf_data_clear(SESSION_PARAMS_ID, node);
	rval3 = nvf_data_clear(TUNABLE_PARAMS_ID, node);
	mutex_exit(&param_data_lock);

	return (((rval1 == B_TRUE) || (rval2 == B_TRUE) || (rval3 == B_TRUE))
	    ? B_TRUE : B_FALSE);
}

/*
 * persistent_param_lock -- lock access to login parameters.  This
 * ensures the login parameters will be unchanged while the lock is held.
 * The lock should be grabbed while walking through the login parameters.
 */
void
persistent_param_lock(void)
{
	mutex_enter(&param_data_lock);
}

/*
 * persistent_param_unlock -- unlock access to login parameters.
 */
void
persistent_param_unlock(void)
{
	mutex_exit(&param_data_lock);
}

/*
 * +--------------------------------------------------------------------+
 * | Session Config Interfaces                                          |
 * +--------------------------------------------------------------------+
 */


/*
 * persistent_set_config_session -- store configured sessions
 *					for a specific target
 */
boolean_t
persistent_set_config_session(char *node, iscsi_config_sess_t *ics)
{
	boolean_t	rval;
	int		size;

	/*
	 * Make ics_out match ics_in.  Since when someone gets
	 * this information the in value becomes the out.
	 */
	ics->ics_out = ics->ics_in;

	/* calculate size */
	size = ISCSI_SESSION_CONFIG_SIZE(ics->ics_in);

	mutex_enter(&param_data_lock);
	rval = nvf_data_set(SESSION_PARAMS_ID, node, (void *)ics, size);
	mutex_exit(&param_data_lock);

	return (rval);
}

/*
 * persistent_get_config_session -- obtain configured sessions
 *					for a specific target
 */
boolean_t
persistent_get_config_session(char *node, iscsi_config_sess_t *ics)
{
	boolean_t	status;
	int		in;
	int		size;

	ASSERT(ics->ics_in >= 1);

	/* record caller buffer size */
	in = ics->ics_in;

	/* Get base config_sess information */
	size = ISCSI_SESSION_CONFIG_SIZE(in);
	status = nvf_data_get(SESSION_PARAMS_ID, node,
	    (void *)ics, size);

	/* reset the in size */
	ics->ics_in = in;

	return (status);
}

/*
 * persistent_get_tunable_param -- obtain tunable parameters
 *					for a specific target
 */
boolean_t
persistent_get_tunable_param(char *node, persistent_tunable_param_t *tpsg)
{
	return (nvf_data_get(TUNABLE_PARAMS_ID, node,
	    (void *)tpsg, sizeof (persistent_tunable_param_t)));
}

/*
 * persistent_set_tunable_param -- store tunable parameters
 *					for a specific target
 */
boolean_t
persistent_set_tunable_param(char *node, persistent_tunable_param_t *tpss)
{
	boolean_t	rval;
	mutex_enter(&tunable_data_lock);
	rval = nvf_data_set(TUNABLE_PARAMS_ID, node,
	    (void *)tpss, sizeof (persistent_tunable_param_t));
	mutex_exit(&tunable_data_lock);
	return (rval);
}

/*
 * +--------------------------------------------------------------------+
 * | CHAP Parameter Interfaces                                          |
 * +--------------------------------------------------------------------+
 */

/*
 * persistent_chap_set -- store CHAP parameters for a specific target
 */
boolean_t
persistent_chap_set(char *node, iscsi_chap_props_t *chap)
{
	boolean_t	rval;

	mutex_enter(&chap_data_lock);
	rval = nvf_data_set(CHAP_PARAMS_ID, node,
	    (void *)chap, sizeof (iscsi_chap_props_t));
	mutex_exit(&chap_data_lock);

	return (rval);
}

/*
 * persistent_chap_get -- obtain CHAP parameters for a specific target
 */
boolean_t
persistent_chap_get(char *node, iscsi_chap_props_t *chap)
{
	return (nvf_data_get(CHAP_PARAMS_ID, node,
	    (void *)chap, sizeof (*chap)));
}

/*
 * persistent_chap_next -- copy the next target's chap parameters.
 *
 * The first time this function is called, the argument (void **v)
 * should be a pointer to a value of NULL which causes this function to obtain
 * the first target's login parameters.
 *
 * This function assumes the associated chap parameter lock is held.
 *
 * Returns B_TRUE when data in *param is valid. B_FALSE returned when no
 * more data is available.
 */
boolean_t
persistent_chap_next(void **v, char *node, iscsi_chap_props_t *chap)
{
	ASSERT(mutex_owned(&chap_data_lock));

	return (nvf_data_next(CHAP_PARAMS_ID, v, node,
	    (void *)chap, sizeof (*chap)));
}

/*
 * persistent_chap_clear -- remove CHAP parameters for a specific target
 */
boolean_t
persistent_chap_clear(char *node)
{
	boolean_t	rval;

	mutex_enter(&chap_data_lock);
	rval = nvf_data_clear(CHAP_PARAMS_ID, node);
	mutex_exit(&chap_data_lock);

	return (rval);
}

/*
 * persistent_chap_lock -- lock access to chap parameters.  This
 * ensures the chap parameters will be unchanged while the lock is held.
 * The lock should be grabbed while walking through the chap parameters.
 */
void
persistent_chap_lock(void)
{
	mutex_enter(&chap_data_lock);
}

/*
 * persistent_chap_unlock -- unlock access to chap parameters.
 */
void
persistent_chap_unlock(void)
{
	mutex_exit(&chap_data_lock);
}


/*
 * +--------------------------------------------------------------------+
 * | RADIUS Configuration Interfaces                                    |
 * +--------------------------------------------------------------------+
 */

/*
 * persistent_radius_set -- stores the RADIUS configuration info
 */
boolean_t
persistent_radius_set(iscsi_radius_props_t *radius)
{
	return (nvf_node_data_set(RADIUS_PARAMS_ID, (void *)radius,
	    sizeof (iscsi_radius_props_t)));
}

/*
 * persistent_radius_get -- obtain the RADIUS configuration info
 */
iscsi_nvfile_status_t
persistent_radius_get(iscsi_radius_props_t *radius)
{
	return (nvf_node_data_get(RADIUS_PARAMS_ID,
	    (void *)radius, sizeof (*radius)));
}


/*
 * +--------------------------------------------------------------------+
 * | Authentication Configuration Interface                             |
 * +--------------------------------------------------------------------+
 */

/*
 * persistent_auth_set -- stores the bidirectional authentication settings
 * for a specific target
 */
boolean_t
persistent_auth_set(char *node, iscsi_auth_props_t *auth)
{
	boolean_t	rval;

	mutex_enter(&auth_data_lock);
	rval = nvf_data_set(BIDIR_AUTH_PARAMS_ID, node,
	    (void *)auth, sizeof (iscsi_auth_props_t));
	mutex_exit(&auth_data_lock);

	return (rval);
}

/*
 * persistent_auth_get -- gets the bidirectional authentication settings
 * for a specific target
 */
boolean_t
persistent_auth_get(char *node, iscsi_auth_props_t *auth)
{
	return (nvf_data_get(BIDIR_AUTH_PARAMS_ID, node,
	    (void *)auth, sizeof (*auth)));
}

/*
 * persistent_auth_next -- get the next target's bidirectional authentication
 * parameters.
 *
 * The first time this function is called, the argument (void **v)
 * should be a pointer to a value of NULL which causes this function to obtain
 * the first target's login parameters.
 *
 * This function assumes the associated bidirectional authentication lock is
 * held.
 *
 * Returns B_TRUE when data in *param is valid. B_FALSE returned when no
 * more data is available.
 */
boolean_t
persistent_auth_next(void **v,  char *node, iscsi_auth_props_t *auth)
{
	ASSERT(mutex_owned(&auth_data_lock));

	return (nvf_data_next(BIDIR_AUTH_PARAMS_ID, v, node,
	    (void *)auth, sizeof (*auth)));
}

/*
 * persistent_auth_clear -- remove bidirectional authentication parameters for
 * a specific target
 */
boolean_t
persistent_auth_clear(char *node)
{
	boolean_t	rval;

	mutex_enter(&auth_data_lock);
	rval = nvf_data_clear(BIDIR_AUTH_PARAMS_ID, node);
	mutex_exit(&auth_data_lock);

	return (rval);
}

/*
 * persistent_auth_lock -- lock access to bidirectional authentication
 * parameters.  This ensures the authentication parameters will be unchanged
 * while the lock is held.  The lock should be grabbed while walking through
 * the authentication parameters.
 */
void
persistent_auth_lock(void)
{
	mutex_enter(&auth_data_lock);
}

/*
 * persistent_auth_unlock -- unlock access to bidirectional authentication
 * parameters.
 */
void
persistent_auth_unlock(void)
{
	mutex_exit(&auth_data_lock);
}


/*
 * +--------------------------------------------------------------------+
 * | Debug Functions                                                    |
 * +--------------------------------------------------------------------+
 */

#define	BITBUF_LEN	128

/*
 * persistent_dump_data -- dump contents of persistent store
 */
void
persistent_dump_data(void)
{
	boolean_t		rval;
	char			*name;
	iSCSIDiscoveryMethod_t	methods;
	char			*bitbuf;
	iscsi_radius_props_t	*radius;
	entry_t			*entry;
	void			*v;
	char			*addr_buf;
	persistent_param_t	*param;
	uint32_t		param_id;
	char			*param_name;
	iscsi_chap_props_t	*chap;
	iscsi_auth_props_t	*auth;

	name = (char *)kmem_alloc(ISCSI_MAX_NAME_LEN, KM_SLEEP);
	addr_buf = (char *)kmem_alloc(INET6_ADDRSTRLEN, KM_SLEEP);
	bitbuf = (char *)kmem_alloc(BITBUF_LEN, KM_SLEEP);

	rval = persistent_initiator_name_get(name, ISCSI_MAX_NAME_LEN);
	if (rval == B_TRUE) {
		cmn_err(CE_CONT, "    Node Name: %s\n", name);
	}

	rval = persistent_alias_name_get(name, ISCSI_MAX_NAME_LEN);
	if (rval == B_TRUE) {
		cmn_err(CE_CONT, "    Node Alias: %s\n", name);
	}

	methods = persistent_disc_meth_get();
	if (methods != iSCSIDiscoveryMethodUnknown) {
		cmn_err(CE_CONT, "    Methods: <%s>\n",
		    prt_bitmap(methods,
		    "\003SendTarget\002iSNS\001SLP\000Static",
		    bitbuf, BITBUF_LEN));
	}

	radius = (iscsi_radius_props_t *)kmem_alloc(sizeof (*radius),
	    KM_SLEEP);
	if (persistent_radius_get(radius) == ISCSI_NVFILE_SUCCESS) {
		cmn_err(CE_CONT, "    <------ RADIUS Configuration ------>\n");
		if (radius->r_insize == sizeof (struct in_addr)) {
			(void) inet_ntop(AF_INET, &radius->r_addr.u_in4,
			    addr_buf, INET6_ADDRSTRLEN);
		} else {
			(void) inet_ntop(AF_INET6, &radius->r_addr.u_in6,
			    addr_buf, INET6_ADDRSTRLEN);
		}
		cmn_err(CE_CONT, "    IP: %s, port %d\n", addr_buf,
		    radius->r_port);
	}
	kmem_free(radius, sizeof (*radius));

	entry = (entry_t *)kmem_alloc(sizeof (*entry), KM_SLEEP);
	v = NULL;
	cmn_err(CE_CONT,
	    "    <------ Static Target Discovery Addresses ------>\n");
	persistent_static_addr_lock();
	while (persistent_static_addr_next(&v, name, entry) == B_TRUE) {
		cmn_err(CE_CONT, "    Target Name: %s  TPGT: %d\n",
		    name, entry->e_tpgt);
		if (entry->e_insize == sizeof (struct in_addr)) {
			(void) inet_ntop(AF_INET, &entry->e_u.u_in4,
			    addr_buf, INET6_ADDRSTRLEN);
		} else {
			(void) inet_ntop(AF_INET6, &entry->e_u.u_in6,
			    addr_buf, INET6_ADDRSTRLEN);
		}
		cmn_err(CE_CONT,
		    "        IP: %s, port %d\n", addr_buf, entry->e_port);
	}
	persistent_static_addr_unlock();

	v = NULL;
	cmn_err(CE_CONT,
	    "    <------ SendTargets Discovery Addresses ------>\n");
	persistent_disc_addr_lock();
	while (persistent_disc_addr_next(&v, entry) == B_TRUE) {
		if (entry->e_insize == sizeof (struct in_addr)) {
			(void) inet_ntop(AF_INET, &entry->e_u.u_in4,
			    addr_buf, INET6_ADDRSTRLEN);
		} else {
			(void) inet_ntop(AF_INET6, &entry->e_u.u_in6,
			    addr_buf, INET6_ADDRSTRLEN);
		}
		cmn_err(CE_CONT,
		    "    IP: %s, port %d\n", addr_buf, entry->e_port);
	}
	persistent_disc_addr_unlock();

	v = NULL;
	cmn_err(CE_CONT,
	    "    <------ ISNS Server Discovery Addresses ------>\n");
	persistent_isns_addr_lock();
	while (persistent_isns_addr_next(&v, entry) == B_TRUE) {
		if (entry->e_insize == sizeof (struct in_addr)) {
			(void) inet_ntop(AF_INET, &entry->e_u.u_in4,
			    addr_buf, INET6_ADDRSTRLEN);
		} else {
			(void) inet_ntop(AF_INET6, &entry->e_u.u_in6,
			    addr_buf, INET6_ADDRSTRLEN);
		}
		cmn_err(CE_CONT,
		    "    IP: %s, port %d\n", addr_buf, entry->e_port);
	}
	persistent_isns_addr_unlock();
	kmem_free(entry, sizeof (*entry));

	param = (persistent_param_t *)kmem_alloc(sizeof (*param), KM_SLEEP);
	v = NULL;
	cmn_err(CE_CONT, "    <------ Overriden Login Parameters ------>\n");
	persistent_param_lock();
	while (persistent_param_next(&v, name, param) == B_TRUE) {
		cmn_err(CE_CONT, "    Host: %s\n", name);
		cmn_err(CE_CONT, "    Bitmap: <%s>\n",
		    prt_bitmap(param->p_bitmap,
		    "\015DDIG\014HDIG\013SEGLEN\012OUT_R2T\011"
		    "DATAPDU\010MAXCONN\007BURST\006R2T\005"
		    "IMMDATA\004FIRSTBURST\003LEVEL\002T2WAIT"
		    "\001T2RETAIN\000SEQIN", bitbuf, BITBUF_LEN));
		for (param_id = 0; param_id < ISCSI_NUM_LOGIN_PARAM;
		    param_id++) {
			if (param->p_bitmap & (1 << param_id)) {
				param_name = utils_map_param(param_id);
				if (param_name == NULL) {
					param_name = "Param_Not_Found";
				}
				switch (param_id) {
				case ISCSI_LOGIN_PARAM_DATA_SEQUENCE_IN_ORDER:
					cmn_err(CE_CONT, "    %s = %s",
					    param_name, (param->p_params.
					    data_sequence_in_order == B_TRUE) ?
					    "True" : "False");
					break;
				case ISCSI_LOGIN_PARAM_INITIAL_R2T:
					cmn_err(CE_CONT, "    %s = %s",
					    param_name, (param->p_params.
					    initial_r2t == B_TRUE) ?
					    "True" : "False");
					break;
				case ISCSI_LOGIN_PARAM_DATA_PDU_IN_ORDER:
					cmn_err(CE_CONT, "    %s = %s",
					    param_name, (param->p_params.
					    data_pdu_in_order == B_TRUE) ?
					    "True" : "False");
					break;
				case ISCSI_LOGIN_PARAM_HEADER_DIGEST:
					cmn_err(CE_CONT, "    %s = %d",
					    param_name, param->p_params.
					    header_digest);
					break;
				case ISCSI_LOGIN_PARAM_DATA_DIGEST:
					cmn_err(CE_CONT, "    %s = %d",
					    param_name, param->p_params.
					    data_digest);
					break;
			case ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_RETAIN:
					cmn_err(CE_CONT, "    %s = %d",
					    param_name, param->p_params.
					    default_time_to_retain);
					break;
				case ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_WAIT:
					cmn_err(CE_CONT, "    %s = %d",
					    param_name, param->p_params.
					    default_time_to_wait);
					break;
			case ISCSI_LOGIN_PARAM_MAX_RECV_DATA_SEGMENT_LENGTH:
					cmn_err(CE_CONT, "    %s = %d",
					    param_name, param->p_params.
					    max_recv_data_seg_len);
					break;
				case ISCSI_LOGIN_PARAM_FIRST_BURST_LENGTH:
					cmn_err(CE_CONT, "    %s = %d",
					    param_name, param->p_params.
					    first_burst_length);
					break;
				case ISCSI_LOGIN_PARAM_MAX_BURST_LENGTH:
					cmn_err(CE_CONT, "    %s = %d",
					    param_name, param->p_params.
					    max_burst_length);
					break;
				case ISCSI_LOGIN_PARAM_MAX_CONNECTIONS:
					cmn_err(CE_CONT, "    %s = %d",
					    param_name, param->p_params.
					    max_connections);
					break;
				case ISCSI_LOGIN_PARAM_OUTSTANDING_R2T:
					cmn_err(CE_CONT, "    %s = %d",
					    param_name, param->p_params.
					    max_outstanding_r2t);
					break;
				case ISCSI_LOGIN_PARAM_ERROR_RECOVERY_LEVEL:
					cmn_err(CE_CONT, "    %s = %d",
					    param_name, param->p_params.
					    error_recovery_level);
					break;
				default:
					break;
				}
			}
		}
	}
	persistent_param_unlock();
	kmem_free(param, sizeof (*param));

	chap = (iscsi_chap_props_t *)kmem_alloc(sizeof (*chap), KM_SLEEP);
	v = NULL;
	cmn_err(CE_CONT, "    <------ Chap Parameters ------>\n");
	persistent_chap_lock();
	while (persistent_chap_next(&v, name, chap) == B_TRUE) {
		cmn_err(CE_CONT, "    Host: %s\n", name);
		cmn_err(CE_CONT, "        User: %s  Secret: %s\n",
		    chap->c_user, chap->c_secret);
	}
	persistent_chap_unlock();
	kmem_free(chap, sizeof (*chap));

	auth = (iscsi_auth_props_t *)kmem_alloc(sizeof (*auth), KM_SLEEP);
	v = NULL;
	cmn_err(CE_CONT, "    <------ Bidirectional Authentication  ------>\n");
	persistent_auth_lock();
	while (persistent_auth_next(&v, name, auth) == B_TRUE) {
		cmn_err(CE_CONT, "    Host: %s\n", name);
		cmn_err(CE_CONT, "       Bidir Auth = %s\n",
		    (auth->a_bi_auth == B_TRUE) ? "True" : "False");
	}
	persistent_auth_unlock();
	kmem_free(auth, sizeof (*auth));


	kmem_free(bitbuf, BITBUF_LEN);
	kmem_free(addr_buf, INET6_ADDRSTRLEN);
	kmem_free(name, ISCSI_MAX_NAME_LEN);
}
