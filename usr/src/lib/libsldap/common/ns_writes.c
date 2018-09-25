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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <libintl.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <lber.h>
#include <ldap.h>
#include <syslog.h>
#include <stddef.h>
#include <sys/mman.h>

#include "ns_sldap.h"
#include "ns_internal.h"
#include "ns_connmgmt.h"
#include "ns_cache_door.h"

/* Additional headers for addTypedEntry Conversion routines */
#include <pwd.h>
#include <project.h>
#include <shadow.h>
#include <grp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <rpc/rpcent.h>
#include <auth_attr.h>
#include <exec_attr.h>
#include <prof_attr.h>
#include <user_attr.h>
#include <bsm/libbsm.h>
#include <sys/tsol/tndb.h>
#include <tsol/label.h>

static int send_to_cachemgr(const char *,
    ns_ldap_attr_t **, ns_ldap_error_t **);

static int escape_str(char *, char *);

/*
 * If the rdn is a mapped attr:
 *	return NS_LDAP_SUCCESS and a new_dn.
 * If no mapped attr is found in the rdn:
 *	return NS_LDAP_SUCCESS and *new_dn == NULL
 * For example:
 *  service = abc
 *  dn =  cn=foo,dc=bar,dc=com
 *  attributeMapping: abc:cn=sn
 * Then:
 *  new_dn = sn=foo,dc=bar,dc=com
 *
 */
static int
replace_mapped_attr_in_dn(
	const char *service, const char *dn, char **new_dn)
{
	char	**mappedattr;
	char	**dnArray = NULL;
	char	*rservice;
	char	*cur = NULL;
	int	len = 0, orig_len = 0, mapped_len = 0;
	int	dn_len = 0;

	*new_dn = NULL;

	/*
	 * separate dn into individual componets
	 * e.g.
	 * "automountKey=user_01" , "automountMapName_test=auto_home", ...
	 */
	dnArray = ldap_explode_dn(dn, 0);
	if (!dnArray || !*dnArray)
		return (NS_LDAP_INVALID_PARAM);

	cur = strchr(dnArray[0], '=');
	if (!cur) {
		__s_api_free2dArray(dnArray);
		return (NS_LDAP_INVALID_PARAM);
	}
	*cur = '\0';

	/* we only check schema mapping for automount, not for auto_* */
	if (strncasecmp(service, NS_LDAP_TYPE_AUTOMOUNT,
	    sizeof (NS_LDAP_TYPE_AUTOMOUNT) - 1) == 0)
		rservice = "automount";
	else
		rservice = (char *)service;

	mappedattr = __ns_ldap_getMappedAttributes(rservice, dnArray[0]);
	if (!mappedattr || !mappedattr[0]) {
		__s_api_free2dArray(dnArray);
		if (mappedattr)
			__s_api_free2dArray(mappedattr);
		return (NS_LDAP_SUCCESS);
	}
	orig_len = strlen(dnArray[0]);

	/*
	 * The new length is *dn length + (difference between
	 * orig attr and mapped attr) + 1 ;
	 * e.g.
	 * automountKey=aa,automountMapName=auto_home,dc=foo,dc=com
	 * ==>
	 * cn=aa,automountMapName=auto_home,dc=foo,dc=com
	 */
	mapped_len = strlen(mappedattr[0]);
	dn_len = strlen(dn);
	len = dn_len - orig_len + mapped_len + 1;
	*new_dn = (char *)calloc(1, len);
	if (*new_dn == NULL) {
		__s_api_free2dArray(dnArray);
		__s_api_free2dArray(mappedattr);
		return (NS_LDAP_MEMORY);
	}

	(void) snprintf(*new_dn, len, "%s=%s", mappedattr[0], dn + orig_len +1);
	__s_api_free2dArray(dnArray);
	__s_api_free2dArray(mappedattr);

	return (NS_LDAP_SUCCESS);
}


/*
 * The following function is only used by the
 * "gecos" 1 to N attribute mapping code. It expects
 * and handle only one data/length pair.
 */
static int
init_bval_mod(
	LDAPMod *mod,
	int	mop,
	char	*mtype,
	char	*mvptr,
	int	mvlen)
{

	struct berval	**bmodval;

	/* dup attribute name */
	mod->mod_type = strdup(mtype);
	if (mod->mod_type == NULL)
		return (-1);

	/*
	 * assume single value,
	 * since only one value/length pair passed in
	 */
	bmodval = (struct berval **)calloc(2, sizeof (struct berval *));
	if (bmodval == NULL) {
		free(mod->mod_type);
		mod->mod_type = NULL;
		return	(-1);
	}
	bmodval[0] = (struct berval *)calloc(1, sizeof (struct berval));
	if (bmodval[0] == NULL) {
		free(mod->mod_type);
		mod->mod_type = NULL;
		free(bmodval);
		return	(-1);
	}

	/* set pointer to data */
	bmodval[0]->bv_val = mvptr;

	/* set length */
	bmodval[0]->bv_len = mvlen;

	/*
	 * turn on the BVALUE bit to indicate
	 * that the length of data is supplied
	 */
	mod->mod_op = mop | LDAP_MOD_BVALUES;

	mod->mod_bvalues = bmodval;

	return	(0);
}

static void
freeModList(LDAPMod **mods)
{
	int i, j;
	int name_is_oc;

	if (mods == NULL)
		return;

	for (i = 0; mods[i]; i++) {

		/* free attribute name */
		name_is_oc = FALSE;
		if (mods[i]->mod_type) {
			if (strcasecmp(mods[i]->mod_type, "objectclass") == 0)
				name_is_oc = TRUE;
			free(mods[i]->mod_type);
		}

		if (mods[i]->mod_bvalues == NULL)
			continue;
		/*
		 * LDAP_MOD_BVALUES is only set by
		 * the "gecos" 1 to N attribute mapping
		 * code, and the attribute is single valued.
		 */
		if (mods[i]->mod_op & LDAP_MOD_BVALUES) {
			if (mods[i]->mod_bvalues[0])
				free(mods[i]->mod_bvalues[0]);
		} else {
			if (name_is_oc) {
				/*
				 * only values for the "objectclass"
				 * were dupped using strdup.
				 * other attribute values were
				 * not dupped, but via pointer
				 * assignment. So here the
				 * values for "objectclass"
				 * is freed one by one,
				 * but the values for other
				 * attributes need not be freed.
				 */
				for (j = 0; mods[i]->mod_values[j]; j++)
					free(mods[i]->mod_values[j]);
			}

		}
		free(mods[i]->mod_bvalues);
	}

	/* modlist */
	free((char *)(mods[0]));
	free(mods);
}

static LDAPMod **
__s_api_makeModListCount(
	const char *service,
	const ns_ldap_attr_t * const *attr,
	const int mod_op,
	const int count,
	const int flags)
{
	LDAPMod		**mods, *modlist;
	char		**modval;
	char		**mapping;
	int		i;
	int		j;
	int		k, rc, vlen;
	char		*c, *comma1 = NULL, *comma2 = NULL;
	int		schema_mapping_existed = FALSE;
	int		auto_service = FALSE;


	/*
	 * add 2 for "gecos" 1 to up to 3 attribute mapping
	 */
	mods = (LDAPMod **)calloc((count + 3), sizeof (LDAPMod *));
	if (mods == NULL) {
		return (NULL);
	}
	/*
	 * add 2 for "gecos" 1 to up to 3 attribute mapping
	 */
	modlist = (LDAPMod *)calloc(count + 2, sizeof (LDAPMod));
	if (modlist == NULL) {
		free(mods);
		return (NULL);
	}

	if (service != NULL && strncasecmp(service, NS_LDAP_TYPE_AUTOMOUNT,
	    sizeof (NS_LDAP_TYPE_AUTOMOUNT) - 1) == 0)
		auto_service = TRUE;

	/*
	 * see if schema mapping existed for the given service
	 */
	mapping = __ns_ldap_getOrigAttribute(service,
	    NS_HASH_SCHEMA_MAPPING_EXISTED);
	if (mapping) {
		schema_mapping_existed = TRUE;
		__s_api_free2dArray(mapping);
		mapping = NULL;
	}

	for (i = 0, k = 0; k < count && attr[k] != NULL; i++, k++) {
		mods[i] = &modlist[i];
		mods[i]->mod_op = mod_op;
		/*
		 * Perform attribute mapping if necessary.
		 */
		if (schema_mapping_existed && (flags & NS_LDAP_NOMAP) == 0) {
			mapping = __ns_ldap_getMappedAttributes(service,
			    attr[k]->attrname);
		} else
			mapping = NULL;

		if (mapping == NULL && auto_service &&
		    (flags & NS_LDAP_NOMAP) == 0) {
			/*
			 * if service == auto_xxx and
			 * no mapped attribute is found
			 * and NS_LDAP_NOMAP is not set
			 * then try automount's mapped attribute
			 */
			mapping = __ns_ldap_getMappedAttributes("automount",
			    attr[k]->attrname);
		}

		if (mapping == NULL) {
			mods[i]->mod_type = strdup(attr[k]->attrname);
			if (mods[i]->mod_type == NULL)
				goto free_memory;
		} else {
			/*
			 * 1 to N attribute mapping is only done for "gecos",
			 * and only 1 to 3 mapping.
			 * nine cases here:
			 *
			 * A. attrMap=passwd:gecos=a
			 *    1. gecos="xx,yy,zz" -> a="xx,yy,zz"
			 *    2. gecos="xx,yy" -> a="xx,yy"
			 *    3. gecos="xx" -> a="xx"
			 *
			 * B. attrMap=passwd:gecos=a b
			 *    4. gecos="xx,yy,zz" -> a="xx" b="yy,zz"
			 *    5. gecos="xx,yy" -> a="xx" b="yy"
			 *    6. gecos="xx" -> a="xx"
			 *
			 * C. attrMap=passwd:gecos=a b c
			 *    7. gecos="xx,yy,zz" -> a="xx" b="yy" c="zz"
			 *    8. gecos="xx,yy" -> a="xx" b="yy"
			 *    9. gecos="xx" -> a="xx"
			 *
			 * This can be grouped as:
			 *
			 * c1 cases: 1,2,3,6,9
			 *    if ((attrMap=passwd:gecos=a) ||
			 *		(no "," in gecos value))
			 *	same as other no-mapping attributes,
			 *	no special processing needed
			 *    else
			 *
			 * c2 cases: 4,5,8
			 *    if ((attrMap=passwd:gecos=a b) ||
			 *	(only one "," in gecos value))
			 *	a=xx b=yy[,...]
			 *    else
			 *
			 * c3 case: 7
			 *    a=xx b=yy c=...
			 *
			 * notes: in case c2 and c3, ... could still contain ","
			 */
			if (strcasecmp(service, "passwd") == 0 &&
			    strcasecmp(attr[k]->attrname, "gecos") == 0 &&
			    mapping[1] && attr[k]->attrvalue[0] &&
			    (comma1 = strchr(attr[k]->attrvalue[0],
			    COMMATOK)) != NULL) {

			/* is there a second comma? */
			if (*(comma1 + 1) != '\0')
				comma2 = strchr(comma1 + 1, COMMATOK);

			/*
			 * Process case c2 or c3.
			 * case c2: mapped to two attributes or just
			 * one comma
			 */
			if (mapping[2] == NULL || comma2 == NULL) {
				/* case c2 */

				/*
				 * int mod structure for the first attribute
				 */
				vlen = comma1 - attr[k]->attrvalue[0];
				c = attr[k]->attrvalue[0];

				if (vlen > 0 && c) {
					rc = init_bval_mod(mods[i], mod_op,
					    mapping[0], c, vlen);
					if (rc != 0)
						goto free_memory;
				} else {
					/* don't leave a hole in mods array */
					mods[i] = NULL;
					i--;
				}


				/*
				 * init mod structure for the 2nd attribute
				 */
				if (*(comma1 + 1) == '\0') {
					__s_api_free2dArray(mapping);
					mapping = NULL;
					continue;
				}

				i++;
				mods[i] = &modlist[i];

				/*
				 * get pointer to data.
				 * Skip leading spaces.
				 */
				for (c = comma1 + 1; *c == SPACETOK; c++) {
					/* empty */
				}

				/* get data length */
				vlen = strlen(attr[k]->attrvalue[0]) -
				    (c - attr[k]->attrvalue[0]);

				if (vlen > 0 && c) {
					rc = init_bval_mod(mods[i], mod_op,
					    mapping[1], c, vlen);
					if (rc != 0)
						goto free_memory;
				} else {
					/* don't leave a hole in mods array */
					mods[i] = NULL;
					i--;
				}

				/* done with the mapping array */
				__s_api_free2dArray(mapping);
				mapping = NULL;

				continue;
			} else {
				/* case c3 */

				/*
				 * int mod structure for the first attribute
				 */
				vlen = comma1 - attr[k]->attrvalue[0];
				c = attr[k]->attrvalue[0];

				if (vlen > 0 && c) {
					rc = init_bval_mod(mods[i], mod_op,
					    mapping[0], c, vlen);
					if (rc != 0)
						goto free_memory;
				} else {
					/* don't leave a hole in mods array */
					mods[i] = NULL;
					i--;
				}

				/*
				 * init mod structure for the 2nd attribute
				 */
				i++;
				mods[i] = &modlist[i];

				/*
				 * get pointer to data.
				 * Skip leading spaces.
				 */
				for (c = comma1 + 1; *c == SPACETOK; c++) {
					/* empty */
				};

				/* get data length */
				vlen = comma2 - c;

				if (vlen > 0 && c) {
					rc = init_bval_mod(mods[i], mod_op,
					    mapping[1], c, vlen);
					if (rc != 0)
						goto free_memory;
				} else {
					/* don't leave a hole in mods array */
					mods[i] = NULL;
					i--;
				}

				/*
				 * init mod structure for the 3rd attribute
				 */
				if (*(comma2 + 1) == '\0') {
					__s_api_free2dArray(mapping);
					mapping = NULL;
					continue;
				}

				i++;
				mods[i] = &modlist[i];
				/*
				 * get pointer to data.
				 * Skip leading spaces.
				 */
				for (c = comma2 + 1; *c == SPACETOK; c++) {
					/* empty */
				}

				/* get data length */
				vlen = strlen(attr[k]->attrvalue[0]) -
				    (c - attr[k]->attrvalue[0]);

				if (vlen > 0 && c) {
					rc = init_bval_mod(mods[i], mod_op,
					    mapping[2], c, vlen);
					if (rc != 0)
						goto free_memory;
				} else {
					/* don't leave a hole in mods array */
					mods[i] = NULL;
					i--;
				}

				/* done with the mapping array */
				__s_api_free2dArray(mapping);
				mapping = NULL;

				continue;
				}
			}

			/* case c1 */
			mods[i]->mod_type = strdup(mapping[0]);
			if (mods[i]->mod_type == NULL) {
				goto free_memory;
			}
			__s_api_free2dArray(mapping);
			mapping = NULL;
		}

		modval = (char **)calloc(attr[k]->value_count+1,
		    sizeof (char *));
		if (modval == NULL)
			goto free_memory;
		/*
		 * Perform objectclass mapping.
		 * Note that the values for the "objectclass" attribute
		 * will be dupped using strdup. Values for other
		 * attributes will be referenced via pointer
		 * assignments.
		 */
		if (strcasecmp(mods[i]->mod_type, "objectclass") == 0) {
			for (j = 0; j < attr[k]->value_count; j++) {
				if (schema_mapping_existed &&
				    (flags & NS_LDAP_NOMAP) == 0)
					mapping =
					    __ns_ldap_getMappedObjectClass(
					    service, attr[k]->attrvalue[j]);
				else
					mapping = NULL;

				if (mapping == NULL && auto_service &&
				    (flags & NS_LDAP_NOMAP) == 0)
					/*
					 * if service == auto_xxx and
					 * no mapped objectclass is found
					 * then try automount
					 */
					mapping =
					    __ns_ldap_getMappedObjectClass(
					    "automount", attr[k]->attrvalue[j]);

				if (mapping && mapping[0]) {
					/* assume single mapping */
					modval[j] = strdup(mapping[0]);
				} else {
					modval[j] = strdup(attr[k]->
					    attrvalue[j]);
				}
				if (modval[j] == NULL)
					goto free_memory;
			}
		} else {
			for (j = 0; j < attr[k]->value_count; j++) {
				/* ASSIGN NOT COPY */
				modval[j] = attr[k]->attrvalue[j];
			}
		}
		mods[i]->mod_values = modval;
	}

	return (mods);

free_memory:
	freeModList(mods);
	if (mapping)
	__s_api_free2dArray(mapping);

	return (NULL);

}

static LDAPMod **
__s_api_makeModList(
	const char *service,
	const ns_ldap_attr_t * const *attr,
	const int mod_op,
	const int flags)
{
	ns_ldap_attr_t	**aptr = (ns_ldap_attr_t **)attr;
	int		count = 0;

	if (aptr == NULL)
		return (NULL);

	/* count number of attributes */
	while (*aptr++)
		count++;

	return (__s_api_makeModListCount(service, attr, mod_op, count, flags));
}

static void
__s_cvt_freeEntryRdn(ns_ldap_entry_t **entry, char **rdn)
{
	if (*entry != NULL) {
		__ns_ldap_freeEntry(*entry);
		*entry = NULL;
	}
	if (*rdn != NULL) {
		free(*rdn);
		*rdn = NULL;
	}
}

/*
 * This state machine performs one or more LDAP add/delete/modify
 * operations to configured LDAP servers.
 */
static int
write_state_machine(
	int		ldap_op,
	char		*dn,
	LDAPMod		**mods,
	const ns_cred_t *cred,
	const int	flags,
	ns_ldap_error_t ** errorp)
{
	ConnectionID    connectionId = -1;
	Connection	*conp = NULL;
	LDAPMessage	*res;
	char		*target_dn = NULL;
	char		errstr[MAXERROR];
	int		rc = NS_LDAP_SUCCESS;
	int		return_rc = NS_LDAP_SUCCESS;
	int		followRef = FALSE;
	int		target_dn_allocated = FALSE;
	int		len;
	int		msgid;
	int		Errno;
	boolean_t	from_get_lderrno = B_FALSE;
	int		always = 1;
	char		*err, *errmsg = NULL;
	/* referrals returned by the LDAP operation */
	char		**referrals = NULL;
	/*
	 * list of referrals used by the state machine, built from
	 * the referrals variable above
	 */
	ns_referral_info_t *ref_list = NULL;
	/* current referral */
	ns_referral_info_t *current_ref = NULL;
	ns_write_state_t state = W_INIT, new_state, err_state = W_INIT;
	int		do_not_fail_if_new_pwd_reqd = 0;
	ns_ldap_passwd_status_t	pwd_status = NS_PASSWD_GOOD;
	int		passwd_mgmt = 0;
	int		i = 0;
	int		ldap_error;
	int		nopasswd_acct_mgmt = 0;
	ns_conn_user_t	*conn_user = NULL;

	while (always) {
		switch (state) {
		case W_EXIT:
			/* return the MT connection and free the conn user */
			if (conn_user != NULL) {
				if (conn_user->use_mt_conn == B_TRUE) {
					if (conn_user->ns_error != NULL) {
						*errorp = conn_user->ns_error;
						conn_user->ns_error = NULL;
						return_rc = conn_user->ns_rc;
					}
					if (conn_user->conn_mt != NULL)
						__s_api_conn_mt_return(
						    conn_user);
				}
				__s_api_conn_user_free(conn_user);
			}

			if (connectionId > -1)
				DropConnection(connectionId, NS_LDAP_NEW_CONN);
			if (ref_list)
				__s_api_deleteRefInfo(ref_list);
			if (target_dn && target_dn_allocated)
				free(target_dn);
			return (return_rc);
		case W_INIT:
			/* see if need to follow referrals */
			rc = __s_api_toFollowReferrals(flags,
			    &followRef, errorp);
			if (rc != NS_LDAP_SUCCESS) {
				return_rc = rc;
				new_state = W_ERROR;
				break;
			}
			len = strlen(dn);
			if (dn[len-1] == COMMATOK)
				rc = __s_api_append_default_basedn(
				    dn, &target_dn, &target_dn_allocated,
				    errorp);
			else
				target_dn = dn;
			if (rc != NS_LDAP_SUCCESS) {
				return_rc = rc;
				new_state = W_ERROR;
			}
			else
				new_state = GET_CONNECTION;
			break;
		case GET_CONNECTION:
			/* identify self as a write user */
			conn_user = __s_api_conn_user_init(NS_CONN_USER_WRITE,
			    NULL, B_FALSE);
			rc = __s_api_getConnection(NULL,
			    flags, cred, &connectionId, &conp, errorp,
			    do_not_fail_if_new_pwd_reqd, nopasswd_acct_mgmt,
			    conn_user);

			/*
			 * If password control attached
			 * in *errorp,
			 * e.g. rc == NS_LDAP_SUCCESS_WITH_INFO,
			 * free the error structure (we do not need
			 * the password management info).
			 * Reset rc to NS_LDAP_SUCCESS.
			 */
			if (rc == NS_LDAP_SUCCESS_WITH_INFO) {
				(void) __ns_ldap_freeError(errorp);
				*errorp = NULL;
				rc = NS_LDAP_SUCCESS;
			}

			if (rc != NS_LDAP_SUCCESS) {
				return_rc = rc;
				new_state = W_ERROR;
				break;
			}
			if (followRef)
				new_state = SELECT_OPERATION_ASYNC;
			else
				new_state = SELECT_OPERATION_SYNC;
			break;
		case SELECT_OPERATION_SYNC:
			if (ldap_op == LDAP_REQ_ADD)
				new_state = DO_ADD_SYNC;
			else if (ldap_op == LDAP_REQ_DELETE)
				new_state = DO_DELETE_SYNC;
			else if (ldap_op == LDAP_REQ_MODIFY)
				new_state = DO_MODIFY_SYNC;
			break;
		case SELECT_OPERATION_ASYNC:
			if (ldap_op == LDAP_REQ_ADD)
				new_state = DO_ADD_ASYNC;
			else if (ldap_op == LDAP_REQ_DELETE)
				new_state = DO_DELETE_ASYNC;
			else if (ldap_op == LDAP_REQ_MODIFY)
				new_state = DO_MODIFY_ASYNC;
			break;
		case DO_ADD_SYNC:
			rc = ldap_add_ext_s(conp->ld, target_dn,
			    mods, NULL, NULL);
			new_state = GET_RESULT_SYNC;
			break;
		case DO_DELETE_SYNC:
			rc = ldap_delete_ext_s(conp->ld, target_dn,
			    NULL, NULL);
			new_state = GET_RESULT_SYNC;
			break;
		case DO_MODIFY_SYNC:
			rc = ldap_modify_ext_s(conp->ld, target_dn,
			    mods, NULL, NULL);
			new_state = GET_RESULT_SYNC;
			break;
		case DO_ADD_ASYNC:
			rc = ldap_add_ext(conp->ld, target_dn,
			    mods, NULL, NULL, &msgid);
			new_state = GET_RESULT_ASYNC;
			break;
		case DO_DELETE_ASYNC:
			rc = ldap_delete_ext(conp->ld, target_dn,
			    NULL, NULL, &msgid);
			new_state = GET_RESULT_ASYNC;
			break;
		case DO_MODIFY_ASYNC:
			rc = ldap_modify_ext(conp->ld, target_dn,
			    mods, NULL, NULL, &msgid);
			new_state = GET_RESULT_ASYNC;
			break;
		case GET_RESULT_SYNC:
			if (rc != LDAP_SUCCESS) {
				Errno = rc;
				(void) ldap_get_lderrno(conp->ld,
				    NULL, &errmsg);

				/*
				 * No need to deal with the error message if
				 * it's an empty string.
				 */
				if (errmsg != NULL && *errmsg == '\0')
					errmsg = NULL;

				if (errmsg != NULL) {
					/*
					 * ldap_get_lderrno does not expect
					 * errmsg to be freed after use, while
					 * ldap_parse_result below does, so set
					 * a flag to indicate source.
					 */
					from_get_lderrno = B_TRUE;
				}

				new_state = W_LDAP_ERROR;
			} else {
				return_rc = NS_LDAP_SUCCESS;
				new_state = W_EXIT;
			}
			break;
		case GET_RESULT_ASYNC:
			rc = ldap_result(conp->ld, msgid, 1,
			    (struct timeval *)NULL, &res);
			/* if no server response, set Errno */
			if (rc == -1) {
				(void) ldap_get_option(conp->ld,
				    LDAP_OPT_ERROR_NUMBER, &Errno);
				new_state = W_LDAP_ERROR;
				break;
			}
			if (rc == LDAP_RES_ADD || rc == LDAP_RES_MODIFY ||
			    rc == LDAP_RES_DELETE) {
				new_state = PARSE_RESULT;
				break;
			} else {
				return_rc = rc;
				new_state = W_ERROR;
			}
			break;
		case PARSE_RESULT:
			/*
			 * need Errno, referrals, error msg,
			 * and the last "1" is to free
			 * the result (res)
			 */
			rc = ldap_parse_result(conp->ld, res, &Errno,
			    NULL, &errmsg, &referrals, NULL, 1);
			/*
			 * free errmsg if it is an empty string
			 */
			if (errmsg && *errmsg == '\0') {
				ldap_memfree(errmsg);
				errmsg = NULL;
			}
			/*
			 * If we received referral data, process
			 * it if:
			 * - we are configured to follow referrals
			 * - and not already in referral mode (to keep
			 *   consistency with search_state_machine()
			 *   which follows 1 level of referrals only;
			 *   see proc_result_referrals() and
			 *   proc_search_references().
			 */
			if (Errno == LDAP_REFERRAL && followRef && !ref_list) {
				for (i = 0; referrals[i] != NULL; i++) {
					/* add to referral list */
					rc = __s_api_addRefInfo(&ref_list,
					    referrals[i], NULL, NULL, NULL,
					    conp->ld);
					if (rc != NS_LDAP_SUCCESS) {
						__s_api_deleteRefInfo(ref_list);
						ref_list = NULL;
						break;
					}
				}
				ldap_value_free(referrals);
				if (ref_list == NULL) {
					if (rc != NS_LDAP_MEMORY)
						rc = NS_LDAP_INTERNAL;
					return_rc = rc;
					new_state = W_ERROR;
				} else {
					new_state = GET_REFERRAL_CONNECTION;
					current_ref = ref_list;
				}
				if (errmsg) {
					ldap_memfree(errmsg);
					errmsg = NULL;
				}
				break;
			}
			if (Errno != LDAP_SUCCESS) {
				new_state = W_LDAP_ERROR;
			} else {
				return_rc = NS_LDAP_SUCCESS;
				new_state = W_EXIT;
			}
			break;
		case GET_REFERRAL_CONNECTION:
			/*
			 * since we are starting over,
			 * discard the old error info
			 */
			return_rc = NS_LDAP_SUCCESS;
			if (*errorp)
				(void) __ns_ldap_freeError(errorp);
			if (connectionId > -1)
				DropConnection(connectionId, NS_LDAP_NEW_CONN);

			/* set it up to use a referral connection */
			if (conn_user != NULL) {
				/*
				 * If an MT connection is being used,
				 * return it to the pool.
				 */
				if (conn_user->conn_mt != NULL)
					__s_api_conn_mt_return(conn_user);

				conn_user->referral = B_TRUE;
			}
			rc = __s_api_getConnection(current_ref->refHost,
			    0, cred, &connectionId, &conp, errorp,
			    do_not_fail_if_new_pwd_reqd,
			    nopasswd_acct_mgmt, conn_user);

			/*
			 * If password control attached
			 * in errorp,
			 * e.g. rc == NS_LDAP_SUCCESS_WITH_INFO,
			 * free the error structure (we do not need
			 * the password management info).
			 * Reset rc to NS_LDAP_SUCCESS.
			 */
			if (rc == NS_LDAP_SUCCESS_WITH_INFO) {
				(void) __ns_ldap_freeError(errorp);
				*errorp = NULL;
				rc = NS_LDAP_SUCCESS;
			}

			if (rc != NS_LDAP_SUCCESS) {
				return_rc = rc;
				/*
				 * If current referral is not
				 * available for some reason,
				 * try next referral in the list.
				 * Get LDAP error code from errorp.
				 */
				if (*errorp != NULL) {
					ns_write_state_t get_ref =
					    GET_REFERRAL_CONNECTION;

					ldap_error = (*errorp)->status;
					if (ldap_error == LDAP_BUSY ||
					    ldap_error == LDAP_UNAVAILABLE ||
					    ldap_error ==
					    LDAP_UNWILLING_TO_PERFORM ||
					    ldap_error == LDAP_CONNECT_ERROR ||
					    ldap_error == LDAP_SERVER_DOWN) {
						current_ref = current_ref->next;
						if (current_ref == NULL) {
						/* no more referral to follow */
							new_state = W_ERROR;
						} else
							new_state = get_ref;
						/*
						 * free errorp before going to
						 * next referral
						 */
						(void) __ns_ldap_freeError(
						    errorp);
						*errorp = NULL;
						break;
					}
					/*
					 * free errorp before going to W_ERROR
					 */
					(void) __ns_ldap_freeError(errorp);
					*errorp = NULL;
				}
				/* else, exit */
				__s_api_deleteRefInfo(ref_list);
				ref_list = NULL;
				new_state = W_ERROR;
				if (conn_user != NULL)
					conn_user->referral = B_FALSE;
				break;
			}
			/* target DN may changed due to referrals */
			if (current_ref->refDN) {
				if (target_dn && target_dn_allocated) {
					free(target_dn);
					target_dn = NULL;
					target_dn_allocated = FALSE;
				}
				target_dn = current_ref->refDN;
			}
			new_state = SELECT_OPERATION_SYNC;
			break;
		case W_LDAP_ERROR:
			/*
			 * map error code and error message
			 * to password status if necessary.
			 * This is to see if password updates
			 * failed due to password policy or
			 * password syntax checking.
			 */
			if (errmsg) {
				/*
				 * check if server supports
				 * password management
				 */
				passwd_mgmt =
				    __s_api_contain_passwd_control_oid(
				    conp->controls);
					if (passwd_mgmt)
						pwd_status =
						    __s_api_set_passwd_status(
						    Errno, errmsg);
				/*
				 * free only if not returned by ldap_get_lderrno
				 */
				if (!from_get_lderrno)
					ldap_memfree(errmsg);
				errmsg = NULL;
				from_get_lderrno = B_FALSE;
			}

			(void) snprintf(errstr, sizeof (errstr),
			    "%s", ldap_err2string(Errno));
			err = strdup(errstr);
			if (pwd_status != NS_PASSWD_GOOD) {
				MKERROR_PWD_MGMT(*errorp, Errno, err,
				    pwd_status, 0, NULL);
			} else {
				MKERROR(LOG_INFO, *errorp, Errno, err, NULL);
			}
			if (conn_user != NULL &&
			    (Errno == LDAP_SERVER_DOWN ||
			    Errno == LDAP_CONNECT_ERROR)) {
				__s_api_conn_mt_close(conn_user, Errno, errorp);
			}
			return_rc = NS_LDAP_INTERNAL;
			new_state = W_EXIT;
			break;
		case W_ERROR:
		default:
			(void) sprintf(errstr,
			    gettext("Internal write State machine exit"
			    " (state = %d, rc = %d)."),
			    err_state, return_rc);
			err = strdup(errstr);
			MKERROR(LOG_WARNING, *errorp, return_rc, err, NULL);
			new_state = W_EXIT;
			break;
		}

		if (new_state == W_ERROR)
			err_state = state;

		if (conn_user != NULL && conn_user->bad_mt_conn == B_TRUE) {
			__s_api_conn_mt_close(conn_user, 0, NULL);
			new_state = W_EXIT;
		}

		state = new_state;
	}

	/*
	 * should never be here, the next line is to eliminating
	 * lint message
	 */
	return (NS_LDAP_INTERNAL);
}


/*ARGSUSED*/
int
__ns_ldap_addAttr(
	const char *service,
	const char *dn,
	const ns_ldap_attr_t * const *attr,
	const ns_cred_t *cred,
	const int flags,
	ns_ldap_error_t ** errorp)
{
	LDAPMod		**mods;
	int		rc = 0;

#ifdef DEBUG
	(void) fprintf(stderr, "__ns_ldap_addAttr START\n");
#endif
	*errorp = NULL;

	/* Sanity check */
	if ((attr == NULL) || (*attr == NULL) ||
	    (dn == NULL) || (cred == NULL))
		return (NS_LDAP_INVALID_PARAM);

	mods = __s_api_makeModList(service, attr, LDAP_MOD_ADD, flags);
	if (mods == NULL) {
		return (NS_LDAP_MEMORY);
	}

	rc = write_state_machine(LDAP_REQ_MODIFY,
	    (char *)dn, mods, cred, flags, errorp);
	freeModList(mods);

	return (rc);
}


/*ARGSUSED*/
int
__ns_ldap_delAttr(
	const char *service,
	const char *dn,
	const ns_ldap_attr_t * const *attr,
	const ns_cred_t *cred,
	const int flags,
	ns_ldap_error_t ** errorp)
{
	LDAPMod		**mods;
	int		rc = 0;

#ifdef DEBUG
	(void) fprintf(stderr, "__ns_ldap_delAttr START\n");
#endif
	*errorp = NULL;

	/* Sanity check */
	if ((attr == NULL) || (*attr == NULL) ||
	    (dn == NULL) || (cred == NULL))
		return (NS_LDAP_INVALID_PARAM);

	mods = __s_api_makeModList(service, attr, LDAP_MOD_DELETE, flags);
	if (mods == NULL) {
		return (NS_LDAP_MEMORY);
	}

	rc = write_state_machine(LDAP_REQ_MODIFY,
	    (char *)dn, mods, cred, flags, errorp);

	freeModList(mods);
	return (rc);
}

/* Retrieve the admin bind password from the configuration, if allowed. */
static int
get_admin_passwd(ns_cred_t *cred, ns_ldap_error_t **errorp)
{
	void	**paramVal = NULL;
	int	rc, ldaprc;
	char	*modparamVal = NULL;

	/*
	 * For GSSAPI/Kerberos, host credential is used, no need to get
	 * admin bind password
	 */
	if (cred->auth.saslmech == NS_LDAP_SASL_GSSAPI)
		return (NS_LDAP_SUCCESS);

	/*
	 * Retrieve admin bind password.
	 * The admin bind password is available
	 * only in the ldap_cachemgr process as
	 * they are not exposed outside of that
	 * process.
	 */
	paramVal = NULL;
	if ((ldaprc = __ns_ldap_getParam(NS_LDAP_ADMIN_BINDPASSWD_P,
	    &paramVal, errorp)) != NS_LDAP_SUCCESS)
		return (ldaprc);
	if (paramVal == NULL || *paramVal == NULL) {
		rc = NS_LDAP_CONFIG;
		*errorp = __s_api_make_error(NS_CONFIG_NODEFAULT,
		    gettext("Admin bind password not configured"));
		if (*errorp == NULL)
			rc = NS_LDAP_MEMORY;
		return (rc);
	}
	modparamVal = dvalue((char *)*paramVal);
	(void) memset(*paramVal, 0, strlen((char *)*paramVal));
	(void) __ns_ldap_freeParam(&paramVal);
	if (modparamVal == NULL || *((char *)modparamVal) == '\0') {
		if (modparamVal != NULL)
			free(modparamVal);
		rc = NS_LDAP_CONFIG;
		*errorp = __s_api_make_error(NS_CONFIG_SYNTAX,
		    gettext("bind password not valid"));
		if (*errorp == NULL)
			rc = NS_LDAP_MEMORY;
		return (rc);
	}

	cred->cred.unix_cred.passwd = modparamVal;
	return (NS_LDAP_SUCCESS);
}

boolean_t
__ns_ldap_is_shadow_update_enabled(void)
{
	int			**enable_shadow = NULL;
	ns_ldap_error_t		*errorp = NULL;

	if (__ns_ldap_getParam(NS_LDAP_ENABLE_SHADOW_UPDATE_P,
	    (void ***)&enable_shadow, &errorp) != NS_LDAP_SUCCESS) {
		if (errorp)
			(void) __ns_ldap_freeError(&errorp);
		return (B_FALSE);
	}
	if ((enable_shadow != NULL && *enable_shadow != NULL) &&
	    (*enable_shadow[0] == NS_LDAP_ENABLE_SHADOW_UPDATE_TRUE)) {
		(void) __ns_ldap_freeParam((void ***)&enable_shadow);
		return (B_TRUE);
	}
	if (enable_shadow != NULL)
		(void) __ns_ldap_freeParam((void ***)&enable_shadow);
	return (B_FALSE);
}

/*
 * __ns_ldap_repAttr modifies ldap attributes of the 'dn' entry stored
 * on the LDAP server. 'service' indicates the type of database entries
 * to modify. When the Native LDAP client is configured with 'shadow update
 * enabled', Shadowshadow(4) entries can only be modified by privileged users.
 * Such users use the NS_LDAP_UPDATE_SHADOW flag to indicate the call is
 * for such a shadow(4) update, which would be forwarded to ldap_cachemgr
 * for performing the LDAP modify operation. ldap_cachemgr would call
 * this function again and use the special service NS_ADMIN_SHADOW_UPDATE
 * to identify itself, so that admin credential would be obtained and
 * the actual LDAP modify operation be done.
 */
/*ARGSUSED*/
int
__ns_ldap_repAttr(
	const char *service,
	const char *dn,
	const ns_ldap_attr_t * const *attr,
	const ns_cred_t *cred,
	const int flags,
	ns_ldap_error_t ** errorp)
{
	LDAPMod		**mods;
	int		rc = 0;
	boolean_t	priv;
	boolean_t	shadow_update_enabled = B_FALSE;

#ifdef DEBUG
	(void) fprintf(stderr, "__ns_ldap_repAttr START\n");
#endif
	*errorp = NULL;

	/* Sanity check */
	if (attr == NULL || *attr == NULL || dn == NULL)
		return (NS_LDAP_INVALID_PARAM);

	/* Privileged shadow modify? */
	if ((flags & NS_LDAP_UPDATE_SHADOW) != 0 &&
	    strcmp(service, "shadow") == 0) {

		/* Shadow update enabled ? If not, error out */
		shadow_update_enabled = __ns_ldap_is_shadow_update_enabled();
		if (!shadow_update_enabled) {
			*errorp = __s_api_make_error(NS_CONFIG_NOTALLOW,
			    gettext("Shadow Update is not enabled"));
			return (NS_LDAP_CONFIG);
		}

		/* privileged shadow modify requires euid 0 or all zone privs */
		priv = (geteuid() == 0);
		if (!priv) {
			priv_set_t *ps = priv_allocset();	/* caller */
			priv_set_t *zs;				/* zone */

			(void) getppriv(PRIV_EFFECTIVE, ps);
			zs = priv_str_to_set("zone", ",", NULL);
			priv = priv_isequalset(ps, zs);
			priv_freeset(ps);
			priv_freeset(zs);
		}
		if (!priv)
			return (NS_LDAP_OP_FAILED);

		rc = send_to_cachemgr(dn, (ns_ldap_attr_t **)attr, errorp);
		return (rc);
	}

	if (cred == NULL)
		return (NS_LDAP_INVALID_PARAM);

	/*
	 * If service is NS_ADMIN_SHADOW_UPDATE, the caller should be
	 * ldap_cachemgr. We need to get the admin cred to do work.
	 * If the caller is not ldap_cachemgr, but use the service
	 * NS_ADMIN_SHADOW_UPDATE, get_admin_passwd() will fail,
	 * as the admin cred is not available to the caller.
	 */
	if (strcmp(service, NS_ADMIN_SHADOW_UPDATE) == 0) {
		if ((rc = get_admin_passwd((ns_cred_t *)cred, errorp)) !=
		    NS_LDAP_SUCCESS)
			return (rc);
	}

	mods = __s_api_makeModList(service, attr, LDAP_MOD_REPLACE, flags);
	if (mods == NULL)
		return (NS_LDAP_MEMORY);

	rc = write_state_machine(LDAP_REQ_MODIFY,
	    (char *)dn, mods, cred, flags, errorp);

	freeModList(mods);
	return (rc);
}

/*ARGSUSED*/
int
__ns_ldap_addEntry(
	const char *service,
	const char *dn,
	const ns_ldap_entry_t *entry,
	const ns_cred_t *cred,
	const int flags,
	ns_ldap_error_t ** errorp)
{
	char		*new_dn = NULL;
	LDAPMod		**mods = NULL;
	const ns_ldap_attr_t	* const *attr;
	int		nAttr = 0;
	int		rc = 0;

#ifdef DEBUG
	(void) fprintf(stderr, "__ns_ldap_addEntry START\n");
#endif

	if ((entry == NULL) || (dn == NULL) || (cred == NULL))
		return (NS_LDAP_INVALID_PARAM);
	*errorp = NULL;

	/* Construct array of LDAPMod representing attributes of new entry. */

	nAttr = entry->attr_count;
	attr = (const ns_ldap_attr_t * const *)(entry->attr_pair);
	mods = __s_api_makeModListCount(service, attr, LDAP_MOD_ADD,
	    nAttr, flags);
	if (mods == NULL) {
		return (NS_LDAP_MEMORY);
	}

	rc = replace_mapped_attr_in_dn(service, dn, &new_dn);
	if (rc != NS_LDAP_SUCCESS) {
		freeModList(mods);
		return (rc);
	}

	rc = write_state_machine(LDAP_REQ_ADD,
	    new_dn ? new_dn : (char *)dn, mods, cred, flags, errorp);

	if (new_dn)
		free(new_dn);
	freeModList(mods);
	return (rc);
}


/*ARGSUSED*/
int
__ns_ldap_delEntry(
	const char *service,
	const char *dn,
	const ns_cred_t *cred,
	const int flags,
	ns_ldap_error_t ** errorp)
{
	int		rc;

#ifdef DEBUG
	(void) fprintf(stderr, "__ns_ldap_delEntry START\n");
#endif
	if ((dn == NULL) || (cred == NULL))
		return (NS_LDAP_INVALID_PARAM);

	*errorp = NULL;

	rc = write_state_machine(LDAP_REQ_DELETE,
	    (char *)dn, NULL, cred, flags, errorp);

	return (rc);
}

/*
 * Add Typed Entry Helper routines
 */

/*
 * Add Typed Entry Conversion routines
 */

static int
__s_add_attr(ns_ldap_entry_t *e, char *attrname, char *value)
{
	ns_ldap_attr_t	*a;
	char		*v;

	a = (ns_ldap_attr_t *)calloc(1, sizeof (ns_ldap_attr_t));
	if (a == NULL)
		return (NS_LDAP_MEMORY);
	a->attrname = strdup(attrname);
	if (a->attrname == NULL)
		return (NS_LDAP_MEMORY);
	a->attrvalue = (char **)calloc(1, sizeof (char **));
	if (a->attrvalue == NULL)
		return (NS_LDAP_MEMORY);
	a->value_count = 1;
	a->attrvalue[0] = NULL;
	v = strdup(value);
	if (v == NULL)
		return (NS_LDAP_MEMORY);
	a->attrvalue[0] = v;
	e->attr_pair[e->attr_count] = a;
	e->attr_count++;
	return (NS_LDAP_SUCCESS);
}

static int
__s_add_attrlist(ns_ldap_entry_t *e, char *attrname, char **argv)
{
	ns_ldap_attr_t	*a;
	char		*v;
	char		**av;
	int		i, j;

	a = (ns_ldap_attr_t *)calloc(1, sizeof (ns_ldap_attr_t));
	if (a == NULL)
		return (NS_LDAP_MEMORY);
	a->attrname = strdup(attrname);
	if (a->attrname == NULL)
		return (NS_LDAP_MEMORY);

	for (i = 0, av = argv; *av != NULL; av++, i++)
		;

	a->attrvalue = (char **)calloc(i, sizeof (char *));

	if (a->attrvalue == NULL)
		return (NS_LDAP_MEMORY);

	a->value_count = i;
	for (j = 0; j < i; j++) {
		v = strdup(argv[j]);
		if (v == NULL)
			return (NS_LDAP_MEMORY);
		a->attrvalue[j] = v;
	}
	e->attr_pair[e->attr_count] = a;
	e->attr_count++;
	return (NS_LDAP_SUCCESS);
}

static ns_ldap_entry_t *
__s_mk_entry(char **objclass, int max_attr)
{
	ns_ldap_entry_t *e;
	e = (ns_ldap_entry_t *)calloc(1, sizeof (ns_ldap_entry_t));
	if (e == NULL)
		return (NULL);
	/* allocate attributes, +1 for objectclass, +1 for NULL terminator */
	e->attr_pair = (ns_ldap_attr_t **)
	    calloc(max_attr + 2, sizeof (ns_ldap_attr_t *));
	if (e->attr_pair == NULL) {
		free(e);
		return (NULL);
	}
	e->attr_count = 0;
	if (__s_add_attrlist(e, "objectClass", objclass) != NS_LDAP_SUCCESS) {
		free(e->attr_pair);
		free(e);
		return (NULL);
	}
	return (e);
}


/*
 * Conversion:			passwd
 * Input format:		struct passwd
 * Exported objectclass:	posixAccount
 */
static int
__s_cvt_passwd(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	/* routine specific */
	struct passwd	*ptr;
	int		max_attr = 9;
	char		ibuf[10];
	static		char *oclist[] = {
			"posixAccount",
			"shadowAccount",
			"account",
			"top",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);
	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (struct passwd *)data;

	if (ptr->pw_name == NULL || ptr->pw_uid > MAXUID ||
	    ptr->pw_gid > MAXUID || ptr->pw_dir == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "uid=%s", ptr->pw_name);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	/* Error check the data and add the attributes */
	rc = __s_add_attr(e, "uid", ptr->pw_name);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}
	rc = __s_add_attr(e, "cn", ptr->pw_name);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	if (ptr->pw_passwd != NULL &&
	    ptr->pw_passwd[0] != '\0') {
		rc = __s_add_attr(e, "userPassword", ptr->pw_passwd);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	(void) sprintf(ibuf, "%u", ptr->pw_uid);
	rc = __s_add_attr(e, "uidNumber", ibuf);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	(void) sprintf(ibuf, "%u", ptr->pw_gid);
	rc = __s_add_attr(e, "gidNumber", ibuf);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}
	if (ptr->pw_gecos != NULL &&
	    ptr->pw_gecos[0] != '\0') {
		rc = __s_add_attr(e, "gecos", ptr->pw_gecos);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	rc = __s_add_attr(e, "homeDirectory", ptr->pw_dir);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}
	if (ptr->pw_shell != NULL &&
	    ptr->pw_shell[0] != '\0') {
		rc = __s_add_attr(e, "loginShell", ptr->pw_shell);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	return (NS_LDAP_SUCCESS);
}

/*
 * escape_str function escapes special characters in str and
 * copies to escstr string.
 *
 * return 0 for successful
 *        1 for fail
 */
static int escape_str(char *escstr, char *str)
{
	int	index = 0;

	while ((*str != '\0') && (index < (RDNSIZE - 1))) {
		if (*str == '+' || *str == ';' || *str == '>' ||
		    *str == '<' || *str == ',' || *str == '"' ||
		    *str == '\\' || *str == '=' ||
		    (*str == '#' && index == 0)) {
			*escstr++ = '\\';
			*escstr++ = *str++;
			index += 2;
		} else {
			*escstr++ = *str++;
			index++;
		}
	}

	if (*str == '\0') {
		*escstr = '\0';
		return (0);
	} else {
		return (1);
	}
}

/*
 * Conversion:			project
 * Input format:		struct project
 * Exported objectclass:	SolarisProject
 */
static int
__s_cvt_project(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];

	/* routine specific */
	struct project	*ptr;
	int		max_attr = 9;
	char		ibuf[11];
	static char	*oclist[] = {
			"SolarisProject",
			"top",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);

	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (struct project *)data;

	if (ptr->pj_name == NULL || ptr->pj_projid > MAXUID) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "SolarisProjectName=%s", ptr->pj_name);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	/* Error check the data and add the attributes */

	/* Project name */
	rc = __s_add_attr(e, "SolarisProjectName", ptr->pj_name);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	/*
	 * Project ID:
	 * ibuf is 11 chars big, which should be enough for string
	 * representation of 32bit number + nul-car
	 */
	if (snprintf(ibuf, sizeof (ibuf), "%u", ptr->pj_projid) < 0) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (NS_LDAP_INVALID_PARAM);
	}
	rc = __s_add_attr(e, "SolarisProjectID", ibuf);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	/* Comment/Description */
	if (ptr->pj_comment != NULL && ptr->pj_comment[0] != '\0') {
		rc = __s_add_attr(e, "description", ptr->pj_comment);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	/* Attributes */
	if (ptr->pj_attr != NULL && ptr->pj_attr[0] != '\0') {
		rc = __s_add_attr(e, "SolarisProjectAttr", ptr->pj_attr);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	/* Users */
	if (ptr->pj_users != NULL) {
		rc = __s_add_attrlist(e, "memberUid", ptr->pj_users);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	/* Groups */
	if (ptr->pj_groups != NULL) {
		rc = __s_add_attrlist(e, "memberGid", ptr->pj_groups);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}



	return (NS_LDAP_SUCCESS);
}
/*
 * Conversion:			shadow
 * Input format:		struct shadow
 * Exported objectclass:	shadowAccount
 */
static int
__s_cvt_shadow(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	/* routine specific */
	struct spwd	*ptr;
	int		max_attr = 10;
	char		ibuf[10];
	static		char *oclist[] = {
			"posixAccount",
			"shadowAccount",
			"account",
			"top",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);
	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (struct spwd *)data;

	if (ptr->sp_namp == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "uid=%s", ptr->sp_namp);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	/* Error check the data and add the attributes */
	rc = __s_add_attr(e, "uid", ptr->sp_namp);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	if (ptr->sp_pwdp == NULL) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (NS_LDAP_INVALID_PARAM);
	} else {
		rc = __s_add_attr(e, "userPassword", ptr->sp_pwdp);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}
	if (ptr->sp_lstchg >= 0) {
		(void) sprintf(ibuf, "%d", ptr->sp_lstchg);
		rc = __s_add_attr(e, "shadowLastChange", ibuf);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}
	if (ptr->sp_min >= 0) {
		(void) sprintf(ibuf, "%d", ptr->sp_min);
		rc = __s_add_attr(e, "shadowMin", ibuf);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}
	if (ptr->sp_max >= 0) {
		(void) sprintf(ibuf, "%d", ptr->sp_max);
		rc = __s_add_attr(e, "shadowMax", ibuf);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}
	if (ptr->sp_warn >= 0) {
		(void) sprintf(ibuf, "%d", ptr->sp_warn);
		rc = __s_add_attr(e, "shadowWarning", ibuf);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}
	if (ptr->sp_inact >= 0) {
		(void) sprintf(ibuf, "%d", ptr->sp_inact);
		rc = __s_add_attr(e, "shadowInactive", ibuf);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}
	if (ptr->sp_expire >= 0) {
		(void) sprintf(ibuf, "%d", ptr->sp_expire);
		rc = __s_add_attr(e, "shadowExpire", ibuf);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}
	(void) sprintf(ibuf, "%d", ptr->sp_flag);
	rc = __s_add_attr(e, "shadowFlag", ibuf);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	return (NS_LDAP_SUCCESS);
}


/*
 * Conversion:			group
 * Input format:		struct group
 * Exported objectclass:	posixGroup
 */
static int
__s_cvt_group(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	/* routine specific */
	struct group	*ptr;
	int		i, j, k;
	char		**nm, **lm;
	int		max_attr = 4;
	char		ibuf[10];
	static		char *oclist[] = {
			"posixGroup",
			"top",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);
	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (struct group *)data;

	if (ptr->gr_name == NULL || ptr->gr_gid > MAXUID) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "cn=%s", ptr->gr_name);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	/* Error check the data and add the attributes */
	rc = __s_add_attr(e, "cn", ptr->gr_name);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	(void) sprintf(ibuf, "%u", ptr->gr_gid);
	rc = __s_add_attr(e, "gidNumber", ibuf);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}
	if (ptr->gr_passwd && ptr->gr_passwd[0] != '\0') {
		rc = __s_add_attr(e, "userPassword", ptr->gr_passwd);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	if (ptr->gr_mem && ptr->gr_mem[0]) {
		lm = ptr->gr_mem;
		for (i = 0; *lm; i++, lm++)
			;
		lm = ptr->gr_mem;
		nm = (char **)calloc(i+2, sizeof (char *));
		if (nm == NULL) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (NS_LDAP_MEMORY);
		}
		for (j = 0; j < i; j++) {
			nm[j] = strdup(lm[j]);
			if (nm[j] == NULL) {
				for (k = 0; k < j; k++)
					free(nm[k]);
				free(nm);
				__s_cvt_freeEntryRdn(entry, rdn);
				return (NS_LDAP_MEMORY);
			}
		}
		rc = __s_add_attrlist(e, "memberUid", nm);
		for (j = 0; j < i; j++) {
			free(nm[j]);
		}
		free(nm);
		nm = NULL;
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	return (NS_LDAP_SUCCESS);
}

/*
 * Conversion:			hosts
 * Input format:		struct hostent
 * Exported objectclass:	ipHost
 */
static int
__s_cvt_hosts(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	/* routine specific */
	struct hostent	*ptr;
	int		max_attr = 6;
	int		i, j, k;
	char		**nm, **lm;
	static		char *oclist[] = {
			"ipHost",
			"device",
			"top",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);
	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (struct hostent *)data;

	if (ptr->h_name == NULL ||
	    ptr->h_addr_list == NULL || ptr->h_addr_list[0] == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "cn=%s+ipHostNumber=%s",
	    ptr->h_name, ptr->h_addr_list[0]);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	/* Error check the data and add the attributes */
	if (ptr->h_aliases && ptr->h_aliases[0]) {
		lm = ptr->h_aliases;
		/*
		 * If there is a description, 'i' will contain
		 * the index of the description in the aliases list
		 */
		for (i = 0; *lm && (*lm)[0] != '#'; i++, lm++)
			;
		lm = ptr->h_aliases;
		nm = (char **)calloc(i+2, sizeof (char *));
		if (nm == NULL) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (NS_LDAP_MEMORY);
		}
		nm[0] = ptr->h_name;
		for (j = 0; j < i; j++)
			nm[j+1] = ptr->h_aliases[j];

		rc = __s_add_attrlist(e, "cn", nm);

		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			free(nm);
			return (rc);
		}

		if (lm[i] && lm[i][0] == '#') {
			nm[0] = &(lm[i][1]);
			nm[1] = NULL;
			rc = __s_add_attrlist(e, "description", nm);
		}
		free(nm);
		nm = NULL;
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	} else {
		rc = __s_add_attr(e, "cn", ptr->h_name);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	if (ptr->h_addr_list && ptr->h_addr_list[0]) {
		lm = ptr->h_addr_list;
		for (i = 0; *lm; i++, lm++)
			;
		lm = ptr->h_addr_list;
		nm = (char **)calloc(i+2, sizeof (char *));
		if (nm == NULL) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (NS_LDAP_MEMORY);
		}
		for (j = 0; j < i; j++) {
			nm[j] = strdup(lm[j]);
			if (nm[j] == NULL) {
				for (k = 0; k < j; k++)
					free(nm[k]);
				free(nm);
				__s_cvt_freeEntryRdn(entry, rdn);
				return (NS_LDAP_MEMORY);
			}
		}
		rc = __s_add_attrlist(e, "ipHostNumber", nm);
		for (j = 0; j < i; j++) {
			free(nm[j]);
		}
		free(nm);
		nm = NULL;
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	} else {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (NS_LDAP_INVALID_PARAM);
	}

	return (NS_LDAP_SUCCESS);
}

/*
 * Conversion:			rpc
 * Input format:		struct rpcent
 * Exported objectclass:	oncRpc
 */
static int
__s_cvt_rpc(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	/* routine specific */
	struct rpcent	*ptr;
	int		max_attr = 3;
	int		i, j;
	char		**nm;
	char		ibuf[10];
	static		char *oclist[] = {
			"oncRpc",
			"top",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);
	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (struct rpcent *)data;

	if (ptr->r_name == NULL || ptr->r_number < 0) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "cn=%s", ptr->r_name);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	/* Error check the data and add the attributes */
	if (ptr->r_aliases && ptr->r_aliases[0]) {
		nm = ptr->r_aliases;
		for (i = 0; *nm; i++, nm++)
			;
		nm = (char **)calloc(i+2, sizeof (char *));
		if (nm == NULL) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (NS_LDAP_MEMORY);
		}
		nm[0] = ptr->r_name;
		for (j = 0; j < i; j++)
			nm[j+1] = ptr->r_aliases[j];

		rc = __s_add_attrlist(e, "cn", nm);
		free(nm);
		nm = NULL;
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	} else {
		rc = __s_add_attr(e, "cn", ptr->r_name);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	if (ptr->r_number >= 0) {
		(void) sprintf(ibuf, "%d", ptr->r_number);
		rc = __s_add_attr(e, "oncRpcNumber", ibuf);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	return (NS_LDAP_SUCCESS);

}

/*
 * Conversion:			protocols
 * Input format:		struct protoent
 * Exported objectclass:	ipProtocol
 */
static int
__s_cvt_protocols(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	/* routine specific */
	struct protoent	*ptr;
	int		max_attr = 3;
	int		i, j;
	char		ibuf[10];
	char		**nm;
	static		char *oclist[] = {
			"ipProtocol",
			"top",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);
	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (struct protoent *)data;

	if (ptr->p_name == NULL || ptr->p_proto < 0) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "cn=%s", ptr->p_name);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	/* Error check the data and add the attributes */
	if (ptr->p_aliases && ptr->p_aliases[0]) {
		nm = ptr->p_aliases;
		for (i = 0; *nm; i++, nm++)
			;
		nm = (char **)calloc(i+2, sizeof (char *));
		if (nm == NULL) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (NS_LDAP_MEMORY);
		}
		nm[0] = ptr->p_name;
		for (j = 0; j < i; j++)
			nm[j+1] = ptr->p_aliases[j];

		rc = __s_add_attrlist(e, "cn", nm);
		free(nm);
		nm = NULL;
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	} else {
		rc = __s_add_attr(e, "cn", ptr->p_name);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	(void) sprintf(ibuf, "%d", ptr->p_proto);
	rc = __s_add_attr(e, "ipProtocolNumber", ibuf);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	return (NS_LDAP_SUCCESS);

}

/*
 * Conversion:			services
 * Input format:		struct servent
 * Exported objectclass:	ipService
 */
static int
__s_cvt_services(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	char		esc_str[RDNSIZE];
	/* routine specific */
	struct servent	*ptr;
	int		max_attr = 4;
	int		i, j;
	char		ibuf[10];
	char		**nm;
	static		char *oclist[] = {
			"ipService",
			"top",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);
	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (struct servent *)data;

	if (ptr->s_name == NULL || ptr->s_port < 0 || ptr->s_proto == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/*
	 * Escape special characters in service name.
	 */
	if (escape_str(esc_str, ptr->s_name) != 0) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "cn=%s+ipServiceProtocol=%s",
	    esc_str, ptr->s_proto);

	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	/* Error check the data and add the attributes */
	if (ptr->s_aliases && ptr->s_aliases[0]) {
		nm = ptr->s_aliases;
		for (i = 0; *nm; i++, nm++)
			;
		nm = (char **)calloc(i+2, sizeof (char *));
		if (nm == NULL) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (NS_LDAP_MEMORY);
		}
		nm[0] = ptr->s_name;
		for (j = 0; j < i; j++)
			nm[j+1] = ptr->s_aliases[j];

		rc = __s_add_attrlist(e, "cn", nm);
		free(nm);
		nm = NULL;
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	} else {
		rc = __s_add_attr(e, "cn", ptr->s_name);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	(void) sprintf(ibuf, "%d", ptr->s_port);
	rc = __s_add_attr(e, "ipServicePort", ibuf);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}
	rc = __s_add_attr(e, "ipServiceProtocol", ptr->s_proto);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	return (NS_LDAP_SUCCESS);
}

/*
 * Conversion:			networks
 * Input format:		struct netent
 * Exported objectclass:	ipNetwork
 */
static int
__s_cvt_networks(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	/* routine specific */
	struct netent	*ptr;
	int		max_attr = 4;
	int		i, j;
	char		cp[64];
	char		**nm;
	static		char *oclist[] = {
			"ipNetwork",
			"top",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);
	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (struct netent *)data;

	if (ptr->n_name == NULL || ptr->n_net == 0) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	(void) snprintf(cp, sizeof (cp), "%d.%d.%d.%d",
	    (ptr->n_net & 0xFF000000) >> 24,
	    (ptr->n_net & 0x00FF0000) >> 16,
	    (ptr->n_net & 0x0000FF00) >> 8,
	    (ptr->n_net & 0x000000FF));

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "ipNetworkNumber=%s", cp);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	/* Error check the data and add the attributes */
	if (ptr->n_aliases && ptr->n_aliases[0]) {
		nm = ptr->n_aliases;
		for (i = 0; *nm; i++, nm++)
			;
		nm = (char **)calloc(i+2, sizeof (char *));
		if (nm == NULL) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (NS_LDAP_MEMORY);
		}
		nm[0] = ptr->n_name;
		for (j = 0; j < i; j++)
			nm[j+1] = ptr->n_aliases[j];

		rc = __s_add_attrlist(e, "cn", nm);
		free(nm);
		nm = NULL;
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	} else {
		rc = __s_add_attr(e, "cn", ptr->n_name);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	rc = __s_add_attr(e, "ipNetworkNumber", cp);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	return (NS_LDAP_SUCCESS);

}
/*
 * Conversion:			netmasks
 * Input format:		struct _ns_netmasks
 * Exported objectclass:	ipNetwork
 */
static int
__s_cvt_netmasks(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	/* routine specific */
	struct _ns_netmasks *ptr;
	int		max_attr = 4;
	static		char *oclist[] = {
			"ipNetwork",
			"top",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);
	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (struct _ns_netmasks *)data;

	if (ptr->netnumber == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "ipNetworkNumber=%s", ptr->netnumber);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	/* Error check the data and add the attributes */
	rc = __s_add_attr(e, "ipNetworkNumber", ptr->netnumber);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	if (ptr->netmask != NULL) {
		rc = __s_add_attr(e, "ipNetmaskNumber", ptr->netmask);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	return (NS_LDAP_SUCCESS);

}
/*
 * Conversion:			netgroups
 * Input format:		struct _ns_netgroups
 * Exported objectclass:	nisNetgroup
 */
static int
__s_cvt_netgroups(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	/* routine specific */
	struct _ns_netgroups *ptr;
	int		max_attr = 6;
	int		i, j;
	char		**nm;
	static		char *oclist[] = {
			"nisNetgroup",
			"top",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);
	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (struct _ns_netgroups *)data;

	if (ptr->name == NULL || *ptr->name == '\0') {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "cn=%s", ptr->name);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	rc = __s_add_attr(e, "cn", ptr->name);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	/* Error check the data and add the attributes */
	if (ptr->triplet && ptr->triplet[0]) {
		nm = ptr->triplet;
		for (i = 0; *nm; i++, nm++)
			;
		nm = (char **)calloc(i+2, sizeof (char *));
		if (nm == NULL) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (NS_LDAP_MEMORY);
		}
		for (j = 0; j < i; j++)
			nm[j] = ptr->triplet[j];

		rc = __s_add_attrlist(e, "nisNetgroupTriple", nm);
		free(nm);
		nm = NULL;
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}
	if (ptr->netgroup && ptr->netgroup[0]) {
		nm = ptr->netgroup;
		for (i = 0; *nm; i++, nm++)
			;
		nm = (char **)calloc(i+2, sizeof (char *));
		if (nm == NULL) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (NS_LDAP_MEMORY);
		}
		for (j = 0; j < i; j++)
			nm[j] = ptr->netgroup[j];

		rc = __s_add_attrlist(e, "memberNisNetgroup", nm);
		free(nm);
		nm = NULL;
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}
	return (NS_LDAP_SUCCESS);
}
/*
 * Conversion:			bootparams
 * Input format:		struct _ns_bootp
 * Exported objectclass:	bootableDevice, device
 */
static int
__s_cvt_bootparams(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	/* routine specific */
	struct _ns_bootp *ptr;
	int		max_attr = 4;
	int		i, j;
	char		**nm;
	static		char *oclist[] = {
			"bootableDevice",
			"device",
			"top",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);
	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (struct _ns_bootp *)data;

	if (ptr->name == NULL || *ptr->name == '\0') {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "cn=%s", ptr->name);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	rc = __s_add_attr(e, "cn", ptr->name);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	/* Error check the data and add the attributes */
	if (ptr->param && ptr->param[0]) {
		nm = ptr->param;
		for (i = 0; *nm; i++, nm++)
			;
		nm = (char **)calloc(i+2, sizeof (char *));
		if (nm == NULL) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (NS_LDAP_MEMORY);
		}
		for (j = 0; j < i; j++)
			nm[j] = ptr->param[j];

		rc = __s_add_attrlist(e, "bootParameter", nm);
		free(nm);
		nm = NULL;
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	return (NS_LDAP_SUCCESS);

}
/*
 * Conversion:			ethers
 * Input format:		struct _ns_ethers
 * Exported objectclass:	ieee802Device, device
 */
static int
__s_cvt_ethers(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	/* routine specific */
	struct _ns_ethers	*ptr;
	int		max_attr = 4;
	static		char *oclist[] = {
			"ieee802Device",
			"device",
			"top",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);
	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (struct _ns_ethers *)data;

	if (ptr->name == NULL || *ptr->name == '\0' || ptr->ether == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "cn=%s", ptr->name);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	/* Error check the data and add the attributes */
	rc = __s_add_attr(e, "cn", ptr->name);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	rc = __s_add_attr(e, "macAddress", ptr->ether);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	return (NS_LDAP_SUCCESS);
}
/*
 * This function is used when processing an ethers (objectclass: ieee802Device)
 * or a bootparams (objectclass: bootableDevice) entry, and the entry is
 * already found in LDAP. Since both ethers and bootparams share the same
 * LDAP container, we want to check that the entry found in LDAP is:
 * - either the same entry (same cn, same objectclass): we don't do anything
 *   in this case
 * - or an entry which does not have the objectclass we are interesting in:
 *   in this case, we modify the existing entry by adding the relevant
 *   objectclass (ieee802Device or bootableDevice) and the relevant attribute(s)
 *   from the attribute list previously computing by the relevant conversion
 *   function.
 *   Note: from conversion functions __s_cvt_ethers() and  __s_cvt_bootparams()
 *   we know that there is only 1 more attribute today to add (macAddress
 *   or bootParameter)
 */
#define	_MAX_ATTR_ETHBOOTP	2
static int
modify_ethers_bootp(
	const char *service,
	const char *rdn,
	const char *fulldn,
	const ns_ldap_attr_t * const *attrlist,
	const ns_cred_t *cred,
	const int flags,
	ns_ldap_error_t	 **errorp)
{
	char	filter[BUFSIZ];
	ns_ldap_result_t *resultp;
	int rc = 0;
	int i;
	ns_ldap_attr_t *new_attrlist[_MAX_ATTR_ETHBOOTP+1];
	ns_ldap_attr_t new_attrlist0;
	char *new_attrvalue0[1];
	const ns_ldap_attr_t	* const *aptr = attrlist;
	ns_ldap_attr_t *aptr2;
	ns_ldap_error_t	 *new_errorp = NULL;

	if (rdn == NULL || fulldn == NULL || attrlist == NULL ||
	    errorp == NULL || service == NULL)
		return (NS_LDAP_OP_FAILED);

	bzero(&new_attrlist, sizeof (new_attrlist));
	bzero(&new_attrlist0, sizeof (new_attrlist0));
	new_attrlist[0] = &new_attrlist0;
	new_attrlist[0]->attrvalue = new_attrvalue0;

	new_attrlist[0]->attrname = "objectclass";
	new_attrlist[0]->value_count = 1;
	if (strcasecmp(service, "ethers") == NULL) {
		(void) snprintf(&filter[0], sizeof (filter),
		    "(&(objectClass=ieee802Device)(%s))", rdn);
		new_attrlist[0]->attrvalue[0] = "ieee802Device";
	} else {
		(void) snprintf(&filter[0], sizeof (filter),
		    "(&(objectClass=bootableDevice)(%s))", rdn);
		new_attrlist[0]->attrvalue[0] = "bootableDevice";
	}

	rc =  __ns_ldap_list(service, filter, NULL, (const char **)NULL,
	    NULL, NS_LDAP_SCOPE_SUBTREE, &resultp, &new_errorp,
	    NULL, NULL);

	switch (rc) {
	case NS_LDAP_SUCCESS:
		/*
		 * entry already exists for this service
		 * return NS_LDAP_INTERNAL and do not modify the incoming errorp
		 */
		rc = NS_LDAP_INTERNAL;
		break;
	case NS_LDAP_NOTFOUND:
		/*
		 * entry not found with the given objectclasss but entry exists
		 * hence add the relevant attribute (macAddress or bootparams).
		 */
		i = 1;
		while (*aptr && (i < _MAX_ATTR_ETHBOOTP)) {
			/* aptr2 needed here to avoid lint warning */
			aptr2 = (ns_ldap_attr_t *)*aptr++;
			if ((strcasecmp(aptr2->attrname, "cn") != 0) &&
			    (strcasecmp(aptr2->attrname,
			    "objectclass") != 0)) {
				new_attrlist[i++] = (ns_ldap_attr_t *)aptr2;
			}
		}

		if (i != _MAX_ATTR_ETHBOOTP) {
			/* we haven't found all expected attributes */
			rc = NS_LDAP_OP_FAILED;
			break;
		}

		aptr = (const ns_ldap_attr_t	* const *) new_attrlist;
		/* clean errorp first */
		(void) __ns_ldap_freeError(errorp);
		rc =  __ns_ldap_addAttr(service, fulldn, aptr, cred, flags,
		    errorp);
		break;
	default:
		/*
		 * unexpected error happenned
		 * returning relevant error
		 */
		(void) __ns_ldap_freeError(errorp);
		*errorp = new_errorp;
		break;
	}

	return (rc);
}

/*
 * Conversion:			publickey
 * Input format:		struct _ns_pubkey
 * Exported objectclass:	NisKeyObject
 */
static int
__s_cvt_publickey(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	/* routine specific */
	struct _ns_pubkey	*ptr;
	int		max_attr = 3;
	static		char *oclist[] = {
			"NisKeyObject",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);
	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (struct _ns_pubkey *)data;

	if (ptr->name == NULL || *ptr->name == '\0' || ptr->pubkey == NULL ||
	    ptr->privkey == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	if (ptr->hostcred == NS_HOSTCRED_FALSE)
		(void) snprintf(trdn, RDNSIZE, "uid=%s", ptr->name);
	else
		(void) snprintf(trdn, RDNSIZE, "cn=%s", ptr->name);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	/* Error check the data and add the attributes */

	rc = __s_add_attr(e, "nisPublickey", ptr->pubkey);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	rc = __s_add_attr(e, "nisSecretkey", ptr->privkey);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	return (NS_LDAP_SUCCESS);
}
/*
 * Conversion:			aliases
 * Input format:		struct _ns_alias
 * Exported objectclass:	mailGroup
 */
static int
__s_cvt_aliases(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	/* routine specific */
	struct _ns_alias *ptr;
	int		max_attr = 4;
	int		i, j;
	char		**nm;
	static		char *oclist[] = {
			"mailGroup",
			"top",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);
	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (struct _ns_alias *)data;

	if (ptr->alias == NULL || *ptr->alias == '\0') {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "cn=%s", ptr->alias);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	rc = __s_add_attr(e, "mail", (char *)ptr->alias);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	/* Error check the data and add the attributes */
	if (ptr->member && ptr->member[0]) {
		nm = ptr->member;
		for (i = 0; *nm; i++, nm++)
			;
		nm = (char **)calloc(i+2, sizeof (char *));
		if (nm == NULL) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (NS_LDAP_MEMORY);
		}
		for (j = 0; j < i; j++)
			nm[j] = ptr->member[j];

		rc = __s_add_attrlist(e, "mgrpRFC822MailMember", nm);
		free(nm);
		nm = NULL;
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	return (NS_LDAP_SUCCESS);

}
/*
 * Conversion:			automount
 * Input format:		struct _ns_automount
 * Exported objectclass:	automount
 */
static int
__s_cvt_auto_mount(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	/* routine specific */
	struct _ns_automount *ptr;
	int		max_attr = 6;
	void		**paramVal = NULL;
	char		**mappedschema = NULL;
	int		version1 = 0;
	static		char *oclist[] = {
			NULL,
			"top",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);

	/* determine profile version number */
	rc = __ns_ldap_getParam(NS_LDAP_FILE_VERSION_P, &paramVal, errorp);
	if (paramVal && *paramVal &&
	    strcasecmp(*paramVal, NS_LDAP_VERSION_1) == 0)
		version1 = 1;
	if (paramVal)
		(void) __ns_ldap_freeParam(&paramVal);
	if (rc && errorp)
		(void) __ns_ldap_freeError(errorp);

	/* use old schema for version 1 profiles */
	if (version1)
		oclist[0] = "nisObject";
	else
		oclist[0] = "automount";

	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (struct _ns_automount *)data;

	if (ptr->key == NULL || *ptr->key == '\0' || ptr->value == NULL ||
	    ptr->mapname == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, version1 ? "cn=%s" : "automountKey=%s",
	    ptr->key);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	rc = __s_add_attr(e, version1 ? "cn" : "automountKey",
	    (char *)ptr->key);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	rc = __s_add_attr(e, version1 ? "nisMapEntry" : "automountInformation",
	    (char *)ptr->value);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	/*
	 * even for version 2, if automount is mapped to nisObject we
	 * still need 'nisMapName' attribute
	 */
	mappedschema = __ns_ldap_getMappedObjectClass("automount", "automount");
	if (mappedschema && mappedschema[0] &&
	    strcasecmp(mappedschema[0], "nisObject") == 0)
		version1 = 1;
	if (mappedschema)
		__s_api_free2dArray(mappedschema);

	if (version1) {
		rc = __s_add_attr(e, "nisMapName", (char *)ptr->mapname);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	return (NS_LDAP_SUCCESS);
}
/*
 * Conversion:			auth_attr
 * Input format:		authstr_t
 * Exported objectclass:	SolarisAuthAttr
 */
static int
__s_cvt_authattr(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	/* routine specific */
	authstr_t	*ptr;
	int		max_attr = 6;
	static		char *oclist[] = {
			"SolarisAuthAttr",
			"top",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);

	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (authstr_t *)data;

	if (ptr->name == NULL || ptr->name[0] == '\0' || ptr->attr == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "cn=%s", ptr->name);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	rc = __s_add_attr(e, "cn", ptr->name);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	rc = __s_add_attr(e, "SolarisAttrKeyValue", ptr->attr);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	if (ptr->res1 != NULL) {
		rc = __s_add_attr(e, "SolarisAttrReserved1", ptr->res1);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	if (ptr->res2 != NULL) {
		rc = __s_add_attr(e, "SolarisAttrReserved2", ptr->res2);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	if (ptr->short_desc != NULL) {
		rc = __s_add_attr(e, "SolarisAttrShortDesc", ptr->short_desc);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	if (ptr->long_desc != NULL) {
		rc = __s_add_attr(e, "SolarisAttrLongDesc", ptr->long_desc);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	return (NS_LDAP_SUCCESS);
}
/*
 * Conversion:			exec_attr
 * Input format:		execstr_t
 * Exported objectclass:	SolarisExecAttr
 */
static int
__s_cvt_execattr(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	char		esc_str[RDNSIZE];
	/* routine specific */
	execstr_t	*ptr;
	int		max_attr = 7;
	static		char *oclist[] = {
			"SolarisExecAttr",
			"SolarisProfAttr",
			"top",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);

	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (execstr_t *)data;

	if (ptr->name == NULL || ptr->name[0] == '\0' ||
	    ptr->policy == NULL || ptr->policy[0] == '\0' ||
	    ptr->type == NULL || ptr->type[0] == '\0' ||
	    ptr->id == NULL || ptr->id[0] == '\0') {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/*
	 * Escape special characters in ProfileID.
	 */
	if (escape_str(esc_str, ptr->id) != 0) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "cn=%s+SolarisKernelSecurityPolicy=%s"
	    "+SolarisProfileType=%s+SolarisProfileId=%s",
	    ptr->name, ptr->policy, ptr->type, esc_str);

	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	rc = __s_add_attr(e, "cn", ptr->name);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	rc = __s_add_attr(e, "SolarisKernelSecurityPolicy", ptr->policy);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	rc = __s_add_attr(e, "SolarisProfileType", ptr->type);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	rc = __s_add_attr(e, "SolarisProfileId", ptr->id);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	rc = __s_add_attr(e, "SolarisAttrKeyValue", ptr->attr);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	if (ptr->res1 != NULL) {
		rc = __s_add_attr(e, "SolarisAttrRes1", ptr->res1);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	if (ptr->res2 != NULL) {
		rc = __s_add_attr(e, "SolarisAttrRes2", ptr->res2);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	return (NS_LDAP_SUCCESS);
}
/*
 * Conversion:			prof_attr
 * Input format:		profstr_t
 * Exported objectclass:	SolarisProfAttr
 */
static int
__s_cvt_profattr(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	/* routine specific */
	profstr_t	*ptr;
	int		max_attr = 5;
	static		char *oclist[] = {
			"SolarisProfAttr",
			"top",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);

	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (profstr_t *)data;

	if (ptr->name == NULL || ptr->name[0] == '\0' || ptr->attr == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "cn=%s", ptr->name);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	rc = __s_add_attr(e, "cn", ptr->name);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	rc = __s_add_attr(e, "SolarisAttrKeyValue", ptr->attr);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	if (ptr->res1 != NULL) {
		rc = __s_add_attr(e, "SolarisAttrReserved1", ptr->res1);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	if (ptr->res2 != NULL) {
		rc = __s_add_attr(e, "SolarisAttrReserved2", ptr->res2);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	if (ptr->desc != NULL) {
		rc = __s_add_attr(e, "SolarisAttrLongDesc", ptr->desc);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	return (NS_LDAP_SUCCESS);
}
/*
 * Conversion:			user_attr
 * Input format:		userstr_t
 * Exported objectclass:	SolarisUserAttr
 */
static int
__s_cvt_userattr(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	/* routine specific */
	userstr_t	*ptr;
	int		max_attr = 5;
	static		char *oclist[] = {
			"SolarisUserAttr",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);

	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (userstr_t *)data;

	if (ptr->name == NULL || ptr->name[0] == '\0' ||
	    ptr->attr == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "uid=%s", ptr->name);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	/*
	 * SolarisUserAttr has no uid attribute
	 */

	rc = __s_add_attr(e, "SolarisAttrKeyValue", ptr->attr);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	if (ptr->qualifier != NULL) {
		rc = __s_add_attr(e, "SolarisUserQualifier", ptr->qualifier);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	if (ptr->res1 != NULL) {
		rc = __s_add_attr(e, "SolarisAttrReserved1", ptr->res1);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	if (ptr->res2 != NULL) {
		rc = __s_add_attr(e, "SolarisAttrReserved2", ptr->res2);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	return (NS_LDAP_SUCCESS);
}
/*
 * Conversion:			audit_user
 * Input format:		au_user_str_t
 * Exported objectclass:	SolarisAuditUser
 */
static int
__s_cvt_audituser(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	/* routine specific */
	au_user_str_t	*ptr;
	int		max_attr = 3;
	static		char *oclist[] = {
			"SolarisAuditUser",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);

	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (au_user_str_t *)data;

	if (ptr->au_name == NULL || ptr->au_name[0] == '\0') {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "uid=%s", ptr->au_name);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	/*
	 * Solaris AuditUser has no uid attribute
	 */

	if (ptr->au_always != NULL) {
		rc = __s_add_attr(e, "SolarisAuditAlways", ptr->au_always);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	if (ptr->au_never != NULL) {
		rc = __s_add_attr(e, "SolarisAuditNever", ptr->au_never);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(entry, rdn);
			return (rc);
		}
	}

	return (NS_LDAP_SUCCESS);
}
/*
 * Conversion:			tnrhtp
 * Input format:		tsol_tpstr_t
 * Exported objectclass:	ipTnetTemplate
 */
static int
__s_cvt_tnrhtp(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	char		esc_str[RDNSIZE];
	/* routine specific */
	int		max_attr = 2;
	tsol_tpstr_t	*ptr;
	static		char *oclist[] = {
			"ipTnetTemplate",
			"top",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);

	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (tsol_tpstr_t *)data;

	if (ptr->template == NULL || *ptr->template == '\0') {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/*
	 * Escape special characters in Template name.
	 */
	if (escape_str(esc_str, ptr->template) != 0) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "ipTnetTemplateName=%s", esc_str);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	rc = __s_add_attr(e, "ipTnetTemplateName", ptr->template);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	rc = __s_add_attr(e, "SolarisAttrKeyValue", ptr->attrs);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	return (NS_LDAP_SUCCESS);
}
/*
 * Conversion:			tnrhdb
 * Input format:		tsol_rhstr_t
 * Exported objectclass:	ipTnetHost
 */
static int
__s_cvt_tnrhdb(const void *data, char **rdn,
    ns_ldap_entry_t **entry, ns_ldap_error_t **errorp)
{
	ns_ldap_entry_t	*e;
	int		rc;
	char		trdn[RDNSIZE];
	/* routine specific */
	tsol_rhstr_t	*ptr;
	int		max_attr = 2;
	static		char *oclist[] = {
			"ipTnetHost",
			"ipTnetTemplate",
			"top",
			NULL
			};

	if (data == NULL || rdn == NULL || entry == NULL || errorp == NULL)
		return (NS_LDAP_OP_FAILED);

	*entry = e = __s_mk_entry(oclist, max_attr);
	if (e == NULL)
		return (NS_LDAP_MEMORY);

	/* Convert the structure */
	ptr = (tsol_rhstr_t *)data;

	if (ptr->address == NULL || *ptr->address == '\0' ||
	    ptr->template == NULL || *ptr->template == '\0') {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	/* Create an appropriate rdn */
	(void) snprintf(trdn, RDNSIZE, "ipTnetNumber=%s", ptr->address);
	*rdn = strdup(trdn);
	if (*rdn == NULL) {
		__ns_ldap_freeEntry(e);
		*entry = NULL;
		return (NS_LDAP_MEMORY);
	}

	rc = __s_add_attr(e, "ipTnetNumber", ptr->address);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	rc = __s_add_attr(e, "ipTnetTemplateName", ptr->template);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(entry, rdn);
		return (rc);
	}

	return (NS_LDAP_SUCCESS);
}
/*
 * Add Typed Entry Conversion data structures
 */

typedef struct	__ns_cvt_type {
	const char	*service;
	int		flags;
#define	AE		1	/* alway add entries */
	int		(*cvt_rtn)(const void *data,
				char		**rdn,
				ns_ldap_entry_t	**entry,
				ns_ldap_error_t	**errorp);
} __ns_cvt_type_t;

static __ns_cvt_type_t __s_cvtlist[] = {
	{ NS_LDAP_TYPE_PASSWD,		0, __s_cvt_passwd },
	{ NS_LDAP_TYPE_GROUP,		0, __s_cvt_group },
	{ NS_LDAP_TYPE_HOSTS,		0, __s_cvt_hosts },
	{ NS_LDAP_TYPE_IPNODES,		0, __s_cvt_hosts },
	{ NS_LDAP_TYPE_RPC,		0, __s_cvt_rpc },
	{ NS_LDAP_TYPE_PROTOCOLS,	0, __s_cvt_protocols },
	{ NS_LDAP_TYPE_NETWORKS,	0, __s_cvt_networks },
	{ NS_LDAP_TYPE_NETGROUP,	0, __s_cvt_netgroups },
	{ NS_LDAP_TYPE_ALIASES,		0, __s_cvt_aliases },
	{ NS_LDAP_TYPE_SERVICES,	0, __s_cvt_services },
	{ NS_LDAP_TYPE_ETHERS,		0, __s_cvt_ethers },
	{ NS_LDAP_TYPE_SHADOW,		0, __s_cvt_shadow },
	{ NS_LDAP_TYPE_NETMASKS,	0, __s_cvt_netmasks },
	{ NS_LDAP_TYPE_BOOTPARAMS,	0, __s_cvt_bootparams },
	{ NS_LDAP_TYPE_AUTHATTR,	0, __s_cvt_authattr },
	{ NS_LDAP_TYPE_EXECATTR,	0, __s_cvt_execattr },
	{ NS_LDAP_TYPE_PROFILE,		0, __s_cvt_profattr },
	{ NS_LDAP_TYPE_USERATTR,	AE, __s_cvt_userattr },
	{ NS_LDAP_TYPE_AUTOMOUNT,	0, __s_cvt_auto_mount },
	{ NS_LDAP_TYPE_PUBLICKEY,	AE, __s_cvt_publickey },
	{ NS_LDAP_TYPE_AUUSER,		AE, __s_cvt_audituser },
	{ NS_LDAP_TYPE_TNRHTP,		0,  __s_cvt_tnrhtp },
	{ NS_LDAP_TYPE_TNRHDB,		0,  __s_cvt_tnrhdb },
	{ NS_LDAP_TYPE_PROJECT,		0,  __s_cvt_project },
	{ NULL,				0, NULL },
};

/*
 * Add Typed Entry Routine
 */

/*ARGSUSED*/
int  __ns_ldap_addTypedEntry(
	const char *servicetype,
	const char *basedn,
	const void *data,
	const int  create,
	const ns_cred_t *cred,
	const int flags,
	ns_ldap_error_t **errorp)
{
	char			*rdn = NULL, *fulldn = NULL;
	void			**paramVal = NULL;
	ns_ldap_entry_t		*entry = NULL;
	const ns_ldap_attr_t	*const *modattrlist;
	ns_ldap_search_desc_t	**sdlist;
	char			**dns = NULL;
	char			trdn[RDNSIZE];
	char			service[BUFSIZE];
	int			rc = 0;
	int			automount = 0;
	int			i, s;

	rc = NS_LDAP_OP_FAILED;
	for (s = 0; __s_cvtlist[s].service != NULL; s++) {
		if (__s_cvtlist[s].cvt_rtn == NULL)
			continue;
		if (strcasecmp(__s_cvtlist[s].service, servicetype) == 0)
			break;
		/* Or, check if the servicetype is  auto_ */
		if (strcmp(__s_cvtlist[s].service,
		    NS_LDAP_TYPE_AUTOMOUNT) == 0 &&
		    strncasecmp(servicetype, NS_LDAP_TYPE_AUTOMOUNT,
		    sizeof (NS_LDAP_TYPE_AUTOMOUNT) - 1) == 0) {
			automount++;
			break;
		}
	}
	if (__s_cvtlist[s].service == NULL)
		return (rc);

	/* Convert the data */
	rc = (*__s_cvtlist[s].cvt_rtn)(data, &rdn, &entry, errorp);
	if (rc != NS_LDAP_SUCCESS) {
		__s_cvt_freeEntryRdn(&entry, &rdn);
		return (rc);
	}
	if (rdn == NULL) {
		__ns_ldap_freeEntry(entry);
		return (NS_LDAP_OP_FAILED);
	}

	if (strcmp(servicetype, "publickey") == 0) {
		struct _ns_pubkey *ptr;
		ptr = (struct _ns_pubkey *)data;
		if (ptr->hostcred == NS_HOSTCRED_TRUE)
			(void) strcpy(service, "hosts");
		else
			(void) strcpy(service, "passwd");
	} else
		(void) strcpy(service, servicetype);

	/* Create the Full DN */
	if (basedn == NULL) {
		rc = __s_api_get_SSD_from_SSDtoUse_service(service,
		    &sdlist, errorp);
		if (rc != NS_LDAP_SUCCESS) {
			__s_cvt_freeEntryRdn(&entry, &rdn);
			return (rc);
		}

		if (sdlist == NULL) {
			rc = __s_api_getDNs(&dns, service, errorp);
			if (rc != NS_LDAP_SUCCESS) {
				if (dns) {
					__s_api_free2dArray(dns);
					dns = NULL;
				}
				__s_cvt_freeEntryRdn(&entry, &rdn);
				return (rc);
			}
			(void) snprintf(trdn, RDNSIZE, "%s,%s", rdn, dns[0]);
			__s_api_free2dArray(dns);
		} else {
			if (sdlist[0]->basedn) {
				(void) snprintf(trdn, RDNSIZE, "%s,%s",
				    rdn, sdlist[0]->basedn);
			} else {
				__s_cvt_freeEntryRdn(&entry, &rdn);
				return (NS_LDAP_OP_FAILED);
			}
		}
		i = strlen(trdn) - 1;
		if (trdn[i] == COMMATOK) {
			rc = __ns_ldap_getParam(NS_LDAP_SEARCH_BASEDN_P,
			    &paramVal, errorp);
			if (rc != NS_LDAP_SUCCESS) {
				__s_cvt_freeEntryRdn(&entry, &rdn);
				return (rc);
			}
			i = strlen(trdn) + strlen((char *)(paramVal[0])) + 1;
			fulldn = (char *)calloc(i, 1);
			if (fulldn == NULL) {
				(void) __ns_ldap_freeParam(&paramVal);
				__s_cvt_freeEntryRdn(&entry, &rdn);
				return (NS_LDAP_MEMORY);
			}
			(void) snprintf(fulldn, i, "%s%s", trdn,
			    (char *)(paramVal[0]));
			(void) __ns_ldap_freeParam(&paramVal);
		} else {
			fulldn = strdup(trdn);
			if (fulldn == NULL) {
				__s_cvt_freeEntryRdn(&entry, &rdn);
				return (NS_LDAP_MEMORY);
			}
		}
	} else {
		i = strlen(rdn) + strlen(basedn) + 2;
		fulldn = (char *)calloc(i, 1);
		if (fulldn == NULL) {
			__s_cvt_freeEntryRdn(&entry, &rdn);
			return (NS_LDAP_MEMORY);
		}
		(void) snprintf(fulldn, i, "%s,%s", rdn, basedn);
	}

	modattrlist = (const ns_ldap_attr_t * const *)entry->attr_pair;
	/* Check to see if the entry exists already */
	/* May need to delete or update first */

	if (create != 1) {
		/* Modify the entry */
		/*
		 * To add a shadow-like entry, the addTypedEntry function
		 * would call __ns_ldap_repAttr first, and if server says
		 * LDAP_NO_SUCH_OBJECT, then it tries __ns_ldap_addEntry.
		 * This is to allow a netmask entry to be added even if the
		 * base network entry is not in the directory. It would work
		 * because the difference between the schema for the network
		 * and netmask data contains only MAY attributes.
		 *
		 * But for shadow data, the attributes do not have MUST
		 * attributes the base entry needs, so if the __ns_ldap_addEntry
		 * is executed, it would fail. The real reason, however, is that
		 * the base entry did not exist. So returning
		 * LDAP_OBJECT_CLASS_VIOLATION would just confused.
		 */
		if ((__s_cvtlist[s].flags & AE) != 0)
			rc = __ns_ldap_addAttr(service, fulldn, modattrlist,
			    cred, flags, errorp);
		else {
			rc = __ns_ldap_repAttr(service, fulldn, modattrlist,
			    cred, flags, errorp);
			if (rc == NS_LDAP_INTERNAL && *errorp &&
			    (*errorp)->status == LDAP_NO_SUCH_OBJECT) {
				(void) __ns_ldap_freeError(errorp);
				rc = __ns_ldap_addEntry(service, fulldn,
				    entry, cred, flags, errorp);
				if (rc == NS_LDAP_INTERNAL && *errorp &&
				    (*errorp)->status ==
				    LDAP_OBJECT_CLASS_VIOLATION)
					(*errorp)->status = LDAP_NO_SUCH_OBJECT;
			}
		}
	} else {
		/* Add the entry */
		rc = __ns_ldap_addEntry(service, fulldn, entry,
		    cred, flags, errorp);
		if (rc == NS_LDAP_INTERNAL && *errorp &&
		    (*errorp)->status == LDAP_ALREADY_EXISTS &&
		    ((strcmp(service, "ethers") == 0) ||
		    (strcmp(service, "bootparams") == 0))) {
			rc = modify_ethers_bootp(service, rdn, fulldn,
			    modattrlist, cred, flags, errorp);
		}
	}

	/* Free up entry created by conversion routine */
	if (fulldn != NULL)
		free(fulldn);
	__s_cvt_freeEntryRdn(&entry, &rdn);
	return (rc);
}


/*
 * Append the default base dn to the dn
 * when it ends with ','.
 * e.g.
 * SSD = service:ou=foo,
 */
int
__s_api_append_default_basedn(const char *dn, char **new_dn, int *allocated,
    ns_ldap_error_t **errp)
{

	int		rc = NS_LDAP_SUCCESS, len = 0;
	void		**param = NULL;
	char		*str = NULL;

	*allocated = FALSE;
	*new_dn = NULL;

	if (dn == NULL)
		return (NS_LDAP_INVALID_PARAM);

	rc = __ns_ldap_getParam(NS_LDAP_SEARCH_BASEDN_P,
	    (void ***)&param, errp);

	if (rc != NS_LDAP_SUCCESS) {
		if (param)
			(void) __ns_ldap_freeParam(&param);
		return (rc);
	}

	len = strlen(dn);
	str = ((char **)param)[0];
	len = len + strlen(str) +1;
	*new_dn = (char *)malloc(len);
	if (*new_dn == NULL) {
		(void) __ns_ldap_freeParam(&param);
		return (NS_LDAP_MEMORY);
	}
	*allocated = TRUE;

	(void) strcpy(*new_dn, dn);
	(void) strcat(*new_dn, str);

	(void) __ns_ldap_freeParam(&param);
	return (NS_LDAP_SUCCESS);
}

/*
 * Flatten the input ns_ldap_attr_t list, 'attr', and convert it into an
 * ldap_strlist_t structure in buffer 'buf', to be used by ldap_cachemgr.
 * The output contains a count, a list of offsets, which show where the
 * corresponding copied attribute type and attribute value are located.
 * For example, for dn=aaaa, userpassword=bbbb, shadowlastchange=cccc,
 * the output is the ldap_strlist_t structure with: ldap_count = 6,
 * (buf + ldap_offsets[0]) -> "dn"
 * (buf + ldap_offsets[1]) -> "aaaa"
 * (buf + ldap_offsets[2]) -> "userPassword"
 * (buf + ldap_offsets[3]) -> "bbbb"
 * (buf + ldap_offsets[4]) -> "shadowlastchange"
 * (buf + ldap_offsets[5]) -> "cccc"
 * and all the string data shown above copied into the buffer after
 * the offset array. The total length of the data will be the return
 * value, or -1 if error.
 */
static int
attr2list(const char *dn, ns_ldap_attr_t **attr,
    char *buf, int bufsize)
{
	int		c = 0;
	char		*ap;
	int		ao;
	ldap_strlist_t	*al = (ldap_strlist_t *)buf;
	ns_ldap_attr_t	*a = (ns_ldap_attr_t *)*attr;
	ns_ldap_attr_t	**aptr = (ns_ldap_attr_t **)attr;

	/* bufsize > strlen(dn) + strlen("dn") + 1 ('\0') */
	if ((strlen(dn) + 2 + 1) >= bufsize)
		return (-1);

	/* count number of attributes */
	while (*aptr++)
		c++;
	al->ldap_count = 2 + c * 2;
	ao = sizeof (al->ldap_count) + sizeof (al->ldap_offsets[0]) *
	    al->ldap_count;
	if (ao > bufsize)
		return (-1);
	al->ldap_offsets[0] = ao;
	ap = buf + ao;
	ao += 3;

	/* copy entry DN */
	if (ao > bufsize)
		return (-1);
	(void) strlcpy(ap, "dn", bufsize);
	ap += 3;

	al->ldap_offsets[1] = ao;
	ao += strlen(dn) + 1;
	if (ao > bufsize)
		return (-1);
	(void) strlcpy(ap, dn, bufsize);
	ap = buf + ao;

	aptr = attr;
	for (c = 2; c < al->ldap_count; c++, aptr++) {
		a = *aptr;
		if (a->attrname == NULL || a->attrvalue == NULL ||
		    a->value_count != 1 || a->attrvalue[0] == NULL)
			return (-1);
		al->ldap_offsets[c] = ao;
		ao += strlen(a->attrname) + 1;
		if (ao > bufsize)
			return (-1);
		(void) strlcpy(ap, a->attrname, bufsize);
		ap = buf + ao;

		c++;
		al->ldap_offsets[c] = ao;
		ao += strlen(a->attrvalue[0]) + 1;
		(void) strlcpy(ap, a->attrvalue[0], bufsize);
		ap = buf + ao;
	};

	return (ao);
}

/*
 * Send a modify request to the ldap_cachemgr daemon
 * which will use the admin credential to perform the
 * operation.
 */

static int
send_to_cachemgr(
	const char *dn,
	ns_ldap_attr_t **attr,
	ns_ldap_error_t **errorp)
{
	union {
		ldap_data_t	s_d;
		char		s_b[DOORBUFFERSIZE];
	} space;

	ldap_data_t		*sptr;
	int			ndata;
	int			adata;
	int			len;
	int			rc;
	char			errstr[MAXERROR];
	ldap_admin_mod_result_t	*admin_result;

	*errorp = NULL;
	(void) memset(space.s_b, 0, DOORBUFFERSIZE);
	len = attr2list(dn, attr, (char *)&space.s_d.ldap_call.ldap_u.strlist,
	    sizeof (space) - offsetof(ldap_return_t, ldap_u));
	if (len <= 0)
		return (NS_LDAP_INVALID_PARAM);

	adata = sizeof (ldap_call_t) + len;
	ndata = sizeof (space);
	space.s_d.ldap_call.ldap_callnumber = ADMINMODIFY;
	sptr = &space.s_d;

	switch (__ns_ldap_trydoorcall(&sptr, &ndata, &adata)) {
	case NS_CACHE_SUCCESS:
		break;
	case NS_CACHE_NOTFOUND:
		(void) snprintf(errstr, sizeof (errstr),
		    gettext("Door call ADMINMODIFY to "
		    "ldap_cachemgr failed - error: %d"),
		    space.s_d.ldap_ret.ldap_errno);
		MKERROR(LOG_WARNING, *errorp, NS_CONFIG_CACHEMGR,
		    strdup(errstr), NULL);
		return (NS_LDAP_OP_FAILED);
	default:
		return (NS_LDAP_OP_FAILED);
	}

	admin_result = &sptr->ldap_ret.ldap_u.admin_result;
	if (admin_result->ns_err == NS_LDAP_SUCCESS)
		rc = NS_LDAP_SUCCESS;
	else {
		rc = admin_result->ns_err;
		if (admin_result->msg_size == 0)
			*errorp = __s_api_make_error(admin_result->status,
			    NULL);
		else
			*errorp = __s_api_make_error(admin_result->status,
			    admin_result->msg);
	}

	/* clean up the door call */
	if (sptr != &space.s_d) {
		(void) munmap((char *)sptr, ndata);
	}

	return (rc);
}
