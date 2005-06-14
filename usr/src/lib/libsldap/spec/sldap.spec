#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libsldap/spec/sldap.spec

function	__getldapaliasbyname
include		"../../common/ns_sldap.h"
declaration	int __getldapaliasbyname( \
			char *alias, \
			char *answer, \
			size_t ans_len)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_list
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_list( \
			const char *service, \
			const char *filter, \
			int (*init_filter_cb)(const ns_ldap_search_desc_t \
			      *desc, char **realfilter, \
			      const void *userdata), \
			const char * const *attribute, \
			const ns_cred_t *cred, \
			const int flags, \
			ns_ldap_result_t ** result, \
			ns_ldap_error_t ** errorp, \
			int (*callback)(const ns_ldap_entry_t *entry, \
				const void *userdata), \
			const void *userdata)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_addAttr
include		"../../common/ns_sldap.h"
declaration	int  __ns_ldap_addAttr( \
			const char *service, \
			const char *dn, \
			const ns_ldap_attr_t * const *attr, \
			const ns_cred_t *cred, \
			const int flags, \
			ns_ldap_error_t **errorp)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_delAttr
include		"../../common/ns_sldap.h"
declaration	int  __ns_ldap_delAttr( \
			const char *service, \
			const char *dn, \
			const ns_ldap_attr_t * const *attr, \
			const ns_cred_t *cred, \
			const int flags, \
			ns_ldap_error_t **errorp)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_repAttr
include		"../../common/ns_sldap.h"
declaration	int  __ns_ldap_repAttr( \
			const char *service, \
			const char *dn, \
			const ns_ldap_attr_t * const *attr, \
			const ns_cred_t *cred, \
			const int flags, \
			ns_ldap_error_t **errorp)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_addEntry
include		"../../common/ns_sldap.h"
declaration	int  __ns_ldap_addEntry( \
			const char *service, \
			const char *dn, \
			const ns_ldap_entry_t *entry, \
			const ns_cred_t *cred, \
			const int flags, \
			ns_ldap_error_t **errorp)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_addTypedEntry
include		"../../common/ns_sldap.h"
declaration	int  __ns_ldap_addTypedEntry( \
			const char *servicetype, \
			const char *basedn, \
			const void *data, \
			const int  create, \
			const ns_cred_t *cred, \
			const int flags, \
			ns_ldap_error_t **errorp)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_delEntry
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_delEntry( \
			const char *service, \
			const char *dn, \
			const ns_cred_t *cred, \
			const int flags, \
			ns_ldap_error_t **errorp)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_firstEntry
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_firstEntry( \
			const char *service, \
			const char *filter, \
			int (*init_filter_cb)(const ns_ldap_search_desc_t \
			      *desc, char **realfilter, \
			      const void *userdata), \
			const char * const *attribute, \
			const ns_cred_t *cred, \
			const int flags, \
			void **cookie, \
			ns_ldap_result_t ** result, \
			ns_ldap_error_t **errorp, \
			const void *userdata)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_nextEntry
include		"../../common/ns_sldap.h"
declaration	int  __ns_ldap_nextEntry( \
			void *cookie, \
			ns_ldap_result_t ** result, \
			ns_ldap_error_t **errorp)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_endEntry
include		"../../common/ns_sldap.h"
declaration	int  __ns_ldap_endEntry( \
			void **cookie, \
			ns_ldap_error_t **errorp)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_freeResult
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_freeResult( \
			ns_ldap_result_t **result)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_freeError
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_freeError( \
			ns_ldap_error_t **errorp)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_freeCred
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_freeCred( \
			ns_cred_t **credp)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_uid2dn
include		"../../common/ns_sldap.h"
declaration	int  __ns_ldap_uid2dn( \
			const char *uid, \
			char **userDN, \
			const ns_cred_t *cred, \
			ns_ldap_error_t ** errorp)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_host2dn
include		"../../common/ns_sldap.h"
declaration	int  __ns_ldap_host2dn( \
			const char *host, \
			const char *domain, \
			char **hostDN, \
			const ns_cred_t *cred, \
			ns_ldap_error_t ** errorp)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_dn2domain
include		"../../common/ns_sldap.h"
declaration	int  __ns_ldap_dn2domain( \
			const char *dn, \
			char **domain, \
			const ns_cred_t *cred, \
			ns_ldap_error_t ** errorp)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_auth
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_auth( \
			const ns_cred_t *cred, \
			const int flag, \
			ns_ldap_error_t **errorp, \
			LDAPControl **serverctrls, \
			LDAPControl **clientctrls)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_err2str
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_err2str( \
			int err, \
			char **strmsg)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_getParam
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_getParam( \
			const ParamIndexType type, \
			void ***data, \
			ns_ldap_error_t **errorp)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_setParam
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_setParam( \
			const ParamIndexType type, \
			const void *data, \
			ns_ldap_error_t **errorp)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_freeParam
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_freeParam(void ***data)
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_getAttr
include		"../../common/ns_sldap.h"
declaration	char **__ns_ldap_getAttr( \
			const ns_ldap_entry_t *entry, \
			const char *attrname); 
version		SUNWprivate_1.0
exception	$return == NULL
end

function	__ns_ldap_setServer
include		"../../common/ns_sldap.h"
declaration	void __ns_ldap_setServer( \
			int set); 
version		SUNWprivate_1.0
end

function	__ns_ldap_LoadConfiguration
include		"../../common/ns_sldap.h"
declaration	ns_ldap_error_t *__ns_ldap_LoadConfiguration(); 
version		SUNWprivate_1.0
exception	$return == NULL
end

function	__ns_ldap_LoadDoorInfo
include		"../../common/ns_sldap.h"
declaration	ns_ldap_error_t *__ns_ldap_LoadDoorInfo( \
			LineBuf *configinfo, \
			char *domainname);
version		SUNWprivate_1.0
exception	$return == NULL
end

function	__ns_ldap_DumpConfiguration
include		"../../common/ns_sldap.h"
declaration	ns_ldap_error_t *__ns_ldap_DumpConfiguration( \
			char *filename);
version		SUNWprivate_1.0
exception	$return == NULL
end

function	__ns_ldap_DumpLdif
include		"../../common/ns_sldap.h"
declaration	ns_ldap_error_t *__ns_ldap_DumpLdif( \
			char *filename);
version		SUNWprivate_1.0
exception	$return == NULL
end

function	__ns_ldap_download
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_download( \
			const char *profilename, \
			char *serveraddr, \
			char *basedn, \
			ns_ldap_error_t **errorp);
version		SUNWprivate_1.0
exception	$return == 1
end

function	__ns_ldap_trydoorcall
include		"../../common/ns_cache_door.h"
declaration	int __ns_ldap_trydoorcall( \
			ldap_data_t **dptr, \
			int *ndata, \
			int *adata);
version		SUNWprivate_1.0
exception	$return == NULL
end

function	__ns_ldap_print_config
include		"../../common/ns_sldap.h"
declaration	ns_ldap_error_t *__ns_ldap_print_config(int verbose);
version		SUNWprivate_1.0
exception	$return == NULL
end

function	__ns_ldap_default_config
include		"../../common/ns_sldap.h"
declaration	void __ns_ldap_default_config();
version		SUNWprivate_1.0
end

function	__ns_ldap_cache_ping
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_cache_ping();
version		SUNWprivate_1.0
end

function	__ns_ldap_getServiceAuthMethods
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_getServiceAuthMethods( \
			const char *service, \
			ns_auth_t ***auth, \
			ns_ldap_error_t **errorp);
version		SUNWprivate_1.0
end

function	__ns_ldap_getSearchDescriptors
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_getSearchDescriptors( \
			const char *service, \
			ns_ldap_search_desc_t ***desc, \
			ns_ldap_error_t **errorp);
version		SUNWprivate_1.0
end

function	__ns_ldap_freeSearchDescriptors
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_freeSearchDescriptors( \
			ns_ldap_search_desc_t ***desc);
version		SUNWprivate_1.0
end

function	__ns_ldap_getAttributeMaps
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_getAttributeMaps( \
			const char *service, \
			ns_ldap_attribute_map_t ***maps, \
			ns_ldap_error_t **errorp);
version		SUNWprivate_1.0
end

function	__ns_ldap_freeAttributeMaps
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_freeAttributeMaps( \
			ns_ldap_attribute_map_t ***maps);
version		SUNWprivate_1.0
end

function	__ns_ldap_getMappedAttributes
include		"../../common/ns_sldap.h"
declaration	char **__ns_ldap_getMappedAttributes( \
			const char *service, \
			const char *origAttribute);
version		SUNWprivate_1.0
end

function	__ns_ldap_getOrigAttribute
include		"../../common/ns_sldap.h"
declaration	char **__ns_ldap_getOrigAttribute( \
			const char *service, \
			const char *mappedAttribute);
version		SUNWprivate_1.0
end

function	__ns_ldap_getObjectClassMaps
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_getObjectClassMaps( \
			const char *service, \
			ns_ldap_objectclass_map_t ***maps, \
			ns_ldap_error_t **errorp);
version		SUNWprivate_1.0
end

function	__ns_ldap_freeObjectClassMaps
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_freeObjectClassMaps( \
			ns_ldap_objectclass_map_t ***maps);
version		SUNWprivate_1.0
end

function	__ns_ldap_getMappedObjectClass
include		"../../common/ns_sldap.h"
declaration	char **__ns_ldap_getMappedObjectClass( \
			const char *service, \
			const char *origObjectClass);
version		SUNWprivate_1.0
end

function	__ns_ldap_getOrigObjectClass
include		"../../common/ns_sldap.h"
declaration	char **__ns_ldap_getOrigObjectClass( \
			const char *service, \
			const char *mappedObjectClass);
version		SUNWprivate_1.0
end

function	__ns_ldap_getParamType
include		"../../common/ns_sldap.h"
declaration	int __ns_ldap_getParamType( \
			const char *value, \
			ParamIndexType *type);
version		SUNWprivate_1.0
exception	$return == -1
end

function	__ns_ldap_make_config
include		"../../common/ns_sldap.h"
include		"../../common/ns_internal.h"
declaration	ns_config_t *__ns_ldap_make_config( \
			ns_ldap_result_t *result);
version		SUNWprivate_1.0
exception	$return == NULL
end

function	__s_api_init_config
include		"../../common/ns_sldap.h"
include		"../../common/ns_internal.h"
declaration	void __s_api_init_config( \
			ns_config_t *ptr);
version		SUNWprivate_1.0
end

function	__s_api_getServers
include		"../../common/ns_sldap.h"
include		"../../common/ns_internal.h"
declaration	int __s_api_getServers( \
			char *** servers, \
                	ns_ldap_error_t ** error);
version		SUNWprivate_1.0
exception	$return == -1
end

function	__s_api_destroy_config
include		"../../common/ns_sldap.h"
include		"../../common/ns_internal.h"
declaration	void __s_api_destroy_config( \
			ns_config_t *ptr);
version		SUNWprivate_1.0
end

function	__ns_ldap_setParamValue
include		"../../common/ns_sldap.h"
include		"../../common/ns_internal.h"
declaration	int __ns_ldap_setParamValue( \
			ns_config_t *ptr, \
                        const ParamIndexType type, \
                        const void *data, \
			ns_ldap_error_t **error);
version		SUNWprivate_1.0
exception	$return == -1
end

function	__s_api_prepend_automountmapname_to_dn
include		"../../common/ns_sldap.h"
include		"../../common/ns_internal.h"
declaration	int __s_api_prepend_automountmapname_to_dn( \
			const char *service, \
			char **dn, \
			ns_ldap_error_t **errorp);
version		SUNWprivate_1.0
exception	$return == -1
end

function	__s_api_free2dArray
include		"../../common/ns_sldap.h"
include		"../../common/ns_internal.h"
declaration	void __s_api_free2dArray( \
			char **inarray);
version		SUNWprivate_1.0
end

function	__s_api_crosscheck
include		"../../common/ns_sldap.h"
include		"../../common/ns_internal.h"
declaration	ns_parse_status __s_api_crosscheck( \
			ns_config_t *ptr, \
			char *errstr, \
			int check_dn);
version		SUNWprivate_1.0
exception	$return == -1
end

function	__s_api_get_canonical_name
include		"../../common/ns_sldap.h"
include		"../../common/ns_internal.h"
declaration	char * __s_api_get_canonical_name( \
			ns_ldap_entry_t *entry, \
			ns_ldap_attr_t *attrptr, \
			int case_ignore);
version		SUNWprivate_1.1
exception	$return == NULL
end
