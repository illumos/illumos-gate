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
 */

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <libintl.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <priv.h>

#include "ns_sldap.h"
#include "ns_internal.h"
#include "ns_cache_door.h"
#include "ns_connmgmt.h"

#define	_NIS_FILTER	"nisdomain=*"
#define	_NIS_DOMAIN	"nisdomain"
static const char *nis_domain_attrs[] = {
	_NIS_DOMAIN,
	(char *)NULL
};

static int validate_filter(ns_ldap_cookie_t *cookie);

void
__ns_ldap_freeEntry(ns_ldap_entry_t *ep)
{
	int		j, k = 0;

	if (ep == NULL)
		return;

	if (ep->attr_pair == NULL) {
		free(ep);
		return;
	}
	for (j = 0; j < ep->attr_count; j++) {
		if (ep->attr_pair[j] == NULL)
			continue;
		if (ep->attr_pair[j]->attrname)
			free(ep->attr_pair[j]->attrname);
		if (ep->attr_pair[j]->attrvalue) {
			for (k = 0; (k < ep->attr_pair[j]->value_count) &&
			    (ep->attr_pair[j]->attrvalue[k]); k++) {
				free(ep->attr_pair[j]->attrvalue[k]);
			}
			free(ep->attr_pair[j]->attrvalue);
		}
		free(ep->attr_pair[j]);
	}
	free(ep->attr_pair);
	free(ep);
}

static void
_freeControlList(LDAPControl ***ctrls)
{
	LDAPControl	**ctrl;

	if (ctrls == NULL || *ctrls == NULL)
		return;

	for (ctrl = *ctrls; *ctrl != NULL; ctrl++)
		ldap_control_free(*ctrl);
	free(*ctrls);
	*ctrls = NULL;
}
/*
 * Convert attribute type in a RDN that has an attribute mapping to the
 * original mappped type.
 * e.g.
 * cn<->cn-st and iphostnumber<->iphostnumber-st
 * cn-st=aaa+iphostnumber-st=10.10.01.01
 * is mapped to
 * cn=aaa+iphostnumber=10.10.01.01
 *
 * Input - service: e.g. hosts, passwd etc.
 *         rdn: RDN
 * Return: NULL - No attribute mapping in the RDN
 *         Non-NULL - The attribute type(s) in the RDN are mapped and
 *                    the memory is allocated for the new rdn.
 *
 */
static char *
_cvtRDN(const char *service, const char *rdn) {
	char	**attrs, **mapped_attrs, **mapp, *type, *value, *attr;
	char	*new_rdn = NULL;
	int	nAttr = 0, i, attr_mapped, len = 0;

	/* Break down "type=value\0" pairs. Assume RDN is normalized */
	if ((attrs = ldap_explode_rdn(rdn, 0)) == NULL)
		return (NULL);

	for (nAttr = 0; attrs[nAttr] != NULL; nAttr++);

	if ((mapped_attrs = (char **)calloc(nAttr, sizeof (char *))) == NULL) {
		ldap_value_free(attrs);
		return (NULL);
	}

	attr_mapped = 0;
	for (i = 0; i < nAttr; i++) {
		/* Parse type=value pair */
		if ((type = strtok_r(attrs[i], "=", &value)) == NULL ||
					value == NULL)
			goto cleanup;
		/* Reverse map: e.g. cn-sm -> cn */
		mapp = __ns_ldap_getOrigAttribute(service, type);
		if (mapp != NULL && mapp[0] != NULL) {
			/* The attribute mapping is found */
			type = mapp[0];
			attr_mapped = 1;

			/* "type=value\0" */
			len = strlen(type) + strlen(value) + 2;

			/* Reconstruct type=value pair. A string is allocated */
			if ((attr = (char *)calloc(1, len)) == NULL) {
				__s_api_free2dArray(mapp);
				goto cleanup;
			}
			(void) snprintf(attr, len, "%s=%s",
						type, value);
			mapped_attrs[i] = attr;
		} else {
			/*
			 * No attribute mapping. attrs[i] is going to be copied
			 * later. Restore "type\0value\0" back to
			 * "type=value\0".
			 */
			type[strlen(type)] = '=';
		}
		__s_api_free2dArray(mapp);
	}
	if (attr_mapped == 0)
		/* No attribute mapping. Don't bother to reconstruct RDN */
		goto cleanup;

	len = 0;
	/* Reconstruct RDN from type=value pairs */
	for (i = 0; i < nAttr; i++) {
		if (mapped_attrs[i])
			len += strlen(mapped_attrs[i]);
		else
			len += strlen(attrs[i]);
		/* Add 1 for "+" */
		len++;
	}
	if ((new_rdn = (char *)calloc(1, ++len)) == NULL)
		goto cleanup;
	for (i = 0; i < nAttr; i++) {
		if (i > 0)
			/* Add seperator */
			(void) strlcat(new_rdn, "+", len);

		if (mapped_attrs[i])
			(void) strlcat(new_rdn, mapped_attrs[i], len);
		else
			(void) strlcat(new_rdn, attrs[i], len);

	}
cleanup:
	ldap_value_free(attrs);
	if (mapped_attrs) {
		if (attr_mapped) {
			for (i = 0; i < nAttr; i++) {
				if (mapped_attrs[i])
					free(mapped_attrs[i]);
			}
		}
		free(mapped_attrs);
	}

	return (new_rdn);
}
/*
 * Convert attribute type in a DN that has an attribute mapping to the
 * original mappped type.
 * e.g
 * The mappings are cn<->cn-sm, iphostnumber<->iphostnumber-sm
 *
 * dn: cn-sm=aaa+iphostnumber-sm=9.9.9.9,dc=central,dc=sun,dc=com
 * is converted to
 * dn: cn=aaa+iphostnumber=9.9.9.9,dc=central,dc=sun,dc=com
 *
 * Input - service: e.g. hosts, passwd etc.
 *         dn: the value of a distinguished name
 * Return - NULL: error
 *          non-NULL: A converted DN and the memory is allocated
 */
static char *
_cvtDN(const char *service, const char *dn) {
	char	**mapped_rdns;
	char	**rdns, *new_rdn, *new_dn = NULL;
	int	nRdn = 0, i, len = 0, rdn_mapped;

	if (service == NULL || dn == NULL)
		return (NULL);

	if ((rdns = ldap_explode_dn(dn, 0)) == NULL)
		return (NULL);

	for (nRdn = 0; rdns[nRdn] != NULL; nRdn++);

	if ((mapped_rdns = (char **)calloc(nRdn, sizeof (char *))) == NULL) {
		ldap_value_free(rdns);
		return (NULL);
	}

	rdn_mapped = 0;
	/* Break down RDNs in a DN */
	for (i = 0; i < nRdn; i++) {
		if ((new_rdn = _cvtRDN(service, rdns[i])) != NULL) {
			mapped_rdns[i] = new_rdn;
			rdn_mapped = 1;
		}
	}
	if (rdn_mapped == 0) {
		/*
		 * No RDN contains any attribute mapping.
		 * Don't bother to reconstruct DN from RDN. Copy DN directly.
		 */
		new_dn = strdup(dn);
		goto cleanup;
	}
	/*
	 * Reconstruct dn from RDNs.
	 * Calculate the length first.
	 */
	for (i = 0; i < nRdn; i++) {
		if (mapped_rdns[i])
			len += strlen(mapped_rdns[i]);
		else
			len += strlen(rdns[i]);

		/* add 1 for ',' */
		len ++;
	}
	if ((new_dn = (char *)calloc(1, ++len)) == NULL)
		goto cleanup;
	for (i = 0; i < nRdn; i++) {
		if (i > 0)
			/* Add seperator */
			(void) strlcat(new_dn, ",", len);

		if (mapped_rdns[i])
			(void) strlcat(new_dn, mapped_rdns[i], len);
		else
			(void) strlcat(new_dn, rdns[i], len);

	}

cleanup:
	ldap_value_free(rdns);
	if (mapped_rdns) {
		if (rdn_mapped) {
			for (i = 0; i < nRdn; i++) {
				if (mapped_rdns[i])
					free(mapped_rdns[i]);
			}
		}
		free(mapped_rdns);
	}

	return (new_dn);
}
/*
 * Convert a single ldap entry from a LDAPMessage
 * into an ns_ldap_entry structure.
 * Schema map the entry if specified in flags
 */

static int
__s_api_cvtEntry(LDAP	*ld,
	const char	*service,
	LDAPMessage	*e,
	int		flags,
	ns_ldap_entry_t	**ret,
	ns_ldap_error_t	**error)
{

	ns_ldap_entry_t	*ep = NULL;
	ns_ldap_attr_t	**ap = NULL;
	BerElement	*ber;
	char		*attr = NULL;
	char		**vals = NULL;
	char		**mapping;
	char		*dn;
	int		nAttrs = 0;
	int		i, j, k = 0;
	char		**gecos_mapping = NULL;
	int		gecos_val_index[3] = { -1, -1, -1};
	char		errstr[MAXERROR];
	int		schema_mapping_existed = FALSE;
	int		gecos_mapping_existed = FALSE;
	int		gecos_attr_matched;
	int		auto_service = FALSE;
	int		rc = NS_LDAP_SUCCESS;

	if (e == NULL || ret == NULL || error == NULL)
		return (NS_LDAP_INVALID_PARAM);

	*error = NULL;

	ep = (ns_ldap_entry_t *)calloc(1, sizeof (ns_ldap_entry_t));
	if (ep == NULL)
		return (NS_LDAP_MEMORY);

	if (service != NULL &&
	    (strncasecmp(service, "auto_", 5) == 0 ||
	    strcasecmp(service, "automount") == 0))
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
	} else if (auto_service) {
		/*
		 * If service == auto_* and no
		 * schema mapping found
		 * then try automount
		 * There is certain case that schema mapping exist
		 * but __ns_ldap_getOrigAttribute(service,
		 *	NS_HASH_SCHEMA_MAPPING_EXISTED);
		 * returns NULL.
		 * e.g.
		 * NS_LDAP_ATTRIBUTEMAP = automount:automountMapName=AAA
		 * NS_LDAP_OBJECTCLASSMAP = automount:automountMap=MynisMap
		 * NS_LDAP_OBJECTCLASSMAP = automount:automount=MynisObject
		 *
		 * Make a check for schema_mapping_existed here
		 * so later on __s_api_convert_automountmapname won't be called
		 * unnecessarily. It is also used for attribute mapping
		 * and objectclass mapping.
		 */
		mapping = __ns_ldap_getOrigAttribute("automount",
		    NS_HASH_SCHEMA_MAPPING_EXISTED);
		if (mapping) {
			schema_mapping_existed = TRUE;
			__s_api_free2dArray(mapping);
			mapping = NULL;
		}
	}

	nAttrs = 1;  /* start with 1 for the DN attr */
	for (attr = ldap_first_attribute(ld, e, &ber); attr != NULL;
	    attr = ldap_next_attribute(ld, e, ber)) {
		nAttrs++;
		ldap_memfree(attr);
		attr = NULL;
	}
	ber_free(ber, 0);
	ber = NULL;

	ep->attr_count = nAttrs;

	/*
	 * add 1 for "gecos" 1 to N attribute mapping,
	 * just in case it is needed.
	 * ep->attr_count will be updated later if that is true.
	 */
	ap = (ns_ldap_attr_t **)calloc(ep->attr_count + 1,
	    sizeof (ns_ldap_attr_t *));
	if (ap == NULL) {
		__ns_ldap_freeEntry(ep);
		ep = NULL;
		return (NS_LDAP_MEMORY);
	}
	ep->attr_pair = ap;

	/* DN attribute */
	dn = ldap_get_dn(ld, e);
	ap[0] = (ns_ldap_attr_t *)calloc(1, sizeof (ns_ldap_attr_t));
	if (ap[0] == NULL) {
		ldap_memfree(dn);
		dn = NULL;
		__ns_ldap_freeEntry(ep);
		ep = NULL;
		return (NS_LDAP_MEMORY);
	}

	if ((ap[0]->attrname = strdup("dn")) == NULL) {
		ldap_memfree(dn);
		dn = NULL;
		__ns_ldap_freeEntry(ep);
		ep = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}
	ap[0]->value_count = 1;
	if ((ap[0]->attrvalue = (char **)
	    calloc(2, sizeof (char *))) == NULL) {
		ldap_memfree(dn);
		dn = NULL;
		__ns_ldap_freeEntry(ep);
		ep = NULL;
		return (NS_LDAP_MEMORY);
	}

	if (schema_mapping_existed && ((flags & NS_LDAP_NOT_CVT_DN) == 0))
		ap[0]->attrvalue[0] = _cvtDN(service, dn);
	else
		ap[0]->attrvalue[0] = strdup(dn);

	if (ap[0]->attrvalue[0] == NULL) {
		ldap_memfree(dn);
		dn = NULL;
		__ns_ldap_freeEntry(ep);
		ep = NULL;
		return (NS_LDAP_MEMORY);
	}
	ldap_memfree(dn);
	dn = NULL;

	if ((flags & NS_LDAP_NOMAP) == 0 && auto_service &&
	    schema_mapping_existed) {
		rc = __s_api_convert_automountmapname(service,
		    &ap[0]->attrvalue[0],
		    error);
		if (rc != NS_LDAP_SUCCESS) {
			__ns_ldap_freeEntry(ep);
			ep = NULL;
			return (rc);
		}
	}

	/* other attributes */
	for (attr = ldap_first_attribute(ld, e, &ber), j = 1;
	    attr != NULL && j != nAttrs;
	    attr = ldap_next_attribute(ld, e, ber), j++) {
		/* allocate new attr name */

		if ((ap[j] = (ns_ldap_attr_t *)
		    calloc(1, sizeof (ns_ldap_attr_t))) == NULL) {
			ber_free(ber, 0);
			ber = NULL;
			__ns_ldap_freeEntry(ep);
			ep = NULL;
			if (gecos_mapping)
				__s_api_free2dArray(gecos_mapping);
			gecos_mapping = NULL;
			return (NS_LDAP_MEMORY);
		}

		if ((flags & NS_LDAP_NOMAP) || schema_mapping_existed == FALSE)
			mapping = NULL;
		else
			mapping = __ns_ldap_getOrigAttribute(service, attr);

		if (mapping == NULL && auto_service &&
		    schema_mapping_existed && (flags & NS_LDAP_NOMAP) == 0)
			/*
			 * if service == auto_* and no schema mapping found
			 * and schema_mapping_existed is TRUE and NS_LDAP_NOMAP
			 * is not set then try automount e.g.
			 * NS_LDAP_ATTRIBUTEMAP = automount:automountMapName=AAA
			 */
			mapping = __ns_ldap_getOrigAttribute("automount",
			    attr);

		if (mapping == NULL) {
			if ((ap[j]->attrname = strdup(attr)) == NULL) {
				ber_free(ber, 0);
				ber = NULL;
				__ns_ldap_freeEntry(ep);
				ep = NULL;
				if (gecos_mapping)
					__s_api_free2dArray(gecos_mapping);
				gecos_mapping = NULL;
				return (NS_LDAP_MEMORY);
			}
		} else {
			/*
			 * for "gecos" 1 to N mapping,
			 * do not remove the mapped attribute,
			 * just create a new gecos attribute
			 * and append it to the end of the attribute list
			 */
			if (strcasecmp(mapping[0], "gecos") == 0) {
				ap[j]->attrname = strdup(attr);
				gecos_mapping_existed = TRUE;
			} else
				ap[j]->attrname = strdup(mapping[0]);

			if (ap[j]->attrname == NULL) {
				ber_free(ber, 0);
				ber = NULL;
				__ns_ldap_freeEntry(ep);
				ep = NULL;
				if (gecos_mapping)
					__s_api_free2dArray(gecos_mapping);
				gecos_mapping = NULL;
				return (NS_LDAP_MEMORY);
			}
			/*
			 * 1 to N attribute mapping processing
			 * is only done for "gecos"
			 */

			if (strcasecmp(mapping[0], "gecos") == 0) {
				/*
				 * get attribute mapping for "gecos",
				 * need to know the number and order of the
				 * mapped attributes
				 */
				if (gecos_mapping == NULL) {
					gecos_mapping =
					    __ns_ldap_getMappedAttributes(
					    service, mapping[0]);
					if (gecos_mapping == NULL ||
					    gecos_mapping[0] == NULL) {
						/*
						 * this should never happens,
						 * syslog the error
						 */
						(void) sprintf(errstr,
						    gettext(
						    "Attribute mapping "
						    "inconsistency "
						    "found for attributes "
						    "'%s' and '%s'."),
						    mapping[0], attr);
						syslog(LOG_ERR, "libsldap: %s",
						    errstr);

						ber_free(ber, 0);
						ber = NULL;
						__ns_ldap_freeEntry(ep);
						ep = NULL;
						__s_api_free2dArray(mapping);
						mapping = NULL;
						if (gecos_mapping)
							__s_api_free2dArray(
							    gecos_mapping);
						gecos_mapping = NULL;
						return (NS_LDAP_INTERNAL);
					}
				}

				/*
				 * is this attribute the 1st, 2nd, or
				 * 3rd attr in the mapping list?
				 */
				gecos_attr_matched = FALSE;
				for (i = 0; i < 3 && gecos_mapping[i]; i++) {
					if (gecos_mapping[i] &&
					    strcasecmp(gecos_mapping[i],
					    attr) == 0) {
						gecos_val_index[i] = j;
						gecos_attr_matched = TRUE;
						break;
					}
				}
				if (gecos_attr_matched == FALSE) {
					/*
					 * Not match found.
					 * This should never happens,
					 * syslog the error
					 */
					(void) sprintf(errstr,
					    gettext(
					    "Attribute mapping "
					    "inconsistency "
					    "found for attributes "
					    "'%s' and '%s'."),
					    mapping[0], attr);
					syslog(LOG_ERR, "libsldap: %s", errstr);

					ber_free(ber, 0);
					ber = NULL;
					__ns_ldap_freeEntry(ep);
					ep = NULL;
					__s_api_free2dArray(mapping);
					mapping = NULL;
					__s_api_free2dArray(gecos_mapping);
					gecos_mapping = NULL;
					return (NS_LDAP_INTERNAL);
				}
			}
			__s_api_free2dArray(mapping);
			mapping = NULL;
		}

		if ((vals = ldap_get_values(ld, e, attr)) != NULL) {

			if ((ap[j]->value_count =
			    ldap_count_values(vals)) == 0) {
				ldap_value_free(vals);
				vals = NULL;
				continue;
			} else {
				ap[j]->attrvalue = (char **)
				    calloc(ap[j]->value_count+1,
				    sizeof (char *));
				if (ap[j]->attrvalue == NULL) {
					ber_free(ber, 0);
					ber = NULL;
					__ns_ldap_freeEntry(ep);
					ep = NULL;
					if (gecos_mapping)
						__s_api_free2dArray(
						    gecos_mapping);
					gecos_mapping = NULL;
					return (NS_LDAP_MEMORY);
				}
			}

			/* map object classes if necessary */
			if ((flags & NS_LDAP_NOMAP) == 0 &&
			    schema_mapping_existed && ap[j]->attrname &&
			    strcasecmp(ap[j]->attrname, "objectclass") == 0) {
				for (k = 0; k < ap[j]->value_count; k++) {
					mapping =
					    __ns_ldap_getOrigObjectClass(
					    service, vals[k]);

					if (mapping == NULL && auto_service)
						/*
						 * if service == auto_* and no
						 * schema mapping found
						 * then try automount
						 */
					mapping =
					    __ns_ldap_getOrigObjectClass(
					    "automount", vals[k]);

					if (mapping == NULL) {
						ap[j]->attrvalue[k] =
						    strdup(vals[k]);
					} else {
						ap[j]->attrvalue[k] =
						    strdup(mapping[0]);
						__s_api_free2dArray(mapping);
						mapping = NULL;
					}
					if (ap[j]->attrvalue[k] == NULL) {
						ber_free(ber, 0);
						ber = NULL;
						__ns_ldap_freeEntry(ep);
						ep = NULL;
						if (gecos_mapping)
							__s_api_free2dArray(
							    gecos_mapping);
						gecos_mapping = NULL;
						return (NS_LDAP_MEMORY);
					}
				}
			} else {
				for (k = 0; k < ap[j]->value_count; k++) {
					if ((ap[j]->attrvalue[k] =
					    strdup(vals[k])) == NULL) {
						ber_free(ber, 0);
						ber = NULL;
						__ns_ldap_freeEntry(ep);
						ep = NULL;
						if (gecos_mapping)
							__s_api_free2dArray(
							    gecos_mapping);
						gecos_mapping = NULL;
						return (NS_LDAP_MEMORY);
					}
				}
			}

			ap[j]->attrvalue[k] = NULL;
			ldap_value_free(vals);
			vals = NULL;
		}

		ldap_memfree(attr);
		attr = NULL;
	}

	ber_free(ber, 0);
	ber = NULL;

	if (gecos_mapping) {
		__s_api_free2dArray(gecos_mapping);
		gecos_mapping = NULL;
	}

	/* special processing for gecos 1 to up to 3 attribute mapping */
	if (schema_mapping_existed && gecos_mapping_existed) {

		int	f = -1;

		for (i = 0; i < 3; i++) {
			k = gecos_val_index[i];

			/*
			 * f is the index of the first returned
			 * attribute which "gecos" attribute mapped to
			 */
			if (k != -1 && f == -1)
				f = k;

			if (k != -1 && ap[k]->value_count > 0 &&
			    ap[k]->attrvalue[0] &&
			    strlen(ap[k]->attrvalue[0]) > 0) {

				if (k == f) {
					/*
					 * Create and fill in the last reserved
					 * ap with the data from the "gecos"
					 * mapping attributes
					 */
					ap[nAttrs] = (ns_ldap_attr_t *)
					    calloc(1,
					    sizeof (ns_ldap_attr_t));
					if (ap[nAttrs] == NULL) {
						__ns_ldap_freeEntry(ep);
						ep = NULL;
						return (NS_LDAP_MEMORY);
					}
					ap[nAttrs]->attrvalue = (char **)calloc(
					    2, sizeof (char *));
					if (ap[nAttrs]->attrvalue == NULL) {
						__ns_ldap_freeEntry(ep);
						ep = NULL;
						return (NS_LDAP_MEMORY);
					}
					/* add 1 more for a possible "," */
					ap[nAttrs]->attrvalue[0] =
					    (char *)calloc(
					    strlen(ap[f]->attrvalue[0]) +
					    2, 1);
					if (ap[nAttrs]->attrvalue[0] == NULL) {
						__ns_ldap_freeEntry(ep);
						ep = NULL;
						return (NS_LDAP_MEMORY);
					}
					(void) strcpy(ap[nAttrs]->attrvalue[0],
					    ap[f]->attrvalue[0]);

					ap[nAttrs]->attrname = strdup("gecos");
					if (ap[nAttrs]->attrname == NULL) {
						__ns_ldap_freeEntry(ep);
						ep = NULL;
						return (NS_LDAP_MEMORY);
					}

					ap[nAttrs]->value_count = 1;
					ep->attr_count = nAttrs + 1;

				} else {
					char	*tmp = NULL;

					/*
					 * realloc to add "," and
					 * ap[k]->attrvalue[0]
					 */
					tmp = (char *)realloc(
					    ap[nAttrs]->attrvalue[0],
					    strlen(ap[nAttrs]->
					    attrvalue[0]) +
					    strlen(ap[k]->
					    attrvalue[0]) + 2);
					if (tmp == NULL) {
						__ns_ldap_freeEntry(ep);
						ep = NULL;
						return (NS_LDAP_MEMORY);
					}
					ap[nAttrs]->attrvalue[0] = tmp;
					(void) strcat(ap[nAttrs]->attrvalue[0],
					    ",");
					(void) strcat(ap[nAttrs]->attrvalue[0],
					    ap[k]->attrvalue[0]);
				}
			}
		}
	}

	*ret = ep;
	return (NS_LDAP_SUCCESS);
}

static int
__s_api_getEntry(ns_ldap_cookie_t *cookie)
{
	ns_ldap_entry_t	*curEntry = NULL;
	int		ret;

#ifdef DEBUG
	(void) fprintf(stderr, "__s_api_getEntry START\n");
#endif

	if (cookie->resultMsg == NULL) {
		return (NS_LDAP_INVALID_PARAM);
	}
	ret = __s_api_cvtEntry(cookie->conn->ld, cookie->service,
	    cookie->resultMsg, cookie->i_flags,
	    &curEntry, &cookie->errorp);
	if (ret != NS_LDAP_SUCCESS) {
		return (ret);
	}

	if (cookie->result == NULL) {
		cookie->result = (ns_ldap_result_t *)
		    calloc(1, sizeof (ns_ldap_result_t));
		if (cookie->result == NULL) {
			__ns_ldap_freeEntry(curEntry);
			curEntry = NULL;
			return (NS_LDAP_MEMORY);
		}
		cookie->result->entry = curEntry;
		cookie->nextEntry = curEntry;
	} else {
		cookie->nextEntry->next = curEntry;
		cookie->nextEntry = curEntry;
	}
	cookie->result->entries_count++;

	return (NS_LDAP_SUCCESS);
}

static int
__s_api_get_cachemgr_data(const char *type,
		const char *from, char **to)
{
	union {
		ldap_data_t	s_d;
		char		s_b[DOORBUFFERSIZE];
	} space;
	ldap_data_t	*sptr;
	int		ndata;
	int		adata;
	int		rc;

#ifdef DEBUG
	(void) fprintf(stderr, "__s_api_get_cachemgr_data START\n");
#endif
	/*
	 * We are not going to perform DN to domain mapping
	 * in the Standalone mode
	 */
	if (__s_api_isStandalone()) {
		return (-1);
	}

	if (from == NULL || from[0] == '\0' || to == NULL)
		return (-1);

	*to = NULL;
	(void) memset(space.s_b, 0, DOORBUFFERSIZE);

	space.s_d.ldap_call.ldap_callnumber = GETCACHE;
	(void) snprintf(space.s_d.ldap_call.ldap_u.domainname,
	    DOORBUFFERSIZE - sizeof (space.s_d.ldap_call.ldap_callnumber),
	    "%s%s%s",
	    type,
	    DOORLINESEP,
	    from);
	ndata = sizeof (space);
	adata = sizeof (ldap_call_t) +
	    strlen(space.s_d.ldap_call.ldap_u.domainname) + 1;
	sptr = &space.s_d;

	rc = __ns_ldap_trydoorcall(&sptr, &ndata, &adata);
	if (rc != NS_CACHE_SUCCESS)
		return (-1);
	else
		*to = strdup(sptr->ldap_ret.ldap_u.buff);
	return (NS_LDAP_SUCCESS);
}

static int
__s_api_set_cachemgr_data(const char *type,
		const char *from, const char *to)
{
	union {
		ldap_data_t	s_d;
		char		s_b[DOORBUFFERSIZE];
	} space;
	ldap_data_t	*sptr;
	int		ndata;
	int		adata;
	int		rc;

#ifdef DEBUG
	(void) fprintf(stderr, "__s_api_set_cachemgr_data START\n");
#endif
	/*
	 * We are not going to perform DN to domain mapping
	 * in the Standalone mode
	 */
	if (__s_api_isStandalone()) {
		return (-1);
	}

	if ((from == NULL) || (from[0] == '\0') ||
	    (to == NULL) || (to[0] == '\0'))
		return (-1);

	(void) memset(space.s_b, 0, DOORBUFFERSIZE);

	space.s_d.ldap_call.ldap_callnumber = SETCACHE;
	(void) snprintf(space.s_d.ldap_call.ldap_u.domainname,
	    DOORBUFFERSIZE - sizeof (space.s_d.ldap_call.ldap_callnumber),
	    "%s%s%s%s%s",
	    type,
	    DOORLINESEP,
	    from,
	    DOORLINESEP,
	    to);

	ndata = sizeof (space);
	adata = sizeof (ldap_call_t) +
	    strlen(space.s_d.ldap_call.ldap_u.domainname) + 1;
	sptr = &space.s_d;

	rc = __ns_ldap_trydoorcall(&sptr, &ndata, &adata);
	if (rc != NS_CACHE_SUCCESS)
		return (-1);

	return (NS_LDAP_SUCCESS);
}


static char *
__s_api_remove_rdn_space(char *rdn)
{
	char	*tf, *tl, *vf, *vl, *eqsign;

	/* if no space(s) to remove, return */
	if (strchr(rdn, SPACETOK) == NULL)
		return (rdn);

	/* if no '=' separator, return */
	eqsign = strchr(rdn, '=');
	if (eqsign == NULL)
		return (rdn);

	tf = rdn;
	tl = eqsign - 1;
	vf = eqsign + 1;
	vl = rdn + strlen(rdn) - 1;

	/* now two strings, type and value */
	*eqsign = '\0';

	/* remove type's leading spaces */
	while (tf < tl && *tf == SPACETOK)
		tf++;
	/* remove type's trailing spaces */
	while (tf < tl && *tl == SPACETOK)
		tl--;
	/* add '=' separator back */
	*(++tl) = '=';
	/* remove value's leading spaces */
	while (vf < vl && *vf == SPACETOK)
		vf++;
	/* remove value's trailing spaces */
	while (vf < vl && *vl == SPACETOK)
		*vl-- = '\0';

	/* move value up if necessary */
	if (vf != tl + 1)
		(void) strcpy(tl + 1, vf);

	return (tf);
}

static
ns_ldap_cookie_t *
init_search_state_machine()
{
	ns_ldap_cookie_t	*cookie;
	ns_config_t		*cfg;

	cookie = (ns_ldap_cookie_t *)calloc(1, sizeof (ns_ldap_cookie_t));
	if (cookie == NULL)
		return (NULL);
	cookie->state = INIT;
	/* assign other state variables */
	cfg = __s_api_loadrefresh_config();
	cookie->connectionId = -1;
	if (cfg == NULL ||
	    cfg->paramList[NS_LDAP_SEARCH_TIME_P].ns_ptype == NS_UNKNOWN) {
		cookie->search_timeout.tv_sec = NS_DEFAULT_SEARCH_TIMEOUT;
	} else {
		cookie->search_timeout.tv_sec =
		    cfg->paramList[NS_LDAP_SEARCH_TIME_P].ns_i;
	}
	if (cfg != NULL)
		__s_api_release_config(cfg);
	cookie->search_timeout.tv_usec = 0;

	return (cookie);
}

static void
delete_search_cookie(ns_ldap_cookie_t *cookie)
{
	if (cookie == NULL)
		return;
	if (cookie->connectionId > -1)
		DropConnection(cookie->connectionId, cookie->i_flags);
	if (cookie->filter)
		free(cookie->filter);
	if (cookie->i_filter)
		free(cookie->i_filter);
	if (cookie->service)
		free(cookie->service);
	if (cookie->sdlist)
		(void) __ns_ldap_freeSearchDescriptors(&(cookie->sdlist));
	if (cookie->result)
		(void) __ns_ldap_freeResult(&cookie->result);
	if (cookie->attribute)
		__s_api_free2dArray(cookie->attribute);
	if (cookie->errorp)
		(void) __ns_ldap_freeError(&cookie->errorp);
	if (cookie->reflist)
		__s_api_deleteRefInfo(cookie->reflist);
	if (cookie->basedn)
		free(cookie->basedn);
	if (cookie->ctrlCookie)
		ber_bvfree(cookie->ctrlCookie);
	_freeControlList(&cookie->p_serverctrls);
	if (cookie->resultctrl)
		ldap_controls_free(cookie->resultctrl);
	free(cookie);
}

static int
get_mapped_filter(ns_ldap_cookie_t *cookie, char **new_filter)
{

	typedef	struct	filter_mapping_info {
		char	oc_or_attr;
		char	*name_start;
		char	*name_end;
		char	*veq_pos;
		char	*from_name;
		char	*to_name;
		char	**mapping;
	} filter_mapping_info_t;

	char			*c, *last_copied;
	char			*filter_c, *filter_c_next;
	char			*key, *tail, *head;
	char			errstr[MAXERROR];
	int			num_eq = 0, num_veq = 0;
	int			in_quote = FALSE;
	int			is_value = FALSE;
	int			i, j, oc_len, len;
	int			at_least_one = FALSE;
	filter_mapping_info_t	**info, *info1;
	char			**mapping;
	char			*service, *filter, *err;
	int			auto_service = FALSE;

	if (cookie == NULL || new_filter == NULL)
		return (NS_LDAP_INVALID_PARAM);

	*new_filter = NULL;
	service = cookie->service;
	filter = cookie->filter;

	/*
	 * count the number of '=' char
	 */
	for (c = filter; *c; c++) {
		if (*c == TOKENSEPARATOR)
			num_eq++;
	}

	if (service != NULL && strncasecmp(service, "auto_", 5) == 0)
		auto_service = TRUE;

	/*
	 * See if schema mapping existed for the given service.
	 * If not, just return success.
	 */
	mapping = __ns_ldap_getOrigAttribute(service,
	    NS_HASH_SCHEMA_MAPPING_EXISTED);

	if (mapping == NULL && auto_service)
		/*
		 * if service == auto_* and no
		 * schema mapping found
		 * then try automount
		 */
		mapping = __ns_ldap_getOrigAttribute(
		    "automount", NS_HASH_SCHEMA_MAPPING_EXISTED);

	if (mapping)
		__s_api_free2dArray(mapping);
	else
		return (NS_LDAP_SUCCESS);

	/*
	 * no '=' sign, just say OK and return nothing
	 */
	if (num_eq == 0)
		return (NS_LDAP_SUCCESS);

	/*
	 * Make a copy of the filter string
	 * for saving the name of the objectclasses or
	 * attributes that need to be passed to the
	 * objectclass or attribute mapping functions.
	 * pointer "info->from_name" points to the locations
	 * within this string.
	 *
	 * The input filter string, filter, will be used
	 * to indicate where these names start and end.
	 * pointers "info->name_start" and "info->name_end"
	 * point to locations within the input filter string,
	 * and are used at the end of this function to
	 * merge the original filter data with the
	 * mapped objectclass or attribute names.
	 */
	filter_c = strdup(filter);
	if (filter_c == NULL)
		return (NS_LDAP_MEMORY);
	filter_c_next = filter_c;

	/*
	 * get memory for info arrays
	 */
	info = (filter_mapping_info_t **)calloc(num_eq + 1,
	    sizeof (filter_mapping_info_t *));

	if (info == NULL) {
		free(filter_c);
		return (NS_LDAP_MEMORY);
	}

	/*
	 * find valid '=' for further processing,
	 * ignore the "escaped =" (.i.e. "\="), or
	 * "=" in quoted string
	 */
	for (c = filter_c; *c; c++) {

		switch (*c) {
		case TOKENSEPARATOR:
			if (!in_quote && !is_value) {
				info1 = (filter_mapping_info_t *)calloc(1,
				    sizeof (filter_mapping_info_t));
				if (!info1) {
					free(filter_c);
					for (i = 0; i < num_veq; i++)
						free(info[i]);
					free(info);
					return (NS_LDAP_MEMORY);
				}
				info[num_veq] = info1;

				/*
				 * remember the location of this "="
				 */
				info[num_veq++]->veq_pos = c;

				/*
				 * skip until the end of the attribute value
				 */
				is_value = TRUE;
			}
			break;
		case CPARATOK:
			/*
			 * mark the end of the attribute value
			 */
			if (!in_quote)
				is_value = FALSE;
			break;
		case QUOTETOK:
			/*
			 * switch on/off the in_quote mode
			 */
			in_quote = (in_quote == FALSE);
			break;
		case '\\':
			/*
			 * ignore escape characters
			 * don't skip if next char is '\0'
			 */
			if (!in_quote)
				if (*(++c) == '\0')
					c--;
			break;
		}

	}

	/*
	 * for each valid "=" found, get the name to
	 * be mapped
	 */
	oc_len = strlen("objectclass");
	for (i = 0; i < num_veq; i++) {

		/*
		 * look at the left side of "=" to see
		 * if assertion is "objectclass=<ocname>"
		 * or "<attribute name>=<attribute value>"
		 *
		 * first skip spaces before "=".
		 * Note that filter_c_next may not point to the
		 * start of the filter string. For i > 0,
		 * it points to the end of the last name processed + 2
		 */
		for (tail = info[i]->veq_pos; (tail > filter_c_next) &&
		    (*(tail - 1) == SPACETOK); tail--)
			;

		/*
		 * mark the end of the left side string (the key)
		 */
		*tail = '\0';
		info[i]->name_end = tail - filter_c - 1 + filter;

		/*
		 * find the start of the key
		 */
		key = filter_c_next;
		for (c = tail; filter_c_next <= c; c--) {
			/* OPARATOK is '(' */
			if (*c == OPARATOK ||
			    *c == SPACETOK) {
				key = c + 1;
				break;
			}
		}
		info[i]->name_start = key - filter_c + filter;

		if ((key + oc_len) <= tail) {
			if (strncasecmp(key, "objectclass",
			    oc_len) == 0) {
				/*
				 * assertion is "objectclass=ocname",
				 * ocname is the one needs to be mapped
				 *
				 * skip spaces after "=" to find start
				 * of the ocname
				 */
				head = info[i]->veq_pos;
				for (head = info[i]->veq_pos + 1;
				    *head && *head == SPACETOK; head++)
					;

				/* ignore empty ocname */
				if (!(*head))
					continue;

				info[i]->name_start = head - filter_c +
				    filter;

				/*
				 * now find the end of the ocname
				 */
				for (c = head; ; c++) {
					/* CPARATOK is ')' */
					if (*c == CPARATOK ||
					    *c == '\0' ||
					    *c == SPACETOK) {
						*c = '\0';
						info[i]->name_end =
						    c - filter_c - 1 +
						    filter;
						filter_c_next = c + 1;
						info[i]->oc_or_attr = 'o';
						info[i]->from_name = head;
						break;
					}
				}
			}
		}

		/*
		 * assertion is not "objectclass=ocname",
		 * assume assertion is "<key> = <value>",
		 * <key> is the one needs to be mapped
		 */
		if (info[i]->from_name == NULL && strlen(key) > 0) {
			info[i]->oc_or_attr = 'a';
			info[i]->from_name = key;
		}
	}

	/* perform schema mapping */
	for (i = 0; i < num_veq; i++) {
		if (info[i]->from_name == NULL)
			continue;

		if (info[i]->oc_or_attr == 'a')
			info[i]->mapping =
			    __ns_ldap_getMappedAttributes(service,
			    info[i]->from_name);
		else
			info[i]->mapping =
			    __ns_ldap_getMappedObjectClass(service,
			    info[i]->from_name);

		if (info[i]->mapping == NULL && auto_service)  {
			/*
			 * If no mapped attribute/objectclass is found
			 * and service == auto*
			 * try to find automount's
			 * mapped attribute/objectclass
			 */
			if (info[i]->oc_or_attr == 'a')
				info[i]->mapping =
				    __ns_ldap_getMappedAttributes("automount",
				    info[i]->from_name);
			else
				info[i]->mapping =
				    __ns_ldap_getMappedObjectClass("automount",
				    info[i]->from_name);
		}

		if (info[i]->mapping == NULL ||
		    info[i]->mapping[0] == NULL) {
			info[i]->to_name = NULL;
		} else if (info[i]->mapping[1] == NULL) {
			info[i]->to_name = info[i]->mapping[0];
			at_least_one = TRUE;
		} else {
			__s_api_free2dArray(info[i]->mapping);
			/*
			 * multiple mapping
			 * not allowed
			 */
			(void) sprintf(errstr,
			    gettext(
			    "Multiple attribute or objectclass "
			    "mapping for '%s' in filter "
			    "'%s' not allowed."),
			    info[i]->from_name, filter);
			err = strdup(errstr);
			if (err) {
				MKERROR(LOG_WARNING, cookie->errorp,
				    NS_CONFIG_SYNTAX,
				    err, NULL);
			}

			free(filter_c);
			for (j = 0; j < num_veq; j++) {
				if (info[j]->mapping)
					__s_api_free2dArray(
					    info[j]->mapping);
				free(info[j]);
			}
			free(info);
			return (NS_LDAP_CONFIG);
		}
	}


	if (at_least_one) {

		len = strlen(filter);
		last_copied = filter - 1;

		for (i = 0; i < num_veq; i++) {
			if (info[i]->to_name)
				len += strlen(info[i]->to_name);
		}

		*new_filter = (char *)calloc(1, len);
		if (*new_filter == NULL) {
			free(filter_c);
			for (j = 0; j < num_veq; j++) {
				if (info[j]->mapping)
					__s_api_free2dArray(
					    info[j]->mapping);
				free(info[j]);
			}
			free(info);
			return (NS_LDAP_MEMORY);
		}

		for (i = 0; i < num_veq; i++) {
			if (info[i]->to_name != NULL &&
			    info[i]->to_name != NULL) {

				/*
				 * copy the original filter data
				 * between the last name and current
				 * name
				 */
				if ((last_copied + 1) != info[i]->name_start)
					(void) strncat(*new_filter,
					    last_copied + 1,
					    info[i]->name_start -
					    last_copied - 1);

				/* the data is copied */
				last_copied = info[i]->name_end;

				/*
				 * replace the name with
				 * the mapped name
				 */
				(void) strcat(*new_filter, info[i]->to_name);
			}

			/* copy the filter data after the last name */
			if (i == (num_veq -1) &&
			    info[i]->name_end <
			    (filter + strlen(filter)))
				(void) strncat(*new_filter, last_copied + 1,
				    filter + strlen(filter) -
				    last_copied - 1);
		}

	}

	/* free memory */
	free(filter_c);
	for (j = 0; j < num_veq; j++) {
		if (info[j]->mapping)
			__s_api_free2dArray(info[j]->mapping);
		free(info[j]);
	}
	free(info);

	return (NS_LDAP_SUCCESS);
}

static int
setup_next_search(ns_ldap_cookie_t *cookie)
{
	ns_ldap_search_desc_t	*dptr;
	int			scope;
	char			*filter, *str;
	int			baselen;
	int			rc;
	void			**param;

	dptr = *cookie->sdpos;
	scope = cookie->i_flags & (NS_LDAP_SCOPE_BASE |
	    NS_LDAP_SCOPE_ONELEVEL |
	    NS_LDAP_SCOPE_SUBTREE);
	if (scope)
		cookie->scope = scope;
	else
		cookie->scope = dptr->scope;
	switch (cookie->scope) {
	case NS_LDAP_SCOPE_BASE:
		cookie->scope = LDAP_SCOPE_BASE;
		break;
	case NS_LDAP_SCOPE_ONELEVEL:
		cookie->scope = LDAP_SCOPE_ONELEVEL;
		break;
	case NS_LDAP_SCOPE_SUBTREE:
		cookie->scope = LDAP_SCOPE_SUBTREE;
		break;
	}

	filter = NULL;
	if (cookie->use_filtercb && cookie->init_filter_cb &&
	    dptr->filter && strlen(dptr->filter) > 0) {
		(*cookie->init_filter_cb)(dptr, &filter,
		    cookie->userdata);
	}
	if (filter == NULL) {
		if (cookie->i_filter == NULL) {
			cookie->err_rc = NS_LDAP_INVALID_PARAM;
			return (-1);
		} else {
			if (cookie->filter)
				free(cookie->filter);
			cookie->filter = strdup(cookie->i_filter);
			if (cookie->filter == NULL) {
				cookie->err_rc = NS_LDAP_MEMORY;
				return (-1);
			}
		}
	} else {
		if (cookie->filter)
			free(cookie->filter);
		cookie->filter = strdup(filter);
		free(filter);
		if (cookie->filter == NULL) {
			cookie->err_rc = NS_LDAP_MEMORY;
			return (-1);
		}
	}

	/*
	 * perform attribute/objectclass mapping on filter
	 */
	filter = NULL;

	if (cookie->service) {
		rc = get_mapped_filter(cookie, &filter);
		if (rc != NS_LDAP_SUCCESS) {
			cookie->err_rc = rc;
			return (-1);
		} else {
			/*
			 * get_mapped_filter returns
			 * NULL filter pointer, if
			 * no mapping was done
			 */
			if (filter) {
				free(cookie->filter);
				cookie->filter = filter;
			}
		}
	}

	/*
	 * validate filter to make sure it's legal
	 * [remove redundant ()'s]
	 */
	rc = validate_filter(cookie);
	if (rc != NS_LDAP_SUCCESS) {
		cookie->err_rc = rc;
		return (-1);
	}

	baselen = strlen(dptr->basedn);
	if (baselen > 0 && dptr->basedn[baselen-1] == COMMATOK) {
		rc = __ns_ldap_getParam(NS_LDAP_SEARCH_BASEDN_P,
		    (void ***)&param, &cookie->errorp);
		if (rc != NS_LDAP_SUCCESS) {
			cookie->err_rc = rc;
			return (-1);
		}
		str = ((char **)param)[0];
		baselen += strlen(str)+1;
		if (cookie->basedn)
			free(cookie->basedn);
		cookie->basedn = (char *)malloc(baselen);
		if (cookie->basedn == NULL) {
			cookie->err_rc = NS_LDAP_MEMORY;
			return (-1);
		}
		(void) strcpy(cookie->basedn, dptr->basedn);
		(void) strcat(cookie->basedn, str);
		(void) __ns_ldap_freeParam(&param);
	} else {
		if (cookie->basedn)
			free(cookie->basedn);
		cookie->basedn = strdup(dptr->basedn);
	}
	return (0);
}

static int
setup_referral_search(ns_ldap_cookie_t *cookie)
{
	ns_referral_info_t	*ref;

	ref = cookie->refpos;
	cookie->scope = ref->refScope;
	if (cookie->filter) {
		free(cookie->filter);
	}
	cookie->filter = strdup(ref->refFilter);
	if (cookie->basedn) {
		free(cookie->basedn);
	}
	cookie->basedn = strdup(ref->refDN);
	if (cookie->filter == NULL || cookie->basedn == NULL) {
		cookie->err_rc = NS_LDAP_MEMORY;
		return (-1);
	}
	return (0);
}

static int
get_current_session(ns_ldap_cookie_t *cookie)
{
	ConnectionID	connectionId = -1;
	Connection	*conp = NULL;
	int		rc;
	int		fail_if_new_pwd_reqd = 1;

	rc = __s_api_getConnection(NULL, cookie->i_flags,
	    cookie->i_auth, &connectionId, &conp,
	    &cookie->errorp, fail_if_new_pwd_reqd,
	    cookie->nopasswd_acct_mgmt, cookie->conn_user);

	/*
	 * If password control attached in *cookie->errorp,
	 * e.g. rc == NS_LDAP_SUCCESS_WITH_INFO,
	 * free the error structure (we do not need
	 * the sec_to_expired info).
	 * Reset rc to NS_LDAP_SUCCESS.
	 */
	if (rc == NS_LDAP_SUCCESS_WITH_INFO) {
		(void) __ns_ldap_freeError(
		    &cookie->errorp);
		cookie->errorp = NULL;
		rc = NS_LDAP_SUCCESS;
	}

	if (rc != NS_LDAP_SUCCESS) {
		cookie->err_rc = rc;
		return (-1);
	}
	cookie->conn = conp;
	cookie->connectionId = connectionId;

	return (0);
}

static int
get_next_session(ns_ldap_cookie_t *cookie)
{
	ConnectionID	connectionId = -1;
	Connection	*conp = NULL;
	int		rc;
	int		fail_if_new_pwd_reqd = 1;

	if (cookie->connectionId > -1) {
		DropConnection(cookie->connectionId, cookie->i_flags);
		cookie->connectionId = -1;
	}

	/* If using a MT connection, return it. */
	if (cookie->conn_user != NULL &&
	    cookie->conn_user->conn_mt != NULL)
		__s_api_conn_mt_return(cookie->conn_user);

	rc = __s_api_getConnection(NULL, cookie->i_flags,
	    cookie->i_auth, &connectionId, &conp,
	    &cookie->errorp, fail_if_new_pwd_reqd,
	    cookie->nopasswd_acct_mgmt, cookie->conn_user);

	/*
	 * If password control attached in *cookie->errorp,
	 * e.g. rc == NS_LDAP_SUCCESS_WITH_INFO,
	 * free the error structure (we do not need
	 * the sec_to_expired info).
	 * Reset rc to NS_LDAP_SUCCESS.
	 */
	if (rc == NS_LDAP_SUCCESS_WITH_INFO) {
		(void) __ns_ldap_freeError(
		    &cookie->errorp);
		cookie->errorp = NULL;
		rc = NS_LDAP_SUCCESS;
	}

	if (rc != NS_LDAP_SUCCESS) {
		cookie->err_rc = rc;
		return (-1);
	}
	cookie->conn = conp;
	cookie->connectionId = connectionId;
	return (0);
}

static int
get_referral_session(ns_ldap_cookie_t *cookie)
{
	ConnectionID	connectionId = -1;
	Connection	*conp = NULL;
	int		rc;
	int		fail_if_new_pwd_reqd = 1;

	if (cookie->connectionId > -1) {
		DropConnection(cookie->connectionId, cookie->i_flags);
		cookie->connectionId = -1;
	}

	/* set it up to use a connection opened for referral */
	if (cookie->conn_user != NULL) {
		/* If using a MT connection, return it. */
		if (cookie->conn_user->conn_mt != NULL)
			__s_api_conn_mt_return(cookie->conn_user);
		cookie->conn_user->referral = B_TRUE;
	}

	rc = __s_api_getConnection(cookie->refpos->refHost, 0,
	    cookie->i_auth, &connectionId, &conp,
	    &cookie->errorp, fail_if_new_pwd_reqd,
	    cookie->nopasswd_acct_mgmt, cookie->conn_user);

	/*
	 * If password control attached in *cookie->errorp,
	 * e.g. rc == NS_LDAP_SUCCESS_WITH_INFO,
	 * free the error structure (we do not need
	 * the sec_to_expired info).
	 * Reset rc to NS_LDAP_SUCCESS.
	 */
	if (rc == NS_LDAP_SUCCESS_WITH_INFO) {
		(void) __ns_ldap_freeError(
		    &cookie->errorp);
		cookie->errorp = NULL;
		rc = NS_LDAP_SUCCESS;
	}

	if (rc != NS_LDAP_SUCCESS) {
		cookie->err_rc = rc;
		return (-1);
	}
	cookie->conn = conp;
	cookie->connectionId = connectionId;
	return (0);
}

static int
paging_supported(ns_ldap_cookie_t *cookie)
{
	int		rc;

	cookie->listType = 0;
	rc = __s_api_isCtrlSupported(cookie->conn,
	    LDAP_CONTROL_VLVREQUEST);
	if (rc == NS_LDAP_SUCCESS) {
		cookie->listType = VLVCTRLFLAG;
		return (1);
	}
	rc = __s_api_isCtrlSupported(cookie->conn,
	    LDAP_CONTROL_SIMPLE_PAGE);
	if (rc == NS_LDAP_SUCCESS) {
		cookie->listType = SIMPLEPAGECTRLFLAG;
		return (1);
	}
	return (0);
}

typedef struct servicesorttype {
	char *service;
	ns_srvsidesort_t type;
} servicesorttype_t;

static servicesorttype_t *sort_type = NULL;
static int sort_type_size = 0;
static int sort_type_hwm = 0;
static mutex_t sort_type_mutex = DEFAULTMUTEX;


static ns_srvsidesort_t
get_srvsidesort_type(char *service)
{
	int i;
	ns_srvsidesort_t type = SSS_UNKNOWN;

	if (service == NULL)
		return (type);

	(void) mutex_lock(&sort_type_mutex);
	if (sort_type != NULL) {
		for (i = 0; i < sort_type_hwm; i++) {
			if (strcmp(sort_type[i].service, service) == 0) {
				type = sort_type[i].type;
				break;
			}
		}
	}
	(void) mutex_unlock(&sort_type_mutex);
	return (type);
}

static void
update_srvsidesort_type(char *service, ns_srvsidesort_t type)
{
	int i, size;
	servicesorttype_t *tmp;

	if (service == NULL)
		return;

	(void) mutex_lock(&sort_type_mutex);

	for (i = 0; i < sort_type_hwm; i++) {
		if (strcmp(sort_type[i].service, service) == 0) {
			sort_type[i].type = type;
			(void) mutex_unlock(&sort_type_mutex);
			return;
		}
	}
	if (sort_type == NULL) {
		size = 10;
		tmp = malloc(size * sizeof (servicesorttype_t));
		if (tmp == NULL) {
			(void) mutex_unlock(&sort_type_mutex);
			return;
		}
		sort_type = tmp;
		sort_type_size = size;
	} else if (sort_type_hwm >= sort_type_size) {
		size = sort_type_size + 10;
		tmp = realloc(sort_type, size * sizeof (servicesorttype_t));
		if (tmp == NULL) {
			(void) mutex_unlock(&sort_type_mutex);
			return;
		}
		sort_type = tmp;
		sort_type_size = size;
	}
	sort_type[sort_type_hwm].service = strdup(service);
	if (sort_type[sort_type_hwm].service == NULL) {
		(void) mutex_unlock(&sort_type_mutex);
		return;
	}
	sort_type[sort_type_hwm].type = type;
	sort_type_hwm++;

	(void) mutex_unlock(&sort_type_mutex);
}

static int
setup_vlv_params(ns_ldap_cookie_t *cookie)
{
	LDAPControl	**ctrls;
	LDAPsortkey	**sortkeylist;
	LDAPControl	*sortctrl = NULL;
	LDAPControl	*vlvctrl = NULL;
	LDAPVirtualList	vlist;
	char		*sortattr;
	int		rc;
	int		free_sort = FALSE;

	_freeControlList(&cookie->p_serverctrls);

	if (cookie->sortTypeTry == SSS_UNKNOWN)
		cookie->sortTypeTry = get_srvsidesort_type(cookie->service);
	if (cookie->sortTypeTry == SSS_UNKNOWN)
		cookie->sortTypeTry = SSS_SINGLE_ATTR;

	if (cookie->sortTypeTry == SSS_SINGLE_ATTR) {
		if ((cookie->i_flags & NS_LDAP_NOMAP) == 0 &&
		    cookie->i_sortattr) {
			sortattr =  __ns_ldap_mapAttribute(cookie->service,
			    cookie->i_sortattr);
			free_sort = TRUE;
		} else if (cookie->i_sortattr) {
			sortattr = (char *)cookie->i_sortattr;
		} else {
			sortattr = "cn";
		}
	} else {
		sortattr = "cn uid";
	}

	rc = ldap_create_sort_keylist(&sortkeylist, sortattr);
	if (free_sort)
		free(sortattr);
	if (rc != LDAP_SUCCESS) {
		(void) ldap_get_option(cookie->conn->ld,
		    LDAP_OPT_ERROR_NUMBER, &rc);
		return (rc);
	}
	rc = ldap_create_sort_control(cookie->conn->ld,
	    sortkeylist, 1, &sortctrl);
	ldap_free_sort_keylist(sortkeylist);
	if (rc != LDAP_SUCCESS) {
		(void) ldap_get_option(cookie->conn->ld,
		    LDAP_OPT_ERROR_NUMBER, &rc);
		return (rc);
	}

	vlist.ldvlist_index = cookie->index;
	vlist.ldvlist_size = 0;

	vlist.ldvlist_before_count = 0;
	vlist.ldvlist_after_count = LISTPAGESIZE-1;
	vlist.ldvlist_attrvalue = NULL;
	vlist.ldvlist_extradata = NULL;

	rc = ldap_create_virtuallist_control(cookie->conn->ld,
	    &vlist, &vlvctrl);
	if (rc != LDAP_SUCCESS) {
		ldap_control_free(sortctrl);
		(void) ldap_get_option(cookie->conn->ld, LDAP_OPT_ERROR_NUMBER,
		    &rc);
		return (rc);
	}

	ctrls = (LDAPControl **)calloc(3, sizeof (LDAPControl *));
	if (ctrls == NULL) {
		ldap_control_free(sortctrl);
		ldap_control_free(vlvctrl);
		return (LDAP_NO_MEMORY);
	}

	ctrls[0] = sortctrl;
	ctrls[1] = vlvctrl;

	cookie->p_serverctrls = ctrls;
	return (LDAP_SUCCESS);
}

static int
setup_simplepg_params(ns_ldap_cookie_t *cookie)
{
	LDAPControl	**ctrls;
	LDAPControl	*pgctrl = NULL;
	int		rc;

	_freeControlList(&cookie->p_serverctrls);

	rc = ldap_create_page_control(cookie->conn->ld, LISTPAGESIZE,
	    cookie->ctrlCookie, (char)0, &pgctrl);
	if (rc != LDAP_SUCCESS) {
		(void) ldap_get_option(cookie->conn->ld, LDAP_OPT_ERROR_NUMBER,
		    &rc);
		return (rc);
	}

	ctrls = (LDAPControl **)calloc(2, sizeof (LDAPControl *));
	if (ctrls == NULL) {
		ldap_control_free(pgctrl);
		return (LDAP_NO_MEMORY);
	}
	ctrls[0] = pgctrl;
	cookie->p_serverctrls = ctrls;
	return (LDAP_SUCCESS);
}

static void
proc_result_referrals(ns_ldap_cookie_t *cookie)
{
	int 		errCode, i, rc;
	char 		**referrals = NULL;

	/*
	 * Only follow one level of referrals, i.e.
	 * if already in referral mode, do nothing
	 */
	if (cookie->refpos == NULL) {
		cookie->new_state = END_RESULT;
		rc = ldap_parse_result(cookie->conn->ld,
		    cookie->resultMsg,
		    &errCode, NULL,
		    NULL, &referrals,
		    NULL, 0);
		if (rc != NS_LDAP_SUCCESS) {
			(void) ldap_get_option(cookie->conn->ld,
			    LDAP_OPT_ERROR_NUMBER,
			    &cookie->err_rc);
			cookie->new_state = LDAP_ERROR;
			return;
		}
		if (errCode == LDAP_REFERRAL) {
			for (i = 0; referrals[i] != NULL;
			    i++) {
				/* add to referral list */
				rc = __s_api_addRefInfo(
				    &cookie->reflist,
				    referrals[i],
				    cookie->basedn,
				    &cookie->scope,
				    cookie->filter,
				    cookie->conn->ld);
				if (rc != NS_LDAP_SUCCESS) {
					cookie->new_state =
					    ERROR;
					break;
				}
			}
			ldap_value_free(referrals);
		}
	}
}

static void
proc_search_references(ns_ldap_cookie_t *cookie)
{
	char 		**refurls = NULL;
	int 		i, rc;

	/*
	 * Only follow one level of referrals, i.e.
	 * if already in referral mode, do nothing
	 */
	if (cookie->refpos == NULL) {
		refurls = ldap_get_reference_urls(
		    cookie->conn->ld,
		    cookie->resultMsg);
		if (refurls == NULL) {
			(void) ldap_get_option(cookie->conn->ld,
			    LDAP_OPT_ERROR_NUMBER,
			    &cookie->err_rc);
			cookie->new_state = LDAP_ERROR;
			return;
		}
		for (i = 0; refurls[i] != NULL; i++) {
			/* add to referral list */
			rc = __s_api_addRefInfo(
			    &cookie->reflist,
			    refurls[i],
			    cookie->basedn,
			    &cookie->scope,
			    cookie->filter,
			    cookie->conn->ld);
			if (rc != NS_LDAP_SUCCESS) {
				cookie->new_state =
				    ERROR;
				break;
			}
		}
		/* free allocated storage */
		for (i = 0; refurls[i] != NULL; i++)
			free(refurls[i]);
	}
}

static ns_state_t
multi_result(ns_ldap_cookie_t *cookie)
{
	char		errstr[MAXERROR];
	char		*err;
	ns_ldap_error_t **errorp = NULL;
	LDAPControl	**retCtrls = NULL;
	int		i, rc;
	int		errCode;
	int		finished = 0;
	unsigned long	target_posp = 0;
	unsigned long	list_size = 0;
	unsigned int	count = 0;
	char 		**referrals = NULL;

	if (cookie->listType == VLVCTRLFLAG) {
		rc = ldap_parse_result(cookie->conn->ld, cookie->resultMsg,
		    &errCode, NULL, NULL, &referrals, &retCtrls, 0);
		if (rc != LDAP_SUCCESS) {
			(void) ldap_get_option(cookie->conn->ld,
			    LDAP_OPT_ERROR_NUMBER,
			    &cookie->err_rc);
			(void) sprintf(errstr,
			    gettext("LDAP ERROR (%d): %s.\n"),
			    cookie->err_rc,
			    gettext(ldap_err2string(cookie->err_rc)));
			err = strdup(errstr);
			MKERROR(LOG_WARNING, *errorp, NS_LDAP_INTERNAL, err,
			    NULL);
			cookie->err_rc = NS_LDAP_INTERNAL;
			cookie->errorp = *errorp;
			return (LDAP_ERROR);
		}
		if (errCode == LDAP_REFERRAL) {
			for (i = 0; referrals[i] != NULL;
			    i++) {
				/* add to referral list */
				rc = __s_api_addRefInfo(
				    &cookie->reflist,
				    referrals[i],
				    cookie->basedn,
				    &cookie->scope,
				    cookie->filter,
				    cookie->conn->ld);
				if (rc != NS_LDAP_SUCCESS) {
					ldap_value_free(
					    referrals);
					if (retCtrls)
						ldap_controls_free(
						    retCtrls);
					return (ERROR);
				}
			}
			ldap_value_free(referrals);
			if (retCtrls)
				ldap_controls_free(retCtrls);
			return (END_RESULT);
		}
		if (retCtrls) {
			rc = ldap_parse_virtuallist_control(
			    cookie->conn->ld, retCtrls,
			    &target_posp, &list_size, &errCode);
			if (rc == LDAP_SUCCESS) {
				/*
				 * AD does not return valid target_posp
				 * and list_size
				 */
				if (target_posp != 0 && list_size != 0) {
					cookie->index =
					    target_posp + LISTPAGESIZE;
					if (cookie->index > list_size)
						finished = 1;
				} else {
					if (cookie->entryCount < LISTPAGESIZE)
						finished = 1;
					else
						cookie->index +=
						    cookie->entryCount;
				}
			}
			ldap_controls_free(retCtrls);
			retCtrls = NULL;
		}
		else
			finished = 1;
	} else if (cookie->listType == SIMPLEPAGECTRLFLAG) {
		rc = ldap_parse_result(cookie->conn->ld, cookie->resultMsg,
		    &errCode, NULL, NULL, &referrals, &retCtrls, 0);
		if (rc != LDAP_SUCCESS) {
			(void) ldap_get_option(cookie->conn->ld,
			    LDAP_OPT_ERROR_NUMBER,
			    &cookie->err_rc);
			(void) sprintf(errstr,
			    gettext("LDAP ERROR (%d): %s.\n"),
			    cookie->err_rc,
			    gettext(ldap_err2string(cookie->err_rc)));
			err = strdup(errstr);
			MKERROR(LOG_WARNING, *errorp, NS_LDAP_INTERNAL, err,
			    NULL);
			cookie->err_rc = NS_LDAP_INTERNAL;
			cookie->errorp = *errorp;
			return (LDAP_ERROR);
		}
		if (errCode == LDAP_REFERRAL) {
			for (i = 0; referrals[i] != NULL;
			    i++) {
				/* add to referral list */
				rc = __s_api_addRefInfo(
				    &cookie->reflist,
				    referrals[i],
				    cookie->basedn,
				    &cookie->scope,
				    cookie->filter,
				    cookie->conn->ld);
				if (rc != NS_LDAP_SUCCESS) {
					ldap_value_free(
					    referrals);
					if (retCtrls)
						ldap_controls_free(
						    retCtrls);
					return (ERROR);
				}
			}
			ldap_value_free(referrals);
			if (retCtrls)
				ldap_controls_free(retCtrls);
			return (END_RESULT);
		}
		if (retCtrls) {
			if (cookie->ctrlCookie)
				ber_bvfree(cookie->ctrlCookie);
			cookie->ctrlCookie = NULL;
			rc = ldap_parse_page_control(
			    cookie->conn->ld, retCtrls,
			    &count, &cookie->ctrlCookie);
			if (rc == LDAP_SUCCESS) {
				if ((cookie->ctrlCookie == NULL) ||
				    (cookie->ctrlCookie->bv_val == NULL) ||
				    (cookie->ctrlCookie->bv_len == 0))
					finished = 1;
			}
			ldap_controls_free(retCtrls);
			retCtrls = NULL;
		}
		else
			finished = 1;
	}
	if (!finished && cookie->listType == VLVCTRLFLAG)
		return (NEXT_VLV);
	if (!finished && cookie->listType == SIMPLEPAGECTRLFLAG)
		return (NEXT_PAGE);
	if (finished)
		return (END_RESULT);
	return (ERROR);
}

/*
 * clear_results(ns_ldap_cookie_t):
 *
 * Attempt to obtain remnants of ldap responses and free them.  If remnants are
 * not obtained within a certain time period tell the server we wish to abandon
 * the request.
 *
 * Note that we do not initially tell the server to abandon the request as that
 * can be an expensive operation for the server, while it is cheap for us to
 * just flush the input.
 *
 * If something was to remain in libldap queue as a result of some error then
 * it would be freed later during drop connection call or when no other
 * requests share the connection.
 */
static void
clear_results(ns_ldap_cookie_t *cookie)
{
	int rc;
	if (cookie->conn != NULL && cookie->conn->ld != NULL &&
	    (cookie->connectionId != -1 ||
	    (cookie->conn_user != NULL &&
	    cookie->conn_user->conn_mt != NULL)) &&
	    cookie->msgId != 0) {
		/*
		 * We need to cleanup the rest of response (if there is such)
		 * and LDAP abandon is too heavy for LDAP servers, so we will
		 * wait for the rest of response till timeout and "process" it.
		 */
		rc = ldap_result(cookie->conn->ld, cookie->msgId, LDAP_MSG_ALL,
		    (struct timeval *)&cookie->search_timeout,
		    &cookie->resultMsg);
		if (rc != -1 && rc != 0 && cookie->resultMsg != NULL) {
			(void) ldap_msgfree(cookie->resultMsg);
			cookie->resultMsg = NULL;
		}

		/*
		 * If there was timeout then we will send  ABANDON request to
		 * LDAP server to decrease load.
		 */
		if (rc == 0)
			(void) ldap_abandon_ext(cookie->conn->ld, cookie->msgId,
			    NULL, NULL);
		/* Disassociate cookie with msgId */
		cookie->msgId = 0;
	}
}

/*
 * This state machine performs one or more LDAP searches to a given
 * directory server using service search descriptors and schema
 * mapping as appropriate.  The approximate pseudocode for
 * this routine is the following:
 *    Given the current configuration [set/reset connection etc.]
 *    and the current service search descriptor list
 *        or default search filter parameters
 *    foreach (service search filter) {
 *        initialize the filter [via filter_init if appropriate]
 *		  get a valid session/connection (preferably the current one)
 *					Recover if the connection is lost
 *        perform the search
 *        foreach (result entry) {
 *            process result [via callback if appropriate]
 *                save result for caller if accepted.
 *                exit and return all collected if allResults found;
 *        }
 *    }
 *    return collected results and exit
 */

static
ns_state_t
search_state_machine(ns_ldap_cookie_t *cookie, ns_state_t state, int cycle)
{
	char		errstr[MAXERROR];
	char		*err;
	int		rc, ret;
	int		rc_save;
	ns_ldap_entry_t	*nextEntry;
	ns_ldap_error_t *error = NULL;
	ns_ldap_error_t **errorp;
	struct timeval	tv;

	errorp = &error;
	cookie->state = state;
	errstr[0] = '\0';

	for (;;) {
		switch (cookie->state) {
		case CLEAR_RESULTS:
			clear_results(cookie);
			cookie->new_state = EXIT;
			break;
		case GET_ACCT_MGMT_INFO:
			/*
			 * Set the flag to get ldap account management controls.
			 */
			cookie->nopasswd_acct_mgmt = 1;
			cookie->new_state = INIT;
			break;
		case EXIT:
			/* state engine/connection cleaned up in delete */
			if (cookie->attribute) {
				__s_api_free2dArray(cookie->attribute);
				cookie->attribute = NULL;
			}
			if (cookie->reflist) {
				__s_api_deleteRefInfo(cookie->reflist);
				cookie->reflist = NULL;
			}
			return (EXIT);
		case INIT:
			cookie->sdpos = NULL;
			cookie->new_state = NEXT_SEARCH_DESCRIPTOR;
			if (cookie->attribute) {
				__s_api_free2dArray(cookie->attribute);
				cookie->attribute = NULL;
			}
			if ((cookie->i_flags & NS_LDAP_NOMAP) == 0 &&
			    cookie->i_attr) {
				cookie->attribute =
				    __ns_ldap_mapAttributeList(
				    cookie->service,
				    cookie->i_attr);
			}
			break;
		case REINIT:
			/* Check if we've reached MAX retries. */
			cookie->retries++;
			if (cookie->retries > NS_LIST_TRY_MAX - 1) {
				cookie->new_state = LDAP_ERROR;
				break;
			}

			/*
			 * Even if we still have retries left, check
			 * if retry is possible.
			 */
			if (cookie->conn_user != NULL) {
				int		retry;
				ns_conn_mgmt_t	*cmg;
				cmg = cookie->conn_user->conn_mgmt;
				retry = cookie->conn_user->retry;
				if (cmg != NULL && cmg->cfg_reloaded == 1)
					retry = 1;
				if (retry == 0) {
					cookie->new_state = LDAP_ERROR;
					break;
				}
			}
			/*
			 * Free results if any, reset to the first
			 * search descriptor and start a new session.
			 */
			if (cookie->resultMsg != NULL) {
				(void) ldap_msgfree(cookie->resultMsg);
				cookie->resultMsg = NULL;
			}
			(void) __ns_ldap_freeError(&cookie->errorp);
			(void) __ns_ldap_freeResult(&cookie->result);
			cookie->sdpos = cookie->sdlist;
			cookie->err_from_result = 0;
			cookie->err_rc = 0;
			cookie->new_state = NEXT_SESSION;
			break;
		case NEXT_SEARCH_DESCRIPTOR:
			/* get next search descriptor */
			if (cookie->sdpos == NULL) {
				cookie->sdpos = cookie->sdlist;
				cookie->new_state = GET_SESSION;
			} else {
				cookie->sdpos++;
				cookie->new_state = NEXT_SEARCH;
			}
			if (*cookie->sdpos == NULL)
				cookie->new_state = EXIT;
			break;
		case GET_SESSION:
			if (get_current_session(cookie) < 0)
				cookie->new_state = NEXT_SESSION;
			else
				cookie->new_state = NEXT_SEARCH;
			break;
		case NEXT_SESSION:
			if (get_next_session(cookie) < 0)
				cookie->new_state = RESTART_SESSION;
			else
				cookie->new_state = NEXT_SEARCH;
			break;
		case RESTART_SESSION:
			if (cookie->i_flags & NS_LDAP_HARD) {
				cookie->new_state = NEXT_SESSION;
				break;
			}
			(void) sprintf(errstr,
			    gettext("Session error no available conn.\n"),
			    state);
			err = strdup(errstr);
			MKERROR(LOG_WARNING, *errorp, NS_LDAP_INTERNAL, err,
			    NULL);
			cookie->err_rc = NS_LDAP_INTERNAL;
			cookie->errorp = *errorp;
			cookie->new_state = EXIT;
			break;
		case NEXT_SEARCH:
			/* setup referrals search if necessary */
			if (cookie->refpos) {
				if (setup_referral_search(cookie) < 0) {
					cookie->new_state = EXIT;
					break;
				}
			} else if (setup_next_search(cookie) < 0) {
				cookie->new_state = EXIT;
				break;
			}
			/* only do VLV/PAGE on scopes onelevel/subtree */
			if (paging_supported(cookie)) {
				if (cookie->use_paging &&
				    (cookie->scope != LDAP_SCOPE_BASE)) {
					cookie->index = 1;
					if (cookie->listType == VLVCTRLFLAG)
						cookie->new_state = NEXT_VLV;
					else
						cookie->new_state = NEXT_PAGE;
					break;
				}
			}
			cookie->new_state = ONE_SEARCH;
			break;
		case NEXT_VLV:
			rc = setup_vlv_params(cookie);
			if (rc != LDAP_SUCCESS) {
				cookie->err_rc = rc;
				cookie->new_state = LDAP_ERROR;
				break;
			}
			cookie->next_state = MULTI_RESULT;
			cookie->new_state = DO_SEARCH;
			break;
		case NEXT_PAGE:
			rc = setup_simplepg_params(cookie);
			if (rc != LDAP_SUCCESS) {
				cookie->err_rc = rc;
				cookie->new_state = LDAP_ERROR;
				break;
			}
			cookie->next_state = MULTI_RESULT;
			cookie->new_state = DO_SEARCH;
			break;
		case ONE_SEARCH:
			cookie->next_state = NEXT_RESULT;
			cookie->new_state = DO_SEARCH;
			break;
		case DO_SEARCH:
			cookie->entryCount = 0;
			rc = ldap_search_ext(cookie->conn->ld,
			    cookie->basedn,
			    cookie->scope,
			    cookie->filter,
			    cookie->attribute,
			    0,
			    cookie->p_serverctrls,
			    NULL,
			    &cookie->search_timeout, 0,
			    &cookie->msgId);
			if (rc != LDAP_SUCCESS) {
				if (rc == LDAP_BUSY ||
				    rc == LDAP_UNAVAILABLE ||
				    rc == LDAP_UNWILLING_TO_PERFORM ||
				    rc == LDAP_CONNECT_ERROR ||
				    rc == LDAP_SERVER_DOWN) {

					if (cookie->reinit_on_retriable_err) {
						cookie->err_rc = rc;
						cookie->new_state = REINIT;
					} else
						cookie->new_state =
						    NEXT_SESSION;

					/*
					 * If not able to reach the
					 * server, inform the ldap
					 * cache manager that the
					 * server should be removed
					 * from it's server list.
					 * Thus, the manager will not
					 * return this server on the next
					 * get-server request and will
					 * also reduce the server list
					 * refresh TTL, so that it will
					 * find out sooner when the server
					 * is up again.
					 */
					if ((rc == LDAP_CONNECT_ERROR ||
					    rc == LDAP_SERVER_DOWN) &&
					    (cookie->conn_user == NULL ||
					    cookie->conn_user->conn_mt ==
					    NULL)) {
						ret = __s_api_removeServer(
						    cookie->conn->serverAddr);
						if (ret == NS_CACHE_NOSERVER &&
						    cookie->conn_auth_type
						    == NS_LDAP_AUTH_NONE) {
							/*
							 * Couldn't remove
							 * server from server
							 * list.
							 * Exit to avoid
							 * potential infinite
							 * loop.
							 */
							cookie->err_rc = rc;
							cookie->new_state =
							    LDAP_ERROR;
						}
						if (cookie->connectionId > -1) {
							/*
							 * NS_LDAP_NEW_CONN
							 * indicates that the
							 * connection should
							 * be deleted, not
							 * kept alive
							 */
							DropConnection(
							    cookie->
							    connectionId,
							    NS_LDAP_NEW_CONN);
							cookie->connectionId =
							    -1;
						}
					} else if ((rc == LDAP_CONNECT_ERROR ||
					    rc == LDAP_SERVER_DOWN) &&
					    cookie->conn_user != NULL) {
						if (cookie->
						    reinit_on_retriable_err) {
							/*
							 * MT connection not
							 * usable, close it
							 * before REINIT.
							 * rc has already
							 * been saved in
							 * cookie->err_rc above.
							 */
							__s_api_conn_mt_close(
							    cookie->conn_user,
							    rc,
							    &cookie->errorp);
						} else {
							/*
							 * MT connection not
							 * usable, close it in
							 * the LDAP_ERROR state.
							 * A retry will be done
							 * next if allowed.
							 */
							cookie->err_rc = rc;
							cookie->new_state =
							    LDAP_ERROR;
						}
					}
					break;
				}
				cookie->err_rc = rc;
				cookie->new_state = LDAP_ERROR;
				break;
			}
			cookie->new_state = cookie->next_state;
			break;
		case NEXT_RESULT:
			/*
			 * Caller (e.g. __ns_ldap_list_batch_add)
			 * does not want to block on ldap_result().
			 * Therefore we execute ldap_result() with
			 * a zeroed timeval.
			 */
			if (cookie->no_wait == B_TRUE)
				(void) memset(&tv, 0, sizeof (tv));
			else
				tv = cookie->search_timeout;
			rc = ldap_result(cookie->conn->ld, cookie->msgId,
			    LDAP_MSG_ONE,
			    &tv,
			    &cookie->resultMsg);
			if (rc == LDAP_RES_SEARCH_RESULT) {
				cookie->new_state = END_RESULT;
				/* check and process referrals info */
				if (cookie->followRef)
					proc_result_referrals(
					    cookie);
				(void) ldap_msgfree(cookie->resultMsg);
				cookie->resultMsg = NULL;
				break;
			}
			/* handle referrals if necessary */
			if (rc == LDAP_RES_SEARCH_REFERENCE) {
				if (cookie->followRef)
					proc_search_references(cookie);
				(void) ldap_msgfree(cookie->resultMsg);
				cookie->resultMsg = NULL;
				break;
			}
			if (rc != LDAP_RES_SEARCH_ENTRY) {
				switch (rc) {
				case 0:
					if (cookie->no_wait == B_TRUE) {
						(void) ldap_msgfree(
						    cookie->resultMsg);
						cookie->resultMsg = NULL;
						return (cookie->new_state);
					}
					rc = LDAP_TIMEOUT;
					break;
				case -1:
					rc = ldap_get_lderrno(cookie->conn->ld,
					    NULL, NULL);
					break;
				default:
					rc = ldap_result2error(cookie->conn->ld,
					    cookie->resultMsg, 1);
					break;
				}
				if ((rc == LDAP_TIMEOUT ||
				    rc == LDAP_SERVER_DOWN) &&
				    (cookie->conn_user == NULL ||
				    cookie->conn_user->conn_mt == NULL)) {
					if (rc == LDAP_TIMEOUT)
						(void) __s_api_removeServer(
						    cookie->conn->serverAddr);
					if (cookie->connectionId > -1) {
						DropConnection(
						    cookie->connectionId,
						    NS_LDAP_NEW_CONN);
						cookie->connectionId = -1;
					}
					cookie->err_from_result = 1;
				}
				(void) ldap_msgfree(cookie->resultMsg);
				cookie->resultMsg = NULL;
				if (rc == LDAP_BUSY ||
				    rc == LDAP_UNAVAILABLE ||
				    rc == LDAP_UNWILLING_TO_PERFORM) {
					if (cookie->reinit_on_retriable_err) {
						cookie->err_rc = rc;
						cookie->err_from_result = 1;
						cookie->new_state = REINIT;
					} else
						cookie->new_state =
						    NEXT_SESSION;
					break;
				}
				if ((rc == LDAP_CONNECT_ERROR ||
				    rc == LDAP_SERVER_DOWN) &&
				    cookie->reinit_on_retriable_err) {
					ns_ldap_error_t *errorp = NULL;
					cookie->err_rc = rc;
					cookie->err_from_result = 1;
					cookie->new_state = REINIT;
					if (cookie->conn_user != NULL)
						__s_api_conn_mt_close(
						    cookie->conn_user,
						    rc, &errorp);
					if (errorp != NULL) {
						(void) __ns_ldap_freeError(
						    &cookie->errorp);
						cookie->errorp = errorp;
					}
					break;
				}
				cookie->err_rc = rc;
				cookie->new_state = LDAP_ERROR;
				break;
			}
			/* else LDAP_RES_SEARCH_ENTRY */
			/* get account management response control */
			if (cookie->nopasswd_acct_mgmt == 1) {
				rc = ldap_get_entry_controls(cookie->conn->ld,
				    cookie->resultMsg,
				    &(cookie->resultctrl));
				if (rc != LDAP_SUCCESS) {
					cookie->new_state = LDAP_ERROR;
					cookie->err_rc = rc;
					break;
				}
			}
			rc = __s_api_getEntry(cookie);
			(void) ldap_msgfree(cookie->resultMsg);
			cookie->resultMsg = NULL;
			if (rc != NS_LDAP_SUCCESS) {
				cookie->new_state = LDAP_ERROR;
				break;
			}
			cookie->new_state = PROCESS_RESULT;
			cookie->next_state = NEXT_RESULT;
			break;
		case MULTI_RESULT:
			if (cookie->no_wait == B_TRUE)
				(void) memset(&tv, 0, sizeof (tv));
			else
				tv = cookie->search_timeout;
			rc = ldap_result(cookie->conn->ld, cookie->msgId,
			    LDAP_MSG_ONE,
			    &tv,
			    &cookie->resultMsg);
			if (rc == LDAP_RES_SEARCH_RESULT) {
				rc = ldap_result2error(cookie->conn->ld,
				    cookie->resultMsg, 0);
				if (rc == LDAP_ADMINLIMIT_EXCEEDED &&
				    cookie->listType == VLVCTRLFLAG &&
				    cookie->sortTypeTry == SSS_SINGLE_ATTR) {
					/* Try old "cn uid" server side sort */
					cookie->sortTypeTry = SSS_CN_UID_ATTRS;
					cookie->new_state = NEXT_VLV;
					(void) ldap_msgfree(cookie->resultMsg);
					cookie->resultMsg = NULL;
					break;
				}
				if (rc != LDAP_SUCCESS) {
					cookie->err_rc = rc;
					cookie->new_state = LDAP_ERROR;
					(void) ldap_msgfree(cookie->resultMsg);
					cookie->resultMsg = NULL;
					break;
				}
				cookie->new_state = multi_result(cookie);
				(void) ldap_msgfree(cookie->resultMsg);
				cookie->resultMsg = NULL;
				break;
			}
			/* handle referrals if necessary */
			if (rc == LDAP_RES_SEARCH_REFERENCE &&
			    cookie->followRef) {
				proc_search_references(cookie);
				(void) ldap_msgfree(cookie->resultMsg);
				cookie->resultMsg = NULL;
				break;
			}
			if (rc != LDAP_RES_SEARCH_ENTRY) {
				switch (rc) {
				case 0:
					if (cookie->no_wait == B_TRUE) {
						(void) ldap_msgfree(
						    cookie->resultMsg);
						cookie->resultMsg = NULL;
						return (cookie->new_state);
					}
					rc = LDAP_TIMEOUT;
					break;
				case -1:
					rc = ldap_get_lderrno(cookie->conn->ld,
					    NULL, NULL);
					break;
				default:
					rc = ldap_result2error(cookie->conn->ld,
					    cookie->resultMsg, 1);
					break;
				}
				if ((rc == LDAP_TIMEOUT ||
				    rc == LDAP_SERVER_DOWN) &&
				    (cookie->conn_user == NULL ||
				    cookie->conn_user->conn_mt == NULL)) {
					if (rc == LDAP_TIMEOUT)
						(void) __s_api_removeServer(
						    cookie->conn->serverAddr);
					if (cookie->connectionId > -1) {
						DropConnection(
						    cookie->connectionId,
						    NS_LDAP_NEW_CONN);
						cookie->connectionId = -1;
					}
					cookie->err_from_result = 1;
				}
				(void) ldap_msgfree(cookie->resultMsg);
				cookie->resultMsg = NULL;
				if (rc == LDAP_BUSY ||
				    rc == LDAP_UNAVAILABLE ||
				    rc == LDAP_UNWILLING_TO_PERFORM) {
					if (cookie->reinit_on_retriable_err) {
						cookie->err_rc = rc;
						cookie->err_from_result = 1;
						cookie->new_state = REINIT;
					} else
						cookie->new_state =
						    NEXT_SESSION;
					break;
				}

				if ((rc == LDAP_CONNECT_ERROR ||
				    rc == LDAP_SERVER_DOWN) &&
				    cookie->reinit_on_retriable_err) {
					ns_ldap_error_t *errorp = NULL;
					cookie->err_rc = rc;
					cookie->err_from_result = 1;
					cookie->new_state = REINIT;
					if (cookie->conn_user != NULL)
						__s_api_conn_mt_close(
						    cookie->conn_user,
						    rc, &errorp);
					if (errorp != NULL) {
						(void) __ns_ldap_freeError(
						    &cookie->errorp);
						cookie->errorp = errorp;
					}
					break;
				}
				cookie->err_rc = rc;
				cookie->new_state = LDAP_ERROR;
				break;
			}
			/* else LDAP_RES_SEARCH_ENTRY */
			cookie->entryCount++;
			rc = __s_api_getEntry(cookie);
			(void) ldap_msgfree(cookie->resultMsg);
			cookie->resultMsg = NULL;
			if (rc != NS_LDAP_SUCCESS) {
				cookie->new_state = LDAP_ERROR;
				break;
			}
			/*
			 * If VLV search was successfull save the server
			 * side sort type tried.
			 */
			if (cookie->listType == VLVCTRLFLAG)
				update_srvsidesort_type(cookie->service,
				    cookie->sortTypeTry);

			cookie->new_state = PROCESS_RESULT;
			cookie->next_state = MULTI_RESULT;
			break;
		case PROCESS_RESULT:
			/* NOTE THIS STATE MAY BE PROCESSED BY CALLER */
			if (cookie->use_usercb && cookie->callback) {
				rc = 0;
				for (nextEntry = cookie->result->entry;
				    nextEntry != NULL;
				    nextEntry = nextEntry->next) {
					rc = (*cookie->callback)(nextEntry,
					    cookie->userdata);

					if (rc == NS_LDAP_CB_DONE) {
					/* cb doesn't want any more data */
						rc = NS_LDAP_PARTIAL;
						cookie->err_rc = rc;
						break;
					} else if (rc != NS_LDAP_CB_NEXT) {
					/* invalid return code */
						rc = NS_LDAP_OP_FAILED;
						cookie->err_rc = rc;
						break;
					}
				}
				(void) __ns_ldap_freeResult(&cookie->result);
				cookie->result = NULL;
			}
			if (rc != 0) {
				cookie->new_state = EXIT;
				break;
			}
			/* NOTE PREVIOUS STATE SPECIFIES NEXT STATE */
			cookie->new_state = cookie->next_state;
			break;
		case END_PROCESS_RESULT:
			cookie->new_state = cookie->next_state;
			break;
		case END_RESULT:
			/*
			 * XXX DO WE NEED THIS CASE?
			 * if (search is complete) {
			 * 	cookie->new_state = EXIT;
			 * } else
			 */
				/*
				 * entering referral mode if necessary
				 */
				if (cookie->followRef && cookie->reflist)
					cookie->new_state =
					    NEXT_REFERRAL;
				else
					cookie->new_state =
					    NEXT_SEARCH_DESCRIPTOR;
			break;
		case NEXT_REFERRAL:
			/* get next referral info */
			if (cookie->refpos == NULL)
				cookie->refpos =
				    cookie->reflist;
			else
				cookie->refpos =
				    cookie->refpos->next;
			/* check see if done with all referrals */
			if (cookie->refpos != NULL)
				cookie->new_state =
				    GET_REFERRAL_SESSION;
			else {
				__s_api_deleteRefInfo(cookie->reflist);
				cookie->reflist = NULL;
				cookie->new_state =
				    NEXT_SEARCH_DESCRIPTOR;
				if (cookie->conn_user != NULL)
					cookie->conn_user->referral = B_FALSE;
			}
			break;
		case GET_REFERRAL_SESSION:
			if (get_referral_session(cookie) < 0)
				cookie->new_state = EXIT;
			else {
				cookie->new_state = NEXT_SEARCH;
			}
			break;
		case LDAP_ERROR:
			rc_save = cookie->err_rc;
			if (cookie->err_from_result) {
				if (cookie->err_rc == LDAP_SERVER_DOWN) {
					(void) sprintf(errstr,
					    gettext("LDAP ERROR (%d): "
					    "Error occurred during"
					    " receiving results. "
					    "Connection to server lost."),
					    cookie->err_rc);
				} else if (cookie->err_rc == LDAP_TIMEOUT) {
					(void) sprintf(errstr,
					    gettext("LDAP ERROR (%d): "
					    "Error occurred during"
					    " receiving results. %s"
					    "."), cookie->err_rc,
					    ldap_err2string(
					    cookie->err_rc));
				}
			} else
				(void) sprintf(errstr,
				    gettext("LDAP ERROR (%d): %s."),
				    cookie->err_rc,
				    ldap_err2string(cookie->err_rc));
			err = strdup(errstr);
			if (cookie->err_from_result) {
				if (cookie->err_rc == LDAP_SERVER_DOWN) {
					MKERROR(LOG_INFO, *errorp,
					    cookie->err_rc, err, NULL);
				} else {
					MKERROR(LOG_WARNING, *errorp,
					    cookie->err_rc, err, NULL);
				}
			} else {
				MKERROR(LOG_WARNING, *errorp, NS_LDAP_INTERNAL,
				    err, NULL);
			}
			cookie->err_rc = NS_LDAP_INTERNAL;
			cookie->errorp = *errorp;
			if (cookie->conn_user != NULL)  {
				if (rc_save == LDAP_SERVER_DOWN ||
				    rc_save == LDAP_CONNECT_ERROR) {
					/*
					 * MT connection is not usable,
					 * close it.
					 */
					__s_api_conn_mt_close(cookie->conn_user,
					    rc_save, &cookie->errorp);
					return (ERROR);
				}
			}
			return (ERROR);
		default:
		case ERROR:
			(void) sprintf(errstr,
			    gettext("Internal State machine exit (%d).\n"),
			    cookie->state);
			err = strdup(errstr);
			MKERROR(LOG_WARNING, *errorp, NS_LDAP_INTERNAL, err,
			    NULL);
			cookie->err_rc = NS_LDAP_INTERNAL;
			cookie->errorp = *errorp;
			return (ERROR);
		}

		if (cookie->conn_user != NULL &&
		    cookie->conn_user->bad_mt_conn ==  B_TRUE) {
			__s_api_conn_mt_close(cookie->conn_user, 0, NULL);
			cookie->err_rc = cookie->conn_user->ns_rc;
			cookie->errorp = cookie->conn_user->ns_error;
			cookie->conn_user->ns_error = NULL;
			return (ERROR);
		}

		if (cycle == ONE_STEP) {
			return (cookie->new_state);
		}
		cookie->state = cookie->new_state;
	}
	/*NOTREACHED*/
#if 0
	(void) sprintf(errstr,
	    gettext("Unexpected State machine error.\n"));
	err = strdup(errstr);
	MKERROR(LOG_WARNING, *errorp, NS_LDAP_INTERNAL, err, NULL);
	cookie->err_rc = NS_LDAP_INTERNAL;
	cookie->errorp = *errorp;
	return (ERROR);
#endif
}

/*
 * For a lookup of shadow data, if shadow update is enabled,
 * check the calling process' privilege to ensure it's
 * allowed to perform such operation.
 */
static int
check_shadow(ns_ldap_cookie_t *cookie, const char *service)
{
	char errstr[MAXERROR];
	char *err;
	boolean_t priv;
	/* caller */
	priv_set_t *ps;
	/* zone */
	priv_set_t *zs;

	/*
	 * If service is "shadow", we may need
	 * to use privilege credentials.
	 */
	if ((strcmp(service, "shadow") == 0) &&
	    __ns_ldap_is_shadow_update_enabled()) {
		/*
		 * Since we release admin credentials after
		 * connection is closed and we do not cache
		 * them, we allow any root or all zone
		 * privilege process to read shadow data.
		 */
		priv = (geteuid() == 0);
		if (!priv) {
			/* caller */
			ps = priv_allocset();

			(void) getppriv(PRIV_EFFECTIVE, ps);
			zs = priv_str_to_set("zone", ",", NULL);
			priv = priv_isequalset(ps, zs);
			priv_freeset(ps);
			priv_freeset(zs);
		}
		if (!priv) {
			(void) sprintf(errstr,
			    gettext("Permission denied"));
			err = strdup(errstr);
			if (err == NULL)
				return (NS_LDAP_MEMORY);
			MKERROR(LOG_INFO, cookie->errorp, NS_LDAP_INTERNAL, err,
			    NULL);
			return (NS_LDAP_INTERNAL);
		}
		cookie->i_flags |= NS_LDAP_READ_SHADOW;
		/*
		 * We do not want to reuse connection (hence
		 * keep it open) with admin credentials.
		 * If NS_LDAP_KEEP_CONN is set, reject the
		 * request.
		 */
		if (cookie->i_flags & NS_LDAP_KEEP_CONN)
			return (NS_LDAP_INVALID_PARAM);
		cookie->i_flags |= NS_LDAP_NEW_CONN;
	}

	return (NS_LDAP_SUCCESS);
}

/*
 * internal function for __ns_ldap_list
 */
static int
ldap_list(
	ns_ldap_list_batch_t *batch,
	const char *service,
	const char *filter,
	const char *sortattr,
	int (*init_filter_cb)(const ns_ldap_search_desc_t *desc,
	char **realfilter, const void *userdata),
	const char * const *attribute,
	const ns_cred_t *auth,
	const int flags,
	ns_ldap_result_t **rResult, /* return result entries */
	ns_ldap_error_t **errorp,
	int *rcp,
	int (*callback)(const ns_ldap_entry_t *entry, const void *userdata),
	const void *userdata, ns_conn_user_t *conn_user)
{
	ns_ldap_cookie_t	*cookie;
	ns_ldap_search_desc_t	**sdlist = NULL;
	ns_ldap_search_desc_t	*dptr;
	ns_ldap_error_t		*error = NULL;
	char			**dns = NULL;
	int			scope;
	int			rc;
	int			from_result;

	*errorp = NULL;
	*rResult = NULL;
	*rcp = NS_LDAP_SUCCESS;

	/*
	 * Sanity check - NS_LDAP_READ_SHADOW is for our
	 * own internal use.
	 */
	if (flags & NS_LDAP_READ_SHADOW)
		return (NS_LDAP_INVALID_PARAM);

	/* Initialize State machine cookie */
	cookie = init_search_state_machine();
	if (cookie == NULL) {
		*rcp = NS_LDAP_MEMORY;
		return (NS_LDAP_MEMORY);
	}
	cookie->conn_user = conn_user;

	/* see if need to follow referrals */
	rc = __s_api_toFollowReferrals(flags,
	    &cookie->followRef, errorp);
	if (rc != NS_LDAP_SUCCESS) {
		delete_search_cookie(cookie);
		*rcp = rc;
		return (rc);
	}

	/* get the service descriptor - or create a default one */
	rc = __s_api_get_SSD_from_SSDtoUse_service(service,
	    &sdlist, &error);
	if (rc != NS_LDAP_SUCCESS) {
		delete_search_cookie(cookie);
		*errorp = error;
		*rcp = rc;
		return (rc);
	}

	if (sdlist == NULL) {
		/* Create default service Desc */
		sdlist = (ns_ldap_search_desc_t **)calloc(2,
		    sizeof (ns_ldap_search_desc_t *));
		if (sdlist == NULL) {
			delete_search_cookie(cookie);
			cookie = NULL;
			*rcp = NS_LDAP_MEMORY;
			return (NS_LDAP_MEMORY);
		}
		dptr = (ns_ldap_search_desc_t *)
		    calloc(1, sizeof (ns_ldap_search_desc_t));
		if (dptr == NULL) {
			free(sdlist);
			delete_search_cookie(cookie);
			cookie = NULL;
			*rcp = NS_LDAP_MEMORY;
			return (NS_LDAP_MEMORY);
		}
		sdlist[0] = dptr;

		/* default base */
		rc = __s_api_getDNs(&dns, service, &cookie->errorp);
		if (rc != NS_LDAP_SUCCESS) {
			if (dns) {
				__s_api_free2dArray(dns);
				dns = NULL;
			}
			*errorp = cookie->errorp;
			cookie->errorp = NULL;
			delete_search_cookie(cookie);
			cookie = NULL;
			*rcp = rc;
			return (rc);
		}
		dptr->basedn = strdup(dns[0]);
		__s_api_free2dArray(dns);
		dns = NULL;

		/* default scope */
		scope = 0;
		rc = __s_api_getSearchScope(&scope, &cookie->errorp);
		dptr->scope = scope;
	}

	cookie->sdlist = sdlist;

	/*
	 * use VLV/PAGE control only if NS_LDAP_PAGE_CTRL is set
	 */
	if (flags & NS_LDAP_PAGE_CTRL)
		cookie->use_paging = TRUE;
	else
		cookie->use_paging = FALSE;

	/* Set up other arguments */
	cookie->userdata = userdata;
	if (init_filter_cb != NULL) {
		cookie->init_filter_cb = init_filter_cb;
		cookie->use_filtercb = 1;
	}
	if (callback != NULL) {
		cookie->callback = callback;
		cookie->use_usercb = 1;
	}

	/* check_shadow() may add extra value to cookie->i_flags */
	cookie->i_flags = flags;
	if (service) {
		cookie->service = strdup(service);
		if (cookie->service == NULL) {
			delete_search_cookie(cookie);
			cookie = NULL;
			*rcp = NS_LDAP_MEMORY;
			return (NS_LDAP_MEMORY);
		}

		/*
		 * If given, use the credential given by the caller, and
		 * skip the credential check required for shadow update.
		 */
		if (auth == NULL) {
			rc = check_shadow(cookie, service);
			if (rc != NS_LDAP_SUCCESS) {
				*errorp = cookie->errorp;
				cookie->errorp = NULL;
				delete_search_cookie(cookie);
				cookie = NULL;
				*rcp = rc;
				return (rc);
			}
		}
	}

	cookie->i_filter = strdup(filter);
	cookie->i_attr = attribute;
	cookie->i_auth = auth;
	cookie->i_sortattr = sortattr;

	if (batch != NULL) {
		cookie->batch = batch;
		cookie->reinit_on_retriable_err = B_TRUE;
		cookie->no_wait = B_TRUE;
		(void) search_state_machine(cookie, INIT, 0);
		cookie->no_wait = B_FALSE;
		rc = cookie->err_rc;

		if (rc == NS_LDAP_SUCCESS) {
			/*
			 * Here rc == NS_LDAP_SUCCESS means that the state
			 * machine init'ed successfully. The actual status
			 * of the search will be determined by
			 * __ns_ldap_list_batch_end(). Add the cookie to our
			 * batch.
			 */
			cookie->caller_result = rResult;
			cookie->caller_errorp = errorp;
			cookie->caller_rc = rcp;
			cookie->next_cookie_in_batch = batch->cookie_list;
			batch->cookie_list = cookie;
			batch->nactive++;
			return (rc);
		}
		/*
		 * If state machine init failed then copy error to the caller
		 * and delete the cookie.
		 */
	} else {
		(void) search_state_machine(cookie, INIT, 0);
	}

	/* Copy results back to user */
	rc = cookie->err_rc;
	if (rc != NS_LDAP_SUCCESS) {
		if (conn_user != NULL && conn_user->ns_error != NULL) {
			*errorp = conn_user->ns_error;
			conn_user->ns_error = NULL;
		} else
			*errorp = cookie->errorp;
	}
	*rResult = cookie->result;
	from_result = cookie->err_from_result;

	cookie->errorp = NULL;
	cookie->result = NULL;
	delete_search_cookie(cookie);
	cookie = NULL;

	if (from_result == 0 && *rResult == NULL)
		rc = NS_LDAP_NOTFOUND;
	*rcp = rc;
	return (rc);
}


/*
 * __ns_ldap_list performs one or more LDAP searches to a given
 * directory server using service search descriptors and schema
 * mapping as appropriate. The operation may be retried a
 * couple of times in error situations.
 */
int
__ns_ldap_list(
	const char *service,
	const char *filter,
	int (*init_filter_cb)(const ns_ldap_search_desc_t *desc,
	char **realfilter, const void *userdata),
	const char * const *attribute,
	const ns_cred_t *auth,
	const int flags,
	ns_ldap_result_t **rResult, /* return result entries */
	ns_ldap_error_t **errorp,
	int (*callback)(const ns_ldap_entry_t *entry, const void *userdata),
	const void *userdata)
{
	int mod_flags;
	/*
	 * Strip the NS_LDAP_PAGE_CTRL option as this interface does not
	 * support this. If you want to use this option call the API
	 * __ns_ldap_list_sort() with has the sort attribute.
	 */
	mod_flags = flags & (~NS_LDAP_PAGE_CTRL);

	return (__ns_ldap_list_sort(service, filter, NULL, init_filter_cb,
	    attribute, auth, mod_flags, rResult, errorp,
	    callback, userdata));
}

/*
 * __ns_ldap_list_sort performs one or more LDAP searches to a given
 * directory server using service search descriptors and schema
 * mapping as appropriate. The operation may be retried a
 * couple of times in error situations.
 */
int
__ns_ldap_list_sort(
	const char *service,
	const char *filter,
	const char *sortattr,
	int (*init_filter_cb)(const ns_ldap_search_desc_t *desc,
	char **realfilter, const void *userdata),
	const char * const *attribute,
	const ns_cred_t *auth,
	const int flags,
	ns_ldap_result_t **rResult, /* return result entries */
	ns_ldap_error_t **errorp,
	int (*callback)(const ns_ldap_entry_t *entry, const void *userdata),
	const void *userdata)
{
	ns_conn_user_t	*cu = NULL;
	int		try_cnt = 0;
	int		rc = NS_LDAP_SUCCESS, trc;

	for (;;) {
		if (__s_api_setup_retry_search(&cu, NS_CONN_USER_SEARCH,
		    &try_cnt, &rc, errorp) == 0)
			break;
		rc = ldap_list(NULL, service, filter, sortattr, init_filter_cb,
		    attribute, auth, flags, rResult, errorp, &trc, callback,
		    userdata, cu);
	}

	return (rc);
}

/*
 * Create and initialize batch for native LDAP lookups
 */
int
__ns_ldap_list_batch_start(ns_ldap_list_batch_t **batch)
{
	*batch = calloc(1, sizeof (ns_ldap_list_batch_t));
	if (*batch == NULL)
		return (NS_LDAP_MEMORY);
	return (NS_LDAP_SUCCESS);
}


/*
 * Add a LDAP search request to the batch.
 */
int
__ns_ldap_list_batch_add(
	ns_ldap_list_batch_t *batch,
	const char *service,
	const char *filter,
	int (*init_filter_cb)(const ns_ldap_search_desc_t *desc,
	char **realfilter, const void *userdata),
	const char * const *attribute,
	const ns_cred_t *auth,
	const int flags,
	ns_ldap_result_t **rResult, /* return result entries */
	ns_ldap_error_t **errorp,
	int *rcp,
	int (*callback)(const ns_ldap_entry_t *entry, const void *userdata),
	const void *userdata)
{
	ns_conn_user_t	*cu;
	int		rc;
	int		mod_flags;

	cu =  __s_api_conn_user_init(NS_CONN_USER_SEARCH, NULL, 0);
	if (cu == NULL) {
		if (rcp != NULL)
			*rcp = NS_LDAP_MEMORY;
		return (NS_LDAP_MEMORY);
	}

	/*
	 * Strip the NS_LDAP_PAGE_CTRL option as the batch interface does not
	 * support this.
	 */
	mod_flags = flags & (~NS_LDAP_PAGE_CTRL);

	rc = ldap_list(batch, service, filter, NULL, init_filter_cb, attribute,
	    auth, mod_flags, rResult, errorp, rcp, callback, userdata, cu);

	/*
	 * Free the conn_user if the cookie was not batched. If the cookie
	 * was batched then __ns_ldap_list_batch_end or release will free the
	 * conn_user. The batch API instructs the search_state_machine
	 * to reinit and retry (max 3 times) on retriable LDAP errors.
	 */
	if (rc != NS_LDAP_SUCCESS && cu != NULL) {
		if (cu->conn_mt != NULL)
			__s_api_conn_mt_return(cu);
		__s_api_conn_user_free(cu);
	}
	return (rc);
}


/*
 * Free batch.
 */
void
__ns_ldap_list_batch_release(ns_ldap_list_batch_t *batch)
{
	ns_ldap_cookie_t	*c, *next;

	for (c = batch->cookie_list; c != NULL; c = next) {
		next = c->next_cookie_in_batch;
		if (c->conn_user != NULL) {
			if (c->conn_user->conn_mt != NULL)
				__s_api_conn_mt_return(c->conn_user);
			__s_api_conn_user_free(c->conn_user);
			c->conn_user = NULL;
		}
		delete_search_cookie(c);
	}
	free(batch);
}

#define	LD_USING_STATE(st) \
	((st == DO_SEARCH) || (st == MULTI_RESULT) || (st == NEXT_RESULT))

/*
 * Process batch. Everytime this function is called it selects an
 * active cookie from the batch and single steps through the
 * search_state_machine for the selected cookie. If lookup associated
 * with the cookie is complete (success or error) then the cookie is
 * removed from the batch and its memory freed.
 *
 * Returns 1 (if batch still has active cookies)
 *         0 (if batch has no more active cookies)
 *        -1 (on errors, *rcp will contain the error code)
 *
 * The caller should call this function in a loop as long as it returns 1
 * to process all the requests added to the batch. The results (and errors)
 * will be available in the locations provided by the caller at the time of
 * __ns_ldap_list_batch_add().
 */
static
int
__ns_ldap_list_batch_process(ns_ldap_list_batch_t *batch, int *rcp)
{
	ns_ldap_cookie_t	*c, *ptr, **prev;
	ns_state_t		state;
	ns_ldap_error_t		*errorp = NULL;
	int			rc;

	/* Check if are already done */
	if (batch->nactive == 0)
		return (0);

	/* Get the next cookie from the batch */
	c = (batch->next_cookie == NULL) ?
	    batch->cookie_list : batch->next_cookie;

	batch->next_cookie = c->next_cookie_in_batch;

	/*
	 * Checks the status of the cookie's connection if it needs
	 * to use that connection for ldap_search_ext or ldap_result.
	 * If the connection is no longer good but worth retrying
	 * then reinit the search_state_machine for this cookie
	 * starting from the first search descriptor. REINIT will
	 * clear any leftover results if max retries have not been
	 * reached and redo the search (which may also involve
	 * following referrals again).
	 *
	 * Note that each cookie in the batch will make this
	 * determination when it reaches one of the LD_USING_STATES.
	 */
	if (LD_USING_STATE(c->new_state) && c->conn_user != NULL) {
		rc = __s_api_setup_getnext(c->conn_user, &c->err_rc, &errorp);
		if (rc == LDAP_BUSY || rc == LDAP_UNAVAILABLE ||
		    rc == LDAP_UNWILLING_TO_PERFORM) {
			if (errorp != NULL) {
				(void) __ns_ldap_freeError(&c->errorp);
				c->errorp = errorp;
			}
			c->new_state = REINIT;
		} else if (rc == LDAP_CONNECT_ERROR ||
		    rc == LDAP_SERVER_DOWN) {
			if (errorp != NULL) {
				(void) __ns_ldap_freeError(&c->errorp);
				c->errorp = errorp;
			}
			c->new_state = REINIT;
			/*
			 * MT connection is not usable,
			 * close it before REINIT.
			 */
			__s_api_conn_mt_close(
			    c->conn_user, rc, NULL);
		} else if (rc != NS_LDAP_SUCCESS) {
			if (rcp != NULL)
				*rcp = rc;
			*c->caller_result = NULL;
			*c->caller_errorp = errorp;
			*c->caller_rc = rc;
			return (-1);
		}
	}

	for (;;) {
		/* Single step through the search_state_machine */
		state = search_state_machine(c, c->new_state, ONE_STEP);
		switch (state) {
		case LDAP_ERROR:
			(void) search_state_machine(c, state, ONE_STEP);
			(void) search_state_machine(c, CLEAR_RESULTS, ONE_STEP);
			/* FALLTHROUGH */
		case ERROR:
		case EXIT:
			*c->caller_result = c->result;
			*c->caller_errorp = c->errorp;
			*c->caller_rc =
			    (c->result == NULL && c->err_from_result == 0)
			    ? NS_LDAP_NOTFOUND : c->err_rc;
			c->result = NULL;
			c->errorp = NULL;
			/* Remove the cookie from the batch */
			ptr = batch->cookie_list;
			prev = &batch->cookie_list;
			while (ptr != NULL) {
				if (ptr == c) {
					*prev = ptr->next_cookie_in_batch;
					break;
				}
				prev = &ptr->next_cookie_in_batch;
				ptr = ptr->next_cookie_in_batch;
			}
			/* Delete cookie and decrement active cookie count */
			if (c->conn_user != NULL) {
				if (c->conn_user->conn_mt != NULL)
					__s_api_conn_mt_return(c->conn_user);
				__s_api_conn_user_free(c->conn_user);
				c->conn_user = NULL;
			}
			delete_search_cookie(c);
			batch->nactive--;
			break;
		case NEXT_RESULT:
		case MULTI_RESULT:
			/*
			 * This means that search_state_machine needs to do
			 * another ldap_result() for the cookie in question.
			 * We only do at most one ldap_result() per call in
			 * this function and therefore we return. This allows
			 * the caller to process results from other cookies
			 * in the batch without getting tied up on just one
			 * cookie.
			 */
			break;
		default:
			/*
			 * This includes states that follow NEXT_RESULT or
			 * MULTI_RESULT such as PROCESS_RESULT and
			 * END_PROCESS_RESULT. We continue processing
			 * this cookie till we reach either the error, exit
			 * or the result states.
			 */
			continue;
		}
		break;
	}

	/* Return 0 if no more cookies left otherwise 1 */
	return ((batch->nactive > 0) ? 1 : 0);
}


/*
 * Process all the active cookies in the batch and when none
 * remains finalize the batch.
 */
int
__ns_ldap_list_batch_end(ns_ldap_list_batch_t *batch)
{
	int rc = NS_LDAP_SUCCESS;
	while (__ns_ldap_list_batch_process(batch, &rc) > 0)
		;
	__ns_ldap_list_batch_release(batch);
	return (rc);
}

/*
 * find_domainname performs one or more LDAP searches to
 * find the value of the nisdomain attribute associated with
 * the input DN (with no retry).
 */

static int
find_domainname(const char *dn, char **domainname, const ns_cred_t *cred,
    ns_ldap_error_t **errorp, ns_conn_user_t *conn_user)
{

	ns_ldap_cookie_t	*cookie;
	ns_ldap_search_desc_t	**sdlist;
	ns_ldap_search_desc_t	*dptr;
	int			rc;
	char			**value;
	int			flags = 0;

	*domainname = NULL;
	*errorp = NULL;

	/* Initialize State machine cookie */
	cookie = init_search_state_machine();
	if (cookie == NULL) {
		return (NS_LDAP_MEMORY);
	}
	cookie->conn_user = conn_user;

	/* see if need to follow referrals */
	rc = __s_api_toFollowReferrals(flags,
	    &cookie->followRef, errorp);
	if (rc != NS_LDAP_SUCCESS) {
		delete_search_cookie(cookie);
		return (rc);
	}

	/* Create default service Desc */
	sdlist = (ns_ldap_search_desc_t **)calloc(2,
	    sizeof (ns_ldap_search_desc_t *));
	if (sdlist == NULL) {
		delete_search_cookie(cookie);
		cookie = NULL;
		return (NS_LDAP_MEMORY);
	}
	dptr = (ns_ldap_search_desc_t *)
	    calloc(1, sizeof (ns_ldap_search_desc_t));
	if (dptr == NULL) {
		free(sdlist);
		delete_search_cookie(cookie);
		cookie = NULL;
		return (NS_LDAP_MEMORY);
	}
	sdlist[0] = dptr;

	/* search base is dn */
	dptr->basedn = strdup(dn);

	/* search scope is base */
	dptr->scope = NS_LDAP_SCOPE_BASE;

	/* search filter is "nisdomain=*" */
	dptr->filter = strdup(_NIS_FILTER);

	cookie->sdlist = sdlist;
	cookie->i_filter = strdup(dptr->filter);
	cookie->i_attr = nis_domain_attrs;
	cookie->i_auth = cred;
	cookie->i_flags = 0;

	/* Process search */
	rc = search_state_machine(cookie, INIT, 0);

	/* Copy domain name if found */
	rc = cookie->err_rc;
	if (rc != NS_LDAP_SUCCESS) {
		if (conn_user != NULL && conn_user->ns_error != NULL) {
			*errorp = conn_user->ns_error;
			conn_user->ns_error = NULL;
		} else
			*errorp = cookie->errorp;
	}
	if (cookie->result == NULL)
		rc = NS_LDAP_NOTFOUND;
	if (rc == NS_LDAP_SUCCESS) {
		value = __ns_ldap_getAttr(cookie->result->entry,
		    _NIS_DOMAIN);
		if (value[0])
			*domainname = strdup(value[0]);
		else
			rc = NS_LDAP_NOTFOUND;
	}
	if (cookie->result != NULL)
		(void) __ns_ldap_freeResult(&cookie->result);
	cookie->errorp = NULL;
	delete_search_cookie(cookie);
	cookie = NULL;
	return (rc);
}

/*
 * __s_api_find_domainname performs one or more LDAP searches to
 * find the value of the nisdomain attribute associated with
 * the input DN (with retry).
 */

static int
__s_api_find_domainname(const char *dn, char **domainname,
    const ns_cred_t *cred, ns_ldap_error_t **errorp)
{
	ns_conn_user_t	*cu = NULL;
	int		try_cnt = 0;
	int		rc = NS_LDAP_SUCCESS;

	for (;;) {
		if (__s_api_setup_retry_search(&cu, NS_CONN_USER_SEARCH,
		    &try_cnt, &rc, errorp) == 0)
			break;
		rc = find_domainname(dn, domainname, cred, errorp, cu);
	}

	return (rc);
}

static int
firstEntry(
    const char *service,
    const char *filter,
    const char *sortattr,
    int (*init_filter_cb)(const ns_ldap_search_desc_t *desc,
    char **realfilter, const void *userdata),
    const char * const *attribute,
    const ns_cred_t *auth,
    const int flags,
    void **vcookie,
    ns_ldap_result_t **result,
    ns_ldap_error_t ** errorp,
    const void *userdata,
    ns_conn_user_t *conn_user)
{
	ns_ldap_cookie_t	*cookie = NULL;
	ns_ldap_error_t		*error = NULL;
	ns_state_t		state;
	ns_ldap_search_desc_t	**sdlist;
	ns_ldap_search_desc_t	*dptr;
	char			**dns = NULL;
	int			scope;
	int			rc;

	*errorp = NULL;
	*result = NULL;

	/*
	 * Sanity check - NS_LDAP_READ_SHADOW is for our
	 * own internal use.
	 */
	if (flags & NS_LDAP_READ_SHADOW)
		return (NS_LDAP_INVALID_PARAM);

	/* get the service descriptor - or create a default one */
	rc = __s_api_get_SSD_from_SSDtoUse_service(service,
	    &sdlist, &error);
	if (rc != NS_LDAP_SUCCESS) {
		*errorp = error;
		return (rc);
	}
	if (sdlist == NULL) {
		/* Create default service Desc */
		sdlist = (ns_ldap_search_desc_t **)calloc(2,
		    sizeof (ns_ldap_search_desc_t *));
		if (sdlist == NULL) {
			return (NS_LDAP_MEMORY);
		}
		dptr = (ns_ldap_search_desc_t *)
		    calloc(1, sizeof (ns_ldap_search_desc_t));
		if (dptr == NULL) {
			free(sdlist);
			return (NS_LDAP_MEMORY);
		}
		sdlist[0] = dptr;

		/* default base */
		rc = __s_api_getDNs(&dns, service, &error);
		if (rc != NS_LDAP_SUCCESS) {
			if (dns) {
				__s_api_free2dArray(dns);
				dns = NULL;
			}
			if (sdlist) {
				(void) __ns_ldap_freeSearchDescriptors(
				    &sdlist);

				sdlist = NULL;
			}
			*errorp = error;
			return (rc);
		}
		dptr->basedn = strdup(dns[0]);
		__s_api_free2dArray(dns);
		dns = NULL;

		/* default scope */
		scope = 0;
		cookie = init_search_state_machine();
		if (cookie == NULL) {
			if (sdlist) {
				(void) __ns_ldap_freeSearchDescriptors(&sdlist);
				sdlist = NULL;
			}
			return (NS_LDAP_MEMORY);
		}
		rc = __s_api_getSearchScope(&scope, &cookie->errorp);
		dptr->scope = scope;
	}

	/* Initialize State machine cookie */
	if (cookie == NULL)
		cookie = init_search_state_machine();
	if (cookie == NULL) {
		if (sdlist) {
			(void) __ns_ldap_freeSearchDescriptors(&sdlist);
			sdlist = NULL;
		}
		return (NS_LDAP_MEMORY);
	}

	/* identify self as a getent user */
	cookie->conn_user = conn_user;

	cookie->sdlist = sdlist;

	/* see if need to follow referrals */
	rc = __s_api_toFollowReferrals(flags,
	    &cookie->followRef, errorp);
	if (rc != NS_LDAP_SUCCESS) {
		delete_search_cookie(cookie);
		return (rc);
	}

	/*
	 * use VLV/PAGE control only if NS_LDAP_NO_PAGE_CTRL is not set
	 */
	if (flags & NS_LDAP_NO_PAGE_CTRL)
		cookie->use_paging = FALSE;
	else
		cookie->use_paging = TRUE;

	/* Set up other arguments */
	cookie->userdata = userdata;
	if (init_filter_cb != NULL) {
		cookie->init_filter_cb = init_filter_cb;
		cookie->use_filtercb = 1;
	}
	cookie->use_usercb = 0;
	/* check_shadow() may add extra value to cookie->i_flags */
	cookie->i_flags = flags;
	if (service) {
		cookie->service = strdup(service);
		if (cookie->service == NULL) {
			delete_search_cookie(cookie);
			return (NS_LDAP_MEMORY);
		}

		/*
		 * If given, use the credential given by the caller, and
		 * skip the credential check required for shadow update.
		 */
		if (auth == NULL) {
			rc = check_shadow(cookie, service);
			if (rc != NS_LDAP_SUCCESS) {
				*errorp = cookie->errorp;
				cookie->errorp = NULL;
				delete_search_cookie(cookie);
				cookie = NULL;
				return (rc);
			}
		}
	}

	cookie->i_filter = strdup(filter);
	cookie->i_attr = attribute;
	cookie->i_sortattr = sortattr;
	cookie->i_auth = auth;

	state = INIT;
	for (;;) {
		state = search_state_machine(cookie, state, ONE_STEP);
		switch (state) {
		case PROCESS_RESULT:
			*result = cookie->result;
			cookie->result = NULL;
			*vcookie = (void *)cookie;
			return (NS_LDAP_SUCCESS);
		case LDAP_ERROR:
			state = search_state_machine(cookie, state, ONE_STEP);
			state = search_state_machine(cookie, CLEAR_RESULTS,
			    ONE_STEP);
			/* FALLTHROUGH */
		case ERROR:
			rc = cookie->err_rc;
			if (conn_user != NULL && conn_user->ns_error != NULL) {
				*errorp = conn_user->ns_error;
				conn_user->ns_error = NULL;
			} else {
				*errorp = cookie->errorp;
				cookie->errorp = NULL;
			}
			delete_search_cookie(cookie);
			return (rc);
		case EXIT:
			rc = cookie->err_rc;
			if (rc != NS_LDAP_SUCCESS) {
				*errorp = cookie->errorp;
				cookie->errorp = NULL;
			} else {
				rc = NS_LDAP_NOTFOUND;
			}

			delete_search_cookie(cookie);
			return (rc);

		default:
			break;
		}
	}
}

int
__ns_ldap_firstEntry(
    const char *service,
    const char *filter,
    const char *vlv_sort,
    int (*init_filter_cb)(const ns_ldap_search_desc_t *desc,
    char **realfilter, const void *userdata),
    const char * const *attribute,
    const ns_cred_t *auth,
    const int flags,
    void **vcookie,
    ns_ldap_result_t **result,
    ns_ldap_error_t ** errorp,
    const void *userdata)
{
	ns_conn_user_t	*cu = NULL;
	int		try_cnt = 0;
	int		rc = NS_LDAP_SUCCESS;

	for (;;) {
		if (__s_api_setup_retry_search(&cu, NS_CONN_USER_GETENT,
		    &try_cnt, &rc, errorp) == 0)
			break;
		rc = firstEntry(service, filter, vlv_sort, init_filter_cb,
		    attribute, auth, flags, vcookie, result, errorp, userdata,
		    cu);
	}
	return (rc);
}

/*ARGSUSED2*/
int
__ns_ldap_nextEntry(void *vcookie, ns_ldap_result_t **result,
    ns_ldap_error_t ** errorp)
{
	ns_ldap_cookie_t	*cookie;
	ns_state_t		state;
	int			rc;

	cookie = (ns_ldap_cookie_t *)vcookie;
	cookie->result = NULL;
	*result = NULL;

	if (cookie->conn_user != NULL) {
		rc = __s_api_setup_getnext(cookie->conn_user,
		    &cookie->err_rc, errorp);
		if (rc != NS_LDAP_SUCCESS)
			return (rc);
	}

	state = END_PROCESS_RESULT;
	for (;;) {
		state = search_state_machine(cookie, state, ONE_STEP);
		switch (state) {
		case PROCESS_RESULT:
			*result = cookie->result;
			cookie->result = NULL;
			return (NS_LDAP_SUCCESS);
		case LDAP_ERROR:
			state = search_state_machine(cookie, state, ONE_STEP);
			state = search_state_machine(cookie, CLEAR_RESULTS,
			    ONE_STEP);
			/* FALLTHROUGH */
		case ERROR:
			rc = cookie->err_rc;
			*errorp = cookie->errorp;
			cookie->errorp = NULL;
			return (rc);
		case EXIT:
			return (NS_LDAP_SUCCESS);
		}
	}
}

int
__ns_ldap_endEntry(
	void **vcookie,
	ns_ldap_error_t ** errorp)
{
	ns_ldap_cookie_t	*cookie;
	int			rc;

	if (*vcookie == NULL)
		return (NS_LDAP_INVALID_PARAM);

	cookie = (ns_ldap_cookie_t *)(*vcookie);
	cookie->result = NULL;

	/* Complete search */
	rc = search_state_machine(cookie, CLEAR_RESULTS, 0);

	/* Copy results back to user */
	rc = cookie->err_rc;
	if (rc != NS_LDAP_SUCCESS)
		*errorp = cookie->errorp;

	cookie->errorp = NULL;
	if (cookie->conn_user != NULL) {
		if (cookie->conn_user->conn_mt != NULL)
			__s_api_conn_mt_return(cookie->conn_user);
		__s_api_conn_user_free(cookie->conn_user);
	}
	delete_search_cookie(cookie);
	cookie = NULL;
	*vcookie = NULL;

	return (rc);
}


int
__ns_ldap_freeResult(ns_ldap_result_t **result)
{

	ns_ldap_entry_t	*curEntry = NULL;
	ns_ldap_entry_t	*delEntry = NULL;
	int		i;
	ns_ldap_result_t	*res = *result;

#ifdef DEBUG
	(void) fprintf(stderr, "__ns_ldap_freeResult START\n");
#endif
	if (res == NULL)
		return (NS_LDAP_INVALID_PARAM);

	if (res->entry != NULL)
		curEntry = res->entry;

	for (i = 0; i < res->entries_count; i++) {
		if (curEntry != NULL) {
			delEntry = curEntry;
			curEntry = curEntry->next;
			__ns_ldap_freeEntry(delEntry);
		}
	}

	free(res);
	*result = NULL;
	return (NS_LDAP_SUCCESS);
}

/*ARGSUSED*/
int
__ns_ldap_auth(const ns_cred_t *auth,
		    const int flags,
		    ns_ldap_error_t **errorp,
		    LDAPControl **serverctrls,
		    LDAPControl **clientctrls)
{

	ConnectionID	connectionId = -1;
	Connection	*conp;
	int		rc = 0;
	int		do_not_fail_if_new_pwd_reqd = 0;
	int		nopasswd_acct_mgmt = 0;
	ns_conn_user_t	*conn_user;


#ifdef DEBUG
	(void) fprintf(stderr, "__ns_ldap_auth START\n");
#endif

	*errorp = NULL;
	if (!auth)
		return (NS_LDAP_INVALID_PARAM);

	conn_user = __s_api_conn_user_init(NS_CONN_USER_AUTH,
	    NULL, B_FALSE);

	rc = __s_api_getConnection(NULL, flags | NS_LDAP_NEW_CONN,
	    auth, &connectionId, &conp, errorp,
	    do_not_fail_if_new_pwd_reqd, nopasswd_acct_mgmt,
	    conn_user);

	if (conn_user != NULL)
		__s_api_conn_user_free(conn_user);

	if (rc == NS_LDAP_OP_FAILED && *errorp)
		(void) __ns_ldap_freeError(errorp);

	if (connectionId > -1)
		DropConnection(connectionId, flags);
	return (rc);
}

char **
__ns_ldap_getAttr(const ns_ldap_entry_t *entry, const char *attrname)
{
	int	i;

	if (entry == NULL)
		return (NULL);
	for (i = 0; i < entry->attr_count; i++) {
		if (strcasecmp(entry->attr_pair[i]->attrname, attrname) == NULL)
			return (entry->attr_pair[i]->attrvalue);
	}
	return (NULL);
}

ns_ldap_attr_t *
__ns_ldap_getAttrStruct(const ns_ldap_entry_t *entry, const char *attrname)
{
	int	i;

	if (entry == NULL)
		return (NULL);
	for (i = 0; i < entry->attr_count; i++) {
		if (strcasecmp(entry->attr_pair[i]->attrname, attrname) == NULL)
			return (entry->attr_pair[i]);
	}
	return (NULL);
}


/*ARGSUSED*/
int
__ns_ldap_uid2dn(const char *uid,
		char **userDN,
		const ns_cred_t *cred,	/* cred is ignored */
		ns_ldap_error_t **errorp)
{
	ns_ldap_result_t	*result = NULL;
	char		*filter, *userdata;
	char		errstr[MAXERROR];
	char		**value;
	int		rc = 0;
	int		i = 0;
	size_t		len;

	*errorp = NULL;
	*userDN = NULL;
	if ((uid == NULL) || (uid[0] == '\0'))
		return (NS_LDAP_INVALID_PARAM);

	while (uid[i] != '\0') {
		if (uid[i] == '=') {
			*userDN = strdup(uid);
			return (NS_LDAP_SUCCESS);
		}
		i++;
	}
	i = 0;
	while ((uid[i] != '\0') && (isdigit(uid[i])))
		i++;
	if (uid[i] == '\0') {
		len = strlen(UIDNUMFILTER) + strlen(uid) + 1;
		filter = (char *)malloc(len);
		if (filter == NULL) {
			*userDN = NULL;
			return (NS_LDAP_MEMORY);
		}
		(void) snprintf(filter, len, UIDNUMFILTER, uid);

		len = strlen(UIDNUMFILTER_SSD) + strlen(uid) + 1;
		userdata = (char *)malloc(len);
		if (userdata == NULL) {
			*userDN = NULL;
			return (NS_LDAP_MEMORY);
		}
		(void) snprintf(userdata, len, UIDNUMFILTER_SSD, uid);
	} else {
		len = strlen(UIDFILTER) + strlen(uid) + 1;
		filter = (char *)malloc(len);
		if (filter == NULL) {
			*userDN = NULL;
			return (NS_LDAP_MEMORY);
		}
		(void) snprintf(filter, len, UIDFILTER, uid);

		len = strlen(UIDFILTER_SSD) + strlen(uid) + 1;
		userdata = (char *)malloc(len);
		if (userdata == NULL) {
			*userDN = NULL;
			return (NS_LDAP_MEMORY);
		}
		(void) snprintf(userdata, len, UIDFILTER_SSD, uid);
	}

	/*
	 * we want to retrieve the DN as it appears in LDAP
	 * hence the use of NS_LDAP_NOT_CVT_DN in flags
	 */
	rc = __ns_ldap_list("passwd", filter,
	    __s_api_merge_SSD_filter,
	    NULL, cred, NS_LDAP_NOT_CVT_DN,
	    &result, errorp, NULL,
	    userdata);
	free(filter);
	filter = NULL;
	free(userdata);
	userdata = NULL;
	if (rc != NS_LDAP_SUCCESS) {
		if (result) {
			(void) __ns_ldap_freeResult(&result);
			result = NULL;
		}
		return (rc);
	}
	if (result->entries_count > 1) {
		(void) __ns_ldap_freeResult(&result);
		result = NULL;
		*userDN = NULL;
		(void) sprintf(errstr,
		    gettext("Too many entries are returned for %s"), uid);
		MKERROR(LOG_WARNING, *errorp, NS_LDAP_INTERNAL, strdup(errstr),
		    NULL);
		return (NS_LDAP_INTERNAL);
	}

	value = __ns_ldap_getAttr(result->entry, "dn");
	*userDN = strdup(value[0]);
	(void) __ns_ldap_freeResult(&result);
	result = NULL;
	return (NS_LDAP_SUCCESS);
}


/*ARGSUSED*/
int
__ns_ldap_host2dn(const char *host,
		const char *domain,
		char **hostDN,
		const ns_cred_t *cred,	/* cred is ignored */
		ns_ldap_error_t **errorp)
{
	ns_ldap_result_t	*result = NULL;
	char		*filter, *userdata;
	char		errstr[MAXERROR];
	char		**value;
	int		rc;
	size_t		len;

/*
 * XXX
 * the domain parameter needs to be used in case domain is not local, if
 * this routine is to support multi domain setups, it needs lots of work...
 */
	*errorp = NULL;
	*hostDN = NULL;
	if ((host == NULL) || (host[0] == '\0'))
		return (NS_LDAP_INVALID_PARAM);

	len = strlen(HOSTFILTER) + strlen(host) + 1;
	filter = (char *)malloc(len);
	if (filter == NULL) {
		return (NS_LDAP_MEMORY);
	}
	(void) snprintf(filter,	len, HOSTFILTER, host);

	len = strlen(HOSTFILTER_SSD) + strlen(host) + 1;
	userdata = (char *)malloc(len);
	if (userdata == NULL) {
		return (NS_LDAP_MEMORY);
	}
	(void) snprintf(userdata, len, HOSTFILTER_SSD, host);

	/*
	 * we want to retrieve the DN as it appears in LDAP
	 * hence the use of NS_LDAP_NOT_CVT_DN in flags
	 */
	rc = __ns_ldap_list("hosts", filter,
	    __s_api_merge_SSD_filter,
	    NULL, cred, NS_LDAP_NOT_CVT_DN, &result,
	    errorp, NULL,
	    userdata);
	free(filter);
	filter = NULL;
	free(userdata);
	userdata = NULL;
	if (rc != NS_LDAP_SUCCESS) {
		if (result) {
			(void) __ns_ldap_freeResult(&result);
			result = NULL;
		}
		return (rc);
	}

	if (result->entries_count > 1) {
		(void) __ns_ldap_freeResult(&result);
		result = NULL;
		*hostDN = NULL;
		(void) sprintf(errstr,
		    gettext("Too many entries are returned for %s"), host);
		MKERROR(LOG_WARNING, *errorp, NS_LDAP_INTERNAL, strdup(errstr),
		    NULL);
		return (NS_LDAP_INTERNAL);
	}

	value = __ns_ldap_getAttr(result->entry, "dn");
	*hostDN = strdup(value[0]);
	(void) __ns_ldap_freeResult(&result);
	result = NULL;
	return (NS_LDAP_SUCCESS);
}

/*ARGSUSED*/
int
__ns_ldap_dn2domain(const char *dn,
			char **domain,
			const ns_cred_t *cred,
			ns_ldap_error_t **errorp)
{
	int		rc, pnum, i, j, len = 0;
	char		*newdn, **rdns = NULL;
	char		**dns, *dn1;

	*errorp = NULL;

	if (domain == NULL)
		return (NS_LDAP_INVALID_PARAM);
	else
		*domain = NULL;

	if ((dn == NULL) || (dn[0] == '\0'))
		return (NS_LDAP_INVALID_PARAM);

	/*
	 * break dn into rdns
	 */
	dn1 = strdup(dn);
	if (dn1 == NULL)
		return (NS_LDAP_MEMORY);
	rdns = ldap_explode_dn(dn1, 0);
	free(dn1);
	if (rdns == NULL || *rdns == NULL)
		return (NS_LDAP_INVALID_PARAM);

	for (i = 0; rdns[i]; i++)
		len += strlen(rdns[i]) + 1;
	pnum = i;

	newdn = (char *)malloc(len + 1);
	dns = (char **)calloc(pnum, sizeof (char *));
	if (newdn == NULL || dns == NULL) {
		if (newdn)
			free(newdn);
		ldap_value_free(rdns);
		return (NS_LDAP_MEMORY);
	}

	/* construct a semi-normalized dn, newdn */
	*newdn = '\0';
	for (i = 0; rdns[i]; i++) {
		dns[i] = newdn + strlen(newdn);
		(void) strcat(newdn,
		    __s_api_remove_rdn_space(rdns[i]));
		(void) strcat(newdn, ",");
	}
	/* remove the last ',' */
	newdn[strlen(newdn) - 1] = '\0';
	ldap_value_free(rdns);

	/*
	 * loop and find the domain name associated with newdn,
	 * removing rdn one by one from left to right
	 */
	for (i = 0; i < pnum; i++) {

		if (*errorp)
			(void) __ns_ldap_freeError(errorp);

		/*
		 *  try cache manager first
		 */
		rc = __s_api_get_cachemgr_data(NS_CACHE_DN2DOMAIN,
		    dns[i], domain);
		if (rc != NS_LDAP_SUCCESS) {
			/*
			 *  try ldap server second
			 */
			rc = __s_api_find_domainname(dns[i], domain,
			    cred, errorp);
		} else {
			/*
			 * skip the last one,
			 * since it is already cached by ldap_cachemgr
			 */
			i--;
		}
		if (rc == NS_LDAP_SUCCESS) {
			if (__s_api_nscd_proc()) {
				/*
				 * If it's nscd, ask cache manager to save the
				 * dn to domain mapping(s)
				 */
				for (j = 0; j <= i; j++) {
					(void) __s_api_set_cachemgr_data(
					    NS_CACHE_DN2DOMAIN,
					    dns[j],
					    *domain);
				}
			}
			break;
		}
	}

	free(dns);
	free(newdn);
	if (rc != NS_LDAP_SUCCESS)
		rc = NS_LDAP_NOTFOUND;
	return (rc);
}

/*ARGSUSED*/
int
__ns_ldap_getServiceAuthMethods(const char *service,
		ns_auth_t ***auth,
		ns_ldap_error_t **errorp)
{
	char		errstr[MAXERROR];
	int		rc, i, done = 0;
	int		slen;
	void		**param;
	char		**sam, *srv, *send;
	ns_auth_t	**authpp = NULL, *ap;
	int		cnt, max;
	ns_config_t	*cfg;
	ns_ldap_error_t	*error = NULL;

	if (errorp == NULL)
		return (NS_LDAP_INVALID_PARAM);
	*errorp = NULL;

	if ((service == NULL) || (service[0] == '\0') ||
	    (auth == NULL))
		return (NS_LDAP_INVALID_PARAM);

	*auth = NULL;
	rc = __ns_ldap_getParam(NS_LDAP_SERVICE_AUTH_METHOD_P, &param, &error);
	if (rc != NS_LDAP_SUCCESS || param == NULL) {
		*errorp = error;
		return (rc);
	}
	sam = (char **)param;

	cfg = __s_api_get_default_config();
	cnt = 0;

	slen = strlen(service);

	for (; *sam; sam++) {
		srv = *sam;
		if (strncasecmp(service, srv, slen) != 0)
			continue;
		srv += slen;
		if (*srv != COLONTOK)
			continue;
		send = srv;
		srv++;
		for (max = 1; (send = strchr(++send, SEMITOK)) != NULL;
		    max++) {}
		authpp = (ns_auth_t **)calloc(++max, sizeof (ns_auth_t *));
		if (authpp == NULL) {
			(void) __ns_ldap_freeParam(&param);
			__s_api_release_config(cfg);
			return (NS_LDAP_MEMORY);
		}
		while (!done) {
			send = strchr(srv, SEMITOK);
			if (send != NULL) {
				*send = '\0';
				send++;
			}
			i = __s_get_enum_value(cfg, srv, NS_LDAP_AUTH_P);
			if (i == -1) {
				(void) __ns_ldap_freeParam(&param);
				(void) sprintf(errstr,
				gettext("Unsupported "
				    "serviceAuthenticationMethod: %s.\n"), srv);
				MKERROR(LOG_WARNING, *errorp, NS_CONFIG_SYNTAX,
				    strdup(errstr), NULL);
				__s_api_release_config(cfg);
				return (NS_LDAP_CONFIG);
			}
			ap = __s_api_AuthEnumtoStruct((EnumAuthType_t)i);
			if (ap == NULL) {
				(void) __ns_ldap_freeParam(&param);
				__s_api_release_config(cfg);
				return (NS_LDAP_MEMORY);
			}
			authpp[cnt++] = ap;
			if (send == NULL)
				done = TRUE;
			else
				srv = send;
		}
	}

	*auth = authpp;
	(void) __ns_ldap_freeParam(&param);
	__s_api_release_config(cfg);
	return (NS_LDAP_SUCCESS);
}

/*
 * This routine is called when certain scenario occurs
 * e.g.
 * service == auto_home
 * SSD = automount: ou = mytest,
 * NS_LDAP_MAPATTRIBUTE= auto_home: automountMapName=AAA
 * NS_LDAP_OBJECTCLASSMAP= auto_home:automountMap=MynisMap
 * NS_LDAP_OBJECTCLASSMAP= auto_home:automount=MynisObject
 *
 * The automountMapName is prepended implicitely but is mapped
 * to AAA. So dn could appers as
 * dn: AAA=auto_home,ou=bar,dc=foo,dc=com
 * dn: automountKey=user_01,AAA=auto_home,ou=bar,dc=foo,dc=com
 * dn: automountKey=user_02,AAA=auto_home,ou=bar,dc=foo,dc=com
 * in the directory.
 * This function is called to covert the mapped attr back to
 * orig attr when the entries are searched and returned
 */

int
__s_api_convert_automountmapname(const char *service, char **dn,
		ns_ldap_error_t **errp) {

	char	**mapping = NULL;
	char	*mapped_attr = NULL;
	char	*automountmapname = "automountMapName";
	char	*buffer = NULL;
	int	rc = NS_LDAP_SUCCESS;
	char	errstr[MAXERROR];

	/*
	 * dn is an input/out parameter, check it first
	 */

	if (service == NULL || dn == NULL || *dn == NULL)
		return (NS_LDAP_INVALID_PARAM);

	/*
	 * Check to see if there is a mapped attribute for auto_xxx
	 */

	mapping = __ns_ldap_getMappedAttributes(service, automountmapname);

	/*
	 * if no mapped attribute for auto_xxx, try automount
	 */

	if (mapping == NULL)
		mapping = __ns_ldap_getMappedAttributes(
			"automount", automountmapname);

	/*
	 * if no mapped attribute is found, return SUCCESS (no op)
	 */

	if (mapping == NULL)
		return (NS_LDAP_SUCCESS);

	/*
	 * if the mapped attribute is found and attr is not empty,
	 * copy it
	 */

	if (mapping[0] != NULL) {
		mapped_attr = strdup(mapping[0]);
		__s_api_free2dArray(mapping);
		if (mapped_attr == NULL) {
			return (NS_LDAP_MEMORY);
		}
	} else {
		__s_api_free2dArray(mapping);

		(void) snprintf(errstr, (2 * MAXERROR),
			gettext(
			"Attribute nisMapName is mapped to an "
			"empty string.\n"));

		MKERROR(LOG_ERR, *errp, NS_CONFIG_SYNTAX,
			strdup(errstr), NULL);

		return (NS_LDAP_CONFIG);
	}

	/*
	 * Locate the mapped attribute in the dn
	 * and replace it if it exists
	 */

	rc = __s_api_replace_mapped_attr_in_dn(
		(const char *) automountmapname, (const char *) mapped_attr,
		(const char *) *dn, &buffer);

	/* clean up */

	free(mapped_attr);

	/*
	 * If mapped attr is found(buffer != NULL)
	 *	a new dn is returned
	 * If no mapped attribute is in dn,
	 *	return NS_LDAP_SUCCESS (no op)
	 * If no memory,
	 *	return NS_LDAP_MEMORY (no op)
	 */

	if (buffer != NULL) {
		free(*dn);
		*dn = buffer;
	}

	return (rc);
}

/*
 * If the mapped attr is found in the dn,
 * 	return NS_LDAP_SUCCESS and a new_dn.
 * If no mapped attr is found,
 * 	return NS_LDAP_SUCCESS and *new_dn == NULL
 * If there is not enough memory,
 * 	return NS_LDAP_MEMORY and *new_dn == NULL
 */

int
__s_api_replace_mapped_attr_in_dn(
	const char *orig_attr, const char *mapped_attr,
	const char *dn, char **new_dn) {

	char	**dnArray = NULL;
	char	*cur = NULL, *start = NULL;
	int	i = 0, found = 0;
	int	len = 0, orig_len = 0, mapped_len = 0;
	int	dn_len = 0, tmp_len = 0;

	*new_dn = NULL;

	/*
	 * seperate dn into individual componets
	 * e.g.
	 * "automountKey=user_01" , "automountMapName_test=auto_home", ...
	 */
	dnArray = ldap_explode_dn(dn, 0);

	/*
	 * This will find "mapped attr=value" in dn.
	 * It won't find match if mapped attr appears
	 * in the value.
	 */
	for (i = 0; dnArray[i] != NULL; i++) {
		/*
		 * This function is called when reading from
		 * the directory so assume each component has "=".
		 * Any ill formatted dn should be rejected
		 * before adding to the directory
		 */
		cur = strchr(dnArray[i], '=');
		*cur = '\0';
		if (strcasecmp(mapped_attr, dnArray[i]) == 0)
			found = 1;
		*cur = '=';
		if (found) break;
	}

	if (!found) {
		__s_api_free2dArray(dnArray);
		*new_dn = NULL;
		return (NS_LDAP_SUCCESS);
	}
	/*
	 * The new length is *dn length + (difference between
	 * orig attr and mapped attr) + 1 ;
	 * e.g.
	 * automountKey=aa,automountMapName_test=auto_home,dc=foo,dc=com
	 * ==>
	 * automountKey=aa,automountMapName=auto_home,dc=foo,dc=com
	 */
	mapped_len = strlen(mapped_attr);
	orig_len = strlen(orig_attr);
	dn_len = strlen(dn);
	len = dn_len + orig_len - mapped_len + 1;
	*new_dn = (char *)calloc(1, len);
	if (*new_dn == NULL) {
		__s_api_free2dArray(dnArray);
		return (NS_LDAP_MEMORY);
	}

	/*
	 * Locate the mapped attr in the dn.
	 * Use dnArray[i] instead of mapped_attr
	 * because mapped_attr could appear in
	 * the value
	 */

	cur = strstr(dn, dnArray[i]);
	__s_api_free2dArray(dnArray);
	/* copy the portion before mapped attr in dn  */
	start = *new_dn;
	tmp_len = cur - dn;
	(void) memcpy((void *) start, (const void*) dn, tmp_len);

	/*
	 * Copy the orig_attr. e.g. automountMapName
	 * This replaces mapped attr with orig attr
	 */
	start = start + (cur - dn); /* move cursor in buffer */
	(void) memcpy((void *) start, (const void*) orig_attr, orig_len);

	/*
	 * Copy the portion after mapped attr in dn
	 */
	cur = cur + mapped_len; /* move cursor in  dn  */
	start = start + orig_len; /* move cursor in buffer */
	(void) strcpy(start, cur);

	return (NS_LDAP_SUCCESS);
}

/*
 * Validate Filter functions
 */

/* ***** Start of modified libldap.so.5 filter parser ***** */

/* filter parsing routine forward references */
static int adj_filter_list(char *str);
static int adj_simple_filter(char *str);
static int unescape_filterval(char *val);
static int hexchar2int(char c);
static int adj_substring_filter(char *val);


/*
 * assumes string manipulation is in-line
 * and all strings are sufficient in size
 * return value is the position after 'c'
 */

static char *
resync_str(char *str, char *next, char c)
{
	char	*ret;

	ret = str + strlen(str);
	*next = c;
	if (ret == next)
		return (ret);
	(void) strcat(str, next);
	return (ret);
}

static char *
find_right_paren(char *s)
{
	int	balance, escape;

	balance = 1;
	escape = 0;
	while (*s && balance) {
		if (escape == 0) {
			if (*s == '(')
				balance++;
			else if (*s == ')')
				balance--;
		}
		if (*s == '\\' && ! escape)
			escape = 1;
		else
			escape = 0;
		if (balance)
			s++;
	}

	return (*s ? s : NULL);
}

static char *
adj_complex_filter(char	*str)
{
	char	*next;

	/*
	 * We have (x(filter)...) with str sitting on
	 * the x.  We have to find the paren matching
	 * the one before the x and put the intervening
	 * filters by calling adj_filter_list().
	 */

	str++;
	if ((next = find_right_paren(str)) == NULL)
		return (NULL);

	*next = '\0';
	if (adj_filter_list(str) == -1)
		return (NULL);
	next = resync_str(str, next, ')');
	next++;

	return (next);
}

static int
adj_filter(char *str)
{
	char	*next;
	int	parens, balance, escape;
	char	*np, *cp,  *dp;

	parens = 0;
	while (*str) {
		switch (*str) {
		case '(':
			str++;
			parens++;
			switch (*str) {
			case '&':
				if ((str = adj_complex_filter(str)) == NULL)
					return (-1);

				parens--;
				break;

			case '|':
				if ((str = adj_complex_filter(str)) == NULL)
					return (-1);

				parens--;
				break;

			case '!':
				if ((str = adj_complex_filter(str)) == NULL)
					return (-1);

				parens--;
				break;

			case '(':
				/* illegal ((case - generated by conversion */

				/* find missing close) */
				np = find_right_paren(str+1);

				/* error if not found */
				if (np == NULL)
					return (-1);

				/* remove redundant (and) */
				for (dp = str, cp = str+1; cp < np; ) {
					*dp++ = *cp++;
				}
				cp++;
				while (*cp)
					*dp++ = *cp++;
				*dp = '\0';

				/* re-start test at original ( */
				parens--;
				str--;
				break;

			default:
				balance = 1;
				escape = 0;
				next = str;
				while (*next && balance) {
					if (escape == 0) {
						if (*next == '(')
							balance++;
						else if (*next == ')')
							balance--;
					}
					if (*next == '\\' && ! escape)
						escape = 1;
					else
						escape = 0;
					if (balance)
						next++;
				}
				if (balance != 0)
					return (-1);

				*next = '\0';
				if (adj_simple_filter(str) == -1) {
					return (-1);
				}
				next = resync_str(str, next, ')');
				next++;
				str = next;
				parens--;
				break;
			}
			break;

		case ')':
			str++;
			parens--;
			break;

		case ' ':
			str++;
			break;

		default:	/* assume it's a simple type=value filter */
			next = strchr(str, '\0');
			if (adj_simple_filter(str) == -1) {
				return (-1);
			}
			str = next;
			break;
		}
	}

	return (parens ? -1 : 0);
}


/*
 * Put a list of filters like this "(filter1)(filter2)..."
 */

static int
adj_filter_list(char *str)
{
	char	*next;
	char	save;

	while (*str) {
		while (*str && isspace(*str))
			str++;
		if (*str == '\0')
			break;

		if ((next = find_right_paren(str + 1)) == NULL)
			return (-1);
		save = *++next;

		/* now we have "(filter)" with str pointing to it */
		*next = '\0';
		if (adj_filter(str) == -1)
			return (-1);
		next = resync_str(str, next, save);

		str = next;
	}

	return (0);
}


/*
 * is_valid_attr - returns 1 if a is a syntactically valid left-hand side
 * of a filter expression, 0 otherwise.  A valid string may contain only
 * letters, numbers, hyphens, semi-colons, colons and periods. examples:
 *	cn
 *	cn;lang-fr
 *	1.2.3.4;binary;dynamic
 *	mail;dynamic
 *	cn:dn:1.2.3.4
 *
 * For compatibility with older servers, we also allow underscores in
 * attribute types, even through they are not allowed by the LDAPv3 RFCs.
 */
static int
is_valid_attr(char *a)
{
	for (; *a; a++) {
		if (!isascii(*a)) {
			return (0);
		} else if (!isalnum(*a)) {
			switch (*a) {
			case '-':
			case '.':
			case ';':
			case ':':
			case '_':
				break; /* valid */
			default:
				return (0);
			}
		}
	}
	return (1);
}

static char *
find_star(char *s)
{
	for (; *s; ++s) {
		switch (*s) {
		case '*':
			return (s);
		case '\\':
			++s;
			if (hexchar2int(s[0]) >= 0 && hexchar2int(s[1]) >= 0)
				++s;
		default:
			break;
		}
	}
	return (NULL);
}

static int
adj_simple_filter(char *str)
{
	char		*s, *s2, *s3, filterop;
	char		*value;
	int		ftype = 0;
	int		rc;

	rc = -1;	/* pessimistic */

	if ((str = strdup(str)) == NULL) {
		return (rc);
	}

	if ((s = strchr(str, '=')) == NULL) {
		goto free_and_return;
	}
	value = s + 1;
	*s-- = '\0';
	filterop = *s;
	if (filterop == '<' || filterop == '>' || filterop == '~' ||
	    filterop == ':') {
		*s = '\0';
	}

	if (! is_valid_attr(str)) {
		goto free_and_return;
	}

	switch (filterop) {
	case '<': /* LDAP_FILTER_LE */
	case '>': /* LDAP_FILTER_GE */
	case '~': /* LDAP_FILTER_APPROX */
		break;
	case ':':	/* extended filter - v3 only */
		/*
		 * extended filter looks like this:
		 *
		 *	[type][':dn'][':'oid]':='value
		 *
		 * where one of type or :oid is required.
		 *
		 */
		s2 = s3 = NULL;
		if ((s2 = strrchr(str, ':')) == NULL) {
			goto free_and_return;
		}
		if (strcasecmp(s2, ":dn") == 0) {
			*s2 = '\0';
		} else {
			*s2 = '\0';
			if ((s3 = strrchr(str, ':')) != NULL) {
				if (strcasecmp(s3, ":dn") != 0) {
					goto free_and_return;
				}
				*s3 = '\0';
			}
		}
		if (unescape_filterval(value) < 0) {
			goto free_and_return;
		}
		rc = 0;
		goto free_and_return;
		/* break; */
	default:
		if (find_star(value) == NULL) {
			ftype = 0; /* LDAP_FILTER_EQUALITY */
		} else if (strcmp(value, "*") == 0) {
			ftype = 1; /* LDAP_FILTER_PRESENT */
		} else {
			rc = adj_substring_filter(value);
			goto free_and_return;
		}
		break;
	}

	if (ftype != 0) {	/* == LDAP_FILTER_PRESENT */
		rc = 0;
	} else if (unescape_filterval(value) >= 0) {
		rc = 0;
	}
	if (rc != -1) {
		rc = 0;
	}

free_and_return:
	free(str);
	return (rc);
}


/*
 * Check in place both LDAPv2 (RFC-1960) and LDAPv3 (hexadecimal) escape
 * sequences within the null-terminated string 'val'.
 *
 * If 'val' contains invalid escape sequences we return -1.
 * Otherwise return 1
 */
static int
unescape_filterval(char *val)
{
	int	escape, firstdigit;
	char	*s;

	firstdigit = 0;
	escape = 0;
	for (s = val; *s; s++) {
		if (escape) {
			/*
			 * first try LDAPv3 escape (hexadecimal) sequence
			 */
			if (hexchar2int(*s) < 0) {
				if (firstdigit) {
					/*
					 * LDAPv2 (RFC1960) escape sequence
					 */
					escape = 0;
				} else {
					return (-1);
				}
			}
			if (firstdigit) {
				firstdigit = 0;
			} else {
				escape = 0;
			}

		} else if (*s != '\\') {
			escape = 0;

		} else {
			escape = 1;
			firstdigit = 1;
		}
	}

	return (1);
}


/*
 * convert character 'c' that represents a hexadecimal digit to an integer.
 * if 'c' is not a hexidecimal digit [0-9A-Fa-f], -1 is returned.
 * otherwise the converted value is returned.
 */
static int
hexchar2int(char c)
{
	if (c >= '0' && c <= '9') {
		return (c - '0');
	}
	if (c >= 'A' && c <= 'F') {
		return (c - 'A' + 10);
	}
	if (c >= 'a' && c <= 'f') {
		return (c - 'a' + 10);
	}
	return (-1);
}

static int
adj_substring_filter(char *val)
{
	char		*nextstar;

	for (; val != NULL; val = nextstar) {
		if ((nextstar = find_star(val)) != NULL) {
			*nextstar++ = '\0';
		}

		if (*val != '\0') {
			if (unescape_filterval(val) < 0) {
				return (-1);
			}
		}
	}

	return (0);
}

/* ***** End of modified libldap.so.5 filter parser ***** */


/*
 * Walk filter, remove redundant parentheses in-line
 * verify that the filter is reasonable
 */
static int
validate_filter(ns_ldap_cookie_t *cookie)
{
	char			*filter = cookie->filter;
	int			rc;

	/* Parse filter looking for illegal values */

	rc = adj_filter(filter);
	if (rc != 0) {
		return (NS_LDAP_OP_FAILED);
	}

	/* end of filter checking */

	return (NS_LDAP_SUCCESS);
}

/*
 * Set the account management request control that needs to be sent to server.
 * This control is required to get the account management information of
 * a user to do local account checking.
 */
static int
setup_acctmgmt_params(ns_ldap_cookie_t *cookie)
{
	LDAPControl	*req = NULL, **requestctrls;

	req = (LDAPControl *)malloc(sizeof (LDAPControl));

	if (req == NULL)
		return (NS_LDAP_MEMORY);

	/* fill in the fields of this new control */
	req->ldctl_iscritical = 1;
	req->ldctl_oid = strdup(NS_LDAP_ACCOUNT_USABLE_CONTROL);
	if (req->ldctl_oid == NULL) {
		free(req);
		return (NS_LDAP_MEMORY);
	}
	req->ldctl_value.bv_len = 0;
	req->ldctl_value.bv_val = NULL;

	requestctrls = (LDAPControl **)calloc(2, sizeof (LDAPControl *));
	if (requestctrls == NULL) {
		ldap_control_free(req);
		return (NS_LDAP_MEMORY);
	}

	requestctrls[0] = req;

	cookie->p_serverctrls = requestctrls;

	return (NS_LDAP_SUCCESS);
}

/*
 * int get_new_acct_more_info(BerElement *ber,
 *     AcctUsableResponse_t *acctResp)
 *
 * Decode the more_info data from an Account Management control response,
 * when the account is not usable and when code style is from recent LDAP
 * servers (see below comments for parse_acct_cont_resp_msg() to get more
 * details on coding styles and ASN1 description).
 *
 * Expected BER encoding: {tbtbtbtiti}
 *      +t: tag is 0
 *	+b: TRUE if inactive due to account inactivation
 *      +t: tag is 1
 * 	+b: TRUE if password has been reset
 *      +t: tag is 2
 * 	+b: TRUE if password is expired
 *	+t: tag is 3
 *	+i: contains num of remaining grace, 0 means no grace
 *	+t: tag is 4
 *	+i: contains num of seconds before auto-unlock. -1 means acct is locked
 *		forever (i.e. until reset)
 *
 * Asumptions:
 * - ber is not null
 * - acctResp is not null and is initialized with default values for the
 *   fields in its AcctUsableResp.more_info structure
 * - the ber stream is received in the correct order, per the ASN1 description.
 *   We do not check this order and make the asumption that it is correct.
 *   Note that the ber stream may not (and will not in most cases) contain
 *   all fields.
 */
static int
get_new_acct_more_info(BerElement *ber, AcctUsableResponse_t *acctResp)
{
	int		rc = NS_LDAP_SUCCESS;
	char		errstr[MAXERROR];
	ber_tag_t	rTag = LBER_DEFAULT;
	ber_len_t	rLen = 0;
	ber_int_t	rValue;
	char		*last;
	int		berRC = 0;

	/*
	 * Look at what more_info BER element is/are left to be decoded.
	 * look at each of them 1 by 1, without checking on their order
	 * and possible multi values.
	 */
	for (rTag = ber_first_element(ber, &rLen, &last);
	    rTag != LBER_END_OF_SEQORSET;
	    rTag = ber_next_element(ber, &rLen, last)) {

		berRC = 0;
		switch (rTag) {
		case 0 | LBER_CLASS_CONTEXT | LBER_PRIMITIVE:
			/* inactive */
			berRC = ber_scanf(ber, "b", &rValue);
			if (berRC != LBER_ERROR) {
				(acctResp->AcctUsableResp).more_info.
				    inactive = (rValue != 0) ? 1 : 0;
			}
			break;

		case 1 | LBER_CLASS_CONTEXT | LBER_PRIMITIVE:
			/* reset */
			berRC = ber_scanf(ber, "b", &rValue);
			if (berRC != LBER_ERROR) {
				(acctResp->AcctUsableResp).more_info.reset
				    = (rValue != 0) ? 1 : 0;
			}
			break;

		case 2 | LBER_CLASS_CONTEXT | LBER_PRIMITIVE:
			/* expired */
			berRC = ber_scanf(ber, "b", &rValue);
			if (berRC != LBER_ERROR) {
				(acctResp->AcctUsableResp).more_info.expired
				    = (rValue != 0) ? 1 : 0;
			}
			break;

		case 3 | LBER_CLASS_CONTEXT | LBER_PRIMITIVE:
			/* remaining grace */
			berRC = ber_scanf(ber, "i", &rValue);
			if (berRC != LBER_ERROR) {
				(acctResp->AcctUsableResp).more_info.rem_grace
				    = rValue;
			}
			break;

		case 4 | LBER_CLASS_CONTEXT | LBER_PRIMITIVE:
			/* seconds before unlock */
			berRC = ber_scanf(ber, "i", &rValue);
			if (berRC != LBER_ERROR) {
				(acctResp->AcctUsableResp).more_info.
				    sec_b4_unlock = rValue;
			}
			break;

		default :
			(void) sprintf(errstr,
			    gettext("invalid reason tag 0x%x"), rTag);
			syslog(LOG_DEBUG, "libsldap: %s", errstr);
			rc = NS_LDAP_INTERNAL;
			break;
		}
		if (berRC == LBER_ERROR) {
			(void) sprintf(errstr,
			    gettext("error 0x%x decoding value for "
			    "tag 0x%x"), berRC, rTag);
			syslog(LOG_DEBUG, "libsldap: %s", errstr);
			rc = NS_LDAP_INTERNAL;
		}
		if (rc != NS_LDAP_SUCCESS) {
			/* exit the for loop */
			break;
		}
	}

	return (rc);
}

/*
 * int get_old_acct_opt_more_info(BerElement *ber,
 *     AcctUsableResponse_t *acctResp)
 *
 * Decode the optional more_info data from an Account Management control
 * response, when the account is not usable and when code style is from LDAP
 * server 5.2p4 (see below comments for parse_acct_cont_resp_msg() to get more
 * details on coding styles and ASN1 description).
 *
 * Expected BER encoding: titi}
 *	+t: tag is 2
 *	+i: contains num of remaining grace, 0 means no grace
 *	+t: tag is 3
 *	+i: contains num of seconds before auto-unlock. -1 means acct is locked
 *		forever (i.e. until reset)
 *
 * Asumptions:
 * - ber is a valid BER element
 * - acctResp is initialized for the fields in its AcctUsableResp.more_info
 *   structure
 */
static int
get_old_acct_opt_more_info(ber_tag_t tag, BerElement *ber,
    AcctUsableResponse_t *acctResp)
{
	int		rc = NS_LDAP_SUCCESS;
	char		errstr[MAXERROR];
	ber_len_t	len;
	int		rem_grace, sec_b4_unlock;

	switch (tag) {
	case 2:
		/* decode and maybe 3 is following */
		if ((tag = ber_scanf(ber, "i", &rem_grace)) == LBER_ERROR) {
			(void) sprintf(errstr, gettext("Can not get "
			    "rem_grace"));
			syslog(LOG_DEBUG, "libsldap: %s", errstr);
			rc = NS_LDAP_INTERNAL;
			break;
		}
		(acctResp->AcctUsableResp).more_info.rem_grace = rem_grace;

		if ((tag = ber_peek_tag(ber, &len)) == LBER_ERROR) {
			/* this is a success case, break to exit */
			(void) sprintf(errstr, gettext("No more "
			    "optional data"));
			syslog(LOG_DEBUG, "libsldap: %s", errstr);
			break;
		}

		if (tag == 3) {
			if (ber_scanf(ber, "i", &sec_b4_unlock) == LBER_ERROR) {
				(void) sprintf(errstr,
				    gettext("Can not get sec_b4_unlock "
				    "- 1st case"));
				syslog(LOG_DEBUG, "libsldap: %s", errstr);
				rc = NS_LDAP_INTERNAL;
				break;
			}
			(acctResp->AcctUsableResp).more_info.sec_b4_unlock =
			    sec_b4_unlock;
		} else { /* unknown tag */
			(void) sprintf(errstr, gettext("Unknown tag "
			    "- 1st case"));
			syslog(LOG_DEBUG, "libsldap: %s", errstr);
			rc = NS_LDAP_INTERNAL;
			break;
		}
		break;

	case 3:
		if (ber_scanf(ber, "i", &sec_b4_unlock) == LBER_ERROR) {
			(void) sprintf(errstr, gettext("Can not get "
			    "sec_b4_unlock - 2nd case"));
			syslog(LOG_DEBUG, "libsldap: %s", errstr);
			rc = NS_LDAP_INTERNAL;
			break;
		}
		(acctResp->AcctUsableResp).more_info.sec_b4_unlock =
		    sec_b4_unlock;
		break;

	default: /* unknown tag */
		(void) sprintf(errstr, gettext("Unknown tag - 2nd case"));
		syslog(LOG_DEBUG, "libsldap: %s", errstr);
		rc = NS_LDAP_INTERNAL;
		break;
	}

	return (rc);
}

/*
 * **** This function needs to be moved to libldap library ****
 * parse_acct_cont_resp_msg() parses the message received by server according to
 * following format (ASN1 notation):
 *
 *	ACCOUNT_USABLE_RESPONSE::= CHOICE {
 *		is_available		[0] INTEGER,
 *				** seconds before expiration **
 *		is_not_available	[1] more_info
 *	}
 *	more_info::= SEQUENCE {
 *		inactive		[0] BOOLEAN DEFAULT FALSE,
 *		reset			[1] BOOLEAN DEFAULT FALSE,
 *		expired			[2] BOOLEAN DEFAULT FALSE,
 *		remaining_grace		[3] INTEGER OPTIONAL,
 *		seconds_before_unlock	[4] INTEGER OPTIONAL
 *	}
 */
/*
 * #define used to make the difference between coding style as done
 * by LDAP server 5.2p4 and newer LDAP servers. There are 4 values:
 * - DS52p4_USABLE: 5.2p4 coding style, account is usable
 * - DS52p4_NOT_USABLE: 5.2p4 coding style, account is not usable
 * - NEW_USABLE: newer LDAP servers coding style, account is usable
 * - NEW_NOT_USABLE: newer LDAP servers coding style, account is not usable
 *
 * An account would be considered not usable if for instance:
 * - it's been made inactive in the LDAP server
 * - or its password was reset in the LDAP server database
 * - or its password expired
 * - or the account has been locked, possibly forever
 */
#define	DS52p4_USABLE		0x00
#define	DS52p4_NOT_USABLE	0x01
#define	NEW_USABLE		0x00 | LBER_CLASS_CONTEXT | LBER_PRIMITIVE
#define	NEW_NOT_USABLE		0x01 | LBER_CLASS_CONTEXT | LBER_CONSTRUCTED
static int
parse_acct_cont_resp_msg(LDAPControl **ectrls, AcctUsableResponse_t *acctResp)
{
	int		rc = NS_LDAP_SUCCESS;
	BerElement	*ber;
	ber_tag_t 	tag;
	ber_len_t	len;
	int		i;
	char		errstr[MAXERROR];
	/* used for any coding style when account is usable */
	int		seconds_before_expiry;
	/* used for 5.2p4 coding style when account is not usable */
	int		inactive, reset, expired;

	if (ectrls == NULL) {
		(void) sprintf(errstr, gettext("Invalid ectrls parameter"));
		syslog(LOG_DEBUG, "libsldap: %s", errstr);
		return (NS_LDAP_INVALID_PARAM);
	}

	for (i = 0; ectrls[i] != NULL; i++) {
		if (strcmp(ectrls[i]->ldctl_oid, NS_LDAP_ACCOUNT_USABLE_CONTROL)
		    == 0) {
			break;
		}
	}

	if (ectrls[i] == NULL) {
		/* Ldap control is not found */
		(void) sprintf(errstr, gettext("Account Usable Control "
		    "not found"));
		syslog(LOG_DEBUG, "libsldap: %s", errstr);
		return (NS_LDAP_NOTFOUND);
	}

	/* Allocate a BER element from the control value and parse it. */
	if ((ber = ber_init(&ectrls[i]->ldctl_value)) == NULL)
		return (NS_LDAP_MEMORY);

	if ((tag = ber_peek_tag(ber, &len)) == LBER_ERROR) {
		/* Ldap decoding error */
		(void) sprintf(errstr, gettext("Error decoding 1st tag"));
		syslog(LOG_DEBUG, "libsldap: %s", errstr);
		ber_free(ber, 1);
		return (NS_LDAP_INTERNAL);
	}

	switch (tag) {
	case DS52p4_USABLE:
	case NEW_USABLE:
		acctResp->choice = 0;
		if (ber_scanf(ber, "i", &seconds_before_expiry)
		    == LBER_ERROR) {
			/* Ldap decoding error */
			(void) sprintf(errstr, gettext("Can not get "
			    "seconds_before_expiry"));
			syslog(LOG_DEBUG, "libsldap: %s", errstr);
			rc = NS_LDAP_INTERNAL;
			break;
		}
		/* ber_scanf() succeeded */
		(acctResp->AcctUsableResp).seconds_before_expiry =
		    seconds_before_expiry;
		break;

	case DS52p4_NOT_USABLE:
		acctResp->choice = 1;
		if (ber_scanf(ber, "{bbb", &inactive, &reset, &expired)
		    == LBER_ERROR) {
			/* Ldap decoding error */
			(void) sprintf(errstr, gettext("Can not get "
			    "inactive/reset/expired"));
			syslog(LOG_DEBUG, "libsldap: %s", errstr);
			rc = NS_LDAP_INTERNAL;
			break;
		}
		/* ber_scanf() succeeded */
		(acctResp->AcctUsableResp).more_info.inactive =
		    ((inactive == 0) ? 0 : 1);
		(acctResp->AcctUsableResp).more_info.reset =
		    ((reset == 0) ? 0 : 1);
		(acctResp->AcctUsableResp).more_info.expired =
		    ((expired == 0) ? 0 : 1);
		(acctResp->AcctUsableResp).more_info.rem_grace = 0;
		(acctResp->AcctUsableResp).more_info.sec_b4_unlock = 0;

		if ((tag = ber_peek_tag(ber, &len)) == LBER_ERROR) {
			/* this is a success case, break to exit */
			(void) sprintf(errstr, gettext("No optional data"));
			syslog(LOG_DEBUG, "libsldap: %s", errstr);
			break;
		}

		/*
		 * Look at what optional more_info BER element is/are
		 * left to be decoded.
		 */
		rc = get_old_acct_opt_more_info(tag, ber, acctResp);
		break;

	case NEW_NOT_USABLE:
		acctResp->choice = 1;
		/*
		 * Recent LDAP servers won't code more_info data for default
		 * values (see above comments on ASN1 description for what
		 * fields have default values & what fields are optional).
		 */
		(acctResp->AcctUsableResp).more_info.inactive = 0;
		(acctResp->AcctUsableResp).more_info.reset = 0;
		(acctResp->AcctUsableResp).more_info.expired = 0;
		(acctResp->AcctUsableResp).more_info.rem_grace = 0;
		(acctResp->AcctUsableResp).more_info.sec_b4_unlock = 0;

		if (len == 0) {
			/*
			 * Nothing else to decode; this is valid and we
			 * use default values set above.
			 */
			(void) sprintf(errstr, gettext("more_info is "
			    "empty, using default values"));
			syslog(LOG_DEBUG, "libsldap: %s", errstr);
			break;
		}

		/*
		 * Look at what more_info BER element is/are left to
		 * be decoded.
		 */
		rc = get_new_acct_more_info(ber, acctResp);
		break;

	default:
		(void) sprintf(errstr, gettext("unknwon coding style "
		    "(tag: 0x%x)"), tag);
		syslog(LOG_DEBUG, "libsldap: %s", errstr);
		rc = NS_LDAP_INTERNAL;
		break;
	}

	ber_free(ber, 1);
	return (rc);
}

/*
 * internal function for __ns_ldap_getAcctMgmt()
 */
static int
getAcctMgmt(const char *user, AcctUsableResponse_t *acctResp,
	ns_conn_user_t *conn_user)
{
	int		scope, rc;
	char		ldapfilter[1024];
	ns_ldap_cookie_t	*cookie;
	ns_ldap_search_desc_t	**sdlist = NULL;
	ns_ldap_search_desc_t	*dptr;
	ns_ldap_error_t		*error = NULL;
	char			**dns = NULL;
	char		service[] = "shadow";

	if (user == NULL || acctResp == NULL)
		return (NS_LDAP_INVALID_PARAM);

	/* Initialize State machine cookie */
	cookie = init_search_state_machine();
	if (cookie == NULL)
		return (NS_LDAP_MEMORY);
	cookie->conn_user = conn_user;

	/* see if need to follow referrals */
	rc = __s_api_toFollowReferrals(0,
	    &cookie->followRef, &error);
	if (rc != NS_LDAP_SUCCESS) {
		(void) __ns_ldap_freeError(&error);
		goto out;
	}

	/* get the service descriptor - or create a default one */
	rc = __s_api_get_SSD_from_SSDtoUse_service(service,
	    &sdlist, &error);
	if (rc != NS_LDAP_SUCCESS) {
		(void) __ns_ldap_freeError(&error);
		goto out;
	}

	if (sdlist == NULL) {
		/* Create default service Desc */
		sdlist = (ns_ldap_search_desc_t **)calloc(2,
		    sizeof (ns_ldap_search_desc_t *));
		if (sdlist == NULL) {
			rc = NS_LDAP_MEMORY;
			goto out;
		}
		dptr = (ns_ldap_search_desc_t *)
		    calloc(1, sizeof (ns_ldap_search_desc_t));
		if (dptr == NULL) {
			free(sdlist);
			rc = NS_LDAP_MEMORY;
			goto out;
		}
		sdlist[0] = dptr;

		/* default base */
		rc = __s_api_getDNs(&dns, service, &cookie->errorp);
		if (rc != NS_LDAP_SUCCESS) {
			if (dns) {
				__s_api_free2dArray(dns);
				dns = NULL;
			}
			(void) __ns_ldap_freeError(&(cookie->errorp));
			cookie->errorp = NULL;
			goto out;
		}
		dptr->basedn = strdup(dns[0]);
		if (dptr->basedn == NULL) {
			free(sdlist);
			free(dptr);
			if (dns) {
				__s_api_free2dArray(dns);
				dns = NULL;
			}
			rc = NS_LDAP_MEMORY;
			goto out;
		}
		__s_api_free2dArray(dns);
		dns = NULL;

		/* default scope */
		scope = 0;
		rc = __s_api_getSearchScope(&scope, &cookie->errorp);
		dptr->scope = scope;
	}

	cookie->sdlist = sdlist;

	cookie->service = strdup(service);
	if (cookie->service == NULL) {
		rc = NS_LDAP_MEMORY;
		goto out;
	}

	/* search for entries for this particular uid */
	(void) snprintf(ldapfilter, sizeof (ldapfilter), "(uid=%s)", user);
	cookie->i_filter = strdup(ldapfilter);
	if (cookie->i_filter == NULL) {
		rc = NS_LDAP_MEMORY;
		goto out;
	}

	/* create the control request */
	if ((rc = setup_acctmgmt_params(cookie)) != NS_LDAP_SUCCESS)
		goto out;

	/* Process search */
	rc = search_state_machine(cookie, GET_ACCT_MGMT_INFO, 0);

	/* Copy results back to user */
	rc = cookie->err_rc;
	if (rc != NS_LDAP_SUCCESS)
			(void) __ns_ldap_freeError(&(cookie->errorp));

	if (cookie->result == NULL)
			goto out;

	if ((rc = parse_acct_cont_resp_msg(cookie->resultctrl, acctResp))
	    != NS_LDAP_SUCCESS)
		goto out;

	rc = NS_LDAP_SUCCESS;

out:
	delete_search_cookie(cookie);

	return (rc);
}

/*
 * __ns_ldap_getAcctMgmt() is called from pam account management stack
 * for retrieving accounting information of users with no user password -
 * eg. rlogin, rsh, etc. This function uses the account management control
 * request to do a search on the server for the user in question. The
 * response control returned from the server is got from the cookie.
 * Input params: username of whose account mgmt information is to be got
 *		 pointer to hold the parsed account management information
 * Return values: NS_LDAP_SUCCESS on success or appropriate error
 *		code on failure
 */
int
__ns_ldap_getAcctMgmt(const char *user, AcctUsableResponse_t *acctResp)
{
	ns_conn_user_t	*cu = NULL;
	int		try_cnt = 0;
	int		rc = NS_LDAP_SUCCESS;
	ns_ldap_error_t	*error = NULL;

	for (;;) {
		if (__s_api_setup_retry_search(&cu, NS_CONN_USER_SEARCH,
		    &try_cnt, &rc, &error) == 0)
			break;
		rc = getAcctMgmt(user, acctResp, cu);
	}
	return (rc);
}
