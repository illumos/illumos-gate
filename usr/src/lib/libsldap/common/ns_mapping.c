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
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdlib.h>
#include <strings.h>
#include <ctype.h>
#include <locale.h>
#include <syslog.h>
#include "ns_internal.h"

/*
 * Calculate a hash for a string
 * Based on elf_hash algorithm, hash is case insensitive
 * Uses tolower instead of _tolower because of I18N
 */

static unsigned long
ns_hash(const char *str)
{
	unsigned int	hval = 0;

	while (*str) {
		unsigned int	g;

		hval = (hval << 4) + tolower(*str++);
		if ((g = (hval & 0xf0000000)) != 0)
			hval ^= g >> 24;
		hval &= ~g;
	}
	return ((unsigned long)hval);
}

/*
 * Scan a hash table hit for a matching hash entry.
 * Assume service and str are non-NULL.
 */

static ns_hash_t *
ns_scan_hash(ns_hashtype_t type, const char *service,
    const char *str, ns_hash_t *idx)
{
	while (idx) {
		if (idx->h_type == type &&
		    strcasecmp(service, idx->h_map->service) == 0 &&
		    strcasecmp(str, idx->h_map->orig) == 0) {
			return (idx);
		}
		idx = idx->h_next;
	}
	return ((ns_hash_t *)NULL);
}

/*
 * Find an entry in the hash table
 */

static ns_hash_t *
ns_get_hash(const ns_config_t *config,
    ns_hashtype_t type, const char *service, const char *str)
{
	ns_hash_t	*idx, *hashp;
	unsigned long	hash;

	if (config == NULL || service == NULL || str == NULL)
		return (NULL);

	hash = ns_hash(str) % NS_HASH_MAX;
	idx = config->hashTbl[hash];
	hashp = ns_scan_hash(type, service, str, idx);

	return (hashp);
}

/*
 * free a map entry
 */

static void
ns_free_map(ns_mapping_t *mapp)
{
	char	**ptr;

	if (mapp == NULL)
		return;
	if (mapp->service) {
		free(mapp->service);
		mapp->service = NULL;
	}
	if (mapp->orig) {
		free(mapp->orig);
		mapp->orig = NULL;
	}
	if (mapp->map) {
		for (ptr = mapp->map; *ptr; ptr++)
			free(*ptr);
		free(mapp->map);
		mapp->map = NULL;
	}
	free(mapp);
}

/*
 * Remove a hash table entry.
 * This function is not MT safe.
 */

static ns_hash_t *
ns_free_hash(ns_hash_t *p)
{
	ns_mapping_t	*map;
	ns_hash_t	*next;

	map = p->h_map;
	next = p->h_next;
	ns_free_map(map);
	free(p);
	return (next);
}

/*
 * destroy the hash table.
 * This function is not MT safe.
 */

void
__s_api_destroy_hash(ns_config_t *config)
{
	ns_hash_t	*next;
	int		i;

	if (config == NULL)
		return;
	for (i = 0; i < NS_HASH_MAX; i++) {
		next = config->hashTbl[i];
		while (next != NULL) {
			next = ns_free_hash(next);
		}
		config->hashTbl[i] = NULL;
	}
}

/*
 * Add a hash entry to the hash table.
 * This function is not MT safe.
 * Assume map, map->orig, map->service are non-NULL.
 */

int
__s_api_add_map2hash(ns_config_t *config, ns_hashtype_t type,
    ns_mapping_t *map)
{
	ns_hash_t	*idx, *newp;
	unsigned long	hash;

	if (config == NULL)
		return (NS_HASH_RC_CONFIG_ERROR);

	hash = ns_hash(map->orig) % NS_HASH_MAX;
	idx = config->hashTbl[hash];
	if (idx != NULL &&
	    ns_scan_hash(type, map->service, map->orig, idx) != NULL) {
		return (NS_HASH_RC_EXISTED);
	}

	newp = (ns_hash_t *)malloc(sizeof (ns_hash_t));
	if (newp == NULL)
		return (NS_HASH_RC_NO_MEMORY);
	newp->h_type = type;
	newp->h_map = map;
	newp->h_next = idx;
	config->hashTbl[hash] = newp;
	newp->h_llnext = config->llHead;
	config->llHead = newp;
	return (NS_HASH_RC_SUCCESS);
}


/*
 * Parse an attribute map string.
 * Assume space is the only legal whitespace.
 * attributeMap syntax:
 * attributeMap      = serviceId ":" origAttribute "="
 * 			attributes
 * origAttribute     = attribute
 * attributes        = wattribute *( space wattribute )
 * wattribute        = whsp newAttribute whsp
 * newAttribute      = descr | "*NULL*"
 * attribute         = descr
 *
 * objectclassMap syntax:
 * objectclassMap    = serviceId ":" origObjectclass "="
 * 			objectclass
 * origObjectclass   = objectclass
 * objectclass       = keystring
 */

int
__s_api_parse_map(char *cp, char **sid, char **origA, char ***mapA)
{
	char	*sptr, *dptr, **mapp;
	int	i, max;

	*sid = NULL;
	*origA = NULL;
	*mapA = NULL;

	sptr = cp;
	dptr = strchr(sptr, COLONTOK);
	if (dptr == NULL)
		return (NS_HASH_RC_SYNTAX_ERROR);
	i = dptr - sptr + 1;
	*sid = (char *)malloc(i);
	if (*sid == NULL)
		return (NS_HASH_RC_NO_MEMORY);
	(void) strlcpy(*sid, sptr, i);
	sptr = dptr+1;

	dptr = strchr(sptr, TOKENSEPARATOR);
	if (dptr == NULL) {
		free(*sid);
		*sid = NULL;
		return (NS_HASH_RC_SYNTAX_ERROR);
	}
	i = dptr - sptr + 1;
	*origA = (char *)malloc(i);
	if (*origA == NULL) {
		free(*sid);
		*sid = NULL;
		return (NS_HASH_RC_NO_MEMORY);
	}
	(void) strlcpy(*origA, sptr, i);
	sptr = dptr+1;

	max = 1;
	for (dptr = sptr; *dptr; dptr++) {
		if (*dptr == SPACETOK) {
			max++;
			while (*(dptr+1) == SPACETOK)
				dptr++;
		}
	}
	*mapA = (char **)calloc(max+1, sizeof (char *));
	if (*mapA == NULL) {
		free(*sid);
		*sid = NULL;
		free(*origA);
		*origA = NULL;
		return (NS_HASH_RC_NO_MEMORY);
	}
	mapp = *mapA;

	while (*sptr) {
		while (*sptr == SPACETOK)
			sptr++;
		dptr = sptr;
		while (*dptr && *dptr != SPACETOK)
			dptr++;
		i = dptr - sptr + 1;
		*mapp = (char *)malloc(i);
		if (*mapp == NULL) {
			free(*sid);
			*sid = NULL;
			free(*origA);
			*origA = NULL;
			__s_api_free2dArray(*mapA);
			*mapA = NULL;
			return (NS_HASH_RC_NO_MEMORY);
		}
		(void) strlcpy(*mapp, sptr, i);
		mapp++;
		sptr = dptr;
	}
	return (NS_HASH_RC_SUCCESS);
}


static void
__ns_ldap_freeASearchDesc(ns_ldap_search_desc_t *ptr)
{
	if (ptr == NULL)
		return;
	if (ptr->basedn)
		free(ptr->basedn);
	if (ptr->filter)
		free(ptr->filter);
	free(ptr);
}

/*
 * Parse a service descriptor
 * and create a service descriptor struct
 * SD Format:
 *    serviceid:[base][?[scope][?[filter]]];[[base][?[scope][?[filter]]]]
 * desc format:
 *    [base][?[scope][?[filter]]]
 */

typedef enum _ns_parse_state {
	P_ERROR, P_INIT, P_BASEDN, P_SCOPE,
	P_INIFILTER, P_FILTER, P_END, P_EXIT, P_MEMERR
} _ns_parse_state_t;

static
int
__s_api_parseASearchDesc(const char *service,
    char **cur, ns_ldap_search_desc_t **ret)
{
	ns_ldap_search_desc_t	*ptr;
	char			*sptr, *dptr;
	int			i, rc;
	ns_ldap_error_t		**errorp = NULL;
	ns_ldap_error_t		*error = NULL;
	void			**paramVal = NULL;
	char			**dns = NULL;
	_ns_parse_state_t	state = P_INIT;
	int			quoted = 0;
	int			wasquoted = 0;
	int			empty = 1;

	if (ret == NULL)
		return (NS_LDAP_INVALID_PARAM);
	*ret = NULL;
	if (cur == NULL)
		return (NS_LDAP_INVALID_PARAM);

	ptr = (ns_ldap_search_desc_t *)
	    calloc(1, sizeof (ns_ldap_search_desc_t));
	if (ptr == NULL)
		return (NS_LDAP_MEMORY);

	sptr = *cur;

	/* Get the default scope */
	if ((rc = __ns_ldap_getParam(NS_LDAP_SEARCH_SCOPE_P,
	    &paramVal, errorp)) != NS_LDAP_SUCCESS) {
		(void) __ns_ldap_freeError(errorp);
		__ns_ldap_freeASearchDesc(ptr);
		ptr = NULL;
		return (NS_LDAP_MEMORY);
	}
	if (paramVal && *paramVal)
		ptr->scope = * (ScopeType_t *)(*paramVal);
	else
		ptr->scope = NS_LDAP_SCOPE_ONELEVEL;
	(void) __ns_ldap_freeParam(&paramVal);
	paramVal = NULL;

	for (/* none */; state != P_EXIT && sptr && *sptr; sptr++) {
		empty = 0;
		switch (state) {
		case P_INIT:
			if (*sptr == QUESTTOK) {
				/* No basedn */
				ptr->basedn = strdup("");
				if (!ptr->basedn) {
					state = P_MEMERR;
					break;
				}
				state = P_SCOPE;
				break;
			}
			if (*sptr == SEMITOK) {
				/* No SSD */
				ptr->basedn = strdup("");
				if (!ptr->basedn) {
					state = P_MEMERR;
					break;
				}
				state = P_EXIT;
				break;
			}
			/* prepare to copy DN */
			i = strlen(sptr) + 1;
			ptr->basedn = dptr = (char *)calloc(i, sizeof (char));
			if (!ptr->basedn) {
				state = P_MEMERR;
				break;
			}
			if (*sptr == BSLTOK) {
				if (*(sptr+1) == '\0') {
					/* error */
					state = P_ERROR;
					break;
				}
				if (*(sptr+1) == QUOTETOK ||
				    *(sptr+1) == BSLTOK) {
					/* escaped CHARS */
					sptr++;
				} else {
					*dptr++ = *sptr++;
				}
				*dptr++ = *sptr;
			} else if (*sptr == QUOTETOK) {
				quoted = 1;
				wasquoted = 1;
			} else {
				*dptr++ = *sptr;
			}
			state = P_BASEDN;
			break;
		case P_INIFILTER:
			if (*sptr == SEMITOK) {
				/* No filter and no more SSD */
				state = P_EXIT;
				break;
			}
			/* prepare to copy DN */
			i = strlen(sptr) + 1;
			ptr->filter = dptr = (char *)calloc(i, sizeof (char));
			if (!ptr->filter) {
				state = P_MEMERR;
				break;
			}
			if (*sptr == BSLTOK) {
				if (*(sptr+1) == '\0') {
					/* error */
					state = P_ERROR;
					break;
				}
				if (*(sptr+1) == QUOTETOK ||
				    *(sptr+1) == BSLTOK) {
					/* escaped CHARS */
					sptr++;
				} else {
					*dptr++ = *sptr++;
				}
				*dptr++ = *sptr;
			} else if (*sptr == QUOTETOK) {
				quoted = 1;
				wasquoted = 1;
			} else {
				*dptr++ = *sptr;
			}
			state = P_FILTER;
			break;
		case P_SCOPE:
			if (*sptr == SEMITOK) {
				/* no more SSD */
				state = P_EXIT;
				break;
			}
			if (strncasecmp(sptr, "base", 4) == 0) {
				sptr += 4;
				ptr->scope = NS_LDAP_SCOPE_BASE;
			} else if (strncasecmp(sptr, "one", 3) == 0) {
				ptr->scope = NS_LDAP_SCOPE_ONELEVEL;
				sptr += 3;
			} else if (strncasecmp(sptr, "sub", 3) == 0) {
				ptr->scope = NS_LDAP_SCOPE_SUBTREE;
				sptr += 3;
			}
			if (*sptr == '\0' || (*sptr == SEMITOK)) {
				/* no more SSD */
				state = P_EXIT;
				sptr--;
				break;
			}
			if (*sptr != QUESTTOK) {
				state = P_ERROR;
				break;
			}
			state = P_INIFILTER;
			quoted = 0;
			wasquoted = 0;
			break;
		case P_BASEDN:
		case P_FILTER:
			if (quoted) {
				/* Quoted */
				if (*sptr == BSLTOK) {
					if (*(sptr+1) == '\0') {
						state = P_ERROR;
						break;
					}
					if (*(sptr+1) == QUOTETOK ||
					    *(sptr+1) == BSLTOK) {
						/* escaped CHARS */
						sptr++;
					} else {
						*dptr++ = *sptr++;
					}
					/* fall through to char copy */
				} else if (*sptr == QUOTETOK) {
					/* end of string */
					*dptr = '\0';
					quoted = 0;
					break;
				}
				/* else fall through to char copy */
			} else {
				/* Unquoted */
				if (wasquoted && *sptr != QUESTTOK) {
					/* error  past end of quoted string */
					state = P_ERROR;
					break;
				}
				if (*sptr == BSLTOK) {
					if (*(sptr+1) == '\0') {
						state = P_ERROR;
						break;
					}
					if (*(sptr+1) == SEMITOK ||
					    *(sptr+1) == QUESTTOK ||
					    *(sptr+1) == QUOTETOK ||
					    *(sptr+1) == BSLTOK) {
						/* escaped chars */
						sptr++;
					}
					/* fall through to char copy */
				} else if (*sptr == QUOTETOK) {
					/* error */
					state = P_ERROR;
					break;
				} else if (*sptr == QUESTTOK) {
					/* if filter error */
					if (state == P_FILTER) {
						state = P_ERROR;
						break;
					}
					/* end of basedn goto scope */
					*dptr = '\0';
					state = P_SCOPE;
					break;
				} else if (*sptr == SEMITOK) {
					/* end of current SSD */
					*dptr = '\0';
					state = P_EXIT;
					break;
				}
			}
			/* normal character to copy */
			*dptr++ = *sptr;
			break;
		case P_END:
			if (*sptr == SEMITOK) {
				state = P_EXIT;
				break;
			}
			__ns_ldap_freeASearchDesc(ptr);
			ptr = NULL;
			*cur = NULL;
			return (NS_LDAP_CONFIG);
		default:	 /* error should never arrive here */
		case P_ERROR:
			__ns_ldap_freeASearchDesc(ptr);
			ptr = NULL;
			*cur = NULL;
			return (NS_LDAP_CONFIG);
		case P_MEMERR:
			__ns_ldap_freeASearchDesc(ptr);
			ptr = NULL;
			*cur = NULL;
			return (NS_LDAP_MEMORY);
		}
	}

	if (quoted) {
		__ns_ldap_freeASearchDesc(ptr);
		ptr = NULL;
		*cur = NULL;
		return (NS_LDAP_INVALID_PARAM);
	}

	if (empty || strlen(ptr->basedn) == 0) {
		if (ptr->basedn)
			free(ptr->basedn);
		/* get default base */
		rc = __s_api_getDNs(&dns, service, &error);
		if (rc != NS_LDAP_SUCCESS) {
			if (dns) {
				__s_api_free2dArray(dns);
				dns = NULL;
			}
			(void) __ns_ldap_freeError(&error);
			__ns_ldap_freeASearchDesc(ptr);
			ptr = NULL;
			return (NS_LDAP_MEMORY);
		}
		ptr->basedn = strdup(dns[0]);
		__s_api_free2dArray(dns);
		dns = NULL;
	}

	*cur = sptr;
	*ret = ptr;
	return (NS_LDAP_SUCCESS);
}


/*
 * Build up the service descriptor array
 */
#define	NS_SDESC_MAX	4

static int
__ns_ldap_saveSearchDesc(ns_ldap_search_desc_t ***sdlist,
    int *cnt, int *max, ns_ldap_search_desc_t *ret)
{
	ns_ldap_search_desc_t	**tmplist;

	if (*sdlist == NULL) {
		*cnt = 0;
		*max = NS_SDESC_MAX;
		*sdlist = (ns_ldap_search_desc_t **)
		    calloc(*max, sizeof (ns_ldap_search_desc_t *));
		if (*sdlist == NULL)
			return (-1);
	} else if (*cnt+1 >= *max) {
		*max += NS_SDESC_MAX;
		tmplist = (ns_ldap_search_desc_t **)
		    realloc((void *)(*sdlist),
		    *max * sizeof (ns_ldap_search_desc_t *));
		if (tmplist == NULL)
			return (-1);
		else
			*sdlist = tmplist;
	}
	(*sdlist)[*cnt] = ret;
	(*cnt)++;
	(*sdlist)[*cnt] = NULL;
	return (0);
}


/*
 * Exported Search Descriptor Routines
 */

int __ns_ldap_getSearchDescriptors(
	const char *service,
	ns_ldap_search_desc_t ***desc,
	ns_ldap_error_t **errorp)
{
	int			rc;
	int			slen;
	void			**param = NULL;
	void			**paramVal = NULL;
	char			**sdl, *srv, **sdl_save;
	char			errstr[2 * MAXERROR];
	ns_ldap_search_desc_t	**sdlist;
	int			cnt, max;
	int			vers;
	ns_config_t		*cfg;
	ns_ldap_search_desc_t 	*ret;

	if ((desc == NULL) || (errorp == NULL))
		return (NS_LDAP_INVALID_PARAM);

	*desc = NULL;
	*errorp = NULL;

	rc = __ns_ldap_getParam(NS_LDAP_SERVICE_SEARCH_DESC_P,
	    (void ***)&param, errorp);
	if (rc != NS_LDAP_SUCCESS) {
		return (rc);
	}
	sdl = (char **)param;
	cnt = 0;
	max = 0;
	sdlist = NULL;

	cfg = __s_api_get_default_config();

	if (cfg == NULL) {
		(void) snprintf(errstr, sizeof (errstr),
		    gettext("No configuration information available."));
		MKERROR(LOG_ERR, *errorp, NS_CONFIG_NOTLOADED, strdup(errstr),
		    NULL);
		return (NS_LDAP_CONFIG);
	}

	vers = cfg->version;
	__s_api_release_config(cfg);

	/* If using version1 or no sd's process SEARCH_DN if available */
	if (vers == NS_LDAP_V1 && param == NULL) {
		rc = __s_api_get_search_DNs_v1(&sdl, service, errorp);
		if (rc != NS_LDAP_SUCCESS || sdl == NULL) {
			return (rc);
		}
		sdl_save = sdl;
		/* Convert a SEARCH_DN to a search descriptor */
		for (; *sdl; sdl++) {
			ret = (ns_ldap_search_desc_t *)
			    calloc(1, sizeof (ns_ldap_search_desc_t));
			if (ret == NULL) {
				(void) __ns_ldap_freeSearchDescriptors(&sdlist);
				__s_api_free2dArray(sdl_save);
				return (NS_LDAP_MEMORY);
			}
			ret->basedn = strdup(*sdl);
			if (ret->basedn == NULL) {
				free(ret);
				(void) __ns_ldap_freeASearchDesc(ret);
				(void) __ns_ldap_freeSearchDescriptors(&sdlist);
				__s_api_free2dArray(sdl_save);
				return (NS_LDAP_MEMORY);
			}

			/* default scope */
			if ((rc = __ns_ldap_getParam(NS_LDAP_SEARCH_SCOPE_P,
			    &paramVal, errorp)) != NS_LDAP_SUCCESS) {
				(void) __ns_ldap_freeASearchDesc(ret);
				(void) __ns_ldap_freeSearchDescriptors(&sdlist);
				__s_api_free2dArray(sdl_save);
				return (rc);
			}
			if (paramVal && *paramVal)
				ret->scope = * (ScopeType_t *)(*paramVal);
			else
				ret->scope = NS_LDAP_SCOPE_ONELEVEL;
			(void) __ns_ldap_freeParam(&paramVal);
			paramVal = NULL;

			rc = __ns_ldap_saveSearchDesc(&sdlist, &cnt, &max, ret);
			if (rc < 0) {
				(void) __ns_ldap_freeASearchDesc(ret);
				(void) __ns_ldap_freeSearchDescriptors(&sdlist);
				__s_api_free2dArray(sdl_save);
				return (NS_LDAP_MEMORY);
			}
		}
		__s_api_free2dArray(sdl_save);
		*desc = sdlist;
		return (NS_LDAP_SUCCESS);
	}

	if (sdl == NULL || service == NULL) {
		(void) __ns_ldap_freeParam(&param);
		param = NULL;
		*desc = NULL;
		return (NS_LDAP_SUCCESS);
	}
	slen = strlen(service);

	/* Process the version2 sd's */
	for (; *sdl; sdl++) {
		srv = *sdl;
		if (strncasecmp(service, srv, slen) != 0)
			continue;
		srv += slen;
		if (*srv != COLONTOK)
			continue;
		srv++;
		while (srv != NULL && *srv != NULL) {
			/* Process 1 */
			rc = __s_api_parseASearchDesc(service, &srv, &ret);
			if (rc != NS_LDAP_SUCCESS) {
				(void) __ns_ldap_freeSearchDescriptors(&sdlist);
				(void) snprintf(errstr, (2 * MAXERROR), gettext(
				    "Invalid serviceSearchDescriptor (%s). "
				    "Illegal configuration"), *sdl);
				(void) __ns_ldap_freeParam(&param);
				param = NULL;
				MKERROR(LOG_ERR, *errorp, NS_CONFIG_SYNTAX,
				    strdup(errstr), NULL);
				return (rc);
			}
			if (ret != NULL) {
				rc = __ns_ldap_saveSearchDesc(
				    &sdlist, &cnt, &max, ret);
			}
			if (rc < 0) {
				(void) __ns_ldap_freeSearchDescriptors(&sdlist);
				(void) __ns_ldap_freeParam(&param);
				param = NULL;
				return (NS_LDAP_MEMORY);
			}
		}
	}

	(void) __ns_ldap_freeParam(&param);
	param = NULL;
	*desc = sdlist;
	return (NS_LDAP_SUCCESS);
}

int
__ns_ldap_freeSearchDescriptors(ns_ldap_search_desc_t ***desc)
{
	ns_ldap_search_desc_t **dptr;
	ns_ldap_search_desc_t *ptr;

	if (*desc == NULL)
		return (NS_LDAP_SUCCESS);
	for (dptr = *desc; (ptr = *dptr) != NULL; dptr++) {
		__ns_ldap_freeASearchDesc(ptr);
	}
	free(*desc);
	*desc = NULL;

	return (NS_LDAP_SUCCESS);
}




/*
 * Exported Attribute/Objectclass mapping functions.
 */

/*
 * This function is not supported.
 */
/* ARGSUSED */
int __ns_ldap_getAttributeMaps(
	const char *service,
	ns_ldap_attribute_map_t ***maps,
	ns_ldap_error_t **errorp)
{
	*maps = NULL;
	return (NS_LDAP_OP_FAILED);
}

int
__ns_ldap_freeAttributeMaps(ns_ldap_attribute_map_t ***maps)
{
	ns_ldap_attribute_map_t **dptr;
	ns_ldap_attribute_map_t *ptr;
	char **cpp, *cp;

	if (*maps == NULL)
		return (NS_LDAP_SUCCESS);
	for (dptr = *maps; (ptr = *dptr) != NULL; dptr++) {
		if (ptr->origAttr) {
			free(ptr->origAttr);
			ptr->origAttr = NULL;
		}
		if (ptr->mappedAttr) {
			for (cpp = ptr->mappedAttr; (cp = *cpp) != NULL; cpp++)
				free(cp);
			free(ptr->mappedAttr);
			ptr->mappedAttr = NULL;
		}
		free(ptr);
	}
	free(*maps);
	*maps = NULL;

	return (NS_LDAP_SUCCESS);
}

char **__ns_ldap_getMappedAttributes(
	const char *service,
	const char *origAttribute)
{
	ns_config_t	*ptr = __s_api_loadrefresh_config();
	ns_hash_t	*hp;
	char		**ret;

	if (ptr == NULL)
		return (NULL);

	hp = ns_get_hash(ptr, NS_HASH_AMAP, service, origAttribute);

	if (hp == NULL || hp->h_map == NULL)
		ret = NULL;
	else
		ret = __s_api_cp2dArray(hp->h_map->map);
	__s_api_release_config(ptr);
	return (ret);
}

char **__ns_ldap_getOrigAttribute(
	const char *service,
	const char *mappedAttribute)
{
	ns_config_t	*ptr = __s_api_loadrefresh_config();
	ns_hash_t	*hp;
	char		**ret;

	if (ptr == NULL)
		return (NULL);

	hp = ns_get_hash(ptr, NS_HASH_RAMAP, service, mappedAttribute);

	if (hp == NULL || hp->h_map == NULL)
		ret = NULL;
	else
		ret = __s_api_cp2dArray(hp->h_map->map);
	__s_api_release_config(ptr);
	return (ret);
}

/*
 * This function is not supported.
 */
/* ARGSUSED */
int __ns_ldap_getObjectClassMaps(
	const char *service,
	ns_ldap_objectclass_map_t ***maps,
	ns_ldap_error_t **errorp)
{
	*maps = NULL;
	return (NS_LDAP_OP_FAILED);
}

int
__ns_ldap_freeObjectClassMaps(ns_ldap_objectclass_map_t ***maps)
{
	ns_ldap_objectclass_map_t **dptr;
	ns_ldap_objectclass_map_t *ptr;

	if (*maps == NULL)
		return (NS_LDAP_SUCCESS);
	for (dptr = *maps; (ptr = *dptr) != NULL; dptr++) {
		if (ptr->origOC) {
			free(ptr->origOC);
			ptr->origOC = NULL;
		}
		if (ptr->mappedOC) {
			free(ptr->mappedOC);
			ptr->mappedOC = NULL;
		}
		free(ptr);
	}
	free(*maps);
	*maps = NULL;

	return (NS_LDAP_SUCCESS);
}

char **__ns_ldap_getMappedObjectClass(
	const char *service,
	const char *origObjectClass)
{
	ns_config_t	*ptr = __s_api_loadrefresh_config();
	ns_hash_t	*hp;
	char		**ret;

	if (ptr == NULL)
		return (NULL);

	hp = ns_get_hash(ptr, NS_HASH_OMAP, service, origObjectClass);

	if (hp == NULL || hp->h_map == NULL)
		ret = NULL;
	else
		ret = __s_api_cp2dArray(hp->h_map->map);
	__s_api_release_config(ptr);
	return (ret);
}

char **__ns_ldap_getOrigObjectClass(
	const char *service,
	const char *mappedObjectClass)
{
	ns_config_t	*ptr = __s_api_loadrefresh_config();
	ns_hash_t	*hp;
	char		**ret;

	if (ptr == NULL)
		return (NULL);

	hp = ns_get_hash(ptr, NS_HASH_ROMAP, service, mappedObjectClass);

	if (hp == NULL || hp->h_map == NULL)
		ret = NULL;
	else
		ret = __s_api_cp2dArray(hp->h_map->map);
	__s_api_release_config(ptr);
	return (ret);
}

char **__ns_ldap_mapAttributeList(
	const char *service,
	const char * const *origAttrList)
{
	const char * const *opp;
	char **cpp, **npp;
	int i;

	if (origAttrList == NULL)
		return (NULL);

	opp = origAttrList;
	for (i = 0; *opp; i++, opp++)
		;
	cpp = (char **)calloc(i+1, sizeof (char *));
	if (cpp == NULL)
		return (NULL);

	opp = origAttrList;
	for (i = 0; *opp; i++, opp++) {
		npp =  __ns_ldap_getMappedAttributes(service, *opp);
		if (npp && npp[0]) {
			cpp[i] = strdup(npp[0]);
			__s_api_free2dArray(npp);
			npp = NULL;
			if (cpp[i] == NULL) {
				__s_api_free2dArray(cpp);
				return (NULL);
			}
		} else {
			cpp[i] = strdup(*opp);
			if (cpp[i] == NULL) {
				__s_api_free2dArray(cpp);
				return (NULL);
			}
		}
	}
	return (cpp);
}

char *
__ns_ldap_mapAttribute(
	const char *service,
	const char *origAttr)
{
	char **npp;
	char *mappedAttr;

	if (origAttr == NULL)
		return (NULL);

	npp = __ns_ldap_getMappedAttributes(service, origAttr);
	if (npp && npp[0]) {
		mappedAttr = strdup(npp[0]);
		__s_api_free2dArray(npp);
	} else {
		mappedAttr = strdup(origAttr);
	}
	return (mappedAttr);
}
