/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2015 Gary Mills
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/systeminfo.h>
#include <strings.h>
#include <rpcsvc/nis.h>

#include "nis_parse_ldap_conf.h"

#include "ldap_attr.h"
#include "ldap_util.h"
#include "ldap_structs.h"


/*
 * If 'name' doesn't end in a trailing dot, return a copy with the
 * value of "nisplusLDAPbaseDomain" appended. Otherwise, return a
 * copy of 'name'. If deallocate!=0, free 'name'.
 */
char *
fullObjName(int deallocate, char *name) {
	int	l;
	char	*full;
	char	*myself = "fullObjName";

	if (name == 0)
		return (sdup(myself, T, proxyInfo.default_nis_domain));

	l = strlen(name);
	if (name[l-1] == '.') {
		full = sdup(myself, T, name);
	} else {
		full = scat(myself, T, scat(myself, F, name, "."),
			sdup(myself, T, proxyInfo.default_nis_domain));
	}
	if (deallocate)
		free(name);

	return (full);
}

/*
 * Convert a domain name ("x.y.z.", say) to a "dc=..." type LDAP equivalent
 * ("dc=x,dc=y,dx=z"). The domain name supplied MUST be terminated by a
 * trailing dot. If 'domain' is NULL, the value of "nisplusLDAPbaseDomain"
 * is converted.
 */
char *
domain2base(char *domain) {
	char	*base = 0;
	int	l, i;
	char	*myself = "domain2base";

	if (domain == 0)
		domain = sdup(myself, T, proxyInfo.default_nis_domain);
	if (domain == 0)
		return (0);

	for (l = 0, i = 0; domain[i] != '\0'; i++) {
		if (domain[i] == '.') {
			domain[i] = '\0';
			if (l != 0)
				base = scat(myself, T, base,
					scat(myself, F, ",dc=", &domain[l]));
			else
				base = scat(myself, T, base,
					scat(myself, F, "dc=", &domain[l]));
			l = i+1;
		}
	}

	return (base);
}

/*
 * If 'name' ends in a trailing comma, append the value of the
 * "defaultSearchBase". If deallocate!=0, free 'name'.
 */
char *
fullLDAPname(int deallocate, char *name) {
	int	err = 0;

	return (appendBase(name, proxyInfo.default_search_base, &err,
				deallocate));
}

/*
 * If the 'item' string ends in a comma, append 'base', and return
 * the result. On exit, '*err' will be zero if successful, non-zero
 * otherwise. If 'dealloc' is non-zero, 'item' is freed; this happens
 * even if an error status is returned.
 *
 * The return value is always allocated, and must be freed by the caller.
 */
char *
appendBase(char *item, char *base, int *err, int dealloc) {
	char	*new;
	int	len, deferr;
	char	*myself = "appendBase";

	/*
	 * Make sure that 'err' points to something valid, so that we can
	 * dispense with all those 'if (err != 0)'.
	 */
	if (err == 0)
		err = &deferr;

	/* Establish default (successful) error status */
	*err = 0;

	/* Trivial case 1: If 'item' is NULL, return a copy of 'base' */
	if (item == 0) {
		new = sdup(myself, T, base);
		if (new == 0)
			*err = -1;
		return (new);
	}

	/* Trivial case 2: If 'base' is NULL, return a copy of 'item' */
	if (base == 0) {
		new = sdup(myself, T, item);
		if (new == 0)
			*err = -1;
		if (dealloc)
			free(item);
		return (new);
	}

	len = strlen(item);

	/* If 'item' is the empty string, return a copy of 'base' */
	if (len <= 0) {
		new = sdup(myself, T, base);
		if (new == 0)
			*err = -1;
		if (dealloc)
			free(item);
		return (new);
	}

	/*
	 * If 'item' ends in a comma, append 'base', and return a copy
	 * of the result. Otherwise, return a copy of 'item'.
	 */
	if (item[len-1] == ',') {
		int	blen = slen(base);
		new = am(myself, len + blen + 1);
		if (new != 0) {
			(void) memcpy(new, item, len);
			(void) memcpy(&new[len], base, blen);
		} else {
			*err = -1;
		}
	} else {
		new = sdup(myself, T, item);
		if (new == 0)
			*err = -1;
	}

	if (dealloc)
		free(item);

	return (new);
}

/*
 * Despite its general-sounding name, this function only knows how to
 * turn a list of attributes ("a,b,c") into an AND filter ("(&(a)(b)(c))").
 */
char *
makeFilter(char *attr) {
	int	len, s, e, c;
	char	*str, *filter, *tmp;
	char	*myself = "makeFilter";

	if (attr == 0 || (len = strlen(attr)) == 0)
		return (0);

	/* Assume already of appropriate form if first char is '(' */
	if (len > 1 && attr[0] == '(' && attr[len-1] == ')')
		return (sdup(myself, T, attr));

	str = sdup(myself, T, attr);
	if (str == 0)
		return (0);
	filter = sdup(myself, T, "(&");
	if (filter == 0) {
		free(str);
		return (0);
	}
	for (s = c = 0; s < len; s = e+1) {
		/* Skip blank space, if any */
		for (; str[s] == ' ' || str[s] == '\t'; s++);
		/* Find delimiter (comma) or end of string */
		for (e = s; str[e] != '\0' && str[e] != ','; e++);
		str[e] = '\0';
		tmp = scat(myself, T, sdup(myself, T, "("),
			scat(myself, F, &str[s], ")"));
		if (tmp == 0) {
			sfree(filter);
			return (0);
		}
		c++;
		filter = scat(myself, T, filter, tmp);
	}

	/*
	 * If there's just one component, we return it as is. This
	 * means we avoid turning "objectClass=posixAccount" into
	 * "(&(objectClass=posixAccount))".
	 */
	if (c == 1) {
		sfree(filter);
		return (str);
	}

	/* Add the closing ')' */
	tmp = filter;
	filter = scat(myself, F, tmp, ")");
	sfree(tmp);

	free(str);

	return (filter);
}

/*
 * Split an AND-filter string into components.
 */
char **
makeFilterComp(char *filter, int *numComps) {
	int	nc = 0, s, e, i;
	char	**comp = 0, **new, *str;
	int	len;
	char	*myself = "makeFilterComp";

	if ((len = slen(filter)) <= 0)
		return (0);

	/* Is it just a plain "attr=val" string ? If so, return a copy */
	if (len <= 2 || filter[0] != '(') {
		comp = am(myself, 2 * sizeof (comp[0]));
		if (comp == 0)
			return (0);
		comp[0] = sdup(myself, T, filter);
		if (comp[0] == 0) {
			sfree(comp);
			return (0);
		}
		if (numComps != 0)
			*numComps = 1;
		return (comp);
	}

	if (filter != 0 && (len = strlen(filter)) != 0 && len > 2 &&
			filter[0] == '(' && filter[1] == '&' &&
			filter[len-1] == ')') {
		str = sdup(myself, T, filter);
		if (str == 0)
			return (0);
		for (s = 2; s < len; s = e+1) {
			/* Skip past the '(' */
			for (; s < len && str[s] != '('; s++);
			s++;
			if (s >= len)
				break;
			for (e = s; str[e] != '\0' && str[e] != ')'; e++);
			str[e] = '\0';
			new = realloc(comp, (nc+1) * sizeof (comp[nc]));
			if (new == 0) {
				if (comp != 0) {
					for (i = 0; i < nc; i++)
						sfree(comp[i]);
					free(comp);
					comp = 0;
				}
				nc = 0;
				break;
			}
			comp = new;
			comp[nc] = sdup(myself, T, &str[s]);
			if (comp[nc] == 0) {
				for (i = 0; i < nc; i++)
					sfree(comp[i]);
				sfree(comp);
				comp = 0;
				nc = 0;
				break;
			}
			nc++;
		}
		sfree(str);
	}

	if (numComps != 0)
		*numComps = nc;

	return (comp);
}

void
freeFilterComp(char **comp, int numComps) {
	int	i;

	if (comp == 0)
		return;

	for (i = 0; i < numComps; i++) {
		sfree(comp[i]);
	}
	free(comp);
}

char **
addFilterComp(char *new, char **comp, int *numComps) {
	char	**tmp, *str;
	char	*myself = "addFilterComp";

	if (new == 0 || numComps == 0 || *numComps < 0)
		return (comp);

	str = sdup(myself, T, new);
	if (str == 0)
		return (0);
	tmp = realloc(comp, ((*numComps)+1) * sizeof (comp[0]));
	if (tmp == 0) {
		sfree(str);
		return (0);
	}

	comp = tmp;
	comp[*numComps] = str;
	*numComps += 1;

	return (comp);
}

char *
concatenateFilterComps(int numComps, char **comp) {
	int		i;
	__nis_buffer_t	b = {0, 0};
	char		*myself = "concatenateFilterComps";

	if (numComps == 0 || comp == 0)
		return (0);

	bp2buf(myself, &b, "(&");
	for (i = 0; i < numComps; i++) {
		if (comp[i] == 0)
			continue;
		bp2buf(myself, &b, "(%s)", comp[i]);
	}
	bp2buf(myself, &b, ")");

	return (b.buf);
}

void
freeDNs(char **dn, int numDN) {
	int	i;

	if (dn == 0)
		return;

	for (i = 0; i < numDN; i++) {
		sfree(dn[i]);
	}
	sfree(dn);
}

/*
 * Search the supplied rule-value structure array for any attributes called
 * "dn", and return their values. If the "dn" value(s) end in a comma, they
 * get the 'defBase' value appended.
 */
char **
findDNs(char *msg, __nis_rule_value_t *rv, int nrv, char *defBase,
		int *numDN) {
	char	**dn;
	int	irv, iv, ndn;
	char	*myself = "findDNs";

	if (rv == 0 || nrv <= 0 || numDN == 0)
		return (0);

	if (msg == 0)
		msg = myself;

	/* Avoid realloc() by pre-allocating 'dn' at maximum size */
	dn = am(msg, nrv * sizeof (dn[0]));
	if (dn == 0)
		return (0);

	for (ndn = 0, irv = 0; irv < nrv; irv++) {
		for (iv = 0; iv < rv[irv].numAttrs; iv++) {
			/* Looking for string-valued attribute called "dn" */
			if (rv[irv].attrName[iv] != 0 &&
				rv[irv].attrVal[iv].type == vt_string &&
				rv[irv].attrVal[iv].numVals >= 1 &&
				strcasecmp("dn", rv[irv].attrName[iv]) == 0) {
				int	err = 0;
				dn[ndn] = appendBase(
					rv[irv].attrVal[iv].val[0].value,
					defBase, &err, 0);
				if (err != 0) {
					freeDNs(dn, ndn);
					return (0);
				}
				ndn++;
				break;
			}
		}
	}

	*numDN = ndn;
	return (dn);
}
