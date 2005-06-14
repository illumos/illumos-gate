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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#pragma weak _nss_ldap__printers_constr = _nss_ldap_printers_constr

#include "ldap_common.h"

static void append_attr(char *buf, char *attr);

/* printer attributes filters */
#define	_F_GETPRINTERBYNAME	\
	"(&(objectClass=sunPrinter)(|(printer-name=%s)(printer-aliases=%s)))"

/*
 * Attributes from the following classes:
 * 	printerService
 * 	printerAbstact
 * 	sunPrinter
 */

/*
 * Get all attributes.
 */
static const char **printer_attrs = NULL;


/*
 * _nss_ldap_printers2ent is the data marshaling method for the printers
 * getXbyY backend processes. This method is called after a successful
 * ldap search has been performed. This method will parse the ldap search
 * values into argp->buf.buffer. Three error conditions are expected and
 * returned to nsswitch.
 */

static int
_nss_ldap_printers2ent(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int			i, j;
	int			nss_result;
	int			buflen = (int)0;
	unsigned long		len = 0L;
	char			*cp = (char *)NULL;
	char			*buffer = (char *)NULL;
	ns_ldap_attr_t		*attr;
	ns_ldap_result_t	*result = be->result;

	buffer = argp->buf.buffer;
	buflen = (size_t)argp->buf.buflen;
	if (!argp->buf.result) {
		nss_result = (int)NSS_STR_PARSE_ERANGE;
		goto result_printers2ent;
	}

	nss_result = (int)NSS_STR_PARSE_SUCCESS;
	(void) memset(argp->buf.buffer, 0, buflen);

	/* Make sure our buffer stays NULL terminated */
	buflen--;

	attr = getattr(result, 0);
	if (attr == NULL) {
		nss_result = (int)NSS_STR_PARSE_PARSE;
		goto result_printers2ent;
	}

	/*
	 * Pick out the printer name.
	 */
	for (i = 0; i < result->entry->attr_count; i++) {
		attr = getattr(result, i);
		if (attr == NULL) {
			nss_result = (int)NSS_STR_PARSE_PARSE;
			goto result_printers2ent;
		}
		if (strcasecmp(attr->attrname, "printer-name") == 0) {
			len = strlen(attr->attrvalue[0]);
			if (len < 1 || (attr->attrvalue[0] == '\0')) {
				*buffer = 0;
				nss_result = (int)NSS_STR_PARSE_PARSE;
				goto result_printers2ent;
			}
			if (len > buflen) {
				nss_result = (int)NSS_STR_PARSE_ERANGE;
				goto result_printers2ent;
			}
			(void) strcpy(buffer, attr->attrvalue[0]);
		}
	}

	/*
	 * Should never happen since it is mandatory but bail if
	 * we don't have a printer name.
	 */
	if (buffer[0] == NULL) {
		nss_result = (int)NSS_STR_PARSE_PARSE;
		goto result_printers2ent;
	}

	/*
	 * Add the rest of the attributes
	 */
	for (i = 0; i < result->entry->attr_count; i++) {
		attr = getattr(result, i);
		if (attr == NULL) {
			nss_result = (int)NSS_STR_PARSE_PARSE;
			goto result_printers2ent;
		}
		/*
		 * The attribute contains key=value
		 */
		if (strcasecmp(attr->attrname, "sun-printer-kvp") == 0) {
			for (j = 0; j < attr->value_count; j++) {
				len = strlen(attr->attrvalue[j]);
				if (len < 1 ||
				    (attr->attrvalue[j] == '\0')) {
					*buffer = 0;
					nss_result = (int)NSS_STR_PARSE_PARSE;
					goto result_printers2ent;
				}
				len += strlen(buffer) + 1;	/* 1 for ':' */
				if (len > buflen) {
					nss_result = (int)NSS_STR_PARSE_ERANGE;
					goto result_printers2ent;
				}
				if ((cp = strrchr(buffer, '\0')) != NULL) {
						*cp = ':';
					(void) strcat(buffer,
					    attr->attrvalue[j]);
				}
			}
		} else {
			/*
			 * Skip the printer name
			 */
			if (strcmp(attr->attrname, "printer-name") == 0) {
				continue;
			}
			/*
			 * Translate sun-printer-bsdaddr -> bsdaddr
			 */
			if (strcmp(attr->attrname, "sun-printer-bsdaddr") ==
									0) {
				if (attr->attrname != NULL) {
					free(attr->attrname);
				}
				attr->attrname = strdup("bsdaddr");
			}

			/*
			 * The attribute name is the key. The attribute
			 * data is the value.
			 */
			for (j = 0; j < attr->value_count; j++) {
				int k;
				char *kp;

				len = strlen(attr->attrvalue[j]);
				if (len < 1 ||
				    (attr->attrvalue[j] == '\0')) {
					*buffer = 0;
					nss_result = (int)NSS_STR_PARSE_PARSE;
					goto result_printers2ent;
				}
				/*
				 * Add extra for any colons which need to
				 * be backslashed plus ending ':' or ','.
				 */
				k = 0;
				for (kp = attr->attrvalue[j]; *kp != NULL; kp++)
					if (*kp == ':')
						k++;
				len += strlen(buffer) + k;

				if (j == 0) {
					len += strlen(attr->attrname) + 1;
				}
				if (len > buflen) {
					nss_result = (int)NSS_STR_PARSE_ERANGE;
					goto result_printers2ent;
				}
				if ((cp = strrchr(buffer, '\0')) != NULL) {
					if (j == 0) {
						*cp = ':';
						(void) strcat(buffer,
						    attr->attrname);
						(void) strcat(buffer, "=");
					} else {
						*cp = ',';
					}
					(void) append_attr(buffer,
					    attr->attrvalue[j]);
				}
			}
		}
	}

#ifdef DEBUG
	(void) fprintf(stdout, "\n[getprinter.c: _nss_ldap_printers2ent]\n");
	(void) fprintf(stdout, " printers: [%s]\n", buffer);
#endif

result_printers2ent:
	(void) __ns_ldap_freeResult(&be->result);
	return ((int)nss_result);
}

/*
 * Attributes which contain colons must be backslashed.
 */
static void
append_attr(char *buf, char *attr)
{
	char *cp, *bp;

	if (strchr(attr, ':') == NULL) {
		(void) strcat(buf, attr);
		return;
	}
	bp = buf + strlen(buf);
	cp = attr;
	while (*cp != NULL) {
		if (*cp == ':') {
			*bp++ = '\\';
		}
		*bp++ = *cp++;
	}
}

/*
 * getbyname gets printer attributes by printer name. This function
 * constructs an ldap search filter using the printer name invocation
 * parameter and the getprinterbyname search filter defined. Once the
 * filter is constructed, we search for matching entries and marshal
 * the data results into argp->buf.buffer for the frontend process.
 * The function * _nss_ldap_printers2ent performs the data marshaling.
 */

static nss_status_t
getbyname(ldap_backend_ptr be, void *a)
{
	char		printername[BUFSIZ];
	nss_XbyY_args_t	*argp = (nss_XbyY_args_t *)a;
	char		searchfilter[SEARCHFILTERLEN];

	(void) strncpy(printername, argp->key.name, BUFSIZ);
	if (snprintf(searchfilter, SEARCHFILTERLEN,
		_F_GETPRINTERBYNAME, printername, printername) < 0)
		return ((nss_status_t)NSS_NOTFOUND);

	return ((nss_status_t)_nss_ldap_lookup(be, argp,
		_PRINTERS, searchfilter, NULL, NULL, NULL));
}

static ldap_backend_op_t printers_ops[] = {
	_nss_ldap_destr,
	_nss_ldap_endent,
	_nss_ldap_setent,
	_nss_ldap_getent,
	getbyname,
};


/*
 * _nss_ldap_printers_constr is where life begins. This function calls
 * the generic ldap constructor function to define and build the abstract
 * data types required to support ldap operations.
 */

/*ARGSUSED0*/
nss_backend_t *
_nss_ldap_printers_constr(const char *dummy1, const char *dummy2,
			const char *dummy3)
{

#ifdef DEBUG
	(void) fprintf(stdout,
		"\n[getprinterent.c: _nss_ldap_printers_constr]\n");
#endif

	return ((nss_backend_t *)_nss_ldap_constr(printers_ops,
		sizeof (printers_ops)/sizeof (printers_ops[0]), _PRINTERS,
		printer_attrs, _nss_ldap_printers2ent));
}
