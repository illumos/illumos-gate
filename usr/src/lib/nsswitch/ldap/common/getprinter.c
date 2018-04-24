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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma weak _nss_ldap__printers_constr = _nss_ldap_printers_constr

#include "ldap_common.h"

static void append_attr(char *buf, char *attr);

/* printer attributes filters */
#define	_F_GETPRINTERBYNAME	\
	"(&(objectClass=sunPrinter)(|(printer-name=%s)(printer-aliases=%s)))"

#define	PRINTER_PREFIX	"printer-"
#define	SUNWPR_PREFIX	"sunwpr-"

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
 * _nss_ldap_printers2str is the data marshaling method for the printers
 * getXbyY backend processes. This method is called after a successful
 * ldap search has been performed. This method will parse the ldap search
 * values into argp->buf.buffer. Three error conditions are expected and
 * returned to nsswitch.
 * In order to be compatible with old data output, the code is commented out
 * with NSS_LDAP_PRINTERS. The NSS_LDAP_PRINTERS section is for future
 * refrences if it's decided to fix the output format.
 */

static int
_nss_ldap_printers2str(ldap_backend_ptr be, nss_XbyY_args_t *argp)
{
	int			i, j;
	int			nss_result;
	int			buflen = 0, len;
	char			*buffer = NULL;
	char			**name, *attrname;
	ns_ldap_attr_t		*attr;
	ns_ldap_result_t	*result = be->result;
#ifdef	NSS_LDAP_PRINTERS
	int			slen, plen;
#endif

	if (result == NULL)
		return (NSS_STR_PARSE_PARSE);

	buflen = argp->buf.buflen;
	if (argp->buf.result != NULL) {
		be->buffer = calloc(1, buflen);
		if (be->buffer == NULL)
			return (NSS_STR_PARSE_PARSE);
		be->buflen = buflen;
		buffer = be->buffer;
	} else {
		buffer = argp->buf.buffer;
		(void) memset(argp->buf.buffer, 0, buflen);
	}

	nss_result = NSS_STR_PARSE_SUCCESS;

#ifdef	NSS_LDAP_PRINTERS
	slen = strlen(SUNWPR_PREFIX);
	plen = strlen(PRINTER_PREFIX);
#endif

	/*
	 * Pick out the printer name and aliases
	 */
	name = __ns_ldap_getAttr(result->entry, "printer-name");
	if (name == NULL || name[0] == NULL) {
		nss_result = NSS_STR_PARSE_PARSE;
		goto result_printers2str;
	}
	len = snprintf(buffer, buflen, "%s", name[0]);
	TEST_AND_ADJUST(len, buffer, buflen, result_printers2str);

#ifdef	NSS_LDAP_PRINTERS
	attr = __ns_ldap_getAttrStruct(result->entry, "printer-aliases");
	if (attr != NULL && attr->attrvalue != NULL) {
		for (i = 0; i < attr->value_count; i++) {
			len = snprintf(buffer, buflen, "|%s",
					attr->attrvalue[i]);
			TEST_AND_ADJUST(len, buffer, buflen,
					result_printers2str);
		}
	}
#endif
	/*
	 * Add the rest of the attributes
	 */
	for (i = 0; i < result->entry->attr_count; i++) {
		attr = getattr(result, i);
		if (attr == NULL) {
			nss_result = NSS_STR_PARSE_PARSE;
			goto result_printers2str;
		}
		/*
		 * The attribute contains key=value
		 */
		if (strcasecmp(attr->attrname, "sun-printer-kvp") == 0) {
			for (j = 0; j < attr->value_count; j++) {
				len = strlen(attr->attrvalue[j]);
				if (len < 1 ) {
					*buffer = '\0';
					nss_result = (int)NSS_STR_PARSE_PARSE;
					goto result_printers2str;
				}
				len =  snprintf(buffer, buflen, ":%s",
						attr->attrvalue[j]);
				TEST_AND_ADJUST(len, buffer, buflen,
						result_printers2str);
			}
		} else {
			/*
			 * Skip some attr names
			 */
#ifdef	NSS_LDAP_PRINTERS
			if (strcasecmp(attr->attrname, "printer-name") == 0 ||
				strcasecmp(attr->attrname, "dn") == 0 ||
				strcasecmp(attr->attrname,
					"objectclass") == 0 ||
				strcasecmp(attr->attrname,
					"printer-uri") == 0 ||
				strcasecmp(attr->attrname,
					"printer-aliases") == 0)
#else
			if (strcasecmp(attr->attrname, "printer-name") == 0)
#endif
				continue;
			}
			/*
			 * Translate attr name ->key name
			 */
			if (strcmp(attr->attrname, "sun-printer-bsdaddr")
					== 0)
				attrname = "bsdaddr";
#ifdef	NSS_LDAP_PRINTERS
			else if (strcmp(attr->attrname, "printer-info")
					== 0)
				attrname = "description";
			else if (strcmp(attr->attrname, "sunwpr-support")
					== 0)
				attrname = "itopssupported";
			else if (strncmp(attr->attrname, PRINTER_PREFIX, plen)
					== 0)
				attrname = attr->attrname + plen;
			else if (strncmp(attr->attrname, SUNWPR_PREFIX, slen)
					== 0)
				attrname = attr->attrname + slen;
#endif
			else
				attrname = attr->attrname;

			/*
			 * The attrname is the key. The attribute
			 * data is the value.
			 */
			len = snprintf(buffer, buflen, ":%s=", attrname);
			TEST_AND_ADJUST(len, buffer, buflen,
					result_printers2str);

			for (j = 0; j < attr->value_count; j++) {
				int k;
				char *kp;

				if (attr->attrvalue[j] == NULL) {
					*buffer = 0;
					nss_result = NSS_STR_PARSE_PARSE;
					goto result_printers2str;
				}
				len = strlen(attr->attrvalue[j]);
				if (len < 1) {
					*buffer = 0;
					nss_result = NSS_STR_PARSE_PARSE;
					goto result_printers2str;
				}
				/*
				 * Add extra for any colons which need to
				 * be backslashed plus ending ':' or ','.
				 */
				k = 0;
				for (kp = attr->attrvalue[j]; *kp != NULL; kp++)
					if (*kp == ':')
						/* count ':' in value */
						k++;
				if (j == 0)
					/* first time */
					len += k;
				else
					/* add ',' */
					len += k + 1;

				if (len > buflen) {
					nss_result = NSS_STR_PARSE_ERANGE;
					goto result_printers2str;
				}
				if (j > 0)
					*buffer++ = ',';

				(void) append_attr(buffer,
					    attr->attrvalue[j]);
				buffer += strlen(attr->attrvalue[j]) + k;
				buflen -= len;
			}
	}

	if (argp->buf.result != NULL)
		be->buflen = strlen(be->buffer);

result_printers2str:
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
	bp = buf;
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
 * The function _nss_ldap_printers2str performs the data marshaling.
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

	return ((nss_backend_t *)_nss_ldap_constr(printers_ops,
		sizeof (printers_ops)/sizeof (printers_ops[0]), _PRINTERS,
		printer_attrs, _nss_ldap_printers2str));
}
