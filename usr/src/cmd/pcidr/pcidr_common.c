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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/dr.h>
#include <syslog.h>
#include <libnvpair.h>
#include <stdarg.h>
#include <assert.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <signal.h>
#include <pcidr.h>


/*
 * How dpritab is used:
 * dpritab[dlvl_t value] = corresponding syslog priority
 *
 * Be careful of some priorities (facility + severity) that get "lost" by
 * default since they have no syslog.conf entries such as daemon.info and
 * daemon.debug; see syslog(3C) and syslog.conf(5) for more info
 */
int dpritab[] = {LOG_INFO, LOG_WARNING, LOG_NOTICE, LOG_NOTICE};
int dpritab_len = sizeof (dpritab) / sizeof (dpritab[0]);

/*
 * the following affects pcidr_set_logopt() which plugins should use to set
 * these logging options received from the handler
 */
dlvl_t dlvl = MIN_DLVL;	/* verbosity */
char *prg = "";		/* program name */
FILE *dfp = NULL;	/* file to output messages to */
int dsys = 1;		/* flag controlling output to syslog */


void *
pcidr_malloc(size_t size)
{
	int i = 0;
	void *buf;

	errno = 0;
	buf = malloc(size);
	if (buf != NULL)
		return (buf);

	for (i = 0; i < PCIDR_MALLOC_CNT; i++) {
		assert(errno == EAGAIN);
		if (errno != EAGAIN)
			exit(errno);
		(void) usleep(PCIDR_MALLOC_TIME);

		errno = 0;
		buf = malloc(size);
		if (buf != NULL)
			return (buf);
	}

	assert(buf != NULL);
	/* exit() in case assertions are disabled (NDEBUG defined) */
	exit(errno);
	return (NULL);
}


void
dprint(dlvl_t lvl, char *fmt, ...)
{
	int buflen, rv;
	char *buf;
	va_list ap;

	if (dlvl < lvl || (dsys == 0 && dfp == NULL))
		return;

	va_start(ap, fmt);
	/*LINTED*/
	buflen = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (buflen <= 0)
		return;
	buflen++;
	buf = (char *)pcidr_malloc(sizeof (char) * buflen);

	va_start(ap, fmt);
	/*LINTED*/
	rv = vsnprintf(buf, buflen, fmt, ap);
	va_end(ap);
	if (rv <= 0) {
		free(buf);
		return;
	}

#ifdef DEBUG
	if (dsys != 0)
		syslog(dpritab[lvl], "%s", buf);
#endif
	if (dfp != NULL)
		(void) fprintf(dfp, "%s", buf);

	free(buf);
}


void
pcidr_set_logopt(pcidr_logopt_t *logopt)
{
	dlvl = logopt->dlvl;
	prg = logopt->prg;
	dfp = logopt->dfp;
	dsys = logopt->dsys;
}


/*
 * if <name> is recognized, function will return its type through <typep> and
 * return 0; else function will return non-zero
 */
int
pcidr_name2type(char *name, data_type_t *typep)
{
	/* string type */
	if (strcmp(name, ATTRNM_CLASS) == 0 ||
	    strcmp(name, ATTRNM_SUBCLASS) == 0 ||
	    strcmp(name, ATTRNM_PUB_NAME) == 0 ||
	    strcmp(name, DR_REQ_TYPE) == 0 ||
	    strcmp(name, DR_AP_ID) == 0) {
		*typep = DATA_TYPE_STRING;
		return (0);
	}

	return (1);
}


void
pcidr_print_attrlist(dlvl_t lvl, nvlist_t *attrlistp, char *prestr)
{
	char *fn = "pcidr_print_attrlist";
	nvpair_t *nvpairp;
	char *valstr, *name;
	data_type_t type;
	int rv;

	if (prestr == NULL)
		prestr = "";

	nvpairp = NULL;
	while ((nvpairp = nvlist_next_nvpair(attrlistp, nvpairp)) != NULL) {
		type = nvpair_type(nvpairp);
		name = nvpair_name(nvpairp);

		switch (type) {
		case DATA_TYPE_STRING:
			rv = nvpair_value_string(nvpairp, &valstr);
			if (rv != 0) {
				dprint(lvl, "%s: nvpair_value_string() "
				    "failed: name = %s, rv = %d\n",
				    fn, name, rv);
				continue;
			}
			break;
		default:
			dprint(lvl, "%s: unsupported type: name = %s, "
			    "type = 0x%x\n", fn, name, (int)type);
			continue;
		}
		dprint(lvl, "%s%s = %s\n", prestr, name, valstr);
	}
}


/*
 * if one of the args matches <valstr>, return 0; else return non-zero
 * args list must be NULL terminated;
 * if args list is empty, this will return 0 if <valstr> is NOT empty
 */
int
pcidr_check_string(char *valstr, ...)
{
	va_list ap;
	int rv;
	char *argstr;

	assert(valstr != NULL);
	rv = 1;
	va_start(ap, valstr);
	if (va_arg(ap, char *) == NULL) {
		if (valstr[0] != '\0')
			rv = 0;
		goto OUT;
	}

	va_start(ap, valstr);
	while ((argstr = va_arg(ap, char *)) != NULL) {
		if (strcmp(argstr, valstr) == 0) {
			rv = 0;
			break;
		}
	}
OUT:
	va_end(ap);
	return (rv);
}


/*
 * dr attribute values that the default plugin checks for;
 * other plugins may also use this if they support a superset of these
 * values.
 * returns 0 if valid, else non-zero
 */
int
pcidr_check_attrs(pcidr_attrs_t *drp)
{
	char *fn = "pcidr_check_attrs";
	int rv = 0;
	char *val, *name;

	name = ATTRNM_CLASS;
	val = drp->class;
	if (pcidr_check_string(val, EC_DR, NULL) != 0) {
		dprint(DDEBUG, "%s: attribute \"%s\" has invalid value = %s\n",
		    fn, name, val);
		rv = 1;
	}

	name = ATTRNM_SUBCLASS;
	val = drp->subclass;
	if (pcidr_check_string(val, ESC_DR_REQ, NULL) != 0) {
		dprint(DDEBUG, "%s: attribute \"%s\" has invalid value = %s\n",
		    fn, name, val);
		rv = 1;
	}

	name = ATTRNM_PUB_NAME;
	val = drp->pub_name;
	if (pcidr_check_string(val, NULL) != 0) {
		dprint(DDEBUG, "%s: attribute \"%s\" is empty\n",
		    fn, name, val);
		rv = 1;
	}

	name = DR_REQ_TYPE;
	val = drp->dr_req_type;
	if (pcidr_check_string(val, DR_REQ_INCOMING_RES, DR_REQ_OUTGOING_RES,
	    NULL) != 0) {
		dprint(DDEBUG, "%s: attribute \"%s\" has invalid value = %s\n",
		    fn, name, val);
		rv = 1;
	}

	name = DR_AP_ID;
	val = drp->dr_ap_id;
	if (pcidr_check_string(drp->dr_ap_id, NULL) != 0) {
		dprint(DDEBUG, "%s: attribute \"%s\" is empty\n",
		    fn, name, val);
		rv = 1;
	}

	return (rv);
}


/*
 * get dr attributes from <listp> for the default plugin and returns
 * them through <drp>;
 * returns 0 on success
 */
int
pcidr_get_attrs(nvlist_t *attrlistp, pcidr_attrs_t *drp)
{
	char *fn = "pcidr_get_attrs";
	char *name;
	int r, rv = 0;

	name = ATTRNM_CLASS;
	r = nvlist_lookup_string(attrlistp, name, &drp->class);
	if (r != 0) {
		dprint(DDEBUG, "%s: nvlist_lookup_string() failed for "
		    "attribute \"%s\": rv = %d\n", fn, name, r);
		rv = r;
	}

	name = ATTRNM_SUBCLASS;
	r = nvlist_lookup_string(attrlistp, name, &drp->subclass);
	if (r != 0) {
		dprint(DDEBUG, "%s: nvlist_lookup_string() failed for "
		    "attribute \"%s\": rv = %d\n", fn, name, r);
		rv = r;
	}

	name = ATTRNM_PUB_NAME;
	r = nvlist_lookup_string(attrlistp, name, &drp->pub_name);
	if (r != 0) {
		dprint(DDEBUG, "%s: nvlist_lookup_string() failed for "
		    "attribute \"%s\": rv = %d\n", fn, name, r);
		rv = r;
	}

	name = DR_REQ_TYPE;
	r = nvlist_lookup_string(attrlistp, name, &drp->dr_req_type);
	if (r != 0) {
		dprint(DDEBUG, "%s: nvlist_lookup_string() failed for "
		    "attribute \"%s\": rv = %d\n", fn, name, r);
		rv = r;
	}

	name = DR_AP_ID;
	r = nvlist_lookup_string(attrlistp, name, &drp->dr_ap_id);
	if (r != 0) {
		dprint(DDEBUG, "%s: nvlist_lookup_string() failed for "
		    "attribute \"%s\": rv = %d\n", fn, name, r);
		rv = r;
	}

	return (rv);
}
