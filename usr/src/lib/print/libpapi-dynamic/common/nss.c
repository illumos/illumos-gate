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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

/* Id: nss.c 180 2006-07-20 17:33:02Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <syslog.h>
#include <papi.h>
#include <uri.h>
#include <papi_impl.h>
#ifdef NSS_EMULATION
#include <nss-emulation.h>
#elif NSS_SOLARIS
#include <nss_dbdefs.h>
#endif
#include <config-site.h>
#if defined(__sun) && defined(__SVR4)
#include <sys/systeminfo.h>
#endif


static char *
bsdaddr_to_uri(papi_attribute_t **list, char *bsdaddr)
{
	char *result = NULL;

	if (bsdaddr != NULL) {
		char *bsd[3], *tmp, *iter = NULL;
		char buf[512];

		tmp = strdup(bsdaddr);

		bsd[0] = strtok_r(tmp, ":,", &iter);
		if ((bsd[1] = strtok_r(NULL, ":,", &iter)) == NULL)
			papiAttributeListGetString(list, NULL,
					"printer-name", &bsd[1]);
		bsd[2] = strtok_r(NULL, ":,", &iter);

		snprintf(buf, sizeof (buf), "lpd://%s/printers/%s%s%s", bsd[0],
			(bsd[1] != NULL) ? bsd[1] : "",
			(bsd[2] != NULL) ? "#" : "",
			(bsd[2] != NULL) ? bsd[2] : "");

		free(tmp);

		result = strdup(buf);
	}

	return (result);
}

#if defined(__sun) && defined(__SVR4)
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

static struct in6_addr **
local_interfaces()
{
	struct in6_addr **result = NULL;
	int s;
	struct lifnum n;
	struct lifconf c;
	struct lifreq *r;
	int count;

	/* we need a socket to get the interfaces */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		return (0);

	/* get the number of interfaces */
	memset(&n, 0, sizeof (n));
	n.lifn_family = AF_UNSPEC;
	if (ioctl(s, SIOCGLIFNUM, (char *)&n) < 0) {
		close(s);
		return (0);	/* no interfaces */
	}

	/* get the interface(s) configuration */
	memset(&c, 0, sizeof (c));
	c.lifc_family = AF_UNSPEC;
	c.lifc_buf = calloc(n.lifn_count, sizeof (struct lifreq));
	c.lifc_len = (n.lifn_count * sizeof (struct lifreq));
	if (ioctl(s, SIOCGLIFCONF, (char *)&c) < 0) {
		free(c.lifc_buf);
		close(s);
		return (0);	/* can't get interface(s) configuration */
	}
	close(s);

	r = c.lifc_req;
	for (count = c.lifc_len / sizeof (struct lifreq);
	     count > 0; count--, r++) {
		struct in6_addr v6[1], *addr = NULL;

		switch (r->lifr_addr.ss_family) {
		case AF_INET: {
			struct sockaddr_in *s =
				(struct sockaddr_in *)&r->lifr_addr;
			IN6_INADDR_TO_V4MAPPED(&s->sin_addr, v6);
			addr = v6;
			}
			break;
		case AF_INET6: {
			struct sockaddr_in6 *s =
				(struct sockaddr_in6 *)&r->lifr_addr;
			addr = &s->sin6_addr;
			}
			break;
		}

		if (addr != NULL) {
			struct in6_addr *a = malloc(sizeof (*a));

			memcpy(a, addr, sizeof (*a));
			list_append(&result, a);
		}
	}
	free(c.lifc_buf);

	return (result);
}

static int
match_interfaces(char *host)
{
	struct in6_addr **lif = local_interfaces();
	struct hostent *hp;
	int rc = 0;
	int errnum;

	/* are there any local interfaces */
	if (lif == NULL)
		return (0);

	/* cycle through the host db addresses */
	hp = getipnodebyname(host, AF_INET6, AI_ALL|AI_V4MAPPED, &errnum);
	if (hp != NULL) {
		struct in6_addr **tmp = (struct in6_addr **)hp->h_addr_list;
		int i;

		for (i = 0; ((rc == 0) && (tmp[i] != NULL)); i++) {
			int j;

			for (j = 0; ((rc == 0) && (lif[j] != NULL)); j++)
				if (memcmp(tmp[i], lif[j],
						sizeof (struct in6_addr)) == 0)
					rc = 1;
		}
	}
	free(lif);

	return (rc);
}

static int
is_localhost(char *host)
{
	char hostname[BUFSIZ];

	/* is it "localhost" */
	if (strncasecmp(host, "localhost", 10) == 0)
		return (1);

	/* is it the {nodename} */
	sysinfo(SI_HOSTNAME, hostname, sizeof (hostname));
	if (strncasecmp(host, hostname, strlen(hostname)) == 0)
		return (1);

	/* does it match one of the host's configured interfaces */
	if (match_interfaces(host) != 0)
		return (1);

	return (0);
}

/*
 * This is an awful HACK to force the dynamic PAPI library to use the
 * lpsched support when the destination apears to be a local lpsched
 * queue on Solaris.
 */
static void
solaris_lpsched_shortcircuit_hack(papi_attribute_t ***list)
{
	papi_attribute_t *attribute;
	uri_t *uri = NULL;
	char *printer = NULL;
	char buf[128], buf2[128];

	/* setting this in the calling env can be useful for debugging */
	if (getenv("DISABLE_LPSCHED_SHORTCIRCUIT") != NULL)
		return;

	papiAttributeListGetString(*list, NULL,
				"printer-uri-supported", &printer);
	if (uri_from_string(printer, &uri) < 0)
		return;

	/* already an lpsched URI ? */
	if (strcasecmp(uri->scheme, "lpsched") == 0)
		return;

	if ((printer = strrchr(uri->path, '/')) == NULL)
		printer = uri->path;
	else
		printer++;

	/* is there an lpsched queue (printer/class) */
	snprintf(buf, sizeof (buf), "/etc/lp/interfaces/%s", printer);
	snprintf(buf2, sizeof (buf2), "/etc/lp/classes/%s", printer);
	if ((access(buf, F_OK) < 0) && (access(buf2, F_OK) < 0))
		return;

	/* is this the "local" host */
	if ((uri->host != NULL) && (is_localhost(uri->host) == 0))
		return;

	snprintf(buf, sizeof (buf), "lpsched://%s/printers/%s",
			(uri->host ? uri->host : "localhost"), printer);
	papiAttributeListAddString(list, PAPI_ATTR_REPLACE,
			"printer-uri-supported", buf);
}
#endif

static void
fill_printer_uri_supported(papi_attribute_t ***list)
{
	papi_attribute_t *attribute;
	char *string = NULL;

	/* do we have a printer-uri-supported */
	attribute = papiAttributeListFind(*list, "printer-uri-supported");
	if (attribute != NULL) /* we have what we need, return */
		return;

	/* do we have a printer-uri (in URI form) to rename */
	attribute = papiAttributeListFind(*list, "printer-uri");
	if ((attribute != NULL) &&
	    (attribute->type == PAPI_STRING) &&
	    (attribute->values != NULL) &&
	    (attribute->values[0]->string != NULL) &&
	    (strstr(attribute->values[0]->string, "://") != NULL)) {
			/* rename it in place and return */
		free(attribute->name);
		attribute->name = strdup("printer-uri-supported");
		return;
	}

	/* do we have a printers.conf(4) "bsdaddr" to convert */
	papiAttributeListGetString(*list, NULL, "bsdaddr", &string);
	if (string != NULL) { /* parse it, convert it, add it */
		char *uri = bsdaddr_to_uri(*list, string);

		if (uri != NULL) {
			papiAttributeListAddString(list, PAPI_ATTR_APPEND,
					"printer-uri-supported", uri);
			papiAttributeListDelete(list, "bsdaddr");
			free(uri);
			return;
		}
	}

	/* do we have a printers.conf(4) "rm" (and "rp") to convert */
	papiAttributeListGetString(*list, NULL, "rm", &string);
	if (string != NULL) {
		char *rp = NULL;

		/* default to "printer-name", but use "rp" if we have it */
		papiAttributeListGetString(*list, NULL, "printer-name", &rp);
		papiAttributeListGetString(*list, NULL, "rp", &rp);

		if (rp != NULL) { /* fill in the uri if we have the data */
			char buf[BUFSIZ];

			snprintf(buf, sizeof (buf), "lpd://%s/printers/%s",
				string, rp);
			papiAttributeListAddString(list, PAPI_ATTR_APPEND,
					"printer-uri-supported", strdup(buf));
			return;
		}
	}

	/* if were are here, we don't have a printer-uri-supported */
}

#ifdef NEED_BROKEN_PRINTER_URI_SEMANTIC
static void
fill_printer_uri(papi_attribute_t ***list)
{
	papi_attribute_t *attribute;
	char *uri = NULL;

	if ((list == NULL) || (*list == NULL))
		return;

	/* do we have a printer-uri */
	attribute = papiAttributeListFind(*list, "printer-uri");
	if (attribute != NULL) /* we have what we need, return */
		return;

	/*
	 * this is sufficient to fool libgnomeprintpapi, but not promote it's
	 * use in the future.
	 */
	papiAttributeListAddString(list, PAPI_ATTR_EXCL, "printer-uri",
			"broken printer-uri semantic");
}
#endif /* NEED_BROKEN_PRINTER_URI_SEMANTIC */

static void
cvt_all_to_member_names(papi_attribute_t ***list)
{
	papi_status_t status;
	void *iter = NULL;
	char *string = NULL;

	papiAttributeListGetString(*list, NULL, "member-names", &string);
	if (string != NULL) /* already have a member-names */
		return;

	for (status = papiAttributeListGetString(*list, &iter, "all", &string);
	     status == PAPI_OK;
	     status = papiAttributeListGetString(*list, &iter, NULL, &string)) {
		char *s_iter = NULL, *value, *tmp = strdup(string);

		for (value = strtok_r(tmp, ", \t", &s_iter);
		     value != NULL;
		     value = strtok_r(NULL, ", \t", &s_iter))
			papiAttributeListAddString(list, PAPI_ATTR_APPEND,
					"member-names", value);
		free(tmp);
	}
}

static papi_attribute_t **
_cvt_nss_entry_to_printer(char *entry)
{
	char    *key = NULL,
		*cp,
		buf[BUFSIZ];
	int in_namelist = 1, buf_pos = 0;
	papi_attribute_t **list = NULL;

	if (entry == NULL)
		return (NULL);

	memset(buf, 0, sizeof (buf));
	for (cp = entry; *cp != '\0'; cp++) {
		switch (*cp) {
		case ':':	/* end of kvp */
			if (in_namelist != 0) {
				papiAttributeListAddString(&list,
					PAPI_ATTR_APPEND, "printer-name", buf);
				in_namelist = 0;
			} else if (key != NULL)
				papiAttributeListAddString(&list,
					PAPI_ATTR_APPEND, key, buf);
			memset(buf, 0, sizeof (buf));
			buf_pos = 0;
			key = NULL;
			break;
		case '=':	/* kvp seperator */
			if (key == NULL) {
				key = strdup(buf);
				memset(buf, 0, sizeof (buf));
				buf_pos = 0;
			} else
				buf[buf_pos++] = *cp;
			break;
		case '|':	/* namelist seperator */
			if (in_namelist != 0) {
				papiAttributeListAddString(&list,
					PAPI_ATTR_APPEND, "printer-name", buf);
				memset(buf, 0, sizeof (buf));
				buf_pos = 0;
			} else	/* add it to the buffer */
				buf[buf_pos++] = *cp;
			break;
		case '\\':	/* escape char */
			buf[buf_pos++] = *(++cp);
			break;
		default:
			buf[buf_pos++] = *cp;
		}

	}

	if (key != NULL)
		papiAttributeListAddString(&list, PAPI_ATTR_APPEND, key, buf);

	/* resolve any "use" references in the configuration DB */
	key = NULL;
	papiAttributeListGetString(list, NULL, "use", &key);
	if (key != NULL) {
		papi_attribute_t **use_attrs = getprinterbyname(key, NULL);

		list_concatenate(&list, use_attrs);
	}

	fill_printer_uri_supported(&list);
	cvt_all_to_member_names(&list); /* convert "all" to "member-names" */

	return (list);
}

#if defined(NSS_SOLARIS) && !defined(NSS_EMULATION)

#ifndef	NSS_DBNAM__PRINTERS	/* not in nss_dbdefs.h because it's private */
#define	NSS_DBNAM__PRINTERS	"_printers"
#endif

static DEFINE_NSS_DB_ROOT(db_root);
static DEFINE_NSS_GETENT(context);

static char *private_ns = NULL;

static void
_nss_initf_printers(p)
    nss_db_params_t *p;
{
	if (private_ns != NULL) {
		/*
		 * because we need to support a legacy interface that allows
		 * us to select a specific name service, we need to dummy up
		 * the parameters to use a private nsswitch database and set
		 * the * default_config entry to the name service we are
		 * looking into.
		 */
		p->name = NSS_DBNAM__PRINTERS;		/* "_printers" */
		p->default_config = private_ns;
	} else {
		/* regular behaviour */
		p->name = NSS_DBNAM_PRINTERS;	 /* "printers" */
		p->default_config = NSS_DEFCONF_PRINTERS;
	}
	syslog(LOG_DEBUG, "database: %s, default: %s",
		(p->name ? p->name : "NULL"),
		(p->default_config ? p->default_config : "NULL"));
}

/*
 * Return values: 0 = success, 1 = parse error, 2 = erange ...
 * The structure pointer passed in is a structure in the caller's space
 * wherein the field pointers would be set to areas in the buffer if
 * need be. instring and buffer should be separate areas.
 */
/* ARGSUSED */
static int
str2printer(const char *instr, int lenstr, void *ent, char *buffer, int buflen)
{
	if (lenstr + 1 > buflen)
		return (NSS_STR_PARSE_ERANGE);

	/* skip entries that begin with '#' */
	if (instr[0] == '#')
		return (NSS_STR_PARSE_PARSE);

	/*
	 * We copy the input string into the output buffer
	 */
	(void) memcpy(buffer, instr, lenstr);
	buffer[lenstr] = '\0';

	return (NSS_STR_PARSE_SUCCESS);
}
#endif /* NSS_SOLARIS */

int
setprinterentry(int stayopen, char *ns)
{
#ifdef NSS_EMULATION
	emul_setprinterentry(stayopen);
#elif NSS_SOLARIS
	private_ns = ns;
	nss_setent(&db_root, _nss_initf_printers, &context);
	private_ns = NULL;
#endif
	return (0);
}


int
endprinterentry(int i)
{
#ifdef NSS_EMULATION
	emul_endprinterentry();
#elif NSS_SOLARIS
	nss_endent(&db_root, _nss_initf_printers, &context);
	nss_delete(&db_root);
	private_ns = NULL;
#endif
	return (0);
}

/* ARGSUSED2 */
papi_attribute_t **
getprinterentry(char *ns)
{
	papi_attribute_t **result = NULL;

#if defined(NSS_EMULATION) || defined(NSS_SOLARIS)
	char buf[10240];
	nss_status_t	res = NSS_NOTFOUND;

#ifdef NSS_EMULATION
	res = emul_getprinterentry_r(buf, sizeof (buf));
#elif NSS_SOLARIS
	nss_XbyY_args_t arg;

	private_ns = ns;
	NSS_XbyY_INIT(&arg, buf, buf, sizeof (buf), str2printer);
	res = nss_getent(&db_root, _nss_initf_printers, &context, &arg);
	(void) NSS_XbyY_FINI(&arg);
	private_ns = NULL;
#endif

	if (res != NSS_SUCCESS)
		buf[0] = '\0';

	result = _cvt_nss_entry_to_printer(buf);
#if defined(__sun) && defined(__SVR4)
	solaris_lpsched_shortcircuit_hack(&result);
#endif
#ifdef NEED_BROKEN_PRINTER_URI_SEMANTIC
	fill_printer_uri(&result);
#endif /* NEED_BROKEN_PRINTER_URI_SEMANTIC */
#endif

#ifdef DEBUG
	printf("getprinterentry(%s): 0x%8.8x\n", (ns ? ns : "NULL"), result);
	if (result != NULL) {
		char buf[4096];

		papiAttributeListToString(result, "\n\t", buf, sizeof (buf));
		printf("\t%s\n", buf);
	}
#endif /* DEBUG */

	return (result);
}


papi_attribute_t **
getprinterbyname(char *name, char *ns)
{
	papi_attribute_t **result = NULL;

	if (strstr(name, "://") != NULL) {	/* shortcut for URI form */
		papiAttributeListAddString(&result, PAPI_ATTR_APPEND,
				"printer-name", name);
		papiAttributeListAddString(&result, PAPI_ATTR_APPEND,
				"printer-uri-supported", name);
	} else if (strchr(name, ':') != NULL) {	/* shortcut for POSIX form */
		char *uri = bsdaddr_to_uri(result, name);

		papiAttributeListAddString(&result, PAPI_ATTR_APPEND,
				"printer-name", name);
		if (uri != NULL) {
			papiAttributeListAddString(&result, PAPI_ATTR_APPEND,
					"printer-uri-supported", uri);
			free(uri);
		}
	} else {				/* anything else */
#if defined(NSS_EMULATION) || defined(NSS_SOLARIS)
		char buf[10240];
		nss_status_t	res = NSS_NOTFOUND;

#ifdef NSS_EMULATION
		res = emul_getprinterbyname_r(name, buf, sizeof (buf));
#elif NSS_SOLARIS
		nss_XbyY_args_t arg;

		private_ns = ns;
		NSS_XbyY_INIT(&arg, buf, buf, sizeof (buf), str2printer);
		arg.key.name = name;
		res = nss_search(&db_root, _nss_initf_printers,
				NSS_DBOP_PRINTERS_BYNAME, &arg);
		(void) NSS_XbyY_FINI(&arg);
		private_ns = NULL;

		if (res != NSS_SUCCESS)
			buf[0] = '\0';
#endif

		result = _cvt_nss_entry_to_printer(buf);
#endif
	}
#if defined(__sun) && defined(__SVR4)
	solaris_lpsched_shortcircuit_hack(&result);
#endif
#ifdef DEBUG
	printf("getprinterbyname(%s): %s = 0x%8.8x\n", (ns ? ns : "NULL"),
		name, result);
	if (result != NULL) {
		char buf[4096];

		papiAttributeListToString(result, "\n\t", buf, sizeof (buf));
		printf("\t%s\n", buf);
	}
#endif /* DEBUG */

	return (result);
}
