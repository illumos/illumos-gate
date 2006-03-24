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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/systeminfo.h>

#include <syslog.h>

#include <adaptor.h>
#include <print/ns.h>

#ifndef RTLD_GLOBAL	/* for OSF/1 */
#define	RTLD_GLOBAL	0
#endif

/*
 * This file contains the implementation of the API used by the front half
 * of the BSD Print protocol adaptor to select and glue in the back half of
 * the print protocol adaptor dynamically.  Most of the functions in this
 * file are hollow shells that pick a back end, load it, and call the "real"
 * function from the loaded object, with the arguments passed in.  The loaded
 * functions have the naming convention {paradigm}_{function}.
 * These functions are in NO WAY MT-Safe.  They are intended to be used by
 * a single threaded adaptor, that is/may be called via inetd concurrently.
 */


static void *paradigm_handle = NULL;
static char *paradigm_name = NULL;
static int   paradigm_version = -1;
static ns_printer_t *printer_object = NULL;
static char *primary_name = NULL;

static int
is_localhost(char *name)
{
	char buf[BUFSIZ];

	if (name == NULL)
		return (0);

	if (strcasecmp(name, "localhost") == 0)
		return (0);

	(void) sysinfo(SI_HOSTNAME, buf, sizeof (buf));

	return (strcasecmp(name, buf));
}

int
syn_name(const char *str)
{
	register char *p;

	if (!str || !*str)
		return (0);

	if (strlen(str) > (size_t)14)
		return (0);

	for (p = (char *)str; *p; p++)
		if (!isalnum(*p) && *p != '_' && *p != '-')
			return (0);

	return (1);
}

/*
 * A hack for performance.  This will look for a local LP based printer in
 * the most efficient manner.  If found, it will circumvent all future
 * adaptor resolution and load the default lpsched translation module.
 */
static int
lpsched_adaptor_available(const char *printer)
{
	char buf[BUFSIZ], buf2[BUFSIZ];

	syslog(LOG_DEBUG, "in.lpd:lpsched_adaptor_available: entry\n");

	if (!syn_name(printer))
		return (-1);

	(void) snprintf(buf, sizeof (buf), "/etc/lp/interfaces/%s", printer);
	(void) snprintf(buf2, sizeof (buf2), "/etc/lp/classes/%s", printer);
	syslog(LOG_DEBUG,
		"in.lpd:lpsched_adaptor_available: printer is %s\n",
		printer);
	if ((access(buf, F_OK) < 0) && (access(buf2, F_OK) < 0))
		return (-1);

	syslog(LOG_DEBUG,
		"in.lpd:lpsched_adaptor_available: printer %s local\n",
		printer);

	paradigm_handle = dlopen("/usr/lib/print/bsd-adaptor/bsd_lpsched.so",
				RTLD_NOW|RTLD_GLOBAL);
	if (paradigm_handle == NULL)
		return (-1);

	paradigm_name = LPSCHED;
	return (0);
}

/*
 * adaptor_avaliable() takes in the name of a printer, looks it up in the
 * name service, and dynamically loads backend support for the print paradigm
 * the printer is defined in.  If the printer is undefined, UNDEFINED is
 * returned.  If the spooling paradigm is not defined, and the printer is
 * remote, a "cascade" capability is loaded.
 */
int
adaptor_available(const char *printer)
{
	char	*path,
		*dir,
		*tmp,
		*tmp_path;
	ns_bsd_addr_t *addr;

	/*
	 * for performance, check lpsched first and foremost.  This will
	 * hide any NS information if there is an LP configuration, valid
	 * or not.
	 */
	if (lpsched_adaptor_available(printer) == 0)
		return (0);

	errno = 0;
	if (((printer_object = ns_printer_get_name(printer,
						NS_SVC_ETC)) == NULL) &&
	    (endprinterentry() == 0) &&
	    ((printer_object = ns_printer_get_name(printer, NULL)) == NULL)) {
		errno = ENOENT;
		return (-1);
	}

	if ((addr = ns_get_value(NS_KEY_BSDADDR, printer_object)) != NULL)
		primary_name = addr->printer;

	if ((paradigm_name = ns_get_value_string(NS_KEY_ADAPTOR_NAME,
					printer_object)) == NULL) {
		if ((addr != NULL) && (is_localhost(addr->server) == 0))
			paradigm_name = LPSCHED;
		else
			paradigm_name = CASCADE;
	}

	if ((tmp = strrchr(paradigm_name, ',')) != NULL) {
		*tmp++ = NULL;
		paradigm_version = atoi(tmp);
	}

	if ((path = ns_get_value_string(NS_KEY_ADAPTOR_PATH, printer_object))
	    == NULL)
		path = ADAPTOR_PATH;

	tmp_path = strdup(path);
	for (dir = strtok(tmp_path, ":,"); dir != NULL;
	    dir = strtok(NULL, ":,")) {
		static char object[BUFSIZ];

		if (paradigm_version < 0)
			(void) snprintf(object, sizeof (object), "%s/bsd_%s.so",
				dir, paradigm_name);
		else
			(void) snprintf(object, sizeof (object),
				"%s/bsd_%s.so.%d", dir, paradigm_name,
				paradigm_version);
		if ((paradigm_handle = dlopen(object, RTLD_NOW|RTLD_GLOBAL))
		    != NULL)
			break;
#ifdef DEBUG
		syslog(LOG_DEBUG, "dlopen(%d): %s", object, dlerror());
#endif
	}
	free(tmp_path);

	return (paradigm_handle == NULL);
}


static void *
adaptor_function(const char *paradigm, const char *function)
{
	char name[128];
	void *fpt = NULL;

	if (paradigm_handle == NULL)
		return (NULL);

	(void) snprintf(name, sizeof (name), "%s_%s", paradigm, function);
	if ((fpt = dlsym(paradigm_handle, name)) == NULL)
		syslog(LOG_ERR, "could not locate function: %s()", name);

	return (fpt);
}


int
adaptor_spooler_available(const char *printer)
{
	static int (*fpt)() = NULL;

	if ((fpt != NULL) ||
	    ((fpt = (int (*)())adaptor_function(paradigm_name,
						"spooler_available")) != NULL))
		/*
		 *  in the case of cascading,
		 *  use the local name of the printer
		 */
		if (strcmp(paradigm_name, "cascade") == 0)
			return ((int)(fpt)(printer));
		else
			return ((int)(fpt)
				(primary_name ? primary_name : printer));

	    return (-1);
}


int
adaptor_spooler_accepting_jobs(const char *printer)
{
	static int (*fpt)() = NULL;

	if ((fpt != NULL) ||
	    ((fpt = (int (*)())adaptor_function(paradigm_name,
			"spooler_accepting_jobs")) != NULL))
		return ((int)(fpt)(primary_name ? primary_name : printer));

	    return (-1);
}


int
adaptor_client_access(const char *printer, const char *host, int peerfd)
{
	static int (*fpt)() = NULL;

	if ((fpt != NULL) ||
	    ((fpt = (int (*)())adaptor_function(paradigm_name,
						"client_access")) != NULL))
		return ((int)(fpt)((primary_name ? primary_name : printer),
					host, peerfd));

	    return (-1);
}


int
adaptor_restart_printer(const char *printer)
{
	static int (*fpt)() = NULL;

	/* need a cast */
	if ((fpt != NULL) ||
	    ((fpt = (int (*)())adaptor_function(paradigm_name,
						"restart_printer")) != NULL))
		return ((int)(fpt)(primary_name ? primary_name : printer));

	    return (-1);
}


char *
adaptor_temp_dir(const char *printer, const char *host)
{
	static char *(*fpt)() = NULL;

	/* need a cast */
	if ((fpt != NULL) ||
	    ((fpt = (char *(*)())adaptor_function(paradigm_name,
					    "temp_dir")) != NULL))
		return ((char *)(fpt)((primary_name ? primary_name : printer),
					host));

	    return (NULL);
}


int
adaptor_submit_job(const char *printer, const char *host, char *cf,
		    char **df_list)
{
	static int (*fpt)() = NULL;

	/* need a cast */
	if ((fpt != NULL) ||
	    ((fpt = (int (*)())adaptor_function(paradigm_name,
						"submit_job")) != NULL))
		return ((int)(fpt)((primary_name ? primary_name : printer),
					host, cf, df_list));

	    return (-1);
}


int
adaptor_show_queue(const char *printer, FILE *ofp, const int type,
			char **list)
{
	static int (*fpt)() = NULL;

	/* need a cast */
	if ((fpt != NULL) ||
	    ((fpt = (int (*)())adaptor_function(paradigm_name,
						"show_queue")) != NULL))
		return ((int)(fpt)((primary_name ? primary_name : printer),
					ofp, type, list));

	    return (-1);
}


int
adaptor_cancel_job(const char *printer, FILE *ofp, const char *user,
			const char *host, char **list)
{
	static int (*fpt)() = NULL;

	/* need a cast */
	if ((fpt != NULL) ||
	    ((fpt = (int (*)())adaptor_function(paradigm_name,
						"cancel_job")) != NULL))
		return ((int)(fpt)((primary_name ? primary_name : printer),
					ofp, user, host, list));

	    return (-1);
}
