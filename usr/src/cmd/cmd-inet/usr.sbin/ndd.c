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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1990  Mentat Inc.
 * ndd.c 2.1, last change 11/14/90
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <stropts.h>
#include <inet/nd.h>
#include <string.h>
#include <stdlib.h>
#include <libdllink.h>
#include <libintl.h>

static boolean_t do_getset(int fd, int cmd, char *buf, int buf_len);
static int	get_value(char *msg, char *buf, int buf_len);
static void	name_print(char *buf);
static void	getset_interactive(int fd);
static int	open_device(void);
static char	*errmsg(int err);
static void	fatal(char *fmt, ...);
static void	printe(boolean_t print_errno, char *fmt, ...);

static char	gbuf[65536];	/* Need 20k for 160 IREs ... */
static char	usage_str[] =	"usage: ndd -set device_name name value\n"
				"       ndd [-get] device_name name [name ...]";

/*
 * gldv3_warning() catches the case of /sbin/ndd abuse to administer
 * ethernet/MII props. Note that /sbin/ndd has not been abused
 * for administration of other datalink types, which makes it permissible
 * to test for support of the flowctrl property.
 */
static void
gldv3_warning(char *module)
{
	datalink_id_t	linkid;
	dladm_status_t	status;
	char		buf[DLADM_PROP_VAL_MAX], *cp;
	uint_t		cnt = 1;
	char		*link;
	dladm_handle_t	handle;

	link = strrchr(module, '/');
	if (link == NULL)
		return;

	if (dladm_open(&handle) != DLADM_STATUS_OK)
		return;

	status = dladm_name2info(handle, ++link, &linkid, NULL, NULL, NULL);
	if (status == DLADM_STATUS_OK) {
		cp = buf;
		status = dladm_get_linkprop(handle, linkid,
		    DLADM_PROP_VAL_CURRENT, "flowctrl", &cp, &cnt);
		if (status == DLADM_STATUS_OK) {
			(void) fprintf(stderr, gettext(
			    "WARNING: The ndd commands for datalink "
			    "administration are obsolete and may be "
			    "removed in a future release of Solaris. "
			    "Use dladm(1M) to manage datalink tunables.\n"));
		}
	}
	dladm_close(handle);
}

/* ARGSUSED */
int
main(int argc, char **argv)
{
	char	*cp, *value;
	int	cmd;
	int	fd;


	if (!(cp = *++argv)) {
		while ((fd = open_device()) != -1) {
			getset_interactive(fd);
			(void) close(fd);
		}
		return (EXIT_SUCCESS);
	}

	cmd = ND_GET;
	if (cp[0] == '-') {
		if (strncmp(&cp[1], "set", 3) == 0)
			cmd = ND_SET;
		else if (strncmp(&cp[1], "get", 3) != 0)
			fatal(usage_str);
		if (!(cp = *++argv))
			fatal(usage_str);
	}
	gldv3_warning(cp);

	if ((fd = open(cp, O_RDWR)) == -1)
		fatal("open of %s failed: %s", cp, errmsg(errno));

	if (!isastream(fd))
		fatal("%s is not a streams device", cp);

	if (!(cp = *++argv)) {
		getset_interactive(fd);
		(void) close(fd);
		return (EXIT_SUCCESS);
	}

	if (cmd == ND_SET) {
		if (!(value = *++argv))
			fatal(usage_str);
		(void) snprintf(gbuf, sizeof (gbuf), "%s%c%s%c", cp, '\0',
		    value, '\0');
		if (!do_getset(fd, cmd, gbuf, sizeof (gbuf)))
			return (EXIT_FAILURE);
	} else {
		do {
			(void) memset(gbuf, '\0', sizeof (gbuf));
			(void) strlcpy(gbuf, cp, sizeof (gbuf));
			if (!do_getset(fd, cmd, gbuf, sizeof (gbuf)))
				return (EXIT_FAILURE);
			if (cp = *++argv)
				(void) putchar('\n');
		} while (cp);
	}

	(void) close(fd);
	return (EXIT_SUCCESS);
}

static void
name_print(char *buf)
{
	char *cp, *rwtag;

	for (cp = buf; cp[0]; ) {
		for (rwtag = cp; !isspace(*rwtag); rwtag++)
			;
		*rwtag++ = '\0';
		while (isspace(*rwtag))
			rwtag++;
		(void) printf("%-30s%s\n", cp, rwtag);
		for (cp = rwtag; *cp++; )
			;
	}
}

/*
 * This function is vile, but it's better here than in the kernel.
 */
static boolean_t
is_obsolete(const char *param)
{
	if (strcmp(param, "ip_enable_group_ifs") == 0 ||
	    strcmp(param, "ifgrp_status") == 0) {
		(void) fprintf(stderr, "The \"%s\" tunable has been superseded "
		    "by IP Multipathing.\nPlease see the IP Network "
		    "Multipathing Administration Guide for details.\n", param);
		return (B_TRUE);
	}
	return (B_FALSE);
}

static boolean_t
do_getset(int fd, int cmd, char *buf, int buf_len)
{
	char	*cp;
	struct strioctl	stri;
	boolean_t	is_name_get;

	if (is_obsolete(buf))
		return (B_TRUE);

	stri.ic_cmd = cmd;
	stri.ic_timout = 0;
	stri.ic_len = buf_len;
	stri.ic_dp = buf;
	is_name_get = stri.ic_cmd == ND_GET && buf[0] == '?' && buf[1] == '\0';

	if (ioctl(fd, I_STR, &stri) == -1) {
		if (errno == ENOENT)
			(void) printf("name is non-existent for this module\n"
			    "for a list of valid names, use name '?'\n");
		else
			(void) printf("operation failed: %s\n", errmsg(errno));
		return (B_FALSE);
	}
	if (is_name_get)
		name_print(buf);
	else if (stri.ic_cmd == ND_GET) {
		for (cp = buf; *cp != '\0'; cp += strlen(cp) + 1)
			(void) puts(cp);
	}
	(void) fflush(stdout);
	return (B_TRUE);
}

static int
get_value(char *msg, char *buf, int buf_len)
{
	int	len;

	(void) printf("%s", msg);
	(void) fflush(stdout);

	buf[buf_len-1] = '\0';
	if (fgets(buf, buf_len-1, stdin) == NULL)
		exit(EXIT_SUCCESS);
	len = strlen(buf);
	if (buf[len-1] == '\n')
		buf[len - 1] = '\0';
	else
		len++;
	return (len);
}

static void
getset_interactive(int fd)
{
	int	cmd;
	char	*cp;
	int	len, buf_len;
	char	len_buf[10];

	for (;;) {
		(void) memset(gbuf, '\0', sizeof (gbuf));
		len = get_value("name to get/set ? ", gbuf, sizeof (gbuf));
		if (len == 1 || (gbuf[0] == 'q' && gbuf[1] == '\0'))
			return;
		for (cp = gbuf; cp < &gbuf[len]; cp++) {
			if (isspace(*cp))
				*cp = '\0';
		}
		cmd = ND_GET;
		if (gbuf[0] != '?' &&
		    get_value("value ? ", &gbuf[len], sizeof (gbuf) - len) > 1)
			cmd = ND_SET;
		if (cmd == ND_GET && gbuf[0] != '?' &&
		    get_value("length ? ", len_buf, sizeof (len_buf)) > 1) {
			if (!isdigit(len_buf[0])) {
				(void) printf("invalid length\n");
				continue;
			}
			buf_len = atoi(len_buf);
		} else
			buf_len = sizeof (gbuf);
		(void) do_getset(fd, cmd, gbuf, buf_len);
	}
}

static void
printe(boolean_t print_errno, char *fmt, ...)
{
	va_list	ap;
	int error = errno;

	va_start(ap, fmt);
	(void) printf("*ERROR* ");
	(void) vprintf(fmt, ap);
	va_end(ap);

	if (print_errno)
		(void) printf(": %s\n", errmsg(error));
	else
		(void) printf("\n");
}


static int
open_device()
{
	char	name[80];
	int	fd, len;

	for (;;) {
		len = get_value("module to query ? ", name, sizeof (name));
		if (len <= 1 ||
		    (len == 2 && (name[0] == 'q' || name[0] == 'Q')))
			return (-1);

		if ((fd = open(name, O_RDWR)) == -1) {
			printe(B_TRUE, "open of %s failed", name);
			continue;
		}

		gldv3_warning(name);

		if (isastream(fd))
			return (fd);

		(void) close(fd);
		printe(B_FALSE, "%s is not a streams device", name);
	}
}

static void
fatal(char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);
	(void) fprintf(stderr, "\n");

	exit(EXIT_FAILURE);
}

static char *
errmsg(int error)
{
	char *msg = strerror(error);

	return (msg != NULL ? msg : "unknown error");
}
