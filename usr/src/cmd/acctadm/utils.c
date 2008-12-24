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
 */

#include <assert.h>
#include <sys/types.h>
#include <sys/acctctl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <libintl.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <exacct.h>
#include <fcntl.h>
#include <priv.h>

#include "utils.h"

static char PNAME_FMT[] = "%s: ";
static char ERRNO_FMT[] = ": %s\n";

static char *pname;

/*PRINTFLIKE1*/
void
warn(const char *format, ...)
{
	int err = errno;
	va_list alist;
	if (pname != NULL)
		(void) fprintf(stderr, gettext(PNAME_FMT), pname);
	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, gettext(ERRNO_FMT), strerror(err));
}

/*PRINTFLIKE1*/
void
die(char *format, ...)
{
	int err = errno;
	va_list alist;

	if (pname != NULL)
		(void) fprintf(stderr, gettext(PNAME_FMT), pname);
	va_start(alist, format);
	(void) vfprintf(stderr, format, alist);
	va_end(alist);
	if (strchr(format, '\n') == NULL)
		(void) fprintf(stderr, gettext(ERRNO_FMT), strerror(err));

	/* close the libdladm handle if it was opened */
	if (dld_handle != NULL)
		dladm_close(dld_handle);

	exit(E_ERROR);
}

char *
setprogname(char *arg0)
{
	char *p = strrchr(arg0, '/');

	if (p == NULL)
		p = arg0;
	else
		p++;
	pname = p;
	return (pname);
}

/*
 * Return the localized name of an accounting type.
 */
const char *
ac_type_name(int type)
{
	switch (type) {
	case AC_PROC:
		return (gettext("process"));
	case AC_FLOW:
		return (gettext("flow"));
	case AC_TASK:
		return (gettext("task"));
	case AC_NET:
		return (gettext("net"));
	default:
		die(gettext("invalid type %d\n"), type);
	}
	/* NOTREACHED */
	return (NULL);
}

/*
 * Open an accounting file.  The filename specified must be an absolute
 * pathname and the existing contents of the file (if any) must be of the
 * requested type.  Needs euid 0 to open the root-owned accounting file.
 * file_dac_write is required to create a new file in a directory not owned
 * by root (/var/adm/exacct is owned by 'adm').  Assumes sys_acct privilege is
 * already asserted by caller.
 */
int
open_exacct_file(const char *file, int type)
{
	int rc;
	int err;

	if (file[0] != '/') {
		warn(gettext("%s is not an absolute pathname\n"), file);
		return (-1);
	}
	if (!verify_exacct_file(file, type)) {
		warn(gettext("%s is not a %s accounting file\n"), file,
		    ac_type_name(type));
		return (-1);
	}
	if (seteuid(0) == -1 || setegid(0) == -1) {
		warn(gettext("seteuid()/setegid() failed"));
		return (-1);
	}
	assert(priv_ineffect(PRIV_SYS_ACCT));
	(void) priv_set(PRIV_ON, PRIV_EFFECTIVE, PRIV_FILE_DAC_WRITE, NULL);
	rc = acctctl(type | AC_FILE_SET, (void *) file, strlen(file) + 1);
	if (rc == -1 && (err = errno) == EBUSY) {
		char name[MAXPATHLEN];
		struct stat cur;
		struct stat new;

		/*
		 * The file is already open as an accounting file somewhere.
		 * If the file we're trying to open is the same as we have
		 * currently open then we're ok.
		 */
		if (acctctl(type | AC_FILE_GET, name, sizeof (name)) == 0 &&
		    stat(file, &new) != -1 && stat(name, &cur) != -1 &&
		    new.st_dev == cur.st_dev && new.st_ino == cur.st_ino)
			rc = 0;
	}

	/*
	 * euid 0, egid 0 and the file_dac_write privilege are no longer
	 * required; give them up permanently.
	 */
	(void) priv_set(PRIV_OFF, PRIV_PERMITTED, PRIV_FILE_DAC_WRITE, NULL);
	if (setreuid(getuid(), getuid()) == -1 ||
	    setregid(getgid(), getgid()) == -1)
		die(gettext("setreuid()/setregid() failed"));
	if (rc == 0)
		return (0);

	warn(gettext("cannot open %s accounting file %s: %s\n"),
	    ac_type_name(type), file, strerror(err));
	return (-1);
}

/*
 * Verify that the file contents (if any) are extended accounting records
 * of the desired type.
 */
boolean_t
verify_exacct_file(const char *file, int type)
{
	ea_file_t ef;
	ea_object_t eo;
	struct stat st;
	int err;

	if (stat(file, &st) != -1 && st.st_size != 0) {
		if (seteuid(0) == -1)
			return (B_FALSE);
		err = ea_open(&ef, file, "SunOS", EO_TAIL, O_RDONLY, 0);
		if (seteuid(getuid()) == 1)
			die(gettext("seteuid() failed"));
		if (err == -1)
			return (B_FALSE);

		bzero(&eo, sizeof (eo));
		if (ea_previous_object(&ef, &eo) == EO_ERROR) {
			/*
			 * EXR_EOF indicates there are no non-header objects
			 * in the file.  It can't be determined that this
			 * file is or is not the proper type of extended
			 * accounting file, which isn't necessarily an error.
			 * Since it is a proper (albeit empty) extended
			 * accounting file, it matches any desired type.
			 *
			 * if ea_previous_object() failed for any other reason
			 * than EXR_EOF, the file must be corrupt.
			 */
			if (ea_error() != EXR_EOF) {
				(void) ea_close(&ef);
				return (B_FALSE);
			}
		} else {
			/*
			 * A non-header object exists.  Insist that it be
			 * either a process, task, flow  or net accounting
			 * record, the same type as is desired.
			 * xxx-venu:check 101 merge for EXD_GROUP_NET_*
			 */
			uint_t c = eo.eo_catalog & EXD_DATA_MASK;

			if (eo.eo_type != EO_GROUP ||
			    (eo.eo_catalog & EXC_CATALOG_MASK) != EXC_NONE ||
			    (!(c == EXD_GROUP_PROC && type == AC_PROC ||
			    c == EXD_GROUP_TASK && type == AC_TASK ||
			    c == EXD_GROUP_FLOW && type == AC_FLOW ||
			    (c == EXD_GROUP_NET_LINK_DESC ||
			    c == EXD_GROUP_NET_FLOW_DESC ||
			    c == EXD_GROUP_NET_LINK_STATS ||
			    c == EXD_GROUP_NET_FLOW_STATS) &&
			    type == AC_NET))) {
				(void) ea_close(&ef);
				return (B_FALSE);
			}
		}
		(void) ea_close(&ef);
	}
	return (B_TRUE);
}
