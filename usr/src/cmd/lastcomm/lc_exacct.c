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

#include <sys/time.h>
#include <errno.h>
#include "lastcomm.h"

/* ARGSUSED1 */
static void
skip_group(ea_file_t *ef, uint_t nobjs)
{
	ea_object_t curr_obj;

	if (ea_previous_object(ef, &curr_obj) == -1) {
		(void) fprintf(stderr, gettext("lastcomm: "
		    "corrupted exacct file\n"));
		exit(1);
	}
}

static int
ok(int argc, char *argv[], int index, uid_t uid, dev_t tty, char *command)
{
	int j;

	for (j = index; j < argc; j++)
		if (strcmp(getname(uid), argv[j]) &&
		    strcmp(getdev(tty), argv[j]) &&
		    strncmp(command, argv[j], fldsiz(acct, ac_comm)))
			break;
	return (j == argc);
}

static void
disp_group(ea_file_t *ef, uint_t nobjs, int argc, char *argv[], int index)
{
	uint_t i;
	char *command = NULL;
	double cpu_usr_secs = 0.;
	double cpu_usr_nsecs = 0.;
	double cpu_sys_secs = 0.;
	double cpu_sys_nsecs = 0.;
	double totalsecs;
	dev_t tty = 0;
	major_t tty_major = 0;
	minor_t tty_minor = 0;
	uid_t uid = 0;
	time_t time = 0;
	uint32_t flag = 0;

	for (i = 0; i < nobjs; i++) {
		ea_object_t curr_obj;

		if (ea_get_object(ef, &curr_obj) == -1) {
			(void) fprintf(stderr, gettext("lastcomm: "
			    "corrupted exacct file\n"));
			exit(1);
		}

		switch (curr_obj.eo_catalog) {
			case EXT_STRING | EXC_DEFAULT | EXD_PROC_COMMAND:
				command = curr_obj.eo_item.ei_string;
				break;
			case EXT_UINT32 | EXC_DEFAULT | EXD_PROC_UID:
				uid = curr_obj.eo_item.ei_uint32;
				break;
			case EXT_UINT64 | EXC_DEFAULT | EXD_PROC_CPU_SYS_SEC:
				cpu_sys_secs = curr_obj.eo_item.ei_uint64;
				break;
			case EXT_UINT64 | EXC_DEFAULT | EXD_PROC_CPU_USER_SEC:
				cpu_usr_secs = curr_obj.eo_item.ei_uint64;
				break;
			case EXT_UINT64 | EXC_DEFAULT | EXD_PROC_CPU_SYS_NSEC:
				cpu_sys_nsecs = curr_obj.eo_item.ei_uint64;
				break;
			case EXT_UINT64 | EXC_DEFAULT | EXD_PROC_CPU_USER_NSEC:
				cpu_usr_nsecs = curr_obj.eo_item.ei_uint64;
				break;
			case EXT_UINT32 | EXC_DEFAULT | EXD_PROC_TTY_MAJOR:
				tty_major = curr_obj.eo_item.ei_uint32;
				break;
			case EXT_UINT32 | EXC_DEFAULT | EXD_PROC_TTY_MINOR:
				tty_minor = curr_obj.eo_item.ei_uint32;
				break;
			case EXT_UINT32 | EXC_DEFAULT | EXD_PROC_ACCT_FLAGS:
				flag = curr_obj.eo_item.ei_uint32;
				break;
			case EXT_UINT64 | EXC_DEFAULT | EXD_PROC_START_SEC:
				time = (uint32_t)curr_obj.eo_item.ei_uint64;
				break;
			default:
				break;
		}

		if (curr_obj.eo_type == EO_GROUP)
			disp_group(ef, curr_obj.eo_group.eg_nobjs,
			    argc, argv, index);
	}

	if (command == NULL) {
		(void) fprintf(stderr, gettext("lastcomm: "
		    "corrupted exacct file\n"));
		exit(1);
	}

	/*
	 * If a 64-bit kernel returns a major or minor value that would exceed
	 * the capacity of a 32-bit dev_t (and these also become visible in the
	 * filesystem), then the 32-bit makedev may be inaccurate and return
	 * NODEV.  When this occurs, we can remedy the problem by providing
	 * either a function which returns "dev64_t"'s or by providing an LP64
	 * version of lastcomm.
	 */
	tty = makedev(tty_major, tty_minor);

	/*
	 * If this record doesn't match the optional arguments, go on to the
	 * next record.
	 */
	if (argc > index && !ok(argc, argv, index, uid, tty, command))
		return;

	totalsecs =
	    cpu_usr_secs + cpu_usr_nsecs / NANOSEC +
	    cpu_sys_secs + cpu_sys_nsecs / NANOSEC;

	(void) printf("%-*.*s %s %-*s %-*s %6.2f secs %.16s\n",
	    fldsiz(acct, ac_comm), fldsiz(acct, ac_comm), command,
	    flagbits(flag), NMAX, getname(uid), LMAX, getdev(tty),
	    totalsecs, ctime(&time));
}

int
lc_exacct(char *filename, int argc, char *argv[], int index)
{
	ea_file_t ef;
	ea_object_t curr_obj;

	if (ea_open(&ef, filename, EXACCT_CREATOR,
		    EO_TAIL | EO_VALID_HDR, O_RDONLY, 0) < 0) {
		switch (ea_error()) {
			case EXR_CORRUPT_FILE:
				(void) fprintf(stderr, gettext("lastcomm: "
				    "exacct file corrupted\n"));
				break;
			case EXR_SYSCALL_FAIL:
				(void) fprintf(stderr, gettext("lastcomm: "
				    "cannot open %s: %s\n"), filename,
				    strerror(errno));
				break;
			default:
				break;
		}

		return (1);
	}

	while (ea_previous_object(&ef, &curr_obj) != -1) {
		if (ea_get_object(&ef, &curr_obj) == -1) {
			(void) fprintf(stderr, gettext("lastcomm: "
			    "exacct file corrupted\n"));
			exit(1);
		}

		/*
		 * lc_exacct(), in parsing the extended process accounting file,
		 * has knowledge of the fact that process records are top-level
		 * records.
		 */
		if ((curr_obj.eo_catalog & EXT_TYPE_MASK) == EXT_GROUP) {
			if (curr_obj.eo_catalog ==
			    (EXT_GROUP | EXC_DEFAULT | EXD_GROUP_PROC))
				disp_group(&ef, curr_obj.eo_group.eg_nobjs,
				    argc, argv, index);
			else
				skip_group(&ef, curr_obj.eo_group.eg_nobjs);
		}

		/*
		 * Back up to the head of the object we just consumed.
		 */
		if (ea_previous_object(&ef, &curr_obj) == -1) {
			if (ea_error() == EXR_EOF)
				break;

			(void) fprintf(stderr, gettext("lastcomm: "
			    "exacct file corrupted\n"));
			exit(1);
		}
	}

	if (ea_error() != EXR_EOF) {
		(void) fprintf(stderr, gettext("lastcomm: "
		    "exacct file corrupted\n"));
		exit(1);
	}

	(void) ea_close(&ef);

	return (0);
}
