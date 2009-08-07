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
 * fps_compiler_check verifies if the compiler
 * and the libsuperf associated with the compiler
 * are known.
 *
 * How To Update the code with details about
 * a new compiler/libsunperf:
 * - Add a line that describes the new compiler and libsunperf version
 * in version_details table.
 * - Respect the order specified in v_d struct.
 * - cstyle -p fps_compiler_check.c
 * - make
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sunperf.h>

#define	LIM_CI	256

typedef struct
{
	long cc_version;
	long lib_version;
	long lib_patch;
	long lib_update;
	char *lib_ver_string;
} v_d;

v_d version_details[] = {
	{0x550, 0x400000000, 0, 0,
	"Sun Performance Library 4.1 2003/03/13"}, /* 0 - SOS8 */
	{0x570, 0x600000000, 0, 0,
	"Sun Performance Library 6 12/13/04"}, /* 1 - SOS10 */
	{0x580, 0x600000000, 0, 0,
	"Sun Performance Library 6 07/27/2006 Patch_122135-02"}, /* 2-SS11 */
	{0x590, 7, 0, 0,
	"Sun Performance Library 7 Patch_124870-02"}, /* 3 - SS12 */
	{0x590, 7, 124870, 3, /* 4-SS12 QA */
	"Sun Performance Library 7 Patch_124870-03 2008/05/28" },
	{0x5100, 8, 0, 0,
	"Sun Performance Library 8 2008/10/24"}, /* 5 */
	{0x5100, 8, 0, 0,
	"Sun Performance Library 8 2009/04/28"}, /* 6 - SS12 U1 */
	{0, 0, 0, 0, NULL}
};


#if 0
static void printError(
char *Uknown, long cc_version, long lib_version,
long lib_patch, long lib_update, char *lib_ver_string)
{
	if ((NULL != Uknown) && (NULL != lib_ver_string))
	printf("\n %s \n Compiler = 0x%x \n lib_version = %ld 0x%lx \
	\n lib_patch = %ld  0x%lx \n lib_update = %ld  0x%lx \
	\n lib_ver_string = %s\n",
	    Unknown, cc_version, lib_version, lib_version, lib_patch,
	    lib_patch, lib_update, lib_update, lib_ver_string);
}
#endif


int
main()
{
	char *lib_ver_string = NULL;
	long cc_version, lib_version, lib_patch, lib_update;
	int i, k, j, TableElem;
	int CompilerIndex[LIM_CI];


	/* Initialize */
	cc_version = lib_version = lib_patch = lib_update = 0;
	TableElem = sizeof (version_details) / sizeof (v_d);
	for (i = 0; i < LIM_CI; i++) CompilerIndex[i] = -1;

	/* get the info about the current compiler and libsunperf */
#ifndef __lint
	lib_ver_string =
	    sunperf_version_64(&lib_version, &lib_patch, &lib_update);
#endif
	cc_version = __SUNPRO_C;

	for (i = 0; i < TableElem; i++) {
		if (version_details[i].cc_version == cc_version) break;
	}


	/* Check the compiler  __SUNPRO_C  version */
	if ((i - TableElem > 0) ||
	    (cc_version != version_details[i].cc_version)) {
#if 0
		printError("Unknown",
		    cc_version, lib_version, lib_patch,
		    lib_update, lib_ver_string);
#endif
	return (-1);
	}

	/*
	 * We have at least one line in the table that has info
	 * about this compiler. Let's see how many lines with details
	 * about this compiler do we have. Store the indexes.
	 */
	for (k = 0, j = 0; (k < TableElem) && (j < LIM_CI); k++) {
		if (version_details[k].cc_version == cc_version) {
			CompilerIndex[j++] = k;
		}
	}


	/*
	 * We have a  compiler with an known  __SUNPRO_C
	 * Check the libsunperf version, patch, update and version string
	 */

	for (j = 0; (j < LIM_CI) && (-1 != CompilerIndex[j]); j++) {
		if (strlen(version_details[CompilerIndex[j]].lib_ver_string) !=
		    strlen(lib_ver_string))
	continue;
		if (
		    (0 !=
		    strcmp(version_details[CompilerIndex[j]].lib_ver_string,
		    lib_ver_string))	||
		    (version_details[CompilerIndex[j]].lib_version	!=
		    lib_version) 		||
		    (version_details[CompilerIndex[j]].lib_patch 	!=
		    lib_patch)			||
		    (version_details[CompilerIndex[j]].lib_update	!=
		    lib_update)) {
			continue;
		} else {
			break;
		}
	}

	if (-1 == CompilerIndex[j]) {
#if 0
		printError("Uknown Libsunperf ",
		    cc_version, lib_version, lib_patch,
		    lib_update, lib_ver_string);

		for (j = 0; (j < LIM_CI) && (-1 != CompilerIndex[j]); j++) {
			printError("Expected one of the following:",
			    version_details[CompilerIndex[j]].cc_version,
			    version_details[CompilerIndex[j]].lib_version,
			    version_details[CompilerIndex[j]].lib_patch,
			    version_details[CompilerIndex[j]].lib_update,
			    version_details[CompilerIndex[j]].lib_ver_string);
		}
#endif
		return (-1);
	}

	return (CompilerIndex[j]);
}
