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
 * Copyright (c) 2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <dlfcn.h>
#include <sys/systeminfo.h>
#include <sys/utsname.h>

#include <fcode/private.h>
#include <fcode/log.h>

#include <fcdriver/fcdriver.h>

static char *default_search_path;
static char search_proto[] =
	"/usr/platform/%s/lib/efcode%s:"
	"/usr/platform/%s/lib/efcode%s:"
	"/usr/lib/efcode%s";

/*
 * Build the library/drop-in fcode search path.  If there's no architecture
 * passed, we build the search path (per the PSARC decision):
 *      /usr/platform/`uname -i`/lib/efcode
 *      /usr/platform/`uname -m`/lib/efcode
 *      /usr/lib/efcode
 * If there is an architecture passed, we prepend the following search path to
 * the above:
 *      /usr/platform/`uname -i`/lib/efcode/{architecture}
 *	/usr/platform/`uname -m`/lib/efcode/{architecture}
 *	/usr/lib/efcode/{architecture}
 * This allows FCode drop-in searches to find FCode in the non-architecture
 * directories.
 */
static void
build_default_search_path(char *arch)
{
	char platform[100], *p;
	struct stat statb;
	struct utsname utsname;
	int len;

	sysinfo(SI_PLATFORM, platform, sizeof (platform));
	uname(&utsname);
	len = strlen(search_proto) + strlen(platform) + strlen(utsname.machine);
	if (*arch != '\0') {
		len += len + (3 * strlen(arch)) + 1;
	}
	default_search_path = MALLOC(len);
	if (*arch != '\0') {
		sprintf(default_search_path, search_proto, platform, arch,
		    utsname.machine, arch, arch);
		p = default_search_path + strlen(default_search_path);
		*p++ = ':';
	} else
		p = default_search_path;

	sprintf(p, search_proto, platform, "", utsname.machine, "", "");
}

static void
set_default_search_path(fcode_env_t *env)
{
	if (default_search_path)
		FREE(default_search_path);

	parse_word(env);
	default_search_path = pop_a_duped_string(env, NULL);
}

static void
get_default_search_path(fcode_env_t *env)
{
	push_a_string(env, default_search_path);
}

/*
 * Complicated by fact that a library (e.g. a 32-bit library) can match the
 * file name.  But if we're running as 64-bit, dlopen on that library will
 * fail.
 */
static char *
search_path(char *name, char *search, int (*fn)(char *))
{
	char *p, *next_p;
	char *tpath, *fpath;

	fpath = STRDUP(search);
	for (p = fpath; p != NULL; p = next_p) {
		if ((next_p = strchr(p, ':')) != NULL)
			*next_p++ = '\0';
		tpath = MALLOC(strlen(p) + strlen(name) + 2);
		sprintf(tpath, "%s/%s", p, name);
		if ((*fn)(tpath)) {
			FREE(fpath);
			return (tpath);
		}
		FREE(tpath);
	}
	FREE(fpath);
	return (NULL);
}

static int
load_lib_file(char *path)
{
	struct stat buf;

	debug_msg(DEBUG_FIND_FCODE, "load_lib_file: '%s' -> ", path);
	if (stat(path, &buf)) {
		debug_msg(DEBUG_FIND_FCODE, "stat failed\n");
		return (0);
	}
	if (dlopen(path, RTLD_NOW) != NULL) {
		debug_msg(DEBUG_FIND_FCODE, "OK\n");
		return (1);
	}
	debug_msg(DEBUG_FIND_FCODE, "dlopen failed\n");
	return (0);
}

static int
is_fcode_file(char *path)
{
	struct stat statb;
	int fd;
	uchar_t header[8];
	int status;
	static char func_name[] = "is_fcode_file";
	extern int check_fcode_header(char *, uchar_t *, int);

	debug_msg(DEBUG_FIND_FCODE, "%s: '%s' -> ", func_name, path);
	if ((fd = open(path, 0)) < 0) {
		debug_msg(DEBUG_FIND_FCODE, "%s: '%s' can't open\n", func_name,
		    path);
		return (0);
	}
	if (fstat(fd, &statb) != 0 || read(fd, header, sizeof (header)) < 0) {
		debug_msg(DEBUG_FIND_FCODE, "%s: '%s' can't fstat/read\n",
		    func_name, path);
		close(fd);
		return (0);
	}
	status = check_fcode_header(path, header, statb.st_size);
	debug_msg(DEBUG_FIND_FCODE, "%s: '%s' format %s\n", func_name, path,
	    status ? "OK" : "NOT OK");
	close(fd);
	return (status);
}

static char *
find_lib_file(fcode_env_t *env, char *prefix, char *name, char *suffix,
    int (*fn)(char *))
{
	char *search, *fname;
	char *lib_name;
	common_data_t *cdp = env->private;

	if ((search = cdp->search_path) == NULL &&
	    (search = default_search_path) == NULL) {
		log_message(MSG_ERROR, "find_lib_file: no search path\n");
		return (NULL);
	}

	lib_name = MALLOC(strlen(name) + strlen(prefix) + strlen(suffix) + 1);
	sprintf(lib_name, "%s%s%s", prefix, name, suffix);
	fname = search_path(lib_name, search, fn);
	FREE(lib_name);
	return (fname);
}

char *
search_for_fcode_file(fcode_env_t *env, char *basename)
{
	return (find_lib_file(env, "", basename, ".fc", is_fcode_file));
}

static void
load_appropriate_file(fcode_env_t *env, char *name, device_t *d)
{
	char *fname;

	if ((fname = find_lib_file(env, "lfc_", name, ".so", load_lib_file))
	    != NULL) {
		debug_msg(DEBUG_FIND_FCODE, "Loading Library: %s\n", fname);
		FREE(fname);
	} else if ((fname = search_for_fcode_file(env, name)) != NULL) {
		debug_msg(DEBUG_FIND_FCODE, "Loading Fcode: %s\n", fname);
		run_fcode_from_file(env, fname, 0);
		FREE(fname);
	} else {
		throw_from_fclib(env, 1,
		    "Can't find 'lfc_%s.so' or '%s.fc'\n", name, name);
	}
}

void
install_node_data(fcode_env_t *env, device_t *d)
{
	prop_t *p;
	device_t *cd;
	char libname[512];
	static char func_name[] = "install_node_data";

	if (d->parent) {
		if ((p = lookup_package_property(env, "device_type",
		    d->parent)) == NULL) {
			log_message(MSG_ERROR, "%s: no 'device_type' property"
			    " for '%s'\n", func_name, get_path(env, d->parent));
			return;
		}
		/*
		 * Warning: lookup_package_property uses a static data area to
		 * build the property node returned, so we have to grab a copy
		 * of the data.
		 */
		strcpy(libname, (char *)p->data);
		strcat(libname, "_");
	} else
		libname[0] = '\0';

	if ((p = lookup_package_property(env, "device_type", d)) == NULL) {
		log_message(MSG_ERROR, "%s: no 'device_type' property for"
		    " '%s'\n", func_name, get_path(env, d));
		return;
	}

	/*
	 * Warning: lookup_package_property uses a static data area to build
	 * the property node returned, so we have to grab a copy of the
	 * data.
	 */
	strcat(libname, (char *)p->data);

	debug_msg(DEBUG_FIND_FCODE, "%s: `%s` lname: '%s'\n", func_name,
	    get_path(env, d), libname);

	load_appropriate_file(env, libname, d);
}

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	ASSERT(env);
	NOTICE;

#if defined(__sparcv9)
	build_default_search_path("/sparcv9");
#else
	build_default_search_path("");
#endif
	FORTH(0, "set-default-search-path",	set_default_search_path);
	FORTH(0, "get-default-search-path",	get_default_search_path);
}
