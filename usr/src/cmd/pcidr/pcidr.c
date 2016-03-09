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
#include <sys/systeminfo.h>
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
 * pcidr takes in arguments of the form specified in the help() routine
 * including a set of name=value pairs, then looks up a plugin (shared object)
 * based on <plugin_paths> and however find_plugin() operates.  The entry
 * point of the plugin is <PCIDR_PLUGIN_SYM> and has the type
 * <pcidr_plugin_t>.  Plugins must use the <PCIDR_PLUGIN_PROTO> macro to
 * define their entry point.
 *
 * The name=value arguments are intended to be used as a mechanism to pass
 * arbitrary sysevent attributes using the macro expansion capability provided
 * by the syseventd SLM processing sysevent.conf files (i.e. specifying
 * "$attribute" arguments for the handler in a .conf file entry). They are
 * converted into an nvlist_t (see libnvpair(3LIB)) by converting the values
 * of recognized names into appropriate types using pcidr_name2type() and
 * leaving all others as string types. Because pcidr is used as a sysevent.conf
 * handler, the format of the value string for non-string attributes in each
 * name=value argument must match that used by the syseventd macro capability
 *
 * The plugin will be passed this (nvlist_t *) along with a (pcidr_opt_t *) arg
 * for other options.  While pcidr does some basic checking of arguments, it
 * leaves any name=value check (after conversion) up to each plugin.  Note
 * that pcidr_check_attrs() is used by the default plugin and can be used by
 * any plugin that support the same or a superset of its attributes.  If the
 * default plugin supports additional publishers, it should be updated in
 * pcidr_check_attrs().
 *
 * See help() for an example of how pcidr can be specified in a sysevent.conf
 * file.
 */

/*
 * plugin search paths (searched in order specified);
 * macros begin MACRO_BEGTOK and end with MACRO_ENDTOK;
 *
 * be sure to update parse_path() and its support functions whenever macros
 * are updated e.g. si_name2cmd(), as well as substring tokens (prefix or
 * suffix) used to recognize different types of macros e.g. SI_MACRO
 *
 * NOTE: if plugin search algorithm is changed starting with find_plugin(),
 * please update documentation here.
 *
 * macros:
 * SI_PLATFORM = cmd of same name in sysinfo(2)
 * SI_MACHINE = cmd of same name in sysinfo(2)
 */
#define	MACRO_BEGTOK	"${"
#define	MACRO_ENDTOK	"}"
#define	SI_MACRO	"SI_"

static char *plugin_paths[] = {
	"/usr/platform/${SI_PLATFORM}/lib/pci/" PCIDR_PLUGIN_NAME,
	"/usr/platform/${SI_MACHINE}/lib/pci/" PCIDR_PLUGIN_NAME,
	"/usr/lib/pci/" PCIDR_PLUGIN_NAME,
};
static int plugin_paths_len = sizeof (plugin_paths) / sizeof (plugin_paths[0]);


static nvlist_t *nvlistp = NULL;	/* attribute list */

typedef struct {
	char *name;
	char *beg;
	char *end;
} macro_list_t;
static macro_list_t *parse_macros(char *const, int *);
static void free_macros(macro_list_t *, int);
static char *parse_path(char *const);
static void help();
static void exiter();
static char *find_plugin(nvlist_t *);
static int do_plugin(char *, nvlist_t *, pcidr_opt_t *);
static int nvadd(nvlist_t *, char *, char *, data_type_t);
static nvlist_t *parse_argv_attr(int, char **, int *);
static int si_name2cmd(char *);


static void
help()
{
/* since the handler is not public, we don't expose its usage normally */
#ifdef DEBUG
	(void) printf(
"%s [-h] [-s] [-v <level>] [-l <log_file>] <attributes>\n"
"	-h	help\n"
"\n"
"	-s	turn OFF messages to the syslog (use syslog by default)\n"
"\n"
"	-v	verbose mode; <level> range is %d..%d; default is %d\n"
"\n"
"	-l	also log messages to <log_file> (in addition to using\n"
"		the syslog if that option is not disabled);\n"
"		if <log_file> is '-', stdout is used\n"
"\n"
"	<attributes>\n"
"		whitespace seperated strings of <name>=<value> pairs\n"
"\n"
"Example 1 (command line):\n"
"	%s -s -v%d -l- \\\n"
"		class=EC_dr subclass=ESC_dr_req publisher=pcie_pci \\\n"
"		dr_request_type=dr_request_outgoing_resource \\\n"
"		dr_ap_id=/devices/foo/bar\n"
"\n"
"Example 2 (/etc/sysevent/config/SUNW,sysevent.conf entry):\n"
"	EC_dr ESC_dr_req SUNW pcie_pci - - - %s -v%d -l/tmp/log \\\n"
"		class=$class subclass=$subclass publisher=$publisher \\\n"
"		dr_request_type=$dr_request_type\\\n"
"		dr_ap_id=$dr_ap_id\n"
"\n",
	    prg, MIN_DLVL, MAX_DLVL, dlvl,
	    prg, MAX_DLVL, /* Example 1 */
	    prg, DWARN); /* Example 2 */
#endif
}


/*
 * will convert <value> from a string to the type indicated by <type>
 * and will add it with <name> to nvlist_t <listp>; function returns the same
 * value as nvlist_add_*()
 */
static int
nvadd(nvlist_t *listp, char *name, char *value, data_type_t type)
{
	char *fn = "nvadd";
	int rv = 0;

	switch (type) {
	case DATA_TYPE_STRING:
		rv = nvlist_add_string(listp, name, value);
		if (rv != 0) {
			dprint(DDEBUG, "%s: nvlist_add_string() failed: "
			    "name = %s, value = %s, rv = %d\n",
			    fn, name, value, rv);
		}
		break;
	/*
	 * Conversion must support whatever string format syseventd uses for
	 * its .conf macros; in addition, minimum types supported must match
	 * those for pcidr_name2type()
	 */
	default:
		dprint(DDEBUG, "%s: unsupported type: name = %s, value = %s, "
		    "type = 0x%x\n", fn, name, value, (int)type);
		rv = EINVAL;
	}

	return (rv);
}


/*
 * argc: length of argv
 * argv: each string starting from index <argip> has the format "name=value"
 * argip: starting index in <argv>; also used to return ending index
 *
 * return: allocated nvlist on success, exits otherwise
 *
 * recognized names will have predetermined types, while all others will have
 * values of type string
 */
static nvlist_t *
parse_argv_attr(int argc, char **argv, int *argip)
{
	char *fn = "parse_argv_attr";
	int rv, i;
	nvlist_t *attrlistp = NULL;
	char *eqp, *name, *value;
	data_type_t type;

	assert(*argip < argc);

	rv = nvlist_alloc(&attrlistp, NV_UNIQUE_NAME_TYPE, 0);
	if (rv != 0) {
		dprint(DDEBUG, "%s: nvlist_alloc() failed: rv = %d\n", fn, rv);
		goto ERR;
	}

	for (i = *argip; i < argc; i++) {
		eqp = strchr(argv[i], '=');
		if (eqp == NULL)
			goto ERR_ARG;
		*eqp = '\0';
		name = argv[i];
		value = eqp;
		value++;
		if (*name == '\0' || *value == '\0')
			goto ERR_ARG;

		if (pcidr_name2type(name, &type) != 0)
			type = DATA_TYPE_STRING;

		rv = nvadd(attrlistp, name, value, type);
		if (rv != 0) {
			dprint(DDEBUG, "%s: nvadd() failed: attribute \"%s\", "
			    "value = %s, type = %d, rv = %d\n",
			    fn, name, value, (int)type, rv);
			goto ERR;
		}
		*eqp = '=';
	}

	*argip = i;
	return (attrlistp);

	/*NOTREACHED*/
ERR_ARG:
	if (eqp != NULL)
		*eqp = '=';
	dprint(DDEBUG, "%s: bad attribute argv[%d]: \"%s\"\n", fn, i, argv[i]);
ERR:
	nvlist_free(attrlistp);
	return (NULL);
}


static struct {
	int cmd;
	char *name;
} si_cmd_nametab[] = {
	SI_PLATFORM, "SI_PLATFORM",
	SI_MACHINE, "SI_MACHINE",
};
static int si_cmd_nametab_len =
    sizeof (si_cmd_nametab) / sizeof (si_cmd_nametab[0]);

static int
si_name2cmd(char *name)
{
	int i;

	for (i = 0; i < si_cmd_nametab_len; i++) {
		if (strcmp(name, si_cmd_nametab[i].name) == 0)
			return (si_cmd_nametab[i].cmd);
	}
	return (-1);
}


/*
 * finds occurences of substrings surrounded (delimited) by MACRO_BEGTOK and
 * MACRO_ENDTOK in <str>;
 * returns an allocated array of macro_list_t whose length is
 * returned through <lenp>; array entries will be in order of the occurrence;
 * else returns NULL if none are found
 *
 * macro_list_t members:
 *	char *name = allocated string containing name without macro delimiters
 *	char *beg = location in <str> at _first char_ of MACRO_BEGTOK
 *	char *end = location in <str> at _last char_ of MACRO_ENDTOK
 */
static macro_list_t *
parse_macros(char *const str, int *lenp)
{
	char *beg, *end;
	macro_list_t *lp;
	size_t size;
	int i, begtok_len, endtok_len;

	begtok_len = strlen(MACRO_BEGTOK);
	endtok_len = strlen(MACRO_ENDTOK);

	/* count all occurrences */
	for (beg = str, i = 0; beg != NULL; i++) {
		beg = strstr(beg, MACRO_BEGTOK);
		if (beg == NULL)
			break;
		end = strstr(beg + begtok_len, MACRO_ENDTOK);
		if (end == NULL)
			break;
		beg = end + endtok_len;
	}
	if (i <= 0)
		return (NULL);

	*lenp = i;
	lp = pcidr_malloc(sizeof (macro_list_t) * i);

	for (beg = str, i = 0; i < *lenp; i++) {
		beg = strstr(beg, MACRO_BEGTOK);
		assert(beg != NULL);
		end = strstr(beg + begtok_len, MACRO_ENDTOK);
		assert(end != NULL);

		size = (end - (beg + begtok_len)) + 1;
		lp[i].name = pcidr_malloc(size * sizeof (char));
		(void) strlcpy(lp[i].name, beg + begtok_len, size);

		lp[i].beg = beg;
		lp[i].end = (end + endtok_len) - 1;

		beg = end + endtok_len;
	}

	return (lp);
}

static void
free_macros(macro_list_t *lp, int len)
{
	int i;

	for (i = 0; i < len; i++)
		free(lp[i].name);
	free(lp);
}


/*
 * evaluates any macros in <opath> and returns allocated string on success;
 * else NULL
 */
static char *
parse_path(char *const opath)
{
	char *fn = "parse_path";
	char buf[MAXPATHLEN + 1];
	int bufsize = sizeof (buf) / sizeof (buf[0]);
	char sibuf[257];
	int sibufsize = sizeof (sibuf) / sizeof (sibuf[0]);
	macro_list_t *lp;
	char *path, *pathp, *pathend;
	int rv, i, lplen, si_cmd, pathlen, okmacro, si_macro_len;
	size_t sz;

	/*
	 * make a copy so we can modify it for easier parsing;
	 * lp members will refer to the copy
	 */
	path = strdup(opath);
	lp = parse_macros(path, &lplen);
	if (lp == NULL)
		return (path);

	rv = 0;
	si_macro_len = strlen(SI_MACRO);
	pathlen = strlen(path);
	pathend = &path[pathlen - 1];
	pathp = path;
	buf[0] = '\0';
	for (i = 0; i < lplen; i++) {
		lp[i].beg[0] = '\0';
		sz = strlcat(buf, pathp, bufsize);
		assert(sz < bufsize);

		okmacro = 0;
		if (strncmp(lp[i].name, SI_MACRO, si_macro_len) == 0) {
			si_cmd = si_name2cmd(lp[i].name);
			assert(si_cmd >= 0);

			rv = sysinfo(si_cmd, sibuf, sibufsize);
			if (rv < 0) {
				dprint(DDEBUG, "%s: sysinfo cmd %d failed: "
				    "errno = %d\n", fn, si_cmd, errno);
				goto OUT;
			}

			sz = strlcat(buf, sibuf, bufsize);
			assert(sz < bufsize);
			okmacro = 1;
		}
		/* check for unrecognized macros */
		assert(okmacro);
		pathp = lp[i].end + 1;
	}

	rv = 0;
	if (pathp < pathend) {
		sz = strlcat(buf, pathp, bufsize);
		assert(sz < bufsize);
	}
OUT:
	free_macros(lp, lplen);
	free(path);
	if (rv == 0)
		return (strdup(buf));
	return (NULL);
}


/*
 * returns allocated string containing plugin path which caller must free;
 * else NULL;  <attrlistp> is for future use if attributes can be used to
 * determin plugin
 */
/*ARGSUSED*/
static char *
find_plugin(nvlist_t *attrlistp)
{
	char *fn = "find_plugin";
	char *path = NULL;
	int i, rv;
	struct stat statbuf;

	for (i = 0; i < plugin_paths_len; i++) {
		path = parse_path(plugin_paths[i]);
		if (path == NULL) {
			dprint(DDEBUG, "%s: error parsing path %s\n", fn,
			    path);
			return (NULL);
		}

		rv = stat(path, &statbuf);
		if (rv < 0)
			dprint(DDEBUG, "%s: stat on %s failed: "
			    "errno = %d\n", fn, path, errno);
		else if ((statbuf.st_mode & S_IFMT) != S_IFREG)
			dprint(DDEBUG, "%s: %s is not a regular "
			    "file\n", fn, path);
		else
			return (path);

		free(path);
	}
	return (NULL);
}


/*
 * load plugin specified by <path> and pass the proceeding arguments
 * to the plugin interface;  returns 0 on success (likewise for
 * the plugin function)
 */
static int
do_plugin(char *path, nvlist_t *attrlistp, pcidr_opt_t *optp)
{
	char *fn = "do_plugin";
	int rv;
	void *dlh;
	sigset_t set, oset;
	pcidr_plugin_t fp;

	dlh = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
	if (dlh == NULL) {
		dprint(DDEBUG, "%s: dlopen() failed: %s\n", fn, dlerror());
		rv = EINVAL;
		goto OUT;
	}

	if (sigfillset(&set) != 0) {
		dprint(DDEBUG, "%s: sigfillset() failed: errno = %d\n", fn,
		    errno);
		rv = errno;
		goto OUT;
	}
	if (sigprocmask(SIG_BLOCK, &set, &oset) != 0) {
		dprint(DDEBUG, "%s: blocking signals with sigprocmask() "
		    "failed: errno = %d\n", fn, errno);
		rv = errno;
		goto OUT;
	}

	fp = (pcidr_plugin_t)dlsym(dlh, PCIDR_PLUGIN_SYMSTR);
	if (fp == NULL)  {
		dprint(DDEBUG, "%s: dlsym() failed: %s\n", fn, dlerror());
		rv = EINVAL;
		goto OUT;
	}
	rv = fp(attrlistp, optp);
	if (rv != 0)
		dprint(DDEBUG, "%s: %s() failed: rv = %d\n", fn,
		    PCIDR_PLUGIN_SYMSTR, rv);

	if (sigprocmask(SIG_SETMASK, &oset, NULL) != 0) {
		dprint(DDEBUG, "%s: unblocking signals with sigprocmask() "
		    "failed: errno = %d\n", fn, errno);
		rv = errno;
		goto OUT;
	}
OUT:
	if (dlh != NULL)
		(void) dlclose(dlh);
	return (rv);
}


static void
exiter()
{
	extern FILE *dfp;

	if (nvlistp != NULL)
		nvlist_free(nvlistp);
	if (dfp != NULL)
		(void) fclose(dfp);
#ifdef DEBUG
	closelog();
#endif
}


int
main(int argc, char **argv)
{
	int rv, argi;
	char *dfile = NULL, *plugin_path = NULL;
	struct stat statbuf;
	pcidr_opt_t plugin_opt;
	char *optstr = NULL;

	extern char *optarg;
	extern int optind, optopt;
	int c;

	/*CONSTCOND*/
	assert(MIN_DLVL == 0);
	/*CONSTCOND*/
	assert(MIN_DLVL == DNONE);
	assert(MAX_DLVL == dpritab_len - 1);

	(void) atexit(exiter);
	prg = argv[0];
	dfp = NULL;

#ifdef DEBUG
	openlog(prg, LOG_PID | LOG_CONS, LOG_DAEMON);
	dlvl = DWARN;
	dsys = 1;
	optstr = "hsv:l:";
#else
	dlvl = DNONE;
	dsys = 0;
	optstr = "sv:l:";
#endif

	while ((c = getopt(argc, argv, optstr)) != -1) {
		switch (c) {
		case 'h':
			help();
			exit(0);
			break;
		case 's':
			dsys = 0;
			break;
		case 'v':
			dlvl = atoi(optarg);
			break;
		case 'l':
			dfile = optarg;
			break;
		default:
			dprint(DWARN, "bad option: %c\n", optopt);
			return (EINVAL);
		}
	}

	/*
	 * [ -l ] do file option first so we can still get msgs if -s is used
	 */
	if (dfile != NULL) {
		if (strcmp(dfile, "-") == 0) {
			/* ignore if stdout is not open/valid */
			dfp = NULL;
			if (stdout != NULL &&
			    fstat(fileno(stdout), &statbuf) == 0)
				dfp = stdout;
		} else {
			dfp = fopen(dfile, "a");
			if (dfp == NULL) {
				dprint(DWARN, "cannot open %s: %s\n",
				    dfile, strerror(errno));
				return (EINVAL);
			}
		}
	}

	/* [ -v ] */
	if (dlvl < MIN_DLVL || dlvl > MAX_DLVL) {
		dprint(DWARN, "bad arg for -v: %d\n", dlvl);
		return (EINVAL);
	}

	argi = optind;
	if (argi >= argc) {
		dprint(DWARN, "missing attribute arguments\n");
		return (EINVAL);
	}

	nvlistp = parse_argv_attr(argc, argv, &argi);
	if (nvlistp == NULL) {
		dprint(DWARN, "attribute parsing error\n");
		return (EINVAL);
	}

	(void) memset(&plugin_opt, 0, sizeof (plugin_opt));
	plugin_opt.logopt.dlvl = dlvl;
	plugin_opt.logopt.prg = prg;
	plugin_opt.logopt.dfp = dfp;
	plugin_opt.logopt.dsys = dsys;

	dprint(DINFO, "=== sysevent attributes ========================\n");
	pcidr_print_attrlist(DINFO, nvlistp, NULL);
	dprint(DINFO, "================================================\n");

	plugin_path = find_plugin(nvlistp);
	if (plugin_path == NULL) {
		dprint(DWARN, "cannot find plugin\n");
		return (EINVAL);
	}
	dprint(DINFO, "using plugin: %s\n\n", plugin_path);

	rv = do_plugin(plugin_path, nvlistp, &plugin_opt);
	if (rv != 0) {
		dprint(DWARN, "plugin %s failed\n", plugin_path);
	}
	if (plugin_path != NULL)
		free(plugin_path);
	return (rv);
}
