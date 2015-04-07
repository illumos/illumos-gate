/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Garrett D'Amore <garrett@damore.org>
 */

/*
 * This program tests symbol visibility using the /usr/bin/c89 and
 * /usr/bin/c99 programs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <note.h>
#include <sys/wait.h>
#include "test_common.h"

char *dname;
char *cfile;
char *ofile;
char *lfile;
char *efile;

const char *sym = NULL;

static int good_count = 0;
static int fail_count = 0;
static int full_count = 0;
static int extra_debug = 0;
static char *compilation = "compilation.cfg";

#if defined(_LP64)
#define	MFLAG "-m64"
#elif defined(_ILP32)
#define	MFLAG "-m32"
#endif

const char *compilers[] = {
	"cc",
	"gcc",
	"/opt/SUNWspro/bin/cc",
	"/opt/gcc/4.4.4/bin/gcc",
	"/opt/sunstudio12.1/bin/cc",
	"/opt/sfw/bin/gcc",
	"/usr/local/bin/gcc",
	NULL
};

char *compiler = NULL;
const char *c89flags = NULL;
const char *c99flags = NULL;

#define	MAXENV	64	/* maximum number of environments (bitmask width) */
#define	MAXHDR	10	/* maximum # headers to require to access symbol */
#define	MAXARG	20	/* maximum # of arguments */

#define	WS	" \t"

static int next_env = 0;

struct compile_env {
	char		*ce_name;
	char		*ce_lang;
	char		*ce_defs;
	int		ce_index;
};

static struct compile_env compile_env[MAXENV];

struct env_group {
	char			*eg_name;
	uint64_t		eg_mask;
	struct env_group	*eg_next;
};

typedef enum { SYM_TYPE, SYM_VALUE, SYM_FUNC } sym_type_t;

struct sym_test {
	char			*st_name;
	sym_type_t		st_type;
	char			*st_hdrs[MAXHDR];
	char			*st_rtype;
	char			*st_atypes[MAXARG];
	uint64_t		st_test_mask;
	uint64_t		st_need_mask;
	char			*st_prog;
	struct sym_test		*st_next;
};

struct env_group *env_groups = NULL;

struct sym_test *sym_tests = NULL;
struct sym_test **sym_insert = &sym_tests;

static char *
mystrdup(const char *s)
{
	char *r;
	if ((r = strdup(s)) == NULL) {
		perror("strdup");
		exit(1);
	}
	return (r);
}

static void *
myzalloc(size_t sz)
{
	void *buf;
	if ((buf = calloc(1, sz)) == NULL) {
		perror("calloc");
		exit(1);
	}
	return (buf);
}

static void
myasprintf(char **buf, const char *fmt, ...)
{
	int rv;
	va_list va;
	va_start(va, fmt);
	rv = vasprintf(buf, fmt, va);
	va_end(va);
	if (rv < 0) {
		perror("vasprintf");
		exit(1);
	}
}

static void
append_sym_test(struct sym_test *st)
{
	*sym_insert = st;
	sym_insert = &st->st_next;
}

static int
find_env_mask(const char *name, uint64_t *mask)
{
	for (int i = 0; i < MAXENV; i++) {
		if (compile_env[i].ce_name != NULL &&
		    strcmp(compile_env[i].ce_name, name) == 0) {
			*mask |= (1ULL << i);
			return (0);
		}
	}

	for (struct env_group *eg = env_groups; eg != NULL; eg = eg->eg_next) {
		if (strcmp(name, eg->eg_name) == 0) {
			*mask |= eg->eg_mask;
			return (0);
		}
	}
	return (-1);
}


static int
expand_env(char *list, uint64_t *mask, char **erritem)
{
	char *item;
	for (item = strtok(list, WS); item != NULL; item = strtok(NULL, WS)) {
		if (find_env_mask(item, mask) < 0) {
			if (erritem != NULL) {
				*erritem = item;
			}
			return (-1);
		}
	}
	return (0);
}

static int
expand_env_list(char *list, uint64_t *test, uint64_t *need, char **erritem)
{
	uint64_t mask = 0;
	int act;
	char *item;
	for (item = strtok(list, WS); item != NULL; item = strtok(NULL, WS)) {
		switch (item[0]) {
		case '+':
			act = 1;
			item++;
			break;
		case '-':
			act = 0;
			item++;
			break;
		default:
			act = 1;
			break;
		}

		mask = 0;
		if (find_env_mask(item, &mask) < 0) {
			if (erritem != NULL) {
				*erritem = item;
			}
			return (-1);
		}
		*test |= mask;
		if (act) {
			*need |= mask;
		} else {
			*need &= ~(mask);
		}
	}
	return (0);
}

static int
do_env(char **fields, int nfields, char **err)
{
	char *name;
	char *lang;
	char *defs;

	if (nfields != 3) {
		myasprintf(err, "number of fields (%d) != 3", nfields);
		return (-1);
	}

	if (next_env >= MAXENV) {
		myasprintf(err, "too many environments");
		return (-1);
	}

	name = fields[0];
	lang = fields[1];
	defs = fields[2];

	compile_env[next_env].ce_name = mystrdup(name);
	compile_env[next_env].ce_lang = mystrdup(lang);
	compile_env[next_env].ce_defs = mystrdup(defs);
	compile_env[next_env].ce_index = next_env;
	next_env++;
	return (0);
}

static int
do_env_group(char **fields, int nfields, char **err)
{
	char *name;
	char *list;
	struct env_group *eg;
	uint64_t mask;
	char *item;

	if (nfields != 2) {
		myasprintf(err, "number of fields (%d) != 2", nfields);
		return (-1);
	}

	name = fields[0];
	list = fields[1];
	mask = 0;

	if (expand_env(list, &mask, &item) < 0) {
		myasprintf(err, "reference to undefined env %s", item);
		return (-1);
	}

	eg = myzalloc(sizeof (*eg));
	eg->eg_name = mystrdup(name);
	eg->eg_mask = mask;
	eg->eg_next = env_groups;
	env_groups = eg;
	return (0);
}

static char *progbuf = NULL;
size_t proglen = 0;
size_t progsiz = 0;

static void
addprogch(char c)
{
	while (progsiz <= (proglen + 1)) {
		progbuf = realloc(progbuf, progsiz + 4096);
		if (progbuf == NULL) {
			perror("realloc");
			exit(1);
		}
		progsiz += 1024;
	}
	progbuf[proglen++] = c;
	progbuf[proglen] = 0;
}

static void
addprogstr(char *s)
{
	while (*s != NULL) {
		addprogch(*s);
		s++;
	}
}

static void
addprogfmt(const char *fmt, ...)
{
	va_list va;
	char *buf = NULL;
	va_start(va, fmt);
	if (vasprintf(&buf, fmt, va) < 0) {
		perror("vasprintf");
		exit(1);
	}
	va_end(va);
	addprogstr(buf);
	free(buf);
}

static void
mkprog(struct sym_test *st)
{
	char *s;

	proglen = 0;

	for (int i = 0; i < MAXHDR && st->st_hdrs[i] != NULL; i++) {
		addprogfmt("#include <%s>\n", st->st_hdrs[i]);
	}

	for (s = st->st_rtype; *s; s++) {
		addprogch(*s);
		if (*s == '(') {
			s++;
			addprogch(*s);
			s++;
			break;
		}
	}
	addprogch(' ');

	/* for function pointers, s is closing suffix, otherwise empty */

	switch (st->st_type) {
	case SYM_TYPE:
		addprogstr("test_type;");
		break;

	case SYM_VALUE:
		addprogfmt("test_value%s;\n", s);	/* s usually empty */
		addprogstr("void\ntest_func(void)\n{\n");
		addprogfmt("\ttest_value = %s;\n}", st->st_name);
		break;

	case SYM_FUNC:
		addprogstr("\ntest_func(");
		for (int i = 0; st->st_atypes[i] != NULL && i < MAXARG; i++) {
			int didname = 0;
			if (i > 0) {
				addprogstr(", ");
			}
			if (strcmp(st->st_atypes[i], "void") == 0) {
				didname = 1;
			}
			if (strcmp(st->st_atypes[i], "") == 0) {
				didname = 1;
				addprogstr("void");
			}

			/* print the argument list */
			for (char *a = st->st_atypes[i]; *a; a++) {
				if (*a == '(' && a[1] == '*' && !didname) {
					addprogfmt("(*a%d", i);
					didname = 1;
					a++;
				} else if (*a == '[' && !didname) {
					addprogfmt("a%d[", i);
					didname = 1;
				} else {
					addprogch(*a);
				}
			}
			if (!didname) {
				addprogfmt(" a%d", i);
			}
		}

		if (st->st_atypes[0] == NULL) {
			addprogstr("void");
		}

		/*
		 * Close argument list, and closing ")" for func ptrs.
		 * Note that for non-function pointers, s will be empty
		 * below, otherwise it points to the trailing argument
		 * list.
		 */
		addprogfmt(")%s\n{\n\t", s);

		if (strcmp(st->st_rtype, "") != 0 &&
		    strcmp(st->st_rtype, "void") != 0) {
			addprogstr("return ");
		}

		/* add the function call */
		addprogfmt("%s(", st->st_name);
		for (int i = 0; st->st_atypes[i] != NULL && i < MAXARG; i++) {
			if (strcmp(st->st_atypes[i], "") != 0 &&
			    strcmp(st->st_atypes[i], "void") != 0) {
				addprogfmt("%sa%d", i > 0 ? ", " : "", i);
			}
		}

		addprogstr(");\n}");
		break;
	}

	addprogch('\n');

	st->st_prog = progbuf;
}

static int
add_envs(struct sym_test *st, char *envs, char **err)
{
	char *item;
	if (expand_env_list(envs, &st->st_test_mask, &st->st_need_mask,
	    &item) < 0) {
		myasprintf(err, "bad env action %s", item);
		return (-1);
	}
	return (0);
}

static int
add_headers(struct sym_test *st, char *hdrs, char **err)
{
	int i = 0;

	for (char *h = strsep(&hdrs, ";"); h != NULL; h = strsep(&hdrs, ";")) {
		if (i >= MAXHDR) {
			myasprintf(err, "too many headers");
			return (-1);
		}
		test_trim(&h);
		st->st_hdrs[i++] = mystrdup(h);
	}

	return (0);
}

static int
add_arg_types(struct sym_test *st, char *atype, char **err)
{
	int i = 0;
	char *a;
	for (a = strsep(&atype, ";"); a != NULL; a = strsep(&atype, ";")) {
		if (i >= MAXARG) {
			myasprintf(err, "too many arguments");
			return (-1);
		}
		test_trim(&a);
		st->st_atypes[i++] = mystrdup(a);
	}

	return (0);
}

static int
do_type(char **fields, int nfields, char **err)
{
	char *decl;
	char *hdrs;
	char *envs;
	struct sym_test *st;

	if (nfields != 3) {
		myasprintf(err, "number of fields (%d) != 3", nfields);
		return (-1);
	}
	decl = fields[0];
	hdrs = fields[1];
	envs = fields[2];

	st = myzalloc(sizeof (*st));
	st->st_type = SYM_TYPE;
	st->st_name = mystrdup(decl);
	st->st_rtype = mystrdup(decl);

	if ((add_envs(st, envs, err) < 0) ||
	    (add_headers(st, hdrs, err) < 0)) {
		return (-1);
	}
	append_sym_test(st);

	return (0);
}

static int
do_value(char **fields, int nfields, char **err)
{
	char *name;
	char *type;
	char *hdrs;
	char *envs;
	struct sym_test *st;

	if (nfields != 4) {
		myasprintf(err, "number of fields (%d) != 4", nfields);
		return (-1);
	}
	name = fields[0];
	type = fields[1];
	hdrs = fields[2];
	envs = fields[3];

	st = myzalloc(sizeof (*st));
	st->st_type = SYM_VALUE;
	st->st_name = mystrdup(name);
	st->st_rtype = mystrdup(type);

	if ((add_envs(st, envs, err) < 0) ||
	    (add_headers(st, hdrs, err) < 0)) {
		return (-1);
	}
	append_sym_test(st);

	return (0);
}

static int
do_func(char **fields, int nfields, char **err)
{
	char *name;
	char *rtype;
	char *atype;
	char *hdrs;
	char *envs;
	struct sym_test *st;

	if (nfields != 5) {
		myasprintf(err, "number of fields (%d) != 5", nfields);
		return (-1);
	}
	name = fields[0];
	rtype = fields[1];
	atype = fields[2];
	hdrs = fields[3];
	envs = fields[4];

	st = myzalloc(sizeof (*st));
	st->st_type = SYM_FUNC;
	st->st_name = mystrdup(name);
	st->st_rtype = mystrdup(rtype);

	if ((add_envs(st, envs, err) < 0) ||
	    (add_headers(st, hdrs, err) < 0) ||
	    (add_arg_types(st, atype, err) < 0)) {
		return (-1);
	}
	append_sym_test(st);

	return (0);
}

struct sym_test *
next_sym_test(struct sym_test *st)
{
	return (st == NULL ? sym_tests : st->st_next);
}

const char *
sym_test_prog(struct sym_test *st)
{
	if (st->st_prog == NULL) {
		mkprog(st);
	}
	return (st->st_prog);
}

const char *
sym_test_name(struct sym_test *st)
{
	return (st->st_name);
}

/*
 * Iterate through tests.  Pass in NULL for cenv to begin the iteration. For
 * subsequent iterations, use the return value from the previous iteration.
 * Returns NULL when there are no more environments.
 */
struct compile_env *
sym_test_env(struct sym_test *st, struct compile_env *cenv, int *need)
{
	int i = cenv ? cenv->ce_index + 1: 0;
	uint64_t b = 1ULL << i;

	while ((i < MAXENV) && (b != 0)) {
		cenv = &compile_env[i];
		if (b & st->st_test_mask) {
			*need = (st->st_need_mask & b) ? 1 : 0;
			return (cenv);
		}
		b <<= 1;
		i++;
	}
	return (NULL);
}

const char *
env_name(struct compile_env *cenv)
{
	return (cenv->ce_name);
}

const char *
env_lang(struct compile_env *cenv)
{
	return (cenv->ce_lang);
}

const char *
env_defs(struct compile_env *cenv)
{
	return (cenv->ce_defs);
}

static void
show_file(test_t t, const char *path)
{
	FILE *f;
	char *buf = NULL;
	size_t cap = 0;
	int line = 1;

	f = fopen(path, "r");
	if (f == NULL) {
		test_debugf(t, "fopen(%s): %s", path, strerror(errno));
		return;
	}

	test_debugf(t, "----->> begin (%s) <<------", path);
	while (getline(&buf, &cap, f) >= 0) {
		(void) strtok(buf, "\r\n");
		test_debugf(t, "%d: %s", line, buf);
		line++;
	}
	test_debugf(t, "----->> end (%s) <<------", path);
	(void) fclose(f);
}

static void
cleanup(void)
{
	if (ofile != NULL) {
		(void) unlink(ofile);
		free(ofile);
		ofile = NULL;
	}
	if (lfile != NULL) {
		(void) unlink(lfile);
		free(lfile);
		lfile = NULL;
	}
	if (cfile != NULL) {
		(void) unlink(cfile);
		free(cfile);
		cfile = NULL;
	}
	if (efile != NULL) {
		(void) unlink(efile);
		free(efile);
		efile = NULL;
	}
	if (dname) {
		(void) rmdir(dname);
		free(dname);
		dname = NULL;
	}
}

static int
mkworkdir(void)
{
	char b[32];
	char *d;

	cleanup();

	(void) strlcpy(b, "/tmp/symbols_testXXXXXX", sizeof (b));
	if ((d = mkdtemp(b)) == NULL) {
		perror("mkdtemp");
		return (-1);
	}
	dname = mystrdup(d);
	myasprintf(&cfile, "%s/compile_test.c", d);
	myasprintf(&ofile, "%s/compile_test.o", d);
	myasprintf(&lfile, "%s/compile_test.log", d);
	myasprintf(&efile, "%s/compile_test.exe", d);
	return (0);
}

void
find_compiler(void)
{
	test_t t;
	int i;
	FILE *cf;

	t = test_start("finding compiler");

	if ((cf = fopen(cfile, "w+")) == NULL) {
		test_failed(t, "Unable to open %s for write: %s", cfile,
		    strerror(errno));
		return;
	}
	(void) fprintf(cf, "#include <stdio.h>\n");
	(void) fprintf(cf, "int main(int argc, char **argv) {\n");
	(void) fprintf(cf, "#if defined(__SUNPRO_C)\n");
	(void) fprintf(cf, "exit(51);\n");
	(void) fprintf(cf, "#elif defined(__GNUC__)\n");
	(void) fprintf(cf, "exit(52);\n");
	(void) fprintf(cf, "#else\n");
	(void) fprintf(cf, "exit(99)\n");
	(void) fprintf(cf, "#endif\n}\n");
	(void) fclose(cf);

	for (i = 0; compilers[i] != NULL; i++) {
		char cmd[256];
		int rv;

		(void) snprintf(cmd, sizeof (cmd),
		    "%s %s %s -o %s >/dev/null 2>&1",
		    compilers[i], MFLAG, cfile, efile);
		test_debugf(t, "trying %s", cmd);
		rv = system(cmd);

		test_debugf(t, "result: %d", rv);

		if ((rv < 0) || !WIFEXITED(rv) || WEXITSTATUS(rv) != 0)
			continue;

		rv = system(efile);
		if (rv >= 0 && WIFEXITED(rv)) {
			rv = WEXITSTATUS(rv);
		} else {
			rv = -1;
		}

		switch (rv) {
		case 51:	/* STUDIO */
			test_debugf(t, "Found Studio C");
			c89flags = "-Xc -errwarn=%all -v -xc99=%none " MFLAG;
			c99flags = "-Xc -errwarn=%all -v -xc99=%all " MFLAG;
			if (extra_debug) {
				test_debugf(t, "c89flags: %s", c89flags);
				test_debugf(t, "c99flags: %s", c99flags);
			}
			test_passed(t);
			break;
		case 52:	/* GCC */
			test_debugf(t, "Found GNU C");
			c89flags = "-Wall -Werror -std=c89 " MFLAG;
			c99flags = "-Wall -Werror -std=c99 " MFLAG;
			if (extra_debug) {
				test_debugf(t, "c89flags: %s", c89flags);
				test_debugf(t, "c99flags: %s", c99flags);
			}
			test_passed(t);
			break;
		case 99:
			test_debugf(t, "Found unknown (unsupported) compiler");
			continue;
		default:
			continue;
		}
		myasprintf(&compiler, "%s", compilers[i]);
		test_debugf(t, "compiler: %s", compiler);
		return;
	}
	test_failed(t, "No compiler found.");
}

int
do_compile(test_t t, struct sym_test *st, struct compile_env *cenv, int need)
{
	char *cmd;
	FILE *logf;
	FILE *dotc;
	const char *prog;

	full_count++;

	if ((dotc = fopen(cfile, "w+")) == NULL) {
		test_failed(t, "fopen(%s): %s", cfile, strerror(errno));
		return (-1);
	}
	prog = sym_test_prog(st);
	if (fwrite(prog, 1, strlen(prog), dotc) < strlen(prog)) {
		test_failed(t, "fwrite: %s", strerror(errno));
		(void) fclose(dotc);
		return (-1);
	}
	if (fclose(dotc) < 0) {
		test_failed(t, "fclose: %s", strerror(errno));
		return (-1);
	}

	(void) unlink(ofile);

	myasprintf(&cmd, "%s %s %s -c %s -o %s >>%s 2>&1",
	    compiler, strcmp(env_lang(cenv), "c99") == 0 ? c99flags : c89flags,
	    env_defs(cenv), cfile, ofile, lfile);

	if (extra_debug) {
		test_debugf(t, "command: %s", cmd);
	}

	if ((logf = fopen(lfile, "w+")) == NULL) {
		test_failed(t, "fopen: %s", strerror(errno));
		return (-1);
	}
	(void) fprintf(logf, "===================\n");
	(void) fprintf(logf, "PROGRAM:\n%s\n", sym_test_prog(st));
	(void) fprintf(logf, "COMMAND: %s\n", cmd);
	(void) fprintf(logf, "EXPECT: %s\n", need ? "OK" : "FAIL");
	(void) fclose(logf);

	switch (system(cmd)) {
	case -1:
		test_failed(t, "error compiling in %s: %s", env_name(cenv),
		    strerror(errno));
		return (-1);
	case 0:
		if (!need) {
			fail_count++;
			show_file(t, lfile);
			test_failed(t, "symbol visible in %s", env_name(cenv));
			return (-1);
		}
		break;
	default:
		if (need) {
			fail_count++;
			show_file(t, lfile);
			test_failed(t, "error compiling in %s", env_name(cenv));
			return (-1);
		}
		break;
	}
	good_count++;
	return (0);
}

void
test_compile(void)
{
	struct sym_test *st;
	struct compile_env *cenv;
	test_t t;
	int need;

	for (st = next_sym_test(NULL); st; st = next_sym_test(st)) {
		if ((sym != NULL) && strcmp(sym, sym_test_name(st))) {
			continue;
		}
		/* XXX: we really want a sym_test_desc() */
		for (cenv = sym_test_env(st, NULL, &need);
		    cenv != NULL;
		    cenv = sym_test_env(st, cenv, &need)) {
			t = test_start("%s : %c%s", sym_test_name(st),
			    need ? '+' : '-', env_name(cenv));
			if (do_compile(t, st, cenv, need) == 0) {
				test_passed(t);
			}
		}
	}

	if (full_count > 0) {
		test_summary();
	}
}

int
main(int argc, char **argv)
{
	int optc;
	int optC = 0;

	while ((optc = getopt(argc, argv, "DdfCs:c:")) != EOF) {
		switch (optc) {
		case 'd':
			test_set_debug();
			break;
		case 'f':
			test_set_force();
			break;
		case 'D':
			test_set_debug();
			extra_debug++;
			break;
		case 'c':
			compilation = optarg;
			break;
		case 'C':
			optC++;
			break;
		case 's':
			sym = optarg;
			break;
		default:
			(void) fprintf(stderr, "Usage: %s [-df]\n", argv[0]);
			exit(1);
		}
	}

	if (test_load_config(NULL, compilation,
	    "env", do_env, "env_group", do_env_group, NULL) < 0) {
		exit(1);
	}

	while (optind < argc) {
		if (test_load_config(NULL, argv[optind++],
		    "type", do_type,
		    "value", do_value,
		    "func", do_func,
		    NULL) < 0) {
			exit(1);
		}
	}

	if (atexit(cleanup) != 0) {
		perror("atexit");
		exit(1);
	}

	if (mkworkdir() < 0) {
		perror("mkdir");
		exit(1);
	}

	find_compiler();
	if (!optC)
		test_compile();

	exit(0);
}
