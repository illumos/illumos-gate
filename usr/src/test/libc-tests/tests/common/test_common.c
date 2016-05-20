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
 * Common handling for test programs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/param.h>
#include "test_common.h"

static int debug = 0;
static int force = 0;
static pthread_mutex_t lk;

static int passes;
static int tests;

struct test {
	char		*name;
	int		ntids;
	pthread_t	*tids;
	int		fails;
	void		*arg;
	void		(*func)(test_t t, void *);
};

void
test_set_debug(void)
{
	debug++;
}

void
test_set_force(void)
{
	force++;
}

test_t
test_start(const char *format, ...)
{
	va_list args;
	test_t t;
	char *s;

	t = calloc(1, sizeof (*t));
	va_start(args, format);
	(void) vasprintf(&s, format, args);
	va_end(args);

	(void) asprintf(&t->name, "%s (%s)", s, ARCH);
	free(s);

	(void) pthread_mutex_lock(&lk);
	(void) printf("TEST STARTING %s:\n", t->name);
	(void) fflush(stdout);
	(void) pthread_mutex_unlock(&lk);

#ifdef	LINT
	/* We inject references to make avoid name unused warnings */
	test_run(0, NULL, NULL, NULL);
	test_debugf(t, NULL);
	test_failed(t, NULL);
	test_passed(t);
	test_set_debug();
	test_set_force();
	test_summary();
	(void) test_load_config(t, NULL, NULL);
#endif

	tests++;
	return (t);
}

void
test_failed(test_t t, const char *format, ...)
{
	va_list args;

	(void) pthread_mutex_lock(&lk);
	if (t == NULL) {
		(void) printf("FAILURE: ");
		va_start(args, format);
		(void) vprintf(format, args);
		va_end(args);
		(void) printf("\n");
		(void) fflush(stdout);
		(void) pthread_mutex_unlock(&lk);
		return;
	}
	if (force || (t->ntids > 0)) {
		(void) printf("TEST FAILING %s: ", t->name);
	} else {
		(void) printf("TEST FAILED %s: ", t->name);
	}

	va_start(args, format);
	(void) vprintf(format, args);
	va_end(args);
	(void) printf("\n");
	(void) fflush(stdout);
	(void) pthread_mutex_unlock(&lk);

	t->fails++;
	if (!force) {
		if (t->ntids > 0) {
			pthread_exit(NULL);
		} else {
			(void) exit(EXIT_FAILURE);
		}
	}
}

void
test_passed(test_t t)
{
	if (t == NULL) {
		return;
	}
	if (t->ntids > 0) {
		if (debug) {
			(void) pthread_mutex_lock(&lk);
			(void) printf("TEST PASSING: %s\n", t->name);
			(void) pthread_mutex_unlock(&lk);
		}
		return;
	}
	(void) pthread_mutex_lock(&lk);
	if (t->fails == 0) {
		passes++;
		(void) printf("TEST PASS: %s\n", t->name);
	} else {
		(void) printf("TEST FAILED: %d failures\n", t->fails);
	}
	(void) fflush(stdout);
	(void) pthread_mutex_unlock(&lk);
	free(t->name);
	if (t->tids) {
		free(t->tids);
	}
	free(t);
}

void
test_summary(void)
{
	if (passes == tests) {
		(void) printf("TEST SUMMARY: %d / %d (ok)\n", passes, tests);
	} else {
		(void) printf("TEST SUMMARY: %d / %d (%d failing)\n",
		    passes, tests, tests - passes);
	}
}

void
test_debugf(test_t t, const char *format, ...)
{
	va_list args;

	if (!debug)
		return;

	(void) pthread_mutex_lock(&lk);
	if (t) {
		(void) printf("TEST DEBUG %s: ", t->name);
	} else {
		(void) printf("TEST DEBUG: ");
	}
	va_start(args, format);
	(void) vprintf(format, args);
	va_end(args);
	(void) printf("\n");
	(void) fflush(stdout);
	(void) pthread_mutex_unlock(&lk);
}

static void *
test_thr_one(void *arg)
{
	test_t t = arg;
	t->func(t, t->arg);
	return (NULL);
}

void
test_run(int nthr, void (*func)(test_t, void *), void *arg,
    const char *tname, ...)
{
	test_t		t;
	char		*s;
	va_list		args;

	t = calloc(1, sizeof (*t));
	t->ntids = nthr;
	t->tids = calloc(nthr, sizeof (pthread_t));
	t->func = func;
	t->arg = arg;

	va_start(args, tname);
	(void) vasprintf(&s, tname, args);
	va_end(args);

	(void) asprintf(&t->name, "%s (%s)", s, ARCH);
	free(s);

	(void) pthread_mutex_lock(&lk);
	(void) printf("TEST STARTING %s:\n", t->name);
	(void) fflush(stdout);
	(void) pthread_mutex_unlock(&lk);

	test_debugf(t, "running %d threads", nthr);

	for (int i = 0; i < nthr; i++) {
		test_debugf(t, "started thread %d", i);
		(void) pthread_create(&t->tids[i], NULL, test_thr_one, t);
	}

	for (int i = 0; i < nthr; i++) {
		(void) pthread_join(t->tids[i], NULL);
		test_debugf(t, "thread %d joined", i);
		t->ntids--;
	}
	test_passed(t);
}

void
test_trim(char **ptr)
{
	char *p = *ptr;
	while (isspace(*p)) {
		p++;
	}
	*ptr = p;
	p += strlen(p);
	while ((--p >= *ptr) && (isspace(*p))) {
		*p = '\0';
	}
}

#define	MAXCB		20
#define	MAXFIELD	20

int
test_load_config(test_t t, const char *fname, ...)
{
	va_list		va;
	const char	*keyws[MAXCB];
	test_cfg_func_t	callbs[MAXCB];
	char		*fields[MAXFIELD];
	int		nfields;

	FILE    	*cfg;
	char    	line[1024];
	char    	buf[1024];
	int		done;
	char		*ptr;
	char		*tok;
	char		*err;
	int		lineno;
	int		rv;
	int		found;
	char		path[MAXPATHLEN];
	int		i;

	va_start(va, fname);
	for (i = 0; i < MAXCB; i++) {
		keyws[i] = (const char *)va_arg(va, const char *);
		if (keyws[i] == NULL)
			break;
		callbs[i] = (test_cfg_func_t)va_arg(va, test_cfg_func_t);
	}
	va_end(va);
	if (i == MAXCB) {
		test_debugf(t, "too many arguments to function >= %d", MAXCB);
	}

	found = 0;

	if (access(fname, F_OK) == 0) {
		found++;
	}
	if (!found && fname[0] != '/') {
		char *stf = getenv("STF_SUITE");
		if (stf == NULL) {
			stf = "../..";
		}
		(void) snprintf(path, sizeof (path), "%s/cfg/%s", stf, fname);
		if (access(path, F_OK) == 0) {
			fname = path;
			found++;
		} else {
			(void) snprintf(path, sizeof (path), "cfg/%s", fname);
			if (access(path, F_OK) == 0) {
				fname = path;
				found++;
			}
		}
	}

	if ((cfg = fopen(fname, "r")) ==  NULL) {
		test_failed(t, "open(%s): %s", fname, strerror(errno));
		return (-1);
	}

	line[0] = 0;
	done = 0;
	lineno = 0;

	while (!done) {

		lineno++;

		if (fgets(buf, sizeof (buf), cfg) == NULL) {
			done++;
		} else {
			(void) strtok(buf, "\n");
			if ((*buf != 0) && (buf[strlen(buf)-1] == '\\')) {
				/*
				 * Continuation.  This isn't quite right,
				 * as it doesn't allow for a "\" at the
				 * end of line (no escaping).
				 */
				buf[strlen(buf)-1] = 0;
				(void) strlcat(line, buf, sizeof (line));
				continue;
			}
			(void) strlcat(line, buf, sizeof (line));
		}

		/* got a line */
		ptr = line;
		test_trim(&ptr);

		/* skip comments and empty lines */
		if (ptr[0] == 0 || ptr[0] == '#') {
			line[0] = 0;
			continue;
		}

		tok = strsep(&ptr, "|");
		if (tok == NULL) {
			break;
		}
		test_trim(&tok);

		for (nfields = 0; nfields < MAXFIELD; nfields++) {
			fields[nfields] = strsep(&ptr, "|");
			if (fields[nfields] == NULL) {
				break;
			}
			test_trim(&fields[nfields]);
		}

		found = 0;
		rv = 0;

		for (int i = 0; keyws[i] != NULL; i++) {
			if (strcmp(tok, keyws[i]) == 0) {
				found++;
				err = NULL;
				rv = callbs[i](fields, nfields, &err);
			}
		}
		if (!found) {
			rv = -1;
			err = NULL;
			(void) asprintf(&err, "unknown keyword %s", tok);
		}
		if (rv != 0) {
			if (err) {
				test_failed(t, "%s:%d: %s", fname,
				    lineno, err);
				free(err);
			} else {
				test_failed(t, "%s:%d: unknown error",
				    fname, lineno);
			}
			(void) fclose(cfg);
			return (rv);
		}

		line[0] = 0;
	}
	(void) fclose(cfg);
	return (0);
}
