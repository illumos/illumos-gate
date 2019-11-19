/*
 * Copyright (c) 2000, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: rcfile.c,v 1.1.1.2 2001/07/06 22:38:43 conrad Exp $
 */
/*
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

#include <fcntl.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <synch.h>
#include <unistd.h>
#include <pwd.h>
#include <libintl.h>

#include <cflib.h>
#include "rcfile_priv.h"

#include <assert.h>

#if 0 /* before SMF */
#define	SMB_CFG_FILE	"/etc/nsmb.conf"
#define	OLD_SMB_CFG_FILE	"/usr/local/etc/nsmb.conf"
#endif

extern int smb_debug;

static struct rcfile *rc_cachelookup(const char *filename);
static struct rcsection *rc_findsect(struct rcfile *rcp, const char *sectname);
static struct rcsection *rc_addsect(struct rcfile *rcp, const char *sectname);
static int		rc_freesect(struct rcfile *rcp, struct rcsection *rsp);
static struct rckey *rc_sect_findkey(struct rcsection *rsp, const char *key);
static struct rckey *rc_sect_addkey(struct rcsection *rsp, const char *name,
    const char *value);
static void rc_key_free(struct rckey *p);
static void rc_parse(struct rcfile *rcp);

/* lock for the variables below */
mutex_t rcfile_mutex = DEFAULTMUTEX;

SLIST_HEAD(rcfile_head, rcfile);
static struct rcfile_head pf_head = {NULL};
struct rcfile *smb_rc;
int home_nsmbrc;
int insecure_nsmbrc;

/*
 * open rcfile and load its content, if already open - return previous handle
 */
static int
rc_open(const char *filename, const char *mode, struct rcfile **rcfile)
{
	struct stat statbuf;
	struct rcfile *rcp;
	FILE *f;

	assert(MUTEX_HELD(&rcfile_mutex));

	rcp = rc_cachelookup(filename);
	if (rcp) {
		*rcfile = rcp;
		return (0);
	}
	f = fopen(filename, mode);
	if (f == NULL)
		return (errno);
	insecure_nsmbrc = 0;
	if (fstat(fileno(f), &statbuf) >= 0 &&
	    (statbuf.st_mode & 077) != 0)
		insecure_nsmbrc = 1;
	rcp = malloc(sizeof (struct rcfile));
	if (rcp == NULL) {
		fclose(f);
		return (ENOMEM);
	}
	bzero(rcp, sizeof (struct rcfile));
	rcp->rf_name = strdup(filename);
	rcp->rf_f = f;
	SLIST_INSERT_HEAD(&pf_head, rcp, rf_next);
	rc_parse(rcp);
	*rcfile = rcp;
	return (0);
}

static int
rc_merge(const char *filename, struct rcfile **rcfile)
{
	struct stat statbuf;
	struct rcfile *rcp = *rcfile;
	FILE *f, *t;

	assert(MUTEX_HELD(&rcfile_mutex));

	insecure_nsmbrc = 0;
	if (rcp == NULL) {
		return (rc_open(filename, "r", rcfile));
	}
	f = fopen(filename, "r");
	if (f == NULL)
		return (errno);
	insecure_nsmbrc = 0;
	if (fstat(fileno(f), &statbuf) >= 0 &&
	    (statbuf.st_mode & 077) != 0)
		insecure_nsmbrc = 1;
	t = rcp->rf_f;
	rcp->rf_f = f;
	rc_parse(rcp);
	rcp->rf_f = t;
	fclose(f);
	return (0);
}

/*
 * Like rc_open, but creates a temporary file and
 * reads the sharectl settings into it.
 * The file is deleted when we close it.
 */
static int
rc_open_sharectl(struct rcfile **rcfile)
{
	static char template[24] = "/tmp/smbfsXXXXXX";
	struct rcfile *rcp = NULL;
	FILE *fp = NULL;
	int err;
	int fd = -1;

	assert(MUTEX_HELD(&rcfile_mutex));

	fd = mkstemp(template);
	if (fd < 0) {
		err = errno;
		goto errout;
	}

	fp = fdopen(fd, "w+");
	if (fp == NULL) {
		err = errno;
		close(fd);
		goto errout;
	}
	fd = -1; /* The fp owns this fd now. */

	/*
	 * Get smbfs sharectl settings into the file.
	 */
	if ((err = rc_scf_get_sharectl(fp)) != 0)
		goto errout;

	rcp = malloc(sizeof (struct rcfile));
	if (rcp == NULL) {
		err = ENOMEM;
		goto errout;
	}
	bzero(rcp, sizeof (struct rcfile));

	rcp->rf_name = strdup(template);
	if (rcp->rf_name == NULL) {
		err = ENOMEM;
		goto errout;
	}
	rcp->rf_f = fp;
	rcp->rf_flags = RCFILE_DELETE_ON_CLOSE;

	SLIST_INSERT_HEAD(&pf_head, rcp, rf_next);
	insecure_nsmbrc = 0;
	rc_parse(rcp);
	*rcfile = rcp;
	/* fclose(f) in rc_close */
	return (0);

errout:
	if (rcp != NULL)
		free(rcp);
	if (fp != NULL) {
		fclose(fp);
		fd = -1;
	}
	if (fd != -1)
		close(fd);

	return (err);
}


static int
rc_close(struct rcfile *rcp)
{
	struct rcsection *p, *n;

	mutex_lock(&rcfile_mutex);

	fclose(rcp->rf_f);
	if (rcp->rf_flags & RCFILE_DELETE_ON_CLOSE)
		(void) unlink(rcp->rf_name);

	for (p = SLIST_FIRST(&rcp->rf_sect); p; ) {
		n = p;
		p = SLIST_NEXT(p, rs_next);
		rc_freesect(rcp, n);
	}
	free(rcp->rf_name);
	SLIST_REMOVE(&pf_head, rcp, rcfile, rf_next);
	free(rcp);

	mutex_unlock(&rcfile_mutex);
	return (0);
}

static struct rcfile *
rc_cachelookup(const char *filename)
{
	struct rcfile *p;

	assert(MUTEX_HELD(&rcfile_mutex));

	SLIST_FOREACH(p, &pf_head, rf_next)
		if (strcmp(filename, p->rf_name) == 0)
			return (p);
	return (0);
}

static struct rcsection *
rc_findsect(struct rcfile *rcp, const char *sectname)
{
	struct rcsection *p;

	assert(MUTEX_HELD(&rcfile_mutex));

	SLIST_FOREACH(p, &rcp->rf_sect, rs_next)
		if (strcasecmp(p->rs_name, sectname) == 0)
			return (p);
	return (NULL);
}

static struct rcsection *
rc_addsect(struct rcfile *rcp, const char *sectname)
{
	struct rcsection *p;

	assert(MUTEX_HELD(&rcfile_mutex));

	p = rc_findsect(rcp, sectname);
	if (p)
		return (p);
	p = malloc(sizeof (*p));
	if (!p)
		return (NULL);
	p->rs_name = strdup(sectname);
	SLIST_INIT(&p->rs_keys);
	SLIST_INSERT_HEAD(&rcp->rf_sect, p, rs_next);
	return (p);
}

static int
rc_freesect(struct rcfile *rcp, struct rcsection *rsp)
{
	struct rckey *p, *n;

	assert(MUTEX_HELD(&rcfile_mutex));

	SLIST_REMOVE(&rcp->rf_sect, rsp, rcsection, rs_next);
	for (p = SLIST_FIRST(&rsp->rs_keys); p; ) {
		n = p;
		p = SLIST_NEXT(p, rk_next);
		rc_key_free(n);
	}
	free(rsp->rs_name);
	free(rsp);
	return (0);
}

static struct rckey *
rc_sect_findkey(struct rcsection *rsp, const char *keyname)
{
	struct rckey *p;

	assert(MUTEX_HELD(&rcfile_mutex));

	SLIST_FOREACH(p, &rsp->rs_keys, rk_next)
		if (strcmp(p->rk_name, keyname) == 0)
			return (p);
	return (NULL);
}

static struct rckey *
rc_sect_addkey(struct rcsection *rsp, const char *name, const char *value)
{
	struct rckey *p;

	assert(MUTEX_HELD(&rcfile_mutex));

	p = rc_sect_findkey(rsp, name);
	if (!p) {
		p = malloc(sizeof (*p));
		if (!p)
			return (NULL);
		SLIST_INSERT_HEAD(&rsp->rs_keys, p, rk_next);
		p->rk_name = strdup(name);
		p->rk_value = value ? strdup(value) : strdup("");
	}
	return (p);
}

#if 0
void
rc_sect_delkey(struct rcsection *rsp, struct rckey *p)
{

	SLIST_REMOVE(&rsp->rs_keys, p, rckey, rk_next);
	rc_key_free(p);
}
#endif

static void
rc_key_free(struct rckey *p)
{
	free(p->rk_value);
	free(p->rk_name);
	free(p);
}


static char *minauth_values[] = {
	"none",
	"lm",
	"ntlm",
	"ntlmv2",
	"kerberos",
	NULL
};

static int
eval_minauth(char *auth)
{
	int i;

	for (i = 0; minauth_values[i]; i++)
		if (strcmp(auth, minauth_values[i]) == 0)
			return (i);
	return (-1);
}

/*
 * Ensure that "minauth" is set to the highest level
 */
/*ARGSUSED*/
static void
set_value(struct rcfile *rcp, struct rcsection *rsp, struct rckey *rkp,
    char *ptr)
{
	int now, new;
#ifdef DEBUG
	char *from = "SMF";

	if (home_nsmbrc != 0)
		from = "user file";
#endif

	if (strcmp(rkp->rk_name, "minauth") == 0) {
		now = eval_minauth(rkp->rk_value);
		new = eval_minauth(ptr);
		if (new <= now) {
#ifdef DEBUG
			if (smb_debug)
				fprintf(stderr,
				    "set_value: rejecting %s=%s"
				    " in %s from %s\n",
				    rkp->rk_name, ptr,
				    rsp->rs_name, from);
#endif
			return;
		}
	}
#ifdef DEBUG
	if (smb_debug)
		fprintf(stderr,
		    "set_value: applying %s=%s in %s from %s\n",
		    rkp->rk_name, ptr, rsp->rs_name, from);
#endif
	rkp->rk_value = strdup(ptr);
}


/* states in rc_parse */
enum { stNewLine, stHeader, stSkipToEOL, stGetKey, stGetValue};

static void
rc_parse(struct rcfile *rcp)
{
	FILE *f = rcp->rf_f;
	int state = stNewLine, c;
	struct rcsection *rsp = NULL;
	struct rckey *rkp = NULL;
	char buf[2048];
	char *next = buf, *last = &buf[sizeof (buf)-1];

	assert(MUTEX_HELD(&rcfile_mutex));

	while ((c = getc(f)) != EOF) {
		if (c == '\r')
			continue;
		if (state == stNewLine) {
			next = buf;
			if (isspace(c))
				continue;	/* skip leading junk */
			if (c == '[') {
				state = stHeader;
				rsp = NULL;
				continue;
			}
			if (c == '#' || c == ';') {
				state = stSkipToEOL;
			} else {		/* something meaningfull */
				state = stGetKey;
			}
		}
		/* ignore long lines */
		if (state == stSkipToEOL || next == last) {
			if (c == '\n') {
				state = stNewLine;
				next = buf;
			}
			continue;
		}
		if (state == stHeader) {
			if (c == ']') {
				*next = 0;
				next = buf;
				rsp = rc_addsect(rcp, buf);
				state = stSkipToEOL;
			} else
				*next++ = c;
			continue;
		}
		if (state == stGetKey) {
			/* side effect: 'key name=' */
			if (c == ' ' || c == '\t')
				continue;	/* become 'keyname=' */
			if (c == '\n') {	/* silently ignore ... */
				state = stNewLine;
				continue;
			}
			if (c != '=') {
				*next++ = c;
				continue;
			}
			*next = 0;
			if (rsp == NULL) {
				fprintf(stderr, dgettext(TEXT_DOMAIN,
				    "Key '%s' defined before section\n"), buf);
				state = stSkipToEOL;
				continue;
			}
			if (home_nsmbrc != 0 && (
			    strcmp(buf, "nbns") == 0 ||
			    strcmp(buf, "nbns_enable") == 0 ||
			    strcmp(buf, "nbns_broadcast") == 0)) {
				fprintf(stderr, dgettext(TEXT_DOMAIN,
				    "option %s may not be set "
				    "in user .nsmbrc file\n"), buf);
				next = buf;
				state = stNewLine;
				continue;
			}
			if (insecure_nsmbrc != 0 &&
			    strcmp(buf, "password") == 0) {
				fprintf(stderr, dgettext(TEXT_DOMAIN,
				    "Warning: .nsmbrc file not secure, "
				    "ignoring passwords\n"));
				next = buf;
				state = stNewLine;
				continue;
			}
			rkp = rc_sect_addkey(rsp, buf, NULL);
			next = buf;
			state = stGetValue;
			continue;
		}
		/* only stGetValue left */
		if (state != stGetValue) {
			fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "Well, I can't parse file '%s'\n"), rcp->rf_name);
			state = stSkipToEOL;
		}
		if (c != '\n') {
			*next++ = c;
			continue;
		}
		*next = 0;
		set_value(rcp, rsp, rkp, buf);
		state = stNewLine;
		rkp = NULL;
	}	/* while */
	if (c == EOF && state == stGetValue) {
		*next = 0;
		set_value(rcp, rsp, rkp, buf);
	}
}

int
rc_getstringptr(struct rcfile *rcp, const char *section, const char *key,
	char **dest)
{
	struct rcsection *rsp;
	struct rckey *rkp;
	int err;

	mutex_lock(&rcfile_mutex);

	*dest = NULL;
	rsp = rc_findsect(rcp, section);
	if (!rsp) {
		err = ENOENT;
		goto out;
	}
	rkp = rc_sect_findkey(rsp, key);
	if (!rkp) {
		err = ENOENT;
		goto out;
	}
	*dest = rkp->rk_value;
	err = 0;

out:
	mutex_unlock(&rcfile_mutex);
	return (err);
}

int
rc_getstring(struct rcfile *rcp, const char *section, const char *key,
	size_t maxlen, char *dest)
{
	char *value;
	int error;

	error = rc_getstringptr(rcp, section, key, &value);
	if (error)
		return (error);
	if (strlen(value) >= maxlen) {
		fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "line too long for key '%s' in section '%s', max = %d\n"),
		    key, section, maxlen);
		return (EINVAL);
	}
	strcpy(dest, value);
	return (0);
}

int
rc_getint(struct rcfile *rcp, const char *section, const char *key, int *value)
{
	struct rcsection *rsp;
	struct rckey *rkp;
	int err;

	mutex_lock(&rcfile_mutex);

	rsp = rc_findsect(rcp, section);
	if (!rsp) {
		err = ENOENT;
		goto out;
	}
	rkp = rc_sect_findkey(rsp, key);
	if (!rkp) {
		err = ENOENT;
		goto out;
	}
	errno = 0;
	*value = strtol(rkp->rk_value, NULL, 0);
	if ((err = errno) != 0) {
		fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "invalid int value '%s' for key '%s' in section '%s'\n"),
		    rkp->rk_value, key, section);
	}

out:
	mutex_unlock(&rcfile_mutex);
	return (err);
}

/*
 * 1,yes,true
 * 0,no,false
 */
int
rc_getbool(struct rcfile *rcp, const char *section, const char *key, int *value)
{
	struct rcsection *rsp;
	struct rckey *rkp;
	char *p;
	int err;

	mutex_lock(&rcfile_mutex);

	rsp = rc_findsect(rcp, section);
	if (!rsp) {
		err = ENOENT;
		goto out;
	}
	rkp = rc_sect_findkey(rsp, key);
	if (!rkp) {
		err = ENOENT;
		goto out;
	}
	p = rkp->rk_value;
	while (*p && isspace(*p)) p++;
	if (*p == '0' ||
	    strcasecmp(p, "no") == 0 ||
	    strcasecmp(p, "false") == 0) {
		*value = 0;
		err = 0;
		goto out;
	}
	if (*p == '1' ||
	    strcasecmp(p, "yes") == 0 ||
	    strcasecmp(p, "true") == 0) {
		*value = 1;
		err = 0;
		goto out;
	}
	fprintf(stderr, dgettext(TEXT_DOMAIN,
	    "invalid boolean value '%s' for key '%s' in section '%s' \n"),
	    p, key, section);
	err = EINVAL;

out:
	mutex_unlock(&rcfile_mutex);
	return (err);
}

#ifdef DEBUG
void
dump_props(char *where)
{
	struct rcsection *rsp = NULL;
	struct rckey *rkp = NULL;

	fprintf(stderr, "Settings %s\n", where);
	SLIST_FOREACH(rsp, &smb_rc->rf_sect, rs_next) {
		fprintf(stderr, "section=%s\n", rsp->rs_name);
		fflush(stderr);

		SLIST_FOREACH(rkp, &rsp->rs_keys, rk_next) {
			fprintf(stderr, "  key=%s, value=%s\n",
			    rkp->rk_name, rkp->rk_value);
			fflush(stderr);
		}
	}
}
#endif

/*
 * first parse "sharectl get smbfs, then $HOME/.nsmbrc
 * This is called by library consumers (commands)
 */
int
smb_open_rcfile(char *home)
{
	char *fn;
	int len, error = 0;

	mutex_lock(&rcfile_mutex);

	smb_rc = NULL;
#if 0	/* before SMF */
	fn = SMB_CFG_FILE;
	error = rc_open(fn, &smb_rc);
#else
	fn = "(sharectl get smbfs)";
	error = rc_open_sharectl(&smb_rc);
#endif
	if (error != 0 && error != ENOENT) {
		/* Error from fopen. strerror is OK. */
		fprintf(stderr, dgettext(TEXT_DOMAIN,
		    "Can't open %s: %s\n"), fn, strerror(errno));
	}
#ifdef DEBUG
	if (smb_debug)
		dump_props(fn);
#endif

	if (home) {
		len = strlen(home) + 20;
		fn = malloc(len);
		snprintf(fn, len, "%s/.nsmbrc", home);
		home_nsmbrc = 1;
		error = rc_merge(fn, &smb_rc);
		if (error != 0 && error != ENOENT) {
			fprintf(stderr, dgettext(TEXT_DOMAIN,
			    "Can't open %s: %s\n"), fn, strerror(errno));
		}
		home_nsmbrc = 0;
#ifdef DEBUG
		if (smb_debug)
			dump_props(fn);
#endif
		free(fn);
	}

	/* Mostly ignore error returns above. */
	if (smb_rc == NULL)
		error = ENOENT;
	else
		error = 0;

	mutex_unlock(&rcfile_mutex);

	return (error);
}

/*
 * This is called by library consumers (commands)
 */
void
smb_close_rcfile(void)
{
	struct rcfile *rcp;

	if ((rcp = smb_rc) != NULL) {
		smb_rc = NULL;
		rc_close(rcp);
	}
}
