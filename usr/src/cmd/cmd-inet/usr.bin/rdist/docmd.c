/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 */

#include "defs.h"
#include <string.h>
#include <setjmp.h>
#include <netdb.h>
#include <signal.h>
#include <krb5defs.h>

#ifndef RDIST
#ifdef SYSV
/*
 * Historically, the rdist program has had the following hard-coded
 * pathname.  Some operating systems attempt to "improve" the
 * directory layout, in the process re-locating the rdist binary
 * to some other location.  However, the first original implementation
 * sets a standard of sorts.  In order to interoperate with other
 * systems, our implementation must do two things: It must provide
 * the an rdist binary at the pathname below, and it must use this
 * pathname when executing rdist on remote systems via the rcmd()
 * library.  Thus the hard-coded path name below can never be changed.
 */
#endif /* SYSV */
#define	RDIST "/usr/ucb/rdist"
#endif

FILE	*lfp;			/* log file for recording files updated */
struct	subcmd *subcmds;	/* list of sub-commands for current cmd */
jmp_buf	env;

void	cleanup();
void	lostconn();
static int	init_service(int);
static struct servent *sp;

static void notify(char *file, char *rhost, struct namelist *to, time_t lmod);
static void rcmptime(struct stat *st);
static void cmptime(char *name);
static void dodcolon(char **filev, struct namelist *files, char *stamp,
    struct subcmd *cmds);
static void closeconn(void);
static void doarrow(char **filev, struct namelist *files, char *rhost,
    struct subcmd *cmds);
static int makeconn(char *rhost);
static int okname(char *name);

#ifdef SYSV
#include <libgen.h>

static char *recomp;
static char *errstring = "regcmp failed for some unknown reason";

char *
re_comp(char *s)
{
	if ((int)recomp != 0)
		free(recomp);
	recomp = regcmp(s, (char *)0);
	if (recomp == NULL)
		return (errstring);
	else
		return ((char *)0);
}


static int
re_exec(char *s)
{
	if ((int)recomp == 0)
		return (-1);
	if (regex(recomp, s) == NULL)
		return (0);
	else
		return (1);
}
#endif /* SYSV */

/*
 * Do the commands in cmds (initialized by yyparse).
 */
void
docmds(char **dhosts, int argc, char **argv)
{
	struct cmd *c;
	struct namelist *f;
	char **cpp;
	extern struct cmd *cmds;

	/* protect backgrounded rdist */
	if (signal(SIGINT, SIG_IGN) != SIG_IGN)
		(void) signal(SIGINT, cleanup);

	/* ... and running via nohup(1) */
	if (signal(SIGHUP, SIG_IGN) != SIG_IGN)
		(void) signal(SIGHUP, cleanup);
	if (signal(SIGQUIT, SIG_IGN) != SIG_IGN)
		(void) signal(SIGQUIT, cleanup);

	(void) signal(SIGTERM, cleanup);

	if (debug) {
		if (!cmds)
			printf("docmds:  cmds == NULL\n");
		else {
			printf("docmds:  cmds ");
			prcmd(cmds);
		}
	}
	for (c = cmds; c != NULL; c = c->c_next) {
		if (dhosts != NULL && *dhosts != NULL) {
			for (cpp = dhosts; *cpp; cpp++)
				if (strcmp(c->c_name, *cpp) == 0)
					goto fndhost;
			continue;
		}
	fndhost:
		if (argc) {
			for (cpp = argv; *cpp; cpp++) {
				if (c->c_label != NULL &&
				    strcmp(c->c_label, *cpp) == 0) {
					cpp = NULL;
					goto found;
				}
				for (f = c->c_files; f != NULL; f = f->n_next)
					if (strcmp(f->n_name, *cpp) == 0)
						goto found;
			}
			continue;
		} else
			cpp = NULL;
	found:
		switch (c->c_type) {
		case ARROW:
			doarrow(cpp, c->c_files, c->c_name, c->c_cmds);
			break;
		case DCOLON:
			dodcolon(cpp, c->c_files, c->c_name, c->c_cmds);
			break;
		default:
			fatal("illegal command type %d\n", c->c_type);
		}
	}
	closeconn();
}

/*
 * Process commands for sending files to other machines.
 */
static void
doarrow(char **filev, struct namelist *files, char *rhost, struct subcmd *cmds)
{
	struct namelist *f;
	struct subcmd *sc;
	char **cpp;
	int n, ddir, opts = options;

	if (debug)
		printf("doarrow(%x, %s, %x)\n", files, rhost, cmds);

	if (files == NULL) {
		error("no files to be updated\n");
		return;
	}

	subcmds = cmds;
	ddir = files->n_next != NULL;	/* destination is a directory */
	if (nflag)
		printf("updating host %s\n", rhost);
	else {
		if (setjmp(env))
			goto done;
		(void) signal(SIGPIPE, lostconn);
		if (!makeconn(rhost))
			return;
		if (!nflag)
			if ((lfp = fopen(Tmpfile, "w")) == NULL) {
				fatal("cannot open %s\n", Tmpfile);
				exit(1);
			}
	}
	for (f = files; f != NULL; f = f->n_next) {
		if (filev) {
			for (cpp = filev; *cpp; cpp++)
				if (strcmp(f->n_name, *cpp) == 0)
					goto found;
			continue;
		}
	found:
		n = 0;
		for (sc = cmds; sc != NULL; sc = sc->sc_next) {
			if (sc->sc_type != INSTALL)
				continue;
			n++;
			install(f->n_name, sc->sc_name,
			    sc->sc_name == NULL ? 0 : ddir, sc->sc_options);
			opts = sc->sc_options;
		}
		if (n == 0)
			install(f->n_name, NULL, 0, options);
	}
done:
	if (!nflag) {
		(void) signal(SIGPIPE, cleanup);
		(void) fclose(lfp);
		lfp = NULL;
	}
	for (sc = cmds; sc != NULL; sc = sc->sc_next)
		if (sc->sc_type == NOTIFY)
			notify(Tmpfile, rhost, sc->sc_args, 0);
	if (!nflag) {
		(void) unlink(Tmpfile);
		for (; ihead != NULL; ihead = ihead->nextp) {
			free(ihead);
			if ((opts & IGNLNKS) || ihead->count == 0)
				continue;
			log(lfp, "%s: Warning: missing links\n",
			    ihead->pathname);
		}
	}
}

static int
init_service(int krb5flag)
{
	boolean_t success = B_FALSE;

	if (krb5flag > 0) {
		if ((sp = getservbyname("kshell", "tcp")) == NULL) {
			fatal("kshell/tcp: unknown service");
			(void) fprintf(stderr,
			    gettext("trying shell/tcp service...\n"));
		} else {
			success = B_TRUE;
		}
	} else {
		if ((sp = getservbyname("shell", "tcp")) == NULL) {
			fatal("shell/tcp: unknown service");
			exit(1);
		} else {
			success = B_TRUE;
		}
	}
	return (success);
}
/*
 * Create a connection to the rdist server on the machine rhost.
 */
static int
makeconn(char *rhost)
{
	char *ruser, *cp;
	static char *cur_host = NULL;
	static int port = -1;
	char tuser[20];
	int n;
	extern char user[];

	if (debug)
		printf("makeconn(%s)\n", rhost);

	if (cur_host != NULL && rem >= 0) {
		if (strcmp(cur_host, rhost) == 0)
			return (1);
		closeconn();
	}
	cur_host = rhost;
	cp = index(rhost, '@');
	if (cp != NULL) {
		char c = *cp;

		*cp = '\0';
		strncpy(tuser, rhost, sizeof (tuser)-1);
		*cp = c;
		rhost = cp + 1;
		ruser = tuser;
		if (*ruser == '\0')
			ruser = user;
		else if (!okname(ruser))
			return (0);
	} else
		ruser = user;
	if (!qflag)
		printf("updating host %s\n", rhost);
	(void) snprintf(buf, RDIST_BUFSIZ, "%s%s -Server%s",
	    encrypt_flag ? "-x " : "", RDIST, qflag ? " -q" : "");
	if (port < 0) {
		if (debug_port == 0) {
			if ((retval = (int)init_service(krb5auth_flag)) == 0) {
				krb5auth_flag = encrypt_flag = 0;
				(void) init_service(krb5auth_flag);
			}
			port = sp->s_port;

		} else {
			port = debug_port;
		}
	}

	if (debug) {
		printf("port = %d, luser = %s, ruser = %s\n", ntohs(port),
		    user, ruser);
		printf("buf = %s\n", buf);
	}

	fflush(stdout);

	if (krb5auth_flag > 0) {
		if ((encrypt_flag > 0) && (!krb5_privacy_allowed())) {
			(void) fprintf(stderr, gettext("rdist: Encryption "
			    " not supported.\n"));
			exit(1);
		}

		authopts = AP_OPTS_MUTUAL_REQUIRED;

		status = kcmd(&rem, &rhost, port, user, ruser,
		    buf, 0, "host", krb_realm, bsd_context, &auth_context,
		    &cred,
		    0,	/* No need for sequence number */
		    0,	/* No need for server seq # */
		    authopts,
		    1,	/* Always set anyport */
		    &kcmd_proto);
		if (status) {
			/*
			 * If new protocol requested, we dont
			 * fallback to less secure ones.
			 */
			if (kcmd_proto == KCMD_NEW_PROTOCOL) {
				(void) fprintf(stderr, gettext("rdist: kcmdv2 "
				    "to host %s failed - %s\n"
				    "Fallback to normal rdist denied."),
				    host, error_message(status));
				exit(1);
			}
			/* check NO_TKT_FILE or equivalent... */
			if (status != -1) {
				(void) fprintf(stderr, gettext("rdist: "
				    "kcmd to host %s failed - %s\n"
				    "trying normal rdist...\n\n"),
				    host, error_message(status));
			} else {
				(void) fprintf(stderr,
				    gettext("trying normal rdist...\n"));
			}
			/*
			 * kcmd() failed, so we now fallback to normal rdist
			 */
			krb5auth_flag = encrypt_flag = 0;
			(void) init_service(krb5auth_flag);
			port = sp->s_port;
			goto do_rcmd;
		}
#ifdef DEBUG
		else {
			(void) fprintf(stderr, gettext("Kerberized rdist "
			    "session, port %d in use "), port);
			if (kcmd_proto == KCMD_OLD_PROTOCOL)
				(void) fprintf(stderr,
				    gettext("[kcmd ver.1].\n"));
			else
				(void) fprintf(stderr,
				    gettext("[kcmd ver.2].\n"));
		}
#endif /* DEBUG */
		session_key = &cred->keyblock;

		if (kcmd_proto == KCMD_NEW_PROTOCOL) {
			status = krb5_auth_con_getlocalsubkey(bsd_context,
			    auth_context, &session_key);
			if (status) {
				com_err("rdist", status,
				    "determining subkey for session");
				exit(1);
			}
			if (!session_key) {
				com_err("rdist", 0,
				    "no subkey negotiated for connection");
				exit(1);
			}
		}

		eblock.crypto_entry = session_key->enctype;
		eblock.key = (krb5_keyblock *)session_key;

		init_encrypt(encrypt_flag, bsd_context, kcmd_proto, &desinbuf,
		    &desoutbuf, CLIENT, &eblock);


		if (encrypt_flag > 0) {
			char *s = gettext("This rdist session is using "
			    "encryption for all data transmissions.\r\n");
			(void) write(2, s, strlen(s));
		}

	}
	else
do_rcmd:
	{
		rem = rcmd_af(&rhost, port, user, ruser, buf, 0, AF_INET6);
	}

	if (rem < 0)
		return (0);

	cp = buf;
	if (desread(rem, cp, 1, 0) != 1)
		lostconn();
	if (*cp == 'V') {
		do {
			if (desread(rem, cp, 1, 0) != 1)
				lostconn();
		} while (*cp++ != '\n' && cp < &buf[RDIST_BUFSIZ]);
		*--cp = '\0';
		cp = buf;
		n = 0;
		while (*cp >= '0' && *cp <= '9')
			n = (n * 10) + (*cp++ - '0');
		if (*cp == '\0' && n == VERSION)
			return (1);
		error("connection failed: version numbers don't match"
		    " (local %d, remote %d)\n", VERSION, n);
	} else {
		error("connection failed: version numbers don't match\n");
	}
	closeconn();
	return (0);
}

/*
 * Signal end of previous connection.
 */
static void
closeconn(void)
{
	if (debug)
		printf("closeconn()\n");

	if (rem >= 0) {
		(void) deswrite(rem, "\2\n", 2, 0);
		(void) close(rem);
		rem = -1;
	}
}

void
lostconn(void)
{
	if (iamremote)
		cleanup();
	log(lfp, "rdist: lost connection\n");
	longjmp(env, 1);
}

static int
okname(char *name)
{
	char *cp = name;
	int c;

	do {
		c = *cp;
		if (c & 0200)
			goto bad;
		if (!isalpha(c) && !isdigit(c) && c != '_' && c != '-')
			goto bad;
		cp++;
	} while (*cp);
	return (1);
bad:
	error("invalid user name %s\n", name);
	return (0);
}

time_t	lastmod;
FILE	*tfp;
extern	char target[], *tp;

/*
 * Process commands for comparing files to time stamp files.
 */
static void
dodcolon(char **filev, struct namelist *files, char *stamp, struct subcmd *cmds)
{
	struct subcmd *sc;
	struct namelist *f;
	char **cpp;
	struct timeval tv[2];
	struct stat stb;

	if (debug)
		printf("dodcolon()\n");

	if (files == NULL) {
		error("no files to be updated\n");
		return;
	}
	if (stat(stamp, &stb) < 0) {
		error("%s: %s\n", stamp, strerror(errno));
		return;
	}
	if (debug)
		printf("%s: %d\n", stamp, stb.st_mtime);

	subcmds = cmds;
	lastmod = stb.st_mtime;
	if (nflag || (options & VERIFY))
		tfp = NULL;
	else {
		if ((tfp = fopen(Tmpfile, "w")) == NULL) {
			error("%s: %s\n", stamp, strerror(errno));
			return;
		}
		(void) gettimeofday(&tv[0], (struct timezone *)NULL);
		tv[1] = tv[0];
		(void) utimes(stamp, tv);
	}

	for (f = files; f != NULL; f = f->n_next) {
		if (filev) {
			for (cpp = filev; *cpp; cpp++)
				if (strcmp(f->n_name, *cpp) == 0)
					goto found;
			continue;
		}
	found:
		tp = NULL;
		cmptime(f->n_name);
	}

	if (tfp != NULL)
		(void) fclose(tfp);
	for (sc = cmds; sc != NULL; sc = sc->sc_next)
		if (sc->sc_type == NOTIFY)
			notify(Tmpfile, NULL, sc->sc_args, lastmod);
	if (!nflag && !(options & VERIFY))
		(void) unlink(Tmpfile);
}

/*
 * Compare the mtime of file to the list of time stamps.
 */
static void
cmptime(char *name)
{
	struct stat stb;

	if (debug)
		printf("cmptime(%s)\n", name);

	if (except(name))
		return;

	if (nflag) {
		printf("comparing dates: %s\n", name);
		return;
	}

	/*
	 * first time cmptime() is called?
	 */
	if (tp == NULL) {
		if (exptilde(target, RDIST_BUFSIZ, name) == NULL)
			return;
		tp = name = target;
		while (*tp)
			tp++;
	}
	if (access(name, 4) < 0 || stat(name, &stb) < 0) {
		error("%s: %s\n", name, strerror(errno));
		return;
	}

	switch (stb.st_mode & S_IFMT) {
	case S_IFREG:
		break;

	case S_IFDIR:
		rcmptime(&stb);
		return;

	default:
		error("%s: not a plain file\n", name);
		return;
	}

	if (stb.st_mtime > lastmod)
		log(tfp, "new: %s\n", name);
}

static void
rcmptime(struct stat *st)
{
	DIR *d;
	struct dirent *dp;
	char *cp;
	char *otp;
	int len;

	if (debug)
		printf("rcmptime(%x)\n", st);

	if ((d = opendir(target)) == NULL) {
		error("%s: %s\n", target, strerror(errno));
		return;
	}
	otp = tp;
	len = tp - target;
	while (dp = readdir(d)) {
		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0))
			continue;
		if (len + 1 + strlen(dp->d_name) >= RDIST_BUFSIZ - 1) {
			error("%s/%s: Name too long\n", target, dp->d_name);
			continue;
		}
		tp = otp;
		*tp++ = '/';
		cp = dp->d_name;
		while (*tp++ = *cp++)
			;
		tp--;
		cmptime(target);
	}
	closedir(d);
	tp = otp;
	*tp = '\0';
}

/*
 * Notify the list of people the changes that were made.
 * rhost == NULL if we are mailing a list of changes compared to at time
 * stamp file.
 */
static void
notify(char *file, char *rhost, struct namelist *to, time_t lmod)
{
	int fd, len;
	FILE *pf, *popen();
	struct stat stb;

	if ((options & VERIFY) || to == NULL)
		return;
	if (!qflag) {
		printf("notify ");
		if (rhost)
			printf("@%s ", rhost);
		prnames(to);
	}
	if (nflag)
		return;

	if ((fd = open(file, 0)) < 0) {
		error("%s: %s\n", file, strerror(errno));
		return;
	}
	if (fstat(fd, &stb) < 0) {
		error("%s: %s\n", file, strerror(errno));
		(void) close(fd);
		return;
	}
	if (stb.st_size == 0) {
		(void) close(fd);
		return;
	}
	/*
	 * Create a pipe to mailling program.
	 */
	pf = popen(MAILCMD, "w");
	if (pf == NULL) {
		error("notify: \"%s\" failed\n", MAILCMD);
		(void) close(fd);
		return;
	}
	/*
	 * Output the proper header information.
	 */
	fprintf(pf, "From: rdist (Remote distribution program)\n");
	fprintf(pf, "To:");
	if (!any('@', to->n_name) && rhost != NULL)
		fprintf(pf, " %s@%s", to->n_name, rhost);
	else
		fprintf(pf, " %s", to->n_name);
	to = to->n_next;
	while (to != NULL) {
		if (!any('@', to->n_name) && rhost != NULL)
			fprintf(pf, ", %s@%s", to->n_name, rhost);
		else
			fprintf(pf, ", %s", to->n_name);
		to = to->n_next;
	}
	putc('\n', pf);
	if (rhost != NULL)
		fprintf(pf, "Subject: files updated by rdist from %s to %s\n",
		    host, rhost);
	else
		fprintf(pf, "Subject: files updated after %s\n", ctime(&lmod));
	putc('\n', pf);

	while ((len = read(fd, buf, RDIST_BUFSIZ)) > 0)
		(void) fwrite(buf, 1, len, pf);
	(void) close(fd);
	(void) pclose(pf);
}

/*
 * Return true if name is in the list.
 */
int
inlist(struct namelist *list, char *file)
{
	struct namelist *nl;

	for (nl = list; nl != NULL; nl = nl->n_next)
		if (strcmp(file, nl->n_name) == 0)
			return (1);
	return (0);
}

/*
 * Return TRUE if file is in the exception list.
 */
int
except(char *file)
{
	struct	subcmd *sc;
	struct	namelist *nl;

	if (debug)
		printf("except(%s)\n", file);

	for (sc = subcmds; sc != NULL; sc = sc->sc_next) {
		if (sc->sc_type != EXCEPT && sc->sc_type != PATTERN)
			continue;
		for (nl = sc->sc_args; nl != NULL; nl = nl->n_next) {
			if (sc->sc_type == EXCEPT) {
				if (strcmp(file, nl->n_name) == 0)
					return (1);
				continue;
			}
			re_comp(nl->n_name);
			if (re_exec(file) > 0)
				return (1);
		}
	}
	return (0);
}

char *
colon(char *cp)
{
	while (*cp) {
		if (*cp == ':')
			return (cp);
		if (*cp == '/')
			return (0);
		cp++;
	}
	return (0);
}
