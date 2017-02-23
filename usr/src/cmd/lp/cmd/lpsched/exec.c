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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include <pwd.h>
#include <zone.h>
#if defined PS_FAULTED
#undef  PS_FAULTED
#endif /* PS_FAULTED */
#include <dial.h>

#include <stdlib.h>
#include "limits.h"
#include "stdarg.h"
#include "wait.h"
#include "dial.h"
#include "lpsched.h"
#include <syslog.h>
#include "tsol/label.h"

#define Done(EC,ERRNO)	done(((EC) << 8),ERRNO)

#define	STRLCAT(dst, src, size) \
	if (strlcat((dst), (src), (size)) >= (size)) { \
		errno = EINVAL; \
		return (-1); \
	}

static MESG *		ChildMd;

static int		ChildPid;
static int		WaitedChildPid;
static int		do_undial;

static char		argbuf[ARG_MAX];

static long		key;

static void		sigtrap ( int );
static void		done ( int , int );
static void		cool_heels ( void );
static void		addenv (char ***envp, char * , char * );
static void		trap_fault_signals ( void );
static void		ignore_fault_signals ( void );
static void		child_mallocfail ( void );
static void		Fork2 ( void );

static int		Fork1 ( EXEC * );

static void
relock(void)
{
	struct flock		l;

	l.l_type = F_WRLCK;
	l.l_whence = 1;
	l.l_start = 0;
	l.l_len = 0;
	(void)Fcntl (lock_fd, F_SETLK, &l);
	return;
}

static char *_exec_name(int type)
{
	static char *_names[] = {
	"", "EX_INTERF", "EX_SLOWF", "EX_ALERT", "EX_FALERT", "EX_PALERT",
	"EX_NOTIFY", "EX_FAULT_MESSAGE", "EX_FORM_MESSAGE", NULL };

	if ((type < 0) || (type > EX_FORM_MESSAGE))
		return ("BAD_EXEC_TYPE");
	else
		return (_names[type]);
}

/*
 * This function replaces characters in a string that might be used
 * to exploit a security hole.  Replace command seperators (`, &, ;, |, ^),
 * output redirection (>, |), variable expansion ($), and character
 * escape (\).
 *
 * Bugid 4141687
 * Add ( ) < * ? [
 * Bugid 4139071
 * Remove \
 */
void clean_string(char *ptr)
{
	char *cp;
	wchar_t wc;
	size_t len;

	for (cp = ptr; *cp != NULL; ) {
		if ((len = mbtowc(&wc, cp, MB_CUR_MAX)) == -1) {
			cp++;
			continue;
		}

		if (len == 1 &&
		    ((wc == L'`') || (wc == L'&') || (wc == L';') ||
		    (wc == L'|') || (wc == L'>') || (wc == L'^') ||
		    (wc == L'$') || (wc == L'(') || (wc == L')') ||
		    (wc == L'<') || (wc == L'*') || (wc == L'?') ||
		    (wc == L'[')))
			*cp = '_';
		cp += len;
	}
}

enum trust {TRUSTED, UNTRUSTED};

static char *arg_string(enum trust type, char *fmt, ...) __PRINTFLIKE(2);

/* PRINTFLIKE2 */
static char *
arg_string(enum trust type, char *fmt, ...)
{
	char buf[BUFSIZ];
	va_list	args;

	va_start(args, fmt);
	(void) vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

	/*
	 * If the string contains data from an untrusted origin (user supplied),
	 * clean it up in case one of our progeny is a shell script and isn't
	 * careful about checking its input.
	 */
	if (type == UNTRUSTED)
		clean_string(buf);

	return (strdup(buf));
}

/* stolen from libc/gen/port/gen/execvp.c */
static const char *
execat(const char *s1, const char *s2, char *si)
{
        char    *s;
        int cnt = PATH_MAX + 1; /* number of characters in s2 */

        s = si;
        while (*s1 && *s1 != ':') {
                if (cnt > 0) {
                        *s++ = *s1++;
                        cnt--;
                } else
                        s1++;
        }
        if (si != s && cnt > 0) {
                *s++ = '/';
                cnt--;
        }
        while (*s2 && cnt > 0) {
                *s++ = *s2++;
                cnt--;
        }
        *s = '\0';
        return (*s1 ? ++s1: 0);
}

/*
 * Similiar to execvp(), execpt you can supply an environment and we always
 * use /bin/sh for shell scripts.  The PATH searched is the PATH in the
 * current environment, not the environment in the argument list.
 * This was pretty much stolen from libc/gen/port/execvp.c
 */
static int
execvpe(char *name, char *const argv[], char *const envp[])
{
	char *path;
	char fname[PATH_MAX+2];
	char *newargs[256];
	int i;
	const char *cp;
	unsigned etxtbsy = 1;
        int eacces = 0;

	if (*name == '\0') {
		errno = ENOENT;
		return (-1);
	}

	if ((path = getenv("PATH")) == NULL)
		path = "/usr/bin:/bin";

        cp = strchr(name, '/')? (const char *)"": path;

        do {
                cp = execat(cp, name, fname);
        retry:
                /*
                 * 4025035 and 4038378
                 * if a filename begins with a "-" prepend "./" so that
                 * the shell can't interpret it as an option
                 */
                if (*fname == '-') {
                        size_t size = strlen(fname) + 1;
                        if ((size + 2) > sizeof (fname)) {
                                errno = E2BIG;
                                return (-1);
                        }
                        (void) memmove(fname + 2, fname, size);
                        fname[0] = '.';
                        fname[1] = '/';
                }
                (void) execve(fname, argv, envp);
                switch (errno) {
                case ENOEXEC:
                        newargs[0] = "sh";
                        newargs[1] = fname;
                        for (i = 1; (newargs[i + 1] = argv[i]) != NULL; ++i) {
                                if (i >= 254) {
                                        errno = E2BIG;
                                        return (-1);
                                }
                        }
                        (void) execve("/bin/sh", newargs, envp);
                        return (-1);
                case ETXTBSY:
                        if (++etxtbsy > 5)
                                return (-1);
                        (void) sleep(etxtbsy);
                        goto retry;
                case EACCES:
                        ++eacces;
                        break;
                case ENOMEM:
                case E2BIG:
                case EFAULT:
                        return (-1);
                }
        } while (cp);
        if (eacces)
                errno = EACCES;
        return (-1);
}

static char time_buf[50];

/**
 ** exec() - FORK AND EXEC CHILD PROCESS
 **/

/*VARARGS1*/
int
exec(int type, ...)
{
	va_list			args;

	int			i;
	int			procuid;
	int			procgid;
	int			ret;
	int			fr_flg;

	char			*cp;
	char			*infile;
	char			*outfile;
	char			*errfile;
	char			*sep;

	char			**listp;
	char			**file_list;
	char			*printerName;
	char			*printerNameToShow;
	static char		nameBuf[100];
	char			*clean_title;

	PSTATUS			*printer;

	RSTATUS			*request;

	FSTATUS			*form;

	EXEC			*ep;

	PWSTATUS		*pwheel;
	time_t			now;
	struct passwd		*pwp;
#ifdef LP_USE_PAPI_ATTR
	struct stat		tmpBuf;
	char 			tmpName[BUFSIZ];
	char			*path = NULL;
#endif
	char *av[ARG_MAX];
	char **envp = NULL;
	int ac = 0;
	char	*mail_zonename = NULL;
	char	*slabel = NULL;
	int	setid = 1;
	char	*ridno = NULL, *tmprid = NULL;

	syslog(LOG_DEBUG, "exec(%s)", _exec_name(type));

	memset(av, 0, sizeof (*av));

	va_start (args, type);

	switch (type) {

	case EX_INTERF:
		printer = va_arg(args, PSTATUS *);
		request = printer->request;
		ep = printer->exec;
		break;

	case EX_FAULT_MESSAGE:
		printer = va_arg(args, PSTATUS *);
		request = va_arg(args, RSTATUS *);
		if (! ( printer->status & (PS_FORM_FAULT | PS_SHOW_FAULT))) {
			return(0);
		}
		ep = printer->fault_exec;
		printerName = (printer->printer && printer->printer->name
				  ? printer->printer->name : "??");
			snprintf(nameBuf, sizeof (nameBuf),
				"%s (on %s)\n", printerName, Local_System);

		printerNameToShow = nameBuf;

		(void) time(&now);
		(void) strftime(time_buf, sizeof (time_buf),
			NULL, localtime(&now));
		break;

	case EX_SLOWF:
		request = va_arg(args, RSTATUS *);
		ep = request->exec;
		break;

	case EX_NOTIFY:
		request = va_arg(args, RSTATUS *);
		if (request->request->actions & ACT_NOTIFY) {
			errno = EINVAL;
			return (-1);
		}
		ep = request->exec;
		break;

	case EX_ALERT:
		printer = va_arg(args, PSTATUS *);
		if (!(printer->printer->fault_alert.shcmd)) {
			errno = EINVAL;
			return(-1);
		}
		ep = printer->alert->exec;
		break;

	case EX_PALERT:
		pwheel = va_arg(args, PWSTATUS *);
		ep = pwheel->alert->exec;
		break;

	case EX_FORM_MESSAGE:
		(void) time(&now);
		(void) strftime(time_buf, sizeof (time_buf),
			NULL, localtime(&now));

		/*FALLTHRU*/
	case EX_FALERT:
		form = va_arg(args, FSTATUS *);
		ep = form->alert->exec;
		break;

	default:
		errno = EINVAL;
		return(-1);

	}
	va_end (args);

	if (!ep || (ep->pid > 0)) {
		errno = EBUSY;
		return(-1);
	}

	ep->flags = 0;

	key = ep->key = getkey();

	switch ((ep->pid = Fork1(ep))) {

	case -1:
		relock ();
		return(-1);

	case 0:
		/*
		 * We want to be able to tell our parent how we died.
		 */
		lp_alloc_fail_handler = child_mallocfail;
		break;

	default:
		switch(type) {

		case EX_INTERF:
			request->request->outcome |= RS_PRINTING;
			break;

		case EX_NOTIFY:
			request->request->outcome |= RS_NOTIFYING;
			break;

		case EX_SLOWF:
			request->request->outcome |= RS_FILTERING;
			request->request->outcome &= ~RS_REFILTER;
			break;

		}
		return(0);

	}

	for (i = 0; i < NSIG; i++)
		(void)signal (i, SIG_DFL);
	(void)signal (SIGALRM, SIG_IGN);
	(void)signal (SIGTERM, sigtrap);

	closelog();
	for (i = 0; i < OpenMax; i++)
		if (i != ChildMd->writefd)
			Close (i);
	openlog("lpsched", LOG_PID|LOG_NDELAY|LOG_NOWAIT, LOG_LPR);

	setpgrp();

	/* Set a default path */
	addenv (&envp, "PATH", "/usr/lib/lp/bin:/usr/bin:/bin:/usr/sbin:/sbin");
	/* copy locale related variables */
	addenv (&envp, "TZ", getenv("TZ"));
	addenv (&envp, "LANG", getenv("LANG"));
	addenv (&envp, "LC_ALL", getenv("LC_ALL"));
	addenv (&envp, "LC_COLLATE", getenv("LC_COLLATE"));
	addenv (&envp, "LC_CTYPE", getenv("LC_CTYPE"));
	addenv (&envp, "LC_MESSAGES", getenv("LC_MESSAGES"));
	addenv (&envp, "LC_MONETARY", getenv("LC_MONETARY"));
	addenv (&envp, "LC_NUMERIC", getenv("LC_NUMERIC"));
	addenv (&envp, "LC_TIME", getenv("LC_TIME"));

	sprintf ((cp = BIGGEST_NUMBER_S), "%ld", key);
	addenv (&envp, "SPOOLER_KEY", cp);

#if	defined(DEBUG)
	addenv (&envp, "LPDEBUG", (debug? "1" : "0"));
#endif

	/*
	 * Open the standard input, standard output, and standard error.
	 */
	switch (type) {

	case EX_SLOWF:
	case EX_INTERF:
		/*
		 * stdin:  /dev/null
		 * stdout: /dev/null (EX_SLOWF), printer port (EX_INTERF)
		 * stderr: req#
		 */
		infile = 0;
		outfile = 0;
		errfile = makereqerr(request);
		break;

	case EX_NOTIFY:
		/*
		 * stdin:  req#
		 * stdout: /dev/null
		 * stderr: /dev/null
		 */
		infile = makereqerr(request);
		outfile = 0;
		errfile = 0;

		break;

	case EX_ALERT:
	case EX_FALERT:
	case EX_PALERT:
	case EX_FAULT_MESSAGE:
	case EX_FORM_MESSAGE:
		/*
		 * stdin:  /dev/null
		 * stdout: /dev/null
		 * stderr: /dev/null
		 */
		infile = 0;
		outfile = 0;
		errfile = 0;
		break;

	}

	if (infile) {
		if (Open(infile, O_RDONLY) == -1)
			Done (EXEC_EXIT_NOPEN, errno);
	} else {
		if (Open("/dev/null", O_RDONLY) == -1)
			Done (EXEC_EXIT_NOPEN, errno);
	}

	if (outfile) {
		if (Open(outfile, O_CREAT|O_TRUNC|O_WRONLY, 0600) == -1)
			Done (EXEC_EXIT_NOPEN, errno);
	} else {
		/*
		 * If EX_INTERF, this is still needed to cause the
		 * standard error channel to be #2.
		 */
		if (Open("/dev/null", O_WRONLY) == -1)
			Done (EXEC_EXIT_NOPEN, errno);
	}

	if (errfile) {
		if (Open(errfile, O_CREAT|O_TRUNC|O_WRONLY, 0600) == -1)
			Done (EXEC_EXIT_NOPEN, errno);
	} else {
		if (Open("/dev/null", O_WRONLY) == -1)
			Done (EXEC_EXIT_NOPEN, errno);
	}

	switch (type) {

	case EX_INTERF:
		/*
		 * Opening a ``port'' can be dangerous to our health:
		 *
		 *	- Hangups can occur if the line is dropped.
		 *	- The printer may send an interrupt.
		 *	- A FIFO may be closed, generating SIGPIPE.
		 *
		 * We catch these so we can complain nicely.
		 */
		trap_fault_signals ();

		(void)Close (1);

		procuid = request->secure->uid;
		procgid = request->secure->gid;

		if (printer->printer->dial_info)
		{
			ret = open_dialup(request->printer_type,
				printer->printer);
			if (ret == 0)
				do_undial = 1;
		}
		else
		{
			ret = open_direct(request->printer_type,
				printer->printer);
			do_undial = 0;
			/* this is a URI */
			if (is_printer_uri(printer->printer->device) == 0)
				addenv(&envp, "DEVICE_URI",
					 printer->printer->device);
		}
				addenv(&envp, "DEVICE_URI",
					 printer->printer->device);
		if (ret != 0)
			Done (ret, errno);

		if (!(request->request->outcome & RS_FILTERED))
			file_list = request->request->file_list;

		else {
			register int		count	= 0;
			register char *		num	= BIGGEST_REQID_S;
			register char *		prefix;

			prefix = makestr(
				Lp_Temp,
				"/F",
				getreqno(request->secure->req_id),
				"-",
				(char *)0
			);

			file_list = (char **)Malloc(
				(lenlist(request->request->file_list) + 1)
			      * sizeof(char *)
			);

			for (
				listp = request->request->file_list;
				*listp;
				listp++
			) {
				sprintf (num, "%d", count + 1);
				file_list[count] = makestr(
					prefix,
					num,
					(char *)0
				);
				count++;
			}
			file_list[count] = 0;
		}

#ifdef LP_USE_PAPI_ATTR
		/*
		 * Check if the PAPI job attribute file exists, if it does
		 * pass the file's pathname to the printer interface script
		 * in an environment variable. This file is created when
		 * print jobs are submitted via the PAPI interface.
		 */
		snprintf(tmpName, sizeof (tmpName), "%s-%s",
			getreqno(request->secure->req_id), LP_PAPIATTRNAME);
		path = makepath(Lp_Temp, tmpName, (char *)0);
		if ((path != NULL) && (stat(path, &tmpBuf) == 0))
		{
			/*
			 * IPP job attribute file exists for this job so
			 * set the environment variable
			 */
			addenv(&envp, "ATTRPATH", path);
		}
		Free(path);

		/*
		 * now set environment variable for the printer's PostScript
		 * Printer Description (PPD) file, this is used by the filter
		 * when forming the print data for this printer.
		 */
		if ((request->printer != NULL) &&
		    (request->printer->printer != NULL) &&
		    (request->printer->printer->name != NULL))
		{
			snprintf(tmpName, sizeof (tmpName), "%s.ppd",
				request->printer->printer->name);
			path = makepath(ETCDIR, "ppd", tmpName, (char *)0);
			if ((path != NULL) && (stat(path, &tmpBuf) == 0))
			{
				addenv(&envp, "PPD", path);
			}
			Free(path);
		}
#endif

		if (request->printer_type)
			addenv(&envp, "TERM", request->printer_type);

		if (!(printer->printer->daisy)) {
			register char *	chset = 0;
			register char *	csp;

			if (
				request->form
			     && request->form->form->chset
			     && request->form->form->mandatory
			     && !STREQU(NAME_ANY, request->form->form->chset)
			)
				chset = request->form->form->chset;

			else if (
				request->request->charset
			     && !STREQU(NAME_ANY, request->request->charset)
			)
				chset = request->request->charset;

			if (chset) {
				csp = search_cslist(
					chset,
					printer->printer->char_sets
				);

				/*
				 * The "strtok()" below wrecks the string
				 * for future use, but this is a child
				 * process where it won't be needed again.
				 */
				addenv (&envp, "CHARSET",
					(csp? strtok(csp, "=") : chset)
				);
			}
		}

		if (request->fast)
			addenv(&envp, "FILTER", request->fast);

		/*
		 * Add the sensitivity label to the environment for
		 * banner page and header/footer processing
		 */

		if (is_system_labeled() && request->secure->slabel != NULL)
			addenv(&envp, "SLABEL", request->secure->slabel);

		/*
		 * Add the system name to the user name (ala system!user)
		 * unless it is already there. RFS users may have trouble
		 * here, sorry!
		 */
		cp = strchr(request->secure->user, '@');

		allTraysWithForm(printer, request->form);

		/*
		 * Fix for 4137389
		 * Remove double quotes from title string.
		 */
		fr_flg = 1;
		clean_title = strdup(NB(request->request->title));
		if (clean_title == NULL) {
			/*
			 * strdup failed. We're probably hosed
			 * but try setting clean_title
			 * to original title and continuing.
			 */
			clean_title = NB(request->request->title);
			fr_flg = 0;
		} else if (strcmp(clean_title, "") != 0) {
			char *ct_p;

			for (ct_p = clean_title; *ct_p != NULL; ct_p++) {
				if (*ct_p == '"')
					*ct_p = ' ';
			}
		}

		av[ac++] = arg_string(TRUSTED, "%s/%s", Lp_A_Interfaces,
					printer->printer->name);
		/*
		 * Read the options field of the request
		 * In case of remote lpd request
		 * the options field will have
		 * job-id-requested. This is the
		 * id sent by the client
		 */
		if (request->request->options != NULL) {
			char *options = NULL, *temp = NULL;
			options = temp = strdup(request->request->options);

			/*
			 * Search for job-id-requested in
			 * options string
			 */
			options = strstr(options, "job-id-requested");
			if (options != NULL) {
				/*
				 * Extract the ridno from the string
				 * job-id-requested=xxx
				 * In this case ridno = xxx
				 */
				if (STRNEQU(options, "job-id-requested=", 17)) {
					ridno = strdup(options + 17);
					tmprid = strstr(ridno, " ");
					if (ridno != NULL) {
						/*
						 * Read job-id-requested
						 * successfully
						 */
						tmprid = strstr(ridno, " ");
						if (tmprid != NULL)
							*tmprid = '\0';

						setid = 0;
					} else
						/*
						 * could not read
						 * ridno from the string
						 * job-id-requested=xxx
						 */
						setid = 1;
				} else
					/*
					 * could not read
					 * ridno from the string
					 * job-id-requested=xxx
					 */
					setid = 1;
			} else
				/*
				 * No job-id-requested in
				 * request options
				 */
				setid = 1;

			if (temp != NULL)
				free(temp);

		} else
			/*
			 * options field in request structure
			 * not set
			 */
			setid = 1;


		/*
		 * setid = 1 means the job-id-requested attribute
		 * is not set so read the request->secure->req_id
		 */
		if (setid)
			av[ac++] = arg_string(TRUSTED, "%s",
			    request->secure->req_id);
		else {
			/*
			 * From request->secure->req_id extract the
			 * printer-name.
			 * request->secure->req_id = <printer-name>-<req_id>
			 * The final req-id will be
			 * <printer-name>-<ridno>
			 */
			char *r1 = NULL, *r2 = NULL, *tmp = NULL;
			r1 = r2 = tmp = strdup(request->secure->req_id);
			r2 = strrchr(r1, '-');
			if (r2 != NULL) {
				char *r3 = NULL;
				int lr1 = strlen(r1);
				int lr2 = strlen(r2);
				r1[lr1 - lr2 + 1] = '\0';

				/*
				 * Now r1 = <printer-name>-
				 */
				lr1 = strlen(r1);
				lr2 = strlen(ridno);

				r3 = (char *)malloc(lr1+lr2+1);
				if (r3 != NULL) {
					strcpy(r3, r1);
					strcat(r3, ridno);
					/*
					 * Here r3 = <printer-name>-<ridno>
					 */
					av[ac++] = arg_string(TRUSTED,
					    "%s", r3);
					free(r3);
				} else
					av[ac++] = arg_string(TRUSTED, "%s",
					    request->secure->req_id);

			} else
				av[ac++] = arg_string(TRUSTED, "%s",
				    request->secure->req_id);

			if (tmp != NULL)
				free(tmp);

			if (ridno != NULL)
				free(ridno);
		}

		av[ac++] = arg_string(UNTRUSTED, "%s", request->request->user);
		av[ac++] = arg_string(TRUSTED, "%s", clean_title);
		av[ac++] = arg_string(TRUSTED, "%d", request->copies);

		if (fr_flg)
			free (clean_title);

		sep = "";

		/*
		 * Do the administrator defined key=value pair options
		 */

		argbuf[0] = '\0';

		if (printer->printer->options) {
			char **tmp = printer->printer->options;
			while(*tmp != NULL) {
				STRLCAT(argbuf, sep, sizeof (argbuf));
				sep = " ";
				STRLCAT(argbuf, *tmp++, sizeof (argbuf));
			}
		}

		/*
		 * Do the administrator defined ``stty'' stuff before
		 * the user's -o options, to allow the user to override.
		 */
		if (printer->printer->stty) {
			STRLCAT (argbuf, sep, sizeof (argbuf));
			sep = " ";
			STRLCAT (argbuf, "stty='", sizeof (argbuf));
			STRLCAT (argbuf, printer->printer->stty,
			    sizeof (argbuf));
			STRLCAT (argbuf, "'", sizeof (argbuf));
		}

		/*
		 * Do all of the user's options except the cpi/lpi/etc.
		 * stuff, which is done separately.
		 */
		if (request->request->options) {
			listp = dashos(request->request->options);
			while (*listp) {
				if (
					!STRNEQU(*listp, "cpi=", 4)
				     && !STRNEQU(*listp, "lpi=", 4)
				     && !STRNEQU(*listp, "width=", 6)
				     && !STRNEQU(*listp, "length=", 7)
				) {
					STRLCAT (argbuf, sep, sizeof (argbuf));
					sep = " ";
					STRLCAT (argbuf, *listp,
					    sizeof (argbuf));
				}
				listp++;
			}
		}

		/*
		 * The "pickfilter()" routine (from "validate()")
		 * stored the cpi/lpi/etc. stuff that should be
		 * used for this request. It chose form over user,
		 * and user over printer.
		 */
		if (request->cpi) {
			STRLCAT (argbuf, sep, sizeof (argbuf));
			sep = " ";
			STRLCAT (argbuf, "cpi=", sizeof (argbuf));
			STRLCAT (argbuf, request->cpi, sizeof (argbuf));
		}
		if (request->lpi) {
			STRLCAT (argbuf, sep, sizeof (argbuf));
			sep = " ";
			STRLCAT (argbuf, "lpi=", sizeof (argbuf));
			STRLCAT (argbuf, request->lpi, sizeof (argbuf));
		}
		if (request->pwid) {
			STRLCAT (argbuf, sep, sizeof (argbuf));
			sep = " ";
			STRLCAT (argbuf, "width=", sizeof (argbuf));
			STRLCAT (argbuf, request->pwid, sizeof (argbuf));
		}
		if (request->plen) {
			STRLCAT (argbuf, sep, sizeof (argbuf));
			sep = " ";
			STRLCAT (argbuf, "length=", sizeof (argbuf));
			STRLCAT (argbuf, request->plen, sizeof (argbuf));
		}

		/*
		 * Do the ``raw'' bit last, to ensure it gets
		 * done. If the user doesn't want this, then they
		 * can do the correct thing using -o stty=
		 * and leaving out the -r option.
		 */
		if (request->request->actions & ACT_RAW) {
			STRLCAT (argbuf, sep, sizeof (argbuf));
			sep = " ";
			STRLCAT (argbuf, "stty=-opost", sizeof (argbuf));
		}


		/* the "options" */
		av[ac++] = arg_string(UNTRUSTED, "%s", argbuf);

		for (listp = file_list; *listp; listp++)
			av[ac++] = arg_string(TRUSTED, "%s", *listp);

		(void)chfiles (file_list, procuid, procgid);

		break;


	case EX_SLOWF:
		if (request->slow)
			addenv(&envp, "FILTER", request->slow);

		procuid = request->secure->uid;
		procgid = request->secure->gid;

		cp = _alloc_files(
			lenlist(request->request->file_list),
			getreqno(request->secure->req_id),
			procuid, procgid);

		av[ac++] = arg_string(TRUSTED, "%s", Lp_Slow_Filter);
		av[ac++] = arg_string(TRUSTED, "%s/%s", Lp_Temp, cp);
		for (listp = request->request->file_list; *listp; listp++)
			av[ac++] = arg_string(TRUSTED, "%s", *listp);

		(void)chfiles (request->request->file_list, procuid, procgid);

#ifdef LP_USE_PAPI_ATTR
		/*
		 * Check if the PAPI job attribute file exists, if it does
		 * pass the file's pathname to the slow-filters in an
		 * environment variable. Note: this file is created when
		 * print jobs are submitted via the PAPI interface.
		 */
		snprintf(tmpName, sizeof (tmpName), "%s-%s",
			getreqno(request->secure->req_id), LP_PAPIATTRNAME);
		path = makepath(Lp_Temp, tmpName, (char *)0);
		if ((path != NULL) && (stat(path, &tmpBuf) == 0))
		{
			/*
			 * IPP job attribute file exists for this job so
			 * set the environment variable
			 */
			addenv(&envp, "ATTRPATH", path);
		}
		Free(path);


		/*
		 * now set environment variable for the printer's PostScript
		 * Printer Description (PPD) file, this is used by the filter
		 * when forming the print data for this printer.
		 */
		if ((request->printer != NULL) &&
		    (request->printer->printer != NULL) &&
		    (request->printer->printer->name != NULL))
		{
			snprintf(tmpName, sizeof (tmpName), "%s.ppd",
				request->printer->printer->name);
			path = makepath(ETCDIR, "ppd", tmpName, (char *)0);
			if ((path != NULL) && (stat(path, &tmpBuf) == 0))
			{
				addenv(&envp, "PPD", path);
			}
			Free(path);
		}
#endif
		break;

	case EX_ALERT:
		procuid = Lp_Uid;
		procgid = Lp_Gid;
		(void)Chown (printer->alert->msgfile, procuid, procgid);

		av[ac++] = arg_string(TRUSTED, "%s/%s/%s", Lp_A_Printers,
				printer->printer->name, ALERTSHFILE);
		av[ac++] = arg_string(TRUSTED, "%s", printer->alert->msgfile);

		break;

	case EX_PALERT:
		procuid = Lp_Uid;
		procgid = Lp_Gid;
		(void)Chown (pwheel->alert->msgfile, procuid, procgid);

		av[ac++] = arg_string(TRUSTED, "%s/%s/%s", Lp_A_PrintWheels,
				pwheel->pwheel->name, ALERTSHFILE);
		av[ac++] = arg_string(TRUSTED, "%s", printer->alert->msgfile);

		break;

	case EX_FALERT:
		procuid = Lp_Uid;
		procgid = Lp_Gid;
		(void)Chown (form->alert->msgfile, procuid, procgid);

		av[ac++] = arg_string(TRUSTED, "%s/%s/%s", Lp_A_Forms,
				form->form->name, ALERTSHFILE);
		av[ac++] = arg_string(TRUSTED, "%s", printer->alert->msgfile);

		break;

	case EX_FORM_MESSAGE:
		procuid = Lp_Uid;
		procgid = Lp_Gid;

		av[ac++] = arg_string(TRUSTED, "%s/form", Lp_A_Faults);
		av[ac++] = arg_string(TRUSTED, "%s", form->form->name);
		av[ac++] = arg_string(TRUSTED, "%s", time_buf);
		av[ac++] = arg_string(TRUSTED, "%s/%s/%s", Lp_A_Forms,
				form->form->name, FORMMESSAGEFILE);

		break;

	case EX_FAULT_MESSAGE:
		procuid = Lp_Uid;
		procgid = Lp_Gid;

		av[ac++] = arg_string(TRUSTED, "%s/printer", Lp_A_Faults);
		av[ac++] = arg_string(TRUSTED, "%s", printerNameToShow);
		av[ac++] = arg_string(TRUSTED, "%s", time_buf);
		av[ac++] = arg_string(TRUSTED, "%s/%s/%s", Lp_A_Printers,
				printerName, FAULTMESSAGEFILE);

		break;

	case EX_NOTIFY:
		if (request->request->alert) {
			procuid = request->secure->uid;
			procgid = request->secure->gid;

			av[ac++] = arg_string(TRUSTED, "%s",
					request->request->alert);
		} else {
			char *user = strdup(request->request->user);
			clean_string(user);
			slabel = request->secure->slabel;

			if (request->request->actions & ACT_WRITE) {
				av[ac++] = arg_string(TRUSTED, "%s", BINWRITE);
				snprintf(argbuf, sizeof (argbuf),
					"%s %s || %s %s",
					BINWRITE, user,
					BINMAIL, user
				);
				av[ac++] = arg_string(TRUSTED, "/bin/sh");
				av[ac++] = arg_string(TRUSTED, "-c");
				av[ac++] = arg_string(TRUSTED, "%s", argbuf);
			} else if ((getzoneid() == GLOBAL_ZONEID) &&
				   is_system_labeled() && (slabel != NULL)) {
				/*
				 * If in the global zone and the system is
				 * labeled, mail is handled via a local
				 * labeled zone that is the same label as
				 * the request.
				 */
				if ((mail_zonename =
				    get_labeled_zonename(slabel)) ==
				    (char *)-1) {
					/*
					 * Cannot find labeled zone, just
					 * return 0.
					 */
					return(0);
				}
			}
			if (mail_zonename == NULL) {
				procuid = Lp_Uid;
				procgid = Lp_Gid;
				av[ac++] = arg_string(TRUSTED, "%s", BINMAIL);
				av[ac++] = arg_string(UNTRUSTED, "%s", user);
			} else {
				procuid = getuid();
				procgid = getgid();
				av[ac++] = arg_string(TRUSTED, "%s",
				    "/usr/sbin/zlogin");
				av[ac++] = arg_string(TRUSTED, "%s",
				    mail_zonename);
				av[ac++] = arg_string(TRUSTED, "%s",
				    BINMAIL);
				av[ac++] = arg_string(UNTRUSTED, "%s",
				    user);
				Free(mail_zonename);
			}

			free(user);
		}
		break;
	}

	av[ac++] = NULL;

	Fork2 ();
	/* only the child returns */

	/*
	 * Correctly set up the supplemental group list
	 * for proper file access (before execl the interface program)
	 */

	pwp = getpwuid(procuid);
	if (pwp == NULL) {
		note("getpwuid(%d) call failed\n", procuid);
	} else if (initgroups(pwp->pw_name, procgid) < 0) {
		note("initgroups() call failed %d\n", errno);
	}

	setgid (procgid);
	setuid (procuid);

	/*
	 * The shell doesn't allow the "trap" builtin to set a trap
	 * for a signal ignored when the shell is started. Thus, don't
	 * turn off signals in the last child!
	 */

#ifdef DEBUG
	for (i = 0; av[i] != NULL; i++)
		note("exec(%s): av[%d] = %s", _exec_name(type), i, av[i]);
	for (i = 0; envp[i] != NULL; i++)
		note("exec(%s): envp[%d] = %s", _exec_name(type), i, envp[i]);
#endif

	execvpe(av[0], av, envp);
	Done (EXEC_EXIT_NEXEC, errno);
	/*NOTREACHED*/
	return (0);
}

/**
 ** addenv() - ADD A VARIABLE TO THE ENVIRONMENT
 **/

static void
addenv(char ***envp, char *name, char *value)
{
	register char *		cp;

	if ((name == NULL) || (value == NULL))
		return;

	if ((cp = makestr(name, "=", value, (char *)0)))
		addlist(envp, cp);
	return;
}

/**
 ** Fork1() - FORK FIRST CHILD, SET UP CONNECTION TO IT
 **/

static int
Fork1(EXEC *ep)
{
	int			pid;
	int			fds[2];

	if (pipe(fds) == -1) {
		note("Failed to create pipe for child process (%s).\n", PERROR);
		errno = EAGAIN ;
		return(-1);
	}

	ep->md = mconnect((char *)0, fds[0], fds[1]);

	switch (pid = fork()) {

	case -1:
		mdisconnect(ep->md);
		close(fds[0]);
		close(fds[1]);
		ep->md = 0;
		return (-1);

	case 0:
		ChildMd = mconnect(NULL, fds[1], fds[1]);
		return (0);

	default:
		mlistenadd(ep->md, POLLIN);
		return (pid);
	}
}

/**
 ** Fork2() - FORK SECOND CHILD AND WAIT FOR IT
 **/

static void
Fork2(void)
{
	switch ((ChildPid = fork())) {

	case -1:
		Done (EXEC_EXIT_NFORK, errno);
		/*NOTREACHED*/

	case 0:
		return;

	default:
		/*
		 * Delay calling "ignore_fault_signals()" as long
		 * as possible, to give the child a chance to exec
		 * the interface program and turn on traps.
		 */

		cool_heels ();
		/*NOTREACHED*/

	}
}


/**
 ** cool_heels() - WAIT FOR CHILD TO "DIE"
 **/

static void
cool_heels(void)
{
	int			status;

	/*
	 * At this point our only job is to wait for the child process.
	 * If we hang out for a bit longer, that's okay.
	 * By delaying before turning off the fault signals,
	 * we increase the chance that the child process has completed
	 * its exec and has turned on the fault traps. Nonetheless,
	 * we can't guarantee a zero chance of missing a fault.
	 * (We don't want to keep trapping the signals because the
	 * interface program is likely to have a better way to handle
	 * them; this process provides only rudimentary handling.)
	 *
	 * Note that on a very busy system, or with a very fast interface
	 * program, the tables could be turned: Our sleep below (coupled
	 * with a delay in the kernel scheduling us) may cause us to
	 * detect the fault instead of the interface program.
	 *
	 * What we need is a way to synchronize with the child process.
	 */
	sleep (1);
	ignore_fault_signals ();

	WaitedChildPid = 0;
	while ((WaitedChildPid = wait(&status)) != ChildPid)
		;

	if (
		EXITED(status) > EXEC_EXIT_USER
	     && EXITED(status) != EXEC_EXIT_FAULT
	)
		Done (EXEC_EXIT_EXIT, EXITED(status));

	done (status, 0);	/* Don't use Done() */
	/*NOTREACHED*/
}


/**
 ** trap_fault_signals() - TRAP SIGNALS THAT CAN OCCUR ON PRINTER FAULT
 ** ignore_fault_signals() - IGNORE SAME
 **/

static void
trap_fault_signals(void)
{
	signal (SIGHUP, sigtrap);
	signal (SIGINT, sigtrap);
	signal (SIGQUIT, sigtrap);
	signal (SIGPIPE, sigtrap);
	return;
}

static void
ignore_fault_signals(void)
{
	signal (SIGHUP, SIG_IGN);
	signal (SIGINT, SIG_IGN);
	signal (SIGQUIT, SIG_IGN);
	signal (SIGPIPE, SIG_IGN);
	return;
}

/**
 ** sigtrap() - TRAP VARIOUS SIGNALS
 **/

static void
sigtrap(int sig)
{
	signal (sig, SIG_IGN);
	switch (sig) {

	case SIGHUP:
		Done (EXEC_EXIT_HUP, 0);
		/*NOTREACHED*/

	case SIGQUIT:
	case SIGINT:
		Done (EXEC_EXIT_INTR, 0);
		/*NOTREACHED*/

	case SIGPIPE:
		Done (EXEC_EXIT_PIPE, 0);
		/*NOTREACHED*/

	case SIGTERM:
		/*
		 * If we were killed with SIGTERM, it should have been
		 * via the Spooler who should have killed the entire
		 * process group. We have to wait for the children,
		 * since we're their parent, but WE MAY HAVE WAITED
		 * FOR THEM ALREADY (in cool_heels()).
		 */
		if (ChildPid != WaitedChildPid) {
			register int		cpid;

			while (
				(cpid = wait((int *)0)) != ChildPid
			     && (cpid != -1 || errno != ECHILD)
			)
				;
		}

		/*
		 * We can't rely on getting SIGTERM back in the wait()
		 * above, because, for instance, some shells trap SIGTERM
		 * and exit instead. Thus we force it.
		 */
		done (SIGTERM, 0);	/* Don't use Done() */
		/*NOTREACHED*/
	}
}

/**
 ** done() - TELL SPOOLER THIS CHILD IS DONE
 **/

static void
done(int status, int err)
{
	if (do_undial)
		undial (1);

	mputm (ChildMd, S_CHILD_DONE, key, status, err);
	mdisconnect (ChildMd);

	exit (0);
	/*NOTREACHED*/
}

/**
 ** child_mallocfail()
 **/

static void
child_mallocfail(void)
{
	Done (EXEC_EXIT_NOMEM, ENOMEM);
}
