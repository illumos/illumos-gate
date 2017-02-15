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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/zone.h>
#include <stdlib.h>
#include <libintl.h>
#include <sys/tsol/label_macro.h>
#include <bsm/devices.h>
#include "lp.h"
#include "class.h"
#if defined PS_FAULTED
#undef	PS_FAULTED
#endif
#include "printers.h"
#include "msgs.h"

#define	WHO_AM_I	I_AM_LPADMIN
#include "oam.h"

#include "lpadmin.h"

extern	void	fromallclasses();

#if !defined(PATH_MAX)
#define	PATH_MAX	1024
#endif
#if PATH_MAX < 1024
#undef PATH_MAX
#define	PATH_MAX	1024
#endif

extern char		*label;

static void		configure_printer();
static char		*fullpath();
char			*nameit();
static void		pack_white(char *ptr);

/*
 * do_printer() - CREATE OR CHANGE PRINTER
 */

void
do_printer(void)
{
	int rc;

	/*
	 * Set or change the printer configuration.
	 */
	if (strlen(modifications))
		configure_printer(modifications);

	/*
	 * Allow/deny forms.
	 */
	BEGIN_CRITICAL
		if (!oldp)
			if (allow_form_printer(
			    getlist(NAME_NONE, "", ","), p) == -1) {
				LP_ERRMSG1(ERROR, E_ADM_ACCESSINFO, PERROR);
				done(1);
			}

		if (f_allow || f_deny) {
			if (f_allow && allow_form_printer(f_allow, p) == -1) {
				LP_ERRMSG1(ERROR, E_ADM_ACCESSINFO, PERROR);
				done(1);
			}

			if (f_deny && deny_form_printer(f_deny, p) == -1) {
				LP_ERRMSG1(ERROR, E_ADM_ACCESSINFO, PERROR);
				done(1);
			}
		}
	END_CRITICAL

	/* Add/remove types of paper */

	BEGIN_CRITICAL
		if (!oldp)
			if (add_paper_to_printer(
			    getlist(NAME_NONE, "", ","), p) == -1) {
				LP_ERRMSG1(ERROR, E_ADM_ACCESSINFO, PERROR);
				done(1);
			}


		if (p_add && add_paper_to_printer(p_add, p) == -1) {
			LP_ERRMSG1(ERROR, E_ADM_ACCESSINFO, PERROR);
			done(1);
		}

		if (p_remove && remove_paper_from_printer(p_remove, p) == -1) {
			LP_ERRMSG1(ERROR, E_ADM_ACCESSINFO, PERROR);
			done(1);
		}
	END_CRITICAL

	/*
	 * Allow/deny users.
	 */
	BEGIN_CRITICAL
		if (!oldp)
			if (allow_user_printer(
			    getlist(NAME_ALL, "", ","), p) == -1) {
				LP_ERRMSG1(ERROR, E_ADM_ACCESSINFO, PERROR);
				done(1);
			}

		if (u_allow || u_deny) {
			if (u_allow && allow_user_printer(u_allow, p) == -1) {
				LP_ERRMSG1(ERROR, E_ADM_ACCESSINFO, PERROR);
				done(1);
			}

			if (u_deny && deny_user_printer(u_deny, p) == -1) {
				LP_ERRMSG1(ERROR, E_ADM_ACCESSINFO, PERROR);
				done(1);
			}
		}
	END_CRITICAL

	/*
	 * Tell the Spooler about the printer
	 */
	send_message(S_LOAD_PRINTER, p, "", "");
	rc = output(R_LOAD_PRINTER);

	switch (rc) {
	case MOK:
		break;

	case MNODEST:
	case MERRDEST:
		LP_ERRMSG(ERROR, E_ADM_ERRDEST);
		done(1);
		/*NOTREACHED*/

	case MNOSPACE:
		LP_ERRMSG(WARNING, E_ADM_NOPSPACE);
		break;

	case MNOPERM:	/* taken care of up front */
	default:
		LP_ERRMSG1(ERROR, E_LP_BADSTATUS, rc);
		done(1);
		/*NOTREACHED*/
	}

	/*
	 * Now that the Spooler knows about the printer,
	 * we can do the balance of the changes.
	 */

	/*
	 * Mount or unmount form, print-wheel.
	 */
	if (M)
		do_mount(p, (f? f : NULL), (S? *S : NULL));
	else if (t)
		do_max_trays(p);

	/*
	 * Display the alert type.
	 */
	if (A && STREQU(A, NAME_LIST)) {
		if (label)
			(void) printf(gettext("Printer %s: "), label);
		printalert(stdout, &(oldp->fault_alert), 1);
	}

	/*
	 * -A quiet.
	 */
	if (A && STREQU(A, NAME_QUIET)) {

		send_message(S_QUIET_ALERT, p, (char *)QA_PRINTER, "");
		rc = output(R_QUIET_ALERT);

		switch (rc) {
		case MOK:
			break;

		case MNODEST:	/* not quite, but not a lie either */
		case MERRDEST:
			LP_ERRMSG1(WARNING, E_LP_NOQUIET, p);
			break;

		case MNOPERM:	/* taken care of up front */
		default:
			LP_ERRMSG1(ERROR, E_LP_BADSTATUS, rc);
			done(1);
			/*NOTREACHED*/
		}
	}

	/*
	 * Add printer p to class c
	 */
	if (c)  {
		CLASS *pc;
		CLASS clsbuf;

		if (STREQU(c, NAME_ANY))
			c = NAME_ALL;

Loop:		if (!(pc = getclass(c))) {
			if (STREQU(c, NAME_ALL))
				goto Done;

			if (errno != ENOENT) {
				LP_ERRMSG2(ERROR, E_LP_GETCLASS, c, PERROR);
				done(1);
			}

			/*
			 * Create the class
			 */
			clsbuf.name = strdup(c);
			clsbuf.members = 0;
			if (addlist(&clsbuf.members, p) == -1) {
				LP_ERRMSG(ERROR, E_LP_MALLOC);
				done(1);
			}
			pc = &clsbuf;

		} else if (searchlist(p, pc->members))
			LP_ERRMSG2(WARNING, E_ADM_INCLASS, p, pc->name);

		else if (addlist(&pc->members, p) == -1) {
			LP_ERRMSG(ERROR, E_LP_MALLOC);
			done(1);
		}

		BEGIN_CRITICAL
			if (putclass(pc->name, pc) == -1) {
				LP_ERRMSG2(ERROR, E_LP_PUTCLASS, pc->name,
				    PERROR);
				done(1);
			}
		END_CRITICAL

		send_message(S_LOAD_CLASS, pc->name);
		rc = output(R_LOAD_CLASS);

		switch (rc) {
		case MOK:
			break;

		case MNODEST:
		case MERRDEST:
			LP_ERRMSG(ERROR, E_ADM_ERRDEST);
			done(1);
			/*NOTREACHED*/

		case MNOSPACE:
			LP_ERRMSG(WARNING, E_ADM_NOCSPACE);
			break;

		case MNOPERM:	/* taken care of up front */
		default:
			LP_ERRMSG1(ERROR, E_LP_BADSTATUS, rc);
			done(1);
			/*NOTREACHED*/
		}

		if (STREQU(c, NAME_ALL))
			goto Loop;
	}
Done:
	/*
	 * Remove printer p from class r
	 */
	if (r) {
		if (STREQU(r, NAME_ALL) || STREQU(r, NAME_ANY))
			fromallclasses(p);
		else
			fromclass(p, r);
	}
}

/*
 * configure_printer() - SET OR CHANGE CONFIGURATION OF PRINTER
 */

static void
configure_printer(char *list)
{
	PRINTER	*prbufp;
	PRINTER	 printer_struct;
	char type;
	char *infile_opts = NULL;

	if (oldp) {

		prbufp = oldp;

		if (!T)
			T = prbufp->printer_types;

		if (!i && !e && !m)
			/*
			 * Don't copy the original interface program
			 * again, but do keep the name of the original.
			 */
			ignprinter = BAD_INTERFACE;
		else
			ignprinter = 0;

		/*
		 * If we are making this a remote printer,
		 * make sure that local-only attributes are
		 * cleared.
		 */
		if (s) {
			prbufp->banner = 0;
			prbufp->cpi.val = 0;
			prbufp->cpi.sc = 0;
			prbufp->device = 0;
			prbufp->dial_info = 0;
			prbufp->fault_rec = 0;
			prbufp->interface = 0;
			prbufp->lpi.val = 0;
			prbufp->lpi.sc = 0;
			prbufp->plen.val = 0;
			prbufp->plen.sc = 0;
			prbufp->login = 0;
			prbufp->speed = 0;
			prbufp->stty = 0;
			prbufp->pwid.val = 0;
			prbufp->pwid.sc = 0;
			prbufp->fault_alert.shcmd = strdup(NAME_NONE);
			prbufp->fault_alert.Q = 0;
			prbufp->fault_alert.W = 0;
#if	defined(CAN_DO_MODULES)
			prbufp->modules = 0;
#endif

		/*
		 * If we are making this a local printer, make
		 * sure that some local-only attributes are set.
		 * (If the user has specified these as well, their
		 * values will overwrite what we set here.)
		 */
		} else if (oldp->remote) {
			prbufp->banner = BAN_ALWAYS;
			prbufp->interface = makepath(Lp_Model, STANDARD, NULL);
			prbufp->fault_alert.shcmd = nameit(NAME_MAIL);

			/*
			 * Being here means "!s && oldp->remote" is true,
			 * i.e. this printer never had an interface pgm
			 * before. Thus we can safely clear the following.
			 * This is needed to let "putprinter()" copy the
			 * (default) interface program.
			 */
			ignprinter = 0;
		}

	} else {
		/*
		 * The following takes care of the lion's share
		 * of the initialization of a new printer structure.
		 * However, special initialization (e.g. non-zero,
		 * or substructure members) needs to be considered
		 * for EACH NEW MEMBER added to the structure.
		 */
		(void) memset(&printer_struct, 0, sizeof (printer_struct));

		prbufp = &printer_struct;
		prbufp->banner = BAN_ALWAYS;
		prbufp->cpi.val = 0;
		prbufp->cpi.sc = 0;
		if (!s)
			prbufp->interface = makepath(Lp_Model, m, NULL);
		prbufp->lpi.val = 0;
		prbufp->lpi.sc = 0;
		prbufp->plen.val = 0;
		prbufp->plen.sc = 0;
		prbufp->pwid.val = 0;
		prbufp->pwid.sc = 0;
		if (!s && !A)
			prbufp->fault_alert.shcmd = nameit(NAME_MAIL);
		prbufp->fault_alert.Q = 0;
		prbufp->fault_alert.W = 0;
		prbufp->options = NULL;
	}

	while ((type = *list++) != '\0') {
		switch (type) {
		case 'A':
			if (!s) {
				if (STREQU(A, NAME_MAIL) ||
				    STREQU(A, NAME_WRITE))
					prbufp->fault_alert.shcmd = nameit(A);
				else if (!STREQU(A, NAME_QUIET))
					prbufp->fault_alert.shcmd = A;
			}
			break;

		case 'b':
			if (!s)
				prbufp->banner = banner;
			break;

		case 'c':
			if (!s)
				prbufp->cpi = cpi_sdn;
			break;

		case 'D':
			prbufp->description = D;
			break;

		case 'e':
			if (!s) {
				prbufp->interface = makepath(Lp_A_Interfaces,
				    e, NULL);
			}
			break;

		case 'F':
			if (!s)
				prbufp->fault_rec = F;
			break;

#if	defined(CAN_DO_MODULES)
		case 'H':
			if (!s)
				prbufp->modules = H;
			break;
#endif

		case 'h':
			if (!s)
				prbufp->login = 0;
			break;

		case 'i':
			if (!s)
				prbufp->interface = fullpath(i);
			break;

		case 'I':
			prbufp->input_types = I;
			break;

		case 'l':
			if (!s)
				prbufp->login = 1;
			break;

		case 'L':
			if (!s)
				prbufp->plen = length_sdn;
			break;

		case 'm':
			if (!s)
				prbufp->interface = makepath(Lp_Model, m, NULL);
			break;

		case 'M':
			if (!s)
				prbufp->lpi = lpi_sdn;
			break;

#ifdef LP_USE_PAPI_ATTR
		case 'n':
			if (n_opt != NULL) {
				if (*n_opt == '/') {
					prbufp->ppd = fullpath(n_opt);
				} else {
					prbufp->ppd = makepath(Lp_Model, "ppd",
					    n_opt, NULL);
				}
				ppdopt = 1;
			}
			break;
#endif

		case 'o':
			/*
			 * The "undefined" key-value -o options
			 *
			 * Options requires special handling. It is a
			 * list whose members are to be handled
			 * individually.
			 *
			 * Need to: set new options, keep old options if not
			 * redefined, remove old options if defined as "key=".
			 *
			 *
			 * "p" is a global containing the printer name
			 */

			if (!s) {
				if ((infile_opts =
				    getpentry(p, PR_OPTIONS)) == NULL) {
					prbufp->options = o_options;
				} else {
					prbufp->options = pick_opts(infile_opts,
					    o_options);
				}
			}
			break;

		case 'R':
			if (s) {
				prbufp->remote = s;
				prbufp->dial_info = 0;
				prbufp->device = 0;
			} else {
				prbufp->remote = 0;
			}
			break;

		case 's':
			if (!s) {
				/*
				 * lpadmin always defers to stty
				 */
				prbufp->speed = 0;
				prbufp->stty = stty_opt;
			}
			break;

		case 'S':
			if (!M)
				if (STREQU(*S, NAME_NONE))
					prbufp->char_sets = 0;
				else
					prbufp->char_sets = S;
			break;

		case 'T':
			prbufp->printer_types = T;
			break;

		case 'U':
			if (!s) {
				prbufp->dial_info = U;
				prbufp->device = 0;
				prbufp->remote = 0;
			}
			break;

		case 'v':
			if (!s) {
				prbufp->device = v;
				prbufp->dial_info = 0;
				prbufp->remote = 0;
			}
			break;

		case 'w':
			if (!s)
				prbufp->pwid = width_sdn;
			break;

		case 'W':
			if (!s)
				prbufp->fault_alert.W = W;
			break;

		}
	}


	BEGIN_CRITICAL
		if (putprinter(p, prbufp) == -1) {
			if (errno == EINVAL && (badprinter & BAD_INTERFACE))
				LP_ERRMSG1(ERROR, E_ADM_BADINTF,
				    prbufp->interface);
			else
				LP_ERRMSG2(ERROR, E_LP_PUTPRINTER, p, PERROR);
			done(1);
		}

		if ((getzoneid() == GLOBAL_ZONEID) && system_labeled &&
		    (prbufp->device != NULL))
			update_dev_dbs(p, prbufp->device, "ADD");

	END_CRITICAL
}

/*
 * fullpath()
 */

static char *
fullpath(char *str)
{
	char *cur_dir;
	char *path;

	while (*str && *str == ' ')
		str++;
	if (*str == '/')
		return (str);

	if (!(cur_dir = malloc(PATH_MAX + 1)))
		return (str);

	getcwd(cur_dir, PATH_MAX);
	path = makepath(cur_dir, str, (char *)0);

	/*
	 * Here we could be nice and strip out /./ and /../
	 * stuff, but it isn't necessary.
	 */

	return (path);
}

/*
 * nameit() - ADD USER NAME TO COMMAND
 */

char *
nameit(char *cmd)
{
	char *nm;
	char *copy;

	nm = getname();
	copy = malloc(strlen(cmd) + 1 + strlen(nm) + 1);

	(void) strcpy(copy, cmd);
	(void) strcat(copy, " ");
	(void) strcat(copy, nm);
	return (copy);
}

/*
 * update_dev_dbs - ADD/REMOVE ENTRIES FOR THE PRINTER IN DEVICE
 * 			ALLOCATION FILES
 *
 * We intentionally ignore errors, since we don't want the printer
 * installation to be viewed as failing just because we didn't add
 * the device_allocate entry.
 *
 *	Input:
 *		prtname - printer name
 *		devname - device associated w/ this printer
 *		func - [ADD|REMOVE] entries in /etc/security/device_allocate
 *			and /etc/security/device_maps
 *
 *	Return:
 *		Always 'quiet' return.  Failures are ignored.
 */
void
update_dev_dbs(char *prtname, char *devname, char *func)
{
	int		fd, status;
	pid_t		pid;

	pid = fork();
	switch (pid) {
	case -1:
		/* fork failed, just return quietly */
		return;
	case 0:
		/* child */
		/* redirect to /dev/null */
		(void) close(1);
		(void) close(2);
		fd = open("/dev/null", O_WRONLY);
		fd = dup(fd);

		if (strcmp(func, "ADD") == 0) {
			execl("/usr/sbin/add_allocatable", "add_allocatable",
			    "-n", prtname, "-t", "lp", "-l", devname,
			    "-o", "minlabel=admin_low:maxlabel=admin_high",
			    "-a", "*", "-c", "/bin/true", NULL);
		} else {
			if (strcmp(func, "REMOVE") == 0) {
				execl("/usr/sbin/remove_allocatable",
				    "remove_allocatable", "-n", prtname, NULL);
			}
		}
		_exit(1);
		/* NOT REACHED */
	default:
		waitpid(pid, &status, 0);
		return;
	}
}

/*
 * pack_white(ptr) trims off multiple occurances of white space from a NULL
 * terminated string pointed to by "ptr".
 */
static void
pack_white(char *ptr)
{
	char	*tptr;
	char	*mptr;
	int	cnt;

	if (ptr == NULL)
		return;
	cnt = strlen(ptr);
	if (cnt == 0)
		return;
	mptr = (char *)calloc((unsigned)cnt+1, sizeof (char));
	if (mptr == NULL)
		return;
	tptr = strtok(ptr, " \t");
	while (tptr != NULL) {
		(void) strcat(mptr, tptr);
		(void) strcat(mptr, " ");
		tptr = strtok(NULL, " \t");
	}
	cnt = strlen(mptr);
	(void) strcpy(ptr, mptr);
	free(mptr);
}
