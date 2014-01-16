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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "sys/types.h"
#include "sys/stat.h"
#include "stdio.h"
#include "string.h"
#include "errno.h"
#include "stdlib.h"

#include "lp.h"
#include "printers.h"

#include <unistd.h>
#include <sys/wait.h>

#define	SHELL "/bin/sh"
#define	PPDZIP ".gz"

extern struct {
	char			*v;
	short			len,
				okremote;
}			prtrheadings[];

#if	defined(__STDC__)

static void		print_sdn (int, char *, SCALED);
static void		print_l (int, char *, char **);
static void		print_str (int, char *, char *);

#ifdef LP_USE_PAPI_ATTR
static int addPrintersPPD(char *name, PRINTER *prbufp);
static int copyPPDFile(char *ppd, char *printersPPD);
static int unzipPPDFile(char *ppd, char *printersPPD);
#endif

#else

static void		print_sdn(),
			print_l(),
			print_str();

#ifdef LP_USE_PAPI_ATTR
static int addPrintersPPD();
static int copyPPDFile();
static int unzipPPDFile();
#endif

#endif

unsigned long		ignprinter	= 0;
int			ppdopt		= 0;

/**
 ** putprinter() - WRITE PRINTER STRUCTURE TO DISK FILES
 **/

int
putprinter(char *name, PRINTER *prbufp)
{
	register char *		path;
	register char *		stty;
	register char *		speed;

	int fdin, fdout;

	int			fld;

	char			buf[BUFSIZ];

	struct stat		statbuf1,
				statbuf2;


	badprinter = 0;

	if (!name || !*name) {
		errno = EINVAL;
		return (-1);
	}

	if (STREQU(NAME_ALL, name)) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * First go through the structure and see if we have
	 * anything strange.
	 */
	if (!okprinter(name, prbufp, 1)) {
		errno = EINVAL;
		return (-1);
	}

	if (!Lp_A_Printers || !Lp_A_Interfaces) {
		getadminpaths (LPUSER);
		if (!Lp_A_Printers || !Lp_A_Interfaces)
			return (0);
	}

	/*
	 * Create the parent directory for this printer
	 * if it doesn't yet exist.
	 */
	if (!(path = getprinterfile(name, (char *)0)))
		return (-1);
	if (Stat(path, &statbuf1) == 0) {
		if (!S_ISDIR(statbuf1.st_mode)) {
			Free (path);
			errno = ENOTDIR;
			return (-1);
		}
	} else if (errno != ENOENT || mkdir_lpdir(path, MODE_DIR) == -1) {
		Free (path);
		return (-1);
	}
	Free (path);

	/*
	 * Create the copy of the interface program, unless
	 * that would be silly or not desired.
	 * Conversely, make sure the interface program doesn't
	 * exist for a remote printer.
	 */
	if (prbufp->remote) {
		if (!(path = makepath(Lp_A_Interfaces, name, (char *)0)))
			return (-1);
		(void)rmfile (path);
		Free (path);
	}
	if (prbufp->interface && (ignprinter & BAD_INTERFACE) == 0) {
		if (Stat(prbufp->interface, &statbuf1) == -1)
			return (-1);
		if (!(path = makepath(Lp_A_Interfaces, name, (char *)0)))
			return (-1);
		if (
			Stat(path, &statbuf2) == -1
		     || statbuf1.st_dev != statbuf2.st_dev
		     || statbuf1.st_ino != statbuf2.st_ino
		) {
			register int		n;

			if ((fdin = open_locked(prbufp->interface, "r", 0)) < 0) {
				Free (path);
				return (-1);
			}
			if ((fdout = open_locked(path, "w", MODE_EXEC)) < 0) {
				Free (path);
				close(fdin);
				return (-1);
			}
			while ((n = read(fdin, buf, BUFSIZ)) > 0)
				write (fdout, buf,  n);
			close(fdout);
			close(fdin);
		}
		Free (path);
	}

#ifdef LP_USE_PAPI_ATTR
	/*
	 * Handle PPD (Postscript Printer Definition) file for printer
	 * if this printer has been configured with one
	 */
	if ((prbufp->ppd != NULL) && (ppdopt))
	{
		if (addPrintersPPD(name, prbufp) != 0)
		{
			/* failed to added the printers PPD file */
			return (-1);
		}
	}
#endif

	/*
	 * If this printer is dialed up, remove any baud rates
	 * from the stty option list and move the last one to
	 * the ".speed" member if the ".speed" member isn't already
	 * set. Conversely, if this printer is directly connected,
	 * move any value from the ".speed" member to the stty list.
	 */

	stty = (prbufp->stty? Strdup(prbufp->stty) : 0);
	if (prbufp->speed)
		speed = Strdup(prbufp->speed);
	else
		speed = 0;

	if (prbufp->dial_info && stty) {
		register char		*newstty,
					*p,
					*q;

		register int		len;

		if (!(q = newstty = Malloc(strlen(stty) + 1))) {
			Free (stty);
			errno = ENOMEM;
			return (-1);
		}
		newstty[0] = 0;	/* start with empty copy */

		for (
			p = strtok(stty, " ");
			p;
			p = strtok((char *)0, " ")
		) {
			len = strlen(p);
			if (strspn(p, "0123456789") == len) {
				/*
				 * If "prbufp->speed" isn't set, then
				 * use the speed we just found. Don't
				 * check "speed", because if more than
				 * one speed was given in the list, we
				 * want the last one.
				 */
				if (!prbufp->speed) {
					if (speed)
						Free (speed);
					speed = Strdup(p);
				}

			} else {
				/*
				 * Not a speed, so copy it to the
				 * new stty string.
				 */
				if (q != newstty)
					*q++ = ' ';
				strcpy (q, p);
				q += len;
			}
		}

		Free (stty);
		stty = newstty;

	} else if (!prbufp->dial_info && speed) {
		register char		*newstty;

		newstty = Malloc(strlen(stty) + 1 + strlen(speed) + 1);
		if (!newstty) {
			if (stty)
				Free (stty);
			errno = ENOMEM;
			return (-1);
		}

		if (stty) {
			strcpy (newstty, stty);
			strcat (newstty, " ");
			strcat (newstty, speed);
			Free (stty);
		} else
			strcpy (newstty, speed);
		Free (speed);
		speed = 0;

		stty = newstty;

	}

	/*
	 * Open the configuration file and write out the printer
	 * configuration.
	 */

	if (!(path = getprinterfile(name, CONFIGFILE))) {
		if (stty)
			Free (stty);
		if (speed)
			Free (speed);
		return (-1);
	}
	if ((fdout = open_locked(path, "w", MODE_READ)) < 0) {
		Free (path);
		if (stty)
			Free (stty);
		if (speed)
			Free (speed);
		return (-1);
	}
	Free (path);

	errno = 0;
	for (fld = 0; fld < PR_MAX; fld++) {
		if (prbufp->remote && !prtrheadings[fld].okremote)
			continue;

		switch (fld) {

#define HEAD	prtrheadings[fld].v

		case PR_BAN:
			{
				char *ptr = NAME_ON;

				switch (prbufp->banner) {
				case BAN_ALWAYS:
					ptr = NAME_ON;
					break;
				case BAN_NEVER:
					ptr = NAME_OFF;
					break;
				case BAN_OPTIONAL:
					ptr = NAME_OPTIONAL;
					break;
				}
				(void)fdprintf(fdout, "%s %s\n", HEAD, ptr);
			}
			break;

		case PR_CPI:
			print_sdn(fdout, HEAD, prbufp->cpi);
			break;

		case PR_CS:
			if (!emptylist(prbufp->char_sets))
				print_l(fdout, HEAD, prbufp->char_sets);
			break;

		case PR_ITYPES:
			/*
			 * Put out the header even if the list is empty,
			 * to distinguish no input types from the default.
			 */
			print_l(fdout, HEAD, prbufp->input_types);
			break;

		case PR_DEV:
			print_str(fdout, HEAD, prbufp->device);
			break;

		case PR_DIAL:
			print_str(fdout, HEAD, prbufp->dial_info);
			break;

		case PR_RECOV:
			print_str(fdout, HEAD, prbufp->fault_rec);
			break;

		case PR_INTFC:
			print_str(fdout, HEAD, prbufp->interface);
			break;

		case PR_LPI:
			print_sdn(fdout, HEAD, prbufp->lpi);
			break;

		case PR_LEN:
			print_sdn(fdout, HEAD, prbufp->plen);
			break;

		case PR_LOGIN:
			if (prbufp->login & LOG_IN)
				(void)fdprintf(fdout, "%s\n", HEAD);
			break;

		case PR_PTYPE:
		{
			char			**printer_types;

			/*
			 * For backward compatibility for those who
			 * use only "->printer_type", we have to play
			 * some games here.
			 */
			if (prbufp->printer_type && !prbufp->printer_types)
				printer_types = getlist(
					prbufp->printer_type,
					LP_WS,
					LP_SEP
				);
			else
				printer_types = prbufp->printer_types;

			if (!printer_types || !*printer_types)
				print_str(fdout, HEAD, NAME_UNKNOWN);
			else
				print_l(fdout, HEAD, printer_types);

			if (printer_types != prbufp->printer_types)
				freelist (printer_types);
			break;
		}

		case PR_REMOTE:
			print_str(fdout, HEAD, prbufp->remote);
			break;

		case PR_SPEED:
			print_str(fdout, HEAD, speed);
			break;

		case PR_STTY:
			print_str(fdout, HEAD, stty);
			break;

		case PR_WIDTH:
			print_sdn(fdout, HEAD, prbufp->pwid);
			break;

#if	defined(CAN_DO_MODULES)
		case PR_MODULES:
			/*
			 * Put out the header even if the list is empty,
			 * to distinguish no modules from the default.
			 */
			print_l(fdout, HEAD, prbufp->modules);
			break;
#endif

		case PR_OPTIONS:
			print_l(fdout, HEAD, prbufp->options);
			break;

		case PR_PPD:
		{
			print_str(fdout, HEAD, prbufp->ppd);
			break;
		}
		}

	}
	if (stty)
		Free (stty);
	if (speed)
		Free (speed);
	if (errno != 0) {
		close(fdout);
		return (-1);
	}
	close(fdout);

	/*
	 * If we have a description of the printer,
	 * write it out to a separate file.
	 */
	if (prbufp->description) {

		if (!(path = getprinterfile(name, COMMENTFILE)))
			return (-1);

		if (dumpstring(path, prbufp->description) == -1) {
			Free (path);
			return (-1);
		}
		Free (path);
	
	}

	/*
	 * Now write out the alert condition.
	 */
	if (
		prbufp->fault_alert.shcmd
	     && putalert(Lp_A_Printers, name, &(prbufp->fault_alert)) == -1
	)
		return (-1);

	return (0);
}

/**
 ** print_sdn() - PRINT SCALED DECIMAL NUMBER WITH HEADER
 ** print_l() - PRINT (char **) LIST WITH HEADER
 ** print_str() - PRINT STRING WITH HEADER
 **/

static void
print_sdn(int fd, char *head, SCALED sdn)
{
	if (sdn.val <= 0)
		return;

	(void)fdprintf (fd, "%s ", head);
	fdprintsdn (fd, sdn);

	return;
}

static void
print_l(int fd, char *head, char **list)
{
	(void)fdprintf (fd, "%s ", head);
	printlist_setup (0, 0, LP_SEP, 0);
	fdprintlist (fd, list);
	printlist_unsetup ();

	return;
}

static void
print_str(int fd, char *head, char *str)
{
	if (!str || !*str)
		return;

	(void)fdprintf (fd, "%s %s\n", head, str);

	return;
}


#ifdef LP_USE_PAPI_ATTR
/*
 * Function:     addPrintersPPD()
 *
 * Description:  Handle PPD (Postscript Printer Definition) file for this
 *               printer if it has been configured with one
 *
 */

static int
addPrintersPPD(char *name, PRINTER *prbufp)

{
	int result = 0;
	char *path = NULL;
	char *ppd = NULL;
	char  buf[BUFSIZ];
	struct stat statbuf;

	(void) snprintf(buf, sizeof (buf), "%s.ppd", name);
	if (prbufp->remote)
	{
		/* make sure the PPD file doesn't exist for a remote printer */
		if (!(path = makepath(ETCDIR, "ppd", buf, (char *)0)))
		{
			result = -1;
		}
		else
		{
			(void) rmfile(path);
		}
	}

	if ((result == 0) && (prbufp->ppd != NULL))
	{
		ppd = strdup(prbufp->ppd);

		if (ppd == NULL)
		{
			result = -1;
		}
		else
		{
			/* Check the PPD file given exists */

			if (Stat(ppd, &statbuf) == -1)
			{
				/*
				 * The given ppd files does not exist, but
				 * check if there is a zipped version of the
				 * file that we can use instead
				 */
				if (strstr(ppd, PPDZIP) != NULL)
				{
					/* this is a zipped file so exit */
					result = -1;
				}
				else
				{
					ppd = Realloc(ppd,
						strlen(ppd)+strlen(PPDZIP)+2);
					if (ppd != NULL)
					{
						ppd = strcat(ppd, PPDZIP);
						if (Stat(ppd, &statbuf) == -1)
						{
							/*
							 * this zipped version
							 * of the file does not
							 * exist either
							 */
							result = -1;
						}
					}
					else
					{
						result = -1;
					}
				}
			}
		}

		/*
		 * Create the copy of the PPD file for this printer
		 * unless that would be silly or not desired
		 */

		if (result == 0)
		{
			if (!(path = makepath(ETCDIR, "ppd", buf, (char *)0)))
			{
				result = -1;
			}
		}

		/*
		 * At this point we may have a zipped or unzipped ppd file, if
		 * it's unzipped just copy it otherwise unzip it to the
		 * printer's ppd file (/etc/lp/ppd/<printer>.ppd)
		 */

		if (result == 0)
		{
			if (strstr(ppd, PPDZIP) == NULL)
			{
				result = copyPPDFile(ppd, path);
			}
			else
			{
				result = unzipPPDFile(ppd, path);
			}

			(void) chown_lppath(path);
			(void) chmod(path, 0644);
		}

		if (ppd != NULL)
		{
			Free(ppd);
		}
		if (path != NULL)
		{
			Free(path);
		}
	}

	return (result);
} /* addPrintersPPD() */


/*
 * Function:     copyPPDFile()
 *
 * Description:  Copy the given ppd file to the printer's file in /etc/lp/ppd
 *
 */

static int
copyPPDFile(char *ppd, char *printersPPD)

{
	int  result = 0;
	register int n = 0;
	int  fdin  = 0;
	int  fdout = 0;
	char buf[BUFSIZ];

	if ((ppd != NULL) && (printersPPD != NULL))
	{
		if ((fdin = open_locked(ppd, "r", 0)) < 0)
		{
			result = -1;
		}
		else
		{
			fdout = open_locked(printersPPD, "w", MODE_EXEC);
			if (fdout < 0)
			{
				close(fdin);
				result = -1;
			}
		}

		if (result == 0)
		{
			while ((n = read(fdin, buf, BUFSIZ)) > 0)
			{
				write(fdout, buf,  n);
			}
			close(fdout);
			close(fdin);
		}
	}
	else
	{
		result = -1;
	}

	return (result);
} /* copyPPDFile() */



/*
 * Function:     unzipPPDFile()
 *
 * Description:  Unzip the given ppd file to the printer's file in /etc/lp/ppd.
 *               This is done by forking and running the unzip utility on the
 *               zipped ppd file.
 *
 */

static int
unzipPPDFile(char *ppd, char *printersPPD)

{
	int  result = -1;
	char *cmdLine = NULL;
	pid_t childPID = 0;
	int   stat = 0;
	int   clSize = 0;


	if ((ppd != NULL) && (printersPPD != NULL))
	{
		childPID = fork();

		switch (childPID)
		{
			case -1:
			{
				/* return error */
				break;
			}

			case 0:
			{
				/* child process  - so execute something */

				clSize = strlen("/usr/bin/rm -f ") +
						strlen(printersPPD) +
						strlen("/usr/bin/gzip -dc ") +
						strlen(ppd) +
						strlen(printersPPD) + 20;
				cmdLine = malloc(clSize);
				if (cmdLine != NULL)
				{

					(void) snprintf(cmdLine, clSize,
				"/usr/bin/rm -f %s; /usr/bin/gzip -dc %s > %s",
							printersPPD, ppd,
							printersPPD);
					result = execl(SHELL, SHELL, "-c",
							cmdLine, NULL);
					exit(result);
				}
				break;
			}

			default:
			{
				/* parent process, child pid is in childPID */

				while (wait(&stat) != childPID);

				if ((stat & 0xff00) == 0)
				{
					result = 0;
				}
				break;
			}
		}
	}

	return (result);
} /* unzipPPDFile() */
#endif
