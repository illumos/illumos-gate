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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#include "stdlib.h"
#include "string.h"
#include "unistd.h"
#include <syslog.h>

#include "lpsched.h"

#define NCMP(X,Y)	(STRNEQU((X), (Y), sizeof(Y)-1))

static void		load_pstatus ( void );
static void		load_fault_status ( void );
static void		load_cstatus ( void );
static void		put_multi_line ( int , char * );
static PFSTATUS * parseFormList ( char *,short *);
static void markFormsMounted( PSTATUS *);


#define FAULT_MESSAGE_FILE "faultMessage"
static char		*pstatus	= 0,
			*cstatus	= 0;

/**
 ** load_status() - LOAD PRINTER/CLASS STATUS FILES
 **/

void
load_status(void)
{
	load_pstatus ();

	load_cstatus ();
	load_fault_status ();
	return;
}

/**
 ** load_pstatus() - LOAD PRITNER STATUS FILE
 **/

static void
load_pstatus(void)
{
	PSTATUS			*pps;

	char			*rej_reason,
				*dis_reason,
				*pwheel_name,
				buf[BUFSIZ],
				*name,
				*p;

	time_t			rej_date,
				dis_date;

	short			status;

	PFSTATUS		*ppfs;

	PWSTATUS		*ppws;

	int			i,
				len,
				total;

	time_t			now;

	int fd;

	register int		f;
	short			numForms;


	(void) time(&now);

	if (!pstatus)
		pstatus = makepath(Lp_System, PSTATUSFILE, (char *)0);
	if ((fd = open_locked(pstatus, "r", 0)) >= 0) {
		char *tmp = pstatus; /* not NULL */

		while (tmp != NULL) {
			status = 0;
			total = 0;
			name = 0;
			rej_reason = 0;
			dis_reason = 0;
			ppfs = 0;

			errno = 0;
			for (f = 0;
			    (f < PST_MAX) && (tmp = fdgets(buf, BUFSIZ, fd));
			    f++) {
				if (p = strrchr(buf, '\n'))
					*p = '\0';

				switch (f) {
				case PST_BRK:
					break;

				case PST_NAME:
					name = Strdup(buf);
					break;

				case PST_STATUS:
					if (NCMP(buf, NAME_DISABLED))
						status |= PS_DISABLED;
					p = strchr(buf, ' ');
					if (!p || !*(++p))
						break;
					if (NCMP(p, NAME_REJECTING))
						status |= PS_REJECTED;
					break;

				case PST_DATE:
					dis_date = (time_t)atol(buf);
					p = strchr(buf, ' ');
					if (!p || !*(++p))
						break;
					rej_date = (time_t)atol(p);
					break;

				case PST_DISREAS:
					len = strlen(buf);
					if (buf[len - 1] == '\\') {
						buf[len - 1] = '\n';
						f--;
					}
					if (dis_reason) {
						total += len;
						dis_reason = Realloc(
							dis_reason,
							total+1
						);
						strcat (dis_reason, buf);
					} else {
						dis_reason = Strdup(buf);
						total = len;
					}
					break;

				case PST_REJREAS:
					len = strlen(buf);
					if (buf[len - 1] == '\\') {
						buf[len - 1] = '\n';
						f--;
					}
					if (rej_reason) {
						total += len;
						rej_reason = Realloc(
							rej_reason,
							total+1
						);
						strcat (rej_reason, buf);
					} else {
						rej_reason = Strdup(buf);
						total = len;
					}
					break;

				case PST_PWHEEL:
					if (*buf) {
						ppws = search_pwstatus(buf);
						pwheel_name = Strdup(buf);
					} else {
						ppws = 0;
						pwheel_name = 0;
					}
					break;

				case PST_FORM:
					ppfs = parseFormList (buf,&numForms);
					break;
				}
			}

			if ((errno != 0) || f && f != PST_MAX) {
				close(fd);
				note("Had trouble reading file %s", pstatus);
				return;
			}

			if ((tmp != NULL) && name &&
			    (pps = search_pstatus(name))) {
				pps->rej_date = rej_date;
				pps->status |= status;
				pps->forms = ppfs;
				if (ppfs) markFormsMounted(pps);
				pps->numForms = numForms;
				pps->pwheel_name = pwheel_name;
				if ((pps->pwheel = ppws) != NULL)
					ppws->mounted++;
				pps->rej_reason = rej_reason;
				load_str(&pps->fault_reason, CUZ_PRINTING_OK);
				if (pps->printer->login) {
					pps->dis_date = now;
					pps->dis_reason =
						Strdup(CUZ_LOGIN_PRINTER);
				} else {
					pps->dis_date = dis_date;
					pps->dis_reason = dis_reason;
				}

			} else {
				if (ppfs)
					Free(ppfs);
				if (dis_reason)
					Free (dis_reason);
				if (rej_reason)
					Free (rej_reason);
			}
			if (name)
				Free (name);
		}
	}

	if (fd >= 0) {
		if (errno != 0) {
			close(fd);
			note("Had trouble reading file %s", pstatus);
			return;
		}
		close(fd);
	}

	for (i = 0; PStatus != NULL && PStatus[i] != NULL; i++)
		if (PStatus[i]->printer->name && !PStatus[i]->rej_reason) {
			PStatus[i]->dis_reason = Strdup(CUZ_NEW_PRINTER);
			PStatus[i]->rej_reason = Strdup(CUZ_NEW_DEST);
			PStatus[i]->fault_reason = Strdup(CUZ_PRINTING_OK);
			PStatus[i]->dis_date = now;
			PStatus[i]->rej_date = now;
			PStatus[i]->status |= PS_DISABLED | PS_REJECTED;
		}

	return;
}

/**
 ** load_fault_status() - LOAD PRITNER Fault STATUS FILE
 **/

static void 
load_fault_status(void)
{
	char			*fault_reason = NULL,
				buf[BUFSIZ],
				*fault_status,
				*printerName,
				*p;

	int			i,
				len,
				total;


	int fd;

	for (i = 0; PStatus != NULL && PStatus[i] != NULL; i++) {
		PSTATUS *pps = PStatus[i];

		printerName = pps->printer->name;
		if (printerName) {
			fault_status = makepath(Lp_A_Printers, printerName,
				FAULT_MESSAGE_FILE , (char *) 0);
			fault_reason = NULL;
			total = 0;

			if ((fd = open_locked(fault_status, "r", 0)) >= 0) {
				while (fdgets(buf, BUFSIZ, fd)) {
					len = strlen(buf);
					if (fault_reason) {
						total += len;
						fault_reason =
							Realloc(fault_reason,
								total+1);
						strcat (fault_reason, buf);
					} else {
						fault_reason = Strdup(buf);
						total = len;
					}
				}

				if (fault_reason &&
				    (pps = search_pstatus(printerName))) {
					p = fault_reason + strlen(fault_reason)
						- 1;
					if (*p == '\n')
						*p = 0;
					load_str(&pps->fault_reason,
						fault_reason);
				}
				if (fault_reason)
					Free(fault_reason);

				close(fd);
			}
			Free(fault_status);
		}
	}
}


/**
 ** load_cstatus() - LOAD CLASS STATUS FILE
 **/

static void
load_cstatus(void)
{
	CLSTATUS			*pcs;
	char			*rej_reason,
				buf[BUFSIZ],
				*name,
				*p;
	time_t			rej_date;
	short			status;
	int			i,
				len,
				total;
	time_t			now;
	int fd;
	register int		f;


	(void) time(&now);

	if (!cstatus) 
		cstatus = makepath(Lp_System, CSTATUSFILE, (char *)0);

	if ((fd = open_locked(cstatus, "r", 0)) >= 0) {
		char *tmp = cstatus; /* not NULL */

		errno = 0;
		while (tmp != NULL) {
			status = 0;

			total = 0;
			name = 0;

			rej_reason = 0;
			for (f = 0;
			    (f < CST_MAX) && (tmp = fdgets(buf, BUFSIZ, fd));
			    f++) {
				if (p = strrchr(buf, '\n'))
					*p = '\0';
				switch (f) {
				case CST_BRK:
					break;

				case CST_NAME:
					name = Strdup(buf);
					break;

				case CST_STATUS:
					if (NCMP(buf, NAME_REJECTING))
						status |= PS_REJECTED;
					break;

				case CST_DATE:
					rej_date = (time_t)atol(buf);
					break;

				case CST_REJREAS:
					len = strlen(buf);
					if (buf[len - 1] == '\\') {
						buf[len - 1] = '\n';
						f--;
					}
					if (rej_reason) {
						total += len;
						rej_reason = Realloc(
							rej_reason,
							total+1
						);
						strcat (rej_reason, buf);
					} else {
						rej_reason = Strdup(buf);
						total = len;
					}
					break;
				}
			}

			if ((errno != 0) || f && f != CST_MAX) {
				close(fd);
				note("Had trouble reading file %s", cstatus);
				return;
			}

			if ((tmp != NULL) && name &&
			    (pcs = search_cstatus(name))) {
				pcs->rej_reason = rej_reason;
				pcs->rej_date = rej_date;
				pcs->status |= status;

			} else
				if (rej_reason)
					Free (rej_reason);

			if (name)
				Free (name);
		}
	}

	if (fd >= 0) {
		if (errno != 0) {
			close(fd);
			note("Had trouble reading file %s", cstatus);
			return;
		}
		close(fd);
	}

	for (i = 0; CStatus != NULL && CStatus[i] != NULL; i++)
		if (CStatus[i]->class->name && !CStatus[i]->rej_reason) {
			CStatus[i]->status |= CS_REJECTED;
			CStatus[i]->rej_reason = Strdup(CUZ_NEW_DEST);
			CStatus[i]->rej_date = now;
		}

	return;
}

/**
 ** showForms()
 **/
char *
showForms(PSTATUS  *pps)
{
	int i;
	char			*formList = NULL;
	char buf[100];
	FSTATUS *pfs;
	PFSTATUS  *ppfs;
	short numForms;

	numForms = pps->numForms;
	ppfs = pps->forms;
	if (ppfs) {
		for (i = 0; i < numForms; i++) {
			pfs = ppfs[i].form;
			snprintf(buf, sizeof (buf), "%s%c",
				(pfs ? pfs->form->name : ""),
				((i + 1 < numForms) ? *LP_SEP : '\0'));

			if (addstring(&formList,buf)) { /* allocation failed */
				if (formList) {  
					Free(formList);
					formList = NULL;
				}
				return(NULL);
			}
		}
	}
	return(formList);
}

/**
 ** markFormsMounted()
 **/

void
markFormsMounted(PSTATUS *pps)
{
	int i;
	int numTrays;
	PFSTATUS *ppfs;
	FSTATUS *pfs;


	ppfs = pps->forms;
	if (ppfs) {
		numTrays = pps->numForms;
		for (i = 0; i < numTrays; i++) {
			pfs = ppfs[i].form;
			if (pfs)
				pfs->mounted++;
		}
	}
}

/**
 ** parseFormList()
 **/

static PFSTATUS *
parseFormList(char *formList, short *num)
{
	int i;
	FSTATUS *pfs;
	PFSTATUS  *ppfs;
	short numForms=0;
	char *endPtr,*ptr;


	ptr = strchr(formList,*LP_SEP);
	while (ptr)  {
		numForms++;
		ptr = strchr(ptr+1,*LP_SEP);
	}
	if ((numForms == 0) && (*formList))
		numForms = 1;

	if (numForms &&
	    (ppfs = (PFSTATUS *) Calloc(numForms, sizeof(PFSTATUS)))) {
		endPtr = strchr(formList,*LP_SEP);
		if (!endPtr)
			endPtr = formList + strlen(formList);

		ptr = formList;
		for (i = 0; endPtr && (i < numForms); i++) {
			*endPtr = 0;
			ppfs[i].form = pfs = search_fstatus(ptr);
			ppfs[i].isAvailable = (pfs ? 1 : 0);
			ptr = endPtr+1;
			endPtr = strchr(ptr,*LP_SEP);
		}
		*num = numForms;
	} else {
		ppfs = NULL;
		*num = 0;
	}
	return(ppfs);
}

/**
 ** dump_pstatus() - DUMP PRINTER STATUS FILE
 **/

void
dump_pstatus(void)
{
	PSTATUS			*ppsend;
	int fd;
	register PSTATUS	*pps;
	register int		f;
	int i;

	if (!pstatus)
		pstatus = makepath(Lp_System, PSTATUSFILE, (char *)0);
	if ((fd = open_locked(pstatus, "w", MODE_READ)) < 0) {
		note ("Can't open file \"%s\" (%s).\n", pstatus, PERROR);
		return;
	}

	for (i = 0; PStatus != NULL && PStatus[i] != NULL; i++) {
		PSTATUS	*pps = PStatus[i];

		if (pps->printer->name)
			for (f = 0; f < PST_MAX; f++) switch (f) {
			case PST_BRK:
				(void)fdprintf(fd, "+%s\n", STATUS_BREAK);
				break;
			case PST_NAME:
				(void)fdprintf(fd, "%s\n",
					NB(pps->printer->name));
				break;
			case PST_STATUS:
				(void)fdprintf(fd, "%s %s\n",
					(pps->status & PS_DISABLED ?
					    NAME_DISABLED : NAME_ENABLED),
					(pps->status & PS_REJECTED ?
					    NAME_REJECTING : NAME_ACCEPTING));
				break;
			case PST_DATE:
				(void)fdprintf(fd, "%ld %ld\n", pps->dis_date,
					pps->rej_date);
				break;
			case PST_DISREAS:
				put_multi_line(fd, pps->dis_reason);
				break;
			case PST_REJREAS:
				put_multi_line(fd, pps->rej_reason);
				break;
			case PST_PWHEEL:
				(void)fdprintf(fd, "%s\n",
					NB(pps->pwheel_name));
				break;
			case PST_FORM: {
				char *list;
				list = showForms(pps);
				(void)fdprintf(fd, "%s\n", (list ? list : ""));
				if (list)
					Free(list);
				break;
				}
			}
	}
	close(fd);

	return;
}

/**
 ** dump_fault_status() - DUMP PRINTER FAULT STATUS FILE
 **/

void
dump_fault_status(PSTATUS *pps)
{
	int fd;
	char		*fault_status, *printerName;

	printerName = pps->printer->name;
	fault_status = makepath(Lp_A_Printers, printerName, FAULT_MESSAGE_FILE,
			(char *) 0);
	if ((fd = open_locked(fault_status, "w", MODE_READ)) < 0) {
		syslog(LOG_DEBUG, "Can't open file %s (%m)", fault_status);
	} else {
		fdprintf(fd, "%s\n", pps->fault_reason);
		close(fd);
	}

	Free(fault_status);
	return;
}


/**
 ** dump_cstatus() - DUMP CLASS STATUS FILE
 **/

void
dump_cstatus(void)
{
	int fd;
	register int		f;
	int i;


	if (!cstatus)
		cstatus = makepath(Lp_System, CSTATUSFILE, (char *)0);
	if ((fd = open_locked(cstatus, "w", MODE_READ)) < 0) {
		syslog(LOG_DEBUG, "Can't open file %s (%m)", cstatus);
		return;
	}

	for (i = 0; CStatus != NULL && CStatus[i] != NULL; i++) {
		CLSTATUS	*pcs = CStatus[i];

		if (pcs->class->name)
			for (f = 0; f < CST_MAX; f++) switch (f) {
			case CST_BRK:
				(void)fdprintf(fd, "%s\n", STATUS_BREAK);
				break;
			case CST_NAME:
				(void)fdprintf(fd, "%s\n",
					NB(pcs->class->name));
				break;
			case CST_STATUS:
				(void)fdprintf(fd, "%s\n",
					(pcs->status & CS_REJECTED ?
					    NAME_REJECTING : NAME_ACCEPTING)
				);
				break;
			case CST_DATE:
				(void)fdprintf(fd, "%ld\n", pcs->rej_date);
				break;
			case CST_REJREAS:
				put_multi_line(fd, pcs->rej_reason);
				break;
			}
	}
	close(fd);

	return;
}

/**
 ** put_multi_line() - PRINT OUT MULTI-LINE TEXT
 **/

static void
put_multi_line(int fd, char *buf)
{
	register char		*cp,
				*p;

	if (!buf) {
		(void)fdprintf(fd, "\n");
		return;
	}

	for (p = buf; (cp = strchr(p, '\n')); ) {
		*cp++ = 0;
		(void)fdprintf(fd, "%s\\\n", p);
		p = cp;
	}
	(void)fdprintf(fd, "%s\n", p);
	return;
}
