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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#include	<unistd.h>
#include	<stdlib.h>
#include	<sys/types.h>
#include	<ctype.h>
#include	<string.h>
#include	<pwd.h>
#include	<grp.h>
#include	<signal.h>
#include	"ttymon.h"
#include	"tmstruct.h"
#include	"tmextern.h"

static	int	get_flags(char *, long *);
static	int	get_ttyflags(char *, long *);
static	int	same_entry(struct pmtab *, struct pmtab *);
static	int	check_pmtab(struct pmtab *);
static	void	insert_pmtab(struct pmtab *);
static	void	free_pmtab(struct pmtab *);
static	char	*expand(char *, char *);

int	check_identity(struct pmtab *);

/*
 * read_pmtab()
 *	- read and parse pmtab
 *	- store table in linked list pointed by global variable "PMtab"
 *	- exit if file does not exist or error detected.
 */
void
read_pmtab(void)
{
	struct pmtab *gptr;
	char *ptr, *wptr;
	FILE	 *fp;
	int	 input, state, size, rawc, field, linenum;
	char	 oldc;
	char	 line[BUFSIZ];
	char	 wbuf[BUFSIZ];
	static	 char *states[] = {
	    "", "tag", "flags", "identity", "reserved1", "reserved2",
	    "reserved3", "device", "ttyflags", "count", "service", "timeout",
	    "ttylabel", "modules", "prompt", "disable msg", "terminal type",
	    "soft-carrier"
	};

#ifdef DEBUG
	debug("in read_pmtab");
#endif

	if ((fp = fopen(PMTABFILE, "r")) == NULL) {
		fatal("open pmtab (%s) failed", PMTABFILE);
	}

	Nentries = 0;
	if (check_version(PMTAB_VERS, PMTABFILE) != 0)
		fatal("check pmtab version failed");

	for (gptr = PMtab; gptr; gptr = gptr->p_next) {
		if ((gptr->p_status == SESSION) ||
		    (gptr->p_status == LOCKED) ||
		    (gptr->p_status == UNACCESS)) {
			if (gptr->p_fd > 0) {
				(void) close(gptr->p_fd);
				gptr->p_fd = 0;
			}
			gptr->p_inservice = gptr->p_status;
		}
		gptr->p_status = NOTVALID;
	}

	wptr = wbuf;
	input = ACTIVE;
	linenum = 0;
	field = FAILURE;
	do {
		linenum++;
		line[0] = '\0';
		for (ptr = line, oldc = '\0'; ptr < &line[sizeof (line) - 1] &&
		    (rawc = getc(fp)) != '\n' && rawc != EOF;
		    ptr++, oldc = (char)rawc) {
			if ((rawc == '#') && (oldc != '\\'))
				break;
			*ptr = (char)rawc;
		}
		*ptr = '\0';

		/* skip rest of the line */
		if (rawc != EOF && rawc != '\n') {
			if (rawc != '#')
				log("Entry too long.\n");
			while ((rawc = getc(fp)) != EOF && rawc != '\n')
				;
		}

		if (rawc == EOF) {
			if (ptr == line)
				break;
			else
				input = FINISHED;
		}

		/* if empty line, skip */
		for (ptr = line; *ptr != '\0' && isspace(*ptr); ptr++)
			;
		if (*ptr == '\0')
			continue;

#ifdef DEBUG
		debug("**** Next Entry ****\n%s", line);
#endif
		log("Processing pmtab line #%d", linenum);

		/* Now we have the complete line */

		if ((gptr = ALLOC_PMTAB) == NULL)
			fatal("memory allocation failed");

		/* set hangup flag, this is the default */
		gptr->p_ttyflags |= H_FLAG;

		/*
		 * For compatibility reasons, we cannot rely on these
		 * having values assigned from pmtab.
		 */
		gptr->p_termtype = "";
		gptr->p_softcar = "";

		for (state = P_TAG, ptr = line; state != FAILURE &&
		    state != SUCCESS;) {
			switch (state) {
			case P_TAG:
				gptr->p_tag = strsave(getword(ptr, &size, 0));
				break;
			case P_FLAGS:
				(void) strcpy(wptr, getword(ptr, &size, 0));
				if ((get_flags(wptr, &gptr->p_flags)) != 0) {
					field = state;
					state = FAILURE;
				}
				break;
			case P_IDENTITY:
				gptr->p_identity = strsave(
				    getword(ptr, &size, 0));
				break;
			case P_RES1:
				gptr->p_res1 = strsave(getword(ptr, &size, 0));
				break;
			case P_RES2:
				gptr->p_res2 = strsave(getword(ptr, &size, 0));
				break;
			case P_RES3:
				gptr->p_res3 = strsave(getword(ptr, &size, 0));
				break;
			case P_DEVICE:
				gptr->p_device = strsave(
				    getword(ptr, &size, 0));
				break;
			case P_TTYFLAGS:
				(void) strcpy(wptr, getword(ptr, &size, 0));
				if (get_ttyflags(wptr,
				    &gptr->p_ttyflags) != 0) {
					field = state;
					state = FAILURE;
				}
				break;
			case P_COUNT:
				(void) strcpy(wptr, getword(ptr, &size, 0));
				if (strcheck(wptr, NUM) != 0) {
					log("wait_read count must be a "
					    "positive number");
					field = state;
					state = FAILURE;
				} else {
					gptr->p_count = atoi(wptr);
				}
				break;
			case P_SERVER:
				gptr->p_server =
				    strsave(expand(getword(ptr, &size, 1),
				    gptr->p_device));
				break;
			case P_TIMEOUT:
				(void) strcpy(wptr, getword(ptr, &size, 0));
				if (strcheck(wptr, NUM) != 0) {
					log("timeout value must be a positive "
					    "number");
					field = state;
					state = FAILURE;
				} else {
					gptr->p_timeout = atoi(wptr);
				}
				break;
			case P_TTYLABEL:
				gptr->p_ttylabel = strsave(getword(ptr,
				    &size, 0));
				break;
			case P_MODULES:
				gptr->p_modules = strsave(getword(ptr,
				    &size, 0));
				if (vml(gptr->p_modules) != 0) {
					field = state;
					state = FAILURE;
				}
				break;
			case P_PROMPT:
				gptr->p_prompt = strsave(getword(ptr, &size,
				    TRUE));
				break;
			case P_DMSG:
				gptr->p_dmsg = strsave(getword(ptr, &size,
				    TRUE));
				break;

			case P_TERMTYPE:
				gptr->p_termtype = strsave(getword(ptr,
				    &size, TRUE));
				break;

			case P_SOFTCAR:
				gptr->p_softcar = strsave(getword(ptr,
				    &size, TRUE));
				break;

			} /* end switch */
			ptr += size;
			if (state == FAILURE)
				break;
			if (*ptr == ':') {
				ptr++;	/* Skip the ':' */
				state++;
			} else if (*ptr != '\0') {
				field = state;
				state = FAILURE;
			}
			if (*ptr == '\0') {
				/*
				 * Maintain compatibility with older ttymon
				 * pmtab files.  If Sun-added fields are
				 * missing, this should not be an error.
				 */
				if (state > P_DMSG) {
					state = SUCCESS;
				} else {
					field = state;
					state = FAILURE;
				}
			}
		} /* end for loop */

		if (state == SUCCESS) {
			if (check_pmtab(gptr) == 0) {
				if (Nentries < Maxfds) {
					insert_pmtab(gptr);
				} else {
					log("can't add more entries to "
					    "pmtab, Maxfds = %d", Maxfds);
					free_pmtab(gptr);
					(void) fclose(fp);
					return;
				}
			} else {
				log("Parsing failure for entry: \n%s", line);
				log("----------------------------------------"
				    "---");
				free_pmtab(gptr);
			}
		} else {
			*++ptr = '\0';
			log("Parsing failure in the \"%s\" field,\n%s"
			    "<--error detected here", states[field], line);
			log("-------------------------------------------");
			free_pmtab(gptr);
		}
	} while (input == ACTIVE);

	(void) fclose(fp);
}

/*
 * get_flags	- scan flags field to set U_FLAG and X_FLAG
 */
static	int
get_flags(char *wptr, long *flags)
{
	char	*p;
	for (p = wptr; *p; p++) {
		switch (*p) {
		case 'x':
			*flags |= X_FLAG;
			break;
		case 'u':
			*flags |= U_FLAG;
			break;
		default:
			log("Invalid flag -- %c", *p);
			return (-1);
		}
	}
	return (0);
}

/*
 * get_ttyflags	- scan ttyflags field to set corresponding flags
 * char	*wptr		pointer to the input string
 * long	*ttyflags	pointer to the flag to be set
 */
static	int
get_ttyflags(char *wptr, long *ttyflags)
{
	char	*p;
	for (p = wptr; *p; p++) {
		switch (*p) {
		case 'c':
			*ttyflags |= C_FLAG;
			break;
		case 'h': /* h means don't hangup */
			*ttyflags &= ~H_FLAG;
			break;
		case 'b':
			*ttyflags |= B_FLAG;
			break;
		case 'r':
			*ttyflags |= R_FLAG;
			break;
		case 'I':
			*ttyflags |= I_FLAG;
			break;
		default:
			log("Invalid ttyflag -- %c", *p);
			return (-1);
		}
	}
	return (0);
}

#ifdef DEBUG
/*
 * pflags - put service flags into intelligible form for output
 * long flags - binary representation of the flags
 */

char *
pflags(long flags)
{
	int i;			/* scratch counter */
	static char buf[BUFSIZ];	/* formatted flags */

	if (flags == 0)
		return ("-");
	i = 0;
	if (flags & U_FLAG) {
		buf[i++] = 'u';
		flags &= ~U_FLAG;
	}
	if (flags & X_FLAG) {
		buf[i++] = 'x';
		flags &= ~X_FLAG;
	}
	if (flags)
		log("Internal error in pflags");
	buf[i] = '\0';
	return (buf);
}

/*
 * pttyflags - put ttyflags into intelligible form for output
 * long flags - binary representation of ttyflags
 */

char *
pttyflags(long flags)
{
	int i;			/* scratch counter */
	static char buf[BUFSIZ];	/* formatted flags */

	if (flags == 0)
		return ("h");
	i = 0;
	if (flags & C_FLAG) {
		buf[i++] = 'c';
		flags &= ~C_FLAG;
	}
	if (flags & H_FLAG)
		flags &= ~H_FLAG;
	else
		buf[i++] = 'h';
	if (flags & B_FLAG) {
		buf[i++] = 'b';
		flags &= ~B_FLAG;
	}
	if (flags & R_FLAG) {
		buf[i++] = 'r';
		flags &= ~B_FLAG;
	}
	if (flags & I_FLAG) {
		buf[i++] = 'I';
		flags &= ~I_FLAG;
	}
	if (flags)
		log("Internal error in p_ttyflags");
	buf[i] = '\0';
	return (buf);
}

void
dump_pmtab(void)
{
	struct	pmtab *gptr;

	debug("in dump_pmtab");
	log("********** dumping pmtab **********");
	log(" ");
	for (gptr = PMtab; gptr != NULL; gptr = gptr->p_next) {
		log("-------------------------------------------");
		log("tag:\t\t%s", gptr->p_tag);
		log("flags:\t\t%s", pflags(gptr->p_flags));
		log("identity:\t%s", gptr->p_identity);
		log("reserved1:\t%s", gptr->p_res1);
		log("reserved2:\t%s", gptr->p_res2);
		log("reserved3:\t%s", gptr->p_res3);
		log("device:\t%s", gptr->p_device);
		log("ttyflags:\t%s", pttyflags(gptr->p_ttyflags));
		log("count:\t\t%d", gptr->p_count);
		log("server:\t%s", gptr->p_server);
		log("timeout:\t%d", gptr->p_timeout);
		log("ttylabel:\t%s", gptr->p_ttylabel);
		log("modules:\t%s", gptr->p_modules);
		log("prompt:\t%s", gptr->p_prompt);
		log("disable msg:\t%s", gptr->p_dmsg);
		log("terminal type:\t%s", gptr->p_termtype);
		log("soft-carrier:\t%s", gptr->p_softcar);
		log("status:\t\t%d", gptr->p_status);
		log("inservice:\t%d", gptr->p_inservice);
		log("fd:\t\t%d", gptr->p_fd);
		log("pid:\t\t%ld", gptr->p_childpid);
		log("uid:\t\t%ld", gptr->p_uid);
		log("gid:\t\t%ld", gptr->p_gid);
		log("dir:\t%s", gptr->p_dir);
		log(" ");
	}
	log("********** end dumping pmtab **********");
}
#endif

/*
 * same_entry(e1,e2) -    compare 2 entries of pmtab
 *			if the fields are different, copy e2 to e1
 *			return 1 if same, return 0 if different
 */
static	int
same_entry(struct pmtab	*e1, struct pmtab *e2)
{

	if (strcmp(e1->p_identity, e2->p_identity) != 0)
		return (0);
	if (strcmp(e1->p_res1, e2->p_res1) != 0)
		return (0);
	if (strcmp(e1->p_res2, e2->p_res2) != 0)
		return (0);
	if (strcmp(e1->p_res3, e2->p_res3) != 0)
		return (0);
	if (strcmp(e1->p_device, e2->p_device) != 0)
		return (0);
	if (strcmp(e1->p_server, e2->p_server) != 0)
		return (0);
	if (strcmp(e1->p_ttylabel, e2->p_ttylabel) != 0)
		return (0);
	if (strcmp(e1->p_modules, e2->p_modules) != 0)
		return (0);
	if (strcmp(e1->p_prompt, e2->p_prompt) != 0)
		return (0);
	if (strcmp(e1->p_dmsg, e2->p_dmsg) != 0)
		return (0);
	if (strcmp(e1->p_termtype, e2->p_termtype) != 0)
		return (0);
	if (strcmp(e1->p_softcar, e2->p_softcar) != 0)
		return (0);
	if (e1->p_flags != e2->p_flags)
		return (0);
	/*
	 * compare lowest 4 bits only,
	 * because A_FLAG is not part of original ttyflags
	 */
	if ((e1->p_ttyflags & ~A_FLAG) != (e2->p_ttyflags & ~A_FLAG))
		return (0);
	if (e1->p_count != e2->p_count)
		return (0);
	if (e1->p_timeout != e2->p_timeout)
		return (0);
	if (e1->p_uid != e2->p_uid)
		return (0);
	if (e1->p_gid != e2->p_gid)
		return (0);
	if (strcmp(e1->p_dir, e2->p_dir) != 0)
		return (0);
	return (1);
}


/*
 * insert_pmtab - insert a pmtab entry into the linked list
 */

static	void
insert_pmtab(struct pmtab *sp)
{
	struct pmtab *tsp, *savtsp;	/* scratch pointers */
	int ret;				/* strcmp return value */

#ifdef DEBUG
	debug("in insert_pmtab");
#endif
	savtsp = tsp = PMtab;

/*
 * find the correct place to insert this element
 */

	while (tsp) {
		ret = strcmp(sp->p_tag, tsp->p_tag);
		if (ret > 0) {
			/* keep on looking */
			savtsp = tsp;
			tsp = tsp->p_next;
			continue;
		} else if (ret == 0) {
			if (tsp->p_status) {
				/* this is a duplicate entry, ignore it */
				log("Ignoring duplicate entry for <%s>",
				    tsp->p_tag);
			} else {
				if (same_entry(tsp, sp)) {  /* same entry */
					tsp->p_status = VALID;
				} else {	/* entry changed */
					if ((sp->p_flags & X_FLAG) &&
					    ((sp->p_dmsg == NULL) ||
					    (*(sp->p_dmsg) == '\0'))) {
						/* disabled entry */
						tsp->p_status = NOTVALID;
					} else {
#ifdef DEBUG
						debug("replacing <%s>",
						    sp->p_tag);
#endif
						/* replace old entry */
						sp->p_next = tsp->p_next;
						if (tsp == PMtab) {
							PMtab = sp;
						} else {
							savtsp->p_next = sp;
						}
						sp->p_status = CHANGED;
						sp->p_fd = tsp->p_fd;
						sp->p_childpid =
						    tsp->p_childpid;
						sp->p_inservice =
						    tsp->p_inservice;
						sp = tsp;
					}
				}
				Nentries++;
			}
			free_pmtab(sp);
			return;
		} else {
			if ((sp->p_flags & X_FLAG) &&
			    ((sp->p_dmsg == NULL) ||
			    (*(sp->p_dmsg) == '\0'))) { /* disabled entry */
				free_pmtab(sp);
				return;
			}
			/*
			 * Set the state of soft-carrier.
			 * Since this is a one-time only operation,
			 * we do it when this service is added to
			 * the enabled list.
			 */
			if (*sp->p_softcar != '\0')
				set_softcar(sp);

			/* insert it here */
			if (tsp == PMtab) {
				sp->p_next = PMtab;
				PMtab = sp;
			} else {
				sp->p_next = savtsp->p_next;
				savtsp->p_next = sp;
			}
#ifdef DEBUG
			debug("adding <%s>", sp->p_tag);
#endif
			Nentries++;
			/* this entry is "current" */
			sp->p_status = VALID;
			return;
		}
	}

/*
 * either an empty list or should put element at end of list
 */

	if ((sp->p_flags & X_FLAG) &&
	    ((sp->p_dmsg == NULL) ||
	    (*(sp->p_dmsg) == '\0'))) { /* disabled entry */
		free_pmtab(sp);		 /* do not poll this entry */
		return;
	}
	/*
	 * Set the state of soft-carrier.
	 * Since this is a one-time only operation,
	 * we do it when this service is added to
	 * the enabled list.
	 */
	if (*sp->p_softcar != '\0')
		set_softcar(sp);
	sp->p_next = NULL;
	if (PMtab == NULL)
		PMtab = sp;
	else
		savtsp->p_next = sp;
#ifdef DEBUG
	debug("adding <%s>", sp->p_tag);
#endif
	++Nentries;
	/* this entry is "current" */
	sp->p_status = VALID;
}


/*
 * purge - purge linked list of "old" entries
 */
void
purge(void)
{
	struct pmtab *sp;		/* working pointer */
	struct pmtab *savesp, *tsp;	/* scratch pointers */

#ifdef DEBUG
	debug("in purge");
#endif
	sp = savesp = PMtab;
	while (sp) {
		if (sp->p_status) {
#ifdef DEBUG
			debug("p_status not 0");
#endif
			savesp = sp;
			sp = sp->p_next;
		} else {
			tsp = sp;
			if (tsp == PMtab) {
				PMtab = sp->p_next;
				savesp = PMtab;
			} else {
				savesp->p_next = sp->p_next;
			}
#ifdef DEBUG
			debug("purging <%s>", sp->p_tag);
#endif
			sp = sp->p_next;
			free_pmtab(tsp);
		}
	}
}

/*
 *	free_pmtab	- free one pmtab entry
 */
static	void
free_pmtab(struct pmtab	*p)
{
#ifdef	DEBUG
	debug("in free_pmtab");
#endif
	free(p->p_tag);
	free(p->p_identity);
	free(p->p_res1);
	free(p->p_res2);
	free(p->p_res3);
	free(p->p_device);
	free(p->p_server);
	free(p->p_ttylabel);
	free(p->p_modules);
	free(p->p_prompt);
	free(p->p_dmsg);
	free(p->p_termtype);
	free(p->p_softcar);
	free(p->p_dir);
	free(p);
}

/*
 *	check_pmtab - check the fields to make sure things are correct
 *		    - return 0 if everything is ok
 *		    - return -1 if something is wrong
 */
static	int
check_pmtab(struct pmtab *p)
{
	if (p == NULL) {
		log("pmtab ptr is NULL");
		return (-1);
	}

	/* check service tag */
	if ((p->p_tag == NULL) || (*(p->p_tag) == '\0')) {
		log("port/service tag is missing");
		return (-1);
	}
	if (strlen(p->p_tag) > (size_t)(MAXID - 1)) {
		log("port/service tag <%s> is longer than %d", p->p_tag,
		    MAXID-1);
		return (-1);
	}
	if (strcheck(p->p_tag, ALNUM) != 0) {
		log("port/service tag <%s> is not alphanumeric", p->p_tag);
		return (-1);
	}
	if (check_identity(p) != 0) {
		return (-1);
	}

	if (check_device(p->p_device) != 0)
		return (-1);

	if (check_cmd(p->p_server) != 0)
		return (-1);
	return (0);
}

/*
 *	check_identity	- check to see if the identity is a valid user
 *			- log name in the passwd file,
 *			- and if its group id is a valid one
 *			- return 0 if everything is ok. Otherwise, return -1
 */

int
check_identity(struct pmtab *p)
{
	struct passwd *pwdp;

	if ((p->p_identity == NULL) || (*(p->p_identity) == '\0')) {
		log("identity field is missing");
		return (-1);
	}
	if ((pwdp = getpwnam(p->p_identity)) == NULL) {
		log("missing or bad passwd entry for <%s>", p->p_identity);
		endpwent();
		return (-1);
	}
	if (getgrgid(pwdp->pw_gid) == NULL) {
		log("no group entry for %ld", pwdp->pw_gid);
		endgrent();
		endpwent();
		return (-1);
	}
	p->p_uid = pwdp->pw_uid;
	p->p_gid = pwdp->pw_gid;
	p->p_dir = strsave(pwdp->pw_dir);
	endgrent();
	endpwent();
	return (0);
}

/*
 * expand(cmdp, devp)	- expand %d to device name and %% to %,
 *				- any other characters are untouched.
 *				- return the expanded string
 */
static char	*
expand(char *cmdp, char *devp)
{
	char	*cp, *dp, *np;
	static char	buf[BUFSIZ];
	cp = cmdp;
	np = buf;
	dp = devp;
	while (*cp) {
		if (*cp != '%') {
			*np++ = *cp++;
			continue;
		}
		switch (*++cp) {
		case 'd':
			while (*dp) {
				*np++ = *dp++;
			}
			cp++;
			break;
		case '%':
			*np++ = *cp++;
			break;
		default:
			*np++ = *cp++;
			break;
		}
	}
	*np = '\0';
	return (buf);
}
