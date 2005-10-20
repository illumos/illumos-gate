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
 * Copyright 1991 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <stdio.h>
#include <sys/types.h>
#include <sys/label.h>
#include <sys/audit.h>
#include <pwdadj.h>
#include <pwd.h>
#include <rpcsvc/ypclnt.h>
#include <string.h>
#include <malloc.h>

extern void rewind();
extern long strtol();
extern int fclose();

void	setpwaent(void);
void	endpwaent(void);

static struct _pwajunk {
	struct passwd _NULLPW;
	FILE *_pwfadj;
	char *_yp;
	int _yplen;
	char *_oldyp;
	int _oldyplen;
	struct list {
		char *name;
		struct list *nxt;
	} *_minuslist;
	struct passwd _interppasswd;
	struct passwd_adjunct _apwadj;
	char _interpline[BUFSIZ+1];
	char *_domain;
} *__pwajunk, *_pwajunk(void);

#define	NULLPW (_pwa->_NULLPW)
#define pwfadj (_pwa->_pwfadj)
#define yp (_pwa->_yp)
#define yplen (_pwa->_yplen)
#define oldyp (_pwa->_oldyp)
#define oldyplen (_pwa->_oldyplen)
#define minuslist (_pwa->_minuslist)
#define interppasswd (_pwa->_interppasswd)
#define apwadj (_pwa->_apwadj)
#define interpline (_pwa->_interpline)
#define domain (_pwa->_domain)

static char *PASSWDADJ	= "/etc/security/passwd.adjunct"; 

static struct passwd_adjunct	*interpret(char *, int);
static struct passwd_adjunct	*interpretwithsave(char *, int,
    struct passwd_adjunct *);
static struct passwd_adjunct	*save(struct passwd_adjunct *);
static struct passwd_adjunct	*getnamefromyellow(char *,
    struct passwd_adjunct *);
static int	matchname(char [], struct passwd_adjunct **, char *);
static int	onminuslist(struct passwd_adjunct *);
static void	getnextfromyellow(void);
static void	getfirstfromyellow(void);
static void	freeminuslist(void);
static void	addtominuslist(char *);



static struct _pwajunk *
_pwajunk(void)
{

	if (__pwajunk == 0)
		__pwajunk = (struct _pwajunk *)calloc(1, sizeof (*__pwajunk));
	return (__pwajunk);
}

struct passwd_adjunct *
getpwanam(char *name)
{
	struct _pwajunk *_pwa = _pwajunk();
	struct passwd_adjunct *pwadj;
	char line[BUFSIZ+1];

	if (_pwa == 0)
		return (NULL);
	setpwaent();
	if (!pwfadj)
		return (NULL);
	while (fgets(line, BUFSIZ, pwfadj) != NULL) {
		if ((pwadj = interpret(line, strlen(line))) == NULL)
			continue;
		if (matchname(line, &pwadj, name)) {
			endpwaent();
			return (pwadj);
		}
	}
	endpwaent();
	return (NULL);
}


void
setpwaent(void)
{
	struct _pwajunk *_pwa = _pwajunk();

	if (_pwa == 0)
		return;
	if (domain == NULL) {
		(void) yp_get_default_domain(&domain );
	}
	if (pwfadj == NULL)
		pwfadj = fopen(PASSWDADJ, "r");
	else
		rewind(pwfadj);
	if (yp)
		free(yp);
	yp = NULL;
	freeminuslist();
}



void
endpwaent(void)
{
	struct _pwajunk *_pwa = _pwajunk();

	if (_pwa == 0)
		return;
	if (pwfadj != NULL) {
		(void) fclose(pwfadj);
		pwfadj = NULL;
	}
	if (yp)
		free(yp);
	yp = NULL;
	freeminuslist();
	endnetgrent();
}



struct passwd_adjunct *
getpwaent(void)
{
	struct _pwajunk *_pwa = _pwajunk();
	char line[BUFSIZ+1];
	static struct passwd_adjunct *savepwadj;
	struct passwd_adjunct *pwadj;
	char *user; 
	char *mach;
	char *dom;

	if (_pwa == 0)
		return (NULL);
	if (domain == NULL) {
		(void) yp_get_default_domain(&domain );
	}
	if (pwfadj == NULL && (pwfadj = fopen(PASSWDADJ, "r")) == NULL) {
		return (NULL); 
	}

	for (;;) {
		if (yp) {
			pwadj = interpretwithsave(yp, yplen, savepwadj); 
			free(yp);
			if (pwadj == NULL)
				return (NULL);
			getnextfromyellow();
			if (!onminuslist(pwadj)) {
				return (pwadj);
			}
		} else if (getnetgrent(&mach,&user,&dom)) {
			if (user) {
				pwadj = getnamefromyellow(user, savepwadj);
				if (pwadj != NULL && !onminuslist(pwadj)) {
					return (pwadj);
				}
			}
		} else {
			endnetgrent();
			if (fgets(line, BUFSIZ, pwfadj) == NULL)  {
				return (NULL);
			}
			if ((pwadj = interpret(line, strlen(line))) == NULL)
				return (NULL);
			switch(line[0]) {
			case '+':
				if (strcmp(pwadj->pwa_name, "+") == 0) {
					getfirstfromyellow();
					savepwadj = save(pwadj);
				} else if (line[1] == '@') {
					savepwadj = save(pwadj);
					if (innetgr(pwadj->pwa_name+2,(char *) NULL,"*",domain)) {
						/* include the whole NIS database */
						getfirstfromyellow();
					} else {
						setnetgrent(pwadj->pwa_name+2);
					}
				} else {
					/* 
					 * else look up this entry in NIS 
				 	 */
					savepwadj = save(pwadj);
					pwadj = getnamefromyellow(pwadj->pwa_name+1, savepwadj);
					if (pwadj != NULL && !onminuslist(pwadj)) {
						return (pwadj);
					}
				}
				break;
			case '-':
				if (line[1] == '@') {
					if (innetgr(pwadj->pwa_name+2,(char *) NULL,"*",domain)) {
						/* everybody was subtracted */
						return (NULL);
					}
					setnetgrent(pwadj->pwa_name+2);
					while (getnetgrent(&mach,&user,&dom)) {
						if (user) {
							addtominuslist(user);
						}
					}
					endnetgrent();
				} else {
					addtominuslist(pwadj->pwa_name+1);
				}
				break;
			default:
				if (!onminuslist(pwadj)) {
					return (pwadj);
				}
				break;
			}
		}
	}
}

static int
matchname(char line1[], struct passwd_adjunct **pwadjp, char *name)
{
	struct _pwajunk *_pwa = _pwajunk();
	struct passwd_adjunct *savepwadj;
	struct passwd_adjunct *pwadj = *pwadjp;

	if (_pwa == 0)
		return (0);
	switch(line1[0]) {
		case '+':
			if (strcmp(pwadj->pwa_name, "+") == 0) {
				savepwadj = save(pwadj);
				pwadj = getnamefromyellow(name, savepwadj);
				if (pwadj) {
					*pwadjp = pwadj;
					return (1);
				}
				else
					return (0);
			}
			if (line1[1] == '@') {
				if (innetgr(pwadj->pwa_name+2,(char *) NULL,name,domain)) {
					savepwadj = save(pwadj);
					pwadj = getnamefromyellow(name,savepwadj);
					if (pwadj) {
						*pwadjp = pwadj;
						return (1);
					}
				}
				return (0);
			}
			if (strcmp(pwadj->pwa_name+1, name) == 0) {
				savepwadj = save(pwadj);
				pwadj = getnamefromyellow(pwadj->pwa_name+1, savepwadj);
				if (pwadj) {
					*pwadjp = pwadj;
					return (1);
				}
				else
					return (0);
			}
			break;
		case '-':
			if (line1[1] == '@') {
				if (innetgr(pwadj->pwa_name+2,(char *) NULL,name,domain)) {
					*pwadjp = NULL;
					return (1);
				}
			}
			else if (strcmp(pwadj->pwa_name+1, name) == 0) {
				*pwadjp = NULL;
				return (1);
			}
			break;
		default:
			if (strcmp(pwadj->pwa_name, name) == 0)
				return (1);
	}
	return (0);
}

static void
getnextfromyellow(void)
{
	struct _pwajunk *_pwa = _pwajunk();
	int reason;
	char *key;
	int keylen;

	if (_pwa == 0)
		return;
	reason = yp_next(domain, "passwd_adjunct",oldyp, oldyplen, &key
	    ,&keylen,&yp,&yplen);
	if (reason) {
#ifdef DEBUG
fprintf(stderr, "reason yp_next failed is %d\n", reason);
#endif
		yp = NULL;
	}
	if (oldyp)
		free(oldyp);
	oldyp = key;
	oldyplen = keylen;
}

static void
getfirstfromyellow(void)
{
	struct _pwajunk *_pwa = _pwajunk();
	int reason;
	char *key;
	int keylen;
	
	if (_pwa == 0)
		return;
	reason =  yp_first(domain, "passwd_adjunct", &key, &keylen, &yp, &yplen);
	if (reason) {
#ifdef DEBUG
fprintf(stderr, "reason yp_first failed is %d\n", reason);
#endif
		yp = NULL;
	}
	if (oldyp)
		free(oldyp);
	oldyp = key;
	oldyplen = keylen;
}

static struct passwd_adjunct *
getnamefromyellow(char *name, struct passwd_adjunct *savepwadj)
{
	struct _pwajunk *_pwa = _pwajunk();
	struct passwd_adjunct *pwadj;
	int reason;
	char *val;
	int vallen;
	
	if (_pwa == 0)
		return (NULL);
	reason = yp_match(domain, "passwd.adjunct.byname", name, strlen(name)
		, &val, &vallen);
	if (reason) {
#ifdef DEBUG
fprintf(stderr, "reason yp_match failed is %d\n", reason);
#endif
		return (NULL);
	} else {
		pwadj = interpret(val, vallen);
		free(val);
		if (pwadj == NULL)
			return (NULL);
		if (savepwadj->pwa_passwd && *savepwadj->pwa_passwd)
			pwadj->pwa_passwd =  savepwadj->pwa_passwd;
		return (pwadj);
	}
}

static struct passwd_adjunct *
interpretwithsave(char *val, int len, struct passwd_adjunct *savepwadj)
{
	struct _pwajunk *_pwa = _pwajunk();
	struct passwd_adjunct *pwadj;
	
	if (_pwa == 0)
		return (NULL);
	if ((pwadj = interpret(val, len)) == NULL)
		return (NULL);
	if (savepwadj->pwa_passwd && *savepwadj->pwa_passwd)
		pwadj->pwa_passwd =  savepwadj->pwa_passwd;
	return (pwadj);
}

static char *
pwskip(char *p)
{
	while(*p && *p != ':' && *p != '\n')
		++p;
	if (*p == '\n')
		*p = '\0';
	else if (*p != '\0')
		*p++ = '\0';
	return (p);
}

static struct passwd_adjunct *
interpret(char *val, int len)
{
	struct _pwajunk *_pwa = _pwajunk();
	char *p;
	char *field;

	if (_pwa == 0)
		return (NULL);
	(void) strncpy(interpline, val, len);
	p = interpline;
	interpline[len] = '\n';
	interpline[len+1] = 0;

	apwadj.pwa_name = p;
	p = pwskip(p);
	if (strcmp(apwadj.pwa_name, "+") == 0) {
		/* we are going to the NIS - fix the
		 * rest of the struct as much as is needed
		 */
		apwadj.pwa_passwd = "";
		return (&apwadj);
	}
	apwadj.pwa_passwd = p;
	p = pwskip(p);
	field = p;
	p = pwskip(p);
	labelfromstring(0, field, &apwadj.pwa_minimum);
	field = p;
	p = pwskip(p);
	labelfromstring(0, field, &apwadj.pwa_maximum);
	field = p;
	p = pwskip(p);
	labelfromstring(0, field, &apwadj.pwa_def);
	field = p;
	p = pwskip(p);
	apwadj.pwa_au_always.as_success = 0;
	apwadj.pwa_au_always.as_failure = 0;
	if (getauditflagsbin(field, &apwadj.pwa_au_always) != 0)
		return (NULL);
	field = p;
	(void) pwskip(p);
	p = apwadj.pwa_passwd;
	while (*p && *p != ',')
		p++;
	if (*p)
		*p = '\0';
	apwadj.pwa_age = p;
	apwadj.pwa_au_never.as_success = 0;
	apwadj.pwa_au_never.as_failure = 0;
	if (getauditflagsbin(field, &apwadj.pwa_au_never) != 0)
		return (NULL);
	return (&apwadj);
}

static void
freeminuslist(void) {
	struct _pwajunk *_pwa = _pwajunk();
	struct list *ls;
	
	if (_pwa == 0)
		return;
	for (ls = minuslist; ls != NULL; ls = ls->nxt) {
		free(ls->name);
		free((char *) ls);
	}
	minuslist = NULL;
}

static void
addtominuslist(char *name)
{
	struct _pwajunk *_pwa = _pwajunk();
	struct list *ls;
	char *buf;
	
	if (_pwa == 0)
		return;
	ls = (struct list *) malloc(sizeof(struct list));
	buf = malloc((unsigned) strlen(name) + 1);
	(void) strcpy(buf, name);
	ls->name = buf;
	ls->nxt = minuslist;
	minuslist = ls;
}

/* 
 * save away the psswd field, which is the only one which can be
 * specified in a local + entry to override the value in the NIS 
 * for passwd.adjunct
 */
static struct passwd_adjunct *
save(struct passwd_adjunct *pwadj)
{
	struct _pwajunk *_pwa = _pwajunk();
	static struct passwd_adjunct *sv;

	if (_pwa == 0)
		return (NULL);
	/* free up stuff from last call */
	if (sv) {
		free(sv->pwa_passwd);
		free((char *) sv);
	}
	sv = (struct passwd_adjunct *) malloc(sizeof(struct passwd_adjunct));

	sv->pwa_passwd = malloc((unsigned) strlen(pwadj->pwa_passwd) + 1);
	(void) strcpy(sv->pwa_passwd, pwadj->pwa_passwd);

	return (sv);
}

static int
onminuslist(struct passwd_adjunct *pwadj)
{
	struct _pwajunk *_pwa = _pwajunk();
	struct list *ls;
	char *nm;

	if (_pwa == 0)
		return (0);
	nm = pwadj->pwa_name;
	for (ls = minuslist; ls != NULL; ls = ls->nxt) {
		if (strcmp(ls->name,nm) == 0) {
			return (1);
		}
	}
	return (0);
}
