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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "unistd.h"
#include "sys/types.h"
#include "sys/stat.h"
#include "errno.h"
#include "fcntl.h"
#include "stdlib.h"
#include "string.h"

#include "lpsched.h"

/**
 ** walk_ptable() - WALK PRINTER TABLE, RETURNING ACTIVE ENTRIES
 ** walk_ftable() - WALK FORMS TABLE, RETURNING ACTIVE ENTRIES
 ** walk_ctable() - WALK CLASS TABLE, RETURNING ACTIVE ENTRIES
 ** walk_pwtable() - WALK PRINT WHEEL TABLE, RETURNING ACTIVE ENTRIES
 **/


PSTATUS *
walk_ptable(int start)
{
	static PSTATUS		*psend,
				*ps = 0;

	if (start || !ps) {
		ps = PStatus;
		psend = PStatus + PT_Size;
	}

	while (ps < psend && !ps->printer->name)
		ps++;

	if (ps >= psend)
		return (ps = 0);
	else
		return (ps++);
}

FSTATUS *
walk_ftable(int start)
{
	static FSTATUS		*psend,
				*ps = 0;

	if (start || !ps) {
		ps = FStatus;
		psend = FStatus + FT_Size;
	}

	while (ps < psend && !ps->form->name)
		ps++;

	if (ps >= psend)
		return (ps = 0);
	else
		return (ps++);
}

CSTATUS *
walk_ctable (int start)
{
	static CSTATUS		*psend,
				*ps = 0;

	if (start || !ps) {
		ps = CStatus;
		psend = CStatus + CT_Size;
	}

	while (ps < psend && !ps->class->name)
		ps++;

	if (ps >= psend)
		return (ps = 0);
	else
		return (ps++);
}

PWSTATUS *
walk_pwtable(int start)
{
	static PWSTATUS		*psend,
				*ps = 0;

	if (start || !ps) {
		ps = PWStatus;
		psend = PWStatus + PWT_Size;
	}

	while (ps < psend && !ps->pwheel->name)
		ps++;

	if (ps >= psend)
		return (ps = 0);
	else
		return (ps++);
}


/**
 ** search_ptable() - SEARCH PRINTER TABLE
 ** search_ftable() - SEARCH FORMS TABLE
 ** search_ctable() - SEARCH CLASS TABLE
 ** search_pwtable() - SEARCH PRINT WHEEL TABLE
 **/

PSTATUS *
search_ptable(register char *name)
{ 
	register PSTATUS	*ps,
				*psend; 

	for ( 
		ps = & PStatus[0], psend = & PStatus[PT_Size]; 
		ps < psend && !SAME(ps->printer->name, name); 
		ps++ 
	)
		; 

	if (ps >= psend) 
		ps = 0; 

	return (ps); 
}


FSTATUS *
search_ftable(register char *name)
{ 
	register FSTATUS	*ps, *psend; 

	for (ps = & FStatus[0], psend = & FStatus[FT_Size]; 
	    ps < psend && !SAME(ps->form->name, name); ps++); 

	if (ps >= psend) 
		ps = 0; 

	return (ps); 
}

FSTATUS *
search_fptable(register char *paper)
{ 
	register FSTATUS	*ps,*cand, *psend; 

	cand = NULL;
	for (ps = & FStatus[0], psend = & FStatus[FT_Size]; ps < psend; ps++)
		if (SAME(ps->form->paper, paper)) {
			if (ps->form->isDefault) {
				cand = ps;
				break;
			} else if (!cand)
				cand = ps;
		}

	return (cand); 
}

CSTATUS *
search_ctable(register char *name)
{ 
	register CSTATUS	*ps,
				*psend; 

	for ( 
		ps = & CStatus[0], psend = & CStatus[CT_Size]; 
		ps < psend && !SAME(ps->class->name, name); 
		ps++ 
	)
		; 

	if (ps >= psend) 
		ps = 0; 

	return (ps); 
}

PWSTATUS *
search_pwtable(register char *name)
{ 
	register PWSTATUS	*ps,
				*psend; 

	for ( 
		ps = & PWStatus[0], psend = & PWStatus[PWT_Size]; 
		ps < psend && !SAME(ps->pwheel->name, name); 
		ps++ 
	)
		; 

	if (ps >= psend) 
		ps = 0; 

	return (ps); 
}


/**
 ** load_str() - LOAD STRING WHERE ALLOC'D STRING MAY BE
 ** unload_str() - REMOVE POSSIBLE ALLOC'D STRING
 **/

void
load_str(char **pdst, char *src)
{
	if (*pdst)
		Free (*pdst);
	*pdst = Strdup(src);
	return;
}

void
unload_str(char **pdst)
{
	if (*pdst)
		Free (*pdst);
	*pdst = 0;
	return;
}

/**
 ** unload_list() - REMOVE POSSIBLE ALLOC'D LIST
 **/

void
unload_list(char ***plist)
{
	if (*plist)
		freelist (*plist);
	*plist = 0;
	return;
}

/**
 ** load_sdn() - LOAD STRING WITH ASCII VERSION OF SCALED DECIMAL NUMBER
 **/

void
load_sdn(char **p, SCALED sdn)
{
	if (!p)
		return;

	if (*p)
		Free (*p);
	*p = 0;

	if (sdn.val <= 0 || 999999 < sdn.val)
		return;

	*p = Malloc(sizeof("999999.999x"));
	sprintf (
		*p,
		"%.3f%s",
		sdn.val,
		(sdn.sc == 'c'? "c" : (sdn.sc == 'i'? "i" : ""))
	);

	return;
}

/**
 ** Getform() - EASIER INTERFACE TO "getform()"
 **/

_FORM *
Getform(char *form)
{
	static _FORM		_formbuf;

	FORM			formbuf;

	FALERT			alertbuf;

	int			ret;


	while (
		(ret = getform(form, &formbuf, &alertbuf, (FILE **)0)) == -1
	     && errno == EINTR
	)
		;
	if (ret == -1)
		return (0);

	_formbuf.plen = formbuf.plen;
	_formbuf.pwid = formbuf.pwid;
	_formbuf.lpi = formbuf.lpi;
	_formbuf.cpi = formbuf.cpi;
	_formbuf.np = formbuf.np;
	_formbuf.chset = formbuf.chset;
	_formbuf.mandatory = formbuf.mandatory;
	_formbuf.rcolor = formbuf.rcolor;
	_formbuf.comment = formbuf.comment;
	_formbuf.conttype = formbuf.conttype;
	_formbuf.name = formbuf.name;
	_formbuf.paper = formbuf.paper;
	_formbuf.isDefault = formbuf.isDefault;

	if ((_formbuf.alert.shcmd = alertbuf.shcmd) != NULL) {
		_formbuf.alert.Q = alertbuf.Q;
		_formbuf.alert.W = alertbuf.W;
	} else {
		_formbuf.alert.Q = 0;
		_formbuf.alert.W = 0;
	}

	return (&_formbuf);
}

/**
 ** Getprinter()
 ** Getrequest()
 ** Getuser()
 ** Getclass()
 ** Getpwheel()
 ** Getsecure()
 ** Getsystem()
 ** Loadfilters()
 **/

PRINTER *
Getprinter(char *name)
{
	register PRINTER	*ret;

	while (!(ret = getprinter(name)) && errno == EINTR)
		;
	return (ret);
}

REQUEST *
Getrequest(char *file)
{
	register REQUEST	*ret;

	while (!(ret = getrequest(file)) && errno == EINTR)
		;
	return (ret);
}

USER *
Getuser(char *name)
{
	register USER		*ret;

	while (!(ret = getuser(name)) && errno == EINTR)
		;
	return (ret);
}

CLASS *
Getclass(char *name)
{
	register CLASS		*ret;

	while (!(ret = getclass(name)) && errno == EINTR)
		;
	return (ret);
}

PWHEEL *
Getpwheel(char *name)
{
	register PWHEEL		*ret;

	while (!(ret = getpwheel(name)) && errno == EINTR)
		;
	return (ret);
}

SECURE *
Getsecure(char *file)
{
	register SECURE		*ret;

	while (!(ret = getsecure(file)) && errno == EINTR)
		;
        return ((SECURE *) ret);
}


int
Loadfilters(char *file)
{
	register int		ret;

	while ((ret = loadfilters(file)) == -1 && errno == EINTR)
		;
	return (ret);
}

/**
 ** free_form() - FREE MEMORY ALLOCATED FOR _FORM STRUCTURE
 **/

void
free_form(register _FORM *pf)
{
	if (!pf)
		return;
	if (pf->chset)
		Free (pf->chset);
	if (pf->rcolor)
		Free (pf->rcolor);
	if (pf->comment)
		Free (pf->comment);
	if (pf->conttype)
		Free (pf->conttype);
	if (pf->name)
		Free (pf->name);
	if (pf->paper)
		Free (pf->paper);
	pf->name = 0;
	if (pf->alert.shcmd)
		Free (pf->alert.shcmd);
	return;
}

/**
 ** getreqno() - GET NUMBER PART OF REQUEST ID
 **/

char *
getreqno(char *req_id)
{
	register char		*cp;


	if (!(cp = strrchr(req_id, '-')))
		cp = req_id;
	else
		cp++;
	return (cp);
}

/* Putsecure():	Insurance for writing out the secure request file.
 *	input:	char ptr to name of the request file,
 *		ptr to the SECURE structure to be written.
 *	ouput:	0 if successful, -1 otherwise.
 *
 *	Description:
 *		The normal call to putsecure() is woefully lacking.
 *		The bottom line here is that there
 *		is no way to make sure that the file has been written out
 *		as expected. This can cause rude behaviour later on.
 *
 *		This routine calls putsecure(), and then does a getsecure().
 *		The results are compared to the original structure. If the
 *		info obtained by getsecure() doesn't match, we retry a few
 *		times before giving up (presumably something is very seriously
 *		wrong at that point).
 */


int
Putsecure(char *file, SECURE *secbufp)
{
	SECURE	*pls;
	int	retries = 5;	/* # of attempts			*/
	int	status;		/*  0 = success, nonzero otherwise	*/


	while (retries--) {
		status = 1;	/* assume the worst, hope for the best	*/
		if (putsecure(file, secbufp) == -1) {
			rmsecure(file);
			continue;
		}

		if ((pls = getsecure(file)) == (SECURE *) NULL) {
			rmsecure(file);
			status = 2;
			continue;
		}

		/* now compare each field	*/

		/*
		 * A comparison is only valid if secbufp and pls point to
		 * different locations.  In reality getsecure() will have
		 * already been called, allocating the same STATIC memory
		 * location to both structures making the following compare
		 * meaningless.
		 * Therefore test for this condition to prevent us from
		 * calling freesecure which will destroy uid, system and
		 * req_id fields in the strucure
		 */

		status = 0;
		if (secbufp != pls) {
			if (strcmp(pls->req_id, secbufp->req_id) != 0) {
				rmsecure(file);
				status = 3;
				continue;
			}

			if (pls->uid != secbufp->uid) {
				rmsecure(file);
				status = 4;
				continue;
			}

			if (strcmp(pls->user, secbufp->user) != 0) {
				rmsecure(file);
				status = 5;
				continue;
			}

			if (pls->gid != secbufp->gid) {
				rmsecure(file);
				status = 6;
				continue;
			}

			if (pls->size != secbufp->size) {
				rmsecure(file);
				status = 7;
				continue;
			}

			if (pls->date != secbufp->date) {
				rmsecure(file);
				status = 8;
				continue;
			}

			if (strcmp(pls->system, secbufp->system) != 0) {
				rmsecure(file);
				status = 9;
				continue;
			}
			freesecure(pls);
		}
		break;
	}

	if (status != 0) {
		note("Putsecure failed, status=%d\n", status);
		return -1;
	}

	return 0;
}

void GetRequestFiles(REQUEST *req, char *buffer, int length)
{
	char buf[BUFSIZ];

	memset(buf, 0, sizeof(buf));

	if (req->title) {
		char *r = req->title;
		char *ptr = buf;

		while ( *r && strncmp(r,"\\n",2)) {
		  	*ptr++ = *r++;
		}
	} else if (req->file_list)
		strlcpy(buf, *req->file_list, sizeof (buf));
	
	if (*buf == NULL || !strncmp(buf, SPOOLDIR, sizeof(SPOOLDIR)-1))
		strcpy(buf, "<File name not available>");

	if (strlen(buf) > (size_t) 24) {
		char *r;

		if (r = strrchr(buf, '/'))
			r++;
		else
			r = buf;
	
		snprintf(buffer, length, "%-.24s", r);	
	} else
		strlcpy(buffer, buf, length);
	return;
}


/**
 ** _Malloc()
 ** _Realloc()
 ** _Calloc()
 ** _Strdup()
 ** _Free()
 **/

void			(*lp_alloc_fail_handler)( void ) = 0;

typedef void *alloc_type;

alloc_type
_Malloc(size_t size, const char *file, int line)
{
	alloc_type		ret;

	ret = malloc(size);
	if (!ret) {
		if (lp_alloc_fail_handler)
			(*lp_alloc_fail_handler)();
		errno = ENOMEM;
	}
	return (ret);
}

alloc_type
_Realloc(void *ptr, size_t size, const char *file, int line)
{
	alloc_type		ret	= realloc(ptr, size);

	if (!ret) {
		if (lp_alloc_fail_handler)
			(*lp_alloc_fail_handler)();
		errno = ENOMEM;
	}
	return (ret);
}

alloc_type
_Calloc(size_t nelem, size_t elsize, const char *file, int line)
{
	alloc_type		ret	= calloc(nelem, elsize);

	if (!ret) {
		if (lp_alloc_fail_handler)
			(*lp_alloc_fail_handler)();
		errno = ENOMEM;
	}
	return (ret);
}

char *
_Strdup(const char *s, const char *file, int line)
{
	char *			ret;

	if (!s)
		return( (char *) 0);

	ret = strdup(s);

	if (!ret) {
		if (lp_alloc_fail_handler)
			(*lp_alloc_fail_handler)();
		errno = ENOMEM;
	}
	return (ret);
}

void
_Free(void *ptr, const char *file, int line)
{
	free (ptr);
	return;
}
