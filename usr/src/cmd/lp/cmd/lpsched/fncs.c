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

/* EMACS_MODES: !fill, lnumb, !overwrite, !nodelete, !picture */

#include "unistd.h"
#include "sys/types.h"
#include "sys/stat.h"
#include "errno.h"
#include "fcntl.h"
#include "stdlib.h"
#include "string.h"

#include "lpsched.h"

static int __list_increment = 16;

int
list_append(void ***list, void *item)
{
        int count;

        if ((list == NULL) || (item == NULL)) {
                errno = EINVAL;
                return (-1);
        }

        if (item != NULL) {
                if (*list == NULL)
                        *list = (void **)calloc(__list_increment,
                                                sizeof (void *));

		if (*list == NULL)
			return (-1);

                for (count = 0; (*list)[count] != NULL; count++);

                if ((count + 1) % __list_increment == 0) { /* expand the list */                        void **new_list = NULL;
                        int new_size = (((count + 1) / __list_increment) + 1) *
                                __list_increment;

                        new_list = (void **)calloc(new_size, sizeof (void *));
			if (new_list == NULL)
				return (-1);

                        for (count = 0; (*list)[count] != NULL; count++)
                                new_list[count] = (*list)[count];
                        free(*list);
                        *list = new_list;
                }

                (*list)[count] = item;
        }

        return (0);
}

void
list_remove(void ***list, void *item)
{
        int i, count;
	void **tmp = NULL;

        if ((list == NULL) || (*list == NULL) || (item == NULL))
                return;

        for (count = 0; (*list)[count] != NULL; count++)
                ;

	if (count > 0) {
        	int new_size = (((count + 1) / __list_increment) + 1) *
                                	__list_increment;

        	if ((tmp = (void **)calloc(new_size, sizeof (void *))) == NULL)
			tmp = *list;
	
		/* copy up to item */
        	for (i = 0; (((*list)[i] != NULL) && ((*list)[i] != item)); i++)
			tmp[i] = (*list)[i];
		/* copy after item */
		if ((*list)[i] == item)
        		for (++i; ((*list)[i] != NULL); i++)
				tmp[i-1] = (*list)[i];
	}

	/* replace the list */
	if (tmp != *list) {
		free(*list);
		*list = tmp;
	}
}

void
free_exec(EXEC *ep)
{
	if (ep != NULL) {
		free(ep);
		list_remove((void ***)&Exec_Table, (void *)ep);
	}
}

EXEC *
new_exec(int type, void *ex)
{
	EXEC *result = calloc(1, sizeof (*result));

	if (result != NULL) {
		result->type = type;
		switch (type) {
		case EX_ALERT:
		case EX_INTERF:
		case EX_FAULT_MESSAGE:
			result->ex.printer = ex;
			break;
		case EX_FALERT:
			result->ex.form = ex;
			break;
		case EX_PALERT:
			result->ex.pwheel = ex;
			break;
		case EX_SLOWF:
		case EX_NOTIFY:
			break;
		}
		list_append((void ***)&Exec_Table, (void *)result);
	}

	return (result);
}

void
free_alert(ALERT *ap)
{
	if (ap != NULL) {
		if (ap->msgfile != NULL)
			free(ap->msgfile);
		if (ap->exec != NULL)
			free_exec(ap->exec);
		free(ap);
	}
}

ALERT *
new_alert(char *fmt, int i)
{
	ALERT *result = calloc(1, sizeof (*result));

	if (result != NULL) {
		char	buf[15];

		snprintf(buf, sizeof (buf), fmt, i);
		result->msgfile = makepath(Lp_Temp, buf, (char *)0);
		(void) Unlink(result->msgfile);
	}

	return (result);
}

void
free_pstatus(PSTATUS *psp)
{
	if (psp != NULL) {
		if (psp->alert != NULL)
			free_alert(psp->alert);
		if (psp->exec != NULL)
			free_exec(psp->exec);
		if (psp->fault_exec != NULL)
			free_exec(psp->fault_exec);
		if (psp->printer != NULL)
			freeprinter(psp->printer);
		if (psp->pwheel_name != NULL)
			free(psp->pwheel_name);
		if (psp->dis_reason != NULL)
			free(psp->dis_reason);
		if (psp->rej_reason != NULL)
			free(psp->rej_reason);
		if (psp->users_allowed != NULL)
			unload_list(&psp->users_allowed);
		if (psp->users_denied != NULL)
			unload_list(&psp->users_denied);
		if (psp->forms_allowed != NULL)
			unload_list(&psp->forms_allowed);
		if (psp->forms_denied != NULL)
			unload_list(&psp->forms_denied);
		if (psp->cpi != NULL)
			free(psp->cpi);
		if (psp->lpi != NULL)
			free(psp->lpi);
		if (psp->plen != NULL)
			free(psp->plen);
		if (psp->pwid != NULL)
			free(psp->pwid);
		if (psp->fault_reason != NULL)
			free(psp->fault_reason);
		if (psp->paper_allowed != NULL)
			unload_list(&psp->paper_allowed);
		free(psp);
	}
}

void
pstatus_add_printer(PSTATUS *ps, PRINTER *p)
{
	if ((ps != NULL) && (p != NULL)) {
    		char	**paperDenied = NULL;

		ps->printer = p;
		load_userprinter_access(p->name, &(ps->users_allowed),
				&(ps->users_denied));
		load_formprinter_access(p->name, &(ps->forms_allowed),
				&(ps->forms_denied));
		load_paperprinter_access(p->name, &ps->paper_allowed,
				&paperDenied);
		freelist(paperDenied);
		load_sdn(&(ps->cpi), p->cpi);
		load_sdn(&(ps->lpi), p->lpi);
		load_sdn(&(ps->plen), p->plen);
		load_sdn(&(ps->pwid), p->pwid);
	}
}

PSTATUS *
new_pstatus(PRINTER *p)
{
	PSTATUS *result = calloc(1, sizeof (*result));
	
	if (result != NULL) {
		static int i = 0;
    		char	**paperDenied = NULL;

		result->alert = new_alert("A-%d", i++);
		result->alert->exec = new_exec(EX_ALERT, result);
		result->exec = new_exec(EX_INTERF, result);
		result->fault_exec = new_exec(EX_FAULT_MESSAGE, result);

		if (p != NULL)
			pstatus_add_printer(result, p);

		list_append((void ***)&PStatus, (void *)result);
	}

	return (result);
}

void
free_cstatus(CLSTATUS *csp)
{
	if (csp != NULL) {
		if (csp->rej_reason != NULL)
			free(csp->rej_reason);
		if (csp->class != NULL)
			freeclass(csp->class);
		free(csp);
	}
}

CLSTATUS *
new_cstatus(CLASS *c)
{
	CLSTATUS *result = calloc(1, sizeof (*result));
	
	if (result != NULL) {
		if (c != NULL)
			result->class = c;
		else
			result->class = calloc(1, sizeof (CLASS));

        	list_append((void ***)&CStatus, result);
	}

	return (result);
}

void
free_fstatus(FSTATUS *fsp)
{
	if (fsp != NULL) {
		if (fsp->form != NULL)
			free_form(fsp->form);
		if (fsp->alert != NULL)
			free_alert(fsp->alert);
		if (fsp->users_allowed != NULL)
			unload_list(&fsp->users_allowed);
		if (fsp->users_denied != NULL)
			unload_list(&fsp->users_denied);
		if (fsp->cpi != NULL)
			free(fsp->cpi);
		if (fsp->lpi != NULL)
			free(fsp->lpi);
		if (fsp->plen != NULL)
			free(fsp->plen);
		if (fsp->pwid != NULL)
			free(fsp->pwid);
		free(fsp);
	}
}

FSTATUS *
new_fstatus(_FORM *f)
{
	FSTATUS *result = calloc(1, sizeof (*result));
	
	if (result != NULL) {
		static int i = 0;

		if (f != NULL)
			result->form = f;
		else
			result->form = calloc(1, sizeof (_FORM));

		result->alert = new_alert("F-%d", i++);
		result->alert->exec = new_exec(EX_FALERT, result);
		result->trigger = result->form->alert.Q;

		if (f != NULL) {	
			load_userform_access(f->name, &(result->users_allowed),
		    			&(result->users_denied));
			load_sdn (&(result->cpi), f->cpi);
			load_sdn (&(result->lpi), f->lpi);
			load_sdn (&(result->plen), f->plen);
			load_sdn (&(result->pwid), f->pwid);
		}

		list_append((void ***)&FStatus, (void *)result);
	}

	return (result);
}

void
free_pwstatus(PWSTATUS *pwp)
{
	if (pwp != NULL) {
		if (pwp->pwheel)
			freepwheel(pwp->pwheel);
		if (pwp->alert != NULL)
			free_alert(pwp->alert);
		free(pwp);
	}
}

PWSTATUS *
new_pwstatus(PWHEEL *p)
{
	PWSTATUS *result = calloc(1, sizeof (*result));

	if (result != NULL) {
		static int i = 0;

		if (p != NULL)
			result->pwheel = p;	
		else
			result->pwheel = calloc(1, sizeof (*result));
			
		result->alert = new_alert("P-%d", i++);
		result->alert->exec = new_exec(EX_PALERT, result);
		result->trigger = result->pwheel->alert.Q;

		list_append((void ***)&PWStatus, (void *)result);
	}

	return (result);
}

void
free_rstatus(RSTATUS *rsp)
{
	if (rsp != NULL) {
		remover(rsp);

		if (rsp->request != NULL)
			freerequest(rsp->request);
		if (rsp->secure != NULL)
			freesecure(rsp->secure);
		if (rsp->req_file)
			Free (rsp->req_file);
		if (rsp->slow)
			Free (rsp->slow);
		if (rsp->fast)
			Free (rsp->fast);
		if (rsp->pwheel_name)
			Free (rsp->pwheel_name);
		if (rsp->printer_type)
			Free (rsp->printer_type);
		if (rsp->output_type)
			Free (rsp->output_type);
		if (rsp->cpi)
			Free (rsp->cpi);
		if (rsp->lpi)
			Free (rsp->lpi);
		if (rsp->plen)
			Free (rsp->plen);
		if (rsp->pwid)
			Free (rsp->pwid);
		free(rsp);
	}
}

RSTATUS *
new_rstatus(REQUEST *r, SECURE *s)
{
	RSTATUS *result = calloc(1, sizeof (*result));

	if (result != NULL) {
		if ((result->request = r) == NULL)
			result->request = calloc(1, sizeof (REQUEST));
		if ((result->secure = s) == NULL)
			result->secure = calloc(1, sizeof (SECURE));
	}

	return (result);
}

/**
 ** search_pstatus() - SEARCH PRINTER TABLE
 ** search_fstatus() - SEARCH FORMS TABLE
 ** search_cstatus() - SEARCH CLASS TABLE
 ** search_pwstatus() - SEARCH PRINT WHEEL TABLE
 **/

PSTATUS *
search_pstatus(register char *name)
{ 
	PSTATUS	*ps = NULL;

	if (name != NULL) {
		if (PStatus != NULL) {
			int i;

			for (i = 0; ((PStatus[i] != NULL) && (ps == NULL)); i++)
				if (SAME(PStatus[i]->printer->name, name))
					ps = PStatus[i];
		}
	} else
		ps = new_pstatus(NULL);

	return (ps); 
}


FSTATUS *
search_fstatus(register char *name)
{ 
	FSTATUS	*ps = NULL;

	if (name != NULL) {
		if (FStatus != NULL) {
			int i;

			for (i = 0; ((FStatus[i] != NULL) && (ps == NULL)); i++)
				if (SAME(FStatus[i]->form->name, name))
					ps = FStatus[i];
		}
	} else
		ps = new_fstatus(NULL);

	return (ps); 
}

FSTATUS *
search_fptable(register char *paper)
{ 
	FSTATUS	*ps = NULL;
	int i;

	if (FStatus != NULL) {
		for (i = 0; ((FStatus[i] != NULL) && (ps == NULL)); i++)
			if (SAME(FStatus[i]->form->paper, paper)) {
				if (ps->form->isDefault)
					ps = FStatus[i];
			}
	}

	return (ps); 
}

CLSTATUS *
search_cstatus(register char *name)
{ 
	CLSTATUS	*ps = NULL;

	if (name != NULL) {
		if (CStatus != NULL) {
			int i;

			for (i = 0; ((CStatus[i] != NULL) && (ps == NULL)); i++)
				if (SAME(CStatus[i]->class->name, name))
					ps = CStatus[i];
		}
	} else
		ps = new_cstatus(NULL);

	return (ps); 
}

PWSTATUS *
search_pwstatus(register char *name)
{ 
	PWSTATUS	*ps = NULL;

	if (name != NULL) {
		if (PWStatus != NULL) {
			int i;

			for (i = 0; ((PWStatus[i] != NULL) && (ps == NULL)); i++)
				if (SAME(PWStatus[i]->pwheel->name, name))
					ps = PWStatus[i];
		}
	} else
		ps = new_pwstatus(NULL);

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
	_FORM		*_form;

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

	_form = calloc(1, sizeof (*_form));
	_form->plen = formbuf.plen;
	_form->pwid = formbuf.pwid;
	_form->lpi = formbuf.lpi;
	_form->cpi = formbuf.cpi;
	_form->np = formbuf.np;
	_form->chset = formbuf.chset;
	_form->mandatory = formbuf.mandatory;
	_form->rcolor = formbuf.rcolor;
	_form->comment = formbuf.comment;
	_form->conttype = formbuf.conttype;
	_form->name = formbuf.name;
	_form->paper = formbuf.paper;
	_form->isDefault = formbuf.isDefault;

	if ((_form->alert.shcmd = alertbuf.shcmd) != NULL) {
		_form->alert.Q = alertbuf.Q;
		_form->alert.W = alertbuf.W;
	} else {
		_form->alert.Q = 0;
		_form->alert.W = 0;
	}

	return (_form);
}

/**
 ** Getprinter()
 ** Getrequest()
 ** Getuser()
 ** Getclass()
 ** Getpwheel()
 ** Getsecure()
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
		 * calling freesecure which will destroy uid and
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
