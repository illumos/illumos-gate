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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

# include	<stdarg.h>
# include	"lpsched.h"

typedef struct fault	FLT;

struct fault
{
    FLT *	next;
    int		type;
    int		i1;
    char *	s1;
    RSTATUS *	r1;
    MESG *	ident;
};

static void free_flt ( FLT * );
static void do_flt_acts ( MESG * );

static FLT	Fault_Head = { NULL, 0, 0, NULL, NULL, NULL };
static FLT *	Fault_List = &Fault_Head;

void
add_flt_act(MESG * md, ...)
{
    va_list	arg;
    FLT		*f;

    va_start (arg, md);

    f = (FLT *)Malloc(sizeof(FLT));
    
    (void) memset((char *)f, 0, sizeof(FLT));
    
    f->type = (int)va_arg(arg, int);
    f->ident = md;
    
    if (md->on_discon == NULL)
	if (mon_discon(md, do_flt_acts))
	    mallocfail();

    switch(f->type)
    {
	case FLT_FILES:
	f->s1 = Strdup((char *)va_arg(arg, char *));
	f->i1 = (int)va_arg(arg, int);
	break;
	
	case FLT_CHANGE:
	f->r1 = (RSTATUS *)va_arg(arg, RSTATUS *);
	break;
    }

    va_end(arg);

    f->next = Fault_List->next;
    Fault_List->next = f;
}


void
del_flt_act(MESG *md, ...)
{
    va_list	arg;
    int		type;
    FLT		*fp;
    FLT		*f;

    va_start(arg, md);

    type = (int)va_arg(arg, int);
    
    for (f = Fault_List; f->next; f = f->next)
	if (f->next->type == type && f->next->ident == md)
	{
	    fp = f->next;
	    f->next = f->next->next;
	    free_flt(fp);
	    break;
	}

    va_end(arg);
}

static void
do_flt_acts(MESG *md)
{
    FLT		*f;
    FLT		*fp;
    char	*file;
    char	id[15];
#ifdef LP_USE_PAPI_ATTR
    struct stat	tmpBuf;
    char	attrFile[BUFSIZ];
#endif
    
    for (f = Fault_List; f && f->next; f = f->next)
	if (f->next->ident == md)
	{
	    fp = f->next;
	    f->next = f->next->next;

	    switch (fp->type)
	    {
		case FLT_FILES:
		/* remove files created with alloc_files */

		while(fp->i1--)
		{
		    (void) snprintf(id, sizeof (id), "%s-%d", fp->s1, fp->i1);
		    file = makepath(Lp_Temp, id, (char *)0);
		    (void) Unlink(file);
		    Free(file);
		}

#ifdef LP_USE_PAPI_ATTR
		/*
		 * check if the PAPI attribute file exists, if it does delete it
		 */
		(void) snprintf(attrFile, sizeof (attrFile),
				"%s-%s", fp->s1, LP_PAPIATTRNAME);
		file = makepath(Lp_Temp, attrFile, (char *)0);
		if ((file != NULL) && (stat(file, &tmpBuf) == 0))
		{
			(void) Unlink(file);
		}
		Free(file);
#endif
		break;
		

		case FLT_CHANGE:
		/* clear RS_CHANGE bit, write request file, and schedule */
		fp->r1->request->outcome &= ~RS_CHANGING;
		putrequest(fp->r1->req_file, fp->r1->request);
		if (NEEDS_FILTERING(fp->r1))
		    schedule(/* LP_FILTER */ EV_SLOWF, fp->r1);
		else
		    schedule(/* LP_PRINTER */ EV_INTERF, fp->r1->printer);
		break;
	    }
	    free_flt(fp);
	}
}

static void
free_flt(FLT *f)
{
    if (f->s1)
	Free(f->s1);
    Free((char *)f);
}
