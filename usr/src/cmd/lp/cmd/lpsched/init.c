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
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.10.1.8	*/

#include "lpsched.h"
#include <syslog.h>

CSTATUS		*CStatus;		/* Status of same          */
EXEC		*Exec_Table;		/* Running processes       */
EXEC		*Exec_Slow;		/*   Slow filters	   */
EXEC		*Exec_Notify;		/*   Notifications	   */
FSTATUS		*FStatus;		/* status of same	   */
PSTATUS		*PStatus;		/* Status of same          */
PWSTATUS	*PWStatus;		/* Status of same          */ 
RSTATUS		*Request_List;		/* Queue of print requests */

int		CT_Size,
		ET_Size,
		ET_SlowSize	= 1,
		ET_NotifySize	= 1,
		FT_Size,
		PT_Size,
		PWT_Size;

static ALERT	*Alert_Table;		/* Printer fault alerts    */
static ALERT	*FAlert_Table;		/* Form mount alerts       */
static ALERT	*PAlert_Table;		/* PrintWheel mount alerts */
static CLASS	*Class_Table;		/* Known classes           */
static _FORM	*Form_Table;		/* Known forms             */
static PRINTER	*Printer_Table;		/* Known printers          */
static PWHEEL	*PrintWheel_Table;	/* Known print wheels      */

/*
**
**	CLRMEM clears memory pointed to by <addr> over the range of
**	<addr>[<cnt> .. <size>].  <datum> is the size of an element of <addr>.
**
*/
# define	CLRMEM(addr, cnt, size, datum) \
                      (void) memset((char *)(addr + cnt), 0, \
		                    (int)((size - cnt ) * sizeof(datum)))

#define	ACLUSTERSIZE	10


static void	init_printers(),
		init_classes(),
		init_forms(),
		init_pwheels(),
		init_exec();


static RSTATUS	*init_requests();

void
init_memory(void)
{
    init_printers();
    init_classes();
    init_forms();
    init_pwheels();
    init_exec();

    /*
     * Load the status after the basic structures have been loaded,
     * but before loading requests still in the queue. This is so
     * the requests can be compared against accurate status information
     * (except rejection status--accept the jobs anyway).
     */
    load_status();

    Loadfilters(Lp_A_Filters);

    Request_List = init_requests();
}

static void
init_printers()
{
    PRINTER	*p;
    PRINTER	*pt_pointer;
    int		pt_allocation;
    int		at_allocation;
    int		PT_Count;
    int		i;
    char	**paperDenied;


    PT_Size = 10;
    PT_Count = 0;
    pt_allocation = PT_Size * sizeof(PRINTER);

    Printer_Table = (PRINTER *)Malloc(pt_allocation);

    CLRMEM(Printer_Table, PT_Count, PT_Size, PRINTER);
    
    pt_pointer = Printer_Table;
    
    while((p = Getprinter(NAME_ALL)) != NULL || errno != ENOENT) {
	if (!p)
	    continue;

	if (p->remote)	/* this is remote, ignore it */
		continue;

	syslog(LOG_DEBUG, "Loaded printer: %s\n", p->name);

	*pt_pointer = *p;
	pt_pointer++;

	if (++PT_Count < PT_Size)
	    continue;
	
	PT_Size += 10;
	pt_allocation = PT_Size * sizeof(PRINTER);

	Printer_Table = (PRINTER *)Realloc(Printer_Table, pt_allocation);

	CLRMEM(Printer_Table, PT_Count, PT_Size, PRINTER);

	pt_pointer = Printer_Table + PT_Count;
    }

    PT_Size = PT_Count + 40;

    pt_allocation = PT_Size * sizeof(PRINTER);

    Printer_Table = (PRINTER *)Realloc(Printer_Table, pt_allocation);

    CLRMEM(Printer_Table, PT_Count, PT_Size, PRINTER);

    at_allocation = PT_Size * sizeof(ALERT);

    Alert_Table = (ALERT *)Malloc(at_allocation);

    CLRMEM(Alert_Table, 0, PT_Size, ALERT);

    pt_allocation = PT_Size * sizeof(PSTATUS);
    
    PStatus = (PSTATUS *)Malloc(pt_allocation);

    CLRMEM(PStatus, 0, PT_Size, PSTATUS);

    for (i = 0; i < PT_Size; i++)
    {
	char	buf[15];
	PSTATUS	*psp;
	
	psp = PStatus + i;
	p = psp->printer = Printer_Table + i;
	psp->alert = Alert_Table + i;
	sprintf(buf, "A-%d", i);
	Alert_Table[i].msgfile = makepath(Lp_Temp, buf, (char *)0);
	(void) Unlink(Alert_Table[i].msgfile);
	if (i < PT_Count)
	{
	    load_userprinter_access (
		    p->name,
		    &(psp->users_allowed),
		    &(psp->users_denied)
	    );
	    load_formprinter_access (
		    p->name,
		    &(psp->forms_allowed),
		    &(psp->forms_denied)
	    );
		 load_paperprinter_access (
			 p->name,
			 &psp->paper_allowed,
			 &paperDenied
			 ); 
		 freelist(paperDenied);
	    load_sdn (&(psp->cpi), p->cpi);
	    load_sdn (&(psp->lpi), p->lpi);
	    load_sdn (&(psp->plen), p->plen);
	    load_sdn (&(psp->pwid), p->pwid);
	}
    }
}

static void
init_classes()
{
    CLASS	*p;
    CLASS	*ct_pointer;
    int		ct_allocation;
    int		CT_Count;
    int		i;


    CT_Size = 10;
    CT_Count = 0;
    ct_allocation = CT_Size * sizeof(CLASS);

    Class_Table = (CLASS *)Malloc(ct_allocation);

    CLRMEM(Class_Table, CT_Count, CT_Size, CLASS);
    
    ct_pointer = Class_Table;

    while((p = Getclass(NAME_ALL)) != NULL || errno != ENOENT)
    {
	if (!p)
	    continue;

	*ct_pointer = *p;
	ct_pointer++;

	if (++CT_Count < CT_Size)
	    continue;
	
	CT_Size += 10;
	ct_allocation = CT_Size * sizeof(CLASS);

	Class_Table = (CLASS *)Realloc(Class_Table, ct_allocation);

	CLRMEM(Class_Table, CT_Count, CT_Size, CLASS);

	ct_pointer = Class_Table + CT_Count;

    }

    CT_Size = CT_Count + 40;

    ct_allocation = CT_Size * sizeof(CLASS);

    Class_Table = (CLASS *)Realloc(Class_Table, ct_allocation);

    CLRMEM(Class_Table, CT_Count, CT_Size, CLASS);

    ct_allocation = CT_Size * sizeof(CSTATUS);
    
    CStatus = (CSTATUS *)Malloc(ct_allocation);

    CLRMEM(CStatus, 0, CT_Size, CSTATUS);

    for (i = 0; i < CT_Size; i++)
	CStatus[i].class = Class_Table + i;
}

static void
init_forms()
{
    _FORM	*ft_pointer,
		*f;
    int		at_allocation;
    int		ft_allocation;
    int		FT_Count;
    int		i;


    FT_Size = 10;
    FT_Count = 0;
    ft_allocation = FT_Size * sizeof(_FORM);

    Form_Table = (_FORM *)Malloc(ft_allocation);

    CLRMEM(Form_Table, FT_Count, FT_Size, _FORM);
    
    ft_pointer = Form_Table;

    ft_pointer->plen.val = 0.0;
    ft_pointer->plen.sc = 'i';
    ft_pointer->pwid.val = 0.0;
    ft_pointer->pwid.sc = 'i';
    ft_pointer->lpi.val = 0.0;
    ft_pointer->lpi.sc = 'i';
    ft_pointer->cpi.val = 0.0;
    ft_pointer->cpi.sc = 'i';
    ft_pointer->np = 0;
    ft_pointer->chset = NULL;
    ft_pointer->mandatory = 0;
    ft_pointer->rcolor = NULL;
    ft_pointer->comment = NULL;
    ft_pointer->conttype = NULL;
    ft_pointer->name = NULL;
    ft_pointer->alert.shcmd = NULL;
    ft_pointer->alert.Q = 0;
    ft_pointer->alert.W = 0;
    ft_pointer->paper = NULL;
    ft_pointer->isDefault = 0;

    ft_pointer++;
    FT_Count++;

    while ((f = Getform(NAME_ALL)) != NULL) {
	*(ft_pointer++) = *f;

	if (++FT_Count < FT_Size)
	    continue;
	
	FT_Size += 10;
	ft_allocation = FT_Size * sizeof(_FORM);

	Form_Table = (_FORM *)Realloc(Form_Table, ft_allocation);

	CLRMEM(Form_Table, FT_Count, FT_Size, _FORM);

	ft_pointer = Form_Table + FT_Count;
    }

    FT_Size = FT_Count + 40;

    ft_allocation = FT_Size * sizeof(_FORM);

    Form_Table = (_FORM *)Realloc(Form_Table, ft_allocation);

    CLRMEM(Form_Table, FT_Count, FT_Size, _FORM);

    at_allocation = FT_Size * sizeof(ALERT);

    FAlert_Table = (ALERT *)Malloc(at_allocation);

    CLRMEM(FAlert_Table, 0, FT_Size, ALERT);

    ft_allocation = FT_Size * sizeof(FSTATUS);
    
    FStatus = (FSTATUS *)Malloc(ft_allocation);

    CLRMEM(FStatus, 0, FT_Size, FSTATUS);

    for (i = 0; i < FT_Size; i++) {
	char	buf[15];
	
	FStatus[i].form = Form_Table + i;
	FStatus[i].alert = FAlert_Table + i;
	FStatus[i].trigger = Form_Table[i].alert.Q;
	sprintf(buf, "F-%d", i);
	FAlert_Table[i].msgfile = makepath(Lp_Temp, buf, (char *)0);
	(void) Unlink(FAlert_Table[i].msgfile);

	if (i < FT_Count) {
	    load_userform_access (
		    Form_Table[i].name,
		    &(FStatus[i].users_allowed),
		    &(FStatus[i].users_denied)
	    );
	    load_sdn (&(FStatus[i].cpi), Form_Table[i].cpi);
	    load_sdn (&(FStatus[i].lpi), Form_Table[i].lpi);
	    load_sdn (&(FStatus[i].plen), Form_Table[i].plen);
	    load_sdn (&(FStatus[i].pwid), Form_Table[i].pwid);
	}
    }
    FStatus[0].users_denied = Calloc(2,sizeof(char *));
    /* for BSD_FORM, make sure it denies no one */
}

static void
init_pwheels()
{
    PWHEEL	*pwt_pointer;
    PWHEEL	*p;
    int		at_allocation;
    int		pwt_allocation;
    int		PWT_Count;
    int		i;
    

    PWT_Count = 0;
    PWT_Size = 10;
    pwt_allocation = PWT_Size * sizeof(PWHEEL);

    PrintWheel_Table = (PWHEEL *)Malloc(pwt_allocation);

    CLRMEM(PrintWheel_Table, PWT_Count, PWT_Size, PWHEEL);
    
    pwt_pointer = PrintWheel_Table;

    while((p = Getpwheel(NAME_ALL)) != NULL || errno != ENOENT)
    {
	if (!p)
	    continue;

	*pwt_pointer = *p;
	pwt_pointer++;

	if (++PWT_Count < PWT_Size)
	    continue;
	
	PWT_Size += 10;
	pwt_allocation = PWT_Size * sizeof(PWHEEL);

	PrintWheel_Table = (PWHEEL *)Realloc(PrintWheel_Table, pwt_allocation);

	CLRMEM(PrintWheel_Table, PWT_Count, PWT_Size, PWHEEL);

	pwt_pointer = &PrintWheel_Table[PWT_Count];

    }

    PWT_Size = PWT_Count + 40;

    pwt_allocation = PWT_Size * sizeof(PWHEEL);

    PrintWheel_Table = (PWHEEL *)Realloc(PrintWheel_Table, pwt_allocation);

    CLRMEM(PrintWheel_Table, PWT_Count, PWT_Size, PWHEEL);

    at_allocation = PWT_Size * sizeof(ALERT);

    PAlert_Table = (ALERT *)Malloc(at_allocation);

    CLRMEM(PAlert_Table, 0, PWT_Size, ALERT);

    pwt_allocation = PWT_Size * sizeof(PWSTATUS);
    
    PWStatus = (PWSTATUS *)Malloc(pwt_allocation);

    CLRMEM(PWStatus, 0, PWT_Size, PWSTATUS);

    for (i = 0; i < PWT_Size; i++)
    {
	char	buf[15];
	
	PWStatus[i].pwheel = PrintWheel_Table + i;
	PWStatus[i].trigger = PrintWheel_Table[i].alert.Q;
	PWStatus[i].alert = PAlert_Table + i;
	sprintf(buf, "P-%d", i);
	PAlert_Table[i].msgfile = makepath(Lp_Temp, buf, (char *)0);
	(void) Unlink(PAlert_Table[i].msgfile);
    }
}

static RSTATUS *
init_requests(void)
{
    REQUEST		*r;
    RSTATUS		**table;
    RSTATUS		*rp = NULL;
    SECURE		*s;
    char		*name;
    char		*sysdir;
    char		*sysname;
    char		*reqfile = NULL;
    int			count;
    int			i;
    long		addr = -1;
    long		sysaddr = -1;
    unsigned long	size;
    short		vr_ret;

    size = 20;
    count = 0;
    

    table = (RSTATUS **)Malloc(size * sizeof(RSTATUS *));
    
    while((sysname = next_dir(Lp_Requests, &addr)) != NULL) {
	
	sysdir = makepath(Lp_Requests, sysname, NULL);

	while((name = next_file(sysdir, &sysaddr)) != NULL) {
	    table[count] = allocr();

	    reqfile = makepath(sysname, name, NULL);	
	    Free(name);
	    syslog(LOG_DEBUG, "Loaded request: %s\n", reqfile);

	    if ((s = Getsecure(reqfile)) == NULL) {
		table[count]->req_file = reqfile;	/* fix for 1103890 */
		reqfile = NULL;				/* fix for 1103890 */
		rmfiles(table[count], 0);
		freerstatus(table[count]);
		continue;
	    }
	    *(table[count]->secure) = *s;
	    table[count]->secure->req_id = Strdup(s->req_id);
	    table[count]->secure->user = Strdup(s->user);
	    table[count]->secure->system = Strdup(s->system);
	    freesecure(s);

	    if((r = Getrequest(reqfile)) == NULL) {
		rmfiles(table[count], 0);
		freerstatus(table[count]);
		Free(reqfile);
		continue;
	    }
	    r->outcome &= ~RS_ACTIVE;	/* it can't be! */
	    *(table[count]->request) = *r;

	    table[count]->req_file = reqfile;
	    reqfile = NULL;

	    if ((r->outcome & (RS_CANCELLED|RS_FAILED)) &&
		!(r->outcome & RS_NOTIFY))
	    {
		rmfiles(table[count], 0);
		freerstatus(table[count]);
		continue;
	    }

	    /*
	     * So far, the only way RS_NOTIFY can be set without there
	     * being a notification file containing the message to the
	     * user, is if the request was cancelled. This is because
	     * cancelling a request does not cause the creation of the
	     * message if the request is currently printing or filtering.
	     * (The message is created after the child process dies.)
	     * Thus, we know what to say.
	     *
	     * If this behaviour changes, we may have to find another way
	     * of determining what to say in the message.
	     */
	    if (r->outcome & RS_NOTIFY) {
		char	*file = makereqerr(table[count]);

		if (Access(file, F_OK) == -1) {
		    if (!(r->outcome & RS_CANCELLED)) {
			Free(file);
			rmfiles(table[count], 0);
			freerstatus(table[count]);
			continue;
		    }
		    notify(table[count], NULL, 0, 0, 0);
		}
		Free(file);
	    }

	    /* fix for bugid 1103709. if validate_request returns
	     * MNODEST, then the printer for the request doesn't exist
	     * anymore! E.g. lpadmin -x was issued, and the request
	     * hasn't been cleaned up. In this case, the "printer"
	     * element of table[] will be NULL, and cancel will
	     * core dump! So we clean this up here.
	     */

	    /*
	     * Well actually this happens with MDENYDEST too. The real problem
	     * is if the printer is NULL, so test for it
	     */

	    if ((vr_ret=validate_request(table[count], NULL, 1)) != MOK) {
		if (vr_ret == MNODEST || (table[count]->printer == NULL)) {
			rmfiles(table[count], 0);
			freerstatus(table[count]);
			continue;
		}
		cancel(table[count], 1);
	    }


	    if (++count < size)
		continue;

	    size += 20;

	    table = (RSTATUS **)Realloc((char *)table, size * sizeof(RSTATUS *));
	}
	Free(sysdir);
	Free(sysname);
	sysaddr = -1;
    }
    
    if (!count)
	Free ((char *)table);
    else
	if ((size = count) > 0) {
	    table = (RSTATUS **)Realloc((char *)table,
					size * sizeof(RSTATUS *));

	    qsort((void *)table, size, sizeof(RSTATUS *),
			(int (*)(const void * , const void *))rsort);

	    for (i = 0; i < size - 1; i++) {
		table[i]->next = table[i + 1];
		table[i + 1]->prev = table[i];
	    }

	    table[0]->prev = 0;
	    table[size - 1]->next = 0;

	    rp = *table;
	    Free(table);

	}

    return(rp);
}

static void
init_exec()
{
    EXEC	*et_pointer;
    int		et_allocation;
    int		i;

    ET_Size	= ET_SlowSize
		+ ET_NotifySize
    		+ PT_Size * 3	/* 1 each for interface, alert, fault msg */
		+ PWT_Size
		+ FT_Size;

    et_allocation = ET_Size * sizeof(EXEC);

    Exec_Table = (EXEC *)Malloc(et_allocation);
    
    CLRMEM(Exec_Table, 0, ET_Size, EXEC);

    et_pointer = Exec_Table;

    Exec_Slow = et_pointer;
    for (i = 0; i < ET_SlowSize; i++)
	(et_pointer++)->type = EX_SLOWF;

    Exec_Notify = et_pointer;
    for (i = 0; i < ET_NotifySize; i++)
	(et_pointer++)->type = EX_NOTIFY;

    for (i = 0; i < PT_Size; i++) {
	PStatus[i].exec = et_pointer;
	et_pointer->type = EX_INTERF;
	et_pointer->ex.printer = PStatus + i;
	et_pointer++;

	PStatus[i].alert->exec = et_pointer;
	et_pointer->type = EX_ALERT;
	et_pointer->ex.printer = PStatus + i;
	et_pointer++;

	PStatus[i].fault_exec = et_pointer;
	et_pointer->type = EX_FAULT_MESSAGE;
	et_pointer->ex.printer = PStatus + i;
	et_pointer++;
    }

    for (i = 0; i < PWT_Size; i++) {
	PWStatus[i].alert->exec = et_pointer;
	et_pointer->type = EX_PALERT;
	et_pointer->ex.pwheel = PWStatus + i;
	et_pointer++;
    }

    for (i = 0; i < FT_Size; i++) {
	FStatus[i].alert->exec = et_pointer;
	et_pointer->type = EX_FALERT;
	et_pointer->ex.form = FStatus + i;
	et_pointer++;
    }
    
}
