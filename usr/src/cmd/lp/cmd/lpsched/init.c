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


#include "lpsched.h"
#include <syslog.h>

CLSTATUS	**CStatus = NULL;		/* Status of same          */
PSTATUS		**PStatus = NULL;		/* Status of same          */
FSTATUS		**FStatus = NULL;		/* status of same	   */
PWSTATUS	**PWStatus = NULL;		/* Status of same          */ 
EXEC		**Exec_Table = NULL;		/* Running processes       */
EXEC		**Exec_Slow = NULL;		/*   Slow filters	   */
EXEC		**Exec_Notify = NULL;		/*   Notifications	   */
RSTATUS		*Request_List = NULL;		/* Queue of print requests */

int		ET_SlowSize	= 1,
		ET_NotifySize	= 1;

static void	init_printers(),
		init_classes(),
		init_forms(),
		init_pwheels(),
		init_exec();


static void	init_requests();

void
init_memory(void)
{
    init_exec();
    init_printers();
    init_classes();
    init_forms();
    init_pwheels();

    /*
     * Load the status after the basic structures have been loaded,
     * but before loading requests still in the queue. This is so
     * the requests can be compared against accurate status information
     * (except rejection status--accept the jobs anyway).
     */
    load_status();

    Loadfilters(Lp_A_Filters);

    init_requests();
}

static void
init_printers()
{
    PRINTER	*p;
    int i = 0;

    while((p = Getprinter(NAME_ALL)) != NULL || errno != ENOENT) {
	if ((!p) || (p->remote))	/* NULL or this is remote, ignore it */
		continue;

	(void) new_pstatus(p);
	syslog(LOG_DEBUG, "Loaded printer: %s", p->name);
    }
}

static void
init_classes()
{
    CLASS       *c;

    while((c = Getclass(NAME_ALL)) != NULL) {
	(void) new_cstatus(c);
        syslog(LOG_DEBUG, "Loaded class: %s", c->name);
    }
}

static void
init_forms()
{
    _FORM	*f;
    int		i = 0;

    while ((f = Getform(NAME_ALL)) != NULL) {
	(void) new_fstatus(f);
	syslog(LOG_DEBUG, "Loaded form: %s", f->name);
    }
}

static void
init_pwheels()
{
    PWHEEL	*p;
    int i = 0;
    
    while((p = Getpwheel(NAME_ALL)) != NULL || errno != ENOENT)
    {
	if (!p)			/* NULL, ignore it. */
	    continue;

	(void) new_pwstatus(p);
    	syslog(LOG_DEBUG, "Loaded print-wheel: %s", p->name);
    }
}

static void
init_requests(void)
{
    RSTATUS		**table = NULL;
    REQUEST		*r;
    SECURE		*s;
    char		*name;
    char		*sysdir;
    char		*sysname;
    char		*reqfile = NULL;
    long		addr = -1;
    long		sysaddr = -1;
    short		vr_ret;

    while((sysname = next_dir(Lp_Requests, &addr)) != NULL) {
    	RSTATUS		*rsp;

	sysdir = makepath(Lp_Requests, sysname, NULL);

	while((name = next_file(sysdir, &sysaddr)) != NULL) {
	    reqfile = makepath(sysname, name, NULL);	
	    Free(name);

	    if ((s = Getsecure(reqfile)) == NULL) {
		RSTATUS tmp;

		memset(&tmp, 0, sizeof (tmp));
		tmp.req_file = reqfile;	/* fix for 1103890 */
		rmfiles(&tmp, 0);
		free(tmp.req_file);
		continue;
	    }
	    syslog(LOG_DEBUG, "Loaded request: %s", reqfile);

	    if((r = Getrequest(reqfile)) == NULL) {
		RSTATUS tmp;

		memset(&tmp, 0, sizeof (tmp));
		tmp.req_file = reqfile;	/* fix for 1103890 */
		rmfiles(&tmp, 0);
		freesecure(s);
		free(tmp.req_file);
		continue;
	    }
	    syslog(LOG_DEBUG, "Loaded secure: %s", s->req_id);

	    rsp = new_rstatus(r, s);

	    r->outcome &= ~RS_ACTIVE;	/* it can't be! */
	    rsp->req_file = reqfile;

	    if ((r->outcome & (RS_CANCELLED|RS_FAILED)) &&
		!(r->outcome & RS_NOTIFY)) {
			rmfiles(rsp, 0);
			free_rstatus(rsp);
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
		char	*file = makereqerr(rsp);

		if (Access(file, F_OK) == -1) {
		    if (!(r->outcome & RS_CANCELLED)) {
			Free(file);
			rmfiles(rsp, 0);
			free_rstatus(rsp);
			continue;
		    }
		    notify(rsp, NULL, 0, 0, 0);
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

	    if ((vr_ret=validate_request(rsp, NULL, 1)) != MOK) {
		if (vr_ret == MNODEST || (rsp->printer == NULL)) {
			rmfiles(rsp, 0);
			free_rstatus(rsp);
			continue;
		}
		cancel(rsp, 1);
	    }

	    list_append((void ***)&table, (void *)rsp);
	}
	Free(sysdir);
	Free(sysname);
	sysaddr = -1;
    }
   
    if (table != NULL) {
	unsigned long i;

	for (i = 0; table[i] != NULL; i++);

	qsort((void *)table, i, sizeof(RSTATUS *),
			(int (*)(const void * , const void *))rsort);

	for (i = 0; table[i] != NULL; i++) {
		table[i]->next = table[i + 1];
		if (table[i + 1] != NULL)
			table[i + 1]->prev = table[i];
	}

	Request_List = *table;
	Free(table);
    }
}

static void
init_exec()
{
    EXEC	*ep;
    int		i;

    for (i = 0; i < ET_SlowSize; i++) {
	ep = new_exec(EX_SLOWF, NULL);
	list_append((void ***)&Exec_Slow, (void *)ep);
    }

    for (i = 0; i < ET_NotifySize; i++) {
	ep = new_exec(EX_NOTIFY, NULL);
	list_append((void ***)&Exec_Notify, (void *)ep);
    }
}
