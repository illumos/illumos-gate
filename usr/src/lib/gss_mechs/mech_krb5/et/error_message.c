/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * util/et/error_message.c
 *
 * Copyright 1987 by the Student Information Processing Board
 * of the Massachusetts Institute of Technology
 *
 * For copyright info, see "mit-sipb-copyright.h".
 */

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <string.h>
#include <libintl.h>
#include "com_err.h"
#include "mit-sipb-copyright.h"
#include "internal.h"
#include "error_message.h"

static char buffer[25];

struct et_list * _et_list = (struct et_list *) NULL;

const char * KRB5_CALLCONV error_message (code)
long code;
{
    int offset;
    long l_offset;
    long table_num;
    int started = 0;
    char *cp;

    l_offset = code & ((1<<ERRCODE_RANGE)-1);
    offset = (int) l_offset;
    table_num = code - l_offset;
    if (!table_num) {
#ifdef HAVE_STRERROR
	cp = strerror(offset);
	if (cp)
	    return cp;
	goto oops;
#else
#ifdef HAVE_SYS_ERRLIST
        if (offset < sys_nerr)
	    return(sys_errlist[offset]);
	else
	    goto oops;
#else
		goto oops;
#endif /* HAVE_SYS_ERRLIST */
#endif /* HAVE_STRERROR */
    }
	switch (table_num) {
	case -2045022976L:
		return(ggss_error_table(offset));
	case -1783126272L:
		return(kadm_error_table(offset));
	case -1780008448L:
		return(kdb5_error_table(offset));
	case -1779992064L:
		return(kdc5_error_table(offset));
	case -1767084800L:
		return(kpws_error_table(offset));
	case -1765328384L:
		return(krb5_error_table(offset));
	case -1760647424L:
		return(kv5m_error_table(offset));
	case -1492553984L:
		return(ovku_error_table(offset));
	case -1429577728L:
		return(prof_error_table(offset));
	case 748800L:
		return(ss_error_table(offset));
	case 28810240L:
		return(adb_error_table(offset));
	case 1859794432L:
		return(asn1_error_table(offset));
	case 37349888L:
		return(imp_error_table(offset));
	case 39756032L:
		return(k5g_error_table(offset));
	case 43787520L:
		return(ovk_error_table(offset));
	case 44806912L:
		return(pty_error_table(offset));
	}
oops:
    strlcpy (buffer, dgettext(TEXT_DOMAIN, "Unknown code "), sizeof (buffer));
    for (cp = buffer; *cp; cp++)
	;
    if (offset >= 100) {
	*cp++ = '0' + offset / 100;
	offset %= 100;
	started++;
    }
    if (started || offset >= 10) {
	*cp++ = '0' + offset / 10;
	offset %= 10;
    }
    *cp++ = '0' + offset;
    *cp = '\0';
    return(buffer);
}

int com_err_finish_init()
{
	/*
	 * SUNW14resync
	 * Since the original SEAM (Solaris Kerberos) error_message()
	 * has deviated substantially from MIT let's disable
	 * com_err_initialize for now and revisit if necessary.
	 */
	/* return CALL_INIT_FUNCTION(com_err_initialize); */
	return 0;
}
