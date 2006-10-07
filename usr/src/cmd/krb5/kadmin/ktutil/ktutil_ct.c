/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 *	Openvision retains the copyright to derivative works of
 *	this source code.  Do *NOT* create a derivative of this
 *	source code before consulting with your legal department.
 *	Do *NOT* integrate *ANY* of this source code into another
 *	product before consulting with your legal department.
 *
 *	For further information, read the top-level Openvision
 *	copyright which is contained in the top-level MIT Kerberos
 *	copyright.
 *
 * WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING
 *
 */


/* ktutil_ct.c - automatically generated from ktutil_ct.ct */
/* Above no longer appears to be true */

#include <libintl.h>
#include <ss/ss.h>
#include "k5-int.h"

/*
 * I18n hack. We sill define gettext(s) to be s here. That way the info_strings
 * will be extracted to the .po file.
 */

#define	gettext(s) s

#ifndef __STDC__
#define const
#endif

static char const * const ssu00001[] = {
"clear_list",
    "clear",
    (char const *)0
};
extern void ktutil_clear_list __SS_PROTO;
static char const * const ssu00002[] = {
"read_kt",
    "rkt",
    (char const *)0
};
extern void ktutil_read_v5 __SS_PROTO;
static char const * const ssu00003[] = {
"read_st",
    "rst",
    (char const *)0
};
extern void ktutil_read_v4 __SS_PROTO;
static char const * const ssu00004[] = {
"write_kt",
    "wkt",
    (char const *)0
};
extern void ktutil_write_v5 __SS_PROTO;
static char const * const ssu00005[] = {
"write_st",
    "wst",
    (char const *)0
};
extern void ktutil_write_v4 __SS_PROTO;
static char const * const ssu00006[] = {
"add_entry",
    "addent",
    (char const *)0
};
extern void ktutil_add_entry __SS_PROTO;
static char const * const ssu00007[] = {
"delete_entry",
    "delent",
    (char const *)0
};
extern void ktutil_delete_entry __SS_PROTO;
static char const * const ssu00008[] = {
"list",
    "l",
    (char const *)0
};
extern void ktutil_list __SS_PROTO;
static char const * const ssu00009[] = {
"list_requests",
    "lr",
    "?",
    (char const *)0
};
extern void ss_list_requests __SS_PROTO;
static char const * const ssu00010[] = {
"quit",
    "exit",
    "q",
    (char const *)0
};
extern void ss_quit __SS_PROTO;
static ss_request_entry ssu00011[] = {
    { ssu00001,
      ktutil_clear_list,
		gettext("Clear the current keylist."),
      0 },
    { ssu00002,
      ktutil_read_v5,
		gettext("Read a krb5 keytab into the current keylist."),
      0 },
    { ssu00003,
      ktutil_read_v4,
		gettext("Read a krb4 srvtab into the current keylist."),
      0 },
    { ssu00004,
      ktutil_write_v5,
		gettext("Write the current keylist to a krb5 keytab."),
      0 },
    { ssu00005,
      ktutil_write_v4,
		gettext("Write the current keylist to a krb4 srvtab."),
      0 },
    { ssu00006,
      ktutil_add_entry,
		gettext("Add an entry to the current keylist."),
      0 },
    { ssu00007,
      ktutil_delete_entry,
		gettext("Delete an entry from the current keylist."),
      0 },
    { ssu00008,
      ktutil_list,
		gettext("List the current keylist."),
      0 },
    { ssu00009,
      ss_list_requests,
		gettext("List available requests."),
      0 },
    { ssu00010,
      ss_quit,
		gettext("Exit program."),
      0 },
    { 0, 0, 0, 0 }
};

ss_request_table ktutil_cmds = { 2, ssu00011 };

#undef gettext

/*
 * This routine is responsible for localizing all the displayable
 * messages in the table.  This was necessary since ktutil will be
 * invoking library calls that need to be able to display the messages
 * in the correct text domain (which only ktutil knows).
 *
 * This function assumes that the US version of the messages are
 * pre-loaded in the table and will be used should gettext not be
 * successful.  This routine does NOT free the replaced strings as
 * its expected they may be in the heap (as above) and not malloc'ed.
 * If the caller malloc'ed the strings, they should retain pointers
 * and free them if not matching the contents of the table.
 */
krb5_error_code
ktutil_initialize_cmds_table(ss_request_table *ktutil_cmds)
{
	char *localized_text;
	ss_request_entry *ss_cmd;
	krb5_error_code retval = 0;

	if (ktutil_cmds) {
		for (ss_cmd = ktutil_cmds->requests;
		ss_cmd->info_string && *(ss_cmd->info_string) != '\0';
		++ss_cmd) {
			localized_text = gettext(ss_cmd->info_string);

			if ((strcmp(localized_text, ss_cmd->info_string))
				!= 0) {
				ss_cmd->info_string = strdup(localized_text);
			}
		}
	}
	else
		retval = EINVAL;

	return (retval);
}
