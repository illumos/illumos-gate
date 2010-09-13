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



/* kadmin_ct.c - automatically generated from kadmin_ct.ct */
/* Above no longer appears to be true */

/*
 * I18n hack. We sill define gettext(s) to be s here. That way the info_strings
 * will be extracted to the .po file.
 */

#define	gettext(s) s

#include <ss/ss.h>

#ifndef __STDC__
#define const
#endif

static char const * const ssu00001[] = {
"add_principal",
    "addprinc",
    "ank",
    (char const *)0
};
extern void kadmin_addprinc __SS_PROTO;
static char const * const ssu00002[] = {
"delete_principal",
    "delprinc",
    (char const *)0
};
extern void kadmin_delprinc __SS_PROTO;
static char const * const ssu00003[] = {
"modify_principal",
    "modprinc",
    (char const *)0
};
extern void kadmin_modprinc __SS_PROTO;
static char const * const ssu00004[] = {
"change_password",
    "cpw",
    (char const *)0
};
extern void kadmin_cpw __SS_PROTO;
static char const * const ssu00005[] = {
"get_principal",
    "getprinc",
    (char const *)0
};
extern void kadmin_getprinc __SS_PROTO;
static char const * const ssu00006[] = {
"list_principals",
    "listprincs",
    "get_principals",
    "getprincs",
    (char const *)0
};
extern void kadmin_getprincs __SS_PROTO;
static char const * const ssu00007[] = {
"add_policy",
    "addpol",
    (char const *)0
};
extern void kadmin_addpol __SS_PROTO;
static char const * const ssu00008[] = {
"modify_policy",
    "modpol",
    (char const *)0
};
extern void kadmin_modpol __SS_PROTO;
static char const * const ssu00009[] = {
"delete_policy",
    "delpol",
    (char const *)0
};
extern void kadmin_delpol __SS_PROTO;
static char const * const ssu00010[] = {
"get_policy",
    "getpol",
    (char const *)0
};
extern void kadmin_getpol __SS_PROTO;
static char const * const ssu00011[] = {
"list_policies",
    "listpols",
    "get_policies",
    "getpols",
    (char const *)0
};
extern void kadmin_getpols __SS_PROTO;
static char const * const ssu00012[] = {
"get_privs",
    "getprivs",
    (char const *)0
};
extern void kadmin_getprivs __SS_PROTO;
static char const * const ssu00013[] = {
"ktadd",
    "xst",
    (char const *)0
};
extern void kadmin_keytab_add __SS_PROTO;
static char const * const ssu00014[] = {
"ktremove",
    "ktrem",
    (char const *)0
};
extern void kadmin_keytab_remove __SS_PROTO;

static char const * const ssu00015[] = {
"lock",
    (char const *)0
};
extern void kadmin_lock __SS_PROTO;
static char const * const ssu00016[] = {
"unlock",
    (char const *)0
};
extern void kadmin_unlock __SS_PROTO;

static char const * const ssu00017[] = {
"list_requests",
    "lr",
    "?",
    (char const *)0
};

extern void ss_list_requests __SS_PROTO;
static char const * const ssu00018[] = {
"quit",
    "exit",
    "q",
    (char const *)0
};
extern void ss_quit __SS_PROTO;
static ss_request_entry ssu00019[] = {
    { ssu00001,
      kadmin_addprinc,
      gettext("Add principal"),
      0 },
    { ssu00002,
      kadmin_delprinc,
      gettext("Delete principal"),
      0 },
    { ssu00003,
      kadmin_modprinc,
      gettext("Modify principal"),
      0 },
    { ssu00004,
      kadmin_cpw,
      gettext("Change password"),
      0 },
    { ssu00005,
      kadmin_getprinc,
      gettext("Get principal"),
      0 },
    { ssu00006,
      kadmin_getprincs,
      gettext("List principals"),
      0 },
    { ssu00007,
      kadmin_addpol,
      gettext("Add policy"),
      0 },
    { ssu00008,
      kadmin_modpol,
      gettext("Modify policy"),
      0 },
    { ssu00009,
      kadmin_delpol,
      gettext("Delete policy"),
      0 },
    { ssu00010,
      kadmin_getpol,
      gettext("Get policy"),
      0 },
    { ssu00011,
      kadmin_getpols,
      gettext("List policies"),
      0 },
    { ssu00012,
      kadmin_getprivs,
      gettext("Get privileges"),
      0 },
    { ssu00013,
      kadmin_keytab_add,
      gettext("Add entry(s) to a keytab"),
      0 },
    { ssu00014,
      kadmin_keytab_remove,
      gettext("Remove entry(s) from a keytab"),
      0 },
    { ssu00015,
      kadmin_lock,
      gettext("Lock database exclusively (use with extreme caution!)"),
      0 },
    { ssu00016,
      kadmin_unlock,
      gettext("Release exclusive database lock"),
      0 },
    { ssu00017,
      ss_list_requests,
      gettext("List available requests."),
      0 },
    { ssu00018,
      ss_quit,
      gettext("Exit program."),
      0 },
    { 0, 0, 0, 0 }
};

ss_request_table kadmin_cmds = { 2, ssu00019 };

#undef gettext
