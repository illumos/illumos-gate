%{
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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016, Chris Fraire <cfraire@me.com>.
 */

#include <string.h>
#include <libintl.h>
#include <sys/types.h>
#include "nwamcfg.h"
#include "nwamcfg_grammar.tab.h"

int lex_lineno = 1;	/* line number for error reporting */
static int state = INITIAL;
extern boolean_t cmd_file_mode;

extern void yyerror(char *s);
char *safe_strdup(char *s);
%}

%a 7000
%p 5000
%e 2000
%n 800
%o 12000

%{
/*
 * The state below are for tokens.
 */
%}
%s TSTATE
%%

<INITIAL>"#"[^\n]*	{ }

<INITIAL>cancel {
			BEGIN TSTATE;
			state = TSTATE;
			return CANCEL;
		}

<INITIAL>clear	{
			BEGIN TSTATE;
			state = TSTATE;
			return CLEAR;
		}

<INITIAL>commit	{
			BEGIN TSTATE;
			state = TSTATE;
			return COMMIT;
		}

<INITIAL>create	{
			BEGIN TSTATE;
			state = TSTATE;
			return CREATE;
		}


<INITIAL>destroy {
			BEGIN TSTATE;
			state = TSTATE;
			return DESTROY;
		}

<INITIAL>end	{
			BEGIN TSTATE;
			state = TSTATE;
			return END;
		}

<INITIAL>exit|quit {
			BEGIN TSTATE;
			state = TSTATE;
			return EXIT;
		}

<INITIAL>export	{
			BEGIN TSTATE;
			state = TSTATE;
			return EXPORT;
		}

<INITIAL>get	{
			BEGIN TSTATE;
			state = TSTATE;
			return GET;
		}

<INITIAL>"?"|help {
			BEGIN TSTATE;
			state = TSTATE;
			return HELP;
		}

<INITIAL>list	{
			BEGIN TSTATE;
			state = TSTATE;
			return LIST;
		}

<INITIAL>revert	{
			BEGIN TSTATE;
			state = TSTATE;
			return REVERT;
		}

<INITIAL>select	{
			BEGIN TSTATE;
			state = TSTATE;
			return SELECT;
		}

<INITIAL>set	{
			BEGIN TSTATE;
			state = TSTATE;
			return SET;
		}

<INITIAL>verify	{
			BEGIN TSTATE;
			state = TSTATE;
			return VERIFY;
		}

<INITIAL>walkprop {
			BEGIN TSTATE;
			state = TSTATE;
			return WALKPROP;
		}

<TSTATE>[Ll][Oo][Cc]		{ return LOC; }
<TSTATE>[Nn][Cc][Pp]		{ return NCP; }
<TSTATE>[Ee][Nn][Mm]		{ return ENM; }
<TSTATE>[Ww][Ll][Aa][Nn]	{ return WLAN; }

<TSTATE>[Nn][Cc][Uu]		{ return NCU; }

<TSTATE>[Pp][Hh][Yy][Ss]	{ return PHYS; }
<TSTATE>[Ii][Pp]		{ return IP; }

<TSTATE>unknown		{ return UNKNOWN; }
<TSTATE>activation-mode	{ return ACTIVATION_MODE; }
<TSTATE>conditions	{ return CONDITIONS; }
<TSTATE>enabled		{ return ENABLED; }

<TSTATE>type			{ return TYPE; }
<TSTATE>class			{ return CLASS; }
<TSTATE>parent			{ return PARENT; }
<TSTATE>priority-group		{ return PRIORITY_GROUP; }
<TSTATE>priority-mode		{ return PRIORITY_MODE; }
<TSTATE>link-mac-addr		{ return LINK_MACADDR; }
<TSTATE>link-autopush		{ return LINK_AUTOPUSH; }
<TSTATE>link-mtu		{ return LINK_MTU; }
<TSTATE>ip-version		{ return IP_VERSION; }
<TSTATE>ipv4-addrsrc		{ return IPV4_ADDRSRC; }
<TSTATE>ipv4-addr		{ return IPV4_ADDR; }
<TSTATE>ipv4-default-route	{ return IPV4_DEFAULT_ROUTE; }
<TSTATE>ipv6-addrsrc		{ return IPV6_ADDRSRC; }
<TSTATE>ipv6-addr		{ return IPV6_ADDR; }
<TSTATE>ipv6-default-route	{ return IPV6_DEFAULT_ROUTE; }
<TSTATE>ip-primary		{ return IP_PRIMARY; }
<TSTATE>ip-reqhost		{ return IP_REQHOST; }

<TSTATE>state		{ return ENM_STATE; }
<TSTATE>fmri		{ return ENM_FMRI; }
<TSTATE>start		{ return ENM_START; }
<TSTATE>stop		{ return ENM_STOP; }

<TSTATE>nameservices			{ return LOC_NAMESERVICES; }
<TSTATE>nameservices-config-file	{ return LOC_NAMESERVICES_CONFIG; }
<TSTATE>dns-nameservice-configsrc	{ return LOC_DNS_CONFIGSRC; }
<TSTATE>dns-nameservice-domain		{ return LOC_DNS_DOMAIN; }
<TSTATE>dns-nameservice-servers		{ return LOC_DNS_SERVERS; }
<TSTATE>dns-nameservice-search		{ return LOC_DNS_SEARCH; }
<TSTATE>nis-nameservice-configsrc	{ return LOC_NIS_CONFIGSRC; }
<TSTATE>nis-nameservice-servers		{ return LOC_NIS_SERVERS; }
<TSTATE>ldap-nameservice-configsrc	{ return LOC_LDAP_CONFIGSRC; }
<TSTATE>ldap-nameservice-servers	{ return LOC_LDAP_SERVERS; }
<TSTATE>default-domain			{ return LOC_DEFAULT_DOMAIN; }
<TSTATE>nfsv4-domain			{ return LOC_NFSV4_DOMAIN; }
<TSTATE>ipfilter-config-file		{ return LOC_IPF_CONFIG; }
<TSTATE>ipfilter-v6-config-file		{ return LOC_IPF_V6_CONFIG; }
<TSTATE>ipnat-config-file		{ return LOC_IPNAT_CONFIG; }
<TSTATE>ippool-config-file		{ return LOC_IPPOOL_CONFIG; }
<TSTATE>ike-config-file			{ return LOC_IKE_CONFIG; }
<TSTATE>ipsecpolicy-config-file		{ return LOC_IPSECPOL_CONFIG; }

<TSTATE>bssids		{ return WLAN_BSSIDS; }
<TSTATE>priority	{ return WLAN_PRIORITY; }
<TSTATE>keyname		{ return WLAN_KEYNAME; }
<TSTATE>keyslot		{ return WLAN_KEYSLOT; }
<TSTATE>security-mode	{ return WLAN_SECURITY_MODE; }

<TSTATE>=		{ return EQUAL; }

<TSTATE>\-[adftV] {	/* matches options */
			yylval.strval = safe_strdup(yytext);
			return OPTION; 
		}

<TSTATE>[^ \t\n\";=\[\]\(\)]+	{	/* matches non-quoted values */
			yylval.strval = safe_strdup(yytext);
			return TOKEN;
		}

<TSTATE>\"[^\"\n]*[\"\n] {	/* matches string with quotes */
			yylval.strval = safe_strdup(yytext);
			return TOKEN;
		}

<TSTATE>\".*\"\,\".*\" {	/* matches string list of the form "a","b",.. */
			yylval.strval = safe_strdup(yytext);
			return TOKEN;
		}

";"		{
			BEGIN INITIAL;
			return (yytext[0]);
		}

\n		{
			lex_lineno++;
			BEGIN INITIAL;
			return (yytext[0]);
		}

[ \t]		;	/* ignore white space */

.		{	/* matches all single otherwise unmatched characters */
			return (yytext[0]);
		}

%%

char *
safe_strdup(char *s)
{
	char *result;

	if ((result = strdup(s)) == NULL) {
		yyerror("Out of memory");
		exit(1);
	}
	return (result);
}

void
yyerror(char *s)
{
	/* feof(yyin) is not an error; anything else is, so we set saw_error */
	if (yytext[0] == '\0') {
		if (!feof(yyin)) {
			saw_error = B_TRUE;
			(void) fprintf(stderr, gettext("%s, token expected\n"),
			    s);
		}
		return;
	}

	saw_error = B_TRUE;
	if (cmd_file_mode) {
		(void) fprintf(stderr, gettext("%s on line %d at '%s'\n"), s,
		    lex_lineno, (yytext[0] == '\n') ? "\\n" : yytext);
	} else {
		(void) fprintf(stderr, gettext("%s at '%s'\n\n"), s,
		    (yytext[0] == '\n') ? "\\n" : yytext);
	}
	help_wrap();
}
