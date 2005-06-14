#
# Copyright (c) 1998-1999 by Sun Microsystems, Inc.
# All rights reserved.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/gss_mechs/mech_krb5/spec/krb5_errtbl.spec
#

function	asn1_error_table
include		<error_message.h>
declaration	const char *asn1_error_table(long errno)
version		SUNWprivate_1.1
end

function	adb_error_table
include		<error_message.h>
declaration	const char *adb_error_table(long errno)
version		SUNWprivate_1.1
end

# spec2trace RFE
function        error_message
include         <com_err.h>
declaration     const char  * error_message (long code)
version         SUNWprivate_1.1
end

function	ggss_error_table
include		<error_message.h>
declaration	const char *ggss_error_table (long errno)
version		SUNWprivate_1.1
end

function	imp_error_table
include		<error_message.h>
declaration	const char *imp_error_table (long errno)
version		SUNWprivate_1.1
end

function	k5g_error_table
include		<error_message.h>
declaration	const char *k5g_error_table (long errno)
version		SUNWprivate_1.1
end

function	kadm_error_table
include		<error_message.h>
declaration	const char * kadm_error_table (long errno)
version		SUNWprivate_1.1
end

function	kdb5_error_table
include		<error_message.h>
declaration	const char * kdb5_error_table (long errno)
version		SUNWprivate_1.1
end

function	kdc5_error_table
include		<error_message.h>
declaration	const char * kdc5_error_table (long errno)
version		SUNWprivate_1.1
end

function	krb5_error_table
include		<error_message.h>
declaration	const char * krb5_error_table (long errno)
version		SUNWprivate_1.1
end

function	kpws_error_table
include		<error_message.h>
declaration	const char * kpws_error_table (long errno)
version		SUNWprivate_1.1
end

function	kv5m_error_table
include		<error_message.h>
declaration	const char *kv5m_error_table (long errorno)
version		SUNWprivate_1.1
end

function	ovk_error_table
include		<error_message.h>
declaration	const char *ovk_error_table (long errorno)
version		SUNWprivate_1.1
end

function	ovku_error_table
include		<error_message.h>
declaration	const char *ovku_error_table (long errorno)
version		SUNWprivate_1.1
end

function	prof_error_table
include		<error_message.h>
declaration	const char *prof_error_table (long errorno)
version		SUNWprivate_1.1
end

function	pty_error_table
include		<error_message.h>
declaration	const char *pty_error_table (long errorno)
version		SUNWprivate_1.1
end

function	ss_error_table
include		<error_message.h>
declaration	const char *ss_error_table (long errorno)
version		SUNWprivate_1.1
end
