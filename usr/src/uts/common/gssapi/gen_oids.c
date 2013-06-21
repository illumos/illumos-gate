/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 1993 by OpenVision Technologies, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software
 * and its documentation for any purpose is hereby granted without fee,
 * provided that the above copyright notice appears in all copies and
 * that both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of OpenVision not be used
 * in advertising or publicity pertaining to distribution of the software
 * without specific, written prior permission. OpenVision makes no
 * representations about the suitability of this software for any
 * purpose.  It is provided "as is" without express or implied warranty.
 *
 * OPENVISION DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
 * EVENT SHALL OPENVISION BE LIABLE FOR ANY SPECIAL, INDIRECT OR
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
 * USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <mechglueP.h>

/*
 * See krb5/gssapi_krb5.c for a description of the algorithm for
 * encoding an object identifier.
 */

/*
 * The OID of user_name is(gss_nt_user_name, GSS_C_NT_USER_NAME):
 * 	iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 * 	generic(1) user_name(1) = 1.2.840.113554.1.2.1.1
 * machine_uid_name(gss_nt_machine_uid_name, GSS_C_NT_MACHINE_UID_NAME):
 * 	iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 * 	generic(1) machine_uid_name(2) = 1.2.840.113554.1.2.1.2
 * string_uid_name(gss_nt_string_uid_name,GSS_C_NT_STRING_UID_NAME):
 * 	iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 * 	generic(1) string_uid_name(3) = 1.2.840.113554.1.2.1.3
 * service_name(gss_nt_service_name):
 * 	iso(1) member-body(2) US(840) mit(113554) infosys(1) gssapi(2)
 * 	generic(1) service_name(4) = 1.2.840.113554.1.2.1.4
 * hostbased_service_name(GSS_C_NT_HOSTBASED_SERVICE)
 * 	iso(1) org(3) dod(6) 1(internet) 5(security) 6(nametypes)
 *   	2(gss-host-based-services) == 1.3.6.1.5.6.2
 * anonymous_name(GSS_C_NT_ANONYMOUS)
 * 	iso(1) org(3) dod(6) 1(internet) 5(security) 6(nametypes)
 *   	3(anonymous) = 1.3.6.1.5.6.3
 * export_name(GSS_C_NT_EXPORT)
 * 	iso(1) org(3) dod(6) 1(internet) 5(security) 6(nametypes)
 *   	4(export) = 1.3.6.1.5.6.4
 */

static const gss_OID_desc oids[] = {
	/* GSS_C_NT_USER_NAME */
	{10, "\052\206\110\206\367\022\001\002\001\001"},
	/* GSS_C_NT_MACHINE_UID_NAME */
	{10, "\052\206\110\206\367\022\001\002\001\002"},
	/* GSS_C_NT_STRING_UID_NAME */
	{10, "\052\206\110\206\367\022\001\002\001\003"},
	/* gss_nt_service_name */
	{10, "\052\206\110\206\367\022\001\002\001\004"},

	/* GSS_C_NT_HOSTBASED_SERVICE */
	{6, "\053\006\001\005\006\002"},
	/* GSS_C_NT_ANONYMOUS */
	{6, "\053\006\001\005\006\003"},
	/* GSS_C_NT_EXPORT_NAME */
	{6, "\053\006\001\005\006\004"},

	/* GSS_C_INQ_SSPI_SESSION_KEY */
	{11, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x05\x05"},
};

const gss_OID_desc * const gss_nt_user_name = oids+0;
const gss_OID_desc * const gss_nt_machine_uid_name = oids+1;
const gss_OID_desc * const gss_nt_string_uid_name = oids+2;
const gss_OID_desc * const gss_nt_service_name = oids+3;
/* XXXXX These are needed for Kerberos */
const gss_OID_desc * const gss_nt_service_name_v2 = oids+4;
const gss_OID_desc * const gss_nt_exported_name = oids+6;


/*
 * These are added to reflect definitions in the
 * gss c-bindings spec.
 */

/*
 * The use of the following defines are preferred over the above defines.
 * This is because the following are the only ones defined
 * in GSS-API Specs.
 */
const gss_OID GSS_C_NT_USER_NAME = (gss_OID)oids+0;
const gss_OID GSS_C_NT_MACHINE_UID_NAME = (gss_OID)oids+1;
const gss_OID GSS_C_NT_STRING_UID_NAME = (gss_OID)oids+2;
const gss_OID GSS_C_NT_HOSTBASED_SERVICE = (gss_OID)oids+4;
const gss_OID GSS_C_NT_ANONYMOUS = (gss_OID)oids+5;
const gss_OID GSS_C_NT_EXPORT_NAME = (gss_OID)oids+6;
const gss_OID GSS_C_INQ_SSPI_SESSION_KEY = (gss_OID)oids+7;
