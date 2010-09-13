/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _RDN_PARSER_H
#define	_RDN_PARSER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * The Original Code is the Netscape security libraries.
 *
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are
 * Copyright (C) 1994-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable
 * instead of those above.  If you wish to allow use of your
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 */

typedef enum {
	OID_AVA_COMMON_NAME = 0,
	OID_AVA_SURNAME,
	OID_AVA_GIVEN_NAME,
	OID_AVA_LOCALITY,
	OID_AVA_STATE_OR_PROVINCE,
	OID_AVA_ORGANIZATION_NAME,
	OID_AVA_ORGANIZATIONAL_UNIT_NAME,
	OID_AVA_COUNTRY_NAME,
	OID_AVA_STREET_ADDRESS,
	OID_AVA_DC,
	OID_RFC1274_UID,
	OID_PKCS9_EMAIL_ADDRESS,
	OID_RFC1274_MAIL,
	OID_UNKNOWN
} OidAvaTag;

struct NameToKind {
    const char  *name;
    OidAvaTag    kind;
    KMF_OID	 *OID;
};

#define	C_DOUBLE_QUOTE '\042'

#define	C_BACKSLASH '\134'

#define	C_EQUAL '='

#define	OPTIONAL_SPACE(c) \
	(((c) == ' ') || ((c) == '\r') || ((c) == '\n'))

#define	SPECIAL_CHAR(c)							\
	(((c) == ',') || ((c) == '=') || ((c) == C_DOUBLE_QUOTE) ||	\
	((c) == '\r') || ((c) == '\n') || ((c) == '+') ||		\
	((c) == '<') || ((c) == '>') || ((c) == '#') ||			\
	((c) == ';') || ((c) == C_BACKSLASH))


#define	IS_PRINTABLE(c)							\
	((((c) >= 'a') && ((c) <= 'z')) ||				\
	(((c) >= 'A') && ((c) <= 'Z')) ||				\
	(((c) >= '0') && ((c) <= '9')) ||				\
	((c) == ' ') ||							\
	((c) == '\'') ||						\
	((c) == '\050') ||				/* ( */		\
	((c) == '\051') ||				/* ) */		\
	(((c) >= '+') && ((c) <= '/')) ||		/* + , - . / */	\
	((c) == ':') ||							\
	((c) == '=') ||							\
	((c) == '?'))


#ifdef __cplusplus
}
#endif
#endif /* _RDN_PARSER_H */
