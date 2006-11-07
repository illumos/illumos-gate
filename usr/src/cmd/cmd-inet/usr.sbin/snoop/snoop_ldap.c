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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <net/if.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include "snoop.h"

#ifndef MIN
#define	MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

extern char *src_name;
extern char *dst_name;
#define	MAX_CTX  (10)
#define	LINE_LEN (255)
#define	BUF_SIZE (16000)
static int ldap = 0;		/* flag to control initialization */
struct ctx {
	int src;
	int dst;
	char *src_name;
	char *dst_name;
};
char *osibuff = NULL;
int osilen = 0;
char scrbuffer[BUF_SIZE];	/* buffer to accumulate data until a */
				/* complete LDAPmessage is received  */
char resultcode[LINE_LEN];	/* These are used */
char operation[LINE_LEN];	/* by -V option.  */
char bb[LINE_LEN];

int gi_osibuf[MAX_CTX];
int otyp[MAX_CTX];
int olen[MAX_CTX];
int level[MAX_CTX];

void decode_ldap(char *buf, int len);

#define	X unsigned char
typedef	X * A;
#define	INT(a) ((int)(a))
#define	SCRUB (void) strcat(scrbuffer, bb);

static X	hex;		/* input hex octet */
static A	*PTRaclass;	/* application tag table pointer */

/*
 * ASN.1 Message Printing Macros
 */

#define	asnshw1(a)				{(void)sprintf(bb, a); SCRUB }
#define	asnshw2(a, b)			{(void)sprintf(bb, a, b); SCRUB }
#define	asnshw3(a, b, c)		{(void)sprintf(bb, a, b, c); SCRUB }
#define	asnshw4(a, b, c, d)		{(void)sprintf(bb, a, b, c, d); SCRUB }
#define	asnshw5(a, b, c, d, e)	{(void)sprintf(bb, a, b, c, d, e); SCRUB }

/*
 * Local Types And Variables
 */

/*
 * Object identifier oid to name mapping description type
 */

typedef struct {
	A	oidname;	/* object identifier string name */
	X	oidcode[16];	/* object identifier hexa code */
}	oidelmT;
typedef oidelmT *oidelmTp;

/*
 * Snoop's entry point to ldap decoding
 */

void
interpret_ldap(flags, data, fraglen, src, dst)
int flags;
char *data;
int fraglen;
int src;
int dst;
{

	if (!ldap) {
		init_ldap();
		ldap = 1;
	}

	(void) decode_ldap(data, fraglen);

	if (flags & F_DTAIL) {
		/* i.e. when snoop is run with -v (verbose) */
		show_header("LDAP:  ",
		"Lightweight Directory Access Protocol Header", fraglen);
		show_space();
		printf("%s", scrbuffer);
	}

	if (flags & F_SUM) {
	/* i.e. when snoop is run with -V (summary) */
		(void) strcpy(data, "");

		if (strlen(operation) != 0) {
			(void) strcat(data, " ");
			(void) strncat(data, operation, 30);
			(void) strcpy(operation, "");
		}

		if (strlen(resultcode) != 0) {
			(void) strcat(data, " ");
			(void) strncat(data, resultcode, 30);
			(void) strcpy(resultcode, "");
		}

		if (dst == 389) {
			(void) sprintf(get_sum_line(),
				"LDAP C port=%d%s", src, data);
		}
		if (src == 389) {
			(void) sprintf(get_sum_line(),
				"LDAP R port=%d%s", dst, data);
		}
	}

	(void) strcpy(scrbuffer, "");
}

/*
 * Known object identifiers: customize to add your own oids
 */

static oidelmT OidTab[] = {
/*
 *	X.500 Standardized Attribute Types
 */
{(A)"ObjectClass",				{ 0x03, 0x55, 0x04, 0x00 }},
{(A)"AliasObjectName",			{ 0x03, 0x55, 0x04, 0x01 }},
{(A)"KnowledgeInfo",			{ 0x03, 0x55, 0x04, 0x02 }},
{(A)"CommonName",				{ 0x03, 0x55, 0x04, 0x03 }},
{(A)"Surname",					{ 0x03, 0x55, 0x04, 0x04 }},
{(A)"SerialNumber",				{ 0x03, 0x55, 0x04, 0x05 }},
{(A)"CountryName",				{ 0x03, 0x55, 0x04, 0x06 }},
{(A)"LocalityName",				{ 0x03, 0x55, 0x04, 0x07 }},
{(A)"StateOrProvinceName",		{ 0x03, 0x55, 0x04, 0x08 }},
{(A)"StreetAddress",			{ 0x03, 0x55, 0x04, 0x09 }},
{(A)"OrganizationName",			{ 0x03, 0x55, 0x04, 0x0a }},
{(A)"OrganizationUnitName",		{ 0x03, 0x55, 0x04, 0x0b }},
{(A)"Title",					{ 0x03, 0x55, 0x04, 0x0c }},
{(A)"Description",				{ 0x03, 0x55, 0x04, 0x0d }},
{(A)"SearchGuide",				{ 0x03, 0x55, 0x04, 0x0e }},
{(A)"BusinessCategory",			{ 0x03, 0x55, 0x04, 0x0f }},
{(A)"PostalAddress",			{ 0x03, 0x55, 0x04, 0x10 }},
{(A)"PostalCode",				{ 0x03, 0x55, 0x04, 0x11 }},
{(A)"PostOfficeBox",			{ 0x03, 0x55, 0x04, 0x12 }},
{(A)"PhysicalDeliveryOffice",	{ 0x03, 0x55, 0x04, 0x13 }},
{(A)"TelephoneNUmber",			{ 0x03, 0x55, 0x04, 0x14 }},
{(A)"TelexNumber",				{ 0x03, 0x55, 0x04, 0x15 }},
{(A)"TeletexTerminalId",		{ 0x03, 0x55, 0x04, 0x16 }},
{(A)"FaxTelephoneNumber",		{ 0x03, 0x55, 0x04, 0x17 }},
{(A)"X121Address",				{ 0x03, 0x55, 0x04, 0x18 }},
{(A)"IsdnAddress",				{ 0x03, 0x55, 0x04, 0x19 }},
{(A)"RegisteredAddress",		{ 0x03, 0x55, 0x04, 0x1a }},
{(A)"DestinationIndicator",		{ 0x03, 0x55, 0x04, 0x1b }},
{(A)"PreferDeliveryMethod",		{ 0x03, 0x55, 0x04, 0x1c }},
{(A)"PresentationAddress",		{ 0x03, 0x55, 0x04, 0x1d }},
{(A)"SupportedApplContext",		{ 0x03, 0x55, 0x04, 0x1e }},
{(A)"Member",					{ 0x03, 0x55, 0x04, 0x1f }},
{(A)"Owner",					{ 0x03, 0x55, 0x04, 0x20 }},
{(A)"RoleOccupant",				{ 0x03, 0x55, 0x04, 0x21 }},
{(A)"SeeAlso",					{ 0x03, 0x55, 0x04, 0x22 }},
{(A)"Password",					{ 0x03, 0x55, 0x04, 0x23 }},
{(A)"UserCertificate",			{ 0x03, 0x55, 0x04, 0x24 }},
{(A)"CaCertificate",			{ 0x03, 0x55, 0x04, 0x25 }},
{(A)"AuthorityRevList",			{ 0x03, 0x55, 0x04, 0x26 }},
{(A)"CertificateRevList",		{ 0x03, 0x55, 0x04, 0x27 }},
{(A)"CrossCertificatePair",		{ 0x03, 0x55, 0x04, 0x28 }},

/*
 *	X.500 Standardized Object Classes
 */
{(A)"Top",					{ 0x03, 0x55, 0x06, 0x00 }},
{(A)"Alias",				{ 0x03, 0x55, 0x06, 0x01 }},
{(A)"Country",				{ 0x03, 0x55, 0x06, 0x02 }},
{(A)"Locality",				{ 0x03, 0x55, 0x06, 0x03 }},
{(A)"Organization",			{ 0x03, 0x55, 0x06, 0x04 }},
{(A)"OrganizationUnit",		{ 0x03, 0x55, 0x06, 0x05 }},
{(A)"Person",				{ 0x03, 0x55, 0x06, 0x06 }},
{(A)"OrganizationPersion",	{ 0x03, 0x55, 0x06, 0x07 }},
{(A)"OrganizationRole",		{ 0x03, 0x55, 0x06, 0x08 }},
{(A)"Group",				{ 0x03, 0x55, 0x06, 0x09 }},
{(A)"ResidentialPerson",	{ 0x03, 0x55, 0x06, 0x0A }},
{(A)"ApplicationProcess",	{ 0x03, 0x55, 0x06, 0x0B }},
{(A)"ApplicationEntity",	{ 0x03, 0x55, 0x06, 0x0C }},
{(A)"Dsa",					{ 0x03, 0x55, 0x06, 0x0D }},
{(A)"Device",				{ 0x03, 0x55, 0x06, 0x0E }},
{(A)"StrongAuthenticUser",	{ 0x03, 0x55, 0x06, 0x0F }},
{(A)"CaAuthority",			{ 0x03, 0x55, 0x06, 0x10 }},

/*
 *	ACSE Protocol Object Identifiers
 */
{(A)"Asn1BER-TS",		{ 0x02, 0x51, 0x01 }},
{(A)"Private-TS",		{ 0x06, 0x2b, 0xce, 0x06, 0x01, 0x04, 0x06 }},
{(A)"ACSE-AS",			{ 0x04, 0x52, 0x01, 0x00, 0x01 }},

/*
 *	Directory Protocol Oids
 */
{(A)"DirAccess-AC",			{ 0x03, 0x55, 0x03, 0x01 }},
{(A)"DirSystem-AC",			{ 0x03, 0x55, 0x03, 0x02 }},

{(A)"DirAccess-AS",			{ 0x03, 0x55, 0x09, 0x01 }},
{(A)"DirSystem-AS",			{ 0x03, 0x55, 0x09, 0x02 }},

/*
 *	and add your private object identifiers here ...
 */
};

#define	OIDNB (sizeof (OidTab) / sizeof (oidelmT))	/* total oid nb */

/*
 *	asn.1 tag class definition
 */

static A class[] = {	/* tag class */
	(A)"UNIV ",
	(A)"APPL ",
	(A)"CTXs ",
	(A)"PRIV "
};

/*
 *	universal tag definition
 */

static A uclass[] = {	/* universal tag assignment */
(A)"EndOfContents",			/* 0  */
(A)"Boolean",				/* 1  */
(A)"Integer",				/* 2  */
(A)"BitString",				/* 3  */
(A)"OctetString",			/* 4  */
(A)"Null",				/* 5  */
(A)"Oid",				/* 6  */
(A)"ObjDescriptor",			/* 7  */
(A)"External",				/* 8  */
(A)"Real",				/* 9  */
(A)"Enumerated",			/* 10 */
(A)"Reserved",				/* 11 */
(A)"Reserved",				/* 12 */
(A)"Reserved",				/* 13 */
(A)"Reserved",				/* 14 */
(A)"Reserved",				/* 15 */
(A)"Sequence",				/* 16 */
(A)"Set",				/* 17 */
(A)"NumericString",			/* 18 */
(A)"PrintableString",			/* 19 */
(A)"T.61String",			/* 20 */
(A)"VideotexString",			/* 21 */
(A)"IA5String",				/* 22 */
(A)"UTCTime",				/* 23 */
(A)"GeneralizedTime",			/* 24 */
(A)"GraphicString",			/* 25 */
(A)"VisibleString",			/* 26 */
(A)"GeneralString",			/* 27 */
(A)"Reserved",				/* 28 */
(A)"Reserved",				/* 29 */
(A)"Reserved",				/* 30 */
(A)"Reserved" 				/* 31 */
};

static A MHSaclass[] = {	/* mhs application tag assignment */
(A)"Bind Request",			/* 0 */
(A)"Bind Response",
(A)"Unbind Request",
(A)"Search Request",
(A)"Search ResEntry",
(A)"Search ResDone",			/* 5 */
(A)"Modify Request",
(A)"Modify Response",
(A)"Add Request",
(A)"Add Response",			/* 9 */
(A)"Del Request",
(A)"Del Response",
(A)"ModDN Request",
(A)"ModDN Response",
(A)"Compare Request",			/* 14 */
(A)"Compare Response",
(A)"Abandon Request",
(A)"",					/* 17 */
(A)"",					/* 18 */
(A)"Search ResRef",			/* 19 */
(A)"",					/* 20 */
(A)"",					/* 21 */
(A)"",					/* 22 */
(A)"Extended Request",
(A)"Extended Response",
(A)"",					/* 25 */
(A)"",					/* 26 */
(A)"",					/* 27 */
(A)"",					/* 28 */
(A)"",					/* 29 */
(A)"",					/* 30 */
(A)"" 					/* 31 */
};


static A DFTaclass[] = {	/* Default Application Tag Assignment */
(A)"",				/* 0  */
(A)"",				/* 1  */
(A)"",				/* 2  */
(A)"",				/* 3  */
(A)"",				/* 4  */
(A)"",				/* 5  */
(A)"",				/* 6  */
(A)"",				/* 7  */
(A)"",				/* 8  */
(A)"",				/* 9  */
(A)"",				/* 10 */
(A)"",				/* 11 */
(A)"",				/* 12 */
(A)"",				/* 13 */
(A)"",				/* 14 */
(A)"",				/* 15 */
(A)"",				/* 16 */
(A)"",				/* 17 */
(A)"",				/* 18 */
(A)"",				/* 19 */
(A)"",				/* 20 */
(A)"",				/* 21 */
(A)"",				/* 22 */
(A)"",				/* 23 */
(A)"",				/* 24 */
(A)"",				/* 25 */
(A)"",				/* 26 */
(A)"",				/* 27 */
(A)"",				/* 28 */
(A)"",				/* 29 */
(A)"",				/* 30 */
(A)"" 				/* 31 */
};

typedef struct asndefS {
char *name;
int type;
int application;
int nbson;
struct {
	char *sonname;
	struct asndefS *sondef;
	long tag;
	} son[50];
} asndefT, * asndefTp;

#define	SEQUENCE		0x0002
#define	SEQUENCEOF		0x0003
#define	SET				0x0004
#define	PRINTABLE		0x0008
#define	ENUM			0x0010
#define	BITSTRING		0x0020
#define	EXTENSION		0x0040
#define	CONTENTTYPE		0x0080
#define	CONTENT			0x0100
#define	CHOICE			0x0200

static asndefT RTSpasswd = { "RTS Authentification data", SET,  -1, 2, {
			{"MTA Name", 0, 0},
			{"MTA Password", 0, 1}}};
static asndefT RTSudata = { "RTS User data", SET,  -1, 1, {
			{0, &RTSpasswd, 1}}};

static asndefT baseObject = {"Base Object", PRINTABLE, -1, 0, {0}};

static asndefT scope = {"Scope", ENUM, -1, 3, {
			{"BaseObject", 0, 0},
			{"singleLevel", 0, 1},
			{"wholeSubtree", 0, 2}}};

static asndefT derefAliases = {"DerefAliases", ENUM, -1, 4, {
			{"neverDerefAliases", 0, 0},
			{"derefInSearching", 0, 1},
			{"derefFindingBaseObj", 0, 2},
			{"derefAlways", 0, 3}}};

static asndefT filter;
static asndefT and = {"And", SET, -1, 1, {
			{0, &filter, -1}}};
static asndefT or = {"Or", SET, -1, 1, {
			{0, &filter, -1}}};
static asndefT not = {"Not", SET, -1, 1, {
			{0, &filter, -1}}};
static asndefT equalityMatch = {"Equality Match", SEQUENCE, -1, 2, {
			{"Attr Descr", 0, -1},
			{"Value", 0, -1}}};
static asndefT substrings = {"Substring", SEQUENCE, -1, 2, {
			{"Type", 0, -1},
			{"Substrings (initial)", 0, 0},
			{"Substrings (any)", 0, 1},
			{"Substring (final)", 0, 2}}};
static asndefT greaterOrEqual = {"Greater Or Equal", SEQUENCE, -1, 2, {
			{"Attr Descr", 0, -1},
			{"Value", 0, -1}}};
static asndefT lessOrEqual = {"Less Or Equal", SEQUENCE, -1, 2, {
			{"Attr Descr", 0, -1},
			{"Value", 0, -1}}};
static asndefT approxMatch = {"Approx Match", SEQUENCE, -1, 2, {
			{"Attr Descr", 0, -1},
			{"Value", 0, -1}}};
static asndefT extensibleMatch = {"Extensible Match", SEQUENCE, -1, 4, {
			{"MatchingRule", 0, 1},
			{"Type", 0, 2},
			{"MatchValue", 0, 3},
			{"dnAttributes", 0, 4}}};

static asndefT filter = {"Filter", CHOICE, -1, 10, {
			{0, &and, 0},
			{0, &or, 1},
			{0, &not, 2},
			{0, &equalityMatch, 3},
			{0, &substrings, 4},
			{0, &greaterOrEqual, 5},
			{0, &lessOrEqual, 6},
			{"Filter: Present", 0, 7},
			{0, &approxMatch, 8},
			{0, &extensibleMatch, 9}}};

static asndefT attributedescription = \
			{"Attribute Description", PRINTABLE, -1, 0, {0}};
static asndefT attributes = {"Attribute List", SEQUENCEOF, -1, 1, {
			{0, &attributedescription, -1}}};

static asndefT searchRequest = {"Operation", SEQUENCE, 3, 8, {
			{0, &baseObject, -1},
			{0, &scope, -1},
			{0, &derefAliases, -1},
			{"SizeLimit", 0, -1},
			{"TimeLimit", 0, -1},
			{"TypesOnly", 0, -1},
			{0, &filter, -1},
			{0, &attributes, -1}}};

static asndefT objectName = {"Object Name", PRINTABLE, -1, 0, {0}};

static asndefT ldapEntry = {"Entry", PRINTABLE, -1, 0, {0}};
static asndefT relativeLdapEntry = \
			{"Relative LDAP Entry", PRINTABLE, -1, 0, {0}};
static asndefT newSuperior = {"New Superior", PRINTABLE, -1, 0, {0}};

static asndefT vals = {"Vals", SET, -1, 1, {
			{"Value", 0, -1}}};

static asndefT attribute = {"Attribute", SEQUENCE, -1, 2, {
			{"Type", 0, -1},
			{0, &vals, -1}}};

static asndefT partialAttributes = {"Partial Attributes", SEQUENCEOF, -1, 1, {
			{0, &attribute, -1}}};

static asndefT searchResEntry = {"Operation", SEQUENCE, 4, 2, {
			{0, &objectName, -1},
			{0, &partialAttributes, -1}}};

static asndefT authChoice = {"Authentication Choice", CHOICE, -1, 2, {
			{"Authentication: Simple", 0, 0},
			{"Authentication: SASL", 0, 3}}};

static asndefT bindRequest = {"Operation", SEQUENCE, 0, 3, {
			{"Version", 0, -1},
			{0, &objectName, -1},
			{0, &authChoice, -1}}};

static asndefT resultCode = {"Result Code", ENUM, -1, 39, {
			{"Success", 0, 0},
			{"Operation Error", 0, 1},
			{"Protocol Error", 0, 2},
			{"Time Limit Exceeded", 0, 3},
			{"Size Limit Exceeded", 0, 4},
			{"Compare False", 0, 5},
			{"Compare True", 0, 6},
			{"Auth Method Not supported", 0, 7},
			{"Strong Auth Required", 0, 8},
			{"Referral", 0, 10},
			{"Admin Limit Exceeded", 0, 11},
			{"Unavailable Critical Extension", 0, 12},
			{"Confidentiality required", 0, 13},
			{"SASL Bind In Progress", 0, 14},
			{"No Such Attribute", 0, 16},
			{"Undefined Attribute Type", 0, 17},
			{"Inappropriate Matching", 0, 18},
			{"Constraint violation", 0, 19},
			{"Attribute or Value Exists", 0, 20},
			{"Invalid Attribute Syntax", 0, 21},
			{"No Such Object", 0, 32},
			{"Alias Problem", 0, 33},
			{"Invalid DN Syntax", 0, 34},
			{"Alias Dereferencing Problem", 0, 36},
			{"Inappropriate Authentication", 0, 48},
			{"Invalid Credentials", 0, 49},
			{"Insufficient Access Rights", 0, 50},
			{"Busy", 0, 51},
			{"Unavailable", 0, 52},
			{"Unwilling To Perform", 0, 53},
			{"Loop Detect", 0, 54},
			{"Naming Violation", 0, 64},
			{"ObjectClass violation", 0, 65},
			{"Not Allowed On Non Leaf", 0, 66},
			{"Not Allowed On RDN", 0, 67},
			{"Entry Already Exists", 0, 68},
			{"ObjectClass Mods Prohibited", 0, 69},
			{"Affects Multiple DSAs", 0, 71},
			{"Other", 0, 80}}};


static asndefT referral = {"Referral", SEQUENCEOF, -1, 1, {
			{"LDAP URL", 0, -1}}};

static asndefT ldapResult = {"LDAP Result", SEQUENCE, -1, 4, {
			{0, &resultCode, -1},
			{"Matched DN", 0, -1},
			{"Error Message", 0, -1},
			{0, &referral, 3}}};

static asndefT bindResponse = {"Operation", SEQUENCE, 1, 5, {
			{0, &resultCode, -1},
			{"Matched DN", 0, -1},
			{"Error Message", 0, -1},
			{0, &referral, 3},
			{"SASL Credentials", 0, 7}}};

static asndefT unbindRequest = {"Operation", SEQUENCE, 2, 0, {0}};

static asndefT searchResDone = {"Operation", SEQUENCE, 5, 4, {
			{0, &resultCode, -1},
			{"Matched DN", 0, -1},
			{"Error Message", 0, -1},
			{0, &referral, 3}}};

static asndefT seqModOperation = {"Operation", ENUM, -1, 4, {
			{"Add", 0, 0},
			{"Delete", 0, 1},
			{"Replace", 0, 2}}};

static asndefT seqModModification = {"Modification", SEQUENCE, -1, 1, {
			{0, &attribute, -1}}};

static asndefT seqModification = {"", SEQUENCE, -1, 2, {
		    {0, &seqModOperation, -1},
			{0, &seqModModification, -1}}};

static asndefT modification = {"Modification", SEQUENCEOF, -1, 1, {
			{0, &seqModification, -1}}};

static asndefT modifyRequest = {"Operation", SEQUENCE, 6, 2, {
			{0, &objectName, -1},
			{0, &modification, -1}}};

static asndefT modifyResponse = {"Operation", SEQUENCE, 7, 4, {
			{0, &resultCode, -1},
			{"Matched DN", 0, -1},
			{"Error Message", 0, -1},
			{0, &referral, 3}}};

static asndefT addAttributes = {"Attributes", SEQUENCEOF, -1, 1, {
			{0, &attribute, -1}}};

static asndefT addRequest = {"Operation", SEQUENCE, 8, 2, {
			{0, &ldapEntry, -1},
			{0, &addAttributes, -1}}};

static asndefT addResponse = {"Operation", SEQUENCE, 9, 4, {
			{0, &resultCode, -1},
			{"Matched DN", 0, -1},
			{"Error Message", 0, -1},
			{0, &referral, 3}}};

static asndefT delRequest = {"Operation", SEQUENCE, 10, 1, {
			{0, &ldapEntry, -1}}};

static asndefT delResponse = {"Operation", SEQUENCE, 11, 4, {
			{0, &resultCode, -1},
			{"Matched DN", 0, -1},
			{"Error Message", 0, -1},
			{0, &referral, 3}}};

static asndefT modifyDNRequest = {"Operation", SEQUENCE, 12, 4, {
			{0, &ldapEntry, -1},
			{0, &relativeLdapEntry, -1},
			{"Delete Old RDN", 0, -1},
			{0, &newSuperior, 0}}};

static asndefT modifyDNResponse = {"Operation", SEQUENCE, 13, 4, {
			{0, &resultCode, -1},
			{"Matched DN", 0, -1},
			{"Error Message", 0, -1},
			{0, &referral, 3}}};

static asndefT ava = {"Ava", SEQUENCE, -1, 2, {
			{"Attr Descr", 0, -1},
			{"Value", 0, -1}}};

static asndefT compareRequest = {"Operation", SEQUENCE, 14, 2, {
			{0, &ldapEntry, -1},
			{0, &ava, 0}}};

static asndefT compareResponse = {"Operation", SEQUENCE, 15, 4, {
			{0, &resultCode, -1},
			{"Matched DN", 0, -1},
			{"Error Message", 0, -1},
			{0, &referral, 3}}};

static asndefT abandonRequest = {"Operation", SEQUENCE, 16, 1, {
		    {"Message ID", 0, -1}}};

static asndefT searchResRef =  {"Operation", SEQUENCEOF, 19, 1, {
			{"LDAP URL", 0, -1}}};

static asndefT extendedRequest = {"Operation", SEQUENCE, 14, 2, {
			{"Request Name", 0, 0},
			{"Request Value", 0, 1}}};

static asndefT extendedResponse = {"Operation", SEQUENCE, 24, 6, {
			{0, &resultCode, -1},
			{"Matched DN", 0, -1},
			{"Error Message", 0, -1},
			{0, &referral, 3},
			{"Response Name", 0, 10},
			{"Response", 0, 11}}};

static asndefT protocolOp = {"Protocol Op", CHOICE, -1, 20, {
			{0, &bindRequest, 0},
			{0, &bindResponse, 1},
			{0, &unbindRequest, 2},
			{0, &searchRequest, 3},
			{0, &searchResEntry, 4},
			{0, &searchResDone, 5},
			{0, &modifyRequest, 6},
			{0, &modifyResponse, 7},
			{0, &addRequest, 8},
			{0, &addResponse, 9},
			{0, &delRequest, 10},
			{0, &delResponse, 11},
			{0, &modifyDNRequest, 12},
			{0, &modifyDNResponse, 13},
			{0, &compareRequest, 14},
			{0, &compareResponse, 15},
			{0, &abandonRequest, 16},
			{0, &searchResRef, 19},
			{0, &extendedRequest, 23},
			{0, &extendedResponse, 24}}};

static asndefT control = {"Control", SEQUENCE, -1, 3, {
			{"LDAP OID", 0, -1},
			{"Criticality", 0, -1},
			{"Control value", 0, -1}}};

static asndefT controls = {"Controls List", SEQUENCEOF, -1, 1, {
	{0, &control, -1}}};

static asndefT LDAPMessage = { "LDAPMessage", SEQUENCE, -1, 3, {
			{"Message ID", 0, -1},
			{0, &protocolOp, -1},
			{0, &controls, 0}}};

static asndefT MPDU = { "MPDU", SET,  -1, 1,
			{{0, &LDAPMessage, 0}}};

static int mytype[] = {
0,			/* EndOfContents	*/
0,			/* Boolean			*/
0,			/* Integer			*/
BITSTRING,	/* BitString		*/
0,			/* OctetString		*/
0,			/* Null				*/
0,			/* Oid				*/
0,			/* ObjDescriptor	*/
0,			/* External			*/
0,			/* Real				*/
ENUM,		/* Enumerated		*/
0,			/* Reserved			*/
0,			/* Reserved			*/
0,			/* Reserved			*/
0,			/* Reserved			*/
0,			/* Reserved			*/
SEQUENCE,	/* Sequence			*/
SET,		/* Set				*/
0,			/* NumericString	*/
0,			/* PrintableString	*/
0,			/* T.61String		*/
0,			/* VideotexString	*/
0,			/* IA5String		*/
0,			/* UTCTime			*/
0,			/* GeneralizedTime	*/
0,			/* GraphicString	*/
0,			/* VisibleString	*/
0,			/* GeneralString	*/
0,			/* Reserved			*/
0,			/* Reserved			*/
0,			/* Reserved			*/
0,			/* Reserved			*/
};

/*
 * Find object identifier in known oid table
 * A	oid - oid hexa string
 * int	olg - oid length
 */
static int
oidmap(A oid, int olg)
{
	register int ix, goon;
	register A oidptr, tabptr, tabend;

/* returns (oid table size) if not found */

	for (ix = 0; ix < OIDNB; ix++) {
		oidptr = oid; tabptr = (&(OidTab[ix].oidcode[0]));
		if (olg == INT(*tabptr++)) {
			tabend = tabptr + olg;
			goon = 1;
			while (goon != 0 && tabptr < tabend) {
				if (*tabptr++ != *oidptr++)
					goon = 0;
			}
			if (goon != 0)
				return (ix);
		}
	}
	return (OIDNB);
}

/*
 * Read an hexacode and convert it into ASCII
 */
static int getnext(int ctxnum)
{
	static X c[3]; /* c[0-3] will contain ascii values on exit */
	hex = 0;
	if (gi_osibuf[ctxnum] == osilen)
		return (-1);
	hex = osibuff[gi_osibuf[ctxnum]++];
	(void) sprintf((char *)c, "%02x", (hex&0x00FF));
	return (0);
}

/*
 * Skip everything that is not an LDAPMessage
 */
static char *skipjunk(len, pdu)
int len;
char *pdu;
{
	int tag;
	char *buf = pdu;
	int offset = 0;
	while (len > 0) {
		/* size minumum for a sequence + integer = 5 */
		/* LDAPMessage::= SEQUENCE  */
		if ((len > 5) && (buf[0] == 0x30)) {
			tag = buf[1]&0x00ff;
			if (tag < 0x80) {
				/* length is one one octet */
				offset = 1;
			} else {
				/* length is multiple octet.  */
				offset = 1+ tag&0x007f;
			}
			/* Make sure we don't read past the end */
			/* of the buffer */
			if (len - (1+offset) > 0) {
				/* skip after the length */
				tag = buf[1+offset]&0x00ff;
				if (tag == 0x02) { /* INTEGER */
					/* looks like a valid PDU */
					return (buf);
				}
			}
		}
		len --;
		buf++;
	}
	return (buf);
}


#define	GETNEXT(a) (void)getnext(a);

/*
 * main routine: decode a TLV; to be called recursively
 *
 * pdulen: current pdu's length
 */
static int
decpdu(int pdulen, asndefTp ASNDESC, int ctxnum)
{
	X		scrlin[99];	/* screen line */
	X		oidstr[80];	/* oid hexa string */
	int		slen;	/* screen line length */
	int		stlv;	/* sub-tlv length */
	int		oix;	/* oid table index */
	int		effnb;	/* effectively traced octet nb */
	int		i = 0, j = 0;
	int		ai = -2;
	asndefTp SASNDESC = 0;
	asndefTp TMPDESC = 0;
	asndefTp GR_TMPDESC = 0;
	int tmpai = 0;
	int gr_tmpai = 0;
	int dontprint = 0;
	int already = 0;
	static int rlen = 0;	/* tlv's real length */

	++level[ctxnum];	/* level indicator */
	effnb = 0;

	/*
	 * Decode the current TLV segment
	 */
	while (pdulen > 1) {

		if (getnext(ctxnum)) {
			break;
		}
		if (strlen(scrbuffer)) asnshw2("%s  ", "LDAP:");
		/* screen printing according to level indicator */
		for (i = 1; i < level[ctxnum]; ++i) asnshw1("   ");

		/* get tag */
		otyp[ctxnum] = INT(hex); /* single octet type only */
		--pdulen;
		++effnb;

		/* get length */
		GETNEXT(ctxnum);
		olen[ctxnum] = INT(hex);	/* tlv length */
		--pdulen;
		++effnb;

		/* Continuing decoding of current TLV... */
		/*
		 * Snoop's lower layers do not allow us
		 * to know the true length for
		 * datastream protocols like LDAP.
		 */

		/*
		 * if length is less than 128, we
		 * already have the real TLV length.
		 */
		if (olen[ctxnum] < 128) {	/* short length form */
			rlen = olen[ctxnum];
		} else {		/* long and any form length */
		/* else we do more getnext()'s */
			for (rlen = 0, olen[ctxnum] &= 0x0F;
			(olen[ctxnum]) && (pdulen > 0);
			--olen[ctxnum], --pdulen, ++effnb) {
				GETNEXT(ctxnum);
				rlen = (rlen << 8) | INT(hex);
			}
			if (!rlen) {
				pdulen = 0x7fffffff;
			}
		}

		/*
		 * print the tag class and number
		 */
		i = otyp[ctxnum]&0x1F;
		switch (otyp[ctxnum] >> 6) {	/* class */
		case 0:	/* universal */
			if (ASNDESC && i != 0) {
				int dobreak = 0;
				switch (ASNDESC->type) {
				case CONTENT:
					SASNDESC = ASNDESC;
					break;
				case SET:
					for (ai = 0;
						ai < ASNDESC->nbson && i < 32 &&
						ASNDESC->son[ai].sondef &&
					/*
					 * For this test SEQUENCE & SEQUENCE OF
					 * are same, so suppress the last bit
					 */
						(ASNDESC->son[ai].sondef
							->type&0xFE)
						!= mytype[i]; ++ai);
					if (ai < ASNDESC->nbson) {
						SASNDESC =
						    ASNDESC->son[ai].sondef;
					if (ASNDESC->son[ai].sonname != NULL) {

					if (ASNDESC->son[ai].sondef != NULL &&
					    ASNDESC->son[ai].sondef->name !=
					    NULL) {
						asnshw2("%s	", "LDAP:");
						asnshw4(" %c[%s %s]",
						((otyp[ctxnum]&0x20)?'*':' '),
						ASNDESC->son[ai].sonname,
						ASNDESC->son[ai].sondef->name);
					} else {
						asnshw2("%s	", "");
						asnshw3(" %c[%s]",
						((otyp[ctxnum]&0x20)?'*':' '),
						ASNDESC->son[ai].sonname);
					} /* end if */

					dobreak = 1;

					} else if (ASNDESC->son[ai].sondef !=
					    NULL &&
					    ASNDESC->son[ai].sondef->name !=
					    NULL) {
						asnshw2("%s	", "LDAP:");
						asnshw3(" %c[%s]",
						((otyp[ctxnum]&0x20)?'*':' '),
						ASNDESC->son[ai].sondef->name);
						dobreak = 1;
					} /* end if */
					} /* end if */
						break;
				case CHOICE:
					if (GR_TMPDESC) {
						ASNDESC = TMPDESC;
						TMPDESC = GR_TMPDESC;
						GR_TMPDESC = 0;
					} else if (TMPDESC) {
						ASNDESC = TMPDESC;
						TMPDESC = 0;
					}
					if (gr_tmpai) {
						ai = tmpai;
						tmpai = gr_tmpai;
						gr_tmpai = 0;
					} else if (tmpai) {
						ai = tmpai;
						tmpai = 0;
					}
					break;

				case SEQUENCE:
					if (ai == -2) {
						ai = 0;
					} else {
						do {
							ai++;
						} while \
			(ai < ASNDESC->nbson && i < 32 && mytype[i] && \
			ASNDESC->son[ai].sondef &&
					/*
					 * For this test SEQUENCE & SEQUENCE OF
					 * are the same, so suppress last bit
					 */
			(ASNDESC->son[ai].sondef->type&0xFE) != mytype[i]);
					} /* end if */
					if (ai < ASNDESC->nbson) {
						SASNDESC = \
						ASNDESC->son[ai].sondef;
						if (ASNDESC->son[ai].sonname) {
							if \
			(ASNDESC->son[ai].sondef &&
			ASNDESC->son[ai].sondef->name) {
								asnshw4 \
			(" %c[%s %s]", ((otyp[ctxnum]&0x20)?'*':' '),
			ASNDESC->son[ai].sonname,
			ASNDESC->son[ai].sondef->name);
							} else {
								asnshw3 \
			(" %c[%s]", ((otyp[ctxnum]&0x20)?'*':' '),
			ASNDESC->son[ai].sonname);
							} /* end if */
							dobreak = 1;
						} else if \
			(ASNDESC->son[ai].sondef &&
			ASNDESC->son[ai].sondef->name) {
								asnshw3 \
			(" %c[%s]", ((otyp[ctxnum]&0x20)?'*':' '),
			ASNDESC->son[ai].sondef->name);
							dobreak = 1;
						} /* end if */
					} /* end if */
					break;
				case SEQUENCEOF:
					ai = 0;
					SASNDESC = ASNDESC->son[ai].sondef;
					if (ASNDESC->son[ai].sonname) {
						if (ASNDESC->son[ai].sondef && \
			ASNDESC->son[ai].sondef->name) {
								asnshw4 \
			(" %c[%s %s]", ((otyp[ctxnum]&0x20)?'*':' '),
			ASNDESC->son[ai].sonname,
			ASNDESC->son[ai].sondef->name);
						} else {
							asnshw3 \
			(" %c[%s]", ((otyp[ctxnum]&0x20)?'*':' '),
			ASNDESC->son[ai].sonname);
						} /* end if */
						dobreak = 1;
					} else if \
			(ASNDESC->son[ai].sondef &&
			ASNDESC->son[ai].sondef->name) {
							asnshw3 \
			(" %c[%s]", ((otyp[ctxnum]&0x20)?'*':' '),
			ASNDESC->son[ai].sondef->name);
						dobreak = 1;
					} /* end if */
				} /* end switch */
				if (dobreak) {
					break;
				} /* end if */
			} /* end if */
			if (uclass[i]) {
				asnshw3 \
			(" %c[%s]", ((otyp[ctxnum]&0x20)?'*':' '), uclass[i]);
			} else {
				asnshw4 \
			(" %c[%s%d]", ((otyp[ctxnum]&0x20)?'*':' '),
			class[0], i);
			}
			break;
		case 1:		/* application */

		if (ASNDESC) {

				for (ai = 0; ai < ASNDESC->nbson; ++ai) {
					int i2 = 0;

					if \
			(ASNDESC->son[ai].sondef &&
			ASNDESC->son[ai].sondef->type == CHOICE) {
						while \
			(i2 < ASNDESC->son[ai].sondef->nbson &&
			ASNDESC->son[ai].sondef->son[i2].sondef && \
	ASNDESC->son[ai].sondef->son[i2].sondef->application != i) {
							i2++;
							continue;
						}
						if \
			(i2 == ASNDESC->son[ai].sondef->nbson) {
							ai = ASNDESC->nbson;
							break;
						}
			if (TMPDESC) {
				GR_TMPDESC = TMPDESC;
				gr_tmpai = tmpai;
			}
					TMPDESC = ASNDESC;
					ASNDESC = ASNDESC->son[ai].sondef;
					tmpai = ai;
					ai = i2;
					}

					if (ASNDESC->son[ai].sondef && \
			ASNDESC->son[ai].sondef->application == i) {
						SASNDESC = \
			ASNDESC->son[ai].sondef;
						if (ASNDESC->son[ai].sonname) {
							if \
			(ASNDESC->son[ai].sondef->name) {
								asnshw3 \
			(" %s %s", ASNDESC->son[ai].sonname,
			ASNDESC->son[ai].sondef->name);
							} else {
								asnshw2 \
			(" %s", ASNDESC->son[ai].sonname);
							} /* end if */
						} else if \
			(ASNDESC->son[ai].sondef->name) {
							asnshw2 \
			(" %s", ASNDESC->son[ai].sondef->name);
						} /* end if */
						break;
					} /* end if */
				} /* end for */
				if (ai >= ASNDESC->nbson) {
					ai = -1;	/* not found */
				} /* end if */
			} /* end if */
			if (PTRaclass[i]) {
				asnshw5 \
			(" %c[%s%d: %s]", ((otyp[ctxnum]&0x20)?'*':' '),
			class[1], i, PTRaclass[i]);
				(void) strcpy(operation, (char *)PTRaclass[i]);
			} else {
				asnshw4 \
			(" %c[%s%d]", ((otyp[ctxnum]&0x20)?'*':' '), \
			class[1], i);
			}
			break;

		case 2:		/* context-specific */

			if (TMPDESC) {
				ASNDESC = TMPDESC;
				TMPDESC = GR_TMPDESC;
				already = 1;
			}
			if (ASNDESC) {

				for (ai = 0; ai < ASNDESC->nbson; ++ai) {
					if \
			(!already && ASNDESC->son[ai].sondef &&
			ASNDESC->son[ai].sondef->type == CHOICE) {
						int i2 = 0;
						while \
			(i2 < ASNDESC->son[ai].sondef->nbson &&
			ASNDESC->son[ai].sondef->son[i2].tag != i) {
							i2++;
							continue;
						}
						if (i2 == \
			ASNDESC->son[ai].sondef->nbson) {
							ai = ASNDESC->nbson;
							break;
						}
						if (TMPDESC) {
							GR_TMPDESC = TMPDESC;
							gr_tmpai = tmpai;
						}
						TMPDESC = ASNDESC;
						ASNDESC = \
			ASNDESC->son[ai].sondef;
						tmpai = ai;
						ai = i2;
					}

					if \
			(ASNDESC->son[ai].tag == i) {
						SASNDESC = \
			ASNDESC->son[ai].sondef;
						if (ASNDESC->son[ai].sonname) {
							if \
			(ASNDESC->son[ai].sondef &&
			ASNDESC->son[ai].sondef->name) {
								asnshw3 \
			(" %s %s", ASNDESC->son[ai].sonname,
			ASNDESC->son[ai].sondef->name);
							} else {
								asnshw2 \
			(" %s", ASNDESC->son[ai].sonname);
							} /* end if */
						} else if \
			(ASNDESC->son[ai].sondef &&
			ASNDESC->son[ai].sondef->name) {
							asnshw2 \
			(" %s", ASNDESC->son[ai].sondef->name);
						} /* end if */
						break;
					} /* end if */
				} /* end for */
				if (ai >= ASNDESC->nbson) {
					ai = -1;	/* not found */
				} /* end if */
			} /* end if */
			asnshw3 \
			(" %c[%d]", ((otyp[ctxnum]&0x20)?'*':' '), i);
			break;

		case 3:		/* private */
			asnshw4 \
			(" %c[%s%d]", ((otyp[ctxnum]&0x20)?'*':' '), \
			class[3], i);
		} /* esac: tag */

		/*
		 * print the length - as a debug tool only.
		 */
		/* asnshw2(" Length=%d ",rlen); */
		asnshw1("\n");
		if (rlen > pdulen) {
			asnshw1("*** Decode length error,");
			asnshw2(" PDU length = %d ***\n", pdulen);
			rlen = pdulen;
		}

		/*
		 * recursive interpretation of the value if constructor
		 */
		if (otyp[ctxnum]&0x20) {		/* constructor */

			stlv = decpdu((rlen?rlen:pdulen), \
			ASNDESC && ai != -1 ?(ai == -2 ? ASNDESC:
			ASNDESC->son[ai].sondef):0, ctxnum);
			/* recursive decoding */
			pdulen -= stlv;
			effnb += stlv;
		} else if (otyp[ctxnum] == 0x06) {
			/*
			 * interpretation of the object identifier
			 */
			for (j = 0; (rlen) && (pdulen > 0); \
			--rlen, --pdulen, ++effnb) {
				GETNEXT(ctxnum);
				oidstr[j++] = hex;
			}

			/* interpret the object identifier */
			oidstr[j++] = '\0';
			oix = oidmap(oidstr, j-1);
			asnshw1("\n");
			if (oix >= 0 && oix < OIDNB) {	/* recognized obj id */
				asnshw2("%s\n", OidTab[oix].oidname);
			} else {
				asnshw1("Unknown Oid\n");
			}
		} else {
			/*
			 * interpretation of other primitive tags
			 */
			if (!otyp[ctxnum] && !rlen) {
			/* end of contents: any form length */
				pdulen = 0;
			} else {
				X   hexstr[5];
				int k = 0;
				int klen = rlen;
				if (SASNDESC && SASNDESC->type == CONTENT && \
			SASNDESC->nbson && SASNDESC->son[0].sondef) {
					(void)
			decpdu(rlen, SASNDESC->son[0].sondef, ctxnum);
				} else {
					if (rlen < 200) {
					for (j = 0, slen = 0; \
			(rlen) && (pdulen > 0);
					--rlen, --pdulen, ++effnb) {
						if (!slen) {
						    (void) \
			strcpy((char *)scrlin, "LDAP:  "); j += 7;
						    for \
			(i = 0; i < level[ctxnum]; ++i) {
							scrlin[j++] = ' ';
							scrlin[j++] = ' ';
							scrlin[j++] = ' ';
							scrlin[j++] = ' ';
						    }
						}

						GETNEXT(ctxnum);
						if (k < 5) {
							hexstr[k++] = hex;
						} /* end if */
						if (!isprint(hex)) {
							hex = '_';
							dontprint = 1;
						}
						scrlin[j++] = hex;
						if ((slen += 2) >= \
			(72 - (level[ctxnum] * 3))) {
							slen = 0;
							scrlin[j] = 0;
							if (!dontprint) {
								asnshw2 \
			("%s\n", scrlin);
							}
							j = 0;
						}
					} /* rof: primitive values */
					if (slen) {
						scrlin[j] = 0;
						if (!dontprint) {
							asnshw2("%s\n", scrlin);
						}
					}
					dontprint = 0;
				} else {
					asnshw2("%s  ", "LDAP:");
				    for (i = 0; i < level[ctxnum]; ++i) {
						asnshw1("   ");
						scrlin[j++] = ' ';
						scrlin[j++] = ' ';
						scrlin[j++] = ' ';
					}

				    for (j = 0; (rlen) && (pdulen > 0); \
			--rlen, --pdulen, ++effnb) {
						GETNEXT(ctxnum);
						if (k < 5) {
							hexstr[k++] = hex;
						}
					}
				    (void) strcpy \
			((char *)scrlin, \
			"*** NOT PRINTED - Too long value ***");
						asnshw2("%s\n", scrlin);
					}

					if \
			(SASNDESC && SASNDESC->type == BITSTRING &&\
			klen <= 5) {
						unsigned long bitstr = 0;
						for (i = 1; i < 5; ++i) {
							bitstr = \
			((bitstr) << 8) + ((i < klen)?hexstr[i]:0);
						} /* end for */
						for \
			(i = 0; i < SASNDESC->nbson; ++i) {
							if ((bitstr & \
			((unsigned long)SASNDESC->son[i].sondef)) ==
			((unsigned long)SASNDESC->son[i].tag)) {
								if \
			(SASNDESC->son[i].sonname) {
								int k;
								asnshw2 \
			("%s  ", "LDAP:");
								for \
			(k = 0; k < level[ctxnum]; ++k) {
								asnshw1("   ");
								}
								asnshw2 \
			("%s", SASNDESC->son[i].sonname);
								} /* end if */
							} /* end if */
						} /* end for */
					} /* end if */
					if (SASNDESC && \
			(SASNDESC->type == ENUM ||
			SASNDESC->type == CONTENTTYPE) && klen <= 5) {
						unsigned long value = 0;
						for (i = 0; i < klen; ++i) {
							value = \
			((value) << 8) + hexstr[i];
						} /* end for */
						for \
			(i = 0; i < SASNDESC->nbson; ++i) {
							if \
			(value == ((unsigned long)SASNDESC->son[i].tag)) {
								if \
			(SASNDESC->son[i].sonname) {
									int k;
								asnshw2 \
			("%s  ", "LDAP:");
									for \
			(k = 0; k < level[ctxnum]; ++k) {
								asnshw1("   ");
									}
								asnshw2 \
			("%s\n", SASNDESC->son[i].sonname);
									(void) \
			strcpy(resultcode, SASNDESC->son[i].sonname);
								} /* end if */
								break;
							} /* end if */
						} /* end for */
					} /* end if */

				} /* end if */
			} /* fi: constructor/obj-id/primitive */
		} /* fi: tag analysis */
	} /* elihw: len>1 */
	--level[ctxnum];
	return (effnb);
}


/* init_ldap initializes various buffers and variables */
/* it is called one-time (in snoop_filter.c) only. */

void
init_ldap()
{
	int i;

	for (i = 0; i < MAX_CTX; i++) {
		gi_osibuf[i] = 0;
		level[i] = 0;
	}
}
static void
ldapdump(char *data, int datalen)
{
	char *p;
	ushort_t *p16 = (ushort_t *)data;
	char *p8 = data;
	int i, left, len;
	int chunk = 16;  /* 16 bytes per line */

	asnshw1("LDAP: Skipping until next full LDAPMessage\n");

	for (p = data; p < data + datalen; p += chunk) {
		asnshw2("LDAP:\t%4d: ", p - data);
		left = (data + datalen) - p;
		len = MIN(chunk, left);
		for (i = 0; i < (len / 2); i++)
			asnshw2("%04x ", ntohs(*p16++) & 0xffff);
		if (len % 2) {
			asnshw2("%02x   ", *((unsigned char *)p16));
		}
		for (i = 0; i < (chunk - left) / 2; i++)
			asnshw1("     ");

		asnshw1("   ");
		for (i = 0; i < len; i++, p8++)
			asnshw2("%c", isprint(*p8) ? *p8 : '.');
		asnshw1("\n");
	}

	asnshw1("LDAP:\n");
}

/* decode_ldap is the entry point for the main decoding function */
/* decpdu(). decode_ldap() is only called by interpret_ldap. */

void
decode_ldap(char *buf, int len)
{
	asndefTp ASNDESC = 0;
	char *newbuf;
	int skipped = 0;

	PTRaclass = MHSaclass;
	ASNDESC = &MPDU;


	newbuf =  skipjunk(len, buf);
	if (newbuf > buf) {
		skipped = newbuf-buf;
		ldapdump(buf, newbuf-buf);
	}
	buf = newbuf;
	len = len-skipped;
	osibuff = buf;	/* Undecoded buf is passed by interpret_ldap */
	osilen = len;	/* length of tcp data is also passed */

	(void) decpdu(len, ASNDESC, 0);
	gi_osibuf[0] = 0;
}
