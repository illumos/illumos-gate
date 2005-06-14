#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * include/krb5/adm_defs.h
 *
 * Copyright 1990 by the Massachusetts Institute of Technology.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 * 
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 * 
 *
 * <<< Description >>>
 */


#ifndef __ADM_DEFINES__
#define __ADM_DEFINES__

#define ADM5_VERSTR		"ADM5VER1"
#define ADM5_VERSIZE		strlen(ADM5_VERSTR)
/* This used to be kerberos_master */
#define ADM5_PORTNAME		"kerberos-adm"
#define ADM5_DEFAULT_PORT	752
#define ADM5_CPW_VERSION	"V5CPWS01"
#define ADM5_ADM_VERSION	"V5ADMS01"
#define CPWNAME			"kadmin"
#define ADMINSTANCE		"admin"

#define ADM_CPW_VERSION         "V5CPWS01"
#define ADM_MAX_PW_ITERATIONS	5
#define ADM_MAX_PW_CHOICES	5

#ifdef MACH_PASS
#define ADM_MAX_PW_LENGTH       8
#define ADM_MAX_PHRASE_LENGTH	101
#else
#define ADM_MAX_PW_LENGTH       255
#endif

#define CPW_SNAME               ADM5_PORTNAME

#define MAXCPWBUFSIZE 4096

#ifdef unicos61
#define SIZEOF_INADDR  SIZEOF_in_addr
#else
#define SIZEOF_INADDR sizeof(struct in_addr)
#endif

/* Server */
#define KADMIND		0x01

/* Applications */
#define KPASSWD		0x01
#define KSRVUTIL	0x02
#define KADMIN		0x03

/* Operations */
#define ADDOPER		0x01    /* Add Principal */
#define CHGOPER		0x02    /* Change Password */
#define ADROPER         0x03    /* Add principal with random password */
#define CHROPER         0x04    /* Change to random password */
#define DELOPER		0x05    /* Delete Principal */
#define MODOPER		0x06    /* Modify Principal attributes */
#define INQOPER		0x07    /* Display Principal info */
#define AD4OPER         0x08    /* Add Principal using v4 string-to-key */
#define CH4OPER         0x09    /* Change password using v4 string-to-key */
#define COMPLETE	0x0f

/* Extra Message Types */
#define SENDDATA1	0x00
#define SENDDATA2	0x01
#define SENDDATA3	0x02

/* Unknowns */
#define KUNKNOWNAPPL	0xff
#define KUNKNOWNOPER	0xff
#define KUNKNOWNERR	0xff

typedef struct {
    char appl_code;
    char oper_code;
    char retn_code;
    char FAR *message;
} kadmin_requests;

#if 0
static char FAR *oper_type[] = {
	"complete",					/* 0 */
	"addition",					/* 1 */
	"deletion",					/* 2 */
	"change",					/* 3 */
	"modification",					/* 4 */
	"inquiry"					/* 5 */
};
#endif

#define SKYCHANGED	0x00
#define NSKYRCVD	0x01


#if 0
static char FAR *ksrvutil_message[] = {
	"Service Key Changed",				/* 0 */
	"New Key and Version Received"			/* 1 */
};
#endif

#define KADMGOOD	0x00
#define KADMSAG		0x01

#if 0
static char FAR *kadmind_general_response[] = {
	"Success",					/* 0 */
	"Service Access Granted"			/* 1 */
};
#endif


#define KPASSGOOD	0x00
#define KPASSBAD	0x01

#if 0
static char FAR *kadmind_kpasswd_response[] = {
	"Password Changed",				/* 0 */
	"Password NOT Changed!"				/* 1 */
};
#endif

#define KSRVGOOD	0x00
#define KSRVBAD		0x01
#define KSRVCATASTROPHE	0x02

#if 0
static char FAR *kadmind_ksrvutil_response[] = {
	"Service Password Change Complete",		/* 0 */
	"One or More Service Password Change(s) Failed!",	/* 1 */
	"Database Update Failure - Possible Catastrophe!!"	/* 2 */
};
#endif

#define KADMGOOD	0x00
#define KADMBAD		0x01

#if 0
static char FAR *kadmind_kadmin_response[] = {
	"Administrative Service Completed",		/* 0 */
	"Principal Unknown!",				/* 1 */
	"Principal Already Exists!",			/* 2 */
	"Allocation Failure!",				/* 3 */
	"Password Failure!",				/* 4 */
	"Protocol Failure!",				/* 5 */
	"Security Failure!",				/* 6 */
	"Admin Client Not in ACL List!",			/* 7 */
	"Database Update Failure - Possible Catastrophe!!"	/* 8 */
};
#endif

#define KMODVNO		0x00
#define KMODATTR	0x01

#ifdef SANDIA
#define KMODFCNT	0x02
#endif

#define ATTRPOST	0x00
#define ATTRNOPOST	0x01
#define ATTRFOR		0x02
#define ATTRNOFOR	0x03
#define ATTRTGT		0x04
#define ATTRNOTGT	0x05
#define ATTRREN		0x06
#define ATTRNOREN	0x07
#define ATTRPROXY	0x08
#define ATTRNOPROXY	0x09
#define ATTRDSKEY	0x0a
#define ATTRNODSKEY	0x0b
#define ATTRLOCK	0x0c
#define ATTRUNLOCK	0x0d

#ifdef SANDIA
#define ATTRPRE		0x0e
#define ATTRNOPRE	0x0f
#define ATTRPWOK	0x10
#define ATTRPWCHG	0x11
#define ATTRSID		0x12
#define ATTRNOSID	0x13
#endif

#define ATTRNOSVR       0x14
#define ATTRSVR         0x15

#define BADATTR		0x3f

#endif /* __ADM_DEFINES__ */
