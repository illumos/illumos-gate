/*
 * include/krb5/adm.h
 *
 * Copyright 1995,2001 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
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
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */
#ifndef	KRB5_ADM_H__
#define	KRB5_ADM_H__

/*
 * Kerberos V5 Change Password service name
 */
#define	KRB5_ADM_SERVICE_NAME	"kpasswd"
#define	KRB5_ADM_DEFAULT_PORT	464

#define KRB5_ADM_SERVICE_INSTANCE "changepw"

/*
 * Maximum password length.
 */
#define	KRB5_ADM_MAX_PASSWORD_LEN	512

/*
 * Protocol command strings.
 */
#define	KRB5_ADM_QUIT_CMD	"QUIT"
#define	KRB5_ADM_CHECKPW_CMD	"CHECKPW"
#define	KRB5_ADM_CHANGEPW_CMD	"CHANGEPW"
#define	KRB5_ADM_MOTD_CMD	"MOTD"
#define	KRB5_ADM_MIME_CMD	"MIME"
#define	KRB5_ADM_LANGUAGE_CMD	"LANGUAGE"

#define	KRB5_ADM_ADD_PRINC_CMD	"ADD-PRINCIPAL"
#define	KRB5_ADM_DEL_PRINC_CMD	"DELETE-PRINCIPAL"
#define	KRB5_ADM_REN_PRINC_CMD	"RENAME-PRINCIPAL"
#define	KRB5_ADM_MOD_PRINC_CMD	"MODIFY-PRINCIPAL"
#define	KRB5_ADM_INQ_PRINC_CMD	"INQUIRE-PRINCIPAL"
#define	KRB5_ADM_EXT_KEY_CMD	"EXTRACT-KEY"

/*
 * Protocol command strings for the current version of the admin
 * server.  (Chris had removed them in the version he was working
 * with.)
 *
 * XXX I'm adding them back so the tree works.  We need to take care
 * of this eventually.
 */
#define       KRB5_ADM_CHG_OPW_CMD    "OTHER-CHANGEPW"
#define       KRB5_ADM_CHG_ORPW_CMD   "OTHER-RANDOM-CHANGEPW"
#define       KRB5_ADM_ADD_KEY_CMD    "ADD-KEY"
#define       KRB5_ADM_DEL_KEY_CMD    "DELETE-KEY"

/*
 * Reply status values.
 */
#define	KRB5_ADM_SUCCESS		0
#define	KRB5_ADM_CMD_UNKNOWN		1
#define	KRB5_ADM_PW_UNACCEPT		2
#define	KRB5_ADM_BAD_PW			3
#define	KRB5_ADM_NOT_IN_TKT		4
#define	KRB5_ADM_CANT_CHANGE		5
#define	KRB5_ADM_LANG_NOT_SUPPORTED	6

#define	KRB5_ADM_P_ALREADY_EXISTS	64
#define	KRB5_ADM_P_DOES_NOT_EXIST	65
#define	KRB5_ADM_NOT_AUTHORIZED		66
#define	KRB5_ADM_BAD_OPTION		67
#define	KRB5_ADM_VALUE_REQUIRED		68
#define	KRB5_ADM_SYSTEM_ERROR		69
#define	KRB5_ADM_KEY_DOES_NOT_EXIST	70
#define	KRB5_ADM_KEY_ALREADY_EXISTS	71

/*
 * Principal flag keywords.
 */
/* Settable only */
#define	KRB5_ADM_KW_PASSWORD		"PASSWORD"
#define	KRB5_ADM_KW_APASSWORD		"APASSWORD"
#define	KRB5_ADM_KW_RANDOMKEY		"RANDOMKEY"
#define	KRB5_ADM_KW_ARANDOMKEY		"ARANDOMKEY"
#define	KRB5_ADM_KW_SETFLAGS		"SETFLAGS"
#define	KRB5_ADM_KW_UNSETFLAGS		"UNSETFLAGS"
/* Settable and retrievable */
#define	KRB5_ADM_KW_MAXLIFE		"MAXLIFE"
#define	KRB5_ADM_KW_MAXRENEWLIFE	"MAXRENEWLIFE"
#define	KRB5_ADM_KW_EXPIRATION		"EXPIRATION"
#define	KRB5_ADM_KW_PWEXPIRATION	"PWEXPIRATION"
#define	KRB5_ADM_KW_FLAGS		"FLAGS"
#define	KRB5_ADM_KW_AUXDATA		"AUXDATA"
#define	KRB5_ADM_KW_EXTRADATA		"EXTRADATA"
/* Retrievable only */
#define	KRB5_ADM_KW_LASTPWCHANGE	"LASTPWCHANGE"
#define	KRB5_ADM_KW_LASTSUCCESS		"LASTSUCCESS"
#define	KRB5_ADM_KW_LASTFAILED		"LASTFAILED"
#define	KRB5_ADM_KW_FAILCOUNT		"FAILCOUNT"
#define	KRB5_ADM_KW_KEYDATA		"KEYDATA"

/* Valid mask */
#define	KRB5_ADM_M_PASSWORD		0x00000001
#define	KRB5_ADM_M_MAXLIFE		0x00000002
#define	KRB5_ADM_M_MAXRENEWLIFE		0x00000004
#define	KRB5_ADM_M_EXPIRATION		0x00000008
#define	KRB5_ADM_M_PWEXPIRATION		0x00000010
#define	KRB5_ADM_M_RANDOMKEY		0x00000020
#define	KRB5_ADM_M_FLAGS		0x00000040
#define	KRB5_ADM_M_LASTPWCHANGE		0x00000080
#define	KRB5_ADM_M_LASTSUCCESS		0x00000100
#define	KRB5_ADM_M_LASTFAILED		0x00000200
#define	KRB5_ADM_M_FAILCOUNT		0x00000400
#define	KRB5_ADM_M_AUXDATA		0x00000800
#define	KRB5_ADM_M_KEYDATA		0x00001000
#define	KRB5_ADM_M_APASSWORD		0x00002000
#define	KRB5_ADM_M_ARANDOMKEY		0x00004000
#define	KRB5_ADM_M_UNUSED_15		0x00008000
#define	KRB5_ADM_M_UNUSED_16		0x00010000
#define KRB5_ADM_M_UNUSED_17		0x00020000
#define	KRB5_ADM_M_UNUSED_18		0x00040000
#define	KRB5_ADM_M_UNUSED_19		0x00080000
#define	KRB5_ADM_M_UNUSED_20		0x00100000
#define	KRB5_ADM_M_UNUSED_21		0x00200000
#define	KRB5_ADM_M_UNUSED_22		0x00400000
#define	KRB5_ADM_M_UNUSED_23		0x00800000
#define	KRB5_ADM_M_UNUSED_24		0x01000000
#define	KRB5_ADM_M_UNUSED_25		0x02000000
#define	KRB5_ADM_M_UNUSED_26		0x04000000
#define	KRB5_ADM_M_UNUSED_27		0x08000000
#define	KRB5_ADM_M_UNUSED_28		0x10000000
#define	KRB5_ADM_M_UNUSED_29		0x20000000
#define	KRB5_ADM_M_GET			0x40000000
#define	KRB5_ADM_M_SET			0x80000000

#define KRB5_ADM_M_EXTRADATA		0x00000000 /* Hack to get */
						   /* libkadm to compile */

#define	KRB5_ADM_M_SET_VALID		(KRB5_ADM_M_SET		+ \
					 KRB5_ADM_M_PASSWORD	+ \
					 KRB5_ADM_M_APASSWORD	+ \
					 KRB5_ADM_M_MAXLIFE	+ \
					 KRB5_ADM_M_MAXRENEWLIFE+ \
					 KRB5_ADM_M_EXPIRATION	+ \
					 KRB5_ADM_M_PWEXPIRATION+ \
					 KRB5_ADM_M_RANDOMKEY	+ \
					 KRB5_ADM_M_ARANDOMKEY	+ \
					 KRB5_ADM_M_FLAGS	+ \
					 KRB5_ADM_M_AUXDATA)
#define	KRB5_ADM_M_GET_VALID		(KRB5_ADM_M_GET		+ \
					 KRB5_ADM_M_MAXLIFE	+ \
					 KRB5_ADM_M_MAXRENEWLIFE+ \
					 KRB5_ADM_M_EXPIRATION	+ \
					 KRB5_ADM_M_PWEXPIRATION+ \
					 KRB5_ADM_M_FLAGS	+ \
					 KRB5_ADM_M_LASTPWCHANGE+ \
					 KRB5_ADM_M_LASTSUCCESS	+ \
					 KRB5_ADM_M_LASTFAILED	+ \
					 KRB5_ADM_M_FAILCOUNT	+ \
					 KRB5_ADM_M_AUXDATA	+ \
					 KRB5_ADM_M_KEYDATA)

/*
 * Keytab reply components.
 */
#define	KRB5_ADM_KT_PRINCIPAL	0
#define	KRB5_ADM_KT_TIMESTAMP	1
#define	KRB5_ADM_KT_VNO		2
#define	KRB5_ADM_KT_KEY_ENCTYPE	3
#define	KRB5_ADM_KT_KEY_KEY	4
#define	KRB5_ADM_KT_NCOMPS	5

/* for krb5_key_salt_tuple */
#include "kdb.h"

/*
 * Data structure returned by krb5_read_realm_params()
 */
typedef struct __krb5_realm_params {
    char *		realm_profile;
    char *		realm_dbname;
    char *		realm_mkey_name;
    char *		realm_stash_file;
    char *		realm_kdc_ports;
    char *		realm_kdc_tcp_ports;
    char *		realm_acl_file;
    krb5_int32		realm_kadmind_port;
    krb5_enctype	realm_enctype;
    krb5_deltat		realm_max_life;
    krb5_deltat		realm_max_rlife;
    krb5_timestamp	realm_expiration;
    krb5_flags		realm_flags;
    krb5_key_salt_tuple	*realm_keysalts;
    unsigned int	realm_reject_bad_transit:1;
    unsigned int	realm_kadmind_port_valid:1;
    unsigned int	realm_enctype_valid:1;
    unsigned int	realm_max_life_valid:1;
    unsigned int	realm_max_rlife_valid:1;
    unsigned int	realm_expiration_valid:1;
    unsigned int	realm_flags_valid:1;
    unsigned int	realm_reject_bad_transit_valid:1;
    krb5_int32		realm_num_keysalts;
} krb5_realm_params;
#endif	/* KRB5_ADM_H__ */
