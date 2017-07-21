/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

#ifndef	_ARPA_TELNET_H
#define	_ARPA_TELNET_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Definitions for the TELNET protocol.
 */
#define	IAC	255		/* interpret as command: */
#define	DONT	254		/* you are not to use option */
#define	DO	253		/* please, you use option */
#define	WONT	252		/* I won't use option */
#define	WILL	251		/* I will use option */
#define	SB	250		/* interpret as subnegotiation */
#define	GA	249		/* you may reverse the line */
#define	EL	248		/* erase the current line */
#define	EC	247		/* erase the current character */
#define	AYT	246		/* are you there */
#define	AO	245		/* abort output--but let prog finish */
#define	IP	244		/* interrupt process--permanently */
#define	BREAK	243		/* break */
#define	DM	242		/* data mark--for connect. cleaning */
#define	NOP	241		/* nop */
#define	SE	240		/* end sub negotiation */
#define	EOR	239		/* end of record (transparent mode) */
#define	ABORT	238		/* Abort process */
#define	SUSP	237		/* Suspend process */
#define	xEOF	236		/* End of file: EOF is already used... */

#define	SYNCH	242		/* for telfunc calls */

#ifdef TELCMDS
char *telcmds[] = {
	"EOF", "SUSP", "ABORT", "EOR",
	"SE", "NOP", "DMARK", "BRK", "IP", "AO", "AYT", "EC",
	"EL", "GA", "SB", "WILL", "WONT", "DO", "DONT", "IAC", 0
};
#endif

#define	TELCMD_FIRST	xEOF
#define	TELCMD_LAST	IAC
#define	TELCMD_OK(x)	((unsigned int)(x) <= TELCMD_LAST && \
			    (unsigned int)(x) >= TELCMD_FIRST)
#define	TELCMD(x)	telcmds[(x)-TELCMD_FIRST]

/* telnet options */
#define	TELOPT_BINARY	0	/* 8-bit data path */
#define	TELOPT_ECHO	1	/* echo */
#define	TELOPT_RCP	2	/* prepare to reconnect */
#define	TELOPT_SGA	3	/* suppress go ahead */
#define	TELOPT_NAMS	4	/* approximate message size */
#define	TELOPT_STATUS	5	/* give status */
#define	TELOPT_TM	6	/* timing mark */
#define	TELOPT_RCTE	7	/* remote controlled transmission and echo */
#define	TELOPT_NAOL	8	/* negotiate about output line width */
#define	TELOPT_NAOP	9	/* negotiate about output page size */
#define	TELOPT_NAOCRD	10	/* negotiate about CR disposition */
#define	TELOPT_NAOHTS	11	/* negotiate about horizontal tabstops */
#define	TELOPT_NAOHTD	12	/* negotiate about horizontal tab disposition */
#define	TELOPT_NAOFFD	13	/* negotiate about formfeed disposition */
#define	TELOPT_NAOVTS	14	/* negotiate about vertical tab stops */
#define	TELOPT_NAOVTD	15	/* negotiate about vertical tab disposition */
#define	TELOPT_NAOLFD	16	/* negotiate about output LF disposition */
#define	TELOPT_XASCII	17	/* extended ascic character set */
#define	TELOPT_LOGOUT	18	/* force logout */
#define	TELOPT_BM	19	/* byte macro */
#define	TELOPT_DET	20	/* data entry terminal */
#define	TELOPT_SUPDUP	21	/* supdup protocol */
#define	TELOPT_SUPDUPOUTPUT 22	/* supdup output */
#define	TELOPT_SNDLOC	23	/* send location */
#define	TELOPT_TTYPE	24	/* terminal type */
#define	TELOPT_EOR	25	/* end or record */
#define	TELOPT_TUID	26	/* TACACS user identification */
#define	TELOPT_OUTMRK	27	/* output marking */
#define	TELOPT_TTYLOC	28	/* terminal location number */
#define	TELOPT_3270REGIME 29	/* 3270 regime */
#define	TELOPT_X3PAD	30	/* X.3 PAD */
#define	TELOPT_NAWS	31	/* window size */
#define	TELOPT_TSPEED	32	/* terminal speed */
#define	TELOPT_LFLOW	33	/* remote flow control */
#define	TELOPT_LINEMODE	34	/* Linemode option */
#define	TELOPT_XDISPLOC	35	/* X Display Location */
#define	TELOPT_OLD_ENVIRON 36	/* Old - Environment variables */
#define	TELOPT_AUTHENTICATION 37 /* Authenticate */
#define	TELOPT_ENCRYPT	38	/* Encryption option */
#define	TELOPT_NEW_ENVIRON 39	/* New - Environment variables */
#define	TELOPT_EXOPL	255	/* extended-options-list */

#ifdef TELOPTS
#define	NTELOPTS	(1+TELOPT_NEW_ENVIRON)
char *telopts[NTELOPTS+1] = {
	"BINARY", "ECHO", "RCP", "SUPPRESS GO AHEAD", "NAME",
	"STATUS", "TIMING MARK", "RCTE", "NAOL", "NAOP",
	"NAOCRD", "NAOHTS", "NAOHTD", "NAOFFD", "NAOVTS",
	"NAOVTD", "NAOLFD", "EXTEND ASCII", "LOGOUT", "BYTE MACRO",
	"DATA ENTRY TERMINAL", "SUPDUP", "SUPDUP OUTPUT",
	"SEND LOCATION", "TERMINAL TYPE", "END OF RECORD",
	"TACACS UID", "OUTPUT MARKING", "TTYLOC",
	"3270 REGIME", "X.3 PAD", "NAWS", "TSPEED", "LFLOW",
	"LINEMODE", "XDISPLOC", "OLD-ENVIRON", "AUTHENTICATION",
	"ENCRYPT", "NEW-ENVIRON",
	0,
};
#endif /* TELOPTS */
#define	TELOPT_FIRST	TELOPT_BINARY
#define	TELOPT_LAST	TELOPT_NEW_ENVIRON
#define	TELOPT_OK(x)	((unsigned int)(x) <= TELOPT_LAST)
#define	TELOPT(x)	telopts[(x)-TELOPT_FIRST]

/* sub-option qualifiers */
#define	TELQUAL_IS	0	/* option is... */
#define	TELQUAL_SEND	1	/* send option */
#define	TELQUAL_INFO	2	/* ENVIRON: informational version of IS */
#define	TELQUAL_REPLY	2	/* AUTHENTICATION: client version of IS */
#define	TELQUAL_NAME	3	/* AUTHENTICATION: client version of IS */

#define	LFLOW_OFF		0	/* Disable remote flow control */
#define	LFLOW_ON		1	/* Enable remote flow control */
#define	LFLOW_RESTART_ANY	2	/* Restart output on any char */
#define	LFLOW_RESTART_XON	3	/* Restart output only on XON */

/*
 * LINEMODE suboptions
 */

#define	LM_MODE		1
#define	LM_FORWARDMASK	2
#define	LM_SLC		3

#define	MODE_EDIT	0x01
#define	MODE_TRAPSIG	0x02
#define	MODE_ACK	0x04
#define	MODE_SOFT_TAB	0x08
#define	MODE_LIT_ECHO	0x10

#define	MODE_MASK	0x1f

/* Not part of protocol, but needed to simplify things... */
#define	MODE_FLOW		0x0100
#define	MODE_ECHO		0x0200
#define	MODE_INBIN		0x0400
#define	MODE_OUTBIN		0x0800
#define	MODE_FORCE		0x1000

#define	SLC_SYNCH	1
#define	SLC_BRK		2
#define	SLC_IP		3
#define	SLC_AO		4
#define	SLC_AYT		5
#define	SLC_EOR		6
#define	SLC_ABORT	7
#define	SLC_EOF		8
#define	SLC_SUSP	9
#define	SLC_EC		10
#define	SLC_EL		11
#define	SLC_EW		12
#define	SLC_RP		13
#define	SLC_LNEXT	14
#define	SLC_XON		15
#define	SLC_XOFF	16
#define	SLC_FORW1	17
#define	SLC_FORW2	18

#define	NSLC		18

/*
 * For backwards compatability, we define SLC_NAMES to be the
 * list of names if SLC_NAMES is not defined.
 */
#define	SLC_NAMELIST	"0", "SYNCH", "BRK", "IP", "AO", "AYT", "EOR", \
			"ABORT", "EOF", "SUSP", "EC", "EL", "EW", "RP", \
			"LNEXT", "XON", "XOFF", "FORW1", "FORW2", 0,
#ifdef	SLC_NAMES
char *slc_names[] = {
	SLC_NAMELIST
};
#else
extern char *slc_names[];
#define	SLC_NAMES SLC_NAMELIST
#endif

#define	SLC_NAME_OK(x)	((unsigned int)(x) <= NSLC)
#define	SLC_NAME(x)	slc_names[x]

#define	SLC_NOSUPPORT	0
#define	SLC_CANTCHANGE	1
#define	SLC_VARIABLE	2
#define	SLC_DEFAULT	3
#define	SLC_LEVELBITS	0x03

#define	SLC_FUNC	0
#define	SLC_FLAGS	1
#define	SLC_VALUE	2

#define	SLC_ACK		0x80
#define	SLC_FLUSHIN	0x40
#define	SLC_FLUSHOUT	0x20

#define	OLD_ENV_VAR	1
#define	OLD_ENV_VALUE	0
#define	NEW_ENV_VAR	0
#define	NEW_ENV_VALUE	1
#define	ENV_ESC		2
#define	ENV_USERVAR	3

/*
 * AUTHENTICATION suboptions
 */
#define	AUTH_REJECT	0	/* Rejected */
#define	AUTH_UNKNOWN	1	/* We don't know who it is, but it's okay */
#define	AUTH_OTHER	2	/* We know it, but not it's name */
#define	AUTH_USER	3	/* We know it's name */
#define	AUTH_VALID	4	/* We know it, and it needs no password */

/*
 * Who is authenticating who ...
 */
#define	AUTH_WHO_CLIENT		0	/* Client authenticating server */
#define	AUTH_WHO_SERVER		1	/* Server authenticating client */
#define	AUTH_WHO_MASK		1

#ifdef	AUTHWHO_STR
char *authwho_str[] = {
	"CLIENT", "SERVER" };
#define	AUTHWHO_NAME(x)	authwho_str[x]
#endif /* AUTHWHO_STR */

/*
 * amount of authentication done
 */
#define	AUTH_HOW_ONE_WAY	0
#define	AUTH_HOW_MUTUAL		2
#define	AUTH_HOW_MASK		2

/*
 * should we be encrypting? (not yet formally standardized)
 */
#define	AUTH_ENCRYPT_OFF	0
#define	AUTH_ENCRYPT_ON		4
#define	AUTH_ENCRYPT_MASK	4

#define	AUTHTYPE_NULL		0
#define	AUTHTYPE_KERBEROS_V4	1	/* not supported */
#define	AUTHTYPE_KERBEROS_V5	2
#define	AUTHTYPE_CNT		3

#define	OPTS_FORWARD_CREDS		0x00000002
#define	OPTS_FORWARDABLE_CREDS		0x00000001

#ifdef AUTHTYPE_NAMES
char *authtype_names[] = {
	"NULL", "KERBEROS_V4", "KERBEROS_V5", 0,
};
#else
extern char *authtype_names[];
#endif /* AUTHTYPE_NAMES */

#define	AUTHTYPE_NAME(x)	authtype_names[x]
#define	AUTHTYPE_NAME_OK(x)	((unsigned int)(x) < AUTHTYPE_CNT)

#ifdef AUTHHOW_NAMES
char *authhow_names[] = {
	"ONE-WAY", "[undefined]", "MUTUAL" };
#endif /* AUTHHOW_NAMES */

#define	AUTHHOW_NAME(x)		authhow_names[x]

#define	KRB_AUTH		0	/* Authentication data follows */
#define	KRB_REJECT		1	/* Rejected (reason might follow) */
#define	KRB_ACCEPT		2	/* Accepted */
#define	KRB_RESPONSE		3	/* Response for mutual auth. */
#define	KRB_FORWARD		4	/* Forwarded credentials follow */
#define	KRB_FORWARD_ACCEPT	5	/* Forwarded credentials accepted */
#define	KRB_FORWARD_REJECT	6	/* Forwarded credentials rejected */

#ifdef AUTHRSP_NAMES
char *authrsp_names[] = {
	"AUTH", "REJECT", "ACCEPT", "RESPONSE", "FORWARD",
	"FORWARD_ACCEPT", "FORWARD_REJECT" };
#define	AUTHRSP_NAME(x)		authrsp_names[x]
#endif /* AUTHRSP_NAMES */

#define	AUTH_MODE_REQUIRE	0
#define	AUTH_MODE_PROMPT	1
#define	AUTH_MODE_WARN		2
#define	AUTH_MODE_REJECT	3


/*
 * Encryption suboptions. See RFC 2946.
 */
#define	ENCRYPT_IS		0	/* I pick encryption type ... */
#define	ENCRYPT_SUPPORT		1	/* I support encryption types ... */
#define	ENCRYPT_REPLY		2	/* Initial setup response */
#define	ENCRYPT_START		3	/* Starting encrypting output */
#define	ENCRYPT_END		4	/* End encrypting output */
#define	ENCRYPT_REQSTART	5	/* Request to start encrypting output */
#define	ENCRYPT_REQEND		6	/* Request to stop encrypting output */
#define	ENCRYPT_ENC_KEYID	7	/* Negotiate encryption key */
#define	ENCRYPT_DEC_KEYID	8	/* Negotiate decryption key */
#define	ENCRYPT_CNT		9	/* marks the maximum ENCRYPT value */

#define	TELOPT_ENCTYPE_NULL		0
#define	TELOPT_ENCTYPE_DES_CFB64	1 /* 64-bit Cipher Feedback Mode */
#define	TELOPT_ENCTYPE_CNT		2

#define	CFB64_IV	1
#define	CFB64_IV_OK	2
#define	CFB64_IV_BAD	3

#define	FB64_IV		CFB64_IV
#define	FB64_IV_OK	CFB64_IV_OK
#define	FB64_IV_BAD	CFB64_IV_BAD

#ifdef ENCRYPT_NAMES
char *encrypt_names[] = {
	"IS", "SUPPORT", "REPLY", "START", "END",
	"REQUEST-START", "REQUEST-END", "ENC-KEYID", "DEC-KEYID",
	0,
};

char *enctype_names[] = {
	"ANY", "DES_CFB64", 0,
};
#else
extern char *encrypt_names[];
extern char *enctype_names[];
#endif /* ENCRYPT_NAMES */

#define	ENCRYPT_NAME(x)		encrypt_names[x]
#define	ENCTYPE_NAME(x)		enctype_names[x]

#define	ENCRYPT_NAME_OK(x)	((unsigned int)(x) < ENCRYPT_CNT)
#define	ENCTYPE_NAME_OK(x)	((unsigned int)(x) < TELOPT_ENCTYPE_CNT)

#define	SK_DES	1 /* Matched Kerberos v5 ENCTYPE_DES */

#ifndef	DES_BLOCKSIZE
#define	DES_BLOCKSIZE  8
#endif	/* DES_BLOCKSIZE */

#define	TELNET_MAXNUMKEYS	64
#define	TELNET_MAXKEYIDLEN	16

#define	CFB 0

#define	ENCR_STATE_FAILED	-1
#define	ENCR_STATE_OK		0x00
#define	ENCR_STATE_NO_SEND_IV	0x01
#define	ENCR_STATE_NO_RECV_IV	0x02
#define	ENCR_STATE_NO_KEYID	0x04
#define	ENCR_STATE_NOT_READY	0x08
#define	ENCR_STATE_IN_PROGRESS \
	(ENCR_STATE_NO_SEND_IV|ENCR_STATE_NO_RECV_IV|ENCR_STATE_NO_KEYID)
#define	TELNET_DIR_ENCRYPT	0
#define	TELNET_DIR_DECRYPT	1

typedef unsigned char Block[DES_BLOCKSIZE];
typedef unsigned char *BlockT;
typedef struct { Block _; } Schedule[16];

typedef struct {
	short		type;
	int		length;
	unsigned char	*data;
} Session_Key;

typedef struct {
	unsigned char	need_start;
	unsigned char	autoflag;	/* automatically start operation */
	unsigned char	setup;
	unsigned char	type;
	unsigned int	state;
	unsigned char	keyid[TELNET_MAXNUMKEYS];
	int		keyidlen;
	Block		ivec;
	Block		krbdes_key;
} cipher_info_t;

typedef struct {
	cipher_info_t encrypt;
	cipher_info_t decrypt;
} telnet_enc_data_t;

/* A valid key has no "0" bytes */
#define	VALIDKEY(key)	(key[0] | key[1] | key[2] | key[3] | \
		key[4] | key[5] | key[6] | key[7])


#ifdef	__cplusplus
}
#endif

#endif	/* _ARPA_TELNET_H */
