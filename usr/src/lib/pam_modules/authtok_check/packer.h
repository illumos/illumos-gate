/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _PACKER_H
#define	_PACKER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This program is copyright Alec Muffett 1993. The author disclaims all
 * responsibility or liability with respect to it's usage or its effect
 * upon hardware or computer systems, and maintains copyright as set out
 * in the "LICENCE" document which accompanies distributions of Crack v4.0
 * and upwards.
 */

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <synch.h>
#include <syslog.h>

#define	PWADMIN		"/etc/default/passwd"
#define	TRUNCSTRINGSIZE	(PATH_MAX/4)
#define	STRINGSIZE	PATH_MAX

typedef unsigned char int8;
typedef unsigned short int int16;
typedef unsigned long int int32;
#ifndef NUMWORDS
#define	NUMWORDS 	16
#endif
#define	MAXWORDLEN	32
#define	MAXBLOCKLEN 	(MAXWORDLEN * NUMWORDS)

struct pi_header
{
	int32 pih_magic;
	int32 pih_numwords;
	int16 pih_blocklen;
	int16 pih_pad;
};

typedef struct
{
	FILE *ifp;
	FILE *dfp;
	FILE *wfp;

	int32 flags;
#define	PFOR_WRITE	0x0001
#define	PFOR_FLUSH	0x0002
#define	PFOR_USEHWMS	0x0004

	int32 hwms[256];

	struct pi_header header;

	int count;
	char data[NUMWORDS][MAXWORDLEN];
} PWDICT;

#define	PW_WORDS(x) ((x)->header.pih_numwords)
#define	PIH_MAGIC 0x70775631

void PWRemove(char *);
PWDICT *PWOpen(char *, char *);
char *Mangle(char *, char *);

#define	CRACK_TOLOWER(a) 	(isupper(a)?tolower(a):(a))
#define	CRACK_TOUPPER(a) 	(islower(a)?toupper(a):(a))
#define	STRCMP(a, b)		strcmp((a), (b))

char	*Trim(register char *);
int32	FindPW(PWDICT *, char *);
int	PWClose(PWDICT *);
int	PutPW(PWDICT *, char *);
char	Chop(register char *);
char	Chomp(register char *);
char	*GetPW(PWDICT *, int32);

#define	DATABASE_OPEN_FAIL		-1
#define	DICTIONARY_WORD			2
#define	REVERSE_DICTIONARY_WORD		3


/* Dictionary database dir and prefix */

#define	CRACK_DIR		"/var/passwd"
#define	CRACK_DICTPATH		"/var/passwd/pw_dict"
#define	DICT_DATABASE_HWM	"pw_dict.hwm"
#define	DICT_DATABASE_PWD	"pw_dict.pwd"
#define	DICT_DATABASE_PWI	"pw_dict.pwi"

int packer(char *, char *);
char *Reverse(char *);
char *Lowercase(char *);
int DictCheck(char *, char *);
int make_dict_database(char *, char *);
int build_dict_database(char *, char *);
int lock_db(char *);
void unlock_db();

/* Return values for dictionary database checks */

#define	NO_DICTDATABASE		1
#define	UPDATE_DICTDATABASE	2
#define	DICTFILE_ERR		-1
#define	DICTPATH_ERR		-2
#define	DICTDATABASE_BUILD_ERR	-3

#ifdef __cplusplus
}
#endif

#endif /* _PACKER_H */
