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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * data base routines for the network listener process
 */

/* system include files	*/

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/tiuser.h>
#include <sys/stropts.h>

/* listener include files */

#include "lsparam.h"		/* listener parameters		*/
#include "listen.h"		/* listener includes 		*/
#include "lsfiles.h"		/* listener files info		*/
#include "lserror.h"		/* listener error codes		*/
#include "lsdbf.h"		/* data base file stuff		*/
/* #include "nsaddr.h"		nls includes			*/

#define SUPPRESS	1	/* suppress messages during scan*/
#define NOSUPPRESS	0	/* don't suppress messages 	*/

/* static data		*/

static char *dbfopenmsg = "Trouble opening data base file";
static char *dbfrderror = "Error reading data base file: line %d";
static char *dbfbadlmsg = "Data base file: Error on line %d";
static char *dbfdupcmsg = "Data base file: Duplicate service code: <%s>";
static char *dbfunknown = "Unknown error reading data base file: line %d";
static char *dbfsvccmsg = "Data base file: Illegal service code: <%s>";
static char *dbfcorrupt = "Data base file has been corrupted";

static int   Dbflineno;		/* current line number in dbf		*/
static unsigned Dbfentries;	/* number of non-comment lines		*/
extern char  *Server_cmd_lines; /* contains svc_code, cmd_line, mod_list */
extern char  *New_cmd_lines; /* svc_code, cmd_line, mod_list (on reread)*/

/* public variables */


/*
 * read_dbf:
 *
 * read the data base file into internal structures
 *
 * all data base routines under read_dbf log there own errors and return -1
 * in case of an error.
 *
 * if 're_read' is non-zero, this stuff is being called to read a new 
 * data base file after the listener's initialization.
 */

int
read_dbf(re_read)
int	re_read;	/* zero means first time	*/
{
	register unsigned size;
	int exit_flag = EXIT | NOCORE;
	register dbf_t *dbf_p;
	register char  *cmd_p;
	unsigned scan_dbf();
	extern dbf_t *Dbfhead;		/* Dbfentries (when allocated)	*/
	extern dbf_t *Newdbf;		/* Dbfentries (on re-read)	*/
	extern char *calloc();

	DEBUG((9,"in read_dbf"));

	if (check_version())
		error(E_BADVER, EXIT | NOCORE);

	if (re_read)	{			/* not first time */
		exit_flag = CONTINUE;
	}

	/*
	 * note: data base routines log their own error messages
	 */

	Dbfentries = 0;
	DEBUG((9,"read_dbf: open file here:  %s", DBFNAME));
	if ( (size = scan_dbf(DBFNAME)) == (unsigned)(-1) )
		error( E_SCAN_DBF, exit_flag | NO_MSG );

	DEBUG((5,"read_dbf: scan complete: non-commented lines: %u, size: %u",
		Dbfentries, size));

	if (!size)  {
		logmessage("No database?  0 entries?");
		return(0);
	}

	/*
	 * allocate enough space for Dbfentries of 'size' bytes (total)
	 * The +1 is to insure a NULL last entry!
	 */

	if (!(dbf_p = (dbf_t *)calloc(Dbfentries+1,sizeof(dbf_t)))
	   || !(cmd_p = calloc(size, 1)))  {
		DEBUG((1,"cannot calloc %u + %u bytes", size,
			(Dbfentries+1)*(unsigned)sizeof(dbf_t)));
		error( E_DBF_ALLOC, exit_flag);	/* if init, exit */	 

		/* if still here, this is a re-read	*/	

		if (dbf_p)
			free(dbf_p);
		if (cmd_p)
			free(cmd_p);
		return(-1);
	}

	if (get_dbf(dbf_p, cmd_p))  {
		DEBUG((9, "get_dbf FAILED"));
		error(E_DBF_IO, exit_flag | NO_MSG);

		/* if still here, this is a re_read */
		free(dbf_p);     
		free(cmd_p);		
		return(-1);
	}

	if (re_read)  {
		Newdbf = dbf_p;
		New_cmd_lines = cmd_p;
#ifdef	DEBUGMODE
		DEBUG((7,"read_dbf: NEW data base dump..."));
		if (Newdbf)
			for (dbf_p = Newdbf; dbf_p->dbf_svc_code; ++dbf_p)
				DEBUG((7, "svc code <%s>; id: %s; private address: %s; modules: %s; cmd line: %s; sflags: %x, prognum: %d version: %d",
				dbf_p->dbf_svc_code, dbf_p->dbf_id, dbf_p->dbf_prv_adr, dbf_p->dbf_modules, dbf_p->dbf_cmd_line, dbf_p->dbf_sflags, dbf_p->dbf_prognum, dbf_p->dbf_version));
#endif	/* DEBUGMODE */
	}
	else {
		Dbfhead = dbf_p;
		Server_cmd_lines = cmd_p;
#ifdef	DEBUGMODE
		DEBUG((7,"read_dbf: data base dump..."));
		if (Dbfhead)
			for (dbf_p = Dbfhead; dbf_p->dbf_svc_code; ++dbf_p)
				DEBUG((7, "svc code <%s>; id: %s; r1: %s; r2: %s; r3: %s; private address: %s; modules: %s; cmd line: %s; sflags: %x, prognum: %d version: %d",
				dbf_p->dbf_svc_code, dbf_p->dbf_id, dbf_p->dbf_res1, dbf_p->dbf_res2, dbf_p->dbf_res3, dbf_p->dbf_prv_adr, dbf_p->dbf_modules, dbf_p->dbf_cmd_line, dbf_p->dbf_sflags, dbf_p->dbf_prognum, dbf_p->dbf_version));
#endif	/* DEBUGMODE */
	}

	return(0);
}


/*
 * get_dbf: read the file and fill the structures
 *	    checking for duplicate entries as we go
 */

int
get_dbf(dbf_p, cmd_p)
register dbf_t *dbf_p;
register char *cmd_p;
{
	dbf_t *dbfhead = dbf_p;
	register int n, i;
	char buf[DBFLINESZ];
	register char *p = buf;
	char scratch[128];
	FILE *dbfilep;
	char *cmd_line_p;
	int flags;
	char *svc_code_p;
	char *id_p;
	char *res1_p;
	char *res2_p;
	char *res3_p;
	char *private_p;
	int sflags;
	int prognum;
	int vernum;
	char *module_p;
	register dbf_t *tdbf_p;
	extern int atoi();
	extern int Dbf_entries;
	extern int NLPS_proc;
	extern int errno;

	Dbflineno = 0;
	Dbf_entries = 0;  /* number of private addresses in dbf file */

	DEBUG((9,"in get_dbf: "));
	if (!(dbfilep = fopen(DBFNAME,"r")))  {
		logmessage(dbfopenmsg);
		error(E_DBF_IO, EXIT | NOCORE | NO_MSG);
	}

	while (n = rd_dbf_line(dbfilep,p,&svc_code_p,&flags,&id_p,&res1_p,&res2_p,&res3_p,&private_p,&prognum,&vernum,&module_p,&sflags,&cmd_line_p,NOSUPPRESS))  {

		if (n == -1)  {			/* read error	*/
			fclose(dbfilep);
			return(-1);
		}

		/* make sure service code is legal 			*/

		i = strlen(svc_code_p);
		if ( (i == 0) || (i >= SVC_CODE_SZ) )
			goto reject;

		/* check for duplicate service code			*/
		tdbf_p = dbfhead;
		while (tdbf_p->dbf_svc_code)  {	/* duplicate svc code?	*/
			if (!strcmp(svc_code_p, tdbf_p->dbf_svc_code))  {
				sprintf(scratch, dbfdupcmsg, svc_code_p);
				logmessage(scratch);
				return(-1);
			}
			++tdbf_p;
		}

		/* NLPS_proc is set by the nlps_server, which also uses these
		 * routines.  The actual listener child shouldn't ever need
		 * to read a database, so it will never be here
		 */
		if (!NLPS_proc && (strlen(private_p) == 0) && !(sflags & DFLAG))
			continue;	/* ignore entries with no address */

		/*
		 * child doesn't care about private addresses
		 */

		if (!NLPS_proc) {
			i = strlen(private_p);
			if (i >= PRV_ADR_SZ) {
				goto p_reject;
			}	
			Dbf_entries++;
		} 

		/*
		 * legal, non-duplicate entry: copy it into internal data base
		 */

		dbf_p->dbf_fd = -1;	/* set to actual fd in add_prvaddr */
		dbf_p->dbf_flags = flags;
		dbf_p->dbf_sflags = sflags;
		dbf_p->dbf_prognum = prognum;
		dbf_p->dbf_version = vernum;
		strcpy(cmd_p, svc_code_p);
		dbf_p->dbf_svc_code = cmd_p;
		cmd_p += strlen(svc_code_p) + 1;	/* +1 for null */
		strcpy(cmd_p, cmd_line_p);
		dbf_p->dbf_cmd_line = cmd_p;
		cmd_p += strlen(cmd_line_p) + 1;
		strcpy(cmd_p, id_p);
		dbf_p->dbf_id = cmd_p;
		cmd_p += strlen(id_p) + 1;
		strcpy(cmd_p, res1_p);
		dbf_p->dbf_res1 = cmd_p;
		cmd_p += strlen(res1_p) + 1;
		strcpy(cmd_p, res2_p);
		dbf_p->dbf_res2 = cmd_p;
		cmd_p += strlen(res2_p) + 1;
		strcpy(cmd_p, res3_p);
		dbf_p->dbf_res3 = cmd_p;
		cmd_p += strlen(res3_p) + 1;
		if (strlen(private_p) != 0) {
			strcpy(cmd_p, private_p);
			dbf_p->dbf_prv_adr = cmd_p;
			cmd_p += strlen(private_p) + 1;	
		}
		else
			dbf_p->dbf_prv_adr = NULL;
		strcpy(cmd_p, module_p);
		dbf_p->dbf_modules = cmd_p;
		cmd_p += strlen(module_p) + 1;	/* cmd line + null char */
		++dbf_p;
	}

	fclose(dbfilep);
	return(0);

reject:
	DEBUG((9, "svc_code <%s> failed validation test", svc_code_p));
	sprintf(scratch, dbfsvccmsg, svc_code_p);
	logmessage(scratch);
	return(-1);
p_reject:
	DEBUG((9,"private address <%s> failed validation test", private_p));
	sprintf(scratch, "Invalid private address ignored: \\x%x", private_p);
	logmessage(scratch);
	return(-1);
}


/*
 * scan_dbf:	Take a quick pass through the data base file to figure out
 *		approx. how many items in the file we'll need to 
 *		allocate storage for.  Essentially, returns the number
 *		of non-null, non-comment lines in the data base file.
 *
 *		return: -1 == error.
 *			other == number of non-comment characters.
 *			Dbfentries set.
 */

unsigned
scan_dbf(path)
register char *path;
{
	register unsigned int size = 0;
	register int n;
	register FILE *dbfilep;
	char buf[DBFLINESZ];
	register char *p = buf;
	char *svc_code_p;
	int flags;
	char *cmd_line_p;
	char *module_p;
	char *id_p;
	char *res1_p;
	char *res2_p;
	char *res3_p;
	int sflags;
	int prognum;
	int vernum;
	char *private_p;
	extern int errno;

	DEBUG((9, "In scan_dbf.  Scanning data base file %s.", path));

	if (!(dbfilep = fopen(path,"r")))  {
		DEBUG((9,"errorno = %d", errno));
		logmessage(dbfopenmsg);
		return(-1);
	}

	do {
		n = rd_dbf_line(dbfilep,p,&svc_code_p,&flags,&id_p,&res1_p,&res2_p,&res3_p,&private_p,&prognum,&vernum,&module_p,&sflags,&cmd_line_p,SUPPRESS);
		if (n == -1)  {
			fclose(dbfilep);
			return(-1);
		}
		size += (unsigned)n;
		if (n)
			++Dbfentries;
	} while (n);

	fclose(dbfilep);
	return(size);
}


/*
 * rd_dbf_line:	Returns the next non-comment line into the
 *		given buffer (up to DBFLINESZ bytes).
 *		Skips 'ignore' lines.
 *
 *		Returns:	0 = done, -1 = error, 
 * 				other = cmd line size incl. terminating null.
 *				*svc_code_p = service code;
 *				*id_p = user id string;
 *				*res1_p = reserved string;
 *				*res2_p = reserved string;
 *				*res3_p = reserved string;
 *				*private_p = contains private address;
 *				*flags_p = decoded flags;
 *				prognum = RPC program #;
 *				vernum = RPC version $;
 *				cnd_line_p points to null terminated cmd line;
 *
 * When logging errors, the extern Dbflineno is used.
 */

int
rd_dbf_line(fp, bp, svc_code_p, flags_p, id_p, res1_p, res2_p, res3_p, private_p, prognum, vernum, module_p, sflags, cmd_line_p, mflag)
register FILE *fp;
register char *bp;
char **svc_code_p;
int *flags_p;
char **id_p;
char **res1_p;
char **res2_p;
char **res3_p;
char **private_p;
int *prognum;
int *vernum;
char **module_p;
int *sflags;
char **cmd_line_p;
int mflag;
{
	register int length;
	register char *p;

	do {
		++Dbflineno;
		length = 0;

		if (!fgets(bp, DBFLINESZ, fp))  {
			if (feof(fp))  {
				return(0);	/* EOF	*/
			}
			if (ferror(fp))  {
				sprintf(bp,dbfrderror,Dbflineno);
				logmessage(bp);
				return(-1);
			}
			sprintf(bp,dbfunknown,Dbflineno);
			logmessage(bp);
			return(-1);		/* Unknown error (?)	*/
		}

		if (*(bp+strlen(bp)-1) != '\n')  {  /* terminating newline? */
			sprintf(bp, dbfbadlmsg, Dbflineno);
			logmessage(bp);
			return(-1);
		}

		*(bp + strlen(bp) -1) = (char)0; /* delete newline	*/

		if (strlen(bp) && (p = strchr(bp, DBFCOMMENT)))
			*p = (char)0;		/* delete comments	*/
		if (!strlen(bp))
			continue;

		p = bp + strlen(bp) - 1;	/* bp->start; p->end	*/
		while ((p != bp) && (isspace(*p)))  {
			*p = (char)0;		/* delete terminating spaces */
			--p;
		}

		while (*bp)			/* del beginning white space*/
			if (isspace(*bp))
				++bp;
			else
				break;

		if (strlen(bp)) {		/* anything left?	*/

		   if (!(length=scan_line(bp,svc_code_p,flags_p,id_p,res1_p,res2_p,res3_p,private_p,prognum,vernum,module_p,sflags,cmd_line_p,mflag))) {

			DEBUG((1, "rd_dbf_line line %d, error while scanning entry",
			  Dbflineno));
			sprintf(bp, dbfbadlmsg, Dbflineno);
			logmessage(bp);
			return(-1);
		    }
		}

	}  while (!length);		/* until we have something */

	DEBUG((5,"rd_dbf_line: line: %d,cmd line len: %d",Dbflineno, length+1));

	return(length+1); /* +1 for the trailing NULL */

}


/*
 * scan a non-white space line
 *		0 = error;
 *		other = length of cmd line;
 *
 *	non-null lines have the following format:
 *
 *	service_code: flags: id: res1: res2: res3: private address: rpcdata: sflags: modules: cmd_line # comments
 *
 * mflag is set to suppress messages (scan_line is called both for parsing
 * and counting, messages should only be output once)
 */

int
scan_line(bp, svc_code_p, flags_p, id_p, res1_p, res2_p, res3_p, private_p, prognum, vernum, module_p, sflags, cmd_line_p, mflag)
register char *bp;
char **svc_code_p;
register int *flags_p;
char **id_p;
char **res1_p;
char **res2_p;
char **res3_p;
char **private_p;
int *prognum;
int *vernum;
char **module_p;
int *sflags;
register char **cmd_line_p;
int mflag;
{
	register char *p;
	register char *nexttok;
	register char *ptr;
	int sawsep = 0;
	char scratch[BUFSIZ];

	*flags_p = 0;

	if (!(p = strchr(bp, DBFTOKSEP ))) {	/* look for service code string */
		DEBUG((9,"scan_line failed svc_code strchr"));
		return(0);
	}
	*p = '\0';
	*svc_code_p = bp;
	nexttok = ++p;

	if (!(p = strchr(nexttok, DBFTOKSEP )))  {
		DEBUG((9,"scan_line failed flags strchr"));
		return(0);
	}
	*p = '\0';

	while (*nexttok)  {
		switch (*nexttok)  {
		case 'x':		/* service is turned off	*/
		case 'X':
			*flags_p |= DBF_OFF;
			break;
		case 'u':		/* create utmp entry		*/
			*flags_p |= DBF_UTMP;
			break;
		default:
			DEBUG((1,"scan_line: unknown flag char: 0x%x",*nexttok));
			*flags_p = DBF_UNKNOWN;
			break;
		}
		++nexttok;
	}
	nexttok = ++p;

	if (!(p = strchr(nexttok, DBFTOKSEP ))) {
		DEBUG((9,"scan_line failed id strchr"));
		return(0);
	}
	*p = '\0';
	*id_p = nexttok;
	nexttok = ++p;

	if (!(p = strchr(nexttok, DBFTOKSEP ))) {
		DEBUG((9,"scan_line failed res1 strchr"));
		return(0);
	}
	*p = '\0';
	*res1_p = nexttok;
	nexttok = ++p;

	if (!(p = strchr(nexttok, DBFTOKSEP ))) {
		DEBUG((9,"scan_line failed res2 strchr"));
		return(0);
	}
	*p = '\0';
	*res2_p = nexttok;
	nexttok = ++p;

	if (!(p = strchr(nexttok, DBFTOKSEP ))) {
		DEBUG((9,"scan_line failed res3 strchr"));
		return(0);
	}
	*p = '\0';
	*res3_p = nexttok;
	nexttok = ++p;

	if (!(p = strchr(nexttok, DBFTOKSEP ))) {
		DEBUG((9,"scan_line failed private strchr"));
		return(0);
	}
	*p = '\0';
	*private_p = nexttok;
	nexttok = ++p;

	if (!(p = strchr(nexttok, DBFTOKSEP ))) {
		DEBUG((9,"scan_line failed rpc strchr"));
		return(0);
	}
	*p = '\0';

	*prognum = -1;
	*vernum = -1;
	if (*nexttok) {
		/* there is rpc info */
		for (ptr = nexttok; *ptr; ++ptr) {
			if ((*ptr == ',') && !sawsep) {
				/*
				 * skip separator - note that if
				 * separator has been seen, it's not
				 * a digit so it will fail below
				 */
				sawsep++;
				continue;
			}
			if (!isdigit(*ptr)) {
				sprintf(scratch, "service code <%s> specifies non-integer rpc info", *svc_code_p);
				logmessage(scratch);
				return(0);
			}
		}
		ptr = strchr(nexttok, ',');
		if (ptr) {
			if ((*prognum = atoi(nexttok)) < 0) {
				if (!mflag) {
					/* messages aren't suppressed */
					sprintf(scratch, "service code <%s> specifies negative program number", *svc_code_p);
					logmessage(scratch);
				}
				return(0);
			}
			if ((*vernum = atoi(ptr + 1)) < 0) {
				if (!mflag) {
					sprintf(scratch, "service code <%s> specifies negative version number", *svc_code_p);
					logmessage(scratch);
				}
				return(0);
			}
		}
		else {
			if (!mflag) {
				sprintf(scratch, "service code <%s> - invalid rpcinfo", *svc_code_p);
				logmessage(scratch);
			}
			return(0);
		}
	}
	nexttok = ++p;

	if (!(p = strchr(nexttok, DBFTOKSEP ))) {
		DEBUG((9,"scan_line failed sflags strchr"));
		return(0);
	}
	*p = '\0';

	*sflags = 0;
	while (*nexttok)  {
		switch (*nexttok)  {
		case 'c':	/* dbf_cmd_line is a command */
			*sflags |= CFLAG;
			break;
		case 'd':	/* dynamic address */
			if ((int) strlen(*private_p) > 0) {
				if (!mflag) {
					sprintf(scratch, "service code <%s> specifies static and dynamic address", *svc_code_p);
					logmessage(scratch);
					logmessage("  address info ignored");
				}
				/* don't set DFLAG and wipe out private addr */
				**private_p = '\0';
			}
			else {
				*sflags |= DFLAG;
			}
			break;
		case 'p':	/* dbf_cmd_line is a pipe */
			*sflags |= PFLAG;
			break;
		default:
			if (!mflag) {
				sprintf(scratch, "service code <%s> unknown flag <%c> ignored", *svc_code_p, *nexttok);
				logmessage(scratch);
			}
			break;
		}
		++nexttok;
	}
	nexttok = ++p;

	if (!(p = strchr(nexttok, DBFTOKSEP ))) {
		DEBUG((9,"scan_line failed module strchr"));
		return(0);
	}
	*p = '\0';
	*module_p = nexttok;
	nexttok = ++p;

	*cmd_line_p = nexttok;

	DEBUG((9,"scan_line: modules: %s; line: %s; len: %d", *module_p, *cmd_line_p, strlen(*svc_code_p)+strlen(*id_p)+strlen(*res1_p)+strlen(*res2_p)+strlen(*res3_p)+strlen(*private_p)+strlen(*module_p)+strlen(*cmd_line_p)+9));
	/*
	 * return the length of the buffer.  Add 9 for the NULLs after each
	 * string
	 */
	return(strlen(*svc_code_p)+strlen(*id_p)+strlen(*res1_p)+strlen(*res2_p)+strlen(*res3_p)+strlen(*private_p)+strlen(*module_p)+strlen(*cmd_line_p)+9);
}



#define VERSIONSTR	"# VERSION="

int
check_version(void)
{
	FILE *fp;
	char *line, *p, *tmp;
	int version;

	if ((fp = fopen(DBFNAME, "r")) == NULL) {
		logmessage(dbfopenmsg);
		error(E_DBF_IO, EXIT | NOCORE | NO_MSG);
	}
	if ((line = (char *) malloc(DBFLINESZ)) == NULL)
		error(E_DBF_ALLOC, EXIT | NOCORE);
	p = line;
	while (fgets(p, DBFLINESZ, fp)) {
		if (!strncmp(p, VERSIONSTR, strlen(VERSIONSTR))) {
			/* pitch the newline */
			tmp = strchr(p, '\n');
			if (tmp)
				*tmp = '\0';
			else {
				logmessage(dbfcorrupt);
				error(E_DBF_CORRUPT, EXIT | NOCORE);
			}
			p += strlen(VERSIONSTR);
			if (*p)
				version = atoi(p);
			else {
				logmessage(dbfcorrupt);
				error(E_DBF_CORRUPT, EXIT | NOCORE);
			}
			free(line);
			fclose(fp);
			if (version != VERSION)
				return(1);	/* wrong version */
			else
				return(0);	/* version ok */
		}
		p = line;
	}
	logmessage(dbfcorrupt);
	error(E_DBF_CORRUPT, EXIT | NOCORE);
	return(1);
}


/*
 * mkdbfargv:	Given a pointer to a dbf_t, construct argv
 *		for an exec system call.
 *		Warning: returns a pointer to static data which are
 *			 overritten by each call.
 *
 *		There is a practical limit of 50 arguments (including argv[0])
 *
 *		Warning: calling mkdbfargv destroys the data (by writing null
 *		characters via strtok) pointed to by dbp->dbf_cmd_line.
 */

static char *dbfargv[50];
static char *delim = " \t'\"";		/* delimiters */

char **
mkdbfargv(dbp)
register dbf_t	*dbp;
{
	register char **argvp = dbfargv;
	register char *p = dbp->dbf_cmd_line;
	char delch;
	register char *savep;
	register char *tp;
	char scratch[BUFSIZ];
	char *strpbrk();
#ifdef	DEBUGMODE
	register int i = 0;
#endif

	*argvp = 0;
	savep = p;
	while (p && *p) {
		if (p = strpbrk(p, delim)) {
			switch (*p) {
			case ' ':
			case '\t':
				/* "normal" cases */
				*p++ = '\0';
				*argvp++ = savep;
				DEBUG((9, "argv[%d] = %s", i++, savep));
				/* zap trailing white space */
				while (isspace(*p))
					p++;
				savep = p;
				break;
			case '"':
			case '\'':
				/* found a string */
				delch = *p; /* remember the delimiter */
				savep = ++p;

/*
 * We work the string in place, embedded instances of the string delimiter,
 * i.e. \" must have the '\' removed.  Since we'd have to do a compare to
 * decide if a copy were needed, it's less work to just do the copy, even
 * though it is most likely unnecessary.
 */

				tp = p;
				for (;;) {
					if (*p == '\0') {
						sprintf(scratch, "invalid command line, non-terminated string for service code %s", dbp->dbf_svc_code);
						logmessage(scratch);
						exit(2); /* server, don't log */
					}
					if (*p == delch) {
						if (*(tp - 1) == '\\') { /* \delim */
							*(tp - 1) = *p;
							p++;
						}
						else { /* end of string */
							*tp = 0;
							*argvp++ = savep;
							DEBUG((9, "argv[%d] = %s", i++, savep));
							p++;
							/* zap trailing white space */
							while (isspace(*p))
								p++;
							savep = p;
							break;
						}
					}
					else {
						*tp++ = *p++;
					}
				}
				break;
			default:
				logmessage("Internal error in parse routine");
				exit(2); /* server, don't log */
			}
		}
		else {
			*argvp++ = savep;
			DEBUG((9, "argv[%d] = %s", i++, savep));
		}
	}
	*argvp = 0;
	return(dbfargv);
}



/*
 *
 * getentry: Given a fd, this routine will return a
 *		    dbf entry.  If the entry doesn't exist it will 
 *		    return NULL.
 */

dbf_t *
getentry(fd)
int	fd;
{
	extern dbf_t *Dbfhead;		/* Dbfentries (when allocated)	*/
	register dbf_t 	*dbp = Dbfhead;

	if (!Dbfhead) {		/* no private address in database file */
		DEBUG((9, "getdbfentry - nothing in Dbfhead = %s ",Dbfhead));
		return((dbf_t *)0);
	}
	else
		for (dbp = Dbfhead;  dbp->dbf_prv_adr;   ++dbp)
			if (fd == dbp->dbf_fd) {
				return(dbp);
			}

	return((dbf_t *)0);	/* requested private address not in list */

}


/*
 * pushmod:	push modules if defined in the data base entry.
 *
 *		WARNING: This routine writes into the in-memory copy
 *		of the database file.  Therefore, after it is called,
 *		the incore copy of the database file will no longer be valid.
 */

int
pushmod(fd, mp)
int fd;
register char *mp;
{
	register char *cp;
	register char *bufp = mp;
	char name[32];
	extern int errno;

	DEBUG((9,"in pushmod:"));
	if (!mp || *mp == '\0') {
		DEBUG((9,"NULL list: exiting pushmod"));
		return(0);
	}
	/* pop timod if it is on the stack */
	if (ioctl(fd, I_LOOK, name) >= 0) {
		if (strcmp(name, "timod") == 0) {
			if (ioctl(fd, I_POP, 0) < 0)
				DEBUG((9,"pushmod: I_POP failed"));
		}
	}
	while ((cp = strtok(bufp, ",")) != NULL) {
		bufp = NULL;
		DEBUG((9,"pushmod: about to push %s", cp));
		if (ioctl(fd, I_PUSH, cp) < 0) {
			DEBUG((9,"pushmod: ioctl failed, errno = %d",errno));
			return(1);
		}
	}
	DEBUG((9,"exiting pushmod:"));
	return(0);
}
