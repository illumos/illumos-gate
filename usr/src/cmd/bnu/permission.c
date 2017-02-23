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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef UUCHECK
#include "uucp.h"
#endif


/*  field array indexes for PERMISSIONS parameters */
#define U_LOGNAME	0
#define U_MACHINE	1
#define U_CALLBACK	2
#define U_REQUEST	3
#define U_SENDFILES	4
#define U_READPATH	5
#define U_WRITEPATH	6
#define U_NOREADPATH	7
#define U_NOWRITEPATH	8
#define U_MYNAME	9
#define U_COMMANDS	10
#define U_VALIDATE	11
#define U_PUBDIR	12
#define U_DIRECT	13
#define U_ALIAS		14
#define U_PATH		15
/*  NUMFLDS should be one more than the highest U_ value */
#define NUMFLDS		16

/* fields found in PERMISSIONS for requested system/login */
static char *_Flds[NUMFLDS];

/* keyword/value structure */
struct keywords {
	char* kword;
	int kvalue;
};
static struct keywords _Kwords[] = {
	{"LOGNAME", U_LOGNAME},
	{"MACHINE", U_MACHINE},
	{"CALLBACK", U_CALLBACK},
	{"REQUEST", U_REQUEST},
	{"SENDFILES", U_SENDFILES},
	{"READ", U_READPATH},
	{"WRITE", U_WRITEPATH},
	{"NOREAD", U_NOREADPATH},
	{"NOWRITE", U_NOWRITEPATH},
	{"MYNAME", U_MYNAME},
	{"COMMANDS", U_COMMANDS},
	{"VALIDATE", U_VALIDATE},
	{"PUBDIR", U_PUBDIR},
	{"DIRECT", U_DIRECT},
	{"ALIAS", U_ALIAS},
	{"PATH", U_PATH},
};

#define MAXCMDS		30
#define MAXPATHS	20

/* for all options on paths - read, write, noread, nowrite */
/* NB: all pointers assumed to point to static data */
static char *_RPaths[MAXPATHS+1];
static char *_WPaths[MAXPATHS+1];
static char *_NoRPaths[MAXPATHS+1];
static char *_NoWPaths[MAXPATHS+1];
static char *_Commands[MAXCMDS+1];
static char _Cmd_defaults[BUFSIZ];

/* option variables */
static int _Request;	/* TRUE can request, FALSE can not request files */
static int _Switch;	/* FALSE requires a call back to send any files */
static int _CallBack;	/* TRUE for call back for any transaction */
static int _NoSpool;	/* TRUE if delivering directly to destination file */
static char _MyName[MAXBASENAME+1];	/* Myname from PERMISSIONS file */
/* NB: _Pubdir and _Path assumed to point to dynamic data */
static char *_Pubdir = NULL;		/* PUBDIR from PERMISSIONS file */
static char *_Path = NULL;		/* PATH from PERMISSIONS file */

struct name_value
{
	char *name;
	char *value;
};

/* file pointer for PERMISSIONS */
static FILE *Fp = NULL;

/* functions */
extern char *next_token(), *nextarg();
extern int parse_tokens(), canPath(), mkdirs();
static void fillFlds();
static void fillList();
static int cmdMatch(), listMatch(), nameMatch(),
	userFind(), validateFind();

int
noSpool()
{
	return(_NoSpool);
}

/*
 * fill in fields for login name
 * name - the login id
 * rmtname - remote system name
 *
 * return:
 *	0 -> found login name
 *	FAIL -> did not find login
 */

int
logFind(name, rmtname)
char *name, *rmtname;
{
	int ret;
	DEBUG(5, "logFind called (name: %s, ", name);
	DEBUG(5, "rmtname: %s)\n", rmtname);

	ret = validateFind (rmtname);
	if (ret == SUCCESS) { /* found VALIDATE entry */
	    ret = userFind (name, rmtname, U_VALIDATE);
	    if (ret) {
		DEBUG(5, "machine/login match failed%s", "");
		return(FAIL);
	    }
	}
	else
	    ret = userFind (name, "", U_LOGNAME);

	DEBUG(7, "_Request (%s), ",
	    requestOK() ? "TRUE" : "FALSE");
	DEBUG(7, "_Switch (%s), ",
	    switchRole() ? "TRUE" : "FALSE");
	DEBUG(7, "_CallBack (%s), ",
	    callBack() ? "TRUE" : "FALSE");
	DEBUG(7, "_MyName (%s), ", _MyName);
	DEBUG(7, "_NoSpool (%s), ",
	    noSpool() ? "TRUE" : "FALSE");
	return(ret);
}

/*
 * fill in fields for machine name
 * return:
 *	0 -> found machine name
 *	FAIL -> did not find machine
 */

int
mchFind(name)
char *name;
{
	int i, ret;
	DEBUG(5, "mchFind called (%s)\n", name);
	if ( (ret = userFind (name, "", U_MACHINE)) == FAIL)
	    /* see if there is a default line */
	    (void) userFind ("OTHER", "", U_MACHINE);

	/*  mchFind is from MASTER mode - switch role is always ok */
	_Switch = TRUE;

	DEBUG(7, "_Request (%s), ",
	    requestOK() ? "TRUE" : "FALSE");
	DEBUG(7, "_Switch (%s), ",
	    switchRole() ? "TRUE" : "FALSE");
	DEBUG(7, "_CallBack (%s), ",
	    callBack() ? "TRUE" : "FALSE");
	DEBUG(7, "_MyName (%s), ", _MyName);
	DEBUG(7, "_NoSpool (%s), ",
	    noSpool() ? "TRUE" : "FALSE");
	for (i=0; _Commands[i] != NULL; i++)
	    DEBUG(7, "_Commands %s\n",  _Commands[i]);
	return(ret);
}

/*
 * this function will find a login name in the LOGNAME
 * field.
 * input:
 *	name	-> who the remote says they are
 * return:
 *	SUCCESS	-> found
 *	FAIL	-> not found
 */
static int
nameMatch(name, fld)
char *name, *fld;
{
	char *arg;

	if (fld == NULL)
	    return(FAIL);

	while (*fld) {
	    fld = nextarg(fld, &arg);
	    if (EQUALS(arg, name))
		return(SUCCESS);
	}
	return (FAIL);
}


/*
 * interpret the _Flds options and set the option variables
 */
static void
fillFlds()
{

	if (_Flds[U_REQUEST] != NULL) {
		if (EQUALS(_Flds[U_REQUEST], "yes"))
			_Request = TRUE;
		else
			_Request = FALSE;
	}

	if (_Flds[U_SENDFILES] != NULL) {
		if (EQUALS(_Flds[U_SENDFILES], "yes"))
			_Switch = TRUE;
		else
			_Switch = FALSE;
	}

	if (_Flds[U_CALLBACK] != NULL) {
		if (EQUALS(_Flds[U_CALLBACK], "yes"))
			_CallBack = TRUE;
		else
			_CallBack = FALSE;
	}

	if (_Flds[U_DIRECT] != NULL) {
		if (EQUALS(_Flds[U_DIRECT], "yes"))
			_NoSpool = TRUE;
		else
			_NoSpool = FALSE;
	}

	if (_Flds[U_MYNAME] != NULL) {
		strncpy(_MyName, _Flds[U_MYNAME], MAXBASENAME);
		_MyName[MAXBASENAME] = NULLCHAR;
	}

	if (_Flds[U_PUBDIR] != NULL) {
		if (_Pubdir != NULL)
		    free(_Pubdir);	/* get rid of previous one */
		_Pubdir = strdup(_Flds[U_PUBDIR]);
#ifndef UUCHECK
		ASSERT(_Pubdir != NULL, Ct_ALLOCATE, _Flds[U_PUBDIR], 0);
#else /* UUCHECK */
		if (_Pubdir == NULL) {
		    perror(gettext("malloc() error"));
		    exit(1);
		}
#endif /* UUCHECK */
		Pubdir = _RPaths[0] = _WPaths[0] = _Pubdir; /* reset default */
	}

	if (_Flds[U_PATH] != NULL) {
		if (_Path != NULL)
		    free(_Path);	/* get rid of previous one */
		_Path = strdup(_Flds[U_PATH]);
#ifndef UUCHECK
		ASSERT(_Path != NULL, Ct_ALLOCATE, _Flds[U_PATH], 0);
#else /* UUCHECK */
		if (_Path == NULL) {
		    perror(gettext("malloc() error"));
		    exit(1);
		}
#endif /* UUCHECK */
	}

	return;
}

/*
 * fill in the list vector for the system/login
 * input:
 *	type - list type (read, write, noread, nowrite, command)
 * output:
 *	list - filled in with items.
 * return:
 *	number of items in list
 */
static void
fillList(type, list)
int type;
char *list[];
{
	char *p;
	int num;
	int maxlist = 0;

	p = _Flds[type];

	/* find list limit */
	if (type == U_READPATH || type == U_WRITEPATH
	 || type == U_NOREADPATH || type == U_NOWRITEPATH)
		maxlist = MAXPATHS;
	else if (type == U_COMMANDS)
		maxlist = MAXCMDS;

	if (p == NULL || !*p) {
		 /* no names specified, default already setup */
		return;
	}

	num = 0;
	while (*p && num < maxlist) {
		list[num] = p;
		if (*p == ':') {	/* null path */
			*p++ = NULLCHAR;
			continue;
		}
		while (*p && *p != ':')
			p++;
		if (*p == ':')
			*p++ = NULLCHAR;
		DEBUG(7, "list (%s) ", list[num]);
		num++;
	}
	DEBUG(7, "num = %d\n", num);
	list[num] = NULL;
	return;
}

/*
 * Find the line of PERMISSIONS for login.
 * The search is determined by the type field
 * (type=U_LOGNAME, U_MACHINE or U_VALIDATE)
 * For U_LOGNAME:
 *	search for "name" in a LOGNAME= option
 * For U_MACHINE:
 *	search for "name" in a MACHINE= option
 * For U_VALIDATE:
 *	search for "rmtname" in a VALIDATE= option and
 *	for the same entry see if "name" is in the LOGNAME= option
 * input:
 *	name -> search name
 *	logname -> for validate entry
 *	type -> U_MACHINE or U_LOGNAME
 * output:
 *	The global values of all options will be set
 *	(e.g. _RPaths, _WPaths,  _Request, ...)
 * return:
 *	0 -> ok
 *	FAIL -> no match found
 */
static int
userFind(name, rmtname, type)
char *name, *rmtname;
int type;
{
	char *p, *arg, *buf = NULL;
	static char default_buf[BUFSIZ];

	if (name != NULL && strcmp(name, "DEFAULT") != 0) {
		/* call ourself recursively to set defaults */
		(void) userFind("DEFAULT", "", U_MACHINE);
	} else {
		/*
		 * Handle case where looking for DEFAULT entry.
		 * First initialize all defaults to their "base"
		 * values.  Then the DEFAULT entry, if found,
		 * will override these settings.
		 */
		_Request = FALSE;
		_CallBack = FALSE;
		_Switch = FALSE;
		_NoSpool = FALSE;
		_MyName[0] = NULLCHAR;
		_RPaths[0] = _WPaths[0] = PUBDIR;	/* default is public */
		_RPaths[1] = _WPaths[1] = NULLCHAR;
		_NoRPaths[0] = NULLCHAR;
		_NoWPaths[0] = NULLCHAR;
		if (_Pubdir != NULL)
			free(_Pubdir);
		Pubdir = _Pubdir = strdup(PUBDIR);
		if (_Path != NULL)
			free(_Path);
		_Path = strdup(PATH);
		/* set up Commands defaults */
		_Flds[U_COMMANDS] = strcpy(_Cmd_defaults, DEFAULTCMDS);
		fillList(U_COMMANDS, _Commands);
		/*
		 * put defaults we read in in here so they're not overwritten
		 * by non-DEFAULT entries.
		 */
		buf = default_buf;
	}

	if (name == NULL)	/* use defaults */
		return(0);	/* I don't think this will ever happen */

	if ( (Fp = fopen(PERMISSIONS, "r")) == NULL) {
		DEBUG(5, "can't open %s\n", PERMISSIONS);
		return(FAIL);
	}

	for (;;) {
	    if (parse_tokens (_Flds, buf) != 0) {
		(void) fclose(Fp);
		DEBUG(5, "name (%s) not found; return FAIL\n", name);
		return(FAIL);
	    }

	    p = _Flds[type];
	    while (p && *p) {
		p = nextarg(p, &arg);
		switch (type) {
		case U_VALIDATE:
		    if (EQUALS(arg, rmtname)
			&& nameMatch(name, _Flds[U_LOGNAME])==SUCCESS)
				break;
		    continue;

		case U_LOGNAME:
		    if (EQUALS(arg, name))
				break;
		    continue;

		case U_MACHINE:
		    if (EQUALSN(arg, name, MAXBASENAME))
				break;
		    continue;
		}

		(void) fclose(Fp);
		fillFlds();

		/* fill in path lists */
		fillList(U_READPATH, _RPaths);
		fillList(U_WRITEPATH, _WPaths);
		if (!requestOK())
		    _Flds[U_NOREADPATH] = "/";
		fillList(U_NOREADPATH, _NoRPaths);
		fillList(U_NOWRITEPATH, _NoWPaths);

		/* fill in command list */
		fillList(U_COMMANDS, _Commands);

		return(0);
	    }
	}
}

/*
 * see if name is in a VALIDATE option
 * return:
 *	FAIL -> not found
 *	SUCCESS -> found
 */
static int
validateFind(name)
char *name;
{

	if ( (Fp = fopen(PERMISSIONS, "r")) == NULL) {
		DEBUG(5, "can't open %s\n", PERMISSIONS);
		return(FAIL);
	}

	for (;;) {
	    if (parse_tokens (_Flds, NULL) != 0) {
		DEBUG(5, "validateFind (%s) FAIL\n", name);
		(void) fclose(Fp);
		return(FAIL);
	    }

	    if (_Flds[U_VALIDATE] == NULL)
		continue;
	    if (nameMatch(name, _Flds[U_VALIDATE])==SUCCESS) {
		(void) fclose(Fp);
		return (SUCCESS);
	    }
	}

}

/*
 * see if name is in an ALIAS option
 * return:
 *	NULL -> not found
 *	otherwise -> machine name
 */
char *
aliasFind(name)
char *name;
{

	if ( (Fp = fopen(PERMISSIONS, "r")) == NULL) {
		DEBUG(5, "can't open %s\n", PERMISSIONS);
		return(NULL);
	}

	for (;;) {
	    if (parse_tokens (_Flds, NULL) != 0) {
		DEBUG(5, "aliasFind (%s) FAIL\n", name);
		(void) fclose(Fp);
		return(NULL);
	    }

	    if (_Flds[U_ALIAS] == NULL)
		continue;
	    if (nameMatch(name, _Flds[U_ALIAS])==SUCCESS) {
		(void) fclose(Fp);
#ifndef UUCHECK
		ASSERT(strchr(_Flds[U_MACHINE], ':') == NULL,
		    "PERMISSIONS file: ALIAS is one-to-many:",
		    _Flds[U_MACHINE], 0);
#else /* UUCHECK */
		if (strchr(_Flds[U_MACHINE], ':') != NULL) {
		    printf(gettext("ALIAS is one-to-many: %s -> %s\n"),
			name, _Flds[U_MACHINE]);
		    return(NULL);
		}
#endif /* UUCHECK */
		return(_Flds[U_MACHINE]);
	    }
	}

}

/*
 * parse a line in PERMISSIONS and return a vector
 * of fields (flds)
 *
 * return:
 *	0 - OK
 *	EOF - at end of file
 */
int
parse_tokens(flds, buf)
char *flds[];
char *buf;
{
	int i;
	char *p;
	struct name_value pair;
	static char _line[BUFSIZ];
	char *line = buf;

	if (buf == NULL)
		line = _line;	/* if no buffer specified, use default */
	/* initialize defaults  in case parameter is not specified */
	for (i=0;i<NUMFLDS;i++)
		flds[i] = NULL;

	if (getuline(Fp, line) == 0)
		return(EOF);

	for (p=line;p && *p;) {
		p = next_token (p, &pair);

		for (i=0; i<NUMFLDS; i++) {
			if (EQUALS(pair.name, _Kwords[i].kword)) {
				flds[i] = pair.value;
				break;
			}
		}
#ifndef UUCHECK
		ASSERT(i<NUMFLDS, "PERMISSIONS file: BAD OPTION--",
		    pair.name, NUMFLDS);
#else /* UUCHECK */
		if (i >= NUMFLDS) {
			DEBUG(3, "bad option (%s) in PERMISSIONS\n",pair.name);
			(void) printf("\n*****************************\n");
			(void) printf(gettext("**BAD OPTION in PERMISSIONS file: %s\n"),
				pair.name);
			(void) printf("*****************************\n");
			Uerrors++;
			return(0);
		}
#endif /* UUCHECK */

	}
	return(0);
}

/*
 * return a name value pair
 *	string	-> input pointer
 *	pair	-> name value pair
 * return:
 *	pointer to next character
 */
char *
next_token (string, pair)
char *string;
struct name_value *pair;
{
	char	*prev = _uu_setlocale(LC_ALL, "C");

	while ( (*string) && ((*string == '\t') || (*string == ' ')) )
		string++;

	pair->name = string;
	while ((*string) && (*string != '='))
		string++;
	if (*string)
		*string++ = NULLCHAR;

	pair->value = string;
	while ((*string) && (*string != '\t') && (*string != ' ')
	    && (*string != '\n'))
		string++;

	if (*string)
		*string++ = NULLCHAR;

	(void) _uu_resetlocale(LC_ALL, prev);
	return (string);
}

/*
 * get a line from the PERMISSIONS
 * take care of comments (#) in col 1
 * and continuations (\) in last col
 * return:
 *	len of line
 *	0 -> end of file
 */
int
getuline(fp, line)
FILE *fp;
char *line;
{
	char *p, *c;
	char buf[BUFSIZ];

	p = line;
	for (;fgets(buf, BUFSIZ, fp) != NULL;) {
		/* remove trailing white space */
		c = &buf[strlen(buf)-1];
		while (c>=buf && (*c == '\n' || *c == '\t' || *c == ' ') )
			*c-- = NULLCHAR;

		if (buf[0] == '#' || buf[0] == '\n' || buf[0] == NULLCHAR)
			continue;
		(void) strcpy(p, buf);
		p += strlen(buf);
		if ( *(p-1) == '\\')
			p--;
		else
			break;
	}

	return(p-line);
}


#define SMAX	15

/*
 * get the next colon separated argument from the list
 * return:
 *	p -> pointer to next arg in string
 * input:
 *	str -> pointer to input string
 * output:
 *	name -> pointer to arg string
 */
char *
nextarg(str, name)
char *str, **name;
{
	char *p, *b;
	static char buf[SMAX+1];

	for(b=buf,p=str; *p != ':' && *p && b < buf+SMAX;)
		*b++ = *p++;
	*b++ = NULLCHAR;
	if (*p == ':')
		p++;
	*name = buf;
	return(p);
}

/*
 * check if requesting files is permitted
 * return
 *	TRUE -> request permitted
 *	FALSE -> request denied
 */
int
requestOK()
{
	return(_Request);
}

/*
 * myName - return my name from PERMISSIONS file
 *	or if not there, from  uucpname()
 * return: none
 */

void
myName(name)
char *name;
{
	if (*_MyName)
		strcpy(name, _MyName);
	else
		uucpname(name);
	return;
}

/*
 * check for callback required for any transaction
 * return:
 *	TRUE -> callback required
 *	FALSE-> callback NOT required
 */
int
callBack()
{
	return(_CallBack);
}

/*
 * check for callback to send any files from here
 * This means that the called (SLAVE) system will not switch roles.
 * return:
 *	TRUE -> callback requried to send files
 *	FALSE-> callback NOT required to send files
 */
int
switchRole()
{
	return(_Switch);
}

/*
 * Check to see if command is valid for a specific machine.
 * The PERMISSIONS file has an option COMMANDS=name1:name2:... for
 * any machine that does not have the default list which is
 * rmail
 * Note that the PERMISSIONS file is read once for each system
 * at the time the Rmtname is set in xprocess().
 * Return codes:
 *	ok: TRUE
 *	fail: FALSE
 */
int
cmdOK(cmd, fullcmd)
char	*cmd, *fullcmd;
{
	DEBUG(7, "cmdOK(%s, )\n", cmd);
	return(cmdMatch(cmd, fullcmd));
}


/*
 * check a name against a list
 * input:
 *	name	-> name
 *	list	-> list of names
 * return:
 *	TRUE	-> found path
 *	FALSE	-> not found
 */
static int
listMatch(name, list)
char *name, *list[];
{
    int i;
    char *temp, *tend;
    struct stat statbuf;
    dev_t _dev[MAXPATHS+1];
    ino_t _ino[MAXPATHS+1];

    /* ino set to 0 so stat is only done first time */
    for (i=0; list[i] != NULL; i++)
	_ino[i] = 0;

    /* try to match inodes */
    if ( (temp = strdup(name)) != NULL ) {
	for ( tend = temp + strlen(temp) ; *temp; ) {
	    if ( stat(temp, &statbuf) == 0 ) {
		for (i=0; list[i] != NULL; i++) {
		    if ( _ino[i] == 0 ) {
			struct stat tempbuf;
			if ( stat(list[i], &tempbuf) == 0 ) {
			    _dev[i] = tempbuf.st_dev;
			    _ino[i] = tempbuf.st_ino;
			}
		    }
		    if ( _dev[i] == statbuf.st_dev
		      && _ino[i] == statbuf.st_ino ) {
			free(temp);
			return(TRUE);
		    }
		}
	    }
	    *tend = '\0';
	    if ( (tend = strrchr(temp, '/')) == NULL ) {
		free(temp);
		break;
	    } else
		*(tend+1) = '\0';
	}
    }

    return(FALSE);
}


/*
 * Check "name" against a BASENAME or full name of _Commands list.
 * If "name" specifies full path, check full, else check BASENAME.
 *  e.g. "name" rmail matches list item /usr/bin/rmail
 * input:
 *	name	-> name
 * output:
 *	fullname -> copy full command name into fullname if
 *		    a full path was specified in _Commands;
 *		    if not, put name into fullname.
 * return:
 *	TRUE	-> found path
 *	FALSE	-> not found
 */
static int
cmdMatch(name, fullname)
char *name;
char *fullname;
{
	int i;
	char *bname;
	int allok = FALSE;

	for (i=0; _Commands[i] != NULL; i++) {
		if (EQUALS(_Commands[i], "ALL")) {
			/* if ALL specified in the list
			 * set allok and continue in case
			 * a full path name is specified for the command
			 */
			allok = TRUE;
			continue;
		}
		if (name[0] != '/')
			bname = BASENAME(_Commands[i], '/');
		else
			bname = _Commands[i];
		DEBUG(7, "bname=%s\n", bname);
		if (EQUALS(bname, name)) {
			(void) strcpy(fullname, _Commands[i]);
			return(TRUE);
		}
	}
	if (allok == TRUE) {
		/* ALL was specified and the command was not found in list */
		(void) strcpy(fullname, name);
		return(TRUE);
	}
	(void) strcpy(fullname, "NuLL");	/* this is a dummy command */
	return(FALSE);
}


/*
 * check the paths for this login/machine
 * input:
 *	path	pathname
 *	flag	CK_READ or CK_WRITE
 * output:
 *	path	may be modified to canonical form
 *		(../, ./, // will be interpreted/removed)
 * returns:
 *	0		-> success
 *	FAIL		-> failure - not a valid path for access
 */
int
chkpth(path, flag)
char *path;
{
	char *s;

	/*
	 * this is probably redundant,
	 * because expfile did it, but that's ok
	 * Note - the /../ check is not required because of canPath
	 */
	if (canPath(path) == FAIL)
		return(FAIL);

	if (flag == CK_READ)
		if (listMatch(path, _RPaths)
		&& !listMatch(path, _NoRPaths))
			return(0);
	if (flag == CK_WRITE)
		if (listMatch(path, _WPaths)
		&& !listMatch(path, _NoWPaths))
			return(0);


	/* ok if uucp generated D. or X. name for the spool directory */
	if (PREFIX(RemSpool, path) ) {
    		s = &path[strlen(RemSpool)];
		if ( (*s++ == '/')
		  && (*s == DATAPRE || *s == XQTPRE)
		  && (*(++s) == '.')
		  && (strchr(s, '/') == NULL) )
			return(0);
	}

	/*  path name not valid */
	return(FAIL);
}

/*
 * check write permission of file.
 * if mopt != NULL and permissions are ok,
 * a side effect of this routine is to make
 * directories up to the last part of the
 * "to" ( if they do not exit).
 * Input:
 *	to - a path name of the destination file or directory
 *	from - full path name of source file
 *	opt - create directory option (NULL - don't create)
 * Output:
 *	to - will be the full path name of the destination file
 * returns:
 *	0	->success
 *	FAIL	-> failure
 */
int
chkperm(from, to, opt)
char *from, *to, *opt;
{
	char *lxp, *p;
	struct stat s;
	char dir[MAXFULLNAME];

	if (*(p = LASTCHAR(to)) == '/') {
	    if (strlcpy(p+1, BASENAME(from, '/'), MAXFULLNAME - strlen(to)) >=
		MAXFULLNAME - strlen(to)) {
		    return(FAIL);
	    }
	} else if (DIRECTORY(to)) {
	    *++p = '/';
	    if (strlcpy(p+1, BASENAME(from, '/'), MAXFULLNAME - strlen(to)) >=
		MAXFULLNAME - strlen(to)) {
		    return(FAIL);
	    }
	}

	/* to is now the full path name of the destination file */

	if (WRITEANY(to))
	    return(0);
	if (stat(to, &s) == 0)
	    return(FAIL);	/* file exists, but not writeable */

	/* file does not exist--check directory and make when necessary */

	(void) strcpy(dir, to);
	if ( (lxp=strrchr(dir, '/')) == NULL)
	    return(FAIL);	/* no directory part of name */
	if (lxp == dir)	/* at root */
	    lxp++;
	*lxp = NULLCHAR;

	/* should check WRITEANY on parent before mkdirs() */
	if (!DIRECTORY(dir)) {
	    if (opt == NULL)
		return(FAIL);	/* no directory and no opt to make them */
	    else if (mkdirs(dir, PUBMASK) == FAIL)
		return(FAIL);
	}

	/* the directory now exists--check for writability */
	if (EQUALS(RemSpool, dir) || WRITEANY(dir))
	    return(0);

	return(FAIL);
}
