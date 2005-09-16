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

/*	Copyright (c) 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <sys/types.h>		/* EFT abs k16 */
#include "wish.h"
#include "typetab.h"
#include "optabdefs.h"
#include "partabdefs.h"
#include "ifuncdefs.h"
#include "mess.h"
#include "mio.h"
#include "terror.h"
#include "var_arrays.h"
#include "sizes.h"

/*
 * read the object operations and parts information from the definition
 * file.  This file is located in $OASYS/info/OH/eternals and has the name 
 * of the internal TeleSystem name of the object.  The format of this file is:
 *
 * OBJECT DEFINITIONS
 * Number of parts
 * Part Definition 1
 * Part Definition 2
 *  ...
 * Part Definition n
 * Operation Definition 1
 * Operation Definition 2
 *  ...
 * Operation Definition m
 *
 * where:
 *  OBJECT DEFINITIONS = displayname class oeu format applic prod rclass
 *  Part Definition    = partname template flags
 *  Operation Def      = funcname but type intern extern optype mult all none
 *
 * All fields are tab separated.  See optabdefs.h and partabdefs.h for the
 * format of the internal tables.
 *
 * Basically, the way this whole thing works is that there is an internal
 * set of tables (the oot and the opt) which define internally-known 
 * objects.  If a VAR adds an object, he makes a file with the above format
 * which will define it.  If the object architecture is asked to handle an
 * object which is not in the internal table, it looks out in the external
 * files directory for a file with the name of the object it is supposed to
 * handle.  It reads it into the last slot of the internal table.  Thus, if
 * such an object is accessed twice in a row, there is no need to read it in
 * again the second time.
 */


#define LASTOBJ	(MAX_TYPES-1)

static struct operation Extops[MAX_OPERS];	/* external operations */

extern struct operation *Optab[MAX_TYPES][MAX_OPERS];
extern struct opt_entry Partab[MAX_TYPES];
extern struct one_part Parts[MAXPARTS];


extern struct operation	Obj_sh;
extern struct operation	Obj_view;
extern struct operation	Obj_cp;
extern struct operation	Obj_rn;
extern struct operation	Obj_mv;
extern struct operation	Obj_sc;
extern struct operation	Obj_unsc;
extern struct operation	Obj_rm;
extern struct operation	Ascii_pr;
extern struct operation	Ascii_open;
extern struct operation	Ascii_cv;
extern struct operation	Dir_sh;
extern struct operation	Dir_view;
extern struct operation	Dir_ex;
extern struct operation	No_op;
extern struct operation	Illeg_op;

struct operation	Obj_sp;
struct operation	Obj_unrm;
struct operation	Obj_ml;
struct operation	Obj_viewfull;
struct operation	Unknown_ex;
struct operation	Unknown_cv;

struct oper_trans {
	char	*name;
	struct operation	*op;
} Optrans[] = {
	{"SH",	&Obj_sh},
	{"VI",	&Obj_view},
	{"CP",	&Obj_cp},
	{"RN",	&Obj_rn},
	{"MV",	&Obj_mv},
	{"SP",	&Obj_sp},
	{"SC",	&Obj_sc},
	{"UNSC",	&Obj_unsc},
	{"RM",	&Obj_rm},
	{"UNRM",	&Obj_unrm},
	{"ML",	&Obj_ml},
	{"VF",	&Obj_viewfull},
	{"PR",	&Ascii_pr},
	{"ED",	&Ascii_open},

	{"UNK_EX",	&Unknown_ex},
	{"UNK_CV",	&Unknown_cv},
	{"ASC_CV",	&Ascii_cv},

	{"DIR_SH",	&Dir_sh},
	{"DIR_VI",	&Dir_view},
	{"DIR_EX",	&Dir_ex},
	{"NOP",	&No_op},

	{"ILL",	&Illeg_op},
	{"",NULL}
};

static char	**Notfound;	/* all the objects I could never find... */
static int get_oper();

int
ootread(obj)
char	*obj;
{
	char	*fname;
	register int	i;
	FILE	*fp;
	char	*externoot();
	int	lcv;

	if (Notfound)
	{
		lcv = array_len(Notfound);
		for (i = 0; i < lcv; i++)
			if (strcmp(Notfound[i], obj))
				return O_FAIL;
	}

	fname = externoot(obj);

	if ((fp = fopen(fname, "r")) == NULL) {
		var_append(char *, Notfound, (&obj));
		return O_FAIL;
	}

	if (read_parts(fp, obj) == O_FAIL) {
		fclose(fp);
		return O_FAIL;
	}
	for (i = 0; i < MAX_OPERS; i++) {
		Extops[i].opername = NULL;
		Optab[LASTOBJ][i] = Extops + i;
		if (get_oper(fp, i) == O_FAIL)
			break;
	}
	fclose(fp);
	if (i < MAX_OPERS)
		Optab[LASTOBJ][i] = NULL;

	return O_OK;
}

static int
get_oper(fp, index)
FILE	*fp;
int	index;
{
    char	*p;
    char	buf[BUFSIZ];
    register int	i;
    extern int	(*Function[MAX_IFUNCS])();
    struct operation	*optab;
    char	*get_skip();
    char	*tab_parse();
    char	*unbackslash();
    long	tab_long();

    optab = Optab[LASTOBJ][index];
    if (get_skip(buf, BUFSIZ, fp) == NULL)
	return O_FAIL;
    if (buf[0] == '.') {
	for (i = 0; Optrans[i].name[0]; i++) {
	    if (strncmp(buf+1,Optrans[i].name,strlen(Optrans[i].name)) == 0) {
		Optab[LASTOBJ][index] = Optrans[i].op;
#ifdef _DEBUG
		_debug(stderr, "Intern func(%s) at %d\n",Optrans[i].name, index);
#endif
		return O_OK;
	    }
	}
#ifdef _DEBUG
	_debug(stderr, "UNKNOWN BUILT-IN OP: %s\n", buf);
#endif
	return O_FAIL;
    }

    p = tab_parse(&optab->opername, buf);
    (void) unbackslash(optab->opername);
    optab->but = tab_long(&p, 16) - 1;
    optab->func_type = tab_long(&p, 16);
    optab->intern_func = tab_long(&p, 16);
    if (optab->intern_func < 0 || optab->intern_func >= MAX_IFUNCS || Function[optab->intern_func] == NULL) {
#ifdef _DEBUG
	_debug(stderr, "Intern func num out of range: %d\n", optab->intern_func);
#endif
	optab->intern_func = IF_BADFUNC;
    }
    p = tab_parse(&optab->extern_func, p);
    optab->op_type = tab_long(&p, 16);
    optab->multiple = tab_long(&p, 16);
    optab->all_mask = tab_long(&p, 16);
    if (p && *p) {
	optab->none_mask = tab_long(&p, 16);
#ifdef _DEBUG
	_debug(stderr,
	       "PARSED FUNC: %s %x %x %x %s %x %x %x %x at %d\n",
	       optab->opername,
	       optab->but,
	       optab->func_type,
	       optab->intern_func,
	       optab->extern_func,
	       optab->op_type,
	       optab->multiple,
	       optab->all_mask,
	       optab->none_mask,
	       index);
#endif
	return O_OK;
    }
#ifdef _DEBUG
    _debug(stderr, "Bad Func Def line '%s'\n", buf);
#endif
    return O_FAIL;
}

#ifndef WISH

int
ootwrite(objtype, file)
char *objtype, *file;
{
    FILE *fp;
    struct one_part *p;
    struct opt_entry *prt;
    struct operation **oot;
    register int i, j;

    extern struct one_part Parts[MAXPARTS];
    extern char *Oasys;

    struct operation **obj_to_oot();
    struct opt_entry *obj_to_opt();
    char *esc_nl();
    time_t time(), t;	/* EFT abs k16 */
    char *ctime();

    if (objtype == NULL || *objtype == '\0') { /* dump all objects */
	char path[PATHSIZ];
	for (i=0; i < MAX_TYPES; i++) {
	    if (Partab[i].objtype == NULL || Partab[i].objtype[0] == '\0')
		continue;
	    sprintf(path,"%s/info/OH/internals/%s", Oasys, Partab[i].objtype);
	    ootwrite(Partab[i].objtype, path);
	}
	return(O_OK);
    }

    if ((oot = obj_to_oot(objtype)) == NULL)
	return(O_FAIL);

    if ((prt = obj_to_opt(objtype)) == NULL)
	return(O_FAIL);

    if ((fp = fopen(file, "w")) == NULL)
	return(O_FAIL);

    time(&t);
    fprintf(fp, "#\n# Object Definition Dump of object type %s\n", objtype);
    fprintf(fp, "# Dump date: %s#\n", ctime(&t));
    fprintf(fp, "%s\t%x\t%s\t%s\t%s\t%s\t%s\n", 
	    (prt->objdisp && prt->objdisp[0])?prt->objdisp:"-",
	    prt->int_class,
	    prt->oeu, prt->objformat, prt->objapp, prt->objprod, 
	    prt->objclass);

    fprintf(fp, "#\n# Part Definitions\n#\n");
    fprintf(fp, "%d\n", prt->numparts);
    for (i = 0; i < prt->numparts; i++) {
	p = Parts + prt->part_offset+i;
	fprintf(fp, "%s\t%s\t%x\n", p->part_name, 
		p->part_template, p->part_flags);
    }
    fprintf(fp, "#\n# Operation Definitions\n#\n");

    for (i = 0; i < MAX_OPERS && oot[i] != NULL; i++) {
	/* find alias if one exists */
	for (j = 0; Optrans[j].op; j++)
	    if (Optrans[j].op == oot[i])
		break;
	if (Optrans[j].op)
	    fprintf(fp, ".%s\n# ", Optrans[j].name);
	fprintf(fp, "%s\t%d\t%x\t%x\t%s\t%x\t%d\t%x\t%x\n",
		esc_nl(oot[i]->opername), oot[i]->but + 1, oot[i]->func_type,
		oot[i]->intern_func, 
		oot[i]->extern_func?oot[i]->extern_func:"none", oot[i]->op_type,
		oot[i]->multiple, oot[i]->all_mask, oot[i]->none_mask);
    }
    fclose(fp);
}

char *
esc_nl(s)
char *s;
{
	static char news[MAX_WIDTH];
	char *ns = &news[0];

	if (s == NULL || *s == '\0')
		return("none");

	while (*s) {
		if (*s != '\n')
			*ns = *s;
		else {
			*ns++ = '\\';
			*ns = 'n';
		}
		s++;
		ns++;
	}
	*ns = '\0';
	return(&news[0]);
}
#endif
