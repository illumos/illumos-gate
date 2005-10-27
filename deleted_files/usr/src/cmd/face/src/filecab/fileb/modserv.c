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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include "wish.h"

int
main(int argc, char **argv)
{
	FILE *fp;
	char *home;
	char *term, *mname, *appath, *dir, *penv, *oterm, *oname, *oapath, *odir; 
	char hpath[PATHSIZ], path[PATHSIZ], command[BUFSIZ];

	if (argc < 9) {
		fprintf(stderr,"Arguments invalid");
		return FAIL;
	}

	/* Initialize arguments needed to create installation script */
	term=argv[1];
	mname=argv[2];
	appath=argv[3];
	dir=argv[4];
	penv=argv[5];
	oterm=argv[6];
	oname=argv[7];
	oapath=argv[8];
	odir=argv[9];

	home=getenv(penv);

	if(strcmp(term,oterm) == 0 && strcmp(appath,oapath) == 0 && strcmp(dir,odir) == 0 ){
		snprintf(hpath, sizeof (hpath), "%s/bin/%s.ins",home,mname);
		snprintf(path, sizeof (path), "%s/bin/%s.ins",home,oname);

		/* if file exist copy it to old.<name> */
		if (strcmp(mname,oname) != 0)  {
			if (access(path, 00) == 0)  {
				copyfile(path,hpath);
				chmod(hpath, 0755);
	        	}
			snprintf(command, sizeof (command),
			    "$VMSYS/bin/delserve \"%s\" \"%s\"",oname,penv);
			system(command);
		}
	}
	else {
		snprintf(hpath, sizeof (hpath), "%s/bin/%s.ins",home,mname);
		snprintf(path, sizeof (path), "%s/bin/old.%s.ins",home,mname);
		/* if file exist copy it to old.<name> */
		if (access(hpath, 00) == 0) 
			copyfile(hpath,path);

		if ((fp=fopen(hpath,"w+")) == NULL) {
			fprintf(stderr,"Cannot open file");
			return FAIL;
		}

		/* Create the Shell script the application is going to be used */
		fprintf(fp,"TERM=%s;export TERM\n",term);
		fprintf(fp,"cd %s\n",dir);
		fprintf(fp,"%s\n",appath);
		fclose(fp);
		chmod(hpath, 0755);

	}
	/* Update the User's service file */
	if(strcmp(mname,oname) != 0) {
		if (strcmp(penv, "HOME") == 0)
			snprintf(path, sizeof (path), "%s/pref/services",home);
		else
			snprintf(path, sizeof (path),
			    "%s/OBJECTS/Menu.programs",home);

		if ((fp=fopen(path,"a")) == NULL) {
			fprintf(stderr, "Cannot open file");
			return FAIL;
		}
		fprintf(fp,"\n");
		fprintf(fp,"name=%s\n",mname);
		if (strcmp(penv, "HOME") == 0)
			fprintf(fp,"action=`run $HOME/bin/%s.ins`\n",mname);
		else
			fprintf(fp,"action=`run $VMSYS/bin/%s.ins`\n",mname);
		fclose(fp);
	}

	return (0);
}




/*
 * copy a file
 */
FILE *
cpfile(char *from, char *to)
{
	int	c;
	FILE	*src;
	FILE	*dst;

	if ((src = fopen(from, "r")) == NULL)
		return NULL;
	if ((dst = fopen(to, "w+")) == NULL) {
		fclose(src);
		return NULL;
	}
	while ((c = getc(src)) != EOF)
		putc(c, dst);
	if (ferror(src)) {
		fclose(src);
		fclose(dst);
		unlink(to);
		return NULL;
	}
	fclose(src);
	return dst;
}

int
copyfile(char *from, char *to)
{
	FILE *fp;

	if (fp = cpfile(from, to)) {
		fclose(fp);
		return(0);
	}
	return(-1);
}
