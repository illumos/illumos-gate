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
#include <stdlib.h>
#include "wish.h"

int
main(int argc, char **argv)
{
	FILE *fp;
	char *home, *label, *name, *penv, *fname;
	char tpath[PATHSIZ], hpath[PATHSIZ], buf[BUFSIZ], path[PATHSIZ], *opt;
	int flag=0, cond=0, dos=0;
	int app_type();

	penv=argv[argc-1];
	while(--argc > 0 && (*++argv)[0] == '-')
		for(opt=argv[0]+1; *opt != '\0'; opt++)
		switch(*opt) {
			case 'd':
				flag=1;
				break;
			case 'l': /* used to create the rmenu */
				flag=2;
				break;
			case 'm':
				flag=3;
				break;
			case 'p':
				dos=1;
				break;
			default:
				break;
		}
	home=getenv(penv);

	if (strcmp(penv,"HOME") == 0) {
		snprintf(hpath, sizeof (hpath), "%s/pref/services",home);
		sprintf(tpath,"$VMSYS/OBJECTS/%s",dos?"dos":"programs");
	}
	else {
		snprintf(hpath, sizeof (hpath), "%s/lib/services",home);
		sprintf(tpath,"$OBJ_DIR");
	}

	if ((fp=fopen(hpath,"r")) == NULL) {
		printf("init=`message No Programs Installed`false\n");
		exit(FAIL);
	}

	while(fp && (fgets(buf,BUFSIZ,fp) != NULL)) {
		if (*buf == '\n' || *buf == '#' )
			continue;

		label = strtok(buf,"=");

		if (! strcmp(label,"name")) {
			name=strtok(NULL,"\n");
			snprintf(path, sizeof (path),
			    "%s/bin/%s.ins",home,name);
		} else if (! strcmp(label,"`echo 'name")) {
			name=strtok(NULL,"'");
			fname=strtok(NULL,"=");
			fname=strtok(NULL,"$");
			if (! strncmp(fname,"OPEN",4))
				continue;
			fname=strtok(NULL,"`");
			snprintf(path, sizeof (path),
			    "%s%s",home,&fname[strlen(penv)]);
		} else
			continue;
		if ( access(path,00)==0 && app_type(path,dos) ) {
			cond=1;
			if (flag == 2)  {
				printf("%s\n",name);
				continue;
			}
			printf("name=%s\n",name);
			printf("lininfo=\"%s\"\n",path);
			if (flag == 1 )
				printf("action=OPEN TEXT %s/Text.conf %s \"$LININFO\" \"%s\" `getfrm`\n",tpath,name,penv);
			else if (flag == 3 )
				printf("action=OPEN FORM %s/Form.mod %s \"$LININFO\" \"%s\" `getfrm`\n",tpath,name,penv);
			else 
				printf("action=`run %s%s`nop\n",dos?"-n ":"",path);
		}
	}
	if (!cond) {
		if ( dos )
			printf("init=`message No MS-DOS Programs Installed`false\n");
		else
			printf("init=`message No Programs Installed`false\n");
		exit(FAIL);
	}
	return (SUCCESS);
}

int
app_type(char *path, int dos)
{
	FILE *fp;
	char buf[BUFSIZ];
	int retval;

	retval = dos?FALSE:TRUE;

	if ((fp=fopen(path,"r")) == NULL)
		return(retval);

	while(fp && (fgets(buf,BUFSIZ,fp) != NULL)) {
		if ( *buf != '#' )
			continue;

		if (! strcmp(buf,"#dos\n")) {
			retval = dos?TRUE:FALSE;
			break;
		}

		if (! strcmp(buf,"#unix\n")) {
			retval = dos?FALSE:TRUE;
			break;
		}
	}

	(void)fclose(fp);

	return(retval);
}
