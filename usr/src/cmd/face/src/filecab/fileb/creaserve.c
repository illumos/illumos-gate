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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.9	*/

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include "wish.h"

main(argc,argv)
int argc;
char *argv[];
{
	FILE *fp, *tp;
	char *home, *getenv();
	char *prompt, *term, *mname, *appath, *dir, *penv, *npath;
	char path[PATHSIZ], fpath[PATHSIZ], temp_name[PATHSIZ];
	char io_buf[BUFSIZ], new_line[BUFSIZ];
	extern char *tempnam();
	extern pid_t getpid();
	extern uid_t getuid();
	extern gid_t getgid();
	int exist, comp_len, written_yet, dos=0;
	uid_t uid;
	gid_t gid;
	struct passwd *pw;

	if (argc < 7) {
		fprintf(stderr,"Arguments invalid\n");
		exit(FAIL);
	}

	/* Initialize arguments needed to create installation script */
	term=argv[1];
	mname=argv[2];
	appath=argv[3];
	dir=argv[4];
	prompt=argv[5];
	penv=argv[6];
	if ( argc == 8 )
		dos = 1;

	home=getenv(penv);
	sprintf(fpath, "%s/bin", home);
	if ( (npath = tempnam(fpath,"ins.")) == NULL ) {
		fprintf(stderr,"Cannot create install file\n");
		exit(FAIL);
	}

	if ((fp=fopen(npath,"w")) == NULL) {
		fprintf(stderr,"Cannot open install file\n");
		exit(FAIL);
	}

	if (strcmp(penv, "HOME") == 0) {
		uid = getuid();
		gid = getgid();
	} else {
		pw = getpwnam("vmsys");
		uid = pw->pw_uid;
		gid = pw->pw_gid;
	}

	/* Create the Shell script the application is going to use */
	fprintf(fp,"#%s\n",dos?"dos":"unix");
	fprintf(fp,"#TERM=%s;export TERM\n",term);
	fprintf(fp,"cd %s\n",dir);
	if (strcmp(prompt, "yes") == 0) {
		fprintf(fp,"echo \"Enter the arguments for %s: \\c\";",appath);
		fprintf(fp,"read FACE_ARGS\n");
		fprintf(fp,"eval %s%s $FACE_ARGS\n",dos?"dos -c ":"",appath);
	} else {
		fprintf(fp,"%s%s\n",dos?"dos -c ":"",appath);
	}
	fclose(fp);
	chmod(npath, 0755);
	chown(npath, uid, gid);

	/* Update the User's service file */
	if (strcmp(penv, "HOME") == 0)
		sprintf(path, "%s/pref/services",home);
	else
		sprintf(path, "%s/lib/services",home);

	exist = access(path, 00) ? 0 : 1;

	sprintf(temp_name, "/tmp/ins.%ld", getpid());

	if ((tp=fopen(temp_name,"w+")) == NULL) {
		fprintf(stderr, "Cannot open temporary file\n");
		exit(FAIL);
	}

	if ((fp=fopen(path,exist ? "r+" : "w+")) == NULL) {
		fprintf(stderr, "Cannot open services file\n");
		fclose(tp);
		unlink(temp_name);
		exit(FAIL);
	}
/*
 *  copy current services file to a temp file if it exists
 */
	if ( exist )
		while (fgets(io_buf, sizeof(io_buf), fp) != NULL)
			fputs(io_buf, tp);
	else
		fprintf(tp,"#3B2-4I1\n");
	rewind(fp);
	rewind(tp);

	sprintf(new_line,"`echo 'name=\"%s\"';echo 'action=`run %s$%s%s`nop'`\n",mname,dos?"-n ":"",penv,&npath[strlen(home)]);

	comp_len = strcspn(new_line,";");
	written_yet = 0;

	while (fgets(io_buf, sizeof(io_buf), tp) != NULL) {
		if ( ! written_yet && strncmp(new_line,io_buf,comp_len) <= 0 ) {
			written_yet++;
			fputs(new_line, fp);
			fputs(io_buf, fp);
		} else
			fputs(io_buf, fp);
	}

	if ( ! written_yet )
		fputs(new_line, fp);

	fclose(fp);
	fclose(tp);
	chmod(path, 0644);
	chown(path, uid, gid);
	unlink(temp_name);
	exit(SUCCESS);
}
