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
 *  Copyright (c) 1989, 1990 Sun Microsystems, Inc.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI" 

#include <fcntl.h>
#include <stdio.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/file.h>
#include <dirent.h>
#include "iso_spec.h"
#include "iso_impl.h"
/* 
 * crdlist_dno_iso: walk the iso dlist in breadth first order
 * chain all directories together, and assinged directory
 * record number in ascending order start with 1
 * return the total number of directories in iso directory tree
 */

extern *myname;

static dno_iso = 1;
int
crdlist_dno_iso(rootdp)
struct dlist *rootdp;
{
struct dlist *dp;
struct dlist *dp1;
struct dlist *prevdp;

	for (dp=rootdp, prevdp=rootdp, rootdp->idno=dno_iso++; 
		dp != NULL; dp=dp->idirnext) { 
		for (dp1=dp->icdp; dp1 != NULL; dp1=dp1->inext) {
			if ((dp1->dmode & S_IFMT) == S_IFDIR) {
				dp1->idno=dno_iso++;
				prevdp->idirnext = dp1;
				prevdp = dp1;
			}
		}
	}
	return(dno_iso-1);
}


/* 
 * crdlist_dno_unix: walk the unix dlist in breadth first order
 * chain all directories together, and assinged directory
 * record number in ascending order start with 1
 * return the total number of directories in iso directory tree
 */
static dno_unix = 1;
int
crdlist_dno_unix(rootdp)
struct dlist *rootdp;
{
struct dlist *dp;
struct dlist *dp1;
struct dlist *prevdp;

	for (dp=rootdp, prevdp=rootdp, rootdp->udno=dno_unix++; 
		dp != NULL; dp=dp->udirnext) { 
		for (dp1=dp->ucdp; dp1 != NULL; dp1=dp1->unext) {
			if ((dp1->dmode & S_IFMT) == S_IFDIR) {
				dp1->udno=dno_unix++;
				prevdp->udirnext = dp1;
				prevdp = dp1;
			}
		}
	}
	return(dno_unix-1);
}

/* mkdlist - creates a sorted list of all directories */
struct dlist *
mkdlist(path, prototype, extension)
char *path;
int prototype;
int extension;
{
struct dlist *rootdp;

	rootdp = prototype ? mkdlist_proto(path) : mkdlist_path(path);
	(void) sortdlist(rootdp, extension);
	/* assing record number for each directory */
	/* required by the path table */
	(void) crdlist_dno_iso(rootdp);
	if (extension)
		(void) crdlist_dno_unix(rootdp);
	return(rootdp);
}

/* compare two dlist elements according to UNIX file name*/
/* returns < == > if first element is < == > the second */
int
dpcompunix(dpp1, dpp2)
struct dlist **dpp1;
struct dlist **dpp2;
{
	return(strcmp((*dpp1)->unixfname, (*dpp2)->unixfname));

}


/* compare two dlist elements according to ISO file name*/
/* returns < == > if first element is < == > the second */
int
dpcompiso(dpp1, dpp2)
struct dlist **dpp1;
struct dlist **dpp2;
{

	return(strcmp((*dpp1)->isofname, (*dpp2)->isofname));
}

void
sortchild(rootdp, extension)
struct dlist *rootdp;
int extension;
{
struct dlist **p;
struct dlist **pp;
struct dlist *dp;
int	i;
int	nodp;

	for (dp = rootdp->cdp, nodp = 0; dp!= NULL; dp=dp->dnext) 
		nodp++;

	/* no need to do sorting if number of dlist is less than 2 */
	if (nodp < 1 ) return;
	else if (nodp == 1) {
		rootdp->ucdp = rootdp->cdp;
		rootdp->icdp = rootdp->cdp;
		return;
	}

	/* set up the list for sorting */
	pp = (struct dlist **) malloc(nodp * sizeof(struct dlist *));
	for (p=pp,dp=rootdp->cdp;dp != NULL; dp=dp->dnext) 
		*p++=(struct dlist *)dp;

	if (extension) {
		/* do the UNIX sort */
		(void) qsort((char *)pp, nodp, sizeof(struct dlist *), dpcompunix); 

		for (i=0;i< nodp-1;i++) 
			pp[i]->unext=pp[i+1];
	 
		rootdp->ucdp = pp[0];
	}

	/* do the ISO sort */
	(void) qsort((char *)pp, nodp, sizeof(struct dlist *), dpcompiso); 

	for (i=0;i< nodp-1;i++) 
		pp[i]->inext=pp[i+1];
	 
	rootdp->icdp = pp[0];

	(void) cfree(pp);

}

void
sortdlist(rootdp, extension)
struct dlist *rootdp;
int extension;
{
struct dlist *dp;

	if (rootdp == NULL) return;

	(void) sortchild(rootdp, extension);

	for (dp=rootdp->cdp; dp != NULL; dp=dp->dnext)
		if (dp->cdp != NULL) sortdlist(dp, extension); 
}

getpath(startdp, path)
struct dlist *startdp;
char *path;
{
struct dlist *dp;
char s[1024];

	path[0]='\0';

	for (dp=startdp; dp!=NULL; dp = dp->pdp) {
		strcpy(s, path);
		strcpy(path, dp->unixfname);
		strcat(path, "/");
		strcat(path, s);
		if (dp == dp->pdp) break;
	}
}

int
makelnk(fp, lbn, fsize)
struct dlist *fp;
int lbn;
int *fsize;
{
char buf[1024];
int	count;

	if ((count = readlink(fp->ufnp->fname, buf, 1024)) < 0) {
		fprintf(stderr, "%s: cannot readlink", myname);
		perror(fp->ufnp->fname);
		*fsize= 0;
		return(lbn);
	} 

	if (lseek(cdout, LBN_TO_BYTE(lbn), L_SET) < 0) {
		fprintf(stderr, "%s: ", myname);
		perror("bad lseek");
		cleanup();
	}

	if (write(cdout, buf, count) != count) {
		fprintf(stderr, "%s: ", myname);
		perror("bad write during creation of symbolic link");	
		cleanup();
	}
	*fsize=count;
	return(fillblkzero(lbn, count));
}

int
copyfile(fp, lbn, fsize)
struct dlist *fp;
int lbn;
int *fsize;
{
int fd;
struct stat stb;
int i, bsize;
int rsize;
char *buf;

	fd=open(fp->ufnp->fname, 0);
	if (fd < 0) {
		fprintf(stderr, "%s: cannot open: ", myname);
		perror(fp->ufnp->fname);
		*fsize= 0;
		return(lbn);
	}
	if (fstat(fd, &stb) < 0) {
		fprintf(stderr, "%s: cannot stat: ", myname);
		perror(fp->ufnp->fname);
		(void) close(fd);
		*fsize= 0;
		return(lbn);
	}
	/* do the copy */
	bsize = stb.st_blksize;
	buf= (char *) malloc(bsize);
	if (lseek(cdout, LBN_TO_BYTE(lbn), L_SET) < 0) {
		fprintf(stderr, "%s: ", myname);
		perror("bad lseek");
		cleanup();
	}
	for(i=0;;i++) {
		if ((rsize=read(fd, buf, bsize)) == 0)
			break;
		if (write(cdout, buf, rsize) != rsize) {
			fprintf(stderr, "%s: ", myname);
			perror("bad write");	
			cleanup();
		}
		if (rsize != bsize) break;
	}
	(void) cfree(buf);
	close(fd);
	*fsize=i*bsize+rsize;
	return(fillblkzero(lbn, i*bsize+rsize));
}

prntdlist(dp)
struct dlist *dp;
{
	printf("%s\t", dp->pdp->unixfname);
	printf("%s\t", dp->unixfname);
	printf("%s\n", dp->isofname);
}

prntnchild(startdp)
struct dlist *startdp;
{
struct dlist *dp;

	for (dp = startdp->cdp; dp != NULL; dp=dp->dnext) 
		prntdlist(dp);
	for (dp = startdp->cdp; dp != NULL; dp=dp->dnext)
		prntnchild(dp);
}

prntuchild(startdp)
struct dlist *startdp;
{
struct dlist *dp;

	for (dp = startdp->ucdp; dp != NULL; dp=dp->unext) 
		prntdlist(dp);
	for (dp = startdp->ucdp; dp != NULL; dp=dp->unext)
		prntuchild(dp);
}

prntichild(startdp)
struct dlist *startdp;
{
struct dlist *dp;

	for (dp = startdp->icdp; dp != NULL; dp=dp->inext) 
		prntdlist(dp);
	for (dp = startdp->icdp; dp != NULL; dp=dp->inext)
		prntichild(dp);
}

prnttree(startdp)
struct dlist *startdp;
{
	prntdlist(startdp);
	prntnchild(startdp);
	printf("**********\n");
	prntuchild(startdp);
	printf("**********\n");
	prntichild(startdp);
}

prntipath(startdp)
struct dlist *startdp;
{
struct dlist *dp;
	for (dp=startdp; dp!=NULL; dp=dp->idirnext) 
		printf("\t%d\t%s\n", dp->idno, dp->isofname);
}

prntupath(startdp)
struct dlist *startdp;
{
struct dlist *dp;
	for (dp=startdp; dp!=NULL; dp=dp->udirnext) 
		printf("\t%d\t%s\n", dp->udno, dp->unixfname);
}

prntpath(startdp)
struct dlist *startdp;
{
	printf("\tdno\tname\n");
	prntipath(startdp);
	printf("**********\n");
	prntupath(startdp);
}
