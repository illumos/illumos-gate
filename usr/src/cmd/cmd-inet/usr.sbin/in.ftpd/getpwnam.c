#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Replacement for getpwnam - we need it to handle files other than
 * /etc/passwd so we can permit different passwd files for each different
 * host
 * (c) 1998-2000 by Bernhard Rosenkränzer <bero@redhat.com>
 * 19980930	Initial version
 * 20000211	Various fixes
 */

#include "config.h"
#include <pwd.h>
#include <sys/types.h>
#include <stdio.h>
#ifdef SHADOW_PASSWORD
# ifdef HAVE_SHADOW_H
#  include <shadow.h>
# endif
#endif

#ifndef HAVE_FGETPWENT /* Some systems (*BSD) don't have fgetpwent... */
#ifdef HAVE_STRINGS_H
#include <strings.h>
#else
#include <string.h>
#endif
struct passwd *fgetpwent(FILE *stream)
{
	char *entry=(char *) malloc(1024);
	struct passwd *p=(struct passwd *) malloc(sizeof(struct passwd));
	char *tmp,*tmp2;

	if(!fgets(entry,1024,stream)) {
		free(entry);
		free(p);
		return NULL;
	}
	tmp=strdup(entry);
	if(strchr(tmp,':')) {
		*strchr(tmp,':')=0;
		p->pw_name=tmp;
	} else {
		free(tmp); free(entry);	free(p); return NULL;
	}
	tmp2=strchr(entry,':')+1;
	tmp=strdup(tmp2);
	if(strchr(tmp,':')) {
		*strchr(tmp,':')=0;
		p->pw_passwd=tmp;
	} else {
		free(tmp); free(entry); free(p->pw_name); free(p); return NULL;
	}
	tmp2=strchr(tmp2,':')+1;
	tmp=strdup(tmp2);
	if(strchr(tmp,':')) {
		*strchr(tmp,':')=0;
		p->pw_uid=(uid_t) atoi(tmp);
	} else {
		free(tmp); free(entry); free(p->pw_passwd); free(p->pw_name); free(p); return NULL;
	}
	free(tmp);
	tmp2=strchr(tmp2,':')+1;
	tmp=strdup(tmp2);
	if(strchr(tmp,':')) {
		*strchr(tmp,':')=0;
		p->pw_gid=(gid_t) atoi(tmp);
	} else {
		free(tmp); free(entry); free(p->pw_passwd); free(p->pw_name); free(p); return NULL;
	}
	free(tmp);
	tmp2=strchr(tmp2,':')+1;
	tmp=strdup(tmp2);
	if(strchr(tmp,':')) {
		*strchr(tmp,':')=0;
		p->pw_gecos=tmp;
	} else {
		free(tmp); free(entry); free(p->pw_passwd); free(p->pw_name); free(p); return NULL;
	}
	tmp2=strchr(tmp2,':')+1;
	tmp=strdup(tmp2);
	if(strchr(tmp,':')) {
		*strchr(tmp,':')=0;
		p->pw_dir=tmp;
	} else {
		free(tmp); free(entry); free(p->pw_gecos); free(p->pw_passwd); free(p->pw_name); free(p); return NULL;
	}
	tmp2=strchr(tmp2,':')+1;
	if(strchr(tmp2,':')) {
		free(entry); free(p->pw_dir); free(p->pw_gecos); free(p->pw_passwd); free(p->pw_name); free(p); return NULL;
	}
	while(strlen(tmp2) && isspace(tmp2[strlen(tmp2)-1]))
		tmp2[strlen(tmp2)-1]=0;
	p->pw_shell=strdup(tmp2);
	free(entry);
	return p;
}
#endif


struct passwd *bero_getpwnam(const char * name, const char * file)
{
	FILE *f;
	struct passwd *p;
	struct passwd *r;
	
	if (!strcmp(file,"/etc/passwd")) 
	  return (getpwnam(name));
	f=fopen(file,"r");
	if(f==NULL)
		return NULL;
	p=NULL;
	r=NULL;
	while((r==NULL) && (p=fgetpwent(f)))
		if(!strcasecmp(p->pw_name,name))
			r=p;
	fclose(f);
	return r;
}

struct passwd *bero_getpwuid(uid_t uid, const char * file)
{
	FILE *f;
	struct passwd *p;
	struct passwd *r;
	
	if (!strcmp(file,"/etc/passwd"))
	  return getpwuid(uid);
	f=fopen(file,"r");
	if(f==NULL)
		return NULL;
	p=NULL;
	r=NULL;
	while((r==NULL) && (p=fgetpwent(f)))
		if(p->pw_uid==uid)
			r=p;
	fclose(f);
	return r;
}

#ifdef SHADOW_PASSWORD
struct spwd *bero_getspnam(const char * name, const char * file)
{
	FILE *f;
	struct spwd *s;
	struct spwd *r;
	f=fopen(file,"r");
	if(f==NULL)
		return NULL;
	s=NULL;
	r=NULL;
	while((r==NULL) && (s=fgetspent(f)))
		if(!strcasecmp(s->sp_namp,name))
			r=s;
	fclose(f);
	return r;
}
#endif
