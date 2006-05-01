/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* dlopen.c--Unix dlopen() dynamic loader interface
 * Rob Siemborski
 * Rob Earhart
 * $Id: dlopen.c,v 1.45 2003/07/14 20:08:50 rbraun Exp $
 */
/* 
 * Copyright (c) 1998-2003 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <config.h>
#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <limits.h>

#include <sasl.h>
#include "saslint.h"

#ifndef PIC
#include <saslplug.h>
#include "staticopen.h"
#endif

#ifdef _SUN_SDK_
#include <sys/stat.h>
#endif /* _SUN_SDK_ */

#ifdef DO_DLOPEN
#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else /* HAVE_DIRENT_H */
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif /* ! HAVE_DIRENT_H */

#ifndef NAME_MAX
# ifdef _POSIX_NAME_MAX
#  define NAME_MAX _POSIX_NAME_MAX
# else
#  define NAME_MAX 16
# endif
#endif
 
#if NAME_MAX < 8
#  define NAME_MAX 8
#endif

#ifdef __hpux
#include <dl.h>

typedef shl_t dll_handle;
typedef void * dll_func;

dll_handle
dlopen(char *fname, int mode)
{
    shl_t h = shl_load(fname, BIND_DEFERRED, 0L);
    shl_t *hp = NULL;
    
    if (h) {
	hp = (shl_t *)malloc(sizeof (shl_t));
	if (!hp) {
	    shl_unload(h);
	} else {
	    *hp = h;
	}
    }

    return (dll_handle)hp;
}

int
dlclose(dll_handle h)
{
    shl_t hp = *((shl_t *)h);
    if (hp != NULL) free(hp);
    return shl_unload(h);
}

dll_func
dlsym(dll_handle h, char *n)
{
    dll_func handle;
    
    if (shl_findsym ((shl_t *)h, n, TYPE_PROCEDURE, &handle))
	return NULL;
    
    return (dll_func)handle;
}

char *dlerror()
{
    if (errno != 0) {
	return strerror(errno);
    }
    return "Generic shared library error";
}

#define SO_SUFFIX	".sl"
#else /* __hpux */
#define SO_SUFFIX	".so"
#endif /* __hpux */

#define LA_SUFFIX       ".la"
#endif /* DO_DLOPEN */

#if defined DO_DLOPEN || defined WIN_PLUG /* _SUN_SDK_ */
typedef struct lib_list 
{
    struct lib_list *next;
    void *library;
} lib_list_t;

#ifndef _SUN_SDK_
static lib_list_t *lib_list_head = NULL;
#endif /* !_SUN_SDK_ */

DEFINE_STATIC_MUTEX(global_mutex);

#endif /* DO_DLOPEN || WIN_PLUG */ /* _SUN_SDK_ */

int _sasl_locate_entry(void *library, const char *entryname,
		       void **entry_point) 
{
#ifdef DO_DLOPEN
/* note that we still check for known problem systems in
 * case we are cross-compiling */
#if defined(DLSYM_NEEDS_UNDERSCORE) || defined(__OpenBSD__)
    char adj_entryname[1024];
#else
#define adj_entryname entryname
#endif

    if(!entryname) {
#ifndef _SUN_SDK_
	_sasl_log(NULL, SASL_LOG_ERR,
		  "no entryname in _sasl_locate_entry");
#endif /* _SUN_SDK_ */
	return SASL_BADPARAM;
    }

    if(!library) {
#ifndef _SUN_SDK_
	_sasl_log(NULL, SASL_LOG_ERR,
		  "no library in _sasl_locate_entry");
#endif /* _SUN_SDK_ */
	return SASL_BADPARAM;
    }

    if(!entry_point) {
#ifndef _SUN_SDK_
	_sasl_log(NULL, SASL_LOG_ERR,
		  "no entrypoint output pointer in _sasl_locate_entry");
#endif /* _SUN_SDK_ */
	return SASL_BADPARAM;
    }

#if defined(DLSYM_NEEDS_UNDERSCORE) || defined(__OpenBSD__)
    snprintf(adj_entryname, sizeof adj_entryname, "_%s", entryname);
#endif

    *entry_point = NULL;
    *entry_point = dlsym(library, adj_entryname);
    if (*entry_point == NULL) {
#if 0 /* This message appears to confuse people */
	_sasl_log(NULL, SASL_LOG_DEBUG,
		  "unable to get entry point %s: %s", adj_entryname,
		  dlerror());
#endif
	return SASL_FAIL;
    }

    return SASL_OK;
#else
    return SASL_FAIL;
#endif /* DO_DLOPEN */
}

#ifdef DO_DLOPEN

#ifdef _SUN_SDK_
static int _sasl_plugin_load(_sasl_global_context_t *gctx,
			     char *plugin, void *library,
			     const char *entryname,
			     int (*add_plugin)(_sasl_global_context_t *gctx,
					       const char *, void *)) 
#else
static int _sasl_plugin_load(char *plugin, void *library,
			     const char *entryname,
			     int (*add_plugin)(const char *, void *)) 
#endif /* _SUN_SDK_ */
{
    void *entry_point;
    int result;
    
    result = _sasl_locate_entry(library, entryname, &entry_point);
    if(result == SASL_OK) {
#ifdef _SUN_SDK_
	result = add_plugin(gctx, plugin, entry_point);
#else
	result = add_plugin(plugin, entry_point);
#endif /* _SUN_SDK_ */
	if(result != SASL_OK)
#ifdef _SUN_SDK_
	    __sasl_log(gctx, gctx->server_global_callbacks.callbacks == NULL ?
	    	       gctx->client_global_callbacks.callbacks :
	    	       gctx->server_global_callbacks.callbacks,
	    	       SASL_LOG_DEBUG,
		       "_sasl_plugin_load failed on %s for plugin: %s\n",
		       entryname, plugin);
#else
	    _sasl_log(NULL, SASL_LOG_DEBUG,
		      "_sasl_plugin_load failed on %s for plugin: %s\n",
		      entryname, plugin);
#endif /* _SUN_SDK_ */
    }

    return result;
}

#ifndef _SUN_SDK_
/* this returns the file to actually open.
 *  out should be a buffer of size PATH_MAX
 *  and may be the same as in. */

/* We'll use a static buffer for speed unless someone complains */
#define MAX_LINE 2048

static int _parse_la(const char *prefix, const char *in, char *out) 
{
    FILE *file;
    size_t length;
    char line[MAX_LINE];
    char *ntmp = NULL;

    if(!in || !out || !prefix || out == in) return SASL_BADPARAM;

    /* Set this so we can detect failure */
    *out = '\0';

    length = strlen(in);

    if (strcmp(in + (length - strlen(LA_SUFFIX)), LA_SUFFIX)) {
	if(!strcmp(in + (length - strlen(SO_SUFFIX)),SO_SUFFIX)) {
	    /* check for a .la file */
	    strcpy(line, prefix);
	    strcat(line, in);
	    length = strlen(line);
	    *(line + (length - strlen(SO_SUFFIX))) = '\0';
	    strcat(line, LA_SUFFIX);
	    file = fopen(line, "rF");
	    if(file) {
		/* We'll get it on the .la open */
		fclose(file);
		return SASL_FAIL;
	    }
	}
	strcpy(out, prefix);
	strcat(out, in);
	return SASL_OK;
    }

    strcpy(line, prefix);
    strcat(line, in);

    file = fopen(line, "rF");
    if(!file) {
	_sasl_log(NULL, SASL_LOG_WARN,
		  "unable to open LA file: %s", line);
	return SASL_FAIL;
    }
    
    while(!feof(file)) {
	if(!fgets(line, MAX_LINE, file)) break;
	if(line[strlen(line) - 1] != '\n') {
	    _sasl_log(NULL, SASL_LOG_WARN,
		      "LA file has too long of a line: %s", in);
	    return SASL_BUFOVER;
	}
	if(line[0] == '\n' || line[0] == '#') continue;
	if(!strncmp(line, "dlname=", sizeof("dlname=") - 1)) {
	    /* We found the line with the name in it */
	    char *end;
	    char *start;
	    size_t len;
	    end = strrchr(line, '\'');
	    if(!end) continue;
	    start = &line[sizeof("dlname=")-1];
	    len = strlen(start);
	    if(len > 3 && start[0] == '\'') {
		ntmp=&start[1];
		*end='\0';
		/* Do we have dlname="" ? */
		if(ntmp == end) {
		    _sasl_log(NULL, SASL_LOG_DEBUG,
			      "dlname is empty in .la file: %s", in);
		    return SASL_FAIL;
		}
		strcpy(out, prefix);
		strcat(out, ntmp);
	    }
	    break;
	}
    }
    if(ferror(file) || feof(file)) {
	_sasl_log(NULL, SASL_LOG_WARN,
		  "Error reading .la: %s\n", in);
	fclose(file);
	return SASL_FAIL;
    }
    fclose(file);

    if(!(*out)) {
	_sasl_log(NULL, SASL_LOG_WARN,
		  "Could not find a dlname line in .la file: %s", in);
	return SASL_FAIL;
    }

    return SASL_OK;
}
#endif /* !_SUN_SDK_ */
#endif /* DO_DLOPEN */

/* loads a plugin library */
#ifdef _SUN_SDK_
int _sasl_get_plugin(_sasl_global_context_t *gctx,
		     const char *file,
		     const sasl_callback_t *verifyfile_cb,
		     void **libraryptr)
#else
int _sasl_get_plugin(const char *file,
		     const sasl_callback_t *verifyfile_cb,
		     void **libraryptr)
#endif /* _SUN_SDK_ */
{
#ifdef DO_DLOPEN
    int r = 0;
    int flag;
    void *library;
    lib_list_t *newhead;
    
    r = ((sasl_verifyfile_t *)(verifyfile_cb->proc))
		    (verifyfile_cb->context, file, SASL_VRFY_PLUGIN);
    if (r != SASL_OK) return r;

#ifdef RTLD_NOW
    flag = RTLD_NOW;
#else
    flag = 0;
#endif

    newhead = sasl_ALLOC(sizeof(lib_list_t));
    if(!newhead) return SASL_NOMEM;

    if (!(library = dlopen(file, flag))) {
#ifdef _SUN_SDK_
	__sasl_log(gctx, gctx->server_global_callbacks.callbacks == NULL ?
	    	   gctx->client_global_callbacks.callbacks :
	    	   gctx->server_global_callbacks.callbacks,
		   SASL_LOG_ERR,
		   "unable to dlopen %s: %s", file, dlerror());
#else
	_sasl_log(NULL, SASL_LOG_ERR,
		  "unable to dlopen %s: %s", file, dlerror());
#endif /* _SUN_SDK_ */
	sasl_FREE(newhead);
	return SASL_FAIL;
    }

#ifdef _SUN_SDK_
    if (LOCK_MUTEX(&global_mutex) < 0) {
	sasl_FREE(newhead);
	dlclose(library);
	return (SASL_FAIL);
    }
#endif /* _SUN_SDK_ */

    newhead->library = library;
#ifdef _SUN_SDK_
    newhead->next = gctx->lib_list_head;
    gctx->lib_list_head = newhead;
    UNLOCK_MUTEX(&global_mutex);
#else
    newhead->next = lib_list_head;
    lib_list_head = newhead;
#endif /* _SUN_SDK_ */

    *libraryptr = library;
    return SASL_OK;
#else
    return SASL_FAIL;
#endif /* DO_DLOPEN */
}

#ifdef _SUN_SDK_
#if defined DO_DLOPEN || defined WIN_PLUG /* _SUN_SDK_ */

static void release_plugin(_sasl_global_context_t *gctx, void *library)
{
    lib_list_t *libptr, *libptr_next = NULL, *libptr_prev = NULL;
    int r;

    r = LOCK_MUTEX(&global_mutex);
    if (r < 0)
	return;

    for(libptr = gctx->lib_list_head; libptr; libptr = libptr_next) {
	libptr_next = libptr->next;
	if (library == libptr->library) {
	    if(libptr->library)
#if defined DO_DLOPEN /* _SUN_SDK_ */
		dlclose(libptr->library);
#else
		FreeLibrary(libptr->library);
#endif /* DO_DLOPEN */ /* _SUN_SDK_ */
	    sasl_FREE(libptr);
	    break;
	}
	libptr_prev = libptr;
    }
    if (libptr_prev == NULL)
	gctx->lib_list_head = libptr_next;
    else
	libptr_prev->next = libptr_next;

    UNLOCK_MUTEX(&global_mutex);
}
#endif /* DO_DLOPEN || WIN_PLUG */ /* _SUN_SDK_ */
#endif /* _SUN_SDK_ */

/* gets the list of mechanisms */
#ifdef _SUN_SDK_
int _sasl_load_plugins(_sasl_global_context_t *gctx,
		       int server,
		       const add_plugin_list_t *entrypoints,
		       const sasl_callback_t *getpath_cb,
		       const sasl_callback_t *verifyfile_cb)
#else
int _sasl_load_plugins(const add_plugin_list_t *entrypoints,
		       const sasl_callback_t *getpath_cb,
		       const sasl_callback_t *verifyfile_cb)
#endif /* _SUN_SDK_ */
{
    int result;
    const add_plugin_list_t *cur_ep;
#ifdef _SUN_SDK_
    _sasl_path_info_t *path_info, *p_info;
#endif /* _SUN_SDK_ */
#ifdef DO_DLOPEN
    char str[PATH_MAX], tmp[PATH_MAX+2], prefix[PATH_MAX+2];
				/* 1 for '/' 1 for trailing '\0' */
    char c;
    int pos;
    const char *path=NULL;
    int position;
    DIR *dp;
    struct dirent *dir;
#ifdef _SUN_SDK_
    int plugin_loaded;
    struct stat b;
#endif /* _SUN_SDK_ */
#endif
#ifndef PIC
    add_plugin_t *add_plugin;
    _sasl_plug_type type;
    _sasl_plug_rec *p;
#endif

    if (! entrypoints
	|| ! getpath_cb
	|| getpath_cb->id != SASL_CB_GETPATH
	|| ! getpath_cb->proc
	|| ! verifyfile_cb
	|| verifyfile_cb->id != SASL_CB_VERIFYFILE
	|| ! verifyfile_cb->proc)
	return SASL_BADPARAM;

#ifndef PIC
    /* do all the static plugins first */

    for(cur_ep = entrypoints; cur_ep->entryname; cur_ep++) {

	/* What type of plugin are we looking for? */
	if(!strcmp(cur_ep->entryname, "sasl_server_plug_init")) {
	    type = SERVER;
#ifdef _SUN_SDK_
	    add_plugin = (add_plugin_t *)_sasl_server_add_plugin;
#else
	    add_plugin = (add_plugin_t *)sasl_server_add_plugin;
#endif /* _SUN_SDK_ */
	} else if (!strcmp(cur_ep->entryname, "sasl_client_plug_init")) {
	    type = CLIENT;
#ifdef _SUN_SDK_
	    add_plugin = (add_plugin_t *)_sasl_client_add_plugin;
#else
	    add_plugin = (add_plugin_t *)sasl_client_add_plugin;
#endif /* _SUN_SDK_ */
	} else if (!strcmp(cur_ep->entryname, "sasl_auxprop_plug_init")) {
	    type = AUXPROP;
#ifdef _SUN_SDK_
	    add_plugin = (add_plugin_t *)_sasl_auxprop_add_plugin;
#else
	    add_plugin = (add_plugin_t *)sasl_auxprop_add_plugin;
#endif /* _SUN_SDK_ */
	} else if (!strcmp(cur_ep->entryname, "sasl_canonuser_init")) {
	    type = CANONUSER;
#ifdef _SUN_SDK_
	    add_plugin = (add_plugin_t *)_sasl_canonuser_add_plugin;
#else
	    add_plugin = (add_plugin_t *)sasl_canonuser_add_plugin;
#endif /* _SUN_SDK_ */
	} else {
	    /* What are we looking for then? */
	    return SASL_FAIL;
	}
	for (p=_sasl_static_plugins; p->type; p++) {
	    if(type == p->type)
#ifdef _SUN_SDK_
	    	result = add_plugin(gctx, p->name, (void *)p->plug);
#else
	    	result = add_plugin(p->name, p->plug);
#endif /* _SUN_SDK_ */
	}
    }
#endif /* !PIC */

/* only do the following if:
 * 
 * we support dlopen()
 *  AND we are not staticly compiled
 *      OR we are staticly compiled and TRY_DLOPEN_WHEN_STATIC is defined
 */
#if defined(DO_DLOPEN) && (defined(PIC) || (!defined(PIC) && defined(TRY_DLOPEN_WHEN_STATIC)))
    /* get the path to the plugins */
    result = ((sasl_getpath_t *)(getpath_cb->proc))(getpath_cb->context,
						    &path);
    if (result != SASL_OK) return result;
    if (! path) return SASL_FAIL;

    if (strlen(path) >= PATH_MAX) { /* no you can't buffer overrun */
	return SASL_FAIL;
    }

    position=0;
    do {
	pos=0;
	do {
	    c=path[position];
	    position++;
	    str[pos]=c;
	    pos++;
	} while ((c!=':') && (c!='=') && (c!=0));
	str[pos-1]='\0';

	strcpy(prefix,str);
	strcat(prefix,"/");
#ifdef _SUN_SDK_
	path_info = server ? gctx->splug_path_info : gctx->cplug_path_info;
	while (path_info != NULL) {
	    if (strcmp(path_info->path, prefix) == 0)
		break;
	    path_info = path_info->next;
	}
	if (stat(prefix, &b) != 0) {
	    continue;
	}
	if ( path_info == NULL) {
	    p_info = (_sasl_path_info_t *)
		sasl_ALLOC(sizeof (_sasl_path_info_t));
	    if (p_info == NULL) {
		return SASL_NOMEM;
	    }
	    if(_sasl_strdup(prefix, &p_info->path, NULL) != SASL_OK) {
		sasl_FREE(p_info);
		return SASL_NOMEM;
	    }
	    p_info->last_changed = b.st_mtime;
	    if (server) {
		p_info->next = gctx->splug_path_info;
		gctx->splug_path_info = p_info;
	    } else {
		p_info->next = gctx->cplug_path_info;
		gctx->cplug_path_info = p_info;
	    }
	} else {
	    if (b.st_mtime <= path_info->last_changed) {
		continue;
	    }
	}
#endif /* _SUN_SDK_ */

	if ((dp=opendir(str)) !=NULL) /* ignore errors */    
	{
	    while ((dir=readdir(dp)) != NULL)
	    {
		size_t length;
		void *library;
#ifndef _SUN_SDK_
		char *c;
#endif /* !_SUN_SDK_ */
		char plugname[PATH_MAX];
		char name[PATH_MAX];

		length = NAMLEN(dir);
#ifndef _SUN_SDK_
		if (length < 4) 
		    continue; /* can not possibly be what we're looking for */
#endif /* !_SUN_SDK_ */

		if (length + pos>=PATH_MAX) continue; /* too big */

#ifdef _SUN_SDK_
		if (dir->d_name[0] == '.')
		    continue;
#else
		if (strcmp(dir->d_name + (length - strlen(SO_SUFFIX)),
			   SO_SUFFIX)
		    && strcmp(dir->d_name + (length - strlen(LA_SUFFIX)),
			   LA_SUFFIX))
		    continue;
#endif /* _SUN_SDK_ */

		memcpy(name,dir->d_name,length);
		name[length]='\0';

#ifdef _SUN_SDK_
		snprintf(tmp, sizeof (tmp), "%s%s", prefix, name);
#else
		result = _parse_la(prefix, name, tmp);
		if(result != SASL_OK)
		    continue;
#endif /* _SUN_SDK_ */
		
#ifdef _SUN_SDK_
		if (stat(tmp, &b))
			continue;	/* Can't stat it */
		if (!S_ISREG(b.st_mode))
			continue;
		/* Sun plugins don't have lib prefix */
		strcpy(plugname, name);
#else
		/* skip "lib" and cut off suffix --
		   this only need be approximate */
		strcpy(plugname, name + 3);
		c = strchr(plugname, (int)'.');
		if(c) *c = '\0';
#endif /* _SUN_SDK_ */

#ifdef _SUN_SDK_
		result = _sasl_get_plugin(gctx, tmp, verifyfile_cb,
                        &library);
#else
		result = _sasl_get_plugin(tmp, verifyfile_cb, &library);
#endif /* _SUN_SDK_ */

		if(result != SASL_OK)
		    continue;

#ifdef _SUN_SDK_
		plugin_loaded = 0;
		for(cur_ep = entrypoints; cur_ep->entryname; cur_ep++) {
			/* If this fails, it's not the end of the world */
			if (_sasl_plugin_load(gctx, plugname, library,
					cur_ep->entryname,
					cur_ep->add_plugin) == SASL_OK) {
			    plugin_loaded = 1;
			}
		}
		if (!plugin_loaded)
			release_plugin(gctx, library);
#else
		for(cur_ep = entrypoints; cur_ep->entryname; cur_ep++) {
			_sasl_plugin_load(plugname, library, cur_ep->entryname,
					  cur_ep->add_plugin);
			/* If this fails, it's not the end of the world */
		}
#endif /* _SUN_SDK_ */
	    }

	    closedir(dp);
	}

    } while ((c!='=') && (c!=0));
#elif defined _SUN_SDK_ && defined WIN_PLUG
    result =
	_sasl_load_win_plugins(gctx, entrypoints, getpath_cb, verifyfile_cb);
    if (result != SASL_OK)
	return (result);
#endif /* defined(DO_DLOPEN) && (!defined(PIC) || (defined(PIC) && defined(TRY_DLOPEN_WHEN_STATIC))) */

    return SASL_OK;
}

#ifdef _SUN_SDK_
int
_sasl_done_with_plugins(_sasl_global_context_t *gctx)
#else
int
_sasl_done_with_plugins(void)
#endif /* _SUN_SDK_ */
{
#if defined DO_DLOPEN || defined WIN_PLUG /* _SUN_SDK_ */
    lib_list_t *libptr, *libptr_next;
    
#ifdef _SUN_SDK_
    if (LOCK_MUTEX(&global_mutex) < 0)
	return (SASL_FAIL);
#endif /* _SUN_SDK_ */

#ifdef _SUN_SDK_
    for(libptr = gctx->lib_list_head; libptr; libptr = libptr_next) {
#else
    for(libptr = lib_list_head; libptr; libptr = libptr_next) {
#endif /* _SUN_SDK_ */
	libptr_next = libptr->next;
	if(libptr->library)
#ifdef DO_DLOPEN /* _SUN_SDK_ */
	    dlclose(libptr->library);
#else
	    FreeLibrary(libptr->library);
#endif /* DO_DLOPEN */ /* _SUN_SDK_ */
	sasl_FREE(libptr);
    }

#ifdef _SUN_SDK_
    gctx->lib_list_head = NULL;
#else
    lib_list_head = NULL;
#endif /* _SUN_SDK_ */

#ifdef _SUN_SDK_
    UNLOCK_MUTEX(&global_mutex);
#endif /* _SUN_SDK_ */
#endif /* DO_DLOPEN || WIN_PLUG */ /* _SUN_SDK_ */
    return SASL_OK;
}

#ifdef WIN_MUTEX

static HANDLE global_mutex = NULL;

int win_global_mutex_lock()
{
    DWORD dwWaitResult; 

    if (global_mutex == NULL) {
	global_mutex = CreateMutex(NULL, FALSE, NULL);
	if (global_mutex == NULL)
	    return (-1);
    }

    dwWaitResult = WaitForSingleObject(global_mutex, INFINITE);

    switch (dwWaitResult) {
	case WAIT_OBJECT_0: 
		return (0);

           case WAIT_TIMEOUT: 
               return (-1); /* Shouldn't happen */

           case WAIT_ABANDONED: 
               return (-1); /* Shouldn't happen */
    }
    return (-1); /* Unexpected result */
}

int win_global_mutex_unlock()
{
    if (global_mutex == NULL)
	return (-1);

    return (ReleaseMutex(global_mutex) ? 0 : -1);
}

BOOL APIENTRY DllMain(HANDLE hModule, 
                         DWORD  ul_reason_for_call, 
                         LPVOID lpReserved)
{
    switch( ul_reason_for_call ) {
	case DLL_PROCESS_ATTACH:
	    global_mutex = CreateMutex(NULL, FALSE, NULL);
	    if (global_mutex == NULL)
		return (FALSE);
	    break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
	    break;
    }
    return TRUE;
}
#endif
