/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* saslint.h - internal SASL library definitions
 * Rob Siemborski
 * Tim Martin
 * $Id: saslint.h,v 1.48 2003/04/16 19:36:01 rjs3 Exp $
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

#ifndef SASLINT_H
#define SASLINT_H

#include <config.h>
#include "sasl.h"
#include "saslplug.h"
#include "saslutil.h"
#include "prop.h"

/* #define'd constants */
#define CANON_BUF_SIZE 256

/* Error Handling Foo */
/* Helpful Hints:
 *  -Error strings are set as soon as possible (first function in stack trace
 *   with a pointer to the sasl_conn_t.
 *  -Error codes are set as late as possible (only in the sasl api functions),
 *   thoug "as often as possible" also comes to mind to ensure correctness
 *  -Errors from calls to _buf_alloc, _sasl_strdup, etc are assumed to be
 *   memory errors.
 *  -Only errors (error codes < SASL_OK) should be remembered
 */
#define RETURN(conn, val) { if(conn && (val) < SASL_OK) \
                               (conn)->error_code = (val); \
                            return (val); }
#if !defined _SUN_SDK || defined  DEBUG
#define MEMERROR(conn) {\
    if(conn) sasl_seterror( (conn), 0, \
                   "Out of Memory in " __FILE__ " near line %d", __LINE__ ); \
    RETURN(conn, SASL_NOMEM) }
#define PARAMERROR(conn) {\
    if(conn) sasl_seterror( (conn), SASL_NOLOG, \
                  "Parameter error in " __FILE__ " near line %d", __LINE__ ); \
    RETURN(conn, SASL_BADPARAM) }
#define INTERROR(conn, val) {\
    if(conn) sasl_seterror( (conn), 0, \
                   "Internal Error %d in " __FILE__ " near line %d", (val),\
		   __LINE__ ); \
    RETURN(conn, (val)) }
#else
#define MEMERROR(conn) {\
    if(conn) _sasl_log((conn), SASL_LOG_WARN, "Out of Memory"); \
    RETURN(conn, SASL_NOMEM) }
#define PARAMERROR(conn) {\
    if(conn) _sasl_log((conn), SASL_LOG_WARN, "Parameter error"); \
    RETURN(conn, SASL_BADPARAM) }
#define INTERROR(conn, val) {\
    if(conn) _sasl_log((conn), SASL_LOG_ERR, "Internal Error: %d", (val)); \
    RETURN(conn, (val)) }
#endif

#ifndef PATH_MAX
# ifdef WIN32
#  define PATH_MAX MAX_PATH
# else
#  ifdef _POSIX_PATH_MAX
#   define PATH_MAX _POSIX_PATH_MAX
#  else
#   define PATH_MAX 1024         /* arbitrary; probably big enough will
                                  * probably only be 256+64 on
                                  * pre-posix machines */
#  endif /* _POSIX_PATH_MAX */
# endif /* WIN32 */
#endif

/* : Define directory delimiter in SASL_PATH variable */
#ifdef WIN32
#define PATHS_DELIMITER	';'
#else
#define PATHS_DELIMITER	':'
#endif

/* Datatype Definitions */
typedef struct {
  const sasl_callback_t *callbacks;
  const char *appname;
#ifdef _SUN_SDK_
  struct _sasl_global_context_s *gctx;
#endif /* _SUN_SDK_ */
} sasl_global_callbacks_t;

typedef struct _sasl_external_properties 
{
    sasl_ssf_t ssf;
    char *auth_id;
} _sasl_external_properties_t;

typedef struct sasl_string_list
{
    const char *d;
    struct sasl_string_list *next;
} sasl_string_list_t;

typedef struct buffer_info
{ 
    char *data;
    size_t curlen;
    size_t reallen;
} buffer_info_t;

#ifdef _SUN_SDK_
typedef int add_plugin_t(struct _sasl_global_context_s *gctx,
			const char *, void *);
#else
typedef int add_plugin_t(const char *, void *);
#endif /* _SUN_SDK_ */

typedef struct add_plugin_list 
{
    const char *entryname;
    add_plugin_t *add_plugin;
} add_plugin_list_t;

enum Sasl_conn_type { SASL_CONN_UNKNOWN = 0,
		      SASL_CONN_SERVER = 1,
                      SASL_CONN_CLIENT = 2 };

struct sasl_conn {
  enum Sasl_conn_type type;

  void (*destroy_conn)(sasl_conn_t *); /* destroy function */

  char *service;

  unsigned int flags;  /* flags passed to sasl_*_new */

  /* IP information.  A buffer of size 52 is adequate for this in its
     longest format (see sasl.h) */
  int got_ip_local, got_ip_remote;
  char iplocalport[NI_MAXHOST + NI_MAXSERV];
  char ipremoteport[NI_MAXHOST + NI_MAXSERV];

  void *context;
  sasl_out_params_t oparams;

  sasl_security_properties_t props;
  _sasl_external_properties_t external;

#ifndef _SUN_SDK_
  sasl_secret_t *secret;
#endif /* !_SUN_SDK_ */

  int (*idle_hook)(sasl_conn_t *conn);
  const sasl_callback_t *callbacks;
  const sasl_global_callbacks_t *global_callbacks; /* global callbacks
						    * connection */
  char *serverFQDN;

  /* Pointers to memory that we are responsible for */
  buffer_info_t *encode_buf;

  int error_code;
  char *error_buf, *errdetail_buf;
  size_t error_buf_len, errdetail_buf_len;
  char *mechlist_buf;
  size_t mechlist_buf_len;

  char *decode_buf;

  char user_buf[CANON_BUF_SIZE+1], authid_buf[CANON_BUF_SIZE+1];

#ifdef _SUN_SDK_
  struct _sasl_global_context_s *gctx;
#ifdef _INTEGRATED_SOLARIS_
  int sun_reg;
#endif /* _INTEGRATED_SOLARIS_ */
#endif /* _SUN_SDK_ */
};

#ifdef _SUN_SDK_
/* track changes in file system */
typedef struct _sasl_path_info {
    char *path;
    time_t last_changed;
    struct _sasl_path_info *next;
} _sasl_path_info_t;
#endif /* _SUN_SDK_ */

/* Server Conn Type Information */

typedef struct mechanism
{
    int version;
    int condition; /* set to SASL_NOUSER if no available users;
		      set to SASL_CONTINUE if delayed plugn loading */
    char *plugname; /* for AUTHSOURCE tracking */
#ifdef _SUN_SDK_
#ifdef _INTEGRATED_SOLARIS_
    int sun_reg;
#endif /* _INTEGRATED_SOLARIS_ */
    sasl_server_plug_t *plug;
	/*
	 * The global context needs to be stored with separately from the	
	 * the plugin because it will be overwritten when the plugin is
	 * relloaded
	 */
    void *glob_context;
    struct mechanism *next;
#else
    const sasl_server_plug_t *plug;
    struct mechanism *next;
    char *f;       /* where should i load the mechanism from? */
#endif /* _SUN_SDK_ */
} mechanism_t;

typedef struct mech_list {
  const sasl_utils_t *utils;  /* gotten from plug_init */

  void *mutex;            /* mutex for this data */ 
  mechanism_t *mech_list; /* list of mechanisms */
  int mech_length;       /* number of mechanisms */
} mech_list_t;

typedef struct context_list 
{
    mechanism_t *mech;
    void *context;     /* if NULL, this mech is disabled for this connection
			* otherwise, use this context instead of a call
			* to mech_new */
    struct context_list *next;
} context_list_t;

typedef struct sasl_server_conn {
    sasl_conn_t base; /* parts common to server + client */

    char *user_realm; /* domain the user authenticating is in */
    int sent_last; /* Have we already done the last send? */
    int authenticated;
    mechanism_t *mech; /* mechanism trying to use */
    sasl_server_params_t *sparams;
    context_list_t *mech_contexts;
} sasl_server_conn_t;

/* Client Conn Type Information */

typedef struct cmechanism
{
    int version;

    char *plugname;
#ifdef _SUN_SDK_
#ifdef _INTEGRATED_SOLARIS_
    int sun_reg;
#endif /* _INTEGRATED_SOLARIS_ */
	/*
	 * The global context needs to be stored with separately from the	
	 * the plugin because it will be overwritten when the plugin is
	 * relloaded
	 */
    void *glob_context;
    sasl_client_plug_t *plug;
#else
    const sasl_client_plug_t *plug;
#endif /* _SUN_SDK_ */

    struct cmechanism *next;  
} cmechanism_t;

typedef struct cmech_list {
  const sasl_utils_t *utils; 

  void *mutex;            /* mutex for this data */ 
  cmechanism_t *mech_list; /* list of mechanisms */
  int mech_length;       /* number of mechanisms */

} cmech_list_t;

typedef struct sasl_client_conn {
  sasl_conn_t base; /* parts common to server + client */

  cmechanism_t *mech;
  sasl_client_params_t *cparams;

  char *clientFQDN;

} sasl_client_conn_t;

typedef struct sasl_allocation_utils {
  sasl_malloc_t *malloc;
  sasl_calloc_t *calloc;
  sasl_realloc_t *realloc;
  sasl_free_t *free;
} sasl_allocation_utils_t;

typedef struct sasl_mutex_utils {
  sasl_mutex_alloc_t *alloc;
  sasl_mutex_lock_t *lock;
  sasl_mutex_unlock_t *unlock;
  sasl_mutex_free_t *free;
} sasl_mutex_utils_t;

typedef struct sasl_log_utils_s {
  sasl_log_t *log;
} sasl_log_utils_t;

#ifdef _SUN_SDK_
/*
 * The following structure contains the global state for libsasl */
typedef struct _sasl_global_context_s {
    int				sasl_server_active;
				/* sasl server init'ed */
    mech_list_t			*mechlist;
				/* list of server mechs */
    _sasl_path_info_t		*splug_path_info;
				/* path info for server plugins */
    sasl_global_callbacks_t	server_global_callbacks;
				/* callbacks for sasl_server_init */
    int				(*sasl_server_cleanup_hook)
					(struct _sasl_global_context_s *gctx);
				/* entry point to clean up sasl server */
    int				(*sasl_server_idle_hook)(sasl_conn_t *conn);
				/* entry point for sasl server idle */

    cmech_list_t		*cmechlist;
				/* list of client mechs */
    _sasl_path_info_t		*cplug_path_info;
				/* path info for client plugins */
    sasl_global_callbacks_t	client_global_callbacks;
				/* callbacks for sasl_client_init */
    int				sasl_client_active;
				/* sasl client init'ed */
    int				(*sasl_client_cleanup_hook)
					(struct _sasl_global_context_s *gctx);
				/* entry point to clean up sasl client */
    int				(*sasl_client_idle_hook)(sasl_conn_t *conn);
				/* entry point for sasl client idle */

    const sasl_utils_t		*sasl_server_global_utils;
				/* sasl server global utils */
    const sasl_utils_t		*sasl_canonusr_global_utils;
				/* sasl global utils for canonusr plugin */

    void			*configlist;
				/* Configuration key value pair data list */
    int				nconfiglist;
				/* number of items in configlist */
    char			*config_path;
				/* last read config path */
    time_t			config_last_read;
				/* last time config read */

    void			*auxprop_head;
				/* Head of auxprop plugin list */
    void			*canonuser_head;
				/* Head of canonusr plugin list */
    char			**global_mech_list;
				/* Global list of mechanisms */
    void			*free_mutex;
				/* sasl_done()/sasl_dispose() mutex */
    sasl_allocation_utils_t     sasl_allocation_utils;
				/* malloc et al */
    sasl_mutex_utils_t		sasl_mutex_utils;
				/* mutex_alloc et al */
    void			*lib_list_head;
				/* list of dynamic libs opened */
}_sasl_global_context_t;
#endif /* _SUN_SDK_ */

typedef int sasl_plaintext_verifier(sasl_conn_t *conn,
				    const char *userid,
				    const char *passwd,
				    const char *service,
				    const char *user_realm);

struct sasl_verify_password_s {
    char *name;
    sasl_plaintext_verifier *verify;
};

/*
 * globals & constants
 */
/*
 * common.c
 */
#ifndef _SUN_SDK_
LIBSASL_API const sasl_utils_t *sasl_global_utils;

extern int (*_sasl_client_idle_hook)(sasl_conn_t *conn);
extern int (*_sasl_server_idle_hook)(sasl_conn_t *conn);

/* These return SASL_OK if we've actually finished cleanup, 
 * SASL_NOTINIT if that part of the library isn't inited, and
 * SASL_CONTINUE if we need to call them again */
extern int (*_sasl_client_cleanup_hook)(void);
extern int (*_sasl_server_cleanup_hook)(void);

extern sasl_allocation_utils_t _sasl_allocation_utils;
extern sasl_mutex_utils_t _sasl_mutex_utils;
#endif /* !_SUN_SDK_ */

/*
 * checkpw.c
 */
extern struct sasl_verify_password_s _sasl_verify_password[];

/*
 * server.c
 */
/* (this is a function call to ensure this is read-only to the outside) */
#ifdef _SUN_SDK_
extern int _is_sasl_server_active(_sasl_global_context_t *gctx);
#else
extern int _is_sasl_server_active(void);
#endif /* _SUN_SDK_ */

/*
 * Allocation and Mutex utility macros
 */
#ifdef _SUN_SDK_
#define sasl_ALLOC(__size__) (gctx->sasl_allocation_utils.malloc((__size__)))
#define sasl_CALLOC(__nelem__, __size__) \
        (gctx->sasl_allocation_utils.calloc((__nelem__), (__size__)))
#define sasl_REALLOC(__ptr__, __size__) \
        (gctx->sasl_allocation_utils.realloc((__ptr__), (__size__)))
#define sasl_FREE(__ptr__) (gctx->sasl_allocation_utils.free((__ptr__)))
#define sasl_sun_ALLOC(__size__) (malloc((__size__)))
#define sasl_sun_CALLOC(__nelem__, __size__) (calloc((__nelem__), (__size__)))
#define sasl_sun_REALLOC(__ptr__, __size__) (realloc((__ptr__), (__size__)))
#define sasl_sun_FREE(__ptr__) (free((__ptr__)))

#define sasl_MUTEX_ALLOC() (gctx->sasl_mutex_utils.alloc())
#define sasl_MUTEX_LOCK(__mutex__) (gctx->sasl_mutex_utils.lock((__mutex__)))
#define sasl_MUTEX_UNLOCK(__mutex__) \
	(gctx->sasl_mutex_utils.unlock((__mutex__)))
#define sasl_MUTEX_FREE(__mutex__) (gctx->sasl_mutex_utils.free((__mutex__)))
#else
#define sasl_ALLOC(__size__) (_sasl_allocation_utils.malloc((__size__)))
#define sasl_CALLOC(__nelem__, __size__) \
	(_sasl_allocation_utils.calloc((__nelem__), (__size__)))
#define sasl_REALLOC(__ptr__, __size__) \
	(_sasl_allocation_utils.realloc((__ptr__), (__size__)))
#define sasl_FREE(__ptr__) (_sasl_allocation_utils.free((__ptr__)))

#define sasl_MUTEX_ALLOC() (_sasl_mutex_utils.alloc())
#define sasl_MUTEX_LOCK(__mutex__) (_sasl_mutex_utils.lock((__mutex__)))
#define sasl_MUTEX_UNLOCK(__mutex__) (_sasl_mutex_utils.unlock((__mutex__)))
#define sasl_MUTEX_FREE(__mutex__) \
	(_sasl_mutex_utils.free((__mutex__)))
#endif /* _SUN_SDK_ */

/* function prototypes */
/*
 * dlopen.c and staticopen.c
 */
/*
 * The differences here are:
 * _sasl_load_plugins loads all plugins from all files
 * _sasl_get_plugin loads the LIBRARY for an individual file
 * _sasl_done_with_plugins frees the LIBRARIES loaded by the above 2
 * _sasl_locate_entry locates an entrypoint in a given library
 */
#ifdef _SUN_SDK_
extern int _sasl_load_plugins(_sasl_global_context_t *gctx,
			      int server,
                              const add_plugin_list_t *entrypoints,
                              const sasl_callback_t *getpath_callback,
                              const sasl_callback_t *verifyfile_callback);

extern int _sasl_get_plugin(_sasl_global_context_t *gctx,
                            const char *file,
                            const sasl_callback_t *verifyfile_cb,
                            void **libraryptr);
extern int _sasl_locate_entry(void *library, const char *entryname,
                              void **entry_point);
extern int _sasl_done_with_plugins(_sasl_global_context_t *gctx);
#else
extern int _sasl_load_plugins(const add_plugin_list_t *entrypoints,
			       const sasl_callback_t *getpath_callback,
			       const sasl_callback_t *verifyfile_callback);
extern int _sasl_get_plugin(const char *file,
			    const sasl_callback_t *verifyfile_cb,
			    void **libraryptr);
extern int _sasl_locate_entry(void *library, const char *entryname,
                              void **entry_point);
extern int _sasl_done_with_plugins();
#endif /* _SUN_SDK_ */


/*
 * common.c
 */
extern const sasl_callback_t *
_sasl_find_getpath_callback(const sasl_callback_t *callbacks);

extern const sasl_callback_t *
_sasl_find_verifyfile_callback(const sasl_callback_t *callbacks);

#ifdef _SUN_SDK_
extern const sasl_callback_t *
_sasl_find_getconf_callback(const sasl_callback_t *callbacks);

extern int _sasl_common_init(_sasl_global_context_t *gctx,
			     sasl_global_callbacks_t *global_callbacks,
			     int server);
#else
extern int _sasl_common_init(sasl_global_callbacks_t *global_callbacks);
#endif /* _SUN_SDK_ */

extern int _sasl_conn_init(sasl_conn_t *conn,
			   const char *service,
			   unsigned int flags,
			   enum Sasl_conn_type type,
			   int (*idle_hook)(sasl_conn_t *conn),
			   const char *serverFQDN,
			   const char *iplocalport,
			   const char *ipremoteport,
			   const sasl_callback_t *callbacks,
			   const sasl_global_callbacks_t *global_callbacks);
extern void _sasl_conn_dispose(sasl_conn_t *conn);

#ifdef _SUN_SDK_
extern sasl_utils_t *
_sasl_alloc_utils(_sasl_global_context_t *gctx, sasl_conn_t *conn,
		  sasl_global_callbacks_t *global_callbacks);
#else
extern sasl_utils_t *
_sasl_alloc_utils(sasl_conn_t *conn,
		  sasl_global_callbacks_t *global_callbacks);
#endif /* _SUN_SDK_ */
extern int _sasl_free_utils(const sasl_utils_t ** utils);

extern int
_sasl_getcallback(sasl_conn_t * conn,
		  unsigned long callbackid,
		  int (**pproc)(),
		  void **pcontext);

extern void
_sasl_log(sasl_conn_t *conn,
	  int level,
	  const char *fmt,
	  ...);

#ifdef _SUN_SDK_
extern void
__sasl_log(const _sasl_global_context_t *gctx,
	   const sasl_callback_t *callbacks,
	   int level,
	   const char *fmt,
	   ...);
#endif /* _SUN_SDK_ */
void _sasl_get_errorbuf(sasl_conn_t *conn, char ***bufhdl, size_t **lenhdl);
#ifdef _SUN_SDK_
int __sasl_add_string(const _sasl_global_context_t *gctx, char **out,
                      size_t *alloclen,
                      size_t *outlen, const char *add);

#define _sasl_add_string(out, alloclen, outlen, add) \
	__sasl_add_string(gctx, out, alloclen, outlen, add)

/* More Generic Utilities in common.c */
#define _sasl_strdup(in, out, outlen) \
	__sasl_strdup(gctx, in, out, outlen)
extern int __sasl_strdup(const _sasl_global_context_t *gctx, const char *in,
                        char **out, size_t *outlen);

/* Basically a conditional call to realloc(), if we need more */
int __buf_alloc(const _sasl_global_context_t *gctx, char **rwbuf,
	size_t *curlen, size_t newlen);
#define _buf_alloc(rwbuf, curlen, newlen) \
	__buf_alloc(gctx, rwbuf, curlen, newlen)
#else
int _sasl_add_string(char **out, size_t *alloclen,
		     size_t *outlen, const char *add);

/* More Generic Utilities in common.c */
extern int _sasl_strdup(const char *in, char **out, size_t *outlen);

/* Basically a conditional call to realloc(), if we need more */
int _buf_alloc(char **rwbuf, size_t *curlen, size_t newlen);
#endif /* _SUN_SDK_ */

/* convert an iovec to a single buffer */
#ifdef _SUN_SDK_
int _iovec_to_buf(const _sasl_global_context_t *gctx, const struct iovec *vec,
                  unsigned numiov, buffer_info_t **output);
#else
int _iovec_to_buf(const struct iovec *vec,
		  unsigned numiov, buffer_info_t **output);
#endif /* _SUN_SDK_ */

/* Convert between string formats and sockaddr formats */
int _sasl_iptostring(const struct sockaddr *addr, socklen_t addrlen,
		     char *out, unsigned outlen);
int _sasl_ipfromstring(const char *addr, struct sockaddr *out,
		       socklen_t outlen);

/*
 * external plugin (external.c)
 */
int external_client_plug_init(const sasl_utils_t *utils,
			      int max_version,
			      int *out_version,
			      sasl_client_plug_t **pluglist,
			      int *plugcount);
int external_server_plug_init(const sasl_utils_t *utils,
			      int max_version,
			      int *out_version,
			      sasl_server_plug_t **pluglist,
			      int *plugcount);

/* Mech Listing Functions */
#ifdef _SUN_SDK_
int _sasl_build_mechlist(_sasl_global_context_t *gctx);
#else
int _sasl_build_mechlist(void);
#endif /* _SUN_SDK_ */

int _sasl_server_listmech(sasl_conn_t *conn,
			  const char *user,
			  const char *prefix,
			  const char *sep,
			  const char *suffix,
			  const char **result,
			  unsigned *plen,
			  int *pcount);
int _sasl_client_listmech(sasl_conn_t *conn,
			  const char *prefix,
			  const char *sep,
			  const char *suffix,
			  const char **result,
			  unsigned *plen,
			  int *pcount);
/* Just create a straight list of them */
#ifdef _SUN_SDK_
sasl_string_list_t *_sasl_client_mechs(_sasl_global_context_t *gctx);
sasl_string_list_t *_sasl_server_mechs(_sasl_global_context_t *gctx);
#else
sasl_string_list_t *_sasl_client_mechs(void);
sasl_string_list_t *_sasl_server_mechs(void);
#endif /* _SUN_SDK_ */

/*
 * config file declarations (config.c)
 */
#ifdef _SUN_SDK_
extern int sasl_config_init(_sasl_global_context_t *gctx,
        const char *filename);
extern void sasl_config_free(_sasl_global_context_t *gctx);
extern const char *sasl_config_getstring(_sasl_global_context_t *gctx,
        const char *key,const char *def);
extern int sasl_config_getint(_sasl_global_context_t *gctx,
        const char *key,int def);
extern int sasl_config_getswitch(_sasl_global_context_t *gctx,
        const char *key,int def);
#else
extern int sasl_config_init(const char *filename);
extern const char *sasl_config_getstring(const char *key,const char *def);
extern int sasl_config_getint(const char *key,int def);
extern int sasl_config_getswitch(const char *key,int def);
#endif /* _SUN_SDK_ */

/* checkpw.c */
#ifdef DO_SASL_CHECKAPOP
extern int _sasl_auxprop_verify_apop(sasl_conn_t *conn,
				     const char *userstr,
				     const char *challenge,
				     const char *response,
				     const char *user_realm);
#endif /* DO_SASL_CHECKAPOP */

/* Auxprop Plugin (checkpw.c) */
extern int sasldb_auxprop_plug_init(const sasl_utils_t *utils,
				    int max_version,
				    int *out_version,
				    sasl_auxprop_plug_t **plug,
				    const char *plugname);

/*
 * auxprop.c
 */
#ifdef _SUN_SDK_
extern void _sasl_auxprop_free(_sasl_global_context_t *gctx);
#else
extern int _sasl_auxprop_add_plugin(void *p, void *library);
extern void _sasl_auxprop_free(void);
#endif /* _SUN_SDK_ */
extern void _sasl_auxprop_lookup(sasl_server_params_t *sparams,
				 unsigned flags,
				 const char *user, unsigned ulen);

/*
 * canonusr.c
 */
#ifdef _SUN_SDK_
void _sasl_canonuser_free(_sasl_global_context_t *gctx);
#else
void _sasl_canonuser_free();
#endif /* _SUN_SDK_ */
extern int internal_canonuser_init(const sasl_utils_t *utils,
				   int max_version,
				   int *out_version,
				   sasl_canonuser_plug_t **plug,
				   const char *plugname);
extern int _sasl_canon_user(sasl_conn_t *conn,
			    const char *user, unsigned ulen,
			    unsigned flags,
			    sasl_out_params_t *oparams);

#ifdef _SUN_SDK_
/* Private functions to create, free, and use a private context */
void *sasl_create_context(void);

void sasl_free_context(void *context);

extern int _sasl_server_init(void *ctx, const sasl_callback_t *callbacks,
		     const char *appname);

extern int _sasl_server_new(void *ctx, const char *service,
			    const char *serverFQDN, const char *user_realm,
			    const char *iplocalport, const char *ipremoteport,
			    const sasl_callback_t *callbacks, unsigned flags,
			    sasl_conn_t **pconn);

extern int _sasl_client_init(void *ctx,
			     const sasl_callback_t *callbacks);

extern int _sasl_client_new(void *ctx,
			    const char *service,
			    const char *serverFQDN,
			    const char *iplocalport,
			    const char *ipremoteport,
			    const sasl_callback_t *prompt_supp,
			    unsigned flags,
			    sasl_conn_t **pconn);

extern int _sasl_client_add_plugin(void *ctx,
                                   const char *plugname,
                                   sasl_client_plug_init_t *cplugfunc);
extern int _sasl_server_add_plugin(void *ctx,
                                   const char *plugname,
                                   sasl_server_plug_init_t *splugfunc);
extern int _sasl_canonuser_add_plugin(void *ctx,
                                      const char *plugname,
                                      sasl_canonuser_init_t *canonuserfunc);
extern int _sasl_auxprop_add_plugin(void *ctx,
                                    const char *plugname,
                                    sasl_auxprop_init_t *auxpropfunc);

_sasl_global_context_t *_sasl_gbl_ctx(void);

#ifdef _INTEGRATED_SOLARIS_
int _is_sun_reg(void *mech);
#endif /* _INTEGRATED_SOLARIS_ */

/* unsupported functions that are used internally */
int sasl_randcreate(sasl_rand_t **rpool);

void sasl_randfree(sasl_rand_t **rpool);

void sasl_rand(sasl_rand_t *rpool, char *buf, unsigned len);

void sasl_churn(sasl_rand_t *rpool, const char *data, unsigned len);

int sasl_mkchal(sasl_conn_t *conn, char *buf, unsigned maxlen,
		unsigned hostflag);
#endif	/* _SUN_SDK_ */

#endif /* SASLINT_H */
