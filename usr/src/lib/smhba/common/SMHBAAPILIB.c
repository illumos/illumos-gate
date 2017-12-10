/*
 * ************************************************************************
 * Description
 *	HBAAPILIB.c - Implements a sample common (wrapper) HBA API library
 *
 * License:
 *	The contents of this file are subject to the SNIA Public License
 *	Version 1.0 (the "License"); you may not use this file except in
 *	compliance with the License. You may obtain a copy of the License at
 *
 *	/http://www.snia.org/English/Resources/Code/OpenSource.html
 *
 *	Software distributed under the License is distributed on an "AS IS"
 *	basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 *	the License for the specific language governing rights and limitations
 *	under the License.
 *
 * The Original Code is  SNIA HBA API Wrapper Library
 *
 * The Initial Developer of the Original Code is:
 *	Benjamin F. Kuo, Troika Networks, Inc. (benk@troikanetworks.com)
 *
 * Contributor(s):
 *	Tuan Lam, QLogic Corp. (t_lam@qlc.com)
 *	Dan Willie, Emulex Corp. (Dan.Willie@emulex.com)
 *	Dixon Hutchinson, Legato Systems, Inc. (dhutchin@legato.com)
 *	David Dillard, VERITAS Software Corp. (david.dillard@veritas.com)
 *
 * ************************************************************************
 *
 * Adding on SM-HBA support
 *
 * The implementation includes Three different categories functions to support
 * both HBAAPI and SM-HBA through the same library.
 *
 * SM-HBA unique interface:
 *	1. CHECKLIBRARYANDVERSION(SMHBA) : match SMHBA VSL
 *	   Or checking specifically if version is SMHBA beforehand.
 *	2. resolved to ftable.smhbafunctiontable.{interface}
 * HBAAPIV2 unique functions
 *	1. CHECKLIBRARYANDVERSION(HBAAPIV2) : validate and match HBAAPI V2 VSL.
 *	   Or checking specifically if version is HBAAPIV2 beforehand.
 *	2. resolved to ftable.functiontable.{interface}
 * Common interface between SM-HBA and HBAAPIV2.
 *	1. CHECKLIBRARY() : to validate the VSL.
 *	2. FUNCCOMMON macro to map the appropriate entry point table
 *	    (union ftable).
 *	3. If the interface is not supported by HBAAPI(Version 1)
 *	   the funtiion ptr will be set to NULL.
 * Common interface between HBAAPI and HBAAPIV2.
 *	1. Check if version is not SMHBA).
 *	2. ftable.functiontalbe.(interface)
 *
 * ************************************************************************
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifdef WIN32
#include <windows.h>
#include <string.h>
/*
 * Next define forces entry points in the dll to be exported
 * See hbaapi.h to see what it does.
 */
#define	HBAAPI_EXPORTS
#else
#include <dlfcn.h>
#include <strings.h>
#endif
#include <stdio.h>
#include <time.h>
#include "smhbaapi.h"
#include "vendorsmhbaapi.h"
#include <stdlib.h>
#ifdef USESYSLOG
#include <syslog.h>
#endif
#ifdef SOLARIS
#include <link.h>
#include <limits.h>
static int	*handle;
static Link_map *map, *mp;
#endif

/*
 * LIBRARY_NUM is a shortcut to figure out which library we need to call.
 *  The top 16 bits of handle are the library index
 */
#define	LIBRARY_NUM(handle)	((handle)>>16)

/*
 * VENDOR_HANDLE turns a global library handle into a vendor specific handle,
 * with all upper 16 bits set to 0
 */
#define	VENDOR_HANDLE(handle)	((handle)&0xFFFF)

#define	HBA_HANDLE_FROM_LOCAL(library, vendor) \
				(((library)<<16) | ((vendor)&0x0000FFFF))

int _hbaapi_debuglevel = 0;
#define	DEBUG(L, STR, A1, A2, A3)

#if defined(USESYSLOG) && defined(USELOGFILE)
FILE *_hbaapi_debug_fd = NULL;
int _hbaapi_sysloginit = 0;
#undef DEBUG
#ifdef WIN32
#define	DEBUG(L, STR, A1, A2, A3)\
    if ((L) <= _hbaapi_debuglevel) {\
	if (_hbaapi_sysloginit == 0) {\
	    openlog("HBAAPI", LOG_PID|LOG_ODELAY, LOG_USER);\
	    _hbaapi_sysloginit = 1;\
	}\
	syslog(LOG_INFO, (STR), (A1), (A2), (A3));\
	if (_hbaapi_debug_fd == NULL) {\
	    char _logFile[MAX_PATH]; \
	    GetTempPath(MAX_PATH, _logFile); \
	    strcat(_logFile, "HBAAPI.log"); \
	    _hbaapi_debug_fd = fopen(_logFile, "a");\
	}\
	if (_hbaapi_debug_fd != NULL) {\
	    fprintf(_hbaapi_debug_fd, #STR "\n", (A1), (A2), (A3));\
	}\
	}
#else /* WIN32 */
#define	DEBUG(L, STR, A1, A2, A3)\
	if ((L) <= _hbaapi_debuglevel) {\
	if (_hbaapi_sysloginit == 0) {\
	    openlog("HBAAPI", LOG_PID|LOG_ODELAY, LOG_USER);\
	    _hbaapi_sysloginit = 1;\
	}\
	syslog(LOG_INFO, (STR), (A1), (A2), (A3));\
	if (_hbaapi_debug_fd == NULL) {\
	    _hbaapi_debug_fd = fopen("/tmp/HBAAPI.log", "a");\
	}\
	if (_hbaapi_debug_fd != NULL) {\
	    fprintf(_hbaapi_debug_fd, #STR  "\n", (A1), (A2), (A3));\
	}\
	}
#endif /* WIN32 */

#else /* Not both USESYSLOG and USELOGFILE */
#if defined(USESYSLOG)
int _hbaapi_sysloginit = 0;
#undef DEBUG
#define	DEBUG(L, STR, A1, A2, A3) \
    if ((L) <= _hbaapi_debuglevel) {\
	if (_hbaapi_sysloginit == 0) {\
	    openlog("HBAAPI", LOG_PID|LOG_ODELAY, LOG_USER);\
	    _hbaapi_sysloginit = 1;\
	}\
	syslog(LOG_DEBUG, (STR), (A1), (A2), (A3));\
	}
#endif /* USESYSLOG */
#if defined(USELOGFILE)
FILE *_hbaapi_debug_fd = NULL;
#undef DEBUG
#ifdef WIN32
#define	DEBUG(L, STR, A1, A2, A3) \
    if ((L) <= _hbaapi_debuglevel) {\
	if (_hbaapi_debug_fd == NULL) {\
	    char _logFile[MAX_PATH]; \
	    GetTempPath(MAX_PATH, _logFile); \
	    strcat(_logFile, "HBAAPI.log"); \
	    _hbaapi_debug_fd = fopen(_logFile, "a");\
	}\
	}
#else /* WIN32 */
#define	DEBUG(L, STR, A1, A2, A3) \
    if ((L) <= _hbaapi_debuglevel) {\
	if (_hbaapi_debug_fd == NULL) {\
	    _hbaapi_debug_fd = fopen("/tmp/HBAAPI.log", "a");\
	}\
	if (_hbaapi_debug_fd != NULL) { \
	    fprintf(_hbaapi_debug_fd, #STR "\n", (A1), (A2), (A3));\
	}\
	}
#endif /* WIN32 */
#endif /* USELOGFILE */
#endif /* Not both USELOGFILE and USESYSLOG */

#ifdef POSIX_THREADS
#include <pthread.h>
/*
 * When multiple mutex's are grabed, they must be always be grabbed in
 * the same order, or deadlock can result.  There are three levels
 * of mutex's involved in this API.  If LL_mutex is grabbed, always grap
 * it first.  If AL_mutex is grabbed, it may not be grabbed before
 * LL_mutex.  If grabbed in a multi grab sequence, the mutex's protecting
 * the callback lists must always be grabbed last and release before calling
 * a vendor specific library function that might invoke a callback function
 * on the same thread.
 */
#define	GRAB_MUTEX(M)			grab_mutex(M)
#define	RELEASE_MUTEX(M)		release_mutex(M)
#define	RELEASE_MUTEX_RETURN(M, RET)	release_mutex(M); return (RET)
#elif defined(WIN32)
#define	GRAB_MUTEX(m)			EnterCriticalSection(m)
#define	RELEASE_MUTEX(m)		LeaveCriticalSection(m)
#define	RELEASE_MUTEX_RETURN(m, RET)	LeaveCriticalSection(m); return (RET)
#else
#define	GRAB_MUTEX(M)
#define	RELEASE_MUTEX(M)
#define	RELEASE_MUTEX_RETURN(M, RET)	return (RET)
#endif

/*
 * Vendor library information
 */
typedef enum {
    HBA_LIBRARY_UNKNOWN,
    HBA_LIBRARY_LOADED,
    HBA_LIBRARY_NOT_LOADED
} HBA_LIBRARY_STATUS;

typedef enum {
    UNKNOWN = 1,
    SMHBA,
    HBAAPIV2,
    HBAAPI
} LIBRARY_VERSION;

typedef struct hba_library_info {
    struct hba_library_info
			*next;
#ifdef WIN32
    HINSTANCE		hLibrary;		/* Handle to a loaded DLL */
#else
    char		*LibraryName;
    void*		hLibrary;		/* Handle to a loaded DLL */
#endif
    char		*LibraryPath;
    LIBRARY_VERSION	version;		/* resolve union */
    HBA_UINT32		numOfAdapters;
    union {
	SMHBA_ENTRYPOINTS   smhbafunctionTable;	/* smhba function pointers */
	HBA_ENTRYPOINTSV2   functionTable;	/* hba api function pointers */
	} ftable;
    HBA_LIBRARY_STATUS	status;			/* info on this library */
    HBA_UINT32		index;
} HBA_LIBRARY_INFO, *PHBA_LIBRARY_INFO;

#define	ARE_WE_INITED() \
	if (_hbaapi_librarylist == NULL) { \
		return (HBA_STATUS_ERROR_NOT_LOADED); \
	}
HBA_LIBRARY_INFO *_hbaapi_librarylist = NULL;
HBA_UINT32 _hbaapi_total_library_count = 0;
#ifdef POSIX_THREADS
pthread_mutex_t _hbaapi_LL_mutex = PTHREAD_MUTEX_INITIALIZER;
#elif defined(WIN32)
CRITICAL_SECTION _hbaapi_LL_mutex;
#endif

/*
 * Macro to use the right function table between smhba and hbaapi.
 */
#define	FUNCTABLE(lib_infop) \
	((lib_infop->version == SMHBA) ? \
	lib_infop->ftable.smhbafunctionTable : \
	lib_infop->ftable.functionTable);

/*
 * Macro to use the right function ptr between smhba and hbaapi function table.
 * Should be used for an interface common to SM-HBA and HBAAPIV2.
 */
#define	FUNCCOMMON(lib_infop, func) \
	((lib_infop->version == SMHBA) ? \
	lib_infop->ftable.smhbafunctionTable.func : \
	lib_infop->ftable.functionTable.func)

/*
 * Macro to use the hbaapi function ptr.
 * Should be used for an interface applicable only HBAAPIV2.
 */
#define	FUNCHBAAPIV2(lib_infop, func) \
	lib_infop->ftable.functionTable.func

/*
 * Macro to use the hbaapi function ptr.
 * Should be used for an interface applicable only HBAAPIV2.
 */
#define	FUNCSMHBA(lib_infop, func) \
	lib_infop->ftable.smhbafunctionTable.func

/*
 * Individual adapter (hba) information
 */
typedef struct hba_adapter_info {
    struct hba_adapter_info
			*next;
    HBA_STATUS		GNstatus;	/* status from GetAdapterNameFunc */
    char		*name;
    HBA_WWN		nodeWWN;
    HBA_LIBRARY_INFO	*library;
    HBA_UINT32		index;
} HBA_ADAPTER_INFO;

HBA_ADAPTER_INFO *_hbaapi_adapterlist = NULL;
HBA_UINT32 _hbaapi_total_adapter_count = 0;
#ifdef POSIX_THREADS
pthread_mutex_t _hbaapi_AL_mutex = PTHREAD_MUTEX_INITIALIZER;
#elif defined(WIN32)
CRITICAL_SECTION _hbaapi_AL_mutex;
#endif

/*
 * Call back registration
 */
typedef struct hba_vendorcallback_elem {
    struct hba_vendorcallback_elem
				*next;
    HBA_CALLBACKHANDLE		vendorcbhandle;
    HBA_LIBRARY_INFO		*lib_info;
} HBA_VENDORCALLBACK_ELEM;

/*
 * Each instance of HBA_ADAPTERCALLBACK_ELEM represents a call to one of
 * "register" functions that apply to a particular adapter.
 * HBA_ALLADAPTERSCALLBACK_ELEM is used just for HBA_RegisterForAdapterAddEvents
 */
typedef struct hba_adaptercallback_elem {
    struct hba_adaptercallback_elem
			*next;
    HBA_LIBRARY_INFO	*lib_info;
    void		*userdata;
    HBA_CALLBACKHANDLE	vendorcbhandle;
    void		(*callback)();
} HBA_ADAPTERCALLBACK_ELEM;

typedef struct hba_alladapterscallback_elem {
    struct hba_alladapterscallback_elem
				*next;
    void			*userdata;
    HBA_VENDORCALLBACK_ELEM	*vendorhandlelist;
    void			(*callback)();
} HBA_ALLADAPTERSCALLBACK_ELEM;

HBA_ALLADAPTERSCALLBACK_ELEM *_hbaapi_adapteraddevents_callback_list = NULL;
HBA_ADAPTERCALLBACK_ELEM *_hbaapi_adapterevents_callback_list = NULL;
HBA_ADAPTERCALLBACK_ELEM *_hbaapi_adapterportevents_callback_list = NULL;
HBA_ADAPTERCALLBACK_ELEM *_hbaapi_adapterportstatevents_callback_list = NULL;
HBA_ADAPTERCALLBACK_ELEM *_hbaapi_targetevents_callback_list = NULL;
HBA_ADAPTERCALLBACK_ELEM *_hbaapi_linkevents_callback_list = NULL;

HBA_ALLADAPTERSCALLBACK_ELEM *_smhba_adapteraddevents_callback_list = NULL;
HBA_ADAPTERCALLBACK_ELEM *_smhba_adapterevents_callback_list = NULL;
HBA_ADAPTERCALLBACK_ELEM *_smhba_adapterportevents_callback_list = NULL;
HBA_ADAPTERCALLBACK_ELEM *_smhba_adapterportstatevents_callback_list = NULL;
HBA_ADAPTERCALLBACK_ELEM *_smhba_adapterphystatevents_callback_list = NULL;
HBA_ADAPTERCALLBACK_ELEM *_smhba_targetevents_callback_list = NULL;

#ifdef POSIX_THREADS
/* mutex's to protect each list */
pthread_mutex_t _hbaapi_AAE_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t _hbaapi_AE_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t _hbaapi_APE_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t _hbaapi_APSE_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t _hbaapi_TE_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t _hbaapi_LE_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t _smhba_AAE_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t _smhba_AE_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t _smhba_APE_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t _smhba_APSE_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t _smhba_APHYSE_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t _smhba_TE_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t _smhba_LE_mutex = PTHREAD_MUTEX_INITIALIZER;
#elif defined(WIN32)
CRITICAL_SECTION _hbaapi_AAE_mutex;
CRITICAL_SECTION _hbaapi_AE_mutex;
CRITICAL_SECTION _hbaapi_APE_mutex;
CRITICAL_SECTION _hbaapi_APSE_mutex;
CRITICAL_SECTION _hbaapi_TE_mutex;
CRITICAL_SECTION _smhba_AAE_mutex;
CRITICAL_SECTION _smhba_AE_mutex;
CRITICAL_SECTION _smhba_APE_mutex;
CRITICAL_SECTION _smhba_APSE_mutex;
CRITICAL_SECTION _smhba_APHYSE_mutex;
CRITICAL_SECTION _smhba_TE_mutex;
CRITICAL_SECTION _hbaapi_LE_mutex;
#endif

HBA_ADAPTERCALLBACK_ELEM **cb_lists_array[] = {
	&_hbaapi_adapterevents_callback_list,
	&_hbaapi_adapterportevents_callback_list,
	&_hbaapi_adapterportstatevents_callback_list,
	&_hbaapi_targetevents_callback_list,
	&_hbaapi_linkevents_callback_list,
	&_smhba_adapterevents_callback_list,
	&_smhba_adapterportevents_callback_list,
	&_smhba_adapterportstatevents_callback_list,
	&_smhba_adapterphystatevents_callback_list,
	&_smhba_targetevents_callback_list,
	NULL};

/*
 * Common library internal. Mutex handling
 */
#ifdef POSIX_THREADS
static void
grab_mutex(pthread_mutex_t *mp) {
/* LINTED E_FUNC_SET_NOT_USED */
    int ret;
    if ((ret = pthread_mutex_lock(mp)) != 0) {
	perror("pthread_mutex_lock - HBAAPI:");
	DEBUG(1, "pthread_mutex_lock returned %d", ret, 0, 0);
	}
}

static void
release_mutex(pthread_mutex_t *mp) {
/* LINTED E_FUNC_SET_NOT_USED */
    int ret;
    if ((ret = pthread_mutex_unlock(mp)) != 0) {
	perror("pthread_mutex_unlock - HBAAPI:");
	DEBUG(1, "pthread_mutex_unlock returned %d", ret, 0, 0);
	}
}
#endif

/*
 * Common library internal. Check library and return vendorhandle
 */
static HBA_STATUS
HBA_CheckLibrary(HBA_HANDLE handle,
    HBA_LIBRARY_INFO **lib_infopp,
    HBA_HANDLE *vendorhandle) {

    HBA_UINT32		libraryIndex;
    HBA_LIBRARY_INFO	*lib_infop;

    if (_hbaapi_librarylist == NULL) {
	return (HBA_STATUS_ERROR);
	}
    libraryIndex = LIBRARY_NUM(handle);

    GRAB_MUTEX(&_hbaapi_LL_mutex);
    for (lib_infop = _hbaapi_librarylist;
	lib_infop != NULL;
	lib_infop = lib_infop->next) {
	if (lib_infop->index == libraryIndex) {
	    if (lib_infop->status != HBA_LIBRARY_LOADED) {
		return (HBA_STATUS_ERROR);
	    }
	    *lib_infopp = lib_infop;
	    *vendorhandle = VENDOR_HANDLE(handle);
	    /* caller will release the mutex */
	    return (HBA_STATUS_OK);
	}
	}
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_INVALID_HANDLE);
}
#define	CHECKLIBRARY() \
	status = HBA_CheckLibrary(handle, &lib_infop, &vendorHandle);\
	if (status != HBA_STATUS_OK) { \
	    return (status); \
	}

#define	CHECKLIBRARYANDVERSION(ver) \
	status = HBA_CheckLibrary(handle, &lib_infop, &vendorHandle); \
	if (status != HBA_STATUS_OK) { \
	    return (status); \
	} else { \
	    if (ver != lib_infop->version) { \
		RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, \
		    HBA_STATUS_ERROR_INCOMPATIBLE); \
	    } \
	}

/*
 * freevendorhandlelist is called with _hbaapi_LL_mutex already held
 */
static void
freevendorhandlelist(HBA_VENDORCALLBACK_ELEM *vhlist) {
    HBA_VENDORCALLBACK_ELEM	*vhlp;
    HBA_VENDORCALLBACK_ELEM	*vnext;
    HBARemoveCallbackFunc	registeredfunc;

    for (vhlp = vhlist; vhlp != NULL; vhlp = vnext) {
	vnext = vhlp->next;
	registeredfunc =
	    FUNCCOMMON(vhlp->lib_info, RemoveCallbackHandler);
	if (registeredfunc == NULL) {
	    continue;
	}
	(registeredfunc)(vhlp->vendorcbhandle);
	free(vhlp);
	}
}

static
HBA_STATUS
local_remove_callback(HBA_CALLBACKHANDLE cbhandle) {
    HBA_ADAPTERCALLBACK_ELEM		***listp;
    HBA_ADAPTERCALLBACK_ELEM		**lastp;
    HBA_ALLADAPTERSCALLBACK_ELEM	**lap;
    HBA_ALLADAPTERSCALLBACK_ELEM	*allcbp;
    HBA_ADAPTERCALLBACK_ELEM		*cbp;
    HBARemoveCallbackFunc		registeredfunc;
    HBA_VENDORCALLBACK_ELEM		*vhlp;
    HBA_VENDORCALLBACK_ELEM		*vnext;
    int					found;
    HBA_STATUS			status = HBA_STATUS_ERROR_INVALID_HANDLE;


	/* search through the simple lists first */
    GRAB_MUTEX(&_hbaapi_AAE_mutex);
    GRAB_MUTEX(&_hbaapi_AE_mutex);
    GRAB_MUTEX(&_hbaapi_APE_mutex);
    GRAB_MUTEX(&_hbaapi_APSE_mutex);
    GRAB_MUTEX(&_hbaapi_TE_mutex);
    GRAB_MUTEX(&_hbaapi_LE_mutex);
    GRAB_MUTEX(&_smhba_AAE_mutex);
    GRAB_MUTEX(&_smhba_AE_mutex);
    GRAB_MUTEX(&_smhba_APE_mutex);
    GRAB_MUTEX(&_smhba_APSE_mutex);
    GRAB_MUTEX(&_smhba_TE_mutex);
    for (listp = cb_lists_array, found = 0;
	    (found == 0 && *listp != NULL); listp++) {
	lastp = *listp;
	for (cbp = **listp; cbp != NULL; cbp = cbp->next) {
	    if (cbhandle != (HBA_CALLBACKHANDLE)cbp) {
		lastp = &(cbp->next);
		continue;
	    }
	    found = 1;
	    registeredfunc =
		FUNCCOMMON(cbp->lib_info, RemoveCallbackHandler);
	    if (registeredfunc == NULL) {
		break;
	    }
	    (registeredfunc)(cbp->vendorcbhandle);
	    *lastp = cbp->next;
	    free(cbp);
	    break;
	}
	}
    RELEASE_MUTEX(&_hbaapi_LE_mutex);
    RELEASE_MUTEX(&_hbaapi_TE_mutex);
    RELEASE_MUTEX(&_hbaapi_APSE_mutex);
    RELEASE_MUTEX(&_hbaapi_APE_mutex);
    RELEASE_MUTEX(&_hbaapi_AE_mutex);
    RELEASE_MUTEX(&_hbaapi_AAE_mutex);
    RELEASE_MUTEX(&_smhba_AAE_mutex);
    RELEASE_MUTEX(&_smhba_AE_mutex);
    RELEASE_MUTEX(&_smhba_APE_mutex);
    RELEASE_MUTEX(&_smhba_APSE_mutex);
    RELEASE_MUTEX(&_smhba_TE_mutex);

    if (found != 0) {
	if (registeredfunc == NULL) {
	    return (HBA_STATUS_ERROR_NOT_SUPPORTED);
	}
	return (HBA_STATUS_OK);
	}

    GRAB_MUTEX(&_hbaapi_AAE_mutex);
	/*
	 * if it wasnt in the simple lists,
	 * look in the list for adapteraddevents
	 */
    lap = &_hbaapi_adapteraddevents_callback_list;
    for (allcbp = _hbaapi_adapteraddevents_callback_list;
	    allcbp != NULL;
	    allcbp = allcbp->next) {
	if (cbhandle != (HBA_CALLBACKHANDLE)allcbp) {
	    lap = &allcbp->next;
	    continue;
	}
	for (vhlp = allcbp->vendorhandlelist; vhlp != NULL; vhlp = vnext) {
	    vnext = vhlp->next;
	    /* should be HBAAPIV2 VSL to get to here */
	    registeredfunc =
		    vhlp->lib_info->ftable.functionTable.RemoveCallbackHandler;
	    if (registeredfunc == NULL) {
		continue;
	    }
	    (registeredfunc)(vhlp->vendorcbhandle);
	    free(vhlp);
	}
	*lap = allcbp->next;
	free(allcbp);
	status = HBA_STATUS_OK;
	break;
	}
    RELEASE_MUTEX(&_hbaapi_AAE_mutex);

	/* now search smhba adapteradd events. */
    GRAB_MUTEX(&_smhba_AAE_mutex);
    lap = &_smhba_adapteraddevents_callback_list;
    for (allcbp = _smhba_adapteraddevents_callback_list;
	allcbp != NULL;
	allcbp = allcbp->next) {
	if (cbhandle != (HBA_CALLBACKHANDLE)allcbp) {
	    lap = &allcbp->next;
	    continue;
	}
	for (vhlp = allcbp->vendorhandlelist; vhlp != NULL; vhlp = vnext) {
	    vnext = vhlp->next;
	    /* should be SMHBA VSL to get to here */
	    registeredfunc =
		    vhlp->lib_info->
			ftable.smhbafunctionTable.RemoveCallbackHandler;
	    if (registeredfunc == NULL) {
		continue;
	    }
	    (registeredfunc)(vhlp->vendorcbhandle);
	    free(vhlp);
	}
	*lap = allcbp->next;
	free(allcbp);
	status = HBA_STATUS_OK;
	break;
	}
    RELEASE_MUTEX(&_smhba_AAE_mutex);

    return (status);
}

/* LINTED E_STATIC_UE_STATIC_UNUSED */
static char wwn_str1[17];
/* LINTED E_STATIC_UE_STATIC_UNUSED */
static char wwn_str2[17];
/* LINTED E_STATIC_UE_STATIC_UNUSED */
static char wwn_str3[17];
#define	WWN2STR1(wwn) WWN2str(wwn_str1, (wwn))
#define	WWN2STR2(wwn) WWN2str(wwn_str2, (wwn))
#define	WWN2STR3(wwn) WWN2str(wwn_str3, (wwn))
static char *
/* LINTED E_STATIC_UE_STATIC_UNUSED */
WWN2str(char *buf, HBA_WWN *wwn) {
    int j;
    unsigned char *pc = (unsigned char *)&(wwn->wwn[0]);
    buf[0] = '\0';
    for (j = 0; j < 16; j += 2) {
		(void) sprintf(&buf[j], "%02X", (int)*pc++);
	}
    return (buf);
}

#ifdef WIN32
BOOL APIENTRY
DllMain(HANDLE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved)
{
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return (TRUE);
}
#endif

/*
 * Read in the config file and load all the specified vendor specific
 * libraries and perform the function registration exercise
 */
HBA_STATUS
HBA_LoadLibrary()
{
	HBARegisterLibraryFunc RegisterFunc;
	HBARegisterLibraryV2Func RegisterV2Func;
	SMHBARegisterLibraryFunc RegisterSMHBAFunc;
	HBALoadLibraryFunc	LoadLibraryFunc;
	HBAGetVersionFunc	GetVersionFunc;
#ifdef	POSIX_THREADS
	int			ret;
#endif
	HBA_STATUS		status;
	HBA_UINT32		libversion;

	/* Open configuration file from known location */
#ifdef WIN32
	LONG		lStatus;
	HKEY		hkSniaHba, hkVendorLib;
	FILETIME		ftLastWriteTime;
	TCHAR		cSubKeyName[256];
	DWORD		i, dwSize, dwType;
	BYTE		byFileName[MAX_PATH];
	HBA_LIBRARY_INFO	*lib_infop;

	if (_hbaapi_librarylist != NULL) {
		/* this is an app programming error */
		return (HBA_STATUS_ERROR);
	}

	lStatus = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\SNIA\\HBA",
	    0, KEY_READ, &hkSniaHba);
	if (lStatus != ERROR_SUCCESS) {
		/* ???Opportunity to send error msg, configuration error */
		return (HBA_STATUS_ERROR);
	}
	/*
	 * Enumerate all the subkeys. These have the form:
	 * HKLM\Software\SNIA\HBA\<Vendor id> - note that we don't care
	 * what the vendor id is
	 */
	for (i = 0; ; i++) {
		dwSize = 255;	/* how big the buffer is */
		lStatus = RegEnumKeyEx(hkSniaHba, i,
		    (char *)&cSubKeyName, &dwSize, NULL,
		    NULL, NULL, &ftLastWriteTime);
	if (lStatus == ERROR_NO_MORE_ITEMS) {
		break;	/* we're done */
	} else if (lStatus == ERROR_MORE_DATA) { /* buffer not big enough */
		/* do whatever */
		;
	}
	/* Now open the subkey that pertains to this vendor's library */
	lStatus = RegOpenKeyEx(hkSniaHba, cSubKeyName, 0, KEY_READ,
	    &hkVendorLib);
	if (lStatus != ERROR_SUCCESS) {
		RegCloseKey(hkSniaHba);
	    /* ???Opportunity to send error msg, installation error */
		return (HBA_STATUS_ERROR);
		/*
		 * you may want to return something
		 * else or keep trying
		 */
	}
	/*
	 * The name of the library is contained in a REG_SZ Value
	 * keyed to "LibraryFile"
	 */
	dwSize = MAX_PATH;
	lStatus = RegQueryValueEx(hkVendorLib, "LibraryFile", NULL, &dwType,
	    byFileName, &dwSize);
	if (lStatus != ERROR_SUCCESS) {
		RegCloseKey(hkVendorLib);
	    /* ???Opportunity to send error msg, installation error */
		continue;
	}
	lib_infop = (HBA_LIBRARY_INFO *)calloc(1, sizeof (HBA_LIBRARY_INFO));
	if (lib_infop == NULL) {
	    /* what is the right thing to do in MS land??? */
		RegCloseKey(hkVendorLib);
		/* ???Opportunity to send error msg, installation error */
		return (HBA_STATUS_ERROR);
	}
	lib_infop->status = HBA_LIBRARY_NOT_LOADED;
	lib_infop->next = _hbaapi_librarylist;
	lib_infop->index = _hbaapi_total_library_count;
	_hbaapi_total_library_count++;
	_hbaapi_librarylist = lib_infop;

	/* Now I can try to load the library */
	lib_infop->hLibrary = LoadLibrary(byFileName);
	if (lib_infop->hLibrary == NULL) {
	    /* printf("unable to load library %s\n", librarypath); */
	    /* ???Opportunity to send error msg, installation error */
		goto dud_library;
	}
	lib_infop->LibraryPath = strdup(byFileName);
	DEBUG(1, "HBAAPI loading: %s\n", byFileName, 0, 0);

	RegisterSMHBAFunc = (SMHBARegisterLibraryFunc)
	    GetProcAddress(lib_infop->hLibrary, "SMHBA_RegisterLibrary");
	if (RegisterSMHBAFunc != NULL) {
		status = ((RegisterSMHBAFunc)(SMHBA_ENTRYPOINTS *)
		    (&lib_infop->ftable.smhbafunctionTable));
		if (status != HBA_STATUS_OK) {
			/* library not loaded */
			/* ???Opportunity to send error msg, library error? */
			goto dud_library;
		} else {
			lib_infop->version = SMHBA;
		}
	} else {
	    /* Call the registration function to get the list of pointers */
		RegisterV2Func = (HBARegisterLibraryV2Func)GetProcAddress(
		    lib_infop->hLibrary, "HBA_RegisterLibraryV2");
		if (RegisterV2Func != NULL) {
		/*
		 * Load the function pointers directly into
		 * the table of functions
		 */
		status = ((RegisterV2Func)
		    (HBA_ENTRYPOINTSV2 *)(&lib_infop->ftable.functionTable));
		if (status != HBA_STATUS_OK) {
		    /* library not loaded */
		    /* ???Opportunity to send error msg, library error? */
			goto dud_library;
		} else {
			lib_infop->version = HBAAPIV2;
		}
		} else {
		/* Maybe the vendor library is only Rev1 */
		RegisterFunc = (HBARegisterLibraryFunc)
		    GetProcAddress(lib_infop->hLibrary, "HBA_RegisterLibrary");
		if (RegisterFunc == NULL) {
		    /* ???Opportunity to send error msg, library error? */
			goto dud_library;
		}
		/*
		 * Load the function points directly into
		 * the Rev 2 table of functions
		 */
		status = ((RegisterFunc)(
		    (HBA_ENTRYPOINTS *)(&lib_infop->ftable.functionTable)));
		if (status != HBA_STATUS_OK) {
		    /* library not loaded */
		    /* ???Opportunity to send error msg, library error? */
			goto dud_library;
		} else {
			lib_infop->version = HBAAPI;
		}
		}
	}

	/* successfully loaded library */
	/*
	 * SM-HBA and HBAAPI has a seperate handler for GetVersion but
	 * they have the same function signature so use the same variable here.
	 */
	GetVersionFunc = FUNCCOMMON(lib_infop, GetVersionHandler);
	if (GetVersionFunc != NULL) {
		if (lib_infop->version == SMHBA) {
		/* Check the version of this library before loading */
		libversion = ((GetVersionFunc)());
#ifdef NOTDEF /* save for a later time... when it matters */
		if (libversion < SMHBA_LIBVERSION) {
			goto dud_library;
		}
#endif
		} else {
		/* Check the version of this library before loading */
	    /* Actually... This wrapper is compatible with version 1 */
		libversion = ((GetVersionFunc)());
#ifdef NOTDEF /* save for a later time... when it matters */
		if (libversion < HBA_LIBVERSION) {
			goto dud_library;
		}
#endif
		}
	} else {
	    /* ???Opportunity to send error msg, library error? */
		goto dud_library;
	}

	LoadLibraryFunc = FUNCCOMMON(lib_infop, LoadLibraryHandler);
	if (LoadLibraryFunc == NULL) {
	    /* Hmmm, dont we need to flag this in a realy big way??? */
	    /* How about messages to the system event logger ??? */
	    /* ???Opportunity to send error msg, library error? */
		goto dud_library;
	}
	/* Initialize this library */
	status = ((LoadLibraryFunc)());
	if (status != HBA_STATUS_OK) {
	    /* ???Opportunity to send error msg, library error? */
		continue;
	}
	/* successfully loaded library */
	lib_infop->status = HBA_LIBRARY_LOADED;

	dud_library: /* its also just the end of the loop */
	RegCloseKey(hkVendorLib);
	}
	RegCloseKey(hkSniaHba);

#else /* Unix as opposed to Win32 */
	FILE		*hbaconf;
	char		fullline[512];		/* line read from HBA.conf */
	char		*libraryname;		/* Read in from file HBA.conf */
	char		*librarypath;		/* Read in from file HBA.conf */
	char		hbaConfFilePath[256];
	char		*charPtr;
	HBA_LIBRARY_INFO	*lib_infop;

	GRAB_MUTEX(&_hbaapi_LL_mutex);
	if (_hbaapi_librarylist != NULL) {
		(void) fprintf(stderr,
		    "HBA_LoadLibrary: previously unfreed "
		    "libraries exist, call HBA_FreeLibrary().\n");
		RELEASE_MUTEX(&_hbaapi_LL_mutex);
		return (HBA_STATUS_ERROR);
	}

	(void) strcpy(hbaConfFilePath, "/etc/smhba.conf");

	if ((hbaconf = fopen(hbaConfFilePath, "r")) == NULL) {
		(void) printf("Cannot open %s\n", hbaConfFilePath);
		RELEASE_MUTEX(&_hbaapi_LL_mutex);
		return (HBA_STATUS_ERROR);
	}

	/* Read in each line and load library */
	while ((hbaconf != NULL) &&
	    (fgets(fullline, sizeof (fullline), hbaconf))) {
		/* Skip the comments... */
		if ((fullline[0] == '#') || (fullline[0] == '\n')) {
			continue;
		}

	/* grab first 'thing' in line (if its there) */
	if ((libraryname = strtok(fullline, " \t\n")) != NULL) {
		if (strlen(libraryname) >= 64) {
			(void) fprintf(stderr,
			    "Library name(%s) in %s is > 64 characters\n",
			    libraryname, hbaConfFilePath);
		}
	}
	/* grab second 'thing' in line (if its there) */
	if ((librarypath = strtok(NULL, " \t\n")) != NULL) {
		if (strlen(librarypath) >= 256) {
		(void) fprintf(stderr,
		    "Library path(%s) in %s is > 256 characters\n",
		    librarypath, hbaConfFilePath);
		}
	}

	/* there should be no more 'things' in the line */
	if ((charPtr = strtok(NULL, " \n\t")) != NULL) {
		(void) fprintf(stderr, "Extraneous characters (\"%s\") in %s\n",
		    charPtr, hbaConfFilePath);
	}

	/* Continue to the next line if library name or path is invalid */
	if (libraryname == NULL ||
	    strlen(libraryname) == 0 ||
	    librarypath == NULL ||
	    (strlen(librarypath) == 0)) {
		continue;
	}

	/*
	 * Special case....
	 * Look for loglevel
	 */
	if (strcmp(libraryname, "debuglevel") == 0) {
		_hbaapi_debuglevel = strtol(librarypath, NULL, 10);
	    /* error handling does the right thing automagically */
		continue;
	}

	lib_infop = (HBA_LIBRARY_INFO *)calloc(1, sizeof (HBA_LIBRARY_INFO));
	if (lib_infop == NULL) {
		(void) fprintf(stderr, "HBA_LoadLibrary: out of memeory\n");
		RELEASE_MUTEX(&_hbaapi_LL_mutex);
		return (HBA_STATUS_ERROR);
	}
	lib_infop->status = HBA_LIBRARY_NOT_LOADED;
	lib_infop->LibraryName = strdup(libraryname);
	lib_infop->LibraryPath = strdup(librarypath);
	lib_infop->numOfAdapters = 0;
	lib_infop->version = UNKNOWN;
	lib_infop->index = _hbaapi_total_library_count;
	_hbaapi_total_library_count++;
	lib_infop->next = _hbaapi_librarylist;
	_hbaapi_librarylist = lib_infop;

	/* Load the DLL now */
	if ((lib_infop->hLibrary = dlopen(librarypath, RTLD_LAZY)) == NULL) {
	    /* printf("unable to load library %s\n", librarypath); */
		continue;
	}
	/* Call the registration function to get the list of pointers */
	RegisterSMHBAFunc = (SMHBARegisterLibraryFunc)
	    dlsym(lib_infop->hLibrary, "SMHBA_RegisterLibrary");
	if (RegisterSMHBAFunc != NULL) {
		/*
		 * Load the function points directly into
		 * the table of functions
		 */
		status = ((RegisterSMHBAFunc)
		    (&lib_infop->ftable.smhbafunctionTable));
		if (status != HBA_STATUS_OK) {
			/* library not loaded */
			continue;
		} else {
			lib_infop->version = SMHBA;
		}
	} else {
		RegisterV2Func = (HBARegisterLibraryV2Func)
		    dlsym(lib_infop->hLibrary, "HBA_RegisterLibraryV2");
		if (RegisterV2Func != NULL) {
		/*
		 * Load the function points directly into
		 * the table of functions
		 */
		status = ((RegisterV2Func)((HBA_ENTRYPOINTSV2 *)
		    (&lib_infop->ftable.functionTable)));
		if (status != HBA_STATUS_OK) {
		    /* library not loaded */
			continue;
		} else {
			lib_infop->version = HBAAPIV2;
		}
		} else {
		/* Maybe the vendor library is only Rev1 */
		RegisterFunc = (HBARegisterLibraryFunc)
		    dlsym(lib_infop->hLibrary, "HBA_RegisterLibrary");
		if (RegisterFunc == NULL) {
		    /* This function is required */
			(void) fprintf(stderr,
			    "HBA_LoadLibrary: vendor specific RegisterLibrary "
			    "function not found.  lib: %s\n", librarypath);
			DEBUG(1, "HBA_LoadLibrary: vendor specific "
			    "RegisterLibrary function not found.  lib: %s\n",
			    librarypath, 0, 0);
			continue;
		}
		/*
		 * Load the function points directly into
		 * the table of functions
		 */
		status = ((RegisterFunc)
		    ((HBA_ENTRYPOINTS *)(&lib_infop->ftable.functionTable)));
		if (status != HBA_STATUS_OK) {
		    /* library not loaded */
			(void) fprintf(stderr,
			    "HBA_LoadLibrary: vendor specific RegisterLibrary "
			    "function encountered an error.  lib: %s\n",
			    librarypath);
			DEBUG(1,
			    "HBA_LoadLibrary: vendor specific RegisterLibrary "
			    "function encountered an error. lib: %s\n",
			    librarypath, 0, 0);
			continue;
		} else {
			lib_infop->version = HBAAPI;
		}
		}
	}

	/* successfully loaded library */
	/*
	 * SM-HBA and HBAAPI has a seperate handler for GetVersion but
	 * they have the same function signature so use the same variable here.
	 */
	if ((GetVersionFunc = FUNCCOMMON(lib_infop, GetVersionHandler))
	    == NULL) {
		continue;
	}
	if (lib_infop->version == SMHBA) {
		libversion = ((GetVersionFunc)());
		if (libversion < SMHBA_LIBVERSION) {
			(void) printf("Library version mismatch."
			    "Got %d expected %d.\n",
			    libversion, SMHBA_LIBVERSION);
			continue;
		}
	} else {
		libversion = ((GetVersionFunc)());
	    /* Check the version of this library before loading */
	    /* Actually... This wrapper is compatible with version 1 */
		if (libversion < HBA_LIBVERSION) {
			(void) printf("Library version mismatch."
			    "Got %d expected %d.\n",
			    libversion, HBA_LIBVERSION);
			continue;
		}
	}

	DEBUG(1, "%s libversion = %d", librarypath, libversion, 0);
	LoadLibraryFunc = FUNCCOMMON(lib_infop, LoadLibraryHandler);
	if (LoadLibraryFunc == NULL) {
	    /* this function is required */
		(void) fprintf(stderr,
		    "HBA_LoadLibrary: vendor specific LoadLibrary "
		    "function not found.  lib: %s\n", librarypath);
		DEBUG(1, "HBA_LoadLibrary: vendor specific LoadLibrary "
		    "function not found.  lib: %s\n", librarypath, 0, 0);
		continue;
	}
	/* Initialize this library */
	if ((status = ((LoadLibraryFunc)())) != HBA_STATUS_OK) {
	    /* maybe this should be a printf so that we CANNOT miss it */
		(void) fprintf(stderr,
		    "HBA_LoadLibrary: Encounterd and error loading: %s",
		    librarypath);
		DEBUG(1, "Encounterd and error loading: %s", librarypath, 0, 0);
		DEBUG(1, "  HBA_STATUS: %d", status, 0, 0);
		continue;
	}
	/* successfully loaded library */
	lib_infop->status = HBA_LIBRARY_LOADED;
	}
#endif /* WIN32 or UNIX */
#ifdef POSIX_THREADS
	/*
	 * The _hbaapi_LL_mutex is already grabbed to proctect the caller of
	 * HBA_FreeLibrary() during loading.
	 * The mutexes are already initialized
	 * with PTHREAD_MUTEX_INITIALIZER.  Do we need to init again?
	 * Keeping the code from HBAAPI source...
	 */
	ret = pthread_mutex_init(&_hbaapi_AL_mutex, NULL);
	if (ret == 0) {
		ret = pthread_mutex_init(&_hbaapi_AAE_mutex, NULL);
	}
	if (ret == 0) {
		ret = pthread_mutex_init(&_hbaapi_AE_mutex, NULL);
	}
	if (ret == 0) {
		ret = pthread_mutex_init(&_hbaapi_APE_mutex, NULL);
	}
	if (ret == 0) {
		ret = pthread_mutex_init(&_hbaapi_APSE_mutex, NULL);
	}
	if (ret == 0) {
		ret = pthread_mutex_init(&_hbaapi_TE_mutex, NULL);
	}
	if (ret == 0) {
		ret = pthread_mutex_init(&_smhba_AAE_mutex, NULL);
	}
	if (ret == 0) {
		ret = pthread_mutex_init(&_smhba_AE_mutex, NULL);
	}
	if (ret == 0) {
		ret = pthread_mutex_init(&_smhba_APE_mutex, NULL);
	}
	if (ret == 0) {
		ret = pthread_mutex_init(&_smhba_APSE_mutex, NULL);
	}
	if (ret == 0) {
		ret = pthread_mutex_init(&_smhba_TE_mutex, NULL);
	}
	if (ret == 0) {
		ret = pthread_mutex_init(&_hbaapi_LE_mutex, NULL);
	}
	if (ret != 0) {
		perror("pthread_mutex_init - HBA_LoadLibrary");
		RELEASE_MUTEX(&_hbaapi_LL_mutex);
		return (HBA_STATUS_ERROR);
	}
	RELEASE_MUTEX(&_hbaapi_LL_mutex);
#elif defined(WIN32)
	InitializeCriticalSection(&_hbaapi_LL_mutex);
	InitializeCriticalSection(&_hbaapi_AL_mutex);
	InitializeCriticalSection(&_hbaapi_AAE_mutex);
	InitializeCriticalSection(&_hbaapi_AE_mutex);
	InitializeCriticalSection(&_hbaapi_APE_mutex);
	InitializeCriticalSection(&_hbaapi_APSE_mutex);
	InitializeCriticalSection(&_hbaapi_TE_mutex);
	InitializeCriticalSection(&_hbaapi_LE_mutex);
	InitializeCriticalSection(&_smhba_AAE_mutex);
	InitializeCriticalSection(&_smhba_AE_mutex);
	InitializeCriticalSection(&_smhba_APE_mutex);
	InitializeCriticalSection(&_smhba_APSE_mutex);
	InitializeCriticalSection(&_smhba_TE_mutex);
#endif

	return (HBA_STATUS_OK);
}

HBA_STATUS
HBA_FreeLibrary() {
    HBAFreeLibraryFunc	FreeLibraryFunc;
/* LINTED E_FUNC_SET_NOT_USED */
    HBA_STATUS		status __unused;
    HBA_LIBRARY_INFO	*lib_infop;
    HBA_LIBRARY_INFO	*lib_next;
    HBA_ADAPTERCALLBACK_ELEM
			***listp;
    HBA_ADAPTER_INFO	*adapt_infop;
    HBA_ADAPTER_INFO	*adapt_next;

    GRAB_MUTEX(&_hbaapi_LL_mutex);
    if (_hbaapi_librarylist == NULL) {
	RELEASE_MUTEX(&_hbaapi_LL_mutex);
	return (HBA_STATUS_ERROR_NOT_LOADED);
	}

    GRAB_MUTEX(&_hbaapi_AL_mutex);

    DEBUG(1, "HBA_FreeLibrary()", 0, 0, 0);
    for (lib_infop = _hbaapi_librarylist; lib_infop != NULL;
	    lib_infop = lib_next) {
	lib_next = lib_infop->next;
	if (lib_infop->status == HBA_LIBRARY_LOADED) {
	    FreeLibraryFunc = FUNCCOMMON(lib_infop, FreeLibraryHandler);
	    if (FreeLibraryFunc != NULL) {
		/* Free this library */
		status = ((FreeLibraryFunc)());
		DEBUG(1, "HBA_FreeLibrary() Failed %d", status, 0, 0);
	    }
#ifdef WIN32
	    FreeLibrary(lib_infop->hLibrary);	/* Unload DLL from memory */
#else
	    (void) dlclose(lib_infop->hLibrary); /* Unload DLL from memory */
#endif
	}
#ifndef WIN32
	free(lib_infop->LibraryName);
#endif
	free(lib_infop->LibraryPath);
	free(lib_infop);

	}
    _hbaapi_librarylist = NULL;
	/*
	 * OK, now all functions are disabled except for LoadLibrary,
	 * Hope no other thread calls it before we have returned
	 */
    _hbaapi_total_library_count = 0;

    for (adapt_infop = _hbaapi_adapterlist;
	    adapt_infop != NULL;
	    adapt_infop = adapt_next) {
		adapt_next = adapt_infop->next;
		free(adapt_infop->name);
		free(adapt_infop);
	}
    _hbaapi_adapterlist = NULL;
    _hbaapi_total_adapter_count = 0;

	/*
	 * Free up the callbacks, this is not the most efficient, but it works
	 */
	while ((volatile HBA_ADAPTERCALLBACK_ELEM *)
	    _hbaapi_adapteraddevents_callback_list
	    != NULL) {
	(void) local_remove_callback((HBA_CALLBACKHANDLE)
	    _hbaapi_adapteraddevents_callback_list);
	}
	while ((volatile HBA_ADAPTERCALLBACK_ELEM *)
	    _smhba_adapteraddevents_callback_list
	    != NULL) {
	(void) local_remove_callback((HBA_CALLBACKHANDLE)
	    _smhba_adapteraddevents_callback_list);
	}
    for (listp = cb_lists_array; *listp != NULL; listp++) {
	while ((volatile HBA_ADAPTERCALLBACK_ELEM ***)**listp != NULL) {
	    (void) local_remove_callback((HBA_CALLBACKHANDLE)**listp);
	}
	}

    RELEASE_MUTEX(&_hbaapi_AL_mutex);
    RELEASE_MUTEX(&_hbaapi_LL_mutex);

#ifdef USESYSLOG
    closelog();
#endif
#ifdef USELOGFILE
    if (_hbaapi_debug_fd != NULL) {
	fclose(_hbaapi_debug_fd);
	}
    _hbaapi_debug_fd = NULL;
#endif
#ifdef POSIX_THREADS
	/* this will unlock them as well, but who cares */
	(void) pthread_mutex_destroy(&_hbaapi_LE_mutex);
	(void) pthread_mutex_destroy(&_hbaapi_TE_mutex);
	(void) pthread_mutex_destroy(&_hbaapi_APSE_mutex);
	(void) pthread_mutex_destroy(&_hbaapi_APE_mutex);
	(void) pthread_mutex_destroy(&_hbaapi_AE_mutex);
	(void) pthread_mutex_destroy(&_hbaapi_AAE_mutex);
	(void) pthread_mutex_destroy(&_smhba_TE_mutex);
	(void) pthread_mutex_destroy(&_smhba_APSE_mutex);
	(void) pthread_mutex_destroy(&_smhba_APE_mutex);
	(void) pthread_mutex_destroy(&_smhba_AE_mutex);
	(void) pthread_mutex_destroy(&_smhba_AAE_mutex);
	(void) pthread_mutex_destroy(&_hbaapi_AL_mutex);
	(void) pthread_mutex_destroy(&_hbaapi_LL_mutex);
#elif defined(WIN32)
    DeleteCriticalSection(&_hbaapi_LL_mutex);
    DeleteCriticalSection(&_hbaapi_AL_mutex);
    DeleteCriticalSection(&_hbaapi_AAE_mutex);
    DeleteCriticalSection(&_hbaapi_AE_mutex);
    DeleteCriticalSection(&_hbaapi_APE_mutex);
    DeleteCriticalSection(&_hbaapi_APSE_mutex);
    DeleteCriticalSection(&_hbaapi_TE_mutex);
    DeleteCriticalSection(&_hbaapi_LE_mutex);
    DeleteCriticalSection(&_smhba_TE_mutex);
    DeleteCriticalSection(&_smhba_APSE_mutex);
    DeleteCriticalSection(&_smhba_APE_mutex);
    DeleteCriticalSection(&_smhba_AE_mutex);
    DeleteCriticalSection(&_smhba_AAE_mutex);
#endif

	return (HBA_STATUS_OK);
}

/*
 * The API used to use fixed size tables as its primary data structure.
 * Indexing from 1 to N identified each adapters.  Now the adapters are
 * on a linked list.  There is a unique "index" foreach each adapter.
 * Adapters always keep their index, even if they are removed from the
 * hardware.  The only time the indexing is reset is on HBA_FreeLibrary
 */
HBA_UINT32
HBA_GetNumberOfAdapters()
{
	int j = 0;
	HBA_LIBRARY_INFO	*lib_infop;
	HBAGetNumberOfAdaptersFunc GetNumberOfAdaptersFunc;
	HBAGetAdapterNameFunc GetAdapterNameFunc;
	HBA_BOOLEAN		found_name;
	HBA_ADAPTER_INFO	*adapt_infop;
	HBA_STATUS		status;

	char adaptername[256];
	int num_adapters; /* local */

	if (_hbaapi_librarylist == NULL) {
		return (0);
	}
	GRAB_MUTEX(&_hbaapi_LL_mutex); /* pay attention to order */
	GRAB_MUTEX(&_hbaapi_AL_mutex);

	for (lib_infop = _hbaapi_librarylist;
	    lib_infop != NULL;
	    lib_infop = lib_infop->next) {

	if (lib_infop->status != HBA_LIBRARY_LOADED) {
		continue;
	}

	GetNumberOfAdaptersFunc =
	    FUNCCOMMON(lib_infop, GetNumberOfAdaptersHandler);
	if (GetNumberOfAdaptersFunc == NULL)  {
		continue;
	}
	num_adapters = ((GetNumberOfAdaptersFunc)());
#ifndef WIN32
	DEBUG(1, "HBAAPI: num_adapters for %s = %d\n",
	    lib_infop->LibraryName, num_adapters, 0);
#else
	DEBUG(1, "HBAAPI: num_adapters for %s = %d\n",
	    lib_infop->LibraryPath, num_adapters, 0);
#endif

	/* Also get the names of all the adapters here and cache */
	GetAdapterNameFunc = FUNCCOMMON(lib_infop, GetAdapterNameHandler);
	if (GetAdapterNameFunc == NULL) {
		continue;
	}

	for (j = 0; j < num_adapters; j++) {
		found_name = 0;
		status = (GetAdapterNameFunc)(j, (char *)&adaptername);
		if (status == HBA_STATUS_OK) {
		for (adapt_infop = _hbaapi_adapterlist;
		    adapt_infop != NULL;
		    adapt_infop = adapt_infop->next) {
			/*
			 * check for duplicates, really,
			 * this may just be a second
			 * call to this function
			 * ??? how do we know when a name becomes stale?
			 */
			if (strcmp(adaptername, adapt_infop->name) == 0) {
				/* already got this one */
				found_name++;
			break;
			}
		}
		if (found_name != 0) {
			continue;
		}
		}

		adapt_infop = (HBA_ADAPTER_INFO *)
		    calloc(1, sizeof (HBA_ADAPTER_INFO));
		if (adapt_infop == NULL) {
#ifndef WIN32
		(void) fprintf(stderr,
		    "HBA_GetNumberOfAdapters: calloc failed"
		    " on sizeof:%lu\n",
		    (unsigned long)(sizeof (HBA_ADAPTER_INFO)));
#endif
		RELEASE_MUTEX(&_hbaapi_AL_mutex);
		RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex,
		    _hbaapi_total_adapter_count);
		}
		if ((adapt_infop->GNstatus = status) == HBA_STATUS_OK) {
		adapt_infop->name = strdup(adaptername);
		} else {
		char dummyname[512];
		(void) sprintf(dummyname, "NULLADAPTER-%255s-%03d",
		    lib_infop->LibraryPath, _hbaapi_total_adapter_count);
		dummyname[511] = '\0';
		adapt_infop->name = strdup(dummyname);
		}
		lib_infop->numOfAdapters++;
		adapt_infop->library = lib_infop;
		adapt_infop->next = _hbaapi_adapterlist;
		adapt_infop->index = _hbaapi_total_adapter_count;
		_hbaapi_adapterlist = adapt_infop;
		_hbaapi_total_adapter_count++;
	}
	}
	RELEASE_MUTEX(&_hbaapi_AL_mutex);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, _hbaapi_total_adapter_count);
}

HBA_STATUS
HBA_GetAdapterName(
    HBA_UINT32 adapterindex,
    char *adaptername)
{
	HBA_ADAPTER_INFO	*adapt_infop;
	HBA_STATUS		ret = HBA_STATUS_ERROR_ILLEGAL_INDEX;

	if (adaptername == NULL) {
		DEBUG(1, "HBA_GetAdapterName: NULL pointer adaptername",
		    0, 0, 0);
		return (HBA_STATUS_ERROR_ARG);
	}

	/*
	 * The adapter index is from old code, but we have
	 * to support it.  Go down the list looking for
	 * the adapter
	 */
	ARE_WE_INITED();
	GRAB_MUTEX(&_hbaapi_AL_mutex);
	*adaptername = '\0';
	for (adapt_infop = _hbaapi_adapterlist;
	    adapt_infop != NULL;
	    adapt_infop = adapt_infop->next) {

	if (adapt_infop->index == adapterindex) {
		if (adapt_infop->name != NULL &&
		    adapt_infop->GNstatus == HBA_STATUS_OK) {
		(void) strcpy(adaptername, adapt_infop->name);
		} else {
		*adaptername = '\0';
		}
		ret = adapt_infop->GNstatus;
		break;
	}
	}
	DEBUG(2, "GetAdapterName for index:%d ->%s",
	    adapterindex, adaptername, 0);
	RELEASE_MUTEX_RETURN(&_hbaapi_AL_mutex, ret);
}

HBA_HANDLE
HBA_OpenAdapter(char *adaptername)
{
	HBA_HANDLE		handle;
	HBAOpenAdapterFunc	OpenAdapterFunc;
	HBA_ADAPTER_INFO	*adapt_infop;
	HBA_LIBRARY_INFO	*lib_infop;

	DEBUG(2, "OpenAdapter: %s", adaptername, 0, 0);

	handle = HBA_HANDLE_INVALID;
	if (_hbaapi_librarylist == NULL) {
		return (handle);
	}
	if (adaptername == NULL) {
		DEBUG(1, "HBA_OpenAdapter: NULL pointer adaptername",
		    0, 0, 0);
		return (handle);
	}
	GRAB_MUTEX(&_hbaapi_AL_mutex);
	for (adapt_infop = _hbaapi_adapterlist;
	    adapt_infop != NULL;
	    adapt_infop = adapt_infop->next) {
	if (strcmp(adaptername, adapt_infop->name) != 0) {
		continue;
	}
	lib_infop = adapt_infop->library;
	OpenAdapterFunc = FUNCCOMMON(lib_infop, OpenAdapterHandler);

	if (OpenAdapterFunc != NULL) {
	    /* retrieve the vendor handle */
		handle = (OpenAdapterFunc)(adaptername);
		if (handle != 0) {
		/* or this with the library index to get the common handle */
		handle = HBA_HANDLE_FROM_LOCAL(lib_infop->index, handle);
		}
	}
	break;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_AL_mutex, handle);
}

/*
 * Finding an adapter with matching WWN.
 */
HBA_STATUS
HBA_OpenAdapterByWWN(HBA_HANDLE *phandle, HBA_WWN nodeWWN) {
    HBA_HANDLE		handle;
    HBA_LIBRARY_INFO	*lib_infop;
    HBAGetNumberOfAdaptersFunc
			GetNumberOfAdaptersFunc;
    HBAOpenAdapterByWWNFunc
			OpenAdapterFunc;
    HBA_STATUS		status;

    DEBUG(2, "OpenAdapterByWWN: %s", WWN2STR1(&nodeWWN), 0, 0);
    ARE_WE_INITED();

	*phandle = HBA_HANDLE_INVALID;

    GRAB_MUTEX(&_hbaapi_LL_mutex);
    for (lib_infop = _hbaapi_librarylist;
	    lib_infop != NULL;
	    lib_infop = lib_infop->next) {

	status = HBA_STATUS_ERROR_ILLEGAL_WWN;

	if (lib_infop->status != HBA_LIBRARY_LOADED) {
	    continue;
	}

	/* only for HBAAPIV2 */
	if (lib_infop->version != HBAAPIV2) {
	    continue;
	}

	GetNumberOfAdaptersFunc =
		FUNCCOMMON(lib_infop, GetNumberOfAdaptersHandler);
	if (GetNumberOfAdaptersFunc == NULL)  {
	    continue;
	}

	/* look for new hardware */
	(void) ((GetNumberOfAdaptersFunc)());

	OpenAdapterFunc =
	    lib_infop->ftable.functionTable.OpenAdapterByWWNHandler;
	if (OpenAdapterFunc == NULL) {
	    continue;
	}
	/*
	 * We do not know if the WWN is known by this vendor,
	 * just try it
	 */
	if ((status = (OpenAdapterFunc)(&handle, nodeWWN)) != HBA_STATUS_OK) {
	    continue;
	}
	/* OK, make a vendor non-specific handle */
	*phandle = HBA_HANDLE_FROM_LOCAL(lib_infop->index, handle);
	status = HBA_STATUS_OK;
	break;
	}
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

void
HBA_RefreshAdapterConfiguration() {
    DEBUG(2, "HBA_RefreshAdapterConfiguration", 0, 0, 0);
	(void) HBA_GetNumberOfAdapters();
}

HBA_UINT32
HBA_GetVersion() {
    DEBUG(2, "HBA_GetVersion", 0, 0, 0);
	return (HBA_LIBVERSION);
}

/*
 * This function is VERY OS dependent.  Wing it as best you can.
 */
HBA_UINT32
HBA_GetWrapperLibraryAttributes(
    HBA_LIBRARYATTRIBUTES *attributes)
{

	DEBUG(2, "HBA_GetWrapperLibraryAttributes", 0, 0, 0);

	if (attributes == NULL) {
		DEBUG(1, "HBA_GetWrapperLibraryAttributes:"
		    "NULL pointer attributes",
		    0, 0, 0);
		return (HBA_STATUS_ERROR_ARG);
	}

	(void) memset(attributes, 0, sizeof (HBA_LIBRARYATTRIBUTES));

#if defined(SOLARIS)
	if ((handle = dlopen("libHBAAPI.so", RTLD_NOW)) != NULL) {
	if (dlinfo(handle, RTLD_DI_LINKMAP, &map) >= 0) {
		for (mp = map; mp != NULL; mp = mp->l_next) {
		if (strlen(map->l_name) < 256) {
			(void) strcpy(attributes->LibPath, map->l_name);
		}
		}
	}
	}
#elif defined(WIN32)
	HMODULE module;

	/* No need to do anything with the module handle */
	/* It wasn't alloocated so it doesn't need to be freed */
	module = GetModuleHandle("HBAAPI");
	if (module != NULL) {
		if (GetModuleFileName(module, attributes->LibPath,
		    sizeof (attributes->LibPath)) == 0) {
			attributes->LibPath[0] = '\0';
		}
	}
#endif
#if defined(VENDOR)
	(void) strcpy(attributes->VName, VENDOR);
#else
	attributes->VName[0] = '\0';
#endif
#if defined(VERSION)
	(void) strcpy(attributes->VVersion, VERSION);
#else
	attributes->VVersion[0] = '\0';
#endif
#if defined(BUILD_DATE)
#if defined(WIN32)
	int matchCount;
	matchCount = sscanf(BUILD_DATE, "%u/%u/%u %u:%u:%u",
	    &attributes->build_date.tm_year,
	    &attributes->build_date.tm_mon,
	    &attributes->build_date.tm_mday,
	    &attributes->build_date.tm_hour,
	    &attributes->build_date.tm_min,
	    &attributes->build_date.tm_sec);

	if (matchCount != 6) {
		memset(&attributes->build_date, 0, sizeof (struct tm));
	} else {
		attributes->build_date.tm_year -= 1900;
		attributes->build_date.tm_isdst = -1;
	}
#else
	if (strptime(BUILD_DATE,
	    "%Y/%m/%d %T %Z", &(attributes->build_date)) == NULL) {
		(void) memset(&attributes->build_date, 0, sizeof (struct tm));
	}
#endif
#else
	(void) memset(&attributes->build_date, 0, sizeof (struct tm));
#endif
	return (2);
}

/*
 * Callback registation and handling
 */
HBA_STATUS
HBA_RemoveCallback(HBA_CALLBACKHANDLE cbhandle) {
    HBA_STATUS	status;

    DEBUG(2, "HBA_RemoveCallback", 0, 0, 0);
    ARE_WE_INITED();

    GRAB_MUTEX(&_hbaapi_LL_mutex);
    status = local_remove_callback(cbhandle);
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

/* Adapter Add Events ************************************************* */
static void
/* LINTED E_FUNC_ARG_UNUSED */
adapteraddevents_callback(void *data, HBA_WWN PortWWN, HBA_UINT32 eventType) {
    HBA_ALLADAPTERSCALLBACK_ELEM	*cbp;

    DEBUG(3, "AddAdapterEvent, port: %s", WWN2STR1(&PortWWN), 0, 0);

    GRAB_MUTEX(&_hbaapi_AAE_mutex);
    for (cbp = _hbaapi_adapteraddevents_callback_list;
	    cbp != NULL;
	    cbp = cbp->next) {
	(*cbp->callback)(data, PortWWN, HBA_EVENT_ADAPTER_ADD);
	}
    RELEASE_MUTEX(&_hbaapi_AAE_mutex);

}

HBA_STATUS
HBA_RegisterForAdapterAddEvents(
    void		(*callback)(
	void		*data,
	HBA_WWN		PortWWN,
	HBA_UINT32	eventType),
	void		*userData,
    HBA_CALLBACKHANDLE *callbackHandle) {

    HBA_ALLADAPTERSCALLBACK_ELEM	*cbp;
    HBA_VENDORCALLBACK_ELEM		*vcbp;
    HBA_VENDORCALLBACK_ELEM		*vendorhandlelist;
    HBARegisterForAdapterAddEventsFunc	registeredfunc;
    HBA_STATUS				status = HBA_STATUS_OK;
    HBA_STATUS				failure = HBA_STATUS_OK;
    HBA_LIBRARY_INFO			*lib_infop;
    int					registered_cnt = 0;
    int					vendor_cnt = 0;
    int					not_supported_cnt = 0;
    int					status_OK_bar_cnt = 0;
    int					status_OK_cnt = 0;

    DEBUG(2, "HBA_RegisterForAdapterAddEvents", 0, 0, 0);
    ARE_WE_INITED();

    cbp = (HBA_ALLADAPTERSCALLBACK_ELEM *)
	calloc(1, sizeof (HBA_ALLADAPTERSCALLBACK_ELEM));
	*callbackHandle = (HBA_CALLBACKHANDLE) cbp;
	if (cbp == NULL) {
#ifndef WIN32
	(void) fprintf(stderr,
		"HBA_RegisterForAdapterAddEvents: calloc failed "
		"for %lu bytes\n",
		(unsigned long)(sizeof (HBA_ALLADAPTERSCALLBACK_ELEM)));
#endif
	return (HBA_STATUS_ERROR);
	}

    GRAB_MUTEX(&_hbaapi_LL_mutex);
    GRAB_MUTEX(&_hbaapi_AAE_mutex);
    cbp->callback = callback;
    cbp->next = _hbaapi_adapteraddevents_callback_list;
    _hbaapi_adapteraddevents_callback_list = cbp;
	/*
	 * Need to release the mutex now incase the vendor function invokes the
	 * callback.  We will grap the mutex later to attach the vendor handle
	 * list to the callback structure
	 */
    RELEASE_MUTEX(&_hbaapi_AAE_mutex);

	/*
	 * now create a list of vendors (vendor libraryies, NOT ADAPTERS)
	 * that have successfully registerred
	 */
	vendorhandlelist = NULL;
    for (lib_infop = _hbaapi_librarylist;
	    lib_infop != NULL;
	    lib_infop = lib_infop->next) {

	/* only for HBAAPI V2 */
	if ((lib_infop->version != HBAAPIV2)) {
	    continue;
	} else {
	    vendor_cnt++;
	}

	registeredfunc =
	    lib_infop->ftable.functionTable.RegisterForAdapterAddEventsHandler;
	if (registeredfunc == NULL) {
	    continue;
	}

	vcbp = (HBA_VENDORCALLBACK_ELEM *)
	    calloc(1, sizeof (HBA_VENDORCALLBACK_ELEM));
	if (vcbp == NULL) {
#ifndef WIN32
	    (void) fprintf(stderr,
		    "HBA_RegisterForAdapterAddEvents: "
		    "calloc failed for %lu bytes\n",
		    (unsigned long)(sizeof (HBA_VENDORCALLBACK_ELEM)));
#endif
	    freevendorhandlelist(vendorhandlelist);
	    status = HBA_STATUS_ERROR;
	    break;
	}

	registered_cnt++;
	status = (registeredfunc)(adapteraddevents_callback,
	    userData, &vcbp->vendorcbhandle);
	if (status == HBA_STATUS_ERROR_NOT_SUPPORTED) {
	    not_supported_cnt++;
	    free(vcbp);
	    continue;
	} else if (status != HBA_STATUS_OK) {
	    status_OK_bar_cnt++;
	    DEBUG(1,
		    "HBA_RegisterForAdapterAddEvents: Library->%s, Error->%d",
		    lib_infop->LibraryPath, status, 0);
#ifndef WIN32
	    (void) fprintf(stderr,
		    "HBA_RegisterForAdapterAddEvents: Library->%s, Error->%d",
		    lib_infop->LibraryPath, status);
#endif
	    failure = status;
	    free(vcbp);
	    continue;
	} else {
	    status_OK_cnt++;
	}
	vcbp->lib_info = lib_infop;
	vcbp->next = vendorhandlelist;
	vendorhandlelist = vcbp;
	}
    if (vendor_cnt == 0) {
	/* no HBAAPIV2 is deteced.  should be okay? */
	status = HBA_STATUS_ERROR;
	} else if (registered_cnt == 0) {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	freevendorhandlelist(vendorhandlelist);
	(void) local_remove_callback((HBA_CALLBACKHANDLE) cbp);
	} else if (status_OK_cnt == 0 && not_supported_cnt != 0) {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	} else if (status_OK_cnt == 0) {
	/*
	 * At least one vendor library registered this function, but no
	 * vendor call succeeded
	 */
	(void) local_remove_callback((HBA_CALLBACKHANDLE) cbp);
	status = failure;
	} else {
	/* we have had atleast some success, now finish up */
	GRAB_MUTEX(&_hbaapi_AAE_mutex);
	/*
	 * this seems silly, but what if another thread called
	 * the callback remove
	 */
	for (cbp = _hbaapi_adapteraddevents_callback_list;
	    cbp != NULL; cbp = cbp->next) {
	    if ((HBA_CALLBACKHANDLE)cbp == *callbackHandle) {
		/* yup, its still there, hooray */
		cbp->vendorhandlelist = vendorhandlelist;
		vendorhandlelist = NULL;
		break;
	    }
	}
	RELEASE_MUTEX(&_hbaapi_AAE_mutex);
	if (vendorhandlelist != NULL) {
		/*
		 * bummer, somebody removed the callback before we finished
		 * registration, probably will never happen
		 */
	    freevendorhandlelist(vendorhandlelist);
	    DEBUG(1,
		    "HBA_RegisterForAdapterAddEvents: HBA_RemoveCallback was "
		    "called for a handle before registration was finished.",
		    0, 0, 0);
	    status = HBA_STATUS_ERROR;
	} else {
	    status = HBA_STATUS_OK;
	}
	}
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

/* Adapter Events (other than add) ************************************** */
static void
adapterevents_callback(void *data,
			HBA_WWN PortWWN,
			HBA_UINT32 eventType) {
    HBA_ADAPTERCALLBACK_ELEM	*acbp;

    DEBUG(3, "AdapterEvent, port:%s, eventType:%d", WWN2STR1(&PortWWN),
	    eventType, 0);

	GRAB_MUTEX(&_hbaapi_AE_mutex);
	for (acbp = _hbaapi_adapterevents_callback_list;
	acbp != NULL;
	acbp = acbp->next) {
	if (data == (void *)acbp) {
	    (*acbp->callback)(acbp->userdata, PortWWN, eventType);
	    break;
	}
	}
    RELEASE_MUTEX(&_hbaapi_AE_mutex);
}
HBA_STATUS
HBA_RegisterForAdapterEvents(
    void		(*callback) (
	void		*data,
	HBA_WWN		PortWWN,
	HBA_UINT32	eventType),
    void		*userData,
    HBA_HANDLE		handle,
    HBA_CALLBACKHANDLE	*callbackHandle) {

    HBA_ADAPTERCALLBACK_ELEM		*acbp;
    HBARegisterForAdapterEventsFunc	registeredfunc;
    HBA_STATUS				status;
    HBA_LIBRARY_INFO			*lib_infop;
    HBA_HANDLE				vendorHandle;

    DEBUG(2, "HBA_RegisterForAdapterEvents", 0, 0, 0);

    CHECKLIBRARYANDVERSION(HBAAPIV2);

	/* we now have the _hbaapi_LL_mutex */

    registeredfunc =
	    lib_infop->ftable.functionTable.RegisterForAdapterEventsHandler;
    if (registeredfunc == NULL) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_NOT_SUPPORTED);
	}

	/*
	 * that allocated memory is used both as the handle for the
	 * caller, and as userdata to the vendor call so that on
	 * callback the specific registration may be recalled
	 */
    acbp = (HBA_ADAPTERCALLBACK_ELEM *)
	calloc(1, sizeof (HBA_ADAPTERCALLBACK_ELEM));
    if (acbp == NULL) {
#ifndef WIN32
	(void) fprintf(stderr,
		"HBA_RegisterForAdapterEvents: calloc failed for %lu bytes\n",
		(unsigned long)(sizeof (HBA_ADAPTERCALLBACK_ELEM)));
#endif
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR);
	}
	*callbackHandle = (HBA_CALLBACKHANDLE) acbp;
    acbp->callback = callback;
    acbp->userdata = userData;
    acbp->lib_info = lib_infop;

    status = (registeredfunc)(adapterevents_callback,
	    (void *)acbp,
	    vendorHandle,
	    &acbp->vendorcbhandle);
    if (status != HBA_STATUS_OK) {
	free(acbp);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
	}

    GRAB_MUTEX(&_hbaapi_AE_mutex);
    acbp->next = _hbaapi_adapterevents_callback_list;
    _hbaapi_adapterevents_callback_list = acbp;
    RELEASE_MUTEX(&_hbaapi_AE_mutex);

    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_OK);
}

/* Adapter Port Events ************************************************** */
static void
adapterportevents_callback(void *data,
			    HBA_WWN PortWWN,
			    HBA_UINT32 eventType,
			    HBA_UINT32 fabricPortID) {
    HBA_ADAPTERCALLBACK_ELEM	*acbp;

    DEBUG(3, "AdapterPortEvent, port:%s, eventType:%d fabricPortID:0X%06x",
	    WWN2STR1(&PortWWN), eventType, fabricPortID);

    GRAB_MUTEX(&_hbaapi_APE_mutex);

    for (acbp = _hbaapi_adapterportevents_callback_list;
	acbp != NULL;
	acbp = acbp->next) {
	if (data == (void *)acbp) {
	    (*acbp->callback)(acbp->userdata, PortWWN, eventType, fabricPortID);
	    break;
	}
	}
    RELEASE_MUTEX(&_hbaapi_APE_mutex);
}

HBA_STATUS
HBA_RegisterForAdapterPortEvents(
    void		(*callback) (
	void		*data,
	HBA_WWN		PortWWN,
	HBA_UINT32	eventType,
	HBA_UINT32	fabricPortID),
    void		*userData,
    HBA_HANDLE		handle,
    HBA_WWN		PortWWN,
    HBA_CALLBACKHANDLE	*callbackHandle) {

    HBA_ADAPTERCALLBACK_ELEM		*acbp;
    HBARegisterForAdapterPortEventsFunc	registeredfunc;
    HBA_STATUS				status;
    HBA_LIBRARY_INFO			*lib_infop;
    HBA_HANDLE				vendorHandle;

    DEBUG(2, "HBA_RegisterForAdapterPortEvents for port: %s",
	    WWN2STR1(&PortWWN), 0, 0);

    CHECKLIBRARYANDVERSION(HBAAPIV2);
	/* we now have the _hbaapi_LL_mutex */

	registeredfunc =
	lib_infop->ftable.functionTable.RegisterForAdapterPortEventsHandler;
    if (registeredfunc == NULL) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_NOT_SUPPORTED);
	}

	/*
	 * that allocated memory is used both as the handle for the
	 * caller, and as userdata to the vendor call so that on
	 * callback the specific registration may be recalled
	 */
	acbp = (HBA_ADAPTERCALLBACK_ELEM *)
	calloc(1, sizeof (HBA_ADAPTERCALLBACK_ELEM));
    if (acbp == NULL) {
#ifndef WIN32
	(void) fprintf(stderr,
		"HBA_RegisterForAdapterPortEvents: "
		"calloc failed for %lu bytes\n",
		(unsigned long)(sizeof (HBA_ADAPTERCALLBACK_ELEM)));
#endif
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR);

	}
	*callbackHandle = (HBA_CALLBACKHANDLE) acbp;
    acbp->callback = callback;
    acbp->userdata = userData;
    acbp->lib_info = lib_infop;

    status = (registeredfunc)(adapterportevents_callback,
	    (void *)acbp,
	    vendorHandle,
	    PortWWN,
	    &acbp->vendorcbhandle);
    if (status != HBA_STATUS_OK) {
	free(acbp);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
	}

    GRAB_MUTEX(&_hbaapi_APE_mutex);
    acbp->next = _hbaapi_adapterportevents_callback_list;
    _hbaapi_adapterportevents_callback_list = acbp;
    RELEASE_MUTEX(&_hbaapi_APE_mutex);

    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_OK);
}

/* Adapter State Events ************************************************ */
static void
adapterportstatevents_callback(void *data,
				HBA_WWN PortWWN,
				HBA_UINT32 eventType) {
    HBA_ADAPTERCALLBACK_ELEM	*acbp;

	DEBUG(3, "AdapterPortStatEvent, port:%s, eventType:%d",
	    WWN2STR1(&PortWWN),
	    eventType, 0);

    GRAB_MUTEX(&_hbaapi_APSE_mutex);
    for (acbp = _hbaapi_adapterportstatevents_callback_list;
	acbp != NULL;
	acbp = acbp->next) {
	if (data == (void *)acbp) {
	    (*acbp->callback)(acbp->userdata, PortWWN, eventType);
	    return;
	}
	}
    RELEASE_MUTEX(&_hbaapi_APSE_mutex);
}
HBA_STATUS
HBA_RegisterForAdapterPortStatEvents(
    void		(*callback) (
	void		*data,
	HBA_WWN		PortWWN,
	HBA_UINT32	eventType),
    void		*userData,
    HBA_HANDLE		handle,
    HBA_WWN		PortWWN,
    HBA_PORTSTATISTICS	stats,
    HBA_UINT32		statType,
    HBA_CALLBACKHANDLE	*callbackHandle) {

    HBA_ADAPTERCALLBACK_ELEM	*acbp;
    HBARegisterForAdapterPortStatEventsFunc
				registeredfunc;
    HBA_STATUS			status;
    HBA_LIBRARY_INFO		*lib_infop;
    HBA_HANDLE			vendorHandle;

    DEBUG(2, "HBA_RegisterForAdapterPortStatEvents for port: %s",
	    WWN2STR1(&PortWWN), 0, 0);

    CHECKLIBRARYANDVERSION(HBAAPIV2);
	/* we now have the _hbaapi_LL_mutex */

    registeredfunc =
	lib_infop->ftable.functionTable.RegisterForAdapterPortStatEventsHandler;
    if (registeredfunc == NULL) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_NOT_SUPPORTED);
	}

	/*
	 * that allocated memory is used both as the handle for the
	 * caller, and as userdata to the vendor call so that on
	 * callback the specific registration may be recalled
	 */
    acbp = (HBA_ADAPTERCALLBACK_ELEM *)
	calloc(1, sizeof (HBA_ADAPTERCALLBACK_ELEM));
    if (acbp == NULL) {
#ifndef WIN32
	(void) fprintf(stderr,
		"HBA_RegisterForAdapterPortStatEvents: "
		"calloc failed for %lu bytes\n",
		(unsigned long)(sizeof (HBA_ADAPTERCALLBACK_ELEM)));
#endif
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR);
	}
	*callbackHandle = (HBA_CALLBACKHANDLE) acbp;
    acbp->callback = callback;
    acbp->userdata = userData;
    acbp->lib_info = lib_infop;

    status = (registeredfunc)(adapterportstatevents_callback,
	    (void *)acbp,
	    vendorHandle,
	    PortWWN,
	    stats,
	    statType,
	    &acbp->vendorcbhandle);
    if (status != HBA_STATUS_OK) {
	free(acbp);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
	}

    GRAB_MUTEX(&_hbaapi_APSE_mutex);
    acbp->next = _hbaapi_adapterportstatevents_callback_list;
    _hbaapi_adapterportstatevents_callback_list = acbp;
    RELEASE_MUTEX(&_hbaapi_APSE_mutex);

    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_OK);
}

/* Target Events ******************************************************* */
static void
targetevents_callback(void *data,
    HBA_WWN hbaPortWWN,
    HBA_WWN discoveredPortWWN,
    HBA_UINT32 eventType) {

	HBA_ADAPTERCALLBACK_ELEM	*acbp;

    DEBUG(3, "TargetEvent, hbaPort:%s, discoveredPort:%s eventType:%d",
	    WWN2STR1(&hbaPortWWN), WWN2STR2(&discoveredPortWWN), eventType);

    GRAB_MUTEX(&_hbaapi_TE_mutex);
    for (acbp = _hbaapi_targetevents_callback_list;
	acbp != NULL;
	acbp = acbp->next) {
	if (data == (void *)acbp) {
	    (*acbp->callback)(acbp->userdata, hbaPortWWN,
	    discoveredPortWWN, eventType);
	    break;
	}
	}
    RELEASE_MUTEX(&_hbaapi_TE_mutex);
}

HBA_STATUS
HBA_RegisterForTargetEvents(
    void		(*callback) (
	void		*data,
	HBA_WWN		hbaPortWWN,
	HBA_WWN		discoveredPortWWN,
	HBA_UINT32	eventType),
    void		*userData,
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		discoveredPortWWN,
    HBA_CALLBACKHANDLE	*callbackHandle,
    HBA_UINT32		allTargets) {

    HBA_ADAPTERCALLBACK_ELEM
			*acbp;
    HBARegisterForTargetEventsFunc
			registeredfunc;
    HBA_STATUS		status;
    HBA_LIBRARY_INFO	*lib_infop;
    HBA_HANDLE		vendorHandle;

    DEBUG(2, "HBA_RegisterForTargetEvents, hbaPort: %s, discoveredPort: %s",
	    WWN2STR1(&hbaPortWWN), WWN2STR2(&discoveredPortWWN), 0);

    CHECKLIBRARYANDVERSION(HBAAPIV2);
	/* we now have the _hbaapi_LL_mutex */

    registeredfunc =
	    lib_infop->ftable.functionTable.RegisterForTargetEventsHandler;
    if (registeredfunc == NULL) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_NOT_SUPPORTED);
	}

	/*
	 * that allocated memory is used both as the handle for the
	 * caller, and as userdata to the vendor call so that on
	 * callback the specific registration may be recalled
	 */
	acbp = (HBA_ADAPTERCALLBACK_ELEM *)
	calloc(1, sizeof (HBA_ADAPTERCALLBACK_ELEM));
    if (acbp == NULL) {
#ifndef WIN32
	(void) fprintf(stderr,
		"HBA_RegisterForTargetEvents: calloc failed for %lu bytes\n",
		(unsigned long)(sizeof (HBA_ADAPTERCALLBACK_ELEM)));
#endif
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR);
	}
	*callbackHandle = (HBA_CALLBACKHANDLE) acbp;
    acbp->callback = callback;
    acbp->userdata = userData;
    acbp->lib_info = lib_infop;

    status = (registeredfunc)(targetevents_callback,
	    (void *)acbp,
	    vendorHandle,
	    hbaPortWWN,
	    discoveredPortWWN,
	    &acbp->vendorcbhandle,
	    allTargets);
    if (status != HBA_STATUS_OK) {
	free(acbp);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
	}

    GRAB_MUTEX(&_hbaapi_TE_mutex);
    acbp->next = _hbaapi_targetevents_callback_list;
    _hbaapi_targetevents_callback_list = acbp;
    RELEASE_MUTEX(&_hbaapi_TE_mutex);

    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_OK);
}

/* Link Events ********************************************************* */
static void
linkevents_callback(void *data,
    HBA_WWN adapterWWN,
    HBA_UINT32 eventType,
    void *pRLIRBuffer,
    HBA_UINT32 RLIRBufferSize) {
	HBA_ADAPTERCALLBACK_ELEM	*acbp;

    DEBUG(3, "LinkEvent, hbaWWN:%s, eventType:%d",
	    WWN2STR1(&adapterWWN), eventType, 0);

    GRAB_MUTEX(&_hbaapi_LE_mutex);
    for (acbp = _hbaapi_linkevents_callback_list;
	acbp != NULL;
	acbp = acbp->next) {
	if (data == (void *)acbp) {
	    (*acbp->callback)(acbp->userdata, adapterWWN,
		eventType, pRLIRBuffer, RLIRBufferSize);
	    break;
	}
	}
    RELEASE_MUTEX(&_hbaapi_LE_mutex);
}
HBA_STATUS
HBA_RegisterForLinkEvents(
    void		(*callback) (
	void		*data,
	HBA_WWN		adapterWWN,
	HBA_UINT32	eventType,
	void		*pRLIRBuffer,
	HBA_UINT32	RLIRBufferSize),
    void		*userData,
    void		*pRLIRBuffer,
    HBA_UINT32		RLIRBufferSize,
    HBA_HANDLE		handle,
    HBA_CALLBACKHANDLE	*callbackHandle) {

    HBA_ADAPTERCALLBACK_ELEM	*acbp;
    HBARegisterForLinkEventsFunc
				registeredfunc;
    HBA_STATUS			status;
    HBA_LIBRARY_INFO		*lib_infop;
    HBA_HANDLE			vendorHandle;

    DEBUG(2, "HBA_RegisterForLinkEvents", 0, 0, 0);

    CHECKLIBRARY();
	/* we now have the _hbaapi_LL_mutex */

    registeredfunc = FUNCCOMMON(lib_infop, RegisterForLinkEventsHandler);

    if (registeredfunc == NULL) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_NOT_SUPPORTED);
	}

	/*
	 * that allocated memory is used both as the handle for the
	 * caller, and as userdata to the vendor call so that on
	 * callback the specific registration may be recalled
	 */
    acbp = (HBA_ADAPTERCALLBACK_ELEM *)
	calloc(1, sizeof (HBA_ADAPTERCALLBACK_ELEM));
    if (acbp == NULL) {
#ifndef WIN32
	(void) fprintf(stderr,
		"HBA_RegisterForLinkEvents: calloc failed for %lu bytes\n",
		(unsigned long)(sizeof (HBA_ADAPTERCALLBACK_ELEM)));
#endif
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR);
	}
	*callbackHandle = (HBA_CALLBACKHANDLE) acbp;
    acbp->callback = callback;
    acbp->userdata = userData;
    acbp->lib_info = lib_infop;

    status = (registeredfunc)(linkevents_callback,
	    (void *)acbp,
	    pRLIRBuffer,
	    RLIRBufferSize,
	    vendorHandle,
	    &acbp->vendorcbhandle);
    if (status != HBA_STATUS_OK) {
	free(acbp);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
	}

    GRAB_MUTEX(&_hbaapi_LE_mutex);
    acbp->next = _hbaapi_linkevents_callback_list;
    _hbaapi_linkevents_callback_list = acbp;
    RELEASE_MUTEX(&_hbaapi_LE_mutex);

    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_OK);
}

/*
 * All of the functions below are almost passthru functions to the
 * vendor specific function
 */

void
HBA_CloseAdapter(HBA_HANDLE handle) {
    HBA_STATUS		status;
    HBA_LIBRARY_INFO	*lib_infop;
    HBA_HANDLE		vendorHandle;
    HBACloseAdapterFunc CloseAdapterFunc;

    DEBUG(2, "HBA_CloseAdapter", 0, 0, 0);

    status = HBA_CheckLibrary(handle, &lib_infop, &vendorHandle);
    if (status == HBA_STATUS_OK) {
	CloseAdapterFunc = FUNCCOMMON(lib_infop, CloseAdapterHandler);
	if (CloseAdapterFunc != NULL) {
	    ((CloseAdapterFunc)(vendorHandle));
	}
	RELEASE_MUTEX(&_hbaapi_LL_mutex);
	}
}

HBA_STATUS
HBA_GetAdapterAttributes(
    HBA_HANDLE		handle,
    HBA_ADAPTERATTRIBUTES
			*hbaattributes)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBAGetAdapterAttributesFunc GetAdapterAttributesFunc;

	DEBUG(2, "HBA_GetAdapterAttributes", 0, 0, 0);

	CHECKLIBRARY();

	if (lib_infop->version == SMHBA) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_INCOMPATIBLE);
	}

	GetAdapterAttributesFunc =
	    lib_infop->ftable.functionTable.GetAdapterAttributesHandler;
	if (GetAdapterAttributesFunc != NULL) {
	status = ((GetAdapterAttributesFunc)(vendorHandle, hbaattributes));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetAdapterPortAttributes(
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_PORTATTRIBUTES	*portattributes)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBAGetAdapterPortAttributesFunc
	    GetAdapterPortAttributesFunc;

	DEBUG(2, "HBA_GetAdapterPortAttributes", 0, 0, 0);

	CHECKLIBRARY();
	if (lib_infop->version == SMHBA) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_INCOMPATIBLE);
	}

	GetAdapterPortAttributesFunc =
	    lib_infop->ftable.functionTable.GetAdapterPortAttributesHandler;
	if (GetAdapterPortAttributesFunc != NULL) {
	status = ((GetAdapterPortAttributesFunc)
	    (vendorHandle, portindex, portattributes));
	} else {
		status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetPortStatistics(
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_PORTSTATISTICS	*portstatistics)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBAGetPortStatisticsFunc
	    GetPortStatisticsFunc;

	DEBUG(2, "HBA_GetPortStatistics", 0, 0, 0);

	CHECKLIBRARY();
	if (lib_infop->version == SMHBA) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_INCOMPATIBLE);
	}

	GetPortStatisticsFunc =
	    lib_infop->ftable.functionTable.GetPortStatisticsHandler;
	if (GetPortStatisticsFunc != NULL) {
	status = ((GetPortStatisticsFunc)
	    (vendorHandle, portindex, portstatistics));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetDiscoveredPortAttributes(
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_UINT32		discoveredportindex,
    HBA_PORTATTRIBUTES	*portattributes)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBAGetDiscoveredPortAttributesFunc
	    GetDiscoveredPortAttributesFunc;

	DEBUG(2, "HBA_GetDiscoveredPortAttributes", 0, 0, 0);

	CHECKLIBRARY();
	if (lib_infop->version == SMHBA) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_INCOMPATIBLE);
	}

	GetDiscoveredPortAttributesFunc =
	    lib_infop->ftable.functionTable.GetDiscoveredPortAttributesHandler;
	if (GetDiscoveredPortAttributesFunc != NULL)  {
	status = ((GetDiscoveredPortAttributesFunc)
	    (vendorHandle, portindex, discoveredportindex,
	    portattributes));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetPortAttributesByWWN(
    HBA_HANDLE		handle,
    HBA_WWN		PortWWN,
    HBA_PORTATTRIBUTES	*portattributes)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBAGetPortAttributesByWWNFunc
	    GetPortAttributesByWWNFunc;

	DEBUG(2, "HBA_GetPortAttributesByWWN: %s", WWN2STR1(&PortWWN), 0, 0);

	CHECKLIBRARY();
	if (lib_infop->version == SMHBA) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_INCOMPATIBLE);
	}

	GetPortAttributesByWWNFunc =
	    lib_infop->ftable.functionTable.GetPortAttributesByWWNHandler;
	if (GetPortAttributesByWWNFunc != NULL) {
	status = ((GetPortAttributesByWWNFunc)
	    (vendorHandle, PortWWN, portattributes));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SendCTPassThru(
    HBA_HANDLE		handle,
    void		*pReqBuffer,
    HBA_UINT32		ReqBufferSize,
    void		*pRspBuffer,
    HBA_UINT32		RspBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBASendCTPassThruFunc
	    SendCTPassThruFunc;

	DEBUG(2, "HBA_SendCTPassThru", 0, 0, 0);

	CHECKLIBRARY();
	if (lib_infop->version == SMHBA) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_INCOMPATIBLE);
	}

	SendCTPassThruFunc =
	    lib_infop->ftable.functionTable.SendCTPassThruHandler;
	if (SendCTPassThruFunc != NULL) {
	status = (SendCTPassThruFunc)
	    (vendorHandle,
	    pReqBuffer, ReqBufferSize,
	    pRspBuffer, RspBufferSize);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SendCTPassThruV2(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    void		*pReqBuffer,
    HBA_UINT32		ReqBufferSize,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBASendCTPassThruV2Func
	    registeredfunc;

	DEBUG(2, "HBA_SendCTPassThruV2m hbaPortWWN: %s",
	    WWN2STR1(&hbaPortWWN), 0, 0);

	CHECKLIBRARYANDVERSION(HBAAPIV2);
	registeredfunc = FUNCCOMMON(lib_infop, SendCTPassThruV2Handler);
	if (registeredfunc != NULL) {
	status = (registeredfunc)
	    (vendorHandle, hbaPortWWN,
	    pReqBuffer, ReqBufferSize,
	    pRspBuffer, pRspBufferSize);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetEventBuffer(
    HBA_HANDLE		handle,
    PHBA_EVENTINFO	EventBuffer,
    HBA_UINT32		*EventBufferCount)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBAGetEventBufferFunc
	    GetEventBufferFunc;

	DEBUG(2, "HBA_GetEventBuffer", 0, 0, 0);

	CHECKLIBRARY();
	if (lib_infop->version == SMHBA) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_INCOMPATIBLE);
	}

	GetEventBufferFunc =
	    lib_infop->ftable.functionTable.GetEventBufferHandler;
	if (GetEventBufferFunc != NULL) {
	status = (GetEventBufferFunc)
	    (vendorHandle, EventBuffer, EventBufferCount);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SetRNIDMgmtInfo(HBA_HANDLE handle, HBA_MGMTINFO Info) {
    HBA_STATUS		status;
    HBA_LIBRARY_INFO	*lib_infop;
    HBA_HANDLE		vendorHandle;
    HBASetRNIDMgmtInfoFunc
			SetRNIDMgmtInfoFunc;

    DEBUG(2, "HBA_SetRNIDMgmtInfo", 0, 0, 0);

    CHECKLIBRARY();
    SetRNIDMgmtInfoFunc = FUNCCOMMON(lib_infop, SetRNIDMgmtInfoHandler);
    if (SetRNIDMgmtInfoFunc != NULL) {
	status = (SetRNIDMgmtInfoFunc)(vendorHandle, Info);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetRNIDMgmtInfo(HBA_HANDLE handle, HBA_MGMTINFO *pInfo) {
    HBA_STATUS		status;
    HBA_LIBRARY_INFO	*lib_infop;
    HBA_HANDLE		vendorHandle;
    HBAGetRNIDMgmtInfoFunc
	    GetRNIDMgmtInfoFunc;

    DEBUG(2, "HBA_GetRNIDMgmtInfo", 0, 0, 0);

    CHECKLIBRARY();
    GetRNIDMgmtInfoFunc = FUNCCOMMON(lib_infop, GetRNIDMgmtInfoHandler);
    if (GetRNIDMgmtInfoFunc != NULL) {
	status = (GetRNIDMgmtInfoFunc)(vendorHandle, pInfo);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SendRNID(
    HBA_HANDLE		handle,
    HBA_WWN		wwn,
    HBA_WWNTYPE		wwntype,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBASendRNIDFunc	SendRNIDFunc;

	DEBUG(2, "HBA_SendRNID for wwn: %s", WWN2STR1(&wwn), 0, 0);

	CHECKLIBRARY();
	if (lib_infop->version == SMHBA) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_INCOMPATIBLE);
	}

	SendRNIDFunc = lib_infop->ftable.functionTable.SendRNIDHandler;
	if (SendRNIDFunc != NULL) {
	status = ((SendRNIDFunc)(vendorHandle, wwn, wwntype,
	    pRspBuffer, pRspBufferSize));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SendRNIDV2(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		destWWN,
    HBA_UINT32		destFCID,
    HBA_UINT32		NodeIdDataFormat,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBASendRNIDV2Func	registeredfunc;

	DEBUG(2, "HBA_SendRNIDV2, hbaPortWWN: %s", WWN2STR1(&hbaPortWWN), 0, 0);

	CHECKLIBRARY();
	registeredfunc = FUNCCOMMON(lib_infop, SendRNIDV2Handler);
	if (registeredfunc != NULL) {
	status = (registeredfunc)
	    (vendorHandle, hbaPortWWN, destWWN, destFCID, NodeIdDataFormat,
	    pRspBuffer, pRspBufferSize);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

void
HBA_RefreshInformation(HBA_HANDLE handle) {
    HBA_STATUS		status;
    HBA_LIBRARY_INFO	*lib_infop;
    HBA_HANDLE		vendorHandle;
    HBARefreshInformationFunc
	    RefreshInformationFunc;

	DEBUG(2, "HBA_RefreshInformation", 0, 0, 0);

	status = HBA_CheckLibrary(handle, &lib_infop, &vendorHandle);
	if (status == HBA_STATUS_OK) {
	RefreshInformationFunc =
	    FUNCCOMMON(lib_infop, RefreshInformationHandler);
	if (RefreshInformationFunc != NULL) {
	    ((RefreshInformationFunc)(vendorHandle));
	}
	RELEASE_MUTEX(&_hbaapi_LL_mutex);
	}
}

void
HBA_ResetStatistics(HBA_HANDLE handle, HBA_UINT32 portindex) {
    HBA_STATUS		status;
    HBA_LIBRARY_INFO	*lib_infop;
    HBA_HANDLE		vendorHandle;
    HBAResetStatisticsFunc
			ResetStatisticsFunc;

    DEBUG(2, "HBA_ResetStatistics", 0, 0, 0);

    status = HBA_CheckLibrary(handle, &lib_infop, &vendorHandle);
    if (status == HBA_STATUS_OK) {
	if (lib_infop->version == SMHBA) {
		RELEASE_MUTEX(&_hbaapi_LL_mutex);
	}

	ResetStatisticsFunc =
	    lib_infop->ftable.functionTable.ResetStatisticsHandler;
	if (ResetStatisticsFunc != NULL) {
	    ((ResetStatisticsFunc)(vendorHandle, portindex));
	}
	RELEASE_MUTEX(&_hbaapi_LL_mutex);
	}
}

HBA_STATUS
HBA_GetFcpTargetMapping(HBA_HANDLE handle, PHBA_FCPTARGETMAPPING mapping) {
    HBA_STATUS		status;
    HBA_LIBRARY_INFO	*lib_infop;
    HBA_HANDLE		vendorHandle;
    HBAGetFcpTargetMappingFunc GetFcpTargetMappingFunc;

    DEBUG(2, "HBA_GetFcpTargetMapping", 0, 0, 0);

    CHECKLIBRARY();
    if (lib_infop->version == SMHBA) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_INCOMPATIBLE);
	}

    GetFcpTargetMappingFunc =
	lib_infop->ftable.functionTable.GetFcpTargetMappingHandler;
    if (GetFcpTargetMappingFunc != NULL) {
	status = ((GetFcpTargetMappingFunc)(vendorHandle, mapping));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetFcpTargetMappingV2(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_FCPTARGETMAPPINGV2 *pmapping)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBAGetFcpTargetMappingV2Func
	    registeredfunc;

	DEBUG(2, "HBA_GetFcpTargetMapping", 0, 0, 0);

	CHECKLIBRARYANDVERSION(HBAAPIV2);

	registeredfunc =
	    lib_infop->ftable.functionTable.GetFcpTargetMappingV2Handler;
	if (registeredfunc != NULL) {
	status = ((registeredfunc)(vendorHandle, hbaPortWWN, pmapping));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetFcpPersistentBinding(HBA_HANDLE handle, PHBA_FCPBINDING binding) {
    HBA_STATUS		status;
    HBA_LIBRARY_INFO	*lib_infop;
    HBA_HANDLE		vendorHandle;
    HBAGetFcpPersistentBindingFunc
	    GetFcpPersistentBindingFunc;

	DEBUG(2, "HBA_GetFcpPersistentBinding", 0, 0, 0);

	CHECKLIBRARY();
	if (lib_infop->version == SMHBA) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_INCOMPATIBLE);
	}

	GetFcpPersistentBindingFunc =
	    lib_infop->ftable.functionTable.GetFcpPersistentBindingHandler;
	if (GetFcpPersistentBindingFunc != NULL) {
	status = ((GetFcpPersistentBindingFunc)(vendorHandle, binding));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_ScsiInquiryV2(
    HBA_HANDLE	handle,
    HBA_WWN	hbaPortWWN,
    HBA_WWN	discoveredPortWWN,
    HBA_UINT64	fcLUN,
    HBA_UINT8	CDB_Byte1,
    HBA_UINT8	CDB_Byte2,
    void	*pRspBuffer,
    HBA_UINT32	*pRspBufferSize,
    HBA_UINT8	*pScsiStatus,
    void	*pSenseBuffer,
    HBA_UINT32	*pSenseBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBAScsiInquiryV2Func ScsiInquiryV2Func;

	DEBUG(2, "HBA_ScsiInquiryV2 to discoveredPortWWN: %s",
	    WWN2STR1(&discoveredPortWWN), 0, 0);

	CHECKLIBRARYANDVERSION(HBAAPIV2);

	ScsiInquiryV2Func =
	    lib_infop->ftable.functionTable.ScsiInquiryV2Handler;
	if (ScsiInquiryV2Func != NULL) {
	status = ((ScsiInquiryV2Func)(
	    vendorHandle, hbaPortWWN, discoveredPortWWN, fcLUN, CDB_Byte1,
	    CDB_Byte2, pRspBuffer, pRspBufferSize, pScsiStatus,
	    pSenseBuffer, pSenseBufferSize));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SendScsiInquiry(
    HBA_HANDLE	handle,
    HBA_WWN	PortWWN,
    HBA_UINT64	fcLUN,
    HBA_UINT8	EVPD,
    HBA_UINT32	PageCode,
    void	*pRspBuffer,
    HBA_UINT32	RspBufferSize,
    void	*pSenseBuffer,
    HBA_UINT32	SenseBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBASendScsiInquiryFunc SendScsiInquiryFunc;

	DEBUG(2, "HBA_SendScsiInquiry to PortWWN: %s",
	    WWN2STR1(&PortWWN), 0, 0);

	CHECKLIBRARY();
	if (lib_infop->version == SMHBA) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_INCOMPATIBLE);
	}

	SendScsiInquiryFunc =
	    lib_infop->ftable.functionTable.ScsiInquiryHandler;
	if (SendScsiInquiryFunc != NULL) {
	status = ((SendScsiInquiryFunc)(
	    vendorHandle, PortWWN, fcLUN, EVPD, PageCode, pRspBuffer,
	    RspBufferSize, pSenseBuffer, SenseBufferSize));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_ScsiReportLUNsV2(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		discoveredPortWWN,
    void		*pRespBuffer,
    HBA_UINT32		*pRespBufferSize,
    HBA_UINT8		*pScsiStatus,
    void		*pSenseBuffer,
    HBA_UINT32		*pSenseBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBAScsiReportLUNsV2Func ScsiReportLUNsV2Func;

	DEBUG(2, "HBA_ScsiReportLUNsV2 to discoveredPortWWN: %s",
	    WWN2STR1(&discoveredPortWWN), 0, 0);

	CHECKLIBRARYANDVERSION(HBAAPIV2);

	ScsiReportLUNsV2Func =
	    lib_infop->ftable.functionTable.ScsiReportLUNsV2Handler;
	if (ScsiReportLUNsV2Func != NULL) {
	status = ((ScsiReportLUNsV2Func)(
	    vendorHandle, hbaPortWWN, discoveredPortWWN,
	    pRespBuffer, pRespBufferSize,
	    pScsiStatus,
	    pSenseBuffer, pSenseBufferSize));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SendReportLUNs(
    HBA_HANDLE handle,
    HBA_WWN portWWN,
    void *pRspBuffer,
    HBA_UINT32 RspBufferSize,
    void *pSenseBuffer,
    HBA_UINT32 SenseBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBASendReportLUNsFunc SendReportLUNsFunc;

	DEBUG(2, "HBA_SendReportLUNs to PortWWN: %s", WWN2STR1(&portWWN), 0, 0);

	CHECKLIBRARY();
	if (lib_infop->version == SMHBA) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_INCOMPATIBLE);
	}

	SendReportLUNsFunc = lib_infop->ftable.functionTable.ReportLUNsHandler;
	if (SendReportLUNsFunc != NULL) {
	status = ((SendReportLUNsFunc)(
	    vendorHandle, portWWN, pRspBuffer,
	    RspBufferSize, pSenseBuffer, SenseBufferSize));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_ScsiReadCapacityV2(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		discoveredPortWWN,
    HBA_UINT64		fcLUN,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize,
    HBA_UINT8		*pScsiStatus,
    void		*pSenseBuffer,
    HBA_UINT32		*SenseBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBAScsiReadCapacityV2Func ScsiReadCapacityV2Func;

	DEBUG(2, "HBA_ScsiReadCapacityV2 to discoveredPortWWN: %s",
	    WWN2STR1(&discoveredPortWWN), 0, 0);

	CHECKLIBRARYANDVERSION(HBAAPIV2);

	ScsiReadCapacityV2Func =
	    lib_infop->ftable.functionTable.ScsiReadCapacityV2Handler;
	if (ScsiReadCapacityV2Func != NULL) {
	status = ((ScsiReadCapacityV2Func)(
	    vendorHandle, hbaPortWWN, discoveredPortWWN, fcLUN,
	    pRspBuffer, pRspBufferSize,
	    pScsiStatus,
	    pSenseBuffer, SenseBufferSize));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SendReadCapacity(
    HBA_HANDLE handle,
    HBA_WWN portWWN,
    HBA_UINT64 fcLUN,
    void *pRspBuffer,
    HBA_UINT32 RspBufferSize,
    void *pSenseBuffer,
    HBA_UINT32 SenseBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBASendReadCapacityFunc SendReadCapacityFunc;

	DEBUG(2, "HBA_SendReadCapacity to portWWN: %s",
	    WWN2STR1(&portWWN), 0, 0);

	CHECKLIBRARY();
	if (lib_infop->version == SMHBA) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_INCOMPATIBLE);
	}

	SendReadCapacityFunc =
	    lib_infop->ftable.functionTable.ReadCapacityHandler;
	if (SendReadCapacityFunc != NULL) {
	status = ((SendReadCapacityFunc)
	    (vendorHandle, portWWN, fcLUN, pRspBuffer,
	    RspBufferSize, pSenseBuffer, SenseBufferSize));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SendRPL(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		agent_wwn,
    HBA_UINT32		agent_domain,
    HBA_UINT32		portindex,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBASendRPLFunc registeredfunc;

	DEBUG(2, "HBA_SendRPL to agent_wwn: %s:%d",
	    WWN2STR1(&agent_wwn), agent_domain, 0);

	CHECKLIBRARY();
	registeredfunc = FUNCCOMMON(lib_infop, SendRPLHandler);
	if (registeredfunc != NULL) {
	status = (registeredfunc)(
	    vendorHandle, hbaPortWWN, agent_wwn, agent_domain, portindex,
	    pRspBuffer, pRspBufferSize);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SendRPS(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		agent_wwn,
    HBA_UINT32		agent_domain,
    HBA_WWN		object_wwn,
    HBA_UINT32		object_port_number,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBASendRPSFunc registeredfunc;

	DEBUG(2, "HBA_SendRPS  to agent_wwn: %s:%d",
	    WWN2STR1(&agent_wwn), agent_domain, 0);

	CHECKLIBRARY();
	registeredfunc = FUNCCOMMON(lib_infop, SendRPSHandler);
	if (registeredfunc != NULL) {
	status = (registeredfunc)(
	    vendorHandle, hbaPortWWN, agent_wwn, agent_domain,
	    object_wwn, object_port_number,
	    pRspBuffer, pRspBufferSize);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SendSRL(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		wwn,
    HBA_UINT32		domain,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBASendSRLFunc registeredfunc;

	DEBUG(2, "HBA_SendSRL to wwn:%s domain:%d", WWN2STR1(&wwn), domain, 0);

	CHECKLIBRARY();
	registeredfunc = FUNCCOMMON(lib_infop, SendSRLHandler);
	if (registeredfunc != NULL) {
	status = (registeredfunc)(
	    vendorHandle, hbaPortWWN, wwn, domain,
	    pRspBuffer, pRspBufferSize);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}
HBA_STATUS
HBA_SendRLS(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		destWWN,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBASendRLSFunc registeredfunc;

	DEBUG(2, "HBA_SendRLS dest_wwn: %s",
	    WWN2STR1(&destWWN), 0, 0);

	CHECKLIBRARY();
	registeredfunc = FUNCCOMMON(lib_infop, SendRLSHandler);
	if (registeredfunc != NULL) {
	status = (registeredfunc)(
	    vendorHandle, hbaPortWWN, destWWN,
	    pRspBuffer, pRspBufferSize);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SendLIRR(
    HBA_HANDLE		handle,
    HBA_WWN		sourceWWN,
    HBA_WWN		destWWN,
    HBA_UINT8		function,
    HBA_UINT8		type,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBASendLIRRFunc registeredfunc;

	DEBUG(2, "HBA_SendLIRR destWWN:%s", WWN2STR1(&destWWN), 0, 0);

	CHECKLIBRARY();
	registeredfunc = FUNCCOMMON(lib_infop, SendLIRRHandler);
	if (registeredfunc != NULL) {
	status = (registeredfunc)(
	    vendorHandle, sourceWWN, destWWN, function, type,
	    pRspBuffer, pRspBufferSize);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetBindingCapability(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_BIND_CAPABILITY *pcapability)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBAGetBindingCapabilityFunc
	    registeredfunc;

	DEBUG(2, "HBA_GetBindingCapability", 0, 0, 0);

	CHECKLIBRARYANDVERSION(HBAAPIV2);

	registeredfunc =
	    lib_infop->ftable.functionTable.GetBindingCapabilityHandler;
	if (registeredfunc != NULL) {
	status = (registeredfunc)(vendorHandle, hbaPortWWN, pcapability);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetBindingSupport(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_BIND_CAPABILITY *pcapability)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBAGetBindingSupportFunc
	    registeredfunc;

	DEBUG(2, "HBA_GetBindingSupport", 0, 0, 0);

	CHECKLIBRARYANDVERSION(HBAAPIV2);

	registeredfunc =
	    lib_infop->ftable.functionTable.GetBindingSupportHandler;
	if (registeredfunc != NULL) {
	status = (registeredfunc)(vendorHandle, hbaPortWWN, pcapability);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SetBindingSupport(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_BIND_CAPABILITY capability)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBASetBindingSupportFunc
	    registeredfunc;

	DEBUG(2, "HBA_SetBindingSupport", 0, 0, 0);

	CHECKLIBRARYANDVERSION(HBAAPIV2);

	registeredfunc =
	    lib_infop->ftable.functionTable.SetBindingSupportHandler;
	if (registeredfunc != NULL) {
	status = (registeredfunc)(vendorHandle, hbaPortWWN, capability);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SetPersistentBindingV2(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    const HBA_FCPBINDING2 *pbinding)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBASetPersistentBindingV2Func
	    registeredfunc;

	DEBUG(2, "HBA_SetPersistentBindingV2 port: %s",
	    WWN2STR1(&hbaPortWWN), 0, 0);

	CHECKLIBRARYANDVERSION(HBAAPIV2);

	registeredfunc =
	    lib_infop->ftable.functionTable.SetPersistentBindingV2Handler;
	if (registeredfunc != NULL) {
	status = (registeredfunc)(vendorHandle, hbaPortWWN, pbinding);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetPersistentBindingV2(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_FCPBINDING2	*pbinding)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBAGetPersistentBindingV2Func
	    registeredfunc;

	DEBUG(2, "HBA_GetPersistentBindingV2 port: %s",
	    WWN2STR1(&hbaPortWWN), 0, 0);

	CHECKLIBRARYANDVERSION(HBAAPIV2);

	registeredfunc =
	    lib_infop->ftable.functionTable.GetPersistentBindingV2Handler;
	if (registeredfunc != NULL) {
	status = (registeredfunc)(vendorHandle, hbaPortWWN, pbinding);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_RemovePersistentBinding(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    const HBA_FCPBINDING2
			*pbinding)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBARemovePersistentBindingFunc
	    registeredfunc;

	DEBUG(2, "HBA_RemovePersistentBinding", 0, 0, 0);

	CHECKLIBRARYANDVERSION(HBAAPIV2);

	registeredfunc =
	    lib_infop->ftable.functionTable.RemovePersistentBindingHandler;
	if (registeredfunc != NULL) {
	status = (registeredfunc)(vendorHandle, hbaPortWWN, pbinding);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_RemoveAllPersistentBindings(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBARemoveAllPersistentBindingsFunc
	    registeredfunc;

	DEBUG(2, "HBA_RemoveAllPersistentBindings", 0, 0, 0);

	CHECKLIBRARYANDVERSION(HBAAPIV2);

	registeredfunc =
	    lib_infop->ftable.functionTable.RemoveAllPersistentBindingsHandler;
	if (registeredfunc != NULL) {
	status = (registeredfunc)(vendorHandle, hbaPortWWN);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetFC4Statistics(
    HBA_HANDLE		handle,
    HBA_WWN		portWWN,
    HBA_UINT8		FC4type,
    HBA_FC4STATISTICS	*pstatistics)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBAGetFC4StatisticsFunc
	    registeredfunc;

	DEBUG(2, "HBA_GetFC4Statistics port: %s", WWN2STR1(&portWWN), 0, 0);

	CHECKLIBRARYANDVERSION(HBAAPIV2);

	registeredfunc =
	    lib_infop->ftable.functionTable.GetFC4StatisticsHandler;
	if (registeredfunc != NULL) {
	status = (registeredfunc)
	    (vendorHandle, portWWN, FC4type, pstatistics);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetFCPStatistics(
    HBA_HANDLE		handle,
    const HBA_SCSIID	*lunit,
    HBA_FC4STATISTICS	*pstatistics)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	HBAGetFCPStatisticsFunc
	    registeredfunc;

	DEBUG(2, "HBA_GetFCPStatistics", 0, 0, 0);

	CHECKLIBRARYANDVERSION(HBAAPIV2);

	registeredfunc =
	    lib_infop->ftable.functionTable.GetFCPStatisticsHandler;
	if (registeredfunc != NULL) {
	status = (registeredfunc)(vendorHandle, lunit, pstatistics);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_UINT32
HBA_GetVendorLibraryAttributes(
    HBA_UINT32 adapter_index,
    HBA_LIBRARYATTRIBUTES *attributes)
{
	HBA_ADAPTER_INFO	*adapt_infop;
	HBAGetVendorLibraryAttributesFunc
	    registeredfunc;
	HBA_UINT32		ret = 0;

	DEBUG(2, "HBA_GetVendorLibraryAttributes adapterindex:%d",
	    adapter_index, 0, 0);
	if (_hbaapi_librarylist == NULL) {
	DEBUG(1, "HBAAPI not loaded yet.", 0, 0, 0);
	return (0);
	}

	if (attributes == NULL) {
		DEBUG(1,
		    "HBA_GetVendorLibraryAttributes: NULL pointer attributes",
		    0, 0, 0);
		return (HBA_STATUS_ERROR_ARG);
	}

	(void) memset(attributes, 0, sizeof (HBA_LIBRARYATTRIBUTES));

	GRAB_MUTEX(&_hbaapi_LL_mutex);
	GRAB_MUTEX(&_hbaapi_AL_mutex);
	for (adapt_infop = _hbaapi_adapterlist;
	    adapt_infop != NULL;
	    adapt_infop = adapt_infop->next) {

	if (adapt_infop->index == adapter_index) {

		if (adapt_infop->library->version == SMHBA) {
		RELEASE_MUTEX(&_hbaapi_AL_mutex);
		RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex,
		    HBA_STATUS_ERROR_INCOMPATIBLE);
		}

		registeredfunc = adapt_infop->library->
		    ftable.functionTable.GetVendorLibraryAttributesHandler;
		if (registeredfunc != NULL) {
		ret = (registeredfunc)(attributes);
		} else {
		/* Version 1 libary? */
		HBAGetVersionFunc	GetVersionFunc;
		GetVersionFunc = adapt_infop->library->
		    ftable.functionTable.GetVersionHandler;
		if (GetVersionFunc != NULL) {
			ret = ((GetVersionFunc)());
		}
#ifdef NOTDEF
		else {
		    /* This should not happen, dont think its going to */
		}
#endif
		}
		if (attributes->LibPath[0] == '\0') {
		if (strlen(adapt_infop->library->LibraryPath) < 256) {
			(void) strcpy(attributes->LibPath,
			    adapt_infop->library->LibraryPath);
		}
		}
		break;
	}
	}
	RELEASE_MUTEX(&_hbaapi_AL_mutex);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, ret);
}


/*
 * This function returns SM-HBA version that the warpper library implemented.
 */
HBA_UINT32
SMHBA_GetVersion() {
    DEBUG(2, "SMHBA_GetVersion", 0, 0, 0);
    return (SMHBA_LIBVERSION);
}

/*
 * This function returns the attributes for the warpper library.
 */
HBA_UINT32
SMHBA_GetWrapperLibraryAttributes(
    SMHBA_LIBRARYATTRIBUTES *attributes)
{

	struct timeval tv;
	struct tm tp;

	DEBUG(2, "SMHBA_GetWrapperLibraryAttributes", 0, 0, 0);

	if (attributes == NULL) {
		DEBUG(1, "SMHBA_GetWrapperLibraryAttributes: "
		    "NULL pointer attributes",
		    0, 0, 0);
		return (HBA_STATUS_ERROR_ARG);
	}

	(void) memset(attributes, 0, sizeof (SMHBA_LIBRARYATTRIBUTES));

#if defined(SOLARIS)
	if ((handle = dlopen("libSMHBAAPI.so", RTLD_NOW)) != NULL) {
	if (dlinfo(handle, RTLD_DI_LINKMAP, &map) >= 0) {
		for (mp = map; mp != NULL; mp = mp->l_next) {
		if (strlen(map->l_name) < 256) {
			(void) strcpy(attributes->LibPath, map->l_name);
		}
		}
	}
	}

#endif

#if defined(VENDOR)
	(void) strcpy(attributes->VName, VENDOR);
#else
	attributes->VName[0] = '\0';
#endif
#if	defined(VERSION)
	(void) strcpy(attributes->VVersion, VERSION);
#else
	attributes->VVersion[0] = '\0';
#endif

	if (gettimeofday(&tv, (void *)0) == 0) {
	if (localtime_r(&tv.tv_sec, &tp) != NULL) {
		attributes->build_date.tm_mday = tp.tm_mday;
		attributes->build_date.tm_mon = tp.tm_mon;
		attributes->build_date.tm_year = tp.tm_year;
	} else {
		(void) memset(&attributes->build_date, 0,
		    sizeof (attributes->build_date));
	}
	(void) memset(&attributes->build_date, 0,
	    sizeof (attributes->build_date));
	}

	return (1);
}

/*
 * This function returns the attributes for the warpper library.
 */
HBA_UINT32
SMHBA_GetVendorLibraryAttributes(
    HBA_UINT32 adapter_index,
    SMHBA_LIBRARYATTRIBUTES *attributes)
{
	HBA_ADAPTER_INFO	*adapt_infop;
	SMHBAGetVendorLibraryAttributesFunc
	    registeredfunc;
	HBA_UINT32		ret = 0;

	DEBUG(2, "SMHBA_GetVendorLibraryAttributes adapterindex:%d",
	    adapter_index, 0, 0);
	if (_hbaapi_librarylist == NULL) {
	DEBUG(1, "SMHBAAPI not loaded yet.", 0, 0, 0);
	return (0);
	}

	if (attributes == NULL) {
		DEBUG(1, "SMHBA_GetVendorLibraryAttributes: "
		    "NULL pointer attributes",
		    0, 0, 0);
		return (HBA_STATUS_ERROR_ARG);
	}

	(void) memset(attributes, 0, sizeof (SMHBA_LIBRARYATTRIBUTES));

	GRAB_MUTEX(&_hbaapi_LL_mutex);
	GRAB_MUTEX(&_hbaapi_AL_mutex);
	for (adapt_infop = _hbaapi_adapterlist;
	    adapt_infop != NULL;
	    adapt_infop = adapt_infop->next) {

	if (adapt_infop->index == adapter_index) {

		if (adapt_infop->library->version != SMHBA) {
		RELEASE_MUTEX(&_hbaapi_AL_mutex);
		RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex,
		    HBA_STATUS_ERROR_INCOMPATIBLE);
		}

		registeredfunc = adapt_infop->library->
		    ftable.smhbafunctionTable.GetVendorLibraryAttributesHandler;
		if (registeredfunc != NULL) {
		ret = (registeredfunc)(attributes);
#ifdef NOTDEF
		} else {
		/* This should not happen since the VSL is already loaded. */
#endif
		}
		if (attributes->LibPath[0] == '\0') {
		if (strlen(adapt_infop->library->LibraryPath) < 256) {
			(void) strcpy(attributes->LibPath,
			    adapt_infop->library->LibraryPath);
		}
		}
		break;
	}
	}
	RELEASE_MUTEX(&_hbaapi_AL_mutex);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, ret);
}

HBA_STATUS
SMHBA_GetAdapterAttributes(
    HBA_HANDLE		handle,
    SMHBA_ADAPTERATTRIBUTES *hbaattributes)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBAGetAdapterAttributesFunc GetAdapterAttributesFunc;

	DEBUG(2, "SMHBA_GetAdapterAttributes", 0, 0, 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	GetAdapterAttributesFunc =
	    lib_infop->ftable.smhbafunctionTable.GetAdapterAttributesHandler;
	if (GetAdapterAttributesFunc != NULL) {
	status = ((GetAdapterAttributesFunc)(vendorHandle, hbaattributes));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_GetNumberOfPorts(
    HBA_HANDLE		handle,
    HBA_UINT32		*numberofports)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBAGetNumberOfPortsFunc GetNumberOfPortsFunc;

	DEBUG(2, "SMHBA_GetAdapterAttributes", 0, 0, 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	GetNumberOfPortsFunc =
	    lib_infop->ftable.smhbafunctionTable.GetNumberOfPortsHandler;
	if (GetNumberOfPortsFunc != NULL) {
	status = ((GetNumberOfPortsFunc)(vendorHandle, numberofports));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_GetPortType(
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_PORTTYPE	*porttype)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBAGetPortTypeFunc GetPortTypeFunc;

	DEBUG(2, "SMHBA_GetAdapterAttributes", 0, 0, 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	GetPortTypeFunc =
	    lib_infop->ftable.smhbafunctionTable.GetPortTypeHandler;
	if (GetPortTypeFunc != NULL) {
	status = ((GetPortTypeFunc)(vendorHandle, portindex, porttype));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_GetAdapterPortAttributes(
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    SMHBA_PORTATTRIBUTES	*portattributes)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBAGetAdapterPortAttributesFunc
	    GetAdapterPortAttributesFunc;

	DEBUG(2, "SMHBA_GetAdapterPortAttributes", 0, 0, 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	GetAdapterPortAttributesFunc =
	    lib_infop->ftable.smhbafunctionTable.\
	    GetAdapterPortAttributesHandler;
	if (GetAdapterPortAttributesFunc != NULL) {
	status = ((GetAdapterPortAttributesFunc)
	    (vendorHandle, portindex, portattributes));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_GetDiscoveredPortAttributes(
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_UINT32		discoveredportindex,
    SMHBA_PORTATTRIBUTES	*portattributes)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBAGetDiscoveredPortAttributesFunc
	    GetDiscoveredPortAttributesFunc;

	DEBUG(2, "SMHBA_GetDiscoveredPortAttributes", 0, 0, 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	GetDiscoveredPortAttributesFunc =
	    lib_infop->ftable.smhbafunctionTable.\
	    GetDiscoveredPortAttributesHandler;
	if (GetDiscoveredPortAttributesFunc != NULL)  {
	status = ((GetDiscoveredPortAttributesFunc)
	    (vendorHandle, portindex, discoveredportindex,
	    portattributes));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_GetPortAttributesByWWN(
    HBA_HANDLE		handle,
    HBA_WWN		portWWN,
    HBA_WWN		domainPortWWN,
    SMHBA_PORTATTRIBUTES	*portattributes)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBAGetPortAttributesByWWNFunc
	    GetPortAttributesByWWNFunc;

	DEBUG(2, "SMHBA_GetPortAttributesByWWN: %s", WWN2STR1(&portWWN), 0, 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	GetPortAttributesByWWNFunc =
	    lib_infop->ftable.smhbafunctionTable.GetPortAttributesByWWNHandler;
	if (GetPortAttributesByWWNFunc != NULL) {
	status = ((GetPortAttributesByWWNFunc)
	    (vendorHandle, portWWN, domainPortWWN, portattributes));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_GetFCPhyAttributes(
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_UINT32		phyindex,
    SMHBA_FC_PHY	*phytype)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBAGetFCPhyAttributesFunc GetFCPhyAttributesFunc;

	DEBUG(2, "SMHBA_GetFCPhyAttributesByWWN", 0, 0, 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	GetFCPhyAttributesFunc =
	    lib_infop->ftable.smhbafunctionTable.GetFCPhyAttributesHandler;
	if (GetFCPhyAttributesFunc != NULL) {
	status = ((GetFCPhyAttributesFunc)
	    (vendorHandle, portindex, phyindex, phytype));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_GetSASPhyAttributes(
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_UINT32		phyindex,
    SMHBA_SAS_PHY	*phytype)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBAGetSASPhyAttributesFunc GetSASPhyAttributesFunc;

	DEBUG(2, "SMHBA_GetFCPhyAttributesByWWN", 0, 0, 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	GetSASPhyAttributesFunc =
	    lib_infop->ftable.smhbafunctionTable.GetSASPhyAttributesHandler;
	if (GetSASPhyAttributesFunc != NULL) {
	status = ((GetSASPhyAttributesFunc)
	    (vendorHandle, portindex, phyindex, phytype));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_GetProtocolStatistics(
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_UINT32		protocoltype,
    SMHBA_PROTOCOLSTATISTICS *pProtocolStatistics)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBAGetProtocolStatisticsFunc
	    GetProtocolStatisticsFunc;

	DEBUG(2, "SMHBA_GetProtocolStatistics port index: %d protocol type: %d",
	    portindex, protocoltype, 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	GetProtocolStatisticsFunc =
	    lib_infop->ftable.smhbafunctionTable.GetProtocolStatisticsHandler;
	if (GetProtocolStatisticsFunc != NULL) {
	status = (GetProtocolStatisticsFunc)
	    (vendorHandle, portindex, protocoltype, pProtocolStatistics);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_GetPhyStatistics(
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_UINT32		phyindex,
    SMHBA_PHYSTATISTICS *pPhyStatistics)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBAGetPhyStatisticsFunc
	    GetPhyStatisticsFunc;

	DEBUG(2, "SMHBA_GetPhyStatistics port index: %d phy idex: %d",
	    portindex, phyindex, 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	GetPhyStatisticsFunc =
	    lib_infop->ftable.smhbafunctionTable.GetPhyStatisticsHandler;
	if (GetPhyStatisticsFunc != NULL) {
	status = (GetPhyStatisticsFunc)
	    (vendorHandle, portindex, phyindex, pPhyStatistics);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_GetBindingCapability(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		domainPortWWN,
    SMHBA_BIND_CAPABILITY *pFlags)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBAGetBindingCapabilityFunc GetBindingCapabilityFunc;

	DEBUG(2, "HBA_GetBindingCapability", 0, 0, 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	GetBindingCapabilityFunc =
	    lib_infop->ftable.smhbafunctionTable.GetBindingCapabilityHandler;
	if (GetBindingCapabilityFunc != NULL) {
	status = (GetBindingCapabilityFunc)(vendorHandle, hbaPortWWN,
	    domainPortWWN, pFlags);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_GetBindingSupport(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		domainPortWWN,
    SMHBA_BIND_CAPABILITY *pFlags)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBAGetBindingSupportFunc
	    GetBindingSupporFunc;

	DEBUG(2, "SMHBA_GetBindingSupport port: %s",
	    WWN2STR1(&hbaPortWWN), 0, 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	GetBindingSupporFunc =
	    lib_infop->ftable.smhbafunctionTable.GetBindingSupportHandler;
	if (GetBindingSupporFunc != NULL) {
	status = (GetBindingSupporFunc)(vendorHandle,
	    hbaPortWWN, domainPortWWN, pFlags);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_SetBindingSupport(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		domainPortWWN,
    SMHBA_BIND_CAPABILITY flags)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBASetBindingSupportFunc
	    SetBindingSupporFunc;

	DEBUG(2, "SMHBA_GetBindingSupport port: %s",
	    WWN2STR1(&hbaPortWWN), 0, 0);

	CHECKLIBRARYANDVERSION(HBAAPIV2);

	SetBindingSupporFunc =
	    lib_infop->ftable.smhbafunctionTable.SetBindingSupportHandler;
	if (SetBindingSupporFunc != NULL) {
	status = (SetBindingSupporFunc)
	    (vendorHandle, hbaPortWWN, domainPortWWN, flags);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_GetTargetMapping(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		domainPortWWN,
    SMHBA_TARGETMAPPING *pMapping)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBAGetTargetMappingFunc GetTargetMappingFunc;

	DEBUG(2, "SMHBA_GetTargetMapping port WWN: %s",
	    WWN2STR1(&hbaPortWWN), 0, 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	GetTargetMappingFunc =
	    lib_infop->ftable.smhbafunctionTable.GetTargetMappingHandler;
	if (GetTargetMappingFunc != NULL) {
	status = ((GetTargetMappingFunc)(vendorHandle,
	    hbaPortWWN, domainPortWWN, pMapping));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_GetPersistentBinding(
    HBA_HANDLE handle,
    HBA_WWN	hbaPortWWN,
    HBA_WWN	domainPortWWN,
    SMHBA_BINDING *binding)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBAGetPersistentBindingFunc
	    GetPersistentBindingFunc;

	DEBUG(2, "SMHBA_GetPersistentBinding port WWN: %s",
	    WWN2STR1(&hbaPortWWN), 0, 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	GetPersistentBindingFunc =
	    lib_infop->ftable.smhbafunctionTable.GetPersistentBindingHandler;
	if (GetPersistentBindingFunc != NULL) {
	status = ((GetPersistentBindingFunc)(vendorHandle,
	    hbaPortWWN, domainPortWWN, binding));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_SetPersistentBinding(
    HBA_HANDLE handle,
    HBA_WWN	hbaPortWWN,
    HBA_WWN	domainPortWWN,
    const SMHBA_BINDING *binding)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBASetPersistentBindingFunc
	    SetPersistentBindingFunc;

	DEBUG(2, "SMHBA_SetPersistentBinding port WWN: %s",
	    WWN2STR1(&hbaPortWWN), 0, 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	SetPersistentBindingFunc =
	    lib_infop->ftable.smhbafunctionTable.SetPersistentBindingHandler;
	if (SetPersistentBindingFunc != NULL) {
	status = ((SetPersistentBindingFunc)(vendorHandle,
	    hbaPortWWN, domainPortWWN, binding));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_RemovePersistentBinding(
    HBA_HANDLE handle,
    HBA_WWN	hbaPortWWN,
    HBA_WWN	domainPortWWN,
    const SMHBA_BINDING *binding)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBARemovePersistentBindingFunc
	    RemovePersistentBindingFunc;

	DEBUG(2, "SMHBA_RemovePersistentBinding port WWN: %s",
	    WWN2STR1(&hbaPortWWN), 0, 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	RemovePersistentBindingFunc =
	    lib_infop->ftable.smhbafunctionTable.RemovePersistentBindingHandler;
	if (RemovePersistentBindingFunc != NULL) {
	status = ((RemovePersistentBindingFunc)(vendorHandle,
	    hbaPortWWN, domainPortWWN, binding));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_RemoveAllPersistentBindings(
    HBA_HANDLE handle,
    HBA_WWN	hbaPortWWN,
    HBA_WWN	domainPortWWN)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBARemoveAllPersistentBindingsFunc
	    RemoveAllPersistentBindingsFunc;

	DEBUG(2, "SMHBA_RemoveAllPersistentBinding port WWN: %s",
	    WWN2STR1(&hbaPortWWN), 0, 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	RemoveAllPersistentBindingsFunc =
	    lib_infop->ftable.smhbafunctionTable.\
	    RemoveAllPersistentBindingsHandler;
	if (RemoveAllPersistentBindingsFunc != NULL) {
	status = ((RemoveAllPersistentBindingsFunc)(vendorHandle,
	    hbaPortWWN, domainPortWWN));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_GetLUNStatistics(
    HBA_HANDLE handle,
    const HBA_SCSIID *lunit,
    SMHBA_PROTOCOLSTATISTICS *statistics)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBAGetLUNStatisticsFunc GetLUNStatisticsFunc;

	DEBUG(2, "SMHBA_GetLUNStatistics", 0, 0, 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	GetLUNStatisticsFunc =
	    lib_infop->ftable.smhbafunctionTable.GetLUNStatisticsHandler;
	if (GetLUNStatisticsFunc != NULL) {
	status = ((GetLUNStatisticsFunc)(vendorHandle, lunit, statistics));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_ScsiInquiry(
    HBA_HANDLE	handle,
    HBA_WWN	hbaPortWWN,
    HBA_WWN	discoveredPortWWN,
    HBA_WWN	domainPortWWN,
    SMHBA_SCSILUN	smhbaLUN,
    HBA_UINT8	CDB_Byte1,
    HBA_UINT8	CDB_Byte2,
    void	*pRspBuffer,
    HBA_UINT32	*pRspBufferSize,
    HBA_UINT8	*pScsiStatus,
    void	*pSenseBuffer,
    HBA_UINT32	*pSenseBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBAScsiInquiryFunc ScsiInquiryFunc;

	DEBUG(2, "SMHBA_ScsiInquiry to hba port: %s discoveredPortWWN: %s",
	    WWN2STR1(&hbaPortWWN), WWN2STR1(&discoveredPortWWN), 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	ScsiInquiryFunc =
	    lib_infop->ftable.smhbafunctionTable.ScsiInquiryHandler;
	if (ScsiInquiryFunc != NULL) {
	status = ((ScsiInquiryFunc)(
	    vendorHandle, hbaPortWWN, discoveredPortWWN, domainPortWWN,
	    smhbaLUN, CDB_Byte1, CDB_Byte2, pRspBuffer, pRspBufferSize,
	    pScsiStatus, pSenseBuffer, pSenseBufferSize));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_ScsiReportLUNs(
    HBA_HANDLE	handle,
    HBA_WWN	hbaPortWWN,
    HBA_WWN	discoveredPortWWN,
    HBA_WWN	domainPortWWN,
    void	*pRspBuffer,
    HBA_UINT32	*pRspBufferSize,
    HBA_UINT8	*pScsiStatus,
    void	*pSenseBuffer,
    HBA_UINT32	*pSenseBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBAScsiReportLUNsFunc ScsiReportLUNsFunc;

	DEBUG(2, "SMHBA_ScsiReportLuns to hba port: %s discoveredPortWWN: %s",
	    WWN2STR1(&hbaPortWWN), WWN2STR1(&discoveredPortWWN), 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	ScsiReportLUNsFunc =
	    lib_infop->ftable.smhbafunctionTable.ScsiReportLUNsHandler;
	if (ScsiReportLUNsFunc != NULL) {
	status = ((ScsiReportLUNsFunc)(
	    vendorHandle, hbaPortWWN, discoveredPortWWN, domainPortWWN,
	    pRspBuffer, pRspBufferSize, pScsiStatus, pSenseBuffer,
	    pSenseBufferSize));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_ScsiReadCapacity(
    HBA_HANDLE	handle,
    HBA_WWN	hbaPortWWN,
    HBA_WWN	discoveredPortWWN,
    HBA_WWN	domainPortWWN,
    SMHBA_SCSILUN	smhbaLUN,
    void	*pRspBuffer,
    HBA_UINT32	*pRspBufferSize,
    HBA_UINT8	*pScsiStatus,
    void	*pSenseBuffer,
    HBA_UINT32	*pSenseBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBAScsiReadCapacityFunc ScsiReadCapacityFunc;

	DEBUG(2, "SMHBA_ScsiReadCapacity to hba port: %s discoveredPortWWN: %s",
	    WWN2STR1(&hbaPortWWN), WWN2STR1(&discoveredPortWWN), 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	ScsiReadCapacityFunc =
	    lib_infop->ftable.smhbafunctionTable.ScsiReadCapacityHandler;
	if (ScsiReadCapacityFunc != NULL) {
	status = ((ScsiReadCapacityFunc)(
	    vendorHandle, hbaPortWWN, discoveredPortWWN, domainPortWWN,
	    smhbaLUN, pRspBuffer, pRspBufferSize, pScsiStatus, pSenseBuffer,
	    pSenseBufferSize));
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_SendTEST(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		destWWN,
    HBA_UINT32		destFCID,
    void		*pRspBuffer,
    HBA_UINT32		pRspBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBASendTESTFunc	SendTESTFunc;

	DEBUG(2, "SMHBA_SendTEST, hbaPortWWN: %s destWWN",
	    WWN2STR1(&hbaPortWWN),
	    WWN2STR1(&destWWN), 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	SendTESTFunc = lib_infop->ftable.smhbafunctionTable.SendTESTHandler;
	if (SendTESTFunc != NULL) {
	status = (SendTESTFunc)
	    (vendorHandle, hbaPortWWN, destWWN, destFCID,
	    pRspBuffer, pRspBufferSize);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_SendECHO(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		destWWN,
    HBA_UINT32		destFCID,
    void		*pReqBuffer,
    HBA_UINT32		ReqBufferSize,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBASendECHOFunc	SendECHOFunc;

	DEBUG(2, "SMHBA_SendECHO, hbaPortWWN: %s destWWN",
	    WWN2STR1(&hbaPortWWN), WWN2STR1(&destWWN), 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	SendECHOFunc = lib_infop->ftable.smhbafunctionTable.SendECHOHandler;
	if (SendECHOFunc != NULL) {
	status = (SendECHOFunc)
	    (vendorHandle, hbaPortWWN, destWWN, destFCID,
	    pReqBuffer, ReqBufferSize, pRspBuffer, pRspBufferSize);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
SMHBA_SendSMPPassThru(
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		destWWN,
    HBA_WWN		domainPortWWN,
    void		*pReqBuffer,
    HBA_UINT32		ReqBufferSize,
    void		*pRspBuffer,
    HBA_UINT32		*pRspBufferSize)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	SMHBASendSMPPassThruFunc	SendSMPPassThruFunc;

	DEBUG(2, "SMHBA_SendSMPPassThru, hbaPortWWN: %s destWWN: %s",
	    WWN2STR1(&hbaPortWWN), WWN2STR1(&destWWN), 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	SendSMPPassThruFunc = lib_infop->ftable.\
	    smhbafunctionTable.SendSMPPassThruHandler;

	if (SendSMPPassThruFunc != NULL) {
	status = (SendSMPPassThruFunc)
	    (vendorHandle, hbaPortWWN, destWWN, domainPortWWN,
	    pReqBuffer, ReqBufferSize, pRspBuffer, pRspBufferSize);
	} else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

/*
 * Following the similar logic of HBAAPI addaspterevents_callback.
 *
 * Unlike other events Adapter Add Event is not limited to a specific
 * adapter(i.e. no adapter handle is passed for registration) so
 * the event should be passed to all registrants.  The routine below
 * is passed to the VSLs as a callback and when Adapter Add event is detected
 * by VSL it will call smhba_adapteraddevents_callback() which in turn check
 * if the passed userdata ptr matches with the one stored in the callback list
 * and calls the stored callback.
 *
 * For the situation that multiple clients are registered for Adapter Add event
 * each registration is passed to VSLs so VSL may call
 * smhba_adapteraddevents_callback() multiple times or it may call only once
 * since the callback function is same.  For this implemneation, the userdata
 * is stored in HBA_ALLADAPTERSCALLBACK_ELEM so it is expected that VSL call
 * smhba_adapteraddevents_callback() only once and
 * smhba_adapteraddevents_callback() will call the client callback with proper
 * userdata.
 */
static void
smhba_adapteraddevents_callback(
/* LINTED E_FUNC_ARG_UNUSED */
    void *data,
    HBA_WWN PortWWN,
/* LINTED E_FUNC_ARG_UNUSED */
    HBA_UINT32 eventType)
{
	HBA_ALLADAPTERSCALLBACK_ELEM	*cbp;

	DEBUG(3, "AddAdapterEvent, port:%s", WWN2STR1(&PortWWN), 0, 0);

	GRAB_MUTEX(&_smhba_AAE_mutex);
	for (cbp = _smhba_adapteraddevents_callback_list;
	    cbp != NULL;
	    cbp = cbp->next) {
	(*cbp->callback)(cbp->userdata, PortWWN, HBA_EVENT_ADAPTER_ADD);
	}
	RELEASE_MUTEX(&_smhba_AAE_mutex);

}

HBA_STATUS
SMHBA_RegisterForAdapterAddEvents(
    void		(*pCallback) (
	void		*data,
	HBA_WWN		PortWWN,
	HBA_UINT32	eventType),
    void		*pUserData,
    HBA_CALLBACKHANDLE  *pCallbackHandle) {

    HBA_ALLADAPTERSCALLBACK_ELEM	*cbp;
    HBA_VENDORCALLBACK_ELEM		*vcbp;
    HBA_VENDORCALLBACK_ELEM		*vendorhandlelist;
    SMHBARegisterForAdapterAddEventsFunc	registeredfunc;
    HBA_STATUS				status = HBA_STATUS_OK;
    HBA_STATUS				failure = HBA_STATUS_OK;
    HBA_LIBRARY_INFO			*lib_infop;
    int					registered_cnt = 0;
    int					vendor_cnt = 0;
    int					not_supported_cnt = 0;
    int					status_OK_bar_cnt = 0;
    int					status_OK_cnt = 0;

    DEBUG(2, "SMHBA_RegisterForAdapterAddEvents", 0, 0, 0);
    ARE_WE_INITED();

    cbp = (HBA_ALLADAPTERSCALLBACK_ELEM *)
	    calloc(1, sizeof (HBA_ALLADAPTERSCALLBACK_ELEM));
	*pCallbackHandle = (HBA_CALLBACKHANDLE) cbp;
    if (cbp == NULL) {
	return (HBA_STATUS_ERROR);
	}

    GRAB_MUTEX(&_hbaapi_LL_mutex);
    GRAB_MUTEX(&_smhba_AAE_mutex);
    cbp->callback = pCallback;
    cbp->userdata = pUserData;
    cbp->next = _smhba_adapteraddevents_callback_list;
    _smhba_adapteraddevents_callback_list = cbp;

	/*
	 * Need to release the mutex now incase the vendor function invokes the
	 * callback.  We will grap the mutex later to attach the vendor handle
	 * list to the callback structure
	 */
	RELEASE_MUTEX(&_smhba_AAE_mutex);


	/*
	 * now create a list of vendors (vendor libraryies, NOT ADAPTERS)
	 * that have successfully registerred
	 */
    vendorhandlelist = NULL;
    for (lib_infop = _hbaapi_librarylist;
	lib_infop != NULL;
	lib_infop = lib_infop->next) {

	/* only for HBAAPI V2 */
	if (lib_infop->version != SMHBA) {
	    continue;
	} else {
	    vendor_cnt++;
	}

	registeredfunc =
	    lib_infop->ftable.smhbafunctionTable.\
	    RegisterForAdapterAddEventsHandler;
	if (registeredfunc == NULL) {
	    continue;
	}

	vcbp = (HBA_VENDORCALLBACK_ELEM *)
	    calloc(1, sizeof (HBA_VENDORCALLBACK_ELEM));
	if (vcbp == NULL) {
	    freevendorhandlelist(vendorhandlelist);
	    status = HBA_STATUS_ERROR;
	    break;
	}

	registered_cnt++;
	status = (registeredfunc)(smhba_adapteraddevents_callback,
	    pUserData, &vcbp->vendorcbhandle);
	if (status == HBA_STATUS_ERROR_NOT_SUPPORTED) {
	    not_supported_cnt++;
	    free(vcbp);
	    continue;
	} else if (status != HBA_STATUS_OK) {
	    status_OK_bar_cnt++;
	    DEBUG(1,
		    "SMHBA_RegisterForAdapterAddEvents: Library->%s, Error->%d",
		    lib_infop->LibraryPath, status, 0);
	    failure = status;
	    free(vcbp);
	    continue;
	} else {
	    status_OK_cnt++;
	}
	vcbp->lib_info = lib_infop;
	vcbp->next = vendorhandlelist;
	vendorhandlelist = vcbp;
	}

    if (vendor_cnt == 0) {
	/* no SMHBA VSL found.  Should be okay?? */
	status = HBA_STATUS_ERROR;
	} else if (registered_cnt == 0) {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	freevendorhandlelist(vendorhandlelist);
	(void) local_remove_callback((HBA_CALLBACKHANDLE) cbp);
	} else if (status_OK_cnt == 0 && not_supported_cnt != 0) {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	} else if (status_OK_cnt == 0) {
	/*
	 * At least one vendor library registered this function, but no
	 * vendor call succeeded
	 */
	(void) local_remove_callback((HBA_CALLBACKHANDLE) cbp);
	status = failure;
	} else {
	/* we have had atleast some success, now finish up */
	GRAB_MUTEX(&_smhba_AAE_mutex);
	/*
	 * this seems silly, but what if another thread called
	 * the callback remove
	 */
	for (cbp = _smhba_adapteraddevents_callback_list;
	    cbp != NULL; cbp = cbp->next) {
	    if ((HBA_CALLBACKHANDLE)cbp == *pCallbackHandle) {
		/* yup, its still there, hooray */
		cbp->vendorhandlelist = vendorhandlelist;
		vendorhandlelist = NULL;
		break;
	    }
	}
	RELEASE_MUTEX(&_smhba_AAE_mutex);
	if (vendorhandlelist != NULL) {
		/*
		 * bummer, somebody removed the callback before we finished
		 * registration, probably will never happen
		 */
	    freevendorhandlelist(vendorhandlelist);
	    DEBUG(1,
		    "HBA_RegisterForAdapterAddEvents: HBA_RemoveCallback was "
		    "called for a handle before registration was finished.",
		    0, 0, 0);
	    status = HBA_STATUS_ERROR;
	} else {
	    status = HBA_STATUS_OK;
	}
	}
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

/* SMHBA Adapter Events (other than add) ******************************** */
static void
smhba_adapterevents_callback(void *data,
			HBA_WWN PortWWN,
			HBA_UINT32 eventType)
{
	HBA_ADAPTERCALLBACK_ELEM	*acbp;

	DEBUG(3, "AdapterEvent, port:%s, eventType:%d", WWN2STR1(&PortWWN),
	    eventType, 0);

	GRAB_MUTEX(&_hbaapi_AE_mutex);
	for (acbp = _smhba_adapterevents_callback_list;
	    acbp != NULL;
	    acbp = acbp->next) {
	if (data == (void *)acbp) {
		(*acbp->callback)(acbp->userdata, PortWWN, eventType);
		break;
	}
	}
	RELEASE_MUTEX(&_hbaapi_AE_mutex);
}

HBA_STATUS
SMHBA_RegisterForAdapterEvents(
    void		(*pCallback) (
	void		*data,
	HBA_WWN		PortWWN,
	HBA_UINT32	eventType),
    void		*pUserData,
    HBA_HANDLE		handle,
    HBA_CALLBACKHANDLE	*pCallbackHandle) {

	HBA_ADAPTERCALLBACK_ELEM		*acbp;
	SMHBARegisterForAdapterEventsFunc	registeredfunc;
	HBA_STATUS				status;
	HBA_LIBRARY_INFO			*lib_infop;
	HBA_HANDLE				vendorHandle;

	DEBUG(2, "SMHBA_RegisterForAdapterEvents", 0, 0, 0);

	CHECKLIBRARYANDVERSION(SMHBA);

	/* we now have the _hbaapi_LL_mutex */

	registeredfunc = lib_infop->ftable.smhbafunctionTable.\
	    RegisterForAdapterEventsHandler;
    if (registeredfunc == NULL) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_NOT_SUPPORTED);
	}

	/*
	 * that allocated memory is used both as the handle for the
	 * caller, and as userdata to the vendor call so that on
	 * callback the specific registration may be recalled
	 */
	acbp = (HBA_ADAPTERCALLBACK_ELEM *)
	    calloc(1, sizeof (HBA_ADAPTERCALLBACK_ELEM));
	if (acbp == NULL) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR);
	}
	*pCallbackHandle = (HBA_CALLBACKHANDLE) acbp;
	acbp->callback = pCallback;
	acbp->userdata = pUserData;
	acbp->lib_info = lib_infop;

	status = (registeredfunc)(smhba_adapterevents_callback,
	    (void *)acbp,
	    vendorHandle,
	    &acbp->vendorcbhandle);
    if (status != HBA_STATUS_OK) {
	free(acbp);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
	}

	GRAB_MUTEX(&_smhba_AE_mutex);
	acbp->next = _smhba_adapterevents_callback_list;
	    _hbaapi_adapterevents_callback_list = acbp;

	RELEASE_MUTEX(&_smhba_AE_mutex);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_OK);
}

/* Adapter Port Events *********************************************** */
static void
smhba_adapterportevents_callback(void *data,
			    HBA_WWN PortWWN,
			    HBA_UINT32 eventType,
			    HBA_UINT32 fabricPortID)
{
	HBA_ADAPTERCALLBACK_ELEM	*acbp;

	DEBUG(3,
	    "SMHBA_AdapterPortEvent, port:%s, eventType:%d fabricPortID:0X%06x",
	    WWN2STR1(&PortWWN), eventType, fabricPortID);

	GRAB_MUTEX(&_smhba_APE_mutex);

	for (acbp = _smhba_adapterportevents_callback_list;
	    acbp != NULL;
	    acbp = acbp->next) {
	if (data == (void *)acbp) {
		(*acbp->callback)(acbp->userdata, PortWWN,
		    eventType, fabricPortID);
		break;
	}
	}
	RELEASE_MUTEX(&_smhba_APE_mutex);
}

HBA_STATUS
SMHBA_RegisterForAdapterPortEvents(
    void		(*pCallback) (
	void		*pData,
	HBA_WWN		PortWWN,
	HBA_UINT32	eventType,
	HBA_UINT32	fabricPortID),
    void		*pUserData,
    HBA_HANDLE		handle,
    HBA_WWN		portWWN,
    HBA_UINT32		specificEventType,
    HBA_CALLBACKHANDLE	*pCallbackHandle) {

	HBA_ADAPTERCALLBACK_ELEM		*acbp;
	SMHBARegisterForAdapterPortEventsFunc	registeredfunc;
	HBA_STATUS				status;
	HBA_LIBRARY_INFO			*lib_infop;
	HBA_HANDLE				vendorHandle;

	DEBUG(2, "SMHBA_RegisterForAdapterPortEvents for port: %s",
	    WWN2STR1(&portWWN), 0, 0);

	CHECKLIBRARYANDVERSION(SMHBA);
	/* we now have the _hbaapi_LL_mutex */

	registeredfunc =
	    lib_infop->ftable.smhbafunctionTable.\
	    RegisterForAdapterPortEventsHandler;
	if (registeredfunc == NULL) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_NOT_SUPPORTED);
	}

	/*
	 * that allocated memory is used both as the handle for the
	 * caller, and as userdata to the vendor call so that on
	 * callback the specific registration may be recalled
	 */
	acbp = (HBA_ADAPTERCALLBACK_ELEM *)
	    calloc(1, sizeof (HBA_ADAPTERCALLBACK_ELEM));
	if (acbp == NULL) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR);
	}
	*pCallbackHandle = (HBA_CALLBACKHANDLE) acbp;
	acbp->callback = pCallback;
	acbp->userdata = pUserData;
	acbp->lib_info = lib_infop;

	status = (registeredfunc)(smhba_adapterportevents_callback,
	    (void *)acbp,
	    vendorHandle,
	    portWWN,
	    specificEventType,
	    &acbp->vendorcbhandle);
	if (status != HBA_STATUS_OK) {
	free(acbp);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
	}

	GRAB_MUTEX(&_smhba_APE_mutex);
	acbp->next = _smhba_adapterportevents_callback_list;
	_smhba_adapterportevents_callback_list = acbp;

	RELEASE_MUTEX(&_smhba_APE_mutex);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_OK);
}

/* SMHBA Adapter Port Stat Events ******************************** */
static void
smhba_adapterportstatevents_callback(void *data,
				HBA_WWN portWWN,
				HBA_UINT32 protocolType,
				HBA_UINT32 eventType)
{
	HBA_ADAPTERCALLBACK_ELEM	*acbp;

	DEBUG(3,
	    "SMBA_AdapterPortStateEvent, port:%s, eventType:%d",
	    WWN2STR1(&portWWN), eventType, 0);

	GRAB_MUTEX(&_smhba_APSE_mutex);
	for (acbp = _smhba_adapterportstatevents_callback_list;
	    acbp != NULL;
	    acbp = acbp->next) {
	if (data == (void *)acbp) {
		(*acbp->callback)(acbp->userdata, portWWN,
		    protocolType, eventType);
		return;
	}
	}
	RELEASE_MUTEX(&_smhba_APSE_mutex);
}

HBA_STATUS
SMHBA_RegisterForAdapterPortStatEvents(
    void		(*pCallback) (
	void		*pData,
	HBA_WWN		portWWN,
	HBA_UINT32	protocolType,
	HBA_UINT32	eventType),
    void		*pUserData,
    HBA_HANDLE		handle,
    HBA_WWN		portWWN,
    HBA_UINT32		protocolType,
    SMHBA_PROTOCOLSTATISTICS	stats,
    HBA_UINT32		statType,
    HBA_CALLBACKHANDLE	*pCallbackHandle) {

	HBA_ADAPTERCALLBACK_ELEM	*acbp;
	SMHBARegisterForAdapterPortStatEventsFunc
	    registeredfunc;
	HBA_STATUS			status;
	HBA_LIBRARY_INFO		*lib_infop;
	HBA_HANDLE			vendorHandle;

	DEBUG(2, "SMHBA_RegisterForAdapterPortStatEvents for port: %s",
	    WWN2STR1(&portWWN), 0, 0);

	CHECKLIBRARYANDVERSION(SMHBA);
	/* we now have the _hbaapi_LL_mutex */

	registeredfunc =
	    lib_infop->ftable.smhbafunctionTable.\
	    RegisterForAdapterPortStatEventsHandler;
	if (registeredfunc == NULL) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_NOT_SUPPORTED);
	}

	/*
	 * that allocated memory is used both as the handle for the
	 * caller, and as userdata to the vendor call so that on
	 * callback the specific registration may be recalled
	 */
	acbp = (HBA_ADAPTERCALLBACK_ELEM *)
	    calloc(1, sizeof (HBA_ADAPTERCALLBACK_ELEM));
	if (acbp == NULL) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR);
	}
	*pCallbackHandle = (HBA_CALLBACKHANDLE) acbp;
	acbp->callback = pCallback;
	acbp->userdata = pUserData;
	acbp->lib_info = lib_infop;

	status = (registeredfunc)(smhba_adapterportstatevents_callback,
	    (void *)acbp,
	    vendorHandle,
	    portWWN,
	    protocolType,
	    stats,
	    statType,
	    &acbp->vendorcbhandle);
	if (status != HBA_STATUS_OK) {
	free(acbp);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
	}

	GRAB_MUTEX(&_smhba_APSE_mutex);
	acbp->next = _smhba_adapterportstatevents_callback_list;
	_smhba_adapterportstatevents_callback_list = acbp;

	RELEASE_MUTEX(&_smhba_APSE_mutex);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_OK);
}

/* SMHBA Adapter Port Phy Stat Events ************************************ */
static void
smhba_adapterphystatevents_callback(void *data,
				HBA_WWN portWWN,
				HBA_UINT32 phyIndex,
				HBA_UINT32 eventType)
{
	HBA_ADAPTERCALLBACK_ELEM	*acbp;

	DEBUG(3,
	    "SMBA_AdapterPortStateEvent, port:%s, eventType:%d",
	    WWN2STR1(&portWWN), eventType, 0);

	GRAB_MUTEX(&_smhba_APHYSE_mutex);
	for (acbp = _smhba_adapterphystatevents_callback_list;
	    acbp != NULL;
	    acbp = acbp->next) {
	if (data == (void *)acbp) {
		(*acbp->callback)(acbp->userdata, portWWN, phyIndex, eventType);
		return;
	}
	}
	RELEASE_MUTEX(&_smhba_APHYSE_mutex);
}

HBA_STATUS
SMHBA_RegisterForAdapterPhyStatEvents(
    void		(*pCallback) (
	void		*pData,
	HBA_WWN		portWWN,
	HBA_UINT32	phyIndex,
	HBA_UINT32	eventType),
    void		*pUserData,
    HBA_HANDLE		handle,
    HBA_WWN		portWWN,
    HBA_UINT32		phyIndex,
    SMHBA_PHYSTATISTICS	stats,
    HBA_UINT32		statType,
    HBA_CALLBACKHANDLE	*pCallbackHandle) {

	HBA_ADAPTERCALLBACK_ELEM	*acbp;
	SMHBARegisterForAdapterPhyStatEventsFunc
	    registeredfunc;
	HBA_STATUS			status;
	HBA_LIBRARY_INFO		*lib_infop;
	HBA_HANDLE			vendorHandle;

	DEBUG(2, "SMHBA_RegisterForAdapterPhyStatEvents for port: %s",
	    WWN2STR1(&portWWN), 0, 0);

	CHECKLIBRARYANDVERSION(SMHBA);
	/* we now have the _hbaapi_LL_mutex */

	registeredfunc =
	    lib_infop->ftable.smhbafunctionTable.\
	    RegisterForAdapterPhyStatEventsHandler;
	if (registeredfunc == NULL) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_NOT_SUPPORTED);
	}

	/*
	 * that allocated memory is used both as the handle for the
	 * caller, and as userdata to the vendor call so that on
	 * callback the specific registration may be recalled
	 */
	acbp = (HBA_ADAPTERCALLBACK_ELEM *)
	    calloc(1, sizeof (HBA_ADAPTERCALLBACK_ELEM));
	if (acbp == NULL) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR);
	}
	*pCallbackHandle = (HBA_CALLBACKHANDLE) acbp;
	acbp->callback = pCallback;
	acbp->userdata = pUserData;
	acbp->lib_info = lib_infop;

	status = (registeredfunc)(smhba_adapterphystatevents_callback,
	    (void *)acbp,
	    vendorHandle,
	    portWWN,
	    phyIndex,
	    stats,
	    statType,
	    &acbp->vendorcbhandle);
	if (status != HBA_STATUS_OK) {
	free(acbp);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
	}

	GRAB_MUTEX(&_smhba_APHYSE_mutex);
	acbp->next = _smhba_adapterphystatevents_callback_list;
	_smhba_adapterphystatevents_callback_list = acbp;

	RELEASE_MUTEX(&_smhba_APHYSE_mutex);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_OK);
}

/* SMHBA Target Events ********************************************* */
static void
smhba_targetevents_callback(void *data,
	HBA_WWN hbaPortWWN,
	HBA_WWN discoveredPortWWN,
	HBA_WWN domainPortWWN,
	HBA_UINT32 eventType)
{
	HBA_ADAPTERCALLBACK_ELEM	*acbp;

	DEBUG(3, "TargetEvent, hbaPort:%s, discoveredPort:%s eventType:%d",
	    WWN2STR1(&hbaPortWWN), WWN2STR2(&discoveredPortWWN), eventType);

	GRAB_MUTEX(&_smhba_TE_mutex);
	for (acbp = _smhba_targetevents_callback_list;
	    acbp != NULL;
	    acbp = acbp->next) {
	if (data == (void *)acbp) {
		(*acbp->callback)(acbp->userdata, hbaPortWWN,
		    discoveredPortWWN, domainPortWWN, eventType);
		break;
	}
	}
	RELEASE_MUTEX(&_smhba_TE_mutex);
}

HBA_STATUS
SMHBA_RegisterForTargetEvents(
    void		(*pCallback) (
	void		*pData,
	HBA_WWN		hbaPortWWN,
	HBA_WWN		discoveredPortWWN,
	HBA_WWN		domainPortWWN,
	HBA_UINT32	eventType),
    void		*pUserData,
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_WWN		discoveredPortWWN,
    HBA_WWN		domainPortWWN,
    HBA_CALLBACKHANDLE	*pCallbackHandle,
    HBA_UINT32		allTargets) {

	HBA_ADAPTERCALLBACK_ELEM *acbp;
	SMHBARegisterForTargetEventsFunc
	    registeredfunc;
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;

	DEBUG(2, "SMHBA_RegisterForTargetEvents, hbaPort:"
	    "%s, discoveredPort: %s",
	    WWN2STR1(&hbaPortWWN), WWN2STR2(&discoveredPortWWN), 0);

	CHECKLIBRARYANDVERSION(SMHBA);
	/* we now have the _hbaapi_LL_mutex */

	registeredfunc = lib_infop->ftable.smhbafunctionTable.\
	    RegisterForTargetEventsHandler;

	if (registeredfunc == NULL) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_NOT_SUPPORTED);
	}

	/*
	 * that allocated memory is used both as the handle for the
	 * caller, and as userdata to the vendor call so that on
	 * callback the specific registration may be recalled
	 */
	acbp = (HBA_ADAPTERCALLBACK_ELEM *)
	    calloc(1, sizeof (HBA_ADAPTERCALLBACK_ELEM));
	if (acbp == NULL) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR);
	}
	*pCallbackHandle = (HBA_CALLBACKHANDLE) acbp;
	acbp->callback = pCallback;
	acbp->userdata = pUserData;
	acbp->lib_info = lib_infop;

	status = (registeredfunc)(smhba_targetevents_callback,
	    (void *)acbp,
	    vendorHandle,
	    hbaPortWWN,
	    discoveredPortWWN,
	    domainPortWWN,
	    &acbp->vendorcbhandle,
	    allTargets);
	if (status != HBA_STATUS_OK) {
	free(acbp);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
	}

	GRAB_MUTEX(&_smhba_TE_mutex);
	acbp->next = _smhba_targetevents_callback_list;
	_smhba_targetevents_callback_list = acbp;

	RELEASE_MUTEX(&_smhba_TE_mutex);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_OK);
}
