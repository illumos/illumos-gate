/*************************************************************************
 * Description
 *	HBAAPILIB-sun.c - Implements the Sun Extention for Target mode
 *		FCHBA discovery
 *
 * License:
 *	The contents of this file are subject to the SNIA Public License
 *	Version 1.0 (the "License"); you may not use this file except in
 *	compliance with the License. You may obtain a copy of the License at
 *
 *	http://www.snia.org/English/Resources/Code/OpenSource.html
 *
 *	Software distributed under the License is distributed on an "AS IS"
 *	basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 *	the License for the specific language governing rights and limitations
 *	under the License.
 *
 *************************************************************************
 */
/*
 * 	Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * 	Use is subject to license terms.
 */

#ifdef WIN32
#include <windows.h>
#include <string.h>
/*
 * Next define forces entry points in the dll to be exported
 * See hbaapi.h to see what it does.
 */
#define HBAAPI_EXPORTS
#else
#include <dlfcn.h>
#include <strings.h>
#endif
#include <stdio.h>
#include <time.h>
#include <dlfcn.h>
#include "hbaapi.h"
#include "hbaapi-sun.h"
#include "vendorhbaapi.h"
#include <stdlib.h>
#ifdef USESYSLOG
#include <syslog.h>
#endif


/*
 * LIBRARY_NUM is a shortcut to figure out which library we need to call.
 *  The top 16 bits of handle are the library index
 */
#define LIBRARY_NUM(handle)	((handle)>>16)

/*
 * VENDOR_HANDLE turns a global library handle into a vendor specific handle,
 * with all upper 16 bits set to 0
 */
#define VENDOR_HANDLE(handle)	((handle)&0xFFFF)

#define HBA_HANDLE_FROM_LOCAL(library, vendor) \
				(((library)<<16) | ((vendor)&0x0000FFFF))

extern int _hbaapi_debuglevel;
#define DEBUG(L, STR, A1, A2, A3)

#if defined(USESYSLOG) && defined(USELOGFILE)
extern FILE *_hbaapi_debug_fd;
extern int _hbaapi_sysloginit;
#undef DEBUG
#ifdef WIN32
#define DEBUG(L, STR, A1, A2, A3)\
    if ((L) <= _hbaapi_debuglevel) {\
	if(_hbaapi_sysloginit == 0) {\
	    openlog("HBAAPI", LOG_PID|LOG_ODELAY ,LOG_USER);\
	    _hbaapi_sysloginit = 1;\
	}\
	syslog (LOG_INFO, (STR), (A1), (A2), (A3));\
	if(_hbaapi_debug_fd == NULL) {\
	    char _logFile[MAX_PATH]; \
	    GetTempPath(MAX_PATH, _logFile); \
	    strcat(_logFile, "HBAAPI.log"); \
	    _hbaapi_debug_fd = fopen(_logFile, "a");\
	}\
        if(_hbaapi_debug_fd != NULL) {\
	    fprintf(_hbaapi_debug_fd, (STR ## "\n"), (A1), (A2), (A3));\
	}\
    }
#else /* WIN32*/
#define DEBUG(L, STR, A1, A2, A3)\
    if ((L) <= _hbaapi_debuglevel) {\
	if(_hbaapi_sysloginit == 0) {\
	    openlog("HBAAPI", LOG_PID|LOG_ODELAY ,LOG_USER);\
	    _hbaapi_sysloginit = 1;\
	}\
	syslog (LOG_INFO, (STR), (A1), (A2), (A3));\
	if(_hbaapi_debug_fd == NULL) {\
	    _hbaapi_debug_fd = fopen("/tmp/HBAAPI.log", "a");\
	}\
        if(_hbaapi_debug_fd != NULL) {\
	    fprintf(_hbaapi_debug_fd, (STR ## "\n"), (A1), (A2), (A3));\
	}\
    }
#endif /* WIN32*/
 
#else /* Not both USESYSLOG and USELOGFILE */
#if defined(USESYSLOG)
int _hbaapi_sysloginit = 0;
#undef DEBUG
#define DEBUG(L, STR, A1, A2, A3) \
    if ((L) <= _hbaapi_debuglevel) {\
	if(_hbaapi_sysloginit == 0) {\
	    openlog("HBAAPI", LOG_PID|LOG_ODELAY ,LOG_USER);\
	    _hbaapi_sysloginit = 1;\
	}\
	syslog (LOG_INFO, (STR), (A1), (A2), (A3));\
    }
#endif /* USESYSLOG */
#if defined(USELOGFILE)
FILE *_hbaapi_debug_fd = NULL;
#undef DEBUG
#ifdef WIN32
#define DEBUG(L, STR, A1, A2, A3) \
    if((L) <= _hbaapi_debuglevel) {\
	if(_hbaapi_debug_fd == NULL) {\
	    char _logFile[MAX_PATH]; \
	    GetTempPath(MAX_PATH, _logFile); \
	    strcat(_logFile, "HBAAPI.log"); \
	    _hbaapi_debug_fd = fopen(_logFile, "a");\
        }\
    }
#else /* WIN32 */
#define DEBUG(L, STR, A1, A2, A3) \
    if((L) <= _hbaapi_debuglevel) {\
	if(_hbaapi_debug_fd == NULL) {\
	    _hbaapi_debug_fd = fopen("/tmp/HBAAPI.log", "a");\
	}\
	if(_hbaapi_debug_fd != NULL) { \
	    fprintf(_hbaapi_debug_fd, (STR) ## "\n", (A1), (A2), (A3));\
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
#define GRAB_MUTEX(M)			grab_mutex(M)
#define RELEASE_MUTEX(M)		release_mutex(M)
#define RELEASE_MUTEX_RETURN(M,RET)	release_mutex(M); return(RET)
#elif defined (WIN32)
#define GRAB_MUTEX(m)			EnterCriticalSection(m)
#define RELEASE_MUTEX(m)		LeaveCriticalSection(m)
#define RELEASE_MUTEX_RETURN(m, RET)	LeaveCriticalSection(m); return(RET)
#else
#define GRAB_MUTEX(M)
#define RELEASE_MUTEX(M)
#define RELEASE_MUTEX_RETURN(M,RET)	return(RET)
#endif
 
/*
 * HBA_LIBRARY_STATUS and HBA_LIBRARY_INFO are redefined here.
 * Avoid any change in the common code.
 */ 
typedef enum {
    HBA_LIBRARY_UNKNOWN,
    HBA_LIBRARY_LOADED,
    HBA_LIBRARY_NOT_LOADED
} HBA_LIBRARY_STATUS;

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
    HBA_ENTRYPOINTSV2	functionTable;		/* Function pointers */
    HBA_LIBRARY_STATUS	status;			/* info on this library */
    HBA_UINT32		index;
} HBA_LIBRARY_INFO, *PHBA_LIBRARY_INFO;

#define ARE_WE_INITED() \
	if (_hbaapi_librarylist == NULL) { \
		return(HBA_STATUS_ERROR); \
	}

extern HBA_LIBRARY_INFO *_hbaapi_librarylist;
extern HBA_UINT32 _hbaapi_total_library_count;
#ifdef POSIX_THREADS
extern pthread_mutex_t _hbaapi_LL_mutex;
#elif defined(WIN32)
extern CRITICAL_SECTION _hbaapi_LL_mutex;
#endif

/*
 * Function type def fop Sun extentions.
 */
typedef HBA_UINT32	(* Sun_HBAGetNumberOfTgtAdaptersFunc)();
typedef HBA_STATUS	(* Sun_HBAGetTgtAdapterNameFunc)(HBA_UINT32, char *);
typedef HBA_HANDLE	(* Sun_HBAOpenTgtAdapterFunc)(char *);
typedef HBA_STATUS	(* Sun_HBAOpenTgtAdapterByWWNFunc)
			    (HBA_HANDLE *, HBA_WWN);
typedef	HBA_STATUS	(* Sun_HBANPIVGetAdapterAttributesFunc)
			    (HBA_HANDLE, HBA_ADAPTERATTRIBUTES *);
typedef	HBA_STATUS	(* Sun_HBAGetNPIVPortInfoFunc)
			    (HBA_HANDLE, HBA_UINT32, HBA_UINT32, HBA_NPIVATTRIBUTES *);
typedef HBA_STATUS	(* Sun_HBADeleteNPIVPortFunc)
			    (HBA_HANDLE, HBA_UINT32, HBA_WWN);
typedef HBA_STATUS	(* Sun_HBACreateNPIVPortFunc)
			    (HBA_HANDLE, HBA_UINT32, HBA_WWN, HBA_WWN, HBA_UINT32 *);
typedef	HBA_STATUS	(* Sun_HBAAdapterReturnWWNFunc)
			    (HBA_HANDLE, HBA_UINT32, HBA_WWN *, HBA_WWN *);
typedef	HBA_STATUS	(* Sun_HBAAdapterCreateWWNFunc)
			    (HBA_HANDLE, HBA_UINT32, HBA_WWN *, HBA_WWN *, HBA_WWN *,
			    HBA_INT32);
typedef	HBA_STATUS	(* Sun_HBAGetPortNPIVAttributesFunc)
			    (HBA_HANDLE, HBA_UINT32, HBA_PORTNPIVATTRIBUTES *);
typedef	HBA_STATUS	(* Sun_HBARegisterForAdapterDeviceEventsFunc)
			    (void (*)(void *, HBA_WWN, HBA_UINT32, HBA_UINT32),
			    void *, HBA_HANDLE, HBA_WWN, HBA_CALLBACKHANDLE *);

/*
 * Individual adapter (hba) information
 * Same as hbaadapter with different structure name.
 */
typedef struct hba_tgtadapter_info {
    struct hba_tgtadapter_info
			*next;
    HBA_STATUS		GNstatus; /* status from GetTgtAdapterNameFunc */
    char		*name;
    HBA_WWN		nodeWWN;
    HBA_LIBRARY_INFO	*library;
    HBA_UINT32		index;
} HBA_TGTADAPTER_INFO;

/*
 * Make the list as an array with max size 16
 */
HBA_TGTADAPTER_INFO *_hbaapi_tgtadapterlist;
HBA_UINT32 _hbaapi_total_tgtadapter_count = 0;
#ifdef POSIX_THREADS
pthread_mutex_t _hbaapi_tgtAL_mutex = PTHREAD_MUTEX_INITIALIZER;
#elif defined(WIN32)
CRITICAL_SECTION _hbaapi_tgtAL_mutex;
#endif

/*
 * Common library internal. Mutex handling
 */
#ifdef POSIX_THREADS
static void
grab_mutex(pthread_mutex_t *mp) {
    int ret;
    if((ret = pthread_mutex_lock(mp)) != 0) {
	perror("pthread_mutex_lock - HBAAPI:");
	DEBUG(0, "pthread_mutex_lock returned %d", ret, 0, 0);
    }
}

static void
release_mutex(pthread_mutex_t *mp) {
    int ret;
    if((ret = pthread_mutex_unlock(mp)) != 0) {
	perror("pthread_mutex_unlock - HBAAPI:");
	DEBUG(0, "pthread_mutex_unlock returned %d", ret, 0, 0);
    }
}
#endif

/*
 * The API used to use fixed size tables as its primary data structure.
 * Indexing from 1 to N identified each adapters.  Now the adapters are
 * on a linked list.  There is a unique "index" foreach each adapter.
 * Adapters always keep their index, even if they are removed from the
 * hardware.  The only time the indexing is reset is on HBA_FreeLibrary
 */
HBA_UINT32
Sun_HBA_GetNumberOfTgtAdapters()
{
    int j=0;
    HBA_LIBRARY_INFO	*lib_infop;
    Sun_HBAGetNumberOfTgtAdaptersFunc
			GetNumberOfTgtAdaptersFunc = NULL;
    Sun_HBAGetTgtAdapterNameFunc
			GetTgtAdapterNameFunc = NULL;
    HBA_BOOLEAN		found_name;
    HBA_TGTADAPTER_INFO	*adapt_infop;
    HBA_STATUS		status;

    char adaptername[256];
    int num_adapters; /* local */

    if(_hbaapi_librarylist == NULL) {
	return (0);
    }
    GRAB_MUTEX(&_hbaapi_LL_mutex); /* pay attention to order */
    GRAB_MUTEX(&_hbaapi_tgtAL_mutex);

    for (lib_infop = _hbaapi_librarylist;
	 lib_infop != NULL;
	 lib_infop = lib_infop->next) {

	if (lib_infop->status != HBA_LIBRARY_LOADED) {
	    continue;
	}

	if (lib_infop->hLibrary != NULL) {
            GetNumberOfTgtAdaptersFunc = (Sun_HBAGetNumberOfTgtAdaptersFunc)
		dlsym(lib_infop->hLibrary, "Sun_fcGetNumberOfTgtAdapters");
            GetTgtAdapterNameFunc = (Sun_HBAGetTgtAdapterNameFunc)
		dlsym(lib_infop->hLibrary, "Sun_fcGetTgtAdapterName");
	    if (GetNumberOfTgtAdaptersFunc == NULL ||
		GetTgtAdapterNameFunc == NULL)	{	    
		GetNumberOfTgtAdaptersFunc = GetTgtAdapterNameFunc = NULL;
                continue;
            }
	} else {
	    continue;
	}

	num_adapters = ((GetNumberOfTgtAdaptersFunc)());
#ifndef WIN32
	DEBUG(1, "HBAAPI: number of target mode adapters for %s = %d\n", 
	      lib_infop->LibraryName, num_adapters, 0);
#else
	DEBUG(1, "HBAAPI: number of target mode_adapters for %s = %d\n", 
	      lib_infop->LibraryPath, num_adapters, 0);
#endif

	for (j = 0; j < num_adapters; j++) {
	    found_name = 0;
	    status = (GetTgtAdapterNameFunc)(j, (char *)&adaptername);
	    if(status == HBA_STATUS_OK) {
		for(adapt_infop = _hbaapi_tgtadapterlist;
		    adapt_infop != NULL;
		    adapt_infop = adapt_infop->next) {
		    /*
		     * check for duplicates, really, this may just be a second
		     * call to this function
		     * ??? how do we know when a name becomes stale?
		     */
		    if(strcmp(adaptername, adapt_infop->name) == 0) {
			/* already got this one */
			found_name++;
			break;
		    }
		}
		if(found_name != 0) {
		    continue;
		}
	    }

	    adapt_infop = (HBA_TGTADAPTER_INFO *)
		calloc(1, sizeof(HBA_TGTADAPTER_INFO));
	    if(adapt_infop == NULL) {
#ifndef WIN32
		fprintf(stderr,
			"HBA_GetNumberOfAdapters: calloc failed on sizeof:%d\n",
			sizeof(HBA_TGTADAPTER_INFO));
#endif
		RELEASE_MUTEX(&_hbaapi_tgtAL_mutex);
		RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex,
				     _hbaapi_total_tgtadapter_count);
	    }
	    if((adapt_infop->GNstatus = status) == HBA_STATUS_OK) {
		adapt_infop->name = strdup(adaptername);
	    } else {
		char dummyname[512];
		sprintf(dummyname, "NULLADAPTER-%s-%03d", 
			lib_infop->LibraryPath, _hbaapi_total_tgtadapter_count);
		dummyname[255] = '\0';
		adapt_infop->name = strdup(dummyname);
	    }
	    adapt_infop->library = lib_infop;
	    adapt_infop->next = _hbaapi_tgtadapterlist;
	    adapt_infop->index = _hbaapi_total_tgtadapter_count;
	    _hbaapi_tgtadapterlist = adapt_infop;
	    _hbaapi_total_tgtadapter_count++;
	}
	GetNumberOfTgtAdaptersFunc = GetTgtAdapterNameFunc = NULL;
    }
    RELEASE_MUTEX(&_hbaapi_tgtAL_mutex);
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, _hbaapi_total_tgtadapter_count);
}

HBA_STATUS
Sun_HBA_GetTgtAdapterName(
    HBA_UINT32 adapterindex,
    char *adaptername)
{
    HBA_TGTADAPTER_INFO	*adapt_infop;
    HBA_STATUS		ret = HBA_STATUS_ERROR_ILLEGAL_INDEX;

    if (adaptername == NULL) {
	    return(HBA_STATUS_ERROR_ARG);
    }
    /*
     * The adapter index is from old code, but we have
     * to support it.  Go down the list looking for
     * the adapter
     */
    ARE_WE_INITED();
    GRAB_MUTEX(&_hbaapi_tgtAL_mutex);
    *adaptername = '\0';
    for(adapt_infop = _hbaapi_tgtadapterlist;
	adapt_infop != NULL;
	adapt_infop = adapt_infop->next) {

	if(adapt_infop->index == adapterindex) {
	    if(adapt_infop->name != NULL && 
	       adapt_infop->GNstatus == HBA_STATUS_OK) {
		strcpy(adaptername, adapt_infop->name);
	    } else {
		*adaptername = '\0';
	    }
	    ret = adapt_infop->GNstatus;
	    break;
	}
    }
    DEBUG(2, "GetAdapterName for index:%d ->%s", adapterindex, adaptername, 0);
    RELEASE_MUTEX_RETURN(&_hbaapi_AL_mutex, ret);
}

HBA_HANDLE
Sun_HBA_OpenTgtAdapter(char* adaptername)
{
    HBA_HANDLE		handle;
    Sun_HBAOpenTgtAdapterFunc	OpenTgtAdapterFunc;
    HBA_TGTADAPTER_INFO	*adapt_infop;
    HBA_LIBRARY_INFO	*lib_infop;

    DEBUG(2, "OpenAdapter: %s", adaptername, 0, 0);

    if(_hbaapi_librarylist == NULL) {
	return(HBA_HANDLE_INVALID);
    }
    if (adaptername == NULL) {
	return(HBA_STATUS_ERROR_ARG);
    }
    handle = HBA_HANDLE_INVALID;
    GRAB_MUTEX(&_hbaapi_AL_mutex);
    for(adapt_infop = _hbaapi_tgtadapterlist;
	adapt_infop != NULL;
	adapt_infop = adapt_infop->next) {
	if (strcmp(adaptername, adapt_infop->name) != 0) {
	    continue;
	}
	lib_infop = adapt_infop->library;
        OpenTgtAdapterFunc = (Sun_HBAOpenTgtAdapterFunc)
		dlsym(lib_infop->hLibrary, "Sun_fcOpenTgtAdapter");
	if (OpenTgtAdapterFunc != NULL) {
	    /* retrieve the vendor handle */
	    handle = (OpenTgtAdapterFunc)(adaptername);
	    if(handle != 0) {
		/* or this with the library index to get the common handle */
		handle = HBA_HANDLE_FROM_LOCAL(lib_infop->index, handle);
	    }
	}
	break;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_AL_mutex, handle);
}

/*
 * This function ignores the list of known adapters and instead tries
 * each vendors open function to see if one of them
 * can open an adapter when referenced with a particular WWN
 */
HBA_STATUS
Sun_HBA_OpenTgtAdapterByWWN(HBA_HANDLE *phandle, HBA_WWN nodeWWN)
{
    HBA_HANDLE		handle;
    HBA_LIBRARY_INFO	*lib_infop;
    Sun_HBAGetNumberOfTgtAdaptersFunc
			GetNumberOfTgtAdaptersFunc;
    Sun_HBAOpenTgtAdapterByWWNFunc
			OpenTgtAdapterByWWNFunc;
    HBA_STATUS		status;

    DEBUG(2, "OpenAdapterByWWN: %s", WWN2STR1(&nodeWWN), 0, 0);

    if (phandle == NULL) {
	    return(HBA_STATUS_ERROR_ARG);
    }

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

        GetNumberOfTgtAdaptersFunc = (Sun_HBAGetNumberOfTgtAdaptersFunc)
		dlsym(lib_infop->hLibrary, "Sun_fcGetNumberOfTgtAdapters");
        OpenTgtAdapterByWWNFunc = (Sun_HBAOpenTgtAdapterByWWNFunc)
		dlsym(lib_infop->hLibrary, "Sun_fcOpenTgtAdapterByWWN");
	if (GetNumberOfTgtAdaptersFunc == NULL ||
		OpenTgtAdapterByWWNFunc == NULL) {	    
		GetNumberOfTgtAdaptersFunc = OpenTgtAdapterByWWNFunc = NULL;
                continue;
        }

	(void) ((GetNumberOfTgtAdaptersFunc)());
 
	if((status = (OpenTgtAdapterByWWNFunc)(&handle, nodeWWN))
	    != HBA_STATUS_OK) {
	    GetNumberOfTgtAdaptersFunc = OpenTgtAdapterByWWNFunc = NULL;
	    continue;
	}
	/* OK, make a vendor non-specific handle */
	*phandle = HBA_HANDLE_FROM_LOCAL(lib_infop->index, handle);
	status = HBA_STATUS_OK;
	break;

	GetNumberOfTgtAdaptersFunc = OpenTgtAdapterByWWNFunc = NULL;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

static HBA_STATUS
HBA_NPIV_CheckLibrary(HBA_HANDLE handle,
			HBA_LIBRARY_INFO **lib_infopp,
			HBA_HANDLE *vendorhandle) {
	HBA_UINT32		libraryIndex;
	HBA_LIBRARY_INFO	*lib_infop;

	if (vendorhandle == NULL) {
		return(HBA_STATUS_ERROR_ARG);
	}
	if(_hbaapi_librarylist == NULL) {
		return(HBA_STATUS_ERROR);
	}
	libraryIndex = LIBRARY_NUM(handle);

	GRAB_MUTEX(&_hbaapi_LL_mutex);
	for(lib_infop = _hbaapi_librarylist;
	    lib_infop != NULL;
	    lib_infop = lib_infop->next) {
		if(lib_infop->index == libraryIndex) {
			if(lib_infop->status != HBA_LIBRARY_LOADED) {
				return HBA_STATUS_ERROR;
			}
			*lib_infopp = lib_infop;
			*vendorhandle = VENDOR_HANDLE(handle);
			/* caller will release the mutex */
			return HBA_STATUS_OK;
		}
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_INVALID_HANDLE);
}
#define	NPIVCHECKLIBRARY() \
	status = HBA_NPIV_CheckLibrary(handle, &lib_infop, &vendorHandle); \
	if(status != HBA_STATUS_OK) { \
		return(status); \
	}

HBA_STATUS
Sun_HBA_NPIVGetAdapterAttributes (
    HBA_HANDLE		handle,
    HBA_ADAPTERATTRIBUTES
			*hbaattributes)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	Sun_HBANPIVGetAdapterAttributesFunc	NPIVGetAdapterAttributesFunc;

	DEBUG(2, "HBA_NPIVGetAdapterAttributes", 0, 0, 0);

	NPIVCHECKLIBRARY();
	NPIVGetAdapterAttributesFunc = (Sun_HBANPIVGetAdapterAttributesFunc)
	    dlsym(lib_infop->hLibrary, "Sun_fcNPIVGetAdapterAttributes");
	if (NPIVGetAdapterAttributesFunc != NULL) {
		status = ((NPIVGetAdapterAttributesFunc)(vendorHandle,
			hbaattributes));
	} else {
		status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
Sun_HBA_GetNPIVPortInfo (
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_UINT32		vportindex,
    HBA_NPIVATTRIBUTES	*attributes)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	Sun_HBAGetNPIVPortInfoFunc	GetNPIVPortInfoFunc;

	NPIVCHECKLIBRARY();
	GetNPIVPortInfoFunc = (Sun_HBAGetNPIVPortInfoFunc)
		dlsym(lib_infop->hLibrary, "Sun_fcGetNPIVPortInfo");
	if (GetNPIVPortInfoFunc != NULL) {
		status = ((GetNPIVPortInfoFunc)(vendorHandle, portindex,
			vportindex, attributes));
	} else {
		status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
Sun_HBA_DeleteNPIVPort (
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_WWN		vportWWN)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	Sun_HBADeleteNPIVPortFunc	DeleteNPIVPortFunc;

	NPIVCHECKLIBRARY();
	DeleteNPIVPortFunc = (Sun_HBADeleteNPIVPortFunc)
		dlsym(lib_infop->hLibrary, "Sun_fcDeleteNPIVPort");
	if (DeleteNPIVPortFunc != NULL) {
		status = ((DeleteNPIVPortFunc)(vendorHandle,
		    portindex, vportWWN));
	} else {
		status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
Sun_HBA_CreateNPIVPort (
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_WWN		vnodeWWN,
    HBA_WWN		vportWWN,
    HBA_UINT32		*vportindex)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	Sun_HBACreateNPIVPortFunc	CreateNPIVPortFunc;

	NPIVCHECKLIBRARY();
	CreateNPIVPortFunc = (Sun_HBACreateNPIVPortFunc)
		dlsym(lib_infop->hLibrary, "Sun_fcCreateNPIVPort");
	if (CreateNPIVPortFunc != NULL) {
		status = ((CreateNPIVPortFunc)(vendorHandle,
		    portindex, vnodeWWN, vportWWN, vportindex));
	} else {
		status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
Sun_HBA_GetPortNPIVAttributes (
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_PORTNPIVATTRIBUTES	*portnpivattributes)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	Sun_HBAGetPortNPIVAttributesFunc	GetPortNPIVAttributesFunc;

	NPIVCHECKLIBRARY();
	GetPortNPIVAttributesFunc = (Sun_HBAGetPortNPIVAttributesFunc)
		dlsym(lib_infop->hLibrary, "Sun_fcGetPortNPIVAttributes");
	if (GetPortNPIVAttributesFunc != NULL) {
		status = ((GetPortNPIVAttributesFunc)(
		    vendorHandle, portindex, portnpivattributes));
	} else {
		status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
Sun_HBA_AdapterCreateWWN (
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_WWN		*nwwn,
    HBA_WWN		*pwwn,
    HBA_WWN		*OUI,
    HBA_INT32		method)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	Sun_HBAAdapterCreateWWNFunc	AdapterCreateWWNFunc;

	NPIVCHECKLIBRARY();
	AdapterCreateWWNFunc = (Sun_HBAAdapterCreateWWNFunc)
		dlsym(lib_infop->hLibrary, "Sun_fcAdapterCreateWWN");
	if (AdapterCreateWWNFunc != NULL) {
		status = ((AdapterCreateWWNFunc)(vendorHandle,
		    portindex, nwwn, pwwn, OUI, method));
	} else {
		status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
Sun_HBA_AdapterReturnWWN (
    HBA_HANDLE		handle,
    HBA_UINT32		portindex,
    HBA_WWN		*nwwn,
    HBA_WWN		*pwwn)
{
	HBA_STATUS		status;
	HBA_LIBRARY_INFO	*lib_infop;
	HBA_HANDLE		vendorHandle;
	Sun_HBAAdapterReturnWWNFunc	AdapterReturnWWNFunc;

	NPIVCHECKLIBRARY();
	AdapterReturnWWNFunc = (Sun_HBAAdapterReturnWWNFunc)
		dlsym(lib_infop->hLibrary, "Sun_fcAdapterReturnWWN");
	if (AdapterReturnWWNFunc != NULL) {
		status = ((AdapterReturnWWNFunc)(vendorHandle,
		    portindex, nwwn, pwwn));
	} else {
		status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

typedef struct hba_npivadaptercallback_elem {
    struct hba_npivadaptercallback_elem
			*next;
    HBA_LIBRARY_INFO	*lib_info;
    void		*userdata;
    HBA_CALLBACKHANDLE	vendorcbhandle;
    void		(*callback)();
} HBA_NPIVADAPTERCALLBACK_ELEM;
extern HBA_NPIVADAPTERCALLBACK_ELEM *_hbaapi_adapterdeviceevents_callback_list;

/* Adapter Device Events ********************************************************/
static void
adapterdeviceevents_callback (void *data,
    HBA_WWN	PortWWN,
    HBA_UINT32	eventType,
    HBA_UINT32	fabricPortID)
{
	HBA_NPIVADAPTERCALLBACK_ELEM	*acbp;

	DEBUG(3, "AdapterDeviceEvent, port:%s, eventType:%d fabricPortID:0X%06x",
	    WWN2STR1(&PortWWN), eventType, fabricPortID);

	GRAB_MUTEX(&_hbaapi_APE_mutex);

	for(acbp = _hbaapi_adapterdeviceevents_callback_list;
	    acbp != NULL;
	    acbp = acbp->next) {
		if(data == (void *)acbp) {
			(*acbp->callback)(acbp->userdata, PortWWN, eventType, fabricPortID);
			break;
		}
	}
	RELEASE_MUTEX(&_hbaapi_APE_mutex);
}

HBA_STATUS
Sun_HBA_RegisterForAdapterDeviceEvents (
    void	(*callback) (
	void		*data,
	HBA_WWN		PortWWN,
	HBA_UINT32	eventType,
	HBA_UINT32	fabricPortID
	),
    void		*userData,
    HBA_HANDLE		handle,
    HBA_WWN		PortWWN,
    HBA_CALLBACKHANDLE	*callbackHandle)
{
	HBA_NPIVADAPTERCALLBACK_ELEM	*acbp;
	HBA_STATUS			status;
	HBA_LIBRARY_INFO		*lib_infop;
	HBA_HANDLE			vendorHandle;
	Sun_HBARegisterForAdapterDeviceEventsFunc
					registeredfunc;

	if (callbackHandle == NULL) {
		return(HBA_STATUS_ERROR_ARG);
	}

        NPIVCHECKLIBRARY();
	registeredfunc = (Sun_HBARegisterForAdapterDeviceEventsFunc)
                dlsym(lib_infop->hLibrary,
		    "Sun_fcRegisterForAdapterDeviceEvents");
	if (registeredfunc == NULL) {
		RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_NOT_SUPPORTED);
	}

	acbp = (HBA_NPIVADAPTERCALLBACK_ELEM *)
		calloc(1, sizeof(HBA_NPIVADAPTERCALLBACK_ELEM));

	if(acbp == NULL) {
		RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR);
	}

	*callbackHandle = (HBA_CALLBACKHANDLE) acbp;
	acbp->callback = callback;
	acbp->userdata = userData;
	acbp->lib_info = lib_infop;

	status = (registeredfunc)(adapterdeviceevents_callback,
		(void *)acbp,
		vendorHandle,
		PortWWN,
		&acbp->vendorcbhandle);
	if(status != HBA_STATUS_OK) {
		free(acbp);
		RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
	}

	GRAB_MUTEX(&_hbaapi_APE_mutex);
	acbp->next = _hbaapi_adapterdeviceevents_callback_list;
	_hbaapi_adapterdeviceevents_callback_list = acbp;
	RELEASE_MUTEX(&_hbaapi_APE_mutex);

	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_OK);
}
