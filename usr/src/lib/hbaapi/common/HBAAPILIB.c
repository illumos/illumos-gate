/*************************************************************************
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
 *************************************************************************
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
#include "hbaapi.h"
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

int _hbaapi_debuglevel = 0;
#define DEBUG(L, STR, A1, A2, A3)

#if defined(USESYSLOG) && defined(USELOGFILE)
FILE *_hbaapi_debug_fd = NULL;
int _hbaapi_sysloginit = 0;
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
 * Vendor library information 
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
HBA_LIBRARY_INFO *_hbaapi_librarylist = NULL;
HBA_UINT32 _hbaapi_total_library_count = 0;
#ifdef POSIX_THREADS
pthread_mutex_t _hbaapi_LL_mutex = PTHREAD_MUTEX_INITIALIZER;
#elif defined(WIN32)
CRITICAL_SECTION _hbaapi_LL_mutex;
#endif

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
HBA_ADAPTERCALLBACK_ELEM *_hbaapi_adapterdeviceevents_callback_list = NULL;
#ifdef POSIX_THREADS
/* mutex's to protect each list */
pthread_mutex_t _hbaapi_AAE_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t _hbaapi_AE_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t _hbaapi_APE_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t _hbaapi_APSE_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t _hbaapi_TE_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t _hbaapi_LE_mutex = PTHREAD_MUTEX_INITIALIZER;
#elif defined(WIN32)
CRITICAL_SECTION _hbaapi_AAE_mutex;
CRITICAL_SECTION _hbaapi_AE_mutex;
CRITICAL_SECTION _hbaapi_APE_mutex;
CRITICAL_SECTION _hbaapi_APSE_mutex;
CRITICAL_SECTION _hbaapi_TE_mutex;
CRITICAL_SECTION _hbaapi_LE_mutex;
#endif

HBA_ADAPTERCALLBACK_ELEM **cb_lists_array[] = {
    &_hbaapi_adapterevents_callback_list,
    &_hbaapi_adapterportevents_callback_list,
    &_hbaapi_adapterportstatevents_callback_list,
    &_hbaapi_targetevents_callback_list,
    &_hbaapi_linkevents_callback_list,
    &_hbaapi_adapterdeviceevents_callback_list,
    NULL};

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
 * Common library internal. Check library and return vendorhandle
 */
static HBA_STATUS
HBA_CheckLibrary(HBA_HANDLE handle,
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
#define CHECKLIBRARY() \
	status = HBA_CheckLibrary(handle, &lib_infop, &vendorHandle);\
 	if(status != HBA_STATUS_OK) { \
	    return(status); \
 	}

/*
 *freevendorhandlelist is called with _hbaapi_LL_mutex already held
 */
static void
freevendorhandlelist(HBA_VENDORCALLBACK_ELEM *vhlist) {
    HBA_VENDORCALLBACK_ELEM	*vhlp;
    HBA_VENDORCALLBACK_ELEM	*vnext;
    HBARemoveCallbackFunc	registeredfunc;

    for(vhlp = vhlist; vhlp != NULL; vhlp = vnext) {
	vnext = vhlp->next;
	registeredfunc = 
	    vhlp->lib_info->functionTable.RemoveCallbackHandler;
	if(registeredfunc == NULL) {
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
    HBA_STATUS				status = HBA_STATUS_ERROR_INVALID_HANDLE;


    /* search through the simple lists first */
    GRAB_MUTEX(&_hbaapi_AAE_mutex);
    GRAB_MUTEX(&_hbaapi_AE_mutex);
    GRAB_MUTEX(&_hbaapi_APE_mutex);
    GRAB_MUTEX(&_hbaapi_APSE_mutex);
    GRAB_MUTEX(&_hbaapi_TE_mutex);
    GRAB_MUTEX(&_hbaapi_LE_mutex);
    for(listp = cb_lists_array, found = 0; found == 0, *listp != NULL; listp++) {
	lastp = *listp;
	for(cbp=**listp; cbp != NULL; cbp = cbp->next) {
	    if(cbhandle != (HBA_CALLBACKHANDLE)cbp) {
		lastp = &(cbp->next);
		continue;
	    }
	    found = 1;
	    registeredfunc = cbp->lib_info->functionTable.RemoveCallbackHandler;
	    if(registeredfunc == NULL) {
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
    if(found != 0) {
	if(registeredfunc == NULL) {
	    return HBA_STATUS_ERROR_NOT_SUPPORTED;
	}
	return HBA_STATUS_OK;
    }

    GRAB_MUTEX(&_hbaapi_AAE_mutex);
    /* if it wasnt in the simple lists, look in the list for adapteraddevents */
    lap = &_hbaapi_adapteraddevents_callback_list;
    for(allcbp = _hbaapi_adapteraddevents_callback_list; 
	allcbp != NULL;
	allcbp = allcbp->next) {
	if(cbhandle != (HBA_CALLBACKHANDLE)allcbp) {
	    lap = &allcbp->next;
	    continue;
	}
	for(vhlp = allcbp->vendorhandlelist; vhlp != NULL; vhlp = vnext) {
	    vnext = vhlp->next;
	    registeredfunc = 
		vhlp->lib_info->functionTable.RemoveCallbackHandler;
	    if(registeredfunc == NULL) {
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
    return(status);
}

static char wwn_str1[17];
static char wwn_str2[17];
static char wwn_str3[17];
#define WWN2STR1(wwn) WWN2str(wwn_str1, (wwn))
#define WWN2STR2(wwn) WWN2str(wwn_str2, (wwn))
#define WWN2STR3(wwn) WWN2str(wwn_str3, (wwn))
static char *
WWN2str(char *buf, HBA_WWN *wwn) {
    int j;
    unsigned char *pc = (unsigned char *)&(wwn->wwn[0]);
    buf[0] = '\0';
    for (j=0; j<16; j+=2) {
        sprintf(&buf[j], "%02X", (int)*pc++);
    }
    return(buf);
}


#ifdef WIN32
BOOL APIENTRY
DllMain( HANDLE hModule,
	 DWORD  ul_reason_for_call,
	 LPVOID lpReserved
    )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	break;
    case DLL_PROCESS_DETACH:
	break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
	break;
    }
    return TRUE;
}
#endif

/*
 * Read in the config file and load all the specified vendor specific
 * libraries and perform the function registration exercise
 */
HBA_STATUS
HBA_LoadLibrary(void) {
    HBARegisterLibraryFunc
			RegisterFunc;
    HBARegisterLibraryV2Func
			RegisterV2Func;
    HBALoadLibraryFunc	LoadLibraryFunc;
    HBAGetVersionFunc	GetVersionFunc;
#ifdef POSIX_THREADS
    int			ret;
#endif
    HBA_STATUS		status;
#ifdef NOTDEF
    HBA_UINT32		libversion;
#endif

    /* Open configuration file from known location */
#ifdef WIN32
    LONG		lStatus;
    HKEY		hkSniaHba, hkVendorLib;
    FILETIME		ftLastWriteTime;
    TCHAR		cSubKeyName[256];
    DWORD		i, dwSize, dwType;
    BYTE		byFileName[MAX_PATH];
    HBA_LIBRARY_INFO	*lib_infop;

    if(_hbaapi_librarylist != NULL) {
	/* this is an app programming error */
	return HBA_STATUS_ERROR;
    }

    lStatus = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\SNIA\\HBA",
			   0, KEY_READ, &hkSniaHba);
    if (lStatus != ERROR_SUCCESS) {
	/* ???Opportunity to send error msg, configuration error */
	return HBA_STATUS_ERROR;
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
	    return HBA_STATUS_ERROR; /* you may want to return something
				      * else or keep trying */
	}
	/* The name of the library is contained in a REG_SZ Value
	 * keyed to "LibraryFile" */
	dwSize = MAX_PATH;
	lStatus = RegQueryValueEx(hkVendorLib, "LibraryFile", NULL, &dwType,
				  byFileName, &dwSize);
	if (lStatus != ERROR_SUCCESS) {
	    RegCloseKey(hkVendorLib);
	    /* ???Opportunity to send error msg, installation error */
	    continue;
	}
	lib_infop = (HBA_LIBRARY_INFO *)calloc(1, sizeof(HBA_LIBRARY_INFO));
	if(lib_infop == NULL) {
	    /* what is the right thing to do in MS land??? */
	    RegCloseKey(hkVendorLib);
	    /* ???Opportunity to send error msg, installation error */
	    return(HBA_STATUS_ERROR);
	}
	lib_infop->status = HBA_LIBRARY_NOT_LOADED;
	lib_infop->next = _hbaapi_librarylist;
	lib_infop->index = _hbaapi_total_library_count;
	_hbaapi_total_library_count++;
	_hbaapi_librarylist = lib_infop;

	/* Now I can try to load the library */
	lib_infop->hLibrary = LoadLibrary(byFileName);
	if (lib_infop->hLibrary == NULL){
	    /* printf("unable to load library %s\n", librarypath); */
	    /* ???Opportunity to send error msg, installation error */
	    goto dud_library;
	}
	lib_infop->LibraryPath = strdup(byFileName);
	DEBUG(1, "HBAAPI loading: %s\n", byFileName, 0, 0);

	/* Call the registration function to get the list of pointers */
	RegisterV2Func = (HBARegisterLibraryV2Func)
	    GetProcAddress(lib_infop->hLibrary, "HBA_RegisterLibraryV2");
	if (RegisterV2Func != NULL) {
	    /* Load the function pointers directly into
	     * the table of functions */
	    status = ((RegisterV2Func)(&lib_infop->functionTable));
	    if (status != HBA_STATUS_OK) {
		/* library not loaded */
		/* ???Opportunity to send error msg, library error? */
		goto dud_library;
	    }
	} else {
	    /* Maybe the vendor library is only Rev1 */
	    RegisterFunc = (HBARegisterLibraryFunc)
		GetProcAddress(lib_infop->hLibrary, "HBA_RegisterLibrary");
	    if(RegisterFunc == NULL) {
		/* ???Opportunity to send error msg, library error? */
		goto dud_library;
	    }
	    /* Load the function points directly into
	     * the Rev 2 table of functions */
	    status = ((RegisterFunc)(
		(HBA_ENTRYPOINTS *)(&lib_infop->functionTable)));
	    if (status != HBA_STATUS_OK) {
		/* library not loaded */
		/* ???Opportunity to send error msg, library error? */
		goto dud_library;
	    }
	}

	/* successfully loaded library */
	GetVersionFunc = lib_infop->functionTable.GetVersionHandler;
	if (GetVersionFunc == NULL) {
	    /* ???Opportunity to send error msg, library error? */
	    goto dud_library;
	}
#ifdef NOTDEF /* save for a later time... when it matters */
	/* Check the version of this library before loading */
	/* Actually... This wrapper is compatible with version 1 */
	libversion = ((GetVersionFunc)());
	if (libversion < HBA_LIBVERSION) {
	    goto dud_library;
	}
#endif
	LoadLibraryFunc = lib_infop->functionTable.LoadLibraryHandler;
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

    if(_hbaapi_librarylist != NULL) {
	fprintf(stderr,
		"HBA_LoadLibrary: previously unfreed "
		"libraries exist, call HBA_FreeLibrary().\n");
	return HBA_STATUS_ERROR;
    }

    strcpy(hbaConfFilePath, "/etc/hba.conf");

    if ((hbaconf = fopen(hbaConfFilePath, "r")) == NULL) {
	printf("Cannot open %s\n", hbaConfFilePath);
	return HBA_STATUS_ERROR;
    }

    /* Read in each line and load library */
    while ((hbaconf != NULL) && (fgets(fullline, sizeof(fullline), hbaconf))) {
	/* Skip the comments... */
	if ((fullline[0] == '#') || (fullline[0] == '\n')) {
	    continue;
	}

	/* grab first 'thing' in line (if its there)*/
	if((libraryname = strtok(fullline, " \t\n")) != NULL) {
	    if(strlen(libraryname) >= 64) {
		fprintf(stderr, "Library name(%s) in %s is > 64 characters\n",
			libraryname, hbaConfFilePath);
	    }
	}
	/* grab second 'thing' in line (if its there)*/
	if((librarypath = strtok(NULL, " \t\n")) != NULL) {
	    if(strlen(librarypath) >= 256) {
		fprintf(stderr, "Library path(%s) in %s is > 256 characters\n",
			librarypath, hbaConfFilePath);
	    }
	}

	/* there should be no more 'things' in the line */
	if((charPtr = strtok(NULL, " \n\t")) != NULL) {
	    fprintf(stderr, "Extraneous characters (\"%s\") in %s\n",
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
	if(strcmp(libraryname, "debuglevel") == 0) {
	    _hbaapi_debuglevel = strtol(librarypath, NULL, 10);
	    /* error handling does the right thing automagically */
	    continue;
	}

	lib_infop = (HBA_LIBRARY_INFO *)calloc(1, sizeof(HBA_LIBRARY_INFO));
	if(lib_infop == NULL) {
	    fprintf(stderr, "HBA_LoadLibrary: out of memeory\n");
	    return(HBA_STATUS_ERROR);
	}
	lib_infop->status = HBA_LIBRARY_NOT_LOADED;
	lib_infop->LibraryName = strdup(libraryname);
	lib_infop->LibraryPath = strdup(librarypath);
	lib_infop->index = _hbaapi_total_library_count;
	_hbaapi_total_library_count++;
	lib_infop->next = _hbaapi_librarylist;
	_hbaapi_librarylist = lib_infop;

	/* Load the DLL now */
	if((lib_infop->hLibrary = dlopen(librarypath,RTLD_LAZY)) == NULL) {
	    /*printf("unable to load library %s\n", librarypath); */
	    continue;
	}
	/* Call the registration function to get the list of pointers */
	RegisterV2Func = (HBARegisterLibraryV2Func)
	    dlsym(lib_infop->hLibrary, "HBA_RegisterLibraryV2");
	if (RegisterV2Func != NULL) {
	    /* Load the function points directly into
	     * the table of functions */
	    status = ((RegisterV2Func)(&lib_infop->functionTable));
	    if (status != HBA_STATUS_OK) {
		/* library not loaded */
		continue;
	    }
	} else {
	    /* Maybe the vendor library is only Rev1 */
	    RegisterFunc = (HBARegisterLibraryFunc)
		dlsym(lib_infop->hLibrary, "HBA_RegisterLibrary");
	    if(RegisterFunc == NULL) {
		/* This function is required */
		fprintf(stderr,
			"HBA_LoadLibrary: vendor specific RegisterLibrary "
			"function not found.  lib: %s\n", librarypath);
		DEBUG(0, "HBA_LoadLibrary: vendor specific RegisterLibrary "
		      "function not found.  lib: %s\n", librarypath, 0, 0);
		continue;
	    }
	    /* Load the function points directly into
	     * the table of functions */
	    status = ((RegisterFunc)
		      ((HBA_ENTRYPOINTS *)(&lib_infop->functionTable)));
	    if (status != HBA_STATUS_OK) {
		/* library not loaded */
		fprintf(stderr,
			"HBA_LoadLibrary: vendor specific RegisterLibrary "
			"function encountered an error.  lib: %s\n", librarypath);
		DEBUG(0, "HBA_LoadLibrary: vendor specific RegisterLibrary "
		      "function encountered an error. lib: %s\n", librarypath, 0, 0);
		continue;
	    }
	}

	/* successfully loaded library */
	if((GetVersionFunc = lib_infop->functionTable.GetVersionHandler) 
	   == NULL) {
	    continue;
	}
#ifdef NOTDEF /* save for a later time... when it matters */
	libversion = ((GetVersionFunc)());
	/* Check the version of this library before loading */
	/* Actually... This wrapper is compatible with version 1 */
	if(libversion < HBA_LIBVERSION) {
	    printf("Library version mismatch. Got %d expected %d.\n",
		   libversion, HBA_LIBVERSION);
	    continue;
	}
	DEBUG(1, "%s libversion = %d", librarypath, libversion, 0);
#endif
	LoadLibraryFunc = lib_infop->functionTable.LoadLibraryHandler;
	if (LoadLibraryFunc == NULL) {
	    /* this function is required */
	    fprintf(stderr,
		    "HBA_LoadLibrary: vendor specific LoadLibrary "
		    "function not found.  lib: %s\n", librarypath);
	    DEBUG(0, "HBA_LoadLibrary: vendor specific LoadLibrary "
		    "function not found.  lib: %s\n", librarypath, 0, 0);
	    continue;
	}
	/* Initialize this library */
	if((status = ((LoadLibraryFunc)())) != HBA_STATUS_OK) {
	    /* maybe this should be a printf so that we CANNOT miss it */
	    fprintf(stderr, 
		    "HBA_LoadLibrary: Encounterd and error loading: %s",
		    librarypath);
	    DEBUG(0, "Encounterd and error loading: %s", librarypath, 0, 0);
	    DEBUG(0, "  HBA_STATUS: %d", status, 0, 0);
	    continue;
	}
	/* successfully loaded library */
	lib_infop->status = HBA_LIBRARY_LOADED;
    }

    fclose(hbaconf);
#endif /* WIN32 or UNIX */
#ifdef POSIX_THREADS
    ret = pthread_mutex_init(&_hbaapi_LL_mutex, NULL);
    if(ret == 0) {
	ret = pthread_mutex_init(&_hbaapi_AL_mutex, NULL);
    }
    if(ret == 0) {
	ret = pthread_mutex_init(&_hbaapi_AAE_mutex, NULL);
    }
    if(ret == 0) {
	ret = pthread_mutex_init(&_hbaapi_AE_mutex, NULL);
    }
    if(ret == 0) {
	ret = pthread_mutex_init(&_hbaapi_APE_mutex, NULL);
    }
    if(ret == 0) {
	ret = pthread_mutex_init(&_hbaapi_APSE_mutex, NULL);
    }
    if(ret == 0) {
	ret = pthread_mutex_init(&_hbaapi_TE_mutex, NULL);
    }
    if(ret == 0) {
	ret = pthread_mutex_init(&_hbaapi_LE_mutex, NULL);
    }
    if(ret != 0) {
	perror("pthread_mutec_init - HBA_LoadLibrary");
	return(HBA_STATUS_ERROR);
    }
#elif defined(WIN32)
    InitializeCriticalSection(&_hbaapi_LL_mutex);
    InitializeCriticalSection(&_hbaapi_AL_mutex);
    InitializeCriticalSection(&_hbaapi_AAE_mutex);
    InitializeCriticalSection(&_hbaapi_AE_mutex);
    InitializeCriticalSection(&_hbaapi_APE_mutex);
    InitializeCriticalSection(&_hbaapi_APSE_mutex);
    InitializeCriticalSection(&_hbaapi_TE_mutex);
    InitializeCriticalSection(&_hbaapi_LE_mutex);
#endif


    return HBA_STATUS_OK;
}

HBA_STATUS
HBA_FreeLibrary(void) {
    HBAFreeLibraryFunc	FreeLibraryFunc;
    HBA_LIBRARY_INFO	*lib_infop;
    HBA_LIBRARY_INFO	*lib_next;
    HBA_ADAPTERCALLBACK_ELEM
			***listp;
    HBA_ADAPTER_INFO	*adapt_infop;
    HBA_ADAPTER_INFO	*adapt_next;

    ARE_WE_INITED();
    GRAB_MUTEX(&_hbaapi_LL_mutex);
    GRAB_MUTEX(&_hbaapi_AL_mutex);

    DEBUG(1, "HBA_FreeLibrary()", 0, 0, 0);
    for(lib_infop = _hbaapi_librarylist; lib_infop != NULL; lib_infop = lib_next) {
	lib_next = lib_infop->next;
	if (lib_infop->status == HBA_LIBRARY_LOADED) {
	    FreeLibraryFunc = lib_infop->functionTable.FreeLibraryHandler;
	    if (FreeLibraryFunc != NULL) {
		/* Free this library */
		(void)((FreeLibraryFunc)());
	    }
#ifdef WIN32
	    FreeLibrary(lib_infop->hLibrary);	/* Unload DLL from memory */
#else
	    dlclose(lib_infop->hLibrary);	/* Unload DLL from memory */
#endif
	}
#ifndef WIN32
	free(lib_infop->LibraryName);
#endif
	free(lib_infop->LibraryPath);
	free(lib_infop);

    }
    _hbaapi_librarylist = NULL;
    /* OK, now all functions are disabled except for LoadLibrary,
     * Hope no other thread calls it before we have returned */
    _hbaapi_total_library_count = 0;

    for(adapt_infop = _hbaapi_adapterlist;
	adapt_infop != NULL;
	adapt_infop = adapt_next) {
	adapt_next = adapt_infop->next;
	free(adapt_infop->name);
	free(adapt_infop);
    }
    _hbaapi_adapterlist = NULL;
    _hbaapi_total_adapter_count = 0;

    /* Free up the callbacks, this is not the most efficient, but it works */
    while((volatile HBA_ADAPTERCALLBACK_ELEM *)
	  _hbaapi_adapteraddevents_callback_list
	  != NULL) {
	local_remove_callback((HBA_CALLBACKHANDLE)
			   _hbaapi_adapteraddevents_callback_list);
    }
    for(listp = cb_lists_array; *listp != NULL; listp++) {
	while((volatile HBA_ADAPTERCALLBACK_ELEM ***)**listp != NULL) {
	    local_remove_callback((HBA_CALLBACKHANDLE)**listp);
	}
    }

    RELEASE_MUTEX(&_hbaapi_AL_mutex);
    RELEASE_MUTEX(&_hbaapi_LL_mutex);
    
#ifdef USESYSLOG
    closelog();
#endif
#ifdef USELOGFILE
    if(_hbaapi_debug_fd != NULL) {
	fclose(_hbaapi_debug_fd);
    }
    _hbaapi_debug_fd = NULL;
#endif
#ifdef POSIX_THREADS
    /* this will unlock them as well, but who cares */
    pthread_mutex_destroy(&_hbaapi_LE_mutex);
    pthread_mutex_destroy(&_hbaapi_TE_mutex);
    pthread_mutex_destroy(&_hbaapi_APSE_mutex);
    pthread_mutex_destroy(&_hbaapi_APE_mutex);
    pthread_mutex_destroy(&_hbaapi_AE_mutex);
    pthread_mutex_destroy(&_hbaapi_AAE_mutex);
    pthread_mutex_destroy(&_hbaapi_AL_mutex);
    pthread_mutex_destroy(&_hbaapi_LL_mutex);
#elif defined(WIN32)
    DeleteCriticalSection(&_hbaapi_LL_mutex);
    DeleteCriticalSection(&_hbaapi_AL_mutex);
    DeleteCriticalSection(&_hbaapi_AAE_mutex);
    DeleteCriticalSection(&_hbaapi_AE_mutex);
    DeleteCriticalSection(&_hbaapi_APE_mutex);
    DeleteCriticalSection(&_hbaapi_APSE_mutex);
    DeleteCriticalSection(&_hbaapi_TE_mutex);
    DeleteCriticalSection(&_hbaapi_LE_mutex);
#endif
    
    return HBA_STATUS_OK;
}

/*
 * The API used to use fixed size tables as its primary data structure.
 * Indexing from 1 to N identified each adapters.  Now the adapters are
 * on a linked list.  There is a unique "index" foreach each adapter.
 * Adapters always keep their index, even if they are removed from the
 * hardware.  The only time the indexing is reset is on HBA_FreeLibrary
 */
HBA_UINT32
HBA_GetNumberOfAdapters(void) {
    int j=0;
    HBA_LIBRARY_INFO	*lib_infop;
    HBAGetNumberOfAdaptersFunc
			GetNumberOfAdaptersFunc;
    HBAGetAdapterNameFunc
			GetAdapterNameFunc;
    HBA_BOOLEAN		found_name;
    HBA_ADAPTER_INFO	*adapt_infop;
    HBA_STATUS		status;

    char adaptername[256];
    int num_adapters; /* local */

    if(_hbaapi_librarylist == NULL) {
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
	    lib_infop->functionTable.GetNumberOfAdaptersHandler;
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
	GetAdapterNameFunc = lib_infop->functionTable.GetAdapterNameHandler;
	if(GetAdapterNameFunc == NULL) {
	    continue;
	}

	for (j = 0; j < num_adapters; j++) {
	    found_name = 0;
	    status = (GetAdapterNameFunc)(j, (char *)&adaptername);
	    if(status == HBA_STATUS_OK) {
		for(adapt_infop = _hbaapi_adapterlist;
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

	    adapt_infop = (HBA_ADAPTER_INFO *)
		calloc(1, sizeof(HBA_ADAPTER_INFO));
	    if(adapt_infop == NULL) {
#ifndef WIN32
		fprintf(stderr,
			"HBA_GetNumberOfAdapters: calloc failed on sizeof:%d\n",
			sizeof(HBA_ADAPTER_INFO));
#endif
		RELEASE_MUTEX(&_hbaapi_AL_mutex);
		RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex,
				     _hbaapi_total_adapter_count);
	    }
	    if((adapt_infop->GNstatus = status) == HBA_STATUS_OK) {
		adapt_infop->name = strdup(adaptername);
	    } else {
		char dummyname[512];
		sprintf(dummyname, "NULLADAPTER-%s-%03d", 
			lib_infop->LibraryPath, _hbaapi_total_adapter_count);
		dummyname[255] = '\0';
		adapt_infop->name = strdup(dummyname);
	    }
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
	    return(HBA_STATUS_ERROR_ARG);
    }
    /*
     * The adapter index is from old code, but we have
     * to support it.  Go down the list looking for
     * the adapter
     */
    ARE_WE_INITED();
    GRAB_MUTEX(&_hbaapi_AL_mutex);
    *adaptername = '\0';
    for(adapt_infop = _hbaapi_adapterlist;
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
HBA_OpenAdapter(char* adaptername) {
    HBA_HANDLE		handle;
    HBAOpenAdapterFunc	OpenAdapterFunc;
    HBA_ADAPTER_INFO	*adapt_infop;
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
    for(adapt_infop = _hbaapi_adapterlist;
	adapt_infop != NULL;
	adapt_infop = adapt_infop->next) {
	if (strcmp(adaptername, adapt_infop->name) != 0) {
	    continue;
	}
	lib_infop = adapt_infop->library;
	OpenAdapterFunc =
	    lib_infop->functionTable.OpenAdapterHandler;
	if (OpenAdapterFunc != NULL) {
	    /* retrieve the vendor handle */
	    handle = (OpenAdapterFunc)(adaptername);
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
HBA_OpenAdapterByWWN(HBA_HANDLE *phandle, HBA_WWN nodeWWN) {
    HBA_HANDLE		handle;
    HBA_LIBRARY_INFO	*lib_infop;
    HBAGetNumberOfAdaptersFunc
			GetNumberOfAdaptersFunc;
    HBAOpenAdapterByWWNFunc
			OpenAdapterFunc;
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

	GetNumberOfAdaptersFunc =
	    lib_infop->functionTable.GetNumberOfAdaptersHandler;
	if (GetNumberOfAdaptersFunc == NULL)  {
	    continue;
	}

	/* look for new hardware */
	(void) ((GetNumberOfAdaptersFunc)());
 
	OpenAdapterFunc = lib_infop->functionTable.OpenAdapterByWWNHandler;
	if (OpenAdapterFunc == NULL) {
	    continue;
	}
	/*
	 * We do not know if the WWN is known by this vendor,
	 * just try it
	 */
	if((status = (OpenAdapterFunc)(&handle, nodeWWN)) != HBA_STATUS_OK) {
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
    (void)HBA_GetNumberOfAdapters();
    return;
}

HBA_UINT32
HBA_GetVersion() {
    DEBUG(2, "HBA_GetVersion", 0, 0, 0);
    return HBA_LIBVERSION;
}

/* 
 * This function is VERY OS dependent.  Wing it as best you can.
 */
HBA_UINT32
HBA_GetWrapperLibraryAttributes (
    HBA_LIBRARYATTRIBUTES *attributes)
{

    DEBUG(2, "HBA_GetWrapperLibraryAttributes", 0, 0, 0);

    if (attributes == NULL) {
	    return(HBA_STATUS_ERROR_ARG);
    }

    memset(attributes, 0, sizeof(HBA_LIBRARYATTRIBUTES));

#if defined(SOLARIS)
    if((handle = dlopen("libHBAAPI.so", RTLD_NOW)) != NULL) {
	if(dlinfo(handle, RTLD_DI_LINKMAP, &map) >= 0) {
	    for(mp = map; mp != NULL; mp = mp->l_next) {
		if(strlen(map->l_name) < 256) {
		    strcpy(attributes->LibPath, map->l_lname);
		}
	    }
	}
    }
#elif defined(WIN32)
    {
	HMODULE module;

	/* No need to do anything with the module handle */
	/* It wasn't alloocated so it doesn't need to be freed */
	module = GetModuleHandle("HBAAPI");
	if ( module != NULL ) {
	    if ( GetModuleFileName(module, attributes->LibPath,
				sizeof(attributes->LibPath)) == 0 ) {
	        attributes->LibPath[0] = '\0';
	    }
	}
    }
#endif
#if defined(VENDOR)
    strcpy(attributes->VName, VENDOR);
#else
    attributes->VName[0] = '\0';
#endif
#if defined(VERSION)
    strcpy(attributes->VVersion, VERSION);
#else
    attributes->VVersion[0] = '\0';
#endif
#if defined(BUILD_DATE)
#if defined(WIN32)
    {
	int matchCount;
	matchCount = sscanf(BUILD_DATE, "%u/%u/%u %u:%u:%u",
		&attributes->build_date.tm_year,
		&attributes->build_date.tm_mon,
		&attributes->build_date.tm_mday,
		&attributes->build_date.tm_hour,
		&attributes->build_date.tm_min,
		&attributes->build_date.tm_sec
	);

	if ( matchCount != 6 ) {
	    memset(&attributes->build_date, 0, sizeof(struct tm));
	} else {
	    attributes->build_date.tm_year -= 1900;
	    attributes->build_date.tm_isdst = -1;
	}

    }
#else
    if(strptime(BUILD_DATE, "%Y/%m/%d %T %Z", &(attributes->build_date)) == NULL) {
	memset(&attributes->build_date, 0, sizeof(struct tm));
    }
#endif
#else
    memset(&attributes->build_date, 0, sizeof(struct tm));
#endif
    return 2;
}

/*
 * Callback registation and handling
 */
HBA_STATUS
HBA_RemoveCallback (HBA_CALLBACKHANDLE cbhandle) {
    HBA_STATUS	status;

    DEBUG(2, "HBA_RemoveCallback", 0, 0, 0);
    ARE_WE_INITED();

    GRAB_MUTEX(&_hbaapi_LL_mutex);
    status = local_remove_callback(cbhandle);
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

/* Adapter Add Events *********************************************************/
static void
adapteraddevents_callback (void *data, HBA_WWN PortWWN, HBA_UINT32 eventType) {
    HBA_ALLADAPTERSCALLBACK_ELEM	*cbp;

    DEBUG(3, "AddAdapterEvent, port:%s", WWN2STR1(&PortWWN), 0, 0);

    GRAB_MUTEX(&_hbaapi_AAE_mutex);
    for(cbp = _hbaapi_adapteraddevents_callback_list;
	cbp != NULL;
	cbp = cbp->next) {
	(*cbp->callback)(data, PortWWN, HBA_EVENT_ADAPTER_ADD);
    }
    RELEASE_MUTEX(&_hbaapi_AAE_mutex);

}
HBA_STATUS
HBA_RegisterForAdapterAddEvents (
    void		(*callback) (
	void		*data,
	HBA_WWN		PortWWN,
	HBA_UINT32	eventType
	),
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

    if (callbackHandle == NULL) {
	    return(HBA_STATUS_ERROR_ARG);
    }
    ARE_WE_INITED();

    cbp = (HBA_ALLADAPTERSCALLBACK_ELEM *)
	calloc(1, sizeof(HBA_ALLADAPTERSCALLBACK_ELEM));
    *callbackHandle = (HBA_CALLBACKHANDLE) cbp;
    if(cbp == NULL) {
#ifndef WIN32
	fprintf(stderr,
		"HBA_RegisterForAdapterAddEvents: calloc failed for %d bytes\n",
		sizeof(HBA_ALLADAPTERSCALLBACK_ELEM));
#endif
	return HBA_STATUS_ERROR;
    }

    GRAB_MUTEX(&_hbaapi_LL_mutex);
    GRAB_MUTEX(&_hbaapi_AAE_mutex);
    cbp->callback = callback;
    cbp->next = _hbaapi_adapteraddevents_callback_list;
    _hbaapi_adapteraddevents_callback_list = cbp;
    /* Need to release the mutex now incase the vendor function invokes the
     * callback.  We will grap the mutex later to attach the vendor handle list
     * to the callback structure */
    RELEASE_MUTEX(&_hbaapi_AAE_mutex);
    

    /*
     * now create a list of vendors (vendor libraryies, NOT ADAPTERS) that have
     * successfully registerred
     */
    vendorhandlelist = NULL;
    for(lib_infop = _hbaapi_librarylist;
	lib_infop != NULL;
	lib_infop = lib_infop->next) {

	vendor_cnt++;

	registeredfunc =
	    lib_infop->functionTable.RegisterForAdapterAddEventsHandler;
	if(registeredfunc == NULL) {
	    continue;
	}

	vcbp = (HBA_VENDORCALLBACK_ELEM *)
	    calloc(1, sizeof(HBA_VENDORCALLBACK_ELEM));
	if(vcbp == NULL) {
#ifndef WIN32
	    fprintf(stderr,
		    "HBA_RegisterForAdapterAddEvents: "
		    "calloc failed for %d bytes\n",
		    sizeof(HBA_VENDORCALLBACK_ELEM));
#endif
	    freevendorhandlelist(vendorhandlelist);
	    status = HBA_STATUS_ERROR;
	    break;
	}

	registered_cnt++;
	status = (registeredfunc)(adapteraddevents_callback,
				  userData, &vcbp->vendorcbhandle);
	if(status == HBA_STATUS_ERROR_NOT_SUPPORTED) {
	    not_supported_cnt++;
	    free(vcbp);
	    continue;
	} else if (status != HBA_STATUS_OK) {
	    status_OK_bar_cnt++;
	    DEBUG(0,
		  "HBA_RegisterForAdapterAddEvents: Library->%s, Error->%d",
		  lib_infop->LibraryPath, status, 0);
#ifndef WIN32
	    fprintf(stderr,
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
    if(registered_cnt == 0) {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
	freevendorhandlelist(vendorhandlelist);
	local_remove_callback((HBA_CALLBACKHANDLE) cbp);
    } else if (status_OK_cnt == 0 && not_supported_cnt != 0) {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    } else if (status_OK_cnt == 0) {
	/* At least one vendor library registered this function, but no
	 * vendor call succeeded */
	local_remove_callback((HBA_CALLBACKHANDLE) cbp);
	status = failure;
    } else {
	/* we have had atleast some success, now finish up */
	GRAB_MUTEX(&_hbaapi_AAE_mutex);
	/* this seems silly, but what if another thread called 
	 * the callback remove */
	for(cbp = _hbaapi_adapteraddevents_callback_list;
	    cbp != NULL; cbp = cbp->next) {
	    if((HBA_CALLBACKHANDLE)cbp == *callbackHandle) {
		/* yup, its still there, hooray */
		cbp->vendorhandlelist = vendorhandlelist;
		vendorhandlelist = NULL;
		break;
	    }
	}
	RELEASE_MUTEX(&_hbaapi_AAE_mutex);
	if(vendorhandlelist != NULL) {
	    /* bummer, somebody removed the callback before we finished
	     * registration, probably will never happen */
	    freevendorhandlelist(vendorhandlelist);
	    DEBUG(0, 
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

/* Adapter Events (other than add) ********************************************/
static void
adapterevents_callback (void *data,
			HBA_WWN PortWWN,
			HBA_UINT32 eventType) {
    HBA_ADAPTERCALLBACK_ELEM	*acbp;

    DEBUG(3, "AdapterEvent, port:%s, eventType:%d", WWN2STR1(&PortWWN),
	  eventType, 0);
    
    GRAB_MUTEX(&_hbaapi_AE_mutex);
    for(acbp = _hbaapi_adapterevents_callback_list;
	acbp != NULL;
	acbp = acbp->next) {
	if(data == (void *)acbp) {
	    (*acbp->callback)(acbp->userdata, PortWWN, eventType);
	    break;
	}
    }
    RELEASE_MUTEX(&_hbaapi_AE_mutex);
}
HBA_STATUS
HBA_RegisterForAdapterEvents (
    void		(*callback) (
	void		*data,
	HBA_WWN		PortWWN,
	HBA_UINT32	eventType
	),
    void		*userData,
    HBA_HANDLE		handle,
    HBA_CALLBACKHANDLE	*callbackHandle) {

    HBA_ADAPTERCALLBACK_ELEM		*acbp;
    HBARegisterForAdapterEventsFunc	registeredfunc;
    HBA_STATUS				status;
    HBA_LIBRARY_INFO			*lib_infop;
    HBA_HANDLE				vendorHandle;

    DEBUG(2, "HBA_RegisterForAdapterEvents", 0, 0, 0);

    if (callbackHandle == NULL) {
	    return(HBA_STATUS_ERROR_ARG);
    }

    CHECKLIBRARY();

    /* we now have the _hbaapi_LL_mutex */

    registeredfunc = lib_infop->functionTable.RegisterForAdapterEventsHandler;
    if(registeredfunc == NULL) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_NOT_SUPPORTED);
    }

    /*
     * that allocated memory is used both as the handle for the
     * caller, and as userdata to the vendor call so that on
     * callback the specific registration may be recalled
     */
    acbp = (HBA_ADAPTERCALLBACK_ELEM *) 
	calloc(1, sizeof(HBA_ADAPTERCALLBACK_ELEM));
    if(acbp == NULL) {
#ifndef WIN32
	fprintf(stderr,
		"HBA_RegisterForAdapterEvents: calloc failed for %d bytes\n",
		sizeof(HBA_ADAPTERCALLBACK_ELEM));
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
    if(status != HBA_STATUS_OK) {
	free(acbp);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
    }

    GRAB_MUTEX(&_hbaapi_AE_mutex);
    acbp->next = _hbaapi_adapterevents_callback_list;
    _hbaapi_adapterevents_callback_list = acbp;
    RELEASE_MUTEX(&_hbaapi_AE_mutex);

    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_OK);
}

/* Adapter Port Events ********************************************************/
static void
adapterportevents_callback (void *data,
			    HBA_WWN PortWWN,
			    HBA_UINT32 eventType,
			    HBA_UINT32 fabricPortID) {
    HBA_ADAPTERCALLBACK_ELEM	*acbp;

    DEBUG(3, "AdapterPortEvent, port:%s, eventType:%d fabricPortID:0X%06x",
	  WWN2STR1(&PortWWN), eventType, fabricPortID);
    
    GRAB_MUTEX(&_hbaapi_APE_mutex);

    for(acbp = _hbaapi_adapterportevents_callback_list;
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
HBA_RegisterForAdapterPortEvents (
    void		(*callback) (
	void		*data,
	HBA_WWN		PortWWN,
	HBA_UINT32	eventType,
	HBA_UINT32	fabricPortID
	),
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

    if (callbackHandle == NULL) {
	    return(HBA_STATUS_ERROR_ARG);
    }

    CHECKLIBRARY();
    /* we now have the _hbaapi_LL_mutex */

    registeredfunc = 
	lib_infop->functionTable.RegisterForAdapterPortEventsHandler;
    if(registeredfunc == NULL) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_NOT_SUPPORTED);
    }

    /*
     * that allocated memory is used both as the handle for the
     * caller, and as userdata to the vendor call so that on
     * callback the specific registration may be recalled
     */
    acbp = (HBA_ADAPTERCALLBACK_ELEM *) 
	calloc(1, sizeof(HBA_ADAPTERCALLBACK_ELEM));
    if(acbp == NULL) {
#ifndef WIN32
	fprintf(stderr,
		"HBA_RegisterForAdapterPortEvents: "
		"calloc failed for %d bytes\n",
		sizeof(HBA_ADAPTERCALLBACK_ELEM));
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
    if(status != HBA_STATUS_OK) {
	free(acbp);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
    }

    GRAB_MUTEX(&_hbaapi_APE_mutex);
    acbp->next = _hbaapi_adapterportevents_callback_list;
    _hbaapi_adapterportevents_callback_list = acbp;
    RELEASE_MUTEX(&_hbaapi_APE_mutex);

    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_OK);
}

/* Adapter State Events *******************************************************/
static void
adapterportstatevents_callback (void *data,
				HBA_WWN PortWWN,
				HBA_UINT32 eventType) {
    HBA_ADAPTERCALLBACK_ELEM	*acbp;

    DEBUG(3, "AdapterPortStateEvent, port:%s, eventType:%d", WWN2STR1(&PortWWN),
	  eventType, 0);
    
    GRAB_MUTEX(&_hbaapi_APSE_mutex);
    for(acbp = _hbaapi_adapterportstatevents_callback_list;
	acbp != NULL;
	acbp = acbp->next) {
	if(data == (void *)acbp) {
	    (*acbp->callback)(acbp->userdata, PortWWN, eventType);
	    return;
	}
    }
}
HBA_STATUS
HBA_RegisterForAdapterPortStatEvents (
    void		(*callback) (
	void		*data,
	HBA_WWN		PortWWN,
	HBA_UINT32	eventType
	),
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

    if (callbackHandle == NULL) {
	    return(HBA_STATUS_ERROR_ARG);
    }

    CHECKLIBRARY();
    /* we now have the _hbaapi_LL_mutex */

    registeredfunc =
	lib_infop->functionTable.RegisterForAdapterPortStatEventsHandler;
    if(registeredfunc == NULL) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_NOT_SUPPORTED);
    }

    /*
     * that allocated memory is used both as the handle for the
     * caller, and as userdata to the vendor call so that on
     * callback the specific registration may be recalled
     */
    acbp = (HBA_ADAPTERCALLBACK_ELEM *) 
	calloc(1, sizeof(HBA_ADAPTERCALLBACK_ELEM));
    if(acbp == NULL) {
#ifndef WIN32
	fprintf(stderr,
		"HBA_RegisterForAdapterPortStatEvents: "
		"calloc failed for %d bytes\n",
		sizeof(HBA_ADAPTERCALLBACK_ELEM));
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
    if(status != HBA_STATUS_OK) {
	free(acbp);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
    }

    GRAB_MUTEX(&_hbaapi_APSE_mutex);
    acbp->next = _hbaapi_adapterportstatevents_callback_list;
    _hbaapi_adapterportstatevents_callback_list = acbp;
    RELEASE_MUTEX(&_hbaapi_APSE_mutex);

    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_OK);
}

/* Target Events **************************************************************/
static void
targetevents_callback (void *data,
		       HBA_WWN hbaPortWWN,
		       HBA_WWN discoveredPortWWN,
		       HBA_UINT32 eventType) {
    HBA_ADAPTERCALLBACK_ELEM	*acbp;

    DEBUG(3, "TargetEvent, hbaPort:%s, discoveredPort:%s eventType:%d",
	  WWN2STR1(&hbaPortWWN), WWN2STR2(&discoveredPortWWN), eventType);
    
    GRAB_MUTEX(&_hbaapi_TE_mutex);
    for(acbp = _hbaapi_targetevents_callback_list;
	acbp != NULL;
	acbp = acbp->next) {
	if(data == (void *)acbp) {
	    (*acbp->callback)(acbp->userdata, hbaPortWWN,
			      discoveredPortWWN, eventType);
	    break;
	}
    }
    RELEASE_MUTEX(&_hbaapi_TE_mutex);
}
HBA_STATUS
HBA_RegisterForTargetEvents (
    void		(*callback) (
	void		*data,
	HBA_WWN		hbaPortWWN,
	HBA_WWN		discoveredPortWWN,
	HBA_UINT32	eventType
	),
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

    if (callbackHandle == NULL) {
	    return(HBA_STATUS_ERROR_ARG);
    }

    CHECKLIBRARY();
    /* we now have the _hbaapi_LL_mutex */

    registeredfunc = lib_infop->functionTable.RegisterForTargetEventsHandler;
    if(registeredfunc == NULL) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_NOT_SUPPORTED);
    }

    /*
     * that allocated memory is used both as the handle for the
     * caller, and as userdata to the vendor call so that on
     * callback the specific registration may be recalled
     */
    acbp = (HBA_ADAPTERCALLBACK_ELEM *) 
	calloc(1, sizeof(HBA_ADAPTERCALLBACK_ELEM));
    if(acbp == NULL) {
#ifndef WIN32
	fprintf(stderr,
		"HBA_RegisterForTargetEvents: calloc failed for %d bytes\n",
		sizeof(HBA_ADAPTERCALLBACK_ELEM));
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
    if(status != HBA_STATUS_OK) {
	free(acbp);
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
    }

    GRAB_MUTEX(&_hbaapi_TE_mutex);
    acbp->next = _hbaapi_targetevents_callback_list;
    _hbaapi_targetevents_callback_list = acbp;
    RELEASE_MUTEX(&_hbaapi_TE_mutex);

    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_OK);
}

/* Link Events ****************************************************************/
static void
linkevents_callback (void *data,
		     HBA_WWN adapterWWN,
		     HBA_UINT32 eventType,
		     void *pRLIRBuffer,
		     HBA_UINT32 RLIRBufferSize) {
    HBA_ADAPTERCALLBACK_ELEM	*acbp;

    DEBUG(3, "LinkEvent, hbaWWN:%s, eventType:%d",
	  WWN2STR1(&adapterWWN), eventType, 0);
    
    GRAB_MUTEX(&_hbaapi_LE_mutex);
    for(acbp = _hbaapi_linkevents_callback_list;
	acbp != NULL;
	acbp = acbp->next) {
	if(data == (void *)acbp) {
	    (*acbp->callback)(acbp->userdata, adapterWWN,
			      eventType, pRLIRBuffer, RLIRBufferSize);
	    break;
	}
    }
    RELEASE_MUTEX(&_hbaapi_LE_mutex);
}
HBA_STATUS
HBA_RegisterForLinkEvents (
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

    if (callbackHandle == NULL) {
	    return(HBA_STATUS_ERROR_ARG);
    }

    CHECKLIBRARY();
    /* we now have the _hbaapi_LL_mutex */

    registeredfunc = lib_infop->functionTable.RegisterForLinkEventsHandler;
    if(registeredfunc == NULL) {
	RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, HBA_STATUS_ERROR_NOT_SUPPORTED);
    }

    /*
     * that allocated memory is used both as the handle for the
     * caller, and as userdata to the vendor call so that on
     * callback the specific registration may be recalled
     */
    acbp = (HBA_ADAPTERCALLBACK_ELEM *) 
	calloc(1, sizeof(HBA_ADAPTERCALLBACK_ELEM));
    if(acbp == NULL) {
#ifndef WIN32
	fprintf(stderr,
		"HBA_RegisterForLinkEvents: calloc failed for %d bytes\n",
		sizeof(HBA_ADAPTERCALLBACK_ELEM));
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
    if(status != HBA_STATUS_OK) {
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
	CloseAdapterFunc = lib_infop->functionTable.CloseAdapterHandler;
	if (CloseAdapterFunc != NULL) {
	    ((CloseAdapterFunc)(vendorHandle));
	}
	RELEASE_MUTEX(&_hbaapi_LL_mutex);
    }
}

HBA_STATUS
HBA_GetAdapterAttributes (
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
    GetAdapterAttributesFunc = 
	lib_infop->functionTable.GetAdapterAttributesHandler;
    if (GetAdapterAttributesFunc != NULL) {
	status = ((GetAdapterAttributesFunc)(vendorHandle, hbaattributes));
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetAdapterPortAttributes (
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
    GetAdapterPortAttributesFunc = 
	lib_infop->functionTable.GetAdapterPortAttributesHandler;
    if (GetAdapterPortAttributesFunc != NULL) {
	status = ((GetAdapterPortAttributesFunc)
		  (vendorHandle, portindex, portattributes));
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetPortStatistics (
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
    GetPortStatisticsFunc = 
	lib_infop->functionTable.GetPortStatisticsHandler;
    if (GetPortStatisticsFunc != NULL) {
	status = ((GetPortStatisticsFunc)
		  (vendorHandle, portindex, portstatistics));
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetDiscoveredPortAttributes (
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
    GetDiscoveredPortAttributesFunc = 
	lib_infop->functionTable.GetDiscoveredPortAttributesHandler;
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
HBA_GetPortAttributesByWWN (
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
    GetPortAttributesByWWNFunc = 
	lib_infop->functionTable.GetPortAttributesByWWNHandler;
    if (GetPortAttributesByWWNFunc != NULL) {
	status = ((GetPortAttributesByWWNFunc)
		  (vendorHandle, PortWWN, portattributes));
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SendCTPassThru (
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
    SendCTPassThruFunc = lib_infop->functionTable.SendCTPassThruHandler;
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
HBA_SendCTPassThruV2 (
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

    DEBUG(2, "HBA_SendCTPassThruV2m hbaPortWWN: %s", WWN2STR1(&hbaPortWWN), 0, 0);

    CHECKLIBRARY();
    registeredfunc = lib_infop->functionTable.SendCTPassThruV2Handler;
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
HBA_GetEventBuffer (
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
    GetEventBufferFunc = lib_infop->functionTable.GetEventBufferHandler;
    if (GetEventBufferFunc != NULL) {
	status = (GetEventBufferFunc)
	    (vendorHandle, EventBuffer, EventBufferCount);
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SetRNIDMgmtInfo (HBA_HANDLE handle, HBA_MGMTINFO Info) {
    HBA_STATUS		status;
    HBA_LIBRARY_INFO	*lib_infop;
    HBA_HANDLE		vendorHandle;
    HBASetRNIDMgmtInfoFunc
			SetRNIDMgmtInfoFunc;

    DEBUG(2, "HBA_SetRNIDMgmtInfo", 0, 0, 0);

    CHECKLIBRARY();
    SetRNIDMgmtInfoFunc = lib_infop->functionTable.SetRNIDMgmtInfoHandler;
    if (SetRNIDMgmtInfoFunc != NULL) {
	status = (SetRNIDMgmtInfoFunc)(vendorHandle, Info);
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetRNIDMgmtInfo (HBA_HANDLE handle, HBA_MGMTINFO *pInfo) {
    HBA_STATUS		status;
    HBA_LIBRARY_INFO	*lib_infop;
    HBA_HANDLE		vendorHandle;
    HBAGetRNIDMgmtInfoFunc
			 GetRNIDMgmtInfoFunc;

    DEBUG(2, "HBA_GetRNIDMgmtInfo", 0, 0, 0);

    CHECKLIBRARY();
    GetRNIDMgmtInfoFunc = lib_infop->functionTable.GetRNIDMgmtInfoHandler;
    if (GetRNIDMgmtInfoFunc != NULL) {
	status = (GetRNIDMgmtInfoFunc)(vendorHandle, pInfo);
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SendRNID (
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
    SendRNIDFunc = lib_infop->functionTable.SendRNIDHandler;
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
    registeredfunc = lib_infop->functionTable.SendRNIDV2Handler;
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
HBA_RefreshInformation (HBA_HANDLE handle) {
    HBA_STATUS		status;
    HBA_LIBRARY_INFO	*lib_infop;
    HBA_HANDLE		vendorHandle;
    HBARefreshInformationFunc
			RefreshInformationFunc;

    DEBUG(2, "HBA_RefreshInformation", 0, 0, 0);

    status = HBA_CheckLibrary(handle, &lib_infop, &vendorHandle);
    if(status == HBA_STATUS_OK) {
	RefreshInformationFunc = 
	    lib_infop->functionTable.RefreshInformationHandler;
	if (RefreshInformationFunc != NULL) {
	    ((RefreshInformationFunc)(vendorHandle));
	}
	RELEASE_MUTEX(&_hbaapi_LL_mutex);
    }
}

void
HBA_ResetStatistics (HBA_HANDLE handle, HBA_UINT32 portindex) {
    HBA_STATUS		status;
    HBA_LIBRARY_INFO	*lib_infop;
    HBA_HANDLE		vendorHandle;
    HBAResetStatisticsFunc
			ResetStatisticsFunc;

    DEBUG(2, "HBA_ResetStatistics", 0, 0, 0);

    status = HBA_CheckLibrary(handle, &lib_infop, &vendorHandle);
    if(status == HBA_STATUS_OK) {
	ResetStatisticsFunc = lib_infop->functionTable.ResetStatisticsHandler;
	if (ResetStatisticsFunc != NULL) {
	    ((ResetStatisticsFunc)(vendorHandle, portindex));
	}
	RELEASE_MUTEX(&_hbaapi_LL_mutex);
    }
}

HBA_STATUS
HBA_GetFcpTargetMapping (HBA_HANDLE handle, PHBA_FCPTARGETMAPPING mapping) {
    HBA_STATUS		status;
    HBA_LIBRARY_INFO	*lib_infop;
    HBA_HANDLE		vendorHandle;
    HBAGetFcpTargetMappingFunc GetFcpTargetMappingFunc;

    DEBUG(2, "HBA_GetFcpTargetMapping", 0, 0, 0);

    CHECKLIBRARY();
    GetFcpTargetMappingFunc =
	lib_infop->functionTable.GetFcpTargetMappingHandler;
    if (GetFcpTargetMappingFunc != NULL) {
	status = ((GetFcpTargetMappingFunc)(vendorHandle, mapping));
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetFcpTargetMappingV2 (
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_FCPTARGETMAPPINGV2
    			*pmapping)
{
    HBA_STATUS		status;
    HBA_LIBRARY_INFO	*lib_infop;
    HBA_HANDLE		vendorHandle;
    HBAGetFcpTargetMappingV2Func
			registeredfunc;

    DEBUG(2, "HBA_GetFcpTargetMapping", 0, 0, 0);

    CHECKLIBRARY();
    registeredfunc = 
	lib_infop->functionTable.GetFcpTargetMappingV2Handler;
    if (registeredfunc != NULL) {
	status = ((registeredfunc)(vendorHandle, hbaPortWWN, pmapping));
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetFcpPersistentBinding (HBA_HANDLE handle, PHBA_FCPBINDING binding) {
    HBA_STATUS		status;
    HBA_LIBRARY_INFO	*lib_infop;
    HBA_HANDLE		vendorHandle;
    HBAGetFcpPersistentBindingFunc
			GetFcpPersistentBindingFunc;

    DEBUG(2, "HBA_GetFcpPersistentBinding", 0, 0, 0);

    CHECKLIBRARY();
    GetFcpPersistentBindingFunc =
	lib_infop->functionTable.GetFcpPersistentBindingHandler;
    if (GetFcpPersistentBindingFunc != NULL) {
	status = ((GetFcpPersistentBindingFunc)(vendorHandle, binding));
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_ScsiInquiryV2 (
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

    CHECKLIBRARY();
    ScsiInquiryV2Func =
	lib_infop->functionTable.ScsiInquiryV2Handler;
    if (ScsiInquiryV2Func != NULL) {
	status =((ScsiInquiryV2Func)(
	    vendorHandle, hbaPortWWN, discoveredPortWWN, fcLUN, CDB_Byte1,
	    CDB_Byte2, pRspBuffer, pRspBufferSize, pScsiStatus,
	    pSenseBuffer, pSenseBufferSize));
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SendScsiInquiry (
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

    DEBUG(2, "HBA_SendScsiInquiry to PortWWN: %s", WWN2STR1(&PortWWN), 0, 0);

    CHECKLIBRARY();
    SendScsiInquiryFunc = lib_infop->functionTable.ScsiInquiryHandler;
    if (SendScsiInquiryFunc != NULL) {
	status =((SendScsiInquiryFunc)(
	    vendorHandle, PortWWN, fcLUN, EVPD, PageCode, pRspBuffer,
	    RspBufferSize, pSenseBuffer, SenseBufferSize));
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_ScsiReportLUNsV2 (
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

    CHECKLIBRARY();
    ScsiReportLUNsV2Func = lib_infop->functionTable.ScsiReportLUNsV2Handler;
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
HBA_SendReportLUNs (
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
    SendReportLUNsFunc = lib_infop->functionTable.ReportLUNsHandler;
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
HBA_ScsiReadCapacityV2 (
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

    CHECKLIBRARY();
    ScsiReadCapacityV2Func =
	lib_infop->functionTable.ScsiReadCapacityV2Handler;
    if (ScsiReadCapacityV2Func != NULL) {
	status =((ScsiReadCapacityV2Func)(
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
HBA_SendReadCapacity (
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

    DEBUG(2, "HBA_SendReadCapacity to portWWN: %s", WWN2STR1(&portWWN), 0, 0);

    CHECKLIBRARY();
    SendReadCapacityFunc = lib_infop->functionTable.ReadCapacityHandler;
    if (SendReadCapacityFunc != NULL) {
	status =((SendReadCapacityFunc)
		 (vendorHandle, portWWN, fcLUN, pRspBuffer,
		  RspBufferSize, pSenseBuffer, SenseBufferSize));
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SendRLS (
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

    DEBUG(2, "HBA_SendRLS to agent_wwn: %s:%d",
	  WWN2STR1(&agent_wwn), agent_domain, 0);

    CHECKLIBRARY();
    registeredfunc = lib_infop->functionTable.SendRLSHandler;
    if (registeredfunc != NULL) {
	status =(registeredfunc)(
	    vendorHandle, hbaPortWWN, destWWN, pRspBuffer, pRspBufferSize);
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SendRPL (
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
    registeredfunc = lib_infop->functionTable.SendRPLHandler;
    if (registeredfunc != NULL) {
	status =(registeredfunc)(
	    vendorHandle, hbaPortWWN, agent_wwn, agent_domain, portindex,
	    pRspBuffer, pRspBufferSize);
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SendRPS (
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
    registeredfunc = lib_infop->functionTable.SendRPSHandler;
    if (registeredfunc != NULL) {
	status =(registeredfunc)(
	    vendorHandle, hbaPortWWN, agent_wwn, agent_domain,
	    object_wwn, object_port_number,
	    pRspBuffer, pRspBufferSize);
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SendSRL (
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
    registeredfunc = lib_infop->functionTable.SendSRLHandler;
    if (registeredfunc != NULL) {
	status =(registeredfunc)(
	    vendorHandle, hbaPortWWN, wwn, domain,
	    pRspBuffer, pRspBufferSize);
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SendLIRR (
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
    registeredfunc = lib_infop->functionTable.SendLIRRHandler;
    if (registeredfunc != NULL) {
	status =(registeredfunc)(
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

    CHECKLIBRARY();
    registeredfunc = lib_infop->functionTable.GetBindingCapabilityHandler;
    if (registeredfunc != NULL) {
	status =(registeredfunc)(vendorHandle, hbaPortWWN, pcapability);
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetBindingSupport (
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

    CHECKLIBRARY();
    registeredfunc = lib_infop->functionTable.GetBindingSupportHandler;
    if (registeredfunc != NULL) {
	status =(registeredfunc)(vendorHandle, hbaPortWWN, pcapability);
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

    CHECKLIBRARY();
    registeredfunc = lib_infop->functionTable.SetBindingSupportHandler;
    if (registeredfunc != NULL) {
	status =(registeredfunc)(vendorHandle, hbaPortWWN, capability);
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_SetPersistentBindingV2 (
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    const HBA_FCPBINDING2
    			*pbinding)
{
    HBA_STATUS		status;
    HBA_LIBRARY_INFO	*lib_infop;
    HBA_HANDLE		vendorHandle;
    HBASetPersistentBindingV2Func
			registeredfunc;

    DEBUG(2, "HBA_SetPersistentBindingV2 port: %s", WWN2STR1(&hbaPortWWN), 0, 0);

    CHECKLIBRARY();
    registeredfunc = lib_infop->functionTable.SetPersistentBindingV2Handler;
    if (registeredfunc != NULL) {
	status =(registeredfunc)(vendorHandle, hbaPortWWN, pbinding);
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetPersistentBindingV2 (
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN,
    HBA_FCPBINDING2	*pbinding)
{
    HBA_STATUS		status;
    HBA_LIBRARY_INFO	*lib_infop;
    HBA_HANDLE		vendorHandle;
    HBAGetPersistentBindingV2Func
			registeredfunc;

    DEBUG(2, "HBA_GetPersistentBindingV2 port: %s", WWN2STR1(&hbaPortWWN), 0, 0);

    CHECKLIBRARY();
    registeredfunc = lib_infop->functionTable.GetPersistentBindingV2Handler;
    if (registeredfunc != NULL) {
	status =(registeredfunc)(vendorHandle, hbaPortWWN, pbinding);
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_RemovePersistentBinding (
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

    CHECKLIBRARY();
    registeredfunc = 
	lib_infop->functionTable.RemovePersistentBindingHandler;
    if (registeredfunc != NULL) {
	status =(registeredfunc)(vendorHandle, hbaPortWWN, pbinding);
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_RemoveAllPersistentBindings (
    HBA_HANDLE		handle,
    HBA_WWN		hbaPortWWN)
{
    HBA_STATUS		status;
    HBA_LIBRARY_INFO	*lib_infop;
    HBA_HANDLE		vendorHandle;
    HBARemoveAllPersistentBindingsFunc
			registeredfunc;

    DEBUG(2, "HBA_RemoveAllPersistentBindings", 0, 0, 0);

    CHECKLIBRARY();
    registeredfunc = 
	lib_infop->functionTable.RemoveAllPersistentBindingsHandler;
    if (registeredfunc != NULL) {
	status =(registeredfunc)(vendorHandle, hbaPortWWN);
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetFC4Statistics (
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

    CHECKLIBRARY();
    registeredfunc = 
	lib_infop->functionTable.GetFC4StatisticsHandler;
    if (registeredfunc != NULL) {
	status =(registeredfunc)
	    (vendorHandle, portWWN, FC4type, pstatistics);
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_STATUS
HBA_GetFCPStatistics (
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

    CHECKLIBRARY();
    registeredfunc = 
	lib_infop->functionTable.GetFCPStatisticsHandler;
    if (registeredfunc != NULL) {
	status =(registeredfunc)(vendorHandle, lunit, pstatistics);
    } else {
	status = HBA_STATUS_ERROR_NOT_SUPPORTED;
    }
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, status);
}

HBA_UINT32
HBA_GetVendorLibraryAttributes (
    HBA_UINT32 adapter_index,
    HBA_LIBRARYATTRIBUTES *attributes)
{
    HBA_ADAPTER_INFO	*adapt_infop;
    HBAGetVendorLibraryAttributesFunc
			registeredfunc;
    HBA_UINT32		ret = 0;

    DEBUG(2, "HBA_GetVendorLibraryAttributes adapterindex:%d",
	  adapter_index, 0, 0);
    if(_hbaapi_librarylist == NULL) {
	DEBUG(1, "HBAAPI not loaded yet.", 0, 0, 0);
	return(0);
    }

    if (attributes == NULL) {
	    return(HBA_STATUS_ERROR_ARG);
    }

    memset(attributes, 0, sizeof(HBA_LIBRARYATTRIBUTES));

    GRAB_MUTEX(&_hbaapi_LL_mutex);
    GRAB_MUTEX(&_hbaapi_AL_mutex);
    for(adapt_infop = _hbaapi_adapterlist;
	adapt_infop != NULL;
	adapt_infop = adapt_infop->next) {

	if(adapt_infop->index == adapter_index) {
	    registeredfunc = adapt_infop->library->
		functionTable.GetVendorLibraryAttributesHandler;
	    if(registeredfunc != NULL) {
		ret = (registeredfunc)(attributes);
	    } else {
		/* Version 1 libary? */
		HBAGetVersionFunc	GetVersionFunc;
		GetVersionFunc = adapt_infop->library->
		    functionTable.GetVersionHandler;
		if(GetVersionFunc != NULL) {
		    ret = ((GetVersionFunc)());
		}
#ifdef NOTDEF
		else {
		    /* This should not happen, dont think its going to */
		}
#endif
	    }
	    if (attributes->LibPath[0] == '\0') {
		if(strlen(adapt_infop->library->LibraryPath) < 256) {
		    strcpy(attributes->LibPath, 
			   adapt_infop->library->LibraryPath);
		}
	    }
	    break;
	}
    }
    RELEASE_MUTEX(&_hbaapi_AL_mutex);
    RELEASE_MUTEX_RETURN(&_hbaapi_LL_mutex, ret);
}
