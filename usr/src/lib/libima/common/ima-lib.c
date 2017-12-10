/*
 * Description
 * ImaLib.c - Implements a sample common IMA library
 *
 * License:
 * The contents of this file are subject to the SNIA Public License
 * Version 1.0(the "License"); you may not use this file except in
 *  compliance with the License. You may obtain a copy of the License at
 *
 * /http://www.snia.org/English/Resources/Code/OpenSource.html
 *
 *  Software distributed under the License is distributed on an "AS IS"
 *  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 *  the License for the specific language governing rights and limitations
 *  under the License.
 *
 * The Original Code is  SNIA HBA API and IMA general header file
 *
 * The Initial Developer of the Original Code is:
 * Benjamin F. Kuo, Troika Networks, Inc. (benk@troikanetworks.com)
 * David Dillard       VERITAS Software        david.dillard@veritas.com
 *
 * Contributor(s):
 * Jeff Ding, Adaptec, Inc. (jding@corp.adaptec.com)
 *
 *   Changes:
 *  09/24/2003 Initial Draft
 *  (for other changes... see the CVS logs)
 *
 *  12/15/2003 corrected the defined parameter in IMA_SetPhbaIsnsDiscovery().
 *  lower case the computer name as iscsi name in IMA_GenerateNodeName().
 *
 *  01/21/2005 Updated to support IMA 1.1.3.
 */

#ifdef WIN32
#include <windows.h>
#else
#include <sys/sem.h>
#include <dlfcn.h>
#include <stdarg.h>
#endif

#include <string.h>
#include <strings.h>
#include <stdlib.h>
// #include <sys/sem.h>
#include <unistd.h>
#include <time.h>
#include <stdio.h>
#include <sys/types.h>
// #include <sys/ipc.h>
#include <netdb.h>

#include "libsun_ima.h"
#include "ima.h"
#include "ima-plugin.h"


#define	LIBRARY_PROPERTY_SUPPORTED_IMA_VERSION 1
#define	LIBRARY_PROPERTY_IMPLEMENTATION_VERSION L"1.0.2"
#define	LIBRARY_PROPERTY_VENDOR L"QLogic, Inc."
#define	DEFAULT_NODE_NAME_FORMAT "iqn.1986-03.com.sun.central.%s"

/* Linux only */
#define	LIBRARY_FILE_NAME L"libima.so"

#define	EUOS_ERROR IMA_ERROR_UNEXPECTED_OS_ERROR

IMA_PLUGIN_INFO  plugintable[IMA_MAX_NUM_PLUGINS];
int number_of_plugins = -1;
static IMA_NODE_NAME    sharedNodeName;
static IMA_NODE_ALIAS   sharedNodeAlias;

#ifdef WIN32
static HANDLE libMutex = NULL;
#else
int libMutex = -1;
#endif

void InitLibrary();
void ExitLibrary();

static void libSwprintf(wchar_t *wcs, const wchar_t *lpszFormat, ...) {
	va_list args;
	va_start(args, lpszFormat);

#ifdef WIN32
	vswprintf(wcs, lpszFormat, args);
#else
	vswprintf(wcs, 255, lpszFormat, args);
#endif
	va_end(args);
}


#ifdef WIN32
/* Begin implementation */
BOOL APIENTRY DllMain(HANDLE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved) {
	switch (ul_reason_for_call) {

	case DLL_PROCESS_ATTACH:
		// InitLibrary();
		break;
	case DLL_PROCESS_DETACH:
		ExitLibrary();
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return (TRUE);
}
#elif defined(SOLARIS)

void so_init(void);
void so_fini(void);
static int os_createmutex(int *semid);
static void os_obtainmutex(int semid);
static void os_releasemutex(int semid);
static void os_destroymutex(int semid);
static IMA_STATUS getSolarisNodeProps(IMA_NODE_PROPERTIES *nodeProps);
static IMA_STATUS getSolarisSharedNodeName(IMA_NODE_NAME name);
static IMA_STATUS getSolarisSharedNodeAlias(IMA_NODE_ALIAS alias);
static IMA_STATUS setSolarisSharedNodeName(const IMA_NODE_NAME name);
static IMA_STATUS setSolarisSharedNodeAlias(const IMA_NODE_ALIAS alias);

#pragma init(so_init)
#pragma fini(so_fini)

void so_init() {
	InitLibrary();
}
void so_fini() {
	ExitLibrary();
}

static IMA_STATUS getSolarisNodeProps(IMA_NODE_PROPERTIES *nodeProps) {
	int ret;
	int i;
	IMA_STATUS status = IMA_ERROR_UNKNOWN_ERROR;
	IMA_GetNodePropertiesFn PassFunc;
	IMA_OID nodeOid;

	if (number_of_plugins == -1)
		InitLibrary();

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (strstr(plugintable[i].PluginPath,
		    "libsun_ima.so") == NULL) {
			continue;
		}
		status = IMA_ERROR_UNEXPECTED_OS_ERROR;
		if (plugintable[i].hPlugin != NULL) {
			os_obtainmutex(plugintable[i].pluginMutex);
			PassFunc =
			    (IMA_GetNodePropertiesFn) dlsym(
			    plugintable[i].hPlugin,
			    "IMA_GetNodeProperties");
			if (PassFunc != NULL) {
				status = PassFunc(nodeOid, nodeProps);
			}
			os_releasemutex(plugintable[i].pluginMutex);
		}
		break;
	}

	os_releasemutex(libMutex);
	return (status);
}

static IMA_STATUS getSolarisSharedNodeName(IMA_NODE_NAME name) {
	IMA_STATUS status = IMA_ERROR_UNKNOWN_ERROR;
	IMA_NODE_PROPERTIES nodeProps;

	status = getSolarisNodeProps(&nodeProps);
	if (status != IMA_STATUS_SUCCESS) {
		return (status);
	}
	bcopy(&nodeProps.name, name, sizeof (IMA_NODE_NAME));
	return (status);
}

static IMA_STATUS getSolarisSharedNodeAlias(IMA_NODE_ALIAS alias) {
	IMA_STATUS status = IMA_ERROR_UNKNOWN_ERROR;
	IMA_NODE_PROPERTIES nodeProps;

	status = getSolarisNodeProps(&nodeProps);
	if (status != IMA_STATUS_SUCCESS) {
		return (status);
	}
	bcopy(&nodeProps.alias, alias, sizeof (IMA_NODE_ALIAS));
	return (status);
}

static IMA_STATUS setSolarisSharedNodeName(const IMA_NODE_NAME name) {
	int ret;
	int i;
	IMA_STATUS status = IMA_ERROR_UNKNOWN_ERROR;
	IMA_NODE_PROPERTIES nodeProps;
	IMA_SetNodeNameFn PassFunc;
	IMA_OID nodeOid;

	if (number_of_plugins == -1)
		InitLibrary();

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (strstr(plugintable[i].PluginPath,
		    "libsun_ima.so") == NULL) {
			continue;
		}
		status = IMA_ERROR_UNEXPECTED_OS_ERROR;
		if (plugintable[i].hPlugin != NULL) {
			os_obtainmutex(plugintable[i].pluginMutex);
			PassFunc =
			    (IMA_SetNodeNameFn) dlsym(plugintable[i].hPlugin,
			    "IMA_SetNodeName");
			if (PassFunc != NULL) {
				status = PassFunc(nodeOid, name);
			}
			os_releasemutex(plugintable[i].pluginMutex);
		}
		break;
	}

	os_releasemutex(libMutex);
	return (status);
}

static IMA_STATUS setSolarisSharedNodeAlias(const IMA_NODE_ALIAS alias) {
	int ret;
	int i;
	IMA_STATUS status = IMA_ERROR_UNKNOWN_ERROR;
	IMA_NODE_PROPERTIES nodeProps;
	IMA_SetNodeAliasFn PassFunc;
	IMA_OID nodeOid;

	if (number_of_plugins == -1)
		InitLibrary();

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (strstr(plugintable[i].PluginPath,
		    "libsun_ima.so") == NULL) {
			continue;
		}
		status = IMA_ERROR_UNEXPECTED_OS_ERROR;
		if (plugintable[i].hPlugin != NULL) {
			os_obtainmutex(plugintable[i].pluginMutex);
			PassFunc =
			    (IMA_SetNodeAliasFn) dlsym(plugintable[i].hPlugin,
			    "IMA_SetNodeAlias");
			if (PassFunc != NULL) {
				status = PassFunc(nodeOid, alias);
			}
			os_releasemutex(plugintable[i].pluginMutex);
		}
		break;
	}

	os_releasemutex(libMutex);
	return (status);
}

#else
/*
 * add code in .init and .fini,
 * "__attribute__ ((constructor))" and "__attribute__ ((destructor))"
 * are used with gcc
 */
__attribute__((constructor)) void init()
{
	InitLibrary();
}

__attribute__((destructor)) void fini()
{
	ExitLibrary();
}

#endif


#ifdef WIN32

static BOOL os_createmutex(HANDLE Mutex) {
	Mutex = CreateMutex(NULL, FALSE, NULL);

	if (Mutex == NULL) {
		return (FALSE);
	}

	return (TRUE);
}

static void os_destroymutex(HANDLE Mutex) {
	if (Mutex != NULL) {
		CloseHandle(Mutex);
	}
}


static void os_obtainmutex(HANDLE Mutex) {
	WaitForSingleObject(Mutex, INFINITE);
}

static void os_releasemutex(HANDLE Mutex) {
	ReleaseMutex(Mutex);
}

#else
#if defined(__GNU_LIBRARY__) && !defined(_SEM_SEMUN_UNDEFINED)
/* <sys/sem.h> */
#else
union semun {
	int val; /* value for SETVAL */
	struct semid_ds *bf; /* buffer for IPC_STAT, IPC_SET */
	unsigned short int *array; /* array for GETALL, SETALL */
	struct seminfo *__buf; /* buffer for IPC_INFO */
};
#endif

/* Create the semaphore.  Return 1 if successful, 0 otherwise */
static int os_createmutex(int *semid) {
	int retVal;
	union semun sem_union;

	if (semid == NULL) {
		return (0);
	}

	retVal = semget(IPC_PRIVATE, 1, IPC_CREAT);
	if (retVal == -1) {
		return (0);
	}

	*semid = retVal; /* save key of created semaphore */
	sem_union.val = 1; /* start semaphore off signaled */
	retVal = semctl(*semid, 0, SETVAL, sem_union);
	if (retVal == -1) {
		return (0);
	}

	return (1);
}

static void
os_obtainmutex(int semid)
{
	struct sembuf sem_b;

	sem_b.sem_num = 0;
	sem_b.sem_op = -1;
	sem_b.sem_flg = SEM_UNDO;
	(void) semop(semid, &sem_b, 1);
}

static void
os_releasemutex(int semid)
{
	struct sembuf sem_b;

	sem_b.sem_num = 0;
	sem_b.sem_op = 1;
	sem_b.sem_flg = SEM_UNDO;
	(void) semop(semid, &sem_b, 1);
}

/* Destroy the SNMP semaphore. */
static void
os_destroymutex(int semid)
{
	union semun sem_union;

	(void) semctl(semid, 0, IPC_RMID, sem_union);
}
#endif


void InitLibrary() {

	FILE *imaconf;
	char fullline[512]; /* Full line read in from IMA.conf */
	char pluginname[64]; /* Read in from file IMA.conf */
	char pluginpath[256]; /* Read in from file IMA.conf */
	char imaConfFilePath[256];
	char systemPath[256];
	char *charPtr;
	IMA_UINT i = 0;

	if (number_of_plugins != -1)
		return;

	number_of_plugins = 0;

	if (os_createmutex(&libMutex) == 0) {
		return;
	}
	os_obtainmutex(libMutex);

	sharedNodeAlias[0] = 0;

	/* Open configuration file from known location */
#ifdef WIN32
	if (GetSystemDirectory(systemPath, sizeof (systemPath)))
		sprintf(imaConfFilePath, "%s\\drivers\\etc\\ima.conf",
		    systemPath);
	else
		strcpy(imaConfFilePath, "ima.conf");
#else
	strcpy(imaConfFilePath, "/etc/ima.conf");
#endif

	if ((imaconf = fopen(imaConfFilePath, "r")) == NULL) {
		os_releasemutex(libMutex);
		return;
	}
	/* Read in each line and load library */
	while ((imaconf != NULL) &&
	    (fgets(fullline, sizeof (fullline), imaconf))) {
		if ((fullline[0] != '#') && (fullline[0] != '\n')) {
			/* Take out the '\n' */
			if ((charPtr = (char *)strchr(fullline, '\n')) != NULL)
				*charPtr = '\0';

			/* look for the first tab */
			if ((charPtr = (char *)strchr(fullline, '\t')) == NULL)
				charPtr = (char *)strchr(fullline, ' ');

			/* Set Null termination for library name if found */
			if (charPtr != NULL) {
				*charPtr++ = '\0';
				/*
				 * Skip spaces and tabs until
				 * the next character found
				 */
				while ((*charPtr == ' ') || (*charPtr == '\t'))
					charPtr++;
			}
			else
				continue; /* May be invalid entry */

			/* Copy library name and path */
			strcpy(pluginname, fullline);
			strcpy(pluginpath, charPtr);

			/*
			 * Continue to the next line if library name or
			 * path is invalid
			 */
			if ((strlen(pluginname) == 0) ||
			    (strlen(pluginpath) == 0))
				continue;

#ifdef WIN32
			/* Load the DLL now */
			plugintable[i].hPlugin = LoadLibrary(pluginpath);
#else
			/* Load the DLL now */
			plugintable[i].hPlugin = dlopen(pluginpath, RTLD_LAZY);
#endif
			if (plugintable[i].hPlugin != NULL) {
				typedef int (*InitializeFn)();
				InitializeFn PassFunc;

				memcpy((char *)&plugintable[i].PluginName,
				    (char *)&pluginname, 64);
				memcpy((char *)
				    &plugintable[i].PluginPath,
				    (char *)&pluginpath, 256);
				plugintable[i].ownerId = i + 1;

#ifdef WIN32
				PassFunc = (InitializeFn)
				    GetProcAddress(
				    plugintable[i].hPlugin, "Initialize");
#else
				PassFunc = (InitializeFn)
				    dlsym(
				    plugintable[i].hPlugin, "Initialize");
#endif
				if (PassFunc != NULL) {
					(void) PassFunc(plugintable[i].ownerId);
				}

				plugintable[i].number_of_vbcallbacks = 0;
				plugintable[i].number_of_pccallbacks = 0;
				os_createmutex(&(plugintable[i].pluginMutex));
				i++;
			}
		}
	}
	number_of_plugins = i;
	os_releasemutex(libMutex);
}


void ExitLibrary() {
	IMA_UINT j;
	IMA_UINT i;

	if (number_of_plugins == -1)
		return;

	os_obtainmutex(libMutex);
	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].hPlugin != NULL) {
			TerminateFn ExitPassFunc;

			os_obtainmutex(plugintable[i].pluginMutex);
			for (j = 0; j < plugintable[i].number_of_vbcallbacks;
			    j++) {
#define	IMA_DFOBC_STR "IMA_DeregisterForObjectVisibilityChangesFn"
				IMA_DeregisterForObjectVisibilityChangesFn
				    PassFunc;
#ifdef WIN32
				PassFunc =
				    (IMA_DeregisterForObjectVisibilityChangesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    IMA_DFOBC_STR);
#else
				PassFunc =
				    (IMA_DeregisterForObjectVisibilityChangesFn)
				    dlsym(plugintable[i].hPlugin,
				    IMA_DFOBC_STR);
#endif
				if (PassFunc != NULL) {
					PassFunc(plugintable[i].vbcallback[j]);
				}
#undef IMA_DFOBC_STR
			}
			plugintable[i].number_of_vbcallbacks = 0;

			for (j = 0; j < plugintable[i].number_of_pccallbacks;
			    j++) {
				IMA_DeregisterForObjectPropertyChangesFn
				    PassFunc;
#ifdef WIN32
				PassFunc =
				    (IMA_DeregisterForObjectPropertyChangesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_DeregisterForObjectPropertyChangesFn");
#else
				PassFunc =
				    (IMA_DeregisterForObjectPropertyChangesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_DeregisterForObjectPropertyChangesFn");
#endif
				if (PassFunc != NULL) {
					PassFunc(plugintable[i].pccallback[j]);
				}
			}
			plugintable[i].number_of_pccallbacks = 0;

#ifdef WIN32
			ExitPassFunc =
			    (TerminateFn) GetProcAddress
			    (plugintable[i].hPlugin, "Terminate");
#else
			ExitPassFunc = (TerminateFn)
			    dlsym(plugintable[i].hPlugin, "Terminate");
#endif
			if (ExitPassFunc != NULL) {
				ExitPassFunc();
			}
#ifdef WIN32
			/* Unload DLL from memory */
			FreeLibrary(plugintable[i].hPlugin);
#else
			/* Unload DLL from memory */
			dlclose(plugintable[i].hPlugin);
#endif
			os_releasemutex(plugintable[i].pluginMutex);
			os_destroymutex(plugintable[i].pluginMutex);
		}
	}
	number_of_plugins = -1;
	os_releasemutex(libMutex);
	os_destroymutex(libMutex);
}


static void VisibilityCallback(
    IMA_BOOL becomingVisible,
    IMA_OID objectId) {
	IMA_UINT i, j;
	os_obtainmutex(libMutex);
	for (i = 0; i < number_of_plugins; i++) {
		if ((plugintable[i].hPlugin != NULL) &&
		    (objectId.ownerId == plugintable[i].ownerId)) {
			os_obtainmutex(plugintable[i].pluginMutex);
			for (j = 0;
			    j < plugintable[i].number_of_vbcallbacks;
			    j++) {
				(plugintable[i].vbcallback[j])
				    (becomingVisible, objectId);
			}
			os_releasemutex(plugintable[i].pluginMutex);
		}
	}
	os_releasemutex(libMutex);

}

static void PropertyCallback(
    IMA_OID objectId) {
	IMA_UINT i, j;

	os_obtainmutex(libMutex);
	for (i = 0; i < number_of_plugins; i++) {
		if ((plugintable[i].hPlugin != NULL) &&
		    (objectId.ownerId == plugintable[i].ownerId)) {
			os_obtainmutex(plugintable[i].pluginMutex);
			for (j = 0;
			    j < plugintable[i].number_of_pccallbacks;
			    j++) {
				(plugintable[i].pccallback[j])(objectId);
			}
			os_releasemutex(plugintable[i].pluginMutex);
		}
	}
	os_releasemutex(libMutex);
}

/*
 * Gets the date and time, in the form of an IMA_DATETIME, from the build
 * script when compiled.
 */
static void GetBuildTime(IMA_DATETIME* pdatetime) {

#ifdef WIN32
	char *dayToken[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
	char *monthToken[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
	char monthString[4];
	char dayString[4];
	int  i;

	sscanf(__TIME__, "%u:%u:%u", &pdatetime->tm_hour,
	    &pdatetime->tm_min, &pdatetime->tm_sec);
	sscanf(__DATE__, "%s %u %u", monthString,
	    &pdatetime->tm_mday, &pdatetime->tm_year);
	sscanf(__TIMESTAMP__, "%s", dayString);

	pdatetime->tm_year -= 1900;
	pdatetime->tm_isdst = -1;

	pdatetime->tm_wday = 0;
	for (i = 0;  i < 7;  i++) {
		if (strcmp(dayToken[i], dayString) == 0) {
			pdatetime->tm_wday = i;
			break;
		}
	}

	pdatetime->tm_mon = 0;
	for (i = 0; i < 12; i++) {
		if (strcmp(monthToken[i], monthString) == 0) {
			pdatetime->tm_mon = i;
			break;
		}
	}

#else
#if defined(BUILD_DATE)
	if (strptime(BUILD_DATE, "%Y/%m/%d %T %Z", pdatetime) == NULL) {
		memset(pdatetime, 0, sizeof (IMA_DATETIME));
	}
#else
	memset(pdatetime, 0, sizeof (IMA_DATETIME));
#endif
#endif

}



/*
 * Gets the properties of the IMA library that is being used.
 *
 * @param pProps A pointer to an @ref IMA_LIBRARY_PROPERTIES structure
 *    allocated by the caller.  On successful return this structure will
 *    contain the properties of the IMA library.
 * @return An IMA_STATUS indicating if the operation was successful or if
 *     an error occurred.
 * @retval IMA_SUCCESS Returned if the library properties were successfully
 *    returned.
 * @retval IMA_ERROR_INVALID_PARAMETER Returned if @a pProps is NULL or
 *    specifies a memory area to which data cannot be written.
 */
IMA_API IMA_STATUS IMA_GetLibraryProperties(
    IMA_LIBRARY_PROPERTIES *pProps) {

	char imaPath[256];
#ifdef WIN32
	HMODULE imaHandle;
#endif

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	// Fill in the library properties.
	GetBuildTime(&pProps->buildTime);
	pProps->supportedImaVersion = LIBRARY_PROPERTY_SUPPORTED_IMA_VERSION;
	libSwprintf(pProps->implementationVersion, L"%ls",
	    LIBRARY_PROPERTY_IMPLEMENTATION_VERSION);
	libSwprintf(pProps->vendor, L"%ls", LIBRARY_PROPERTY_VENDOR);


#ifdef WIN32
	imaHandle = GetModuleHandleA("ima");
	imaPath[0] = 0;
	if (imaHandle != NULL) {
		GetModuleFileNameA(imaHandle, imaPath, 256);
	}
	MultiByteToWideChar(CP_ACP, 0, imaPath, -1,
	pProps->fileName, 256);
#else
	libSwprintf(pProps->fileName, LIBRARY_FILE_NAME);

	//  mbstowcs(pProps->fileName, imaPath, 256);
#endif

	return (IMA_STATUS_SUCCESS);
}


/*
 * Gets a list of the object IDs of all currently loaded plugins.
 *
 * @param ppList A pointer to a pointer to an @ref IMA_OID_LIST.
 *    On successful return this will contain a pointer to an @ref
 *    IMA_OID_LIST which contains the object IDs of all of the plugins
 *    currently loaded by the library.
 * @return An IMA_STATUS indicating if the operation was successful
 *    or if an error occurred.
 * @retval IMA_SUCCESS Returned if the plugin ID list was successfully
 *    returned.
 * @retval IMA_ERROR_INVALID_PARAMETER Returned if @a ppList is NULL or
 *    specifies a memory area to which data cannot be written.
 */
IMA_API IMA_STATUS IMA_GetPluginOidList(
    IMA_OID_LIST **ppList) {
	IMA_UINT i;


	if (number_of_plugins == -1)
		InitLibrary();

	if (ppList == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	os_obtainmutex(libMutex);

	*ppList = (IMA_OID_LIST*)calloc(1, sizeof (IMA_OID_LIST) +
	    (number_of_plugins - 1) * sizeof (IMA_OID));

	if ((*ppList) == NULL)
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);

	(*ppList)->oidCount = number_of_plugins;

	for (i = 0; i < number_of_plugins; i++) {

		(*ppList)->oids[i].objectType = IMA_OBJECT_TYPE_PLUGIN;
		(*ppList)->oids[i].ownerId = plugintable[i].ownerId;
		(*ppList)->oids[i].objectSequenceNumber = 0;

	}
	os_releasemutex(libMutex);
	return (IMA_STATUS_SUCCESS);
}




/*
 * Gets the properties of the specified vendor plugin.
 *
 * @param pluginId The ID of the plugin whose properties are being retrieved.
 * @param pProps A pointer to an @ref IMA_PLUGIN_PROPERTIES structure
 *    allocated by the caller.  On successful return this will contain the
 *    properties of the plugin specified by pluginId.
 * @return An IMA_STATUS indicating if the operation was successful or if
 *    an error occurred.
 * @retval IMA_SUCCESS Returned if the plugin properties were successfully
 *    returned.
 * @retval IMA_ERROR_INVALID_OBJECT_TYPE Returned if @a pluginId does not
 *    specify any valid object type.
 * @retval IMA_ERROR_INCORRECT_OBJECT_TYPE Returned if @a pluginId does not
 *    specify a plugin object.
 * @retval IMA_ERROR_OBJECT_NOT_FOUND Returned if @a pluginId refers to a
 *     plugin, but not one that is currently loaded.
 * @retval IMA_ERROR_INVALID_PARAMETER Returned if @a pProps is NULL or
 *    specify a memory area to which data cannot be written.
 */
IMA_API IMA_STATUS IMA_GetPluginProperties(
    IMA_OID pluginOid,
    IMA_PLUGIN_PROPERTIES *pProps) {
	IMA_GetPluginPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if ((pluginOid.objectType != IMA_OBJECT_TYPE_PLUGIN) ||
	    (pluginOid.objectSequenceNumber != 0))
		return (IMA_ERROR_INVALID_PARAMETER);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == pluginOid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetPluginPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetPluginProperties");
#else
				PassFunc = (IMA_GetPluginPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetPluginProperties");
#endif
				if (PassFunc != NULL) {
					status = PassFunc(pluginOid, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);

}




/*
 * Gets the object ID for the plugin associated with the specified object ID.
 *
 * @param objectId The object ID of an object that has been received from
 *    a previous library call.
 * @param pPluginId A pointer to an @ref IMA_OID structure allocated by the
 *    caller.  On successful return this will contain the object ID of the
 *    plugin associated with the object specified by @a objectId.  This
 *    can then be used to work with the plugin, e.g., to get the
 *    properties of the plugin or the send the plugin an IOCtl.
 * @return An IMA_STATUS indicating if the operation was successful or if
 *    an error occurred.
 * @retval IMA_SUCCESS Returned if the associated plugin ID was
 *    successfully returned.
 * @retval IMA_ERROR_INVALID_PARAMETER Returned if @a pPluginId is NULL
 *    or specifes a memory area to which data cannot be written.
 * @retval IMA_ERROR_INVALID_PARAMETER Returned if @a objectId specifies
 *    an object not owned by a plugin, but instead one that is owned by
 *    the library.
 * @retval IMA_ERROR_INVALID_OBJECT_TYPE Returned if @a objectId specifies
 *    an object with an invalid type.
 */
IMA_API IMA_STATUS IMA_GetAssociatedPluginOid(
    IMA_OID objectId,
    IMA_OID *pPluginId) {
	IMA_UINT i;
	IMA_STATUS status;


	if (number_of_plugins == -1)
		InitLibrary();

	if (pPluginId == NULL || objectId.ownerId == RL_LIBRARY_SEQNUM)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (objectId.objectType != IMA_OBJECT_TYPE_UNKNOWN &&
	    objectId.objectType != IMA_OBJECT_TYPE_PLUGIN &&
	    objectId.objectType != IMA_OBJECT_TYPE_NODE &&
	    objectId.objectType != IMA_OBJECT_TYPE_LHBA &&
	    objectId.objectType != IMA_OBJECT_TYPE_PHBA &&
	    objectId.objectType != IMA_OBJECT_TYPE_NETWORK_PORTAL &&
	    objectId.objectType != IMA_OBJECT_TYPE_PORTAL_GROUP &&
	    objectId.objectType != IMA_OBJECT_TYPE_LNP &&
	    objectId.objectType != IMA_OBJECT_TYPE_PNP &&
	    objectId.objectType != IMA_OBJECT_TYPE_TARGET &&
	    objectId.objectType != IMA_OBJECT_TYPE_LU &&
	    objectId.objectType != IMA_OBJECT_TYPE_DISCOVERY_ADDRESS &&
	    objectId.objectType != IMA_OBJECT_TYPE_STATIC_DISCOVERY_TARGET)
		return (IMA_ERROR_INVALID_OBJECT_TYPE);

	os_obtainmutex(libMutex);

	status = IMA_ERROR_OBJECT_NOT_FOUND;
	for (i = 0; i < number_of_plugins; i++) {
		if (objectId.ownerId == plugintable[i].ownerId) {
			pPluginId->objectType = IMA_OBJECT_TYPE_PLUGIN;
			pPluginId->ownerId = plugintable[i].ownerId;
			pPluginId->objectSequenceNumber = 0;
			status = IMA_STATUS_SUCCESS;
		}

	}
	os_releasemutex(libMutex);
	return (status);
}




/*
 * Gets the object ID of the shared node.
 *
 * @param pSharedNodeId A pointer to an @ref IMA_OID structure allocated by
 *    the caller.  On successful return it will contain the object ID of the
 *    shared node of the currently executing system is placed.
 * @return An IMA_STATUS indicating if the operation was successful or if
 *    an error occurred.
 * @retval IMA_SUCCESS Returned if the shared node ID has been successfully
 *    retrieved.
 * @retval IMA_ERROR_INVALID_PARAMETER Returned if @a pSharedNodeId is NULL
 *    or specifies a memory area to which data cannot be written.
 */
IMA_API IMA_STATUS IMA_GetSharedNodeOid(
    IMA_OID *pSharedNodeId) {
	if (pSharedNodeId == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	pSharedNodeId->objectType = IMA_OBJECT_TYPE_NODE;
	pSharedNodeId->ownerId = RL_LIBRARY_SEQNUM;
	pSharedNodeId->objectSequenceNumber = RL_SHARED_NODE_SEQNUM;
	return (IMA_STATUS_SUCCESS);
}


IMA_API IMA_STATUS IMA_GetObjectType(
    IMA_OID oid,
    IMA_OBJECT_TYPE *pObjectType) {
	IMA_STATUS status;
	IMA_UINT i;

	if (pObjectType == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (oid.objectType != IMA_OBJECT_TYPE_UNKNOWN &&
	    oid.objectType != IMA_OBJECT_TYPE_PLUGIN &&
	    oid.objectType != IMA_OBJECT_TYPE_NODE &&
	    oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    oid.objectType != IMA_OBJECT_TYPE_PHBA &&
	    oid.objectType != IMA_OBJECT_TYPE_NETWORK_PORTAL &&
	    oid.objectType != IMA_OBJECT_TYPE_PORTAL_GROUP &&
	    oid.objectType != IMA_OBJECT_TYPE_LNP &&
	    oid.objectType != IMA_OBJECT_TYPE_PNP &&
	    oid.objectType != IMA_OBJECT_TYPE_TARGET &&
	    oid.objectType != IMA_OBJECT_TYPE_LU &&
	    oid.objectType != IMA_OBJECT_TYPE_DISCOVERY_ADDRESS &&
	    oid.objectType != IMA_OBJECT_TYPE_STATIC_DISCOVERY_TARGET)
		return (IMA_ERROR_INVALID_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == oid.ownerId) {
			*pObjectType = oid.objectType;
			status = IMA_STATUS_SUCCESS;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}



/*
 * Gets the properties of the specified iSCSI node.
 * @param nodeId The ID of the node to get the properties of.
 * @param pProps A pointer to an @ref IMA_NODE_PROPERTIES structure
 *    which on successfully return
 *    will contain the properties of the specified node.
 * @return An IMA_STATUS indicating if the operation was successful or
 *    if an error occurred.
 * @retval IMA_SUCCESS Returned if the node properties have been
 *    successfully retrieved.
 * @retval IMA_ERROR_INVALID_PARAMETER Returned if @a pProps is NULL
 *    or specifies a memory area to which data cannot be written.
 * @retval IMA_ERROR_INVALID_OBJECT_TYPE Returned if @a nodeId does
 *     not specify any valid object type.
 * @retval IMA_ERROR_INCORRECT_OBJECT_TYPE Returned if @a nodeId does
 *    not specify a node object.
 * @retval IMA_ERROR_OBJECT_NOT_FOUND Returned if @a nodeId does not
 *    specify a node which is currently known to the system.
 */
IMA_API IMA_STATUS IMA_GetNodeProperties(
    IMA_OID nodeOid,
    IMA_NODE_PROPERTIES *pProps) {
	IMA_GetNodePropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;
	char fullline[512]; /* Full line read in from IMA.conf */
	char nodename[MAXHOSTNAMELEN];

#if defined(_WINDOWS)
	IMA_UINT dwStrLength;
#endif

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (nodeOid.objectType != IMA_OBJECT_TYPE_NODE)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	if ((nodeOid.ownerId == RL_LIBRARY_SEQNUM) &&
	    (nodeOid.objectSequenceNumber == RL_SHARED_NODE_SEQNUM)) {
		pProps->runningInInitiatorMode = IMA_TRUE;
		pProps->runningInTargetMode = IMA_TRUE;
		pProps->nameAndAliasSettable = IMA_TRUE;

		if (sharedNodeName[0] == 0) {
#if defined(_WINDOWS)
			GetComputerName((char *)fullline,
			    (LPDWORD)&dwStrLength);
			sprintf(nodename, DEFAULT_NODE_NAME_FORMAT, fullline);
			MultiByteToWideChar(CP_ACP, 0, nodename, -1,
			    sharedNodeName, 256);
#elif defined(SOLARIS)

			if (getSolarisSharedNodeName(sharedNodeName) !=
			    IMA_STATUS_SUCCESS) {
				gethostname((char *)fullline,
				    sizeof (fullline));
				sprintf(nodename,
				    DEFAULT_NODE_NAME_FORMAT, fullline);
				mbstowcs(sharedNodeName, nodename, 256);
			}
#else
			gethostname((char *)fullline, sizeof (fullline));
			sprintf(nodename, DEFAULT_NODE_NAME_FORMAT, fullline);
			mbstowcs(sharedNodeName, nodename, 256);
#endif
		}

		if (sharedNodeName[0] != 0) {
			libSwprintf(pProps->name, L"%ls", sharedNodeName);
			pProps->nameValid = IMA_TRUE;
		}
		else
			pProps->nameValid = IMA_FALSE;

#if defined(SOLARIS)
		if (sharedNodeAlias[0] == 0) {
			getSolarisSharedNodeAlias(sharedNodeAlias);
		}
#endif

		if (sharedNodeAlias[0] != 0) {
			libSwprintf(pProps->alias, L"%ls", sharedNodeAlias);
			pProps->aliasValid = IMA_TRUE;
		}
		else
			pProps->aliasValid = IMA_FALSE;

		return (IMA_STATUS_SUCCESS);
	}

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == nodeOid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetNodePropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetNodeProperties");
#else
				PassFunc = (IMA_GetNodePropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetNodeProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(nodeOid, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);

}




/*
 * Sets the name of the specified node.
 *
 * @param nodeId The object ID of the node whose name is being set.
 * @param newName The new name of the node.
 * @return An IMA_STATUS indicating if the operation was successful or if
 *    an error occurred.
 * @retval IMA_SUCCESS Returned if the node name was successfully changed.
 * @retval IMA_STATUS_REBOOT_NECESSARY Returned if a reboot is necessary
 *    before the setting of the name actually takes affect.
 * @retval IMA_ERROR_INVALID_PARAMETER Returned if @a newname is NULL, or
 *    specifies a memory area to which data cannot be written, or has a
 *    length of 0.
 * @retval IMA_ERROR_INVALID_OBJECT_TYPE Returned if @a nodeId does not
 *    specify any valid object type.
 * @retval IMA_ERROR_INCORRECT_OBJECT_TYPE Returned if @a nodeId does not
 *    specify a node object.
 * @retval IMA_ERROR_OBJECT_NOT_FOUND Returned if @a nodeId does not specify a
 *    node which is currently known to the system.
 * @retval IMA_ERROR_NAME_TOO_LONG Returned if @a newName contains too many
 *    characters.
 */
IMA_API IMA_STATUS IMA_SetNodeName(
    IMA_OID nodeOid,
    const IMA_NODE_NAME newName) {
	IMA_SetNodeNameFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (newName == NULL || wcslen(newName) == 0)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (wcslen(newName) > IMA_NODE_NAME_LEN - 1)
		return (IMA_ERROR_NAME_TOO_LONG);

	if (nodeOid.objectType != IMA_OBJECT_TYPE_NODE)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	if ((nodeOid.ownerId == RL_LIBRARY_SEQNUM) &&
	    (nodeOid.objectSequenceNumber == RL_SHARED_NODE_SEQNUM)) {
#if defined(SOLARIS)
		if (setSolarisSharedNodeName(newName) != IMA_STATUS_SUCCESS) {
			return (IMA_ERROR_UNKNOWN_ERROR);
		}
#endif
		os_obtainmutex(libMutex);
		libSwprintf(sharedNodeName, L"%ls", newName);
		os_releasemutex(libMutex);
		return (IMA_STATUS_SUCCESS);
	}

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == nodeOid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_SetNodeNameFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetNodeName");
#else
				PassFunc = (IMA_SetNodeNameFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetNodeName");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(nodeOid, newName);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);

}




/*
 * Generates an unique node name for the currently running system.
 *
 * @param generatedname On successful return contains the generated node
 *    name.
 * @return An IMA_STATUS indicating if the operation was successful or if
 *    an error occurred.
 * @retval IMA_ERROR_INVALID_PARAMETER Returned if @a generatedname is NULL
 *    or specifies a memory area to which data cannot be written.
 */
IMA_API IMA_STATUS IMA_GenerateNodeName(
    IMA_NODE_NAME generatedname) {
	char computername[256];
	char nodename[MAXHOSTNAMELEN];

#if defined(_WINDOWS)
	IMA_UINT dwStrLength = 255;
#endif

#ifndef _WINDOWS
#ifndef SOLARIS
	int i;
#endif
#endif

	if (generatedname == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

#if defined(_WINDOWS)
	GetComputerName((char *)computername, (LPDWORD)&dwStrLength);
	_strlwr(computername);
	_snprintf(nodename, 256, DEFAULT_NODE_NAME_FORMAT, computername);
	MultiByteToWideChar(CP_ACP, 0, nodename, -1,
	generatedname, 256);
#elif defined(SOLARIS)
	if (getSolarisSharedNodeName(generatedname) != IMA_STATUS_SUCCESS) {
		gethostname(computername, sizeof (computername));
		sprintf(nodename, DEFAULT_NODE_NAME_FORMAT, generatedname);
		mbstowcs(generatedname, nodename, 256);
	}
#else
	gethostname((char *)computername, sizeof (computername));
	i = 0;
	while (computername[i] != '\0') {
		computername[i] = tolower(computername[i]);
		i++;
	}
	snprintf(nodename, 256, DEFAULT_NODE_NAME_FORMAT, computername);
	mbstowcs(generatedname, nodename, 256);
#endif

	return (IMA_STATUS_SUCCESS);
}


/*
 * Sets the alias of the specified node.
 *
 * @param nodeId The object ID of the node whose alias is being set.
 * @param newAlias A pointer to a Unicode string which contains the new node
 *    alias.If this parameter is NULL then the current alias is deleted, in
 *    which case the specified node no longer has an alias.
 * @return An IMA_STATUS indicating if the operation was successful or if
 *    an error occurred.
 * @retval IMA_SUCCESS Returned if the node's alias has been successfully set.
 * @retval IMA_STATUS_REBOOT_NECESSARY A reboot is necessary before
 *    the setting of the
 *    alias actually takes affect.
 * @retval IMA_ERROR_INVALID_OBJECT_TYPE Returned if @a nodeId does not
 *    specify any valid object type.
 * @retval IMA_ERROR_INCORRECT_OBJECT_TYPE Returned if @a nodeId does not
 *    specify a node object.
 * @retval IMA_ERROR_OBJECT_NOT_FOUND Returned if @a nodeId does not specify
 *    a node which is currently known to the system.
 * @retval IMA_ERROR_NAME_TOO_LONG Returned if @a newAlias contains too many
 *               characters.
 */
IMA_API IMA_STATUS IMA_SetNodeAlias(
    IMA_OID nodeOid,
    const IMA_NODE_ALIAS newAlias) {
	IMA_SetNodeAliasFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (newAlias == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (wcslen(newAlias) > IMA_NODE_ALIAS_LEN - 1)
		return (IMA_ERROR_NAME_TOO_LONG);

	if (nodeOid.objectType != IMA_OBJECT_TYPE_NODE)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	if ((nodeOid.ownerId == RL_LIBRARY_SEQNUM) &&
	    (nodeOid.objectSequenceNumber == RL_SHARED_NODE_SEQNUM)) {
#if defined(SOLARIS)
		if (setSolarisSharedNodeAlias(newAlias) != IMA_STATUS_SUCCESS) {
			return (IMA_ERROR_UNKNOWN_ERROR);
		}
#endif
		os_obtainmutex(libMutex);
		if (wcslen(newAlias) > 0 && newAlias != NULL)
			libSwprintf(sharedNodeAlias, L"%ls", newAlias);
		else
			libSwprintf(sharedNodeAlias, L"%ls", "");

		os_releasemutex(libMutex);
		return (IMA_STATUS_SUCCESS);
	}

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == nodeOid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_SetNodeAliasFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetNodeAlias");
#else
				PassFunc = (IMA_SetNodeAliasFn)
				    dlsym(
				    plugintable[i].hPlugin,
				    "IMA_SetNodeAlias");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(nodeOid, newAlias);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}




/*
 * Gets a list of the object IDs of all the logical HBAs in the system.
 *
 * @param ppList A pointer to a pointer to an @ref IMA_OID_LIST structure.
 *    on successful return this will contain a pointer to an
 *    @ref IMA_OID_LIST which contains the object IDs of all of the
 *    LHBAs currently in the system.
 * @return An IMA_STATUS indicating if the operation was successful or if
 *    an error occurred.
 * @retval IMA_SUCCESS Returned if the LHBA ID list has been successfully
 *    returned.
 * @retval IMA_ERROR_INVALID_PARAMETER Returned if @a ppList is NULL or
 *   specifies a
 *   memory area to which data cannot be written.
 */
IMA_API IMA_STATUS IMA_GetLhbaOidList(
    IMA_OID_LIST **ppList) {
	IMA_GetLhbaOidListFn PassFunc;
	IMA_FreeMemoryFn FreeFunc;

	IMA_UINT i;
	IMA_UINT j;
	IMA_UINT totalIdCount;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (ppList == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	os_obtainmutex(libMutex);
	// Get total id count first
	totalIdCount = 0;

	for (i = 0; i < number_of_plugins; i++) {
		status = IMA_ERROR_UNEXPECTED_OS_ERROR;
		if (plugintable[i].hPlugin != NULL) {
			os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
			PassFunc = (IMA_GetLhbaOidListFn)
			    GetProcAddress(plugintable[i].hPlugin,
			    "IMA_GetLhbaOidList");
#else
			PassFunc = (IMA_GetLhbaOidListFn)
			    dlsym(plugintable[i].hPlugin,
			    "IMA_GetLhbaOidList");
#endif
			if (PassFunc != NULL) {
				IMA_OID_LIST *ppOidList;
				status = PassFunc(&ppOidList);
				if (status == IMA_STATUS_SUCCESS) {
					totalIdCount += ppOidList->oidCount;
#ifdef WIN32
					FreeFunc = (IMA_FreeMemoryFn)
					    GetProcAddress(
					    plugintable[i].hPlugin,
					    "IMA_FreeMemory");
#else
					FreeFunc = (IMA_FreeMemoryFn)
					    dlsym(plugintable[i].hPlugin,
					    "IMA_FreeMemory");
#endif
					if (FreeFunc != NULL) {
						FreeFunc(ppOidList);
					}
				}

			}
			os_releasemutex(plugintable[i].pluginMutex);
		}
		if (status != IMA_STATUS_SUCCESS) {
			break;
		}
	}


	*ppList = (IMA_OID_LIST*)calloc(1, sizeof (IMA_OID_LIST) +
	    (totalIdCount - 1) * sizeof (IMA_OID));

	if ((*ppList) == NULL) {
		os_releasemutex(libMutex);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}
	(*ppList)->oidCount = totalIdCount;

	// 2nd pass to copy the id lists
	totalIdCount = 0;
	status = IMA_STATUS_SUCCESS;
	for (i = 0; i < number_of_plugins; i++) {
		status = IMA_ERROR_UNEXPECTED_OS_ERROR;
		if (plugintable[i].hPlugin != NULL) {
			os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
			PassFunc = (IMA_GetLhbaOidListFn)
			    GetProcAddress(plugintable[i].hPlugin,
			    "IMA_GetLhbaOidList");
#else
			PassFunc = (IMA_GetLhbaOidListFn)
			    dlsym(plugintable[i].hPlugin,
			    "IMA_GetLhbaOidList");
#endif
			if (PassFunc != NULL) {
				IMA_OID_LIST *ppOidList;
				status = PassFunc(&ppOidList);
				if (status == IMA_STATUS_SUCCESS) {
					for (j = 0;
					    (j < ppOidList->oidCount) &&
					    (totalIdCount <
					    (*ppList)->oidCount);
					    j++) {
						(*ppList)->oids[totalIdCount].
						    objectType
						    = ppOidList->oids[j].
						    objectType;
						(*ppList)->oids[totalIdCount].
						    objectSequenceNumber =
						    ppOidList->oids[j].
						    objectSequenceNumber;
						(*ppList)->oids[totalIdCount].
						    ownerId =
						    ppOidList->oids[j].ownerId;
						totalIdCount++;
					}
#ifdef WIN32
					FreeFunc = (IMA_FreeMemoryFn)
					    GetProcAddress(
					    plugintable[i].hPlugin,
					    "IMA_FreeMemory");
#else
					FreeFunc = (IMA_FreeMemoryFn)
					    dlsym(plugintable[i].hPlugin,
					    "IMA_FreeMemory");
#endif
					if (FreeFunc != NULL) {
						FreeFunc(ppOidList);
					}
				}
			}
			os_releasemutex(plugintable[i].pluginMutex);
		}
		if (status != IMA_STATUS_SUCCESS) {
			free(*ppList);
			break;
		}

	}
	os_releasemutex(libMutex);
	return (status);
}




/*
 * Gets the properties of the specified logical HBA.
 *
 * @param lhbaId The object ID of the LHBA whose properties are being
 *    retrieved.
 * @param pProps A pointer to an @ref IMA_LHBA_PROPERTIES structure.
 *    On successful
 *    return this will contain the properties of the LHBA specified by
 *    @a lhbaId.
 * @return An IMA_STATUS indicating if the operation was successful or if
 *    an error occurred.
 * @retval IMA_SUCCESS Returned if the properties of the specified LHBA
 *    have been successfully retrieved.
 * @retval IMA_ERROR_INVALID_PARAMETER Returned if @a pProps is NULL or
 *    specify a memory area to which data cannot be written.
 * @retval IMA_ERROR_INVALID_OBJECT_TYPE Returned if @a lhbaId does not
 *    specify any valid object type.
 * @retval IMA_ERROR_INCORRECT_OBJECT_TYPE Returned if @a lhbaId does not
 *    specify a LHBA.
 * @retval IMA_ERROR_OBJECT_NOT_FOUND Returned if @a lhbaId does not
 *    specify a LHBA which is currently known to the system.
 */
IMA_API IMA_STATUS IMA_GetLhbaProperties(
    IMA_OID lhbaId,
    IMA_LHBA_PROPERTIES *pProps) {
	IMA_GetLhbaPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (lhbaId.objectType != IMA_OBJECT_TYPE_LHBA)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == lhbaId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetLhbaPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetLhbaProperties");
#else
				PassFunc = (IMA_GetLhbaPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetLhbaProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(lhbaId, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}




/*
 * Gets a list of the object IDs of all the physical HBAs in the system.
 *
 * @param ppList A pointer to a pointer to an @ref IMA_OID_LIST structure.
 *    on successful return this will contain a pointer to an
 *    @ref IMA_OID_LIST which contains the object IDs of all of the
 *    PHBAs currently in the system.
 * @return An IMA_STATUS indicating if the operation was successful or if
 *    an error occurred.
 * @retval IMA_SUCCESS Returned if the PHBA ID list has been successfully
 *    returned.
 * @retval IMA_ERROR_INVALID_PARAMETER Returned if @a ppList is NULL or
 *    specify a memory area to which data cannot be written.
 * @retval IMA_SUCCESS Returned if the properties of the specified PHBA
 *    have been successfully retrieved.
 * @retval IMA_ERROR_OBJECT_NOT_FOUND Returned if @a phbaId does not
 *    specify a PHBA which is currently known to the system.
 * @retval IMA_ERROR_INVALID_PARAMETER Returned if @a ppList is NULL or
 *    specify a memory area to which data cannot be written.
 */
IMA_API IMA_STATUS IMA_GetPhbaOidList(
    IMA_OID_LIST **ppList) {
	IMA_GetPhbaOidListFn PassFunc;
	IMA_FreeMemoryFn FreeFunc;

	IMA_UINT i;
	IMA_UINT j;
	IMA_UINT totalIdCount;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (ppList == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	os_obtainmutex(libMutex);
	// Get total id count first
	totalIdCount = 0;

	for (i = 0; i < number_of_plugins; i++) {
		status = IMA_ERROR_UNEXPECTED_OS_ERROR;
		if (plugintable[i].hPlugin != NULL) {
			os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
			PassFunc = (IMA_GetPhbaOidListFn)
			    GetProcAddress(plugintable[i].hPlugin,
			    "IMA_GetPhbaOidList");
#else
			PassFunc = (IMA_GetPhbaOidListFn)
			    dlsym(plugintable[i].hPlugin,
			    "IMA_GetPhbaOidList");
#endif
			if (PassFunc != NULL) {
				IMA_OID_LIST *ppOidList;
				status = PassFunc(&ppOidList);
				if (status == IMA_STATUS_SUCCESS) {
					totalIdCount += ppOidList->oidCount;
#ifdef WIN32
					FreeFunc = (IMA_FreeMemoryFn)
					    GetProcAddress(
					    plugintable[i].hPlugin,
					    "IMA_FreeMemory");
#else
					FreeFunc = (IMA_FreeMemoryFn)
					    dlsym(plugintable[i].hPlugin,
					    "IMA_FreeMemory");
#endif
					if (FreeFunc != NULL) {
						FreeFunc(ppOidList);
					}
				}
			}
			os_releasemutex(plugintable[i].pluginMutex);
		}
		if (status != IMA_STATUS_SUCCESS) {
			break;
		}

	}


	*ppList = (IMA_OID_LIST*)calloc(1, sizeof (IMA_OID_LIST) +
	    (totalIdCount - 1) * sizeof (IMA_OID));

	if ((*ppList) == NULL) {
		os_releasemutex(libMutex);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(*ppList)->oidCount = totalIdCount;

	// 2nd pass to copy the id lists
	totalIdCount = 0;
	status = IMA_STATUS_SUCCESS;
	for (i = 0; i < number_of_plugins; i++) {
		status = IMA_ERROR_UNEXPECTED_OS_ERROR;
		if (plugintable[i].hPlugin != NULL) {
			os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
			PassFunc = (IMA_GetPhbaOidListFn)
			    GetProcAddress(plugintable[i].hPlugin,
			    "IMA_GetPhbaOidList");
#else
			PassFunc = (IMA_GetPhbaOidListFn)
			    dlsym(plugintable[i].hPlugin,
			    "IMA_GetPhbaOidList");
#endif
			if (PassFunc != NULL) {
				IMA_OID_LIST *ppOidList;
				status = PassFunc(&ppOidList);
				if (status == IMA_STATUS_SUCCESS) {
					for (j = 0;
					    (j < ppOidList->oidCount) &&
					    (totalIdCount <
					    (*ppList)->oidCount);
					    j++) {
						(*ppList)->oids[totalIdCount].
						    objectType =
						    ppOidList->oids[j].
						    objectType;
						(*ppList)->oids[totalIdCount].
						    objectSequenceNumber =
						    ppOidList->oids[j].
						    objectSequenceNumber;
						(*ppList)->oids[totalIdCount].
						    ownerId =
						    ppOidList->oids[j].ownerId;
						totalIdCount++;
					}
#ifdef WIN32
					FreeFunc = (IMA_FreeMemoryFn)
					    GetProcAddress
					    (plugintable[i].hPlugin,
					    "IMA_FreeMemory");
#else
					FreeFunc = (IMA_FreeMemoryFn)
					    dlsym(plugintable[i].hPlugin,
					    "IMA_FreeMemory");
#endif
					if (FreeFunc != NULL) {
						FreeFunc(ppOidList);
					}
				}
			}
			os_releasemutex(plugintable[i].pluginMutex);
		}
		if (status != IMA_STATUS_SUCCESS) {
			free(*ppList);
			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


/*
 * Gets the general properties of a physical HBA.
 *
 * @param phbaId The object ID of the PHBA whose
 *    properties are being queried.
 * @param pProps A pointer to an @ref
 *    IMA_PHBA_PROPERTIES structure.  On successful
 *    return this will contain the properties of
 *    the PHBA specified by @a phbaId.
 * @return An IMA_STATUS indicating if the
 *    operation was successful or if an error
 *    occurred.
 * @retval IMA_SUCCESS Returned if the properties
 *    of the specified PHBA have been
 *    successfully retrieved.
 * @retval IMA_ERROR_INVALID_PARAMETER Returned
 *    if @a pProps is NULL or specifies a
 *    memory area to which data cannot be written.
 * @retval IMA_ERROR_INVALID_OBJECT_TYPE Returned
 *    if @a phbaId does not specify any
 *    valid object type.
 * @retval IMA_ERROR_INCORRECT_OBJECT_TYPE Returned
 *    if @a phbaId does not specify a
 *    PHBA.
 * @retval IMA_ERROR_OBJECT_NOT_FOUND Returned
 *    if @a phbaId does not specify a PHBA
 *    which is currently known to the system.
 */
IMA_API IMA_STATUS IMA_GetPhbaProperties(
    IMA_OID phbaId,
    IMA_PHBA_PROPERTIES *pProps) {
	IMA_GetPhbaPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (phbaId.objectType != IMA_OBJECT_TYPE_PHBA)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == phbaId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetPhbaPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetPhbaProperties");
#else
				PassFunc = (IMA_GetPhbaPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetPhbaProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(phbaId, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

/*
 * Frees a previously allocated IMA_OID_LIST structure.
 *
 * @param pList A pointer to an @ref IMA_OID_LIST
 *    structure allocated by the
 *    library.  On successful return the memory
 *    allocated by the list is freed.
 * @return An IMA_STATUS indicating if the operation
 *    was successful or if an error occurred.
 * @retval IMA_SUCCESS Returned if the specified object
 *    ID list was successfully freed.
 * @retval IMA_ERROR_INVALID_PARAMETER Returned
 *    if @a pList is NULL or specifies a
 *    memory area from which data cannot be read.
 */
IMA_API IMA_STATUS IMA_FreeMemory(
    void *pMemory) {
	if (pMemory == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);
	free(pMemory);
	return (IMA_STATUS_SUCCESS);
}




IMA_API IMA_STATUS IMA_GetNonSharedNodeOidList(
    IMA_OID_LIST **ppList) {
	IMA_GetNonSharedNodeOidListFn PassFunc;
	IMA_FreeMemoryFn FreeFunc;

	IMA_UINT i;
	IMA_UINT j;
	IMA_UINT totalIdCount;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (ppList == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	os_obtainmutex(libMutex);
	// Get total id count first
	totalIdCount = 0;

	for (i = 0; i < number_of_plugins; i++) {
		status = IMA_ERROR_UNEXPECTED_OS_ERROR;
		if (plugintable[i].hPlugin != NULL) {
			os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
			PassFunc = (IMA_GetNonSharedNodeOidListFn)
			    GetProcAddress(plugintable[i].hPlugin,
			    "IMA_GetNonSharedNodeOidList");
#else
			PassFunc = (IMA_GetNonSharedNodeOidListFn)
			    dlsym(plugintable[i].hPlugin,
			    "IMA_GetNonSharedNodeOidList");
#endif
			if (PassFunc != NULL) {
				IMA_OID_LIST *ppOidList;
				status = PassFunc(&ppOidList);
				if (status == IMA_STATUS_SUCCESS) {
					totalIdCount += ppOidList->oidCount;
#ifdef WIN32
					FreeFunc = (IMA_FreeMemoryFn)
					    GetProcAddress(
					    plugintable[i].hPlugin,
					    "IMA_FreeMemory");
#else
					FreeFunc = (IMA_FreeMemoryFn)
					    dlsym(plugintable[i].hPlugin,
					    "IMA_FreeMemory");
#endif
					if (FreeFunc != NULL) {
						FreeFunc(ppOidList);
					}
				}
			}
			os_releasemutex(plugintable[i].pluginMutex);
		}
		if (status != IMA_STATUS_SUCCESS) {
			break;
		}

	}

	*ppList = (IMA_OID_LIST*)calloc(1, sizeof (IMA_OID_LIST) +
	    (totalIdCount - 1) * sizeof (IMA_OID));

	if ((*ppList) == NULL) {
		os_releasemutex(libMutex);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(*ppList)->oidCount = totalIdCount;

	// 2nd pass to copy the id lists
	totalIdCount = 0;
	status = IMA_STATUS_SUCCESS;
	for (i = 0; i < number_of_plugins; i++) {
		status = IMA_ERROR_UNEXPECTED_OS_ERROR;
		if (plugintable[i].hPlugin != NULL) {
			os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
			PassFunc = (IMA_GetNonSharedNodeOidListFn)
			    GetProcAddress(plugintable[i].hPlugin,
			    "IMA_GetNonSharedNodeOidList");
#else
			PassFunc = (IMA_GetNonSharedNodeOidListFn)
			    dlsym(plugintable[i].hPlugin,
			    "IMA_GetNonSharedNodeOidList");
#endif
			if (PassFunc != NULL) {
				IMA_OID_LIST *ppOidList;
				status = PassFunc(&ppOidList);
				if (status == IMA_STATUS_SUCCESS) {
					for (j = 0;
					    (j < ppOidList->oidCount) &&
					    (totalIdCount < (
					    *ppList)->oidCount);
					    j++) {
						(*ppList)->oids[
						    totalIdCount].objectType =
						    ppOidList->oids[j].
						    objectType;
						(*ppList)->oids[totalIdCount].
						    objectSequenceNumber =
						    ppOidList->oids[j].
						    objectSequenceNumber;
						(*ppList)->oids[
						    totalIdCount].
						    ownerId =
						    ppOidList->oids[j].
						    ownerId;
						totalIdCount++;
					}
#ifdef WIN32
					FreeFunc = (IMA_FreeMemoryFn)
					    GetProcAddress(
					    plugintable[i].hPlugin,
					    "IMA_FreeMemory");
#else
					FreeFunc = (IMA_FreeMemoryFn)
					    dlsym(plugintable[i].hPlugin,
					    "IMA_FreeMemory");
#endif
					if (FreeFunc != NULL) {
						FreeFunc(ppOidList);
					}
				}
			}
			os_releasemutex(plugintable[i].pluginMutex);
		}
		if (status != IMA_STATUS_SUCCESS) {
			free(*ppList);
			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}



/*
 * Gets the first burst length properties of
 * the specified logical HBA.
 *
 * @param lhbaId The object ID of the logical HBA
 *    to get the first burst length
 *    properties of.
 * @param pProps A pointer to a min/max values
 *    structure.
 * @return An IMA_STATUS indicating if the operation
 *    was successful or if an error
 *    occurred.
 * @retval IMA_SUCCESS Returned if the first burst
 *    length properties have been
 *    successfully retrieved.
 * @retval IMA_ERROR_INVALID_PARAMETER Returned
 *    if @a pProps is NULL or specifies a
 *    memory area to which data cannot be written.
 * @retval IMA_ERROR_INVALID_OBJECT_TYPE Returned
 *    if @a lhbaId does not specify any
 *    valid object type.
 * @retval IMA_ERROR_INCORRECT_OBJECT_TYPE Returned
 *    if @a lhbaId does not specify a LHBA.
 * @retval IMA_ERROR_OBJECT_NOT_FOUND Returned
 *    @a lhbaId does not specify a LHBA
 *    which is currently known to the system.
 */
IMA_API IMA_STATUS IMA_GetFirstBurstLengthProperties(
    IMA_OID Oid,
    IMA_MIN_MAX_VALUE *pProps) {
	IMA_GetFirstBurstLengthPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (Oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    Oid.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetFirstBurstLengthPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetFirstBurstLengthProperties");
#else
				PassFunc =
				    (IMA_GetFirstBurstLengthPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetFirstBurstLengthProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(Oid, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

/*
 * Gets the max burst length properties of the
 * specified logical HBA.
 *
 * @param lhbaId The object ID of the logical HBA to
 * get the max burst length properties of.
 * @param pProps A pointer to an @ref IMA_MIN_MAX_VALUE
 *    structure allocated by the
 *    caller.  On successful return this structure
 *    will contain the max
 *    burst length properties of this LHBA.
 * @return An IMA_STATUS indicating if the operation
 *    was successful or if an error occurred.
 * @retval IMA_SUCCESS Returned if the max burst
 *    length properties have been
 *    successfully retrieved.
 * @retval IMA_ERROR_INVALID_PARAMETER Returned
 *    if @a pProps is NULL or specifies a
 *    memory area to which data cannot be written.
 * @retval IMA_ERROR_INVALID_OBJECT_TYPE Returned
 *    if @a lhbaId does not specify any
 *    valid object type.
 * @retval IMA_ERROR_INCORRECT_OBJECT_TYPE Returned
 *    if @a lhbaId does not specify a HBA.
 * @retval IMA_ERROR_OBJECT_NOT_FOUND Returned
 *    if @a lhbaId does not specify a LHBA
 *    which is currently known to the system.
 */
IMA_API IMA_STATUS IMA_GetMaxBurstLengthProperties(
    IMA_OID Oid,
    IMA_MIN_MAX_VALUE *pProps) {
	IMA_GetMaxBurstLengthPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (Oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    Oid.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetMaxBurstLengthPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetMaxBurstLengthProperties");
#else
				PassFunc =
				    (IMA_GetMaxBurstLengthPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetMaxBurstLengthProperties");
#endif
				if (PassFunc != NULL) {
					status = PassFunc(Oid, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


/*
 * Gets the maximum receive data segment length properties
 * of the specified logical HBA.
 *
 * @param lhbaId The object ID of the logical HBA to
 *    get the max receive data
 *    segment length properties of.
 * @param pProps A pointer to an @ref IMA_MIN_MAX_VALUE
 *    structure allocated by the caller.
 *    On successful return this structure will contain the max
 *    receive data segment length properties of this LHBA.
 * @return An IMA_STATUS indicating if the operation
 *    was successful or if an error occurred.
 * @retval IMA_SUCCESS Returned if the max receive
 *    data segment length properties
 *    have been successfully retrieved.
 * @retval IMA_ERROR_INVALID_PARAMETER Returned if
 *    @a pProps is NULL or specifies a
 *    memory area to which data cannot be written.
 * @retval IMA_ERROR_INVALID_OBJECT_TYPE Returned if
 *    @a lhbaId does not specify any
 *    valid object type.
 * @retval IMA_ERROR_INCORRECT_OBJECT_TYPE Returned if
 *    a lhbaId does not specify a LHBA.
 * @retval IMA_ERROR_OBJECT_NOT_FOUND Returned if @a
 *    lhbaId does not specify a LHBA
 *    which is currently known to the system.
 */
IMA_API IMA_STATUS IMA_GetMaxRecvDataSegmentLengthProperties(
    IMA_OID Oid,
    IMA_MIN_MAX_VALUE *pProps) {
	IMA_GetMaxRecvDataSegmentLengthPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;
#define	IMA_GMRDSLPFN IMA_GetMaxRecvDataSegmentLengthPropertiesFn
#define	IMA_GMRDSLP "IMA_GetMaxRecvDataSegmentLengthProperties"

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (Oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    Oid.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GMRDSLPFN)
				    GetProcAddress(plugintable[i].hPlugin,
				    IMA_GMRDSLP);
#else
				PassFunc =
				    (IMA_GMRDSLPFN)
				    dlsym(plugintable[i].hPlugin,
				    IMA_GMRDSLP);
#endif

				if (PassFunc != NULL) {
					status = PassFunc(Oid, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
#undef IMA_GMRDSLPFN
#undef IMA_GMRDSLP
	return (status);
}



/* --------------------------------------------- */
IMA_API IMA_STATUS IMA_PluginIOCtl(
    IMA_OID pluginOid,
    IMA_UINT command,
    const void *pInputBuffer,
    IMA_UINT inputBufferLength,
    void *pOutputBuffer,
    IMA_UINT *pOutputBufferLength) {
	IMA_PluginIOCtlFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pInputBuffer == NULL || inputBufferLength == 0 ||
	    pOutputBuffer == NULL || pOutputBufferLength == NULL ||
	    *pOutputBufferLength == 0)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (pluginOid.objectType != IMA_OBJECT_TYPE_PLUGIN)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == pluginOid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_PluginIOCtlFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_PluginIOCtl");
#else
				PassFunc = (IMA_PluginIOCtlFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_PluginIOCtl");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(
					    pluginOid, command,
					    pInputBuffer, inputBufferLength,
					    pOutputBuffer, pOutputBufferLength);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}




IMA_API IMA_STATUS IMA_GetNetworkPortalOidList(
    IMA_OID lnpId,
    IMA_OID_LIST **ppList) {
	IMA_GetNetworkPortalOidListFn PassFunc;
	IMA_FreeMemoryFn FreeFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (ppList == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (lnpId.objectType != IMA_OBJECT_TYPE_LNP)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == lnpId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetNetworkPortalOidListFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetNetworkPortalOidList");
#else
				PassFunc = (IMA_GetNetworkPortalOidListFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetNetworkPortalOidList");
#endif

				if (PassFunc != NULL) {
					IMA_OID_LIST *ppOidList;
					IMA_UINT listSize;
					listSize = sizeof (IMA_OID_LIST);
					status = PassFunc(lnpId, &ppOidList);
					if (IMA_SUCCESS(status)) {

						*ppList = (IMA_OID_LIST*)
						    calloc(1,
						    sizeof (IMA_OID_LIST)
						    + (ppOidList->
						    oidCount - 1)*
						    sizeof (IMA_OID));

						if ((*ppList) == NULL) {
							return (EUOS_ERROR);
						}
						else
							memcpy((*ppList),
							    ppOidList,
							    listSize
							    + (ppOidList->
							    oidCount - 1)*
							    sizeof (IMA_OID));
#ifdef WIN32
						FreeFunc = (IMA_FreeMemoryFn)
						    GetProcAddress(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#else
						FreeFunc = (IMA_FreeMemoryFn)
						    dlsym(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#endif
						if (FreeFunc != NULL) {
							FreeFunc(ppOidList);
						}
					}
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetFirstBurstLength(
    IMA_OID lhbaId,
    IMA_UINT firstBurstLength) {
	IMA_SetFirstBurstLengthFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (lhbaId.objectType != IMA_OBJECT_TYPE_LHBA &&
	    lhbaId.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == lhbaId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_SetFirstBurstLengthFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetFirstBurstLength");
#else
				PassFunc = (IMA_SetFirstBurstLengthFn)
				    dlsym(
				    plugintable[i].hPlugin,
				    "IMA_SetFirstBurstLength");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(
					    lhbaId, firstBurstLength);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetMaxBurstLength(
    IMA_OID lhbaId,
    IMA_UINT maxBurstLength) {
	IMA_SetMaxBurstLengthFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (lhbaId.objectType != IMA_OBJECT_TYPE_LHBA &&
	    lhbaId.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == lhbaId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_SetMaxBurstLengthFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetMaxBurstLength");
#else
				PassFunc = (IMA_SetMaxBurstLengthFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetMaxBurstLength");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(
					    lhbaId, maxBurstLength);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetMaxRecvDataSegmentLength(
    IMA_OID lhbaId,
    IMA_UINT maxRecvDataSegmentLength) {
	IMA_SetMaxRecvDataSegmentLengthFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (lhbaId.objectType != IMA_OBJECT_TYPE_LHBA &&
	lhbaId.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == lhbaId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_SetMaxRecvDataSegmentLengthFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetMaxRecvDataSegmentLength");
#else
				PassFunc =
				    (IMA_SetMaxRecvDataSegmentLengthFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetMaxRecvDataSegmentLength");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(
					    lhbaId,
					    maxRecvDataSegmentLength);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetMaxConnectionsProperties(
    IMA_OID Oid,
    IMA_MIN_MAX_VALUE *pProps) {
	IMA_GetMaxConnectionsPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (Oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    Oid.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetMaxConnectionsPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetMaxConnectionsProperties");
#else
				PassFunc =
				    (IMA_GetMaxConnectionsPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetMaxConnectionsProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(Oid, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetMaxConnections(
    IMA_OID lhbaId,
    IMA_UINT maxConnections) {
	IMA_SetMaxConnectionsFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (lhbaId.objectType != IMA_OBJECT_TYPE_LHBA &&
	    lhbaId.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == lhbaId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_SetMaxConnectionsFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetMaxConnections");
#else
				PassFunc = (IMA_SetMaxConnectionsFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetMaxConnections");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(
					    lhbaId, maxConnections);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetDefaultTime2RetainProperties(
    IMA_OID lhbaId,
    IMA_MIN_MAX_VALUE *pProps) {
	IMA_GetDefaultTime2RetainPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (lhbaId.objectType != IMA_OBJECT_TYPE_LHBA &&
	    lhbaId.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == lhbaId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetDefaultTime2RetainPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetDefaultTime2RetainProperties");
#else
				PassFunc =
				    (IMA_GetDefaultTime2RetainPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetDefaultTime2RetainProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(lhbaId, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetDefaultTime2Retain(
    IMA_OID lhbaId,
    IMA_UINT defaultTime2Retain) {
	IMA_SetDefaultTime2RetainFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (lhbaId.objectType != IMA_OBJECT_TYPE_LHBA &&
	    lhbaId.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == lhbaId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_SetDefaultTime2RetainFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetDefaultTime2Retain");
#else
				PassFunc =
				    (IMA_SetDefaultTime2RetainFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetDefaultTime2Retain");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(
					    lhbaId, defaultTime2Retain);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetDefaultTime2WaitProperties(
    IMA_OID lhbaId,
    IMA_MIN_MAX_VALUE *pProps) {
	IMA_GetDefaultTime2WaitPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (lhbaId.objectType != IMA_OBJECT_TYPE_LHBA &&
	    lhbaId.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == lhbaId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetDefaultTime2WaitPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetDefaultTime2WaitProperties");
#else
				PassFunc =
				    (IMA_GetDefaultTime2WaitPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetDefaultTime2WaitProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(lhbaId, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetDefaultTime2Wait(
    IMA_OID lhbaId,
    IMA_UINT defaultTime2Wait) {
	IMA_SetDefaultTime2WaitFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (lhbaId.objectType != IMA_OBJECT_TYPE_LHBA &&
	    lhbaId.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == lhbaId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_SetDefaultTime2WaitFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetDefaultTime2Wait");
#else
				PassFunc =
				    (IMA_SetDefaultTime2WaitFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetDefaultTime2Wait");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(
					    lhbaId, defaultTime2Wait);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetMaxOutstandingR2TProperties(
    IMA_OID Oid,
    IMA_MIN_MAX_VALUE *pProps) {
	IMA_GetMaxOutstandingR2TPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (Oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    Oid.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetMaxOutstandingR2TPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetMaxOutstandingR2TProperties");
#else
				PassFunc =
				    (IMA_GetMaxOutstandingR2TPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetMaxOutstandingR2TProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(Oid, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetMaxOutstandingR2T(
    IMA_OID lhbaId,
    IMA_UINT maxOutstandingR2T) {
	IMA_SetMaxOutstandingR2TFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (lhbaId.objectType != IMA_OBJECT_TYPE_LHBA &&
	    lhbaId.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == lhbaId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_SetMaxOutstandingR2TFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetMaxOutstandingR2T");
#else
				PassFunc =
				    (IMA_SetMaxOutstandingR2TFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetMaxOutstandingR2T");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(
					    lhbaId, maxOutstandingR2T);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetErrorRecoveryLevelProperties(
    IMA_OID Oid,
    IMA_MIN_MAX_VALUE *pProps) {
	IMA_GetMaxOutstandingR2TPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (Oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    Oid.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetErrorRecoveryLevelPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetErrorRecoveryLevelProperties");
#else
				PassFunc =
				    (IMA_GetErrorRecoveryLevelPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetErrorRecoveryLevelProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(Oid, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetErrorRecoveryLevel(
    IMA_OID Oid,
    IMA_UINT errorRecoveryLevel) {
	IMA_SetErrorRecoveryLevelFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (Oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    Oid.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_SetErrorRecoveryLevelFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetErrorRecoveryLevel");
#else
				PassFunc =
				    (IMA_SetErrorRecoveryLevelFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetErrorRecoveryLevel");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(
					    Oid, errorRecoveryLevel);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetInitialR2TProperties(
    IMA_OID Oid,
    IMA_BOOL_VALUE *pProps) {
	IMA_GetInitialR2TPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (Oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    Oid.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetInitialR2TPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetInitialR2TProperties");
#else
				PassFunc =
				    (IMA_GetInitialR2TPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetInitialR2TProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(Oid, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetInitialR2T(
    IMA_OID Oid,
    IMA_BOOL initialR2T)
{
	IMA_SetInitialR2TFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (initialR2T != IMA_TRUE &&
	    initialR2T != IMA_FALSE)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (Oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    Oid.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_SetInitialR2TFn) GetProcAddress(
				    plugintable[i].hPlugin,
				    "IMA_SetInitialR2T");
#else
				PassFunc =
				    (IMA_SetInitialR2TFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetInitialR2T");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(Oid, initialR2T);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetImmediateDataProperties(
    IMA_OID Oid,
    IMA_BOOL_VALUE *pProps) {
	IMA_GetImmediateDataPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (Oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    Oid.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetImmediateDataPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetImmediateDataProperties");
#else
				PassFunc =
				    (IMA_GetImmediateDataPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetImmediateDataProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(Oid, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetImmediateData(
    IMA_OID Oid,
    IMA_BOOL immediateData) {
	IMA_SetImmediateDataFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (immediateData != IMA_TRUE &&
	    immediateData != IMA_FALSE)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (Oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    Oid.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_SetImmediateDataFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetImmediateData");
#else
				PassFunc =
				    (IMA_SetImmediateDataFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetImmediateData");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(Oid, immediateData);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetDataPduInOrderProperties(
    IMA_OID Oid,
    IMA_BOOL_VALUE *pProps) {
	IMA_GetDataPduInOrderPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (Oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    Oid.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetDataPduInOrderPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetDataPduInOrderProperties");
#else
				PassFunc =
				    (IMA_GetDataPduInOrderPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetDataPduInOrderProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(Oid, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetDataPduInOrder(
    IMA_OID Oid,
    IMA_BOOL dataPduInOrder) {
	IMA_SetDataPduInOrderFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (dataPduInOrder != IMA_TRUE &&
	    dataPduInOrder != IMA_FALSE)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (Oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    Oid.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_SetDataPduInOrderFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetDataPduInOrder");
#else
				PassFunc =
				    (IMA_SetDataPduInOrderFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetDataPduInOrder");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(Oid, dataPduInOrder);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetDataSequenceInOrderProperties(
    IMA_OID Oid,
    IMA_BOOL_VALUE *pProps) {
	IMA_GetDataSequenceInOrderPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (Oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    Oid.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetDataSequenceInOrderPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetDataSequenceInOrderProperties");
#else
				PassFunc =
				    (IMA_GetDataSequenceInOrderPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetDataSequenceInOrderProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(Oid, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetDataSequenceInOrder(
    IMA_OID Oid,
    IMA_BOOL dataSequenceInOrder) {
	IMA_SetDataSequenceInOrderFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (dataSequenceInOrder != IMA_TRUE &&
	    dataSequenceInOrder != IMA_FALSE)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (Oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    Oid.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_SetDataSequenceInOrderFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetDataSequenceInOrder");
#else
				PassFunc =
				    (IMA_SetDataSequenceInOrderFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetDataSequenceInOrder");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(
					    Oid, dataSequenceInOrder);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetStatisticsCollection(
    IMA_OID Oid,
    IMA_BOOL enableStatisticsCollection) {
	IMA_SetStatisticsCollectionFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (enableStatisticsCollection != IMA_TRUE &&
	    enableStatisticsCollection != IMA_FALSE)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (Oid.objectType != IMA_OBJECT_TYPE_PHBA &&
	    Oid.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_SetStatisticsCollectionFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetStatisticsCollection");
#else
				PassFunc =
				    (IMA_SetStatisticsCollectionFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetStatisticsCollection");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(
					Oid, enableStatisticsCollection);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetNetworkPortStatus(
    IMA_OID portOid,
    IMA_NETWORK_PORT_STATUS *pStatus) {
	IMA_GetNetworkPortStatusFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pStatus == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (portOid.objectType != IMA_OBJECT_TYPE_PNP &&
	    portOid.objectType != IMA_OBJECT_TYPE_LNP)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == portOid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetNetworkPortStatusFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetNetworkPortStatus");
#else
				PassFunc =
				    (IMA_GetNetworkPortStatusFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetNetworkPortStatus");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(portOid, pStatus);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetTargetOidList(
    IMA_OID Oid,
    IMA_OID_LIST **ppList) {
	IMA_GetTargetOidListFn PassFunc;
	IMA_FreeMemoryFn FreeFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (ppList == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (Oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    Oid.objectType != IMA_OBJECT_TYPE_LNP)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetTargetOidListFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetTargetOidList");
#else
				PassFunc =
				    (IMA_GetTargetOidListFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetTargetOidList");
#endif

				if (PassFunc != NULL) {
					IMA_OID_LIST *ppOidList;
					IMA_UINT listSize;
					listSize = sizeof (IMA_OID_LIST);
					status = PassFunc(Oid, &ppOidList);
					if (IMA_SUCCESS(status)) {
						*ppList =
						    (IMA_OID_LIST*)calloc(1,
						    sizeof (IMA_OID_LIST) +
						    ((ppOidList->oidCount - 1)*
						    sizeof (IMA_OID)));

						if ((*ppList) == NULL) {
							return (EUOS_ERROR);
						}
						else
							memcpy((*ppList),
							    ppOidList, listSize
							    + (ppOidList->
							    oidCount - 1)*
							    sizeof (IMA_OID));
#ifdef WIN32
						FreeFunc = (IMA_FreeMemoryFn)
						    GetProcAddress(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#else
						FreeFunc = (IMA_FreeMemoryFn)
						    dlsym(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#endif
						if (FreeFunc != NULL) {
							FreeFunc(ppOidList);
						}
					}
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_RemoveStaleData(
    IMA_OID lhbaId) {
	IMA_RemoveStaleDataFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (lhbaId.objectType != IMA_OBJECT_TYPE_LHBA)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == lhbaId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_RemoveStaleDataFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_RemoveStaleData");
#else
				PassFunc = (IMA_RemoveStaleDataFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_RemoveStaleData");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(lhbaId);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetIsnsDiscovery(
    IMA_OID phbaId,
    IMA_BOOL enableIsnsDiscovery,
    IMA_ISNS_DISCOVERY_METHOD discoveryMethod,
    const IMA_HOST_ID *iSnsHost) {
	IMA_SetIsnsDiscoveryFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (enableIsnsDiscovery != IMA_TRUE &&
	    enableIsnsDiscovery != IMA_FALSE)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (enableIsnsDiscovery == IMA_TRUE && iSnsHost == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (discoveryMethod != IMA_ISNS_DISCOVERY_METHOD_STATIC &&
	    discoveryMethod != IMA_ISNS_DISCOVERY_METHOD_DHCP &&
	    discoveryMethod != IMA_ISNS_DISCOVERY_METHOD_SLP)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (phbaId.objectType != IMA_OBJECT_TYPE_PHBA &&
	    phbaId.objectType != IMA_OBJECT_TYPE_LHBA) {
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);
	}

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == phbaId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_SetIsnsDiscoveryFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetIsnsDiscovery");
#else
				PassFunc =
				    (IMA_SetIsnsDiscoveryFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetIsnsDiscovery");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(phbaId,
					    enableIsnsDiscovery,
					    discoveryMethod, iSnsHost);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetSlpDiscovery(
    IMA_OID phbaId,
    IMA_BOOL enableSlpDiscovery) {
	IMA_SetSlpDiscoveryFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (enableSlpDiscovery != IMA_TRUE &&
	    enableSlpDiscovery != IMA_FALSE)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (phbaId.objectType != IMA_OBJECT_TYPE_PHBA &&
	    phbaId.objectType != IMA_OBJECT_TYPE_LHBA)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == phbaId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_SetSlpDiscoveryFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetSlpDiscovery");
#else
				PassFunc = (IMA_SetSlpDiscoveryFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetSlpDiscovery");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(
					    phbaId,
					    enableSlpDiscovery);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetStaticDiscovery(
    IMA_OID phbaId,
    IMA_BOOL enableStaticDiscovery) {
	IMA_SetStaticDiscoveryFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (enableStaticDiscovery != IMA_TRUE &&
	    enableStaticDiscovery != IMA_FALSE)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (phbaId.objectType != IMA_OBJECT_TYPE_PHBA &&
	    phbaId.objectType != IMA_OBJECT_TYPE_LHBA)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == phbaId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_SetStaticDiscoveryFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetStaticDiscovery");
#else
				PassFunc = (IMA_SetStaticDiscoveryFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetStaticDiscovery");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(
					    phbaId,
					    enableStaticDiscovery);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetSendTargetsDiscovery(
    IMA_OID phbaId,
    IMA_BOOL enableSendTargetsDiscovery) {
	IMA_SetSendTargetsDiscoveryFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (enableSendTargetsDiscovery != IMA_TRUE &&
	    enableSendTargetsDiscovery != IMA_FALSE)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (phbaId.objectType != IMA_OBJECT_TYPE_PHBA &&
	    phbaId.objectType != IMA_OBJECT_TYPE_LHBA) {
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);
	}

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == phbaId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_SetSendTargetsDiscoveryFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetSendTargetsDiscovery");
#else
				PassFunc = (IMA_SetSendTargetsDiscoveryFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetSendTargetsDiscovery");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(
					    phbaId,
					    enableSendTargetsDiscovery);
				}
				os_releasemutex(
				    plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

/*
 * this forces plugins to rescan all iscsi targets on this
 * ipaddress/port and return a
 * list of discovered targets.
 * ERROR/todo:
 * according to IMA spec., pTargetOidList is allocated by
 * the caller for library to return data,
 * how does a caller know how much space it will be?
 * pTargetOidList should be allocated by the library/plugin
 * like IMA_GetLnpOidList
 */
IMA_API IMA_STATUS IMA_AddPhbaStaticDiscoveryTarget(
    IMA_OID phbaOid,
    const IMA_TARGET_ADDRESS targetAddress,
    IMA_OID_LIST **pTargetOidList) {
	IMA_AddPhbaStaticDiscoveryTargetFn PassFunc;
	IMA_FreeMemoryFn FreeFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {

		if (plugintable[i].ownerId == phbaOid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_AddPhbaStaticDiscoveryTargetFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_AddPhbaStaticDiscoveryTarget");
#else
				PassFunc =
				    (IMA_AddPhbaStaticDiscoveryTargetFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_AddPhbaStaticDiscoveryTarget");
#endif

				if (PassFunc != NULL) {
					IMA_OID_LIST *ppOidList;
					IMA_UINT listSize;
					listSize =
					    sizeof (IMA_OID_LIST);
					status = PassFunc(phbaOid,
					    targetAddress, &ppOidList);
					if (IMA_SUCCESS(status)) {

						(*pTargetOidList) =
						    (IMA_OID_LIST*)
						    calloc(1, listSize +
						    (ppOidList->oidCount-1)*
						    sizeof (IMA_OID));

						if ((*pTargetOidList) == NULL) {
							status =
							    EUOS_ERROR;
						}
						memcpy((*pTargetOidList),
						    ppOidList,
						    listSize +
						    (ppOidList->oidCount-1)*
						    sizeof (IMA_OID));
#ifdef WIN32
						FreeFunc = (IMA_FreeMemoryFn)
						    GetProcAddress(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#else
						FreeFunc = (IMA_FreeMemoryFn)
						    dlsym(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#endif
						if (FreeFunc != NULL) {
							FreeFunc(ppOidList);
						}
					}
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_RemovePhbaStaticDiscoveryTarget(
    IMA_OID phbaOid,
    IMA_OID targetOid) {
	IMA_RemovePhbaStaticDiscoveryTargetFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == targetOid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_RemovePhbaStaticDiscoveryTargetFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_RemovePhbaStaticDiscoveryTarget");
#else
				PassFunc =
				    (IMA_RemovePhbaStaticDiscoveryTargetFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_RemovePhbaStaticDiscoveryTarget");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(phbaOid, targetOid);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetPnpOidList(
    IMA_OID Oid,
    IMA_OID_LIST **ppList) {
	IMA_GetPnpOidListFn PassFunc;
	IMA_FreeMemoryFn FreeFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (ppList == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (Oid.objectType != IMA_OBJECT_TYPE_PHBA &&
	    Oid.objectType != IMA_OBJECT_TYPE_LNP)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;
	for (i = 0; i < number_of_plugins; i++) {

		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetPnpOidListFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetPnpOidList");
#else
				PassFunc = (IMA_GetPnpOidListFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetPnpOidList");
#endif

				if (PassFunc != NULL) {
					IMA_OID_LIST *ppOidList;

					status = PassFunc(Oid, &ppOidList);
					if (IMA_SUCCESS(status)) {
						IMA_UINT listSize;
						listSize =
						    sizeof (IMA_OID_LIST);
						*ppList = (IMA_OID_LIST*)
						    calloc(1, listSize +
						    (ppOidList->oidCount-1)*
						    sizeof (IMA_OID));

						if ((*ppList) == NULL) {
							status =
							    EUOS_ERROR;
						}
						else
							memcpy((*ppList),
							    ppOidList,
							    listSize +
							    (ppOidList->
							    oidCount - 1)*
							    sizeof (IMA_OID));
#ifdef WIN32
						FreeFunc = (IMA_FreeMemoryFn)
						    GetProcAddress(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#else
						FreeFunc = (IMA_FreeMemoryFn)
						    dlsym(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#endif
						if (FreeFunc != NULL) {
							FreeFunc(ppOidList);
						}
					}
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetPhbaDownloadProperties(
    IMA_OID phbaId,
    IMA_PHBA_DOWNLOAD_PROPERTIES *pProps) {
	IMA_GetPhbaDownloadPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (phbaId.objectType != IMA_OBJECT_TYPE_PHBA)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == phbaId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetPhbaDownloadPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetPhbaDownloadProperties");
#else
				PassFunc = (IMA_GetPhbaDownloadPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetPhbaDownloadProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(phbaId, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_IsPhbaDownloadFile(
    IMA_OID phbaId,
    const IMA_WCHAR *pFileName,
    IMA_PHBA_DOWNLOAD_IMAGE_PROPERTIES *pProps) {
	IMA_IsPhbaDownloadFileFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pFileName == NULL || pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (phbaId.objectType != IMA_OBJECT_TYPE_PHBA)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == phbaId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_IsPhbaDownloadFileFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_IsPhbaDownloadFile");
#else
				PassFunc = (IMA_IsPhbaDownloadFileFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_IsPhbaDownloadFile");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(
					    phbaId, pFileName, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_PhbaDownload(
    IMA_OID phbaId,
    IMA_PHBA_DOWNLOAD_IMAGE_TYPE imageType,
    const IMA_WCHAR *pFileName) {
	IMA_PhbaDownloadFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (phbaId.objectType != IMA_OBJECT_TYPE_PHBA)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	if (imageType != IMA_DOWNLOAD_IMAGE_TYPE_FIRMWARE &&
	    imageType != IMA_DOWNLOAD_IMAGE_TYPE_OPTION_ROM &&
	    imageType != IMA_DOWNLOAD_IMAGE_TYPE_ALL &&
	    imageType != IMA_DOWNLOAD_IMAGE_TYPE_BOOTCODE)
	    return (IMA_ERROR_INVALID_PARAMETER);

	if (pFileName == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == phbaId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_PhbaDownloadFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_PhbaDownload");
#else
				PassFunc = (IMA_PhbaDownloadFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_PhbaDownload");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(
					    phbaId, imageType, pFileName);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetNetworkPortalProperties(
    IMA_OID networkPortalId,
    IMA_NETWORK_PORTAL_PROPERTIES *pProps) {
	IMA_GetNetworkPortalPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (networkPortalId.objectType != IMA_OBJECT_TYPE_NETWORK_PORTAL)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == networkPortalId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetNetworkPortalPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetNetworkPortalProperties");
#else
				PassFunc =
				    (IMA_GetNetworkPortalPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetNetworkPortalProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(
					    networkPortalId, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetNetworkPortalIpAddress(
    IMA_OID networkPortalId,
    const IMA_IP_ADDRESS NewIpAddress) {
	IMA_SetNetworkPortalIpAddressFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (networkPortalId.objectType != IMA_OBJECT_TYPE_NETWORK_PORTAL)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == networkPortalId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_SetNetworkPortalIpAddressFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetNetworkPortalIpAddress");
#else
				PassFunc = (IMA_SetNetworkPortalIpAddressFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetNetworkPortalIpAddress");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(
					    networkPortalId, NewIpAddress);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetLnpOidList(
    IMA_OID_LIST **ppList) {
	IMA_GetLnpOidListFn PassFunc;
	IMA_FreeMemoryFn    FreeFunc;

	IMA_UINT i;
	IMA_UINT j;
	IMA_UINT totalIdCount;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (ppList == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	os_obtainmutex(libMutex);
	// Get total id count first
	totalIdCount = 0;

	for (i = 0; i < number_of_plugins; i++) {
		status = IMA_ERROR_UNEXPECTED_OS_ERROR;
		if (plugintable[i].hPlugin != NULL) {
			os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
			PassFunc = (IMA_GetLnpOidListFn)
			    GetProcAddress(plugintable[i].hPlugin,
			    "IMA_GetLnpOidList");
#else
			PassFunc = (IMA_GetLnpOidListFn)
			    dlsym(plugintable[i].hPlugin,
			    "IMA_GetLnpOidList");
#endif
			if (PassFunc != NULL) {
				IMA_OID_LIST *ppOidList;
				status = PassFunc(&ppOidList);
				if (status == IMA_STATUS_SUCCESS) {
					totalIdCount += ppOidList->oidCount;
#ifdef WIN32
					FreeFunc = (IMA_FreeMemoryFn)
					    GetProcAddress(
					    plugintable[i].hPlugin,
					    "IMA_FreeMemory");
#else
					FreeFunc = (IMA_FreeMemoryFn)
					    dlsym(plugintable[i].hPlugin,
					    "IMA_FreeMemory");
#endif
					if (FreeFunc != NULL) {
						FreeFunc(ppOidList);
					}
				}
			}
			os_releasemutex(plugintable[i].pluginMutex);
		}
		if (status != IMA_STATUS_SUCCESS) {
			break;
		}

	}


	*ppList = (IMA_OID_LIST*)calloc(1,
	    sizeof (IMA_OID_LIST) + (totalIdCount - 1)* sizeof (IMA_OID));

	if ((*ppList) == NULL) {
		os_releasemutex(libMutex);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(*ppList)->oidCount = totalIdCount;

	// 2nd pass to copy the id lists
	totalIdCount = 0;
	status = IMA_STATUS_SUCCESS;
	for (i = 0; i < number_of_plugins; i++) {
		status = IMA_ERROR_UNEXPECTED_OS_ERROR;
		if (plugintable[i].hPlugin != NULL) {
			os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
			PassFunc = (IMA_GetLnpOidListFn)
			    GetProcAddress(plugintable[i].hPlugin,
			    "IMA_GetLnpOidList");
#else
			PassFunc = (IMA_GetLnpOidListFn)
			    dlsym(plugintable[i].hPlugin,
			    "IMA_GetLnpOidList");
#endif
			if (PassFunc != NULL) {
				IMA_OID_LIST *ppOidList;
				status = PassFunc(&ppOidList);
				if (status == IMA_STATUS_SUCCESS) {
					for (j = 0; (j < ppOidList->oidCount) &&
					    (totalIdCount <
					    (*ppList)->oidCount);
					    j++) {
						(*ppList)->oids[totalIdCount].
						    objectType =
						    ppOidList->oids[j].
						    objectType;
						(*ppList)->oids[totalIdCount].
						    objectSequenceNumber =
						    ppOidList->oids[j].
						    objectSequenceNumber;

						(*ppList)->oids[totalIdCount].
						    ownerId =
						    ppOidList->oids[j].ownerId;
						totalIdCount++;
					}
#ifdef WIN32
					FreeFunc = (IMA_FreeMemoryFn)
					    GetProcAddress(
					    plugintable[i].hPlugin,
					    "IMA_FreeMemory");
#else
					FreeFunc = (IMA_FreeMemoryFn)
					    dlsym(plugintable[i].hPlugin,
					    "IMA_FreeMemory");
#endif
					if (FreeFunc != NULL) {
						FreeFunc(ppOidList);
					}
				}
			}
			os_releasemutex(plugintable[i].pluginMutex);
		}
		if (status != IMA_STATUS_SUCCESS) {
			free(*ppList);
			break;
		}

	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetLnpProperties(
    IMA_OID lnpId,
    IMA_LNP_PROPERTIES *pProps) {
	IMA_GetLnpPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (lnpId.objectType != IMA_OBJECT_TYPE_LNP)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == lnpId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetLnpPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetLnpProperties");
#else
				PassFunc = (IMA_GetLnpPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetLnpProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(lnpId, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetPnpProperties(
    IMA_OID pnpId,
    IMA_PNP_PROPERTIES *pProps) {
	IMA_GetPnpPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (pnpId.objectType != IMA_OBJECT_TYPE_PNP)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == pnpId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetPnpPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetPnpProperties");
#else
				PassFunc = (IMA_GetPnpPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetPnpProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(pnpId, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetPnpStatistics(
    IMA_OID pnpId,
    IMA_PNP_STATISTICS *pStats) {
	IMA_GetPnpStatisticsFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pStats == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (pnpId.objectType != IMA_OBJECT_TYPE_PNP)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == pnpId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetPnpStatisticsFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetPnpStatistics");
#else
				PassFunc = (IMA_GetPnpStatisticsFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetPnpStatistics");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(pnpId, pStats);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetTargetProperties(
    IMA_OID targetId,
    IMA_TARGET_PROPERTIES *pProps) {
	IMA_GetTargetPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (targetId.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == targetId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetTargetPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetTargetProperties");
#else
				PassFunc = (IMA_GetTargetPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetTargetProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(targetId, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

IMA_API	IMA_STATUS IMA_GetSessionProperties(
    IMA_OID sessionId,
    IMA_SESSION_PROPERTIES *pProps) {
	IMA_GetSessionPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (sessionId.objectType != IMA_OBJECT_TYPE_SESSION)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == sessionId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetSessionPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetSessionProperties");
#else
				PassFunc = (IMA_GetSessionPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetSessionProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(sessionId, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API	IMA_STATUS IMA_GetConnectionProperties(
    IMA_OID connectionId,
    IMA_CONNECTION_PROPERTIES *pProps) {
	IMA_GetConnectionPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (connectionId.objectType != IMA_OBJECT_TYPE_CONNECTION)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == connectionId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetConnectionPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetConnectionProperties");
#else
				PassFunc = (IMA_GetConnectionPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetConnectionProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(connectionId, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetTargetErrorStatistics(
    IMA_OID targetId,
    IMA_TARGET_ERROR_STATISTICS *pStats) {
	IMA_GetTargetErrorStatisticsFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pStats == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (targetId.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == targetId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetTargetErrorStatisticsFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetTargetErrorStatistics");
#else
				PassFunc = (IMA_GetTargetErrorStatisticsFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetTargetErrorStatistics");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(targetId, pStats);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetLuOidList(
    IMA_OID Oid,
    IMA_OID_LIST **ppList) {
	IMA_GetLuOidListFn PassFunc;
	IMA_FreeMemoryFn FreeFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (ppList == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (Oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    Oid.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {

		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetLuOidListFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetLuOidList");
#else
				PassFunc = (IMA_GetLuOidListFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetLuOidList");
#endif

				if (PassFunc != NULL) {
					IMA_OID_LIST *ppOidList;

					status = PassFunc(Oid, &ppOidList);
					if (IMA_SUCCESS(status)) {
						IMA_UINT listSize;
						listSize =
						    sizeof (IMA_OID_LIST);
						*ppList = (IMA_OID_LIST*)
						    calloc(1, listSize +
						    (ppOidList->oidCount - 1)*
						    sizeof (IMA_OID));

						if ((*ppList) == NULL) {
							status = EUOS_ERROR;
						}
						else
							memcpy((*ppList),
							    ppOidList,
							    listSize +
							    (ppOidList->
							    oidCount - 1)*
							    sizeof (IMA_OID));
#ifdef WIN32
						FreeFunc = (IMA_FreeMemoryFn)
						    GetProcAddress(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#else
						FreeFunc = (IMA_FreeMemoryFn)
						    dlsym(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#endif
						if (FreeFunc != NULL) {
							FreeFunc(ppOidList);
						}
					}
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetLuOid(
    IMA_OID targetId,
    IMA_UINT64 lun,
    IMA_OID *pluId) {
	IMA_GetLuOidFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pluId == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);


	if (targetId.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
		status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == targetId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(
				    plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetLuOidFn)
				    GetProcAddress(
				    plugintable[i].hPlugin,
				    "IMA_GetLuOid");
#else
				PassFunc = (IMA_GetLuOidFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetLuOid");
#endif

				if (PassFunc != NULL) {
					status =
					    PassFunc(targetId, lun, pluId);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetLuProperties(
    IMA_OID luId,
    IMA_LU_PROPERTIES *pProps) {
	IMA_GetLuPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (luId.objectType != IMA_OBJECT_TYPE_LU)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == luId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetLuPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetLuProperties");
#else
				PassFunc = (IMA_GetLuPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetLuProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(luId, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetStatisticsProperties(
    IMA_OID oid,
    IMA_STATISTICS_PROPERTIES *pProps) {
	IMA_GetStatisticsPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (oid.objectType != IMA_OBJECT_TYPE_TARGET &&
	    oid.objectType != IMA_OBJECT_TYPE_LU &&
	    oid.objectType != IMA_OBJECT_TYPE_PNP)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);


	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetStatisticsPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetStatisticsProperties");
#else
				PassFunc =
				    (IMA_GetStatisticsPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetStatisticsProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(oid, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetDeviceStatistics(
    IMA_OID oid,
    IMA_DEVICE_STATISTICS *pStats) {
	IMA_GetDeviceStatisticsFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pStats == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (oid.objectType != IMA_OBJECT_TYPE_LU &&
	    oid.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetDeviceStatisticsFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetDeviceStatistics");
#else
				PassFunc =
				    (IMA_GetDeviceStatisticsFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetDeviceStatistics");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(oid, pStats);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_LuInquiry(
    IMA_OID deviceId,
    IMA_BOOL evpd,
    IMA_BOOL cmddt,
    IMA_BYTE pageCode,

    IMA_BYTE *pOutputBuffer,
    IMA_UINT *pOutputBufferLength,

    IMA_BYTE *pSenseBuffer,
    IMA_UINT *pSenseBufferLength) {
	IMA_LuInquiryFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pOutputBuffer == NULL || pOutputBufferLength == NULL ||
	    *pOutputBufferLength == 0 ||
	    (pSenseBuffer == NULL && pSenseBufferLength != NULL &&
	    *pSenseBufferLength != 0))
		return (IMA_ERROR_INVALID_PARAMETER);

	if ((evpd != IMA_TRUE && evpd != IMA_FALSE) ||
	    (cmddt != IMA_TRUE && cmddt != IMA_FALSE))
		return (IMA_ERROR_INVALID_PARAMETER);

	if (deviceId.objectType != IMA_OBJECT_TYPE_TARGET &&
	    deviceId.objectType != IMA_OBJECT_TYPE_LU)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == deviceId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_LuInquiryFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_LuInquiry");
#else
				PassFunc = (IMA_LuInquiryFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_LuInquiry");
#endif

				if (PassFunc != NULL) {
					status =
					    PassFunc(deviceId, evpd,
					    cmddt, pageCode,
					    pOutputBuffer, pOutputBufferLength,
					    pSenseBuffer, pSenseBufferLength);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_LuReadCapacity(
    IMA_OID deviceId,
    IMA_UINT cdbLength,
    IMA_BYTE *pOutputBuffer,
    IMA_UINT *pOutputBufferLength,

    IMA_BYTE *pSenseBuffer,
    IMA_UINT *pSenseBufferLength) {
	IMA_LuReadCapacityFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (cdbLength != 10 && cdbLength != 16)
		return (IMA_ERROR_INVALID_PARAMETER);

	if ((pOutputBuffer == NULL || pOutputBufferLength == NULL ||
	    *pOutputBufferLength == 0) ||
	    (pSenseBuffer == NULL && pSenseBufferLength != NULL &&
	    *pSenseBufferLength != 0))
		return (IMA_ERROR_INVALID_PARAMETER);

	if (deviceId.objectType != IMA_OBJECT_TYPE_TARGET &&
	    deviceId.objectType != IMA_OBJECT_TYPE_LU)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == deviceId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_LuReadCapacityFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_LuReadCapacity");
#else
				PassFunc = (IMA_LuReadCapacityFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_LuReadCapacity");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(deviceId, cdbLength,
					    pOutputBuffer, pOutputBufferLength,
					    pSenseBuffer, pSenseBufferLength);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_LuReportLuns(
    IMA_OID deviceId,
    IMA_BOOL sendToWellKnownLun,
    IMA_BYTE selectReport,

    IMA_BYTE *pOutputBuffer,
    IMA_UINT *pOutputBufferLength,

    IMA_BYTE *pSenseBuffer,
    IMA_UINT *pSenseBufferLength) {
	IMA_LuReportLunsFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if ((pOutputBuffer == NULL || pOutputBufferLength == NULL ||
	    *pOutputBufferLength == 0) ||
	    (pSenseBuffer == NULL && pSenseBufferLength != NULL &&
	    *pSenseBufferLength != 0))
		return (IMA_ERROR_INVALID_PARAMETER);

	if (sendToWellKnownLun != IMA_TRUE && sendToWellKnownLun != IMA_FALSE)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (deviceId.objectType != IMA_OBJECT_TYPE_TARGET &&
	    deviceId.objectType != IMA_OBJECT_TYPE_LU)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == deviceId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_LuReportLunsFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_LuReportLuns");
#else
				PassFunc = (IMA_LuReportLunsFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_LuReportLuns");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(deviceId,
					    sendToWellKnownLun, selectReport,
					    pOutputBuffer, pOutputBufferLength,
					    pSenseBuffer, pSenseBufferLength);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

IMA_API IMA_STATUS IMA_ExposeLu(
    IMA_OID luId) {
	IMA_ExposeLuFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (luId.objectType != IMA_OBJECT_TYPE_LU)
		return (IMA_ERROR_INVALID_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == luId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_ExposeLuFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_ExposeLu");

#else
				PassFunc = (IMA_ExposeLuFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_ExposeLu");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(luId);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_UnexposeLu(
    IMA_OID luId) {
	IMA_UnexposeLuFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (luId.objectType != IMA_OBJECT_TYPE_LU)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == luId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_UnexposeLuFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_UnexposeLu");
#else
				PassFunc = (IMA_UnexposeLuFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_UnexposeLu");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(luId);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetPhbaStatus(
    IMA_OID hbaId,
    IMA_PHBA_STATUS *pStatus) {
	IMA_GetPhbaStatusFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pStatus == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (hbaId.objectType != IMA_OBJECT_TYPE_PHBA)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == hbaId.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetPhbaStatusFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetPhbaStatus");
#else
				PassFunc = (IMA_GetPhbaStatusFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetPhbaStatus");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(hbaId, pStatus);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_RegisterForObjectVisibilityChanges(
    IMA_OBJECT_VISIBILITY_FN pClientFn) {
	IMA_RegisterForObjectVisibilityChangesFn PassFunc;
	IMA_UINT i;
	IMA_UINT j;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pClientFn == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	os_obtainmutex(libMutex);

	status = IMA_STATUS_SUCCESS;
	for (i = 0; i < number_of_plugins; i++) {
		status = IMA_ERROR_UNEXPECTED_OS_ERROR;
		if (plugintable[i].hPlugin != NULL) {
			os_obtainmutex(plugintable[i].pluginMutex);
			if (plugintable[i].number_of_vbcallbacks >=
			    IMA_MAX_CALLBACK_PER_PLUGIN) {
				os_releasemutex(plugintable[i].pluginMutex);
				continue;
			}

			/* check if registered already */
			for (j = 0;
			    j < plugintable[i].number_of_vbcallbacks; j++) {
				if (plugintable[i].vbcallback[j] == pClientFn) {
					status = IMA_STATUS_SUCCESS;
					break;
				}
			}
			if (status != IMA_STATUS_SUCCESS) {

#ifdef WIN32
				PassFunc =
				    (IMA_RegisterForObjectVisibilityChangesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_RegisterForObjectVisibilityChanges");
#else
				PassFunc =
				    (IMA_RegisterForObjectVisibilityChangesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_RegisterForObjectVisibilityChanges");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(VisibilityCallback);
					if (status == IMA_STATUS_SUCCESS) {
						j = plugintable[i].
						    number_of_vbcallbacks;
						plugintable[i].vbcallback[j] =
						    pClientFn;
						plugintable[i].
						    number_of_vbcallbacks++;
					}

				}
			}
			os_releasemutex(plugintable[i].pluginMutex);
		}
		if (status != IMA_STATUS_SUCCESS)
			break;

	}
	os_releasemutex(libMutex);
	return (status);

}


IMA_API IMA_STATUS IMA_DeregisterForObjectVisibilityChanges(
    IMA_OBJECT_VISIBILITY_FN pClientFn) {
	IMA_DeregisterForObjectVisibilityChangesFn PassFunc;
	IMA_UINT i;
	IMA_UINT j;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pClientFn == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	os_obtainmutex(libMutex);

	status = IMA_STATUS_SUCCESS;
	for (i = 0; i < number_of_plugins; i++) {
		status = IMA_ERROR_UNEXPECTED_OS_ERROR;
		if (plugintable[i].hPlugin != NULL) {
			os_obtainmutex(plugintable[i].pluginMutex);
			/* check if deregistered already */
			status = IMA_STATUS_SUCCESS;
			for (j = 0;
			    j < plugintable[i].number_of_vbcallbacks; j++) {
				if (plugintable[i].vbcallback[j] == pClientFn) {
					/*
					 * use IMA_ERROR_UNKNOWN_ERROR
					 * as a flag
					 */
					status = IMA_ERROR_UNKNOWN_ERROR;
					break;
				}
			}

			if (status != IMA_STATUS_SUCCESS) {

#ifdef WIN32
				PassFunc =
				    (IMA_DeregisterForObjectVisibilityChangesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_DeregisterForObjectVisibilityChanges");
#else
				PassFunc =
				    (IMA_DeregisterForObjectVisibilityChangesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_DeregisterForObjectVisibilityChanges");
#endif
				if (PassFunc != NULL) {
					status = PassFunc(VisibilityCallback);
					if (status == IMA_STATUS_SUCCESS) {
						/*
						 * where plugintable[i].
						 * vbcallback[j] == pClientFn
						 */
						for (; j <
						    plugintable[i].
						    number_of_vbcallbacks;
						    j++) {
							plugintable[i].
							    vbcallback[j] =
							    plugintable[i].
							    vbcallback[j+1];

						}
						plugintable[i].
						    number_of_vbcallbacks--;
					}
				}
			}
			os_releasemutex(plugintable[i].pluginMutex);
		}
		if (status != IMA_STATUS_SUCCESS)
			break;
	}
	os_releasemutex(libMutex);
	return (status);

}


IMA_API IMA_STATUS IMA_RegisterForObjectPropertyChanges(
    IMA_OBJECT_PROPERTY_FN pClientFn) {
	IMA_RegisterForObjectPropertyChangesFn PassFunc;
	IMA_UINT i;
	IMA_UINT j;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pClientFn == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	os_obtainmutex(libMutex);

	status = IMA_STATUS_SUCCESS;
	for (i = 0; i < number_of_plugins; i++) {
		status = IMA_ERROR_UNEXPECTED_OS_ERROR;
		if (plugintable[i].hPlugin != NULL) {
			os_obtainmutex(plugintable[i].pluginMutex);
			if (plugintable[i].number_of_pccallbacks >=
			    IMA_MAX_CALLBACK_PER_PLUGIN) {
				os_releasemutex(plugintable[i].pluginMutex);
				continue;
			}

			/* check if registered already */
			for (j = 0;
			    j < plugintable[i].number_of_pccallbacks;
			    j++) {
				if (plugintable[i].pccallback[j] ==
				    pClientFn) {
					status = IMA_STATUS_SUCCESS;
					break;
				}
			}
			if (status != IMA_STATUS_SUCCESS) {

#ifdef WIN32
				PassFunc =
				    (IMA_RegisterForObjectPropertyChangesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_RegisterForObjectPropertyChanges");
#else
				PassFunc =
				    (IMA_RegisterForObjectPropertyChangesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_RegisterForObjectPropertyChanges");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(PropertyCallback);
					if (status == IMA_STATUS_SUCCESS) {
						j = plugintable[i].
						    number_of_pccallbacks;
						plugintable[i].pccallback[j] =
						    pClientFn;
						plugintable[i].
						    number_of_pccallbacks++;
					}

				}
			}
			os_releasemutex(plugintable[i].pluginMutex);
		}
		if (status != IMA_STATUS_SUCCESS)
			break;

	}
	os_releasemutex(libMutex);
	return (status);

}


IMA_API IMA_STATUS IMA_DeregisterForObjectPropertyChanges(
    IMA_OBJECT_PROPERTY_FN pClientFn) {
	IMA_DeregisterForObjectPropertyChangesFn PassFunc;
	IMA_UINT i;
	IMA_UINT j;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pClientFn == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	os_obtainmutex(libMutex);
	status = IMA_STATUS_SUCCESS;
	for (i = 0; i < number_of_plugins; i++) {
		status = IMA_ERROR_UNEXPECTED_OS_ERROR;
		if (plugintable[i].hPlugin != NULL) {
			os_obtainmutex(plugintable[i].pluginMutex);
			/* check if deregistered already */
			status = IMA_STATUS_SUCCESS;
			for (j = 0;
			    j < plugintable[i].number_of_pccallbacks;
			    j++) {
				if (plugintable[i].pccallback[j] ==
				    pClientFn) {
					/*
					 * use IMA_ERROR_UNKNOWN_ERROR
					 * as a flag
					 */
					status = IMA_ERROR_UNKNOWN_ERROR;
					break;
				}
			}

			if (status != IMA_STATUS_SUCCESS) {

#ifdef WIN32
				PassFunc =
				    (IMA_DeregisterForObjectPropertyChangesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_DeregisterForObjectPropertyChanges");

#else
				PassFunc =
				    (IMA_DeregisterForObjectPropertyChangesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_DeregisterForObjectPropertyChanges");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(PropertyCallback);
					if (status == IMA_STATUS_SUCCESS) {
					/*
					 * where plugintable[i].vbcallback[
					 * j] == pClientFn
					 */
						for (; j < plugintable[i].
						    number_of_pccallbacks;
						    j++) {
							plugintable[i].
							    pccallback[j]
							    = plugintable[i].
							    pccallback[j+1];

						}
						plugintable[i].
						    number_of_pccallbacks--;
					}

				}
			}
			os_releasemutex(plugintable[i].pluginMutex);
		}
		if (status != IMA_STATUS_SUCCESS)
			break;

	}
	os_releasemutex(libMutex);
	return (status);

}


IMA_API IMA_STATUS IMA_GetIpProperties(
    IMA_OID oid,
    IMA_IP_PROPERTIES *pProps) {
	IMA_GetIpPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (oid.objectType != IMA_OBJECT_TYPE_PNP)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetIpPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetIpProperties");
#else
				PassFunc = (IMA_GetIpPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetIpProperties");
#endif
				if (PassFunc != NULL) {
					status = PassFunc(oid, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetIpConfigMethod(
    IMA_OID oid,
    IMA_BOOL enableDhcpIpConfiguration) {
	IMA_SetIpConfigMethodFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (enableDhcpIpConfiguration != IMA_TRUE &&
	    enableDhcpIpConfiguration != IMA_FALSE)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (oid.objectType != IMA_OBJECT_TYPE_PNP)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_SetIpConfigMethodFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetIpConfigMethod");
#else
				PassFunc = (IMA_SetIpConfigMethodFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetIpConfigMethod");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(oid,
					    enableDhcpIpConfiguration);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

IMA_API IMA_STATUS IMA_SetSubnetMask(
    IMA_OID oid,
    IMA_IP_ADDRESS subnetMask) {
	IMA_SetSubnetMaskFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (oid.objectType != IMA_OBJECT_TYPE_PNP)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_SetSubnetMaskFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetSubnetMask");
#else
				PassFunc = (IMA_SetSubnetMaskFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetSubnetMask");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(oid, subnetMask);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetDnsServerAddress(
    IMA_OID oid,
    const IMA_IP_ADDRESS *primaryDnsServerAddress,
    const IMA_IP_ADDRESS *alternateDnsServerAddress) {
	IMA_SetDnsServerAddressFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (primaryDnsServerAddress == NULL &&
	    alternateDnsServerAddress != NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (primaryDnsServerAddress != NULL &&
	    alternateDnsServerAddress != NULL &&
	    memcmp(primaryDnsServerAddress->ipAddress,
	    alternateDnsServerAddress->ipAddress,
	    sizeof (primaryDnsServerAddress->ipAddress)) == 0)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (oid.objectType != IMA_OBJECT_TYPE_PNP)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_SetDnsServerAddressFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetDnsServerAddress");
#else
				PassFunc = (IMA_SetDnsServerAddressFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetDnsServerAddress");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(oid,
					    primaryDnsServerAddress,
					    alternateDnsServerAddress);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_SetDefaultGateway(
    IMA_OID oid,
    IMA_IP_ADDRESS defaultGateway) {
	IMA_SetDefaultGatewayFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (oid.objectType != IMA_OBJECT_TYPE_PNP)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_SetDefaultGatewayFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetDefaultGateway");
#else
				PassFunc = (IMA_SetDefaultGatewayFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetDefaultGateway");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(oid, defaultGateway);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetSupportedAuthMethods(
    IMA_OID lhbaOid,
    IMA_BOOL getSettableMethods,
    IMA_UINT *pMethodCount,
    IMA_AUTHMETHOD *pMethodList) {
	IMA_GetSupportedAuthMethodsFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pMethodCount == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (lhbaOid.objectType != IMA_OBJECT_TYPE_LHBA)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == lhbaOid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetSupportedAuthMethodsFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetSupportedAuthMethods");
#else
				PassFunc = (IMA_GetSupportedAuthMethodsFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetSupportedAuthMethods");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(lhbaOid,
					    getSettableMethods,
					    pMethodCount, pMethodList);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetInUseInitiatorAuthMethods(
    IMA_OID lhbaOid,
    IMA_UINT *pMethodCount,
    IMA_AUTHMETHOD *pMethodList) {
	IMA_GetInUseInitiatorAuthMethodsFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pMethodCount == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (lhbaOid.objectType != IMA_OBJECT_TYPE_LHBA)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == lhbaOid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetInUseInitiatorAuthMethodsFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetInUseInitiatorAuthMethods");
#else
				PassFunc = (IMA_GetInUseInitiatorAuthMethodsFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetInUseInitiatorAuthMethods");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(lhbaOid,
					    pMethodCount, pMethodList);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}


IMA_API IMA_STATUS IMA_GetInitiatorAuthParms(
    IMA_OID lhbaOid,
    IMA_AUTHMETHOD method,
    IMA_INITIATOR_AUTHPARMS *pParms) {
	IMA_GetInitiatorAuthParmsFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pParms == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (lhbaOid.objectType != IMA_OBJECT_TYPE_LHBA)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	if (method != IMA_AUTHMETHOD_NONE &&
	    method != IMA_AUTHMETHOD_CHAP &&
	    method != IMA_AUTHMETHOD_SRP &&
	    method != IMA_AUTHMETHOD_KRB5 &&
	    method != IMA_AUTHMETHOD_SPKM1 &&
	    method != IMA_AUTHMETHOD_SPKM2)
		return (IMA_ERROR_INVALID_PARAMETER);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == lhbaOid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetInitiatorAuthParmsFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetInitiatorAuthParms");
#else
				PassFunc = (IMA_GetInitiatorAuthParmsFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetInitiatorAuthParms");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(lhbaOid,
					    method, pParms);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

IMA_API IMA_STATUS IMA_SetInitiatorAuthMethods(
    IMA_OID lhbaOid,
    IMA_UINT methodCount,
    const IMA_AUTHMETHOD *pMethodList) {
	IMA_SetInitiatorAuthMethodsFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (methodCount == 0 || pMethodList == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (lhbaOid.objectType != IMA_OBJECT_TYPE_LHBA)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == lhbaOid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_SetInitiatorAuthMethodsFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetInitiatorAuthMethods");
#else
				PassFunc = (IMA_SetInitiatorAuthMethodsFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetInitiatorAuthMethods");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(lhbaOid,
					    methodCount, pMethodList);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

IMA_API IMA_STATUS IMA_SetInitiatorAuthParms(
    IMA_OID lhbaOid,
    IMA_AUTHMETHOD method,
    const IMA_INITIATOR_AUTHPARMS *pParms) {

	IMA_SetInitiatorAuthParmsFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pParms == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (method != IMA_AUTHMETHOD_NONE &&
	    method != IMA_AUTHMETHOD_CHAP &&
	    method != IMA_AUTHMETHOD_SRP &&
	    method != IMA_AUTHMETHOD_KRB5 &&
	    method != IMA_AUTHMETHOD_SPKM1 &&
	    method != IMA_AUTHMETHOD_SPKM2)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (lhbaOid.objectType != IMA_OBJECT_TYPE_LHBA)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == lhbaOid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_SetInitiatorAuthParmsFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_SetInitiatorAuthParms");
#else
				PassFunc = (IMA_SetInitiatorAuthParmsFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_SetInitiatorAuthParms");
#endif

				if (PassFunc != NULL) {
					status =
					    PassFunc(
					    lhbaOid, method, pParms);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

IMA_API IMA_STATUS IMA_GetStaticDiscoveryTargetOidList(
    IMA_OID oid,
    IMA_OID_LIST **ppList) {
	IMA_GetStaticDiscoveryTargetOidListFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (ppList == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    oid.objectType != IMA_OBJECT_TYPE_PNP)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;
	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetStaticDiscoveryTargetOidListFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetStaticDiscoveryTargetOidList");
#else
				PassFunc =
				    (IMA_GetStaticDiscoveryTargetOidListFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetStaticDiscoveryTargetOidList");
#endif
				if (PassFunc != NULL) {
					status = PassFunc(oid, ppList);
				}

				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

IMA_API IMA_STATUS IMA_GetDiscoveryProperties(
    IMA_OID oid,
    IMA_DISCOVERY_PROPERTIES *pProps) {
	IMA_GetDiscoveryPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (oid.objectType != IMA_OBJECT_TYPE_PHBA &&
	    oid.objectType != IMA_OBJECT_TYPE_LHBA)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;
	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetDiscoveryPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetDiscoveryProperties");
#else
				PassFunc = (IMA_GetDiscoveryPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetDiscoveryProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(oid, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

IMA_API IMA_STATUS IMA_AddDiscoveryAddress(
    IMA_OID oid,
    const IMA_TARGET_ADDRESS discoveryAddress,
    IMA_OID *pDiscoveryAddressOid) {
	IMA_AddDiscoveryAddressFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    oid.objectType != IMA_OBJECT_TYPE_PNP)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;
	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_AddDiscoveryAddressFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_AddDiscoveryAddress");
#else
				PassFunc = (IMA_AddDiscoveryAddressFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_AddDiscoveryAddress");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(oid,
					    discoveryAddress,
					    pDiscoveryAddressOid);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

IMA_API IMA_STATUS IMA_AddStaticDiscoveryTarget(
    IMA_OID oid,
    const IMA_STATIC_DISCOVERY_TARGET staticDiscoveryTarget,
    IMA_OID *pStaticDiscoveryTargetOid) {
	IMA_AddStaticDiscoveryTargetFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    oid.objectType != IMA_OBJECT_TYPE_PNP)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;
	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_AddStaticDiscoveryTargetFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_AddStaticDiscoveryTarget");

#else
				PassFunc = (IMA_AddStaticDiscoveryTargetFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_AddStaticDiscoveryTarget");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(oid,
					    staticDiscoveryTarget,
					    pStaticDiscoveryTargetOid);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

IMA_API IMA_STATUS IMA_CommitHbaParameters(IMA_OID oid,
    IMA_COMMIT_LEVEL commitLevel)
{
	IMA_CommitHbaParametersFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (oid.objectType != IMA_OBJECT_TYPE_LHBA &&
	    oid.objectType != IMA_OBJECT_TYPE_PHBA)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;
	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_CommitHbaParametersFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_CommitHbaParameters");
#else
				PassFunc = (IMA_CommitHbaParametersFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_CommitHbaParameters");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(oid, commitLevel);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

IMA_API IMA_STATUS IMA_RemoveStaticDiscoveryTarget(
    IMA_OID oid) {
	IMA_RemoveStaticDiscoveryTargetFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (oid.objectType != IMA_OBJECT_TYPE_STATIC_DISCOVERY_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_RemoveStaticDiscoveryTargetFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_RemoveStaticDiscoveryTarget");
#else
				PassFunc = (IMA_RemoveStaticDiscoveryTargetFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_RemoveStaticDiscoveryTarget");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(oid);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

IMA_API IMA_STATUS IMA_GetStaticDiscoveryTargetProperties(
    IMA_OID staticDiscoveryTargetOid,
    IMA_STATIC_DISCOVERY_TARGET_PROPERTIES *pProps) {
	IMA_GetStaticDiscoveryTargetPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (staticDiscoveryTargetOid.objectType !=
	    IMA_OBJECT_TYPE_STATIC_DISCOVERY_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId ==
		    staticDiscoveryTargetOid.ownerId) {

			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetStaticDiscoveryTargetPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetStaticDiscoveryTargetProperties");
#else
				PassFunc =
				    (IMA_GetStaticDiscoveryTargetPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetStaticDiscoveryTargetProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(
					    staticDiscoveryTargetOid, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

IMA_API IMA_STATUS IMA_GetDiscoveryAddressOidList(
    IMA_OID Oid,
    IMA_OID_LIST **ppList) {

	IMA_GetDiscoveryAddressOidListFn PassFunc;
	IMA_FreeMemoryFn FreeFunc;

	IMA_UINT i;
	IMA_UINT j;
	IMA_UINT totalIdCount;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (ppList == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if ((Oid.objectType != IMA_OBJECT_TYPE_LHBA) &&
	    (Oid.objectType != IMA_OBJECT_TYPE_PNP)) {
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);
	}

	os_obtainmutex(libMutex);
	// Get total id count first
	totalIdCount = 0;

	status = IMA_ERROR_OBJECT_NOT_FOUND;
	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetDiscoveryAddressOidListFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetDiscoveryAddressOidList");
#else
				PassFunc = (IMA_GetDiscoveryAddressOidListFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetDiscoveryAddressOidList");
#endif
				if (PassFunc != NULL) {
					IMA_OID_LIST *ppOidList;
					status = PassFunc(Oid, &ppOidList);
					if (status == IMA_STATUS_SUCCESS) {
						totalIdCount +=
						    ppOidList->oidCount;
#ifdef WIN32
						FreeFunc = (IMA_FreeMemoryFn)
						    GetProcAddress(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#else
						FreeFunc = (IMA_FreeMemoryFn)
						    dlsym(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#endif
						if (FreeFunc != NULL) {
							FreeFunc(ppOidList);
						}
					}
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}
			if (status != IMA_STATUS_SUCCESS) {
				break;
			}
		}
	}

	*ppList = (IMA_OID_LIST*)calloc(1, sizeof (IMA_OID_LIST) +
	    (totalIdCount - 1)* sizeof (IMA_OID));

	if ((*ppList) == NULL) {
		os_releasemutex(libMutex);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}
	(*ppList)->oidCount = totalIdCount;

	// 2nd pass to copy the id lists
	totalIdCount = 0;
	status = IMA_ERROR_OBJECT_NOT_FOUND;
	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetDiscoveryAddressOidListFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetDiscoveryAddressOidList");
#else
				PassFunc = (IMA_GetDiscoveryAddressOidListFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetDiscoveryAddressOidList");
#endif
				if (PassFunc != NULL) {
					IMA_OID_LIST *ppOidList;
					status = PassFunc(Oid, &ppOidList);
					if (status == IMA_STATUS_SUCCESS) {
						for (j = 0;
						    (j < ppOidList->oidCount) &&
						    (totalIdCount <
						    (*ppList)->oidCount);
						    j++) {
#define	OBJ_SEQ_NUM ppOidList->oids[j].objectSequenceNumber
							(*ppList)->oids
							    [totalIdCount].
							    objectType =
							    ppOidList->oids[j].
							    objectType;
							(*ppList)->oids[
							    totalIdCount].
							    objectSequenceNumber
							    = OBJ_SEQ_NUM;
							(*ppList)->oids[
							    totalIdCount].
							    ownerId =
							    ppOidList->
							    oids[j].ownerId;
							totalIdCount++;
#undef OBJ_SEQ_NUM
						}
#ifdef WIN32
						FreeFunc = (IMA_FreeMemoryFn)
						    GetProcAddress(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#else
						FreeFunc = (IMA_FreeMemoryFn)
						    dlsym(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#endif
						if (FreeFunc != NULL) {
							FreeFunc(ppOidList);
						}
					}
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}
			if (status != IMA_STATUS_SUCCESS) {
				free(*ppList);
				break;
			}
		}
	}

	os_releasemutex(libMutex);
	return (status);

}

IMA_API IMA_STATUS IMA_GetSessionOidList(
    IMA_OID Oid,
    IMA_OID_LIST **ppList) {

	IMA_GetSessionOidListFn PassFunc;
	IMA_FreeMemoryFn FreeFunc;

	IMA_UINT i;
	IMA_UINT j;
	IMA_UINT totalIdCount;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (ppList == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if ((Oid.objectType != IMA_OBJECT_TYPE_LHBA) &&
	    (Oid.objectType != IMA_OBJECT_TYPE_TARGET)) {
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);
	}

	os_obtainmutex(libMutex);
	// Get total id count first
	totalIdCount = 0;

	status = IMA_ERROR_OBJECT_NOT_FOUND;
	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetSessionOidListFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetSessionOidList");
#else
				PassFunc = (IMA_GetSessionOidListFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetSessionOidList");
#endif
				if (PassFunc != NULL) {
					IMA_OID_LIST *ppOidList;
					status = PassFunc(Oid, &ppOidList);
					if (status == IMA_STATUS_SUCCESS) {
						totalIdCount +=
						    ppOidList->oidCount;
#ifdef WIN32
						FreeFunc = (IMA_FreeMemoryFn)
						    GetProcAddress(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#else
						FreeFunc = (IMA_FreeMemoryFn)
						    dlsym(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#endif
						if (FreeFunc != NULL) {
							FreeFunc(ppOidList);
						}
					}

				}
				os_releasemutex(plugintable[i].pluginMutex);
			}
			if (status != IMA_STATUS_SUCCESS) {
				break;
			}
		}
	}

	*ppList = (IMA_OID_LIST*)calloc(1, sizeof (IMA_OID_LIST) +
	    (totalIdCount - 1)* sizeof (IMA_OID));

	if ((*ppList) == NULL) {
		os_releasemutex(libMutex);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}
	(*ppList)->oidCount = totalIdCount;

	// 2nd pass to copy the id lists
	totalIdCount = 0;
	status = IMA_ERROR_OBJECT_NOT_FOUND;
	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetSessionOidListFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetSessionOidList");
#else
				PassFunc = (IMA_GetSessionOidListFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetSessionOidList");
#endif
				if (PassFunc != NULL) {
					IMA_OID_LIST *ppOidList;
					status = PassFunc(Oid, &ppOidList);
					if (status == IMA_STATUS_SUCCESS) {
						for (j = 0;
						    (j < ppOidList->oidCount) &&
						    (totalIdCount <
						    (*ppList)->oidCount);
						    j++) {

#define	OBJ_SEQ_NUM ppOidList->oids[j].objectSequenceNumber
							(*ppList)->oids[
							    totalIdCount].
							    objectType =
							    ppOidList->oids[j].
							    objectType;
							(*ppList)->oids[
							    totalIdCount].
							    objectSequenceNumber
							    = OBJ_SEQ_NUM;
							(*ppList)->oids[
							    totalIdCount].
							    ownerId =
							    ppOidList->oids[j].
							    ownerId;
							totalIdCount++;
#undef OBJ_SEQ_NUM
						}
#ifdef WIN32
						FreeFunc = (IMA_FreeMemoryFn)
						    GetProcAddress(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#else
						FreeFunc = (IMA_FreeMemoryFn)
						    dlsym(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#endif
						if (FreeFunc != NULL) {
							FreeFunc(ppOidList);
						}
					}
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}
			if (status != IMA_STATUS_SUCCESS) {
				free(*ppList);
				break;
			}
		}
	}

	os_releasemutex(libMutex);
	return (status);

}

IMA_API IMA_STATUS IMA_GetConnectionOidList(
    IMA_OID Oid,
    IMA_OID_LIST **ppList) {

	IMA_GetSessionOidListFn PassFunc;
	IMA_FreeMemoryFn FreeFunc;

	IMA_UINT i;
	IMA_UINT j;
	IMA_UINT totalIdCount;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (ppList == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (Oid.objectType != IMA_OBJECT_TYPE_SESSION) {
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);
	}

	os_obtainmutex(libMutex);
	// Get total id count first
	totalIdCount = 0;

	status = IMA_ERROR_OBJECT_NOT_FOUND;
	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetConnectionOidListFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetConnectionOidList");
#else
				PassFunc = (IMA_GetConnectionOidListFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetConnectionOidList");
#endif
				if (PassFunc != NULL) {
					IMA_OID_LIST *ppOidList;
					status = PassFunc(Oid, &ppOidList);
					if (status == IMA_STATUS_SUCCESS) {
						totalIdCount +=
						    ppOidList->oidCount;
#ifdef WIN32
						FreeFunc = (IMA_FreeMemoryFn)
						    GetProcAddress(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#else
						FreeFunc = (IMA_FreeMemoryFn)
						    dlsym(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#endif
						if (FreeFunc != NULL) {
							FreeFunc(ppOidList);
						}
					}

				}
				os_releasemutex(plugintable[i].pluginMutex);
			}
			if (status != IMA_STATUS_SUCCESS) {
				break;
			}
		}
	}


	*ppList = (IMA_OID_LIST*)calloc(1, sizeof (IMA_OID_LIST)
	    + (totalIdCount - 1)* sizeof (IMA_OID));

	if ((*ppList) == NULL) {
		os_releasemutex(libMutex);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}
	(*ppList)->oidCount = totalIdCount;

	// 2nd pass to copy the id lists
	totalIdCount = 0;
	status = IMA_ERROR_OBJECT_NOT_FOUND;
	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == Oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetConnectionOidListFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetConnectionOidList");
#else
				PassFunc = (IMA_GetConnectionOidListFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetConnectionOidList");
#endif
				if (PassFunc != NULL) {
					IMA_OID_LIST *ppOidList;
					status = PassFunc(Oid, &ppOidList);
					if (status == IMA_STATUS_SUCCESS) {
						for (j = 0; (
						    j < ppOidList->oidCount) &&
						    (totalIdCount <
						    (*ppList)->oidCount);
						    j++) {
#define	OBJ_SEQ_NUM ppOidList->oids[j].objectSequenceNumber
							(*ppList)->
							    oids[totalIdCount].
							    objectType =
							    ppOidList->
							    oids[j].objectType;
							(*ppList)->
							    oids[totalIdCount].
							    objectSequenceNumber
							    = OBJ_SEQ_NUM;
							(*ppList)->
							    oids[totalIdCount].
							    ownerId =
							    ppOidList->oids[j].
							    ownerId;
							totalIdCount++;
#undef OBJ_SEQ_NUM
						}
#ifdef WIN32
						FreeFunc = (IMA_FreeMemoryFn)
						    GetProcAddress(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#else
						FreeFunc = (IMA_FreeMemoryFn)
						    dlsym(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#endif
						if (FreeFunc != NULL) {
							FreeFunc(ppOidList);
						}
					}
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}
			if (status != IMA_STATUS_SUCCESS) {
				free(*ppList);
				break;
			}
		}
	}
	os_releasemutex(libMutex);
	return (status);

}

IMA_API IMA_STATUS IMA_RemoveDiscoveryAddress(
    IMA_OID discoveryAddressOid) {

	IMA_RemoveDiscoveryAddressFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (discoveryAddressOid.objectType !=
	    IMA_OBJECT_TYPE_DISCOVERY_ADDRESS) {
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);
	}

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == discoveryAddressOid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_RemoveDiscoveryAddressFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_RemoveDiscoveryAddress");
#else
				PassFunc = (IMA_RemoveDiscoveryAddressFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_RemoveDiscoveryAddress");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(discoveryAddressOid);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

IMA_API IMA_STATUS IMA_GetIpsecProperties(
    IMA_OID oid,
    IMA_IPSEC_PROPERTIES *pProps) {
	IMA_GetIpsecPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (oid.objectType != IMA_OBJECT_TYPE_PNP &&
	    oid.objectType != IMA_OBJECT_TYPE_LHBA) {
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);
	}

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc = (IMA_GetIpsecPropertiesFn)
				    GetProcAddress(plugintable[i].hPlugin,
				    "IMA_GetIpsecProperties");
#else
				PassFunc = (IMA_GetIpsecPropertiesFn)
				    dlsym(plugintable[i].hPlugin,
				    "IMA_GetIpsecProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(oid, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

IMA_API IMA_STATUS IMA_GetAddressKeys(
    IMA_OID targetOid,
    IMA_ADDRESS_KEYS **ppKeys) {
	IMA_GetAddressKeysFn PassFunc;
	IMA_FreeMemoryFn FreeFunc;

	IMA_STATUS status;
	IMA_UINT i;


	if (number_of_plugins == -1)
		InitLibrary();

	if (ppKeys == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (targetOid.objectType != IMA_OBJECT_TYPE_TARGET)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);

	status = IMA_ERROR_OBJECT_NOT_FOUND;
	for (i = 0; i < number_of_plugins; i++) {

		if (plugintable[i].ownerId == targetOid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetAddressKeysFn) GetProcAddress(
				    plugintable[i].hPlugin,
				    "IMA_GetAddressKeys");
#else
				PassFunc = (IMA_GetAddressKeysFn) dlsym(
				    plugintable[i].hPlugin,
				    "IMA_GetAddressKeys");
#endif

				if (PassFunc != NULL) {
					IMA_ADDRESS_KEYS *ppKeysList;
					IMA_UINT addrSize;
					addrSize = sizeof (IMA_ADDRESS_KEYS);
					status =
					    PassFunc(targetOid, &ppKeysList);
					if (IMA_SUCCESS(status)) {

						*ppKeys =
						    (IMA_ADDRESS_KEYS*)calloc(1,
						    addrSize +
						    (ppKeysList->addressKeyCount
						    - 1) * addrSize);
						if ((*ppKeys) == NULL) {
							status = EUOS_ERROR;
						} else {
							memcpy((*ppKeys),
							    ppKeysList,
							    addrSize +
							    (ppKeysList->
							    addressKeyCount-1)*
							    addrSize);

						}
#ifdef WIN32
						FreeFunc = (IMA_FreeMemoryFn)
						    GetProcAddress(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#else
						FreeFunc = (IMA_FreeMemoryFn)
						    dlsym(
						    plugintable[i].hPlugin,
						    "IMA_FreeMemory");
#endif
						if (FreeFunc != NULL) {
							FreeFunc(ppKeysList);
						}
					}
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

IMA_API IMA_STATUS IMA_GetDiscoveryAddressProperties(
    IMA_OID oid,
    IMA_DISCOVERY_ADDRESS_PROPERTIES *pProps) {

	IMA_GetDiscoveryAddressPropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (pProps == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (oid.objectType != IMA_OBJECT_TYPE_DISCOVERY_ADDRESS)
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				PassFunc =
				    (IMA_GetDiscoveryAddressPropertiesFn)
				    GetProcAddress(
				    plugintable[i].hPlugin,
				    "IMA_GetDiscoveryAddressProperties");
#else
				PassFunc =
				    (IMA_GetDiscoveryAddressPropertiesFn) dlsym(
				    plugintable[i].hPlugin,
				    "IMA_GetDiscoveryAddressProperties");
#endif

				if (PassFunc != NULL) {
					status = PassFunc(oid, pProps);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

IMA_API IMA_STATUS QIMA_SetUpdateInterval(
    IMA_OID pluginOid, time_t interval) {
	QIMA_SetUpdateIntervalFn updFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1)
		InitLibrary();

	if (interval <= 1)
		return (IMA_ERROR_INVALID_PARAMETER);

	if ((pluginOid.objectType != IMA_OBJECT_TYPE_PLUGIN) ||
	    (pluginOid.objectSequenceNumber != 0))
		return (IMA_ERROR_INVALID_PARAMETER);

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == pluginOid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			if (plugintable[i].hPlugin != NULL) {
				os_obtainmutex(plugintable[i].pluginMutex);
#ifdef WIN32
				updFunc = (QIMA_SetUpdateIntervalFn)
				    GetProcAddress(
				    plugintable[i].hPlugin,
				    "QIMA_SetUpdateInterval");
#else
				updFunc = (QIMA_SetUpdateIntervalFn) dlsym(
				    plugintable[i].hPlugin,
				    "QIMA_SetUpdateInterval");
#endif

				if (updFunc != NULL) {
					status = updFunc(pluginOid, interval);
				}
				os_releasemutex(plugintable[i].pluginMutex);
			}

			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);

}
