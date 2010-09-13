/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*---------------------------------------------------------------------------
 * Module:            System Abstraction Layer
 *
 * Description:
 * The system layer provides an abstract layer for the most commonly 
 * used system calls for multi-platforms including Windows and most 
 * Unix variants.
 *
 * All the functions defined in this layer fall into 4 categories:
 *     Threading related functions
 *     Mutexes
 *     Conditional variables
 *     Other Utilities
 *--------------------------------------------------------------------------*/

#ifndef SYS_COMMON_H
#define SYS_COMMON_H
#ifdef __cplusplus
extern "C" {
#endif

/*---------------------------------------------------------------------------
 * ERROR code
 *--------------------------------------------------------------------------*/

#define K_SYS_OK                    0
#define K_SYS_ERR_NO_MEMORY         1
#define K_SYS_ERR_CREATE_THREAD     2
#define K_SYS_ERR_JOIN_THREAD       3
#define K_SYS_ERR_COND              4

/*---------------------------------------------------------------------------
 *  Header files
 *--------------------------------------------------------------------------*/

#ifdef WIN32
    #include <windows.h>
    #include <process.h>
#else
    #include <pthread.h>

    /* UNIX : added by STG */
    #include <stdlib.h>
    #include <string.h>
#ifndef METAWARE
    #include <wchar.h>
#endif
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <stdarg.h>

    /*
     * These functions are not needed, since the Agent API hides them
     * enum KeystoneAgent_SortOrder {};
     * enum KeystoneAgent_FilterOperator {};
     */
    
#endif

/*---------------------------------------------------------------------------
 * MACRO definitions
 *--------------------------------------------------------------------------*/

#ifdef WIN32
#define PATH_SEPARATOR '\\'
#define PATH_SEPARATOR_WSTR L"\\"
#ifndef PATH_MAX
#define PATH_MAX MAX_PATH
#endif
#else
#define PATH_SEPARATOR '/'
#define PATH_SEPARATOR_WSTR L"/"
#endif

#ifndef BOOL
#define BOOL int
#endif
#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#ifdef     K_LINUX_PLATFORM
    #ifndef UNIX
    #define UNIX
    #endif
#endif

#ifdef     K_AIX_PLATFORM
    #ifndef UNIX
    #define UNIX
    #endif
#endif

#ifdef     K_SOLARIS_PLATFORM
    #ifndef UNIX
    #define UNIX
    #endif
#endif

#ifdef     K_HPUX_PLATFORM
    #ifndef UNIX
    #define UNIX
    #endif
#endif

/*---------------------------------------------------------------------------
 * Fatal error definitions
 *--------------------------------------------------------------------------*/

#ifndef __FUNCTION__
#define __FUNCTION__ "(Unknown)"
#endif

#ifndef FATAL_APPLICATION_STATE

#ifdef DEBUG

#ifdef WIN32
#include "crtdbg.h"
#define DEBUG_BREAK() { _CrtDbgBreak(); }
#else /* WIN32 */
#ifdef METAWARE 
#define DEBUG_BREAK() (void *) 0x00000000;    /* dummy operation */
#else
#if !defined(__i386)
#define DEBUG_BREAK()
#else
#ifdef __GNUC__
#define DEBUG_BREAK() { __asm__ ( "int3" ); } /* NOTE: This only works for x86 platforms */
#else
#define DEBUG_BREAK()
#endif
#endif /* __i386 */
#endif /* METAWARE */
#endif /* WIN32 */

#define FATAL_APPLICATION_STATE() \
do { \
    DEBUG_BREAK(); \
    process_fatal_application_state(__FILE__,__FUNCTION__,__LINE__,0); \
} while(0)

#define FATAL_APPLICATION_STATE1(additional_text) \
do { \
    DEBUG_BREAK(); \
    process_fatal_application_state(__FILE__,__FUNCTION__,__LINE__,additional_text); \
} while(0)

#else //DEBUG

#define DEBUG_BREAK()

#define FATAL_APPLICATION_STATE() \
do { \
    process_fatal_application_state(__FILE__,__FUNCTION__,__LINE__,0); \
} while(0)

#define FATAL_APPLICATION_STATE1(additional_text) \
do { \
    process_fatal_application_state(__FILE__,__FUNCTION__,__LINE__,additional_text); \
} while(0)

#endif //DEBUG

#define FATAL_ASSERT(expression) do { if(!(expression)) {FATAL_APPLICATION_STATE();} } while(0)
#define FATAL_ASSERT1(expression,additional_text) do { if(!(expression)) {FATAL_APPLICATION_STATE1(additional_text);} } while(0)

/* MS Visual Studio compiler does not support __attribute__() */
#ifndef __GNUC__
#define __attribute__(x)
#endif

void process_fatal_application_state(const char* sFile, const char* sFunction, int iLine, const char* sAdditionalText) __attribute__((noreturn));

void generate_stack_trace(const char* i_sFile, const wchar_t* i_wsErrMsg);

#endif /* FATAL_APPLICATION_STATE */

/*---------------------------------------------------------------------------
 * Primitive type definitions 
 *--------------------------------------------------------------------------*/

#ifdef WIN32
typedef __int64 int64;
#else
#ifndef K_AIX_PLATFORM
typedef signed long long int64;
#endif
#endif


#ifdef K_HPUX_PLATFORM
wchar_t* wcsstr (const wchar_t* haystack, const wchar_t* needle);
int wprintf (const wchar_t* format, ...);
int swprintf (wchar_t* s, size_t maxlen, const wchar_t* format, ...);
int vswprintf (wchar_t* s, size_t maxlen, const wchar_t* format, va_list args);
int swscanf(const wchar_t *s, const wchar_t *format, ...);
int64 atoll(const char *str);
#endif

/*---------------------------------------------------------------------------
 * Thread type definitions
 *--------------------------------------------------------------------------*/

#ifdef WIN32
typedef  HANDLE  K_THREAD_HANDLE;
#else
typedef  pthread_t  K_THREAD_HANDLE;
#endif

/*---------------------------------------------------------------------------
 * Mutex type definitions
 *--------------------------------------------------------------------------*/

#ifdef WIN32

typedef struct {
    HANDLE m_handle; /* mutex handle */

    CRITICAL_SECTION m_stCriticalSection; /* criticalSection */

    int    m_bIsRecursive;
}  WIN32Mutex;

typedef WIN32Mutex* K_MUTEX_HANDLE;

#else
typedef pthread_mutex_t* K_MUTEX_HANDLE;
#endif

/*---------------------------------------------------------------------------
 * Conditional variable type definitions
 *--------------------------------------------------------------------------*/

#ifdef WIN32
    struct K_CondStruct
    {
            HANDLE m_hEvent;
            HANDLE m_hMutex;
            int m_iSignalAll;
            int m_iNumWaiting;
            int m_iSignalled;
     };
    typedef struct K_CondStruct K_ConditionalVariable;

#else
    typedef pthread_cond_t K_ConditionalVariable;
#endif

/*---------------------------------------------------------------------------
 * Thread function type definitions
 *--------------------------------------------------------------------------*/

    /*
     * Having the function return int breaks compatibility between Windows
     * and Unix; the function has to return void
     */
/*#ifdef WIN32
 *   typedef int (_stdcall *K_ThreadFunc) (void *vpData);
 *#else
 */
    typedef void (*K_ThreadFunc) (void *vpData);
/*
 *#endif
 */


/*---------------------------------------------------------------------------
 * Function: K_CreateThread
 *
 * Description:
 *  This thread creation function takes a thread function
 *  and its parameter to create a thread. It also has a Boolean
 *  parameter to indicate if the thread is detached or joinable.
 *  A new thread's handle is returned through the output parameter.
 *
 * Input
 * -----
 *    i_pFunc         Function pointer of the thread function
 *    i_pvData        The point of the parameter passed to the thread function
 *    i_bIsDetached   The thread is detached or not. If detached, then it is
 *                    not joinable. (Note: It is not supported on Win32)
 *
 * Output
 * ------
 *    o_pNewThread    The Thread handle
 *
 * Return value       Error code
 *
 *--------------------------------------------------------------------------*/
int K_CreateThread(K_ThreadFunc i_pFunc,
                  void *i_pvData,
                  int i_bIsDetached,
                  K_THREAD_HANDLE *o_pNewThread);


/*---------------------------------------------------------------------------
 * Function: K_JoinThread
 *
 * Description:
 *  This thread joining function is called when the current thread
 *  waits another thread to terminate.
 *
 * Input
 * -----
 *    i_hThread        The thread handle of the to-be-joined thread
 *
 * Output
 * ------
 *    (none)
 *
 * Return value        Error code
 *
 *--------------------------------------------------------------------------*/
int  K_JoinThread(K_THREAD_HANDLE i_hThread);


/*---------------------------------------------------------------------------
 * Function: K_GetCurrentThreadId
 *
 * Description:
 *  Returns the thread ID of the current thread.
 *
 * Input
 * -----
 *    (none)
 *
 * Output
 * ------
 *    (none)
 *
 * Return value        The thread ID
 *
 *--------------------------------------------------------------------------*/

int K_GetCurrentThreadId();


/*---------------------------------------------------------------------------
 * Function: K_CreateMutex
 *
 * Description:
 *  The mutex creation function creates a mutex according to the given
 *  mutex type, and returns the mutex handle to the output parameter.
 *
 * Input
 * -----
 *    (none)
 *    
 * Output
 * ------
 *    o_phandle        the handle pointer to the mutex
 *
 * Return value        Error Code
 *
 *--------------------------------------------------------------------------*/

int K_CreateMutex( K_MUTEX_HANDLE *o_phandle );


/*---------------------------------------------------------------------------
 * Function: K_LockMutex
 *
 * Description:
 *  K_LockMutex is used to lock the mutex, and K_UnlockMutex is
 *  used to unlock it.
 *
 * Input
 * -----
 *    i_handle        the mutex handle
 *
 * Output
 * ------
 *   (none)
 *
 * return value       Error Code
 *
 *--------------------------------------------------------------------------*/
int K_LockMutex(K_MUTEX_HANDLE i_handle);


/*---------------------------------------------------------------------------
 * Function: K_UnlockMutex
 *
 * Description:
 *  K_UnlockMutex is used to unlock the lock.
 *
 * Input
 * -----
 *    i_handle        the mutex handle
 *
 * Output
 * ------
 *    (none)
 *
 * Return value       Error Code
 *
 *--------------------------------------------------------------------------*/
int K_UnlockMutex(K_MUTEX_HANDLE i_handle);


/*---------------------------------------------------------------------------
 * Function: K_DestroyMutex
 *
 * Description:
 *  When a mutex is no longer needed, K_DestroyMutex must be called
 *  to destroy it.
 *
 * Input
 * -----
 *    i_handle        the mutex handle
 *
 * Output
 * ------
 *    (none)
 *
 * Return value       Error Code
 *
 *--------------------------------------------------------------------------*/

int K_DestroyMutex(K_MUTEX_HANDLE i_handle);


/*---------------------------------------------------------------------------
 *
 *  The following section defines Conditional Variable
 *
 * Conditional Variable implements similar functionalities defined
 * in POSIX thread library. But it only supports conditional variables
 * inside one process and doesn't support pthread_cond_timedwait().
*--------------------------------------------------------------------------*/


/*---------------------------------------------------------------------------
 * Function: K_InitConditionalVariable
 *
 * Description:
 *  This function initializes a conditional variable; Upon successful
 *  completion, the new condition variable is returned via the condition
 *  parameter, and 0 is returned. Otherwise, an error code is returned.
 *
 * Input
 * -----
 *    i_pCond     the pointer to the conditional variable which is to be
 *                initialized
 *
 * Output
 * ------
 *    (none)
 *
 * Return value   Error Code
 *
 *--------------------------------------------------------------------------*/
int K_InitConditionalVariable (K_ConditionalVariable * i_pCond);



/*---------------------------------------------------------------------------
 * Function: K_DestroyConditionalVariable
 *
 * Description:
 *  This function destroys a conditional variable.  Upon successful
 *  completion, the condition variable is destroyed, and 0 is returned.
 *  Otherwise, an error code is returned.
 *  After deletion of the condition variable, the condition parameter
 *  is not valid until it is initialized again by a call to the
 *  K_InitConditionalVariable subroutine.
 *
 * Input
 * -----
 *    i_pCond     the pointer to the conditional variable which is to be
 *                destroyed
 *
 * Output
 * ------
 *    (none)
 *
 * Return value   Error Code
 *
 *--------------------------------------------------------------------------*/

int K_DestroyConditionalVariable(K_ConditionalVariable * i_pCond);


/*---------------------------------------------------------------------------
 * Function: K_WaitConditionalVariable
 *
 * Description:
 *  This function is used to block on a condition variable.
 *  They are called with mutex locked by the calling thread or undefined
 *  behaviour will result.
 *
 * Input
 * -----
 *    i_pCond     the pointer to the conditional variable
 *    i_handle    the companion mutex handle
 *
 * Output
 * ------
 *    (none)
 *
 * Return value   Error Code
 *
 *--------------------------------------------------------------------------*/
int  K_WaitConditionalVariable(K_ConditionalVariable * i_pCond,
                               K_MUTEX_HANDLE i_handle);


/*---------------------------------------------------------------------------
 * Function: K_SignalConditionalVariable
 *
 * Description:
 *  This function is used to restart one of the threads that are waiting on
 *  the condition variable.  If no threads are waiting on it, nothing happens.
 *  If several threads are waiting on it, exactly one is restarted.
 *
 * Input
 * -----
 *    i_pCond        the pointer to the conditional variable
 *
 * Output
 * ------
 *    (none)
 *
 * Return value      Error Code
 *
 *--------------------------------------------------------------------------*/
int K_SignalConditionalVariable(K_ConditionalVariable * i_pCond);


/*---------------------------------------------------------------------------
 * Function: K_BroadcastConditionalVariable
 *
 * Description:
 *  This function is used to restart all threads that are waiting on
 *  the condition variable.
 *
 * Input
 * -----
 *    i_pCond        the pointer to the conditional variable
 *
 * Output
 * ------
 *    (none)
 *
 * Return value      Error Code
 *
 *--------------------------------------------------------------------------*/
int K_BroadcastConditionalVariable(K_ConditionalVariable * i_pCond);


/*---------------------------------------------------------------------------
 * Function: K_Sleep
 *
 * Description:
 *  Sleep for a given period in the given milliseconds.
 *
 * Input
 * -----
 *    i_ms        milliseconds
 *
 * Output
 * ------
 *    (none)
 *
 * Return value   (none)
 *
 *--------------------------------------------------------------------------*/
void K_Sleep(int i_ms);


/*---------------------------------------------------------------------------
 * Function: K_GetTickCount
 *
 * Description:
 *  The K_GetTickCount function retrieves the number of
 *  milliseconds that have elapsed since the system was started.
 *
 * Input
 * -----
 *    (none)
 *
 * Output
 * ------
 *    (none)
 *
 * Return value        the elasped milliseconds since the system was started
 *
 *--------------------------------------------------------------------------*/
unsigned int K_GetTickCount();


/*---------------------------------------------------------------------------
 * Function: K_AdjustClock
 *
 * Description:
 *  The K_AdjustClock function immediately adjusts the system clock by
 *  the given number of seconds.  A positive number adjusts the system
 *  clock forward; a negative number adjusts the system clock backward.
 *
 * Input
 * -----
 *    i_iAdjustmentInSeconds   Number of seconds by which to adjust the
 *                             system clock
 * Output
 * ------
 *    (none)
 *
 * Return value      1 if successful, 0 on error
 *
 *--------------------------------------------------------------------------*/
int K_AdjustClock( long i_iAdjustmentInSeconds );


/*---------------------------------------------------------------------------
 * Function: K_IsLittleEndian
 *
 * Description:
 *  Checks to see whether this platform uses little endian integer
 *  representation.
 *
 * Input
 * -----
 *    (none)
 *
 * Output
 * ------
 *    (none)
 *
 * Return value        1 for little endian
 *
 *--------------------------------------------------------------------------*/
int K_IsLittleEndian();


/*---------------------------------------------------------------------------
 * Function: K_FileLength32
 *
 * Description:
 *  Gets the size in bytes of the file associated with the given FILE pointer.
 *
 * Input
 * -----
 *    i_fpFile         File handle
 *
 * Output
 * ------
 *    (none)
 *
 * Return value        File size in bytes, or -1L on error
 *
 *--------------------------------------------------------------------------*/
long K_FileLength32( FILE* i_fpFile );


/*---------------------------------------------------------------------------
 * Function: K_StringCompareNoCase
 *
 * Description:
 *  Compares the two given strings insensitive to case.
 *
 * Input
 * -----
 *    i_sString1       First string
 *    i_sString2       Second string
 *
 * Output
 * ------
 *    (none)
 *
 * Return value        0 if identical, -1 if first string is less than second
 *                     string, or 1 if first string is greater than second 
 *
 *--------------------------------------------------------------------------*/
int K_StringCompareNoCase( const char* i_sString1, const char* i_sString2 );


/*---------------------------------------------------------------------------
 * Function: K_StringCompareNoCaseWide
 *
 * Description:
 *  Compares the two given wide strings insensitive to case.
 *
 * Input
 * -----
 *    i_wsString1      First wide string
 *    i_wsString2      Second wide string
 *
 * Output
 * ------
 *    (none)
 *
 * Return value        0 if identical, -1 if first string is less than second
 *                     string, or 1 if first string is greater than second 
 *
 *--------------------------------------------------------------------------*/
int K_StringCompareNoCaseWide( const wchar_t* i_wsString1, const wchar_t* i_wsString2 );


/*---------------------------------------------------------------------------
 * Function: K_snprintf
 *
 * Description:
 *  See the snprintf(3C) man page.
 *
 *--------------------------------------------------------------------------*/
#ifdef WIN32
#define K_snprintf  _snprintf
#else
#define K_snprintf  snprintf
#endif


/*---------------------------------------------------------------------------
 * Function: K_snwprintf
 *
 * Description:
 *  See the swprintf(3C) man page.
 *
 *--------------------------------------------------------------------------*/
#ifdef WIN32
#define K_snwprintf  _snwprintf
#else
#define K_snwprintf  swprintf
#endif

#ifdef WIN32
#define K_fseek fseek
#define K_ftell ftell
#else
#define K_fseek fseeko
#define K_ftell ftello
#endif


/*---------------------------------------------------------------------------
 * Function: K_CreateDirectory
 *
 * Description:
 *  Creates a directory with the given path name.
 *
 * Input
 * -----
 *    i_sDirectoryName  Directory name
 *
 * Output
 * ------
 *    (none)
 *
 * Return value        0 on success, -1 on failure
 *
 *--------------------------------------------------------------------------*/
int K_CreateDirectory( const char* i_sDirectoryName );


/*---------------------------------------------------------------------------
 * Function: K_DeleteFile
 *
 * Description:
 *  Deletes the given file.
 *
 * Input
 * -----
 *    i_sFilename      Name of file to delete
 *
 * Output
 * ------
 *    (none)
 *
 * Return value        0 on success, errno on failure
 *
 *--------------------------------------------------------------------------*/
int K_DeleteFile( const char* i_sFilename );


/*---------------------------------------------------------------------------
 * Function: K_ReadFile
 *
 * Description:
 *  Reads from the given file and passes the bytes read back to the output
 *  parameter.  The caller must deallocate o_ppFileData using free().
 *
 * Input
 * -----
 *    i_sFilename      Name of file from which to read
 *
 * Output
 * ------
 *    o_ppFileData     Pointer to bytes read
 *
 * Return value        Number of bytes read on success, -1 on failure
 *
 *--------------------------------------------------------------------------*/
int K_ReadFile( const char* i_sFilename, unsigned char** o_ppFileData );


/*---------------------------------------------------------------------------
 * Function: K_ReadFileString
 *
 * Description:
 *  Reads from the given file and passes the bytes read back to the output
 *  parameter, appending these bytes with a null terminator.  There is no
 *  guarantee that there are no non-text characters in the returned "string".
 *  The caller must deallocate o_ppFileData using free().
 *
 * Input
 * -----
 *    i_sFilename      Name of file from which to read
 *
 * Output
 * ------
 *    o_psFileDataString     Pointer to bytes read
 *
 * Return value        Number of bytes read (including null terminator) on
 *                     success (0 if file is empty), -1 on failure
 *
 *--------------------------------------------------------------------------*/
int K_ReadFileString( const char* i_sFilename, char** o_psFileDataString );


/*---------------------------------------------------------------------------
 * Function: K_WriteFile
 *
 * Description:
 *  Writes the given bytes to the given file.
 *
 * Input
 * -----
 *    i_sFilename      Name of file to which to write
 *    i_pFileData      Bytes to write
 *    i_iFileDataSize  Number of bytes to write
 *
 * Output
 * ------
 *    (none)
 *
 * Return value        0 on success, errno or -1 (generic error) on failure
 *
 *--------------------------------------------------------------------------*/
int K_WriteFile( const char* i_sFilename, const unsigned char* i_pFileData, int i_iFileDataSize );


/*---------------------------------------------------------------------------
 * Function: K_WriteFileString
 *
 * Description:
 *  Writes the given null-terminated bytes to the given file.  The null
 *  terminator itself is not written to the file.
 *
 * Input
 * -----
 *    i_sFilename      Name of file to which to write
 *    i_sFileData      Bytes to write
 *
 * Output
 * ------
 *    (none)
 *
 * Return value        0 on success, errno or -1 (generic error) on failure
 *
 *--------------------------------------------------------------------------*/
int K_WriteFileString( const char* i_sFilename, const char* i_sFileData );


/*---------------------------------------------------------------------------
 * Function: K_FileExists
 *
 * Description:
 *  Checks to see whehter the given file exists.
 *
 * Input
 * -----
 *    i_sFilename      Name of file to check
 *
 * Output
 * ------
 *    (none)
 *
 * Return value        1 if file exists, 0 if not, -1 on failure
 *
 *--------------------------------------------------------------------------*/
int K_FileExists( const char* i_sFilename );


/*---------------------------------------------------------------------------
 * Function: K_CopyFile
 *
 * Description:
 *  Reads from the given source file and writes these bytes to the given
 *  destination file.
 *
 * Input
 * -----
 *    i_sSrcFilename   Name of file from which to read
 *    i_sDestFilename  Name of file to which to write
 *
 * Output
 * ------
 *    o_pbFileExists   Non-zero if the destination file already exists
 *
 * Return value        0 on success, errno or -1 (generic error) on failure
 *
 *--------------------------------------------------------------------------*/
int K_CopyFile(
        const char* i_sSrcFilename,
        const char* i_sDestFilename,
        int* o_pbFileExists );


/*---------------------------------------------------------------------------
 * Function: K_GetFilenamesInDirectoryCount
 *
 * Description:
 *  Reads the given directory and returns the number of files that it contains.
 *
 * Input
 * -----
 *    i_sDirectoryName  Name of directory
 *
 * Output
 * ------
 *    (none)
 *
 * Return value        Number of files on success, -1 on failure
 *
 *--------------------------------------------------------------------------*/
int K_GetFilenamesInDirectoryCount( const char* i_sDirectoryName );


/*---------------------------------------------------------------------------
 * Function: K_GetFilenamesInDirectory
 *
 * Description:
 *  Reads the given directory and returns an array of names of files that it
 *  contains.  A null pointer appears at the last item in the array.  The
 *  caller must deallocate o_pasFilenames by using K_FreeFilenames or by
 *  calling free() for each file name and then calling free() on the array
 *  itself.
 *
 * Input
 * -----
 *    i_sDirectoryName  Name of directory
 *
 * Output
 * ------
 *    o_pasFilenames   Array of names of files found in this directory
 *
 * Return value        Number of files on success, -1 on failure
 *
 *--------------------------------------------------------------------------*/
int K_GetFilenamesInDirectory(
        const char* i_sDirectoryName,
        char*** o_pasFilenames );


/*---------------------------------------------------------------------------
 * Function: K_FreeFilenames
 *
 * Description:
 *  Deallocates the memory allocated in a successful call to
 *  K_GetFilenamesInDirectory.
 *
 * Input
 * -----
 *    i_asFilenames    Array of names of files
 *
 * Output
 * ------
 *    (none)
 *
 * Return value        (none)
 *
 *--------------------------------------------------------------------------*/
void K_FreeFilenames( char** i_asFilenames );


/*---------------------------------------------------------------------------
 * Function: K_AdjustLocalClock
 *
 * Description:
 *  The K_AdjustLocalClock function gradually adjusts the system clock by
 *  the given number of seconds.  A positive number adjusts the system
 *  clock forward; a negative number adjusts the system clock backward.
 *
 * Input
 * -----
 *    i_iAdjustmentInSeconds   Number of seconds by which to adjust the
 *                             system clock
 * Output
 * ------
 *    (none)
 *
 * Return value        1 if successful, 0 on error
 *
 *--------------------------------------------------------------------------*/
int K_AdjustLocalClock( int i_iNumberOfSeconds );


/*---------------------------------------------------------------------------
 * Function: K_SetRootPassword
 *
 * Description:
 *  The K_SetRootPassword function sets the password for the root user via
 *  Pluggable Authentication Module (PAM).  This function is interactive.
 *
 * Input
 * -----
 *    i_sPassword      Password to set
 *
 * Output
 * ------
 *    (none)
 *
 * Return value        0 if successful, -1 on error
 *
 *--------------------------------------------------------------------------*/
int K_SetRootPassword( const char* i_sPassword );


/*---------------------------------------------------------------------------
 * Function: K_Alarm
 *
 * Description:
 *  Calls alarm(2) on Unix in order to cause the operating system to generate
 *  a SIGALRM signal for this process after the given number of real-time
 *  seconds.  Does nothing on Windows.
 *
 * Input
 * -----
 *    i_iSeconds       Number of seconds after which to generate a SIGALRM
 *                     signal
 *
 * Output
 * ------
 *    (none)
 *
 * Return value        If a previous alarm request is pending, then it returns
 *                     the number of seconds until this previous request would
 *                     have generated a SIGALRM signal.  Otherwise, returns 0.
 *
 *--------------------------------------------------------------------------*/
unsigned int K_Alarm( unsigned int i_iSeconds );


/*---------------------------------------------------------------------------
 * Function: K_GetExtendedVersionFromBase
 *
 * Description:
 *  This KMS-specific function prepends the timestamp value to the specified
 *  base replication schema version and returns this value as an extended
 *  replication schema version.
 *
 * Input
 * -----
 *    i_iBaseSchemaVersion  Base replication schema version
 *
 * Output
 * ------
 *    (none)
 *
 * Return value        Extended replication schema version
 *
 *--------------------------------------------------------------------------*/
unsigned int K_GetExtendedVersionFromBase( unsigned int i_iBaseSchemaVersion );


/*---------------------------------------------------------------------------
 * Function: K_ParseTimestampFromExtendedVersion
 *
 * Description:
 *  This KMS-specific function parses the timestamp value from the given
 *  extended replication schema version and returns this timestamp value.
 *
 * Input
 * -----
 *    i_iExtendedSchemaVersion  Extended replication schema version
 *
 * Output
 * ------
 *    (none)
 *
 * Return value        Timestamp value
 *
 *--------------------------------------------------------------------------*/
unsigned int K_ParseTimestampFromExtendedVersion(
    unsigned int i_iExtendedSchemaVersion );


/*---------------------------------------------------------------------------
 * Function: K_ParseBaseFromExtendedVersion
 *
 * Description:
 *  This KMS-specific function parses the base replication schema value from
 *  the given extended replication schema version and returns this base value.
 *
 * Input
 * -----
 *    i_iExtendedSchemaVersion  Extended replication schema version
 *
 * Output
 * ------
 *    (none)
 *
 * Return value        Base replication schema value
 *
 *--------------------------------------------------------------------------*/

unsigned int K_ParseBaseFromExtendedVersion(
    unsigned int i_iExtendedSchemaVersion );


/*---------------------------------------------------------------------------
 * Function: K_System
 *
 * Description:
 *  This function is a thread-safe replacement for the unsafe system(3C) call.
 *  See the popen(3C) man page for more information.
 *
 * Input
 * -----
 *    i_sCmd           Command to execute
 *
 * Output
 * ------
 *    (none)
 *
 * Return value        Termination status of the command language interpreter
 *                     if successful, -1 on failure
 *
 *--------------------------------------------------------------------------*/

int K_System( const char *i_sCmd );

#define K_system  K_System

#ifdef __cplusplus
}
#endif

#endif


