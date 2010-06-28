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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*---------------------------------------------------------------------------
 * Module:            SYSCommon.c
 *-------------------------------------------------------------------------*/

#include <stdio.h>
#include "SYSCommon.h"
#include <time.h>
#include <errno.h>
#include <sys/stat.h> 
#include <sys/types.h>
#include <signal.h>

#ifndef WIN32
#include <unistd.h>
#endif

#ifdef WIN32
#include <io.h>
#include <stdlib.h>   /* for malloc, calloc, and free */
#elif defined K_LINUX_PLATFORM
#include <unistd.h>   /* it includes usleep(us) */
#include <sys/time.h>
#include <fts.h>
#else
/*
 * Directory traversal code is not yet available for Solaris.
 * If such code will need to be written, then it will probably use ftw.h.
 */
#endif

#ifdef K_SOLARIS_PLATFORM
/* For K_AdjustLocalClock */
#include <unistd.h>
/* For K_SetRootPassword */
#define    __EXTENSIONS__    /* to expose flockfile and friends in stdio.h */ 
#include <errno.h>
#include <libgen.h>
#include <malloc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <stropts.h>
#include <unistd.h>
#include <termio.h>
#include <security/pam_appl.h>
#include <widec.h>
#endif

#ifdef K_LINUX_PLATFORM
extern int pthread_mutexattr_settype __P ((pthread_mutexattr_t *__attr,
                       int __kind));
#endif

#ifdef K_HPUX_PLATFORM
int64 atoll(const char *str)
{
    int64 tmp = 0;
    sscanf(str, "%lld", &tmp);
    return tmp;
}

#endif


/*---------------------------------------------------------------------------
 * Function: K_CreateThread
 *
 * Description:
 *  Thread creation function "CreateThread" takes a thread function
 *  and its parameter to create a thread. It also has a Boolean
 *  parameter to indicate if the thread is detached or joinable.
 *  A new thread's handle is returned through the output parameter.
 *
 * Input
 * -----
 *    i_pFunc         Function pointer of the thread function
 *    i_pvData        The point of the parameter passed to the thread function
 *    i_bIsDetached   The thread is detached or not
 *                    (Note: It is not supported on Win32)
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
                  K_THREAD_HANDLE *o_pNewThread)
{
    int iOK = K_SYS_OK;
    int iReturn = 0;

#ifdef WIN32

    {
       unsigned id;

        *o_pNewThread = (HANDLE)_beginthreadex(NULL,
                                        0,
                                        (int (_stdcall *) (void *vpData))i_pFunc,
                                        i_pvData,
                                        0,
                                        &id);


        if(*o_pNewThread == 0)
        {
#ifdef SYS_DEBUG
            printf(" (%s, %d): error creating pthread, error = %d\n",
                __FILE__, __LINE__, iReturn);
#endif
            return K_SYS_ERR_CREATE_THREAD;
        }

        return K_SYS_OK;
    }

#else
    pthread_attr_t attr;
    
    iReturn = pthread_attr_init(&attr);

    if ( iReturn == 0 )
    {
        iReturn = pthread_attr_setdetachstate(&attr, (i_bIsDetached) ?
                    PTHREAD_CREATE_DETACHED :
                    PTHREAD_CREATE_JOINABLE);
    }
    
#ifdef UNIX
    if ( iReturn == 0 )
    {
        iReturn = pthread_attr_setstacksize(&attr, 1024*1024);
    }
#endif

    if ( iReturn == 0 )
    {
        iReturn = pthread_create(o_pNewThread, &attr, (void *(*)(void *)) i_pFunc, i_pvData);
    }

    if ( iReturn == 0 )
    {
        iReturn = pthread_attr_destroy(&attr);
    }

    // TODO: Log error?
    if ( iReturn )
    {
#ifdef SYS_DEBUG
        printf(" (%s, %d): error creating pthread, error = %d\n",
                __FILE__, __LINE__, iReturn);
#endif

        iOK = K_SYS_ERR_CREATE_THREAD;
    }

    return iOK;
#endif
}


/*---------------------------------------------------------------------------
 * Function: K_JoinThread
 *
 * Description:
 *  Thread joining function is called when the current thread
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

int  K_JoinThread(K_THREAD_HANDLE i_hThread)
{
    int iOK = K_SYS_OK;
#ifdef WIN32

    WaitForSingleObject(i_hThread, INFINITE);

#else
    {
        int iReturn;
        iReturn = pthread_join(i_hThread, NULL);

        if ( iReturn )
        {

#ifdef SYS_DEBUG
            printf(" (%s, %d): error creating pthread, error = %d\n",
                    __FILE__, __LINE__, iReturn);
#endif
            iOK = K_SYS_ERR_JOIN_THREAD;
        }
    }

#endif
    return iOK;
}


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

int K_GetCurrentThreadId()
{
#ifdef WIN32
    return GetCurrentThreadId();
#else
    return pthread_self();
#endif

}


/*---------------------------------------------------------------------------
 * Function: K_CreateMutex
 *
 * Description:
 *  The mutex creation function creates a mutex according to the given
 *  mutex type, and returns the mutex handle to the output parameter.
 *
 * Input
 * -----
 *    i_bIsRecursive   Indication whether the mutex can be entered recursively
 *
 * Output
 * ------
 *    o_phandle        the handle pointer to the mutex
 *
 * Return value        Error Code
 *
 *--------------------------------------------------------------------------*/

int K_CreateMutex( K_MUTEX_HANDLE *o_phandle )
{
    int iOK = K_SYS_OK;
    BOOL bIsRecursive = 1;  // this used to be an input -- but why do we want this to be optional?

#ifdef WIN32
    {
        *o_phandle = (WIN32Mutex *)malloc(sizeof(WIN32Mutex));
        if(*o_phandle == NULL)
        {
            return K_SYS_ERR_NO_MEMORY;
        }
        (*o_phandle)->m_bIsRecursive = bIsRecursive;
        if(bIsRecursive)
        {
                InitializeCriticalSection(&((*o_phandle)->m_stCriticalSection));
        }
        else
        {
            (*o_phandle)->m_handle = CreateMutex(NULL, FALSE, NULL);
        }

    }
#else
    {
        int iType;
        pthread_mutexattr_t attr;
        
        if ( pthread_mutexattr_init(&attr) )
        {
            return K_SYS_ERR_COND;
        }

        if(bIsRecursive)
        {
            iType =
#ifdef K_LINUX_PLATFORM
            PTHREAD_MUTEX_RECURSIVE_NP;
#else
            PTHREAD_MUTEX_RECURSIVE;
#endif
            
            if ( pthread_mutexattr_settype(&attr, iType) )
            {
                return K_SYS_ERR_COND;
            }
        }
        
        *o_phandle = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
        if(*o_phandle == NULL)
        {
            return K_SYS_ERR_NO_MEMORY;
        }
        
        if ( pthread_mutex_init(*o_phandle, &attr) )
        {
            return K_SYS_ERR_COND;
        }

        if ( pthread_mutexattr_destroy(&attr) )
        {
            return K_SYS_ERR_COND;
        }
    }
#endif

    return iOK;
}


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
 *    (none)
 *
 * Return value       Error Code
 *
 *--------------------------------------------------------------------------*/

int K_LockMutex(K_MUTEX_HANDLE i_handle)
{
    int iOK = K_SYS_OK;
#ifdef WIN32
    
    if(i_handle->m_bIsRecursive)
    {
        EnterCriticalSection(&(i_handle->m_stCriticalSection));
    }
    else
    {
        WaitForSingleObject(i_handle->m_handle, INFINITE);
    }

#else

    if ( pthread_mutex_lock(i_handle) )
    {
        return K_SYS_ERR_COND;
    }

#endif
    return iOK; // TODO: better error handling
}


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

int K_UnlockMutex(K_MUTEX_HANDLE i_handle)
{
    int iOK = K_SYS_OK;

#ifdef WIN32
    if(i_handle->m_bIsRecursive)
    {
        LeaveCriticalSection(&(i_handle->m_stCriticalSection));
    }
    else
    {
        ReleaseMutex(i_handle->m_handle);
    }

#else

    if ( pthread_mutex_unlock(i_handle) )
    {
        return K_SYS_ERR_COND;
    }
#endif

    return iOK; // TODO: better error handling
}


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
 * Output
 * ------
 *    (none)
 *
 * Return value       Error Code
 *
 *--------------------------------------------------------------------------*/

int K_DestroyMutex(K_MUTEX_HANDLE i_handle)
{

    int iOK = K_SYS_OK;

#ifdef WIN32

    if(i_handle->m_bIsRecursive)
    {
        DeleteCriticalSection(&(i_handle->m_stCriticalSection));
    }
    else
    {
        CloseHandle(i_handle->m_handle);
    }
    free(i_handle);

#else
    pthread_mutex_destroy(i_handle);
    free(i_handle);
#endif
    return iOK; // TODO: better error handling
}


/*---------------------------------------------------------------------------
 * Function: K_InitConditionalVariable
 *
 * Description:
 *  This function initializes a conditional variable.  Upon successful
 *  completion, the new condition variable is returned via the condition
 *  parameter, and 0 is returned.  Otherwise, an error code is returned.
 *
 * Input
 * -----
 *    i_pCond         the pointer to the conditional variable which is to be
 *                    initialized
 *
 * Output
 * ------
 *    (none)
 *
 * Return value       Error Code
 *
 *--------------------------------------------------------------------------*/

int K_InitConditionalVariable (K_ConditionalVariable * i_pCond)
{
    int iOK = K_SYS_OK;
#ifdef WIN32

    i_pCond->m_hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    i_pCond->m_hMutex = CreateMutex(NULL, FALSE, NULL);
    i_pCond->m_iSignalAll = 0;
    i_pCond->m_iNumWaiting = 0;    

#else
    
    if ( pthread_cond_init(i_pCond, NULL) )
    {
        return K_SYS_ERR_COND;
    }
    
#endif

    return iOK;
}


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
 *    i_pCond        the pointer to the conditional variable which is to be
 *                   destroyed
 * Output
 * ------
 *    (none)
 *
 * Return value      Error Code
 *
 *--------------------------------------------------------------------------*/

int K_DestroyConditionalVariable(K_ConditionalVariable * i_pCond)
{
    int iOK = K_SYS_OK;
#ifdef WIN32
    CloseHandle(i_pCond->m_hMutex);
    CloseHandle(i_pCond->m_hEvent);
#else
    
    if ( pthread_cond_destroy(i_pCond) )
    {
        return K_SYS_ERR_COND;
    }

#endif
    return iOK;

}


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
 *    i_pCond        the pointer to the conditional variable
 *    i_handle       the companion mutex handle
 *
 * Output
 * ------
 *    (none)
 *
 * Return value      Error Code
 *
 *--------------------------------------------------------------------------*/

int  K_WaitConditionalVariable(K_ConditionalVariable * i_pCond,
                               K_MUTEX_HANDLE i_handle)
{

    int iOK = K_SYS_OK;
#ifdef WIN32
    DWORD res;

    while (1) 
    {
        iOK = WaitForSingleObject(i_pCond->m_hMutex, INFINITE);
        if (iOK != WAIT_OBJECT_0) 
        {
            return K_SYS_ERR_COND;
        }
        i_pCond->m_iNumWaiting++;
        ReleaseMutex(i_pCond->m_hMutex);

        K_UnlockMutex(i_handle);
        res = WaitForSingleObject(i_pCond->m_hEvent, INFINITE);
        i_pCond->m_iNumWaiting--;
        
        if (res != WAIT_OBJECT_0) 
        {
            ReleaseMutex(i_pCond->m_hMutex);
            return K_SYS_ERR_COND;
        }
        
        if (i_pCond->m_iSignalAll) 
        {
            if (i_pCond->m_iNumWaiting == 0) 
            {
                ResetEvent(i_pCond->m_hEvent);
            }
            break;
        }
        
        if (i_pCond->m_iSignalled) 
        {
            i_pCond->m_iSignalled = 0;
            ResetEvent(i_pCond->m_hEvent);
            break;
        }
        ReleaseMutex(i_pCond->m_hMutex);
    }

    K_LockMutex(i_handle);

    return K_SYS_OK;
#else
    
    if ( pthread_cond_wait(i_pCond, i_handle) )
    {
        return K_SYS_ERR_COND;
    }

#endif
    return iOK; // TODO: better error handling
}


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

int K_SignalConditionalVariable(K_ConditionalVariable * i_pCond)
{
    int iOK = K_SYS_OK;
#ifdef WIN32

    int iReturn;

    iReturn = WaitForSingleObject(i_pCond->m_hMutex, INFINITE);
    if (iReturn != WAIT_OBJECT_0) 
    {
        return K_SYS_ERR_COND;
    }

    i_pCond->m_iSignalled = 1;

    iReturn = SetEvent(i_pCond->m_hEvent);
    if (iReturn == 0) 
    {
        iOK = K_SYS_ERR_COND;
    }
    ReleaseMutex(i_pCond->m_hMutex);

    return iOK;
#else
    
    if ( pthread_cond_signal(i_pCond) )
    {
        return K_SYS_ERR_COND;
    }

#endif
    return iOK; 
}


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

int K_BroadcastConditionalVariable(K_ConditionalVariable * i_pCond)
{

    int iOK = K_SYS_OK;

#ifdef WIN32

    int iReturn;

    iReturn = WaitForSingleObject(i_pCond->m_hMutex, INFINITE);
    if (iReturn != WAIT_OBJECT_0) 
    {
        return K_SYS_ERR_COND;
    }
    i_pCond->m_iSignalled = 1;
    i_pCond->m_iSignalAll = 1;

    iReturn = SetEvent(i_pCond->m_hEvent);

    if (iReturn == 0) 
    {
        iOK = K_SYS_ERR_COND;
    }

    ReleaseMutex(i_pCond->m_hMutex);

    return iOK;

#else
    
    if ( pthread_cond_broadcast(i_pCond) )
    {
        return K_SYS_ERR_COND;
    }

#endif
    return iOK; 
}


/*---------------------------------------------------------------------------
 * Function: K_Sleep
 *
 * Description:
 *  Sleep for a given period in given milliseconds.
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

void K_Sleep(int i_ms)
{
#ifdef WIN32
    Sleep(i_ms);
#else
    usleep(i_ms * 1000);
#endif
}


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

unsigned int K_GetTickCount()
{
#ifdef WIN32
    return (unsigned int)GetTickCount();
#else
    {
        struct timeval tv;
        gettimeofday( &tv, NULL );
        /* this will rollover ~ every 49.7 days
           dont surprise when it returns negative values, since we are only interested
          in using  sth like "tickCount2 - tickCount1" to get the time interval
        */
        return ( tv.tv_sec * 1000 ) + ( tv.tv_usec / 1000 );
    }
#endif
}


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
 * Return value        1 if successful, 0 on error
 *
 *--------------------------------------------------------------------------*/

int K_AdjustClock( long i_iAdjustmentInSeconds )
{
#ifndef WIN32
    struct timeval stDateTime;
    if ( 0 != gettimeofday(&stDateTime, NULL) )
    {
        return FALSE;
    }

    stDateTime.tv_sec += i_iAdjustmentInSeconds;

    if ( 0 != settimeofday(&stDateTime, NULL) )
    {
        return FALSE;
    }
#else
    // TODO: implement for Windows
    return FALSE;
#endif

    return TRUE;
}


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

int K_IsLittleEndian()
{
    short iWord = 0x4321;
    return ((*(unsigned char*)&iWord) == 0x21);
}


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

long K_FileLength32( FILE* i_fpFile )
{
#ifdef WIN32
    int iFileDescriptor = _fileno( i_fpFile );
    struct _stat stStat;
    
    if ( _fstat(iFileDescriptor, &stStat) != 0)
    {
        // error
        return -1L;
    }

#else
    int iFileDescriptor = fileno( i_fpFile );
    struct stat stStat;
    
    if ( fstat(iFileDescriptor, &stStat) != 0)
    {
        // error
        return -1L;
    }

#endif

    return stStat.st_size;
}


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

int K_StringCompareNoCase( const char* i_sString1, const char* i_sString2 )
{
#ifdef WIN32
    return _stricmp( i_sString1, i_sString2 );
#else
    return strcasecmp( i_sString1, i_sString2 );
#endif
}


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

int K_StringCompareNoCaseWide( const wchar_t* i_wsString1, const wchar_t* i_wsString2 )
{
#ifdef WIN32
    return _wcsicmp( i_wsString1, i_wsString2 );
#elif defined K_SOLARIS_PLATFORM
    return wscasecmp( i_wsString1, i_wsString2 );
#else
    return wcscasecmp( i_wsString1, i_wsString2 );
#endif
}


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

int K_CreateDirectory( const char* i_sDirectoryName )
{
    // TODO: make this build all parent directories as well.

#ifdef WIN32
    if ( CreateDirectoryA( i_sDirectoryName, NULL ) )
    {
        return 0;
    }
    else
    {
        DWORD dwError = GetLastError();
        return ( dwError == ERROR_ALREADY_EXISTS ) ? 0 : (dwError ? dwError : -1);
    }
#else
    if ( mkdir( i_sDirectoryName, S_IRWXU ) == 0 )
    {
        return 0;
    }
    else
    {
        return ( errno == EEXIST ) ? 0 : (errno ? errno : -1);
    }
#endif
}


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

int K_DeleteFile( const char* i_sFilename )
{
    int bSuccess = 0;

    bSuccess = 
#ifdef WIN32
        _unlink( 
#else
        unlink( 
#endif
            i_sFilename ) == 0;

    return bSuccess ? 0 : errno;
}


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

int K_ReadFile( const char* i_sFilename, unsigned char** o_ppFileData )
{
    FILE* pFile = 0;
    long iFileSize = 0;

    if ( !i_sFilename || (strlen(i_sFilename) <= 0) || !o_ppFileData )
    {
        return -1;
    }

    *o_ppFileData = 0;

    // Open the file

    pFile = fopen( i_sFilename, "rb" );
    if ( !pFile )
    {
        return -1;
    }

    // Determine the file size

    if ( fseek( pFile, 0, SEEK_END ) )
    {
        (void) fclose( pFile );
        return -1;
    }

    iFileSize = ftell( pFile );
    if ( iFileSize < 0 )
    {
        (void) fclose( pFile );
        return -1;
    }
    else if ( iFileSize == 0 )
    {
        (void) fclose( pFile );
        return 0;
    }

    if ( fseek( pFile, 0, SEEK_SET ) )
    {
        (void) fclose( pFile );
        return -1;
    }

    *o_ppFileData = (unsigned char*)malloc( iFileSize );
    if ( !*o_ppFileData )
    {
        // Out of memory.
        (void) fclose( pFile );
        return -1;
    }

    if ( iFileSize != (long)fread( *o_ppFileData, 1, iFileSize, pFile ) )
    {
        free( *o_ppFileData );
        *o_ppFileData = 0;
        (void) fclose( pFile );
        return -1;
    }

    (void) fclose( pFile );

    return iFileSize;
}


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

int K_ReadFileString( const char* i_sFilename, char** o_psFileDataString )
{
    unsigned char* pFileData = 0;
    int iFileSize = 0;

    *o_psFileDataString = 0;

    iFileSize = K_ReadFile( i_sFilename, &pFileData );

    if ( iFileSize <= 0 )
    {
        return iFileSize;
    }    

    *o_psFileDataString = (char*)malloc( iFileSize+1 );

    if ( !*o_psFileDataString )
    {
        // Out of memory.
        if ( pFileData )
        {
            free( pFileData );
        }
        return -1;
    }

    memcpy( *o_psFileDataString, pFileData, iFileSize );

    (*o_psFileDataString)[iFileSize] = '\0';

    if ( pFileData )
    {
        free( pFileData );
    }

    return iFileSize+1;
}


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

int K_WriteFile( const char* i_sFilename, const unsigned char* i_pFileData, int i_iFileDataSize )
{
    FILE* pFile = 0;

    if ( !i_sFilename || (strlen(i_sFilename) <= 0) || (!i_pFileData && (i_iFileDataSize > 0)) || (i_iFileDataSize < 0) )
    {
        return -1;
    }

    pFile = fopen( i_sFilename, "wb" );
    if ( !pFile )
    {
        int iError = errno;
        return (iError != 0) ? iError : -1;
    }

    if ( i_iFileDataSize > 0 )
    {
        if ( i_iFileDataSize != (int)fwrite( i_pFileData, 1, i_iFileDataSize, pFile ) )
        {
            int iError = ferror( pFile );
            (void) fclose( pFile );
            return (iError != 0) ? iError : -1;
        }
    }

    (void) fclose( pFile );

    return 0;
}


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

int K_WriteFileString( const char* i_sFilename, const char* i_sFileData )
{
    if ( !i_sFilename || (strlen(i_sFilename) <= 0) || !i_sFileData || (strlen(i_sFileData) <= 0) )
    {
        return -1;
    }

    return K_WriteFile( i_sFilename, (const unsigned char*)i_sFileData, strlen(i_sFileData) );
}


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

int K_FileExists( const char* i_sFilename )
{
    FILE* pFile = 0;

    if ( !i_sFilename || (strlen(i_sFilename) <= 0) )
    {
        return -1;
    }

    pFile = fopen( i_sFilename, "r+" );

    if ( !pFile )
    {
        if ( errno == ENOENT )
        {
            return 0;
        }

        return -1;
    }

    (void) fclose( pFile );

    return 1;
}


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

int K_CopyFile( const char* i_sSrcFilename, const char* i_sDestFilename, int* o_pbFileExists )
{
    unsigned char* pFileData = 0;
    int iFileSize = 0;
    int iError, iFileExists;

    if ( !i_sSrcFilename || (strlen(i_sSrcFilename) <= 0) 
         || !i_sDestFilename || (strlen(i_sDestFilename) <= 0) 
         || !o_pbFileExists )
    {
        return -1;
    }

    *o_pbFileExists = 0;

    iFileExists = K_FileExists( i_sDestFilename );

    if ( iFileExists < 0 )
    {
        iError = errno;
        return (iError == 0) ? -1 : iError;
    }
    else if ( iFileExists > 0 )
    {
        *o_pbFileExists = 1;
        return -1;
    }

    iFileSize = K_ReadFile( i_sSrcFilename, &pFileData );
    if ( iFileSize < 0 )
    {
        iError = errno;
        return (iError == 0) ? -1 : iError;
    }

    iError = K_WriteFile( i_sDestFilename, pFileData, iFileSize );

    if ( pFileData )
    {
        free( pFileData );
    }

    return iError;
}


#ifdef K_LINUX_PLATFORM
static int fts_compare( const FTSENT** i_ppF1, const FTSENT** i_ppF2 )
{
    return strcmp( (*i_ppF1)->fts_name, (*i_ppF2)->fts_name );
}
#else
/*
 * Directory traversal code is not yet available for Solaris.
 * If such code will need to be written, then it will probably use ftw.h.
 */
#endif


/*
 *  TODO:  Set up functions for platform-specific find-file operations to
 *  help clean up the code below.
 */

typedef struct K_FindInfo
{
#ifdef WIN32
    struct _finddata_t m_stFindData;
    long m_hFile;
#elif defined K_LINUX_PLATFORM
    FTS* m_pFTS;
    FTSENT* m_pFTSENT;
#else
/*
 * Directory traversal code is not yet available for Solaris.
 * If such code will need to be written, then it will probably use ftw.h.
 */
    int unused;
#endif
} K_FindInfo;

// Memory for filename is held in i_pFindInfo.
const char* K_GetFilenameFromInfo( const K_FindInfo* i_pFindInfo )
{
    if( !i_pFindInfo )
    {
        return 0;
    }

#ifdef WIN32
    return i_pFindInfo->m_stFindData.name;
#elif defined K_LINUX_PLATFORM
    return i_pFindInfo->m_pFTSENT->fts_name;
#else
/*
 * Directory traversal code is not yet available for Solaris.
 * If such code will need to be written, then it will probably use ftw.h.
 */
    FATAL_ASSERT( 0 );
    return 0;
#endif
}

// Forward declarations
int K_FindFileNext( K_FindInfo* io_pFindInfo );
void K_FindFileClose( K_FindInfo* io_pFindInfo );

// Returns 0 if successful, 1 if not found, -1 if error.
// If not error, K_FindFileClose must be called.
// o_pFindInfo must not be null.
int K_FindFileFirst( const char* i_sDirectoryName, K_FindInfo* o_pFindInfo )
{
#ifdef WIN32
    char* sSearchString = 0;
    int iSearchStringIndex = 0;
#endif

    if ( !i_sDirectoryName || (strlen(i_sDirectoryName) <= 0) || !o_pFindInfo )
    {
        return -1;
    }

#ifdef WIN32
    memset( o_pFindInfo, 0, sizeof(K_FindInfo) );

    iSearchStringIndex = strlen(i_sDirectoryName);
    if ( i_sDirectoryName[iSearchStringIndex-1] == PATH_SEPARATOR )
    {
        iSearchStringIndex += 2;
    }
    else
    {
        iSearchStringIndex += 3;
    }

    sSearchString = (char*)calloc( iSearchStringIndex, 1 );
    if ( !sSearchString )
    {
        return -1;
    }

    strcpy( sSearchString, i_sDirectoryName );
    iSearchStringIndex--;
    sSearchString[iSearchStringIndex] = '\0';
    iSearchStringIndex--;
    sSearchString[iSearchStringIndex] = '*';
    iSearchStringIndex--;
    sSearchString[iSearchStringIndex] = PATH_SEPARATOR;

    o_pFindInfo->m_hFile = _findfirst( sSearchString, &o_pFindInfo->m_stFindData );
    free( sSearchString );
    if ( o_pFindInfo->m_hFile == -1 )
    {
        if ( errno == ENOENT )
        {
            return 1;
        }
        else
        {
            return -1;
        }
    }
#elif defined K_LINUX_PLATFORM
    memset( o_pFindInfo, 0, sizeof(K_FindInfo) );

    o_pFindInfo->m_pFTS = fts_open( aPath, FTS_PHYSICAL | FTS_NOSTAT, fts_compare );
    if ( !o_pFindInfo->m_pFTS )
    {
        return -1;
    }

    o_pFindInfo->m_pFTSENT = fts_read( o_pFindInfo->m_pFTS );
    if ( !o_pFindInfo->m_pFTSENT )
    {
        if ( errno == 0 )
        {
            return 1;
        }
        else
        {
            fts_close( o_pFindInfo->m_pFTS );
            return -1;
        }
    }
#else
/*
 * Directory traversal code is not yet available for Solaris.
 * If such code will need to be written, then it will probably use ftw.h.
 */
#endif

    // If what we found is not actually a file, get the next hit.
#ifdef WIN32
    if ( (o_pFindInfo->m_stFindData.attrib & _A_SUBDIR) )
#elif defined K_LINUX_PLATFORM
    if ( !(o_pFindInfo->m_pFTSENT->fts_info & FTS_F) )
#else
/*
 * Directory traversal code is not yet available for Solaris.
 * If such code will need to be written, then it will probably use ftw.h.
 */
#endif
    {
        int iNextReturn = K_FindFileNext( o_pFindInfo );
        if ( iNextReturn < 0 )
        {
            K_FindFileClose( o_pFindInfo );
            return -1;
        }
        else
        {
            return iNextReturn;
        }
    }

#if defined(WIN32) || defined(K_LINUX_PLATFORM)
    return 0;
#endif
}

// Returns 0 if successful, 1 if not found, -1 if error.
int K_FindFileNext( K_FindInfo* io_pFindInfo )
{
    if ( !io_pFindInfo )
    {
        return -1;
    }

#ifdef WIN32
    if ( _findnext( io_pFindInfo->m_hFile, &io_pFindInfo->m_stFindData ) != 0 )
    {
        return (errno == ENOENT) ? 1 : -1;
    }
#elif defined K_LINUX_PLATFORM
    io_pFindInfo->m_pFTSENT = fts_read( io_pFindInfo->m_pFTS );
    if ( !io_pFindInfo->m_pFTSENT )
    {
        return (errno == 0) ? 1 : -1;
    }
#else
/*
 * Directory traversal code is not yet available for Solaris.
 * If such code will need to be written, then it will probably use ftw.h.
 */
#endif

    // If what we found is not actually a file, get the next hit.
#ifdef WIN32
    if ( (io_pFindInfo->m_stFindData.attrib & _A_SUBDIR) )
#elif defined K_LINUX_PLATFORM
    if ( !(io_pFindInfo->m_pFTSENT->fts_info & FTS_F) )
#else
/*
 * Directory traversal code is not yet available for Solaris.
 * If such code will need to be written, then it will probably use ftw.h.
 */
#endif
    {
        return K_FindFileNext( io_pFindInfo );
    }

#if defined(WIN32) || defined(K_LINUX_PLATFORM)
    return 0;
#endif
}

void K_FindFileClose( K_FindInfo* io_pFindInfo )
{
    if ( !io_pFindInfo )
    {
        return;
    }

#ifdef WIN32
    _findclose( io_pFindInfo->m_hFile );
#elif defined K_LINUX_PLATFORM
    fts_close( io_pFindInfo->m_pFTS );
#else
/*
 * Directory traversal code is not yet available for Solaris.
 * If such code will need to be written, then it will probably use ftw.h.
 */
#endif
}


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

int K_GetFilenamesInDirectoryCount( const char* i_sDirectoryName )
{
    K_FindInfo stFindInfo;
    int iCurrentFile = 0;
    int iError = 0;

    if ( !i_sDirectoryName || (strlen(i_sDirectoryName) <= 0) )
    {
        return -1;
    }

    iError = K_FindFileFirst( i_sDirectoryName, &stFindInfo );
    if ( iError < 0 )
    {
        // error
        return -1;
    }
    else if ( iError > 0 )
    {
        // no files found
        K_FindFileClose( &stFindInfo );
        return 0;
    }

    while ( 1 )
    {
        iCurrentFile++;

        iError = K_FindFileNext( &stFindInfo );
        if ( iError < 0 )
        {
            // error
            K_FindFileClose( &stFindInfo );
            return -1;
        }
        else if ( iError > 0 )
        {
            // no more files found
            break;
        }
    }

    K_FindFileClose( &stFindInfo );

    return iCurrentFile;
}


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
        char*** o_pasFilenames )
{
    // Note that we iterate through the filenames twice -- once to get the count
    // (K_GetFilenamesInDirectoryCount) and then once to get all the names. But 
    // it may happen that the count changes between these calls.  So we'll retrieve
    // at most the number of files that's returned in the first pass.

    K_FindInfo stFindInfo;
    int iFilenameCount = 0, iCurrentFile = 0;
    int iError = 0;

    if ( !i_sDirectoryName || (strlen(i_sDirectoryName) <= 0) || !o_pasFilenames )
    {
        return -1;
    }

    *o_pasFilenames = 0;

    iFilenameCount = K_GetFilenamesInDirectoryCount( i_sDirectoryName );

    if ( iFilenameCount < 0 )
    {
        return -1;
    }

    iError = K_FindFileFirst( i_sDirectoryName, &stFindInfo );
    if ( iError < 0 )
    {
        // error
        return -1;
    }
    else if ( iError > 0 )
    {
        // No files found
        K_FindFileClose( &stFindInfo );
        return 0;
    }

    *o_pasFilenames = (char**)calloc( (iFilenameCount+1), sizeof(char*) );    // +1 for the null last one
    if ( !*o_pasFilenames )
    {
        // Out of memory
        K_FindFileClose( &stFindInfo );
        return -1;
    }

    while ( 1 )
    {
        const char* sFilename = K_GetFilenameFromInfo( &stFindInfo );

        size_t iFilenameLength = sFilename ? strlen( sFilename ) : 0;

        if ( iFilenameLength <= 0 )
        {
            K_FreeFilenames( *o_pasFilenames );
            K_FindFileClose( &stFindInfo );
            return -1;
        }

        (*o_pasFilenames)[iCurrentFile] = (char*)calloc( (iFilenameLength+1), sizeof(char) );
        if ( !(*o_pasFilenames)[iCurrentFile] )
        {
            K_FreeFilenames( *o_pasFilenames );
            K_FindFileClose( &stFindInfo );
            return -1;
        }

        strncpy( (*o_pasFilenames)[iCurrentFile], sFilename, iFilenameLength );
        (*o_pasFilenames)[iCurrentFile][iFilenameLength] = '\0';

        iCurrentFile++;

        if ( iCurrentFile >= iFilenameCount )
        {
            break;
        }

        iError = K_FindFileNext( &stFindInfo );
        if ( iError < 0 )
        {
            // error
            K_FindFileClose( &stFindInfo );
            return -1;
        }
        else if ( iError > 0 )
        {
            // no more files found
            break;
        }
    }

    K_FindFileClose( &stFindInfo );

    return iCurrentFile;
}


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

void K_FreeFilenames( char** i_asFilenames )
{
    int i;

    if ( !i_asFilenames )
    {
        return;
    }

    for ( i = 0; (i_asFilenames[i] != 0); i++ )
    {
        free( i_asFilenames[i] );
        i_asFilenames[i] = 0;
    }

    free( i_asFilenames );
}


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

int K_AdjustLocalClock( int i_iNumberOfSeconds )
{
    struct timeval delta, lastchange;

#ifndef K_SOLARIS_PLATFORM
    /* Only supported/tested on Solaris at the moment */

    return -1;
#else
    /* WARNING: uses standard C time functions with Year 2038 limitations */
    time_t now;

    if ( (now = time(NULL)) == ((time_t)-1) )
    {
        return -1;
    }

    delta.tv_sec = i_iNumberOfSeconds;
    delta.tv_usec = 0;

    return adjtime(&delta, &lastchange);
#endif
}


#ifdef K_SOLARIS_PLATFORM
static int pam_tty_conv(
    int num_msg,
    struct pam_message** mess,
    struct pam_response** resp,
    void* my_data)
{
    // Following code implements a console-based PAM "conversation" function
    // (based sample code from Solaris 10 Software Developer Collection >>
    // Solaris Security for Developers Guide >>
    // 3.  Writing PAM Applications and Services)

    struct pam_message* m = *mess;
    struct pam_response* r;
    int i, j;
    const char* sPassword = (const char*)my_data;
    int error = PAM_CONV_ERR;

    if (num_msg <= 0 || num_msg >= PAM_MAX_NUM_MSG)
    {
        (void) fprintf(stderr, "PAM error: bad number of messages");
        *resp = NULL;
        return (PAM_CONV_ERR);
    }

    if ((*resp = r = calloc(num_msg, sizeof (struct pam_response))) == NULL)
    {
        return (PAM_BUF_ERR);
    }

    // Loop through messages
    for (i = 0; i < num_msg; i++) {

        // bad message from service module
        if (m->msg == NULL)
        {
            (void) fprintf(stderr, "PAM error: bad message");
            goto err;
        }

        // fix up final newline: removed for prompts, added back for messages
        if (m->msg[strlen(m->msg)] == '\n')
        {
            m->msg[strlen(m->msg)] = '\0';
        }

        // Since the KMA has its own password prompts and enforces its own rule checks, we already have the
        // new password in memory.  So instead of displaying PAM prompts and collecting user responses, we
        // "automate" by assuming that the prompts correspond to the standard sequence of "New password:"
        // followed by "Confirm password:" and so in each case we immediately return the password we already
        // have in memory.  This violates the PAM "conversation" function instructions (which say, basically,
        // not to assume any particular sequence of prompts since there could be any number of underlying
        // password managers), but since the KMA is running on an appliance with a fixed password manager,
        // our assumptions should hold.

        r->resp = NULL;
        r->resp_retcode = 0;
        switch (m->msg_style)
        {
        case PAM_PROMPT_ECHO_OFF:
        case PAM_PROMPT_ECHO_ON:
            // Assume the prompt asked for New/Confirm password, so return password.
            if ( (r->resp = strdup(sPassword)) == NULL )
            {
                error = PAM_BUF_ERR;
                goto err;
            }
            break;

        case PAM_ERROR_MSG:
            // Assuming the system is configured properly and the KMA password prompts enforce password strength rules,
            // there should not be errors because of weak passwords, etc.  Still, print errors so users/support can
            // diagnose problems.
            (void) fputs(m->msg, stderr);
            (void) fputc('\n', stderr);
            break;

        case PAM_TEXT_INFO:
            // Supress prompts (again, making assumptions).
            break;

        default:
            (void) fprintf(stderr, "PAM error: unknown message");
            goto err;
        }
        if (errno == EINTR)
        {
            goto err;
        }

        // next message/response
        m++;
        r++;
    }
    return (PAM_SUCCESS);

err:
    // Service modules do not clean up responses if an error is returned.
    // Free responses here.
    for (j = 0; j < i; j++, r++)
    {
        if (r->resp)
        {
            // clear before freeing -- may be a password
            bzero(r->resp, strlen(r->resp));
            free(r->resp);
            r->resp = NULL;
        }
    }
    free(r);
    *resp = NULL;
    return error;
}
#endif


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

int K_SetRootPassword( const char* i_sPassword )
{
    // Only supported/tested on Solaris at the moment
#ifndef K_SOLARIS_PLATFORM
    return -1;
#else
    // Based on sample code from Solaris 10 Software Developer Collection >>
    // Solaris Security for Developers Guide >>
    // 3. Writing PAM Applications and Services

    // TODO: Return PAM error codes (to be logged) instead of emitting
    // messages to screen?

    struct pam_conv conv;
    pam_handle_t *pamh;
    int err;

    conv.conv = pam_tty_conv;
    conv.appdata_ptr = (void*)i_sPassword;

    // Initialize PAM framework
    err = pam_start("KeyMgr", "root", &conv, &pamh);
    if (err != PAM_SUCCESS)
    {
        fprintf(stderr, "PAM error: %s\n", pam_strerror(pamh, err));
        return -1;
    }

    // Change password
    err = pam_chauthtok(pamh, 0);
    if (err != PAM_SUCCESS)
    {
        fprintf(stderr, "PAM error: %s\n", pam_strerror(pamh, err));
        // fall through to cleanup
    }

    // Cleanup session
    pam_end(pamh, 0);

    return (err == PAM_SUCCESS) ? 0 : -1;
#endif
}


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

unsigned int K_Alarm( unsigned int i_iSeconds )
{
#ifndef WIN32
    return alarm( i_iSeconds );
#else
    return 0;
#endif
}


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

unsigned int K_GetExtendedVersionFromBase( unsigned int i_iBaseSchemaVersion )
{
    // seconds since 1970, force to 32-bit
#ifdef WIN32
    INT32 iTimeStamp = (INT32) time(NULL);
#else
    int32_t iTimeStamp = (int32_t) time(NULL);
#endif
    // minutes since 1970
    iTimeStamp = iTimeStamp / 60;
    // minutes since 2000 (approximately)
    iTimeStamp -= (30*365*24*60);
    // shift 8 bits to clear out room for schema version #
    iTimeStamp = iTimeStamp << 8;
    // add schema version # to lower end
    iTimeStamp |= i_iBaseSchemaVersion;

    return (unsigned int) iTimeStamp;

}


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
    unsigned int i_iExtendedSchemaVersion )
{
    unsigned int iTimeStamp = i_iExtendedSchemaVersion >> 8;

    return iTimeStamp;
}


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
    unsigned int i_iExtendedSchemaVersion )
{
    unsigned int iBaseSchemaVersion = i_iExtendedSchemaVersion & 0x000000FF;

    return iBaseSchemaVersion;
}


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

int K_System( const char *i_sCmd )
{
#ifndef WIN32
        FILE *p;
        int rc;
        struct sigaction sOldAction;

        // Save signal handler
        sigaction( SIGCHLD, NULL, &sOldAction );

        // Use default child signal handler
        sigset( SIGCHLD, SIG_DFL );

        p = popen( i_sCmd, "w" );
        if ( p == NULL )
        {
            rc = -1;
        }
        else
        {
            rc = pclose( p );
        }

        // Reset signal handler
        sigset( SIGCHLD, sOldAction.sa_handler );

        return rc;
#else
        return system( i_sCmd );
#endif
}

