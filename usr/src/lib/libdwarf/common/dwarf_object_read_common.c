/*
Copyright (c) 2018, David Anderson
All rights reserved.

Redistribution and use in source and binary forms, with
or without modification, are permitted provided that the
following conditions are met:

    Redistributions of source code must retain the above
    copyright notice, this list of conditions and the following
    disclaimer.

    Redistributions in binary form must reproduce the above
    copyright notice, this list of conditions and the following
    disclaimer in the documentation and/or other materials
    provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif /* _WIN32 */

#include "config.h"
#include <stdio.h>
#include <string.h> /* memcpy */
#include <sys/types.h> /* lseek and read */
#ifdef HAVE_UNISTD_H
#include <unistd.h> /* lseek read close */
#elif defined(_WIN32) && defined(_MSC_VER)
#include <io.h>
#include <basetsd.h>
typedef SSIZE_T ssize_t; /* MSVC does not have POSIX ssize_t */
#endif /* HAVE_UNISTD_H */

/* Windows specific header files */
#if defined(_WIN32) && defined(HAVE_STDAFX_H)
#include "stdafx.h"
#endif /* HAVE_STDAFX_H */

#include "libdwarf.h" /* For error codes. */
#include "dwarf_object_read_common.h"

/*  Neither off_t nor ssize_t is in C90.
    However, both are in Posix:
    IEEE Std 1003.1-1990, aka
    ISO/IEC 9954-1:1990. */
int
_dwarf_object_read_random(int fd, char *buf, off_t loc,
    size_t size, off_t filesize, int *errc)
{
    off_t scode = 0;
    ssize_t rcode = 0;
    off_t endpoint = 0;

    if (loc >= filesize) {
        /*  Seek can seek off the end. Lets not allow that.
            The object is corrupt. */
        *errc = DW_DLE_SEEK_OFF_END;
        return DW_DLV_ERROR;
    }
    endpoint = loc+size;
    if (endpoint > filesize) {
        /*  Let us -not- try to read past end of object.
            The object is corrupt. */
        *errc = DW_DLE_READ_OFF_END;
        return DW_DLV_ERROR;
    }
    scode = lseek(fd,loc,SEEK_SET);
    if (scode == (off_t)-1) {
        *errc = DW_DLE_SEEK_ERROR;
        return DW_DLV_ERROR;
    }
    rcode = read(fd,buf,size);
    if (rcode == -1 ||
        (size_t)rcode != size) {
        *errc = DW_DLE_READ_ERROR;
        return DW_DLV_ERROR;
    }
    return DW_DLV_OK;
}

void
_dwarf_safe_strcpy(char *out, long outlen, const char *in, long inlen)
{
    if (inlen >= (outlen - 1)) {
        strncpy(out, in, outlen - 1);
        out[outlen - 1] = 0;
    } else {
        strcpy(out, in);
    }
}
