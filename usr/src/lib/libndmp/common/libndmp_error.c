/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <libndmp.h>

int ndmp_errno;

static const struct {
	int err;
	const char *msg;
} ndmp_errlist[] = {
	{ ENDMP_DOOR_SRV_TIMEOUT, "No answer from ndmpd service." },
	{ ENDMP_INVALID_ARG, "Invalid argument." },
	{ ENDMP_DOOR_SRV_OPERATION, "NDMP server operation failed." },
	{ ENDMP_DOOR_OPEN, "Door file open error." },
	{ ENDMP_MEM_ALLOC, "Out of memory." },
	{ ENDMP_DOOR_ENCODE_START, "Data encode start failed." },
	{ ENDMP_DOOR_ENCODE_FINISH, "Data encode finish failed." },
	{ ENDMP_DOOR_DECODE_FINISH, "Data decode finish failed." },
	{ ENDMP_SMF_PERM, "SMF permission denied." },
	{ ENDMP_SMF_INTERNAL, "SMF internal error." },
	{ ENDMP_SMF_PROP, "SMF property not set." },
	{ ENDMP_SMF_PROP_GRP, "Invalid SMF property group" }
};

static const int ndmp_nerr = sizeof (ndmp_errlist) / sizeof (ndmp_errlist[0]);

const char *
ndmp_strerror(int errnum)
{
	int i;

	if (((errnum >= ENDMP_BASE) && (errnum - ENDMP_BASE)) < ndmp_nerr) {
		for (i = 0; i < ndmp_nerr; i++) {
			if (ndmp_errlist[i].err == errnum)
				return (ndmp_errlist[i].msg);
			}
	}
	return ("Unknown error");
}
