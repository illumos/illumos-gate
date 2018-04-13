/*
 * Copyright (c) 2000, Boris Popov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SMBUTIL_COMMON_H
#define	_SMBUTIL_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>

int  cmd_crypt(int argc, char *argv[]);
int  cmd_help(int argc, char *argv[]);
int  cmd_info(int argc, char *argv[]);
int  cmd_login(int argc, char *argv[]);
int  cmd_logout(int argc, char *argv[]);
int  cmd_logoutall(int argc, char *argv[]);
int  cmd_lookup(int argc, char *argv[]);
int  cmd_print(int argc, char *argv[]);
int  cmd_status(int argc, char *argv[]);
int  cmd_view(int argc, char *argv[]);

void crypt_usage(void);
void help_usage(void);
void info_usage(void);
void login_usage(void);
void logout_usage(void);
void logoutall_usage(void);
void lookup_usage(void);
void print_usage(void);
void status_usage(void);
void view_usage(void);

/* See view.c */
int share_enum_rap(struct smb_ctx *ctx);
int share_enum_rpc(struct smb_ctx *ctx, char *server);
void view_print_share(char *share, int type, char *comment);

#ifdef __cplusplus
}
#endif

#endif	/* _SMBUTIL_COMMON_H */
