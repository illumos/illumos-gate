/*******************************************************************************
 * Copyright (C) 2004-2008 Intel Corp. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 *  - Neither the name of Intel Corp. nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL Intel Corp. OR THE CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/

#ifndef __LMS_PLUGIN_H__
#define __LMS_PLUGIN_H__

#define LMS_OK		   0x0
#define LMS_ERROR	   0x1

#define LMS_ACCEPTED  0x1
#define LMS_DROPPED   0x2
#define LMS_STOPPED   0x3


#ifdef __sun
#define LMS_PLUGIN_CONFIG_FILE   "/etc/lms_plugin.conf"
#else
#define LMS_PLUGIN_CONFIG_FILE   "@prefix@/etc/lms_plugin.conf"
#endif

#define LMS_INIT_FUNC_NAME	"lms_init_func"
#define LMS_VERSION_FUNC_NAME   "lms_version_func"
#define LMS_PRE_FUNC_NAME	"lms_pre_func"
#define LMS_RETRY_FUNC_NAME	"lms_retry_func"
#define LMS_POST_FUNC_NAME	"lms_post_func"
#define LMS_DEINIT_FUNC_NAME	"lms_deinit_func"


typedef int (*lms_init_t)(void);
typedef void (*lms_version_t)(unsigned char version);
typedef int (*lms_pre_t)(unsigned char *buff, int len);
typedef int (*lms_retry_t)(unsigned char *buff, int len);
typedef int (*lms_post_t)(unsigned char *buff, int len, int status);
typedef void (*lms_deinit_t)(void);


#endif

