/*
 * Copyright (c) 2008-2016 Solarflare Communications Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are
 * those of the authors and should not be interpreted as representing official
 * policies, either expressed or implied, of the FreeBSD Project.
 */

#ifndef	_SYS_SFXGE_DEBUG_H
#define	_SYS_SFXGE_DEBUG_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	DEBUG

extern boolean_t sfxge_aask;

#define	SFXGE_OBJ_CHECK(_objp, _type)					\
	do {								\
		uint8_t *p = (uint8_t *)(_objp);			\
		size_t off;						\
									\
		for (off = 0; off < sizeof (_type); off++) {		\
			char buf[MAXNAMELEN];				\
									\
			if (*p++ == 0)					\
				continue;				\
									\
			(void) snprintf(buf, MAXNAMELEN - 1,		\
			    "%s[%d]: non-zero byte found in %s "	\
			    "at 0x%p+%lx", __FILE__, __LINE__, #_type,	\
			    (void *)(_objp), off);			\
									\
			if (sfxge_aask)					\
				debug_enter(buf);			\
			break;						\
		}							\
	_NOTE(CONSTANTCONDITION)					\
	} while (B_FALSE)

/* Log cmn_err(9F) messages to console and system log */
#define	SFXGE_CMN_ERR	""

#else	/* DEBUG */

#define	SFXGE_OBJ_CHECK(_objp, _type)

/* Log cmn_err(9F) messages to system log only */
#define	SFXGE_CMN_ERR	"!"

#endif	/* DEBUG */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SFXGE_DEBUG_H */
