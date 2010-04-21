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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <sys/auxv.h>
#include <sys/bitmap.h>
#include <sys/brand.h>
#include <sys/inttypes.h>
#include <sys/lwp.h>
#include <sys/syscall.h>
#include <sys/systm.h>
#include <sys/utsname.h>
#include <fcntl.h>

#include <sn1_brand.h>
#include <brand_misc.h>

/*
 * See usr/src/lib/brand/shared/brand/common/brand_util.c for general
 * emulation notes.
 *
 * *** sn1 brand emulation scope considerations
 *
 * Given that the sn1 brand exists for testing purposes, it should
 * eventually be enhanced to redirect all system calls through the
 * brand emulation library.  This will ensure the maximum testing
 * exposure for the brandz infrastructure.  Some other options to
 * consider for improving brandz test exposure are:
 * - Folding the sn1 brand into the native brand and only enabling
 *   it on DEBUG builds.
 * - Modifying the zones test suite to use sn1 branded zones by default,
 *   and adapting functional test harnesses to use sn1 branded zones
 *   by default instead of native zones.
 */

static long
sn1_uname(sysret_t *rv, uintptr_t p1)
{
	struct utsname	un, *unp = (struct utsname *)p1;
	int		rev, err;

	if ((err = __systemcall(rv, SYS_uname + 1024, &un)) != 0)
		return (err);

	rev = atoi(&un.release[2]);
	brand_assert(rev >= 10);
	(void) sprintf(un.release, "5.%d", rev - 1);

	if (uucopy(&un, unp, sizeof (un)) != 0)
		return (EFAULT);
	return (0);
}

/*ARGSUSED*/
int
brand_init(int argc, char *argv[], char *envp[])
{
	ulong_t			ldentry;

	brand_pre_init();
	ldentry = brand_post_init(SN1_VERSION, argc, argv, envp);

	brand_runexe(argv, ldentry);
	/*NOTREACHED*/
	brand_abort(0, "brand_runexe() returned");
	return (-1);
}

#define	IN_KERNEL_SYSCALL(name, num)					\
static long								\
sn1_##name(sysret_t *rv,						\
    uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3,		\
    uintptr_t a4, uintptr_t a5, uintptr_t a6, uintptr_t a7)		\
{									\
	return (__systemcall(rv, num + 1024,				\
	    a0, a1, a2, a3, a4, a5, a6, a7));				\
}

/*
 * These are branded system calls, which have been redirected to this
 * userland emulation library, and are emulated by passing them strait
 * on to the kernel as native system calls.
 */
IN_KERNEL_SYSCALL(read,		SYS_read)		/*   3 */
IN_KERNEL_SYSCALL(write,	SYS_write)		/*   4 */
IN_KERNEL_SYSCALL(time,		SYS_time)		/*  13 */
IN_KERNEL_SYSCALL(getpid,	SYS_getpid)		/*  20 */
IN_KERNEL_SYSCALL(mount,	SYS_mount)		/*  21 */
IN_KERNEL_SYSCALL(getuid,	SYS_getuid)		/*  24 */
IN_KERNEL_SYSCALL(times,	SYS_times)		/*  43 */
IN_KERNEL_SYSCALL(getgid,	SYS_getgid)		/*  47 */
IN_KERNEL_SYSCALL(utssys,	SYS_utssys)		/*  57 */
IN_KERNEL_SYSCALL(readlink,	SYS_readlink)		/*  90 */
IN_KERNEL_SYSCALL(waitid,	SYS_waitid)		/* 107 */

/*
 * This table must have at least NSYSCALL entries in it.
 *
 * The second parameter of each entry in the brand_sysent_table
 * contains the number of parameters and flags that describe the
 * syscall return value encoding.  See the block comments at the
 * top of this file for more information about the syscall return
 * value flags and when they should be used.
 */
brand_sysent_table_t brand_sysent_table[] = {
#if defined(__sparc) && !defined(__sparcv9)
	EMULATE(brand_indir, 9 | RV_64RVAL),	/*  0 */
#else /* !__sparc || __sparcv9 */
	NOSYS,					/*  0 */
#endif /* !__sparc || __sparcv9 */
	NOSYS,					/*   1 */
	NOSYS,					/*   2 */
	EMULATE(sn1_read, 3 | RV_DEFAULT),	/*   3 */
	EMULATE(sn1_write, 3 | RV_DEFAULT),	/*   4 */
	NOSYS,					/*   5 */
	NOSYS,					/*   6 */
	NOSYS,					/*   7 */
	NOSYS,					/*   8 */
	NOSYS,					/*   9 */
	NOSYS,					/*  10 */
	NOSYS,					/*  11 */
	NOSYS,					/*  12 */
	EMULATE(sn1_time, 0 | RV_DEFAULT),	/*  13 */
	NOSYS,					/*  14 */
	NOSYS,					/*  15 */
	NOSYS,					/*  16 */
	NOSYS,					/*  17 */
	NOSYS,					/*  18 */
	NOSYS,					/*  19 */
	EMULATE(sn1_getpid, 0 | RV_32RVAL2),	/*  20 */
	EMULATE(sn1_mount, 8 | RV_DEFAULT),	/*  21 */
	NOSYS,					/*  22 */
	NOSYS,					/*  23 */
	EMULATE(sn1_getuid, 0 | RV_32RVAL2),	/*  24 */
	NOSYS,					/*  25 */
	NOSYS,					/*  26 */
	NOSYS,					/*  27 */
	NOSYS,					/*  28 */
	NOSYS,					/*  29 */
	NOSYS,					/*  30 */
	NOSYS,					/*  31 */
	NOSYS,					/*  32 */
	NOSYS,					/*  33 */
	NOSYS,					/*  34 */
	NOSYS,					/*  35 */
	NOSYS,					/*  36 */
	NOSYS,					/*  37 */
	NOSYS,					/*  38 */
	NOSYS,					/*  39 */
	NOSYS,					/*  40 */
	NOSYS,					/*  41 */
	NOSYS,					/*  42 */
	EMULATE(sn1_times, 1 | RV_DEFAULT),	/*  43 */
	NOSYS,					/*  44 */
	NOSYS,					/*  45 */
	NOSYS,					/*  46 */
	EMULATE(sn1_getgid, 0 | RV_32RVAL2),	/*  47 */
	NOSYS,					/*  48 */
	NOSYS,					/*  49 */
	NOSYS,					/*  50 */
	NOSYS,					/*  51 */
	NOSYS,					/*  52 */
	NOSYS,					/*  53 */
	NOSYS,					/*  54 */
	NOSYS,					/*  55 */
	NOSYS,					/*  56 */
	EMULATE(sn1_utssys, 4 | RV_32RVAL2),	/*  57 */
	NOSYS,					/*  58 */
	NOSYS,					/*  59 */
	NOSYS,					/*  60 */
	NOSYS,					/*  61 */
	NOSYS,					/*  62 */
	NOSYS,					/*  63 */
	NOSYS,					/*  64 */
	NOSYS,					/*  65 */
	NOSYS,					/*  66 */
	NOSYS,					/*  67 */
	NOSYS,					/*  68 */
	NOSYS,					/*  69 */
	NOSYS,					/*  70 */
	NOSYS,					/*  71 */
	NOSYS,					/*  72 */
	NOSYS,					/*  73 */
	NOSYS,					/*  74 */
	NOSYS,					/*  75 */
	NOSYS,					/*  76 */
	NOSYS,					/*  77 */
	NOSYS,					/*  78 */
	NOSYS,					/*  79 */
	NOSYS,					/*  80 */
	NOSYS,					/*  81 */
	NOSYS,					/*  82 */
	NOSYS,					/*  83 */
	NOSYS,					/*  84 */
	NOSYS,					/*  85 */
	NOSYS,					/*  86 */
	NOSYS,					/*  87 */
	NOSYS,					/*  88 */
	NOSYS,					/*  89 */
	EMULATE(sn1_readlink, 3 | RV_DEFAULT),	/*  90 */
	NOSYS,					/*  91 */
	NOSYS,					/*  92 */
	NOSYS,					/*  93 */
	NOSYS,					/*  94 */
	NOSYS,					/*  95 */
	NOSYS,					/*  96 */
	NOSYS,					/*  97 */
	NOSYS,					/*  98 */
	NOSYS,					/*  99 */
	NOSYS,					/* 100 */
	NOSYS,					/* 101 */
	NOSYS,					/* 102 */
	NOSYS,					/* 103 */
	NOSYS,					/* 104 */
	NOSYS,					/* 105 */
	NOSYS,					/* 106 */
	EMULATE(sn1_waitid, 4 | RV_DEFAULT),	/* 107 */
	NOSYS,					/* 108 */
	NOSYS,					/* 109 */
	NOSYS,					/* 110 */
	NOSYS,					/* 111 */
	NOSYS,					/* 112 */
	NOSYS,					/* 113 */
	NOSYS,					/* 114 */
	NOSYS,					/* 115 */
	NOSYS,					/* 116 */
	NOSYS,					/* 117 */
	NOSYS,					/* 118 */
	NOSYS,					/* 119 */
	NOSYS,					/* 120 */
	NOSYS,					/* 121 */
	NOSYS,					/* 122 */
	NOSYS,					/* 123 */
	NOSYS,					/* 124 */
	NOSYS,					/* 125 */
	NOSYS,					/* 126 */
	NOSYS,					/* 127 */
	NOSYS,					/* 128 */
	NOSYS,					/* 129 */
	NOSYS,					/* 130 */
	NOSYS,					/* 131 */
	NOSYS,					/* 132 */
	NOSYS,					/* 133 */
	NOSYS,					/* 134 */
	EMULATE(sn1_uname, 1 | RV_DEFAULT),	/* 135 */
	NOSYS,					/* 136 */
	NOSYS,					/* 137 */
	NOSYS,					/* 138 */
	NOSYS,					/* 139 */
	NOSYS,					/* 140 */
	NOSYS,					/* 141 */
	NOSYS,					/* 142 */
	NOSYS,					/* 143 */
	NOSYS,					/* 144 */
	NOSYS,					/* 145 */
	NOSYS,					/* 146 */
	NOSYS,					/* 147 */
	NOSYS,					/* 148 */
	NOSYS,					/* 149 */
	NOSYS,					/* 150 */
	NOSYS,					/* 151 */
	NOSYS,					/* 152 */
	NOSYS,					/* 153 */
	NOSYS,					/* 154 */
	NOSYS,					/* 155 */
	NOSYS,					/* 156 */
	NOSYS,					/* 157 */
	NOSYS,					/* 158 */
	NOSYS,					/* 159 */
	NOSYS,					/* 160 */
	NOSYS,					/* 161 */
	NOSYS,					/* 162 */
	NOSYS,					/* 163 */
	NOSYS,					/* 164 */
	NOSYS,					/* 165 */
	NOSYS,					/* 166 */
	NOSYS,					/* 167 */
	NOSYS,					/* 168 */
	NOSYS,					/* 169 */
	NOSYS,					/* 170 */
	NOSYS,					/* 171 */
	NOSYS,					/* 172 */
	NOSYS,					/* 173 */
	NOSYS,					/* 174 */
	NOSYS,					/* 175 */
	NOSYS,					/* 176 */
	NOSYS,					/* 177 */
	NOSYS,					/* 178 */
	NOSYS,					/* 179 */
	NOSYS,					/* 180 */
	NOSYS,					/* 181 */
	NOSYS,					/* 182 */
	NOSYS,					/* 183 */
	NOSYS,					/* 184 */
	NOSYS,					/* 185 */
	NOSYS,					/* 186 */
	NOSYS,					/* 187 */
	NOSYS,					/* 188 */
	NOSYS,					/* 189 */
	NOSYS,					/* 190 */
	NOSYS,					/* 191 */
	NOSYS,					/* 192 */
	NOSYS,					/* 193 */
	NOSYS,					/* 194 */
	NOSYS,					/* 195 */
	NOSYS,					/* 196 */
	NOSYS,					/* 197 */
	NOSYS,					/* 198 */
	NOSYS,					/* 199 */
	NOSYS,					/* 200 */
	NOSYS,					/* 201 */
	NOSYS,					/* 202 */
	NOSYS,					/* 203 */
	NOSYS,					/* 204 */
	NOSYS,					/* 205 */
	NOSYS,					/* 206 */
	NOSYS,					/* 207 */
	NOSYS,					/* 208 */
	NOSYS,					/* 209 */
	NOSYS,					/* 210 */
	NOSYS,					/* 211 */
	NOSYS,					/* 212 */
	NOSYS,					/* 213 */
	NOSYS,					/* 214 */
	NOSYS,					/* 215 */
	NOSYS,					/* 216 */
	NOSYS,					/* 217 */
	NOSYS,					/* 218 */
	NOSYS,					/* 219 */
	NOSYS,					/* 220 */
	NOSYS,					/* 221 */
	NOSYS,					/* 222 */
	NOSYS,					/* 223 */
	NOSYS,					/* 224 */
	NOSYS,					/* 225 */
	NOSYS,					/* 226 */
	NOSYS,					/* 227 */
	NOSYS,					/* 228 */
	NOSYS,					/* 229 */
	NOSYS,					/* 230 */
	NOSYS,					/* 231 */
	NOSYS,					/* 232 */
	NOSYS,					/* 233 */
	NOSYS,					/* 234 */
	NOSYS,					/* 235 */
	NOSYS,					/* 236 */
	NOSYS,					/* 237 */
	NOSYS,					/* 238 */
	NOSYS,					/* 239 */
	NOSYS,					/* 240 */
	NOSYS,					/* 241 */
	NOSYS,					/* 242 */
	NOSYS,					/* 243 */
	NOSYS,					/* 244 */
	NOSYS,					/* 245 */
	NOSYS,					/* 246 */
	NOSYS,					/* 247 */
	NOSYS,					/* 248 */
	NOSYS,					/* 249 */
	NOSYS,					/* 250 */
	NOSYS,					/* 251 */
	NOSYS,					/* 252 */
	NOSYS,					/* 253 */
	NOSYS,					/* 254 */
	NOSYS					/* 255 */
};
