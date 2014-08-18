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
 * Copyright 2012, Joyent, Inc. All rights reserved.
 */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <sys/brand.h>
#include <sys/syscall.h>
#include <sys/systm.h>
#include <sys/stat.h>
#include <libgen.h>
#include <sys/auxv.h>

#include <sngl_brand.h>
#include <brand_misc.h>

/*
 * See usr/src/lib/brand/shared/brand/common/brand_util.c for general
 * emulation notes.
 */

#define	CONF32_PATH	"/system/usr/lib/brand/sngl/ld.sys.config"
#define	CONF64_PATH	"/system/usr/lib/brand/sngl/ld.sys64.config"

brand_sysent_table_t brand_sysent_table[];

static boolean_t is_sys = B_FALSE;
static boolean_t is_crle = B_FALSE;

typedef struct {
	char *mnt_name;
	dev_t mnt_id;
} sys_mnt_dev_t;

/*
 * The brand platform mounts several GZ file systems into the zone. We know
 * which ones can actually be on seperate file systems, so we only stat those
 * when checking for system commands. This reduces the number of stats needed
 * when we start up.
 */
static sys_mnt_dev_t sys_mounts[] = {
	{"/system/usr", 0},
	{"/lib", 0},
	{NULL, 0}
};

/*
 * If this is a /sytem binary and ld.so is opening the default config file,
 * then redirect so it opens the /system config file instead. We need to do it
 * this way, instead of setting one of the LD_CONFIG env vars, since those
 * are ignored for secure binaries.
 *
 * We don't redirect if we're crle so that it can still be used on the default
 * config files.
 */
int
sngl_open(sysret_t *rval, char *path, int oflag, mode_t mode)
{
	char tstr[MAXPATHLEN];

	if (is_sys && !is_crle) {
		/* Get a copy of the path we're trying to open */
		bzero(tstr, sizeof (tstr));
		(void) brand_uucopystr(path, tstr, sizeof (tstr));

		if (strcmp(tstr, "/var/ld/ld.config") == 0)
			return (__systemcall(rval, SYS_open + 1024,
			    CONF32_PATH, oflag, mode));

		if (strcmp(tstr, "/var/ld/64/ld.config") == 0)
			return (__systemcall(rval, SYS_open + 1024,
			    CONF64_PATH, oflag, mode));
	}

	return (__systemcall(rval, SYS_open + 1024, path, oflag, mode));
}

/*ARGSUSED*/
int
brand_init(int argc, char *argv[], char *envp[])
{
	ulong_t		ldentry;
	int		i;
	uintptr_t	*p;
	auxv_t		*ap;
	struct stat64	buf;
	char		*bname;

	brand_pre_init();

	/*
	 * Check if we're trying to run a system binary.
	 *
	 * We haven't installed our emulation table yet, so its safe to make
	 * system calls directly.
	 *
	 * First, get the /system devices, then stat the executable to see if
	 * its on one of the /system devs.
	 */
	for (i = 0; sys_mounts[i].mnt_name != NULL; i++) {
		if (stat64(sys_mounts[i].mnt_name, &buf) != -1)
			sys_mounts[i].mnt_id = buf.st_dev;
	}

	/* Find the aux vector on the stack. */
	p = (uintptr_t *)envp;
	while (*p != NULL)
		p++;
	p++;

	/* Find AT_SUN_EXECNAME */
	for (ap = (auxv_t *)p; ap->a_type != AT_NULL; ap++) {
		if (ap->a_type != AT_SUN_EXECNAME)
			continue;
		if (stat64(ap->a_un.a_ptr, &buf) != -1) {
			for (i = 0; sys_mounts[i].mnt_name != NULL; i++) {
				if (sys_mounts[i].mnt_id == buf.st_dev) {
					is_sys = B_TRUE;
					bname = basename(ap->a_un.a_ptr);
					if (strcmp("crle", bname) == 0)
						is_crle = B_TRUE;
					break;
				}
			}
		}
		break;
	}

	ldentry = brand_post_init(SNGL_VERSION, argc, argv, envp);

	brand_runexe(argv, ldentry);
	/*NOTREACHED*/
	brand_abort(0, "brand_runexe() returned");
	return (-1);
}

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
	NOSYS,					/*  0 */
	NOSYS,					/*   1 */
	NOSYS,					/*   2 */
	NOSYS,					/*   3 */
	NOSYS,					/*   4 */
	EMULATE(sngl_open, 3 | RV_DEFAULT),	/*   5 */
	NOSYS,					/*   6 */
	NOSYS,					/*   7 */
	NOSYS,					/*   8 */
	NOSYS,					/*   9 */
	NOSYS,					/*  10 */
	NOSYS,					/*  11 */
	NOSYS,					/*  12 */
	NOSYS,					/*  13 */
	NOSYS,					/*  14 */
	NOSYS,					/*  15 */
	NOSYS,					/*  16 */
	NOSYS,					/*  17 */
	NOSYS,					/*  18 */
	NOSYS,					/*  19 */
	NOSYS,					/*  20 */
	NOSYS,					/*  21 */
	NOSYS,					/*  22 */
	NOSYS,					/*  23 */
	NOSYS,					/*  24 */
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
	NOSYS,					/*  43 */
	NOSYS,					/*  44 */
	NOSYS,					/*  45 */
	NOSYS,					/*  46 */
	NOSYS,					/*  47 */
	NOSYS,					/*  48 */
	NOSYS,					/*  49 */
	NOSYS,					/*  50 */
	NOSYS,					/*  51 */
	NOSYS,					/*  52 */
	NOSYS,					/*  53 */
	NOSYS,					/*  54 */
	NOSYS,					/*  55 */
	NOSYS,					/*  56 */
	NOSYS,					/*  57 */
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
	NOSYS,					/*  90 */
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
	NOSYS,					/* 107 */
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
	NOSYS,					/* 135 */
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
