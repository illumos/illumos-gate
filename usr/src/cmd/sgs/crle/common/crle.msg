#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

@ _START_

# Message file for cmd/sgs/crle.

@ MSG_ID_CRLE


# Argument usage messages.

@ MSG_ARG_USAGE		"usage: %s [-64] [-a name] [-A name] [-c conf] \
			 [-e env] [-E env] [-f flags] [-g name] [-G name ] \
			 [-i name] [-I name] [-l dir] [-o dir ] [-s dir] \
			 [-t ELF|AOUT] [-u] [-v]\n\
			 \t[-64]\t\tprocess 64-bit objects\n\
			 \t[-a name]\tdefine an alternative object name\n\
			 \t[-A name]\tdefine an optional alternative object \
			  name\n\
			 \t[-c conf]\tspecify configuration file\n\
			 \t[-e env]\tdefine a replaceable environment \
			  variable\n\
			 \t[-E env]\tdefine a permanent environment variable\n\
			 \t[-f flags]\tspecify flags for -G and -I\n\
			 \t[-g name]\tdefine a group object name\n\
			 \t[-G name]\tdefine a group object name and create \
			  alternatives\n\
			 \t[-i name]\tdefine an individual object name\n\
			 \t[-I name]\tdefine an individual object name and \
			  create an\n\
			 \t\t\talternative\n\
			 \t[-l dir]\tdefine a default search directory\n\
			 \t[-o dir]\tuse directory for alternative objects\n\
			 \t[-s dir]\tdefine a  trusted search directory\n\
			 \t[-t ELF|AOUT]\ttoggle object type for -l and -s\n\
			 \t[-u]\t\tupdate existing configuration file\n\
			 \t[-v]\t\tprovide verbose processing information\n\
			 \n\
			 \tNote: without the -u option, the information \
			  defined by the options\n\
			 \tto crle() result in the replacement of any existing \
			  configuration\n\
			 \tfile, or default search paths.  With the -u option, \
			  the information\n\
			 \tdefined by the options to crle() is appended to any \
			  existing\n\
			 \tconfiguration file, or default search paths.\n\
			 \n\
			 \tSet the environment variable LD_NOCONFIG=yes to \
			  disable the processing\n\
			 \tof any configuration file information.  \
			  See ld.so.1(1).\n"


@ MSG_ARG_ILLEGAL	"%s: option %s has illegal argument `%s'\n"
@ MSG_ARG_MULT		"%s: argument %s specified multiple times\n"
@ MSG_ARG_TYPE		"%s: unknown object type: %s\n"
@ MSG_ARG_FLAGS		"%s: unknown flags: %s\n"
@ MSG_ARG_MODE		"%s: RTLD_REL_EXEC cannot be used with multiple \
			 dynamic executables: %s: %s\n"
@ MSG_ARG_ALT		"%s: %s: cannot override original file with \
			 alternative; specify -o\n"
@ MSG_ARG_UPDATE	"%s: %s: version [%d] of configuration file provides \
			 limited update (-u) and command-line regeneration \
			 capabilities: best effort in effect\n"
@ MSG_ARG_UPDATEVER	"%s: %s: file version [%d] newer than crle() version \
			[%d].  Unable to update\n"
@ MSG_ARG_PRINTVER	"%s: %s: file version [%d] newer than crle() version \
			[%d]. Displayed information may be incomplete\n"
@ MSG_ARG_CLASS		"%s: %s: 32-bit file is incompatible with -64 \
			 option\n"
@ MSG_ARG_WRONGARCH	"%s: %s: %s %s file is incompatible with \
			%s %s version of crle()\n"

@ MSG_WARN_ENV		"%s: warning: %.*s: environment variable \
			 multiply-defined, first definition taken\n"

# ISA errors
@ MSG_ISA32_NO64SUP	"%s: This system lacks support for 64-bit \
			configuration files\n"

# System error messages

@ MSG_SYS_MALLOC	"%s: malloc failed: %s\n"
@ MSG_SYS_TEMPNAME	"%s: unable to create temporary filename: %s\n"
@ MSG_SYS_PIPE		"%s: pipe failed: %s\n"
@ MSG_SYS_FORK		"%s: fork failed: %s\n"
@ MSG_SYS_PUTENV	"%s: putenv failed: %s\n"

@ MSG_COR_TRUNC		"%s: %s: corrupt file, possible truncation\n"

@ MSG_SYS_ACCESS	"%s: %s: access failed: %s\n"
@ MSG_SYS_OPEN		"%s: %s: open failed: %s\n"
@ MSG_SYS_MMAP		"%s: %s: mmap failed: %s\n"
@ MSG_SYS_TRUNC		"%s: %s: ftruncate failed: %s\n"
@ MSG_SYS_STAT		"%s: %s: stat failed: %s\n"
@ MSG_SYS_WRITE		"%s: %s: write failed: %s\n"

@ MSG_SYS_EXEC		"%s: %s: exec failed: due to signal %d %s\n"
@ MSG_SYS_EXECLP	"%s: %s: exec failed: %s\n"
@ MSG_SYS_CORE		"(core dumped)"


# Elf error messages

@ MSG_ELF_TYPE		"%s: %s: invalid ELF file\n"
@ MSG_ELF_BEGIN		"%s: %s: elf_begin: %s\n"


# Generic error messages

@ MSG_GEN_INVFILE	"%s: %s: invalid file type\n"
@ MSG_GEN_CREATE	"%s: configuration file: %s: not created\n"


# System defaults

@ MSG_DEF_NOCONF	"\nDefault configuration file (%s) not found\n"

@ MSG_DEF_NEWDLP	"  Default Library Path (ELF):\t/lib:/usr/lib  \
			 (system default)\n"
@ MSG_DEF_OLDDLP	"  Default Library Path (ELF):\t/usr/lib  \
			 (system default)\n"
@ MSG_DEF_NEWTD		"  Trusted Directories (ELF):\t\
			 /lib/secure:/usr/lib/secure  (system default)\n"
@ MSG_DEF_OLDTD		"  Trusted Directories (ELF):\t/usr/lib/secure  \
			 (system default)\n"
@ MSG_DEF_NEWDLP_64	"  Default Library Path (ELF):\t/lib/64:/usr/lib/64  \
			 (system default)\n"
@ MSG_DEF_OLDDLP_64	"  Default Library Path (ELF):\t/usr/lib/64  \
			 (system default)\n"
@ MSG_DEF_NEWTD_64	"  Trusted Directories (ELF):\t\
			 /lib/secure/64:/usr/lib/secure/64  (system default)\n"
@ MSG_DEF_OLDTD_64	"  Trusted Directories (ELF):\t\
			 /usr/lib/secure/64  (system default)\n"

@ MSG_DEF_AOUTDLP	"  Default Library Path (AOUT):\t\
			 /usr/lib:/usr/local/lib  \
			 (system default)\n"
@ MSG_DEF_AOUTNEWTD	"  Trusted Directories (AOUT):\t\
			 /lib/secure:/usr/lib/secure  (system default)\n"
@ MSG_DEF_AOUTOLDTD	"  Trusted Directories (AOUT):\t\/usr/lib/secure  \
			 (system default)\n"

@ MSG_ENV_TITLE		"\nEnvironment Variables:\n"
@ MSG_ENV_RPL		"  %s  (replaceable)\n"
@ MSG_ENV_PRM		"  %s  (permanent)\n"

@ MSG_FLT_TITLE		"\nFilters:\n"
@ MSG_FLT_FILTER	"  %s  -  %s:\n"
@ MSG_FLT_FILTEE	"    %s  (filtee)\n"

# Diagnostic strings

@ MSG_DIA_CONFILE	"output configuration file: %s\n"
@ MSG_DIA_OBJDIR	"output object directory: %s\n"
@ MSG_DIA_INSPECT	"inspect: %s\n"
@ MSG_DIA_RPLENV	" adding replaceable environment variable: %s\n"
@ MSG_DIA_PRMENV	" adding permanent environment variable: %s\n"
@ MSG_DIA_DLIBPTH	" adding default library path (%s): %s\n"
@ MSG_DIA_TLIBPTH	" adding trusted library path (%s): %s\n"
@ MSG_DIA_NOEXIST	" adding directory [id=%d]: %s  (non-existent path)\n"
@ MSG_DIA_DIR		" adding directory [id=%d]: %s\n",
@ MSG_DIA_FILE		"  adding file [id=%d]: %s\n"
@ MSG_DIA_ALTCREATE	"    creating alternate: %s  (for %s)\n"
@ MSG_DIA_ALTUPDATE	"    updating alternate: %s  (for %s)\n"

# Dump strings

@ MSG_DMP_HEAD		"\nConfiguration file [version %d]: %s  %s\n"
@ MSG_DMP_PLATFORM	"  Platform:\t%s %s %s\n"
@ MSG_DMP_APP		"  Specific application: %s  (original: %s)\n"
@ MSG_DMP_DLIBPTH	"  Default Library Path (%s):\t%s\n"
@ MSG_DMP_TLIBPTH	"  Trusted Directories (%s):\t%s\n"
@ MSG_DMP_RESV		"\nMemory Reservation:\t%llx - %llx (%llx bytes)\n"
@ MSG_DMP_DIR_1		"\nDirectory: %s\n"
@ MSG_DMP_DIR_2		"\nDirectory: %s\t(non-existent)\n"
@ MSG_DMP_FILE_1	"  %s\n"
@ MSG_DMP_FILE_2	"  %s\t(alternate: %s)\n"
@ MSG_DMP_HASH		"Object Entries:\n   Id\tBkt\tString\n"
@ MSG_DMP_HASHENT_1	"    %d\t[%d]\t%s\t%s\n"
@ MSG_DMP_HASHENT_2	"    %d\t\t%s\t%s\n"

@ MSG_DMP_STAT		"\nWARNING: original file %s: stat failed: %s\n\n"
@ MSG_DMP_DCMP		"\nWARNING: original directory %s: modified since \
			 configuration file creation\n\n"
@ MSG_DMP_FCMP		"\nWARNING: original file %s: modified since \
			 configuration file creation\n\n"

@ MSG_DMP_CMD_TITLE	"\nCommand line:\n"
@ MSG_DMP_CMD_ONE	"  crle %s\n\n"
@ MSG_DMP_CMD_BGN	"  crle %s "
@ MSG_DMP_CMD_MID	"%s "
@ MSG_DMP_CMD_END	"%s\n\n"

@ MSG_DMP_CMD_ONE_V	"  crle %s\n\n"
@ MSG_DMP_CMD_BGN_V	"  crle %s \\\n"
@ MSG_DMP_CMD_MID_V	"    %s \\\n"
@ MSG_DMP_CMD_END_V	"    %s\n\n"

@ _END_


# The following strings represent reserved words, files, pathnames and symbols.
# Reference to this strings is via the MSG_ORIG() macro, and thus no message
# translation is required.

@ MSG_ARG_OPTIONS	"6:a:A:c:e:E:f:G:g:I:i:l:o:s:t:uv"
@ MSG_ARG_6		"-6"
@ MSG_ARG_C		"-c"
@ MSG_ARG_F		"-f"

@ MSG_CMD_64		"-64"
@ MSG_CMD_ALTER		"-a %s"
@ MSG_CMD_OPTIONAL	"-A %s"
@ MSG_CMD_CONF		"-c %s"
@ MSG_CMD_RPLENV	"-e %s"
@ MSG_CMD_PRMENV	"-E %s"
@ MSG_CMD_FLAGS		"-f %s"
@ MSG_CMD_GRP		"-g %s"
@ MSG_CMD_DUMPGRP	"-G %s"
@ MSG_CMD_IND		"-i %s"
@ MSG_CMD_DUMPIND	"-I %s"
@ MSG_CMD_EDLIB		"-l %s"
@ MSG_CMD_OUTPUT	"-o %s"
@ MSG_CMD_ESLIB		"-s %s"
@ MSG_CMD_ASLIB		"-t AOUT -s %s"
@ MSG_CMD_ADLIB		"-t AOUT -l %s"

@ MSG_STR_ELF		"ELF"
@ MSG_STR_AOUT		"AOUT"
@ MSG_STR_EMPTY		""
@ MSG_STR_READ		"r"
@ MSG_STR_NL		"\n"
@ MSG_STR_COLON		":"

@ MSG_AUD_PRF		"__CRLE_DEP__:"
@ MSG_AUD_DEPEND	"depend:"
@ MSG_AUD_FILTER	"filter:"
@ MSG_AUD_RESBGN	"resbgn:"
@ MSG_AUD_RESEND	"resend:"

@ MSG_ENV_AUD_FD	"CRLE_FD=%d"
@ MSG_ENV_AUD_FLAGS	"CRLE_FLAGS=%d"

@ MSG_ENV_LD_AUDIT	"LD_AUDIT=libcrle.so.1"
@ MSG_ENV_LD_PRELOAD	"LD_PRELOAD=%s"
@ MSG_ENV_LD_CONFIG	"LD_CONFIG=%s"
@ MSG_ENV_LD_FLAGS	"LD_FLAGS=confgen,loadfltr"

@ MSG_LDFLG_LOADAVAIL	",loadavail"

@ MSG_PTH_CONFIG	"/var/ld/ld.config"
@ MSG_PTH_CONFIG_64	"/var/ld/64/ld.config"
@ MSG_PTH_DOT		"./"

@ MSG_PTH_NEWDLP	"/lib:/usr/lib"
@ MSG_PTH_OLDDLP	"/usr/lib"
@ MSG_PTH_UPDLP		"/lib"
@ MSG_PTH_NEWTD		"/lib/secure:/usr/lib/secure"
@ MSG_PTH_OLDTD		"/usr/lib/secure"
@ MSG_PTH_UPTD		"/lib/secure"
@ MSG_PTH_NEWDLP_64	"/lib/64:/usr/lib/64"
@ MSG_PTH_OLDDLP_64	"/usr/lib/64"
@ MSG_PTH_UPDLP_64	"/lib/64"
@ MSG_PTH_NEWTD_64	"/lib/secure/64:/usr/lib/secure/64"
@ MSG_PTH_OLDTD_64	"/usr/lib/secure/64"
@ MSG_PTH_UPTD_64	"/lib/secure/64"

@ MSG_PTH_AOUTDLP	"/usr/lib:/usr/local/lib"

@ MSG_DIR_ROOT		"/"
@ MSG_DIR_DOT		"."

@ MSG_TMP_DIR		"/var/tmp"
@ MSG_TMP_PFX		"crle."

@ MSG_FMT_PATH		"%s/%s"
@ MSG_FMT_COLON		":%s"

@ MSG_SUNW_OST_SGS	"SUNW_OST_SGS"


@ MSG_MOD_SEPARATE	" \t|"
@ MSG_MOD_REL_RELATIVE	"RTLD_REL_RELATIVE"
@ MSG_MOD_REL_EXEC	"RTLD_REL_EXEC"
@ MSG_MOD_REL_DEPENDS	"RTLD_REL_DEPENDS"
@ MSG_MOD_REL_PRELOAD	"RTLD_REL_PRELOAD"
@ MSG_MOD_REL_SELF	"RTLD_REL_SELF"
@ MSG_MOD_REL_WEAK	"RTLD_REL_WEAK"
@ MSG_MOD_REL_ALL	"RTLD_REL_ALL"
@ MSG_MOD_REL_MEMORY	"RTLD_MEMORY"
@ MSG_MOD_REL_STRIP	"RTLD_STRIP"
@ MSG_MOD_REL_NOHEAP	"RTLD_NOHEAP"
@ MSG_MOD_REL_CONFGEN	"RTLD_CONFGEN"
