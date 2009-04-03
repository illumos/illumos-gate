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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

@ MSG_STT_NOTYPE_CF		"STT_NOTYPE"		# 0
@ MSG_STT_NOTYPE_NF			"notype"
@ MSG_STT_NOTYPE_DEF			"NOTY"
@ MSG_STT_OBJECT_CF		"STT_OBJECT"			# 1
@ MSG_STT_OBJECT_NF			"object"
@ MSG_STT_OBJECT_DEF			"OBJT"
@ MSG_STT_FUNC_CF		"STT_FUNC"			# 2
@ MSG_STT_FUNC_NF			"func"
@ MSG_STT_FUNC_DEF			"FUNC"
@ MSG_STT_SECTION_CF		"STT_SECTION"			# 3
@ MSG_STT_SECTION_NF			"section"
@ MSG_STT_SECTION_DEF			"SECT"
@ MSG_STT_FILE_CF		"STT_FILE"			# 4
@ MSG_STT_FILE_NF			"file"
@ MSG_STT_FILE_DEF			"FILE"
@ MSG_STT_COMMON_CF		"STT_COMMON"			# 5
@ MSG_STT_COMMON_NF			"common"
@ MSG_STT_COMMON_DEF			"COMM"
@ MSG_STT_TLS_CF		"STT_TLS"			# 6
@ MSG_STT_TLS_NF			"tls"
@ MSG_STT_TLS_DEF			"TLS "
@ MSG_STT_IFUNC_CF		"STT_IFUNC"			# 6
@ MSG_STT_IFUNC_NF			"ifunc"
@ MSG_STT_IFUNC_DEF			"IFNC"
@ MSG_STT_SPARC_REGISTER_CF	"STT_SPARC_REGISTER"		#13
@ MSG_STT_SPARC_REGISTER_NF		"sparc_register"
@ MSG_STT_SPARC_REGISTER_DEF		"REGI"

@ MSG_STB_LOCAL_CF		"STB_LOCAL"			# 0
@ MSG_STB_LOCAL_NF			"local"
@ MSG_STB_LOCAL_DEF			"LOCL"
@ MSG_STB_GLOBAL_CF		"STB_GLOBAL"			# 1
@ MSG_STB_GLOBAL_NF			"global"
@ MSG_STB_GLOBAL_DEF			"GLOB"
@ MSG_STB_WEAK_CF		"STB_WEAK"			# 2
@ MSG_STB_WEAK_NF			"weak"
@ MSG_STB_WEAK_DEF			"WEAK"

@ MSG_STV_DEFAULT_CF		"STV_DEFAULT"			# 0
@ MSG_STV_DEFAULT_NF			"default"
@ MSG_STV_DEFAULT_DEF			"D"
@ MSG_STV_INTERNAL_CF		"STV_INTERNAL"			# 1
@ MSG_STV_INTERNAL_NF			"internal"
@ MSG_STV_INTERNAL_DEF			"I"
@ MSG_STV_HIDDEN_CF		"STV_HIDDEN"			# 2
@ MSG_STV_HIDDEN_NF			"hidden"
@ MSG_STV_HIDDEN_DEF			"H"
@ MSG_STV_PROTECTED_CF		"STV_PROTECTED"			# 3
@ MSG_STV_PROTECTED_NF			"protected"
@ MSG_STV_PROTECTED_DEF			"P"
@ MSG_STV_EXPORTED_CF		"STV_EXPORTED"			# 4
@ MSG_STV_EXPORTED_NF			"exported"
@ MSG_STV_EXPORTED_DEF			"X"
@ MSG_STV_SINGLETON_CF		"STV_SINGLETON"			# 5
@ MSG_STV_SINGLETON_NF			"singleton"
@ MSG_STV_SINGLETON_DEF			"S"
@ MSG_STV_ELIMINATE_CF		"STV_ELIMINATE"			# 6
@ MSG_STV_ELIMINATE_NF			"eliminate"
@ MSG_STV_ELIMINATE_DEF			"E"

@ MSG_SHN_UNDEF_CF		"SHN_UNDEF"			# 0
@ MSG_SHN_UNDEF_CFNP			"UNDEF"
@ MSG_SHN_UNDEF_NF			"undef"
@ MSG_SHN_BEFORE_CF		"SHN_BEFORE"			# 0xff00
@ MSG_SHN_BEFORE_CFNP			"BEFORE"
@ MSG_SHN_BEFORE_NF			"before"
@ MSG_SHN_AFTER_CF		"SHN_AFTER"			# 0xff01
@ MSG_SHN_AFTER_CFNP			"AFTER"
@ MSG_SHN_AFTER_NF			"after"
@ MSG_SHN_AMD64_LCOMMON_CF	"SHN_AMD64_LCOMMON"		# 0xff02
@ MSG_SHN_AMD64_LCOMMON_CFNP		"AMD64_LCOMMON"
@ MSG_SHN_AMD64_LCOMMON_NF		"amd64_lcommon"
@ MSG_SHN_AMD64_LCOMMON_DEF		"LCOMMON"
@ MSG_SHN_X86_64_LCOMMON_CF	"SHN_X86_64_LCOMMON" # Alias: SHN_AMD64_LCOMMON
@ MSG_SHN_X86_64_LCOMMON_CFNP		"X86_64_LCOMMON"
@ MSG_SHN_X86_64_LCOMMON_NF		"x86_64_lcommon"
@ MSG_SHN_SUNW_IGNORE_CF	"SHN_SUNW_IGNORE"		# 0xff3f
@ MSG_SHN_SUNW_IGNORE_CFNP		"SUNW_IGNORE"
@ MSG_SHN_SUNW_IGNORE_NF		"sunw_ignore"
@ MSG_SHN_SUNW_IGNORE_DEF		"IGNORE"
@ MSG_SHN_ABS_CF		"SHN_ABS"			# 0xfff1
@ MSG_SHN_ABS_CFNP			"ABS"
@ MSG_SHN_ABS_NF			"abs"
@ MSG_SHN_COMMON_CF		"SHN_COMMON"			# 0xfff2
@ MSG_SHN_COMMON_CFNP			"COMMON"
@ MSG_SHN_COMMON_NF			"common"
@ MSG_SHN_XINDEX_CF		"SHN_XINDEX"			# 0xffff
@ MSG_SHN_XINDEX_CFNP			"XINDEX"
@ MSG_SHN_XINDEX_NF			"xindex"

@ MSG_SYM_FMT_VAL_32	"0x%8.8llx"
@ MSG_SYM_FMT_VAL_64	"0x%16.16llx"
