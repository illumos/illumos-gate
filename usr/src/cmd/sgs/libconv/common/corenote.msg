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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2012 DEY Storage Systems, Inc.  All rights reserved.
# Copyright 2016 Joyent, Inc.
#

@ MSG_NT_PRSTATUS		"[ NT_PRSTATUS ]"
@ MSG_NT_PRFPREG		"[ NT_PRFPREG ]"
@ MSG_NT_PRPSINFO		"[ NT_PRPSINFO ]"
@ MSG_NT_PRXREG			"[ NT_PRXREG ]"
@ MSG_NT_PLATFORM		"[ NT_PLATFORM ]"
@ MSG_NT_AUXV			"[ NT_AUXV ]"
@ MSG_NT_GWINDOWS		"[ NT_GWINDOWS ]"
@ MSG_NT_ASRS			"[ NT_ASRS ]"
@ MSG_NT_LDT			"[ NT_LDT ]"
@ MSG_NT_PSTATUS		"[ NT_PSTATUS ]"
@ MSG_NT_PSINFO			"[ NT_PSINFO ]"
@ MSG_NT_PRCRED			"[ NT_PRCRED ]"
@ MSG_NT_UTSNAME		"[ NT_UTSNAME ]"
@ MSG_NT_LWPSTATUS		"[ NT_LWPSTATUS ]"
@ MSG_NT_LWPSINFO		"[ NT_LWPSINFO ]"
@ MSG_NT_PRPRIV			"[ NT_PRPRIV ]"
@ MSG_NT_PRPRIVINFO		"[ NT_PRPRIVINFO ]"
@ MSG_NT_CONTENT		"[ NT_CONTENT ]"
@ MSG_NT_ZONENAME		"[ NT_ZONENAME ]"
@ MSG_NT_FDINFO			"[ NT_FDINFO ]"
@ MSG_NT_SPYMASTER		"[ NT_SPYMASTER ]"
@ MSG_NT_SECFLAGS		"[ NT_SECFLAGS ]"


@ MSG_AUXV_AF_SUN_SETUGID		"AF_SUN_SETUGID"
@ MSG_AUXV_AF_SUN_HWCAPVERIFY		"AF_SUN_HWCAPVERIFY"
@ MSG_AUXV_AF_SUN_NOPLM			"AF_SUN_NOPLM"


@ MSG_AUXV_AT_NULL			"NULL"
@ MSG_AUXV_AT_IGNORE			"IGNORE"
@ MSG_AUXV_AT_EXECFD			"EXECFD"
@ MSG_AUXV_AT_PHDR			"PHDR"
@ MSG_AUXV_AT_PHENT			"PHENT"
@ MSG_AUXV_AT_PHNUM			"PHNUM"
@ MSG_AUXV_AT_PAGESZ			"PAGESZ"
@ MSG_AUXV_AT_BASE			"BASE"
@ MSG_AUXV_AT_FLAGS			"FLAGS"
@ MSG_AUXV_AT_ENTRY			"ENTRY"
@ MSG_AUXV_AT_NOTELF			"NOTELF"
@ MSG_AUXV_AT_UID			"UID"
@ MSG_AUXV_AT_EUID			"EUID"
@ MSG_AUXV_AT_GID			"GID"
@ MSG_AUXV_AT_EGID			"EGID"
@ MSG_AUXV_AT_PLATFORM			"PLATFORM"
@ MSG_AUXV_AT_HWCAP			"HWCAP"
@ MSG_AUXV_AT_CLKTCK			"CLKTCK"
@ MSG_AUXV_AT_FPUCW			"FPUCW"
@ MSG_AUXV_AT_DCACHEBSIZE		"DCACHEBSIZE"
@ MSG_AUXV_AT_ICACHEBSIZE		"ICACHEBSIZE"
@ MSG_AUXV_AT_UCACHEBSIZE		"UCACHEBSIZE"
@ MSG_AUXV_AT_IGNOREPPC			"IGNOREPPC"
@ MSG_AUXV_AT_SUN_UID			"SUN_UID"
@ MSG_AUXV_AT_SUN_RUID			"SUN_RUID"
@ MSG_AUXV_AT_SUN_GID			"SUN_GID"
@ MSG_AUXV_AT_SUN_RGID			"SUN_RGID"
@ MSG_AUXV_AT_SUN_LDELF			"SUN_LDELF"
@ MSG_AUXV_AT_SUN_LDSHDR		"SUN_LDSHDR"
@ MSG_AUXV_AT_SUN_LDNAME		"SUN_LDNAME"
@ MSG_AUXV_AT_SUN_LPAGESZ		"SUN_LPAGESZ"
@ MSG_AUXV_AT_SUN_PLATFORM		"SUN_PLATFORM"
@ MSG_AUXV_AT_SUN_HWCAP			"SUN_HWCAP"
@ MSG_AUXV_AT_SUN_IFLUSH		"SUN_IFLUSH"
@ MSG_AUXV_AT_SUN_CPU			"SUN_CPU"
@ MSG_AUXV_AT_SUN_EXECNAME		"SUN_EXECNAME"
@ MSG_AUXV_AT_SUN_MMU			"SUN_MMU"
@ MSG_AUXV_AT_SUN_LDDATA		"SUN_LDDATA"
@ MSG_AUXV_AT_SUN_AUXFLAGS		"SUN_AUXFLAGS"
@ MSG_AUXV_AT_SUN_EMULATOR		"SUN_EMULATOR"
@ MSG_AUXV_AT_SUN_BRANDNAME		"SUN_BRANDNAME"
@ MSG_AUXV_AT_SUN_BRAND_AUX1		"SUN_BRAND_AUX1"
@ MSG_AUXV_AT_SUN_BRAND_AUX2		"SUN_BRAND_AUX2"
@ MSG_AUXV_AT_SUN_BRAND_AUX3		"SUN_BRAND_AUX3"
@ MSG_AUXV_AT_SUN_HWCAP2		"SUN_HWCAP2"
@ MSG_AUXV_AT_SUN_COMMPAGE		"SUN_COMMPAGE"


@ MSG_CC_CONTENT_STACK		"STACK"
@ MSG_CC_CONTENT_HEAP		"HEAP"
@ MSG_CC_CONTENT_SHFILE		"SHFILE"
@ MSG_CC_CONTENT_SHANON		"SHANON"
@ MSG_CC_CONTENT_TEXT		"TEXT"
@ MSG_CC_CONTENT_DATA		"DATA"
@ MSG_CC_CONTENT_RODATA		"RODATA"
@ MSG_CC_CONTENT_ANON		"ANON"
@ MSG_CC_CONTENT_SHM		"SHM"
@ MSG_CC_CONTENT_ISM		"ISM"
@ MSG_CC_CONTENT_DISM		"DISM"
@ MSG_CC_CONTENT_CTF		"CTF"
@ MSG_CC_CONTENT_SYMTAB		"SYMTAB"


@ MSG_ERRNO_EPERM		"[ EPERM ]"			# 1
@ MSG_ERRNO_ENOENT		"[ ENOENT ]"		# 2
@ MSG_ERRNO_ESRCH		"[ ESRCH ]"			# 3
@ MSG_ERRNO_EINTR		"[ EINTR ]"			# 4
@ MSG_ERRNO_EIO			"[ EIO ]"			# 5
@ MSG_ERRNO_ENXIO		"[ ENXIO ]"			# 6
@ MSG_ERRNO_E2BIG		"[ E2BIG ]"			# 7
@ MSG_ERRNO_ENOEXEC		"[ ENOEXEC ]"		# 8
@ MSG_ERRNO_EBADF		"[ EBADF ]"			# 9
@ MSG_ERRNO_ECHILD		"[ ECHILD ]"		# 10
@ MSG_ERRNO_EAGAIN		"[ EAGAIN ]"		# 11
@ MSG_ERRNO_ENOMEM		"[ ENOMEM ]"		# 12
@ MSG_ERRNO_EACCES		"[ EACCES ]"		# 13
@ MSG_ERRNO_EFAULT		"[ EFAULT ]"		# 14
@ MSG_ERRNO_ENOTBLK		"[ ENOTBLK ]"		# 15
@ MSG_ERRNO_EBUSY		"[ EBUSY ]"			# 16
@ MSG_ERRNO_EEXIST		"[ EEXIST ]"		# 17
@ MSG_ERRNO_EXDEV		"[ EXDEV ]"			# 18
@ MSG_ERRNO_ENODEV		"[ ENODEV ]"		# 19
@ MSG_ERRNO_ENOTDIR		"[ ENOTDIR ]"		# 20
@ MSG_ERRNO_EISDIR		"[ EISDIR ]"		# 21
@ MSG_ERRNO_EINVAL		"[ EINVAL ]"		# 22
@ MSG_ERRNO_ENFILE		"[ ENFILE ]"		# 23
@ MSG_ERRNO_EMFILE		"[ EMFILE ]"		# 24
@ MSG_ERRNO_ENOTTY		"[ ENOTTY ]"		# 25
@ MSG_ERRNO_ETXTBSY		"[ ETXTBSY ]"		# 26
@ MSG_ERRNO_EFBIG		"[ EFBIG ]"			# 27
@ MSG_ERRNO_ENOSPC		"[ ENOSPC ]"		# 28
@ MSG_ERRNO_ESPIPE		"[ ESPIPE ]"		# 29
@ MSG_ERRNO_EROFS		"[ EROFS ]"			# 30
@ MSG_ERRNO_EMLINK		"[ EMLINK ]"		# 31
@ MSG_ERRNO_EPIPE		"[ EPIPE ]"			# 32
@ MSG_ERRNO_EDOM		"[ EDOM ]"			# 33
@ MSG_ERRNO_ERANGE		"[ ERANGE ]"		# 34
@ MSG_ERRNO_ENOMSG		"[ ENOMSG ]"		# 35
@ MSG_ERRNO_EIDRM		"[ EIDRM ]"			# 36
@ MSG_ERRNO_ECHRNG		"[ ECHRNG ]"		# 37
@ MSG_ERRNO_EL2NSYNC		"[ EL2NSYNC ]"		# 38
@ MSG_ERRNO_EL3HLT		"[ EL3HLT ]"		# 39
@ MSG_ERRNO_EL3RST		"[ EL3RST ]"		# 40
@ MSG_ERRNO_ELNRNG		"[ ELNRNG ]"		# 41
@ MSG_ERRNO_EUNATCH		"[ EUNATCH ]"		# 42
@ MSG_ERRNO_ENOCSI		"[ ENOCSI ]"		# 43
@ MSG_ERRNO_EL2HLT		"[ EL2HLT ]"		# 44
@ MSG_ERRNO_EDEADLK		"[ EDEADLK ]"		# 45
@ MSG_ERRNO_ENOLCK		"[ ENOLCK ]"		# 46
@ MSG_ERRNO_ECANCELED		"[ ECANCELED ]"		# 47
@ MSG_ERRNO_ENOTSUP		"[ ENOTSUP ]"		# 48
@ MSG_ERRNO_EDQUOT		"[ EDQUOT ]"		# 49
@ MSG_ERRNO_EBADE		"[ EBADE ]"			# 50
@ MSG_ERRNO_EBADR		"[ EBADR ]"			# 51
@ MSG_ERRNO_EXFULL		"[ EXFULL ]"		# 52
@ MSG_ERRNO_ENOANO		"[ ENOANO ]"		# 53
@ MSG_ERRNO_EBADRQC		"[ EBADRQC ]"		# 54
@ MSG_ERRNO_EBADSLT		"[ EBADSLT ]"		# 55
@ MSG_ERRNO_EDEADLOCK		"[ EDEADLOCK ]"		# 56
@ MSG_ERRNO_EBFONT		"[ EBFONT ]"		# 57
@ MSG_ERRNO_EOWNERDEAD		"[ EOWNERDEAD ]"		# 58
@ MSG_ERRNO_ENOTRECOVERABLE	"[ ENOTRECOVERABLE ]"	# 59
@ MSG_ERRNO_ENOSTR		"[ ENOSTR ]"		# 60
@ MSG_ERRNO_ENODATA		"[ ENODATA ]"		# 61
@ MSG_ERRNO_ETIME		"[ ETIME ]"			# 62
@ MSG_ERRNO_ENOSR		"[ ENOSR ]"			# 63
@ MSG_ERRNO_ENONET		"[ ENONET ]"		# 64
@ MSG_ERRNO_ENOPKG		"[ ENOPKG ]"		# 65
@ MSG_ERRNO_EREMOTE		"[ EREMOTE ]"		# 66
@ MSG_ERRNO_ENOLINK		"[ ENOLINK ]"		# 67
@ MSG_ERRNO_EADV		"[ EADV ]"			# 68
@ MSG_ERRNO_ESRMNT		"[ ESRMNT ]"		# 69
@ MSG_ERRNO_ECOMM		"[ ECOMM ]"			# 70
@ MSG_ERRNO_EPROTO		"[ EPROTO ]"		# 71
@ MSG_ERRNO_ELOCKUNMAPPED	"[ ELOCKUNMAPPED ]"		# 72
@ MSG_ERRNO_ENOTACTIVE		"[ ENOTACTIVE ]"		# 73
@ MSG_ERRNO_EMULTIHOP		"[ EMULTIHOP ]"		# 74
# errno 75 and 76 are not defined
@ MSG_ERRNO_EBADMSG		"[ EBADMSG ]"		# 77
@ MSG_ERRNO_ENAMETOOLONG	"[ ENAMETOOLONG ]"		# 78
@ MSG_ERRNO_EOVERFLOW		"[ EOVERFLOW ]"		# 79
@ MSG_ERRNO_ENOTUNIQ		"[ ENOTUNIQ ]"		# 80
@ MSG_ERRNO_EBADFD		"[ EBADFD ]"		# 81
@ MSG_ERRNO_EREMCHG		"[ EREMCHG ]"		# 82
@ MSG_ERRNO_ELIBACC		"[ ELIBACC ]"		# 83
@ MSG_ERRNO_ELIBBAD		"[ ELIBBAD ]"		# 84
@ MSG_ERRNO_ELIBSCN		"[ ELIBSCN ]"		# 85
@ MSG_ERRNO_ELIBMAX		"[ ELIBMAX ]"		# 86
@ MSG_ERRNO_ELIBEXEC		"[ ELIBEXEC ]"		# 87
@ MSG_ERRNO_EILSEQ		"[ EILSEQ ]"		# 88
@ MSG_ERRNO_ENOSYS		"[ ENOSYS ]"		# 89
@ MSG_ERRNO_ELOOP		"[ ELOOP ]"			# 90
@ MSG_ERRNO_ERESTART		"[ ERESTART ]"		# 91
@ MSG_ERRNO_ESTRPIPE		"[ ESTRPIPE ]"		# 92
@ MSG_ERRNO_ENOTEMPTY		"[ ENOTEMPTY ]"		# 93
@ MSG_ERRNO_EUSERS		"[ EUSERS ]"		# 94
@ MSG_ERRNO_ENOTSOCK		"[ ENOTSOCK ]"		# 95
@ MSG_ERRNO_EDESTADDRREQ	"[ EDESTADDRREQ ]"		# 96
@ MSG_ERRNO_EMSGSIZE		"[ EMSGSIZE ]"		# 97
@ MSG_ERRNO_EPROTOTYPE		"[ EPROTOTYPE ]"		# 98
@ MSG_ERRNO_ENOPROTOOPT		"[ ENOPROTOOPT ]"		# 99
# Gap in ERRNO values 100-119
@ MSG_ERRNO_EPROTONOSUPPORT	"[ EPROTONOSUPPORT ]"	# 120
@ MSG_ERRNO_ESOCKTNOSUPPORT	"[ ESOCKTNOSUPPORT ]"	# 121
@ MSG_ERRNO_EOPNOTSUPP		"[ EOPNOTSUPP ]"		# 122
@ MSG_ERRNO_EPFNOSUPPORT	"[ EPFNOSUPPORT ]"		# 123
@ MSG_ERRNO_EAFNOSUPPORT	"[ EAFNOSUPPORT ]"		# 124
@ MSG_ERRNO_EADDRINUSE		"[ EADDRINUSE ]"		# 125
@ MSG_ERRNO_EADDRNOTAVAIL	"[ EADDRNOTAVAIL ]"		# 126
@ MSG_ERRNO_ENETDOWN		"[ ENETDOWN ]"		# 127
@ MSG_ERRNO_ENETUNREACH		"[ ENETUNREACH ]"		# 128
@ MSG_ERRNO_ENETRESET		"[ ENETRESET ]"		# 129
@ MSG_ERRNO_ECONNABORTED	"[ ECONNABORTED ]"		# 130
@ MSG_ERRNO_ECONNRESET		"[ ECONNRESET ]"		# 131
@ MSG_ERRNO_ENOBUFS		"[ ENOBUFS ]"		# 132
@ MSG_ERRNO_EISCONN		"[ EISCONN ]"		# 133
@ MSG_ERRNO_ENOTCONN		"[ ENOTCONN ]"		# 134
#XENIX has 135 - 142
@ MSG_ERRNO_ESHUTDOWN		"[ ESHUTDOWN ]"		# 143
@ MSG_ERRNO_ETOOMANYREFS	"[ ETOOMANYREFS ]"		# 144
@ MSG_ERRNO_ETIMEDOUT		"[ ETIMEDOUT ]"		# 145
@ MSG_ERRNO_ECONNREFUSED	"[ ECONNREFUSED ]"		# 146
@ MSG_ERRNO_EHOSTDOWN		"[ EHOSTDOWN ]"		# 147
@ MSG_ERRNO_EHOSTUNREACH	"[ EHOSTUNREACH ]"		# 148
@ MSG_ERRNO_EALREADY		"[ EALREADY ]"		# 149
@ MSG_ERRNO_EINPROGRESS		"[ EINPROGRESS ]"		# 150
@ MSG_ERRNO_ESTALE		"[ ESTALE ]"		# 151


@ MSG_PR_MODEL_UNKNOWN		"[ PR_MODEL_UNKNOWN ]"
@ MSG_PR_MODEL_ILP32		"[ PR_MODEL_ILP32 ]"
@ MSG_PR_MODEL_LP64		"[ PR_MODEL_LP64 ]"

@ MSG_PR_FLAGS_STOPPED		"PR_STOPPED"
@ MSG_PR_FLAGS_ISTOP		"PR_ISTOP"
@ MSG_PR_FLAGS_DSTOP		"PR_DSTOP"
@ MSG_PR_FLAGS_STEP		"PR_STEP"
@ MSG_PR_FLAGS_ASLEEP		"PR_ASLEEP"
@ MSG_PR_FLAGS_PCINVAL		"PR_PCINVAL"
@ MSG_PR_FLAGS_ASLWP		"PR_ASLWP"
@ MSG_PR_FLAGS_AGENT		"PR_AGENT"
@ MSG_PR_FLAGS_DETACH		"PR_DETACH"
@ MSG_PR_FLAGS_DAEMON		"PR_DAEMON"
@ MSG_PR_FLAGS_IDLE		"PR_IDLE"
@ MSG_PR_FLAGS_ISSYS		"PR_ISSYS"
@ MSG_PR_FLAGS_VFORKP		"PR_VFORKP"
@ MSG_PR_FLAGS_ORPHAN		"PR_ORPHAN"
@ MSG_PR_FLAGS_NOSIGCHLD	"PR_NOSIGCHLD"
@ MSG_PR_FLAGS_WAITPID		"PR_WAITPID"
@ MSG_PR_FLAGS_FORK		"PR_FORK"
@ MSG_PR_FLAGS_RLC		"PR_RLC"
@ MSG_PR_FLAGS_KLC		"PR_KLC"
@ MSG_PR_FLAGS_ASYNC		"PR_ASYNC"
@ MSG_PR_FLAGS_MSACCT		"PR_MSACCT"
@ MSG_PR_FLAGS_BPTADJ		"PR_BPTADJ"
@ MSG_PR_FLAGS_PTRACE		"PR_PTRACE"
@ MSG_PR_FLAGS_MSFORK		"PR_MSFORK"
@ MSG_PR_FLAGS_PCOMPAT		"PR_PCOMPAT"


@ MSG_PROC_FLAG_SSYS		"SSYS"
@ MSG_PROC_FLAG_SMSACCT		"SMSACCT"

@ MSG_ASLR		"ASLR"
@ MSG_FORBIDNULLMAP	"FORBIDNULLMAP"
@ MSG_NOEXECSTACK	"NOEXECSTACK"

@ MSG_PS_NONE			"[ PS_NONE ]"
@ MSG_PS_QUERY			"[ PS_QUERY ]"
@ MSG_PS_MYID			"[ PS_MYID ]"
@ MSG_PS_SOFT			"[ PS_SOFT ]"
@ MSG_PS_HARD			"[ PS_HARD ]"
@ MSG_PS_QUERY_TYPE		"[ PS_QUERY_TYPE ]"


@ MSG_REG_SPARC_G0		"[ r0/g0 ]"
@ MSG_REG_SPARC_G1		"[ r1/g1 ]"
@ MSG_REG_SPARC_G2		"[ r2/g2 ]"
@ MSG_REG_SPARC_G3		"[ r3/g3 ]"
@ MSG_REG_SPARC_G4		"[ r4/g4 ]"
@ MSG_REG_SPARC_G5		"[ r5/g5 ]"
@ MSG_REG_SPARC_G6		"[ r6/g6 ]"
@ MSG_REG_SPARC_G7		"[ r7/g7 ]"
@ MSG_REG_SPARC_O0		"[ r8/o0 ]"
@ MSG_REG_SPARC_O1		"[ r9/o1 ]"
@ MSG_REG_SPARC_O2		"[ r10/o2 ]"
@ MSG_REG_SPARC_O3		"[ r11/o3 ]"
@ MSG_REG_SPARC_O4		"[ r12/o4 ]"
@ MSG_REG_SPARC_O5		"[ r13/o5 ]"
@ MSG_REG_SPARC_O6		"[ r14/o6/sp ]"
@ MSG_REG_SPARC_O7		"[ r15/o7 ]"
@ MSG_REG_SPARC_L0		"[ r16/l0 ]"
@ MSG_REG_SPARC_L1		"[ r17/l1 ]"
@ MSG_REG_SPARC_L2		"[ r18/l2 ]"
@ MSG_REG_SPARC_L3		"[ r19/l3 ]"
@ MSG_REG_SPARC_L4		"[ r20/l4 ]"
@ MSG_REG_SPARC_L5		"[ r21/l5 ]"
@ MSG_REG_SPARC_L6		"[ r22/l6 ]"
@ MSG_REG_SPARC_L7		"[ r23/l7 ]"
@ MSG_REG_SPARC_I0		"[ r24/i0 ]"
@ MSG_REG_SPARC_I1		"[ r25/i1 ]"
@ MSG_REG_SPARC_I2		"[ r26/i2 ]"
@ MSG_REG_SPARC_I3		"[ r27/i3 ]"
@ MSG_REG_SPARC_I4		"[ r28/i4 ]"
@ MSG_REG_SPARC_I5		"[ r29/i5 ]"
@ MSG_REG_SPARC_I6		"[ r30/i6/fp ]"
@ MSG_REG_SPARC_I7		"[ r31/i7 ]"
@ MSG_REG_SPARC_CCR		"[ ccr ]"
@ MSG_REG_SPARC_PSR		"[ psr ]"
@ MSG_REG_SPARC_PC		"[ pc ]"
@ MSG_REG_SPARC_nPC		"[ npc ]"
@ MSG_REG_SPARC_Y		"[ y ]"
@ MSG_REG_SPARC_ASI		"[ asi ]"
@ MSG_REG_SPARC_FPRS		"[ fprs ]"
@ MSG_REG_SPARC_WIM		"[ wim ]"
@ MSG_REG_SPARC_TBR		"[ tbr ]"

@ MSG_REG_AMD64_R15		"[ r15 ]"
@ MSG_REG_AMD64_R14		"[ r14 ]"
@ MSG_REG_AMD64_R13		"[ r13 ]"
@ MSG_REG_AMD64_R12		"[ r12 ]"
@ MSG_REG_AMD64_R11		"[ r11 ]"
@ MSG_REG_AMD64_R10		"[ r10 ]"
@ MSG_REG_AMD64_R9 		"[ r9 ]" 
@ MSG_REG_AMD64_R8		"[ r8 ]"
@ MSG_REG_AMD64_RDI		"[ rdi ]"
@ MSG_REG_AMD64_RSI		"[ rsi ]"
@ MSG_REG_AMD64_RBP		"[ rbp ]"
@ MSG_REG_AMD64_RBX		"[ rbx ]"
@ MSG_REG_AMD64_RDX		"[ rdx ]"
@ MSG_REG_AMD64_RCX		"[ rcx ]"
@ MSG_REG_AMD64_RAX		"[ rax ]"
@ MSG_REG_AMD64_TRAPNO		"[ trapno ]"
@ MSG_REG_AMD64_ERR		"[ err ]"
@ MSG_REG_AMD64_RIP		"[ rip ]"
@ MSG_REG_AMD64_CS		"[ cs ]"
@ MSG_REG_AMD64_RFL		"[ rfl ]"
@ MSG_REG_AMD64_RSP		"[ rsp ]"
@ MSG_REG_AMD64_SS		"[ ss ]"
@ MSG_REG_AMD64_FS		"[ fs ]"
@ MSG_REG_AMD64_GS		"[ gs ]"
@ MSG_REG_AMD64_ES		"[ es ]"
@ MSG_REG_AMD64_DS		"[ ds ]"
@ MSG_REG_AMD64_FSBASE		"[ fsbase ]"
@ MSG_REG_AMD64_GSBASE		"[ gsbase ]"

@ MSG_REG_I86_GS		"[ gs ]"
@ MSG_REG_I86_FS		"[ fs ]"
@ MSG_REG_I86_ES		"[ es ]"
@ MSG_REG_I86_DS		"[ ds ]"
@ MSG_REG_I86_EDI		"[ edi ]"
@ MSG_REG_I86_ESI		"[ esi ]"
@ MSG_REG_I86_EBP		"[ ebp ]"
@ MSG_REG_I86_ESP		"[ esp ]"
@ MSG_REG_I86_EBX		"[ ebx ]"
@ MSG_REG_I86_EDX		"[ edx ]"
@ MSG_REG_I86_ECX		"[ ecx ]"
@ MSG_REG_I86_EAX		"[ eax ]"
@ MSG_REG_I86_TRAPNO		"[ trapno ]"
@ MSG_REG_I86_ERR		"[ err ]"
@ MSG_REG_I86_EIP		"[ eip ]"
@ MSG_REG_I86_CS		"[ cs ]"
@ MSG_REG_I86_EFL		"[ efl ]"
@ MSG_REG_I86_UESP		"[ uesp ]"
@ MSG_REG_I86_SS		"[ ss ]"

@ MSG_PR_WHY_REQUESTED		"[ PR_REQUESTED ]"
@ MSG_PR_WHY_SIGNALLED		"[ PR_SIGNALLED ]"
@ MSG_PR_WHY_SYSENTRY		"[ PR_SYSENTRY ]"
@ MSG_PR_WHY_SYSEXIT		"[ PR_SYSEXIT ]"
@ MSG_PR_WHY_JOBCONTROL		"[ PR_JOBCONTROL ]"
@ MSG_PR_WHY_FAULTED		"[ PR_FAULTED ]"
@ MSG_PR_WHY_SUSPENDED		"[ PR_SUSPENDED ]"
@ MSG_PR_WHY_CHECKPOINT		"[ PR_CHECKPOINT ]"

@ MSG_PRIV_ALL			"[ PRIV_ALL ]"
@ MSG_PRIV_MULTIPLE		"[ PRIV_MULTIPLE ]"
@ MSG_PRIV_NONE			"[ PRIV_NONE ]"
@ MSG_PRIV_ALLZONE		"[ PRIV_ALLZONE ]"
@ MSG_PRIV_GLOBAL		"[ PRIV_ALLGLOBAL ]"


@ MSG_SA_ONSTACK		"SA_ONSTACK"
@ MSG_SA_RESETHAND		"SA_RESETHAND"
@ MSG_SA_RESTART		"SA_RESTART"
@ MSG_SA_SIGINFO		"SA_SIGINFO"
@ MSG_SA_NODEFER		"SA_NODEFER"
@ MSG_SA_NOCLDWAIT		"SA_NOCLDWAIT"
@ MSG_SA_NOCLDSTOP		"SA_NOCLDSTOP"


@ MSG_SOBJ_NONE			"[ SOBJ_NONE ]"
@ MSG_SOBJ_MUTEX		"[ SOBJ_MUTEX ]"
@ MSG_SOBJ_RWLOCK		"[ SOBJ_RWLOCK ]"
@ MSG_SOBJ_CV			"[ SOBJ_CV ]"
@ MSG_SOBJ_SEMA			"[ SOBJ_SEMA ]"
@ MSG_SOBJ_USER			"[ SOBJ_USER ]"
@ MSG_SOBJ_USER_PI		"[ SOBJ_USER_PI ]"
@ MSG_SOBJ_SHUTTLE		"[ SOBJ_SHUTTLE ]"


@ MSG_SS_ONSTACK		"SS_ONSTACK"
@ MSG_SS_DISABLE		"SS_DISABLE"


@ MSG_SI_NOINFO			"[ SI_NOINFO ]"
@ MSG_SI_DTRACE			"[ SI_DTRACE ]"
@ MSG_SI_RCTL			"[ SI_RCTL ]"
@ MSG_SI_USER			"[ SI_USER ]"
@ MSG_SI_LWP			"[ SI_LWP ]"
@ MSG_SI_QUEUE			"[ SI_QUEUE ]"
@ MSG_SI_TIMER			"[ SI_TIMER ]"
@ MSG_SI_ASYNCIO		"[ SI_ASYNCIO ]"
@ MSG_SI_MESGQ			"[ SI_MESGQ ]"

@ MSG_SI_ILL_ILLOPC		"[ ILL_ILLOPC ]"
@ MSG_SI_ILL_ILLOPN		"[ ILL_ILLOPN ]"
@ MSG_SI_ILL_ILLADR		"[ ILL_ILLADR ]"
@ MSG_SI_ILL_ILLTRP		"[ ILL_ILLTRP ]"
@ MSG_SI_ILL_PRVOPC		"[ ILL_PRVOPC ]"
@ MSG_SI_ILL_PRVREG		"[ ILL_PRVREG ]"
@ MSG_SI_ILL_COPROC		"[ ILL_COPROC ]"
@ MSG_SI_ILL_BADSTK		"[ ILL_BADSTK ]"

@ MSG_SI_EMT_TAGOVF		"[ EMT_TAGOVF ]"
@ MSG_SI_EMT_CPCOVF		"[ EMT_CPCOVF ]"

@ MSG_SI_FPE_INTDIV		"[ FPE_INTDIV ]"
@ MSG_SI_FPE_INTOVF		"[ FPE_INTOVF ]"
@ MSG_SI_FPE_FLTDIV		"[ FPE_FLTDIV ]"
@ MSG_SI_FPE_FLTOVF		"[ FPE_FLTOVF ]"
@ MSG_SI_FPE_FLTUND		"[ FPE_FLTUND ]"
@ MSG_SI_FPE_FLTRES		"[ FPE_FLTRES ]"
@ MSG_SI_FPE_FLTINV		"[ FPE_FLTINV ]"
@ MSG_SI_FPE_FLTSUB		"[ FPE_FLTSUB ]"
@ MSG_SI_FPE_FLTDEN		"[ FPE_FLTDEN ]"

@ MSG_SI_SEGV_MAPERR		"[ SEGV_MAPERR ]"
@ MSG_SI_SEGV_ACCERR		"[ SEGV_ACCERR ]"

@ MSG_SI_BUS_ADRALN		"[ BUS_ADRALN ]"
@ MSG_SI_BUS_ADRERR		"[ BUS_ADRERR ]"
@ MSG_SI_BUS_OBJERR		"[ BUS_OBJERR ]"

@ MSG_SI_TRAP_BRKPT		"[ TRAP_BRKPT ]"
@ MSG_SI_TRAP_TRACE		"[ TRAP_TRACE ]"
@ MSG_SI_TRAP_RWATCH		"[ TRAP_RWATCH ]"
@ MSG_SI_TRAP_WWATCH		"[ TRAP_WWATCH ]"
@ MSG_SI_TRAP_XWATCH		"[ TRAP_XWATCH ]"
@ MSG_SI_TRAP_DTRACE		"[ TRAP_DTRACE ]"

@ MSG_SI_CLD_EXITED		"[ CLD_EXITED ]"
@ MSG_SI_CLD_KILLED		"[ CLD_KILLED ]"
@ MSG_SI_CLD_DUMPED		"[ CLD_DUMPED ]"
@ MSG_SI_CLD_TRAPPED		"[ CLD_TRAPPED ]"
@ MSG_SI_CLD_STOPPED		"[ CLD_STOPPED ]"
@ MSG_SI_CLD_CONTINUED		"[ CLD_CONTINUED ]"

@ MSG_SI_POLL_IN		"[ POLL_IN ]"
@ MSG_SI_POLL_OUT		"[ POLL_OUT ]"
@ MSG_SI_POLL_MSG		"[ POLL_MSG ]"
@ MSG_SI_POLL_ERR		"[ POLL_ERR ]"
@ MSG_SI_POLL_PRI		"[ POLL_PRI ]"
@ MSG_SI_POLL_HUP		"[ POLL_HUP ]"

@ MSG_SIGHUP			"[ SIGHUP ]"
@ MSG_SIGHUP_ALT		"SIGHUP"
@ MSG_SIGINT			"[ SIGINT ]"
@ MSG_SIGINT_ALT		"SIGINT"
@ MSG_SIGQUIT			"[ SIGQUIT ]"
@ MSG_SIGQUIT_ALT		"SIGQUIT"
@ MSG_SIGILL			"[ SIGILL ]"
@ MSG_SIGILL_ALT		"SIGILL"
@ MSG_SIGTRAP			"[ SIGTRAP ]"
@ MSG_SIGTRAP_ALT		"SIGTRAP"
@ MSG_SIGABRT			"[ SIGABRT ]"
@ MSG_SIGABRT_ALT		"SIGABRT"
@ MSG_SIGEMT			"[ SIGEMT ]"
@ MSG_SIGEMT_ALT		"SIGEMT"
@ MSG_SIGFPE			"[ SIGFPE ]"
@ MSG_SIGFPE_ALT		"SIGFPE"
@ MSG_SIGKILL			"[ SIGKILL ]"
@ MSG_SIGKILL_ALT		"SIGKILL"
@ MSG_SIGBUS			"[ SIGBUS ]"
@ MSG_SIGBUS_ALT		"SIGBUS"
@ MSG_SIGSEGV			"[ SIGSEGV ]"
@ MSG_SIGSEGV_ALT		"SIGSEGV"
@ MSG_SIGSYS			"[ SIGSYS ]"
@ MSG_SIGSYS_ALT		"SIGSYS"
@ MSG_SIGPIPE			"[ SIGPIPE ]"
@ MSG_SIGPIPE_ALT		"SIGPIPE"
@ MSG_SIGALRM			"[ SIGALRM ]"
@ MSG_SIGALRM_ALT		"SIGALRM"
@ MSG_SIGTERM			"[ SIGTERM ]"
@ MSG_SIGTERM_ALT		"SIGTERM"
@ MSG_SIGUSR1			"[ SIGUSR1 ]"
@ MSG_SIGUSR1_ALT		"SIGUSR1"
@ MSG_SIGUSR2			"[ SIGUSR2 ]"
@ MSG_SIGUSR2_ALT		"SIGUSR2"
@ MSG_SIGCHLD			"[ SIGCHLD ]"
@ MSG_SIGCHLD_ALT		"SIGCHLD"
@ MSG_SIGPWR			"[ SIGPWR ]"
@ MSG_SIGPWR_ALT		"SIGPWR"
@ MSG_SIGWINCH			"[ SIGWINCH ]"
@ MSG_SIGWINCH_ALT		"SIGWINCH"
@ MSG_SIGURG			"[ SIGURG ]"
@ MSG_SIGURG_ALT		"SIGURG"
@ MSG_SIGPOLL			"[ SIGPOLL ]"
@ MSG_SIGPOLL_ALT		"SIGPOLL"
@ MSG_SIGSTOP			"[ SIGSTOP ]"
@ MSG_SIGSTOP_ALT		"SIGSTOP"
@ MSG_SIGTSTP			"[ SIGTSTP ]"
@ MSG_SIGTSTP_ALT		"SIGTSTP"
@ MSG_SIGCONT			"[ SIGCONT ]"
@ MSG_SIGCONT_ALT		"SIGCONT"
@ MSG_SIGTTIN			"[ SIGTTIN ]"
@ MSG_SIGTTIN_ALT		"SIGTTIN"
@ MSG_SIGTTOU			"[ SIGTTOU ]"
@ MSG_SIGTTOU_ALT		"SIGTTOU"
@ MSG_SIGVTALRM			"[ SIGVTALRM ]"
@ MSG_SIGVTALRM_ALT		"SIGVTALRM"
@ MSG_SIGPROF			"[ SIGPROF ]"
@ MSG_SIGPROF_ALT		"SIGPROF"
@ MSG_SIGXCPU			"[ SIGXCPU ]"
@ MSG_SIGXCPU_ALT		"SIGXCPU"
@ MSG_SIGXFSZ			"[ SIGXFSZ ]"
@ MSG_SIGXFSZ_ALT		"SIGXFSZ"
@ MSG_SIGWAITING		"[ SIGWAITING ]"
@ MSG_SIGWAITING_ALT		"SIGWAITING"
@ MSG_SIGLWP			"[ SIGLWP ]"
@ MSG_SIGLWP_ALT		"SIGLWP"
@ MSG_SIGFREEZE			"[ SIGFREEZE ]"
@ MSG_SIGFREEZE_ALT		"SIGFREEZE"
@ MSG_SIGTHAW			"[ SIGTHAW ]"
@ MSG_SIGTHAW_ALT		"SIGTHAW"
@ MSG_SIGCANCEL			"[ SIGCANCEL ]"
@ MSG_SIGCANCEL_ALT		"SIGCANCEL"
@ MSG_SIGLOST			"[ SIGLOST ]"
@ MSG_SIGLOST_ALT		"SIGLOST"
@ MSG_SIGXRES			"[ SIGXRES ]"
@ MSG_SIGXRES_ALT		"SIGXRES"
@ MSG_SIGJVM1			"[ SIGJVM1 ]"
@ MSG_SIGJVM1_ALT		"SIGJVM1"
@ MSG_SIGJVM2			"[ SIGJVM2 ]"
@ MSG_SIGJVM2_ALT		"SIGJVM2"

@ MSG_FLTILL			"[ FLTILL ]"
@ MSG_FLTILL_ALT		"FLTILL"
@ MSG_FLTPRIV			"[ FLTPRIV ]"
@ MSG_FLTPRIV_ALT		"FLTPRIV"
@ MSG_FLTBPT			"[ FLTBPT ]"
@ MSG_FLTBPT_ALT		"FLTBPT"
@ MSG_FLTTRACE			"[ FLTTRACE ]"
@ MSG_FLTTRACE_ALT		"FLTTRACE"
@ MSG_FLTACCESS			"[ FLTACCESS ]"
@ MSG_FLTACCESS_ALT		"FLTACCESS"
@ MSG_FLTBOUNDS			"[ FLTBOUNDS ]"
@ MSG_FLTBOUNDS_ALT		"FLTBOUNDS"
@ MSG_FLTIOVF			"[ FLTIOVF ]"
@ MSG_FLTIOVF_ALT		"FLTIOVF"
@ MSG_FLTIZDIV			"[ FLTIZDIV ]"
@ MSG_FLTIZDIV_ALT		"FLTIZDIV"
@ MSG_FLTFPE			"[ FLTFPE ]"
@ MSG_FLTFPE_ALT		"FLTFPE"
@ MSG_FLTSTACK			"[ FLTSTACK ]"
@ MSG_FLTSTACK_ALT		"FLTSTACK"
@ MSG_FLTPAGE			"[ FLTPAGE ]"
@ MSG_FLTPAGE_ALT		"FLTPAGE"
@ MSG_FLTWATCH			"[ FLTWATCH ]"
@ MSG_FLTWATCH_ALT		"FLTWATCH"
@ MSG_FLTCPCOVF			"[ FLTCPCOVF ]"
@ MSG_FLTCPCOVF_ALT		"FLTCPCOVF"

@ MSG_SYS_EXIT				"[ exit ]"			# 1
@ MSG_SYS_EXIT_ALT			"exit"
@ MSG_SYS_2				"2"				# 2 (u)
@ MSG_SYS_READ				"[ read ]"			# 3
@ MSG_SYS_READ_ALT			"read"
@ MSG_SYS_WRITE				"[ write ]"			# 4
@ MSG_SYS_WRITE_ALT			"write"
@ MSG_SYS_OPEN				"[ open ]"			# 5
@ MSG_SYS_OPEN_ALT			"open"
@ MSG_SYS_CLOSE				"[ close ]"			# 6
@ MSG_SYS_CLOSE_ALT			"close"
@ MSG_SYS_7				"7"				# 7 (u)
@ MSG_SYS_8				"8"				# 8 (u)
@ MSG_SYS_LINK				"[ link ]"			# 9
@ MSG_SYS_LINK_ALT			"link"
@ MSG_SYS_UNLINK			"[ unlink ]"			# 10
@ MSG_SYS_UNLINK_ALT			"unlink"
@ MSG_SYS_11				"11"				# 11 (u)
@ MSG_SYS_CHDIR				"[ chdir ]"			# 12
@ MSG_SYS_CHDIR_ALT			"chdir"
@ MSG_SYS_TIME				"[ time ]"			# 13
@ MSG_SYS_TIME_ALT			"time"
@ MSG_SYS_MKNOD				"[ mknod ]"			# 14
@ MSG_SYS_MKNOD_ALT			"mknod"
@ MSG_SYS_CHMOD				"[ chmod ]"			# 15
@ MSG_SYS_CHMOD_ALT			"chmod"
@ MSG_SYS_CHOWN				"[ chown ]"			# 16
@ MSG_SYS_CHOWN_ALT			"chown"
@ MSG_SYS_BRK				"[ brk ]"			# 17
@ MSG_SYS_BRK_ALT			"brk"
@ MSG_SYS_STAT				"[ stat ]"			# 18
@ MSG_SYS_STAT_ALT			"stat"
@ MSG_SYS_LSEEK				"[ lseek ]"			# 19
@ MSG_SYS_LSEEK_ALT			"lseek"
@ MSG_SYS_GETPID			"[ getpid ]"			# 20
@ MSG_SYS_GETPID_ALT			"getpid"
@ MSG_SYS_MOUNT				"[ mount ]"			# 21
@ MSG_SYS_MOUNT_ALT			"mount"
@ MSG_SYS_22				"22"				# 22 (u)
@ MSG_SYS_SETUID			"[ setuid ]"			# 23
@ MSG_SYS_SETUID_ALT			"setuid"
@ MSG_SYS_GETUID			"[ getuid ]"			# 24
@ MSG_SYS_GETUID_ALT			"getuid"
@ MSG_SYS_STIME				"[ stime ]"			# 25
@ MSG_SYS_STIME_ALT			"stime"
@ MSG_SYS_PCSAMPLE			"[ pcsample ]"			# 26
@ MSG_SYS_PCSAMPLE_ALT			"pcsample"
@ MSG_SYS_ALARM				"[ alarm ]"			# 27
@ MSG_SYS_ALARM_ALT			"alarm"
@ MSG_SYS_FSTAT				"[ fstat ]"			# 28
@ MSG_SYS_FSTAT_ALT			"fstat"
@ MSG_SYS_PAUSE				"[ pause ]"			# 29
@ MSG_SYS_PAUSE_ALT			"pause"
@ MSG_SYS_30				"30"				# 30 (u)
@ MSG_SYS_STTY				"[ stty ]"			# 31
@ MSG_SYS_STTY_ALT			"stty"
@ MSG_SYS_GTTY				"[ gtty ]"			# 32
@ MSG_SYS_GTTY_ALT			"gtty"
@ MSG_SYS_ACCESS			"[ access ]"			# 33
@ MSG_SYS_ACCESS_ALT			"access"
@ MSG_SYS_NICE				"[ nice ]"			# 34
@ MSG_SYS_NICE_ALT			"nice"
@ MSG_SYS_STATFS			"[ statfs ]"			# 35
@ MSG_SYS_STATFS_ALT			"statfs"
@ MSG_SYS_SYNC				"[ sync ]"			# 36
@ MSG_SYS_SYNC_ALT			"sync"
@ MSG_SYS_KILL				"[ kill ]"			# 37
@ MSG_SYS_KILL_ALT			"kill"
@ MSG_SYS_FSTATFS			"[ fstatfs ]"			# 38
@ MSG_SYS_FSTATFS_ALT			"fstatfs"
@ MSG_SYS_PGRPSYS			"[ pgrpsys ]"			# 39
@ MSG_SYS_PGRPSYS_ALT			"pgrpsys"
@ MSG_SYS_UUCOPYSTR			"[ uucopystr ]"			# 40
@ MSG_SYS_UUCOPYSTR_ALT			"uucopystr"
@ MSG_SYS_41				"41"				# 41 (u)
@ MSG_SYS_PIPE				"[ pipe ]"			# 42
@ MSG_SYS_PIPE_ALT			"pipe"
@ MSG_SYS_TIMES				"[ times ]"			# 43
@ MSG_SYS_TIMES_ALT			"times"
@ MSG_SYS_PROFIL			"[ profil ]"			# 44
@ MSG_SYS_PROFIL_ALT			"profil"
@ MSG_SYS_FACCESSAT			"[ faccessat ]"			# 45
@ MSG_SYS_FACCESSAT_ALT			"faccessat"
@ MSG_SYS_SETGID			"[ setgid ]"			# 46
@ MSG_SYS_SETGID_ALT			"setgid"
@ MSG_SYS_GETGID			"[ getgid ]"			# 47
@ MSG_SYS_GETGID_ALT			"getgid"
@ MSG_SYS_48				"48"				# 48 (u)
@ MSG_SYS_MSGSYS			"[ msgsys ]"			# 49
@ MSG_SYS_MSGSYS_ALT			"msgsys"
@ MSG_SYS_SYSI86			"[ sysi86 ]"			# 50
@ MSG_SYS_SYSI86_ALT			"sysi86"
@ MSG_SYS_ACCT				"[ acct ]"			# 51
@ MSG_SYS_ACCT_ALT			"acct"
@ MSG_SYS_SHMSYS			"[ shmsys ]"			# 52
@ MSG_SYS_SHMSYS_ALT			"shmsys"
@ MSG_SYS_SEMSYS			"[ semsys ]"			# 53
@ MSG_SYS_SEMSYS_ALT			"semsys"
@ MSG_SYS_IOCTL				"[ ioctl ]"			# 54
@ MSG_SYS_IOCTL_ALT			"ioctl"
@ MSG_SYS_UADMIN			"[ uadmin ]"			# 55
@ MSG_SYS_UADMIN_ALT			"uadmin"
@ MSG_SYS_FCHOWNAT			"[ fchownat ]"			# 56
@ MSG_SYS_FCHOWNAT_ALT			"fchownat"
@ MSG_SYS_UTSSYS			"[ utssys ]"			# 57
@ MSG_SYS_UTSSYS_ALT			"utssys"
@ MSG_SYS_FDSYNC			"[ fdsync ]"			# 58
@ MSG_SYS_FDSYNC_ALT			"fdsync"
@ MSG_SYS_EXECVE			"[ execve ]"			# 59
@ MSG_SYS_EXECVE_ALT			"execve"
@ MSG_SYS_UMASK				"[ umask ]"			# 60
@ MSG_SYS_UMASK_ALT			"umask"
@ MSG_SYS_CHROOT			"[ chroot ]"			# 61
@ MSG_SYS_CHROOT_ALT			"chroot"
@ MSG_SYS_FCNTL				"[ fcntl ]"			# 62
@ MSG_SYS_FCNTL_ALT			"fcntl"
@ MSG_SYS_ULIMIT			"[ ulimit ]"			# 63
@ MSG_SYS_ULIMIT_ALT			"ulimit"	
@ MSG_SYS_RENAMEAT			"[ renameat ]"			# 64
@ MSG_SYS_RENAMEAT_ALT			"renameat"
@ MSG_SYS_UNLINKAT			"[ unlinkat ]"			# 65
@ MSG_SYS_UNLINKAT_ALT			"unlinkat"
@ MSG_SYS_FSTATAT			"[ fstatat ]"			# 66
@ MSG_SYS_FSTATAT_ALT			"fstatat"
@ MSG_SYS_FSTATAT64			"[ fstatat64 ]"			# 67
@ MSG_SYS_FSTATAT64_ALT			"fstatat64"
@ MSG_SYS_OPENAT			"[ openat ]"			# 68
@ MSG_SYS_OPENAT_ALT			"openat"
@ MSG_SYS_OPENAT64			"[ openat64 ]"			# 69
@ MSG_SYS_OPENAT64_ALT			"openat64"
@ MSG_SYS_TASKSYS			"[ tasksys ]"			# 70
@ MSG_SYS_TASKSYS_ALT			"tasksys	"
@ MSG_SYS_ACCTCTL			"[ acctctl ]"			# 71
@ MSG_SYS_ACCTCTL_ALT			"acctctl	"
@ MSG_SYS_EXACCTSYS			"[ exacctsys ]"			# 72
@ MSG_SYS_EXACCTSYS_ALT			"exacctsys"
@ MSG_SYS_GETPAGESIZES			"[ getpagesizes ]"		# 73
@ MSG_SYS_GETPAGESIZES_ALT		"getpagesizes"
@ MSG_SYS_RCTLSYS			"[ rctlsys ]"			# 74
@ MSG_SYS_RCTLSYS_ALT			"rctlsys	"
@ MSG_SYS_SIDSYS			"[ sidsys ]"			# 75
@ MSG_SYS_SIDSYS_ALT			"sidsys"	
@ MSG_SYS_76				"76"				# 76 (u)
@ MSG_SYS_LWP_PARK			"[ lwp_park ]"			# 77
@ MSG_SYS_LWP_PARK_ALT			"lwp_park"
@ MSG_SYS_SENDFILEV			"[ sendfilev ]"			# 78
@ MSG_SYS_SENDFILEV_ALT			"sendfilev"
@ MSG_SYS_RMDIR				"[ rmdir ]"			# 79
@ MSG_SYS_RMDIR_ALT			"rmdir"
@ MSG_SYS_MKDIR				"[ mkdir ]"			# 80
@ MSG_SYS_MKDIR_ALT			"mkdir"
@ MSG_SYS_GETDENTS			"[ getdents ]"			# 81
@ MSG_SYS_GETDENTS_ALT			"getdents"
@ MSG_SYS_PRIVSYS			"[ privsys ]"			# 82
@ MSG_SYS_PRIVSYS_ALT			"privsys"
@ MSG_SYS_UCREDSYS			"[ ucredsys ]"			# 83
@ MSG_SYS_UCREDSYS_ALT			"ucredsys"
@ MSG_SYS_SYSFS				"[ sysfs ]"			# 84
@ MSG_SYS_SYSFS_ALT			"sysfs"
@ MSG_SYS_GETMSG			"[ getmsg ]"			# 85
@ MSG_SYS_GETMSG_ALT			"getmsg"
@ MSG_SYS_PUTMSG			"[ putmsg ]"			# 86
@ MSG_SYS_PUTMSG_ALT			"putmsg"
@ MSG_SYS_87				"87"				# 87 (u)
@ MSG_SYS_LSTAT				"[ lstat ]"			# 88
@ MSG_SYS_LSTAT_ALT			"lstat"
@ MSG_SYS_SYMLINK			"[ symlink ]"			# 89
@ MSG_SYS_SYMLINK_ALT			"symlink"
@ MSG_SYS_READLINK			"[ readlink ]"			# 90
@ MSG_SYS_READLINK_ALT			"readlink"
@ MSG_SYS_SETGROUPS			"[ setgroups ]"			# 91
@ MSG_SYS_SETGROUPS_ALT			"setgroups"
@ MSG_SYS_GETGROUPS			"[ getgroups ]"			# 92
@ MSG_SYS_GETGROUPS_ALT			"getgroups"
@ MSG_SYS_FCHMOD			"[ fchmod ]"			# 93
@ MSG_SYS_FCHMOD_ALT			"fchmod"
@ MSG_SYS_FCHOWN			"[ fchown ]"			# 94
@ MSG_SYS_FCHOWN_ALT			"fchown"
@ MSG_SYS_SIGPROCMASK			"[ sigprocmask ]"		# 95
@ MSG_SYS_SIGPROCMASK_ALT		"sigprocmask"
@ MSG_SYS_SIGSUSPEND			"[ sigsuspend ]"		# 96
@ MSG_SYS_SIGSUSPEND_ALT		"sigsuspend"
@ MSG_SYS_SIGALTSTACK			"[ sigaltstack ]"		# 97
@ MSG_SYS_SIGALTSTACK_ALT		"sigaltstack"
@ MSG_SYS_SIGACTION			"[ sigaction ]"			# 98
@ MSG_SYS_SIGACTION_ALT			"sigaction"
@ MSG_SYS_SIGPENDING			"[ sigpending ]"		# 99
@ MSG_SYS_SIGPENDING_ALT		"sigpending"
@ MSG_SYS_CONTEXT			"[ context ]"			# 100
@ MSG_SYS_CONTEXT_ALT			"context"
@ MSG_SYS_101				"101"				# 101(u)
@ MSG_SYS_102				"102"				# 102(u)
@ MSG_SYS_STATVFS			"[ statvfs ]"			# 103
@ MSG_SYS_STATVFS_ALT			"statvfs"
@ MSG_SYS_FSTATVFS			"[ fstatvfs ]"			# 104
@ MSG_SYS_FSTATVFS_ALT			"fstatvfs"
@ MSG_SYS_GETLOADAVG			"[ getloadavg ]"		# 105
@ MSG_SYS_GETLOADAVG_ALT		"getloadavg"
@ MSG_SYS_NFSSYS			"[ nfssys ]"			# 106
@ MSG_SYS_NFSSYS_ALT			"nfssys"
@ MSG_SYS_WAITID			"[ waitid ]"			# 107
@ MSG_SYS_WAITID_ALT			"waitid"
@ MSG_SYS_SIGSENDSYS			"[ sigsendsys ]"		# 108
@ MSG_SYS_SIGSENDSYS_ALT		"sigsendsys"
@ MSG_SYS_HRTSYS			"[ hrtsys ]"			# 109
@ MSG_SYS_HRTSYS_ALT			"hrtsys"
@ MSG_SYS_UTIMESYS			"[ utimesys ]"			# 110
@ MSG_SYS_UTIMESYS_ALT			"utimesys"
@ MSG_SYS_SIGRESEND			"[ sigresend ]"			# 111
@ MSG_SYS_SIGRESEND_ALT			"sigresend"
@ MSG_SYS_PRIOCNTLSYS			"[ priocntlsys ]"		# 112
@ MSG_SYS_PRIOCNTLSYS_ALT		"priocntlsys"
@ MSG_SYS_PATHCONF			"[ pathconf ]"			# 113
@ MSG_SYS_PATHCONF_ALT			"pathconf"
@ MSG_SYS_MINCORE			"[ mincore ]"			# 114
@ MSG_SYS_MINCORE_ALT			"mincore"
@ MSG_SYS_MMAP				"[ mmap ]"			# 115
@ MSG_SYS_MMAP_ALT			"mmap"
@ MSG_SYS_MPROTECT			"[ mprotect ]"			# 116
@ MSG_SYS_MPROTECT_ALT			"mprotect"
@ MSG_SYS_MUNMAP			"[ munmap ]"			# 117
@ MSG_SYS_MUNMAP_ALT			"munmap"
@ MSG_SYS_FPATHCONF			"[ fpathconf ]"			# 118
@ MSG_SYS_FPATHCONF_ALT			"fpathconf"
@ MSG_SYS_VFORK				"[ vfork ]"			# 119
@ MSG_SYS_VFORK_ALT			"vfork"
@ MSG_SYS_FCHDIR			"[ fchdir ]"			# 120
@ MSG_SYS_FCHDIR_ALT			"fchdir"
@ MSG_SYS_READV				"[ readv ]"			# 121
@ MSG_SYS_READV_ALT			"readv"
@ MSG_SYS_WRITEV			"[ writev ]"			# 122
@ MSG_SYS_WRITEV_ALT			"writev"
@ MSG_SYS_123				"123"				# 123(u)
@ MSG_SYS_124				"124"				# 124(u)
@ MSG_SYS_125				"125"				# 125(u)
@ MSG_SYS_126				"126"				# 126(u)
@ MSG_SYS_MMAPOBJ			"[ mmapobj ]"			# 127
@ MSG_SYS_MMAPOBJ_ALT			"mmapobj"
@ MSG_SYS_SETRLIMIT			"[ setrlimit ]"			# 128
@ MSG_SYS_SETRLIMIT_ALT			"setrlimit"
@ MSG_SYS_GETRLIMIT			"[ getrlimit ]"			# 129
@ MSG_SYS_GETRLIMIT_ALT			"getrlimit"
@ MSG_SYS_LCHOWN			"[ lchown ]"			# 130
@ MSG_SYS_LCHOWN_ALT			"lchown"
@ MSG_SYS_MEMCNTL			"[ memcntl ]"			# 131
@ MSG_SYS_MEMCNTL_ALT			"memcntl"
@ MSG_SYS_GETPMSG			"[ getpmsg ]"			# 132
@ MSG_SYS_GETPMSG_ALT			"getpmsg"
@ MSG_SYS_PUTPMSG			"[ putpmsg ]"			# 133
@ MSG_SYS_PUTPMSG_ALT			"putpmsg"
@ MSG_SYS_RENAME			"[ rename ]"			# 134
@ MSG_SYS_RENAME_ALT			"rename"
@ MSG_SYS_UNAME				"[ uname ]"			# 135
@ MSG_SYS_UNAME_ALT			"uname"
@ MSG_SYS_SETEGID			"[ setegid ]"			# 136
@ MSG_SYS_SETEGID_ALT			"setegid"
@ MSG_SYS_SYSCONFIG			"[ sysconfig ]"			# 137
@ MSG_SYS_SYSCONFIG_ALT			"sysconfig"
@ MSG_SYS_ADJTIME			"[ adjtime ]"			# 138
@ MSG_SYS_ADJTIME_ALT			"adjtime"
@ MSG_SYS_SYSTEMINFO			"[ systeminfo ]"		# 139
@ MSG_SYS_SYSTEMINFO_ALT		"systeminfo"
@ MSG_SYS_SHAREFS			"[ sharefs ]"			# 140
@ MSG_SYS_SHAREFS_ALT			"sharefs"
@ MSG_SYS_SETEUID			"[ seteuid ]"			# 141
@ MSG_SYS_SETEUID_ALT			"seteuid"
@ MSG_SYS_FORKSYS			"[ forksys ]"			# 142
@ MSG_SYS_FORKSYS_ALT			"forksys"
@ MSG_SYS_143				"143"				# 143(u)
@ MSG_SYS_SIGTIMEDWAIT			"[ sigtimedwait ]"		# 144
@ MSG_SYS_SIGTIMEDWAIT_ALT		"sigtimedwait"
@ MSG_SYS_LWP_INFO			"[ lwp_info ]"			# 145
@ MSG_SYS_LWP_INFO_ALT			"lwp_info"
@ MSG_SYS_YIELD				"[ yield ]"			# 146
@ MSG_SYS_YIELD_ALT			"yield"
@ MSG_SYS_147				"147"				# 147(u)
@ MSG_SYS_LWP_SEMA_POST			"[ lwp_sema_post ]"		# 148
@ MSG_SYS_LWP_SEMA_POST_ALT		"lwp_sema_post"
@ MSG_SYS_LWP_SEMA_TRYWAIT		"[ lwp_sema_trywait ]"		# 149
@ MSG_SYS_LWP_SEMA_TRYWAIT_ALT		"lwp_sema_trywait"
@ MSG_SYS_LWP_DETACH			"[ lwp_detach ]"		# 150
@ MSG_SYS_LWP_DETACH_ALT		"lwp_detach"
@ MSG_SYS_CORECTL			"[ corectl ]"			# 151
@ MSG_SYS_CORECTL_ALT			"corectl"
@ MSG_SYS_MODCTL			"[ modctl ]"			# 152
@ MSG_SYS_MODCTL_ALT			"modctl"
@ MSG_SYS_FCHROOT			"[ fchroot ]"			# 153
@ MSG_SYS_FCHROOT_ALT			"fchroot"
@ MSG_SYS_154				"154"				# 154(u)
@ MSG_SYS_VHANGUP			"[ vhangup ]"			# 155
@ MSG_SYS_VHANGUP_ALT			"vhangup"
@ MSG_SYS_GETTIMEOFDAY			"[ gettimeofday ]"		# 156
@ MSG_SYS_GETTIMEOFDAY_ALT		"gettimeofday"
@ MSG_SYS_GETITIMER			"[ getitimer ]"			# 157
@ MSG_SYS_GETITIMER_ALT			"getitimer"
@ MSG_SYS_SETITIMER			"[ setitimer ]"			# 158
@ MSG_SYS_SETITIMER_ALT			"setitimer"
@ MSG_SYS_LWP_CREATE			"[ lwp_create ]"		# 159
@ MSG_SYS_LWP_CREATE_ALT		"lwp_create"
@ MSG_SYS_LWP_EXIT			"[ lwp_exit ]"			# 160
@ MSG_SYS_LWP_EXIT_ALT			"lwp_exit"
@ MSG_SYS_LWP_SUSPEND			"[ lwp_suspend ]"		# 161
@ MSG_SYS_LWP_SUSPEND_ALT		"lwp_suspend"
@ MSG_SYS_LWP_CONTINUE			"[ lwp_continue ]"		# 162
@ MSG_SYS_LWP_CONTINUE_ALT		"lwp_continue"
@ MSG_SYS_LWP_KILL			"[ lwp_kill ]"			# 163
@ MSG_SYS_LWP_KILL_ALT			"lwp_kill"
@ MSG_SYS_LWP_SELF			"[ lwp_self ]"			# 164
@ MSG_SYS_LWP_SELF_ALT			"lwp_self"
@ MSG_SYS_LWP_SIGMASK			"[ lwp_sigmask ]"		# 165
@ MSG_SYS_LWP_SIGMASK_ALT		"lwp_sigmask"
@ MSG_SYS_LWP_PRIVATE			"[ lwp_private ]"		# 166
@ MSG_SYS_LWP_PRIVATE_ALT		"lwp_private"
@ MSG_SYS_LWP_WAIT			"[ lwp_wait ]"			# 167
@ MSG_SYS_LWP_WAIT_ALT			"lwp_wait"
@ MSG_SYS_LWP_MUTEX_WAKEUP		"[ lwp_mutex_wakeup ]"		# 168
@ MSG_SYS_LWP_MUTEX_WAKEUP_ALT		"lwp_mutex_wakeup"
@ MSG_SYS_169				"169"				# 169(u)
@ MSG_SYS_LWP_COND_WAIT			"[ lwp_cond_wait ]"		# 170
@ MSG_SYS_LWP_COND_WAIT_ALT		"lwp_cond_wait"
@ MSG_SYS_LWP_COND_SIGNAL		"[ lwp_cond_signal ]"		# 171
@ MSG_SYS_LWP_COND_SIGNAL_ALT		"lwp_cond_signal"
@ MSG_SYS_LWP_COND_BROADCAST		"[ lwp_cond_broadcast ]"	# 172
@ MSG_SYS_LWP_COND_BROADCAST_ALT	"lwp_cond_broadcast"
@ MSG_SYS_PREAD				"[ pread ]"			# 173
@ MSG_SYS_PREAD_ALT			"pread"
@ MSG_SYS_PWRITE			"[ pwrite ]"			# 174
@ MSG_SYS_PWRITE_ALT			"pwrite"
@ MSG_SYS_LLSEEK			"[ llseek ]"			# 175
@ MSG_SYS_LLSEEK_ALT			"llseek"
@ MSG_SYS_INST_SYNC			"[ inst_sync ]"			# 176
@ MSG_SYS_INST_SYNC_ALT			"inst_sync"
@ MSG_SYS_BRAND				"[ brand ]"			# 177
@ MSG_SYS_BRAND_ALT			"brand"
@ MSG_SYS_KAIO				"[ kaio ]"			# 178
@ MSG_SYS_KAIO_ALT			"kaio"
@ MSG_SYS_CPC				"[ cpc ]"			# 179
@ MSG_SYS_CPC_ALT			"cpc"
@ MSG_SYS_LGRPSYS			"[ lgrpsys ]"			# 180
@ MSG_SYS_LGRPSYS_ALT			"lgrpsys"
@ MSG_SYS_RUSAGESYS			"[ rusagesys ]"			# 181
@ MSG_SYS_RUSAGESYS_ALT			"rusagesys"
@ MSG_SYS_PORT				"[ port ]"			# 182
@ MSG_SYS_PORT_ALT			"port"
@ MSG_SYS_POLLSYS			"[ pollsys ]"			# 183
@ MSG_SYS_POLLSYS_ALT			"pollsys"
@ MSG_SYS_LABELSYS			"[ labelsys ]"			# 184
@ MSG_SYS_LABELSYS_ALT			"labelsys"
@ MSG_SYS_ACL				"[ acl ]"			# 185
@ MSG_SYS_ACL_ALT			"acl"
@ MSG_SYS_AUDITSYS			"[ auditsys ]"			# 186
@ MSG_SYS_AUDITSYS_ALT			"auditsys"
@ MSG_SYS_PROCESSOR_BIND		"[ processor_bind ]"		# 187
@ MSG_SYS_PROCESSOR_BIND_ALT		"processor_bind"
@ MSG_SYS_PROCESSOR_INFO		"[ processor_info ]"		# 188
@ MSG_SYS_PROCESSOR_INFO_ALT		"processor_info"
@ MSG_SYS_P_ONLINE			"[ p_online ]"			# 189
@ MSG_SYS_P_ONLINE_ALT			"p_online"
@ MSG_SYS_SIGQUEUE			"[ sigqueue ]"			# 190
@ MSG_SYS_SIGQUEUE_ALT			"sigqueue"
@ MSG_SYS_CLOCK_GETTIME			"[ clock_gettime ]"		# 191
@ MSG_SYS_CLOCK_GETTIME_ALT		"clock_gettime"
@ MSG_SYS_CLOCK_SETTIME			"[ clock_settime ]"		# 192
@ MSG_SYS_CLOCK_SETTIME_ALT		"clock_settime"
@ MSG_SYS_CLOCK_GETRES			"[ clock_getres ]"		# 193
@ MSG_SYS_CLOCK_GETRES_ALT		"clock_getres"
@ MSG_SYS_TIMER_CREATE			"[ timer_create ]"		# 194
@ MSG_SYS_TIMER_CREATE_ALT		"timer_create"
@ MSG_SYS_TIMER_DELETE			"[ timer_delete ]"		# 195
@ MSG_SYS_TIMER_DELETE_ALT		"timer_delete"
@ MSG_SYS_TIMER_SETTIME			"[ timer_settime ]"		# 196
@ MSG_SYS_TIMER_SETTIME_ALT		"timer_settime"
@ MSG_SYS_TIMER_GETTIME			"[ timer_gettime ]"		# 197
@ MSG_SYS_TIMER_GETTIME_ALT		"timer_gettime"
@ MSG_SYS_TIMER_GETOVERRUN		"[ timer_getoverrun ]"		# 198
@ MSG_SYS_TIMER_GETOVERRUN_ALT		"timer_getoverrun"
@ MSG_SYS_NANOSLEEP			"[ nanosleep ]"			# 199
@ MSG_SYS_NANOSLEEP_ALT			"nanosleep"
@ MSG_SYS_FACL				"[ facl ]"			# 200
@ MSG_SYS_FACL_ALT			"facl"
@ MSG_SYS_DOOR				"[ door ]"			# 201
@ MSG_SYS_DOOR_ALT			"door"
@ MSG_SYS_SETREUID			"[ setreuid ]"			# 202
@ MSG_SYS_SETREUID_ALT			"setreuid"
@ MSG_SYS_SETREGID			"[ setregid ]"			# 203
@ MSG_SYS_SETREGID_ALT			"setregid"
@ MSG_SYS_INSTALL_UTRAP			"[ install_utrap ]"		# 204
@ MSG_SYS_INSTALL_UTRAP_ALT		"install_utrap"
@ MSG_SYS_SIGNOTIFY			"[ signotify ]"			# 205
@ MSG_SYS_SIGNOTIFY_ALT			"signotify"
@ MSG_SYS_SCHEDCTL			"[ schedctl ]"			# 206
@ MSG_SYS_SCHEDCTL_ALT			"schedctl"
@ MSG_SYS_PSET				"[ pset ]"			# 207
@ MSG_SYS_PSET_ALT			"pset"
@ MSG_SYS_SPARC_UTRAP_INSTALL		"[ sparc_utrap_install ]"	# 208
@ MSG_SYS_SPARC_UTRAP_INSTALL_ALT	"sparc_utrap_install"
@ MSG_SYS_RESOLVEPATH			"[ resolvepath ]"		# 209
@ MSG_SYS_RESOLVEPATH_ALT		"resolvepath"
@ MSG_SYS_LWP_MUTEX_TIMEDLOCK		"[ lwp_mutex_timedlock ]"	# 210
@ MSG_SYS_LWP_MUTEX_TIMEDLOCK_ALT	"lwp_mutex_timedlock"
@ MSG_SYS_LWP_SEMA_TIMEDWAIT		"[ lwp_sema_timedwait ]"	# 211
@ MSG_SYS_LWP_SEMA_TIMEDWAIT_ALT	"lwp_sema_timedwait"
@ MSG_SYS_LWP_RWLOCK_SYS		"[ lwp_rwlock_sys ]"		# 212
@ MSG_SYS_LWP_RWLOCK_SYS_ALT		"lwp_rwlock_sys"
@ MSG_SYS_GETDENTS64			"[ getdents64 ]"		# 213
@ MSG_SYS_GETDENTS64_ALT		"getdents64"
@ MSG_SYS_MMAP64			"[ mmap64 ]"			# 214
@ MSG_SYS_MMAP64_ALT			"mmap64"
@ MSG_SYS_STAT64			"[ stat64 ]"			# 215
@ MSG_SYS_STAT64_ALT			"stat64"
@ MSG_SYS_LSTAT64			"[ lstat64 ]"			# 216
@ MSG_SYS_LSTAT64_ALT			"lstat64"
@ MSG_SYS_FSTAT64			"[ fstat64 ]"			# 217
@ MSG_SYS_FSTAT64_ALT			"fstat64"
@ MSG_SYS_STATVFS64			"[ statvfs64 ]"			# 218
@ MSG_SYS_STATVFS64_ALT			"statvfs64"
@ MSG_SYS_FSTATVFS64			"[ fstatvfs64 ]"		# 219
@ MSG_SYS_FSTATVFS64_ALT		"fstatvfs64"
@ MSG_SYS_SETRLIMIT64			"[ setrlimit64 ]"		# 220
@ MSG_SYS_SETRLIMIT64_ALT		"setrlimit64"
@ MSG_SYS_GETRLIMIT64			"[ getrlimit64 ]"		# 221
@ MSG_SYS_GETRLIMIT64_ALT		"getrlimit64"
@ MSG_SYS_PREAD64			"[ pread64 ]"			# 222
@ MSG_SYS_PREAD64_ALT			"pread64"
@ MSG_SYS_PWRITE64			"[ pwrite64 ]"			# 223
@ MSG_SYS_PWRITE64_ALT			"pwrite64"
@ MSG_SYS_224				"224"				# 224(u)
@ MSG_SYS_OPEN64			"[ open64 ]"			# 225
@ MSG_SYS_OPEN64_ALT			"open64"
@ MSG_SYS_RPCSYS			"[ rpcsys ]"			# 226
@ MSG_SYS_RPCSYS_ALT			"rpcsys"
@ MSG_SYS_ZONE				"[ zone ]"			# 227
@ MSG_SYS_ZONE_ALT			"zone"
@ MSG_SYS_AUTOFSSYS			"[ autofssys ]"			# 228
@ MSG_SYS_AUTOFSSYS_ALT			"autofssys"
@ MSG_SYS_GETCWD			"[ getcwd ]"			# 229
@ MSG_SYS_GETCWD_ALT			"getcwd"
@ MSG_SYS_SO_SOCKET			"[ so_socket ]"			# 230
@ MSG_SYS_SO_SOCKET_ALT			"so_socket"
@ MSG_SYS_SO_SOCKETPAIR			"[ so_socketpair ]"		# 231
@ MSG_SYS_SO_SOCKETPAIR_ALT		"so_socketpair"
@ MSG_SYS_BIND				"[ bind ]"			# 232
@ MSG_SYS_BIND_ALT			"bind"
@ MSG_SYS_LISTEN			"[ listen ]"			# 233
@ MSG_SYS_LISTEN_ALT			"listen"
@ MSG_SYS_ACCEPT			"[ accept ]"			# 234
@ MSG_SYS_ACCEPT_ALT			"accept"
@ MSG_SYS_CONNECT			"[ connect ]"			# 235
@ MSG_SYS_CONNECT_ALT			"connect"
@ MSG_SYS_SHUTDOWN			"[ shutdown ]"			# 236
@ MSG_SYS_SHUTDOWN_ALT			"shutdown"
@ MSG_SYS_RECV				"[ recv ]"			# 237
@ MSG_SYS_RECV_ALT			"recv"
@ MSG_SYS_RECVFROM			"[ recvfrom ]"			# 238
@ MSG_SYS_RECVFROM_ALT			"recvfrom"
@ MSG_SYS_RECVMSG			"[ recvmsg ]"			# 239
@ MSG_SYS_RECVMSG_ALT			"recvmsg"
@ MSG_SYS_SEND				"[ send ]"			# 240
@ MSG_SYS_SEND_ALT			"send"
@ MSG_SYS_SENDMSG			"[ sendmsg ]"			# 241
@ MSG_SYS_SENDMSG_ALT			"sendmsg"
@ MSG_SYS_SENDTO			"[ sendto ]"			# 242
@ MSG_SYS_SENDTO_ALT			"sendto"
@ MSG_SYS_GETPEERNAME			"[ getpeername ]"		# 243
@ MSG_SYS_GETPEERNAME_ALT		"getpeername"
@ MSG_SYS_GETSOCKNAME			"[ getsockname ]"		# 244
@ MSG_SYS_GETSOCKNAME_ALT		"getsockname"
@ MSG_SYS_GETSOCKOPT			"[ getsockopt ]"		# 245
@ MSG_SYS_GETSOCKOPT_ALT		"getsockopt"
@ MSG_SYS_SETSOCKOPT			"[ setsockopt ]"		# 246
@ MSG_SYS_SETSOCKOPT_ALT		"setsockopt"
@ MSG_SYS_SOCKCONFIG			"[ sockconfig ]"		# 247
@ MSG_SYS_SOCKCONFIG_ALT		"sockconfig"
@ MSG_SYS_NTP_GETTIME			"[ ntp_gettime ]"		# 248
@ MSG_SYS_NTP_GETTIME_ALT		"ntp_gettime"
@ MSG_SYS_NTP_ADJTIME			"[ ntp_adjtime ]"		# 249
@ MSG_SYS_NTP_ADJTIME_ALT		"ntp_adjtime"
@ MSG_SYS_LWP_MUTEX_UNLOCK		"[ lwp_mutex_unlock ]"		# 250
@ MSG_SYS_LWP_MUTEX_UNLOCK_ALT		"lwp_mutex_unlock"
@ MSG_SYS_LWP_MUTEX_TRYLOCK		"[ lwp_mutex_trylock ]"		# 251
@ MSG_SYS_LWP_MUTEX_TRYLOCK_ALT		"lwp_mutex_trylock"
@ MSG_SYS_LWP_MUTEX_REGISTER		"[ lwp_mutex_register ]"	# 252
@ MSG_SYS_LWP_MUTEX_REGISTER_ALT	"lwp_mutex_register"
@ MSG_SYS_CLADM				"[ cladm ]"			# 253
@ MSG_SYS_CLADM_ALT			"cladm"
@ MSG_SYS_UUCOPY			"[ uucopy ]"			# 254
@ MSG_SYS_UUCOPY_ALT			"uucopy"
@ MSG_SYS_UMOUNT2			"[ umount2 ]"			# 255
@ MSG_SYS_UMOUNT2_ALT			"umount2"

@ MSG_PR_O_RDONLY			"O_RDONLY"
@ MSG_PR_O_WRONLY			"O_WRONLY"
@ MSG_PR_O_RDWR				"O_RDWR"
@ MSG_PR_O_SEARCH			"O_SEARCH"
@ MSG_PR_O_EXEC				"O_EXEC"
@ MSG_PR_O_NDELAY			"O_NDELAY"
@ MSG_PR_O_NONBLOCK			"O_NONBLOCK"
@ MSG_PR_O_APPEND			"O_APPEND"
@ MSG_PR_O_SYNC				"O_SYNC"
@ MSG_PR_O_DSYNC			"O_DSYNC"
@ MSG_PR_O_RSYNC			"O_RSYNC"
@ MSG_PR_O_CREAT			"O_CREAT"
@ MSG_PR_O_TRUNC			"O_TRUNC"
@ MSG_PR_O_EXCL				"O_EXCL"
@ MSG_PR_O_NOCTTY			"O_NOCTTY"
@ MSG_PR_O_LARGEFILE			"O_LARGEFILE"
@ MSG_PR_O_XATTR			"O_XATTR"
@ MSG_PR_O_NOFOLLOW			"O_NOFOLLOW"
@ MSG_PR_O_NOLINKS			"O_NOLINKS"

@ MSG_S_IFIFO				"S_IFIFO"
@ MSG_S_IFCHR				"S_IFCHR"
@ MSG_S_IFDIR				"S_IFDIR"
@ MSG_S_IFNAM				"S_IFNAM"
@ MSG_S_IFBLK				"S_IFBLK"
@ MSG_S_IFREG				"S_IFREG"
@ MSG_S_IFLNK				"S_IFLNK"
@ MSG_S_IFSOCK				"S_IFSOCK"
@ MSG_S_IFDOOR				"S_IFDOOR"
@ MSG_S_IFPORT				"S_IFPORT"
@ MSG_S_ISUID				"S_ISUID"
@ MSG_S_ISGID				"S_ISGID"
@ MSG_S_ISVTX				"S_ISVTX"
@ MSG_S_IRUSR				"S_IRUSR"
@ MSG_S_IWUSR				"S_IWUSR"
@ MSG_S_IXUSR				"S_IXUSR"
@ MSG_S_IRGRP				"S_IRGRP"
@ MSG_S_IWGRP				"S_IWGRP"
@ MSG_S_IXGRP				"S_IXGRP"
@ MSG_S_IROTH				"S_IROTH"
@ MSG_S_IWOTH				"S_IWOTH"
@ MSG_S_IXOTH				"S_IXOTH"

@ MSG_GBL_ZERO		"0"

@ MSG_FMT_INT		"%d"
@ MSG_FMT_WORD		"%u"
@ MSG_FMT_HEXINT	"%#x"
