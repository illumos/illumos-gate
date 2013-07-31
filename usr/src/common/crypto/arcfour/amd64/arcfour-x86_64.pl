#!/usr/bin/env perl
#
# ====================================================================
# Written by Andy Polyakov <appro@fy.chalmers.se> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================
#
# 2.22x RC4 tune-up:-) It should be noted though that my hand [as in
# "hand-coded assembler"] doesn't stand for the whole improvement
# coefficient. It turned out that eliminating RC4_CHAR from config
# line results in ~40% improvement (yes, even for C implementation).
# Presumably it has everything to do with AMD cache architecture and
# RAW or whatever penalties. Once again! The module *requires* config
# line *without* RC4_CHAR! As for coding "secret," I bet on partial
# register arithmetics. For example instead of 'inc %r8; and $255,%r8'
# I simply 'inc %r8b'. Even though optimization manual discourages
# to operate on partial registers, it turned out to be the best bet.
# At least for AMD... How IA32E would perform remains to be seen...

# As was shown by Marc Bevand reordering of couple of load operations
# results in even higher performance gain of 3.3x:-) At least on
# Opteron... For reference, 1x in this case is RC4_CHAR C-code
# compiled with gcc 3.3.2, which performs at ~54MBps per 1GHz clock.
# Latter means that if you want to *estimate* what to expect from
# *your* Opteron, then multiply 54 by 3.3 and clock frequency in GHz.

# Intel P4 EM64T core was found to run the AMD64 code really slow...
# The only way to achieve comparable performance on P4 was to keep
# RC4_CHAR. Kind of ironic, huh? As it's apparently impossible to
# compose blended code, which would perform even within 30% marginal
# on either AMD and Intel platforms, I implement both cases. See
# rc4_skey.c for further details...

# P4 EM64T core appears to be "allergic" to 64-bit inc/dec. Replacing
# those with add/sub results in 50% performance improvement of folded
# loop...

# As was shown by Zou Nanhai loop unrolling can improve Intel EM64T
# performance by >30% [unlike P4 32-bit case that is]. But this is
# provided that loads are reordered even more aggressively! Both code
# pathes, AMD64 and EM64T, reorder loads in essentially same manner
# as my IA-64 implementation. On Opteron this resulted in modest 5%
# improvement [I had to test it], while final Intel P4 performance
# achieves respectful 432MBps on 2.8GHz processor now. For reference.
# If executed on Xeon, current RC4_CHAR code-path is 2.7x faster than
# RC4_INT code-path. While if executed on Opteron, it's only 25%
# slower than the RC4_INT one [meaning that if CPU µ-arch detection
# is not implemented, then this final RC4_CHAR code-path should be
# preferred, as it provides better *all-round* performance].

# Intel Core2 was observed to perform poorly on both code paths:-( It
# apparently suffers from some kind of partial register stall, which
# occurs in 64-bit mode only [as virtually identical 32-bit loop was
# observed to outperform 64-bit one by almost 50%]. Adding two movzb to
# cloop1 boosts its performance by 80%! This loop appears to be optimal
# fit for Core2 and therefore the code was modified to skip cloop8 on
# this CPU.

#
# OpenSolaris OS modifications
#
# Sun elects to use this software under the BSD license.
#
# This source originates from OpenSSL file rc4-x86_64.pl at
# ftp://ftp.openssl.org/snapshot/openssl-0.9.8-stable-SNAP-20080131.tar.gz
# (presumably for future OpenSSL release 0.9.8h), with these changes:
#
# 1. Added some comments, "use strict", and declared all variables.
#
# 2. Added OpenSolaris ENTRY_NP/SET_SIZE macros from
# /usr/include/sys/asm_linkage.h.
#
# 3. Changed function name from RC4() to arcfour_crypt_asm() and RC4_set_key()
# to arcfour_key_init(), and changed the parameter order for both to that
# used by OpenSolaris.
#
# 4. The current method of using cpuid feature bits 20 (NX) or 28 (HTT) from
# function OPENSSL_ia32_cpuid() to distinguish Intel/AMD does not work for
# some newer AMD64 processors, as these bits are set on both Intel EM64T
# processors and newer AMD64 processors.  I replaced this with C code
# (function arcfour_crypt_on_intel()) to call cpuid_getvendor()
# when executing in the kernel and getisax() when executing in userland.
#
# 5. Set a new field in the key structure, key->flag to 0 for AMD AMD64
# and 1 for Intel EM64T.  This is to select the most-efficient arcfour_crypt()
# function to use.
#
# 6. Removed x86_64-xlate.pl script (not needed for as(1) or gas(1) assemblers).
#
# 7. Removed unused RC4_CHAR, Lcloop1, and Lcloop8 code.
#
# 8. Added C function definitions for use by lint(1B).
#

use strict;
my ($code, $dat, $inp, $out, $len, $idx, $ido, $i, @XX, @TX, $YY, $TY);
my $output = shift;
open STDOUT,">$output";

#
# Parameters
#

# OpenSSL:
# void RC4(RC4_KEY *key, unsigned long len, const unsigned char *indata,
#	unsigned char *outdata);
#$dat="%rdi";	    # arg1
#$len="%rsi";	    # arg2
#$inp="%rdx";	    # arg3
#$out="%rcx";	    # arg4

# OpenSolaris:
# void arcfour_crypt_asm(ARCFour_key *key, uchar_t *in, uchar_t *out,
#	size_t len);
$dat="%rdi";	    # arg1
$inp="%rsi";	    # arg2
$out="%rdx";	    # arg3
$len="%rcx";	    # arg4

#
# Register variables
#
# $XX[0] is key->i (aka key->x), $XX[1] is a temporary.
# $TX[0] and $TX[1] are temporaries.
# $YY is key->j (aka key->y).
# $TY is a temporary.
#
@XX=("%r8","%r10");
@TX=("%r9","%r11");
$YY="%r12";
$TY="%r13";

$code=<<___;
#if defined(lint) || defined(__lint)

#include "arcfour.h"

/* ARGSUSED */
void
arcfour_crypt_asm(ARCFour_key *key, uchar_t *in, uchar_t *out, size_t len)
{}

/* ARGSUSED */
void
arcfour_key_init(ARCFour_key *key, uchar_t *keyval, int keyvallen)
{}

#else
#include <sys/asm_linkage.h>

ENTRY_NP(arcfour_crypt_asm)
	or	$len,$len # If (len == 0) return
	jne	.Lentry
	ret
.Lentry:
	push	%r12
	push	%r13

	/ Set $dat to beginning of array, key->arr[0]
	add	\$8,$dat
	/ Get key->j
	movl	-8($dat),$XX[0]#d
	/ Get key->i
	movl	-4($dat),$YY#d

	/
	/ Use a 4-byte key schedule element array
	/
	inc	$XX[0]#b
	movl	($dat,$XX[0],4),$TX[0]#d
	test	\$-8,$len
	jz	.Lloop1
	jmp	.Lloop8

.align	16
.Lloop8:
___
for ($i=0;$i<8;$i++) {
$code.=<<___;
	add	$TX[0]#b,$YY#b
	mov	$XX[0],$XX[1]
	movl	($dat,$YY,4),$TY#d
	ror	\$8,%rax			# ror is redundant when $i=0
	inc	$XX[1]#b
	movl	($dat,$XX[1],4),$TX[1]#d
	cmp	$XX[1],$YY
	movl	$TX[0]#d,($dat,$YY,4)
	cmove	$TX[0],$TX[1]
	movl	$TY#d,($dat,$XX[0],4)
	add	$TX[0]#b,$TY#b
	movb	($dat,$TY,4),%al
___
push(@TX,shift(@TX)); push(@XX,shift(@XX));	# "rotate" registers
}
$code.=<<___;
	ror	\$8,%rax
	sub	\$8,$len

	xor	($inp),%rax
	add	\$8,$inp
	mov	%rax,($out)
	add	\$8,$out

	test	\$-8,$len
	jnz	.Lloop8
	cmp	\$0,$len
	jne	.Lloop1

.Lexit:
	/
	/ Cleanup and exit code
	/
	/ --i to undo ++i done at entry
	sub	\$1,$XX[0]#b
	/ set key->i
	movl	$XX[0]#d,-8($dat)
	/ set key->j
	movl	$YY#d,-4($dat)

	pop	%r13
	pop	%r12
	ret

.align	16
.Lloop1:
	add	$TX[0]#b,$YY#b
	movl	($dat,$YY,4),$TY#d
	movl	$TX[0]#d,($dat,$YY,4)
	movl	$TY#d,($dat,$XX[0],4)
	add	$TY#b,$TX[0]#b
	inc	$XX[0]#b
	movl	($dat,$TX[0],4),$TY#d
	movl	($dat,$XX[0],4),$TX[0]#d
	xorb	($inp),$TY#b
	inc	$inp
	movb	$TY#b,($out)
	inc	$out
	dec	$len
	jnz	.Lloop1
	jmp	.Lexit

	ret
SET_SIZE(arcfour_crypt_asm)
___


#
# Parameters
#

# OpenSSL:
# void RC4_set_key(RC4_KEY *key, int len, const unsigned char *data);
#$dat="%rdi";	    # arg1
#$len="%rsi";	    # arg2
#$inp="%rdx";	    # arg3

# OpenSolaris:
# void arcfour_key_init(ARCFour_key *key, uchar_t *keyval, int keyvallen);
$dat="%rdi";	    # arg1
$inp="%rsi";	    # arg2
$len="%rdx";	    # arg3

# Temporaries
$idx="%r8";
$ido="%r9";

$code.=<<___;
	/ int arcfour_crypt_on_intel(void);
.extern	arcfour_crypt_on_intel

ENTRY_NP(arcfour_key_init)
	/ Find out if we're running on Intel or something else (e.g., AMD64).
	/ This sets %eax to 1 for Intel, otherwise 0.
	push	%rdi		/ Save arg1
	push	%rsi		/ Save arg2
	push	%rdx		/ Save arg3
	call	arcfour_crypt_on_intel
	pop	%rdx		/ Restore arg3
	pop	%rsi		/ Restore arg2
	pop	%rdi		/ Restore arg1
	/ Save return value in key->flag (1=Intel, 0=AMD)
	movl	%eax,1032($dat)

	/ Set $dat to beginning of array, key->arr[0]
	lea	8($dat),$dat
	lea	($inp,$len),$inp
	neg	$len
	mov	$len,%rcx

	xor	%eax,%eax
	xor	$ido,$ido
	xor	%r10,%r10
	xor	%r11,%r11

	/ Use a 4-byte data array
	jmp	.Lw1stloop

.align	16
.Lw1stloop:
	/ AMD64 (4-byte array)
	mov	%eax,($dat,%rax,4)
	add	\$1,%al
	jnc	.Lw1stloop

	xor	$ido,$ido
	xor	$idx,$idx

.align	16
.Lw2ndloop:
	mov	($dat,$ido,4),%r10d
	add	($inp,$len,1),$idx#b
	add	%r10b,$idx#b
	add	\$1,$len
	mov	($dat,$idx,4),%r11d
	cmovz	%rcx,$len
	mov	%r10d,($dat,$idx,4)
	mov	%r11d,($dat,$ido,4)
	add	\$1,$ido#b
	jnc	.Lw2ndloop

	/ Exit code
	xor	%eax,%eax
	mov	%eax,-8($dat)
	mov	%eax,-4($dat)

	ret
SET_SIZE(arcfour_key_init)
.asciz	"RC4 for x86_64, CRYPTOGAMS by <appro\@openssl.org>"
#endif /* !lint && !__lint */
___

$code =~ s/#([bwd])/$1/gm;

print $code;

close STDOUT;
