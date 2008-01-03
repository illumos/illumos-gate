#if !defined(lint) && !defined(__lint)
/  ARCFOUR implementation optimized for AMD64.
/
/  Author: Marc Bevand <bevand_m (at) epita.fr>
/  Licence: I hereby disclaim the copyright on this code and place it
/  in the public domain.
/
/  The code has been designed to be easily integrated into openssl:
/  the exported RC4() function can replace the actual implementations
/  openssl already contains. Please note that when linking with openssl,
/  it requires that sizeof(RC4_INT) == 8. So openssl must be compiled
/  with -DRC4_INT='unsigned long'.
/
/  The throughput achieved by this code is about 320 MBytes/sec, on
/  a 1.8 GHz AMD Opteron (rev C0) processor.


/ ***** BEGIN LICENSE BLOCK *****
/ Version: MPL 1.1/GPL 2.0/LGPL 2.1
/
/ The contents of this file are subject to the Mozilla Public License Version
/ 1.1 (the "License"); you may not use this file except in compliance with
/ the License. You may obtain a copy of the License at
/ http://www.mozilla.org/MPL/
/
/ Software distributed under the License is distributed on an "AS IS" basis,
/ WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
/ for the specific language governing rights and limitations under the
/ License.
/
/ The Original Code is "Marc Bevand's fast AMD64 ARCFOUR source"
/
/ The Initial Developer of the Original Code is
/ Marc Bevand <bevand_m@epita.fr> .
/ Portions created by the Initial Developer are
/ Copyright (C) 2004 the Initial Developer. All Rights Reserved.
/
/ Contributor(s):
/
/ Alternatively, the contents of this file may be used under the terms of
/ either the GNU General Public License Version 2 or later (the "GPL"), or
/ the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
/ in which case the provisions of the GPL or the LGPL are applicable instead
/ of those above. If you wish to allow use of your version of this file only
/ under the terms of either the GPL or the LGPL, and not to allow others to
/ use your version of this file under the terms of the MPL, indicate your
/ decision by deleting the provisions above and replace them with the notice
/ and other provisions required by the GPL or the LGPL. If you do not delete
/ the provisions above, a recipient may use your version of this file under
/ the terms of any one of the MPL, the GPL or the LGPL.
/
/ ***** END LICENSE BLOCK *****

	.ident	"%Z%%M%	%I%	%E% SMI"

/
/ void arcfour_crypt(ARCFour_key *key, uchar_t *in,
/		uchar_t *out, size_t len);
/
/ The following is Marc Bevand's RC4 implementation optimized for
/ AMD64.  It has been lifted intact, except for minor interface
/ changes to get along with Solaris crypto common code (the parameter
/ order and the key struct element order are both different).
/ This function works for both aligned and unaligned data ('in' and 'out').
/ The key and key elements must be aligned.
/
/ Register Usage
/ rax		data[x]
/ rbx		ARG(len)
/ rcx		key->i (aka x)
/ rdx		key->j (aka y)
/ rsi		ARG(in)
/ rdi		ARG(out)
/ rbp		key->arr (aka data or d)
/ rsp		stack
/ r8		8 bytes of rc4 stream
/ r9		temp
/ r10-r15 	unused
/

#include <sys/asm_linkage.h>


	ENTRY_NP(arcfour_crypt)
	/* EXPORT DELETE START */
					/ load parameters
	push	%rbp
	push	%rbx
	mov	%rdi,		%rbp	/ rbp = ARG(key)
					/ rsi = ARG(in)
	mov	%rdx,		%rdi	/ rdi = ARG(out)
	mov	%rcx,		%rbx	/ rbx = ARG(len)

					/ load key indices and key
	mov	2048(%rbp),	%rcx	/ rcx x = key->i
	mov	2056(%rbp),	%rdx	/ rdx y = key->j
					/ rbp d = key->arr
	inc	%rcx			/ x++
	and	$255,		%rcx	/ x &= 0xff
	lea	-8(%rbx,%rsi),	%rbx	/ rbx = in+len-8
	mov	%rbx,		%r9	/ tmp = in+len-8
	mov	(%rbp,%rcx,8),	%rax	/ tx = d[x]
	cmp	%rsi,		%rbx	/ cmp in with in+len-8
	jl	.Lend			/ jump if (in+len-8 < in)

.Lstart:
	add	$8,		%rsi		/ increment in
	add	$8,		%rdi		/ increment out

	/ generate the next 8 bytes of the rc4 stream into %r8
	mov	$8,		%r11		/ byte counter
1:	add	%al,		%dl		/ y += tx
	mov	(%rbp,%rdx,8),	%ebx		/ ty = d[y]
	mov	%ebx,		(%rbp,%rcx,8)	/ d[x] = ty
	add	%al,		%bl		/ val = ty + tx
	mov	%eax,		(%rbp,%rdx,8)	/ d[y] = tx
	inc	%cl				/ x++		(NEXT ROUND)
	mov	(%rbp,%rcx,8),	%eax		/ tx = d[x]	(NEXT ROUND)
	movb	(%rbp,%rbx,8),	%r8b		/ val = d[val]
	dec	%r11b
	ror	$8,		%r8		/ (ror does not change ZF)
	jnz	1b

	/ xor 8 bytes
	xor	-8(%rsi),	%r8
	cmp	%r9,		%rsi		/ cmp in+len-8 with in
	mov	%r8,		-8(%rdi)
	jle	.Lstart				/ jump if (in <= in+len-8)

.Lend:
	add	$8,		%r9		/ tmp = in+len

	/ handle the last bytes, one by one
1:	cmp	%rsi,		%r9		/ cmp in with in+len
	jle	.Lfinished			/ jump if (in+len <= in)
	add	%al,		%dl		/ y += tx
	mov	(%rbp,%rdx,8),	%ebx		/ ty = d[y]
	mov	%ebx,		(%rbp,%rcx,8)	/ d[x] = ty
	add	%al,		%bl		/ val = ty + tx
	mov	%eax,		(%rbp,%rdx,8)	/ d[y] = tx
	inc	%cl				/ x++		(NEXT ROUND)
	mov	(%rbp,%rcx,8),	%eax		/ tx = d[x]	(NEXT ROUND)
	movb	(%rbp,%rbx,8),	%r8b		/ val = d[val]
	xor	(%rsi),		%r8b		/ xor 1 byte
	movb	%r8b,		(%rdi)
	inc	%rsi				/ in++
	inc	%rdi				/ out++
	jmp	1b

.Lfinished:					/ save key indices i & j
	dec	%rcx				/ x--
	movb	%dl,		2056(%rbp)	/ key->j = y
	movb	%cl,		2048(%rbp)	/ key->i = x
	pop	%rbx
	pop	%rbp

	/* EXPORT DELETE END */

	ret
	SET_SIZE(arcfour_crypt)

#else
	/* LINTED */
	/* Nothing to be linted in this file--it's pure assembly source. */
#endif /* !lint && !__lint */
