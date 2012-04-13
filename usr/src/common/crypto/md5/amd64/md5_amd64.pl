#!/usr/bin/perl -w
#
# MD5 optimized for AMD64.
#
# Author: Marc Bevand <bevand_m (at) epita.fr>
# Licence: I hereby disclaim the copyright on this code and place it
# in the public domain.
#

#
# The following is Marc Bevand's MD5 implementation optimized for
# AMD64.  It has been lifted intact, except for changing the comment
# character and adding comments.
#
# typedef struct {
#	uint32_t state[4];	/* state (ABCD) */
#	uint32_t count[2];	/* number of bits, modulo 2^64 (lsb first) */
#	union	{
#		uint8_t		buf8[64];	/* undigested input */
#		uint32_t	buf32[16];	/* realigned input */
#		} buf_un;
#	} MD5_CTX;
#
# void md5_block_asm_host_order(MD5_CTX *ctx, const void *inpp,
#        unsigned int input_length_in_blocks);
#
# Registers used:
#	rax  A		r8  old A
#	rbx  B		r9  old B
#	rcx  C		r10 tmp
#	rdx  D		r11 tmp
#	rsi  ptr	r12 tmp
#	rdi  end	r13 -
#	rbp  -		r14 old C
#	rsp  stack	r15 old D
#

use strict;
my $code;


# round1_step() does:
#   dst = x + ((dst + F(x,y,z) + X[k] + T_i) <<< s)
#   %r10d = X[k_next]
#   %r11d = z' (copy of z for the next step)
# Each round1_step() takes about 5.3 clocks (9 instructions, 1.7 IPC)
sub round1_step
{
    my ($pos, $dst, $x, $y, $z, $k_next, $T_i, $s) = @_;
    $code .= "	mov	0*4(%rsi),	%r10d		/* (NEXT STEP) X[0] */\n" if ($pos == -1);
    $code .= "	mov	%edx,		%r11d		/* (NEXT STEP) z' = %edx */\n" if ($pos == -1);
    $T_i = sprintf("-0x%08x", (0xffffffff ^ hex($T_i))+1)
        if (hex($T_i) >= 0x80000000);

    $code .= <<EOF;
	xor	$y,		%r11d		/* y ^ ... */
	lea	$T_i($dst,%r10d),$dst		/* Const + dst + ... r1 */
	and	$x,		%r11d		/* x & ... */
	xor	$z,		%r11d		/* z ^ ... */
	mov	$k_next*4(%rsi),%r10d		/* (NEXT STEP) X[$k_next] */
	add	%r11d,		$dst		/* dst += ... */
	rol	\$$s,		$dst		/* dst <<< s */
	mov	$y,		%r11d		/* (NEXT STEP) z' = $y */
	add	$x,		$dst		/* dst += x */
EOF
}

# round2_step() does:
#   dst = x + ((dst + G(x,y,z) + X[k] + T_i) <<< s)
#   %r10d = X[k_next]
#   %r11d = z' (copy of z for the next step)
#   %r12d = z' (copy of z for the next step)
# Each round2_step() takes about 5.4 clocks (11 instructions, 2.0 IPC)
sub round2_step
{
    my ($pos, $dst, $x, $y, $z, $k_next, $T_i, $s) = @_;
    $code .= "	mov	1*4(%rsi),	%r10d		/* (NEXT STEP) X[1] */\n" if ($pos == -1);
    $code .= "	mov	%edx,		%r11d		/* (NEXT STEP) z' = %edx */\n" if ($pos == -1);
    $code .= "	mov	%edx,		%r12d		/* (NEXT STEP) z' = %edx */\n" if ($pos == -1);
    $T_i = sprintf("-0x%08x", (0xffffffff ^ hex($T_i))+1)
        if (hex($T_i) >= 0x80000000);

    $code .= <<EOF;
	not	%r11d				/* not z */
	lea	$T_i($dst,%r10d),$dst		/* Const + dst + ... r2 */
	and	$x,		%r12d		/* x & z */
	and	$y,		%r11d		/* y & (not z) */
	mov	$k_next*4(%rsi),%r10d		/* (NEXT STEP) X[$k_next] */
	or	%r11d,		%r12d		/* (y & (not z)) | (x & z) */
	mov	$y,		%r11d		/* (NEXT STEP) z' = $y */
	add	%r12d,		$dst		/* dst += ... */
	mov	$y,		%r12d		/* (NEXT STEP) z' = $y */
	rol	\$$s,		$dst		/* dst <<< s */
	add	$x,		$dst		/* dst += x */
EOF
}

# round3_step() does:
#   dst = x + ((dst + H(x,y,z) + X[k] + T_i) <<< s)
#   %r10d = X[k_next]
#   %r11d = y' (copy of y for the next step)
# Each round3_step() takes about 4.2 clocks (8 instructions, 1.9 IPC)
sub round3_step
{
    my ($pos, $dst, $x, $y, $z, $k_next, $T_i, $s) = @_;
    $code .= "	mov	5*4(%rsi),	%r10d		/* (NEXT STEP) X[5] */\n" if ($pos == -1);
    $code .= "	mov	%ecx,		%r11d		/* (NEXT STEP) y' = %ecx */\n" if ($pos == -1);
    $T_i = sprintf("-0x%08x", (0xffffffff ^ hex($T_i))+1)
        if (hex($T_i) >= 0x80000000);

    $code .= <<EOF;
	lea	$T_i($dst,%r10d),$dst		/* Const + dst + ... r3 */
	mov	$k_next*4(%rsi),%r10d		/* (NEXT STEP) X[$k_next] */
	xor	$z,		%r11d		/* z ^ ... */
	xor	$x,		%r11d		/* x ^ ... */
	add	%r11d,		$dst		/* dst += ... */
	rol	\$$s,		$dst		/* dst <<< s */
	mov	$x,		%r11d		/* (NEXT STEP) y' = $x */
	add	$x,		$dst		/* dst += x */
EOF
}

# round4_step() does:
#   dst = x + ((dst + I(x,y,z) + X[k] + T_i) <<< s)
#   %r10d = X[k_next]
#   %r11d = not z' (copy of not z for the next step)
# Each round4_step() takes about 5.2 clocks (9 instructions, 1.7 IPC)
sub round4_step
{
    my ($pos, $dst, $x, $y, $z, $k_next, $T_i, $s) = @_;
    $code .= "	mov	0*4(%rsi),	%r10d		/* (NEXT STEP) X[0] */\n" if ($pos == -1);
    $code .= "	mov	\$0xffffffff,	%r11d\n" if ($pos == -1);
    $code .= "	xor	%edx,		%r11d		/* (NEXT STEP) not z' = not %edx*/\n"
    if ($pos == -1);
    $T_i = sprintf("-0x%08x", (0xffffffff ^ hex($T_i))+1)
        if (hex($T_i) >= 0x80000000);

    $code .= <<EOF;
	lea	$T_i($dst,%r10d),$dst		/* Const + dst + ... r4 */
	or	$x,		%r11d		/* x | ... */
	xor	$y,		%r11d		/* y ^ ... */
	add	%r11d,		$dst		/* dst += ... */
	mov	$k_next*4(%rsi),%r10d		/* (NEXT STEP) X[$k_next] */
	mov	\$0xffffffff,	%r11d
	rol	\$$s,		$dst		/* dst <<< s */
	xor	$y,		%r11d		/* (NEXT STEP) not z' = not $y */
	add	$x,		$dst		/* dst += x */
EOF
}


#
# Execution begins here.
#

my $output = shift;
open STDOUT,">$output" or die "can't open $output: $!";

$code .= <<EOF;
#if defined(lint) || defined(__lint)
#include <sys/md5.h>

/* ARGSUSED */
void md5_block_asm_host_order(MD5_CTX *ctx, const void *inpp,
    unsigned int input_length_in_blocks)
{
}

#else
#include <sys/asm_linkage.h>

	ENTRY_NP(md5_block_asm_host_order)
	push	%rbp
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	/ rdi = arg #1 (ctx, MD5_CTX pointer)
	/ rsi = arg #2 (ptr, data pointer)
	/ rdx = arg #3 (nbr, number of 64-byte blocks to process)
	mov	%rdi,		%rbp	/ rbp = ctx
	shl	\$6,		%rdx	/ rdx = nbr in bytes
	lea	(%rsi,%rdx),	%rdi	/ rdi = end
	mov	0*4(%rbp),	%eax	/ eax = ctx->A
	mov	1*4(%rbp),	%ebx	/ ebx = ctx->B
	mov	2*4(%rbp),	%ecx	/ ecx = ctx->C
	mov	3*4(%rbp),	%edx	/ edx = ctx->D
	push	%rbp			/ save ctx
	/ end is 'rdi'
	/ ptr is 'rsi'
	/ A is 'eax'
	/ B is 'ebx'
	/ C is 'ecx'
	/ D is 'edx'

	cmp	%rdi,		%rsi		/ cmp end with ptr
	je	1f				/ jmp if ptr == end

	/ BEGIN of loop over 64-byte blocks
2:	/ save old values of A, B, C, D
	mov	%eax,		%r8d
	mov	%ebx,		%r9d
	mov	%ecx,		%r14d
	mov	%edx,		%r15d
EOF
round1_step(-1,'%eax','%ebx','%ecx','%edx', '1','0xd76aa478', '7');
round1_step( 0,'%edx','%eax','%ebx','%ecx', '2','0xe8c7b756','12');
round1_step( 0,'%ecx','%edx','%eax','%ebx', '3','0x242070db','17');
round1_step( 0,'%ebx','%ecx','%edx','%eax', '4','0xc1bdceee','22');
round1_step( 0,'%eax','%ebx','%ecx','%edx', '5','0xf57c0faf', '7');
round1_step( 0,'%edx','%eax','%ebx','%ecx', '6','0x4787c62a','12');
round1_step( 0,'%ecx','%edx','%eax','%ebx', '7','0xa8304613','17');
round1_step( 0,'%ebx','%ecx','%edx','%eax', '8','0xfd469501','22');
round1_step( 0,'%eax','%ebx','%ecx','%edx', '9','0x698098d8', '7');
round1_step( 0,'%edx','%eax','%ebx','%ecx','10','0x8b44f7af','12');
round1_step( 0,'%ecx','%edx','%eax','%ebx','11','0xffff5bb1','17');
round1_step( 0,'%ebx','%ecx','%edx','%eax','12','0x895cd7be','22');
round1_step( 0,'%eax','%ebx','%ecx','%edx','13','0x6b901122', '7');
round1_step( 0,'%edx','%eax','%ebx','%ecx','14','0xfd987193','12');
round1_step( 0,'%ecx','%edx','%eax','%ebx','15','0xa679438e','17');
round1_step( 1,'%ebx','%ecx','%edx','%eax', '0','0x49b40821','22');

round2_step(-1,'%eax','%ebx','%ecx','%edx', '6','0xf61e2562', '5');
round2_step( 0,'%edx','%eax','%ebx','%ecx','11','0xc040b340', '9');
round2_step( 0,'%ecx','%edx','%eax','%ebx', '0','0x265e5a51','14');
round2_step( 0,'%ebx','%ecx','%edx','%eax', '5','0xe9b6c7aa','20');
round2_step( 0,'%eax','%ebx','%ecx','%edx','10','0xd62f105d', '5');
round2_step( 0,'%edx','%eax','%ebx','%ecx','15', '0x2441453', '9');
round2_step( 0,'%ecx','%edx','%eax','%ebx', '4','0xd8a1e681','14');
round2_step( 0,'%ebx','%ecx','%edx','%eax', '9','0xe7d3fbc8','20');
round2_step( 0,'%eax','%ebx','%ecx','%edx','14','0x21e1cde6', '5');
round2_step( 0,'%edx','%eax','%ebx','%ecx', '3','0xc33707d6', '9');
round2_step( 0,'%ecx','%edx','%eax','%ebx', '8','0xf4d50d87','14');
round2_step( 0,'%ebx','%ecx','%edx','%eax','13','0x455a14ed','20');
round2_step( 0,'%eax','%ebx','%ecx','%edx', '2','0xa9e3e905', '5');
round2_step( 0,'%edx','%eax','%ebx','%ecx', '7','0xfcefa3f8', '9');
round2_step( 0,'%ecx','%edx','%eax','%ebx','12','0x676f02d9','14');
round2_step( 1,'%ebx','%ecx','%edx','%eax', '0','0x8d2a4c8a','20');

round3_step(-1,'%eax','%ebx','%ecx','%edx', '8','0xfffa3942', '4');
round3_step( 0,'%edx','%eax','%ebx','%ecx','11','0x8771f681','11');
round3_step( 0,'%ecx','%edx','%eax','%ebx','14','0x6d9d6122','16');
round3_step( 0,'%ebx','%ecx','%edx','%eax', '1','0xfde5380c','23');
round3_step( 0,'%eax','%ebx','%ecx','%edx', '4','0xa4beea44', '4');
round3_step( 0,'%edx','%eax','%ebx','%ecx', '7','0x4bdecfa9','11');
round3_step( 0,'%ecx','%edx','%eax','%ebx','10','0xf6bb4b60','16');
round3_step( 0,'%ebx','%ecx','%edx','%eax','13','0xbebfbc70','23');
round3_step( 0,'%eax','%ebx','%ecx','%edx', '0','0x289b7ec6', '4');
round3_step( 0,'%edx','%eax','%ebx','%ecx', '3','0xeaa127fa','11');
round3_step( 0,'%ecx','%edx','%eax','%ebx', '6','0xd4ef3085','16');
round3_step( 0,'%ebx','%ecx','%edx','%eax', '9', '0x4881d05','23');
round3_step( 0,'%eax','%ebx','%ecx','%edx','12','0xd9d4d039', '4');
round3_step( 0,'%edx','%eax','%ebx','%ecx','15','0xe6db99e5','11');
round3_step( 0,'%ecx','%edx','%eax','%ebx', '2','0x1fa27cf8','16');
round3_step( 1,'%ebx','%ecx','%edx','%eax', '0','0xc4ac5665','23');

round4_step(-1,'%eax','%ebx','%ecx','%edx', '7','0xf4292244', '6');
round4_step( 0,'%edx','%eax','%ebx','%ecx','14','0x432aff97','10');
round4_step( 0,'%ecx','%edx','%eax','%ebx', '5','0xab9423a7','15');
round4_step( 0,'%ebx','%ecx','%edx','%eax','12','0xfc93a039','21');
round4_step( 0,'%eax','%ebx','%ecx','%edx', '3','0x655b59c3', '6');
round4_step( 0,'%edx','%eax','%ebx','%ecx','10','0x8f0ccc92','10');
round4_step( 0,'%ecx','%edx','%eax','%ebx', '1','0xffeff47d','15');
round4_step( 0,'%ebx','%ecx','%edx','%eax', '8','0x85845dd1','21');
round4_step( 0,'%eax','%ebx','%ecx','%edx','15','0x6fa87e4f', '6');
round4_step( 0,'%edx','%eax','%ebx','%ecx', '6','0xfe2ce6e0','10');
round4_step( 0,'%ecx','%edx','%eax','%ebx','13','0xa3014314','15');
round4_step( 0,'%ebx','%ecx','%edx','%eax', '4','0x4e0811a1','21');
round4_step( 0,'%eax','%ebx','%ecx','%edx','11','0xf7537e82', '6');
round4_step( 0,'%edx','%eax','%ebx','%ecx', '2','0xbd3af235','10');
round4_step( 0,'%ecx','%edx','%eax','%ebx', '9','0x2ad7d2bb','15');
round4_step( 1,'%ebx','%ecx','%edx','%eax', '0','0xeb86d391','21');
$code .= <<EOF;
	/ add old values of A, B, C, D
	add	%r8d,	%eax
	add	%r9d,	%ebx
	add	%r14d,	%ecx
	add	%r15d,	%edx

	/ loop control
	add	\$64,		%rsi		/ ptr += 64
	cmp	%rdi,		%rsi		/ cmp end with ptr
	jb	2b				/ jmp if ptr < end
	/ END of loop over 64-byte blocks

1:	pop	%rbp				/ restore ctx
	mov	%eax,		0*4(%rbp)	/ ctx->A = A
	mov	%ebx,		1*4(%rbp)	/ ctx->B = B
	mov	%ecx,		2*4(%rbp)	/ ctx->C = C
	mov	%edx,		3*4(%rbp)	/ ctx->D = D

	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbx
	pop	%rbp
	ret
	SET_SIZE(md5_block_asm_host_order)

#endif /* lint || __lint */
EOF

print $code;
