struct u {
	unsigned int f:3;
};

unsigned int upostinc(struct u *x)
{
	return x->f++;
}

unsigned int upreinc(struct u *x)
{
	return ++x->f;
}

void ucpy(struct u *d, const struct u *s)
{
	d->f = s->f;
}


struct s {
	int f:3;
};

int spostinc(struct s *x)
{
	return x->f++;
}

int spreinc(struct s *x)
{
	return ++x->f;
}

void scpy(struct s *d, const struct s *s)
{
	d->f = s->f;
}

/*
 * check-name: bitfield-size
 * check-command: test-linearize -m64 -Wno-decl -fdump-ir  $file
  * check-assert: sizeof(void *) == 8
 *
 * check-output-start
upostinc:
.L0:
	<entry-point>
	store.64    %arg1 -> 0[x]
	load.64     %r1 <- 0[x]
	load.32     %r2 <- 0[%r1]
	trunc.3     %r3 <- (32) %r2
	zext.32     %r4 <- (3) %r3
	add.32      %r5 <- %r4, $1
	trunc.3     %r6 <- (32) %r5
	load.32     %r7 <- 0[%r1]
	zext.32     %r8 <- (3) %r6
	and.32      %r9 <- %r7, $0xfffffff8
	or.32       %r10 <- %r9, %r8
	store.32    %r10 -> 0[%r1]
	zext.32     %r11 <- (3) %r4
	phisrc.32   %phi1(return) <- %r11
	br          .L1

.L1:
	phi.32      %r12 <- %phi1(return)
	ret.32      %r12


upreinc:
.L2:
	<entry-point>
	store.64    %arg1 -> 0[x]
	load.64     %r13 <- 0[x]
	load.32     %r14 <- 0[%r13]
	trunc.3     %r15 <- (32) %r14
	zext.32     %r16 <- (3) %r15
	add.32      %r17 <- %r16, $1
	trunc.3     %r18 <- (32) %r17
	load.32     %r19 <- 0[%r13]
	zext.32     %r20 <- (3) %r18
	and.32      %r21 <- %r19, $0xfffffff8
	or.32       %r22 <- %r21, %r20
	store.32    %r22 -> 0[%r13]
	zext.32     %r23 <- (3) %r18
	phisrc.32   %phi2(return) <- %r23
	br          .L3

.L3:
	phi.32      %r24 <- %phi2(return)
	ret.32      %r24


ucpy:
.L4:
	<entry-point>
	store.64    %arg1 -> 0[d]
	store.64    %arg2 -> 0[s]
	load.64     %r25 <- 0[s]
	load.32     %r26 <- 0[%r25]
	trunc.3     %r27 <- (32) %r26
	load.64     %r28 <- 0[d]
	load.32     %r29 <- 0[%r28]
	zext.32     %r30 <- (3) %r27
	and.32      %r31 <- %r29, $0xfffffff8
	or.32       %r32 <- %r31, %r30
	store.32    %r32 -> 0[%r28]
	br          .L5

.L5:
	ret


spostinc:
.L6:
	<entry-point>
	store.64    %arg1 -> 0[x]
	load.64     %r33 <- 0[x]
	load.32     %r34 <- 0[%r33]
	trunc.3     %r35 <- (32) %r34
	zext.32     %r36 <- (3) %r35
	add.32      %r37 <- %r36, $1
	trunc.3     %r38 <- (32) %r37
	load.32     %r39 <- 0[%r33]
	zext.32     %r40 <- (3) %r38
	and.32      %r41 <- %r39, $0xfffffff8
	or.32       %r42 <- %r41, %r40
	store.32    %r42 -> 0[%r33]
	zext.32     %r43 <- (3) %r36
	phisrc.32   %phi3(return) <- %r43
	br          .L7

.L7:
	phi.32      %r44 <- %phi3(return)
	ret.32      %r44


spreinc:
.L8:
	<entry-point>
	store.64    %arg1 -> 0[x]
	load.64     %r45 <- 0[x]
	load.32     %r46 <- 0[%r45]
	trunc.3     %r47 <- (32) %r46
	zext.32     %r48 <- (3) %r47
	add.32      %r49 <- %r48, $1
	trunc.3     %r50 <- (32) %r49
	load.32     %r51 <- 0[%r45]
	zext.32     %r52 <- (3) %r50
	and.32      %r53 <- %r51, $0xfffffff8
	or.32       %r54 <- %r53, %r52
	store.32    %r54 -> 0[%r45]
	zext.32     %r55 <- (3) %r50
	phisrc.32   %phi4(return) <- %r55
	br          .L9

.L9:
	phi.32      %r56 <- %phi4(return)
	ret.32      %r56


scpy:
.L10:
	<entry-point>
	store.64    %arg1 -> 0[d]
	store.64    %arg2 -> 0[s]
	load.64     %r57 <- 0[s]
	load.32     %r58 <- 0[%r57]
	trunc.3     %r59 <- (32) %r58
	load.64     %r60 <- 0[d]
	load.32     %r61 <- 0[%r60]
	zext.32     %r62 <- (3) %r59
	and.32      %r63 <- %r61, $0xfffffff8
	or.32       %r64 <- %r63, %r62
	store.32    %r64 -> 0[%r60]
	br          .L11

.L11:
	ret


 * check-output-end
 */
