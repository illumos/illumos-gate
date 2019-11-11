typedef unsigned int u32;
typedef          int s32;

s32 asr31(s32 a) { return a >> 31; }
s32 asr32(s32 a) { return a >> 32; }
s32 asr33(s32 a) { return a >> 33; }

u32 lsr31(u32 a) { return a >> 31; }
u32 lsr32(u32 a) { return a >> 32; }
u32 lsr33(u32 a) { return a >> 33; }

u32 shl31(u32 a) { return a << 31; }
u32 shl32(u32 a) { return a << 32; }
u32 shl33(u32 a) { return a << 33; }

/*
 * check-name: optim/shift-big.c
 * check-command: test-linearize -Wno-decl -m64 $file
 *
 * check-error-ignore
 * check-output-start
asr31:
.L0:
	<entry-point>
	asr.32      %r2 <- %arg1, $31
	ret.32      %r2


asr32:
.L2:
	<entry-point>
	asr.32      %r5 <- %arg1, $32
	ret.32      %r5


asr33:
.L4:
	<entry-point>
	asr.32      %r8 <- %arg1, $33
	ret.32      %r8


lsr31:
.L6:
	<entry-point>
	lsr.32      %r11 <- %arg1, $31
	ret.32      %r11


lsr32:
.L8:
	<entry-point>
	ret.32      $0


lsr33:
.L10:
	<entry-point>
	ret.32      $0


shl31:
.L12:
	<entry-point>
	shl.32      %r20 <- %arg1, $31
	ret.32      %r20


shl32:
.L14:
	<entry-point>
	ret.32      $0


shl33:
.L16:
	<entry-point>
	ret.32      $0


 * check-output-end
 */
