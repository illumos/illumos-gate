void def(void);
void r0(void);
void r1(void);

void sw_long(long long a)
{
	switch (a) {
	case 0: return r0();
	case 1LL << 00: return r1();
	case 1LL << 32: return r1();
	}

	return def();
}

/*
 * check-name: switch-long
 * check-command: test-linearize -Wno-decl $file
 *
 * check-output-start
sw_long:
.L0:
	<entry-point>
	switch.64   %arg1, 0 -> .L2, 1 -> .L3, 4294967296 -> .L4, default -> .L1

.L2:
	call        r0
	br          .L5

.L3:
	call        r1
	br          .L5

.L4:
	call        r1
	br          .L5

.L1:
	call        def
	br          .L5

.L5:
	ret


 * check-output-end
 */
