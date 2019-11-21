int def(void);
int r0(void);
int r1(void);
int r2(void);
int r3(void);
int r4(void);
int r5(void);
int r6(void);
int r7(void);
int r8(void);
int r9(void);

int small(int a)
{
	switch (a) {
	case 0: return r0();
	case 1: return r1();
	case 2: return r2();
	}

	return def();
}

int densefull(int a)
{
	switch (a) {
	case 0: return r0();
	case 1: return r1();
	case 2: return r2();
	case 3: return r3();
	case 4: return r4();
	case 5: return r5();
	case 6: return r6();
	case 7: return r7();
	case 8: return r8();
	case 9: return r9();
	}

	return def();
}

int densepart(int a)
{
	switch (a) {
	case 0: return r0();
	case 1: return r1();
	case 2: return r2();
	case 3: return r3();
	case 4: return r4();

	case 6: return r6();
	case 7: return r7();
	case 8: return r8();
	case 9: return r9();
	}

	return def();
}

int dense_dense_20(int a)
{
	switch (a) {
	case 0: return r0();
	case 1: return r1();
	case 2: return r2();
	case 3: return r3();
	case 4: return r4();
	case 5: return r5();
	case 6: return r6();
	case 7: return r7();
	case 8: return r8();
	case 9: return r9();

	case 20: return r0();
	case 21: return r1();
	case 22: return r2();
	case 23: return r3();
	case 24: return r4();
	case 25: return r5();
	case 26: return r6();
	case 27: return r7();
	case 28: return r8();
	case 29: return r9();
	}

	return def();
}

int dense_dense_100(int a)
{
	switch (a) {
	case 0: return r0();
	case 1: return r1();
	case 2: return r2();
	case 3: return r3();
	case 4: return r4();
	case 5: return r5();
	case 6: return r6();
	case 7: return r7();
	case 8: return r8();
	case 9: return r9();

	case 100: return r0();
	case 101: return r1();
	case 102: return r2();
	case 103: return r3();
	case 104: return r4();
	case 105: return r5();
	case 106: return r6();
	case 107: return r7();
	case 108: return r8();
	case 109: return r9();
	}

	return def();
}

int dense_dense_1000(int a)
{
	switch (a) {
	case 0: return r0();
	case 1: return r1();
	case 2: return r2();
	case 3: return r3();
	case 4: return r4();
	case 5: return r5();
	case 6: return r6();
	case 7: return r7();
	case 8: return r8();
	case 9: return r9();

	case 1000: return r0();
	case 1001: return r1();
	case 1002: return r2();
	case 1003: return r3();
	case 1004: return r4();
	case 1005: return r5();
	case 1006: return r6();
	case 1007: return r7();
	case 1008: return r8();
	case 1009: return r9();
	}

	return def();
}

int sparse(int a)
{
	switch (a) {
	case 0: return r0();
	case 3: return r1();
	case 12: return r2();
	case 31: return r3();
	case 54: return r4();
	case 75: return r5();
	case 96: return r6();
	case 107: return r7();
	case 189: return r8();
	case 999: return r9();
	}

	return def();
}

int range_simple(int a)
{
	switch (a) {
	case 1 ... 9: return r0();
	}

	return def();
}

int range_complex(int a)
{
	switch (a) {
	case -1: return r0();
	case 1 ... 9: return r0();
	case 10 ... 19: return r1();
	case 200 ... 202: return r2();
	case 300 ... 303: return r3();
	}

	return def();
}

void switch_call(int a)
{
	int r;

	switch (a) {
	case 0: r0(); break;
	case 1: r1(); break;
	case 2: r2(); break;
	case 3: r3(); break;
	case 4: r4(); break;
	case 5: r5(); break;
	case 6: r6(); break;
	case 7: r7(); break;
	case 8: r8(); break;
	case 9: r9(); break;
	}
}

int switch_retcall(int a)
{
	int r = 0;

	switch (a) {
	case 0: r = r0(); break;
	case 1: r = r1(); break;
	case 2: r = r2(); break;
	case 3: r = r3(); break;
	case 4: r = r4(); break;
	case 5: r = r5(); break;
	case 6: r = r6(); break;
	case 7: r = r7(); break;
	case 8: r = r8(); break;
	case 9: r = r9(); break;
	}

	return r;
}

int switch_cmov(int a)
{
	int r;

	switch (a) {
	case 0: r = 3; break;
	case 1: r = 1; break;
	case 2: r = 7; break;
	case 3: r = 2; break;
	case 4: r = 9; break;

	case 6: r = 5; break;
	case 7: r = 8; break;
	case 8: r = 6; break;
	case 9: r = 4; break;
	}

	return r;
}

/*
 * check-name: llvm-switch
 * check-command: sparsec -Wno-decl -c $file -o tmp.o
 */
