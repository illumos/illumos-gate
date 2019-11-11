int fun(void);

static int foo(int a) { return 0 || fun(); }
static int bar(int a) { return 1 || fun(); }
static int baz(int a) { return 0 && fun(); }
static int qux(int a) { return 1 && fun(); }

static int oof(int a) { return fun() || 1; }
static int rab(int a) { return fun() || 0; }
static int zab(int a) { return fun() && 1; }
static int xuq(int a) { return fun() && 0; }

/*
 * check-name: phi-order02
 * check-command: sparse -vir -flinearize=last $file
 */
