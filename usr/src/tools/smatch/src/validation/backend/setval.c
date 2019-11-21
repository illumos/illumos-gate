double setfval64(void) { return 1.23; }
float  setfval32(void) { return 1.23F; }

/*
 * check-name: setval-float
 * check-command: sparsec -Wno-decl -c $file -o tmp.o
 */
