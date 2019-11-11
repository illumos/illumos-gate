#include "optim/cast-kinds.c"

/*
 * check-name: cast-kinds check
 * check-command: sparse -m64 -v -Wno-pointer-to-int-cast $file
 * check-assert: sizeof(long) == 8
 *
 * check-error-start
optim/cast-kinds.c:5:45: warning: cast drops bits
optim/cast-kinds.c:6:47: warning: cast drops bits
optim/cast-kinds.c:7:46: warning: cast drops bits
optim/cast-kinds.c:8:45: warning: cast drops bits
optim/cast-kinds.c:12:48: warning: cast drops bits
optim/cast-kinds.c:13:50: warning: cast drops bits
optim/cast-kinds.c:14:49: warning: cast drops bits
optim/cast-kinds.c:15:48: warning: cast drops bits
optim/cast-kinds.c:37:48: warning: non size-preserving integer to pointer cast
optim/cast-kinds.c:38:50: warning: non size-preserving integer to pointer cast
 * check-error-end
 */
