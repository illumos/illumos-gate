__FILE__
__BASE_FILE__

#include "base-file.h"

/*
 * check-name: base file
 * check-command: sparse -E $file
 *
 * check-output-start

"preprocessor/base-file.c"
"preprocessor/base-file.c"
"preprocessor/base-file.h"
"preprocessor/base-file.c"
 * check-output-end
 */
