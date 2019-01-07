__FILE__ __COUNTER__
#include <counter2.h>
__FILE__ __COUNTER__
/*
 * check-name: __COUNTER__ #2
 * check-command: sparse -Ipreprocessor -E $file
 *
 * check-output-start

"preprocessor/counter2.c" 0
"preprocessor/counter2.h" 1
"preprocessor/counter2.c" 2
 * check-output-end
 */
