/*
 * check-name: __COUNTER__ #3
 * check-command: sparse -Ipreprocessor -E preprocessor/counter1.c $file
 *
 * check-output-start

0
1
"preprocessor/counter2.c" 0
"preprocessor/counter2.h" 1
"preprocessor/counter2.c" 2
 * check-output-end
 */
#include "counter2.c"
