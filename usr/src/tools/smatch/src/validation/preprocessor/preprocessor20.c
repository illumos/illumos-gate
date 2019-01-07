#include "preprocessor20.h"
#define X
#define Y
#include "preprocessor20.h"
/*
 * check-name: Preprocessor #20
 * check-command: sparse -E $file
 *
 * check-output-start

A
B
 * check-output-end
 */
