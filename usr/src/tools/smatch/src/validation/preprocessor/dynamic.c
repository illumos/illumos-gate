#if defined(__LINE__)
__LINE__
#endif
#if defined(__FILE__)
__FILE__
#endif
#if defined(__BASE_FILE__)
__BASE_FILE__
#endif
#if defined(__DATE__)
date
#endif
#if defined(__TIME__)
time
#endif
#if defined(__COUNTER__)
counter
#endif
#if defined(__INCLUDE_LEVEL__)
__INCLUDE_LEVEL__
#endif

/*
 * check-name: dynamic-macros
 * check-command: sparse -E $file
 *
 * check-output-start

2
"preprocessor/dynamic.c"
"preprocessor/dynamic.c"
date
time
counter
0
 * check-output-end
 */
