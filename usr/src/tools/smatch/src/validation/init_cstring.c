static struct alpha {
  char a[2];
} x = { .a = "ab" };
/*
 * check-name: -Winit-cstring option
 *
 * check-command: sparse -Winit-cstring $file
 * check-error-start
init_cstring.c:3:14: warning: too long initializer-string for array of char(no space for nul char)
 * check-error-end
 */
