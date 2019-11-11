enum e { };
enum f { F = 0.1 };

/*
 * check-name: enum-invalid
 *
 * check-error-start
enum-invalid.c:1:10: error: empty enum definition
enum-invalid.c:2:14: error: bad constant expression
 * check-error-end
 */
