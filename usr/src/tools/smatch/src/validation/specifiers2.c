typedef int T;
void BAD(
char char,
char int,
char double,
char float,
char long,
char short,
int char,
int int,
int double,
int float,
double char,
double int,
double double,
double float,
double short,
double signed,
double unsigned,
float char,
float int,
float double,
float float,
float short,
float long,
float signed,
float unsigned,
short char,
short double,
short float,
short short,
short long,
long char,
long float,
long short,
signed double,
signed float,
signed signed,
signed unsigned,
unsigned double,
unsigned float,
unsigned signed,
unsigned unsigned,
unsigned signed,
long long long,
long double long,
long long double,
double long long,
T char,
T int,
T double,
T float,
T short,
T long,
T signed,
T unsigned,
T void,
void char,
void int,
void double,
void float,
void short,
void long,
void signed,
void unsigned,
char void,
int void,
double void,
float void,
short void,
long void,
signed void,
unsigned void,
void void
);
/*
 * check-name: invalid specifier combinations
 * check-error-start
specifiers2.c:3:6: error: two or more data types in declaration specifiers
specifiers2.c:4:6: error: two or more data types in declaration specifiers
specifiers2.c:5:6: error: two or more data types in declaration specifiers
specifiers2.c:6:6: error: two or more data types in declaration specifiers
specifiers2.c:7:6: error: impossible combination of type specifiers: char long
specifiers2.c:8:6: error: impossible combination of type specifiers: char short
specifiers2.c:9:5: error: two or more data types in declaration specifiers
specifiers2.c:10:5: error: two or more data types in declaration specifiers
specifiers2.c:11:5: error: two or more data types in declaration specifiers
specifiers2.c:12:5: error: two or more data types in declaration specifiers
specifiers2.c:13:8: error: two or more data types in declaration specifiers
specifiers2.c:14:8: error: two or more data types in declaration specifiers
specifiers2.c:15:8: error: two or more data types in declaration specifiers
specifiers2.c:16:8: error: two or more data types in declaration specifiers
specifiers2.c:17:8: error: impossible combination of type specifiers: double short
specifiers2.c:18:8: error: impossible combination of type specifiers: double signed
specifiers2.c:19:8: error: impossible combination of type specifiers: double unsigned
specifiers2.c:20:7: error: two or more data types in declaration specifiers
specifiers2.c:21:7: error: two or more data types in declaration specifiers
specifiers2.c:22:7: error: two or more data types in declaration specifiers
specifiers2.c:23:7: error: two or more data types in declaration specifiers
specifiers2.c:24:7: error: impossible combination of type specifiers: float short
specifiers2.c:25:7: error: impossible combination of type specifiers: float long
specifiers2.c:26:7: error: impossible combination of type specifiers: float signed
specifiers2.c:27:7: error: impossible combination of type specifiers: float unsigned
specifiers2.c:28:7: error: impossible combination of type specifiers: short char
specifiers2.c:29:7: error: impossible combination of type specifiers: short double
specifiers2.c:30:7: error: impossible combination of type specifiers: short float
specifiers2.c:31:7: error: impossible combination of type specifiers: short short
specifiers2.c:32:7: error: impossible combination of type specifiers: short long
specifiers2.c:33:6: error: impossible combination of type specifiers: long char
specifiers2.c:34:6: error: impossible combination of type specifiers: long float
specifiers2.c:35:6: error: impossible combination of type specifiers: long short
specifiers2.c:36:8: error: impossible combination of type specifiers: signed double
specifiers2.c:37:8: error: impossible combination of type specifiers: signed float
specifiers2.c:38:8: error: impossible combination of type specifiers: signed signed
specifiers2.c:39:8: error: impossible combination of type specifiers: signed unsigned
specifiers2.c:40:10: error: impossible combination of type specifiers: unsigned double
specifiers2.c:41:10: error: impossible combination of type specifiers: unsigned float
specifiers2.c:42:10: error: impossible combination of type specifiers: unsigned signed
specifiers2.c:43:10: error: impossible combination of type specifiers: unsigned unsigned
specifiers2.c:44:10: error: impossible combination of type specifiers: unsigned signed
specifiers2.c:45:11: error: impossible combination of type specifiers: long long long
specifiers2.c:46:13: error: impossible combination of type specifiers: long long double
specifiers2.c:47:11: error: impossible combination of type specifiers: long long double
specifiers2.c:48:13: error: impossible combination of type specifiers: long long double
specifiers2.c:49:3: error: two or more data types in declaration specifiers
specifiers2.c:50:3: error: two or more data types in declaration specifiers
specifiers2.c:51:3: error: two or more data types in declaration specifiers
specifiers2.c:52:3: error: two or more data types in declaration specifiers
specifiers2.c:53:3: error: two or more data types in declaration specifiers
specifiers2.c:54:3: error: two or more data types in declaration specifiers
specifiers2.c:55:3: error: two or more data types in declaration specifiers
specifiers2.c:56:3: error: two or more data types in declaration specifiers
specifiers2.c:57:3: error: two or more data types in declaration specifiers
specifiers2.c:58:6: error: two or more data types in declaration specifiers
specifiers2.c:59:6: error: two or more data types in declaration specifiers
specifiers2.c:60:6: error: two or more data types in declaration specifiers
specifiers2.c:61:6: error: two or more data types in declaration specifiers
specifiers2.c:62:6: error: two or more data types in declaration specifiers
specifiers2.c:63:6: error: two or more data types in declaration specifiers
specifiers2.c:64:6: error: two or more data types in declaration specifiers
specifiers2.c:65:6: error: two or more data types in declaration specifiers
specifiers2.c:66:6: error: two or more data types in declaration specifiers
specifiers2.c:67:5: error: two or more data types in declaration specifiers
specifiers2.c:68:8: error: two or more data types in declaration specifiers
specifiers2.c:69:7: error: two or more data types in declaration specifiers
specifiers2.c:70:7: error: impossible combination of type specifiers: short void
specifiers2.c:71:6: error: impossible combination of type specifiers: long void
specifiers2.c:72:8: error: impossible combination of type specifiers: signed void
specifiers2.c:73:10: error: impossible combination of type specifiers: unsigned void
specifiers2.c:74:6: error: two or more data types in declaration specifiers
 * check-error-end
 */
