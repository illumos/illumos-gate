#include "enum-common.c"

/*
 * check-name: -Wenum-to-int
 * check-command: sparse -Wenum-to-int -Wno-enum-mismatch -Wno-int-to-enum $file
 *
 * check-error-start
enum-common.c:97:13: warning: conversion of
enum-common.c:97:13:     int enum ENUM_TYPE_A  to
enum-common.c:97:13:     int
enum-common.c:98:13: warning: conversion of
enum-common.c:98:13:     int enum ENUM_TYPE_B  to
enum-common.c:98:13:     int
enum-common.c:103:34: warning: conversion of
enum-common.c:103:34:     int enum ENUM_TYPE_A  to
enum-common.c:103:34:     int
enum-common.c:104:34: warning: conversion of
enum-common.c:104:34:     int enum ENUM_TYPE_B  to
enum-common.c:104:34:     int
enum-common.c:100:22: warning: conversion of
enum-common.c:100:22:     int enum ENUM_TYPE_A  to
enum-common.c:100:22:     int
enum-common.c:101:22: warning: conversion of
enum-common.c:101:22:     int enum ENUM_TYPE_B  to
enum-common.c:101:22:     int
 * check-error-end
 */
