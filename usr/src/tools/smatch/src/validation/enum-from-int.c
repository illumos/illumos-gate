#include "enum-common.c"

/*
 * check-name: -Wint-to-enum
 * check-command: sparse -Wno-enum-mismatch $file
 *
 * check-error-start
enum-common.c:84:45: warning: conversion of
enum-common.c:84:45:     int to
enum-common.c:84:45:     int enum ENUM_TYPE_A 
enum-common.c:85:45: warning: conversion of
enum-common.c:85:45:     int to
enum-common.c:85:45:     int enum ENUM_TYPE_A 
enum-common.c:82:22: warning: conversion of
enum-common.c:82:22:     int to
enum-common.c:82:22:     int enum ENUM_TYPE_A 
enum-common.c:87:17: warning: conversion of
enum-common.c:87:17:     int to
enum-common.c:87:17:     int enum ENUM_TYPE_A 
enum-common.c:88:17: warning: conversion of
enum-common.c:88:17:     int to
enum-common.c:88:17:     int enum ENUM_TYPE_B 
enum-common.c:89:25: warning: conversion of
enum-common.c:89:25:     int to
enum-common.c:89:25:     int enum <noident> 
enum-common.c:90:25: warning: conversion of
enum-common.c:90:25:     int to
enum-common.c:90:25:     int enum <noident> 
enum-common.c:91:18: warning: conversion of
enum-common.c:91:18:     int to
enum-common.c:91:18:     int enum ENUM_TYPE_A 
enum-common.c:92:18: warning: conversion of
enum-common.c:92:18:     int to
enum-common.c:92:18:     int enum ENUM_TYPE_A 
 * check-error-end
 */
