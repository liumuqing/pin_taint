#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>


//#define BIGENDIAN
#define DEBUG
#define ERROR(fmt, ...) (printf("[ERROR]" fmt "\n", ##__VA_ARGS__), exit(1))
#ifdef DEBUG
	#define MSG(fmt, ...) printf("[MSG]" fmt "\n", ##__VA_ARGS__)
#else
	#define MSG(fmt, ...) 
#endif


#define MAX_OPERAND_COUNT (4)

#define CONFIG_WITH_INST_STR
#ifdef CONFIG_WITH_INST_STR
	#define INST_STR_MAX_LEN 32
#endif
typedef uint32_t uint_t;
typedef int32_t int_t;

/*
 * for MAC OSX
 */
#ifndef MAP_ANONYMOUS
	#define MAP_ANONYMOUS MAP_ANON
#endif
#ifdef TARGET_WINDOWS
#ifdef _M_X64
#define BITS 64
#else
#define BITS 32
#endif
#endif


