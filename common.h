#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>

extern FILE * KnobOutputFile;

#define DEBUG
#define ERROR(fmt, ...) (fprintf(KnobOutputFile, "[ERROR]" fmt "\n", ##__VA_ARGS__), fflush(KnobOutputFile), exit(1))
#ifdef DEBUG
	#define MSG(fmt, ...) (fprintf(KnobOutputFile, "[MSG]" fmt "\n", ##__VA_ARGS__), fflush(KnobOutputFile))
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

#ifndef BITS
#error("BITS not defined")
#endif

#if BITS==64
#define FORMAT_ADDR_X PRIx64
#define FORMAT_ADDR_U PRIu64
#elif BITS==32
#define FORMAT_ADDR_X PRIx32
#define FORMAT_ADDR_U PRIu32
#else
#error("BITS not 64/32")
#endif

typedef uint32_t TAG_t;
#define FORMAT_TAG_X PRIx32
#define FORMAT_TAG_U PRIu32
